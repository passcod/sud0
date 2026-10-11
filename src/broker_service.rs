use std::collections::HashMap;
use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::sync::{Notify, watch};
use zbus::fdo::DBusProxy;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::zvariant::{OwnedFd as ZOwnedFd, OwnedObjectPath, Type};
use zbus::{Connection, DBusError, interface};

use crate::broker_auth::{ZbusAuthority, authorize};
use crate::{
    AuthorizationOutcome, AuthorizationRequest, CallerIdentity, Cancellation, CancellationReason,
    CommandOutcome, LaunchError, LaunchRequest, PreparedRequest, RunWire, SystemdLauncher,
    WindowSize, set_pty_window_size,
};

const PHASE_AUTHORIZING: u8 = 0;
const PHASE_STARTING: u8 = 1;
const PHASE_RUNNING: u8 = 2;
const PHASE_COMPLETE: u8 = 3;
const PHASE_FAILED: u8 = 4;
const PHASE_CANCELLED: u8 = 5;
const PHASE_DENIED: u8 = 6;

const MAX_GLOBAL_INVOCATIONS: usize = 256;
const MAX_OWNER_INVOCATIONS: usize = 16;
const MAX_GLOBAL_VALIDATIONS: usize = 64;
const MAX_OWNER_VALIDATIONS: usize = 4;
const INVOCATION_EXPIRY: Duration = Duration::from_secs(60);

const OUTCOME_NONE: u8 = 0;
const OUTCOME_EXITED: u8 = 1;
const OUTCOME_SIGNALED: u8 = 2;
const OUTCOME_SERVICE_FAILURE: u8 = 3;

/// Stable, queryable invocation state used by both `Status` and `Wait`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct InvocationStatusWire {
    pub phase: u8,
    pub terminal: bool,
    pub outcome: u8,
    pub status: i32,
    pub signal: i32,
    pub core_dumped: bool,
    pub error_category: String,
}

impl InvocationStatusWire {
    fn authorizing() -> Self {
        Self {
            phase: PHASE_AUTHORIZING,
            terminal: false,
            outcome: OUTCOME_NONE,
            status: 0,
            signal: 0,
            core_dumped: false,
            error_category: String::new(),
        }
    }

    fn phase(phase: u8) -> Self {
        Self {
            phase,
            ..Self::authorizing()
        }
    }

    fn from_outcome(outcome: CommandOutcome) -> Self {
        match outcome {
            CommandOutcome::Exited(status) => Self {
                phase: PHASE_COMPLETE,
                terminal: true,
                outcome: OUTCOME_EXITED,
                status,
                signal: 0,
                core_dumped: false,
                error_category: String::new(),
            },
            CommandOutcome::Signaled {
                signal,
                core_dumped,
            } => Self {
                phase: PHASE_COMPLETE,
                terminal: true,
                outcome: OUTCOME_SIGNALED,
                status: 0,
                signal,
                core_dumped,
                error_category: String::new(),
            },
            CommandOutcome::ServiceFailure { .. } => Self {
                phase: PHASE_FAILED,
                terminal: true,
                outcome: OUTCOME_SERVICE_FAILURE,
                status: 0,
                signal: 0,
                core_dumped: false,
                error_category: "service-failure".to_owned(),
            },
        }
    }

    fn terminal_phase(phase: u8, category: &str) -> Self {
        Self {
            phase,
            terminal: true,
            outcome: OUTCOME_NONE,
            status: 0,
            signal: 0,
            core_dumped: false,
            error_category: category.to_owned(),
        }
    }
}

#[derive(Debug)]
struct InvocationState {
    status: InvocationStatusWire,
    pty_master: Option<OwnedFd>,
    released: bool,
}

#[derive(Debug)]
struct SharedInvocation {
    owner: String,
    cancellation: Cancellation,
    state: Mutex<InvocationState>,
    changed: Notify,
    terminal: Notify,
    owner_monitor: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SharedInvocation {
    fn new(owner: String, cancellation: Cancellation) -> Self {
        Self {
            owner,
            cancellation,
            state: Mutex::new(InvocationState {
                status: InvocationStatusWire::authorizing(),
                pty_master: None,
                released: false,
            }),
            changed: Notify::new(),
            terminal: Notify::new(),
            owner_monitor: Mutex::new(None),
        }
    }

    fn check_owner(&self, header: &Header<'_>) -> Result<(), BrokerDbusError> {
        let sender = header
            .sender()
            .ok_or_else(|| BrokerDbusError::AccessDenied("missing D-Bus sender".to_owned()))?;
        if sender.as_str() != self.owner {
            return Err(BrokerDbusError::AccessDenied(
                "invocation belongs to another D-Bus connection".to_owned(),
            ));
        }
        Ok(())
    }

    fn update(&self, status: InvocationStatusWire) {
        let terminal = status.terminal;
        self.state.lock().unwrap().status = status;
        self.changed.notify_waiters();
        if terminal {
            self.terminal.notify_waiters();
        }
    }

    async fn wait_until_terminal(&self) {
        loop {
            let notified = self.terminal.notified();
            if self.state.lock().unwrap().status.terminal {
                return;
            }
            notified.await;
        }
    }

    async fn wait_until_released(&self) {
        loop {
            let notified = self.changed.notified();
            if self.state.lock().unwrap().released {
                return;
            }
            notified.await;
        }
    }

    fn install_owner_monitor(&self, monitor: tokio::task::JoinHandle<()>) {
        *self.owner_monitor.lock().unwrap() = Some(monitor);
    }

    fn stop_owner_monitor(&self) {
        if let Some(monitor) = self.owner_monitor.lock().unwrap().take() {
            monitor.abort();
        }
    }

    fn install_pty(&self, pty_master: OwnedFd) {
        self.state.lock().unwrap().pty_master = Some(pty_master);
        self.changed.notify_waiters();
    }

    fn owner_lost(&self) {
        self.cancellation.cancel(CancellationReason::OwnerLost);
        let mut state = self.state.lock().unwrap();
        state.pty_master = None;
        state.released = true;
        drop(state);
        self.changed.notify_waiters();
    }
}

#[derive(Debug)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[derive(Debug)]
struct InvocationPermit {
    owner: String,
    limits: Arc<BrokerLimits>,
}

impl Drop for InvocationPermit {
    fn drop(&mut self) {
        self.limits.release_invocation(&self.owner);
    }
}

#[derive(Debug, Clone)]
struct InvocationObject {
    shared: Arc<SharedInvocation>,
    connection: Connection,
    path: OwnedObjectPath,
    _permit: Arc<InvocationPermit>,
}

impl InvocationObject {
    fn schedule_removal(&self) {
        let connection = self.connection.clone();
        let path = self.path.clone();
        let shared = self.shared.clone();
        tokio::spawn(async move {
            remove_invocation(&connection, path, &shared).await;
        });
    }
}

async fn remove_invocation(
    connection: &Connection,
    path: OwnedObjectPath,
    shared: &SharedInvocation,
) {
    let _ = connection
        .object_server()
        .remove::<InvocationObject, _>(path)
        .await;
    shared.stop_owner_monitor();
    shared.cancellation.cancel(CancellationReason::Caller);
    let mut state = shared.state.lock().unwrap();
    state.pty_master = None;
    state.released = true;
    drop(state);
    shared.changed.notify_waiters();
}

#[interface(name = "nz.passcod.sud0.Invocation1")]
impl InvocationObject {
    async fn status(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<InvocationStatusWire, BrokerDbusError> {
        self.shared.check_owner(&header)?;
        Ok(self.shared.state.lock().unwrap().status.clone())
    }

    async fn wait(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<InvocationStatusWire, BrokerDbusError> {
        self.shared.check_owner(&header)?;
        loop {
            let notified = self.shared.changed.notified();
            let status = self.shared.state.lock().unwrap().status.clone();
            if status.terminal {
                self.shared.state.lock().unwrap().released = true;
                self.schedule_removal();
                return Ok(status);
            }
            notified.await;
            self.shared.check_owner(&header)?;
        }
    }

    async fn cancel(&self, #[zbus(header)] header: Header<'_>) -> Result<(), BrokerDbusError> {
        self.shared.check_owner(&header)?;
        self.shared.cancellation.cancel(CancellationReason::Caller);
        Ok(())
    }

    async fn take_pty(
        &self,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<ZOwnedFd, BrokerDbusError> {
        self.shared.check_owner(&header)?;
        let state = self.shared.state.lock().unwrap();
        if state.status.phase < PHASE_RUNNING {
            return Err(BrokerDbusError::NotReady(
                "PTY is not available before startup".to_owned(),
            ));
        }
        let pty = state
            .pty_master
            .as_ref()
            .ok_or_else(|| BrokerDbusError::NotAvailable("invocation has no PTY".to_owned()))?;
        let duplicate = pty
            .as_fd()
            .try_clone_to_owned()
            .map_err(|_| BrokerDbusError::Failed("failed to duplicate PTY".to_owned()))?;
        Ok(duplicate.into())
    }

    async fn set_window_size(
        &self,
        size: WindowSize,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<(), BrokerDbusError> {
        self.shared.check_owner(&header)?;
        let state = self.shared.state.lock().unwrap();
        let pty = state
            .pty_master
            .as_ref()
            .ok_or_else(|| BrokerDbusError::NotAvailable("invocation has no PTY".to_owned()))?;
        set_pty_window_size(pty, size)
            .map_err(|_| BrokerDbusError::InvalidRequest("invalid PTY size".to_owned()))
    }

    async fn release(&self, #[zbus(header)] header: Header<'_>) -> Result<(), BrokerDbusError> {
        self.shared.check_owner(&header)?;
        let mut state = self.shared.state.lock().unwrap();
        if !state.status.terminal {
            return Err(BrokerDbusError::NotReady(
                "invocation has not completed".to_owned(),
            ));
        }
        state.released = true;
        state.pty_master = None;
        drop(state);
        self.shared.changed.notify_waiters();
        self.schedule_removal();
        Ok(())
    }
}

#[derive(Debug, Default)]
struct LimitState {
    invocations: HashMap<String, usize>,
    validations: HashMap<String, usize>,
}

#[derive(Debug, Default)]
struct BrokerLimits {
    state: Mutex<LimitState>,
}

impl BrokerLimits {
    fn acquire_invocation(
        self: &Arc<Self>,
        owner: &str,
    ) -> Result<Arc<InvocationPermit>, BrokerDbusError> {
        let mut state = self.state.lock().unwrap();
        let global = state.invocations.values().sum::<usize>();
        let owner_count = state.invocations.get(owner).copied().unwrap_or_default();
        if global >= MAX_GLOBAL_INVOCATIONS || owner_count >= MAX_OWNER_INVOCATIONS {
            return Err(BrokerDbusError::LimitsExceeded(
                "too many outstanding invocations".to_owned(),
            ));
        }
        state.invocations.insert(owner.to_owned(), owner_count + 1);
        Ok(Arc::new(InvocationPermit {
            owner: owner.to_owned(),
            limits: self.clone(),
        }))
    }

    fn acquire_validation(
        self: &Arc<Self>,
        owner: &str,
    ) -> Result<ValidationPermit, BrokerDbusError> {
        let mut state = self.state.lock().unwrap();
        let global = state.validations.values().sum::<usize>();
        let owner_count = state.validations.get(owner).copied().unwrap_or_default();
        if global >= MAX_GLOBAL_VALIDATIONS || owner_count >= MAX_OWNER_VALIDATIONS {
            return Err(BrokerDbusError::LimitsExceeded(
                "too many concurrent validations".to_owned(),
            ));
        }
        state.validations.insert(owner.to_owned(), owner_count + 1);
        Ok(ValidationPermit {
            owner: owner.to_owned(),
            limits: self.clone(),
        })
    }

    fn release_invocation(&self, owner: &str) {
        release_limit(&mut self.state.lock().unwrap().invocations, owner);
    }

    fn release_validation(&self, owner: &str) {
        release_limit(&mut self.state.lock().unwrap().validations, owner);
    }
}

fn release_limit(counts: &mut HashMap<String, usize>, owner: &str) {
    let Some(count) = counts.get_mut(owner) else {
        return;
    };
    *count -= 1;
    if *count == 0 {
        counts.remove(owner);
    }
}

#[derive(Debug)]
struct ValidationPermit {
    owner: String,
    limits: Arc<BrokerLimits>,
}

impl Drop for ValidationPermit {
    fn drop(&mut self) {
        self.limits.release_validation(&self.owner);
    }
}

/// Public broker manager registered at the stable service path.
#[derive(Debug, Clone)]
pub struct BrokerManager {
    connection: Connection,
    launcher: SystemdLauncher,
    limits: Arc<BrokerLimits>,
    shutdown: watch::Receiver<bool>,
}

impl BrokerManager {
    pub fn new(
        connection: Connection,
        launcher: SystemdLauncher,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            connection,
            launcher,
            limits: Arc::new(BrokerLimits::default()),
            shutdown,
        }
    }
}

#[interface(name = "nz.passcod.sud0.Manager1")]
impl BrokerManager {
    async fn run(
        &self,
        wire: RunWire,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<OwnedObjectPath, BrokerDbusError> {
        let caller = authenticated_caller(&self.connection, &header).await?;
        let permit = self.limits.acquire_invocation(caller.sender())?;
        let prepared = PreparedRequest::from_wire(wire)
            .map_err(|_| BrokerDbusError::InvalidRequest("invalid run request".to_owned()))?;
        let cancellation = Cancellation::new();
        let owner_changes = owner_change_stream(&self.connection, caller.sender()).await?;
        let path = random_invocation_path()?;
        let shared = Arc::new(SharedInvocation::new(
            caller.sender().to_owned(),
            cancellation.clone(),
        ));
        self.connection
            .object_server()
            .at(
                path.clone(),
                InvocationObject {
                    shared: shared.clone(),
                    connection: self.connection.clone(),
                    path: path.clone(),
                    _permit: permit.clone(),
                },
            )
            .await
            .map_err(BrokerDbusError::ZBus)?;

        let owner_monitor = spawn_owner_monitor(
            owner_changes,
            shared.clone(),
            self.connection.clone(),
            path.clone(),
        );
        shared.install_owner_monitor(owner_monitor);
        spawn_invocation_expiry(
            self.connection.clone(),
            path.clone(),
            shared.clone(),
            permit,
        );
        let connection = self.connection.clone();
        let launcher = self.launcher.clone();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            run_pipeline(
                connection,
                launcher,
                caller,
                prepared,
                shared,
                cancellation,
                shutdown,
            )
            .await;
        });
        Ok(path)
    }

    async fn validate(
        &self,
        allow_interaction: bool,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<bool, BrokerDbusError> {
        let caller = authenticated_caller(&self.connection, &header).await?;
        let _permit = self.limits.acquire_validation(caller.sender())?;
        let cancellation = Cancellation::new();
        let owner_changes = owner_change_stream(&self.connection, caller.sender()).await?;
        let _owner_monitor = AbortOnDrop(spawn_validation_owner_monitor(
            owner_changes,
            cancellation.clone(),
        ));
        let mut shutdown = self.shutdown.clone();
        let shutdown_cancellation = cancellation.clone();
        let _shutdown_monitor = AbortOnDrop(tokio::spawn(async move {
            if shutdown.changed().await.is_ok() && *shutdown.borrow() {
                shutdown_cancellation.cancel(CancellationReason::Shutdown);
            }
        }));
        let request = AuthorizationRequest::for_validation(&caller, allow_interaction)
            .map_err(|_| BrokerDbusError::Failed("authorization setup failed".to_owned()))?;
        let authority = ZbusAuthority::new(self.connection.clone());
        let outcome = authorize(&authority, &request, cancellation.subscribe())
            .await
            .map_err(|_| BrokerDbusError::Failed("authorization failed".to_owned()))?;
        if outcome != AuthorizationOutcome::Authorized {
            return Ok(false);
        }
        name_has_owner(&self.connection, caller.sender()).await
    }
}

async fn run_pipeline(
    connection: Connection,
    launcher: SystemdLauncher,
    caller: CallerIdentity,
    prepared: PreparedRequest,
    shared: Arc<SharedInvocation>,
    cancellation: Cancellation,
    mut shutdown: watch::Receiver<bool>,
) {
    let shutdown_cancellation = cancellation.clone();
    let _shutdown_monitor = AbortOnDrop(tokio::spawn(async move {
        if shutdown.changed().await.is_ok() && *shutdown.borrow() {
            shutdown_cancellation.cancel(CancellationReason::Shutdown);
        }
    }));

    let cwd_identity = match prepared.cwd().identity() {
        Ok(identity) => identity,
        Err(_) => {
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "authorization-setup",
            ));
            return;
        }
    };
    let cwd_path = match prepared.cwd().display_path() {
        Ok(path) => path,
        Err(_) => {
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "authorization-setup",
            ));
            return;
        }
    };
    let authorization = match AuthorizationRequest::for_run(
        &caller,
        prepared.request(),
        prepared.description(),
        &cwd_path,
        cwd_identity,
        prepared.allow_interaction(),
    ) {
        Ok(request) => request,
        Err(_) => {
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "authorization-setup",
            ));
            return;
        }
    };
    let authority = ZbusAuthority::new(connection.clone());
    let outcome = match authorize(&authority, &authorization, cancellation.subscribe()).await {
        Ok(outcome) => outcome,
        Err(_) => {
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "authorization",
            ));
            return;
        }
    };
    match outcome {
        AuthorizationOutcome::Authorized => {}
        AuthorizationOutcome::Denied | AuthorizationOutcome::Dismissed => {
            shared.update(InvocationStatusWire::terminal_phase(PHASE_DENIED, "denied"));
            return;
        }
        AuthorizationOutcome::Cancelled(_) => {
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_CANCELLED,
                "cancelled",
            ));
            return;
        }
    }

    match name_has_owner(&connection, caller.sender()).await {
        Ok(true) => {}
        Ok(false) => {
            cancellation.cancel(CancellationReason::OwnerLost);
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_CANCELLED,
                "owner-lost",
            ));
            return;
        }
        Err(_) => {
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "owner-check",
            ));
            return;
        }
    }
    if let Some(reason) = cancellation.reason() {
        let category = match reason {
            CancellationReason::OwnerLost => "owner-lost",
            CancellationReason::Caller | CancellationReason::Shutdown => "cancelled",
        };
        shared.update(InvocationStatusWire::terminal_phase(
            PHASE_CANCELLED,
            category,
        ));
        return;
    }

    shared.update(InvocationStatusWire::phase(PHASE_STARTING));
    let (request, cwd, io, _) = prepared.into_launch_parts();
    let started = match launcher
        .launch(
            LaunchRequest::new(request, cwd, io),
            cancellation.subscribe(),
        )
        .await
    {
        Ok(started) => started,
        Err(_) => {
            let phase = if cancellation.reason().is_some() {
                PHASE_CANCELLED
            } else {
                PHASE_FAILED
            };
            shared.update(InvocationStatusWire::terminal_phase(phase, "startup"));
            return;
        }
    };
    let (_unit_name, pty_master, completion) = started.into_parts();
    if let Some(master) = pty_master {
        shared.install_pty(master);
    }
    shared.update(InvocationStatusWire::phase(PHASE_RUNNING));
    match completion.wait().await {
        Ok(outcome) => shared.update(InvocationStatusWire::from_outcome(outcome)),
        Err(LaunchError::Systemd(error)) => {
            tracing::error!(error = %error, "failed to track transient command");
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "tracking-systemd",
            ));
        }
        Err(LaunchError::Cleanup(error)) => {
            tracing::error!(error = %error, "failed to clean up transient command");
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "tracking-cleanup",
            ));
        }
        Err(error) => {
            tracing::error!(error = %error, "failed to track transient command");
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "tracking",
            ));
        }
    }
}

async fn authenticated_caller(
    connection: &Connection,
    header: &Header<'_>,
) -> Result<CallerIdentity, BrokerDbusError> {
    let sender = header
        .sender()
        .ok_or_else(|| BrokerDbusError::AccessDenied("missing D-Bus sender".to_owned()))?
        .to_owned();
    let proxy = DBusProxy::new(connection)
        .await
        .map_err(|_| BrokerDbusError::Failed("D-Bus identity operation failed".to_owned()))?;
    let credentials = proxy
        .get_connection_credentials(sender.clone().into())
        .await
        .map_err(|_| BrokerDbusError::Failed("D-Bus identity operation failed".to_owned()))?;
    let uid = credentials
        .unix_user_id()
        .ok_or_else(|| BrokerDbusError::AccessDenied("caller has no Unix UID".to_owned()))?;
    let pid = credentials
        .process_id()
        .ok_or_else(|| BrokerDbusError::AccessDenied("caller has no process ID".to_owned()))?;
    let pidfd = credentials
        .process_fd()
        .ok_or_else(|| {
            BrokerDbusError::AccessDenied("caller has no process descriptor".to_owned())
        })?
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| {
            BrokerDbusError::Failed("failed to duplicate caller process descriptor".to_owned())
        })?;
    Ok(CallerIdentity::from_authenticated_sender(
        sender.as_str().to_owned(),
        uid,
        pid,
        pidfd,
    ))
}

async fn owner_change_stream(
    connection: &Connection,
    sender: &str,
) -> Result<zbus::fdo::NameOwnerChangedStream, BrokerDbusError> {
    let proxy = DBusProxy::new(connection)
        .await
        .map_err(|_| BrokerDbusError::Failed("D-Bus identity operation failed".to_owned()))?;
    proxy
        .receive_name_owner_changed_with_args(&[(0, sender)])
        .await
        .map_err(|_| BrokerDbusError::Failed("D-Bus identity operation failed".to_owned()))
}

fn spawn_owner_monitor(
    mut changes: zbus::fdo::NameOwnerChangedStream,
    shared: Arc<SharedInvocation>,
    connection: Connection,
    path: OwnedObjectPath,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(signal) = changes.next().await {
            let Ok(args) = signal.args() else {
                break;
            };
            if args.new_owner().is_none() {
                break;
            }
        }
        shared.owner_lost();
        remove_invocation(&connection, path, &shared).await;
    })
}

fn spawn_validation_owner_monitor(
    mut changes: zbus::fdo::NameOwnerChangedStream,
    cancellation: Cancellation,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(signal) = changes.next().await {
            let Ok(args) = signal.args() else {
                break;
            };
            if args.new_owner().is_none() {
                break;
            }
        }
        cancellation.cancel(CancellationReason::OwnerLost);
    })
}

fn spawn_invocation_expiry(
    connection: Connection,
    path: OwnedObjectPath,
    shared: Arc<SharedInvocation>,
    permit: Arc<InvocationPermit>,
) {
    tokio::spawn(async move {
        shared.wait_until_terminal().await;
        tokio::select! {
            () = shared.wait_until_released() => {}
            () = tokio::time::sleep(INVOCATION_EXPIRY) => {
                remove_invocation(&connection, path, &shared).await;
            }
        }
        drop(permit);
    });
}

async fn name_has_owner(connection: &Connection, sender: &str) -> Result<bool, BrokerDbusError> {
    let proxy = DBusProxy::new(connection)
        .await
        .map_err(|_| BrokerDbusError::Failed("D-Bus identity operation failed".to_owned()))?;
    let name = BusName::try_from(sender)
        .map_err(|_| BrokerDbusError::AccessDenied("invalid unique sender".to_owned()))?;
    proxy
        .name_has_owner(name)
        .await
        .map_err(|_| BrokerDbusError::Failed("D-Bus identity operation failed".to_owned()))
}

fn random_invocation_path() -> Result<OwnedObjectPath, BrokerDbusError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| BrokerDbusError::Failed("identifier generation failed".to_owned()))?;
    let path = format!("/nz/passcod/sud0/invocation/{}", hex::encode(random));
    OwnedObjectPath::try_from(path)
        .map_err(|_| BrokerDbusError::Failed("identifier generation failed".to_owned()))
}

#[derive(Debug, DBusError)]
#[zbus(prefix = "nz.passcod.sud0.Error")]
pub enum BrokerDbusError {
    AccessDenied(String),
    InvalidRequest(String),
    NotReady(String),
    NotAvailable(String),
    LimitsExceeded(String),
    Failed(String),
    #[zbus(error)]
    ZBus(zbus::Error),
}

/// Type-only client proxy for the public broker manager API.
#[zbus::proxy(
    interface = "nz.passcod.sud0.Manager1",
    default_service = "nz.passcod.sud0",
    default_path = "/nz/passcod/sud0",
    gen_blocking = false
)]
pub trait Manager {
    fn run(&self, request: RunWire) -> zbus::Result<OwnedObjectPath>;
    fn validate(&self, allow_interaction: bool) -> zbus::Result<bool>;
}

/// Type-only client proxy for owner-bound invocation objects.
#[zbus::proxy(interface = "nz.passcod.sud0.Invocation1", gen_blocking = false)]
pub trait Invocation {
    fn status(&self) -> zbus::Result<InvocationStatusWire>;
    fn wait(&self) -> zbus::Result<InvocationStatusWire>;
    fn cancel(&self) -> zbus::Result<()>;
    fn take_pty(&self) -> zbus::Result<ZOwnedFd>;
    fn set_window_size(&self, size: WindowSize) -> zbus::Result<()>;
    fn release(&self) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{BROKER_INVOCATION_INTERFACE, BROKER_MANAGER_INTERFACE};

    fn headerless_owner_check(shared: &SharedInvocation, sender: &str) -> bool {
        shared.owner == sender
    }

    #[test]
    fn status_mapping_never_contains_request_metadata() {
        let status = InvocationStatusWire::from_outcome(CommandOutcome::ServiceFailure {
            result: "exit-code".to_owned(),
            code: libc::CLD_EXITED,
            status: 22,
        });
        assert_eq!(status.error_category, "service-failure");
        assert!(!status.error_category.contains("exit-code"));
        assert!(status.terminal);
    }

    #[test]
    fn invocation_owner_is_transport_identity_not_object_path() {
        let shared = SharedInvocation::new(":1.7".to_owned(), Cancellation::new());
        assert!(headerless_owner_check(&shared, ":1.7"));
        assert!(!headerless_owner_check(&shared, ":1.8"));
        let first = random_invocation_path().unwrap();
        let second = random_invocation_path().unwrap();
        assert_ne!(first, second);
        assert!(!first.as_str().contains(":1.7"));
    }

    #[test]
    fn owner_loss_cancels_and_releases_descriptor_state() {
        let cancellation = Cancellation::new();
        let shared = SharedInvocation::new(":1.7".to_owned(), cancellation.clone());
        shared.owner_lost();
        assert_eq!(cancellation.reason(), Some(CancellationReason::OwnerLost));
        assert!(shared.state.lock().unwrap().released);
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum FakeAuthorization {
        Authorized,
        Denied,
        Cancelled,
    }

    fn fake_transaction(
        authorization: FakeAuthorization,
        owner_present: bool,
        events: &mut Vec<&'static str>,
    ) -> bool {
        events.push("authorize");
        if authorization != FakeAuthorization::Authorized {
            return false;
        }
        events.push("owner-recheck");
        if !owner_present {
            return false;
        }
        events.push("seal");
        events.push("launch");
        true
    }

    #[test]
    fn launch_sequence_is_authorize_recheck_seal_launch() {
        let mut events = Vec::new();
        assert!(fake_transaction(
            FakeAuthorization::Authorized,
            true,
            &mut events
        ));
        assert_eq!(events, ["authorize", "owner-recheck", "seal", "launch"]);
    }

    #[test]
    fn denied_cancelled_and_lost_owner_never_launch() {
        for (authorization, owner_present, expected) in [
            (FakeAuthorization::Denied, true, vec!["authorize"]),
            (FakeAuthorization::Cancelled, true, vec!["authorize"]),
            (
                FakeAuthorization::Authorized,
                false,
                vec!["authorize", "owner-recheck"],
            ),
        ] {
            let mut events = Vec::new();
            assert!(!fake_transaction(authorization, owner_present, &mut events));
            assert_eq!(events, expected);
        }
    }

    #[test]
    fn limits_are_per_owner_global_and_released_by_raii() {
        let limits = Arc::new(BrokerLimits::default());
        let mut first_owner = Vec::new();
        for _ in 0..MAX_OWNER_INVOCATIONS {
            first_owner.push(limits.acquire_invocation(":1.7").unwrap());
        }
        assert!(matches!(
            limits.acquire_invocation(":1.7"),
            Err(BrokerDbusError::LimitsExceeded(_))
        ));
        assert!(limits.acquire_invocation(":1.8").is_ok());

        drop(first_owner.pop());
        assert!(limits.acquire_invocation(":1.7").is_ok());

        let mut validations = Vec::new();
        for _ in 0..MAX_OWNER_VALIDATIONS {
            validations.push(limits.acquire_validation(":1.9").unwrap());
        }
        assert!(matches!(
            limits.acquire_validation(":1.9"),
            Err(BrokerDbusError::LimitsExceeded(_))
        ));
        drop(validations.pop());
        assert!(limits.acquire_validation(":1.9").is_ok());
    }

    #[test]
    fn exported_interfaces_match_constants() {
        assert_eq!(BROKER_MANAGER_INTERFACE, "nz.passcod.sud0.Manager1");
        assert_eq!(BROKER_INVOCATION_INTERFACE, "nz.passcod.sud0.Invocation1");
    }
}
