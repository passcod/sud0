use std::collections::HashMap;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
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
    CommandOutcome, LaunchError, LaunchRequest, PreparedRequest, PromptTemplate, RunWire,
    SystemdLauncher, WindowSize, set_pty_window_size,
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
const INVOCATION_EXPIRY: Duration = Duration::from_secs(60);

const OUTCOME_NONE: u8 = 0;
const OUTCOME_EXITED: u8 = 1;
const OUTCOME_SIGNALED: u8 = 2;
const OUTCOME_SERVICE_FAILURE: u8 = 3;

/// Stable, queryable invocation state used by both `Status` and `Wait`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Type)]
pub struct InvocationStatusWire {
    pub phase: u8,
    pub outcome: u8,
    pub status: i32,
    pub signal: i32,
    pub error_category: String,
}

impl InvocationStatusWire {
    pub const fn is_terminal(&self) -> bool {
        matches!(
            self.phase,
            PHASE_COMPLETE | PHASE_FAILED | PHASE_CANCELLED | PHASE_DENIED
        )
    }

    fn authorizing() -> Self {
        Self {
            phase: PHASE_AUTHORIZING,
            outcome: OUTCOME_NONE,
            status: 0,
            signal: 0,
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
                outcome: OUTCOME_EXITED,
                status,
                signal: 0,
                error_category: String::new(),
            },
            CommandOutcome::Signaled(signal) => Self {
                phase: PHASE_COMPLETE,
                outcome: OUTCOME_SIGNALED,
                status: 0,
                signal,
                error_category: String::new(),
            },
            CommandOutcome::ServiceFailure => Self {
                phase: PHASE_FAILED,
                outcome: OUTCOME_SERVICE_FAILURE,
                status: 0,
                signal: 0,
                error_category: "service-failure".to_owned(),
            },
        }
    }

    fn terminal_phase(phase: u8, category: &str) -> Self {
        Self {
            phase,
            outcome: OUTCOME_NONE,
            status: 0,
            signal: 0,
            error_category: category.to_owned(),
        }
    }
}

#[derive(Debug)]
struct InvocationState {
    status: InvocationStatusWire,
    pty_master: Option<OwnedFd>,
}

#[derive(Debug)]
struct SharedInvocation {
    owner: String,
    cancellation: Cancellation,
    state: Mutex<InvocationState>,
    changed: Notify,
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
            }),
            changed: Notify::new(),
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
        self.state.lock().unwrap().status = status;
        self.changed.notify_waiters();
    }

    async fn wait_until_terminal(&self) {
        loop {
            let notified = self.changed.notified();
            if self.state.lock().unwrap().status.is_terminal() {
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
        drop(state);
        self.changed.notify_waiters();
    }
}

#[derive(Debug)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);

#[derive(Debug, Default)]
struct PipelineState {
    active: usize,
    stopping: bool,
}

#[derive(Debug, Default)]
struct PipelineRegistry {
    state: Mutex<PipelineState>,
    idle: Notify,
}

impl PipelineRegistry {
    fn acquire(self: &Arc<Self>) -> Result<PipelinePermit, BrokerDbusError> {
        let mut state = self.state.lock().unwrap();
        if state.stopping {
            return Err(BrokerDbusError::Failed(
                "broker is shutting down".to_owned(),
            ));
        }
        state.active += 1;
        Ok(PipelinePermit(self.clone()))
    }

    async fn stop_and_wait(&self) {
        self.state.lock().unwrap().stopping = true;
        loop {
            let notified = self.idle.notified();
            if self.state.lock().unwrap().active == 0 {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Debug)]
struct PipelinePermit(Arc<PipelineRegistry>);

impl Drop for PipelinePermit {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().unwrap();
        state.active -= 1;
        let idle = state.active == 0;
        drop(state);
        if idle {
            self.0.idle.notify_waiters();
        }
    }
}

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
        let mut counts = self.limits.invocations.lock().unwrap();
        let count = counts
            .get_mut(&self.owner)
            .expect("active permit is counted");
        *count -= 1;
        if *count == 0 {
            counts.remove(&self.owner);
        }
    }
}

#[derive(Debug)]
struct InvocationObject {
    shared: Arc<SharedInvocation>,
    connection: Connection,
    path: OwnedObjectPath,
    _permit: InvocationPermit,
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
    shared.state.lock().unwrap().pty_master = None;
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
            if status.is_terminal() {
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
}

#[derive(Debug, Default)]
struct BrokerLimits {
    invocations: Mutex<HashMap<String, usize>>,
}

impl BrokerLimits {
    fn acquire_invocation(
        self: &Arc<Self>,
        owner: &str,
    ) -> Result<InvocationPermit, BrokerDbusError> {
        let mut invocations = self.invocations.lock().unwrap();
        let global = invocations.values().sum::<usize>();
        let owner_count = invocations.get(owner).copied().unwrap_or_default();
        if global >= MAX_GLOBAL_INVOCATIONS || owner_count >= MAX_OWNER_INVOCATIONS {
            return Err(BrokerDbusError::LimitsExceeded(
                "too many outstanding invocations".to_owned(),
            ));
        }
        invocations.insert(owner.to_owned(), owner_count + 1);
        Ok(InvocationPermit {
            owner: owner.to_owned(),
            limits: self.clone(),
        })
    }
}

/// Public broker manager registered at the stable service path.
#[derive(Clone)]
pub struct BrokerManager {
    connection: Connection,
    launcher: SystemdLauncher,
    prompt_template: Arc<PromptTemplate>,
    limits: Arc<BrokerLimits>,
    shutdown: watch::Receiver<bool>,
    pipelines: Arc<PipelineRegistry>,
}

impl BrokerManager {
    pub fn new(
        connection: Connection,
        launcher: SystemdLauncher,
        prompt_template: PromptTemplate,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            connection,
            launcher,
            prompt_template: Arc::new(prompt_template),
            limits: Arc::new(BrokerLimits::default()),
            shutdown,
            pipelines: Arc::new(PipelineRegistry::default()),
        }
    }

    pub async fn shutdown(&self) {
        self.pipelines.stop_and_wait().await;
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
        let pipeline_permit = self.pipelines.acquire()?;
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
                    _permit: permit,
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
        spawn_invocation_expiry(self.connection.clone(), path.clone(), shared.clone());
        let connection = self.connection.clone();
        let launcher = self.launcher.clone();
        let prompt_template = self.prompt_template.clone();
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            run_pipeline(RunPipeline {
                connection,
                launcher,
                prompt_template,
                caller,
                prepared,
                shared,
                cancellation,
                shutdown,
                _permit: pipeline_permit,
            })
            .await;
        });
        Ok(path)
    }
}

struct RunPipeline {
    connection: Connection,
    launcher: SystemdLauncher,
    prompt_template: Arc<PromptTemplate>,
    caller: CallerIdentity,
    prepared: PreparedRequest,
    shared: Arc<SharedInvocation>,
    cancellation: Cancellation,
    shutdown: watch::Receiver<bool>,
    _permit: PipelinePermit,
}

async fn run_pipeline(pipeline: RunPipeline) {
    let RunPipeline {
        connection,
        launcher,
        prompt_template,
        caller,
        prepared,
        shared,
        cancellation,
        mut shutdown,
        _permit,
    } = pipeline;
    let shutdown_cancellation = cancellation.clone();
    let _shutdown_monitor = AbortOnDrop(tokio::spawn(async move {
        if *shutdown.borrow() || shutdown.changed().await.is_ok() && *shutdown.borrow() {
            shutdown_cancellation.cancel(CancellationReason::Shutdown);
        }
    }));

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
        &prompt_template,
        prepared.request(),
        prepared.description(),
        &cwd_path,
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
    let outcome = match authorize(
        &authority,
        &caller,
        &authorization,
        cancellation.subscribe(),
    )
    .await
    {
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
        AuthorizationOutcome::Denied => {
            shared.update(InvocationStatusWire::terminal_phase(PHASE_DENIED, "denied"));
            return;
        }
        AuthorizationOutcome::Cancelled => {
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
    let (request, cwd, io) = prepared.into_launch_parts();
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
    let crate::StartedUnit {
        pty_master,
        completion,
    } = started;
    if let Some(master) = pty_master {
        shared.install_pty(master);
    }
    shared.update(InvocationStatusWire::phase(PHASE_RUNNING));
    match completion.wait().await {
        Ok(outcome) => shared.update(InvocationStatusWire::from_outcome(outcome)),
        Err(LaunchError::Systemd(error)) => {
            eprintln!("sud0-broker: failed to track transient command: {error}");
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "tracking-systemd",
            ));
        }
        Err(LaunchError::Cleanup(error)) => {
            eprintln!("sud0-broker: failed to clean up transient command: {error}");
            shared.update(InvocationStatusWire::terminal_phase(
                PHASE_FAILED,
                "tracking-cleanup",
            ));
        }
        Err(error) => {
            eprintln!("sud0-broker: failed to track transient command: {error}");
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
    let pidfd = credentials.process_fd().ok_or_else(|| {
        BrokerDbusError::AccessDenied("caller has no process descriptor".to_owned())
    })?;
    let (authorization_pid, authorization_pidfd) =
        authenticated_parent_process(pid, uid, pidfd.as_fd())?;
    Ok(CallerIdentity::from_authenticated_sender(
        sender.as_str().to_owned(),
        uid,
        authorization_pid,
        authorization_pidfd,
    ))
}

fn authenticated_parent_process(
    caller_pid: u32,
    caller_uid: u32,
    caller_pidfd: BorrowedFd<'_>,
) -> Result<(u32, OwnedFd), BrokerDbusError> {
    verify_pidfd_identifies(caller_pidfd, caller_pid)?;
    let parent_pid = read_parent_pid(caller_pid)?;
    if parent_pid <= 1 {
        return Err(BrokerDbusError::AccessDenied(
            "caller has no retainable parent process".to_owned(),
        ));
    }

    let parent = rustix::process::Pid::from_raw(parent_pid as i32)
        .ok_or_else(|| BrokerDbusError::AccessDenied("invalid caller parent process".to_owned()))?;
    let parent_pidfd = rustix::process::pidfd_open(parent, rustix::process::PidfdFlags::empty())
        .map_err(|_| BrokerDbusError::AccessDenied("caller parent process exited".to_owned()))?;
    verify_pidfd_identifies(parent_pidfd.as_fd(), parent_pid)?;

    // Re-read after pinning both processes to close PID reuse and reparenting races.
    verify_pidfd_identifies(caller_pidfd, caller_pid)?;
    if read_parent_pid(caller_pid)? != parent_pid {
        return Err(BrokerDbusError::AccessDenied(
            "caller parent changed during authentication".to_owned(),
        ));
    }
    if read_effective_uid(parent_pid)? != caller_uid {
        return Err(BrokerDbusError::AccessDenied(
            "caller parent belongs to another user".to_owned(),
        ));
    }

    Ok((parent_pid, parent_pidfd))
}

fn verify_pidfd_identifies(
    pidfd: BorrowedFd<'_>,
    expected_pid: u32,
) -> Result<(), BrokerDbusError> {
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd()))
        .map_err(|_| {
            BrokerDbusError::AccessDenied("process descriptor is no longer valid".to_owned())
        })?;
    let actual_pid = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:"))
        .and_then(|value| value.trim().parse::<u32>().ok())
        .ok_or_else(|| BrokerDbusError::AccessDenied("invalid process descriptor".to_owned()))?;
    if actual_pid != expected_pid {
        return Err(BrokerDbusError::AccessDenied(
            "process descriptor does not match process ID".to_owned(),
        ));
    }
    Ok(())
}

fn read_parent_pid(pid: u32) -> Result<u32, BrokerDbusError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| {
        BrokerDbusError::AccessDenied("failed to inspect caller process".to_owned())
    })?;
    let command_end = stat.rfind(')').ok_or_else(|| {
        BrokerDbusError::AccessDenied("invalid caller process metadata".to_owned())
    })?;
    stat.get(command_end + 2..)
        .and_then(|fields| fields.split_ascii_whitespace().nth(1))
        .and_then(|parent| parent.parse::<u32>().ok())
        .ok_or_else(|| BrokerDbusError::AccessDenied("invalid caller parent process".to_owned()))
}

fn read_effective_uid(pid: u32) -> Result<u32, BrokerDbusError> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|_| BrokerDbusError::AccessDenied("failed to inspect caller parent".to_owned()))?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|value| value.split_ascii_whitespace().nth(1))
        .and_then(|uid| uid.parse::<u32>().ok())
        .ok_or_else(|| BrokerDbusError::AccessDenied("invalid caller parent identity".to_owned()))
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

fn spawn_invocation_expiry(
    connection: Connection,
    path: OwnedObjectPath,
    shared: Arc<SharedInvocation>,
) {
    tokio::spawn(async move {
        shared.wait_until_terminal().await;
        tokio::time::sleep(INVOCATION_EXPIRY).await;
        remove_invocation(&connection, path, &shared).await;
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
}

/// Type-only client proxy for owner-bound invocation objects.
#[zbus::proxy(interface = "nz.passcod.sud0.Invocation1", gen_blocking = false)]
pub trait Invocation {
    fn status(&self) -> zbus::Result<InvocationStatusWire>;
    fn wait(&self) -> zbus::Result<InvocationStatusWire>;
    fn cancel(&self) -> zbus::Result<()>;
    fn take_pty(&self) -> zbus::Result<ZOwnedFd>;
    fn set_window_size(&self, size: WindowSize) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_never_contains_request_metadata() {
        let status = InvocationStatusWire::from_outcome(CommandOutcome::ServiceFailure);
        assert_eq!(status.error_category, "service-failure");
        assert!(status.is_terminal());
    }

    #[test]
    fn owner_loss_cancels_and_drops_descriptor_state() {
        let cancellation = Cancellation::new();
        let shared = SharedInvocation::new(":1.7".to_owned(), cancellation.clone());
        shared.install_pty(std::fs::File::open("/dev/null").unwrap().into());
        shared.owner_lost();
        assert_eq!(cancellation.reason(), Some(CancellationReason::OwnerLost));
        assert!(shared.state.lock().unwrap().pty_master.is_none());
    }

    #[tokio::test]
    async fn shutdown_rejects_new_pipelines_and_waits_for_active_pipeline() {
        let registry = Arc::new(PipelineRegistry::default());
        let permit = registry.acquire().unwrap();
        let shutdown = tokio::spawn({
            let registry = registry.clone();
            async move { registry.stop_and_wait().await }
        });
        tokio::task::yield_now().await;
        assert!(registry.acquire().is_err());
        assert!(!shutdown.is_finished());
        drop(permit);
        shutdown.await.unwrap();
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
        drop(first_owner.pop());
        first_owner.push(limits.acquire_invocation(":1.7").unwrap());

        let mut permits = first_owner;
        for owner in MAX_OWNER_INVOCATIONS..MAX_GLOBAL_INVOCATIONS {
            permits.push(limits.acquire_invocation(&format!(":1.{owner}")).unwrap());
        }
        assert!(matches!(
            limits.acquire_invocation(":1.next"),
            Err(BrokerDbusError::LimitsExceeded(_))
        ));
        drop(permits.pop());
        assert!(limits.acquire_invocation(":1.next").is_ok());
    }
}
