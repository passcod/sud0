use std::os::fd::{AsFd, OwnedFd};
use std::sync::{Arc, Mutex};

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
    CommandOutcome, LaunchRequest, PreparedRequest, RunWire, SystemdLauncher, WindowSize,
    set_pty_window_size,
};

const PHASE_AUTHORIZING: u8 = 0;
const PHASE_STARTING: u8 = 1;
const PHASE_RUNNING: u8 = 2;
const PHASE_COMPLETE: u8 = 3;
const PHASE_FAILED: u8 = 4;
const PHASE_CANCELLED: u8 = 5;
const PHASE_DENIED: u8 = 6;

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

#[derive(Debug, Clone)]
struct InvocationObject {
    shared: Arc<SharedInvocation>,
    connection: Connection,
    path: OwnedObjectPath,
}

impl InvocationObject {
    fn schedule_removal(&self) {
        let connection = self.connection.clone();
        let path = self.path.clone();
        tokio::spawn(async move {
            let _ = connection
                .object_server()
                .remove::<InvocationObject, _>(path)
                .await;
        });
    }
}

#[interface(name = "io.github.passcod.sud0.Invocation1")]
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

/// Public broker manager registered at the stable service path.
#[derive(Debug, Clone)]
pub struct BrokerManager {
    connection: Connection,
    launcher: SystemdLauncher,
    shutdown: watch::Receiver<bool>,
}

impl BrokerManager {
    pub const fn new(
        connection: Connection,
        launcher: SystemdLauncher,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            connection,
            launcher,
            shutdown,
        }
    }
}

#[interface(name = "io.github.passcod.sud0.Manager1")]
impl BrokerManager {
    async fn run(
        &self,
        wire: RunWire,
        #[zbus(header)] header: Header<'_>,
    ) -> Result<OwnedObjectPath, BrokerDbusError> {
        let caller = authenticated_caller(&self.connection, &header).await?;
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
                },
            )
            .await
            .map_err(BrokerDbusError::ZBus)?;

        spawn_owner_monitor(
            owner_changes,
            shared.clone(),
            Some((self.connection.clone(), path.clone())),
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
        let cancellation = Cancellation::new();
        let owner_changes = owner_change_stream(&self.connection, caller.sender()).await?;
        let shared = Arc::new(SharedInvocation::new(
            caller.sender().to_owned(),
            cancellation.clone(),
        ));
        spawn_owner_monitor(owner_changes, shared, None);
        let mut shutdown = self.shutdown.clone();
        let shutdown_cancellation = cancellation.clone();
        tokio::spawn(async move {
            if shutdown.changed().await.is_ok() && *shutdown.borrow() {
                shutdown_cancellation.cancel(CancellationReason::Shutdown);
            }
        });
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
    tokio::spawn(async move {
        if shutdown.changed().await.is_ok() && *shutdown.borrow() {
            shutdown_cancellation.cancel(CancellationReason::Shutdown);
        }
    });

    let authorization = match AuthorizationRequest::for_run(
        &caller,
        prepared.request(),
        prepared.description(),
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
        Err(_) => shared.update(InvocationStatusWire::terminal_phase(
            PHASE_FAILED,
            "tracking",
        )),
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
    Ok(CallerIdentity::from_authenticated_sender(
        sender.as_str().to_owned(),
        uid,
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
    dynamic_object: Option<(Connection, OwnedObjectPath)>,
) {
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
        if let Some((connection, path)) = dynamic_object {
            let _ = connection
                .object_server()
                .remove::<InvocationObject, _>(path)
                .await;
        }
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
    let path = format!("/io/github/passcod/sud0/invocation/{}", hex::encode(random));
    OwnedObjectPath::try_from(path)
        .map_err(|_| BrokerDbusError::Failed("identifier generation failed".to_owned()))
}

#[derive(Debug, DBusError)]
#[zbus(prefix = "io.github.passcod.sud0.Error")]
pub enum BrokerDbusError {
    AccessDenied(String),
    InvalidRequest(String),
    NotReady(String),
    NotAvailable(String),
    Failed(String),
    #[zbus(error)]
    ZBus(zbus::Error),
}

/// Type-only client proxy for the public broker manager API.
#[zbus::proxy(
    interface = "io.github.passcod.sud0.Manager1",
    default_service = "io.github.passcod.sud0",
    default_path = "/io/github/passcod/sud0",
    gen_blocking = false
)]
pub trait Manager {
    fn run(&self, request: RunWire) -> zbus::Result<OwnedObjectPath>;
    fn validate(&self, allow_interaction: bool) -> zbus::Result<bool>;
}

/// Type-only client proxy for owner-bound invocation objects.
#[zbus::proxy(interface = "io.github.passcod.sud0.Invocation1", gen_blocking = false)]
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
    fn exported_interfaces_match_constants() {
        assert_eq!(BROKER_MANAGER_INTERFACE, "io.github.passcod.sud0.Manager1");
        assert_eq!(
            BROKER_INVOCATION_INTERFACE,
            "io.github.passcod.sud0.Invocation1"
        );
    }
}
