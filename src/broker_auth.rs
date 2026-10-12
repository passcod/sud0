use std::collections::HashMap;
use std::future::Future;
use std::os::fd::{AsFd, OwnedFd};

use thiserror::Error;
use tokio::sync::watch;
use zbus::zvariant::{Fd, Value};

use crate::constants::POLKIT_RUN_ACTION;
use crate::{FrozenRequest, HumanDescription, PromptTemplate, PromptTemplateError};

const POLKIT_ALLOW_USER_INTERACTION: u32 = 1;

#[zbus::proxy(
    interface = "org.freedesktop.PolicyKit1.Authority",
    default_service = "org.freedesktop.PolicyKit1",
    default_path = "/org/freedesktop/PolicyKit1/Authority",
    gen_blocking = false
)]
trait PolicyKitAuthority {
    fn check_authorization(
        &self,
        subject: (&str, HashMap<&str, Value<'_>>),
        action_id: &str,
        details: HashMap<&str, &str>,
        flags: u32,
        cancellation_id: &str,
    ) -> zbus::Result<(bool, bool, HashMap<String, String>)>;

    fn cancel_check_authorization(&self, cancellation_id: &str) -> zbus::Result<()>;
}

/// Authenticated identity attached to a broker method call.
///
/// The constructor is crate-private so only the D-Bus boundary can create this value from the
/// message header and `GetConnectionCredentials` result.
#[derive(Debug)]
pub struct CallerIdentity {
    sender: String,
    unix_uid: u32,
    authorization_process_id: u32,
    authorization_process_fd: OwnedFd,
}

impl CallerIdentity {
    pub(crate) fn from_authenticated_sender(
        sender: String,
        unix_uid: u32,
        authorization_process_id: u32,
        authorization_process_fd: OwnedFd,
    ) -> Self {
        Self {
            sender,
            unix_uid,
            authorization_process_id,
            authorization_process_fd,
        }
    }

    pub fn sender(&self) -> &str {
        &self.sender
    }

    pub const fn unix_uid(&self) -> u32 {
        self.unix_uid
    }

    pub const fn authorization_process_id(&self) -> u32 {
        self.authorization_process_id
    }

    pub fn authorization_process_fd(&self) -> &OwnedFd {
        &self.authorization_process_fd
    }
}

/// Fully broker-derived authorization request.
#[derive(Debug)]
pub struct AuthorizationRequest {
    message: String,
    flags: u32,
    cancellation_id: String,
}

impl AuthorizationRequest {
    pub fn for_run(
        template: &PromptTemplate,
        request: &FrozenRequest,
        description: Option<&HumanDescription>,
        cwd_path: &str,
        allow_interaction: bool,
    ) -> Result<Self, AuthorizationError> {
        Ok(Self {
            message: template.render(request, description, cwd_path)?,
            flags: u32::from(allow_interaction) * POLKIT_ALLOW_USER_INTERACTION,
            cancellation_id: random_identifier("sud0-auth")?,
        })
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub const fn flags(&self) -> u32 {
        self.flags
    }

    pub fn cancellation_id(&self) -> &str {
        &self.cancellation_id
    }
}

fn random_identifier(prefix: &str) -> Result<String, AuthorizationError> {
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random).map_err(AuthorizationError::Random)?;
    Ok(format!("{prefix}-{}", hex::encode(random)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancellationReason {
    Caller,
    OwnerLost,
    Shutdown,
}

/// A clonable cancellation source shared by the invocation object and owner/shutdown monitors.
#[derive(Debug, Clone)]
pub struct Cancellation {
    sender: watch::Sender<Option<CancellationReason>>,
}

impl Cancellation {
    pub fn new() -> Self {
        let (sender, _) = watch::channel(None);
        Self { sender }
    }

    pub fn cancel(&self, reason: CancellationReason) {
        let _ = self.sender.send_if_modified(|current| {
            if current.is_some() {
                false
            } else {
                *current = Some(reason);
                true
            }
        });
    }

    pub fn subscribe(&self) -> watch::Receiver<Option<CancellationReason>> {
        self.sender.subscribe()
    }

    pub fn reason(&self) -> Option<CancellationReason> {
        *self.sender.borrow()
    }
}

impl Default for Cancellation {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationOutcome {
    Authorized,
    Denied,
    Dismissed,
    Cancelled(CancellationReason),
}

pub(crate) trait Authority {
    fn check(
        &self,
        caller: &CallerIdentity,
        request: &AuthorizationRequest,
    ) -> impl Future<Output = Result<PolicyKitResult, AuthorizationError>> + Send;

    fn cancel(
        &self,
        cancellation_id: &str,
    ) -> impl Future<Output = Result<(), AuthorizationError>> + Send;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PolicyKitResult {
    authorized: bool,
    dismissed: bool,
}

/// Authorizes one request and gives explicit cancellation precedence over a racing completion.
pub(crate) async fn authorize<A: Authority>(
    authority: &A,
    caller: &CallerIdentity,
    request: &AuthorizationRequest,
    mut cancellation: watch::Receiver<Option<CancellationReason>>,
) -> Result<AuthorizationOutcome, AuthorizationError> {
    if let Some(reason) = *cancellation.borrow() {
        return Ok(AuthorizationOutcome::Cancelled(reason));
    }

    let check = authority.check(caller, request);
    tokio::pin!(check);

    tokio::select! {
        biased;
        changed = cancellation.changed() => {
            let reason = match changed {
                Ok(()) => (*cancellation.borrow()).unwrap_or(CancellationReason::Shutdown),
                Err(_) => CancellationReason::Shutdown,
            };
            // The result can legitimately report that the check has just completed. Cancellation
            // still wins locally and no authorization result from this check may permit launch.
            let _ = authority.cancel(request.cancellation_id()).await;
            Ok(AuthorizationOutcome::Cancelled(reason))
        }
        result = &mut check => {
            let result = result?;
            let cancellation_reason = *cancellation.borrow();
            if let Some(reason) = cancellation_reason {
                let _ = authority.cancel(request.cancellation_id()).await;
                return Ok(AuthorizationOutcome::Cancelled(reason));
            }
            if result.dismissed {
                Ok(AuthorizationOutcome::Dismissed)
            } else if result.authorized {
                Ok(AuthorizationOutcome::Authorized)
            } else {
                Ok(AuthorizationOutcome::Denied)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ZbusAuthority {
    connection: zbus::Connection,
}

impl ZbusAuthority {
    pub const fn new(connection: zbus::Connection) -> Self {
        Self { connection }
    }
}

impl Authority for ZbusAuthority {
    async fn check(
        &self,
        caller: &CallerIdentity,
        request: &AuthorizationRequest,
    ) -> Result<PolicyKitResult, AuthorizationError> {
        let proxy = PolicyKitAuthorityProxy::new(&self.connection)
            .await
            .map_err(AuthorizationError::PolicyKit)?;
        let mut subject_details = HashMap::new();
        subject_details.insert("pid", Value::new(caller.authorization_process_id()));
        subject_details.insert("start-time", Value::new(0_u64));
        subject_details.insert("uid", Value::new(caller.unix_uid() as i32));
        subject_details.insert(
            "pidfd",
            Value::new(Fd::from(caller.authorization_process_fd().as_fd())),
        );
        let mut details = HashMap::new();
        details.insert("polkit.message", request.message());
        let (authorized, _challenge, result_details) = proxy
            .check_authorization(
                ("unix-process", subject_details),
                POLKIT_RUN_ACTION,
                details,
                request.flags(),
                request.cancellation_id(),
            )
            .await
            .map_err(AuthorizationError::PolicyKit)?;
        Ok(PolicyKitResult {
            authorized,
            dismissed: result_details
                .get("polkit.dismissed")
                .is_some_and(|value| !value.is_empty()),
        })
    }

    async fn cancel(&self, cancellation_id: &str) -> Result<(), AuthorizationError> {
        let proxy = PolicyKitAuthorityProxy::new(&self.connection)
            .await
            .map_err(AuthorizationError::PolicyKit)?;
        proxy
            .cancel_check_authorization(cancellation_id)
            .await
            .map_err(AuthorizationError::PolicyKit)
    }
}

#[derive(Debug, Error)]
pub enum AuthorizationError {
    #[error("failed to render trusted authentication prompt: {0}")]
    Prompt(#[from] PromptTemplateError),
    #[error("failed to obtain a random authorization identifier: {0}")]
    Random(getrandom::Error),
    #[error("PolicyKit authorization failed")]
    PolicyKit(#[source] zbus::Error),
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use tokio::sync::Notify;

    use super::*;
    use crate::IoMode;

    fn caller() -> CallerIdentity {
        let pid = std::process::id();
        let pid = rustix::process::Pid::from_raw(pid as i32).unwrap();
        let pidfd = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty()).unwrap();
        CallerIdentity::from_authenticated_sender(
            ":1.42".to_owned(),
            nix::unistd::Uid::effective().as_raw(),
            std::process::id(),
            pidfd,
        )
    }

    fn request() -> FrozenRequest {
        FrozenRequest::new(
            vec!["/usr/bin/printf".to_owned(), "secret\n".to_owned()],
            Vec::new(),
            IoMode::Pipe,
        )
        .unwrap()
    }

    fn authorization(allow_interaction: bool) -> AuthorizationRequest {
        AuthorizationRequest::for_run(
            &PromptTemplate::parse("{command}".to_owned()).unwrap(),
            &request(),
            None,
            "/actual",
            allow_interaction,
        )
        .unwrap()
    }

    #[test]
    fn run_request_has_exact_broker_derived_policy_fields() {
        let description = HumanDescription::new("disk maintenance").unwrap();
        let template =
            PromptTemplate::parse("{description_line}|{command}|{cwd}".to_owned()).unwrap();
        let check = AuthorizationRequest::for_run(
            &template,
            &request(),
            Some(&description),
            "/actual",
            true,
        )
        .unwrap();

        assert_eq!(check.flags(), 1);
        assert_eq!(
            check.message(),
            template
                .render(&request(), Some(&description), "/actual")
                .unwrap()
        );
        assert!(!check.cancellation_id().is_empty());
    }

    #[test]
    fn cancellation_identifiers_are_nonempty_and_unique() {
        let first = authorization(false);
        let second = authorization(false);
        assert_ne!(first.cancellation_id(), second.cancellation_id());
    }

    #[derive(Debug)]
    struct FakeAuthority {
        result: PolicyKitResult,
        release: Arc<Notify>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl Authority for FakeAuthority {
        async fn check(
            &self,
            _caller: &CallerIdentity,
            request: &AuthorizationRequest,
        ) -> Result<PolicyKitResult, AuthorizationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("check:{}", request.cancellation_id()));
            self.release.notified().await;
            Ok(self.result.clone())
        }

        async fn cancel(&self, cancellation_id: &str) -> Result<(), AuthorizationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("cancel:{cancellation_id}"));
            Ok(())
        }
    }

    #[tokio::test]
    async fn explicit_cancellation_cancels_same_check_and_never_authorizes() {
        let release = Arc::new(Notify::new());
        let calls = Arc::new(Mutex::new(Vec::new()));
        let authority = FakeAuthority {
            result: PolicyKitResult {
                authorized: true,
                dismissed: false,
            },
            release,
            calls: calls.clone(),
        };
        let request = authorization(true);
        let cancellation = Cancellation::new();
        let caller = caller();
        let future = authorize(&authority, &caller, &request, cancellation.subscribe());
        tokio::pin!(future);
        let state = std::future::poll_fn(|context| {
            std::task::Poll::Ready(future.as_mut().poll(context))
        })
        .await;
        assert!(state.is_pending());
        cancellation.cancel(CancellationReason::Caller);

        assert_eq!(
            future.await.unwrap(),
            AuthorizationOutcome::Cancelled(CancellationReason::Caller)
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], format!("check:{}", request.cancellation_id()));
        assert_eq!(calls[1], format!("cancel:{}", request.cancellation_id()));
    }

    #[tokio::test]
    async fn cancellation_wins_a_ready_authorization_race() {
        let release = Arc::new(Notify::new());
        let authority = FakeAuthority {
            result: PolicyKitResult {
                authorized: true,
                dismissed: false,
            },
            release: release.clone(),
            calls: Arc::new(Mutex::new(Vec::new())),
        };
        let request = authorization(true);
        let cancellation = Cancellation::new();
        let caller = caller();
        let future = authorize(&authority, &caller, &request, cancellation.subscribe());
        tokio::pin!(future);
        let state = std::future::poll_fn(|context| {
            std::task::Poll::Ready(future.as_mut().poll(context))
        })
        .await;
        assert!(state.is_pending());
        release.notify_one();
        cancellation.cancel(CancellationReason::OwnerLost);

        assert_eq!(
            future.await.unwrap(),
            AuthorizationOutcome::Cancelled(CancellationReason::OwnerLost)
        );
    }

    #[tokio::test]
    async fn only_authorized_boolean_permits_authorized_outcome() {
        for (result, expected) in [
            (
                PolicyKitResult {
                    authorized: true,
                    dismissed: false,
                },
                AuthorizationOutcome::Authorized,
            ),
            (
                PolicyKitResult {
                    authorized: false,
                    dismissed: false,
                },
                AuthorizationOutcome::Denied,
            ),
            (
                PolicyKitResult {
                    authorized: true,
                    dismissed: true,
                },
                AuthorizationOutcome::Dismissed,
            ),
        ] {
            let release = Arc::new(Notify::new());
            release.notify_one();
            let authority = FakeAuthority {
                result,
                release,
                calls: Arc::new(Mutex::new(Vec::new())),
            };
            let request = authorization(false);
            let cancellation = Cancellation::new();
            assert_eq!(
                authorize(&authority, &caller(), &request, cancellation.subscribe())
                    .await
                    .unwrap(),
                expected
            );
        }
    }
}
