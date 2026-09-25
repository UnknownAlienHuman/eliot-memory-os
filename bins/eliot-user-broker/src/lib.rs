//! Production composition root for the A-09 user broker.
//!
//! The binary owns only process lifetime and durable registration wiring. G-01
//! and P-04 remain explicit provider boundaries; this root never manufactures
//! authority or process evidence when those providers are not composed.
//!
//! Issue #74 makes the per-operation identity ledger durable. The protected
//! launch binding still carries stable caller/launch fields only and never a
//! per-operation [`eliot_protocol::RequestIdentity`]; instead every identity
//! the issuer spends is projected into the same atomic snapshot publication as
//! the registration state, and a restarted broker re-seeds its issuer from that
//! recovered ledger before `self_register` can mint. A restart therefore
//! continues from the protected launch/caller identity plus a *new*
//! registration operation and never revives a historical request id,
//! cancellation id, or idempotency key.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_notify::NotifyLaunchRequestReference;
use eliot_platform::ClockObservation;
use eliot_platform::WorkScopePath;
use eliot_platform_windows::{ProtectedPathLease, WindowsPlatform};
use eliot_process::{
    ActionLeaseRef, CancellationReceipt, DispatchAuthorityId, DispatchPermitAuthority,
    DispatchValidationContext, FencingToken, KernelDispatchKey, OperationId, PermitIssuance,
    ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView,
    ProcessExecutor, ProcessIntent, ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_user_broker_core::{
    AuthorityPort, BrokerAdmissionIdentity, BrokerControlOperation, BrokerError, BrokerSnapshot,
    DurableRegistrationPort, HeartbeatReceipt, HeartbeatRequest, IssuedOperationIdentity,
    IssuedOperationIdentityLedger, LaunchGrant, LaunchRequest, LostOperation, PortError,
    ProcessPort, ProcessStartOutcome, RegistrationReceipt, RegistrationStatus, RequiredProvider,
    UserBroker,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod kernel_authority_port;
mod notify_fallback_ensure;
pub mod notify_launch_callin;
pub mod notify_request_channel;
mod operation_identity;
mod protected_launch_config;
use kernel_authority_port::KernelAuthorityPort;
pub use notify_fallback_ensure::{
    LiveNotifyFallbackEffects, NotifyFallbackEffects, NotifyFallbackEnsure,
    NotifyFallbackRegistration, ensure_notify_fallback_registered,
};
pub use notify_launch_callin::{
    BrokerNotifyError, BrokerNotifyLaunchAuthority, NotifyLaunchStage, VerifiedLaunchRef,
    admit_notify_request, request_names_notify_image, resolve_broker_notify_launch,
    stage_normal_notify_launch,
};
pub use notify_request_channel::{NotifyRequestChannelError, build_notify_request_channel};
use operation_identity::{
    BrokerOperation, DurableIssuedIdentity, IssuerHandle, OperationIdentityIssuer,
};
use protected_launch_config::{
    BrokerLaunchBinding, BrokerProcessBinding, REGISTRATION_LEASE_TTL_MS, binding_digest,
    current_process_binding, current_process_identity, fresh_registration_request,
    load_protected_launch_binding,
};

pub const SERVICE_NAME: &str = "eliot-user-broker";
pub const PROTOCOL_VERSION: &str = "eliot.user-broker.v1";
const SNAPSHOT_RELATIVE_DIRECTORY: &str = "Eliot/user-broker";
const SNAPSHOT_LIMIT: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrokerConfig {
    pub data_root: PathBuf,
    pub snapshot_name: String,
}

impl BrokerConfig {
    pub fn from_root(data_root: impl Into<PathBuf>) -> Self {
        Self {
            data_root: data_root.into(),
            snapshot_name: "user-broker.snapshot.json".to_owned(),
        }
    }

    fn validate(&self) -> Result<(), CompositionError> {
        if !self.data_root.is_absolute() {
            return Err(CompositionError::InvalidConfiguration(
                "data_root must be an absolute path".to_owned(),
            ));
        }
        if self.snapshot_name.trim().is_empty()
            || Path::new(&self.snapshot_name).components().count() != 1
        {
            return Err(CompositionError::InvalidConfiguration(
                "snapshot_name must be one file name".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Typed, closed refusal taxonomy for the broker's own admission boundary.
///
/// A refusal keeps its exact cause across the composition and reaches the
/// operation stream as its own stable code. Collapsing these into one
/// "composition rejected" string would make an unverifiable principal
/// indistinguishable from a lost lease, which is precisely the read the
/// registration contour must never leave ambiguous.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Error)]
pub enum BrokerAdmissionRefusal {
    /// The live process identity (id, start instant, or running image) could
    /// not be proven, or the running image is not the executable this process
    /// started from.
    #[error("BROKER_PROCESS_IDENTITY_UNPROVABLE")]
    ProcessIdentityUnprovable,
    /// The live process identity changed after admission: a replaced image, a
    /// recycled process id, or a substituted process.
    #[error("BROKER_PROCESS_IDENTITY_CHANGED")]
    ProcessIdentityChanged,
    /// The durable registration belongs to another installation, SID, logon
    /// Session, or boot Session, so this broker is not its owner.
    #[error("BROKER_REGISTRATION_IDENTITY_FOREIGN")]
    RegistrationIdentityForeign,
    /// A broker-owned control operation named an effect whose outcome is not
    /// yet proven; it must be reconciled before it can be cancelled.
    #[error("BROKER_OPERATION_OUTCOME_UNRECONCILED")]
    OperationOutcomeUnreconciled,
    /// The launch's tool is not in the introduced operation set.
    #[error("CAPABILITY_INTRODUCTION_REQUIRED")]
    IntroductionOperationNotGranted,
    /// The launch's resource root is not in the introduced resource set.
    #[error("CAPABILITY_INTRODUCTION_REQUIRED")]
    IntroductionResourceNotGranted,
    /// The launch's effect ceiling exceeds the introduced ceiling.
    #[error("CAPABILITY_INTRODUCTION_REQUIRED")]
    IntroductionEffectCeilingExceeded,
    /// The grant introduces no resource or credential for this launch.
    #[error("CAPABILITY_INTRODUCTION_REQUIRED")]
    IntroductionRequired,
    /// The introduced resource or credential lease is not active.
    #[error("CAPABILITY_GRANT_REVOKED")]
    IntroductionExpired,
    /// The launch's credential is not the one its introduction names.
    #[error("CAPABILITY_INTRODUCTION_REQUIRED")]
    IntroductionCredentialUnnamed,
    /// An operation identity was already spent under a fenced generation.
    #[error("IDENTITY_CONFLICT")]
    OperationIdRetired,
    /// An exact replay of an operation that a fenced generation already
    /// spent, under a new generation.
    #[error("UNKNOWN_OUTCOME")]
    RetiredOperation,
}

impl BrokerAdmissionRefusal {
    /// Returns the exact stable wire code of this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProcessIdentityUnprovable => "BROKER_PROCESS_IDENTITY_UNPROVABLE",
            Self::ProcessIdentityChanged => "BROKER_PROCESS_IDENTITY_CHANGED",
            Self::RegistrationIdentityForeign => "BROKER_REGISTRATION_IDENTITY_FOREIGN",
            Self::OperationOutcomeUnreconciled => "BROKER_OPERATION_OUTCOME_UNRECONCILED",
            Self::IntroductionOperationNotGranted
            | Self::IntroductionResourceNotGranted
            | Self::IntroductionEffectCeilingExceeded
            | Self::IntroductionRequired
            | Self::IntroductionCredentialUnnamed => "CAPABILITY_INTRODUCTION_REQUIRED",
            Self::IntroductionExpired => "CAPABILITY_GRANT_REVOKED",
            Self::OperationIdRetired => "IDENTITY_CONFLICT",
            Self::RetiredOperation => "UNKNOWN_OUTCOME",
        }
    }

    /// Attaches the adapter detail that explains *why* the refusal happened
    /// without letting that detail become the refusal's identity.
    pub fn with_platform(self, detail: impl std::fmt::Display) -> CompositionError {
        CompositionError::Admission {
            refusal: self,
            detail: detail.to_string(),
        }
    }
}

#[derive(Debug, Error)]
pub enum CompositionError {
    #[error("invalid broker configuration: {0}")]
    InvalidConfiguration(String),
    #[error("durable registration: {0}")]
    Durable(#[source] io::Error),
    #[error("snapshot encoding: {0}")]
    Encoding(#[from] serde_json::Error),
    #[error("protected broker path: {0}")]
    Protected(String),
    #[error("protected launch configuration: {0}")]
    Launch(String),
    #[error("broker admission refused: {refusal} ({detail})")]
    Admission {
        /// Exact closed refusal cause.
        refusal: BrokerAdmissionRefusal,
        /// Adapter detail explaining the refusal; never its identity.
        detail: String,
    },
    #[error("broker recovery: {0}")]
    Recovery(#[source] BrokerError),
    #[error("Kernel front-door composition: {0}")]
    Kernel(String),
    #[error("Kernel front-door lock poisoned")]
    KernelLock,
    /// The durable per-operation identity ledger recovered at startup
    /// contradicts itself or the retained launch declaration. The broker
    /// refuses to start rather than mint an identity a previous process
    /// already spent.
    #[error("durable operation identity ledger conflict: {0}")]
    OperationIdentityLedger(String),
    /// One broker-owned Kernel operation lost its acknowledgement. The exact
    /// transport identity that issued it is named so the outcome is reconciled
    /// by operation identity (issue #74 A6), never by a blind retry: a new
    /// registration refresh, a second logoff, or a second launch is not
    /// created from this path.
    #[error(
        "Kernel {operation} acknowledgement is unknown for request {request_id} (cancellation {cancellation_id}, idempotency key {idempotency_key}, canonical digest {canonical_digest}); the exact operation must be reconciled before any further effect"
    )]
    LostOperation {
        /// Closed Kernel operation selector that issued the identity.
        operation: &'static str,
        /// Exact transport request id of the issued identity.
        request_id: String,
        /// Exact transport cancellation id of the issued identity.
        cancellation_id: String,
        /// Exact transport idempotency key of the issued identity.
        idempotency_key: String,
        /// Canonical digest of the exact operation payload.
        canonical_digest: String,
    },
}

type SharedKernelClient = Arc<Mutex<eliot_cli::kernel_client::KernelClient>>;

/// Projects the composed per-operation identity issuer into the durable
/// broker snapshot.
///
/// This is the one place where broker-local transport identity strings become
/// durable state. It carries no authority: the registration receipt beside it
/// in the same snapshot remains the only registration/epoch evidence, and the
/// broker-local `user_broker_epoch` scalar is never copied into these rows.
struct IssuedIdentityLedger {
    issuer: IssuerHandle,
}

impl IssuedOperationIdentityLedger for IssuedIdentityLedger {
    fn issued_operation_identities(&self) -> Vec<IssuedOperationIdentity> {
        match self.issuer.lock() {
            Ok(issuer) => issuer
                .issued_identities()
                .into_iter()
                .map(IssuedOperationIdentity::from)
                .collect(),
            // A poisoned identity lock must not silently drop the spent
            // identities from the durable snapshot; returning the empty
            // projection makes the next issuance fail closed instead.
            Err(_) => Vec::new(),
        }
    }
}

impl From<DurableIssuedIdentity> for IssuedOperationIdentity {
    fn from(issued: DurableIssuedIdentity) -> Self {
        Self {
            operation: issued.operation,
            canonical_digest: issued.canonical_digest,
            request_id: issued.request_id,
            idempotency_key: issued.idempotency_key,
            cancellation_id: issued.cancellation_id,
            deadline_unix_ms: issued.deadline_unix_ms,
            issued_at_ms: issued.issued_at_ms,
            caller_request_id: issued.caller_request_id,
        }
    }
}

impl From<&IssuedOperationIdentity> for DurableIssuedIdentity {
    fn from(issued: &IssuedOperationIdentity) -> Self {
        Self {
            operation: issued.operation.clone(),
            canonical_digest: issued.canonical_digest.clone(),
            request_id: issued.request_id.clone(),
            idempotency_key: issued.idempotency_key.clone(),
            cancellation_id: issued.cancellation_id.clone(),
            deadline_unix_ms: issued.deadline_unix_ms,
            issued_at_ms: issued.issued_at_ms,
            caller_request_id: issued.caller_request_id.clone(),
        }
    }
}

/// Retains observation-only process evidence without granting any additional
/// authority to the broker or its callers.
struct BrokerEvidenceSink {
    records: Arc<Mutex<Vec<ProcessEvidence>>>,
}

impl ProcessEvidenceSink for BrokerEvidenceSink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), eliot_process::EvidenceSinkError> {
        self.records
            .lock()
            .map_err(|_| eliot_process::EvidenceSinkError {
                message: "broker evidence lock poisoned".to_owned(),
            })?
            .push(evidence);
        Ok(())
    }
}

/// Ephemeral broker-owned P-03 authority.  The key is generated in memory at
/// composition time and never crosses the launch-grant or stdin boundary;
/// `DispatchPermitAuthority` supplies the one-shot replay fence.
struct BrokerDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl BrokerDispatchAuthority {
    fn new() -> Result<Self, PortError> {
        let authority_id =
            DispatchAuthorityId::new(format!("user-broker-{}", uuid::Uuid::new_v4().simple()))
                .map_err(|error| PortError::Invalid(error.to_string()))?;
        let mut key = [0_u8; 32];
        let nonce = uuid::Uuid::new_v4().as_bytes().to_owned();
        key[..16].copy_from_slice(&nonce);
        key[16..].copy_from_slice(&Sha256::digest(nonce)[..16]);
        let key = KernelDispatchKey::from_secret_bytes(key)
            .map_err(|error| PortError::Invalid(error.to_string()))?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    fn issue(
        &self,
        intent: &ProcessIntent,
        grant: &LaunchGrant,
        now: u64,
    ) -> Result<ProcessRequest, PortError> {
        // INTENDED EpochId shape (Split C broker mint + Split A cutover):
        // LaunchGrant.authority_epoch is EpochId; FencingToken::new(EpochId).
        // B→A→C order; do not edit A/B files.
        let fence = FencingToken::new(
            grant.authority_epoch.clone(),
            grant.approved.generation,
            grant.approved.process_fence_nonce.clone(),
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        let issuance = PermitIssuance::new(
            ActionLeaseRef::new(grant.approved.idempotency_key.clone())
                .map_err(|error| PortError::Invalid(error.to_string()))?,
            fence.clone(),
            BTreeMap::from([("launch-grant".to_owned(), grant.grant_digest.clone())]),
            now.saturating_sub(1).max(1),
            grant.expires_at,
            grant.grant_digest.clone(),
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| PortError::Unknown)?
            .issue(intent, issuance)
            .map_err(|error| PortError::Invalid(error.to_string()))?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(now).unwrap_or(i64::MAX)),
                known_time_ms: Some(i64::try_from(now).unwrap_or(i64::MAX)),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            grant.authority_epoch.clone(),
            BTreeMap::from([("launch-grant".to_owned(), grant.grant_digest.clone())]),
            1,
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        *self.context.lock().map_err(|_| PortError::Unknown)? = Some(context);
        ProcessRequest::new(intent.clone(), permit)
            .map_err(|error| PortError::Invalid(error.to_string()))
    }
}

impl DispatchValidationPort for BrokerDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("broker context lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("missing broker validation context".to_owned())
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("broker authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}

/// Local P-04 composition for the interactive user's Job/process contour.
/// Kernel only supplies a typed `LaunchGrant`; this adapter never sends the
/// sealed P-03 request over EBP.
struct LocalProcessPort {
    authority: Arc<BrokerDispatchAuthority>,
    executor: WindowsProcessExecutor,
    runtime: tokio::runtime::Runtime,
    evidence: Arc<Mutex<Vec<ProcessEvidence>>>,
    pending_requests: BTreeMap<OperationId, ProcessRequest>,
    identity_issuer: Option<IssuerHandle>,
}

impl LocalProcessPort {
    fn new() -> Result<Self, CompositionError> {
        let authority = Arc::new(
            BrokerDispatchAuthority::new()
                .map_err(|error| CompositionError::Kernel(error.to_string()))?,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CompositionError::Kernel(error.to_string()))?;
        let executor = WindowsProcessExecutor::new(authority.clone());
        Ok(Self {
            authority,
            executor,
            runtime,
            evidence: Arc::new(Mutex::new(Vec::new())),
            pending_requests: BTreeMap::new(),
            identity_issuer: None,
        })
    }

    /// Attaches the operation-identity issuer for process/effect lineage
    /// bookkeeping. Lineage never blocks an effect; a missing issuer only
    /// omits the broker-local lineage entry.
    pub(crate) fn set_identity_issuer(&mut self, issuer: IssuerHandle) {
        self.identity_issuer = Some(issuer);
    }

    fn note_process_effect(
        &self,
        caller_request_id: &str,
        grant_request_digest: &str,
        process_request_digest: &str,
    ) {
        let now = Self::now_ms().unwrap_or(0);
        if let Some(issuer) = self.identity_issuer.as_ref()
            && let Ok(mut issuer) = issuer.lock()
        {
            issuer.note_process_effect(
                caller_request_id,
                grant_request_digest,
                process_request_digest,
                now,
            );
        }
    }

    fn now_ms() -> Result<u64, PortError> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| PortError::Invalid(error.to_string()))
            .and_then(|duration| {
                u64::try_from(duration.as_millis())
                    .map_err(|error| PortError::Invalid(error.to_string()))
            })
    }

    fn request_from_grant(&self, grant: &LaunchGrant) -> Result<ProcessRequest, PortError> {
        let now = Self::now_ms()?;
        if grant.expires_at <= now {
            return Err(PortError::Denied);
        }
        // The introduced user-session resource/credential has its own
        // deadline, enforced here at the point of use rather than only at
        // admission: a grant that outlived its own introduction, or a
        // credential lease that ended inside it, cannot start a child.
        let introduction = &grant.approved.introduction;
        if introduction.expires_at <= now
            || introduction
                .credential_binding
                .as_ref()
                .is_some_and(|binding| binding.expires_at <= now)
        {
            return Err(PortError::Denied);
        }
        // The credential is introduced as an opaque reference only. It is
        // deliberately NOT added to the child environment: `ProcessExecutor`
        // refuses any request carrying environment secret references
        // ("secret environment references require an admitted secret
        // projection"), and I6.15 requires that signing secrets never enter
        // a child environment. The child resolves the handle itself through
        // its own crypto port, so nothing here materialises or forwards it.
        let intent = ProcessIntent::new(
            grant.approved.operation_id.clone(),
            grant.approved.process_tree_id.clone(),
            grant.approved.job_id.clone(),
            grant.approved.image_id.clone(),
            grant.approved.session_id.clone(),
            grant.approved.generation,
            grant.approved.executable.clone(),
            grant.approved.artifact_digest.clone(),
            grant.approved.argv.clone(),
            grant.approved.working_directory.clone(),
            grant.approved.environment.clone(),
            grant.approved.resource_limits,
        )
        .map_err(|error| PortError::Invalid(error.to_string()))?;
        self.authority.issue(&intent, grant, now)
    }

    fn map_error(error: ProcessExecutionError) -> PortError {
        match error {
            ProcessExecutionError::UnknownOutcome | ProcessExecutionError::NotFound => {
                PortError::Unknown
            }
            ProcessExecutionError::Unavailable(_detail) => PortError::Unavailable,
            ProcessExecutionError::Contract(error) => PortError::Invalid(error.to_string()),
            ProcessExecutionError::EvidenceSink(error) => PortError::Invalid(error.to_string()),
        }
    }
}

impl ProcessPort for LocalProcessPort {
    fn prepare_start(
        &mut self,
        grant: &LaunchGrant,
        _registration: &RegistrationReceipt,
    ) -> Result<String, PortError> {
        let request = self.request_from_grant(grant)?;
        let operation_id = request.operation_id().clone();
        let request_digest = request.invocation_digest().to_owned();
        // Record the authorization→effect lineage link before the physical
        // start boundary. The grant, transport, and effect identities stay
        // distinct; this entry only joins them for reconciliation.
        self.note_process_effect(
            &grant.approved.request_id,
            &grant.request_digest,
            &request_digest,
        );
        if self
            .pending_requests
            .insert(operation_id, request)
            .is_some()
        {
            return Err(PortError::Invalid(
                "duplicate pending process start operation".to_owned(),
            ));
        }
        Ok(request_digest)
    }

    fn start(
        &mut self,
        grant: &LaunchGrant,
        _registration: &RegistrationReceipt,
        expected_request_digest: &str,
    ) -> Result<ProcessStartOutcome, PortError> {
        let request = self
            .pending_requests
            .remove(&grant.approved.operation_id)
            .ok_or_else(|| PortError::Invalid("process start was not prepared".to_owned()))?;
        let request_digest = request.invocation_digest().to_owned();
        if request_digest != expected_request_digest {
            return Err(PortError::Invalid(
                "prepared process request digest changed".to_owned(),
            ));
        }
        let sink = Arc::new(BrokerEvidenceSink {
            records: self.evidence.clone(),
        });
        match self.runtime.block_on(self.executor.start(request, sink)) {
            Ok(receipt) => Ok(ProcessStartOutcome::Started {
                request_digest,
                receipt,
            }),
            Err(ProcessExecutionError::UnknownOutcome) => {
                Ok(ProcessStartOutcome::Unknown { request_digest })
            }
            Err(error) => Err(Self::map_error(error)),
        }
    }

    fn inspect(&mut self, operation_id: &OperationId) -> Result<ProcessExecutionView, PortError> {
        self.runtime
            .block_on(self.executor.inspect(operation_id.clone()))
            .map_err(Self::map_error)
    }

    fn cancel(&mut self, operation_id: &OperationId) -> Result<CancellationReceipt, PortError> {
        self.runtime
            .block_on(self.executor.cancel(operation_id.clone()))
            .map_err(Self::map_error)
    }

    fn reconcile(&mut self, operation_id: &OperationId) -> Result<ProcessExecutionView, PortError> {
        self.runtime
            .block_on(self.executor.reconcile(operation_id.clone()))
            .map_err(Self::map_error)?;
        self.inspect(operation_id)
    }
}

struct FileRegistrationStore {
    path: PathBuf,
    #[cfg(windows)]
    platform: Option<WindowsPlatform>,
    #[cfg(windows)]
    lease: Option<ProtectedPathLease>,
    #[cfg(windows)]
    protected_relative: Option<PathBuf>,
}

impl FileRegistrationStore {
    fn open(_path: &Path) -> Result<Self, CompositionError> {
        Err(CompositionError::Protected(
            "durable broker state requires the retained protected ProgramData lease".to_owned(),
        ))
    }

    #[cfg(windows)]
    fn open_protected(path: &Path, relative: PathBuf) -> Result<Self, CompositionError> {
        let lease = ProtectedPathLease::open_or_create(&relative)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        let canonical_path = fs::canonicalize(path).map_err(CompositionError::Durable)?;
        if lease.path() != canonical_path {
            return Err(CompositionError::Protected(
                "snapshot path is not the retained protected object".to_owned(),
            ));
        }
        let parent = canonical_path
            .parent()
            .ok_or_else(|| CompositionError::Protected("snapshot has no parent".to_owned()))?;
        let platform = WindowsPlatform::new(parent)
            .map_err(|error| CompositionError::Protected(error.to_string()))?;
        Ok(Self {
            path: canonical_path,
            platform: Some(platform),
            lease: Some(lease),
            protected_relative: Some(relative),
        })
    }

    #[cfg(windows)]
    fn read_verified_lease(
        lease: &ProtectedPathLease,
        path: &Path,
        post_publication: bool,
    ) -> Result<Vec<u8>, PortError> {
        let verify = lease
            .verify_stable_identity()
            .and_then(|()| lease.verify_path_identity());
        if let Err(error) = verify {
            return Err(if post_publication {
                PortError::Unknown
            } else {
                PortError::Invalid(error.to_string())
            });
        }
        lease.read_bounded(SNAPSHOT_LIMIT).map_err(|error| {
            if post_publication {
                PortError::Unknown
            } else {
                PortError::Invalid(format!("read {}: {error}", path.display()))
            }
        })
    }

    #[cfg(windows)]
    fn decode_snapshot(bytes: &[u8], path: &Path) -> Result<Option<BrokerSnapshot>, PortError> {
        if bytes.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(bytes)
            .map(Some)
            .map_err(|error| PortError::Invalid(format!("decode {}: {error}", path.display())))
    }

    /// Reacquires the exact protected object after an atomic publication.
    ///
    /// The replacement lease is installed before any result is returned.  A
    /// successful open whose identity/read proof fails is still retained so
    /// the next operation cannot accidentally fall back to an unprotected
    /// path; all later operations re-verify that retained handle.
    #[cfg(windows)]
    fn reacquire_after_publication(&mut self, relative: &Path) -> Result<Vec<u8>, PortError> {
        let Ok(replacement) = ProtectedPathLease::open_or_create(relative) else {
            // The old lease had to be released before replacement.  An
            // unavailable replacement is therefore an explicit unknown
            // state, never a successful save or a retryable failure.
            self.lease = None;
            return Err(PortError::Unknown);
        };
        let result = Self::read_verified_lease(&replacement, &self.path, true);
        self.lease = Some(replacement);
        result
    }
}

impl DurableRegistrationPort for FileRegistrationStore {
    fn load(&mut self) -> Result<Option<BrokerSnapshot>, PortError> {
        #[cfg(windows)]
        let bytes = {
            let lease = self.lease.as_ref().ok_or(PortError::Unavailable)?;
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| PortError::Invalid(error.to_string()))?;
            match lease.read_bounded(SNAPSHOT_LIMIT) {
                Ok(bytes) => bytes,
                Err(error) => return Err(PortError::Invalid(error.to_string())),
            }
        };
        #[cfg(not(windows))]
        return Err(PortError::Unavailable);
        if bytes.is_empty() {
            return Ok(None);
        }
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| PortError::Invalid(format!("decode {}: {error}", self.path.display())))
    }

    fn save(&mut self, snapshot: &BrokerSnapshot) -> Result<(), PortError> {
        let bytes = serde_json::to_vec(snapshot)
            .map_err(|error| PortError::Invalid(format!("encode snapshot: {error}")))?;
        #[cfg(windows)]
        {
            let relative = self
                .protected_relative
                .as_ref()
                .ok_or(PortError::Unavailable)?
                .clone();
            let previous_bytes = {
                let lease = self.lease.as_ref().ok_or(PortError::Unavailable)?;
                Self::read_verified_lease(lease, &self.path, false)?
            };
            let previous = Self::decode_snapshot(&previous_bytes, &self.path)?;
            let scope_name = self
                .path
                .file_name()
                .ok_or(PortError::Invalid("snapshot filename missing".to_owned()))?
                .to_string_lossy()
                .into_owned();
            let scope = WorkScopePath::new(scope_name)
                .map_err(|error| PortError::Invalid(error.to_string()))?;

            // The old no-delete-sharing lease must be released for the
            // atomic replacement.  From this point onward there are no `?`
            // exits until the replacement has been retained again.
            let lease = self.lease.take().ok_or(PortError::Unavailable)?;
            drop(lease);
            if let Some(platform) = self.platform.as_ref() {
                let _ = platform.publish_atomic(&scope, &bytes);
            }

            let current_bytes = self.reacquire_after_publication(&relative)?;
            let current = Self::decode_snapshot(&current_bytes, &self.path)?;
            if current.as_ref() == Some(snapshot) {
                // The publish response may have been lost, but the exact
                // desired bytes are now durable and can be acknowledged.
                return Ok(());
            }
            if current == previous {
                return Err(PortError::Unknown);
            }
            // Any other bytes are an unresolvable publication race. Do not
            // classify this as a deterministic provider failure: the caller
            // must reconcile the exact registration snapshot before retrying.
            Err(PortError::Unknown)
        }
        #[cfg(not(windows))]
        {
            let _ = bytes;
            Err(PortError::Unavailable)
        }
    }
}

#[derive(Debug, Serialize)]
pub struct BrokerReadiness<'a> {
    pub service: &'a str,
    pub protocol: &'a str,
    pub registration_state: &'static str,
    pub missing_providers: Vec<RequiredProvider>,
    pub snapshot: String,
}

pub struct BrokerComposition {
    broker: UserBroker,
    snapshot: PathBuf,
    providers_admitted: bool,
    launch_binding: Option<BrokerLaunchBinding>,
    launch_lease: Option<ProtectedPathLease>,
    /// The live process identity this broker admitted itself as. Re-observed
    /// on every authenticated operation; see [`Self::verify_launch_lease`].
    process_binding: Option<BrokerProcessBinding>,
    registration_digest: Option<String>,
    identity_issuer: IssuerHandle,
    /// Broker-retained normal Notify launch authority: the verified installed
    /// `eliot-notify.exe` reference resolved from the installer-published
    /// declaration at startup. This is what makes the notification adapter
    /// launchable only from here; see
    /// [`BrokerComposition::launch_notify`].
    notify_launch: BrokerNotifyLaunchAuthority,
}

impl BrokerComposition {
    pub fn start(config: BrokerConfig) -> Result<Self, CompositionError> {
        Self::start_with_kernel(config)
    }

    /// Starts the production binary composition with an authenticated Kernel
    /// front door. The binary never substitutes a local authority/process
    /// provider when this composition is unavailable.
    pub fn start_with_kernel(config: BrokerConfig) -> Result<Self, CompositionError> {
        let (launch_binding, launch_lease) = load_protected_launch_binding()?;
        let client = eliot_cli::kernel_client::KernelClient::load()
            .map_err(|error| CompositionError::Kernel(error.to_string()))?;
        let client = Arc::new(Mutex::new(client));
        let issuer = Self::issuer_for_binding(&launch_binding)?;
        let mut process = LocalProcessPort::new()?;
        process.set_identity_issuer(issuer.clone());
        Self::start_with_ports(
            config,
            Some(Box::new(KernelAuthorityPort {
                client: client.clone(),
                issuer: issuer.clone(),
            })),
            Some(Box::new(process)),
            Some(client),
            Some((launch_binding, launch_lease)),
            issuer,
        )
    }

    /// Builds the per-operation identity issuer for one stable launch
    /// binding. The issuer carries the installation fence baseline; every
    /// register, heartbeat, authorize-launch, and fence transaction then
    /// mints its own exact transport identity.
    fn issuer_for_binding(binding: &BrokerLaunchBinding) -> Result<IssuerHandle, CompositionError> {
        let digest = binding_digest(binding)?;
        let issuer = OperationIdentityIssuer::bound(digest, binding.launch_authority_fence.clone())
            .map_err(|error| CompositionError::Launch(error.to_string()))?;
        Ok(Arc::new(Mutex::new(issuer)))
    }

    fn start_with_ports(
        config: BrokerConfig,
        authority: Option<Box<dyn AuthorityPort>>,
        process: Option<Box<dyn ProcessPort>>,
        _kernel_client: Option<SharedKernelClient>,
        launch: Option<(BrokerLaunchBinding, ProtectedPathLease)>,
        issuer: IssuerHandle,
    ) -> Result<Self, CompositionError> {
        config.validate()?;
        let snapshot = config.data_root.join(config.snapshot_name);
        #[cfg(windows)]
        let mut durable = if launch.is_some() {
            let relative = PathBuf::from(SNAPSHOT_RELATIVE_DIRECTORY).join(
                snapshot.file_name().ok_or_else(|| {
                    CompositionError::InvalidConfiguration("snapshot filename missing".to_owned())
                })?,
            );
            FileRegistrationStore::open_protected(&snapshot, relative)?
        } else {
            FileRegistrationStore::open(&snapshot)?
        };
        #[cfg(not(windows))]
        let mut durable = FileRegistrationStore::open(&snapshot)?;
        if durable
            .load()
            .map_err(|error| CompositionError::InvalidConfiguration(error.to_string()))?
            .is_none()
        {
            durable
                .save(&BrokerSnapshot {
                    registration: None,
                    user_broker_epoch: 0,
                    operation_cursors: Vec::new(),
                    operation_identities: Vec::new(),
                    retired_operations: Vec::new(),
                })
                .map_err(|error| CompositionError::InvalidConfiguration(error.to_string()))?;
        }
        let providers_admitted = authority.is_some() && process.is_some();
        let mut broker = UserBroker::new(authority, process, Some(Box::new(durable)));
        // The live identity ledger must be attached before recovery so the
        // snapshot is republished with the exact identities this process
        // issues, and before the first Kernel call can mint.
        broker.attach_issued_operation_identity_ledger(Box::new(IssuedIdentityLedger {
            issuer: issuer.clone(),
        }));
        broker.recover().map_err(CompositionError::Recovery)?;
        // The live process identity is observed before anything is admitted:
        // an unprovable id/start/image means this process cannot name which
        // process the declaration describes, so no registration is refreshed,
        // no launch is admitted, and no control operation is accepted.
        let process_binding = current_process_binding()?;
        // Single-broker admission. A registration recovered from shared
        // durable state is adopted only when it carries exactly this
        // installation/SID/Session/boot-Session tuple; a surviving
        // registration of another principal is refused, never heartbeated.
        let (launch_binding, launch_lease) = launch.map_or((None, None), |(binding, lease)| {
            (Some(binding), Some(lease))
        });
        if let Some(binding) = launch_binding.as_ref() {
            broker
                .bind_admission(&BrokerAdmissionIdentity {
                    installation_id: binding.registration.installation_id.clone(),
                    windows_sid: binding.registration.windows_sid.clone(),
                    interactive_session_id: binding.registration.interactive_session_id.clone(),
                    boot_session_id: binding.registration.boot_session_id.clone(),
                    broker_process_id: binding.registration.broker_process_id.clone(),
                    broker_artifact_digest: binding.registration.broker_artifact_digest.clone(),
                    protocol_generation: binding.registration.protocol_generation,
                    launch_nonce: binding.registration.launch_nonce.clone(),
                })
                .map_err(|error| match error {
                    BrokerError::StaleRegistrationIdentity => {
                        BrokerAdmissionRefusal::RegistrationIdentityForeign.with_platform(error)
                    }
                    other => CompositionError::Recovery(other),
                })?;
        }
        // A4: a restart continues from the protected launch/caller identity
        // plus a new registration operation and never revives a historical
        // request id.  Re-seeding the issuer from the recovered durable ledger
        // before `self_register` is what holds that: every request id,
        // cancellation id, and idempotency key the previous process spent is
        // already bound to its exact operation, so replaying one is an
        // identity conflict rather than a fresh mint.  A retained row that
        // contradicts live state fails the whole composition closed.
        let mut identity = issuer.lock().map_err(|_| CompositionError::KernelLock)?;
        for retained in broker.recovered_operation_identities() {
            identity
                .restore_issued(&DurableIssuedIdentity::from(&retained))
                .map_err(|error| CompositionError::OperationIdentityLedger(error.to_string()))?;
        }
        drop(identity);
        let registration_digest = broker.registration_digest().map(ToOwned::to_owned);
        Ok(Self {
            broker,
            snapshot,
            providers_admitted,
            launch_binding,
            launch_lease,
            process_binding: Some(process_binding),
            registration_digest,
            identity_issuer: issuer,
            notify_launch: BrokerNotifyLaunchAuthority::unstaged(NotifyLaunchStage::Deferred {
                reason: "NOT_STAGED",
            }),
        })
    }

    pub fn readiness(&self) -> BrokerReadiness<'_> {
        BrokerReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            registration_state: "RECOVERED",
            missing_providers: if self.providers_admitted {
                Vec::new()
            } else {
                vec![RequiredProvider::G01Authority, RequiredProvider::P03Process]
            },
            snapshot: self.snapshot.display().to_string(),
        }
    }

    /// Performs broker self-authentication from the retained stable
    /// installation declaration, then registers or refreshes the recovered
    /// lease. Every Kernel transaction mints its own exact operation
    /// identity: no static request identity is installed or reused. No
    /// caller-provided registration tuple is accepted by this boundary.
    pub fn self_register(&mut self) -> Result<(), CompositionError> {
        self.verify_launch_lease()?;
        let binding = self.launch_binding.clone().ok_or_else(|| {
            CompositionError::Launch("protected launch configuration is not composed".to_owned())
        })?;
        // A fresh lease window per registration operation: a restart never
        // revives historical request bytes, so it never revives a historical
        // request identity either.
        let observed_at = now_unix_ms()?;
        let lease_expires_at = observed_at
            .checked_add(REGISTRATION_LEASE_TTL_MS)
            .filter(|expires| *expires > observed_at)
            .ok_or_else(|| {
                CompositionError::Launch("registration lease window overflowed".to_owned())
            })?;
        let declaration = fresh_registration_request(&binding, observed_at, lease_expires_at)?;
        // A recovered registration is only refreshable while it is still the
        // current one. A `Closed`/`Draining` registration — this process's
        // own previous process after a clean stop, or a registration the
        // Kernel already fenced — carries no launch authority, and renewing
        // it would either resurrect a fenced lease or leave the broker unable
        // to ever start again. Such a broker registers afresh under a new
        // broker generation instead.
        let refreshable = self.broker.registration().is_some_and(|registration| {
            registration.status == RegistrationStatus::Active
                && observed_at < registration.expires_at
        });
        if refreshable {
            let receipt = self.heartbeat()?;
            self.registration_digest = Some(receipt.registration_digest);
        } else {
            let receipt = self
                .broker
                .register(declaration)
                .map_err(CompositionError::Recovery)?;
            let epoch = serde_json::to_value(&receipt.authority_epoch)
                .map_err(|error| CompositionError::Launch(error.to_string()))?;
            self.sync_authority_epoch(&epoch)?;
            self.registration_digest = Some(receipt.registration_digest);
        }
        Ok(())
    }

    /// Refreshes the exact protected registration lease; the stdin protocol
    /// cannot manufacture or submit a heartbeat identity.
    ///
    /// A lost lease-refresh acknowledgement is first reconciled against the
    /// durable registration bound to that exact operation. When the durable
    /// projection already proves the renewal, the recovered receipt is
    /// returned and no second refresh identity is minted; otherwise the exact
    /// transport identity that lost its acknowledgement is named in
    /// [`CompositionError::LostOperation`] and the broker must re-attach
    /// through a fresh protected launch binding.
    pub fn heartbeat(&mut self) -> Result<HeartbeatReceipt, CompositionError> {
        self.verify_launch_lease()?;
        let registration_digest = self
            .registration_digest
            .clone()
            .or_else(|| self.broker.registration_digest().map(ToOwned::to_owned))
            .ok_or_else(|| CompositionError::Launch("broker is not registered".to_owned()))?;
        let observed_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| CompositionError::Launch(error.to_string()))?
            .as_millis()
            .try_into()
            .map_err(|error| CompositionError::Launch(format!("clock overflow: {error}")))?;
        let receipt = match self.broker.heartbeat(HeartbeatRequest {
            registration_digest,
            observed_at,
        }) {
            Ok(receipt) => receipt,
            Err(BrokerError::UnknownOutcome) => return Err(self.lost_operation_error()),
            Err(error) => return Err(CompositionError::Recovery(error)),
        };
        self.registration_digest = Some(receipt.registration_digest.clone());
        Ok(receipt)
    }

    /// Closes the authenticated registration before the broker process exits.
    ///
    /// A clean stdin EOF and an admitted `stop` operation use the same durable
    /// close path; dropping the composition alone must never leave an active
    /// registration lease for the next process instance.
    ///
    /// The fence owns its own operation identity, so closing twice is one
    /// Kernel operation, not two. A lost logoff acknowledgement is reconciled
    /// against the durable projection of that exact fence: when the fence
    /// landed, the close completes without a duplicate logoff; otherwise the
    /// exact transport identity is named in
    /// [`CompositionError::LostOperation`].
    pub fn close(&mut self) -> Result<(), CompositionError> {
        self.verify_launch_lease()?;
        match self.broker.logoff() {
            Ok(()) => {
                self.registration_digest = None;
                Ok(())
            }
            Err(BrokerError::UnknownOutcome) => Err(self.lost_operation_error()),
            Err(error) => Err(CompositionError::Recovery(error)),
        }
    }

    /// Reconciles a lost or unknown broker-owned Kernel acknowledgement by the
    /// exact transport operation identity that issued it.
    ///
    /// The core classifies *which* broker-owned operation lost its outcome
    /// (a lease refresh or a fence), and the exact transport identity for
    /// that operation is read back from the issuer's spent ledger: request id,
    /// cancellation id, idempotency key, and the canonical payload digest it
    /// is bound to. Naming it here instead of returning a bare error is what
    /// keeps a heartbeat/fence race from being settled by a second refresh, a
    /// duplicate logoff, or a second launch under a new identity.
    fn lost_operation_error(&mut self) -> CompositionError {
        let Some(lost) = self.broker.take_lost_operation() else {
            return CompositionError::OperationIdentityLedger(
                "an unknown outcome was reported without a classified broker operation".to_owned(),
            );
        };
        let operation = match lost {
            LostOperation::LeaseRefresh => BrokerOperation::HeartbeatRenewal,
            LostOperation::Fence => BrokerOperation::FenceLogoff,
        };
        let issued = self
            .identity_issuer
            .lock()
            .ok()
            .and_then(|issuer| issuer.last_issued(operation));
        let Some(issued) = issued else {
            return CompositionError::OperationIdentityLedger(format!(
                "{} has no issued operation identity to reconcile",
                operation.selector()
            ));
        };
        CompositionError::LostOperation {
            operation: operation.selector(),
            request_id: issued.request_id,
            cancellation_id: issued.cancellation_id,
            idempotency_key: issued.idempotency_key,
            canonical_digest: issued.canonical_digest,
        }
    }

    /// Stages broker-bound Notify normal-launch inputs for one grant.
    ///
    /// Thin projection over [`resolve_broker_notify_launch`]: the SID/session
    /// pair comes from this composition's authenticated protected launch
    /// binding (verified lease first), the declaration bytes are
    /// caller-injected from the protected lease read at the edge, and the
    /// Kernel challenge is this composition's Kernel-issued registration
    /// digest from [`BrokerComposition::self_register`] — never a
    /// caller-supplied string. Per-notification spawn stays on the
    /// Kernel-approved [`BrokerComposition::launch`] path: the staged inputs
    /// feed the Kernel `notify_grant` evidence join, which the central
    /// composition maps onto `ApprovedLaunch`.
    pub fn resolve_notify_launch(
        &self,
        declaration_bytes: &[u8],
    ) -> Result<VerifiedLaunchRef, BrokerNotifyError> {
        self.verify_launch_lease()
            .map_err(|_| BrokerNotifyError::NotAuthenticated)?;
        let binding = self
            .launch_binding
            .as_ref()
            .ok_or(BrokerNotifyError::NotAuthenticated)?;
        let challenge = self
            .registration_digest
            .as_deref()
            .ok_or(BrokerNotifyError::NotAuthenticated)?;
        let session_id: u32 = binding
            .registration
            .interactive_session_id
            .parse()
            .map_err(|_| BrokerNotifyError::InvalidIdentity)?;
        resolve_broker_notify_launch(
            declaration_bytes,
            &binding.registration.windows_sid,
            session_id,
            challenge,
        )
    }

    /// Stages the installer-published Notify declaration and RETAINS the
    /// verified launch reference used by [`Self::launch_notify`].
    ///
    /// This is the composition's production entry to
    /// [`stage_normal_notify_launch`]. The reference it retains is the whole
    /// point: without it the broker could prove it *can* name the installed
    /// image but had no authority to spawn one, which is exactly the gap that
    /// left normal `eliot-notify` invocation unconstrained.
    pub fn stage_notify_launch(&mut self) -> NotifyLaunchStage {
        let authority = stage_normal_notify_launch(self);
        let stage = authority.stage().clone();
        self.notify_launch = authority;
        stage
    }

    /// The broker-retained normal Notify launch authority.
    #[must_use]
    pub fn notify_launch_authority(&self) -> &BrokerNotifyLaunchAuthority {
        &self.notify_launch
    }

    /// Spawns the per-user notification adapter on a Kernel-authorized grant.
    ///
    /// This is the ONLY dispatcher that may start `eliot-notify.exe`, and it is
    /// notify-specific on purpose (I11.6:3, "Normal delivery is launched
    /// through the authorized User Broker"). Before anything is dispatched the
    /// request must satisfy four independent gates:
    ///
    /// 1. the protected launch lease still verifies and the registration is
    ///    heartbeated, so a revoked or expired broker cannot spawn;
    /// 2. this broker currently RETAINS a verified launch reference, resolved at
    ///    startup from the installer-published declaration and bound to the
    ///    broker's authenticated SID/session plus the Kernel-issued
    ///    registration digest;
    /// 3. the request names exactly that executable path and its artifact
    ///    digest equals the digest of the bytes this broker observed;
    /// 4. the broker has itself built the notify request channel on the grant:
    ///    exactly `NOTIFY_REQUEST_ARGUMENT` plus one single-line canonical
    ///    request reference, proved by the binding owner and within the platform
    ///    launch-line cap. A request that arrives with caller-selected child
    ///    arguments is refused rather than overruled.
    ///
    /// The channel is installed BEFORE the launch is dispatched, so the argv the
    /// broker built is the argv the G-01 authority provider approves and the
    /// durable operation digest covers — it is not a post-hoc rewrite of an
    /// approved launch.
    ///
    /// Only then is the request dispatched on the existing authority/process
    /// ports, which apply the Kernel grant. A generic `Launch` request naming
    /// the notify image is refused by the binary before reaching here (see
    /// [`request_names_notify_image`]), so no other request shape can produce a
    /// normal notification invocation.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::Launch`] when the launch lease does not
    /// verify, when the notify request channel cannot be built
    /// ([`NotifyRequestChannelError`]), or when the notify-specific admission
    /// rejects the grant it is about to dispatch.
    pub fn launch_notify(
        &mut self,
        mut request: LaunchRequest,
        reference: &NotifyLaunchRequestReference,
    ) -> Result<eliot_user_broker_core::LaunchReceipt, CompositionError> {
        self.verify_launch_lease()?;
        // The broker is the argv authority for the notification adapter, so the
        // channel is produced here from the canonical reference this call just
        // proved — never relayed from the caller's own bytes.
        request.approved.argv =
            build_notify_request_channel(&request, reference).map_err(|error| {
                CompositionError::Launch(format!("notify launch rejected: {}", error.code()))
            })?;
        notify_launch_callin::admit_notify_request(&self.notify_launch, &request).map_err(
            |error| CompositionError::Launch(format!("notify launch rejected: {}", error.code())),
        )?;
        // The dispatch itself is the existing generic authority/process path,
        // so the Kernel grant, operation identity, and fencing stay exactly
        // where they are; only the argv and the admission above are
        // notify-specific.
        self.launch(request)
    }

    /// Heartbeats the protected registration before an admitted launch.
    pub fn launch(
        &mut self,
        request: LaunchRequest,
    ) -> Result<eliot_user_broker_core::LaunchReceipt, CompositionError> {
        let _ = self.heartbeat()?;
        self.broker.launch(request).map_err(Self::classify)
    }

    /// Cancels a broker-owned operation selected by its admitted operation
    /// identity.  The sealed operation permit remains inside `UserBroker`.
    ///
    /// The cancellation first passes the broker's own control-operation
    /// admission: an exact durable cancel identity is recorded for that exact
    /// target under the current registration, and a target whose outcome is
    /// still unproven is refused so an unknown launch/effect is reconciled
    /// before anything tries to erase it.
    pub fn cancel(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<CancellationReceipt, CompositionError> {
        self.verify_launch_lease()?;
        self.admit_control_operation(BrokerControlOperation::Cancel, operation_id)?;
        self.broker
            .cancel_operation(operation_id)
            .map_err(Self::classify)
    }

    /// Reconciles a broker-owned operation selected by its admitted operation
    /// identity.  No caller-supplied P-03 request or permit crosses stdin.
    pub fn reconcile(
        &mut self,
        operation_id: &OperationId,
    ) -> Result<ProcessExecutionView, CompositionError> {
        self.verify_launch_lease()?;
        self.admit_control_operation(BrokerControlOperation::Reconcile, operation_id)?;
        self.broker
            .reconcile_operation(operation_id)
            .map_err(Self::classify)
    }

    /// Records this broker-owned control operation's distinct durable
    /// operation identity before its effect is dispatched.
    fn admit_control_operation(
        &mut self,
        operation: BrokerControlOperation,
        operation_id: &OperationId,
    ) -> Result<(), CompositionError> {
        let observed_at = now_unix_ms()?;
        self.broker
            .admit_control_operation(operation, operation_id, observed_at)
            .map_err(Self::classify)
    }

    /// Projects one core refusal onto the broker's closed admission taxonomy.
    ///
    /// A refusal the broker can name keeps its exact cause and its own stable
    /// code; anything else stays the typed `Recovery` variant rather than a
    /// string. Nothing here is downgraded to a generic composition error.
    fn classify(error: BrokerError) -> CompositionError {
        let refusal = match error {
            BrokerError::StaleRegistrationIdentity => {
                Some(BrokerAdmissionRefusal::RegistrationIdentityForeign)
            }
            BrokerError::UnreconciledEffect(_) => {
                Some(BrokerAdmissionRefusal::OperationOutcomeUnreconciled)
            }
            BrokerError::RetiredOperation(_) => Some(BrokerAdmissionRefusal::RetiredOperation),
            BrokerError::OperationIdRetired(_) => Some(BrokerAdmissionRefusal::OperationIdRetired),
            BrokerError::IntroductionRequired(_) => {
                Some(BrokerAdmissionRefusal::IntroductionRequired)
            }
            BrokerError::IntroductionOperationNotGranted => {
                Some(BrokerAdmissionRefusal::IntroductionOperationNotGranted)
            }
            BrokerError::IntroductionResourceNotGranted => {
                Some(BrokerAdmissionRefusal::IntroductionResourceNotGranted)
            }
            BrokerError::IntroductionEffectCeilingExceeded => {
                Some(BrokerAdmissionRefusal::IntroductionEffectCeilingExceeded)
            }
            BrokerError::IntroductionExpired => Some(BrokerAdmissionRefusal::IntroductionExpired),
            BrokerError::IntroductionCredentialUnnamed => {
                Some(BrokerAdmissionRefusal::IntroductionCredentialUnnamed)
            }
            _ => None,
        };
        match refusal {
            Some(refusal) => refusal.with_platform(error),
            None => CompositionError::Recovery(error),
        }
    }

    /// Proves, before any authenticated broker operation, that the protected
    /// launch declaration is still the retained protected object *and* that
    /// this process is still the process that was admitted.
    ///
    /// The launch lease alone cannot carry that: it proves the declaration
    /// bytes are intact, not that the running image, process id, and process
    /// start are the ones the broker authenticated itself with. Both are
    /// re-proven here so a replaced image, a recycled process id, or a
    /// substituted process fails closed before a register, heartbeat, launch,
    /// cancel, reconcile, or close can cross the Kernel boundary.
    fn verify_launch_lease(&self) -> Result<(), CompositionError> {
        if let Some(lease) = &self.launch_lease {
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|error| CompositionError::Protected(error.to_string()))?;
        }
        let bound = self.process_binding.as_ref().ok_or_else(|| {
            BrokerAdmissionRefusal::ProcessIdentityUnprovable
                .with_platform("broker process identity is not bound")
        })?;
        let observed = current_process_identity()?;
        if !bound.identity.is_same_process(&observed) {
            return Err(BrokerAdmissionRefusal::ProcessIdentityChanged
                .with_platform("live process identity differs from the admitted one"));
        }
        Ok(())
    }

    /// Refreshes the issuer fence from a Kernel-issued registration
    /// authority epoch, serialized as its exact JSON value. Only the
    /// lineage-aware epoch moves; no scalar authority is copied into
    /// broker-local state.
    fn sync_authority_epoch(&self, epoch: &serde_json::Value) -> Result<(), CompositionError> {
        self.identity_issuer
            .lock()
            .map_err(|_| CompositionError::KernelLock)?
            .note_authority_epoch(epoch)
            .map_err(|error| CompositionError::Launch(error.to_string()))
    }
}

pub fn canonical_root(path: &Path) -> Result<PathBuf, CompositionError> {
    fs::canonicalize(path).map_err(CompositionError::Durable)
}

fn now_unix_ms() -> Result<u64, CompositionError> {
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| CompositionError::Launch(error.to_string()))?
        .as_millis()
        .try_into()
        .map_err(|error| CompositionError::Launch(format!("clock overflow: {error}")))?;
    if now == 0 {
        return Err(CompositionError::Launch(
            "broker clock observation is zero".to_owned(),
        ));
    }
    Ok(now)
}

pub fn snapshot_digest(path: &Path) -> Result<String, CompositionError> {
    let mut file = File::open(path).map_err(CompositionError::Durable)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(CompositionError::Durable)?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}

#[cfg(test)]
mod tests {
    use super::{BrokerDispatchAuthority, LocalProcessPort};

    #[test]
    fn broker_dispatch_authority_constructs_ephemeral_key() {
        // Regression for #1390: key assembly panicked copying the 32-byte
        // digest into the 16-byte second half of the 32-byte key.
        assert!(BrokerDispatchAuthority::new().is_ok());
        assert!(BrokerDispatchAuthority::new().is_ok());
    }

    #[test]
    fn local_process_port_constructs_on_this_platform() {
        // Production path `start_with_kernel` -> `LocalProcessPort::new()`;
        // unit-level only: no daemon/service start, no network.
        assert!(LocalProcessPort::new().is_ok());
    }
}
