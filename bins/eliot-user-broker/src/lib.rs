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
//! continues from the protected launch/caller identity plus the exact current
//! registration. It permits replay only for an unexpired original identity
//! under that same registration and fence; every other historical request id,
//! cancellation id, and idempotency key stays reserved.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_platform::ClockObservation;
use eliot_platform::WorkScopePath;
use eliot_platform_windows::{
    NamedPipePeerEvidence, ProcessIdentity, ProtectedPathLease, WindowsPlatform,
};
use eliot_process::{
    ActionLeaseRef, CancellationReceipt, DispatchAuthorityId, DispatchPermitAuthority,
    DispatchValidationContext, FencingToken, KernelDispatchKey, OperationId, PermitIssuance,
    ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessExecutionView,
    ProcessExecutor, ProcessIntent, ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_user_broker_core::{
    AuthorityPort, BrokerAdmissionIdentity, BrokerControlOperation, BrokerError, BrokerSnapshot,
    CutoverReceipt, DurableRegistrationPort, HeartbeatReceipt, HeartbeatRequest,
    IssuedOperationIdentity, IssuedOperationIdentityLedger, LaunchGrant, LaunchRequest,
    LostOperation, OperatorArtifact, OperatorEndpoint, OperatorHandoffRequest, PortError,
    ProcessEffectLineage, ProcessPort, ProcessStartOutcome, RegistrationReceipt,
    RegistrationStatus, RequiredProvider, UserBroker,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

mod bridge_contract;
mod kernel_authority_port;
mod notify_fallback_ensure;
pub mod notify_launch_callin;
mod operation_identity;
#[cfg(windows)]
mod own_generation_job;
mod protected_launch_config;
use bridge_contract::{user_broker_contract, validate_user_broker_contract};
use kernel_authority_port::KernelAuthorityPort;
pub use notify_fallback_ensure::{
    LiveNotifyFallbackEffects, NotifyFallbackDeclaration, NotifyFallbackEffects,
    NotifyFallbackEnsure, NotifyFallbackRegistration, ensure_notify_fallback_registered,
};
pub use notify_launch_callin::{
    BrokerNotifyError, BrokerNotifyLaunchAuthority, NotifyAcknowledge, NotifyDeliver,
    NotifyLaunchStage, VerifiedLaunchRef, admit_notify_request, render_notify_acknowledge_line,
    render_notify_deliver_line, request_names_notify_image, resolve_broker_notify_launch,
    stage_normal_notify_launch,
};
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

struct BoundedSnapshotWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl BoundedSnapshotWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}

impl Write for BoundedSnapshotWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next_len = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("snapshot exceeds its byte limit"))?;
        if next_len > self.limit {
            return Err(io::Error::other("snapshot exceeds its byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

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
    /// A one-shot Operator handoff was presented a second time, or an endpoint
    /// was presented that this broker never issued for the live registration.
    /// Reconnect requires a newly issued handoff, never a replayed one.
    #[error("RESOURCE_LEASE_REPLAYED")]
    OperatorHandoffReplayed,
    /// A one-shot Operator handoff was presented after its own expiry window.
    #[error("DEADLINE_EXCEEDED")]
    OperatorHandoffExpired,
    /// A one-shot Operator handoff was presented against a registration epoch,
    /// logon Session, or installation-approved artifact that is no longer the
    /// live one, so the endpoint generation it names is stale.
    #[error("STALE_AUTHORITY_EPOCH")]
    OperatorHandoffStaleGeneration,
    /// The one-shot Operator handoff boundary is not composed: this broker has
    /// no authenticated protected launch declaration naming the approved
    /// Operator artifact, so it can name no image to hand off.
    #[error("BROKER_OPERATOR_HANDOFF_UNCOMPOSED")]
    OperatorHandoffUncomposed,
    /// The request named a role or capability set the handoff policy does not
    /// introduce. The handoff introduces exactly
    /// `eliot_user_broker_core::OPERATOR_CAPABILITIES`; anything wider is
    /// refused rather than narrowed.
    #[error("CAPABILITY_INTRODUCTION_REQUIRED")]
    OperatorHandoffNotAdmitted,
    /// A presented Kernel session token is not the live registration digest:
    /// the binding was issued under a superseded Kernel session, or the live
    /// registration lease already elapsed. A fresh binding is required.
    #[error("STALE_AUTHORITY_EPOCH")]
    OperatorSessionTokenStale,
    /// A presented Windows SID/logon Session is not the installation/SID/
    /// Session tuple this broker was admitted for. Another principal's
    /// binding is refused, never adopted.
    #[error("BROKER_REGISTRATION_IDENTITY_FOREIGN")]
    OperatorBindingCrossSession,
    /// The OS-observed image of the redeeming client process is not the
    /// installation-approved Operator artifact this binding was issued for.
    #[error("BROKER_OPERATOR_CLIENT_PROCESS_FOREIGN")]
    OperatorClientProcessForeign,
    /// A state-changing request carries no authenticated Human principal, or
    /// names a principal that is not the Windows SID this broker session was
    /// admitted for.
    #[error("BROKER_HUMAN_PRINCIPAL_REQUIRED")]
    HumanPrincipalRequired,
    /// A state-changing request names a role or capability outside the exact
    /// set granted by the redeemed Kernel-backed binding.
    #[error("CAPABILITY_INTRODUCTION_REQUIRED")]
    HumanCapabilityNotGranted,
    /// A state-changing request carries no exact Kernel-canonicalized
    /// approval hash, carries a malformed one, or names a different hash
    /// than the one already bound to the same operation.
    #[error("BROKER_APPROVAL_HASH_REQUIRED")]
    HumanApprovalRequired,
    /// A broker-generation cutover stopped because termination of the
    /// superseded generation's Job Object is not proven, so the candidate is
    /// not marked active and the transition requires reconciliation. The
    /// receipt is published durably; it is not a completion.
    #[error("CUTOVER_REQUIRES_RECONCILIATION")]
    CutoverRequiresReconciliation,
    /// A broker-generation cutover stopped because a precondition this broker
    /// holds no fact for is unmet: no live logon Session, no superseded
    /// registration in this lineage, or a predecessor that did not move
    /// strictly forward inside one user Session.
    #[error("CUTOVER_PRECONDITION_UNMET")]
    CutoverPreconditionUnmet,
    /// A broker-generation cutover was attempted after the interactive logon
    /// Session ended. Logout stops cutover.
    #[error("CUTOVER_SESSION_GONE")]
    CutoverSessionGone,
    /// This broker process generation could not create and own a Job Object it
    /// can prove: the durable name is not a valid object-manager name, a Job
    /// Object already held this generation's name, Windows refused to admit
    /// this process to the Job Object it had just created, or the admitted
    /// assignment resolved to a different process. `I1.6` puts the broker in
    /// its own Job Object, so a generation that cannot prove that contour is
    /// refused rather than left running in a job it does not own.
    #[error("BROKER_GENERATION_JOB_UNOWNABLE")]
    GenerationJobUnownable,
}

impl BrokerAdmissionRefusal {
    /// Returns the exact stable wire code of this refusal.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProcessIdentityUnprovable => "BROKER_PROCESS_IDENTITY_UNPROVABLE",
            Self::ProcessIdentityChanged => "BROKER_PROCESS_IDENTITY_CHANGED",
            Self::RegistrationIdentityForeign | Self::OperatorBindingCrossSession => {
                "BROKER_REGISTRATION_IDENTITY_FOREIGN"
            }
            Self::OperationOutcomeUnreconciled => "BROKER_OPERATION_OUTCOME_UNRECONCILED",
            Self::IntroductionOperationNotGranted
            | Self::IntroductionResourceNotGranted
            | Self::IntroductionEffectCeilingExceeded
            | Self::IntroductionRequired
            | Self::IntroductionCredentialUnnamed
            | Self::OperatorHandoffNotAdmitted
            | Self::HumanCapabilityNotGranted => "CAPABILITY_INTRODUCTION_REQUIRED",
            Self::IntroductionExpired => "CAPABILITY_GRANT_REVOKED",
            Self::OperationIdRetired => "IDENTITY_CONFLICT",
            Self::RetiredOperation => "UNKNOWN_OUTCOME",
            Self::OperatorHandoffReplayed => "RESOURCE_LEASE_REPLAYED",
            Self::OperatorHandoffExpired => "DEADLINE_EXCEEDED",
            Self::OperatorSessionTokenStale | Self::OperatorHandoffStaleGeneration => {
                "STALE_AUTHORITY_EPOCH"
            }
            Self::OperatorClientProcessForeign => "BROKER_OPERATOR_CLIENT_PROCESS_FOREIGN",
            Self::HumanPrincipalRequired => "BROKER_HUMAN_PRINCIPAL_REQUIRED",
            Self::HumanApprovalRequired => "BROKER_APPROVAL_HASH_REQUIRED",
            Self::CutoverRequiresReconciliation => "CUTOVER_REQUIRES_RECONCILIATION",
            Self::CutoverPreconditionUnmet => "CUTOVER_PRECONDITION_UNMET",
            Self::CutoverSessionGone => "CUTOVER_SESSION_GONE",
            Self::OperatorHandoffUncomposed => "BROKER_OPERATOR_HANDOFF_UNCOMPOSED",
            Self::GenerationJobUnownable => "BROKER_GENERATION_JOB_UNOWNABLE",
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

/// Maximum wire length of one presented identity/authority text field. This
/// mirrors the `WinUI` `OperatorIdentityFields.MaxFieldChars` bound so both
/// ends of the binding refuse the same oversized values.
const AUTHORITY_FIELD_LIMIT: usize = 512;

/// OS-observed client evidence presented with one issued handoff at
/// redemption (I11.8 binding: Windows SID/session identity, client process
/// identity, fresh short-lived Kernel challenge/session token). Every field
/// is validated against the Kernel-backed session binding this broker
/// recorded when it issued the handoff; nothing here is trusted on receipt.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperatorClientBinding {
    /// OS process id of the redeeming `WinUI` client, observed by the pipe
    /// server from the live connection — never self-reported authority.
    pub client_process_id: u32,
    /// Windows SID the client proved for that process.
    pub windows_sid: String,
    /// Interactive logon Session the client proved for that process.
    pub interactive_session_id: String,
    /// Kernel session token the client's binding was issued under: the live
    /// Kernel-issued registration digest, never a caller-minted value.
    pub kernel_session_token: String,
}

/// Explicit authenticated Human authority for one broker state-changing
/// request (I11.3 human roles, I11.8 authentication: explicit principal,
/// role/capability, and the exact Kernel-canonicalized approval hash). The
/// broker admits the shape and the binding; exact approval semantics stay
/// Kernel-canonicalized through the typed Kernel path the request is then
/// dispatched on.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HumanStateAuthority {
    /// Authenticated Human principal: the Windows SID of the interactive
    /// user this broker session was admitted for.
    pub principal: String,
    /// Interactive logon Session the principal acts in.
    pub interactive_session_id: String,
    /// Requested Human role; must equal the role the redeemed binding
    /// granted.
    pub role: String,
    /// Requested capabilities; every entry must have been granted by the
    /// redeemed binding — a capability outside the grant is refused.
    pub capabilities: Vec<String>,
    /// Exact Kernel-canonicalized approval hash (lowercase SHA-256) for the
    /// critical action this request performs.
    pub approval_hash: String,
    /// Live Kernel session token this request is bound to.
    pub kernel_session_token: String,
}

/// One Kernel-backed Operator session binding recorded when the broker
/// issues a handoff (I11.8). The Kernel session token is the live
/// Kernel-issued registration digest: short-lived, refreshed by the
/// heartbeat loop, and stable only while the Kernel session is live — every
/// redemption and state-changing request re-proves it against the live
/// registration and its lease horizon. Rows are process-memory only, so a
/// broker restart discards every binding and a restarted UI must acquire a
/// fresh one.
#[derive(Clone, Debug, PartialEq, Eq)]
struct OperatorSessionBinding {
    endpoint: OperatorEndpoint,
    kernel_session_token: String,
    windows_sid: String,
    interactive_session_id: String,
    role: String,
    capabilities: Vec<String>,
    challenge_peer: Option<ProcessIdentity>,
    redeemed_peer: Option<ProcessIdentity>,
    redeemed: bool,
}

fn is_bounded_text(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= AUTHORITY_FIELD_LIMIT
        && !value.chars().any(char::is_control)
}

fn is_exact_approval_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

impl OperatorClientBinding {
    fn validate(&self) -> Result<(), CompositionError> {
        if self.client_process_id == 0 {
            return Err(BrokerAdmissionRefusal::OperatorClientProcessForeign
                .with_platform("redeeming client process id is not observable"));
        }
        if !is_bounded_text(&self.windows_sid) {
            return Err(BrokerAdmissionRefusal::OperatorBindingCrossSession
                .with_platform("redeeming client SID is not a bounded identity value"));
        }
        if !is_bounded_text(&self.interactive_session_id) {
            return Err(BrokerAdmissionRefusal::OperatorBindingCrossSession
                .with_platform("redeeming client session is not a bounded identity value"));
        }
        if !is_bounded_text(&self.kernel_session_token) {
            return Err(BrokerAdmissionRefusal::OperatorSessionTokenStale
                .with_platform("redeeming client session token is not a bounded token value"));
        }
        Ok(())
    }
}

impl HumanStateAuthority {
    fn validate(&self) -> Result<(), CompositionError> {
        if !is_bounded_text(&self.principal) {
            return Err(
                BrokerAdmissionRefusal::HumanPrincipalRequired.with_platform(
                    "state-changing request carries no bounded authenticated principal",
                ),
            );
        }
        if !is_bounded_text(&self.interactive_session_id) {
            return Err(BrokerAdmissionRefusal::OperatorBindingCrossSession
                .with_platform("state-changing request session is not a bounded identity value"));
        }
        if !is_bounded_text(&self.role) {
            return Err(BrokerAdmissionRefusal::HumanCapabilityNotGranted
                .with_platform("state-changing request carries no bounded role"));
        }
        if self.capabilities.is_empty() {
            return Err(BrokerAdmissionRefusal::HumanCapabilityNotGranted
                .with_platform("state-changing request carries no capability set"));
        }
        for capability in &self.capabilities {
            if !is_bounded_text(capability) {
                return Err(BrokerAdmissionRefusal::HumanCapabilityNotGranted
                    .with_platform("state-changing request capability is not a bounded value"));
            }
        }
        if !is_exact_approval_hash(&self.approval_hash) {
            return Err(BrokerAdmissionRefusal::HumanApprovalRequired.with_platform(
                "state-changing request carries no exact Kernel-canonicalized approval hash",
            ));
        }
        if !is_bounded_text(&self.kernel_session_token) {
            return Err(
                BrokerAdmissionRefusal::OperatorSessionTokenStale.with_platform(
                    "state-changing request session token is not a bounded token value",
                ),
            );
        }
        Ok(())
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
    fn issued_operation_identities(&self) -> Result<Vec<IssuedOperationIdentity>, String> {
        match self.issuer.lock() {
            Ok(issuer) => Ok(issuer
                .issued_identities()
                .into_iter()
                .map(IssuedOperationIdentity::from)
                .collect()),
            Err(_) => Err("broker identity lock is poisoned".to_owned()),
        }
    }

    fn process_effect_lineage(&self) -> Result<Vec<ProcessEffectLineage>, String> {
        match self.issuer.lock() {
            Ok(issuer) => Ok(issuer.process_effect_lineage()),
            Err(_) => Err("broker process-lineage lock is poisoned".to_owned()),
        }
    }
}

impl From<DurableIssuedIdentity> for IssuedOperationIdentity {
    fn from(issued: DurableIssuedIdentity) -> Self {
        Self {
            schema_version: issued.schema_version,
            operation: issued.operation,
            canonical_digest: issued.canonical_digest,
            request_id: issued.request_id,
            idempotency_key: issued.idempotency_key,
            cancellation_id: issued.cancellation_id,
            deadline_unix_ms: issued.deadline_unix_ms,
            registration_digest: issued.registration_digest,
            user_broker_epoch: issued.user_broker_epoch,
            request_identity: issued.request_identity,
            issued_at_ms: issued.issued_at_ms,
            caller_request_id: issued.caller_request_id,
            caller_idempotency_key: issued.caller_idempotency_key,
        }
    }
}

impl From<&IssuedOperationIdentity> for DurableIssuedIdentity {
    fn from(issued: &IssuedOperationIdentity) -> Self {
        Self {
            schema_version: issued.schema_version,
            operation: issued.operation.clone(),
            canonical_digest: issued.canonical_digest.clone(),
            request_id: issued.request_id.clone(),
            idempotency_key: issued.idempotency_key.clone(),
            cancellation_id: issued.cancellation_id.clone(),
            deadline_unix_ms: issued.deadline_unix_ms,
            registration_digest: issued.registration_digest.clone(),
            user_broker_epoch: issued.user_broker_epoch,
            request_identity: issued.request_identity.clone(),
            issued_at_ms: issued.issued_at_ms,
            caller_request_id: issued.caller_request_id.clone(),
            caller_idempotency_key: issued.caller_idempotency_key.clone(),
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
struct PendingProcessStart {
    request: ProcessRequest,
    stdin_payload: Option<Vec<u8>>,
    caller_request_id: String,
    grant_request_digest: String,
    process_request_digest: String,
}

struct LocalProcessPort {
    authority: Arc<BrokerDispatchAuthority>,
    executor: WindowsProcessExecutor,
    runtime: tokio::runtime::Runtime,
    evidence: Arc<Mutex<Vec<ProcessEvidence>>>,
    /// Sealed request and the exact one-shot standard-input bytes retained from
    /// `prepare_start`. The bytes live here, not in the sealed `ProcessRequest`
    /// (which is Kernel-signed P-03 effect material and must not grow a
    /// request-content field), and they are read at the start boundary rather
    /// than accepted again there, so the payload written to the child is the
    /// payload the durably committed request digest was computed from.
    pending_requests: BTreeMap<OperationId, PendingProcessStart>,
    identity_issuer: Option<IssuerHandle>,
    last_lineage_recovery_required: Option<bool>,
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
            last_lineage_recovery_required: None,
        })
    }

    /// Attaches the operation-identity issuer for process/effect lineage
    /// bookkeeping. The process cursor carries a recovery obligation if this
    /// observational ledger is unavailable when a real effect is returned.
    pub(crate) fn set_identity_issuer(&mut self, issuer: IssuerHandle) {
        self.identity_issuer = Some(issuer);
    }

    fn note_process_effect(
        &self,
        caller_request_id: &str,
        grant_request_digest: &str,
        process_request_digest: &str,
    ) -> bool {
        let Ok(now) = Self::now_ms() else {
            return true;
        };
        let Some(issuer) = self.identity_issuer.as_ref() else {
            return true;
        };
        let Ok(mut issuer) = issuer.lock() else {
            return true;
        };
        issuer
            .note_process_effect(
                caller_request_id,
                grant_request_digest,
                process_request_digest,
                now,
            )
            .is_err()
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
        stdin_payload: Option<&str>,
    ) -> Result<String, PortError> {
        let request = self.request_from_grant(grant)?;
        let operation_id = request.operation_id().clone();
        let request_digest = request.invocation_digest().to_owned();
        if self
            .pending_requests
            .insert(
                operation_id,
                PendingProcessStart {
                    request,
                    stdin_payload: stdin_payload.map(<str>::as_bytes).map(<[u8]>::to_vec),
                    caller_request_id: grant.approved.request_id.clone(),
                    grant_request_digest: grant.request_digest.clone(),
                    process_request_digest: request_digest.clone(),
                },
            )
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
        self.last_lineage_recovery_required = None;
        let pending = self
            .pending_requests
            .remove(&grant.approved.operation_id)
            .ok_or_else(|| PortError::Invalid("process start was not prepared".to_owned()))?;
        let request_digest = pending.request.invocation_digest().to_owned();
        if request_digest != expected_request_digest {
            return Err(PortError::Invalid(
                "prepared process request digest changed".to_owned(),
            ));
        }
        let sink = Arc::new(BrokerEvidenceSink {
            records: self.evidence.clone(),
        });
        // The payload is the one retained at preparation, never one supplied at
        // the start boundary, so the bytes the child reads are the bytes the
        // durably committed request digest covers. `None` takes the same path
        // `start_with_stdin` takes with no payload: the pipe is created, never
        // written, and closed.
        // `start_with_stdin` is the synchronous physical start, the same driver
        // the async `ProcessExecutor::start` method reaches, so it is driven on
        // this single-threaded runtime through `ready` rather than spawned.
        let start =
            self.executor
                .start_with_stdin(pending.request, sink, pending.stdin_payload.as_deref());
        let result = self.runtime.block_on(std::future::ready(start));
        self.last_lineage_recovery_required = match &result {
            Ok(_) => Some(self.note_process_effect(
                &pending.caller_request_id,
                &pending.grant_request_digest,
                &pending.process_request_digest,
            )),
            // The invocation was attempted, but its physical effect was not
            // proven. Do not write an effect-lineage row that could be read as
            // confirmation; preserve the exact Unknown cursor obligation.
            Err(ProcessExecutionError::UnknownOutcome) => Some(true),
            Err(_) => None,
        };
        match result {
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

    fn take_process_lineage_recovery_obligation(&mut self) -> Result<bool, PortError> {
        self.last_lineage_recovery_required.take().ok_or_else(|| {
            PortError::Invalid("process lineage status is unavailable for this start".to_owned())
        })
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
        let snapshot_limit = usize::try_from(SNAPSHOT_LIMIT).map_err(|_| {
            PortError::Invalid("snapshot limit does not fit the platform address space".to_owned())
        })?;
        let mut writer = BoundedSnapshotWriter::new(snapshot_limit);
        serde_json::to_writer(&mut writer, snapshot)
            .map_err(|error| PortError::Invalid(format!("encode snapshot: {error}")))?;
        let bytes = writer.bytes;
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
    /// The durable identity of the Job Object this broker process generation
    /// created and assigned itself to, bound to this generation by its process
    /// id and observed start instant. A surviving Job Object of the same
    /// durable name can never be a contour this generation joined, because
    /// creation refuses an existing name rather than opening it.
    pub generation_job: Option<&'a str>,
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
    /// The Job Object this broker process generation created and assigned
    /// itself to, bound to `process_binding` by construction.
    ///
    /// Creation is exclusive — the durable name carries this generation's
    /// process id and observed start instant, and `CreateJobObjectW` refuses a
    /// name that already exists — but exclusive creation is not handle
    /// ownership. The job's DACL is `D:P(A;;GA;;;SY)(A;;GA;;;OW)`, so a
    /// `LocalSystem` process or another process running as this same user can
    /// open that name and hold its own handle. This field is therefore the
    /// handle *this* generation created, not proof that it is the only handle
    /// in existence; while any other handle is open the kill-on-close limit
    /// does not fire on this field's release at all.
    ///
    /// It contains THIS broker process, so the invariant is: no path may drop
    /// the composition while it still owes a diagnostic. Dropping the
    /// composition releases this handle, which fires the kill-on-close limit
    /// installed before the handle was ever returned, and that termination
    /// happens inside `drop`. In `main` that is now the intended exit for the
    /// failed-`Ready`-write, unwritable-response, and stdin-EOF paths, and for
    /// the clean `Stop` path — the last of which therefore exits through
    /// kill-on-close instead of returning from `main`, and whose exit code is
    /// consequently the kernel's, not the process's own. The heartbeat-failure
    /// path deliberately does not drop the composition, so its
    /// `BROKER_HEARTBEAT_REJECTED` line is still written first.
    #[cfg(windows)]
    generation_job: own_generation_job::OwnedGenerationJob,
    registration_digest: Option<String>,
    identity_issuer: IssuerHandle,
    /// Kernel-backed Operator session bindings keyed by issued handoff
    /// nonce (I11.8). Each row pins the live Kernel-issued registration
    /// digest the handoff was issued under, the bound SID/Session tuple,
    /// and the exact granted role/capability set.
    /// Process-memory only: a broker restart discards every row, so a
    /// restarted UI can only redeem a freshly issued binding.
    operator_session_bindings: BTreeMap<String, OperatorSessionBinding>,
    /// Exact approval hashes bound to broker state-changing operations,
    /// keyed by operation identity (launch idempotency key or control
    /// operation id). One operation owns exactly one approved hash: a
    /// conflicting hash for the same operation is refused. Process-memory
    /// only, alongside the session bindings above.
    approval_bindings: BTreeMap<String, String>,
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

    fn restore_identity_issuer(
        broker: &UserBroker,
        issuer: &IssuerHandle,
    ) -> Result<(), CompositionError> {
        // Re-seed spent IDs before any Kernel operation can mint. Only the
        // exact active registration can admit an original replay identity.
        let restored_at = now_unix_ms()?;
        let current_registration = broker
            .registration()
            .filter(|registration| {
                registration.status == RegistrationStatus::Active
                    && restored_at < registration.expires_at
            })
            .cloned();
        let mut identity = issuer.lock().map_err(|_| CompositionError::KernelLock)?;
        if let Some(registration) = current_registration.as_ref() {
            let epoch = serde_json::to_value(&registration.authority_epoch)
                .map_err(|error| CompositionError::Launch(error.to_string()))?;
            identity
                .note_registration_binding(
                    &registration.registration_digest,
                    registration.user_broker_epoch,
                    &epoch,
                )
                .map_err(|error| CompositionError::OperationIdentityLedger(error.to_string()))?;
        }
        for retained in broker.recovered_operation_identities() {
            identity
                .restore_issued(&DurableIssuedIdentity::from(&retained), restored_at)
                .map_err(|error| CompositionError::OperationIdentityLedger(error.to_string()))?;
        }
        for retained in broker.recovered_process_effect_lineage() {
            identity
                .restore_process_effect_lineage(&retained)
                .map_err(|error| CompositionError::OperationIdentityLedger(error.to_string()))?;
        }
        Ok(())
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
        // Build and validate the I6.5 bridge contract for the composed broker.
        // The contract is bound to the broker's own protocol version and
        // service identity, not a self-reported version; a mismatch refuses
        // composition.
        let bridge_contract = user_broker_contract()
            .map_err(|error| CompositionError::InvalidConfiguration(error.to_string()))?;
        validate_user_broker_contract(&bridge_contract)
            .map_err(|error| CompositionError::InvalidConfiguration(error.to_string()))?;
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
                    process_effect_lineage: Vec::new(),
                    retired_operations: Vec::new(),
                    predecessor_registration: None,
                    cutover_receipt: None,
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
        Self::restore_identity_issuer(&broker, &issuer)?;
        let registration_digest = broker.registration_digest().map(ToOwned::to_owned);
        // The broker is its own failure domain: this process generation creates
        // one Job Object for itself and is assigned to it. Creation refuses an
        // existing name, so the contour is created here rather than joined, and
        // a generation that cannot create it, or cannot be assigned to the one
        // it just created, is refused.
        //
        // This is deliberately the LAST fallible statement in this function.
        // From the moment this process is a member of a job carrying
        // `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, dropping that job terminates
        // this process, so no `?` may follow: an error raised after this point
        // would drop the job on the way out and kill the broker inside the
        // error path, before the refusal could be reported. The only statement
        // after it is the `Ok(Self { .. })` construction, which cannot fail.
        #[cfg(windows)]
        let generation_job =
            own_generation_job::create_owned_generation_job(&process_binding.identity)?;
        Ok(Self {
            broker,
            snapshot,
            providers_admitted,
            launch_binding,
            launch_lease,
            process_binding: Some(process_binding),
            #[cfg(windows)]
            generation_job,
            registration_digest,
            identity_issuer: issuer,
            operator_session_bindings: BTreeMap::new(),
            approval_bindings: BTreeMap::new(),
            notify_launch: BrokerNotifyLaunchAuthority::unstaged(NotifyLaunchStage::Deferred {
                reason: "NOT_STAGED",
            }),
        })
    }

    pub fn readiness(&self) -> BrokerReadiness<'_> {
        // The Job Object identity is a Windows-only fact; the field stays
        // present on every build so the readiness shape does not fork.
        #[cfg(windows)]
        let generation_job = Some(self.generation_job.identity().name());
        #[cfg(not(windows))]
        let generation_job: Option<&str> = None;
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
            generation_job,
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
            self.sync_registration_binding(&receipt)?;
            self.registration_digest = Some(receipt.registration_digest.clone());
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
        let registration = self.broker.registration().cloned().ok_or_else(|| {
            CompositionError::Launch("heartbeat lost its registration".to_owned())
        })?;
        if registration.status != RegistrationStatus::Active
            || registration.registration_digest != receipt.registration_digest
            || registration.user_broker_epoch != receipt.user_broker_epoch
            || registration.fence_id != receipt.fence_id
            || registration.expires_at != receipt.expires_at
        {
            return Err(CompositionError::Launch(
                "heartbeat receipt differs from the current registration".to_owned(),
            ));
        }
        self.sync_registration_binding(&registration)?;
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
    /// request must satisfy three independent gates:
    ///
    /// 1. the protected launch lease still verifies and the registration is
    ///    heartbeated, so a revoked or expired broker cannot spawn;
    /// 2. this broker currently RETAINS a verified launch reference, resolved at
    ///    startup from the installer-published declaration and bound to the
    ///    broker's authenticated SID/session plus the Kernel-issued
    ///    registration digest;
    /// 3. the request names exactly that executable path and its artifact
    ///    digest equals the digest of the bytes this broker observed.
    ///
    /// Only then is the request dispatched on the existing authority/process
    /// ports, which apply the Kernel grant. A generic `Launch` request naming
    /// the notify image is refused by the binary before reaching here (see
    /// [`request_names_notify_image`]), so no other request shape can produce a
    /// normal notification invocation.
    pub fn launch_notify(
        &mut self,
        request: LaunchRequest,
    ) -> Result<eliot_user_broker_core::LaunchReceipt, CompositionError> {
        self.verify_launch_lease()?;
        notify_launch_callin::admit_notify_request(&self.notify_launch, &request).map_err(
            |error| CompositionError::Launch(format!("notify launch rejected: {}", error.code())),
        )?;
        // The dispatch itself is the existing generic authority/process path,
        // so the Kernel grant, operation identity, and fencing stay exactly
        // where they are; only the admission above is notify-specific.
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

    /// Admits one authenticated Human acknowledgement without spawning a
    /// canonical writer (issue #1780, A2).
    ///
    /// This is the composition's production entry to the acknowledgement leg:
    /// the broker is the only admitted spawner (I11.6:7, "canonical
    /// notification → User Broker → native toast → authenticated local UI"),
    /// so the broker is what admits the actor and validates the exact line
    /// the adapter schema defines
    /// ([`notify_launch_callin::render_notify_acknowledge_line`]).
    ///
    /// The same three independent gates as [`Self::launch_notify`] apply — the
    /// protected launch lease, the retained verified launch reference, and the
    /// request naming exactly those bytes — plus one more: a caller-supplied
    /// `stdin_payload` is refused, so only the triple this composition
    /// rendered and validated is ever admitted.
    ///
    /// The acknowledgement is a Human role action (I11.3:13) and it is not a
    /// resolution (I11.7:5): the principal travels as record data and the
    /// record stays unresolved. The canonical transition itself is owned by
    /// `eliotd`, not by any broker-spawned child: the adapter's direct frame
    /// reaches the store only through a dead route (the surface selector is
    /// admitted by no `frame_dispatch.rs` predicate, and the serving arm
    /// requires the daemon session), so no child is spawned here and this
    /// entry answers the admitted triple with an explicit non-completion
    /// instead of a launch receipt for a write that can never land.
    ///
    /// `principal` is the authenticated principal this broker admitted for the
    /// request. It is never taken from the request line: it is the identity
    /// `admit_human_state_change` proved against the live registration, so the
    /// canonical record can name no actor but the admitted Human.
    pub fn launch_notify_acknowledge(
        &mut self,
        request: &LaunchRequest,
        acknowledgement: &NotifyAcknowledge,
        principal: &str,
    ) -> Result<eliot_user_broker_core::LaunchReceipt, CompositionError> {
        self.verify_launch_lease()?;
        // This gate also refuses a caller-supplied `stdin_payload`, so the bytes
        // bound below are the only bytes this launch can ever carry.
        notify_launch_callin::admit_notify_request(&self.notify_launch, request).map_err(
            |error| CompositionError::Launch(format!("notify launch rejected: {}", error.code())),
        )?;
        let _line =
            notify_launch_callin::render_notify_acknowledge_line(acknowledgement, principal)
                .map_err(|error| {
                    CompositionError::Launch(format!("notify launch rejected: {}", error.code()))
                })?;
        // No child is spawned: the rendered line only proves the admitted
        // triple was well-formed, and its bytes are discarded. The canonical
        // acknowledgement is owned by `eliotd` (issue #1780, A2) — the
        // broker-spawned adapter reaches the store only through a dead frame
        // (the surface selector is admitted by no `frame_dispatch.rs`
        // predicate, and the serving arm requires the daemon session) — so
        // spawning it would mint a second ungoverned owner path (A0.3) and
        // answer a launch receipt for a write that can never land. The
        // admitted triple is refused here instead, until the acknowledgement
        // intake lane forwards it to the owner.
        Err(CompositionError::Launch(
            "notify acknowledgement not completed: canonical acknowledgement is owned by eliotd"
                .to_owned(),
        ))
    }

    /// Spawns the per-user notification adapter to deliver one canonical
    /// notification as a native toast (issue #1781, W2/A1).
    ///
    /// This is the composition's production entry to the delivery leg, and the
    /// reason `eliot-notify`'s delivery line has a caller: the broker is the
    /// only admitted spawner (I11.6:7, "canonical notification → User Broker →
    /// native toast → authenticated local UI"), so the broker is what composes
    /// the line the adapter serves
    /// ([`notify_launch_callin::render_notify_deliver_line`]).
    ///
    /// The same three independent gates as [`Self::launch_notify`] apply — the
    /// protected launch lease, the retained verified launch reference, and the
    /// request naming exactly those bytes — plus one more: a caller-supplied
    /// `stdin_payload` is refused, so the bytes handed to the child are always
    /// the line this composition rendered and never caller text. The delivery
    /// itself is applied and re-validated on the admitted Kernel-backed route
    /// inside the adapter.
    pub fn launch_notify_deliver(
        &mut self,
        request: LaunchRequest,
        delivery: &NotifyDeliver,
    ) -> Result<eliot_user_broker_core::LaunchReceipt, CompositionError> {
        self.verify_launch_lease()?;
        // This gate also refuses a caller-supplied `stdin_payload`, so the
        // bytes bound below are the only bytes this launch can ever carry.
        notify_launch_callin::admit_notify_request(&self.notify_launch, &request).map_err(
            |error| CompositionError::Launch(format!("notify launch rejected: {}", error.code())),
        )?;
        let line = notify_launch_callin::render_notify_deliver_line(delivery).map_err(|error| {
            CompositionError::Launch(format!("notify launch rejected: {}", error.code()))
        })?;
        // The rendered line becomes the admitted request's own standard-input
        // bytes, so it is inside `digest(&request)`: this operation identity
        // is bound to exactly this delivery, and a replay carrying different
        // bytes is a `ReplayConflict` rather than a second effect.
        let request = LaunchRequest {
            stdin_payload: Some(line),
            ..request
        };
        self.launch(request)
    }

    /// The composition's production entry to the owner-issued, single-use
    /// Operator handoff, and the replacement for a consumed-environment
    /// reconnect: a reconnect is *this call again*, never a replay of the
    /// previous endpoint.
    ///
    /// Everything the handoff is bound to comes from owner state, not from the
    /// caller. The installation/SID/logon Session, broker artifact, and
    /// installation epoch fence come from the retained protected launch
    /// declaration (whose lease and live process identity are re-proven first);
    /// the approved Operator image comes from that same declaration's
    /// `operator_artifact`; the endpoint generation is the live registration
    /// epoch, which the core reads from its own registration; the nonce is
    /// minted by the core authority. The caller's `request` may name only the
    /// role and the capability set, and any widening is refused.
    ///
    /// I11.8 additionally binds every issued handoff to the fresh
    /// short-lived Kernel session: the live Kernel-issued registration
    /// digest is recorded against the issued nonce together with the bound
    /// SID/Session tuple and the exact granted role/capability set.
    /// Redemption and every later state-changing request must still present
    /// that live token inside its lease horizon; a superseded session is
    /// stale, never continuous.
    ///
    /// It is deliberately not a heartbeat: an expired or fenced registration
    /// makes the handoff unavailable rather than being refreshed here, so a dead
    /// broker cannot mint one.
    pub fn admit_operator_handoff(
        &mut self,
        request: &OperatorHandoffRequest,
    ) -> Result<OperatorEndpoint, CompositionError> {
        self.verify_launch_lease()?;
        let artifact = self.operator_artifact()?;
        let observed_at = now_unix_ms()?;
        let live = self.live_registration()?;
        let endpoint = self
            .broker
            .issue_operator_handoff(request, &artifact, observed_at)
            .map_err(Self::classify_operator_handoff)?;
        let binding = self.launch_binding.as_ref().ok_or_else(|| {
            BrokerAdmissionRefusal::OperatorHandoffUncomposed
                .with_platform("protected launch configuration is not composed")
        })?;
        // Redeemed rows from a superseded Kernel session can never be
        // presented again, so they leave the ledger; unredeemed rows stay so
        // a late redemption reports stale rather than unknown.
        let live_token = live.registration_digest.clone();
        self.operator_session_bindings
            .retain(|_, row| !row.redeemed || row.kernel_session_token == live_token);
        self.operator_session_bindings.insert(
            endpoint.handoff_nonce.clone(),
            OperatorSessionBinding {
                endpoint: endpoint.clone(),
                kernel_session_token: live.registration_digest.clone(),
                windows_sid: binding.registration.windows_sid.clone(),
                interactive_session_id: binding.registration.interactive_session_id.clone(),
                role: endpoint.role.clone(),
                capabilities: endpoint.capabilities.clone(),
                challenge_peer: None,
                redeemed_peer: None,
                redeemed: false,
            },
        );
        Ok(endpoint)
    }

    /// Returns the existing live Kernel registration token for one exact,
    /// freshly issued endpoint after the connected pipe peer has been
    /// authenticated as the approved Operator process in the bound SID and
    /// interactive session. The peer identity is pinned so a different UI
    /// process cannot inherit this endpoint between challenge and redemption.
    pub fn challenge_operator_handoff(
        &mut self,
        endpoint: &OperatorEndpoint,
        peer: &NamedPipePeerEvidence,
    ) -> Result<String, CompositionError> {
        endpoint
            .validate()
            .map_err(Self::classify_operator_handoff)?;
        self.verify_launch_lease()?;
        let artifact = self.operator_artifact()?;
        let live = self.live_registration()?;
        let Some(row) = self
            .operator_session_bindings
            .get(&endpoint.handoff_nonce)
            .cloned()
        else {
            return Err(BrokerAdmissionRefusal::OperatorHandoffNotAdmitted
                .with_platform("challenge endpoint was not issued by this broker generation"));
        };
        if row.redeemed || row.endpoint != *endpoint {
            return Err(
                BrokerAdmissionRefusal::OperatorHandoffNotAdmitted.with_platform(
                    "challenge endpoint is consumed or differs from its issued binding",
                ),
            );
        }
        if row.kernel_session_token != live.registration_digest {
            return Err(BrokerAdmissionRefusal::OperatorSessionTokenStale
                .with_platform("challenge endpoint is not bound to the live Kernel registration"));
        }
        Self::validate_operator_pipe_peer(peer, &row, &artifact)?;
        if row
            .challenge_peer
            .as_ref()
            .is_some_and(|bound| bound != peer.process())
        {
            return Err(
                BrokerAdmissionRefusal::OperatorClientProcessForeign.with_platform(
                    "challenge endpoint is already bound to a different Operator process",
                ),
            );
        }
        let Some(stored) = self
            .operator_session_bindings
            .get_mut(&endpoint.handoff_nonce)
        else {
            return Err(BrokerAdmissionRefusal::OperatorHandoffNotAdmitted
                .with_platform("challenge binding disappeared before it could be pinned"));
        };
        stored.challenge_peer = Some(peer.process().clone());
        Ok(row.kernel_session_token)
    }

    /// Redeems one issued Operator handoff exactly once and returns the
    /// installation-approved image it authenticates.
    ///
    /// This is the redemption half of the same boundary, and it is where
    /// single-use is enforced rather than asserted: a second presentation of a
    /// consumed nonce is `RESOURCE_LEASE_REPLAYED`, an endpoint past its own
    /// expiry is `DEADLINE_EXCEEDED`, and an endpoint naming a superseded
    /// registration epoch or logon Session is `STALE_AUTHORITY_EPOCH`. It
    /// resolves and returns an artifact identity; it starts nothing.
    ///
    /// I11.8 redemption additionally proves the binding the `WinUI` client
    /// presents: the caller's `client` evidence must name the live Kernel
    /// session token this nonce was issued under (stale tokens are refused
    /// before any state change), the bound Windows SID/Session tuple
    /// (cross-session presentation is refused), and an OS-observed client
    /// process whose running image is the installation-approved Operator
    /// artifact. The endpoint's own role/capability set must equal the
    /// granted set exactly: a capability outside the grant is refused rather
    /// than narrowed.
    pub fn redeem_operator_handoff(
        &mut self,
        endpoint: &OperatorEndpoint,
        client: &OperatorClientBinding,
        peer: &NamedPipePeerEvidence,
    ) -> Result<OperatorArtifact, CompositionError> {
        self.verify_launch_lease()?;
        let artifact = self.operator_artifact()?;
        let now = now_unix_ms()?;
        client.validate()?;
        let Some(row) = self
            .operator_session_bindings
            .get(&endpoint.handoff_nonce)
            .cloned()
        else {
            // A nonce this process never issued (including every nonce from
            // before a restart, whose rows died with the previous process)
            // keeps the core single-use/expiry semantics below.
            return self
                .broker
                .consume_operator_handoff(endpoint, &artifact, now)
                .map_err(Self::classify_operator_handoff);
        };
        if row.redeemed {
            return self
                .broker
                .consume_operator_handoff(endpoint, &artifact, now)
                .map_err(Self::classify_operator_handoff);
        }
        if row.endpoint != *endpoint {
            return Err(BrokerAdmissionRefusal::OperatorHandoffNotAdmitted
                .with_platform("redeemed endpoint differs from the exact issued binding"));
        }
        let live = self.live_registration()?;
        if client.kernel_session_token != row.kernel_session_token
            || live.registration_digest != row.kernel_session_token
        {
            return Err(BrokerAdmissionRefusal::OperatorSessionTokenStale
                .with_platform("redeemed handoff does not present the live Kernel session token"));
        }
        if client.windows_sid != row.windows_sid
            || client.interactive_session_id != row.interactive_session_id
        {
            return Err(
                BrokerAdmissionRefusal::OperatorBindingCrossSession.with_platform(
                    "redeemed handoff presents a foreign Windows SID/session identity",
                ),
            );
        }
        if endpoint.role != row.role || endpoint.capabilities != row.capabilities {
            return Err(
                BrokerAdmissionRefusal::OperatorHandoffNotAdmitted.with_platform(
                    "redeemed handoff names a role/capability set outside the granted binding",
                ),
            );
        }
        if row.challenge_peer.as_ref() != Some(peer.process()) {
            return Err(
                BrokerAdmissionRefusal::OperatorClientProcessForeign.with_platform(
                    "redemption peer differs from the OS-authenticated challenge peer",
                ),
            );
        }
        if client.client_process_id != peer.process().process_id
            || client.windows_sid != peer.sid()
            || client.interactive_session_id != peer.session_id().to_string()
        {
            return Err(
                BrokerAdmissionRefusal::OperatorBindingCrossSession.with_platform(
                    "caller identity fields differ from the connected OS-observed peer",
                ),
            );
        }
        Self::validate_operator_pipe_peer(peer, &row, &artifact)?;
        let redeemed_artifact = self
            .broker
            .consume_operator_handoff(endpoint, &artifact, now)
            .map_err(Self::classify_operator_handoff)?;
        if let Some(stored) = self
            .operator_session_bindings
            .get_mut(&endpoint.handoff_nonce)
        {
            stored.redeemed_peer = Some(peer.process().clone());
            stored.redeemed = true;
        }
        self.operator_session_bindings.retain(|nonce, stored| {
            nonce == &endpoint.handoff_nonce
                || !stored.redeemed
                || stored.kernel_session_token != row.kernel_session_token
                || stored.windows_sid != row.windows_sid
                || stored.interactive_session_id != row.interactive_session_id
        });
        Ok(redeemed_artifact)
    }

    fn validate_operator_pipe_peer(
        peer: &NamedPipePeerEvidence,
        row: &OperatorSessionBinding,
        artifact: &OperatorArtifact,
    ) -> Result<(), CompositionError> {
        if peer.process().process_id == 0
            || peer.sid() != row.windows_sid
            || peer.session_id().to_string() != row.interactive_session_id
        {
            return Err(BrokerAdmissionRefusal::OperatorBindingCrossSession
                .with_platform("connected pipe peer SID/session differs from the issued binding"));
        }
        if !eliot_platform_windows::ordinal_eq_str(&peer.process().image_path, &artifact.executable)
        {
            return Err(BrokerAdmissionRefusal::OperatorClientProcessForeign
                .with_platform("connected pipe peer image is not the approved Operator artifact"));
        }
        Ok(())
    }

    /// Returns the live Kernel-issued registration this broker currently
    /// holds: admitted, `Active`, and inside its lease horizon. Anything
    /// else carries no session authority, so no handoff may be issued or
    /// redeemed and no state change may be admitted against it.
    fn live_registration(&self) -> Result<RegistrationReceipt, CompositionError> {
        let now = now_unix_ms()?;
        let live = self.broker.registration().cloned().ok_or_else(|| {
            BrokerAdmissionRefusal::OperatorHandoffStaleGeneration
                .with_platform("broker holds no live Kernel registration")
        })?;
        if live.status != RegistrationStatus::Active || now >= live.expires_at {
            return Err(BrokerAdmissionRefusal::OperatorHandoffStaleGeneration
                .with_platform("broker Kernel registration is not live"));
        }
        Ok(live)
    }

    /// Proves the redeeming `WinUI` client process from OS evidence: the
    /// process id is opened and observed live, and its running image must be
    /// exactly the installation-approved Operator artifact. A pid alone is
    /// never identity — Windows reuses ids — so the observation, not the
    /// presented number, decides.
    fn observe_operator_client(
        expected: &ProcessIdentity,
        artifact: &OperatorArtifact,
    ) -> Result<(), CompositionError> {
        #[cfg(not(windows))]
        {
            let _ = (expected, artifact);
            return Err(BrokerAdmissionRefusal::OperatorClientProcessForeign
                .with_platform("client process observation requires Windows"));
        }
        #[cfg(windows)]
        {
            let observed =
                eliot_platform_windows::observe_named_pipe_peer_process(expected.process_id)
                    .map_err(|error| {
                        BrokerAdmissionRefusal::OperatorClientProcessForeign
                            .with_platform(error.to_string())
                    })?;
            if observed.identity() != expected
                || !eliot_platform_windows::ordinal_eq_str(
                    observed.image_path(),
                    &artifact.executable,
                )
            {
                return Err(
                    BrokerAdmissionRefusal::OperatorClientProcessForeign.with_platform(
                        "redeeming Operator process generation is no longer the authenticated peer",
                    ),
                );
            }
            Ok(())
        }
    }

    /// Admits one broker state-changing request under an explicit
    /// authenticated Human authority (I11.3 roles, I11.8 authentication).
    /// Every check runs before any state change, and the admitted request is
    /// then dispatched on the existing typed Kernel path, where approval
    /// semantics stay Kernel-canonicalized:
    ///
    /// * the principal must be present and must be the Windows SID this
    ///   broker session was admitted for (omitted or foreign principals are
    ///   refused);
    /// * the presented Kernel session token must be the live registration
    ///   digest inside its lease horizon (missing or stale tokens refused);
    /// * the presented SID/Session must equal the bound tuple
    ///   (cross-session requests refused);
    /// * the presented role/capabilities must be covered by a redeemed
    ///   Kernel-backed binding for that live session (capability expansion
    ///   refused);
    /// * the presented approval hash must be one exact lowercase SHA-256,
    ///   and an operation owns exactly one hash: a conflicting hash for the
    ///   same `operation_key` is refused.
    pub fn admit_human_state_change(
        &mut self,
        authority: Option<&HumanStateAuthority>,
        operation_key: &str,
    ) -> Result<(), CompositionError> {
        let authority = authority.ok_or_else(|| {
            BrokerAdmissionRefusal::HumanPrincipalRequired
                .with_platform("state-changing request carries no authenticated Human principal")
        })?;
        authority.validate()?;
        if operation_key.trim().is_empty() || operation_key.chars().any(char::is_control) {
            return Err(BrokerAdmissionRefusal::HumanApprovalRequired
                .with_platform("state-changing request carries no bounded operation identity"));
        }
        let binding = self.launch_binding.as_ref().ok_or_else(|| {
            BrokerAdmissionRefusal::OperatorHandoffUncomposed
                .with_platform("protected launch configuration is not composed")
        })?;
        if authority.principal != binding.registration.windows_sid {
            return Err(
                BrokerAdmissionRefusal::HumanPrincipalRequired.with_platform(
                    "state-changing request principal is not the admitted session SID",
                ),
            );
        }
        if authority.interactive_session_id != binding.registration.interactive_session_id {
            return Err(BrokerAdmissionRefusal::OperatorBindingCrossSession
                .with_platform("state-changing request session is not the admitted session"));
        }
        let live = self.live_registration()?;
        if authority.kernel_session_token != live.registration_digest {
            return Err(
                BrokerAdmissionRefusal::OperatorSessionTokenStale.with_platform(
                    "state-changing request does not present the live Kernel session token",
                ),
            );
        }
        let granted = self.operator_session_bindings.values().find(|row| {
            row.redeemed
                && row.kernel_session_token == live.registration_digest
                && row.windows_sid == authority.principal
                && row.interactive_session_id == authority.interactive_session_id
        });
        let Some(granted) = granted else {
            return Err(
                BrokerAdmissionRefusal::HumanCapabilityNotGranted.with_platform(
                    "no redeemed Kernel-backed binding grants authority for this session",
                ),
            );
        };
        let Some(redeemed_peer) = granted.redeemed_peer.as_ref() else {
            return Err(
                BrokerAdmissionRefusal::OperatorClientProcessForeign.with_platform(
                    "redeemed authority has no retained OS-observed Operator process identity",
                ),
            );
        };
        let artifact = self.operator_artifact()?;
        Self::observe_operator_client(redeemed_peer, &artifact)?;
        if authority.role != granted.role || authority.capabilities != granted.capabilities {
            return Err(
                BrokerAdmissionRefusal::HumanCapabilityNotGranted.with_platform(
                    "state-changing request role and capability set must exactly match the redeemed binding",
                ),
            );
        }
        if let Some(bound) = self.approval_bindings.get(operation_key)
            && bound != &authority.approval_hash
        {
            return Err(BrokerAdmissionRefusal::HumanApprovalRequired.with_platform(
                "state-changing request approval hash conflicts with the hash bound to this operation",
            ));
        }
        self.approval_bindings
            .insert(operation_key.to_owned(), authority.approval_hash.clone());
        Ok(())
    }

    /// The installation-approved Operator image from the retained protected
    /// launch declaration.  It is not a configured value, a caller argument, or
    /// a discovered path: a broker without that declaration names no image.
    fn operator_artifact(&self) -> Result<OperatorArtifact, CompositionError> {
        let artifact = self
            .launch_binding
            .as_ref()
            .ok_or(
                BrokerAdmissionRefusal::OperatorHandoffUncomposed
                    .with_platform("protected launch configuration is not composed"),
            )?
            .operator_artifact
            .clone();
        Ok(OperatorArtifact {
            image_id: artifact.image_id,
            executable: artifact.executable,
            artifact_digest: artifact.artifact_digest,
        })
    }

    /// Projects one Operator-handoff refusal onto the broker's closed
    /// admission taxonomy.
    ///
    /// The three properties this boundary exists to hold — single-use,
    /// expiry, and generation binding — each keep their own exact stable code
    /// instead of collapsing into a generic composition error, so a reconnect
    /// attempt is distinguishable from a dead registration at the wire.
    fn classify_operator_handoff(error: BrokerError) -> CompositionError {
        let refusal = match error {
            BrokerError::ReplayConflict => Some(BrokerAdmissionRefusal::OperatorHandoffReplayed),
            BrokerError::StaleLease => Some(BrokerAdmissionRefusal::OperatorHandoffExpired),
            BrokerError::StaleEpoch | BrokerError::StaleRegistrationIdentity => {
                Some(BrokerAdmissionRefusal::OperatorHandoffStaleGeneration)
            }
            BrokerError::Denied | BrokerError::InvalidField(_) => {
                Some(BrokerAdmissionRefusal::OperatorHandoffNotAdmitted)
            }
            _ => None,
        };
        match refusal {
            Some(refusal) => refusal.with_platform(error),
            None => CompositionError::Recovery(error),
        }
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

    /// Publishes the registration/cutover receipt for the broker generation
    /// transition this lineage performed (I14.17, issue #1954).
    ///
    /// This changes durable broker state — the receipt and the recorded Session
    /// binding transfer are written through
    /// [`UserBroker::publish_cutover_receipt`] before this call returns — so it
    /// passes the same admitted-role gate as every other state-changing
    /// request. The operation identity it is bound to is the live registration
    /// digest, because that digest *is* the transition being published: the
    /// caller cannot choose it, and the authenticated Human authority must
    /// already present it as its live Kernel session token.
    ///
    /// The receipt is a record, never a completion signal. This owner cannot
    /// prove termination of the superseded generation's Job Object, so the
    /// candidate is not marked active and the transition is left for
    /// reconciliation; see `eliot_user_broker_core::OldJobObjectTermination`.
    pub fn publish_cutover_receipt(
        &mut self,
        authority: Option<&HumanStateAuthority>,
    ) -> Result<CutoverReceipt, CompositionError> {
        self.verify_launch_lease()?;
        let live = self.live_registration()?;
        self.admit_human_state_change(authority, &live.registration_digest)?;
        self.broker
            .publish_cutover_receipt(now_unix_ms()?)
            .map_err(Self::classify_cutover)
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

    /// Projects one cutover refusal onto the broker's closed admission
    /// taxonomy.
    ///
    /// The three conditions I14.17 makes distinct at the cutover boundary each
    /// keep their own exact stable code instead of collapsing into the generic
    /// composition error: a stopped cutover awaiting reconciliation, a cutover
    /// whose precondition this broker holds no fact for, and a cutover
    /// attempted after the logon Session ended are three different things to an
    /// operator deciding what to do next.
    fn classify_cutover(error: BrokerError) -> CompositionError {
        let refusal = match &error {
            BrokerError::CutoverRequiresReconciliation(_) => {
                Some(BrokerAdmissionRefusal::CutoverRequiresReconciliation)
            }
            BrokerError::CutoverPrecondition(_) | BrokerError::SessionBindingNotTransferred => {
                Some(BrokerAdmissionRefusal::CutoverPreconditionUnmet)
            }
            // Logout closed this registration, so there is no logon Session left
            // to move a binding within.
            BrokerError::LeaseExpired | BrokerError::StaleLease => {
                Some(BrokerAdmissionRefusal::CutoverSessionGone)
            }
            _ => None,
        };
        match refusal {
            Some(refusal) => refusal.with_platform(error),
            None => Self::classify(error),
        }
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

    /// Refreshes the issuer fence and retry generation from one validated
    /// Kernel-issued registration receipt. The broker-local epoch is retained
    /// as a distinct registration generation; only the lineage-aware epoch is
    /// merged into the State Fence.
    fn sync_registration_binding(
        &self,
        registration: &RegistrationReceipt,
    ) -> Result<(), CompositionError> {
        let epoch = serde_json::to_value(&registration.authority_epoch)
            .map_err(|error| CompositionError::Launch(error.to_string()))?;
        self.identity_issuer
            .lock()
            .map_err(|_| CompositionError::KernelLock)?
            .note_registration_binding(
                &registration.registration_digest,
                registration.user_broker_epoch,
                &epoch,
            )
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
