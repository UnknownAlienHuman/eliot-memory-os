use std::fmt;

use eliot_contracts::{EpochContractError, EpochId as EpochIdentity, EpochTransition, StateFence};
use eliot_observation_contracts::ObservationRecordEnvelope;
use eliot_platform::{HostProcessNonce, KernelActivationNonce, PlatformHandle, PortOutcome};
use eliot_runtime_contracts::{
    HealthDimension, KernelActivationState, ServiceProcessRecord, ServiceProcessState,
    SupervisionLeasePredecessorIdentity, WakeIntent, WakeIntentState,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::JournalError;
use crate::reactive_context::{
    ReactiveContextQueueState, ReactiveContextRecord, validate_record_for_journal,
};

fn deserialize_required_active_pipe<'de, D>(
    deserializer: D,
) -> Result<Option<PlatformHandle>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<PlatformHandle>::deserialize(deserializer)
}

fn deserialize_required_active_supervision_lease<'de, D>(
    deserializer: D,
) -> Result<Option<SupervisionLeasePredecessorIdentity>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<SupervisionLeasePredecessorIdentity>::deserialize(deserializer)
}

fn handle(value: &PlatformHandle, field: &'static str) -> Result<(), JournalError> {
    let text = value.as_str();
    if text.trim().is_empty() || text.chars().any(char::is_control) {
        return Err(JournalError::Invalid(format!("{field} must be non-blank")));
    }
    Ok(())
}

fn digest(value: &PlatformHandle, field: &'static str) -> Result<(), JournalError> {
    handle(value, field)?;
    let text = value.as_str();
    if text.len() != 64 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(JournalError::Invalid(format!(
            "{field} must be a 64-character hexadecimal digest"
        )));
    }
    Ok(())
}

/// Exact lowercase SHA-256 record-checksum form, as emitted by
/// [`crate::record_checksum`].
///
/// The reducer compares an attempt link to that checksum by exact string
/// identity, so a differently cased or truncated digest is a *different* byte
/// string and is refused rather than normalized into a match.
fn record_checksum_digest(value: &str, field: &'static str) -> Result<(), JournalError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(JournalError::Invalid(format!("{field} must be non-blank")));
    }
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(JournalError::Invalid(format!(
            "{field} must be a 64-character lowercase hexadecimal record checksum"
        )));
    }
    Ok(())
}

fn handles(
    values: &[PlatformHandle],
    field: &'static str,
    required: bool,
) -> Result<(), JournalError> {
    if required && values.is_empty() {
        return Err(JournalError::Invalid(format!("{field} must not be empty")));
    }
    for (index, value) in values.iter().enumerate() {
        handle(value, field)?;
        if values[..index].contains(value) {
            return Err(JournalError::Invalid(format!(
                "{field} contains duplicates"
            )));
        }
    }
    Ok(())
}

/// Epoch identity is the canonical lineage-aware [`EpochId`] owned by
/// `eliot-contracts`. Host keeps no parallel implementation: exact tuple
/// equality is the authority-match rule and only a same-lineage sequence+1
/// step is a direct child. There is deliberately no `Ord`, no scalar
/// coercion, and no cross-lineage ordering.
fn map_epoch_contract_error(error: &EpochContractError) -> JournalError {
    match error {
        EpochContractError::SequenceOverflow => JournalError::Sequence,
        _ => JournalError::EpochLineageConflict,
    }
}

/// Validates a canonical transition against the genesis/explicit-parent
/// invariants. Construction alone cannot prove them, so every admission and
/// reducer boundary calls this explicitly.
pub(crate) fn validate_epoch_transition(transition: &EpochTransition) -> Result<(), JournalError> {
    transition
        .validate()
        .map_err(|error| map_epoch_contract_error(&error))
}

/// Exact one-step child check between two validated transitions. `false`
/// covers both "valid but not a child" and cross-lineage inputs; an invalid
/// transition fails closed instead of comparing.
pub(crate) fn epoch_transition_is_direct_child_of(
    child: &EpochTransition,
    parent: &EpochTransition,
) -> Result<bool, JournalError> {
    validate_epoch_transition(child)?;
    validate_epoch_transition(parent)?;
    Ok(child.advances(&parent.current))
}

/// Reasons that require a fresh Host lineage instead of continuing a counter.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecoveryLineageReason {
    Corruption,
    Restore,
    Migration,
    BreakGlass,
}

/// External evidence for an explicitly recovered, globally distinct Host lineage.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryLineageEvidence {
    pub reason: RecoveryLineageReason,
    pub source_evidence_refs: Vec<PlatformHandle>,
}

impl RecoveryLineageEvidence {
    fn validate(&self) -> Result<(), JournalError> {
        handles(
            &self.source_evidence_refs,
            "host.recovery.source_evidence_refs",
            true,
        )
    }
}

/// Installation identity and exact parent-fenced Host epoch.
///
/// The epoch is the canonical [`EpochTransition`]: equality (not ordering)
/// is the authority rule, so this type keeps `Eq` but deliberately has no
/// `Ord` and no `Hash` over the transition.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInstallationEpoch {
    pub installation: PlatformHandle,
    pub epoch: EpochTransition,
    pub nonce: PlatformHandle,
    pub recovery: Option<RecoveryLineageEvidence>,
}

impl fmt::Debug for HostInstallationEpoch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HostInstallationEpoch")
            .field("installation", &self.installation)
            .field("epoch", &self.epoch)
            .field("nonce", &"<redacted>")
            .field("recovery", &self.recovery)
            .finish()
    }
}

impl HostInstallationEpoch {
    pub(crate) fn validate(&self) -> Result<(), JournalError> {
        handle(&self.installation, "host.installation")?;
        handle(&self.nonce, "host.nonce")?;
        validate_epoch_transition(&self.epoch)?;
        if let Some(recovery) = &self.recovery {
            recovery.validate()?;
            if self.epoch.parent.is_some() {
                return Err(JournalError::EpochLineageConflict);
            }
        }
        Ok(())
    }

    pub(crate) fn is_direct_child_of(&self, parent: &Self) -> Result<bool, JournalError> {
        self.validate()?;
        parent.validate()?;
        Ok(self.installation == parent.installation
            && epoch_transition_is_direct_child_of(&self.epoch, &parent.epoch)?)
    }

    /// Returns the Host-process credential under its canonical, non-activation type.
    pub fn host_process_nonce(&self) -> HostProcessNonce {
        HostProcessNonce::new(self.nonce.clone())
    }
}

/// Computes the canonical sequence-bound Host owner capability digest.
///
/// A direct-child Host preserves its epoch lineage, so the monotonic epoch
/// sequence is part of the owner identity. Consumers must use this function
/// rather than projecting an installation/lineage pair independently.
pub fn host_owner_epoch_digest(
    host_epoch: &HostInstallationEpoch,
) -> Result<PlatformHandle, JournalError> {
    host_epoch.validate()?;
    let bytes = serde_json::to_vec(&(
        "eliot.host.owner-epoch.v2",
        &host_epoch.installation,
        &host_epoch.epoch.current.lineage_id,
        host_epoch.epoch.current.sequence,
    ))
    .map_err(|error| {
        JournalError::Invalid(format!("serialize canonical Host owner epoch: {error}"))
    })?;
    PlatformHandle::new(format!("{:x}", Sha256::digest(bytes))).map_err(|error| {
        JournalError::Invalid(format!(
            "construct canonical Host owner epoch digest: {error}"
        ))
    })
}

/// Stable mutation identity used for replay and conflict detection.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyIdentity {
    pub operation_id: PlatformHandle,
    pub idempotency_key: PlatformHandle,
}

impl IdempotencyIdentity {
    pub(crate) fn validate(&self) -> Result<(), JournalError> {
        handle(&self.operation_id, "operation_id")?;
        handle(&self.idempotency_key, "idempotency_key")
    }
}

/// Every record carries the current Host and activation fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordFence {
    pub host: HostInstallationEpoch,
    /// The Eliot activation that owns this record. Every record in one
    /// activation generation must carry the same identity; the reducer, not
    /// a caller, establishes the binding against the activation projection.
    pub activation_id: PlatformHandle,
    pub activation_generation: EpochTransition,
}

impl RecordFence {
    pub(crate) fn validate(&self) -> Result<(), JournalError> {
        self.host.validate()?;
        handle(&self.activation_id, "fence.activation_id")?;
        validate_epoch_transition(&self.activation_generation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActivationState {
    Stopped,
    Starting,
    ControlReady,
    Active,
    Draining,
    StoppedClean,
    DegradedRecovery,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKernelStoreLineage {
    pub host_epoch: EpochIdentity,
    pub kernel_epoch: EpochIdentity,
    pub watchdog_epoch: EpochIdentity,
    pub store_generation: EpochIdentity,
}

impl HostKernelStoreLineage {
    fn validate(&self, host: &HostInstallationEpoch) -> Result<(), JournalError> {
        // Canonical epoch values are valid by construction (validated
        // lineage spelling, non-zero sequence); only the Host binding is
        // checked here.
        if self.host_epoch != host.epoch.current {
            return Err(JournalError::StaleFence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadinessEvidence {
    pub supervision_ready: bool,
    pub control_ready: bool,
    pub evidence_refs: Vec<PlatformHandle>,
}

impl ReadinessEvidence {
    fn validate(&self) -> Result<(), JournalError> {
        handles(&self.evidence_refs, "readiness.evidence_refs", true)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleTimestamps {
    pub started_at: Option<PlatformHandle>,
    pub ready_at: Option<PlatformHandle>,
    pub draining_at: Option<PlatformHandle>,
    pub stopped_at: Option<PlatformHandle>,
}

impl LifecycleTimestamps {
    fn validate(&self) -> Result<(), JournalError> {
        for (value, field) in [
            (&self.started_at, "timestamps.started_at"),
            (&self.ready_at, "timestamps.ready_at"),
            (&self.draining_at, "timestamps.draining_at"),
            (&self.stopped_at, "timestamps.stopped_at"),
        ] {
            if let Some(value) = value {
                handle(value, field)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureRecoveryDirective {
    pub failure_ref: PlatformHandle,
    pub recovery_owner: PlatformHandle,
    pub directive: PlatformHandle,
}

impl FailureRecoveryDirective {
    fn validate(&self) -> Result<(), JournalError> {
        handle(&self.failure_ref, "failure_ref")?;
        handle(&self.recovery_owner, "recovery_owner")?;
        handle(&self.directive, "recovery_directive")
    }
}

/// Complete Host activation projection from Implementation I1.5.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EliotActivationRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub activation_id: PlatformHandle,
    pub trigger_class: PlatformHandle,
    pub trigger_evidence: Vec<PlatformHandle>,
    pub requester_principal_session_or_scheduler: PlatformHandle,
    pub requested_capabilities: Vec<PlatformHandle>,
    pub candidate_scope: PlatformHandle,
    pub state: ActivationState,
    pub drain_generation: Option<EpochTransition>,
    pub lineage: HostKernelStoreLineage,
    pub readiness: ReadinessEvidence,
    pub governance_profile: PlatformHandle,
    pub runtime_lease_refs: Vec<PlatformHandle>,
    pub supervision_lease_refs: Vec<PlatformHandle>,
    pub wake_intent_refs: Vec<PlatformHandle>,
    pub drain_commit_ref: Option<PlatformHandle>,
    pub wake_during_drain_disposition: Option<WakeDisposition>,
    pub boot_session_evidence: Vec<PlatformHandle>,
    pub power_transition_evidence: Vec<PlatformHandle>,
    pub timestamps: LifecycleTimestamps,
    pub failure_and_recovery_directive: Option<FailureRecoveryDirective>,
}

impl EliotActivationRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        handle(&self.activation_id, "activation_id")?;
        if self.fence.activation_id != self.activation_id {
            return Err(JournalError::StaleFence);
        }
        handle(&self.trigger_class, "trigger_class")?;
        handles(&self.trigger_evidence, "trigger_evidence", true)?;
        handle(
            &self.requester_principal_session_or_scheduler,
            "requester_principal_session_or_scheduler",
        )?;
        handles(&self.requested_capabilities, "requested_capabilities", true)?;
        handle(&self.candidate_scope, "candidate_scope")?;
        if let Some(drain) = &self.drain_generation {
            validate_epoch_transition(drain)?;
            if drain.current.lineage_id != self.fence.activation_generation.current.lineage_id {
                return Err(JournalError::EpochLineageConflict);
            }
        }
        if matches!(
            self.state,
            ActivationState::Draining | ActivationState::StoppedClean
        ) && self.drain_generation.is_none()
        {
            return Err(JournalError::Invalid(
                "draining/clean-stop activation requires drain_generation".into(),
            ));
        }
        self.lineage.validate(&self.fence.host)?;
        self.readiness.validate()?;
        handle(&self.governance_profile, "governance_profile")?;
        handles(&self.runtime_lease_refs, "runtime_lease_refs", false)?;
        handles(
            &self.supervision_lease_refs,
            "supervision_lease_refs",
            false,
        )?;
        handles(&self.wake_intent_refs, "wake_intent_refs", false)?;
        if let Some(value) = &self.drain_commit_ref {
            handle(value, "drain_commit_ref")?;
        }
        handles(&self.boot_session_evidence, "boot_session_evidence", true)?;
        handles(
            &self.power_transition_evidence,
            "power_transition_evidence",
            false,
        )?;
        self.timestamps.validate()?;
        if let Some(directive) = &self.failure_and_recovery_directive {
            directive.validate()?;
        }
        if matches!(
            self.state,
            ActivationState::Failed | ActivationState::DegradedRecovery
        ) && self.failure_and_recovery_directive.is_none()
        {
            return Err(JournalError::Invalid(
                "failed/recovery activation requires a directive".into(),
            ));
        }
        if matches!(
            self.state,
            ActivationState::ControlReady | ActivationState::Active
        ) && !(self.readiness.control_ready && self.readiness.supervision_ready)
        {
            return Err(JournalError::Invalid(
                "ready/active activation requires control and supervision readiness".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NonceState {
    Unissued,
    Issued,
    Consumed,
    Revoked,
}

/// Exact durable binding needed to reopen the candidate Kernel Job.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelJobBinding {
    pub job_name: PlatformHandle,
    pub owner: PlatformHandle,
    pub root_pid: u32,
    pub root_start_time_100ns: u64,
    pub root_image_path: PlatformHandle,
    pub root_volume_serial_number: u32,
    pub root_file_index: u64,
}

impl KernelJobBinding {
    fn validate(&self) -> Result<(), JournalError> {
        handle(&self.job_name, "kernel.job_binding.job_name")?;
        handle(&self.owner, "kernel.job_binding.owner")?;
        if self.root_pid == 0 || self.root_start_time_100ns == 0 {
            return Err(JournalError::Invalid(
                "Kernel Job binding requires non-zero PID and start time".into(),
            ));
        }
        handle(&self.root_image_path, "kernel.job_binding.root_image_path")?;
        if self.root_image_path.as_str().encode_utf16().count() > 32_767
            || self.root_file_index == 0
            || self.root_volume_serial_number == 0
        {
            return Err(JournalError::Invalid(
                "Kernel Job binding has invalid image/file identity".into(),
            ));
        }
        Ok(())
    }

    fn root_process_handle(&self) -> String {
        format!("pid:{}:start:{}", self.root_pid, self.root_start_time_100ns)
    }
}

/// Durable source observation for the previous Kernel generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorKernelSource {
    pub host: HostInstallationEpoch,
    pub activation_identity: PlatformHandle,
    pub generation: EpochTransition,
    pub job: KernelJobBinding,
    pub process: ServiceProcessRecord,
    pub history_complete: bool,
    pub job_empty: bool,
    pub root_reaped: bool,
}

impl PriorKernelSource {
    fn validate(&self) -> Result<(), JournalError> {
        self.host.validate()?;
        handle(
            &self.activation_identity,
            "prior_kernel.activation_identity",
        )?;
        validate_epoch_transition(&self.generation)?;
        self.job.validate()?;
        self.process
            .validate()
            .map_err(|error| JournalError::Invalid(error.to_string()))?;
        if self.process.owner != self.job.owner.as_str()
            || self.process.process_id != self.job.root_process_handle()
        {
            return Err(JournalError::Invalid(
                "prior Kernel process does not match its Job root binding".into(),
            ));
        }
        Ok(())
    }

    fn is_fully_terminated(&self) -> bool {
        self.history_complete
            && self.job_empty
            && self.root_reaped
            && self.process.state.is_terminal()
    }
}

/// Non-opaque prior-Kernel disposition. `disposition_evidence` is forensic
/// context only and cannot substitute for these variants.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PriorKernelDisposition {
    NoPriorKernel,
    Running(PriorKernelSource),
    Terminated(PriorKernelSource),
    Unknown(PriorKernelSource),
}

impl PriorKernelDisposition {
    fn validate(&self) -> Result<(), JournalError> {
        match self {
            Self::NoPriorKernel => Ok(()),
            Self::Running(source) | Self::Terminated(source) | Self::Unknown(source) => {
                source.validate()
            }
        }
    }

    fn proves_terminated(&self) -> bool {
        match self {
            Self::NoPriorKernel => true,
            Self::Terminated(source) => source.is_fully_terminated(),
            Self::Running(_) | Self::Unknown(_) => false,
        }
    }

    pub(crate) fn binds_to(&self, prior: &KernelRecord) -> bool {
        let source = match self {
            Self::Terminated(source) | Self::Running(source) | Self::Unknown(source) => source,
            Self::NoPriorKernel => return false,
        };
        prior.candidate_job_binding.as_ref().is_some_and(|job| {
            source.host == prior.fence.host
                && source.activation_identity == prior.activation_identity
                && source.generation == prior.kernel_generation
                && source.job == *job
        })
    }
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OneTimeNonceState {
    /// Absent until the old Kernel disposition is durably proven.
    nonce_ref: Option<PlatformHandle>,
    state: NonceState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OneTimeNonceStateWire {
    nonce_ref: Option<PlatformHandle>,
    state: NonceState,
}

impl<'de> Deserialize<'de> for OneTimeNonceState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = OneTimeNonceStateWire::deserialize(deserializer)?;
        match (wire.nonce_ref, wire.state) {
            (None, NonceState::Unissued) => Ok(Self::unissued()),
            (
                Some(nonce),
                state @ (NonceState::Issued | NonceState::Consumed | NonceState::Revoked),
            ) => {
                let nonce = KernelActivationNonce::new(nonce).map_err(serde::de::Error::custom)?;
                Ok(Self {
                    nonce_ref: Some(nonce.into_handle()),
                    state,
                })
            }
            _ => Err(serde::de::Error::custom(
                "one-time nonce must be absent before issuance and present thereafter",
            )),
        }
    }
}

impl fmt::Debug for OneTimeNonceState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OneTimeNonceState")
            .field("nonce_ref", &self.nonce_ref.as_ref().map(|_| "<redacted>"))
            .field("state", &self.state)
            .finish()
    }
}

impl OneTimeNonceState {
    pub const fn state(&self) -> NonceState {
        self.state
    }

    /// Returns a non-secret SHA-256 projection of the retained Kernel
    /// activation nonce.
    ///
    /// The raw one-use nonce remains private to the Host journal contract;
    /// read-only observers can use this digest to prove that a later Kernel
    /// activation did not reuse the predecessor credential.
    #[must_use]
    pub fn activation_nonce_digest(&self) -> Option<String> {
        self.nonce_ref
            .as_ref()
            .map(|nonce| format!("{:x}", Sha256::digest(nonce.as_str().as_bytes())))
    }

    pub(crate) fn nonce_ref(&self) -> Option<&PlatformHandle> {
        self.nonce_ref.as_ref()
    }

    /// Sole compatibility constructor used by the journal replay boundary.
    const fn from_legacy_raw(nonce_ref: Option<PlatformHandle>, state: NonceState) -> Self {
        Self { nonce_ref, state }
    }

    fn validate(&self) -> Result<(), JournalError> {
        match (&self.nonce_ref, self.state) {
            (None, NonceState::Unissued) => Ok(()),
            (Some(nonce), NonceState::Issued | NonceState::Consumed | NonceState::Revoked) => {
                // Old journal frames stored an opaque non-blank handle. Keep
                // replay compatibility; new issuance must use `issued`, which
                // accepts only the canonical 256-bit typed nonce.
                handle(nonce, "kernel.nonce_ref")
            }
            _ => Err(JournalError::Invalid(
                "one-time nonce must be absent before issuance and present thereafter".into(),
            )),
        }
    }

    fn validate_live_admission(&self) -> Result<(), JournalError> {
        self.validate()?;
        if let Some(nonce) = self.nonce_ref.as_ref() {
            KernelActivationNonce::new(nonce.clone())
                .map_err(|error| JournalError::Invalid(error.to_string()))?;
        }
        Ok(())
    }

    pub const fn unissued() -> Self {
        Self {
            nonce_ref: None,
            state: NonceState::Unissued,
        }
    }

    pub fn issued(nonce: KernelActivationNonce) -> Self {
        Self {
            nonce_ref: Some(nonce.into_handle()),
            state: NonceState::Issued,
        }
    }

    pub fn consume(&self) -> Result<Self, JournalError> {
        if self.state != NonceState::Issued {
            return Err(JournalError::Invalid(
                "only an issued Kernel activation nonce may be consumed".into(),
            ));
        }
        Ok(Self {
            nonce_ref: self.nonce_ref.clone(),
            state: NonceState::Consumed,
        })
    }

    pub fn revoke(&self) -> Result<Self, JournalError> {
        if self.state != NonceState::Issued {
            return Err(JournalError::Invalid(
                "only an issued Kernel activation nonce may be revoked".into(),
            ));
        }
        Ok(Self {
            nonce_ref: self.nonce_ref.clone(),
            state: NonceState::Revoked,
        })
    }

    pub fn activation_nonce(&self) -> Result<Option<KernelActivationNonce>, JournalError> {
        match self.state {
            NonceState::Unissued => Ok(None),
            NonceState::Issued => self
                .nonce_ref
                .as_ref()
                .map(|nonce| {
                    KernelActivationNonce::new(nonce.clone())
                        .map_err(|error| JournalError::Invalid(error.to_string()))
                })
                .transpose(),
            NonceState::Consumed | NonceState::Revoked => Err(JournalError::Invalid(
                "terminal Kernel activation nonce material cannot be re-issued".into(),
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub activation_identity: PlatformHandle,
    pub approved_artifact_hash: PlatformHandle,
    /// Exact pipe identity after the Kernel reaches Active.  There is no
    /// sentinel identity: before Active this must remain absent.
    #[serde(deserialize_with = "deserialize_required_active_pipe")]
    pub active_pipe_identity: Option<PlatformHandle>,
    pub candidate_pipe_identity: Option<PlatformHandle>,
    pub candidate_job_binding: Option<KernelJobBinding>,
    pub prior_kernel_disposition: PriorKernelDisposition,
    pub kernel_generation: EpochTransition,
    pub one_time_nonce: OneTimeNonceState,
    pub state: KernelActivationState,
    pub process: Option<ServiceProcessRecord>,
    pub readiness_evidence: Vec<PlatformHandle>,
    pub disposition_evidence: Vec<PlatformHandle>,
}

impl KernelRecord {
    /// Computes a fresh direct-child Kernel generation without changing the Host epoch.
    pub fn direct_child_generation(&self) -> Result<EpochTransition, JournalError> {
        EpochTransition::direct_child(&self.kernel_generation.current)
            .map_err(|error| map_epoch_contract_error(&error))
    }

    pub(crate) fn restore_legacy_nonce_for_replay(
        &mut self,
        nonce_ref: PlatformHandle,
    ) -> Result<(), JournalError> {
        if KernelActivationNonce::new(nonce_ref.clone()).is_ok()
            || !matches!(
                self.one_time_nonce.state,
                NonceState::Issued | NonceState::Consumed | NonceState::Revoked
            )
        {
            return Err(JournalError::Invalid(
                "legacy replay nonce boundary requires opaque issued nonce material".into(),
            ));
        }
        self.one_time_nonce =
            OneTimeNonceState::from_legacy_raw(Some(nonce_ref), self.one_time_nonce.state);
        self.one_time_nonce.validate()
    }

    #[allow(clippy::too_many_lines)]
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        handle(&self.activation_identity, "kernel.activation_identity")?;
        if self.fence.activation_id != self.activation_identity {
            return Err(JournalError::StaleFence);
        }
        handle(
            &self.approved_artifact_hash,
            "kernel.approved_artifact_hash",
        )?;
        if let Some(active_pipe) = &self.active_pipe_identity {
            handle(active_pipe, "kernel.active_pipe_identity")?;
        }
        if let Some(candidate) = &self.candidate_pipe_identity {
            handle(candidate, "kernel.candidate_pipe_identity")?;
        }
        validate_epoch_transition(&self.kernel_generation)?;
        self.one_time_nonce.validate()?;
        self.prior_kernel_disposition.validate()?;
        if let Some(binding) = &self.candidate_job_binding {
            binding.validate()?;
        }
        if self.candidate_job_binding.is_some()
            && !matches!(
                self.state,
                KernelActivationState::ShadowNoAuthority
                    | KernelActivationState::HandoffPrepared
                    | KernelActivationState::OldTerminated
                    | KernelActivationState::NonceIssued
                    | KernelActivationState::Activating
                    | KernelActivationState::Active
                    | KernelActivationState::Failed
                    | KernelActivationState::ManualRecovery
            )
        {
            return Err(JournalError::Invalid(
                "candidate Job binding is valid only after candidate launch or on retained terminal state"
                    .into(),
            ));
        }
        if let Some(process) = &self.process {
            process
                .validate()
                .map_err(|error| JournalError::Invalid(error.to_string()))?;
        }
        handles(
            &self.readiness_evidence,
            "kernel.readiness_evidence",
            self.state == KernelActivationState::Active,
        )?;
        handles(
            &self.disposition_evidence,
            "kernel.disposition_evidence",
            true,
        )?;
        let nonce_matches = match self.state {
            KernelActivationState::Idle
            | KernelActivationState::ShadowNoAuthority
            | KernelActivationState::HandoffPrepared
            | KernelActivationState::OldTerminated => {
                self.one_time_nonce.state == NonceState::Unissued
            }
            KernelActivationState::NonceIssued | KernelActivationState::Activating => {
                self.one_time_nonce.state == NonceState::Issued
            }
            KernelActivationState::Active => self.one_time_nonce.state == NonceState::Consumed,
            KernelActivationState::Failed => matches!(
                self.one_time_nonce.state,
                NonceState::Unissued | NonceState::Revoked | NonceState::Consumed
            ),
            KernelActivationState::ManualRecovery => matches!(
                self.one_time_nonce.state,
                NonceState::Unissued | NonceState::Revoked
            ),
        };
        if !nonce_matches {
            return Err(JournalError::Invalid(
                "kernel state and one-time nonce state disagree".into(),
            ));
        }
        if matches!(
            self.state,
            KernelActivationState::ShadowNoAuthority
                | KernelActivationState::HandoffPrepared
                | KernelActivationState::OldTerminated
                | KernelActivationState::NonceIssued
                | KernelActivationState::Activating
        ) && self.candidate_pipe_identity.is_none()
        {
            return Err(JournalError::Invalid(
                "candidate Kernel pipe identity is required during handoff".into(),
            ));
        }
        if matches!(
            self.state,
            KernelActivationState::ShadowNoAuthority
                | KernelActivationState::HandoffPrepared
                | KernelActivationState::OldTerminated
                | KernelActivationState::NonceIssued
                | KernelActivationState::Activating
                | KernelActivationState::Active
        ) && (self.candidate_job_binding.is_none() || self.process.is_none())
        {
            return Err(JournalError::Invalid(
                "launched Kernel candidate requires exact process and Job binding".into(),
            ));
        }
        if self.active_pipe_identity.is_some()
            && !matches!(
                self.state,
                KernelActivationState::Active | KernelActivationState::Failed
            )
        {
            return Err(JournalError::Invalid(
                "active Kernel pipe identity is valid only for Active or failed-after-Active"
                    .into(),
            ));
        }
        match self.state {
            KernelActivationState::Idle
            | KernelActivationState::ShadowNoAuthority
            | KernelActivationState::HandoffPrepared
            | KernelActivationState::OldTerminated
            | KernelActivationState::NonceIssued
            | KernelActivationState::Activating
                if self.active_pipe_identity.is_some() =>
            {
                return Err(JournalError::Invalid(
                    "active Kernel pipe identity must be absent before Active".into(),
                ));
            }
            KernelActivationState::Active => {
                let Some(active_pipe) = self.active_pipe_identity.as_ref() else {
                    return Err(JournalError::Invalid(
                        "active Kernel requires an active pipe identity".into(),
                    ));
                };
                if self.candidate_pipe_identity.as_ref() != Some(active_pipe) {
                    return Err(JournalError::StaleFence);
                }
            }
            KernelActivationState::Failed => match self.one_time_nonce.state {
                NonceState::Consumed => {
                    let Some(active_pipe) = self.active_pipe_identity.as_ref() else {
                        return Err(JournalError::Invalid(
                            "failed-after-Active Kernel must retain its active pipe identity"
                                .into(),
                        ));
                    };
                    if self.candidate_pipe_identity.as_ref() != Some(active_pipe) {
                        return Err(JournalError::StaleFence);
                    }
                }
                NonceState::Unissued | NonceState::Revoked
                    if self.active_pipe_identity.is_some() =>
                {
                    return Err(JournalError::Invalid(
                        "failure before Active cannot carry an active pipe identity".into(),
                    ));
                }
                NonceState::Unissued | NonceState::Revoked => {}
                NonceState::Issued => {
                    return Err(JournalError::Invalid(
                        "failed Kernel cannot retain an issued nonce".into(),
                    ));
                }
            },
            _ => {}
        }
        if matches!(
            self.state,
            KernelActivationState::OldTerminated
                | KernelActivationState::NonceIssued
                | KernelActivationState::Activating
                | KernelActivationState::Active
        ) && !self.prior_kernel_disposition.proves_terminated()
        {
            return Err(JournalError::Invalid(
                "Kernel authority requires exact prior disposition proof".into(),
            ));
        }
        if self.process.is_some() != self.candidate_job_binding.is_some() {
            return Err(JournalError::Invalid(
                "Kernel process and candidate Job binding must appear together".into(),
            ));
        }
        if let (Some(binding), Some(process)) = (&self.candidate_job_binding, &self.process)
            && (process.owner != binding.owner.as_str()
                || process.process_id != binding.root_process_handle())
        {
            return Err(JournalError::Invalid(
                "Kernel process does not match candidate Job root".into(),
            ));
        }
        if self.state == KernelActivationState::Active
            && !self.process.as_ref().is_some_and(|process| {
                process.state == ServiceProcessState::Ready
                    && process.health.liveness == HealthDimension::Healthy
                    && process.health.readiness == HealthDimension::Healthy
            })
        {
            return Err(JournalError::Invalid(
                "active Kernel requires ready process evidence with healthy liveness and readiness"
                    .into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DependencyState {
    Starting,
    Active,
    Failed,
    Stopped,
    Unknown,
}

/// Immutable, provider-neutral identity of the exact dependency launch plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImmutableProcessManifest {
    pub manifest_identity: PlatformHandle,
    pub executable_identity: PlatformHandle,
    pub invocation_hash: PlatformHandle,
    pub job_object_policy_ref: PlatformHandle,
    pub readiness_contract_ref: PlatformHandle,
}

impl ImmutableProcessManifest {
    fn validate(&self) -> Result<(), JournalError> {
        handle(
            &self.manifest_identity,
            "process_manifest.manifest_identity",
        )?;
        handle(
            &self.executable_identity,
            "process_manifest.executable_identity",
        )?;
        handle(&self.invocation_hash, "process_manifest.invocation_hash")?;
        handle(
            &self.job_object_policy_ref,
            "process_manifest.job_object_policy_ref",
        )?;
        handle(
            &self.readiness_contract_ref,
            "process_manifest.readiness_contract_ref",
        )
    }
}

/// Remaining bounded Host attempts for each dependency lifecycle action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyLifecycleBudget {
    pub budget_identity: PlatformHandle,
    pub start_attempts_remaining: u32,
    pub stop_attempts_remaining: u32,
    pub restart_attempts_remaining: u32,
}

impl DependencyLifecycleBudget {
    fn validate(&self) -> Result<(), JournalError> {
        handle(&self.budget_identity, "lifecycle_budget.budget_identity")
    }
}

/// Complete host-enforced resource ceiling for one dependency generation.
/// The physical P-02/P-09 adapter consumes these values; P-05 persists and
/// compares the immutable contract on every lifecycle transition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyResourceBudget {
    pub budget_identity: PlatformHandle,
    pub max_cpu_time_ms: u64,
    pub max_memory_bytes: u64,
    pub max_process_handles: u32,
    pub max_io_bytes: u64,
    pub max_child_processes: u32,
}

impl DependencyResourceBudget {
    fn validate(&self) -> Result<(), JournalError> {
        handle(&self.budget_identity, "resource_budget.budget_identity")?;
        if self.max_cpu_time_ms == 0
            || self.max_memory_bytes == 0
            || self.max_process_handles == 0
            || self.max_io_bytes == 0
        {
            return Err(JournalError::Invalid(
                "resource_budget ceilings must be positive".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub dependency: PlatformHandle,
    pub process_manifest: ImmutableProcessManifest,
    pub requester_identity: PlatformHandle,
    pub process_generation: EpochTransition,
    pub state: DependencyState,
    pub outcome: PortOutcome<ServiceProcessRecord>,
    pub pid_job_lineage_refs: Vec<PlatformHandle>,
    pub lifecycle_budget: DependencyLifecycleBudget,
    pub resource_budget: DependencyResourceBudget,
    pub approved_artifact_hash: PlatformHandle,
    pub approved_config_hash: PlatformHandle,
    pub disposition_evidence: Vec<PlatformHandle>,
}

impl DependencyRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        handle(&self.dependency, "dependency")?;
        self.process_manifest.validate()?;
        handle(&self.requester_identity, "requester_identity")?;
        validate_epoch_transition(&self.process_generation)?;
        validate_process_outcome(&self.outcome)?;
        handles(&self.pid_job_lineage_refs, "pid_job_lineage_refs", false)?;
        self.lifecycle_budget.validate()?;
        self.resource_budget.validate()?;
        handle(&self.approved_artifact_hash, "approved_artifact_hash")?;
        handle(&self.approved_config_hash, "approved_config_hash")?;
        handles(&self.disposition_evidence, "disposition_evidence", true)?;
        if self.state == DependencyState::Active && !matches!(self.outcome, PortOutcome::Known(_)) {
            return Err(JournalError::Invalid(
                "active dependency requires a known process observation".into(),
            ));
        }
        Ok(())
    }
}

fn validate_process_outcome(
    outcome: &PortOutcome<ServiceProcessRecord>,
) -> Result<(), JournalError> {
    match outcome {
        PortOutcome::Known(process) => process
            .validate()
            .map_err(|error| JournalError::Invalid(error.to_string())),
        PortOutcome::Partial { value, missing } => {
            value
                .validate()
                .map_err(|error| JournalError::Invalid(error.to_string()))?;
            handles(missing, "dependency.outcome.missing", true)
        }
        PortOutcome::Unknown(_) | PortOutcome::Error(_) => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DrainState {
    Requested,
    Draining,
    Cancelled,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum WakeDisposition {
    CancelDrain,
    QueueNextGeneration,
    RejectStale,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub drain_generation: EpochTransition,
    pub state: DrainState,
    pub evidence_refs: Vec<PlatformHandle>,
    /// Attempt link of a re-armed pre-commit drain, set on exactly one edge:
    /// the `Cancelled -> Requested` successor inside the same
    /// `drain_generation` (Implementation I1.5: "A new observable-use trigger
    /// received before the durable drain linearization point cancels drain and
    /// returns the same generation to `ACTIVE` after readiness revalidation";
    /// the re-armed drain stays inside that same generation). The value is the
    /// exact record checksum of the `Cancelled` predecessor this attempt
    /// re-arms, so the projection keeps exactly one `DrainRecord` and still
    /// distinguishes attempt N from attempt N+1. Every other drain edge
    /// continues the current attempt and carries `None`.
    ///
    /// `default` is mandatory, not stylistic: `DrainRecord` and
    /// `HostStateRecord` both deny unknown fields and `JOURNAL_VERSION` is 3,
    /// so a required field would make every installed v3 frame fail
    /// `decode_record_for_replay` and render the whole epoch unloadable.
    ///
    /// `skip_serializing_if` is equally mandatory, for the same reason
    /// `EpochRetirementRecord::predecessor_relation` carries it (#2868):
    /// `record_checksum` hashes the RE-SERIALIZED record, so emitting
    /// `"expected_predecessor":null` for a frame written without the key would
    /// change that frame's checksum and therefore its recomputed transaction
    /// identity. The field was added to the frozen v3 schema without it, so
    /// every drain frame persisted before that change re-serializes
    /// differently; omitting the member keeps those frames byte-identical to the
    /// shape they were written with.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_predecessor: Option<String>,
}

impl DrainRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        validate_epoch_transition(&self.drain_generation)?;
        if self.drain_generation.current.lineage_id
            != self.fence.activation_generation.current.lineage_id
        {
            return Err(JournalError::EpochLineageConflict);
        }
        if let Some(predecessor) = self.expected_predecessor.as_deref() {
            record_checksum_digest(predecessor, "drain.expected_predecessor")?;
        }
        handles(&self.evidence_refs, "drain.evidence_refs", true)
    }
}

/// Durable drain linearization point from Implementation I1.5.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DrainCommitRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub drain_generation: EpochTransition,
    pub last_admission_closed_at: PlatformHandle,
    pub lease_and_pending_operation_snapshot: Vec<PlatformHandle>,
    pub authority_epochs_fenced: Vec<EpochIdentity>,
    pub processes_modules_and_store_branches_to_stop: Vec<PlatformHandle>,
    pub wake_during_drain_disposition: WakeDisposition,
    pub irreversible_stage: PlatformHandle,
    pub recovery_owner: PlatformHandle,
    pub committed_at: PlatformHandle,
}

impl DrainCommitRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        validate_epoch_transition(&self.drain_generation)?;
        handle(&self.last_admission_closed_at, "last_admission_closed_at")?;
        handles(
            &self.lease_and_pending_operation_snapshot,
            "lease_and_pending_operation_snapshot",
            false,
        )?;
        if self.authority_epochs_fenced.is_empty() {
            return Err(JournalError::Invalid(
                "authority_epochs_fenced must not be empty".into(),
            ));
        }
        // Fenced epochs are canonical values, valid by construction; only
        // exact duplication is rejected here.
        for (index, epoch) in self.authority_epochs_fenced.iter().enumerate() {
            if self.authority_epochs_fenced[..index].contains(epoch) {
                return Err(JournalError::Invalid(
                    "authority_epochs_fenced contains duplicates".into(),
                ));
            }
        }
        handles(
            &self.processes_modules_and_store_branches_to_stop,
            "processes_modules_and_store_branches_to_stop",
            true,
        )?;
        handle(&self.irreversible_stage, "irreversible_stage")?;
        handle(&self.recovery_owner, "recovery_owner")?;
        handle(&self.committed_at, "committed_at")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ServiceSafetyClass {
    ServiceSafe,
    UserSessionRequired,
}

/// Host binding for the complete C0-04 wake intent fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub wake_id: PlatformHandle,
    pub intent: WakeIntent,
    pub reason_evidence_refs: Vec<PlatformHandle>,
    pub earliest_start: PlatformHandle,
    pub deadline: PlatformHandle,
    pub expiry: PlatformHandle,
    pub required_capabilities: Vec<PlatformHandle>,
    pub maintenance_family: PlatformHandle,
    pub safety_class: ServiceSafetyClass,
    pub state_fence_revalidation_ref: PlatformHandle,
    pub budget_ref: PlatformHandle,
}

impl WakeRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        handle(&self.wake_id, "wake_id")?;
        self.intent
            .validate()
            .map_err(|error| JournalError::Invalid(error.to_string()))?;
        if self.intent.wake_id != self.wake_id.as_str() {
            return Err(JournalError::Invalid(
                "wake_id must equal intent.wake_id".into(),
            ));
        }
        handles(
            &self.reason_evidence_refs,
            "wake.reason_evidence_refs",
            true,
        )?;
        handle(&self.earliest_start, "wake.earliest_start")?;
        handle(&self.deadline, "wake.deadline")?;
        handle(&self.expiry, "wake.expiry")?;
        handles(
            &self.required_capabilities,
            "wake.required_capabilities",
            true,
        )?;
        handle(&self.maintenance_family, "wake.maintenance_family")?;
        handle(
            &self.state_fence_revalidation_ref,
            "wake.state_fence_revalidation_ref",
        )?;
        handle(&self.budget_ref, "wake.budget_ref")
    }
}

/// One compare-and-swap member of an atomic `UserAutomation` wake
/// cancellation.  The expected checksum binds the transition to the exact
/// snapshot validated by the caller; the journal reducer checks every member
/// before changing any member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeCancellationBatchEntry {
    pub expected_record_checksum: PlatformHandle,
    pub wake: WakeRecord,
}

impl WakeCancellationBatchEntry {
    fn validate(&self, batch_fence: &RecordFence) -> Result<(), JournalError> {
        digest(
            &self.expected_record_checksum,
            "wake_cancellation.expected_record_checksum",
        )?;
        self.wake.validate()?;
        if self.wake.fence != *batch_fence {
            return Err(JournalError::StaleFence);
        }
        if self.wake.intent.state != WakeIntentState::Cancelled {
            return Err(JournalError::Invalid(
                "wake cancellation batch entries must be Cancelled".into(),
            ));
        }
        Ok(())
    }
}

/// Atomic journal record for cancelling several unadmitted wakes.
///
/// The record is one journal transaction and one idempotency identity.  Its
/// reducer validates every expected checksum and lifecycle transition before
/// applying any replacement, so a later target cannot leave earlier targets
/// durably cancelled while returning an ordinary failure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeCancellationBatchRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub entries: Vec<WakeCancellationBatchEntry>,
}

impl WakeCancellationBatchRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        if self.entries.is_empty() {
            return Err(JournalError::Invalid(
                "wake cancellation batch must not be empty".into(),
            ));
        }
        let mut wake_ids = std::collections::BTreeSet::new();
        for entry in &self.entries {
            entry.validate(&self.fence)?;
            if !wake_ids.insert(entry.wake.wake_id.clone()) {
                return Err(JournalError::Invalid(
                    "wake cancellation batch contains duplicate wake ids".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Observation records cannot bypass the Host and activation fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostObservationRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub observation: ObservationRecordEnvelope,
    pub binding_evidence_refs: Vec<PlatformHandle>,
}

impl HostObservationRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        self.observation
            .validate()
            .map_err(|error| JournalError::Invalid(error.to_string()))?;
        handles(
            &self.binding_evidence_refs,
            "observation.binding_evidence_refs",
            true,
        )
    }
}

/// A durable Host observation of one already-validated Kernel-authored readiness proof.
///
/// This is deliberately not another Kernel state transition or a readiness receipt.
/// The journal reducer binds it to the exact active [`KernelRecord`] before it is
/// accepted, and later probes append additional observations.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelReadinessObservationRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub active_kernel_record_checksum: PlatformHandle,
    pub probe_request_digest: PlatformHandle,
    pub ready_receipt_digest: PlatformHandle,
    pub kernel_process: ServiceProcessRecord,
    pub kernel_job: KernelJobBinding,
    pub config_digest: PlatformHandle,
    pub authority_epoch: u64,
    pub store_fence: PlatformHandle,
    pub observed_at: PlatformHandle,
    pub evidence_refs: Vec<PlatformHandle>,
    /// Exact active supervision lease and ORS receipt retained for the next
    /// Host incarnation to fence. Absence is permitted only for genesis.
    #[serde(deserialize_with = "deserialize_required_active_supervision_lease")]
    pub active_supervision_lease: Option<SupervisionLeasePredecessorIdentity>,
}

/// Exact approved/current contour observed by Host immediately before journal admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadinessApprovedContour {
    pub config_digest: PlatformHandle,
    pub store_fence: PlatformHandle,
}

impl ReadinessApprovedContour {
    pub(crate) fn validate(&self) -> Result<(), JournalError> {
        digest(&self.config_digest, "readiness_contour.config_digest")?;
        handle(&self.store_fence, "readiness_contour.store_fence")
    }
}

impl KernelReadinessObservationRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        digest(
            &self.active_kernel_record_checksum,
            "readiness_observation.active_kernel_record_checksum",
        )?;
        digest(
            &self.probe_request_digest,
            "readiness_observation.probe_request_digest",
        )?;
        digest(
            &self.ready_receipt_digest,
            "readiness_observation.ready_receipt_digest",
        )?;
        digest(&self.config_digest, "readiness_observation.config_digest")?;
        self.kernel_process
            .validate()
            .map_err(|error| JournalError::Invalid(error.to_string()))?;
        self.kernel_job.validate()?;
        if self.kernel_process.owner != self.kernel_job.owner.as_str()
            || self.kernel_process.process_id != self.kernel_job.root_process_handle()
        {
            return Err(JournalError::Invalid(
                "readiness observation process does not match the Kernel Job root".into(),
            ));
        }
        if self.authority_epoch == 0
            || self.kernel_process.authority_epoch.value() != self.authority_epoch
        {
            return Err(JournalError::Invalid(
                "readiness observation authority epoch does not match the Kernel process".into(),
            ));
        }
        if self.kernel_process.state != ServiceProcessState::Ready
            || self.kernel_process.health.liveness != HealthDimension::Healthy
            || self.kernel_process.health.readiness != HealthDimension::Healthy
        {
            return Err(JournalError::Invalid(
                "readiness observation requires a live and ready Kernel process".into(),
            ));
        }
        handle(&self.store_fence, "readiness_observation.store_fence")?;
        handle(&self.observed_at, "readiness_observation.observed_at")?;
        handles(
            &self.evidence_refs,
            "readiness_observation.evidence_refs",
            true,
        )?;
        if let Some(identity) = &self.active_supervision_lease {
            identity
                .validate()
                .map_err(|error| JournalError::Invalid(error.to_string()))?;
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        active: &KernelRecord,
        active_checksum: &str,
    ) -> Result<(), JournalError> {
        self.validate()?;
        if active.state != KernelActivationState::Active
            || self.fence != active.fence
            || self.active_kernel_record_checksum.as_str() != active_checksum
            || active.candidate_job_binding.as_ref() != Some(&self.kernel_job)
            || self.authority_epoch != self.kernel_process.authority_epoch.value()
        {
            return Err(JournalError::StaleFence);
        }
        let Some(active_process) = active.process.as_ref() else {
            return Err(JournalError::StaleFence);
        };
        if active_process.process_id != self.kernel_process.process_id
            || active_process.owner != self.kernel_process.owner
            || active_process.authority_epoch != self.kernel_process.authority_epoch
        {
            return Err(JournalError::StaleFence);
        }
        Ok(())
    }

    pub fn validate_approved_contour(
        &self,
        expected: &ReadinessApprovedContour,
    ) -> Result<(), JournalError> {
        expected.validate()?;
        if self.config_digest != expected.config_digest || self.store_fence != expected.store_fence
        {
            return Err(JournalError::StaleFence);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalManifest {
    pub schema_version: u16,
    pub last_sequence: u64,
    pub last_checksum: PlatformHandle,
}

impl JournalManifest {
    fn validate(&self) -> Result<(), JournalError> {
        handle(&self.last_checksum, "manifest.last_checksum")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanMarker {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub manifest: JournalManifest,
    pub shutdown_evidence_refs: Vec<PlatformHandle>,
}

impl CleanMarker {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        self.manifest.validate()?;
        handles(&self.shutdown_evidence_refs, "shutdown_evidence_refs", true)
    }
}

/// Domain separator and contract revision of [`PredecessorRetirementRelation`].
///
/// The relation is a closed, versioned record. The version is part of the
/// canonical bytes hashed into `relation_digest`, so a future revision of this
/// contract cannot be replayed as this one.
pub const PREDECESSOR_RETIREMENT_RELATION_CONTRACT: &str =
    "eliot.host.predecessor-retirement-relation.v1";

/// Owner-issued proof that one exact installation generation was carried by one
/// exact Host epoch, issued for one cutover operation (#2868).
///
/// # Why this record exists
///
/// A cutover names its predecessor as a GENERATION (`PlatformHandle`, compared
/// against the installation registry's `active_generation()`), while the Host
/// journal owns EPOCHS. Before this record the retirement effect accepted the
/// epoch to retire as an independent parameter and proved only that it was
/// *some* unretired prior epoch of the same installation. With two outstanding
/// prior epochs that proof is satisfied by the wrong one, so the effect and the
/// `Reconciled` disposition it reported were not bound to the predecessor the
/// cutover actually consumed.
///
/// Nothing else in the durable state preserves the mapping for a PREDECESSOR.
/// The installation registry does construct the join - `ActivationCommitFence`
/// pairs an approved `generation: PlatformHandle` with a mandatory
/// `phase_b_live_binding` naming the Host epoch - but for the activation being
/// COMMITTED, and staging a new approved generation clears the registry's single
/// such fence, which the cutover's own target staging does before its CAS. The
/// Host journal's `CutoverIntentRecord` names installation generations, but its
/// `RecordFence` binds them to the epoch that PERFORMED the cutover, never to the
/// epoch that carried the predecessor generation. This record is therefore the
/// only place the predecessor's mapping can be preserved, and it is preserved by
/// whoever can prove it, not by the retirement effect.
///
/// # Effect identity
///
/// Every field that affects authority, scope, ordering, privacy or effect is
/// inside `relation_digest`, and [`PredecessorRetirementRelation::validate`]
/// RE-DERIVES that digest from the field values instead of shape-checking it. A
/// changed mapping under one `cutover_operation` identity therefore cannot keep
/// the original digest and cannot pass validation with it (I5.27).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PredecessorRetirementRelation {
    /// [`PREDECESSOR_RETIREMENT_RELATION_CONTRACT`], exactly.
    pub contract: PlatformHandle,
    /// Installation whose registry owns the predecessor generation.
    pub installation: PlatformHandle,
    /// Exact expected predecessor generation this cutover consumed.
    pub predecessor_generation: PlatformHandle,
    /// Exact Host epoch that carried `predecessor_generation`.
    pub retired_host: HostInstallationEpoch,
    /// Canonical `(installation, epoch)` digest of `retired_host`, recomputed by
    /// [`host_owner_epoch_digest`]. Present so a reader can match the epoch
    /// without re-deriving it, and checked so the two cannot disagree.
    pub retired_host_epoch_digest: PlatformHandle,
    /// Activation the issuer recorded for the predecessor it retires.
    pub activation_id: PlatformHandle,
    /// Host activation lineage the issuer recorded for `retired_host`.
    ///
    /// This is the retired epoch's own recorded transition, which is what an
    /// issuer can actually observe for a predecessor. It is NOT the activation
    /// that owned the predecessor generation: that transition lives in the retired
    /// epoch's own log (`EliotActivationRecord`) and no current owner retains it
    /// once the epoch is retired. An [`EpochRetirementRecord`] therefore carries
    /// two distinct `activation_generation`-named fields - this one, and
    /// `fence.activation_generation` for the activation performing the cutover -
    /// holding different values. Neither is checked against the other, and a
    /// reader must not treat this field as proof of the activation that owned the
    /// retired generation.
    pub activation_generation: EpochTransition,
    /// Authority fence under which the issuer observed the mapping.
    pub state_fence: StateFence,
    /// The cutover operation identity this relation is issued for. A relation
    /// is operation-specific: a different operation does not inherit it.
    pub cutover_operation: IdempotencyIdentity,
    /// Owner that issued the relation.
    pub relation_issuer: PlatformHandle,
    /// Issuer-recorded issuance identity for this exact relation.
    ///
    /// This is deliberately NOT a wall-clock reading. The issuer supplies it and
    /// [`PredecessorRetirementRelation::issue`] covers it with `relation_digest`,
    /// so it is a currentness commitment over the owner read that produced the
    /// relation rather than a timestamp the effect could fabricate. A pure crate
    /// that may not read a clock (and the Host journal owner is one) therefore
    /// still issues a reproducible value.
    ///
    /// What it commits to is exactly what the issuer hashed into it - the
    /// owner-read facts behind this relation. This record cannot itself verify
    /// that set; a reader must compare it against the issuer's own inputs. An
    /// issuer that omits a fact it consumed produces an `issued_at` that does not
    /// move when that fact changes, so the field is only as strong as the issuer's
    /// construction of it.
    pub issued_at: PlatformHandle,
    /// Canonical digest over the contract separator and every field above.
    pub relation_digest: PlatformHandle,
}

impl PredecessorRetirementRelation {
    /// Constructs one relation from issuer-proved facts and returns it only if
    /// it validates.
    ///
    /// `relation_digest` and `retired_host_epoch_digest` are NOT inputs: both are
    /// re-derived here from the values that were supplied, and the finished record
    /// is validated before it is handed back. So a caller cannot present a mapping
    /// whose digest was computed over different contents (I5.27).
    ///
    /// This is a convenience that makes the correct construction the easy one, NOT
    /// a gate. The type's fields are `pub`, it is not `#[non_exhaustive]`, it
    /// derives `Deserialize`, and this constructor is `pub` - so any dependent
    /// crate can equally build a value and recompute the digest by the documented
    /// canonical formula. Nothing may treat "built by `issue`" as provenance.
    /// What actually bounds a forged relation is structural and lives elsewhere:
    /// the retirement effect accepts no relation from any caller, and this
    /// journal's own reducer re-checks a record's relation against the retained
    /// cutover intent before it is admitted.
    ///
    /// It grants no authority by itself. A relation proves a mapping only for the
    /// cutover operation it names, and it becomes durable evidence only when the
    /// journal owner appends it inside an [`EpochRetirementRecord`] whose
    /// `retired_host` is the same epoch.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError::Invalid`] when a supplied fact fails this record's
    /// own validation - for example a `retired_host` belonging to another
    /// installation, an unusable handle, or a `state_fence` the fence contract
    /// rejects. It does NOT report a mismatched epoch digest: that field is
    /// computed from `retired_host` here, so it cannot disagree unless the epoch
    /// itself is invalid.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        installation: PlatformHandle,
        predecessor_generation: PlatformHandle,
        retired_host: HostInstallationEpoch,
        activation_id: PlatformHandle,
        activation_generation: EpochTransition,
        state_fence: StateFence,
        cutover_operation: IdempotencyIdentity,
        relation_issuer: PlatformHandle,
        issued_at: PlatformHandle,
    ) -> Result<Self, JournalError> {
        let mut value = Self {
            contract: PlatformHandle::new(PREDECESSOR_RETIREMENT_RELATION_CONTRACT).map_err(
                |error| {
                    JournalError::Invalid(format!(
                        "predecessor_relation.contract is not constructible: {error}"
                    ))
                },
            )?,
            installation,
            predecessor_generation,
            retired_host,
            retired_host_epoch_digest: PlatformHandle::new("pending").map_err(|error| {
                JournalError::Invalid(format!(
                    "predecessor_relation.retired_host_epoch_digest is not constructible: {error}"
                ))
            })?,
            activation_id,
            activation_generation,
            state_fence,
            cutover_operation,
            relation_issuer,
            issued_at,
            relation_digest: PlatformHandle::new("pending").map_err(|error| {
                JournalError::Invalid(format!(
                    "predecessor_relation.relation_digest is not constructible: {error}"
                ))
            })?,
        };
        value.retired_host_epoch_digest = host_owner_epoch_digest(&value.retired_host)?;
        value.relation_digest = value.canonical_digest()?;
        value.validate()?;
        Ok(value)
    }

    /// The canonical digest this relation's own field values produce.
    ///
    /// Deterministic and versioned: the contract separator is the first tuple
    /// element, so a later revision of this contract cannot produce this
    /// revision's digest. `relation_digest` is excluded because it is the value
    /// being checked; including it would be circular.
    fn canonical_digest(&self) -> Result<PlatformHandle, JournalError> {
        let bytes = serde_json::to_vec(&(
            PREDECESSOR_RETIREMENT_RELATION_CONTRACT,
            &self.installation,
            &self.predecessor_generation,
            &self.retired_host,
            &self.retired_host_epoch_digest,
            &self.activation_id,
            &self.activation_generation,
            &self.state_fence,
            &self.cutover_operation,
            &self.relation_issuer,
            &self.issued_at,
        ))
        .map_err(|error| {
            JournalError::Invalid(format!("predecessor_relation is not encodable: {error}"))
        })?;
        PlatformHandle::new(format!("{:x}", Sha256::digest(bytes)))
            .map_err(|error| JournalError::Invalid(format!("predecessor_relation digest: {error}")))
    }

    fn validate(&self) -> Result<(), JournalError> {
        if self.contract.as_str() != PREDECESSOR_RETIREMENT_RELATION_CONTRACT {
            return Err(JournalError::Invalid(
                "predecessor_relation.contract is not the accepted relation contract".to_owned(),
            ));
        }
        handle(&self.installation, "predecessor_relation.installation")?;
        handle(
            &self.predecessor_generation,
            "predecessor_relation.predecessor_generation",
        )?;
        self.retired_host.validate()?;
        if self.retired_host.installation != self.installation {
            return Err(JournalError::Invalid(
                "predecessor_relation.retired_host belongs to another installation".to_owned(),
            ));
        }
        // The epoch digest is not decorative: it is re-derived from the epoch it
        // claims, so the two can never name different Host epochs.
        let expected = host_owner_epoch_digest(&self.retired_host)?;
        if self.retired_host_epoch_digest != expected {
            return Err(JournalError::Invalid(
                "predecessor_relation.retired_host_epoch_digest does not match retired_host"
                    .to_owned(),
            ));
        }
        handle(&self.activation_id, "predecessor_relation.activation_id")?;
        validate_epoch_transition(&self.activation_generation)?;
        self.state_fence.validate().map_err(|error| {
            JournalError::Invalid(format!("predecessor_relation.state_fence: {error}"))
        })?;
        self.cutover_operation.validate()?;
        handle(
            &self.relation_issuer,
            "predecessor_relation.relation_issuer",
        )?;
        handle(&self.issued_at, "predecessor_relation.issued_at")?;
        // Re-derived, not shape-checked: the digest is a real commitment over the
        // mapping. A changed generation or epoch under one operation identity
        // cannot pass with the previous digest.
        if self.relation_digest != self.canonical_digest()? {
            return Err(JournalError::Invalid(
                "predecessor_relation.relation_digest does not match the relation contents"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    /// Whether this relation's GENERATION half names the request's exact
    /// expected predecessor generation of this exact installation.
    ///
    /// The generation side only. Whether the relation's `retired_host` is the
    /// epoch the record actually retired is a SEPARATE comparison, deliberately
    /// not folded in here: the record owner enforces that pairing
    /// ([`EpochRetirementRecord::validate`]), and a caller that satisfied a
    /// one-sided join would be recreating the defect this relation exists to
    /// remove.
    pub fn maps_generation(
        &self,
        installation: &PlatformHandle,
        predecessor: &PlatformHandle,
    ) -> bool {
        self.installation == *installation
            && self.predecessor_generation == *predecessor
            && self.retired_host.installation == *installation
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochRetirementRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub retired_host: HostInstallationEpoch,
    pub retirement_evidence_refs: Vec<PlatformHandle>,
    pub retired_at: PlatformHandle,
    /// Owner-issued predecessor-generation-to-Host-epoch relation for this
    /// retirement (#2868).
    ///
    /// `default` is mandatory, not stylistic: `EpochRetirementRecord` and
    /// `HostStateRecord` both deny unknown fields and `JOURNAL_VERSION` is 3,
    /// so a required field would make every already-installed v3 frame fail
    /// `decode_record_for_replay` and render the whole epoch unloadable.
    ///
    /// `None` is a legacy record written before the relation existed. It stays
    /// historical evidence with a LOWER proof ceiling: the status binder
    /// requires a relation for exact completion, so a legacy record can never
    /// close predecessor retirement and can never produce `Reconciled`.
    ///
    /// `skip_serializing_if` is a correctness requirement here, not an
    /// optimization. `record_checksum` is a SHA-256 over the RE-SERIALIZED
    /// record, and `query_epoch_retirement` recomputes the transaction identity
    /// from that checksum. Emitting `"predecessor_relation":null` for a record
    /// that was persisted without the key would change the checksum of every
    /// already-installed v3 frame, so its recomputed transaction identity would
    /// stop matching the durably recorded one - which would turn a genuine
    /// historical retirement into an absent one and a byte-identical re-append
    /// into an idempotency conflict. Omitting the member when it is absent is
    /// what keeps a legacy record serializing byte-identically to the shape it
    /// was written with. `default` remains required for the decode direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub predecessor_relation: Option<PredecessorRetirementRelation>,
}

impl EpochRetirementRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        self.retired_host.validate()?;
        handles(
            &self.retirement_evidence_refs,
            "retirement_evidence_refs",
            true,
        )?;
        handle(&self.retired_at, "retired_at")?;
        if let Some(relation) = &self.predecessor_relation {
            relation.validate()?;
            // The relation and the record name one retirement. A record whose
            // relation maps a DIFFERENT epoch than the record retires is
            // internally contradictory, and the journal owner refuses it here
            // rather than letting a reader pick the side it prefers.
            if relation.retired_host != self.retired_host
                || relation.installation != self.retired_host.installation
            {
                return Err(JournalError::Invalid(
                    "predecessor_relation names a different retired epoch than the record"
                        .to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Durable pre-effect intent and terminal disposition of one separately
/// authorized installation cutover (#961).
///
/// The Host journal is the durable owner of the cutover operation, so the
/// intent is appended BEFORE the installation-registry activation CAS: within
/// the Host epoch performing the cutover, a lost response, a crash between the
/// registry and the journal, or a terminal refusal can therefore never leave an
/// activation without a durable record of the operation that produced it.
///
/// Scope, stated precisely: like every other Host journal record, this one
/// lives in the log of the Host epoch that wrote it. A restart re-bases the
/// journal into a new epoch, so a cutover that spans an epoch boundary is
/// reconciled from the registry owner readback instead — the bounded `Unknown`
/// state the issue already requires — and is never asserted committed from a
/// record this projection no longer holds.
///
/// This is the same intent/terminal seam the Store-rebind record already uses —
/// one record type per Host-owned effect, never a shared catch-all.
///
/// Every state is a fresh append for the same cutover operation, installation
/// and canonical request digest, under a per-disposition journal mutation
/// identity; the reducer keeps the newest disposition, refuses a foreign
/// operation, and refuses any move out of a terminal state. The
/// `target_build_digest` / `target_config_digest` / `user_broker_ref` bindings
/// are the exact identities the admitted request carried, so the durable
/// record — not a console-presented value — is what a later reconciliation
/// re-reads.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CutoverIntentRecord {
    pub fence: RecordFence,
    /// Journal mutation identity. One per disposition of this cutover
    /// (`<cutover operation>:<state>`), because the journal keys
    /// `applied_operations` on this identity: reusing one identity for the
    /// intent and its terminal record would be a checksum conflict, not a
    /// second mutation. A retry of the *same* disposition reuses the identity
    /// and therefore replays byte-identically.
    pub operation: IdempotencyIdentity,
    /// Destination installation this cutover activates. Carried so the exact
    /// replay identity is self-contained in the durable record and a
    /// reconciliation never has to take it from a console-presented request.
    pub installation: PlatformHandle,
    /// Exact cutover operation identity issued for the destination
    /// installation.
    pub cutover_operation: PlatformHandle,
    /// Canonical cutover request digest (the idempotency key of the operation
    /// itself, distinct from the journal mutation identity above).
    pub request_digest: PlatformHandle,
    /// Exact active predecessor generation observed when the intent was
    /// committed.
    pub expected_predecessor: PlatformHandle,
    /// Exact approved target generation this cutover activates.
    pub target_generation: PlatformHandle,
    /// Owner-approved target build digest bound by the admitted request.
    pub target_build_digest: PlatformHandle,
    /// Owner-approved target configuration digest bound by the admitted
    /// request.
    pub target_config_digest: PlatformHandle,
    /// Owner-issued `UserBroker` identity for the destination generation.
    pub user_broker_ref: PlatformHandle,
    /// Bounded owner-receipt evidence bound to this intent. Digests only.
    pub intent_evidence_refs: Vec<PlatformHandle>,
    /// Exact disposition reached for this operation.
    pub state: CutoverIntentState,
}

impl CutoverIntentRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        handle(&self.installation, "cutover_intent.installation")?;
        handle(&self.cutover_operation, "cutover_intent.cutover_operation")?;
        handle(&self.request_digest, "cutover_intent.request_digest")?;
        handle(
            &self.expected_predecessor,
            "cutover_intent.expected_predecessor",
        )?;
        handle(&self.target_generation, "cutover_intent.target_generation")?;
        if self.expected_predecessor == self.target_generation {
            return Err(JournalError::Invalid(
                "cutover intent target must differ from the expected predecessor".into(),
            ));
        }
        handle(
            &self.target_build_digest,
            "cutover_intent.target_build_digest",
        )?;
        handle(
            &self.target_config_digest,
            "cutover_intent.target_config_digest",
        )?;
        handle(&self.user_broker_ref, "cutover_intent.user_broker_ref")?;
        handles(
            &self.intent_evidence_refs,
            "cutover_intent.intent_evidence_refs",
            true,
        )
    }
}

/// Disposition of one durable cutover intent.
///
/// `Pending` is the pre-effect state and the only non-terminal one: the
/// activation CAS may only run after it is durable. `Committed` and `Failed`
/// are terminal and are appended after the CAS attempt, so an operator can
/// always read which of the two happened for the exact operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CutoverIntentState {
    /// Durable intent committed; no activation effect applied yet.
    Pending,
    /// The registry activation CAS committed for this exact operation.
    Committed,
    /// Terminal refusal: no installation changed for this operation.
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreRebindState {
    Pending,
    Committed,
    /// The exact operation was reconciled as not committed.  This is a
    /// terminal disposition and permits a fresh operation with a new
    /// identity while retaining the old request for audit/retry binding.
    Aborted,
    /// The operation outcome could not be proven either way.  This is a
    /// durable recovery disposition; callers must retry the exact operation
    /// identity/query before starting a fresh rebind.
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreRebindRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub state: StoreRebindState,
    pub operation_id: PlatformHandle,
    pub request_digest: PlatformHandle,
    pub requirement: PlatformHandle,
    pub candidate_binding_digest: PlatformHandle,
    pub store_fence: PlatformHandle,
    pub process_id: u32,
    pub process_start_time_100ns: u64,
    pub process_image_path: PlatformHandle,
    pub job_name: PlatformHandle,
    pub generation: u64,
    pub authority_epoch: u64,
    pub receipt_request_digest: Option<PlatformHandle>,
    pub receipt_store_fence: Option<PlatformHandle>,
}

impl StoreRebindRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        handle(&self.operation_id, "store_rebind.operation_id")?;
        digest(&self.request_digest, "store_rebind.request_digest")?;
        handle(&self.requirement, "store_rebind.requirement")?;
        digest(
            &self.candidate_binding_digest,
            "store_rebind.candidate_binding_digest",
        )?;
        digest(&self.store_fence, "store_rebind.store_fence")?;
        if self.process_id == 0 || self.process_start_time_100ns == 0 {
            return Err(JournalError::Invalid(
                "store_rebind process identity must be non-zero".into(),
            ));
        }
        handle(&self.process_image_path, "store_rebind.process_image_path")?;
        handle(&self.job_name, "store_rebind.job_name")?;
        if self.generation == 0 || self.authority_epoch == 0 {
            return Err(JournalError::Invalid(
                "store_rebind generation and epoch must be non-zero".into(),
            ));
        }
        if let Some(value) = &self.receipt_request_digest {
            digest(value, "store_rebind.receipt_request_digest")?;
        }
        if let Some(value) = &self.receipt_store_fence {
            digest(value, "store_rebind.receipt_store_fence")?;
        }
        match self.state {
            StoreRebindState::Pending => {
                if self.receipt_request_digest.is_some() || self.receipt_store_fence.is_some() {
                    return Err(JournalError::Invalid(
                        "pending store rebind must not carry receipt".into(),
                    ));
                }
            }
            StoreRebindState::Committed => {
                if self.receipt_request_digest.is_none() || self.receipt_store_fence.is_none() {
                    return Err(JournalError::Invalid(
                        "committed store rebind requires receipt".into(),
                    ));
                }
                if self.receipt_request_digest.as_ref() != Some(&self.request_digest) {
                    return Err(JournalError::Invalid(
                        "committed receipt digest must match request".into(),
                    ));
                }
                if self.receipt_store_fence.as_ref() != Some(&self.store_fence) {
                    return Err(JournalError::Invalid(
                        "committed receipt fence must match handoff fence".into(),
                    ));
                }
            }
            StoreRebindState::Aborted | StoreRebindState::Unknown => {
                if self.receipt_request_digest.is_some() || self.receipt_store_fence.is_some() {
                    return Err(JournalError::Invalid(
                        "terminal store rebind disposition must not carry receipt".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn store_rebind_transition(
    current: Option<&StoreRebindRecord>,
    next: &StoreRebindRecord,
) -> Result<(), JournalError> {
    if let Some(current) = current {
        if current.fence != next.fence
            || current.operation_id != next.operation_id
            || current.request_digest != next.request_digest
        {
            return Err(JournalError::StaleFence);
        }
        let legal = matches!(
            (current.state, next.state),
            (
                StoreRebindState::Pending,
                StoreRebindState::Committed | StoreRebindState::Aborted | StoreRebindState::Unknown
            ) | (
                StoreRebindState::Unknown,
                StoreRebindState::Committed | StoreRebindState::Aborted
            )
        ) || (current.state == StoreRebindState::Unknown
            && next.state == StoreRebindState::Unknown
            && current.operation == next.operation);
        if !legal {
            return Err(illegal("store_rebind", current.state, next.state));
        }
        if current.requirement != next.requirement
            || current.candidate_binding_digest != next.candidate_binding_digest
            || current.store_fence != next.store_fence
            || current.process_id != next.process_id
            || current.process_start_time_100ns != next.process_start_time_100ns
            || current.process_image_path != next.process_image_path
            || current.job_name != next.job_name
            || current.generation != next.generation
            || current.authority_epoch != next.authority_epoch
        {
            return Err(JournalError::StaleFence);
        }
        Ok(())
    } else if next.state == StoreRebindState::Pending {
        Ok(())
    } else {
        Err(illegal("store_rebind", "NONE", next.state))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum HostStateRecord {
    Activation(EliotActivationRecord),
    Kernel(KernelRecord),
    Dependency(DependencyRecord),
    Drain(DrainRecord),
    DrainCommit(DrainCommitRecord),
    Wake(WakeRecord),
    WakeCancellationBatch(WakeCancellationBatchRecord),
    Observation(HostObservationRecord),
    ReadinessObservation(KernelReadinessObservationRecord),
    CleanMarker(CleanMarker),
    EpochRetirement(EpochRetirementRecord),
    StoreRebind(StoreRebindRecord),
    ReactiveContext(ReactiveContextRecord),
    /// Durable cutover intent/terminal record (#961).
    CutoverIntent(CutoverIntentRecord),
}

impl HostStateRecord {
    pub(crate) fn validate(&self) -> Result<(), JournalError> {
        match self {
            Self::Activation(value) => value.validate(),
            Self::Kernel(value) => value.validate(),
            Self::Dependency(value) => value.validate(),
            Self::Drain(value) => value.validate(),
            Self::DrainCommit(value) => value.validate(),
            Self::Wake(value) => value.validate(),
            Self::WakeCancellationBatch(value) => value.validate(),
            Self::Observation(value) => value.validate(),
            Self::ReadinessObservation(value) => value.validate(),
            Self::CleanMarker(value) => value.validate(),
            Self::EpochRetirement(value) => value.validate(),
            Self::StoreRebind(value) => value.validate(),
            Self::ReactiveContext(value) => validate_record_for_journal(value),
            Self::CutoverIntent(value) => value.validate(),
        }
    }

    pub(crate) fn validate_live_admission(&self) -> Result<(), JournalError> {
        self.validate()?;
        if let Self::Kernel(kernel) = self {
            kernel.one_time_nonce.validate_live_admission()?;
        }
        Ok(())
    }

    pub(crate) fn fence(&self) -> &RecordFence {
        match self {
            Self::Activation(value) => &value.fence,
            Self::Kernel(value) => &value.fence,
            Self::Dependency(value) => &value.fence,
            Self::Drain(value) => &value.fence,
            Self::DrainCommit(value) => &value.fence,
            Self::Wake(value) => &value.fence,
            Self::WakeCancellationBatch(value) => &value.fence,
            Self::Observation(value) => &value.fence,
            Self::ReadinessObservation(value) => &value.fence,
            Self::CleanMarker(value) => &value.fence,
            Self::EpochRetirement(value) => &value.fence,
            Self::StoreRebind(value) => &value.fence,
            Self::ReactiveContext(value) => &value.fence,
            Self::CutoverIntent(value) => &value.fence,
        }
    }

    pub(crate) fn operation(&self) -> &IdempotencyIdentity {
        match self {
            Self::Activation(value) => &value.operation,
            Self::Kernel(value) => &value.operation,
            Self::Dependency(value) => &value.operation,
            Self::Drain(value) => &value.operation,
            Self::DrainCommit(value) => &value.operation,
            Self::Wake(value) => &value.operation,
            Self::WakeCancellationBatch(value) => &value.operation,
            Self::Observation(value) => &value.operation,
            Self::ReadinessObservation(value) => &value.operation,
            Self::CleanMarker(value) => &value.operation,
            Self::EpochRetirement(value) => &value.operation,
            Self::StoreRebind(value) => &value.operation,
            Self::ReactiveContext(value) => &value.operation,
            Self::CutoverIntent(value) => &value.operation,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AppliedOperation {
    pub identity: IdempotencyIdentity,
    pub checksum: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EpochEvidence {
    pub host: HostInstallationEpoch,
    pub last_sequence: u64,
    pub last_checksum: Option<String>,
    pub forensic_digest: String,
    pub replay_verified: bool,
    pub retired: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HostState {
    pub host: HostInstallationEpoch,
    pub sequence: u64,
    pub last_checksum: Option<String>,
    pub activation: Option<EliotActivationRecord>,
    pub kernel: Option<KernelRecord>,
    /// Terminal/predecessor Kernel generations retained for nonce-reuse rejection.
    #[serde(default)]
    pub kernel_history: Vec<KernelRecord>,
    /// Exact previous-generation Kernel projection retained across a Host
    /// activation-generation cutover. This is reducer context, not caller
    /// supplied disposition evidence.
    pub prior_kernel: Option<KernelRecord>,
    /// Retained/recovered evidence exists, but no exact prior Kernel record
    /// was available. Kernel authority must remain fenced in this state.
    pub prior_kernel_unknown: bool,
    pub dependencies: Vec<DependencyRecord>,
    pub drain: Option<DrainRecord>,
    pub drain_commit: Option<DrainCommitRecord>,
    pub wakes: Vec<WakeRecord>,
    pub observations: Vec<HostObservationRecord>,
    pub readiness_observations: Vec<KernelReadinessObservationRecord>,
    #[serde(default)]
    pub store_rebinds: Vec<StoreRebindRecord>,
    /// Durable reactive-Context queue projection owned by this journal.
    #[serde(default)]
    pub reactive_context: Option<ReactiveContextQueueState>,
    /// Durable cutover intent/terminal projection owned by this journal.
    ///
    /// `None` means no cutover intent is outstanding. Reconciliation re-reads
    /// this projection instead of assuming an activation from local state.
    #[serde(default)]
    pub pending_cutover: Option<CutoverIntentRecord>,
    pub clean_marker: Option<CleanMarker>,
    pub retained_epochs: Vec<EpochEvidence>,
    pub retired_epochs: Vec<HostInstallationEpoch>,
    pub applied_operations: Vec<AppliedOperation>,
    /// Retirement records this Host log durably applied, retained so a reader
    /// can resolve one retirement by its exact operation identity.
    ///
    /// `retired_epochs` keeps only the retired Host epoch, so a caller cannot
    /// tell which cutover operation produced a retirement, nor when it was
    /// recorded, nor which evidence it carried; this projection keeps the
    /// resolved record itself.
    ///
    /// The list is bounded: the reducer admits a retirement only for a
    /// retained epoch that is not already retired, so one epoch contributes at
    /// most one entry. A later authorized activation-generation change does not
    /// erase it.
    ///
    /// This field grants no authority. `HostState` is a rebuildable read model
    /// replayed from the durable journal bytes; an entry here is a resolution
    /// aid, never proof that an effect occurred.
    #[serde(default)]
    pub epoch_retirements: Vec<EpochRetirementRecord>,
}

impl HostState {
    pub(crate) fn new(host: HostInstallationEpoch, retained_epochs: Vec<EpochEvidence>) -> Self {
        Self {
            host,
            sequence: 0,
            last_checksum: None,
            activation: None,
            kernel: None,
            kernel_history: Vec::new(),
            prior_kernel: None,
            prior_kernel_unknown: false,
            dependencies: Vec::new(),
            drain: None,
            drain_commit: None,
            wakes: Vec::new(),
            observations: Vec::new(),
            readiness_observations: Vec::new(),
            store_rebinds: Vec::new(),
            reactive_context: Some(ReactiveContextQueueState::default()),
            pending_cutover: None,
            clean_marker: None,
            retained_epochs,
            retired_epochs: Vec::new(),
            applied_operations: Vec::new(),
            epoch_retirements: Vec::new(),
        }
    }
}

pub(crate) fn activation_transition(
    current: Option<&EliotActivationRecord>,
    next: &EliotActivationRecord,
    drain_committed: bool,
) -> Result<(), JournalError> {
    let Some(current) = current else {
        return if matches!(
            next.state,
            ActivationState::Stopped
                | ActivationState::Starting
                | ActivationState::DegradedRecovery
        ) {
            Ok(())
        } else {
            Err(illegal("activation", "NONE", next.state))
        };
    };
    let same_generation = current.fence.activation_generation == next.fence.activation_generation;
    if !same_generation {
        if !epoch_transition_is_direct_child_of(
            &next.fence.activation_generation,
            &current.fence.activation_generation,
        )? || !matches!(
            current.state,
            ActivationState::StoppedClean
                | ActivationState::Failed
                | ActivationState::DegradedRecovery
        ) || next.state != ActivationState::Starting
        {
            return Err(JournalError::StaleFence);
        }
        return Ok(());
    }
    if current.activation_id != next.activation_id {
        return Err(JournalError::StaleFence);
    }
    let legal = matches!(
        (current.state, next.state),
        (
            ActivationState::Stopped,
            ActivationState::Starting | ActivationState::DegradedRecovery
        ) | (
            ActivationState::Starting,
            ActivationState::ControlReady
                | ActivationState::Failed
                | ActivationState::DegradedRecovery
        ) | (
            ActivationState::ControlReady,
            ActivationState::Active | ActivationState::Failed | ActivationState::DegradedRecovery
        ) | (
            ActivationState::Active,
            ActivationState::Draining | ActivationState::Failed | ActivationState::DegradedRecovery
        ) | (
            ActivationState::Draining,
            ActivationState::Active
                | ActivationState::StoppedClean
                | ActivationState::Failed
                | ActivationState::DegradedRecovery
        ) | (ActivationState::Failed, ActivationState::DegradedRecovery)
            | (
                ActivationState::DegradedRecovery,
                ActivationState::Failed | ActivationState::Stopped
            )
    );
    if !legal || (drain_committed && next.state == ActivationState::Active) {
        return Err(illegal("activation", current.state, next.state));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)]
pub(crate) fn kernel_transition(
    current: Option<&KernelRecord>,
    next: &KernelRecord,
) -> Result<(), JournalError> {
    let Some(current) = current else {
        return if matches!(
            next.state,
            KernelActivationState::Idle
                | KernelActivationState::ShadowNoAuthority
                | KernelActivationState::ManualRecovery
        ) {
            Ok(())
        } else {
            Err(illegal("kernel", "NONE", next.state))
        };
    };
    let same = current.kernel_generation == next.kernel_generation;
    if !same {
        // T6-E4-A host scalar closure: scalar process ordering is
        // intra-lineage only. Cross-lineage numeric ordering is forbidden,
        // so the scalar `>` below is gated on the typed epoch tuple proving
        // same lineage via `relation_to`. The typed direct-child check
        // remains the admission authority; this gate ensures a larger scalar
        // from another lineage can never satisfy `authority_advances`.
        let same_kernel_lineage = !matches!(
            next.kernel_generation
                .current
                .relation_to(&current.kernel_generation.current),
            eliot_contracts::EpochRelation::UnrelatedLineage
        );
        let authority_advances = same_kernel_lineage
            && current
                .process
                .as_ref()
                .zip(next.process.as_ref())
                .is_some_and(|(prior_process, candidate_process)| {
                    candidate_process.authority_epoch.value()
                        > prior_process.authority_epoch.value()
                });
        if !epoch_transition_is_direct_child_of(
            &next.kernel_generation,
            &current.kernel_generation,
        )? || !matches!(
            current.state,
            KernelActivationState::Failed | KernelActivationState::ManualRecovery
        ) || next.state != KernelActivationState::ShadowNoAuthority
            || !authority_advances
            || !next.prior_kernel_disposition.binds_to(current)
            || !next.prior_kernel_disposition.proves_terminated()
        {
            return Err(JournalError::StaleFence);
        }
        return Ok(());
    }
    let legal = matches!(
        (current.state, next.state),
        (
            KernelActivationState::Idle,
            KernelActivationState::ShadowNoAuthority | KernelActivationState::ManualRecovery
        ) | (
            KernelActivationState::ShadowNoAuthority,
            KernelActivationState::HandoffPrepared | KernelActivationState::Failed
        ) | (
            KernelActivationState::HandoffPrepared,
            KernelActivationState::OldTerminated | KernelActivationState::Failed
        ) | (
            KernelActivationState::OldTerminated,
            KernelActivationState::NonceIssued | KernelActivationState::Failed
        ) | (
            KernelActivationState::NonceIssued,
            KernelActivationState::Activating | KernelActivationState::Failed
        ) | (
            KernelActivationState::Activating,
            KernelActivationState::Active | KernelActivationState::Failed
        ) | (KernelActivationState::Active, KernelActivationState::Failed)
            | (
                KernelActivationState::Failed,
                KernelActivationState::ManualRecovery
            )
    );
    if !legal {
        return Err(illegal("kernel", current.state, next.state));
    }

    if current.activation_identity != next.activation_identity
        || current.approved_artifact_hash != next.approved_artifact_hash
        || current.fence != next.fence
    {
        return Err(JournalError::StaleFence);
    }

    if next.state == KernelActivationState::OldTerminated
        && !next.prior_kernel_disposition.proves_terminated()
    {
        return Err(JournalError::Invalid(
            "OldTerminated requires exact prior disposition proof".into(),
        ));
    }
    if matches!(
        next.state,
        KernelActivationState::NonceIssued
            | KernelActivationState::Activating
            | KernelActivationState::Active
    ) && !next.prior_kernel_disposition.proves_terminated()
    {
        return Err(JournalError::Invalid(
            "Kernel authority requires exact prior disposition proof".into(),
        ));
    }
    if matches!(
        current.state,
        KernelActivationState::OldTerminated
            | KernelActivationState::NonceIssued
            | KernelActivationState::Activating
            | KernelActivationState::Active
    ) && current.prior_kernel_disposition != next.prior_kernel_disposition
    {
        return Err(JournalError::StaleFence);
    }
    if matches!(
        next.state,
        KernelActivationState::Activating | KernelActivationState::Active
    ) && next.candidate_job_binding.is_none()
    {
        return Err(JournalError::Invalid(
            "activating/active Kernel requires a candidate Job binding".into(),
        ));
    }
    if current.state == KernelActivationState::Activating
        && next.state == KernelActivationState::Active
        && current.candidate_job_binding != next.candidate_job_binding
    {
        return Err(JournalError::StaleFence);
    }
    if matches!(
        next.state,
        KernelActivationState::Idle
            | KernelActivationState::ShadowNoAuthority
            | KernelActivationState::HandoffPrepared
            | KernelActivationState::OldTerminated
            | KernelActivationState::NonceIssued
            | KernelActivationState::Activating
    ) && next.active_pipe_identity.is_some()
    {
        return Err(JournalError::Invalid(
            "active Kernel pipe identity must remain absent before Active".into(),
        ));
    }
    if current.state == KernelActivationState::Active
        && let (Some(current_pipe), Some(next_pipe)) = (
            current.active_pipe_identity.as_ref(),
            next.active_pipe_identity.as_ref(),
        )
        && current_pipe != next_pipe
    {
        return Err(JournalError::StaleFence);
    }
    if next.state == KernelActivationState::Failed
        && (current.active_pipe_identity != next.active_pipe_identity
            || current.candidate_pipe_identity != next.candidate_pipe_identity
            || current.candidate_job_binding != next.candidate_job_binding
            || current.process.as_ref().map(|process| {
                (
                    process.process_id.as_str(),
                    process.owner.as_str(),
                    process.authority_epoch,
                )
            }) != next.process.as_ref().map(|process| {
                (
                    process.process_id.as_str(),
                    process.owner.as_str(),
                    process.authority_epoch,
                )
            }))
    {
        return Err(JournalError::StaleFence);
    }
    if current.candidate_pipe_identity.is_some()
        && current.candidate_pipe_identity != next.candidate_pipe_identity
    {
        return Err(JournalError::StaleFence);
    }
    if current.candidate_job_binding.is_some()
        && current.candidate_job_binding != next.candidate_job_binding
    {
        return Err(JournalError::StaleFence);
    }
    if let Some(current_process) = current.process.as_ref() {
        let Some(next_process) = next.process.as_ref() else {
            return Err(JournalError::StaleFence);
        };
        if current_process.process_id != next_process.process_id
            || current_process.owner != next_process.owner
            || current_process.authority_epoch != next_process.authority_epoch
        {
            return Err(JournalError::StaleFence);
        }
    }
    if next.state == KernelActivationState::Active
        && next.active_pipe_identity != next.candidate_pipe_identity
    {
        return Err(JournalError::StaleFence);
    }

    match (current.one_time_nonce.nonce_ref.as_ref(), next.state) {
        (Some(current_nonce), KernelActivationState::Activating) => {
            if next.one_time_nonce.nonce_ref.as_ref() != Some(current_nonce)
                || next.one_time_nonce.state != NonceState::Issued
            {
                return Err(JournalError::Invalid(
                    "Activating must retain the issued nonce exactly".into(),
                ));
            }
        }
        (Some(current_nonce), KernelActivationState::Active) => {
            if next.one_time_nonce.nonce_ref.as_ref() != Some(current_nonce)
                || next.one_time_nonce.state != NonceState::Consumed
            {
                return Err(JournalError::Invalid(
                    "Active must consume the exact issued nonce".into(),
                ));
            }
        }
        (Some(current_nonce), KernelActivationState::Failed) => {
            let expected_state = if current.state == KernelActivationState::Active {
                NonceState::Consumed
            } else {
                NonceState::Revoked
            };
            if next.one_time_nonce.nonce_ref.as_ref() != Some(current_nonce)
                || next.one_time_nonce.state != expected_state
            {
                return Err(JournalError::Invalid(
                    "failed Kernel must retain Consumed after Active or revoke an issued nonce"
                        .into(),
                ));
            }
        }
        (None, KernelActivationState::NonceIssued) => {
            if next.one_time_nonce.nonce_ref.is_none()
                || next.one_time_nonce.state != NonceState::Issued
            {
                return Err(JournalError::Invalid(
                    "NonceIssued requires a newly persisted nonce".into(),
                ));
            }
        }
        (None, KernelActivationState::Failed | KernelActivationState::ManualRecovery)
            if next.one_time_nonce.nonce_ref.is_some()
                || next.one_time_nonce.state != NonceState::Unissued =>
        {
            return Err(JournalError::Invalid(
                "pre-issuance failure must not create an active nonce".into(),
            ));
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn dependency_transition(
    current: Option<&DependencyRecord>,
    next: &DependencyRecord,
) -> Result<(), JournalError> {
    let Some(current) = current else {
        return if matches!(
            next.state,
            DependencyState::Starting | DependencyState::Unknown
        ) {
            Ok(())
        } else {
            Err(illegal("dependency", "NONE", next.state))
        };
    };
    let same = current.process_generation == next.process_generation;
    if !same {
        if !epoch_transition_is_direct_child_of(
            &next.process_generation,
            &current.process_generation,
        )? || !matches!(
            current.state,
            DependencyState::Failed | DependencyState::Stopped | DependencyState::Unknown
        ) || next.state != DependencyState::Starting
        {
            return Err(JournalError::StaleFence);
        }
        return Ok(());
    }
    if current.process_manifest != next.process_manifest
        || current.requester_identity != next.requester_identity
        || current.approved_artifact_hash != next.approved_artifact_hash
        || current.approved_config_hash != next.approved_config_hash
        || current.lifecycle_budget.budget_identity != next.lifecycle_budget.budget_identity
        || current.resource_budget != next.resource_budget
    {
        return Err(JournalError::StaleFence);
    }
    let legal = matches!(
        (current.state, next.state),
        (
            DependencyState::Starting,
            DependencyState::Active | DependencyState::Failed | DependencyState::Unknown
        ) | (
            DependencyState::Active,
            DependencyState::Stopped | DependencyState::Failed | DependencyState::Unknown
        ) | (
            DependencyState::Unknown,
            DependencyState::Active | DependencyState::Failed | DependencyState::Stopped
        )
    );
    if legal {
        Ok(())
    } else {
        Err(illegal("dependency", current.state, next.state))
    }
}

pub(crate) fn drain_transition(
    current: Option<&DrainRecord>,
    next: &DrainRecord,
    committed: bool,
) -> Result<(), JournalError> {
    if committed {
        return Err(illegal("drain", "COMMITTED", next.state));
    }
    let Some(current) = current else {
        return if next.state == DrainState::Requested {
            Ok(())
        } else {
            Err(illegal("drain", "NONE", next.state))
        };
    };
    if current.drain_generation != next.drain_generation {
        return Err(JournalError::StaleFence);
    }
    let legal = matches!(
        (current.state, next.state),
        (
            DrainState::Requested,
            DrainState::Draining | DrainState::Cancelled | DrainState::Failed
        ) | (
            DrainState::Draining,
            DrainState::Cancelled | DrainState::Failed
        ) | (DrainState::Cancelled, DrainState::Requested)
    );
    if legal {
        Ok(())
    } else {
        Err(illegal("drain", current.state, next.state))
    }
}

pub(crate) fn wake_transition(
    current: Option<&WakeRecord>,
    next: &WakeRecord,
) -> Result<(), JournalError> {
    let Some(current) = current else {
        return if next.intent.state == WakeIntentState::Pending {
            Ok(())
        } else {
            Err(illegal("wake", "NONE", next.intent.state))
        };
    };
    let legal = matches!(
        (current.intent.state, next.intent.state),
        (
            WakeIntentState::Pending,
            WakeIntentState::Claimed
                | WakeIntentState::Cancelled
                | WakeIntentState::Expired
                | WakeIntentState::Failed
        ) | (
            WakeIntentState::Claimed,
            WakeIntentState::Started
                | WakeIntentState::Cancelled
                | WakeIntentState::Expired
                | WakeIntentState::Failed
        ) | (
            WakeIntentState::Started,
            WakeIntentState::Satisfied | WakeIntentState::Cancelled | WakeIntentState::Failed
        )
    );
    if legal {
        Ok(())
    } else {
        Err(illegal("wake", current.intent.state, next.intent.state))
    }
}

fn illegal(
    machine: &'static str,
    from: impl std::fmt::Debug,
    to: impl std::fmt::Debug,
) -> JournalError {
    JournalError::IllegalTransition {
        machine,
        from: format!("{from:?}"),
        to: format!("{to:?}"),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod host_scalar_closure_tests {
    use std::num::NonZeroU64;

    use eliot_contracts::{EpochId, EpochLineageId, EpochRelation};

    use super::epoch_transition_is_direct_child_of;

    const LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";
    const LINEAGE_B: &str = "550e8400-e29b-41d4-a716-446655440001";

    fn lineage(value: &str) -> EpochLineageId {
        EpochLineageId::new(value).expect("valid test lineage")
    }

    fn epoch(lineage_value: &str, sequence: u64) -> EpochId {
        EpochId::new(
            lineage(lineage_value),
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    /// T6-E4-A: same-lineage seq+1 advances via the typed tuple;
    /// changed-lineage equal-seq is unrelated and fails typed (callers map
    /// `Ok(false)` to `StaleFence`; lineage mismatches elsewhere map to
    /// `EpochLineageConflict`). No scalar ordering is consulted here.
    #[test]
    fn same_lineage_direct_child_advances_cross_lineage_equal_seq_rejected() {
        let parent_epoch = epoch(LINEAGE_A, 1);
        let parent = eliot_contracts::EpochTransition::genesis(lineage(LINEAGE_A));
        let child = eliot_contracts::EpochTransition::direct_child(&parent_epoch)
            .expect("direct child mint");
        assert!(epoch(LINEAGE_A, 2).is_direct_child_of(&parent_epoch));
        assert!(
            epoch_transition_is_direct_child_of(&child, &parent).expect("validated transitions")
        );

        let foreign_genesis = eliot_contracts::EpochTransition::genesis(lineage(LINEAGE_B));
        let foreign_epoch = epoch(LINEAGE_B, 1);
        assert!(!foreign_epoch.is_same_authority(&parent_epoch));
        assert!(!foreign_epoch.is_direct_child_of(&parent_epoch));
        assert_eq!(
            foreign_epoch.relation_to(&parent_epoch),
            EpochRelation::UnrelatedLineage
        );
        assert!(
            !epoch_transition_is_direct_child_of(&foreign_genesis, &parent)
                .expect("validated transitions")
        );
    }
}
