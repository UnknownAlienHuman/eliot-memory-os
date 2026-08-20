use std::fmt;

use eliot_observation_contracts::ObservationRecordEnvelope;
use eliot_platform::{HostProcessNonce, KernelActivationNonce, PlatformHandle, PortOutcome};
use eliot_runtime_contracts::{
    HealthDimension, KernelActivationState, ServiceProcessRecord, ServiceProcessState, WakeIntent,
    WakeIntentState,
};
use serde::{Deserialize, Serialize};

use crate::JournalError;

fn deserialize_required_active_pipe<'de, D>(
    deserializer: D,
) -> Result<Option<PlatformHandle>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<PlatformHandle>::deserialize(deserializer)
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

/// An epoch is comparable only by exact identity inside one explicit lineage.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochIdentity {
    pub lineage: PlatformHandle,
    pub sequence: u64,
}

impl EpochIdentity {
    pub(crate) fn validate(&self) -> Result<(), JournalError> {
        handle(&self.lineage, "epoch.lineage")?;
        if self.sequence == 0 {
            return Err(JournalError::Invalid(
                "epoch.sequence must be positive".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn is_direct_child_of(&self, parent: &Self) -> Result<bool, JournalError> {
        self.validate()?;
        parent.validate()?;
        if self.lineage != parent.lineage {
            return Ok(false);
        }
        Ok(parent.sequence.checked_add(1) == Some(self.sequence))
    }
}

/// Carries the parent explicitly; no caller may infer ancestry by integer order.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochTransition {
    pub current: EpochIdentity,
    pub parent: Option<EpochIdentity>,
}

impl EpochTransition {
    pub(crate) fn validate(&self) -> Result<(), JournalError> {
        self.current.validate()?;
        match &self.parent {
            None if self.current.sequence == 1 => Ok(()),
            Some(parent) if self.current.is_direct_child_of(parent)? => Ok(()),
            _ => Err(JournalError::EpochLineageConflict),
        }
    }

    pub(crate) fn is_direct_child_of(&self, parent: &Self) -> Result<bool, JournalError> {
        self.validate()?;
        parent.validate()?;
        Ok(self.parent.as_ref() == Some(&parent.current))
    }

    /// Creates the only legal next generation in this exact lineage.
    pub fn direct_child(&self) -> Result<Self, JournalError> {
        self.validate()?;
        let sequence = self
            .current
            .sequence
            .checked_add(1)
            .ok_or(JournalError::Sequence)?;
        Ok(Self {
            current: EpochIdentity {
                lineage: self.current.lineage.clone(),
                sequence,
            },
            parent: Some(self.current.clone()),
        })
    }
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
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
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
        self.epoch.validate()?;
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
            && self.epoch.is_direct_child_of(&parent.epoch)?)
    }

    /// Returns the Host-process credential under its canonical, non-activation type.
    pub fn host_process_nonce(&self) -> HostProcessNonce {
        HostProcessNonce::new(self.nonce.clone())
    }
}

/// Stable mutation identity used for replay and conflict detection.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdempotencyIdentity {
    pub operation_id: PlatformHandle,
    pub idempotency_key: PlatformHandle,
}

impl IdempotencyIdentity {
    fn validate(&self) -> Result<(), JournalError> {
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
    fn validate(&self) -> Result<(), JournalError> {
        self.host.validate()?;
        handle(&self.activation_id, "fence.activation_id")?;
        self.activation_generation.validate()
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
        self.host_epoch.validate()?;
        self.kernel_epoch.validate()?;
        self.watchdog_epoch.validate()?;
        self.store_generation.validate()?;
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
            drain.validate()?;
            if drain.current.lineage != self.fence.activation_generation.current.lineage {
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
        self.generation.validate()?;
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
        self.kernel_generation.direct_child()
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
        self.kernel_generation.validate()?;
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
        self.process_generation.validate()?;
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
}

impl DrainRecord {
    fn validate(&self) -> Result<(), JournalError> {
        self.fence.validate()?;
        self.operation.validate()?;
        self.drain_generation.validate()?;
        if self.drain_generation.current.lineage != self.fence.activation_generation.current.lineage
        {
            return Err(JournalError::EpochLineageConflict);
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
        self.drain_generation.validate()?;
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
        for (index, epoch) in self.authority_epochs_fenced.iter().enumerate() {
            epoch.validate()?;
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
        )
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochRetirementRecord {
    pub fence: RecordFence,
    pub operation: IdempotencyIdentity,
    pub retired_host: HostInstallationEpoch,
    pub retirement_evidence_refs: Vec<PlatformHandle>,
    pub retired_at: PlatformHandle,
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
        handle(&self.retired_at, "retired_at")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum StoreRebindState {
    Pending,
    Committed,
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
            (StoreRebindState::Pending, StoreRebindState::Committed)
        );
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
    Observation(HostObservationRecord),
    ReadinessObservation(KernelReadinessObservationRecord),
    CleanMarker(CleanMarker),
    EpochRetirement(EpochRetirementRecord),
    StoreRebind(StoreRebindRecord),
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
            Self::Observation(value) => value.validate(),
            Self::ReadinessObservation(value) => value.validate(),
            Self::CleanMarker(value) => value.validate(),
            Self::EpochRetirement(value) => value.validate(),
            Self::StoreRebind(value) => value.validate(),
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
            Self::Observation(value) => &value.fence,
            Self::ReadinessObservation(value) => &value.fence,
            Self::CleanMarker(value) => &value.fence,
            Self::EpochRetirement(value) => &value.fence,
            Self::StoreRebind(value) => &value.fence,
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
            Self::Observation(value) => &value.operation,
            Self::ReadinessObservation(value) => &value.operation,
            Self::CleanMarker(value) => &value.operation,
            Self::EpochRetirement(value) => &value.operation,
            Self::StoreRebind(value) => &value.operation,
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
    pub clean_marker: Option<CleanMarker>,
    pub retained_epochs: Vec<EpochEvidence>,
    pub retired_epochs: Vec<HostInstallationEpoch>,
    pub applied_operations: Vec<AppliedOperation>,
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
            clean_marker: None,
            retained_epochs,
            retired_epochs: Vec::new(),
            applied_operations: Vec::new(),
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
        if !next
            .fence
            .activation_generation
            .is_direct_child_of(&current.fence.activation_generation)?
            || !matches!(
                current.state,
                ActivationState::StoppedClean
                    | ActivationState::Failed
                    | ActivationState::DegradedRecovery
            )
            || next.state != ActivationState::Starting
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
        let authority_advances = current
            .process
            .as_ref()
            .zip(next.process.as_ref())
            .is_some_and(|(prior, candidate)| {
                candidate.authority_epoch.value() > prior.authority_epoch.value()
            });
        if !next
            .kernel_generation
            .is_direct_child_of(&current.kernel_generation)?
            || !matches!(
                current.state,
                KernelActivationState::Failed | KernelActivationState::ManualRecovery
            )
            || next.state != KernelActivationState::ShadowNoAuthority
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
        if !next
            .process_generation
            .is_direct_child_of(&current.process_generation)?
            || !matches!(
                current.state,
                DependencyState::Failed | DependencyState::Stopped | DependencyState::Unknown
            )
            || next.state != DependencyState::Starting
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
        )
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
