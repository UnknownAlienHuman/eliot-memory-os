//! Host↔Kernel protocol records.

use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};
use eliot_platform::{PlatformHandle, PortError};
use eliot_process::{
    CancellationReceipt, OperationId, ProcessCallerBinding, ProcessEvidence,
    ProcessExecutionAdmissionRequest, ProcessExecutionError, ProcessExecutionView,
    ProcessStartReceipt,
};
use eliot_runtime_contracts::{HealthVector, ServiceProcessState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{KernelServiceError, validate_text};

fn handle(value: &PlatformHandle, field: &'static str) -> Result<(), KernelServiceError> {
    validate_text(value.as_str(), field)
}

/// Host-approved, store-neutral canonical-store bootstrap descriptor.
///
/// These values are an admission prerequisite, not caller-supplied store
/// authority.  The Kernel/store client binds every EBP handshake and request
/// to the exact pipe, store generation, schema generation, and state fence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostStoreBootstrapRequirement {
    /// Stable Kernel route identity selected by Host.
    pub route_identity: PlatformHandle,
    /// Canonical authenticated local-store pipe identity selected by Host.
    pub canonical_pipe_identity: PlatformHandle,
    /// Store module generation selected by Kernel/Host cutover.
    pub store_generation: ResourceGeneration,
    /// Authority/resource fence captured for this store binding.
    pub state_fence: StateFence,
    /// Host-issued launch nonce for this store lineage.
    pub launch_nonce: PlatformHandle,
    /// Transport connection identity selected for this session.
    pub connection_id: PlatformHandle,
    /// Expected authenticated peer SID for the store process.
    pub expected_peer_sid: PlatformHandle,
    /// Expected authenticated peer session id for the store process.
    pub expected_peer_session_id: u32,
    /// Host-approved store artifact digest echoed by the store handshake.
    pub approved_artifact_hash: PlatformHandle,
    /// Host-approved store configuration digest echoed by the store handshake.
    pub approved_config_hash: PlatformHandle,
    /// Bounded connection timeout selected by Host, in milliseconds.
    pub timeout_ms: u64,
}

/// Store-neutral name for the Host handoff descriptor.
pub type StoreBootstrapDescriptor = HostStoreBootstrapRequirement;

/// Closed Kernel process-execution operation set for authenticated clients.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "operation", content = "payload")]
#[allow(clippy::large_enum_variant)]
pub enum ProcessExecutionRequest {
    /// Admit and start one exact process intent.
    Start(ProcessExecutionAdmissionRequest),
    /// Inspect one admitted operation.
    Inspect {
        /// Exact operation identity to inspect.
        operation_id: OperationId,
    },
    /// Cancel one admitted operation.
    Cancel {
        /// Exact operation identity to cancel.
        operation_id: OperationId,
    },
    /// Reconcile one operation after an unknown delivery/result boundary.
    Reconcile {
        /// Exact operation identity to reconcile.
        operation_id: OperationId,
    },
}

/// Process operation plus the authenticated Session projection that produced
/// it. Kernel replaces/validates this binding at the established front door.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionEnvelope {
    /// Caller/session/principal projection.
    pub caller: ProcessCallerBinding,
    /// Closed process operation.
    pub request: ProcessExecutionRequest,
}

impl ProcessExecutionEnvelope {
    /// Validates caller and operation projections.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        self.request.validate()
    }
}

impl ProcessExecutionRequest {
    /// Validates the closed operation payload.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        match self {
            Self::Start(request) => request
                .validate()
                .map_err(|error| KernelServiceError::Platform(error.to_string())),
            Self::Inspect { operation_id }
            | Self::Cancel { operation_id }
            | Self::Reconcile { operation_id } => {
                if operation_id.as_str().trim().is_empty() {
                    return Err(KernelServiceError::InvalidField {
                        field: "operation_id",
                        reason: "must be non-blank",
                    });
                }
                Ok(())
            }
        }
    }

    /// Returns the exact operation identity when one is present.
    pub fn operation_id(&self) -> Option<&OperationId> {
        match self {
            Self::Start(request) => Some(request.intent().operation_id()),
            Self::Inspect { operation_id }
            | Self::Cancel { operation_id }
            | Self::Reconcile { operation_id } => Some(operation_id),
        }
    }
}

/// Provider-neutral response projection; no child handle or permit crosses
/// the Kernel front door.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, tag = "result", content = "payload")]
pub enum ProcessExecutionResponse {
    /// Exact receipt after a child was admitted and resumed.
    Started(ProcessStartReceipt),
    /// Current non-authoritative operation projection.
    Status(ProcessExecutionView),
    /// Exact cancellation projection.
    Cancelled(CancellationReceipt),
    /// Observation-only reconciliation evidence.
    Reconciled(ProcessEvidence),
    /// Bounded provider-neutral rejection.
    Rejected(ProcessExecutionRejection),
}

/// Stable error projection for cross-process callers.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessExecutionRejection {
    /// Stable category, never a raw child/provider error.
    pub code: String,
    /// Bounded diagnostic detail.
    pub detail: String,
}

impl ProcessExecutionRejection {
    /// Converts a process execution error into a bounded transport projection.
    pub fn from_error(error: &ProcessExecutionError) -> Self {
        Self {
            code: match error {
                ProcessExecutionError::UnknownOutcome => "UNKNOWN_OUTCOME",
                ProcessExecutionError::NotFound => "NOT_FOUND",
                ProcessExecutionError::Contract(_) => "CONTRACT_REJECTED",
                ProcessExecutionError::Unavailable(_) => "UNAVAILABLE",
                ProcessExecutionError::EvidenceSink(_) => "EVIDENCE_REJECTED",
            }
            .to_owned(),
            detail: error.to_string().chars().take(512).collect(),
        }
    }
}

impl HostStoreBootstrapRequirement {
    /// Validates the complete Host-approved store binding.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.route_identity, "store_bootstrap.route_identity")?;
        if self.route_identity.as_str() != crate::STORE_ROUTE_IDENTITY {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "route_identity",
            });
        }
        handle(
            &self.canonical_pipe_identity,
            "store_bootstrap.canonical_pipe_identity",
        )?;
        handle(&self.launch_nonce, "store_bootstrap.launch_nonce")?;
        handle(&self.connection_id, "store_bootstrap.connection_id")?;
        handle(&self.expected_peer_sid, "store_bootstrap.expected_peer_sid")?;
        handle(
            &self.approved_artifact_hash,
            "store_bootstrap.approved_artifact_hash",
        )?;
        handle(
            &self.approved_config_hash,
            "store_bootstrap.approved_config_hash",
        )?;
        for (value, field) in [
            (
                &self.approved_artifact_hash,
                "store_bootstrap.approved_artifact_hash",
            ),
            (
                &self.approved_config_hash,
                "store_bootstrap.approved_config_hash",
            ),
        ] {
            if value.as_str().len() != 64
                || !value
                    .as_str()
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(KernelServiceError::InvalidField {
                    field,
                    reason: "must be a lowercase SHA-256 digest",
                });
            }
        }
        self.state_fence
            .validate()
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        if self.store_generation.value() == 0
            || self.store_generation != self.state_fence.resource_generation
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "store_generation",
            });
        }
        if self.timeout_ms == 0 || self.timeout_ms > 300_000 {
            return Err(KernelServiceError::InvalidField {
                field: "store_bootstrap.timeout_ms",
                reason: "must be between 1 and 300000 milliseconds",
            });
        }
        eliot_ipc::validate_pipe_name(self.canonical_pipe_identity.as_str())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        Ok(())
    }

    /// Returns the exact authority epoch bound by this requirement.
    #[must_use]
    pub const fn authority_epoch(&self) -> AuthorityEpoch {
        self.state_fence.authority_epoch
    }

    /// Returns the Host-approved bounded connection timeout.
    #[must_use]
    pub const fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }
}

/// A bounded restart budget owned by Host for one Kernel lineage.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartBudget {
    /// Number of starts still allowed before quarantine.
    pub remaining: u32,
    /// Maximum starts admitted for this lineage.
    pub maximum: u32,
}

impl RestartBudget {
    /// Creates a budget, rejecting an inconsistent remaining count.
    pub const fn new(maximum: u32, remaining: u32) -> Result<Self, KernelServiceError> {
        if maximum == 0 || remaining > maximum {
            return Err(KernelServiceError::InvalidField {
                field: "restart_budget",
                reason: "maximum must be non-zero and remaining must not exceed maximum",
            });
        }
        Ok(Self { remaining, maximum })
    }

    /// Consumes one permitted restart without wrapping.
    pub const fn consume(self) -> Result<Self, KernelServiceError> {
        if self.remaining == 0 {
            return Err(KernelServiceError::RestartBudgetExhausted);
        }
        Ok(Self {
            remaining: self.remaining - 1,
            maximum: self.maximum,
        })
    }
}

/// A Host-observed process identity and lifecycle snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessObservation {
    /// Exact physical process lineage identity.
    pub process_id: PlatformHandle,
    /// Host-owned Job Object identity.
    pub job_object_id: PlatformHandle,
    /// Current process state; survival alone does not imply readiness.
    pub state: ServiceProcessState,
    /// Six-dimensional process health evidence.
    pub health: HealthVector,
    /// Opaque evidence references proving the observation.
    pub evidence_refs: Vec<PlatformHandle>,
}

impl ProcessObservation {
    /// Validates the non-secret observation envelope.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.process_id, "process_observation.process_id")?;
        handle(&self.job_object_id, "process_observation.job_object_id")?;
        if self.evidence_refs.is_empty() {
            return Err(KernelServiceError::InvalidField {
                field: "process_observation.evidence_refs",
                reason: "at least one evidence reference is required",
            });
        }
        for evidence in &self.evidence_refs {
            handle(evidence, "process_observation.evidence_refs")?;
        }
        Ok(())
    }
}

/// The immutable Host lineage and activation binding presented to Kernel.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKernelHandshake {
    /// Host installation identity.
    pub installation_id: PlatformHandle,
    /// Host installation epoch that owns this process.
    pub host_epoch: AuthorityEpoch,
    /// Kernel authority epoch proposed for this activation.
    pub kernel_epoch: AuthorityEpoch,
    /// Exact activation identity shared by Host state and Kernel.
    pub activation_id: PlatformHandle,
    /// Approved immutable Kernel artifact hash/reference.
    pub artifact_hash: PlatformHandle,
    /// Immutable configuration hash/reference.
    pub config_hash: PlatformHandle,
    /// One-time activation nonce. It is consumed exactly once.
    pub activation_nonce: PlatformHandle,
    /// Host-owned Kernel Job Object identity.
    pub job_object_id: PlatformHandle,
    /// Candidate/active authenticated local IPC identity.
    pub pipe_identity: PlatformHandle,
    /// Restart budget for this lineage.
    pub restart_budget: RestartBudget,
    /// Containment action required if the previous lineage is suspect.
    pub containment_action: Option<ContainmentAction>,
}

impl HostKernelHandshake {
    /// Validates all identity and epoch invariants before a candidate starts.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        for (value, field) in [
            (&self.installation_id, "handshake.installation_id"),
            (&self.activation_id, "handshake.activation_id"),
            (&self.artifact_hash, "handshake.artifact_hash"),
            (&self.config_hash, "handshake.config_hash"),
            (&self.activation_nonce, "handshake.activation_nonce"),
            (&self.job_object_id, "handshake.job_object_id"),
            (&self.pipe_identity, "handshake.pipe_identity"),
        ] {
            handle(value, field)?;
        }
        if self.host_epoch.value() == 0 || self.kernel_epoch.value() == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "handshake.epoch",
                reason: "must be non-zero",
            });
        }
        if self.host_epoch.value() > self.kernel_epoch.value() {
            return Err(KernelServiceError::InvalidField {
                field: "handshake.kernel_epoch",
                reason: "must not precede host epoch",
            });
        }
        if let Some(containment) = &self.containment_action {
            containment.validate()?;
        }
        Ok(())
    }
}

/// A Host containment action reference, not an instruction to perform OS work.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainmentAction {
    /// Stable action identity recorded by Host/Watchdog.
    pub action_id: PlatformHandle,
    /// Evidence that the prior lineage was contained or marked suspect.
    pub evidence_ref: PlatformHandle,
}

impl ContainmentAction {
    /// Validates the action envelope.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        handle(&self.action_id, "containment.action_id")?;
        handle(&self.evidence_ref, "containment.evidence_ref")
    }
}

/// Receipt proving that a Kernel candidate consumed its Host handoff nonce.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelReadyReceipt {
    /// Activation identity echoed from the handshake.
    pub activation_id: PlatformHandle,
    /// Activation nonce echoed from the handshake.
    pub activation_nonce: PlatformHandle,
    /// Process and Job Object observation at readiness time.
    pub process: ProcessObservation,
    /// Kernel health vector at readiness time.
    pub health: HealthVector,
    /// Kernel-side readiness evidence references.
    pub evidence_refs: Vec<PlatformHandle>,
}

impl KernelReadyReceipt {
    /// Validates readiness without inferring success from process existence.
    pub fn validate(&self, handshake: &HostKernelHandshake) -> Result<(), KernelServiceError> {
        handle(&self.activation_id, "ready.activation_id")?;
        handle(&self.activation_nonce, "ready.activation_nonce")?;
        if self.activation_id != handshake.activation_id {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "activation_id",
            });
        }
        if self.activation_nonce != handshake.activation_nonce {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "activation_nonce",
            });
        }
        self.process.validate()?;
        if self.process.job_object_id != handshake.job_object_id {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "job_object_id",
            });
        }
        if self.process.state != ServiceProcessState::Ready
            || !self.process.health.is_fully_healthy()
            || !self.health.is_fully_healthy()
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if self.evidence_refs.is_empty() {
            return Err(KernelServiceError::InvalidField {
                field: "ready.evidence_refs",
                reason: "at least one readiness evidence reference is required",
            });
        }
        for evidence in &self.evidence_refs {
            handle(evidence, "ready.evidence_refs")?;
        }
        Ok(())
    }
}

/// Control messages accepted by the Kernel service boundary.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum KernelControlCommand {
    /// Begin reconciliation of one Host activation lineage.
    Reconcile(HostKernelHandshake),
    /// Enter side-by-side candidate mode without authority.
    Shadow,
    /// Record that Host prepared the exclusive handoff.
    PrepareHandoff,
    /// Begin consuming the one-time activation nonce.
    Activate,
    /// Publish a complete readiness receipt.
    Ready(KernelReadyReceipt),
    /// Close normal admission while retaining recovery control.
    Degrade(PlatformHandle),
    /// Drain normal work before stopping.
    Drain,
    /// Record a clean stop.
    Stop,
    /// Record a bounded failure and its recovery reference.
    Fail(PlatformHandle),
}

impl From<PortError> for KernelServiceError {
    fn from(error: PortError) -> Self {
        Self::Platform(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::expect_used,
        reason = "tests use expects for fixed-valid protocol fixtures"
    )]

    use super::*;

    fn handle_value(value: &str) -> PlatformHandle {
        PlatformHandle::new(value).expect("test handle")
    }

    fn requirement() -> HostStoreBootstrapRequirement {
        let fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
        HostStoreBootstrapRequirement {
            route_identity: handle_value(crate::STORE_ROUTE_IDENTITY),
            canonical_pipe_identity: handle_value(r"\\.\pipe\eliot\store"),
            store_generation: ResourceGeneration::genesis(),
            state_fence: fence,
            launch_nonce: handle_value("nonce-1"),
            connection_id: handle_value("connection-1"),
            expected_peer_sid: handle_value("S-1-5-18"),
            expected_peer_session_id: 0,
            approved_artifact_hash: handle_value(&"a".repeat(64)),
            approved_config_hash: handle_value(&"b".repeat(64)),
            timeout_ms: 5_000,
        }
    }

    #[test]
    fn store_bootstrap_accepts_system_session_zero() {
        assert!(requirement().validate().is_ok());
    }

    #[test]
    fn store_bootstrap_rejects_generation_or_digest_substitution() {
        let mut wrong_generation = requirement();
        wrong_generation.store_generation = ResourceGeneration::new(2).expect("generation");
        assert!(wrong_generation.validate().is_err());

        let mut wrong_digest = requirement();
        wrong_digest.approved_config_hash = handle_value(&"C".repeat(64));
        assert!(wrong_digest.validate().is_err());
    }
}
