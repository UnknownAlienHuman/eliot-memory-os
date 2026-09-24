//! Composition root for the production research exchange process.
//!
//! The process owns only exchange admission and lifecycle. Provider execution
//! runs exclusively through the shared governed process contour once
//! Kernel-issued research admission exists; until then every bridge call fails
//! closed with a typed source-unavailable gap. Returned research remains a
//! candidate until an authority outside this package admits it.
//!
//! No executable path is ever read from ambient environment, task text, or
//! stdin. Bridges carry only explicit immutable identity and admission handed
//! to their constructors by already-admitted material.

#![forbid(unsafe_code)]

pub mod admission;
pub mod evidence;
pub mod execution;
pub mod protocol;
pub mod runtime;

use std::path::{Component, Path};

use eliot_contracts::StateFence;
use eliot_process::CancellationStatus;
use eliot_research_exchange::{ExchangeError, ExchangeJob, ResearchBridge};
use eliot_research_exchange_api::{
    CoverageGapKind, ResearchEvidenceBundle, ResearchProviderFailure, ResearchQueryRequest,
};
use eliot_researcher::Researcher;
use thiserror::Error;

pub use admission::{
    AdmissionRefusal, BridgeContract, CancellationBinding, CredentialBinding,
    ModuleGenerationEvidence, ProviderAdmission, ProviderRegistry, ProviderRoute,
};
pub use evidence::{
    ProviderAttemptReceipt, ProviderCleanupReceipt, ProviderIntentRecord, RawProviderEvidence,
    StreamOmission, StreamRecord, sha256_hex,
};
pub use execution::{
    BOUND_RUN_DEADLINE, ProviderBridge, ProviderExecution, ProviderFailureKind, ProviderOutcome,
    RequestPortError, ResearchRequestPort,
};
pub use protocol::{
    CoverageDenominator, MAX_CHANNEL_BYTES, MAX_WIRE_BYTES, MAX_WIRE_LINES,
    PROVIDER_CHANNEL_ARGUMENT, PROVIDER_REQUEST_FILE_PREFIX, PROVIDER_RESULT_FILE_PREFIX,
    RESEARCH_PROVIDER_WIRE_VERSION, ResearchRequestChannel, ResearchResultDocument, ResultFrame,
    SubmitAck, SubmitEnvelope,
};

/// Stable gap code emitted when no governed provider execution is available.
pub const RESEARCH_SOURCE_UNAVAILABLE: &str = "RESEARCH_SOURCE_UNAVAILABLE";

/// Length of a lowercase SHA-256 hex digest binding one bridge executable.
const SHA256_HEX_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("research bridge identity is invalid: {reason}")]
    InvalidBridgeIdentity {
        /// Stable reason for the rejection.
        reason: &'static str,
    },
    #[error(
        "RESEARCH_SOURCE_UNAVAILABLE: kernel-issued research admission is required; no provider execution was attempted"
    )]
    ProviderUnavailable,
    #[error("research provider operation is not admitted: {reason}")]
    NotAdmitted {
        /// Stable reason for the refusal.
        reason: &'static str,
    },
    #[error("research provider wire is not the admitted protocol: {reason}")]
    ProtocolViolation {
        /// Stable reason for the refusal; provider bodies are never included.
        reason: &'static str,
    },
    #[error("research provider execution failed: {reason}")]
    ProviderFailed {
        /// Stable reason for the failure; provider bodies are never included.
        reason: &'static str,
    },
    #[error("research provider evidence is incomplete: {reason}")]
    EvidenceIncomplete {
        /// Stable reason for the refusal.
        reason: &'static str,
    },
    #[error(
        "research provider execution exceeded the deadline; cancellation was attempted and the outcome is unconfirmed: reconcile by operation identity before any retry"
    )]
    TimedOut,
    #[error("research provider acquisition was cancelled: {reason}")]
    Cancelled {
        /// Stable cancellation detail.
        reason: &'static str,
    },
    #[error(
        "research provider outcome is unknown: reconcile by operation identity before any retry"
    )]
    UnknownOutcome,
    #[error("shared process contour failed: {0}")]
    Process(#[from] eliot_process::ProcessExecutionError),
}

impl BridgeError {
    /// Maps this failure to the typed coverage-gap kind the caller records.
    /// Provider failure degrades only acquisition coverage: every variant maps
    /// to a gap, never to a fabricated result or a semantic failure.
    #[must_use]
    pub const fn coverage_gap_kind(&self) -> CoverageGapKind {
        match self {
            Self::InvalidBridgeIdentity { .. } | Self::ProviderUnavailable => {
                CoverageGapKind::SourceUnavailable
            }
            Self::NotAdmitted { .. } => CoverageGapKind::PolicyOrDisclosureDenied,
            Self::ProtocolViolation { .. } => CoverageGapKind::StaleSourceOrIndex,
            Self::TimedOut => CoverageGapKind::Timeout,
            Self::ProviderFailed { .. } => CoverageGapKind::Unknown,
            Self::Cancelled { .. } => CoverageGapKind::Cancelled,
            Self::EvidenceIncomplete { .. } | Self::UnknownOutcome | Self::Process(_) => {
                CoverageGapKind::Unknown
            }
        }
    }

    /// Projects this error into the typed exchange coverage failure.
    #[must_use]
    pub fn provider_failure(&self) -> ResearchProviderFailure {
        let (code, kind, detail) = match self {
            Self::ProviderUnavailable => (
                RESEARCH_SOURCE_UNAVAILABLE,
                CoverageGapKind::SourceUnavailable,
                "no admitted provider execution was available",
            ),
            Self::NotAdmitted { .. } => (
                "RESEARCH_PROVIDER_NOT_ADMITTED",
                self.coverage_gap_kind(),
                "provider execution was refused before effect",
            ),
            Self::ProtocolViolation { .. } => (
                "RESEARCH_PROVIDER_PROTOCOL_INVALID",
                CoverageGapKind::StaleSourceOrIndex,
                "provider wire or correlation was not admitted",
            ),
            Self::ProviderFailed { .. } => (
                "RESEARCH_PROVIDER_FAILED",
                CoverageGapKind::Unknown,
                "provider reported an acquisition failure",
            ),
            Self::Cancelled { .. } => (
                "RESEARCH_PROVIDER_CANCELLED",
                CoverageGapKind::Cancelled,
                "provider acquisition was cancelled",
            ),
            Self::TimedOut => (
                "RESEARCH_PROVIDER_TIMEOUT",
                CoverageGapKind::Timeout,
                "provider acquisition exceeded the admitted deadline",
            ),
            Self::UnknownOutcome => (
                "RESEARCH_PROVIDER_UNKNOWN_OUTCOME",
                CoverageGapKind::Unknown,
                "provider outcome requires same-operation reconciliation",
            ),
            Self::EvidenceIncomplete { .. } | Self::Process(_) => (
                "RESEARCH_PROVIDER_EVIDENCE_INCOMPLETE",
                CoverageGapKind::Unknown,
                "provider evidence or process receipt is incomplete",
            ),
            Self::InvalidBridgeIdentity { .. } => (
                "RESEARCH_PROVIDER_IDENTITY_INVALID",
                CoverageGapKind::SourceUnavailable,
                "provider bridge identity is invalid",
            ),
        };
        ResearchProviderFailure::new(
            code,
            kind,
            format!("provider:{}", coverage_kind_label(self.coverage_gap_kind())),
            detail,
        )
    }
}

fn coverage_kind_label(kind: CoverageGapKind) -> &'static str {
    match kind {
        CoverageGapKind::SourceUnavailable => "source-unavailable",
        CoverageGapKind::StaleSourceOrIndex => "stale-source-or-index",
        CoverageGapKind::PolicyOrDisclosureDenied => "policy-or-disclosure-denied",
        CoverageGapKind::BudgetExhausted => "budget-exhausted",
        CoverageGapKind::Timeout => "timeout",
        CoverageGapKind::Cancelled => "cancelled",
        CoverageGapKind::Unknown => "unknown",
    }
}
///
/// Both fields arrive from already-admitted material. Nothing here is read
/// from ambient environment, and identity alone grants no execution: the
/// Kernel-issued research admission that binds this identity to one exact
/// operation lands in [`ProviderAdmission`].
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeIdentity {
    executable: String,
    executable_sha256: String,
}

impl BridgeIdentity {
    /// Binds one bridge executable path to its exact content digest.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidBridgeIdentity`] when the path is not an
    /// absolute canonical path or the digest is not a lowercase SHA-256 hex
    /// string.
    pub fn new(
        executable: impl Into<String>,
        executable_sha256: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let executable = executable.into();
        let executable_sha256 = executable_sha256.into();
        if executable.trim().is_empty()
            || !Path::new(&executable).is_absolute()
            || Path::new(&executable)
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(BridgeError::InvalidBridgeIdentity {
                reason: "executable path is not an absolute canonical path",
            });
        }
        if !is_lowercase_sha256(&executable_sha256) {
            return Err(BridgeError::InvalidBridgeIdentity {
                reason: "executable digest is not a lowercase SHA-256 hex digest",
            });
        }
        Ok(Self {
            executable,
            executable_sha256,
        })
    }

    /// Rechecks the immutable bridge identity after transport/deserialization.
    pub fn validate(&self) -> Result<(), BridgeError> {
        if self.executable.trim().is_empty()
            || self.executable.chars().any(char::is_control)
            || !Path::new(&self.executable).is_absolute()
            || Path::new(&self.executable)
                .components()
                .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(BridgeError::InvalidBridgeIdentity {
                reason: "executable path is not an absolute canonical path",
            });
        }
        if !is_lowercase_sha256(&self.executable_sha256) {
            return Err(BridgeError::InvalidBridgeIdentity {
                reason: "executable digest is not a lowercase SHA-256 hex digest",
            });
        }
        Ok(())
    }

    /// Returns the registered bridge executable path.
    #[must_use]
    pub fn executable(&self) -> &str {
        &self.executable
    }

    /// Returns the exact content digest of the registered executable.
    #[must_use]
    pub fn executable_sha256(&self) -> &str {
        &self.executable_sha256
    }
}

pub(crate) fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_LEN
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Governed research provider bridge.
///
/// Execution runs exclusively through the shared governed process contour
/// once Kernel-issued research admission binds the carried identity to one
/// exact operation. Until that admission exists, every call fails closed
/// with [`BridgeError::ProviderUnavailable`]: a typed coverage gap, never a
/// fabricated result and never an ambient child process.
pub struct GovernedResearchBridge {
    identity: BridgeIdentity,
}

impl GovernedResearchBridge {
    /// Wraps one explicit immutable bridge identity. Grants no execution.
    #[must_use]
    pub fn new(identity: BridgeIdentity) -> Self {
        Self { identity }
    }

    /// Returns the carried bridge identity.
    #[must_use]
    pub fn identity(&self) -> &BridgeIdentity {
        &self.identity
    }
}

impl ResearchBridge for GovernedResearchBridge {
    type Error = BridgeError;

    fn submit(&mut self, _request: &ResearchQueryRequest) -> Result<String, Self::Error> {
        Err(BridgeError::ProviderUnavailable)
    }

    fn cancel(&mut self, _job_id: &str) -> Result<(), Self::Error> {
        Err(BridgeError::ProviderUnavailable)
    }

    fn last_failure(&self) -> Option<ResearchProviderFailure> {
        Some(BridgeError::ProviderUnavailable.provider_failure())
    }
}

/// Lifecycle phase of one admitted operation. One bridge serves exactly one
/// bounded operation: after any executor contact the operation is never
/// resubmitted blindly — unknown or timed-out outcomes must be reconciled by
/// the stable operation identity first, and every other outcome requires a
/// fresh admission for a fresh attempt.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum BridgePhase {
    /// Nothing was attempted through the executor yet.
    Awaiting,
    /// The executor was contacted; resubmission is refused.
    Submitted {
        outcome: ProviderOutcome,
        evidence: Option<RawProviderEvidence>,
        receipt: Option<ProviderAttemptReceipt>,
        provider_job_ref: Option<String>,
        candidate: Option<ResearchEvidenceBundle>,
        failure: Option<ResearchProviderFailure>,
        cancellation: Option<eliot_process::CancellationReceipt>,
        reconciliation: Option<eliot_process::ProcessEvidence>,
        reconciled: bool,
    },
}

/// Admitted research provider bridge: one exact admission, one bounded
/// operation, shared-executor execution.
pub struct AdmittedResearchBridge {
    runner: ProviderBridge,
    admission: ProviderAdmission,
    phase: BridgePhase,
}

impl AdmittedResearchBridge {
    /// Binds one admitted operation to the shared execution contour. Starts
    /// nothing; grants no execution until `submit`.
    #[must_use]
    pub fn new(runner: ProviderBridge, admission: ProviderAdmission) -> Self {
        Self {
            runner,
            admission,
            phase: BridgePhase::Awaiting,
        }
    }

    /// Returns the bound admission.
    #[must_use]
    pub const fn admission(&self) -> &ProviderAdmission {
        &self.admission
    }

    /// Returns whether the executor was contacted for this operation.
    #[must_use]
    pub const fn has_submitted(&self) -> bool {
        matches!(self.phase, BridgePhase::Submitted { .. })
    }

    /// Returns the last immutable raw evidence when materialized.
    #[must_use]
    pub const fn last_evidence(&self) -> Option<&RawProviderEvidence> {
        match &self.phase {
            BridgePhase::Awaiting => None,
            BridgePhase::Submitted { evidence, .. } => evidence.as_ref(),
        }
    }

    /// Returns the complete operation/process receipt.
    #[must_use]
    pub const fn last_receipt(&self) -> Option<&ProviderAttemptReceipt> {
        match &self.phase {
            BridgePhase::Awaiting => None,
            BridgePhase::Submitted { receipt, .. } => receipt.as_ref(),
        }
    }

    /// Returns the provider-local job reference when the submit ack decoded.
    #[must_use]
    pub const fn last_provider_job_ref(&self) -> Option<&String> {
        match &self.phase {
            BridgePhase::Awaiting => None,
            BridgePhase::Submitted {
                provider_job_ref, ..
            } => provider_job_ref.as_ref(),
        }
    }

    /// Takes candidate-only provider material for the exchange.
    #[must_use]
    pub fn take_candidate_bundle(&mut self) -> Option<ResearchEvidenceBundle> {
        match &mut self.phase {
            BridgePhase::Submitted { candidate, .. } => candidate.take(),
            BridgePhase::Awaiting => None,
        }
    }

    /// Returns the typed failure retained after the last provider call.
    #[must_use]
    pub fn last_failure(&self) -> Option<ResearchProviderFailure> {
        match &self.phase {
            BridgePhase::Submitted { failure, .. } => failure.clone(),
            BridgePhase::Awaiting => None,
        }
    }

    /// Reconciles an unknown or timed-out outcome by the stable operation ID.
    pub fn reconcile(&mut self) -> Result<eliot_process::ProcessEvidence, BridgeError> {
        let BridgePhase::Submitted {
            outcome,
            reconciled,
            ..
        } = &self.phase
        else {
            return Err(BridgeError::NotAdmitted {
                reason: "nothing was attempted through the executor yet",
            });
        };
        if !matches!(
            outcome,
            ProviderOutcome::TimedOut | ProviderOutcome::Unknown
        ) || *reconciled
        {
            return Err(BridgeError::NotAdmitted {
                reason: "outcome is classified or already reconciled",
            });
        }
        let evidence = self
            .runner
            .reconcile_operation(self.admission.operation_id())?;
        if let BridgePhase::Submitted {
            reconciliation,
            receipt,
            reconciled,
            ..
        } = &mut self.phase
        {
            *reconciled = true;
            *reconciliation = Some(evidence.clone());
            if let Some(receipt) = receipt {
                receipt.reconciliation = Some(evidence.clone());
            }
        }
        Ok(evidence)
    }
}

impl ResearchBridge for AdmittedResearchBridge {
    type Error = BridgeError;

    fn submit(&mut self, request: &ResearchQueryRequest) -> Result<String, Self::Error> {
        if !matches!(self.phase, BridgePhase::Awaiting) {
            return Err(BridgeError::NotAdmitted {
                reason: "operation already started; a new admission is required",
            });
        }
        match self.runner.execute(&self.admission, request) {
            Ok(execution) => {
                let error = execution.bridge_error();
                let failure = error.as_ref().map(BridgeError::provider_failure);
                let job_id = execution.job_id.clone();
                self.phase = BridgePhase::Submitted {
                    outcome: execution.outcome,
                    evidence: Some(execution.evidence),
                    receipt: Some(execution.receipt),
                    provider_job_ref: execution.provider_job_ref,
                    candidate: execution.candidate,
                    failure,
                    cancellation: None,
                    reconciliation: None,
                    reconciled: false,
                };
                match error {
                    Some(error) => Err(error),
                    None => Ok(job_id),
                }
            }
            Err(error) => {
                // A port refusal before executor contact is retryable only with
                // corrected input. Every other post-admission failure is held
                // as an unknown operation and is never collapsed to Refused.
                if matches!(
                    error,
                    BridgeError::ProviderUnavailable
                        | BridgeError::InvalidBridgeIdentity { .. }
                        | BridgeError::NotAdmitted { .. }
                        | BridgeError::ProtocolViolation { .. }
                        | BridgeError::EvidenceIncomplete { .. }
                        | BridgeError::Process(_)
                ) {
                    return Err(error);
                }
                self.phase = BridgePhase::Submitted {
                    outcome: ProviderOutcome::Unknown,
                    evidence: None,
                    receipt: None,
                    provider_job_ref: None,
                    candidate: None,
                    failure: Some(error.provider_failure()),
                    cancellation: None,
                    reconciliation: None,
                    reconciled: false,
                };
                Err(error)
            }
        }
    }

    fn cancel(&mut self, job_id: &str) -> Result<(), Self::Error> {
        if job_id != self.admission.operation_id().as_str() {
            return Err(BridgeError::NotAdmitted {
                reason: "cancel targets a foreign operation",
            });
        }
        if matches!(self.phase, BridgePhase::Awaiting) {
            return Err(BridgeError::NotAdmitted {
                reason: "nothing was attempted through the executor yet",
            });
        }
        let receipt = self
            .runner
            .cancel_operation(self.admission.operation_id())?;
        let status = receipt.status();
        if let BridgePhase::Submitted {
            outcome,
            failure,
            cancellation,
            receipt: attempt_receipt,
            ..
        } = &mut self.phase
        {
            *cancellation = Some(receipt.clone());
            if let Some(attempt_receipt) = attempt_receipt {
                attempt_receipt.cancellation = Some(receipt.clone());
                match status {
                    CancellationStatus::Completed => {
                        attempt_receipt.outcome = ProviderOutcome::Cancelled;
                        *outcome = ProviderOutcome::Cancelled;
                        *failure = Some(
                            BridgeError::Cancelled {
                                reason: "provider cancellation completed",
                            }
                            .provider_failure(),
                        );
                    }
                    CancellationStatus::Requested
                    | CancellationStatus::InProgress
                    | CancellationStatus::UnknownOutcome => {
                        attempt_receipt.outcome = ProviderOutcome::Unknown;
                        *outcome = ProviderOutcome::Unknown;
                        *failure = Some(BridgeError::UnknownOutcome.provider_failure());
                    }
                    CancellationStatus::NotRequested | CancellationStatus::RejectedStaleFence => {}
                }
            }
        }
        match status {
            CancellationStatus::Completed => Ok(()),
            CancellationStatus::Requested
            | CancellationStatus::InProgress
            | CancellationStatus::UnknownOutcome => Err(BridgeError::UnknownOutcome),
            CancellationStatus::NotRequested | CancellationStatus::RejectedStaleFence => {
                Err(BridgeError::NotAdmitted {
                    reason: "provider cancellation had no admitted effect",
                })
            }
        }
    }

    fn last_failure(&self) -> Option<ResearchProviderFailure> {
        AdmittedResearchBridge::last_failure(self)
    }

    fn last_operation_id(&self) -> Option<&str> {
        match &self.phase {
            BridgePhase::Awaiting => None,
            BridgePhase::Submitted { .. } => Some(self.admission.operation_id().as_str()),
        }
    }

    fn take_candidate_bundle(&mut self) -> Option<ResearchEvidenceBundle> {
        AdmittedResearchBridge::take_candidate_bundle(self)
    }
}

pub type ResearchComposition = Researcher<GovernedResearchBridge>;

/// Composes one researcher over an explicit immutable bridge identity.
///
/// No environment is consulted. Execution still requires Kernel-issued
/// research admission before any provider call can succeed.
#[must_use]
pub fn compose_with_bridge(identity: BridgeIdentity) -> ResearchComposition {
    Researcher::new(GovernedResearchBridge::new(identity))
}

/// Composes one researcher over one admitted provider operation.
#[must_use]
pub fn compose_admitted(
    runner: ProviderBridge,
    admission: ProviderAdmission,
) -> Researcher<AdmittedResearchBridge> {
    Researcher::new(AdmittedResearchBridge::new(runner, admission))
}

pub fn submit<B: ResearchBridge>(
    researcher: &mut Researcher<B>,
    request: ResearchQueryRequest,
) -> Result<ExchangeJob, ExchangeError> {
    researcher.submit_query(request)
}

pub fn cancel<B: ResearchBridge>(
    researcher: &mut Researcher<B>,
    job_id: &str,
    fence: &StateFence,
) -> Result<ExchangeJob, ExchangeError> {
    researcher.exchange_mut().cancel(job_id, fence)
}

#[must_use]
pub fn exchange_snapshot<B>(
    researcher: &Researcher<B>,
) -> &eliot_research_exchange::ExchangeSnapshot {
    researcher.exchange().snapshot()
}

/// Shared deterministic builders for the crate's proof surface.
///
/// Every value below is fixed test material, never authority: admissions bind
/// the same bridge identity, epoch, fence, and ceilings the unit tests assert
/// against, so a binding regression fails the assertion, not the builder.
#[cfg(test)]
pub(crate) mod support {
    #![allow(clippy::expect_used)]

    use std::num::NonZeroU64;

    use eliot_contracts::{
        ContractVersion, EpochId, EpochLineageId, ResourceGeneration, StateFence,
    };
    use eliot_process::{Generation, OperationId};
    use eliot_research_exchange_api::{
        AllowedReferenceManifest, AnchorPrecision, DisclosureClass, ResearchQueryRequest,
        SourceClass,
    };

    use super::{
        BridgeContract, BridgeIdentity, CancellationBinding, CredentialBinding,
        ModuleGenerationEvidence, ProviderAdmission, ProviderRegistry, ProviderRoute,
    };

    pub(crate) const DIGEST_A: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    pub(crate) const DIGEST_B: &str =
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    pub(crate) const DIGEST_C: &str =
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    pub(crate) const DIGEST_UPPER: &str =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    pub(crate) const DIGEST_SHORT: &str = "aaaa";
    pub(crate) const EXECUTABLE: &str = "C:\\providers\\research-bridge-v1.exe";

    pub(crate) fn test_epoch() -> EpochId {
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::new(7).expect("sequence"),
        )
        .expect("epoch")
    }

    pub(crate) fn test_fence() -> StateFence {
        StateFence::new(test_epoch(), ResourceGeneration::genesis())
    }

    pub(crate) fn test_identity() -> BridgeIdentity {
        BridgeIdentity::new(EXECUTABLE, DIGEST_A).expect("test bridge identity must construct")
    }

    pub(crate) fn test_operation_id() -> OperationId {
        OperationId::new("op-24-slice-a").expect("operation")
    }

    pub(crate) fn test_admission() -> ProviderAdmission {
        let route = ProviderRoute {
            route_id: "route-research-private".to_owned(),
            provider_id: "provider-research".to_owned(),
            route_class: "service".to_owned(),
            data_class: "project-bound".to_owned(),
            paid_network: true,
            credential_binding: CredentialBinding {
                binding_id: "credential-binding-24".to_owned(),
                owner_principal: "researcher-owner".to_owned(),
                acting_principal: "requester-24-slice-a".to_owned(),
                mode: "explicit_delegation".to_owned(),
                data_classes: vec!["project-bound".to_owned()],
                secret_ref_sha256: DIGEST_A.to_owned(),
                revocation_ref: "revocation-24".to_owned(),
            },
        };
        let contract = BridgeContract::new(
            test_identity(),
            DIGEST_B,
            DIGEST_C,
            "mod-research-provider",
            "gen-mod-24-a",
            DIGEST_A,
            Generation::new(3).expect("generation"),
            test_epoch(),
            test_fence(),
            route.clone(),
            DisclosureClass::ProjectBound,
            "project-bound",
            10,
            1_800_000_000_000,
            ContractVersion::new(1, 0, 0),
            "research-evidence-bundle/v1",
            "gen-24-slice-a",
            CancellationBinding {
                operation_id: test_operation_id(),
                cancellation_id: "cancel-op-24".to_owned(),
                owner_principal: "researcher-owner".to_owned(),
                deadline_unix_ms: 1_800_000_000_000,
            },
        )
        .expect("test contract must construct");
        let evidence = ModuleGenerationEvidence {
            module_id: contract.module_id.clone(),
            generation_id: contract.module_generation_id.clone(),
            artifact_sha256: contract.bridge.executable_sha256().to_owned(),
            config_sha256: contract.config_digest.clone(),
            protocol_sha256: contract.protocol_digest.clone(),
            protocol_revision: contract.protocol_revision,
            route,
            state_fence: contract.fence.clone(),
            active: true,
            evidence_sha256: contract.registry_evidence_sha256.clone(),
        };
        ProviderAdmission::from_contract(
            contract,
            test_operation_id(),
            &ProviderRegistry::new(vec![evidence]),
        )
        .expect("test admission must construct")
    }

    pub(crate) fn test_request() -> ResearchQueryRequest {
        ResearchQueryRequest {
            exchange_id: "ex-24-slice-a".to_owned(),
            protocol_revision: ContractVersion::new(1, 0, 0),
            bridge_generation: "gen-24-slice-a".to_owned(),
            idempotency_key: "idem-24-slice-a".to_owned(),
            requester_principal: "requester-24-slice-a".to_owned(),
            state_fence: test_fence(),
            question: "which valve alloy survives".to_owned(),
            question_scope: "propulsion thermal envelope".to_owned(),
            expected_decision: "alloy selection".to_owned(),
            source_classes: vec![SourceClass::Paper],
            coverage_goal: "bounded exact sources with explicit unknowns".to_owned(),
            allowed_references: AllowedReferenceManifest {
                run_id: "run-24-slice-a".to_owned(),
                state_fence: test_fence(),
                source_handles: vec!["src-a".to_owned()],
                evidence_handles: Vec::new(),
                artifact_handles: Vec::new(),
                allowed_anchor_precision: AnchorPrecision::Section,
                stale_or_revoked_handles: Vec::new(),
                digest: DIGEST_A.to_owned(),
            },
            disclosure: DisclosureClass::ProjectBound,
            retention: "governed-by-caller".to_owned(),
            license_policy: "caller-policy".to_owned(),
            budget_units: 10,
            deadline_ms: 1_800_000_000_000,
            required_schema: "research-evidence-bundle/v1".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use eliot_research_exchange_api::CoverageGapKind;

    use super::support::{
        DIGEST_A, DIGEST_SHORT, DIGEST_UPPER, test_fence, test_identity, test_request,
    };
    use super::*;

    #[test]
    fn bridge_identity_accepts_exact_material() {
        let identity = test_identity();
        assert_eq!(
            identity.executable(),
            "C:\\providers\\research-bridge-v1.exe"
        );
        assert_eq!(identity.executable_sha256(), DIGEST_A);
    }

    #[test]
    fn bridge_identity_rejects_blank_executable() {
        for candidate in ["", "   ", "\t\n "] {
            assert!(
                matches!(
                    BridgeIdentity::new(candidate, DIGEST_A),
                    Err(BridgeError::InvalidBridgeIdentity { .. })
                ),
                "blank executable must be rejected: {candidate:?}"
            );
        }
    }

    #[test]
    fn bridge_identity_rejects_malformed_digest() {
        for candidate in [
            "",
            DIGEST_SHORT,
            DIGEST_UPPER,
            "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        ] {
            assert!(
                matches!(
                    BridgeIdentity::new("C:\\providers\\research-bridge-v1.exe", candidate),
                    Err(BridgeError::InvalidBridgeIdentity { .. })
                ),
                "malformed digest must be rejected: {candidate:?}"
            );
        }
    }

    #[test]
    fn gap_code_is_stable_and_machine_greppable() {
        assert_eq!(RESEARCH_SOURCE_UNAVAILABLE, "RESEARCH_SOURCE_UNAVAILABLE");
        let message = BridgeError::ProviderUnavailable.to_string();
        assert!(
            message.contains(RESEARCH_SOURCE_UNAVAILABLE),
            "typed gap must carry the stable code: {message}"
        );
        assert!(
            !message.to_ascii_lowercase().contains("ready"),
            "typed gap must never claim readiness: {message}"
        );
    }

    #[test]
    fn submit_is_a_typed_gap_and_records_no_job() {
        let mut researcher = compose_with_bridge(test_identity());
        let result = submit(&mut researcher, test_request());
        assert!(
            matches!(result, Err(ExchangeError::Provider { .. })),
            "bridge gap must surface as a typed coverage failure without fabricating a job"
        );
        assert!(
            exchange_snapshot(&researcher).jobs.is_empty(),
            "no exchange job may be recorded for an unexecuted provider call"
        );
        assert!(
            exchange_snapshot(&researcher).idempotency.is_empty(),
            "no idempotency binding may be recorded for an unexecuted provider call"
        );
    }

    #[test]
    fn bridge_cancel_is_a_typed_gap() {
        let mut bridge = GovernedResearchBridge::new(test_identity());
        assert!(
            matches!(
                ResearchBridge::submit(&mut bridge, &test_request()),
                Err(BridgeError::ProviderUnavailable)
            ),
            "submit without kernel admission must be a typed gap"
        );
        assert!(
            matches!(
                ResearchBridge::cancel(&mut bridge, "job-24-slice-a"),
                Err(BridgeError::ProviderUnavailable)
            ),
            "cancel without kernel admission must be a typed gap"
        );
    }

    /// Behavioral ambient-execution guard without environment mutation.
    ///
    /// Slice A removed environment-selected provider execution entirely, so
    /// no ambient configuration value can enable execution: both bridge
    /// operations must remain the typed non-executing gap. This test
    /// deliberately performs no process-environment mutation: the crate is
    /// `#![forbid(unsafe_code)]` and `std::env::set_var` is `unsafe` in the
    /// crate's edition, so mutating the environment in-process would require
    /// weakening the crate's unsafe policy. Restoration of the ambient path
    /// is instead made observable by
    /// `crate_sources_contain_no_ambient_launch_path` below.
    #[test]
    fn no_ambient_research_bridge_configuration_can_enable_execution() {
        let mut bridge = GovernedResearchBridge::new(test_identity());
        assert!(
            matches!(
                ResearchBridge::submit(&mut bridge, &test_request()),
                Err(BridgeError::ProviderUnavailable)
            ),
            "submit must stay a typed gap regardless of ambient configuration"
        );
        assert!(
            matches!(
                ResearchBridge::cancel(&mut bridge, "job-24-slice-a"),
                Err(BridgeError::ProviderUnavailable)
            ),
            "cancel must stay a typed gap regardless of ambient configuration"
        );
    }

    /// Static ambient-launch guard: the crate must not regain an
    /// environment-selected execution path.
    ///
    /// The forbidden symbols are spelled as fragments joined at runtime so
    /// this guard never matches its own source text. If the removed ambient
    /// bridge (environment lookup, ambient constructors/composer, or the
    /// child-process launch primitive) is restored in any crate source file,
    /// this test fails before any behavioral assertion runs.
    #[test]
    fn crate_sources_contain_no_ambient_launch_path() {
        // Each pair joins to one removed ambient-bridge symbol. Keep the
        // halves split so this file never contains a forbidden symbol itself.
        const FORBIDDEN_FRAGMENTS: [(&str, &str); 5] = [
            ("Command:", ":new"),
            ("std::process:", ":Command"),
            ("ELIOT_RESEARCH_", "BRIDGE"),
            ("from_", "environment"),
            ("compose_from_", "environment"),
        ];
        const SOURCES: [&str; 7] = [
            include_str!("lib.rs"),
            include_str!("main.rs"),
            include_str!("admission.rs"),
            include_str!("evidence.rs"),
            include_str!("execution.rs"),
            include_str!("protocol.rs"),
            include_str!("runtime.rs"),
        ];
        for (head, tail) in FORBIDDEN_FRAGMENTS {
            let symbol = format!("{head}{tail}");
            for source in SOURCES {
                assert!(
                    !source.contains(symbol.as_str()),
                    "ambient launch symbol must not return to eliot-mod-research"
                );
            }
        }
    }

    #[test]
    fn carried_identity_is_exact_end_to_end() {
        let researcher = compose_with_bridge(test_identity());
        let (bridge, _) = researcher.into_exchange().into_parts();
        assert_eq!(bridge.identity(), &test_identity());
    }

    #[test]
    fn free_cancel_forwards_without_fabricating() {
        let mut researcher = compose_with_bridge(test_identity());
        let fence = test_fence();
        assert!(
            matches!(
                cancel(&mut researcher, "job-24-slice-a", &fence),
                Err(ExchangeError::NotFound)
            ),
            "cancel of an unknown job must report absence, never fabricate"
        );
    }

    #[test]
    fn bridge_failures_map_to_acquisition_coverage_gaps() {
        assert_eq!(
            BridgeError::ProviderUnavailable.coverage_gap_kind(),
            CoverageGapKind::SourceUnavailable
        );
        assert_eq!(
            BridgeError::NotAdmitted { reason: "x" }.coverage_gap_kind(),
            CoverageGapKind::PolicyOrDisclosureDenied
        );
        assert_eq!(
            BridgeError::ProtocolViolation { reason: "x" }.coverage_gap_kind(),
            CoverageGapKind::StaleSourceOrIndex
        );
        assert_eq!(
            BridgeError::TimedOut.coverage_gap_kind(),
            CoverageGapKind::Timeout
        );
        for error in [
            BridgeError::ProviderFailed { reason: "x" },
            BridgeError::EvidenceIncomplete { reason: "x" },
            BridgeError::UnknownOutcome,
        ] {
            assert_eq!(
                error.coverage_gap_kind(),
                CoverageGapKind::Unknown,
                "unclassified provider failure must stay an explicit unknown gap"
            );
        }
    }

    #[test]
    fn admitted_cancel_before_submit_is_refused() {
        let mut bridge = admitted_test_bridge(super::execution::RequestPortError::NoAuthority);
        assert!(
            matches!(
                ResearchBridge::cancel(&mut bridge, "op-24-slice-a"),
                Err(BridgeError::NotAdmitted { .. })
            ),
            "cancel before submit must be refused: nothing was attempted"
        );
        assert!(
            !bridge.has_submitted(),
            "a refused cancel must not mark the operation submitted"
        );
    }

    #[test]
    fn admitted_cancel_targets_only_the_bound_operation() {
        let mut bridge = admitted_test_bridge(super::execution::RequestPortError::NoAuthority);
        assert!(
            matches!(
                ResearchBridge::cancel(&mut bridge, "op-foreign"),
                Err(BridgeError::NotAdmitted { .. })
            ),
            "cancel of a foreign operation must be refused"
        );
    }

    #[test]
    fn admitted_reconcile_before_submit_is_refused() {
        let mut bridge = admitted_test_bridge(super::execution::RequestPortError::Refused);
        assert!(
            matches!(bridge.reconcile(), Err(BridgeError::NotAdmitted { .. })),
            "reconcile before submit must be refused: nothing was attempted"
        );
        assert_eq!(bridge.last_provider_job_ref(), None);
        assert_eq!(bridge.last_evidence(), None);
    }

    #[test]
    fn admitted_submit_without_authority_is_a_gap_and_records_no_job() {
        let mut researcher = compose_admitted(
            test_runner(super::execution::RequestPortError::NoAuthority),
            super::support::test_admission(),
        );
        let result = submit(&mut researcher, test_request());
        assert!(
            matches!(result, Err(ExchangeError::Provider { .. })),
            "absent process authority must surface as a typed gap, never a job"
        );
        assert!(
            exchange_snapshot(&researcher).jobs.is_empty(),
            "no exchange job may be recorded for an unexecuted provider call"
        );
        let (bridge, _) = researcher.into_exchange().into_parts();
        assert!(
            !bridge.has_submitted(),
            "a gap before executor contact must keep the operation retryable, not submitted"
        );
        assert_eq!(
            bridge.admission().operation_id().as_str(),
            "op-24-slice-a",
            "the bound admission stays exact after a gap"
        );
        assert_eq!(bridge.last_evidence(), None);
        assert_eq!(bridge.last_provider_job_ref(), None);
    }

    /// Test-only request port: always refuses, so no executor contact happens.
    struct RefusingTestPort(super::execution::RequestPortError);

    impl super::execution::ResearchRequestPort for RefusingTestPort {
        fn bind(
            &self,
            _admission: &super::admission::ProviderAdmission,
            _envelope: &super::protocol::SubmitEnvelope,
            _wire_bytes: &[u8],
        ) -> Result<eliot_process::ProcessRequest, super::execution::RequestPortError> {
            Err(self.0)
        }
    }

    /// Test-only evidence sink that accepts and drops everything.
    #[derive(Default)]
    struct DropSink;

    impl eliot_process::ProcessEvidenceSink for DropSink {
        fn record(
            &self,
            _evidence: eliot_process::ProcessEvidence,
        ) -> Result<(), eliot_process::EvidenceSinkError> {
            Ok(())
        }
    }

    /// Authority port that must never be contacted: every test here fails
    /// before the executor is reached, so any call is a test failure.
    struct UnreachedPort;

    impl eliot_process_executor::DispatchValidationPort for UnreachedPort {
        fn validate_and_consume(
            &self,
            _request: eliot_process::ProcessRequest,
            _observed: eliot_process::SuspendedProcessIdentity,
        ) -> Result<eliot_process::ValidatedDispatch, eliot_process::ProcessExecutionError>
        {
            panic!("refusal tests must not reach the executor");
        }
    }

    fn test_runner(
        refusal: super::execution::RequestPortError,
    ) -> super::execution::ProviderBridge {
        use std::sync::Arc;
        let executor = Arc::new(eliot_process_executor::WindowsProcessExecutor::new(
            Arc::new(UnreachedPort),
        ));
        super::execution::ProviderBridge::new(
            executor,
            Arc::new(RefusingTestPort(refusal)),
            Arc::new(DropSink),
        )
    }

    fn admitted_test_bridge(refusal: super::execution::RequestPortError) -> AdmittedResearchBridge {
        AdmittedResearchBridge::new(test_runner(refusal), super::support::test_admission())
    }
}
