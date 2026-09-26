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
pub mod dispatch_authority;
pub mod dispatched_material;
pub mod evidence;
pub mod execution;
pub mod kernel_client;
pub mod protocol;

use eliot_contracts::StateFence;
use eliot_process::ExitDisposition;
use eliot_research_exchange::{ExchangeError, ExchangeJob, ResearchBridge};
use eliot_research_exchange_api::{CoverageGapKind, ResearchQueryRequest, SourceClass};
use eliot_researcher::{
    AcquisitionOutcome, CandidateEvidence, InquiryGovernance, InquiryHorizon, InquiryObservation,
    InquiryRisk, InquirySelectionFeatures, InquiryUncertainty, Researcher,
    SpecialistDiscoverability, StreamEvidence, VerifierStrength,
};
use thiserror::Error;

pub use admission::{AdmissionRefusal, ProviderAdmission};
pub use dispatch_authority::{
    AdmittedRequestPort, ProviderEvidenceRecorder, ResearchAuthorityError,
    ResearchDispatchAuthority,
};
pub use evidence::{
    CancellationEvidence, ProviderEvidenceRecord, ProviderExecutionReceipt, RawProviderEvidence,
    RedactedEvidence, RedactionReceipt, StreamOmission, StreamRecord, sha256_hex,
};
pub use execution::{
    BOUND_RUN_DEADLINE, ProviderBridge, ProviderExecution, ProviderOutcome, RequestPortError,
    ResearchRequestPort, build_submit_binding,
};
pub use kernel_client::{ResearchKernelClient, ResearchKernelClientError};
pub use protocol::{
    MAX_WIRE_BYTES, MAX_WIRE_LINES, RESEARCH_PROVIDER_WIRE_VERSION, ResultFrame, SubmitBinding,
    SubmitEnvelope,
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
    TimedOut {
        /// The retained cancellation receipt fragment. It is always present on
        /// this variant: a timeout that proved nothing about cancellation is
        /// reported as cancellation-unconfirmed, never as a clean stop.
        ///
        /// Boxed so the typed error stays small enough to return by value from
        /// every call site without an allocation on the success path.
        cancellation: Box<CancellationEvidence>,
    },
    #[error(
        "research provider outcome is unknown: reconcile by operation identity before any retry"
    )]
    UnknownOutcome {
        /// Immutable raw evidence materialized before the outcome was found
        /// unclassifiable. Preserved so a reconcile can use the same bytes.
        /// Boxed for the same reason as [`BridgeError::TimedOut`].
        evidence: Option<Box<RawProviderEvidence>>,
    },
    #[error("shared process contour failed: {0}")]
    Process(#[from] eliot_process::ProcessExecutionError),
}

/// Why the `R6` inquiry-governance view of one admitted operation could not be
/// projected.
///
/// The refusal is a typed gap on the evidence stream. It never becomes a closed
/// inquiry, an admitted result, or a substitute provider receipt.
#[derive(Debug, Error)]
pub enum R6ProjectionError {
    /// The admitted material does not bind one exact operation.
    #[error("inquiry governance projection refused: {reason}")]
    UnboundAdmission {
        /// Stable reason for the refusal.
        reason: &'static str,
    },
    /// The `R6` domain refused the admitted material.
    #[error("inquiry governance projection refused by the researcher domain: {0}")]
    Domain(#[from] eliot_researcher::InquiryError),
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
            Self::TimedOut { .. } => CoverageGapKind::Timeout,
            Self::ProviderFailed { .. }
            | Self::EvidenceIncomplete { .. }
            | Self::UnknownOutcome { .. }
            | Self::Process(_) => CoverageGapKind::Unknown,
        }
    }

    /// Returns the exact I7.20 `reason_code` for this failure.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidBridgeIdentity { .. } | Self::ProviderUnavailable => {
                eliot_kernel_service::REASON_RESEARCH_SOURCE_UNAVAILABLE
            }
            Self::NotAdmitted { .. } => eliot_kernel_service::REASON_POLICY_DENIED,
            Self::ProtocolViolation { .. } => eliot_kernel_service::REASON_PROTOCOL_INCOMPATIBLE,
            Self::TimedOut { .. } => eliot_kernel_service::REASON_DEADLINE_EXCEEDED,
            Self::ProviderFailed { .. } | Self::Process(_) => {
                eliot_kernel_service::REASON_RUNTIME_FAILED
            }
            Self::EvidenceIncomplete { .. } => {
                eliot_kernel_service::REASON_INSTRUMENT_EVIDENCE_INCOMPLETE
            }
            Self::UnknownOutcome { .. } => eliot_kernel_service::REASON_UNKNOWN_OUTCOME,
        }
    }

    /// Returns the retained cancellation receipt fragment, when one exists.
    #[must_use]
    pub const fn cancellation(&self) -> Option<&CancellationEvidence> {
        match self {
            Self::TimedOut { cancellation } => Some(cancellation),
            _ => None,
        }
    }

    /// Returns the immutable raw evidence, when it was materialized before the
    /// failure was classified.
    #[must_use]
    pub fn evidence(&self) -> Option<&RawProviderEvidence> {
        match self {
            Self::UnknownOutcome { evidence } => evidence.as_deref(),
            _ => None,
        }
    }
}

/// Explicit immutable identity of one registered research provider bridge.
///
/// Both fields arrive from already-admitted material. Nothing here is read
/// from ambient environment, and identity alone grants no execution: the
/// Kernel-issued research admission that binds this identity to one exact
/// operation lands in [`ProviderAdmission`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BridgeIdentity {
    executable: String,
    executable_sha256: String,
}

impl BridgeIdentity {
    /// Binds one bridge executable path to its exact content digest.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::InvalidBridgeIdentity`] when the path is blank
    /// or the digest is not a lowercase SHA-256 hex string.
    pub fn new(
        executable: impl Into<String>,
        executable_sha256: impl Into<String>,
    ) -> Result<Self, BridgeError> {
        let executable = executable.into();
        let executable_sha256 = executable_sha256.into();
        if executable.trim().is_empty() {
            return Err(BridgeError::InvalidBridgeIdentity {
                reason: "executable path is empty",
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
}

/// Lifecycle phase of one admitted operation. One bridge serves exactly one
/// bounded operation: after any executor contact the operation is never
/// resubmitted blindly — unknown or timed-out outcomes must be reconciled by
/// the stable operation identity first, and every other outcome requires a
/// fresh admission for a fresh attempt.
#[derive(Clone, Debug)]
enum BridgePhase {
    /// Nothing was attempted through the executor yet.
    Awaiting,
    /// The executor was contacted; resubmission is refused.
    ///
    /// Boxed because the submitted payload carries the raw evidence and the
    /// submit reconciliation record; the awaiting phase is the common case and
    /// must not pay for them.
    Submitted(Box<SubmittedState>),
}

/// The state of one attempt that has reached the executor.
#[derive(Clone, Debug)]
struct SubmittedState {
    /// Typed terminal outcome (or the failure that ended the attempt).
    outcome: SubmittedOutcome,
    /// Immutable raw evidence when the attempt reached materialization.
    evidence: Option<RawProviderEvidence>,
    /// Provider-local job reference when the ack decoded.
    provider_job_ref: Option<String>,
    /// Cancellation receipt fragment when a cancellation was issued.
    cancellation: Option<CancellationEvidence>,
    /// Exact reconciliation record for the submit, when one was built.
    submission: Option<SubmissionRecord>,
    /// Terminal classification of the failure that ended the attempt.
    failure: Option<TerminalFailure>,
    /// Whether an unknown outcome was reconciled since.
    reconciled: bool,
}

/// Cloneable terminal classification of one failed provider attempt.
///
/// `BridgeError` itself is not `Clone` (it carries the executor's
/// non-cloneable process error), so the bridge retains this projection instead:
/// the exact I7.20 reason code, the typed coverage-gap kind, and whatever
/// evidence and cancellation proof existed at the moment of failure. Nothing
/// is collapsed into prose.
#[derive(Clone, Debug)]
pub struct TerminalFailure {
    /// Exact I7.20 reason code for the failure.
    pub reason_code: &'static str,
    /// Typed coverage-gap kind the caller records.
    pub coverage_gap: CoverageGapKind,
    /// Provider-local terminal outcome the failure classifies as.
    pub outcome: ProviderOutcome,
    /// Immutable raw evidence, when it was materialized before the failure.
    pub evidence: Option<RawProviderEvidence>,
    /// Cancellation receipt fragment, when a cancellation was issued.
    pub cancellation: Option<CancellationEvidence>,
}

impl TerminalFailure {
    /// Projects one typed bridge failure into its cloneable terminal record.
    #[must_use]
    pub fn from_error(error: &BridgeError) -> Self {
        let outcome = match error {
            BridgeError::TimedOut { .. } => ProviderOutcome::TimedOut,
            BridgeError::UnknownOutcome { .. } => ProviderOutcome::Unknown,
            // A refused or failed attempt reached the executor or its contour,
            // so it is crash-class acquisition evidence, never a clean stop and
            // never a fabricated completion.
            _ => ProviderOutcome::Crashed,
        };
        Self {
            reason_code: error.reason_code(),
            coverage_gap: error.coverage_gap_kind(),
            outcome,
            evidence: error.evidence().cloned(),
            cancellation: error.cancellation().cloned(),
        }
    }
}

/// The exact reconciliation record of one sealed submit.
///
/// It exists so a replay or an unknown outcome can be resolved byte-for-byte:
/// `submit_binding_sha256` is what the provider was actually given through the
/// admitted argv, and `envelope_sha256` / `envelope_bytes` are the full
/// canonical envelope that additionally binds the sealed process-request
/// digest. Neither is derivable from the other, and neither is provider output.
#[derive(Clone, Debug)]
pub struct SubmissionRecord {
    /// Digest of the bounded projection delivered through the admitted argv.
    pub submit_binding_sha256: String,
    /// Digest of the full canonical submit envelope.
    pub envelope_sha256: String,
    /// The exact canonical submit envelope bytes.
    pub envelope_bytes: Vec<u8>,
}

/// Terminal record of one submitted attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SubmittedOutcome {
    Completed,
    Crashed,
    TimedOut,
    Cancelled,
    Unknown,
    Refused,
}

impl SubmittedOutcome {
    /// Returns whether this outcome requires reconciliation before any retry.
    /// A fresh admission is required regardless; this flag additionally opens
    /// the `reconcile` path.
    const fn requires_reconciliation(self) -> bool {
        matches!(self, Self::TimedOut | Self::Unknown)
    }
}

/// Admitted research provider bridge: one exact admission, one bounded
/// operation, shared-executor execution.
///
/// The bridge is constructed from already-admitted material (identity,
/// admission, executor handle, request-minting port, evidence sink) and mints
/// no authority. `submit` returns the admitted operation identity — the only
/// identity the exchange keys on; the provider-local job reference stays
/// outcome evidence. Provider output remains candidate/evidence-set material:
/// this bridge never builds a `ResearchEvidenceBundle`, never touches
/// Cognitive Inheritance, policy, or finish.
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

    /// Returns whether the executor has been contacted for this operation.
    #[must_use]
    pub const fn has_submitted(&self) -> bool {
        matches!(self.phase, BridgePhase::Submitted(_))
    }

    /// Returns the submitted state, when the executor has been contacted.
    const fn submitted(&self) -> Option<&SubmittedState> {
        match &self.phase {
            BridgePhase::Awaiting => None,
            BridgePhase::Submitted(state) => Some(state),
        }
    }

    /// Returns the last immutable raw evidence when materialized.
    #[must_use]
    pub fn last_evidence(&self) -> Option<&RawProviderEvidence> {
        self.submitted().and_then(|state| state.evidence.as_ref())
    }

    /// Returns the retained cancellation receipt fragment, when one was issued.
    ///
    /// Present after a deadline overrun and after an explicit cancel: a
    /// cancellation that was attempted is never discarded.
    #[must_use]
    pub fn last_cancellation(&self) -> Option<&CancellationEvidence> {
        self.submitted()
            .and_then(|state| state.cancellation.as_ref())
    }

    /// Returns the exact submit reconciliation record, when one was sealed.
    #[must_use]
    pub fn last_submission(&self) -> Option<&SubmissionRecord> {
        self.submitted().and_then(|state| state.submission.as_ref())
    }

    /// Returns the terminal classification of the failure that ended the
    /// attempt, when the attempt failed after reaching the executor.
    #[must_use]
    pub fn last_failure(&self) -> Option<&TerminalFailure> {
        self.submitted().and_then(|state| state.failure.as_ref())
    }

    /// Returns the provider-local job reference when the submit ack decoded.
    /// Correlation only: this reference is never canonical identity.
    #[must_use]
    pub fn last_provider_job_ref(&self) -> Option<&String> {
        self.submitted()
            .and_then(|state| state.provider_job_ref.as_ref())
    }

    /// Reconciles an unknown or timed-out outcome by operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::NotAdmitted`] when nothing was attempted, when
    /// the outcome is already classified, or when it was already reconciled.
    /// Transport failures surface as [`BridgeError::Process`].
    pub fn reconcile(&mut self) -> Result<eliot_process::ProcessEvidence, BridgeError> {
        let Some(state) = self.submitted() else {
            return Err(BridgeError::NotAdmitted {
                reason: "nothing was attempted through the executor yet",
            });
        };
        if !state.outcome.requires_reconciliation() || state.reconciled {
            return Err(BridgeError::NotAdmitted {
                reason: "outcome is classified or already reconciled",
            });
        }
        let evidence = self
            .runner
            .reconcile_operation(self.admission.operation_id())?;
        if let BridgePhase::Submitted(state) = &mut self.phase {
            state.reconciled = true;
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
                let outcome = match execution.outcome {
                    ProviderOutcome::Completed => SubmittedOutcome::Completed,
                    ProviderOutcome::Crashed => SubmittedOutcome::Crashed,
                    ProviderOutcome::TimedOut => SubmittedOutcome::TimedOut,
                    ProviderOutcome::Cancelled => SubmittedOutcome::Cancelled,
                    ProviderOutcome::Unknown => SubmittedOutcome::Unknown,
                };
                let job_id = execution.job_id.clone();
                self.phase = BridgePhase::Submitted(Box::new(SubmittedState {
                    outcome,
                    evidence: Some(execution.evidence),
                    provider_job_ref: Some(execution.provider_job_ref),
                    cancellation: execution.cancellation,
                    submission: Some(SubmissionRecord {
                        submit_binding_sha256: execution.submit_binding_sha256,
                        envelope_sha256: sha256_hex(&execution.wire_bytes),
                        envelope_bytes: execution.wire_bytes,
                    }),
                    failure: None,
                    reconciled: false,
                }));
                Ok(job_id)
            }
            Err(error) => {
                // Nothing reached the executor for binding refusals and absent
                // authority: the same admission may be retried with corrected
                // input. Every other failure means the operation may exist in
                // the executor registry, so resubmission is refused and
                // unknown outcomes stay reconcile-gated.
                let terminal = match &error {
                    BridgeError::TimedOut { .. } => SubmittedOutcome::TimedOut,
                    BridgeError::UnknownOutcome { .. } => SubmittedOutcome::Unknown,
                    BridgeError::ProviderFailed { .. }
                    | BridgeError::EvidenceIncomplete { .. }
                    | BridgeError::ProtocolViolation { .. }
                    | BridgeError::Process(_) => SubmittedOutcome::Refused,
                    BridgeError::NotAdmitted { .. }
                    | BridgeError::ProviderUnavailable
                    | BridgeError::InvalidBridgeIdentity { .. } => return Err(error),
                };
                // The evidence and the cancellation receipt materialized
                // immediately before the failure are retained here. The
                // previous arm set `evidence: None`, which threw away the
                // stderr/exit/lineage record for exactly the two terminal
                // cases that most need it.
                self.phase = BridgePhase::Submitted(Box::new(SubmittedState {
                    outcome: terminal,
                    evidence: error.evidence().cloned(),
                    provider_job_ref: None,
                    cancellation: error.cancellation().cloned(),
                    submission: self.runner.last_submission(),
                    failure: Some(TerminalFailure::from_error(&error)),
                    reconciled: false,
                }));
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
        if !matches!(self.phase, BridgePhase::Awaiting) {
            // Identity/ownership is proven before a cancel as well as before a
            // start: the cancellation is refused unless the stored operation
            // record still answers to this admission's exact operation
            // identity, request digest, and Authority Epoch. Cancelling by a
            // bare job id would let a stale generation or a retargeted request
            // reach another operation's process tree.
            let view = self.runner.observe_bound_operation()?;
            if view.operation_id() != self.admission.operation_id()
                || !view
                    .fence()
                    .authority_epoch()
                    .is_same_authority(self.admission.epoch())
            {
                return Err(BridgeError::NotAdmitted {
                    reason: "stored operation no longer matches the admitted identity or epoch",
                });
            }
            self.runner
                .cancel_operation(self.admission.operation_id())?;
            return Ok(());
        }
        Err(BridgeError::NotAdmitted {
            reason: "nothing was attempted through the executor yet",
        })
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

/// Stable code prefixed to the `R6` inquiry-governance view of one admitted
/// operation on the evidence stream.
pub const INQUIRY_GOVERNANCE_VIEW: &str = "INQUIRY_GOVERNANCE_VIEW";

/// Stable code emitted on the evidence stream when the `R6` inquiry-governance
/// view of one admitted operation could not be projected.
///
/// The provider receipt stays the operation's own truth: a governance projection
/// that cannot be built is reported as a typed gap, never as a closed inquiry
/// and never as an admitted result.
pub const INQUIRY_GOVERNANCE_REFUSED: &str = "INQUIRY_GOVERNANCE_REFUSED";

/// Projects the `R6` inquiry-governance view of one admitted provider
/// operation.
///
/// This is the production edge that makes the `R6` typed domain reachable: every
/// admitted operation this composition root performs is observed exactly once
/// here, and the resulting record is a versioned inquiry profile with its
/// selected grade and lane, the source-admissibility disposition of the retained
/// material, a coverage receipt with a declared denominator kind, the compiler
/// inputs for the open obligations, the non-canonical governed artifacts, and a
/// terminal typed inquiry disposition bound to the profile, portfolio, manifest
/// and State Fence.
///
/// Every field is derived from already-admitted material and from the retained
/// raw evidence of this process. The projection never decodes the provider body,
/// never claims a source, citation, anchor or coverage the evidence does not
/// carry, and never promotes the result: the record stays candidate-only and the
/// Governor applies any transition.
///
/// # Errors
///
/// Returns [`R6ProjectionError::UnboundAdmission`] when the admitted request and
/// the terminal receipt do not bind the same operation, exchange, budget or
/// deadline, and [`R6ProjectionError::Domain`] when the `R6` domain refuses the
/// admitted material. Neither variant changes the provider receipt or this
/// process's exit code: the refusal is reported on the evidence stream.
pub fn project_admitted_inquiry(
    request: &ResearchQueryRequest,
    receipt: &ProviderExecutionReceipt,
) -> Result<InquiryGovernance, crate::R6ProjectionError> {
    if receipt.operation_id.is_empty()
        || receipt.exchange_id != request.exchange_id
        || receipt.cancellation_id.is_empty()
        || receipt.inquiry_digest.is_empty()
        || receipt.denominator_digest.is_empty()
    {
        return Err(crate::R6ProjectionError::UnboundAdmission {
            reason: "admitted request and terminal receipt do not bind the same operation",
        });
    }
    if receipt.budget_units != request.budget_units || receipt.deadline_ms != request.deadline_ms {
        return Err(crate::R6ProjectionError::UnboundAdmission {
            reason: "terminal receipt widens the admitted budget or deadline",
        });
    }
    let assessment_time_ms = i64::try_from(dispatch_authority::unix_ms()).unwrap_or(i64::MAX);
    let route = format!(
        "{}@{}",
        receipt.module_generation_id, receipt.executable_sha256
    );
    let observation = InquiryObservation {
        inquiry_id: receipt.exchange_id.clone(),
        evidence_set_id: request.allowed_references.run_id.clone(),
        profile_id: format!("inquiry-profile-{}", receipt.exchange_id),
        operation_id: receipt.operation_id.clone(),
        exchange_id: receipt.exchange_id.clone(),
        inquiry_digest: receipt.inquiry_digest.clone(),
        denominator_digest: receipt.denominator_digest.clone(),
        question: request.question.clone(),
        scope: request.question_scope.clone(),
        intended_decision_or_artifact: request.expected_decision.clone(),
        requester: request.requester_principal.clone(),
        requested_source_classes: request.source_classes.clone(),
        reference_manifest: request.allowed_references.clone(),
        admitted_coverage_goal: request.coverage_goal.clone(),
        required_schema: request.required_schema.clone(),
        disclosure: request.disclosure,
        budget_units: request.budget_units,
        deadline_ms: request.deadline_ms,
        cancellation_id: receipt.cancellation_id.clone(),
        provider_generation: receipt.module_generation_id.clone(),
        admissible_routes: vec![route.clone()],
        features: admitted_selection_features(request),
        candidates: vec![retained_provider_material(request, receipt, &route)],
        outcome: acquisition_outcome(receipt),
        reason_code: receipt.reason_code.to_owned(),
        assessment_time_ms,
    };
    InquiryGovernance::record(observation).map_err(crate::R6ProjectionError::from)
}

/// The structural selection features this boundary can prove from admitted
/// material.
///
/// The selection inputs I21.3 requires are properties of the requesting task
/// definition: sequential dependency, branch independence, shared mutable state,
/// verifier cost and strength, specialist discoverability, horizon, uncertainty
/// and risk. A bounded provider admission does not carry them, and this process
/// does not read them from ambient material. Rather than guess them, every
/// feature takes the weakest value the admitted intent can support, and the two
/// facts the admission does establish are read from the requester-declared
/// source classes: whether a primary-source class and whether a measured-evidence
/// class were named. The resulting profile is therefore the weakest profile the
/// admitted intent can support, and the inquiry disposition it produces cannot
/// claim more rigour than the observation carries.
fn admitted_selection_features(request: &ResearchQueryRequest) -> InquirySelectionFeatures {
    let names_primary_source = request.source_classes.iter().any(|class| {
        matches!(
            class,
            SourceClass::Paper | SourceClass::Documentation | SourceClass::Repository
        )
    });
    let names_measured_evidence = request.source_classes.contains(&SourceClass::Dataset);
    InquirySelectionFeatures {
        sequential_dependency: false,
        branch_independence: false,
        shared_mutable_state: false,
        verifier_cost: VerifierStrength::Low,
        verifier_strength: VerifierStrength::Low,
        specialist_discoverability: SpecialistDiscoverability::None,
        horizon: InquiryHorizon::Immediate,
        uncertainty: InquiryUncertainty::High,
        risk: InquiryRisk::Low,
        evaluator_exists: false,
        primary_source_available: names_primary_source,
        measured_evidence_available: names_measured_evidence,
        bounded_decision: true,
    }
}

/// Projects the retained provider material of one run into the candidate source
/// material the `R6` boundary assesses.
///
/// The candidate carries the exact custody this process holds: the retained
/// stdout digest, the retained evidence transport digest, the admitted route and
/// provider generation, the terminal outcome, the retained stream state and the
/// physical exit disposition. It never carries the provider body.
fn retained_provider_material(
    request: &ResearchQueryRequest,
    receipt: &ProviderExecutionReceipt,
    route: &str,
) -> CandidateEvidence {
    let stream = match (receipt.raw.stdout.omission, receipt.raw.stdout.complete) {
        (Some(StreamOmission::NoHandle), _) => StreamEvidence::Absent,
        (None, true) => StreamEvidence::Complete,
        _ => StreamEvidence::Partial,
    };
    let receipt_handle = receipt.evidence_records.first().map_or_else(
        || receipt.raw.invocation_digest.clone(),
        |record| record.transport_sha256.clone(),
    );
    CandidateEvidence {
        handle: format!("provider-artifact:{}", receipt.raw.stdout.sha256),
        class: request
            .source_classes
            .first()
            .copied()
            .unwrap_or(SourceClass::Unknown),
        operation_id: receipt.operation_id.clone(),
        content_digest: receipt.raw.stdout.sha256.clone(),
        receipt_handle,
        route: route.to_owned(),
        provider_generation: receipt.module_generation_id.clone(),
        lineage_root: Some(route.to_owned()),
        outcome: acquisition_outcome(receipt),
        stream,
        exit_completed: matches!(receipt.raw.exit_disposition, ExitDisposition::Completed),
        // A submit binding exists only once a submit reached the shared process
        // contour, so its absence with no stream handle is the exact "refused
        // before acquisition" signal rather than a crash with no output.
        refused: stream == StreamEvidence::Absent && receipt.submit_binding_sha256.is_empty(),
    }
}

/// Maps this crate's typed provider outcome onto the `R6` domain vocabulary.
fn acquisition_outcome(receipt: &ProviderExecutionReceipt) -> AcquisitionOutcome {
    match receipt.outcome {
        ProviderOutcome::Completed => AcquisitionOutcome::Completed,
        ProviderOutcome::Crashed => AcquisitionOutcome::Crashed,
        ProviderOutcome::TimedOut => AcquisitionOutcome::TimedOut,
        ProviderOutcome::Cancelled => AcquisitionOutcome::Cancelled,
        ProviderOutcome::Unknown => AcquisitionOutcome::Unknown,
    }
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

    use super::{BridgeIdentity, ProviderAdmission};

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
    pub(crate) const COVERAGE_GOAL: &str = "bounded exact sources with explicit unknowns";

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
        ProviderAdmission::new(
            test_identity(),
            DIGEST_B,
            DIGEST_C,
            "mod-research-provider",
            "gen-mod-24-a",
            Generation::new(3).expect("generation"),
            test_epoch(),
            test_fence(),
            DisclosureClass::ProjectBound,
            10,
            1_800_000_000_000,
            ContractVersion::new(1, 0, 0),
            "research-evidence-bundle/v1",
            "gen-24-slice-a",
            test_operation_id(),
            DIGEST_A,
            DIGEST_B,
            COVERAGE_GOAL,
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
            coverage_goal: COVERAGE_GOAL.to_owned(),
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
            matches!(result, Err(ExchangeError::InvalidTransition)),
            "bridge gap must surface without fabricating a job"
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
        const SOURCES: [&str; 9] = [
            include_str!("lib.rs"),
            include_str!("main.rs"),
            include_str!("admission.rs"),
            include_str!("dispatch_authority.rs"),
            include_str!("dispatched_material.rs"),
            include_str!("evidence.rs"),
            include_str!("execution.rs"),
            include_str!("kernel_client.rs"),
            include_str!("protocol.rs"),
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
            BridgeError::TimedOut {
                cancellation: Box::new(super::evidence::CancellationEvidence {
                    operation_id: "op-24-slice-a".to_owned(),
                    request_digest: super::support::DIGEST_A.to_owned(),
                    status: "Requested".to_owned(),
                    lifecycle: "Running".to_owned(),
                    no_effect_proven: false,
                    descendants_complete: false,
                }),
            }
            .coverage_gap_kind(),
            CoverageGapKind::Timeout
        );
        for error in [
            BridgeError::ProviderFailed { reason: "x" },
            BridgeError::EvidenceIncomplete { reason: "x" },
            BridgeError::UnknownOutcome { evidence: None },
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
            matches!(result, Err(ExchangeError::InvalidTransition)),
            "absent process authority must surface as a gap, never a job"
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
            _submit_binding: &(String, String),
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
