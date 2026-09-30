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
pub mod capability_cell;
pub mod dispatch_authority;
pub mod dispatched_material;
pub mod evidence;
pub mod execution;
pub mod kernel_client;
pub mod protocol;

use eliot_contracts::StateFence;
use eliot_process::{ExitDisposition, OperationId};
use eliot_research_exchange::{ExchangeError, ExchangeJob, ResearchBridge};
use eliot_research_exchange_api::{
    CoverageGapKind, DisclosureClass, ExternalKnowledgeFailure, ResearchQueryRequest,
    ResearchSourceGapOutcome, SourceClass,
};
use eliot_researcher::{
    AcquisitionOutcome, CandidateEvidence, InquiryGovernance, InquiryHorizon, InquiryObservation,
    InquiryRisk, InquirySelectionFeatures, InquiryUncertainty, Researcher,
    SpecialistDiscoverability, StreamEvidence, VerifierStrength,
};
use thiserror::Error;

pub use admission::{AdmissionRefusal, ProviderAdmission};
pub use capability_cell::resolve_admitted_cell;
pub use dispatch_authority::{
    AdmittedRequestPort, ProviderEvidenceRecorder, ResearchAuthorityError,
    ResearchDispatchAuthority,
};
pub use evidence::{
    CancellationEvidence, OwnerReconciliationAttempt, ProviderEvidenceRecord,
    ProviderExecutionReceipt, RawProviderEvidence, ReconciliationEvidence, RedactedEvidence,
    RedactionReceipt, StreamOmission, StreamRecord, sha256_hex,
};
pub use execution::{
    BOUND_RUN_DEADLINE, CancellationOutcome, EvidenceObservation, Obligation, ProviderBridge,
    ProviderExecution, ProviderOutcome, RequestPortError, ResearchRequestPort,
    UndischargedObligation, build_submit_binding,
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
        /// The immutable raw evidence already materialized when the wire was
        /// found malformed.
        ///
        /// A wire refusal is a statement about the protocol, not about the
        /// process: the provider's stdout/stderr/exit/lineage were observed
        /// before its output was decoded, and they are retained here rather
        /// than replaced by an absence record. `None` only for a refusal raised
        /// before the executor was contacted, where no provider output existed
        /// to retain.
        evidence: Option<Box<RawProviderEvidence>>,
        /// The provider's observed process disposition, kept separate from the
        /// protocol's validity.
        ///
        /// A provider can exit cleanly and still answer with a wire this
        /// bridge does not accept. Collapsing those two facts would let a
        /// process that genuinely completed be reported as though nothing ran.
        /// `None` when no terminal process state was observed.
        disposition: Option<ProviderOutcome>,
    },
    #[error("research provider stream readback did not answer")]
    StreamReadbackFailed {
        /// Executor disposition observed before the stream readback failed.
        disposition: Option<ProviderOutcome>,
        /// Typed executor refusal from the attempted readback.
        #[source]
        source: Box<eliot_process::ProcessExecutionError>,
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
        /// What the deadline arm's cancellation attempt produced.
        ///
        /// The receipt is the only proof a cancellation was attempted and what
        /// it achieved, so it is retained whenever the executor answered. An
        /// unanswered cancellation is its own state, not the same as never
        /// having tried and not a clean stop.
        ///
        /// Boxed so the typed error stays small enough to return by value from
        /// every call site without an allocation on the success path.
        cancellation: Box<CancellationOutcome>,
        /// What the post-deadline stream readback produced.
        ///
        /// `Observed` carries the provider's real stdout/stderr; `Unobserved`
        /// means the readback was attempted and did not answer, and
        /// `NotAttempted` that it was never reached. Neither of those two is
        /// ever rendered as the digest or byte count of an actually empty
        /// stream, so missing evidence and empty evidence stay different.
        evidence: Box<EvidenceObservation>,
        /// Bounded secondary obligations this timeout could not discharge.
        ///
        /// The deadline is the one primary cause. A cancellation or a stream
        /// readback that failed while the deadline was being reported is
        /// recorded here as its own typed refusal rather than replacing the
        /// timeout, discarding a receipt already obtained, or multiplying the
        /// terminal event. At most two obligations exist, so this is bounded by
        /// construction. Empty when both follow-up attempts succeeded.
        undischarged: Vec<UndischargedObligation>,
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
    #[error("executor start did not return a verified receipt; reconcile by operation identity")]
    StartFailed {
        /// Exact operation binding retained across the possible handoff.
        context: Box<StartAttemptContext>,
        /// Typed executor refusal; the operation may still exist.
        #[source]
        source: Box<eliot_process::ProcessExecutionError>,
    },
    #[error(
        "executor start receipt did not preserve the bound request; reconcile by operation identity"
    )]
    StartReceiptMismatch {
        /// Exact operation binding retained across the possible handoff.
        context: Box<StartAttemptContext>,
    },
    #[error("runner could not retain the verified start binding: {reason}")]
    StartBindingInstallFailed {
        /// Exact operation binding retained across the possible handoff.
        context: Box<StartAttemptContext>,
        /// Stable lock failure reason.
        reason: &'static str,
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
            | Self::StartFailed { .. }
            | Self::StartReceiptMismatch { .. }
            | Self::StartBindingInstallFailed { .. }
            | Self::StreamReadbackFailed { .. }
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
            Self::EvidenceIncomplete { .. } | Self::StreamReadbackFailed { .. } => {
                eliot_kernel_service::REASON_INSTRUMENT_EVIDENCE_INCOMPLETE
            }
            Self::UnknownOutcome { .. }
            | Self::StartFailed { .. }
            | Self::StartReceiptMismatch { .. }
            | Self::StartBindingInstallFailed { .. } => {
                eliot_kernel_service::REASON_UNKNOWN_OUTCOME
            }
        }
    }

    /// Returns the retained cancellation receipt fragment, when the executor
    /// answered the cancellation.
    ///
    /// A timeout whose cancellation was never answered returns `None` here, and
    /// that is exactly what distinguishes it: the receipt is absent because no
    /// receipt exists, not because no cancellation was attempted. The
    /// attempt itself stays visible through [`BridgeError::cancellation_state`].
    #[must_use]
    pub fn cancellation(&self) -> Option<&CancellationEvidence> {
        match self {
            Self::TimedOut { cancellation, .. } => cancellation.receipt(),
            _ => None,
        }
    }

    /// Returns what this failure's cancellation attempt actually produced,
    /// including an attempt the executor never answered.
    ///
    /// This is the only accessor that distinguishes "no cancellation was
    /// attempted" from "a cancellation was attempted and proved nothing".
    #[must_use]
    pub const fn cancellation_state(&self) -> Option<&CancellationOutcome> {
        match self {
            Self::TimedOut { cancellation, .. } => Some(cancellation),
            _ => None,
        }
    }

    /// Returns the bounded secondary obligations the primary cause could not
    /// discharge.
    ///
    /// A deadline overrun records an unanswered cancellation or an unanswered
    /// stream readback here rather than letting either replace the timeout.
    /// Transport failures on other variants have no such obligation, so this is
    /// empty for them.
    #[must_use]
    pub fn undischarged(&self) -> &[UndischargedObligation] {
        match self {
            Self::TimedOut { undischarged, .. } => undischarged,
            _ => &[],
        }
    }

    /// Returns the immutable raw evidence, when it was materialized before the
    /// failure was classified.
    ///
    /// A deadline overrun and a malformed provider wire both read the
    /// executor's captured streams back before they classify, so a timed-out or
    /// unanswerable provider's real stdout/stderr/exit/lineage are retained on
    /// exactly the same footing as an unclassifiable terminal state. `None` here
    /// never means "the provider produced nothing": the stream's own absence
    /// state is carried by [`BridgeError::evidence_observation`], and an absent
    /// record is rendered as an explicit gap rather than as an empty capture.
    #[must_use]
    pub fn evidence(&self) -> Option<&RawProviderEvidence> {
        match self {
            Self::UnknownOutcome { evidence } | Self::ProtocolViolation { evidence, .. } => {
                evidence.as_deref()
            }
            Self::TimedOut { evidence, .. } => evidence.observed(),
            _ => None,
        }
    }

    /// Returns how this failure's stream readback resolved, so a consumer can
    /// tell a not-attempted readback from one that was attempted and never
    /// answered.
    ///
    /// Variants that never read streams back report
    /// [`EvidenceObservation::NotAttempted`]: the readback was genuinely not
    /// reached, which is an honest statement rather than an empty stream.
    #[must_use]
    pub fn evidence_observation(&self) -> EvidenceObservation {
        match self {
            Self::TimedOut { evidence, .. } => evidence.as_ref().clone(),
            Self::ProtocolViolation {
                evidence: Some(evidence),
                ..
            }
            | Self::UnknownOutcome {
                evidence: Some(evidence),
            } => EvidenceObservation::Observed(evidence.clone()),
            Self::StreamReadbackFailed { .. } => EvidenceObservation::Unobserved,
            _ => EvidenceObservation::NotAttempted,
        }
    }

    /// Returns the provider's observed process disposition when this failure
    /// carries one separately from protocol validity.
    ///
    /// A provider that exited cleanly and answered with a wire this bridge does
    /// not accept is both a completed process and a protocol violation; only
    /// this accessor keeps the two facts from collapsing into one.
    #[must_use]
    pub const fn process_disposition(&self) -> Option<ProviderOutcome> {
        match self {
            Self::ProtocolViolation { disposition, .. }
            | Self::StreamReadbackFailed { disposition, .. } => *disposition,
            _ => None,
        }
    }

    /// Returns the exact operation context retained before executor start,
    /// when the start handoff or receipt failed.
    #[must_use]
    pub fn start_attempt_context(&self) -> Option<&StartAttemptContext> {
        match self {
            Self::StartFailed { context, .. }
            | Self::StartReceiptMismatch { context }
            | Self::StartBindingInstallFailed { context, .. } => Some(context),
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

    fn classify(error: &Self::Error) -> ExternalKnowledgeFailure {
        // Exhaustive by design: a timeout, a crash, an unavailable source and an
        // unknown provider outcome must stay distinct on the way into the
        // exchange, so every outcome this error type distinguishes keeps its own
        // external-knowledge value and no catch-all arm may re-collapse them.
        match error {
            // An invalid bridge identity never reached a provider, and this crate
            // already classifies it as the same source-unavailable gap an absent
            // provider is, so it folds into that outcome rather than inventing an
            // external-knowledge meaning it does not have, so the
            // RESEARCH_SOURCE_UNAVAILABLE disposition is reachable for both.
            BridgeError::InvalidBridgeIdentity { .. } | BridgeError::ProviderUnavailable => {
                ExternalKnowledgeFailure::SourceUnavailable
            }
            // The retained cancellation receipt stays with this error; only the
            // outcome is projected.
            BridgeError::TimedOut { .. } => ExternalKnowledgeFailure::TimedOut,
            BridgeError::ProviderFailed { reason } => {
                ExternalKnowledgeFailure::ProviderFailed { reason }
            }
            BridgeError::NotAdmitted { reason } => ExternalKnowledgeFailure::NotAdmitted { reason },
            // Only the reason is projected; the retained evidence and the
            // provider's observed process disposition stay with this error.
            BridgeError::ProtocolViolation { reason, .. } => {
                ExternalKnowledgeFailure::ProtocolViolation { reason }
            }
            BridgeError::EvidenceIncomplete { reason } => {
                ExternalKnowledgeFailure::EvidenceIncomplete { reason }
            }
            BridgeError::StreamReadbackFailed { .. } => {
                ExternalKnowledgeFailure::EvidenceIncomplete {
                    reason: "executor stream readback did not answer",
                }
            }
            // The retained raw provider evidence stays with this error so a
            // reconcile reuses the same bytes; only the outcome is projected.
            BridgeError::UnknownOutcome { .. }
            | BridgeError::StartFailed { .. }
            | BridgeError::StartReceiptMismatch { .. }
            | BridgeError::StartBindingInstallFailed { .. } => {
                ExternalKnowledgeFailure::UnknownOutcome
            }
            BridgeError::Process(_) => ExternalKnowledgeFailure::ProcessFailed,
        }
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
    /// The provider's observed process disposition, kept separate from the
    /// failure's protocol classification.
    ///
    /// A provider can complete its process and still answer with a wire this
    /// bridge refuses. `outcome` above is the submitted-state classification of
    /// the attempt; this is the physical disposition that was actually observed,
    /// so neither fact has to be inferred from the other.
    observed_disposition: Option<ProviderOutcome>,
    /// The exact operation identity this attempt bound, retained whether or not
    /// the start response was received.
    ///
    /// A start-response loss leaves an operation that may exist in the executor
    /// registry. Naming it here is what makes that attempt resolvable by its
    /// stable identity instead of being reported as an attempt that never
    /// happened — and it is explicitly not permission to mint a new one.
    operation_id: Option<String>,
    /// Exact pre-handoff operation context when start did not produce a
    /// verified receipt. Retained here after the typed start failure returns.
    start_attempt: Option<StartAttemptContext>,
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
    /// Typed cancellation disposition, including an attempted cancellation
    /// whose receipt never arrived.
    pub cancellation_outcome: CancellationOutcome,
    /// How this failure's stream readback resolved.
    ///
    /// Retained so a consumer can tell a stream that was never read back from
    /// one whose readback was attempted and never answered, and from one that
    /// really was observed empty. [`TerminalFailure::evidence`] alone cannot
    /// carry that distinction, and rendering a missing readback as an empty
    /// capture would be exactly the false observation these repairs remove.
    pub evidence_observation: EvidenceObservation,
    /// Which bounded follow-up obligations the primary cause could not
    /// discharge, in attempt order.
    ///
    /// Each names the obligation only; the typed refusals stay on the
    /// `BridgeError` this record was projected from. Empty when the failure was
    /// not a deadline overrun, or when every follow-up attempt succeeded.
    pub undischarged: Vec<Obligation>,
}

impl TerminalFailure {
    /// Projects one typed bridge failure into its cloneable terminal record.
    #[must_use]
    pub fn from_error(error: &BridgeError) -> Self {
        let outcome = match error {
            BridgeError::TimedOut { .. } => ProviderOutcome::TimedOut,
            BridgeError::UnknownOutcome { .. }
            | BridgeError::StartFailed { .. }
            | BridgeError::StartReceiptMismatch { .. }
            | BridgeError::StartBindingInstallFailed { .. }
            | BridgeError::StreamReadbackFailed { .. } => ProviderOutcome::Unknown,
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
            evidence_observation: error.evidence_observation(),
            cancellation_outcome: error
                .cancellation_state()
                .cloned()
                .unwrap_or(CancellationOutcome::NotAttempted),
            undischarged: error
                .undischarged()
                .iter()
                .map(|obligation| obligation.obligation)
                .collect(),
        }
    }

    /// Builds the terminal record of a classified terminal outcome that left no
    /// `BridgeError` behind.
    ///
    /// `ProviderBridge::execute` returns `Ok` for every terminal state it could
    /// classify, so a crashed, cancelled, timed-out or unknown provider reaches
    /// this path with no error to project. The reason code and coverage gap come
    /// from the crate's own `BridgeError` vocabulary through the same
    /// `reason_code`/`coverage_gap_kind` pair, so an outcome is never reported
    /// under a second, privately chosen classification.
    #[must_use]
    pub fn outcome_degradation(
        outcome: ProviderOutcome,
        cancellation: Option<&CancellationEvidence>,
    ) -> Self {
        let reason_code = match outcome {
            // Both a clean terminal classification and a crash-class
            // classification are a runtime failure of the provider process, so
            // they share the one runtime-failure code the vocabulary defines.
            ProviderOutcome::Completed | ProviderOutcome::Crashed => {
                eliot_kernel_service::REASON_RUNTIME_FAILED
            }
            ProviderOutcome::TimedOut => eliot_kernel_service::REASON_DEADLINE_EXCEEDED,
            ProviderOutcome::Cancelled => eliot_kernel_service::REASON_CANCELLATION_UNCONFIRMED,
            ProviderOutcome::Unknown => eliot_kernel_service::REASON_UNKNOWN_OUTCOME,
        };
        let coverage_gap = match outcome {
            ProviderOutcome::TimedOut => CoverageGapKind::Timeout,
            ProviderOutcome::Crashed
            | ProviderOutcome::Cancelled
            | ProviderOutcome::Unknown
            | ProviderOutcome::Completed => CoverageGapKind::Unknown,
        };
        Self {
            reason_code,
            coverage_gap,
            outcome,
            evidence: None,
            cancellation: cancellation.cloned(),
            // This path is reached only when `execute` returned `Ok`, so no
            // failed readback is being projected here. The final receipt gets
            // the successful stream observation directly from the execution.
            evidence_observation: EvidenceObservation::NotAttempted,
            cancellation_outcome: cancellation
                .map_or(CancellationOutcome::NotAttempted, |receipt| {
                    CancellationOutcome::Confirmed(Box::new(receipt.clone()))
                }),
            undischarged: Vec::new(),
        }
    }
}

/// The exact typed acquisition-coverage degradation one failed provider attempt
/// produced.
///
/// A13.11 and I21.13 make the *scope* of a provider failure the whole point: a
/// local capability degrades, the Kernel and independent work survive, and
/// dependent work continues with a narrower declared coverage. This record is
/// therefore the degradation itself rather than a claim about it, and it is the
/// only thing this process may report for a run that failed.
///
/// It cannot stand in for the material it did not obtain. The type is `Copy`
/// over closed vocabularies and has no field for a result, a candidate digest,
/// a source handle, a State Fence, an authority epoch or a finish, so there is
/// no way to read a degradation as an answer or as an admitted finding. It
/// cannot be a Researcher semantic failure either: it is built only from a
/// [`TerminalFailure`] — the retained projection of a [`BridgeError`] — so a
/// degradation exists exactly when a provider attempt failed and never as a way
/// of stating a verdict about the question.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub struct AcquisitionCoverageDegradation {
    /// Typed coverage-gap kind, taken from the bridge's own closed error
    /// vocabulary rather than from a second local classification.
    pub coverage_gap: CoverageGapKind,
    /// Exact I7.20 reason code for the terminal disposition.
    pub reason_code: &'static str,
    /// Provider-local terminal outcome this degradation classifies. This is
    /// acquisition evidence, never a semantic verdict and never task finish.
    pub outcome: ProviderOutcome,
    /// The typed I21.11 source-gap outcome the dependent inquiry records, or
    /// `None` when this gap is not one of the two named source gaps.
    ///
    /// The absence is load-bearing: a deadline overrun, a policy denial, an
    /// exhausted budget and an unclassifiable outcome are each their own
    /// disposition, and coercing any of them into `RESEARCH_SOURCE_UNAVAILABLE`
    /// would claim a source could not be fetched when the retained evidence
    /// does not say that.
    pub inquiry_outcome: Option<ResearchSourceGapOutcome>,
}

impl AcquisitionCoverageDegradation {
    /// Returns the exact I21.11 wire name a dependent inquiry records for this
    /// degradation, or `None` when the gap is not one of the two named source
    /// gaps.
    #[must_use]
    pub const fn inquiry_reason_code(self) -> Option<&'static str> {
        match self.inquiry_outcome {
            Some(outcome) => Some(outcome.wire_name()),
            None => None,
        }
    }
}

/// Converts one failed or unavailable provider attempt into the exact typed
/// acquisition-coverage degradation this process reports.
///
/// This is the crate's single conversion from "the provider did not deliver" to
/// "acquisition coverage narrows, and only that". Every consumer of a failed run
/// reads it: the terminal receipt's outcome and reason code, the degraded
/// disposition the binary exits with, and the `I21.11` outcome the dependent
/// inquiry records all come from here, so a degradation can neither be
/// fabricated for a run that succeeded nor be replaced by a second, privately
/// chosen classification of the same failure.
///
/// The mapping reuses the vocabularies the contract already defines and invents
/// none. The coverage-gap kind and the reason code arrive through the retained
/// [`TerminalFailure`], which [`TerminalFailure::from_error`] built from
/// [`BridgeError::coverage_gap_kind`] and [`BridgeError::reason_code`]; the
/// inquiry outcome is the exchange contract's own [`ResearchSourceGapOutcome`],
/// so an unavailable source keeps its `RESEARCH_SOURCE_UNAVAILABLE` spelling and
/// an unverifiable generation or index keeps `INCOMPLETE_COVERAGE`:
///
/// ```text
/// source that cannot be fetched        -> RESEARCH_SOURCE_UNAVAILABLE
/// source generation/index not verified -> INCOMPLETE_COVERAGE
/// ```
///
/// The `R6` domain binds that code into the terminal inquiry record together
/// with the preserved explicit unknown and the preserved next probe, so a
/// narrowed coverage is recorded as a narrowed coverage. Every other
/// acquisition reason keeps the receipt's own classification: a timeout is not
/// an unfetchable source, a policy denial is not incomplete coverage, and an
/// exhausted budget is neither, so none of them is coerced into one of the two
/// named gaps. The acquisition outcome itself stays the receipt's: this process
/// reports what the provider run did, and the inquiry records why its coverage
/// narrowed.
///
/// An absent failure is not an answer either. A submit refused before the
/// executor was contacted has no retained terminal classification, and it is
/// reported as the explicit `UNKNOWN_OUTCOME` disposition with an unknown
/// acquisition outcome — never as a completion, never as an absence of
/// findings, and never as a source that could not be fetched.
pub fn acquisition_coverage_degradation(
    failure: Option<&TerminalFailure>,
) -> AcquisitionCoverageDegradation {
    let (reason_code, coverage_gap, outcome) = match failure {
        Some(terminal) => (
            terminal.reason_code,
            terminal.coverage_gap,
            terminal.outcome,
        ),
        None => (
            eliot_kernel_service::REASON_UNKNOWN_OUTCOME,
            CoverageGapKind::Unknown,
            ProviderOutcome::Unknown,
        ),
    };
    let inquiry_outcome = match coverage_gap {
        CoverageGapKind::SourceUnavailable => {
            Some(ResearchSourceGapOutcome::ResearchSourceUnavailable)
        }
        CoverageGapKind::StaleSourceOrIndex => Some(ResearchSourceGapOutcome::IncompleteCoverage),
        _ => None,
    };
    AcquisitionCoverageDegradation {
        coverage_gap,
        reason_code,
        outcome,
        inquiry_outcome,
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

/// Bounded identity and sealed submit retained across the executor-start
/// handoff when no verified start receipt is returned.
///
/// This is carried on the existing bridge error/submitted-state path. It is
/// not a second operation ledger: the operation identity and request digest
/// come from the exact `ProcessRequest` passed to `ProcessExecutor::start`.
#[derive(Clone, Debug)]
pub struct StartAttemptContext {
    /// Stable identity taken from the admitted `ProcessRequest`.
    pub operation_id: OperationId,
    /// Exact invocation digest taken from that same request.
    pub invocation_digest: String,
    /// Process generation accepted by the request.
    pub process_generation: u64,
    /// Exact canonical submit record sealed before handoff.
    pub submission: SubmissionRecord,
}

/// Terminal record of one submitted attempt.
///
/// This is the bridge's own retained classification of what the provider run
/// did. A crashed, cancelled, timed-out or unclassifiable attempt reaches a
/// terminal state that is not a completion, and the terminal receipt has to
/// carry that exact state rather than a locally chosen success label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmittedOutcome {
    /// A clean completed exit with a zero code and proven tree closure.
    Completed,
    /// A non-zero exit or a crash-class disposition.
    Crashed,
    /// The terminal wait exceeded the deadline.
    TimedOut,
    /// Cancellation stopped the tree.
    Cancelled,
    /// The terminal state could not be classified from local evidence.
    Unknown,
    /// The attempt failed at or after the executor and keeps no finer
    /// classification; it is still crash-class acquisition evidence, never a
    /// clean stop and never a fabricated completion.
    Refused,
}

impl SubmittedOutcome {
    /// Returns whether this outcome requires reconciliation before any retry.
    /// A fresh admission is required regardless; this flag additionally opens
    /// the `reconcile` path.
    const fn requires_reconciliation(self) -> bool {
        matches!(self, Self::TimedOut | Self::Unknown)
    }

    /// Returns the provider-local outcome this retained classification carries.
    ///
    /// `Refused` is crash-class acquisition evidence: the attempt reached the
    /// executor or its contour, so it is never reported as a completion.
    #[must_use]
    pub const fn provider_outcome(self) -> ProviderOutcome {
        match self {
            Self::Completed => ProviderOutcome::Completed,
            Self::Crashed
            // An unclassifiable terminal state and a refusal that reached the
            // executor are both crash-class acquisition evidence: neither is a
            // completion, and neither stays a locally invented label.
            | Self::Unknown
            | Self::Refused => ProviderOutcome::Crashed,
            Self::TimedOut => ProviderOutcome::TimedOut,
            Self::Cancelled => ProviderOutcome::Cancelled,
        }
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

    /// Returns the retained terminal classification of this attempt.
    ///
    /// The terminal receipt carries this value verbatim. A submit that reached
    /// a terminal executor state is not a completion by virtue of succeeding
    /// as a Rust call, so the caller reads what the run actually did here
    /// instead of choosing a label of its own. `None` only before the executor
    /// has been contacted, where no terminal state exists.
    #[must_use]
    pub fn last_outcome(&self) -> Option<SubmittedOutcome> {
        self.submitted().map(|state| state.outcome)
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

    /// Returns the exact operation identity this attempt bound, when one was
    /// sealed.
    ///
    /// A start-response loss leaves an operation that may exist in the executor
    /// registry, and this is the identity that names it. It is custody, not a
    /// retry permit: the phase has already moved to submitted, so no fresh
    /// admission is implied by reading it.
    #[must_use]
    pub fn last_operation_id(&self) -> Option<&str> {
        self.submitted()
            .and_then(|state| state.operation_id.as_deref())
    }

    /// Returns the provider's observed process disposition, kept separate from
    /// the protocol's validity.
    ///
    /// A provider whose process completed cleanly while answering with a
    /// malformed wire reports `Completed` here and `Refused` from
    /// [`AdmittedResearchBridge::last_outcome`]. Neither fact is derived from
    /// the other.
    #[must_use]
    pub fn last_observed_disposition(&self) -> Option<ProviderOutcome> {
        self.submitted()
            .and_then(|state| state.observed_disposition)
    }

    /// Returns how this attempt's stream readback resolved.
    ///
    /// This is the accessor the final receipt uses to tell an observed stream
    /// from one that was never read back or whose readback never answered.
    /// Reporting an empty capture for any of those would be a false
    /// observation, so the receipt renders the gap explicitly instead.
    #[must_use]
    pub fn last_evidence_observation(&self) -> Option<&EvidenceObservation> {
        self.submitted()
            .and_then(|state| state.failure.as_ref())
            .map(|failure| &failure.evidence_observation)
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
        let (operation, digest) = self.retained_attempt_binding()?;
        // Adoption is a lifecycle operation on a physical process, so it carries
        // the same ownership proof as a cancel: the runner compares the stored
        // record against this attempt's sealed digest, the admitted generation,
        // epoch and artifact before the executor is asked to reconcile it.
        let evidence = self
            .runner
            .reconcile_operation(&self.admission, &operation, &digest)?;
        if let BridgePhase::Submitted(state) = &mut self.phase {
            state.reconciled = true;
        }
        Ok(evidence)
    }

    /// Returns the exact operation identity and sealed invocation digest this
    /// submitted attempt is bound to.
    ///
    /// This is the same retained attempt/evidence owner the cancel path reads:
    /// the [`StartAttemptContext`] when the executor handoff was reached, and
    /// otherwise the sealed submit envelope's own digest, which is decoded from
    /// the recorded bytes rather than assumed. Reconciliation keys on this pair,
    /// never on the operation name alone.
    fn retained_attempt_binding(&self) -> Result<(OperationId, String), BridgeError> {
        let state = self.submitted().ok_or(BridgeError::NotAdmitted {
            reason: "no submitted attempt owns the operation",
        })?;
        if let Some(context) = &state.start_attempt {
            return Ok((
                context.operation_id.clone(),
                context.invocation_digest.clone(),
            ));
        }
        let submission = state.submission.as_ref().ok_or(BridgeError::NotAdmitted {
            reason: "submitted attempt has no sealed operation binding",
        })?;
        let envelope = SubmitEnvelope::decode(&submission.envelope_bytes).map_err(|_| {
            BridgeError::NotAdmitted {
                reason: "submitted attempt has no decodable operation binding",
            }
        })?;
        if envelope.operation_id != self.admission.operation_id().as_str() {
            return Err(BridgeError::NotAdmitted {
                reason: "sealed submit targets a foreign operation",
            });
        }
        Ok((
            self.admission.operation_id().clone(),
            envelope.invocation_digest,
        ))
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
                // The provider-local disposition is retained before it is
                // mapped into the submitted-state classification, so the two
                // remain separately readable.
                let observed = execution.outcome;
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
                    observed_disposition: Some(observed),
                    operation_id: Some(execution.job_id.clone()),
                    start_attempt: None,
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
                    BridgeError::UnknownOutcome { .. }
                    | BridgeError::StartFailed { .. }
                    | BridgeError::StartReceiptMismatch { .. }
                    | BridgeError::StartBindingInstallFailed { .. }
                    | BridgeError::StreamReadbackFailed { .. } => SubmittedOutcome::Unknown,
                    BridgeError::ProviderFailed { .. }
                    | BridgeError::EvidenceIncomplete { .. }
                    | BridgeError::ProtocolViolation { .. }
                    | BridgeError::Process(_) => SubmittedOutcome::Refused,
                    BridgeError::NotAdmitted { .. }
                    | BridgeError::ProviderUnavailable
                    | BridgeError::InvalidBridgeIdentity { .. } => return Err(error),
                };
                // The evidence, the cancellation receipt and the bound
                // operation identity are all retained here. The previous arm set
                // `evidence: None`, which threw away the stderr/exit/lineage
                // record for exactly the two terminal cases that most need it,
                // and it left a start-response loss looking like an attempt that
                // was never made. A failed start carries its sealed context
                // directly; later failures use runner fields installed after
                // the receipt passed binding checks. Either way the
                // possibly-started operation stays addressable by its original
                // identity.
                let start_attempt = error.start_attempt_context().cloned();
                let submission = start_attempt
                    .as_ref()
                    .map(|context| context.submission.clone())
                    .or_else(|| self.runner.last_submission());
                let operation_id = start_attempt
                    .as_ref()
                    .map(|context| context.operation_id.as_str().to_owned())
                    .or_else(|| self.runner.last_bound_operation());
                self.phase = BridgePhase::Submitted(Box::new(SubmittedState {
                    outcome: terminal,
                    evidence: error.evidence().cloned(),
                    provider_job_ref: None,
                    cancellation: error.cancellation().cloned(),
                    submission,
                    failure: Some(TerminalFailure::from_error(&error)),
                    reconciled: false,
                    observed_disposition: error.process_disposition(),
                    operation_id,
                    start_attempt,
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
            // identity, request digest, Authority Epoch, and admitted artifact
            // digest. Cancelling by a bare job id would let a stale generation
            // or a retargeted request reach another operation's process tree.
            let (target_operation, expected_digest) = self.retained_attempt_binding()?;
            let receipt = self.runner.cancel_operation(
                &self.admission,
                &target_operation,
                &expected_digest,
            )?;
            if let BridgePhase::Submitted(state) = &mut self.phase {
                state.cancellation = Some(CancellationEvidence::from_receipt(&receipt));
            }
            return Ok(());
        }
        Err(BridgeError::NotAdmitted {
            reason: "nothing was attempted through the executor yet",
        })
    }

    fn classify(error: &Self::Error) -> ExternalKnowledgeFailure {
        // Exhaustive by design: a timeout, a crash, an unavailable source and an
        // unknown provider outcome must stay distinct on the way into the
        // exchange, so every outcome this error type distinguishes keeps its own
        // external-knowledge value and no catch-all arm may re-collapse them.
        // Identical to `GovernedResearchBridge` because both bridges report the
        // same `BridgeError`; it is repeated rather than shared so neither impl
        // can be silently narrowed by the other.
        match error {
            // An invalid bridge identity never reached a provider, and this crate
            // already classifies it as the same source-unavailable gap an absent
            // provider is, so it folds into that outcome rather than inventing an
            // external-knowledge meaning it does not have, so the
            // RESEARCH_SOURCE_UNAVAILABLE disposition is reachable for both.
            BridgeError::InvalidBridgeIdentity { .. } | BridgeError::ProviderUnavailable => {
                ExternalKnowledgeFailure::SourceUnavailable
            }
            // The retained cancellation receipt stays with this error; only the
            // outcome is projected.
            BridgeError::TimedOut { .. } => ExternalKnowledgeFailure::TimedOut,
            BridgeError::ProviderFailed { reason } => {
                ExternalKnowledgeFailure::ProviderFailed { reason }
            }
            BridgeError::NotAdmitted { reason } => ExternalKnowledgeFailure::NotAdmitted { reason },
            // Only the reason is projected; the retained evidence and the
            // provider's observed process disposition stay with this error.
            BridgeError::ProtocolViolation { reason, .. } => {
                ExternalKnowledgeFailure::ProtocolViolation { reason }
            }
            BridgeError::EvidenceIncomplete { reason } => {
                ExternalKnowledgeFailure::EvidenceIncomplete { reason }
            }
            BridgeError::StreamReadbackFailed { .. } => {
                ExternalKnowledgeFailure::EvidenceIncomplete {
                    reason: "executor stream readback did not answer",
                }
            }
            // The retained raw provider evidence stays with this error so a
            // reconcile reuses the same bytes; only the outcome is projected.
            BridgeError::UnknownOutcome { .. }
            | BridgeError::StartFailed { .. }
            | BridgeError::StartReceiptMismatch { .. }
            | BridgeError::StartBindingInstallFailed { .. } => {
                ExternalKnowledgeFailure::UnknownOutcome
            }
            BridgeError::Process(_) => ExternalKnowledgeFailure::ProcessFailed,
        }
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

/// Spelling of a release gate that admitted this run's material claims.
///
/// I21.8 item 6: a claim may be promoted only when every required chain, excerpt
/// and audit dimension is established. The gate answer is published on the
/// governance line so a consumer reads the decision rather than having to
/// re-derive it, and so an absent gate is visibly absent.
pub const RELEASE_GATE_ADMITTED: &str = "admitted";

/// Spelling of a release gate that refused to promote this run's material
/// claims, followed by the specific member or condition that refused it.
pub const RELEASE_GATE_BLOCKED: &str = "blocked";

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
/// This is the validating edge between acquisition and admissibility, so it
/// proves the binding before it derives anything. `admission.validate_request`
/// re-proves the request/admission binding over fence, bridge generation,
/// privacy class, budget, deadline, protocol revision, required schema and
/// coverage goal, and the receipt is then required to be *this* admitted
/// operation's receipt — same operation identity, module generation, executable
/// digest, process generation, privacy class, inquiry digest and denominator
/// digest, with a well-formed Kernel dispatch digest and admission-receipt digest
/// present. The candidate's `route` and `provider_generation` are read straight
/// off the receipt, so an unbound receipt would otherwise mint provenance out of
/// unverified fields. A provider's own `candidate_sha256` and its `Completed`
/// label are read nowhere here: I21.11 keeps endpoint reachability, a successful
/// login and a self-reported result from establishing ELIOT authority.
///
/// `failure` is the bridge's retained typed terminal classification. It is what
/// carries the acquisition coverage gap this run actually suffered, so the
/// dependent inquiry records the two named `I21.11` outcomes
/// (`RESEARCH_SOURCE_UNAVAILABLE`, `INCOMPLETE_COVERAGE`) instead of a generic
/// acquisition code, and the `R6` domain keeps that inquiry open with its
/// preserved explicit unknown and next probe.
///
/// # Errors
///
/// Returns [`R6ProjectionError::UnboundAdmission`] when the admitted request and
/// the terminal receipt do not bind the same operation, exchange, budget or
/// deadline, when the receipt is not the receipt of the admitted operation's
/// Kernel dispatch, or when the admitted request and the admission disagree on
/// any bound dimension; and [`R6ProjectionError::Domain`] when the `R6` domain
/// refuses the admitted material. Neither variant changes the provider receipt
/// or this process's exit code: the refusal is reported on the evidence stream.
pub fn project_admitted_inquiry(
    request: &ResearchQueryRequest,
    admission: &ProviderAdmission,
    receipt: &ProviderExecutionReceipt,
    failure: Option<&TerminalFailure>,
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
    // The request/admission binding is re-proved here, on the edge that turns
    // retained material into an inquiry candidate.
    // `ProviderAdmission::validate_request` is the crate's exact binding over
    // fence, bridge generation, disclosure, budget, deadline, protocol revision,
    // required schema and coverage goal; the executor applies it before a
    // provider starts, but this governance projection is a second, later use of
    // the same request, and a projection that skipped the check would let
    // material assessed under one binding be published under another.
    admission.validate_request(request).map_err(|error| {
        crate::R6ProjectionError::UnboundAdmission {
            reason: error.reason(),
        }
    })?;
    // The receipt is custody of *this* admitted operation. Without these, a
    // receipt naming a foreign module generation, a foreign executable digest,
    // a foreign process generation, a wider privacy class, a different inquiry
    // or denominator, or no Kernel dispatch at all, would still produce a
    // candidate source and an admissibility decision: the `route` below and
    // `provider_generation` on every candidate are read straight off the
    // receipt, so an unbound receipt would mint provenance out of unverified
    // fields. `ProviderExecutionReceipt::candidate_sha256` is a provider's own
    // claim and proves nothing, which is why it is not read here.
    if receipt.module_generation_id != admission.module_generation_id().as_str()
        || receipt.executable_sha256 != admission.bridge().executable_sha256()
        || receipt.process_generation != admission.process_generation().get()
        || receipt.disclosure != admitted_disclosure_wire(admission.disclosure())
        || receipt.inquiry_digest != admission.inquiry_digest()
        || receipt.denominator_digest != admission.denominator_digest()
        || receipt.operation_id != admission.operation_id().as_str()
    {
        return Err(crate::R6ProjectionError::UnboundAdmission {
            reason: "terminal receipt is not the receipt of the admitted operation",
        });
    }
    if !is_lowercase_sha256(&receipt.dispatch_sha256)
        || !is_lowercase_sha256(&receipt.admission_receipt_sha256)
    {
        return Err(crate::R6ProjectionError::UnboundAdmission {
            reason: "terminal receipt carries no verifiable Kernel dispatch or admission receipt",
        });
    }
    let assessment_time_ms = i64::try_from(dispatch_authority::unix_ms()).unwrap_or(i64::MAX);
    let route = format!(
        "{}@{}",
        receipt.module_generation_id, receipt.executable_sha256
    );
    // The acquisition-coverage degradation this run suffered is read from the
    // crate's single named conversion rather than re-derived here. A dependent
    // inquiry therefore records the same typed gap the provider receipt and the
    // degraded disposition were built from, and it records one of the two named
    // I21.11 outcomes exactly when the failure was that gap. Every other
    // acquisition reason keeps the receipt's own classification, so a timeout
    // is not an unfetchable source, a policy denial is not incomplete coverage,
    // and an exhausted budget is neither.
    let degradation = acquisition_coverage_degradation(failure);
    // W2 (`#1765`): this projection carries the admitted request, the provider
    // admission and the terminal receipt — and no retained source bytes. The
    // crate that owns the observation states that a handle absent from
    // `retained_revisions` is "a real finding rather than a skip", so the
    // honest value here is the EMPTY map: every excerpt offered from a source
    // this projection admitted then fails verification with
    // `NoRetainedRevision`, which is the truthful W2 outcome for a run that did
    // not persist before synthesis.
    //
    // It is deliberately NOT populated from the receipt, and no artifact
    // reference is invented: this subtree has no canonical-store write
    // authority, so a digest of bytes nobody holds is not a retained original.
    // The provider path that DOES persist before synthesis supplies this map
    // through the governed source-admission owner.
    let retained_revisions = std::collections::BTreeMap::new();
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
        candidates: retained_provider_material(request, receipt, &route)
            .into_iter()
            .collect(),
        retained_revisions,
        outcome: acquisition_outcome(receipt),
        reason_code: degradation
            .inquiry_reason_code()
            .unwrap_or(receipt.reason_code)
            .to_owned(),
        assessment_time_ms,
        // Read straight off the admitted request. `freeze_predecessor` in
        // `eliot_researcher::inquiry_governance` builds the successor relation
        // from exactly these two fields and invents neither, and
        // `ResearchQueryRequest::validate` refuses the half-present pair at the
        // exchange boundary, so a run admitted with a predecessor and a reason
        // produces a real successor freeze while a first freeze stays an honest
        // first freeze. The two move together off one source rather than being
        // decided here: a projection that could set one without the other would
        // be the only way to publish a relation the admitted request never
        // carried, which is exactly what the request-level refusal exists to
        // prevent.
        predecessor_freeze_digest: request.predecessor_freeze_digest.clone(),
        reopen_reason: request.reopen_reason.clone(),
    };
    InquiryGovernance::record(observation).map_err(crate::R6ProjectionError::from)
}

/// The Kernel's closed wire spelling of one admitted privacy class.
///
/// `ProviderExecutionReceipt::disclosure` carries the Kernel's own string
/// verbatim, because the receipt is custody of what the Kernel admitted and
/// rewriting it here would destroy that. The admitted `DisclosureClass` has to
/// be compared against it, so the same four spellings `admit` reads in
/// `main.rs` are read back out. This is the Kernel research-provider wire
/// vocabulary, not a second one of this crate's own: a new spelling here would
/// admit a privacy class the Kernel never sealed.
const fn admitted_disclosure_wire(class: DisclosureClass) -> &'static str {
    match class {
        DisclosureClass::Private => "Private",
        DisclosureClass::ProjectBound => "ProjectBound",
        DisclosureClass::ExportableRedacted => "ExportableRedacted",
        DisclosureClass::Public => "Public",
    }
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
) -> Option<CandidateEvidence> {
    let content_digest = receipt.raw.stdout.sha256.clone()?;
    let stream = match (receipt.raw.stdout.omission, receipt.raw.stdout.complete) {
        (Some(StreamOmission::NoHandle), _) => StreamEvidence::Absent,
        (None, true) => StreamEvidence::Complete,
        _ => StreamEvidence::Partial,
    };
    let receipt_handle = receipt.evidence_records.first().map_or_else(
        || receipt.raw.invocation_digest.clone(),
        |record| record.transport_sha256.clone(),
    );
    Some(CandidateEvidence {
        handle: format!("provider-artifact:{content_digest}"),
        class: request
            .source_classes
            .first()
            .copied()
            .unwrap_or(SourceClass::Unknown),
        operation_id: receipt.operation_id.clone(),
        content_digest,
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
    })
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
            "cancel-24-slice-a",
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
                root_context_revision: "root-24-slice-a".to_owned(),
                state_fence: test_fence(),
                source_handles: vec!["src-a".to_owned()],
                evidence_handles: Vec::new(),
                artifact_handles: Vec::new(),
                url_handles: Vec::new(),
                tool_refs: Vec::new(),
                verifier_refs: Vec::new(),
                allowed_anchor_precision: AnchorPrecision::Section,
                scope_class: "propulsion thermal envelope".to_owned(),
                disclosure: DisclosureClass::ProjectBound,
                retention_class: "governed-by-caller".to_owned(),
                stale_or_revoked_handles: Vec::new(),
                expansion_routes: Vec::new(),
                digest: String::new(),
            }
            .seal()
            .expect("test manifest must seal"),
            disclosure: DisclosureClass::ProjectBound,
            retention: "governed-by-caller".to_owned(),
            license_policy: "caller-policy".to_owned(),
            budget_units: 10,
            deadline_ms: 1_800_000_000_000,
            required_schema: "research-evidence-bundle/v1".to_owned(),
            predecessor_freeze_digest: None,
            reopen_reason: None,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use eliot_research_exchange_api::{CoverageGapKind, ExternalKnowledgeStage};

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
            matches!(
                result,
                Err(ExchangeError::ExternalKnowledge {
                    stage: ExternalKnowledgeStage::Submit,
                    failure: ExternalKnowledgeFailure::SourceUnavailable,
                })
            ),
            "bridge gap must surface as the provider's own unavailable-source outcome at the submit stage, without fabricating a job"
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
            BridgeError::ProtocolViolation {
                reason: "x",
                evidence: None,
                disposition: None,
            }
            .coverage_gap_kind(),
            CoverageGapKind::StaleSourceOrIndex
        );
        assert_eq!(
            BridgeError::TimedOut {
                cancellation: Box::new(super::execution::CancellationOutcome::Confirmed(Box::new(
                    super::evidence::CancellationEvidence {
                        operation_id: "op-24-slice-a".to_owned(),
                        request_digest: super::support::DIGEST_A.to_owned(),
                        status: "Requested".to_owned(),
                        lifecycle: "Running".to_owned(),
                        no_effect_proven: false,
                        descendants_complete: false,
                    },
                ))),
                evidence: Box::new(super::execution::EvidenceObservation::NotAttempted),
                undischarged: Vec::new(),
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
            matches!(
                result,
                Err(ExchangeError::ExternalKnowledge {
                    stage: ExternalKnowledgeStage::Submit,
                    failure: ExternalKnowledgeFailure::SourceUnavailable,
                })
            ),
            "absent process authority must surface as a typed unavailable-source gap at the submit stage, never a job"
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
