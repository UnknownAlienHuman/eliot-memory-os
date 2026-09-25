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
pub(crate) mod r6_consumer;
pub use r6_consumer::R6CompletionProjection;

use serde::{Deserialize, Serialize};

#[cfg(test)]
use eliot_contracts::StateFence;
use eliot_research_exchange::{
    CompletedEvidence, ExchangeError, ExchangeJob, ExchangeStatus, ResearchBridge,
    seal_completed_evidence,
};
use eliot_research_exchange_api::{CoverageGapKind, ResearchEvidenceBundle, ResearchQueryRequest};
use eliot_researcher::{
    GovernedInquiryError, InquiryGovernanceError, InquiryObligationInput,
    InquiryProtocolProfileParams, Researcher, TaskGraphCompilationReceipt,
};
use eliot_store_api::{TransitionClass, WriteReceiptStatus};
use eliot_task::{TaskError, TaskOwnerCapability};
use thiserror::Error;

pub use admission::{AdmissionRefusal, AdmittedProviderAdmission};
pub use evidence::{RawProviderEvidence, StreamOmission, StreamRecord, sha256_hex};
pub use execution::{
    BOUND_RUN_DEADLINE, ProviderBridge, ProviderExecution, ProviderOutcome, RequestPortError,
    ResearchRequestPort,
};
pub use protocol::{
    MAX_WIRE_BYTES, MAX_WIRE_LINES, RESEARCH_PROVIDER_WIRE_VERSION, ResultFrame, SubmitEnvelope,
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
            Self::ProviderFailed { .. }
            | Self::EvidenceIncomplete { .. }
            | Self::UnknownOutcome
            | Self::Process(_) => CoverageGapKind::Unknown,
        }
    }
}

/// Explicit immutable identity of one registered research provider bridge.
///
/// Both fields arrive from already-admitted material. Nothing here is read
/// from ambient environment, and identity alone grants no execution: the
/// Kernel-issued research admission that binds this identity to one exact
/// operation lands in [`ProviderAdmission`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
    #[allow(
        dead_code,
        reason = "diagnostic-only no-admission bridge retained for proof fixtures"
    )]
    pub(crate) fn new(identity: BridgeIdentity) -> Self {
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

    fn owner_capability(&self) -> Option<&TaskOwnerCapability> {
        None
    }

    fn submit(&mut self, _request: &ResearchQueryRequest) -> Result<String, Self::Error> {
        Err(BridgeError::ProviderUnavailable)
    }

    fn cancel(&mut self, _job_id: &str) -> Result<(), Self::Error> {
        Err(BridgeError::ProviderUnavailable)
    }

    fn accept_completed_bundle(
        &self,
        _request: &ResearchQueryRequest,
        _binding_digest: &str,
        _bundle: ResearchEvidenceBundle,
    ) -> Result<CompletedEvidence, Self::Error> {
        Err(BridgeError::ProviderUnavailable)
    }
}

/// Lifecycle phase of one admitted operation. One bridge serves exactly one
/// bounded operation: after any executor contact the operation is never
/// resubmitted blindly — unknown or timed-out outcomes must be reconciled by
/// the stable operation identity first, and every other outcome requires a
/// fresh admission for a fresh attempt.
#[derive(Clone, Debug)]
#[allow(
    dead_code,
    reason = "the live production owner caller is not wired in this bounded repair turn"
)]
#[allow(clippy::large_enum_variant)]
enum BridgePhase {
    /// Nothing was attempted through the executor yet.
    Awaiting,
    /// The executor was contacted; resubmission is refused.
    Submitted {
        /// Typed terminal outcome (or the failure that ended the attempt).
        outcome: SubmittedOutcome,
        /// Immutable raw evidence when the attempt reached materialization.
        evidence: Option<RawProviderEvidence>,
        /// Provider-local job reference when the ack decoded.
        provider_job_ref: Option<String>,
        /// Terminal result frame returned by the admitted provider process.
        result_frame: Option<crate::protocol::ResultFrame>,
        /// Whether an unknown outcome was reconciled since.
        reconciled: bool,
    },
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
    admission: AdmittedProviderAdmission,
    phase: BridgePhase,
}

impl AdmittedResearchBridge {
    /// Binds one admitted operation to the shared execution contour. Starts
    /// nothing; grants no execution until `submit`.
    #[must_use]
    #[allow(
        dead_code,
        reason = "the live production owner caller is not wired in this bounded repair turn"
    )]
    pub(crate) fn new(runner: ProviderBridge, admission: AdmittedProviderAdmission) -> Self {
        Self {
            runner,
            admission,
            phase: BridgePhase::Awaiting,
        }
    }

    /// Returns the bound admission.
    #[must_use]
    pub const fn admission(&self) -> &AdmittedProviderAdmission {
        &self.admission
    }

    /// Returns whether the executor has been contacted for this operation.
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

    /// Returns the provider-local job reference when the submit ack decoded.
    /// Correlation only: this reference is never canonical identity.
    #[must_use]
    pub const fn last_provider_job_ref(&self) -> Option<&String> {
        match &self.phase {
            BridgePhase::Awaiting => None,
            BridgePhase::Submitted {
                provider_job_ref, ..
            } => provider_job_ref.as_ref(),
        }
    }

    /// Returns the terminal result frame observed from the admitted provider
    /// process, if one was decoded.
    #[must_use]
    pub const fn last_result_frame(&self) -> Option<&crate::protocol::ResultFrame> {
        match &self.phase {
            BridgePhase::Awaiting => None,
            BridgePhase::Submitted { result_frame, .. } => result_frame.as_ref(),
        }
    }

    /// Accepts a candidate only when the exact terminal provider frame names
    /// it, then returns the exchange's opaque completion seal.
    pub(crate) fn accept_completed_bundle(
        &self,
        request: &ResearchQueryRequest,
        binding_digest: &str,
        bundle: ResearchEvidenceBundle,
    ) -> Result<CompletedEvidence, BridgeError> {
        self.admission
            .validate_request(request)
            .map_err(|refusal| BridgeError::NotAdmitted {
                reason: refusal.reason(),
            })?;
        let BridgePhase::Submitted {
            outcome: SubmittedOutcome::Completed,
            result_frame: Some(frame),
            ..
        } = &self.phase
        else {
            return Err(BridgeError::EvidenceIncomplete {
                reason: "provider execution has no completed terminal result frame",
            });
        };
        if frame.disposition
            != crate::protocol::ProviderResultDisposition::CompletedCandidateAvailable
            || frame.candidate_sha256 != bundle.immutable_bundle_digest
            || bundle.job_id != self.admission.operation_id().as_str()
        {
            return Err(BridgeError::EvidenceIncomplete {
                reason: "provider result frame does not name the candidate bundle",
            });
        }
        seal_completed_evidence(
            self.admission.owner_capability(),
            request,
            binding_digest,
            self.admission.operation_id().as_str(),
            bundle,
        )
        .map_err(|error| match error {
            ExchangeError::Contract(_) => BridgeError::EvidenceIncomplete {
                reason: "provider candidate bundle failed the admitted request binding",
            },
            _ => BridgeError::NotAdmitted {
                reason: "owner capability did not seal the completed candidate",
            },
        })
    }

    /// Reconciles an unknown or timed-out outcome by operation identity.
    ///
    /// # Errors
    ///
    /// Returns [`BridgeError::NotAdmitted`] when nothing was attempted, when
    /// the outcome is already classified, or when it was already reconciled.
    /// Transport failures surface as [`BridgeError::Process`].
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
        if !outcome.requires_reconciliation() || *reconciled {
            return Err(BridgeError::NotAdmitted {
                reason: "outcome is classified or already reconciled",
            });
        }
        let evidence = self
            .runner
            .reconcile_operation(self.admission.operation_id())?;
        if let BridgePhase::Submitted { reconciled, .. } = &mut self.phase {
            *reconciled = true;
        }
        Ok(evidence)
    }
}

impl ResearchBridge for AdmittedResearchBridge {
    type Error = BridgeError;

    fn owner_capability(&self) -> Option<&TaskOwnerCapability> {
        Some(self.admission.owner_capability())
    }

    fn submit(&mut self, request: &ResearchQueryRequest) -> Result<String, Self::Error> {
        self.admission
            .validate()
            .map_err(|refusal| BridgeError::NotAdmitted {
                reason: refusal.reason(),
            })?;
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
                let result_frame = execution.result_frame.clone();
                self.phase = BridgePhase::Submitted {
                    outcome,
                    evidence: Some(execution.evidence),
                    provider_job_ref: Some(execution.provider_job_ref),
                    result_frame,
                    reconciled: false,
                };
                Ok(job_id)
            }
            Err(error) => {
                // Nothing reached the executor for binding refusals and absent
                // authority: the same admission may be retried with corrected
                // input. Every other failure means the operation may exist in
                // the executor registry, so resubmission is refused and
                // unknown outcomes stay reconcile-gated.
                let terminal = match &error {
                    BridgeError::TimedOut => SubmittedOutcome::TimedOut,
                    BridgeError::UnknownOutcome => SubmittedOutcome::Unknown,
                    BridgeError::ProviderFailed { .. }
                    | BridgeError::EvidenceIncomplete { .. }
                    | BridgeError::ProtocolViolation { .. }
                    | BridgeError::Process(_) => SubmittedOutcome::Refused,
                    BridgeError::NotAdmitted { .. }
                    | BridgeError::ProviderUnavailable
                    | BridgeError::InvalidBridgeIdentity { .. } => return Err(error),
                };
                self.phase = BridgePhase::Submitted {
                    outcome: terminal,
                    evidence: None,
                    provider_job_ref: None,
                    result_frame: None,
                    reconciled: false,
                };
                Err(error)
            }
        }
    }

    fn cancel(&mut self, job_id: &str) -> Result<(), Self::Error> {
        self.admission
            .validate()
            .map_err(|refusal| BridgeError::NotAdmitted {
                reason: refusal.reason(),
            })?;
        if job_id != self.admission.operation_id().as_str() {
            return Err(BridgeError::NotAdmitted {
                reason: "cancel targets a foreign operation",
            });
        }
        if !matches!(self.phase, BridgePhase::Awaiting) {
            self.runner
                .cancel_operation(self.admission.operation_id())?;
            return Ok(());
        }
        Err(BridgeError::NotAdmitted {
            reason: "nothing was attempted through the executor yet",
        })
    }

    fn accept_completed_bundle(
        &self,
        request: &ResearchQueryRequest,
        binding_digest: &str,
        bundle: ResearchEvidenceBundle,
    ) -> Result<CompletedEvidence, Self::Error> {
        AdmittedResearchBridge::accept_completed_bundle(self, request, binding_digest, bundle)
    }
}

pub type ResearchComposition = Researcher<GovernedResearchBridge>;

/// Composes one researcher over an explicit immutable bridge identity.
///
/// No environment is consulted. Execution still requires Kernel-issued
/// research admission before any provider call can succeed.
#[must_use]
#[allow(
    dead_code,
    reason = "diagnostic-only bridge composition is not a production entry point"
)]
pub(crate) fn compose_with_bridge(identity: BridgeIdentity) -> ResearchComposition {
    Researcher::new(GovernedResearchBridge::new(identity))
}

/// Composes one researcher over one admitted provider operation.
#[must_use]
#[allow(
    dead_code,
    reason = "the live production owner caller is not wired in this bounded repair turn"
)]
pub(crate) fn compose_admitted(
    runner: ProviderBridge,
    admission: AdmittedProviderAdmission,
) -> Researcher<AdmittedResearchBridge> {
    Researcher::new(AdmittedResearchBridge::new(runner, admission))
}

/// Imports one provider bundle through both the admitted bridge check and the
/// exchange state machine. No caller can turn an `Accepted` job into a
/// completed result by calling the lower-level exchange directly.
pub(crate) fn import_admitted_bundle<B: ResearchBridge>(
    researcher: &mut Researcher<B>,
    request: &ResearchQueryRequest,
    binding_digest: &str,
    bundle: ResearchEvidenceBundle,
) -> Result<ExchangeJob, GovernedInquiryError> {
    researcher.import_completed_bundle(request, binding_digest, bundle)
}

/// Imports the provider bundle and returns a new sealed submission output.
/// The exchange job is replaced only by its own completed result; callers
/// cannot mutate the private submission record to manufacture completion.
pub(crate) fn complete_r6_submission(
    mut submission: R6SubmissionOutput,
    researcher: &mut Researcher<AdmittedResearchBridge>,
    request: &ResearchQueryRequest,
    bundle: ResearchEvidenceBundle,
) -> Result<R6SubmissionOutput, GovernedInquiryError> {
    submission.binding.validate_integrity()?;
    if request != &submission.binding.query {
        return Err(GovernedInquiryError::Exchange(
            ExchangeError::IdempotencyConflict,
        ));
    }
    let raw_evidence =
        researcher
            .bridge()
            .last_evidence()
            .ok_or(GovernedInquiryError::Exchange(
                ExchangeError::ResultRequired,
            ))?;
    if raw_evidence.operation_id != submission.binding.provider_operation_id {
        return Err(GovernedInquiryError::Exchange(
            ExchangeError::IdempotencyConflict,
        ));
    }
    submission.raw_evidence_digest = raw_evidence
        .digest()
        .map_err(|_| GovernedInquiryError::Exchange(ExchangeError::InvalidTransition))?;
    let existing = researcher
        .exchange()
        .snapshot()
        .jobs
        .get(&submission.exchange_job.job_id)
        .ok_or(ExchangeError::NotFound)?;
    if existing.request != submission.binding.query
        || existing.exchange_id != submission.binding.query.exchange_id
        || existing.state_fence != submission.binding.state_fence
    {
        return Err(GovernedInquiryError::Exchange(
            ExchangeError::IdempotencyConflict,
        ));
    }
    let job = import_admitted_bundle(researcher, request, &submission.binding.digest, bundle)?;
    if job.job_id != submission.exchange_job.job_id
        || job.exchange_id != submission.binding.query.exchange_id
        || job.state_fence != submission.binding.state_fence
        || job.request != submission.binding.query
        || job.status != ExchangeStatus::Completed
        || job.result.is_none()
    {
        return Err(GovernedInquiryError::Exchange(
            ExchangeError::ResultRequired,
        ));
    }
    submission.exchange_job = job;
    Ok(submission)
}

/// Owner-bound R6 submission input. It contains no task snapshot, task
/// reconstruction context, source proposal, coverage projection, or caller
/// disposition. Those values are either read from the live owner or derived
/// from the completed provider bundle by [`compose_r6_completed`].
#[derive(Clone, Debug)]
pub struct R6OwnerBoundRequest {
    inquiry_id: String,
    profile: InquiryProtocolProfileParams,
    profile_revision: Option<InquiryProtocolProfileParams>,
    obligations: Vec<InquiryObligationInput>,
    query: ResearchQueryRequest,
    provider_admission: AdmittedProviderAdmission,
}

impl R6OwnerBoundRequest {
    /// Creates an owner-bound R6 request. The provider admission is already
    /// opaque and owner-issued; this constructor does not create authority.
    #[must_use]
    pub fn new(
        inquiry_id: String,
        profile: InquiryProtocolProfileParams,
        profile_revision: Option<InquiryProtocolProfileParams>,
        obligations: Vec<InquiryObligationInput>,
        query: ResearchQueryRequest,
        provider_admission: AdmittedProviderAdmission,
    ) -> Self {
        Self {
            inquiry_id,
            profile,
            profile_revision,
            obligations,
            query,
            provider_admission,
        }
    }
}

/// The result of owner-authenticated submission. An `Accepted` exchange job
/// is deliberately not an inquiry outcome; completion is a separate,
/// evidence-consuming step.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct R6SubmissionOutput {
    inquiry_id: String,
    binding: eliot_researcher::InquiryExecutionBinding,
    task_compilation: TaskGraphCompilationReceipt,
    canonical_compilation_receipt: eliot_store_api::WriteReceipt,
    raw_evidence_digest: String,
    exchange_job: ExchangeJob,
    candidate_only: bool,
    canonical_write_authorized: bool,
}

impl R6SubmissionOutput {
    #[must_use]
    pub const fn candidate_only(&self) -> bool {
        self.candidate_only
    }

    #[must_use]
    pub const fn canonical_write_authorized(&self) -> bool {
        self.canonical_write_authorized
    }
}

/// Canonical digest helper used only to bind already-admitted provider and
/// bridge manifests into the one execution record.
fn canonical_digest(value: &impl Serialize) -> Result<String, R6CompositionError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        R6CompositionError::InvalidBinding(format!(
            "admitted manifest serialization failed: {error}"
        ))
    })?;
    Ok(sha256_hex(&bytes))
}

/// Compiles and submits one R6 inquiry only through the live authenticated
/// Governor/Task Controller owner. The owner receipt is durably persisted
/// before the exchange is contacted, and its exact binding digest is consumed
/// by the exchange submission.
#[allow(clippy::too_many_lines)]
pub(crate) async fn compose_r6_owner_bound<P>(
    researcher: &mut Researcher<AdmittedResearchBridge>,
    owner: &eliot_governor::GovernorTaskLifecycle<'_, P>,
    identity: &eliot_protocol::RequestIdentity,
    operation_id: eliot_contracts::OperationId,
    request: R6OwnerBoundRequest,
) -> Result<R6SubmissionOutput, R6CompositionError>
where
    P: eliot_governor::KernelTransitionPort + ?Sized,
{
    if identity.request.metadata.state_fence != request.query.state_fence {
        return Err(R6CompositionError::InvalidBinding(
            "authenticated request and query fences differ".to_owned(),
        ));
    }
    if identity
        .request
        .metadata
        .task_id
        .as_ref()
        .map(eliot_contracts::TaskId::as_str)
        != Some(request.profile.task_id.as_str())
    {
        return Err(R6CompositionError::InvalidBinding(
            "authenticated request task identity differs from the R6 profile input".to_owned(),
        ));
    }
    if request.provider_admission != *researcher.bridge().admission() {
        return Err(R6CompositionError::InvalidBinding(
            "provider admission is not the bridge's owner-issued admission".to_owned(),
        ));
    }
    request
        .provider_admission
        .validate()
        .map_err(|error| R6CompositionError::InvalidBinding(error.reason().to_owned()))?;
    request
        .provider_admission
        .validate_request(&request.query)
        .map_err(|error| R6CompositionError::InvalidBinding(error.reason().to_owned()))?;
    let profile = researcher.resolve_inquiry_profile(request.profile)?;
    let profile = if let Some(revision) = request.profile_revision {
        researcher.revise_inquiry_profile(&profile.profile_id, revision)?
    } else {
        profile
    };
    profile.validate_integrity()?;
    if identity
        .request
        .metadata
        .task_id
        .as_ref()
        .map(eliot_contracts::TaskId::as_str)
        != Some(profile.task_id.as_str())
    {
        return Err(R6CompositionError::InvalidBinding(
            "authenticated request task identity differs from the R6 profile".to_owned(),
        ));
    }
    if request.query.state_fence != profile.state_fence
        || request.query.question != profile.question
        || request.query.question_scope != profile.scope
        || request.query.allowed_references.digest != profile.reference_manifest_digest
    {
        return Err(R6CompositionError::InvalidBinding(
            "query is not bound to the owner-resolved profile".to_owned(),
        ));
    }
    let bridge_digest = canonical_digest(researcher.bridge().admission().bridge())?;
    let admission_digest = canonical_digest(request.provider_admission.manifest())?;
    let provenance_digest = canonical_digest(&(
        request.provider_admission.manifest(),
        &request.query.allowed_references,
    ))?;
    let portfolio_digest = canonical_digest(&request.query.allowed_references)?;
    let binding = eliot_researcher::InquiryExecutionBinding::new(
        &request.inquiry_id,
        profile.clone(),
        request.query.clone(),
        admission_digest,
        request.provider_admission.module_generation_id().to_owned(),
        request
            .provider_admission
            .operation_id()
            .as_str()
            .to_owned(),
        bridge_digest,
        provenance_digest,
        canonical_digest(&request.query.exchange_id)?,
        portfolio_digest,
        request.query.allowed_references.digest.clone(),
        profile.truth_surfaces_and_admissible_providers.clone(),
        request.query.source_classes.clone(),
        request.query.disclosure,
        request.query.budget_units,
        request.query.deadline_ms,
        request.query.state_fence.clone(),
    )?;
    let compilation_request = researcher.prepare_obligation_compilation(
        &profile.profile_id,
        profile.revision,
        &request.obligations,
        &binding.digest,
    )?;
    let task_compilation = owner
        .compile_inquiry_obligations(compilation_request.clone())
        .map_err(R6CompositionError::from)?;
    let owner_capability = owner
        .issue_research_capability(compilation_request.clone())
        .map_err(R6CompositionError::from)?;
    if owner_capability != *request.provider_admission.owner_capability() {
        return Err(R6CompositionError::InvalidBinding(
            "provider admission is not paired with the live owner-issued capability".to_owned(),
        ));
    }
    let canonical_compilation_receipt = owner
        .persist_inquiry_compilation(
            identity,
            operation_id.clone(),
            &compilation_request,
            &task_compilation,
        )
        .await
        .map_err(R6CompositionError::from)?;
    if canonical_compilation_receipt.validate().is_err()
        || canonical_compilation_receipt.status != WriteReceiptStatus::Committed
        || canonical_compilation_receipt.transition_class != TransitionClass::CaptureCandidate
        || canonical_compilation_receipt.operation_id != operation_id
        || canonical_compilation_receipt.idempotency_key != identity.idempotency_key
        || canonical_compilation_receipt.state_fence != request.query.state_fence
    {
        return Err(R6CompositionError::InvalidBinding(
            "owner compiler receipt was not committed for this exact operation".to_owned(),
        ));
    }
    let (exchange_job, task_compilation) = researcher.submit_governed_query_with_receipt(
        &profile.profile_id,
        profile.revision,
        &request.obligations,
        &binding,
        &task_compilation,
        request.query,
    )?;
    Ok(R6SubmissionOutput {
        inquiry_id: request.inquiry_id,
        binding,
        task_compilation,
        canonical_compilation_receipt,
        raw_evidence_digest: String::new(),
        exchange_job,
        candidate_only: true,
        canonical_write_authorized: false,
    })
}

/// The sole production R6 consumer. It accepts only an admitted bridge, a
/// live Governor/Task Controller owner, an authenticated request identity, and
/// the exact provider bundle returned by that operation. No public closure
/// constructor is exposed; the returned record is read-only and candidate-only.
pub async fn run_admitted_r6<P>(
    researcher: &mut Researcher<AdmittedResearchBridge>,
    owner: &eliot_governor::GovernorTaskLifecycle<'_, P>,
    identity: &eliot_protocol::RequestIdentity,
    operation_id: eliot_contracts::OperationId,
    request: R6OwnerBoundRequest,
    bundle: ResearchEvidenceBundle,
) -> Result<R6CompletionProjection, R6CompositionError>
where
    P: eliot_governor::KernelTransitionPort + ?Sized,
{
    let query = request.query.clone();
    let submission =
        compose_r6_owner_bound(researcher, owner, identity, operation_id, request).await?;
    let submission = complete_r6_submission(submission, researcher, &query, bundle)
        .map_err(R6CompositionError::Exchange)?;
    let completed = r6_consumer::compose_r6_completed(&submission)?;
    Ok(R6CompletionProjection::from_completed(completed))
}

#[derive(Debug, Error)]
pub enum R6CompositionError {
    #[error("R6 request binding is invalid: {0}")]
    InvalidBinding(String),
    #[error("R6 governance rejected the request: {0}")]
    Governance(#[from] InquiryGovernanceError),
    #[error("R6 Task Controller rejected the request: {0}")]
    TaskOwner(#[from] TaskError),
    #[error("R6 authenticated owner rejected the request: {0}")]
    Owner(Box<eliot_governor::TaskLifecycleError>),
    #[error("R6 exchange rejected the request: {0}")]
    Exchange(#[from] GovernedInquiryError),
}

impl From<eliot_governor::TaskLifecycleError> for R6CompositionError {
    fn from(error: eliot_governor::TaskLifecycleError) -> Self {
        Self::Owner(Box::new(error))
    }
}

#[cfg(test)]
fn submit<B: ResearchBridge>(
    researcher: &mut Researcher<B>,
    request: ResearchQueryRequest,
) -> Result<ExchangeJob, ExchangeError> {
    let _ = (researcher, request);
    Err(ExchangeError::InvalidTransition)
}

#[cfg(test)]
pub(crate) fn cancel<B: ResearchBridge>(
    researcher: &mut Researcher<B>,
    job_id: &str,
    fence: &StateFence,
) -> Result<ExchangeJob, ExchangeError> {
    researcher.cancel_governed_query(job_id, fence)
}

#[must_use]
#[cfg(test)]
pub(crate) fn exchange_snapshot<B: ResearchBridge>(
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
        ClockReading, ContractVersion, EpochId, EpochLineageId, ResourceGeneration, StateFence,
        TaskId,
    };
    use eliot_process::{Generation, OperationId};
    use eliot_research_exchange_api::{
        AllowedReferenceManifest, AnchorPrecision, DisclosureClass, ResearchQueryRequest,
        SourceClass,
    };
    use eliot_task::{
        TaskCommandContext, TaskGraphCompilationRequest, TaskLifecycleOwner, TaskProposal,
    };

    use super::{AdmittedProviderAdmission, BridgeIdentity};
    use crate::admission::ProviderAdmission;

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

    pub(crate) fn test_capability() -> eliot_task::TaskOwnerCapability {
        let task_id = TaskId::new("task-r6-test").expect("task id");
        let context = TaskCommandContext {
            request_id: "request-r6-test".to_owned(),
            event_id: "event-r6-test".to_owned(),
            actor_ref: "test-owner".to_owned(),
            state_fence: test_fence(),
            authority_epoch: test_epoch(),
            observed_at: ClockReading {
                valid_time_ms: Some(1_700_000_000_000),
                known_time_ms: Some(1_700_000_000_000),
                transaction_sequence: None,
                monotonic_ns: None,
            },
        };
        let mut owner =
            TaskLifecycleOwner::new(test_epoch(), test_fence()).expect("test task owner");
        owner
            .propose(TaskProposal {
                task_id: task_id.clone(),
                project_ref: "project-r6-test".to_owned(),
                goal: "research exchange proof".to_owned(),
                context,
            })
            .expect("test task proposal");
        let task_definition_digest = owner
            .task_definition_digest(&task_id)
            .expect("test task definition");
        owner
            .issue_research_capability(TaskGraphCompilationRequest {
                task_id,
                task_definition_digest,
                profile_id: "profile-r6-test".to_owned(),
                profile_revision: 1,
                profile_digest: DIGEST_A.to_owned(),
                obligation_ids: vec!["obligation-r6-test".to_owned()],
                obligation_digests: vec![DIGEST_B.to_owned()],
                state_fence: test_fence(),
                inquiry_binding_digest: DIGEST_A.to_owned(),
            })
            .expect("test owner capability")
    }

    pub(crate) fn test_admission() -> AdmittedProviderAdmission {
        let shape = ProviderAdmission::new_shape(
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
        )
        .expect("test admission shape must construct");
        AdmittedProviderAdmission::from_owner_capability(shape, test_capability())
            .expect("test owner-bound admission must construct")
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
        const SOURCES: [&str; 6] = [
            include_str!("lib.rs"),
            include_str!("main.rs"),
            include_str!("admission.rs"),
            include_str!("evidence.rs"),
            include_str!("execution.rs"),
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
        assert_eq!(researcher.bridge().identity(), &test_identity());
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
            matches!(result, Err(ExchangeError::InvalidTransition)),
            "absent process authority must surface as a gap, never a job"
        );
        assert!(
            exchange_snapshot(&researcher).jobs.is_empty(),
            "no exchange job may be recorded for an unexecuted provider call"
        );
        assert!(
            !researcher.bridge().has_submitted(),
            "a gap before executor contact must keep the operation retryable, not submitted"
        );
        assert_eq!(
            researcher.bridge().admission().operation_id().as_str(),
            "op-24-slice-a",
            "the bound admission stays exact after a gap"
        );
        assert_eq!(researcher.bridge().last_evidence(), None);
        assert_eq!(researcher.bridge().last_provider_job_ref(), None);
    }

    /// Test-only request port: always refuses, so no executor contact happens.
    struct RefusingTestPort(super::execution::RequestPortError);

    impl super::execution::ResearchRequestPort for RefusingTestPort {
        fn bind(
            &self,
            _admission: &super::admission::AdmittedProviderAdmission,
            _request_sha256: &str,
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
