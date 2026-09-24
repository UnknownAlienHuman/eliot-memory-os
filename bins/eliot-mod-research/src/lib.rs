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

use serde::{Deserialize, Serialize};

use eliot_contracts::{StateFence, TaskId};
use eliot_research_exchange::{ExchangeError, ExchangeJob, ResearchBridge};
use eliot_research_exchange_api::{CoverageGapKind, ResearchQueryRequest};
use eliot_researcher::{
    CanonicalCoverageProjection, ClaimAudit, EvidenceFreeze, GovernedInquiryError,
    GovernorProfileAdmissionRequest, GovernorSourceAdmissionRequest, InquiryDisposition,
    InquiryDispositionRecord, InquiryGovernanceError, InquiryObligationInput,
    InquiryProtocolProfile, InquiryProtocolProfileParams, ResearchDebt, Researcher,
    SourceAdmissibilityRecord, SourceEligibility, SourceProposal, TaskGraphCompilationReceipt,
    UnsupportedPrecisionItem,
};
use eliot_task::{TaskCommandContext, TaskError, TaskLifecycleOwner, TaskLifecycleSnapshot};
use thiserror::Error;

pub use admission::{AdmissionRefusal, ProviderAdmission};
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

    fn provider_unavailable(&self) -> bool {
        true
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
    Submitted {
        /// Typed terminal outcome (or the failure that ended the attempt).
        outcome: SubmittedOutcome,
        /// Immutable raw evidence when the attempt reached materialization.
        evidence: Option<RawProviderEvidence>,
        /// Provider-local job reference when the ack decoded.
        provider_job_ref: Option<String>,
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
                self.phase = BridgePhase::Submitted {
                    outcome,
                    evidence: Some(execution.evidence),
                    provider_job_ref: Some(execution.provider_job_ref),
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
        if !matches!(self.phase, BridgePhase::Awaiting) {
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

/// Non-test production request accepted by the R6 composition path. The
/// request is data, not authority: the Task Controller owner and the normal
/// provider admission boundary remain authoritative.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R6ResearchRequest {
    pub inquiry_id: String,
    pub bridge_identity: BridgeIdentity,
    pub task_id: TaskId,
    pub task_project: String,
    pub task_goal: String,
    pub task_context: TaskCommandContext,
    pub task_snapshot: Option<TaskLifecycleSnapshot>,
    pub profile: InquiryProtocolProfileParams,
    pub profile_revision: Option<InquiryProtocolProfileParams>,
    pub obligations: Vec<InquiryObligationInput>,
    pub source_proposals: Vec<SourceProposal>,
    pub query: ResearchQueryRequest,
    pub portfolio_digest: Option<String>,
    pub manifest_digest: Option<String>,
    pub coverage_receipt_digest: Option<String>,
    pub canonical_coverage: Option<CanonicalCoverageProjection>,
    pub evidence_freeze: Option<EvidenceFreeze>,
    pub claim_audits: Vec<ClaimAudit>,
    pub research_debts: Vec<ResearchDebt>,
    pub unsupported_precision: Vec<UnsupportedPrecisionItem>,
    pub disposition: InquiryDisposition,
    pub next_probe: Option<String>,
    pub narrower_claim: Option<String>,
    pub explicit_unknown: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct R6CompositionOutput {
    pub inquiry_id: String,
    pub profile: InquiryProtocolProfile,
    pub task_compilation: TaskGraphCompilationReceipt,
    pub source_records: Vec<SourceAdmissibilityRecord>,
    pub governor_profile_request: GovernorProfileAdmissionRequest,
    pub governor_source_requests: Vec<GovernorSourceAdmissionRequest>,
    pub exchange_job: Option<ExchangeJob>,
    pub canonical_coverage: Option<CanonicalCoverageProjection>,
    pub evidence_freeze: Option<EvidenceFreeze>,
    pub claim_audits: Vec<ClaimAudit>,
    pub research_debts: Vec<ResearchDebt>,
    pub unsupported_precision: Vec<UnsupportedPrecisionItem>,
    pub disposition: InquiryDispositionRecord,
    pub candidate_only: bool,
    pub canonical_write_authorized: bool,
}

#[derive(Debug, Error)]
pub enum R6CompositionError {
    #[error("R6 request binding is invalid: {0}")]
    InvalidBinding(String),
    #[error("R6 governance rejected the request: {0}")]
    Governance(#[from] InquiryGovernanceError),
    #[error("R6 Task Controller rejected the request: {0}")]
    TaskOwner(#[from] TaskError),
    #[error("R6 exchange rejected the request: {0}")]
    Exchange(#[from] GovernedInquiryError),
}

/// Reconstructs the existing Task Controller owner from an explicitly supplied
/// lifecycle snapshot. The snapshot is a candidate input; this helper does not
/// persist it or grant canonical authority.
pub fn task_owner_from_snapshot(
    snapshot: TaskLifecycleSnapshot,
    context: &TaskCommandContext,
) -> Result<TaskLifecycleOwner, R6CompositionError> {
    Ok(TaskLifecycleOwner::from_snapshot(
        context.authority_epoch.clone(),
        context.state_fence.clone(),
        snapshot,
    )?)
}

#[allow(clippy::too_many_lines)]
/// Real non-test R6 request/composition consumer.
///
/// It resolves/revises the profile, asks the existing Task Controller owner
/// for the typed compilation receipt, assesses every source candidate, emits
/// Governor-facing requests, and only then submits the exact query through the
/// governed exchange. A provider-unavailable result is returned as a typed
/// terminal gap; it is never converted into an answer.
pub fn compose_r6_request<B: ResearchBridge>(
    researcher: &mut Researcher<B>,
    task_owner: &TaskLifecycleOwner,
    request: R6ResearchRequest,
) -> Result<R6CompositionOutput, R6CompositionError> {
    if request.inquiry_id.trim().is_empty()
        || request.task_id != request.profile.task_id
        || request.task_context.state_fence != request.query.state_fence
        || request.task_context.state_fence != request.profile.state_fence
    {
        return Err(R6CompositionError::InvalidBinding(
            "task/profile/query identity or fence does not match".to_owned(),
        ));
    }
    let task = task_owner.task(&request.task_id).ok_or_else(|| {
        R6CompositionError::InvalidBinding("task is absent from owner".to_owned())
    })?;
    if task.project_ref != request.task_project || task.goal != request.task_goal {
        return Err(R6CompositionError::InvalidBinding(
            "request task project/goal does not match the live task record".to_owned(),
        ));
    }
    let derived_task_definition = task_owner.task_definition_digest(&request.task_id)?;
    if request.profile.task_definition_digest != derived_task_definition {
        return Err(R6CompositionError::InvalidBinding(
            "profile task-definition digest is not the live Task Controller digest".to_owned(),
        ));
    }
    if let Some(revision) = &request.profile_revision
        && (revision.task_id != request.task_id
            || revision.task_definition_digest != derived_task_definition)
    {
        return Err(R6CompositionError::InvalidBinding(
            "profile revision is not bound to the live task definition".to_owned(),
        ));
    }

    let profile = researcher.resolve_inquiry_profile(request.profile)?;
    let profile = if let Some(revision) = request.profile_revision {
        researcher.revise_inquiry_profile(&profile.profile_id, revision)?
    } else {
        profile
    };
    let mut source_records = Vec::with_capacity(request.source_proposals.len());
    for proposal in &request.source_proposals {
        source_records.push(researcher.assess_source_candidate(
            &profile.profile_id,
            profile.revision,
            &proposal.evidence_set_id,
            proposal,
        )?);
    }
    if !source_records.is_empty()
        && !source_records
            .iter()
            .any(|record| record.eligibility == SourceEligibility::Eligible)
    {
        return Err(R6CompositionError::InvalidBinding(
            "all proposed sources are pending or ineligible".to_owned(),
        ));
    }

    let (job, task_compilation) = match researcher.submit_governed_query(
        &profile.profile_id,
        profile.revision,
        &request.obligations,
        task_owner,
        request.query.clone(),
    ) {
        Ok(value) => (Some(value.0), value.1),
        Err(GovernedInquiryError::Exchange(ExchangeError::InvalidTransition))
            if researcher.bridge().provider_unavailable() =>
        {
            // Compile again through the same owner to retain the receipt while
            // preserving the provider-unavailable disposition. This second
            // call is idempotent at the Task Controller boundary and never
            // retries the provider.
            (
                None,
                researcher.compile_obligations(
                    &profile.profile_id,
                    profile.revision,
                    &request.obligations,
                    task_owner,
                )?,
            )
        }
        Err(error) => return Err(R6CompositionError::Exchange(error)),
    };
    if let Some(coverage) = &request.canonical_coverage {
        coverage
            .denominator
            .validate()
            .map_err(|error| R6CompositionError::InvalidBinding(error.to_string()))?;
        coverage
            .receipt
            .validate()
            .map_err(|error| R6CompositionError::InvalidBinding(error.to_string()))?;
        if coverage.denominator.scope != profile.scope
            || coverage.receipt.scope != profile.scope
            || coverage.receipt.fence != profile.state_fence
            || coverage.receipt.task_id != request.task_id
            || coverage.receipt.denominator != coverage.denominator.digest
        {
            return Err(R6CompositionError::InvalidBinding(
                "canonical coverage projection is not bound to the exact task/profile/scope/fence"
                    .to_owned(),
            ));
        }
    }
    let portfolio_digest = request
        .canonical_coverage
        .as_ref()
        .map(|coverage| coverage.portfolio_digest.clone())
        .or(request.portfolio_digest.clone());
    if request
        .portfolio_digest
        .as_ref()
        .is_some_and(|digest| Some(digest) != portfolio_digest.as_ref())
    {
        return Err(R6CompositionError::InvalidBinding(
            "caller portfolio digest does not match the canonical projection".to_owned(),
        ));
    }
    let coverage_receipt_digest = request
        .canonical_coverage
        .as_ref()
        .map(|coverage| coverage.receipt.digest.clone())
        .or(request.coverage_receipt_digest.clone());
    if request
        .canonical_coverage
        .as_ref()
        .is_some_and(|coverage| coverage.receipt.fence != profile.state_fence)
    {
        return Err(R6CompositionError::InvalidBinding(
            "canonical coverage receipt is not bound to the profile fence".to_owned(),
        ));
    }
    if request
        .coverage_receipt_digest
        .as_ref()
        .is_some_and(|digest| Some(digest) != coverage_receipt_digest.as_ref())
    {
        return Err(R6CompositionError::InvalidBinding(
            "caller coverage digest does not match the canonical receipt".to_owned(),
        ));
    }
    if let Some(freeze) = &request.evidence_freeze
        && (freeze.profile_id != profile.profile_id
            || freeze.profile_revision != profile.revision
            || freeze.profile_digest != profile.digest
            || freeze.state_fence != profile.state_fence
            || coverage_receipt_digest
                .as_ref()
                .is_some_and(|digest| &freeze.coverage_receipt_digest != digest))
    {
        return Err(R6CompositionError::InvalidBinding(
            "evidence freeze is not bound to the exact profile/fence/coverage receipt".to_owned(),
        ));
    }
    if request.disposition.may_close()
        && (!request.research_debts.is_empty() || !request.unsupported_precision.is_empty())
    {
        return Err(R6CompositionError::InvalidBinding(
            "open research debts or unsupported precision cannot close an inquiry".to_owned(),
        ));
    }
    let disposition = if job.is_none() {
        InquiryDisposition::SourceUnavailable
    } else {
        request.disposition
    };
    let disposition = InquiryDispositionRecord::new(
        &request.inquiry_id,
        &profile,
        source_records
            .first()
            .map_or_else(String::new, |record| record.evidence_set_id.clone()),
        portfolio_digest,
        request.manifest_digest,
        coverage_receipt_digest,
        disposition,
        request.next_probe,
        request.narrower_claim,
        request.explicit_unknown,
    )?;
    let governor_profile_request = profile.governor_admission_request();
    let governor_source_requests = source_records
        .iter()
        .map(SourceAdmissibilityRecord::governor_admission_request)
        .collect();
    Ok(R6CompositionOutput {
        inquiry_id: request.inquiry_id,
        profile,
        task_compilation,
        source_records,
        governor_profile_request,
        governor_source_requests,
        exchange_job: job,
        canonical_coverage: request.canonical_coverage,
        evidence_freeze: request.evidence_freeze,
        claim_audits: request.claim_audits,
        research_debts: request.research_debts,
        unsupported_precision: request.unsupported_precision,
        disposition,
        candidate_only: true,
        canonical_write_authorized: false,
    })
}

#[cfg(test)]
fn submit<B: ResearchBridge>(
    researcher: &mut Researcher<B>,
    request: ResearchQueryRequest,
) -> Result<ExchangeJob, ExchangeError> {
    let _ = (researcher, request);
    Err(ExchangeError::InvalidTransition)
}

pub fn cancel<B: ResearchBridge>(
    researcher: &mut Researcher<B>,
    job_id: &str,
    fence: &StateFence,
) -> Result<ExchangeJob, ExchangeError> {
    researcher.cancel_governed_query(job_id, fence)
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
            _admission: &super::admission::ProviderAdmission,
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
