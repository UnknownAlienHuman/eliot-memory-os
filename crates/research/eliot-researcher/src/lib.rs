//! Researcher composition root.
//!
//! Researcher owns acquisition requests and bridge composition only. It does
//! not interpret claims, promote memory, or bypass the exchange fence.

#![forbid(unsafe_code)]

pub mod evidence_portfolio;
pub mod inquiry_governance;
pub mod inquiry_obligations;
pub mod source_admissibility;

pub use evidence_portfolio::{CanonicalCoverageProjection, UnsupportedPrecisionItem};

use eliot_contracts::StateFence;
use eliot_research_exchange::{ExchangeError, ExchangeJob, GovernedExchange, ResearchBridge};
use eliot_research_exchange_api::{
    AllowedReferenceManifest, AnchorPrecision, ResearchQueryRequest,
};

pub use eliot_task::{
    TaskGraphCompilationReceipt, TaskGraphCompilationRequest, TaskLifecycleOwner,
};
pub use inquiry_governance::{
    BudgetDeadlineStopRule, ClaimAudit, CoverageGoal, EvidenceFreeze, EvidenceGrade,
    GovernorProfileAdmissionRequest, HypothesisPolicy, IndependenceBlindingPolicy,
    InquiryExecutionBinding,
    InquiryDisposition, InquiryDispositionRecord, InquiryGovernance, InquiryGovernanceError,
    InquiryHorizon, InquiryLane, InquiryProtocol, InquiryProtocolProfile,
    InquiryProtocolProfileParams, InquiryRisk, InquirySelectionFeatures, InquiryUncertainty,
    OutputContractAndReopenConditions, ResearchDebt, ResearchDebtKind,
    ResearchDebtProblemBinding, SpecialistDiscoverability,
    VerifierStrength, select_protocol,
};
pub use inquiry_obligations::{
    AcceptanceCertificate, AcceptanceCertificateKind, InquiryObligation, InquiryObligationInput,
    InquiryObligationStatus,
};
pub use source_admissibility::{
    GovernorSourceAdmissionRequest, SourceAdmissibilityReason, SourceAdmissibilityRecord,
    SourceEligibility, SourceIndependence, SourceLimits, SourceProposal, SourceProvenance,
    SourceTaint,
};

/// Error returned when governance compilation precedes an exchange submit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GovernedInquiryError {
    Governance(InquiryGovernanceError),
    Exchange(ExchangeError),
}

impl From<InquiryGovernanceError> for GovernedInquiryError {
    fn from(error: InquiryGovernanceError) -> Self {
        Self::Governance(error)
    }
}

impl From<ExchangeError> for GovernedInquiryError {
    fn from(error: ExchangeError) -> Self {
        Self::Exchange(error)
    }
}

impl std::fmt::Display for GovernedInquiryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Governance(error) => write!(f, "inquiry governance rejected submission: {error}"),
            Self::Exchange(error) => write!(f, "research exchange rejected submission: {error}"),
        }
    }
}

impl std::error::Error for GovernedInquiryError {}

pub struct Researcher<B> {
    exchange: GovernedExchange<B>,
    governance: InquiryGovernance,
}

impl<B> Researcher<B> {
    pub fn new(bridge: B) -> Self {
        Self {
            exchange: GovernedExchange::new(bridge),
            governance: InquiryGovernance::new(),
        }
    }
    #[allow(dead_code, reason = "retained for crate-local recovery composition only")]
    pub(crate) fn from_exchange(exchange: GovernedExchange<B>) -> Self {
        Self {
            exchange,
            governance: InquiryGovernance::new(),
        }
    }
    #[must_use]
    pub fn exchange(&self) -> &GovernedExchange<B> {
        &self.exchange
    }
    /// Read-only view of the composed exchange bridge.
    #[must_use]
    pub fn bridge(&self) -> &B {
        self.exchange.bridge()
    }
    /// Read-only view of the runtime-local R6 governance registry.
    #[must_use]
    pub fn governance(&self) -> &InquiryGovernance {
        &self.governance
    }
}

impl<B: ResearchBridge> Researcher<B> {
    /// Resolves a profile through the production Researcher composition root.
    pub fn resolve_inquiry_profile(
        &mut self,
        params: InquiryProtocolProfileParams,
    ) -> Result<InquiryProtocolProfile, InquiryGovernanceError> {
        self.governance.resolve_profile(params)
    }

    /// Revises the latest profile while preserving the previous revision.
    pub fn revise_inquiry_profile(
        &mut self,
        profile_id: &str,
        params: InquiryProtocolProfileParams,
    ) -> Result<InquiryProtocolProfile, InquiryGovernanceError> {
        self.governance.revise_profile(profile_id, params)
    }

    /// Prepares the exact owner-port compilation request for one complete
    /// inquiry execution binding. The request is not a receipt and cannot be
    /// persisted by the Researcher; a live authenticated owner must issue it.
    pub fn prepare_obligation_compilation(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        inputs: &[InquiryObligationInput],
        inquiry_binding_digest: &str,
    ) -> Result<TaskGraphCompilationRequest, InquiryGovernanceError> {
        self.governance.prepare_obligation_compilation(
            profile_id,
            profile_revision,
            inputs,
            inquiry_binding_digest,
        )
    }

    /// Compiles profile-bound obligations through the existing work-graph port.
    pub fn compile_obligations(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        inputs: &[InquiryObligationInput],
        task_owner: &TaskLifecycleOwner,
    ) -> Result<TaskGraphCompilationReceipt, InquiryGovernanceError> {
        self.governance
            .compile_obligations(profile_id, profile_revision, inputs, task_owner)
    }

    /// Evaluates a provider source as candidate-only for an exact profile.
    pub fn assess_source_candidate(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        evidence_set_id: &str,
        proposal: &SourceProposal,
    ) -> Result<SourceAdmissibilityRecord, InquiryGovernanceError> {
        self.governance
            .assess_source(profile_id, profile_revision, evidence_set_id, proposal)
    }

    /// Returns a Governor-facing profile request without granting admission.
    #[must_use]
    pub fn governor_profile_admission_request(
        &self,
        profile_id: &str,
        profile_revision: u64,
    ) -> Option<GovernorProfileAdmissionRequest> {
        self.governance
            .profile(profile_id, profile_revision)
            .map(InquiryProtocolProfile::governor_admission_request)
    }

    /// Compiles obligations first, then submits through the existing governed
    /// exchange. This is acquisition composition, not self-enqueue or Finish.
    pub fn submit_governed_query(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        obligations: &[InquiryObligationInput],
        task_owner: &TaskLifecycleOwner,
        query: ResearchQueryRequest,
    ) -> Result<(ExchangeJob, TaskGraphCompilationReceipt), GovernedInquiryError> {
        let profile = self
            .governance
            .profile(profile_id, profile_revision)
            .ok_or_else(|| InquiryGovernanceError::UnknownProfile {
                profile_id: profile_id.to_owned(),
                revision: profile_revision,
            })?;
        if !profile.matches_binding(&profile.task_definition_digest, &query.state_fence)
            || query.state_fence != profile.state_fence
            || query.question != profile.question
            || query.question_scope != profile.scope
            || query.allowed_references.state_fence != profile.state_fence
            || query.allowed_references.digest != profile.reference_manifest_digest
        {
            return Err(InquiryGovernanceError::InvalidField {
                field: "query.profile_binding",
            }
            .into());
        }
        let receipt = self.governance.compile_obligations(
            profile_id,
            profile_revision,
            obligations,
            task_owner,
        )?;
        let job = self.exchange.submit(query)?;
        Ok((job, receipt))
    }

    /// Submits only after a live owner has issued and durably persisted the
    /// compilation receipt for this exact profile/obligation/query binding.
    /// The exchange never accepts a caller-supplied compiler identity or a
    /// merely well-formed self-asserted receipt.
    pub fn submit_governed_query_with_receipt(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        inputs: &[InquiryObligationInput],
        inquiry_binding_digest: &str,
        receipt: &TaskGraphCompilationReceipt,
        query: ResearchQueryRequest,
    ) -> Result<(ExchangeJob, TaskGraphCompilationReceipt), GovernedInquiryError> {
        let profile = self
            .governance
            .profile(profile_id, profile_revision)
            .ok_or_else(|| InquiryGovernanceError::UnknownProfile {
                profile_id: profile_id.to_owned(),
                revision: profile_revision,
            })?
            .clone();
        let request = self.governance.prepare_obligation_compilation(
            profile_id,
            profile_revision,
            inputs,
            inquiry_binding_digest,
        )?;
        receipt
            .validate_against(&request)
            .map_err(|error| GovernedInquiryError::Governance(
                InquiryGovernanceError::TaskOwnerRejected { error },
            ))?;
        if !profile.matches_binding(&profile.task_definition_digest, &profile.state_fence)
            || query.state_fence != profile.state_fence
            || query.question != profile.question
            || query.question_scope != profile.scope
            || query.allowed_references.state_fence != profile.state_fence
            || query.allowed_references.digest != profile.reference_manifest_digest
        {
            return Err(InquiryGovernanceError::InvalidField {
                field: "query.profile_binding",
            }
            .into());
        }
        let job = self.exchange.submit(query)?;
        Ok((job, receipt.clone()))
    }

    /// Imports a provider bundle only through the normal exchange state
    /// machine. Callers that own an admitted bridge must first validate the
    /// bundle against that bridge's terminal result frame; an `Accepted` job
    /// is never treated as completed here.
    pub fn import_completed_bundle(
        &mut self,
        bundle: eliot_research_exchange_api::ResearchEvidenceBundle,
    ) -> Result<ExchangeJob, GovernedInquiryError> {
        Ok(self.exchange.import_bundle(bundle)?)
    }

    /// Reads a completed job with a materialized result, rejecting an
    /// acknowledgement-only `Accepted` job.
    pub fn completed_job(&self, job_id: &str) -> Result<ExchangeJob, GovernedInquiryError> {
        Ok(self.exchange.completed_job(job_id)?)
    }

    /// Cancels only a job accepted through the governed composition path.
    pub fn cancel_governed_query(
        &mut self,
        job_id: &str,
        fence: &StateFence,
    ) -> Result<ExchangeJob, ExchangeError> {
        self.exchange.cancel(job_id, fence)
    }
}

#[must_use]
pub fn manifest(
    run_id: impl Into<String>,
    fence: StateFence,
    sources: Vec<String>,
    digest: impl Into<String>,
) -> AllowedReferenceManifest {
    AllowedReferenceManifest {
        run_id: run_id.into(),
        state_fence: fence,
        source_handles: sources,
        evidence_handles: Vec::new(),
        artifact_handles: Vec::new(),
        allowed_anchor_precision: AnchorPrecision::Section,
        stale_or_revoked_handles: Vec::new(),
        digest: digest.into(),
    }
}
