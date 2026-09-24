//! Researcher composition root.
//!
//! Researcher owns acquisition requests and bridge composition only. It does
//! not interpret claims, promote memory, or bypass the exchange fence.

#![forbid(unsafe_code)]

pub mod evidence_portfolio;
pub mod inquiry_governance;
pub mod inquiry_obligations;
pub mod source_admissibility;

use eliot_contracts::StateFence;
use eliot_research_exchange::{ExchangeError, ExchangeJob, GovernedExchange, ResearchBridge};
use eliot_research_exchange_api::{
    AllowedReferenceManifest, AnchorPrecision, DisclosureClass, ResearchQueryRequest, SourceClass,
};

pub use inquiry_governance::{
    BudgetDeadlineStopRule, CoverageGoal, EvidenceGrade, GovernorProfileAdmissionRequest,
    HypothesisPolicy, IndependenceBlindingPolicy, InquiryGovernance, InquiryGovernanceError,
    InquiryHorizon, InquiryLane, InquiryProtocol, InquiryProtocolProfile,
    InquiryProtocolProfileParams, InquiryRisk, InquirySelectionFeatures, InquiryUncertainty,
    OutputContractAndReopenConditions, SpecialistDiscoverability, VerifierStrength,
    select_protocol,
};
pub use inquiry_obligations::{
    AcceptanceCertificate, AcceptanceCertificateKind, InquiryObligation, InquiryObligationInput,
    InquiryObligationStatus, TaskGraphCompilationReceipt, TaskGraphCompiler,
};
pub use source_admissibility::{
    GovernorSourceAdmissionRequest, SourceAdmissibilityReason, SourceAdmissibilityRecord,
    SourceEligibility, SourceLimits, SourceProposal, SourceProvenance, SourceTaint,
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
    pub fn from_exchange(exchange: GovernedExchange<B>) -> Self {
        Self {
            exchange,
            governance: InquiryGovernance::new(),
        }
    }
    #[must_use]
    pub fn exchange(&self) -> &GovernedExchange<B> {
        &self.exchange
    }
    pub fn exchange_mut(&mut self) -> &mut GovernedExchange<B> {
        &mut self.exchange
    }
    /// Read-only view of the runtime-local R6 governance registry.
    #[must_use]
    pub fn governance(&self) -> &InquiryGovernance {
        &self.governance
    }
    /// Mutable view for the Researcher-owned governance registry.
    pub fn governance_mut(&mut self) -> &mut InquiryGovernance {
        &mut self.governance
    }
    pub fn into_exchange(self) -> GovernedExchange<B> {
        self.exchange
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

    /// Compiles profile-bound obligations through the existing work-graph port.
    pub fn compile_obligations<C: TaskGraphCompiler>(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        inputs: &[InquiryObligationInput],
        compiler_id: impl Into<String>,
        compiler: &mut C,
    ) -> Result<TaskGraphCompilationReceipt, InquiryGovernanceError> {
        self.governance.compile_obligations(
            profile_id,
            profile_revision,
            inputs,
            compiler_id,
            compiler,
        )
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
    pub fn submit_governed_query<C: TaskGraphCompiler>(
        &mut self,
        profile_id: &str,
        profile_revision: u64,
        obligations: &[InquiryObligationInput],
        compiler_id: impl Into<String>,
        compiler: &mut C,
        query: ResearchQueryRequest,
    ) -> Result<(ExchangeJob, TaskGraphCompilationReceipt), GovernedInquiryError> {
        let profile = self
            .governance
            .profile(profile_id, profile_revision)
            .ok_or_else(|| InquiryGovernanceError::UnknownProfile {
                profile_id: profile_id.to_owned(),
                revision: profile_revision,
            })?;
        if query.state_fence != profile.state_fence
            || query.question != profile.question
            || query.question_scope != profile.scope
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
            compiler_id,
            compiler,
        )?;
        let job = self.exchange.submit(query)?;
        Ok((job, receipt))
    }

    pub fn submit_query(
        &mut self,
        query: ResearchQueryRequest,
    ) -> Result<ExchangeJob, ExchangeError> {
        self.exchange.submit(query)
    }

    // Keep the protocol façade's explicit request fields stable; grouping them
    // would broaden the public call-surface change beyond this lint fix.
    #[allow(clippy::too_many_arguments)]
    pub fn request(
        &mut self,
        exchange_id: impl Into<String>,
        bridge_generation: impl Into<String>,
        idempotency_key: impl Into<String>,
        requester_principal: impl Into<String>,
        fence: StateFence,
        question: impl Into<String>,
        scope: impl Into<String>,
        expected_decision: impl Into<String>,
        source_classes: Vec<SourceClass>,
        allowed_references: AllowedReferenceManifest,
        budget_units: u64,
        deadline_ms: i64,
    ) -> Result<ExchangeJob, ExchangeError> {
        self.submit_query(ResearchQueryRequest {
            exchange_id: exchange_id.into(),
            protocol_revision: eliot_research_exchange_api::CONTRACT_VERSION,
            bridge_generation: bridge_generation.into(),
            idempotency_key: idempotency_key.into(),
            requester_principal: requester_principal.into(),
            state_fence: fence,
            question: question.into(),
            question_scope: scope.into(),
            expected_decision: expected_decision.into(),
            source_classes,
            coverage_goal: "bounded exact sources with explicit unknowns".into(),
            allowed_references,
            disclosure: DisclosureClass::ProjectBound,
            retention: "governed-by-caller".into(),
            license_policy: "caller-policy".into(),
            budget_units,
            deadline_ms,
            required_schema: "research-evidence-bundle/v1".into(),
        })
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
