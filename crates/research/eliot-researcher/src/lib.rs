//! Researcher composition root.
//!
//! Researcher owns acquisition requests, the frozen evidence portfolio, the
//! typed `R6` inquiry-governance domain and the confirmatory/exploratory lane
//! registration that gates a confirmatory claim. It does not interpret claims,
//! promote memory, own a work graph, or bypass the exchange fence.

#![forbid(unsafe_code)]

pub mod evidence_portfolio;
pub mod inquiry_governance;
pub mod inquiry_lanes;
pub mod inquiry_obligations;
pub mod source_admissibility;

use eliot_contracts::StateFence;
use eliot_research_exchange::{ExchangeError, ExchangeJob, GovernedExchange, ResearchBridge};
use eliot_research_exchange_api::{
    AllowedReferenceManifest, AnchorPrecision, DisclosureClass, ResearchContractError,
    ResearchQueryRequest, SourceClass,
};

// The `R6` typed inquiry-governance surface. Every field type a consumer reads
// off an exported record is nameable here, so the domain can be consumed without
// reaching into a module path for a vocabulary it must match on.
pub use inquiry_governance::{
    AcquisitionOutcome, BlindedField, CandidateEvidence, ClaimAuditRecord, CounterSearchStatus,
    CoverageGoal, CoverageReceipt, DenominatorKind, EvidenceFreeze, EvidenceGrade,
    EvidenceSetPrecision, GovernorInquiryAdmissionRequest, HypothesisPolicy,
    IndependenceBlindingPolicy, IndependenceDimension, IndependenceProfile, InquiryError,
    InquiryGovernance, InquiryHorizon, InquiryLane, InquiryObservation, InquiryOutputContract,
    InquiryProtocol, InquiryProtocolProfile, InquiryRisk, InquirySelectionFeatures,
    InquiryStopRule, InquiryTerminalRecord, InquiryUncertainty, MissingSourceClass,
    PreservedNextProbe, PreservedUnknown, ReopenCondition, ResearchDebt, ResearchDebtKind,
    SourcePortfolio, SpecialistDiscoverability, StopRuleKind, StreamEvidence, UnadmittedReference,
    UnadmittedReferenceKind, VerifierStrength,
};
pub use inquiry_lanes::{
    AttemptOutcome, AttemptRecord, AttemptRecordParams, BlindedDelivery, BlindedDeliveryParams,
    BlindingApplication, ConfirmatoryClaimKind, ConfirmatoryExposureAuthorization,
    ConfirmatoryLaneClaim, ConfirmatoryReleaseRequest, DeterministicAssignmentRule,
    DeviationAllowance, DeviationDisposition, DeviationRecord, DeviationRecordParams,
    DeviationScope, ExclusionAndQualityControl, ExploratoryFinding, ExploratoryRelease,
    ExposureChannel, ExposureEvent, ExposureEventKind, ExposureEventParams, ExposureLedger,
    GradeChangeKind, GradeRequirementChange, GradeRevisionOutcome, InquiryLaneDiscipline,
    LaneEvidenceClass, LanePartition, LanePartitionParams, LaneRegistration, LaneRegistrationError,
    LaneRegistrationParams, LaneReleaseAuthorization, OrderedSubjectKind, OwnerOrderingReceipt,
    OwnerOrderingReceiptParams, PartitionAssignment, PartitionSide, PrimaryOutcomeRule,
    RegistrationDigests, SealedBlindingMapping, SealedBlindingMappingParams,
};
pub use inquiry_obligations::{
    AcceptanceCertificateKind, InquiryObligation, InquiryObligationStatus,
    TaskGraphCompilationInputs,
};
pub use source_admissibility::{
    GovernorSourceTransitionRequest, SourceAdmissibilityReason, SourceAdmissibilityRecord,
    SourceEligibility, SourceIndependence, SourceLimits, SourceTaint,
};

pub struct Researcher<B> {
    exchange: GovernedExchange<B>,
}

impl<B> Researcher<B> {
    pub fn new(bridge: B) -> Self {
        Self {
            exchange: GovernedExchange::new(bridge),
        }
    }
    pub fn from_exchange(exchange: GovernedExchange<B>) -> Self {
        Self { exchange }
    }
    #[must_use]
    pub fn exchange(&self) -> &GovernedExchange<B> {
        &self.exchange
    }
    pub fn exchange_mut(&mut self) -> &mut GovernedExchange<B> {
        &mut self.exchange
    }
    pub fn into_exchange(self) -> GovernedExchange<B> {
        self.exchange
    }
}

impl<B: ResearchBridge> Researcher<B> {
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

/// Opens a run-bound reference allowlist over one inquiry.
///
/// I21.7: the digest is **not** a parameter. The allowlist is sealed over its own
/// content here, so every field that can change what a citation is allowed to
/// say is inside the digest preimage and a caller cannot present a digest that
/// disagrees with the handles, precision ceiling, classes and State Fence the
/// manifest actually carries.
///
/// The derived fields are the weakest values that keep the manifest honest: a
/// document-level anchor precision, an explicit root context revision, the
/// narrowest-but-one disclosure class, an explicit retention class, and no
/// admitted URL, tool definition, verifier or expansion route. A run that
/// admits none of those admits none of them.
///
/// # Errors
///
/// Returns [`ResearchContractError`] when the sealed content cannot be encoded
/// into its canonical preimage.
pub fn manifest(
    run_id: impl Into<String>,
    fence: StateFence,
    sources: Vec<String>,
    root_context_revision: impl Into<String>,
    scope_class: impl Into<String>,
    retention_class: impl Into<String>,
) -> Result<AllowedReferenceManifest, ResearchContractError> {
    AllowedReferenceManifest {
        run_id: run_id.into(),
        root_context_revision: root_context_revision.into(),
        state_fence: fence,
        source_handles: sources,
        evidence_handles: Vec::new(),
        artifact_handles: Vec::new(),
        url_handles: Vec::new(),
        tool_refs: Vec::new(),
        verifier_refs: Vec::new(),
        allowed_anchor_precision: AnchorPrecision::Document,
        scope_class: scope_class.into(),
        disclosure: DisclosureClass::ProjectBound,
        retention_class: retention_class.into(),
        stale_or_revoked_handles: Vec::new(),
        expansion_routes: Vec::new(),
        digest: String::new(),
    }
    .seal()
}
