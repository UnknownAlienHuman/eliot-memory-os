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

// The coverage-account vocabulary `R6` publishes on its records: the observed
// population the account learns, the owner-bound absence preconditions and the
// verdict they produce. Referenced, never redefined here.
//
// `NoMatchEvaluationParams` is deliberately absent from this list. It is
// crate-private with `NoMatchEvaluation::issue`, because a public one is a
// public way to hand-assemble the record that
// `NoMatchEvaluationIssuer::issue_for` exists to issue. `NoMatchEvaluation`
// itself stays public because a consumer reads the record off
// `AbsencePreconditions`; it can no longer be constructed from outside.
//
// `NoMatchEvaluationIssuer`, its named-argument params and
// `AuthorizedManifest` ARE exported, because they are the three values the
// evaluator/denominator owner outside this crate needs in order to issue a
// record at all. They are nameable from here so a positive case is expressible
// from outside the crate; `issue_for` remains the only construction path for the
// record itself, so exporting them widens the surface a holder needs and
// removes no door.
pub use evidence_portfolio::{
    AbsencePreconditions, AbsenceVerdict, AuditBindingError, AuditReferenceBinding,
    AuthorizedManifest, AuthorizedManifestParams, CLAIM_REQUIREMENTS, ClaimRequirement,
    DimensionEvaluation, ManifestSource, MemberNoMatchResult, NoMatchApplicability,
    NoMatchDimension, NoMatchEvaluation, NoMatchEvaluationIssuer, NoMatchEvaluationIssuerParams,
    ObservedOutsideScope, RequirementOutcome, UnsupportedPrecisionItem,
};
// The `R6` typed inquiry-governance surface. Every field type a consumer reads
// off an exported record is nameable here, so the domain can be consumed without
// reaching into a module path for a vocabulary it must match on.
pub use inquiry_governance::{
    AbsenceEvidence, AcquisitionOutcome, BlindedField, CandidateEvidence, ClaimAuditRecord,
    CounterSearchStatus, CoverageGoal, CoverageReceipt, CoverageReceiptParams, DenominatorKind,
    EnumerationState, EvidenceFreeze, EvidenceFreezeParams, EvidenceGrade, EvidenceSetPrecision,
    GovernorInquiryAdmissionRequest, HypothesisPolicy, IndependenceBlindingPolicy,
    IndependenceDimension, IndependenceDimensionMeasurement, IndependenceProfile, InquiryError,
    InquiryGovernance, InquiryHorizon, InquiryLane, InquiryObservation, InquiryOutputContract,
    InquiryProtocol, InquiryProtocolProfile, InquiryRisk, InquirySelectionFeatures,
    InquiryStopRule, InquiryTerminalRecord, InquiryUncertainty, LaneDisciplineOutcome,
    MissingSourceClass, PreservedNextProbe, PreservedUnknown, ReopenCondition, ResearchDebt,
    ResearchDebtKind, ResearchDebtRestriction, SourcePortfolio, SpecialistDiscoverability,
    StopRuleKind, StreamEvidence, UnadmittedReference, UnadmittedReferenceKind, VerifierStrength,
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
// The committed registration a profile revision is given. It is a read-only
// value here: the only way to obtain one is this crate's own profile-resolution
// path, which is what keeps a caller from declaring a confirmatory lane by
// supplying a digest.
pub use inquiry_lanes::CommittedLaneRegistration;
pub use inquiry_obligations::{
    AcceptanceCertificateKind, InquiryObligation, InquiryObligationStatus,
    TaskGraphCompilationInputs,
};
pub use source_admissibility::{
    GovernorSourceTransitionRequest, PresentedReference, RecordReferenceSurface,
    SourceAdmissibilityReason, SourceAdmissibilityRecord, SourceEligibility, SourceIndependence,
    SourceLimits, SourceTaint, admits_record_reference, record_references,
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
        // The request inherits the manifest's retention class rather than
        // declaring one of its own. `ResearchQueryRequest::validate` requires
        // `allowed_references.retention_class == retention`, so a façade that
        // hardcoded a retention string guaranteed a refusal for every manifest
        // `manifest()` builds with any other one, and that refusal did not name
        // either field. As with `disclosure` below, the run-bound manifest is
        // the authority for the classes a run declares and the façade only fills
        // in the protocol boilerplate around it.
        let retention = allowed_references.retention_class.clone();
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
            retention,
            license_policy: "caller-policy".into(),
            budget_units,
            deadline_ms,
            required_schema: "research-evidence-bundle/v1".into(),
            // A first freeze is the honest state for a request admitted without a
            // predecessor. `request` is the first-freeze façade: it has no prior
            // freeze to reopen and takes no predecessor argument, so it declares
            // neither half rather than inventing one. The reopen-aware producer
            // is `request_reopening`, and a caller that has a predecessor and a
            // reason must use it.
            predecessor_freeze_digest: None,
            reopen_reason: None,
        })
    }

    /// Submits a query that reopens a prior evidence freeze.
    ///
    /// I21.8: "New material, materially changed source content or changed
    /// protocol requires a recorded reopen/successor freeze with reason and
    /// expected revision. It must not mutate a prior brief or audit." The two
    /// facts that make a reopen a reopen — which freeze it supersedes and why —
    /// have to be **declared by the requester**, and the only place they can be
    /// declared is on the admitted request: the consumer
    /// (`inquiry_governance::freeze_predecessor`) reads them from there and
    /// invents neither, and `ResearchQueryRequest::validate` refuses the
    /// half-present pair at the exchange boundary.
    ///
    /// This is therefore the production producer of the pair on the live path,
    /// and it is a separate entry point rather than a parameter on
    /// [`Self::request`] on purpose: an inherited `Option` there would let the
    /// first-freeze path carry a half-declared relation by accident, and the
    /// whole point of the pair is that it is either fully declared or absent.
    ///
    /// # Errors
    ///
    /// Propagates [`ResearchContractError::InvalidDigest`] for a predecessor that
    /// is not a lowercase SHA-256 digest and
    /// [`ResearchContractError::InvalidText`] for a blank or control-bearing
    /// reason, both from the exchange's own validation of the request this
    /// builds, plus every [`ExchangeError`] the underlying submit produces.
    pub fn request_reopening(
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
        predecessor_freeze_digest: impl Into<String>,
        reopen_reason: impl Into<String>,
    ) -> Result<ExchangeJob, ExchangeError> {
        // Same protocol boilerplate as `request`, with the reopen pair supplied
        // by the caller instead of hardcoded to a first freeze. The retention
        // class is still inherited from the manifest for the same reason
        // `request` inherits it: the run-bound manifest is the authority for the
        // class a run declares.
        let retention = allowed_references.retention_class.clone();
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
            retention,
            license_policy: "caller-policy".into(),
            budget_units,
            deadline_ms,
            required_schema: "research-evidence-bundle/v1".into(),
            predecessor_freeze_digest: Some(predecessor_freeze_digest.into()),
            reopen_reason: Some(reopen_reason.into()),
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
/// # The anchor ceiling is `Document`, and that is a change
///
/// This helper used to stamp `AnchorPrecision::Section`. It now stamps
/// `Document`, and the reason belongs here rather than in a diff: `Section` was
/// a pre-firewall default with nothing behind it, while the ceiling is now
/// load-bearing. `AnchorPrecision::permits` is a `>=` test, so a `Section`
/// ceiling lets a delivered bundle anchor a citation at a section without any
/// Governor-admitted support at that granularity ever existing. `Document`
/// refuses the same delivery with `CitationNotAllowed` at
/// `ResearchEvidenceBundle::validate_against`, which is the honest answer for a
/// manifest nobody has sealed against a support relation finer than the
/// document. A run that genuinely admits section anchors should not use this
/// weakest-manifest constructor; it should build the manifest itself and seal
/// it, which is the only thing that can widen a ceiling on the record.
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
        // The weakest honest ceiling, and lower than this helper used to stamp:
        // see "The anchor ceiling is `Document`" above before widening it.
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
