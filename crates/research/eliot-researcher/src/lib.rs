//! Researcher composition root.
//!
//! Researcher owns acquisition requests, the frozen evidence portfolio, the
//! typed `R6` inquiry-governance domain and the confirmatory/exploratory lane
//! registration that gates a confirmatory claim. It does not interpret claims,
//! promote memory, own a work graph, or bypass the exchange fence.

#![forbid(unsafe_code)]

// `admitted_excerpt` is declared first because `evidence_portfolio` and
// `inquiry_governance` both name its types in their own public surfaces; module
// declaration order is not a dependency in Rust, but naming the reason here
// stops a reader from "tidying" the order and losing the cross-reference.
pub mod admitted_excerpt;
pub mod evidence_portfolio;
pub mod inquiry_governance;
pub mod inquiry_lanes;
pub mod inquiry_obligations;
pub mod source_admissibility;
pub mod synthesis_input;

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
    AuthorizedManifest, AuthorizedManifestParams, CLAIM_REQUIREMENTS, ClaimCoverageMap,
    ClaimRequirement, ClaimVerdict, DimensionEvaluation, ManifestSource, MemberNoMatchResult,
    NoMatchApplicability, NoMatchDimension, NoMatchEvaluation, NoMatchEvaluationIssuer,
    NoMatchEvaluationIssuerParams, ObservedOutsideScope, RequirementOutcome,
    UnsupportedPrecisionItem, audit_claim, audit_claim_with_excerpts,
};
// The retained-original and exact-excerpt verification surface. Exported because
// the governed source-admission/persistence owner outside this crate has to be
// able to hand in a `RetainedSourceRevision` and read back the typed
// `OccurrenceFailure` values, and because a release consumer asking "was this
// crop detected" reads `OccurrenceCheck` rather than prose.
pub use admitted_excerpt::{
    AdmittedExcerpt, AdmittedExcerptParams, ContextAxis, ContextFinding, ExcerptPosition,
    OccurrenceCheck, OccurrenceFailure, RetainedSourceRevision, RetainedSourceRevisionParams,
    SnippetRegion, verify_excerpt_occurrence,
};
// The `R6` typed inquiry-governance surface. Every field type a consumer reads
// off an exported record is nameable here, so the domain can be consumed without
// reaching into a module path for a vocabulary it must match on.
pub use inquiry_governance::{
    AbsenceEvidence, AcquisitionOutcome, BlindedField, CandidateEvidence, ClaimAuditRecord,
    CounterSearchStatus, CoverageGoal, CoverageReceipt, CoverageReceiptParams, DenominatorKind,
    EnumerationState, EvidenceFreeze, EvidenceFreezeParams, EvidenceGrade, EvidenceSetPrecision,
    FreezeMemberReceipt, GovernorInquiryAdmissionRequest, HypothesisPolicy,
    IndependenceBlindingPolicy, IndependenceDimension, IndependenceDimensionMeasurement,
    IndependenceProfile, InquiryError, InquiryGovernance, InquiryHorizon, InquiryLane,
    InquiryObservation, InquiryOutputContract,
    InquiryProtocol, InquiryProtocolProfile, InquiryRisk, InquirySelectionFeatures,
    InquiryStopRule, InquiryTerminalRecord, InquiryUncertainty, LaneDisciplineOutcome,
    MissingSourceClass, PreservedNextProbe, PreservedUnknown, RESEARCH_GATE_FAMILY,
    ReopenCondition, ResearchDebt, ResearchDebtKind, ResearchDebtRegistrationRequest,
    ResearchDebtRestriction, ResearchGateRecord, ResearchGateStatus, SourcePortfolio,
    SpecialistDiscoverability, StopRuleKind, StreamEvidence, UnadmittedReference,
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
    FreezeCommitment, GovernorSourceTransitionRequest, PresentedReference, RecordReferenceSurface,
    SourceAdmissibilityReason, SourceAdmissibilityRecord, SourceEligibility, SourceIndependence,
    SourceLimits, SourceTaint, admits_record_reference, record_references,
};
// The committed-freeze proof and the governed synthesis-input pack. Exported
// because the composition root that admits a synthesis run reads the pack, and
// because a consumer asking "was the freeze committed before synthesis" reads
// `CommittedFreeze` rather than reconstructing one from request fields.
pub use synthesis_input::{
    CommittedFreeze, CommittedFreezeMember, PackLimitation, PackMember, PackOmission,
    SynthesisInputPack,
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
        self.request_reopening(
            exchange_id,
            bridge_generation,
            idempotency_key,
            requester_principal,
            fence,
            question,
            scope,
            expected_decision,
            source_classes,
            allowed_references,
            budget_units,
            deadline_ms,
            None,
            None,
        )
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
    /// [`Self::request`] delegates here with both halves `None`, which is the
    /// honest first-freeze state; a caller that HAS a predecessor and a reason
    /// names them here. One function rather than two keeps a single producer of
    /// the pair, so a half-declared relation is impossible on this façade for
    /// the same reason it is impossible on the request.
    ///
    /// # Errors
    ///
    /// Propagates [`ResearchContractError::InvalidDigest`] for a predecessor that
    /// is not a lowercase SHA-256 digest and
    /// [`ResearchContractError::FieldNotAccepted`] for a half-present pair, both
    /// from the exchange's own validation of the request this builds, plus every
    /// [`ExchangeError`] the underlying submit produces.
    #[allow(clippy::too_many_arguments)]
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
        predecessor_freeze_digest: Option<String>,
        reopen_reason: Option<String>,
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
            // The reopen pair moves together or not at all: `request` supplies
            // both halves as `None` (the honest first-freeze state) and a caller
            // reopening a prior freeze supplies both. `validate` refuses the
            // half-present pair at the exchange boundary, so neither half can
            // be published on its own.
            predecessor_freeze_digest,
            reopen_reason,
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
