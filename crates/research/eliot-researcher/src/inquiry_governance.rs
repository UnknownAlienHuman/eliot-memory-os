//! R6 typed inquiry-governance domain for the Researcher plane (issue #1762).
//!
//! This module is the research-domain half of Smart runtime layer `R6`. It owns
//! the typed decision side of one inquiry: resolution and revision of the
//! versioned [`InquiryProtocolProfile`], the frozen [`SourcePortfolio`] and
//! [`CoverageReceipt`], the terminal typed [`InquiryTerminalRecord`] with its
//! reopen and next-probe preservation, the compiler inputs for the open
//! inquiry obligations, and the non-canonical governed artifacts
//! ([`EvidenceFreeze`], [`ClaimAuditRecord`], [`ResearchDebt`]). Source
//! admissibility itself lives in [`crate::source_admissibility`].
//!
//! Everything here is candidate-only. The domain emits
//! [`GovernorInquiryAdmissionRequest`] and source transition requests for the
//! existing Governor admission path; it never writes canonical state, never
//! finishes a task, never schedules, never owns memory and never promotes its
//! own output. `R6` is a capability plane inside Smart, not a fifth plane and
//! not a second Governor.
//!
//! Reuse over re-creation is deliberate. The evidence-grade ladder, the exact
//! coverage accounting, the absence assessment, the vetted source record with
//! its provenance and limits, the typed completion dispositions, the precision
//! residue items and the claim verdicts already have owners in
//! [`crate::evidence_portfolio`] and in `eliot-research-exchange-api`. This
//! module references them, binds them to an inquiry profile, a State Fence and
//! a reference manifest, and adds only what the `R6` boundary genuinely owns.
//!
//! No work graph is defined here.
//! [`crate::inquiry_obligations::TaskGraphCompilationInputs`] carries compiler
//! *inputs* for the existing deterministic `TaskGraphCompiler` (I10.15); a
//! researcher-local compiler, a second graph, an order, a lease and a schedule
//! are all outside this crate's ownership.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::StateFence;
use eliot_research_exchange_api::{
    AllowedReferenceManifest, AnchorPrecision, CompletionDisposition, DisclosureClass,
    ResearchContractError, SourceClass,
};

use crate::evidence_portfolio::{
    AbsenceVerdict, ClaimVerdict, CoverageAccount, LineageTable, PortfolioError,
    PrecisionAssertion, PrecisionKind, RiskState, SourceDisposition, SourceRecord,
    SourceRecordParams, UnsupportedPrecisionItem, assess_absence, check_precision, digest, freeze,
    grade_name, grade_rank, push_count, push_field, reject_vague, text,
};
use crate::inquiry_obligations::{
    AcceptanceCertificateKind, InquiryObligation, InquiryObligationParams, InquiryObligationStatus,
    TaskGraphCompilationInputs,
};
use crate::source_admissibility::{
    GovernorSourceTransitionRequest, SourceAdmissibilityRecord, SourceEligibility,
};

/// Stable identity of this domain surface.
pub const INQUIRY_GOVERNANCE_CONTRACT: &str = "eliot.research.inquiry-governance";
/// Current revision of this domain surface.
pub const INQUIRY_GOVERNANCE_VERSION: &str = "1.0.0";

/// Typed inquiry-governance failure. Every variant names the failing concept or
/// field path only; no supplied value is ever echoed back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InquiryError {
    /// A required value is empty, whitespace-only or control-bearing.
    Blank {
        /// Failing field path.
        field: &'static str,
    },
    /// A value is not lowercase SHA-256 hex.
    BadDigest {
        /// Failing field path.
        field: &'static str,
    },
    /// A scope spelling claims coverage without declaring a denominator.
    VagueScope {
        /// Failing field path.
        field: &'static str,
    },
    /// A grade name is not one of the four canonical frozen names.
    UnknownGrade,
    /// A declared grade requirement exceeds what its own inputs allow.
    GradeCeiling {
        /// Failing field path.
        field: &'static str,
    },
    /// A closed-vocabulary value is not a member of its vocabulary.
    UnknownVocabulary {
        /// Failing field path.
        field: &'static str,
    },
    /// A revision was requested without the reason I21.2 requires.
    RevisionRequiresReason,
    /// An identity is already bound to other content, or a revision changed the
    /// inquiry the profile governs.
    Duplicate {
        /// Failing field path.
        field: &'static str,
    },
    /// A referenced identity is absent from the set that must contain it.
    UnknownHandle {
        /// Failing field path.
        field: &'static str,
    },
    /// The frozen denominator is empty or otherwise unusable.
    IncompleteDenominator {
        /// Failing field path.
        field: &'static str,
    },
    /// A terminal disposition is open but preserves no unknown, narrower claim
    /// and no next probe.
    PreservationRequired {
        /// Failing field path.
        field: &'static str,
    },
    /// A terminal disposition tries to close on a denominator that is not a
    /// complete scope.
    ClosureWithoutCompleteScope {
        /// Failing field path.
        field: &'static str,
    },
    /// A confirmatory lane was declared without a frozen registration.
    LaneRegistrationRequired {
        /// Failing field path.
        field: &'static str,
    },
    /// The recomputed digest of a record does not match its own content.
    IntegrityMismatch {
        /// Failing field path.
        field: &'static str,
    },
    /// The frozen acquisition-side discipline refused the material.
    Portfolio(PortfolioError),
    /// The exchange contract refused the admitted reference manifest.
    ///
    /// I21.7: the run-bound `AllowedReferenceManifest` is a mandatory input, so
    /// a malformed manifest, or one whose digest does not cover its own content,
    /// is refused here rather than being published as a bound allowlist.
    Contract(ResearchContractError),
}

impl std::fmt::Display for InquiryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blank { field } => write!(formatter, "{field} is required"),
            Self::BadDigest { field } => {
                write!(formatter, "{field} is not a lowercase SHA-256 digest")
            }
            Self::VagueScope { field } => {
                write!(
                    formatter,
                    "{field} claims coverage without a declared denominator"
                )
            }
            Self::UnknownGrade => formatter.write_str("evidence grade is not a canonical name"),
            Self::GradeCeiling { field } => {
                write!(formatter, "{field} exceeds the ceiling its inputs allow")
            }
            Self::UnknownVocabulary { field } => {
                write!(
                    formatter,
                    "{field} is not a member of its closed vocabulary"
                )
            }
            Self::RevisionRequiresReason => formatter
                .write_str("a profile revision or grade supersession requires a recorded reason"),
            Self::Duplicate { field } => write!(formatter, "{field} is already bound"),
            Self::UnknownHandle { field } => {
                write!(formatter, "{field} is not part of the frozen set")
            }
            Self::IncompleteDenominator { field } => {
                write!(formatter, "{field} does not close the frozen denominator")
            }
            Self::PreservationRequired { field } => {
                write!(
                    formatter,
                    "{field} must preserve an unknown, narrower claim or next probe"
                )
            }
            Self::ClosureWithoutCompleteScope { field } => {
                write!(
                    formatter,
                    "{field} cannot close without a complete-scope denominator"
                )
            }
            Self::LaneRegistrationRequired { field } => {
                write!(formatter, "{field} requires a frozen lane registration")
            }
            Self::IntegrityMismatch { field } => {
                write!(
                    formatter,
                    "{field} does not match its own recomputed digest"
                )
            }
            Self::Portfolio(error) => write!(formatter, "frozen portfolio discipline: {error}"),
            Self::Contract(error) => {
                write!(formatter, "reference manifest contract: {error}")
            }
        }
    }
}

impl std::error::Error for InquiryError {}

impl From<PortfolioError> for InquiryError {
    fn from(error: PortfolioError) -> Self {
        Self::Portfolio(error)
    }
}

impl From<ResearchContractError> for InquiryError {
    fn from(error: ResearchContractError) -> Self {
        Self::Contract(error)
    }
}

fn require_text(value: &str, field: &'static str) -> Result<(), InquiryError> {
    text(value, field).map_err(InquiryError::from)
}

fn require_digest(value: &str, field: &'static str) -> Result<(), InquiryError> {
    digest(value, field).map_err(InquiryError::from)
}

fn require_scope(value: &str, field: &'static str) -> Result<(), InquiryError> {
    text(value, field).map_err(InquiryError::from)?;
    reject_vague(value, field).map_err(InquiryError::from)
}

fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

/// Canonical grade on the frozen I21.2 ladder.
///
/// The ladder itself has exactly one owner,
/// [`crate::evidence_portfolio::GRADE_ORDER`], which references the canonical
/// epistemic-contract names. This type is a checked handle onto that rank, not
/// a second enumeration of the four grades.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EvidenceGrade {
    rank: u8,
}

impl EvidenceGrade {
    /// The weakest grade, `ORIENTING`, at rank zero.
    pub const ORIENTING: Self = Self { rank: 0 };

    /// Resolves one frozen grade name onto its canonical rank.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::UnknownGrade`] when the name is not one of the
    /// four canonical frozen names.
    pub fn from_name(name: &str) -> Result<Self, InquiryError> {
        grade_rank(name)
            .map(|rank| Self { rank })
            .map_err(|_| InquiryError::UnknownGrade)
    }

    /// Resolves one canonical rank.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::UnknownGrade`] when the rank is outside the
    /// frozen ladder.
    pub fn from_rank(rank: u8) -> Result<Self, InquiryError> {
        grade_name(rank).map_err(|_| InquiryError::UnknownGrade)?;
        Ok(Self { rank })
    }

    /// The canonical weakest-first rank of this grade.
    #[must_use]
    pub const fn rank(self) -> u8 {
        self.rank
    }

    /// The canonical frozen name of this grade.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::UnknownGrade`] when the rank is outside the
    /// frozen ladder, which construction already excludes.
    pub fn name(self) -> Result<&'static str, InquiryError> {
        grade_name(self.rank).map_err(|_| InquiryError::UnknownGrade)
    }
}

impl std::fmt::Display for EvidenceGrade {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match grade_name(self.rank) {
            Ok(name) => formatter.write_str(name),
            Err(_) => formatter.write_str("UNRESOLVED_GRADE"),
        }
    }
}

/// Inquiry protocol selected from the structure of the question (I21.3).
///
/// A single generic pipeline for every question is the most common failure of
/// research automation, so the protocol is an explicit, revisable selection
/// rather than a default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InquiryProtocol {
    /// Bounded exact or cached lookup.
    Lookup,
    /// Structured review of an existing body of evidence.
    EvidenceReview,
    /// Causal or mechanism diagnosis.
    CausalDiagnosis,
    /// Formal derivation or proof.
    FormalProof,
    /// Synthesis of a program or design space.
    ProgramSynthesis,
    /// An architecture or boundary decision.
    ArchitectureDecision,
    /// Search for an algorithm or design under constraints.
    AlgorithmSearch,
    /// Discovery of an empirical regularity.
    EmpiricalDiscovery,
    /// Development of a theory.
    TheoryDevelopment,
    /// Support for a pending decision.
    DecisionSupport,
}

/// Every protocol in canonical order, so the closed vocabulary has exactly one
/// spelling table and no variant can drift out of it.
const INQUIRY_PROTOCOLS: [InquiryProtocol; 10] = [
    InquiryProtocol::Lookup,
    InquiryProtocol::EvidenceReview,
    InquiryProtocol::CausalDiagnosis,
    InquiryProtocol::FormalProof,
    InquiryProtocol::ProgramSynthesis,
    InquiryProtocol::ArchitectureDecision,
    InquiryProtocol::AlgorithmSearch,
    InquiryProtocol::EmpiricalDiscovery,
    InquiryProtocol::TheoryDevelopment,
    InquiryProtocol::DecisionSupport,
];

impl InquiryProtocol {
    /// Stable wire spelling of this protocol.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Lookup => "lookup",
            Self::EvidenceReview => "evidence_review",
            Self::CausalDiagnosis => "causal_diagnosis",
            Self::FormalProof => "formal_proof",
            Self::ProgramSynthesis => "program_synthesis",
            Self::ArchitectureDecision => "architecture_decision",
            Self::AlgorithmSearch => "algorithm_search",
            Self::EmpiricalDiscovery => "empirical_discovery",
            Self::TheoryDevelopment => "theory_development",
            Self::DecisionSupport => "decision_support",
        }
    }

    /// Every protocol, in canonical order.
    #[must_use]
    pub const fn all() -> [Self; 10] {
        INQUIRY_PROTOCOLS
    }
}

impl std::fmt::Display for InquiryProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Declared lane of one inquiry (I21.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InquiryLane {
    /// Confirmatory: a frozen protocol, evaluator and registration precede
    /// outcome exposure.
    Confirmatory,
    /// Exploratory: results are exploratory findings and may not confirm the
    /// hypothesis that generated them on the same exposure.
    Exploratory,
    /// Mixed with an explicit, frozen partition between the two sides.
    MixedWithDeclaredSplit,
}

impl InquiryLane {
    /// Stable wire spelling of this lane.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Confirmatory => "confirmatory",
            Self::Exploratory => "exploratory",
            Self::MixedWithDeclaredSplit => "mixed_with_declared_split",
        }
    }
}

impl std::fmt::Display for InquiryLane {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Declared coverage goal of one inquiry (I21.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoverageGoal {
    /// Bounded exploration with no completeness claim.
    Exploratory,
    /// A representative sample of the frozen scope.
    Representative,
    /// High recall over the frozen scope.
    HighRecall,
    /// Exhaustive enumeration of the frozen scope.
    Exhaustive,
}

impl CoverageGoal {
    /// Stable wire spelling of this coverage goal.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Exploratory => "exploratory",
            Self::Representative => "representative",
            Self::HighRecall => "high_recall",
            Self::Exhaustive => "exhaustive",
        }
    }

    /// Resolves one exact wire spelling.
    #[must_use]
    pub fn from_wire(value: &str) -> Option<Self> {
        [
            Self::Exploratory,
            Self::Representative,
            Self::HighRecall,
            Self::Exhaustive,
        ]
        .into_iter()
        .find(|goal| goal.wire_name() == value)
    }
}

impl std::fmt::Display for CoverageGoal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Declared hypothesis policy of one inquiry (I21.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HypothesisPolicy {
    /// Rival alternatives must be represented.
    AlternativesRequired,
    /// A counter-search must be run and reported.
    CounterSearchRequired,
    /// Falsification must be attempted.
    FalsificationRequired,
}

impl HypothesisPolicy {
    /// Stable wire spelling of this policy.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::AlternativesRequired => "alternatives_required",
            Self::CounterSearchRequired => "counter_search_required",
            Self::FalsificationRequired => "falsification_required",
        }
    }

    /// Whether this policy requires a counter-search to be run and reported.
    #[must_use]
    pub const fn requires_counter_search(self) -> bool {
        matches!(self, Self::CounterSearchRequired)
    }
}

/// Counter-search status recorded on a coverage receipt (I21.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CounterSearchStatus {
    /// The resolved hypothesis policy does not require one.
    NotRequired,
    /// One was required and is accounted for.
    Satisfied,
    /// One was required and is still open.
    RequiredAndOpen,
}

/// Denominator kind of one coverage receipt (I21.6).
///
/// `complete_scope` is the only basis on which a scoped absence may be claimed;
/// an indexed top-k result never narrows the denominator of an exact negative
/// claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenominatorKind {
    /// Every member of the frozen scope was enumerated and closed intact.
    CompleteScope,
    /// A declared sampling method bounded the enumeration.
    ///
    /// No current admitted path declares a sampling method, so this member of
    /// the closed vocabulary states the kind a future sampling boundary would
    /// have to declare; it is never produced by default and never used to
    /// narrow a denominator implicitly.
    SampledWithMethod,
    /// The denominator could not be established.
    Unknown,
}

impl DenominatorKind {
    /// Stable wire spelling of this denominator kind.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::CompleteScope => "complete_scope",
            Self::SampledWithMethod => "sampled_with_method",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this kind is the only basis for a scoped absence claim.
    #[must_use]
    pub const fn supports_scoped_absence(self) -> bool {
        matches!(self, Self::CompleteScope)
    }
}

impl std::fmt::Display for DenominatorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Independence dimension one inquiry profile requires (I21.3/I21.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum IndependenceDimension {
    /// Distinct source families.
    SourceFamily,
    /// Distinct provider families.
    ProviderFamily,
    /// Distinct evaluator families.
    EvaluatorFamily,
    /// Absence of a shared context ancestor.
    SharedContextAncestor,
    /// Absence of shared assumptions.
    SharedAssumptions,
}

impl IndependenceDimension {
    /// Stable wire spelling of this dimension.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::SourceFamily => "source_family",
            Self::ProviderFamily => "provider_family",
            Self::EvaluatorFamily => "evaluator_family",
            Self::SharedContextAncestor => "shared_context_ancestor",
            Self::SharedAssumptions => "shared_assumptions",
        }
    }
}

/// One leakage channel a confirmatory lane closes (I21.4).
///
/// The blinded field names one channel to close, not a universal mask, and it
/// creates no second independence model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlindedField {
    /// The preferred hypothesis.
    PreferredHypothesis,
    /// Condition labels.
    ConditionLabel,
    /// The parent conclusion.
    ParentConclusion,
    /// The holdout expected score.
    HoldoutExpectedScore,
    /// The candidate author.
    CandidateAuthor,
    /// Source prestige.
    SourcePrestige,
}

impl BlindedField {
    /// Stable wire spelling of this blinded field.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::PreferredHypothesis => "preferred_hypothesis",
            Self::ConditionLabel => "condition_label",
            Self::ParentConclusion => "parent_conclusion",
            Self::HoldoutExpectedScore => "holdout_expected_score",
            Self::CandidateAuthor => "candidate_author",
            Self::SourcePrestige => "source_prestige",
        }
    }
}

/// Stop rule one inquiry profile declares (I21.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StopRuleKind {
    /// Stop at the admitted budget or deadline ceiling.
    BudgetOrDeadlineExhausted,
    /// Stop when the frozen denominator is fully closed.
    DenominatorClosed,
    /// Stop when the declared lane's obligations are certified.
    LaneSatisfied,
    /// Stop on an admitted cancellation request.
    CancellationRequested,
}

impl StopRuleKind {
    /// Stable wire spelling of this stop rule.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::BudgetOrDeadlineExhausted => "budget_or_deadline_exhausted",
            Self::DenominatorClosed => "denominator_closed",
            Self::LaneSatisfied => "lane_satisfied",
            Self::CancellationRequested => "cancellation_requested",
        }
    }
}

/// Reopen condition one inquiry profile declares or one terminal record
/// preserves (I21.3/I21.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReopenCondition {
    /// Material new evidence became available.
    NewEvidenceAvailable,
    /// A source that was unavailable became available.
    SourceBecameAvailable,
    /// A verifier produced a counterexample.
    VerifierCounterexample,
    /// A contradiction remains unresolved.
    ContradictionUnresolved,
    /// Retained evidence went stale.
    StaleEvidence,
    /// The task contract changed.
    ContractChanged,
    /// The budget entered a new phase.
    BudgetPhaseChanged,
    /// The human issued a semantic interrupt.
    HumanSemanticInterrupt,
}

impl ReopenCondition {
    /// Stable wire spelling of this reopen condition.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::NewEvidenceAvailable => "new_evidence_available",
            Self::SourceBecameAvailable => "source_became_available",
            Self::VerifierCounterexample => "verifier_counterexample",
            Self::ContradictionUnresolved => "contradiction_unresolved",
            Self::StaleEvidence => "stale_evidence",
            Self::ContractChanged => "contract_changed",
            Self::BudgetPhaseChanged => "budget_phase_changed",
            Self::HumanSemanticInterrupt => "human_semantic_interrupt",
        }
    }
}

impl std::fmt::Display for ReopenCondition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Independence and blinding policy resolved for one inquiry (I21.3/I21.4).
///
/// The independence requirement is what a corroborated grade demands and the
/// registration facts are what a confirmatory lane demands. Both are recorded
/// as typed facts, never as prose a later reader may reinterpret, and the
/// declaration itself never claims the requirement was met.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndependenceBlindingPolicy {
    /// Dimensions independence is required on.
    pub dimensions: Vec<IndependenceDimension>,
    /// Minimum number of independent lineages the evidence set must reach.
    pub minimum_independent_families: u64,
    /// Leakage channels a confirmatory run closes.
    pub blinded_fields: Vec<BlindedField>,
    /// Assumptions every member of the evidence set is known to share.
    pub shared_assumptions: Vec<String>,
    /// Deviations registered before outcome exposure.
    pub allowed_deviations: Vec<String>,
    /// Lane registration digest, required for a confirmatory lane.
    pub lane_registration_digest: Option<String>,
    /// Whether the registration was frozen before any outcome exposure.
    pub registered_before_outcome_exposure: bool,
    /// Digest over the whole policy shape.
    pub digest: String,
}

impl IndependenceBlindingPolicy {
    /// Resolves and freezes the policy for one grade and lane.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::GradeCeiling`] when a grade below
    /// `CORROBORATED` declares a non-zero independence requirement it cannot
    /// carry, [`InquiryError::LaneRegistrationRequired`] when a confirmatory
    /// lane has no frozen registration, and a field error for blank or
    /// malformed input.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve(
        grade: EvidenceGrade,
        lane: InquiryLane,
        dimensions: Vec<IndependenceDimension>,
        minimum_independent_families: u64,
        blinded_fields: Vec<BlindedField>,
        shared_assumptions: Vec<String>,
        allowed_deviations: Vec<String>,
        lane_registration_digest: Option<String>,
    ) -> Result<Self, InquiryError> {
        let corroborated_rank = EvidenceGrade::from_name("CORROBORATED")?.rank();
        if grade.rank() < corroborated_rank && minimum_independent_families > 0 {
            return Err(InquiryError::GradeCeiling {
                field: "profile.independence_policy.minimum_independent_families",
            });
        }
        let registered_before_outcome_exposure = lane_registration_digest.is_some();
        if lane == InquiryLane::Confirmatory && !registered_before_outcome_exposure {
            return Err(InquiryError::LaneRegistrationRequired {
                field: "profile.independence_policy.lane_registration_digest",
            });
        }
        if let Some(registration) = &lane_registration_digest {
            require_digest(registration, "profile.lane_registration_digest")?;
        }
        for assumption in &shared_assumptions {
            require_text(assumption, "profile.independence_policy.shared_assumptions")?;
        }
        for deviation in &allowed_deviations {
            require_text(deviation, "profile.independence_policy.allowed_deviations")?;
        }
        let mut preimage = String::from("independence-blinding-policy/v1;");
        push_count(&mut preimage, "dimensions", dimensions.len());
        for dimension in &dimensions {
            push_field(&mut preimage, "dimension", dimension.wire_name());
        }
        push_field(
            &mut preimage,
            "minimum_independent_families",
            &minimum_independent_families.to_string(),
        );
        push_count(&mut preimage, "blinded_fields", blinded_fields.len());
        for field in &blinded_fields {
            push_field(&mut preimage, "blinded_field", field.wire_name());
        }
        push_count(
            &mut preimage,
            "shared_assumptions",
            shared_assumptions.len(),
        );
        for assumption in &shared_assumptions {
            push_field(&mut preimage, "shared_assumption", assumption);
        }
        push_count(
            &mut preimage,
            "allowed_deviations",
            allowed_deviations.len(),
        );
        for deviation in &allowed_deviations {
            push_field(&mut preimage, "allowed_deviation", deviation);
        }
        if let Some(registration) = &lane_registration_digest {
            push_field(&mut preimage, "lane_registration", registration);
            push_field(
                &mut preimage,
                "registered_before_outcome_exposure",
                bool_text(registered_before_outcome_exposure),
            );
        }
        Ok(Self {
            dimensions,
            minimum_independent_families,
            blinded_fields,
            shared_assumptions,
            allowed_deviations,
            lane_registration_digest,
            registered_before_outcome_exposure,
            digest: freeze(&preimage),
        })
    }
}

/// Budget, deadline and stop rule bound into one profile revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryStopRule {
    /// Admitted budget ceiling in provider units.
    pub budget_units: u64,
    /// Admitted deadline ceiling in Unix milliseconds.
    pub deadline_ms: i64,
    /// Declared stop rule.
    pub stop_rule: StopRuleKind,
    /// Cancellation identity the admitted operation is bound to.
    pub cancellation_identity: String,
    /// Digest over the whole stop-rule shape.
    pub digest: String,
}

impl InquiryStopRule {
    /// Resolves and freezes the stop rule from admitted material.
    ///
    /// # Errors
    ///
    /// Returns a field error for a zero budget, a non-positive deadline or a
    /// blank cancellation identity.
    pub fn resolve(
        budget_units: u64,
        deadline_ms: i64,
        stop_rule: StopRuleKind,
        cancellation_identity: &str,
    ) -> Result<Self, InquiryError> {
        if budget_units == 0 {
            return Err(InquiryError::Blank {
                field: "stop_rule.budget_units",
            });
        }
        if deadline_ms <= 0 {
            return Err(InquiryError::Blank {
                field: "stop_rule.deadline_ms",
            });
        }
        require_text(cancellation_identity, "stop_rule.cancellation_identity")?;
        let mut preimage = String::from("inquiry-stop-rule/v1;");
        push_field(&mut preimage, "budget_units", &budget_units.to_string());
        push_field(&mut preimage, "deadline_ms", &deadline_ms.to_string());
        push_field(&mut preimage, "stop_rule", stop_rule.wire_name());
        push_field(
            &mut preimage,
            "cancellation_identity",
            cancellation_identity,
        );
        Ok(Self {
            budget_units,
            deadline_ms,
            stop_rule,
            cancellation_identity: cancellation_identity.to_owned(),
            digest: freeze(&preimage),
        })
    }
}

/// Output contract and declared reopen conditions of one profile revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryOutputContract {
    /// Admitted required result schema.
    pub output_contract: String,
    /// Reopen conditions this profile declares in advance.
    pub reopen_conditions: Vec<ReopenCondition>,
    /// Digest over the whole output-contract shape.
    pub digest: String,
}

impl InquiryOutputContract {
    /// Resolves and freezes the output contract.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank output contract and
    /// [`InquiryError::UnknownVocabulary`] for an empty reopen-condition set.
    pub fn resolve(
        output_contract: &str,
        reopen_conditions: Vec<ReopenCondition>,
    ) -> Result<Self, InquiryError> {
        require_text(output_contract, "output_contract.output_contract")?;
        if reopen_conditions.is_empty() {
            return Err(InquiryError::UnknownVocabulary {
                field: "output_contract.reopen_conditions",
            });
        }
        let mut preimage = String::from("inquiry-output-contract/v1;");
        push_field(&mut preimage, "output_contract", output_contract);
        push_count(&mut preimage, "reopen_conditions", reopen_conditions.len());
        for condition in &reopen_conditions {
            push_field(&mut preimage, "reopen_condition", condition.wire_name());
        }
        Ok(Self {
            output_contract: output_contract.to_owned(),
            reopen_conditions,
            digest: freeze(&preimage),
        })
    }
}

macro_rules! strength_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub enum $name {
            $(
                #[doc = concat!("The `", $wire, "` level.")]
                $variant,
            )+
        }

        impl $name {
            /// Stable wire spelling of this level.
            #[must_use]
            pub const fn wire_name(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)+
                }
            }
        }
    };
}

strength_enum! {
    /// Cost of verifying an answer.
    VerifierStrength {
        Low => "low",
        Moderate => "moderate",
        High => "high",
    }
}

strength_enum! {
    /// Discoverability of a specialist for the question.
    SpecialistDiscoverability {
        None => "none",
        Partial => "partial",
        Direct => "direct",
    }
}

strength_enum! {
    /// Planning horizon the inquiry must cover.
    InquiryHorizon {
        Immediate => "immediate",
        Bounded => "bounded",
        OpenEnded => "open_ended",
    }
}

strength_enum! {
    /// Current uncertainty about the answer.
    InquiryUncertainty {
        Low => "low",
        Moderate => "moderate",
        High => "high",
    }
}

strength_enum! {
    /// Risk of acting on a wrong answer.
    InquiryRisk {
        Low => "low",
        Moderate => "moderate",
        High => "high",
    }
}

/// Task features that drive protocol, lane, grade, goal and policy selection.
///
/// Selection inputs are structural features, not task vocabulary (I21.3), and
/// the same inputs feed the recipe planner, so protocol and staffing are chosen
/// consistently instead of by two competing heuristics. Every field is a closed
/// structural fact; no task text, no question and no scope is carried here.
///
/// The independent structural predicates are the point of the type: I21.3
/// requires protocol selection to read task *features*, so the feature vector
/// stays a set of separate typed booleans rather than an opaque score.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InquirySelectionFeatures {
    /// Whether the answer depends on a strict sequence of earlier answers.
    pub sequential_dependency: bool,
    /// Whether candidate branches are independent of each other.
    pub branch_independence: bool,
    /// Whether branches share mutable state.
    pub shared_mutable_state: bool,
    /// Cost of verifying an answer.
    pub verifier_cost: VerifierStrength,
    /// Strength of the available verifier.
    pub verifier_strength: VerifierStrength,
    /// Whether a specialist could be discovered for this question.
    pub specialist_discoverability: SpecialistDiscoverability,
    /// Planning horizon of the inquiry.
    pub horizon: InquiryHorizon,
    /// How uncertain the current understanding is.
    pub uncertainty: InquiryUncertainty,
    /// Risk of acting on a wrong answer.
    pub risk: InquiryRisk,
    /// Whether an evaluator already exists for the question.
    pub evaluator_exists: bool,
    /// Whether a fixed specification or a primary source is available.
    pub primary_source_available: bool,
    /// Whether a measured or operational record is available.
    pub measured_evidence_available: bool,
    /// Whether the question is bounded and decidable now.
    pub bounded_decision: bool,
}

/// Selects the inquiry protocol from structural features (I21.3).
///
/// The mapping is total and deterministic: the same features always select the
/// same protocol and every protocol is reachable. Protocol choice is a default,
/// not a hard boundary, so [`InquiryProtocolProfile::revise`] may change it with
/// a recorded reason.
#[must_use]
pub fn select_protocol(features: &InquirySelectionFeatures) -> InquiryProtocol {
    if features.primary_source_available && features.evaluator_exists && features.bounded_decision {
        return InquiryProtocol::FormalProof;
    }
    if features.shared_mutable_state && features.risk >= InquiryRisk::Moderate {
        return InquiryProtocol::CausalDiagnosis;
    }
    if features.measured_evidence_available && features.uncertainty == InquiryUncertainty::High {
        return InquiryProtocol::EmpiricalDiscovery;
    }
    if features.specialist_discoverability == SpecialistDiscoverability::Direct
        && features.horizon == InquiryHorizon::OpenEnded
    {
        return InquiryProtocol::TheoryDevelopment;
    }
    if features.sequential_dependency && features.branch_independence {
        return InquiryProtocol::ProgramSynthesis;
    }
    if features.risk == InquiryRisk::High || features.horizon == InquiryHorizon::OpenEnded {
        return InquiryProtocol::ArchitectureDecision;
    }
    if features.verifier_strength >= VerifierStrength::Moderate
        && features.uncertainty == InquiryUncertainty::High
    {
        return InquiryProtocol::AlgorithmSearch;
    }
    if features.primary_source_available {
        return InquiryProtocol::EvidenceReview;
    }
    if features.uncertainty == InquiryUncertainty::High
        && features.horizon == InquiryHorizon::Immediate
    {
        return InquiryProtocol::DecisionSupport;
    }
    InquiryProtocol::Lookup
}

/// Selects the coverage goal from structural features (I21.3).
#[must_use]
pub fn select_coverage_goal(features: &InquirySelectionFeatures) -> CoverageGoal {
    if features.horizon == InquiryHorizon::OpenEnded || features.risk == InquiryRisk::High {
        CoverageGoal::HighRecall
    } else if features.verifier_cost == VerifierStrength::High {
        CoverageGoal::Exhaustive
    } else if features.horizon == InquiryHorizon::Bounded {
        CoverageGoal::Representative
    } else {
        CoverageGoal::Exploratory
    }
}

/// Selects the lane from the resolved protocol and its evaluation surface.
///
/// A confirmatory lane is available only when a protocol, an evaluator and a
/// low-risk, strongly verified structure exist together; otherwise the
/// selection is exploratory, and exploratory evidence may not confirm the
/// hypothesis that generated it on the same exposure.
#[must_use]
pub fn select_lane(protocol: InquiryProtocol, features: &InquirySelectionFeatures) -> InquiryLane {
    let confirmatory_protocol = matches!(
        protocol,
        InquiryProtocol::FormalProof | InquiryProtocol::EvidenceReview
    );
    if confirmatory_protocol
        && features.evaluator_exists
        && features.verifier_strength == VerifierStrength::High
        && features.risk == InquiryRisk::Low
    {
        InquiryLane::Confirmatory
    } else {
        InquiryLane::Exploratory
    }
}

/// Selects the hypothesis policy from structural features (I21.3).
#[must_use]
pub fn select_hypothesis_policy(features: &InquirySelectionFeatures) -> HypothesisPolicy {
    if features.risk == InquiryRisk::High {
        HypothesisPolicy::FalsificationRequired
    } else if features.uncertainty == InquiryUncertainty::High {
        HypothesisPolicy::CounterSearchRequired
    } else {
        HypothesisPolicy::AlternativesRequired
    }
}

/// Selects the evidence grade the observed structure can carry (I21.2).
///
/// Grade is a selected level of rigour, not a separate feature: one contour
/// serves a quick lookup and a full investigation and the difference is the
/// declared grade. The selection is monotone in the verifier surface, and
/// science grade is capped unless a confirmatory lane is declared, because
/// science grade requires a declared lane in addition to a corroborated base.
///
/// # Errors
///
/// Returns [`InquiryError::UnknownGrade`] when the resolved rank leaves the
/// frozen ladder, which the closed ranges below exclude.
pub fn select_evidence_grade(
    features: &InquirySelectionFeatures,
    lane: InquiryLane,
) -> Result<EvidenceGrade, InquiryError> {
    let mut rank: u8 = match features.verifier_strength {
        VerifierStrength::High => 2,
        VerifierStrength::Moderate => 1,
        VerifierStrength::Low => 0,
    };
    if lane == InquiryLane::Confirmatory {
        rank = rank.saturating_add(1);
    }
    let ceiling: u8 = if lane == InquiryLane::Confirmatory {
        3
    } else {
        2
    };
    EvidenceGrade::from_rank(rank.min(ceiling))
}

/// Selects the independence dimensions and minimum independent lineages a
/// grade requires (I21.2/I21.3).
///
/// `ORIENTING` and `GROUNDED` make no coverage claim and therefore require no
/// independent lineage; `CORROBORATED` requires independent source and provider
/// families; `SCIENCE_GRADE` additionally requires distinct evaluators and no
/// shared context ancestor or shared assumption.
#[must_use]
pub fn select_independence_requirement(grade: EvidenceGrade) -> (Vec<IndependenceDimension>, u64) {
    let corroborating = vec![
        IndependenceDimension::SourceFamily,
        IndependenceDimension::ProviderFamily,
    ];
    let science = vec![
        IndependenceDimension::SourceFamily,
        IndependenceDimension::ProviderFamily,
        IndependenceDimension::EvaluatorFamily,
        IndependenceDimension::SharedContextAncestor,
        IndependenceDimension::SharedAssumptions,
    ];
    match grade.rank() {
        0 | 1 => (corroborating, 0),
        2 => (corroborating, 2),
        _ => (science, 3),
    }
}

/// Selects the reopen conditions a profile declares in advance (I21.3).
#[must_use]
pub fn select_reopen_conditions(
    goal: CoverageGoal,
    policy: HypothesisPolicy,
) -> Vec<ReopenCondition> {
    let mut conditions = vec![
        ReopenCondition::NewEvidenceAvailable,
        ReopenCondition::StaleEvidence,
        ReopenCondition::ContractChanged,
    ];
    if matches!(goal, CoverageGoal::HighRecall | CoverageGoal::Exhaustive) {
        conditions.push(ReopenCondition::SourceBecameAvailable);
    }
    if policy.requires_counter_search() {
        conditions.push(ReopenCondition::VerifierCounterexample);
    }
    conditions.sort();
    conditions.dedup();
    conditions
}

/// Digest over the structural selection inputs (I21.3).
fn selection_features_digest(features: &InquirySelectionFeatures) -> String {
    let mut preimage = String::from("inquiry-selection-features/v1;");
    for (tag, value) in [
        ("sequential_dependency", features.sequential_dependency),
        ("branch_independence", features.branch_independence),
        ("shared_mutable_state", features.shared_mutable_state),
        ("evaluator_exists", features.evaluator_exists),
        (
            "primary_source_available",
            features.primary_source_available,
        ),
        (
            "measured_evidence_available",
            features.measured_evidence_available,
        ),
        ("bounded_decision", features.bounded_decision),
    ] {
        push_field(&mut preimage, tag, bool_text(value));
    }
    for (tag, value) in [
        ("verifier_cost", features.verifier_cost.wire_name()),
        ("verifier_strength", features.verifier_strength.wire_name()),
        (
            "specialist_discoverability",
            features.specialist_discoverability.wire_name(),
        ),
        ("horizon", features.horizon.wire_name()),
        ("uncertainty", features.uncertainty.wire_name()),
        ("risk", features.risk.wire_name()),
    ] {
        push_field(&mut preimage, tag, value);
    }
    freeze(&preimage)
}

/// Named constructor arguments for [`InquiryProtocolProfile::resolve`].
#[derive(Clone, Debug)]
pub struct InquiryProfileParams {
    /// Stable profile identity.
    pub profile_id: String,
    /// Stable inquiry identity this profile governs.
    pub inquiry_id: String,
    /// Admitted operation identity the inquiry is bound to.
    pub operation_id: String,
    /// Admitted exchange identity.
    pub exchange_id: String,
    /// Exact question under inquiry.
    pub question: String,
    /// Decision or artifact the answer must serve.
    pub intended_decision_or_artifact: String,
    /// Exact frozen scope; vague spellings are refused.
    pub scope: String,
    /// Requesting principal that proposed the inquiry.
    pub requester_principal: String,
    /// Kernel-admitted digest of the frozen inquiry this profile resolves.
    pub admitted_inquiry_digest: String,
    /// Structural features the selection is resolved from.
    pub features: InquirySelectionFeatures,
    /// Truth surfaces and admissible providers for this inquiry.
    pub truth_surfaces_and_admissible_providers: Vec<String>,
    /// Source classes the profile admits.
    pub admissible_source_classes: Vec<SourceClass>,
    /// Reference manifest digest the profile is bound to.
    pub reference_manifest_digest: String,
    /// Kernel-admitted denominator digest.
    pub admitted_denominator_digest: String,
    /// Admitted coverage-goal text exactly as admitted.
    pub admitted_coverage_goal: String,
    /// Admitted result schema, which is the output contract.
    pub required_schema: String,
    /// Privacy and disclosure ceiling for the whole inquiry.
    pub disclosure_ceiling: DisclosureClass,
    /// Budget, deadline and stop rule.
    pub stop_rule: InquiryStopRule,
    /// State Fence this revision is frozen under.
    pub state_fence: StateFence,
    /// Optional frozen lane registration digest.
    pub lane_registration_digest: Option<String>,
}

/// Versioned inquiry protocol profile (I21.2/I21.3).
///
/// Resolution, not inheritance: the profile is proposed by the requesting
/// route, resolved here into a versioned shape under the current task
/// definition, admitted by the Governor together with budget, privacy and route
/// policy, and enforced downstream. A revision is a supersession with a recorded
/// reason and never a silent adjustment, and evidence already exposed keeps the
/// grade and lane it was produced under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryProtocolProfile {
    /// Stable profile identity.
    pub profile_id: String,
    /// Monotonic revision of this profile, starting at one.
    pub revision: u64,
    /// Digest of the profile revision this one supersedes.
    pub supersedes: Option<String>,
    /// Stable inquiry identity.
    pub inquiry_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Admitted exchange identity.
    pub exchange_id: String,
    /// Exact question under inquiry.
    pub question: String,
    /// Decision or artifact the answer must serve.
    pub intended_decision_or_artifact: String,
    /// Exact frozen scope.
    pub scope: String,
    /// Requesting principal that proposed the inquiry.
    pub requester_principal: String,
    /// Kernel-admitted digest of the frozen inquiry.
    pub admitted_inquiry_digest: String,
    /// Resolved protocol.
    pub protocol: InquiryProtocol,
    /// Digest of the structural selection inputs.
    pub selection_features_digest: String,
    /// Selected evidence grade.
    pub evidence_grade: EvidenceGrade,
    /// Declared lane.
    pub lane: InquiryLane,
    /// Resolved coverage goal.
    pub coverage_goal: CoverageGoal,
    /// Admitted coverage-goal text exactly as admitted.
    pub admitted_coverage_goal: String,
    /// Whether the admitted coverage-goal text is exactly this resolved goal.
    pub admitted_coverage_goal_resolved: bool,
    /// Declared hypothesis policy.
    pub hypothesis_policy: HypothesisPolicy,
    /// Truth surfaces and admissible providers.
    pub truth_surfaces_and_admissible_providers: Vec<String>,
    /// Admissible source classes.
    pub admissible_source_classes: Vec<SourceClass>,
    /// Reference manifest digest.
    pub reference_manifest_digest: String,
    /// Kernel-admitted denominator digest.
    pub admitted_denominator_digest: String,
    /// Independence and blinding policy.
    pub independence_and_blinding_policy: IndependenceBlindingPolicy,
    /// Digest of the independence and blinding policy.
    pub independence_and_blinding_policy_digest: String,
    /// Fidelity ceiling declared for this inquiry.
    pub fidelity_ceiling: String,
    /// Budget, deadline and stop rule.
    pub stop_rule: InquiryStopRule,
    /// Output contract and declared reopen conditions.
    pub output_contract: InquiryOutputContract,
    /// Privacy and disclosure ceiling.
    pub disclosure_ceiling: DisclosureClass,
    /// State Fence this revision is frozen under.
    pub state_fence: StateFence,
    /// Reason this revision exists; always present.
    pub change_reason: String,
    /// Digest over the full revision content.
    pub integrity_digest: String,
}

impl InquiryProtocolProfile {
    /// Resolves the first revision of one inquiry profile.
    ///
    /// # Errors
    ///
    /// Returns a field error for blank, control-bearing, vague or malformed
    /// input, [`InquiryError::UnknownGrade`] for a grade outside the frozen
    /// ladder, and [`InquiryError::LaneRegistrationRequired`] when a
    /// confirmatory lane has no frozen registration.
    pub fn resolve(params: InquiryProfileParams) -> Result<Self, InquiryError> {
        Self::build(params, 1, None, "initial inquiry protocol resolution")
    }

    /// Resolves the next revision of this profile with a recorded reason.
    ///
    /// Protocol and lane may change; only obligations that depended on the
    /// previous protocol are invalidated, and the supersession is explicit. A
    /// revision may not relabel a different inquiry or a different question.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::RevisionRequiresReason`] for a blank reason,
    /// [`InquiryError::Duplicate`] when the revision would change the inquiry
    /// identity, question, scope or decision the profile governs, a field error
    /// for malformed input, and [`InquiryError::LaneRegistrationRequired`] when
    /// a confirmatory lane has no frozen registration.
    pub fn revise(&self, params: InquiryProfileParams, reason: &str) -> Result<Self, InquiryError> {
        require_text(reason, "profile.change_reason")?;
        let next = self
            .revision
            .checked_add(1)
            .ok_or(InquiryError::Duplicate {
                field: "profile.revision",
            })?;
        let mut revision = Self::build(params, next, Some(self.integrity_digest.clone()), reason)?;
        if revision.inquiry_id != self.inquiry_id
            || revision.profile_id != self.profile_id
            || revision.question != self.question
            || revision.scope != self.scope
            || revision.intended_decision_or_artifact != self.intended_decision_or_artifact
        {
            return Err(InquiryError::Duplicate {
                field: "profile.inquiry_binding",
            });
        }
        revision.supersedes = Some(self.integrity_digest.clone());
        Ok(revision)
    }

    /// Stable `profile_id@revision` reference.
    #[must_use]
    pub fn profile_id_and_revision(&self) -> String {
        format!("{}@{}", self.profile_id, self.revision)
    }

    /// Whether this revision still binds the same inquiry identity and fence.
    #[must_use]
    pub fn binds(&self, inquiry_id: &str, fence: &StateFence) -> bool {
        self.inquiry_id == inquiry_id && &self.state_fence == fence
    }

    /// Builds the Governor-facing admission request for this revision.
    ///
    /// The request asks the existing Governor admission path to admit the
    /// profile together with budget, privacy and route policy. It carries no
    /// canonical-write authority, no scheduling and no finish.
    #[must_use]
    pub fn admission_request(&self) -> GovernorInquiryAdmissionRequest {
        GovernorInquiryAdmissionRequest {
            request_kind: GovernorInquiryAdmissionRequest::REQUEST_KIND.to_owned(),
            inquiry_id: self.inquiry_id.clone(),
            profile_id: self.profile_id.clone(),
            profile_revision: self.revision,
            profile_integrity_digest: self.integrity_digest.clone(),
            protocol: self.protocol,
            evidence_grade: self.evidence_grade,
            lane: self.lane,
            coverage_goal: self.coverage_goal,
            admitted_coverage_goal: self.admitted_coverage_goal.clone(),
            hypothesis_policy: self.hypothesis_policy,
            reference_manifest_digest: self.reference_manifest_digest.clone(),
            admitted_denominator_digest: self.admitted_denominator_digest.clone(),
            independence_and_blinding_policy_digest: self
                .independence_and_blinding_policy_digest
                .clone(),
            output_contract_digest: self.output_contract.digest.clone(),
            stop_rule_digest: self.stop_rule.digest.clone(),
            budget_units: self.stop_rule.budget_units,
            deadline_ms: self.stop_rule.deadline_ms,
            disclosure_ceiling: self.disclosure_ceiling,
            state_fence: self.state_fence.clone(),
            candidate_only: true,
            canonical_write_authorized: false,
        }
    }

    fn build(
        params: InquiryProfileParams,
        revision: u64,
        supersedes: Option<String>,
        change_reason: &str,
    ) -> Result<Self, InquiryError> {
        validate_profile_params(&params, change_reason)?;

        let protocol = select_protocol(&params.features);
        let coverage_goal = select_coverage_goal(&params.features);
        let lane = select_lane(protocol, &params.features);
        let hypothesis_policy = select_hypothesis_policy(&params.features);
        let evidence_grade = select_evidence_grade(&params.features, lane)?;
        let (dimensions, minimum_independent_families) =
            select_independence_requirement(evidence_grade);
        let independence_and_blinding_policy = IndependenceBlindingPolicy::resolve(
            evidence_grade,
            lane,
            dimensions,
            minimum_independent_families,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            params.lane_registration_digest.clone(),
        )?;
        let output_contract = InquiryOutputContract::resolve(
            &params.required_schema,
            select_reopen_conditions(coverage_goal, hypothesis_policy),
        )?;
        let fidelity_ceiling = format!(
            "verifier_strength={} horizon={}",
            params.features.verifier_strength.wire_name(),
            params.features.horizon.wire_name()
        );
        let admitted_coverage_goal_resolved =
            CoverageGoal::from_wire(&params.admitted_coverage_goal) == Some(coverage_goal);
        let mut profile = Self {
            profile_id: params.profile_id,
            revision,
            supersedes,
            inquiry_id: params.inquiry_id,
            operation_id: params.operation_id,
            exchange_id: params.exchange_id,
            question: params.question,
            intended_decision_or_artifact: params.intended_decision_or_artifact,
            scope: params.scope,
            requester_principal: params.requester_principal,
            admitted_inquiry_digest: params.admitted_inquiry_digest,
            protocol,
            selection_features_digest: selection_features_digest(&params.features),
            evidence_grade,
            lane,
            coverage_goal,
            admitted_coverage_goal_resolved,
            admitted_coverage_goal: params.admitted_coverage_goal,
            hypothesis_policy,
            truth_surfaces_and_admissible_providers: params.truth_surfaces_and_admissible_providers,
            admissible_source_classes: params.admissible_source_classes,
            reference_manifest_digest: params.reference_manifest_digest,
            admitted_denominator_digest: params.admitted_denominator_digest,
            independence_and_blinding_policy_digest: independence_and_blinding_policy
                .digest
                .clone(),
            independence_and_blinding_policy,
            fidelity_ceiling,
            stop_rule: params.stop_rule,
            output_contract,
            disclosure_ceiling: params.disclosure_ceiling,
            state_fence: params.state_fence,
            change_reason: change_reason.to_owned(),
            integrity_digest: String::new(),
        };
        profile.integrity_digest = profile.compute_integrity_digest();
        Ok(profile)
    }

    /// The frozen selection half of this revision, exactly as the profile
    /// carries it: protocol, selected grade, lane, coverage goal, hypothesis
    /// policy, the structural-selection digest, the admitted coverage-goal text
    /// and the source classes and truth surfaces the profile admits.
    fn push_selection_into(&self, preimage: &mut String) {
        push_field(preimage, "protocol", self.protocol.wire_name());
        push_field(
            preimage,
            "selection_features_digest",
            &self.selection_features_digest,
        );
        push_field(preimage, "evidence_grade", &self.evidence_grade.to_string());
        push_field(preimage, "lane", self.lane.wire_name());
        push_field(preimage, "coverage_goal", self.coverage_goal.wire_name());
        push_field(
            preimage,
            "admitted_coverage_goal",
            &self.admitted_coverage_goal,
        );
        push_field(
            preimage,
            "admitted_coverage_goal_resolved",
            bool_text(self.admitted_coverage_goal_resolved),
        );
        push_field(
            preimage,
            "hypothesis_policy",
            self.hypothesis_policy.wire_name(),
        );
        push_count(
            preimage,
            "truth_surfaces",
            self.truth_surfaces_and_admissible_providers.len(),
        );
        for surface in &self.truth_surfaces_and_admissible_providers {
            push_field(preimage, "truth_surface", surface);
        }
        push_count(
            preimage,
            "admissible_source_classes",
            self.admissible_source_classes.len(),
        );
        for class in &self.admissible_source_classes {
            push_field(preimage, "source_class", class_wire(*class));
        }
    }

    fn compute_integrity_digest(&self) -> String {
        let mut preimage = String::from("inquiry-protocol-profile/v1;");
        push_field(&mut preimage, "profile_id", &self.profile_id);
        push_field(&mut preimage, "revision", &self.revision.to_string());
        if let Some(supersedes) = &self.supersedes {
            push_field(&mut preimage, "supersedes", supersedes);
        }
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "operation_id", &self.operation_id);
        push_field(&mut preimage, "exchange_id", &self.exchange_id);
        push_field(&mut preimage, "question", &self.question);
        push_field(
            &mut preimage,
            "intended_decision_or_artifact",
            &self.intended_decision_or_artifact,
        );
        push_field(&mut preimage, "scope", &self.scope);
        push_field(
            &mut preimage,
            "requester_principal",
            &self.requester_principal,
        );
        push_field(
            &mut preimage,
            "admitted_inquiry_digest",
            &self.admitted_inquiry_digest,
        );
        self.push_selection_into(&mut preimage);
        push_field(
            &mut preimage,
            "reference_manifest_digest",
            &self.reference_manifest_digest,
        );
        push_field(
            &mut preimage,
            "admitted_denominator_digest",
            &self.admitted_denominator_digest,
        );
        push_field(
            &mut preimage,
            "independence_and_blinding_policy_digest",
            &self.independence_and_blinding_policy_digest,
        );
        push_field(&mut preimage, "fidelity_ceiling", &self.fidelity_ceiling);
        push_field(&mut preimage, "stop_rule_digest", &self.stop_rule.digest);
        push_field(
            &mut preimage,
            "output_contract_digest",
            &self.output_contract.digest,
        );
        push_field(
            &mut preimage,
            "disclosure_ceiling",
            disclosure_wire(self.disclosure_ceiling),
        );
        push_field(&mut preimage, "change_reason", &self.change_reason);
        freeze(&preimage)
    }

    /// Re-proves this revision's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.compute_integrity_digest() != self.integrity_digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "profile.integrity_digest",
            });
        }
        Ok(())
    }
}

/// Validates the admitted material one profile revision is resolved from.
///
/// # Errors
///
/// Returns a field error for blank, control-bearing, vague or malformed input,
/// [`InquiryError::UnknownVocabulary`] when the profile admits no source class
/// or no truth surface, and a field error for an invalid State Fence.
fn validate_profile_params(
    params: &InquiryProfileParams,
    change_reason: &str,
) -> Result<(), InquiryError> {
    require_text(&params.profile_id, "profile.profile_id")?;
    require_text(&params.inquiry_id, "profile.inquiry_id")?;
    require_text(&params.operation_id, "profile.operation_id")?;
    require_text(&params.exchange_id, "profile.exchange_id")?;
    require_text(&params.question, "profile.question")?;
    require_text(
        &params.intended_decision_or_artifact,
        "profile.intended_decision_or_artifact",
    )?;
    require_scope(&params.scope, "profile.scope")?;
    require_text(&params.requester_principal, "profile.requester_principal")?;
    require_digest(
        &params.admitted_inquiry_digest,
        "profile.admitted_inquiry_digest",
    )?;
    require_digest(
        &params.reference_manifest_digest,
        "profile.reference_manifest_digest",
    )?;
    require_digest(
        &params.admitted_denominator_digest,
        "profile.admitted_denominator_digest",
    )?;
    require_text(
        &params.admitted_coverage_goal,
        "profile.admitted_coverage_goal",
    )?;
    require_text(&params.required_schema, "profile.required_schema")?;
    require_text(change_reason, "profile.change_reason")?;
    if params.admissible_source_classes.is_empty() {
        return Err(InquiryError::UnknownVocabulary {
            field: "profile.admissible_source_classes",
        });
    }
    if params.truth_surfaces_and_admissible_providers.is_empty() {
        return Err(InquiryError::UnknownVocabulary {
            field: "profile.truth_surfaces_and_admissible_providers",
        });
    }
    for surface in &params.truth_surfaces_and_admissible_providers {
        require_text(surface, "profile.truth_surfaces_and_admissible_providers")?;
    }
    params
        .state_fence
        .validate()
        .map_err(|_| InquiryError::Blank {
            field: "profile.state_fence",
        })
}

/// Governor-facing admission request for one profile revision.
///
/// The domain requests admission; it never applies it. The request carries no
/// canonical-write authority and cannot finish a task.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernorInquiryAdmissionRequest {
    /// Closed request-kind discriminator.
    pub request_kind: String,
    /// Inquiry identity.
    pub inquiry_id: String,
    /// Profile identity.
    pub profile_id: String,
    /// Profile revision.
    pub profile_revision: u64,
    /// Exact profile revision digest.
    pub profile_integrity_digest: String,
    /// Resolved protocol.
    pub protocol: InquiryProtocol,
    /// Selected evidence grade.
    pub evidence_grade: EvidenceGrade,
    /// Declared lane.
    pub lane: InquiryLane,
    /// Resolved coverage goal.
    pub coverage_goal: CoverageGoal,
    /// Admitted coverage-goal text exactly as admitted.
    pub admitted_coverage_goal: String,
    /// Declared hypothesis policy.
    pub hypothesis_policy: HypothesisPolicy,
    /// Reference manifest digest.
    pub reference_manifest_digest: String,
    /// Kernel-admitted denominator digest.
    pub admitted_denominator_digest: String,
    /// Independence and blinding policy digest.
    pub independence_and_blinding_policy_digest: String,
    /// Output contract digest.
    pub output_contract_digest: String,
    /// Stop rule digest.
    pub stop_rule_digest: String,
    /// Admitted budget ceiling.
    pub budget_units: u64,
    /// Admitted deadline ceiling.
    pub deadline_ms: i64,
    /// Privacy and disclosure ceiling.
    pub disclosure_ceiling: DisclosureClass,
    /// State Fence the request is presented under.
    pub state_fence: StateFence,
    /// Whether the requested material stays candidate-only.
    pub candidate_only: bool,
    /// Always false: this domain never authorizes a canonical write.
    pub canonical_write_authorized: bool,
}

impl GovernorInquiryAdmissionRequest {
    /// Closed request-kind discriminator for inquiry-profile admission.
    pub const REQUEST_KIND: &'static str = "inquiry_profile_admission";
}

/// Independence profile of one source portfolio (I21.6).
///
/// Ten pages from one vendor are not ten independent sources: two outputs are
/// dependent when they share a source, restate one primary work, run on one
/// model family, saw one parent summary, use one evaluator or inherit one
/// mistaken assumption. Unknown lineage stays preserved and never inflates the
/// independent count.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndependenceProfile {
    /// Distinct known lineage roots behind the eligible evidence set.
    pub lineage_roots: Vec<String>,
    /// Eligible handles whose independence is unknown.
    pub unknown_independence_handles: Vec<String>,
    /// Number of distinct independent lineages actually observed.
    pub independent_lineages: usize,
    /// Minimum independent lineages the profile requires.
    pub minimum_independent_families: u64,
    /// Whether the observed independence meets the profile requirement.
    pub meets_requirement: bool,
    /// Digest over the profile shape.
    pub digest: String,
}

impl IndependenceProfile {
    /// Derives the independence profile from the eligible handles and the exact
    /// vetted records behind them.
    #[must_use]
    pub fn derive(
        eligible: &[String],
        records: &BTreeMap<String, SourceRecord>,
        minimum_independent_families: u64,
    ) -> Self {
        let lineage = LineageTable::build(records);
        let (independent, unknown) = lineage.independent_support(eligible);
        let mut lineage_roots: Vec<String> = eligible
            .iter()
            .filter_map(|handle| {
                records
                    .get(handle)
                    .and_then(|record| record.lineage_root.clone())
            })
            .collect();
        lineage_roots.sort();
        lineage_roots.dedup();
        let mut unknown_independence_handles: Vec<String> = eligible
            .iter()
            .filter(|handle| {
                records
                    .get(*handle)
                    .is_none_or(|record| record.lineage_root.is_none())
            })
            .cloned()
            .collect();
        unknown_independence_handles.sort();
        unknown_independence_handles.dedup();
        let observed = u64::try_from(independent).unwrap_or(u64::MAX);
        // Unknown lineage is preserved as an explicit count and never counted
        // as independence, so it can never satisfy the requirement.
        let meets_requirement = unknown == 0 && observed >= minimum_independent_families;
        let mut profile = Self {
            lineage_roots,
            unknown_independence_handles,
            independent_lineages: independent,
            minimum_independent_families,
            meets_requirement,
            digest: String::new(),
        };
        profile.digest = profile.compute_digest();
        profile
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("independence-profile/v1;");
        push_count(&mut preimage, "lineage_roots", self.lineage_roots.len());
        for root in &self.lineage_roots {
            push_field(&mut preimage, "lineage_root", root);
        }
        push_count(
            &mut preimage,
            "unknown_independence_handles",
            self.unknown_independence_handles.len(),
        );
        for handle in &self.unknown_independence_handles {
            push_field(&mut preimage, "unknown_handle", handle);
        }
        push_field(
            &mut preimage,
            "independent_lineages",
            &self.independent_lineages.to_string(),
        );
        push_field(
            &mut preimage,
            "minimum_independent_families",
            &self.minimum_independent_families.to_string(),
        );
        push_field(
            &mut preimage,
            "meets_requirement",
            bool_text(self.meets_requirement),
        );
        freeze(&preimage)
    }
}

/// One requested source class the inquiry did not cover, with the reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MissingSourceClass {
    /// Requested source class.
    pub class: SourceClass,
    /// Bounded reason the class contributed no eligible source.
    pub reason: String,
}

/// Frozen source portfolio for one inquiry evidence set (I21.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourcePortfolio {
    /// Inquiry identity this portfolio answers.
    pub inquiry_id: String,
    /// Profile revision the portfolio was assembled under.
    pub profile_id_and_revision: String,
    /// Exact profile revision digest.
    pub profile_digest: String,
    /// Primary sources and specifications.
    pub primary_sources: Vec<String>,
    /// Reviews and secondary analyses.
    pub reviews_and_secondary: Vec<String>,
    /// Operational and measured evidence.
    pub operational_and_measured: Vec<String>,
    /// Independent implementations.
    pub independent_implementations: Vec<String>,
    /// Critical or negative sources.
    pub critical_or_negative: Vec<String>,
    /// Requested classes with no eligible source, and why.
    pub missing_source_classes: Vec<MissingSourceClass>,
    /// Independence profile of the eligible set.
    pub independence: IndependenceProfile,
    /// Digest over the portfolio shape.
    pub digest: String,
}

impl SourcePortfolio {
    /// Assembles the portfolio from the admissible records and the source
    /// classes the profile admits.
    ///
    /// # Errors
    ///
    /// Returns a field error when the inquiry identity is blank and
    /// [`InquiryError::UnknownHandle`] when a record belongs to another inquiry
    /// or profile revision.
    pub fn assemble(
        inquiry_id: &str,
        profile: &InquiryProtocolProfile,
        records: &[SourceAdmissibilityRecord],
    ) -> Result<Self, InquiryError> {
        require_text(inquiry_id, "portfolio.inquiry_id")?;
        let mut covered: BTreeSet<&'static str> = BTreeSet::new();
        let mut portfolio = Self {
            inquiry_id: inquiry_id.to_owned(),
            profile_id_and_revision: profile.profile_id_and_revision(),
            profile_digest: profile.integrity_digest.clone(),
            primary_sources: Vec::new(),
            reviews_and_secondary: Vec::new(),
            operational_and_measured: Vec::new(),
            independent_implementations: Vec::new(),
            critical_or_negative: Vec::new(),
            missing_source_classes: Vec::new(),
            independence: IndependenceProfile {
                lineage_roots: Vec::new(),
                unknown_independence_handles: Vec::new(),
                independent_lineages: 0,
                minimum_independent_families: 0,
                meets_requirement: false,
                digest: String::new(),
            },
            digest: String::new(),
        };
        for record in records {
            if record.inquiry_id != inquiry_id || record.profile_digest != profile.integrity_digest
            {
                return Err(InquiryError::UnknownHandle {
                    field: "portfolio.record_binding",
                });
            }
            if !record.is_admitted_to(profile) {
                continue;
            }
            covered.insert(class_wire(record.record.class));
            let handle = record.record.handle.clone();
            match record.record.class {
                SourceClass::Paper | SourceClass::Documentation | SourceClass::Repository => {
                    portfolio.primary_sources.push(handle.clone());
                }
                SourceClass::Report | SourceClass::Web | SourceClass::ServiceDossier => {
                    portfolio.reviews_and_secondary.push(handle.clone());
                }
                SourceClass::Dataset => portfolio.operational_and_measured.push(handle.clone()),
                SourceClass::Unknown => {}
            }
            if record.record.class == SourceClass::Repository {
                portfolio.independent_implementations.push(handle.clone());
            }
            if !record.record.counterevidence_of.is_empty() {
                portfolio.critical_or_negative.push(handle);
            }
        }
        for bucket in [
            &mut portfolio.primary_sources,
            &mut portfolio.reviews_and_secondary,
            &mut portfolio.operational_and_measured,
            &mut portfolio.independent_implementations,
            &mut portfolio.critical_or_negative,
        ] {
            bucket.sort();
            bucket.dedup();
        }
        for class in &profile.admissible_source_classes {
            if !covered.contains(class_wire(*class)) {
                portfolio.missing_source_classes.push(MissingSourceClass {
                    class: *class,
                    reason: "no eligible source of this class was admitted to the evidence set"
                        .to_owned(),
                });
            }
        }
        let records_by_handle = vetted_records(records);
        let eligible: Vec<String> = records
            .iter()
            .filter(|record| record.is_admitted_to(profile))
            .map(|record| record.record.handle.clone())
            .collect();
        portfolio.independence = IndependenceProfile::derive(
            &eligible,
            &records_by_handle,
            profile
                .independence_and_blinding_policy
                .minimum_independent_families,
        );
        portfolio.digest = portfolio.compute_digest();
        Ok(portfolio)
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("source-portfolio/v1;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(
            &mut preimage,
            "profile_id_and_revision",
            &self.profile_id_and_revision,
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        for (tag, bucket) in [
            ("primary", &self.primary_sources),
            ("review", &self.reviews_and_secondary),
            ("operational", &self.operational_and_measured),
            ("implementation", &self.independent_implementations),
            ("critical", &self.critical_or_negative),
        ] {
            push_count(&mut preimage, tag, bucket.len());
            for handle in bucket {
                push_field(&mut preimage, tag, handle);
            }
        }
        push_count(
            &mut preimage,
            "missing_source_classes",
            self.missing_source_classes.len(),
        );
        for missing in &self.missing_source_classes {
            push_field(&mut preimage, "missing_class", class_wire(missing.class));
            push_field(&mut preimage, "missing_reason", &missing.reason);
        }
        push_field(&mut preimage, "independence", &self.independence.digest);
        freeze(&preimage)
    }
}

/// Builds the exact vetted-record map the existing lineage owner consumes.
fn vetted_records(records: &[SourceAdmissibilityRecord]) -> BTreeMap<String, SourceRecord> {
    records
        .iter()
        .map(|record| (record.record.handle.clone(), record.record.clone()))
        .collect()
}

/// Coverage receipt for one inquiry (I21.6).
///
/// "No result" is not absence or completeness without a declared denominator
/// and a provider/coverage disposition, so the receipt always states which
/// denominator kind was established and preserves the open remainder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageReceipt {
    /// Inquiry identity this receipt covers.
    pub inquiry_id: String,
    /// Profile revision digest the receipt was computed under.
    pub profile_digest: String,
    /// Exact requested scope text.
    pub requested_scope: String,
    /// Digest of the frozen scope snapshot the receipt accounts over.
    pub frozen_scope_digest: String,
    /// Kernel-admitted denominator digest, retained verbatim.
    pub admitted_denominator_digest: String,
    /// Whether the frozen scope snapshot equals the admitted denominator.
    pub scope_snapshot_matches_admission: bool,
    /// Number of expected denominator members.
    pub expected_members: usize,
    /// Digest of the exact coverage accounting the receipt was computed over.
    pub account_digest: String,
    /// Members that carry no visible disposition.
    pub open_members: Vec<String>,
    /// Whether every expected member is accounted exactly once.
    pub accounted: bool,
    /// Whether every accounted member closed intact.
    pub all_closed: bool,
    /// Eligible handles the receipt represents.
    pub eligible_handles: Vec<String>,
    /// Explicit coverage unknowns, preserved rather than smoothed.
    pub unknown_coverage: Vec<String>,
    /// Routes the run used.
    pub routes_used: Vec<String>,
    /// Provider degradation observed on this run.
    pub provider_degradation: Vec<String>,
    /// Counter-search status.
    pub counter_search_status: CounterSearchStatus,
    /// Absence assessment over the exact accounting.
    pub absence_verdict: AbsenceVerdict,
    /// Declared denominator kind.
    pub denominator_kind: DenominatorKind,
    /// Budget limitation that bounded the run, when one applied.
    pub budget_limitation: Option<String>,
    /// Digest over the receipt shape.
    pub digest: String,
}

impl CoverageReceipt {
    /// Computes the receipt from the exact accounting and the eligibility set.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IncompleteDenominator`] when the frozen
    /// denominator has no member to account, and a field error for a vague
    /// scope or a malformed frozen-scope digest.
    #[allow(clippy::too_many_arguments)]
    pub fn compute(
        profile: &InquiryProtocolProfile,
        requested_scope: &str,
        frozen_scope_digest: &str,
        account: &CoverageAccount,
        records: &[SourceAdmissibilityRecord],
        routes_used: Vec<String>,
        provider_degradation: Vec<String>,
        unknown_coverage: Vec<String>,
        budget_limitation: Option<String>,
    ) -> Result<Self, InquiryError> {
        require_scope(requested_scope, "coverage.requested_scope")?;
        require_digest(frozen_scope_digest, "coverage.frozen_scope_digest")?;
        let expected_members = account.denominator_size();
        if expected_members == 0 {
            return Err(InquiryError::IncompleteDenominator {
                field: "coverage.expected_members",
            });
        }
        let accounted = account.is_accounted();
        let all_closed = account.all_closed();
        let mut eligible_handles: Vec<String> = records
            .iter()
            .filter(|record| record.eligibility == SourceEligibility::Eligible)
            .map(|record| record.record.handle.clone())
            .collect();
        eligible_handles.sort();
        eligible_handles.dedup();
        // Completeness is never claimed here: this boundary does not prove the
        // route authoritative for the scope, so the absence assessment stays
        // unproven and the denominator kind is established only by the exact
        // accounting, which is the sole admissible basis.
        let absence_verdict = assess_absence(all_closed, account, false);
        let counter_search_status = if profile.hypothesis_policy.requires_counter_search() {
            CounterSearchStatus::RequiredAndOpen
        } else {
            CounterSearchStatus::NotRequired
        };
        let denominator_kind = if all_closed
            && accounted
            && absence_verdict == AbsenceVerdict::Proven
            && provider_degradation.is_empty()
            && counter_search_status == CounterSearchStatus::Satisfied
        {
            DenominatorKind::CompleteScope
        } else {
            DenominatorKind::Unknown
        };
        let mut receipt = Self {
            inquiry_id: profile.inquiry_id.clone(),
            profile_digest: profile.integrity_digest.clone(),
            requested_scope: requested_scope.to_owned(),
            frozen_scope_digest: frozen_scope_digest.to_owned(),
            admitted_denominator_digest: profile.admitted_denominator_digest.clone(),
            scope_snapshot_matches_admission: frozen_scope_digest
                == profile.admitted_denominator_digest,
            expected_members,
            account_digest: account.digest(),
            open_members: account.open_members(),
            accounted,
            all_closed,
            eligible_handles,
            unknown_coverage,
            routes_used,
            provider_degradation,
            counter_search_status,
            absence_verdict,
            denominator_kind,
            budget_limitation,
            digest: String::new(),
        };
        receipt.digest = receipt.compute_digest();
        Ok(receipt)
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("coverage-receipt/v1;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_field(&mut preimage, "requested_scope", &self.requested_scope);
        push_field(
            &mut preimage,
            "frozen_scope_digest",
            &self.frozen_scope_digest,
        );
        push_field(
            &mut preimage,
            "admitted_denominator_digest",
            &self.admitted_denominator_digest,
        );
        push_field(
            &mut preimage,
            "scope_snapshot_matches_admission",
            bool_text(self.scope_snapshot_matches_admission),
        );
        push_field(
            &mut preimage,
            "expected_members",
            &self.expected_members.to_string(),
        );
        push_field(&mut preimage, "account_digest", &self.account_digest);
        push_count(&mut preimage, "open_members", self.open_members.len());
        for member in &self.open_members {
            push_field(&mut preimage, "open_member", member);
        }
        push_field(&mut preimage, "accounted", bool_text(self.accounted));
        push_field(&mut preimage, "all_closed", bool_text(self.all_closed));
        push_count(
            &mut preimage,
            "eligible_handles",
            self.eligible_handles.len(),
        );
        for handle in &self.eligible_handles {
            push_field(&mut preimage, "eligible_handle", handle);
        }
        for (tag, values) in [
            ("unknown_coverage", &self.unknown_coverage),
            ("route_used", &self.routes_used),
            ("degradation", &self.provider_degradation),
        ] {
            push_count(&mut preimage, tag, values.len());
            for value in values {
                push_field(&mut preimage, tag, value);
            }
        }
        push_field(
            &mut preimage,
            "counter_search_status",
            counter_search_wire(self.counter_search_status),
        );
        push_field(
            &mut preimage,
            "absence_verdict",
            absence_wire(&self.absence_verdict),
        );
        push_field(
            &mut preimage,
            "denominator_kind",
            self.denominator_kind.wire_name(),
        );
        if let Some(limitation) = &self.budget_limitation {
            push_field(&mut preimage, "budget_limitation", limitation);
        }
        freeze(&preimage)
    }
}

/// Highest anchor precision the evidence set supports, with the residue the
/// reference firewall produces (I21.7).
///
/// A source that supports a document-level claim does not automatically support
/// a symbol, line, causal mechanism or population-wide statement, so a
/// precision above what the set supports is preserved as typed residue instead
/// of being smoothed away.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceSetPrecision {
    /// Inquiry identity.
    pub inquiry_id: String,
    /// Precision the reference manifest admits.
    pub manifest_precision: AnchorPrecision,
    /// Highest precision the eligible evidence set actually supports.
    pub supported_precision: AnchorPrecision,
    /// Preserved unsupported-precision residue, reusing the existing owner type.
    pub residue: Vec<UnsupportedPrecisionItem>,
    /// Digest over the shape.
    pub digest: String,
}

impl EvidenceSetPrecision {
    /// Evaluates the evidence set against the manifest's admitted precision.
    ///
    /// A set with no eligible source record is a different fact from a set whose
    /// support is too coarse, so the two cases are recorded distinctly: the
    /// first is "nothing supports any anchor here" and the second is "the
    /// admitted anchor is finer than this source supports". The second case is
    /// checked through the crate's typed precision owner [`check_precision`], so
    /// an over-precise anchor produces an [`UnsupportedPrecisionItem`] with the
    /// same structure as a false quantification or a false causal mechanism
    /// rather than a bespoke shape. Both cases retain typed items, never only a
    /// rendered line.
    #[must_use]
    pub fn evaluate(
        inquiry_id: &str,
        manifest_precision: AnchorPrecision,
        records: &[SourceAdmissibilityRecord],
    ) -> Self {
        let eligible: Vec<&SourceAdmissibilityRecord> = records
            .iter()
            .filter(|record| record.eligibility == SourceEligibility::Eligible)
            .collect();
        let mut supported = AnchorPrecision::Source;
        let mut residue = Vec::new();
        if eligible.is_empty() {
            residue.push(UnsupportedPrecisionItem {
                asserted: anchor_wire(manifest_precision).to_owned(),
                highest_supported: anchor_wire(AnchorPrecision::Source).to_owned(),
                basis: "no eligible source record supports any anchor in this evidence set"
                    .to_owned(),
                risk: "a reference at manifest precision would be unbacked text".to_owned(),
                required_probe: "acquire and admit one source record inside the frozen scope"
                    .to_owned(),
            });
        } else {
            for record in &eligible {
                if record.limits.max_anchor_precision > supported {
                    supported = record.limits.max_anchor_precision;
                }
            }
            if manifest_precision > supported {
                for record in &eligible {
                    if let Some(item) = coordinate_residue(
                        manifest_precision,
                        record.limits.max_anchor_precision,
                        &format!(
                            "source {} supports at most {} precision",
                            record.record.handle,
                            anchor_wire(record.limits.max_anchor_precision)
                        ),
                    ) {
                        residue.push(item);
                    }
                }
            }
        }
        let mut evaluation = Self {
            inquiry_id: inquiry_id.to_owned(),
            manifest_precision,
            supported_precision: supported,
            residue,
            digest: String::new(),
        };
        let mut preimage = String::from("evidence-set-precision/v1;");
        push_field(&mut preimage, "inquiry_id", &evaluation.inquiry_id);
        push_field(
            &mut preimage,
            "manifest_precision",
            anchor_wire(evaluation.manifest_precision),
        );
        push_field(
            &mut preimage,
            "supported_precision",
            anchor_wire(evaluation.supported_precision),
        );
        push_count(&mut preimage, "residue", evaluation.residue.len());
        for item in &evaluation.residue {
            push_field(&mut preimage, "asserted", &item.asserted);
            push_field(&mut preimage, "highest_supported", &item.highest_supported);
            push_field(&mut preimage, "basis", &item.basis);
            push_field(&mut preimage, "required_probe", &item.required_probe);
        }
        evaluation.digest = freeze(&preimage);
        evaluation
    }

    /// Whether any unsupported-precision residue remains.
    #[must_use]
    pub fn has_residue(&self) -> bool {
        !self.residue.is_empty()
    }
}

/// The typed over-precision item for one anchor claimed against the anchor an
/// admitted source record actually supports, or `None` when the claim is within
/// it.
///
/// The comparison is delegated to [`check_precision`] with the coordinate
/// precision kind, so a false line anchor is shaped exactly like a false
/// quantification or a false causal mechanism instead of being a second,
/// differently shaped residue vocabulary.
fn coordinate_residue(
    asserted: AnchorPrecision,
    supported: AnchorPrecision,
    basis: &str,
) -> Option<UnsupportedPrecisionItem> {
    check_precision(&PrecisionAssertion {
        kind: PrecisionKind::Coordinate,
        asserted: anchor_wire(asserted).to_owned(),
        supported: anchor_wire(supported).to_owned(),
        basis: basis.to_owned(),
    })
    .err()
}

/// Evidence freeze of one accepted evidence revision (I21.8).
///
/// A synthesis author may not silently acquire a new fact and include it without
/// admission, so the accepted evidence revision is frozen before prose
/// synthesis begins. The freeze is a non-canonical governed artifact: it is
/// candidate material that only Governor admission can promote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceFreeze {
    /// Stable freeze identity.
    pub freeze_id: String,
    /// Inquiry identity.
    pub inquiry_id: String,
    /// Profile revision the freeze was taken under.
    pub profile_id_and_revision: String,
    /// Profile revision digest.
    pub profile_digest: String,
    /// Portfolio digest frozen with the evidence.
    pub portfolio_digest: String,
    /// Reference manifest digest frozen with the evidence.
    pub manifest_digest: String,
    /// Coverage receipt digest frozen with the evidence.
    pub coverage_receipt_digest: String,
    /// Evidence-set identity the freeze covers.
    pub evidence_set_id: String,
    /// Included evidence references, in canonical order.
    pub included_evidence_refs: Vec<String>,
    /// Excluded evidence and the reason it was excluded.
    pub excluded_evidence: Vec<(String, String)>,
    /// Unresolved contradictions observed between members.
    pub unresolved_contradictions: Vec<String>,
    /// Open research debts at freeze time.
    pub open_research_debts: Vec<String>,
    /// State Fence the freeze was taken under.
    pub state_fence: StateFence,
    /// Freeze instant in Unix milliseconds.
    pub frozen_at_ms: i64,
    /// Always false: a freeze is never canonical state.
    pub canonical: bool,
    /// Always true: promotion requires Governor admission.
    pub governor_admission_required: bool,
    /// Digest over the freeze shape.
    pub digest: String,
}

impl EvidenceFreeze {
    /// Freezes the accepted evidence revision for one inquiry.
    ///
    /// # Errors
    ///
    /// Returns a field error for blank identities or malformed digests.
    #[allow(clippy::too_many_arguments)]
    pub fn freeze(
        inquiry_id: &str,
        profile: &InquiryProtocolProfile,
        portfolio_digest: &str,
        manifest_digest: &str,
        coverage_receipt_digest: &str,
        evidence_set_id: &str,
        included_evidence_refs: Vec<String>,
        excluded_evidence: Vec<(String, String)>,
        unresolved_contradictions: Vec<String>,
        open_research_debts: Vec<String>,
        frozen_at_ms: i64,
    ) -> Result<Self, InquiryError> {
        require_text(inquiry_id, "freeze.inquiry_id")?;
        require_text(evidence_set_id, "freeze.evidence_set_id")?;
        require_digest(portfolio_digest, "freeze.portfolio_digest")?;
        require_digest(manifest_digest, "freeze.manifest_digest")?;
        require_digest(coverage_receipt_digest, "freeze.coverage_receipt_digest")?;
        let mut record = Self {
            freeze_id: format!("freeze-{inquiry_id}-{}", profile.profile_id_and_revision()),
            inquiry_id: inquiry_id.to_owned(),
            profile_id_and_revision: profile.profile_id_and_revision(),
            profile_digest: profile.integrity_digest.clone(),
            portfolio_digest: portfolio_digest.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            coverage_receipt_digest: coverage_receipt_digest.to_owned(),
            evidence_set_id: evidence_set_id.to_owned(),
            included_evidence_refs,
            excluded_evidence,
            unresolved_contradictions,
            open_research_debts,
            state_fence: profile.state_fence.clone(),
            frozen_at_ms,
            canonical: false,
            governor_admission_required: true,
            digest: String::new(),
        };
        record.digest = record.compute_digest();
        Ok(record)
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("evidence-freeze/v1;");
        push_field(&mut preimage, "freeze_id", &self.freeze_id);
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(
            &mut preimage,
            "profile_id_and_revision",
            &self.profile_id_and_revision,
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_field(&mut preimage, "portfolio_digest", &self.portfolio_digest);
        push_field(&mut preimage, "manifest_digest", &self.manifest_digest);
        push_field(
            &mut preimage,
            "coverage_receipt_digest",
            &self.coverage_receipt_digest,
        );
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_count(
            &mut preimage,
            "included_evidence_refs",
            self.included_evidence_refs.len(),
        );
        for reference in &self.included_evidence_refs {
            push_field(&mut preimage, "included", reference);
        }
        push_count(
            &mut preimage,
            "excluded_evidence",
            self.excluded_evidence.len(),
        );
        for (handle, reason) in &self.excluded_evidence {
            push_field(&mut preimage, "excluded", handle);
            push_field(&mut preimage, "reason", reason);
        }
        push_count(
            &mut preimage,
            "unresolved_contradictions",
            self.unresolved_contradictions.len(),
        );
        for contradiction in &self.unresolved_contradictions {
            push_field(&mut preimage, "contradiction", contradiction);
        }
        push_count(
            &mut preimage,
            "open_research_debts",
            self.open_research_debts.len(),
        );
        for debt in &self.open_research_debts {
            push_field(&mut preimage, "debt", debt);
        }
        push_field(
            &mut preimage,
            "frozen_at_ms",
            &self.frozen_at_ms.to_string(),
        );
        freeze(&preimage)
    }

    /// Re-proves this freeze's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.compute_digest() != self.digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "freeze.digest",
            });
        }
        Ok(())
    }
}

/// Kind of one research debt (I21.12).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResearchDebtKind {
    /// A load-bearing assumption is unverified.
    Epistemic,
    /// A candidate lacks a sufficient verifier.
    Verification,
    /// No independent failure domain backs a generalization.
    Replication,
    /// A material question branch is unclosed.
    Coverage,
    /// A conflict is unresolved and unscoped.
    Contradiction,
    /// The evaluator poorly represents the target.
    Fidelity,
    /// A raw artifact or lineage is missing.
    Provenance,
    /// A trade-off was not accepted by its owner.
    Authority,
}

impl ResearchDebtKind {
    /// Stable wire spelling of this debt kind.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Epistemic => "epistemic",
            Self::Verification => "verification",
            Self::Replication => "replication",
            Self::Coverage => "coverage",
            Self::Contradiction => "contradiction",
            Self::Fidelity => "fidelity",
            Self::Provenance => "provenance",
            Self::Authority => "authority",
        }
    }

    /// The claim class this debt blocks.
    #[must_use]
    pub const fn blocks(self) -> &'static str {
        match self {
            Self::Epistemic => "a strong claim",
            Self::Verification => "release",
            Self::Replication => "generalization",
            Self::Coverage => "completeness",
            Self::Contradiction => "a unified conclusion",
            Self::Fidelity => "decision confidence",
            Self::Provenance => "audit",
            Self::Authority => "the final decision",
        }
    }
}

/// One registered research debt (I21.12).
///
/// An unmet obligation is a typed object, not a caveat at the end of a report.
/// Registration in the Problem Registry is owned elsewhere; this record is the
/// non-canonical candidate binding the Governor admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchDebt {
    /// Stable debt identity.
    pub debt_id: String,
    /// Inquiry identity the debt belongs to.
    pub inquiry_id: String,
    /// Profile revision the debt was registered under.
    pub profile_digest: String,
    /// Debt kind.
    pub kind: ResearchDebtKind,
    /// Bounded summary of what is unmet.
    pub summary: String,
    /// Owner accountable for resolving the debt.
    pub owner: String,
    /// Condition under which the debt is reviewed.
    pub review_condition: String,
    /// Expiry in Unix milliseconds, when the debt expires.
    pub expires_at_ms: Option<i64>,
    /// What this debt blocks.
    pub blocks: String,
    /// State Fence the debt was registered under.
    pub state_fence: StateFence,
    /// Always true while the debt is open.
    pub open: bool,
    /// Always false: a debt is never canonical state on its own.
    pub canonical: bool,
    /// Digest over the debt shape.
    pub digest: String,
}

impl ResearchDebt {
    /// Registers one debt for an inquiry.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank identity, owner, summary or review
    /// condition.
    #[allow(clippy::too_many_arguments)]
    pub fn register(
        debt_id: &str,
        inquiry_id: &str,
        profile: &InquiryProtocolProfile,
        kind: ResearchDebtKind,
        summary: &str,
        owner: &str,
        review_condition: &str,
        expires_at_ms: Option<i64>,
    ) -> Result<Self, InquiryError> {
        require_text(debt_id, "debt.debt_id")?;
        require_text(inquiry_id, "debt.inquiry_id")?;
        require_text(summary, "debt.summary")?;
        require_text(owner, "debt.owner")?;
        require_text(review_condition, "debt.review_condition")?;
        let mut debt = Self {
            debt_id: debt_id.to_owned(),
            inquiry_id: inquiry_id.to_owned(),
            profile_digest: profile.integrity_digest.clone(),
            kind,
            summary: summary.to_owned(),
            owner: owner.to_owned(),
            review_condition: review_condition.to_owned(),
            expires_at_ms,
            blocks: kind.blocks().to_owned(),
            state_fence: profile.state_fence.clone(),
            open: true,
            canonical: false,
            digest: String::new(),
        };
        debt.digest = debt.compute_digest();
        Ok(debt)
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("research-debt/v1;");
        push_field(&mut preimage, "debt_id", &self.debt_id);
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_field(&mut preimage, "kind", self.kind.wire_name());
        push_field(&mut preimage, "summary", &self.summary);
        push_field(&mut preimage, "owner", &self.owner);
        push_field(&mut preimage, "review_condition", &self.review_condition);
        if let Some(expiry) = self.expires_at_ms {
            push_field(&mut preimage, "expires_at_ms", &expiry.to_string());
        }
        push_field(&mut preimage, "blocks", &self.blocks);
        freeze(&preimage)
    }
}

/// Claim-audit binding for one audited claim (I21.8).
///
/// The audit itself is owned by [`crate::evidence_portfolio::audit_claim`]; this
/// record binds its verdict to the inquiry profile, the frozen manifest and the
/// State Fence, and states that the result is a non-canonical candidate. The
/// reference firewall holds: no citation, source identity, URL, line range or
/// support relation is minted here through prose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimAuditRecord {
    /// Audited claim identity.
    pub claim_id: String,
    /// Inquiry identity.
    pub inquiry_id: String,
    /// Profile revision the audit ran under.
    pub profile_id_and_revision: String,
    /// Profile revision digest.
    pub profile_digest: String,
    /// Manifest digest the claim was audited against.
    pub manifest_digest: String,
    /// Evidence-set identity.
    pub evidence_set_id: String,
    /// Verdict produced by the existing claim-audit owner.
    pub verdict: ClaimVerdict,
    /// State Fence the audit ran under.
    pub state_fence: StateFence,
    /// Always false: a claim audit never becomes canonical state by itself.
    pub canonical: bool,
    /// Digest over the binding shape.
    pub digest: String,
}

impl ClaimAuditRecord {
    /// Binds one claim verdict to the inquiry it was produced under.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank identity or a malformed manifest
    /// digest.
    pub fn bind(
        inquiry_id: &str,
        profile: &InquiryProtocolProfile,
        manifest_digest: &str,
        evidence_set_id: &str,
        verdict: ClaimVerdict,
    ) -> Result<Self, InquiryError> {
        require_text(inquiry_id, "claim_audit.inquiry_id")?;
        require_text(evidence_set_id, "claim_audit.evidence_set_id")?;
        require_digest(manifest_digest, "claim_audit.manifest_digest")?;
        let mut record = Self {
            claim_id: verdict.claim_id.clone(),
            inquiry_id: inquiry_id.to_owned(),
            profile_id_and_revision: profile.profile_id_and_revision(),
            profile_digest: profile.integrity_digest.clone(),
            manifest_digest: manifest_digest.to_owned(),
            evidence_set_id: evidence_set_id.to_owned(),
            verdict,
            state_fence: profile.state_fence.clone(),
            canonical: false,
            digest: String::new(),
        };
        record.digest = record.compute_digest();
        Ok(record)
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("claim-audit-record/v1;");
        push_field(&mut preimage, "claim_id", &self.claim_id);
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(
            &mut preimage,
            "profile_id_and_revision",
            &self.profile_id_and_revision,
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_field(&mut preimage, "manifest_digest", &self.manifest_digest);
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_field(
            &mut preimage,
            "verdict_outcome",
            self.verdict.outcome.wire_name(),
        );
        for (tag, values) in [
            ("residue", &self.verdict.residue),
            ("counterevidence", &self.verdict.counterevidence),
            ("unknown", &self.verdict.unknowns),
            ("evidence_map", &self.verdict.evidence_map),
        ] {
            push_count(&mut preimage, tag, values.len());
            for value in values {
                push_field(&mut preimage, tag, value);
            }
        }
        // I21.7: the over-precision residue is bound as the typed items it is,
        // so a binding that covers this record cannot be re-pointed at a
        // different asserted coordinate by changing only the rendered prose.
        for line in self.verdict.unsupported_precision_lines() {
            push_field(&mut preimage, "unsupported_precision", &line);
        }
        push_count(
            &mut preimage,
            "unsupported_precision",
            self.verdict.unsupported_precision.len(),
        );
        freeze(&preimage)
    }
}

/// Explicitly preserved unknown on a terminal inquiry record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservedUnknown {
    /// What remains unknown.
    pub subject: String,
    /// Bounded detail of the unknown.
    pub detail: String,
}

/// Preserved next probe on a terminal inquiry record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservedNextProbe {
    /// Reopen condition the probe satisfies.
    pub reopen_condition: ReopenCondition,
    /// Obligations the probe would close.
    pub obligation_refs: Vec<String>,
    /// Bounded statement of what the next probe must do.
    pub required_probe: String,
}

/// Terminal typed disposition of one inquiry (I21.9).
///
/// An empty answer or an exhausted search is never silently promoted to
/// "question answered": the record binds the profile, portfolio, manifest and
/// State Fence, and every non-closing disposition must preserve an explicit
/// unknown, a narrower claim, or a next probe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryTerminalRecord {
    /// Inquiry identity.
    pub inquiry_id: String,
    /// Profile identity.
    pub profile_id: String,
    /// Profile revision.
    pub profile_revision: u64,
    /// Profile revision digest.
    pub profile_digest: String,
    /// Portfolio digest the disposition was computed over.
    pub portfolio_digest: String,
    /// Reference manifest digest.
    pub manifest_digest: String,
    /// Coverage receipt digest.
    pub coverage_receipt_digest: String,
    /// Evidence-set identity.
    pub evidence_set_id: String,
    /// Declared denominator kind behind the disposition.
    pub denominator_kind: DenominatorKind,
    /// Typed completion disposition, reusing the canonical closed vocabulary.
    pub disposition: CompletionDisposition,
    /// Terminal acquisition outcome the disposition was derived from.
    pub acquisition_outcome: AcquisitionOutcome,
    /// Exact reason code the provider run reported.
    pub reason_code: String,
    /// Explicit preserved unknown.
    pub explicit_unknown: Option<PreservedUnknown>,
    /// Narrower claim the evidence actually supports.
    pub narrower_claim: Option<String>,
    /// Preserved next probe.
    pub next_probe: Option<PreservedNextProbe>,
    /// State Fence the disposition was taken under.
    pub state_fence: StateFence,
    /// Always true: a terminal inquiry record stays candidate-only.
    pub candidate_only: bool,
    /// Always false: closing a task stays in the existing Governor path.
    pub canonical_write_authorized: bool,
    /// Digest over the record shape.
    pub digest: String,
}

impl InquiryTerminalRecord {
    /// Binds the terminal disposition to the profile, portfolio, manifest and
    /// State Fence.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::PreservationRequired`] when a non-closing
    /// disposition carries no explicit unknown, no narrower claim and no next
    /// probe, [`InquiryError::ClosureWithoutCompleteScope`] when a closing
    /// disposition rests on a denominator that is not a complete scope, and a
    /// field error for blank identities or malformed digests.
    #[allow(clippy::too_many_arguments)]
    pub fn bind(
        profile: &InquiryProtocolProfile,
        portfolio_digest: &str,
        manifest_digest: &str,
        coverage_receipt_digest: &str,
        evidence_set_id: &str,
        denominator_kind: DenominatorKind,
        disposition: CompletionDisposition,
        acquisition_outcome: AcquisitionOutcome,
        reason_code: &str,
        explicit_unknown: Option<PreservedUnknown>,
        narrower_claim: Option<String>,
        next_probe: Option<PreservedNextProbe>,
    ) -> Result<Self, InquiryError> {
        require_text(evidence_set_id, "terminal.evidence_set_id")?;
        require_text(reason_code, "terminal.reason_code")?;
        require_digest(portfolio_digest, "terminal.portfolio_digest")?;
        require_digest(manifest_digest, "terminal.manifest_digest")?;
        require_digest(coverage_receipt_digest, "terminal.coverage_receipt_digest")?;
        let may_close = disposition.may_close_inquiry();
        if may_close && !denominator_kind.supports_scoped_absence() {
            return Err(InquiryError::ClosureWithoutCompleteScope {
                field: "terminal.denominator_kind",
            });
        }
        let preserved =
            explicit_unknown.is_some() || narrower_claim.is_some() || next_probe.is_some();
        if !may_close && !preserved {
            return Err(InquiryError::PreservationRequired {
                field: "terminal.disposition",
            });
        }
        let mut record = Self {
            inquiry_id: profile.inquiry_id.clone(),
            profile_id: profile.profile_id.clone(),
            profile_revision: profile.revision,
            profile_digest: profile.integrity_digest.clone(),
            portfolio_digest: portfolio_digest.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            coverage_receipt_digest: coverage_receipt_digest.to_owned(),
            evidence_set_id: evidence_set_id.to_owned(),
            denominator_kind,
            disposition,
            acquisition_outcome,
            reason_code: reason_code.to_owned(),
            explicit_unknown,
            narrower_claim,
            next_probe,
            state_fence: profile.state_fence.clone(),
            candidate_only: true,
            canonical_write_authorized: false,
            digest: String::new(),
        };
        record.digest = record.compute_digest();
        Ok(record)
    }

    /// Whether this disposition may close its inquiry.
    ///
    /// Only `ANSWERED_WITH_SUPPORTED_RESULT` or a properly scoped
    /// `NO_MATCH_IN_COMPLETE_SCOPE` may close; every other outcome stays open
    /// and keeps its preserved unknown, narrower claim and next probe.
    #[must_use]
    pub fn may_close(&self) -> bool {
        self.disposition.may_close_inquiry()
    }

    /// Whether the acquisition this record was derived from reported success.
    ///
    /// A successful acquisition is not an answered inquiry: only the disposition
    /// and its declared denominator kind decide closure.
    #[must_use]
    pub fn acquisition_succeeded(&self) -> bool {
        self.acquisition_outcome.is_successful()
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("inquiry-terminal-record/v1;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "profile_id", &self.profile_id);
        push_field(
            &mut preimage,
            "profile_revision",
            &self.profile_revision.to_string(),
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_field(&mut preimage, "portfolio_digest", &self.portfolio_digest);
        push_field(&mut preimage, "manifest_digest", &self.manifest_digest);
        push_field(
            &mut preimage,
            "coverage_receipt_digest",
            &self.coverage_receipt_digest,
        );
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_field(
            &mut preimage,
            "denominator_kind",
            self.denominator_kind.wire_name(),
        );
        push_field(
            &mut preimage,
            "disposition",
            disposition_wire(self.disposition),
        );
        push_field(
            &mut preimage,
            "acquisition_outcome",
            self.acquisition_outcome.wire_name(),
        );
        push_field(&mut preimage, "reason_code", &self.reason_code);
        if let Some(unknown) = &self.explicit_unknown {
            push_field(&mut preimage, "unknown_subject", &unknown.subject);
            push_field(&mut preimage, "unknown_detail", &unknown.detail);
        }
        if let Some(claim) = &self.narrower_claim {
            push_field(&mut preimage, "narrower_claim", claim);
        }
        if let Some(probe) = &self.next_probe {
            push_field(
                &mut preimage,
                "next_probe_condition",
                probe.reopen_condition.wire_name(),
            );
            push_field(&mut preimage, "next_probe_required", &probe.required_probe);
            push_count(
                &mut preimage,
                "next_probe_obligations",
                probe.obligation_refs.len(),
            );
            for obligation in &probe.obligation_refs {
                push_field(&mut preimage, "next_probe_obligation", obligation);
            }
        }
        push_field(&mut preimage, "may_close", bool_text(self.may_close()));
        freeze(&preimage)
    }

    /// Re-proves this record's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.compute_digest() != self.digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "terminal.digest",
            });
        }
        Ok(())
    }
}

/// Terminal outcome of one admitted acquisition run, in the vocabulary this
/// domain owns.
///
/// The composition root maps its own typed provider outcome onto this closed
/// vocabulary; the domain never depends on a composition crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquisitionOutcome {
    /// The provider operation reached its terminal completion.
    Completed,
    /// The provider process or its contour failed.
    Crashed,
    /// The bounded run exceeded its admitted deadline.
    TimedOut,
    /// An admitted cancellation ended the run.
    Cancelled,
    /// The outcome could not be established and needs reconciliation.
    Unknown,
    /// The run was refused before or at execution and produced no evidence.
    Refused,
}

impl AcquisitionOutcome {
    /// Whether this outcome means the provider operation itself succeeded.
    #[must_use]
    pub const fn is_successful(self) -> bool {
        matches!(self, Self::Completed)
    }

    /// Stable wire spelling of this outcome.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Crashed => "crashed",
            Self::TimedOut => "timed_out",
            Self::Cancelled => "cancelled",
            Self::Unknown => "unknown",
            Self::Refused => "refused",
        }
    }
}

/// Retained stream evidence state for one provider stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamEvidence {
    /// No stream handle was supplied.
    Absent,
    /// A partial or truncated stream was retained.
    Partial,
    /// The complete stream was retained.
    Complete,
}

/// One candidate source material proposed to an inquiry evidence set.
///
/// The provider resolved and snapshotted the material; this observation is the
/// exact custody of that snapshot (content digest, receipt handle, exit
/// disposition and process lineage) and never the payload body.
#[derive(Clone, Debug)]
pub struct CandidateEvidence {
    /// Stable handle of the captured material.
    pub handle: String,
    /// Source class of the captured material.
    pub class: SourceClass,
    /// Admitted operation identity that produced it.
    pub operation_id: String,
    /// Exact digest of the captured content bytes.
    pub content_digest: String,
    /// Retained raw-evidence receipt handle.
    pub receipt_handle: String,
    /// Admitted route that produced it.
    pub route: String,
    /// Admitted provider generation that produced it.
    pub provider_generation: String,
    /// Exact common lineage root, when known.
    pub lineage_root: Option<String>,
    /// Terminal outcome of the acquisition.
    pub outcome: AcquisitionOutcome,
    /// Retained stream state of the captured material.
    pub stream: StreamEvidence,
    /// Whether the provider process exited normally.
    pub exit_completed: bool,
    /// Whether the operation was refused rather than executed.
    pub refused: bool,
}

/// Which reference identity an unadmitted observation presented as.
///
/// I21.7: "It cannot mint a valid citation, URL, source ID, line range, artifact
/// handle or support relation through prose." Naming which of those identities
/// was observed is what makes the retained diagnostic actionable, because each
/// has a different acquisition path: a URL needs a provider to resolve and
/// snapshot it, an artifact handle needs a manifest transition, and a stale or
/// revoked handle needs a fresh admission rather than any acquisition at all.
///
/// The live record path observes exactly these three identities and no more,
/// because the composition root never decodes the provider body: a source
/// identity is judged on the `SourceRecord.handle` the observation projects into
/// ([`crate::source_admissibility::SourceAdmissibilityRecord::evaluate`]), and a
/// line range is judged by the manifest's admitted anchor precision in
/// [`EvidenceSetPrecision::evaluate`]. Neither can be a *citation* on this path,
/// so neither is a candidate diagnostic here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnadmittedReferenceKind {
    /// A URL the manifest does not list as a URL handle.
    LocatorUrl,
    /// An artifact handle the manifest does not list.
    ArtifactHandle,
    /// A handle the manifest lists but marks stale or revoked.
    StaleOrRevoked,
}

impl UnadmittedReferenceKind {
    /// Stable wire spelling of this reference identity.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::LocatorUrl => "LOCATOR_URL",
            Self::ArtifactHandle => "ARTIFACT_HANDLE",
            Self::StaleOrRevoked => "STALE_OR_REVOKED",
        }
    }
}

/// One reference observed in the observed material that the run-bound manifest
/// does not admit.
///
/// I21.7: "A syntactically plausible but absent/stale/wrong-scope reference
/// remains unsupported text and produces a candidate diagnostic rather than an
/// evidence edge", and a newly mentioned external URL "may be captured as an
/// untrusted `ObservationCandidate` for later acquisition, but it is not treated
/// as an allowed source or citation for the current run". This is that
/// untrusted candidate diagnostic in the research plane's own vocabulary: the
/// reference text is retained verbatim as inert data, the kind names which
/// identity it is, and the reason names why the manifest does not admit it.
///
/// The record is a candidate only. `trusted` is always false, it grants no
/// citation and no support relation, and the only transition out of it is a
/// Governor-applied `SourceRecord` transition that adds the handle to a new
/// frozen manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnadmittedReference {
    /// Inquiry identity this diagnostic belongs to.
    pub inquiry_id: String,
    /// Evidence-set identity this diagnostic belongs to.
    pub evidence_set_id: String,
    /// The untrusted reference text, retained verbatim as data.
    pub reference: String,
    /// Which reference identity this is.
    pub kind: UnadmittedReferenceKind,
    /// Why the run-bound manifest does not admit it.
    pub reason: String,
    /// State Fence the diagnostic was observed under.
    pub state_fence: StateFence,
    /// Always false: an unadmitted reference is never trusted.
    pub trusted: bool,
    /// Digest over the diagnostic shape.
    pub digest: String,
}

impl UnadmittedReference {
    /// Records one observed reference the run-bound manifest does not admit.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank inquiry, evidence-set or reference
    /// identity.
    pub fn observe(
        inquiry_id: &str,
        evidence_set_id: &str,
        reference: &str,
        kind: UnadmittedReferenceKind,
        reason: &str,
        state_fence: &StateFence,
    ) -> Result<Self, InquiryError> {
        require_text(inquiry_id, "unadmitted_reference.inquiry_id")?;
        require_text(evidence_set_id, "unadmitted_reference.evidence_set_id")?;
        require_text(reference, "unadmitted_reference.reference")?;
        require_text(reason, "unadmitted_reference.reason")?;
        let mut record = Self {
            inquiry_id: inquiry_id.to_owned(),
            evidence_set_id: evidence_set_id.to_owned(),
            reference: reference.to_owned(),
            kind,
            reason: reason.to_owned(),
            state_fence: state_fence.clone(),
            trusted: false,
            digest: String::new(),
        };
        record.digest = record.compute_digest();
        Ok(record)
    }

    /// Re-proves this diagnostic's own digest and its candidate-only shape.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.trusted || self.compute_digest() != self.digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "unadmitted_reference.digest",
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("unadmitted-reference/v1;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_field(&mut preimage, "reference", &self.reference);
        push_field(&mut preimage, "kind", self.kind.wire_name());
        push_field(&mut preimage, "reason", &self.reason);
        push_field(&mut preimage, "trusted", bool_text(self.trusted));
        freeze(&preimage)
    }
}

/// Named constructor arguments for [`InquiryGovernance::record`].
#[derive(Clone, Debug)]
pub struct InquiryObservation {
    /// Stable inquiry identity.
    pub inquiry_id: String,
    /// Stable evidence-set identity.
    pub evidence_set_id: String,
    /// Profile identity.
    pub profile_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Admitted exchange identity.
    pub exchange_id: String,
    /// Kernel-admitted digest of the frozen inquiry.
    pub inquiry_digest: String,
    /// Kernel-admitted denominator digest.
    pub denominator_digest: String,
    /// Exact question under inquiry.
    pub question: String,
    /// Exact frozen scope.
    pub scope: String,
    /// Decision or artifact the answer must serve.
    pub intended_decision_or_artifact: String,
    /// Requesting principal.
    pub requester: String,
    /// Source classes the inquiry requested.
    pub requested_source_classes: Vec<SourceClass>,
    /// Reference manifest the run was admitted under.
    pub reference_manifest: AllowedReferenceManifest,
    /// Admitted coverage-goal text exactly as admitted.
    pub admitted_coverage_goal: String,
    /// Admitted result schema.
    pub required_schema: String,
    /// Admitted privacy class.
    pub disclosure: DisclosureClass,
    /// Admitted budget ceiling.
    pub budget_units: u64,
    /// Admitted deadline ceiling.
    pub deadline_ms: i64,
    /// Admitted cancellation identity.
    pub cancellation_id: String,
    /// Admitted provider module generation.
    pub provider_generation: String,
    /// Admitted route identities usable for this inquiry.
    pub admissible_routes: Vec<String>,
    /// Structural features the selection is resolved from.
    pub features: InquirySelectionFeatures,
    /// Candidate material proposed to the evidence set.
    pub candidates: Vec<CandidateEvidence>,
    /// Terminal outcome of the acquisition run.
    pub outcome: AcquisitionOutcome,
    /// Exact reason code the run reported.
    pub reason_code: String,
    /// Assessment instant in Unix milliseconds.
    pub assessment_time_ms: i64,
}

/// The `R6` inquiry-governance record for one inquiry.
///
/// This is the composite the runtime shows: a versioned inquiry profile with its
/// selected grade and lane, the source-admissibility disposition of every
/// proposed source, a coverage receipt with a declared denominator kind, the
/// compiler inputs for the open obligations, the non-canonical governed
/// artifacts, and a terminal typed inquiry disposition bound to the profile,
/// portfolio, manifest and State Fence.
#[derive(Clone, Debug)]
pub struct InquiryGovernance {
    /// Inquiry identity.
    pub inquiry_id: String,
    /// Evidence-set identity.
    pub evidence_set_id: String,
    /// Versioned inquiry protocol profile.
    pub profile: InquiryProtocolProfile,
    /// Source-admissibility disposition of every proposed source.
    pub admissibility: Vec<SourceAdmissibilityRecord>,
    /// Untrusted candidate diagnostics for every observed reference the
    /// run-bound manifest does not admit.
    ///
    /// This is the I21.7 demotion: the reference text is retained here as inert
    /// data instead of being dropped, and nothing in this set is a source, a
    /// citation, a support relation or an evidence edge.
    pub unadmitted_references: Vec<UnadmittedReference>,
    /// Frozen source portfolio.
    pub portfolio: SourcePortfolio,
    /// Coverage receipt with its declared denominator kind.
    pub coverage_receipt: CoverageReceipt,
    /// Highest supported anchor precision and its residue.
    pub precision: EvidenceSetPrecision,
    /// Obligations compiled as inputs for the existing work-graph owner.
    pub obligations: Vec<InquiryObligation>,
    /// Evidence freeze of the accepted evidence revision.
    pub freeze: EvidenceFreeze,
    /// Registered research debts.
    pub research_debts: Vec<ResearchDebt>,
    /// Terminal typed inquiry disposition.
    pub terminal: InquiryTerminalRecord,
    /// Governor-facing profile admission request.
    pub profile_admission_request: GovernorInquiryAdmissionRequest,
    /// Governor-facing source transition requests.
    pub source_admission_requests: Vec<GovernorSourceTransitionRequest>,
    /// Compiler inputs for the existing `TaskGraphCompiler` owner.
    pub compilation_inputs: TaskGraphCompilationInputs,
}

impl InquiryGovernance {
    /// Records the complete `R6` governance view of one observed inquiry.
    ///
    /// # Errors
    ///
    /// Returns a field, vocabulary, denominator or integrity error when the
    /// admitted material cannot produce a bound, non-closing record. No branch
    /// fabricates a closing disposition, a coverage claim, or an evidence
    /// reference.
    pub fn record(observation: InquiryObservation) -> Result<Self, InquiryError> {
        // I21.7 reference firewall, before candidate promotion and on the live
        // path: the run-bound allowlist is a mandatory input, so it is validated
        // and its digest is re-proved against its own content first. A manifest
        // whose content was widened after it was sealed, or whose digest is a
        // caller-supplied string unrelated to its fields, produces no record at
        // all instead of a record that publishes a false bound allowlist into
        // the profile, coverage receipt, evidence freeze and terminal digests.
        observation.reference_manifest.validate()?;
        let unadmitted_references = reference_firewall(&observation)?;
        let profile = resolve_profile(&observation)?;
        let admissibility = assess_sources(&observation, &profile)?;
        let portfolio =
            SourcePortfolio::assemble(&observation.inquiry_id, &profile, &admissibility)?;
        let account = coverage_account(&observation)?;
        let degradation = degradation(&observation, &account);
        let coverage_receipt = CoverageReceipt::compute(
            &profile,
            &observation.scope,
            &observation.reference_manifest.digest,
            &account,
            &admissibility,
            observation.admissible_routes.clone(),
            degradation.provider_degradation,
            degradation.unknown_coverage,
            degradation.budget_limitation,
        )?;
        let precision = EvidenceSetPrecision::evaluate(
            &observation.inquiry_id,
            observation.reference_manifest.allowed_anchor_precision,
            &admissibility,
        );
        let obligations = open_obligations(&observation, &profile, &account)?;
        let compilation_inputs = TaskGraphCompilationInputs::for_inquiry(
            &profile,
            &observation.evidence_set_id,
            &obligations,
        )?;
        let research_debts = research_debts(
            &observation,
            &profile,
            &portfolio,
            &coverage_receipt,
            &precision,
        )?;
        let freeze = evidence_freeze(
            &observation,
            &profile,
            &portfolio,
            &coverage_receipt,
            &admissibility,
            &research_debts,
        )?;
        let terminal = terminal_record(
            &observation,
            &profile,
            &portfolio,
            &coverage_receipt,
            &precision,
            &obligations,
        )?;
        let record = Self {
            inquiry_id: observation.inquiry_id,
            evidence_set_id: observation.evidence_set_id,
            profile_admission_request: profile.admission_request(),
            source_admission_requests: admissibility
                .iter()
                .map(SourceAdmissibilityRecord::transition_request)
                .collect(),
            unadmitted_references,
            profile,
            admissibility,
            portfolio,
            coverage_receipt,
            precision,
            obligations,
            freeze,
            research_debts,
            terminal,
            compilation_inputs,
        };
        record.validate_integrity()?;
        Ok(record)
    }

    /// Re-proves every digest this record publishes and every binding between
    /// the profile, the portfolio, the manifest, the State Fence and the
    /// terminal disposition.
    ///
    /// # Errors
    ///
    /// Returns the first integrity failure observed.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        self.profile.validate_integrity()?;
        self.freeze.validate_integrity()?;
        self.terminal.validate_integrity()?;
        self.compilation_inputs.validate_integrity()?;
        if self.compilation_inputs.profile_digest != self.profile.integrity_digest
            || self.compilation_inputs.evidence_set_id != self.evidence_set_id
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.compilation_inputs",
            });
        }
        if !self
            .profile
            .binds(&self.inquiry_id, &self.freeze.state_fence)
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.profile_binding",
            });
        }
        if self.terminal.profile_digest != self.profile.integrity_digest
            || self.terminal.portfolio_digest != self.portfolio.digest
            || self.terminal.coverage_receipt_digest != self.coverage_receipt.digest
            || self.terminal.manifest_digest != self.profile.reference_manifest_digest
            || self.terminal.state_fence != self.profile.state_fence
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.terminal_binding",
            });
        }
        if self.freeze.coverage_receipt_digest != self.coverage_receipt.digest
            || self.freeze.portfolio_digest != self.portfolio.digest
            || self.freeze.manifest_digest != self.profile.reference_manifest_digest
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.freeze_binding",
            });
        }
        for record in &self.admissibility {
            record.validate_integrity()?;
        }
        for diagnostic in &self.unadmitted_references {
            diagnostic.validate_integrity()?;
            if diagnostic.inquiry_id != self.inquiry_id
                || diagnostic.evidence_set_id != self.evidence_set_id
                || diagnostic.state_fence != self.terminal.state_fence
            {
                return Err(InquiryError::IntegrityMismatch {
                    field: "inquiry.unadmitted_reference_binding",
                });
            }
        }
        for obligation in &self.obligations {
            obligation.validate_integrity()?;
        }
        Ok(())
    }
}

impl std::fmt::Display for InquiryGovernance {
    /// Renders the composite as one bounded, secret-free key/value line.
    ///
    /// Only identities, digests, closed-vocabulary spellings, counts and typed
    /// dispositions appear: no provider prose, payload body or credential is
    /// reproduced, and the candidate-only flag is printed so a reader cannot
    /// mistake the line for an admitted result.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let terminal = &self.terminal;
        let eligible = self
            .admissibility
            .iter()
            .filter(|record| record.eligibility == SourceEligibility::Eligible)
            .count();
        write!(
            formatter,
            "contract={INQUIRY_GOVERNANCE_CONTRACT} version={INQUIRY_GOVERNANCE_VERSION} \
             inquiry={} evidence_set={} profile={}@{} protocol={} grade={} lane={} \
             coverage_goal={} goal_text_resolved={} hypothesis_policy={} manifest={} \
             admitted_inquiry={} admitted_denominator={} stop_rule={} output_contract={} \
             independence_ok={} admissibility={} eligible={} unadmitted_refs={} portfolio={} \
             expected_members={} open_members={} accounted={} all_closed={} denominator_kind={} \
             absence={} supported_precision={} precision_residue={} obligations={} \
             materialisable={} deferred={} compilation_inputs={} freeze={} debts={} \
             disposition={} terminal_denominator_kind={} may_close={} \
             acquisition_succeeded={} preserved_unknown={} narrower_claim={} \
             next_probe={} reason={} authority_epoch={}/{} candidate_only={}",
            self.inquiry_id,
            self.evidence_set_id,
            self.profile.profile_id,
            self.profile.revision,
            self.profile.protocol,
            self.profile.evidence_grade,
            self.profile.lane,
            self.profile.coverage_goal,
            self.profile.admitted_coverage_goal_resolved,
            self.profile.hypothesis_policy.wire_name(),
            self.profile.reference_manifest_digest,
            self.profile.admitted_inquiry_digest,
            self.profile.admitted_denominator_digest,
            self.profile.stop_rule.stop_rule.wire_name(),
            self.profile.output_contract.output_contract,
            self.portfolio.independence.meets_requirement,
            self.admissibility.len(),
            eligible,
            self.unadmitted_references.len(),
            self.portfolio.digest,
            self.coverage_receipt.expected_members,
            self.coverage_receipt.open_members.len(),
            self.coverage_receipt.accounted,
            self.coverage_receipt.all_closed,
            self.coverage_receipt.denominator_kind,
            absence_wire(&self.coverage_receipt.absence_verdict),
            anchor_wire(self.precision.supported_precision),
            self.precision.residue.len(),
            self.obligations.len(),
            self.compilation_inputs.materialisable().len(),
            self.compilation_inputs.deferred().len(),
            self.compilation_inputs.digest,
            self.freeze.digest,
            self.research_debts.len(),
            disposition_wire(terminal.disposition),
            terminal.denominator_kind,
            terminal.may_close(),
            terminal.acquisition_succeeded(),
            terminal.explicit_unknown.is_some(),
            terminal.narrower_claim.is_some(),
            terminal.next_probe.is_some(),
            terminal.reason_code,
            terminal.state_fence.authority_epoch.lineage_id,
            terminal.state_fence.authority_epoch.sequence,
            terminal.candidate_only,
        )
    }
}

/// Resolves the profile revision for one observed inquiry.
fn resolve_profile(
    observation: &InquiryObservation,
) -> Result<InquiryProtocolProfile, InquiryError> {
    let stop_rule = InquiryStopRule::resolve(
        observation.budget_units,
        observation.deadline_ms,
        StopRuleKind::BudgetOrDeadlineExhausted,
        &observation.cancellation_id,
    )?;
    let mut truth_surfaces = observation.admissible_routes.clone();
    truth_surfaces.push(observation.provider_generation.clone());
    truth_surfaces.sort();
    truth_surfaces.dedup();
    InquiryProtocolProfile::resolve(InquiryProfileParams {
        profile_id: observation.profile_id.clone(),
        inquiry_id: observation.inquiry_id.clone(),
        operation_id: observation.operation_id.clone(),
        exchange_id: observation.exchange_id.clone(),
        question: observation.question.clone(),
        intended_decision_or_artifact: observation.intended_decision_or_artifact.clone(),
        scope: observation.scope.clone(),
        requester_principal: observation.requester.clone(),
        admitted_inquiry_digest: observation.inquiry_digest.clone(),
        features: observation.features,
        truth_surfaces_and_admissible_providers: truth_surfaces,
        admissible_source_classes: observation.requested_source_classes.clone(),
        reference_manifest_digest: observation.reference_manifest.digest.clone(),
        admitted_denominator_digest: observation.denominator_digest.clone(),
        admitted_coverage_goal: observation.admitted_coverage_goal.clone(),
        required_schema: observation.required_schema.clone(),
        disclosure_ceiling: observation.disclosure,
        stop_rule,
        state_fence: observation.reference_manifest.state_fence.clone(),
        lane_registration_digest: None,
    })
}

/// Produces the source-admissibility disposition of every proposed source.
fn assess_sources(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
) -> Result<Vec<SourceAdmissibilityRecord>, InquiryError> {
    let mut records = Vec::new();
    for candidate in &observation.candidates {
        let record = candidate_source_record(candidate, observation)?;
        records.push(SourceAdmissibilityRecord::evaluate(
            &observation.inquiry_id,
            &observation.evidence_set_id,
            profile,
            record,
            &observation.scope,
            &observation.reference_manifest,
            observation.assessment_time_ms,
        )?);
    }
    Ok(records)
}

/// Retains every observed reference the run-bound manifest does not admit as an
/// untrusted candidate diagnostic.
///
/// I21.7: "A syntactically plausible but absent/stale/wrong-scope reference
/// remains unsupported text and produces a candidate diagnostic rather than an
/// evidence edge." This is that diagnostic on the live record path, and it is
/// deliberately *not* a decision: the same reference is still judged by
/// [`assess_sources`], which refuses it for evidentiary use, so the retention
/// here cannot promote anything. What it adds is the retained, typed, digest
/// bound form of the untrusted text, so the Governor sees what the run observed
/// instead of a dropped string.
///
/// The candidate handle is the reference identity this boundary can observe: the
/// composition root derives it from the retained provider artifact digest, so it
/// is caller-influenced text and is checked against the manifest like any other.
/// A URL appearing inside the provider body is not observable here — the live
/// projection never decodes the body — so a URL is admitted or refused at the
/// `SourceSnapshot::locator` boundary in
/// `eliot_research_exchange_api::ResearchEvidenceBundle::validate_against`.
fn reference_firewall(
    observation: &InquiryObservation,
) -> Result<Vec<UnadmittedReference>, InquiryError> {
    let manifest = &observation.reference_manifest;
    let mut diagnostics = Vec::new();
    let mut seen = BTreeSet::new();
    for candidate in &observation.candidates {
        if !seen.insert(candidate.handle.clone()) {
            continue;
        }
        let (kind, reason) = if manifest
            .stale_or_revoked_handles
            .iter()
            .any(|stale| stale == &candidate.handle)
        {
            (
                UnadmittedReferenceKind::StaleOrRevoked,
                "the run-bound manifest lists this reference as stale or revoked",
            )
        } else if !manifest.allows(&candidate.handle) {
            let kind = if candidate.handle.contains("://") {
                UnadmittedReferenceKind::LocatorUrl
            } else {
                UnadmittedReferenceKind::ArtifactHandle
            };
            (
                kind,
                "the run-bound manifest does not admit this reference handle",
            )
        } else {
            continue;
        };
        diagnostics.push(UnadmittedReference::observe(
            &observation.inquiry_id,
            &observation.evidence_set_id,
            &candidate.handle,
            kind,
            reason,
            &manifest.state_fence,
        )?);
    }
    Ok(diagnostics)
}

/// Opens the exact coverage accounting over the admitted reference members.
fn coverage_account(observation: &InquiryObservation) -> Result<CoverageAccount, InquiryError> {
    let manifest = &observation.reference_manifest;
    let mut members: BTreeSet<String> = BTreeSet::new();
    for handle in manifest
        .source_handles
        .iter()
        .chain(&manifest.evidence_handles)
        .chain(&manifest.artifact_handles)
    {
        members.insert(handle.clone());
    }
    CoverageAccount::open(members).map_err(InquiryError::from)
}

/// Observed degradation, coverage unknowns and the budget limitation of one run.
struct RunDegradation {
    /// Typed provider degradation, empty for a clean run.
    provider_degradation: Vec<String>,
    /// Explicit coverage unknowns, never smoothed away.
    unknown_coverage: Vec<String>,
    /// Budget limitation that bounded the run, when one applied.
    budget_limitation: Option<String>,
}

fn degradation(observation: &InquiryObservation, account: &CoverageAccount) -> RunDegradation {
    let mut provider_degradation = Vec::new();
    let mut unknown_coverage = account.open_members();
    unknown_coverage.sort();
    unknown_coverage.dedup();
    if !observation.outcome.is_successful() {
        provider_degradation.push(format!(
            "acquisition_outcome={} reason={}",
            observation.outcome.wire_name(),
            observation.reason_code
        ));
    }
    let budget_limitation = (observation.outcome == AcquisitionOutcome::TimedOut).then(|| {
        format!(
            "admitted budget_units={} deadline_ms={} ended the run",
            observation.budget_units, observation.deadline_ms
        )
    });
    RunDegradation {
        provider_degradation,
        unknown_coverage,
        budget_limitation,
    }
}

/// Materialises the obligations that the open denominator members make
/// necessary.
///
/// Planning is receding-horizon: only what current observations can determine is
/// materialised, and an information-dependent future stays `Stub` until the
/// upstream result arrives.
fn open_obligations(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
    account: &CoverageAccount,
) -> Result<Vec<InquiryObligation>, InquiryError> {
    let mut obligations = Vec::new();
    for member in account.open_members() {
        obligations.push(InquiryObligation::new(InquiryObligationParams {
            obligation_id: format!("obl-{member}"),
            parent_question: observation.question.clone(),
            goal: format!("resolve admitted reference {member} inside the frozen scope"),
            protocol_ref: profile.profile_id_and_revision(),
            dependencies: Vec::new(),
            assumptions: Vec::new(),
            acceptance_certificate_kind: AcceptanceCertificateKind::ExactSourceIdentityAndPassage,
            information_boundary: observation.scope.clone(),
            responsible_role: "researcher",
            verifier: "instrument-plane provider execution evidence",
            budget_units: observation.budget_units,
            stop_condition: StopRuleKind::BudgetOrDeadlineExhausted.wire_name(),
            status: InquiryObligationStatus::Stub,
            profile,
        })?);
    }
    Ok(obligations)
}

/// Registers the research debts the observed residue makes necessary.
fn research_debts(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
    portfolio: &SourcePortfolio,
    coverage_receipt: &CoverageReceipt,
    precision: &EvidenceSetPrecision,
) -> Result<Vec<ResearchDebt>, InquiryError> {
    let mut debts = Vec::new();
    if !coverage_receipt.open_members.is_empty() {
        debts.push(ResearchDebt::register(
            &format!("debt-coverage-{}", observation.inquiry_id),
            &observation.inquiry_id,
            profile,
            ResearchDebtKind::Coverage,
            &format!(
                "{} admitted reference members carry no disposition",
                coverage_receipt.open_members.len()
            ),
            "researcher",
            "a source record is admitted for every frozen reference member",
            None,
        )?);
    }
    if !portfolio.independence.meets_requirement {
        debts.push(ResearchDebt::register(
            &format!("debt-replication-{}", observation.inquiry_id),
            &observation.inquiry_id,
            profile,
            ResearchDebtKind::Replication,
            &format!(
                "observed independent lineages {} do not meet the declared minimum {}",
                portfolio.independence.independent_lineages,
                portfolio.independence.minimum_independent_families
            ),
            "researcher",
            "independent lineages meet the declared minimum with no unknown lineage",
            None,
        )?);
    }
    if precision.has_residue() {
        debts.push(ResearchDebt::register(
            &format!("debt-provenance-{}", observation.inquiry_id),
            &observation.inquiry_id,
            profile,
            ResearchDebtKind::Provenance,
            "retained material supports no anchor at the precision the manifest admits",
            "researcher",
            "an admitted source record supports the cited anchors",
            None,
        )?);
    }
    Ok(debts)
}

/// Freezes the accepted evidence revision for one inquiry.
fn evidence_freeze(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
    portfolio: &SourcePortfolio,
    coverage_receipt: &CoverageReceipt,
    admissibility: &[SourceAdmissibilityRecord],
    debts: &[ResearchDebt],
) -> Result<EvidenceFreeze, InquiryError> {
    let mut included: Vec<String> = admissibility
        .iter()
        .filter(|record| record.eligibility == SourceEligibility::Eligible)
        .map(|record| record.record.handle.clone())
        .collect();
    included.sort();
    let excluded: Vec<(String, String)> = admissibility
        .iter()
        .filter(|record| record.eligibility != SourceEligibility::Eligible)
        .map(|record| {
            let reasons = record
                .reasons
                .iter()
                .map(|reason| reason.wire_name())
                .collect::<Vec<&str>>()
                .join(",");
            (record.record.handle.clone(), reasons)
        })
        .collect();
    let contradictions: Vec<String> = included
        .iter()
        .filter(|handle| {
            admissibility
                .iter()
                .any(|record| record.record.counterevidence_of.contains(*handle))
        })
        .cloned()
        .collect();
    EvidenceFreeze::freeze(
        &observation.inquiry_id,
        profile,
        &portfolio.digest,
        &profile.reference_manifest_digest,
        &coverage_receipt.digest,
        &observation.evidence_set_id,
        included,
        excluded,
        contradictions,
        debts.iter().map(|debt| debt.debt_id.clone()).collect(),
        observation.assessment_time_ms,
    )
}

/// Derives the terminal typed disposition from the observed run.
///
/// Submission and provider acknowledgement are not inquiry outcomes: a completed
/// provider operation still closes nothing unless the frozen denominator closed
/// intact, and every other outcome keeps an explicit disposition.
fn terminal_disposition(
    observation: &InquiryObservation,
    coverage_receipt: &CoverageReceipt,
) -> CompletionDisposition {
    match observation.outcome {
        AcquisitionOutcome::TimedOut => CompletionDisposition::Inconclusive,
        AcquisitionOutcome::Cancelled => CompletionDisposition::Cancelled,
        AcquisitionOutcome::Refused => CompletionDisposition::PolicyOrDisclosureDenied,
        AcquisitionOutcome::Crashed | AcquisitionOutcome::Unknown => {
            CompletionDisposition::SourceUnavailable
        }
        AcquisitionOutcome::Completed => {
            if coverage_receipt.all_closed
                && coverage_receipt.denominator_kind.supports_scoped_absence()
            {
                CompletionDisposition::AnsweredWithSupportedResult
            } else {
                CompletionDisposition::IncompleteCoverage
            }
        }
    }
}

/// The explicit unknown a non-closing terminal record must preserve.
fn preserved_unknown(
    observation: &InquiryObservation,
    coverage_receipt: &CoverageReceipt,
) -> Option<PreservedUnknown> {
    if coverage_receipt.open_members.is_empty() && observation.outcome.is_successful() {
        return None;
    }
    let detail = if coverage_receipt.open_members.is_empty() {
        format!(
            "acquisition outcome {} with reason {} left the frozen scope unresolved",
            observation.outcome.wire_name(),
            observation.reason_code
        )
    } else {
        format!(
            "{} admitted reference members carry no disposition: {}",
            coverage_receipt.open_members.len(),
            coverage_receipt.open_members.join(",")
        )
    };
    Some(PreservedUnknown {
        subject: format!("inquiry {}", observation.inquiry_id),
        detail,
    })
}

/// The reopen condition and next probe a non-closing terminal record preserves.
fn preserved_next_probe(
    observation: &InquiryObservation,
    coverage_receipt: &CoverageReceipt,
    obligations: &[InquiryObligation],
) -> PreservedNextProbe {
    let condition = match observation.outcome {
        AcquisitionOutcome::TimedOut | AcquisitionOutcome::Cancelled => {
            ReopenCondition::BudgetPhaseChanged
        }
        AcquisitionOutcome::Crashed | AcquisitionOutcome::Unknown => {
            ReopenCondition::SourceBecameAvailable
        }
        AcquisitionOutcome::Refused => ReopenCondition::ContractChanged,
        AcquisitionOutcome::Completed => ReopenCondition::NewEvidenceAvailable,
    };
    let required_probe = if coverage_receipt.open_members.is_empty() {
        format!(
            "re-observe this inquiry under a fresh admission after {}",
            condition.wire_name()
        )
    } else {
        format!(
            "acquire and admit a source record for the {} remaining reference member(s)",
            coverage_receipt.open_members.len()
        )
    };
    PreservedNextProbe {
        reopen_condition: condition,
        obligation_refs: obligations
            .iter()
            .map(|obligation| obligation.obligation_id.clone())
            .collect(),
        required_probe,
    }
}

/// Builds the terminal typed inquiry record for one observed run.
fn terminal_record(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
    portfolio: &SourcePortfolio,
    coverage_receipt: &CoverageReceipt,
    precision: &EvidenceSetPrecision,
    obligations: &[InquiryObligation],
) -> Result<InquiryTerminalRecord, InquiryError> {
    let narrower_claim = precision.has_residue().then(|| {
        format!(
            "claim may not exceed {} precision on this evidence set",
            anchor_wire(precision.supported_precision)
        )
    });
    InquiryTerminalRecord::bind(
        profile,
        &portfolio.digest,
        &profile.reference_manifest_digest,
        &coverage_receipt.digest,
        &observation.evidence_set_id,
        coverage_receipt.denominator_kind,
        terminal_disposition(observation, coverage_receipt),
        observation.outcome,
        &observation.reason_code,
        preserved_unknown(observation, coverage_receipt),
        narrower_claim,
        Some(preserved_next_probe(
            observation,
            coverage_receipt,
            obligations,
        )),
    )
}

/// Derives the exact acquisition disposition of one candidate from its retained
/// stream evidence and terminal outcome.
///
/// Timeout, cancellation, crash-adjacent unavailability, an incomplete capture
/// and a clean observation stay distinct, and a run that did not exit normally
/// never decodes as an intact acquisition.
fn candidate_source_record(
    candidate: &CandidateEvidence,
    observation: &InquiryObservation,
) -> Result<SourceRecord, InquiryError> {
    let acquisition = match (candidate.stream, candidate.exit_completed) {
        (StreamEvidence::Absent, _) => SourceDisposition::Unavailable,
        (StreamEvidence::Complete, true) => SourceDisposition::Observed,
        (StreamEvidence::Complete, false) | (StreamEvidence::Partial, true) => {
            SourceDisposition::Partial
        }
        (StreamEvidence::Partial, false) => SourceDisposition::Unknown,
    };
    let mut authority_domains = BTreeSet::new();
    authority_domains.insert(observation.scope.clone());
    let mut content_flags = BTreeSet::new();
    if candidate.refused {
        content_flags.insert("admission_refused_before_acquisition".to_owned());
    }
    let retrieved = if candidate.outcome == AcquisitionOutcome::Refused {
        None
    } else {
        Some(observation.assessment_time_ms)
    };
    let params = SourceRecordParams {
        handle: candidate.handle.clone(),
        class: candidate.class,
        title: format!(
            "retained provider material for admitted operation {}",
            candidate.operation_id
        ),
        locator: format!("{}#{}", candidate.route, candidate.receipt_handle),
        content_digest: candidate.content_digest.clone(),
        operation_id: candidate.operation_id.clone(),
        receipt_handle: candidate.receipt_handle.clone(),
        acquisition,
        published_ms: None,
        observed_ms: retrieved,
        retrieved_ms: retrieved,
        freshness_boundary_ms: None,
        // The retained provider snapshot is the raw material itself, not a
        // reduction of an earlier source, so no raw-source derivation is claimed.
        transformed_from: None,
        transform_verified: false,
        grade: None,
        authority_domains,
        lineage_root: candidate.lineage_root.clone(),
        disclosure: observation.disclosure,
        content_flags,
        incentives_note: "not assessed by the admitted provider process".to_owned(),
        deception_risk: RiskState::Unassessed,
        allowed_use: "candidate citation material for this inquiry evidence set".to_owned(),
        allowed_effects: "none; researcher output is candidate-only".to_owned(),
        verifier: "instrument-plane provider execution evidence (transport digest)".to_owned(),
        quarantine: None,
        counterevidence_of: BTreeSet::new(),
        cites: Vec::new(),
        evidence_spans: Vec::new(),
        data_role: "retained_provider_material".to_owned(),
    };
    SourceRecord::new(params).map_err(InquiryError::from)
}

/// Stable wire spelling of one closed wire-vocabulary value.
fn class_wire(class: SourceClass) -> &'static str {
    match class {
        SourceClass::Paper => "paper",
        SourceClass::Documentation => "documentation",
        SourceClass::Dataset => "dataset",
        SourceClass::Repository => "repository",
        SourceClass::Web => "web",
        SourceClass::Report => "report",
        SourceClass::ServiceDossier => "service_dossier",
        SourceClass::Unknown => "unknown",
    }
}

/// Stable wire spelling of one privacy class.
fn disclosure_wire(class: DisclosureClass) -> &'static str {
    match class {
        DisclosureClass::Private => "private",
        DisclosureClass::ProjectBound => "project_bound",
        DisclosureClass::ExportableRedacted => "exportable_redacted",
        DisclosureClass::Public => "public",
    }
}

/// Stable wire spelling of the canonical completion disposition.
fn disposition_wire(disposition: CompletionDisposition) -> &'static str {
    match disposition {
        CompletionDisposition::AnsweredWithSupportedResult => "ANSWERED_WITH_SUPPORTED_RESULT",
        CompletionDisposition::NoMatchInCompleteScope => "NO_MATCH_IN_COMPLETE_SCOPE",
        CompletionDisposition::NoNewUsefulEvidence => "NO_NEW_USEFUL_EVIDENCE",
        CompletionDisposition::SourceUnavailable => "SOURCE_UNAVAILABLE",
        CompletionDisposition::StaleSourceOrIndex => "STALE_SOURCE_OR_INDEX",
        CompletionDisposition::PolicyOrDisclosureDenied => "POLICY_OR_DISCLOSURE_DENIED",
        CompletionDisposition::IncompleteCoverage => "INCOMPLETE_COVERAGE",
        CompletionDisposition::Inconclusive => "INCONCLUSIVE",
        CompletionDisposition::Cancelled => "CANCELLED",
    }
}

/// Stable wire spelling of the absence assessment.
fn absence_wire(verdict: &AbsenceVerdict) -> &'static str {
    match verdict {
        AbsenceVerdict::Proven => "proven",
        AbsenceVerdict::Unproven { .. } => "unproven",
        AbsenceVerdict::PartialExhaustion { .. } => "partial_exhaustion",
    }
}

/// Stable wire spelling of the counter-search status.
fn counter_search_wire(status: CounterSearchStatus) -> &'static str {
    match status {
        CounterSearchStatus::NotRequired => "not_required",
        CounterSearchStatus::Satisfied => "satisfied",
        CounterSearchStatus::RequiredAndOpen => "required_and_open",
    }
}

/// Stable wire spelling of one anchor precision.
fn anchor_wire(precision: AnchorPrecision) -> &'static str {
    match precision {
        AnchorPrecision::Source => "source",
        AnchorPrecision::Document => "document",
        AnchorPrecision::Page => "page",
        AnchorPrecision::Section => "section",
        AnchorPrecision::Paragraph => "paragraph",
        AnchorPrecision::Line => "line",
        AnchorPrecision::ByteRange => "byte_range",
    }
}
