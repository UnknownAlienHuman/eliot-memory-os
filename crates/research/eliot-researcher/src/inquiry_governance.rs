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
    LocatorClass, ResearchContractError, SourceClass, classify_locator,
};

use crate::evidence_portfolio::{
    AbsencePreconditions, AbsenceVerdict, ClaimVerdict, CoverageAccount, LineageTable,
    ObservedOutsideScope, PortfolioError, PrecisionAssertion, PrecisionKind, RiskState,
    SourceDisposition, SourceRecord, SourceRecordParams, UnsupportedPrecisionItem, assess_absence,
    check_precision, digest, freeze, grade_name, grade_rank, push_count, push_field, reject_vague,
    text,
};
use crate::inquiry_lanes::{
    CommittedLaneRegistration, DeviationAllowance, DeviationScope, ExclusionAndQualityControl,
    INQUIRY_LANES_CONTRACT, LaneRegistration, LaneRegistrationError, LaneRegistrationParams,
    OrderedSubjectKind, OwnerOrderingReceipt, OwnerOrderingReceiptParams, PrimaryOutcomeRule,
    RegistrationDigests, SealedBlindingMapping, SealedBlindingMappingParams,
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
///
/// #2894: `1.0.0` -> `2.0.0`. The untrusted-reference diagnostic changed
/// incompatibly: `UnadmittedReferenceKind` gained
/// `INTERNAL_OWNED_REFERENCE` and `AMBIGUOUS_REFERENCE`, the kind of every
/// unadmitted reference is now read from
/// `eliot_research_exchange_api::classify_locator` instead of a `://` substring
/// test, and every reason now names the lever that can actually change the
/// verdict on this path. Both the `kind` and the `reason` are inside
/// `UnadmittedReference::compute_digest`, so every retained diagnostic has a
/// different digest than it did under `absolute-locator/1`.
///
/// **What this constant does not do, stated plainly:** it is in no digest
/// preimage. It appears only in the `Display` impl below. The invalidation above
/// is real but rests entirely on the five reason strings having changed text, not
/// on this constant. Two consequences a reader must not assume away:
///
/// - a future classifier change that produced the *same* `(kind, reason)` pair for
///   a handle would not move any digest, so bumping this constant alone would
///   invalidate nothing;
/// - `UnadmittedReference::observe` is `pub`, so a caller can construct a
///   diagnostic carrying a pre-bump `(kind, reason)` pair and
///   `validate_integrity` will accept it, because that method re-proves the digest
///   against the pair it was handed rather than against a version.
///
/// So the honest statement is: a diagnostic *this path* produced before the bump
/// cannot re-present as one produced after it, and nothing stronger is claimed.
pub const INQUIRY_GOVERNANCE_VERSION: &str = "2.0.0";

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
    /// A terminal disposition is one an open research debt restricts (I21.12).
    ///
    /// The debt is already registered and its restriction already derived, so
    /// binding the disposition anyway would publish a claim the same record
    /// proves is blocked. A debt that is resolved, or one whose claim class
    /// this disposition does not name, does not raise this error.
    ///
    /// MEASURED REACHABILITY, stated so this is not mistaken for live
    /// enforcement: on the `InquiryGovernance::record` path this error CANNOT
    /// fire today, and the reason is structural rather than accidental. The
    /// only disposition `terminal_disposition` can return that any debt
    /// refuses is `ANSWERED_WITH_SUPPORTED_RESULT`, and reaching it requires
    /// `outcome == Completed` with an intact denominator. A completed run
    /// contributes no `provider_degradation` (so no `Verification` debt) and
    /// leaves no open member (so no `Coverage` debt); `Replication` and
    /// `Provenance` refuse no disposition, and `Contradiction` is never
    /// registered. The guard is kept because it is the correct invariant and
    /// because `bind` is public: a caller that binds a record directly can
    /// reach it today. It is a bound, not a fired, check.
    DebtRestrictedDisposition {
        /// Failing field path.
        field: &'static str,
    },
    /// A confirmatory lane was declared without a frozen registration.
    LaneRegistrationRequired {
        /// Failing field path.
        field: &'static str,
    },
    /// The confirmatory-lane registration discipline refused the material.
    ///
    /// I21.4's registration, its owner commit receipt and its exposure ordering
    /// are owned by [`crate::inquiry_lanes`]. This domain keeps its own closed
    /// vocabulary, so a lane refusal is carried here as the failing field path
    /// the lane owner named; the two refusals that carry a foreign typed error
    /// are converted to that domain's own error instead.
    LaneRegistrationRefused {
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
            Self::DebtRestrictedDisposition { field } => write!(
                formatter,
                "{field} is restricted by an open research debt (I21.12)"
            ),
            Self::LaneRegistrationRequired { field } => {
                write!(formatter, "{field} requires a frozen lane registration")
            }
            Self::LaneRegistrationRefused { field } => write!(
                formatter,
                "{field} was refused by the confirmatory lane registration discipline"
            ),
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

impl From<LaneRegistrationError> for InquiryError {
    /// Converts one lane-discipline refusal into this domain's closed
    /// vocabulary.
    ///
    /// The two lane variants that carry a foreign typed error convert to that
    /// domain's own error, which is lossless; every other lane variant names
    /// only a field path, and that path is what this domain keeps.
    fn from(error: LaneRegistrationError) -> Self {
        match error {
            LaneRegistrationError::Portfolio(error) => Self::Portfolio(error),
            LaneRegistrationError::Profile(error) => error,
            error => Self::LaneRegistrationRefused {
                field: error.field().unwrap_or("lane_registration"),
            },
        }
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

/// What one run actually established about the frozen eligible scope (I21.1).
///
/// "No eligible source" and "the enumeration never ran" are different facts and
/// must never be read as one. A verified empty scope needs an enumeration that
/// ran over a closed population; when nothing was enumerated the same empty
/// eligible set is an absent measurement and stays `Uninitialised`.
///
/// A *verified empty* eligible scope is a state this vocabulary cannot
/// currently express, and no placeholder member is invented to close that gap:
/// [`crate::evidence_portfolio::CoverageAccount::open`] refuses a zero-member
/// denominator and [`CoverageReceipt::compute`] refuses a zero expected-member
/// count, so an inquiry whose admitted manifest declares no member produces no
/// record at all rather than a record stating that the eligible scope is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnumerationState {
    /// Nothing was observed against the frozen scope, so an empty eligible set
    /// is an absent measurement and never an empty population.
    Uninitialised,
    /// The enumeration ran and the declared remainder is still unexamined.
    Incomplete,
    /// The enumeration ran and every declared member closed intact.
    Complete,
}

impl EnumerationState {
    /// Stable wire spelling of this enumeration state.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Uninitialised => "uninitialised",
            Self::Incomplete => "incomplete",
            Self::Complete => "complete",
        }
    }
}

impl std::fmt::Display for EnumerationState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Derives what one run actually established about the frozen eligible scope.
///
/// An enumeration that recorded nothing leaves the declared remainder
/// indistinguishable from a scope nobody ever checked. The state, read beside
/// the observed population that is provably outside the frozen scope, keeps
/// those two facts apart instead of letting an enumeration that never ran read
/// as a verified empty scope.
fn enumeration_state(
    account: &CoverageAccount,
    observed_outside_scope: &[ObservedOutsideScope],
) -> EnumerationState {
    if account.all_closed() {
        return EnumerationState::Complete;
    }
    if observed_outside_scope.is_empty()
        && account.open_members().len() == account.denominator_size()
    {
        return EnumerationState::Uninitialised;
    }
    EnumerationState::Incomplete
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
    /// `committed_registration` is a [`CommittedLaneRegistration`], never a
    /// digest: it is re-proved here, so a string a caller composed cannot
    /// declare a confirmatory lane.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::GradeCeiling`] when a grade below
    /// `CORROBORATED` declares a non-zero independence requirement it cannot
    /// carry, [`InquiryError::LaneRegistrationRequired`] when a confirmatory
    /// lane has no committed registration, a lane-discipline refusal when the
    /// presented registration does not re-prove, and a field error for blank or
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
        committed_registration: Option<&CommittedLaneRegistration>,
    ) -> Result<Self, InquiryError> {
        let corroborated_rank = EvidenceGrade::from_name("CORROBORATED")?.rank();
        if grade.rank() < corroborated_rank && minimum_independent_families > 0 {
            return Err(InquiryError::GradeCeiling {
                field: "profile.independence_policy.minimum_independent_families",
            });
        }
        // The flag is a declaration, not the ordering proof: what it now says is
        // that an owner-committed registration exists and re-proves itself here,
        // not that any caller asserted an order. A confirmatory lane without one
        // is still refused, and the actual order proof stays
        // `crate::inquiry_lanes::LaneRegistration::require_commit_precedes`.
        if let Some(registration) = committed_registration {
            registration.validate_integrity()?;
        }
        let registered_before_outcome_exposure = committed_registration.is_some();
        if lane == InquiryLane::Confirmatory && !registered_before_outcome_exposure {
            return Err(InquiryError::LaneRegistrationRequired {
                field: "profile.independence_policy.lane_registration_digest",
            });
        }
        let lane_registration_digest =
            committed_registration.map(|registration| registration.digest().to_owned());
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
    /// Owner-committed lane registration this revision carries.
    ///
    /// A confirmatory lane requires one and an exploratory lane must carry none.
    /// The value is a registration, not a digest: it is re-proved on
    /// construction, so no caller can declare a confirmatory lane by supplying
    /// 64 hex characters. `None` here is the honest "no registration was
    /// committed", which the confirmatory arm below refuses.
    pub committed_lane_registration: Option<CommittedLaneRegistration>,
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
    /// Digest a lane registration commits to, covering every field of this
    /// revision except the one that names the registration.
    ///
    /// `integrity_digest` cannot serve that purpose: it covers the independence
    /// and blinding policy, that policy's digest covers the committed
    /// registration identity, and a registration that names
    /// `integrity_digest` would have to be committed before the profile that
    /// contains the digest of that commit. I21.4 needs the registration to name
    /// the exact revision and I21.3 needs the profile to carry the committed
    /// identity, so this second digest is what makes both true at once. It is
    /// resolved from the same admitted material as `integrity_digest`, by the
    /// same function the registration producer calls, so it is never a second
    /// guess at the selection.
    pub registration_binding_digest: String,
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

/// The half of one profile revision that does not depend on the committed lane
/// registration.
///
/// I21.4 requires the registration to name the exact profile revision it
/// governs, and I21.3 requires the profile to carry the registration's committed
/// identity, so one of those two facts has to be resolvable before the other
/// exists. Holding the selection separately means
/// [`InquiryProtocolProfile::select`] and the registration producer resolve the
/// same selection through the same code, and the registration binding digest
/// they agree on is not a second guess at it.
struct ProfileSelection {
    /// Resolved protocol.
    protocol: InquiryProtocol,
    /// Resolved coverage goal.
    coverage_goal: CoverageGoal,
    /// Whether the admitted coverage-goal text is exactly this resolved goal.
    admitted_coverage_goal_resolved: bool,
    /// Declared hypothesis policy.
    hypothesis_policy: HypothesisPolicy,
    /// Selected evidence grade.
    evidence_grade: EvidenceGrade,
    /// Declared lane.
    lane: InquiryLane,
    /// Dimensions independence is required on.
    dimensions: Vec<IndependenceDimension>,
    /// Minimum number of independent lineages the evidence set must reach.
    minimum_independent_families: u64,
    /// Digest of the structural selection inputs.
    selection_features_digest: String,
    /// Fidelity ceiling declared for this inquiry.
    fidelity_ceiling: String,
    /// Budget, deadline and stop rule.
    stop_rule: InquiryStopRule,
    /// Output contract and declared reopen conditions.
    output_contract: InquiryOutputContract,
    /// Privacy and disclosure ceiling for the whole inquiry.
    disclosure_ceiling: DisclosureClass,
}

/// Digest a lane registration commits to for one profile revision.
///
/// This covers every field of the revision except the committed lane
/// registration itself, and it is resolved from the admitted material through
/// the same values [`InquiryProtocolProfile::build`] freezes into the revision.
/// It is not a weaker identity than
/// [`InquiryProtocolProfile::integrity_digest`] for the purpose I21.4 states:
/// it names the same revision, and it is the only one of the two a
/// registration can name without a SHA-256 fixed point (see
/// [`InquiryProtocolProfile::registration_binding_digest`]).
fn registration_binding_digest(
    params: &InquiryProfileParams,
    revision: u64,
    supersedes: Option<&str>,
    selection: &ProfileSelection,
) -> String {
    let mut preimage = String::from("inquiry-profile-registration-binding/v1;");
    push_field(&mut preimage, "profile_id", &params.profile_id);
    push_field(&mut preimage, "revision", &revision.to_string());
    push_field(&mut preimage, "supersedes", supersedes.unwrap_or("none"));
    push_field(&mut preimage, "inquiry_id", &params.inquiry_id);
    push_field(&mut preimage, "operation_id", &params.operation_id);
    push_field(&mut preimage, "exchange_id", &params.exchange_id);
    push_field(&mut preimage, "question", &params.question);
    push_field(
        &mut preimage,
        "intended_decision_or_artifact",
        &params.intended_decision_or_artifact,
    );
    push_field(&mut preimage, "scope", &params.scope);
    push_field(
        &mut preimage,
        "requester_principal",
        &params.requester_principal,
    );
    push_field(
        &mut preimage,
        "admitted_inquiry_digest",
        &params.admitted_inquiry_digest,
    );
    push_field(&mut preimage, "protocol", selection.protocol.wire_name());
    push_field(
        &mut preimage,
        "selection_features_digest",
        &selection.selection_features_digest,
    );
    push_field(
        &mut preimage,
        "evidence_grade",
        &selection.evidence_grade.to_string(),
    );
    push_field(&mut preimage, "lane", selection.lane.wire_name());
    push_field(
        &mut preimage,
        "coverage_goal",
        selection.coverage_goal.wire_name(),
    );
    push_field(
        &mut preimage,
        "admitted_coverage_goal",
        &params.admitted_coverage_goal,
    );
    push_field(
        &mut preimage,
        "admitted_coverage_goal_resolved",
        bool_text(selection.admitted_coverage_goal_resolved),
    );
    push_field(
        &mut preimage,
        "hypothesis_policy",
        selection.hypothesis_policy.wire_name(),
    );
    push_binding_admission(&mut preimage, params);
    push_binding_independence(&mut preimage, selection);
    freeze(&preimage)
}

/// Appends the admitted material half of a registration binding: what the run
/// was admitted under, and the contracts the revision is bound to.
fn push_binding_admission(preimage: &mut String, params: &InquiryProfileParams) {
    push_count(
        preimage,
        "truth_surfaces",
        params.truth_surfaces_and_admissible_providers.len(),
    );
    for surface in &params.truth_surfaces_and_admissible_providers {
        push_field(preimage, "truth_surface", surface);
    }
    push_count(
        preimage,
        "admissible_source_classes",
        params.admissible_source_classes.len(),
    );
    for class in &params.admissible_source_classes {
        push_field(preimage, "source_class", class_wire(*class));
    }
    push_field(
        preimage,
        "reference_manifest_digest",
        &params.reference_manifest_digest,
    );
    push_field(
        preimage,
        "admitted_denominator_digest",
        &params.admitted_denominator_digest,
    );
}

/// Appends the independence, fidelity and contract half of a registration
/// binding.
fn push_binding_independence(preimage: &mut String, selection: &ProfileSelection) {
    push_count(
        preimage,
        "independence_dimensions",
        selection.dimensions.len(),
    );
    for dimension in &selection.dimensions {
        push_field(preimage, "independence_dimension", dimension.wire_name());
    }
    push_field(
        preimage,
        "minimum_independent_families",
        &selection.minimum_independent_families.to_string(),
    );
    push_field(preimage, "fidelity_ceiling", &selection.fidelity_ceiling);
    push_field(preimage, "stop_rule_digest", &selection.stop_rule.digest);
    push_field(
        preimage,
        "output_contract_digest",
        &selection.output_contract.digest,
    );
    push_field(
        preimage,
        "disclosure_ceiling",
        disclosure_wire(selection.disclosure_ceiling),
    );
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
        let selection = Self::select(&params)?;
        Self::build(
            params,
            selection,
            1,
            None,
            "initial inquiry protocol resolution",
        )
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
        let selection = Self::select(&params)?;
        let mut revision = Self::build(
            params,
            selection,
            next,
            Some(self.integrity_digest.clone()),
            reason,
        )?;
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

    /// Resolves the selection half of one profile revision from admitted
    /// material.
    ///
    /// This is separated from [`InquiryProtocolProfile::build`] because I21.4
    /// needs the lane registration to name the profile revision before that
    /// revision is frozen. The registration producer and the profile therefore
    /// resolve the *same* selection through the *same* function, so the binding
    /// digest they agree on cannot drift from the selection the profile carries.
    fn select(params: &InquiryProfileParams) -> Result<ProfileSelection, InquiryError> {
        let protocol = select_protocol(&params.features);
        let coverage_goal = select_coverage_goal(&params.features);
        let lane = select_lane(protocol, &params.features);
        let hypothesis_policy = select_hypothesis_policy(&params.features);
        let evidence_grade = select_evidence_grade(&params.features, lane)?;
        let (dimensions, minimum_independent_families) =
            select_independence_requirement(evidence_grade);
        let output_contract = InquiryOutputContract::resolve(
            &params.required_schema,
            select_reopen_conditions(coverage_goal, hypothesis_policy),
        )?;
        Ok(ProfileSelection {
            protocol,
            coverage_goal,
            admitted_coverage_goal_resolved: CoverageGoal::from_wire(
                &params.admitted_coverage_goal,
            ) == Some(coverage_goal),
            hypothesis_policy,
            evidence_grade,
            lane,
            dimensions,
            minimum_independent_families,
            selection_features_digest: selection_features_digest(&params.features),
            fidelity_ceiling: format!(
                "verifier_strength={} horizon={}",
                params.features.verifier_strength.wire_name(),
                params.features.horizon.wire_name()
            ),
            stop_rule: params.stop_rule.clone(),
            output_contract,
            disclosure_ceiling: params.disclosure_ceiling,
        })
    }

    fn build(
        params: InquiryProfileParams,
        selection: ProfileSelection,
        revision: u64,
        supersedes: Option<String>,
        change_reason: &str,
    ) -> Result<Self, InquiryError> {
        validate_profile_params(&params, change_reason)?;

        let independence_and_blinding_policy = IndependenceBlindingPolicy::resolve(
            selection.evidence_grade,
            selection.lane,
            selection.dimensions.clone(),
            selection.minimum_independent_families,
            Vec::new(),
            Vec::new(),
            Vec::new(),
            params.committed_lane_registration.as_ref(),
        )?;
        let binding =
            registration_binding_digest(&params, revision, supersedes.as_deref(), &selection);
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
            protocol: selection.protocol,
            selection_features_digest: selection.selection_features_digest,
            evidence_grade: selection.evidence_grade,
            lane: selection.lane,
            coverage_goal: selection.coverage_goal,
            admitted_coverage_goal_resolved: selection.admitted_coverage_goal_resolved,
            admitted_coverage_goal: params.admitted_coverage_goal,
            hypothesis_policy: selection.hypothesis_policy,
            truth_surfaces_and_admissible_providers: params.truth_surfaces_and_admissible_providers,
            admissible_source_classes: params.admissible_source_classes,
            reference_manifest_digest: params.reference_manifest_digest,
            admitted_denominator_digest: params.admitted_denominator_digest,
            independence_and_blinding_policy_digest: independence_and_blinding_policy
                .digest
                .clone(),
            independence_and_blinding_policy,
            registration_binding_digest: binding,
            fidelity_ceiling: selection.fidelity_ceiling,
            stop_rule: selection.stop_rule,
            output_contract: selection.output_contract,
            disclosure_ceiling: selection.disclosure_ceiling,
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
        push_field(
            &mut preimage,
            "registration_binding_digest",
            &self.registration_binding_digest,
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
    /// Candidates the run observed outside the frozen scope, each with its real
    /// disposition and evidence identity. They close no declared member and
    /// narrow no denominator.
    pub observed_outside_scope: Vec<ObservedOutsideScope>,
    /// What the run actually established about the frozen eligible scope.
    pub enumeration_state: EnumerationState,
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
    /// denominator has no member to account, a field error for a vague
    /// scope or a malformed frozen-scope digest, and the absence-precondition
    /// error when a bound predicate evaluation names no member or no longer
    /// re-proves its own identity. This route binds neither a bounded predicate
    /// evaluation nor an authorized manifest, so the absence verdict it produces
    /// can never be [`AbsenceVerdict::Proven`] and the receipt stays
    /// fail-closed.
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
        assessment_time_ms: i64,
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
        let observed_outside_scope = account.observed_outside_scope();
        let enumeration_state = enumeration_state(account, &observed_outside_scope);
        // This plane records per-source acquisition dispositions, not per-member
        // query predicate results, and it holds no authoritative enumeration
        // attestation for the route. It therefore binds no bounded predicate
        // evaluation and no `AuthorizedManifest` here, and the absence assessment
        // names the accounting facts that block the negative as its reason
        // instead of resting on a caller-supplied flag. Both arguments are the
        // fail-closed answer, not a placeholder: `AbsencePreconditions::derive`
        // admits an owner-issued `NoMatchEvaluation` only when the live route
        // supplies one, and #2893 forbids fabricating one here to complete the
        // receipt.
        let absence_preconditions = AbsencePreconditions::derive(
            account,
            &vetted_records(records),
            None,
            assessment_time_ms,
            frozen_scope_digest,
            None,
        )?;
        let absence_verdict = assess_absence(account, &absence_preconditions);
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
            observed_outside_scope,
            enumeration_state,
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
        // Bumped `v1` -> `v2` by #2893, and the reason is that this preimage does
        // not bind an identity, it binds a *reason string verbatim* (see the
        // `absence_reason` push below). #2893 changed two of those strings and the
        // population that reaches them, so for the same run this digest now
        // produces a different value under one name — the exact defect the
        // declared-domain rule exists to prevent. The preimage field set did not
        // change; what changed is the value space of a field that was already
        // there, which is the same reason `source-record/v1` -> `v2` was recorded.
        //
        // Transitively, `evidence-freeze/v1` and `inquiry-terminal-record/v1` bind
        // this digest and therefore produce different values for the same run.
        // Their own field sets and domains are unchanged and are deliberately not
        // bumped: a domain names the shape of the record being hashed, and a
        // changed value in a field they already declared is exactly the dependency
        // behaving as declared, not a new shape. `research-debt/v1` is unaffected
        // because its preimage never named the receipt digest.
        let mut preimage = String::from("coverage-receipt/v2;");
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
            "observed_outside_scope",
            self.observed_outside_scope.len(),
        );
        // The handles and dispositions the receipt publishes are bound here;
        // each observation's content digest, admitted operation and manifest
        // digest are bound by the adjacent account digest.
        for observation in &self.observed_outside_scope {
            push_field(
                &mut preimage,
                ObservedOutsideScope::REASON,
                &observation.handle,
            );
            push_field(
                &mut preimage,
                "observed_disposition",
                observation.disposition.wire_name(),
            );
        }
        push_field(
            &mut preimage,
            "enumeration_state",
            self.enumeration_state.wire_name(),
        );
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
        // The class spelling is bounded; the reason is digested as its own
        // field, so the digest binds *why* the negative was refused.
        if let Some(reason) = absence_reason(&self.absence_verdict) {
            push_field(&mut preimage, "absence_reason", reason);
        }
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

    /// Whether an open debt of this kind refuses this terminal disposition.
    ///
    /// The I21.12 table names a claim class, not a disposition, so the claim
    /// class is mapped onto the canonical closed
    /// [`CompletionDisposition`] vocabulary here and nowhere else. Only the
    /// two closing dispositions can be refused: `ANSWERED_WITH_SUPPORTED_RESULT`
    /// is a strong claim, a release and a unified conclusion at once, and
    /// `NO_MATCH_IN_COMPLETE_SCOPE` is a completeness claim. The remaining
    /// kinds do not name a disposition — replication, fidelity and provenance
    /// constrain what a release may GENERALIZE, how CONFIDENT it may be and
    /// whether it may be AUDITED, which is carried by the narrower claim
    /// instead of by a disposition the I21.9 vocabulary has no word for.
    /// Refusing more would turn an honest narrow outcome into a refusal, and
    /// I21.12 keeps unrelated independently supported claims free to proceed.
    ///
    /// The published [`blocks`](Self::blocks) text is the I21.12 claim-class
    /// LABEL, verbatim from the table; this function is that label's projection
    /// onto dispositions, and the two are not the same granularity. `Coverage`
    /// reads "completeness" and refuses both closing dispositions, because a
    /// supported result inside an incomplete scope asserts completeness just as
    /// much as a scoped absence does. `Verification` reads "release" and
    /// likewise refuses both, because both closing dispositions ARE releases.
    /// A reader who needs the enforced set rather than the label reads
    /// [`ResearchDebtRestriction::refused_dispositions`], which publishes it
    /// per record, and [`ResearchDebtRestriction::statement`], which names it
    /// per debt.
    #[must_use]
    pub const fn blocks_disposition(self, disposition: CompletionDisposition) -> bool {
        match self {
            Self::Epistemic | Self::Contradiction => {
                matches!(
                    disposition,
                    CompletionDisposition::AnsweredWithSupportedResult
                )
            }
            Self::Verification | Self::Coverage | Self::Authority => matches!(
                disposition,
                CompletionDisposition::AnsweredWithSupportedResult
                    | CompletionDisposition::NoMatchInCompleteScope
            ),
            Self::Replication | Self::Fidelity | Self::Provenance => false,
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

/// The restriction open research debts place on one terminal claim (I21.12).
///
/// I21.12 states the rule this record enforces: "A release that carries open
/// debts states them; it does not describe them as minor limitations." A debt
/// is therefore not a count and not a footnote: this record names every open
/// debt, the claim class it blocks, its accountable owner and the condition
/// under which it is reviewed, and it names the terminal dispositions those
/// debts refuse.
///
/// The restriction is derived from the registered debts rather than restated,
/// so the debt a consumer reads and the debt the producer registered cannot
/// drift. It is bound into the terminal record digest: an unbound restriction
/// would be a claim, not evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResearchDebtRestriction {
    /// Inquiry identity the restriction was derived for.
    pub inquiry_id: String,
    /// Whether at least one open debt restricts the terminal claim.
    pub restricted: bool,
    /// The closing dispositions the open debts refuse, in canonical order.
    pub refused_dispositions: Vec<CompletionDisposition>,
    /// Identity of every open debt contributing to the restriction.
    pub debt_ids: Vec<String>,
    /// I21.12 kind of every open debt, aligned with `debt_ids`.
    ///
    /// Published so a reader can tell WHICH restriction applies to which debt
    /// without re-deriving it, and so the enforced refusal set is stated per
    /// debt rather than only in aggregate.
    pub debt_kinds: Vec<ResearchDebtKind>,
    /// The claim class each open debt blocks, paired with its debt identity.
    pub blocked_claims: Vec<(String, String)>,
    /// Accountable owner of each open debt, paired with its debt identity.
    pub owners: Vec<(String, String)>,
    /// Review condition of each open debt, paired with its debt identity.
    pub review_conditions: Vec<(String, String)>,
    /// Expiry in Unix milliseconds of each open debt, paired with its identity.
    pub expiries: Vec<(String, Option<i64>)>,
    /// Digest over the shape.
    pub digest: String,
}

impl ResearchDebtRestriction {
    /// Derives the restriction the open debts place on a terminal disposition.
    ///
    /// Only open debts restrict: a resolved debt is not carried by this record
    /// and never blocks. An empty debt set derives an unrestricted record
    /// rather than a refusal, so an inquiry that registered no obligation is
    /// not thinned by the absence of one.
    #[must_use]
    pub fn derive(inquiry_id: &str, debts: &[ResearchDebt]) -> Self {
        let open: Vec<&ResearchDebt> = debts.iter().filter(|debt| debt.open).collect();
        let mut refused: Vec<CompletionDisposition> = Vec::new();
        for disposition in [
            CompletionDisposition::AnsweredWithSupportedResult,
            CompletionDisposition::NoMatchInCompleteScope,
        ] {
            if open
                .iter()
                .any(|debt| debt.kind.blocks_disposition(disposition))
            {
                refused.push(disposition);
            }
        }
        let mut debt_ids = Vec::with_capacity(open.len());
        let mut debt_kinds = Vec::with_capacity(open.len());
        let mut blocked_claims = Vec::with_capacity(open.len());
        let mut owners = Vec::with_capacity(open.len());
        let mut review_conditions = Vec::with_capacity(open.len());
        let mut expiries = Vec::with_capacity(open.len());
        for debt in &open {
            debt_ids.push(debt.debt_id.clone());
            debt_kinds.push(debt.kind);
            blocked_claims.push((debt.debt_id.clone(), debt.blocks.clone()));
            owners.push((debt.debt_id.clone(), debt.owner.clone()));
            review_conditions.push((debt.debt_id.clone(), debt.review_condition.clone()));
            expiries.push((debt.debt_id.clone(), debt.expires_at_ms));
        }
        let mut restriction = Self {
            inquiry_id: inquiry_id.to_owned(),
            restricted: !open.is_empty(),
            refused_dispositions: refused,
            debt_ids,
            debt_kinds,
            blocked_claims,
            owners,
            review_conditions,
            expiries,
            digest: String::new(),
        };
        restriction.digest = restriction.compute_digest();
        restriction
    }

    /// Whether this restriction refuses the given disposition.
    #[must_use]
    pub fn refuses(&self, disposition: CompletionDisposition) -> bool {
        self.refused_dispositions.contains(&disposition)
    }

    /// The I21.12 statement of every open debt, in one bounded line.
    ///
    /// Names the debt, the claim class it blocks, its owner and its review
    /// condition, so a release that carries open debts states them rather than
    /// describing them as minor limitations. Where a debt actually refuses a
    /// disposition, the refused wire names are stated with it, so the claim a
    /// reader can check and the claim the gate enforces are the same claim.
    /// No provider prose is reproduced.
    #[must_use]
    pub fn statement(&self) -> Option<String> {
        if !self.restricted {
            return None;
        }
        let parts = self
            .debt_ids
            .iter()
            .zip(&self.blocked_claims)
            .zip(&self.owners)
            .zip(&self.review_conditions)
            .zip(&self.debt_kinds)
            .map(
                |((((debt_id, (blocked_id, blocks)), (owner_id, owner)), (review_id, review)), kind)| {
                    debug_assert_eq!(debt_id, blocked_id);
                    debug_assert_eq!(debt_id, owner_id);
                    debug_assert_eq!(debt_id, review_id);
                    let refused = refused_dispositions_for(*kind);
                    if refused.is_empty() {
                        format!("{debt_id} blocks {blocks} (owner {owner}; review: {review})")
                    } else {
                        format!(
                            "{debt_id} blocks {blocks} and refuses {} (owner {owner}; review: {review})",
                            refused.join(",")
                        )
                    }
                },
            )
            .collect::<Vec<String>>()
            .join("; ");
        Some(format!(
            "{} open research debt(s) restrict this claim: {parts}",
            self.debt_ids.len()
        ))
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("research-debt-restriction/v1;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "restricted", bool_text(self.restricted));
        push_count(
            &mut preimage,
            "refused_dispositions",
            self.refused_dispositions.len(),
        );
        for disposition in &self.refused_dispositions {
            push_field(
                &mut preimage,
                "refused_disposition",
                disposition_wire(*disposition),
            );
        }
        push_count(&mut preimage, "debt_ids", self.debt_ids.len());
        for debt_id in &self.debt_ids {
            push_field(&mut preimage, "debt_id", debt_id);
        }
        for kind in &self.debt_kinds {
            push_field(&mut preimage, "debt_kind", kind.wire_name());
        }
        for (debt_id, blocks) in &self.blocked_claims {
            push_field(&mut preimage, "blocked_debt", debt_id);
            push_field(&mut preimage, "blocked_claim", blocks);
        }
        for (debt_id, owner) in &self.owners {
            push_field(&mut preimage, "owner_debt", debt_id);
            push_field(&mut preimage, "owner", owner);
        }
        for (debt_id, review) in &self.review_conditions {
            push_field(&mut preimage, "review_debt", debt_id);
            push_field(&mut preimage, "review_condition", review);
        }
        for (debt_id, expiry) in &self.expiries {
            push_field(&mut preimage, "expiry_debt", debt_id);
            if let Some(expiry) = expiry {
                push_field(&mut preimage, "expires_at_ms", &expiry.to_string());
            }
        }
        freeze(&preimage)
    }

    /// Re-proves this restriction's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.compute_digest() == self.digest {
            Ok(())
        } else {
            Err(InquiryError::IntegrityMismatch {
                field: "debt_restriction.digest",
            })
        }
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
    /// Restriction the open research debts place on this claim (I21.12).
    pub debt_restriction: ResearchDebtRestriction,
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
        debt_restriction: ResearchDebtRestriction,
        next_probe: Option<PreservedNextProbe>,
    ) -> Result<Self, InquiryError> {
        require_text(evidence_set_id, "terminal.evidence_set_id")?;
        require_text(reason_code, "terminal.reason_code")?;
        require_digest(portfolio_digest, "terminal.portfolio_digest")?;
        require_digest(manifest_digest, "terminal.manifest_digest")?;
        require_digest(coverage_receipt_digest, "terminal.coverage_receipt_digest")?;
        debt_restriction.validate_integrity()?;
        if debt_restriction.inquiry_id != profile.inquiry_id {
            return Err(InquiryError::UnknownHandle {
                field: "terminal.debt_restriction.inquiry_id",
            });
        }
        // I21.12 use-time check. A closing disposition is exactly the strong
        // claim, release, completeness claim and unified conclusion the table
        // restricts, so an open debt that refuses it must not be bound beside
        // it. Rejecting the record here is the honest outcome: the debt is
        // already registered and its restriction is already derived, so
        // emitting a closing disposition anyway would publish a claim the
        // same record proves is blocked.
        if debt_restriction.refuses(disposition) {
            return Err(InquiryError::DebtRestrictedDisposition {
                field: "terminal.disposition",
            });
        }
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
            debt_restriction,
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
        push_field(
            &mut preimage,
            "debt_restriction_digest",
            &self.debt_restriction.digest,
        );
        push_field(
            &mut preimage,
            "debt_restricted",
            bool_text(self.debt_restriction.restricted),
        );
        push_count(
            &mut preimage,
            "debt_restriction_refused",
            self.debt_restriction.refused_dispositions.len(),
        );
        for disposition in &self.debt_restriction.refused_dispositions {
            push_field(
                &mut preimage,
                "debt_restriction_refused_disposition",
                disposition_wire(*disposition),
            );
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

    /// Re-proves this record's own digest and the debt restriction it carries.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one, and
    /// [`InquiryError::DebtRestrictedDisposition`] when a closing disposition
    /// coexists with an open debt that refuses it.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        self.debt_restriction.validate_integrity()?;
        if self.debt_restriction.refuses(self.disposition) {
            return Err(InquiryError::DebtRestrictedDisposition {
                field: "terminal.disposition",
            });
        }
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
/// has a different acquisition path: a URL needs an exact `url_handles` entry and
/// a provider to resolve and snapshot it, an internally owned reference and a
/// plain handle both need a manifest transition that admits the handle, an
/// ambiguous spelling needs nothing to be acquired first — the text itself has to
/// become a classifiable reference — and a stale or revoked handle needs a fresh
/// admission rather than any acquisition at all.
///
/// Every arm is chosen by the one shared classifier,
/// [`eliot_research_exchange_api::classify_locator`], which is the same function
/// the delivered-bundle firewall in
/// [`eliot_research_exchange_api::ResearchEvidenceBundle::validate_against`]
/// applies to `SourceSnapshot::locator`. Before #2894 this path tested
/// `handle.contains("://")` instead, so `https://…` was named a URL in one path
/// and a non-URL in the other, and `urn:`/`mailto:` were named artifact handles
/// even though the enforcement path gated them as URLs. The kinds are now
/// projections of one classification, not a second spelling of it.
///
/// # A kind names the reference; the reason names the lever
///
/// A candidate handle is a reference identity, and the only thing that admits one
/// on this path is `AllowedReferenceManifest::allows`, which reads
/// `source_handles`, `evidence_handles` and `artifact_handles`. `url_handles`
/// belongs to the separate `admits_url` predicate on the delivered-locator path
/// and is never consulted here. So `LocatorUrl` says *what the spelling presents
/// itself as* and the reason says *which list can change the verdict*; a reader
/// who follows the reason reaches the lever, and the two cannot disagree because
/// both come from the same function.
///
/// # What the live record path can actually observe
///
/// The whole live classification is `reference_firewall`, and the only thing it
/// looks at is each `ObservationCandidate`'s `handle`. That makes the reachable
/// set a property of what a candidate handle can be, not of all six identities
/// I21.7 enumerates:
///
/// - The single live candidate is the `provider-artifact:<sha256>` handle that
///   `retained_provider_material` in `bins/eliot-mod-research` derives from the
///   retained stdout digest, so the live kind is `InternalOwnedReference`. That
///   spelling carries a valid RFC 3986 scheme token (`provider-artifact`)
///   followed by a non-colon, so it is formally a URI with an opaque part; it is
///   internally owned because a named owner mints it under a closed 64-hex
///   grammar (see `owned_scheme` in `eliot_research_exchange_api`). The `://`
///   test used to name it `ArtifactHandle` and the first #2894 revision named it
///   `LocatorUrl`; both were wrong, in opposite directions.
/// - Nothing is promoted by that reading.
///   `AllowedReferenceManifest::allows` is unchanged, so the live handle is still
///   unadmitted exactly as before and the diagnostic is still candidate-only.
///   Only the named kind and reason change — from a label that sent the reader to
///   a list which cannot admit the value, to one that names the list which can.
/// - `LocatorUrl` is reached by any other unadmitted candidate whose scheme is
///   not internally owned, which includes `https://…`, `urn:…` and `mailto:…`
///   that the `://` test mislabelled as artifact handles.
///
/// A URL inside the provider body is still not observable here, because the
/// projection never decodes the body; the delivered-locator surface is closed at
/// `SourceSnapshot::locator` in
/// `eliot_research_exchange_api::ResearchEvidenceBundle::validate_against`.
///
/// `AmbiguousReference` is reachable for a candidate that breaks the shared
/// classifier's own grammar — a blank or oversized spelling, a bare scheme
/// separator, a non-canonical internal form, or a malformed `name::…`. A
/// *well-formed* `name::id` is not one of these: it is a namespaced opaque handle
/// and classifies as `ArtifactHandle`. No current production caller projects an
/// `AmbiguousReference` — the one live candidate is `provider-artifact:<sha256>`
/// — and the kind is kept because a candidate handle is caller-shaped, not fixed.
/// A source identity is judged on the `SourceRecord.handle` the observation
/// projects into
/// [`crate::source_admissibility::SourceAdmissibilityRecord::evaluate`], and a
/// line range is judged by the manifest's admitted anchor precision in
/// [`EvidenceSetPrecision::evaluate`]; neither can be a *citation* on this path,
/// so neither is a candidate diagnostic here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnadmittedReferenceKind {
    /// An absolute locator URL, named for what the spelling presents itself as.
    ///
    /// It says nothing about `url_handles`: `reference_firewall` never calls
    /// `admits_url`, so it cannot know whether the manifest lists this value
    /// there. A value can be listed in `url_handles` and still be unadmitted as a
    /// handle, and this kind is still the right one. The lever is in the reason.
    LocatorUrl,
    /// An opaque handle the manifest does not list.
    ArtifactHandle,
    /// A reference a named owner mints internally — a canonical `eliot://`
    /// resource identity, or a `provider-artifact:<sha256>` content handle —
    /// presented as a candidate handle.
    ///
    /// Not named "resource URI": the live case is a provider artifact handle,
    /// not a bridge resource, and a diagnostic that misnames the one candidate
    /// the product actually produces is its own defect.
    InternalOwnedReference,
    /// A spelling the shared classifier cannot classify as a reference at all:
    /// blank, control-bearing, oversized, a scheme-separator with nothing after
    /// it, a non-canonical internal form, or a `name::id` spelling that breaks the
    /// namespaced-handle grammar.
    ///
    /// A *well-formed* `name::id` is not in this kind — it classifies as
    /// `ArtifactHandle`, because a namespaced opaque handle is a handle and the
    /// grammar is what keeps it distinct from a URI scheme.
    AmbiguousReference,
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
            Self::InternalOwnedReference => "INTERNAL_OWNED_REFERENCE",
            Self::AmbiguousReference => "AMBIGUOUS_REFERENCE",
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
    ///
    /// Inside [`Self::digest`]: a fence that can change what a retained
    /// diagnostic means has to be inside the preimage, so a diagnostic moved
    /// onto a different fence cannot re-present the old digest.
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
    /// The preimage covers the fence as well as the retained text, so this
    /// stands alone: a diagnostic whose fence was moved fails here, and not
    /// only where [`InquiryGovernance`] happens to cross-check the fence against
    /// its own.
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

    /// I21.7 reference firewall: the fence is part of what this record means, so
    /// it is inside the preimage and not only cross-checked by the governance
    /// record. No sibling record in this crate pushes a fence of its own, so the
    /// encoding is the crate's single canonical one — `push_field` per fence
    /// component, tagged with the `StateFence` field names that
    /// `canonical_json_bytes` gives the same value inside the sealed
    /// `AllowedReferenceManifest` — and an absent optional revision is spelled
    /// `none` under its own tag, as everywhere else in these preimages.
    fn compute_digest(&self) -> String {
        let mut preimage = String::from("unadmitted-reference/v1;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_field(&mut preimage, "reference", &self.reference);
        push_field(&mut preimage, "kind", self.kind.wire_name());
        push_field(&mut preimage, "reason", &self.reason);
        push_field(
            &mut preimage,
            "authority_epoch_lineage",
            self.state_fence.authority_epoch.lineage_id.as_str(),
        );
        push_field(
            &mut preimage,
            "authority_epoch_sequence",
            &self.state_fence.authority_epoch.sequence.to_string(),
        );
        push_field(
            &mut preimage,
            "resource_generation",
            &self.state_fence.resource_generation.value().to_string(),
        );
        // The three optional revisions have three DISTINCT types, so each is
        // spelled out rather than iterated: an array would require one element
        // type and would either coerce or fail to compile.
        for (tag, revision) in [
            (
                "task_revision",
                self.state_fence
                    .task_revision
                    .map(|value| value.value().to_string()),
            ),
            (
                "policy_revision",
                self.state_fence
                    .policy_revision
                    .map(|value| value.value().to_string()),
            ),
            (
                "integration_revision",
                self.state_fence
                    .integration_revision
                    .map(|value| value.value().to_string()),
            ),
        ] {
            match revision {
                Some(value) => push_field(&mut preimage, tag, &value),
                None => push_field(&mut preimage, tag, "none"),
            }
        }
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
        let account = coverage_account(&observation, &admissibility)?;
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
            observation.assessment_time_ms,
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
            &admissibility,
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
            &research_debts,
        )?;
        let record = Self {
            inquiry_id: observation.inquiry_id,
            evidence_set_id: observation.evidence_set_id,
            profile_admission_request: profile.admission_request(),
            source_admission_requests: admissibility
                .iter()
                .map(SourceAdmissibilityRecord::transition_request)
                .collect::<Result<Vec<_>, _>>()?,
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
        // I21.12: the restriction a reader sees must be the restriction the
        // registered debts imply. Re-deriving it here means a debt added,
        // removed or resolved after the terminal record was built is caught
        // instead of being published beside a stale restriction.
        let derived = ResearchDebtRestriction::derive(&self.inquiry_id, &self.research_debts);
        if derived != self.terminal.debt_restriction {
            return Err(InquiryError::IntegrityMismatch {
                field: "terminal.debt_restriction",
            });
        }
        for debt in &self.research_debts {
            if !self.freeze.open_research_debts.contains(&debt.debt_id) {
                return Err(InquiryError::IntegrityMismatch {
                    field: "freeze.open_research_debts",
                });
            }
        }
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
             expected_members={} open_members={} accounted={} all_closed={} enumeration={} \
             observed_outside={} denominator_kind={} absence={} absence_reason={} \
             supported_precision={} precision_residue={} obligations={} \
             materialisable={} deferred={} compilation_inputs={} freeze={} debts={} \
             debt_kinds={} debt_restricted={} debt_restriction_refused={} \
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
            self.coverage_receipt.enumeration_state,
            self.coverage_receipt.observed_outside_scope.len(),
            self.coverage_receipt.denominator_kind,
            absence_wire(&self.coverage_receipt.absence_verdict),
            absence_reason(&self.coverage_receipt.absence_verdict)
                .unwrap_or(absence_wire(&self.coverage_receipt.absence_verdict)),
            anchor_wire(self.precision.supported_precision),
            self.precision.residue.len(),
            self.obligations.len(),
            self.compilation_inputs.materialisable().len(),
            self.compilation_inputs.deferred().len(),
            self.compilation_inputs.digest,
            self.freeze.digest,
            self.research_debts.len(),
            debt_kinds_wire(&self.research_debts),
            terminal.debt_restriction.restricted,
            terminal
                .debt_restriction
                .refused_dispositions
                .iter()
                .map(|disposition| disposition_wire(*disposition))
                .collect::<Vec<&str>>()
                .join(","),
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
///
/// This is on the live path of every run: `InquiryGovernance::record` calls it
/// before anything else is assessed, and it is the only place a profile revision
/// is produced. It resolves the selection, commits the lane registration the
/// selection demands through [`commit_lane_registration`], and only then freezes
/// the revision that carries it — so a confirmatory profile exists only where an
/// owner-committed registration precedes it, and an exploratory one exists where
/// none is needed.
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
    let mut params = InquiryProfileParams {
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
        committed_lane_registration: None,
    };
    // I21.4: the profile states the required rigour, and a confirmatory lane
    // additionally requires a frozen registration committed before any outcome
    // exposure. The selection is resolved first because the registration has to
    // name the exact revision it governs, and the registration is committed
    // before the revision that carries it is frozen.
    let selection = InquiryProtocolProfile::select(&params)?;
    params.committed_lane_registration =
        commit_lane_registration(&params, &selection, observation.assessment_time_ms)?;
    InquiryProtocolProfile::build(
        params,
        selection,
        1,
        None,
        "initial inquiry protocol resolution",
    )
}

/// The contract owner that commits lane registrations into the ordering journal
/// of one inquiry.
///
/// I21.2 resolves the grade and the lane here, and I21.4 freezes the
/// registration under the Researcher contract owner, so this is the owner whose
/// commit receipt a confirmatory claim rests on. It is a named constant rather
/// than a caller-supplied string: a caller that may name its own owner could
/// also place its own exposure receipts in a journal of its own choosing and
/// order them against a registration nobody committed.
const LANE_JOURNAL_OWNER: &str = "eliot.research.inquiry-governance.contract-owner";

/// Commits the lane registration one profile revision must carry.
///
/// This is the producer the issue was missing. It returns `None` for a purely
/// exploratory selection, because I21.4 requires no registration for purely
/// exploratory work and inventing one would let a confirmatory claim be
/// manufactured for work that never had a confirmatory surface. For confirmatory
/// content it freezes one [`LaneRegistration`] and admits it as a
/// [`CommittedLaneRegistration`], which is the only value
/// [`InquiryProfileParams::committed_lane_registration`] accepts.
///
/// # What the registration commits to, and where each part comes from
///
/// Every value below is derived from material the profile was already resolved
/// from, so nothing here is asserted, guessed or supplied by a caller:
///
/// - `contract_digest` is the kernel-admitted `admitted_inquiry_digest`, i.e.
///   the exact contract the run executes under;
/// - `protocol_digest` is the resolved protocol/coverage/grade/lane selection
///   this revision carries, so any later reader can recompute it from the
///   published profile;
/// - `hypothesis_digest` is the exact question, scope and intended decision the
///   proposition consists of;
/// - `evaluator_digest` is the admitted evaluation surface — result schema,
///   verifier cost and strength, admitted routes and provider generation. The
///   Researcher record carries no evaluator identity of its own, so this is the
///   exact admitted surface the registration freezes; substituting any part of
///   it after exposure is a content change and therefore a new revision;
/// - the primary outcome and its decision rule are the admitted result schema
///   and the admitted coverage goal plus the intended decision, frozen
///   verbatim, so I21.4's "may not change the primary metric" has something
///   concrete to compare against;
/// - the stated exclusion rule and the quality controls are the run-bound
///   reference allowlist and the declared denominator, i.e. the two controls the
///   run is actually admitted under;
/// - the blinded fields are the I21.4-named channels that carry the answer to
///   the evaluator, and the sealed mapping over the concealed assignment is
///   retained under this contract owner at the journal origin, before the
///   registration that cites it is committed;
/// - the only permitted deviation is an exclusion made under the stated rule.
///   I21.4 forbids changing the metric, weakening the proposition, replacing the
///   evaluator after seeing results or hiding failed attempts, so no allowance
///   is registered for those facets and a deviation on any of them is refused by
///   `LaneRegistration::classify_deviation`.
///
/// # Where the commit sits in the owner journal
///
/// Two owner acts happen here, in this order, and both are issued into one
/// journal: the blinding mapping is sealed at the origin, and the registration
/// that cites that mapping is committed immediately after it, chained to the
/// seal. Positions are therefore the journal's own two positions rather than
/// numbers chosen to order something, and the proof is
/// `CommittedLaneRegistration::commit`'s hash-chain ancestry check — not a
/// comparison of `recorded_at_ms` against anything.
///
/// `recorded_at_ms` is the instant the run itself reported. It is retained as a
/// record of that fact only; this module never orders anything by it.
///
/// # Errors
///
/// Returns [`InquiryError::LaneRegistrationRefused`] carrying the lane owner's
/// own field path for a malformed or unprovable registration, and
/// [`InquiryError::UnknownVocabulary`] for a mixed-lane selection, which
/// [`select_lane`] does not currently produce and for which the observation
/// carries no frozen partition membership or deterministic assignment rule.
fn commit_lane_registration(
    params: &InquiryProfileParams,
    selection: &ProfileSelection,
    recorded_at_ms: i64,
) -> Result<Option<CommittedLaneRegistration>, InquiryError> {
    if selection.lane == InquiryLane::Exploratory {
        return Ok(None);
    }
    if selection.lane != InquiryLane::Confirmatory {
        // A mixed lane needs a partition frozen before outcomes are seen, and
        // `InquiryObservation` carries neither explicit membership nor an
        // assignment rule with its version and seed. Refusing is the honest
        // reading: a partition cannot be invented, and a complete partition map
        // with unknown leak history is not proof of uncontaminated confirmation.
        return Err(InquiryError::UnknownVocabulary {
            field: "profile.lane.mixed_partition",
        });
    }
    let state_fence = params.state_fence.clone();
    let journal = lane_journal_identity(params, selection.lane);
    let sealed_blinding_mapping = seal_blinded_mapping(params, &journal, &state_fence)?;
    let registration_params = LaneRegistrationParams {
        registration_id: format!("lane-registration/{}", params.inquiry_id),
        inquiry_id: params.inquiry_id.clone(),
        profile_id: params.profile_id.clone(),
        profile_revision: 1,
        profile_digest: registration_binding_digest(params, 1, None, selection),
        digests: RegistrationDigests::bind(
            &params.admitted_inquiry_digest,
            &lane_protocol_digest(selection),
            &lane_hypothesis_digest(params),
            &lane_evaluator_digest(params),
        )?,
        primary_outcome: PrimaryOutcomeRule::bind(
            &format!("admitted_result_schema:{}", params.required_schema),
            &format!(
                "admitted_coverage_goal:{};intended_decision:{}",
                params.admitted_coverage_goal, params.intended_decision_or_artifact
            ),
        )?,
        exclusions_and_quality_controls: ExclusionAndQualityControl::bind(
            vec![format!(
                "no case may be excluded unless its handle is admitted by run_bound_reference_allowlist:{}",
                params.reference_manifest_digest
            )],
            vec![
                format!(
                    "run_bound_reference_allowlist:{}",
                    params.reference_manifest_digest
                ),
                format!(
                    "declared_denominator:{}",
                    params.admitted_denominator_digest
                ),
            ],
        )?,
        blinded_fields: lane_blinded_fields(),
        allowed_deviations: lane_allowed_deviations()?,
        evidence_partition: None,
        // The commit receipt does not exist yet: it is issued *over* the frozen
        // content, which is why `LaneRegistration::content_digest_of` exists.
        // The mapping seal receipt stands in until the real commit receipt
        // replaces it two steps below, and `freeze_content` never reads it.
        owner_receipt: sealed_blinding_mapping.receipt.clone(),
        sealed_blinding_mapping,
        registered_at_ms: recorded_at_ms,
        state_fence,
    };
    let content_digest = LaneRegistration::content_digest_of(&registration_params)?;
    let mut registration_params = registration_params;
    registration_params.owner_receipt = OwnerOrderingReceipt::issue(OwnerOrderingReceiptParams {
        receipt_id: format!("{journal}#1"),
        owner_principal: LANE_JOURNAL_OWNER.to_owned(),
        journal_identity: journal,
        position: 1,
        predecessor_receipt_digest: Some(
            registration_params
                .sealed_blinding_mapping
                .receipt
                .receipt_digest
                .clone(),
        ),
        subject: OrderedSubjectKind::LaneRegistrationCommit,
        subject_id: registration_params.registration_id.clone(),
        subject_digest: content_digest,
        state_fence: registration_params.state_fence.clone(),
    })?;
    let registration = LaneRegistration::register(registration_params)?;
    Ok(Some(CommittedLaneRegistration::commit(registration)?))
}

/// Identity of the one owner journal this inquiry's lane receipts order inside.
///
/// Positions are meaningful only together with the owner and the journal, so
/// the journal is derived from exactly those admitted facts: the contract owner
/// that issues the receipts, the inquiry and profile identity, and the State
/// Fence everything is frozen under. A different fence is a different journal,
/// which is what makes a receipt from a superseded fence order nothing.
fn lane_journal_identity(params: &InquiryProfileParams, lane: InquiryLane) -> String {
    let fence = &params.state_fence;
    let mut preimage = String::from("inquiry-lane-journal/v1;");
    push_field(&mut preimage, "owner_principal", LANE_JOURNAL_OWNER);
    push_field(&mut preimage, "contract", INQUIRY_LANES_CONTRACT);
    push_field(&mut preimage, "inquiry_id", &params.inquiry_id);
    push_field(&mut preimage, "profile_id", &params.profile_id);
    push_field(&mut preimage, "lane", lane.wire_name());
    push_field(
        &mut preimage,
        "authority_lineage",
        fence.authority_epoch.lineage_id.as_str(),
    );
    push_field(
        &mut preimage,
        "authority_sequence",
        &fence.authority_epoch.sequence.to_string(),
    );
    push_field(
        &mut preimage,
        "resource_generation",
        &fence.resource_generation.value().to_string(),
    );
    freeze(&preimage)
}

/// Seals the blinding mapping the declared channels conceal, at the journal
/// origin.
///
/// I21.4 keeps the sealed mapping under the existing independence/disclosure
/// owner and lets the registration carry only its handle and digest, so what is
/// sealed here is a digest of the assignment the blinding conceals — the
/// admitted source classes, the admitted truth surfaces and the admitted
/// disclosure ceiling — and never the concealed values themselves. The receipt
/// sits at position zero with no predecessor because it opens the journal: it
/// is the first act of this owner for this inquiry, which is a structural fact
/// and not a claim about a clock.
fn seal_blinded_mapping(
    params: &InquiryProfileParams,
    journal: &str,
    state_fence: &StateFence,
) -> Result<SealedBlindingMapping, InquiryError> {
    let mapping_handle = format!("blinded-mapping/{}", params.inquiry_id);
    let mapping_digest = lane_blinded_mapping_digest(params);
    let receipt = OwnerOrderingReceipt::issue(OwnerOrderingReceiptParams {
        receipt_id: format!("{journal}#0"),
        owner_principal: LANE_JOURNAL_OWNER.to_owned(),
        journal_identity: journal.to_owned(),
        position: 0,
        predecessor_receipt_digest: None,
        subject: OrderedSubjectKind::SealedBlindingMapping,
        subject_id: mapping_handle.clone(),
        subject_digest: mapping_digest.clone(),
        state_fence: state_fence.clone(),
    })?;
    Ok(SealedBlindingMapping::seal(SealedBlindingMappingParams {
        mapping_handle,
        mapping_digest,
        owner_principal: LANE_JOURNAL_OWNER.to_owned(),
        receipt,
    })?)
}

/// The exact protocol selection a registration freezes.
fn lane_protocol_digest(selection: &ProfileSelection) -> String {
    let mut preimage = String::from("inquiry-lane-protocol/v1;");
    push_field(&mut preimage, "protocol", selection.protocol.wire_name());
    push_field(
        &mut preimage,
        "coverage_goal",
        selection.coverage_goal.wire_name(),
    );
    push_field(
        &mut preimage,
        "hypothesis_policy",
        selection.hypothesis_policy.wire_name(),
    );
    push_field(
        &mut preimage,
        "evidence_grade",
        &selection.evidence_grade.to_string(),
    );
    push_field(&mut preimage, "lane", selection.lane.wire_name());
    push_field(
        &mut preimage,
        "selection_features_digest",
        &selection.selection_features_digest,
    );
    freeze(&preimage)
}

/// The exact proposition a registration freezes.
fn lane_hypothesis_digest(params: &InquiryProfileParams) -> String {
    let mut preimage = String::from("inquiry-lane-hypothesis/v1;");
    push_field(&mut preimage, "question", &params.question);
    push_field(&mut preimage, "scope", &params.scope);
    push_field(
        &mut preimage,
        "intended_decision_or_artifact",
        &params.intended_decision_or_artifact,
    );
    freeze(&preimage)
}

/// The exact admitted evaluation surface a registration freezes as its
/// evaluator.
fn lane_evaluator_digest(params: &InquiryProfileParams) -> String {
    let mut preimage = String::from("inquiry-lane-evaluator/v1;");
    push_field(&mut preimage, "required_schema", &params.required_schema);
    push_field(
        &mut preimage,
        "verifier_cost",
        params.features.verifier_cost.wire_name(),
    );
    push_field(
        &mut preimage,
        "verifier_strength",
        params.features.verifier_strength.wire_name(),
    );
    push_count(
        &mut preimage,
        "admissible_routes",
        params.truth_surfaces_and_admissible_providers.len(),
    );
    for surface in &params.truth_surfaces_and_admissible_providers {
        push_field(&mut preimage, "truth_surface", surface);
    }
    freeze(&preimage)
}

/// The concealed assignment the sealed blinding mapping covers.
fn lane_blinded_mapping_digest(params: &InquiryProfileParams) -> String {
    let mut classes: Vec<&str> = params
        .admissible_source_classes
        .iter()
        .map(|class| class_wire(*class))
        .collect();
    classes.sort_unstable();
    classes.dedup();
    let mut preimage = String::from("inquiry-lane-blinded-mapping/v1;");
    push_field(
        &mut preimage,
        "disclosure_ceiling",
        disclosure_wire(params.disclosure_ceiling),
    );
    push_count(&mut preimage, "source_classes", classes.len());
    for class in classes {
        push_field(&mut preimage, "source_class", class);
    }
    push_count(
        &mut preimage,
        "truth_surfaces",
        params.truth_surfaces_and_admissible_providers.len(),
    );
    for surface in &params.truth_surfaces_and_admissible_providers {
        push_field(&mut preimage, "truth_surface", surface);
    }
    freeze(&preimage)
}

/// The leakage channels a confirmatory run closes before outcome exposure.
///
/// I21.4 names these as the typical fields: "preferred hypothesis, condition
/// labels, …, holdout expected score". Each one would otherwise hand the
/// evaluator the answer the registration exists to keep from it, so a confirmatory
/// lane declares all three. This is a policy definition, not an observed value,
/// and `BlindingApplication::evaluate` is what later proves each one was actually
/// delivered masked and that masking it did not remove essential task or safety
/// information.
fn lane_blinded_fields() -> Vec<BlindedField> {
    vec![
        BlindedField::PreferredHypothesis,
        BlindedField::ConditionLabel,
        BlindedField::HoldoutExpectedScore,
    ]
}

/// The deviations a confirmatory run permits before outcome exposure.
///
/// Only `Exclusions` is permitted, and only under the stated rule the
/// registration carries. I21.4 forbids changing the primary metric, weakening
/// the proposition, replacing the evaluator after seeing results and hiding
/// failed attempts, so those four facets get no allowance and a deviation on any
/// of them is classified `OutsideDeclaredAllowance`, which invalidates the
/// affected confirmation.
fn lane_allowed_deviations() -> Result<Vec<DeviationAllowance>, InquiryError> {
    Ok(vec![DeviationAllowance::allow(
        "exclusion-under-stated-rule",
        DeviationScope::Exclusions,
        "a case may be excluded only under the exclusion rule stated in this registration",
    )?])
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
///
/// #2894: the kind is read from the one shared classifier,
/// [`eliot_research_exchange_api::classify_locator`], which is the same
/// classification the delivered-bundle firewall applies to
/// `SourceSnapshot::locator`. This path used to test `handle.contains("://")`,
/// so it disagreed with the enforcement path in both directions: `https://…` was
/// named a URL here while the enforcement path could not name it one, and
/// `urn:`/`mailto:` were named artifact handles while the enforcement path gates
/// them as URLs. There is no `contains` test left in this function.
///
/// Every reason this function emits names a lever that can change the verdict
/// here, and the branch comment records which list that is. Two mistakes this
/// replaces are worth naming, because they are mirror images of each other: the
/// first #2894 revision told a reader that an unadmitted URL-shaped candidate
/// needed an exact `url_handles` entry, and this function never calls
/// `admits_url`, so following that advice left the diagnostic recurring forever;
/// and the same revision told a reader that an unclassifiable spelling could be
/// admitted by no list at all, which was equally wrong in the other direction —
/// this path tests `manifest.allows` and nothing else, so a handle entry removes
/// the diagnostic whatever the spelling is. A reason here names a list this
/// function actually reads, and says plainly when the remaining problem is the
/// text rather than the list.
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
        let (kind, reason): (UnadmittedReferenceKind, String) = if manifest
            .stale_or_revoked_handles
            .iter()
            .any(|stale| stale == &candidate.handle)
        {
            // Revocation is applied after membership and on every call, so this
            // verdict survives a handle-list entry too. The reason says that, or
            // a reader adds the handle to a list, the diagnostic recurs, and the
            // firewall looks broken.
            (
                UnadmittedReferenceKind::StaleOrRevoked,
                "the run-bound manifest lists this reference as stale or revoked, and revocation \
                 applies after membership, so a handle entry alone does not readmit it"
                    .to_owned(),
            )
        } else if !manifest.allows(&candidate.handle) {
            // Every reason below names the one thing that can change this
            // verdict, and the arm it names is one this path actually reads.
            // This path tests `manifest.allows` and nothing else:
            // `AllowedReferenceManifest::allows` reads `source_handles`,
            // `evidence_handles` and `artifact_handles`, so the handle allowlist
            // is the only lever here. `url_handles` belongs to the separate
            // `admits_url` predicate, which is the delivered-locator path in
            // `eliot_research_exchange_api` and is never called from this
            // function — so a reason that told a reader to add the value to
            // `url_handles` would name a list that cannot admit it and the
            // diagnostic would recur forever.
            match classify_locator(&candidate.handle) {
                // The spelling presents as an absolute locator, and the lever is
                // still the handle allowlist: a candidate handle is a reference
                // identity, not a `SourceSnapshot::locator`, so it is admitted by
                // `allows` or by nothing. Saying so is the whole point — naming
                // `url_handles` here would send the reader to the wrong list.
                LocatorClass::ExternalUri { .. } => (
                    UnadmittedReferenceKind::LocatorUrl,
                    "this reference presents as an absolute locator URL; a candidate handle is \
                     admitted only by the manifest's source, evidence and artifact handles, and \
                     url_handles is not consulted on this path"
                        .to_owned(),
                ),
                // An internally owned reference is still just a handle identity:
                // being internal is not admission, so the lever is the same
                // handle allowlist.
                LocatorClass::InternalUri { .. } => (
                    UnadmittedReferenceKind::InternalOwnedReference,
                    "this reference is an internally owned handle; admission is a source, evidence \
                     or artifact handle entry, and being internal is not admission"
                        .to_owned(),
                ),
                LocatorClass::OpaqueHandle => (
                    UnadmittedReferenceKind::ArtifactHandle,
                    "the run-bound manifest does not admit this reference handle in its source, \
                     evidence or artifact handles"
                        .to_owned(),
                ),
                // A spelling the classifier cannot read. The lever is STILL the
                // handle allowlist, and this is the arm where that is easiest to
                // get wrong: `classify_locator` plays no part in the admission
                // decision above — it only chose this kind and this string. A
                // manifest handle entry for this exact text removes the
                // diagnostic, exactly as it does for every other arm, so the
                // reason says so rather than claiming no list can help. What no
                // entry can do is make the *text* classifiable: that is a
                // property of the spelling, and the reason names the rule that
                // failed so a reader knows which one to fix.
                LocatorClass::MalformedOrAmbiguous { reason } => (
                    UnadmittedReferenceKind::AmbiguousReference,
                    format!(
                        "this reference is not a classifiable locator: {}; a source, evidence or \
                         artifact handle entry admits it like any other candidate, but no entry \
                         can make the text itself classifiable",
                        reason.wire_name()
                    ),
                ),
            }
        } else {
            continue;
        };
        diagnostics.push(UnadmittedReference::observe(
            &observation.inquiry_id,
            &observation.evidence_set_id,
            &candidate.handle,
            kind,
            &reason,
            &manifest.state_fence,
        )?);
    }
    Ok(diagnostics)
}

/// Opens the exact coverage accounting over the admitted reference members.
///
/// The declared denominator is exactly the admitted manifest, and it is never
/// widened to fit an observation. Each observed candidate is either bound to the
/// member the manifest declared for it, or retained as an
/// [`ObservedOutsideScope`] observation: a provider result the Kernel could not
/// have known when it froze the manifest stays visibly outside the frozen scope
/// with its real disposition instead of silently becoming part of it. The two
/// populations stay separately readable in the account digest, which is what
/// lets a verified empty scope be told apart from an enumeration that never ran.
fn coverage_account(
    observation: &InquiryObservation,
    admissibility: &[SourceAdmissibilityRecord],
) -> Result<CoverageAccount, InquiryError> {
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
    let mut account = CoverageAccount::open(members).map_err(InquiryError::from)?;
    for record in admissibility {
        account.observe(
            &record.record.handle,
            record.record.acquisition,
            &record.record.content_digest,
            &record.record.operation_id,
            &manifest.digest,
        )?;
    }
    Ok(account)
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
    admissibility: &[SourceAdmissibilityRecord],
) -> Result<Vec<ResearchDebt>, InquiryError> {
    let mut debts = Vec::new();
    if !coverage_receipt.open_members.is_empty() {
        debts.push(ResearchDebt::register(
            &format!("debt-coverage-{}", observation.inquiry_id),
            &observation.inquiry_id,
            profile,
            ResearchDebtKind::Coverage,
            &format!(
                "{} admitted reference member(s) carry no disposition: {}; {} candidate(s) were \
                 observed outside the frozen scope instead and close none of them",
                coverage_receipt.open_members.len(),
                coverage_receipt.open_members.join(","),
                coverage_receipt.observed_outside_scope.len()
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
    // I21.12 names eight debt kinds. The three above are decided by the
    // coverage, independence and precision receipts; `Verification` below by a
    // fourth signal this record already computes. The remaining four
    // (`Contradiction`, `Epistemic`, `Fidelity`, `Authority`) are deliberately
    // NOT registered, each for a measured reason rather than for convenience: a
    // producer that can never fire is the "helper without a caller" the brief
    // forbids, so a kind is registered only where an observed signal exists.
    // `Contradiction` is the instructive one - see `unresolved_contradictions`
    // - and the assert below is the tripwire that will tell the next attempt
    // when its signal finally becomes real.
    if !coverage_receipt.provider_degradation.is_empty() {
        debts.push(ResearchDebt::register(
            &format!("debt-verification-{}", observation.inquiry_id),
            &observation.inquiry_id,
            profile,
            ResearchDebtKind::Verification,
            &format!(
                "acquisition degraded rather than completing cleanly, so no admitted candidate is \
                 backed by an independently verified source: {}",
                coverage_receipt.provider_degradation.join(",")
            ),
            "researcher",
            "a non-degraded acquisition admits a candidate with an independently verified source",
            None,
        )?);
    }
    let contradictions = unresolved_contradictions(admissibility);
    debug_assert!(
        contradictions.is_empty(),
        "a populated counterevidence set changes the I21.12 debt set; re-derive the producers",
    );
    Ok(debts)
}

/// The admitted sources recorded as counterevidence of another admitted source.
///
/// Extracted so the contradiction check and the evidence freeze read the SAME
/// unresolved set: if they computed it separately, one could name a conflict
/// the other does not carry, and the freeze would then understate an
/// obligation the same record registered.
///
/// MEASURED: on the `InquiryGovernance::record` path this set is provably
/// EMPTY, because `candidate_source_record` is the only producer of
/// admissibility records here and it hardcodes `counterevidence_of:
/// BTreeSet::new()`. A `Contradiction` debt registered from it would be a
/// producer that can never fire, which is the "helper without a caller" the
/// brief forbids, so no such debt is registered. Populating the field is the
/// prerequisite, and it is NOT invented here.
fn unresolved_contradictions(admissibility: &[SourceAdmissibilityRecord]) -> Vec<String> {
    let included: Vec<&str> = admissibility
        .iter()
        .filter(|record| record.eligibility == SourceEligibility::Eligible)
        .map(|record| record.record.handle.as_str())
        .collect();
    let mut contradictions: Vec<String> = included
        .iter()
        .filter(|handle| {
            admissibility
                .iter()
                .any(|record| record.record.counterevidence_of.contains(**handle))
        })
        .map(|handle| (*handle).to_owned())
        .collect();
    contradictions.sort();
    contradictions.dedup();
    contradictions
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
    let contradictions = unresolved_contradictions(admissibility);
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
///
/// `debts` is the set this run registered, and it is the ONLY input that can
/// restrict the claim: the disposition is derived from the acquisition outcome
/// and the coverage receipt, then narrowed by the open research debts before it
/// is bound. Deriving the restriction from the registered debts rather than
/// restating it is what makes the I21.12 use-time check an invariant of the
/// record rather than a comment about it.
fn terminal_record(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
    portfolio: &SourcePortfolio,
    coverage_receipt: &CoverageReceipt,
    precision: &EvidenceSetPrecision,
    obligations: &[InquiryObligation],
    debts: &[ResearchDebt],
) -> Result<InquiryTerminalRecord, InquiryError> {
    let debt_restriction = ResearchDebtRestriction::derive(&observation.inquiry_id, debts);
    let derived = terminal_disposition(observation, coverage_receipt);
    // A restricted disposition is downgraded to the typed incomplete-coverage
    // outcome rather than dropped: the run did complete, but the claim it could
    // have carried is blocked, and I21.13 requires the honest limited outcome
    // to be the one reported. The debt statement below keeps the specific
    // reason, so the downgrade loses nothing a reader needs.
    //
    // MEASURED: on this path the downgrade is currently INERT. No debt kind
    // that refuses a disposition can coexist with a disposition this function
    // produces - see the reachability note on
    // `InquiryError::DebtRestrictedDisposition` for the proof. The branch is
    // kept because it is the correct invariant and because it costs nothing,
    // but nothing should be read into it as live enforcement today.
    let disposition = if debt_restriction.refuses(derived) {
        CompletionDisposition::IncompleteCoverage
    } else {
        derived
    };
    let precision_claim = precision.has_residue().then(|| {
        format!(
            "claim may not exceed {} precision on this evidence set",
            anchor_wire(precision.supported_precision)
        )
    });
    let narrower_claim = match (precision_claim, debt_restriction.statement()) {
        (Some(precision), Some(debts)) => Some(format!("{precision}; {debts}")),
        (Some(precision), None) => Some(precision),
        (None, Some(debts)) => Some(debts),
        (None, None) => None,
    };
    InquiryTerminalRecord::bind(
        profile,
        &portfolio.digest,
        &profile.reference_manifest_digest,
        &coverage_receipt.digest,
        &observation.evidence_set_id,
        coverage_receipt.denominator_kind,
        disposition,
        observation.outcome,
        &observation.reason_code,
        preserved_unknown(observation, coverage_receipt),
        narrower_claim,
        debt_restriction,
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
/// The dispositions one I21.12 debt kind refuses, in wire names.
///
/// Stated per debt so a reader can check the enforced set against the claim
/// class the debt publishes, instead of having to trust that the two agree.
fn refused_dispositions_for(kind: ResearchDebtKind) -> Vec<&'static str> {
    [
        CompletionDisposition::AnsweredWithSupportedResult,
        CompletionDisposition::NoMatchInCompleteScope,
    ]
    .into_iter()
    .filter(|disposition| kind.blocks_disposition(*disposition))
    .map(disposition_wire)
    .collect()
}

/// Stable wire spelling of the debt kinds a run registered, deduplicated and
/// ordered.
///
/// I21.12 requires a release that carries open debts to STATE them, so the kind
/// reaches the boundary as a closed wire name rather than only as a count.
/// No debt summary, owner prose or provider text is reproduced here.
fn debt_kinds_wire(debts: &[ResearchDebt]) -> String {
    let mut kinds: Vec<&str> = debts.iter().map(|debt| debt.kind.wire_name()).collect();
    kinds.sort_unstable();
    kinds.dedup();
    kinds.join(",")
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

/// Bounded reason an absence claim was left unproven, when one applies.
///
/// Only [`AbsenceVerdict::Unproven`] retains a reason. The class spelling stays
/// bounded, so the reason travels beside it as its own retained fact rather than
/// inside the wire name, and a verdict that retained no reason contributes no
/// field.
fn absence_reason(verdict: &AbsenceVerdict) -> Option<&str> {
    match verdict {
        AbsenceVerdict::Unproven { reason } => Some(reason),
        AbsenceVerdict::Proven | AbsenceVerdict::PartialExhaustion { .. } => None,
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
