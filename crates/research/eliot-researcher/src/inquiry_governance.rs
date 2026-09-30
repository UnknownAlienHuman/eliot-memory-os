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
//! The terminal projection carries the governed artifacts rather than restating
//! them: [`InquiryTerminalRecord`] holds the [`EvidenceFreeze`], the
//! [`UnsupportedPrecisionItem`] residue and, when one exists, the
//! [`ClaimAuditRecord`], and re-proves and binds each of them. What it does not
//! carry it does not summarise either — the claim audit is `None` on the live
//! path because nothing in this repository produces an
//! [`crate::evidence_portfolio::AuditedClaim`] to bind, and that absence is
//! reported rather than filled.
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
    AbsencePreconditions, AbsenceVerdict, AuditBindingError, AuditReferenceBinding, AuditedClaim,
    AuthorizedManifest, AuthorizedManifestParams, ClaimCoverageMap, ClaimVerdict, CoverageAccount,
    EvidencePortfolio, LineageTable, ManifestSource, MaterialClaimRoster, NoMatchEvaluation,
    ObservedOutsideScope, PortfolioError, PrecisionAssertion, PrecisionKind, RiskState,
    SourceDisposition, SourceRecord, SourceRecordParams, UnsupportedPrecisionItem, assess_absence,
    bool_text, check_precision, digest, fence_preimage, freeze, grade_name, grade_rank, push_count,
    push_field, reject_vague, text,
};
use crate::inquiry_lanes::{
    CommittedLaneRegistration, DeviationAllowance, DeviationScope, ExclusionAndQualityControl,
    INQUIRY_LANES_CONTRACT, InquiryLaneDiscipline, LaneEvidenceClass, LaneRegistration,
    LaneRegistrationError, LaneRegistrationParams, OrderedSubjectKind, OwnerOrderingReceipt,
    OwnerOrderingReceiptParams, PrimaryOutcomeRule, RegistrationDigests, SealedBlindingMapping,
    SealedBlindingMappingParams,
};
use crate::inquiry_obligations::{
    AcceptanceCertificateKind, InquiryObligation, InquiryObligationParams, InquiryObligationStatus,
    TaskGraphCompilationInputs,
};
use crate::source_admissibility::{
    GovernorSourceTransitionRequest, PresentedReference, RecordReferenceSurface,
    SourceAdmissibilityRecord, SourceEligibility, admits_record_reference, record_references,
};

/// Stable identity of this domain surface.
pub const INQUIRY_GOVERNANCE_CONTRACT: &str = "eliot.research.inquiry-governance";
/// Current revision of this domain surface.
///
/// #1762: `2.0.0` -> `3.0.0`. The terminal projection changed incompatibly:
/// `InquiryTerminalRecord` gained three carried fields — the `EvidenceFreeze`,
/// the `Option<ClaimAuditRecord>` and the `Vec<UnsupportedPrecisionItem>` — and
/// all three are inside `InquiryTerminalRecord::compute_digest`, so every
/// terminal record has a different digest than it did under
/// `inquiry-terminal-record/v1` and the surface a consumer reads gained three
/// typed fields. #1765 supplied the missing `AuditedClaim` producer this field
/// had been `None` for, so the field now carries a real audit on any run that
/// released admitted material. See the field's own doc comment.
///
/// **What this constant does not do, stated plainly:** it is in no digest
/// preimage. It appears only in the `Display` impl below. The invalidation above
/// is real but rests entirely on the three added fields being inside
/// `InquiryTerminalRecord::compute_digest`, not on this constant.
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
/// #1764: `3.0.0` -> `4.0.0`. The retained-diagnostic *set* changed
/// incompatibly. `reference_firewall` previously observed only
/// `InquiryObservation::candidates[].handle`, so a record whose source identity
/// the manifest admitted and whose `locator`, `receipt_handle`, `cites` edge or
/// `evidence_spans[].anchor` it did not produced no diagnostic at all — the
/// reference was neither refused nor retained, and
/// `SourceAdmissibilityRecord::decide` did not look at it either, so it reached
/// the evidence set on an admitted handle. It now observes every reference the
/// record presents and retains each unadmitted one, so a run can produce
/// diagnostics it could not produce before, with reason texts that did not exist
/// before, and both the `reason` and the `reference` are inside
/// `UnadmittedReference::compute_digest`.
///
/// **What this constant does not do, stated plainly:** it is in no digest
/// preimage, for the same reason as the two bumps above. The invalidation is real
/// but rests entirely on the reference texts and reason strings a run can now
/// produce, not on this constant.
///
/// `3.0.0` -> `4.0.0` is therefore the whole change. `CONTRACT_VERSION` in
/// `eliot_research_exchange_api` is **not** bumped: no delivered wire type gained
/// or lost a field, so no `ResearchQueryRequest`, `AllowedReferenceManifest` or
/// `ResearchEvidenceBundle` produced by an earlier peer stops deserialising, and a
/// bundle this crate does not read is not this crate's to re-version. The demotion
/// record lives on `InquiryGovernance`, which is a non-canonical, in-process
/// governed artifact that no envelope carries.
pub const INQUIRY_GOVERNANCE_VERSION: &str = "4.0.0";

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
    /// A terminal disposition tries to close after an unsuccessful acquisition.
    ClosureWithoutSuccessfulAcquisition {
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
    /// A record has no canonical encoding, so it has no decision identity.
    ///
    /// Refused rather than defaulted: a digest computed over a silently
    /// shortened preimage would look like provenance while covering fewer bytes
    /// than the record it claims to identify. The spelling matches
    /// [`PortfolioError::Unencodable`], which is the same refusal on the
    /// acquisition side of this domain.
    Unencodable {
        /// Failing field path.
        field: &'static str,
    },
    /// The frozen acquisition-side discipline refused the material.
    Portfolio(PortfolioError),
    /// The run-bound audit reference authorization refused to bind.
    ///
    /// I21.7 requires an audit job to be bound to the exact run and State Fence
    /// it may judge under, and that binding is owned by
    /// [`AuditReferenceBinding`]. Its refusal is carried here whole rather than
    /// collapsed into a field path, because "the run-bound manifest does not
    /// match its own digest" and "the authorized manifest does not match its own
    /// digest" are different facts about different owners, and a run whose audit
    /// authorization cannot be proved produces no record at all.
    AuditBinding(AuditBindingError),
    /// The exchange contract refused the admitted reference manifest.
    ///
    /// I21.7: the run-bound `AllowedReferenceManifest` is a mandatory input, so
    /// a malformed manifest, or one whose digest does not cover its own content,
    /// is refused here rather than being published as a bound allowlist.
    Contract(ResearchContractError),
    /// The release gate refused to promote this run's material claims.
    ///
    /// I21.8 item 6 forbids a `SUPPORTED` promotion while a required chain,
    /// excerpt or audit dimension fails or is unknown, and the issue's
    /// acceptance requires an omitted material claim to block a complete-audit
    /// claim. The two gates refuse for different reasons, so the gate that
    /// refused and the specific member that refused it are both carried: a
    /// consumer that only learns "blocked" would have to re-derive which
    /// requirement failed.
    ReleaseGateRefused {
        /// Which gate refused: `claim_coverage` or `claim_audit`.
        gate: &'static str,
        /// The specific member or condition the gate refused on.
        detail: String,
    },
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
            Self::ClosureWithoutSuccessfulAcquisition { field } => {
                write!(
                    formatter,
                    "{field} cannot close after an unsuccessful acquisition"
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
            Self::Unencodable { field } => {
                write!(
                    formatter,
                    "{field} cannot be encoded into its canonical preimage"
                )
            }
            Self::Portfolio(error) => write!(formatter, "frozen portfolio discipline: {error}"),
            Self::AuditBinding(cause) => {
                write!(formatter, "claim audit reference binding: {cause}")
            }
            Self::Contract(error) => {
                write!(formatter, "reference manifest contract: {error}")
            }
            Self::ReleaseGateRefused { gate, detail } => {
                write!(formatter, "release gate {gate} refused: {detail}")
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

    /// Canonical digest over the whole revision.
    ///
    /// # What the `v1` -> `v2` bump changed
    ///
    /// The `v1` preimage named every field of this struct *except* one: it
    /// published `state_fence` and no byte of the preimage covered it. A
    /// revision read back after the fact could therefore carry a **substituted**
    /// fence — a different authority epoch, resource generation or task
    /// revision — and still re-prove its own `integrity_digest` unchanged.
    ///
    /// That is a real gap and not a theoretical one, because `integrity_digest`
    /// is the identity every downstream binding compares against rather than
    /// a free field printed beside the revision:
    ///
    /// - `SourceAdmissibilityRecord::is_admitted_to` admits a source to an
    ///   evidence set on `profile_digest == profile.integrity_digest`, so a
    ///   substituted fence inherited that same stale equality and kept admitting
    ///   under a fence the run was never admitted under;
    /// - `SourcePortfolio`, `CoverageReceipt`, `EvidenceFreeze`, the terminal
    ///   record and `TaskGraphCompilationInputs` all bind this exact digest, so
    ///   every one of them would carry the substitution forward consistently
    ///   and none would notice it;
    /// - `GovernorInquiryAdmissionRequest::state_fence` is the fence a
    ///   receiving Governor would read, and it is populated from the same
    ///   field, so the request crossing the boundary would present the
    ///   substituted fence as the one the profile was frozen under.
    ///
    /// The fence is now bound through [`fence_preimage`], the shared canonical
    /// serializer that every other record on this plane already uses for the
    /// same value (the lane discipline outcome, the evidence freeze, the claim
    /// audit and the terminal record), so its five components are bound by
    /// their own contract spellings rather than by a field name chosen here.
    fn compute_integrity_digest(&self) -> String {
        let mut preimage = String::from("inquiry-protocol-profile/v2;");
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
        // The State Fence this revision is frozen under. Bound through the
        // shared canonical serializer for the same reason the terminal record,
        // the evidence freeze, the claim audit and the lane discipline outcome
        // bind theirs: five typed components, each already carrying its own
        // contract spelling, and a hand-written field list here would be
        // coupled to that struct by hand rather than by the compiler.
        push_field(
            &mut preimage,
            "state_fence",
            &fence_preimage(&self.state_fence),
        );
        push_field(&mut preimage, "change_reason", &self.change_reason);
        freeze(&preimage)
    }

    /// Re-proves this revision's own digest.
    ///
    /// This is the readback check, and since the `v2` bump it is also the check
    /// that a substituted State Fence cannot survive: the fence is inside the
    /// preimage, so a revision whose fence was rewritten after the fact now
    /// computes a different digest and is refused here instead of reporting
    /// itself as the revision that was made.
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

/// One required independence dimension, measured over the eligible set.
///
/// The measurement is deliberately *not* a count. A count is exactly the shape
/// that lets ten pages from one vendor read as ten independent sources, so each
/// dimension is reported as the partition it actually imposes plus the
/// dimension-specific unknown linkage, and the requirement is checked against the
/// partition rather than against a score. Unknown linkage is preserved inside
/// the partition and never folded into it, so a member whose family cannot be
/// established cannot contribute a group to any of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndependenceDimensionMeasurement {
    /// The dimension this partition was measured on.
    pub dimension: IndependenceDimension,
    /// Distinct group identities the eligible members fall into, sorted. Two
    /// members in the same group are dependent on this dimension.
    pub groups: Vec<String>,
    /// Eligible handles whose group on this dimension could not be
    /// established. They are excluded from `groups` and never counted as
    /// independent support.
    pub unknown_handles: Vec<String>,
    /// Number of groups the requirement for this dimension demands, or zero when
    /// the requirement names none for this dimension.
    pub required_groups: u64,
    /// Whether the observed partition meets the dimension's own requirement.
    ///
    /// `false` whenever any group on this dimension is unknown, because an
    /// unestablished group is missing evidence rather than an extra group.
    pub meets_requirement: bool,
    /// Digest over the measurement shape.
    pub digest: String,
}

impl IndependenceDimensionMeasurement {
    /// Measures one dimension over the eligible handles and their records.
    ///
    /// The group identity of a handle is read from the exact vetted record on
    /// the one input that can establish it, and a handle with no record or no
    /// value on that input lands in `unknown_handles` rather than being given a
    /// group of its own. Duplication therefore never adds a group: two members
    /// that restate one primary work share the work's own group identity, and
    /// two members read off one evaluator share the evaluator's.
    #[must_use]
    fn measure(
        dimension: IndependenceDimension,
        eligible: &[String],
        records: &BTreeMap<String, SourceRecord>,
        required_groups: u64,
    ) -> Self {
        let (mut groups, mut unknown_handles) = independent_groups(dimension, eligible, records);
        groups.sort();
        groups.dedup();
        unknown_handles.sort();
        unknown_handles.dedup();
        let observed = u64::try_from(groups.len()).unwrap_or(u64::MAX);
        // A zero requirement means the declared profile named no minimum on this
        // axis, so the axis is measured and published but nothing is demanded of
        // it. A non-zero one is satisfied only by distinct known groups: an
        // unknown group is missing evidence, never an extra group.
        let meets_requirement =
            required_groups == 0 || (unknown_handles.is_empty() && observed >= required_groups);
        let mut measurement = Self {
            dimension,
            groups,
            unknown_handles,
            required_groups,
            meets_requirement,
            digest: String::new(),
        };
        measurement.digest = measurement.compute_digest();
        measurement
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("independence-dimension/v1;");
        push_field(&mut preimage, "dimension", self.dimension.wire_name());
        push_count(&mut preimage, "groups", self.groups.len());
        for group in &self.groups {
            push_field(&mut preimage, "group", group);
        }
        push_count(&mut preimage, "unknown_handles", self.unknown_handles.len());
        for handle in &self.unknown_handles {
            push_field(&mut preimage, "unknown_handle", handle);
        }
        push_field(
            &mut preimage,
            "required_groups",
            &self.required_groups.to_string(),
        );
        push_field(
            &mut preimage,
            "meets_requirement",
            bool_text(self.meets_requirement),
        );
        freeze(&preimage)
    }
}

/// The group identity one eligible handle falls into on one dimension, or
/// `None` when the vetted record behind it establishes none.
///
/// Each dimension reads the single record field that can actually establish it,
/// rather than a projection of the lineage root: a provider family and an
/// evaluator family are facts about *how* the material was produced, and a
/// shared context ancestor is a fact about what the material descends from.
/// Falling back to the lineage root for those three would make a shared
/// evaluator look like a shared source and would let a source-family
/// measurement stand in for the other four.
fn independent_groups(
    dimension: IndependenceDimension,
    eligible: &[String],
    records: &BTreeMap<String, SourceRecord>,
) -> (Vec<String>, Vec<String>) {
    let mut groups = Vec::new();
    let mut unknown_handles = Vec::new();
    for handle in eligible {
        let Some(record) = records.get(handle) else {
            unknown_handles.push(handle.clone());
            continue;
        };
        let group: Option<String> = match dimension {
            IndependenceDimension::SourceFamily => record.lineage_root.clone(),
            IndependenceDimension::ProviderFamily => record.provider_family.clone(),
            IndependenceDimension::EvaluatorFamily => record.evaluator_family.clone(),
            IndependenceDimension::SharedContextAncestor => record.transformed_from.clone(),
            IndependenceDimension::SharedAssumptions => shared_assumption_group(record),
        };
        match group {
            Some(group) => groups.push(group),
            None => unknown_handles.push(handle.clone()),
        }
    }
    (groups, unknown_handles)
}

/// The group identity shared-assumption independence falls into for one record.
///
/// Assumptions are a *set*, not a value, so two members share an assumption
/// family only when their whole assumption sets are equal. A record that carries
/// no assumption establishes none, and is therefore not placed in a shared
/// group with another record: "no known assumption" is a statement about what was
/// recorded, and treating it as a family would let any two unannotated members
/// corroborate each other.
fn shared_assumption_group(record: &SourceRecord) -> Option<String> {
    if record.assumptions.is_empty() {
        return None;
    }
    let mut preimage = String::from("assumption-family/v1;");
    push_count(&mut preimage, "assumptions", record.assumptions.len());
    for assumption in &record.assumptions {
        push_field(&mut preimage, "assumption", assumption);
    }
    Some(freeze(&preimage))
}

/// Independence profile of one source portfolio (I21.6).
///
/// Ten pages from one vendor are not ten independent sources: two outputs are
/// dependent when they share a source, restate one primary work, run on one
/// model family, saw one parent summary, use one evaluator or inherit one
/// mistaken assumption. Unknown lineage stays preserved and never inflates the
/// independent count.
///
/// The profile measures each of those five axes separately and binds the
/// result to the dimensions the profile actually declared, so the requirement
/// comes from [`IndependenceBlindingPolicy::dimensions`] rather than from a
/// hardcoded rule here.
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
    /// One measurement per dimension [`IndependenceBlindingPolicy::dimensions`]
    /// declared, in the declared order.
    ///
    /// The list is the declared requirement itself, not a fixed five: a profile
    /// that declared only source and provider family carries only those two
    /// measurements, so a consumer never has to infer which axes were in force.
    pub dimensions: Vec<IndependenceDimensionMeasurement>,
    /// Digest over the profile shape.
    pub digest: String,
}

impl IndependenceProfile {
    /// Derives the independence profile from the eligible handles, the exact
    /// vetted records behind them and the dimensions the profile declared.
    ///
    /// `required_dimensions` comes from
    /// [`IndependenceBlindingPolicy::dimensions`], so the measurement is bound
    /// to the claim and protocol rather than to a global rule, and
    /// `minimum_independent_families` supplies the count each declared axis has
    /// to reach. That count applies to every axis uniformly, including the two
    /// I21.6 phrases negatively ("saw one parent summary", "inherits one
    /// mistaken assumption"): both are partitions of the eligible set, and
    /// "no shared ancestor" is exactly "at least one group per member", so
    /// requiring distinct groups is the same statement in countable form.
    ///
    /// With no declared dimension the measurements list is empty and
    /// `meets_requirement` falls back to the lineage-level answer, which is the
    /// honest reading of a profile that declared no independence requirement.
    #[must_use]
    pub fn derive(
        eligible: &[String],
        records: &BTreeMap<String, SourceRecord>,
        required_dimensions: &[IndependenceDimension],
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
        let lineage_meets_requirement = unknown == 0 && observed >= minimum_independent_families;
        let mut dimensions: Vec<IndependenceDimensionMeasurement> = required_dimensions
            .iter()
            .copied()
            .map(|dimension| {
                // The same minimum applies to every declared axis, including the
                // two I21.6 phrases negatively: "no shared context ancestor" and
                // "no shared assumption" are partitions of the eligible set, and
                // each is satisfied exactly when its members form at least that
                // many distinct groups. A zero minimum therefore names no demand
                // on the axis while still measuring and publishing it.
                IndependenceDimensionMeasurement::measure(
                    dimension,
                    eligible,
                    records,
                    minimum_independent_families,
                )
            })
            .collect();
        dimensions.sort_by_key(|measurement| measurement.dimension);
        dimensions.dedup_by_key(|measurement| measurement.dimension);
        let meets_requirement = if dimensions.is_empty() {
            lineage_meets_requirement
        } else {
            // Every declared dimension must be satisfied. An axis that is
            // unmeasured or unmet cannot be compensated by another axis meeting
            // its own: five pages from one evaluator are not five independent
            // sources, however many different vendors they quote.
            lineage_meets_requirement
                && dimensions
                    .iter()
                    .all(|measurement| measurement.meets_requirement)
        };
        let mut profile = Self {
            lineage_roots,
            unknown_independence_handles,
            independent_lineages: independent,
            minimum_independent_families,
            meets_requirement,
            dimensions,
            digest: String::new(),
        };
        profile.digest = profile.compute_digest();
        profile
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("independence-profile/v2;");
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
        push_count(&mut preimage, "dimensions", self.dimensions.len());
        for measurement in &self.dimensions {
            push_field(
                &mut preimage,
                "dimension",
                measurement.dimension.wire_name(),
            );
            push_field(&mut preimage, "dimension_digest", &measurement.digest);
        }
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
                dimensions: Vec::new(),
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
            &profile.independence_and_blinding_policy.dimensions,
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

/// Names exactly which independence axis fell short, and why.
///
/// The lineage-level count alone is no longer the whole story now that the
/// profile measures every declared dimension, so the debt says which axis
/// produced the shortfall rather than leaving a reader to re-derive it. An axis
/// whose groups are all known but too few is reported as a count; an axis with
/// unknown linkage is reported as unknown, because a missing group is missing
/// evidence and never an extra group.
fn independence_shortfall(profile: &IndependenceProfile) -> String {
    let unmet: Vec<String> = profile
        .dimensions
        .iter()
        .filter(|measurement| !measurement.meets_requirement)
        .map(|measurement| {
            if measurement.unknown_handles.is_empty() {
                format!(
                    "{}: {} distinct group(s) do not meet the declared minimum {}",
                    measurement.dimension.wire_name(),
                    measurement.groups.len(),
                    measurement.required_groups
                )
            } else {
                format!(
                    "{}: {} of {} eligible member(s) have no established group",
                    measurement.dimension.wire_name(),
                    measurement.unknown_handles.len(),
                    measurement.groups.len() + measurement.unknown_handles.len()
                )
            }
        })
        .collect();
    if unmet.is_empty() {
        return format!(
            "observed independent lineages {} do not meet the declared minimum {}",
            profile.independent_lineages, profile.minimum_independent_families
        );
    }
    format!(
        "observed independent lineages {} do not meet the declared minimum {}; unmet: {}",
        profile.independent_lineages,
        profile.minimum_independent_families,
        unmet.join("; ")
    )
}

/// Builds the exact vetted-record map the existing lineage owner consumes.
fn vetted_records(records: &[SourceAdmissibilityRecord]) -> BTreeMap<String, SourceRecord> {
    records
        .iter()
        .map(|record| (record.record.handle.clone(), record.record.clone()))
        .collect()
}

/// The one seam through which an admitted route presents owner-issued absence
/// evidence to the live coverage receipt.
///
/// Before this type existed there was no place at all to present such a record:
/// [`CoverageReceipt::compute`] hard-passed `None` in both the manifest and the
/// evaluation positions of [`AbsencePreconditions::derive`], so the
/// evidence-gated arms of
/// [`assess_absence`](crate::evidence_portfolio::assess_absence) were
/// unreachable not because the evidence was refused but because nothing could be
/// handed over. The two are paired deliberately and cannot be separated: an
/// owner-issued [`NoMatchEvaluation`] is only meaningful against the exact
/// [`AuthorizedManifest`] its own commitments name, and presenting the record
/// without the manifest it was issued under would be presenting a claim with no
/// authorizing document behind it.
///
/// This is a *presentation* point, not a producer. The ordinary research route
/// presents `None` at its construction site, with the reason written there, which
/// is the fail-closed state issue step 11 and checklist item W11 require. No
/// evaluation is fabricated to complete a receipt.
///
/// # Which owner values this seam still needs, and why they are absent
///
/// #2893 item 12 asks that final `NO_MATCH`/closure be connected here once the
/// evidence record exists. The closure gate is already in place and is not what
/// blocks it: `terminal_disposition` refuses any closing disposition unless
/// `all_closed` and `denominator_kind.supports_scoped_absence()`, and
/// `denominator_kind` requires both `absence_evidence_digest` and
/// `absence_proof_ceiling_grade`. What is missing is the record that arrives
/// here, and the measurement of what it would take is exact rather than
/// approximate.
///
/// Filling this seam needs a
/// [`NoMatchEvaluationIssuer`](crate::evidence_portfolio::NoMatchEvaluationIssuer),
/// and the issuer holds
/// twenty commitments. Twelve of them have a live owner value on this path. Eight
/// do not, and they are not derivable from anything this crate or this plane
/// holds:
///
/// | Held commitment | Owner value on the live route |
/// |---|---|
/// | `denominator_digest` | `profile.admitted_denominator_digest` |
/// | `manifest_digest`, `manifest_revision` | the manifest `audit_binding` freezes |
/// | `fence` | `profile.state_fence` |
/// | `work_scope` | `observation.scope` |
/// | `scope_digest` | `profile.admitted_denominator_digest` — available, not yet threaded; see below |
/// | `predicate_id`, `predicate_revision`, `predicate_form` | **absent** |
/// | `issuer_id`, `evaluator_id`, `evaluator_revision` | **absent** |
/// | `admission_receipt_id` | **absent** |
/// | `index_revision`, `source_revision` | **absent** |
/// | `scope_revision` | **absent** |
///
/// The eight absent values are one fact seen from eight sides: this plane carries
/// per-source *acquisition custody* and never per-member *predicate execution*.
/// [`CandidateEvidence`] is the whole of what the R6 plane observes about a
/// candidate — handle, class, operation identity, content digest, receipt handle,
/// route, provider generation, lineage root, outcome, stream state, exit and
/// refusal — and none of those is a predicate identity, a query commitment, an
/// evaluator identity, an admission receipt, an index or corpus revision, or a
/// scope-snapshot revision. There is no field on [`InquiryObservation`] that
/// carries one either, and no value anywhere in this repository that produces
/// them: `git grep` over `crates/research` and `bins` finds `predicate_id`,
/// `predicate_revision`, `admission_receipt_id` and `MemberNoMatchResult`
/// only in this crate's own type declarations, and the same holds on the live
/// route for `index_revision`, `source_revision` and `evaluator_revision`.
/// `scope_revision` has a handful of unrelated same-named fields in other
/// crates; none of them is a producer for this commitment.
///
/// The scope-snapshot commitment is the one that is closest to reachable, and it
/// is worth being exact about why it is not yet threaded. `scope_digest` is the
/// "digest of the frozen scope/denominator snapshot" (see
/// [`NoMatchEvaluation`](crate::evidence_portfolio::NoMatchEvaluation)), and
/// `check_scope_binding` requires the presented digest to equal the issuer's
/// held `scope_digest` exactly. The live route currently supplies
/// `frozen_scope_digest: &observation.reference_manifest.digest` (see the
/// construction site in [`InquiryGovernance::record`]), and *that* value is
/// wrong for the slot: it is the digest of a run-bound reference allowlist, a
/// different commitment from a different owner.
///
/// The correct value is not missing. It is `profile.admitted_denominator_digest`
/// — the Kernel-admitted denominator digest, already read on this very path and
/// already compared against `frozen_scope_digest` by the receipt's own
/// `scope_snapshot_matches_admission` check. This crate therefore already
/// states, in code, that the frozen scope digest is *expected* to equal the
/// admitted denominator digest; the reference-allowlist digest currently passed
/// at that site does not, and the receipt's comparison is what exposes it.
/// Threading `admitted_denominator_digest` into the issuer's `scope_digest` is
/// therefore a one-value change, not a new digest and not a new owner. It is
/// deferred with the other eight commitments above rather than half-applied:
/// correcting the scope value alone would still leave the seam fail-closed on
/// the eight genuinely absent query/evaluator commitments, and changing a
/// receipt input the issuer cannot yet join is not this increment's work.
///
/// Constructing the issuer in this crate would therefore mean writing the eight
/// absent values above as literals and asserting, through `issue_for`, that a predicate
/// ran against members this process never searched. That is the exact fabrication
/// the issue forbids and the exact residual trust boundary documented on
/// [`NoMatchEvaluation`]: an issuer holder that invents evaluator attestations
/// makes the negative self-consistent and unearned at the same time, and it
/// would convert a receipt that is honestly `Unproven` into a `CompleteScope`
/// closure backed by no predicate execution at all. A test fixture may
/// legitimately hold an issuer — the package fixture in `tests/` is exactly that
/// and is the positive case #2893 item 10 asked for — but a production holder
/// that fabricates one is the failure this boundary exists to prevent.
///
/// So the seam stays `None`, deliberately and with the reason recorded here, and
/// the route that fills it is the live evaluator composition owned by
/// #1762/#1767. The exported issuer, its named-argument params and
/// [`AuthorizedManifest`] are already public precisely so that an external
/// holder can issue and present a record here without this crate widening its
/// own surface further.
#[derive(Clone, Debug)]
pub struct AbsenceEvidence {
    /// The authorized manifest the evaluation was issued under.
    pub manifest: AuthorizedManifest,
    /// The owner-issued per-member predicate evaluation.
    pub evaluation: NoMatchEvaluation,
}

/// The exact owner-issued absence evidence one terminal closure decision rests
/// on, re-proved at the point of closure.
///
/// # #2893 item 12
///
/// Item 12 asks that final `NO_MATCH`/closure be connected here once the
/// evidence record exists. This is that connection, and it is deliberately a
/// *closure-side* value rather than another receipt field, for two reasons:
///
/// * the receipt already retains the record's identity
///   ([`CoverageReceipt::absence_evidence_digest`]) and its ceiling
///   ([`CoverageReceipt::absence_proof_ceiling_grade`]) inside
///   `coverage-receipt/v3`, and it re-proves the record itself inside
///   [`AbsencePreconditions::derive`] before the verdict is derived. A third copy
///   of the same fact on the receipt would be a second owner of it;
/// * a closure decision needs the *record*, not its digest. "The digest of a
///   record that once existed" cannot be re-proved against the State Fence, the
///   frozen scope snapshot or the assessment instant of the operation that is
///   closing, and those are precisely the commitments `NoMatchEvaluation`
///   carries and `AbsencePreconditions::derive` checked. Carrying the record is
///   what lets a releasing owner re-run those checks against *this* operation
///   instead of trusting a closure that a different one published.
///
/// Every field is private and there is exactly one way to obtain a value,
/// [`Self::verify`], which refuses rather than returns an optional. A record
/// that cannot re-prove itself, or that does not name this run's own profile,
/// State Fence and frozen scope snapshot, produces `None` — so
/// [`terminal_disposition`] has no value to read and the closure stays
/// [`CompletionDisposition::IncompleteCoverage`]. There is no constructor that
/// mints one from a caller-supplied digest or a bare `Proven` verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbsenceClosureEvidence {
    /// The re-proved owner-issued evaluation.
    evaluation: NoMatchEvaluation,
    /// Its canonical identity, so a reader compares it against the receipt's
    /// retained `absence_evidence_digest` by recomputation, not by trust.
    evaluation_digest: String,
    /// The authorized manifest the evaluation was issued under, re-proved.
    manifest: AuthorizedManifest,
    /// The proof ceiling this closure may not exceed.
    proof_ceiling_grade: Option<u8>,
}

impl AbsenceClosureEvidence {
    /// Re-proves one presented record against *this* operation and, only if
    /// every commitment joins, produces the value a closure may rest on.
    ///
    /// The join is against the same run the receipt was computed over: the
    /// evaluation's State Fence must be the profile's, its held `scope_digest`
    /// must be the admitted denominator snapshot this receipt accounts over, its
    /// named manifest must be the presented manifest's, and the record must
    /// re-prove its own identity and still declare a proof ceiling. A mismatch
    /// is `None`, never a relaxed closure.
    pub fn verify(
        evidence: &AbsenceEvidence,
        profile: &InquiryProtocolProfile,
        receipt: &CoverageReceipt,
    ) -> Option<Self> {
        evidence.evaluation.verify_integrity().ok()?;
        evidence.manifest.verify_integrity().ok()?;
        let evaluation_digest = evidence.evaluation.canonical_digest().ok()?;
        // Bound to *this* operation rather than merely to a digest the receipt
        // already holds: an evaluation admitted under a different fence, or over
        // a different frozen scope snapshot, is a different run's evidence even
        // if the receipt were handed a matching digest.
        if !evidence.evaluation.is_admitted_under(&profile.state_fence)
            || !evidence
                .evaluation
                .covers_scope(&receipt.admitted_denominator_digest)
        {
            return None;
        }
        // Kept as the record's own `Option`, not unwrapped: a record that never
        // established a ceiling publishes `none` here, and `closes_negative`
        // compares it with the receipt's own retained value, so a receipt that
        // published no ceiling and a record that established none still agree
        // while a record that established one can never be published under a
        // receipt that published none.
        let proof_ceiling_grade = evidence.evaluation.proof_ceiling_grade();
        Some(Self {
            evaluation: evidence.evaluation.clone(),
            evaluation_digest,
            manifest: evidence.manifest.clone(),
            proof_ceiling_grade,
        })
    }

    /// Whether this evidence supports a scoped-negative closure over `receipt`.
    ///
    /// Every conjunct below is a fact the record itself carries, re-proved by
    /// [`Self::verify`]; none of them is read off a caller flag, and
    /// `denominator_kind` is deliberately *not* re-implemented here — the
    /// receipt's own field already encodes every other condition
    /// (`all_closed`, `accounted`, no provider degradation, counter-search
    /// satisfied) and re-deciding them would be the second validator #2893
    /// forbids. What this adds is the one check the receipt's own gate cannot
    /// make: that the record a reader is being asked to trust is the same record
    /// the receipt retained, and that it is the record of a *negative* over this
    /// exact accounting.
    fn closes_negative(&self, receipt: &CoverageReceipt) -> bool {
        // The identity the receipt retained must be this record's own, so the
        // verdict and the record it was derived from cannot be re-pointed.
        receipt.absence_evidence_digest.as_deref() == Some(self.evaluation_digest.as_str())
            // The record's held manifest must be the one presented with it.
            // Compared by RECOMPUTING the presented manifest's canonical digest
            // rather than by reading its frozen field, so the join is against a
            // value derived from the record's own bytes and not a field a
            // caller could have written. `verify` already re-proved that digest
            // against the manifest's own frozen identity.
            && self
                .manifest
                .canonical_digest()
                .is_ok_and(|digest| digest == self.evaluation.named_manifest_digest())
            // The record must be *proven* absence, and it must not have been
            // published over a scope snapshot this run did not account over.
            && self.evaluation.proves_absence()
            && self.evaluation.covers_scope(&receipt.frozen_scope_digest)
            // The retained ceiling must not be weaker than what the receipt
            // published, so the two facts a reader reads cannot disagree.
            && self.proof_ceiling_grade == receipt.absence_proof_ceiling_grade
            // The denominator kind is the receipt's own verdict over the whole
            // conjunction; reading it here rather than re-deriving it keeps one
            // owner for it.
            && receipt.denominator_kind.supports_scoped_absence()
            && receipt.all_closed
            && receipt.scope_snapshot_matches_admission
    }

    /// Canonical digest of the owner-issued evaluation this closure rests on.
    ///
    /// Read by a releasing owner to confirm it is holding the record the
    /// disposition was taken over, which is what
    /// [`InquiryTerminalRecord::absence_closure_evidence_digest`] publishes.
    #[must_use]
    pub fn evaluation_digest(&self) -> &str {
        &self.evaluation_digest
    }

    /// Proof ceiling this closure may not be published past.
    #[must_use]
    pub fn proof_ceiling_grade(&self) -> Option<u8> {
        self.proof_ceiling_grade
    }

    /// The members this record carries an owner-issued per-member result for, in
    /// canonical order.
    #[must_use]
    pub fn evaluated_members(&self) -> Vec<String> {
        self.evaluation.evaluated_members()
    }
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
    /// Digest of the owner-issued [`NoMatchEvaluation`] the verdict was derived
    /// against, when the route presented one.
    ///
    /// `coverage-receipt/v2` bound the verdict class and its reason but never the
    /// record behind it, so a receipt could publish an `AbsenceVerdict` into the
    /// evidence-freeze and terminal-record digests with nothing nameable to
    /// revalidate. A holder reads this to re-prove the exact record rather than
    /// trust the verdict it produced. `None` is the fail-closed state and is
    /// digested explicitly as `absent`, so "nothing was presented" is a bound
    /// fact about this receipt rather than an omission a reader has to notice.
    pub absence_evidence_digest: Option<String>,
    /// Proof ceiling the presented evidence may not exceed, when one was
    /// presented.
    ///
    /// Retained beside the verdict so a releasing owner can refuse to publish a
    /// claim stronger than the evidence's own ceiling allows, rather than
    /// re-deriving that ceiling from records it may no longer hold.
    pub absence_proof_ceiling_grade: Option<u8>,
    /// Declared denominator kind.
    pub denominator_kind: DenominatorKind,
    /// Budget limitation that bounded the run, when one applied.
    pub budget_limitation: Option<String>,
    /// Digest over the receipt shape.
    pub digest: String,
}

/// Named arguments for [`CoverageReceipt::compute`].
///
/// A parameter list here is not cosmetic. The eleven inputs a coverage receipt
/// consumes are eleven chances to transpose two of them, and the seam argument
/// added by #2893 is the one whose order matters most: an evaluation presented
/// against the wrong account is exactly the caller-constructed negative this
/// issue exists to refuse. Named fields make that a compile error instead.
#[derive(Clone, Debug)]
pub struct CoverageReceiptParams<'a> {
    /// Resolved protocol profile the receipt is computed under.
    pub profile: &'a InquiryProtocolProfile,
    /// Exact requested scope text.
    pub requested_scope: &'a str,
    /// Digest of the frozen scope snapshot the receipt accounts over.
    pub frozen_scope_digest: &'a str,
    /// The exact coverage accounting being receipted.
    pub account: &'a CoverageAccount,
    /// Vetted admissibility records this run admitted.
    pub records: &'a [SourceAdmissibilityRecord],
    /// Owner-issued absence evidence, when the route holds it.
    pub absence_evidence: Option<&'a AbsenceEvidence>,
    /// Routes the run used.
    pub routes_used: Vec<String>,
    /// Provider degradation observed on this run.
    pub provider_degradation: Vec<String>,
    /// Explicit coverage unknowns, preserved rather than smoothed.
    pub unknown_coverage: Vec<String>,
    /// Budget limitation that bounded the run, when one applied.
    pub budget_limitation: Option<String>,
    /// The run's own assessment instant.
    pub assessment_time_ms: i64,
}

impl CoverageReceipt {
    /// Computes the receipt from the exact accounting and the eligibility set.
    ///
    /// `absence_evidence` is the single seam through which a route that holds an
    /// owner-issued record presents it, as the authorized manifest and the
    /// evaluation the record was issued under. `None` is the ordinary state and is
    /// the fail-closed answer, not a placeholder: with no evaluation bound, the
    /// absence verdict can never be [`AbsenceVerdict::Proven`], the denominator
    /// kind stays [`DenominatorKind::Unknown`] and the receipt names the missing
    /// record as its reason. The research plane records per-source acquisition
    /// dispositions, not per-member query predicate results, and #2893 forbids
    /// fabricating one here.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IncompleteDenominator`] when the frozen
    /// denominator has no member to account, a field error for a vague
    /// scope or a malformed frozen-scope digest, and the absence-precondition
    /// error when presented evidence names no member, does not re-prove its own
    /// identity, or does not join the records this run admitted.
    pub fn compute(params: CoverageReceiptParams<'_>) -> Result<Self, InquiryError> {
        let CoverageReceiptParams {
            profile,
            requested_scope,
            frozen_scope_digest,
            account,
            records,
            absence_evidence,
            routes_used,
            provider_degradation,
            unknown_coverage,
            budget_limitation,
            assessment_time_ms,
        } = params;
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
        // The evaluation and the manifest it was issued under arrive together or
        // not at all, through `AbsenceEvidence` above. Presenting a record
        // without its manifest would be presenting a claim with no authorizing
        // document behind it, and `AbsencePreconditions::derive` re-proves both
        // on the way in, so a rewritten one is refused before any of its content
        // is believed.
        let absence_preconditions = AbsencePreconditions::derive(
            account,
            &vetted_records(records),
            absence_evidence.map(|evidence| &evidence.manifest),
            assessment_time_ms,
            frozen_scope_digest,
            absence_evidence.map(|evidence| evidence.evaluation.clone()),
        )?;
        let absence_verdict = assess_absence(account, &absence_preconditions);
        // The retained identity and ceiling come from the record the derivation
        // just re-proved, not from the presented argument, so they cannot disagree
        // with the verdict the assessor produced from that same record.
        let absence_evidence_digest = absence_evidence
            .map(|evidence| evidence.evaluation.canonical_digest())
            .transpose()?;
        let absence_proof_ceiling_grade =
            absence_evidence.and_then(|evidence| evidence.evaluation.proof_ceiling_grade());
        let counter_search_status = if profile.hypothesis_policy.requires_counter_search() {
            CounterSearchStatus::RequiredAndOpen
        } else {
            CounterSearchStatus::NotRequired
        };
        let evidence = CompleteScopeEvidence {
            all_closed,
            accounted,
            absence_verdict: &absence_verdict,
            absence_evidence_digest: absence_evidence_digest.as_deref(),
            absence_proof_ceiling_grade,
            degradation_count: provider_degradation.len(),
            counter_search_status,
        };
        let denominator_kind = denominator_kind(&evidence);
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
            absence_evidence_digest,
            absence_proof_ceiling_grade,
            denominator_kind,
            budget_limitation,
            digest: String::new(),
        };
        receipt.digest = receipt.compute_digest();
        Ok(receipt)
    }

    fn compute_digest(&self) -> String {
        // Bumped `v1` -> `v2` by #2893 for a changed *value space* under one name:
        // this preimage binds a reason string verbatim (see the `absence_reason`
        // push below), and #2893 changed two of those strings and the population
        // that reaches them. #2893 then bumped `v2` -> `v3` for the other reason
        // named by the declared-domain rule: the preimage field set GREW. The
        // receipt now binds the digest of the owner-issued record its verdict was
        // derived from, and the proof ceiling that record may not be exceeded
        // past. Under `v2` those two facts were carried on the record but reached
        // no digest, so two receipts with the same verdict and different evidence
        // behind it were indistinguishable, which is precisely what this issue
        // exists to prevent.
        //
        // Transitively, `evidence-freeze/v2` and `inquiry-terminal-record/*` bind
        // this digest and therefore produce different values for the same run.
        // `evidence-freeze` was then bumped `v1` -> `v2` by #1765, and for the
        // other reason: its own preimage field set *grew* (the State Fence and the
        // three successor-relation fields), and one name must not cover two field
        // sets. That is the shape-change rule stated here, applied to the freeze
        // rather than to the receipt.
        // `inquiry-terminal-record` was bumped `v1` -> `v2` by #1762 for the
        // opposite reason: its preimage *field set* changed when the evidence
        // freeze, the claim audit and the unsupported-precision residue became
        // carried fields. `research-debt/v1` is unaffected because its preimage
        // never named the receipt digest.
        let mut preimage = String::from("coverage-receipt/v3;");
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
        push_repeated_fields(&mut preimage, self);
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
        // The retained record identity and its ceiling. `absent` is spelled
        // rather than omitted, so "no evidence was presented" is a bound state
        // of this preimage and not an indistinguishable one: an omitted field
        // would make a receipt that presented nothing digest identically to a
        // receipt whose absent field was simply not reached.
        match &self.absence_evidence_digest {
            Some(digest) => push_field(&mut preimage, "absence_evidence", digest),
            None => push_field(&mut preimage, "absence_evidence", "absent"),
        }
        match self.absence_proof_ceiling_grade {
            Some(ceiling) => push_field(&mut preimage, "absence_ceiling", &ceiling.to_string()),
            None => push_field(&mut preimage, "absence_ceiling", "unknown"),
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

/// Pushes the receipt's three free-valued retained lists onto a digest preimage.
///
/// Each list is bound as a count followed by that many values under the same
/// tag, so a reader of the preimage can tell an empty list from a list whose
/// values were never reached. The tag order is the field order, and the order
/// of the values within each list is the order the receipt itself carries.
fn push_repeated_fields(preimage: &mut String, receipt: &CoverageReceipt) {
    for (tag, values) in [
        ("unknown_coverage", &receipt.unknown_coverage),
        ("route_used", &receipt.routes_used),
        ("degradation", &receipt.provider_degradation),
    ] {
        push_count(preimage, tag, values.len());
        for value in values {
            push_field(preimage, tag, value);
        }
    }
}

/// The facts a complete-scope denominator claim is decided from.
///
/// A named struct rather than a positional list, because four of these seven
/// inputs are `Option`-shaped or reference-shaped and a positional call at this
/// width makes transposition a compile-time no-op. The two #2893 added are the
/// ones that matter most: presenting an evaluation against the wrong account is
/// exactly the caller-constructed negative this issue exists to refuse, and
/// reading a verdict's ceiling off the wrong field would publish a claim
/// stronger than the evidence allows.
struct CompleteScopeEvidence<'a> {
    /// Whether every accounted member closed intact.
    all_closed: bool,
    /// Whether every expected member is accounted exactly once.
    accounted: bool,
    /// The absence assessment produced for this run.
    absence_verdict: &'a AbsenceVerdict,
    /// Digest of the owner-issued record the verdict was derived from.
    absence_evidence_digest: Option<&'a str>,
    /// That record's proof ceiling.
    absence_proof_ceiling_grade: Option<u8>,
    /// How many provider degradations this run observed.
    degradation_count: usize,
    /// Whether the hypothesis policy's counter search is satisfied.
    counter_search_status: CounterSearchStatus,
}

/// Decides which denominator kind a run may publish.
///
/// [`DenominatorKind::CompleteScope`] is the only kind that grounds a scoped
/// absence, so every condition here is load-bearing and none of them
/// substitutes for another: the accounting must be complete and intact, the
/// assessor must have returned [`AbsenceVerdict::Proven`], the provider must not
/// have degraded, and the hypothesis policy's counter search must be satisfied.
///
/// #2893 added the two evidence conditions, and they are the point of this
/// function. Before them, a complete-scope claim rested on the verdict enum
/// alone, so the receipt published `CompleteScope` with nothing nameable behind
/// it and a releasing owner had no retained record to revalidate. The verdict and
/// the record are now required together, which is a statement about *evidence*,
/// not about a different verdict: the record is what the verdict was derived
/// from, so demanding both cannot refuse a run that could pass on the verdict
/// alone, and it does refuse a run whose verdict came from somewhere that kept
/// no record. Both conditions are unreachable in production today, because
/// [`assess_absence`](crate::evidence_portfolio::assess_absence) cannot return
/// `Proven` without an owner-issued evaluation; they are written out rather
/// than assumed, so a future assessor that grew a new way to prove absence
/// cannot raise this receipt's denominator kind without a record behind it.
fn denominator_kind(evidence: &CompleteScopeEvidence<'_>) -> DenominatorKind {
    if evidence.all_closed
        && evidence.accounted
        && evidence.absence_verdict == &AbsenceVerdict::Proven
        && evidence.absence_evidence_digest.is_some()
        && evidence.absence_proof_ceiling_grade.is_some()
        && evidence.degradation_count == 0
        && evidence.counter_search_status == CounterSearchStatus::Satisfied
    {
        DenominatorKind::CompleteScope
    } else {
        DenominatorKind::Unknown
    }
}

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
    ///
    /// Derived from the inquiry, the profile revision **and the content
    /// commitment of the frozen set itself**. The previous spelling named only
    /// the inquiry and the profile revision, so two successive freezes of the
    /// same inquiry at the same profile revision — the reopen case I21.8
    /// describes — received one identical identity and became indistinguishable
    /// from each other. The portfolio, manifest and coverage digests are all
    /// already in the preimage, so naming the freeze over them costs nothing and
    /// makes the identity move exactly when the frozen content does.
    pub freeze_id: String,
    /// Digest of the freeze this one supersedes, when it is a successor.
    ///
    /// `None` on the first freeze of an inquiry. I21.8 requires new material,
    /// materially changed source content or a changed protocol to produce an
    /// explicit successor carrying its reason and its expected revision, and it
    /// must not mutate the prior brief or audit: the prior freeze is named, never
    /// rewritten, so both stay addressable.
    pub supersedes: Option<String>,
    /// Why this freeze was opened as a successor, when it is one.
    pub supersede_reason: Option<String>,
    /// The evidence revision this successor expected to find, when it is one.
    ///
    /// Recorded as a declared expectation rather than a comparison result: the
    /// prior freeze's own digest is in `supersedes`, and this is the revision the
    /// run said it was reopening to reach. A run that reopens without a declared
    /// expectation is refused by [`Self::validate_successor`].
    pub expected_revision: Option<String>,
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

/// Named constructor arguments for [`EvidenceFreeze::freeze`].
///
/// A params struct rather than a longer positional list: the freeze takes more
/// inputs than a positional signature can carry without a lint suppression, and
/// a named struct is what makes the successor relation readable at the call
/// site instead of hiding it behind a bag of `&str`s.
#[derive(Clone, Debug)]
pub struct EvidenceFreezeParams {
    /// Inquiry identity.
    pub inquiry_id: String,
    /// Portfolio digest frozen with the evidence.
    pub portfolio_digest: String,
    /// Reference manifest digest frozen with the evidence.
    pub manifest_digest: String,
    /// Coverage receipt digest frozen with the evidence.
    pub coverage_receipt_digest: String,
    /// Evidence-set identity the freeze covers.
    pub evidence_set_id: String,
    /// Included evidence references.
    pub included_evidence_refs: Vec<String>,
    /// Excluded evidence and the reason it was excluded.
    pub excluded_evidence: Vec<(String, String)>,
    /// Unresolved contradictions observed between members.
    pub unresolved_contradictions: Vec<String>,
    /// Open research debts at freeze time.
    pub open_research_debts: Vec<String>,
    /// Freeze instant in Unix milliseconds.
    pub frozen_at_ms: i64,
    /// Digest of the freeze this one supersedes, when it is a successor.
    pub supersedes: Option<String>,
    /// Why this freeze was opened as a successor, when it is one.
    pub supersede_reason: Option<String>,
    /// The evidence revision this successor expected to find, when it is one.
    pub expected_revision: Option<String>,
}

impl EvidenceFreeze {
    /// Freezes the accepted evidence revision for one inquiry.
    ///
    /// # Errors
    ///
    /// Returns a field error for blank identities or malformed digests, and a
    /// successor error when a successor freeze is declared without all three of
    /// its relation fields.
    pub fn freeze(
        params: EvidenceFreezeParams,
        profile: &InquiryProtocolProfile,
    ) -> Result<Self, InquiryError> {
        require_text(&params.inquiry_id, "freeze.inquiry_id")?;
        require_text(&params.evidence_set_id, "freeze.evidence_set_id")?;
        require_digest(&params.portfolio_digest, "freeze.portfolio_digest")?;
        require_digest(&params.manifest_digest, "freeze.manifest_digest")?;
        require_digest(
            &params.coverage_receipt_digest,
            "freeze.coverage_receipt_digest",
        )?;
        // `supersedes` and `expected_revision` are commitments and are checked as
        // digests; `supersede_reason` is the recorded cause and is bounded text,
        // because a digest would say only that some reason exists and not which
        // one — and I21.8 requires the reason itself to be recorded.
        for (tag, value) in [
            ("freeze.supersedes", params.supersedes.as_deref()),
            (
                "freeze.expected_revision",
                params.expected_revision.as_deref(),
            ),
        ] {
            if let Some(value) = value {
                require_digest(value, tag)?;
            }
        }
        // The three successor fields are one relation, not three independent
        // optionals. A successor without its reason states no cause, and a
        // successor without its expected revision states no target, so either
        // half alone is refused rather than published as a relation that means
        // nothing.
        let successor_fields = [
            params.supersedes.is_some(),
            params.supersede_reason.is_some(),
            params.expected_revision.is_some(),
        ];
        if successor_fields.iter().filter(|present| **present).count() != 0
            && !successor_fields.iter().all(|present| *present)
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "freeze.successor_relation",
            });
        }
        if let Some(reason) = &params.supersede_reason {
            require_text(reason, "freeze.supersede_reason")?;
        }
        // The identity names the content commitment, not only the question and
        // the protocol. Two freezes of one inquiry at one profile revision over
        // different evidence are different freezes and say so.
        let content_commitment = freeze(&format!(
            "freeze-identity/v1;{}|{}|{}|{}",
            params.portfolio_digest,
            params.manifest_digest,
            params.coverage_receipt_digest,
            params.evidence_set_id
        ));
        let mut record = Self {
            freeze_id: format!(
                "freeze-{}-{}@{}",
                params.inquiry_id,
                profile.profile_id_and_revision(),
                &content_commitment[..16]
            ),
            supersedes: params.supersedes,
            supersede_reason: params.supersede_reason,
            expected_revision: params.expected_revision,
            inquiry_id: params.inquiry_id,
            profile_id_and_revision: profile.profile_id_and_revision(),
            profile_digest: profile.integrity_digest.clone(),
            portfolio_digest: params.portfolio_digest,
            manifest_digest: params.manifest_digest,
            coverage_receipt_digest: params.coverage_receipt_digest,
            evidence_set_id: params.evidence_set_id,
            included_evidence_refs: params.included_evidence_refs,
            excluded_evidence: params.excluded_evidence,
            unresolved_contradictions: params.unresolved_contradictions,
            open_research_debts: params.open_research_debts,
            state_fence: profile.state_fence.clone(),
            frozen_at_ms: params.frozen_at_ms,
            canonical: false,
            governor_admission_required: true,
            digest: String::new(),
        };
        record.digest = record.compute_digest();
        Ok(record)
    }

    /// Declared identity domain of [`EvidenceFreeze::digest`].
    ///
    /// Bumped `v1` -> `v2` for `#1765`. The `v1` preimage named every field
    /// except `state_fence` and the three successor-relation fields, so two
    /// records that differed only in their State Fence, or in which freeze they
    /// reopened, rehashed identically. One name must not cover two field sets,
    /// and the same rule the `coverage-receipt` and `inquiry-terminal-record`
    /// preimages state for themselves applies here.
    pub const DIGEST_DOMAIN: &'static str = "evidence-freeze/v2";

    /// Whether this freeze is the successor of a prior one.
    #[must_use]
    pub fn is_successor(&self) -> bool {
        self.supersedes.is_some()
    }

    /// Whether `handle` is an **admitted included member** of this freeze.
    ///
    /// This is the one membership question W2 and W3 ask, and it is deliberately
    /// not "is this handle mentioned anywhere on the record": an excluded member
    /// is named here too, with the reason it was excluded, and a handle that
    /// appears only in `excluded_evidence` is precisely the member that must not
    /// enter a synthesis pack or back a freeze commit. So membership is answered
    /// against the included set alone.
    #[must_use]
    pub fn includes(&self, handle: &str) -> bool {
        self.included_evidence_refs
            .iter()
            .any(|member| member == handle)
    }

    /// The admitted included members, in the freeze's own canonical order.
    #[must_use]
    pub fn included_members(&self) -> &[String] {
        &self.included_evidence_refs
    }

    /// Re-proves the successor relation, if this freeze declares one.
    ///
    /// The three fields move together by construction, and this re-proves that
    /// on readback so a record that lost one of them between construction and
    /// publication is refused rather than presented as a first freeze.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when exactly some of the
    /// three relation fields are present.
    pub fn validate_successor(&self) -> Result<(), InquiryError> {
        let present = [
            self.supersedes.is_some(),
            self.supersede_reason.is_some(),
            self.expected_revision.is_some(),
        ];
        if present.iter().filter(|held| **held).count() != 0 && !present.iter().all(|held| *held) {
            return Err(InquiryError::IntegrityMismatch {
                field: "freeze.successor_relation",
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from(Self::DIGEST_DOMAIN);
        preimage.push(';');
        push_field(&mut preimage, "freeze_id", &self.freeze_id);
        // The successor relation is inside the identity: a reopen is a different
        // freeze, and a record that named the same members under a different
        // reason or expectation would otherwise re-present the prior identity.
        push_field(
            &mut preimage,
            "supersedes",
            self.supersedes.as_deref().unwrap_or("none"),
        );
        push_field(
            &mut preimage,
            "supersede_reason",
            self.supersede_reason.as_deref().unwrap_or("none"),
        );
        push_field(
            &mut preimage,
            "expected_revision",
            self.expected_revision.as_deref().unwrap_or("none"),
        );
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
        // The State Fence was published on the record but never named in the
        // preimage, so the freeze's own identity was fence-insensitive: the same
        // members frozen under a different authority epoch, resource generation
        // or task revision rehashed to the same digest. I21.8 names fence,
        // policy and interpretation-sensitive fields as exactly the ones a
        // rehash must cover, so the fence is inside.
        push_field(
            &mut preimage,
            "state_fence",
            &fence_preimage(&self.state_fence),
        );
        freeze(&preimage)
    }

    /// Re-proves this freeze's own digest and its successor relation.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one, when the record claims canonical state, or
    /// when the successor relation is half-present.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.canonical {
            return Err(InquiryError::IntegrityMismatch {
                field: "freeze.canonical",
            });
        }
        self.validate_successor()?;
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
/// record binds its verdict to the inquiry profile, the run-bound reference
/// manifest and the State Fence, and states that the result is a non-canonical
/// candidate. The reference firewall holds: no citation, source identity, URL,
/// line range or support relation is minted here through prose.
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
    /// Digest of the run-bound `AllowedReferenceManifest` the claim was audited
    /// against.
    ///
    /// Sourced from the re-proved manifest itself rather than from a
    /// caller-supplied string, so it cannot disagree with the manifest that
    /// produced the verdict.
    pub run_reference_manifest_digest: String,
    /// Run identity the audit was bound to.
    pub run_id: String,
    /// Root context revision the audit was bound to.
    pub root_context_revision: String,
    /// Evidence-set identity.
    pub evidence_set_id: String,
    /// Verdict produced by the existing claim-audit owner.
    pub verdict: ClaimVerdict,
    /// State Fence the audit ran under.
    ///
    /// The run-bound manifest's own fence, and proven equal to the profile's
    /// when the record is bound, so a verdict cannot be filed under a fence that
    /// is neither the run's nor the profile's.
    pub state_fence: StateFence,
    /// The exact final wording released for this claim when the audit ran.
    ///
    /// This is the post-audit-material-edit arm's subject. The verdict says what
    /// was true of a STATEMENT; nothing on this record said which statement, so a
    /// release consumer could reword the claim after the audit, publish the
    /// verdict beside it, and the audit would still verify. I21.8 requires the
    /// final delivered or rendered wording to be reviewed as well as the
    /// intermediate structures, and the only way to review the final wording is
    /// for the record to hold it.
    ///
    /// It is inside [`Self::digest`] and re-compared by
    /// [`Self::validate_released_wording`], so an edit between the audit and the
    /// release is refused rather than inherited.
    pub released_statement: String,
    /// Always false: a claim audit never becomes canonical state by itself.
    pub canonical: bool,
    /// Digest over the binding shape.
    pub digest: String,
}

impl ClaimAuditRecord {
    /// Binds one claim verdict to the inquiry and run it was produced under.
    ///
    /// `run_manifest` is the re-proved [`AllowedReferenceManifest`] itself, not a
    /// digest of one. It used to take a bare `manifest_digest: &str` that was
    /// only shape-checked as 64 lowercase hex and never compared with any
    /// manifest, so the binding proved nothing: a record could name a digest that
    /// no manifest ever produced, and the field it filled had no `run_id`, no
    /// `root_context_revision` and no fence of its own. I21.7 requires an audit
    /// job to be bound to the exact run and State Fence, so the manifest is now
    /// an input and the fence is taken from it.
    ///
    /// The profile's own State Fence must equal the manifest's. A profile
    /// resolved under one fence and a manifest frozen under another describe two
    /// different runs, and binding them together would produce a record whose two
    /// halves disagree about which run it describes.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank identity, and
    /// [`InquiryError::IntegrityMismatch`] when the run-bound manifest does not
    /// re-prove its own digest or the profile's State Fence is not the manifest's.
    pub fn bind(
        inquiry_id: &str,
        profile: &InquiryProtocolProfile,
        run_manifest: &AllowedReferenceManifest,
        evidence_set_id: &str,
        released_statement: &str,
        verdict: ClaimVerdict,
    ) -> Result<Self, InquiryError> {
        require_text(inquiry_id, "claim_audit.inquiry_id")?;
        require_text(evidence_set_id, "claim_audit.evidence_set_id")?;
        // The released wording is required, not defaulted. A record with an empty
        // statement would be one whose post-audit-edit check could never fire,
        // which is the same "a constructor call proves nothing" defect the pair
        // of custody fields on `ResearchQueryRequest` exists to prevent.
        require_text(released_statement, "claim_audit.released_statement")?;
        // Re-prove the manifest rather than trusting a digest a caller could have
        // typed: `validate` recomputes the digest over every field that can change
        // what a citation is allowed to say, so a widened or edited manifest is
        // refused here instead of being filed under its own stale identity.
        run_manifest
            .validate()
            .map_err(|_| InquiryError::IntegrityMismatch {
                field: "claim_audit.run_reference_manifest",
            })?;
        if profile.state_fence != run_manifest.state_fence {
            return Err(InquiryError::IntegrityMismatch {
                field: "claim_audit.state_fence",
            });
        }
        let mut record = Self {
            claim_id: verdict.claim_id.clone(),
            inquiry_id: inquiry_id.to_owned(),
            profile_id_and_revision: profile.profile_id_and_revision(),
            profile_digest: profile.integrity_digest.clone(),
            run_reference_manifest_digest: run_manifest.digest.clone(),
            run_id: run_manifest.run_id.clone(),
            root_context_revision: run_manifest.root_context_revision.clone(),
            evidence_set_id: evidence_set_id.to_owned(),
            verdict,
            state_fence: run_manifest.state_fence.clone(),
            released_statement: released_statement.to_owned(),
            canonical: false,
            digest: String::new(),
        };
        record.digest = record.compute_digest();
        Ok(record)
    }

    /// Refuses a released wording that is not the wording this audit judged.
    ///
    /// This is the gate a release consumer calls with the text it is about to
    /// deliver, and it is the fourth of the four acceptance cases enforced in
    /// product code rather than in a test: a claim whose material sentence was
    /// added, edited, given a new numeric value, widened in causal scope,
    /// translated, or assembled from two quotations after the audit ran is
    /// refused here, because the audit's verdict is about a different statement.
    ///
    /// A heading-only or formatting change is NOT accepted by silence either: it
    /// must be presented as an explicit nonsemantic mapping, which is what
    /// [`Self::is_nonsemantic_restyle_of`] answers. There is deliberately no
    /// default-true path, so "the text differs" always requires a caller to say
    /// why that difference does not change the meaning.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::ReleaseGateRefused`] naming `released_statement`
    /// when the delivered text is not the audited wording.
    pub fn validate_released_wording(&self, delivered: &str) -> Result<(), InquiryError> {
        if delivered == self.released_statement {
            return Ok(());
        }
        Err(InquiryError::ReleaseGateRefused {
            gate: "released_statement",
            detail: format!(
                "the audit judged statement digest {} but the delivered text differs and no \
                 explicit nonsemantic mapping was offered",
                self.released_statement
            ),
        })
    }

    /// Whether `delivered` is the audited wording with formatting-only changes.
    ///
    /// An explicit nonsemantic mapping is the ONLY way I21.8 permits evidence to
    /// be reused across a wording change, so the question is narrow and decided
    /// mechanically: the two texts must differ in nothing but whitespace, and
    /// the audit must have judged a statement at all. A change to any non-space
    /// byte, including a numeric value, a punctuation mark, a capitalisation and a
    /// word, is not a restyle and is not accepted.
    ///
    /// This is deliberately the conservative direction. A mapping that dropped a
    /// qualifier would still be accepted here only if it dropped whitespace, so
    /// the function cannot launder a semantic edit; it can only fail to admit a
    /// legitimate restyle, which a caller resolves by re-running the audit.
    #[must_use]
    pub fn is_nonsemantic_restyle_of(&self, delivered: &str) -> bool {
        !self.released_statement.trim().is_empty()
            && split_whitespace(&self.released_statement) == split_whitespace(delivered)
    }

    fn compute_digest(&self) -> String {
        // `v1` -> `v2`: the preimage now names the run identity and the root
        // context revision, and takes its State Fence from the run-bound manifest
        // rather than from the profile. A `v1` record could not be re-derived from
        // its own bytes under one name, so the domain says so rather than letting
        // one name cover two field sets.
        //
        // `v2` -> `v3` for #1765: the preimage now names the released final
        // wording and every measured excerpt check. A `v2` record bound a verdict
        // that said a statement had been audited without saying which statement,
        // and carried no occurrence measurement at all; a record of that shape
        // re-presented as one that had reviewed the delivered text, and it could
        // not be distinguished by any reader of this digest.
        let mut preimage = String::from("claim-audit-record/v3;");
        push_field(&mut preimage, "claim_id", &self.claim_id);
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(
            &mut preimage,
            "profile_id_and_revision",
            &self.profile_id_and_revision,
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_field(
            &mut preimage,
            "run_reference_manifest_digest",
            &self.run_reference_manifest_digest,
        );
        push_field(&mut preimage, "run_id", &self.run_id);
        push_field(
            &mut preimage,
            "root_context_revision",
            &self.root_context_revision,
        );
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_field(
            &mut preimage,
            "verdict_outcome",
            self.verdict.outcome.wire_name(),
        );
        // I21.7: the audit's own run binding is inside this record's identity, not
        // only inside the manifest's, so a binding that covers this record cannot
        // be re-pointed at another run's verdict.
        for (tag, value) in [
            (
                "verdict_run_reference_manifest_digest",
                self.verdict.run_reference_manifest_digest.as_str(),
            ),
            ("verdict_run_id", self.verdict.run_id.as_str()),
            (
                "verdict_root_context_revision",
                self.verdict.root_context_revision.as_str(),
            ),
        ] {
            push_field(&mut preimage, tag, value);
        }
        push_field(
            &mut preimage,
            "state_fence",
            &fence_preimage(&self.state_fence),
        );
        // The released wording is inside this record's identity, not only
        // compared at release time. Without it here, an audit record and a
        // reworded claim could be bound together again by recomputing nothing:
        // the digest would be identical and the post-audit edit would be
        // invisible to every consumer that re-proves the record.
        push_field(
            &mut preimage,
            "released_statement",
            &self.released_statement,
        );
        // The measured excerpt checks travel with the record for the same
        // reason. `verdict.excerpt_checks` says the occurrence and context were
        // verified against a retained revision; without its own line here the
        // checks could be dropped and the requirement re-rendered as though no
        // check had been made, and the record would still rehash.
        for check in &self.verdict.excerpt_checks {
            push_field(
                &mut preimage,
                "excerpt_check",
                &crate::admitted_excerpt::check_line(check),
            );
        }
        push_count(
            &mut preimage,
            "excerpt_checks",
            self.verdict.excerpt_checks.len(),
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

    /// Re-proves this binding's own digest and its run binding.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one, when the record claims canonical state, or
    /// when its verdict names a different run than the record does.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.canonical
            || self.compute_digest() != self.digest
            || self.verdict.run_reference_manifest_digest != self.run_reference_manifest_digest
            || self.verdict.run_id != self.run_id
            || self.verdict.root_context_revision != self.root_context_revision
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "claim_audit.digest",
            });
        }
        // The released wording is a required, non-empty, digest-bound field. A
        // record that lost it between binding and publication would otherwise
        // pass the digest check under a preimage that hashed the empty string,
        // and every post-audit-edit comparison would compare against nothing.
        require_text(&self.released_statement, "claim_audit.released_statement")?;
        // Each excerpt check is re-proved against its own excerpt identity, so a
        // check whose verdict was edited after the audit stopped agreeing with
        // the excerpt it claims to have measured. The retained BYTES are not
        // re-read here: this crate does not hold them, and pretending otherwise
        // is exactly the "a digest of bytes nobody holds" substitution W2
        // refuses. What is re-proved is what this record asserts about the check.
        for check in &self.verdict.excerpt_checks {
            check
                .excerpt
                .verify_integrity()
                .map_err(|_| InquiryError::IntegrityMismatch {
                    field: "claim_audit.excerpt_check",
                })?;
        }
        Ok(())
    }
}

/// Splits a text into its non-whitespace words, for the nonsemantic-restyle
/// comparison in [`ClaimAuditRecord::is_nonsemantic_restyle_of`].
///
/// Normalising the WHITESPACE RUNS rather than the tokens is deliberate: a run
/// of spaces, a tab and a newline are one boundary in rendered text, and a
/// reformatting change turns one into the other constantly. Collapsing the run to
/// a single space is what makes a restyle recognisable, and it is why the
/// comparison is anchored on the raw text rather than on a token stream: two
/// texts that differ in a non-space byte produce different words here.
fn split_whitespace(text: &str) -> Vec<&str> {
    text.split_whitespace().collect()
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
    /// Evidence freeze of the accepted evidence revision this disposition was
    /// taken over (I21.8).
    ///
    /// The freeze is carried whole, not as a digest beside it, because the
    /// terminal claim is exactly the claim the freeze is supposed to bound: a
    /// record that named the freeze's identity without its included set, its
    /// exclusions, its open contradictions and its open debts could not show
    /// that the evidence it rests on was the evidence that was frozen.
    pub freeze: EvidenceFreeze,
    /// Claim audit bound to this terminal record, when one exists (I21.8).
    ///
    /// `None` means this run released no material claim at all: the producer
    /// derives one audited claim per admitted, citable source handle, and a run
    /// with no admitted material releases none. `None` is therefore never a
    /// stand-in for a skipped audit — a run that cannot audit its material claims
    /// produces no record at all, because the binding is attempted with
    /// `?` rather than defaulted. Where a run did release material claims this
    /// is the first of them, and
    /// [`Self::validate_carried_artifacts`](Self) — with the full trail and the
    /// A3 coverage map carried beside it on [`InquiryGovernance`] — proves the
    /// terminal audit is one of the audited claims rather than a foreign record.
    pub claim_audit: Option<ClaimAuditRecord>,
    /// Unsupported-precision residue the evidence set preserves (I21.7).
    ///
    /// The typed items, not a count: each one names the asserted coordinate, the
    /// highest supported precision, the basis, the false-precision risk and the
    /// probe or narrower wording required, so a reader learns what the claim may
    /// not say rather than only that something was imprecise.
    pub unsupported_precision: Vec<UnsupportedPrecisionItem>,
    /// State Fence the disposition was taken under.
    pub state_fence: StateFence,
    /// Identity of the owner-issued absence record this closure rests on
    /// (#2893 item 12).
    ///
    /// `None` for every non-closing disposition, and also for a closing one whose
    /// record could not be re-proved against this run's fence and frozen scope
    /// snapshot — in which case the disposition is `IncompleteCoverage` and this
    /// is `None` too. It is the canonical digest of the record computed by
    /// recomputation, never a value a caller supplied, so a reader can compare it
    /// against the coverage receipt's own retained `absence_evidence_digest` and
    /// see whether the same record closed the run.
    pub absence_closure_evidence_digest: Option<String>,
    /// Always true: a terminal inquiry record stays candidate-only.
    pub candidate_only: bool,
    /// Always false: closing a task stays in the existing Governor path.
    pub canonical_write_authorized: bool,
    /// Digest over the record shape.
    pub digest: String,
}

impl InquiryTerminalRecord {
    fn validate_preservation(
        disposition: CompletionDisposition,
        explicit_unknown: Option<&PreservedUnknown>,
        narrower_claim: Option<&str>,
        next_probe: Option<&PreservedNextProbe>,
    ) -> Result<(), InquiryError> {
        if let Some(unknown) = explicit_unknown {
            require_text(&unknown.subject, "terminal.explicit_unknown.subject")?;
            require_text(&unknown.detail, "terminal.explicit_unknown.detail")?;
        }
        if let Some(claim) = narrower_claim {
            require_text(claim, "terminal.narrower_claim")?;
        }
        if let Some(probe) = next_probe {
            require_text(&probe.required_probe, "terminal.next_probe.required_probe")?;
            for obligation_ref in &probe.obligation_refs {
                require_text(obligation_ref, "terminal.next_probe.obligation_refs")?;
            }
        }
        if !disposition.may_close_inquiry()
            && explicit_unknown.is_none()
            && narrower_claim.is_none()
            && next_probe.is_none()
        {
            return Err(InquiryError::PreservationRequired {
                field: "terminal.disposition",
            });
        }
        Ok(())
    }

    /// Binds the terminal disposition to the profile, portfolio, manifest and
    /// State Fence.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::PreservationRequired`] when a non-closing
    /// disposition carries no explicit unknown, no narrower claim and no next
    /// probe, [`InquiryError::ClosureWithoutCompleteScope`] when a closing
    /// disposition rests on a denominator that is not a complete scope,
    /// [`InquiryError::ClosureWithoutSuccessfulAcquisition`] when a closing
    /// disposition follows an unsuccessful acquisition, and a field error for
    /// blank identities or malformed digests. [`InquiryError::Portfolio`] is
    /// returned when a provided preservation field is blank or control-bearing.
    /// The carried evidence freeze, claim audit and unsupported-precision residue
    /// are re-proved and bound to this record here, and
    /// [`InquiryError::IntegrityMismatch`] is returned when one of them describes
    /// a different inquiry, profile revision digest, manifest or State Fence than
    /// the record it is being carried on.
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
        freeze: EvidenceFreeze,
        claim_audit: Option<ClaimAuditRecord>,
        unsupported_precision: Vec<UnsupportedPrecisionItem>,
        absence_closure_evidence_digest: Option<String>,
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
        if let Some(digest) = &absence_closure_evidence_digest {
            require_digest(digest, "terminal.absence_closure_evidence_digest")?;
        }
        // #2893 item 12: a scoped-negative closure is the claim that needs the
        // owner-issued record behind it, so a record that CLOSES over
        // `NO_MATCH_IN_COMPLETE_SCOPE` without naming that record is refused
        // here rather than published and explained in a doc comment. The
        // converse direction is not imposed: a positive closure is the other
        // owner's decision (the claim-audit release gate) and does not rest on
        // absence evidence, so it is not required to carry this field.
        if disposition == CompletionDisposition::NoMatchInCompleteScope
            && absence_closure_evidence_digest.is_none()
        {
            return Err(InquiryError::UnknownHandle {
                field: "terminal.absence_closure_evidence_digest",
            });
        }
        let may_close = disposition.may_close_inquiry();
        if may_close && !acquisition_outcome.is_successful() {
            return Err(InquiryError::ClosureWithoutSuccessfulAcquisition {
                field: "terminal.acquisition_outcome",
            });
        }
        if may_close && !denominator_kind.supports_scoped_absence() {
            return Err(InquiryError::ClosureWithoutCompleteScope {
                field: "terminal.denominator_kind",
            });
        }
        Self::validate_preservation(
            disposition,
            explicit_unknown.as_ref(),
            narrower_claim.as_deref(),
            next_probe.as_ref(),
        )?;
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
            freeze,
            claim_audit,
            unsupported_precision,
            state_fence: profile.state_fence.clone(),
            absence_closure_evidence_digest,
            candidate_only: true,
            canonical_write_authorized: false,
            digest: String::new(),
        };
        // The same method `validate_integrity` runs, so a record that is built
        // can never differ from a record that is read back: the three carried
        // artifacts are re-proved and bound here, before the digest is taken.
        record.validate_carried_artifacts()?;
        record.digest = record.compute_digest();
        Ok(record)
    }

    /// Re-proves the evidence freeze, claim audit and unsupported-precision
    /// residue this record carries, and binds each of them to this record's own
    /// identity.
    ///
    /// The three checks are the whole point of carrying the artifacts, so they
    /// are stated once and run from both `bind` and `validate_integrity`:
    ///
    /// - the freeze must re-prove its own digest and must name the same inquiry,
    ///   profile revision digest, portfolio, manifest, coverage receipt, evidence
    ///   set and State Fence this record does. A freeze that disagrees is not a
    ///   stricter version of this one, it is a freeze of different evidence, so
    ///   the terminal claim it would appear to bound is not the claim that was
    ///   frozen;
    /// - a claim audit, when present, must re-prove its own digest and its own
    ///   run binding and must name the same inquiry, profile revision digest, run
    ///   reference manifest, evidence set and State Fence. An audit for another
    ///   run is a real record of a real audit and is simply not this one's;
    /// - every unsupported-precision item must name its asserted coordinate, its
    ///   highest supported precision, its basis, its risk and its required probe
    ///   as non-blank, non-control-bearing text. A residue item with a hole in it
    ///   cannot be checked, so it is refused here instead of being carried as a
    ///   shape a reader would have to trust.
    ///
    /// Absence is not a failure: an empty residue is a measurement, and a missing
    /// claim audit is the state this path is honestly in.
    fn validate_carried_artifacts(&self) -> Result<(), InquiryError> {
        self.freeze.validate_integrity()?;
        if self.freeze.inquiry_id != self.inquiry_id
            || self.freeze.profile_digest != self.profile_digest
            || self.freeze.portfolio_digest != self.portfolio_digest
            || self.freeze.manifest_digest != self.manifest_digest
            || self.freeze.coverage_receipt_digest != self.coverage_receipt_digest
            || self.freeze.evidence_set_id != self.evidence_set_id
            || self.freeze.state_fence != self.state_fence
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "terminal.freeze_binding",
            });
        }
        if let Some(audit) = &self.claim_audit {
            audit.validate_integrity()?;
            if audit.inquiry_id != self.inquiry_id
                || audit.profile_digest != self.profile_digest
                || audit.run_reference_manifest_digest != self.manifest_digest
                || audit.evidence_set_id != self.evidence_set_id
                || audit.state_fence != self.state_fence
            {
                return Err(InquiryError::IntegrityMismatch {
                    field: "terminal.claim_audit_binding",
                });
            }
        }
        for item in &self.unsupported_precision {
            require_text(&item.asserted, "terminal.unsupported_precision.asserted")?;
            require_text(
                &item.highest_supported,
                "terminal.unsupported_precision.highest_supported",
            )?;
            require_text(&item.basis, "terminal.unsupported_precision.basis")?;
            require_text(&item.risk, "terminal.unsupported_precision.risk")?;
            require_text(
                &item.required_probe,
                "terminal.unsupported_precision.required_probe",
            )?;
        }
        // #2893 item 12, readback side: the same rule `bind` enforces, re-proved
        // from this record's own bytes rather than trusted from a field. A
        // record read back from storage that closes over a scoped negative
        // without naming the record behind it is the same contradiction the
        // constructor refuses, and `validate_integrity` is the only method a
        // reader is required to run.
        if let Some(digest) = &self.absence_closure_evidence_digest {
            require_digest(digest, "terminal.absence_closure_evidence_digest")?;
        }
        if self.disposition == CompletionDisposition::NoMatchInCompleteScope
            && self.absence_closure_evidence_digest.is_none()
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "terminal.absence_closure_evidence_digest",
            });
        }
        Ok(())
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
        // `v1` -> `v2` for #1762 W8. The preimage field set changed: the evidence
        // freeze, the claim audit and the unsupported-precision residue are now
        // carried here and their content is inside this preimage, and one name
        // must not cover two field sets. This is the rule the `coverage-receipt`
        // preimage comment states for itself: a domain names the shape of the
        // record being hashed, so a shape change bumps it, while a changed *value*
        // in a field that was already declared does not (which is why
        // `evidence-freeze/v2` above is deliberately not bumped by #1762: at
        // that time its own field set was unchanged and only the values it
        // transitively binds moved. #1765 later grew that field set (the State
        // Fence and the three successor-relation fields), which is the bump that
        // took the freeze to `v2`.
        // `v2` -> `v3` by #2893 for the same reason as the earlier bumps above:
        // the preimage field set GREW. The terminal record now names the
        // identity of the owner-issued absence record a scoped-negative closure
        // rests on, and under `v2` two records with the same disposition and
        // different evidence behind it hashed identically. The bound value is
        // `none` for every non-closing and every refused-closure record, so this
        // is a shape change and not a value change under one name.
        let mut preimage = String::from("inquiry-terminal-record/v3;");
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
        // The record identity behind a scoped-negative closure. Bound explicitly
        // so a terminal record cannot be re-pointed at a different owner-issued
        // evaluation while keeping its disposition and every other field.
        push_field(
            &mut preimage,
            "absence_closure_evidence_digest",
            self.absence_closure_evidence_digest
                .as_deref()
                .unwrap_or("none"),
        );
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
        self.push_carried_artifacts(&mut preimage);
        freeze(&preimage)
    }

    /// Pushes the three carried artifacts of #1762 W8 into the terminal
    /// record's digest preimage.
    ///
    /// The freeze is bound by its own re-proved digest, which covers every
    /// field of it, and the residue by its typed items rather than by a count,
    /// so a binding that covers this digest cannot be re-pointed at a
    /// different frozen evidence set, or at a different asserted coordinate,
    /// by editing only the rendered narrower claim. The claim audit is pushed
    /// by its own digest and verdict, or as the explicit literal `none` when
    /// no audited claim exists — an absent audit is a recorded fact, never an
    /// omitted field that would let a digest cover two different records.
    fn push_carried_artifacts(&self, preimage: &mut String) {
        push_field(preimage, "evidence_freeze_digest", &self.freeze.digest);
        push_field(preimage, "evidence_freeze_id", &self.freeze.freeze_id);
        // The successor relation is inside the terminal identity: a disposition
        // taken over a reopened freeze describes a different evidence revision
        // than one taken over the freeze it superseded, and a terminal digest
        // that could not tell them apart would let a reopen restate the prior
        // brief's answer under a new identity.
        push_field(
            preimage,
            "evidence_freeze_supersedes",
            self.freeze.supersedes.as_deref().unwrap_or("none"),
        );
        push_field(
            preimage,
            "evidence_freeze_supersede_reason",
            self.freeze.supersede_reason.as_deref().unwrap_or("none"),
        );
        push_field(
            preimage,
            "evidence_freeze_expected_revision",
            self.freeze.expected_revision.as_deref().unwrap_or("none"),
        );
        if let Some(audit) = &self.claim_audit {
            push_field(preimage, "claim_audit_digest", &audit.digest);
            push_field(preimage, "claim_audit_claim_id", &audit.claim_id);
            push_field(
                preimage,
                "claim_audit_outcome",
                audit.verdict.outcome.wire_name(),
            );
        } else {
            push_field(preimage, "claim_audit", "none");
        }
        push_count(
            preimage,
            "unsupported_precision",
            self.unsupported_precision.len(),
        );
        for item in &self.unsupported_precision {
            push_field(preimage, "unsupported_precision_asserted", &item.asserted);
            push_field(
                preimage,
                "unsupported_precision_highest_supported",
                &item.highest_supported,
            );
            push_field(preimage, "unsupported_precision_basis", &item.basis);
            push_field(preimage, "unsupported_precision_risk", &item.risk);
            push_field(
                preimage,
                "unsupported_precision_required_probe",
                &item.required_probe,
            );
        }
    }

    /// Re-proves this record's own digest, the debt restriction it carries and
    /// the evidence freeze, claim audit and unsupported-precision residue it
    /// carries beside it.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one, and
    /// [`InquiryError::PreservationRequired`] when a non-closing disposition
    /// carries no valid preserved field, or [`InquiryError::Portfolio`] when a
    /// provided preservation field is blank or control-bearing; it also returns
    /// [`InquiryError::DebtRestrictedDisposition`] when a disposition coexists
    /// with an open debt that refuses it, or
    /// [`InquiryError::ClosureWithoutSuccessfulAcquisition`] when a closing
    /// disposition follows an unsuccessful acquisition. The carried artifacts are
    /// checked by `validate_carried_artifacts`, which `bind` also runs, so a
    /// stored-but-never-re-proved field cannot pass here.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        self.validate_carried_artifacts()?;
        self.debt_restriction.validate_integrity()?;
        if self.debt_restriction.refuses(self.disposition) {
            return Err(InquiryError::DebtRestrictedDisposition {
                field: "terminal.disposition",
            });
        }
        if self.may_close() && !self.acquisition_succeeded() {
            return Err(InquiryError::ClosureWithoutSuccessfulAcquisition {
                field: "terminal.acquisition_outcome",
            });
        }
        Self::validate_preservation(
            self.disposition,
            self.explicit_unknown.as_ref(),
            self.narrower_claim.as_deref(),
            self.next_probe.as_ref(),
        )?;
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
/// The set above is the set of reference *identities* that reach this boundary,
/// and it is not the same as the set of references that reach it. Since the
/// demotion half was completed,
/// [`crate::inquiry_governance::reference_firewall`] also reads every reference
/// the *record* built from each candidate presents — its `locator`, its
/// `receipt_handle`, each of its `cites` edges and each of its
/// `evidence_spans[].anchor` — and retains each unadmitted one under the same
/// kinds. On the live path the record's locator is `"<route>#<receipt_handle>"`,
/// where the route is a module generation and an executable digest and the
/// receipt handle is a transport digest. The locator carries a `:` and a scheme
/// token, so the shared classifier reads it as a coordinate and the two coordinate
/// surfaces keep their admitted-by-classification rule.
///
/// The receipt handle is the live record reference that is *not* a coordinate:
/// the transport digest has no `:` and no scheme, so it classifies as an opaque
/// handle, and it names a different artifact rather than a position inside this
/// source. It is therefore judged against the manifest's handle lists like any
/// other identity, which means a run whose manifest does not list that digest now
/// produces an `ArtifactHandle` diagnostic on the `receipt_handle` surface and
/// refuses the record. It did neither before: the receipt handle sat on the
/// coordinate arm, where an opaque spelling was admitted unconditionally, so the
/// reference was neither refused nor retained and a manifest admitting no
/// artifact handle at all still yielded citable records. Which records present
/// which references is the composition root's projection, not this boundary's;
/// what this boundary decides is that such a reference is refused for evidentiary
/// use *and* retained, rather than being neither.
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
/// [`crate::source_admissibility::SourceAdmissibilityRecord::evaluate`].
///
/// # What a line range is, and is not
///
/// `LineSpan` names a *reference the run observed*, not an anchor decision. How
/// coarse an admitted anchor may be is the manifest's `allowed_anchor_precision`
/// and belongs to [`EvidenceSetPrecision::evaluate`]; that check answers "may a
/// citation anchor this finely?", while this kind answers "was a line range
/// minted in prose?". They are separate obligations and neither substitutes for
/// the other: a line range can be perfectly well formed and still be outside the
/// manifest's admitted anchor precision, and it is refused here for the list
/// reason rather than for the precision one.
///
/// Which candidates the run actually produces is the composition root's
/// projection, not this boundary's: `retained_provider_material` in
/// `bins/eliot-mod-research` mints one `provider-artifact:<sha256>` handle from
/// the retained stdout digest and never decodes the body, so neither a URL nor a
/// line range reaches this classification from the current live path. Both arms
/// are reachable for a candidate whose handle carries that shape, which is what a
/// caller-influenced handle means; enumerating the references inside provider
/// output is a separate and still-open step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnadmittedReferenceKind {
    /// An absolute locator URL, named for what the spelling presents itself as.
    ///
    /// It says nothing about `url_handles`: `reference_firewall` never calls
    /// `admits_url`, so it cannot know whether the manifest lists this value
    /// there. A value can be listed in `url_handles` and still be unadmitted as a
    /// handle, and this kind is still the right one. The lever is in the reason.
    LocatorUrl,
    /// An opaque handle the manifest does not list, presented as a candidate
    /// handle or on an identity surface a record presents.
    ///
    /// The record surfaces are the citation edge and the receipt handle, both of
    /// which the manifest must list, so this kind is the right one for either. The
    /// receipt handle is the live case worth naming: the composition root writes a
    /// bare transport digest into `candidate.receipt_handle`, a spelling with no
    /// `:` and no scheme, so it classifies as an opaque handle and is reported
    /// here when the manifest does not list it.
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
    /// A line anchor or line range: a handle the shared classifier reads as an
    /// opaque handle, followed by `:<line>` or an inclusive `:<first>-<last>`.
    ///
    /// I21.7 lists a line range beside citation, URL, source ID, artifact handle
    /// and support relation as a reference a model cannot mint through prose, so
    /// it is a reference identity here and gets its own kind rather than being
    /// reported as whatever the classifier made of the handle part. It is not an
    /// *anchor* decision either: how coarse an admitted anchor may be belongs to
    /// the manifest's admitted anchor precision in
    /// [`EvidenceSetPrecision::evaluate`], and this kind only says that the
    /// observed spelling is a line range.
    ///
    /// Recognition is fail-closed and refuses every spelling it cannot decide:
    /// see [`line_span_shape`], which is the single reader of the grammar.
    LineSpan,
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
            Self::LineSpan => "LINE_SPAN",
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
    /// record. The encoding is [`crate::evidence_portfolio::fence_preimage`],
    /// the crate's single canonical one: `push_field` per fence component, tagged
    /// with the `StateFence` field names that `canonical_json_bytes` gives the
    /// same value inside the sealed `AllowedReferenceManifest`, with an absent
    /// optional revision spelled `none` under its own tag, as everywhere else in
    /// these preimages. It used to be spelled out inline here on the stated
    /// ground that no sibling record in this crate pushed a fence; the audit
    /// reference binding now does, so the encoding moved to the one owner rather
    /// than being copied, and two spellings of a fence preimage would be two
    /// identities for the same fence.
    ///
    /// `v1` -> `v2` with that move. The fence's five components were five
    /// top-level preimage fields and are now one `state_fence` field, so the
    /// bytes changed under an unchanged name — which is the same defect the
    /// `source-record/v2` and `frozen-inquiry/v3` bumps exist to prevent. A
    /// diagnostic sealed under the old spelling cannot re-verify under this one
    /// and needs re-sealing, not a grandfathered admission.
    fn compute_digest(&self) -> String {
        let mut preimage = String::from("unadmitted-reference/v2;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_field(&mut preimage, "reference", &self.reference);
        push_field(&mut preimage, "kind", self.kind.wire_name());
        push_field(&mut preimage, "reason", &self.reason);
        push_field(
            &mut preimage,
            "state_fence",
            &fence_preimage(&self.state_fence),
        );
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
    /// Digest of the evidence freeze this run reopens, when it reopens one.
    ///
    /// I21.8 requires new material, materially changed source content or a
    /// changed protocol to produce an explicit successor freeze that names its
    /// predecessor. The predecessor is named by the digest the run was admitted
    /// under, never rewritten, so the prior freeze and its audit stay addressable.
    /// `None` is a first freeze, which is the honest state for a run admitted
    /// without a predecessor.
    pub predecessor_freeze_digest: Option<String>,
    /// Why this run reopens the predecessor freeze, when it reopens one.
    ///
    /// Required together with [`Self::predecessor_freeze_digest`]: a successor
    /// without a stated cause states no reopen, and `EvidenceFreeze::freeze`
    /// refuses a half-present relation.
    pub reopen_reason: Option<String>,
    /// The retained original bytes of each admitted source revision, keyed by
    /// source handle.
    ///
    /// W2: "Resolve accepted sources through the governed source-admission
    /// owner, retain their exact bytes or immutable accessible artifacts, and
    /// commit the freeze before admitting synthesis. An in-memory clone or hash
    /// of unavailable bytes is insufficient." This field is that retained
    /// original, and it is the reason the excerpt obligation below is decidable
    /// at all: without the actual bytes, the only evidence available about a
    /// quotation is a digest of bytes nobody holds, which cannot distinguish an
    /// exact quote from a fabricated one, a cropped negation from its absence,
    /// or a page quote from a search snippet.
    ///
    /// It is an **immutable artifact reference plus the exact bytes that
    /// artifact resolved to**, handed here by the governed source-admission and
    /// persistence owner. This crate does not store them and does not claim to:
    /// `crates/research/AGENTS.md` states this subtree "has no canonical-store
    /// write authority", so the commit happened elsewhere and this value is the
    /// reference to it, re-proved on every use.
    ///
    /// A handle absent from this map is a real finding rather than a skip: the
    /// source was admitted without its original being retained, and every
    /// excerpt offered from it therefore fails verification with
    /// `NoRetainedRevision`. That is the honest W2 outcome for a run that did
    /// not persist before synthesis, and it is what makes the persistence
    /// observable rather than asserted.
    pub retained_revisions: BTreeMap<String, crate::admitted_excerpt::RetainedSourceRevision>,
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
    /// One bound claim-audit record per material claim this run released.
    ///
    /// This is the per-claim audit trail I21.8 requires and it is produced here
    /// by `claim_audit_for_run`, which runs the existing
    /// [`crate::evidence_portfolio::audit_claim`] over each claim it derives from
    /// admitted material. An empty set is the honest "this run released no
    /// material claim", never a stand-in verdict: a run whose audit could not be
    /// built produces no record at all.
    pub claim_audits: Vec<ClaimAuditRecord>,
    /// The final coverage map over those claims.
    ///
    /// Carried whole rather than as a digest beside it, because A3 is a
    /// completeness question a reader must be able to re-ask: which material
    /// claims the frozen owner admitted, which the run actually audited, and
    /// which are in exactly one of the two. The map's expected roster is derived
    /// independently by [`MaterialClaimRoster::derive`] from the portfolio and
    /// the frozen manifest, so a member cannot disappear from it by being dropped
    /// from the release.
    pub claim_coverage: ClaimCoverageMap,
    /// Material claims the frozen owner admitted that carry no released verdict,
    /// sorted.
    ///
    /// Non-empty is exactly the condition under which
    /// [`crate::evidence_portfolio::require_complete_claim_coverage`] refuses a
    /// complete-audit claim. It is published beside the map so a consumer reads
    /// the specific unaudited claim and not only that coverage is incomplete.
    pub claim_coverage_unaccounted: Vec<String>,
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
    /// The proof that this freeze was **committed through the governed
    /// source-admission owner**, with each admitted source's retained original
    /// bound to it.
    ///
    /// W2: "Persist before synthesis and retain the original … commit the freeze
    /// before admitting synthesis." The ordering is structural rather than
    /// documentary: every request in [`Self::source_admission_requests`] carries
    /// this freeze's identity and digest inside its own `request_digest`, and
    /// [`crate::synthesis_input::CommittedFreeze::commit`] refuses any request
    /// that does not. So a record carrying this field published a freeze that was
    /// already committed when the requests were built, and a record without one
    /// cannot be produced on this path at all.
    pub committed_freeze: crate::synthesis_input::CommittedFreeze,
    /// The retained original of every source this record committed an admission
    /// for, keyed by source handle.
    ///
    /// The same commitments [`Self::source_admission_requests`] already name,
    /// carried whole rather than as a digest beside them, because each
    /// [`FreezeCommitment`](crate::source_admissibility::FreezeCommitment) holds
    /// the *claim* that an original was persisted — its artifact reference and two
    /// digests — and not the bytes, so a record carrying only the requests would
    /// let a reader check that some retention was asserted and never that any
    /// bytes were retained, much less that they reproduce the admitted
    /// `content_digest` they are filed under. Carrying the revisions is what makes
    /// the retained originals on this record re-proveable by a reader:
    /// `validate_source_admission_requests` re-runs each revision's own
    /// `verify_integrity` and compares it against the commitment its request
    /// publishes, so a `retained_revisions` entry swapped for a different revision
    /// of the same source is refused.
    ///
    /// It is populated from [`InquiryObservation::retained_revisions`] **only for
    /// the handles this record actually committed** — the same eligible-and-retained
    /// filter [`crate::synthesis_input::CommittedFreeze::commit`] builds its own
    /// members from — so the map cannot hold a revision whose admission was never
    /// committed, and every entry has a request beside it on this record. The
    /// owner is unchanged: the bytes were committed by the governed
    /// source-admission/persistence owner, this crate has no canonical-store write
    /// authority (`crates/research/AGENTS.md`), and this is the reference to that
    /// commit rather than a second store of it. An original that was never
    /// retained therefore produces no entry and no request, and the synthesis pack
    /// reports it as a published omission with
    /// [`crate::synthesis_input::PackLimitation::NoRetainedOriginal`].
    pub retained_revisions: BTreeMap<String, crate::admitted_excerpt::RetainedSourceRevision>,
    /// The synthesis-input pack resolved from that committed freeze.
    ///
    /// W3: "Build the actual synthesis pack from that freeze. Resolve only its
    /// admitted included members under the current disclosure and reference
    /// manifest." Carried whole rather than as a digest, because the omissions
    /// are the point: a reader needs to see which freeze members did not resolve
    /// and why, which is the explicit limited/blocked result I21.8 item 3
    /// requires rather than a stale authorization or a silent omission.
    pub synthesis_input: crate::synthesis_input::SynthesisInputPack,
    /// Registered research debts.
    pub research_debts: Vec<ResearchDebt>,
    /// Lane class the lane discipline decided for this run.
    ///
    /// I21.2 keeps grade and status orthogonal, so the class is the only thing
    /// that separates an exploratory finding from a confirmatory claim. It is
    /// produced by running the [`InquiryLaneDiscipline`] over the frozen evidence
    /// of this very record on the live path, so a reader learns the class from
    /// the discipline that authorised it rather than from the profile's declared
    /// lane alone.
    pub lane_discipline: LaneDisciplineOutcome,
    /// Terminal typed inquiry disposition.
    pub terminal: InquiryTerminalRecord,
    /// The run-bound reference allowlist, re-proved and carried whole.
    ///
    /// Carried as the manifest itself, not only as the digest
    /// `profile.reference_manifest_digest` publishes, because the published
    /// digest is a claim while the manifest is the thing a reader needs in order
    /// to **check** that claim. With only the digest on the record, the
    /// `certified=` figure has nothing to re-derive the presented certificate
    /// from and can only report the recorded status; with the manifest carried,
    /// the same figure is re-derived from the run's own admission predicate and
    /// an independent set of admitted records.
    ///
    /// I21.7: this is the allowlist, so a reference outside it is unsupported
    /// text and can never become a citable source. It is re-proved here against
    /// its own content through [`AllowedReferenceManifest::validate`] and bound
    /// to the profile that published its digest, so a widened manifest cannot sit
    /// beside a profile resolved under the narrower one.
    pub run_reference_manifest: AllowedReferenceManifest,
    /// Governor-facing profile admission request.
    pub profile_admission_request: GovernorInquiryAdmissionRequest,
    /// Governor-facing source transition requests.
    ///
    /// The Researcher half of the two-record pair, one request per
    /// admissibility decision, each committed to its own bytes. There is
    /// deliberately no owner receipt field beside them: the
    /// Governor/Kernel/Store commit receipt is the owner's, this domain has no
    /// named transition to submit to, and inventing a placeholder for it would
    /// be a false proof claim under A0.3.
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
        let resolved = resolve_profile(&observation)?;
        // I21.3 revision, on the live path and before anything binds the profile
        // digest. The first revision is resolved from the requested source-class
        // list alone; the revision is decided from what the evidence set actually
        // covers, so it runs between resolution and source assessment, and before
        // the coverage receipt, the obligations, the freeze, the claim audit and
        // the terminal record — every one of which binds `profile.integrity_digest`
        // through the admissibility records.
        //
        // It is deliberately before `assess_sources`, not after: a
        // `SourceAdmissibilityRecord` freezes `profile_digest`
        // (`source_admissibility.rs:384`), and `SourcePortfolio::assemble`
        // refuses any record whose digest is not the profile it assembles against
        // (`portfolio.record_binding`). A second, independent check agrees on the
        // same ordering: `SourceAdmissibilityRecord::is_admitted_to` also compares
        // `profile_digest` against `profile.integrity_digest`
        // (`source_admissibility.rs:413`), and a mismatch there is a silent skip
        // rather than an error, so a revision taken after assessment would also
        // leave the portfolio's `primary_sources` empty with the admission
        // decision swallowed. Revising after assessment would therefore
        // leave the record holding admissibility decisions about a superseded
        // revision, and the re-assembly that a later revision needs is exactly
        // what that refusal forbids. Deciding from the observed coverage instead
        // is what keeps one profile revision governing one whole record.
        let profile = revise_profile(&observation, &resolved)?;
        let admissibility = assess_sources(&observation, &profile)?;
        // I21.7 demotion, still before any promotion: `assess_sources` decides
        // eligibility and nothing else — it does not assemble the portfolio, the
        // coverage account or the evidence freeze, which are the surfaces a
        // reference would have to reach to become an evidence edge, and all three
        // run below. It runs before the firewall rather than after so the firewall
        // can read the *record* each candidate projected into, which is where the
        // locator, receipt handle, citation edges and span anchors live. Reading
        // only `candidate.handle` could not see any of them, so those references
        // were neither refused nor retained before this ordering existed.
        let unadmitted_references = reference_firewall(&observation, &admissibility)?;
        let portfolio =
            SourcePortfolio::assemble(&observation.inquiry_id, &profile, &admissibility)?;
        let account = coverage_account(&observation, &admissibility)?;
        let degradation = degradation(&observation, &account);
        // The absence-evidence seam is presented empty here, and that is the
        // honest state rather than a placeholder: this plane carries per-source
        // acquisition custody, not per-member query predicate results, so there
        // is no record here that could be issued from. An owner-issued
        // `NoMatchEvaluation` needs a query/evaluator owner that ran the predicate
        // per member and named the result identities, and no such route exists in
        // this repository — building one is a second query engine, which this
        // issue forbids. Presenting `None` keeps the receipt fail-closed: the
        // verdict stays `Unproven`, the denominator stays `Unknown` and the
        // receipt retains `absence_evidence_digest = None` naming exactly what is
        // missing. #2893 item 11 requires precisely this and forbids fabricating
        // a record to make the receipt look complete. The evaluator route that
        // will fill it is BLOCKED-BY #1762/#1767.
        //
        // #2893 item 12 is the seam this is. The eight commitments a
        // `NoMatchEvaluationIssuer` holds that have no producer on this path at
        // all — predicate identity and bytes, issuer, evaluator and
        // admission-receipt identity, index, source and scope revisions — remain
        // exactly as absent as they were, so an issuer constructed here would
        // still be eight fabricated attestations that `issue_for` then joins and
        // reports as owner-issued. The ninth, the frozen scope digest, was a
        // separate and smaller matter and is now corrected at the call site
        // below: the run-bound *reference allowlist* digest is replaced there by
        // `profile.admitted_denominator_digest`, the Kernel-admitted digest this
        // crate's own `scope_snapshot_matches_admission` check already compares
        // against.
        //
        // What #2893 item 12 asks for is not that this seam be filled — it is
        // that the *final* `NO_MATCH`/closure decision be connected to the
        // evidence record, which is now done at
        // `terminal_disposition`/`terminal_record`: the closure decision reads
        // the receipt's retained absence verdict and the retained
        // `absence_evidence_digest` together, and a closing
        // `NO_MATCH_IN_COMPLETE_SCOPE` is published only over a receipt that
        // carries both. Package-level `Proven` alone can no longer close
        // anything, and the seam stays `None` until the live evaluator
        // composition holds a real issuer, so a run that cannot be backed by an
        // owner-issued record remains `INCOMPLETE_COVERAGE`.
        let absence_evidence: Option<AbsenceEvidence> = None;
        let coverage_receipt = CoverageReceipt::compute(CoverageReceiptParams {
            profile: &profile,
            requested_scope: &observation.scope,
            // #2893: this is the frozen scope/denominator snapshot digest, and
            // the only value on this path that is one. It was the run-bound
            // *reference allowlist* digest, which is a different commitment from a
            // different owner, so the receipt's own
            // `scope_snapshot_matches_admission` comparison could never be true
            // for a run that reached this line — the crate stated in code that
            // the two are expected to be equal and then supplied a value that
            // was not. The Kernel-admitted denominator digest is already read on
            // this path (it is `profile.admitted_denominator_digest`, itself
            // frozen from `observation.denominator_digest`), so this is the
            // ninth, one-value correction the crate documented and deferred; it
            // is now threaded. The reference-allowlist digest remains published
            // in its own right, as `profile.reference_manifest_digest` and
            // `InquiryGovernance::run_reference_manifest`, which is where a
            // reader of an allowlist commitment looks for it.
            frozen_scope_digest: &profile.admitted_denominator_digest,
            account: &account,
            records: &admissibility,
            absence_evidence: absence_evidence.as_ref(),
            routes_used: observation.admissible_routes.clone(),
            provider_degradation: degradation.provider_degradation,
            unknown_coverage: degradation.unknown_coverage,
            budget_limitation: degradation.budget_limitation,
            assessment_time_ms: observation.assessment_time_ms,
        })?;
        let precision = EvidenceSetPrecision::evaluate(
            &observation.inquiry_id,
            observation.reference_manifest.allowed_anchor_precision,
            &admissibility,
        );
        let obligations = open_obligations(&observation, &profile, &account, &admissibility)?;
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
        // The per-claim audit now has a production producer. `claim_audit_for_run`
        // derives the audited claims from the admitted material this record already
        // resolved, runs `audit_claim` over each, binds a record per verdict and
        // builds the coverage map. The previous `None` recorded a real state — no
        // `AuditedClaim` producer existed — and that state is now over, so the
        // value is threaded from the audit rather than restated. A run that cannot
        // audit its material claims produces no record at all, so an absent audit
        // here means the run released no material claim, never that the audit was
        // skipped.
        let claim_audit = claim_audit_for_run(&observation, &profile, &account, &admissibility)?;
        // The lane discipline runs on the live path, after the evidence is
        // frozen and before the terminal record is built, so the class the
        // terminal record publishes is the class the discipline decided over the
        // real frozen evidence rather than a value re-derived beside it.
        let lane_discipline = run_lane_discipline(&observation, &profile, &admissibility, &freeze)?;
        let terminal = terminal_record(
            &observation,
            &profile,
            &portfolio,
            &coverage_receipt,
            &precision,
            &obligations,
            &research_debts,
            &freeze,
            claim_audit.records.first(),
            absence_evidence.as_ref(),
        )?;
        // W2 and W3 together: commit the freeze through the existing governed
        // source-admission owner, then build the synthesis pack from that
        // committed freeze. The ordering is the guarantee, so both steps live in
        // one named function rather than being two calls in a long body.
        let (source_admission_requests, retained_revisions, committed_freeze, synthesis_input) =
            commit_freeze_and_resolve_synthesis_input(
                &observation,
                &freeze,
                &admissibility,
                &profile,
                &lane_discipline,
            )?;
        let record = Self {
            inquiry_id: observation.inquiry_id,
            evidence_set_id: observation.evidence_set_id,
            run_reference_manifest: observation.reference_manifest.clone(),
            profile_admission_request: profile.admission_request(),
            source_admission_requests,
            retained_revisions,
            unadmitted_references,
            profile,
            claim_audits: claim_audit.records,
            claim_coverage: claim_audit.coverage,
            claim_coverage_unaccounted: claim_audit.unaccounted,
            admissibility,
            portfolio,
            coverage_receipt,
            precision,
            obligations,
            freeze,
            committed_freeze,
            synthesis_input,
            research_debts,
            lane_discipline,
            terminal,
            compilation_inputs,
        };
        record.validate_integrity()?;
        Ok(record)
    }

    /// The release gate a consumer must ask before it may release this run's
    /// material claims as fully supported.
    ///
    /// I21.8 item 6: "No `SUPPORTED` promotion while a required chain, excerpt
    /// or audit dimension fails/is unknown", and the issue's acceptance
    /// sentence: "an omitted claim blocks a complete-audit claim". The previous
    /// code published `is_complete()`, `dimensions_complete()` and
    /// `public_class()` and nothing read them, so the verdict existed and no
    /// production path ever asked. This is that question, over the record's own
    /// carried audit trail and coverage map.
    ///
    /// Every conjunct is decided by content over the carried records, never by a
    /// caller flag: the coverage map is re-proved, its published `unaccounted`
    /// list is re-derived from the same gate, and each claim's own verdict is
    /// re-read through [`crate::evidence_portfolio::ClaimVerdict::releasable_as_supported`],
    /// which requires the five-class projection, every recorded dimension and
    /// both I21.8 requirement obligations.
    ///
    /// A2: the fourth of the four named acceptance cases — a post-audit material
    /// edit — is the part of this gate that reads the **delivered** wording, not
    /// only the record. `delivered` is a map from audited claim identity to the
    /// exact text the release is about to deliver for it; it is checked against
    /// the wording the audit judged, so an added, edited, re-numbered, causally
    /// widened, translated or joined statement is refused rather than published
    /// beside a verdict that described different words. A claim the delivery map
    /// does not name is a *material* omission and is refused as one, because the
    /// acceptance requirement is that every released material claim is in the
    /// coverage map. A claim named here that the audit trail never carried is a
    /// fabricated claim identity and is likewise refused.
    ///
    /// The one thing this gate accepts is a **nonsemantic restyle**: the same
    /// non-space words in a different whitespace or capitalisation-free
    /// arrangement, which I21.8 permits under an explicit mapping. That is
    /// decided by [`ClaimAuditRecord::is_nonsemantic_restyle_of`], never by
    /// "the strings look close enough" — a difference in any non-space byte is a
    /// material edit and is refused, so this gate cannot launder a semantic
    /// change through a formatting path.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] naming the first gate that
    /// refuses, or [`InquiryError::ReleaseGateRefused`] naming
    /// `released_wording` and the offending claim, so a consumer reads WHICH
    /// requirement failed rather than only that the release is blocked.
    pub fn release_gate(&self, delivered: &BTreeMap<String, String>) -> Result<(), InquiryError> {
        if let Some(prior) =
            crate::evidence_portfolio::require_complete_claim_coverage(&self.claim_coverage).err()
        {
            return Err(InquiryError::ReleaseGateRefused {
                gate: "claim_coverage",
                detail: prior.join(","),
            });
        }
        for audit in &self.claim_audits {
            audit.validate_integrity()?;
            if !audit.verdict.releasable_as_supported() {
                return Err(InquiryError::ReleaseGateRefused {
                    gate: "claim_audit",
                    detail: audit.claim_id.clone(),
                });
            }
            // A2: the delivered wording must be the wording the audit judged.
            // `delivered` is consulted per claim so a claim that is audited but
            // absent from the delivery map is caught as a material omission here,
            // at the gate a release consumer actually calls.
            let Some(text) = delivered.get(&audit.claim_id) else {
                return Err(InquiryError::ReleaseGateRefused {
                    gate: "released_wording",
                    detail: format!(
                        "{}: audited but not named in the delivered text",
                        audit.claim_id
                    ),
                });
            };
            if text == &audit.released_statement {
                continue;
            }
            if audit.is_nonsemantic_restyle_of(text) {
                continue;
            }
            return Err(InquiryError::ReleaseGateRefused {
                gate: "released_wording",
                detail: format!(
                    "{}: delivered text is a material edit of the audited wording and no \
                     explicit nonsemantic mapping was offered",
                    audit.claim_id
                ),
            });
        }
        // A claim the delivery map names that the audit trail never carried is a
        // fabricated claim identity: it would be a released material statement
        // with no coverage-map entry, which is exactly the omission this issue
        // says blocks a complete-audit claim. It is refused by comparing the two
        // independent rosters — the carried audits and the delivery map — not by
        // reading one back from the other.
        let audited: BTreeSet<&str> = self
            .claim_audits
            .iter()
            .map(|audit| audit.claim_id.as_str())
            .collect();
        for claim_id in delivered.keys() {
            if !audited.contains(claim_id.as_str()) {
                return Err(InquiryError::ReleaseGateRefused {
                    gate: "released_wording",
                    detail: format!(
                        "{claim_id}: named in the delivered text but absent from the audited \
                         coverage map"
                    ),
                });
            }
        }
        Ok(())
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
        self.validate_compilation_input_binding()?;
        self.validate_run_reference_manifest()?;
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
        self.validate_lane_discipline_binding()?;
        self.validate_terminal_carried_bindings()?;
        // The claim-audit trail and the coverage map are re-proved here, not
        // carried on trust. A record that lost an audit between construction and
        // publication would otherwise present a coverage map whose `released`
        // roster no longer matches the records it claims to describe, and a
        // complete-audit claim would survive the loss. Re-deriving the released
        // roster from the carried records is what makes the omission observable.
        for audit in &self.claim_audits {
            audit.validate_integrity()?;
        }
        self.claim_coverage.verify_integrity()?;
        self.validate_claim_coverage_binding()?;
        for record in &self.admissibility {
            record.validate_integrity()?;
        }
        self.validate_source_admission_requests()?;
        self.validate_committed_freeze_and_synthesis_input()?;
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
        // I21.5: a recorded `VERIFIED` status is this domain's own verdict, and a
        // verdict is only publishable if the certificate it names still re-derives
        // from the run's own material. Two rosters are built and compared:
        //
        // - `recorded` is every obligation whose status this record claims is
        //   `VERIFIED`;
        // - `derived` is every obligation whose acceptance certificate, re-derived
        //   from the carried manifest and the admitted source records for its own
        //   `coverage_member`, is of the kind that obligation declares.
        //
        // They are built from different inputs on purpose: `recorded` reads the
        // status field, `derived` never reads it. A writer that flipped a status
        // to `VERIFIED` without holding a matching certificate makes `recorded`
        // larger than `derived`; a writer that satisfied an obligation and then
        // restated the status makes `derived` larger than `recorded`. Both are
        // refused. Comparing one list against a restated copy of itself would
        // prove nothing, which is why the two are produced separately.
        let mut recorded: Vec<&str> = self
            .obligations
            .iter()
            .filter(|obligation| obligation.status == InquiryObligationStatus::Verified)
            .map(|obligation| obligation.obligation_id.as_str())
            .collect();
        recorded.sort_unstable();
        let mut derived = certified_obligations(
            &self.run_reference_manifest,
            &self.obligations,
            &self.admissibility,
        )?;
        derived.sort_unstable();
        if recorded != derived {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.certified_obligations",
            });
        }
        Ok(())
    }

    /// Re-proves that the work-graph compilation bundle this record carries was
    /// compiled under this record's own inquiry, evidence set, profile revision
    /// and lane registration.
    ///
    /// The work graph receives the lane and the committed registration the work
    /// was compiled under, so a bundle that carried another lane or another
    /// registration would let queued execution and resume present a registration
    /// the profile does not hold. The registration identity is compared against
    /// the profile's own `independence_and_blinding_policy.lane_registration_digest`,
    /// which originates from the unforgeable `CommittedLaneRegistration`; the check
    /// is therefore on the registration itself, never on
    /// `registered_before_outcome_exposure` or on any timestamp.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] naming
    /// `inquiry.compilation_inputs` when any of the four bindings disagrees.
    fn validate_compilation_input_binding(&self) -> Result<(), InquiryError> {
        if self.compilation_inputs.profile_digest != self.profile.integrity_digest
            || self.compilation_inputs.evidence_set_id != self.evidence_set_id
            || self.compilation_inputs.lane != self.profile.lane
            || self.compilation_inputs.lane_registration_digest
                != self
                    .profile
                    .independence_and_blinding_policy
                    .lane_registration_digest
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.compilation_inputs",
            });
        }
        Ok(())
    }

    /// Re-proves the Governor-facing source-admission requests this record
    /// carries against the admissibility records it publishes beside them.
    ///
    /// The Researcher half of the two-record pair a positive admitted source
    /// has to show is re-proved here rather than trusted: each
    /// Governor-facing request is an artefact that leaves this domain, and a
    /// request whose inquiry, evidence set, profile revision, source handle,
    /// source-record digest, eligibility, scope or fence was rewritten after
    /// it was built would otherwise be published beside a decision it no
    /// longer describes. The other half of the pair - the actual
    /// Governor/Kernel/Store commit receipt - is deliberately absent and this
    /// domain does not synthesize one; I21.1 puts the transition through the
    /// sole canonical writer.
    ///
    /// # Errors
    ///
    /// Returns an integrity mismatch when the request count does not match the
    /// admissibility record count, when a request no longer re-derives its own
    /// digest, or when a request has been swapped for a well-formed request
    /// about a different source, decision, evidence set or fence.
    fn validate_source_admission_requests(&self) -> Result<(), InquiryError> {
        // The request count no longer equals the admissibility record count, and
        // that is the W2 signal rather than a defect: a source whose original was
        // never retained has no committed admission, so it produces no request.
        // The check below is therefore per-handle — every request must still be
        // the request for one of this record's decisions, and every decision with
        // a committed freeze must still have its request — rather than a count
        // equality that a run that did not persist before synthesis could never
        // satisfy.
        for request in &self.source_admission_requests {
            request.validate_integrity()?;
            let Some(record) = self
                .admissibility
                .iter()
                .find(|record| record.record.handle == request.source_handle)
            else {
                return Err(InquiryError::IntegrityMismatch {
                    field: "inquiry.source_admission_request_binding",
                });
            };
            // The request must still be the request for *this* decision under
            // *this* inquiry and evidence set. Its own digest proves it was not
            // edited; these bindings prove it was not swapped for a well-formed
            // request about a different source, a different decision or a
            // different set.
            if request.inquiry_id != self.inquiry_id
                || request.evidence_set_id != self.evidence_set_id
                || request.admissibility_digest != record.digest
                || request.source_handle != record.record.handle
                || request.eligibility != record.eligibility
                || request.state_fence != record.state_fence
            {
                return Err(InquiryError::IntegrityMismatch {
                    field: "inquiry.source_admission_request_binding",
                });
            }
            // W2: a request on this record must name THIS record's committed
            // freeze, and the retained original it names must be the admitted
            // record's own revision. Both are comparisons against values a
            // different owner produced — the freeze's own digest and the admitted
            // record's own `content_digest` — rather than against a restatement
            // of the request's own fields.
            let Some(commitment) = &request.freeze_commit else {
                return Err(InquiryError::IntegrityMismatch {
                    field: "inquiry.source_admission_request.freeze_commit",
                });
            };
            if commitment.freeze_digest != self.freeze.digest
                || commitment.freeze_id != self.freeze.freeze_id
                || !self.freeze.includes(&request.source_handle)
            {
                return Err(InquiryError::IntegrityMismatch {
                    field: "inquiry.source_admission_request.freeze_commit",
                });
            }
            match self.retained_revisions.get(&request.source_handle) {
                Some(retained) => {
                    retained.verify_integrity()?;
                    if retained.content_digest != record.record.content_digest
                        || retained.artifact_ref != commitment.retained_artifact_ref
                        || retained.digest != commitment.retained_revision_digest
                    {
                        return Err(InquiryError::IntegrityMismatch {
                            field: "inquiry.retained_revision_binding",
                        });
                    }
                }
                None => {
                    return Err(InquiryError::IntegrityMismatch {
                        field: "inquiry.retained_revision_binding",
                    });
                }
            }
        }
        // Every committed member of the freeze this record published must still
        // have its admission request, so a dropped request cannot shrink the
        // committed set while the freeze still names the source. The expected set
        // is read off the committed freeze and the requests, which are separate
        // values, and compared rather than one being read back from the other.
        let mut expected: Vec<&str> = self
            .freeze
            .included_members()
            .iter()
            .map(String::as_str)
            .filter(|handle| {
                self.admissibility.iter().any(|record| {
                    record.record.handle == **handle
                        && record.eligibility == SourceEligibility::Eligible
                        && self.retained_revisions.contains_key(*handle)
                })
            })
            .collect();
        expected.sort_unstable();
        let mut carried: Vec<&str> = self
            .source_admission_requests
            .iter()
            .map(|request| request.source_handle.as_str())
            .collect();
        carried.sort_unstable();
        if expected != carried {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.source_admission_request_coverage",
            });
        }
        Ok(())
    }

    /// Re-proves the committed-freeze proof and the synthesis pack this record
    /// carries against the ORIGINAL recorded values they were built from.
    ///
    /// Neither value is re-derived here. Each is re-proved by running the
    /// **existing** validators over the values a *different* owner recorded, which
    /// is the whole difference between a check that can fire and a recomputation
    /// that would agree with whatever it was handed:
    ///
    /// 1. [`crate::synthesis_input::CommittedFreeze::commit`] is re-run over
    ///    **this record's own** `source_admission_requests` and `freeze`. That
    ///    re-proves, per request through the admission owner's own
    ///    `validate_integrity`, the five
    ///    [`FreezeCommitment`](crate::source_admissibility::FreezeCommitment) fields a
    ///    `CommittedFreeze` member carries: `freeze_id` and `freeze_digest`
    ///    against the freeze this record published, `retained_content_digest`
    ///    against the admitted record's own `content_digest`, and
    ///    `retained_revision_digest` / `retained_artifact_ref` against the
    ///    retained revision the persistence owner committed. The reconstructed
    ///    value is then compared **by content** with the carried one, so a
    ///    `committed_freeze` that was swapped for another commit cannot pass on
    ///    the strength of re-deriving cleanly.
    /// 2. [`crate::synthesis_input::SynthesisInputPack::resolve`] is re-run over
    ///    that re-proven commit, this record's `freeze`, its own re-proved
    ///    `run_reference_manifest`, the admitted source records and the
    ///    lane discipline. This is what makes the W3 membership rule *fire*:
    ///    resolution is driven by [`EvidenceFreeze::includes`], so a pack that
    ///    resolved a member the freeze excluded, or dropped a member it
    ///    included, is caught here rather than read off the pack's own list.
    ///    The reconstructed pack is again compared by content with the carried
    ///    one.
    ///
    /// The comparison is content equality over the whole typed value rather than
    /// a digest spot-check, because the pack's `digest` already covers every
    /// field and comparing digests would only re-ask the question the value's own
    /// `validate_integrity` answers.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] naming the first field whose
    /// carried value disagrees with the value re-proved from this record's own
    /// requests, freeze, manifest, admitted records and lane discipline.
    fn validate_committed_freeze_and_synthesis_input(&self) -> Result<(), InquiryError> {
        let re_proven = crate::synthesis_input::CommittedFreeze::commit(
            &self.freeze,
            &self.source_admission_requests,
        )?;
        if re_proven != self.committed_freeze {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.committed_freeze",
            });
        }
        let repacked = crate::synthesis_input::SynthesisInputPack::resolve(
            &self.committed_freeze,
            &self.freeze,
            &self.run_reference_manifest,
            &admitted_records(&self.admissibility),
            &self.committed_freeze.members_by_handle(),
            &self.profile.question,
            // The disclosure class the run admitted, read back from the profile
            // that resolved this run under its own reference manifest rather than
            // from a value only the consumed `Observation` carried: the profile's
            // `disclosure_ceiling` is the governed value the record publishes for
            // exactly this question, and I21.7 makes it the ceiling a source
            // record may not exceed.
            self.profile.disclosure_ceiling,
            &self.lane_discipline,
        )?;
        if repacked != self.synthesis_input {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.synthesis_input",
            });
        }
        Ok(())
    }

    /// Re-proves the run-bound reference allowlist this record carries.
    ///
    /// I21.7: the allowlist is re-proved on the RECORD, not only on the
    /// observation `record` was handed. `AllowedReferenceManifest::validate`
    /// recomputes the canonical digest over the manifest's own content and
    /// refuses a mismatch, so the manifest carried beside the published
    /// `manifest=` digest is the one that digest was computed from. The three
    /// bindings below then make the same manifest the one the profile, the
    /// freeze and the terminal disposition were all bound to: comparing the
    /// carried `digest` field against each of those is a real comparison
    /// between two independently produced values, whereas before the manifest
    /// was carried at all the record held only its digest and had nothing to
    /// re-derive an admission or a certificate from.
    ///
    /// # Errors
    ///
    /// Returns an integrity mismatch when the carried manifest does not
    /// re-derive its own published digest, or when the profile, the freeze and
    /// the terminal disposition are not all bound to that same manifest and
    /// fence.
    fn validate_run_reference_manifest(&self) -> Result<(), InquiryError> {
        self.run_reference_manifest
            .validate()
            .map_err(|_| InquiryError::IntegrityMismatch {
                field: "inquiry.run_reference_manifest",
            })?;
        if self.run_reference_manifest.digest != self.profile.reference_manifest_digest
            || self.run_reference_manifest.digest != self.freeze.manifest_digest
            || self.run_reference_manifest.digest != self.terminal.manifest_digest
            || self.run_reference_manifest.state_fence != self.terminal.state_fence
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.run_reference_manifest_binding",
            });
        }
        Ok(())
    }

    /// A3: the published coverage map must still describe the audit trail this
    /// record carries.
    ///
    /// Three facts are re-derived and compared, and each names a different way
    /// the map could have stopped describing the release:
    ///
    /// * the map's `released` roster must equal the claim identities the carried
    ///   [`ClaimAuditRecord`]s actually name, so a dropped audit cannot leave a
    ///   map that still claims it was covered;
    /// * the published `claim_coverage_unaccounted` list must equal what
    ///   [`crate::evidence_portfolio::require_complete_claim_coverage`] returns
    ///   for this map, so the specific unaudited claims a consumer reads are the
    ///   ones the gate refuses on;
    /// * the terminal record's carried audit must be one of the audited claims,
    ///   not a foreign record the map never saw.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] naming the first disagreement.
    fn validate_claim_coverage_binding(&self) -> Result<(), InquiryError> {
        let released: Vec<String> = self
            .claim_audits
            .iter()
            .map(|audit| audit.claim_id.clone())
            .collect();
        if released != self.claim_coverage.released_material_claims() {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.claim_coverage_released",
            });
        }
        let gate = crate::evidence_portfolio::require_complete_claim_coverage(&self.claim_coverage)
            .err()
            .unwrap_or_default();
        if gate != self.claim_coverage_unaccounted {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.claim_coverage_unaccounted",
            });
        }
        if let Some(audit) = &self.terminal.claim_audit
            && !released.contains(&audit.claim_id)
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "terminal.claim_audit_binding",
            });
        }
        for audit in &self.claim_audits {
            if audit.inquiry_id != self.inquiry_id
                || audit.evidence_set_id != self.evidence_set_id
                || audit.profile_digest != self.profile.integrity_digest
            {
                return Err(InquiryError::IntegrityMismatch {
                    field: "inquiry.claim_audit_binding",
                });
            }
        }
        Ok(())
    }

    /// The lane class the discipline decided is bound to the same evidence the
    /// record froze, so a class decided over one evidence revision cannot be
    /// published beside another.
    ///
    /// The outcome's own digest is re-proved first: it is an artefact that leaves
    /// this record, and a rewritten grade, lane, handle set or fence would
    /// otherwise be published as the discipline's own decision. Every comparison
    /// is by content — the recorded evidence revision against
    /// [`EvidenceFreeze::digest`], the recorded profile revision against the
    /// profile's own integrity digest — never by a timestamp and never by a
    /// caller flag.
    ///
    /// I21.2 keeps the class as the only thing separating E3 exploratory from E3
    /// confirmatory, so a confirmatory class may only be read back from a lane
    /// that actually committed a registration: the check is on the profile's
    /// `CommittedLaneRegistration`, which is unforgeable, rather than on
    /// `registered_before_outcome_exposure`.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] naming the first lane field
    /// that disagrees with the composite that produced it.
    fn validate_lane_discipline_binding(&self) -> Result<(), InquiryError> {
        if self.lane_discipline.compute_digest() != self.lane_discipline.digest
            || self.lane_discipline.inquiry_id != self.inquiry_id
            || self.lane_discipline.evidence_revision_digest != self.freeze.digest
            || self.lane_discipline.profile_digest != self.profile.integrity_digest
            || self.lane_discipline.produced_under_grade != self.profile.evidence_grade
            || self.lane_discipline.produced_under_lane != self.profile.lane
            || self.lane_discipline.state_fence != self.profile.state_fence
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.lane_discipline_binding",
            });
        }
        if self.lane_discipline.evidence_class.is_confirmatory()
            && self
                .profile
                .independence_and_blinding_policy
                .lane_registration_digest
                .is_none()
        {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.lane_discipline_confirmatory_without_registration",
            });
        }
        Ok(())
    }

    /// I21.7/I21.8: the terminal projection has to carry the evidence freeze and
    /// the unsupported-precision residue this run produced, not a copy that was
    /// restated while it was being bound. Comparing the two owners to what the
    /// terminal record carries catches a freeze or a residue that was replaced,
    /// dropped or added between the two constructions.
    ///
    /// The claim audit is compared, but not here: the carried audit is bound
    /// against the released roster in
    /// [`Self::validate_claim_coverage_binding`], which requires the terminal's
    /// carried [`ClaimAuditRecord`] to name one of the released
    /// [`ClaimAuditRecord`]s (`terminal.claim_audit_binding`), and
    /// `record` passes `claim_audit.records.first()` into the `terminal_record`
    /// call so that comparison has a real production owner on the live path. This
    /// function compares only the two owners it holds side by side; the terminal
    /// record's own `validate_carried_artifacts` still re-proves an audit and
    /// binds it to this inquiry, profile, manifest and State Fence, so a `Some`
    /// cannot be a foreign or edited record.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] naming the first carried
    /// artifact that disagrees with the composite that produced it.
    fn validate_terminal_carried_bindings(&self) -> Result<(), InquiryError> {
        if self.terminal.freeze != self.freeze {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.terminal_freeze_binding",
            });
        }
        if self.terminal.unsupported_precision != self.precision.residue {
            return Err(InquiryError::IntegrityMismatch {
                field: "inquiry.terminal_unsupported_precision_binding",
            });
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
    ///
    /// What the terminal record *carries* is printed as its own key so a reader
    /// can see which freeze, claim audit and unsupported-precision residue the
    /// disposition was bound over rather than only that the composite holds some.
    /// `terminal_claim_audit=none` is the honest spelling of a run that released
    /// no material claim — the producer derives one audited claim per admitted,
    /// citable source handle — and not a stand-in for a skipped audit, because a
    /// run that cannot audit its material claims produces no record at all.
    ///
    /// The Governor-facing source-admission requests are counted and their
    /// digests published here, which is what makes this line the Researcher half
    /// of the two-record pair a positive admitted source has to show. They are
    /// proposals, so the line states that no owner receipt exists: the
    /// Governor/Kernel/Store commit receipt is the owner's, and a line that
    /// implied one would be a false proof claim under A0.3.
    ///
    /// `certified` is the number of obligations this run both recorded as
    /// satisfied AND whose acceptance certificate re-derives, from the run-bound
    /// manifest and the admitted source records, as a kind that obligation
    /// declares. It is not a status read: see [`certified_obligations`].
    /// `certified=0` is the honest spelling of the live state whenever the run
    /// holds no admitted certificate of a declared kind for any member, and the
    /// line says that instead of omitting the figure.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let terminal = &self.terminal;
        // `certified` is re-derived, and a re-derivation that cannot be completed
        // has no honest numeric spelling, so it renders as `unproved` rather than
        // as a count the run did not establish. `record` runs
        // `validate_integrity`, which performs the same derivation and refuses the
        // record on failure, so this arm is reachable only on a record assembled
        // outside that path.
        let certified = match certified_obligations(
            &self.run_reference_manifest,
            &self.obligations,
            &self.admissibility,
        ) {
            Ok(certified) => certified.len().to_string(),
            Err(_) => "unproved".to_owned(),
        };
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
             materialisable={} deferred={} certified={} compilation_inputs={} \
             {} freeze={} \
             lane_class={} lane_result={} lane_result_grade={} lane_result_lane={} \
             lane_delivered_handles={} lane_discipline={} \
             terminal_freeze={} terminal_claim_audit={} terminal_precision_residue={} \
             claim_audits={} claim_coverage={} \
             debts={} debt_kinds={} {} \
             {} \
             source_admission_owner_receipt=none",
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
            self.admissibility
                .iter()
                .filter(|record| record.eligibility == SourceEligibility::Eligible)
                .count(),
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
            certified,
            self.compilation_inputs.digest,
            WorkGraphLaneProjection {
                inputs: &self.compilation_inputs,
            },
            self.freeze.digest,
            self.lane_discipline.evidence_class.wire_name(),
            self.lane_discipline.result_id,
            self.lane_discipline.produced_under_grade,
            self.lane_discipline.produced_under_lane.wire_name(),
            self.lane_discipline.delivered_handle_count,
            self.lane_discipline.digest,
            terminal.freeze.digest,
            terminal
                .claim_audit
                .as_ref()
                .map_or("none", |audit| audit.digest.as_str()),
            terminal.unsupported_precision.len(),
            self.claim_audits.len(),
            ClaimCoverageProjection {
                map: &self.claim_coverage,
                unaccounted: &self.claim_coverage_unaccounted,
            },
            self.research_debts.len(),
            debt_kinds_wire(&self.research_debts),
            DebtRestrictionProjection {
                restriction: &terminal.debt_restriction,
            },
            TerminalDispositionProjection {
                terminal,
                source_admission_requests: &self.source_admission_requests,
            },
        )
    }
}

/// The exact admitted material one profile revision is resolved from.
///
/// [`resolve_profile`] builds revision one from this and
/// [`revise_profile`] builds the next revision from the same values, so the two
/// cannot drift into resolving from different inputs: a revision that changed its
/// own selection inputs would compare a new selection against a registration
/// committed for the old one.
fn profile_params(observation: &InquiryObservation) -> Result<InquiryProfileParams, InquiryError> {
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
    Ok(InquiryProfileParams {
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
    })
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
    let mut params = profile_params(observation)?;
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

/// Revises the profile for one observed inquiry when the run observed something
/// that changes the resolved selection.
///
/// I21.3: "Protocol choice is a Default, not a Hard Boundary: it may be changed
/// mid-run with a recorded reason, and the change invalidates only obligations
/// that depended on the previous protocol." I21.1 puts that revision in the
/// Researcher's own ownership ("resolution **and revision** of the versioned
/// inquiry profile and Evidence Grade"). Until this existed,
/// [`InquiryProtocolProfile::revise`] had no caller on the live
/// `InquiryGovernance::record` path, and the only other caller in the crate,
/// [`revise_grade_requirement`](crate::inquiry_lanes::revise_grade_requirement)
/// (which reaches `revise` at `inquiry_lanes.rs:3070`), is itself `pub` but
/// uncalled, so no run reached a revision through it either: every run froze
/// revision one and a selection the admitted material contradicted stayed in
/// force for the rest of the run.
///
/// # What decides the revision
///
/// One fact read from the material this run was admitted to carry: the profile
/// resolved [`InquiryProtocol::EvidenceReview`], which
/// [`select_protocol`] selects only when `primary_source_available` is true, and
/// the admitted candidates contain no primary-source class at all.
///
/// That is the *same* predicate [`SourcePortfolio::assemble`] buckets with — it
/// places exactly `Paper | Documentation | Repository` in `primary_sources` — so
/// "the profile selected a protocol for a primary class" and "an admitted
/// candidate is of a primary class" are one question read from one list, not two
/// definitions that can drift. The consequence is the one I21.3's opening
/// sentence names ("A single generic pipeline for every question is the most
/// common failure of research automation") and the one I21.1 answers by
/// revision ("Absence of a provider narrows declared coverage and is reported
/// as a gap"): a run whose material holds no primary source cannot review
/// evidence, and continuing to declare that protocol would assert rigour the
/// admitted material does not carry.
///
/// The condition is content — a set membership over the admitted candidates and
/// the profile's own class list — not a flag, not a version and not a caller
/// intention.
///
/// # Why the decision is made from the candidates and not from the evidence set
///
/// This runs before [`assess_sources`] on purpose, and that ordering is forced
/// rather than chosen. A [`SourceAdmissibilityRecord`](crate::source_admissibility::SourceAdmissibilityRecord)
/// freezes `profile_digest` and [`SourcePortfolio::assemble`] refuses any record
/// whose digest is not the profile it assembles against
/// (`portfolio.record_binding`), so a revision taken *after* assessment would
/// leave the record holding admissibility decisions about a superseded revision,
/// with no way to re-derive them.
/// [`SourceAdmissibilityRecord::is_admitted_to`](crate::source_admissibility::SourceAdmissibilityRecord::is_admitted_to)
/// is a second, independent check on the same field, and a mismatch there is a
/// silent skip rather than an error, so the same late revision would also leave
/// the portfolio with an empty `primary_sources` and a swallowed admission
/// decision. Deciding from the candidate classes therefore
/// reads exactly the input the eligibility decision is about to be taken over,
/// and leaves one profile revision governing one whole record.
///
/// # What the revision carries
///
/// Real values on every field, none of them a stand-in:
///
/// - `features` are the observation's own [`InquirySelectionFeatures`] with
///   `primary_source_available` corrected to the observed fact, so
///   [`select_protocol`] re-resolves to the protocol the admitted material
///   supports rather than the one the requested classes implied;
/// - every other field is the identical admitted value the first revision was
///   resolved from, rebuilt by [`profile_params`], so a revision cannot
///   restate the question, the scope or the intended decision;
/// - `committed_lane_registration` is `None`. That is the value the re-resolved
///   exploratory selection must carry, and re-committing the superseded
///   revision's registration would freeze a receipt that names a revision this
///   run did not produce. The drop is safe exactly because the re-resolution
///   can only reach an exploratory lane here: [`select_lane`] admits a
///   confirmatory lane only under an evaluator and a strong verifier, and the
///   revision is reachable only from an [`InquiryProtocol::EvidenceReview`]
///   selection that this branch has just re-derived from features carrying
///   `evaluator_exists` from the observation unchanged. If a re-resolution ever
///   did reach a confirmatory lane, [`IndependenceBlindingPolicy::resolve`]
///   refuses the missing registration rather than publishing an unregistered
///   confirmatory revision, so the failure is typed and the record is refused;
/// - the reason names the classes the run admitted, the classes the protocol was
///   selected for, and the run's own acquisition outcome and reason code — the
///   observed facts, not a restated version number.
///
/// # Errors
///
/// Returns the profile domain's own errors when the revised selection cannot be
/// resolved or the revision does not re-prove its own digest, so a run whose
/// material cannot support a coherent selection produces no record rather than a
/// record whose profile disagrees with its evidence.
fn revise_profile(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
) -> Result<InquiryProtocolProfile, InquiryError> {
    if profile.protocol != InquiryProtocol::EvidenceReview {
        return Ok(profile.clone());
    }
    // The protocol was selected for a primary source, so only a class the profile
    // actually admits can have satisfied that premise. Reading the candidates
    // through the profile's own class list keeps the trigger inside the admitted
    // scope: a primary class nobody asked for is not evidence that this
    // evidence-review premise failed.
    let admits_primary = profile
        .admissible_source_classes
        .iter()
        .any(|class| is_primary_source_class(*class));
    let admitted_primary: BTreeSet<&'static str> = observation
        .candidates
        .iter()
        .filter(|candidate| is_primary_source_class(candidate.class))
        .map(|candidate| class_wire(candidate.class))
        .collect();
    if !admits_primary || !admitted_primary.is_empty() {
        return Ok(profile.clone());
    }
    let unmet: Vec<&'static str> = profile
        .admissible_source_classes
        .iter()
        .filter(|class| is_primary_source_class(**class))
        .map(|class| class_wire(*class))
        .collect();
    let mut params = profile_params(observation)?;
    params.features.primary_source_available = false;
    let reason = format!(
        "revision {}-{} selected {} because the request admitted the primary source class(es) \
         {}, but the run admitted {} candidate(s) and none of them is of a primary class; \
         acquisition outcome {} with reason {}; the protocol is revised to the one this evidence \
         can support",
        profile.revision,
        profile.profile_id,
        profile.protocol.wire_name(),
        unmet.join(","),
        observation.candidates.len(),
        observation.outcome.wire_name(),
        observation.reason_code,
    );
    let revised = profile.revise(params, &reason)?;
    revised.validate_integrity()?;
    Ok(revised)
}

/// Whether a source class is a primary source or specification.
///
/// This is the one class predicate this plane already uses, read off
/// [`SourcePortfolio::assemble`], which buckets exactly
/// `Paper | Documentation | Repository` into `primary_sources`. Naming the same
/// three here is what makes "the protocol was selected for a primary class" and
/// "an admitted candidate is a primary class" the same question rather than two
/// lists that can drift apart.
fn is_primary_source_class(class: SourceClass) -> bool {
    matches!(
        class,
        SourceClass::Paper | SourceClass::Documentation | SourceClass::Repository
    )
}

/// The class of lane result one recorded inquiry run actually produced (I21.2/I21.4).
///
/// This is what the [`InquiryLaneDiscipline`] decided on the live path, and it is
/// carried here so a reader of the governance record learns the lane class from
/// the discipline that authorised it rather than from the profile's declared
/// lane alone. The digest is over the same fields [`Display`] publishes, so the
/// rendered line and the re-proved value cannot drift apart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneDisciplineOutcome {
    /// Class the release produced: a confirmatory claim or an exploratory
    /// finding.
    pub evidence_class: LaneEvidenceClass,
    /// Stable identity of the released result.
    pub result_id: String,
    /// Inquiry the result belongs to.
    pub inquiry_id: String,
    /// Profile revision the result was produced under.
    pub profile_id_and_revision: String,
    /// Exact profile revision digest the result was produced under.
    pub profile_digest: String,
    /// Grade requirement the result was produced under.
    pub produced_under_grade: EvidenceGrade,
    /// Lane the result was produced under.
    pub produced_under_lane: InquiryLane,
    /// Exact evidence revision the result was produced from.
    pub evidence_revision_digest: String,
    /// Digest over the sorted delivered handles the release covered.
    pub delivered_handle_digest: String,
    /// Number of delivered handles the release covered.
    pub delivered_handle_count: usize,
    /// State Fence the result was produced under.
    pub state_fence: StateFence,
    /// Instant the result was recorded.
    pub recorded_at_ms: i64,
    /// Digest over the whole outcome.
    pub digest: String,
}

impl LaneDisciplineOutcome {
    fn compute_digest(&self) -> String {
        let mut preimage = String::from("inquiry-lane-discipline-outcome/v1;");
        push_field(
            &mut preimage,
            "evidence_class",
            self.evidence_class.wire_name(),
        );
        push_field(&mut preimage, "result_id", &self.result_id);
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(
            &mut preimage,
            "profile_id_and_revision",
            &self.profile_id_and_revision,
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_field(
            &mut preimage,
            "produced_under_grade",
            &self.produced_under_grade.to_string(),
        );
        push_field(
            &mut preimage,
            "produced_under_lane",
            self.produced_under_lane.wire_name(),
        );
        push_field(
            &mut preimage,
            "evidence_revision_digest",
            &self.evidence_revision_digest,
        );
        push_field(
            &mut preimage,
            "delivered_handle_digest",
            &self.delivered_handle_digest,
        );
        push_field(
            &mut preimage,
            "delivered_handle_count",
            &self.delivered_handle_count.to_string(),
        );
        push_field(
            &mut preimage,
            "state_fence",
            &fence_preimage(&self.state_fence),
        );
        push_field(
            &mut preimage,
            "recorded_at_ms",
            &self.recorded_at_ms.to_string(),
        );
        freeze(&preimage)
    }
}

/// Renders exactly the fields `compute_digest` covers, so the published line and
/// the re-proved value cannot drift apart.
impl std::fmt::Display for LaneDisciplineOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "class={} result={} grade={} lane={} delivered_handles={} digest={}",
            self.evidence_class.wire_name(),
            self.result_id,
            self.produced_under_grade,
            self.produced_under_lane.wire_name(),
            self.delivered_handle_count,
            self.digest
        )
    }
}

/// Runs the [`InquiryLaneDiscipline`] over the result this run actually produced.
///
/// # Why this is on the live path
///
/// I21.4 is only an executed property if the machinery that enforces it is
/// reached by a real run. The discipline is the one owner of the register
/// itself — exposure, deviations, attempts, blinded deliveries, the release gate
/// and the claim it authorises — and before this call nothing on the `R6` path
/// ever entered it: a `LaneRegistration` was committed and published on the
/// profile, but no lane was ever *run* against it, so the commit-before-exposure
/// proof, the deviation classification and the release gate were code no run
/// could execute.
///
/// # What it decides, and from what
///
/// Every input is a value this run already computed, so nothing here is
/// asserted, guessed or supplied by a caller:
///
/// - the discipline is opened on the exact profile revision [`resolve_profile`]
///   committed, which is what carries the committed lane registration;
/// - the evidence revision released is [`EvidenceFreeze::digest`], i.e. the real
///   frozen evidence revision, never a fresh digest computed for the release;
/// - the delivered handles are the eligible source handles of the real
///   admissibility disposition, which is the exact set a consumer of this record
///   reads;
/// - the fence is the profile's own State Fence, and the instant is the run's own
///   assessment time.
///
/// # What it does NOT do
///
/// It mints a confirmatory claim only for a lane that actually committed a
/// registration, and it never manufactures one. A purely exploratory lane — the
/// only lane `select_lane` can currently produce for a governed provider run,
/// because such a run admits no evaluator and no strong verifier — is released
/// under [`LaneEvidenceClass::ExploratoryFinding`], which I21.4 defines as
/// explicitly *not* a confirmation and as requiring no registration. A
/// confirmatory release on this path additionally requires a committed
/// registration, attested exposure coverage over every mandatory channel and
/// blinded deliveries, none of which a single provider run can have.
///
/// # Errors
///
/// Returns the [`LaneRegistrationError`]-derived [`InquiryError`] when the
/// discipline refuses, and [`InquiryError::IntegrityMismatch`] when the release
/// it produced does not describe the evidence this record actually holds. The
/// check is by content: the released evidence revision, the delivered handle
/// count and the fence are compared against the freeze, the admissibility
/// disposition and the profile, so a release that is merely produced and
/// discarded cannot pass.
fn run_lane_discipline(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
    admissibility: &[SourceAdmissibilityRecord],
    evidence_freeze: &EvidenceFreeze,
) -> Result<LaneDisciplineOutcome, InquiryError> {
    let mut discipline = InquiryLaneDiscipline::open(profile.clone())?;
    let delivered_handles: BTreeSet<String> = admissibility
        .iter()
        .filter(|record| record.eligibility == SourceEligibility::Eligible)
        .map(|record| record.record.handle.clone())
        .collect();
    revalidate_lane_discipline(&discipline, observation)?;
    let current_fence = &profile.state_fence;
    let release = discipline.release_outcome_material(
        &evidence_freeze.digest,
        &delivered_handles,
        current_fence,
    )?;
    let Some(released) = release.exploratory_release() else {
        // A confirmatory release on this path is a real authorization over a
        // committed registration. It is not a failure, but this run has no claim
        // to close from it here, so the record is refused rather than published
        // with an authorization nothing consumed.
        return Err(InquiryError::UnknownVocabulary {
            field: "lane_discipline.confirmatory_release",
        });
    };
    // The release is compared against the record by content, not by timestamp or
    // by a caller boolean: the same evidence revision, the same count of
    // delivered handles, the same fence. `build_exploratory_release` digests the
    // sorted handle set, so the digest is recomputed here from the same
    // independent source — the admissibility disposition — rather than read back
    // from the release being checked.
    let mut handle_preimage = String::from("lane-delivered-handles/v1;");
    push_count(
        &mut handle_preimage,
        "delivered_handles",
        delivered_handles.len(),
    );
    for handle in &delivered_handles {
        push_field(&mut handle_preimage, "delivered_handle", handle);
    }
    if released.evidence_class != LaneEvidenceClass::ExploratoryFinding
        || released.evidence_revision_digest != evidence_freeze.digest
        || released.delivered_handle_count != delivered_handles.len()
        || released.delivered_handle_digest != freeze(&handle_preimage)
        || released.state_fence != profile.state_fence
    {
        return Err(InquiryError::IntegrityMismatch {
            field: "lane_discipline.exploratory_release",
        });
    }
    let result_id = format!("exploratory-finding/{}", observation.evidence_set_id);
    let finding = discipline.record_exploratory_finding(
        &result_id,
        &evidence_freeze.digest,
        observation.assessment_time_ms,
        current_fence,
    )?;
    // The finding the discipline stored is re-proved against what this record is
    // about to publish, so the class published is the class the discipline
    // recorded and not a value recomputed beside it.
    if finding.evidence_class() != LaneEvidenceClass::ExploratoryFinding
        || finding.inquiry_id != observation.inquiry_id
        || finding.profile_digest != profile.integrity_digest
        || finding.evidence_revision_digest != evidence_freeze.digest
        || finding.produced_under_grade != profile.evidence_grade
        || finding.produced_under_lane != profile.lane
        || finding.state_fence != profile.state_fence
    {
        return Err(InquiryError::IntegrityMismatch {
            field: "lane_discipline.exploratory_finding",
        });
    }
    let mut outcome = LaneDisciplineOutcome {
        evidence_class: LaneEvidenceClass::ExploratoryFinding,
        result_id,
        inquiry_id: finding.inquiry_id.clone(),
        profile_id_and_revision: profile.profile_id_and_revision(),
        profile_digest: finding.profile_digest.clone(),
        produced_under_grade: finding.produced_under_grade,
        produced_under_lane: finding.produced_under_lane,
        evidence_revision_digest: finding.evidence_revision_digest.clone(),
        delivered_handle_digest: released.delivered_handle_digest.clone(),
        delivered_handle_count: released.delivered_handle_count,
        state_fence: finding.state_fence.clone(),
        recorded_at_ms: finding.recorded_at_ms,
        digest: String::new(),
    };
    outcome.digest = outcome.compute_digest();
    Ok(outcome)
}

/// Revalidates the current fence and profile on the release edge (I21.4 item 6).
///
/// I21.4 requires that queued execution and a resume present the fence and the
/// profile revision the work was admitted under, and that a restart cannot
/// create a fresh registration with a backdated claim. This is that check, on
/// the edge that actually authorises a release, so it is reached by every run
/// rather than by a caller that may skip it.
///
/// `revalidate` re-proves the profile's own integrity preimage and the exposure
/// ledger's, refuses a fence other than the one this profile revision was frozen
/// under, and re-checks that the active registration, when there is one, still
/// binds this revision. The fence presented is the run-bound allowlist's own
/// sealed State Fence: it was sealed by the requester at submission and is a
/// separate object from the profile that names it, so this compares the
/// submitted binding against the revision resolved from it rather than a value
/// against itself. It reads no clock, and the registration history is
/// append-only, so no restart can substitute a newer registration for an older
/// one.
///
/// # Errors
///
/// Returns the [`LaneRegistrationError`]-derived [`InquiryError`] when the
/// presented fence is stale, the profile or ledger fails its own integrity
/// re-proof, or the active registration binds another profile revision.
fn revalidate_lane_discipline(
    discipline: &InquiryLaneDiscipline,
    observation: &InquiryObservation,
) -> Result<(), InquiryError> {
    discipline.revalidate(&observation.reference_manifest.state_fence)?;
    Ok(())
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
/// The kind is a function of that one reference text, not of the shape the
/// composition root happens to mint today. A candidate whose handle is a
/// syntactically valid absolute URL reaches [`UnadmittedReferenceKind::LocatorUrl`]
/// and one that carries a line anchor or range reaches
/// [`UnadmittedReferenceKind::LineSpan`], because both are reference identities
/// I21.7 names and neither is an artifact handle. Which candidates the run
/// actually produces is the composition root's projection and is not decided
/// here; what is decided here is that a reference of either shape is refused and
/// retained rather than typed as a handle.
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
///
/// The line-range arm runs before the shared locator classification, because a
/// line range is a position inside a reference rather than a reference identity
/// of its own kind: `README.md:12-40` classifies as an external URI under
/// `classify_locator` (the `README.md` prefix is a valid RFC 3986 scheme token),
/// and reporting that as a URL would name the wrong acquisition path for a
/// spelling that is a line range. [`line_span_shape`] is the single reader of
/// that grammar and it declines every spelling it cannot decide.
///
/// # The observed set is the whole reference surface, not one field
///
/// A source identity is a reference I21.7 names, and so is everything a record
/// built from it carries: its locator, its retained raw-evidence artifact
/// handle, each of its citation edges and each of its span anchors. Before this
/// revision this function looked at `candidate.handle` and nothing else, so a
/// record whose *handle* was admitted and whose *locator* was
/// `https://attacker.example/paper` produced no diagnostic at all — the URL was
/// neither refused nor retained, and the eligibility decision in
/// [`crate::source_admissibility::decide`] did not look at it either, so it rode
/// into the evidence set on an admitted handle. That is precisely the sentence
/// A1 forbids. The observed set is now read through the one
/// [`crate::source_admissibility::record_references`] reader, and the verdict
/// through the one
/// [`crate::source_admissibility::admits_record_reference`] predicate, so the
/// retained diagnostic and the eligibility decision cannot disagree about a
/// reference: the two now call the same functions on the same record.
///
/// The candidate-handle arm keeps its own richer reason vocabulary — stale and
/// revoked is a distinct fact here, and the line-range arm names a shape the
/// shared reader deliberately does not — but it no longer decides admission on
/// its own: it is the same `manifest.allows` call, reached through
/// [`crate::source_admissibility::admits_record_reference`], so the two agree by
/// construction rather than by review.
///
/// The two arms are **siblings over one loop, not one arm and its tail.** Each
/// candidate is judged for its own handle and for every reference its record
/// presents, and each unadmitted reference produces its own diagnostic whether or
/// not the handle beside it was admitted. Nesting the record arm inside the
/// handle arm — so that an admitted handle `continue`d past it — made the record
/// references unreachable for exactly the records A1 is about: one whose source
/// identity the manifest *does* declare while its artifact handle is absent.
/// Refusing is `decide`'s job and it was already correct; retention was the half
/// that silently dropped the text, which is why "neither refused nor retained" is
/// the defect and not merely an unhelpful diagnostic.
fn reference_firewall(
    observation: &InquiryObservation,
    records: &[SourceAdmissibilityRecord],
) -> Result<Vec<UnadmittedReference>, InquiryError> {
    let manifest = &observation.reference_manifest;
    let mut diagnostics = Vec::new();
    let mut seen = BTreeSet::new();
    // The record a candidate projected into, so a record surface is classified
    // against the same record whose eligibility was just decided. `assess_sources`
    // emits one record per candidate in candidate order, and this is reached only
    // from `record` after that call, so the pairing is positional by construction
    // rather than by a lookup that could silently miss.
    for (candidate, admissibility) in observation.candidates.iter().zip(records.iter()) {
        if !seen.insert(candidate.handle.clone()) {
            continue;
        }
        let presented = PresentedReference {
            surface: RecordReferenceSurface::CandidateHandle,
            reference: candidate.handle.clone(),
        };
        if !admits_record_reference(&presented, manifest) {
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
            } else {
                // Admitted references already left the loop above, so every
                // reference reaching here is unadmitted and the only question left
                // is which identity it presents as. The admission decision itself was
                // taken by `admits_record_reference`, not here, which is why this arm
                // no longer re-tests it.
                if let Some(shape) = line_span_shape(&candidate.handle) {
                    (UnadmittedReferenceKind::LineSpan, line_span_reason(shape))
                } else {
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
                }
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
        // The references the record built from that candidate presents. This runs
        // for **every** candidate, not only for one whose own handle was
        // unadmitted, and it is a sibling of the handle arm above rather than a
        // continuation of it. Scoping it behind that arm's `continue` is what
        // made the record's references unreachable whenever the handle was
        // admitted — which is exactly the A1 case: a source identity the manifest
        // declares while the record still presents an artifact handle it never
        // declared. `decide` refuses such a record through
        // `SourceAdmissibilityReason::ReferenceNotAdmitted`, but nothing else on
        // this path retains the text, so the reference would be neither refused
        // nor retained and an absent artifact handle would simply disappear.
        // Running both arms per candidate also keeps a retained handle and a
        // retained record reference two diagnostics a reader can tell apart,
        // instead of one that has silently swallowed the other.
        diagnostics.extend(retain_record_references(
            observation,
            &admissibility.record,
            manifest,
        )?);
    }
    Ok(diagnostics)
}

/// Retains every reference one vetted record presents that the run-bound
/// manifest does not admit.
///
/// This is the demotion half of I21.7 for a record that already passed its
/// source-identity check. The record is refused for evidentiary use by
/// [`crate::source_admissibility::decide`] — an unadmitted reference is
/// [`crate::source_admissibility::SourceAdmissibilityReason::ReferenceNotAdmitted`],
/// which is blocking, so the record cannot enter the portfolio, the coverage
/// account or the evidence freeze — and the reference text is retained *here* as
/// the typed untrusted diagnostic, so the Governor sees the observation instead
/// of a dropped string.
///
/// Which references exist is read from
/// [`crate::source_admissibility::record_references`] and whether the manifest
/// admits them from
/// [`crate::source_admissibility::admits_record_reference`], so the set retained
/// here is exactly the set the eligibility decision refused. A reason here names
/// the lever that can change the verdict and, unlike the candidate-handle arm,
/// names the *surface* it was found on: a URL on a locator is admitted by
/// `url_handles`, a citation edge and a receipt handle are admitted by the
/// handle lists, and those are different lists for different surfaces, so a
/// reason that named one where the other applies would send a reader to a list
/// that cannot change the verdict.
///
/// This runs for every candidate rather than only for one whose own handle was
/// unadmitted. A record whose source identity the manifest declares but whose
/// receipt handle it does not is refused by `decide` and must still be retained
/// here, and the receipt handle is exactly that reference: a bare transport
/// digest is opaque, so it is admitted by the handle lists and by nothing else.
///
/// Each surface's kind is the same [`classify_locator`] projection the
/// candidate-handle arm uses, with the line-range arm first for the same reason it
/// is first there: `README.md:12-40` reads as an external URI to the shared
/// classifier, and naming that a URL would point a reader at the wrong
/// acquisition path for a spelling that is a line range.
fn retain_record_references(
    observation: &InquiryObservation,
    record: &SourceRecord,
    manifest: &AllowedReferenceManifest,
) -> Result<Vec<UnadmittedReference>, InquiryError> {
    let mut diagnostics = Vec::new();
    let mut seen = BTreeSet::new();
    for presented in record_references(record) {
        // A repeat of a reference already retained for this record is one
        // observation, not two: `SourceRecord::new` already rejects a repeated
        // citation edge, but the same text on two surfaces is a different
        // observation and is kept, because the surface is what tells a reader
        // which lever to use.
        if !seen.insert((presented.surface, presented.reference.clone())) {
            continue;
        }
        if admits_record_reference(&presented, manifest) {
            continue;
        }
        let class = classify_locator(&presented.reference);
        let line_range = presented.surface == RecordReferenceSurface::SpanAnchor
            && line_span_shape(&presented.reference).is_some();
        let (kind, reason) = if line_range {
            // The line-range arm runs first for the reason it runs first on the
            // candidate handle: `README.md:12-40` classifies as an external URI
            // to the shared reader, and reporting that as a URL would name the
            // wrong acquisition path for a spelling that is a line range. The
            // lever stated here is the one this path actually reads. A span
            // anchor is a coordinate into the admitted source, so it is not a
            // citable identity and no handle entry admits it; what can admit it
            // is an exact `url_handles` entry for the exact text, which is the
            // same lever the shared classifier puts this spelling on.
            (
                UnadmittedReferenceKind::LineSpan,
                format!(
                    "the record's {} carries a line range over a handle; a line range is a \
                     position inside a reference rather than an identity of its own, and the only \
                     lever that admits this exact text here is an exact url_handles entry",
                    presented.surface.wire_name()
                ),
            )
        } else {
            let kind = match class {
                LocatorClass::ExternalUri { .. } => UnadmittedReferenceKind::LocatorUrl,
                LocatorClass::InternalUri { .. } => UnadmittedReferenceKind::InternalOwnedReference,
                LocatorClass::OpaqueHandle => UnadmittedReferenceKind::ArtifactHandle,
                LocatorClass::MalformedOrAmbiguous { .. } => {
                    UnadmittedReferenceKind::AmbiguousReference
                }
            };
            let observed = match class {
                LocatorClass::ExternalUri { .. } => {
                    "presents as an absolute external URL, which carries authority and therefore \
                     needs an exact url_handles entry"
                }
                LocatorClass::InternalUri { .. } => {
                    "is an internally owned identity, which is not a source identity and is \
                     admitted only by the manifest's source, evidence and artifact handles"
                }
                // An opaque handle reaches this arm on an identity surface: on the
                // two coordinate surfaces an opaque spelling carries no authority
                // of its own and is admitted above, while a candidate handle, a
                // citation edge and a receipt handle are all identities the
                // manifest must list. Naming the handle lists here is therefore the
                // correct lever on each of them and the only one.
                LocatorClass::OpaqueHandle => {
                    "is an opaque handle, and an opaque handle is admitted only where it is a \
                     source identity the manifest lists in its source, evidence or artifact handles"
                }
                LocatorClass::MalformedOrAmbiguous { reason } => {
                    // The reason names the rule that failed, never the text: an
                    // unclassifiable spelling has no acquisition path at all, so
                    // the text itself has to become classifiable first and no list
                    // entry can do that.
                    return retained_unreadable_reference(
                        observation,
                        manifest,
                        &presented,
                        kind,
                        reason.wire_name(),
                    );
                }
            };
            (
                kind,
                format!(
                    "the record's {} {observed}; it is retained untrusted and cannot support a \
                 citation, an evidence edge or a precision claim in this run",
                    presented.surface.wire_name()
                ),
            )
        };
        diagnostics.push(UnadmittedReference::observe(
            &observation.inquiry_id,
            &observation.evidence_set_id,
            &presented.reference,
            kind,
            &reason,
            &manifest.state_fence,
        )?);
    }
    Ok(diagnostics)
}

/// Retains one reference the shared classifier cannot read as a classifiable
/// locator.
///
/// Split out of [`retain_record_references`] because this arm ends the loop
/// iteration rather than producing a `(kind, reason)` pair for it, and folding
/// the `?` into a `return` inside a `match` arm of that loop is the shape this
/// crate does not use elsewhere.
fn retained_unreadable_reference(
    observation: &InquiryObservation,
    manifest: &AllowedReferenceManifest,
    presented: &PresentedReference,
    kind: UnadmittedReferenceKind,
    ambiguity: &'static str,
) -> Result<Vec<UnadmittedReference>, InquiryError> {
    Ok(vec![UnadmittedReference::observe(
        &observation.inquiry_id,
        &observation.evidence_set_id,
        &presented.reference,
        kind,
        &format!(
            "the record's {} is not a classifiable reference: {ambiguity}; no manifest list can \
             admit it, because the text itself has to become a classifiable reference first",
            presented.surface.wire_name()
        ),
        &manifest.state_fence,
    )?])
}

/// The closed shape of one recognised line-range reference spelling.
///
/// The shape is carried rather than the text: this module's residue convention
/// is to name the observed fact and never echo the supplied reference, and the
/// two shapes are the only thing a consumer acts on differently.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineSpanShape {
    /// `<handle>:<line>` — one line anchor.
    Single,
    /// `<handle>:<first>-<last>` — an inclusive line range, `first <= last`.
    Range,
}

/// Recognises a line anchor or line range in one observed reference, or declines.
///
/// This is the single reader of that grammar, and it declines every spelling it
/// cannot decide rather than guessing. Three conditions, each stated because
/// dropping it would re-type something that is not a line range:
///
/// 1. The text is `<precedent>:<anchor>` at its **last** colon, and the
///    precedent is non-empty. The anchor is decimal digits, optionally a
///    `-`-separated inclusive pair with `first <= last`. A range spelled the
///    other way round is not a range, and no upper bound is assumed.
/// 2. The **precedent** classifies as [`LocatorClass::OpaqueHandle`], so a
///    colon the shared classifier already reads as a scheme separator is never
///    re-read as a line separator. This is what keeps `https://host:8080` a
///    URL rather than a line anchor: its precedent is an external URI.
/// 3. The **whole** text does not classify as [`LocatorClass::InternalUri`], so
///    a scheme a named owner mints keeps its opaque part. `provider-artifact:12`
///    is an internally owned handle, not the twelfth line of anything, and this
///    is the condition that says so.
///
/// Condition 2 alone would already re-type `README.md:12-40` away from the
/// external URI `classify_locator` calls it, which is the point: the prefix
/// there is a valid RFC 3986 scheme token and nothing more, and a position
/// inside a reference is a line range rather than a URL. The live
/// `provider-artifact:<sha256>` candidate is unaffected by all three.
fn line_span_shape(text: &str) -> Option<LineSpanShape> {
    let colon = text.rfind(':')?;
    let (precedent, anchor) = text.split_at(colon);
    let anchor = anchor.strip_prefix(':')?;
    if precedent.is_empty() || !matches!(classify_locator(precedent), LocatorClass::OpaqueHandle) {
        return None;
    }
    if matches!(classify_locator(text), LocatorClass::InternalUri { .. }) {
        return None;
    }
    match anchor.split_once('-') {
        Some((first, last)) => match (first.parse::<u64>(), last.parse::<u64>()) {
            (Ok(first), Ok(last)) if first <= last => Some(LineSpanShape::Range),
            _ => None,
        },
        None => decimal_exact(anchor).then_some(LineSpanShape::Single),
    }
}

/// Whether `value` is one or more ASCII decimal digits and nothing else.
///
/// A hand-rolled digit test rather than a numeric parse, because the single-line
/// shape never needs a value: only the shape is load-bearing, and parsing it
/// would imply a base and a bound the grammar does not state.
fn decimal_exact(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// The reason a line-range reference is retained unadmitted.
///
/// As every reason on this path does, it names the list that can change the
/// verdict — here the same handle allowlist every other arm names, because
/// `line_span_shape` chose the *kind* and takes no part in the admission
/// decision — and it states the second fact a reader needs, that a line range
/// is not a citable identity on this path at all.
fn line_span_reason(shape: LineSpanShape) -> String {
    let observed = match shape {
        LineSpanShape::Single => "a single line anchor over a handle",
        LineSpanShape::Range => "an inclusive line range over a handle",
    };
    format!(
        "this reference carries {observed}; a line range is not a citable identity on this path, \
         and the only lever here is the manifest's source, evidence and artifact handle allowlist, \
         which admits the exact text as a handle or not at all"
    )
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

/// The claim audit this run actually produced, plus the coverage map that says
/// whether it audited everything the frozen owner admitted.
///
/// The composite previously carried `None` here and recorded the reason: nothing
/// in this repository produced an [`AuditedClaim`], so the per-claim audit trail
/// had no producer and was unreachable from any production entry point. This is
/// that producer, and it is a real one: it derives the audited claims from
/// already-admitted material — the reference firewall, the source-admissibility
/// dispositions and the coverage accounting above all ran on the same
/// [`InquiryObservation`] before this — runs the existing
/// [`audit_claim`] over each, and binds a [`ClaimAuditRecord`] per verdict.
///
/// # The claim this run releases
///
/// One material claim per **admitted, citable** source handle: "this retained
/// material is evidence the inquiry's question could be decided from, within
/// this run's admitted scope". That is the only material statement an admitted
/// provider run actually asserts, and it is exactly the statement I21.8 requires
/// to carry a resolved chain. A handle the manifest revoked, never admitted, or
/// admits without a provable record produces no claim: there is nothing released
/// about it to audit, and manufacturing a verdict for it would be the fabricated
/// provenance this crate refuses to mint.
///
/// # Why the coverage map is not the released list read twice
///
/// [`MaterialClaimRoster::derive`] recomputes the expected roster from the
/// portfolio and the frozen manifest, so it cannot shrink when a verdict is
/// dropped. [`ClaimCoverageMap::build`] then compares that roster against the
/// claim identities actually present in the verdicts, and
/// [`crate::evidence_portfolio::require_complete_claim_coverage`] refuses a
/// complete-audit claim while the two differ. An omitted claim is therefore a
/// named, observable defect rather than a self-consistent list.
struct RunClaimAudit {
    /// One bound record per audited material claim, in canonical claim order.
    records: Vec<ClaimAuditRecord>,
    /// The coverage map over the independently derived expected roster.
    coverage: ClaimCoverageMap,
    /// Expected material-claim identities with no released verdict, sorted.
    ///
    /// Kept beside the records rather than derived from them on demand so the
    /// terminal record and this struct cannot disagree about which claim is
    /// unaudited.
    unaccounted: Vec<String>,
}

/// Runs the per-claim audit over every material claim this run releases and
/// builds the coverage map that gates a complete-audit claim.
///
/// # Errors
///
/// Returns [`InquiryError::Portfolio`] when the authorized manifest, the
/// audit reference binding, the frozen claim identity, the audit itself or the
/// coverage map cannot be built or re-proved. A run that cannot audit its
/// material claims produces no record at all rather than a record whose audit
/// field is silently absent.
fn claim_audit_for_run(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
    account: &CoverageAccount,
    admissibility: &[SourceAdmissibilityRecord],
) -> Result<RunClaimAudit, InquiryError> {
    let portfolio = audit_portfolio(profile, account, admissibility);
    let binding = audit_binding(observation, account, &portfolio)?;
    let roster =
        MaterialClaimRoster::derive(&portfolio, &binding).map_err(InquiryError::AuditBinding)?;
    let mut records = Vec::new();
    let mut verdicts: Vec<ClaimVerdict> = Vec::new();
    for claim_id in &roster.claim_ids {
        let claim = released_material_claim(observation, claim_id);
        // A claim with no verifiable frozen identity can never be released as
        // supported, so the identity is frozen here from the statement the run
        // actually releases rather than being trusted as a caller-supplied value.
        let identity = claim.freeze_identity().map_err(InquiryError::from)?;
        let claim = AuditedClaim {
            frozen_identities: vec![identity],
            excerpts: retained_excerpts(observation, claim_id),
            ..claim
        };
        // The released wording is captured ONCE, before the audit, from the same
        // value the claim carries. Reading it back off `claim.statement` after
        // the verdict is built would be the post-audit edit this field exists to
        // detect: whatever the release actually says is the bytes that were
        // audited, and nothing recomputes them afterwards.
        let released_statement = claim.statement.clone();
        let verdict = crate::evidence_portfolio::audit_claim_with_excerpts(
            &claim,
            &portfolio,
            &binding,
            observation.assessment_time_ms,
            &observation.retained_revisions,
        );
        records.push(ClaimAuditRecord::bind(
            &observation.inquiry_id,
            profile,
            binding.allowed_references(),
            &observation.evidence_set_id,
            &released_statement,
            verdict.clone(),
        )?);
        verdicts.push(verdict);
    }
    let coverage = ClaimCoverageMap::build(&roster, &binding, &verdicts)
        .map_err(InquiryError::AuditBinding)?;
    let unaccounted = crate::evidence_portfolio::require_complete_claim_coverage(&coverage)
        .err()
        .unwrap_or_default();
    Ok(RunClaimAudit {
        records,
        coverage,
        unaccounted,
    })
}

/// Assembles the audited [`EvidencePortfolio`] over the exact records this run
/// already assessed.
///
/// The records are the same [`SourceRecord`] values the source-admissibility
/// stage decided on, carried whole rather than rebuilt, so the portfolio the
/// audit reads is the portfolio the release published and not a second
/// projection of it. The coverage accounting is the one the run already opened.
fn audit_portfolio(
    profile: &InquiryProtocolProfile,
    account: &CoverageAccount,
    admissibility: &[SourceAdmissibilityRecord],
) -> EvidencePortfolio {
    let mut records = BTreeMap::new();
    for record in admissibility {
        if !record.is_admitted_to(profile) {
            continue;
        }
        records.insert(record.record.handle.clone(), record.record.clone());
    }
    EvidencePortfolio {
        inquiry_digest: profile.admitted_inquiry_digest.clone(),
        records,
        coverage: account.clone(),
    }
}

/// Binds the audit job to the exact run and State Fence it may judge under.
///
/// The authorized manifest is frozen over exactly the material the run holds:
/// the inquiry digest it was admitted under, the declared denominator, the
/// canonical commitment of every record the audit may cite, the coverage
/// accounting the release published, and the citable allowlist. It is frozen
/// *here*, from admitted material, rather than being taken from a caller, so
/// the authorization the audit ran under is the one the run's own evidence
/// describes and not a claim about one.
fn audit_binding(
    observation: &InquiryObservation,
    account: &CoverageAccount,
    portfolio: &EvidencePortfolio,
) -> Result<AuditReferenceBinding, InquiryError> {
    let run_manifest = &observation.reference_manifest;
    let mut sources = BTreeMap::new();
    let mut allowlist: Vec<String> = Vec::new();
    for (handle, record) in &portfolio.records {
        allowlist.push(handle.clone());
        sources.insert(
            handle.clone(),
            ManifestSource {
                record_digest: record.digest().map_err(InquiryError::from)?,
                content_digest: record.content_digest.clone(),
                transformed_from: record.transformed_from.clone(),
            },
        );
    }
    if allowlist.is_empty() {
        // `AuthorizedManifest::freeze` refuses an empty allowlist, and an
        // unadmitted run has no citable material to audit. Refusing the whole
        // projection here is the honest answer: this is not a failed audit of a
        // release, it is a release with nothing released.
        return Err(InquiryError::UnknownHandle {
            field: "claim_audit.allowlist",
        });
    }
    let authorized = AuthorizedManifest::freeze(AuthorizedManifestParams {
        inquiry_digest: observation.inquiry_digest.clone(),
        denominator_digest: observation.denominator_digest.clone(),
        sources,
        dependence_edges: BTreeSet::new(),
        coverage_digest: account.digest(),
        grade_limits: Vec::new(),
        counterevidence: Vec::new(),
        conflicts: Vec::new(),
        unknowns: Vec::new(),
        allowlist,
        revoked: Vec::new(),
        disclosure: observation.disclosure,
        // The audit is judged at the same instant the coverage accounting was
        // closed, so the authorization cannot outlive the evidence it covers.
        expires_ms: observation.assessment_time_ms.saturating_add(1).max(1),
        revision: 1,
    })
    .map_err(InquiryError::from)?;
    AuditReferenceBinding::bind(
        authorized,
        run_manifest.clone(),
        run_manifest.state_fence.clone(),
    )
    .map_err(InquiryError::AuditBinding)
}

/// Projects the one material claim an admitted source handle releases.
///
/// The statement is data, never executed: it names the question the inquiry is
/// asking, the exact artifact commitment the run retained, and the scope the
/// run was admitted for, so the audit judges a claim about a specific artifact
/// under specific conditions rather than a bare assertion. The citation is the
/// handle itself, and the counterclaim list is empty: `counterevidence_of` is
/// not part of the canonical [`SourceRecord`] digest, so it is not trusted
/// frozen data and a contradiction is never inferred from its presence or its
/// absence.
fn released_material_claim(observation: &InquiryObservation, claim_id: &str) -> AuditedClaim {
    AuditedClaim {
        claim_id: claim_id.to_owned(),
        statement: released_material_statement(observation, claim_id),
        material: true,
        domain: observation.scope.clone(),
        citations: vec![claim_id.to_owned()],
        precision: Vec::new(),
        counterclaim_ids: Vec::new(),
        unknown_refs: Vec::new(),
        frozen_identities: Vec::new(),
        opposition_relations: Vec::new(),
        excerpts: Vec::new(),
    }
}

/// The exact excerpt the released material statement offers as evidence for one
/// admitted handle.
///
/// The span is sliced out of the **retained original bytes**, not out of the
/// statement. That direction matters and the previous producer had it backwards:
/// it read a quoted run out of the claim's own sentence and then compared THAT
/// text with the source, which cannot detect a fabricated quotation, a cropped
/// negation or a page quote presented as a snippet, because the text being
/// checked was never claimed to come from the source in the first place.
///
/// What this returns is therefore a genuine offer to a careful reader: the exact
/// contiguous window of the admitted revision that backs the claim, offered with
/// its measured byte offset, so the verifier can check the position rather than
/// search for the bytes. A handle with no retained revision, or one whose bytes
/// are not text, produces no excerpt — and that is a reported state rather than
/// a skip, because the claim then has no verified excerpt at all, the
/// `excerpt_supports_requirement` obligation is `Unsatisfied`, and the residue
/// names the missing retention.
fn retained_excerpts(
    observation: &InquiryObservation,
    claim_id: &str,
) -> Vec<crate::admitted_excerpt::AdmittedExcerpt> {
    let Some(retained) = observation.retained_revisions.get(claim_id) else {
        return Vec::new();
    };
    let Some(text) = retained.as_text() else {
        return Vec::new();
    };
    let Some((offset, quote)) = evidenced_span(text) else {
        return Vec::new();
    };
    crate::admitted_excerpt::AdmittedExcerpt::offer(
        crate::admitted_excerpt::AdmittedExcerptParams {
            source_handle: claim_id.to_owned(),
            excerpt: quote,
            // The offset is measured from the retained bytes here, so asserting
            // it is a measurement rather than a claim. This is the strong form of
            // `ExcerptPosition`: the verifier then confirms the admitted revision
            // holds exactly these bytes AT this offset, and a revision fetched
            // from a different place fails the check instead of passing it by
            // accident.
            position: crate::admitted_excerpt::ExcerptPosition::ByteOffset { offset },
        },
    )
    .ok()
    .into_iter()
    .collect()
}

/// The contiguous window of an admitted revision that a released material claim
/// cites, and the byte offset it was measured at.
///
/// The window is the **whole admitted revision** when the revision is a single
/// contiguous passage, and the first complete line of a longer one otherwise.
/// Both are honest: this is a citation of a retained source revision, and the
/// evidence for it is the revision's own text, so the exact bytes offered are
/// read out of the revision rather than composed by this function. It is NOT a
/// search for a sentence that would flatter the claim — nothing about the
/// claim's wording selects which span is returned, so the check that follows
/// compares the offered bytes with the revision and the revision with the
/// admission, and neither step can be satisfied by choosing flattering text.
///
/// `(None, ...)` for a revision that holds no non-blank text at all. That yields
/// no excerpt, which the requirement recorder reports rather than treats as
/// satisfied.
fn evidenced_span(text: &str) -> Option<(usize, String)> {
    let trimmed = text.trim_matches(|character: char| character.is_whitespace());
    if trimmed.is_empty() {
        return None;
    }
    // The leading whitespace run was removed, so the offset has to skip it to
    // name a position in the ORIGINAL bytes rather than in the trimmed copy.
    let offset = text.len() - trimmed.len();
    Some((offset, trimmed.to_owned()))
}

/// The exact released wording of one material claim.
///
/// `claim_id` is the admitted source handle this run is releasing a material claim
/// about, and the statement names it, so the wording a reader receives is
/// self-identifying. It was previously threaded in and dropped, which left the
/// released sentence the *same bytes for every claim in the run*: a record with
/// three admitted sources published three audits that judged one indistinguishable
/// sentence, so a consumer holding the delivered text could not tell which claim it
/// was, and a post-audit edit to one claim's wording was indistinguishable from an
/// edit to another's. Naming the artifact also makes the wording match the
/// evidence it is released with — the handle is the claim's only citation and the
/// key its retained original is filed under — so the sentence cannot promise a
/// retained artifact without naming the one that was retained.
///
/// One function so the statement [`released_material_claim`] publishes, the
/// identity frozen for the audit, the statement bound into the resulting
/// [`ClaimAuditRecord`], and any span derived from it all come from the **same**
/// bytes. Two copies of this format string would let a later edit change the
/// released wording while the audit kept pointing at the old one, which is
/// exactly the post-audit-material-edit failure the issue names.
fn released_material_statement(observation: &InquiryObservation, claim_id: &str) -> String {
    format!(
        "the retained provider artifact `{}` for inquiry {} contains evidence the question `{}` \
         could be decided from within the admitted scope `{}`",
        claim_id, observation.inquiry_id, observation.question, observation.scope
    )
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

/// Materialises the obligations that the frozen denominator makes necessary.
///
/// Planning is receding-horizon: only what current observations can determine is
/// materialised, and an information-dependent future stays `Stub` until the
/// upstream result arrives.
///
/// Three member classes exist on this path, and the class is decided by the
/// certificate the run actually holds, not by the caller's intent:
///
/// - a member this run resolved with admitted evidence that carries an exact
///   passage is **satisfied by that certificate** and lands `VERIFIED`;
/// - a member the run-bound manifest withholds is `INVALIDATED` with the cause;
/// - a member with no admitted evidence at all stays `STUB`.
///
/// A satisfied obligation is retained rather than dropped, for the same reason an
/// invalidated one is: I21.5 keeps what became true and what it cost visible, and
/// [`TaskGraphCompilationInputs::materialisable`] excludes every terminal
/// obligation, so a verified member is never handed to the work graph as work.
///
/// The satisfied obligation goes `STUB` -> `VERIFIED` without passing through
/// `READY`, `RUNNING` or `SUBMITTED`, and that skip is deliberate rather than a
/// missing step: this record is built after the run, so those three states were
/// never observed here and are not narrated. The recorded status is the
/// certificate verdict, which is the one thing I21.5 says settles an
/// obligation, and the same reasoning is why `resources_spent` below is `0`.
///
/// # Why a revoked member's obligation is invalidated rather than re-materialised
///
/// I21.5: "Invalidated obligations are not deleted: they retain the invalidating
/// cause, spent resources and any reusable artifacts, so that repeated planning
/// cost becomes visible." Exactly one member class on this path is decidable now
/// rather than pending, and leaving it pending is a real defect rather than a
/// conservative default.
///
/// [`coverage_account`] opens the denominator over the manifest's source,
/// evidence and artifact handles and does not apply the manifest's revocation
/// list, while [`AllowedReferenceManifest::allows`] documents that a handle the
/// manifest admits *and* lists as stale or revoked is never admitted. Such a
/// member therefore stays an open denominator member on every run, and the very
/// same handle delivered as a candidate is refused outright by
/// [`crate::source_admissibility::SourceAdmissibilityReason::ManifestEntryRevoked`].
/// A fresh work obligation for it each run is the repeated planning cost I21.5
/// names, and no admission of this manifest can ever satisfy it.
///
/// The obligation is therefore retained as `INVALIDATED` with that cause instead
/// of staying `STUB`. The member is **not** removed from the denominator: the
/// coverage receipt, the coverage research debt, the preserved explicit unknown
/// and the preserved next probe all keep reading it as unresolved, so nothing
/// here narrows a completeness or absence claim, and the obligation stays in
/// [`TaskGraphCompilationInputs`] and in the next probe's obligation references so
/// the spent planning stays visible.
///
/// `resources_spent` is `0` and `reusable_artifacts` is empty because the
/// obligation is materialised and invalidated inside one record and was never
/// dispatched; both are the honest values for this transition, not defaults
/// standing in for a measurement. Nothing is asserted here that the observation
/// does not carry: the trigger is the run-bound manifest's own revocation list,
/// which this crate already reads on the candidate path.
///
/// # The certificate check is what decides, and it runs first
///
/// The check is not a post-hoc read: it is consulted before the status is
/// decided, and the answer is what moves the obligation. A member the run
/// withheld is invalidated because the certificate check refused it *and* the
/// manifest withholds the handle; a member the run resolved is `VERIFIED` only
/// because the check accepted the certificate it presented. Neither status could
/// be reached without that answer.
///
/// MEASURED, and stated so no one reads more into this than it is: on the
/// `eliot-mod-research` path no candidate handle is a frozen-denominator handle
/// today — the composition root mints `provider-artifact:<raw stdout digest>`,
/// which no manifest declares — and `candidate_source_record` records
/// `evidence_spans: Vec::new()`, so the satisfied arm does not fire on any
/// admitted material that exists now and every live obligation is `STUB` or
/// `INVALIDATED`. The arm is reachable, and correct, the moment an admitted
/// candidate carries a declared handle with an exact passage; nothing here was
/// faked to make it fire.
fn open_obligations(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
    account: &CoverageAccount,
    admissibility: &[SourceAdmissibilityRecord],
) -> Result<Vec<InquiryObligation>, InquiryError> {
    let manifest = &observation.reference_manifest;
    // A member the run already resolved is an obligation too. Materialising only
    // the open members would make the satisfied class unreachable by
    // construction — an open member has, by definition, no admitted record — and
    // `AllowedReferenceManifest::allows` is the one existing admission predicate
    // that says whether a record's handle is a declared member, so it is the one
    // used here rather than a second membership test.
    let mut members: BTreeSet<String> = account.open_members().into_iter().collect();
    for record in admissibility {
        if manifest.allows(&record.record.handle) {
            members.insert(record.record.handle.clone());
        }
    }
    let mut obligations = Vec::new();
    for member in members {
        let mut obligation = InquiryObligation::new(InquiryObligationParams {
            obligation_id: format!("obl-{member}"),
            // The member is carried on the record, not only inside the identity
            // and the goal prose, so a reader holding the run's manifest and
            // admitted records can re-derive which certificate this obligation
            // was actually about and ask `is_verified_by_certificate` a real
            // question instead of reading the recorded status back.
            coverage_member: member.clone(),
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
        })?;
        // The certificate this run actually holds is presented and checked before
        // any state is decided, and the answer is what the state depends on.
        let presented = presented_acceptance_certificate(manifest, &member, admissibility)?;
        if !obligation.admit_acceptance_certificate(presented)
            && manifest
                .stale_or_revoked_handles
                .iter()
                .any(|revoked| revoked == &member)
        {
            obligation.invalidate(
                &format!(
                    "the run-bound manifest lists reference {member} as stale or revoked, so no \
                     admission of this manifest can resolve it and the acceptance certificate this \
                     obligation declared is not one the run holds; the member is retained as an open \
                     denominator member and this obligation is retained as INVALIDATED with the \
                     cause instead of being re-materialised as pending work on every run"
                ),
                0,
                Vec::new(),
            )?;
        }
        obligations.push(obligation);
    }
    Ok(obligations)
}

/// The acceptance-certificate kind this run actually holds for one obligation.
///
/// `member` is a frozen-denominator handle. The kind is read only from material
/// the run admitted, and it is read through the existing owners:
///
/// - the exact source identity is the run-bound manifest, which
///   [`InquiryGovernance::record`] has already re-proved through
///   [`AllowedReferenceManifest::validate`] before any of this runs, and which
///   [`AllowedReferenceManifest::allows`] answers for;
/// - the exact passage is the admitted evidence that supports an anchor for that
///   member, which exists only when an admitted, eligible source record for it
///   carries exact evidence spans. Each such record is re-proved through its own
///   owner, [`SourceAdmissibilityRecord::validate_integrity`], on the recorded
///   value before it is read — not by recomputing a fresh checksum over what is
///   held here.
///
/// So the presented kind is
/// [`AcceptanceCertificateKind::ExactSourceIdentityAndPassage`] when both halves
/// are present, and [`AcceptanceCertificateKind::ImmutableInputsAndRawMeasurements`]
/// when only the frozen handle is. The second spelling is a true statement about
/// what the run holds — an immutable input with no raw measurement for this
/// member — and it is deliberately not the kind the obligation declared, so
/// [`InquiryObligation::is_verified_by_certificate`] refuses it. A withheld
/// handle yields the same refusal, because a stale or revoked handle is not a
/// source identity at all.
///
/// # Errors
///
/// Returns the first integrity failure of an admitted record whose handle is
/// read for the passage test, rather than deciding on a record that no longer
/// re-proves its own digest.
fn presented_acceptance_certificate(
    manifest: &AllowedReferenceManifest,
    member: &str,
    admissibility: &[SourceAdmissibilityRecord],
) -> Result<AcceptanceCertificateKind, InquiryError> {
    if !manifest.allows(member) {
        return Ok(AcceptanceCertificateKind::ImmutableInputsAndRawMeasurements);
    }
    for record in admissibility {
        if record.record.handle != member || record.eligibility != SourceEligibility::Eligible {
            continue;
        }
        record.validate_integrity()?;
        if !record.record.evidence_spans.is_empty() {
            return Ok(AcceptanceCertificateKind::ExactSourceIdentityAndPassage);
        }
    }
    Ok(AcceptanceCertificateKind::ImmutableInputsAndRawMeasurements)
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
            &independence_shortfall(&portfolio.independence),
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

/// Commits the evidence freeze through the existing governed source-admission
/// owner, binding each admitted source's retained original to it.
///
/// This is the W2 producer, and it is deliberately a **producer of the existing
/// owner's records** rather than a new owner: every value it returns is a
/// [`GovernorSourceTransitionRequest`], which already had a digest domain, a
/// canonical preimage and a `validate_integrity` before this issue touched it. The
/// only new thing is that the request is now built by
/// [`SourceAdmissibilityRecord::transition_request_committing_freeze`], which
/// names the committed freeze and the retained original and refuses either that
/// does not re-prove itself.
///
/// It returns the retained originals **as well as** the requests, and that is one
/// traversal rather than two on purpose: the same commit binds the same revision,
/// so a second pass over the admissibility records would be a second place where
/// "which originals were committed" is decided, and the two could disagree without
/// any check firing. Carrying them beside the requests is what makes the retained
/// original on [`InquiryGovernance::retained_revisions`] the revision the
/// commitment was actually built from rather than a map a reader has to take on
/// trust.
///
/// A record whose original is missing produces no request and no retained entry
/// for that handle. That is the honest W2 outcome, not a hole: a source that was
/// admitted without its bytes persisted cannot have its admission committed, and
/// the run's own freeze still lists it, so the synthesis pack below reports it as
/// a published omission with [`crate::synthesis_input::PackLimitation::NoRetainedOriginal`]
/// rather than dropping it.
///
/// The eligibility filter is the same one [`evidence_freeze`] uses to build the
/// included set, so the committed members and the frozen members cannot disagree
/// about which sources are in the evidence set.
///
/// # Errors
///
/// Propagates every refusal of the existing owner's own builder: a retained
/// revision that is not the admitted record's own revision, a freeze that does not
/// include the source, a request whose own digest does not re-prove, and the
/// encoding refusal when the decision's source record has no canonical
/// commitment.
fn commit_freeze_through_source_admission(
    observation: &InquiryObservation,
    freeze: &EvidenceFreeze,
    admissibility: &[SourceAdmissibilityRecord],
) -> Result<
    (
        Vec<GovernorSourceTransitionRequest>,
        BTreeMap<String, crate::admitted_excerpt::RetainedSourceRevision>,
    ),
    InquiryError,
> {
    let mut requests = Vec::new();
    let mut retained_revisions: BTreeMap<String, crate::admitted_excerpt::RetainedSourceRevision> =
        BTreeMap::new();
    for record in admissibility {
        if record.eligibility != SourceEligibility::Eligible {
            continue;
        }
        let Some(retained) = observation.retained_revisions.get(&record.record.handle) else {
            continue;
        };
        requests.push(record.transition_request_committing_freeze(retained, freeze)?);
        retained_revisions.insert(record.record.handle.clone(), retained.clone());
    }
    Ok((requests, retained_revisions))
}

/// The admitted source records of one run, keyed by handle.
///
/// The same records the portfolio assembled and the freeze enumerated, carried
/// whole rather than rebuilt, so the synthesis pack resolves members against the
/// records the run published rather than a second projection of them.
fn admitted_records(admissibility: &[SourceAdmissibilityRecord]) -> BTreeMap<String, SourceRecord> {
    admissibility
        .iter()
        .filter(|record| record.eligibility == SourceEligibility::Eligible)
        .map(|record| (record.record.handle.clone(), record.record.clone()))
        .collect()
}

/// Commits the W2 evidence freeze and resolves the W3 synthesis pack from it.
///
/// W2: the freeze is committed through the existing governed source-admission
/// owner, and the retained original is bound to it there. Every request on this
/// path is built by `transition_request_committing_freeze`, so a run that did not
/// persist before synthesis produces **no** request at all for the sources whose
/// original it never retained — the plain `transition_request` builder still
/// exists for a pre-freeze proposal, and this path does not use it, because a
/// request that named no freeze is exactly the state W2 forbids admitting
/// synthesis from.
///
/// The committed-freeze proof is then re-derived from those same requests
/// through the owner's existing validator. It is not built from the freeze alone:
/// `CommittedFreeze::commit` takes the requests, so the proof exists only if every
/// one of them already carried this exact freeze.
///
/// W3 then resolves the pack from that committed freeze. The two live in one
/// function because the ORDER is the guarantee: a pack may only be resolved from
/// a freeze that a governed owner has already committed, so separating them into
/// two independently callable steps would make the ordering a convention.
#[allow(clippy::type_complexity)]
fn commit_freeze_and_resolve_synthesis_input(
    observation: &InquiryObservation,
    freeze: &EvidenceFreeze,
    admissibility: &[SourceAdmissibilityRecord],
    profile: &InquiryProtocolProfile,
    lane_discipline: &LaneDisciplineOutcome,
) -> Result<
    (
        Vec<GovernorSourceTransitionRequest>,
        BTreeMap<String, crate::admitted_excerpt::RetainedSourceRevision>,
        crate::synthesis_input::CommittedFreeze,
        crate::synthesis_input::SynthesisInputPack,
    ),
    InquiryError,
> {
    let (source_admission_requests, retained_revisions) =
        commit_freeze_through_source_admission(observation, freeze, admissibility)?;
    let committed_freeze =
        crate::synthesis_input::CommittedFreeze::commit(freeze, &source_admission_requests)?;
    let synthesis_input = resolve_synthesis_input(
        observation,
        admissibility,
        &committed_freeze,
        freeze,
        profile,
        lane_discipline,
    )?;
    Ok((
        source_admission_requests,
        retained_revisions,
        committed_freeze,
        synthesis_input,
    ))
}

/// Resolves the W3 synthesis pack for one recorded run.
///
/// W3: the synthesis pack is resolved from the committed freeze under the
/// run-bound reference manifest and the admitted disclosure class, so a member
/// the freeze excluded, the manifest revoked or the disclosure forbids is a
/// published omission rather than a silent one.
///
/// The question and the disclosure class are read off the PROFILE, not off the
/// `Observation`, for the same reason
/// `validate_committed_freeze_and_synthesis_input` reads them off the profile:
/// the record has to re-derive the same pack from the values it publishes, and
/// the observation is consumed here. The profile carries the admitted question
/// verbatim (`profile_params` copies it) and the admitted disclosure class as
/// its `disclosure_ceiling`, so a re-proof that read either from the
/// observation could not exist.
///
/// The pack's own denominator stays the freeze's included set, read inside
/// `SynthesisInputPack::resolve` and not off `committed_freeze` here: a commit
/// that had lost or gained a member still re-proves its own digest, and only
/// the freeze is the authority on which members exist.
fn resolve_synthesis_input(
    observation: &InquiryObservation,
    admissibility: &[SourceAdmissibilityRecord],
    committed_freeze: &crate::synthesis_input::CommittedFreeze,
    freeze: &EvidenceFreeze,
    profile: &InquiryProtocolProfile,
    lane_discipline: &LaneDisciplineOutcome,
) -> Result<crate::synthesis_input::SynthesisInputPack, InquiryError> {
    crate::synthesis_input::SynthesisInputPack::resolve(
        committed_freeze,
        freeze,
        &observation.reference_manifest,
        &admitted_records(admissibility),
        &committed_freeze.members_by_handle(),
        &profile.question,
        profile.disclosure_ceiling,
        lane_discipline,
    )
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
    let FreezePredecessor {
        supersedes,
        supersede_reason,
        expected_revision,
    } = freeze_predecessor(observation);
    EvidenceFreeze::freeze(
        EvidenceFreezeParams {
            inquiry_id: observation.inquiry_id.clone(),
            portfolio_digest: portfolio.digest.clone(),
            manifest_digest: profile.reference_manifest_digest.clone(),
            coverage_receipt_digest: coverage_receipt.digest.clone(),
            evidence_set_id: observation.evidence_set_id.clone(),
            included_evidence_refs: included,
            excluded_evidence: excluded,
            unresolved_contradictions: contradictions,
            open_research_debts: debts.iter().map(|debt| debt.debt_id.clone()).collect(),
            frozen_at_ms: observation.assessment_time_ms,
            supersedes,
            supersede_reason,
            expected_revision,
        },
        profile,
    )
}

/// The successor relation this run's freeze carries, derived from what the run
/// itself declares.
///
/// I21.8: "New material, materially changed source content or changed protocol
/// requires a recorded reopen/successor freeze with reason and expected
/// revision." A reopen is exactly this: the two fields that identify it are
/// already on the admitted request — the `predecessor_freeze_digest` the run was
/// admitted under and the `reopen_reason` it declared. Neither is invented here,
/// and a run that declares neither is a first freeze rather than a silent
/// successor.
///
/// The prior freeze is NAMED, never rewritten: this relation is carried on the
/// new record only, so the old freeze and its audit stay exactly where they were
/// and both remain addressable by digest.
fn freeze_predecessor(observation: &InquiryObservation) -> FreezePredecessor {
    match (
        observation.predecessor_freeze_digest.as_deref(),
        observation.reopen_reason.as_deref(),
    ) {
        (Some(prior), Some(reason)) => FreezePredecessor {
            supersedes: Some(prior.to_owned()),
            supersede_reason: Some(reason.to_owned()),
            // The expected revision is the commitment this reopen reached: the
            // evidence-set identity it was admitted under, which is what the
            // successor was opened to record. It is read off the admitted request
            // rather than recomputed from the freeze's own fields, so the
            // expectation cannot be made to agree with the outcome by editing one
            // of them.
            expected_revision: Some(freeze(&format!(
                "expected-evidence-revision/v1;{}|{}",
                observation.evidence_set_id, observation.inquiry_digest
            ))),
        },
        _ => FreezePredecessor::default(),
    }
}

/// The three successor-relation fields of [`EvidenceFreezeParams`], filled from
/// the run's own declared reopen.
#[derive(Clone, Debug, Default)]
struct FreezePredecessor {
    /// Digest of the freeze this one supersedes.
    supersedes: Option<String>,
    /// Why this freeze was opened as a successor.
    supersede_reason: Option<String>,
    /// The evidence revision this successor expected to find.
    expected_revision: Option<String>,
}

/// Derives the terminal typed disposition from the observed run.
///
/// Submission and provider acknowledgement are not inquiry outcomes: a completed
/// provider operation still closes nothing unless the frozen denominator closed
/// intact, and every other outcome keeps an explicit disposition.
///
/// # #2893 item 12: what closure actually reads
///
/// The previous body decided `ANSWERED_WITH_SUPPORTED_RESULT` from two
/// `CoverageReceipt` fields — `all_closed` and
/// `denominator_kind.supports_scoped_absence()` — and consulted the receipt's
/// retained absence evidence nowhere. `denominator_kind` is itself decided over
/// the evidence record (see [`denominator_kind`]), so the *kind* was already
/// evidence-gated, but the terminal record published neither the verdict class
/// nor the record's identity: a reader of the disposition could not tell whether
/// the closure rested on an owner-issued evaluation, and a closure published
/// from a receipt whose evidence had since been rewritten was indistinguishable
/// from one published over the intact record.
///
/// So the decision is now made from the same [`AbsenceClosureEvidence`] this
/// record carries and binds, never from a bare enum read. That value is built
/// only from an [`AbsenceEvidence`] the receipt itself re-proved while deriving
/// the preconditions, and it is refused — not defaulted — when the receipt holds
/// no record. A run with no owner-issued evaluation therefore stays
/// [`CompletionDisposition::IncompleteCoverage`], which is the honest result,
/// not a failure of this function.
fn terminal_disposition(
    observation: &InquiryObservation,
    coverage_receipt: &CoverageReceipt,
    closure_evidence: Option<&AbsenceClosureEvidence>,
) -> CompletionDisposition {
    match observation.outcome {
        AcquisitionOutcome::TimedOut => CompletionDisposition::Inconclusive,
        AcquisitionOutcome::Cancelled => CompletionDisposition::Cancelled,
        AcquisitionOutcome::Refused => CompletionDisposition::PolicyOrDisclosureDenied,
        AcquisitionOutcome::Crashed | AcquisitionOutcome::Unknown => {
            CompletionDisposition::SourceUnavailable
        }
        AcquisitionOutcome::Completed => {
            // I21.9: only `ANSWERED_WITH_SUPPORTED_RESULT` or a properly scoped
            // `NO_MATCH_IN_COMPLETE_SCOPE` may close. #2893 makes the second of
            // those the disposition this path can actually reach, because a
            // `NO_MATCH` closure is the scoped-negative claim and is exactly the
            // claim that needs the owner-issued record behind it; an inquiry that
            // did find support closes through the claim-audit release gate
            // (`InquiryGovernance::release_gate`), which is the other owner and
            // is not reachable from an acquisition receipt. Before this, both
            // closing classes collapsed onto the positive one, so
            // `NO_MATCH_IN_COMPLETE_SCOPE` had no producer on the live path at
            // all even though I21.6's receipt publishes `absence_verdict` as a
            // first-class field.
            if !closure_evidence.is_some_and(|evidence| evidence.closes_negative(coverage_receipt))
            {
                return CompletionDisposition::IncompleteCoverage;
            }
            CompletionDisposition::NoMatchInCompleteScope
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
///
/// `freeze` and `claim_audit` are the artifacts this run actually produced, and
/// they are carried onto the record rather than re-derived from it, so the
/// terminal projection publishes the same values the freeze and the audit
/// committed to. `precision` supplies the unsupported-precision residue the
/// evidence set already produced, for the same reason.
#[allow(clippy::too_many_arguments)]
fn terminal_record(
    observation: &InquiryObservation,
    profile: &InquiryProtocolProfile,
    portfolio: &SourcePortfolio,
    coverage_receipt: &CoverageReceipt,
    precision: &EvidenceSetPrecision,
    obligations: &[InquiryObligation],
    debts: &[ResearchDebt],
    freeze: &EvidenceFreeze,
    claim_audit: Option<&ClaimAuditRecord>,
    absence_evidence: Option<&AbsenceEvidence>,
) -> Result<InquiryTerminalRecord, InquiryError> {
    let debt_restriction = ResearchDebtRestriction::derive(&observation.inquiry_id, debts);
    // #2893 item 12: the closure decision is made over the re-proved record, not
    // over a bare enum read. This is the only construction site of
    // `AbsenceClosureEvidence`, and it is refused rather than defaulted: a run
    // whose receipt retained no record, or whose record does not re-prove
    // against THIS run's fence and frozen scope snapshot, yields `None` and
    // therefore `IncompleteCoverage`.
    let closure_evidence = absence_evidence
        .and_then(|evidence| AbsenceClosureEvidence::verify(evidence, profile, coverage_receipt));
    let derived = terminal_disposition(observation, coverage_receipt, closure_evidence.as_ref());
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
        freeze.clone(),
        claim_audit.cloned(),
        precision.residue.clone(),
        // The record identity behind the closure decision, taken from the very
        // value `terminal_disposition` just read. If the disposition is not a
        // scoped-negative closure this is `None` even when a re-proved record
        // exists, because a record that did not close the inquiry is not what
        // the terminal record claims to rest on.
        closure_evidence
            .as_ref()
            .filter(|_| disposition == CompletionDisposition::NoMatchInCompleteScope)
            .map(|evidence| evidence.evaluation_digest().to_owned()),
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
        // One provider generation is one provider family, and it is the exact
        // admitted generation on the candidate rather than a label derived from
        // it. A record with no established provider family carries `None`, which
        // keeps it off that independence axis instead of placing it in a family
        // of its own.
        provider_family: (!candidate.provider_generation.is_empty())
            .then(|| candidate.provider_generation.clone()),
        // The evaluator that judged a retained provider artifact is the
        // instrument-plane execution that admitted it, which the candidate names
        // by route. It is not a claim that a human or model re-read the material.
        evaluator_family: (!candidate.route.is_empty()).then(|| candidate.route.clone()),
        // The retained snapshot is the material itself, so it inherits no
        // assumption of its own beyond the refusal flag already in
        // `content_flags`; an empty set is preserved as unknown on the
        // shared-assumption axis rather than read as "shares no assumption".
        assumptions: BTreeSet::new(),
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

/// Obligation identities this run actually satisfied by an acceptance
/// certificate it holds.
///
/// Three things must all hold, and the first two together are the property the
/// previous form of this function did not have:
///
/// 1. the obligation was **recorded** `VERIFIED` — this domain's own verdict;
/// 2. the certificate kind **re-derived from the run's own material** for that
///    obligation's `coverage_member` — the run-bound manifest read through
///    [`AllowedReferenceManifest::allows`], and an admitted, integrity-re-proved,
///    `ELIGIBLE` [`SourceAdmissibilityRecord`] carrying exact evidence spans —
///    is of the kind the obligation **declares**; and
/// 3. the recorded state is not one the certificate predicate refuses, so no
///    presented kind verifies a rejected, cancelled or invalidated obligation.
///
/// The re-derivation is what makes this a verification rather than an echo. The
/// previous body asked
/// `is_verified_by_certificate(obligation.acceptance_certificate_kind)`, which
/// hands the predicate the obligation's **own declared** kind; the kind
/// comparison in [`InquiryObligation::is_verified_by_certificate`] then
/// compared a value with itself and was `true` by construction, leaving the
/// recorded status as the only thing actually being read. That is the same
/// status-echo defect the predicate itself was corrected for, one layer up: a
/// `VERIFIED` status asserted by a writer that never held a matching
/// certificate published `certified=1`.
///
/// Here the presented kind comes from `manifest` and `admissibility`, the same
/// two inputs [`open_obligations`] decides the build side from, so the read side
/// and the build side answer the same question from the same admitted material
/// and can be compared by a reader who holds neither the code nor the writer's
/// intent. It is on the live route: `eliot-mod-research` renders this line on
/// every run.
///
/// # Errors
///
/// Returns the first integrity failure of an admitted record whose handle is
/// read while re-deriving a presented kind, rather than counting a certificate
/// from a record that no longer re-proves its own digest.
fn certified_obligations<'a>(
    manifest: &AllowedReferenceManifest,
    obligations: &'a [InquiryObligation],
    admissibility: &[SourceAdmissibilityRecord],
) -> Result<Vec<&'a str>, InquiryError> {
    let mut certified = Vec::new();
    for obligation in obligations {
        if obligation.status != InquiryObligationStatus::Verified {
            continue;
        }
        // The member comes off the record, and the presented kind off the run's
        // own admitted material — never off the obligation's declared kind.
        let presented =
            presented_acceptance_certificate(manifest, &obligation.coverage_member, admissibility)?;
        if obligation.is_verified_by_certificate(presented) {
            certified.push(obligation.obligation_id.as_str());
        }
    }
    Ok(certified)
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

/// Renders an already-canonical member list for the terminal receipt line.
///
/// The A3 coverage map publishes three rosters — the independently derived
/// expected one, the released one and the unaccounted remainder — and a count
/// alone would leave a reader unable to see WHICH claim was unaudited. The
/// Governor-facing source-admission request digests are rendered through this
/// same function rather than through a second inline `join`, so a reader parses
/// one list spelling on the receipt line instead of two.
///
/// The members are claim and source handles this record already decided on, so
/// publishing them adds no provider prose, payload body or credential, and
/// `none` is the honest spelling of an empty list.
fn member_list_wire(members: &[&str]) -> String {
    if members.is_empty() {
        return "none".to_owned();
    }
    members.join(",")
}

/// The `work_graph_lane=` and `work_graph_registration=` values on the receipt
/// line.
///
/// A named projection rather than two inline format arguments, so the receipt line
/// keeps one field per value it publishes and the work-graph lane half is rendered
/// in one place that cannot drift from the compilation bundle it reads. The lane
/// is the closed wire name the work was compiled under and the registration is the
/// committed registration digest the profile's own lane policy holds, or the
/// honest `none` spelling for a run that commits no registration; no provider
/// prose, payload body or credential is reproduced.
struct WorkGraphLaneProjection<'a> {
    /// The work-graph compilation bundle this record carries.
    inputs: &'a TaskGraphCompilationInputs,
}

impl std::fmt::Display for WorkGraphLaneProjection<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "work_graph_lane={} work_graph_registration={}",
            self.inputs.lane.wire_name(),
            self.inputs
                .lane_registration_digest
                .as_deref()
                .unwrap_or("none"),
        )
    }
}

/// The `claim_coverage=` value on the terminal receipt line.
///
/// A named projection rather than eight inline format arguments, so the receipt
/// line keeps one field per value it publishes and the coverage detail is
/// rendered in one place that cannot drift from the map it reads. Every value is
/// an identity, a count, a digest or a boolean, and the two rosters are the
/// claim/source handles this record already decided on; no provider prose,
/// payload body or credential is reproduced.
struct ClaimCoverageProjection<'a> {
    /// The coverage map this record carries.
    map: &'a ClaimCoverageMap,
    /// The specific members the complete-audit gate refuses on.
    unaccounted: &'a [String],
}

impl std::fmt::Display for ClaimCoverageProjection<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "digest={} expected_claim_ids={} released_claim_ids={} complete={} \
             unaccounted_claim_ids={}",
            self.map.digest(),
            member_list_wire(&str_members(self.map.expected_material_claims())),
            member_list_wire(&str_members(self.map.released_material_claims())),
            bool_text(self.map.is_complete()),
            member_list_wire(&str_members(self.unaccounted)),
        )
    }
}

/// Borrows an owned roster as the borrowed member list [`member_list_wire`] takes.
///
/// Both rosters are `Vec<String>` inside values this record already owns, and
/// the receipt line only reads them, so the two spellings are the same data
/// behind one rendering function rather than two renderers.
fn str_members(members: &[String]) -> Vec<&str> {
    members.iter().map(String::as_str).collect()
}

/// The `debt_restricted=` and `debt_restriction_refused=` values on the receipt
/// line.
///
/// I21.12 makes a debt a typed object that states what it blocks, so the line
/// publishes the restriction boolean beside the closed wire names of the
/// dispositions the debts actually refuse. Rendering both from one owner means
/// the boolean and the list cannot disagree about which debt kinds are present.
struct DebtRestrictionProjection<'a> {
    /// The restriction the registered debts imply.
    restriction: &'a ResearchDebtRestriction,
}

impl std::fmt::Display for DebtRestrictionProjection<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "debt_restricted={} debt_restriction_refused={}",
            bool_text(self.restriction.restricted),
            self.restriction
                .refused_dispositions
                .iter()
                .map(|disposition| disposition_wire(*disposition))
                .collect::<Vec<&str>>()
                .join(","),
        )
    }
}

/// The terminal-disposition and Governor-pair values on the receipt line.
///
/// A named projection rather than fourteen inline format arguments, so the
/// receipt line keeps one field per value it publishes and the disposition half
/// is rendered in one place that cannot drift from the terminal record it reads.
/// The two request counts the Governor pair publishes are rendered here beside
/// the digest list they belong to, because a count separated from its own values
/// is the shape a reader cannot check.
struct TerminalDispositionProjection<'a> {
    /// The terminal typed disposition this record carries.
    terminal: &'a InquiryTerminalRecord,
    /// The Governor-facing source transition requests this record proposes.
    source_admission_requests: &'a [GovernorSourceTransitionRequest],
}

impl std::fmt::Display for TerminalDispositionProjection<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let terminal = self.terminal;
        write!(
            formatter,
            "disposition={} terminal_denominator_kind={} may_close={} \
             acquisition_succeeded={} preserved_unknown={} narrower_claim={} \
             next_probe={} reason={} authority_epoch={}/{} candidate_only={} \
             source_admission_requests={} source_admission_request_digests={}",
            disposition_wire(terminal.disposition),
            terminal.denominator_kind,
            bool_text(terminal.may_close()),
            bool_text(terminal.acquisition_succeeded()),
            bool_text(terminal.explicit_unknown.is_some()),
            bool_text(terminal.narrower_claim.is_some()),
            bool_text(terminal.next_probe.is_some()),
            terminal.reason_code,
            terminal.state_fence.authority_epoch.lineage_id,
            terminal.state_fence.authority_epoch.sequence,
            bool_text(terminal.candidate_only),
            self.source_admission_requests.len(),
            member_list_wire(
                &self
                    .source_admission_requests
                    .iter()
                    .map(|request| request.request_digest.as_str())
                    .collect::<Vec<_>>(),
            ),
        )
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
        AnchorPrecision::Symbol => "symbol",
        AnchorPrecision::ByteRange => "byte_range",
    }
}
