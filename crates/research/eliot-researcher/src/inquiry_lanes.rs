//! Confirmatory and exploratory lane registration for the Researcher contract
//! owner (issue #1763, I21.4).
//!
//! I21.4 requires a frozen [`LaneRegistration`] for a confirmatory lane or a
//! confirmatory partition: the exact contract, protocol, hypothesis and
//! evaluator digests, the primary outcome and its decision rule, the exclusions
//! and quality controls, the blinded fields, the permitted deviations, the
//! intended evidence partition, the registration identity/revision/time/fence
//! and an owner receipt. This module owns exactly that record and the machinery
//! that makes it executable.
//!
//! # The defect this module replaces
//!
//! I21.4 says "registered before outcome exposure", and the sibling profile
//! policy in [`crate::inquiry_governance`] derives that fact from the *presence
//! of a caller-supplied digest string* — any 64-hex string makes a confirmatory
//! lane resolvable. The same section of the architecture forbids exactly that:
//! "caller timestamps or `registered_before_outcome_exposure=true` are not proof
//! of order". This module therefore owns a different proof:
//!
//! * an [`OwnerOrderingReceipt`] is a **hash-chained position inside one
//!   owner-issued journal**, not a clock reading. Two positions are comparable
//!   only inside the same `(owner_principal, journal_identity)` pair, so no
//!   subtraction of unrelated clocks exists anywhere in this module;
//! * [`LaneRegistration`] cannot be constructed without the owner receipt that
//!   attests its own content digest, so a bare string cannot stand in for a
//!   committed registration;
//! * [`authorise_confirmatory_exposure`] proves through
//!   [`LaneRegistration::require_commit_precedes`] that the commit is an
//!   **ancestor of every exposure event that touches the evidence about to be
//!   released**, not merely earlier than some unrelated timestamp;
//! * [`ExposureLedger`] is append-only: re-fetching exposed data, renaming a run
//!   or changing a model never erases prior exposure, and missing coverage
//!   blocks a confirmatory claim instead of implying no exposure.
//!
//! The `IndependenceBlindingPolicy::registered_before_outcome_exposure` flag
//! therefore remains what it always was — a declaration recorded by the profile
//! — and this module's [`authorise_confirmatory_exposure`] is the only thing
//! that authorises a confirmatory claim. A reviewer should check exactly that:
//! the field is read nowhere in this module, and
//! [`LaneRegistration::committed_registration_digest`] is the value a profile
//! revision must carry.
//!
//! # What this module does not own
//!
//! No second grade ladder ([`crate::inquiry_governance::EvidenceGrade`] and
//! `eliot-epistemic-contracts` own the four grades), no second independence
//! model (I21.4: "`blinded_fields` … does not create a second independence
//! model"), no second work graph, no scheduler, no canonical write, no provider
//! execution, no sealed mapping content (the existing independence/disclosure
//! owner keeps the mapping; this module keeps only its handle and digest), and
//! no preregistration database. The commit, the disclosure and the execution
//! receipts are issued by their existing owners; this module only binds and
//! orders them.
//!
//! Digests are lowercase SHA-256 over an explicit length-prefixed canonical
//! preimage built by the crate's single [`crate::evidence_portfolio::freeze`]
//! recipe, and every set iterates in `BTree` order, so arrival order never
//! affects frozen bytes.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::StateFence;

use crate::evidence_portfolio::{PortfolioError, digest, freeze, push_count, push_field, text};
use crate::inquiry_governance::{
    BlindedField, EvidenceGrade, InquiryError, InquiryLane, InquiryProfileParams,
    InquiryProtocolProfile,
};

/// Stable identity of this domain surface.
pub const INQUIRY_LANES_CONTRACT: &str = "eliot.research.inquiry-lanes";
/// Current revision of this domain surface.
pub const INQUIRY_LANES_VERSION: &str = "1.0.0";

/// Storage class I21.4 requires for an exploratory result.
///
/// An exploratory result is stored under this class and may not be promoted to
/// a confirmatory claim on the same exposure; a later reader may not upgrade a
/// claim by quoting it.
pub const EXPLORATORY_FINDING_CLASS: &str = "EXPLORATORY_FINDING";

/// Typed lane-registration failure. Every variant names the failing concept or
/// field path only; no supplied value is ever echoed back and no typed failure
/// is collapsed into a string or a generic code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaneRegistrationError {
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
    /// A closed-vocabulary value is not a member of its vocabulary.
    UnknownVocabulary {
        /// Failing field path.
        field: &'static str,
    },
    /// A confirmatory lane was declared with no committed registration.
    LaneRegistrationRequired {
        /// Failing field path.
        field: &'static str,
    },
    /// The profile does not carry the committed registration digest, so no
    /// owner receipt attests the registration it would rely on.
    RegistrationNotCommitted {
        /// Failing field path.
        field: &'static str,
    },
    /// Outcome material was exposed before the registration commit, proven by
    /// the owner-issued receipt chain rather than by a caller timestamp.
    ExposurePrecedesCommit {
        /// Failing field path.
        field: &'static str,
    },
    /// A receipt belongs to another owner or another journal, so its position
    /// is not comparable with the registration commit.
    OrderingReceiptForeign {
        /// Failing field path.
        field: &'static str,
    },
    /// A registration, receipt or ledger entry was replayed under an identity
    /// already bound to different content, or for another partition.
    OrderingReceiptReplayed {
        /// Failing field path.
        field: &'static str,
    },
    /// Exposure coverage is not attested across every mandatory channel.
    ExposureCoverageIncomplete {
        /// Failing field path.
        field: &'static str,
    },
    /// Exploratory material reached the confirmatory evaluator, directly or
    /// through a summary, a cache or a shared ancestor context.
    CrossLaneEvidence {
        /// Failing field path.
        field: &'static str,
    },
    /// The evidence partition is missing, unfrozen or incomplete for the lane.
    PartitionNotFrozen {
        /// Failing field path.
        field: &'static str,
    },
    /// The partition does not decide the side of one evidence handle.
    PartitionMemberUnknown {
        /// Failing field path.
        field: &'static str,
    },
    /// A change outside the registered allowance invalidates the affected
    /// confirmation.
    UnregisteredDeviation {
        /// Failing field path.
        field: &'static str,
    },
    /// A failed or negative attempt was not preserved and shown with the
    /// result.
    AttemptNotDisclosed {
        /// Failing field path.
        field: &'static str,
    },
    /// A declared blinded field was delivered unblinded, or masking it would
    /// remove essential task or safety information.
    BlindingNotApplied {
        /// Failing field path.
        field: &'static str,
    },
    /// Blinding would remove information the task or a safety control needs.
    BlindingRemovesEssentialInformation {
        /// Failing field path.
        field: &'static str,
    },
    /// Blinded fields are declared but no sealed mapping is retained under the
    /// existing independence/disclosure owner.
    SealedBlindingMappingRequired {
        /// Failing field path.
        field: &'static str,
    },
    /// The presented fence is not the fence the profile and registration were
    /// frozen under.
    StaleFence {
        /// Failing field path.
        field: &'static str,
    },
    /// The built revision's grade is not the change the caller declared.
    GradeChangeNotAsDeclared {
        /// Failing field path.
        field: &'static str,
    },
    /// A grade supersession named no owner distinct from the requesting
    /// principal, so the caller could be lowering the requirement itself.
    SupersessionOwnerRequired {
        /// Failing field path.
        field: &'static str,
    },
    /// The recomputed digest of a record does not match its own content.
    IntegrityMismatch {
        /// Failing field path.
        field: &'static str,
    },
    /// A shared portfolio discipline refused the material.
    Portfolio(PortfolioError),
    /// The sibling inquiry-governance domain refused the material.
    Profile(InquiryError),
}

impl std::fmt::Display for LaneRegistrationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Blank { field } => write!(formatter, "{field} is required"),
            Self::BadDigest { field } => {
                write!(formatter, "{field} is not a lowercase SHA-256 digest")
            }
            Self::UnknownVocabulary { field } => {
                write!(
                    formatter,
                    "{field} is not a member of its closed vocabulary"
                )
            }
            Self::LaneRegistrationRequired { field } => {
                write!(formatter, "{field} requires a committed lane registration")
            }
            Self::RegistrationNotCommitted { field } => write!(
                formatter,
                "{field} does not carry the owner-issued committed registration digest"
            ),
            Self::ExposurePrecedesCommit { field } => write!(
                formatter,
                "{field} was exposed before its registration commit in the owner-issued order"
            ),
            Self::OrderingReceiptForeign { field } => write!(
                formatter,
                "{field} belongs to another owner journal and cannot order against the commit"
            ),
            Self::OrderingReceiptReplayed { field } => {
                write!(
                    formatter,
                    "{field} is replayed under an already bound identity"
                )
            }
            Self::ExposureCoverageIncomplete { field } => write!(
                formatter,
                "{field} leaves a mandatory exposure channel unattested"
            ),
            Self::CrossLaneEvidence { field } => write!(
                formatter,
                "{field} carries exploratory material into the confirmatory evaluator"
            ),
            Self::PartitionNotFrozen { field } => {
                write!(formatter, "{field} has no frozen evidence partition")
            }
            Self::PartitionMemberUnknown { field } => {
                write!(formatter, "{field} is not a member of the frozen partition")
            }
            Self::UnregisteredDeviation { field } => write!(
                formatter,
                "{field} changes the run outside the registered allowance"
            ),
            Self::AttemptNotDisclosed { field } => write!(
                formatter,
                "{field} omits a failed or negative attempt from the result"
            ),
            Self::BlindingNotApplied { field } => {
                write!(
                    formatter,
                    "{field} was delivered without its declared blinding"
                )
            }
            Self::BlindingRemovesEssentialInformation { field } => write!(
                formatter,
                "{field} masks essential task or safety information"
            ),
            Self::SealedBlindingMappingRequired { field } => write!(
                formatter,
                "{field} declares blinding with no sealed mapping under the disclosure owner"
            ),
            Self::StaleFence { field } => {
                write!(formatter, "{field} is not the current State Fence")
            }
            Self::GradeChangeNotAsDeclared { field } => write!(
                formatter,
                "{field} is not the grade change this revision declared"
            ),
            Self::SupersessionOwnerRequired { field } => write!(
                formatter,
                "{field} must name an owner distinct from the requesting principal"
            ),
            Self::IntegrityMismatch { field } => {
                write!(
                    formatter,
                    "{field} does not match its own recomputed digest"
                )
            }
            Self::Portfolio(error) => write!(formatter, "frozen portfolio discipline: {error}"),
            Self::Profile(error) => write!(formatter, "inquiry profile discipline: {error}"),
        }
    }
}

impl std::error::Error for LaneRegistrationError {}

impl From<PortfolioError> for LaneRegistrationError {
    fn from(error: PortfolioError) -> Self {
        Self::Portfolio(error)
    }
}

impl From<InquiryError> for LaneRegistrationError {
    fn from(error: InquiryError) -> Self {
        Self::Profile(error)
    }
}

fn require_text(value: &str, field: &'static str) -> Result<(), LaneRegistrationError> {
    text(value, field).map_err(LaneRegistrationError::from)
}

fn require_digest(value: &str, field: &'static str) -> Result<(), LaneRegistrationError> {
    digest(value, field).map_err(LaneRegistrationError::from)
}

fn bool_text(value: bool) -> &'static str {
    if value { "true" } else { "false" }
}

// ---------------------------------------------------------------------------
// Owner-issued ordering
// ---------------------------------------------------------------------------

/// Kind of committed subject one owner-issued ordering receipt attests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderedSubjectKind {
    /// The registration record itself was committed through the governed
    /// record/artifact path.
    LaneRegistrationCommit,
    /// Evidence was acquired.
    Acquisition,
    /// Material was disclosed to a consumer.
    Disclosure,
    /// A dependent evaluation was started.
    Execution,
    /// The owner attested that exposure coverage across the observed channels
    /// is complete.
    CoverageAttestation,
}

impl OrderedSubjectKind {
    /// Stable wire spelling of this subject kind.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::LaneRegistrationCommit => "lane_registration_commit",
            Self::Acquisition => "acquisition",
            Self::Disclosure => "disclosure",
            Self::Execution => "execution",
            Self::CoverageAttestation => "coverage_attestation",
        }
    }
}

impl std::fmt::Display for OrderedSubjectKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Named constructor arguments for [`OwnerOrderingReceipt::issue`].
#[derive(Clone, Debug)]
pub struct OwnerOrderingReceiptParams {
    /// Stable identity of this receipt.
    pub receipt_id: String,
    /// The owner that issued it: the governed record/artifact path, the
    /// disclosure owner, the execution owner or the acquisition owner.
    pub owner_principal: String,
    /// Identity of the one owner-issued journal this position belongs to.
    ///
    /// Positions are comparable only inside one journal, so a receipt from
    /// another journal orders nothing.
    pub journal_identity: String,
    /// Monotonic position of this entry inside that journal.
    pub position: u64,
    /// Receipt of the immediately preceding entry in the same journal.
    pub predecessor_receipt_digest: Option<String>,
    /// What this entry attests.
    pub subject: OrderedSubjectKind,
    /// Stable identity of the committed subject.
    pub subject_id: String,
    /// Exact content digest of the committed subject.
    pub subject_digest: String,
    /// State Fence the owner committed the subject under.
    pub state_fence: StateFence,
}

/// One owner-issued ordering receipt (I21.4).
///
/// The commit-before-exposure proof in this module is a **hash-chained position
/// inside one owner-issued journal**. It is deliberately not a timestamp and
/// never a subtraction of two unrelated clocks: `position` is meaningful only
/// together with `owner_principal` and `journal_identity`, and a receipt
/// authenticates nothing by itself — it authorises a claim only when the chain
/// from a later receipt reaches the registration commit, or fails to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerOrderingReceipt {
    /// Stable identity of this receipt.
    pub receipt_id: String,
    /// The owner that issued it.
    pub owner_principal: String,
    /// Identity of the one owner-issued journal this position belongs to.
    pub journal_identity: String,
    /// Monotonic position of this entry inside that journal.
    pub position: u64,
    /// Receipt of the immediately preceding entry in the same journal.
    pub predecessor_receipt_digest: Option<String>,
    /// What this entry attests.
    pub subject: OrderedSubjectKind,
    /// Stable identity of the committed subject.
    pub subject_id: String,
    /// Exact content digest of the committed subject.
    pub subject_digest: String,
    /// State Fence the owner committed the subject under.
    pub state_fence: StateFence,
    /// Digest over the whole receipt.
    pub receipt_digest: String,
}

impl OwnerOrderingReceipt {
    /// Issues one owner ordering receipt over a committed subject.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::Blank`] for a blank identity, owner or
    /// journal, [`LaneRegistrationError::BadDigest`] for a malformed subject or
    /// predecessor digest, and [`LaneRegistrationError::StaleFence`] when the
    /// presented fence fails its own validation.
    pub fn issue(params: OwnerOrderingReceiptParams) -> Result<Self, LaneRegistrationError> {
        require_text(&params.receipt_id, "receipt.receipt_id")?;
        require_text(&params.owner_principal, "receipt.owner_principal")?;
        require_text(&params.journal_identity, "receipt.journal_identity")?;
        require_text(&params.subject_id, "receipt.subject_id")?;
        require_digest(&params.subject_digest, "receipt.subject_digest")?;
        if let Some(predecessor) = &params.predecessor_receipt_digest {
            require_digest(predecessor, "receipt.predecessor_receipt_digest")?;
        }
        params
            .state_fence
            .validate()
            .map_err(|_| LaneRegistrationError::StaleFence {
                field: "receipt.state_fence",
            })?;
        let mut receipt = Self {
            receipt_id: params.receipt_id,
            owner_principal: params.owner_principal,
            journal_identity: params.journal_identity,
            position: params.position,
            predecessor_receipt_digest: params.predecessor_receipt_digest,
            subject: params.subject,
            subject_id: params.subject_id,
            subject_digest: params.subject_digest,
            state_fence: params.state_fence,
            receipt_digest: String::new(),
        };
        receipt.receipt_digest = receipt.compute_digest();
        Ok(receipt)
    }

    /// Whether `self` was committed strictly before `other` in the same
    /// owner-issued journal.
    ///
    /// A receipt from another owner or another journal orders nothing and
    /// returns `false`; the caller receives the typed
    /// [`LaneRegistrationError::OrderingReceiptForeign`] instead of a lenient
    /// comparison.
    #[must_use]
    pub fn is_strictly_before(&self, other: &Self) -> bool {
        self.shares_journal_with(other) && self.position < other.position
    }

    /// Whether both receipts were issued into the same owner-issued journal.
    #[must_use]
    pub fn shares_journal_with(&self, other: &Self) -> bool {
        self.owner_principal == other.owner_principal
            && self.journal_identity == other.journal_identity
    }

    /// Re-proves this receipt's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::IntegrityMismatch`] when the recomputed
    /// digest disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), LaneRegistrationError> {
        if self.compute_digest() != self.receipt_digest {
            return Err(LaneRegistrationError::IntegrityMismatch {
                field: "receipt.receipt_digest",
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("lane-owner-ordering-receipt/v1;");
        push_field(&mut preimage, "receipt_id", &self.receipt_id);
        push_field(&mut preimage, "owner_principal", &self.owner_principal);
        push_field(&mut preimage, "journal_identity", &self.journal_identity);
        push_field(&mut preimage, "position", &self.position.to_string());
        match &self.predecessor_receipt_digest {
            Some(predecessor) => push_field(&mut preimage, "predecessor", predecessor),
            None => push_field(&mut preimage, "predecessor", "journal_origin"),
        }
        push_field(&mut preimage, "subject", self.subject.wire_name());
        push_field(&mut preimage, "subject_id", &self.subject_id);
        push_field(&mut preimage, "subject_digest", &self.subject_digest);
        freeze(&preimage)
    }
}

/// Walks the owner-issued receipt chain from `start` backwards looking for
/// `anchor`.
///
/// The walk fails when it leaves the known receipts, when a predecessor is
/// absent, or after visiting more receipts than exist, so a cycle in forged
/// input terminates instead of looping.
fn chain_reaches(index: &BTreeMap<&str, &OwnerOrderingReceipt>, start: &str, anchor: &str) -> bool {
    let mut cursor = start;
    for _ in 0..=index.len() {
        if cursor == anchor {
            return true;
        }
        let Some(receipt) = index.get(cursor) else {
            return false;
        };
        let Some(predecessor) = &receipt.predecessor_receipt_digest else {
            return false;
        };
        cursor = predecessor.as_str();
    }
    false
}

// ---------------------------------------------------------------------------
// Registration content (I21.4)
// ---------------------------------------------------------------------------

/// Exact contract, protocol, hypothesis and evaluator digests one registration
/// commits to (I21.4 `contract_protocol_hypothesis_and_evaluator_digests`).
///
/// These are four distinct subjects. Folding them into one digest would let a
/// caller swap the evaluator while keeping the digest it already registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistrationDigests {
    /// Exact digest of the contract the run executes under.
    pub contract_digest: String,
    /// Exact digest of the protocol the run executes.
    pub protocol_digest: String,
    /// Exact digest of the proposition under test.
    pub hypothesis_digest: String,
    /// Exact digest of the evaluator that decides the outcome.
    pub evaluator_digest: String,
}

impl RegistrationDigests {
    /// Binds the four exact digests one registration commits to.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::BadDigest`] when any digest is not
    /// lowercase SHA-256 hex.
    pub fn bind(
        contract_digest: &str,
        protocol_digest: &str,
        hypothesis_digest: &str,
        evaluator_digest: &str,
    ) -> Result<Self, LaneRegistrationError> {
        require_digest(contract_digest, "digests.contract_digest")?;
        require_digest(protocol_digest, "digests.protocol_digest")?;
        require_digest(hypothesis_digest, "digests.hypothesis_digest")?;
        require_digest(evaluator_digest, "digests.evaluator_digest")?;
        Ok(Self {
            contract_digest: contract_digest.to_owned(),
            protocol_digest: protocol_digest.to_owned(),
            hypothesis_digest: hypothesis_digest.to_owned(),
            evaluator_digest: evaluator_digest.to_owned(),
        })
    }

    fn push_into(&self, preimage: &mut String) {
        push_field(preimage, "contract_digest", &self.contract_digest);
        push_field(preimage, "protocol_digest", &self.protocol_digest);
        push_field(preimage, "hypothesis_digest", &self.hypothesis_digest);
        push_field(preimage, "evaluator_digest", &self.evaluator_digest);
    }
}

/// Primary outcome and the decision rule that decides it (I21.4
/// `primary_outcome_and_decision_rule`).
///
/// I21.4: "After registration the run may not change the primary metric". The
/// decision rule is frozen with the metric, so swapping one without the other is
/// a content change and therefore a new registration revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrimaryOutcomeRule {
    /// Exact primary outcome the run reports.
    pub primary_outcome: String,
    /// Exact rule that maps observations onto a decision.
    pub decision_rule: String,
}

impl PrimaryOutcomeRule {
    /// Binds the primary outcome and its decision rule.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::Blank`] when either the outcome or the
    /// decision rule is blank or control-bearing.
    pub fn bind(primary_outcome: &str, decision_rule: &str) -> Result<Self, LaneRegistrationError> {
        require_text(primary_outcome, "primary_outcome.primary_outcome")?;
        require_text(decision_rule, "primary_outcome.decision_rule")?;
        Ok(Self {
            primary_outcome: primary_outcome.to_owned(),
            decision_rule: decision_rule.to_owned(),
        })
    }

    fn push_into(&self, preimage: &mut String) {
        push_field(preimage, "primary_outcome", &self.primary_outcome);
        push_field(preimage, "decision_rule", &self.decision_rule);
    }
}

/// Stated exclusion rules and quality controls (I21.4
/// `exclusions_and_quality_controls`).
///
/// I21.4: "may not … exclude a case without a stated rule". An empty exclusion
/// set is therefore legal (no exclusion is declared) but a later
/// [`LaneRegistration::classify_deviation`] refuses any deviation that claims an
/// exclusion without a stated rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExclusionAndQualityControl {
    /// Stated rules under which a case may be excluded.
    pub stated_exclusion_rules: Vec<String>,
    /// Quality controls applied to every included case.
    pub quality_controls: Vec<String>,
}

impl ExclusionAndQualityControl {
    /// Binds the stated exclusion rules and the quality controls.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::Blank`] for a blank entry and
    /// [`LaneRegistrationError::UnknownVocabulary`] when the run declares no
    /// quality control at all.
    pub fn bind(
        stated_exclusion_rules: Vec<String>,
        quality_controls: Vec<String>,
    ) -> Result<Self, LaneRegistrationError> {
        for rule in &stated_exclusion_rules {
            require_text(rule, "controls.stated_exclusion_rules")?;
        }
        for control in &quality_controls {
            require_text(control, "controls.quality_controls")?;
        }
        if quality_controls.is_empty() {
            return Err(LaneRegistrationError::UnknownVocabulary {
                field: "controls.quality_controls",
            });
        }
        Ok(Self {
            stated_exclusion_rules,
            quality_controls,
        })
    }

    fn push_into(&self, preimage: &mut String) {
        push_count(
            preimage,
            "stated_exclusion_rules",
            self.stated_exclusion_rules.len(),
        );
        for rule in &self.stated_exclusion_rules {
            push_field(preimage, "stated_exclusion_rule", rule);
        }
        push_count(preimage, "quality_controls", self.quality_controls.len());
        for control in &self.quality_controls {
            push_field(preimage, "quality_control", control);
        }
    }
}

/// The one facet a registered allowance or an observed deviation speaks about
/// (I21.4).
///
/// Facets are closed so a deviation cannot be filed under a name that no
/// allowance covers, which is what "outside the registered allowance" has to
/// mean to be executable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviationScope {
    /// The primary metric or endpoint.
    PrimaryMetric,
    /// The evaluator that decides the outcome.
    Evaluator,
    /// Which cases are excluded.
    Exclusions,
    /// How strong the proposition under test is.
    PropositionStrength,
    /// Whether failed and negative attempts are shown.
    FailureDisclosure,
}

impl DeviationScope {
    /// Stable wire spelling of this facet.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::PrimaryMetric => "primary_metric",
            Self::Evaluator => "evaluator",
            Self::Exclusions => "exclusions",
            Self::PropositionStrength => "proposition_strength",
            Self::FailureDisclosure => "failure_disclosure",
        }
    }

    /// Every facet, in canonical order.
    #[must_use]
    pub const fn all() -> [Self; 5] {
        [
            Self::PrimaryMetric,
            Self::Evaluator,
            Self::Exclusions,
            Self::PropositionStrength,
            Self::FailureDisclosure,
        ]
    }
}

impl std::fmt::Display for DeviationScope {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// One permitted deviation, frozen before outcome exposure (I21.4
/// `allowed_deviations`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviationAllowance {
    /// Stable allowance identity a deviation is classified against.
    pub allowance_id: String,
    /// Facet this allowance covers.
    pub scope: DeviationScope,
    /// Exact description of the permitted change.
    pub description: String,
}

impl DeviationAllowance {
    /// Registers one permitted deviation.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::Blank`] when the allowance identity or
    /// description is blank or control-bearing.
    pub fn allow(
        allowance_id: &str,
        scope: DeviationScope,
        description: &str,
    ) -> Result<Self, LaneRegistrationError> {
        require_text(allowance_id, "allowance.allowance_id")?;
        require_text(description, "allowance.description")?;
        Ok(Self {
            allowance_id: allowance_id.to_owned(),
            scope,
            description: description.to_owned(),
        })
    }
}

// ---------------------------------------------------------------------------
// Mixed-lane partition (I21.4)
// ---------------------------------------------------------------------------

/// Side of a mixed lane one evidence handle belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionSide {
    /// The confirmatory side, whose evaluator may only read confirmatory
    /// material.
    Confirmatory,
    /// The exploratory side, whose findings may not confirm on this exposure.
    Exploratory,
}

impl PartitionSide {
    /// Stable wire spelling of this side.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Confirmatory => "confirmatory",
            Self::Exploratory => "exploratory",
        }
    }
}

impl std::fmt::Display for PartitionSide {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// How membership of a mixed lane is decided.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartitionAssignment {
    /// Membership is enumerated and frozen with the registration.
    ExplicitMembership,
    /// Membership is an immutable deterministic rule with a version and a seed.
    DeterministicRule,
}

impl PartitionAssignment {
    /// Stable wire spelling of this assignment kind.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ExplicitMembership => "explicit_membership",
            Self::DeterministicRule => "deterministic_rule",
        }
    }
}

impl std::fmt::Display for PartitionAssignment {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// The immutable deterministic assignment rule of a mixed lane (I21.4).
///
/// Membership is `sha256(rule_version | rule_digest | seed_digest | handle)`;
/// the first byte of that digest, scaled against the declared fraction, selects
/// the confirmatory side. Rule, version and seed are all frozen digests, so the
/// side of any handle is recomputable by any later reader and cannot drift after
/// outcomes are seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeterministicAssignmentRule {
    /// Version of the assignment rule.
    pub rule_version: String,
    /// Digest of the exact rule text.
    pub rule_digest: String,
    /// Digest of the seed the rule was instantiated with.
    pub seed_digest: String,
    /// Numerator of the confirmatory fraction.
    pub confirmatory_numerator: u32,
    /// Denominator of the confirmatory fraction.
    pub confirmatory_denominator: u32,
}

impl DeterministicAssignmentRule {
    /// Binds the versioned, seeded assignment rule.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::Blank`] for a blank rule version,
    /// [`LaneRegistrationError::BadDigest`] for a malformed rule or seed digest,
    /// and [`LaneRegistrationError::UnknownVocabulary`] when the declared
    /// fraction is not strictly inside `(0, 1)`.
    pub fn bind(
        rule_version: &str,
        rule_digest: &str,
        seed_digest: &str,
        confirmatory_numerator: u32,
        confirmatory_denominator: u32,
    ) -> Result<Self, LaneRegistrationError> {
        require_text(rule_version, "rule.rule_version")?;
        require_digest(rule_digest, "rule.rule_digest")?;
        require_digest(seed_digest, "rule.seed_digest")?;
        if confirmatory_denominator == 0
            || confirmatory_numerator == 0
            || confirmatory_numerator >= confirmatory_denominator
        {
            return Err(LaneRegistrationError::UnknownVocabulary {
                field: "rule.confirmatory_fraction",
            });
        }
        Ok(Self {
            rule_version: rule_version.to_owned(),
            rule_digest: rule_digest.to_owned(),
            seed_digest: seed_digest.to_owned(),
            confirmatory_numerator,
            confirmatory_denominator,
        })
    }

    /// Decides the side of one handle under this rule.
    fn side_for(&self, handle: &str) -> Result<PartitionSide, LaneRegistrationError> {
        let mut preimage = String::from("lane-partition-assignment/v1;");
        push_field(&mut preimage, "rule_version", &self.rule_version);
        push_field(&mut preimage, "rule_digest", &self.rule_digest);
        push_field(&mut preimage, "seed_digest", &self.seed_digest);
        push_field(&mut preimage, "handle", handle);
        let derived = freeze(&preimage);
        let Ok(byte) = u8::from_str_radix(&derived[..2], 16) else {
            return Err(LaneRegistrationError::PartitionMemberUnknown {
                field: "rule.assignment_digest",
            });
        };
        let scale = 256u32;
        let threshold = self.confirmatory_numerator * scale / self.confirmatory_denominator;
        Ok(if u32::from(byte) < threshold {
            PartitionSide::Confirmatory
        } else {
            PartitionSide::Exploratory
        })
    }

    fn push_into(&self, preimage: &mut String) {
        push_field(preimage, "rule_version", &self.rule_version);
        push_field(preimage, "rule_digest", &self.rule_digest);
        push_field(preimage, "seed_digest", &self.seed_digest);
        push_field(
            preimage,
            "confirmatory_numerator",
            &self.confirmatory_numerator.to_string(),
        );
        push_field(
            preimage,
            "confirmatory_denominator",
            &self.confirmatory_denominator.to_string(),
        );
    }
}

/// Named constructor arguments for [`LanePartition::freeze`].
#[derive(Clone, Debug)]
pub struct LanePartitionParams {
    /// Stable partition identity.
    pub partition_id: String,
    /// How membership is decided.
    pub assignment: PartitionAssignment,
    /// Handles on the confirmatory side; used by explicit membership.
    pub confirmatory_members: Vec<String>,
    /// Handles on the exploratory side; used by explicit membership.
    pub exploratory_members: Vec<String>,
    /// The deterministic rule; required by [`PartitionAssignment::DeterministicRule`].
    pub rule: Option<DeterministicAssignmentRule>,
    /// State Fence the partition was frozen under.
    pub state_fence: StateFence,
}

/// The intended evidence partition of a lane (I21.4).
///
/// I21.4: "A mixed lane freezes an explicit partition; evidence may not silently
/// cross from the exploratory side into the confirmatory evaluator." A complete
/// partition map with unknown leak history is not proof of uncontaminated
/// confirmation, so the partition alone authorises nothing: the exposure ledger
/// must additionally attest coverage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LanePartition {
    /// Stable partition identity.
    pub partition_id: String,
    /// How membership is decided.
    pub assignment: PartitionAssignment,
    /// Handles on the confirmatory side.
    pub confirmatory_members: BTreeSet<String>,
    /// Handles on the exploratory side.
    pub exploratory_members: BTreeSet<String>,
    /// The deterministic rule, when membership is derived.
    pub rule: Option<DeterministicAssignmentRule>,
    /// State Fence the partition was frozen under.
    pub state_fence: StateFence,
    /// Digest over the whole partition.
    pub digest: String,
}

impl LanePartition {
    /// Freezes the partition before outcomes are seen.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::Blank`] for a blank partition identity or
    /// member handle, [`LaneRegistrationError::UnknownVocabulary`] when a
    /// deterministic rule is declared without its rule (or an explicit partition
    /// carries one), and [`LaneRegistrationError::PartitionNotFrozen`] when a
    /// handle is on both sides or an explicit partition is empty.
    pub fn freeze(params: LanePartitionParams) -> Result<Self, LaneRegistrationError> {
        require_text(&params.partition_id, "partition.partition_id")?;
        params
            .state_fence
            .validate()
            .map_err(|_| LaneRegistrationError::StaleFence {
                field: "partition.state_fence",
            })?;
        let confirmatory_members: BTreeSet<String> = params
            .confirmatory_members
            .iter()
            .map(|handle| validated_member(handle))
            .collect::<Result<_, _>>()?;
        let exploratory_members: BTreeSet<String> = params
            .exploratory_members
            .iter()
            .map(|handle| validated_member(handle))
            .collect::<Result<_, _>>()?;
        if confirmatory_members
            .intersection(&exploratory_members)
            .next()
            .is_some()
        {
            return Err(LaneRegistrationError::PartitionNotFrozen {
                field: "partition.members",
            });
        }
        let mut partition = Self {
            partition_id: params.partition_id,
            assignment: params.assignment,
            confirmatory_members,
            exploratory_members,
            rule: params.rule,
            state_fence: params.state_fence,
            digest: String::new(),
        };
        partition.validate_shape()?;
        partition.digest = partition.compute_digest();
        Ok(partition)
    }

    /// Decides the side of one evidence handle.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::PartitionMemberUnknown`] when an
    /// explicit partition does not decide the handle. A handle that the frozen
    /// partition cannot place is refused rather than assumed confirmatory.
    pub fn side_for(&self, handle: &str) -> Result<PartitionSide, LaneRegistrationError> {
        require_text(handle, "partition.handle")?;
        match (&self.assignment, &self.rule) {
            (PartitionAssignment::DeterministicRule, Some(rule)) => rule.side_for(handle),
            (PartitionAssignment::ExplicitMembership, None) => {
                if self.confirmatory_members.contains(handle) {
                    Ok(PartitionSide::Confirmatory)
                } else if self.exploratory_members.contains(handle) {
                    Ok(PartitionSide::Exploratory)
                } else {
                    Err(LaneRegistrationError::PartitionMemberUnknown {
                        field: "partition.members",
                    })
                }
            }
            _ => Err(LaneRegistrationError::PartitionNotFrozen {
                field: "partition.assignment",
            }),
        }
    }

    /// Re-proves this partition's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::IntegrityMismatch`] when the recomputed
    /// digest disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), LaneRegistrationError> {
        if self.compute_digest() != self.digest {
            return Err(LaneRegistrationError::IntegrityMismatch {
                field: "partition.digest",
            });
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), LaneRegistrationError> {
        match (&self.assignment, &self.rule) {
            (PartitionAssignment::DeterministicRule, Some(_)) => Ok(()),
            (PartitionAssignment::ExplicitMembership, None) => {
                if self.confirmatory_members.is_empty() || self.exploratory_members.is_empty() {
                    Err(LaneRegistrationError::PartitionNotFrozen {
                        field: "partition.members",
                    })
                } else {
                    Ok(())
                }
            }
            _ => Err(LaneRegistrationError::PartitionNotFrozen {
                field: "partition.assignment",
            }),
        }
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("lane-partition/v1;");
        push_field(&mut preimage, "partition_id", &self.partition_id);
        push_field(&mut preimage, "assignment", self.assignment.wire_name());
        for (tag, members) in [
            ("confirmatory_member", &self.confirmatory_members),
            ("exploratory_member", &self.exploratory_members),
        ] {
            push_count(&mut preimage, tag, members.len());
            for member in members {
                push_field(&mut preimage, tag, member);
            }
        }
        if let Some(rule) = &self.rule {
            rule.push_into(&mut preimage);
        }
        freeze(&preimage)
    }
}

fn validated_member(handle: &str) -> Result<String, LaneRegistrationError> {
    require_text(handle, "partition.members")?;
    Ok(handle.to_owned())
}

// ---------------------------------------------------------------------------
// Sealed blinding
// ---------------------------------------------------------------------------

/// Named constructor arguments for [`SealedBlindingMapping::seal`].
#[derive(Clone, Debug)]
pub struct SealedBlindingMappingParams {
    /// Stable handle of the mapping under the existing independence/disclosure
    /// owner.
    pub mapping_handle: String,
    /// Digest of the mapping content the owner holds.
    pub mapping_digest: String,
    /// The independence/disclosure owner that holds the mapping.
    pub owner_principal: String,
    /// Owner receipt attesting the mapping was sealed.
    pub receipt: OwnerOrderingReceipt,
}

/// Handle to a sealed blinding mapping retained under the existing
/// independence/disclosure owner (I21.4/I10.15).
///
/// Only the handle and the digest enter the registration. The mapping content
/// never reaches this crate, so the registration cannot leak the very values the
/// blinding closes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBlindingMapping {
    /// Stable handle of the mapping under the disclosure owner.
    pub mapping_handle: String,
    /// Digest of the mapping content the owner holds.
    pub mapping_digest: String,
    /// The independence/disclosure owner that holds the mapping.
    pub owner_principal: String,
    /// Owner receipt attesting the mapping was sealed.
    pub receipt: OwnerOrderingReceipt,
}

impl SealedBlindingMapping {
    /// Binds a sealed mapping handle to the owner that holds it.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::Blank`] for a blank handle or owner,
    /// [`LaneRegistrationError::BadDigest`] for a malformed mapping digest, and
    /// [`LaneRegistrationError::SealedBlindingMappingRequired`] when the owner
    /// receipt does not bind the mapping content it claims to have sealed.
    pub fn seal(params: SealedBlindingMappingParams) -> Result<Self, LaneRegistrationError> {
        require_text(&params.mapping_handle, "sealed_blinding.mapping_handle")?;
        require_text(&params.owner_principal, "sealed_blinding.owner_principal")?;
        require_digest(&params.mapping_digest, "sealed_blinding.mapping_digest")?;
        params.receipt.validate_integrity()?;
        if params.receipt.subject_digest != params.mapping_digest {
            return Err(LaneRegistrationError::SealedBlindingMappingRequired {
                field: "sealed_blinding.receipt",
            });
        }
        Ok(Self {
            mapping_handle: params.mapping_handle,
            mapping_digest: params.mapping_digest,
            owner_principal: params.owner_principal,
            receipt: params.receipt,
        })
    }
}

// ---------------------------------------------------------------------------
// The registration
// ---------------------------------------------------------------------------

/// Named constructor arguments for [`LaneRegistration::register`].
#[derive(Clone, Debug)]
pub struct LaneRegistrationParams {
    /// Stable registration identity.
    pub registration_id: String,
    /// Inquiry identity the registration governs.
    pub inquiry_id: String,
    /// Profile identity the registration binds.
    pub profile_id: String,
    /// Profile revision the registration binds.
    pub profile_revision: u64,
    /// Exact profile revision digest the registration binds.
    pub profile_digest: String,
    /// Exact contract, protocol, hypothesis and evaluator digests.
    pub digests: RegistrationDigests,
    /// Primary outcome and its decision rule.
    pub primary_outcome: PrimaryOutcomeRule,
    /// Stated exclusion rules and quality controls.
    pub exclusions_and_quality_controls: ExclusionAndQualityControl,
    /// Leakage channels this run closes.
    pub blinded_fields: Vec<BlindedField>,
    /// Deviations permitted before outcome exposure.
    pub allowed_deviations: Vec<DeviationAllowance>,
    /// Intended evidence partition; required for a mixed lane.
    pub evidence_partition: Option<LanePartition>,
    /// Sealed mapping retained under the independence/disclosure owner.
    pub sealed_blinding_mapping: SealedBlindingMapping,
    /// Instant the owner recorded the registration.
    ///
    /// Retained as evidence of the recorded fact only. This module never
    /// compares it against another clock: ordering comes from
    /// [`OwnerOrderingReceipt`] alone, so a predated caller timestamp changes
    /// nothing.
    pub registered_at_ms: i64,
    /// State Fence the registration was frozen under.
    pub state_fence: StateFence,
    /// Owner receipt committing this registration through the governed
    /// record/artifact path.
    pub owner_receipt: OwnerOrderingReceipt,
}

/// The immutable lane registration I21.4 requires (issue #1763).
///
/// Every field of the I21.4 shape is present: the four digests, the primary
/// outcome and decision rule, the exclusions and quality controls, the blinded
/// fields, the permitted deviations, the intended evidence partition, the
/// registration identity/revision/time/fence and the owner receipt. What I21.4
/// spells `registered_before_outcome_exposure` is **not** a field here: it is
/// derived by [`LaneRegistration::require_commit_precedes`] from the owner-issued
/// receipt chain, so no caller can assert it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LaneRegistration {
    /// Stable registration identity.
    pub registration_id: String,
    /// Monotonic revision of this registration, starting at one.
    pub revision: u64,
    /// Digest of the registration revision this one supersedes.
    pub supersedes: Option<String>,
    /// Inquiry identity the registration governs.
    pub inquiry_id: String,
    /// Profile identity the registration binds.
    pub profile_id: String,
    /// Profile revision the registration binds.
    pub profile_revision: u64,
    /// Exact profile revision digest the registration binds.
    pub profile_digest: String,
    /// Exact contract, protocol, hypothesis and evaluator digests.
    pub contract_protocol_hypothesis_and_evaluator_digests: RegistrationDigests,
    /// Primary outcome and its decision rule.
    pub primary_outcome_and_decision_rule: PrimaryOutcomeRule,
    /// Stated exclusion rules and quality controls.
    pub exclusions_and_quality_controls: ExclusionAndQualityControl,
    /// Leakage channels this run closes.
    pub blinded_fields: Vec<BlindedField>,
    /// Deviations permitted before outcome exposure.
    pub allowed_deviations: Vec<DeviationAllowance>,
    /// Intended evidence partition.
    pub evidence_partition: Option<LanePartition>,
    /// Sealed mapping retained under the independence/disclosure owner.
    pub sealed_blinding_mapping: SealedBlindingMapping,
    /// Instant the owner recorded the registration; never used for ordering.
    pub registered_at_ms: i64,
    /// State Fence the registration was frozen under.
    pub state_fence: StateFence,
    /// Owner receipt committing this registration.
    pub owner_receipt: OwnerOrderingReceipt,
    /// Digest over the registration content, excluding the commit receipt.
    pub content_digest: String,
}

impl LaneRegistration {
    /// Commits the first revision of one registration.
    ///
    /// # Errors
    ///
    /// Returns a field error for blank or malformed input, a stale-fence error
    /// when the fence fails validation,
    /// [`LaneRegistrationError::LaneRegistrationRequired`] when the run declares
    /// blinded fields with no sealed mapping under the disclosure owner, and
    /// [`LaneRegistrationError::RegistrationNotCommitted`] when the owner
    /// receipt is not a registration commit over exactly this content — which is
    /// what makes a bare digest string insufficient.
    pub fn register(params: LaneRegistrationParams) -> Result<Self, LaneRegistrationError> {
        Self::build(params, 1, None, "initial lane registration")
    }

    /// Commits the next revision of this registration with a recorded reason.
    ///
    /// I21.4: "Content changes create a linked new revision." A revision keeps
    /// the registration identity and the inquiry, links the previous content
    /// digest, and needs an owner commit receipt later than the previous one in
    /// the same journal.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`LaneRegistration::register`] plus
    /// [`LaneRegistrationError::Blank`] for a blank reason and
    /// [`LaneRegistrationError::OrderingReceiptReplayed`] when the revision
    /// reuses an already bound registration identity.
    pub fn revise(
        &self,
        params: LaneRegistrationParams,
        reason: &str,
    ) -> Result<Self, LaneRegistrationError> {
        require_text(reason, "registration.change_reason")?;
        if params.registration_id != self.registration_id {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "registration.registration_id",
            });
        }
        if params.inquiry_id != self.inquiry_id {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "registration.inquiry_binding",
            });
        }
        if !self.owner_receipt.is_strictly_before(&params.owner_receipt) {
            return Err(LaneRegistrationError::ExposurePrecedesCommit {
                field: "registration.owner_receipt",
            });
        }
        let next =
            self.revision
                .checked_add(1)
                .ok_or(LaneRegistrationError::OrderingReceiptReplayed {
                    field: "registration.revision",
                })?;
        Self::build(params, next, Some(self.content_digest.clone()), reason)
    }

    /// The committed identity a profile revision must carry as its lane
    /// registration digest.
    ///
    /// This is not the content digest: it additionally binds the owner commit
    /// receipt, so a value a caller composed from content alone cannot stand in
    /// for a committed registration. Even this value authorises nothing by
    /// itself; [`authorise_confirmatory_exposure`] does.
    #[must_use]
    pub fn committed_registration_digest(&self) -> String {
        let mut preimage = String::from("lane-registration-committed/v1;");
        push_field(&mut preimage, "content_digest", &self.content_digest);
        push_field(
            &mut preimage,
            "owner_receipt_digest",
            &self.owner_receipt.receipt_digest,
        );
        push_field(
            &mut preimage,
            "owner_receipt_position",
            &self.owner_receipt.position.to_string(),
        );
        push_field(
            &mut preimage,
            "journal_identity",
            &self.owner_receipt.journal_identity,
        );
        freeze(&preimage)
    }

    /// Proves, from the owner-issued receipt chain alone, that this commit
    /// precedes every exposure recorded against the evidence about to be
    /// released.
    ///
    /// This is the predicate I21.4 spells `registered_before_outcome_exposure`.
    /// It is a function of owner receipts — never of a caller boolean and never
    /// of the difference between two unrelated clocks — so a predated caller
    /// timestamp changes nothing and a receipt that does not chain to this
    /// commit fails.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::OrderingReceiptReplayed`] when two
    /// receipts claim one digest, [`LaneRegistrationError::OrderingReceiptForeign`]
    /// when a touching event was issued into another owner journal, and
    /// [`LaneRegistrationError::ExposurePrecedesCommit`] when a touching event is
    /// not provably a descendant of this commit.
    pub fn require_commit_precedes(
        &self,
        ledger: &ExposureLedger,
        delivered_handles: &BTreeSet<String>,
        evidence_revision_digest: &str,
    ) -> Result<(), LaneRegistrationError> {
        let index = ordered_index(self, ledger)?;
        let anchor = self.owner_receipt.receipt_digest.as_str();
        for event in ledger.events_touching(delivered_handles, evidence_revision_digest) {
            if !event.receipt.shares_journal_with(&self.owner_receipt) {
                return Err(LaneRegistrationError::OrderingReceiptForeign {
                    field: "exposure.receipt",
                });
            }
            let after_commit = event.receipt.position > self.owner_receipt.position
                && chain_reaches(&index, &event.receipt.receipt_digest, anchor);
            if !after_commit {
                return Err(LaneRegistrationError::ExposurePrecedesCommit {
                    field: "exposure.receipt",
                });
            }
        }
        Ok(())
    }

    /// Classifies one observed deviation against the registered allowances.
    ///
    /// A change outside the registered allowance invalidates the affected
    /// confirmation; an allowed deviation is still disclosed, so this returns a
    /// disposition rather than a pass/fail verdict.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::UnknownVocabulary`] when the deviation
    /// names no registered facet.
    pub fn classify_deviation(
        &self,
        scope: DeviationScope,
        described_change: &str,
    ) -> Result<DeviationDisposition, LaneRegistrationError> {
        require_text(described_change, "deviation.description")?;
        if !DeviationScope::all().contains(&scope) {
            return Err(LaneRegistrationError::UnknownVocabulary {
                field: "deviation.scope",
            });
        }
        if scope == DeviationScope::Exclusions
            && self
                .exclusions_and_quality_controls
                .stated_exclusion_rules
                .is_empty()
        {
            return Ok(DeviationDisposition::OutsideDeclaredAllowance);
        }
        Ok(
            if self
                .allowed_deviations
                .iter()
                .any(|allowance| allowance.scope == scope)
            {
                DeviationDisposition::WithinDeclaredAllowance
            } else {
                DeviationDisposition::OutsideDeclaredAllowance
            },
        )
    }

    /// The allowance a deviation of this facet is classified against.
    #[must_use]
    pub fn allowance_for(&self, scope: DeviationScope) -> Option<&DeviationAllowance> {
        self.allowed_deviations
            .iter()
            .find(|allowance| allowance.scope == scope)
    }

    /// Re-proves this registration's own content digest and its commit receipt.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::IntegrityMismatch`] when the recomputed
    /// content digest disagrees with the stored one, when the owner receipt
    /// fails its own digest, or when the receipt no longer attests this exact
    /// content.
    pub fn validate_integrity(&self) -> Result<(), LaneRegistrationError> {
        if self.compute_content_digest() != self.content_digest {
            return Err(LaneRegistrationError::IntegrityMismatch {
                field: "registration.content_digest",
            });
        }
        self.owner_receipt.validate_integrity()?;
        if self.owner_receipt.subject != OrderedSubjectKind::LaneRegistrationCommit
            || self.owner_receipt.subject_digest != self.content_digest
        {
            return Err(LaneRegistrationError::RegistrationNotCommitted {
                field: "registration.owner_receipt",
            });
        }
        if let Some(partition) = &self.evidence_partition {
            partition.validate_integrity()?;
        }
        Ok(())
    }

    fn build(
        params: LaneRegistrationParams,
        revision: u64,
        supersedes: Option<String>,
        change_reason: &str,
    ) -> Result<Self, LaneRegistrationError> {
        require_text(&params.registration_id, "registration.registration_id")?;
        require_text(&params.inquiry_id, "registration.inquiry_id")?;
        require_text(&params.profile_id, "registration.profile_id")?;
        require_digest(&params.profile_digest, "registration.profile_digest")?;
        require_text(change_reason, "registration.change_reason")?;
        // `BlindedField` carries no canonical order of its own, so the frozen
        // preimage orders the closed vocabulary by its wire spelling instead of
        // introducing a second enumeration.
        let mut blinded_fields = params.blinded_fields;
        blinded_fields.sort_by_key(|field| field.wire_name());
        blinded_fields.dedup();
        if blinded_fields.is_empty() {
            return Err(LaneRegistrationError::UnknownVocabulary {
                field: "registration.blinded_fields",
            });
        }
        if params.allowed_deviations.is_empty() {
            return Err(LaneRegistrationError::UnknownVocabulary {
                field: "registration.allowed_deviations",
            });
        }
        if params
            .exclusions_and_quality_controls
            .quality_controls
            .is_empty()
        {
            return Err(LaneRegistrationError::UnknownVocabulary {
                field: "registration.exclusions_and_quality_controls",
            });
        }
        params
            .sealed_blinding_mapping
            .receipt
            .validate_integrity()?;
        params
            .state_fence
            .validate()
            .map_err(|_| LaneRegistrationError::StaleFence {
                field: "registration.state_fence",
            })?;
        params.owner_receipt.validate_integrity()?;
        if params.owner_receipt.subject != OrderedSubjectKind::LaneRegistrationCommit {
            return Err(LaneRegistrationError::RegistrationNotCommitted {
                field: "registration.owner_receipt",
            });
        }
        if params.owner_receipt.state_fence != params.state_fence {
            return Err(LaneRegistrationError::StaleFence {
                field: "registration.owner_receipt",
            });
        }
        if let Some(partition) = &params.evidence_partition {
            partition.validate_integrity()?;
        }
        let mut registration = Self {
            registration_id: params.registration_id,
            revision,
            supersedes,
            inquiry_id: params.inquiry_id,
            profile_id: params.profile_id,
            profile_revision: params.profile_revision,
            profile_digest: params.profile_digest,
            contract_protocol_hypothesis_and_evaluator_digests: params.digests,
            primary_outcome_and_decision_rule: params.primary_outcome,
            exclusions_and_quality_controls: params.exclusions_and_quality_controls,
            blinded_fields,
            allowed_deviations: params.allowed_deviations,
            evidence_partition: params.evidence_partition,
            sealed_blinding_mapping: params.sealed_blinding_mapping,
            registered_at_ms: params.registered_at_ms,
            state_fence: params.state_fence,
            owner_receipt: params.owner_receipt,
            content_digest: String::new(),
        };
        registration.content_digest = registration.compute_content_digest();
        if registration.owner_receipt.subject_digest != registration.content_digest {
            return Err(LaneRegistrationError::RegistrationNotCommitted {
                field: "registration.owner_receipt",
            });
        }
        Ok(registration)
    }

    fn compute_content_digest(&self) -> String {
        let mut preimage = String::from("lane-registration/v1;");
        push_field(&mut preimage, "registration_id", &self.registration_id);
        push_field(&mut preimage, "revision", &self.revision.to_string());
        match &self.supersedes {
            Some(supersedes) => push_field(&mut preimage, "supersedes", supersedes),
            None => push_field(&mut preimage, "supersedes", "none"),
        }
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "profile_id", &self.profile_id);
        push_field(
            &mut preimage,
            "profile_revision",
            &self.profile_revision.to_string(),
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        self.contract_protocol_hypothesis_and_evaluator_digests
            .push_into(&mut preimage);
        self.primary_outcome_and_decision_rule
            .push_into(&mut preimage);
        self.exclusions_and_quality_controls
            .push_into(&mut preimage);
        push_count(&mut preimage, "blinded_fields", self.blinded_fields.len());
        for field in &self.blinded_fields {
            push_field(&mut preimage, "blinded_field", field.wire_name());
        }
        push_count(
            &mut preimage,
            "allowed_deviations",
            self.allowed_deviations.len(),
        );
        for allowance in &self.allowed_deviations {
            push_field(
                &mut preimage,
                "allowed_deviation_id",
                &allowance.allowance_id,
            );
            push_field(
                &mut preimage,
                "allowed_deviation_scope",
                allowance.scope.wire_name(),
            );
            push_field(
                &mut preimage,
                "allowed_deviation_description",
                &allowance.description,
            );
        }
        match &self.evidence_partition {
            Some(partition) => {
                push_field(&mut preimage, "evidence_partition", &partition.digest);
            }
            None => push_field(&mut preimage, "evidence_partition", "none"),
        }
        push_field(
            &mut preimage,
            "sealed_blinding_handle",
            &self.sealed_blinding_mapping.mapping_handle,
        );
        push_field(
            &mut preimage,
            "sealed_blinding_digest",
            &self.sealed_blinding_mapping.mapping_digest,
        );
        push_field(
            &mut preimage,
            "sealed_blinding_owner",
            &self.sealed_blinding_mapping.owner_principal,
        );
        push_field(
            &mut preimage,
            "sealed_blinding_receipt_digest",
            &self.sealed_blinding_mapping.receipt.receipt_digest,
        );
        push_field(
            &mut preimage,
            "registered_at_ms",
            &self.registered_at_ms.to_string(),
        );
        freeze(&preimage)
    }
}

// ---------------------------------------------------------------------------
// Exposure ledger
// ---------------------------------------------------------------------------

/// Leakage channel one exposure event touched (I21.4).
///
/// I21.4 names the channels a confirmatory run must account for: exposure to
/// hypothesis and method selectors and to evaluators, "including caches,
/// summaries and shared ancestor context". A channel nobody observed stays
/// unattested, which blocks a confirmatory claim; it never implies that the
/// channel was clean.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExposureChannel {
    /// The preferred hypothesis or condition label reached a selector.
    HypothesisSelector,
    /// The method, prompt or tuning knob reached a selector.
    MethodSelector,
    /// Outcome material reached an evaluator.
    Evaluator,
    /// Material was served from a cache of earlier work.
    CachedRetrieval,
    /// Material reached an evaluator through a derived summary.
    DerivedSummary,
    /// Material reached an evaluator through a shared ancestor context.
    SharedAncestorContext,
    /// Holdout or outcome material was released.
    HoldoutOutcomeMaterial,
}

impl ExposureChannel {
    /// Stable wire spelling of this channel.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::HypothesisSelector => "hypothesis_selector",
            Self::MethodSelector => "method_selector",
            Self::Evaluator => "evaluator",
            Self::CachedRetrieval => "cached_retrieval",
            Self::DerivedSummary => "derived_summary",
            Self::SharedAncestorContext => "shared_ancestor_context",
            Self::HoldoutOutcomeMaterial => "holdout_outcome_material",
        }
    }

    /// Every channel a confirmatory claim must have attested, in canonical
    /// order.
    #[must_use]
    pub const fn mandatory() -> [Self; 7] {
        [
            Self::HypothesisSelector,
            Self::MethodSelector,
            Self::Evaluator,
            Self::CachedRetrieval,
            Self::DerivedSummary,
            Self::SharedAncestorContext,
            Self::HoldoutOutcomeMaterial,
        ]
    }
}

impl std::fmt::Display for ExposureChannel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Kind of owner-attested event one exposure record carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExposureEventKind {
    /// The material was acquired.
    Acquisition,
    /// The material was disclosed to a consumer.
    Disclosure,
    /// A dependent evaluation was started on the material.
    Execution,
}

impl ExposureEventKind {
    /// Stable wire spelling of this event kind.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Acquisition => "acquisition",
            Self::Disclosure => "disclosure",
            Self::Execution => "execution",
        }
    }
}

impl std::fmt::Display for ExposureEventKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Named constructor arguments for [`ExposureEvent::record`].
#[derive(Clone, Debug)]
pub struct ExposureEventParams {
    /// Stable identity of this exposure event.
    pub event_id: String,
    /// Kind of owner-attested event.
    pub event_kind: ExposureEventKind,
    /// Leakage channel the event touched.
    pub channel: ExposureChannel,
    /// Exact evidence handle the material reached.
    pub subject_handle: String,
    /// Exact evidence revision the material belonged to.
    pub evidence_revision_digest: String,
    /// Instant the owner recorded the exposure.
    pub observed_at_ms: i64,
    /// State Fence the exposure happened under.
    pub state_fence: StateFence,
    /// Owner receipt attesting the event and its journal position.
    pub receipt: OwnerOrderingReceipt,
}

/// One recorded exposure to hypothesis/method selectors, evaluators, caches,
/// summaries or shared ancestor context (I21.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExposureEvent {
    /// Stable identity of this exposure event.
    pub event_id: String,
    /// Kind of owner-attested event.
    pub event_kind: ExposureEventKind,
    /// Leakage channel the event touched.
    pub channel: ExposureChannel,
    /// Exact evidence handle the material reached.
    pub subject_handle: String,
    /// Exact evidence revision the material belonged to.
    pub evidence_revision_digest: String,
    /// Instant the owner recorded the exposure.
    pub observed_at_ms: i64,
    /// State Fence the exposure happened under.
    pub state_fence: StateFence,
    /// Owner receipt attesting the event and its journal position.
    pub receipt: OwnerOrderingReceipt,
    /// Digest over the whole event.
    pub digest: String,
}

impl ExposureEvent {
    /// Records one exposure event under its owner receipt.
    ///
    /// # Errors
    ///
    /// Returns a field error for blank or malformed input,
    /// [`LaneRegistrationError::StaleFence`] when the event fence or the receipt
    /// fence fails validation, and [`LaneRegistrationError::OrderingReceiptForeign`]
    /// when the receipt does not attest the event it claims to order.
    pub fn record(params: ExposureEventParams) -> Result<Self, LaneRegistrationError> {
        require_text(&params.event_id, "exposure.event_id")?;
        require_text(&params.subject_handle, "exposure.subject_handle")?;
        require_digest(
            &params.evidence_revision_digest,
            "exposure.evidence_revision_digest",
        )?;
        params
            .state_fence
            .validate()
            .map_err(|_| LaneRegistrationError::StaleFence {
                field: "exposure.state_fence",
            })?;
        params.receipt.validate_integrity()?;
        if params.receipt.subject_id != params.event_id
            || params.receipt.subject_digest != params.evidence_revision_digest
        {
            return Err(LaneRegistrationError::OrderingReceiptForeign {
                field: "exposure.receipt",
            });
        }
        let mut event = Self {
            event_id: params.event_id,
            event_kind: params.event_kind,
            channel: params.channel,
            subject_handle: params.subject_handle,
            evidence_revision_digest: params.evidence_revision_digest,
            observed_at_ms: params.observed_at_ms,
            state_fence: params.state_fence,
            receipt: params.receipt,
            digest: String::new(),
        };
        event.digest = event.compute_digest();
        Ok(event)
    }

    /// Re-proves this event's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::IntegrityMismatch`] when the recomputed
    /// digest disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), LaneRegistrationError> {
        if self.compute_digest() != self.digest {
            return Err(LaneRegistrationError::IntegrityMismatch {
                field: "exposure.digest",
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("lane-exposure-event/v1;");
        push_field(&mut preimage, "event_id", &self.event_id);
        push_field(&mut preimage, "event_kind", self.event_kind.wire_name());
        push_field(&mut preimage, "channel", self.channel.wire_name());
        push_field(&mut preimage, "subject_handle", &self.subject_handle);
        push_field(
            &mut preimage,
            "evidence_revision_digest",
            &self.evidence_revision_digest,
        );
        push_field(
            &mut preimage,
            "observed_at_ms",
            &self.observed_at_ms.to_string(),
        );
        push_field(
            &mut preimage,
            "receipt_digest",
            &self.receipt.receipt_digest,
        );
        freeze(&preimage)
    }
}

/// Append-only exposure ledger for one inquiry (I21.4).
///
/// The ledger never erases. Re-fetching exposed data, renaming a run or
/// changing a model produces another entry; none of them makes the earlier
/// exposure go away, so a restart cannot reset the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExposureLedger {
    /// Inquiry identity the ledger belongs to.
    pub inquiry_id: String,
    /// Profile identity the ledger was opened under.
    pub profile_id: String,
    /// Profile revision digest the ledger was opened under.
    pub profile_digest: String,
    /// Recorded exposure events, in arrival order.
    pub events: Vec<ExposureEvent>,
    /// Channels some recorded event actually touched.
    pub observed_channels: BTreeSet<ExposureChannel>,
    /// Channels the owner requires for a confirmatory claim.
    pub mandatory_channels: BTreeSet<ExposureChannel>,
    /// Whether the owner attested complete coverage over the observed channels.
    pub coverage_attested: bool,
    /// Owner receipt attesting that coverage.
    pub coverage_receipt: Option<OwnerOrderingReceipt>,
    /// State Fence the ledger is presented under.
    pub state_fence: StateFence,
    /// Digest over the whole ledger.
    pub digest: String,
}

impl ExposureLedger {
    /// Opens the ledger for one profile revision.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::StaleFence`] when the profile fence
    /// fails validation.
    pub fn open(profile: &InquiryProtocolProfile) -> Result<Self, LaneRegistrationError> {
        profile.validate_integrity()?;
        profile
            .state_fence
            .validate()
            .map_err(|_| LaneRegistrationError::StaleFence {
                field: "ledger.state_fence",
            })?;
        let mandatory_channels = ExposureChannel::mandatory().into_iter().collect();
        let mut ledger = Self {
            inquiry_id: profile.inquiry_id.clone(),
            profile_id: profile.profile_id.clone(),
            profile_digest: profile.integrity_digest.clone(),
            events: Vec::new(),
            observed_channels: BTreeSet::new(),
            mandatory_channels,
            coverage_attested: false,
            coverage_receipt: None,
            state_fence: profile.state_fence.clone(),
            digest: String::new(),
        };
        ledger.digest = ledger.compute_digest();
        Ok(ledger)
    }

    /// Appends one exposure event. The ledger only ever grows.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::OrderingReceiptReplayed`] when the event
    /// identity is already bound to different content or when its owner receipt
    /// reuses a journal position, and [`LaneRegistrationError::OrderingReceiptForeign`]
    /// when the receipt belongs to another journal than the recorded events.
    pub fn record_exposure(&mut self, event: ExposureEvent) -> Result<(), LaneRegistrationError> {
        event.validate_integrity()?;
        if self
            .events
            .iter()
            .any(|recorded| recorded.event_id == event.event_id && recorded.digest != event.digest)
        {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "exposure.event_id",
            });
        }
        let same_owner_journal = self
            .events
            .first()
            .is_none_or(|existing| existing.receipt.shares_journal_with(&event.receipt));
        if !same_owner_journal {
            return Err(LaneRegistrationError::OrderingReceiptForeign {
                field: "exposure.receipt",
            });
        }
        if self
            .events
            .iter()
            .any(|recorded| recorded.receipt.position == event.receipt.position)
        {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "exposure.receipt",
            });
        }
        self.observed_channels.insert(event.channel);
        self.events.push(event);
        self.digest = self.compute_digest();
        Ok(())
    }

    /// Attests that exposure coverage over the observed channels is complete.
    ///
    /// The attestation binds the ledger digest as it stood before the
    /// attestation, and its receipt must be ordered after every recorded event.
    /// Re-attestation after new events is refused, so an attestation can never
    /// cover events that arrived after it.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::ExposureCoverageIncomplete`] when the
    /// receipt is not a coverage attestation, does not bind this ledger digest or
    /// is not ordered after every recorded event.
    pub fn attest_coverage(
        &mut self,
        receipt: OwnerOrderingReceipt,
    ) -> Result<(), LaneRegistrationError> {
        receipt.validate_integrity()?;
        if self.coverage_attested {
            return Err(LaneRegistrationError::ExposureCoverageIncomplete {
                field: "ledger.coverage_receipt",
            });
        }
        if receipt.subject != OrderedSubjectKind::CoverageAttestation
            || receipt.subject_digest != self.digest
        {
            return Err(LaneRegistrationError::ExposureCoverageIncomplete {
                field: "ledger.coverage_receipt",
            });
        }
        let ordered_after_every_event = self
            .events
            .iter()
            .all(|event| event.receipt.is_strictly_before(&receipt));
        if !ordered_after_every_event {
            return Err(LaneRegistrationError::ExposureCoverageIncomplete {
                field: "ledger.coverage_receipt",
            });
        }
        self.coverage_attested = true;
        self.coverage_receipt = Some(receipt);
        self.digest = self.compute_digest();
        Ok(())
    }

    /// The mandatory channels this ledger still has no observation for.
    #[must_use]
    pub fn unattested_channels(&self) -> Vec<&ExposureChannel> {
        self.mandatory_channels
            .iter()
            .filter(|channel| !self.observed_channels.contains(channel))
            .collect()
    }

    /// Events that touched one of the given evidence handles or that belong to
    /// the given evidence revision.
    #[must_use]
    pub fn events_touching(
        &self,
        delivered_handles: &BTreeSet<String>,
        evidence_revision_digest: &str,
    ) -> Vec<&ExposureEvent> {
        self.events
            .iter()
            .filter(|event| {
                delivered_handles.contains(&event.subject_handle)
                    || event.evidence_revision_digest == evidence_revision_digest
            })
            .collect()
    }

    /// Re-proves this ledger's own digest and every nested event digest.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::IntegrityMismatch`] when the recomputed
    /// ledger digest or any nested event digest disagrees.
    pub fn validate_integrity(&self) -> Result<(), LaneRegistrationError> {
        if self.compute_digest() != self.digest {
            return Err(LaneRegistrationError::IntegrityMismatch {
                field: "ledger.digest",
            });
        }
        for event in &self.events {
            event.validate_integrity()?;
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("lane-exposure-ledger/v1;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "profile_id", &self.profile_id);
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_count(&mut preimage, "events", self.events.len());
        for event in &self.events {
            push_field(&mut preimage, "event_id", &event.event_id);
            push_field(&mut preimage, "event_digest", &event.digest);
            push_field(&mut preimage, "event_kind", event.event_kind.wire_name());
            push_field(&mut preimage, "event_channel", event.channel.wire_name());
            push_field(&mut preimage, "event_subject", &event.subject_handle);
        }
        push_count(
            &mut preimage,
            "observed_channels",
            self.observed_channels.len(),
        );
        for channel in &self.observed_channels {
            push_field(&mut preimage, "observed_channel", channel.wire_name());
        }
        push_count(
            &mut preimage,
            "mandatory_channels",
            self.mandatory_channels.len(),
        );
        for channel in &self.mandatory_channels {
            push_field(&mut preimage, "mandatory_channel", channel.wire_name());
        }
        push_field(
            &mut preimage,
            "coverage_attested",
            bool_text(self.coverage_attested),
        );
        match &self.coverage_receipt {
            Some(receipt) => push_field(
                &mut preimage,
                "coverage_receipt_digest",
                &receipt.receipt_digest,
            ),
            None => push_field(&mut preimage, "coverage_receipt_digest", "none"),
        }
        freeze(&preimage)
    }
}

/// Indexes every receipt the registration and the ledger can order against.
///
/// # Errors
///
/// Returns [`LaneRegistrationError::OrderingReceiptReplayed`] when two entries
/// claim the same receipt digest, which no honest owner journal can produce.
fn ordered_index<'a>(
    registration: &'a LaneRegistration,
    ledger: &'a ExposureLedger,
) -> Result<BTreeMap<&'a str, &'a OwnerOrderingReceipt>, LaneRegistrationError> {
    let mut index: BTreeMap<&str, &OwnerOrderingReceipt> = BTreeMap::new();
    index.insert(
        registration.owner_receipt.receipt_digest.as_str(),
        &registration.owner_receipt,
    );
    for event in &ledger.events {
        if index
            .insert(event.receipt.receipt_digest.as_str(), &event.receipt)
            .is_some()
        {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "exposure.receipt",
            });
        }
    }
    Ok(index)
}

// ---------------------------------------------------------------------------
// Deviations and attempts
// ---------------------------------------------------------------------------

/// Disposition of one recorded deviation against the registered allowances.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviationDisposition {
    /// A registered allowance covers the change; it is still disclosed.
    WithinDeclaredAllowance,
    /// No registered allowance covers the change, so the affected confirmation
    /// is invalid.
    OutsideDeclaredAllowance,
}

impl DeviationDisposition {
    /// Stable wire spelling of this disposition.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::WithinDeclaredAllowance => "within_declared_allowance",
            Self::OutsideDeclaredAllowance => "outside_declared_allowance",
        }
    }

    /// Whether this disposition invalidates the affected confirmation.
    #[must_use]
    pub const fn invalidates_confirmation(self) -> bool {
        matches!(self, Self::OutsideDeclaredAllowance)
    }
}

impl std::fmt::Display for DeviationDisposition {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Named constructor arguments for [`DeviationRecord::record`].
#[derive(Clone, Debug)]
pub struct DeviationRecordParams {
    /// Stable identity of this deviation.
    pub deviation_id: String,
    /// Facet the deviation speaks about.
    pub scope: DeviationScope,
    /// Exact description of the observed change.
    pub description: String,
    /// Exact evidence revision the deviation was observed on.
    pub evidence_revision_digest: String,
    /// Instant the deviation was recorded.
    pub observed_at_ms: i64,
    /// State Fence the deviation was observed under.
    pub state_fence: StateFence,
}

/// One recorded deviation from the registration (I21.4).
///
/// I21.4: "Declared deviations are preserved and shown with the result", and a
/// change outside the registered allowance "invalidates the affected
/// confirmation". Both are facts about this record, and neither is erased by a
/// later registration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviationRecord {
    /// Stable identity of this deviation.
    pub deviation_id: String,
    /// Facet the deviation speaks about.
    pub scope: DeviationScope,
    /// Exact description of the observed change.
    pub description: String,
    /// Exact evidence revision the deviation was observed on.
    pub evidence_revision_digest: String,
    /// Disposition against the registered allowances.
    pub disposition: DeviationDisposition,
    /// Allowance identity the deviation was classified against, when one covers
    /// it.
    pub allowance_id: Option<String>,
    /// Whether this deviation is disclosed with the result.
    pub disclosed_with_result: bool,
    /// Instant the deviation was recorded.
    pub observed_at_ms: i64,
    /// State Fence the deviation was observed under.
    pub state_fence: StateFence,
    /// Digest over the whole deviation record.
    pub digest: String,
}

impl DeviationRecord {
    /// Records one deviation and classifies it against the registration.
    ///
    /// # Errors
    ///
    /// Returns a field error for blank or malformed input and
    /// [`LaneRegistrationError::StaleFence`] when the presented fence fails
    /// validation.
    pub fn record(
        params: DeviationRecordParams,
        registration: &LaneRegistration,
    ) -> Result<Self, LaneRegistrationError> {
        require_text(&params.deviation_id, "deviation.deviation_id")?;
        require_text(&params.description, "deviation.description")?;
        require_digest(
            &params.evidence_revision_digest,
            "deviation.evidence_revision_digest",
        )?;
        params
            .state_fence
            .validate()
            .map_err(|_| LaneRegistrationError::StaleFence {
                field: "deviation.state_fence",
            })?;
        let disposition = registration.classify_deviation(params.scope, &params.description)?;
        let allowance_id = registration
            .allowance_for(params.scope)
            .map(|allowance| allowance.allowance_id.clone());
        let mut record = Self {
            deviation_id: params.deviation_id,
            scope: params.scope,
            description: params.description,
            evidence_revision_digest: params.evidence_revision_digest,
            disposition,
            allowance_id,
            disclosed_with_result: true,
            observed_at_ms: params.observed_at_ms,
            state_fence: params.state_fence,
            digest: String::new(),
        };
        record.digest = record.compute_digest();
        Ok(record)
    }

    /// Re-proves this deviation's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::IntegrityMismatch`] when the recomputed
    /// digest disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), LaneRegistrationError> {
        if self.compute_digest() != self.digest {
            return Err(LaneRegistrationError::IntegrityMismatch {
                field: "deviation.digest",
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("lane-deviation-record/v1;");
        push_field(&mut preimage, "deviation_id", &self.deviation_id);
        push_field(&mut preimage, "scope", self.scope.wire_name());
        push_field(&mut preimage, "description", &self.description);
        push_field(
            &mut preimage,
            "evidence_revision_digest",
            &self.evidence_revision_digest,
        );
        push_field(&mut preimage, "disposition", self.disposition.wire_name());
        match &self.allowance_id {
            Some(allowance_id) => push_field(&mut preimage, "allowance_id", allowance_id),
            None => push_field(&mut preimage, "allowance_id", "none"),
        }
        push_field(
            &mut preimage,
            "disclosed_with_result",
            bool_text(self.disclosed_with_result),
        );
        push_field(
            &mut preimage,
            "observed_at_ms",
            &self.observed_at_ms.to_string(),
        );
        freeze(&preimage)
    }
}

/// Outcome of one recorded evaluation attempt (I21.4).
///
/// The direction of the outcome is retained verbatim. I21.4: "Acceptance is
/// outcome-neutral: a compliant negative result is a valid confirmatory
/// result", so [`AttemptOutcome::NotConfirmed`] and [`AttemptOutcome::Failed`]
/// change nothing about whether a claim may be confirmed — only whether the
/// attempt was shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttemptOutcome {
    /// The evaluator confirmed the registered proposition.
    Confirmed,
    /// The evaluator did not confirm the registered proposition.
    NotConfirmed,
    /// The attempt could not complete.
    Failed,
}

impl AttemptOutcome {
    /// Stable wire spelling of this outcome.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::NotConfirmed => "not_confirmed",
            Self::Failed => "failed",
        }
    }

    /// Whether this outcome must be shown with the result.
    #[must_use]
    pub const fn requires_disclosure(self) -> bool {
        !matches!(self, Self::Confirmed)
    }
}

impl std::fmt::Display for AttemptOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Named constructor arguments for [`AttemptRecord::record`].
#[derive(Clone, Debug)]
pub struct AttemptRecordParams {
    /// Stable identity of this attempt.
    pub attempt_id: String,
    /// Exact evidence revision the attempt ran on.
    pub evidence_revision_digest: String,
    /// Exact evaluator digest the attempt actually ran.
    pub evaluator_digest: String,
    /// Outcome the attempt observed.
    pub outcome: AttemptOutcome,
    /// Whether this attempt is shown with the result.
    pub reported_with_result: bool,
    /// Instant the attempt was recorded.
    pub observed_at_ms: i64,
    /// State Fence the attempt ran under.
    pub state_fence: StateFence,
}

/// One recorded evaluation attempt, successful or not (I21.4).
///
/// I21.4 forbids "hide failed attempts", so a failed or negative attempt is a
/// first-class record rather than an absence. Nothing here may replace an
/// evaluator after seeing results: the attempt carries the evaluator it actually
/// ran, and a replacement is a deviation of facet
/// [`DeviationScope::Evaluator`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptRecord {
    /// Stable identity of this attempt.
    pub attempt_id: String,
    /// Exact evidence revision the attempt ran on.
    pub evidence_revision_digest: String,
    /// Exact evaluator digest the attempt actually ran.
    pub evaluator_digest: String,
    /// Outcome the attempt observed.
    pub outcome: AttemptOutcome,
    /// Whether this attempt is shown with the result.
    pub reported_with_result: bool,
    /// Instant the attempt was recorded.
    pub observed_at_ms: i64,
    /// State Fence the attempt ran under.
    pub state_fence: StateFence,
    /// Digest over the whole attempt record.
    pub digest: String,
}

impl AttemptRecord {
    /// Records one evaluation attempt under the exact evaluator it ran.
    ///
    /// # Errors
    ///
    /// Returns a field error for blank or malformed input and
    /// [`LaneRegistrationError::StaleFence`] when the presented fence fails
    /// validation.
    pub fn record(params: AttemptRecordParams) -> Result<Self, LaneRegistrationError> {
        require_text(&params.attempt_id, "attempt.attempt_id")?;
        require_digest(
            &params.evidence_revision_digest,
            "attempt.evidence_revision_digest",
        )?;
        require_digest(&params.evaluator_digest, "attempt.evaluator_digest")?;
        params
            .state_fence
            .validate()
            .map_err(|_| LaneRegistrationError::StaleFence {
                field: "attempt.state_fence",
            })?;
        let mut attempt = Self {
            attempt_id: params.attempt_id,
            evidence_revision_digest: params.evidence_revision_digest,
            evaluator_digest: params.evaluator_digest,
            outcome: params.outcome,
            reported_with_result: params.reported_with_result,
            observed_at_ms: params.observed_at_ms,
            state_fence: params.state_fence,
            digest: String::new(),
        };
        attempt.digest = attempt.compute_digest();
        Ok(attempt)
    }

    /// Re-proves this attempt's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::IntegrityMismatch`] when the recomputed
    /// digest disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), LaneRegistrationError> {
        if self.compute_digest() != self.digest {
            return Err(LaneRegistrationError::IntegrityMismatch {
                field: "attempt.digest",
            });
        }
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("lane-attempt-record/v1;");
        push_field(&mut preimage, "attempt_id", &self.attempt_id);
        push_field(
            &mut preimage,
            "evidence_revision_digest",
            &self.evidence_revision_digest,
        );
        push_field(&mut preimage, "evaluator_digest", &self.evaluator_digest);
        push_field(&mut preimage, "outcome", self.outcome.wire_name());
        push_field(
            &mut preimage,
            "reported_with_result",
            bool_text(self.reported_with_result),
        );
        push_field(
            &mut preimage,
            "observed_at_ms",
            &self.observed_at_ms.to_string(),
        );
        freeze(&preimage)
    }
}

// ---------------------------------------------------------------------------
// Applied blinding
// ---------------------------------------------------------------------------

/// Named constructor arguments for [`BlindedDelivery::deliver`].
#[derive(Clone, Debug)]
pub struct BlindedDeliveryParams {
    /// Leakage channel this delivery is about.
    pub field: BlindedField,
    /// The consumer the field was delivered to.
    pub delivered_to: String,
    /// Whether the delivered value actually carried the mask.
    pub delivered_blinded: bool,
    /// Whether the field is essential task or safety information.
    pub essential_task_or_safety_information: bool,
}

/// One actually delivered field of an evaluator input (I21.4).
///
/// "`blinded_fields` names one leakage channel to close, not a universal mask",
/// so the record is per field and per consumer rather than one global mask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindedDelivery {
    /// Leakage channel this delivery is about.
    pub field: BlindedField,
    /// The consumer the field was delivered to.
    pub delivered_to: String,
    /// Whether the delivered value actually carried the mask.
    pub delivered_blinded: bool,
    /// Whether the field is essential task or safety information.
    pub essential_task_or_safety_information: bool,
    /// Digest over the whole delivery.
    pub digest: String,
}

impl BlindedDelivery {
    /// Records one actually delivered field.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::Blank`] when the delivering consumer is
    /// blank or control-bearing.
    pub fn deliver(params: BlindedDeliveryParams) -> Result<Self, LaneRegistrationError> {
        require_text(&params.delivered_to, "delivery.delivered_to")?;
        let mut delivery = Self {
            field: params.field,
            delivered_to: params.delivered_to,
            delivered_blinded: params.delivered_blinded,
            essential_task_or_safety_information: params.essential_task_or_safety_information,
            digest: String::new(),
        };
        delivery.digest = delivery.compute_digest();
        Ok(delivery)
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("lane-blinded-delivery/v1;");
        push_field(&mut preimage, "field", self.field.wire_name());
        push_field(&mut preimage, "delivered_to", &self.delivered_to);
        push_field(
            &mut preimage,
            "delivered_blinded",
            bool_text(self.delivered_blinded),
        );
        push_field(
            &mut preimage,
            "essential_task_or_safety_information",
            bool_text(self.essential_task_or_safety_information),
        );
        freeze(&preimage)
    }

    /// Re-proves this delivery's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::IntegrityMismatch`] when the recomputed
    /// digest disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), LaneRegistrationError> {
        if self.compute_digest() != self.digest {
            return Err(LaneRegistrationError::IntegrityMismatch {
                field: "delivery.digest",
            });
        }
        Ok(())
    }
}

/// The blinding the registration declared, checked against what was actually
/// delivered (I21.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlindingApplication {
    /// Registration identity the check belongs to.
    pub registration_id: String,
    /// Committed registration digest the check belongs to.
    pub registration_digest: String,
    /// Sealed mapping handle under the independence/disclosure owner.
    pub sealed_mapping_handle: String,
    /// Leakage channels that were actually delivered masked.
    pub masked_channels: BTreeSet<&'static str>,
    /// Digest over the whole check.
    pub digest: String,
}

impl BlindingApplication {
    /// Checks the declared blinding against the actually delivered fields.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::BlindingNotApplied`] when a declared
    /// channel reached a consumer unmasked, and
    /// [`LaneRegistrationError::BlindingRemovesEssentialInformation`] when a
    /// masked channel carries information the task or a safety control needs.
    pub fn evaluate(
        registration: &LaneRegistration,
        deliveries: &[BlindedDelivery],
    ) -> Result<Self, LaneRegistrationError> {
        let mut masked_channels = BTreeSet::new();
        for delivery in deliveries {
            delivery.validate_integrity()?;
        }
        for field in &registration.blinded_fields {
            let delivered = deliveries
                .iter()
                .find(|delivery| delivery.field == *field)
                .ok_or(LaneRegistrationError::BlindingNotApplied {
                    field: "registration.blinded_fields",
                })?;
            if !delivered.delivered_blinded {
                return Err(LaneRegistrationError::BlindingNotApplied {
                    field: "delivery.delivered_blinded",
                });
            }
            if delivered.essential_task_or_safety_information {
                return Err(LaneRegistrationError::BlindingRemovesEssentialInformation {
                    field: "delivery.essential_task_or_safety_information",
                });
            }
            masked_channels.insert(field.wire_name());
        }
        let sealed_mapping_handle = registration.sealed_blinding_mapping.mapping_handle.clone();
        let mut application = Self {
            registration_id: registration.registration_id.clone(),
            registration_digest: registration.committed_registration_digest(),
            sealed_mapping_handle,
            masked_channels,
            digest: String::new(),
        };
        let mut preimage = String::from("lane-blinding-application/v1;");
        push_field(
            &mut preimage,
            "registration_id",
            &application.registration_id,
        );
        push_field(
            &mut preimage,
            "registration_digest",
            &application.registration_digest,
        );
        push_field(
            &mut preimage,
            "sealed_mapping_handle",
            &application.sealed_mapping_handle,
        );
        push_count(
            &mut preimage,
            "masked_channels",
            application.masked_channels.len(),
        );
        for channel in &application.masked_channels {
            push_field(&mut preimage, "masked_channel", channel);
        }
        application.digest = freeze(&preimage);
        Ok(application)
    }
}

// ---------------------------------------------------------------------------
// Grade requirement change (I21.2)
// ---------------------------------------------------------------------------

/// The declared intent behind a profile revision (I21.2).
///
/// I21.2: "A grade may be raised prospectively at any point in a task" and
/// "Lowering an already declared grade for an unchanged claim is a supersession
/// with a reason, not a silent adjustment". The two are different operations
/// with different authority, so they are different values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GradeRequirementChange {
    /// The requirement rises; evidence already exposed keeps the grade it was
    /// produced under.
    ProspectiveRaise,
    /// The requirement falls for an unchanged claim; an owner distinct from the
    /// requesting principal must authorise it with a reason.
    ReasonedSupersession,
    /// The requirement is unchanged and only a reason is recorded.
    Unchanged,
}

impl GradeRequirementChange {
    /// Stable wire spelling of this change.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ProspectiveRaise => "prospective_raise",
            Self::ReasonedSupersession => "reasoned_supersession",
            Self::Unchanged => "unchanged",
        }
    }
}

impl std::fmt::Display for GradeRequirementChange {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// Which grade change a revision actually performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GradeChangeKind {
    /// The requirement rose prospectively.
    Raised,
    /// The requirement fell under an explicit reasoned supersession.
    SupersededByReasonedDecision,
    /// The requirement did not move.
    Unchanged,
}

impl GradeChangeKind {
    /// Stable wire spelling of this performed change.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Raised => "raised",
            Self::SupersededByReasonedDecision => "superseded_by_reasoned_decision",
            Self::Unchanged => "unchanged",
        }
    }
}

impl std::fmt::Display for GradeChangeKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// The result of one declared grade-requirement change (I21.2).
///
/// I21.2: "Evidence already exposed retains the grade and lane under which it
/// was produced; raising the requirement does not retroactively turn exploratory
/// evidence into confirmation" and "A claim carries the grade it was produced
/// under; a later reader may not upgrade it by quoting it." The previous
/// revision's binding is therefore retained here, so an old claim still resolves
/// to the grade and lane it was produced under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GradeRevisionOutcome {
    /// Profile identity whose requirement changed.
    pub profile_id: String,
    /// Revision before the change.
    pub previous_revision: u64,
    /// Grade requirement before the change.
    pub previous_grade: EvidenceGrade,
    /// Exact digest of the previous revision.
    pub previous_integrity_digest: String,
    /// Revision after the change.
    pub revised_revision: u64,
    /// Grade requirement after the change.
    pub revised_grade: EvidenceGrade,
    /// Exact digest of the revised revision.
    pub revised_integrity_digest: String,
    /// Lane the revised revision declares.
    pub revised_lane: InquiryLane,
    /// Declared intent of this change.
    pub declared_change: GradeRequirementChange,
    /// Which change actually happened.
    pub performed_change: GradeChangeKind,
    /// Reason recorded for the change.
    pub reason: String,
    /// Owner that authorised a supersession; empty for a raise.
    pub supersession_owner: String,
    /// The revised profile revision, admitted under the same selection.
    pub revised_profile: InquiryProtocolProfile,
    /// Digest over the whole outcome.
    pub digest: String,
}

impl GradeRevisionOutcome {
    /// The binding a claim produced under the previous revision still resolves
    /// to, so a later reader cannot upgrade it by quoting it.
    #[must_use]
    pub fn previous_claim_binding(&self) -> String {
        format!(
            "{}@{}@{}",
            self.profile_id, self.previous_revision, self.previous_integrity_digest
        )
    }

    /// The binding a claim produced under the revised revision resolves to.
    #[must_use]
    pub fn revised_claim_binding(&self) -> String {
        format!(
            "{}@{}@{}",
            self.profile_id, self.revised_revision, self.revised_integrity_digest
        )
    }
}

/// Revises the grade requirement of one profile under a declared change.
///
/// This is the production caller of
/// [`InquiryProtocolProfile::revise`]: the profile ladder itself stays owned by
/// [`crate::inquiry_governance`], and this module only decides which declared
/// change is admissible and with whose authority. A raise is prospective, a
/// supersession needs a reason and an owner distinct from the requesting
/// principal (so the caller cannot lower the requirement to make a failed
/// inquiry pass), and both keep the previous binding so old claims are unchanged.
///
/// # Errors
///
/// Returns [`LaneRegistrationError::Blank`] for a blank reason or supersession
/// owner, [`LaneRegistrationError::SupersessionOwnerRequired`] when a
/// supersession names no owner distinct from the requesting principal,
/// [`LaneRegistrationError::RegistrationNotCommitted`] when a confirmatory lane
/// revision does not carry the committed registration digest (or invents one
/// for an exploratory lane), [`LaneRegistrationError::GradeChangeNotAsDeclared`]
/// when the built revision's grade is not the declared change, and any profile
/// error the sibling domain raises.
pub fn revise_grade_requirement(
    profile: &InquiryProtocolProfile,
    params: InquiryProfileParams,
    declared_change: GradeRequirementChange,
    reason: &str,
    supersession_owner: &str,
    committed_registration_digest: Option<&str>,
) -> Result<GradeRevisionOutcome, LaneRegistrationError> {
    profile.validate_integrity()?;
    require_text(reason, "grade_revision.reason")?;
    let confirmatory = matches!(
        profile.lane,
        InquiryLane::Confirmatory | InquiryLane::MixedWithDeclaredSplit
    );
    if declared_change == GradeRequirementChange::ReasonedSupersession {
        require_text(supersession_owner, "grade_revision.supersession_owner")?;
        if supersession_owner == profile.requester_principal {
            return Err(LaneRegistrationError::SupersessionOwnerRequired {
                field: "grade_revision.supersession_owner",
            });
        }
    }
    // A confirmatory revision must carry the committed registration digest; an
    // exploratory revision must carry none, so a confirmatory registration can
    // never be invented for work that never needed one.
    let expected = committed_registration_digest.map(str::to_owned);
    if confirmatory != expected.is_some() {
        return Err(LaneRegistrationError::RegistrationNotCommitted {
            field: "grade_revision.lane_registration_digest",
        });
    }
    let mut params = params;
    params.lane_registration_digest = expected;
    let revised = profile.revise(params, reason)?;
    revised.validate_integrity()?;
    let previous_grade = profile.evidence_grade;
    let performed_change = match declared_change {
        GradeRequirementChange::ProspectiveRaise => {
            if revised.evidence_grade.rank() <= previous_grade.rank() {
                return Err(LaneRegistrationError::GradeChangeNotAsDeclared {
                    field: "grade_revision.revised_grade",
                });
            }
            GradeChangeKind::Raised
        }
        GradeRequirementChange::ReasonedSupersession => {
            if revised.evidence_grade.rank() >= previous_grade.rank() {
                return Err(LaneRegistrationError::GradeChangeNotAsDeclared {
                    field: "grade_revision.revised_grade",
                });
            }
            GradeChangeKind::SupersededByReasonedDecision
        }
        GradeRequirementChange::Unchanged => {
            if revised.evidence_grade != previous_grade {
                return Err(LaneRegistrationError::GradeChangeNotAsDeclared {
                    field: "grade_revision.revised_grade",
                });
            }
            GradeChangeKind::Unchanged
        }
    };
    Ok(build_outcome(
        profile,
        revised,
        declared_change,
        performed_change,
        reason,
        supersession_owner,
    ))
}

/// Assembles the outcome record of one admitted grade change.
fn build_outcome(
    profile: &InquiryProtocolProfile,
    revised: InquiryProtocolProfile,
    declared_change: GradeRequirementChange,
    performed_change: GradeChangeKind,
    reason: &str,
    supersession_owner: &str,
) -> GradeRevisionOutcome {
    let mut outcome = GradeRevisionOutcome {
        profile_id: profile.profile_id.clone(),
        previous_revision: profile.revision,
        previous_grade: profile.evidence_grade,
        previous_integrity_digest: profile.integrity_digest.clone(),
        revised_revision: revised.revision,
        revised_grade: revised.evidence_grade,
        revised_integrity_digest: revised.integrity_digest.clone(),
        revised_lane: revised.lane,
        declared_change,
        performed_change,
        reason: reason.to_owned(),
        supersession_owner: if performed_change == GradeChangeKind::SupersededByReasonedDecision {
            supersession_owner.to_owned()
        } else {
            String::new()
        },
        revised_profile: revised,
        digest: String::new(),
    };
    let mut preimage = String::from("lane-grade-revision-outcome/v1;");
    push_field(&mut preimage, "profile_id", &outcome.profile_id);
    push_field(
        &mut preimage,
        "previous_revision",
        &outcome.previous_revision.to_string(),
    );
    push_field(
        &mut preimage,
        "previous_grade",
        &outcome.previous_grade.to_string(),
    );
    push_field(
        &mut preimage,
        "previous_integrity_digest",
        &outcome.previous_integrity_digest,
    );
    push_field(
        &mut preimage,
        "revised_revision",
        &outcome.revised_revision.to_string(),
    );
    push_field(
        &mut preimage,
        "revised_grade",
        &outcome.revised_grade.to_string(),
    );
    push_field(
        &mut preimage,
        "revised_integrity_digest",
        &outcome.revised_integrity_digest,
    );
    push_field(
        &mut preimage,
        "revised_lane",
        outcome.revised_lane.wire_name(),
    );
    push_field(
        &mut preimage,
        "declared_change",
        outcome.declared_change.wire_name(),
    );
    push_field(
        &mut preimage,
        "performed_change",
        outcome.performed_change.wire_name(),
    );
    push_field(&mut preimage, "reason", &outcome.reason);
    push_field(
        &mut preimage,
        "supersession_owner",
        &outcome.supersession_owner,
    );
    outcome.digest = freeze(&preimage);
    outcome
}

// ---------------------------------------------------------------------------
// The commit-before-exposure gate
// ---------------------------------------------------------------------------

/// Named constructor arguments for [`authorise_confirmatory_exposure`].
#[derive(Debug)]
pub struct ConfirmatoryReleaseRequest<'a> {
    /// Profile revision the claim is produced under.
    pub profile: &'a InquiryProtocolProfile,
    /// Committed registration the claim relies on.
    pub registration: &'a LaneRegistration,
    /// Append-only exposure ledger.
    pub ledger: &'a ExposureLedger,
    /// Delivered fields actually handed to the consumer.
    pub deliveries: &'a [BlindedDelivery],
    /// Evaluation attempts already recorded for the released evidence.
    pub attempts: &'a [AttemptRecord],
    /// Exact evidence revision about to be released or evaluated.
    pub evidence_revision_digest: &'a str,
    /// Every evidence handle the consumer will read, including derived
    /// summaries, cached retrievals and shared ancestor context.
    pub delivered_handles: &'a BTreeSet<String>,
    /// State Fence the release happens under.
    pub current_fence: &'a StateFence,
}

/// Proof that a committed registration precedes the exposure of one exact
/// evidence revision (I21.4).
///
/// The proof is an owner-issued ordering receipt chain plus an attested exposure
/// coverage. A caller timestamp changes nothing; a predated timestamp, a stale
/// fence or a receipt replayed for another partition all fail above.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmatoryExposureAuthorization {
    /// Registration identity the proof belongs to.
    pub registration_id: String,
    /// Committed registration digest the proof belongs to.
    pub registration_digest: String,
    /// Receipt of the registration commit.
    pub commit_receipt_digest: String,
    /// Journal the commit and the exposure receipts share.
    pub journal_identity: String,
    /// Inquiry identity the proof belongs to.
    pub inquiry_id: String,
    /// Profile identity the proof belongs to.
    pub profile_id: String,
    /// Exact profile revision digest the proof belongs to.
    pub profile_digest: String,
    /// Grade requirement the claim is produced under.
    pub evidence_grade: EvidenceGrade,
    /// Declared lane.
    pub lane: InquiryLane,
    /// Exact evidence revision the proof covers.
    pub evidence_revision_digest: String,
    /// Digest over the sorted delivered handles.
    pub delivered_handle_digest: String,
    /// Number of delivered handles.
    pub delivered_handle_count: usize,
    /// Exposure events the proof was checked against.
    pub exposure_event_count: usize,
    /// Channels attested as observed.
    pub attested_channels: BTreeSet<ExposureChannel>,
    /// State Fence the proof was produced under.
    pub state_fence: StateFence,
    /// Digest over the whole proof.
    pub authorization_digest: String,
}

/// Authorises release of relevant outcome material, or the start of a dependent
/// evaluation, for a confirmatory lane or a confirmatory partition.
///
/// The check is the real boundary described by I21.4: a confirmatory run cannot
/// receive relevant outcome material or begin evaluation before a committed
/// matching registration. Every step is an owner-issued fact; none of them is a
/// caller boolean, a caller timestamp or a comparison of unrelated clocks.
///
/// # Errors
///
/// Returns [`LaneRegistrationError::LaneRegistrationRequired`] when the profile
/// declares no confirmatory content, [`LaneRegistrationError::StaleFence`] for a
/// stale fence, [`LaneRegistrationError::RegistrationNotCommitted`] when the
/// profile does not carry the committed registration digest,
/// [`LaneRegistrationError::OrderingReceiptReplayed`] for a registration
/// replayed for another profile or another partition,
/// [`LaneRegistrationError::OrderingReceiptForeign`] for a receipt from another
/// owner journal, [`LaneRegistrationError::ExposurePrecedesCommit`] when
/// exposure is not provably after the commit,
/// [`LaneRegistrationError::ExposureCoverageIncomplete`] when a mandatory
/// channel is unattested, [`LaneRegistrationError::CrossLaneEvidence`] when
/// exploratory material reaches the confirmatory evaluator,
/// [`LaneRegistrationError::UnregisteredDeviation`] for a change outside the
/// registered allowance, [`LaneRegistrationError::AttemptNotDisclosed`] for a
/// hidden failed or negative attempt, and the blinding errors of
/// [`BlindingApplication::evaluate`].
pub fn authorise_confirmatory_exposure(
    request: &ConfirmatoryReleaseRequest<'_>,
) -> Result<ConfirmatoryExposureAuthorization, LaneRegistrationError> {
    request.profile.validate_integrity()?;
    request.registration.validate_integrity()?;
    request.ledger.validate_integrity()?;
    require_digest(
        request.evidence_revision_digest,
        "release.evidence_revision_digest",
    )?;
    let committed = verify_lane_and_profile_binding(request)?;
    verify_current_fence(request.profile, request.registration, request.current_fence)?;
    verify_partition_binding(request.registration, request.profile.lane)?;
    request.registration.require_commit_precedes(
        request.ledger,
        request.delivered_handles,
        request.evidence_revision_digest,
    )?;
    verify_exposure_coverage(request.ledger)?;
    verify_cross_lane_isolation(request.registration, request.delivered_handles)?;
    verify_attempts(
        request.registration,
        request.attempts,
        request.evidence_revision_digest,
        "release.attempt",
    )?;
    BlindingApplication::evaluate(request.registration, request.deliveries)?;
    Ok(build_authorization(request, committed))
}

/// Verifies that the lane is confirmatory content and that the registration and
/// the profile it binds are the same exact revision.
fn verify_lane_and_profile_binding(
    request: &ConfirmatoryReleaseRequest<'_>,
) -> Result<String, LaneRegistrationError> {
    if !matches!(
        request.profile.lane,
        InquiryLane::Confirmatory | InquiryLane::MixedWithDeclaredSplit
    ) {
        return Err(LaneRegistrationError::LaneRegistrationRequired {
            field: "profile.lane",
        });
    }
    if request.registration.profile_digest != request.profile.integrity_digest
        || request.registration.inquiry_id != request.profile.inquiry_id
    {
        return Err(LaneRegistrationError::OrderingReceiptReplayed {
            field: "registration.profile_digest",
        });
    }
    let committed = request.registration.committed_registration_digest();
    let declared = request
        .profile
        .independence_and_blinding_policy
        .lane_registration_digest
        .as_deref();
    if declared != Some(committed.as_str()) {
        return Err(LaneRegistrationError::RegistrationNotCommitted {
            field: "profile.independence_and_blinding_policy.lane_registration_digest",
        });
    }
    Ok(committed)
}

/// Verifies that the presented fence is the one everything was frozen under.
fn verify_current_fence(
    profile: &InquiryProtocolProfile,
    registration: &LaneRegistration,
    current_fence: &StateFence,
) -> Result<(), LaneRegistrationError> {
    if &profile.state_fence != current_fence
        || &registration.state_fence != current_fence
        || &registration.owner_receipt.state_fence != current_fence
    {
        return Err(LaneRegistrationError::StaleFence {
            field: "release.current_fence",
        });
    }
    Ok(())
}

/// Verifies that a mixed lane carries a frozen partition and that any partition
/// still re-proves its own digest. A purely confirmatory lane has no
/// exploratory side, so I21.4 requires no partition of it.
fn verify_partition_binding(
    registration: &LaneRegistration,
    lane: InquiryLane,
) -> Result<(), LaneRegistrationError> {
    match &registration.evidence_partition {
        Some(partition) => partition.validate_integrity(),
        None if lane == InquiryLane::MixedWithDeclaredSplit => {
            Err(LaneRegistrationError::PartitionNotFrozen {
                field: "registration.evidence_partition",
            })
        }
        None => Ok(()),
    }
}

/// Verifies that exposure coverage is attested across every mandatory channel.
fn verify_exposure_coverage(ledger: &ExposureLedger) -> Result<(), LaneRegistrationError> {
    if !ledger.coverage_attested {
        return Err(LaneRegistrationError::ExposureCoverageIncomplete {
            field: "ledger.coverage_attested",
        });
    }
    if !ledger.unattested_channels().is_empty() {
        return Err(LaneRegistrationError::ExposureCoverageIncomplete {
            field: "ledger.observed_channels",
        });
    }
    Ok(())
}

/// Verifies that no exploratory material reaches the confirmatory evaluator.
///
/// The delivered handles name everything the consumer will read, so a derived
/// summary, a cached retrieval or a shared ancestor context is judged on the
/// same partition as the case it feeds.
fn verify_cross_lane_isolation(
    registration: &LaneRegistration,
    delivered_handles: &BTreeSet<String>,
) -> Result<(), LaneRegistrationError> {
    let Some(partition) = &registration.evidence_partition else {
        return Ok(());
    };
    for handle in delivered_handles {
        if partition.side_for(handle)? != PartitionSide::Confirmatory {
            return Err(LaneRegistrationError::CrossLaneEvidence {
                field: "release.delivered_handles",
            });
        }
    }
    Ok(())
}

/// Verifies the recorded attempts on one evidence revision.
///
/// I21.4 forbids "replace the evaluator after seeing results" and "hide failed
/// attempts", so both are checked here against the registered evaluator digest
/// and against the disclosure flag. The *direction* of an outcome is never
/// checked: a compliant negative result is a valid confirmatory result.
fn verify_attempts(
    registration: &LaneRegistration,
    attempts: &[AttemptRecord],
    evidence_revision_digest: &str,
    field: &'static str,
) -> Result<(), LaneRegistrationError> {
    let registered_evaluator = &registration
        .contract_protocol_hypothesis_and_evaluator_digests
        .evaluator_digest;
    for attempt in attempts {
        if attempt.evidence_revision_digest != evidence_revision_digest {
            continue;
        }
        attempt.validate_integrity()?;
        if &attempt.evaluator_digest != registered_evaluator {
            return Err(LaneRegistrationError::UnregisteredDeviation {
                field: "attempt.evaluator_digest",
            });
        }
        if attempt.outcome.requires_disclosure() && !attempt.reported_with_result {
            return Err(LaneRegistrationError::AttemptNotDisclosed { field });
        }
    }
    Ok(())
}

/// Assembles the authorization record from a satisfied release request.
fn build_authorization(
    request: &ConfirmatoryReleaseRequest<'_>,
    committed: String,
) -> ConfirmatoryExposureAuthorization {
    let mut handle_digest = String::from("lane-delivered-handles/v1;");
    push_count(
        &mut handle_digest,
        "delivered_handles",
        request.delivered_handles.len(),
    );
    for handle in request.delivered_handles {
        push_field(&mut handle_digest, "delivered_handle", handle);
    }
    let mut authorization = ConfirmatoryExposureAuthorization {
        registration_id: request.registration.registration_id.clone(),
        registration_digest: committed,
        commit_receipt_digest: request.registration.owner_receipt.receipt_digest.clone(),
        journal_identity: request.registration.owner_receipt.journal_identity.clone(),
        inquiry_id: request.profile.inquiry_id.clone(),
        profile_id: request.profile.profile_id.clone(),
        profile_digest: request.profile.integrity_digest.clone(),
        evidence_grade: request.profile.evidence_grade,
        lane: request.profile.lane,
        evidence_revision_digest: request.evidence_revision_digest.to_owned(),
        delivered_handle_digest: freeze(&handle_digest),
        delivered_handle_count: request.delivered_handles.len(),
        exposure_event_count: request
            .ledger
            .events_touching(request.delivered_handles, request.evidence_revision_digest)
            .len(),
        attested_channels: request.ledger.observed_channels.clone(),
        state_fence: request.current_fence.clone(),
        authorization_digest: String::new(),
    };
    authorization.authorization_digest = freeze_authorization(&authorization);
    authorization
}

fn freeze_authorization(authorization: &ConfirmatoryExposureAuthorization) -> String {
    let mut preimage = String::from("lane-confirmatory-exposure-authorization/v1;");
    push_field(
        &mut preimage,
        "registration_id",
        &authorization.registration_id,
    );
    push_field(
        &mut preimage,
        "registration_digest",
        &authorization.registration_digest,
    );
    push_field(
        &mut preimage,
        "commit_receipt_digest",
        &authorization.commit_receipt_digest,
    );
    push_field(
        &mut preimage,
        "journal_identity",
        &authorization.journal_identity,
    );
    push_field(&mut preimage, "inquiry_id", &authorization.inquiry_id);
    push_field(&mut preimage, "profile_id", &authorization.profile_id);
    push_field(
        &mut preimage,
        "profile_digest",
        &authorization.profile_digest,
    );
    push_field(
        &mut preimage,
        "evidence_grade",
        &authorization.evidence_grade.to_string(),
    );
    push_field(&mut preimage, "lane", authorization.lane.wire_name());
    push_field(
        &mut preimage,
        "evidence_revision_digest",
        &authorization.evidence_revision_digest,
    );
    push_field(
        &mut preimage,
        "delivered_handle_digest",
        &authorization.delivered_handle_digest,
    );
    push_field(
        &mut preimage,
        "delivered_handle_count",
        &authorization.delivered_handle_count.to_string(),
    );
    push_field(
        &mut preimage,
        "exposure_event_count",
        &authorization.exposure_event_count.to_string(),
    );
    push_count(
        &mut preimage,
        "attested_channels",
        authorization.attested_channels.len(),
    );
    for channel in &authorization.attested_channels {
        push_field(&mut preimage, "attested_channel", channel.wire_name());
    }
    freeze(&preimage)
}

// ---------------------------------------------------------------------------
// Claims and findings
// ---------------------------------------------------------------------------

/// Which class of lane result one record is (I21.2/I21.4).
///
/// Grade is orthogonal to status, so `SCIENCE_GRADE` appears in both classes and
/// the class is the only thing that separates E3 exploratory from E3
/// confirmatory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LaneEvidenceClass {
    /// A confirmatory claim produced under a committed registration.
    ConfirmatoryClaim,
    /// An exploratory finding stored under
    /// [`EXPLORATORY_FINDING_CLASS`].
    ExploratoryFinding,
}

impl LaneEvidenceClass {
    /// Stable wire spelling of this class.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ConfirmatoryClaim => "confirmatory_claim",
            Self::ExploratoryFinding => EXPLORATORY_FINDING_CLASS,
        }
    }

    /// Whether this class may be read back as a confirmation.
    #[must_use]
    pub const fn is_confirmatory(self) -> bool {
        matches!(self, Self::ConfirmatoryClaim)
    }
}

impl std::fmt::Display for LaneEvidenceClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// The sufficient truth surface one confirmatory claim rests on (I21.4).
///
/// I21.2: "Any new sufficient truth surface, including replication or formal
/// proof, is a separately bound result, not a retroactive upgrade by
/// quotation." Each variant is a separately bound result with its own
/// registration and authorization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfirmatoryClaimKind {
    /// A preregistered test.
    PreregisteredTest,
    /// Evidence from a fresh holdout.
    FreshHoldout,
    /// An independent run.
    IndependentRun,
    /// A replication.
    Replication,
    /// A formal proof.
    FormalProof,
    /// Another sufficient truth surface named by the registration.
    OtherSufficientTruthSurface,
}

impl ConfirmatoryClaimKind {
    /// Stable wire spelling of this truth surface.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::PreregisteredTest => "preregistered_test",
            Self::FreshHoldout => "fresh_holdout",
            Self::IndependentRun => "independent_run",
            Self::Replication => "replication",
            Self::FormalProof => "formal_proof",
            Self::OtherSufficientTruthSurface => "other_sufficient_truth_surface",
        }
    }
}

impl std::fmt::Display for ConfirmatoryClaimKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.wire_name())
    }
}

/// One confirmatory claim produced under a committed registration (I21.4).
///
/// The claim carries the grade and lane it was produced under and the negative
/// or failed attempts shown with it. I21.2: "a later reader may not upgrade it
/// by quoting it", so nothing here is recomputed from a later grade
/// requirement. I21.4: "Acceptance is outcome-neutral: a compliant negative
/// result is a valid confirmatory result" — this record is about compliance and
/// deliberately carries no field for the direction of the result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfirmatoryLaneClaim {
    /// Stable claim identity.
    pub claim_id: String,
    /// Inquiry identity the claim belongs to.
    pub inquiry_id: String,
    /// Profile identity the claim was produced under.
    pub profile_id: String,
    /// Exact profile revision digest the claim was produced under.
    pub profile_digest: String,
    /// Grade requirement the claim was produced under.
    pub produced_under_grade: EvidenceGrade,
    /// Lane the claim was produced under.
    pub produced_under_lane: InquiryLane,
    /// Sufficient truth surface the claim rests on.
    pub truth_surface: ConfirmatoryClaimKind,
    /// Committed registration digest the claim rests on.
    pub registration_digest: String,
    /// Authorization digest of the release this claim followed.
    pub authorization_digest: String,
    /// Exact evidence revision the claim was produced from.
    pub evidence_revision_digest: String,
    /// Attempts that were not confirmed or that failed, shown with the result.
    pub negative_or_failed_attempts: Vec<String>,
    /// State Fence the claim was produced under.
    pub state_fence: StateFence,
    /// Instant the claim was recorded.
    pub recorded_at_ms: i64,
    /// Digest over the whole claim.
    pub claim_digest: String,
}

impl ConfirmatoryLaneClaim {
    /// Closes one confirmatory claim over a satisfied authorization.
    ///
    /// # Errors
    ///
    /// Returns a field error for blank input, a stale-fence error when the claim
    /// is recorded under a fence other than the authorization's, and
    /// [`LaneRegistrationError::AttemptNotDisclosed`] when a failed or negative
    /// attempt on the authorized evidence revision is not shown.
    pub fn confirm(
        claim_id: &str,
        authorization: &ConfirmatoryExposureAuthorization,
        truth_surface: ConfirmatoryClaimKind,
        attempts: &[AttemptRecord],
        recorded_at_ms: i64,
        state_fence: &StateFence,
    ) -> Result<Self, LaneRegistrationError> {
        require_text(claim_id, "claim.claim_id")?;
        if &authorization.state_fence != state_fence {
            return Err(LaneRegistrationError::StaleFence {
                field: "claim.state_fence",
            });
        }
        let hidden = attempts.iter().any(|attempt| {
            attempt.evidence_revision_digest == authorization.evidence_revision_digest
                && attempt.outcome.requires_disclosure()
                && !attempt.reported_with_result
        });
        if hidden {
            return Err(LaneRegistrationError::AttemptNotDisclosed {
                field: "claim.reported_with_result",
            });
        }
        let mut negative_or_failed: Vec<String> = attempts
            .iter()
            .filter(|attempt| {
                attempt.evidence_revision_digest == authorization.evidence_revision_digest
                    && attempt.outcome.requires_disclosure()
            })
            .map(|attempt| attempt.attempt_id.clone())
            .collect();
        negative_or_failed.sort();
        let mut claim = Self {
            claim_id: claim_id.to_owned(),
            inquiry_id: authorization.inquiry_id.clone(),
            profile_id: authorization.profile_id.clone(),
            profile_digest: authorization.profile_digest.clone(),
            produced_under_grade: authorization.evidence_grade,
            produced_under_lane: authorization.lane,
            truth_surface,
            registration_digest: authorization.registration_digest.clone(),
            authorization_digest: authorization.authorization_digest.clone(),
            evidence_revision_digest: authorization.evidence_revision_digest.clone(),
            negative_or_failed_attempts: negative_or_failed,
            state_fence: state_fence.clone(),
            recorded_at_ms,
            claim_digest: String::new(),
        };
        claim.claim_digest = claim.compute_digest();
        Ok(claim)
    }

    /// The class this record may be read back as.
    #[must_use]
    pub const fn evidence_class(&self) -> LaneEvidenceClass {
        LaneEvidenceClass::ConfirmatoryClaim
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("lane-confirmatory-claim/v1;");
        push_field(&mut preimage, "claim_id", &self.claim_id);
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "profile_id", &self.profile_id);
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
            "truth_surface",
            self.truth_surface.wire_name(),
        );
        push_field(
            &mut preimage,
            "registration_digest",
            &self.registration_digest,
        );
        push_field(
            &mut preimage,
            "authorization_digest",
            &self.authorization_digest,
        );
        push_field(
            &mut preimage,
            "evidence_revision_digest",
            &self.evidence_revision_digest,
        );
        push_count(
            &mut preimage,
            "negative_or_failed_attempts",
            self.negative_or_failed_attempts.len(),
        );
        for attempt in &self.negative_or_failed_attempts {
            push_field(&mut preimage, "negative_or_failed_attempt", attempt);
        }
        push_field(
            &mut preimage,
            "recorded_at_ms",
            &self.recorded_at_ms.to_string(),
        );
        freeze(&preimage)
    }
}

/// One exploratory finding stored under [`EXPLORATORY_FINDING_CLASS`] (I21.4).
///
/// I21.4: "Exploratory results are stored as `EXPLORATORY_FINDING`" and "do not
/// require a confirmatory registration for purely exploratory work". This record
/// therefore needs no registration, and it also never reads back as a
/// confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExploratoryFinding {
    /// Stable finding identity.
    pub finding_id: String,
    /// Storage class the finding is stored under.
    pub finding_class: String,
    /// Inquiry identity the finding belongs to.
    pub inquiry_id: String,
    /// Profile identity the finding was produced under.
    pub profile_id: String,
    /// Exact profile revision digest the finding was produced under.
    pub profile_digest: String,
    /// Grade requirement the finding was produced under.
    pub produced_under_grade: EvidenceGrade,
    /// Lane the finding was produced under.
    pub produced_under_lane: InquiryLane,
    /// Exact evidence revision the finding was produced from.
    pub evidence_revision_digest: String,
    /// State Fence the finding was produced under.
    pub state_fence: StateFence,
    /// Instant the finding was recorded.
    pub recorded_at_ms: i64,
    /// Digest over the whole finding.
    pub digest: String,
}

impl ExploratoryFinding {
    /// Records one exploratory finding. No lane registration is required.
    ///
    /// # Errors
    ///
    /// Returns a field error for blank input, a stale-fence error when the
    /// finding is recorded under a fence other than the profile's, and
    /// [`LaneRegistrationError::OrderingReceiptReplayed`] when the same finding
    /// identity is reused on another evidence revision.
    pub fn record(
        finding_id: &str,
        profile: &InquiryProtocolProfile,
        evidence_revision_digest: &str,
        recorded_at_ms: i64,
        state_fence: &StateFence,
        already_recorded: &[ExploratoryFinding],
    ) -> Result<Self, LaneRegistrationError> {
        require_text(finding_id, "finding.finding_id")?;
        require_digest(evidence_revision_digest, "finding.evidence_revision_digest")?;
        if &profile.state_fence != state_fence {
            return Err(LaneRegistrationError::StaleFence {
                field: "finding.state_fence",
            });
        }
        if already_recorded.iter().any(|recorded| {
            recorded.finding_id == finding_id
                && recorded.evidence_revision_digest != evidence_revision_digest
        }) {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "finding.finding_id",
            });
        }
        let mut finding = Self {
            finding_id: finding_id.to_owned(),
            finding_class: EXPLORATORY_FINDING_CLASS.to_owned(),
            inquiry_id: profile.inquiry_id.clone(),
            profile_id: profile.profile_id.clone(),
            profile_digest: profile.integrity_digest.clone(),
            produced_under_grade: profile.evidence_grade,
            produced_under_lane: profile.lane,
            evidence_revision_digest: evidence_revision_digest.to_owned(),
            state_fence: state_fence.clone(),
            recorded_at_ms,
            digest: String::new(),
        };
        finding.digest = finding.compute_digest();
        Ok(finding)
    }

    /// The class this record may be read back as.
    #[must_use]
    pub const fn evidence_class(&self) -> LaneEvidenceClass {
        LaneEvidenceClass::ExploratoryFinding
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("lane-exploratory-finding/v1;");
        push_field(&mut preimage, "finding_id", &self.finding_id);
        push_field(&mut preimage, "finding_class", &self.finding_class);
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "profile_id", &self.profile_id);
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
            "recorded_at_ms",
            &self.recorded_at_ms.to_string(),
        );
        freeze(&preimage)
    }
}

// ---------------------------------------------------------------------------
// The composed discipline
// ---------------------------------------------------------------------------

/// The grade and lane discipline bound to one inquiry (I21.2/I21.4, #1763).
///
/// This is the entry point a consumer path uses. It opens the exposure ledger,
/// admits a committed registration, records exposure, deviations, attempts and
/// deliveries, revalidates the current fence and profile on queued execution and
/// resume, gates confirmatory release and closes confirmatory claims or
/// exploratory findings. It owns no scheduling, no acquisition, no provider
/// execution, no canonical write and no memory promotion: every receipt it holds
/// was issued by the existing record/artifact, disclosure, execution and
/// acquisition owners.
#[derive(Clone, Debug)]
pub struct InquiryLaneDiscipline {
    profile: InquiryProtocolProfile,
    ledger: ExposureLedger,
    registration_history: Vec<LaneRegistration>,
    active_registration: Option<usize>,
    deviations: Vec<DeviationRecord>,
    attempts: Vec<AttemptRecord>,
    deliveries: Vec<BlindedDelivery>,
    confirmatory_claims: Vec<ConfirmatoryLaneClaim>,
    exploratory_findings: Vec<ExploratoryFinding>,
    preserved_claim_bindings: Vec<String>,
}

impl InquiryLaneDiscipline {
    /// Opens the discipline for one profile revision.
    ///
    /// # Errors
    ///
    /// Returns the profile's own integrity failure or a stale-fence error.
    pub fn open(profile: InquiryProtocolProfile) -> Result<Self, LaneRegistrationError> {
        let ledger = ExposureLedger::open(&profile)?;
        let opening_binding = format!(
            "{}@{}@{}",
            profile.profile_id, profile.revision, profile.integrity_digest
        );
        Ok(Self {
            profile,
            ledger,
            registration_history: Vec::new(),
            active_registration: None,
            deviations: Vec::new(),
            attempts: Vec::new(),
            deliveries: Vec::new(),
            confirmatory_claims: Vec::new(),
            exploratory_findings: Vec::new(),
            preserved_claim_bindings: vec![opening_binding],
        })
    }

    /// The profile revision this discipline currently governs.
    #[must_use]
    pub fn profile(&self) -> &InquiryProtocolProfile {
        &self.profile
    }

    /// The append-only exposure ledger.
    #[must_use]
    pub fn ledger(&self) -> &ExposureLedger {
        &self.ledger
    }

    /// Every registration ever committed for this inquiry, in commit order.
    #[must_use]
    pub fn registration_history(&self) -> &[LaneRegistration] {
        &self.registration_history
    }

    /// The registration that currently authorises confirmatory work, if any.
    ///
    /// A grade revision clears this without erasing the history, so evidence
    /// produced under the previous revision keeps its own registration and
    /// becomes unregistered — and therefore exploratory — until a new
    /// registration governs it.
    #[must_use]
    pub fn active_registration(&self) -> Option<&LaneRegistration> {
        self.active_registration
            .and_then(|index| self.registration_history.get(index))
    }

    /// Deviations recorded for this inquiry, in arrival order.
    #[must_use]
    pub fn deviations(&self) -> &[DeviationRecord] {
        &self.deviations
    }

    /// Attempts recorded for this inquiry, in arrival order.
    #[must_use]
    pub fn attempts(&self) -> &[AttemptRecord] {
        &self.attempts
    }

    /// Confirmatory claims closed for this inquiry, in arrival order.
    #[must_use]
    pub fn confirmatory_claims(&self) -> &[ConfirmatoryLaneClaim] {
        &self.confirmatory_claims
    }

    /// Exploratory findings stored for this inquiry, in arrival order.
    #[must_use]
    pub fn exploratory_findings(&self) -> &[ExploratoryFinding] {
        &self.exploratory_findings
    }

    /// Commits a registration for the current profile revision.
    ///
    /// A purely exploratory profile needs no registration, so the lane is
    /// refused rather than faked: there is nothing to register.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::LaneRegistrationRequired`] for an
    /// exploratory profile, [`LaneRegistrationError::PartitionNotFrozen`] when a
    /// mixed lane registers no partition, a profile-binding or replay error for a
    /// registration bound to another revision, and the errors of
    /// [`LaneRegistration::register`].
    pub fn commit_registration(
        &mut self,
        params: LaneRegistrationParams,
    ) -> Result<&LaneRegistration, LaneRegistrationError> {
        if params.profile_digest != self.profile.integrity_digest
            || params.inquiry_id != self.profile.inquiry_id
        {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "registration.profile_digest",
            });
        }
        if self.profile.lane == InquiryLane::Exploratory {
            return Err(LaneRegistrationError::LaneRegistrationRequired {
                field: "profile.lane",
            });
        }
        if self.profile.lane == InquiryLane::MixedWithDeclaredSplit
            && params.evidence_partition.is_none()
        {
            return Err(LaneRegistrationError::PartitionNotFrozen {
                field: "registration.evidence_partition",
            });
        }
        let registration = LaneRegistration::register(params)?;
        if self
            .registration_history
            .iter()
            .any(|recorded| recorded.registration_id == registration.registration_id)
        {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "registration.registration_id",
            });
        }
        self.registration_history.push(registration);
        self.active_registration = Some(self.registration_history.len() - 1);
        self.active_registration()
            .ok_or(LaneRegistrationError::RegistrationNotCommitted {
                field: "registration_history",
            })
    }

    /// Commits the next revision of the active registration with a reason.
    ///
    /// I21.2: "In a confirmatory lane, a change outside registered deviations
    /// also invalidates the registration; subsequent analysis is exploratory
    /// until a new registration is frozen before new outcome exposure." The
    /// earlier revisions stay in the history, so the change is preserved rather
    /// than overwritten, and the new revision only governs evidence whose
    /// exposure receipts chain after its own commit.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::LaneRegistrationRequired`] when no
    /// registration is active, and the errors of
    /// [`LaneRegistration::revise`] otherwise.
    pub fn revise_registration(
        &mut self,
        params: LaneRegistrationParams,
        reason: &str,
    ) -> Result<&LaneRegistration, LaneRegistrationError> {
        let current = self
            .active_registration()
            .ok_or(LaneRegistrationError::LaneRegistrationRequired {
                field: "registration",
            })?
            .clone();
        let revised = current.revise(params, reason)?;
        if self
            .registration_history
            .iter()
            .any(|recorded| recorded.content_digest == revised.content_digest)
        {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "registration.content_digest",
            });
        }
        self.registration_history.push(revised);
        self.active_registration = Some(self.registration_history.len() - 1);
        self.active_registration()
            .ok_or(LaneRegistrationError::RegistrationNotCommitted {
                field: "registration_history",
            })
    }

    /// Records one exposure event against the append-only ledger.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ExposureEvent::record`] and
    /// [`ExposureLedger::record_exposure`].
    pub fn record_exposure(
        &mut self,
        params: ExposureEventParams,
    ) -> Result<&ExposureEvent, LaneRegistrationError> {
        let event = ExposureEvent::record(params)?;
        self.ledger.record_exposure(event)?;
        self.ledger
            .events
            .last()
            .ok_or(LaneRegistrationError::IntegrityMismatch {
                field: "ledger.events",
            })
    }

    /// Attests that exposure coverage is complete for this inquiry.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ExposureLedger::attest_coverage`].
    pub fn attest_exposure_coverage(
        &mut self,
        receipt: OwnerOrderingReceipt,
    ) -> Result<(), LaneRegistrationError> {
        self.ledger.attest_coverage(receipt)
    }

    /// Records one actually delivered field of an evaluator input.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`BlindedDelivery::deliver`].
    pub fn record_delivery(
        &mut self,
        params: BlindedDeliveryParams,
    ) -> Result<&BlindedDelivery, LaneRegistrationError> {
        let delivery = BlindedDelivery::deliver(params)?;
        self.deliveries.push(delivery);
        self.deliveries
            .last()
            .ok_or(LaneRegistrationError::IntegrityMismatch {
                field: "deliveries",
            })
    }

    /// Records one deviation and classifies it against the active registration.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::LaneRegistrationRequired`] when a
    /// confirmatory lane has no active registration, and the errors of
    /// [`DeviationRecord::record`].
    pub fn record_deviation(
        &mut self,
        params: DeviationRecordParams,
    ) -> Result<&DeviationRecord, LaneRegistrationError> {
        let registration = self
            .active_registration()
            .ok_or(LaneRegistrationError::LaneRegistrationRequired {
                field: "registration",
            })?
            .clone();
        let deviation = DeviationRecord::record(params, &registration)?;
        self.deviations.push(deviation);
        self.deviations
            .last()
            .ok_or(LaneRegistrationError::IntegrityMismatch {
                field: "deviations",
            })
    }

    /// Records one evaluation attempt, successful or not.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`AttemptRecord::record`].
    pub fn record_attempt(
        &mut self,
        params: AttemptRecordParams,
    ) -> Result<&AttemptRecord, LaneRegistrationError> {
        let attempt = AttemptRecord::record(params)?;
        self.attempts.push(attempt);
        self.attempts
            .last()
            .ok_or(LaneRegistrationError::IntegrityMismatch { field: "attempts" })
    }

    /// Revalidates the current fence and profile before queued execution or a
    /// resume.
    ///
    /// I21.4 work item six: a resumed run must present the fence and the profile
    /// revision it was admitted under. A restart cannot present a fresh
    /// registration with a backdated claim, because the registration history is
    /// append-only and the active registration must still bind this profile
    /// revision.
    ///
    /// # Errors
    ///
    /// Returns [`LaneRegistrationError::StaleFence`] for a fence other than the
    /// one the profile was frozen under, [`LaneRegistrationError::OrderingReceiptReplayed`]
    /// when the active registration binds another profile revision, and the
    /// ledger's integrity failure.
    pub fn revalidate(&self, current_fence: &StateFence) -> Result<(), LaneRegistrationError> {
        self.profile.validate_integrity()?;
        if &self.profile.state_fence != current_fence {
            return Err(LaneRegistrationError::StaleFence {
                field: "revalidate.current_fence",
            });
        }
        self.ledger.validate_integrity()?;
        let registration_binds_profile = self.active_registration().is_none_or(|registration| {
            registration.profile_digest == self.profile.integrity_digest
        });
        if !registration_binds_profile {
            return Err(LaneRegistrationError::OrderingReceiptReplayed {
                field: "revalidate.registration_profile_digest",
            });
        }
        Ok(())
    }

    /// Revises the grade requirement and re-binds the discipline.
    ///
    /// A raise or a supersession produces a new profile revision, so the
    /// previous registration no longer binds it. The registration history is kept
    /// and the active registration is cleared: evidence produced under the
    /// previous revision keeps its own grade and lane, and any analysis the
    /// previous registration covered is unregistered under the new one until a
    /// new registration is committed.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`revise_grade_requirement`].
    pub fn revise_grade_requirement(
        &mut self,
        params: InquiryProfileParams,
        declared_change: GradeRequirementChange,
        reason: &str,
        supersession_owner: &str,
    ) -> Result<GradeRevisionOutcome, LaneRegistrationError> {
        let committed = self
            .active_registration()
            .map(LaneRegistration::committed_registration_digest);
        let outcome = revise_grade_requirement(
            &self.profile,
            params,
            declared_change,
            reason,
            supersession_owner,
            committed.as_deref(),
        )?;
        self.adopt_revision(&outcome);
        self.preserved_claim_bindings
            .push(outcome.previous_claim_binding());
        self.preserved_claim_bindings
            .push(outcome.revised_claim_binding());
        Ok(outcome)
    }

    /// Bindings of every profile revision this inquiry has been governed under,
    /// oldest first.
    ///
    /// I21.2: "Evidence already exposed retains the grade and lane under which it
    /// was produced; raising the requirement does not retroactively turn
    /// exploratory evidence into confirmation" and "a later reader may not
    /// upgrade it by quoting it." A claim therefore resolves to the binding it
    /// was produced under, and this list keeps every such binding resolvable
    /// after a raise or a supersession.
    #[must_use]
    pub fn preserved_claim_bindings(&self) -> &[String] {
        &self.preserved_claim_bindings
    }

    /// Releases relevant outcome material, or authorises a dependent
    /// evaluation, for the lane this inquiry declares.
    ///
    /// A confirmatory lane or a mixed lane reaches
    /// [`authorise_confirmatory_exposure`]. A purely exploratory lane is
    /// released without a registration, because I21.4 does not require one for
    /// purely exploratory work — and the release is explicitly not a
    /// confirmation.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`authorise_confirmatory_exposure`] for a
    /// confirmatory or mixed lane.
    pub fn release_outcome_material(
        &self,
        evidence_revision_digest: &str,
        delivered_handles: &BTreeSet<String>,
        current_fence: &StateFence,
    ) -> Result<LaneReleaseAuthorization, LaneRegistrationError> {
        if self.profile.lane == InquiryLane::Exploratory {
            return Ok(LaneReleaseAuthorization::Exploratory(
                build_exploratory_release(
                    evidence_revision_digest,
                    delivered_handles,
                    current_fence,
                ),
            ));
        }
        let registration =
            self.active_registration()
                .ok_or(LaneRegistrationError::LaneRegistrationRequired {
                    field: "registration",
                })?;
        let authorization = authorise_confirmatory_exposure(&ConfirmatoryReleaseRequest {
            profile: &self.profile,
            registration,
            ledger: &self.ledger,
            deliveries: &self.deliveries,
            attempts: &self.attempts,
            evidence_revision_digest,
            delivered_handles,
            current_fence,
        })?;
        verify_registered_deviations(
            &self.deviations,
            evidence_revision_digest,
            "release.unregistered_deviation",
        )?;
        Ok(LaneReleaseAuthorization::Confirmatory(Box::new(
            authorization,
        )))
    }

    /// Closes one confirmatory claim for this inquiry.
    ///
    /// The release is re-derived here rather than taken from the caller, so a
    /// claim cannot be closed against a stale or fabricated authorization. The
    /// claim is about compliance only: a compliant negative result closes a
    /// valid confirmatory claim, exactly as I21.4 requires.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`release_outcome_material`] and
    /// [`ConfirmatoryLaneClaim::confirm`].
    pub fn confirm_claim(
        &mut self,
        claim_id: &str,
        truth_surface: ConfirmatoryClaimKind,
        evidence_revision_digest: &str,
        delivered_handles: &BTreeSet<String>,
        current_fence: &StateFence,
        recorded_at_ms: i64,
    ) -> Result<&ConfirmatoryLaneClaim, LaneRegistrationError> {
        let release = self.release_outcome_material(
            evidence_revision_digest,
            delivered_handles,
            current_fence,
        )?;
        if !release.evidence_class().is_confirmatory() {
            return Err(LaneRegistrationError::LaneRegistrationRequired {
                field: "profile.lane",
            });
        }
        let LaneReleaseAuthorization::Confirmatory(authorization) = release else {
            return Err(LaneRegistrationError::LaneRegistrationRequired {
                field: "profile.lane",
            });
        };
        let claim = ConfirmatoryLaneClaim::confirm(
            claim_id,
            &authorization,
            truth_surface,
            &self.attempts,
            recorded_at_ms,
            current_fence,
        )?;
        self.confirmatory_claims.push(claim);
        self.confirmatory_claims
            .last()
            .ok_or(LaneRegistrationError::IntegrityMismatch {
                field: "confirmatory_claims",
            })
    }

    /// Stores one exploratory finding under
    /// [`EXPLORATORY_FINDING_CLASS`].
    ///
    /// # Errors
    ///
    /// Returns the errors of [`ExploratoryFinding::record`].
    pub fn record_exploratory_finding(
        &mut self,
        finding_id: &str,
        evidence_revision_digest: &str,
        recorded_at_ms: i64,
        current_fence: &StateFence,
    ) -> Result<&ExploratoryFinding, LaneRegistrationError> {
        let finding = ExploratoryFinding::record(
            finding_id,
            &self.profile,
            evidence_revision_digest,
            recorded_at_ms,
            current_fence,
            &self.exploratory_findings,
        )?;
        self.exploratory_findings.push(finding);
        self.exploratory_findings
            .last()
            .ok_or(LaneRegistrationError::IntegrityMismatch {
                field: "exploratory_findings",
            })
    }

    /// Re-binds the discipline onto a revised profile revision.
    fn adopt_revision(&mut self, outcome: &GradeRevisionOutcome) {
        self.profile = outcome.revised_profile.clone();
        self.ledger.profile_id = self.profile.profile_id.clone();
        self.ledger.profile_digest = self.profile.integrity_digest.clone();
        self.ledger.state_fence = self.profile.state_fence.clone();
        self.ledger.digest = self.ledger.compute_digest();
        self.active_registration = None;
    }
}

/// Builds the explicitly non-confirmatory release of an exploratory lane.
fn build_exploratory_release(
    evidence_revision_digest: &str,
    delivered_handles: &BTreeSet<String>,
    current_fence: &StateFence,
) -> ExploratoryRelease {
    let mut handle_digest = String::from("lane-delivered-handles/v1;");
    push_count(
        &mut handle_digest,
        "delivered_handles",
        delivered_handles.len(),
    );
    for handle in delivered_handles {
        push_field(&mut handle_digest, "delivered_handle", handle);
    }
    ExploratoryRelease {
        evidence_class: LaneEvidenceClass::ExploratoryFinding,
        evidence_revision_digest: evidence_revision_digest.to_owned(),
        delivered_handle_digest: freeze(&handle_digest),
        delivered_handle_count: delivered_handles.len(),
        state_fence: current_fence.clone(),
    }
}

/// Refuses a release while an unregistered deviation is outstanding on the same
/// evidence revision.
fn verify_registered_deviations(
    deviations: &[DeviationRecord],
    evidence_revision_digest: &str,
    field: &'static str,
) -> Result<(), LaneRegistrationError> {
    for deviation in deviations {
        if deviation.evidence_revision_digest != evidence_revision_digest {
            continue;
        }
        deviation.validate_integrity()?;
        if deviation.disposition.invalidates_confirmation() {
            return Err(LaneRegistrationError::UnregisteredDeviation { field });
        }
    }
    Ok(())
}

/// Release of lane-bound material, typed by whether it is a confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaneReleaseAuthorization {
    /// A committed registration, owner-ordered strictly before every recorded
    /// exposure of the released material.
    Confirmatory(Box<ConfirmatoryExposureAuthorization>),
    /// Exploratory material. Explicitly not a confirmation, and requiring no
    /// registration.
    Exploratory(ExploratoryRelease),
}

impl LaneReleaseAuthorization {
    /// The class of lane result this release produces.
    #[must_use]
    pub fn evidence_class(&self) -> LaneEvidenceClass {
        match self {
            Self::Confirmatory(_) => LaneEvidenceClass::ConfirmatoryClaim,
            Self::Exploratory(_) => LaneEvidenceClass::ExploratoryFinding,
        }
    }
}

/// Release of exploratory material, carrying no confirmation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExploratoryRelease {
    /// The class of lane result this release produces.
    pub evidence_class: LaneEvidenceClass,
    /// Exact evidence revision the release covers.
    pub evidence_revision_digest: String,
    /// Digest over the sorted delivered handles.
    pub delivered_handle_digest: String,
    /// Number of delivered handles.
    pub delivered_handle_count: usize,
    /// State Fence the release was produced under.
    pub state_fence: StateFence,
}
