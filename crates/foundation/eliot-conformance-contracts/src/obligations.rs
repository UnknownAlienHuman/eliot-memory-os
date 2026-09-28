//! I18.49 active conformance obligation compilation (issue #1921).
//!
//! Donor research, historical failures and section-by-section audit issue
//! inventories are cold, non-normative lineage (I18.49, I18.51, I18.52). This
//! module compiles that cold lineage into [`ActiveConformanceObligation`] rows
//! for one exact current product identity. It is owner-neutral and effect-free:
//! every input is an argument, and the module holds no registry, cache,
//! current-state lifecycle, issue-store reader, scraper or network client.
//! Ingesting a live issue tracker is a separate concern and is out of scope.
//!
//! # I18.49 field to type map (frozen)
//!
//! | I18.49 field | Field |
//! |---|---|
//! | `obligation_id_and_source_lineage` | `obligation_id` + `source_lineage` |
//! | `affected_contract_owner_and_property` | `contract_ref` + `owner` + `property` |
//! | `activation_trigger_and_current_support_gap` | `activation_trigger` + `support_gap` |
//! | `exact_old_failure_or_competing_hypothesis` | `old_failure_or_competing_hypothesis` |
//! | `discriminator_or_falsifier` | `discriminator` |
//! | `selected_module_edge_product_or_recovery_profile` | `selected_proof_profile_ref` |
//! | `oracle_and_evidence_lineage` | `oracle` + `evidence_refs` |
//! | `proof_ceiling_and_expected_nonzero_execution` | `proof_ceiling_ref` + `evidence_execution_status` |
//! | `budget_resource_and_expiry` | `budget_ref` + `expires_at_ms` |
//! | `terminal_disposition_and_writeback` | `status` + `writeback_ref` |
//!
//! The exact current product identity is bound by `product_id` and
//! `source_revision` on every row, because cold findings stay non-normative
//! until they are compiled for one exact identity.
//!
//! # Closed disposition vocabulary
//!
//! I18.51 fixes the three ways a lineage entry stops being an executable
//! obligation: an executable discriminator on the exact current identity, an
//! explicit `TARGET` / `NOT_EXECUTED` disposition, or `STALE`. `TARGET`,
//! `NOT_EXECUTED` and `STALE` are therefore not new spellings here: they are
//! the existing I0.5 `ImplementationSupport` and `EvidenceExecutionStatus`
//! values, and `ObligationStatus` names the obligation-level outcome itself.
//!
//! # Cold lineage versus the runtime hotset
//!
//! `ActiveObligationHotsetEntry` is a separate type with no `source_lineage`
//! field, so a module-capsule or product-evaluation-plan consumer of
//! `ActiveObligationHotset` cannot receive source issue IDs or donor handles
//! through it. The separation is structural, not a comment.
//!
//! Nothing here connects obligations to a capsule or plan producer.
//! `ActiveObligationHotset` is the seam those consumers read.
//!
//! # Donor adoption stages (issue #1921 addendum, I17.19)
//!
//! A donor-derived cold source (`donor_ref` present) must name its
//! [`AdoptionStage`]. Stage A is research disposition only and is never an
//! executable obligation. Stage B is gated on the producer-minted Operational
//! Spine Proof 1 (or a current safety blocker), Stage C on the minted
//! component promotion proof plus demonstrated product need, Stage D on minted
//! measured need. The minted gate evidence is a separate compiler input
//! ([`AdoptionGateEvidence`]); a Stage B+ entry is executable only when the
//! evidence it cites matches the minted evidence for its stage. An ungated
//! entry is retained as [`ObligationStatus::InactiveResearchGate`] with its
//! reason, never as `ACTIVE`: ungated Stage B-D entries do not count as
//! planned, and donor research is never auto-promoted into normative
//! contracts.
//!
//! The seven I17.19 stop/narrow conditions are compiler rejection rules: a
//! source that asserts any [`DonorStopCondition`] is refused with a dedicated
//! [`ObligationError`] variant at the compile boundary.
//!
//! # Source test disposition (issue #1921, I18.14 and I19.9)
//!
//! A cold source derived from an existing proof carries the I19.9 five-way
//! classification ([`TestDisposition`]), the source test/inventory identity and
//! the retained rationale and evidence for retirement or narrowing (I18.14).
//! A proof disposed as removed/narrowed or retired compiles to an explicit
//! `RETIRED` disposition carrying that rationale; it never becomes `ACTIVE`
//! product work. This records the disposition only: the compiler deletes no
//! test and starts no test campaign.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    EvidenceExecutionStatus, ImplementationSupport, MAX_SET_ITEMS, MAX_SUPPORT_ROWS, MAX_TEXT_BYTES,
};

/// Current serialized obligation-contract revision.
pub const OBLIGATION_CONTRACT_VERSION: u16 = 2;
/// Stable schema identity for [`ActiveConformanceObligation`].
pub const OBLIGATION_SCHEMA: &str = "eliot.conformance.active-obligation.v2";

/// Closed obligation-level outcome. `TARGET` / `NOT_EXECUTED` / `STALE` are
/// carried by the existing I0.5 support and execution axes on every row; this
/// enum names the obligation outcome itself.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ObligationStatus {
    /// Executable now: the capability is on the current product identity and
    /// the obligation names a nonzero discriminator and a selected proof
    /// profile.
    Active,
    /// The capability is absent from the current product identity. This is I0.5
    /// `TARGET` support with `NOT_EXECUTED` evidence; no executable test
    /// obligation is emitted and the lineage is not silently dropped.
    TargetNotExecuted,
    /// The named capability or its evidence outlived the current identity, so
    /// the row carries `STALE` support.
    Stale,
    /// Terminal disposition. The owner that closes the obligation writes the
    /// terminal `writeback_ref`; this crate never fabricates a retirement, in
    /// the same way it never fabricates a retired `ContractMaturity` row.
    Retired,
    /// INACTIVE Research Gate (I17.19). A staged donor proposal whose stage
    /// gate is not satisfied against the producer-minted gate evidence, or a
    /// Stage A research disposition, retained with its reason. Never
    /// executable, and distinct from terminal `Retired`: the gate may still
    /// open, while a retirement closes the obligation.
    InactiveResearchGate,
}

impl ObligationStatus {
    /// Whether this status emits an executable obligation into a module capsule
    /// or a product evaluation plan. Only `ACTIVE` does.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Active)
    }
}

/// Donor adoption stage (I17.19). Every donor-derived obligation carries one.
/// Audit-only cold sources carry none and follow the pre-existing compilation
/// path unchanged.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AdoptionStage {
    /// Research disposition in the non-normative donor ledger, not contract
    /// proliferation. Never an executable obligation.
    StageA,
    /// After Operational Spine Proof 1, or earlier only for a current safety
    /// blocker.
    StageB,
    /// After component promotion proof plus demonstrated product need.
    StageC,
    /// Only after measured need.
    StageD,
}

/// One I17.19 stop/narrow condition asserted about a donor mechanism. A cold
/// source that asserts any of the seven is refused at the compile boundary
/// with the matching [`ObligationError`] variant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DonorStopCondition {
    /// Creates a second authority, policy or memory owner.
    SecondAuthorityPolicyOrMemoryOwner,
    /// Duplicates watchers or index roots.
    DuplicateWatchersOrIndexRoots,
    /// Has no independent discriminator or reference path.
    NoIndependentDiscriminatorOrReferencePath,
    /// Increases prompt/tool surface without measured reduction elsewhere.
    SurfaceGrowthWithoutMeasuredReduction,
    /// Cannot explain revocation, restore and privacy behavior.
    UnexplainedRevocationRestoreOrPrivacy,
    /// Turns derived navigation into proof.
    NavigationAsProof,
    /// Delays Operational Spine Proof 1 or memory rehabilitation.
    SpineOrMemoryRehabilitationDelay,
}

/// I19.9 five-way classification of an existing proof by current purpose. Only
/// the removed/narrowed and retired classes forbid an executable obligation;
/// the remaining classes ride on the compiled row as recorded disposition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TestDisposition {
    /// Behavior proof: keep or adapt.
    BehaviorProofKeepAdapt,
    /// Implementation lock-in: delete or narrow. Never `ACTIVE` product work.
    ImplementationLockinRemoveNarrow,
    /// Redundant phase certification: retire. Never `ACTIVE` product work.
    RedundantPhaseCertificationRetire,
    /// Critical recovery/security proof: preserve early.
    CriticalRecoverySecurityRetainEarly,
    /// Unknown value: measure runtime and failure history first.
    UnknownValueMeasure,
}

impl TestDisposition {
    /// Whether this disposition forbids an executable obligation. Removed,
    /// narrowed and retired proofs never silently become mandatory product
    /// work; they compile to an explicit `RETIRED` disposition instead.
    #[must_use]
    pub const fn excludes_active(self) -> bool {
        matches!(
            self,
            Self::ImplementationLockinRemoveNarrow | Self::RedundantPhaseCertificationRetire
        )
    }
}

/// Producer-minted stage-gate evidence the compiler evaluates stage gates
/// against. This is a compiler input, not a claim: a Stage B+ entry is
/// executable only when the gate evidence it cites matches a minted reference
/// here for its stage, so a gate cannot be satisfied by re-labelling the cold
/// source. Absent (`None`) minted references keep their gate closed.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptionGateEvidence {
    /// Minted Operational Spine Proof 1 reference, when that proof exists.
    pub operational_spine_proof_1_ref: Option<String>,
    /// Minted current-safety-blocker reference, when one exists.
    pub current_safety_blocker_ref: Option<String>,
    /// Minted component promotion proof reference, when one exists.
    pub component_promotion_proof_ref: Option<String>,
    /// Minted demonstrated-product-need reference, when one exists.
    pub demonstrated_product_need_ref: Option<String>,
    /// Minted measured-need reference, when one exists.
    pub measured_need_ref: Option<String>,
}

/// The exact current product identity the compiler binds against. This is a
/// compiler input, not a product-identity model: it carries only what "the
/// capability exists on the current product identity" needs to answer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProductIdentityCapabilitySet {
    /// Product/source identity.
    pub product_id: String,
    /// Exact source or artifact revision of that product.
    pub source_revision: String,
    /// Capabilities present on that exact identity, in canonical order.
    pub capability_refs: Vec<String>,
}

impl ProductIdentityCapabilitySet {
    /// Whether one exact capability exists on this product identity.
    #[must_use]
    pub fn has_capability(&self, capability_ref: &str) -> bool {
        self.capability_refs
            .iter()
            .any(|present| present == capability_ref)
    }

    /// Validates the identity handle, the revision, and the canonical
    /// duplicate-free capability set.
    pub fn validate(&self) -> Result<(), ObligationError> {
        validate_text("product_identity.product_id", &self.product_id)?;
        validate_text("product_identity.source_revision", &self.source_revision)?;
        validate_text_set("product_identity.capability_refs", &self.capability_refs)
    }
}

/// One cold source: an audit issue and/or a donor reference. It is lineage
/// only, and becomes executable solely through compilation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ColdSourceClaim {
    /// Audit issue identity, when this cold source is an audit issue.
    pub source_issue_id: Option<String>,
    /// Donor-project reference, when this cold source is donor research.
    pub donor_ref: Option<String>,
    /// Compiled obligation identity this source claims.
    pub obligation_id: String,
    /// Affected contract reference.
    pub contract_ref: String,
    /// Current causal-property owner.
    pub owner: String,
    /// Current causal property this obligation is about.
    pub property: String,
    /// Capability whose presence on the current product identity decides
    /// whether the obligation can be executable at all.
    pub capability_ref: String,
    /// Activation trigger for the obligation.
    pub activation_trigger: String,
    /// Current support gap that makes the obligation due.
    pub support_gap: String,
    /// The exact old failure or competing hypothesis.
    pub old_failure_or_competing_hypothesis: String,
    /// Nonzero discriminator or falsifier. A source that names none cannot
    /// explain an additional failure class and is omitted (I18.49).
    pub discriminator: Option<String>,
    /// Selected module-edge, product or recovery proof profile.
    pub selected_proof_profile_ref: Option<String>,
    /// Oracle the discriminator is judged against.
    pub oracle: Option<String>,
    /// Evidence lineage, in canonical order.
    pub evidence_refs: Vec<String>,
    /// Proof ceiling the obligation may claim.
    pub proof_ceiling_ref: Option<String>,
    /// Budget resource for the obligation.
    pub budget_ref: String,
    /// Expiry of the obligation, in epoch milliseconds.
    pub expires_at_ms: u64,
    /// Exact I0.5 implementation support this source claims.
    pub implementation_support: ImplementationSupport,
    /// Exact I0.5 evidence execution status this source claims.
    pub evidence_execution_status: EvidenceExecutionStatus,
    /// Owner writeback target for the terminal disposition.
    pub writeback_ref: String,
    /// Donor adoption stage. Required when `donor_ref` is present; every
    /// donor-derived obligation carries its stage (I17.19).
    pub adoption_stage: Option<AdoptionStage>,
    /// Gate evidence this source cites for its stage. A Stage B+ entry is
    /// executable only when this matches the producer-minted gate evidence
    /// for its stage.
    pub stage_gate_evidence_ref: Option<String>,
    /// Retained reason for staying an INACTIVE Research Gate. Required when
    /// the compiled row lands inactive-gated.
    pub inactive_gate_reason: Option<String>,
    /// I17.19 stop/narrow conditions this source asserts about the donor
    /// mechanism, in canonical order. Any asserted condition refuses the
    /// whole compilation at the compile boundary.
    pub stop_conditions: Vec<DonorStopCondition>,
    /// Source test or inventory identity this claim derives from, when it
    /// derives from an existing proof (for example a #905 inventory entry).
    pub source_test_ref: Option<String>,
    /// I19.9 five-way classification of that source proof by current purpose.
    pub test_disposition: Option<TestDisposition>,
    /// Retained rationale for a retirement or narrowing (I18.14 vocabulary).
    /// Required when `test_disposition` removes, narrows or retires.
    pub test_disposition_reason: Option<String>,
    /// Retained evidence for a retirement or narrowing.
    /// Required when `test_disposition` removes, narrows or retires.
    pub test_disposition_evidence_ref: Option<String>,
}

/// External lineage of one compiled obligation. It is traceability metadata and
/// is deliberately absent from the runtime hotset projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ColdSourceLineage {
    /// Audit issue identity, when present.
    pub source_issue_id: Option<String>,
    /// Donor-project reference, when present.
    pub donor_ref: Option<String>,
    /// Source test or inventory identity this lineage entry derives from,
    /// when it derives from an existing proof.
    pub source_test_ref: Option<String>,
    /// I19.9 classification of that source proof, when classified.
    pub test_disposition: Option<TestDisposition>,
}

/// One obligation compiled for the exact current product identity, either
/// executable or explicitly dispositioned.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveConformanceObligation {
    /// Current serialized contract revision.
    pub contract_version: u16,
    /// Compiled obligation identity.
    pub obligation_id: String,
    /// Exact product identity this row was compiled for.
    pub product_id: String,
    /// Exact source or artifact revision this row was compiled for.
    pub source_revision: String,
    /// Affected contract reference.
    pub contract_ref: String,
    /// Current causal-property owner.
    pub owner: String,
    /// Current causal property.
    pub property: String,
    /// Capability whose presence on the current identity gated this row.
    pub capability_ref: String,
    /// Activation trigger.
    pub activation_trigger: String,
    /// Current support gap.
    pub support_gap: String,
    /// The exact old failure or competing hypothesis.
    pub old_failure_or_competing_hypothesis: String,
    /// Exact nonzero discriminator. `None` only for a non-active disposition.
    pub discriminator: Option<String>,
    /// Exact selected owner proof profile. `None` only for a non-active
    /// disposition that selected no profile.
    pub selected_proof_profile_ref: Option<String>,
    /// Oracle the discriminator is judged against.
    pub oracle: Option<String>,
    /// Evidence lineage, in canonical order.
    pub evidence_refs: Vec<String>,
    /// Proof ceiling the obligation may claim.
    pub proof_ceiling_ref: Option<String>,
    /// Budget resource.
    pub budget_ref: String,
    /// Expiry in epoch milliseconds.
    pub expires_at_ms: u64,
    /// Exact I0.5 implementation support for this row.
    pub implementation_support: ImplementationSupport,
    /// Exact I0.5 evidence execution status for this row.
    pub evidence_execution_status: EvidenceExecutionStatus,
    /// Closed obligation-level outcome.
    pub status: ObligationStatus,
    /// Owner writeback target for the terminal disposition.
    pub writeback_ref: String,
    /// Donor adoption stage. Present on every donor-derived row.
    pub adoption_stage: Option<AdoptionStage>,
    /// Gate evidence this row cites for its stage. Present on every Stage B+
    /// row whose gate is satisfied; retained as cited otherwise.
    pub stage_gate_evidence_ref: Option<String>,
    /// Retained reason for an INACTIVE Research Gate. Present exactly when
    /// `status` is `INACTIVE_RESEARCH_GATE`.
    pub inactive_gate_reason: Option<String>,
    /// Agreed I19.9 disposition of the source proofs that collapsed into this
    /// row, when classified.
    pub test_disposition: Option<TestDisposition>,
    /// Retained rationale for a retirement or narrowing (I18.14).
    pub test_disposition_reason: Option<String>,
    /// Retained evidence for a retirement or narrowing.
    pub test_disposition_evidence_ref: Option<String>,
    /// Every cold source that collapsed into this row, in canonical order.
    pub source_lineage: Vec<ColdSourceLineage>,
}

/// One compiled obligation set bound to one exact current product identity.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveConformanceObligationSet {
    /// Current serialized contract revision.
    pub contract_version: u16,
    /// Exact product identity every row was compiled for.
    pub product_id: String,
    /// Exact source or artifact revision every row was compiled for.
    pub source_revision: String,
    /// Compilation boundary in epoch milliseconds.
    pub compiled_at_ms: u64,
    /// Compiled obligations in canonical owner/property order.
    pub obligations: Vec<ActiveConformanceObligation>,
}

impl ActiveConformanceObligationSet {
    /// The `ACTIVE` rows only, in canonical order. This is the set a module
    /// capsule or a product evaluation plan may consume.
    #[must_use]
    pub fn active_obligations(&self) -> Vec<&ActiveConformanceObligation> {
        self.obligations
            .iter()
            .filter(|obligation| obligation.status.is_executable())
            .collect()
    }

    /// Projects the `ACTIVE` rows into the runtime hotset. The projection
    /// carries no source issue ID and no donor handle, so historical names never
    /// reach the agent hotset through it. A row that is not `ACTIVE`, or that
    /// lacks the exact discriminator or selected proof profile an `ACTIVE` row
    /// must carry, is refused rather than projected with invented content. A
    /// donor-derived row without a gated stage is likewise refused: ungated
    /// Stage B-D entries do not count as planned.
    #[must_use]
    pub fn hotset(&self) -> ActiveObligationHotset {
        ActiveObligationHotset {
            entries: self
                .active_obligations()
                .into_iter()
                .filter_map(ActiveObligationHotsetEntry::from_obligation)
                .collect(),
        }
    }
}

/// The runtime hotset a module capsule or product evaluation plan consumes. It
/// has no lineage field.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveObligationHotset {
    /// One entry per `ACTIVE` obligation, in canonical order.
    pub entries: Vec<ActiveObligationHotsetEntry>,
}

/// One `ACTIVE` obligation reduced to runtime-hotset content: exact owner and
/// property, exact discriminator, exact selected proof profile, and the
/// remaining execution identity. Cold lineage is intentionally not projected.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveObligationHotsetEntry {
    /// Compiled obligation identity.
    pub obligation_id: String,
    /// Exact current owner.
    pub owner: String,
    /// Exact current causal property.
    pub property: String,
    /// Capability whose presence gated activation.
    pub capability_ref: String,
    /// Exact nonzero discriminator.
    pub discriminator: String,
    /// Exact selected owner proof profile.
    pub selected_proof_profile_ref: String,
    /// Proof ceiling the entry may claim.
    pub proof_ceiling_ref: Option<String>,
    /// Expiry in epoch milliseconds.
    pub expires_at_ms: u64,
    /// Donor adoption stage this entry was gated under, when staged. Carried
    /// so a capsule or plan consumer can see that a donor-derived entry
    /// passed its stage gate instead of being auto-promoted.
    pub adoption_stage: Option<AdoptionStage>,
    /// Gate evidence this entry cited for its stage, when staged.
    pub stage_gate_evidence_ref: Option<String>,
}

impl ActiveObligationHotsetEntry {
    /// Reduces one `ACTIVE` obligation to its runtime-hotset content. Returns
    /// `None` for a row whose actual status is not executable, or whose exact
    /// discriminator or selected proof profile is missing, so only exact
    /// `ACTIVE` content reaches a module capsule or product evaluation plan.
    /// Donor-derived rows are additionally refused unless they carry a stage
    /// past Stage A and cite gate evidence: no auto-promotion of donor
    /// research, and ungated Stage B-D entries do not count as planned.
    fn from_obligation(obligation: &ActiveConformanceObligation) -> Option<Self> {
        if !obligation.status.is_executable() {
            return None;
        }
        let (Some(discriminator), Some(selected_proof_profile_ref)) = (
            obligation.discriminator.clone(),
            obligation.selected_proof_profile_ref.clone(),
        ) else {
            return None;
        };
        if obligation
            .source_lineage
            .iter()
            .any(|lineage| lineage.donor_ref.is_some())
        {
            let stage = obligation.adoption_stage?;
            if stage == AdoptionStage::StageA || obligation.stage_gate_evidence_ref.is_none() {
                return None;
            }
        }
        Some(Self {
            obligation_id: obligation.obligation_id.clone(),
            owner: obligation.owner.clone(),
            property: obligation.property.clone(),
            capability_ref: obligation.capability_ref.clone(),
            discriminator,
            selected_proof_profile_ref,
            proof_ceiling_ref: obligation.proof_ceiling_ref.clone(),
            expires_at_ms: obligation.expires_at_ms,
            adoption_stage: obligation.adoption_stage,
            stage_gate_evidence_ref: obligation.stage_gate_evidence_ref.clone(),
        })
    }
}

/// Closed structural and semantic failures returned by the obligation compiler
/// and validators. Distinct failures stay distinct variants.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ObligationError {
    #[error("unsupported contract version {actual}; expected {expected}")]
    UnsupportedContractVersion { expected: u16, actual: u16 },
    #[error("invalid {field}: {reason}")]
    InvalidText {
        field: &'static str,
        reason: &'static str,
    },
    #[error("{field} contains {actual} entries; maximum is {maximum}")]
    CollectionTooLarge {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    #[error("duplicate value in {field}: {value}")]
    DuplicateValue { field: &'static str, value: String },
    #[error("{field} is not in canonical order")]
    NonCanonicalCollection { field: &'static str },
    #[error("invalid time field {field}")]
    InvalidTime { field: &'static str },
    #[error("cold source names neither an audit issue nor a donor reference")]
    MissingSourceLineage,
    #[error("required evidence is missing: {field}")]
    MissingEvidence { field: &'static str },
    #[error("cold source {source_ref} names no nonzero discriminator for {owner}/{property}")]
    MissingDiscriminator {
        source_ref: String,
        owner: String,
        property: String,
    },
    #[error("{owner}/{property} has conflicting cold-source {field} across its lineages")]
    ConflictingColdSource {
        owner: String,
        property: String,
        field: &'static str,
    },
    #[error("invalid obligation disposition: {reason}")]
    InvalidDisposition { reason: &'static str },
    #[error("duplicate compiled obligation for {owner}/{property}")]
    DuplicateObligation { owner: String, property: String },
    #[error(
        "obligation {obligation_id} expired at {expires_at_ms} at compilation boundary {compiled_at_ms}"
    )]
    ObligationExpired {
        obligation_id: String,
        expires_at_ms: u64,
        compiled_at_ms: u64,
    },
    #[error("{owner}/{property} would create a second authority, policy or memory owner")]
    DonorSecondOwner { owner: String, property: String },
    #[error("{owner}/{property} duplicates watchers or index roots")]
    DonorDuplicateWatchersOrRoots { owner: String, property: String },
    #[error("{owner}/{property} has no independent discriminator or reference path")]
    DonorNoIndependentDiscriminator { owner: String, property: String },
    #[error("{owner}/{property} grows prompt/tool surface without measured reduction")]
    DonorSurfaceGrowthWithoutReduction { owner: String, property: String },
    #[error("{owner}/{property} cannot explain revocation, restore and privacy behavior")]
    DonorUnexplainedRevocationRestoreOrPrivacy { owner: String, property: String },
    #[error("{owner}/{property} turns derived navigation into proof")]
    DonorNavigationAsProof { owner: String, property: String },
    #[error("{owner}/{property} delays Operational Spine Proof 1 or memory rehabilitation")]
    DonorSpineOrRehabilitationDelay { owner: String, property: String },
    #[error("donor-derived cold source for {owner}/{property} names no adoption stage")]
    MissingAdoptionStage { owner: String, property: String },
}

/// Compiles cold audit/donor lineage into obligations for one exact current
/// product identity.
///
/// Claims are deduplicated by current causal property and owner: every claim in
/// a group that agrees on the whole obligation body collapses into one row that
/// retains all of their lineages. A row is `ACTIVE` only when the capability
/// exists on `product_identity` and the claim names a nonzero discriminator and
/// a selected proof profile. A capability absent from the product identity
/// yields a `TARGET_NOT_EXECUTED` row with no executable test obligation.
///
/// `stage_gates` is the producer-minted gate evidence stage gates are
/// evaluated against. A donor-derived claim must name its adoption stage, and
/// a Stage B+ entry reaches `ACTIVE` only when its cited gate evidence matches
/// the minted evidence for its stage; otherwise the row is retained as an
/// `INACTIVE_RESEARCH_GATE` with its reason. A claim that asserts any I17.19
/// stop/narrow condition refuses the whole compilation.
pub fn compile_active_conformance_obligations(
    sources: Vec<ColdSourceClaim>,
    product_identity: &ProductIdentityCapabilitySet,
    stage_gates: &AdoptionGateEvidence,
    compiled_at_ms: u64,
) -> Result<ActiveConformanceObligationSet, ObligationError> {
    product_identity.validate()?;
    validate_gate_evidence(stage_gates)?;
    validate_collection_bound("cold_sources", sources.len(), MAX_SUPPORT_ROWS)?;
    if compiled_at_ms == 0 {
        return Err(ObligationError::InvalidTime {
            field: "compiled_at_ms",
        });
    }

    let mut sources = sources;
    for source in &mut sources {
        canonicalize_text_set("cold_source.evidence_refs", &mut source.evidence_refs)?;
        canonicalize_stop_conditions(&mut source.stop_conditions)?;
        validate_cold_source_claim(source)?;
    }
    sources.sort_by_key(|source| (source.owner.clone(), source.property.clone()));

    let mut obligations: Vec<ActiveConformanceObligation> = Vec::new();
    for source in sources {
        merge_cold_source(&mut obligations, source, product_identity, stage_gates)?;
    }
    obligations.sort_by(|left, right| obligation_key(left).cmp(&obligation_key(right)));

    let obligation_set = ActiveConformanceObligationSet {
        contract_version: OBLIGATION_CONTRACT_VERSION,
        product_id: product_identity.product_id.clone(),
        source_revision: product_identity.source_revision.clone(),
        compiled_at_ms,
        obligations,
    };
    validate_obligation_set(&obligation_set)?;
    Ok(obligation_set)
}

/// Validates the intrinsic shape of one cold source claim.
pub fn validate_cold_source_claim(claim: &ColdSourceClaim) -> Result<(), ObligationError> {
    validate_optional_text(
        "cold_source.source_issue_id",
        claim.source_issue_id.as_deref(),
    )?;
    validate_optional_text("cold_source.donor_ref", claim.donor_ref.as_deref())?;
    if claim.source_issue_id.is_none() && claim.donor_ref.is_none() {
        return Err(ObligationError::MissingSourceLineage);
    }
    validate_text("cold_source.obligation_id", &claim.obligation_id)?;
    validate_text("cold_source.contract_ref", &claim.contract_ref)?;
    validate_text("cold_source.owner", &claim.owner)?;
    validate_text("cold_source.property", &claim.property)?;
    validate_text("cold_source.capability_ref", &claim.capability_ref)?;
    validate_text("cold_source.activation_trigger", &claim.activation_trigger)?;
    validate_text("cold_source.support_gap", &claim.support_gap)?;
    validate_text(
        "cold_source.old_failure_or_competing_hypothesis",
        &claim.old_failure_or_competing_hypothesis,
    )?;
    validate_optional_text("cold_source.discriminator", claim.discriminator.as_deref())?;
    validate_optional_text(
        "cold_source.selected_proof_profile_ref",
        claim.selected_proof_profile_ref.as_deref(),
    )?;
    validate_optional_text("cold_source.oracle", claim.oracle.as_deref())?;
    validate_optional_text(
        "cold_source.proof_ceiling_ref",
        claim.proof_ceiling_ref.as_deref(),
    )?;
    validate_text_set("cold_source.evidence_refs", &claim.evidence_refs)?;
    validate_text("cold_source.budget_ref", &claim.budget_ref)?;
    validate_text("cold_source.writeback_ref", &claim.writeback_ref)?;
    validate_optional_text(
        "cold_source.stage_gate_evidence_ref",
        claim.stage_gate_evidence_ref.as_deref(),
    )?;
    validate_optional_text(
        "cold_source.inactive_gate_reason",
        claim.inactive_gate_reason.as_deref(),
    )?;
    validate_optional_text(
        "cold_source.source_test_ref",
        claim.source_test_ref.as_deref(),
    )?;
    validate_optional_text(
        "cold_source.test_disposition_reason",
        claim.test_disposition_reason.as_deref(),
    )?;
    validate_optional_text(
        "cold_source.test_disposition_evidence_ref",
        claim.test_disposition_evidence_ref.as_deref(),
    )?;
    validate_stop_conditions(&claim.stop_conditions)?;
    if claim.expires_at_ms == 0 {
        return Err(ObligationError::InvalidTime {
            field: "cold_source.expires_at_ms",
        });
    }
    Ok(())
}

/// Validates one compiled obligation, including its disposition against the
/// exact product identity and compilation boundary it was compiled for.
pub fn validate_active_conformance_obligation(
    obligation: &ActiveConformanceObligation,
) -> Result<(), ObligationError> {
    validate_contract_version(obligation.contract_version)?;
    validate_text("obligation.obligation_id", &obligation.obligation_id)?;
    validate_text("obligation.product_id", &obligation.product_id)?;
    validate_text("obligation.source_revision", &obligation.source_revision)?;
    validate_text("obligation.contract_ref", &obligation.contract_ref)?;
    validate_text("obligation.owner", &obligation.owner)?;
    validate_text("obligation.property", &obligation.property)?;
    validate_text("obligation.capability_ref", &obligation.capability_ref)?;
    validate_text(
        "obligation.activation_trigger",
        &obligation.activation_trigger,
    )?;
    validate_text("obligation.support_gap", &obligation.support_gap)?;
    validate_text(
        "obligation.old_failure_or_competing_hypothesis",
        &obligation.old_failure_or_competing_hypothesis,
    )?;
    validate_optional_text(
        "obligation.discriminator",
        obligation.discriminator.as_deref(),
    )?;
    validate_optional_text(
        "obligation.selected_proof_profile_ref",
        obligation.selected_proof_profile_ref.as_deref(),
    )?;
    validate_optional_text("obligation.oracle", obligation.oracle.as_deref())?;
    validate_optional_text(
        "obligation.proof_ceiling_ref",
        obligation.proof_ceiling_ref.as_deref(),
    )?;
    validate_text_set("obligation.evidence_refs", &obligation.evidence_refs)?;
    validate_text("obligation.budget_ref", &obligation.budget_ref)?;
    validate_text("obligation.writeback_ref", &obligation.writeback_ref)?;
    validate_optional_text(
        "obligation.stage_gate_evidence_ref",
        obligation.stage_gate_evidence_ref.as_deref(),
    )?;
    validate_optional_text(
        "obligation.inactive_gate_reason",
        obligation.inactive_gate_reason.as_deref(),
    )?;
    validate_optional_text(
        "obligation.test_disposition_reason",
        obligation.test_disposition_reason.as_deref(),
    )?;
    validate_optional_text(
        "obligation.test_disposition_evidence_ref",
        obligation.test_disposition_evidence_ref.as_deref(),
    )?;
    validate_lineage("obligation.source_lineage", &obligation.source_lineage)?;
    if obligation.expires_at_ms == 0 {
        return Err(ObligationError::InvalidTime {
            field: "obligation.expires_at_ms",
        });
    }
    validate_obligation_disposition(obligation)
}

/// Validates an already canonical compiled obligation set: one product identity
/// and one compilation boundary for every row, unique owner/property identity,
/// and canonical order.
pub fn validate_obligation_set(
    obligation_set: &ActiveConformanceObligationSet,
) -> Result<(), ObligationError> {
    validate_contract_version(obligation_set.contract_version)?;
    validate_text("obligation_set.product_id", &obligation_set.product_id)?;
    validate_text(
        "obligation_set.source_revision",
        &obligation_set.source_revision,
    )?;
    if obligation_set.compiled_at_ms == 0 {
        return Err(ObligationError::InvalidTime {
            field: "obligation_set.compiled_at_ms",
        });
    }
    validate_collection_bound(
        "obligation_set.obligations",
        obligation_set.obligations.len(),
        MAX_SUPPORT_ROWS,
    )?;

    let mut seen = BTreeSet::new();
    for obligation in &obligation_set.obligations {
        validate_active_conformance_obligation(obligation)?;
        if obligation.product_id != obligation_set.product_id
            || obligation.source_revision != obligation_set.source_revision
        {
            return Err(ObligationError::InvalidDisposition {
                reason: "every obligation must be compiled for the set's exact product identity",
            });
        }
        if obligation.status.is_executable()
            && obligation.expires_at_ms <= obligation_set.compiled_at_ms
        {
            return Err(ObligationError::ObligationExpired {
                obligation_id: obligation.obligation_id.clone(),
                expires_at_ms: obligation.expires_at_ms,
                compiled_at_ms: obligation_set.compiled_at_ms,
            });
        }
        if !seen.insert(obligation_key(obligation)) {
            return Err(ObligationError::DuplicateObligation {
                owner: obligation.owner.clone(),
                property: obligation.property.clone(),
            });
        }
    }

    for pair in obligation_set.obligations.windows(2) {
        if obligation_key(&pair[0]) >= obligation_key(&pair[1]) {
            return Err(ObligationError::NonCanonicalCollection {
                field: "obligation_set.obligations",
            });
        }
    }
    Ok(())
}

/// Merges one cold source into the compiled set, deduplicating by current
/// causal property and owner while retaining every source lineage. A source
/// that asserts an I17.19 stop/narrow condition refuses the whole compilation
/// before any merge, on either the new-row or the existing-row path.
fn merge_cold_source(
    obligations: &mut Vec<ActiveConformanceObligation>,
    source: ColdSourceClaim,
    product_identity: &ProductIdentityCapabilitySet,
    stage_gates: &AdoptionGateEvidence,
) -> Result<(), ObligationError> {
    if let Some(condition) = source.stop_conditions.first() {
        return Err(stop_condition_error(
            *condition,
            source.owner,
            source.property,
        ));
    }
    let existing = obligations.iter_mut().find(|obligation| {
        obligation.owner == source.owner && obligation.property == source.property
    });
    let Some(obligation) = existing else {
        let compiled = compile_obligation(&source, product_identity, stage_gates)?;
        return push_obligation(obligations, compiled);
    };

    if let Some(field) = conflicting_field(obligation, &source, product_identity) {
        return Err(ObligationError::ConflictingColdSource {
            owner: source.owner,
            property: source.property,
            field,
        });
    }
    let lineage = ColdSourceLineage {
        source_issue_id: source.source_issue_id.clone(),
        donor_ref: source.donor_ref.clone(),
        source_test_ref: source.source_test_ref.clone(),
        test_disposition: source.test_disposition,
    };
    if obligation
        .source_lineage
        .iter()
        .any(|existing| lineage_key(existing) == lineage_key(&lineage))
    {
        return Err(ObligationError::DuplicateValue {
            field: "obligation.source_lineage",
            value: source_label(&lineage),
        });
    }
    obligation.source_lineage.push(lineage);
    obligation
        .source_lineage
        .sort_by(|left, right| lineage_key(left).cmp(&lineage_key(right)));

    // I18.49 keeps the oracle/evidence lineage of every source that collapsed
    // into the row, so distinct evidence refs merge instead of conflicting.
    for evidence_ref in source.evidence_refs {
        if !obligation.evidence_refs.contains(&evidence_ref) {
            obligation.evidence_refs.push(evidence_ref);
        }
    }
    canonicalize_text_set("obligation.evidence_refs", &mut obligation.evidence_refs)
}

/// Compiles the first cold source of a group into its obligation row. A claim
/// that names no nonzero discriminator on a present capability is rejected
/// rather than dispositioned: it explains no additional failure class, and this
/// crate never fabricates a disposition its sources do not justify.
///
/// A donor-derived claim without an adoption stage is rejected: every
/// donor-derived obligation carries its stage. Disposition precedence on a
/// present, non-stale capability is then test disposition (a removed, narrowed
/// or retired proof compiles to an explicit `RETIRED` disposition carrying its
/// retained rationale, never to `ACTIVE`), then the stage gate (an ungated
/// Stage B-D entry or any Stage A research disposition is retained as an
/// `INACTIVE_RESEARCH_GATE` with its reason, never auto-promoted), then
/// `ACTIVE`.
fn compile_obligation(
    source: &ColdSourceClaim,
    product_identity: &ProductIdentityCapabilitySet,
    stage_gates: &AdoptionGateEvidence,
) -> Result<ActiveConformanceObligation, ObligationError> {
    if source.donor_ref.is_some() && source.adoption_stage.is_none() {
        return Err(ObligationError::MissingAdoptionStage {
            owner: source.owner.clone(),
            property: source.property.clone(),
        });
    }
    let capability_present = product_identity.has_capability(&source.capability_ref);
    let executable_support = if source.implementation_support == ImplementationSupport::Stale {
        Some(ObligationStatus::Stale)
    } else {
        None
    };
    let status = if !capability_present {
        ObligationStatus::TargetNotExecuted
    } else if source.discriminator.is_none() {
        return Err(ObligationError::MissingDiscriminator {
            source_ref: source_label(&ColdSourceLineage {
                source_issue_id: source.source_issue_id.clone(),
                donor_ref: source.donor_ref.clone(),
                source_test_ref: source.source_test_ref.clone(),
                test_disposition: source.test_disposition,
            }),
            owner: source.owner.clone(),
            property: source.property.clone(),
        });
    } else if source
        .test_disposition
        .is_some_and(TestDisposition::excludes_active)
    {
        if source.test_disposition_reason.is_none() {
            return Err(ObligationError::MissingEvidence {
                field: "cold_source.test_disposition_reason",
            });
        }
        if source.test_disposition_evidence_ref.is_none() {
            return Err(ObligationError::MissingEvidence {
                field: "cold_source.test_disposition_evidence_ref",
            });
        }
        ObligationStatus::Retired
    } else if source.adoption_stage.is_some_and(|stage| {
        !stage_gate_permits_active(
            stage,
            source.stage_gate_evidence_ref.as_deref(),
            stage_gates,
        )
    }) {
        if source.inactive_gate_reason.is_none() {
            return Err(ObligationError::MissingEvidence {
                field: "cold_source.inactive_gate_reason",
            });
        }
        ObligationStatus::InactiveResearchGate
    } else {
        executable_support.unwrap_or(ObligationStatus::Active)
    };

    let (implementation_support, evidence_execution_status) =
        obligation_axes(source, product_identity, status);
    let obligation = ActiveConformanceObligation {
        contract_version: OBLIGATION_CONTRACT_VERSION,
        obligation_id: source.obligation_id.clone(),
        product_id: product_identity.product_id.clone(),
        source_revision: product_identity.source_revision.clone(),
        contract_ref: source.contract_ref.clone(),
        owner: source.owner.clone(),
        property: source.property.clone(),
        capability_ref: source.capability_ref.clone(),
        activation_trigger: source.activation_trigger.clone(),
        support_gap: source.support_gap.clone(),
        old_failure_or_competing_hypothesis: source.old_failure_or_competing_hypothesis.clone(),
        discriminator: source.discriminator.clone(),
        selected_proof_profile_ref: source.selected_proof_profile_ref.clone(),
        oracle: source.oracle.clone(),
        evidence_refs: source.evidence_refs.clone(),
        proof_ceiling_ref: source.proof_ceiling_ref.clone(),
        budget_ref: source.budget_ref.clone(),
        expires_at_ms: source.expires_at_ms,
        implementation_support,
        evidence_execution_status,
        status,
        writeback_ref: source.writeback_ref.clone(),
        adoption_stage: source.adoption_stage,
        stage_gate_evidence_ref: source.stage_gate_evidence_ref.clone(),
        inactive_gate_reason: source.inactive_gate_reason.clone(),
        test_disposition: source.test_disposition,
        test_disposition_reason: source.test_disposition_reason.clone(),
        test_disposition_evidence_ref: source.test_disposition_evidence_ref.clone(),
        source_lineage: vec![ColdSourceLineage {
            source_issue_id: source.source_issue_id.clone(),
            donor_ref: source.donor_ref.clone(),
            source_test_ref: source.source_test_ref.clone(),
            test_disposition: source.test_disposition,
        }],
    };
    validate_obligation_disposition(&obligation)?;
    Ok(obligation)
}

/// Appends one newly compiled obligation to the set under construction.
fn push_obligation(
    obligations: &mut Vec<ActiveConformanceObligation>,
    obligation: ActiveConformanceObligation,
) -> Result<(), ObligationError> {
    if obligations.len() >= MAX_SUPPORT_ROWS {
        return Err(ObligationError::CollectionTooLarge {
            field: "obligation_set.obligations",
            maximum: MAX_SUPPORT_ROWS,
            actual: obligations.len() + 1,
        });
    }
    obligations.push(obligation);
    Ok(())
}

/// The exact I0.5 support and execution axes a compiled row carries. A
/// capability absent from the current product identity is always I0.5 `TARGET`
/// support with `NOT_EXECUTED` evidence, and a `STALE` row always carries
/// `STALE` support.
fn obligation_axes(
    source: &ColdSourceClaim,
    product_identity: &ProductIdentityCapabilitySet,
    status: ObligationStatus,
) -> (ImplementationSupport, EvidenceExecutionStatus) {
    if !product_identity.has_capability(&source.capability_ref) {
        return (
            ImplementationSupport::Target,
            EvidenceExecutionStatus::NotExecuted,
        );
    }
    let support = if status == ObligationStatus::Stale {
        ImplementationSupport::Stale
    } else {
        source.implementation_support
    };
    (support, source.evidence_execution_status)
}

/// Whether a staged entry may reach `ACTIVE`: the cited gate evidence must
/// match the producer-minted evidence for its stage. Stage A never permits
/// `ACTIVE`: it is research disposition, not a normative contract. Stage B
/// matches the minted Operational Spine Proof 1 or the minted current safety
/// blocker. Stage C matches the minted component promotion proof or the
/// minted demonstrated product need, and both must exist. Stage D matches the
/// minted measured need. The comparison is against evidence the producer
/// minted, so citing an unminted handle keeps the gate closed.
fn stage_gate_permits_active(
    stage: AdoptionStage,
    cited: Option<&str>,
    gates: &AdoptionGateEvidence,
) -> bool {
    let Some(cited) = cited else {
        return false;
    };
    match stage {
        AdoptionStage::StageA => false,
        AdoptionStage::StageB => {
            gates.operational_spine_proof_1_ref.as_deref() == Some(cited)
                || gates.current_safety_blocker_ref.as_deref() == Some(cited)
        }
        AdoptionStage::StageC => {
            gates.component_promotion_proof_ref.is_some()
                && gates.demonstrated_product_need_ref.is_some()
                && (gates.component_promotion_proof_ref.as_deref() == Some(cited)
                    || gates.demonstrated_product_need_ref.as_deref() == Some(cited))
        }
        AdoptionStage::StageD => gates.measured_need_ref.as_deref() == Some(cited),
    }
}

/// Maps one asserted I17.19 stop/narrow condition to its compiler rejection.
fn stop_condition_error(
    condition: DonorStopCondition,
    owner: String,
    property: String,
) -> ObligationError {
    match condition {
        DonorStopCondition::SecondAuthorityPolicyOrMemoryOwner => {
            ObligationError::DonorSecondOwner { owner, property }
        }
        DonorStopCondition::DuplicateWatchersOrIndexRoots => {
            ObligationError::DonorDuplicateWatchersOrRoots { owner, property }
        }
        DonorStopCondition::NoIndependentDiscriminatorOrReferencePath => {
            ObligationError::DonorNoIndependentDiscriminator { owner, property }
        }
        DonorStopCondition::SurfaceGrowthWithoutMeasuredReduction => {
            ObligationError::DonorSurfaceGrowthWithoutReduction { owner, property }
        }
        DonorStopCondition::UnexplainedRevocationRestoreOrPrivacy => {
            ObligationError::DonorUnexplainedRevocationRestoreOrPrivacy { owner, property }
        }
        DonorStopCondition::NavigationAsProof => {
            ObligationError::DonorNavigationAsProof { owner, property }
        }
        DonorStopCondition::SpineOrMemoryRehabilitationDelay => {
            ObligationError::DonorSpineOrRehabilitationDelay { owner, property }
        }
    }
}

/// Validates the producer-minted gate evidence handles.
fn validate_gate_evidence(gates: &AdoptionGateEvidence) -> Result<(), ObligationError> {
    validate_optional_text(
        "stage_gates.operational_spine_proof_1_ref",
        gates.operational_spine_proof_1_ref.as_deref(),
    )?;
    validate_optional_text(
        "stage_gates.current_safety_blocker_ref",
        gates.current_safety_blocker_ref.as_deref(),
    )?;
    validate_optional_text(
        "stage_gates.component_promotion_proof_ref",
        gates.component_promotion_proof_ref.as_deref(),
    )?;
    validate_optional_text(
        "stage_gates.demonstrated_product_need_ref",
        gates.demonstrated_product_need_ref.as_deref(),
    )?;
    validate_optional_text(
        "stage_gates.measured_need_ref",
        gates.measured_need_ref.as_deref(),
    )
}

/// Sorts asserted stop/narrow conditions into canonical order and rejects
/// duplicates, like any other set-like compiler input.
fn canonicalize_stop_conditions(
    conditions: &mut [DonorStopCondition],
) -> Result<(), ObligationError> {
    validate_collection_bound(
        "cold_source.stop_conditions",
        conditions.len(),
        MAX_SET_ITEMS,
    )?;
    conditions.sort();
    if let Some([duplicate, _]) = conditions.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(ObligationError::DuplicateValue {
            field: "cold_source.stop_conditions",
            value: format!("{duplicate:?}"),
        });
    }
    Ok(())
}

/// Validates already-canonical asserted stop/narrow conditions.
fn validate_stop_conditions(conditions: &[DonorStopCondition]) -> Result<(), ObligationError> {
    validate_collection_bound(
        "cold_source.stop_conditions",
        conditions.len(),
        MAX_SET_ITEMS,
    )?;
    for pair in conditions.windows(2) {
        if pair[0] == pair[1] {
            return Err(ObligationError::DuplicateValue {
                field: "cold_source.stop_conditions",
                value: format!("{:?}", pair[0]),
            });
        }
        if pair[0] > pair[1] {
            return Err(ObligationError::NonCanonicalCollection {
                field: "cold_source.stop_conditions",
            });
        }
    }
    Ok(())
}

/// Enforces the disposition invariants: only `ACTIVE` is executable, and only
/// an `ACTIVE` row carries a discriminator, a selected proof profile, and an
/// oracle/evidence lineage. A donor-derived row always carries its adoption
/// stage; Stage A is never executable; a Stage B+ `ACTIVE` row cites gate
/// evidence; an `INACTIVE_RESEARCH_GATE` row retains its reason; and a removed,
/// narrowed or retired test proof is never `ACTIVE`. Expiry is checked against
/// the compilation boundary by [`validate_obligation_set`], which owns that
/// boundary.
fn validate_obligation_disposition(
    obligation: &ActiveConformanceObligation,
) -> Result<(), ObligationError> {
    let donor_derived = obligation
        .source_lineage
        .iter()
        .any(|lineage| lineage.donor_ref.is_some());
    if donor_derived && obligation.adoption_stage.is_none() {
        return Err(ObligationError::InvalidDisposition {
            reason: "a donor-derived obligation must carry its adoption stage",
        });
    }
    if obligation.status == ObligationStatus::TargetNotExecuted
        && (obligation.implementation_support != ImplementationSupport::Target
            || obligation.evidence_execution_status != EvidenceExecutionStatus::NotExecuted)
    {
        return Err(ObligationError::InvalidDisposition {
            reason: "a TARGET_NOT_EXECUTED obligation requires TARGET support and NOT_EXECUTED evidence",
        });
    }
    if obligation.status == ObligationStatus::Stale
        && obligation.implementation_support != ImplementationSupport::Stale
    {
        return Err(ObligationError::InvalidDisposition {
            reason: "a STALE obligation requires STALE implementation support",
        });
    }
    if obligation.status == ObligationStatus::InactiveResearchGate
        && obligation.inactive_gate_reason.is_none()
    {
        return Err(ObligationError::MissingEvidence {
            field: "obligation.inactive_gate_reason",
        });
    }
    if obligation
        .test_disposition
        .is_some_and(TestDisposition::excludes_active)
        && obligation.status.is_executable()
    {
        return Err(ObligationError::InvalidDisposition {
            reason: "a removed, narrowed or retired test proof is never an executable obligation",
        });
    }
    if !obligation.status.is_executable() {
        return Ok(());
    }

    if obligation.adoption_stage == Some(AdoptionStage::StageA) {
        return Err(ObligationError::InvalidDisposition {
            reason: "a Stage A research disposition is never an executable obligation",
        });
    }
    if obligation.adoption_stage.is_some() && obligation.stage_gate_evidence_ref.is_none() {
        return Err(ObligationError::MissingEvidence {
            field: "obligation.stage_gate_evidence_ref",
        });
    }

    if obligation.discriminator.is_none() {
        return Err(ObligationError::MissingDiscriminator {
            source_ref: obligation.obligation_id.clone(),
            owner: obligation.owner.clone(),
            property: obligation.property.clone(),
        });
    }
    if obligation.selected_proof_profile_ref.is_none() {
        return Err(ObligationError::MissingEvidence {
            field: "obligation.selected_proof_profile_ref",
        });
    }
    if obligation.oracle.is_none() && obligation.evidence_refs.is_empty() {
        return Err(ObligationError::MissingEvidence {
            field: "obligation.oracle_or_evidence",
        });
    }
    Ok(())
}

/// The first cold-source field on which two claims for the same owner/property
/// disagree, or `None` when they describe the same obligation. `evidence_refs`
/// is deliberately absent: it is oracle/evidence lineage and merges by union.
fn conflicting_field(
    obligation: &ActiveConformanceObligation,
    source: &ColdSourceClaim,
    product_identity: &ProductIdentityCapabilitySet,
) -> Option<&'static str> {
    let (support, execution) = obligation_axes(source, product_identity, obligation.status);
    let mismatched = [
        (
            "obligation_id",
            obligation.obligation_id != source.obligation_id,
        ),
        (
            "contract_ref",
            obligation.contract_ref != source.contract_ref,
        ),
        (
            "capability_ref",
            obligation.capability_ref != source.capability_ref,
        ),
        (
            "activation_trigger",
            obligation.activation_trigger != source.activation_trigger,
        ),
        ("support_gap", obligation.support_gap != source.support_gap),
        (
            "old_failure_or_competing_hypothesis",
            obligation.old_failure_or_competing_hypothesis
                != source.old_failure_or_competing_hypothesis,
        ),
        (
            "discriminator",
            obligation.discriminator != source.discriminator,
        ),
        (
            "selected_proof_profile_ref",
            obligation.selected_proof_profile_ref != source.selected_proof_profile_ref,
        ),
        ("oracle", obligation.oracle != source.oracle),
        (
            "proof_ceiling_ref",
            obligation.proof_ceiling_ref != source.proof_ceiling_ref,
        ),
        ("budget_ref", obligation.budget_ref != source.budget_ref),
        (
            "expires_at_ms",
            obligation.expires_at_ms != source.expires_at_ms,
        ),
        (
            "implementation_support",
            obligation.implementation_support != support,
        ),
        (
            "evidence_execution_status",
            obligation.evidence_execution_status != execution,
        ),
        (
            "writeback_ref",
            obligation.writeback_ref != source.writeback_ref,
        ),
        (
            "adoption_stage",
            obligation.adoption_stage != source.adoption_stage,
        ),
        (
            "stage_gate_evidence_ref",
            obligation.stage_gate_evidence_ref != source.stage_gate_evidence_ref,
        ),
        (
            "inactive_gate_reason",
            obligation.inactive_gate_reason != source.inactive_gate_reason,
        ),
        (
            "test_disposition",
            obligation.test_disposition != source.test_disposition,
        ),
        (
            "test_disposition_reason",
            obligation.test_disposition_reason != source.test_disposition_reason,
        ),
        (
            "test_disposition_evidence_ref",
            obligation.test_disposition_evidence_ref != source.test_disposition_evidence_ref,
        ),
    ];
    mismatched
        .iter()
        .find(|(_, differs)| *differs)
        .map(|(field, _)| *field)
}

fn source_label(lineage: &ColdSourceLineage) -> String {
    lineage
        .source_issue_id
        .clone()
        .or_else(|| lineage.donor_ref.clone())
        .unwrap_or_default()
}

fn obligation_key(obligation: &ActiveConformanceObligation) -> (&str, &str) {
    (obligation.owner.as_str(), obligation.property.as_str())
}

fn lineage_key(lineage: &ColdSourceLineage) -> (Option<&str>, Option<&str>) {
    (
        lineage.source_issue_id.as_deref(),
        lineage.donor_ref.as_deref(),
    )
}

fn validate_contract_version(actual: u16) -> Result<(), ObligationError> {
    if actual == OBLIGATION_CONTRACT_VERSION {
        Ok(())
    } else {
        Err(ObligationError::UnsupportedContractVersion {
            expected: OBLIGATION_CONTRACT_VERSION,
            actual,
        })
    }
}

fn validate_text(field: &'static str, value: &str) -> Result<(), ObligationError> {
    if value.is_empty() {
        return Err(ObligationError::InvalidText {
            field,
            reason: "must not be empty",
        });
    }
    if value.trim() != value {
        return Err(ObligationError::InvalidText {
            field,
            reason: "must not contain leading or trailing whitespace",
        });
    }
    if value.len() > MAX_TEXT_BYTES {
        return Err(ObligationError::InvalidText {
            field,
            reason: "exceeds the maximum UTF-8 byte length",
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ObligationError::InvalidText {
            field,
            reason: "must not contain control characters",
        });
    }
    Ok(())
}

fn validate_optional_text(field: &'static str, value: Option<&str>) -> Result<(), ObligationError> {
    value.map_or(Ok(()), |value| validate_text(field, value))
}

fn canonicalize_text_set(
    field: &'static str,
    values: &mut [String],
) -> Result<(), ObligationError> {
    validate_collection_bound(field, values.len(), MAX_SET_ITEMS)?;
    for value in values.iter() {
        validate_text(field, value)?;
    }
    values.sort();
    if let Some([duplicate, _]) = values.windows(2).find(|pair| pair[0] == pair[1]) {
        return Err(ObligationError::DuplicateValue {
            field,
            value: duplicate.clone(),
        });
    }
    Ok(())
}

fn validate_text_set(field: &'static str, values: &[String]) -> Result<(), ObligationError> {
    validate_collection_bound(field, values.len(), MAX_SET_ITEMS)?;
    for value in values {
        validate_text(field, value)?;
    }
    for pair in values.windows(2) {
        if pair[0] == pair[1] {
            return Err(ObligationError::DuplicateValue {
                field,
                value: pair[0].clone(),
            });
        }
        if pair[0] > pair[1] {
            return Err(ObligationError::NonCanonicalCollection { field });
        }
    }
    Ok(())
}

fn validate_lineage(
    field: &'static str,
    lineage: &[ColdSourceLineage],
) -> Result<(), ObligationError> {
    validate_collection_bound(field, lineage.len(), MAX_SET_ITEMS)?;
    for entry in lineage {
        validate_optional_text(
            "obligation.source_issue_id",
            entry.source_issue_id.as_deref(),
        )?;
        validate_optional_text("obligation.donor_ref", entry.donor_ref.as_deref())?;
        validate_optional_text(
            "obligation.source_test_ref",
            entry.source_test_ref.as_deref(),
        )?;
        if entry.source_issue_id.is_none() && entry.donor_ref.is_none() {
            return Err(ObligationError::MissingSourceLineage);
        }
    }
    for pair in lineage.windows(2) {
        if lineage_key(&pair[0]) >= lineage_key(&pair[1]) {
            return Err(ObligationError::NonCanonicalCollection { field });
        }
    }
    Ok(())
}

fn validate_collection_bound(
    field: &'static str,
    actual: usize,
    maximum: usize,
) -> Result<(), ObligationError> {
    if actual > maximum {
        Err(ObligationError::CollectionTooLarge {
            field,
            maximum,
            actual,
        })
    } else {
        Ok(())
    }
}
