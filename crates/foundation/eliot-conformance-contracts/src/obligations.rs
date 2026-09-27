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

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    EvidenceExecutionStatus, ImplementationSupport, MAX_SET_ITEMS, MAX_SUPPORT_ROWS, MAX_TEXT_BYTES,
};

/// Current serialized obligation-contract revision.
pub const OBLIGATION_CONTRACT_VERSION: u16 = 1;
/// Stable schema identity for [`ActiveConformanceObligation`].
pub const OBLIGATION_SCHEMA: &str = "eliot.conformance.active-obligation.v1";

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
}

impl ObligationStatus {
    /// Whether this status emits an executable obligation into a module capsule
    /// or a product evaluation plan. Only `ACTIVE` does.
    #[must_use]
    pub const fn is_executable(self) -> bool {
        matches!(self, Self::Active)
    }
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
    /// reach the agent hotset through it.
    #[must_use]
    pub fn hotset(&self) -> ActiveObligationHotset {
        ActiveObligationHotset {
            entries: self
                .active_obligations()
                .into_iter()
                .map(ActiveObligationHotsetEntry::from_obligation)
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
}

impl ActiveObligationHotsetEntry {
    /// Reduces one `ACTIVE` obligation to its runtime-hotset content. A
    /// non-active row is never projected, so the fields are present.
    fn from_obligation(obligation: &ActiveConformanceObligation) -> Self {
        Self {
            obligation_id: obligation.obligation_id.clone(),
            owner: obligation.owner.clone(),
            property: obligation.property.clone(),
            capability_ref: obligation.capability_ref.clone(),
            discriminator: obligation.discriminator.clone().unwrap_or_default(),
            selected_proof_profile_ref: obligation
                .selected_proof_profile_ref
                .clone()
                .unwrap_or_default(),
            proof_ceiling_ref: obligation.proof_ceiling_ref.clone(),
            expires_at_ms: obligation.expires_at_ms,
        }
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
pub fn compile_active_conformance_obligations(
    sources: Vec<ColdSourceClaim>,
    product_identity: &ProductIdentityCapabilitySet,
    compiled_at_ms: u64,
) -> Result<ActiveConformanceObligationSet, ObligationError> {
    product_identity.validate()?;
    validate_collection_bound("cold_sources", sources.len(), MAX_SUPPORT_ROWS)?;
    if compiled_at_ms == 0 {
        return Err(ObligationError::InvalidTime {
            field: "compiled_at_ms",
        });
    }

    let mut sources = sources;
    for source in &mut sources {
        canonicalize_text_set("cold_source.evidence_refs", &mut source.evidence_refs)?;
        validate_cold_source_claim(source)?;
    }
    sources.sort_by_key(|source| (source.owner.clone(), source.property.clone()));

    let mut obligations: Vec<ActiveConformanceObligation> = Vec::new();
    for source in sources {
        merge_cold_source(&mut obligations, source, product_identity)?;
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
/// causal property and owner while retaining every source lineage.
fn merge_cold_source(
    obligations: &mut Vec<ActiveConformanceObligation>,
    source: ColdSourceClaim,
    product_identity: &ProductIdentityCapabilitySet,
) -> Result<(), ObligationError> {
    let existing = obligations.iter_mut().find(|obligation| {
        obligation.owner == source.owner && obligation.property == source.property
    });
    let Some(obligation) = existing else {
        let compiled = compile_obligation(&source, product_identity)?;
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
fn compile_obligation(
    source: &ColdSourceClaim,
    product_identity: &ProductIdentityCapabilitySet,
) -> Result<ActiveConformanceObligation, ObligationError> {
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
            }),
            owner: source.owner.clone(),
            property: source.property.clone(),
        });
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
        source_lineage: vec![ColdSourceLineage {
            source_issue_id: source.source_issue_id.clone(),
            donor_ref: source.donor_ref.clone(),
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

/// Enforces the disposition invariants: only `ACTIVE` is executable, and only
/// an `ACTIVE` row carries a discriminator, a selected proof profile, and an
/// oracle/evidence lineage. Expiry is checked against the compilation boundary
/// by [`validate_obligation_set`], which owns that boundary.
fn validate_obligation_disposition(
    obligation: &ActiveConformanceObligation,
) -> Result<(), ObligationError> {
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
    if !obligation.status.is_executable() {
        return Ok(());
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
