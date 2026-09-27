//! Skill-scoped harness activation receipts, instruction conflicts, and the
//! Material-use staleness gate.
//!
//! This module implements the I7.25 contract fragment owned by the Skill
//! lifecycle owner: one per-attempt `SkillHarnessActivationReceipt` binding
//! eligibility, packet position, retrieval, delivery, observable activation
//! and early/mid/final adherence; `InstructionConflict` records that preserve
//! explicitly specified or observed ordering instead of prompt order; and a
//! dependency/Tool Definition staleness gate that blocks Material use until
//! governed review or restore. Absent adherence evidence stays unknown;
//! aggregate counts never substitute for the exact receipt.
//!
//! It also owns the unknown-effects reconciliation assessment (issue #2664):
//! one unique current-state projection of a bounded evidence window, per
//! execution dispositions, and an explicit clearance that replaces the
//! page-local retry boolean. A submitted page is an observation, never a
//! denominator — without an owner-issued expected execution/effect set the
//! window cannot be shown complete, so it clears nothing. The assessment is
//! evidence for the existing retry/admission gate and never issues a permit.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};

use super::{
    DependencyVersion, ExecutionOutcome, LifecycleAction, LifecycleCounters, SkillCatalogueEntry,
    SkillError, SkillExecutionEvidence, SkillInteractionView, SkillLifecycleView, SkillRef,
    SkillScope, SkillStatus, digest, text, unique,
};

/// How retrieval of the Skill for one attempt was observed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillRetrievalStatus {
    /// The Skill was not eligible for this attempt.
    NotEligible,
    /// Eligible but never retrieved; packet inclusion alone never implies this.
    EligibleNotRetrieved,
    /// Retrieved for the attempt surface.
    Retrieved,
    /// Retrieved and expanded (lazy handle resolved).
    Expanded,
    /// Retrieval observability was missing or inconclusive.
    #[default]
    Unknown,
}

/// How delivery of the retrieved Skill to the attempt surface was observed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillDeliveryStatus {
    /// Nothing was delivered for this attempt.
    #[default]
    NotDelivered,
    /// Full Skill content delivered at the recorded packet position.
    Full,
    /// Partial delivery (truncation or compaction loss recorded separately).
    Partial,
    /// Delivery was expected but the payload is missing.
    Missing,
}

/// Whether qualifying observable activation of the Skill occurred.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillActivationStatus {
    /// Activation was never assessed for this attempt.
    #[default]
    NotAssessed,
    /// Assessed and no qualifying observable use was found. This proves
    /// nothing about non-use; it records absence of evidence only.
    NotObserved,
    /// A qualifying observable use was recorded with a use reference.
    Observed,
    /// Activation observability was missing or inconclusive.
    Unknown,
}

/// Whether the Skill prescription was followed at one checkpoint.
///
/// Silence about adherence is unknown, never compliance.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillAdherenceStatus {
    /// The checkpoint was never assessed.
    #[default]
    NotAssessed,
    /// The prescription was observably followed.
    Followed,
    /// The prescription was partially followed.
    Partial,
    /// The prescription was observably violated.
    Violated,
    /// Adherence evidence was missing or inconclusive.
    Unknown,
}

/// Early/mid/final adherence checkpoints bound to one attempt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdherenceCheckpoints {
    pub early: SkillAdherenceStatus,
    pub mid: SkillAdherenceStatus,
    pub final_checkpoint: SkillAdherenceStatus,
}

impl AdherenceCheckpoints {
    /// Combines the three checkpoints without inferring compliance:
    /// any violation dominates, then partial, then unanimous followed;
    /// any silence stays `Unknown`, never compliance (I7.25: silence about
    /// adherence is unknown, not compliance; installation, retrieval,
    /// repetition and model agreement never appear here).
    #[must_use]
    pub fn combined(self) -> SkillAdherenceStatus {
        use SkillAdherenceStatus::{Followed, Partial, Unknown, Violated};
        let checkpoints = [self.early, self.mid, self.final_checkpoint];
        if checkpoints.contains(&Violated) {
            Violated
        } else if checkpoints.contains(&Partial) {
            Partial
        } else if checkpoints.iter().all(|status| *status == Followed) {
            Followed
        } else {
            Unknown
        }
    }
}

/// Per-attempt evidence binding eligibility, packet position, retrieval,
/// delivery, observable activation and adherence for one Skill revision.
///
/// Retrieval, delivery, activation, adherence and outcome remain orthogonal;
/// the fields are not a success ladder. Receipt existence never implies
/// successful delivery, use, adherence or benefit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillHarnessActivationReceipt {
    pub receipt_id: String,
    pub skill_id: String,
    pub skill_revision: String,
    pub package_digest: String,
    pub attempt_ref: String,
    pub route_ref: String,
    pub state_fence: StateFence,
    pub packet_digest: String,
    pub packet_position: u64,
    pub eligible: bool,
    pub eligibility_reason: String,
    pub retrieval: SkillRetrievalStatus,
    pub delivery: SkillDeliveryStatus,
    pub activation: SkillActivationStatus,
    pub activation_observed_use_ref: Option<String>,
    pub activation_latency_ms: Option<u64>,
    pub adherence: AdherenceCheckpoints,
    pub conflict_or_suppression_refs: Vec<String>,
    pub downstream_refs: Vec<String>,
    /// Verifier-backed outcome evidence. Only non-empty verified outcomes can
    /// support a usefulness claim; installation, retrieval, repetition and
    /// model agreement never appear here.
    pub verified_outcome_refs: Vec<String>,
}

impl SkillHarnessActivationReceipt {
    pub fn validate(&self) -> Result<(), SkillError> {
        self.validate_identity()?;
        self.validate_flow()?;
        self.validate_activation()?;
        self.validate_adherence()?;
        self.validate_refs()?;
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), SkillError> {
        for (value, field) in [
            (&self.receipt_id, "receipt.receipt_id"),
            (&self.skill_id, "receipt.skill_id"),
            (&self.skill_revision, "receipt.skill_revision"),
            (&self.attempt_ref, "receipt.attempt_ref"),
            (&self.route_ref, "receipt.route_ref"),
            (&self.eligibility_reason, "receipt.eligibility_reason"),
        ] {
            text(value, field)?;
        }
        digest(&self.package_digest, "receipt.package_digest")?;
        digest(&self.packet_digest, "receipt.packet_digest")?;
        self.state_fence
            .validate()
            .map_err(|error| SkillError::Surface(error.to_string()))
    }

    fn validate_flow(&self) -> Result<(), SkillError> {
        if self.eligible && self.retrieval == SkillRetrievalStatus::NotEligible {
            return Err(SkillError::InvalidField {
                field: "receipt.retrieval",
                reason: "an eligible Skill cannot carry a not-eligible retrieval",
            });
        }
        if !self.eligible
            && !matches!(
                self.retrieval,
                SkillRetrievalStatus::NotEligible | SkillRetrievalStatus::Unknown
            )
        {
            return Err(SkillError::InvalidField {
                field: "receipt.retrieval",
                reason: "an ineligible Skill cannot be retrieved or expanded",
            });
        }
        if matches!(
            self.delivery,
            SkillDeliveryStatus::Full | SkillDeliveryStatus::Partial
        ) && !matches!(
            self.retrieval,
            SkillRetrievalStatus::Retrieved | SkillRetrievalStatus::Expanded
        ) {
            return Err(SkillError::InvalidField {
                field: "receipt.delivery",
                reason: "delivery requires exact retrieval evidence",
            });
        }
        Ok(())
    }

    fn validate_activation(&self) -> Result<(), SkillError> {
        if self.activation == SkillActivationStatus::Observed {
            if !matches!(
                self.delivery,
                SkillDeliveryStatus::Full | SkillDeliveryStatus::Partial
            ) {
                return Err(SkillError::InvalidField {
                    field: "receipt.activation",
                    reason: "observed activation requires exact delivery evidence",
                });
            }
            match &self.activation_observed_use_ref {
                Some(use_ref) => text(use_ref, "receipt.activation_observed_use_ref")?,
                None => {
                    return Err(SkillError::InvalidField {
                        field: "receipt.activation_observed_use_ref",
                        reason: "observed activation requires a qualifying use reference",
                    });
                }
            }
        } else {
            if self.activation_observed_use_ref.is_some() {
                return Err(SkillError::InvalidField {
                    field: "receipt.activation_observed_use_ref",
                    reason: "a use reference without observed activation is not evidence",
                });
            }
            if self.activation_latency_ms.is_some() {
                return Err(SkillError::InvalidField {
                    field: "receipt.activation_latency_ms",
                    reason: "latency without observed activation is not evidence",
                });
            }
        }
        Ok(())
    }

    fn validate_adherence(&self) -> Result<(), SkillError> {
        let assessed = [
            self.adherence.early,
            self.adherence.mid,
            self.adherence.final_checkpoint,
        ]
        .iter()
        .any(|status| {
            matches!(
                status,
                SkillAdherenceStatus::Followed
                    | SkillAdherenceStatus::Partial
                    | SkillAdherenceStatus::Violated
            )
        });
        if assessed && self.activation != SkillActivationStatus::Observed {
            return Err(SkillError::InvalidField {
                field: "receipt.adherence",
                reason: "adherence findings require observed activation",
            });
        }
        Ok(())
    }

    fn validate_refs(&self) -> Result<(), SkillError> {
        for (values, field) in [
            (
                &self.conflict_or_suppression_refs,
                "receipt.conflict_or_suppression_refs",
            ),
            (&self.downstream_refs, "receipt.downstream_refs"),
            (&self.verified_outcome_refs, "receipt.verified_outcome_refs"),
        ] {
            unique(values.iter().cloned(), field)?;
            for value in values {
                text(value, field)?;
            }
        }
        Ok(())
    }
}

/// Whether usefulness is established for one attempt, and by what evidence.
///
/// I7.25 keeps `installed != delivered != executed != useful` and states that
/// a `SkillExecutionEvidence` "cannot prove that the Skill alone caused the
/// result", while I12.24 makes usefulness depend on an owner-backed
/// utility/outcome relation rather than on a presented reference. A plain
/// `bool` cannot express that gap, so the claim is a vocabulary: only an
/// owner-resolved relation to a recorded verifier-run/outcome record may
/// produce [`OwnerBacked`](Self::OwnerBacked); every other state — including
/// a presented-but-unresolved outcome reference — stays
/// [`Unknown`](Self::Unknown) or [`NotEstablished`](Self::NotEstablished).
/// Absence of a resolved owner relation is never a negative fact about the
/// Skill and never a positive one.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillUsefulness {
    /// The observed activation, followed adherence and the presented outcome
    /// references resolved to owner-recorded verifier-run/outcome records
    /// bound to this exact attempt, Skill revision and fence.
    OwnerBacked,
    /// Activation or adherence was not observed, so no usefulness relation
    /// could be evaluated. Never a negative finding.
    #[default]
    Unknown,
    /// The owner record was resolved and it does not attribute utility to this
    /// attempt; the run is observed but unattributed.
    NotEstablished,
}

impl SkillUsefulness {
    /// Whether this variant is a positive usefulness claim. Only the
    /// owner-backed relation qualifies, so no plain boolean can stand in for
    /// it.
    #[must_use]
    pub const fn is_useful(self) -> bool {
        matches!(self, Self::OwnerBacked)
    }
}

/// Derived per-attempt lifecycle summary. `delivered`, `retrieved`,
/// `activated`, `adhered` and `useful` are distinct claims; a Skill included
/// in a packet but never retrieved or activated is never marked successful.
///
/// The four flags are independent lifecycle stages, not a ladder, so the
/// struct keeps them as plain booleans by design. Usefulness is NOT a
/// boolean: it is a [`SkillUsefulness`] because only an owner-resolved
/// utility/outcome relation can establish it (I7.25, I12.24).
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptLifecycleSummary {
    pub delivered: bool,
    pub retrieved: bool,
    pub activated: bool,
    pub adhered: SkillAdherenceStatus,
    pub useful: SkillUsefulness,
}

/// Derives the attempt summary from the exact receipt, WITHOUT any usefulness
/// claim.
///
/// Usefulness is deliberately absent from this derivation: a presented
/// `verified_outcome_refs` list is an unverified wire string set, and
/// recognising that the list is non-empty proves nothing about the Skill.
/// This function therefore always reports [`SkillUsefulness::Unknown`]; the
/// owner-backed verdict comes only from
/// [`qualify_useful_outcomes`](crate::qualify_useful_outcomes), which
/// compares each reference against a real owner record. This keeps
/// [`AttemptLifecycleSummary::useful`] unassignable by shape alone.
#[must_use]
pub fn derive_attempt_summary(receipt: &SkillHarnessActivationReceipt) -> AttemptLifecycleSummary {
    let delivered = matches!(
        receipt.delivery,
        SkillDeliveryStatus::Full | SkillDeliveryStatus::Partial
    );
    let retrieved = matches!(
        receipt.retrieval,
        SkillRetrievalStatus::Retrieved | SkillRetrievalStatus::Expanded
    );
    let activated = receipt.activation == SkillActivationStatus::Observed;
    let adhered = receipt.adherence.combined();
    AttemptLifecycleSummary {
        delivered,
        retrieved,
        activated,
        adhered,
        useful: SkillUsefulness::Unknown,
    }
}

/// One presented outcome reference resolved to a canonical owner record, with
/// the owner revision the read reported.
///
/// `record` is the ORIGINAL recorded value, re-validated against itself by
/// [`qualify_useful_outcomes`] before it may support a claim — never a freshly
/// recomputed substitute — and `reference` is the exact string the receipt
/// presented. The pair exists only because a bounded named owner read returned
/// the record under a selector that names this attempt; a caller that cannot
/// produce this pair cannot produce a usefulness claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedOutcome {
    /// Exact presented outcome reference this record was resolved for.
    pub reference: String,
    /// Owner revision (commit order) the canonical read reported, when that
    /// owner reports one. `None` is the honest state for a keyed immutable
    /// row owner (issue #1868 learning records) whose identity IS its
    /// `record_digest` and which publishes no per-row commit order: a revision
    /// is never synthesized to fill the field.
    pub source_revision: Option<u64>,
    /// The original recorded outcome, carried verbatim.
    pub record: SkillExecutionEvidence,
}

/// Resolves the usefulness relation for one observed attempt against real
/// owner-recorded outcomes, and returns the owner-backed summary.
///
/// `resolved` pairs are the owner records the caller's bounded named read
/// returned for this receipt's `verified_outcome_refs`; each record is the
/// ORIGINAL recorded value and is re-validated through
/// [`SkillExecutionEvidence::validate`] before it may support a claim. The
/// gate is conjunctive and evidence-typed:
///
/// * the attempt must show observed activation, and
/// * adherence must combine to [`SkillAdherenceStatus::Followed`], and
/// * at least one of the receipt's presented `verified_outcome_refs` must
///   resolve to an owner record that itself validates.
///
/// Anything short of that reports [`SkillUsefulness::Unknown`] — never
/// `OwnerBacked`, and never a negative fact about the Skill. A foreign or
/// substituted outcome reference cannot produce a positive claim: a reference
/// the receipt never presented is ignored outright, and one that resolves to
/// a record failing its own validation is discarded.
///
/// Causal credit is never consumed here. Usefulness never converts
/// [`CausalCredit::NoCausalCredit`] or a distributed/uncertain credit into a
/// sole-cause claim: it records only that a verifier-run/outcome owner record
/// exists for this attempt.
#[must_use]
pub fn qualify_useful_outcomes(
    receipt: &SkillHarnessActivationReceipt,
    resolved: &[ResolvedOutcome],
) -> AttemptLifecycleSummary {
    let mut summary = derive_attempt_summary(receipt);
    if receipt.activation != SkillActivationStatus::Observed
        || summary.adhered != SkillAdherenceStatus::Followed
    {
        return summary;
    }
    let matched = resolved.iter().any(|candidate| {
        // The reference must be one this receipt actually presented, and the
        // record must be the one that reference resolved to, validated as
        // recorded.
        receipt.verified_outcome_refs.contains(&candidate.reference)
            && candidate.record.execution_ref == candidate.reference
            && candidate.record.validate().is_ok()
    });
    summary.useful = if matched {
        SkillUsefulness::OwnerBacked
    } else {
        SkillUsefulness::Unknown
    };
    summary
}

/// How completely one owner-qualified claim was backed by the reads that
/// actually ran.
///
/// Coverage is recorded, never assumed: a claim whose source read was absent,
/// refused, or truncated reports the corresponding state instead of silently
/// degrading to a positive or negative finding (I7.25, I12.24).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceCoverage {
    /// Every load-bearing source read ran, was current, and was complete.
    Complete,
    /// A source read was unavailable or refused; the claim is unqualified.
    #[default]
    Partial,
    /// A source read was truncated, so currency could not be proved.
    Truncated,
    /// A load-bearing source read was absent, so the claim is unqualified.
    Blocked,
}

impl EvidenceCoverage {
    /// Whether the backing reads fully settled this candidate. Only
    /// [`Complete`](Self::Complete) may publish a settled claim; every other
    /// state reports the unresolved coverage instead, so a missing read is
    /// never read as a finding.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::Complete)
    }
}

/// One load-bearing owner revision a qualification decision depended on.
///
/// The revision is whatever the canonical read actually reported for that
/// source. It is never synthesized: an entry exists only because a bounded
/// named read returned a current value for the exact selector that named this
/// attempt, and `revision` is `None` for a keyed immutable row owner whose own
/// digest IS its revision identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRevision {
    /// Closed source this revision came from (e.g. the lifecycle row, the
    /// attempt record, the outcome record).
    pub source: String,
    /// Owner revision the canonical read reported, when it reports one.
    pub revision: Option<u64>,
}

impl SourceRevision {
    pub fn validate(&self) -> Result<(), SkillError> {
        text(&self.source, "source_revision.source")?;
        Ok(())
    }
}

/// An ingest candidate bound to the owner revisions and evidence that
/// qualified it, together with the coverage those reads actually achieved.
///
/// This is a candidate, not a finding. It is the ingest-side counterpart of
/// `LifecycleCounters`: it records WHAT was read, AT WHICH revision, and HOW
/// COMPLETELY — and a claim that could not be fully backed stays
/// `unknown`/unqualified rather than becoming a negative fact about the Skill
/// or a positive summary. Every load-bearing owner revision is carried
/// explicitly, so a later publisher can re-check them under a fresh borrow
/// rather than trusting a stale observation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerQualifiedCandidate {
    /// Skill identity the candidate observes.
    pub skill_id: String,
    /// Skill revision observed.
    pub skill_revision: String,
    /// Package digest observed.
    pub package_digest: String,
    /// Attempt identity the evidence is bound to — the HISTORICAL agent
    /// attempt being observed, never the authenticated ingest request.
    pub subject_attempt_ref: String,
    /// Load-bearing owner revisions the qualification depended on.
    pub source_revisions: Vec<SourceRevision>,
    /// Owner records that resolved this receipt's presented outcome refs.
    pub resolved_outcomes: Vec<ResolvedOutcome>,
    /// How completely the backing reads were served.
    pub coverage: EvidenceCoverage,
    /// Usefulness established from the resolved owner records, or unknown.
    pub useful: SkillUsefulness,
}

impl OwnerQualifiedCandidate {
    /// Whether every load-bearing read was complete and current. A partial,
    /// truncated or blocked candidate is never publishable as a settled claim.
    #[must_use]
    pub fn is_fully_qualified(&self) -> bool {
        self.coverage == EvidenceCoverage::Complete
    }

    pub fn validate(&self) -> Result<(), SkillError> {
        text(&self.skill_id, "candidate.skill_id")?;
        text(&self.skill_revision, "candidate.skill_revision")?;
        digest(&self.package_digest, "candidate.package_digest")?;
        text(&self.subject_attempt_ref, "candidate.subject_attempt_ref")?;
        for revision in &self.source_revisions {
            revision.validate()?;
        }
        for outcome in &self.resolved_outcomes {
            text(&outcome.reference, "candidate.resolved_outcome.reference")?;
            outcome
                .record
                .validate()
                .map_err(|error| SkillError::Surface(error.to_string()))?;
        }
        Ok(())
    }
}

/// What the recorded skill ordering is grounded in. Packet (prompt) order is
/// deliberately not a variant: conflicting Skills are never resolved by
/// prompt order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderingBasis {
    ExplicitlySpecified,
    Observed,
}

/// A preserved conflict between two Skills. The recorded ordering is the
/// explicitly specified or observed one; it never defaults to packet order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionConflict {
    pub conflict_id: String,
    pub skill_a_id: String,
    pub skill_b_id: String,
    pub reason: String,
    pub first_skill_id: String,
    pub ordering_basis: OrderingBasis,
    pub mutual_exclusion: bool,
}

impl InstructionConflict {
    pub fn validate(&self) -> Result<(), SkillError> {
        for (value, field) in [
            (&self.conflict_id, "conflict.conflict_id"),
            (&self.skill_a_id, "conflict.skill_a_id"),
            (&self.skill_b_id, "conflict.skill_b_id"),
            (&self.reason, "conflict.reason"),
            (&self.first_skill_id, "conflict.first_skill_id"),
        ] {
            text(value, field)?;
        }
        if self.skill_a_id == self.skill_b_id {
            return Err(SkillError::InvalidField {
                field: "conflict",
                reason: "a Skill cannot conflict with itself",
            });
        }
        if self.first_skill_id != self.skill_a_id && self.first_skill_id != self.skill_b_id {
            return Err(SkillError::InvalidField {
                field: "conflict.first_skill_id",
                reason: "ordering must name one of the conflicting Skills",
            });
        }
        Ok(())
    }
}

/// Records an instruction conflict between two Skills, preserving the
/// explicitly specified or observed ordering. Packet order is never consulted.
///
/// The `skill_a_id`/`skill_b_id` pair names are intentional domain vocabulary.
#[allow(clippy::similar_names)]
pub fn record_instruction_conflict(
    conflict_id: String,
    skill_a_id: String,
    skill_b_id: String,
    reason: String,
    first_skill_id: String,
    ordering_basis: OrderingBasis,
    mutual_exclusion: bool,
) -> Result<InstructionConflict, SkillError> {
    let conflict = InstructionConflict {
        conflict_id,
        skill_a_id,
        skill_b_id,
        reason,
        first_skill_id,
        ordering_basis,
        mutual_exclusion,
    };
    conflict.validate()?;
    Ok(conflict)
}

/// Indexes dependency versions by name for exact comparison.
fn index_versions(versions: &[DependencyVersion]) -> BTreeMap<String, (String, String)> {
    versions
        .iter()
        .map(|dependency| {
            (
                dependency.name.clone(),
                (
                    dependency.version.clone(),
                    dependency.contract_digest.clone(),
                ),
            )
        })
        .collect()
}

/// Compares the dependency and Tool Definition versions pinned by a Skill
/// against the currently registered versions. Returns a stale reason naming
/// every added, removed or changed dependency, or `None` when the sets agree.
///
/// Any version or contract-digest change marks the Skill stale before Material
/// use, per I7.24/I7.25.
#[must_use]
pub fn detect_dependency_staleness(
    pinned: &[DependencyVersion],
    current: &[DependencyVersion],
) -> Option<String> {
    let pinned_map = index_versions(pinned);
    let current_map = index_versions(current);
    let mut changes = Vec::new();
    for (name, pinned_entry) in &pinned_map {
        match current_map.get(name) {
            None => changes.push(format!("{name}: removed")),
            Some(current_entry) => {
                if current_entry != pinned_entry {
                    changes.push(format!("{name}: {} -> {}", pinned_entry.0, current_entry.0));
                }
            }
        }
    }
    for name in current_map.keys() {
        if !pinned_map.contains_key(name) {
            changes.push(format!("{name}: added"));
        }
    }
    if changes.is_empty() {
        None
    } else {
        Some(format!(
            "dependency versions changed: {}",
            changes.join("; ")
        ))
    }
}

/// Whether the Skill may appear in Material use. Stale and quarantined Skills
/// are blocked until governed review or restore; every other status is left
/// to its own admission path.
#[must_use]
pub const fn material_use_allowed(status: SkillStatus) -> bool {
    !matches!(status, SkillStatus::Stale | SkillStatus::Quarantined)
}

/// Names of dependencies whose pinned versions disagree, for ledger detail.
/// Returns an empty set when the sets agree.
#[must_use]
pub fn changed_dependency_names(
    pinned: &[DependencyVersion],
    current: &[DependencyVersion],
) -> BTreeSet<String> {
    let pinned_map = index_versions(pinned);
    let current_map = index_versions(current);
    pinned_map
        .iter()
        .filter(|(name, pinned_entry)| current_map.get(*name) != Some(*pinned_entry))
        .map(|(name, _)| name.clone())
        .chain(
            current_map
                .keys()
                .filter(|name| !pinned_map.contains_key(*name))
                .cloned(),
        )
        .collect()
}

/// Marks a Skill lifecycle view stale when its pinned dependency or Tool
/// Definition versions disagree with the currently registered versions.
///
/// Returns `Ok(None)` when the sets agree, when the view already carries this
/// exact stale reason, or when the view is quarantined: quarantine is governed
/// state and its reason must only change through review, while the Material
/// gate already blocks quarantined Skills. Otherwise returns the next-revision
/// view with `Stale` status and the detection reason, leaving counters,
/// evidence, curation advice and fence untouched.
pub fn apply_dependency_staleness(
    view: &SkillLifecycleView,
    current: &[DependencyVersion],
) -> Result<Option<SkillLifecycleView>, SkillError> {
    view.validate()?;
    if view.status == SkillStatus::Quarantined {
        return Ok(None);
    }
    let Some(reason) = detect_dependency_staleness(&view.dependencies, current) else {
        return Ok(None);
    };
    if view.status == SkillStatus::Stale
        && view.stale_or_quarantine_reason.as_deref() == Some(reason.as_str())
    {
        return Ok(None);
    }
    let mut marked = view.clone();
    marked.status = SkillStatus::Stale;
    marked.stale_or_quarantine_reason = Some(reason);
    marked.lifecycle_revision = view.lifecycle_revision.saturating_add(1);
    marked.validate()?;
    Ok(Some(marked))
}

/// Immutable evidence bundle for deriving one [`SkillLifecycleView`].
///
/// Every field traces to a Governor-owned record; nothing is inferred:
/// `skill_ref` is the install identity (skill/revision/name/package digest),
/// `scope` the Governor admission scope, `applies_when` the package behavior
/// applicability the catalogue entry does not retain, `entry` the installed
/// catalogue body/dependencies/applicability, `attempts` the per-attempt
/// harness receipts, `executions` the step/artifact/verifier/outcome evidence,
/// `conflicts` the recorded instruction conflicts, and `current_dependencies`
/// the live world versions the pinned set is compared against.
pub struct LifecycleEvidence<'a> {
    pub skill_ref: SkillRef,
    pub scope: SkillScope,
    pub applies_when: Vec<String>,
    pub entry: &'a SkillCatalogueEntry,
    pub attempts: &'a [SkillHarnessActivationReceipt],
    pub executions: &'a [SkillExecutionEvidence],
    pub conflicts: &'a [InstructionConflict],
    pub current_dependencies: &'a [DependencyVersion],
    pub observed_decision_or_verifier_delta: Option<String>,
    pub state_fence: StateFence,
}

/// Derives one lifecycle view strictly from immutable evidence.
///
/// Counter bijection (mirrors the surface `DeliveryProjection` rule that every
/// counter value equals its exact evidence-list length): `installed` is 1 for
/// the presented entry; `delivered`/`expanded` count the bound attempts with
/// delivery/expansion evidence; `executed`/`failed`/`uncertain` count the
/// execution evidence by outcome and `verified` counts observed executions
/// with verifier refs; `useful` counts attempts whose exact receipt summary is
/// useful. Installed, delivered, executed and useful stay distinct. The view
/// retains the exact bound attempt receipts alongside the counters, so
/// lifecycle fields resolve to their underlying activation records instead of
/// leaving aggregate counts to substitute for them.
/// Status is `Stale` with the detection reason exactly when the pinned
/// dependencies disagree with the live set, else `Current`: quarantine only
/// arrives through governed review, never through derivation. Interaction refs
/// fold validated conflicts (conflict id, preserved first-skill ordering,
/// rival id on mutual exclusion); packet order is never read. Attempts from a
/// foreign skill revision or package digest fail closed with `IdentityMismatch`.
/// A coherent evidence window is required: incoherent sets (more deliveries
/// than installs, usefulness without verifier-backed execution evidence) are
/// rejected by the final validation, never adjusted — the runtime accumulates
/// coherent windows across install revisions.
///
/// The execution counters here come from the unique current-state projection,
/// so an evidence slice carrying one record twice, or two different records
/// under one identity, derives counters the view's own validation rejects
/// rather than publishing an inflated or arbitrarily resolved count. See
/// [`fold_execution_evidence`] for the full statement of which inputs disagree
/// with that validation and why the projection is the authoritative one.
pub fn derive_lifecycle_view(
    evidence: LifecycleEvidence<'_>,
) -> Result<SkillLifecycleView, SkillError> {
    evidence.skill_ref.validate()?;
    evidence.scope.validate()?;
    if evidence.entry.index.skill_id != evidence.skill_ref.skill_id() {
        return Err(SkillError::IdentityMismatch);
    }
    let skill_id = evidence.skill_ref.skill_id().to_owned();
    let attempts = fold_attempt_evidence(
        &skill_id,
        &evidence.skill_ref.registration.revision,
        &evidence.skill_ref.package_digest,
        evidence.attempts,
    )?;
    let executions = fold_execution_evidence(evidence.executions)?;
    let interactions = fold_interaction_evidence(&skill_id, evidence.conflicts)?;
    let (status, stale_or_quarantine_reason) = match detect_dependency_staleness(
        &evidence.entry.dependencies,
        evidence.current_dependencies,
    ) {
        Some(reason) => (SkillStatus::Stale, Some(reason)),
        None => (SkillStatus::Current, None),
    };
    let view = SkillLifecycleView {
        skill_ref: evidence.skill_ref,
        scope: evidence.scope,
        applies_when: evidence.applies_when,
        does_not_apply_when: evidence.entry.body.where_not_apply.clone(),
        dependencies: evidence.entry.dependencies.clone(),
        counters: LifecycleCounters {
            installed: 1,
            delivered: attempts.delivered,
            expanded: attempts.expanded,
            executed: executions.executed,
            verified: executions.verified,
            failed: executions.failed,
            uncertain: executions.uncertain,
            useful: attempts.useful,
        },
        execution_evidence: evidence.executions.to_vec(),
        // The fold above validated every receipt and bound it to this exact
        // skill revision and package digest, so retaining the presented slice
        // keeps exactly the records the counters count — no more, no fewer.
        attempt_receipts: evidence.attempts.to_vec(),
        observed_decision_or_verifier_delta: evidence.observed_decision_or_verifier_delta,
        false_activation_refs: attempts.false_activation_refs,
        interactions,
        status,
        stale_or_quarantine_reason,
        proposed_action: LifecycleAction::Keep,
        review: None,
        state_fence: evidence.state_fence,
        lifecycle_revision: 1,
    };
    view.validate()?;
    Ok(view)
}

/// Per-attempt counts folded from exact harness receipts bound to one skill
/// revision and package digest.
struct AttemptFold {
    delivered: u64,
    expanded: u64,
    useful: u64,
    false_activation_refs: Vec<String>,
}

/// Folds delivery/expansion/usefulness counts from receipts bound to the exact
/// skill identity. Retrieval, delivery, activation, adherence and outcome stay
/// orthogonal per receipt; retrieved-but-unobserved attempts contribute their
/// attempt ref to the false-activation history (a history ref, never a
/// non-use verdict). Foreign revisions or digests fail closed.
fn fold_attempt_evidence(
    skill_id: &str,
    skill_revision: &str,
    package_digest: &str,
    attempts: &[SkillHarnessActivationReceipt],
) -> Result<AttemptFold, SkillError> {
    let mut fold = AttemptFold {
        delivered: 0,
        expanded: 0,
        useful: 0,
        false_activation_refs: Vec::new(),
    };
    for receipt in attempts {
        receipt.validate()?;
        if receipt.skill_id != skill_id
            || receipt.skill_revision != skill_revision
            || receipt.package_digest != package_digest
        {
            return Err(SkillError::IdentityMismatch);
        }
        let summary = derive_attempt_summary(receipt);
        if summary.delivered {
            fold.delivered = fold.delivered.saturating_add(1);
        }
        if receipt.retrieval == SkillRetrievalStatus::Expanded {
            fold.expanded = fold.expanded.saturating_add(1);
        }
        if summary.useful.is_useful() {
            fold.useful = fold.useful.saturating_add(1);
        }
        if summary.retrieved
            && receipt.activation == SkillActivationStatus::NotObserved
            && !fold.false_activation_refs.contains(&receipt.attempt_ref)
        {
            fold.false_activation_refs.push(receipt.attempt_ref.clone());
        }
    }
    Ok(fold)
}

/// Execution counters folded from the ONE unique current-state projection of
/// step/artifact/verifier evidence. Public so production evidence ingest
/// (daemon execution drive) and the lifecycle derivation fold through the
/// same named counter type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionFold {
    /// Distinct executions whose current state is an observed outcome.
    pub executed: u64,
    /// Distinct observed executions whose effect disposition is complete: a
    /// verifier run over the observed effect.
    pub verified: u64,
    /// Distinct executions whose current state is a known failure.
    pub failed: u64,
    /// Distinct executions whose effects are still unknown.
    pub uncertain: u64,
}

/// Exact source-event/evidence identity of one retained execution record,
/// with the commitment over its own recorded content.
///
/// `evidence_ref` is the identity the record is filed under and
/// `content_digest` a digest over that record's canonical content. Two
/// presentations of one record share both whatever their outcome, so an exact
/// replay is recognisable without reading the outcome; the same identity with
/// a different digest is a conflict, never a rewrite (I14.21: a changed
/// record is not the same evidence, and no blind duplicate effect follows).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEvidenceIdentity {
    /// Exact evidence identity the record was presented under.
    pub evidence_ref: String,
    /// Digest over the record's own canonical content.
    pub content_digest: String,
}

/// What the current-state projection says about ONE execution's effects, and
/// therefore what that execution may do next.
///
/// This is the I14.21 partition per operation, never an aggregate: `committed
/// → reconcile ORS`, `known rollback → retry under the same identity`,
/// `unknown → pause Ordering Scope, preserve the operation`.
///
/// The issue's table separates "exact committed effect/result found" from
/// "Observed status without complete effect disposition" while the evidence
/// vocabulary has ONE observed outcome, so the split has to rest on a field
/// that records whether the effect disposition is actually complete. It rests
/// on the same signal this crate already uses for the `verified` counter — a
/// non-empty `verifier_refs` — because that is the only field in
/// [`SkillExecutionEvidence`] carrying "a verifier observed this effect"
/// (I7.25: Skill execution is linked to exact steps, artifacts and verifiers
/// when observable). An observed record with a verifier run is a committed
/// result to reconcile; an observed record without one has a status only.
/// A reviewer could reasonably split these two the other way, and the field to
/// change is `effect_state` alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEffectState {
    /// Exact committed effect/result found: reconcile and return the ORIGINAL
    /// result. That effect is not executed again.
    CommittedResult,
    /// Observed status WITHOUT a complete effect disposition (no verifier run
    /// over the effect). No retry safety is inferred from the status alone.
    ObservedWithoutEffectDisposition,
    /// Known execution failure. The effect is not a committed result, but a
    /// failure is a STATUS: the original retry policy and its existing
    /// same-identity gate decide whether a retry is permitted, never this
    /// projection.
    KnownFailure,
    /// Unknown effects. No retry-qualified clearance; the identity stays
    /// pending until an owner-authorized resolution exists for it.
    Uncertain,
    /// One evidence identity presented with different content, or with
    /// unordered/contradictory revisions. Nothing resolves and the conflict
    /// stays visible.
    ContradictoryRevisions,
}

impl ExecutionEffectState {
    /// Whether this state leaves the execution's effect unresolved, so its
    /// exact identity must be retained as pending rather than counted away.
    /// Only a committed result or a known failure is a settled effect state,
    /// and even a known failure settles nothing about retry safety: that is the
    /// original retry policy's decision.
    #[must_use]
    pub const fn leaves_effect_unresolved(self) -> bool {
        matches!(
            self,
            Self::Uncertain | Self::ContradictoryRevisions | Self::ObservedWithoutEffectDisposition
        )
    }
}

/// One execution's current state in the unique projection, with the exact
/// identity and content commitment the state was read from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDisposition {
    /// `execution_ref` the member is filed under.
    pub execution_ref: String,
    /// Exact identity and content commitment this state was read from.
    pub identity: ExecutionEvidenceIdentity,
    /// The current state, and what it means downstream.
    pub state: ExecutionEffectState,
}

/// A count that depends on a denominator no owner established.
///
/// Absence of the owner is reported as its own state and never as `0`: a zero
/// expected count would read as a complete set, which is exactly the inference
/// this assessment refuses to make from a submitted page.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentCount {
    /// No owner established the set this count is measured against.
    NotEstablished,
    /// The owner-issued set established the count.
    Counted(u64),
}

/// Upper bound on the per-execution dispositions one assessment carries.
///
/// An assessment is actionable evidence, not a history dump: it is bounded by
/// one bounded ingest window (the Skill transport admits at most 256 execution
/// records per page) and holds nothing between calls.
/// `disposition_count` always carries the exact total, so a truncated list is
/// visible to the receiver instead of being silently short.
pub const MAX_ASSESSMENT_DISPOSITIONS: usize = 256;

/// What one assessment was actually computed over.
///
/// The scope is never a completeness claim: completeness is decided by the
/// expected set and the coverage, and a page-local scope can never be shown to
/// cover an attempt. Page statistics and attempt-wide statistics are separate
/// fields and are never conflated.
///
/// The discriminator is read off the OWNER'S OWN window, never asserted: a
/// window that holds records this ingest did not contribute is retained
/// history, and one that holds only what this page contributed is reported as
/// the page it is. The uncertain direction is the fail-closed one — an owner
/// that retains by replay can look identical to one that retains nothing, and
/// this label then under-claims rather than over-claims.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum AssessmentScope {
    /// Exactly the submitted ingest page: the owner returned nothing beyond
    /// what this ingest contributed, so no retained history is behind it. A
    /// genuine B-only page is this — it says nothing about an execution an
    /// owner would hold from an earlier page, and it can never clear one.
    SubmittedPage {
        /// Closed source and revision the window was read at.
        source_revision: SourceRevision,
        /// Records this submitted page carried.
        page_records: u64,
    },
    /// The window the lifecycle owner returned after accepting this ingest, and
    /// it holds records this ingest did not contribute: the retained set the
    /// owner merged the page into, read at this owner revision.
    OwnerRetainedWindow {
        /// Closed source and revision the owner returned the window at.
        source_revision: SourceRevision,
        /// Attempt-wide records in the window the owner returned.
        window_records: u64,
        /// Records this ingest contributed to that window (page statistics).
        page_records: u64,
    },
}

/// The owner-issued expected execution/effect set an assessment is measured
/// against, or the honest state that no owner issued one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ExpectedExecutionSet {
    /// No owner issued an expected set for this attempt, so the denominator is
    /// NOT ESTABLISHED. This is the honest state, not a defect to be papered
    /// over with a plausible count: `expected`/`missing` below stay
    /// `NotEstablished`, and no window — not even one whose pending list is
    /// empty — may be reported as a complete set (I7.25: silence about
    /// adherence is unknown, not compliance).
    NotEstablished {
        /// What the assessment looked to for the set, so the gap is named
        /// instead of left implicit.
        owner: String,
    },
    /// The owner-issued set, read at the revision it was read at: the exact
    /// expected execution/effect members, finite.
    ///
    /// An empty `members` list here is a LEGITIMATE OWNER-PROVEN EMPTY SET and
    /// is categorically different from an invalid empty input page, which the
    /// transport refuses before any assessment exists.
    Issued {
        /// Owner revision the set was read at.
        source_revision: SourceRevision,
        /// Exact expected execution/effect identities the owner issued.
        members: Vec<String>,
    },
}

/// What the evidence alone establishes about the executions it names.
///
/// Every state here is EVIDENCE. None of them is an execution permit, and the
/// only two that look permissive are deliberately weaker than a permit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearanceState {
    /// No retry-qualified clearance. The exact unresolved identities and the
    /// recovery action are retained; nothing is executed on this evidence.
    NotCleared,
    /// Every NAMED execution resolves to an exact committed result: reconcile
    /// and return the ORIGINAL results. That effect is not executed again —
    /// this replays a recorded result and grants no authority.
    CommittedResultsToReplay,
    /// Every NAMED execution is a known failure with no recorded effect. This
    /// is ELIGIBLE FOR THE EXISTING SAME-IDENTITY RETRY GATE and nothing
    /// more: the original retry policy and its existing gate decide whether the
    /// attempt may run. It is NOT an independently issued execution permit,
    /// and a status alone is not retry safety.
    EligibleForSameIdentityRetryGate,
}

/// Why no retry-qualified clearance follows, so the receiver gets an actionable
/// recovery action instead of a bare count.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClearanceBlocker {
    /// An execution's effects are unknown. The exact identities are in
    /// `dispositions`: I14.21 pauses Ordering Scope and preserves the
    /// operation, and a Human/Doctor chooses the evidence-backed
    /// reconciliation. No blind duplicate effect.
    UncertainEffect,
    /// An observed status without a complete effect disposition. No retry
    /// safety is inferred from the status alone.
    IncompleteEffectDisposition,
    /// One evidence identity carried different content, or unordered
    /// contradictory revisions. Nothing resolves until the owner issues an
    /// authoritative resolution.
    ContradictoryRevisions,
    /// The evidence window behind this assessment was not obtained completely.
    IncompleteCoverage,
    /// No owner issued the expected set, so this set cannot be shown complete
    /// even when nothing is pending.
    ExpectedSetNotEstablished,
    /// The owner-issued set names expected members this window did not
    /// evidence.
    MissingExpectedMembers,
    /// The evidence set is completely resolved, but the policy/lease/authority
    /// that may admit execution is not established here: evidence may be
    /// complete while execution remains denied.
    AuthorityNotEstablished,
}

/// The explicit reconciliation verdict for one bounded evidence window
/// (issue #1191 / #2664, I7.25 / I14.21).
///
/// It replaces a page-local retry boolean. A submitted page is an OBSERVATION,
/// never a denominator: without an owner-issued expected execution/effect set
/// the set cannot be shown complete, so a page with no uncertain member
/// reports [`ClearanceState::NotCleared`] with
/// [`ClearanceBlocker::ExpectedSetNotEstablished`] rather than a permission.
/// Silence about unresolved effects is unknown, never compliance (I7.25:28),
/// and an aggregate count never substitutes for the exact record behind it
/// (I7.25:38) — hence the per-execution dispositions beside the counts.
///
/// The verdict is evidence for the existing retry/admission gate. It never
/// creates a permission: a committed result replays the ORIGINAL result, and a
/// known failure is only routed to the EXISTING same-identity retry gate,
/// which the original retry policy still owns.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnknownEffectsVerdict {
    /// What this assessment was computed over.
    pub scope: AssessmentScope,
    /// The owner-issued expected set, or the honest not-established state.
    pub expected_set: ExpectedExecutionSet,
    /// Expected member count, or `NotEstablished` when no owner issued one.
    pub expected: AssessmentCount,
    /// Expected members this window did not evidence, or `NotEstablished`.
    /// Never derived from a short last page: a count is established only from
    /// a settled read.
    pub missing: AssessmentCount,
    /// Distinct executions whose current state is an observed outcome.
    pub observed: u64,
    /// Distinct executions whose current state is a known failure.
    pub failed: u64,
    /// Distinct executions whose effects are still unknown.
    pub uncertain: u64,
    /// How completely the window behind this assessment was obtained.
    pub coverage: EvidenceCoverage,
    /// Per-execution current-state disposition, bounded by
    /// [`MAX_ASSESSMENT_DISPOSITIONS`]; `disposition_count` is always the
    /// exact total, so a truncated list is visible.
    pub dispositions: Vec<ExecutionDisposition>,
    /// Exact number of distinct executions in the projection.
    pub disposition_count: u64,
    /// Exact number of dispositions whose effect is unresolved, even when the
    /// carried list is truncated.
    pub pending_count: u64,
    /// What the evidence establishes, and why nothing more follows.
    pub clearance: ReconciliationClearance,
}

/// The explicit assessment: the state the evidence establishes plus the
/// blocker that keeps a permission from following.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationClearance {
    /// What the evidence alone establishes.
    pub state: ClearanceState,
    /// The primary reason no retry-qualified clearance follows. `None` only
    /// when `state` already states a resolved, non-permissive path.
    pub blocker: Option<ClearanceBlocker>,
}

impl UnknownEffectsVerdict {
    pub fn validate(&self) -> Result<(), SkillError> {
        match (self.clearance.state, self.clearance.blocker) {
            (ClearanceState::NotCleared, None) => {
                return Err(SkillError::InvalidField {
                    field: "verdict.clearance",
                    reason: "a verdict that clears nothing must name its blocker",
                });
            }
            (state, Some(_)) if state != ClearanceState::NotCleared => {
                return Err(SkillError::InvalidField {
                    field: "verdict.clearance",
                    reason: "a resolved path carries no clearance blocker",
                });
            }
            _ => {}
        }
        unique(
            self.dispositions
                .iter()
                .map(|disposition| disposition.execution_ref.clone()),
            "verdict.dispositions",
        )?;
        for disposition in &self.dispositions {
            text(
                &disposition.execution_ref,
                "verdict.disposition.execution_ref",
            )?;
            text(
                &disposition.identity.evidence_ref,
                "verdict.disposition.evidence_ref",
            )?;
            digest(
                &disposition.identity.content_digest,
                "verdict.disposition.content_digest",
            )?;
        }
        if self.dispositions.len() > MAX_ASSESSMENT_DISPOSITIONS
            || u64::try_from(self.dispositions.len()).unwrap_or(u64::MAX) > self.disposition_count
            || self.pending_count > self.disposition_count
            || self.observed + self.failed + self.uncertain > self.disposition_count
        {
            return Err(SkillError::InvalidField {
                field: "verdict.dispositions",
                reason: "dispositions cannot outrun the exact projected totals",
            });
        }
        if let ExpectedExecutionSet::Issued { members, .. } = &self.expected_set {
            unique(members.iter().cloned(), "verdict.expected_set.members")?;
            for member in members {
                text(member, "verdict.expected_set.member")?;
            }
        }
        Ok(())
    }
}

/// The one bounded evidence window an assessment is computed over.
///
/// `window` is the evidence the caller obtained from its owner — the retained
/// attempt-wide set when one exists, otherwise exactly the submitted page —
/// and `scope` names which of the two it is, so a page is never read as an
/// attempt. `expected_set` is the denominator, or the honest
/// not-established state; `coverage` is how completely the window itself was
/// obtained, never whether the ATTEMPT is complete.
pub struct ExecutionAssessmentWindow<'a> {
    /// The evidence records the projection reads.
    pub window: &'a [SkillExecutionEvidence],
    /// What this window is.
    pub scope: AssessmentScope,
    /// The owner-issued expected set, or the honest not-established state.
    pub expected_set: ExpectedExecutionSet,
    /// How completely the window was obtained.
    pub coverage: EvidenceCoverage,
}

/// The ONE unique current-state projection of an evidence window, computed
/// before any counter is derived. Every counter in this module — the
/// reconciliation verdict and the lifecycle counters alike — reads it, so the
/// two can no longer disagree about duplicates (I7.25: an aggregate count
/// never substitutes for the exact record behind it).
///
/// A member is one exact evidence identity. Identical records (same identity
/// and same content commitment) fold idempotently whatever their outcome, so an
/// exact replay of Observed, Failed or Uncertain behaves identically and
/// inflates nothing. The same identity with different content is a conflict:
/// nothing orders two contradictory revisions on caller input, so neither
/// supersedes the other and both stay visible.
struct ExecutionProjection {
    members: Vec<ExecutionDisposition>,
}

impl ExecutionProjection {
    fn project(window: &[SkillExecutionEvidence]) -> Result<Self, SkillError> {
        let mut members: Vec<ExecutionDisposition> = Vec::new();
        for execution in window {
            execution.validate()?;
            let evidence_ref = execution.execution_ref.clone();
            let content_digest = execution_content_digest(execution)?;
            match members
                .iter_mut()
                .find(|member| member.execution_ref == evidence_ref)
            {
                Some(member) if member.identity.content_digest == content_digest => {}
                Some(member) => member.state = ExecutionEffectState::ContradictoryRevisions,
                None => members.push(ExecutionDisposition {
                    execution_ref: evidence_ref,
                    identity: ExecutionEvidenceIdentity {
                        evidence_ref: execution.execution_ref.clone(),
                        content_digest,
                    },
                    state: effect_state(execution),
                }),
            }
        }
        Ok(Self { members })
    }

    fn count(&self, states: &[ExecutionEffectState]) -> u64 {
        self.members
            .iter()
            .filter(|member| states.contains(&member.state))
            .count() as u64
    }

    /// Lifecycle counters over the unique current state. `executed` counts
    /// executions with an observed outcome and `verified` those whose effect
    /// disposition is complete (a verifier run over the observed effect), so
    /// one execution can never be counted twice.
    fn counts(&self) -> ExecutionFold {
        let committed = [ExecutionEffectState::CommittedResult];
        let observed = [
            ExecutionEffectState::CommittedResult,
            ExecutionEffectState::ObservedWithoutEffectDisposition,
        ];
        ExecutionFold {
            executed: self.count(&observed),
            verified: self.count(&committed),
            failed: self.count(&[ExecutionEffectState::KnownFailure]),
            uncertain: self.count(&[ExecutionEffectState::Uncertain]),
        }
    }

    /// Expected and missing member counts, measured against the OWNER-issued
    /// set only and only from a settled read: a truncated page cannot prove
    /// that an expected member is absent, and no owner-issued set leaves both
    /// counts not established rather than zero.
    fn expected_counts(
        &self,
        assessment: &ExecutionAssessmentWindow<'_>,
    ) -> (AssessmentCount, AssessmentCount) {
        let issued = match &assessment.expected_set {
            ExpectedExecutionSet::Issued { members, .. } => Some(members),
            ExpectedExecutionSet::NotEstablished { .. } => None,
        };
        match issued {
            Some(members) if assessment.coverage.is_settled() => {
                let unevidenced = members
                    .iter()
                    .filter(|member| {
                        !self
                            .members
                            .iter()
                            .any(|observed| &&observed.execution_ref == member)
                    })
                    .count();
                (
                    AssessmentCount::Counted(members.len() as u64),
                    AssessmentCount::Counted(unevidenced as u64),
                )
            }
            _ => (
                AssessmentCount::NotEstablished,
                AssessmentCount::NotEstablished,
            ),
        }
    }

    /// The explicit clearance this projection supports, decided fail-closed in
    /// a fixed order: an unresolved effect first, then incomplete coverage,
    /// then the two paths the evidence alone can state, then the denominator.
    fn clearance(
        &self,
        assessment: &ExecutionAssessmentWindow<'_>,
        missing: AssessmentCount,
    ) -> ReconciliationClearance {
        let not_cleared = |blocker| ReconciliationClearance {
            state: ClearanceState::NotCleared,
            blocker: Some(blocker),
        };
        let unresolved = self
            .members
            .iter()
            .map(|member| member.state)
            .find(|state| state.leaves_effect_unresolved());
        if let Some(state) = unresolved {
            return match state {
                ExecutionEffectState::ContradictoryRevisions => {
                    not_cleared(ClearanceBlocker::ContradictoryRevisions)
                }
                ExecutionEffectState::Uncertain => not_cleared(ClearanceBlocker::UncertainEffect),
                _ => not_cleared(ClearanceBlocker::IncompleteEffectDisposition),
            };
        }
        if !assessment.coverage.is_settled() {
            return not_cleared(ClearanceBlocker::IncompleteCoverage);
        }
        // Both remaining positive paths are bounded to the NAMED dispositions
        // and claim nothing about members no owner has enumerated: an exact
        // committed result is replayed, never executed again, and a known
        // failure is only routed to the existing same-identity retry gate.
        let named = !self.members.is_empty();
        if named
            && self
                .members
                .iter()
                .all(|member| member.state == ExecutionEffectState::CommittedResult)
        {
            return ReconciliationClearance {
                state: ClearanceState::CommittedResultsToReplay,
                blocker: None,
            };
        }
        if named
            && self
                .members
                .iter()
                .all(|member| member.state == ExecutionEffectState::KnownFailure)
        {
            return ReconciliationClearance {
                state: ClearanceState::EligibleForSameIdentityRetryGate,
                blocker: None,
            };
        }
        match &assessment.expected_set {
            ExpectedExecutionSet::NotEstablished { .. } => {
                not_cleared(ClearanceBlocker::ExpectedSetNotEstablished)
            }
            ExpectedExecutionSet::Issued { .. } if matches!(missing, AssessmentCount::Counted(count) if count > 0) => {
                not_cleared(ClearanceBlocker::MissingExpectedMembers)
            }
            // Every named execution is resolved and the issued set is fully
            // evidenced; execution is still denied here, because the
            // policy/lease/authority owner — not this evidence — admits it.
            ExpectedExecutionSet::Issued { .. } => {
                not_cleared(ClearanceBlocker::AuthorityNotEstablished)
            }
        }
    }
}

/// Digest over one record's own canonical content: the content commitment a
/// replay is recognised by. It is compared against the ORIGINAL recorded value
/// of the member it belongs to, never recomputed over a substituted record.
fn execution_content_digest(execution: &SkillExecutionEvidence) -> Result<String, SkillError> {
    let bytes = canonical_json_bytes(execution)
        .map_err(|error| SkillError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// The current effect state of one record. An observed effect WITH a verifier
/// run over it is a committed result; an observed status without one has an
/// incomplete effect disposition. A failure is a known status, and an
/// uncertain record has unknown effects.
fn effect_state(execution: &SkillExecutionEvidence) -> ExecutionEffectState {
    match execution.outcome {
        ExecutionOutcome::Observed if !execution.verifier_refs.is_empty() => {
            ExecutionEffectState::CommittedResult
        }
        ExecutionOutcome::Observed => ExecutionEffectState::ObservedWithoutEffectDisposition,
        ExecutionOutcome::Failed => ExecutionEffectState::KnownFailure,
        ExecutionOutcome::Uncertain => ExecutionEffectState::Uncertain,
    }
}

/// Reconciles the evidence window into one explicit assessment before retry
/// (issue #1191 / #2664, I7.25 / I14.21).
///
/// ONE current-state projection is computed first ([`ExecutionProjection`]),
/// and every count below is read from it, so a duplicate, a superseded record
/// and a lifecycle counter can no longer disagree. The projection is the
/// authoritative current state, and the input-ordering question it refuses to
/// answer is refused here too: a second record under one identity with
/// different content is a conflict, never a supersession, because nothing in
/// the evidence a caller presents orders two revisions. The verdict then states
/// what the evidence establishes and what it does not:
///
/// * a contradictory identity, an uncertain effect, an observed status without
///   a complete effect disposition, incomplete coverage or an unestablished
///   expected set clears nothing, and the exact unresolved identities are
///   retained;
/// * an exact committed effect is reconciled and its ORIGINAL result returned,
///   never executed again;
/// * a known failure is routed to the EXISTING same-identity retry gate, which
///   the original retry policy still owns — this is not an execution permit;
/// * a complete resolved set still leaves execution denied unless the
///   policy/lease/authority owner admits it.
///
/// Completion is never inferred from a short last page, a record count, an
/// empty pending list, or the caller's word: without an owner-issued expected
/// set, `expected`/`missing` stay [`AssessmentCount::NotEstablished`] and the
/// verdict cannot report a complete set.
///
/// This is the same projection [`fold_execution_evidence`] counts, and it is
/// the authoritative one: where a view's own validation disagrees — because it
/// recomputes its counters from raw records rather than from the projection —
/// `fold_execution_evidence` documents exactly which inputs disagree and what a
/// caller now sees.
pub fn reconcile_unknown_effects(
    assessment: ExecutionAssessmentWindow<'_>,
) -> Result<UnknownEffectsVerdict, SkillError> {
    let projection = ExecutionProjection::project(assessment.window)?;
    let counts = projection.counts();
    let disposition_count = projection.members.len() as u64;
    let pending_count = projection
        .members
        .iter()
        .filter(|member| member.state.leaves_effect_unresolved())
        .count() as u64;
    let (expected, missing) = projection.expected_counts(&assessment);
    let clearance = projection.clearance(&assessment, missing);
    let verdict = UnknownEffectsVerdict {
        scope: assessment.scope,
        expected_set: assessment.expected_set,
        expected,
        missing,
        observed: counts.executed,
        failed: counts.failed,
        uncertain: counts.uncertain,
        coverage: assessment.coverage,
        dispositions: projection
            .members
            .iter()
            .take(MAX_ASSESSMENT_DISPOSITIONS)
            .cloned()
            .collect(),
        disposition_count,
        pending_count,
        clearance,
    };
    verdict.validate()?;
    Ok(verdict)
}

/// Counts the executions in the ONE unique current-state projection of an
/// evidence window; observed executions with a verifier run over the effect
/// count as verified. Causal credit is never a sole-cause claim: evidence
/// validation accepts only the distributed, uncertain or associated
/// representations, each bound to exact step refs. This is the counter fold
/// behind [`derive_lifecycle_view`] and behind
/// [`reconcile_unknown_effects`], which read the same projection, so an exact
/// replay cannot inflate one counter and not the other.
///
/// ## The projection is authoritative, and where it disagrees with the view
///
/// A member here is one exact evidence identity, so a window carrying the same
/// record twice counts it once, and a window carrying two different records
/// under one identity counts neither (the identity is
/// [`ExecutionEffectState::ContradictoryRevisions`], not a guess about which
/// revision wins). [`SkillLifecycleView::validate`] still recomputes its
/// execution counters by counting RAW records in the view's own
/// `execution_evidence` slice. The two therefore disagree for exactly two
/// inputs, and both are refused rather than published:
///
/// * a window with two different records under one identity derives counters
///   that the view rejects — a contradiction can no longer be published as a
///   settled count, which is the point;
/// * a window with the SAME record twice also derives counters the view
///   rejects, where it previously derived an inflated `executed`. Before this
///   projection existed, a duplicate inflated a published counter; now the
///   view refuses the window instead.
///
/// Every in-tree caller already deduplicates before folding:
/// `SkillRegistry::record_execution_evidence` keeps one record per evidence
/// identity and refuses a changed one as
/// [`SkillError::RevisionConflict`], which is the only production path into
/// [`derive_lifecycle_view`]. A caller that hands duplicates to the public
/// [`derive_lifecycle_view`] / `derive_and_record` entry points now gets an
/// `Err` instead of inflated counters — the fail-closed direction, and the
/// only behavioural change this projection makes.
pub fn fold_execution_evidence(
    executions: &[SkillExecutionEvidence],
) -> Result<ExecutionFold, SkillError> {
    Ok(ExecutionProjection::project(executions)?.counts())
}

/// Folds validated conflicts involving one skill into its interaction view:
/// conflict id, preserved first-skill ordering, rival id on mutual exclusion.
/// Packet order is never read; conflicts that name neither skill are skipped.
fn fold_interaction_evidence(
    skill_id: &str,
    conflicts: &[InstructionConflict],
) -> Result<SkillInteractionView, SkillError> {
    let mut interactions = SkillInteractionView::default();
    for conflict in conflicts {
        conflict.validate()?;
        if conflict.skill_a_id != skill_id && conflict.skill_b_id != skill_id {
            continue;
        }
        if !interactions.conflict_refs.contains(&conflict.conflict_id) {
            interactions
                .conflict_refs
                .push(conflict.conflict_id.clone());
        }
        if !interactions
            .ordering_refs
            .contains(&conflict.first_skill_id)
        {
            interactions
                .ordering_refs
                .push(conflict.first_skill_id.clone());
        }
        if conflict.mutual_exclusion {
            let rival = if conflict.skill_a_id == skill_id {
                &conflict.skill_b_id
            } else {
                &conflict.skill_a_id
            };
            if !interactions.mutual_exclusion_refs.contains(rival) {
                interactions.mutual_exclusion_refs.push(rival.clone());
            }
        }
    }
    Ok(interactions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LifecycleAction, LifecycleCounters, SkillInteractionView, SkillRef, SkillScope};
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn surface(error: String) -> SkillError {
        SkillError::Surface(error)
    }

    fn fence() -> Result<StateFence, SkillError> {
        let lineage =
            EpochLineageId::new(TEST_LINEAGE).map_err(|error| surface(error.to_string()))?;
        let sequence = NonZeroU64::new(1).ok_or(SkillError::InvalidField {
            field: "test.sequence",
            reason: "sequence must be non-zero",
        })?;
        let epoch = EpochId::new(lineage, sequence).map_err(|error| surface(error.to_string()))?;
        let generation = ResourceGeneration::new(1).map_err(|error| surface(error.to_string()))?;
        Ok(StateFence::new(epoch, generation))
    }

    fn packet_only_receipt(fence: &StateFence) -> SkillHarnessActivationReceipt {
        SkillHarnessActivationReceipt {
            receipt_id: "receipt-packet-only".to_owned(),
            skill_id: "skill-demo".to_owned(),
            skill_revision: "rev-1".to_owned(),
            package_digest: "a".repeat(64),
            attempt_ref: "attempt-1".to_owned(),
            route_ref: "route-1".to_owned(),
            state_fence: fence.clone(),
            packet_digest: "c".repeat(64),
            packet_position: 3,
            eligible: true,
            eligibility_reason: "task scope matches applies_when".to_owned(),
            retrieval: SkillRetrievalStatus::EligibleNotRetrieved,
            delivery: SkillDeliveryStatus::NotDelivered,
            activation: SkillActivationStatus::NotObserved,
            activation_observed_use_ref: None,
            activation_latency_ms: None,
            adherence: AdherenceCheckpoints::default(),
            conflict_or_suppression_refs: Vec::new(),
            downstream_refs: Vec::new(),
            verified_outcome_refs: Vec::new(),
        }
    }

    fn dependency(name: &str, version: &str, digest_char: char) -> DependencyVersion {
        DependencyVersion {
            name: name.to_owned(),
            version: version.to_owned(),
            contract_digest: std::iter::repeat_n(digest_char, 64).collect(),
        }
    }

    fn lifecycle_view(
        fence: &StateFence,
        dependencies: Vec<DependencyVersion>,
    ) -> Result<SkillLifecycleView, SkillError> {
        let skill_ref = SkillRef::new("skill-demo", "rev-1", "Demo Skill", "a".repeat(64))?;
        let view = SkillLifecycleView {
            skill_ref,
            scope: SkillScope {
                task_scope: "task-demo".to_owned(),
                host: "host-demo".to_owned(),
                route: "route-1".to_owned(),
                governance_scope: "gov-demo".to_owned(),
            },
            applies_when: vec!["task scope matches".to_owned()],
            does_not_apply_when: vec!["escalation requested".to_owned()],
            dependencies,
            counters: LifecycleCounters::default(),
            execution_evidence: Vec::new(),
            attempt_receipts: Vec::new(),
            observed_decision_or_verifier_delta: None,
            false_activation_refs: Vec::new(),
            interactions: SkillInteractionView::default(),
            status: SkillStatus::Current,
            stale_or_quarantine_reason: None,
            proposed_action: LifecycleAction::Keep,
            review: None,
            state_fence: fence.clone(),
            lifecycle_revision: 1,
        };
        view.validate()?;
        Ok(view)
    }

    #[test]
    fn packet_included_but_never_activated_is_not_useful() -> Result<(), SkillError> {
        let fence = fence()?;
        let receipt = packet_only_receipt(&fence);
        receipt.validate()?;
        let summary = derive_attempt_summary(&receipt);
        assert!(!summary.retrieved, "never retrieved");
        assert!(!summary.delivered, "never delivered");
        assert!(!summary.activated, "never activated");
        assert!(
            !summary.useful,
            "packet inclusion without activation is never useful"
        );
        assert_eq!(
            summary.adhered,
            SkillAdherenceStatus::Unknown,
            "absent adherence evidence stays unknown, never compliance"
        );
        Ok(())
    }

    #[test]
    fn tool_definition_change_marks_stale_and_blocks_material_use() -> Result<(), SkillError> {
        let pinned = vec![dependency("tool-search", "1.0.0", 'a')];
        let unchanged = vec![dependency("tool-search", "1.0.0", 'a')];
        assert!(
            detect_dependency_staleness(&pinned, &unchanged).is_none(),
            "identical versions stay fresh"
        );
        let current = vec![dependency("tool-search", "1.1.0", 'b')];
        let reason =
            detect_dependency_staleness(&pinned, &current).ok_or(SkillError::InvalidField {
                field: "test.staleness",
                reason: "a Tool Definition change must mark the Skill stale",
            })?;
        assert!(
            reason.contains("tool-search"),
            "stale reason names the changed dependency: {reason}"
        );
        assert!(
            !material_use_allowed(SkillStatus::Stale),
            "stale Skills are blocked from Material use until reviewed or restored"
        );
        assert!(
            !material_use_allowed(SkillStatus::Quarantined),
            "quarantined Skills are blocked from Material use"
        );
        assert!(
            material_use_allowed(SkillStatus::Current),
            "restored current Skills may return to Material use"
        );
        Ok(())
    }

    #[test]
    fn eligible_skill_cannot_carry_not_eligible_retrieval() -> Result<(), SkillError> {
        let fence = fence()?;
        let mut receipt = packet_only_receipt(&fence);
        receipt.retrieval = SkillRetrievalStatus::NotEligible;
        assert!(
            receipt.validate().is_err(),
            "an eligible Skill cannot carry a not-eligible retrieval"
        );
        receipt.eligible = false;
        receipt.validate()?;
        Ok(())
    }

    #[test]
    fn dependency_change_marks_view_stale_and_blocks_material_use() -> Result<(), SkillError> {
        let fence = fence()?;
        let pinned = vec![dependency("tool-search", "1.0.0", 'a')];
        let view = lifecycle_view(&fence, pinned)?;
        let unchanged = vec![dependency("tool-search", "1.0.0", 'a')];
        assert!(
            apply_dependency_staleness(&view, &unchanged)?.is_none(),
            "identical versions stay fresh"
        );
        let current = vec![dependency("tool-search", "1.1.0", 'b')];
        let Some(marked) = apply_dependency_staleness(&view, &current)? else {
            return Err(SkillError::InvalidField {
                field: "test.staleness",
                reason: "a Tool Definition change must mark the Skill stale",
            });
        };
        assert_eq!(marked.status, SkillStatus::Stale);
        let Some(reason) = marked.stale_or_quarantine_reason.clone() else {
            return Err(SkillError::InvalidField {
                field: "test.staleness",
                reason: "a stale Skill requires a reason",
            });
        };
        assert!(
            reason.contains("tool-search"),
            "stale reason names the changed dependency: {reason}"
        );
        assert_eq!(marked.lifecycle_revision, view.lifecycle_revision + 1);
        assert!(
            !material_use_allowed(marked.status),
            "stale Skills are blocked from Material use until reviewed or restored"
        );
        assert!(
            apply_dependency_staleness(&marked, &current)?.is_none(),
            "re-marking with the same reason is a no-op"
        );
        Ok(())
    }

    #[test]
    fn quarantine_reason_survives_dependency_drift() -> Result<(), SkillError> {
        let fence = fence()?;
        let mut view = lifecycle_view(&fence, vec![dependency("tool-search", "1.0.0", 'a')])?;
        view.status = SkillStatus::Quarantined;
        view.stale_or_quarantine_reason = Some("governed quarantine: adverse outcome".to_owned());
        view.validate()?;
        let current = vec![dependency("tool-search", "1.1.0", 'b')];
        assert!(
            apply_dependency_staleness(&view, &current)?.is_none(),
            "a quarantine reason changes only through governed review"
        );
        assert!(
            !material_use_allowed(view.status),
            "quarantined Skills stay blocked from Material use"
        );
        Ok(())
    }
    #[test]
    fn conflicting_skills_produce_instruction_conflict() -> Result<(), SkillError> {
        // Packet order lists skill-a first, but the explicit instruction order
        // runs skill-b first; the record preserves the explicit order.
        let conflict = record_instruction_conflict(
            "conflict-1".to_owned(),
            "skill-a".to_owned(),
            "skill-b".to_owned(),
            "contradictory stop conditions".to_owned(),
            "skill-b".to_owned(),
            OrderingBasis::ExplicitlySpecified,
            false,
        )?;
        assert_eq!(conflict.first_skill_id, "skill-b");
        assert_eq!(conflict.ordering_basis, OrderingBasis::ExplicitlySpecified);
        let reversed = record_instruction_conflict(
            "conflict-2".to_owned(),
            "skill-b".to_owned(),
            "skill-a".to_owned(),
            "contradictory stop conditions".to_owned(),
            "skill-b".to_owned(),
            OrderingBasis::Observed,
            true,
        )?;
        assert_eq!(reversed.first_skill_id, "skill-b");
        assert!(reversed.mutual_exclusion);
        assert!(
            record_instruction_conflict(
                "conflict-3".to_owned(),
                "skill-a".to_owned(),
                "skill-a".to_owned(),
                "self conflict".to_owned(),
                "skill-a".to_owned(),
                OrderingBasis::Observed,
                false,
            )
            .is_err(),
            "a Skill cannot conflict with itself"
        );
        Ok(())
    }
}
