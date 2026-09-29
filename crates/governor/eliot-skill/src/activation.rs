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

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};

use super::{
    DependencyVersion, ExecutionOutcome, LifecycleAction, LifecycleCounters,
    LiveSkillWorld, SkillCatalogueEntry, SkillError, SkillExecutionEvidence, SkillInteractionView,
    SkillLifecycleView, SkillRef, SkillScope, SkillStatus, digest, text, unique,
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
///   resolve to an owner record that itself validates, and
/// * that record's owner-stamped observation binding must name this exact
///   Skill, this exact subject attempt and this exact fence: a real verifier
///   record filed for an unrelated attempt, Skill or fence is insufficient
///   (issue #2663, I7.25/I12.24). A pre-binding row, which carries no stamp,
///   can never satisfy this leg.
///
/// Anything short of that reports [`SkillUsefulness::Unknown`] — never
/// `OwnerBacked`, and never a negative fact about the Skill. A foreign or
/// substituted outcome reference cannot produce a positive claim: a reference
/// the receipt never presented is ignored outright, a record failing its own
/// validation is discarded, and a record bound to another attempt, Skill or
/// fence stays unresolved for this receipt.
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
        // The reference must be one this receipt actually presented, the
        // record must be the one that reference resolved to, validated as
        // recorded, and its owner-stamped binding must name this exact Skill,
        // subject attempt and fence. A genuine record filed for another
        // attempt, Skill or fence — or a pre-binding row carrying no stamp —
        // cannot support this receipt's claim.
        receipt.verified_outcome_refs.contains(&candidate.reference)
            && candidate.record.execution_ref == candidate.reference
            && candidate.record.observed_skill_id.as_deref() == Some(receipt.skill_id.as_str())
            && candidate.record.observed_attempt_ref.as_deref()
                == Some(receipt.attempt_ref.as_str())
            && candidate.record.observed_fence.as_ref() == Some(&receipt.state_fence)
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

/// Material-use gate binding stored status to live dependency staleness.
///
/// The bridge activation path runs this before Material use: a Skill whose
/// stored status already blocks Material work is refused, and so is a Skill
/// whose pinned dependency versions disagree with the currently registered
/// versions — even when the stored status still reads `Current`, because the
/// change has not been recorded yet. Passage returns only for a usable
/// standing against the live set; a drifted Skill passes again only after
/// revalidation or explicit scoped/provisional admission through the
/// governed lifecycle path.
pub fn gate_material_use(
    status: SkillStatus,
    pinned: &[DependencyVersion],
    current: &[DependencyVersion],
) -> Result<(), SkillError> {
    if !material_use_allowed(status) {
        return Err(SkillError::InvalidField {
            field: "entry.status",
            reason: "stale or quarantined Skills are blocked from Material use until governed review or restore",
        });
    }
    if detect_dependency_staleness(pinned, current).is_some() {
        return Err(SkillError::InvalidField {
            field: "entry.dependencies",
            reason: "dependency versions changed since install; the Skill is stale until revalidated or explicitly scoped/provisional",
        });
    }
    Ok(())
}

/// Material-use gate binding every declared dependency leg to the observed
/// live world (`I7.13`, issue #1882 W2/A2).
///
/// [`gate_material_use`] covers stored status plus the dependency set; this
/// is the full-leg variant the bridge activation path runs before Material
/// use once it can supply the operation-observed live world: stored status,
/// the promotion-evidence binding for `Current`, the dependency set, the
/// host/profile versions, the admitted Tool Definition version, and the
/// declared tool basis rechecked against the tool owner's view. Any drift
/// refuses with its own typed field, so an unvalidated or stale Skill cannot
/// reach Material use through a stored-status lag; a drifted Skill passes
/// again only after revalidation or explicit scoped/provisional admission
/// through the governed lifecycle path. Evidence is compared, never
/// synthesized: every leg reads the caller-observed world.
///
/// # STITCH: designated Material-use caller
///
/// `caller: STITCH`. The designated caller is the bridge Material-use
/// admission drive (`skill_admit_material_attempt`) once it observes the live
/// dependency set and host/profile versions alongside the entry pins it
/// already reads; until then admission flows through `is_usable` plus the
/// dependency-set gate with the tool/definition legs enforced upstream.
pub fn gate_material_use_against(
    entry: &SkillCatalogueEntry,
    world: &LiveSkillWorld<'_>,
) -> Result<(), SkillError> {
    if !material_use_allowed(entry.status) {
        return Err(SkillError::InvalidField {
            field: "entry.status",
            reason: "stale or quarantined Skills are blocked from Material use until governed review or restore",
        });
    }
    if entry.status == SkillStatus::Current && entry.promotion_evidence.is_none() {
        return Err(SkillError::InvalidField {
            field: "entry.promotion_evidence",
            reason: "current Skills require bound promotion evidence; unvalidated Skills are blocked from Material use",
        });
    }
    if detect_dependency_staleness(&entry.dependencies, world.current_dependencies).is_some() {
        return Err(SkillError::InvalidField {
            field: "entry.dependencies",
            reason: "dependency versions changed since install; the Skill is stale until revalidated or explicitly scoped/provisional",
        });
    }
    if entry.host_version != world.live_host_version
        || entry.profile_version != world.live_profile_version
    {
        return Err(SkillError::InvalidField {
            field: "entry.host_version",
            reason: "host or profile versions changed since install; the Skill is stale until revalidated or explicitly scoped/provisional",
        });
    }
    if entry.admitted_definition_version != world.live_definition_version {
        return Err(SkillError::InvalidField {
            field: "entry.definition_version",
            reason: "tool definition version changed since install; the Skill is stale until revalidated or explicitly scoped/provisional",
        });
    }
    if entry
        .body
        .tool_refs
        .iter()
        .any(|tool| !world.tools.knows_tool(tool))
    {
        return Err(SkillError::InvalidField {
            field: "entry.tool_basis",
            reason: "declared tools changed since install; the Skill is stale until revalidated or explicitly scoped/provisional",
        });
    }
    Ok(())
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

/// Execution counters folded from exact step/artifact/verifier evidence.
/// Public so production evidence ingest (daemon execution drive) and the
/// lifecycle derivation fold through the same named counter type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionFold {
    /// Presented executions with a fully observed outcome.
    pub executed: u64,
    /// Observed executions carrying verifier refs.
    pub verified: u64,
    /// Presented executions with a known failed outcome.
    pub failed: u64,
    /// Presented executions with unknown effects.
    pub uncertain: u64,
}

/// Which set of executions one assessment's numbers describe (issue #2664).
///
/// Page statistics and attempt-wide statistics are different claims about
/// different sets, and collapsing them is the defect this split removes. A
/// bounded ingest page is an OBSERVATION about the Skill; the owner-retained
/// execution set is the attempt-wide position at exactly one owner revision.
/// A page with no `Uncertain` row therefore says nothing about the rest of the
/// attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionAssessmentScope {
    /// Numbers describe only the bounded page this ingest presented.
    PresentedPage,
    /// Numbers describe the owner-retained execution set for the subject
    /// Skill at the owner revision the assessment names.
    OwnerRetainedSet,
}

/// Maximum per-execution references one assessment publishes over the wire.
///
/// The transport's own ingest bound (`MAX_EXECUTION_RECORDS` in
/// `eliot-agent-bridge-core`) is unchanged by this work; this is the separate
/// bound on the evidence list the assessment itself carries. A longer
/// owner-retained set is cut here and REPORTED as cut
/// ([`ExecutionReconciliationAssessment::entries_truncated`]), never silently
/// shortened into a smaller claim.
pub const MAX_ASSESSMENT_REFS: usize = 256;

/// Closed source label for the owner-retained attempt-wide execution set an
/// assessment was decided over (issue #2664).
///
/// The lifecycle owner publishes a lifecycle revision for the retained set;
/// unlike the keyed immutable learning-record owner (issue #1868) it DOES
/// report one, so a revision is never synthesized to fill
/// [`SourceRevision::revision`].
pub const SOURCE_EXECUTION_OWNER_SET: &str = "execution_owner_retained_set";

/// Expected / observed / missing counts for one scope.
///
/// `expected` and `missing` are present only when an owner-issued expected
/// execution/effect set exists for the subject. They are `None` otherwise, and
/// are never derived from the presented page: a caller-provided record, a
/// `complete = true` self-claim, and a self-comparison of the page against
/// itself can never define a denominator (issue #2664).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSetCounts {
    /// Owner-issued expected execution/effect count for the scope. `None`
    /// when no owner issued one — the honest state, and never inferred from
    /// the presented page.
    pub expected: Option<u64>,
    /// Distinct executions in the scope whose current outcome is
    /// [`ExecutionOutcome::Observed`].
    pub observed: u64,
    /// Distinct executions in the scope whose current outcome is
    /// [`ExecutionOutcome::Failed`].
    pub failed: u64,
    /// Owner-issued expected count that the scope does not resolve. `None`
    /// whenever `expected` is `None`: without a denominator there is nothing
    /// to be missing from.
    pub missing: Option<u64>,
}

impl ExecutionSetCounts {
    pub fn validate(&self) -> Result<(), SkillError> {
        if self.missing.is_some() && self.expected.is_none() {
            return Err(SkillError::InvalidField {
                field: "counts.missing",
                reason: "a missing count requires an owner-issued expected count",
            });
        }
        Ok(())
    }
}

/// How completely the denominator behind one assessment is established.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentCompleteness {
    /// No owner-issued expected execution/effect set is available on this
    /// route, so the presented window is an observation and can never clear a
    /// retry. This is the fail-closed default and the only state reachable
    /// until the owner read contract lands.
    #[default]
    DenominatorUnestablished,
    /// The evidence list published here is a bounded window over a larger
    /// owner-retained set, so it is not the whole attempt.
    PartialWindow,
    /// An owner-issued expected set covers the whole attempt-wide window with
    /// no retention gap.
    Complete,
}

/// Per-execution disposition in the current projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionDisposition {
    /// The owner-retained record proves the effect committed. The result is
    /// replayed or observed, never re-executed.
    CommittedResultToReplay,
    /// The owner-retained record proves a KNOWN bounded effect, so no
    /// unresolved external state remains. This is the evidence the existing
    /// same-identity retry gate needs; it is not a grant of execution.
    KnownEffectRetryGateEligible,
    /// The current owner-retained outcome for this execution is still
    /// [`ExecutionOutcome::Uncertain`]; its effects are unresolved.
    UnresolvedEffect,
    /// Presented evidence disagreed with the owner-retained record under the
    /// same execution identity. A contradictory revision stays unresolved: a
    /// later position in a submitted page never wins.
    Conflict,
}

/// One execution's disposition, bound to its exact execution reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDispositionEntry {
    /// Exact execution reference this disposition names.
    pub execution_ref: String,
    /// Disposition decided from the owner-authorized position.
    pub disposition: ExecutionDisposition,
}

/// The assessment's own disposition, addressed to the retry/admission owner.
///
/// The assessment SUPPLIES EVIDENCE. It never grants execution, and
/// [`AssessmentDisposition::KnownEffectRetryEligible`] only reports that the
/// same-identity retry gate now has the evidence it requires.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssessmentDisposition {
    /// Incomplete / missing: the denominator is unestablished or the published
    /// window is partial, so these counts cannot clear a retry. Fail-closed
    /// default.
    #[default]
    IncompleteMissing,
    /// At least one execution's effects are unresolved; the exact pending
    /// references travel with this assessment.
    UnresolvedEffect,
    /// At least one execution's effect is committed and must be replayed
    /// rather than re-executed.
    CommittedResultToReplay,
    /// Resolved-but-not-authorized: the owner-retained set advanced with
    /// executions this subject's evidence did not present, so those
    /// resolutions are not authorized here.
    ResolvedNotAuthorized,
    /// Presented evidence contradicts the owner-retained revision.
    Conflict,
    /// Every execution in the projection resolved to a known effect, so no
    /// unresolved external state remains. Reachable ONLY when completeness is
    /// [`AssessmentCompleteness::Complete`]: without an owner-issued expected
    /// set this bucket is unreachable by construction.
    KnownEffectRetryEligible,
}

impl AssessmentDisposition {
    /// Stable code a receiver switches on to take a different downstream path.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::IncompleteMissing => "INCOMPLETE_EVIDENCE",
            Self::UnresolvedEffect => "UNRESOLVED_EFFECT",
            Self::CommittedResultToReplay => "COMMITTED_RESULT_REPLAY",
            Self::ResolvedNotAuthorized => "RESOLVED_NOT_AUTHORIZED",
            Self::Conflict => "EVIDENCE_CONFLICT",
            Self::KnownEffectRetryEligible => "RETRY_GATE_ELIGIBLE",
        }
    }
}

/// One observation of the owner-retained execution set for a subject Skill.
///
/// This is the owner's own position: the records it holds and the owner
/// revision it holds them at. It is built from the lifecycle view the owner
/// returns, so a caller cannot present a position the owner does not hold.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SkillExecutionOwnerPosition {
    /// Skill the retained set belongs to.
    pub skill_id: String,
    /// Owner revision (lifecycle revision) the retained set was read at.
    pub revision: u64,
    /// Owner-retained attempt-wide records, exactly as held.
    pub retained: Vec<SkillExecutionEvidence>,
}

impl SkillExecutionOwnerPosition {
    /// Reads one owner position off the lifecycle view the owner returned.
    #[must_use]
    pub fn from_lifecycle_view(view: &SkillLifecycleView) -> Self {
        Self {
            skill_id: view.skill_id().to_owned(),
            revision: view.lifecycle_revision,
            retained: view.execution_evidence.clone(),
        }
    }

    pub fn validate(&self) -> Result<(), SkillError> {
        text(&self.skill_id, "position.skill_id")?;
        if self.revision == 0 {
            return Err(SkillError::InvalidField {
                field: "position.revision",
                reason: "owner revision must be non-zero",
            });
        }
        for record in &self.retained {
            record.validate()?;
        }
        Ok(())
    }
}

/// The current projection one owner-authorized set yields, built BEFORE any
/// counter is derived (issue #2664, I7.25 / I14.21).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProjection {
    /// Per-execution disposition, in owner-retained order.
    pub dispositions: Vec<ExecutionDispositionEntry>,
    /// Exact execution references whose effects are unresolved, in
    /// owner-retained order. Never a count.
    pub pending_refs: Vec<String>,
    /// Presented references whose bytes contradicted the owner-retained
    /// record for the same execution identity.
    pub conflicting_refs: Vec<String>,
    /// Presented references the owner does not hold. These are observations
    /// with no owner position behind them, never absence of an execution.
    pub unowned_refs: Vec<String>,
}

impl ExecutionProjection {
    pub fn validate(&self) -> Result<(), SkillError> {
        let refs = self
            .dispositions
            .iter()
            .map(|entry| entry.execution_ref.clone());
        unique(refs, "projection.dispositions")?;
        for entry in &self.dispositions {
            text(&entry.execution_ref, "projection.disposition.execution_ref")?;
        }
        for (values, field) in [
            (&self.pending_refs, "projection.pending_refs"),
            (&self.conflicting_refs, "projection.conflicting_refs"),
            (&self.unowned_refs, "projection.unowned_refs"),
        ] {
            unique(values.iter().cloned(), field)?;
            for value in values {
                text(value, field)?;
            }
        }
        Ok(())
    }

    /// Distinct executions in the projection whose current outcome is
    /// `Observed` / `Failed`, and the exact unresolved reference list.
    fn counts(&self) -> (u64, u64) {
        let mut observed = 0_u64;
        let mut failed = 0_u64;
        for entry in &self.dispositions {
            match entry.disposition {
                ExecutionDisposition::CommittedResultToReplay => {
                    observed = observed.saturating_add(1);
                }
                ExecutionDisposition::KnownEffectRetryGateEligible => {
                    failed = failed.saturating_add(1);
                }
                ExecutionDisposition::UnresolvedEffect | ExecutionDisposition::Conflict => {}
            }
        }
        (observed, failed)
    }
}

/// Builds the current projection from the OWNER's retained set (issue #2664).
///
/// `retained` is the owner-retained attempt-wide set and `presented` is the
/// bounded page this ingest submitted. Three rules, all owner-authorized:
///
/// 1. every outcome class is deduplicated by exact evidence identity: one
///    `execution_ref` carrying the same bytes folds once, so a duplicate never
///    inflates a class;
/// 2. supersession comes only from the owner's own retained set. The former
///    positional "latest presented wins" fold is gone — where a page places a
///    record says nothing about which revision the owner holds, which is how
///    a B-only page used to clear a retained unresolved A;
/// 3. a presented record that disagrees with the retained record for the same
///    execution is a CONTRADICTORY revision: it is reported as a conflict and
///    that execution stays unresolved. Nothing is overwritten in either
///    direction, and a self-contradictory owner set is a typed
///    [`SkillError::RevisionConflict`] rather than a resolved guess.
///
/// Absent records stay absent: a projection over the presented page alone
/// describes that page and nothing else.
pub fn project_execution_outcomes(
    retained: &[SkillExecutionEvidence],
    presented: &[SkillExecutionEvidence],
) -> Result<ExecutionProjection, SkillError> {
    let mut owner: Vec<SkillExecutionEvidence> = Vec::with_capacity(retained.len());
    for record in retained {
        record.validate()?;
        match owner
            .iter()
            .position(|held| held.execution_ref == record.execution_ref)
        {
            // Same identity, same recorded content: a replay of the same
            // evidence. It folds once and never inflates a class. The
            // comparison excludes the owner-stamped filing binding, which
            // names the filing rather than the observation.
            Some(index) if owner[index].same_recorded_content(record) => {}
            // Same identity, changed recorded content: the retained set
            // disagrees with itself. A contradictory revision is never
            // resolved by position.
            Some(_) => return Err(SkillError::RevisionConflict),
            None => owner.push(record.clone()),
        }
    }
    let mut conflicting_refs = Vec::new();
    let mut unowned_refs = Vec::new();
    for record in presented {
        record.validate()?;
        match owner
            .iter()
            .find(|held| held.execution_ref == record.execution_ref)
        {
            Some(held) if held.same_recorded_content(record) => {}
            Some(_) => conflicting_refs.push(record.execution_ref.clone()),
            None => unowned_refs.push(record.execution_ref.clone()),
        }
    }
    let mut dispositions = Vec::with_capacity(owner.len());
    let mut pending_refs = Vec::new();
    for record in &owner {
        let disposition = if conflicting_refs.contains(&record.execution_ref) {
            ExecutionDisposition::Conflict
        } else {
            match record.outcome {
                ExecutionOutcome::Observed => ExecutionDisposition::CommittedResultToReplay,
                ExecutionOutcome::Failed => ExecutionDisposition::KnownEffectRetryGateEligible,
                ExecutionOutcome::Uncertain => ExecutionDisposition::UnresolvedEffect,
            }
        };
        if disposition == ExecutionDisposition::UnresolvedEffect {
            pending_refs.push(record.execution_ref.clone());
        }
        dispositions.push(ExecutionDispositionEntry {
            execution_ref: record.execution_ref.clone(),
            disposition,
        });
    }
    let projection = ExecutionProjection {
        dispositions,
        pending_refs,
        conflicting_refs,
        unowned_refs,
    };
    projection.validate()?;
    Ok(projection)
}

/// Subject identity one execution assessment is scoped to.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionAssessmentContext {
    /// Skill identity the executions belong to.
    pub skill_id: String,
    /// Skill revision the evidence was observed at.
    pub skill_revision: String,
    /// Package digest the evidence was observed at.
    pub package_digest: String,
    /// This ingest's own authenticated attempt id, never the Skill's
    /// historical attempt: the execution wire carries no subject attempt
    /// reference, so the ingest identity is the only attempt binding this
    /// route can state (I15.2).
    pub ingest_attempt_id: String,
    /// Load-bearing owner revisions the assessment depends on.
    pub source_revisions: Vec<SourceRevision>,
}

impl ExecutionAssessmentContext {
    pub fn validate(&self) -> Result<(), SkillError> {
        text(&self.skill_id, "assessment.skill_id")?;
        text(&self.skill_revision, "assessment.skill_revision")?;
        digest(&self.package_digest, "assessment.package_digest")?;
        text(&self.ingest_attempt_id, "assessment.ingest_attempt_id")?;
        for revision in &self.source_revisions {
            revision.validate()?;
        }
        Ok(())
    }
}

/// The bounded reconciliation assessment that replaces the bare retry flag
/// (issue #2664).
///
/// This is the production decision surface for the execute leg. It is an
/// assessment, not a permission: it carries the scope it covers, the
/// expected/observed/missing counts of BOTH the presented page and the
/// attempt-wide owner-retained set, how completely that denominator is
/// established, the owner revision the position was read at, a per-operation
/// disposition, and the EXACT references still pending — never a count in
/// place of them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReconciliationAssessment {
    /// The set the disposition below was decided over. Always
    /// [`ExecutionAssessmentScope::OwnerRetainedSet`]: dispositions are never
    /// decided from a page.
    pub scope: ExecutionAssessmentScope,
    /// Skill identity this assessment is scoped to.
    pub skill_id: String,
    /// Skill revision the evidence was observed at.
    pub skill_revision: String,
    /// Package digest the evidence was observed at.
    pub package_digest: String,
    /// This ingest's own authenticated attempt id.
    pub ingest_attempt_id: String,
    /// How completely the denominator is established.
    pub completeness: AssessmentCompleteness,
    /// The assessment's disposition for the retry/admission owner.
    pub disposition: AssessmentDisposition,
    /// Stable code matching [`ExecutionReconciliationAssessment::disposition`],
    /// so a receiver takes a different path per disposition.
    pub disposition_code: String,
    /// Statistics over the bounded page this ingest presented. Page numbers are
    /// never attempt-wide numbers.
    pub page_statistics: ExecutionSetCounts,
    /// Statistics over the attempt-wide owner-retained set at the owner
    /// revision named in `source_revisions`.
    pub attempt_statistics: ExecutionSetCounts,
    /// Per-operation disposition for every execution this page presented.
    pub page_dispositions: Vec<ExecutionDispositionEntry>,
    /// Exact execution references whose effects remain unresolved, cut at
    /// [`MAX_ASSESSMENT_REFS`] with `entries_truncated` set when longer.
    pub pending_refs: Vec<String>,
    /// True when `pending_refs` was cut at the bound. The DISPOSITION was
    /// still decided over the whole owner-retained set, so this bounds the
    /// published evidence list, not the decision.
    pub entries_truncated: bool,
    /// Owner-retained references that appeared between the read and the
    /// commit and that this ingest did not present. Non-empty means the
    /// clearance derived from the earlier read is stale.
    pub appeared_after_read_refs: Vec<String>,
    /// Presented references that contradicted the owner-retained revision.
    pub conflicting_refs: Vec<String>,
    /// Load-bearing owner revisions this assessment depends on.
    pub source_revisions: Vec<SourceRevision>,
}

impl ExecutionReconciliationAssessment {
    pub fn validate(&self) -> Result<(), SkillError> {
        ExecutionAssessmentContext {
            skill_id: self.skill_id.clone(),
            skill_revision: self.skill_revision.clone(),
            package_digest: self.package_digest.clone(),
            ingest_attempt_id: self.ingest_attempt_id.clone(),
            source_revisions: self.source_revisions.clone(),
        }
        .validate()?;
        if self.scope != ExecutionAssessmentScope::OwnerRetainedSet {
            return Err(SkillError::InvalidField {
                field: "assessment.scope",
                reason: "a reconciliation disposition is never decided from a presented page",
            });
        }
        self.page_statistics.validate()?;
        self.attempt_statistics.validate()?;
        if self.disposition_code != self.disposition.code() {
            return Err(SkillError::InvalidField {
                field: "assessment.disposition_code",
                reason: "disposition code does not match the disposition it names",
            });
        }
        let refs = self
            .page_dispositions
            .iter()
            .map(|entry| entry.execution_ref.clone());
        unique(refs, "assessment.page_dispositions")?;
        for entry in &self.page_dispositions {
            text(
                &entry.execution_ref,
                "assessment.page_disposition.execution_ref",
            )?;
        }
        for (values, field) in [
            (&self.pending_refs, "assessment.pending_refs"),
            (
                &self.appeared_after_read_refs,
                "assessment.appeared_after_read_refs",
            ),
            (&self.conflicting_refs, "assessment.conflicting_refs"),
        ] {
            unique(values.iter().cloned(), field)?;
            for value in values {
                text(value, field)?;
            }
        }
        if self.pending_refs.len() > MAX_ASSESSMENT_REFS
            || self.page_dispositions.len() > MAX_ASSESSMENT_REFS
        {
            return Err(SkillError::InvalidField {
                field: "assessment.pending_refs",
                reason: "assessment evidence list exceeds its bound",
            });
        }
        if self.entries_truncated && self.completeness == AssessmentCompleteness::Complete {
            return Err(SkillError::InvalidField {
                field: "assessment.entries_truncated",
                reason: "a truncated evidence list is never complete evidence",
            });
        }
        Ok(())
    }
}

/// Builds the bounded reconciliation assessment for one execution ingest
/// (issue #2664, I7.25 / I14.21).
///
/// `read_position` is the owner-retained set as it stood BEFORE the publish,
/// and `committed_position` is the set the owner actually holds AFTER it. The
/// audit recheck lives in the difference: an execution that appears in the
/// committed set, was absent from the read set, and was not presented here is
/// a new execution/effect that appeared between read and commit, so the
/// clearance derived from the read is stale and the disposition says so.
///
/// The denominator is NEVER taken from the page. `expected`/`missing` stay
/// `None` and completeness stays
/// [`AssessmentCompleteness::DenominatorUnestablished`] until an owner-issued
/// expected execution/effect set exists, so
/// [`AssessmentDisposition::KnownEffectRetryEligible`] is unreachable until
/// that read contract lands. The published window is
/// [`AssessmentCompleteness::PartialWindow`] whenever the evidence list had to
/// be cut, which also withholds retry eligibility.
pub fn assess_execution_reconciliation(
    context: ExecutionAssessmentContext,
    page: &[SkillExecutionEvidence],
    read_position: &SkillExecutionOwnerPosition,
    committed_position: &SkillExecutionOwnerPosition,
) -> Result<ExecutionReconciliationAssessment, SkillError> {
    context.validate()?;
    read_position.validate()?;
    committed_position.validate()?;
    if read_position.skill_id != context.skill_id || committed_position.skill_id != context.skill_id
    {
        return Err(SkillError::IdentityMismatch);
    }
    // The page projected over itself is page statistics and nothing more; the
    // disposition below never reads it.
    let page_projection = project_execution_outcomes(page, page)?;
    let attempt_projection = project_execution_outcomes(&committed_position.retained, page)?;
    let (page_observed, page_failed) = page_projection.counts();
    let (attempt_observed, attempt_failed) = attempt_projection.counts();
    let mut appeared_after_read_refs = Vec::new();
    for record in &committed_position.retained {
        let read_held = read_position
            .retained
            .iter()
            .any(|held| held.execution_ref == record.execution_ref);
        let presented = page_projection
            .dispositions
            .iter()
            .any(|entry| entry.execution_ref == record.execution_ref);
        if !read_held && !presented {
            appeared_after_read_refs.push(record.execution_ref.clone());
        }
    }
    let truncated = attempt_projection.pending_refs.len() > MAX_ASSESSMENT_REFS;
    let completeness = if truncated {
        AssessmentCompleteness::PartialWindow
    } else {
        AssessmentCompleteness::DenominatorUnestablished
    };
    let disposition = if !attempt_projection.conflicting_refs.is_empty() {
        AssessmentDisposition::Conflict
    } else if !appeared_after_read_refs.is_empty() {
        AssessmentDisposition::ResolvedNotAuthorized
    } else if !attempt_projection.pending_refs.is_empty() {
        AssessmentDisposition::UnresolvedEffect
    } else if completeness != AssessmentCompleteness::Complete {
        AssessmentDisposition::IncompleteMissing
    } else if attempt_observed > 0 {
        AssessmentDisposition::CommittedResultToReplay
    } else {
        AssessmentDisposition::KnownEffectRetryEligible
    };
    let mut pending_refs = attempt_projection.pending_refs.clone();
    pending_refs.truncate(MAX_ASSESSMENT_REFS);
    let assessment = ExecutionReconciliationAssessment {
        scope: ExecutionAssessmentScope::OwnerRetainedSet,
        skill_id: context.skill_id,
        skill_revision: context.skill_revision,
        package_digest: context.package_digest,
        ingest_attempt_id: context.ingest_attempt_id,
        completeness,
        disposition,
        disposition_code: disposition.code().to_owned(),
        page_statistics: ExecutionSetCounts {
            expected: None,
            observed: page_observed,
            failed: page_failed,
            missing: None,
        },
        attempt_statistics: ExecutionSetCounts {
            expected: None,
            observed: attempt_observed,
            failed: attempt_failed,
            missing: None,
        },
        page_dispositions: page_projection.dispositions,
        pending_refs,
        entries_truncated: truncated,
        appeared_after_read_refs,
        conflicting_refs: attempt_projection.conflicting_refs,
        source_revisions: context.source_revisions,
    };
    assessment.validate()?;
    Ok(assessment)
}

/// Counts presented execution records by outcome; observed executions with
/// verifier refs count as verified. Causal credit is never a sole-cause claim:
/// evidence validation accepts only the distributed, uncertain or associated
/// representations, each bound to exact step refs. This is the record-count
/// fold behind [`derive_lifecycle_view`]: unlike
/// [`project_execution_outcomes`], which deduplicates by exact evidence
/// identity over the OWNER's retained set before deriving any counter, it
/// counts every presented record, so the two agree exactly on duplicate-free
/// windows and intentionally differ when one execution carries repeated
/// records.
pub fn fold_execution_evidence(
    executions: &[SkillExecutionEvidence],
) -> Result<ExecutionFold, SkillError> {
    let mut fold = ExecutionFold {
        executed: 0,
        verified: 0,
        failed: 0,
        uncertain: 0,
    };
    for execution in executions {
        execution.validate()?;
        match execution.outcome {
            ExecutionOutcome::Observed => {
                fold.executed = fold.executed.saturating_add(1);
                if !execution.verifier_refs.is_empty() {
                    fold.verified = fold.verified.saturating_add(1);
                }
            }
            ExecutionOutcome::Failed => {
                fold.failed = fold.failed.saturating_add(1);
            }
            ExecutionOutcome::Uncertain => {
                fold.uncertain = fold.uncertain.saturating_add(1);
            }
        }
    }
    Ok(fold)
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
        assert_eq!(
            summary.useful,
            SkillUsefulness::Unknown,
            "unobserved activation has no owner-qualified usefulness finding"
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
