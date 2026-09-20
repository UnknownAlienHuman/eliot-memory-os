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

use super::{DependencyVersion, SkillError, SkillStatus, digest, text, unique};

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
    /// unanimous silence stays `NotAssessed`, mixed silence stays `Unknown`.
    #[must_use]
    pub fn combined(self) -> SkillAdherenceStatus {
        use SkillAdherenceStatus::{Followed, NotAssessed, Partial, Unknown, Violated};
        let checkpoints = [self.early, self.mid, self.final_checkpoint];
        if checkpoints.contains(&Violated) {
            Violated
        } else if checkpoints.contains(&Partial) {
            Partial
        } else if checkpoints.iter().all(|status| *status == Followed) {
            Followed
        } else if checkpoints.iter().all(|status| *status == NotAssessed) {
            NotAssessed
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

/// Derived per-attempt lifecycle summary. `delivered`, `retrieved`,
/// `activated`, `adhered` and `useful` are distinct claims; a Skill included
/// in a packet but never retrieved or activated is never marked successful.
///
/// The four flags are independent lifecycle stages, not a ladder, so the
/// struct keeps them as plain booleans by design.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptLifecycleSummary {
    pub delivered: bool,
    pub retrieved: bool,
    pub activated: bool,
    pub adhered: SkillAdherenceStatus,
    pub useful: bool,
}

/// Derives the attempt summary from the exact receipt. Usefulness requires
/// observed activation, followed adherence and verifier-backed outcome
/// evidence; it is never inferred from installation, retrieval, repetition
/// or model agreement.
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
    let useful = activated
        && adhered == SkillAdherenceStatus::Followed
        && !receipt.verified_outcome_refs.is_empty();
    AttemptLifecycleSummary {
        delivered,
        retrieved,
        activated,
        adhered,
        useful,
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
    let indexed = |versions: &[DependencyVersion]| {
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
            .collect::<BTreeMap<_, _>>()
    };
    let pinned_map = indexed(pinned);
    let current_map = indexed(current);
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
    let indexed = |versions: &[DependencyVersion]| {
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
            .collect::<BTreeMap<_, _>>()
    };
    let pinned_map = indexed(pinned);
    let current_map = indexed(current);
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

#[cfg(test)]
mod tests {
    use super::*;
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
            SkillAdherenceStatus::NotAssessed,
            "absent adherence evidence stays unassessed, never compliance"
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
