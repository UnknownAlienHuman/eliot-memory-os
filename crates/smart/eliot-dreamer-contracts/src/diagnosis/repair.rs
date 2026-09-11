//! Immutable `RepairLineage` declarations for `DevelopmentDiagnosis`.
//!
//! This module records a bounded, ordered history. It does not execute repairs,
//! group attempts, select mechanisms, infer causality, or require curation
//! failure history. Full product contexts remain separate from the structured
//! mechanism-equivalence projection.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, ContractId};
use eliot_evidence::{EvidenceCoverage, EvidenceEnvelope};
use eliot_receipts::ArtifactBinding;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::validation::{
    MAX_DIAGNOSIS_SEQUENCE_ITEMS, MAX_DIAGNOSIS_TEXT_BYTES, bounded_artifact_refs,
    bounded_contract_id, bounded_digest, bounded_text, canonical_stream_digest,
    preflight_canonical_stream,
};
use crate::{
    AttemptBinding, ContractViolation, ProductContext, UnavailableEvidence, UnavailableField,
    is_hex64_lower,
};

/// Wire revision for the repair-lineage declaration.
pub const REPAIR_LINEAGE_SCHEMA_VERSION: u16 = 2;

/// Whether the supplied history claims no prior repair or has incomplete
/// knowledge about prior repairs.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RepairHistoryPresence {
    ZeroPriorRepairs,
    OneOrMore,
    Unknown,
}

/// One of the nine diagnosis repair-lineage stage kinds.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RepairStageKind {
    Planned,
    Attempted,
    Applied,
    Built,
    Unit,
    Edge,
    Deployed,
    Observed,
    Rollback,
}

/// Typed outcome of an event slot, including explicit non-execution and
/// unresolved evidence states.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", deny_unknown_fields)]
pub enum RepairEventOutcome {
    NotExecuted {
        reason: String,
    },
    Succeeded {
        summary: String,
    },
    Failed {
        summary: String,
    },
    Partial {
        summary: String,
        unresolved: Vec<String>,
    },
    Unknown {
        reason: String,
    },
}

/// Typed declaration of whether the mechanism was exercised at an event.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind", deny_unknown_fields)]
pub enum MechanismExercise {
    NotExercised { reason: String },
    Exercised,
    PartiallyExercised { unresolved: Vec<String> },
    Unknown { reason: String },
}

/// A single load-bearing change retained in mechanism projection order.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBearingChange {
    pub dimension: String,
    pub before: String,
    pub after: String,
}

/// Identity of structured repair mechanism/change content.
///
/// `record_digest` covers the full record, while `equivalence_digest` covers
/// only load-bearing changes, preserved invariants, and operating conditions.
/// Cosmetic labels, mechanism identifiers, and product revisions therefore do
/// not make equivalent structured content novel.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MechanismProjection {
    pub mechanism_id: ContractId,
    pub display_label: String,
    pub product_revision: Option<String>,
    pub load_bearing_changes: Vec<LoadBearingChange>,
    pub preserved_invariants: Vec<String>,
    pub conditions: Vec<String>,
    pub record_digest: String,
    pub equivalence_digest: String,
}

impl MechanismProjection {
    /// Computes the digest over all declaration fields.
    pub fn canonical_record_digest(&self) -> Result<String, ContractViolation> {
        self.validate_content()?;
        self.validate_stored_digests()?;
        let preimage = MechanismRecordPreimage {
            mechanism_id: &self.mechanism_id,
            display_label: &self.display_label,
            product_revision: self.product_revision.as_deref(),
            load_bearing_changes: &self.load_bearing_changes,
            preserved_invariants: &self.preserved_invariants,
            conditions: &self.conditions,
            equivalence_digest: &self.equivalence_digest,
        };
        canonical_stream_digest(&preimage)
    }

    /// Computes the digest used to compare load-bearing mechanism content.
    pub fn canonical_equivalence_digest(&self) -> Result<String, ContractViolation> {
        self.validate_content()?;
        self.validate_stored_digests()?;
        let preimage = MechanismEquivalencePreimage {
            load_bearing_changes: &self.load_bearing_changes,
            preserved_invariants: &self.preserved_invariants,
            conditions: &self.conditions,
        };
        canonical_stream_digest(&preimage)
    }

    /// Returns this projection with both canonical digests populated.
    pub fn with_digests(mut self) -> Result<Self, ContractViolation> {
        self.validate_content()?;
        self.validate_stored_digests()?;
        self.equivalence_digest = self.canonical_equivalence_digest()?;
        self.record_digest = self.canonical_record_digest()?;
        Ok(self)
    }

    /// Checks bounded intrinsic mechanism content and both supplied digests.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_content()?;
        bounded_digest(&self.record_digest, "repair.mechanism.record_digest")?;
        bounded_digest(
            &self.equivalence_digest,
            "repair.mechanism.equivalence_digest",
        )?;
        if self.equivalence_digest != self.canonical_equivalence_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.mechanism.equivalence_digest",
                reason: "supplied mechanism equivalence digest does not match canonical bytes"
                    .to_owned(),
            });
        }
        if self.record_digest != self.canonical_record_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.mechanism.record_digest",
                reason: "supplied mechanism record digest does not match canonical bytes"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn validate_content(&self) -> Result<(), ContractViolation> {
        preflight_canonical_stream(self)?;
        bounded_contract_id(&self.mechanism_id, "repair.mechanism.mechanism_id")?;
        bounded_text(
            &self.display_label,
            "repair.mechanism.display_label",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        if let Some(revision) = &self.product_revision {
            bounded_text(
                revision,
                "repair.mechanism.product_revision",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
        }
        if self.load_bearing_changes.is_empty()
            || self.load_bearing_changes.len() > MAX_DIAGNOSIS_SEQUENCE_ITEMS
        {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.mechanism.load_bearing_changes",
                min: 1,
                max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
                got: i64::try_from(self.load_bearing_changes.len()).unwrap_or(i64::MAX),
            });
        }
        let mut dimensions = BTreeSet::new();
        for change in &self.load_bearing_changes {
            bounded_text(
                &change.dimension,
                "repair.mechanism.change.dimension",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
            bounded_text(
                &change.before,
                "repair.mechanism.change.before",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
            bounded_text(
                &change.after,
                "repair.mechanism.change.after",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
            if change.before == change.after {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.mechanism.change",
                    reason: "load-bearing change cannot declare a no-op".to_owned(),
                });
            }
            if !dimensions.insert(change.dimension.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.mechanism.change.dimension",
                    reason: "load-bearing change dimensions must be unique".to_owned(),
                });
            }
        }
        validate_text_set(
            &self.preserved_invariants,
            "repair.mechanism.preserved_invariants",
        )?;
        validate_text_set(&self.conditions, "repair.mechanism.conditions")
    }

    fn validate_stored_digests(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.record_digest, "repair.mechanism.record_digest"),
            (
                &self.equivalence_digest,
                "repair.mechanism.equivalence_digest",
            ),
        ] {
            if !value.is_empty() && !is_hex64_lower(value) {
                return Err(ContractViolation::Malformed {
                    field,
                    reason: "digest must be empty or lowercase SHA-256".to_owned(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct MechanismRecordPreimage<'a> {
    mechanism_id: &'a ContractId,
    display_label: &'a str,
    product_revision: Option<&'a str>,
    load_bearing_changes: &'a [LoadBearingChange],
    preserved_invariants: &'a [String],
    conditions: &'a [String],
    equivalence_digest: &'a str,
}

#[derive(Serialize)]
struct MechanismEquivalencePreimage<'a> {
    load_bearing_changes: &'a [LoadBearingChange],
    preserved_invariants: &'a [String],
    conditions: &'a [String],
}

/// Closed reason for retaining a repeated or controlled repair attempt.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RepeatReason {
    StochasticReplication,
    NoiseEstimation,
    ExactDefectReproduction,
    ControlledComparison,
    RecoveryProof,
    VerifierCalibration,
}

/// Bounded, evidence-backed justification for a controlled repeat.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepeatJustification {
    pub reason: RepeatReason,
    /// Identifier of the earlier attempt that makes this repeat meaningful.
    pub prior_attempt_id: String,
    /// Optional zero-based event slot in `prior_attempt_id` being repeated.
    pub prior_event_slot: Option<u32>,
    pub explanation: String,
    pub evidence_refs: Vec<ArtifactId>,
}

/// One retained attempt, with its own binding and ordered event slots.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairAttemptRecord {
    pub attempt: AttemptBinding,
    /// Number of event slots declared for this attempt. Event slots are
    /// zero-based and may be represented by `Missing` entries.
    pub expected_event_slots: u32,
    pub events: Vec<RepairEventEntry>,
    pub controlled_repeat: Option<RepeatJustification>,
    /// Direct supporting citations, not an exhaustive transitive denominator.
    pub new_information_refs: Vec<ArtifactId>,
    /// Direct supporting citations, not an exhaustive transitive denominator.
    pub changed_condition_refs: Vec<ArtifactId>,
    /// Direct supporting citations, not an exhaustive transitive denominator.
    pub evidence_refs: Vec<ArtifactId>,
}

impl RepairAttemptRecord {
    /// Performs bounded intrinsic checks for one attempt and every declared
    /// event slot. Attempt and event continuity across lineage entries belongs
    /// to the lineage validator.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        preflight_canonical_stream(self)?;
        if usize::try_from(self.expected_event_slots).unwrap_or(usize::MAX)
            > MAX_DIAGNOSIS_SEQUENCE_ITEMS
        {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.attempt.expected_event_slots",
                min: 0,
                max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
                got: i64::from(self.expected_event_slots),
            });
        }
        if self.events.len() != usize::try_from(self.expected_event_slots).unwrap_or(usize::MAX) {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.attempt.events",
                reason: "retained event entries must equal expected event slot count".to_owned(),
            });
        }
        self.attempt
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "repair.attempt.binding",
                reason: error.to_string(),
            })?;
        bounded_artifact_refs(
            &self.attempt.invalidation_refs,
            "repair.attempt.invalidation_refs",
        )?;
        if let Some(repeat) = &self.controlled_repeat {
            repeat.validate_local()?;
        }
        bounded_artifact_refs(
            &self.new_information_refs,
            "repair.attempt.new_information_refs",
        )?;
        bounded_artifact_refs(
            &self.changed_condition_refs,
            "repair.attempt.changed_condition_refs",
        )?;
        bounded_artifact_refs(&self.evidence_refs, "repair.attempt.evidence_refs")?;
        for (expected_slot, entry) in self.events.iter().enumerate() {
            let expected_slot = u32::try_from(expected_slot).unwrap_or(u32::MAX);
            match entry {
                RepairEventEntry::Observed(event) => {
                    if event.slot != expected_slot {
                        return Err(ContractViolation::BindingMismatch {
                            field: "repair.attempt.events.slot",
                            reason: "observed event slot must equal its zero-based position"
                                .to_owned(),
                        });
                    }
                    event.validate()?;
                }
                RepairEventEntry::Missing { slot, reason } => {
                    if *slot != expected_slot {
                        return Err(ContractViolation::BindingMismatch {
                            field: "repair.attempt.events.slot",
                            reason: "missing event slot must equal its zero-based position"
                                .to_owned(),
                        });
                    }
                    bounded_text(
                        reason,
                        "repair.attempt.events.missing.reason",
                        MAX_DIAGNOSIS_TEXT_BYTES,
                    )?;
                }
            }
        }
        for pair in self.events.windows(2) {
            let (RepairEventEntry::Observed(previous), RepairEventEntry::Observed(next)) =
                (&pair[0], &pair[1])
            else {
                continue;
            };
            check_adjacent_known_identity(previous, next)?;
        }
        Ok(())
    }
}

impl RepeatJustification {
    fn validate_local(&self) -> Result<(), ContractViolation> {
        bounded_text(
            &self.prior_attempt_id,
            "repair.repeat.prior_attempt_id",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        if let Some(slot) = self.prior_event_slot
            && usize::try_from(slot).unwrap_or(usize::MAX) >= MAX_DIAGNOSIS_SEQUENCE_ITEMS
        {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.repeat.prior_event_slot",
                min: 0,
                max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS - 1).unwrap_or(i64::MAX),
                got: i64::from(slot),
            });
        }
        bounded_text(
            &self.explanation,
            "repair.repeat.explanation",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
        validate_nonempty_artifact_refs(&self.evidence_refs, "repair.repeat.evidence_refs")
    }
}

/// Either a fully retained attempt or an explicitly omitted attempt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "record",
    deny_unknown_fields
)]
pub enum RepairAttemptEntry {
    Observed(Box<RepairAttemptRecord>),
    Omitted { attempt_id: String, reason: String },
}

/// Either a retained event or a declared missing slot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "event",
    deny_unknown_fields
)]
pub enum RepairEventEntry {
    Observed(Box<RepairEvent>),
    Missing { slot: u32, reason: String },
}

/// Endpoint of a product-context value that was unavailable for an event.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RepairContextEndpoint {
    Before,
    After,
}

/// Typed reason for an unavailable event context endpoint.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairContextUnavailable {
    pub endpoint: RepairContextEndpoint,
    pub evidence: UnavailableEvidence,
}

/// One event in an attempt. The enclosing attempt owns the attempt binding;
/// event slots preserve omissions without renumbering later observations.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairEvent {
    /// Zero-based position in the enclosing attempt's supplied chronology.
    pub slot: u32,
    pub stage: RepairStageKind,
    pub outcome: RepairEventOutcome,
    pub mechanism_exercise: MechanismExercise,
    pub before_context: Option<ProductContext>,
    pub after_context: Option<ProductContext>,
    pub context_unavailable: Vec<RepairContextUnavailable>,
    pub mechanism: Option<MechanismProjection>,
    pub evidence: EvidenceEnvelope,
    pub artifact_bindings: Vec<ArtifactBinding>,
    pub context_refs: Vec<ArtifactId>,
    pub unavailable: Vec<UnavailableEvidence>,
}

impl RepairEvent {
    /// Performs bounded intrinsic event checks without judging causal meaning.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        preflight_canonical_stream(self)?;
        if usize::try_from(self.slot).unwrap_or(usize::MAX) >= MAX_DIAGNOSIS_SEQUENCE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.event.slot",
                min: 0,
                max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS - 1).unwrap_or(i64::MAX),
                got: i64::from(self.slot),
            });
        }
        validate_event_outcome(&self.outcome)?;
        validate_mechanism_exercise(&self.mechanism_exercise)?;
        validate_context_endpoint(
            self.before_context.as_ref(),
            self.after_context.as_ref(),
            &self.context_unavailable,
        )?;
        if let Some(context) = &self.before_context {
            context.validate()?;
        }
        if let Some(context) = &self.after_context {
            context.validate()?;
        }
        match (&self.mechanism, self.unavailable.as_slice()) {
            (Some(mechanism), []) => mechanism.validate()?,
            (None, [item]) if item.field == UnavailableField::Mechanism => item.validate()?,
            (Some(_), _) => {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.event.mechanism",
                    reason: "present mechanism cannot also be marked unavailable".to_owned(),
                });
            }
            (None, _) => {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.event.mechanism",
                    reason: "missing mechanism requires exactly one typed unavailable reason"
                        .to_owned(),
                });
            }
        }
        self.evidence
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "repair.event.evidence",
                reason: error.to_string(),
            })?;
        bounded_artifact_refs(&self.context_refs, "repair.event.context_refs")?;
        if self.unavailable.len() > MAX_DIAGNOSIS_SEQUENCE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.event.unavailable",
                min: 0,
                max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
                got: i64::try_from(self.unavailable.len()).unwrap_or(i64::MAX),
            });
        }
        for item in &self.unavailable {
            if item.field != UnavailableField::Mechanism {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.event.unavailable.field",
                    reason: "event unavailable field must identify mechanism".to_owned(),
                });
            }
            item.validate()?;
        }
        self.validate_artifacts()
    }

    fn validate_artifacts(&self) -> Result<(), ContractViolation> {
        if self.artifact_bindings.len() > MAX_DIAGNOSIS_SEQUENCE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.event.artifact_bindings",
                min: 0,
                max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
                got: i64::try_from(self.artifact_bindings.len()).unwrap_or(i64::MAX),
            });
        }
        for pair in self.artifact_bindings.windows(2) {
            if pair[0].artifact_id >= pair[1].artifact_id {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.event.artifact_bindings",
                    reason: "event-owned artifact bindings must be unique and in canonical order"
                        .to_owned(),
                });
            }
        }
        let mut bindings: Vec<&ArtifactBinding> = self.artifact_bindings.iter().collect();
        for context in [self.before_context.as_ref(), self.after_context.as_ref()]
            .into_iter()
            .flatten()
        {
            for binding in [
                context.artifact.as_ref(),
                context.binary.as_ref(),
                context.config.as_ref(),
                context.features.as_ref(),
                context.toolchain.as_ref(),
                context.acceptance.external_content.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                bindings.push(binding);
            }
        }
        if bindings.len() > MAX_DIAGNOSIS_SEQUENCE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.event.artifact_bindings",
                min: 0,
                max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
                got: i64::try_from(bindings.len()).unwrap_or(i64::MAX),
            });
        }
        for binding in &bindings {
            validate_artifact_binding(binding)?;
        }
        for (left_index, left) in bindings.iter().enumerate() {
            for right in bindings.iter().skip(left_index + 1) {
                if left.artifact_id == right.artifact_id && left.sha256 != right.sha256 {
                    return Err(ContractViolation::BindingMismatch {
                        field: "repair.event.artifact_bindings",
                        reason: "one artifact id cannot carry different content within an event"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

fn validate_event_outcome(outcome: &RepairEventOutcome) -> Result<(), ContractViolation> {
    match outcome {
        RepairEventOutcome::NotExecuted { reason } | RepairEventOutcome::Unknown { reason } => {
            bounded_text(
                reason,
                "repair.event.outcome.reason",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )
        }
        RepairEventOutcome::Succeeded { summary } | RepairEventOutcome::Failed { summary } => {
            bounded_text(
                summary,
                "repair.event.outcome.summary",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )
        }
        RepairEventOutcome::Partial {
            summary,
            unresolved,
        } => {
            bounded_text(
                summary,
                "repair.event.outcome.summary",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )?;
            validate_nonempty_text_set(unresolved, "repair.event.outcome.unresolved")
        }
    }
}

fn validate_mechanism_exercise(exercise: &MechanismExercise) -> Result<(), ContractViolation> {
    match exercise {
        MechanismExercise::NotExercised { reason } | MechanismExercise::Unknown { reason } => {
            bounded_text(
                reason,
                "repair.event.mechanism_exercise.reason",
                MAX_DIAGNOSIS_TEXT_BYTES,
            )
        }
        MechanismExercise::Exercised => Ok(()),
        MechanismExercise::PartiallyExercised { unresolved } => {
            validate_nonempty_text_set(unresolved, "repair.event.mechanism_exercise.unresolved")
        }
    }
}

fn validate_context_endpoint(
    before: Option<&ProductContext>,
    after: Option<&ProductContext>,
    unavailable: &[RepairContextUnavailable],
) -> Result<(), ContractViolation> {
    if unavailable.len() > 2 {
        return Err(ContractViolation::OutOfBounds {
            field: "repair.event.context_unavailable",
            min: 0,
            max: 2,
            got: i64::try_from(unavailable.len()).unwrap_or(i64::MAX),
        });
    }
    for item in unavailable {
        if item.evidence.field != UnavailableField::ContextDigest {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.event.context_unavailable.evidence.field",
                reason: "context endpoint absence must use ContextDigest".to_owned(),
            });
        }
        item.evidence.validate()?;
    }
    for pair in unavailable.windows(2) {
        if pair[0].endpoint >= pair[1].endpoint {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.event.context_unavailable",
                reason: "context availability must be unique and ordered before then after"
                    .to_owned(),
            });
        }
    }
    for (endpoint, present) in [
        (RepairContextEndpoint::Before, before.is_some()),
        (RepairContextEndpoint::After, after.is_some()),
    ] {
        let count = unavailable
            .iter()
            .filter(|item| item.endpoint == endpoint)
            .count();
        if (present && count != 0) || (!present && count != 1) {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.event.context_unavailable",
                reason: "each context endpoint must be present or exactly once unavailable"
                    .to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_artifact_binding(binding: &ArtifactBinding) -> Result<(), ContractViolation> {
    bounded_text(
        binding.artifact_id.as_str(),
        "repair.event.artifact.artifact_id",
        MAX_DIAGNOSIS_TEXT_BYTES,
    )?;
    bounded_digest(&binding.sha256, "repair.event.artifact.sha256")?;
    if let Some(revision) = &binding.source_revision {
        bounded_text(
            revision,
            "repair.event.artifact.source_revision",
            MAX_DIAGNOSIS_TEXT_BYTES,
        )?;
    }
    Ok(())
}

fn validate_text_set(values: &[String], field: &'static str) -> Result<(), ContractViolation> {
    if values.len() > MAX_DIAGNOSIS_SEQUENCE_ITEMS {
        return Err(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
            got: i64::try_from(values.len()).unwrap_or(i64::MAX),
        });
    }
    for value in values {
        bounded_text(value, field, MAX_DIAGNOSIS_TEXT_BYTES)?;
    }
    for pair in values.windows(2) {
        if pair[0] >= pair[1] {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "set values must be unique and in canonical order".to_owned(),
            });
        }
    }
    Ok(())
}

fn validate_nonempty_text_set(
    values: &[String],
    field: &'static str,
) -> Result<(), ContractViolation> {
    if values.is_empty() {
        return Err(ContractViolation::OutOfBounds {
            field,
            min: 1,
            max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
            got: 0,
        });
    }
    validate_text_set(values, field)
}

fn validate_nonempty_artifact_refs(
    refs: &[ArtifactId],
    field: &'static str,
) -> Result<(), ContractViolation> {
    if refs.is_empty() {
        return Err(ContractViolation::OutOfBounds {
            field,
            min: 1,
            max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
            got: 0,
        });
    }
    bounded_artifact_refs(refs, field)
}

fn check_adjacent_known_identity(
    previous: &RepairEvent,
    next: &RepairEvent,
) -> Result<(), ContractViolation> {
    let (Some(after), Some(before)) = (
        previous.after_context.as_ref(),
        next.before_context.as_ref(),
    ) else {
        return Ok(());
    };

    check_adjacent_required_identity(after, before)?;
    check_adjacent_optional_identity(after, before)?;
    check_adjacent_environment(after, before)?;
    check_adjacent_scope(after, before)?;
    Ok(())
}

fn check_adjacent_required_identity(
    after: &ProductContext,
    before: &ProductContext,
) -> Result<(), ContractViolation> {
    check_equal(
        "repair.adjacent.schema_version",
        &after.schema_version,
        &before.schema_version,
    )?;
    check_equal(
        "repair.adjacent.product_identity",
        &after.product_identity,
        &before.product_identity,
    )?;
    check_equal(
        "repair.adjacent.objective.objective_id",
        &after.objective.objective_id,
        &before.objective.objective_id,
    )?;
    check_equal(
        "repair.adjacent.objective.revision",
        &after.objective.revision,
        &before.objective.revision,
    )?;
    check_equal(
        "repair.adjacent.recovery.profile_id",
        &after.recovery.profile_id,
        &before.recovery.profile_id,
    )?;
    check_equal(
        "repair.adjacent.recovery.objective_ref",
        &after.recovery.objective_ref,
        &before.recovery.objective_ref,
    )?;
    check_equal(
        "repair.adjacent.recovery.revision",
        &after.recovery.revision,
        &before.recovery.revision,
    )?;
    check_equal(
        "repair.adjacent.acceptance.contract_owner",
        &after.acceptance.contract_owner,
        &before.acceptance.contract_owner,
    )?;
    check_equal(
        "repair.adjacent.acceptance.contract_ref",
        &after.acceptance.contract_ref,
        &before.acceptance.contract_ref,
    )?;
    check_equal(
        "repair.adjacent.acceptance.contract_revision",
        &after.acceptance.contract_revision,
        &before.acceptance.contract_revision,
    )?;
    check_equal(
        "repair.adjacent.acceptance.objective_id",
        &after.acceptance.objective_id,
        &before.acceptance.objective_id,
    )?;
    check_equal(
        "repair.adjacent.acceptance.objective_revision",
        &after.acceptance.objective_revision,
        &before.acceptance.objective_revision,
    )?;
    check_equal(
        "repair.adjacent.acceptance.profile_id",
        &after.acceptance.profile_id,
        &before.acceptance.profile_id,
    )?;
    check_equal(
        "repair.adjacent.acceptance.profile_revision",
        &after.acceptance.profile_revision,
        &before.acceptance.profile_revision,
    )?;
    check_equal(
        "repair.adjacent.feature_ref",
        &after.feature_ref,
        &before.feature_ref,
    )?;
    check_equal(
        "repair.adjacent.workflow_ref",
        &after.workflow_ref,
        &before.workflow_ref,
    )?;
    check_equal(
        "repair.adjacent.user_outcome_ref",
        &after.user_outcome_ref,
        &before.user_outcome_ref,
    )?;
    Ok(())
}

fn check_adjacent_optional_identity(
    after: &ProductContext,
    before: &ProductContext,
) -> Result<(), ContractViolation> {
    for (field, left, right) in [
        (
            "repair.adjacent.repository",
            after.repository.as_ref(),
            before.repository.as_ref(),
        ),
        (
            "repair.adjacent.commit",
            after.commit.as_ref(),
            before.commit.as_ref(),
        ),
        (
            "repair.adjacent.tree",
            after.tree.as_ref(),
            before.tree.as_ref(),
        ),
        (
            "repair.adjacent.package",
            after.package.as_ref(),
            before.package.as_ref(),
        ),
        (
            "repair.adjacent.cell",
            after.cell.as_ref(),
            before.cell.as_ref(),
        ),
        (
            "repair.adjacent.component",
            after.component.as_ref(),
            before.component.as_ref(),
        ),
        (
            "repair.adjacent.runtime_generation",
            after.runtime_generation.as_ref(),
            before.runtime_generation.as_ref(),
        ),
    ] {
        check_optional_equal(field, left, right)?;
    }
    for (field, left, right) in [
        (
            "repair.adjacent.artifact",
            after.artifact.as_ref(),
            before.artifact.as_ref(),
        ),
        (
            "repair.adjacent.binary",
            after.binary.as_ref(),
            before.binary.as_ref(),
        ),
        (
            "repair.adjacent.config",
            after.config.as_ref(),
            before.config.as_ref(),
        ),
        (
            "repair.adjacent.features",
            after.features.as_ref(),
            before.features.as_ref(),
        ),
        (
            "repair.adjacent.toolchain",
            after.toolchain.as_ref(),
            before.toolchain.as_ref(),
        ),
        (
            "repair.adjacent.acceptance.external_content",
            after.acceptance.external_content.as_ref(),
            before.acceptance.external_content.as_ref(),
        ),
    ] {
        check_optional_artifact(field, left, right)?;
    }
    Ok(())
}

fn check_adjacent_environment(
    after: &ProductContext,
    before: &ProductContext,
) -> Result<(), ContractViolation> {
    let (Some(left), Some(right)) = (&after.environment, &before.environment) else {
        return Ok(());
    };
    for (field, left, right) in [
        (
            "repair.adjacent.environment.id",
            &left.environment_id,
            &right.environment_id,
        ),
        (
            "repair.adjacent.environment.revision",
            &left.environment_revision,
            &right.environment_revision,
        ),
        (
            "repair.adjacent.environment.platform",
            &left.platform,
            &right.platform,
        ),
        (
            "repair.adjacent.environment.tool_revision",
            &left.tool_revision,
            &right.tool_revision,
        ),
        (
            "repair.adjacent.environment.config_revision",
            &left.config_revision,
            &right.config_revision,
        ),
        (
            "repair.adjacent.environment.capability_revision",
            &left.capability_revision,
            &right.capability_revision,
        ),
        (
            "repair.adjacent.environment.policy_revision",
            &left.policy_revision,
            &right.policy_revision,
        ),
    ] {
        check_equal(field, left, right)?;
    }
    check_optional_equal(
        "repair.adjacent.environment.model_revision",
        left.model_revision.as_ref(),
        right.model_revision.as_ref(),
    )
}

fn check_adjacent_scope(
    after: &ProductContext,
    before: &ProductContext,
) -> Result<(), ContractViolation> {
    let (Some(left), Some(right)) = (&after.scope, &before.scope) else {
        return Ok(());
    };
    check_equal(
        "repair.adjacent.scope.scope_id",
        &left.scope_id,
        &right.scope_id,
    )?;
    check_equal(
        "repair.adjacent.scope.product_id",
        &left.product_id,
        &right.product_id,
    )?;
    check_equal(
        "repair.adjacent.scope.resource_generation",
        &left.resource_generation,
        &right.resource_generation,
    )?;
    Ok(())
}

fn check_equal<T: PartialEq>(
    field: &'static str,
    left: &T,
    right: &T,
) -> Result<(), ContractViolation> {
    if left != right {
        return Err(ContractViolation::BindingMismatch {
            field,
            reason: "adjacent supplied identities conflict".to_owned(),
        });
    }
    Ok(())
}

fn check_optional_equal<T: PartialEq>(
    field: &'static str,
    left: Option<&T>,
    right: Option<&T>,
) -> Result<(), ContractViolation> {
    if let (Some(left), Some(right)) = (left, right) {
        check_equal(field, left, right)?;
    }
    Ok(())
}

fn check_optional_artifact(
    field: &'static str,
    left: Option<&ArtifactBinding>,
    right: Option<&ArtifactBinding>,
) -> Result<(), ContractViolation> {
    let (Some(left), Some(right)) = (left, right) else {
        return Ok(());
    };
    check_equal(field, &left.artifact_id, &right.artifact_id)?;
    check_equal(field, &left.sha256, &right.sha256)?;
    check_optional_equal(
        "repair.adjacent.artifact.source_revision",
        left.source_revision.as_ref(),
        right.source_revision.as_ref(),
    )
}

/// Digest-bearing, multi-attempt repair history.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepairLineage {
    pub schema_version: u16,
    pub lineage_id: ContractId,
    pub presence: RepairHistoryPresence,
    /// Coverage of the declared attempt/event denominator, not proof of
    /// completeness or authentication of arbitrary supporting references.
    pub denominator_coverage: EvidenceCoverage,
    /// Coverage of retained attempt/event entries, not proof of arbitrary
    /// transitive evidence completeness or owner authentication.
    pub retained_coverage: EvidenceCoverage,
    pub expected_attempt_ids: Vec<String>,
    /// Attempts in the supplied chronology; entries are never reordered or
    /// collapsed into a latest/count-only summary.
    pub attempts: Vec<RepairAttemptEntry>,
    /// Direct supporting citations, not an exhaustive transitive denominator.
    pub evidence_refs: Vec<ArtifactId>,
    pub unavailable: Vec<UnavailableEvidence>,
    pub digest: String,
}

impl RepairLineage {
    /// Computes the lineage digest after bounded shape validation.
    pub fn canonical_digest(&self) -> Result<String, ContractViolation> {
        self.validate_shape()?;
        let preimage = RepairLineagePreimage {
            schema_version: self.schema_version,
            lineage_id: &self.lineage_id,
            presence: self.presence,
            denominator_coverage: self.denominator_coverage,
            retained_coverage: self.retained_coverage,
            expected_attempt_ids: &self.expected_attempt_ids,
            attempts: &self.attempts,
            evidence_refs: &self.evidence_refs,
            unavailable: &self.unavailable,
        };
        canonical_stream_digest(&preimage)
    }

    /// Returns this lineage with its canonical digest populated.
    pub fn with_digest(mut self) -> Result<Self, ContractViolation> {
        self.validate_shape()?;
        self.digest = self.canonical_digest()?;
        Ok(self)
    }

    /// Performs bounded aggregate checks without imposing stage or causal
    /// continuity rules.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_shape()?;
        bounded_digest(&self.digest, "repair.lineage.digest")?;
        let expected = self.canonical_digest()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.lineage.digest",
                reason: "supplied lineage digest does not match canonical bytes".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        self.validate_lineage_wire_bounds()?;
        self.validate_presence()?;
        self.validate_coverage()?;
        self.validate_event_work_bounds()?;
        self.validate_attempt_entries()?;
        self.validate_retained_coverage()
    }

    fn validate_lineage_wire_bounds(&self) -> Result<(), ContractViolation> {
        preflight_canonical_stream(self)?;
        if !self.digest.is_empty() && !is_hex64_lower(&self.digest) {
            return Err(ContractViolation::Malformed {
                field: "repair.lineage.digest",
                reason: "digest must be empty or lowercase SHA-256".to_owned(),
            });
        }
        if self.schema_version != REPAIR_LINEAGE_SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.lineage.schema_version",
                min: i64::from(REPAIR_LINEAGE_SCHEMA_VERSION),
                max: i64::from(REPAIR_LINEAGE_SCHEMA_VERSION),
                got: i64::from(self.schema_version),
            });
        }
        bounded_contract_id(&self.lineage_id, "repair.lineage.lineage_id")?;
        validate_text_set(
            &self.expected_attempt_ids,
            "repair.lineage.expected_attempt_ids",
        )?;
        bounded_artifact_refs(&self.evidence_refs, "repair.lineage.evidence_refs")?;
        if self.attempts.len() > MAX_DIAGNOSIS_SEQUENCE_ITEMS {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.lineage.attempts",
                min: 0,
                max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
                got: i64::try_from(self.attempts.len()).unwrap_or(i64::MAX),
            });
        }
        Ok(())
    }

    fn validate_event_work_bounds(&self) -> Result<(), ContractViolation> {
        // Account for declared event work before invoking any nested attempt,
        // event, context, evidence or digest validator.
        let mut total_event_slots = 0_usize;
        for entry in &self.attempts {
            let RepairAttemptEntry::Observed(record) = entry else {
                continue;
            };
            if usize::try_from(record.expected_event_slots).unwrap_or(usize::MAX)
                > MAX_DIAGNOSIS_SEQUENCE_ITEMS
            {
                return Err(ContractViolation::OutOfBounds {
                    field: "repair.lineage.attempt.expected_event_slots",
                    min: 0,
                    max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
                    got: i64::from(record.expected_event_slots),
                });
            }
            if record.events.len()
                != usize::try_from(record.expected_event_slots).unwrap_or(usize::MAX)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.lineage.attempt.events",
                    reason: "retained event entries must equal expected event slot count"
                        .to_owned(),
                });
            }
            total_event_slots = total_event_slots
                .checked_add(usize::try_from(record.expected_event_slots).unwrap_or(usize::MAX))
                .ok_or(ContractViolation::OutOfBounds {
                    field: "repair.lineage.total_event_slots",
                    min: 0,
                    max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
                    got: i64::MAX,
                })?;
            if total_event_slots > MAX_DIAGNOSIS_SEQUENCE_ITEMS {
                return Err(ContractViolation::OutOfBounds {
                    field: "repair.lineage.total_event_slots",
                    min: 0,
                    max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
                    got: i64::try_from(total_event_slots).unwrap_or(i64::MAX),
                });
            }
        }
        Ok(())
    }

    fn validate_attempt_entries(&self) -> Result<(), ContractViolation> {
        let expected_ids: BTreeSet<&str> = self
            .expected_attempt_ids
            .iter()
            .map(String::as_str)
            .collect();
        let mut seen_ids = BTreeSet::new();
        for entry in &self.attempts {
            let attempt_id = match entry {
                RepairAttemptEntry::Observed(record) => {
                    record.validate()?;
                    record.attempt.attempt_id.as_str()
                }
                RepairAttemptEntry::Omitted { attempt_id, reason } => {
                    bounded_text(
                        attempt_id,
                        "repair.lineage.omitted_attempt_id",
                        MAX_DIAGNOSIS_TEXT_BYTES,
                    )?;
                    bounded_text(
                        reason,
                        "repair.lineage.omitted_attempt_reason",
                        MAX_DIAGNOSIS_TEXT_BYTES,
                    )?;
                    attempt_id.as_str()
                }
            };
            if !seen_ids.insert(attempt_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.lineage.attempts",
                    reason: "attempt identifiers must be unique".to_owned(),
                });
            }
            if !expected_ids.contains(attempt_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.lineage.expected_attempt_ids",
                    reason: "attempt entries must be covered by expected attempt identifiers"
                        .to_owned(),
                });
            }
        }
        if seen_ids.len() != expected_ids.len()
            || expected_ids.iter().any(|id| !seen_ids.contains(id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.lineage.expected_attempt_ids",
                reason: "expected attempt identifiers must exactly cover the supplied entries"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn validate_retained_coverage(&self) -> Result<(), ContractViolation> {
        if self.retained_coverage == EvidenceCoverage::CompleteForScope
            && self.attempts.iter().any(|entry| match entry {
                RepairAttemptEntry::Observed(record) => record
                    .events
                    .iter()
                    .any(|event| matches!(event, RepairEventEntry::Missing { .. })),
                RepairAttemptEntry::Omitted { .. } => true,
            })
        {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.lineage.retained_coverage",
                reason: "complete retained coverage cannot contain omitted attempts or missing event slots".to_owned(),
            });
        }
        self.validate_repeat_predecessors()?;
        self.validate_cross_lineage_artifacts()
    }

    fn validate_presence(&self) -> Result<(), ContractViolation> {
        match self.presence {
            RepairHistoryPresence::ZeroPriorRepairs => {
                if !self.expected_attempt_ids.is_empty() || !self.attempts.is_empty() {
                    return Err(ContractViolation::BindingMismatch {
                        field: "repair.lineage.presence",
                        reason: "zero prior repairs requires an empty attempt history".to_owned(),
                    });
                }
                if self.denominator_coverage != EvidenceCoverage::CompleteForScope
                    || self.retained_coverage != EvidenceCoverage::CompleteForScope
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "repair.lineage.presence",
                        reason:
                            "zero prior repairs requires complete denominator and retained coverage"
                                .to_owned(),
                    });
                }
            }
            RepairHistoryPresence::OneOrMore if self.expected_attempt_ids.is_empty() => {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.lineage.expected_attempt_ids",
                    reason: "one-or-more history requires at least one expected attempt".to_owned(),
                });
            }
            RepairHistoryPresence::Unknown
                if self.denominator_coverage == EvidenceCoverage::CompleteForScope =>
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.lineage.denominator_coverage",
                    reason:
                        "unknown history presence cannot claim complete known denominator coverage"
                            .to_owned(),
                });
            }
            RepairHistoryPresence::OneOrMore | RepairHistoryPresence::Unknown => {}
        }
        Ok(())
    }

    fn validate_coverage(&self) -> Result<(), ContractViolation> {
        let mut denominator_unavailable = false;
        let mut retained_unavailable = false;
        if self.unavailable.len() > 2 {
            return Err(ContractViolation::OutOfBounds {
                field: "repair.lineage.unavailable",
                min: 0,
                max: 2,
                got: i64::try_from(self.unavailable.len()).unwrap_or(i64::MAX),
            });
        }
        for item in &self.unavailable {
            match item.field {
                UnavailableField::HistoryDenominator => {
                    if denominator_unavailable {
                        return Err(ContractViolation::BindingMismatch {
                            field: "repair.lineage.unavailable",
                            reason: "history denominator availability must be unique".to_owned(),
                        });
                    }
                    denominator_unavailable = true;
                }
                UnavailableField::RetainedHistory => {
                    if retained_unavailable {
                        return Err(ContractViolation::BindingMismatch {
                            field: "repair.lineage.unavailable",
                            reason: "retained history availability must be unique".to_owned(),
                        });
                    }
                    retained_unavailable = true;
                }
                _ => {
                    return Err(ContractViolation::BindingMismatch {
                        field: "repair.lineage.unavailable.field",
                        reason: "lineage unavailable field must identify a coverage denominator"
                            .to_owned(),
                    });
                }
            }
            item.validate()?;
        }
        for pair in self.unavailable.windows(2) {
            if pair[0].field >= pair[1].field {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.lineage.unavailable",
                    reason: "coverage availability must be unique and in canonical order"
                        .to_owned(),
                });
            }
        }
        for (coverage, present, field) in [
            (
                self.denominator_coverage,
                denominator_unavailable,
                "repair.lineage.denominator_coverage",
            ),
            (
                self.retained_coverage,
                retained_unavailable,
                "repair.lineage.retained_coverage",
            ),
        ] {
            if coverage == EvidenceCoverage::NotApplicable {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: "coverage cannot be NotApplicable for repair history".to_owned(),
                });
            }
            let requires_unavailable = matches!(
                coverage,
                EvidenceCoverage::PartialForScope | EvidenceCoverage::Unknown
            );
            if present != requires_unavailable {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason:
                        "partial or unknown coverage requires exactly one typed unavailable reason"
                            .to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_repeat_predecessors(&self) -> Result<(), ContractViolation> {
        for (index, entry) in self.attempts.iter().enumerate() {
            let RepairAttemptEntry::Observed(record) = entry else {
                continue;
            };
            let Some(repeat) = &record.controlled_repeat else {
                continue;
            };
            let prior = self.attempts[..index]
                .iter()
                .find(|candidate| attempt_entry_id(candidate) == repeat.prior_attempt_id.as_str());
            let Some(prior) = prior else {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.repeat.prior_attempt_id",
                    reason: "repeat justification must reference a strictly earlier attempt entry"
                        .to_owned(),
                });
            };
            if let Some(slot) = repeat.prior_event_slot
                && !attempt_declares_event_slot(prior, slot)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "repair.repeat.prior_event_slot",
                    reason: "prior event slot must identify a declared event slot".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_cross_lineage_artifacts(&self) -> Result<(), ContractViolation> {
        let mut by_id: BTreeMap<String, String> = BTreeMap::new();
        for entry in &self.attempts {
            let RepairAttemptEntry::Observed(record) = entry else {
                continue;
            };
            for event_entry in &record.events {
                let RepairEventEntry::Observed(event) = event_entry else {
                    continue;
                };
                for binding in &event.artifact_bindings {
                    register_artifact(&mut by_id, binding)?;
                }
                for context in [event.before_context.as_ref(), event.after_context.as_ref()]
                    .into_iter()
                    .flatten()
                {
                    for binding in [
                        context.artifact.as_ref(),
                        context.binary.as_ref(),
                        context.config.as_ref(),
                        context.features.as_ref(),
                        context.toolchain.as_ref(),
                        context.acceptance.external_content.as_ref(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        register_artifact(&mut by_id, binding)?;
                    }
                }
            }
        }
        Ok(())
    }
}

fn attempt_declares_event_slot(entry: &RepairAttemptEntry, slot: u32) -> bool {
    let RepairAttemptEntry::Observed(record) = entry else {
        return false;
    };
    let Some(event) = record
        .events
        .get(usize::try_from(slot).unwrap_or(usize::MAX))
    else {
        return false;
    };
    match event {
        RepairEventEntry::Observed(event) => event.slot == slot,
        RepairEventEntry::Missing { slot: declared, .. } => *declared == slot,
    }
}

fn attempt_entry_id(entry: &RepairAttemptEntry) -> &str {
    match entry {
        RepairAttemptEntry::Observed(record) => record.attempt.attempt_id.as_str(),
        RepairAttemptEntry::Omitted { attempt_id, .. } => attempt_id.as_str(),
    }
}

fn register_artifact(
    by_id: &mut BTreeMap<String, String>,
    binding: &ArtifactBinding,
) -> Result<(), ContractViolation> {
    let artifact_id = binding.artifact_id.as_str();
    if let Some(previous) = by_id.get(artifact_id) {
        if previous != &binding.sha256 {
            return Err(ContractViolation::BindingMismatch {
                field: "repair.lineage.artifact_bindings",
                reason: "one artifact id cannot carry different content across the lineage"
                    .to_owned(),
            });
        }
    } else {
        by_id.insert(artifact_id.to_owned(), binding.sha256.clone());
    }
    Ok(())
}

#[derive(Serialize)]
struct RepairLineagePreimage<'a> {
    schema_version: u16,
    lineage_id: &'a ContractId,
    presence: RepairHistoryPresence,
    denominator_coverage: EvidenceCoverage,
    retained_coverage: EvidenceCoverage,
    expected_attempt_ids: &'a [String],
    attempts: &'a [RepairAttemptEntry],
    evidence_refs: &'a [ArtifactId],
    unavailable: &'a [UnavailableEvidence],
}
