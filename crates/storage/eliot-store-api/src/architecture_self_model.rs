//! Store-neutral contracts for the protected Architecture source and ELIOT's
//! self-model. These values describe authority and observed conformance; they
//! do not persist state or certify their own claims.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, SourceId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{StoreError, validate_sha256_hex};

/// Exact adopted Architecture source identity. Audits, summaries, comments,
/// and code-derived projections are not interchangeable with this source.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AdoptedArchitectureRevision {
    /// Stable identity of the protected primary source.
    pub source_id: SourceId,
    /// Human-readable revision label from that source.
    pub revision: String,
    /// SHA-256 of the exact adopted Architecture byte stream.
    pub digest: String,
}

/// The five distinct categories in the System Self-Model.
#[derive(
    Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelfKnowledgeCategory {
    /// What ELIOT is intended to mean.
    Constitutional,
    /// What has actually been built.
    Implemented,
    /// What is currently available or degraded.
    Operational,
    /// Incidents, repairs, and learned limits.
    Experiential,
    /// What is demonstrated, contested, or unknown about ELIOT.
    Epistemic,
}

impl SelfKnowledgeCategory {
    /// Required canonical order for a complete self-model.
    pub const ALL: [Self; 5] = [
        Self::Constitutional,
        Self::Implemented,
        Self::Operational,
        Self::Experiential,
        Self::Epistemic,
    ];
}

/// Evidence references assigned to one self-knowledge category.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfKnowledgeEvidence {
    pub category: SelfKnowledgeCategory,
    /// Exact source handles supporting this category.
    pub source_handles: Vec<SourceId>,
    /// Exact immutable evidence handles supporting this category.
    pub evidence_handles: Vec<ArtifactId>,
}

/// Current status of an Architecture anchor against implementation and
/// observable outcomes.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArchitectureConformanceState {
    Conformant,
    Gap,
    Provisional,
    Invalid,
    Unknown,
}

/// Why an Architecture conformance gap was opened.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ArchitectureGapCause {
    ArchitectureRevisionChanged {
        adopted_digest: String,
        observed_digest: String,
    },
    RuntimeOutcomeDiverged {
        anchor: String,
        expected_outcome: String,
        observed_outcome: String,
    },
}

/// Visible conformance gap with its exact evidence lineage.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureConformanceGap {
    pub anchor: String,
    pub cause: ArchitectureGapCause,
    /// Exact evidence that exposed the gap.
    pub evidence_handles: Vec<ArtifactId>,
}

/// One machine-readable Intent or `ARCH-*` conformance row.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureConformanceEntry {
    pub anchor: String,
    pub implementation_owner: String,
    pub mechanism: String,
    pub failure_behavior: String,
    pub expected_observable_outcome: String,
    pub status: ArchitectureConformanceState,
    pub evidence_handles: Vec<ArtifactId>,
    pub gap: Option<ArchitectureConformanceGap>,
}

/// Typed self-knowledge snapshot bound to the exact adopted Architecture.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSelfModel {
    pub adopted_architecture: AdoptedArchitectureRevision,
    /// Exactly one row for each [`SelfKnowledgeCategory`], in canonical order.
    pub categories: Vec<SelfKnowledgeEvidence>,
    /// Current machine-readable conformance rows. Each row remains evidence,
    /// not authority to change Architecture or self-certify ELIOT.
    pub conformance: Vec<ArchitectureConformanceEntry>,
}

/// A dependent brief or projection that must be rebuilt or reviewed after
/// invalidation.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureInvalidation {
    pub cause: ArchitectureGapCause,
    pub provisional_material: Vec<ArtifactId>,
    pub provisional_conformance: Vec<ArchitectureConformanceEntry>,
}

/// Validates a self-model's protected source identity, five categories, and
/// conformance rows without asserting that any row is true.
pub fn validate_architecture_self_model(model: &SystemSelfModel) -> Result<(), StoreError> {
    validate_sha256_hex(
        &model.adopted_architecture.digest,
        "architecture_self_model.adopted_architecture.digest",
    )?;
    validate_text(
        &model.adopted_architecture.revision,
        "architecture_self_model.adopted_architecture.revision",
    )?;

    if !model
        .categories
        .iter()
        .map(|row| row.category)
        .eq(SelfKnowledgeCategory::ALL)
    {
        return Err(StoreError::InvalidField {
            field: "architecture_self_model.categories",
            reason: "must contain each self-knowledge category exactly once in canonical order",
        });
    }
    for row in &model.categories {
        validate_unique_sources(
            &row.source_handles,
            "architecture_self_model.source_handles",
        )?;
        validate_unique_artifacts(
            &row.evidence_handles,
            "architecture_self_model.category_evidence_handles",
        )?;
    }

    if model.conformance.is_empty() {
        return Err(StoreError::Empty {
            field: "architecture_self_model.conformance",
        });
    }
    let mut anchors = BTreeSet::new();
    for row in &model.conformance {
        validate_anchor(&row.anchor, "architecture_self_model.conformance.anchor")?;
        for (value, field) in [
            (&row.implementation_owner, "implementation_owner"),
            (&row.mechanism, "mechanism"),
            (&row.failure_behavior, "failure_behavior"),
            (
                &row.expected_observable_outcome,
                "expected_observable_outcome",
            ),
        ] {
            validate_text(value, field)?;
        }
        validate_unique_artifacts(
            &row.evidence_handles,
            "architecture_self_model.conformance.evidence_handles",
        )?;
        if row.status == ArchitectureConformanceState::Conformant && row.evidence_handles.is_empty()
        {
            return Err(StoreError::Empty {
                field: "architecture_self_model.conformance.evidence_handles",
            });
        }
        if !anchors.insert(row.anchor.as_str()) {
            return Err(StoreError::Duplicate {
                field: "architecture_self_model.conformance.anchor",
            });
        }
        match (&row.status, &row.gap) {
            (
                ArchitectureConformanceState::Conformant | ArchitectureConformanceState::Unknown,
                None,
            ) => {}
            (
                ArchitectureConformanceState::Conformant | ArchitectureConformanceState::Unknown,
                Some(_),
            )
            | (_, None) => {
                return Err(StoreError::InvalidField {
                    field: "architecture_self_model.conformance.gap",
                    reason: "gap presence must agree with provisional, invalid, or gap status",
                });
            }
            (_, Some(gap)) => {
                if gap.anchor != row.anchor || gap.evidence_handles.is_empty() {
                    return Err(StoreError::InvalidField {
                        field: "architecture_self_model.conformance.gap",
                        reason: "gap must identify its row and cite evidence",
                    });
                }
                validate_gap_cause(
                    &gap.cause,
                    &row.anchor,
                    &row.expected_observable_outcome,
                    &model.adopted_architecture.digest,
                )?;
                validate_unique_artifacts(
                    &gap.evidence_handles,
                    "architecture_self_model.conformance.gap_evidence_handles",
                )?;
            }
        }
    }
    Ok(())
}

/// Derives a provisional snapshot when the adopted source digest changes or
/// an observed runtime outcome diverges. Persistence and dependency discovery
/// remain with the canonical-state owner.
pub fn invalidate_architecture_self_model(
    model: &SystemSelfModel,
    cause: ArchitectureGapCause,
    dependent_material: Vec<ArtifactId>,
    evidence_handles: &[ArtifactId],
) -> Result<ArchitectureInvalidation, StoreError> {
    validate_architecture_self_model(model)?;
    validate_unique_artifacts(
        &dependent_material,
        "architecture_self_model.invalidation.dependent_material",
    )?;
    validate_unique_artifacts(
        evidence_handles,
        "architecture_self_model.invalidation.evidence_handles",
    )?;
    if evidence_handles.is_empty() {
        return Err(StoreError::Empty {
            field: "architecture_self_model.invalidation.evidence_handles",
        });
    }

    let affected_anchor = match &cause {
        ArchitectureGapCause::ArchitectureRevisionChanged {
            adopted_digest,
            observed_digest,
        } => {
            validate_sha256_hex(
                adopted_digest,
                "architecture_self_model.invalidation.adopted_digest",
            )?;
            validate_sha256_hex(
                observed_digest,
                "architecture_self_model.invalidation.observed_digest",
            )?;
            if adopted_digest == observed_digest
                || adopted_digest != &model.adopted_architecture.digest
            {
                return Err(StoreError::InvalidField {
                    field: "architecture_self_model.invalidation.digest_change",
                    reason: "must compare the model's adopted digest with a different observed digest",
                });
            }
            None
        }
        ArchitectureGapCause::RuntimeOutcomeDiverged {
            anchor,
            expected_outcome,
            observed_outcome,
        } => {
            validate_text(anchor, "architecture_self_model.invalidation.anchor")?;
            validate_text(
                expected_outcome,
                "architecture_self_model.invalidation.expected_outcome",
            )?;
            validate_text(
                observed_outcome,
                "architecture_self_model.invalidation.observed_outcome",
            )?;
            if expected_outcome == observed_outcome {
                return Err(StoreError::InvalidField {
                    field: "architecture_self_model.invalidation.runtime_divergence",
                    reason: "observed outcome must differ from the expected outcome",
                });
            }
            let row = model
                .conformance
                .iter()
                .find(|row| row.anchor == *anchor)
                .ok_or(StoreError::InvalidField {
                    field: "architecture_self_model.invalidation.anchor",
                    reason: "must identify an existing conformance row",
                })?;
            if row.expected_observable_outcome != *expected_outcome {
                return Err(StoreError::InvalidField {
                    field: "architecture_self_model.invalidation.expected_outcome",
                    reason: "must match the named conformance row",
                });
            }
            Some(anchor.as_str())
        }
    };

    let provisional_conformance = model
        .conformance
        .iter()
        .filter(|row| affected_anchor.is_none_or(|anchor| row.anchor == anchor))
        .map(|row| {
            let mut provisional = row.clone();
            provisional.status = ArchitectureConformanceState::Provisional;
            provisional.gap = Some(ArchitectureConformanceGap {
                anchor: row.anchor.clone(),
                cause: cause.clone(),
                evidence_handles: evidence_handles.to_vec(),
            });
            provisional
        })
        .collect();

    Ok(ArchitectureInvalidation {
        cause,
        provisional_material: dependent_material,
        provisional_conformance,
    })
}

fn validate_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be nonblank text without control characters",
        });
    }
    Ok(())
}

fn validate_anchor(value: &str, field: &'static str) -> Result<(), StoreError> {
    validate_text(value, field)
}

fn validate_gap_cause(
    cause: &ArchitectureGapCause,
    anchor: &str,
    expected_observable_outcome: &str,
    adopted_architecture_digest: &str,
) -> Result<(), StoreError> {
    match cause {
        ArchitectureGapCause::ArchitectureRevisionChanged {
            adopted_digest,
            observed_digest,
        } => {
            validate_sha256_hex(
                adopted_digest,
                "architecture_self_model.conformance.gap.adopted_digest",
            )?;
            validate_sha256_hex(
                observed_digest,
                "architecture_self_model.conformance.gap.observed_digest",
            )?;
            if adopted_digest != adopted_architecture_digest || adopted_digest == observed_digest {
                return Err(StoreError::InvalidField {
                    field: "architecture_self_model.conformance.gap.digest_change",
                    reason: "gap must bind this model's adopted digest to a different observation",
                });
            }
        }
        ArchitectureGapCause::RuntimeOutcomeDiverged {
            anchor: cause_anchor,
            expected_outcome,
            observed_outcome,
        } => {
            validate_text(
                cause_anchor,
                "architecture_self_model.conformance.gap.anchor",
            )?;
            validate_text(
                expected_outcome,
                "architecture_self_model.conformance.gap.expected_outcome",
            )?;
            validate_text(
                observed_outcome,
                "architecture_self_model.conformance.gap.observed_outcome",
            )?;
            if cause_anchor != anchor
                || expected_outcome != expected_observable_outcome
                || expected_outcome == observed_outcome
            {
                return Err(StoreError::InvalidField {
                    field: "architecture_self_model.conformance.gap.runtime_divergence",
                    reason: "must match the row and record a distinct observed outcome",
                });
            }
        }
    }
    Ok(())
}

fn validate_unique_sources(values: &[SourceId], field: &'static str) -> Result<(), StoreError> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value.as_str())) {
        return Err(StoreError::Duplicate { field });
    }
    Ok(())
}

fn validate_unique_artifacts(values: &[ArtifactId], field: &'static str) -> Result<(), StoreError> {
    let mut seen = BTreeSet::new();
    if values.iter().any(|value| !seen.insert(value.as_str())) {
        return Err(StoreError::Duplicate { field });
    }
    Ok(())
}
