//! Candidate and sealed-result contracts for the relation closure.

use eliot_contracts::ArtifactId;
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::curation::CurationKind;
use crate::draft::CurationAcceptanceCtx;
use crate::encoding::{canonical_bytes, digest_hex};
use crate::error::{ContractViolation, check_text, check_vec_bound, is_hex64_lower};

use super::input::{
    RelationInput, RelationSnapshot, RelationTemporalEvidence, preflight_serialized,
};
use super::registry::{RelationDirection, RelationFamily};

const MAX_TEXT: usize = 1024;
const MAX_ITEMS: usize = 256;
const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024;

fn digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "must be lowercase sha256".to_owned(),
        })
    }
}

fn unique_refs(values: &[String], field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_ITEMS, field)?;
    for (index, value) in values.iter().enumerate() {
        check_text(value, field, MAX_TEXT)?;
        if values[..index].contains(value) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "duplicate retained reference".to_owned(),
            });
        }
    }
    Ok(())
}

/// Exact I9.7 preservation dimensions for a relation transformation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationPreservationDimension {
    Coverage,
    Preservation,
    Faithfulness,
    Lineage,
    Reversibility,
    SourceAuthority,
    DependencyClosure,
}

impl RelationPreservationDimension {
    /// Canonical I9.7 spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coverage => "coverage",
            Self::Preservation => "preservation",
            Self::Faithfulness => "faithfulness",
            Self::Lineage => "lineage",
            Self::Reversibility => "reversibility",
            Self::SourceAuthority => "source_authority",
            Self::DependencyClosure => "dependency_closure",
        }
    }
    /// Parses one of the seven exact dimensions.
    pub fn parse(value: &str) -> Result<Self, ContractViolation> {
        Self::all()
            .iter()
            .copied()
            .find(|d| d.as_str() == value)
            .ok_or_else(|| ContractViolation::UnknownVariant {
                field: "relation.preservation_dimension",
                value: value.to_owned(),
            })
    }
    /// Returns the complete dimension set.
    #[must_use]
    pub const fn all() -> &'static [Self] {
        &[
            Self::Coverage,
            Self::Preservation,
            Self::Faithfulness,
            Self::Lineage,
            Self::Reversibility,
            Self::SourceAuthority,
            Self::DependencyClosure,
        ]
    }
}

/// Verdict for one preservation dimension.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationPreservationVerdict {
    pub dimension: RelationPreservationDimension,
    pub passed: bool,
    pub known: bool,
    pub note: String,
}

/// Seven-dimensional, non-averaging I9.7 preservation report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationPreservation {
    pub verdicts: Vec<RelationPreservationVerdict>,
}

impl RelationPreservation {
    /// Validates exact dimension coverage and notes.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.verdicts.len() != 7 {
            return Err(ContractViolation::Preservation(format!(
                "expected seven relation preservation dimensions, got {}",
                self.verdicts.len()
            )));
        }
        let mut seen = Vec::with_capacity(7);
        for verdict in &self.verdicts {
            check_text(&verdict.note, "relation.preservation.note", MAX_TEXT)?;
            if seen.contains(&verdict.dimension) {
                return Err(ContractViolation::Preservation(format!(
                    "duplicate dimension {}",
                    verdict.dimension.as_str()
                )));
            }
            seen.push(verdict.dimension);
        }
        if RelationPreservationDimension::all()
            .iter()
            .any(|d| !seen.contains(d))
        {
            return Err(ContractViolation::Preservation(
                "missing relation preservation dimension".to_owned(),
            ));
        }
        Ok(())
    }
    /// Requires every dimension to be known and passing.
    pub fn overall(&self) -> Result<(), ContractViolation> {
        self.validate()?;
        if let Some(verdict) = self.verdicts.iter().find(|v| !v.known || !v.passed) {
            return Err(ContractViolation::Preservation(format!(
                "dimension {} is not passing",
                verdict.dimension.as_str()
            )));
        }
        Ok(())
    }
}

/// Typed relation candidate disposition, retaining ambiguity and gaps.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationDisposition {
    Positive,
    Duplicate,
    Inverse,
    Ambiguous,
    Conflict,
    Unsupported,
    Partial,
    Stale,
    Blocked,
    Abstention,
    Error,
}

/// Explicit reversible/removal/restoration handles for a relation candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationRollback {
    pub predecessor: Option<String>,
    pub rollback_refs: Vec<String>,
    pub removal_or_restoration_refs: Vec<String>,
    pub invalidation_refs: Vec<String>,
    pub raw_history_refs: Vec<String>,
    pub note: String,
}

impl RelationRollback {
    fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(value) = &self.predecessor {
            check_text(value, "relation.rollback.predecessor", MAX_TEXT)?;
        }
        for (values, field) in [
            (&self.rollback_refs, "relation.rollback.refs"),
            (
                &self.removal_or_restoration_refs,
                "relation.rollback.removal_or_restoration",
            ),
            (&self.invalidation_refs, "relation.rollback.invalidation"),
            (&self.raw_history_refs, "relation.rollback.raw_history"),
        ] {
            check_vec_bound(values.len(), MAX_ITEMS, field)?;
            for value in values {
                check_text(value, field, MAX_TEXT)?;
            }
        }
        check_text(&self.note, "relation.rollback.note", MAX_TEXT)
    }
}

/// Candidate-only typed relation proposal, retaining the entire input join.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationCandidate {
    pub candidate_id: String,
    pub relation_id: String,
    pub operation_id: String,
    pub input_digest: String,
    pub policy_digest: String,
    pub kind: CurationKind,
    pub family: RelationFamily,
    pub direction: RelationDirection,
    pub source_id: String,
    pub target_id: String,
    pub source_material_digest: String,
    pub target_material_digest: String,
    pub registry_digest: String,
    pub temporal: RelationTemporalEvidence,
    pub evidence_refs: Vec<String>,
    pub counterevidence_refs: Vec<String>,
    pub rival_refs: Vec<String>,
    pub no_relation_ref: Option<String>,
    pub before: Option<RelationSnapshot>,
    pub after: Option<RelationSnapshot>,
    pub preservation: RelationPreservation,
    pub rollback: RelationRollback,
    pub disposition: RelationDisposition,
    pub proof_ceiling: ProofCeiling,
}

impl RelationCandidate {
    /// Validates candidate closure against the exact supplied input.
    pub fn validate_against(&self, input: &RelationInput) -> Result<(), ContractViolation> {
        input.preflight()?;
        preflight_serialized(self, MAX_RESULT_BYTES, "relation.candidate_bytes")?;
        input.validate()?;
        self.validate_identity(input)?;
        self.validate_evidence_refs(input)?;
        self.validate_snapshots(input)?;
        self.validate_rollback(input)?;
        self.temporal.validate()?;
        self.preservation.validate()?;
        if self.disposition == RelationDisposition::Positive {
            self.preservation.overall()?;
        }
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(ContractViolation::ForbiddenCarry(
                "relation candidate exceeds candidate-only proof ceiling".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_identity(&self, input: &RelationInput) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.candidate_id, "relation.candidate_id"),
            (&self.relation_id, "relation.id"),
            (&self.operation_id, "relation.operation_id"),
        ] {
            check_text(value, field, MAX_TEXT)?;
        }
        for (value, field) in [
            (&self.input_digest, "relation.input_digest"),
            (&self.policy_digest, "relation.policy_digest"),
            (&self.registry_digest, "relation.registry_digest"),
            (
                &self.source_material_digest,
                "relation.source_material_digest",
            ),
            (
                &self.target_material_digest,
                "relation.target_material_digest",
            ),
        ] {
            digest(value, field)?;
        }
        if self.kind != CurationKind::Relation
            || self.family != input.family
            || self.direction != input.direction
            || self.operation_id != input.operation_id
            || self.policy_digest != input.policy_digest
            || self.source_id != input.source.endpoint_id()
            || self.target_id != input.target.endpoint_id()
            || self.source_material_digest != input.source.material_digest()
            || self.target_material_digest != input.target.material_digest()
            || self.registry_digest != input.registry.digest
            || self.temporal != input.temporal
            || self.preservation != input.preservation
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.candidate.identity",
                reason: "candidate identity differs from input".to_owned(),
            });
        }
        let expected = super::input::relation_input_digest(input)?;
        if self.input_digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.input_digest",
                reason: "candidate does not bind input".to_owned(),
            });
        }
        if self.candidate_id
            != Self::expected_candidate_id(
                &self.operation_id,
                &self.input_digest,
                &self.policy_digest,
                self.family,
                self.direction,
                &self.source_id,
                &self.target_id,
            )
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.candidate_id",
                reason: "candidate id is not derived from operation/input/policy/endpoints"
                    .to_owned(),
            });
        }
        Ok(())
    }

    fn validate_evidence_refs(&self, input: &RelationInput) -> Result<(), ContractViolation> {
        unique_refs(&self.evidence_refs, "relation.evidence_refs")?;
        unique_refs(&self.counterevidence_refs, "relation.counterevidence_refs")?;
        unique_refs(&self.rival_refs, "relation.rival_refs")?;
        let evidence = input.evidence.iter().chain(&input.counterevidence);
        let evidence_ids = evidence
            .clone()
            .map(super::input::RelationEvidence::evidence_id)
            .collect::<Vec<_>>();
        if self.evidence_refs.iter().any(|id| {
            !input
                .evidence
                .iter()
                .any(|value| value.evidence_id() == id && Self::is_primary_evidence(value, input))
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.evidence_refs",
                reason: "candidate evidence must resolve the primary predicate tuple".to_owned(),
            });
        }
        if self.counterevidence_refs.iter().any(|id| {
            !input
                .counterevidence
                .iter()
                .any(|value| value.evidence_id() == id && Self::is_primary_evidence(value, input))
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.counterevidence_refs",
                reason: "candidate counterevidence must resolve the primary predicate tuple"
                    .to_owned(),
            });
        }
        if self
            .evidence_refs
            .iter()
            .chain(&self.counterevidence_refs)
            .any(|id| !evidence_ids.contains(&id.as_str()))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.candidate.evidence_refs",
                reason: "candidate evidence is not retained in input".to_owned(),
            });
        }
        if self.rival_refs.iter().any(|id| {
            !input
                .rivals
                .iter()
                .any(|alternative| alternative.alternative_id == *id)
        }) {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.candidate.rival_refs",
                reason: "candidate rival is not retained in input".to_owned(),
            });
        }
        if let Some(value) = &self.no_relation_ref {
            check_text(value, "relation.no_relation_ref", MAX_TEXT)?;
            if input
                .no_relation_alternative
                .as_ref()
                .map(|alternative| &alternative.alternative_id)
                != Some(value)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.no_relation_ref",
                    reason: "candidate no-relation record is not retained in input".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn is_primary_evidence(
        evidence: &super::input::RelationEvidence,
        input: &RelationInput,
    ) -> bool {
        let predicate = &evidence.predicate;
        predicate.family == Some(input.family)
            && predicate.direction == Some(input.direction)
            && predicate.source_id == input.source.endpoint_id()
            && predicate.target_id == input.target.endpoint_id()
    }

    fn validate_snapshots(&self, input: &RelationInput) -> Result<(), ContractViolation> {
        if let Some(existing) = input
            .neighborhood
            .relations
            .iter()
            .find(|retained| retained.relation_id == self.relation_id)
        {
            let same_edge = existing.source_id == self.source_id
                && existing.target_id == self.target_id
                && existing.family == self.family
                && existing.direction == self.direction
                && existing.scope_id == input.scope_id
                && existing.state_fence == input.state_fence
                && existing.registry_digest == self.registry_digest
                && existing.temporal == self.temporal;
            if !same_edge
                && (self.disposition != RelationDisposition::Conflict || self.after.is_some())
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.id",
                    reason: "candidate relation id conflicts with retained edge identity"
                        .to_owned(),
                });
            }
        }
        if let Some(snapshot) = &self.before {
            snapshot.validate()?;
            let Some(retained) = input
                .neighborhood
                .relations
                .iter()
                .find(|retained| retained.relation_id == snapshot.relation_id)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.before",
                    reason: "before snapshot is not retained by neighborhood closure".to_owned(),
                });
            };
            if retained != snapshot {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.before",
                    reason: "before snapshot changed relative to retained neighborhood".to_owned(),
                });
            }
            if self.rollback.predecessor.as_deref() != Some(snapshot.relation_id.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.rollback.predecessor",
                    reason: "rollback predecessor must identify the retained before snapshot"
                        .to_owned(),
                });
            }
        }
        if let Some(snapshot) = &self.after {
            snapshot.validate()?;
            if snapshot.relation_id != self.relation_id
                || snapshot.source_id != self.source_id
                || snapshot.target_id != self.target_id
                || snapshot.family != self.family
                || snapshot.direction != self.direction
                || snapshot.scope_id != input.scope_id
                || snapshot.state_fence != input.state_fence
                || snapshot.registry_digest != self.registry_digest
                || snapshot.temporal != self.temporal
                || snapshot.predecessor != self.rollback.predecessor
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.after",
                    reason: "after snapshot does not equal candidate relation closure".to_owned(),
                });
            }
            if let Some(existing) = input
                .neighborhood
                .relations
                .iter()
                .find(|retained| retained.relation_id == snapshot.relation_id)
                && existing != snapshot
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.after",
                    reason: "after snapshot conflicts with an existing retained relation"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_rollback(&self, input: &RelationInput) -> Result<(), ContractViolation> {
        self.rollback.validate()?;
        self.validate_rollback_sets()?;
        let retained_relation_ids = input
            .neighborhood
            .relations
            .iter()
            .map(|snapshot| snapshot.relation_id.as_str())
            .chain(input.neighborhood.omitted_refs.iter().map(String::as_str))
            .collect::<Vec<_>>();
        if let Some(predecessor) = &self.rollback.predecessor
            && self.before.is_none()
            && !retained_relation_ids.contains(&predecessor.as_str())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.rollback.predecessor",
                reason: "rollback predecessor is not retained or explicitly omitted".to_owned(),
            });
        }
        let mut relation_refs = retained_relation_ids.clone();
        relation_refs.push(self.relation_id.as_str());
        for value in self
            .rollback
            .rollback_refs
            .iter()
            .chain(&self.rollback.removal_or_restoration_refs)
        {
            if !relation_refs.contains(&value.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.rollback.refs",
                    reason: "rollback reference must resolve a candidate or retained relation"
                        .to_owned(),
                });
            }
        }
        let condition_refs = input
            .neighborhood
            .relations
            .iter()
            .filter_map(|snapshot| snapshot.invalidation_condition.as_deref())
            .collect::<Vec<_>>();
        for value in &self.rollback.invalidation_refs {
            if !relation_refs.contains(&value.as_str()) && !condition_refs.contains(&value.as_str())
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.rollback.invalidation",
                    reason: "invalidation reference must resolve a retained relation or condition"
                        .to_owned(),
                });
            }
        }
        let mut history_refs = retained_relation_ids.clone();
        for endpoint in [&input.source, &input.target] {
            history_refs.extend(
                endpoint
                    .admitted
                    .source_handles
                    .iter()
                    .map(ArtifactId::as_str),
            );
        }
        for evidence in input.evidence.iter().chain(&input.counterevidence) {
            history_refs.extend(evidence.named.source_handles.iter().map(ArtifactId::as_str));
            if let Some(raw_handle) = evidence
                .named
                .foundation_evidence_envelope
                .provenance
                .raw_handle
                .as_deref()
            {
                history_refs.push(raw_handle);
            }
        }
        for snapshot in &input.neighborhood.relations {
            history_refs.extend(snapshot.provenance_refs.iter().map(String::as_str));
        }
        for value in &self.rollback.raw_history_refs {
            if !history_refs.contains(&value.as_str()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.rollback.raw_history",
                    reason: "raw-history reference must resolve retained history or provenance"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_rollback_sets(&self) -> Result<(), ContractViolation> {
        for (values, field) in [
            (&self.rollback.rollback_refs, "relation.rollback.refs"),
            (
                &self.rollback.removal_or_restoration_refs,
                "relation.rollback.removal_or_restoration",
            ),
            (
                &self.rollback.invalidation_refs,
                "relation.rollback.invalidation",
            ),
            (
                &self.rollback.raw_history_refs,
                "relation.rollback.raw_history",
            ),
        ] {
            unique_refs(values, field)?;
        }
        Ok(())
    }
    /// Deterministic candidate identity over the complete directional join.
    #[must_use]
    pub fn expected_candidate_id(
        operation_id: &str,
        input_digest: &str,
        policy_digest: &str,
        family: RelationFamily,
        direction: RelationDirection,
        source_id: &str,
        target_id: &str,
    ) -> String {
        format!(
            "relation:{operation_id}:{input_digest}:{policy_digest}:{}:{}:{source_id}:{target_id}",
            family.as_str(),
            direction.as_str()
        )
    }

    pub(crate) fn normalized_for_digest(&self) -> Result<Self, ContractViolation> {
        self.preservation.validate()?;
        self.rollback.validate()?;
        let mut normalized = self.clone();
        normalized.evidence_refs.sort();
        normalized.counterevidence_refs.sort();
        normalized.rival_refs.sort();
        normalized.rollback.rollback_refs.sort();
        normalized.rollback.removal_or_restoration_refs.sort();
        normalized.rollback.invalidation_refs.sort();
        normalized.rollback.raw_history_refs.sort();
        normalized
            .preservation
            .verdicts
            .sort_by_key(|value| value.dimension.as_str());
        normalized.before = normalized.before.map(|mut value| {
            value.provenance_refs.sort();
            value
        });
        normalized.after = normalized.after.map(|mut value| {
            value.provenance_refs.sort();
            value
        });
        Ok(normalized)
    }
}

/// Closed result after input acceptance and candidate sealing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationCandidateClosure {
    pub schema_version: u32,
    pub input: RelationInput,
    pub input_digest: String,
    pub candidate: RelationCandidate,
    pub accepted_item_digest: String,
    pub result_digest: String,
}

impl RelationCandidateClosure {
    /// Validates the sealed closure and recomputed result identity.
    pub fn validate(&self, input: &RelationInput) -> Result<(), ContractViolation> {
        if self.schema_version != 1 {
            return Err(ContractViolation::OutOfBounds {
                field: "relation.result.schema_version",
                min: 1,
                max: 1,
                got: i64::from(self.schema_version),
            });
        }
        preflight_serialized(self, MAX_RESULT_BYTES, "relation.result_bytes")?;
        self.input.validate()?;
        if super::input::relation_input_digest(&self.input)?
            != super::input::relation_input_digest(input)?
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.result.input",
                reason: "sealed closure input differs from supplied input".to_owned(),
            });
        }
        self.candidate.validate_against(&self.input)?;
        if self.input_digest != self.candidate.input_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.result.input_digest",
                reason: "result input digest drift".to_owned(),
            });
        }
        digest(&self.accepted_item_digest, "relation.accepted_item_digest")?;
        if self.accepted_item_digest != self.input.screen.item_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.accepted_item_digest",
                reason: "accepted item digest differs from retained screen binding".to_owned(),
            });
        }
        digest(&self.result_digest, "relation.result_digest")?;
        let expected = result_digest(input, &self.candidate, &self.accepted_item_digest)?;
        if self.result_digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.result_digest",
                reason: "result digest drift".to_owned(),
            });
        }
        Ok(())
    }
}

fn result_digest(
    input: &RelationInput,
    candidate: &RelationCandidate,
    accepted_item_digest: &str,
) -> Result<String, ContractViolation> {
    preflight_serialized(input, MAX_RESULT_BYTES, "relation.result.input_bytes")?;
    preflight_serialized(
        candidate,
        MAX_RESULT_BYTES,
        "relation.result.candidate_bytes",
    )?;
    let normalized_input = input.normalized_for_digest()?;
    let normalized = candidate.normalized_for_digest()?;
    let preimage = (normalized_input, accepted_item_digest, normalized);
    Ok(digest_hex(&canonical_bytes(&preimage)?))
}

/// Seals a supplied candidate after the accepted A03 curation seam.
pub fn seal_relation(
    input: RelationInput,
    candidate: RelationCandidate,
    ctx: &CurationAcceptanceCtx<'_>,
) -> Result<RelationCandidateClosure, ContractViolation> {
    input.validate_acceptance(ctx)?;
    candidate.validate_against(&input)?;
    let input_digest = candidate.input_digest.clone();
    let accepted_item_digest = input.item.item_digest(ctx.grounded)?;
    if accepted_item_digest != input.screen.item_digest {
        return Err(ContractViolation::BindingMismatch {
            field: "relation.accepted_item_digest",
            reason: "accepted item digest differs from retained screen binding".to_owned(),
        });
    }
    let mut closure = RelationCandidateClosure {
        schema_version: 1,
        input,
        input_digest,
        candidate,
        accepted_item_digest,
        result_digest: "0".repeat(64),
    };
    preflight_serialized(&closure, MAX_RESULT_BYTES, "relation.result_bytes")?;
    closure.result_digest = result_digest(
        &closure.input,
        &closure.candidate,
        &closure.accepted_item_digest,
    )?;
    preflight_serialized(&closure, MAX_RESULT_BYTES, "relation.result_bytes")?;
    Ok(closure)
}
