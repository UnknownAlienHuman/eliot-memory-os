//! Bounded relation input closure and structural joins.
use super::registry::{RelationDirection, RelationFamily, RelationRegistrySnapshot};
use super::result::RelationPreservation;
use crate::classification::{AdmittedTargetRef, ClassificationRecordFamily, NamedEvidence};
use crate::curation::{CurationKind, CurationPayload};
use crate::draft::{CurationAcceptanceCtx, ValidatedCurationItem};
use crate::encoding::{canonical_bytes, digest_hex};
use crate::error::{ContractViolation, check_fence, check_text, check_vec_bound, is_hex64_lower};
use crate::screen::{ScreenBinding, ScreenState};
use eliot_contracts::{ClockReading, StateFence};
use eliot_evidence::{EpistemicStatus, LifecycleState};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};
const SCHEMA_VERSION: u32 = 1;
const MAX_TEXT: usize = 1024;
const MAX_ITEMS: usize = 256;
const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
fn check_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "must be lowercase sha256".to_owned(),
        })
    }
}
fn check_id(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    check_text(value, field, MAX_TEXT)
}
fn check_set(values: &[String], field: &'static str, cap: usize) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), cap, field)?;
    for (index, value) in values.iter().enumerate() {
        check_text(value, field, MAX_TEXT)?;
        if values[..index].contains(value) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "duplicate set member".to_owned(),
            });
        }
    }
    Ok(())
}
fn check_alternatives(
    values: &[RelationAlternative],
    field: &'static str,
) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_ITEMS, field)?;
    for (index, value) in values.iter().enumerate() {
        value.validate()?;
        if values[..index]
            .iter()
            .any(|prior| prior.alternative_id == value.alternative_id)
        {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "duplicate alternative identity".to_owned(),
            });
        }
    }
    Ok(())
}

/// Exact admitted endpoint identity supplied by the admission owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationEndpoint {
    pub admitted: AdmittedTargetRef,
    pub record_family: ClassificationRecordFamily,
    pub role: String,
    pub privacy_class: String,
    pub validity: String,
    pub authority: String,
    pub status: EpistemicStatus,
}
impl RelationEndpoint {
    /// Checks typed identity shape and bounded lineage.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.role, "endpoint.role"),
            (&self.privacy_class, "endpoint.privacy_class"),
            (&self.validity, "endpoint.validity"),
            (&self.authority, "endpoint.authority"),
        ] {
            check_id(value, field)?;
        }
        check_id(self.admitted.target_id.as_str(), "endpoint.id")?;
        check_id(&self.admitted.target_revision, "endpoint.revision")?;
        check_digest(&self.admitted.target_digest, "endpoint.content_digest")?;
        check_id(
            self.admitted.admission.receipt_id.as_str(),
            "endpoint.receipt_id",
        )?;
        check_digest(
            &self.admitted.admission.canonical_sha256,
            "endpoint.admission_digest",
        )?;
        check_id(self.admitted.task_id.as_str(), "endpoint.task_id")?;
        check_id(self.admitted.scope_id.as_str(), "endpoint.scope_id")?;
        check_fence(&self.admitted.state_fence)?;
        check_vec_bound(
            self.admitted.source_handles.len(),
            MAX_ITEMS,
            "endpoint.source_refs",
        )?;
        for (index, handle) in self.admitted.source_handles.iter().enumerate() {
            check_id(handle.as_str(), "endpoint.source_refs")?;
            if self.admitted.source_handles[..index].contains(handle) {
                return Err(ContractViolation::Registry(
                    "duplicate endpoint source ref".to_owned(),
                ));
            }
        }
        Ok(())
    }
    #[must_use]
    pub fn endpoint_id(&self) -> &str {
        self.admitted.target_id.as_str()
    }
    #[must_use]
    pub fn material_digest(&self) -> &str {
        &self.admitted.target_digest
    }
}

/// Polarity of a supplied grounded relation statement.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationEvidencePolarity {
    Support,
    Counter,
    Unknown,
}
/// Predicate identity is bound to the exact directed endpoint pair.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationPredicate {
    pub family: Option<RelationFamily>,
    pub direction: Option<RelationDirection>,
    pub source_id: String,
    pub target_id: String,
    pub expression: String,
}
impl RelationPredicate {
    fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.source_id, "predicate.source_id")?;
        check_id(&self.target_id, "predicate.target_id")?;
        check_id(&self.expression, "predicate.expression")?;
        if self.family.is_some() != self.direction.is_some() {
            return Err(ContractViolation::BindingMismatch {
                field: "predicate.relation_options",
                reason: "family and direction must both be present or absent".to_owned(),
            });
        }
        Ok(())
    }
}
/// Grounded predicate/evidence with lineage and dependence retained.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationEvidence {
    pub named: NamedEvidence,
    pub predicate: RelationPredicate,
    pub polarity: RelationEvidencePolarity,
    pub relation_role: String,
}
impl RelationEvidence {
    fn validate(&self) -> Result<(), ContractViolation> {
        check_id(self.named.id.as_str(), "evidence.id")?;
        self.named.validate()?;
        self.predicate.validate()?;
        check_id(&self.relation_role, "evidence.relation_role")?;
        Ok(())
    }
    #[must_use]
    pub fn evidence_id(&self) -> &str {
        self.named.id.as_str()
    }
}

/// Retained rival or no-relation record for downstream semantic selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationAlternative {
    pub alternative_id: String,
    pub family: Option<RelationFamily>,
    pub direction: Option<RelationDirection>,
    pub source_id: String,
    pub target_id: String,
    pub source_revision: String,
    pub target_revision: String,
    pub source_material_digest: String,
    pub target_material_digest: String,
    pub source_admission_id: String,
    pub target_admission_id: String,
    pub source_admission_digest: String,
    pub target_admission_digest: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub registry_digest: String,
    pub evidence_refs: Vec<String>,
}
impl RelationAlternative {
    fn validate(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.alternative_id, "alternative.id"),
            (&self.source_id, "alternative.source_id"),
            (&self.target_id, "alternative.target_id"),
            (&self.source_revision, "alternative.source_revision"),
            (&self.target_revision, "alternative.target_revision"),
            (&self.source_admission_id, "alternative.source_admission_id"),
            (&self.target_admission_id, "alternative.target_admission_id"),
            (&self.scope_id, "alternative.scope_id"),
        ] {
            check_id(value, field)?;
        }
        for (value, field) in [
            (
                &self.source_material_digest,
                "alternative.source_material_digest",
            ),
            (
                &self.target_material_digest,
                "alternative.target_material_digest",
            ),
            (
                &self.source_admission_digest,
                "alternative.source_admission_digest",
            ),
            (
                &self.target_admission_digest,
                "alternative.target_admission_digest",
            ),
            (&self.registry_digest, "alternative.registry_digest"),
        ] {
            check_digest(value, field)?;
        }
        if self.family.is_some() != self.direction.is_some() {
            return Err(ContractViolation::BindingMismatch {
                field: "alternative.relation_options",
                reason: "family and direction must both be present or absent".to_owned(),
            });
        }
        check_fence(&self.state_fence)?;
        check_set(&self.evidence_refs, "alternative.evidence_refs", MAX_ITEMS)
    }
}

/// One clock reading; clock domains are intentionally never ordered here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationTimePoint {
    pub reading: ClockReading,
    pub clock_ref: String,
    pub uncertainty_ms: u64,
    pub conversion_ref: Option<String>,
}
impl RelationTimePoint {
    fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.clock_ref, "time.clock_ref")?;
        self.reading
            .validate()
            .map_err(|error| ContractViolation::Malformed {
                field: "time.reading",
                reason: error.to_string(),
            })?;
        if let Some(value) = &self.conversion_ref {
            check_id(value, "time.conversion_ref")?;
        }
        Ok(())
    }
}
/// Typed privacy/disclosure evidence; absence remains unknown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationDisclosureEvidence {
    pub owner: String,
    pub ref_id: String,
    pub digest: String,
    pub source_id: String,
    pub target_id: String,
    pub source_revision: String,
    pub target_revision: String,
    pub source_material_digest: String,
    pub target_material_digest: String,
    pub source_admission_id: String,
    pub target_admission_id: String,
    pub source_admission_digest: String,
    pub target_admission_digest: String,
    pub family: RelationFamily,
    pub direction: RelationDirection,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub permitted: Option<bool>,
    pub decision: EpistemicStatus,
}
impl RelationDisclosureEvidence {
    fn validate(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.owner, "disclosure.owner"),
            (&self.ref_id, "disclosure.ref_id"),
            (&self.source_id, "disclosure.source_id"),
            (&self.target_id, "disclosure.target_id"),
            (&self.source_revision, "disclosure.source_revision"),
            (&self.target_revision, "disclosure.target_revision"),
            (&self.source_admission_id, "disclosure.source_admission_id"),
            (&self.target_admission_id, "disclosure.target_admission_id"),
            (&self.scope_id, "disclosure.scope_id"),
        ] {
            check_id(value, field)?;
        }
        for (value, field) in [
            (&self.digest, "disclosure.digest"),
            (
                &self.source_material_digest,
                "disclosure.source_material_digest",
            ),
            (
                &self.target_material_digest,
                "disclosure.target_material_digest",
            ),
            (
                &self.source_admission_digest,
                "disclosure.source_admission_digest",
            ),
            (
                &self.target_admission_digest,
                "disclosure.target_admission_digest",
            ),
        ] {
            check_digest(value, field)?;
        }
        check_fence(&self.state_fence)
    }
}
/// Independent event/effective/observation/ingestion/commit readings.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationTemporalEvidence {
    pub event_time: Option<RelationTimePoint>,
    pub effective_time: Option<RelationTimePoint>,
    pub observation_time: Option<RelationTimePoint>,
    pub ingestion_time: Option<RelationTimePoint>,
    pub commit_time: Option<RelationTimePoint>,
    pub temporal_status: EpistemicStatus,
    pub uncertainty_ref: Option<String>,
}
impl RelationTemporalEvidence {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        for point in [
            &self.event_time,
            &self.effective_time,
            &self.observation_time,
            &self.ingestion_time,
            &self.commit_time,
        ]
        .into_iter()
        .flatten()
        {
            point.validate()?;
        }
        if let Some(value) = &self.uncertainty_ref {
            check_id(value, "time.uncertainty_ref")?;
        }
        Ok(())
    }
}
/// Independent verifier identity and exact proof binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationVerifier {
    pub verifier_id: String,
    pub owner: String,
    pub revision: String,
    pub digest: String,
}
impl RelationVerifier {
    fn validate(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.verifier_id, "verifier.id"),
            (&self.owner, "verifier.owner"),
            (&self.revision, "verifier.revision"),
        ] {
            check_id(value, field)?;
        }
        check_digest(&self.digest, "verifier.digest")
    }
}
/// Existing relation identity supplied by a bounded neighborhood read.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationSnapshot {
    pub relation_id: String,
    pub source_id: String,
    pub target_id: String,
    pub family: RelationFamily,
    pub direction: RelationDirection,
    pub scope_id: String,
    pub registry_digest: String,
    pub relation_digest: String,
    pub state_fence: StateFence,
    pub temporal: RelationTemporalEvidence,
    pub adapter_revision: String,
    pub build_revision: String,
    pub invalidation_condition: Option<String>,
    pub status: EpistemicStatus,
    pub lifecycle: LifecycleState,
    pub provenance_refs: Vec<String>,
    pub predecessor: Option<String>,
}
impl RelationSnapshot {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.relation_id, "relation.id"),
            (&self.source_id, "relation.source_id"),
            (&self.target_id, "relation.target_id"),
            (&self.scope_id, "relation.scope_id"),
            (&self.adapter_revision, "relation.adapter_revision"),
            (&self.build_revision, "relation.build_revision"),
        ] {
            check_id(value, field)?;
        }
        check_digest(&self.registry_digest, "relation.registry_digest")?;
        check_digest(&self.relation_digest, "relation.digest")?;
        check_fence(&self.state_fence)?;
        self.temporal.validate()?;
        if let Some(value) = &self.invalidation_condition {
            check_id(value, "relation.invalidation_condition")?;
        }
        check_set(&self.provenance_refs, "relation.provenance_refs", MAX_ITEMS)?;
        if let Some(value) = &self.predecessor {
            check_id(value, "relation.predecessor")?;
        }
        Ok(())
    }
}
/// Bounded immutable neighborhood snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationNeighborhood {
    pub snapshot_id: String,
    pub revision: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub complete: bool,
    pub relations: Vec<RelationSnapshot>,
    pub omitted_refs: Vec<String>,
    pub coverage_note: String,
}
impl RelationNeighborhood {
    pub(crate) fn validate(&self) -> Result<(), ContractViolation> {
        for (value, field) in [
            (&self.snapshot_id, "neighborhood.id"),
            (&self.revision, "neighborhood.revision"),
            (&self.scope_id, "neighborhood.scope_id"),
        ] {
            check_id(value, field)?;
        }
        check_fence(&self.state_fence)?;
        check_vec_bound(self.relations.len(), MAX_ITEMS, "neighborhood.relations")?;
        check_set(&self.omitted_refs, "neighborhood.omitted_refs", MAX_ITEMS)?;
        if self.complete && !self.omitted_refs.is_empty() {
            return Err(ContractViolation::Registry(
                "complete neighborhood cannot omit relations".to_owned(),
            ));
        }
        if !self.complete && self.omitted_refs.is_empty() {
            return Err(ContractViolation::Registry(
                "partial neighborhood requires explicit omitted relations".to_owned(),
            ));
        }
        check_id(&self.coverage_note, "neighborhood.coverage_note")?;
        for (index, relation) in self.relations.iter().enumerate() {
            relation.validate()?;
            if self.relations[..index]
                .iter()
                .any(|prior| prior.relation_id == relation.relation_id)
            {
                return Err(ContractViolation::Registry(
                    "duplicate neighborhood relation".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Complete immutable A03 relation input. All semantic choices are supplied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RelationInput {
    pub schema_version: u32,
    pub operation_id: String,
    pub request_id: String,
    pub idempotency_key: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub policy_digest: String,
    pub item: ValidatedCurationItem,
    pub source: RelationEndpoint,
    pub target: RelationEndpoint,
    pub family: RelationFamily,
    pub direction: RelationDirection,
    pub registry: RelationRegistrySnapshot,
    pub neighborhood: RelationNeighborhood,
    pub screen: ScreenBinding,
    pub evidence: Vec<RelationEvidence>,
    pub counterevidence: Vec<RelationEvidence>,
    pub rivals: Vec<RelationAlternative>,
    pub no_relation_alternative: Option<RelationAlternative>,
    pub temporal: RelationTemporalEvidence,
    pub verifier: Option<RelationVerifier>,
    pub disclosure_evidence: Option<RelationDisclosureEvidence>,
    pub preservation: RelationPreservation,
}
impl RelationInput {
    /// Serializes by borrow before any normalization clone or digest work.
    pub fn preflight(&self) -> Result<(), ContractViolation> {
        preflight_serialized(self, MAX_INPUT_BYTES, "relation.input_bytes")
    }
    /// Validates the complete structural closure in named phases.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.preflight()?;
        self.validate_header()?;
        self.validate_registry_and_endpoints()?;
        self.validate_neighborhood()?;
        self.validate_evidence_alternatives()?;
        self.validate_temporal_screen()?;
        self.preservation.validate()
    }
    fn validate_header(&self) -> Result<(), ContractViolation> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "relation.schema_version",
                min: 1,
                max: 1,
                got: i64::from(self.schema_version),
            });
        }
        for (value, field) in [
            (&self.operation_id, "relation.operation_id"),
            (&self.request_id, "relation.request_id"),
            (&self.idempotency_key, "relation.idempotency_key"),
            (&self.task_id, "relation.task_id"),
            (&self.scope_id, "relation.scope_id"),
        ] {
            check_id(value, field)?;
        }
        check_digest(&self.policy_digest, "relation.policy_digest")?;
        check_fence(&self.state_fence)?;
        self.item.validate()?;
        if self.item.kind_spelling != CurationKind::Relation.as_str()
            || self.item.payload.kind() != CurationKind::Relation
        {
            return Err(ContractViolation::KindPayload(
                "relation input requires a Relation curation item".to_owned(),
            ));
        }
        Ok(())
    }
    fn validate_registry_and_endpoints(&self) -> Result<(), ContractViolation> {
        self.registry.validate()?;
        if !self.registry.allowed_families.contains(&self.family)
            || !self.registry.denominator.contains(&self.family)
        {
            return Err(ContractViolation::UnknownVariant {
                field: "relation.family",
                value: self.family.as_str().to_owned(),
            });
        }
        let Some(rule) = self
            .registry
            .rules
            .iter()
            .find(|rule| rule.family == self.family)
        else {
            return Err(ContractViolation::Registry(
                "missing per-family relation rule".to_owned(),
            ));
        };
        if rule.direction != self.direction {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.direction",
                reason: "direction differs from registry rule".to_owned(),
            });
        }
        self.source.validate()?;
        self.target.validate()?;
        if self.source.admitted.scope_id.as_str() != self.scope_id
            || self.target.admitted.scope_id.as_str() != self.scope_id
            || self.source.admitted.task_id.as_str() != self.task_id
            || self.target.admitted.task_id.as_str() != self.task_id
            || self.source.admitted.state_fence != self.state_fence
            || self.target.admitted.state_fence != self.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.scope_fence",
                reason: "endpoints do not join input task/scope/fence".to_owned(),
            });
        }
        if self.source.endpoint_id() == self.target.endpoint_id() && !rule.permits_self_relation {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.self_relation",
                reason: "registry forbids self relation".to_owned(),
            });
        }
        if !rule
            .source_roles
            .iter()
            .any(|role| role == &self.source.role)
            || !rule
                .target_roles
                .iter()
                .any(|role| role == &self.target.role)
            || !rule
                .source_record_families
                .contains(&self.source.record_family)
            || !rule
                .target_record_families
                .contains(&self.target.record_family)
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.endpoint_roles",
                reason: "endpoint role or record family outside registry rule".to_owned(),
            });
        }
        let CurationPayload::Relation(payload) = &self.item.payload else {
            return Err(ContractViolation::KindPayload(
                "relation payload discriminator mismatch".to_owned(),
            ));
        };
        if payload.from_handle != self.source.endpoint_id()
            || payload.to_handle != self.target.endpoint_id()
            || payload.relation != self.family.as_str()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.curation_endpoints",
                reason: "curation endpoints or family drift".to_owned(),
            });
        }
        Ok(())
    }
    fn validate_neighborhood(&self) -> Result<(), ContractViolation> {
        self.neighborhood.validate()?;
        if self.neighborhood.scope_id != self.scope_id
            || self.neighborhood.state_fence != self.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.neighborhood",
                reason: "neighborhood scope/fence drift".to_owned(),
            });
        }
        for relation in &self.neighborhood.relations {
            if relation.scope_id != self.scope_id
                || relation.state_fence != self.state_fence
                || relation.registry_digest != self.registry.digest
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.neighborhood",
                    reason: "relation snapshot scope/fence/registry drift".to_owned(),
                });
            }
            if let Some(predecessor) = &relation.predecessor
                && !self
                    .neighborhood
                    .relations
                    .iter()
                    .any(|candidate| &candidate.relation_id == predecessor)
                && !self.neighborhood.omitted_refs.contains(predecessor)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.predecessor",
                    reason: "predecessor is not retained or explicitly omitted".to_owned(),
                });
            }
        }
        Ok(())
    }
    fn alternative_matches_primary(&self, alternative: &RelationAlternative) -> bool {
        let forward = alternative.source_id == self.source.endpoint_id()
            && alternative.target_id == self.target.endpoint_id()
            && alternative.source_revision == self.source.admitted.target_revision
            && alternative.target_revision == self.target.admitted.target_revision
            && alternative.source_material_digest == self.source.material_digest()
            && alternative.target_material_digest == self.target.material_digest()
            && alternative.source_admission_id
                == self.source.admitted.admission.receipt_id.as_str()
            && alternative.target_admission_id
                == self.target.admitted.admission.receipt_id.as_str()
            && alternative.source_admission_digest
                == self.source.admitted.admission.canonical_sha256
            && alternative.target_admission_digest
                == self.target.admitted.admission.canonical_sha256;
        let reverse = alternative.source_id == self.target.endpoint_id()
            && alternative.target_id == self.source.endpoint_id()
            && alternative.source_revision == self.target.admitted.target_revision
            && alternative.target_revision == self.source.admitted.target_revision
            && alternative.source_material_digest == self.target.material_digest()
            && alternative.target_material_digest == self.source.material_digest()
            && alternative.source_admission_id
                == self.target.admitted.admission.receipt_id.as_str()
            && alternative.target_admission_id
                == self.source.admitted.admission.receipt_id.as_str()
            && alternative.source_admission_digest
                == self.target.admitted.admission.canonical_sha256
            && alternative.target_admission_digest
                == self.source.admitted.admission.canonical_sha256;
        forward || reverse
    }

    fn predicate_pair_is_primary(&self, predicate: &RelationPredicate) -> bool {
        predicate.source_id == self.source.endpoint_id()
            && predicate.target_id == self.target.endpoint_id()
    }

    fn validate_evidence_alternatives(&self) -> Result<(), ContractViolation> {
        self.validate_evidence_envelopes()?;
        self.validate_alternative_records()?;
        self.validate_predicate_bindings()
    }

    fn validate_evidence_envelopes(&self) -> Result<(), ContractViolation> {
        Self::validate_evidence(&self.evidence, "evidence")?;
        Self::validate_evidence(&self.counterevidence, "counterevidence")?;
        let mut evidence_ids = Vec::new();
        for evidence in self.evidence.iter().chain(&self.counterevidence) {
            if evidence_ids.contains(&evidence.evidence_id()) {
                return Err(ContractViolation::Registry(
                    "duplicate evidence identity across polarity sets".to_owned(),
                ));
            }
            evidence_ids.push(evidence.evidence_id());
            let envelope = &evidence.named.foundation_evidence_envelope;
            if envelope.provenance.scope != self.scope_id
                || envelope.state_fence != self.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.evidence.provenance",
                    reason: "evidence envelope scope or fence drift".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_alternative_records(&self) -> Result<(), ContractViolation> {
        check_alternatives(&self.rivals, "relation.rivals")?;
        if self
            .rivals
            .iter()
            .any(|alternative| alternative.family.is_none() && alternative.direction.is_none())
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.rivals",
                reason: "no-relation alternatives belong in the dedicated field".to_owned(),
            });
        }
        if let Some(no_relation) = &self.no_relation_alternative {
            no_relation.validate()?;
            if no_relation.family.is_some() || no_relation.direction.is_some() {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.no_relation_alternative",
                    reason: "no-relation alternative must have no family or direction".to_owned(),
                });
            }
            if self
                .rivals
                .iter()
                .any(|alternative| alternative.alternative_id == no_relation.alternative_id)
            {
                return Err(ContractViolation::Registry(
                    "no-relation alternative identity duplicates a rival".to_owned(),
                ));
            }
        }
        let retained_ids = self
            .evidence
            .iter()
            .chain(&self.counterevidence)
            .map(RelationEvidence::evidence_id)
            .collect::<Vec<_>>();
        for alternative in self
            .rivals
            .iter()
            .chain(self.no_relation_alternative.iter())
        {
            if alternative.scope_id != self.scope_id
                || alternative.state_fence != self.state_fence
                || alternative.registry_digest != self.registry.digest
                || !self.alternative_matches_primary(alternative)
                || alternative
                    .evidence_refs
                    .iter()
                    .any(|id| !retained_ids.contains(&id.as_str()))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.alternative",
                    reason: "alternative endpoint or evidence closure drift".to_owned(),
                });
            }
            for evidence_ref in &alternative.evidence_refs {
                if !self
                    .evidence
                    .iter()
                    .chain(&self.counterevidence)
                    .any(|evidence| {
                        evidence.evidence_id() == evidence_ref
                            && evidence.predicate.family == alternative.family
                            && evidence.predicate.direction == alternative.direction
                            && evidence.predicate.source_id == alternative.source_id
                            && evidence.predicate.target_id == alternative.target_id
                    })
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "relation.alternative.evidence",
                        reason: "alternative evidence does not carry the alternative tuple"
                            .to_owned(),
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_predicate_bindings(&self) -> Result<(), ContractViolation> {
        for evidence in self.evidence.iter().chain(&self.counterevidence) {
            let primary = evidence.predicate.family == Some(self.family)
                && evidence.predicate.direction == Some(self.direction)
                && self.predicate_pair_is_primary(&evidence.predicate);
            let alternative = self
                .rivals
                .iter()
                .chain(self.no_relation_alternative.iter())
                .any(|candidate| {
                    candidate.family == evidence.predicate.family
                        && candidate.direction == evidence.predicate.direction
                        && candidate.source_id == evidence.predicate.source_id
                        && candidate.target_id == evidence.predicate.target_id
                        && candidate
                            .evidence_refs
                            .iter()
                            .any(|id| id == evidence.evidence_id())
                });
            if !primary && !alternative {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.evidence.predicate",
                    reason: "predicate is not bound to exact relation or retained alternative"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
    fn validate_temporal_screen(&self) -> Result<(), ContractViolation> {
        self.temporal.validate()?;
        if let Some(verifier) = &self.verifier {
            verifier.validate()?;
        }
        if let Some(value) = &self.disclosure_evidence {
            value.validate()?;
            if value.source_id != self.source.endpoint_id()
                || value.target_id != self.target.endpoint_id()
                || value.source_revision != self.source.admitted.target_revision
                || value.target_revision != self.target.admitted.target_revision
                || value.source_material_digest != self.source.material_digest()
                || value.target_material_digest != self.target.material_digest()
                || value.source_admission_id != self.source.admitted.admission.receipt_id.as_str()
                || value.target_admission_id != self.target.admitted.admission.receipt_id.as_str()
                || value.source_admission_digest != self.source.admitted.admission.canonical_sha256
                || value.target_admission_digest != self.target.admitted.admission.canonical_sha256
                || value.family != self.family
                || value.direction != self.direction
                || value.scope_id != self.scope_id
                || value.state_fence != self.state_fence
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.disclosure",
                    reason: "disclosure decision is not bound to exact relation".to_owned(),
                });
            }
        }
        self.screen.validate()?;
        if self.screen.state != ScreenState::Eligible
            || self.screen.task_id != self.task_id
            || self.screen.scope_id != self.scope_id
            || self.screen.state_fence != self.state_fence
        {
            return Err(ContractViolation::ScreenIneligible(
                "relation requires exact eligible screen binding".to_owned(),
            ));
        }
        Ok(())
    }
    fn validate_evidence(
        values: &[RelationEvidence],
        field: &'static str,
    ) -> Result<(), ContractViolation> {
        check_vec_bound(values.len(), MAX_ITEMS, field)?;
        for (index, value) in values.iter().enumerate() {
            value.validate()?;
            if values[..index]
                .iter()
                .any(|prior| prior.evidence_id() == value.evidence_id())
            {
                return Err(ContractViolation::Registry(format!(
                    "duplicate {field} identity"
                )));
            }
        }
        Ok(())
    }
    /// Accepted-item seam: compares the supplied context, then validates joins.
    pub fn validate_acceptance(
        &self,
        ctx: &CurationAcceptanceCtx<'_>,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        preflight_serialized(ctx.job, MAX_INPUT_BYTES, "relation.acceptance.job_bytes")?;
        preflight_serialized(
            ctx.bundle,
            MAX_INPUT_BYTES,
            "relation.acceptance.bundle_bytes",
        )?;
        preflight_serialized(
            ctx.receipt,
            MAX_INPUT_BYTES,
            "relation.acceptance.receipt_bytes",
        )?;
        preflight_serialized(
            ctx.screen,
            MAX_INPUT_BYTES,
            "relation.acceptance.screen_bytes",
        )?;
        preflight_serialized(
            ctx.grounded,
            MAX_INPUT_BYTES,
            "relation.acceptance.grounded_bytes",
        )?;
        preflight_serialized(
            ctx.request,
            MAX_INPUT_BYTES,
            "relation.acceptance.request_bytes",
        )?;
        preflight_serialized(
            ctx.usage,
            MAX_INPUT_BYTES,
            "relation.acceptance.usage_bytes",
        )?;
        self.item.accept(ctx)?;
        if self.screen != *ctx.screen {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.screen",
                reason: "retained screen differs from accepted screen".to_owned(),
            });
        }
        if self.operation_id != ctx.job.operation_id
            || self.idempotency_key != ctx.job.idempotency_key
            || self.request_id != ctx.request.request_id
            || self.task_id != ctx.job.task_id
            || self.scope_id != ctx.job.scope_id
            || self.state_fence != ctx.job.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "relation.acceptance.identity",
                reason: "operation/request/task/scope/fence drift".to_owned(),
            });
        }
        for endpoint in [&self.source, &self.target] {
            if !ctx.bundle.materials.iter().any(|material| {
                material.handle == endpoint.endpoint_id()
                    && material.digest == endpoint.material_digest()
            }) {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.endpoint_material",
                    reason: "endpoint material handle and digest absent from accepted bundle"
                        .to_owned(),
                });
            }
        }
        for evidence in self.evidence.iter().chain(&self.counterevidence) {
            let require_material = |handle: &str| {
                ctx.bundle
                    .materials
                    .iter()
                    .any(|material| material.handle == handle)
            };
            if !require_material(evidence.evidence_id()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.evidence_material",
                    reason: "evidence identity absent from accepted bundle".to_owned(),
                });
            }
            for handle in &evidence.named.source_handles {
                if !require_material(handle.as_str()) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "relation.evidence_source_material",
                        reason: "evidence source handle absent from accepted bundle".to_owned(),
                    });
                }
            }
            if let Some(raw_handle) = evidence
                .named
                .foundation_evidence_envelope
                .provenance
                .raw_handle
                .as_deref()
                && !require_material(raw_handle)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "relation.evidence_raw_material",
                    reason: "evidence raw handle absent from accepted bundle".to_owned(),
                });
            }
        }
        Ok(())
    }
    /// Returns a clone with only set-like fields normalized for identity.
    pub(crate) fn normalized_for_digest(&self) -> Result<Self, ContractViolation> {
        self.validate()?;
        let mut normalized = self.clone();
        normalized.item.payload = normalized.item.payload.normalized_for_digest();
        normalized.registry = normalized.registry.normalized_for_digest()?;
        normalized
            .evidence
            .sort_by_key(|value| value.evidence_id().to_owned());
        normalized
            .counterevidence
            .sort_by_key(|value| value.evidence_id().to_owned());
        normalized
            .rivals
            .sort_by_key(|value| value.alternative_id.clone());
        normalized
            .neighborhood
            .relations
            .sort_by_key(|value| value.relation_id.clone());
        normalized.neighborhood.omitted_refs.sort();
        normalized.screen.screened_targets.sort();
        for endpoint in [&mut normalized.source, &mut normalized.target] {
            endpoint
                .admitted
                .source_handles
                .sort_by_key(|id| id.as_str().to_owned());
        }
        for relation in &mut normalized.neighborhood.relations {
            relation.provenance_refs.sort();
        }
        for alternative in &mut normalized.rivals {
            alternative.evidence_refs.sort();
        }
        if let Some(alternative) = &mut normalized.no_relation_alternative {
            alternative.evidence_refs.sort();
        }
        for evidence in normalized
            .evidence
            .iter_mut()
            .chain(normalized.counterevidence.iter_mut())
        {
            evidence
                .named
                .source_handles
                .sort_by_key(|id| id.as_str().to_owned());
            evidence.named.dependence_groups.sort();
        }
        normalized
            .preservation
            .verdicts
            .sort_by_key(|value| value.dimension.as_str());
        Ok(normalized)
    }
}
/// Digest of a validated input closure.
pub fn relation_input_digest(input: &RelationInput) -> Result<String, ContractViolation> {
    let normalized = input.normalized_for_digest()?;
    Ok(digest_hex(&canonical_bytes(&normalized)?))
}
/// Structural validator alias for consumers.
pub fn validate_relation(input: &RelationInput) -> Result<(), ContractViolation> {
    input.validate()
}
struct CountingWriter {
    written: usize,
    limit: usize,
}
impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self.written.saturating_add(bytes.len());
        if next > self.limit {
            self.written = self.limit.saturating_add(1);
            return Err(io::Error::other("serialized value exceeds bound"));
        }
        self.written = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(crate) fn preflight_serialized<T: Serialize>(
    value: &T,
    limit: usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    let mut writer = CountingWriter { written: 0, limit };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(()),
        Err(_error) if writer.written > limit => Err(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: i64::try_from(limit).unwrap_or(i64::MAX),
            got: i64::try_from(writer.written).unwrap_or(i64::MAX),
        }),
        Err(error) => Err(ContractViolation::Malformed {
            field,
            reason: error.to_string(),
        }),
    }
}
