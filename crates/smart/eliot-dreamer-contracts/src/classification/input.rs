//! Bound classification input and the A-03 acceptance seam.
//!
//! Values in this module are supplied by already admitted/grounded stages.
//! They are checked for structural joins only; admission authenticity and
//! semantic alternative selection remain outside this crate.

use std::io::{self, Write};

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_evidence::{EvidenceEnvelope, EvidenceFreshness, LifecycleState};
use eliot_receipts::{ReceiptIdentity, WorkScopeId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::curation::CurationKind;
use crate::draft::{CurationAcceptanceCtx, ValidatedCurationItem};
use crate::error::{ContractViolation, check_fence, check_text, check_vec_bound, is_hex64_lower};
use crate::screen::{ScreenBinding, ScreenState};

use super::result::{ClassificationCandidate, ClassificationCandidateClosure};
use super::taxonomy::{
    ClassificationPreservation, ClassificationPreservationDimension, CriterionApplicability,
    CriterionStatus, TaxonomyDenominator,
};

const MAX_TEXT: usize = 1024;
const MAX_ITEMS: usize = 256;
const MAX_INPUT_BYTES: usize = 4 * 1024 * 1024;
const MAX_CONTEXT_BYTES: usize = 8 * 1024 * 1024;
const SCHEMA_VERSION: u32 = 1;

/// Opaque externally supplied admission assertion. It authenticates nothing;
/// A-03 checks only its joins to the retained item and screen.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedTargetRef {
    pub target_id: ArtifactId,
    pub target_revision: String,
    pub target_digest: String,
    pub admission: ReceiptIdentity,
    pub lifecycle: LifecycleState,
    pub freshness: EvidenceFreshness,
    pub task_id: TaskId,
    pub scope_id: WorkScopeId,
    pub state_fence: StateFence,
    pub source_handles: Vec<ArtifactId>,
}

impl AdmittedTargetRef {
    fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.target_id, "classification.target_id")?;
        check_text(
            &self.target_revision,
            "classification.target_revision",
            MAX_TEXT,
        )?;
        check_digest(&self.target_digest, "classification.target_digest")?;
        check_text(
            self.admission.receipt_id.as_str(),
            "classification.admission.receipt_id",
            MAX_TEXT,
        )?;
        check_digest(
            &self.admission.canonical_sha256,
            "classification.admission.digest",
        )?;
        check_text(self.task_id.as_str(), "classification.task_id", MAX_TEXT)?;
        check_text(self.scope_id.as_str(), "classification.scope_id", MAX_TEXT)?;
        check_fence(&self.state_fence)?;
        check_id_set(&self.source_handles, "classification.source_handles")
    }
}

/// Bounded external grade-owner reference. The grade itself remains owned by
/// C1 epistemic contracts and is intentionally not imported into C0.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalGradeRef {
    pub owner: String,
    pub schema: String,
    pub revision: String,
    pub record_id: ArtifactId,
    pub digest: String,
}

impl ExternalGradeRef {
    fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.owner, "classification.grade.owner", MAX_TEXT)?;
        check_text(&self.schema, "classification.grade.schema", MAX_TEXT)?;
        check_text(&self.revision, "classification.grade.revision", MAX_TEXT)?;
        check_id(&self.record_id, "classification.grade.record_id")?;
        check_digest(&self.digest, "classification.grade.digest")
    }
}

/// Named foundation evidence plus source/dependence closure.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NamedEvidence {
    pub id: ArtifactId,
    pub foundation_evidence_envelope: EvidenceEnvelope,
    pub source_handles: Vec<ArtifactId>,
    pub dependence_groups: Vec<String>,
    pub external_grade: Option<ExternalGradeRef>,
}

impl NamedEvidence {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.id, "classification.evidence.id")?;
        self.foundation_evidence_envelope.validate().map_err(|_| {
            ContractViolation::BindingMismatch {
                field: "classification.evidence.envelope",
                reason: "invalid foundation evidence envelope".to_owned(),
            }
        })?;
        check_id_set(
            &self.source_handles,
            "classification.evidence.source_handles",
        )?;
        check_vec_bound(
            self.dependence_groups.len(),
            MAX_ITEMS,
            "classification.evidence.dependence_groups",
        )?;
        for (index, group) in self.dependence_groups.iter().enumerate() {
            check_text(group, "classification.evidence.dependence_group", MAX_TEXT)?;
            if self.dependence_groups[..index]
                .iter()
                .any(|previous| previous == group)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.evidence.dependence_groups",
                    reason: "duplicate dependence group".to_owned(),
                });
            }
        }
        if let Some(grade) = &self.external_grade {
            grade.validate()?;
        }
        Ok(())
    }
}

/// One typed feature observation. `value = None` is preserved as unknown.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FeatureObservation {
    pub feature_id: ArtifactId,
    pub criterion_id: ArtifactId,
    pub applicability: CriterionApplicability,
    pub value: Option<bool>,
    pub status: CriterionStatus,
    pub evidence_refs: Vec<ArtifactId>,
}

impl FeatureObservation {
    fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.feature_id, "classification.feature_id")?;
        check_id(&self.criterion_id, "classification.criterion_id")?;
        check_id_set(&self.evidence_refs, "classification.feature.evidence_refs")
    }
}

/// Prior assignment and predecessor retained for idempotency/refinement/conflict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PriorAssignmentRef {
    pub assignment_id: ArtifactId,
    pub selected_alternative_id: Option<ArtifactId>,
    pub selected_family: Option<String>,
    pub selected_subtype: Option<String>,
    pub target_id: ArtifactId,
    pub target_revision: String,
    pub assignment_digest: String,
    pub predecessor: Option<ArtifactId>,
    pub source_handles: Vec<ArtifactId>,
    pub status: eliot_evidence::EpistemicStatus,
    pub lifecycle: LifecycleState,
    pub receipt: Option<ReceiptIdentity>,
}

impl PriorAssignmentRef {
    fn validate(&self) -> Result<(), ContractViolation> {
        check_id(&self.assignment_id, "classification.assignment_id")?;
        check_id(&self.target_id, "classification.assignment.target_id")?;
        check_text(
            &self.target_revision,
            "classification.assignment.target_revision",
            MAX_TEXT,
        )?;
        check_digest(&self.assignment_digest, "classification.assignment_digest")?;
        check_id_set(
            &self.source_handles,
            "classification.assignment.source_handles",
        )?;
        if let Some(id) = &self.selected_alternative_id {
            check_id(id, "classification.assignment.selected_alternative_id")?;
        }
        if let Some(value) = &self.selected_family {
            check_text(value, "classification.assignment.selected_family", MAX_TEXT)?;
        }
        if let Some(value) = &self.selected_subtype {
            check_text(
                value,
                "classification.assignment.selected_subtype",
                MAX_TEXT,
            )?;
        }
        if let Some(id) = &self.predecessor {
            check_id(id, "classification.assignment.predecessor")?;
        }
        if let Some(receipt) = &self.receipt {
            check_text(
                receipt.receipt_id.as_str(),
                "classification.assignment.receipt_id",
                MAX_TEXT,
            )?;
            check_digest(
                &receipt.canonical_sha256,
                "classification.assignment.receipt_digest",
            )?;
        }
        Ok(())
    }
}

/// Complete immutable input closure for one candidate-only classification.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationInput {
    pub schema_version: u32,
    pub operation_id: ArtifactId,
    pub request_id: String,
    pub idempotency_key: String,
    pub target: AdmittedTargetRef,
    pub item: ValidatedCurationItem,
    pub screen: ScreenBinding,
    pub evidence: Vec<NamedEvidence>,
    pub features: Vec<FeatureObservation>,
    pub taxonomy: TaxonomyDenominator,
    pub prior_assignment: Option<PriorAssignmentRef>,
    pub preservation: ClassificationPreservation,
    pub policy_digest: String,
}

impl ClassificationInput {
    /// Runs bounded borrowed serialization before any canonical clone/hash.
    pub fn preflight(&self) -> Result<(), ContractViolation> {
        bounded_json(self, MAX_INPUT_BYTES, "classification.input_bytes")
    }

    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.preflight()?;
        self.validate_identity_phase()?;
        self.validate_evidence_phase()?;
        self.validate_history_phase()
    }

    fn validate_identity_phase(&self) -> Result<(), ContractViolation> {
        crate::error::check_schema_version(self.schema_version, SCHEMA_VERSION)?;
        check_id(&self.operation_id, "classification.operation_id")?;
        check_text(&self.request_id, "classification.request_id", MAX_TEXT)?;
        check_text(
            &self.idempotency_key,
            "classification.idempotency_key",
            MAX_TEXT,
        )?;
        check_digest(&self.policy_digest, "classification.policy_digest")?;
        self.target.validate()?;
        self.item.validate()?;
        if self.item.kind_spelling != CurationKind::Classification.as_str()
            || self.item.payload.kind() != CurationKind::Classification
        {
            return Err(ContractViolation::KindPayload(
                "classification input requires a Classification item".to_owned(),
            ));
        }
        self.screen.validate()?;
        if self.screen.state != ScreenState::Eligible {
            return Err(ContractViolation::ScreenIneligible(
                "classification requires an eligible ScreenBinding".to_owned(),
            ));
        }
        let target = self.target.target_id.to_string();
        let item_targets = &self.item.payload.facets().targets;
        if item_targets != std::slice::from_ref(&target)
            || self.item.denominator.members != [target.clone()]
            || self.screen.screened_targets != [target.clone()]
        {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.target_membership",
                reason: "exactly one target must join item, denominator and screen".to_owned(),
            });
        }
        if self.item.task_id != self.target.task_id.to_string()
            || self.item.scope_id != self.target.scope_id.to_string()
            || self.item.state_fence != self.target.state_fence
            || self.screen.task_id != self.target.task_id.to_string()
            || self.screen.scope_id != self.target.scope_id.to_string()
            || self.screen.state_fence != self.target.state_fence
        {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.task_scope_fence",
                reason: "target, item and screen disagree".to_owned(),
            });
        }
        self.taxonomy.validate()
    }

    fn validate_evidence_phase(&self) -> Result<(), ContractViolation> {
        check_vec_bound(self.evidence.len(), MAX_ITEMS, "classification.evidence")?;
        check_vec_bound(self.features.len(), MAX_ITEMS, "classification.features")?;
        check_unique_evidence(&self.evidence)?;
        for evidence in &self.evidence {
            evidence.validate()?;
            // Raw provenance is an external route address; only the typed
            // source_handles participate in this retained source closure.
            let provenance = &evidence.foundation_evidence_envelope.provenance;
            if evidence.foundation_evidence_envelope.state_fence != self.target.state_fence
                || provenance.scope != self.target.scope_id.as_str()
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.evidence.scope_fence",
                    reason: "evidence does not join target scope/fence".to_owned(),
                });
            }
            if evidence
                .source_handles
                .iter()
                .any(|handle| !self.target.source_handles.contains(handle))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.evidence.source_handles",
                    reason: "evidence source handle is outside target source closure".to_owned(),
                });
            }
        }
        for criterion in &self.taxonomy.criteria {
            if criterion
                .evidence_refs
                .iter()
                .any(|id| !self.evidence.iter().any(|e| e.id == *id))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "taxonomy.criterion.evidence_refs",
                    reason: "criterion references missing named evidence".to_owned(),
                });
            }
        }
        for alternative in &self.taxonomy.alternatives {
            if alternative
                .evidence_refs
                .iter()
                .chain(alternative.counterevidence_refs.iter())
                .any(|id| !self.evidence.iter().any(|e| e.id == *id))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "taxonomy.alternative.evidence_refs",
                    reason: "alternative references missing named evidence".to_owned(),
                });
            }
        }
        self.validate_feature_phase()?;
        Ok(())
    }

    fn validate_feature_phase(&self) -> Result<(), ContractViolation> {
        let criterion_ids: Vec<_> = self
            .taxonomy
            .criteria
            .iter()
            .map(|criterion| criterion.criterion_id.clone())
            .collect();
        for (index, feature) in self.features.iter().enumerate() {
            feature.validate()?;
            if self.features[..index]
                .iter()
                .any(|other| other.feature_id == feature.feature_id)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.feature_id",
                    reason: "duplicate feature identity".to_owned(),
                });
            }
            if !criterion_ids.contains(&feature.criterion_id) {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.criterion_id",
                    reason: "feature criterion is not declared".to_owned(),
                });
            }
            let Some(criterion) = self
                .taxonomy
                .criteria
                .iter()
                .find(|c| c.criterion_id == feature.criterion_id)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.criterion_id",
                    reason: "feature criterion is not declared".to_owned(),
                });
            };
            if criterion.applicability != feature.applicability {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.feature.applicability",
                    reason: "feature applicability disagrees with taxonomy criterion".to_owned(),
                });
            }
            if feature
                .evidence_refs
                .iter()
                .any(|id| !self.evidence.iter().any(|e| e.id == *id))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.feature.evidence_refs",
                    reason: "feature references missing named evidence".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_history_phase(&self) -> Result<(), ContractViolation> {
        if let Some(prior) = &self.prior_assignment {
            prior.validate()?;
            if prior.target_id != self.target.target_id
                || prior.target_revision != self.target.target_revision
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.prior_assignment",
                    reason: "prior assignment target binding drift".to_owned(),
                });
            }
            if prior
                .source_handles
                .iter()
                .any(|handle| !self.target.source_handles.contains(handle))
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.prior_assignment.source_handles",
                    reason: "prior source handle is outside target source closure".to_owned(),
                });
            }
        }
        self.preservation.validate()
    }

    /// Returns a clone with only set-like fields normalized for identity.
    /// Feature observation sequence remains meaningful; taxonomy alternatives
    /// are a declared set and are normalized by alternative identity.
    pub(crate) fn normalized_for_digest(&self) -> Result<Self, ContractViolation> {
        self.validate()?;
        let mut normalized = self.clone();
        normalized.item.payload = normalized.item.payload.normalized_for_digest();
        normalized
            .target
            .source_handles
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .evidence
            .sort_by_key(|evidence| evidence.id.as_str().to_owned());
        for evidence in &mut normalized.evidence {
            evidence
                .source_handles
                .sort_by_key(|id| id.as_str().to_owned());
            evidence.dependence_groups.sort();
        }
        for feature in &mut normalized.features {
            feature
                .evidence_refs
                .sort_by_key(|id| id.as_str().to_owned());
        }
        normalized
            .taxonomy
            .declared_families
            .sort_by_key(|family| family.as_str());
        normalized
            .taxonomy
            .declared_alternative_ids
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .taxonomy
            .provided_alternative_ids
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .taxonomy
            .omitted_alternative_ids
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .taxonomy
            .missing_criteria
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .taxonomy
            .alternatives
            .sort_by_key(|alternative| alternative.alternative_id.as_str().to_owned());
        normalized
            .taxonomy
            .criteria
            .sort_by_key(|criterion| criterion.criterion_id.as_str().to_owned());
        normalized
            .taxonomy
            .alias_mappings
            .sort_by_key(|mapping| mapping.alias_id.as_str().to_owned());
        for alternative in &mut normalized.taxonomy.alternatives {
            alternative
                .criterion_refs
                .sort_by_key(|id| id.as_str().to_owned());
            alternative
                .evidence_refs
                .sort_by_key(|id| id.as_str().to_owned());
            alternative
                .counterevidence_refs
                .sort_by_key(|id| id.as_str().to_owned());
        }
        for criterion in &mut normalized.taxonomy.criteria {
            criterion
                .evidence_refs
                .sort_by_key(|id| id.as_str().to_owned());
        }
        if let Some(prior) = &mut normalized.prior_assignment {
            prior
                .source_handles
                .sort_by_key(|id| id.as_str().to_owned());
        }
        normalized
            .preservation
            .verdicts
            .sort_by_key(|verdict| preservation_dimension_key(verdict.dimension));
        Ok(normalized)
    }
}

fn preservation_dimension_key(dimension: ClassificationPreservationDimension) -> u8 {
    match dimension {
        ClassificationPreservationDimension::Coverage => 0,
        ClassificationPreservationDimension::Preservation => 1,
        ClassificationPreservationDimension::Faithfulness => 2,
        ClassificationPreservationDimension::Lineage => 3,
        ClassificationPreservationDimension::Reversibility => 4,
        ClassificationPreservationDimension::SourceAuthority => 5,
        ClassificationPreservationDimension::DependencyClosure => 6,
    }
}

/// Bounded preflight for all borrowed acceptance context fields.
pub fn preflight_classification_acceptance(
    ctx: &CurationAcceptanceCtx<'_>,
) -> Result<(), ContractViolation> {
    bounded_json(
        &AcceptanceContextWire {
            job: ctx.job,
            bundle: ctx.bundle,
            receipt: ctx.receipt,
            screen: ctx.screen,
            grounded: ctx.grounded,
            request: ctx.request,
            usage: ctx.usage,
        },
        MAX_CONTEXT_BYTES,
        "classification.acceptance_context_bytes",
    )
}

/// Reuses the existing A-05/A-31 acceptance seam without duplicating it.
pub fn validate_classification_acceptance(
    item: &ValidatedCurationItem,
    context: &CurationAcceptanceCtx<'_>,
) -> Result<(), ContractViolation> {
    preflight_classification_acceptance(context)?;
    bounded_json(item, MAX_INPUT_BYTES, "classification.item_bytes")?;
    if context.job.job_class != crate::job::JobClass::Curation {
        return Err(ContractViolation::KindPayload(
            "classification acceptance requires a curation job".to_owned(),
        ));
    }
    if item.kind_spelling != CurationKind::Classification.as_str()
        || item.payload.kind() != CurationKind::Classification
    {
        return Err(ContractViolation::KindPayload(
            "classification acceptance requires a Classification item".to_owned(),
        ));
    }
    item.accept(context)
}

/// Validates a supplied candidate against the accepted classification input.
pub fn validate_classification(
    input: &ClassificationInput,
    candidate: &ClassificationCandidate,
    context: &CurationAcceptanceCtx<'_>,
) -> Result<(), ContractViolation> {
    preflight_classification_acceptance(context)?;
    input.validate()?;
    if input.operation_id.as_str() != context.job.operation_id
        || input.idempotency_key != context.job.idempotency_key
        || input.request_id != context.request.request_id
        || context.job.job_class != crate::job::JobClass::Curation
    {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.operation_request",
            reason: "classification requires Curation job and matching operation identities"
                .to_owned(),
        });
    }
    if context.screen != &input.screen || context.receipt != &input.item.receipt {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.acceptance",
            reason: "context does not match retained input".to_owned(),
        });
    }
    validate_classification_acceptance(&input.item, context)?;
    // The source bundle has no target revision field; the external revision is
    // retained and joined to the bundle's exact target digest where available.
    let target_material = context
        .bundle
        .materials
        .iter()
        .find(|material| material.handle == input.target.target_id.to_string());
    if target_material.is_some_and(|material| material.digest != input.target.target_digest) {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.target_digest",
            reason: "target digest differs from accepted bundle material".to_owned(),
        });
    }
    if input.target.source_handles.iter().any(|handle| {
        !context
            .bundle
            .materials
            .iter()
            .any(|material| material.handle == handle.to_string())
    }) {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.target.source_handles",
            reason: "target source handle is outside accepted bundle".to_owned(),
        });
    }
    candidate.validate_against(input)
}

/// Seals a supplied candidate after A-03 acceptance. A-03 never chooses it.
pub fn seal_classification(
    input: ClassificationInput,
    candidate: ClassificationCandidate,
    context: &CurationAcceptanceCtx<'_>,
) -> Result<ClassificationCandidateClosure, ContractViolation> {
    preflight_classification_acceptance(context)?;
    input.preflight()?;
    validate_classification(&input, &candidate, context)?;
    ClassificationCandidateClosure::seal(input, candidate)
}

/// Computes the canonical digest A-21 must place in its candidate identity.
pub fn classification_input_digest(
    input: &ClassificationInput,
) -> Result<String, ContractViolation> {
    let normalized = input.normalized_for_digest()?;
    Ok(crate::encoding::digest_hex(
        &crate::encoding::canonical_bytes(&normalized)?,
    ))
}

#[derive(Serialize)]
struct AcceptanceContextWire<'a> {
    job: &'a crate::job::DreamJobInput,
    bundle: &'a crate::bundle::DreamInputBundle,
    receipt: &'a crate::draft::ValidationReceipt,
    screen: &'a ScreenBinding,
    grounded: &'a crate::draft::GroundedDreamDraft,
    request: &'a crate::registry::TypedCurationHandlerRequest,
    usage: &'a crate::budget::BudgetUsage,
}

// The writer never stores bytes: it reports the first byte over the cap.
struct CountingWriter {
    written: usize,
    cap: usize,
    attempted: usize,
}
impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.written.checked_add(bytes.len()) else {
            self.attempted = usize::MAX;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "serialized value exceeds cap",
            ));
        };
        if next > self.cap {
            self.attempted = next;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "serialized value exceeds cap",
            ));
        }
        self.written = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json<T: Serialize>(
    value: &T,
    cap: usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    let mut writer = CountingWriter {
        written: 0,
        cap,
        attempted: 0,
    };
    serde_json::to_writer(&mut writer, value).map_err(|_error| ContractViolation::OutOfBounds {
        field,
        min: 0,
        max: i64::try_from(cap).unwrap_or(i64::MAX),
        got: i64::try_from(if writer.attempted == 0 {
            writer.written
        } else {
            writer.attempted
        })
        .unwrap_or(i64::MAX),
    })
}

pub(crate) fn preflight_serialized<T: Serialize>(
    value: &T,
    cap: usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    bounded_json(value, cap, field)
}

fn check_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "must be 64 lowercase hexadecimal characters".to_owned(),
        })
    }
}
fn check_id(id: &ArtifactId, field: &'static str) -> Result<(), ContractViolation> {
    check_text(id.as_str(), field, MAX_TEXT)
}
fn check_refs(values: &[ArtifactId], field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_ITEMS, field)?;
    values.iter().try_for_each(|value| check_id(value, field))
}
fn check_id_set(values: &[ArtifactId], field: &'static str) -> Result<(), ContractViolation> {
    check_refs(values, field)?;
    for (index, id) in values.iter().enumerate() {
        if values[..index].contains(id) {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "duplicate identity".to_owned(),
            });
        }
    }
    Ok(())
}
fn check_unique_evidence(values: &[NamedEvidence]) -> Result<(), ContractViolation> {
    for (index, value) in values.iter().enumerate() {
        if values[..index].iter().any(|other| other.id == value.id) {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.evidence.id",
                reason: "duplicate evidence identity".to_owned(),
            });
        }
    }
    Ok(())
}
