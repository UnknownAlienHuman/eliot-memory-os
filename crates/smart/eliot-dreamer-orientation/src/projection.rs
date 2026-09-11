//! Deterministic candidate-only Orientation projection.

use std::collections::BTreeSet;
use std::io::{self, Write};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::relation::{
    RelationPreservation, RelationPreservationDimension, RelationPreservationVerdict,
};
use eliot_dreamer_contracts::{
    BudgetUsage, BundleCompleteness, SourceDisposition, SupportState, ValidatedCandidate,
};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

use crate::input::{
    AdmittedOrientationJob, CanonicalEvidenceHandle, CurrentEpistemicPositionHandle,
    OrientationError,
};
use crate::policy::OrientationPolicy;

const ORIENTATION_PACKET_SCHEMA_VERSION: u32 = 2;

fn deserialize_orientation_packet_schema<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let version = u32::deserialize(deserializer)?;
    if version != ORIENTATION_PACKET_SCHEMA_VERSION {
        return Err(serde::de::Error::custom(format_args!(
            "unsupported orientation packet schema version {version}"
        )));
    }
    Ok(version)
}

/// Implementation grouping names used to account for every I9.5 semantic field.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OrientationSectionKind {
    IdentityTaskFrame,
    Constraints,
    EvidenceCoverage,
    Positions,
    InterpretationsRivalsDissent,
    UnknownsGaps,
    RelationCandidates,
    InertProbes,
    SafeExternalHandoff,
    OmissionsExpansionFrontierInvalidation,
    Preservation,
}

impl OrientationSectionKind {
    /// Returns the canonical wire spelling used in deterministic output.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IdentityTaskFrame => "identity_task_frame",
            Self::Constraints => "constraints",
            Self::EvidenceCoverage => "evidence_coverage",
            Self::Positions => "positions",
            Self::InterpretationsRivalsDissent => "interpretations_rivals_dissent",
            Self::UnknownsGaps => "unknowns_gaps",
            Self::RelationCandidates => "relation_candidates",
            Self::InertProbes => "inert_probes",
            Self::SafeExternalHandoff => "safe_external_handoff",
            Self::OmissionsExpansionFrontierInvalidation => {
                "omissions_expansion_frontier_invalidation"
            }
            Self::Preservation => "preservation",
        }
    }
}

/// A section retains text and its source/coverage accounting explicitly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationSection {
    pub kind: OrientationSectionKind,
    pub items: Vec<String>,
    pub item_digests: Vec<String>,
    pub digest: String,
    pub known: bool,
    pub denominator: Option<String>,
}

/// Coverage measured from the supplied bundle, with no absence inference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationCoverage {
    pub completeness: BundleCompleteness,
    pub material_count: u64,
    pub omission_count: u64,
    pub non_excluded_count: u64,
    pub authoritative_denominator: Option<String>,
    pub denominator_digest: Option<String>,
    pub manifest_digest: String,
}

/// One admitted canonical evidence envelope, retained separately from the
/// model-grounding residues and from CEP support/currentness status.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AnchoredEvidence {
    pub source_handle: String,
    pub envelope: eliot_evidence::EvidenceEnvelope,
    pub canonical_digest: String,
}

/// Model-authored interpretation, carried as hypothesis text only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationInterpretation {
    pub statement: String,
    pub uncertainty: String,
    pub expected_benefit: String,
    pub source_handles: Vec<String>,
    pub counterevidence: Vec<String>,
    pub invalidation_conditions: Vec<String>,
}

/// Explicit unsupported residue, never upgraded to an algorithmic relation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationResidue {
    pub kind: String,
    pub text: String,
    pub source: String,
}

/// A model recommendation remains inert and cannot become a typed plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InertProbe {
    pub text: String,
    pub status: String,
    pub result_space: Option<String>,
}

/// Packet provenance proves projection inputs, not truth, delivery or effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationProvenance {
    pub requester_origin: eliot_dreamer_contracts::RequesterOrigin,
    pub requester_principal: String,
    pub requester_session: Option<String>,
    pub privacy_profile: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: eliot_contracts::StateFence,
    pub manifest_digest: String,
    pub validation_input_digest: String,
    pub validation_output_digest: String,
    pub policy_digest: String,
    pub source_handles: Vec<String>,
}

/// Candidate-only I9.5 `DreamPacket` projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationPacketCandidate {
    #[serde(deserialize_with = "deserialize_orientation_packet_schema")]
    pub schema_version: u32,
    pub packet_id: String,
    pub job_id: String,
    pub operation_id: String,
    pub task_id: String,
    pub scope_id: String,
    pub question: String,
    pub frame: crate::input::LocalOrientationFrame,
    pub source_coverage: OrientationCoverage,
    pub source_materials: Vec<eliot_dreamer_contracts::BundleMaterial>,
    pub omission_handles: Vec<eliot_dreamer_contracts::OmissionHandle>,
    pub coverage_denominator: Option<crate::input::OrientationCoverageDenominator>,
    pub resolved_epistemic_position_handles: Vec<CurrentEpistemicPositionHandle>,
    pub anchored_evidence_by_status: Vec<AnchoredEvidence>,
    pub synthesized_interpretations: Vec<OrientationInterpretation>,
    pub rival_models_and_dissent: Vec<OrientationResidue>,
    pub hidden_relation_candidates: Vec<OrientationResidue>,
    pub unknowns_and_gaps: Vec<OrientationResidue>,
    pub recommended_probes_or_next_actions: Vec<InertProbe>,
    pub architecture_implications: OrientationResidue,
    pub model_routes_and_cost: OrientationResidue,
    pub budget_usage: BudgetUsage,
    pub invalidation_conditions: Vec<String>,
    pub provenance: OrientationProvenance,
    pub sections: Vec<OrientationSection>,
    pub preservation: RelationPreservation,
    pub upstream_preservation: eliot_dreamer_contracts::PreservationReport,
    pub model_draft: eliot_dreamer_contracts::ModelDraft,
    pub grounded_draft: eliot_dreamer_contracts::GroundedDreamDraft,
    pub disposition: crate::result::OrientationDisposition,
    pub input_digest: String,
    pub output_digest: String,
}

#[derive(Serialize)]
struct FullInputs<'a> {
    admitted: &'a AdmittedOrientationJob,
    candidate: &'a ValidatedCandidate,
    supplied_bundle: &'a eliot_dreamer_contracts::DreamInputBundle,
    current_epistemic_position_handles: &'a [CurrentEpistemicPositionHandle],
    policy: &'a OrientationPolicy,
}

impl OrientationPacketCandidate {
    /// Validates deterministic packet structure and output fit.
    fn validate(&self, policy: &OrientationPolicy) -> Result<(), OrientationError> {
        policy.validate()?;
        if self.schema_version != ORIENTATION_PACKET_SCHEMA_VERSION
            || self.sections.len() != 11
            || self.sections.len()
                > usize::try_from(policy.max_sections).map_err(|_| OrientationError::Bound)?
            || self.job_id.len() != 64
            || self.packet_id.len() != 64
            || self.output_digest.len() != 64
            || self.input_digest.len() != 64
        {
            return Err(OrientationError::Invalid("packet identity"));
        }
        if self
            .sections
            .iter()
            .map(|s| s.kind)
            .collect::<BTreeSet<_>>()
            .len()
            != 11
        {
            return Err(OrientationError::Invalid("packet sections"));
        }
        for section in &self.sections {
            let (item_digests, digest) = section_digests(
                section.kind,
                &section.items,
                section.known,
                section.denominator.as_ref(),
            )?;
            if section.item_digests != item_digests || section.digest != digest {
                return Err(OrientationError::Binding("section digest"));
            }
        }
        let max_items = usize::try_from(policy.max_items).map_err(|_| OrientationError::Bound)?;
        if self.sections.iter().any(|s| s.items.len() > max_items) {
            return Err(OrientationError::Bounded("packet item count"));
        }
        if self.operation_id != self.frame.operation_id
            || self.task_id != self.frame.task_id
            || self.scope_id != self.frame.scope_id
            || self.question != self.frame.question
            || self.provenance.operation_id != self.operation_id
            || self.provenance.idempotency_key != self.frame.idempotency_key
            || self.provenance.task_id != self.task_id
            || self.provenance.scope_id != self.scope_id
            || self.provenance.state_fence != self.frame.state_fence
            || self.provenance.manifest_digest != self.source_coverage.manifest_digest
        {
            return Err(OrientationError::Binding("packet identity lineage"));
        }
        if self.provenance.policy_digest != policy.canonical_digest {
            return Err(OrientationError::Binding("packet policy"));
        }
        if self.provenance.privacy_profile != "local_only"
            && self.provenance.privacy_profile != "governed_external"
        {
            return Err(OrientationError::Invalid("packet privacy profile"));
        }
        self.model_draft
            .validate()
            .map_err(|_| OrientationError::Invalid("packet model draft"))?;
        self.grounded_draft
            .validate()
            .map_err(|_| OrientationError::Invalid("packet grounded draft"))?;
        self.preservation
            .validate()
            .map_err(|_| OrientationError::Invalid("packet preservation"))?;
        let bytes = canonical_json_bytes(self).map_err(|_| OrientationError::Encoding("packet"))?;
        if u64::try_from(bytes.len())
            .map_err(|_| OrientationError::Bounded("packet output bytes"))?
            > policy.max_output_bytes
        {
            return Err(OrientationError::Bounded("packet output bytes"));
        }
        let mut identity = self.clone();
        identity.packet_id.clear();
        identity.output_digest.clear();
        let expected_id = sha256_hex(
            &canonical_json_bytes(&identity)
                .map_err(|_| OrientationError::Encoding("packet identity"))?,
        );
        if self.packet_id != expected_id {
            return Err(OrientationError::Binding("packet_id"));
        }
        let mut output = self.clone();
        output.output_digest.clear();
        let expected_output = sha256_hex(
            &canonical_json_bytes(&output)
                .map_err(|_| OrientationError::Encoding("packet output"))?,
        );
        if self.output_digest != expected_output {
            return Err(OrientationError::Binding("output_digest"));
        }
        Ok(())
    }

    /// Revalidates the packet against the original admitted five-input set.
    /// Intrinsic self-hashes alone cannot establish these external bindings.
    pub fn validate_against(
        &self,
        admitted: &AdmittedOrientationJob,
        bundle: &eliot_dreamer_contracts::DreamInputBundle,
        candidate: &ValidatedCandidate,
        handles: &[CurrentEpistemicPositionHandle],
        policy: &OrientationPolicy,
    ) -> Result<(), OrientationError> {
        let expected = build_projection(admitted, candidate, bundle, handles, policy)?;
        if &expected != self {
            return Err(OrientationError::Binding("packet admitted input set"));
        }
        Ok(())
    }
}

/// Builds a packet from exactly the five admitted inputs. No I/O or mutation occurs.
pub fn build_projection(
    admitted_orientation_job: &AdmittedOrientationJob,
    bounded_bundle: &ValidatedCandidate,
    supplied_bundle: &eliot_dreamer_contracts::DreamInputBundle,
    current_epistemic_position_handles: &[CurrentEpistemicPositionHandle],
    orientation_policy: &OrientationPolicy,
) -> Result<OrientationPacketCandidate, OrientationError> {
    validate_projection_inputs(
        admitted_orientation_job,
        bounded_bundle,
        supplied_bundle,
        current_epistemic_position_handles,
        orientation_policy,
    )?;
    let data = project_values(
        admitted_orientation_job,
        bounded_bundle,
        current_epistemic_position_handles,
        orientation_policy,
    )?;
    let ordered_handles = ordered_handles(current_epistemic_position_handles);
    let ordered_evidence = ordered_evidence(&admitted_orientation_job.admitted_evidence);
    finalize_packet(
        make_packet(
            admitted_orientation_job,
            bounded_bundle,
            &ordered_handles,
            &ordered_evidence,
            orientation_policy,
            data,
        )?,
        orientation_policy,
        &bounded_bundle.job.budget,
    )
}

struct ProjectionData {
    coverage: OrientationCoverage,
    materials: Vec<eliot_dreamer_contracts::BundleMaterial>,
    omissions: Vec<eliot_dreamer_contracts::OmissionHandle>,
    denominator: Option<crate::input::OrientationCoverageDenominator>,
    evidence: Vec<AnchoredEvidence>,
    interpretation: OrientationInterpretation,
    rivals: Vec<OrientationResidue>,
    gaps: Vec<OrientationResidue>,
    probes: Vec<InertProbe>,
    sources: Vec<String>,
    provenance: OrientationProvenance,
    sections: Vec<OrientationSection>,
    disposition: crate::result::OrientationDisposition,
}

struct SemanticData {
    evidence: Vec<AnchoredEvidence>,
    interpretation: OrientationInterpretation,
    rivals: Vec<OrientationResidue>,
    gaps: Vec<OrientationResidue>,
    probes: Vec<InertProbe>,
}

fn build_semantics(
    candidate: &ValidatedCandidate,
    _handles: &[CurrentEpistemicPositionHandle],
    admitted_evidence: &[CanonicalEvidenceHandle],
) -> Result<SemanticData, OrientationError> {
    Ok(SemanticData {
        evidence: admitted_evidence
            .iter()
            .map(|h| {
                Ok(AnchoredEvidence {
                    source_handle: h.source_handle.clone(),
                    envelope: h.envelope.clone(),
                    canonical_digest: sha256_hex(
                        &canonical_json_bytes(&h.envelope)
                            .map_err(|_| OrientationError::Encoding("evidence envelope"))?,
                    ),
                })
            })
            .collect::<Result<Vec<_>, OrientationError>>()?,
        interpretation: OrientationInterpretation {
            statement: candidate.model.statement.clone(),
            uncertainty: candidate.model.uncertainty.clone(),
            expected_benefit: candidate.model.expected_benefit.clone(),
            source_handles: candidate.model.source_handles.clone(),
            counterevidence: candidate.model.counterevidence.clone(),
            invalidation_conditions: candidate.model.invalidation_conditions.clone(),
        },
        rivals: candidate
            .model
            .counterevidence
            .iter()
            .map(|text| OrientationResidue {
                kind: "counterevidence".to_owned(),
                text: text.clone(),
                source: "model_draft".to_owned(),
            })
            .collect(),
        gaps: candidate
            .bundle
            .omissions
            .iter()
            .map(|o| OrientationResidue {
                kind: "unavailable".to_owned(),
                text: o.reason.clone(),
                source: o.handle.clone(),
            })
            .collect(),
        probes: candidate
            .model
            .recommended_probes
            .iter()
            .map(|text| InertProbe {
                text: text.clone(),
                status: "model_recommendation_inert".to_owned(),
                result_space: None,
            })
            .collect(),
    })
}

fn validate_projection_inputs(
    admitted: &AdmittedOrientationJob,
    candidate: &ValidatedCandidate,
    supplied_bundle: &eliot_dreamer_contracts::DreamInputBundle,
    handles: &[CurrentEpistemicPositionHandle],
    policy: &OrientationPolicy,
) -> Result<(), OrientationError> {
    orientation_preflight(admitted, candidate, supplied_bundle, handles, policy)?;
    if candidate.cancellation_requested {
        return Err(OrientationError::Cancelled);
    }
    candidate
        .usage
        .fits(&candidate.job.budget)
        .map_err(|_| OrientationError::Binding("job budget dimension"))?;
    candidate
        .validate_binding()
        .map_err(|_| OrientationError::Binding("A03 validation receipt"))?;
    if admitted.job != candidate.job {
        return Err(OrientationError::Binding("admitted job"));
    }
    if supplied_bundle != &candidate.bundle {
        return Err(OrientationError::Binding("supplied bundle"));
    }
    admitted.validate_for(supplied_bundle)?;
    policy.validate()?;
    let max_items = usize::try_from(policy.max_items).map_err(|_| OrientationError::Bound)?;
    if handles.len() > max_items || candidate.bundle.materials.len() > max_items {
        return Err(OrientationError::Bound);
    }
    if let Some(max_stu) = policy.max_stu
        && candidate.usage.stu_used > max_stu
    {
        return Err(OrientationError::Bound);
    }
    validate_position_inputs(admitted, candidate, supplied_bundle, handles)?;
    validate_coverage_denominator(admitted, handles)?;
    Ok(())
}

fn validate_position_inputs(
    admitted: &AdmittedOrientationJob,
    candidate: &ValidatedCandidate,
    supplied_bundle: &eliot_dreamer_contracts::DreamInputBundle,
    handles: &[CurrentEpistemicPositionHandle],
) -> Result<(), OrientationError> {
    let mut seen_positions = BTreeSet::new();
    let mut seen_position_ids = BTreeSet::new();
    for handle in handles {
        handle.validate_for(&candidate.job)?;
        handle.validate_material(supplied_bundle)?;
        let (position_id, revision) = handle.position.position_identity();
        let position_id_key = sha256_hex(
            &canonical_json_bytes(position_id)
                .map_err(|_| OrientationError::Encoding("CEP position identity"))?,
        );
        if !seen_position_ids.insert(position_id_key.clone()) {
            return Err(OrientationError::Invalid("duplicate CEP position id"));
        }
        let view = canonical_json_bytes(&handle.position)
            .map_err(|_| OrientationError::Encoding("CEP view"))?;
        let revision_key = sha256_hex(
            &canonical_json_bytes(&revision)
                .map_err(|_| OrientationError::Encoding("CEP revision"))?,
        );
        let key = format!(
            "{}:{position_id_key}:{revision_key}:{}",
            handle.source_handle,
            sha256_hex(&view)
        );
        if !seen_positions.insert(key) {
            return Err(OrientationError::Invalid("duplicate CEP position"));
        }
    }
    if handles
        .iter()
        .any(|handle| handle.source_handle == admitted.frame.frame_source_handle)
    {
        return Err(OrientationError::Binding(
            "frame and CEP source handles must differ",
        ));
    }
    let mut evidence_sources = BTreeSet::new();
    for evidence in &admitted.admitted_evidence {
        if !evidence_sources.insert(evidence.source_handle.clone())
            || evidence.source_handle == admitted.frame.frame_source_handle
            || handles
                .iter()
                .any(|handle| handle.source_handle == evidence.source_handle)
        {
            return Err(OrientationError::Binding(
                "duplicate evidence source handle",
            ));
        }
    }
    if candidate.model.source_handles.iter().any(|handle| {
        !candidate.bundle.materials.iter().any(|material| {
            material.handle == *handle
                && !matches!(material.disposition, SourceDisposition::Excluded)
        })
    }) {
        return Err(OrientationError::Binding("model source outside bundle"));
    }
    Ok(())
}

fn validate_coverage_denominator(
    admitted: &AdmittedOrientationJob,
    handles: &[CurrentEpistemicPositionHandle],
) -> Result<(), OrientationError> {
    let Some(denominator) = &admitted.coverage_denominator else {
        return Ok(());
    };
    if denominator.source_handle == admitted.frame.frame_source_handle
        || handles
            .iter()
            .any(|handle| handle.source_handle == denominator.source_handle)
        || admitted
            .admitted_evidence
            .iter()
            .any(|evidence| evidence.source_handle == denominator.source_handle)
    {
        return Err(OrientationError::Binding(
            "coverage denominator source overlap",
        ));
    }
    let mut expected = denominator
        .cep_members
        .iter()
        .map(|member| {
            coverage_member_key(
                &member.source_handle,
                &member.position_id,
                member.position_revision,
                &member.canonical_view_digest,
            )
        })
        .collect::<Result<Vec<_>, OrientationError>>()?;
    expected.sort();
    let mut actual = handles
        .iter()
        .map(|handle| {
            let (position_id, revision) = handle.position.position_identity();
            coverage_member_key(
                &handle.source_handle,
                position_id,
                revision,
                &handle.position.digest,
            )
        })
        .collect::<Result<Vec<_>, OrientationError>>()?;
    actual.sort();
    if expected != actual {
        return Err(OrientationError::Binding(
            "coverage denominator CEP membership",
        ));
    }
    let mut expected_evidence = denominator
        .evidence_members
        .iter()
        .map(|member| {
            format!(
                "{}:{}",
                member.source_handle, member.canonical_envelope_digest
            )
        })
        .collect::<Vec<_>>();
    expected_evidence.sort();
    let mut actual_evidence = admitted
        .admitted_evidence
        .iter()
        .map(|member| {
            let bytes = canonical_json_bytes(&member.envelope)
                .map_err(|_| OrientationError::Encoding("evidence envelope"))?;
            Ok(format!("{}:{}", member.source_handle, sha256_hex(&bytes)))
        })
        .collect::<Result<Vec<_>, OrientationError>>()?;
    actual_evidence.sort();
    if expected_evidence != actual_evidence {
        return Err(OrientationError::Binding(
            "coverage denominator evidence membership",
        ));
    }
    Ok(())
}

fn coverage_member_key(
    source_handle: &str,
    position_id: &eliot_epistemic_contracts::PositionId,
    revision: eliot_epistemic_contracts::PositionRevision,
    view_digest: &str,
) -> Result<String, OrientationError> {
    let identity = canonical_json_bytes(&(position_id, revision))
        .map_err(|_| OrientationError::Encoding("coverage membership"))?;
    Ok(format!(
        "{source_handle}:{}:{view_digest}",
        sha256_hex(&identity)
    ))
}

#[allow(clippy::too_many_lines)]
fn orientation_preflight(
    admitted: &AdmittedOrientationJob,
    candidate: &ValidatedCandidate,
    supplied_bundle: &eliot_dreamer_contracts::DreamInputBundle,
    handles: &[CurrentEpistemicPositionHandle],
    policy: &OrientationPolicy,
) -> Result<(), OrientationError> {
    policy.validate()?;
    if policy.max_sections < 11 {
        return Err(OrientationError::Invalid("orientation policy sections"));
    }
    if policy.cancellation_requested || candidate.cancellation_requested {
        return Err(OrientationError::Cancelled);
    }
    if let Some(deadline) = candidate.job.deadline_ms {
        let Some(now) = policy.observation_time_ms.or(candidate.observation_time_ms) else {
            return Err(OrientationError::RevalidationRequired);
        };
        if now >= deadline {
            return Err(OrientationError::Bounded("deadline"));
        }
    }
    if let Some(max_stu) = policy.max_stu
        && candidate.usage.stu_used > max_stu
    {
        return Err(OrientationError::Bounded("stu"));
    }
    let max_items = usize::try_from(policy.max_items).map_err(|_| OrientationError::Bound)?;
    if handles.len() > max_items || admitted.admitted_evidence.len() > max_items {
        return Err(OrientationError::Bounded("input item count"));
    }
    if let Some(denominator) = &admitted.coverage_denominator
        && (denominator.cep_members.len() > max_items
            || denominator.evidence_members.len() > max_items
            || denominator.known_empty_sections.len() > max_items)
    {
        return Err(OrientationError::Bounded("denominator item count"));
    }
    let supersession_count = handles.iter().try_fold(0usize, |total, handle| {
        if handle.position.supersession.len() > max_items {
            return Err(OrientationError::Bounded("CEP supersession count"));
        }
        total
            .checked_add(handle.position.supersession.len())
            .ok_or(OrientationError::Bounded("CEP supersession count"))
    })?;
    let counts = [
        candidate.bundle.materials.len(),
        candidate.bundle.omissions.len(),
        candidate.model.source_handles.len(),
        candidate.model.counterevidence.len(),
        candidate.model.recommended_probes.len(),
        candidate.model.invalidation_conditions.len(),
        candidate.model.declared_confirmed_handles.len(),
        candidate.grounded.residues.len(),
        candidate.preservation.verdicts.len(),
        admitted.frame.constraints.len(),
        handles.len(),
        admitted.admitted_evidence.len(),
        supersession_count,
        admitted
            .admitted_evidence
            .iter()
            .filter(|evidence| evidence.envelope.verification.is_some())
            .count(),
        admitted
            .coverage_denominator
            .as_ref()
            .map_or(0, |d| d.cep_members.len()),
        admitted
            .coverage_denominator
            .as_ref()
            .map_or(0, |d| d.evidence_members.len()),
        admitted
            .coverage_denominator
            .as_ref()
            .map_or(0, |d| d.known_empty_sections.len()),
    ];
    if counts.into_iter().any(|count| count > max_items) {
        return Err(OrientationError::Bounded("item count"));
    }
    // The job's input ceiling bounds the admitted serialized input; the
    // local policy may tighten it but cannot enlarge that envelope.
    let job_input_cap = candidate.job.budget.input_bytes.unwrap_or(u64::MAX);
    let input_cap = policy.max_input_bytes.min(job_input_cap);
    let input_bytes = bounded_json_size(
        &FullInputs {
            admitted,
            candidate,
            supplied_bundle,
            current_epistemic_position_handles: handles,
            policy,
        },
        input_cap,
    )
    .map_err(|error| match error {
        OrientationError::Bound => OrientationError::Bounded("input bytes"),
        other => other,
    })?;
    let material_bytes = candidate
        .bundle
        .materials
        .iter()
        .try_fold(0_u64, |total, material| {
            total
                .checked_add(material.bytes)
                .ok_or(OrientationError::Bounded("source bytes"))
        })?;
    if material_bytes > policy.max_source_bytes || material_bytes > job_input_cap {
        return Err(OrientationError::Bounded("source bytes"));
    }
    // `source_width` is the job-owned source-count dimension. Material byte
    // totals remain a local source-byte policy measurement.
    let source_count = u64::try_from(candidate.bundle.materials.len())
        .map_err(|_| OrientationError::Bounded("source count"))?;
    if source_count > u64::from(policy.max_source_count)
        || source_count > candidate.job.budget.source_width.unwrap_or(u64::MAX)
    {
        return Err(OrientationError::Bounded("source count"));
    }
    let item_work = counts.into_iter().try_fold(0_u64, |total, count| {
        total
            .checked_add(u64::try_from(count).map_err(|_| OrientationError::Bounded("work units"))?)
            .ok_or(OrientationError::Bounded("work units"))
    })?;
    let record_count = counts.iter().try_fold(0_u64, |total, count| {
        total
            .checked_add(
                u64::try_from(*count).map_err(|_| OrientationError::Bounded("work units"))?,
            )
            .ok_or(OrientationError::Bounded("work units"))
    })?;
    let record_pairs = record_count
        .checked_mul(
            record_count
                .checked_add(1)
                .ok_or(OrientationError::Bounded("work units"))?,
        )
        .map(|value| value / 2)
        .ok_or(OrientationError::Bounded("work units"))?;
    // These are conservative local reservation units, not CPU or STU:
    // four bounded passes cover projection, sorting, duplicated encoding and
    // output serialization; the quadratic term covers pairwise membership
    // checks used while validating the admitted sets.
    let pass_kib = input_bytes
        .checked_add(material_bytes)
        .and_then(|value| value.checked_add(policy.max_output_bytes))
        .and_then(|value| value.checked_add(3_071))
        .map(|value| value / 1_024)
        .ok_or(OrientationError::Bounded("work units"))?;
    let work_units = pass_kib
        .checked_mul(4)
        .and_then(|value| value.checked_add(item_work))
        .and_then(|value| value.checked_add(record_pairs))
        .ok_or(OrientationError::Bounded("work units"))?;
    if work_units > policy.max_work_units {
        return Err(OrientationError::Bounded("work units"));
    }
    Ok(())
}

struct CappedWriter {
    written: u64,
    cap: u64,
}

impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "input byte count overflow")
            })?)
            .ok_or_else(|| io::Error::new(io::ErrorKind::WriteZero, "input byte count overflow"))?;
        if next > self.cap {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "orientation input byte limit",
            ));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_json_size<T: Serialize>(value: &T, cap: u64) -> Result<u64, OrientationError> {
    let mut writer = CappedWriter { written: 0, cap };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| OrientationError::Bounded("input bytes"))?;
    Ok(writer.written)
}

#[allow(clippy::too_many_lines)]
fn project_values(
    admitted: &AdmittedOrientationJob,
    candidate: &ValidatedCandidate,
    handles: &[CurrentEpistemicPositionHandle],
    policy: &OrientationPolicy,
) -> Result<ProjectionData, OrientationError> {
    let material_count =
        u64::try_from(candidate.bundle.materials.len()).map_err(|_| OrientationError::Bound)?;
    let omission_count =
        u64::try_from(candidate.bundle.omissions.len()).map_err(|_| OrientationError::Bound)?;
    let non_excluded_count = u64::try_from(
        candidate
            .bundle
            .materials
            .iter()
            .filter(|m| !matches!(m.disposition, SourceDisposition::Excluded))
            .count(),
    )
    .map_err(|_| OrientationError::Bound)?;
    let coverage = OrientationCoverage {
        completeness: candidate.bundle.completeness,
        material_count,
        omission_count,
        non_excluded_count,
        authoritative_denominator: candidate.bundle.authoritative_denominator.clone(),
        denominator_digest: admitted
            .coverage_denominator
            .as_ref()
            .map(|d| d.body_digest.clone()),
        manifest_digest: candidate.bundle.manifest_digest.clone(),
    };
    let ordered = ordered_handles(handles);
    let ordered_evidence = ordered_evidence(&admitted.admitted_evidence);
    let semantics = build_semantics(candidate, &ordered, &ordered_evidence)?;
    let sources = candidate
        .bundle
        .materials
        .iter()
        .filter(|m| !matches!(m.disposition, SourceDisposition::Excluded))
        .map(|m| m.handle.clone())
        .collect::<Vec<_>>();
    let provenance = OrientationProvenance {
        requester_origin: candidate.job.requester.origin,
        requester_principal: candidate.job.requester.principal.clone(),
        requester_session: candidate.job.requester.session.clone(),
        privacy_profile: candidate.job.privacy_profile.clone(),
        operation_id: candidate.job.operation_id.clone(),
        idempotency_key: candidate.job.idempotency_key.clone(),
        task_id: candidate.job.task_id.clone(),
        scope_id: candidate.job.scope_id.clone(),
        state_fence: candidate.job.state_fence.clone(),
        manifest_digest: candidate.bundle.manifest_digest.clone(),
        validation_input_digest: candidate.validated.receipt.input_digest.clone(),
        validation_output_digest: candidate.validated.receipt.output_digest.clone(),
        policy_digest: policy.canonical_digest.clone(),
        source_handles: sources.clone(),
    };
    let sections = build_sections(
        admitted,
        candidate,
        &ordered,
        &coverage,
        &semantics.gaps,
        &semantics.probes,
        admitted.coverage_denominator.as_ref().is_some_and(|d| {
            d.known_empty_sections
                .iter()
                .any(|section| section == "relation_candidates")
        }),
    )?;
    let upstream_preservation_complete = candidate
        .preservation
        .verdicts
        .iter()
        .all(|verdict| verdict.passed && verdict.known);
    let architecture_known = admitted.coverage_denominator.as_ref().is_some_and(|d| {
        d.known_empty_sections
            .iter()
            .any(|section| section == "architecture_implications")
    });
    let disposition = if upstream_preservation_complete
        && architecture_known
        && matches!(
            candidate.bundle.completeness,
            BundleCompleteness::CompleteForScope | BundleCompleteness::KnownEmpty
        )
        && candidate.grounded.residues.iter().all(|e| {
            !matches!(
                e.state,
                SupportState::OutsideManifest | SupportState::UnsupportedPrecision
            )
        })
        && sections.iter().all(|section| section.known)
    {
        crate::result::OrientationDisposition::Complete
    } else {
        crate::result::OrientationDisposition::Partial
    };
    Ok(ProjectionData {
        coverage,
        materials: candidate.bundle.materials.clone(),
        omissions: candidate.bundle.omissions.clone(),
        denominator: admitted.coverage_denominator.clone(),
        evidence: semantics.evidence,
        interpretation: semantics.interpretation,
        rivals: semantics.rivals,
        gaps: semantics.gaps,
        probes: semantics.probes,
        sources,
        provenance,
        sections,
        disposition,
    })
}

#[allow(clippy::too_many_lines)]
fn build_sections(
    admitted: &AdmittedOrientationJob,
    candidate: &ValidatedCandidate,
    handles: &[CurrentEpistemicPositionHandle],
    coverage: &OrientationCoverage,
    gaps: &[OrientationResidue],
    probes: &[InertProbe],
    relations_known_empty: bool,
) -> Result<Vec<OrientationSection>, OrientationError> {
    let denominator = admitted.coverage_denominator.as_ref();
    let known_empty = |name: &str| {
        denominator.is_some_and(|d| d.known_empty_sections.iter().any(|section| section == name))
    };
    let positions_known = denominator.is_some();
    let coverage_known = denominator.is_some();
    let relation_items = if relations_known_empty {
        Vec::new()
    } else {
        vec!["relation candidates are not admitted".to_owned()]
    };
    let mut interpretation_items = vec![format!(
        "model_draft:statement:{}",
        candidate.model.statement
    )];
    interpretation_items.extend(
        candidate
            .model
            .counterevidence
            .iter()
            .map(|text| format!("model_draft:counterevidence:{text}")),
    );
    let mut sections = vec![
        section(
            OrientationSectionKind::IdentityTaskFrame,
            vec![admitted.frame.body_digest.clone()],
            true,
            None,
        )?,
        section(
            OrientationSectionKind::Constraints,
            admitted.frame.constraints.clone(),
            true,
            None,
        )?,
        section(
            OrientationSectionKind::EvidenceCoverage,
            vec![format!(
                "materials:{} omissions:{}",
                coverage.material_count, coverage.omission_count
            )],
            coverage_known,
            coverage.denominator_digest.clone(),
        )?,
        section(
            OrientationSectionKind::Positions,
            handles
                .iter()
                .map(|h| format!("position:{}", h.position.digest))
                .collect(),
            positions_known,
            coverage.denominator_digest.clone(),
        )?,
        section(
            OrientationSectionKind::InterpretationsRivalsDissent,
            interpretation_items,
            true,
            None,
        )?,
        section(
            OrientationSectionKind::UnknownsGaps,
            gaps.iter().map(|g| g.text.clone()).collect(),
            true,
            None,
        )?,
        section(
            OrientationSectionKind::RelationCandidates,
            relation_items,
            relations_known_empty,
            None,
        )?,
        section(
            OrientationSectionKind::InertProbes,
            probes.iter().map(|p| p.text.clone()).collect(),
            true,
            None,
        )?,
        section(
            OrientationSectionKind::SafeExternalHandoff,
            if known_empty("safe_external_handoff") {
                Vec::new()
            } else {
                vec!["external handoff status is unknown".to_owned()]
            },
            known_empty("safe_external_handoff"),
            None,
        )?,
        section(
            OrientationSectionKind::OmissionsExpansionFrontierInvalidation,
            candidate.model.invalidation_conditions.clone(),
            true,
            None,
        )?,
        section(
            OrientationSectionKind::Preservation,
            candidate
                .preservation
                .verdicts
                .iter()
                .map(|v| format!("{}:{}", v.dimension.as_str(), v.passed))
                .collect(),
            true,
            None,
        )?,
    ];
    sections.sort_by_key(|s| s.kind.as_str());
    Ok(sections)
}

fn make_packet(
    admitted: &AdmittedOrientationJob,
    candidate: &ValidatedCandidate,
    handles: &[CurrentEpistemicPositionHandle],
    evidence: &[CanonicalEvidenceHandle],
    policy: &OrientationPolicy,
    data: ProjectionData,
) -> Result<OrientationPacketCandidate, OrientationError> {
    let advanced = |kind: &str| OrientationResidue {
        kind: "unsupported".to_owned(),
        text: format!("{kind} is outside the basic Orientation owner"),
        source: "orientation_contract".to_owned(),
    };
    let architecture_known = data.denominator.as_ref().is_some_and(|d| {
        d.known_empty_sections
            .iter()
            .any(|section| section == "architecture_implications")
    });
    let architecture = if architecture_known {
        OrientationResidue {
            kind: "known_empty".to_owned(),
            text: "no architecture implications admitted".to_owned(),
            source: "coverage_denominator".to_owned(),
        }
    } else {
        advanced("Architecture implications")
    };
    let preservation = projection_preservation(candidate, &data, handles, evidence);
    let local_preservation_complete = preservation
        .verdicts
        .iter()
        .all(|verdict| verdict.passed && verdict.known);
    let sections = rebuild_preservation_section(data.sections, &preservation)?;
    let disposition = if local_preservation_complete
        && matches!(
            data.disposition,
            crate::result::OrientationDisposition::Complete
        ) {
        crate::result::OrientationDisposition::Complete
    } else {
        crate::result::OrientationDisposition::Partial
    };
    let input_digest = orientation_input_digest(
        admitted,
        candidate,
        handles,
        evidence,
        policy,
        &preservation,
    )?;
    Ok(OrientationPacketCandidate {
        schema_version: ORIENTATION_PACKET_SCHEMA_VERSION,
        packet_id: String::new(),
        job_id: candidate.job.canonical_id(),
        operation_id: candidate.job.operation_id.clone(),
        task_id: candidate.job.task_id.clone(),
        scope_id: candidate.job.scope_id.clone(),
        question: admitted.frame.question.clone(),
        frame: admitted.frame.clone(),
        source_coverage: data.coverage,
        source_materials: data.materials,
        omission_handles: data.omissions,
        coverage_denominator: data.denominator,
        resolved_epistemic_position_handles: handles.to_vec(),
        anchored_evidence_by_status: data.evidence,
        synthesized_interpretations: vec![data.interpretation],
        rival_models_and_dissent: data.rivals,
        hidden_relation_candidates: if sections.iter().any(|section| {
            section.kind == OrientationSectionKind::RelationCandidates && section.known
        }) {
            Vec::new()
        } else {
            vec![advanced("typed relation projection")]
        },
        unknowns_and_gaps: data.gaps,
        recommended_probes_or_next_actions: data.probes,
        architecture_implications: architecture,
        model_routes_and_cost: OrientationResidue {
            kind: "budget_provenance_unavailable".to_owned(),
            text: format!(
                "A03 usage retained: input_bytes={} output_bytes={} stu_used={}",
                candidate.usage.input_bytes, candidate.usage.output_bytes, candidate.usage.stu_used
            ),
            source: "validated_candidate".to_owned(),
        },
        budget_usage: candidate.usage,
        invalidation_conditions: candidate.model.invalidation_conditions.clone(),
        provenance: data.provenance,
        sections,
        preservation,
        upstream_preservation: candidate.preservation.clone(),
        model_draft: candidate.model.clone(),
        grounded_draft: candidate.grounded.clone(),
        disposition,
        input_digest,
        output_digest: String::new(),
    })
}

fn rebuild_preservation_section(
    mut sections: Vec<OrientationSection>,
    preservation: &RelationPreservation,
) -> Result<Vec<OrientationSection>, OrientationError> {
    if let Some(preservation_section) = sections
        .iter_mut()
        .find(|section| section.kind == OrientationSectionKind::Preservation)
    {
        let items = preservation
            .verdicts
            .iter()
            .map(|verdict| format!("{}:{}", verdict.dimension.as_str(), verdict.passed))
            .collect();
        let replacement = section(
            OrientationSectionKind::Preservation,
            items,
            preservation.verdicts.iter().all(|verdict| verdict.known),
            preservation_section.denominator.clone(),
        )?;
        *preservation_section = replacement;
    }
    Ok(sections)
}

fn ordered_handles(
    handles: &[CurrentEpistemicPositionHandle],
) -> Vec<CurrentEpistemicPositionHandle> {
    let mut ordered = handles.to_vec();
    ordered.sort_by_key(|handle| (handle.source_handle.clone(), handle.position.digest.clone()));
    ordered
}

fn ordered_evidence(handles: &[CanonicalEvidenceHandle]) -> Vec<CanonicalEvidenceHandle> {
    let mut ordered = handles.to_vec();
    ordered.sort_by_key(|handle| handle.source_handle.clone());
    ordered
}

fn orientation_input_digest(
    admitted: &AdmittedOrientationJob,
    candidate: &ValidatedCandidate,
    handles: &[CurrentEpistemicPositionHandle],
    evidence: &[CanonicalEvidenceHandle],
    policy: &OrientationPolicy,
    preservation: &RelationPreservation,
) -> Result<String, OrientationError> {
    #[derive(Serialize)]
    struct Input<'a> {
        packet_schema_version: u32,
        admitted: &'a AdmittedOrientationJob,
        candidate: &'a ValidatedCandidate,
        bundle: &'a eliot_dreamer_contracts::DreamInputBundle,
        cep: &'a [CurrentEpistemicPositionHandle],
        policy: &'a OrientationPolicy,
        preservation: &'a RelationPreservation,
    }
    let mut canonical_admitted = admitted.clone();
    canonical_admitted.admitted_evidence = evidence.to_vec();
    let bytes = canonical_json_bytes(&Input {
        packet_schema_version: ORIENTATION_PACKET_SCHEMA_VERSION,
        admitted: &canonical_admitted,
        candidate,
        bundle: &candidate.bundle,
        cep: handles,
        policy,
        preservation,
    })
    .map_err(|_| OrientationError::Encoding("orientation input"))?;
    Ok(sha256_hex(&bytes))
}

fn finalize_packet(
    mut packet: OrientationPacketCandidate,
    policy: &OrientationPolicy,
    job_budget: &eliot_dreamer_contracts::BudgetLimits,
) -> Result<OrientationPacketCandidate, OrientationError> {
    let preimage =
        canonical_json_bytes(&packet).map_err(|_| OrientationError::Encoding("packet preimage"))?;
    packet.packet_id = sha256_hex(&preimage);
    let output =
        canonical_json_bytes(&packet).map_err(|_| OrientationError::Encoding("packet output"))?;
    // Whole-packet output and the report slice use their independent job
    // dimensions; the local output policy can only tighten output bytes.
    let output_cap = policy
        .max_output_bytes
        .min(job_budget.output_bytes.unwrap_or(u64::MAX));
    // The digest is derived from the unchanged empty-digest preimage, while
    // the cap applies to the complete packet carrying that digest.
    packet.output_digest = sha256_hex(&output);
    let final_output = canonical_json_bytes(&packet)
        .map_err(|_| OrientationError::Encoding("packet final output"))?;
    if u64::try_from(final_output.len()).map_err(|_| OrientationError::Bounded("output bytes"))?
        > output_cap
    {
        return Err(OrientationError::Bounded("output bytes"));
    }
    if let Some(report_cap) = job_budget.report_bytes {
        let report = canonical_json_bytes(&(
            "orientation_report_v2",
            &packet.source_coverage,
            &packet.sections,
            &packet.preservation,
            &packet.upstream_preservation,
        ))
        .map_err(|_| OrientationError::Encoding("orientation report"))?;
        if u64::try_from(report.len()).map_err(|_| OrientationError::Bounded("report bytes"))?
            > report_cap
        {
            return Err(OrientationError::Bounded("report bytes"));
        }
    }
    packet.validate(policy)?;
    Ok(packet)
}
fn section(
    kind: OrientationSectionKind,
    items: Vec<String>,
    known: bool,
    denominator: Option<String>,
) -> Result<OrientationSection, OrientationError> {
    let (item_digests, digest) = section_digests(kind, &items, known, denominator.as_ref())?;
    Ok(OrientationSection {
        kind,
        items,
        item_digests,
        digest,
        known,
        denominator,
    })
}

fn section_digests(
    kind: OrientationSectionKind,
    items: &[String],
    known: bool,
    denominator: Option<&String>,
) -> Result<(Vec<String>, String), OrientationError> {
    let item_digests = items
        .iter()
        .map(|item| {
            let preimage =
                canonical_json_bytes(&("orientation_section_item_v1", kind.as_str(), item))
                    .map_err(|_| OrientationError::Encoding("section item digest"))?;
            Ok(sha256_hex(&preimage))
        })
        .collect::<Result<Vec<_>, OrientationError>>()?;
    let preimage = canonical_json_bytes(&(
        "orientation_section_v1",
        kind.as_str(),
        items,
        known,
        denominator,
        &item_digests,
    ))
    .map_err(|_| OrientationError::Encoding("section digest"))?;
    Ok((item_digests, sha256_hex(&preimage)))
}

fn projection_preservation(
    candidate: &ValidatedCandidate,
    data: &ProjectionData,
    handles: &[CurrentEpistemicPositionHandle],
    evidence: &[CanonicalEvidenceHandle],
) -> RelationPreservation {
    let verdict = |dimension, passed, note: &'static str| RelationPreservationVerdict {
        dimension,
        passed,
        known: true,
        note: note.to_owned(),
    };
    RelationPreservation {
        verdicts: RelationPreservationDimension::all()
            .iter()
            .copied()
            .map(|dimension| match dimension {
                RelationPreservationDimension::Coverage => verdict(
                    dimension,
                    preserves_coverage(candidate, data),
                    "supplied materials, omissions, source counts and section accounting are retained",
                ),
                RelationPreservationDimension::Preservation => verdict(
                    dimension,
                    preserves_rivals_counterevidence_and_temporal_status(
                        candidate, data, handles, evidence,
                    ),
                    "supplied rivals, counterevidence, evidence status and CEP currentness/supersession distinctions are retained",
                ),
                RelationPreservationDimension::Faithfulness => verdict(
                    dimension,
                    preserves_faithfulness(candidate, data),
                    "model and grounded values are copied without additions",
                ),
                RelationPreservationDimension::Lineage => verdict(
                    dimension,
                    preserves_lineage(candidate, data),
                    "job, bundle, receipt, frame and state-fence bindings are retained",
                ),
                RelationPreservationDimension::Reversibility => verdict(
                    dimension,
                    preserves_reversibility(candidate, data),
                    "admitted source references and reversible omissions stay within the upstream proof boundary; no live source-store claim is made",
                ),
                RelationPreservationDimension::SourceAuthority => verdict(
                    dimension,
                    preserves_source_authority(candidate, data, evidence),
                    "privacy, evidence, effect, proof and source ceilings remain bounded by the admitted candidate",
                ),
                RelationPreservationDimension::DependencyClosure => verdict(
                    dimension,
                    preserves_dependency_closure(candidate, data),
                    "retained source references, omissions and the admitted denominator keep dependency closure",
                ),
            })
            .collect(),
    }
}

fn expected_source_handles(candidate: &ValidatedCandidate) -> Vec<String> {
    candidate
        .bundle
        .materials
        .iter()
        .filter(|material| !matches!(material.disposition, SourceDisposition::Excluded))
        .map(|material| material.handle.clone())
        .collect()
}

fn preserves_coverage(candidate: &ValidatedCandidate, data: &ProjectionData) -> bool {
    let expected_sources = expected_source_handles(candidate);
    data.gaps.len() == candidate.bundle.omissions.len()
        && data.omissions == candidate.bundle.omissions
        && data.materials == candidate.bundle.materials
        && data.sources == expected_sources
        && u64::try_from(candidate.bundle.materials.len()).ok()
            == Some(data.coverage.material_count)
        && u64::try_from(candidate.bundle.omissions.len()).ok()
            == Some(data.coverage.omission_count)
        && u64::try_from(expected_sources.len()).ok() == Some(data.coverage.non_excluded_count)
}

fn preserves_rivals_counterevidence_and_temporal_status(
    candidate: &ValidatedCandidate,
    data: &ProjectionData,
    handles: &[CurrentEpistemicPositionHandle],
    evidence: &[CanonicalEvidenceHandle],
) -> bool {
    let expected_rivals = candidate
        .model
        .counterevidence
        .iter()
        .map(|text| OrientationResidue {
            kind: "counterevidence".to_owned(),
            text: text.clone(),
            source: "model_draft".to_owned(),
        })
        .collect::<Vec<_>>();
    let mut expected_evidence = Vec::with_capacity(evidence.len());
    for entry in evidence {
        let Ok(envelope_bytes) = canonical_json_bytes(&entry.envelope) else {
            return false;
        };
        expected_evidence.push(AnchoredEvidence {
            source_handle: entry.source_handle.clone(),
            envelope: entry.envelope.clone(),
            canonical_digest: sha256_hex(&envelope_bytes),
        });
    }
    let positions_section_matches = data
        .sections
        .iter()
        .find(|section| section.kind == OrientationSectionKind::Positions)
        .is_some_and(|section| {
            let expected = handles
                .iter()
                .map(|handle| format!("position:{}", handle.position.digest))
                .collect::<Vec<_>>();
            section.items == expected
        });
    data.rivals == expected_rivals
        && data.interpretation.counterevidence == candidate.model.counterevidence
        && data.evidence == expected_evidence
        && positions_section_matches
}

fn preserves_faithfulness(candidate: &ValidatedCandidate, data: &ProjectionData) -> bool {
    data.interpretation.statement == candidate.model.statement
        && data.interpretation.uncertainty == candidate.model.uncertainty
        && data.interpretation.expected_benefit == candidate.model.expected_benefit
        && data.interpretation.source_handles == candidate.model.source_handles
        && data.interpretation.counterevidence == candidate.model.counterevidence
        && data.interpretation.invalidation_conditions == candidate.model.invalidation_conditions
}

fn preserves_lineage(candidate: &ValidatedCandidate, data: &ProjectionData) -> bool {
    data.provenance.requester_origin == candidate.job.requester.origin
        && data.provenance.requester_principal == candidate.job.requester.principal
        && data.provenance.requester_session == candidate.job.requester.session
        && data.provenance.source_handles == expected_source_handles(candidate)
        && data.provenance.manifest_digest == candidate.bundle.manifest_digest
        && data.provenance.validation_input_digest == candidate.validated.receipt.input_digest
        && data.provenance.validation_output_digest == candidate.validated.receipt.output_digest
        && data.provenance.operation_id == candidate.job.operation_id
        && data.provenance.idempotency_key == candidate.job.idempotency_key
        && data.provenance.task_id == candidate.job.task_id
        && data.provenance.scope_id == candidate.job.scope_id
        && data.provenance.state_fence == candidate.job.state_fence
}

fn preserves_reversibility(candidate: &ValidatedCandidate, data: &ProjectionData) -> bool {
    data.sources == expected_source_handles(candidate)
        && data.materials == candidate.bundle.materials
        && data.omissions.iter().all(|omission| omission.reversible)
}

fn preserves_source_authority(
    candidate: &ValidatedCandidate,
    data: &ProjectionData,
    evidence: &[CanonicalEvidenceHandle],
) -> bool {
    let evidence_retained = data
        .evidence
        .iter()
        .zip(evidence)
        .all(|(retained, admitted)| {
            retained.source_handle == admitted.source_handle
                && retained.envelope == admitted.envelope
                && canonical_json_bytes(&admitted.envelope)
                    .map(|bytes| retained.canonical_digest == sha256_hex(&bytes))
                    .is_ok_and(|matches| matches)
        });
    data.evidence.len() == evidence.len()
        && data.provenance.privacy_profile == candidate.job.privacy_profile
        && data.sources == expected_source_handles(candidate)
        && data.materials == candidate.bundle.materials
        && data.provenance.validation_input_digest == candidate.validated.receipt.input_digest
        && data.provenance.validation_output_digest == candidate.validated.receipt.output_digest
        && candidate.validated.receipt.proof_ceiling
            == eliot_dreamer_contracts::validation::PROOF_CEILING
        && evidence_retained
        && preserves_candidate_effect_ceiling(data)
}

fn preserves_candidate_effect_ceiling(data: &ProjectionData) -> bool {
    data.probes
        .iter()
        .all(|probe| probe.status == "model_recommendation_inert" && probe.result_space.is_none())
}

fn preserves_dependency_closure(candidate: &ValidatedCandidate, data: &ProjectionData) -> bool {
    let denominator_retained = match (
        data.denominator.as_ref(),
        data.coverage.denominator_digest.as_ref(),
    ) {
        (Some(denominator), Some(digest)) => &denominator.body_digest == digest,
        (None, None) => true,
        _ => false,
    };
    data.sources == expected_source_handles(candidate)
        && data.omissions == candidate.bundle.omissions
        && denominator_retained
        && data.denominator.is_some() == candidate.bundle.authoritative_denominator.is_some()
}
