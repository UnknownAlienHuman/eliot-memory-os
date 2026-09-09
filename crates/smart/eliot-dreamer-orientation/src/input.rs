//! Immutable, caller-owned inputs for the Orientation projector.

use std::collections::BTreeSet;

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::{DreamInputBundle, DreamJobInput, ValidatedCandidate};
use eliot_epistemic_contracts::{CurrentEpistemicPosition, PositionId, PositionRevision};
use eliot_evidence::EvidenceEnvelope;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The exact frame a caller wants projected. Its body digest excludes the
/// enclosing manifest; validation binds that body to one admitted material.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalOrientationFrame {
    pub schema_version: u32,
    pub question: String,
    pub goal: String,
    pub constraints: Vec<String>,
    pub attempt: String,
    pub output_contract: String,
    pub idempotency_key: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub operation_id: String,
    pub frame_source_handle: String,
    pub body_bytes: u64,
    pub body_digest: String,
}

impl LocalOrientationFrame {
    /// Creates a frame and freezes its receipt-excluded body digest.
    pub fn new(
        question: impl Into<String>,
        goal: impl Into<String>,
        constraints: Vec<String>,
        attempt: impl Into<String>,
        output_contract: impl Into<String>,
        frame_source_handle: impl Into<String>,
        job: &DreamJobInput,
    ) -> Result<Self, OrientationError> {
        let mut frame = Self {
            schema_version: 1,
            question: question.into(),
            goal: goal.into(),
            constraints,
            attempt: attempt.into(),
            output_contract: output_contract.into(),
            operation_id: job.operation_id.clone(),
            idempotency_key: job.idempotency_key.clone(),
            task_id: job.task_id.clone(),
            scope_id: job.scope_id.clone(),
            state_fence: job.state_fence.clone(),
            frame_source_handle: frame_source_handle.into(),
            body_bytes: 0,
            body_digest: String::new(),
        };
        frame.validate_unsealed_shape()?;
        frame.body_bytes =
            u64::try_from(frame.compute_body_bytes()?).map_err(|_| OrientationError::Bound)?;
        frame.validate_shape()?;
        frame.body_digest = frame.compute_body_digest()?;
        Ok(frame)
    }

    /// Validates identity and digest bindings without external state.
    pub fn validate_for(
        &self,
        job: &DreamJobInput,
        bundle: &DreamInputBundle,
    ) -> Result<(), OrientationError> {
        self.validate_shape()?;
        if self.operation_id != job.operation_id
            || self.idempotency_key != job.idempotency_key
            || self.task_id != job.task_id
            || self.scope_id != job.scope_id
            || self.state_fence != job.state_fence
        {
            return Err(OrientationError::Binding("frame task/scope/fence"));
        }
        let Some(material) = bundle.materials.iter().find(|m| {
            m.handle == self.frame_source_handle
                && !matches!(
                    m.disposition,
                    eliot_dreamer_contracts::SourceDisposition::Excluded
                )
        }) else {
            return Err(OrientationError::Binding("frame source handle"));
        };
        if material.digest != self.body_digest || material.bytes != self.body_bytes {
            return Err(OrientationError::Binding("frame source body"));
        }
        if self.body_bytes
            != u64::try_from(self.compute_body_bytes()?).map_err(|_| OrientationError::Bound)?
        {
            return Err(OrientationError::Binding("frame body length"));
        }
        if self.body_digest != self.compute_body_digest()? {
            return Err(OrientationError::Binding("frame body_digest"));
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), OrientationError> {
        self.validate_unsealed_shape()?;
        if self.frame_source_handle.trim().is_empty() || self.body_bytes == 0 {
            return Err(OrientationError::Invalid("frame source"));
        }
        Ok(())
    }

    fn validate_unsealed_shape(&self) -> Result<(), OrientationError> {
        if self.schema_version != 1 {
            return Err(OrientationError::Unsupported("orientation frame schema"));
        }
        for (value, name) in [
            (&self.question, "question"),
            (&self.goal, "goal"),
            (&self.attempt, "attempt"),
            (&self.output_contract, "output_contract"),
            (&self.operation_id, "operation_id"),
            (&self.idempotency_key, "idempotency_key"),
            (&self.task_id, "task_id"),
            (&self.scope_id, "scope_id"),
            (&self.frame_source_handle, "frame_source_handle"),
        ] {
            if value.trim().is_empty()
                || value.len() > 16_384
                || value.chars().any(char::is_control)
            {
                return Err(OrientationError::Invalid(name));
            }
        }
        let constraint_bytes = self
            .constraints
            .iter()
            .map(String::len)
            .fold(0usize, usize::saturating_add);
        if self.constraints.len() > 256 || constraint_bytes > 1_048_576 {
            return Err(OrientationError::Bound);
        }
        Ok(())
    }

    fn compute_body_digest(&self) -> Result<String, OrientationError> {
        #[derive(Serialize)]
        struct Body<'a> {
            schema_version: u32,
            question: &'a str,
            goal: &'a str,
            constraints: &'a [String],
            attempt: &'a str,
            output_contract: &'a str,
            operation_id: &'a str,
            idempotency_key: &'a str,
            task_id: &'a str,
            scope_id: &'a str,
            state_fence: &'a StateFence,
            frame_source_handle: &'a str,
        }
        let bytes = canonical_json_bytes(&Body {
            schema_version: self.schema_version,
            question: &self.question,
            goal: &self.goal,
            constraints: &self.constraints,
            attempt: &self.attempt,
            output_contract: &self.output_contract,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            frame_source_handle: &self.frame_source_handle,
        })
        .map_err(|_| OrientationError::Encoding("frame body"))?;
        Ok(sha256_hex(&bytes))
    }

    fn compute_body_bytes(&self) -> Result<usize, OrientationError> {
        #[derive(Serialize)]
        struct Body<'a> {
            schema_version: u32,
            question: &'a str,
            goal: &'a str,
            constraints: &'a [String],
            attempt: &'a str,
            output_contract: &'a str,
            operation_id: &'a str,
            idempotency_key: &'a str,
            task_id: &'a str,
            scope_id: &'a str,
            state_fence: &'a StateFence,
            frame_source_handle: &'a str,
        }
        let bytes = canonical_json_bytes(&Body {
            schema_version: self.schema_version,
            question: &self.question,
            goal: &self.goal,
            constraints: &self.constraints,
            attempt: &self.attempt,
            output_contract: &self.output_contract,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            frame_source_handle: &self.frame_source_handle,
        })
        .map_err(|_| OrientationError::Encoding("frame body"))?;
        Ok(bytes.len())
    }
}

/// A job admitted specifically to the Orientation owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmittedOrientationJob {
    pub job: DreamJobInput,
    pub frame: LocalOrientationFrame,
    pub admitted_evidence: Vec<CanonicalEvidenceHandle>,
    pub coverage_denominator: Option<OrientationCoverageDenominator>,
}

/// An exact, source-bound denominator for the admitted input collections.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrientationCoverageDenominator {
    pub source_handle: String,
    pub operation_id: String,
    pub idempotency_key: String,
    pub task_id: String,
    pub scope_id: String,
    pub state_fence: StateFence,
    pub frame_source_handle: String,
    pub cep_members: Vec<CoverageCepMember>,
    pub evidence_members: Vec<CoverageEvidenceMember>,
    pub known_empty_sections: Vec<String>,
    pub body_bytes: u64,
    pub body_digest: String,
}

/// Typed membership identity recorded by an orientation denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageCepMember {
    pub source_handle: String,
    pub position_id: PositionId,
    pub position_revision: PositionRevision,
    pub canonical_view_digest: String,
}

/// Canonical envelope membership recorded by an orientation denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageEvidenceMember {
    pub source_handle: String,
    pub canonical_envelope_digest: String,
}

impl OrientationCoverageDenominator {
    pub fn seal(&mut self) -> Result<(), OrientationError> {
        self.validate_unsealed_shape()?;
        self.cep_members.sort_by_key(|member| {
            (
                member.source_handle.clone(),
                member.canonical_view_digest.clone(),
            )
        });
        if self.cep_members.windows(2).any(|members| {
            members[0].source_handle == members[1].source_handle
                || members[0].position_id == members[1].position_id
        }) {
            return Err(OrientationError::Invalid(
                "coverage denominator CEP members",
            ));
        }
        self.evidence_members.sort_by_key(|member| {
            (
                member.source_handle.clone(),
                member.canonical_envelope_digest.clone(),
            )
        });
        if self
            .evidence_members
            .windows(2)
            .any(|members| members[0].source_handle == members[1].source_handle)
        {
            return Err(OrientationError::Invalid(
                "coverage denominator evidence members",
            ));
        }
        self.known_empty_sections.sort();
        if self
            .known_empty_sections
            .windows(2)
            .any(|sections| sections[0] == sections[1])
        {
            return Err(OrientationError::Invalid("coverage denominator sections"));
        }
        self.validate_canonical_members()?;
        let bytes = self.body_bytes_preimage()?;
        self.body_bytes = u64::try_from(bytes.len()).map_err(|_| OrientationError::Bound)?;
        self.body_digest = sha256_hex(&bytes);
        Ok(())
    }

    pub fn validate_for(
        &self,
        job: &DreamJobInput,
        bundle: &DreamInputBundle,
    ) -> Result<(), OrientationError> {
        self.validate_unsealed_shape()?;
        if self.source_handle.trim().is_empty()
            || self.frame_source_handle.trim().is_empty()
            || self.source_handle == self.frame_source_handle
            || self.body_bytes == 0
            || self.body_digest.len() != 64
            || self.cep_members.len() > 1_024
            || self.evidence_members.len() > 1_024
            || self.known_empty_sections.len() > 11
        {
            return Err(OrientationError::Invalid("coverage denominator"));
        }
        if self.operation_id != job.operation_id
            || self.idempotency_key != job.idempotency_key
            || self.task_id != job.task_id
            || self.scope_id != job.scope_id
            || self.state_fence != job.state_fence
        {
            return Err(OrientationError::Binding("coverage denominator job"));
        }
        if self.known_empty_sections.iter().any(|section| {
            !matches!(
                section.as_str(),
                "relation_candidates" | "safe_external_handoff" | "architecture_implications"
            )
        }) {
            return Err(OrientationError::Invalid("coverage denominator section"));
        }
        self.validate_canonical_members()?;
        let Some(material) = bundle.materials.iter().find(|m| {
            m.handle == self.source_handle
                && matches!(
                    m.disposition,
                    eliot_dreamer_contracts::SourceDisposition::Required
                )
        }) else {
            return Err(OrientationError::Binding("coverage denominator source"));
        };
        let bytes = self.body_bytes_preimage()?;
        if self.body_bytes != u64::try_from(bytes.len()).map_err(|_| OrientationError::Bound)?
            || self.body_digest != sha256_hex(&bytes)
            || material.bytes != self.body_bytes
            || material.digest != self.body_digest
        {
            return Err(OrientationError::Binding("coverage denominator body"));
        }
        Ok(())
    }

    fn validate_unsealed_shape(&self) -> Result<(), OrientationError> {
        for (value, name) in [
            (&self.source_handle, "coverage denominator source"),
            (&self.operation_id, "coverage denominator operation"),
            (&self.idempotency_key, "coverage denominator idempotency"),
            (&self.task_id, "coverage denominator task"),
            (&self.scope_id, "coverage denominator scope"),
            (
                &self.frame_source_handle,
                "coverage denominator frame source",
            ),
        ] {
            if value.trim().is_empty()
                || value.len() > 16_384
                || value.chars().any(char::is_control)
            {
                return Err(OrientationError::Invalid(name));
            }
        }
        if self.source_handle == self.frame_source_handle
            || self.cep_members.len() > 1_024
            || self.evidence_members.len() > 1_024
            || self.known_empty_sections.len() > 11
        {
            return Err(OrientationError::Bound);
        }
        if self.known_empty_sections.iter().any(|section| {
            !matches!(
                section.as_str(),
                "relation_candidates" | "safe_external_handoff" | "architecture_implications"
            ) || section.trim().is_empty()
                || section.len() > 128
                || section.chars().any(char::is_control)
        }) {
            return Err(OrientationError::Invalid("coverage denominator section"));
        }
        for member in &self.cep_members {
            if member.source_handle.trim().is_empty()
                || member.source_handle.len() > 16_384
                || member.source_handle.chars().any(char::is_control)
                || member.canonical_view_digest.len() != 64
            {
                return Err(OrientationError::Invalid("coverage denominator CEP member"));
            }
        }
        for member in &self.evidence_members {
            if member.source_handle.trim().is_empty()
                || member.source_handle.len() > 16_384
                || member.source_handle.chars().any(char::is_control)
                || member.canonical_envelope_digest.len() != 64
            {
                return Err(OrientationError::Invalid(
                    "coverage denominator evidence member",
                ));
            }
        }
        Ok(())
    }

    fn validate_canonical_members(&self) -> Result<(), OrientationError> {
        let mut cep_sources = BTreeSet::new();
        let mut cep_positions = BTreeSet::new();
        for member in &self.cep_members {
            let position_key = canonical_json_bytes(&member.position_id)
                .map_err(|_| OrientationError::Encoding("coverage CEP identity"))?;
            if !cep_sources.insert(member.source_handle.clone())
                || !cep_positions.insert(sha256_hex(&position_key))
            {
                return Err(OrientationError::Invalid(
                    "coverage denominator duplicate CEP member",
                ));
            }
        }
        if self.cep_members.windows(2).any(|members| {
            (&members[0].source_handle, &members[0].canonical_view_digest)
                > (&members[1].source_handle, &members[1].canonical_view_digest)
        }) {
            return Err(OrientationError::Invalid("coverage denominator CEP order"));
        }
        let mut evidence_sources = BTreeSet::new();
        for member in &self.evidence_members {
            if !evidence_sources.insert(member.source_handle.clone()) {
                return Err(OrientationError::Invalid(
                    "coverage denominator duplicate evidence member",
                ));
            }
        }
        if self.evidence_members.windows(2).any(|members| {
            (
                &members[0].source_handle,
                &members[0].canonical_envelope_digest,
            ) > (
                &members[1].source_handle,
                &members[1].canonical_envelope_digest,
            )
        }) || self
            .known_empty_sections
            .windows(2)
            .any(|sections| sections[0] > sections[1])
        {
            return Err(OrientationError::Invalid("coverage denominator order"));
        }
        Ok(())
    }

    fn body_bytes_preimage(&self) -> Result<Vec<u8>, OrientationError> {
        #[derive(Serialize)]
        struct Body<'a> {
            source_handle: &'a str,
            operation_id: &'a str,
            idempotency_key: &'a str,
            task_id: &'a str,
            scope_id: &'a str,
            state_fence: &'a StateFence,
            frame_source_handle: &'a str,
            cep_members: &'a [CoverageCepMember],
            evidence_members: &'a [CoverageEvidenceMember],
            known_empty_sections: &'a [String],
        }
        canonical_json_bytes(&Body {
            source_handle: &self.source_handle,
            operation_id: &self.operation_id,
            idempotency_key: &self.idempotency_key,
            task_id: &self.task_id,
            scope_id: &self.scope_id,
            state_fence: &self.state_fence,
            frame_source_handle: &self.frame_source_handle,
            cep_members: &self.cep_members,
            evidence_members: &self.evidence_members,
            known_empty_sections: &self.known_empty_sections,
        })
        .map_err(|_| OrientationError::Encoding("coverage denominator"))
    }
}

/// A canonical evidence envelope bound to its own admitted bundle material.
/// The raw handle inside provenance remains opaque and distinct from this
/// serialized envelope source handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEvidenceHandle {
    pub source_handle: String,
    pub envelope: EvidenceEnvelope,
}

impl CanonicalEvidenceHandle {
    pub fn validate_for(
        &self,
        job: &DreamJobInput,
        bundle: &DreamInputBundle,
    ) -> Result<(), OrientationError> {
        if self.source_handle.trim().is_empty() {
            return Err(OrientationError::Invalid("evidence source handle"));
        }
        self.envelope
            .validate()
            .map_err(|_| OrientationError::Invalid("evidence envelope"))?;
        if self.envelope.state_fence != job.state_fence
            || self.envelope.provenance.scope != job.scope_id
        {
            return Err(OrientationError::Binding("evidence scope/fence"));
        }
        let Some(material) = bundle.materials.iter().find(|m| {
            m.handle == self.source_handle
                && !matches!(
                    m.disposition,
                    eliot_dreamer_contracts::SourceDisposition::Excluded
                )
        }) else {
            return Err(OrientationError::Binding("evidence source handle"));
        };
        let bytes = canonical_json_bytes(&self.envelope)
            .map_err(|_| OrientationError::Encoding("evidence envelope"))?;
        if material.bytes != u64::try_from(bytes.len()).map_err(|_| OrientationError::Bound)?
            || material.digest != sha256_hex(&bytes)
        {
            return Err(OrientationError::Binding("evidence canonical body"));
        }
        Ok(())
    }
}

impl AdmittedOrientationJob {
    pub fn validate_for(&self, bundle: &DreamInputBundle) -> Result<(), OrientationError> {
        self.job
            .validate()
            .map_err(|_| OrientationError::Invalid("job"))?;
        if !matches!(
            self.job.job_class,
            eliot_dreamer_contracts::JobClass::Orientation
        ) {
            return Err(OrientationError::WrongJobClass);
        }
        if bundle.job_id != self.job.canonical_id()
            || bundle.task_id != self.job.task_id
            || bundle.scope_id != self.job.scope_id
            || bundle.state_fence != self.job.state_fence
            || bundle.manifest_digest != self.job.frozen_manifest_digest
        {
            return Err(OrientationError::Binding("job/bundle"));
        }
        self.frame.validate_for(&self.job, bundle)?;
        if self.admitted_evidence.len() > 1_024 {
            return Err(OrientationError::Bound);
        }
        for evidence in &self.admitted_evidence {
            evidence.validate_for(&self.job, bundle)?;
        }
        if let Some(denominator) = &self.coverage_denominator {
            denominator.validate_for(&self.job, bundle)?;
            if denominator.frame_source_handle != self.frame.frame_source_handle {
                return Err(OrientationError::Binding("coverage denominator frame"));
            }
        }
        Ok(())
    }
}

/// A source-bound wrapper around the canonical CEP view. The canonical value
/// remains intact; this wrapper only records which admitted bundle material
/// carries its canonical view bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurrentEpistemicPositionHandle {
    pub source_handle: String,
    pub position: CurrentEpistemicPosition,
}

impl CurrentEpistemicPositionHandle {
    pub fn validate_for(&self, job: &DreamJobInput) -> Result<(), OrientationError> {
        if self.source_handle.trim().is_empty() {
            return Err(OrientationError::Invalid("CEP source handle"));
        }
        self.position
            .validate()
            .map_err(|_| OrientationError::Invalid("CEP view"))?;
        if self.position.admission.fence != job.state_fence
            || self.position.admission.scope != job.scope_id
        {
            return Err(OrientationError::Binding("CEP scope/fence"));
        }
        Ok(())
    }

    pub fn validate_material(&self, bundle: &DreamInputBundle) -> Result<(), OrientationError> {
        let Some(material) = bundle.materials.iter().find(|m| {
            m.handle == self.source_handle
                && !matches!(
                    m.disposition,
                    eliot_dreamer_contracts::SourceDisposition::Excluded
                )
        }) else {
            return Err(OrientationError::Binding("CEP source handle"));
        };
        let bytes = canonical_json_bytes(&self.position)
            .map_err(|_| OrientationError::Encoding("CEP view"))?;
        if material.bytes != u64::try_from(bytes.len()).map_err(|_| OrientationError::Bound)?
            || material.digest != sha256_hex(&bytes)
        {
            return Err(OrientationError::Binding("CEP canonical view body"));
        }
        Ok(())
    }
}

/// Errors are bounded and carry no model-generated authority.
#[derive(Clone, Debug, Eq, PartialEq, Error, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum OrientationError {
    #[error("wrong job class")]
    WrongJobClass,
    #[error("invalid {0}")]
    Invalid(&'static str),
    #[error("unsupported {0}")]
    Unsupported(&'static str),
    #[error("binding mismatch: {0}")]
    Binding(&'static str),
    #[error("bounded orientation limit exceeded")]
    Bound,
    #[error("bounded orientation input exceeds {0} limit")]
    Bounded(&'static str),
    #[error("revalidation required: current observation time is unavailable")]
    RevalidationRequired,
    #[error("cancelled")]
    Cancelled,
    #[error("encoding failed for {0}")]
    Encoding(&'static str),
    #[error("internal projector failure")]
    Internal,
}

/// The aggregate supplied after A03 validation, under an orientation name.
pub type ValidatedOrientationCandidate = ValidatedCandidate;
