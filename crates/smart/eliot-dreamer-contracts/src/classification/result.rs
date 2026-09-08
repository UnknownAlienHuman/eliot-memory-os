//! Candidate-only classification output and retained input closure.
//!
//! A candidate is supplied by the semantic owner (A-21) and is checked here
//! for identity, membership, lineage and proof ceiling. No field is inferred
//! from a single alternative, confidence value or source count.

use eliot_contracts::{ArtifactId, sha256_hex};
use eliot_receipts::ProofCeiling;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::candidate::CandidateDisposition;
use crate::curation::CurationKind;
use crate::encoding::canonical_bytes;
use crate::error::{ContractViolation, check_text, check_vec_bound, is_hex64_lower};

use super::input::{ClassificationInput, classification_input_digest};
use super::taxonomy::{ClassificationPreservation, ClassificationPreservationDimension};

const MAX_TEXT: usize = 1024;
const MAX_ITEMS: usize = 256;
const MAX_RESULT_BYTES: usize = 4 * 1024 * 1024;
const SCHEMA_VERSION: u32 = 1;

/// Structured before/after assignment retained in the candidate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationAssignmentSnapshot {
    pub alternative_id: Option<ArtifactId>,
    pub family_ref: Option<String>,
    pub subtype_ref: Option<String>,
    pub assignment_digest: Option<String>,
}

/// Reversal and invalidation handles; a free-text rollback note is not enough.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationRollback {
    pub target_id: ArtifactId,
    pub predecessor: Option<ArtifactId>,
    pub rollback_handles: Vec<ArtifactId>,
    pub invalidation_handles: Vec<ArtifactId>,
    pub raw_history_handles: Vec<ArtifactId>,
    pub note: String,
}

/// Candidate-only semantic classification proposed by an external selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationCandidate {
    pub candidate_id: String,
    pub operation_id: ArtifactId,
    pub input_digest: String,
    pub policy_digest: String,
    pub kind: CurationKind,
    pub target_id: ArtifactId,
    pub target_revision: String,
    pub selected_alternative_id: Option<ArtifactId>,
    pub sole_legal_alternative_proof: bool,
    pub family_ref: String,
    pub subtype_ref: Option<String>,
    pub disposition: CandidateDisposition,
    pub alternatives: Vec<ArtifactId>,
    pub source_handles: Vec<ArtifactId>,
    pub evidence_refs: Vec<ArtifactId>,
    pub counterevidence_refs: Vec<ArtifactId>,
    pub before: ClassificationAssignmentSnapshot,
    pub after: ClassificationAssignmentSnapshot,
    pub rollback: ClassificationRollback,
    pub preservation: ClassificationPreservation,
    pub proof_ceiling: ProofCeiling,
}

impl ClassificationCandidate {
    /// Validates the candidate against the complete retained input closure.
    pub fn validate_against(&self, input: &ClassificationInput) -> Result<(), ContractViolation> {
        input.preflight()?;
        super::input::preflight_serialized(
            self,
            MAX_RESULT_BYTES,
            "classification.candidate_bytes",
        )?;
        self.validate_identity_phase(input)?;
        self.validate_selection_phase(input)?;
        self.validate_closure_phase(input)?;
        self.validate_preservation_phase(input)
    }

    fn validate_identity_phase(
        &self,
        input: &ClassificationInput,
    ) -> Result<(), ContractViolation> {
        check_text(&self.candidate_id, "classification.candidate_id", MAX_TEXT)?;
        check_id(&self.operation_id, "classification.operation_id")?;
        check_digest(&self.input_digest, "classification.input_digest")?;
        check_digest(&self.policy_digest, "classification.policy_digest")?;
        if self.kind != CurationKind::Classification {
            return Err(ContractViolation::KindPayload(
                "classification candidate kind mismatch".to_owned(),
            ));
        }
        if self.operation_id != input.operation_id || self.policy_digest != input.policy_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.operation_policy",
                reason: "candidate operation or policy drift".to_owned(),
            });
        }
        let computed_input = classification_input_digest(input)?;
        if self.input_digest != computed_input {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.input_digest",
                reason: "candidate does not bind retained input".to_owned(),
            });
        }
        if self.target_id != input.target.target_id
            || self.target_revision != input.target.target_revision
        {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.target",
                reason: "candidate target revision drift".to_owned(),
            });
        }
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(ContractViolation::ForbiddenCarry(
                "classification candidate exceeds CandidateArtifact proof ceiling".to_owned(),
            ));
        }
        Ok(())
    }

    fn validate_selection_phase(
        &self,
        input: &ClassificationInput,
    ) -> Result<(), ContractViolation> {
        check_ids(&self.alternatives, "classification.alternatives")?;
        if !same_set(&self.alternatives, &input.taxonomy.declared_alternative_ids) {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.alternatives",
                reason: "candidate loses or changes taxonomy denominator".to_owned(),
            });
        }
        let selected = self.selected_alternative_id.as_ref();
        if selected.is_some_and(|id| !input.taxonomy.provided_alternative_ids.contains(id)) {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.selected_alternative_id",
                reason: "selected alternative is not provided".to_owned(),
            });
        }
        if matches!(
            self.disposition,
            CandidateDisposition::Candidate
                | CandidateDisposition::Duplicate
                | CandidateDisposition::Conflict
        ) && selected.is_none()
        {
            return Err(ContractViolation::MissingField(
                "classification.selected_alternative_id",
            ));
        }
        if self.disposition == CandidateDisposition::Candidate
            && selected.is_none_or(|id| !input.taxonomy.provided_alternative_ids.contains(id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.selected_alternative_id",
                reason: "positive candidate must select a known alternative".to_owned(),
            });
        }
        if let Some(selected_id) = selected {
            let Some(alternative) = input
                .taxonomy
                .alternatives
                .iter()
                .find(|a| &a.alternative_id == selected_id)
            else {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.selected_alternative_id",
                    reason: "selected alternative is not in the supplied registry".to_owned(),
                });
            };
            if self.family_ref != alternative.family.as_str()
                || self.subtype_ref != alternative.subtype_ref
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.selected_position",
                    reason: "selected family/subtype differs from taxonomy".to_owned(),
                });
            }
            if self.after.alternative_id.as_ref() != Some(selected_id)
                || self.after.family_ref.as_deref() != Some(alternative.family.as_str())
                || self.after.subtype_ref != alternative.subtype_ref
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.after",
                    reason: "after snapshot differs from selected taxonomy position".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_closure_phase(&self, input: &ClassificationInput) -> Result<(), ContractViolation> {
        check_ids(&self.source_handles, "classification.source_handles")?;
        check_ids(&self.evidence_refs, "classification.evidence_refs")?;
        check_ids(
            &self.counterevidence_refs,
            "classification.counterevidence_refs",
        )?;
        let evidence_ids: Vec<_> = input.evidence.iter().map(|evidence| &evidence.id).collect();
        if self
            .evidence_refs
            .iter()
            .chain(self.counterevidence_refs.iter())
            .any(|id| !evidence_ids.contains(&id))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.evidence_refs",
                reason: "candidate references unretained evidence".to_owned(),
            });
        }
        check_snapshot(&self.before)?;
        check_snapshot(&self.after)?;
        check_rollback(&self.rollback, &input.target.target_id)?;
        match &input.prior_assignment {
            Some(prior) => {
                if self.before.alternative_id != prior.selected_alternative_id
                    || self.before.family_ref != prior.selected_family
                    || self.before.subtype_ref != prior.selected_subtype
                    || self.before.assignment_digest.as_deref()
                        != Some(prior.assignment_digest.as_str())
                    || self.rollback.predecessor.as_ref() != Some(&prior.assignment_id)
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "classification.before",
                        reason: "before snapshot does not retain prior assignment".to_owned(),
                    });
                }
            }
            None if self.before.alternative_id.is_some()
                || self.before.family_ref.is_some()
                || self.before.subtype_ref.is_some()
                || self.before.assignment_digest.is_some()
                || self.rollback.predecessor.is_some() =>
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.before",
                    reason: "invented prior assignment".to_owned(),
                });
            }
            None => {}
        }
        Ok(())
    }

    fn validate_preservation_phase(
        &self,
        input: &ClassificationInput,
    ) -> Result<(), ContractViolation> {
        let selected = self.selected_alternative_id.as_ref();
        self.preservation.validate()?;
        if !same_preservation(&self.preservation, &input.preservation) {
            return Err(ContractViolation::Preservation(
                "candidate cannot replace input preservation verdicts".to_owned(),
            ));
        }
        if matches!(
            self.disposition,
            CandidateDisposition::Candidate | CandidateDisposition::Conflict
        ) && (self.rollback.rollback_handles.is_empty()
            || self.rollback.raw_history_handles.is_empty())
        {
            return Err(ContractViolation::MissingField(
                "classification.rollback_history",
            ));
        }
        if self.disposition == CandidateDisposition::Candidate && !self.preservation.is_complete() {
            return Err(ContractViolation::Preservation(
                "failed or unknown preservation cannot produce a complete candidate".to_owned(),
            ));
        }
        if self.disposition == CandidateDisposition::Candidate
            && input.taxonomy.coverage != super::taxonomy::TaxonomyCoverage::Complete
        {
            return Err(ContractViolation::Preservation(
                "partial taxonomy cannot prove a complete positive candidate".to_owned(),
            ));
        }
        if self.disposition == CandidateDisposition::Candidate
            && input.taxonomy.alternatives.len() < 2
            && !self.sole_legal_alternative_proof
        {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.alternatives",
                reason: "positive candidate needs a material rival or explicit sole-legal proof"
                    .to_owned(),
            });
        }
        let allowed_sources = input
            .target
            .source_handles
            .iter()
            .chain(input.evidence.iter().flat_map(|e| e.source_handles.iter()))
            .chain(
                input
                    .prior_assignment
                    .iter()
                    .flat_map(|p| p.source_handles.iter()),
            );
        for handle in self
            .source_handles
            .iter()
            .chain(self.rollback.rollback_handles.iter())
            .chain(self.rollback.invalidation_handles.iter())
            .chain(self.rollback.raw_history_handles.iter())
        {
            if !allowed_sources.clone().any(|allowed| allowed == handle) {
                return Err(ContractViolation::BindingMismatch {
                    field: "classification.source_handles",
                    reason: "candidate references an unretained source/history handle".to_owned(),
                });
            }
        }
        if self.candidate_id
            != Self::expected_candidate_id(
                self.operation_id.as_str(),
                &self.input_digest,
                &self.policy_digest,
                selected,
            )
        {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.candidate_id",
                reason: "candidate identity must include operation, input and policy digests"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// Returns the deterministic identity for one supplied candidate.
    #[must_use]
    pub fn expected_candidate_id(
        operation_id: &str,
        input_digest: &str,
        policy_digest: &str,
        selected: Option<&ArtifactId>,
    ) -> String {
        format!(
            "classification:{operation_id}:{input_digest}:{policy_digest}:{}",
            selected.map_or("abstention", ArtifactId::as_str)
        )
    }
}

/// Complete retained input plus externally supplied candidate and digests.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClassificationCandidateClosure {
    pub schema_version: u32,
    pub input: ClassificationInput,
    pub input_digest: String,
    pub candidate: ClassificationCandidate,
    pub proof_ceiling: ProofCeiling,
    pub result_digest: String,
}

#[derive(Serialize)]
struct ResultPreimage<'a> {
    schema_version: u32,
    input_digest: &'a str,
    candidate: &'a ClassificationCandidate,
    proof_ceiling: ProofCeiling,
}

impl ClassificationCandidateClosure {
    /// Seals a candidate after caller-side acceptance and candidate validation.
    pub(crate) fn seal(
        input: ClassificationInput,
        candidate: ClassificationCandidate,
    ) -> Result<Self, ContractViolation> {
        input.preflight()?;
        let input_digest = classification_input_digest(&input)?;
        candidate.validate_against(&input)?;
        if candidate.input_digest != input_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.input_digest",
                reason: "supplied candidate digest differs from retained input".to_owned(),
            });
        }
        let mut value = Self {
            schema_version: SCHEMA_VERSION,
            input,
            input_digest,
            candidate,
            proof_ceiling: ProofCeiling::CandidateArtifact,
            result_digest: String::new(),
        };
        value.preflight()?;
        value.result_digest = value.recompute_digest()?;
        Ok(value)
    }

    /// Validates all closure identities without running a semantic classifier.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.preflight()?;
        crate::error::check_schema_version(self.schema_version, SCHEMA_VERSION)?;
        if self.proof_ceiling != ProofCeiling::CandidateArtifact {
            return Err(ContractViolation::ForbiddenCarry(
                "classification closure exceeds CandidateArtifact proof ceiling".to_owned(),
            ));
        }
        self.input.validate()?;
        self.candidate.validate_against(&self.input)?;
        let input_digest = classification_input_digest(&self.input)?;
        if input_digest != self.input_digest || self.candidate.input_digest != self.input_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.input_digest",
                reason: "retained input digest mismatch".to_owned(),
            });
        }
        if !is_hex64_lower(&self.result_digest) || self.result_digest != self.recompute_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "classification.result_digest",
                reason: "candidate closure digest mismatch".to_owned(),
            });
        }
        Ok(())
    }

    /// Runs the bounded output serialization check before allocating output bytes.
    pub fn preflight(&self) -> Result<(), ContractViolation> {
        super::input::preflight_serialized(self, MAX_RESULT_BYTES, "classification.result_bytes")
    }

    /// Returns canonical bytes only after structural validation and bounds checks.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ContractViolation> {
        self.validate()?;
        let normalized = self.normalized_for_digest()?;
        canonical_bytes(&normalized)
    }

    fn recompute_digest(&self) -> Result<String, ContractViolation> {
        let normalized = self.normalized_for_digest()?;
        let candidate = &normalized.candidate;
        let preimage = ResultPreimage {
            schema_version: normalized.schema_version,
            input_digest: &normalized.input_digest,
            candidate,
            proof_ceiling: normalized.proof_ceiling,
        };
        Ok(sha256_hex(&canonical_bytes(&preimage)?))
    }

    fn normalized_for_digest(&self) -> Result<Self, ContractViolation> {
        self.preflight()?;
        let mut normalized = self.clone();
        normalized.input = normalized.input.normalized_for_digest()?;
        normalized
            .candidate
            .alternatives
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .candidate
            .source_handles
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .candidate
            .evidence_refs
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .candidate
            .counterevidence_refs
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .candidate
            .rollback
            .rollback_handles
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .candidate
            .rollback
            .invalidation_handles
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .candidate
            .rollback
            .raw_history_handles
            .sort_by_key(|id| id.as_str().to_owned());
        normalized
            .candidate
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

fn same_preservation(a: &ClassificationPreservation, b: &ClassificationPreservation) -> bool {
    let mut left = a.verdicts.clone();
    let mut right = b.verdicts.clone();
    left.sort_by_key(|verdict| preservation_dimension_key(verdict.dimension));
    right.sort_by_key(|verdict| preservation_dimension_key(verdict.dimension));
    left == right
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
fn check_id_refs(values: &[ArtifactId], field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(values.len(), MAX_ITEMS, field)?;
    values.iter().try_for_each(|id| check_id(id, field))
}
fn check_ids(values: &[ArtifactId], field: &'static str) -> Result<(), ContractViolation> {
    check_id_refs(values, field)?;
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
fn check_snapshot(snapshot: &ClassificationAssignmentSnapshot) -> Result<(), ContractViolation> {
    if let Some(id) = &snapshot.alternative_id {
        check_id(id, "classification.assignment.alternative_id")?;
    }
    if let Some(value) = &snapshot.family_ref {
        check_text(value, "classification.assignment.family_ref", MAX_TEXT)?;
    }
    if let Some(value) = &snapshot.subtype_ref {
        check_text(value, "classification.assignment.subtype_ref", MAX_TEXT)?;
    }
    if let Some(value) = &snapshot.assignment_digest {
        check_digest(value, "classification.assignment.digest")?;
    }
    Ok(())
}
fn check_rollback(
    value: &ClassificationRollback,
    target: &ArtifactId,
) -> Result<(), ContractViolation> {
    check_id(&value.target_id, "classification.rollback.target_id")?;
    if &value.target_id != target {
        return Err(ContractViolation::BindingMismatch {
            field: "classification.rollback.target_id",
            reason: "rollback target drift".to_owned(),
        });
    }
    if let Some(id) = &value.predecessor {
        check_id(id, "classification.rollback.predecessor")?;
    }
    check_ids(&value.rollback_handles, "classification.rollback.handles")?;
    check_ids(
        &value.invalidation_handles,
        "classification.invalidation.handles",
    )?;
    check_ids(
        &value.raw_history_handles,
        "classification.raw_history.handles",
    )?;
    check_text(&value.note, "classification.rollback.note", MAX_TEXT)
}

fn same_set(left: &[ArtifactId], right: &[ArtifactId]) -> bool {
    left.len() == right.len() && left.iter().all(|id| right.contains(id))
}
