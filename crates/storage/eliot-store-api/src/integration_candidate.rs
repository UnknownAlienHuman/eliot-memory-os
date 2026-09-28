//! Store-neutral wire contract for durable integration-candidate manifests.
//!
//! Kernel admits one immutable manifest revision per transition. Store retains
//! the supplied producer evidence and manifest refs, binds each revision to
//! its exact predecessor, and enforces monotonic revision sequencing. The
//! candidate lifecycle (`proposed` through `accepted`) stays owned by the
//! coordination record; this module carries no status and performs no
//! lifecycle transition, so the Store never becomes a second candidate owner.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::TaskId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    NamedMutationOperation, NamedMutationRequest, NamedReadOperation, NamedReadRequest,
    ReadConsistency, ScopeId, StateFence, StoreError, canonical_json_bytes, validate_text,
};

/// Schema identifier for persisted candidate-manifest records.
pub const INTEGRATION_CANDIDATE_SCHEMA_V1: &str = "eliot.integration.candidate.v1";
/// Stable named mutation used for candidate-manifest admission and revision.
pub const INTEGRATION_CANDIDATE_MUTATION_NAME: &str = "ApplyIntegrationCandidate";
/// Stable named read used for exact task/candidate head readback.
pub const INTEGRATION_CANDIDATE_READ_NAME: &str = "GetIntegrationCandidate";

/// One immutable, task-scoped integration-candidate manifest revision.
///
/// This mirrors the I10.16 manifest fields of the coordination candidate
/// without its lifecycle: identity, task/work item, producer lineage, base
/// commit and State Fence, worktree/artifact refs, diff and changed-path
/// manifest, declared effect sets, evidence/verification refs, unresolved
/// conflicts and unknowns, rollback/compensation, and target scope.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidateRecord {
    /// Stable identity across revisions of this candidate.
    pub candidate_id: String,
    /// Task that owns the integration context.
    pub task_id: TaskId,
    /// Work item that produced this candidate.
    pub source_work_item_id: String,
    /// Producer attempt that produced this candidate.
    pub producer_attempt: String,
    /// Producer lineage evidence supplied by the semantic producer. Store
    /// retains this evidence but does not authenticate its provenance.
    pub producer_lineage: Vec<String>,
    /// Base commit the candidate was prepared against.
    pub base_commit: String,
    /// Fence at which this manifest was admitted.
    pub state_fence: StateFence,
    /// Worktree or artifact references holding the candidate content.
    pub worktree_or_artifact_refs: Vec<String>,
    /// Diff reference for the candidate content.
    pub diff_ref: String,
    /// Changed-path manifest of the candidate content.
    pub changed_paths: BTreeSet<String>,
    /// Declared read effect set.
    pub declared_read_effects: BTreeSet<String>,
    /// Declared write effect set.
    pub declared_write_effects: BTreeSet<String>,
    /// Evidence references cited by the candidate.
    pub evidence_refs: Vec<String>,
    /// Verification references cited by the candidate.
    pub verification_refs: Vec<String>,
    /// Unresolved conflicts carried by the candidate.
    pub unresolved_conflicts: Vec<String>,
    /// Unknowns carried by the candidate.
    pub unknowns: Vec<String>,
    /// Declared rollback or compensation handle, when any.
    pub rollback_or_compensation: Option<String>,
    /// Mutable target scope this candidate integrates into.
    pub target_scope: String,
    /// Monotonic immutable manifest revision.
    pub revision: u64,
}

impl IntegrationCandidateRecord {
    /// Validates the closed persisted record without assigning candidate
    /// semantics or granting any decision/effect authority.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.candidate_id, "integration_candidate.candidate_id")?;
        validate_text(
            &self.source_work_item_id,
            "integration_candidate.source_work_item_id",
        )?;
        validate_text(
            &self.producer_attempt,
            "integration_candidate.producer_attempt",
        )?;
        validate_text(&self.base_commit, "integration_candidate.base_commit")?;
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        validate_text(&self.diff_ref, "integration_candidate.diff_ref")?;
        validate_text(&self.target_scope, "integration_candidate.target_scope")?;
        for value in &self.producer_lineage {
            validate_text(value, "integration_candidate.producer_lineage")?;
        }
        for value in &self.worktree_or_artifact_refs {
            validate_text(value, "integration_candidate.worktree_or_artifact_ref")?;
        }
        for value in &self.evidence_refs {
            validate_text(value, "integration_candidate.evidence_ref")?;
        }
        for value in &self.verification_refs {
            validate_text(value, "integration_candidate.verification_ref")?;
        }
        for value in &self.unresolved_conflicts {
            validate_text(value, "integration_candidate.unresolved_conflict")?;
        }
        for value in &self.unknowns {
            validate_text(value, "integration_candidate.unknown")?;
        }
        for value in &self.changed_paths {
            validate_text(value, "integration_candidate.changed_path")?;
        }
        for value in &self.declared_read_effects {
            validate_text(value, "integration_candidate.declared_read_effect")?;
        }
        for value in &self.declared_write_effects {
            validate_text(value, "integration_candidate.declared_write_effect")?;
        }
        if let Some(value) = &self.rollback_or_compensation {
            validate_text(value, "integration_candidate.rollback_or_compensation")?;
        }
        if self.revision == 0 || self.revision > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "integration_candidate.revision",
                reason: "must fit a positive Surreal integer",
            });
        }
        Ok(())
    }
}

/// One manifest revision and the exact current revision expected at its head.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationCandidateRevision {
    /// Complete immutable manifest revision.
    pub record: IntegrationCandidateRecord,
    /// Exact immutable head observed by Kernel; absent only for first admission.
    pub expected_predecessor: Option<IntegrationCandidateRecord>,
}

impl IntegrationCandidateRevision {
    /// Validates immutable revision sequencing and record shape.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.record.validate()?;
        let expected_revision = if let Some(predecessor) = &self.expected_predecessor {
            predecessor.validate()?;
            if predecessor.task_id != self.record.task_id
                || predecessor.candidate_id != self.record.candidate_id
                || predecessor.target_scope != self.record.target_scope
            {
                return Err(StoreError::InvalidField {
                    field: "integration_candidate.expected_predecessor",
                    reason: "task, candidate, and target scope must remain bound",
                });
            }
            predecessor
                .revision
                .checked_add(1)
                .ok_or(StoreError::InvalidField {
                    field: "integration_candidate.expected_predecessor.revision",
                    reason: "revision overflow",
                })?
        } else {
            1
        };
        if expected_revision > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "integration_candidate.expected_predecessor.revision",
                reason: "must fit a positive Surreal integer",
            });
        }
        if self.record.revision != expected_revision {
            return Err(StoreError::InvalidField {
                field: "integration_candidate.revision",
                reason: "must immediately follow the expected predecessor",
            });
        }
        Ok(())
    }

    /// Returns canonical JSON used as the immutable durable revision body.
    pub fn canonical_record_json(&self) -> Result<String, StoreError> {
        let bytes = canonical_json_bytes(&self.record)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        String::from_utf8(bytes).map_err(|error| StoreError::Serialization(error.to_string()))
    }
}

/// Builds the closed named mutation for one manifest revision.
pub fn integration_candidate_request(
    revision: IntegrationCandidateRevision,
) -> Result<NamedMutationRequest, StoreError> {
    revision.validate()?;
    let parameters = BTreeMap::from([(
        "revision".to_owned(),
        serde_json::to_value(revision)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    )]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::ApplyIntegrationCandidate,
        parameters,
    })
}

/// Decodes and validates one closed manifest mutation.
pub fn decode_integration_candidate(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<IntegrationCandidateRevision, StoreError> {
    if operation != NamedMutationOperation::ApplyIntegrationCandidate {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let revision: IntegrationCandidateRevision =
        serde_json::from_value(parameters.get("revision").cloned().ok_or(
            StoreError::InvalidField {
                field: "integration_candidate.revision",
                reason: "is required",
            },
        )?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    revision.validate()?;
    Ok(revision)
}

/// Builds an exact task/candidate head read request. Readback returns the
/// typed record; dependents reference its candidate ID without copying it.
pub fn integration_candidate_read_request(
    task_id: TaskId,
    candidate_id: impl Into<String>,
    state_fence: StateFence,
) -> Result<NamedReadRequest, StoreError> {
    let candidate_id = candidate_id.into();
    validate_text(&candidate_id, "integration_candidate.candidate_id")?;
    let parameters = BTreeMap::from([
        (
            "task_id".to_owned(),
            serde_json::to_value(task_id)
                .map_err(|error| StoreError::Serialization(error.to_string()))?,
        ),
        ("candidate_id".to_owned(), Value::String(candidate_id)),
    ]);
    Ok(NamedReadRequest {
        operation: NamedReadOperation::GetIntegrationCandidate,
        scope_id: None::<ScopeId>,
        consistency: ReadConsistency::ExactFence,
        state_fence,
        parameters,
    })
}
