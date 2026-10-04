use crate::{MemoryRevision, ProjectId};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PROJECT_UNDERSTANDING_SCHEMA_VERSION: &str = "project-understanding-v1";

/// A schema-bearing project-understanding record declares a `schema_version`
/// that is not the one supported version.
///
/// `PROJECT_UNDERSTANDING_SCHEMA_VERSION` is the complete accepted set: there is
/// no legacy project-understanding version, no alias, and no named migration, so
/// any other value — including an empty string — is refused rather than trusted
/// as current authority.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error(
    "{record} declares unsupported project-understanding schema_version `{found}`; supported version is `{supported}`"
)]
pub struct ProjectUnderstandingSchemaVersionError {
    /// The project-understanding record that carried the unsupported version.
    pub record: &'static str,
    /// The offending value as it appeared in the record.
    pub found: String,
    /// The single supported version.
    pub supported: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalHopKind {
    IntentToConcept,
    ConceptToOwner,
    OwnerToSymbol,
    SymbolToStateOrFlow,
    FlowToObservable,
    ObservableToVerifier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalHopStatus {
    Verified,
    Supported,
    Assumed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCausalHop {
    pub hop_kind: CausalHopKind,
    pub from: String,
    pub relation: String,
    pub to: String,
    pub evidence_refs: Vec<String>,
    pub status: CausalHopStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingIntent {
    pub exact_user_goal_ref: String,
    pub normalized_goal: String,
    pub desired_state_transition: String,
    pub non_goals: Vec<String>,
    pub acceptance_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingSystem {
    pub project_purpose: String,
    pub subsystem_refs: Vec<String>,
    pub owner_modules: Vec<String>,
    pub entrypoint_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCausalModel {
    pub hops: Vec<ProjectCausalHop>,
    pub unknown_hops: Vec<CausalHopKind>,
    pub required_probes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcceptanceState {
    pub acceptance_ref: String,
    pub satisfied: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityGitState {
    pub branch: String,
    pub commit: String,
    pub dirty_state_hash: String,
    pub current_diff_ref: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectContinuityState {
    pub exact_goal: String,
    pub acceptance_state: Vec<ContinuityAcceptanceState>,
    pub completed_items: Vec<String>,
    pub active_plan: Vec<String>,
    pub killed_or_paused_paths: Vec<String>,
    pub current_git: ContinuityGitState,
    pub current_truth_refs: Vec<String>,
    pub used_memory_refs: Vec<String>,
    pub open_unknowns: Vec<String>,
    pub next_action: String,
    pub expected_observable: String,
    pub verifier: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingEvidence {
    pub project_purpose: String,
    pub subsystem_refs: Vec<String>,
    pub owner_modules: Vec<String>,
    pub entrypoint_refs: Vec<String>,
    pub invariant_refs: Vec<String>,
    pub danger_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub flow_evidence_refs: Vec<String>,
    pub non_goals: Vec<String>,
}

/// Decodes a project-understanding `schema_version` and refuses anything but
/// the single supported version, at the byte boundary.
///
/// Issue #935 Implementation 3: `validate_schema_version` was the record's only
/// admission check, and a deserialized model could carry any `String` until some
/// caller remembered to call it. This makes the refusal structural - an
/// unsupported or misselected version cannot be decoded into a model at all, so
/// it cannot reach an admission, comparison or continuity decision as
/// current-shaped data.
fn deserialize_project_understanding_schema_version<'de, D>(
    deserializer: D,
) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let found = String::deserialize(deserializer)?;
    if found == PROJECT_UNDERSTANDING_SCHEMA_VERSION {
        Ok(found)
    } else {
        Err(serde::de::Error::custom(
            ProjectUnderstandingSchemaVersionError {
                record: "ProjectUnderstandingModel",
                found,
                supported: PROJECT_UNDERSTANDING_SCHEMA_VERSION,
            }
            .to_string(),
        ))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingModel {
    #[serde(deserialize_with = "deserialize_project_understanding_schema_version")]
    pub schema_version: String,
    pub project_id: ProjectId,
    pub task_id: String,
    pub revision_fence: MemoryRevision,
    pub intent: ProjectUnderstandingIntent,
    pub system: ProjectUnderstandingSystem,
    pub causal_model: ProjectCausalModel,
    pub invariants: Vec<String>,
    pub danger_and_negative_memory: Vec<String>,
    pub current_truth_refs: Vec<String>,
    pub historical_or_stale_refs: Vec<String>,
    pub memory_refs_used: Vec<String>,
    pub files_to_inspect: Vec<String>,
    pub files_to_change: Vec<String>,
    pub predicted_changed_paths: Vec<String>,
    pub predicted_failing_verifiers: Vec<String>,
    pub next_allowed_action: String,
    pub expected_observable: String,
    pub verifier_ref: String,
    pub stop_condition: String,
}

impl ProjectUnderstandingModel {
    /// Refuses a model whose own `schema_version` is not the single supported
    /// constant.
    ///
    /// This is the record's only admission check: a deserialized model may carry
    /// any `String`, so an unsupported or misselected version is indistinguishable
    /// from a current one until the owner refuses it here. The comparison is an
    /// exact match, so a prefix, a legacy value, or an empty string is refused
    /// rather than upgraded.
    pub fn validate_schema_version(&self) -> Result<(), ProjectUnderstandingSchemaVersionError> {
        if self.schema_version == PROJECT_UNDERSTANDING_SCHEMA_VERSION {
            Ok(())
        } else {
            Err(ProjectUnderstandingSchemaVersionError {
                record: "ProjectUnderstandingModel",
                found: self.schema_version.clone(),
                supported: PROJECT_UNDERSTANDING_SCHEMA_VERSION,
            })
        }
    }
}
