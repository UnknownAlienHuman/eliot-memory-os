use crate::{MemoryRevision, ProjectId};
use serde::{Deserialize, Serialize};

pub const PROJECT_UNDERSTANDING_SCHEMA_VERSION: &str = "project-understanding-v1";

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingModel {
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

/// Named legacy `project-understanding` versions this build admits, each paired with the
/// current version its bytes are read under.
///
/// Empty by evidence, not by omission: a repository-wide search finds exactly one
/// `project-understanding-v*` literal, [`PROJECT_UNDERSTANDING_SCHEMA_VERSION`], and it
/// is the only value `eliot-engine`'s `ProjectUnderstandingCompiler::compile` ever
/// stamps. No legacy revision has ever been written, so there is no named migration to
/// preserve here. A future supported legacy revision MUST be added to this table by name
/// together with its migration; it MUST NOT be inferred from the presence of a
/// `schema_version` string on decoded bytes.
pub const PROJECT_UNDERSTANDING_NAMED_LEGACY_MIGRATIONS: &[(&str, &str)] = &[];

/// A decoded `ProjectUnderstandingModel` whose declared `schema_version` this build does
/// not read.
///
/// Refusing here means "no meaning as current project understanding". It never means
/// "reinterpret these bytes under current field meanings".
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectUnderstandingSchemaMismatch {
    /// The version the decoded bytes declared.
    pub declared_version: String,
    /// The only version this build reads and interprets.
    pub supported_version: &'static str,
}

impl std::fmt::Display for ProjectUnderstandingSchemaMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "project understanding declares schema_version {:?}; this build reads only {:?}",
            self.declared_version, self.supported_version
        )
    }
}

impl std::error::Error for ProjectUnderstandingSchemaMismatch {}

impl ProjectUnderstandingModel {
    /// The single owner validation step for a decoded project-understanding model.
    ///
    /// Returns the version this build reads the model under, or refuses. This reuses the
    /// existing [`PROJECT_UNDERSTANDING_SCHEMA_VERSION`] constant and the existing
    /// [`PROJECT_UNDERSTANDING_NAMED_LEGACY_MIGRATIONS`] table, and adds no second
    /// mechanism.
    ///
    /// Callers MUST apply this at the model's real deserialization/admission owner,
    /// before the model may be consumed as current project proof.
    /// `deny_unknown_fields` closes the shape; it never proved the version.
    pub fn admission(&self) -> Result<&'static str, ProjectUnderstandingSchemaMismatch> {
        let declared = self.schema_version.as_str();
        if declared == PROJECT_UNDERSTANDING_SCHEMA_VERSION {
            return Ok(PROJECT_UNDERSTANDING_SCHEMA_VERSION);
        }
        PROJECT_UNDERSTANDING_NAMED_LEGACY_MIGRATIONS
            .iter()
            .find(|(legacy, _)| *legacy == declared)
            .map(|(_, admitted)| *admitted)
            .ok_or_else(|| ProjectUnderstandingSchemaMismatch {
                declared_version: declared.to_owned(),
                supported_version: PROJECT_UNDERSTANDING_SCHEMA_VERSION,
            })
    }
}
