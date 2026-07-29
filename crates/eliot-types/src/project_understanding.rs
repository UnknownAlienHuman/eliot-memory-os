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
pub struct ProjectCausalHop {
    pub hop_kind: CausalHopKind,
    pub from: String,
    pub relation: String,
    pub to: String,
    pub evidence_refs: Vec<String>,
    pub status: CausalHopStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectUnderstandingIntent {
    pub exact_user_goal_ref: String,
    pub normalized_goal: String,
    pub desired_state_transition: String,
    pub non_goals: Vec<String>,
    pub acceptance_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectUnderstandingSystem {
    pub project_purpose: String,
    pub subsystem_refs: Vec<String>,
    pub owner_modules: Vec<String>,
    pub entrypoint_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectCausalModel {
    pub hops: Vec<ProjectCausalHop>,
    pub unknown_hops: Vec<CausalHopKind>,
    pub required_probes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContinuityAcceptanceState {
    pub acceptance_ref: String,
    pub satisfied: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContinuityGitState {
    pub branch: String,
    pub commit: String,
    pub dirty_state_hash: String,
    pub current_diff_ref: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
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
