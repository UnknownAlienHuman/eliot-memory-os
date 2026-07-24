use crate::ProjectId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ManifestPackage {
    pub name: String,
    pub description: Option<String>,
    pub manifest_path: String,
    pub boundary_path: String,
    pub source_files: Vec<String>,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingStage {
    Validated,
    Mining,
    Concepts,
    Capsules,
    SystemMap,
    Charter,
    Complete,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct OnboardingJob {
    pub project_id: ProjectId,
    pub project_root: String,
    pub head_commit: String,
    pub inputs_hash: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct OnboardingCheckpoint {
    pub project_id: ProjectId,
    pub stage: OnboardingStage,
    pub inputs_hash: String,
    pub completed_artifact_refs: Vec<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingTestHook {
    #[default]
    None,
    InterruptAfterConcepts,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct OnboardingReport {
    pub project_id: ProjectId,
    pub head_commit: String,
    pub concept_count: usize,
    pub capsule_count: usize,
    pub module_card_count: usize,
    pub charter_ref: String,
    pub map_ref: String,
    pub unassigned_files: Vec<String>,
    pub rejected_builds: Vec<String>,
    pub reasoning_job_calls: u32,
}
