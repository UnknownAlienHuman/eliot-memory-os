use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskExecutionDomain {
    Code,
    Docs,
    Research,
    Operations,
    #[default]
    Mixed,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskExecutionAction {
    #[default]
    ReadOnly,
    SingleFile,
    MultiFile,
    CrossSubsystem,
    Destructive,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskExecutionArtifact {
    Code,
    Config,
    Docs,
    Report,
    Runtime,
    #[default]
    Mixed,
}

#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskExecutionClassSource {
    ExplicitContract,
    ProjectProfile,
    TouchedPaths,
    Handles,
    #[default]
    Fallback,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct TaskExecutionClass {
    pub domain: TaskExecutionDomain,
    pub action: TaskExecutionAction,
    pub artifact: TaskExecutionArtifact,
    pub subsystem_refs: Vec<String>,
    pub source: TaskExecutionClassSource,
}

impl TaskExecutionClass {
    #[must_use]
    pub fn requires_codecortex(&self) -> bool {
        matches!(
            self.domain,
            TaskExecutionDomain::Code | TaskExecutionDomain::Mixed
        ) && matches!(
            self.artifact,
            TaskExecutionArtifact::Code
                | TaskExecutionArtifact::Config
                | TaskExecutionArtifact::Mixed
        )
    }
}
