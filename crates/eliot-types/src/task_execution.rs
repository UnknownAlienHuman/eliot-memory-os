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

/// Derived execution classification. `Default` is Rust-side construction only:
/// no field carries `#[serde(default)]`, so all five members stay required on
/// the wire and no Serde default can fabricate a class.
///
/// Decoder: derived, no `flatten`, no tagging; the four member enums are
/// externally tagged and already refuse an unknown variant.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
