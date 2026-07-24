use crate::{ProjectId, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const UL_FIELD_VALIDATION_SCHEMA_VERSION: &str = "ul-field-validation-v1";
pub const UL_FIELD_VALIDATION_BASELINE_COMMIT: &str = "80ff615062b61b08df6435a62ce27fd97ee8912f";

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlTaskLedger {
    pub task_id: TaskId,
    pub project_id: ProjectId,
    pub injected_tokens: u64,
    pub read_tool_input_bytes: u64,
    pub read_tool_output_bytes: u64,
    pub expanded_injected_handles: u32,
    pub acknowledged_items: u32,
    pub first_mutation_seen: bool,
}

#[derive(Clone, Debug, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlUseReport {
    pub project_id: ProjectId,
    pub tasks: u32,
    pub injected_tokens: u64,
    pub exploration_tokens: u64,
    pub acknowledged_fraction: f64,
    pub expanded_after_injection_fraction: f64,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UlArtifactInventory {
    pub concept_count: u32,
    pub capsule_count: u32,
    pub fresh_capsule_count: u32,
    pub stale_capsule_count: u32,
    pub module_card_count: u32,
    pub charter_count: u32,
    pub system_map_count: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UlGraphInventory {
    pub co_change_edges: u32,
    pub card_covers_edges: u32,
    pub concept_implemented_by_edges: u32,
    pub concept_depends_on_edges: u32,
    pub capsule_covers_edges: u32,
    #[serde(default)]
    pub total_ul_edges: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UlPredictionInventory {
    pub total: u32,
    pub unresolved: u32,
    pub hit: u32,
    pub miss: u32,
    pub unresolvable: u32,
    pub resolved_subsystem_count: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UlReadinessState {
    Eligible,
    NotEligible,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UlFeatureReadiness {
    pub state: UlReadinessState,
    pub reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UlTask08Readiness {
    pub spreading_activation: UlFeatureReadiness,
    pub reverse_dependency_index: UlFeatureReadiness,
    pub token_ab_and_downgrade: UlFeatureReadiness,
    pub weekly_understanding_exam: UlFeatureReadiness,
    pub model_prose_refinement: UlFeatureReadiness,
    pub host_surface_optimization: UlFeatureReadiness,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UlReadinessInventory {
    pub artifacts: UlArtifactInventory,
    pub graph: UlGraphInventory,
    pub predictions: UlPredictionInventory,
    pub ledger_tasks: u32,
    pub tasks_with_injection: u32,
    pub injection_receipts: u32,
    pub acknowledged_items: u32,
    pub expanded_injected_handles: u32,
    pub read_tool_input_bytes: u64,
    pub read_tool_output_bytes: u64,
    pub acknowledged_fraction: f64,
    pub expanded_after_injection_fraction: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UlFieldValidationManifest {
    pub schema_version: String,
    pub project_id: ProjectId,
    pub project_root: String,
    pub baseline_merge_commit: String,
    pub second_repository: Option<UlSecondRepositoryValidation>,
    pub task_annotations: Vec<UlFieldTaskAnnotation>,
    pub prose_failure_signals: Vec<UlProseFailureSignal>,
    pub host_surface_incidents: Vec<UlHostSurfaceIncident>,
}

impl Default for UlFieldValidationManifest {
    fn default() -> Self {
        Self {
            schema_version: UL_FIELD_VALIDATION_SCHEMA_VERSION.to_owned(),
            project_id: ProjectId::from_uuid(uuid::Uuid::nil()),
            project_root: String::new(),
            baseline_merge_commit: UL_FIELD_VALIDATION_BASELINE_COMMIT.to_owned(),
            second_repository: None,
            task_annotations: Vec::new(),
            prose_failure_signals: Vec::new(),
            host_surface_incidents: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UlSecondRepositoryValidation {
    pub project_id: ProjectId,
    pub project_root: String,
    pub head_commit: String,
    pub concept_count: u32,
    pub capsule_count: u32,
    pub module_card_count: u32,
    pub rejected_builds: u32,
    pub zero_model_calls: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub completed_at: OffsetDateTime,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UlFieldTaskAnnotation {
    pub task_id: TaskId,
    pub task_class: String,
    pub real_task: bool,
    pub verifier_ref: String,
    pub outcome: String,
    pub notes: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UlProseFailureSignal {
    pub capsule_ref: String,
    pub kind: String,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UlHostSurfaceIncident {
    pub kind: String,
    pub session_ref: String,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct UlFieldEvidenceSummary {
    pub manifest_present: bool,
    pub manifest_valid: bool,
    pub matched_real_tasks: u32,
    pub matched_real_injected_tasks: u32,
    pub second_repository_complete: bool,
    pub second_repository_status: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UlReadinessSnapshot {
    pub inventory: UlReadinessInventory,
    pub task08_readiness: UlTask08Readiness,
    pub field_evidence: UlFieldEvidenceSummary,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct UlLedgerDelta {
    pub injected_tokens: u64,
    pub read_tool_input_bytes: u64,
    pub read_tool_output_bytes: u64,
    pub expanded_injected_handles: u32,
    pub acknowledged_items: u32,
    pub first_mutation_seen: bool,
}
