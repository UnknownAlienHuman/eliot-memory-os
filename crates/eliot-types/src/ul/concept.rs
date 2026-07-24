use crate::{CueBinding, ProjectId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ModuleCard {
    pub card_id: String,
    pub project_id: ProjectId,
    pub path: String,
    pub body_md: String,
    pub verifier: String,
    pub hotspot_ref: Option<String>,
    pub co_change_refs: Vec<String>,
    pub failure_refs: Vec<String>,
    pub source_refs: Vec<String>,
    pub cue_bindings: Vec<CueBinding>,
    pub build_fingerprint: String,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ConceptKind {
    DomainConcept,
    Subsystem,
    Mechanism,
    Policy,
    ExternalDependency,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ConceptNode {
    pub concept_id: String,
    pub project_id: ProjectId,
    pub name: String,
    pub kind: ConceptKind,
    pub purpose: String,
    pub boundary_paths: Vec<String>,
    pub invariant_refs: Vec<String>,
    pub hotspot_refs: Vec<String>,
    pub entrypoint_refs: Vec<String>,
    pub parent_concept_id: Option<String>,
    pub cue_bindings: Vec<CueBinding>,
    pub source_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct FileDependency {
    pub path: String,
    pub blake3: String,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct DependencyManifest {
    #[serde(default)]
    pub project_root: String,
    pub file_deps: Vec<FileDependency>,
    pub claim_deps: Vec<String>,
    pub decision_deps: Vec<String>,
    pub edge_deps: Vec<String>,
    pub report_deps: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct ProjectCharter {
    pub charter_id: String,
    pub project_id: ProjectId,
    pub body_md: String,
    pub concept_refs: Vec<String>,
    pub dependency_manifest: DependencyManifest,
    pub build_id: String,
    pub cue_bindings: Vec<CueBinding>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct SystemFlow {
    pub from_concept: String,
    pub to_concept: String,
    pub flow_kind: String,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct SystemMap {
    pub map_id: String,
    pub project_id: ProjectId,
    pub body_md: String,
    pub subsystem_concept_refs: Vec<String>,
    pub flow_edges: Vec<SystemFlow>,
    pub dependency_manifest: DependencyManifest,
    pub build_id: String,
    pub cue_bindings: Vec<CueBinding>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct SubsystemCapsule {
    pub capsule_id: String,
    pub project_id: ProjectId,
    pub concept_id: String,
    pub body_md: String,
    pub dependency_manifest: DependencyManifest,
    pub build_id: String,
    pub cue_bindings: Vec<CueBinding>,
    pub source_refs: Vec<String>,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PyramidTargetKind {
    SubsystemCapsule,
    SystemMap,
    ProjectCharter,
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum PyramidBuildStatus {
    Promoted,
    RejectedAnchor,
    RejectedBudget,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct CapsuleBuild {
    pub build_id: String,
    pub project_id: ProjectId,
    pub target_kind: PyramidTargetKind,
    pub target_id: String,
    pub inputs_hash: String,
    pub anchor_validation: Vec<String>,
    pub budget_limit: u32,
    pub token_estimate: u32,
    pub status: PyramidBuildStatus,
    pub previous_build_id: Option<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum CapsuleFreshness {
    Fresh,
    Stale {
        changed: Vec<String>,
        missing: Vec<String>,
    },
}

#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CoverageClass {
    Covered,
    Thin,
    Blind,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct SubsystemCoverage {
    pub concept_id: String,
    pub capsule_ref: Option<String>,
    pub capsule_fresh: bool,
    pub module_card_count: u32,
    pub claim_count: u32,
    pub decision_count: u32,
    pub failure_count: u32,
    pub coverage: CoverageClass,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct DangerPath {
    pub path: String,
    pub score: u8,
    pub failure_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct UlMetacognitionView {
    pub coverage: Vec<SubsystemCoverage>,
    pub novelty_percent: u8,
    pub novel_paths: Vec<String>,
    pub danger_paths: Vec<DangerPath>,
}
