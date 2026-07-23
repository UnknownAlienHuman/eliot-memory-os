use crate::{CueBinding, ProjectId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

// Task 06 replaces these bounded placeholders with its final pyramid fields.
// They keep the Task-05 ingress closed without admitting arbitrary JSON kinds.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConceptNode {
    pub concept_id: String,
    pub project_id: ProjectId,
    pub cue_bindings: Vec<CueBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectCharter {
    pub charter_id: String,
    pub project_id: ProjectId,
    pub cue_bindings: Vec<CueBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SystemMap {
    pub system_map_id: String,
    pub project_id: ProjectId,
    pub cue_bindings: Vec<CueBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SubsystemCapsule {
    pub capsule_id: String,
    pub project_id: ProjectId,
    pub cue_bindings: Vec<CueBinding>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapsuleBuild {
    pub build_id: String,
    pub project_id: ProjectId,
    pub cue_bindings: Vec<CueBinding>,
}
