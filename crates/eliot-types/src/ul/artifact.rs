use super::behavior::{CoChangeEdge, HotspotScore, MiningRun};
use super::concept::{
    CapsuleBuild, ConceptNode, ModuleCard, ProjectCharter, SubsystemCapsule, SystemMap,
};
use crate::{CueBinding, ProjectId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum UlArtifact {
    MiningRun(MiningRun),
    HotspotScore(HotspotScore),
    CoChangeEdge(CoChangeEdge),
    ModuleCard(ModuleCard),
    ConceptNode(ConceptNode),
    ProjectCharter(ProjectCharter),
    SystemMap(SystemMap),
    SubsystemCapsule(SubsystemCapsule),
    CapsuleBuild(CapsuleBuild),
}

impl UlArtifact {
    #[must_use]
    pub const fn receipt_kind(&self) -> &'static str {
        match self {
            Self::MiningRun(_) => "mining_run",
            Self::HotspotScore(_) => "hotspot_score",
            Self::CoChangeEdge(_) => "co_change_edge",
            Self::ModuleCard(_) => "module_card",
            Self::ConceptNode(_) => "concept_node",
            Self::ProjectCharter(_) => "project_charter",
            Self::SystemMap(_) => "system_map",
            Self::SubsystemCapsule(_) => "subsystem_capsule",
            Self::CapsuleBuild(_) => "capsule_build",
        }
    }

    #[must_use]
    pub fn artifact_id(&self) -> &str {
        match self {
            Self::MiningRun(value) => &value.run_id,
            Self::HotspotScore(value) => &value.hotspot_id,
            Self::CoChangeEdge(value) => &value.edge_id,
            Self::ModuleCard(value) => &value.card_id,
            Self::ConceptNode(value) => &value.concept_id,
            Self::ProjectCharter(value) => &value.charter_id,
            Self::SystemMap(value) => &value.system_map_id,
            Self::SubsystemCapsule(value) => &value.capsule_id,
            Self::CapsuleBuild(value) => &value.build_id,
        }
    }

    #[must_use]
    pub const fn project_id(&self) -> ProjectId {
        match self {
            Self::MiningRun(value) => value.project_id,
            Self::HotspotScore(value) => value.project_id,
            Self::CoChangeEdge(value) => value.project_id,
            Self::ModuleCard(value) => value.project_id,
            Self::ConceptNode(value) => value.project_id,
            Self::ProjectCharter(value) => value.project_id,
            Self::SystemMap(value) => value.project_id,
            Self::SubsystemCapsule(value) => value.project_id,
            Self::CapsuleBuild(value) => value.project_id,
        }
    }

    #[must_use]
    pub fn cue_bindings(&self) -> &[CueBinding] {
        match self {
            Self::MiningRun(value) => &value.cue_bindings,
            Self::HotspotScore(value) => &value.cue_bindings,
            Self::CoChangeEdge(value) => &value.cue_bindings,
            Self::ModuleCard(value) => &value.cue_bindings,
            Self::ConceptNode(value) => &value.cue_bindings,
            Self::ProjectCharter(value) => &value.cue_bindings,
            Self::SystemMap(value) => &value.cue_bindings,
            Self::SubsystemCapsule(value) => &value.cue_bindings,
            Self::CapsuleBuild(value) => &value.cue_bindings,
        }
    }
}
