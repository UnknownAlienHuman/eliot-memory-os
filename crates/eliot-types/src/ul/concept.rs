use crate::{CueBinding, ProjectId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
    #[serde(default)]
    pub dependency_manifest: DependencyManifest,
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct FileDependency {
    pub path: String,
    pub blake3: String,
}

#[derive(Clone, Debug, Default, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct SystemFlow {
    pub from_concept: String,
    pub to_concept: String,
    pub flow_kind: String,
    pub evidence_ref: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    ModuleCard,
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
#[serde(deny_unknown_fields)]
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

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum CapsuleFreshness {
    Fresh,
    Stale {
        changed: Vec<String>,
        missing: Vec<String>,
    },
}

impl<'de> Deserialize<'de> for CapsuleFreshness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(CapsuleFreshnessVisitor)
    }
}

struct CapsuleFreshnessVisitor;

impl<'de> serde::de::Visitor<'de> for CapsuleFreshnessVisitor {
    type Value = CapsuleFreshness;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a capsule freshness record")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut status: Option<String> = None;
        let mut changed: Option<Vec<String>> = None;
        let mut missing: Option<Vec<String>> = None;

        while let Some(key) = map.next_key::<String>()? {
            match key.as_str() {
                "status" => set_once(&mut status, map.next_value()?, "status")?,
                "changed" => set_once(&mut changed, map.next_value()?, "changed")?,
                "missing" => set_once(&mut missing, map.next_value()?, "missing")?,
                _ => {
                    return Err(serde::de::Error::unknown_field(
                        key.as_str(),
                        &["status", "changed", "missing"],
                    ));
                }
            }
        }

        let status = required(status, "status")?;
        match status.as_str() {
            "fresh" => {
                if changed.is_some() {
                    return Err(serde::de::Error::unknown_field("changed", &["status"]));
                }
                if missing.is_some() {
                    return Err(serde::de::Error::unknown_field("missing", &["status"]));
                }
                Ok(CapsuleFreshness::Fresh)
            }
            "stale" => Ok(CapsuleFreshness::Stale {
                changed: required(changed, "changed")?,
                missing: required(missing, "missing")?,
            }),
            other => Err(serde::de::Error::unknown_variant(
                other,
                &["fresh", "stale"],
            )),
        }
    }
}

fn set_once<T, E>(slot: &mut Option<T>, value: T, key: &'static str) -> Result<(), E>
where
    E: serde::de::Error,
{
    if slot.is_some() {
        return Err(E::duplicate_field(key));
    }
    *slot = Some(value);
    Ok(())
}

fn required<T, E>(value: Option<T>, field: &'static str) -> Result<T, E>
where
    E: serde::de::Error,
{
    value.ok_or_else(|| E::missing_field(field))
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
#[serde(deny_unknown_fields)]
pub struct SubsystemCoverage {
    pub concept_id: String,
    pub capsule_ref: Option<String>,
    pub capsule_fresh: bool,
    pub module_card_count: u32,
    pub claim_count: u32,
    pub decision_count: u32,
    pub failure_count: u32,
    pub experience_count: u32,
    pub coverage: CoverageClass,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DangerPath {
    pub path: String,
    pub score: u8,
    pub failure_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlMetacognitionView {
    pub policy_version: String,
    pub coverage: Vec<SubsystemCoverage>,
    pub novelty_percent: u8,
    pub novel_paths: Vec<String>,
    pub danger_paths: Vec<DangerPath>,
}
