use super::{
    ActivationEngine, ActivationProjection, CueIndexSnapshot, InjectionPlan, InjectionPlanner,
    InjectionSelection, InjectionSelectionPolicy, MetacognitionService, TouchedCue,
};
use crate::EngineError;
use eliot_types::{
    CausalBridgeHop, CognitiveProjectionReadState, ConceptNode, CoverageClass, CueKind,
    CueRecordSource, MAX_DURABLE_PENDING_INJECTIONS_PER_SESSION, MemoryRevision, ModuleCard,
    ObservedCue, PendingInjectionItem, ProjectCharter, ProjectId, ProjectUnderstandingEvidence,
    SessionId, SubsystemCapsule, SystemMap, TaskId, UlInjectionMode, UlMetacognitionView,
    path_matches_boundary, ul_token_estimate,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::sync::{Arc, Mutex};

pub const DEFAULT_PROJECT_SNAPSHOT_MAX_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_ARTIFACT_BODY_MAX_BYTES: usize = 512 * 1024;
const DEFAULT_RECORD_PREVIEW_MAX_BYTES: usize = 1024;
const PACKET_PYRAMID_BUDGET: u32 = 1_500;
const FALLBACK_MATCH_TOKEN_LIMIT: usize = 12;
const MAX_SESSION_STRING_BYTES: usize = 4 * 1024;
const MAX_PACKET_GATE_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotFreshness {
    Fresh,
    Stale,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectRevisions {
    pub canonical: Option<MemoryRevision>,
    pub cue: Option<MemoryRevision>,
    pub pyramid: Option<MemoryRevision>,
    pub activation: Option<MemoryRevision>,
    pub dependency: Option<MemoryRevision>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectionFamilyHealth {
    pub state: CognitiveProjectionReadState,
    pub revision: Option<MemoryRevision>,
    pub detail: Option<String>,
}

impl Default for ProjectionFamilyHealth {
    fn default() -> Self {
        Self {
            state: CognitiveProjectionReadState::Unavailable,
            revision: None,
            detail: None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectProjectionHealth {
    pub cue: ProjectionFamilyHealth,
    pub pyramid: ProjectionFamilyHealth,
    pub activation: ProjectionFamilyHealth,
    pub dependency: ProjectionFamilyHealth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectProjectionFamily {
    Cue,
    Pyramid,
    Activation,
    Dependency,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DirtyArtifactProjection {
    pub artifact_ref: String,
    pub changed_dependencies: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DependencyProjection {
    pub dependency_ref: String,
    pub dependent_artifact_refs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct FreshArtifact<T> {
    pub artifact: T,
    pub freshness: SnapshotFreshness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompactRecord {
    pub handle: String,
    pub record_kind: String,
    pub preview: String,
    pub payload: Option<Value>,
    pub source_fingerprint: String,
    pub negative_memory: bool,
    pub invariant: bool,
    pub token_estimate: u32,
    activation_refs: Vec<String>,
}

impl CompactRecord {
    pub(crate) fn pending_item(
        &self,
        fired_cues: Vec<ObservedCue>,
        activation_trace_ref: Option<String>,
        activation_score_milli: Option<u16>,
    ) -> PendingInjectionItem {
        PendingInjectionItem {
            item_ref: self.handle.clone(),
            record_kind: self.record_kind.clone(),
            preview: self.preview.clone(),
            payload: self.payload.clone(),
            source_fingerprint: self.source_fingerprint.clone(),
            fired_cues,
            negative_memory: self.negative_memory,
            invariant: self.invariant,
            token_estimate: self.token_estimate,
            activation_trace_ref,
            activation_score_milli,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CharterSnapshot {
    pub handle: String,
    pub body_md: Option<String>,
    pub concept_refs: Vec<String>,
    pub build_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SystemMapSnapshot {
    pub handle: String,
    pub body_md: Option<String>,
    pub subsystem_concept_refs: Vec<String>,
    pub flow_evidence_refs: Vec<String>,
    pub build_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CapsuleSnapshot {
    pub handle: String,
    pub concept_id: String,
    pub body_md: Option<String>,
    pub freshness: SnapshotFreshness,
    pub build_id: String,
    pub source_refs: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CardSnapshot {
    pub handle: String,
    pub path: String,
    pub body_md: Option<String>,
    pub freshness: SnapshotFreshness,
    pub verifier: String,
    pub source_refs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ProjectSnapshotInput {
    pub project_id: ProjectId,
    pub revisions: ProjectRevisions,
    pub health: ProjectProjectionHealth,
    pub cue_projection: CueIndexSnapshot,
    pub records: Vec<CueRecordSource>,
    pub charter: Option<ProjectCharter>,
    pub system_map: Option<SystemMap>,
    pub concepts: Vec<ConceptNode>,
    pub capsules: Vec<FreshArtifact<SubsystemCapsule>>,
    pub cards: Vec<FreshArtifact<ModuleCard>>,
    pub activation_projection: ActivationProjection,
    pub dirty: Vec<DirtyArtifactProjection>,
    pub dependencies: Vec<DependencyProjection>,
    pub metacognition: UlMetacognitionView,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectSnapshotBuilder {
    pub max_bytes: usize,
    pub max_artifact_body_bytes: usize,
    pub max_record_preview_bytes: usize,
}

impl Default for ProjectSnapshotBuilder {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_PROJECT_SNAPSHOT_MAX_BYTES,
            max_artifact_body_bytes: DEFAULT_ARTIFACT_BODY_MAX_BYTES,
            max_record_preview_bytes: DEFAULT_RECORD_PREVIEW_MAX_BYTES,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProjectSnapshot {
    project_id: ProjectId,
    revisions: ProjectRevisions,
    health: ProjectProjectionHealth,
    cue_projection: CueIndexSnapshot,
    records: Arc<BTreeMap<String, CompactRecord>>,
    activation_records: Arc<BTreeMap<String, Vec<String>>>,
    charter: Option<Arc<CharterSnapshot>>,
    system_map: Option<Arc<SystemMapSnapshot>>,
    concepts: Arc<BTreeMap<String, ConceptNode>>,
    capsules: Arc<BTreeMap<String, CapsuleSnapshot>>,
    cards: Arc<BTreeMap<String, CardSnapshot>>,
    activation_projection: Arc<ActivationProjection>,
    dirty: Arc<BTreeMap<String, DirtyArtifactProjection>>,
    dependencies: Arc<BTreeMap<String, DependencyProjection>>,
    metacognition: Arc<UlMetacognitionView>,
    estimated_bytes: usize,
}

impl ProjectSnapshotBuilder {
    #[allow(clippy::too_many_lines)]
    pub fn build(&self, input: ProjectSnapshotInput) -> Result<ProjectSnapshot, EngineError> {
        if self.max_bytes == 0 {
            return Err(snapshot_error(
                "project snapshot byte budget must be non-zero",
            ));
        }
        if input.cue_projection.project_id() != input.project_id {
            return Err(snapshot_error(
                "cue projection project does not match project snapshot scope",
            ));
        }
        if let Some(cue_revision) = input.cue_projection.revision()
            && input.revisions.cue != Some(cue_revision)
        {
            return Err(snapshot_error(
                "cue projection revision does not match project snapshot fence",
            ));
        }
        if input.health.cue.state != input.cue_projection.projection_state()
            || input.health.cue.revision != input.cue_projection.revision()
        {
            return Err(snapshot_error(
                "cue projection health does not match the installed cue snapshot",
            ));
        }
        for (name, revision, health) in [
            ("pyramid", input.revisions.pyramid, &input.health.pyramid),
            (
                "activation",
                input.revisions.activation,
                &input.health.activation,
            ),
            (
                "dependency",
                input.revisions.dependency,
                &input.health.dependency,
            ),
        ] {
            if health.revision != revision {
                return Err(snapshot_error(&format!(
                    "{name} projection health does not match project snapshot revisions"
                )));
            }
            if health.state.is_published() && revision.is_none() {
                return Err(snapshot_error(&format!(
                    "published {name} projection omitted its revision fence"
                )));
            }
        }
        let mut records = BTreeMap::new();
        let mut activation_records = BTreeMap::<String, Vec<String>>::new();
        for source in input.records {
            if source.record_ref.trim().is_empty() {
                return Err(snapshot_error("compact record handle must not be empty"));
            }
            if records.contains_key(&source.record_ref) {
                return Err(snapshot_error(&format!(
                    "duplicate compact record handle {}",
                    source.record_ref
                )));
            }
            let invariant = source.record_kind == "invariant";
            if (source.negative_memory || invariant) && source.payload.is_none() {
                return Err(snapshot_error(&format!(
                    "mandatory payload is missing for {}",
                    source.record_ref
                )));
            }
            let encoded = serde_json::to_vec(&source)?;
            let activation_refs = activation_refs(&source);
            for activation_ref in &activation_refs {
                activation_records
                    .entry(activation_ref.clone())
                    .or_default()
                    .push(source.record_ref.clone());
            }
            let preview = truncate_utf8(&source.preview_text, self.max_record_preview_bytes);
            let token_estimate = ul_token_estimate(&preview);
            records.insert(
                source.record_ref.clone(),
                CompactRecord {
                    handle: source.record_ref,
                    record_kind: source.record_kind,
                    preview,
                    payload: source.payload,
                    source_fingerprint: blake3::hash(&encoded).to_hex().to_string(),
                    negative_memory: source.negative_memory,
                    invariant,
                    token_estimate,
                    activation_refs,
                },
            );
        }
        if let Some(missing_handle) = input
            .cue_projection
            .record_refs()
            .into_iter()
            .find(|handle| !records.contains_key(handle))
        {
            return Err(snapshot_error(&format!(
                "cue projection handle {missing_handle} is absent from compact project records"
            )));
        }
        for refs in activation_records.values_mut() {
            refs.sort();
            refs.dedup();
        }
        let charter = input.charter.map(|artifact| CharterSnapshot {
            handle: format!("charter:{}", artifact.charter_id),
            body_md: bounded_body(artifact.body_md, self.max_artifact_body_bytes),
            concept_refs: artifact.concept_refs,
            build_id: artifact.build_id,
        });
        let system_map = input.system_map.map(|artifact| SystemMapSnapshot {
            handle: format!("system-map:{}", artifact.map_id),
            body_md: bounded_body(artifact.body_md, self.max_artifact_body_bytes),
            subsystem_concept_refs: artifact.subsystem_concept_refs,
            flow_evidence_refs: artifact
                .flow_edges
                .into_iter()
                .map(|flow| flow.evidence_ref)
                .collect(),
            build_id: artifact.build_id,
        });
        let concepts = input
            .concepts
            .into_iter()
            .map(|concept| (concept.concept_id.clone(), concept))
            .collect::<BTreeMap<_, _>>();
        let capsules = input
            .capsules
            .into_iter()
            .map(|item| {
                let artifact = item.artifact;
                (
                    artifact.concept_id.clone(),
                    CapsuleSnapshot {
                        handle: format!("capsule:{}", artifact.capsule_id),
                        concept_id: artifact.concept_id,
                        body_md: bounded_body(artifact.body_md, self.max_artifact_body_bytes),
                        freshness: item.freshness,
                        build_id: artifact.build_id,
                        source_refs: artifact.source_refs,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let cards = input
            .cards
            .into_iter()
            .map(|item| {
                let artifact = item.artifact;
                let handle = format!("card:{}", artifact.card_id);
                (
                    handle.clone(),
                    CardSnapshot {
                        handle,
                        path: artifact.path,
                        body_md: bounded_body(artifact.body_md, self.max_artifact_body_bytes),
                        freshness: item.freshness,
                        verifier: artifact.verifier,
                        source_refs: artifact.source_refs,
                    },
                )
            })
            .collect::<BTreeMap<_, _>>();
        let dirty = input
            .dirty
            .into_iter()
            .map(|state| (state.artifact_ref.clone(), state))
            .collect();
        let dependencies = input
            .dependencies
            .into_iter()
            .map(|projection| (projection.dependency_ref.clone(), projection))
            .collect();
        let mut snapshot = ProjectSnapshot {
            project_id: input.project_id,
            revisions: compact_owned(&input.revisions)?,
            health: compact_owned(&input.health)?,
            cue_projection: input.cue_projection,
            records: Arc::new(compact_owned(&records)?),
            activation_records: Arc::new(compact_owned(&activation_records)?),
            charter: charter
                .as_ref()
                .map(compact_owned)
                .transpose()?
                .map(Arc::new),
            system_map: system_map
                .as_ref()
                .map(compact_owned)
                .transpose()?
                .map(Arc::new),
            concepts: Arc::new(compact_owned(&concepts)?),
            capsules: Arc::new(compact_owned(&capsules)?),
            cards: Arc::new(compact_owned(&cards)?),
            activation_projection: Arc::new(input.activation_projection),
            dirty: Arc::new(compact_owned(&dirty)?),
            dependencies: Arc::new(compact_owned(&dependencies)?),
            metacognition: Arc::new(compact_owned(&input.metacognition)?),
            estimated_bytes: 0,
        };
        snapshot.estimated_bytes = snapshot.estimate_bytes()?;
        if snapshot.estimated_bytes > self.max_bytes {
            for record in Arc::make_mut(&mut snapshot.records).values_mut().rev() {
                if !record.negative_memory && !record.invariant {
                    record.payload = None;
                }
            }
            snapshot.estimated_bytes = snapshot.estimate_bytes()?;
        }
        if snapshot.estimated_bytes > self.max_bytes {
            for card in Arc::make_mut(&mut snapshot.cards).values_mut().rev() {
                card.body_md = None;
            }
            for capsule in Arc::make_mut(&mut snapshot.capsules).values_mut().rev() {
                capsule.body_md = None;
            }
            if let Some(system_map) = snapshot.system_map.as_mut() {
                Arc::make_mut(system_map).body_md = None;
            }
            if let Some(charter) = snapshot.charter.as_mut() {
                Arc::make_mut(charter).body_md = None;
            }
            snapshot.estimated_bytes = snapshot.estimate_bytes()?;
        }
        if snapshot.estimated_bytes > self.max_bytes {
            return Err(snapshot_error(&format!(
                "project snapshot requires {} bytes, budget is {}; no handles or mandatory payloads were dropped",
                snapshot.estimated_bytes, self.max_bytes
            )));
        }
        Ok(snapshot)
    }
}

impl ProjectSnapshot {
    #[must_use]
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    #[must_use]
    pub const fn revisions(&self) -> &ProjectRevisions {
        &self.revisions
    }

    #[must_use]
    pub const fn health(&self) -> &ProjectProjectionHealth {
        &self.health
    }

    #[must_use]
    pub fn is_fully_published(&self) -> bool {
        let Some(canonical) = self.revisions.canonical else {
            return false;
        };
        self.health.cue.state.is_published()
            && self.health.pyramid.state.is_published()
            && self.health.activation.state.is_published()
            && self.health.dependency.state.is_published()
            && self.revisions.cue == Some(canonical)
            && self.revisions.pyramid == Some(canonical)
            && self.revisions.activation == Some(canonical)
            && self.revisions.dependency == Some(canonical)
    }

    #[must_use]
    pub const fn cue_projection(&self) -> &CueIndexSnapshot {
        &self.cue_projection
    }

    #[must_use]
    pub fn activation_projection(&self) -> &ActivationProjection {
        self.activation_projection.as_ref()
    }

    #[must_use]
    pub fn record(&self, handle: &str) -> Option<&CompactRecord> {
        self.records.get(handle)
    }

    pub fn record_handles(&self) -> impl Iterator<Item = &str> {
        self.records.keys().map(String::as_str)
    }

    #[must_use]
    pub fn record_refs_for_activation_node(&self, node_ref: &str) -> &[String] {
        self.activation_records
            .get(node_ref)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    #[must_use]
    pub fn card_is_fresh(&self, handle: &str) -> bool {
        self.cards
            .get(handle)
            .is_some_and(|card| card.freshness == SnapshotFreshness::Fresh)
    }

    #[must_use]
    pub fn charter(&self) -> Option<&CharterSnapshot> {
        self.charter.as_deref()
    }

    #[must_use]
    pub fn system_map(&self) -> Option<&SystemMapSnapshot> {
        self.system_map.as_deref()
    }

    #[must_use]
    pub fn boot_coverage(&self) -> String {
        let fresh = self
            .capsules
            .values()
            .filter(|capsule| capsule.freshness == SnapshotFreshness::Fresh)
            .count();
        let unassigned = self
            .concepts
            .values()
            .filter(|concept| concept.name == "_unassigned")
            .map(|concept| concept.boundary_paths.len())
            .sum::<usize>();
        format!(
            "{} subsystems; {fresh} fresh capsules; {unassigned} unassigned source files",
            self.concepts.len()
        )
    }

    #[must_use]
    pub const fn estimated_bytes(&self) -> usize {
        self.estimated_bytes
    }

    fn mark_stale(
        &mut self,
        family: ProjectProjectionFamily,
        target_revision: MemoryRevision,
        detail: Option<String>,
    ) {
        let health = match family {
            ProjectProjectionFamily::Cue => {
                self.cue_projection = self
                    .cue_projection
                    .with_projection_state(CognitiveProjectionReadState::Stale);
                &mut self.health.cue
            }
            ProjectProjectionFamily::Pyramid => &mut self.health.pyramid,
            ProjectProjectionFamily::Activation => &mut self.health.activation,
            ProjectProjectionFamily::Dependency => &mut self.health.dependency,
        };
        health.state = CognitiveProjectionReadState::Stale;
        health.revision = Some(target_revision);
        health.detail = detail;
    }

    fn estimate_bytes(&self) -> Result<usize, EngineError> {
        let mut total = self
            .cue_projection
            .estimated_bytes()
            .saturating_add(self.activation_projection.estimated_bytes())
            .saturating_add(size_of::<ProjectSnapshot>())
            .saturating_add(HOT_SNAPSHOT_OWNER_OVERHEAD_BYTES);
        total = total
            .saturating_add(conservative_owned_bytes(&self.project_id)?)
            .saturating_add(conservative_owned_bytes(&self.revisions)?)
            .saturating_add(conservative_owned_bytes(&self.health)?)
            .saturating_add(conservative_owned_bytes(self.records.as_ref())?)
            .saturating_add(conservative_owned_bytes(self.activation_records.as_ref())?)
            .saturating_add(conservative_owned_bytes(&self.charter.as_deref())?)
            .saturating_add(conservative_owned_bytes(&self.system_map.as_deref())?)
            .saturating_add(conservative_owned_bytes(self.concepts.as_ref())?)
            .saturating_add(conservative_owned_bytes(self.capsules.as_ref())?)
            .saturating_add(conservative_owned_bytes(self.cards.as_ref())?)
            .saturating_add(conservative_owned_bytes(self.dirty.as_ref())?)
            .saturating_add(conservative_owned_bytes(self.dependencies.as_ref())?)
            .saturating_add(conservative_owned_bytes(self.metacognition.as_ref())?);
        Ok(total)
    }

    #[allow(clippy::too_many_lines)]
    pub fn plan_packet_understanding(
        &self,
        request: &PacketUnderstandingRequest,
    ) -> PyramidPacketEnrichment {
        let fallback = bounded_fallback_match_tokens(&request.fallback_text);
        let mut ranked = self
            .concepts
            .values()
            .filter_map(|concept| {
                let path_score = request
                    .touched_paths
                    .iter()
                    .filter_map(|path| {
                        concept
                            .boundary_paths
                            .iter()
                            .filter(|boundary| path_matches_boundary(path, boundary))
                            .map(String::len)
                            .max()
                    })
                    .max()
                    .unwrap_or_default();
                let tokens = bounded_fallback_match_tokens(&format!(
                    "{} {} {}",
                    concept.name,
                    concept.purpose,
                    concept.boundary_paths.join(" ")
                ));
                let fallback_match = !fallback.is_disjoint(&tokens);
                (path_score > 0 || fallback_match).then_some((path_score, fallback_match, concept))
            })
            .collect::<Vec<_>>();
        if ranked.iter().any(|(path_score, _, _)| *path_score > 0) {
            ranked.retain(|(path_score, _, _)| *path_score > 0);
        }
        ranked.sort_by(|left, right| {
            right
                .0
                .cmp(&left.0)
                .then_with(|| right.1.cmp(&left.1))
                .then_with(|| left.2.concept_id.cmp(&right.2.concept_id))
        });
        ranked.truncate(3);
        let mut units = 0_u32;
        let mut concepts = Vec::new();
        let mut capsules = Vec::new();
        let mut danger = BTreeSet::new();
        let mut invariants = BTreeSet::new();
        let mut stale_target = None;
        for (_, _, concept) in &ranked {
            let value = json!({
                "ref": format!("concept:{}", concept.concept_id),
                "name": concept.name,
                "purpose": concept.purpose,
                "boundary_paths": concept.boundary_paths,
            });
            units = units.saturating_add(ul_token_estimate(&value.to_string()));
            concepts.push(value);
            danger.extend(concept.hotspot_refs.iter().cloned());
            danger.extend(concept.invariant_refs.iter().cloned());
            let Some(capsule) = self.capsules.get(&concept.concept_id) else {
                continue;
            };
            if capsule.freshness == SnapshotFreshness::Fresh {
                invariants.extend(concept.invariant_refs.iter().cloned());
            } else {
                stale_target.get_or_insert_with(|| concept.concept_id.clone());
            }
            let mut value = json!({
                "ref": capsule.handle,
                "freshness": capsule.freshness,
            });
            if let Some(body) = capsule.body_md.as_ref() {
                let body_units = ul_token_estimate(body);
                if units.saturating_add(body_units) <= PACKET_PYRAMID_BUDGET {
                    value["body_md"] = Value::String(body.clone());
                    units = units.saturating_add(body_units);
                } else {
                    value["handle_only"] = Value::Bool(true);
                }
            } else {
                value["handle_only"] = Value::Bool(true);
            }
            capsules.push(value);
        }
        let concept_list = self.concepts.values().cloned().collect::<Vec<_>>();
        let (mut coverage, mut blind_target) = MetacognitionService::coverage_for_paths(
            &concept_list,
            &self.metacognition,
            &request.touched_paths,
        );
        let covered_paths = request
            .touched_paths
            .iter()
            .filter(|path| {
                ranked.iter().any(|(_, _, concept)| {
                    concept
                        .boundary_paths
                        .iter()
                        .any(|boundary| path_matches_boundary(path, boundary))
                })
            })
            .count();
        let mut meta = MetacognitionService::scope_view(
            &concept_list,
            &self.metacognition,
            &request.touched_paths,
        );
        if let Some(target) = stale_target.as_ref() {
            coverage = CoverageClass::Blind;
            blind_target = Some(target.clone());
            if let Some(subsystem) = meta
                .coverage
                .iter_mut()
                .find(|subsystem| subsystem.concept_id == *target)
            {
                subsystem.capsule_fresh = false;
                subsystem.coverage = CoverageClass::Blind;
            }
        }
        let legacy_coverage = if coverage == CoverageClass::Blind || ranked.is_empty() {
            "blind"
        } else if request.touched_paths.is_empty()
            || (covered_paths == request.touched_paths.len() && capsules.len() == ranked.len())
        {
            "covered"
        } else {
            "thin"
        };
        let first = ranked.first().map(|(_, _, concept)| *concept);
        let bridge = first
            .map(|concept| concept_bridge(&request.task_id, concept))
            .unwrap_or_default();
        let resolved_concept_ids = ranked
            .iter()
            .map(|(_, _, concept)| concept.concept_id.clone())
            .collect::<Vec<_>>();
        let subsystem_concept_id =
            MetacognitionService::concept_for_paths(&concept_list, &request.touched_paths);
        let recommended_probe = self
            .cards
            .values()
            .filter(|card| {
                request
                    .touched_paths
                    .iter()
                    .any(|path| path_matches_boundary(path, &card.path))
            })
            .map(|card| card.verifier.clone())
            .filter(|verifier| !verifier.trim().is_empty())
            .min();
        let project_evidence =
            self.project_evidence(&ranked, &request.touched_paths, &danger, &invariants);
        PyramidPacketEnrichment {
            understanding: json!({
                "concepts": concepts,
                "capsules": capsules,
                "danger": danger.iter().cloned().collect::<Vec<_>>(),
                "coverage": legacy_coverage,
            }),
            bridge,
            meta,
            coverage,
            blind_target,
            recommended_probe,
            subsystem_concept_id,
            resolved_concept_ids,
            required_invariant_refs: invariants.iter().cloned().collect(),
            project_evidence,
        }
    }

    fn project_evidence(
        &self,
        ranked: &[(usize, bool, &ConceptNode)],
        touched_paths: &[String],
        danger: &BTreeSet<String>,
        invariants: &BTreeSet<String>,
    ) -> ProjectUnderstandingEvidence {
        let mut artifact_refs = ranked
            .iter()
            .map(|(_, _, concept)| format!("concept:{}", concept.concept_id))
            .collect::<Vec<_>>();
        artifact_refs.extend(ranked.iter().filter_map(|(_, _, concept)| {
            self.capsules
                .get(&concept.concept_id)
                .map(|capsule| capsule.handle.clone())
        }));
        if let Some(charter) = self.charter.as_ref() {
            artifact_refs.push(charter.handle.clone());
        }
        if let Some(map) = self.system_map.as_ref() {
            artifact_refs.push(map.handle.clone());
        }
        ProjectUnderstandingEvidence {
            project_purpose: self
                .charter
                .as_ref()
                .and_then(|charter| charter.body_md.as_deref())
                .and_then(first_content_line)
                .unwrap_or_default(),
            subsystem_refs: ranked
                .iter()
                .map(|(_, _, concept)| format!("concept:{}", concept.concept_id))
                .collect(),
            owner_modules: self
                .cards
                .values()
                .filter(|card| {
                    touched_paths
                        .iter()
                        .any(|path| path_matches_boundary(path, &card.path))
                })
                .map(|card| card.path.clone())
                .collect(),
            entrypoint_refs: ranked
                .iter()
                .flat_map(|(_, _, concept)| concept.entrypoint_refs.iter().cloned())
                .collect(),
            invariant_refs: invariants.iter().cloned().collect(),
            danger_refs: danger.iter().cloned().collect(),
            artifact_refs,
            flow_evidence_refs: self
                .system_map
                .as_ref()
                .map_or_else(Vec::new, |map| map.flow_evidence_refs.clone()),
            non_goals: self
                .charter
                .as_ref()
                .and_then(|charter| charter.body_md.as_deref())
                .map_or_else(Vec::new, |body| {
                    markdown_section_items(body, &["non-goal", "не цел"])
                }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketUnderstandingRequest {
    pub task_id: String,
    pub touched_paths: Vec<String>,
    pub fallback_text: String,
}

#[derive(Clone, Debug)]
pub struct PyramidPacketEnrichment {
    pub understanding: Value,
    pub bridge: Vec<CausalBridgeHop>,
    pub meta: UlMetacognitionView,
    pub coverage: CoverageClass,
    pub blind_target: Option<String>,
    pub recommended_probe: Option<String>,
    pub subsystem_concept_id: Option<String>,
    pub resolved_concept_ids: Vec<String>,
    pub required_invariant_refs: Vec<String>,
    pub project_evidence: ProjectUnderstandingEvidence,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnderstandingExecutionMode {
    #[default]
    Production,
    Treatment,
    Control,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingRestoreSource {
    PendingInjectionAndReceipts,
    PendingInjectionOnly,
    ReceiptsOnly,
    NotDurableYet,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeliveredFingerprint {
    pub item_ref: String,
    pub source_fingerprint: String,
}

#[derive(Clone, Debug)]
pub struct RestoredSession {
    pub project_id: ProjectId,
    pub session_id: SessionId,
    pub source: PendingRestoreSource,
    pub touched_cues: Vec<TouchedCue>,
    pub pending: Vec<PendingInjectionItem>,
    pub delivered: Vec<DeliveredFingerprint>,
    pub active_concepts: Vec<String>,
    pub packet_revision: Option<MemoryRevision>,
    pub execution_mode: UnderstandingExecutionMode,
    pub boot_sent: bool,
}

#[derive(Clone, Debug)]
pub struct SessionSnapshot {
    pub project_id: ProjectId,
    pub session_id: SessionId,
    pub touched_cues: Vec<TouchedCue>,
    pub touched_paths: BTreeSet<String>,
    pub pending: Vec<PendingInjectionItem>,
    pub delivered: BTreeMap<String, String>,
    pub active_concepts: BTreeSet<String>,
    pub packet_revision: Option<MemoryRevision>,
    pub execution_mode: UnderstandingExecutionMode,
    pub restore_source: PendingRestoreSource,
    pub packet_context_ref: Option<String>,
    pub packet_handles: BTreeSet<String>,
    pub last_task_id: Option<TaskId>,
    pub packet_gate: Option<Value>,
    pub boot_sent: bool,
    next_touch_sequence: u64,
}

impl SessionSnapshot {
    fn empty(
        project_id: ProjectId,
        session_id: SessionId,
        execution_mode: UnderstandingExecutionMode,
    ) -> Self {
        Self {
            project_id,
            session_id,
            touched_cues: Vec::new(),
            touched_paths: BTreeSet::new(),
            pending: Vec::new(),
            delivered: BTreeMap::new(),
            active_concepts: BTreeSet::new(),
            packet_revision: None,
            execution_mode,
            restore_source: PendingRestoreSource::NotDurableYet,
            packet_context_ref: None,
            packet_handles: BTreeSet::new(),
            last_task_id: None,
            packet_gate: None,
            boot_sent: false,
            next_touch_sequence: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnderstandingRuntimeConfig {
    pub max_projects: usize,
    pub max_sessions: usize,
    pub max_touched_cues_per_session: usize,
    pub max_pending_per_session: usize,
    pub max_delivered_per_session: usize,
    pub activation_enable_min_edges: u32,
}

impl Default for UnderstandingRuntimeConfig {
    fn default() -> Self {
        Self {
            max_projects: 16,
            max_sessions: 256,
            max_touched_cues_per_session: 128,
            max_pending_per_session: MAX_DURABLE_PENDING_INJECTIONS_PER_SESSION,
            max_delivered_per_session: 10_000,
            activation_enable_min_edges: 500,
        }
    }
}

#[derive(Default)]
struct RuntimeState {
    clock: u64,
    projects: BTreeMap<ProjectId, (u64, Arc<ProjectSnapshot>)>,
    sessions: BTreeMap<(ProjectId, SessionId), (u64, SessionSnapshot)>,
}

/// The sole bounded owner of hot project and session understanding state.
pub struct UnderstandingRuntime {
    config: UnderstandingRuntimeConfig,
    activation: ActivationEngine,
    state: Mutex<RuntimeState>,
    pending_commit: Arc<tokio::sync::Mutex<()>>,
}

impl UnderstandingRuntime {
    #[must_use]
    pub fn new(mut config: UnderstandingRuntimeConfig) -> Self {
        config.max_projects = config.max_projects.max(1);
        config.max_sessions = config.max_sessions.max(1);
        config.max_touched_cues_per_session = config.max_touched_cues_per_session.max(1);
        config.max_pending_per_session = config.max_pending_per_session.max(1);
        config.max_delivered_per_session = config.max_delivered_per_session.max(1);
        Self {
            activation: ActivationEngine::new(config.activation_enable_min_edges),
            config,
            state: Mutex::new(RuntimeState::default()),
            pending_commit: Arc::new(tokio::sync::Mutex::new(())),
        }
    }

    pub async fn acquire_pending_commit(&self) -> tokio::sync::OwnedMutexGuard<()> {
        Arc::clone(&self.pending_commit).lock_owned().await
    }

    pub fn install_project(&self, snapshot: ProjectSnapshot) -> Result<(), EngineError> {
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        let incoming_revision = snapshot.revisions.canonical.ok_or_else(|| {
            snapshot_error("project snapshot must carry a canonical revision fence")
        })?;
        if let Some((_, current)) = state.projects.get(&snapshot.project_id()) {
            let current_revision = current.revisions.canonical.ok_or_else(|| {
                snapshot_error("installed project snapshot omitted its canonical revision fence")
            })?;
            let revisions_advance = revisions_advance(&current.revisions, &snapshot.revisions);
            let health_recovers = projection_health_recovers(&current.health, &snapshot.health);
            if !revisions_are_monotonic(&current.revisions, &snapshot.revisions)
                || !projection_health_is_monotonic(&current.health, &snapshot.health)
                || (!revisions_advance && !health_recovers)
            {
                return Err(snapshot_error(&format!(
                    "non-monotonic project snapshot revision {} does not advance or recover published health from {}",
                    incoming_revision.value(),
                    current_revision.value()
                )));
            }
        }
        state.clock = state.clock.saturating_add(1);
        let sequence = state.clock;
        state
            .projects
            .insert(snapshot.project_id(), (sequence, Arc::new(snapshot)));
        while state.projects.len() > self.config.max_projects {
            let Some(project_id) = state
                .projects
                .iter()
                .min_by_key(|(_, (sequence, _))| *sequence)
                .map(|(project_id, _)| *project_id)
            else {
                break;
            };
            state.projects.remove(&project_id);
            state
                .sessions
                .retain(|(session_project, _), _| *session_project != project_id);
        }
        Ok(())
    }

    pub fn mark_project_stale(
        &self,
        project_id: ProjectId,
        family: ProjectProjectionFamily,
        target_revision: MemoryRevision,
        detail: Option<String>,
    ) -> Result<(), EngineError> {
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        let Some((sequence, current)) = state.projects.get(&project_id).cloned() else {
            return Err(EngineError::ServiceNotReady {
                service: "understanding_runtime".to_owned(),
                reason: format!("project snapshot {project_id} is not installed"),
            });
        };
        let mut stale_snapshot = (*current).clone();
        stale_snapshot.mark_stale(family, target_revision, detail);
        state
            .projects
            .insert(project_id, (sequence, Arc::new(stale_snapshot)));
        Ok(())
    }

    pub fn mark_project_stale_all(
        &self,
        project_id: ProjectId,
        target_revision: MemoryRevision,
        detail: Option<&str>,
    ) -> Result<(), EngineError> {
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        let Some((sequence, current)) = state.projects.get(&project_id).cloned() else {
            return Err(EngineError::ServiceNotReady {
                service: "understanding_runtime".to_owned(),
                reason: format!("project snapshot {project_id} is not installed"),
            });
        };
        let mut stale_snapshot = (*current).clone();
        for family in [
            ProjectProjectionFamily::Cue,
            ProjectProjectionFamily::Pyramid,
            ProjectProjectionFamily::Activation,
            ProjectProjectionFamily::Dependency,
        ] {
            stale_snapshot.mark_stale(family, target_revision, detail.map(str::to_owned));
        }
        state
            .projects
            .insert(project_id, (sequence, Arc::new(stale_snapshot)));
        Ok(())
    }

    pub fn project_snapshot(
        &self,
        project_id: ProjectId,
    ) -> Result<Option<Arc<ProjectSnapshot>>, EngineError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| runtime_lock_error())?
            .projects
            .get(&project_id)
            .map(|(_, snapshot)| Arc::clone(snapshot)))
    }

    pub fn restore_session(&self, restored: RestoredSession) -> Result<(), EngineError> {
        let session = self.restored_session_snapshot(restored)?;
        self.install_session(session)
    }

    pub fn restore_session_if_absent(&self, restored: RestoredSession) -> Result<(), EngineError> {
        let session = self.restored_session_snapshot(restored)?;
        let key = (session.project_id, session.session_id);
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        if state.sessions.contains_key(&key) {
            return Ok(());
        }
        ensure_session_capacity(&mut state, self.config.max_sessions, key);
        state.clock = state.clock.saturating_add(1);
        let sequence = state.clock;
        state.sessions.insert(key, (sequence, session));
        Ok(())
    }

    fn restored_session_snapshot(
        &self,
        restored: RestoredSession,
    ) -> Result<SessionSnapshot, EngineError> {
        if matches!(
            restored.source,
            PendingRestoreSource::ReceiptsOnly | PendingRestoreSource::NotDurableYet
        ) && !restored.pending.is_empty()
        {
            return Err(snapshot_error(
                "receipt-only or not-durable-yet restore cannot fabricate pending injection",
            ));
        }
        if restored.source == PendingRestoreSource::PendingInjectionOnly
            && !restored.delivered.is_empty()
        {
            return Err(snapshot_error(
                "pending-only restore cannot fabricate delivered fingerprints",
            ));
        }
        let mut session = SessionSnapshot::empty(
            restored.project_id,
            restored.session_id,
            restored.execution_mode,
        );
        session.touched_cues = restored.touched_cues;
        session.touched_cues.sort_by_key(|cue| cue.sequence);
        session
            .touched_cues
            .truncate(self.config.max_touched_cues_per_session);
        session.next_touch_sequence = session.touched_cues.last().map_or(0, |cue| cue.sequence);
        session.touched_paths = session
            .touched_cues
            .iter()
            .filter(|touched| touched.cue.kind == CueKind::FilePath)
            .map(|touched| touched.cue.value.clone())
            .collect();
        for delivered in restored.delivered {
            session
                .delivered
                .insert(delivered.item_ref, delivered.source_fingerprint);
        }
        if session.delivered.len() > self.config.max_delivered_per_session {
            return Err(snapshot_error(
                "restored delivered fingerprints exceed the bounded durable receipt horizon",
            ));
        }
        let pending = restored
            .pending
            .into_iter()
            .filter(|item| session.delivered.get(&item.item_ref) != Some(&item.source_fingerprint))
            .collect();
        session.pending = bounded_pending(pending, self.config.max_pending_per_session)?;
        session.active_concepts = restored.active_concepts.into_iter().collect();
        trim_set(
            &mut session.active_concepts,
            self.config.max_pending_per_session,
        );
        session.packet_revision = restored.packet_revision;
        session.restore_source = restored.source;
        session.boot_sent = restored.boot_sent;
        Ok(session)
    }

    pub fn observe_arguments(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        tool_name: &str,
        arguments: &Value,
    ) -> Result<Vec<ObservedCue>, EngineError> {
        let cues = super::touched::extract_observed_cues(tool_name, arguments);
        self.record_observed_cues(project_id, session_id, &cues)?;
        Ok(cues)
    }

    pub fn observe_result(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        tool_name: &str,
        result: &Value,
    ) -> Result<Vec<ObservedCue>, EngineError> {
        let cues = super::touched::extract_observed_cues(tool_name, result);
        let exact_fetch = (tool_name == "eliot_fetch_l2")
            .then(|| super::touched::exact_fetch_context(project_id, session_id, result));
        self.record_observed_cues(project_id, session_id, &cues)?;
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        ensure_session_capacity(
            &mut state,
            self.config.max_sessions,
            (project_id, session_id),
        );
        let session = ensure_session(&mut state, project_id, session_id);
        if let Some(packet_id) = result.get("packet_id").and_then(Value::as_str) {
            session.packet_context_ref = Some(truncate_utf8(packet_id, MAX_SESSION_STRING_BYTES));
        }
        if let Some(revision) = result
            .get("at_revision")
            .or_else(|| result.get("memory_revision"))
            .and_then(Value::as_u64)
        {
            session.packet_revision = Some(MemoryRevision::new(revision));
        }
        if let Some(handles) = result.get("exact_handles").and_then(Value::as_array) {
            session.packet_handles = handles
                .iter()
                .filter_map(Value::as_str)
                .take(self.config.max_delivered_per_session)
                .map(|handle| truncate_utf8(handle, MAX_SESSION_STRING_BYTES))
                .collect();
        } else if let Some(Some((context_ref, handles))) = exact_fetch {
            session.packet_context_ref = Some(context_ref);
            session.packet_handles = handles
                .into_iter()
                .take(self.config.max_delivered_per_session)
                .collect();
        }
        if let Some(task_id) = result
            .get("task_id")
            .or_else(|| result.pointer("/task_contract/task_id"))
            .and_then(Value::as_str)
            .and_then(|task_id| task_id.parse().ok())
        {
            session.last_task_id = Some(task_id);
        }
        Ok(cues)
    }

    pub fn record_observed_cues(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        cues: &[ObservedCue],
    ) -> Result<(), EngineError> {
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        ensure_session_capacity(
            &mut state,
            self.config.max_sessions,
            (project_id, session_id),
        );
        let session = ensure_session(&mut state, project_id, session_id);
        for cue in normalized_cues(cues) {
            session.next_touch_sequence = session.next_touch_sequence.saturating_add(1);
            session.touched_cues.retain(|touched| touched.cue != cue);
            if cue.kind == CueKind::FilePath {
                session.touched_paths.insert(cue.value.clone());
            }
            session.touched_cues.push(TouchedCue {
                cue,
                sequence: session.next_touch_sequence,
            });
            if session.touched_cues.len() > self.config.max_touched_cues_per_session {
                session.touched_cues.remove(0);
            }
        }
        session.touched_paths = session
            .touched_cues
            .iter()
            .filter(|touched| touched.cue.kind == CueKind::FilePath)
            .map(|touched| touched.cue.value.clone())
            .collect();
        Ok(())
    }

    pub fn plan_cues(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        task_id: Option<TaskId>,
        cues: &[ObservedCue],
    ) -> Result<InjectionPlan, EngineError> {
        let snapshot =
            self.project_snapshot(project_id)?
                .ok_or_else(|| EngineError::ServiceNotReady {
                    service: "understanding_runtime".to_owned(),
                    reason: format!("project snapshot {project_id} is not installed"),
                })?;
        if !snapshot.is_fully_published() {
            let direct_firing = snapshot.cue_projection().fire(cues);
            return Ok(InjectionPlan {
                overflow: direct_firing.overflow,
                direct_firing,
                activation_trace: None,
                items: Vec::new(),
            });
        }
        InjectionPlanner::plan(&snapshot, &self.activation, session_id, task_id, cues)
    }

    pub fn enqueue_plan(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        plan: &InjectionPlan,
    ) -> Result<(), EngineError> {
        let candidate = self.prepare_pending_candidate(project_id, session_id, plan)?;
        self.install_pending_candidate(project_id, session_id, candidate, plan)
    }

    pub fn prepare_pending_candidate(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        plan: &InjectionPlan,
    ) -> Result<Vec<PendingInjectionItem>, EngineError> {
        let state = self.state.lock().map_err(|_| runtime_lock_error())?;
        let mut pending = state
            .sessions
            .get(&(project_id, session_id))
            .map(|(_, session)| session.pending.clone())
            .unwrap_or_default();
        for item in &plan.items {
            pending.retain(|current| current.item_ref != item.item_ref);
            pending.push(item.clone());
        }
        bounded_pending(pending, self.config.max_pending_per_session)
    }

    pub fn install_pending_candidate(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        candidate: Vec<PendingInjectionItem>,
        plan: &InjectionPlan,
    ) -> Result<(), EngineError> {
        let candidate = bounded_pending(candidate, self.config.max_pending_per_session)?;
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        ensure_session_capacity(
            &mut state,
            self.config.max_sessions,
            (project_id, session_id),
        );
        let session = ensure_session(&mut state, project_id, session_id);
        session.pending = candidate;
        if let Some(trace) = plan.activation_trace.as_ref() {
            session.active_concepts.extend(
                trace
                    .activated
                    .iter()
                    .filter_map(|node| node.node_ref.strip_prefix("concept:").map(str::to_owned)),
            );
            trim_set(
                &mut session.active_concepts,
                self.config.max_pending_per_session,
            );
        }
        Ok(())
    }

    pub fn select_pending(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        mode: UlInjectionMode,
    ) -> Result<InjectionSelection, EngineError> {
        self.select_pending_with_policy(
            project_id,
            session_id,
            mode,
            InjectionSelectionPolicy::default(),
        )
    }

    pub fn select_pending_with_policy(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        mode: UlInjectionMode,
        policy: InjectionSelectionPolicy,
    ) -> Result<InjectionSelection, EngineError> {
        let snapshot =
            self.project_snapshot(project_id)?
                .ok_or_else(|| EngineError::ServiceNotReady {
                    service: "understanding_runtime".to_owned(),
                    reason: format!("project snapshot {project_id} is not installed"),
                })?;
        if !snapshot.is_fully_published() {
            return Ok(InjectionSelection::default());
        }
        let session = self.session_snapshot(project_id, session_id)?;
        let Some(session) = session else {
            return Ok(InjectionSelection::default());
        };
        InjectionPlanner::select(
            &snapshot,
            &session.pending,
            &session.delivered,
            mode,
            policy,
        )
    }

    pub fn acknowledge_delivered(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        delivered: &[DeliveredFingerprint],
    ) -> Result<(), EngineError> {
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        ensure_session_capacity(
            &mut state,
            self.config.max_sessions,
            (project_id, session_id),
        );
        let session = ensure_session(&mut state, project_id, session_id);
        let mut next_delivered = session.delivered.clone();
        for item in delivered {
            next_delivered.insert(item.item_ref.clone(), item.source_fingerprint.clone());
        }
        if next_delivered.len() > self.config.max_delivered_per_session {
            return Err(snapshot_error(
                "delivered fingerprints exceed the bounded durable receipt horizon",
            ));
        }
        session.delivered = next_delivered;
        for item in delivered {
            session.pending.retain(|pending| {
                pending.item_ref != item.item_ref
                    || pending.source_fingerprint != item.source_fingerprint
            });
        }
        Ok(())
    }

    pub fn recent_cues(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        limit: usize,
    ) -> Result<Vec<ObservedCue>, EngineError> {
        Ok(self
            .session_snapshot(project_id, session_id)?
            .map(|mut session| {
                session
                    .touched_cues
                    .sort_by_key(|touched| std::cmp::Reverse(touched.sequence));
                session
                    .touched_cues
                    .into_iter()
                    .take(limit)
                    .map(|touched| touched.cue)
                    .collect()
            })
            .unwrap_or_default())
    }

    pub fn packet_context(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
    ) -> Result<(Option<String>, BTreeSet<String>), EngineError> {
        Ok(self
            .session_snapshot(project_id, session_id)?
            .map(|session| (session.packet_context_ref, session.packet_handles))
            .unwrap_or_default())
    }

    pub fn last_task_id(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
    ) -> Result<Option<TaskId>, EngineError> {
        Ok(self
            .session_snapshot(project_id, session_id)?
            .and_then(|session| session.last_task_id))
    }

    pub fn set_packet_gate(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        gate: Option<Value>,
    ) -> Result<(), EngineError> {
        if gate
            .as_ref()
            .map(encoded_len)
            .transpose()?
            .is_some_and(|bytes| bytes > MAX_PACKET_GATE_BYTES)
        {
            return Err(snapshot_error("session packet gate exceeds its byte bound"));
        }
        self.update_session(project_id, session_id, |session| session.packet_gate = gate)
    }

    pub fn packet_gate(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
    ) -> Result<Option<Value>, EngineError> {
        Ok(self
            .session_snapshot(project_id, session_id)?
            .and_then(|session| session.packet_gate))
    }

    pub fn set_execution_mode(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        mode: UnderstandingExecutionMode,
    ) -> Result<(), EngineError> {
        self.update_session(project_id, session_id, |session| {
            session.execution_mode = mode;
        })
    }

    pub fn set_packet_revision(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        revision: Option<MemoryRevision>,
    ) -> Result<(), EngineError> {
        self.update_session(project_id, session_id, |session| {
            session.packet_revision = revision;
        })
    }

    pub fn mark_boot_sent(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
    ) -> Result<(), EngineError> {
        self.update_session(project_id, session_id, |session| session.boot_sent = true)
    }

    pub fn boot_sent(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
    ) -> Result<bool, EngineError> {
        Ok(self
            .session_snapshot(project_id, session_id)?
            .is_some_and(|session| session.boot_sent))
    }

    pub fn session_snapshot(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
    ) -> Result<Option<SessionSnapshot>, EngineError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| runtime_lock_error())?
            .sessions
            .get(&(project_id, session_id))
            .map(|(_, session)| session.clone()))
    }

    fn install_session(&self, session: SessionSnapshot) -> Result<(), EngineError> {
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        state.clock = state.clock.saturating_add(1);
        let sequence = state.clock;
        state.sessions.insert(
            (session.project_id, session.session_id),
            (sequence, session),
        );
        while state.sessions.len() > self.config.max_sessions {
            let Some(key) = state
                .sessions
                .iter()
                .min_by_key(|(_, (sequence, _))| *sequence)
                .map(|(key, _)| *key)
            else {
                break;
            };
            state.sessions.remove(&key);
        }
        Ok(())
    }

    fn update_session(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        update: impl FnOnce(&mut SessionSnapshot),
    ) -> Result<(), EngineError> {
        let mut state = self.state.lock().map_err(|_| runtime_lock_error())?;
        ensure_session_capacity(
            &mut state,
            self.config.max_sessions,
            (project_id, session_id),
        );
        update(ensure_session(&mut state, project_id, session_id));
        Ok(())
    }
}

impl Default for UnderstandingRuntime {
    fn default() -> Self {
        Self::new(UnderstandingRuntimeConfig::default())
    }
}

fn ensure_session(
    state: &mut RuntimeState,
    project_id: ProjectId,
    session_id: SessionId,
) -> &mut SessionSnapshot {
    state.clock = state.clock.saturating_add(1);
    let sequence = state.clock;
    let entry = state
        .sessions
        .entry((project_id, session_id))
        .or_insert_with(|| {
            (
                sequence,
                SessionSnapshot::empty(
                    project_id,
                    session_id,
                    UnderstandingExecutionMode::Production,
                ),
            )
        });
    entry.0 = sequence;
    &mut entry.1
}

fn ensure_session_capacity(
    state: &mut RuntimeState,
    max_sessions: usize,
    incoming: (ProjectId, SessionId),
) {
    if state.sessions.contains_key(&incoming) {
        return;
    }
    while state.sessions.len() >= max_sessions {
        let Some(key) = state
            .sessions
            .iter()
            .min_by_key(|(_, (sequence, _))| *sequence)
            .map(|(key, _)| *key)
        else {
            break;
        };
        state.sessions.remove(&key);
    }
}

fn revisions_are_monotonic(current: &ProjectRevisions, incoming: &ProjectRevisions) -> bool {
    revision_component_is_monotonic(current.canonical, incoming.canonical)
        && revision_component_is_monotonic(current.cue, incoming.cue)
        && revision_component_is_monotonic(current.pyramid, incoming.pyramid)
        && revision_component_is_monotonic(current.activation, incoming.activation)
        && revision_component_is_monotonic(current.dependency, incoming.dependency)
}

fn revisions_advance(current: &ProjectRevisions, incoming: &ProjectRevisions) -> bool {
    revision_component_advances(current.canonical, incoming.canonical)
        || revision_component_advances(current.cue, incoming.cue)
        || revision_component_advances(current.pyramid, incoming.pyramid)
        || revision_component_advances(current.activation, incoming.activation)
        || revision_component_advances(current.dependency, incoming.dependency)
}

fn revision_component_is_monotonic(
    current: Option<MemoryRevision>,
    incoming: Option<MemoryRevision>,
) -> bool {
    current.is_none_or(|current| incoming.is_some_and(|incoming| incoming >= current))
}

fn revision_component_advances(
    current: Option<MemoryRevision>,
    incoming: Option<MemoryRevision>,
) -> bool {
    incoming.is_some_and(|incoming| current.is_none_or(|current| incoming > current))
}

fn projection_health_recovers(
    current: &ProjectProjectionHealth,
    incoming: &ProjectProjectionHealth,
) -> bool {
    family_health_recovers(&current.cue, &incoming.cue)
        || family_health_recovers(&current.pyramid, &incoming.pyramid)
        || family_health_recovers(&current.activation, &incoming.activation)
        || family_health_recovers(&current.dependency, &incoming.dependency)
}

fn projection_health_is_monotonic(
    current: &ProjectProjectionHealth,
    incoming: &ProjectProjectionHealth,
) -> bool {
    family_health_is_monotonic(&current.cue, &incoming.cue)
        && family_health_is_monotonic(&current.pyramid, &incoming.pyramid)
        && family_health_is_monotonic(&current.activation, &incoming.activation)
        && family_health_is_monotonic(&current.dependency, &incoming.dependency)
}

fn family_health_is_monotonic(
    current: &ProjectionFamilyHealth,
    incoming: &ProjectionFamilyHealth,
) -> bool {
    !current.state.is_published()
        || (incoming.state.is_published()
            && revision_component_is_monotonic(current.revision, incoming.revision))
}

fn family_health_recovers(
    current: &ProjectionFamilyHealth,
    incoming: &ProjectionFamilyHealth,
) -> bool {
    !current.state.is_published()
        && incoming.state.is_published()
        && revision_component_is_monotonic(current.revision, incoming.revision)
}

fn bounded_pending(
    mut pending: Vec<PendingInjectionItem>,
    max_pending: usize,
) -> Result<Vec<PendingInjectionItem>, EngineError> {
    pending.sort_by(|left, right| {
        right
            .negative_memory
            .cmp(&left.negative_memory)
            .then_with(|| right.invariant.cmp(&left.invariant))
            .then_with(|| left.item_ref.cmp(&right.item_ref))
            .then_with(|| left.source_fingerprint.cmp(&right.source_fingerprint))
    });
    pending.dedup_by(|left, right| {
        left.item_ref == right.item_ref && left.source_fingerprint == right.source_fingerprint
    });
    let mandatory = pending
        .iter()
        .filter(|item| item.negative_memory || item.invariant)
        .count();
    if mandatory > max_pending {
        return Err(snapshot_error(
            "session pending bound cannot retain every mandatory negative/invariant item",
        ));
    }
    pending.truncate(max_pending);
    Ok(pending)
}

fn activation_refs(source: &CueRecordSource) -> Vec<String> {
    let mut refs = source
        .cue_bindings
        .iter()
        .filter_map(|binding| match binding.cue_kind {
            CueKind::FilePath => Some(format!(
                "file:{}",
                eliot_types::normalize_path(&binding.cue_value, None)
            )),
            CueKind::DirPath => Some(format!(
                "dir:{}",
                eliot_types::normalize_path(&binding.cue_value, None)
            )),
            CueKind::Symbol => Some(format!(
                "symbol:{}",
                eliot_types::normalize_symbol(&binding.cue_value)
            )),
            CueKind::Dependency => Some(format!("dependency:{}", binding.cue_value)),
            CueKind::ApiSurface => Some(format!("api:{}", binding.cue_value)),
            CueKind::Subsystem => Some(format!("subsystem:{}", binding.cue_value)),
            CueKind::Concept => Some(format!("concept:{}", binding.cue_value)),
            CueKind::ErrorSignature | CueKind::CommandPattern | CueKind::TaskClass => None,
        })
        .collect::<Vec<_>>();
    refs.push(source.record_ref.clone());
    refs.sort();
    refs.dedup();
    refs
}

fn normalized_cues(cues: &[ObservedCue]) -> Vec<ObservedCue> {
    let mut normalized = cues
        .iter()
        .map(|cue| ObservedCue {
            kind: cue.kind,
            value: match cue.kind {
                CueKind::FilePath | CueKind::DirPath => {
                    eliot_types::normalize_path(&cue.value, None)
                }
                CueKind::Symbol => eliot_types::normalize_symbol(&cue.value),
                _ => cue
                    .value
                    .trim()
                    .chars()
                    .flat_map(char::to_lowercase)
                    .collect(),
            },
        })
        .filter(|cue| !cue.value.is_empty())
        .collect::<Vec<_>>();
    normalized.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.value.cmp(&right.value))
    });
    normalized.dedup();
    normalized
}

fn bounded_body(body: String, max_bytes: usize) -> Option<String> {
    (body.len() <= max_bytes).then_some(body)
}

const HOT_ALLOCATION_OVERHEAD_BYTES: usize = 32;
const HOT_MAP_ENTRY_OVERHEAD_BYTES: usize = 256;
const HOT_SNAPSHOT_OWNER_OVERHEAD_BYTES: usize = 4 * 1024;

fn compact_owned<T>(value: &T) -> Result<T, EngineError>
where
    T: Serialize + DeserializeOwned,
{
    let encoded = serde_json::to_vec(&value)?;
    Ok(serde_json::from_slice(&encoded)?)
}

fn encoded_len<T: Serialize>(value: &T) -> Result<usize, EngineError> {
    Ok(serde_json::to_vec(value)?.len())
}

fn conservative_owned_bytes<T: Serialize + ?Sized>(value: &T) -> Result<usize, EngineError> {
    let value = serde_json::to_value(value)?;
    Ok(size_of::<Value>().saturating_add(json_dynamic_requested_bytes(&value)))
}

fn json_dynamic_requested_bytes(value: &Value) -> usize {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) => 0,
        Value::String(value) => value
            .capacity()
            .saturating_add(HOT_ALLOCATION_OVERHEAD_BYTES),
        Value::Array(values) => values
            .capacity()
            .saturating_mul(size_of::<Value>())
            .saturating_add(HOT_ALLOCATION_OVERHEAD_BYTES)
            .saturating_add(
                values
                    .iter()
                    .map(json_dynamic_requested_bytes)
                    .fold(0_usize, usize::saturating_add),
            ),
        Value::Object(values) => values
            .iter()
            .map(|(key, value)| {
                size_of::<(String, Value)>()
                    .saturating_add(HOT_MAP_ENTRY_OVERHEAD_BYTES)
                    .saturating_add(key.capacity())
                    .saturating_add(HOT_ALLOCATION_OVERHEAD_BYTES)
                    .saturating_add(json_dynamic_requested_bytes(value))
            })
            .fold(HOT_ALLOCATION_OVERHEAD_BYTES, usize::saturating_add),
    }
}

fn truncate_utf8(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_owned();
    }
    let mut boundary = max_bytes;
    while !value.is_char_boundary(boundary) {
        boundary = boundary.saturating_sub(1);
    }
    value[..boundary].to_owned()
}

fn trim_set(set: &mut BTreeSet<String>, max: usize) {
    while set.len() > max {
        let Some(value) = set.last().cloned() else {
            break;
        };
        set.remove(&value);
    }
}

fn bounded_fallback_match_tokens(value: &str) -> BTreeSet<String> {
    eliot_types::normalize_query_tokens(value)
        .into_iter()
        .take(FALLBACK_MATCH_TOKEN_LIMIT)
        .collect()
}

fn concept_bridge(task_id: &str, concept: &ConceptNode) -> Vec<CausalBridgeHop> {
    let concept_ref = format!("concept:{}", concept.concept_id);
    let evidence = concept.source_refs.first().cloned().or_else(|| {
        concept
            .boundary_paths
            .first()
            .map(|path| format!("file:{path}"))
    });
    let mut bridge = vec![CausalBridgeHop {
        from: format!("intent:{task_id}"),
        relation: "scoped_to".to_owned(),
        to: concept_ref.clone(),
        evidence_ref: evidence,
    }];
    if let Some(entrypoint) = concept.entrypoint_refs.first() {
        bridge.push(CausalBridgeHop {
            from: concept_ref,
            relation: "implemented_by".to_owned(),
            to: entrypoint.clone(),
            evidence_ref: Some(entrypoint.clone()),
        });
    }
    bridge
}

fn first_content_line(markdown: &str) -> Option<String> {
    markdown
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.trim_start_matches(['-', '*', ' ']).to_owned())
}

fn markdown_section_items(markdown: &str, headings: &[&str]) -> Vec<String> {
    let mut active = false;
    let mut items = Vec::new();
    for line in markdown.lines().map(str::trim) {
        if line.starts_with('#') {
            let normalized = eliot_types::normalize_unicode_lowercase(line);
            active = headings.iter().any(|heading| normalized.contains(heading));
            continue;
        }
        if active && let Some(item) = line.strip_prefix("- ").or_else(|| line.strip_prefix("* ")) {
            items.push(item.to_owned());
        }
    }
    items
}

fn snapshot_error(reason: &str) -> EngineError {
    EngineError::WriteRejected(format!("understanding snapshot rejected: {reason}"))
}

fn runtime_lock_error() -> EngineError {
    EngineError::ServiceNotReady {
        service: "understanding_runtime".to_owned(),
        reason: "runtime state lock poisoned".to_owned(),
    }
}
