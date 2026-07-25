use eliot_engine::{
    CueIndexService, InjectionPlanner, MetacognitionService, PredictionService, TouchedSetRegistry,
    UlDependencyService, UlLedgerService, UlTokenPolicyService, WriterHandle, capsule_freshness,
    render_capsule_with_dirty,
};
use eliot_store::{CanonicalRecord, CanonicalStore};
use eliot_types::{
    CapsuleFreshness, CausalBridgeHop, ConceptNode, CoverageClass, HotspotScore, ModuleCard,
    ProjectId, SessionId, SubsystemCapsule, TaskId, UlExperimentArm, UlInjectionMode,
    UlMetacognitionView, UlTaskExperimentAssignment, path_matches_boundary, ul_token_estimate,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const PACKET_PYRAMID_BUDGET: u32 = 1_500;

pub(super) struct PyramidPacketEnrichment {
    pub understanding: Value,
    pub bridge: Vec<CausalBridgeHop>,
    pub meta: UlMetacognitionView,
    pub coverage: CoverageClass,
    pub blind_target: Option<String>,
    pub recommended_probe: Option<String>,
    pub subsystem_concept_id: Option<String>,
    pub required_invariant_refs: Vec<String>,
}

pub(super) struct UlRuntime {
    pub cue_index: Arc<CueIndexService>,
    pub touched: Arc<TouchedSetRegistry>,
    pub planner: Arc<InjectionPlanner>,
    pub dependency: Arc<UlDependencyService>,
    pub ledger: Arc<UlLedgerService>,
    pub token_policy: Arc<UlTokenPolicyService>,
    pub prediction: Arc<PredictionService>,
    store: CanonicalStore,
    project_root: PathBuf,
    runtime_root: PathBuf,
    dependency_ready: Mutex<HashSet<ProjectId>>,
}

impl UlRuntime {
    pub fn new(
        store: CanonicalStore,
        writer: WriterHandle,
        runtime_root: &Path,
        activation_enable_min_edges: u32,
    ) -> Self {
        let cue_index = Arc::new(CueIndexService::new(store.clone()));
        let touched = Arc::new(TouchedSetRegistry::new());
        let project_root = eliot_engine::canonical_project_root(runtime_root);
        let planner = Arc::new(
            InjectionPlanner::with_project_root_and_activation_min_edges(
                Arc::clone(&cue_index),
                store.clone(),
                writer.clone(),
                Arc::clone(&touched),
                project_root.clone(),
                activation_enable_min_edges,
            ),
        );
        let dependency = Arc::new(UlDependencyService::new(store.clone()));
        let ledger = Arc::new(UlLedgerService::with_runtime_root(
            store.clone(),
            runtime_root,
        ));
        let token_policy = Arc::new(UlTokenPolicyService::with_runtime_root(
            store.clone(),
            runtime_root,
        ));
        let prediction = Arc::new(PredictionService::new(store.clone(), writer));
        Self {
            cue_index,
            touched,
            planner,
            dependency,
            ledger,
            token_policy,
            prediction,
            store,
            project_root,
            runtime_root: runtime_root.to_path_buf(),
            dependency_ready: Mutex::new(HashSet::new()),
        }
    }

    pub async fn resolve_concept_ids(
        &self,
        project_id: ProjectId,
        touched_paths: &[String],
    ) -> anyhow::Result<Vec<String>> {
        let mut concepts = self
            .store
            .load_ul_artifacts::<ConceptNode>(project_id, &["concept_node"], 128)
            .await?
            .into_iter()
            .filter(|record| {
                touched_paths.iter().any(|path| {
                    record
                        .receipt_body
                        .boundary_paths
                        .iter()
                        .any(|boundary| path_matches_boundary(path, boundary))
                })
            })
            .map(|record| record.receipt_body.concept_id)
            .collect::<Vec<_>>();
        concepts.sort();
        concepts.dedup();
        Ok(concepts)
    }

    pub async fn effective_injection_mode(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        explicit_control: bool,
    ) -> anyhow::Result<(Option<UlInjectionMode>, Option<UlTaskExperimentAssignment>)> {
        let assignment = if let Some(task_id) = task_id {
            self.token_policy
                .load_assignment(project_id, task_id)
                .await?
        } else {
            None
        };
        let mode = if explicit_control {
            None
        } else if let Some(assignment) = assignment.as_ref() {
            if assignment.arm == UlExperimentArm::Control {
                None
            } else {
                self.token_policy.effective_mode(assignment).await?
            }
        } else {
            Some(UlInjectionMode::Payload)
        };
        Ok((mode, assignment))
    }

    pub fn record_packet_gate(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        task_id: Option<TaskId>,
        gate: Option<&Value>,
    ) -> anyhow::Result<()> {
        self.touched
            .set_packet_gate(project_id, session_id, gate.cloned());
        let directory = self.runtime_root.join("reports").join("ul-gates");
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{session_id}.json"));
        if let Some(gate) = gate {
            let report = json!({
                "project_id": project_id,
                "session_id": session_id,
                "task_id": task_id,
                "gate": gate,
            });
            serde_json::to_writer_pretty(std::fs::File::create(path)?, &report)?;
        } else if path.is_file() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    pub async fn ensure_dependency_state(&self, project_id: ProjectId) -> anyhow::Result<()> {
        if self
            .dependency_ready
            .lock()
            .map_err(|_| anyhow::anyhow!("UL dependency readiness lock poisoned"))?
            .contains(&project_id)
        {
            return Ok(());
        }
        self.dependency.rebuild_index(project_id).await?;
        self.dependency.scan_project(project_id).await?;
        self.dependency_ready
            .lock()
            .map_err(|_| anyhow::anyhow!("UL dependency readiness lock poisoned"))?
            .insert(project_id);
        Ok(())
    }

    pub async fn observe_successful_tool(
        &self,
        project_id: ProjectId,
        session_id: SessionId,
        tool_name: &str,
        arguments: &Value,
        observed_cues: &[eliot_types::ObservedCue],
    ) -> anyhow::Result<()> {
        self.ensure_dependency_state(project_id).await?;
        if !eliot_engine::is_mutation_tool(tool_name, arguments) {
            return Ok(());
        }
        let changed_paths = observed_cues
            .iter()
            .filter(|cue| cue.kind == eliot_types::CueKind::FilePath)
            .map(|cue| cue.value.clone())
            .collect::<Vec<_>>();
        self.dependency
            .mark_paths_dirty(
                project_id,
                &changed_paths,
                &format!("tool:{tool_name}:{session_id}"),
            )
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    pub async fn packet_enrichment(
        &self,
        project_id: ProjectId,
        task_id: &str,
        touched_paths: &[String],
        fallback_text: &str,
    ) -> anyhow::Result<PyramidPacketEnrichment> {
        let concepts = latest_by(
            self.store
                .load_ul_artifacts::<ConceptNode>(project_id, &["concept_node"], 128)
                .await?,
            |concept| concept.concept_id.clone(),
        );
        let capsules = latest_by(
            self.store
                .load_ul_artifacts::<SubsystemCapsule>(project_id, &["subsystem_capsule"], 128)
                .await?,
            |capsule| capsule.concept_id.clone(),
        );
        let concept_list = concepts.values().cloned().collect::<Vec<_>>();
        let capsule_list = capsules.values().cloned().collect::<Vec<_>>();
        let cards = latest_by(
            self.store
                .load_ul_artifacts::<ModuleCard>(project_id, &["module_card"], 512)
                .await?,
            |card| card.card_id.clone(),
        )
        .into_values()
        .collect::<Vec<_>>();
        let hotspots = latest_by(
            self.store
                .load_ul_artifacts::<HotspotScore>(project_id, &["hotspot_score"], 512)
                .await?,
            |hotspot| hotspot.hotspot_id.clone(),
        )
        .into_values()
        .collect::<Vec<_>>();
        let cue_sources = self.store.load_cue_records(project_id).await?;
        let dirty_capsules = self
            .store
            .load_ul_dirty_artifacts(project_id, 512)
            .await?
            .into_iter()
            .filter(|state| state.target_kind == eliot_types::PyramidTargetKind::SubsystemCapsule)
            .map(|state| (state.target_id.clone(), state))
            .collect::<BTreeMap<_, _>>();
        let mut meta = MetacognitionService::evaluate(
            &self.project_root,
            &concept_list,
            &capsule_list,
            &cards,
            &hotspots,
            &cue_sources,
            touched_paths,
        );
        let (mut coverage, mut blind_target) =
            MetacognitionService::coverage_for_paths(&concept_list, &meta, touched_paths);
        let recommended_probe = MetacognitionService::recommended_probe(&cards, touched_paths);
        let subsystem_concept_id =
            MetacognitionService::concept_for_paths(&concept_list, touched_paths);

        let fallback = fallback_text.to_ascii_lowercase();
        let mut ranked = concepts
            .into_values()
            .filter_map(|concept| {
                let path_score = touched_paths
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
                let fallback_match = fallback.contains(&concept.name.to_ascii_lowercase())
                    || concept
                        .boundary_paths
                        .iter()
                        .any(|boundary| fallback.contains(&boundary.to_ascii_lowercase()));
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

        let mut concept_values = Vec::new();
        let mut capsule_values = Vec::new();
        let mut danger = BTreeSet::new();
        let mut required_invariant_refs = BTreeSet::new();
        let mut stale_target = None;
        let mut units = 0_u32;
        for (_, _, concept) in &ranked {
            let concept_value = json!({
                "ref": format!("concept:{}", concept.concept_id),
                "name": concept.name,
                "purpose": concept.purpose,
                "boundary_paths": concept.boundary_paths,
            });
            units = units.saturating_add(ul_token_estimate(&concept_value.to_string()));
            concept_values.push(concept_value);
            danger.extend(concept.hotspot_refs.iter().cloned());
            danger.extend(concept.invariant_refs.iter().cloned());
            let Some(capsule) = capsules.get(&concept.concept_id) else {
                continue;
            };
            let freshness = capsule_freshness(capsule, &self.project_root);
            let dirty = dirty_capsules.get(&capsule.concept_id);
            let capsule_stale = freshness != CapsuleFreshness::Fresh || dirty.is_some();
            if capsule_stale {
                stale_target.get_or_insert_with(|| concept.concept_id.clone());
            } else {
                required_invariant_refs.extend(concept.invariant_refs.iter().cloned());
            }
            let freshness_name = if capsule_stale { "stale" } else { "fresh" };
            let rendered = render_capsule_with_dirty(capsule, &self.project_root, dirty);
            let payload_units = ul_token_estimate(&rendered);
            let mut value = json!({
                "ref": format!("capsule:{}", capsule.capsule_id),
                "freshness": freshness_name,
            });
            if units.saturating_add(payload_units) <= PACKET_PYRAMID_BUDGET {
                value["body_md"] = Value::String(rendered);
                units = units.saturating_add(payload_units);
            } else {
                value["handle_only"] = Value::Bool(true);
            }
            capsule_values.push(value);
        }
        let covered_paths = touched_paths
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
        if let Some(target) = stale_target {
            coverage = CoverageClass::Blind;
            blind_target = Some(target.clone());
            if let Some(subsystem) = meta
                .coverage
                .iter_mut()
                .find(|subsystem| subsystem.concept_id == target)
            {
                subsystem.capsule_fresh = false;
                subsystem.coverage = CoverageClass::Blind;
            }
        }
        let legacy_coverage = if coverage == CoverageClass::Blind || ranked.is_empty() {
            "blind"
        } else if touched_paths.is_empty()
            || (covered_paths == touched_paths.len() && capsule_values.len() == ranked.len())
        {
            "covered"
        } else {
            "thin"
        };
        let bridge = ranked
            .first()
            .map(|(_, _, concept)| concept_bridge(task_id, concept))
            .unwrap_or_default();
        Ok(PyramidPacketEnrichment {
            understanding: json!({
                "concepts": concept_values,
                "capsules": capsule_values,
                "danger": danger.into_iter().collect::<Vec<_>>(),
                "coverage": legacy_coverage,
            }),
            bridge,
            meta,
            coverage,
            blind_target,
            recommended_probe,
            subsystem_concept_id,
            required_invariant_refs: required_invariant_refs.into_iter().collect(),
        })
    }
}

fn latest_by<T, F>(records: Vec<CanonicalRecord<T>>, key: F) -> BTreeMap<String, T>
where
    F: Fn(&T) -> String,
{
    let mut selected = BTreeMap::<String, CanonicalRecord<T>>::new();
    for record in records {
        let identity = key(&record.receipt_body);
        let candidate_order = (
            record
                .memory_revision
                .map_or(0, eliot_types::MemoryRevision::value),
            record
                .project_sequence
                .map_or(0, eliot_types::ProjectSequence::value),
        );
        let replace = selected.get(&identity).is_none_or(|current| {
            candidate_order
                > (
                    current
                        .memory_revision
                        .map_or(0, eliot_types::MemoryRevision::value),
                    current
                        .project_sequence
                        .map_or(0, eliot_types::ProjectSequence::value),
                )
        });
        if replace {
            selected.insert(identity, record);
        }
    }
    selected
        .into_iter()
        .map(|(key, record)| (key, record.receipt_body))
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
