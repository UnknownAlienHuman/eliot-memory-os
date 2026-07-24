use eliot_engine::{
    CueIndexService, InjectionPlanner, MetacognitionService, PredictionService, TouchedSetRegistry,
    UlLedgerService, WriterHandle, capsule_freshness, render_capsule,
};
use eliot_store::{CanonicalRecord, CanonicalStore};
use eliot_types::{
    CapsuleFreshness, CausalBridgeHop, ConceptNode, CoverageClass, HotspotScore, ModuleCard,
    ProjectId, SubsystemCapsule, UlMetacognitionView, ul_token_estimate,
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

const PACKET_PYRAMID_BUDGET: u32 = 1_500;

pub(super) struct PyramidPacketEnrichment {
    pub understanding: Value,
    pub bridge: Vec<CausalBridgeHop>,
    pub meta: UlMetacognitionView,
    pub coverage: CoverageClass,
    pub blind_target: Option<String>,
    pub recommended_probe: Option<String>,
    pub subsystem_concept_id: Option<String>,
}

pub(super) struct UlRuntime {
    pub cue_index: Arc<CueIndexService>,
    pub touched: Arc<TouchedSetRegistry>,
    pub planner: Arc<InjectionPlanner>,
    pub ledger: Arc<UlLedgerService>,
    pub prediction: Arc<PredictionService>,
    store: CanonicalStore,
    project_root: PathBuf,
}

impl UlRuntime {
    pub fn new(store: CanonicalStore, writer: WriterHandle, runtime_root: &Path) -> Self {
        let cue_index = Arc::new(CueIndexService::new(store.clone()));
        let touched = Arc::new(TouchedSetRegistry::new());
        let project_root = eliot_engine::canonical_project_root(runtime_root);
        let planner = Arc::new(InjectionPlanner::with_project_root(
            Arc::clone(&cue_index),
            store.clone(),
            writer.clone(),
            Arc::clone(&touched),
            project_root.clone(),
        ));
        let ledger = Arc::new(UlLedgerService::new(store.clone()));
        let prediction = Arc::new(PredictionService::new(store.clone(), writer));
        Self {
            cue_index,
            touched,
            planner,
            ledger,
            prediction,
            store,
            project_root,
        }
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
        let meta = MetacognitionService::evaluate(
            &self.project_root,
            &concept_list,
            &capsule_list,
            &cards,
            &hotspots,
            &cue_sources,
            touched_paths,
        );
        let (coverage, blind_target) =
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
            let freshness_name = match freshness {
                CapsuleFreshness::Fresh => "fresh",
                CapsuleFreshness::Stale { .. } => "stale",
            };
            let rendered = render_capsule(capsule, &self.project_root);
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
        let legacy_coverage = if ranked.is_empty() {
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

fn path_matches_boundary(path: &str, boundary: &str) -> bool {
    if boundary == "." {
        return true;
    }
    path == boundary
        || path
            .strip_prefix(boundary.trim_end_matches('/'))
            .is_some_and(|suffix| suffix.starts_with('/'))
}
