use super::capsule_freshness;
use crate::EngineError;
use eliot_store::CanonicalStore;
use eliot_types::{
    CapsuleFreshness, ConceptNode, InjectionReceipt, ModuleCard, ObservabilityKind,
    PredictionRecord, PredictionResolution, ProjectCharter, ProjectId, SubsystemCapsule, SystemMap,
    TaskId, UL_FIELD_VALIDATION_BASELINE_COMMIT, UL_FIELD_VALIDATION_SCHEMA_VERSION,
    UlArtifactInventory, UlFeatureReadiness, UlFieldEvidenceSummary, UlFieldValidationManifest,
    UlGraphInventory, UlPredictionInventory, UlReadinessInventory, UlReadinessSnapshot,
    UlReadinessState, UlTask08Readiness, UlTaskLedger,
};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const ARTIFACT_PAGE_SIZE: u16 = 100;

pub struct UlFieldValidationLoad {
    pub manifest: Option<UlFieldValidationManifest>,
    pub present: bool,
    pub warnings: Vec<String>,
}

pub struct UlReadinessService {
    store: CanonicalStore,
}

impl UlReadinessService {
    #[must_use]
    pub fn new(store: CanonicalStore) -> Self {
        Self { store }
    }

    pub async fn collect(
        &self,
        runtime_root: &Path,
        project_id: ProjectId,
    ) -> Result<UlReadinessSnapshot, EngineError> {
        let graph = self.store.load_ul_readiness_inventory(project_id).await?;
        let artifacts = self.artifact_inventory(project_id).await?;
        let predictions = self
            .store
            .load_predictions(project_id, None, None, false, None)
            .await?;
        let ledgers = self.store.load_ul_metrics(project_id).await?;
        let receipts = self
            .store
            .observability_records_by_kind::<InjectionReceipt>(
                project_id,
                None,
                ObservabilityKind::InjectionReceipt,
            )
            .await?;
        let manifest_load = load_field_validation_manifest(runtime_root, project_id);
        let mut warnings = manifest_load.warnings;
        let inventory = readiness_inventory(artifacts, graph, &predictions, &ledgers, &receipts);
        let field_evidence = summarize_field_evidence(
            manifest_load.present,
            manifest_load.manifest.as_ref(),
            &ledgers,
            &receipts,
            &mut warnings,
        );
        let task08_readiness =
            evaluate_task08_readiness(&inventory, manifest_load.manifest.as_ref());
        Ok(UlReadinessSnapshot {
            inventory,
            task08_readiness,
            field_evidence,
            warnings,
        })
    }

    async fn artifact_inventory(
        &self,
        project_id: ProjectId,
    ) -> Result<UlArtifactInventory, EngineError> {
        let concepts = load_latest_artifacts::<ConceptNode, _>(
            &self.store,
            project_id,
            &["concept_node"],
            |concept| concept.concept_id.clone(),
        )
        .await?;
        let capsules = load_latest_artifacts::<SubsystemCapsule, _>(
            &self.store,
            project_id,
            &["subsystem_capsule"],
            |capsule| capsule.concept_id.clone(),
        )
        .await?;
        let cards = load_latest_artifacts::<ModuleCard, _>(
            &self.store,
            project_id,
            &["module_card"],
            |card| card.path.clone(),
        )
        .await?;
        let charters = load_latest_artifacts::<ProjectCharter, _>(
            &self.store,
            project_id,
            &["project_charter"],
            |charter| charter.project_id.to_string(),
        )
        .await?;
        let maps = load_latest_artifacts::<SystemMap, _>(
            &self.store,
            project_id,
            &["system_map"],
            |map| map.project_id.to_string(),
        )
        .await?;
        let fresh_capsule_count = len_u32(
            capsules
                .values()
                .filter(|capsule| readiness_capsule_is_fresh(capsule))
                .count(),
        );
        let capsule_count = len_u32(capsules.len());
        Ok(UlArtifactInventory {
            concept_count: len_u32(concepts.len()),
            capsule_count,
            fresh_capsule_count,
            stale_capsule_count: capsule_count.saturating_sub(fresh_capsule_count),
            module_card_count: len_u32(cards.len()),
            charter_count: len_u32(charters.len()),
            system_map_count: len_u32(maps.len()),
        })
    }
}

#[must_use]
pub fn evaluate_task08_readiness(
    inventory: &UlReadinessInventory,
    manifest: Option<&UlFieldValidationManifest>,
) -> UlTask08Readiness {
    let mut activation = Vec::new();
    if inventory.graph.total_ul_edges < 500 {
        activation.push("requires_at_least_500_live_edges");
    }
    if inventory.artifacts.module_card_count < 10 {
        activation.push("requires_at_least_10_module_cards");
    }
    if inventory.artifacts.capsule_count < 3 {
        activation.push("requires_at_least_3_capsules");
    }
    if inventory.tasks_with_injection < 20 {
        activation.push("requires_at_least_20_injected_tasks");
    }

    let mut reverse_dependency = Vec::new();
    if inventory.artifacts.capsule_count < 10 {
        reverse_dependency.push("requires_at_least_10_capsules");
    }
    if inventory
        .artifacts
        .fresh_capsule_count
        .saturating_add(inventory.artifacts.stale_capsule_count)
        != inventory.artifacts.capsule_count
    {
        reverse_dependency.push("requires_complete_capsule_freshness_inventory");
    }
    if inventory.tasks_with_injection < 10 {
        reverse_dependency.push("requires_at_least_10_injected_tasks");
    }

    let mut token_ab = Vec::new();
    if inventory.ledger_tasks < 20 {
        token_ab.push("requires_at_least_20_ledger_tasks");
    }
    if inventory.tasks_with_injection < 20 {
        token_ab.push("requires_at_least_20_injected_tasks");
    }
    if inventory.injection_receipts < 20 {
        token_ab.push("requires_at_least_20_injection_receipts");
    }
    if inventory
        .read_tool_input_bytes
        .saturating_add(inventory.read_tool_output_bytes)
        == 0
    {
        token_ab.push("requires_nonzero_read_tool_bytes");
    }

    let resolved_predictions = inventory
        .predictions
        .hit
        .saturating_add(inventory.predictions.miss);
    let mut weekly_exam = Vec::new();
    if inventory.artifacts.capsule_count < 5 {
        weekly_exam.push("requires_at_least_5_capsules");
    }
    if inventory.artifacts.fresh_capsule_count < 4 {
        weekly_exam.push("requires_at_least_4_fresh_capsules");
    }
    if resolved_predictions < 20 {
        weekly_exam.push("requires_at_least_20_resolved_predictions");
    }
    if inventory.predictions.resolved_subsystem_count < 2 {
        weekly_exam.push("requires_at_least_2_resolved_subsystems");
    }

    let prose_signal = manifest.is_some_and(|manifest| {
        manifest.prose_failure_signals.iter().any(|signal| {
            !signal.capsule_ref.trim().is_empty()
                && !signal.kind.trim().is_empty()
                && !signal.evidence_ref.trim().is_empty()
        })
    });
    let host_signal = manifest.is_some_and(|manifest| {
        manifest.host_surface_incidents.iter().any(|incident| {
            !incident.kind.trim().is_empty()
                && !incident.session_ref.trim().is_empty()
                && !incident.evidence_ref.trim().is_empty()
        })
    });

    UlTask08Readiness {
        spreading_activation: readiness(activation),
        reverse_dependency_index: readiness(reverse_dependency),
        token_ab_and_downgrade: readiness(token_ab),
        weekly_understanding_exam: readiness(weekly_exam),
        model_prose_refinement: if prose_signal {
            readiness(Vec::new())
        } else {
            readiness(vec!["requires_documented_prose_failure_signal"])
        },
        host_surface_optimization: if host_signal {
            readiness(Vec::new())
        } else {
            readiness(vec!["requires_measured_host_surface_cost"])
        },
    }
}

#[must_use]
pub fn load_field_validation_manifest(
    runtime_root: &Path,
    project_id: ProjectId,
) -> UlFieldValidationLoad {
    let path = field_validation_manifest_path(runtime_root, project_id);
    if !path.is_file() {
        return UlFieldValidationLoad {
            manifest: None,
            present: false,
            warnings: Vec::new(),
        };
    }
    let Ok(bytes) = fs::read(&path) else {
        return invalid_manifest_load("field_validation_manifest_read_error");
    };
    let Ok(manifest) = serde_json::from_slice::<UlFieldValidationManifest>(&bytes) else {
        return invalid_manifest_load("field_validation_manifest_decode_error");
    };
    let mut warnings = Vec::new();
    if manifest.schema_version != UL_FIELD_VALIDATION_SCHEMA_VERSION {
        warnings.push("field_validation_manifest_schema_version_mismatch".to_owned());
    }
    if manifest.project_id != project_id {
        warnings.push("field_validation_manifest_project_mismatch".to_owned());
    }
    if manifest.baseline_merge_commit != UL_FIELD_VALIDATION_BASELINE_COMMIT {
        warnings.push("field_validation_manifest_baseline_mismatch".to_owned());
    }
    let mut task_ids = HashSet::new();
    if manifest
        .task_annotations
        .iter()
        .any(|annotation| !task_ids.insert(annotation.task_id))
    {
        warnings.push("field_validation_manifest_duplicate_task_id".to_owned());
    }
    if warnings.is_empty() {
        UlFieldValidationLoad {
            manifest: Some(manifest),
            present: true,
            warnings,
        }
    } else {
        UlFieldValidationLoad {
            manifest: None,
            present: true,
            warnings,
        }
    }
}

#[must_use]
pub fn field_validation_manifest_path(runtime_root: &Path, project_id: ProjectId) -> PathBuf {
    runtime_root
        .join("reports")
        .join("ul")
        .join("field-validation")
        .join(project_id.to_string())
        .join("manifest.json")
}

fn readiness(reasons: Vec<&str>) -> UlFeatureReadiness {
    UlFeatureReadiness {
        state: if reasons.is_empty() {
            UlReadinessState::Eligible
        } else {
            UlReadinessState::NotEligible
        },
        reasons: reasons.into_iter().map(str::to_owned).collect(),
    }
}

fn readiness_inventory(
    artifacts: UlArtifactInventory,
    graph: UlGraphInventory,
    predictions: &[PredictionRecord],
    ledgers: &[UlTaskLedger],
    receipts: &[InjectionReceipt],
) -> UlReadinessInventory {
    let prediction_inventory = prediction_inventory(predictions);
    let ledger_task_ids = ledgers
        .iter()
        .map(|ledger| ledger.task_id)
        .collect::<HashSet<_>>();
    let injected_task_ids = receipts
        .iter()
        .filter_map(|receipt| receipt.task_id)
        .collect::<HashSet<_>>();
    let acknowledged_items = ledgers.iter().fold(0_u32, |total, ledger| {
        total.saturating_add(ledger.acknowledged_items)
    });
    let expanded_injected_handles = ledgers.iter().fold(0_u32, |total, ledger| {
        total.saturating_add(ledger.expanded_injected_handles)
    });
    let read_tool_input_bytes = ledgers.iter().fold(0_u64, |total, ledger| {
        total.saturating_add(ledger.read_tool_input_bytes)
    });
    let read_tool_output_bytes = ledgers.iter().fold(0_u64, |total, ledger| {
        total.saturating_add(ledger.read_tool_output_bytes)
    });
    let injection_receipts = len_u32(receipts.len());
    let denominator = f64::from(injection_receipts);
    UlReadinessInventory {
        artifacts,
        graph,
        predictions: prediction_inventory,
        ledger_tasks: len_u32(ledger_task_ids.len()),
        tasks_with_injection: len_u32(injected_task_ids.len()),
        injection_receipts,
        acknowledged_items,
        expanded_injected_handles,
        read_tool_input_bytes,
        read_tool_output_bytes,
        acknowledged_fraction: if injection_receipts == 0 {
            0.0
        } else {
            f64::from(acknowledged_items) / denominator
        },
        expanded_after_injection_fraction: if injection_receipts == 0 {
            0.0
        } else {
            f64::from(expanded_injected_handles) / denominator
        },
    }
}

fn prediction_inventory(predictions: &[PredictionRecord]) -> UlPredictionInventory {
    let mut inventory = UlPredictionInventory {
        total: len_u32(predictions.len()),
        ..UlPredictionInventory::default()
    };
    let mut resolved_subsystems = HashSet::new();
    for prediction in predictions {
        match prediction.resolution {
            None => inventory.unresolved = inventory.unresolved.saturating_add(1),
            Some(PredictionResolution::Hit) => {
                inventory.hit = inventory.hit.saturating_add(1);
                if let Some(subsystem) = &prediction.subsystem_concept_id {
                    resolved_subsystems.insert(subsystem.clone());
                }
            }
            Some(PredictionResolution::Miss) => {
                inventory.miss = inventory.miss.saturating_add(1);
                if let Some(subsystem) = &prediction.subsystem_concept_id {
                    resolved_subsystems.insert(subsystem.clone());
                }
            }
            Some(PredictionResolution::Unresolvable) => {
                inventory.unresolvable = inventory.unresolvable.saturating_add(1);
            }
        }
    }
    inventory.resolved_subsystem_count = len_u32(resolved_subsystems.len());
    inventory
}

#[must_use]
pub fn summarize_field_evidence(
    manifest_present: bool,
    manifest: Option<&UlFieldValidationManifest>,
    ledgers: &[UlTaskLedger],
    receipts: &[InjectionReceipt],
    warnings: &mut Vec<String>,
) -> UlFieldEvidenceSummary {
    let Some(manifest) = manifest else {
        return UlFieldEvidenceSummary {
            manifest_present,
            second_repository_status: "SECOND_REPO_PENDING".to_owned(),
            ..UlFieldEvidenceSummary::default()
        };
    };
    let ledger_ids = ledgers
        .iter()
        .map(|ledger| ledger.task_id)
        .collect::<HashSet<TaskId>>();
    let injected_ids = receipts
        .iter()
        .filter_map(|receipt| receipt.task_id)
        .collect::<HashSet<TaskId>>();
    let mut matched_real_tasks = 0_u32;
    let mut matched_real_injected_tasks = 0_u32;
    for annotation in &manifest.task_annotations {
        if !annotation.real_task {
            warnings.push(format!(
                "field_validation_manifest_non_real_task_ignored:{}",
                annotation.task_id
            ));
            continue;
        }
        if !ledger_ids.contains(&annotation.task_id) {
            warnings.push(format!(
                "field_validation_manifest_unmatched_task_annotation:{}",
                annotation.task_id
            ));
            continue;
        }
        matched_real_tasks = matched_real_tasks.saturating_add(1);
        if injected_ids.contains(&annotation.task_id) {
            matched_real_injected_tasks = matched_real_injected_tasks.saturating_add(1);
        } else {
            warnings.push(format!(
                "field_validation_manifest_missing_injection_receipt:{}",
                annotation.task_id
            ));
        }
    }
    let second_repository_complete = manifest
        .second_repository
        .as_ref()
        .is_some_and(second_repository_is_complete);
    if manifest.second_repository.is_some() && !second_repository_complete {
        warnings.push("field_validation_second_repository_incomplete".to_owned());
    }
    let second_repository_status = if second_repository_complete {
        "COMPLETE"
    } else if manifest.second_repository.is_some() {
        "INCOMPLETE"
    } else {
        "SECOND_REPO_PENDING"
    };
    UlFieldEvidenceSummary {
        manifest_present: true,
        manifest_valid: true,
        matched_real_tasks,
        matched_real_injected_tasks,
        second_repository_complete,
        second_repository_status: second_repository_status.to_owned(),
    }
}

fn second_repository_is_complete(validation: &eliot_types::UlSecondRepositoryValidation) -> bool {
    validation.concept_count >= 3
        && validation.capsule_count == validation.concept_count
        && validation.module_card_count >= 1
        && validation.rejected_builds == 0
        && validation.zero_model_calls
        && !validation.project_root.trim().is_empty()
        && !validation.head_commit.trim().is_empty()
}

fn invalid_manifest_load(warning: &str) -> UlFieldValidationLoad {
    UlFieldValidationLoad {
        manifest: None,
        present: true,
        warnings: vec![warning.to_owned()],
    }
}

fn readiness_capsule_is_fresh(capsule: &SubsystemCapsule) -> bool {
    let root = capsule.dependency_manifest.project_root.trim();
    !root.is_empty()
        && Path::new(root).is_dir()
        && capsule_freshness(capsule, Path::new(root)) == CapsuleFreshness::Fresh
}

async fn load_latest_artifacts<T, F>(
    store: &CanonicalStore,
    project_id: ProjectId,
    receipt_kinds: &[&str],
    key: F,
) -> Result<BTreeMap<String, T>, EngineError>
where
    T: DeserializeOwned,
    F: Fn(&T) -> String,
{
    let mut start = 0_u64;
    let mut selected = BTreeMap::<String, (u64, u64, T)>::new();
    loop {
        let page = store
            .canonical_record_page(project_id, None, receipt_kinds, start, ARTIFACT_PAGE_SIZE)
            .await?;
        let page_len = page.len();
        for record in page {
            let body = serde_json::from_value::<T>(record.receipt_body)?;
            let identity = key(&body);
            let order = (
                record
                    .memory_revision
                    .map_or(0, eliot_types::MemoryRevision::value),
                record
                    .project_sequence
                    .map_or(0, eliot_types::ProjectSequence::value),
            );
            let replace = selected
                .get(&identity)
                .is_none_or(|current| order > (current.0, current.1));
            if replace {
                selected.insert(identity, (order.0, order.1, body));
            }
        }
        if page_len < usize::from(ARTIFACT_PAGE_SIZE) {
            break;
        }
        start = start.saturating_add(u64::try_from(page_len).unwrap_or(u64::MAX));
    }
    Ok(selected
        .into_iter()
        .map(|(identity, (_, _, body))| (identity, body))
        .collect())
}

fn len_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}
