use super::{
    CapsuleEvidence, CueIndexService, ModuleCardService, OnboardingService, PyramidBuilder,
    PyramidFailure, UlArtifactWriterService, UlDependencyService, failure_bindings_by_path,
};
use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_store::{CanonicalRecord, CanonicalStore};
use eliot_types::{
    CoChangeEdge, ConceptNode, CueKind, HotspotScore, MiningRun, ModuleCard, ProjectId,
    PyramidTargetKind, UlArtifact, UlArtifactDirtyState, UlMaintenanceReport,
};
use std::collections::BTreeMap;
use std::path::Path;

pub struct UlMaintenanceService {
    store: CanonicalStore,
    writer: WriterHandle,
    dependency: UlDependencyService,
    _onboarding: OnboardingService,
    cue_index: CueIndexService,
}

impl UlMaintenanceService {
    #[must_use]
    pub fn new(store: CanonicalStore, writer: WriterHandle) -> Self {
        Self {
            dependency: UlDependencyService::new(store.clone()),
            _onboarding: OnboardingService::new(store.clone(), writer.clone()),
            cue_index: CueIndexService::new(store.clone()),
            store,
            writer,
        }
    }

    pub async fn rebuild_dirty(
        &self,
        project_id: ProjectId,
        project_root: &Path,
        limit: u16,
    ) -> Result<UlMaintenanceReport, EngineError> {
        if !project_root.is_dir() {
            return Err(EngineError::WriteRejected(format!(
                "UL maintenance project root does not exist: {}",
                project_root.display()
            )));
        }
        let limit = limit.clamp(1, 5);
        let dirty = self
            .store
            .load_ul_dirty_artifacts(project_id, limit)
            .await?;
        let mut rebuilt = Vec::new();
        let mut failed = Vec::new();
        for state in dirty {
            let label = format!("{:?}:{}", state.target_kind, state.target_id);
            match self.rebuild_one(project_root, &state).await {
                Ok(()) => rebuilt.push(label),
                Err(error) => failed.push(format!("{label}: {error}")),
            }
        }
        let remaining_dirty = u32::try_from(
            self.store
                .load_ul_dirty_artifacts(project_id, 512)
                .await?
                .len(),
        )
        .unwrap_or(u32::MAX);
        Ok(UlMaintenanceReport {
            project_id,
            requested: limit,
            rebuilt,
            failed,
            remaining_dirty,
        })
    }

    async fn rebuild_one(
        &self,
        project_root: &Path,
        state: &UlArtifactDirtyState,
    ) -> Result<(), EngineError> {
        let run = latest_single(
            self.store
                .load_ul_artifacts::<MiningRun>(state.project_id, &["mining_run"], 128)
                .await?,
        );
        let run_id = run.as_ref().map_or_else(
            || format!("ul-maintenance-{}", state.project_id),
            |run| run.run_id.clone(),
        );
        match state.target_kind {
            PyramidTargetKind::ModuleCard => {
                self.rebuild_card(project_root, state, &run_id, run.as_ref())
                    .await
            }
            PyramidTargetKind::SubsystemCapsule => {
                self.rebuild_capsule(project_root, state, &run_id).await
            }
            PyramidTargetKind::SystemMap => self.rebuild_map(project_root, state, &run_id).await,
            PyramidTargetKind::ProjectCharter => {
                self.rebuild_charter(project_root, state, &run_id).await
            }
        }
    }

    async fn rebuild_card(
        &self,
        project_root: &Path,
        state: &UlArtifactDirtyState,
        run_id: &str,
        run: Option<&MiningRun>,
    ) -> Result<(), EngineError> {
        let edges = latest_by(
            self.store
                .load_ul_artifacts::<CoChangeEdge>(state.project_id, &["co_change_edge"], 128)
                .await?,
            |edge| edge.edge_id.clone(),
        )
        .into_values()
        .filter(|edge| run.is_none_or(|run| edge.mining_run_ref == run.run_id))
        .collect::<Vec<_>>();
        let hotspots = latest_by(
            self.store
                .load_ul_artifacts::<HotspotScore>(state.project_id, &["hotspot_score"], 128)
                .await?,
            |hotspot| hotspot.hotspot_id.clone(),
        )
        .into_values()
        .filter(|hotspot| run.is_none_or(|run| hotspot.mining_run_ref == run.run_id))
        .collect::<Vec<_>>();
        let sources = self.store.load_cue_records(state.project_id).await?;
        let cards = ModuleCardService::build(
            state.project_id,
            project_root,
            &hotspots,
            &edges,
            &failure_bindings_by_path(&sources),
            &BTreeMap::new(),
        )?;
        let card = cards
            .into_iter()
            .find(|card| card.path == state.target_id)
            .ok_or_else(|| {
                EngineError::WriteRejected(format!(
                    "no current hotspot can rebuild module card {}",
                    state.target_id
                ))
            })?;
        UlArtifactWriterService
            .write_module_cards(
                &self.writer,
                &WriteAdmissionService,
                run_id,
                std::slice::from_ref(&card),
            )
            .await?;
        self.dependency.index_card(&card).await?;
        self.cue_index
            .replace_record_bindings(
                state.project_id,
                &format!("card:{}", card.card_id),
                "module_card",
                &card.body_md,
                &card.cue_bindings,
                false,
            )
            .await?;
        self.store
            .clear_ul_artifact_dirty(
                state.project_id,
                state.target_kind,
                &state.target_id,
                &card.build_fingerprint,
            )
            .await?;
        Ok(())
    }

    async fn rebuild_capsule(
        &self,
        project_root: &Path,
        state: &UlArtifactDirtyState,
        run_id: &str,
    ) -> Result<(), EngineError> {
        let concepts = self.latest_concepts(state.project_id).await?;
        let concept = concepts.get(&state.target_id).ok_or_else(|| {
            EngineError::WriteRejected(format!(
                "capsule concept {} is not current",
                state.target_id
            ))
        })?;
        let cards = self.latest_cards(state.project_id).await?;
        let hotspots = latest_by(
            self.store
                .load_ul_artifacts::<HotspotScore>(state.project_id, &["hotspot_score"], 128)
                .await?,
            |hotspot| hotspot.hotspot_id.clone(),
        )
        .into_values()
        .filter(|hotspot| path_in_concept(&hotspot.path, concept))
        .collect::<Vec<_>>();
        let sources = self.store.load_cue_records(state.project_id).await?;
        let mut evidence = CapsuleEvidence {
            module_cards: cards
                .into_values()
                .filter(|card| path_in_concept(&card.path, concept))
                .collect(),
            hotspots,
            ..CapsuleEvidence::default()
        };
        for source in sources {
            let in_concept = source.cue_bindings.iter().any(|binding| {
                binding.cue_kind == CueKind::FilePath
                    && path_in_concept(&binding.cue_value, concept)
            });
            if !in_concept {
                continue;
            }
            if source.negative_memory {
                evidence.failures.push(PyramidFailure {
                    reference: source.record_ref.clone(),
                    summary: source.preview_text.clone(),
                });
            }
            if source.record_kind == "invariant" {
                evidence.invariant_refs.push(source.record_ref);
            }
        }
        let promoted = PyramidBuilder.build_capsule(
            project_root,
            concept,
            &evidence,
            Some(state.build_id.clone()),
        )?;
        UlArtifactWriterService
            .write_pyramid_target(
                &self.writer,
                &WriteAdmissionService,
                run_id,
                UlArtifact::SubsystemCapsule(promoted.artifact.clone()),
                promoted.build,
            )
            .await?;
        self.dependency.index_capsule(&promoted.artifact).await?;
        self.cue_index
            .replace_record_bindings(
                state.project_id,
                &format!("capsule:{}", promoted.artifact.capsule_id),
                "subsystem_capsule",
                &promoted.artifact.body_md,
                &promoted.artifact.cue_bindings,
                false,
            )
            .await?;
        self.store
            .clear_ul_artifact_dirty(
                state.project_id,
                state.target_kind,
                &state.target_id,
                &promoted.artifact.build_id,
            )
            .await?;
        Ok(())
    }

    async fn rebuild_map(
        &self,
        project_root: &Path,
        state: &UlArtifactDirtyState,
        run_id: &str,
    ) -> Result<(), EngineError> {
        let concepts = self
            .latest_concepts(state.project_id)
            .await?
            .into_values()
            .collect::<Vec<_>>();
        let edges = latest_by(
            self.store
                .load_ul_artifacts::<CoChangeEdge>(state.project_id, &["co_change_edge"], 128)
                .await?,
            |edge| edge.edge_id.clone(),
        )
        .into_values()
        .collect::<Vec<_>>();
        let promoted = PyramidBuilder.build_system_map(
            state.project_id,
            project_root,
            &concepts,
            &edges,
            Some(state.build_id.clone()),
        )?;
        UlArtifactWriterService
            .write_pyramid_target(
                &self.writer,
                &WriteAdmissionService,
                run_id,
                UlArtifact::SystemMap(promoted.artifact.clone()),
                promoted.build,
            )
            .await?;
        self.dependency.index_map(&promoted.artifact).await?;
        self.store
            .clear_ul_artifact_dirty(
                state.project_id,
                state.target_kind,
                &state.target_id,
                &promoted.artifact.build_id,
            )
            .await?;
        Ok(())
    }

    async fn rebuild_charter(
        &self,
        project_root: &Path,
        state: &UlArtifactDirtyState,
        run_id: &str,
    ) -> Result<(), EngineError> {
        let concepts = self
            .latest_concepts(state.project_id)
            .await?
            .into_values()
            .collect::<Vec<_>>();
        let invariant_refs = concepts
            .iter()
            .flat_map(|concept| concept.invariant_refs.iter().cloned())
            .collect::<Vec<_>>();
        let promoted = PyramidBuilder.build_charter(
            state.project_id,
            project_root,
            &concepts,
            &invariant_refs,
            Some(state.build_id.clone()),
        )?;
        UlArtifactWriterService
            .write_pyramid_target(
                &self.writer,
                &WriteAdmissionService,
                run_id,
                UlArtifact::ProjectCharter(promoted.artifact.clone()),
                promoted.build,
            )
            .await?;
        self.dependency.index_charter(&promoted.artifact).await?;
        self.store
            .clear_ul_artifact_dirty(
                state.project_id,
                state.target_kind,
                &state.target_id,
                &promoted.artifact.build_id,
            )
            .await?;
        Ok(())
    }

    async fn latest_concepts(
        &self,
        project_id: ProjectId,
    ) -> Result<BTreeMap<String, ConceptNode>, EngineError> {
        Ok(latest_by(
            self.store
                .load_ul_artifacts::<ConceptNode>(project_id, &["concept_node"], 128)
                .await?,
            |concept| concept.concept_id.clone(),
        ))
    }

    async fn latest_cards(
        &self,
        project_id: ProjectId,
    ) -> Result<BTreeMap<String, ModuleCard>, EngineError> {
        Ok(latest_by(
            self.store
                .load_ul_artifacts::<ModuleCard>(project_id, &["module_card"], 128)
                .await?,
            |card| card.path.clone(),
        ))
    }
}

fn path_in_concept(path: &str, concept: &ConceptNode) -> bool {
    concept
        .boundary_paths
        .iter()
        .any(|boundary| eliot_types::path_matches_boundary(path, boundary))
}

fn latest_by<T, F>(records: Vec<CanonicalRecord<T>>, key: F) -> BTreeMap<String, T>
where
    F: Fn(&T) -> String,
{
    let mut selected = BTreeMap::<String, CanonicalRecord<T>>::new();
    for record in records {
        let identity = key(&record.receipt_body);
        let order = (
            record
                .memory_revision
                .map_or(0, eliot_types::MemoryRevision::value),
            record
                .project_sequence
                .map_or(0, eliot_types::ProjectSequence::value),
        );
        if selected.get(&identity).is_none_or(|current| {
            order
                > (
                    current
                        .memory_revision
                        .map_or(0, eliot_types::MemoryRevision::value),
                    current
                        .project_sequence
                        .map_or(0, eliot_types::ProjectSequence::value),
                )
        }) {
            selected.insert(identity, record);
        }
    }
    selected
        .into_iter()
        .map(|(key, record)| (key, record.receipt_body))
        .collect()
}

fn latest_single<T>(records: Vec<CanonicalRecord<T>>) -> Option<T> {
    records
        .into_iter()
        .max_by_key(|record| {
            (
                record
                    .memory_revision
                    .map_or(0, eliot_types::MemoryRevision::value),
                record
                    .project_sequence
                    .map_or(0, eliot_types::ProjectSequence::value),
            )
        })
        .map(|record| record.receipt_body)
}
