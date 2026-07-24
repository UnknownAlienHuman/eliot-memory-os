use crate::EngineError;
use eliot_store::{CanonicalRecord, CanonicalStore};
use eliot_types::{
    DependencyManifest, ModuleCard, ProjectCharter, ProjectId, PyramidTargetKind, SubsystemCapsule,
    SystemMap, UlArtifactDirtyState, UlDependencyKind, UlDependencyRebuildReport, UlDependencyRef,
    UlDirtyReason,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

#[derive(Clone)]
pub struct UlDependencyService {
    store: CanonicalStore,
}

impl UlDependencyService {
    #[must_use]
    pub const fn new(store: CanonicalStore) -> Self {
        Self { store }
    }

    pub async fn index_capsule(&self, capsule: &SubsystemCapsule) -> Result<(), EngineError> {
        self.index_manifest(
            capsule.project_id,
            PyramidTargetKind::SubsystemCapsule,
            &capsule.concept_id,
            &capsule.build_id,
            &capsule.dependency_manifest,
        )
        .await
    }

    pub async fn index_card(&self, card: &ModuleCard) -> Result<(), EngineError> {
        self.index_manifest(
            card.project_id,
            PyramidTargetKind::ModuleCard,
            &card.path,
            &card.build_fingerprint,
            &card.dependency_manifest,
        )
        .await
    }

    pub async fn index_map(&self, map: &SystemMap) -> Result<(), EngineError> {
        self.index_manifest(
            map.project_id,
            PyramidTargetKind::SystemMap,
            &map.project_id.to_string(),
            &map.build_id,
            &map.dependency_manifest,
        )
        .await
    }

    pub async fn index_charter(&self, charter: &ProjectCharter) -> Result<(), EngineError> {
        self.index_manifest(
            charter.project_id,
            PyramidTargetKind::ProjectCharter,
            &charter.project_id.to_string(),
            &charter.build_id,
            &charter.dependency_manifest,
        )
        .await
    }

    async fn index_manifest(
        &self,
        project_id: ProjectId,
        target_kind: PyramidTargetKind,
        target_id: &str,
        build_id: &str,
        manifest: &DependencyManifest,
    ) -> Result<(), EngineError> {
        let dependencies = dependency_refs(manifest);
        self.store
            .replace_ul_reverse_dependencies(
                project_id,
                target_kind,
                target_id,
                build_id,
                &dependencies,
            )
            .await?;
        Ok(())
    }

    pub async fn mark_paths_dirty(
        &self,
        project_id: ProjectId,
        paths: &[String],
        event_ref: &str,
    ) -> Result<Vec<UlArtifactDirtyState>, EngineError> {
        let dependencies = paths
            .iter()
            .map(|path| UlDependencyRef {
                kind: UlDependencyKind::File,
                key: eliot_types::normalize_path(path, None),
            })
            .filter(|dependency| !dependency.key.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        if dependencies.is_empty() {
            return Ok(Vec::new());
        }
        let rows = self
            .store
            .load_ul_reverse_dependents(project_id, &dependencies)
            .await?;
        let existing = self
            .store
            .load_ul_dirty_artifacts(project_id, 512)
            .await?
            .into_iter()
            .map(|state| ((state.target_kind, state.target_id.clone()), state))
            .collect::<BTreeMap<_, _>>();
        let now = OffsetDateTime::now_utc();
        let mut grouped =
            BTreeMap::<(PyramidTargetKind, String, String), BTreeSet<UlDirtyReason>>::new();
        for row in rows {
            grouped
                .entry((row.target_kind, row.target_id, row.build_id))
                .or_default()
                .insert(UlDirtyReason {
                    dependency: row.dependency,
                    expected_fingerprint: None,
                    observed_fingerprint: None,
                    event_ref: event_ref.to_owned(),
                });
        }
        let mut states = Vec::with_capacity(grouped.len());
        for ((target_kind, target_id, build_id), reasons) in grouped {
            let prior = existing.get(&(target_kind, target_id.clone()));
            let mut merged = prior.map(|state| state.reasons.clone()).unwrap_or_default();
            merged.extend(reasons);
            merged.sort();
            merged.dedup();
            let state = UlArtifactDirtyState {
                project_id,
                target_kind,
                target_id,
                build_id,
                dirty: true,
                reasons: merged,
                first_dirty_at: prior.map_or(now, |state| state.first_dirty_at),
                updated_at: now,
            };
            self.store.mark_ul_artifact_dirty(&state).await?;
            states.push(state);
        }
        states.sort_by(|left, right| {
            left.target_kind
                .cmp(&right.target_kind)
                .then_with(|| left.target_id.cmp(&right.target_id))
        });
        Ok(states)
    }

    pub async fn scan_project(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<UlArtifactDirtyState>, EngineError> {
        let existing = self
            .store
            .load_ul_dirty_artifacts(project_id, 512)
            .await?
            .into_iter()
            .map(|state| ((state.target_kind, state.target_id.clone()), state))
            .collect::<BTreeMap<_, _>>();
        let mut candidates = Vec::new();
        for card in latest_by(
            self.store
                .load_ul_artifacts::<ModuleCard>(project_id, &["module_card"], 128)
                .await?,
            |card| card.path.clone(),
        )
        .into_values()
        {
            candidates.push(ManifestTarget {
                kind: PyramidTargetKind::ModuleCard,
                id: card.path,
                build_id: card.build_fingerprint,
                manifest: card.dependency_manifest,
            });
        }
        for capsule in latest_by(
            self.store
                .load_ul_artifacts::<SubsystemCapsule>(project_id, &["subsystem_capsule"], 128)
                .await?,
            |capsule| capsule.concept_id.clone(),
        )
        .into_values()
        {
            candidates.push(ManifestTarget {
                kind: PyramidTargetKind::SubsystemCapsule,
                id: capsule.concept_id,
                build_id: capsule.build_id,
                manifest: capsule.dependency_manifest,
            });
        }
        if let Some(map) = latest_single(
            self.store
                .load_ul_artifacts::<SystemMap>(project_id, &["system_map"], 128)
                .await?,
        ) {
            candidates.push(ManifestTarget {
                kind: PyramidTargetKind::SystemMap,
                id: project_id.to_string(),
                build_id: map.build_id,
                manifest: map.dependency_manifest,
            });
        }
        if let Some(charter) = latest_single(
            self.store
                .load_ul_artifacts::<ProjectCharter>(project_id, &["project_charter"], 128)
                .await?,
        ) {
            candidates.push(ManifestTarget {
                kind: PyramidTargetKind::ProjectCharter,
                id: project_id.to_string(),
                build_id: charter.build_id,
                manifest: charter.dependency_manifest,
            });
        }

        let now = OffsetDateTime::now_utc();
        let mut dirty = Vec::new();
        for target in candidates {
            let reasons = stale_reasons(&target.manifest, "ul_dependency_scan");
            if reasons.is_empty() {
                continue;
            }
            let prior = existing.get(&(target.kind, target.id.clone()));
            let mut merged = prior.map(|state| state.reasons.clone()).unwrap_or_default();
            merged.extend(reasons);
            merged.sort();
            merged.dedup();
            let state = UlArtifactDirtyState {
                project_id,
                target_kind: target.kind,
                target_id: target.id,
                build_id: target.build_id,
                dirty: true,
                reasons: merged,
                first_dirty_at: prior.map_or(now, |state| state.first_dirty_at),
                updated_at: now,
            };
            self.store.mark_ul_artifact_dirty(&state).await?;
            dirty.push(state);
        }
        dirty.sort_by(|left, right| {
            left.first_dirty_at
                .cmp(&right.first_dirty_at)
                .then_with(|| left.target_kind.cmp(&right.target_kind))
                .then_with(|| left.target_id.cmp(&right.target_id))
        });
        Ok(dirty)
    }

    pub async fn rebuild_index(
        &self,
        project_id: ProjectId,
    ) -> Result<UlDependencyRebuildReport, EngineError> {
        let mut artifacts_indexed = 0_u32;
        let mut dependencies_indexed = 0_u32;
        for card in latest_by(
            self.store
                .load_ul_artifacts::<ModuleCard>(project_id, &["module_card"], 128)
                .await?,
            |card| card.path.clone(),
        )
        .into_values()
        {
            dependencies_indexed = dependencies_indexed.saturating_add(saturating_len(
                dependency_refs(&card.dependency_manifest).len(),
            ));
            self.index_card(&card).await?;
            artifacts_indexed = artifacts_indexed.saturating_add(1);
        }
        for capsule in latest_by(
            self.store
                .load_ul_artifacts::<SubsystemCapsule>(project_id, &["subsystem_capsule"], 128)
                .await?,
            |capsule| capsule.concept_id.clone(),
        )
        .into_values()
        {
            dependencies_indexed = dependencies_indexed.saturating_add(saturating_len(
                dependency_refs(&capsule.dependency_manifest).len(),
            ));
            self.index_capsule(&capsule).await?;
            artifacts_indexed = artifacts_indexed.saturating_add(1);
        }
        if let Some(map) = latest_single(
            self.store
                .load_ul_artifacts::<SystemMap>(project_id, &["system_map"], 128)
                .await?,
        ) {
            dependencies_indexed = dependencies_indexed.saturating_add(saturating_len(
                dependency_refs(&map.dependency_manifest).len(),
            ));
            self.index_map(&map).await?;
            artifacts_indexed = artifacts_indexed.saturating_add(1);
        }
        if let Some(charter) = latest_single(
            self.store
                .load_ul_artifacts::<ProjectCharter>(project_id, &["project_charter"], 128)
                .await?,
        ) {
            dependencies_indexed = dependencies_indexed.saturating_add(saturating_len(
                dependency_refs(&charter.dependency_manifest).len(),
            ));
            self.index_charter(&charter).await?;
            artifacts_indexed = artifacts_indexed.saturating_add(1);
        }
        Ok(UlDependencyRebuildReport {
            project_id,
            artifacts_indexed,
            dependencies_indexed,
        })
    }
}

#[must_use]
pub fn dependency_refs(manifest: &DependencyManifest) -> Vec<UlDependencyRef> {
    let mut dependencies = Vec::new();
    dependencies.extend(manifest.file_deps.iter().map(|dependency| UlDependencyRef {
        kind: UlDependencyKind::File,
        key: eliot_types::normalize_path(&dependency.path, None),
    }));
    dependencies.extend(
        manifest
            .claim_deps
            .iter()
            .map(|key| dependency(UlDependencyKind::Claim, key)),
    );
    dependencies.extend(
        manifest
            .decision_deps
            .iter()
            .map(|key| dependency(UlDependencyKind::Decision, key)),
    );
    dependencies.extend(
        manifest
            .edge_deps
            .iter()
            .map(|key| dependency(UlDependencyKind::Edge, key)),
    );
    dependencies.extend(
        manifest
            .report_deps
            .iter()
            .map(|key| dependency(UlDependencyKind::Report, key)),
    );
    dependencies.retain(|dependency| !dependency.key.is_empty());
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

fn dependency(kind: UlDependencyKind, key: &str) -> UlDependencyRef {
    UlDependencyRef {
        kind,
        key: key.trim().to_owned(),
    }
}

struct ManifestTarget {
    kind: PyramidTargetKind,
    id: String,
    build_id: String,
    manifest: DependencyManifest,
}

fn stale_reasons(manifest: &DependencyManifest, event_ref: &str) -> Vec<UlDirtyReason> {
    let root = PathBuf::from(&manifest.project_root);
    if manifest.project_root.trim().is_empty() || !root.is_dir() {
        return Vec::new();
    }
    let mut reasons = Vec::new();
    for dependency in &manifest.file_deps {
        let path = root.join(&dependency.path);
        let observed = file_fingerprint(&path);
        if observed.as_deref() == Some(dependency.blake3.as_str()) {
            continue;
        }
        reasons.push(UlDirtyReason {
            dependency: UlDependencyRef {
                kind: UlDependencyKind::File,
                key: eliot_types::normalize_path(&dependency.path, None),
            },
            expected_fingerprint: Some(dependency.blake3.clone()),
            observed_fingerprint: observed,
            event_ref: event_ref.to_owned(),
        });
    }
    reasons.sort();
    reasons.dedup();
    reasons
}

fn file_fingerprint(path: &Path) -> Option<String> {
    fs::read(path)
        .ok()
        .map(|bytes| blake3::hash(&bytes).to_hex().to_string())
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

fn saturating_len(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}
