use crate::EngineError;
use eliot_store::CanonicalStore;
use eliot_types::{
    CognitiveProjectionReadState, CueIndexRow, CueKind, CueRecordSource, CueStrength,
    CurrentStateRequest, MemoryRevision, ObservedCue, ProjectId, ReadConsistencyMode, cue_row_id,
    normalize_binding, normalize_path, normalize_symbol, ul_token_estimate,
};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

const MAX_FIRED_MEMORIES: usize = 8;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FiredMemory {
    pub record_ref: String,
    pub record_kind: String,
    pub strength: CueStrength,
    pub negative_memory: bool,
    pub fired_cues: Vec<ObservedCue>,
    pub token_estimate: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FiringResult {
    pub projection_revision: Option<MemoryRevision>,
    pub projection_state: CognitiveProjectionReadState,
    pub matched: usize,
    pub deduplicated: usize,
    pub suppressed: usize,
    pub fired: Vec<FiredMemory>,
    pub overflow: usize,
}

struct ProjectCueShard {
    memory_revision: MemoryRevision,
    exact: BTreeMap<(CueKind, String), Vec<CueIndexRow>>,
    dir_prefix: Vec<CueIndexRow>,
}

pub(crate) struct StagedCueProjection {
    project_id: ProjectId,
    shard: ProjectCueShard,
}

impl StagedCueProjection {
    pub(crate) const fn revision(&self) -> MemoryRevision {
        self.shard.memory_revision
    }
}

pub struct CueIndexService {
    store: CanonicalStore,
    shards: RwLock<HashMap<ProjectId, Arc<ProjectCueShard>>>,
    target_revisions: RwLock<HashMap<ProjectId, MemoryRevision>>,
}

impl CueIndexService {
    #[must_use]
    pub fn new(store: CanonicalStore) -> Self {
        Self {
            store,
            shards: RwLock::new(HashMap::new()),
            target_revisions: RwLock::new(HashMap::new()),
        }
    }

    pub async fn rebuild(&self, project_id: ProjectId) -> Result<MemoryRevision, EngineError> {
        let staged = self.stage_rebuild(project_id).await?;
        self.install_staged(staged)
    }

    /// Builds and persists a stable shard without making it visible. The
    /// coordinator publishes the durable family fence before installation.
    pub(crate) async fn stage_rebuild(
        &self,
        project_id: ProjectId,
    ) -> Result<StagedCueProjection, EngineError> {
        for _attempt in 0..4 {
            let start_revision = self.current_revision(project_id).await?;
            let shard = self.build_shard(project_id, start_revision, true).await?;
            let end_revision = self.current_revision(project_id).await?;
            if start_revision != end_revision {
                continue;
            }
            return Ok(StagedCueProjection { project_id, shard });
        }
        Err(EngineError::ServiceNotReady {
            service: "cue_index".to_owned(),
            reason: "project revision changed repeatedly during cue-index rebuild".to_owned(),
        })
    }

    pub(crate) fn install_staged(
        &self,
        staged: StagedCueProjection,
    ) -> Result<MemoryRevision, EngineError> {
        let revision = staged.revision();
        self.shards
            .write()
            .map_err(|_| lock_error())?
            .insert(staged.project_id, Arc::new(staged.shard));
        self.advance_target_revision(staged.project_id, revision)?;
        Ok(revision)
    }

    async fn build_shard(
        &self,
        project_id: ProjectId,
        memory_revision: MemoryRevision,
        rebuild_from_canonical: bool,
    ) -> Result<ProjectCueShard, EngineError> {
        let rows = if rebuild_from_canonical {
            let sources = self.store.load_cue_records(project_id).await?;
            let mut rows = Vec::new();
            for source in &sources {
                rows.extend(rows_for_source(project_id, source)?);
            }
            rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
            rows.dedup_by(|left, right| left.row_id == right.row_id);
            self.store
                .replace_project_cue_rows(project_id, &rows)
                .await?;
            rows
        } else {
            self.store.load_cue_rows(project_id).await?
        };

        let mut shard = ProjectCueShard {
            memory_revision,
            exact: BTreeMap::new(),
            dir_prefix: Vec::new(),
        };
        for mut row in rows {
            row.cue_value_norm = normalize_cue_value(row.cue_kind, &row.cue_value_norm);
            if row.cue_kind == CueKind::DirPath {
                shard.dir_prefix.push(row);
            } else {
                shard
                    .exact
                    .entry((row.cue_kind, row.cue_value_norm.clone()))
                    .or_default()
                    .push(row);
            }
        }
        for rows in shard.exact.values_mut() {
            rows.sort_by(compare_rows);
        }
        shard.dir_prefix.sort_by(compare_rows);
        Ok(shard)
    }

    /// Loads an already-published durable cue projection into the in-memory
    /// shard without deriving or repairing canonical project state. Cold
    /// rebuild/recovery must use [`Self::rebuild`] instead.
    pub async fn load_persisted_projection(
        &self,
        project_id: ProjectId,
    ) -> Result<MemoryRevision, EngineError> {
        let revision = self.current_revision(project_id).await?;
        self.load_persisted_projection_at(project_id, revision)
            .await?;
        Ok(revision)
    }

    pub async fn load_persisted_projection_at(
        &self,
        project_id: ProjectId,
        published_revision: MemoryRevision,
    ) -> Result<(), EngineError> {
        let shard = self
            .build_shard(project_id, published_revision, false)
            .await?;
        self.shards
            .write()
            .map_err(|_| lock_error())?
            .insert(project_id, Arc::new(shard));
        self.advance_target_revision(project_id, published_revision)?;
        Ok(())
    }

    /// Marks the project target synchronously before a fallible coordinator
    /// notification. Firing can therefore reject a stale shard even when the
    /// bounded notification queue is full and recovery must use the outbox.
    pub fn mark_stale(
        &self,
        project_id: ProjectId,
        target_revision: MemoryRevision,
    ) -> Result<(), EngineError> {
        self.advance_target_revision(project_id, target_revision)
    }

    fn advance_target_revision(
        &self,
        project_id: ProjectId,
        target_revision: MemoryRevision,
    ) -> Result<(), EngineError> {
        let mut targets = self.target_revisions.write().map_err(|_| lock_error())?;
        let target = targets.entry(project_id).or_insert(target_revision);
        if *target < target_revision {
            *target = target_revision;
        }
        Ok(())
    }

    async fn current_revision(&self, project_id: ProjectId) -> Result<MemoryRevision, EngineError> {
        Ok(self
            .store
            .current_state(&CurrentStateRequest {
                project_id,
                consistency: ReadConsistencyMode::Latest,
                at_least_revision: None,
            })
            .await?
            .memory_revision)
    }

    pub fn invalidate(&self, project_id: ProjectId) -> Result<(), EngineError> {
        self.shards
            .write()
            .map_err(|_| lock_error())?
            .remove(&project_id);
        Ok(())
    }

    // Keep the stable async service boundary while the implementation reads
    // only the already-installed in-memory shard.
    #[allow(clippy::unused_async)]
    pub async fn fire(
        &self,
        project_id: ProjectId,
        cues: &[ObservedCue],
    ) -> Result<FiringResult, EngineError> {
        let shard = self
            .shards
            .read()
            .map_err(|_| lock_error())?
            .get(&project_id)
            .cloned();
        let Some(shard) = shard else {
            return Ok(FiringResult {
                projection_revision: None,
                projection_state: CognitiveProjectionReadState::Unavailable,
                matched: 0,
                deduplicated: 0,
                suppressed: 0,
                fired: Vec::new(),
                overflow: 0,
            });
        };
        let target_revision = self
            .target_revisions
            .read()
            .map_err(|_| lock_error())?
            .get(&project_id)
            .copied();
        if target_revision.is_some_and(|target| shard.memory_revision < target) {
            return Ok(FiringResult {
                projection_revision: Some(shard.memory_revision),
                projection_state: CognitiveProjectionReadState::Stale,
                matched: 0,
                deduplicated: 0,
                suppressed: 0,
                fired: Vec::new(),
                overflow: 0,
            });
        }

        let hits = matching_rows(&shard, cues);
        let matched = hits.len();
        let unique_refs = hits
            .iter()
            .map(|(row, _)| row.record_ref.clone())
            .collect::<BTreeSet<_>>();
        let deduplicated = matched.saturating_sub(unique_refs.len());
        let suppressed = hits
            .iter()
            .filter(|(row, _)| !matches!(row.lifecycle.as_str(), "active" | "restored"))
            .count();

        let mut merged = BTreeMap::<String, FiredMemory>::new();
        for (row, cue) in hits
            .into_iter()
            .filter(|(row, _)| matches!(row.lifecycle.as_str(), "active" | "restored"))
        {
            let memory = merged
                .entry(row.record_ref.clone())
                .or_insert_with(|| FiredMemory {
                    record_ref: row.record_ref.clone(),
                    record_kind: row.record_kind.clone(),
                    strength: row.strength,
                    negative_memory: row.negative_memory,
                    fired_cues: Vec::new(),
                    token_estimate: row.token_estimate,
                });
            if row.strength == CueStrength::Primary {
                memory.strength = CueStrength::Primary;
            }
            memory.negative_memory |= row.negative_memory;
            memory.token_estimate = memory.token_estimate.max(row.token_estimate);
            if kind_rank(&row.record_kind) < kind_rank(&memory.record_kind) {
                memory.record_kind = row.record_kind;
            }
            if !memory.fired_cues.contains(&cue) {
                memory.fired_cues.push(cue);
            }
        }

        let mut fired = merged.into_values().collect::<Vec<_>>();
        fired.sort_by(compare_fired);
        let overflow = fired.len().saturating_sub(MAX_FIRED_MEMORIES);
        fired.truncate(MAX_FIRED_MEMORIES);
        Ok(FiringResult {
            projection_revision: Some(shard.memory_revision),
            projection_state: CognitiveProjectionReadState::Published,
            matched,
            deduplicated,
            suppressed,
            fired,
            overflow,
        })
    }
}

fn matching_rows(shard: &ProjectCueShard, cues: &[ObservedCue]) -> Vec<(CueIndexRow, ObservedCue)> {
    let mut observed = cues
        .iter()
        .map(|cue| ObservedCue {
            kind: cue.kind,
            value: normalize_cue_value(cue.kind, &cue.value),
        })
        .filter(|cue| !cue.value.is_empty())
        .collect::<Vec<_>>();
    observed.sort_by(|left, right| {
        left.kind
            .cmp(&right.kind)
            .then_with(|| left.value.cmp(&right.value))
    });
    observed.dedup();

    let mut hits = Vec::new();
    for cue in &observed {
        if let Some(rows) = shard.exact.get(&(cue.kind, cue.value.clone())) {
            hits.extend(rows.iter().cloned().map(|row| (row, cue.clone())));
        }
        if matches!(cue.kind, CueKind::FilePath | CueKind::DirPath) {
            hits.extend(
                shard
                    .dir_prefix
                    .iter()
                    .filter(|row| path_segment_prefix(&cue.value, &row.cue_value_norm))
                    .cloned()
                    .map(|row| (row, cue.clone())),
            );
        }
    }
    hits
}

fn rows_for_source(
    project_id: ProjectId,
    source: &CueRecordSource,
) -> Result<Vec<CueIndexRow>, EngineError> {
    source
        .cue_bindings
        .iter()
        .cloned()
        .map(|binding| {
            let binding = normalize_binding(binding, None).map_err(|error| {
                EngineError::WriteRejected(format!("invalid cue binding: {error}"))
            })?;
            Ok(CueIndexRow {
                row_id: cue_row_id(
                    project_id,
                    binding.cue_kind,
                    binding.match_mode,
                    &binding.cue_value,
                    &source.record_ref,
                ),
                project_id,
                cue_kind: binding.cue_kind,
                cue_value_norm: binding.cue_value,
                match_mode: binding.match_mode,
                record_ref: source.record_ref.clone(),
                record_kind: source.record_kind.clone(),
                strength: binding.strength,
                negative_memory: source.negative_memory,
                lifecycle: source.lifecycle.clone(),
                token_estimate: ul_token_estimate(&source.preview_text),
            })
        })
        .collect()
}

fn normalize_cue_value(kind: CueKind, value: &str) -> String {
    match kind {
        CueKind::FilePath | CueKind::DirPath => normalize_path(value, None),
        CueKind::Symbol => normalize_symbol(value),
        CueKind::ErrorSignature
        | CueKind::CommandPattern
        | CueKind::Dependency
        | CueKind::ApiSurface
        | CueKind::TaskClass
        | CueKind::Subsystem
        | CueKind::Concept => value.trim().chars().flat_map(char::to_lowercase).collect(),
    }
}

fn path_segment_prefix(observed: &str, prefix: &str) -> bool {
    observed == prefix
        || observed
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn compare_rows(left: &CueIndexRow, right: &CueIndexRow) -> Ordering {
    right
        .negative_memory
        .cmp(&left.negative_memory)
        .then_with(|| left.strength.cmp(&right.strength))
        .then_with(|| kind_rank(&left.record_kind).cmp(&kind_rank(&right.record_kind)))
        .then_with(|| left.record_ref.cmp(&right.record_ref))
}

fn compare_fired(left: &FiredMemory, right: &FiredMemory) -> Ordering {
    right
        .negative_memory
        .cmp(&left.negative_memory)
        .then_with(|| left.strength.cmp(&right.strength))
        .then_with(|| kind_rank(&left.record_kind).cmp(&kind_rank(&right.record_kind)))
        .then_with(|| left.record_ref.cmp(&right.record_ref))
}

fn kind_rank(kind: &str) -> u8 {
    match kind {
        "failure_fingerprint" => 0,
        "invariant" => 1,
        "decision" => 2,
        "claim" => 3,
        "experience_case" => 4,
        "skill" => 5,
        "module_card" => 6,
        "subsystem_capsule" => 7,
        _ => 8,
    }
}

fn lock_error() -> EngineError {
    EngineError::ServiceNotReady {
        service: "cue_index".to_owned(),
        reason: "project shard lock poisoned".to_owned(),
    }
}
