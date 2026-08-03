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
use std::mem::size_of;
use std::sync::{Arc, RwLock, Weak};

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

#[derive(Clone, Debug)]
struct ProjectCueShard {
    memory_revision: MemoryRevision,
    exact: BTreeMap<(CueKind, String), Vec<CueIndexRow>>,
    dir_prefix: Vec<CueIndexRow>,
    row_count: usize,
    estimated_bytes: usize,
}

#[derive(Debug)]
struct CachedCueShard {
    strong: Option<Arc<ProjectCueShard>>,
    weak: Weak<ProjectCueShard>,
}

impl CachedCueShard {
    fn staged(shard: Arc<ProjectCueShard>) -> Self {
        Self {
            weak: Arc::downgrade(&shard),
            strong: Some(shard),
        }
    }

    fn snapshot(&self) -> Option<Arc<ProjectCueShard>> {
        self.strong.clone().or_else(|| self.weak.upgrade())
    }

    fn release_strong(&mut self) {
        if let Some(strong) = self.strong.take() {
            self.weak = Arc::downgrade(&strong);
        }
    }
}

/// Immutable cue projection consumed by the hot runtime without store access.
#[derive(Clone, Debug)]
pub struct CueIndexSnapshot {
    project_id: ProjectId,
    shard: Option<Arc<ProjectCueShard>>,
    projection_state: CognitiveProjectionReadState,
}

impl CueIndexSnapshot {
    #[must_use]
    pub const fn unavailable(project_id: ProjectId) -> Self {
        Self {
            project_id,
            shard: None,
            projection_state: CognitiveProjectionReadState::Unavailable,
        }
    }

    pub fn from_rows(
        project_id: ProjectId,
        memory_revision: MemoryRevision,
        projection_state: CognitiveProjectionReadState,
        rows: Vec<CueIndexRow>,
    ) -> Self {
        Self {
            project_id,
            shard: Some(Arc::new(shard_from_rows(memory_revision, rows))),
            projection_state,
        }
    }

    pub fn from_sources(
        project_id: ProjectId,
        memory_revision: MemoryRevision,
        projection_state: CognitiveProjectionReadState,
        sources: &[CueRecordSource],
    ) -> Result<Self, EngineError> {
        let mut rows = Vec::new();
        for source in sources {
            rows.extend(rows_for_source(project_id, source)?);
        }
        rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
        rows.dedup_by(|left, right| left.row_id == right.row_id);
        Ok(Self::from_rows(
            project_id,
            memory_revision,
            projection_state,
            rows,
        ))
    }

    #[must_use]
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }

    #[must_use]
    pub fn revision(&self) -> Option<MemoryRevision> {
        self.shard.as_ref().map(|shard| shard.memory_revision)
    }

    #[must_use]
    pub const fn projection_state(&self) -> CognitiveProjectionReadState {
        self.projection_state
    }

    #[must_use]
    pub fn with_projection_state(&self, projection_state: CognitiveProjectionReadState) -> Self {
        Self {
            project_id: self.project_id,
            shard: self.shard.clone(),
            projection_state,
        }
    }

    #[must_use]
    pub fn row_count(&self) -> usize {
        self.shard.as_ref().map_or(0, |shard| shard.row_count)
    }

    #[must_use]
    pub fn record_refs(&self) -> BTreeSet<String> {
        let Some(shard) = self.shard.as_ref() else {
            return BTreeSet::new();
        };
        shard
            .exact
            .values()
            .flatten()
            .chain(shard.dir_prefix.iter())
            .map(|row| row.record_ref.clone())
            .collect()
    }

    #[must_use]
    pub fn estimated_bytes(&self) -> usize {
        self.shard.as_ref().map_or(0, |shard| shard.estimated_bytes)
    }

    #[must_use]
    pub fn fire(&self, cues: &[ObservedCue]) -> FiringResult {
        let Some(shard) = self.shard.as_ref() else {
            return empty_firing(None, self.projection_state);
        };
        if !self.projection_state.is_published() {
            return empty_firing(Some(shard.memory_revision), self.projection_state);
        }
        fire_shard(shard, cues)
    }
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
    shards: RwLock<HashMap<ProjectId, CachedCueShard>>,
    target_revisions: RwLock<HashMap<ProjectId, MemoryRevision>>,
    max_shard_bytes: usize,
}

impl CueIndexService {
    #[must_use]
    pub fn new(store: CanonicalStore) -> Self {
        Self::with_max_shard_bytes(
            store,
            super::understanding::DEFAULT_PROJECT_SNAPSHOT_MAX_BYTES,
        )
    }

    #[must_use]
    pub fn with_max_shard_bytes(store: CanonicalStore, max_shard_bytes: usize) -> Self {
        Self {
            store,
            shards: RwLock::new(HashMap::new()),
            target_revisions: RwLock::new(HashMap::new()),
            max_shard_bytes: max_shard_bytes.max(1),
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
        ensure_shard_budget(&staged.shard, self.max_shard_bytes)?;
        let shard = Arc::new(staged.shard);
        self.shards
            .write()
            .map_err(|_| lock_error())?
            .insert(staged.project_id, CachedCueShard::staged(shard));
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

        let shard = shard_from_rows(memory_revision, rows);
        ensure_shard_budget(&shard, self.max_shard_bytes)?;
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
        let shard = Arc::new(shard);
        self.shards
            .write()
            .map_err(|_| lock_error())?
            .insert(project_id, CachedCueShard::staged(shard));
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

    /// Transfers the active strong ownership to `UnderstandingRuntime` after
    /// its atomic project-snapshot swap. The service keeps only a weak routing
    /// alias so runtime eviction also releases the hot cue allocation.
    pub(crate) fn release_strong_owner(&self, project_id: ProjectId) -> Result<(), EngineError> {
        if let Some(cached) = self
            .shards
            .write()
            .map_err(|_| lock_error())?
            .get_mut(&project_id)
        {
            cached.release_strong();
        }
        Ok(())
    }

    /// Captures the current store-free shard for installation in an
    /// [`crate::UnderstandingRuntime`].
    pub fn snapshot(&self, project_id: ProjectId) -> Result<CueIndexSnapshot, EngineError> {
        let shard = self
            .shards
            .read()
            .map_err(|_| lock_error())?
            .get(&project_id)
            .and_then(CachedCueShard::snapshot);
        let Some(shard) = shard else {
            return Ok(CueIndexSnapshot::unavailable(project_id));
        };
        let target_revision = self
            .target_revisions
            .read()
            .map_err(|_| lock_error())?
            .get(&project_id)
            .copied();
        let projection_state =
            if target_revision.is_some_and(|target| shard.memory_revision < target) {
                CognitiveProjectionReadState::Stale
            } else {
                CognitiveProjectionReadState::Published
            };
        Ok(CueIndexSnapshot {
            project_id,
            shard: Some(shard),
            projection_state,
        })
    }

    // Keep the stable async service boundary while the implementation reads
    // only the already-installed in-memory shard.
    #[allow(clippy::unused_async)]
    pub async fn fire(
        &self,
        project_id: ProjectId,
        cues: &[ObservedCue],
    ) -> Result<FiringResult, EngineError> {
        Ok(self.snapshot(project_id)?.fire(cues))
    }
}

fn fire_shard(shard: &ProjectCueShard, cues: &[ObservedCue]) -> FiringResult {
    let hits = matching_rows(shard, cues);
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
    FiringResult {
        projection_revision: Some(shard.memory_revision),
        projection_state: CognitiveProjectionReadState::Published,
        matched,
        deduplicated,
        suppressed,
        fired,
        overflow,
    }
}

fn empty_firing(
    projection_revision: Option<MemoryRevision>,
    projection_state: CognitiveProjectionReadState,
) -> FiringResult {
    FiringResult {
        projection_revision,
        projection_state,
        matched: 0,
        deduplicated: 0,
        suppressed: 0,
        fired: Vec::new(),
        overflow: 0,
    }
}

fn shard_from_rows(memory_revision: MemoryRevision, rows: Vec<CueIndexRow>) -> ProjectCueShard {
    let row_count = rows.len();
    let mut shard = ProjectCueShard {
        memory_revision,
        exact: BTreeMap::new(),
        dir_prefix: Vec::new(),
        row_count,
        estimated_bytes: 0,
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
    shard.estimated_bytes = conservative_shard_requested_bytes(&shard);
    shard
}

const ALLOCATION_OVERHEAD_BYTES: usize = 32;
const BTREE_ENTRY_OVERHEAD_BYTES: usize = 256;
const HOT_OWNER_ENTRY_OVERHEAD_BYTES: usize = 512;

fn conservative_shard_requested_bytes(shard: &ProjectCueShard) -> usize {
    let mut total = size_of::<ProjectCueShard>()
        .saturating_add(ALLOCATION_OVERHEAD_BYTES)
        .saturating_add(HOT_OWNER_ENTRY_OVERHEAD_BYTES);
    for ((_, key), rows) in &shard.exact {
        total = total
            .saturating_add(BTREE_ENTRY_OVERHEAD_BYTES)
            .saturating_add(size_of::<(CueKind, String)>())
            .saturating_add(size_of::<Vec<CueIndexRow>>())
            .saturating_add(string_allocation_bytes(key))
            .saturating_add(vec_allocation_bytes::<CueIndexRow>(rows.capacity()));
        for row in rows {
            total = total.saturating_add(cue_row_dynamic_bytes(row));
        }
    }
    total = total.saturating_add(vec_allocation_bytes::<CueIndexRow>(
        shard.dir_prefix.capacity(),
    ));
    for row in &shard.dir_prefix {
        total = total.saturating_add(cue_row_dynamic_bytes(row));
    }
    total
}

fn cue_row_dynamic_bytes(row: &CueIndexRow) -> usize {
    [
        &row.row_id,
        &row.cue_value_norm,
        &row.record_ref,
        &row.record_kind,
        &row.lifecycle,
    ]
    .into_iter()
    .fold(0_usize, |total, value| {
        total.saturating_add(string_allocation_bytes(value))
    })
}

fn string_allocation_bytes(value: &String) -> usize {
    if value.capacity() > 0 {
        value.capacity().saturating_add(ALLOCATION_OVERHEAD_BYTES)
    } else {
        0
    }
}

fn vec_allocation_bytes<T>(capacity: usize) -> usize {
    if capacity > 0 {
        capacity
            .saturating_mul(size_of::<T>())
            .saturating_add(ALLOCATION_OVERHEAD_BYTES)
    } else {
        0
    }
}

fn ensure_shard_budget(shard: &ProjectCueShard, max_shard_bytes: usize) -> Result<(), EngineError> {
    if shard.estimated_bytes > max_shard_bytes {
        return Err(EngineError::ServiceNotReady {
            service: "cue_index".to_owned(),
            reason: format!(
                "hot cue shard requires {} requested bytes, budget is {}",
                shard.estimated_bytes, max_shard_bytes
            ),
        });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::{CachedCueShard, ensure_shard_budget, shard_from_rows};
    use eliot_types::{CueIndexRow, CueKind, CueMatchMode, CueStrength, MemoryRevision, ProjectId};
    use std::sync::Arc;

    #[test]
    fn resident_budget_charges_spare_string_capacity_and_rejects_one_byte_below() {
        let mut row_id = String::with_capacity(1024 * 1024);
        row_id.push_str("cue:capacity-proof");
        let shard = shard_from_rows(
            MemoryRevision::new(1),
            vec![CueIndexRow {
                row_id,
                project_id: ProjectId::new_v7(),
                cue_kind: CueKind::FilePath,
                cue_value_norm: "src/lib.rs".to_owned(),
                match_mode: CueMatchMode::Exact,
                record_ref: "failure:capacity-proof".to_owned(),
                record_kind: "failure_fingerprint".to_owned(),
                strength: CueStrength::Primary,
                negative_memory: true,
                lifecycle: "active".to_owned(),
                token_estimate: 4,
            }],
        );

        assert!(shard.estimated_bytes > 1024 * 1024);
        assert!(ensure_shard_budget(&shard, shard.estimated_bytes).is_ok());
        assert!(ensure_shard_budget(&shard, shard.estimated_bytes - 1).is_err());
    }

    #[test]
    fn cache_releases_its_strong_owner_after_runtime_adoption() {
        let shard = Arc::new(shard_from_rows(MemoryRevision::new(1), Vec::new()));
        let mut cached = CachedCueShard::staged(Arc::clone(&shard));
        assert_eq!(Arc::strong_count(&shard), 2);

        cached.release_strong();

        assert_eq!(Arc::strong_count(&shard), 1);
        assert!(cached.snapshot().is_some());
        drop(shard);
        assert!(cached.snapshot().is_none());
    }

    #[test]
    fn rejected_candidate_release_drops_the_last_strong_owner() {
        let shard = Arc::new(shard_from_rows(MemoryRevision::new(1), Vec::new()));
        let weak = Arc::downgrade(&shard);
        let mut cached = CachedCueShard::staged(shard);

        cached.release_strong();

        assert!(weak.upgrade().is_none());
        assert!(cached.snapshot().is_none());
    }
}
