use crate::{
    ActivationProjection, CueIndexService, DependencyProjection, DirtyArtifactProjection,
    EngineError, FreshArtifact, MetacognitionService, ProjectProjectionFamily,
    ProjectProjectionHealth, ProjectRevisions, ProjectSnapshot, ProjectSnapshotBuilder,
    ProjectSnapshotInput, ProjectionFamilyHealth, SnapshotFreshness, UlDependencyService,
    UnderstandingRuntime, render_capsule_with_dirty,
};
use eliot_store::{
    CanonicalRecord, CanonicalStore, CognitiveProjectionFamily, CognitiveProjectionFamilyState,
    CognitiveProjectionLease, CognitiveProjectionPublicationStatus, StoreError,
};
use eliot_types::{
    CognitiveProjectionReadState, ConceptNode, CurrentStateRequest, DependencyManifest,
    HotspotScore, MemoryRevision, MemoryWriteEnvelope, ModuleCard, ProjectCharter, ProjectId,
    PyramidTargetKind, ReadConsistencyMode, SubsystemCapsule, SystemMap, UlActivationGraphRows,
    UlArtifactDirtyState, UlDependencyKind, UlDependencyRef, UlReverseDependencyRow, WriteReceipt,
    WriteStatus,
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

const DEFAULT_QUEUE_CAPACITY: usize = 256;
const DEFAULT_LEASE_SECONDS: u64 = 600;
const DEFAULT_BATCH_LIMIT: u16 = 64;
const DEFAULT_MAX_ATTEMPTS: u32 = 5;
const DEFAULT_PROJECT_PAGE_SIZE: usize = 100;
const MAX_DELTA_CACHE_ENTRIES: usize = 1_024;
const MAX_SNAPSHOT_FENCE_ATTEMPTS: usize = 4;
const SNAPSHOT_CHARTER_MAP_PAGE_SIZE: u16 = 32;
const SNAPSHOT_CONCEPT_CAPSULE_PAGE_SIZE: u16 = 128;
const SNAPSHOT_CARD_HOTSPOT_PAGE_SIZE: u16 = 512;
const SNAPSHOT_DIRTY_LIMIT: u16 = 512;

struct SnapshotMaterial {
    records: Vec<eliot_types::CueRecordSource>,
    charters: Vec<CanonicalRecord<ProjectCharter>>,
    maps: Vec<CanonicalRecord<SystemMap>>,
    concepts: Vec<CanonicalRecord<ConceptNode>>,
    capsules: Vec<CanonicalRecord<SubsystemCapsule>>,
    cards: Vec<CanonicalRecord<ModuleCard>>,
    hotspots: Vec<CanonicalRecord<HotspotScore>>,
    activation_graph: UlActivationGraphRows,
    dirty: Vec<UlArtifactDirtyState>,
}

struct StagedUnderstandingSnapshot {
    revision: MemoryRevision,
    snapshot: ProjectSnapshot,
}

#[derive(Clone, Copy, Debug)]
pub struct CognitiveProjectionCoordinatorConfig {
    pub queue_capacity: usize,
    pub lease_seconds: u64,
    pub batch_limit: u16,
    pub max_attempts: u32,
    pub project_page_size: usize,
}

impl Default for CognitiveProjectionCoordinatorConfig {
    fn default() -> Self {
        Self {
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            lease_seconds: DEFAULT_LEASE_SECONDS,
            batch_limit: DEFAULT_BATCH_LIMIT,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            project_page_size: DEFAULT_PROJECT_PAGE_SIZE,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CognitiveProjectionMetricsSnapshot {
    pub wake_hints: u64,
    pub dropped_wake_hints: u64,
    pub completed_leases: u64,
    pub cold_rebuilds: u64,
    pub retryable_failures: u64,
    pub blocked_failures: u64,
    pub recovery_pages: u64,
}

#[derive(Default)]
struct CognitiveProjectionMetricsInner {
    wake_hints: AtomicU64,
    dropped_wake_hints: AtomicU64,
    completed_leases: AtomicU64,
    cold_rebuilds: AtomicU64,
    retryable_failures: AtomicU64,
    blocked_failures: AtomicU64,
    recovery_pages: AtomicU64,
}

#[derive(Clone, Default)]
pub struct CognitiveProjectionMetrics {
    inner: Arc<CognitiveProjectionMetricsInner>,
}

impl CognitiveProjectionMetrics {
    #[must_use]
    pub fn snapshot(&self) -> CognitiveProjectionMetricsSnapshot {
        CognitiveProjectionMetricsSnapshot {
            wake_hints: self.inner.wake_hints.load(Ordering::Relaxed),
            dropped_wake_hints: self.inner.dropped_wake_hints.load(Ordering::Relaxed),
            completed_leases: self.inner.completed_leases.load(Ordering::Relaxed),
            cold_rebuilds: self.inner.cold_rebuilds.load(Ordering::Relaxed),
            retryable_failures: self.inner.retryable_failures.load(Ordering::Relaxed),
            blocked_failures: self.inner.blocked_failures.load(Ordering::Relaxed),
            recovery_pages: self.inner.recovery_pages.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
pub struct CognitiveProjectionCoordinatorHandle {
    sender: mpsc::Sender<ProjectionCommand>,
    store: CanonicalStore,
    cue_index: Arc<CueIndexService>,
    understanding: Arc<UnderstandingRuntime>,
    metrics: CognitiveProjectionMetrics,
}

impl CognitiveProjectionCoordinatorHandle {
    /// Arms recovery without performing a store round trip on the READY path.
    /// Inventory pages and cold rebuilds run on the coordinator task.
    pub async fn recover(&self) -> Result<(), EngineError> {
        let (reply, response) = oneshot::channel();
        self.sender
            .send(ProjectionCommand::Recover { reply })
            .await
            .map_err(|_| coordinator_unavailable("recovery queue is closed"))?;
        response
            .await
            .map_err(|_| coordinator_unavailable("recovery acknowledgement was dropped"))?
            .map_err(|reason| coordinator_unavailable(&reason))
    }

    /// Persists the `PostToolUse` intent before using the bounded channel as a
    /// best-effort latency hint. Queue loss is safe because the outbox is the
    /// recovery source of truth.
    pub async fn enqueue_dependency_dirty(
        &self,
        project_id: ProjectId,
        event_ref: &str,
        paths: &[String],
    ) -> Result<(), EngineError> {
        let mut paths = paths
            .iter()
            .map(|path| eliot_types::normalize_path(path, None))
            .filter(|path| !path.is_empty())
            .collect::<Vec<_>>();
        paths.sort();
        paths.dedup();
        if paths.is_empty() {
            return Ok(());
        }
        let revision = current_revision(&self.store, project_id).await?;
        let event_id = dependency_event_id(project_id, revision, event_ref, &paths);
        let intent = self
            .store
            .enqueue_cognitive_projection_intent(
                project_id,
                &event_id,
                revision,
                &[CognitiveProjectionFamily::DependencyDirty],
            )
            .await?;
        if !projection_intent_needs_wake(&intent.status) {
            return Ok(());
        }
        let _ = self.understanding.mark_project_stale(
            project_id,
            ProjectProjectionFamily::Dependency,
            revision,
            Some("dependency mutation awaits background snapshot publication".to_owned()),
        );
        self.metrics
            .inner
            .wake_hints
            .fetch_add(1, Ordering::Relaxed);
        if self
            .sender
            .try_send(ProjectionCommand::DependencyDirty {
                event_id,
                project_id,
                revision,
                paths,
            })
            .is_err()
        {
            self.metrics
                .inner
                .dropped_wake_hints
                .fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }

    #[must_use]
    pub fn metrics(&self) -> CognitiveProjectionMetrics {
        self.metrics.clone()
    }

    /// Writer-only wake hint. The canonical receipt and outbox are already
    /// durable when this method is called, so it must never fail the write.
    pub(crate) fn notify_committed(&self, envelope: MemoryWriteEnvelope, receipt: WriteReceipt) {
        if !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        ) || receipt.write_id != envelope.write_id
            || receipt.project_id != envelope.project_id
        {
            return;
        }
        let Some(revision) = receipt.memory_revision else {
            return;
        };
        // This synchronous fence is deliberately before the fallible wake
        // hint: a full queue must not make an old cue or understanding
        // snapshot look current.
        let _ = self.cue_index.mark_stale(envelope.project_id, revision);
        if invalidates_understanding_snapshot(receipt.status) {
            let _ = self.understanding.mark_project_stale_all(
                envelope.project_id,
                revision,
                Some("canonical commit awaits background snapshot publication"),
            );
        }
        self.metrics
            .inner
            .wake_hints
            .fetch_add(1, Ordering::Relaxed);
        let command = if receipt.status == WriteStatus::Committed {
            ProjectionCommand::CanonicalCommitted {
                envelope: Box::new(envelope),
                receipt,
            }
        } else {
            // A replay is only a recovery wake. Its caller-supplied envelope
            // is not trusted as a fresh incremental projection delta.
            ProjectionCommand::Wake
        };
        if self.sender.try_send(command).is_err() {
            self.metrics
                .inner
                .dropped_wake_hints
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub struct CognitiveProjectionShutdownHandle {
    sender: Option<oneshot::Sender<()>>,
}

impl CognitiveProjectionShutdownHandle {
    pub fn shutdown(mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(());
        }
    }
}

pub struct CognitiveProjectionCoordinator {
    store: CanonicalStore,
    cue_index: Arc<CueIndexService>,
    dependency: Arc<UlDependencyService>,
    understanding: Arc<UnderstandingRuntime>,
    project_root: PathBuf,
    receiver: mpsc::Receiver<ProjectionCommand>,
    shutdown: oneshot::Receiver<()>,
    config: CognitiveProjectionCoordinatorConfig,
    metrics: CognitiveProjectionMetrics,
    committed: HashMap<String, CommittedDelta>,
    dirty: HashMap<String, DirtyDelta>,
    warmed_cues: HashSet<ProjectId>,
    recovery_cursor: Option<usize>,
}

impl CognitiveProjectionCoordinator {
    #[must_use]
    pub fn channel(
        store: CanonicalStore,
        cue_index: Arc<CueIndexService>,
        dependency: Arc<UlDependencyService>,
        understanding: Arc<UnderstandingRuntime>,
        project_root: PathBuf,
        config: CognitiveProjectionCoordinatorConfig,
    ) -> (
        CognitiveProjectionCoordinatorHandle,
        Self,
        CognitiveProjectionShutdownHandle,
    ) {
        let (sender, receiver) = mpsc::channel(config.queue_capacity.max(1));
        let (shutdown_sender, shutdown) = oneshot::channel();
        let metrics = CognitiveProjectionMetrics::default();
        let handle = CognitiveProjectionCoordinatorHandle {
            sender,
            store: store.clone(),
            cue_index: Arc::clone(&cue_index),
            understanding: Arc::clone(&understanding),
            metrics: metrics.clone(),
        };
        let coordinator = Self {
            store,
            cue_index,
            dependency,
            understanding,
            project_root,
            receiver,
            shutdown,
            config,
            metrics,
            committed: HashMap::new(),
            dirty: HashMap::new(),
            warmed_cues: HashSet::new(),
            recovery_cursor: None,
        };
        (
            handle,
            coordinator,
            CognitiveProjectionShutdownHandle {
                sender: Some(shutdown_sender),
            },
        )
    }

    /// Runs the single daemon-owned projection worker. Background failures are
    /// persisted on the claimed lease and never falsify canonical commits.
    pub async fn run(mut self) -> Result<(), EngineError> {
        let mut armed = false;
        let mut delay = Duration::from_secs(86_400);
        loop {
            tokio::select! {
                _ = &mut self.shutdown => {
                    self.receiver.close();
                    while let Ok(command) = self.receiver.try_recv() {
                        self.cache_command(command, None);
                    }
                    return Ok(());
                }
                command = self.receiver.recv() => {
                    let Some(command) = command else {
                        return Ok(());
                    };
                    self.cache_command(command, Some(&mut armed));
                }
                () = tokio::time::sleep(delay), if armed => {}
            }

            if !armed {
                delay = Duration::from_secs(86_400);
                continue;
            }
            match Box::pin(self.background_step()).await {
                Ok(BackgroundStep::Progress) => {
                    delay = Duration::from_millis(10);
                }
                Ok(BackgroundStep::Waiting) => {
                    delay = Duration::from_secs(1);
                }
                Ok(BackgroundStep::Dormant) => {
                    armed = false;
                    delay = Duration::from_secs(86_400);
                }
                Err(_) => {
                    // Claim/inventory transport failure has no lease to mutate.
                    // Keep the task alive and retry at a bounded cadence.
                    delay = Duration::from_secs(1);
                }
            }
        }
    }

    fn cache_command(&mut self, command: ProjectionCommand, mut armed: Option<&mut bool>) {
        match command {
            ProjectionCommand::CanonicalCommitted { envelope, receipt } => {
                cap_cache(&mut self.committed);
                self.committed.insert(
                    envelope.write_id.to_string(),
                    CommittedDelta {
                        envelope: *envelope,
                        receipt,
                    },
                );
                if let Some(armed) = &mut armed {
                    **armed = true;
                }
            }
            ProjectionCommand::DependencyDirty {
                event_id,
                project_id,
                revision,
                paths,
            } => {
                cap_cache(&mut self.dirty);
                self.dirty.insert(
                    event_id,
                    DirtyDelta {
                        project_id,
                        revision,
                        paths,
                    },
                );
                if let Some(armed) = &mut armed {
                    **armed = true;
                }
            }
            ProjectionCommand::Recover { reply } => {
                if armed.is_none() {
                    let _ = reply.send(Err(
                        "cognitive projection coordinator is shutting down".to_owned()
                    ));
                    return;
                }
                self.recovery_cursor = Some(0);
                if let Some(armed) = &mut armed {
                    **armed = true;
                }
                let _ = reply.send(Ok(()));
            }
            ProjectionCommand::Wake => {
                if let Some(armed) = &mut armed {
                    **armed = true;
                }
            }
        }
    }

    async fn background_step(&mut self) -> Result<BackgroundStep, EngineError> {
        if let Some(cursor) = self.recovery_cursor {
            self.bootstrap_page(cursor).await?;
            return Ok(BackgroundStep::Progress);
        }
        if let Some(lease) = self
            .store
            .claim_cognitive_projection_project(
                &format!("cognitive-projection:{}", std::process::id()),
                self.config.lease_seconds,
                self.config.batch_limit,
            )
            .await?
        {
            Box::pin(self.process_claimed_lease(&lease)).await;
            return Ok(BackgroundStep::Progress);
        }
        let backlog = self.store.cognitive_projection_backlog().await?;
        if backlog.pending > 0 || backlog.retryable > 0 || backlog.leased > 0 {
            Ok(BackgroundStep::Waiting)
        } else {
            Ok(BackgroundStep::Dormant)
        }
    }

    async fn bootstrap_page(&mut self, start: usize) -> Result<(), EngineError> {
        let page = self
            .store
            .load_cognitive_projection_projects(start, self.config.project_page_size)
            .await?;
        for project in &page.projects {
            let event_id = recovery_event_id(project.project_id, project.head_revision);
            let snapshot_is_current = self
                .understanding
                .project_snapshot(project.project_id)?
                .is_some_and(|snapshot| {
                    snapshot.revisions().canonical == Some(project.head_revision)
                        && snapshot.is_fully_published()
                });
            if snapshot_is_current {
                self.store
                    .enqueue_cognitive_projection_intent(
                        project.project_id,
                        &event_id,
                        project.head_revision,
                        &[
                            CognitiveProjectionFamily::Search,
                            CognitiveProjectionFamily::Cue,
                            CognitiveProjectionFamily::DependencyDirty,
                        ],
                    )
                    .await?;
            } else {
                self.store
                    .rearm_cognitive_projection_recovery_intent(
                        project.project_id,
                        &event_id,
                        project.head_revision,
                        &[
                            CognitiveProjectionFamily::Search,
                            CognitiveProjectionFamily::Cue,
                            CognitiveProjectionFamily::DependencyDirty,
                        ],
                    )
                    .await?;
            }
            self.store
                .publish_cognitive_projection_family_state(
                    project.project_id,
                    CognitiveProjectionFamily::Utility,
                    project.head_revision,
                    None,
                    CognitiveProjectionPublicationStatus::Unavailable,
                    Some("utility projection is not materialized until Phase 2"),
                )
                .await?;
        }
        self.metrics
            .inner
            .recovery_pages
            .fetch_add(1, Ordering::Relaxed);
        self.recovery_cursor = if page.truncated {
            page.next_start
        } else {
            None
        };
        Ok(())
    }

    async fn process_claimed_lease(&mut self, lease: &CognitiveProjectionLease) {
        let states = match self
            .store
            .cognitive_projection_family_states(lease.project_id)
            .await
        {
            Ok(states) => states
                .into_iter()
                .map(|state| (state.family, state))
                .collect::<BTreeMap<_, _>>(),
            Err(error) => {
                self.persist_failure(lease, None, EngineError::Store(error), &BTreeMap::new())
                    .await;
                return;
            }
        };

        for family in &lease.families {
            if let Err(error) = self.process_family(*family, lease, &states).await {
                let error = self.release_rejected_cue_owner(lease.project_id, error);
                self.persist_failure(lease, Some(*family), error, &states)
                    .await;
                return;
            }
        }
        let staged_snapshot = match Box::pin(self.stage_understanding_snapshot(lease)).await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let error = self.release_rejected_cue_owner(lease.project_id, error);
                self.persist_failure(lease, None, error, &states).await;
                return;
            }
        };
        if let Err(error) = self
            .store
            .complete_cognitive_projection_through(lease)
            .await
        {
            let error = self.release_rejected_cue_owner(lease.project_id, error.into());
            self.persist_failure(lease, None, error, &states).await;
            return;
        }
        match staged_snapshot {
            Some(staged_snapshot) => {
                // A newer canonical or same-head dependency intent safely
                // supersedes this candidate. The newer outbox row owns the
                // next publication; the old runtime snapshot remains stale.
                let adopted = matches!(
                    Box::pin(self.finalize_understanding_snapshot(staged_snapshot)).await,
                    Ok(true)
                );
                if !adopted {
                    // Completion is durable, so recover with a new bounded
                    // project inventory pass rather than mutating the old
                    // lease or retaining an unadopted hot cue owner.
                    let _ = self.cue_index.release_strong_owner(lease.project_id);
                    self.recovery_cursor = Some(0);
                    self.metrics
                        .inner
                        .retryable_failures
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            None => {
                // The lease was superseded before a snapshot could be staged.
                // Drop any service-only candidate installed while processing
                // its durable cue family; a later inventory pass reloads it.
                let _ = self.cue_index.release_strong_owner(lease.project_id);
            }
        }
        for write_id in &lease.write_ids {
            self.committed.remove(write_id);
            self.dirty.remove(write_id);
        }
        self.metrics
            .inner
            .completed_leases
            .fetch_add(1, Ordering::Relaxed);
    }

    fn release_rejected_cue_owner(&self, project_id: ProjectId, error: EngineError) -> EngineError {
        match self.cue_index.release_strong_owner(project_id) {
            Ok(()) => error,
            Err(cleanup_error) => coordinator_unavailable(&format!(
                "{error}; failed to release rejected cue candidate: {cleanup_error}"
            )),
        }
    }

    async fn process_family(
        &mut self,
        family: CognitiveProjectionFamily,
        lease: &CognitiveProjectionLease,
        states: &BTreeMap<CognitiveProjectionFamily, CognitiveProjectionFamilyState>,
    ) -> Result<(), EngineError> {
        let state = states.get(&family);
        match family {
            CognitiveProjectionFamily::Search => self.project_search(lease, state).await,
            CognitiveProjectionFamily::Cue => self.project_cues(lease, state).await,
            CognitiveProjectionFamily::DependencyDirty => {
                self.project_dependencies(lease, state).await
            }
            CognitiveProjectionFamily::Utility => Err(StoreError::PolicyViolation(
                "utility projection cannot be applied before Phase 2".to_owned(),
            )
            .into()),
        }
    }

    async fn project_search(
        &mut self,
        lease: &CognitiveProjectionLease,
        state: Option<&CognitiveProjectionFamilyState>,
    ) -> Result<(), EngineError> {
        if family_published_through(state, lease.through_revision) {
            return Ok(());
        }
        if let Some(deltas) = self.contiguous_search_deltas(lease, state) {
            let mut applied = None;
            for delta in deltas {
                applied = Some(
                    self.store
                        .apply_memory_search_projection_for_envelope(
                            &delta.envelope,
                            &delta.receipt,
                        )
                        .await?,
                );
            }
            if applied == Some(lease.through_revision) {
                self.store
                    .publish_cognitive_projection_family_state(
                        lease.project_id,
                        CognitiveProjectionFamily::Search,
                        lease.through_revision,
                        applied,
                        CognitiveProjectionPublicationStatus::Published,
                        None,
                    )
                    .await?;
                return Ok(());
            }
        }
        self.metrics
            .inner
            .cold_rebuilds
            .fetch_add(1, Ordering::Relaxed);
        let built_revision = self
            .store
            .rebuild_memory_search_projection(lease.project_id)
            .await?;
        if built_revision < lease.through_revision {
            return Err(coordinator_unavailable(
                "search rebuild completed behind the claimed revision",
            ));
        }
        Ok(())
    }

    fn contiguous_search_deltas(
        &self,
        lease: &CognitiveProjectionLease,
        state: Option<&CognitiveProjectionFamilyState>,
    ) -> Option<Vec<CommittedDelta>> {
        let mut expected = state?.applied_revision?.value().checked_add(1)?;
        let mut deltas = lease
            .write_ids
            .iter()
            .map(|write_id| self.committed.get(write_id).cloned())
            .collect::<Option<Vec<_>>>()?;
        deltas.sort_by_key(|delta| delta.receipt.memory_revision);
        for delta in &deltas {
            let revision = delta.receipt.memory_revision?;
            if revision.value() != expected {
                return None;
            }
            expected = expected.checked_add(1)?;
        }
        (deltas.last()?.receipt.memory_revision == Some(lease.through_revision)).then_some(deltas)
    }

    async fn project_cues(
        &mut self,
        lease: &CognitiveProjectionLease,
        state: Option<&CognitiveProjectionFamilyState>,
    ) -> Result<(), EngineError> {
        if family_published_through(state, lease.through_revision) {
            let revision = state
                .and_then(|state| state.applied_revision)
                .ok_or_else(|| {
                    coordinator_unavailable("published cue state omitted its applied revision")
                })?;
            let cached = self.cue_index.snapshot(lease.project_id)?;
            if !self.warmed_cues.contains(&lease.project_id) || cached.revision() != Some(revision)
            {
                self.cue_index
                    .load_persisted_projection_at(lease.project_id, revision)
                    .await?;
                self.warmed_cues.insert(lease.project_id);
            }
            return Ok(());
        }
        self.store
            .publish_cognitive_projection_family_state(
                lease.project_id,
                CognitiveProjectionFamily::Cue,
                lease.through_revision,
                state.and_then(|state| state.applied_revision),
                CognitiveProjectionPublicationStatus::Stale,
                None,
            )
            .await?;
        self.metrics
            .inner
            .cold_rebuilds
            .fetch_add(1, Ordering::Relaxed);
        let staged = self.cue_index.stage_rebuild(lease.project_id).await?;
        let revision = staged.revision();
        self.store
            .publish_cognitive_projection_family_state(
                lease.project_id,
                CognitiveProjectionFamily::Cue,
                revision,
                Some(revision),
                CognitiveProjectionPublicationStatus::Published,
                None,
            )
            .await?;
        let installed_revision = self.cue_index.install_staged(staged)?;
        if installed_revision != revision {
            return Err(coordinator_unavailable(
                "cue installation revision differed from its durable publication",
            ));
        }
        self.warmed_cues.insert(lease.project_id);
        Ok(())
    }

    async fn project_dependencies(
        &mut self,
        lease: &CognitiveProjectionLease,
        state: Option<&CognitiveProjectionFamilyState>,
    ) -> Result<(), EngineError> {
        let dirty_write_ids = lease
            .write_ids
            .iter()
            .filter(|write_id| write_id.starts_with("dependency-dirty:"))
            .collect::<Vec<_>>();
        if dirty_write_ids.is_empty() && family_published_through(state, lease.through_revision) {
            return Ok(());
        }
        let may_apply_live_dirty = state.is_some_and(|state| {
            state.target_revision >= lease.through_revision
                && state
                    .applied_revision
                    .is_some_and(|revision| revision >= lease.through_revision)
                && state.status != CognitiveProjectionPublicationStatus::Blocked
                && state.status != CognitiveProjectionPublicationStatus::Unavailable
        });
        if may_apply_live_dirty && !dirty_write_ids.is_empty() {
            let live_deltas = dirty_write_ids
                .iter()
                .map(|write_id| {
                    self.dirty
                        .get(write_id.as_str())
                        .cloned()
                        .map(|delta| ((*write_id).clone(), delta))
                })
                .collect::<Option<Vec<_>>>();
            if let Some(deltas) = live_deltas {
                for (event_id, delta) in deltas {
                    if delta.project_id != lease.project_id
                        || delta.revision != lease.through_revision
                    {
                        return self.cold_rebuild_dependencies(lease, state).await;
                    }
                    self.dependency
                        .mark_paths_dirty(delta.project_id, &delta.paths, &event_id)
                        .await?;
                }
                return Ok(());
            }
            return self.cold_rebuild_dependencies(lease, state).await;
        }
        self.cold_rebuild_dependencies(lease, state).await
    }

    async fn cold_rebuild_dependencies(
        &mut self,
        lease: &CognitiveProjectionLease,
        state: Option<&CognitiveProjectionFamilyState>,
    ) -> Result<(), EngineError> {
        self.metrics
            .inner
            .cold_rebuilds
            .fetch_add(1, Ordering::Relaxed);
        for _attempt in 0..3 {
            let revision = current_revision(&self.store, lease.project_id).await?;
            self.store
                .publish_cognitive_projection_family_state(
                    lease.project_id,
                    CognitiveProjectionFamily::DependencyDirty,
                    revision,
                    state.and_then(|state| state.applied_revision),
                    CognitiveProjectionPublicationStatus::Stale,
                    None,
                )
                .await?;
            self.store
                .reset_ul_reverse_dependency_project(lease.project_id)
                .await?;
            self.store
                .reset_ul_artifact_dirty_project(lease.project_id)
                .await?;
            self.dependency.rebuild_index(lease.project_id).await?;
            self.dependency.scan_project(lease.project_id).await?;
            let completed_revision = current_revision(&self.store, lease.project_id).await?;
            if completed_revision == revision {
                self.store
                    .publish_cognitive_projection_family_state(
                        lease.project_id,
                        CognitiveProjectionFamily::DependencyDirty,
                        revision,
                        Some(revision),
                        CognitiveProjectionPublicationStatus::Published,
                        None,
                    )
                    .await?;
                return Ok(());
            }
        }
        Err(coordinator_unavailable(
            "dependency projection revision changed during three cold rebuild attempts",
        ))
    }

    /// Builds and admission-checks one immutable candidate while the lease is
    /// still fail-able. Visibility is deferred until lease completion makes
    /// every required durable family Published.
    async fn stage_understanding_snapshot(
        &self,
        lease: &CognitiveProjectionLease,
    ) -> Result<Option<StagedUnderstandingSnapshot>, EngineError> {
        let allow_dependency_stale = lease
            .write_ids
            .iter()
            .any(|write_id| write_id.starts_with("dependency-dirty:"));
        for _attempt in 0..MAX_SNAPSHOT_FENCE_ATTEMPTS {
            let start_revision = current_revision(&self.store, lease.project_id).await?;
            if start_revision < lease.through_revision {
                return Err(coordinator_unavailable(
                    "canonical head is behind the claimed snapshot revision",
                ));
            }
            if start_revision > lease.through_revision {
                // A newer durable outbox row owns publication at the advanced
                // head. Completing this superseded lease avoids pinning the
                // project while the old revision can no longer be fenced.
                return Ok(None);
            }
            let states = self
                .store
                .cognitive_projection_family_states(lease.project_id)
                .await?;
            if let Err(error) =
                require_snapshot_families_ready(&states, start_revision, allow_dependency_stale)
            {
                let dependency_only = lease
                    .families
                    .iter()
                    .all(|family| *family == CognitiveProjectionFamily::DependencyDirty);
                if dependency_only
                    && self
                        .understanding
                        .project_snapshot(lease.project_id)?
                        .is_none()
                {
                    // A derived-only event may precede the first canonical
                    // project snapshot. It must not fabricate Search/Cue
                    // publication or block its own durable lease.
                    return Ok(None);
                }
                return Err(error);
            }

            let cue_projection = self.cue_index.snapshot(lease.project_id)?;
            if cue_projection.revision() != Some(start_revision)
                || cue_projection.projection_state() != CognitiveProjectionReadState::Published
            {
                return Err(coordinator_unavailable(
                    "published cue shard does not match the canonical snapshot fence",
                ));
            }

            let material = Box::pin(self.load_snapshot_material(lease.project_id)).await?;
            let dependency_refs = dirty_dependency_refs(&material.dirty);
            let reverse_dependencies = if dependency_refs.is_empty() {
                Vec::new()
            } else {
                self.store
                    .load_ul_reverse_dependents(lease.project_id, &dependency_refs)
                    .await?
            };

            let end_states = self
                .store
                .cognitive_projection_family_states(lease.project_id)
                .await?;
            let end_revision = current_revision(&self.store, lease.project_id).await?;
            if end_revision != start_revision
                || !snapshot_family_fence_matches(
                    &states,
                    &end_states,
                    start_revision,
                    allow_dependency_stale,
                )
            {
                continue;
            }

            let project_root = self.project_root.clone();
            let project_id = lease.project_id;
            let snapshot = tokio::task::spawn_blocking(move || {
                Self::build_understanding_snapshot(
                    &project_root,
                    project_id,
                    start_revision,
                    &end_states,
                    allow_dependency_stale,
                    cue_projection,
                    material,
                    &reverse_dependencies,
                )
            })
            .await
            .map_err(|error| {
                coordinator_unavailable(&format!(
                    "understanding snapshot builder task failed: {error}"
                ))
            })??;
            return Ok(Some(StagedUnderstandingSnapshot {
                revision: start_revision,
                snapshot,
            }));
        }
        Err(coordinator_unavailable(
            "canonical revision changed during four understanding snapshot attempts",
        ))
    }

    async fn finalize_understanding_snapshot(
        &self,
        staged: StagedUnderstandingSnapshot,
    ) -> Result<bool, EngineError> {
        let states = self
            .store
            .cognitive_projection_family_states(staged.snapshot.project_id())
            .await?;
        let revision = current_revision(&self.store, staged.snapshot.project_id()).await?;
        if revision != staged.revision
            || require_snapshot_families_published(&states, staged.revision).is_err()
        {
            return Ok(false);
        }
        let cue_projection = self.cue_index.snapshot(staged.snapshot.project_id())?;
        if cue_projection.revision() != Some(staged.revision)
            || cue_projection.projection_state() != CognitiveProjectionReadState::Published
        {
            return Ok(false);
        }
        if self
            .understanding
            .project_snapshot(staged.snapshot.project_id())?
            .is_some_and(|current| {
                current.revisions() == staged.snapshot.revisions()
                    && current.health() == staged.snapshot.health()
                    && current.health().cue.state == CognitiveProjectionReadState::Published
                    && current.health().pyramid.state == CognitiveProjectionReadState::Published
                    && current.health().activation.state == CognitiveProjectionReadState::Published
                    && current.health().dependency.state == CognitiveProjectionReadState::Published
            })
        {
            self.cue_index
                .release_strong_owner(staged.snapshot.project_id())?;
            return Ok(true);
        }
        self.understanding.install_project(staged.snapshot)?;
        self.cue_index
            .release_strong_owner(cue_projection.project_id())?;

        // Close the install race. Notifications synchronously stale a later
        // commit/dirty intent, while this recheck covers a change that landed
        // between the pre-install proof and the Arc swap.
        let post_states = self
            .store
            .cognitive_projection_family_states(cue_projection.project_id())
            .await?;
        let post_revision = current_revision(&self.store, cue_projection.project_id()).await?;
        if post_revision != staged.revision
            || !snapshot_family_fence_matches(&states, &post_states, staged.revision, false)
        {
            mark_understanding_stale(
                &self.understanding,
                cue_projection.project_id(),
                post_revision,
                "projection family changed during snapshot installation",
            );
        }
        Ok(true)
    }

    async fn load_snapshot_material(
        &self,
        project_id: ProjectId,
    ) -> Result<SnapshotMaterial, EngineError> {
        let (records, charters, maps, concepts, capsules, cards, hotspots, activation_graph, dirty) =
            tokio::try_join!(
                self.store.load_cue_records(project_id),
                self.store.load_ul_artifacts::<ProjectCharter>(
                    project_id,
                    &["project_charter"],
                    SNAPSHOT_CHARTER_MAP_PAGE_SIZE,
                ),
                self.store.load_ul_artifacts::<SystemMap>(
                    project_id,
                    &["system_map"],
                    SNAPSHOT_CHARTER_MAP_PAGE_SIZE,
                ),
                self.store.load_ul_artifacts::<ConceptNode>(
                    project_id,
                    &["concept_node"],
                    SNAPSHOT_CONCEPT_CAPSULE_PAGE_SIZE,
                ),
                self.store.load_ul_artifacts::<SubsystemCapsule>(
                    project_id,
                    &["subsystem_capsule"],
                    SNAPSHOT_CONCEPT_CAPSULE_PAGE_SIZE,
                ),
                self.store.load_ul_artifacts::<ModuleCard>(
                    project_id,
                    &["module_card"],
                    SNAPSHOT_CARD_HOTSPOT_PAGE_SIZE,
                ),
                self.store.load_ul_artifacts::<HotspotScore>(
                    project_id,
                    &["hotspot_score"],
                    SNAPSHOT_CARD_HOTSPOT_PAGE_SIZE,
                ),
                self.store.load_ul_activation_graph(project_id),
                self.store
                    .load_ul_dirty_artifacts(project_id, SNAPSHOT_DIRTY_LIMIT),
            )?;
        Ok(SnapshotMaterial {
            records,
            charters,
            maps,
            concepts,
            capsules,
            cards,
            hotspots,
            activation_graph,
            dirty,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn build_understanding_snapshot(
        project_root: &Path,
        project_id: ProjectId,
        revision: MemoryRevision,
        states: &[CognitiveProjectionFamilyState],
        allow_dependency_stale: bool,
        cue_projection: crate::CueIndexSnapshot,
        material: SnapshotMaterial,
        reverse_dependencies: &[UlReverseDependencyRow],
    ) -> Result<ProjectSnapshot, EngineError> {
        let charter = latest_artifact(material.charters, |artifact| {
            artifact.project_id.to_string()
        });
        let system_map = latest_artifact(material.maps, |artifact| artifact.project_id.to_string());
        let concepts = latest_artifacts(material.concepts, |artifact| artifact.concept_id.clone())
            .into_values()
            .collect::<Vec<_>>();
        let capsules = latest_artifacts(material.capsules, |artifact| artifact.concept_id.clone())
            .into_values()
            .collect::<Vec<_>>();
        let cards = latest_artifacts(material.cards, |artifact| artifact.card_id.clone())
            .into_values()
            .collect::<Vec<_>>();
        let hotspots = latest_artifacts(material.hotspots, |artifact| artifact.hotspot_id.clone())
            .into_values()
            .collect::<Vec<_>>();
        let target_handles =
            artifact_target_handles(charter.as_ref(), system_map.as_ref(), &capsules, &cards);
        let dirty_targets = material
            .dirty
            .iter()
            .filter(|state| state.dirty)
            .map(|state| ((state.target_kind, state.target_id.clone()), state))
            .collect::<BTreeMap<_, _>>();
        let fresh_capsules = capsules
            .iter()
            .cloned()
            .map(|mut artifact| {
                let dirty = dirty_targets
                    .get(&(
                        PyramidTargetKind::SubsystemCapsule,
                        artifact.concept_id.clone(),
                    ))
                    .filter(|state| state.build_id == artifact.build_id)
                    .copied();
                let freshness =
                    artifact_freshness(&artifact.dependency_manifest, project_root, dirty);
                artifact.body_md = render_capsule_with_dirty(&artifact, project_root, dirty);
                FreshArtifact {
                    artifact,
                    freshness,
                }
            })
            .collect::<Vec<_>>();
        let fresh_cards = cards
            .iter()
            .cloned()
            .map(|artifact| FreshArtifact {
                freshness: artifact_freshness(
                    &artifact.dependency_manifest,
                    project_root,
                    dirty_targets
                        .get(&(PyramidTargetKind::ModuleCard, artifact.path.clone()))
                        .filter(|state| state.build_id == artifact.build_fingerprint)
                        .copied(),
                ),
                artifact,
            })
            .collect::<Vec<_>>();
        let metacognition = MetacognitionService::evaluate(
            project_root,
            &concepts,
            &capsules,
            &cards,
            &hotspots,
            &material.records,
            &[],
        );
        ProjectSnapshotBuilder::default().build(ProjectSnapshotInput {
            project_id,
            revisions: ProjectRevisions {
                canonical: Some(revision),
                cue: Some(revision),
                pyramid: Some(revision),
                activation: Some(revision),
                dependency: Some(revision),
            },
            health: snapshot_health(states, revision, allow_dependency_stale)?,
            cue_projection,
            records: material.records,
            charter,
            system_map,
            concepts,
            capsules: fresh_capsules,
            cards: fresh_cards,
            activation_projection: ActivationProjection::from_graph(&material.activation_graph),
            dirty: dirty_artifact_projection(&material.dirty, &target_handles),
            dependencies: dependency_projection(reverse_dependencies, &target_handles),
            metacognition,
        })
    }

    async fn persist_failure(
        &self,
        lease: &CognitiveProjectionLease,
        failed_family: Option<CognitiveProjectionFamily>,
        error: EngineError,
        states: &BTreeMap<CognitiveProjectionFamily, CognitiveProjectionFamilyState>,
    ) {
        let detail = error.to_string();
        let retryable = is_retryable_projection_error(&error)
            && lease.max_attempt_count < self.config.max_attempts.max(1);
        if retryable {
            let _ = self
                .store
                .fail_cognitive_projection_retryable(
                    lease,
                    &detail,
                    retry_delay_seconds(lease.max_attempt_count),
                )
                .await;
            self.metrics
                .inner
                .retryable_failures
                .fetch_add(1, Ordering::Relaxed);
        } else {
            let _ = self.store.block_cognitive_projection(lease, &detail).await;
            self.metrics
                .inner
                .blocked_failures
                .fetch_add(1, Ordering::Relaxed);
        }
        let publication_status = if retryable {
            CognitiveProjectionPublicationStatus::Stale
        } else {
            CognitiveProjectionPublicationStatus::Blocked
        };
        if let Some(family) = failed_family {
            let _ = self
                .store
                .publish_cognitive_projection_family_state(
                    lease.project_id,
                    family,
                    lease.through_revision,
                    states.get(&family).and_then(|state| state.applied_revision),
                    publication_status,
                    Some(&detail),
                )
                .await;
        }
    }
}

fn require_snapshot_families_published(
    states: &[CognitiveProjectionFamilyState],
    revision: MemoryRevision,
) -> Result<(), EngineError> {
    require_snapshot_families_ready(states, revision, false)
}

fn require_snapshot_families_ready(
    states: &[CognitiveProjectionFamilyState],
    revision: MemoryRevision,
    allow_dependency_stale: bool,
) -> Result<(), EngineError> {
    for family in [
        CognitiveProjectionFamily::Search,
        CognitiveProjectionFamily::Cue,
        CognitiveProjectionFamily::DependencyDirty,
    ] {
        let state = states.iter().find(|state| state.family == family);
        if !state.is_some_and(|state| {
            let acceptable_status = state.status == CognitiveProjectionPublicationStatus::Published
                || (allow_dependency_stale
                    && family == CognitiveProjectionFamily::DependencyDirty
                    && state.status == CognitiveProjectionPublicationStatus::Stale);
            acceptable_status
                && state.target_revision == revision
                && state.applied_revision == Some(revision)
        }) {
            return Err(coordinator_unavailable(&format!(
                "{family:?} is not durably published at snapshot revision {}",
                revision.value()
            )));
        }
    }
    Ok(())
}

fn snapshot_family_fence_matches(
    before: &[CognitiveProjectionFamilyState],
    after: &[CognitiveProjectionFamilyState],
    revision: MemoryRevision,
    allow_dependency_stale: bool,
) -> bool {
    if require_snapshot_families_ready(before, revision, allow_dependency_stale).is_err()
        || require_snapshot_families_ready(after, revision, allow_dependency_stale).is_err()
    {
        return false;
    }
    [
        CognitiveProjectionFamily::Search,
        CognitiveProjectionFamily::Cue,
        CognitiveProjectionFamily::DependencyDirty,
    ]
    .into_iter()
    .all(|family| {
        let before = before.iter().find(|state| state.family == family);
        let after = after.iter().find(|state| state.family == family);
        before == after
    })
}

fn snapshot_health(
    states: &[CognitiveProjectionFamilyState],
    revision: MemoryRevision,
    allow_dependency_stale: bool,
) -> Result<ProjectProjectionHealth, EngineError> {
    require_snapshot_families_ready(states, revision, allow_dependency_stale)?;
    let family_health = |family| {
        let state = states.iter().find(|state| state.family == family);
        ProjectionFamilyHealth {
            state: state.map_or(CognitiveProjectionReadState::Unavailable, |state| {
                publication_read_state(state.status)
            }),
            revision: state.and_then(|state| state.applied_revision),
            detail: state.and_then(|state| state.last_error.clone()),
        }
    };
    Ok(ProjectProjectionHealth {
        cue: family_health(CognitiveProjectionFamily::Cue),
        pyramid: ProjectionFamilyHealth {
            state: CognitiveProjectionReadState::Published,
            revision: Some(revision),
            detail: None,
        },
        activation: ProjectionFamilyHealth {
            state: CognitiveProjectionReadState::Published,
            revision: Some(revision),
            detail: None,
        },
        dependency: if allow_dependency_stale {
            ProjectionFamilyHealth {
                state: CognitiveProjectionReadState::Published,
                revision: Some(revision),
                detail: None,
            }
        } else {
            family_health(CognitiveProjectionFamily::DependencyDirty)
        },
    })
}

const fn publication_read_state(
    status: CognitiveProjectionPublicationStatus,
) -> CognitiveProjectionReadState {
    match status {
        CognitiveProjectionPublicationStatus::Published => CognitiveProjectionReadState::Published,
        CognitiveProjectionPublicationStatus::Stale => CognitiveProjectionReadState::Stale,
        CognitiveProjectionPublicationStatus::Blocked => CognitiveProjectionReadState::Blocked,
        CognitiveProjectionPublicationStatus::Unavailable => {
            CognitiveProjectionReadState::Unavailable
        }
    }
}

fn latest_artifact<T, F>(records: Vec<CanonicalRecord<T>>, key: F) -> Option<T>
where
    F: Fn(&T) -> String,
{
    latest_artifacts(records, key).into_values().next()
}

fn latest_artifacts<T, F>(records: Vec<CanonicalRecord<T>>, key: F) -> BTreeMap<String, T>
where
    F: Fn(&T) -> String,
{
    let mut selected = BTreeMap::<String, CanonicalRecord<T>>::new();
    for record in records {
        let identity = key(&record.receipt_body);
        let candidate_order = (
            record.memory_revision.map_or(0, MemoryRevision::value),
            record
                .project_sequence
                .map_or(0, eliot_types::ProjectSequence::value),
        );
        let replace = selected.get(&identity).is_none_or(|current| {
            candidate_order
                > (
                    current.memory_revision.map_or(0, MemoryRevision::value),
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

fn artifact_freshness(
    manifest: &DependencyManifest,
    fallback_project_root: &Path,
    dirty: Option<&UlArtifactDirtyState>,
) -> SnapshotFreshness {
    if dirty.is_some_and(|state| state.dirty) {
        return SnapshotFreshness::Stale;
    }
    let project_root = if manifest.project_root.trim().is_empty() {
        fallback_project_root.to_path_buf()
    } else {
        PathBuf::from(&manifest.project_root)
    };
    for dependency in &manifest.file_deps {
        let path = project_root.join(&dependency.path);
        if file_blake3(&path).as_deref() != Some(dependency.blake3.as_str()) {
            return SnapshotFreshness::Stale;
        }
    }
    SnapshotFreshness::Fresh
}

fn file_blake3(path: &Path) -> Option<String> {
    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            return Some(hasher.finalize().to_hex().to_string());
        }
        hasher.update(&buffer[..read]);
    }
}

fn dirty_dependency_refs(states: &[UlArtifactDirtyState]) -> Vec<UlDependencyRef> {
    let mut refs = states
        .iter()
        .flat_map(|state| state.reasons.iter().map(|reason| reason.dependency.clone()))
        .collect::<Vec<_>>();
    refs.sort();
    refs.dedup();
    refs
}

fn artifact_target_handles(
    charter: Option<&ProjectCharter>,
    system_map: Option<&SystemMap>,
    capsules: &[SubsystemCapsule],
    cards: &[ModuleCard],
) -> BTreeMap<(PyramidTargetKind, String), String> {
    let mut handles = BTreeMap::new();
    if let Some(charter) = charter {
        handles.insert(
            (
                PyramidTargetKind::ProjectCharter,
                charter.project_id.to_string(),
            ),
            format!("charter:{}", charter.charter_id),
        );
    }
    if let Some(system_map) = system_map {
        handles.insert(
            (
                PyramidTargetKind::SystemMap,
                system_map.project_id.to_string(),
            ),
            format!("system-map:{}", system_map.map_id),
        );
    }
    handles.extend(capsules.iter().map(|capsule| {
        (
            (
                PyramidTargetKind::SubsystemCapsule,
                capsule.concept_id.clone(),
            ),
            format!("capsule:{}", capsule.capsule_id),
        )
    }));
    handles.extend(cards.iter().map(|card| {
        (
            (PyramidTargetKind::ModuleCard, card.path.clone()),
            format!("card:{}", card.card_id),
        )
    }));
    handles
}

fn dirty_artifact_projection(
    states: &[UlArtifactDirtyState],
    target_handles: &BTreeMap<(PyramidTargetKind, String), String>,
) -> Vec<DirtyArtifactProjection> {
    let mut projection = states
        .iter()
        .filter(|state| state.dirty)
        .map(|state| {
            let mut changed_dependencies = state
                .reasons
                .iter()
                .map(|reason| dependency_ref(&reason.dependency))
                .collect::<Vec<_>>();
            changed_dependencies.sort();
            changed_dependencies.dedup();
            DirtyArtifactProjection {
                artifact_ref: target_handles
                    .get(&(state.target_kind, state.target_id.clone()))
                    .cloned()
                    .unwrap_or_else(|| pyramid_artifact_ref(state.target_kind, &state.target_id)),
                changed_dependencies,
            }
        })
        .collect::<Vec<_>>();
    projection.sort_by(|left, right| left.artifact_ref.cmp(&right.artifact_ref));
    projection.dedup_by(|left, right| left.artifact_ref == right.artifact_ref);
    projection
}

fn dependency_projection(
    rows: &[UlReverseDependencyRow],
    target_handles: &BTreeMap<(PyramidTargetKind, String), String>,
) -> Vec<DependencyProjection> {
    let mut by_dependency = BTreeMap::<String, Vec<String>>::new();
    for row in rows {
        by_dependency
            .entry(dependency_ref(&row.dependency))
            .or_default()
            .push(
                target_handles
                    .get(&(row.target_kind, row.target_id.clone()))
                    .cloned()
                    .unwrap_or_else(|| pyramid_artifact_ref(row.target_kind, &row.target_id)),
            );
    }
    by_dependency
        .into_iter()
        .map(|(dependency_ref, mut dependent_artifact_refs)| {
            dependent_artifact_refs.sort();
            dependent_artifact_refs.dedup();
            DependencyProjection {
                dependency_ref,
                dependent_artifact_refs,
            }
        })
        .collect()
}

fn dependency_ref(dependency: &UlDependencyRef) -> String {
    let kind = match dependency.kind {
        UlDependencyKind::File => "file",
        UlDependencyKind::Claim => "claim",
        UlDependencyKind::Decision => "decision",
        UlDependencyKind::Edge => "edge",
        UlDependencyKind::Report => "report",
    };
    format!("{kind}:{}", dependency.key)
}

fn pyramid_artifact_ref(kind: PyramidTargetKind, target_id: &str) -> String {
    let prefix = match kind {
        PyramidTargetKind::ModuleCard => "card",
        PyramidTargetKind::SubsystemCapsule => "capsule",
        PyramidTargetKind::SystemMap => "system-map",
        PyramidTargetKind::ProjectCharter => "charter",
    };
    format!("{prefix}:{target_id}")
}

fn mark_understanding_stale(
    understanding: &UnderstandingRuntime,
    project_id: ProjectId,
    revision: MemoryRevision,
    detail: &str,
) {
    let _ = understanding.mark_project_stale_all(project_id, revision, Some(detail));
}

#[derive(Clone)]
struct CommittedDelta {
    envelope: MemoryWriteEnvelope,
    receipt: WriteReceipt,
}

#[derive(Clone)]
struct DirtyDelta {
    project_id: ProjectId,
    revision: MemoryRevision,
    paths: Vec<String>,
}

enum ProjectionCommand {
    CanonicalCommitted {
        envelope: Box<MemoryWriteEnvelope>,
        receipt: WriteReceipt,
    },
    DependencyDirty {
        event_id: String,
        project_id: ProjectId,
        revision: MemoryRevision,
        paths: Vec<String>,
    },
    Recover {
        reply: oneshot::Sender<Result<(), String>>,
    },
    Wake,
}

enum BackgroundStep {
    Progress,
    Waiting,
    Dormant,
}

fn family_published_through(
    state: Option<&CognitiveProjectionFamilyState>,
    revision: MemoryRevision,
) -> bool {
    state.is_some_and(|state| {
        state.status == CognitiveProjectionPublicationStatus::Published
            && state.target_revision >= revision
            && state
                .applied_revision
                .is_some_and(|applied| applied >= revision)
    })
}

async fn current_revision(
    store: &CanonicalStore,
    project_id: ProjectId,
) -> Result<MemoryRevision, EngineError> {
    Ok(store
        .current_state(&CurrentStateRequest {
            project_id,
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
        })
        .await?
        .memory_revision)
}

fn dependency_event_id(
    project_id: ProjectId,
    revision: MemoryRevision,
    event_ref: &str,
    paths: &[String],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(project_id.to_string().as_bytes());
    hasher.update(&revision.value().to_le_bytes());
    hasher.update(event_ref.as_bytes());
    for path in paths {
        hasher.update(&[0]);
        hasher.update(path.as_bytes());
    }
    format!("dependency-dirty:{}", hasher.finalize().to_hex())
}

fn recovery_event_id(project_id: ProjectId, revision: MemoryRevision) -> String {
    format!("recovery:{project_id}:{}", revision.value())
}

const fn invalidates_understanding_snapshot(status: WriteStatus) -> bool {
    matches!(status, WriteStatus::Committed)
}

fn projection_intent_needs_wake(status: &str) -> bool {
    matches!(status, "pending" | "retryable" | "leased")
}

fn coordinator_unavailable(reason: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: "cognitive_projection".to_owned(),
        reason: reason.to_owned(),
    }
}

fn is_retryable_projection_error(error: &EngineError) -> bool {
    match error {
        EngineError::Store(
            StoreError::ConnectionClosed
            | StoreError::Timeout { .. }
            | StoreError::WebSocket(_)
            | StoreError::ClientSetShuttingDown,
        ) => true,
        EngineError::ServiceNotReady { service, .. } => {
            service == "cognitive_projection" || service == "cue_index"
        }
        _ => false,
    }
}

fn retry_delay_seconds(attempt_count: u32) -> u64 {
    1_u64
        .checked_shl(attempt_count.saturating_sub(1).min(6))
        .unwrap_or(60)
        .min(60)
}

fn cap_cache<T>(cache: &mut HashMap<String, T>) {
    if cache.len() >= MAX_DELTA_CACHE_ENTRIES {
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CognitiveProjectionCoordinator, CognitiveProjectionCoordinatorConfig,
        CognitiveProjectionPublicationStatus, ProjectionCommand, dependency_event_id,
        invalidates_understanding_snapshot, projection_intent_needs_wake, recovery_event_id,
        require_snapshot_families_published, require_snapshot_families_ready, retry_delay_seconds,
        snapshot_family_fence_matches,
    };
    use crate::{
        CueIndexService, DeliveredFingerprint, InjectionSelectionPolicy, UlDependencyService,
        UnderstandingRuntime, UnderstandingRuntimeConfig, WriteAdmissionService, WriterActor,
        WriterConfig, WriterShutdownHandle,
    };
    use eliot_store::{CanonicalStore, ControlWal, DbClientSet};
    use eliot_types::{
        AgentId, ClaimCardInput, ClaimId, CognitiveProjectionReadState, CommandContext,
        ControlWalConfig, CredentialProviderKind, CueBinding, CueKind, CueMatchMode, CueStrength,
        EpistemicStatus, FailureRecordCommand, GovernorConfig, IdempotencyOptions, LifecycleStatus,
        LifecycleWriteOptions, MemoryRevision, MemoryWriteEnvelope, ModuleCard, ObservedCue,
        OperationId, ProjectId, ReadConsistencyMode, RecallL0Request, RelationInput, RelationType,
        SemanticCommand, SemanticCommandKind, SessionId, SurrealServerConfig, TaintClass, TaskId,
        UlArtifact, UlArtifactBatchRecordCommand, UlInjectionMode, Visibility, WriteId,
        WriteStatus,
    };
    use serde_json::{Value, json};
    use std::error::Error;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use time::OffsetDateTime;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, Instant};

    type TestResult<T = ()> = Result<T, Box<dyn Error>>;

    #[test]
    fn retry_delay_is_bounded_exponential() {
        assert_eq!(retry_delay_seconds(1), 1);
        assert_eq!(retry_delay_seconds(2), 2);
        assert_eq!(retry_delay_seconds(5), 16);
        assert_eq!(retry_delay_seconds(99), 60);
    }

    #[test]
    fn dependency_event_id_is_revision_and_path_bound() {
        let project_id = ProjectId::new_v7();
        let first = dependency_event_id(
            project_id,
            MemoryRevision::new(4),
            "tool:edit",
            &["src/lib.rs".to_owned()],
        );
        let same = dependency_event_id(
            project_id,
            MemoryRevision::new(4),
            "tool:edit",
            &["src/lib.rs".to_owned()],
        );
        let changed = dependency_event_id(
            project_id,
            MemoryRevision::new(5),
            "tool:edit",
            &["src/lib.rs".to_owned()],
        );
        assert_eq!(first, same);
        assert_ne!(first, changed);
    }

    #[test]
    fn recovery_event_id_is_project_scoped_at_the_same_revision() {
        // This pure-Rust check cannot detect JSON transport coercion; the live
        // store regression proves exact round-tripping for these identifiers.
        let revision = MemoryRevision::new(9);
        assert_ne!(
            recovery_event_id(ProjectId::new_v7(), revision),
            recovery_event_id(ProjectId::new_v7(), revision)
        );
    }

    #[test]
    fn idempotent_replay_does_not_invalidate_understanding_snapshot() {
        assert!(invalidates_understanding_snapshot(WriteStatus::Committed));
        assert!(!invalidates_understanding_snapshot(
            WriteStatus::IdempotentReplay
        ));
    }

    #[test]
    fn applied_dependency_intent_does_not_reinvalidate_understanding_snapshot() {
        assert!(projection_intent_needs_wake("pending"));
        assert!(projection_intent_needs_wake("retryable"));
        assert!(projection_intent_needs_wake("leased"));
        assert!(!projection_intent_needs_wake("applied"));
        assert!(!projection_intent_needs_wake("blocked"));
    }

    #[test]
    fn same_head_dependency_snapshot_waits_for_lease_completion() {
        let project_id = ProjectId::new_v7();
        let revision = MemoryRevision::new(7);
        let now = OffsetDateTime::now_utc();
        let mut states = [
            super::CognitiveProjectionFamily::Search,
            super::CognitiveProjectionFamily::Cue,
            super::CognitiveProjectionFamily::DependencyDirty,
        ]
        .into_iter()
        .map(|family| super::CognitiveProjectionFamilyState {
            project_id,
            family,
            target_revision: revision,
            applied_revision: Some(revision),
            status: CognitiveProjectionPublicationStatus::Published,
            last_error: None,
            updated_at: now,
        })
        .collect::<Vec<_>>();
        states[2].status = CognitiveProjectionPublicationStatus::Stale;

        assert!(require_snapshot_families_ready(&states, revision, true).is_ok());
        assert!(require_snapshot_families_published(&states, revision).is_err());

        let mut completed = states.clone();
        completed[2].status = CognitiveProjectionPublicationStatus::Published;
        assert!(require_snapshot_families_published(&completed, revision).is_ok());
        assert!(!snapshot_family_fence_matches(
            &states, &completed, revision, true
        ));
    }

    #[tokio::test]
    async fn recovery_acknowledges_without_a_store_round_trip() -> TestResult {
        let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
        let cue_index = Arc::new(CueIndexService::new(store.clone()));
        let dependency = Arc::new(UlDependencyService::new(store.clone()));
        let understanding = Arc::new(UnderstandingRuntime::default());
        let (_handle, mut coordinator, _shutdown) = CognitiveProjectionCoordinator::channel(
            store,
            cue_index,
            dependency,
            understanding,
            PathBuf::new(),
            CognitiveProjectionCoordinatorConfig::default(),
        );
        let (reply, response) = tokio::sync::oneshot::channel();
        let mut armed = false;

        coordinator.cache_command(ProjectionCommand::Recover { reply }, Some(&mut armed));

        assert!(armed);
        assert_eq!(coordinator.recovery_cursor, Some(0));
        assert_eq!(response.await?, Ok(()));
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires scripts/run-isolated-tests.ps1 SurrealDB 3.1.4 guardian"]
    #[allow(clippy::too_many_lines)]
    async fn c7_03c_real_full_wake_queue_recovers_all_projection_families() -> TestResult {
        let config = isolated_config()?;
        require_exact_surreal_version(&config)?;
        let owned_root = isolated_owned_root(&config)?;
        let guardian_pid = read_pid(&owned_root.join("tmp").join("owned-surreal.pid"))?;
        require(
            eliot_windows_ipc::process_is_alive(guardian_pid)?,
            "isolated SurrealDB guardian is not alive",
        )?;

        let clients = Arc::new(DbClientSet::start(config).await?);
        let store = CanonicalStore::from_client_set(Arc::clone(&clients));
        store.migrate_schema().await?;
        let cue_index = Arc::new(CueIndexService::new(store.clone()));
        let dependency = Arc::new(UlDependencyService::new(store.clone()));
        let understanding = Arc::new(UnderstandingRuntime::new(UnderstandingRuntimeConfig {
            activation_enable_min_edges: u32::MAX,
            ..UnderstandingRuntimeConfig::default()
        }));
        let (projection, coordinator, projection_shutdown) =
            CognitiveProjectionCoordinator::channel(
                store.clone(),
                Arc::clone(&cue_index),
                dependency,
                Arc::clone(&understanding),
                owned_root.clone(),
                CognitiveProjectionCoordinatorConfig {
                    queue_capacity: 1,
                    lease_seconds: 60,
                    ..CognitiveProjectionCoordinatorConfig::default()
                },
            );
        let wal = ControlWal::open(&ControlWalConfig {
            path: owned_root
                .join("tmp")
                .join("c7-03c-control.redb")
                .display()
                .to_string(),
        })?;
        let (writer, writer_actor, writer_shutdown) = WriterActor::channel_with_projection_notifier(
            wal,
            store.clone(),
            &WriterConfig::default(),
            projection.clone(),
        );
        let mut writer_shutdown = Some(writer_shutdown);
        let mut projection_shutdown = Some(projection_shutdown);
        let mut writer_task = Some(tokio::spawn(writer_actor.run()));
        let mut coordinator = Some(coordinator);
        let mut projection_task = None;

        let body_result: TestResult = async {
            let unpublished_cue_project = ProjectId::new_v7();
            let staged_cues = cue_index.stage_rebuild(unpublished_cue_project).await?;
            let unpublished_firing = cue_index.fire(unpublished_cue_project, &[]).await?;
            require(
                unpublished_firing.projection_state == CognitiveProjectionReadState::Unavailable,
                "a staged cue shard became visible before durable publication",
            )?;
            drop(staged_cues);

            let project_id = ProjectId::new_v7();
            let first_claim = claim("coordinator missed wake recovery sentinel one");
            let second_claim = claim("coordinator missed wake recovery sentinel two");
            let expected_handle = format!("claim:{}", second_claim.claim_id);
            let first = writer
                .submit(retrieval_envelope(project_id, first_claim)?)
                .await?;
            let second = writer
                .submit(retrieval_envelope(project_id, second_claim)?)
                .await?;
            let same_head_project = ProjectId::new_v7();
            let same_head_first = writer
                .submit(retrieval_envelope(
                    same_head_project,
                    claim("same-head recovery project one"),
                )?)
                .await?;
            let same_head_second = writer
                .submit(retrieval_envelope(
                    same_head_project,
                    claim("same-head recovery project two"),
                )?)
                .await?;
            let expected_revision = second
                .memory_revision
                .ok_or("second committed receipt omitted its memory revision")?;
            require(
                first.status == WriteStatus::Committed
                    && second.status == WriteStatus::Committed
                    && same_head_first.status == WriteStatus::Committed
                    && same_head_second.status == WriteStatus::Committed,
                "a full projection wake queue changed canonical commit success",
            )?;
            require(
                same_head_second.memory_revision == Some(expected_revision),
                "two-project recovery fixture did not reach the same head revision",
            )?;
            require(
                projection.metrics().snapshot().dropped_wake_hints >= 1,
                "queue-capacity proof did not drop the second best-effort wake hint",
            )?;
            let before_backlog = store.cognitive_projection_backlog().await?;
            require(
                before_backlog.pending == 4,
                "durable outbox did not retain all committed writes before recovery",
            )?;
            let before = store
                .recall_l0(&recall_request(
                    project_id,
                    "coordinator missed wake recovery sentinel two",
                ))
                .await?;
            require(
                before.handles.is_empty()
                    && before.projection_state != CognitiveProjectionReadState::Published,
                "public L0 repaired or exposed an unpublished projection",
            )?;
            require(
                store.cognitive_projection_backlog().await?.pending == 4,
                "public L0 mutated the projection outbox",
            )?;
            require(
                understanding.project_snapshot(project_id)?.is_none(),
                "understanding snapshot became visible before durable family publication",
            )?;

            let coordinator = coordinator
                .take()
                .ok_or("projection coordinator was already started")?;
            projection_task = Some(tokio::spawn(coordinator.run()));
            projection.recover().await?;
            wait_for_empty_projection_backlog(&store).await?;

            let states = store.cognitive_projection_family_states(project_id).await?;
            for family in [
                super::CognitiveProjectionFamily::Search,
                super::CognitiveProjectionFamily::Cue,
                super::CognitiveProjectionFamily::DependencyDirty,
            ] {
                require(
                    states.iter().any(|state| {
                        state.family == family
                            && state.status == CognitiveProjectionPublicationStatus::Published
                            && state.applied_revision == Some(expected_revision)
                    }),
                    &format!("{family:?} did not publish the exact recovered head"),
                )?;
            }
            require(
                states.iter().any(|state| {
                    state.family == super::CognitiveProjectionFamily::Utility
                        && state.status == CognitiveProjectionPublicationStatus::Unavailable
                        && state.applied_revision.is_none()
                }),
                "utility projection was not kept explicitly unavailable",
            )?;
            let after = store
                .recall_l0(&recall_request(
                    project_id,
                    "coordinator missed wake recovery sentinel two",
                ))
                .await?;
            require(
                after.projection_state == CognitiveProjectionReadState::Published
                    && after
                        .handles
                        .iter()
                        .any(|handle| handle.handle == expected_handle),
                "recovered FTS projection did not serve the committed target",
            )?;
            let published_snapshot = understanding
                .project_snapshot(project_id)?
                .ok_or("understanding snapshot was unavailable after family publication")?;
            require(
                published_snapshot.revisions().canonical == Some(expected_revision)
                    && published_snapshot.revisions().cue == Some(expected_revision)
                    && published_snapshot.revisions().pyramid == Some(expected_revision)
                    && published_snapshot.revisions().activation == Some(expected_revision)
                    && published_snapshot.revisions().dependency == Some(expected_revision),
                "understanding snapshot did not preserve its exact canonical revision fence",
            )?;
            let metrics = projection.metrics().snapshot();
            require(
                metrics.completed_leases >= 1 && metrics.cold_rebuilds >= 3,
                "missed-wake recovery did not coalesce through the cold family rebuilds",
            )?;

            let injection_project_id = ProjectId::new_v7();
            let injection_session_id = SessionId::new_v7();
            let injection_path = "src/live/revision.rs";
            let failure_ref = "failure:c7-03c-live-revision";
            let card_id = "c7-03c-live-revision-card";
            let card_ref = format!("card:{card_id}");
            let admission = WriteAdmissionService;
            let first_failure_receipt = writer
                .submit(admission.admit(&live_failure_command(
                    injection_project_id,
                    injection_session_id,
                    injection_path,
                    1,
                ))?)
                .await?;
            let card_receipt = writer
                .submit(admission.admit(&live_module_card_command(
                    injection_project_id,
                    injection_session_id,
                    injection_path,
                    card_id,
                ))?)
                .await?;
            require(
                first_failure_receipt.status == WriteStatus::Committed
                    && card_receipt.status == WriteStatus::Committed,
                "revision-one failure/card ingress did not commit through the live writer",
            )?;
            let first_head = card_receipt
                .memory_revision
                .ok_or("revision-one card receipt omitted its memory revision")?;
            wait_for_cue_publication(&store, injection_project_id, first_head).await?;
            wait_for_understanding_snapshot(&understanding, injection_project_id, first_head)
                .await?;

            let observed_cues = [ObservedCue {
                kind: CueKind::FilePath,
                value: injection_path.to_owned(),
            }];
            let first_firing = cue_index.fire(injection_project_id, &observed_cues).await?;
            require(
                first_firing.projection_state == CognitiveProjectionReadState::Published
                    && first_firing
                        .projection_revision
                        .is_some_and(|revision| revision.value() >= first_head.value())
                    && first_firing
                        .fired
                        .iter()
                        .any(|item| item.record_ref == failure_ref)
                    && first_firing
                        .fired
                        .iter()
                        .any(|item| item.record_ref == card_ref),
                "published revision-one cue shard did not fire the failure/card pair",
            )?;
            let first_plan = understanding.plan_cues(
                injection_project_id,
                injection_session_id,
                None,
                &observed_cues,
            )?;
            understanding.enqueue_plan(injection_project_id, injection_session_id, &first_plan)?;
            let first_failure_position = first_plan
                .items
                .iter()
                .position(|item| item.item_ref == failure_ref)
                .ok_or("revision-one failure was not planned")?;
            let first_card_position = first_plan
                .items
                .iter()
                .position(|item| item.item_ref == card_ref)
                .ok_or("revision-one card was not planned")?;
            require(
                first_plan.items.len() == 2 && first_failure_position < first_card_position,
                "revision-one planner did not preserve danger-before-card ordering",
            )?;
            let first_failure_source = first_plan.items[first_failure_position]
                .source_fingerprint
                .clone();
            let first_card_source = first_plan.items[first_card_position]
                .source_fingerprint
                .clone();
            let first_selection = understanding.select_pending_with_policy(
                injection_project_id,
                injection_session_id,
                UlInjectionMode::Payload,
                InjectionSelectionPolicy {
                    max_items: 3,
                    max_token_units: 400,
                    max_negative_payloads: 3,
                },
            )?;
            let first_items = &first_selection.items;
            require(
                first_items.len() == 2
                    && first_items[0].item_ref == failure_ref
                    && first_items[1].item_ref == card_ref
                    && first_items[0]
                        .payload
                        .as_ref()
                        .and_then(|payload| payload.get("source_revision"))
                        .and_then(Value::as_u64)
                        == Some(1),
                "revision-one selection did not deliver the ordered failure/card payload",
            )?;
            understanding.acknowledge_delivered(
                injection_project_id,
                injection_session_id,
                &first_items
                    .iter()
                    .map(|item| DeliveredFingerprint {
                        item_ref: item.item_ref.clone(),
                        source_fingerprint: item.source_fingerprint.clone(),
                    })
                    .collect::<Vec<_>>(),
            )?;

            let second_failure_receipt = writer
                .submit(admission.admit(&live_failure_command(
                    injection_project_id,
                    injection_session_id,
                    injection_path,
                    2,
                ))?)
                .await?;
            require(
                second_failure_receipt.status == WriteStatus::Committed,
                "revision-two failure ingress did not commit through the live writer",
            )?;
            let second_head = second_failure_receipt
                .memory_revision
                .ok_or("revision-two failure receipt omitted its memory revision")?;
            wait_for_cue_publication(&store, injection_project_id, second_head).await?;
            wait_for_understanding_snapshot(&understanding, injection_project_id, second_head)
                .await?;
            let second_plan = understanding.plan_cues(
                injection_project_id,
                injection_session_id,
                None,
                &observed_cues,
            )?;
            understanding.enqueue_plan(injection_project_id, injection_session_id, &second_plan)?;
            let second_failure = second_plan
                .items
                .iter()
                .find(|item| item.item_ref == failure_ref)
                .ok_or("revision-two failure was not planned")?;
            let second_card = second_plan
                .items
                .iter()
                .find(|item| item.item_ref == card_ref)
                .ok_or("unchanged revision-two card was not planned")?;
            require(
                second_failure.source_fingerprint != first_failure_source
                    && second_card.source_fingerprint == first_card_source,
                "revision-two source fingerprints did not distinguish changed from unchanged",
            )?;
            let second_failure_source = second_failure.source_fingerprint.clone();
            let second_selection = understanding.select_pending_with_policy(
                injection_project_id,
                injection_session_id,
                UlInjectionMode::Payload,
                InjectionSelectionPolicy {
                    max_items: 3,
                    max_token_units: 400,
                    max_negative_payloads: 3,
                },
            )?;
            let second_items = &second_selection.items;
            require(
                second_items.len() == 1
                    && second_items[0].item_ref == failure_ref
                    && second_items[0]
                        .payload
                        .as_ref()
                        .and_then(|payload| payload.get("source_revision"))
                        .and_then(Value::as_u64)
                        == Some(2),
                "revision-two selection did not redeliver only the changed failure",
            )?;
            require(
                second_items.iter().any(|item| {
                    item.item_ref == failure_ref && item.source_fingerprint == second_failure_source
                }) && !second_items.iter().any(|item| item.item_ref == card_ref),
                "same-session ledger did not redeliver the changed failure and suppress the card",
            )?;

            let accepted_before_shutdown = writer.metrics().accepted_messages;
            let shutdown_writer = writer.clone();
            let shutdown_envelope = retrieval_envelope(
                project_id,
                claim("successful writer shutdown drain sentinel"),
            )?;
            let shutdown_submit =
                tokio::spawn(async move { shutdown_writer.submit(shutdown_envelope).await });
            wait_for_writer_accept(&writer, accepted_before_shutdown).await?;
            stop_writer(&mut writer_shutdown, &mut writer_task).await?;
            let shutdown_receipt = tokio::time::timeout(Duration::from_secs(10), shutdown_submit)
                .await
                .map_err(|_| "successful shutdown write response timed out")???;
            require(
                shutdown_receipt.status == WriteStatus::Committed,
                "accepted successful write did not commit while writer drained",
            )?;
            wait_for_empty_projection_backlog(&store).await?;
            let applied_recovery = store
                .enqueue_cognitive_projection_intent(
                    same_head_project,
                    &recovery_event_id(same_head_project, expected_revision),
                    expected_revision,
                    &[
                        super::CognitiveProjectionFamily::Search,
                        super::CognitiveProjectionFamily::Cue,
                        super::CognitiveProjectionFamily::DependencyDirty,
                    ],
                )
                .await?;
            require(
                applied_recovery.status == "applied",
                "cold restart fixture did not begin from an applied deterministic recovery row",
            )?;
            require(
                understanding
                    .project_snapshot(same_head_project)?
                    .is_some_and(|snapshot| snapshot.is_fully_published()),
                "first coordinator did not publish the cold restart fixture snapshot",
            )?;
            stop_projection(&mut projection_shutdown, &mut projection_task).await?;

            let cold_cue_index = Arc::new(CueIndexService::new(store.clone()));
            let cold_understanding =
                Arc::new(UnderstandingRuntime::new(UnderstandingRuntimeConfig {
                    activation_enable_min_edges: u32::MAX,
                    ..UnderstandingRuntimeConfig::default()
                }));
            let (cold_projection, cold_coordinator, cold_shutdown) =
                CognitiveProjectionCoordinator::channel(
                    store.clone(),
                    cold_cue_index,
                    Arc::new(UlDependencyService::new(store.clone())),
                    Arc::clone(&cold_understanding),
                    owned_root.clone(),
                    CognitiveProjectionCoordinatorConfig {
                        queue_capacity: 1,
                        lease_seconds: 60,
                        ..CognitiveProjectionCoordinatorConfig::default()
                    },
                );
            projection_shutdown = Some(cold_shutdown);
            projection_task = Some(tokio::spawn(cold_coordinator.run()));
            require(
                cold_understanding
                    .project_snapshot(same_head_project)?
                    .is_none(),
                "fresh process fixture unexpectedly retained an understanding snapshot",
            )?;
            cold_projection.recover().await?;
            wait_for_understanding_snapshot(
                &cold_understanding,
                same_head_project,
                expected_revision,
            )
            .await?;
            wait_for_empty_projection_backlog(&store).await?;
            stop_projection(&mut projection_shutdown, &mut projection_task).await?;
            // The writer handle intentionally remains alive across explicit
            // shutdown; the actor must still have joined before DB shutdown.
            let _retained_writer = &writer;
            Ok(())
        }
        .await;

        let writer_cleanup = stop_writer(&mut writer_shutdown, &mut writer_task).await;
        let projection_cleanup =
            stop_projection(&mut projection_shutdown, &mut projection_task).await;
        drop(coordinator.take());
        let database_cleanup = clients.shutdown().await;
        let guardian_alive = eliot_windows_ipc::process_is_alive(guardian_pid);
        combine_live_results(
            body_result,
            writer_cleanup,
            projection_cleanup,
            database_cleanup.map(|_| ()).map_err(Into::into),
            guardian_alive.map_err(Into::into),
        )
    }

    async fn wait_for_empty_projection_backlog(store: &CanonicalStore) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let backlog = store.cognitive_projection_backlog().await?;
            if backlog.pending == 0
                && backlog.leased == 0
                && backlog.retryable == 0
                && backlog.blocked == 0
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("projection backlog did not drain: {backlog:?}").into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_for_cue_publication(
        store: &CanonicalStore,
        project_id: ProjectId,
        expected_revision: MemoryRevision,
    ) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let states = store.cognitive_projection_family_states(project_id).await?;
            if states.iter().any(|state| {
                state.family == super::CognitiveProjectionFamily::Cue
                    && state.status == CognitiveProjectionPublicationStatus::Published
                    && state
                        .applied_revision
                        .is_some_and(|revision| revision.value() >= expected_revision.value())
            }) {
                return Ok(());
            }
            if let Some(blocked) = states.iter().find(|state| {
                state.family == super::CognitiveProjectionFamily::Cue
                    && state.status == CognitiveProjectionPublicationStatus::Blocked
            }) {
                return Err(format!(
                    "cue projection blocked before revision {}: {blocked:?}",
                    expected_revision.value()
                )
                .into());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "cue projection did not publish revision {}: {states:?}",
                    expected_revision.value()
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_for_understanding_snapshot(
        understanding: &UnderstandingRuntime,
        project_id: ProjectId,
        expected_revision: MemoryRevision,
    ) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            if understanding
                .project_snapshot(project_id)?
                .is_some_and(|snapshot| {
                    snapshot.revisions().canonical == Some(expected_revision)
                        && snapshot.health().cue.state == CognitiveProjectionReadState::Published
                        && snapshot.health().dependency.state
                            == CognitiveProjectionReadState::Published
                })
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "understanding snapshot did not publish revision {}",
                    expected_revision.value()
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn live_failure_command(
        project_id: ProjectId,
        session_id: SessionId,
        path: &str,
        source_revision: u64,
    ) -> SemanticCommand {
        SemanticCommand::FailureRecord(FailureRecordCommand {
            context: live_command_context(
                project_id,
                session_id,
                "c7-03c-live-test",
                TaintClass::LocalVerified,
            ),
            fingerprint: "c7-03c-live-revision".to_owned(),
            summary: format!("same-session failure revision {source_revision}"),
            payload: json!({
                "source_revision": source_revision,
                "cue_bindings": [CueBinding {
                    cue_kind: CueKind::FilePath,
                    cue_value: path.to_owned(),
                    match_mode: CueMatchMode::Exact,
                    strength: CueStrength::Primary,
                    expected_reuse_note: "reuse when editing the live revision fixture".to_owned(),
                }]
            }),
        })
    }

    fn live_module_card_command(
        project_id: ProjectId,
        session_id: SessionId,
        path: &str,
        card_id: &str,
    ) -> SemanticCommand {
        let card = ModuleCard {
            card_id: card_id.to_owned(),
            project_id,
            path: path.to_owned(),
            body_md: "PURPOSE: unchanged same-session live revision card".to_owned(),
            verifier: "c7-03c-coordinator-live".to_owned(),
            hotspot_ref: None,
            co_change_refs: Vec::new(),
            failure_refs: vec!["failure:c7-03c-live-revision".to_owned()],
            source_refs: vec![format!("file:{path}")],
            cue_bindings: vec![CueBinding {
                cue_kind: CueKind::FilePath,
                cue_value: path.to_owned(),
                match_mode: CueMatchMode::Exact,
                strength: CueStrength::Primary,
                expected_reuse_note: "reuse when editing the live revision fixture".to_owned(),
            }],
            build_fingerprint: "c7-03c-live-card-stable".to_owned(),
            dependency_manifest: eliot_types::DependencyManifest::default(),
        };
        SemanticCommand::UlArtifactBatchRecord(UlArtifactBatchRecordCommand {
            context: live_command_context(
                project_id,
                session_id,
                "local-ul-builder",
                TaintClass::LocalTool,
            ),
            relations: vec![RelationInput {
                relation_type: RelationType::CardCovers,
                from: format!("card:{card_id}"),
                to: format!("file:{path}"),
            }],
            artifacts: vec![UlArtifact::ModuleCard(card)],
        })
    }

    fn live_command_context(
        project_id: ProjectId,
        session_id: SessionId,
        authority: &str,
        taint: TaintClass,
    ) -> CommandContext {
        CommandContext {
            write_id: WriteId::new_v7(),
            agent_id: AgentId::from_uuid(session_id.as_uuid()),
            session_id: Some(session_id),
            project_id,
            task_id: None,
            scope: format!("project:{project_id}:c7-03c-live-revision"),
            authority: authority.to_owned(),
            visibility: Visibility::Project,
            taint,
            lifecycle_status: LifecycleStatus::Active,
        }
    }

    async fn wait_for_writer_accept(
        writer: &crate::WriterHandle,
        accepted_before: u64,
    ) -> TestResult {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if writer.metrics().accepted_messages > accepted_before {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err("writer did not accept the shutdown-drain write".into());
            }
            tokio::task::yield_now().await;
        }
    }

    async fn stop_writer(
        shutdown: &mut Option<WriterShutdownHandle>,
        task: &mut Option<JoinHandle<()>>,
    ) -> TestResult {
        if let Some(shutdown) = shutdown.take() {
            shutdown.shutdown();
        }
        if let Some(task) = task.take() {
            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .map_err(|_| "writer shutdown timed out")??;
        }
        Ok(())
    }

    async fn stop_projection(
        shutdown: &mut Option<super::CognitiveProjectionShutdownHandle>,
        task: &mut Option<JoinHandle<Result<(), crate::EngineError>>>,
    ) -> TestResult {
        if let Some(shutdown) = shutdown.take() {
            shutdown.shutdown();
        }
        if let Some(task) = task.take() {
            tokio::time::timeout(Duration::from_secs(10), task)
                .await
                .map_err(|_| "projection shutdown timed out")???;
        }
        Ok(())
    }

    fn combine_live_results(
        body: TestResult,
        writer_cleanup: TestResult,
        projection_cleanup: TestResult,
        database_cleanup: TestResult,
        guardian_alive: Result<bool, Box<dyn Error>>,
    ) -> TestResult {
        let mut failures = Vec::new();
        for result in [body, writer_cleanup, projection_cleanup, database_cleanup] {
            if let Err(error) = result {
                failures.push(error.to_string());
            }
        }
        match guardian_alive {
            Ok(true) => {}
            Ok(false) => {
                failures.push("DbClientSet shutdown stopped the external guardian".to_owned());
            }
            Err(error) => failures.push(error.to_string()),
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; ").into())
        }
    }

    fn isolated_config() -> TestResult<SurrealServerConfig> {
        require(
            std::env::var("ELIOT_DISABLE_REAL_PROVIDER").as_deref() == Ok("1"),
            "ELIOT_DISABLE_REAL_PROVIDER=1 is required",
        )?;
        let mut config = GovernorConfig::default().db.surreal;
        config.exe = required_env("ELIOT_SURREAL_EXE")?;
        config.bind = required_env("ELIOT_TEST_SURREAL_BIND")?;
        config.endpoint = required_env("ELIOT_TEST_SURREAL_ENDPOINT")?;
        config.password_file = required_env("ELIOT_TEST_SURREAL_PASSWORD_FILE")?;
        config.storage = required_env("ELIOT_TEST_SURREAL_STORAGE")?;
        config.credential_provider = CredentialProviderKind::LegacyPasswordFile;
        config.query_timeout_ms = 20_000;
        config.startup_timeout_ms = 20_000;
        Ok(config)
    }

    fn isolated_owned_root(config: &SurrealServerConfig) -> TestResult<PathBuf> {
        let storage = config
            .storage
            .strip_prefix("rocksdb:")
            .ok_or("isolated storage must use rocksdb:")?;
        Path::new(storage)
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| "isolated storage has no owned root".into())
    }

    fn require_exact_surreal_version(config: &SurrealServerConfig) -> TestResult {
        let output = Command::new(&config.exe).arg("version").output()?;
        let version = String::from_utf8(output.stdout)?;
        require(
            output.status.success() && version.split_whitespace().next() == Some("3.1.4"),
            &format!("C7-03C requires SurrealDB 3.1.4, got {}", version.trim()),
        )
    }

    fn read_pid(path: &Path) -> TestResult<u32> {
        Ok(std::fs::read_to_string(path)?.trim().parse()?)
    }

    fn required_env(name: &str) -> TestResult<String> {
        std::env::var(name).map_err(|error| format!("{name} is required: {error}").into())
    }

    fn retrieval_envelope(
        project_id: ProjectId,
        claim: ClaimCardInput,
    ) -> Result<MemoryWriteEnvelope, serde_json::Error> {
        let input_hash = blake3::hash(&serde_json::to_vec(&claim)?)
            .to_hex()
            .to_string();
        Ok(MemoryWriteEnvelope {
            write_id: WriteId::new_v7(),
            operation_id: OperationId::new_v7(),
            agent_id: AgentId::new_v7(),
            session_id: None,
            project_id,
            task_id: Some(TaskId::new_v7()),
            command_kind: SemanticCommandKind::ClaimPropose,
            input_hash,
            policy_snapshot_id: Some("policy:c7-03c-live".to_owned()),
            project_sequence_hint: None,
            created_at: OffsetDateTime::now_utc(),
            scope: "c7-03c-live".to_owned(),
            authority: "isolated-local-verified".to_owned(),
            task_contracts: Vec::new(),
            source_snapshots: Vec::new(),
            evidence_atoms: Vec::new(),
            tool_observations: Vec::new(),
            failures: Vec::new(),
            claims: vec![claim],
            verification_runs: Vec::new(),
            relations: Vec::new(),
            lifecycle: LifecycleWriteOptions {
                status: LifecycleStatus::Active,
                visibility: Visibility::Internal,
                taint: TaintClass::LocalVerified,
            },
            idempotency: IdempotencyOptions { allow_replay: true },
        })
    }

    fn claim(statement: &str) -> ClaimCardInput {
        ClaimCardInput {
            claim_id: ClaimId::new_v7(),
            statement: statement.to_owned(),
            status: EpistemicStatus::Verified,
            payload: json!({ "phase": "C7-03C" }),
        }
    }

    fn recall_request(project_id: ProjectId, query: &str) -> RecallL0Request {
        RecallL0Request {
            project_id,
            query: query.to_owned(),
            consistency: ReadConsistencyMode::Latest,
            at_least_revision: None,
            lifecycle_audit: false,
            task_id: None,
            task_class_cues: Vec::new(),
            scope_refs: Vec::new(),
            concept_refs: Vec::new(),
        }
    }

    fn require(condition: bool, message: &str) -> TestResult {
        if condition {
            Ok(())
        } else {
            Err(message.to_owned().into())
        }
    }
}
