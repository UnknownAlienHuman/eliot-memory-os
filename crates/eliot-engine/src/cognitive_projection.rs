use crate::{CueIndexService, EngineError, UlDependencyService};
use eliot_store::{
    CanonicalStore, CognitiveProjectionFamily, CognitiveProjectionFamilyState,
    CognitiveProjectionLease, CognitiveProjectionPublicationStatus, StoreError,
};
use eliot_types::{
    CurrentStateRequest, MemoryRevision, MemoryWriteEnvelope, ProjectId, ReadConsistencyMode,
    WriteReceipt, WriteStatus,
};
use std::collections::{BTreeMap, HashMap, HashSet};
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
        self.store
            .enqueue_cognitive_projection_intent(
                project_id,
                &event_id,
                revision,
                &[CognitiveProjectionFamily::DependencyDirty],
            )
            .await?;
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
        // hint: a full queue must not make an old cue shard look current.
        let _ = self.cue_index.mark_stale(envelope.project_id, revision);
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
            metrics: metrics.clone(),
        };
        let coordinator = Self {
            store,
            cue_index,
            dependency,
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
        let mut delay = Duration::from_hours(24);
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
                delay = Duration::from_hours(24);
                continue;
            }
            match self.background_step().await {
                Ok(BackgroundStep::Progress) => {
                    delay = Duration::from_millis(10);
                }
                Ok(BackgroundStep::Waiting) => {
                    delay = Duration::from_secs(1);
                }
                Ok(BackgroundStep::Dormant) => {
                    armed = false;
                    delay = Duration::from_hours(24);
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
            self.process_claimed_lease(&lease).await;
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
                self.persist_failure(lease, Some(*family), error, &states)
                    .await;
                return;
            }
        }
        if self
            .store
            .complete_cognitive_projection_through(lease)
            .await
            .is_ok()
        {
            for write_id in &lease.write_ids {
                self.committed.remove(write_id);
                self.dirty.remove(write_id);
            }
            self.metrics
                .inner
                .completed_leases
                .fetch_add(1, Ordering::Relaxed);
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
            if !self.warmed_cues.contains(&lease.project_id) {
                let revision = state
                    .and_then(|state| state.applied_revision)
                    .ok_or_else(|| {
                        coordinator_unavailable("published cue state omitted its applied revision")
                    })?;
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
        recovery_event_id, retry_delay_seconds,
    };
    use crate::{
        CueIndexService, InjectionPlanner, TouchedSetRegistry, UlDependencyService,
        WriteAdmissionService, WriterActor, WriterConfig, WriterShutdownHandle,
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

    #[tokio::test]
    async fn recovery_acknowledges_without_a_store_round_trip() -> TestResult {
        let store = CanonicalStore::new(GovernorConfig::default().db.surreal);
        let cue_index = Arc::new(CueIndexService::new(store.clone()));
        let dependency = Arc::new(UlDependencyService::new(store.clone()));
        let (_handle, mut coordinator, _shutdown) = CognitiveProjectionCoordinator::channel(
            store,
            cue_index,
            dependency,
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
        let (projection, coordinator, projection_shutdown) =
            CognitiveProjectionCoordinator::channel(
                store.clone(),
                Arc::clone(&cue_index),
                dependency,
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
        let touched = Arc::new(TouchedSetRegistry::new());
        let injection = InjectionPlanner::with_project_root_and_activation_min_edges(
            Arc::clone(&cue_index),
            store.clone(),
            writer.clone(),
            Arc::clone(&touched),
            owned_root.clone(),
            u32::MAX,
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
            let first_planned = injection
                .plan_after_tool(injection_project_id, injection_session_id, &observed_cues)
                .await?;
            let first_failure_position = first_planned
                .iter()
                .position(|item| item.item_ref == failure_ref)
                .ok_or("revision-one failure was not planned")?;
            let first_card_position = first_planned
                .iter()
                .position(|item| item.item_ref == card_ref)
                .ok_or("revision-one card was not planned")?;
            require(
                first_planned.len() == 2 && first_failure_position < first_card_position,
                "revision-one planner did not preserve danger-before-card ordering",
            )?;
            let first_failure_source = first_planned[first_failure_position]
                .source_fingerprint
                .clone();
            let first_card_source = first_planned[first_card_position]
                .source_fingerprint
                .clone();
            let mut first_response = json!({"at_revision": first_head.value()});
            let first_injection_receipts = injection
                .attach(
                    injection_project_id,
                    None,
                    injection_session_id,
                    &mut first_response,
                    Some(UlInjectionMode::Payload),
                )
                .await?;
            let first_items = first_response
                .pointer("/ul_fired/items")
                .and_then(Value::as_array)
                .ok_or("revision-one attach omitted ul_fired.items")?;
            require(
                first_items.len() == 2
                    && first_items[0]["item_ref"] == failure_ref
                    && first_items[1]["item_ref"] == card_ref
                    && first_items[0]["payload"]["source_revision"] == 1,
                "revision-one attach did not deliver the ordered failure/card payload",
            )?;
            require(
                first_injection_receipts.iter().any(|receipt| {
                    receipt.item_ref == failure_ref
                        && receipt.source_fingerprint == first_failure_source
                }) && first_injection_receipts.iter().any(|receipt| {
                    receipt.item_ref == card_ref && receipt.source_fingerprint == first_card_source
                }),
                "revision-one delivery ledger omitted a planned source fingerprint",
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
            let second_planned = injection
                .plan_after_tool(injection_project_id, injection_session_id, &observed_cues)
                .await?;
            let second_failure = second_planned
                .iter()
                .find(|item| item.item_ref == failure_ref)
                .ok_or("revision-two failure was not planned")?;
            let second_card = second_planned
                .iter()
                .find(|item| item.item_ref == card_ref)
                .ok_or("unchanged revision-two card was not planned")?;
            require(
                second_failure.source_fingerprint != first_failure_source
                    && second_card.source_fingerprint == first_card_source,
                "revision-two source fingerprints did not distinguish changed from unchanged",
            )?;
            let second_failure_source = second_failure.source_fingerprint.clone();
            let mut second_response = json!({"at_revision": second_head.value()});
            let second_injection_receipts = injection
                .attach(
                    injection_project_id,
                    None,
                    injection_session_id,
                    &mut second_response,
                    Some(UlInjectionMode::Payload),
                )
                .await?;
            let second_items = second_response
                .pointer("/ul_fired/items")
                .and_then(Value::as_array)
                .ok_or("revision-two attach omitted ul_fired.items")?;
            require(
                second_items.len() == 1
                    && second_items[0]["item_ref"] == failure_ref
                    && second_items[0]["payload"]["source_revision"] == 2,
                "revision-two attach did not redeliver only the changed failure",
            )?;
            require(
                second_injection_receipts.iter().any(|receipt| {
                    receipt.item_ref == failure_ref
                        && receipt.source_fingerprint == second_failure_source
                }) && !second_injection_receipts
                    .iter()
                    .any(|receipt| receipt.item_ref == card_ref),
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
                    expected_reuse_note: Some(
                        "reuse when editing the live revision fixture".to_owned(),
                    ),
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
                expected_reuse_note: Some(
                    "reuse when editing the live revision fixture".to_owned(),
                ),
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
