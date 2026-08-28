use crate::StoreError;
use crate::db_client_metrics::MetricCounters;
use crate::surql::{NamedSurqlOp, SurqlAccessClass};
use crate::surreal_rpc::SurrealRpcTransport;
use crate::surreal_server::{ReadySurrealServer, SurrealServerSupervisor, SurrealShutdown};
use eliot_types::SurrealServerConfig;
use serde_json::Value;
use std::collections::VecDeque;
use std::future::Future;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, MutexGuard as StdMutexGuard};
use tokio::sync::{Mutex, RwLock, RwLockReadGuard, Semaphore, SemaphorePermit, oneshot, watch};
use tokio::time::{Duration, timeout};
use uuid::Uuid;

pub use crate::db_client_metrics::DbClientSetMetrics;

pub const DEFAULT_DB_READ_POOL_SIZE: usize = 4;

static ABANDONED_STARTUP_CLEANUP_FAILURES: AtomicU64 = AtomicU64::new(0);

/// One daemon-owned generation of persistent, authenticated `SurrealDB` RPC
/// clients. Clones share the same server lease, transports, ordering locks and
/// shutdown result.
#[derive(Clone, Debug)]
pub struct DbClientSet {
    inner: Arc<DbClientSetInner>,
}

#[derive(Debug)]
struct DbClientSetInner {
    config: SurrealServerConfig,
    generation_id: Uuid,
    started_pid: Option<u32>,
    supervisor: SurrealServerSupervisor,
    ready: Mutex<Option<ReadySurrealServer>>,
    read_pool: ReadPool,
    // Tokio's mutex is FIFO. Holding this guard across the RPC request is the
    // ordering boundary for all writes in this client generation.
    write: OrderedSlot<TransportSlot>,
    admin: Mutex<TransportSlot>,
    operation_gate: RwLock<()>,
    closing: AtomicBool,
    shutdown: DetachedOutcome<StoredShutdown>,
    acquire_timeout_ms: u64,
    connect_timeout_ms: u64,
    reconnect_timeout_ms: u64,
    metrics: MetricCounters,
}

#[derive(Debug)]
struct ReadPool {
    slots: Vec<Mutex<TransportSlot>>,
    available: StdMutex<VecDeque<usize>>,
    permits: Semaphore,
}

#[derive(Debug)]
struct TransportSlot {
    transport: Option<Arc<SurrealRpcTransport>>,
}

#[derive(Debug)]
struct OrderedSlot<T> {
    inner: Mutex<T>,
}

#[derive(Debug)]
struct StartupParts {
    config: SurrealServerConfig,
    generation_id: Uuid,
    started_pid: Option<u32>,
    supervisor: SurrealServerSupervisor,
    ready: ReadySurrealServer,
    read_transports: Vec<Arc<SurrealRpcTransport>>,
    write: Arc<SurrealRpcTransport>,
    admin: Arc<SurrealRpcTransport>,
    acquire_timeout_ms: u64,
    connect_timeout_ms: u64,
    reconnect_timeout_ms: u64,
}

#[derive(Debug)]
struct AdoptionSlot<T> {
    value: StdMutex<Option<T>>,
}

#[derive(Debug)]
struct DetachedOutcome<T>
where
    T: Clone,
{
    started: AtomicBool,
    sender: watch::Sender<Option<T>>,
}

#[derive(Clone, Debug)]
enum StoredShutdown {
    Success(SurrealShutdown),
    Failed(String),
}

struct ReadLease<'a> {
    pool: &'a ReadPool,
    index: usize,
    _permit: SemaphorePermit<'a>,
}

impl DbClientSet {
    /// Establishes one bootstrap/admin session, one ordered writer and the
    /// fixed four-session read pool under a single server lease.
    pub async fn start(config: SurrealServerConfig) -> Result<Self, StoreError> {
        let adoption = Arc::new(AdoptionSlot::new());
        let worker_adoption = Arc::clone(&adoption);
        let (published_tx, published_rx) = oneshot::channel();
        let (adopted_tx, adopted_rx) = oneshot::channel();

        tokio::spawn(async move {
            let outcome = build_startup_parts(config).await;
            if let Some(unadopted) =
                publish_for_adoption(&worker_adoption, outcome, published_tx, adopted_rx).await
                && let Ok(parts) = unadopted
                && cleanup_startup_parts(parts).await.is_err()
            {
                // No caller remains to receive details. Retain a bounded,
                // secret-free signal for host diagnostics instead of writing
                // configuration or credential paths to stderr.
                ABANDONED_STARTUP_CLEANUP_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        });

        published_rx.await.map_err(|_| {
            StoreError::ClientSetStartupFailed(
                "startup ownership worker ended before publishing an outcome".to_owned(),
            )
        })?;
        let outcome = adoption.take().ok_or_else(|| {
            StoreError::ClientSetStartupFailed(
                "startup ownership worker published no adoptable outcome".to_owned(),
            )
        })?;
        // There is no await between taking the value and acknowledging it, so
        // task cancellation cannot make the worker clean an already-returned
        // client generation.
        let client = outcome.map(Self::from_startup_parts);
        let _ = adopted_tx.send(());
        client
    }

    fn from_startup_parts(parts: StartupParts) -> Self {
        let sessions_opened = u64::try_from(parts.read_transports.len() + 2).unwrap_or(u64::MAX);
        Self {
            inner: Arc::new(DbClientSetInner {
                config: parts.config,
                generation_id: parts.generation_id,
                started_pid: parts.started_pid,
                supervisor: parts.supervisor,
                ready: Mutex::new(Some(parts.ready)),
                read_pool: ReadPool::new(parts.read_transports),
                write: OrderedSlot::new(TransportSlot::new(parts.write)),
                admin: Mutex::new(TransportSlot::new(parts.admin)),
                operation_gate: RwLock::new(()),
                closing: AtomicBool::new(false),
                shutdown: DetachedOutcome::new(),
                acquire_timeout_ms: parts.acquire_timeout_ms,
                connect_timeout_ms: parts.connect_timeout_ms,
                reconnect_timeout_ms: parts.reconnect_timeout_ms,
                metrics: MetricCounters::new(sessions_opened),
            }),
        }
    }

    /// Count of cancellation cleanups which attempted all steps but still
    /// encountered one or more failures after their caller had disappeared.
    #[must_use]
    pub fn abandoned_startup_cleanup_failures() -> u64 {
        ABANDONED_STARTUP_CLEANUP_FAILURES.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn generation_id(&self) -> Uuid {
        self.inner.generation_id
    }

    #[must_use]
    pub fn started_pid(&self) -> Option<u32> {
        self.inner.started_pid
    }

    #[must_use]
    pub fn metrics(&self) -> DbClientSetMetrics {
        self.inner
            .metrics
            .snapshot(self.inner.generation_id, self.inner.read_pool.slots.len())
    }

    pub(crate) async fn execute_named(
        &self,
        op: NamedSurqlOp,
        vars: Value,
    ) -> Result<Value, StoreError> {
        self.execute_classified(op.access_class(), op.template(), vars)
            .await
    }

    pub(crate) async fn execute_admin_sql(
        &self,
        sql: &str,
        vars: Value,
    ) -> Result<Value, StoreError> {
        self.execute_classified(SurqlAccessClass::Admin, sql, vars)
            .await
    }

    async fn execute_classified(
        &self,
        access: SurqlAccessClass,
        sql: &str,
        vars: Value,
    ) -> Result<Value, StoreError> {
        let _operation = self.acquire_operation().await?;
        match access {
            SurqlAccessClass::Read => self.execute_read(sql, vars).await,
            SurqlAccessClass::Write => self.execute_write(sql, vars).await,
            SurqlAccessClass::Admin => self.execute_admin(sql, vars).await,
        }
    }

    pub(crate) fn config(&self) -> &SurrealServerConfig {
        &self.inner.config
    }

    async fn execute_read(&self, sql: &str, vars: Value) -> Result<Value, StoreError> {
        let lease = self
            .inner
            .read_pool
            .acquire(self.inner.acquire_timeout_ms)
            .await?;
        let _activity = self.inner.metrics.begin_read();
        self.inner
            .metrics
            .read_queries
            .fetch_add(1, Ordering::Relaxed);
        let mut slot = self.inner.read_pool.slots[lease.index].lock().await;
        self.execute_slot(&mut slot, sql, vars).await
    }

    async fn execute_write(&self, sql: &str, vars: Value) -> Result<Value, StoreError> {
        self.inner
            .metrics
            .write_queries
            .fetch_add(1, Ordering::Relaxed);
        let mut slot = self
            .inner
            .write
            .acquire(self.inner.acquire_timeout_ms)
            .await?;
        self.execute_slot(&mut slot, sql, vars).await
    }

    async fn execute_admin(&self, sql: &str, vars: Value) -> Result<Value, StoreError> {
        self.inner
            .metrics
            .admin_queries
            .fetch_add(1, Ordering::Relaxed);
        let mut slot = timeout(
            Duration::from_millis(self.inner.acquire_timeout_ms),
            self.inner.admin.lock(),
        )
        .await
        .map_err(|_| StoreError::Timeout {
            op: "database admin transport acquisition".to_owned(),
            ms: self.inner.acquire_timeout_ms,
        })?;
        self.execute_slot(&mut slot, sql, vars).await
    }

    async fn execute_slot(
        &self,
        slot: &mut TransportSlot,
        sql: &str,
        vars: Value,
    ) -> Result<Value, StoreError> {
        if slot.transport.is_none() {
            self.inner
                .metrics
                .reconnect_attempts
                .fetch_add(1, Ordering::Relaxed);
            let transport = connect_sibling(
                &self.inner.supervisor,
                self.inner.connect_timeout_ms,
                self.inner.reconnect_timeout_ms,
            )
            .await?;
            self.inner
                .metrics
                .reconnect_successes
                .fetch_add(1, Ordering::Relaxed);
            self.inner
                .metrics
                .sessions_opened
                .fetch_add(1, Ordering::Relaxed);
            slot.transport = Some(Arc::new(transport));
        }

        let transport = Arc::clone(
            slot.transport
                .as_ref()
                .ok_or(StoreError::ConnectionClosed)?,
        );
        let (result, invalidated) = one_query_attempt(&mut slot.transport, async {
            transport.query(sql, vars).await
        })
        .await;
        if invalidated {
            self.inner
                .metrics
                .transport_invalidations
                .fetch_add(1, Ordering::Relaxed);
        }
        result
    }

    async fn acquire_operation(&self) -> Result<RwLockReadGuard<'_, ()>, StoreError> {
        if self.inner.closing.load(Ordering::Acquire) {
            self.inner
                .metrics
                .rejected_after_shutdown
                .fetch_add(1, Ordering::Relaxed);
            return Err(StoreError::ClientSetShuttingDown);
        }
        let guard = timeout(
            Duration::from_millis(self.inner.acquire_timeout_ms),
            self.inner.operation_gate.read(),
        )
        .await
        .map_err(|_| StoreError::Timeout {
            op: "database client operation admission".to_owned(),
            ms: self.inner.acquire_timeout_ms,
        })?;
        if self.inner.closing.load(Ordering::Acquire) {
            drop(guard);
            self.inner
                .metrics
                .rejected_after_shutdown
                .fetch_add(1, Ordering::Relaxed);
            return Err(StoreError::ClientSetShuttingDown);
        }
        Ok(guard)
    }

    /// Refuses new operations, drains the already admitted bounded operations,
    /// closes every transport and releases the sole `ReadySurrealServer` lease.
    /// All callers observe the same stored success or failure.
    pub async fn shutdown(&self) -> Result<SurrealShutdown, StoreError> {
        self.inner.closing.store(true, Ordering::Release);
        if self.inner.shutdown.try_start() {
            let inner = Arc::clone(&self.inner);
            tokio::spawn(async move {
                let outcome = shutdown_generation(&inner).await;
                inner
                    .metrics
                    .shutdown_completed
                    .store(true, Ordering::Release);
                inner.shutdown.complete(outcome);
            });
        }

        self.inner
            .shutdown
            .wait()
            .await
            .ok_or_else(|| {
                StoreError::ClientSetShutdownFailed(
                    "shutdown ownership worker ended without a terminal outcome".to_owned(),
                )
            })?
            .result()
    }
}

#[cfg(test)]
mod live_tests;

impl ReadPool {
    fn new(transports: Vec<Arc<SurrealRpcTransport>>) -> Self {
        let size = transports.len();
        Self {
            slots: transports
                .into_iter()
                .map(TransportSlot::new)
                .map(Mutex::new)
                .collect(),
            available: StdMutex::new((0..size).collect()),
            permits: Semaphore::new(size),
        }
    }

    async fn acquire(&self, timeout_ms: u64) -> Result<ReadLease<'_>, StoreError> {
        let permit = timeout(Duration::from_millis(timeout_ms), self.permits.acquire())
            .await
            .map_err(|_| StoreError::Timeout {
                op: "database reader acquisition".to_owned(),
                ms: timeout_ms,
            })?
            .map_err(|_| StoreError::ClientSetShuttingDown)?;
        let index = self.available_guard().pop_front().ok_or_else(|| {
            StoreError::PolicyViolation("read permit had no pool slot".to_owned())
        })?;
        Ok(ReadLease {
            pool: self,
            index,
            _permit: permit,
        })
    }

    async fn close_slots(&self) -> Vec<String> {
        let mut failures = Vec::new();
        for (index, slot) in self.slots.iter().enumerate() {
            if let Err(error) = close_slot(slot).await {
                failures.push(format!("read transport {index}: {error}"));
            }
        }
        failures
    }

    fn available_guard(&self) -> StdMutexGuard<'_, VecDeque<usize>> {
        self.available
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for ReadLease<'_> {
    fn drop(&mut self) {
        self.pool.available_guard().push_back(self.index);
    }
}

impl TransportSlot {
    fn new(transport: Arc<SurrealRpcTransport>) -> Self {
        Self {
            transport: Some(transport),
        }
    }
}

impl<T> OrderedSlot<T> {
    fn new(value: T) -> Self {
        Self {
            inner: Mutex::new(value),
        }
    }

    async fn acquire(&self, timeout_ms: u64) -> Result<tokio::sync::MutexGuard<'_, T>, StoreError> {
        timeout(Duration::from_millis(timeout_ms), self.inner.lock())
            .await
            .map_err(|_| StoreError::Timeout {
                op: "ordered database writer acquisition".to_owned(),
                ms: timeout_ms,
            })
    }
}

impl<T> AdoptionSlot<T> {
    fn new() -> Self {
        Self {
            value: StdMutex::new(None),
        }
    }

    fn publish(&self, value: T) {
        *self
            .value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(value);
    }

    fn take(&self) -> Option<T> {
        self.value
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

impl<T> DetachedOutcome<T>
where
    T: Clone,
{
    fn new() -> Self {
        let (sender, _receiver) = watch::channel(None);
        Self {
            started: AtomicBool::new(false),
            sender,
        }
    }

    fn try_start(&self) -> bool {
        self.started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    fn complete(&self, outcome: T) {
        self.sender.send_replace(Some(outcome));
    }

    async fn wait(&self) -> Option<T> {
        let mut receiver = self.sender.subscribe();
        loop {
            if let Some(outcome) = receiver.borrow().clone() {
                return Some(outcome);
            }
            if receiver.changed().await.is_err() {
                return None;
            }
        }
    }
}

impl StoredShutdown {
    fn result(&self) -> Result<SurrealShutdown, StoreError> {
        match self {
            Self::Success(shutdown) => Ok(*shutdown),
            Self::Failed(message) => Err(StoreError::ClientSetShutdownFailed(message.clone())),
        }
    }
}

async fn connect_sibling(
    supervisor: &SurrealServerSupervisor,
    connect_timeout_ms: u64,
    reconnect_timeout_ms: u64,
) -> Result<SurrealRpcTransport, StoreError> {
    timeout(
        Duration::from_millis(reconnect_timeout_ms),
        supervisor.connect_authenticated_sibling(connect_timeout_ms),
    )
    .await
    .map_err(|_| StoreError::Timeout {
        op: "authenticated database transport connect".to_owned(),
        ms: reconnect_timeout_ms,
    })?
}

async fn close_slot(slot: &Mutex<TransportSlot>) -> Result<(), StoreError> {
    if let Some(transport) = slot.lock().await.transport.take() {
        transport.close().await?;
    }
    Ok(())
}

async fn build_startup_parts(config: SurrealServerConfig) -> Result<StartupParts, StoreError> {
    let acquire_timeout_ms = config.query_timeout_ms.max(1);
    let connect_timeout_ms = config
        .query_timeout_ms
        .max(1)
        .min(config.startup_timeout_ms.max(1));
    let reconnect_timeout_ms = config.startup_timeout_ms.max(connect_timeout_ms).max(1);
    let supervisor = SurrealServerSupervisor::new(config.clone());
    let mut ready = supervisor.start_or_connect().await?;
    let started_pid = ready.started_pid();
    let admin = match ready.take_transport_handle() {
        Ok(transport) => transport,
        Err(error) => return Err(startup_failure(error, ready, Vec::new()).await),
    };
    let write = match connect_sibling(&supervisor, connect_timeout_ms, reconnect_timeout_ms).await {
        Ok(transport) => Arc::new(transport),
        Err(error) => {
            return Err(startup_failure(error, ready, vec![Arc::clone(&admin)]).await);
        }
    };
    let mut read_transports = Vec::with_capacity(DEFAULT_DB_READ_POOL_SIZE);
    for _ in 0..DEFAULT_DB_READ_POOL_SIZE {
        match connect_sibling(&supervisor, connect_timeout_ms, reconnect_timeout_ms).await {
            Ok(transport) => read_transports.push(Arc::new(transport)),
            Err(error) => {
                let mut opened = Vec::with_capacity(read_transports.len() + 2);
                opened.push(admin);
                opened.push(write);
                opened.extend(read_transports);
                return Err(startup_failure(error, ready, opened).await);
            }
        }
    }
    Ok(StartupParts {
        config,
        generation_id: Uuid::new_v4(),
        started_pid,
        supervisor,
        ready,
        read_transports,
        write,
        admin,
        acquire_timeout_ms,
        connect_timeout_ms,
        reconnect_timeout_ms,
    })
}

async fn startup_failure(
    primary: StoreError,
    ready: ReadySurrealServer,
    transports: Vec<Arc<SurrealRpcTransport>>,
) -> StoreError {
    match cleanup_ready_and_transports(ready, transports).await {
        Ok(()) => primary,
        Err(cleanup) => StoreError::ClientSetStartupFailed(format!(
            "primary failure: {primary}; cleanup failures: {cleanup}"
        )),
    }
}

async fn cleanup_startup_parts(parts: StartupParts) -> Result<(), String> {
    let mut transports = Vec::with_capacity(parts.read_transports.len() + 2);
    transports.push(parts.admin);
    transports.push(parts.write);
    transports.extend(parts.read_transports);
    cleanup_ready_and_transports(parts.ready, transports).await
}

async fn cleanup_ready_and_transports(
    ready: ReadySurrealServer,
    transports: Vec<Arc<SurrealRpcTransport>>,
) -> Result<(), String> {
    let mut failures = Vec::new();
    for (index, transport) in transports.into_iter().enumerate() {
        if let Err(error) = transport.close().await {
            failures.push(format!("transport {index}: {error}"));
        }
    }
    if let Err(error) = ready.shutdown_if_spawned().await {
        failures.push(format!("server lease: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

async fn publish_for_adoption<T>(
    adoption: &Arc<AdoptionSlot<T>>,
    outcome: T,
    published: oneshot::Sender<()>,
    adopted: oneshot::Receiver<()>,
) -> Option<T> {
    adoption.publish(outcome);
    if published.send(()).is_err() || adopted.await.is_err() {
        return adoption.take();
    }
    None
}

async fn shutdown_generation(inner: &Arc<DbClientSetInner>) -> StoredShutdown {
    let _exclusive = inner.operation_gate.write().await;
    inner.read_pool.permits.close();
    let mut failures = inner.read_pool.close_slots().await;
    if let Err(error) = close_slot(&inner.write.inner).await {
        failures.push(format!("write transport: {error}"));
    }
    if let Err(error) = close_slot(&inner.admin).await {
        failures.push(format!("admin transport: {error}"));
    }

    let shutdown = if let Some(ready) = inner.ready.lock().await.take() {
        match ready.shutdown_if_spawned().await {
            Ok(shutdown) => Some(shutdown),
            Err(error) => {
                failures.push(format!("server lease: {error}"));
                None
            }
        }
    } else {
        failures.push("server lease was already consumed".to_owned());
        None
    };
    if failures.is_empty() {
        shutdown.map_or_else(
            || StoredShutdown::Failed("server shutdown produced no outcome".to_owned()),
            StoredShutdown::Success,
        )
    } else {
        StoredShutdown::Failed(failures.join("; "))
    }
}

/// Consumes exactly one already-constructed query future. A fatal result drops
/// the session from its slot, but this function has no factory with which it
/// could reconnect or replay the current operation.
async fn one_query_attempt<T, F>(
    slot: &mut Option<T>,
    attempt: F,
) -> (Result<Value, StoreError>, bool)
where
    F: Future<Output = Result<Value, StoreError>>,
{
    let result = attempt.await;
    let invalidated = result
        .as_ref()
        .is_err_and(StoreError::invalidates_rpc_transport);
    if invalidated {
        slot.take();
    }
    (result, invalidated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use tokio::sync::oneshot;

    #[test]
    fn fatal_transport_errors_are_invalidated_but_rpc_rejections_are_not() {
        assert!(StoreError::ConnectionClosed.invalidates_rpc_transport());
        assert!(StoreError::WebSocket("closed".to_owned()).invalidates_rpc_transport());
        assert!(
            StoreError::Timeout {
                op: "query".to_owned(),
                ms: 10,
            }
            .invalidates_rpc_transport()
        );
        assert!(
            !StoreError::RpcError {
                code: -32000,
                message: "query rejected".to_owned(),
                data: None,
            }
            .invalidates_rpc_transport()
        );
    }

    #[test]
    fn stored_shutdown_outcome_is_repeatable() {
        let success = StoredShutdown::Success(SurrealShutdown::not_owned());
        assert!(matches!(
            success.result(),
            Ok(outcome) if outcome == SurrealShutdown::not_owned()
        ));
        assert!(matches!(
            success.result(),
            Ok(outcome) if outcome == SurrealShutdown::not_owned()
        ));

        let failed = StoredShutdown::Failed("stable failure".to_owned());
        let first = failed.result().map_err(|error| error.to_string());
        let second = failed.result().map_err(|error| error.to_string());
        assert_eq!(first, second);
    }

    #[tokio::test]
    async fn fatal_result_is_not_replayed_and_only_the_next_call_can_reconnect() {
        let attempts = AtomicUsize::new(0);
        let mut slot = Some("session");
        let (result, invalidated) = one_query_attempt(&mut slot, async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Err(StoreError::ConnectionClosed)
        })
        .await;

        assert!(matches!(result, Err(StoreError::ConnectionClosed)));
        assert!(invalidated);
        assert!(slot.is_none());
        assert_eq!(attempts.load(Ordering::Relaxed), 1);

        // A later operation is the only place that may install a new session.
        slot = Some("next-session");
        let (result, invalidated) = one_query_attempt(&mut slot, async {
            attempts.fetch_add(1, Ordering::Relaxed);
            Ok(Value::Bool(true))
        })
        .await;
        assert_eq!(result.ok(), Some(Value::Bool(true)));
        assert!(!invalidated);
        assert_eq!(slot, Some("next-session"));
        assert_eq!(attempts.load(Ordering::Relaxed), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ordered_writer_grants_waiters_in_fifo_order() {
        let writer = Arc::new(OrderedSlot::new(()));
        let held = writer.inner.lock().await;
        let observed = Arc::new(StdMutex::new(Vec::new()));
        let mut waiters = Vec::new();

        for index in 0..8 {
            let writer = Arc::clone(&writer);
            let observed = Arc::clone(&observed);
            let (queued_tx, queued_rx) = oneshot::channel();
            waiters.push(tokio::spawn(async move {
                let _ = queued_tx.send(());
                if let Ok(_guard) = writer.acquire(1_000).await {
                    observed
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push(index);
                }
            }));
            assert!(queued_rx.await.is_ok());
            // The current-thread runtime cannot resume this test until the
            // spawned task has polled the pending FIFO lock acquisition.
            tokio::task::yield_now().await;
        }

        drop(held);
        for waiter in waiters {
            assert!(waiter.await.is_ok());
        }
        let observed = observed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(*observed, (0..8).collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn cancelled_start_adoption_returns_ownership_to_the_worker() {
        let adoption = Arc::new(AdoptionSlot::new());
        let worker_adoption = Arc::clone(&adoption);
        let (published_tx, published_rx) = oneshot::channel();
        let (adopted_tx, adopted_rx) = oneshot::channel::<()>();
        let publisher = tokio::spawn(async move {
            publish_for_adoption(
                &worker_adoption,
                "owned-generation",
                published_tx,
                adopted_rx,
            )
            .await
        });

        assert!(published_rx.await.is_ok());
        drop(adopted_tx);
        let returned = publisher.await.ok().flatten();
        assert_eq!(returned, Some("owned-generation"));
        assert!(adoption.take().is_none());
    }

    #[tokio::test]
    async fn cancelled_shutdown_waiter_does_not_cancel_single_flight_cleanup() {
        let terminal = Arc::new(DetachedOutcome::new());
        let runs = Arc::new(AtomicUsize::new(0));
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        assert!(terminal.try_start());

        let worker_terminal = Arc::clone(&terminal);
        let worker_runs = Arc::clone(&runs);
        let worker = tokio::spawn(async move {
            worker_runs.fetch_add(1, Ordering::Relaxed);
            let _ = started_tx.send(());
            let _ = release_rx.await;
            worker_terminal.complete(17_u64);
        });
        let waiter_terminal = Arc::clone(&terminal);
        let waiter = tokio::spawn(async move { waiter_terminal.wait().await });
        assert!(started_rx.await.is_ok());
        waiter.abort();
        let _ = waiter.await;
        let _ = release_tx.send(());
        assert!(worker.await.is_ok());

        assert_eq!(terminal.wait().await, Some(17));
        assert!(!terminal.try_start());
        assert_eq!(runs.load(Ordering::Relaxed), 1);
    }
}
