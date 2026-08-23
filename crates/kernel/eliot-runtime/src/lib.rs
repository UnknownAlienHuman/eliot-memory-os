//! P-11 framework-neutral bounded runtime facade.
//!
//! Tokio is a private execution mechanism. This crate owns bounded task,
//! mailbox, cancellation, shutdown, and supervision mechanics; it owns no
//! domain state, authority, receipt, process tree, or canonical lifecycle.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use eliot_observation_contracts::ObservationKind;
use eliot_platform::{PortError, PortOutcome, ProviderError, ProviderErrorCode};
use eliot_runtime_contracts::ServiceProcessState;
use std::future::Future;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, Semaphore, mpsc, oneshot};

const RUNNING: u8 = 0;
const SHUTTING_DOWN: u8 = 1;
const TERMINATED: u8 = 2;

/// A framework-neutral control signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlSignal {
    /// Ask a task to stop at its next cancellation point.
    Cancel,
    /// Ask a task to finish its ordered shutdown work.
    Shutdown,
}

/// The item received from a typed mailbox.
#[derive(Debug, Eq, PartialEq)]
pub enum MailboxItem<T> {
    /// A normal data item.
    Data(T),
    /// A protected control item.
    Control(ControlSignal),
}

/// The result of attempting to put an item into a bounded mailbox.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SendResult {
    /// The item was admitted.
    Accepted,
    /// This lane is full; the other lane's capacity is unaffected.
    Saturated,
    /// All receivers have gone away.
    Closed,
}

/// A coarse, framework-neutral runtime outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeResult {
    /// The operation completed.
    Completed,
    /// The operation was capacity constrained.
    Saturated,
    /// The operation completed with reduced guarantees.
    Degraded,
    /// The operation was cancelled.
    Cancelled,
    /// The operation failed for a non-capacity reason.
    Failed(RuntimeFailure),
}

/// Framework-neutral classification of a non-capacity runtime failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFailure {
    /// The request or one of its values was invalid or ambiguous.
    InvalidInput,
    /// An operation identity conflicted with an earlier request.
    Conflict,
    /// The provider was unavailable.
    Unavailable,
    /// The provider denied permission.
    PermissionDenied,
    /// The provider timed out.
    Timeout,
    /// The provider reported an otherwise classified failure.
    ProviderFailed,
}

/// A bounded, typed mailbox with an independent control reserve.
#[derive(Clone)]
pub struct Mailbox<T> {
    data: mpsc::Sender<T>,
    control: mpsc::Sender<ControlSignal>,
}

/// The sending half of a typed mailbox.
pub type MailboxSender<T> = Mailbox<T>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Lane {
    Data,
    Control,
}

/// The receiving half of a typed mailbox.
pub struct MailboxReceiver<T> {
    data: mpsc::Receiver<T>,
    control: mpsc::Receiver<ControlSignal>,
    preferred: Lane,
    last: Option<Lane>,
    streak: usize,
    fairness_quantum: usize,
    data_closed: bool,
    control_closed: bool,
}

impl<T> Mailbox<T> {
    /// Creates a mailbox with caller-supplied capacities and fairness quantum.
    ///
    /// When both lanes stay ready, at most `fairness_quantum` consecutive items
    /// are selected from one lane before the other lane is preferred.
    pub fn bounded(
        data_capacity: usize,
        control_reserve: usize,
        fairness_quantum: usize,
    ) -> Result<(Self, MailboxReceiver<T>), ConfigError> {
        if data_capacity == 0 || control_reserve == 0 || fairness_quantum == 0 {
            return Err(ConfigError::ZeroCapacity);
        }
        let (data, data_rx) = mpsc::channel(data_capacity);
        let (control, control_rx) = mpsc::channel(control_reserve);
        Ok((
            Self { data, control },
            MailboxReceiver {
                data: data_rx,
                control: control_rx,
                preferred: Lane::Control,
                last: None,
                streak: 0,
                fairness_quantum,
                data_closed: false,
                control_closed: false,
            },
        ))
    }

    /// Attempts to send data without consuming control capacity.
    pub fn try_send(&self, item: T) -> SendResult {
        match self.data.try_send(item) {
            Ok(()) => SendResult::Accepted,
            Err(mpsc::error::TrySendError::Full(_)) => SendResult::Saturated,
            Err(mpsc::error::TrySendError::Closed(_)) => SendResult::Closed,
        }
    }

    /// Attempts to send a protected control signal.
    pub fn try_send_control(&self, signal: ControlSignal) -> SendResult {
        match self.control.try_send(signal) {
            Ok(()) => SendResult::Accepted,
            Err(mpsc::error::TrySendError::Full(_)) => SendResult::Saturated,
            Err(mpsc::error::TrySendError::Closed(_)) => SendResult::Closed,
        }
    }

    /// Sends data, waiting only for data capacity.
    pub async fn send(&self, item: T) -> SendResult {
        match self.data.send(item).await {
            Ok(()) => SendResult::Accepted,
            Err(_) => SendResult::Closed,
        }
    }

    /// Sends control, waiting only for protected control capacity.
    pub async fn send_control(&self, signal: ControlSignal) -> SendResult {
        match self.control.send(signal).await {
            Ok(()) => SendResult::Accepted,
            Err(_) => SendResult::Closed,
        }
    }
}

impl<T> MailboxReceiver<T> {
    fn record(&mut self, lane: Lane) {
        if self.last == Some(lane) {
            self.streak += 1;
        } else {
            self.last = Some(lane);
            self.streak = 1;
        }
        if self.streak >= self.fairness_quantum {
            self.preferred = match lane {
                Lane::Data => Lane::Control,
                Lane::Control => Lane::Data,
            };
        } else {
            self.preferred = lane;
        }
    }

    fn data_item(&mut self, item: Option<T>) -> Option<MailboxItem<T>> {
        if let Some(item) = item {
            self.record(Lane::Data);
            Some(MailboxItem::Data(item))
        } else {
            self.data_closed = true;
            None
        }
    }

    fn control_item(&mut self, item: Option<ControlSignal>) -> Option<MailboxItem<T>> {
        if let Some(item) = item {
            self.record(Lane::Control);
            Some(MailboxItem::Control(item))
        } else {
            self.control_closed = true;
            None
        }
    }

    /// Receives with bounded fairness whenever both lanes remain ready.
    pub async fn recv(&mut self) -> Option<MailboxItem<T>> {
        loop {
            if self.data_closed && self.control_closed {
                return None;
            }

            let item = match self.preferred {
                Lane::Control => {
                    tokio::select! {
                        biased;
                        value = self.control.recv(), if !self.control_closed => {
                            self.control_item(value)
                        }
                        value = self.data.recv(), if !self.data_closed => {
                            self.data_item(value)
                        }
                    }
                }
                Lane::Data => {
                    tokio::select! {
                        biased;
                        value = self.data.recv(), if !self.data_closed => {
                            self.data_item(value)
                        }
                        value = self.control.recv(), if !self.control_closed => {
                            self.control_item(value)
                        }
                    }
                }
            };
            if item.is_some() {
                return item;
            }
        }
    }
}

/// A configurable fairness and lifecycle policy. Values are always explicit.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeConfig {
    /// Normal mailbox capacity.
    pub mailbox_capacity: usize,
    /// Reserved control messages per mailbox.
    pub control_reserve: usize,
    /// Maximum concurrently executing data tasks.
    pub concurrency: usize,
    /// Protected execution slots unavailable to data work.
    pub control_concurrency_reserve: usize,
    /// Maximum consecutive selections from a continuously-ready lane.
    pub fairness_quantum: usize,
    /// Maximum restarts in the rolling window.
    pub restart_budget: usize,
    /// Rolling restart window.
    pub restart_window: Duration,
    /// Initial restart delay.
    pub restart_backoff: Duration,
    /// Grace period for cooperative shutdown before forced abortion.
    pub shutdown_grace: Duration,
}

impl RuntimeConfig {
    /// Validates explicitly supplied fairness, capacity, and duration values.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.mailbox_capacity == 0
            || self.control_reserve == 0
            || self.concurrency == 0
            || self.control_concurrency_reserve == 0
            || self.fairness_quantum == 0
        {
            return Err(ConfigError::ZeroCapacity);
        }
        if self.restart_window.is_zero() || self.shutdown_grace.is_zero() {
            return Err(ConfigError::ZeroDuration);
        }
        Ok(())
    }
}

/// Configuration errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigError {
    /// A capacity or fairness parameter was zero.
    ZeroCapacity,
    /// A required time window was zero.
    ZeroDuration,
}

/// The execution lane selected for a task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionClass {
    /// Ordinary data work using the bounded data permits.
    Data,
    /// Protected control work using only the control reserve.
    ProtectedControl,
}

/// Typed spawn admission result.
pub enum SpawnDisposition<H> {
    /// Admission succeeded and produced a runtime-owned handle.
    Admitted(H),
    /// Admission is closed because shutdown is sticky.
    DeniedShuttingDown,
}

impl<H> SpawnDisposition<H> {
    /// Returns true when the work was admitted.
    pub const fn is_admitted(&self) -> bool {
        matches!(self, Self::Admitted(_))
    }

    /// Extracts the admitted handle, if any.
    pub fn into_handle(self) -> Option<H> {
        match self {
            Self::Admitted(handle) => Some(handle),
            Self::DeniedShuttingDown => None,
        }
    }
}

/// Child classification used by supervision policy selection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildClass {
    /// Failure is isolated to this child.
    Worker,
    /// Failure affects explicitly declared downstream children.
    Service,
    /// Failure affects a small inseparable group.
    Critical,
}

/// Restart scope after one child fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionStrategy {
    /// Restart only the failed child.
    OneForOne,
    /// Restart the failed child and declared later dependents.
    RestForOne,
    /// Restart all children in the declared group.
    OneForAll,
}

/// An observation emitted by coordination mechanics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeObservation {
    /// C0-11 class for this observation.
    pub kind: ObservationKind,
    /// Stable facade-owned subject identity.
    pub subject: String,
    /// Human-readable, non-secret detail.
    pub detail: String,
    /// C0-04 process state represented by the observation.
    pub state: ServiceProcessState,
}

/// A stream-independent observation callback.
pub trait ObservationSink: Send + Sync + 'static {
    /// Accepts one observation. Sink failure or panic cannot stop runtime progress.
    fn observe(&self, observation: RuntimeObservation);
}

/// Typed result of delivering optional runtime telemetry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationDisposition {
    /// The sink accepted the observation.
    Delivered,
    /// No sink was configured; runtime progress is unaffected.
    NoSink,
    /// The sink panicked; the panic was contained.
    SinkPanicked,
}

fn observe_safely(
    sink: Option<&Arc<dyn ObservationSink>>,
    observation: RuntimeObservation,
) -> ObservationDisposition {
    let Some(sink) = sink else {
        return ObservationDisposition::NoSink;
    };
    match catch_unwind(AssertUnwindSafe(|| sink.observe(observation))) {
        Ok(()) => ObservationDisposition::Delivered,
        Err(_) => ObservationDisposition::SinkPanicked,
    }
}

/// A framework-neutral task failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskFailure {
    /// The task returned an explicit failure.
    Failed(String),
    /// The factory or task future panicked.
    Panicked,
    /// The task observed cancellation before completion.
    Cancelled,
}

/// The terminal result of a supervised task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionOutcome {
    /// The task completed without exhausting its restart budget.
    Completed,
    /// The task was isolated after its rolling restart budget was exhausted.
    Quarantined,
}

struct Signal {
    requested: AtomicBool,
    notify: Notify,
}

impl Signal {
    fn new() -> Self {
        Self {
            requested: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    fn request(&self) -> bool {
        let first = !self.requested.swap(true, Ordering::AcqRel);
        if first {
            self.notify.notify_waiters();
        }
        first
    }

    fn is_requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    async fn wait(&self) {
        loop {
            if self.is_requested() {
                return;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_requested() {
                return;
            }
            notified.await;
        }
    }
}

struct CancellationInner {
    local: Signal,
    parent: Option<Arc<CancellationInner>>,
}

impl CancellationInner {
    fn is_cancelled(&self) -> bool {
        self.local.is_requested()
            || self
                .parent
                .as_ref()
                .is_some_and(|parent| parent.is_cancelled())
    }

    fn wait_boxed(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            if self.is_cancelled() {
                return;
            }
            if let Some(parent) = &self.parent {
                tokio::select! {
                    () = self.local.wait() => {}
                    () = parent.wait_boxed() => {}
                }
            } else {
                self.local.wait().await;
            }
        })
    }
}

/// A sticky, hierarchical cancellation token with explicit checkpoints.
#[derive(Clone)]
pub struct CancellationToken {
    inner: Arc<CancellationInner>,
}

impl CancellationToken {
    fn root() -> Self {
        Self {
            inner: Arc::new(CancellationInner {
                local: Signal::new(),
                parent: None,
            }),
        }
    }

    fn child(&self) -> Self {
        Self {
            inner: Arc::new(CancellationInner {
                local: Signal::new(),
                parent: Some(self.inner.clone()),
            }),
        }
    }

    fn request(&self) -> bool {
        self.inner.local.request()
    }

    /// Returns true once local or ancestor cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.inner.is_cancelled()
    }

    /// Fails at an explicit cooperative cancellation checkpoint.
    pub fn checkpoint(&self) -> Result<(), TaskFailure> {
        if self.is_cancelled() {
            Err(TaskFailure::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Waits for local or ancestor cancellation without losing an early signal.
    pub async fn cancelled(&self) {
        self.inner.wait_boxed().await;
    }
}

/// Result of requesting or forcing task cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationDisposition {
    /// A cooperative cancellation request was recorded.
    Requested,
    /// Cancellation had already been requested.
    AlreadyRequested,
    /// The task had already reached a terminal state.
    AlreadyFinished,
    /// The still-running task was forcibly aborted.
    Forced,
}

/// A handle for cooperative cancellation and explicit forced abortion.
#[derive(Clone)]
pub struct CancelHandle {
    token: CancellationToken,
    abort: tokio::task::AbortHandle,
}

impl CancelHandle {
    /// Requests sticky cooperative cancellation. This never aborts immediately.
    pub fn cancel(&self) -> CancellationDisposition {
        if self.abort.is_finished() {
            CancellationDisposition::AlreadyFinished
        } else if self.token.request() {
            CancellationDisposition::Requested
        } else {
            CancellationDisposition::AlreadyRequested
        }
    }

    /// Forces abortion after the caller's bounded cooperative grace period.
    pub fn force_abort(&self) -> CancellationDisposition {
        if self.abort.is_finished() {
            CancellationDisposition::AlreadyFinished
        } else {
            self.token.request();
            self.abort.abort();
            CancellationDisposition::Forced
        }
    }

    /// Returns a read-only clone of the task cancellation token.
    pub fn token(&self) -> CancellationToken {
        self.token.clone()
    }
}

struct CatchUnwindFuture<F> {
    future: Pin<Box<F>>,
}

impl<F> CatchUnwindFuture<F> {
    fn new(future: F) -> Self {
        Self {
            future: Box::pin(future),
        }
    }
}

impl<F: Future> Future for CatchUnwindFuture<F> {
    type Output = Result<F::Output, ()>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        match catch_unwind(AssertUnwindSafe(|| self.future.as_mut().poll(context))) {
            Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) => Poll::Ready(Err(())),
        }
    }
}

struct RegistryEntry {
    id: u64,
    abort: tokio::task::AbortHandle,
}

struct TaskRegistry {
    next_id: AtomicU64,
    entries: Mutex<Vec<RegistryEntry>>,
    active: AtomicUsize,
    finished: Notify,
}

struct ActiveGuard {
    registry: Arc<TaskRegistry>,
    id: u64,
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.registry.finish(self.id);
    }
}

impl TaskRegistry {
    fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            entries: Mutex::new(Vec::new()),
            active: AtomicUsize::new(0),
            finished: Notify::new(),
        }
    }

    fn lock_entries(&self) -> MutexGuard<'_, Vec<RegistryEntry>> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn reserve(self: &Arc<Self>) -> ActiveGuard {
        let registry = self.clone();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        self.active.fetch_add(1, Ordering::AcqRel);
        ActiveGuard { registry, id }
    }

    fn register(&self, id: u64, abort: tokio::task::AbortHandle) {
        self.lock_entries().push(RegistryEntry { id, abort });
    }

    fn finish(&self, id: u64) {
        self.lock_entries().retain(|entry| entry.id != id);
        self.active.fetch_sub(1, Ordering::AcqRel);
        self.finished.notify_waiters();
    }

    fn abort_all(&self) -> usize {
        let entries = self.lock_entries();
        let mut forced = 0;
        for entry in entries.iter() {
            if !entry.abort.is_finished() {
                entry.abort.abort();
                forced += 1;
            }
        }
        forced
    }

    async fn wait_zero(&self, duration: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + duration;
        loop {
            if self.active.load(Ordering::Acquire) == 0 {
                return true;
            }
            let notified = self.finished.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.active.load(Ordering::Acquire) == 0 {
                return true;
            }
            if tokio::time::timeout_at(deadline, notified).await.is_err() {
                return self.active.load(Ordering::Acquire) == 0;
            }
        }
    }

    fn spawn<F, T>(self: &Arc<Self>, future: F) -> tokio::task::JoinHandle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        let guard = self.reserve();
        let id = guard.id;
        let (start_tx, start_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            // The guard is captured by the future before spawning. Dropping an
            // unpolled aborted future therefore still releases registration.
            let _guard = guard;
            let _ = start_rx.await;
            future.await
        });
        self.register(id, join.abort_handle());
        let _ = start_tx.send(());
        join
    }
}

struct RuntimeShared {
    lifecycle: AtomicU8,
    admission: Mutex<()>,
    cancellation: CancellationToken,
    registry: Arc<TaskRegistry>,
}

impl RuntimeShared {
    fn lock_admission(&self) -> MutexGuard<'_, ()> {
        self.admission
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn begin_shutdown(&self) -> bool {
        let _gate = self.lock_admission();
        if self.lifecycle.load(Ordering::Acquire) == RUNNING {
            self.lifecycle.store(SHUTTING_DOWN, Ordering::Release);
            self.cancellation.request();
            true
        } else {
            false
        }
    }

    fn is_running(&self) -> bool {
        self.lifecycle.load(Ordering::Acquire) == RUNNING
    }
}

/// A framework-neutral task handle.
pub struct TaskHandle {
    cancel: CancelHandle,
    join: tokio::task::JoinHandle<Result<(), TaskFailure>>,
}

impl TaskHandle {
    /// Returns the cancellation handle without exposing Tokio.
    pub fn cancellation(&self) -> CancelHandle {
        self.cancel.clone()
    }

    /// Waits for the task and maps framework failures to owned failures.
    pub async fn join(self) -> Result<(), TaskFailure> {
        match self.join.await {
            Ok(result) => result,
            Err(error) if error.is_panic() => Err(TaskFailure::Panicked),
            Err(_) => Err(TaskFailure::Cancelled),
        }
    }
}

/// A framework-neutral handle for a supervised task.
pub struct SupervisedHandle {
    cancel: CancelHandle,
    join: tokio::task::JoinHandle<Result<SupervisionOutcome, TaskFailure>>,
}

impl SupervisedHandle {
    /// Returns the cancellation handle without exposing Tokio.
    pub fn cancellation(&self) -> CancelHandle {
        self.cancel.clone()
    }

    /// Waits for supervision to reach a terminal outcome.
    pub async fn join(self) -> Result<SupervisionOutcome, TaskFailure> {
        match self.join.await {
            Ok(result) => result,
            Err(error) if error.is_panic() => Err(TaskFailure::Panicked),
            Err(_) => Err(TaskFailure::Cancelled),
        }
    }
}

/// Typed shutdown terminal disposition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownDisposition {
    /// Every owned task stopped during cooperative grace.
    Graceful,
    /// Forced abortion was required and all owned tasks then stopped.
    Forced,
    /// Owned work still could not be proven stopped after forced abortion.
    Incomplete,
}

/// The result of ordered shutdown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShutdownOutcome {
    /// Typed shutdown disposition.
    pub disposition: ShutdownDisposition,
    /// Number of owned tasks forcibly aborted.
    pub forced_tasks: usize,
    /// Whether no owned task remained after shutdown.
    pub no_orphans: bool,
}

/// A framework-neutral request handle for sticky runtime shutdown.
#[derive(Clone)]
pub struct ShutdownHandle {
    shared: Arc<RuntimeShared>,
}

impl ShutdownHandle {
    /// Requests shutdown and closes future admission. Returns true only once.
    pub fn request(&self) -> bool {
        self.shared.begin_shutdown()
    }

    /// Returns true after shutdown admission closure begins.
    pub fn is_requested(&self) -> bool {
        !self.shared.is_running()
    }
}

/// ELIOT-owned bounded runtime facade.
pub struct Runtime {
    config: RuntimeConfig,
    data_permits: Arc<Semaphore>,
    control_permits: Arc<Semaphore>,
    shared: Arc<RuntimeShared>,
    sink: Option<Arc<dyn ObservationSink>>,
}

impl Runtime {
    /// Creates a facade with caller-supplied fairness and reserve parameters.
    pub fn new(
        config: RuntimeConfig,
        sink: Option<Arc<dyn ObservationSink>>,
    ) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(Self {
            data_permits: Arc::new(Semaphore::new(config.concurrency)),
            control_permits: Arc::new(Semaphore::new(config.control_concurrency_reserve)),
            shared: Arc::new(RuntimeShared {
                lifecycle: AtomicU8::new(RUNNING),
                admission: Mutex::new(()),
                cancellation: CancellationToken::root(),
                registry: Arc::new(TaskRegistry::new()),
            }),
            config,
            sink,
        })
    }

    /// Creates a mailbox using this runtime's bounded fairness policy.
    pub fn mailbox<T>(&self) -> Result<(Mailbox<T>, MailboxReceiver<T>), ConfigError> {
        Mailbox::bounded(
            self.config.mailbox_capacity,
            self.config.control_reserve,
            self.config.fairness_quantum,
        )
    }

    /// Spawns ordinary data work.
    pub fn spawn<F, Fut>(
        &self,
        subject: impl Into<String>,
        factory: F,
    ) -> SpawnDisposition<TaskHandle>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TaskFailure>> + Send + 'static,
    {
        self.spawn_in(ExecutionClass::Data, subject, factory)
    }

    /// Spawns protected control work without consuming data permits.
    pub fn spawn_control<F, Fut>(
        &self,
        subject: impl Into<String>,
        factory: F,
    ) -> SpawnDisposition<TaskHandle>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TaskFailure>> + Send + 'static,
    {
        self.spawn_in(ExecutionClass::ProtectedControl, subject, factory)
    }

    /// Spawns work in an explicit execution lane.
    pub fn spawn_in<F, Fut>(
        &self,
        class: ExecutionClass,
        subject: impl Into<String>,
        factory: F,
    ) -> SpawnDisposition<TaskHandle>
    where
        F: FnOnce(CancellationToken) -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), TaskFailure>> + Send + 'static,
    {
        let _gate = self.shared.lock_admission();
        if !self.shared.is_running() {
            return SpawnDisposition::DeniedShuttingDown;
        }

        let subject = subject.into();
        let permits = match class {
            ExecutionClass::Data => self.data_permits.clone(),
            ExecutionClass::ProtectedControl => self.control_permits.clone(),
        };
        let token = self.shared.cancellation.child();
        let work_token = token.clone();
        let sink = self.sink.clone();
        let join = self.shared.registry.spawn(async move {
            let permit = tokio::select! {
                () = work_token.cancelled() => return Err(TaskFailure::Cancelled),
                permit = permits.acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => return Err(TaskFailure::Cancelled),
                },
            };
            work_token.checkpoint()?;
            let Ok(future) = catch_unwind(AssertUnwindSafe(|| factory(work_token.clone()))) else {
                return Err(TaskFailure::Panicked);
            };
            let result = match CatchUnwindFuture::new(future).await {
                Ok(result) => result,
                Err(()) => Err(TaskFailure::Panicked),
            };
            drop(permit);
            if let Err(error) = &result {
                observe_safely(
                    sink.as_ref(),
                    RuntimeObservation {
                        kind: ObservationKind::TaskProgress,
                        subject,
                        detail: format!("task ended: {error:?}"),
                        state: ServiceProcessState::Stopped,
                    },
                );
            }
            result
        });
        let cancel = CancelHandle {
            token,
            abort: join.abort_handle(),
        };
        SpawnDisposition::Admitted(TaskHandle { cancel, join })
    }

    /// Requests cooperative shutdown, then forcibly aborts only after grace.
    pub async fn shutdown(&self) -> ShutdownOutcome {
        self.shared.begin_shutdown();
        let graceful = self
            .shared
            .registry
            .wait_zero(self.config.shutdown_grace)
            .await;
        let forced_tasks = if graceful {
            0
        } else {
            self.shared.registry.abort_all()
        };
        let no_orphans = if graceful {
            true
        } else {
            self.shared
                .registry
                .wait_zero(self.config.shutdown_grace)
                .await
        };
        self.shared.lifecycle.store(TERMINATED, Ordering::Release);
        let disposition = if graceful {
            ShutdownDisposition::Graceful
        } else if no_orphans {
            ShutdownDisposition::Forced
        } else {
            ShutdownDisposition::Incomplete
        };
        ShutdownOutcome {
            disposition,
            forced_tasks,
            no_orphans,
        }
    }

    /// Returns the configured fairness quantum.
    pub const fn fairness_quantum(&self) -> usize {
        self.config.fairness_quantum
    }

    /// Returns currently unused capacity for one execution lane.
    pub fn available_capacity(&self, class: ExecutionClass) -> usize {
        match class {
            ExecutionClass::Data => self.data_permits.available_permits(),
            ExecutionClass::ProtectedControl => self.control_permits.available_permits(),
        }
    }

    /// Delivers one optional observation with panic containment and typed status.
    pub fn observe(&self, observation: RuntimeObservation) -> ObservationDisposition {
        observe_safely(self.sink.as_ref(), observation)
    }

    /// Creates a runtime-owned supervisor with explicit restart parameters.
    pub fn supervisor(&self, strategy: SupervisionStrategy) -> Supervisor {
        Supervisor {
            strategy,
            budget: self.config.restart_budget,
            window: self.config.restart_window,
            backoff: self.config.restart_backoff,
            shared: self.shared.clone(),
            permits: self.data_permits.clone(),
            sink: self.sink.clone(),
        }
    }

    /// Returns a shutdown request handle without exposing Tokio.
    pub fn shutdown_handle(&self) -> ShutdownHandle {
        ShutdownHandle {
            shared: self.shared.clone(),
        }
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shared.begin_shutdown();
        self.shared.registry.abort_all();
    }
}

/// Restart coordinator whose task and attempt future are owned by the runtime.
pub struct Supervisor {
    strategy: SupervisionStrategy,
    budget: usize,
    window: Duration,
    backoff: Duration,
    shared: Arc<RuntimeShared>,
    permits: Arc<Semaphore>,
    sink: Option<Arc<dyn ObservationSink>>,
}

impl Supervisor {
    /// Returns the selected restart scope.
    pub const fn strategy(&self) -> SupervisionStrategy {
        self.strategy
    }

    /// Returns ordered child indexes affected by a failure.
    pub fn affected_children(&self, failed_index: usize, child_count: usize) -> Vec<usize> {
        if failed_index >= child_count {
            return Vec::new();
        }
        match self.strategy {
            SupervisionStrategy::OneForOne => vec![failed_index],
            SupervisionStrategy::RestForOne => (failed_index..child_count).collect(),
            SupervisionStrategy::OneForAll => (0..child_count).collect(),
        }
    }

    /// Starts a restartable factory with rolling budget, backoff, and quarantine.
    ///
    /// Each attempt future is polled inside the registered supervisor task, so
    /// cancellation or forced abortion drops the nested attempt synchronously;
    /// no detached Tokio child is created.
    pub fn spawn<F, Fut>(
        &self,
        subject: impl Into<String>,
        class: ChildClass,
        factory: F,
    ) -> SpawnDisposition<SupervisedHandle>
    where
        F: Fn(CancellationToken) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), TaskFailure>> + Send + 'static,
    {
        let _gate = self.shared.lock_admission();
        if !self.shared.is_running() {
            return SpawnDisposition::DeniedShuttingDown;
        }

        let subject = subject.into();
        let budget = self.budget;
        let window = self.window;
        let backoff = self.backoff;
        let sink = self.sink.clone();
        let permits = self.permits.clone();
        let token = self.shared.cancellation.child();
        let supervisor_token = token.clone();
        let join = self.shared.registry.spawn(async move {
            let permit = tokio::select! {
                () = supervisor_token.cancelled() => return Err(TaskFailure::Cancelled),
                permit = permits.acquire_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => return Err(TaskFailure::Cancelled),
                },
            };
            let mut failures = Vec::new();
            let mut delay = backoff;
            let result = loop {
                supervisor_token.checkpoint()?;
                let attempt_token = supervisor_token.child();
                let Ok(future) = catch_unwind(AssertUnwindSafe(|| factory(attempt_token.clone())))
                else {
                    if restart_or_quarantine(
                        &mut failures,
                        budget,
                        window,
                        sink.as_ref(),
                        &subject,
                        class,
                        &TaskFailure::Panicked,
                    ) {
                        break Ok(SupervisionOutcome::Quarantined);
                    }
                    tokio::select! {
                        () = supervisor_token.cancelled() => break Err(TaskFailure::Cancelled),
                        () = tokio::time::sleep(delay) => {}
                    }
                    delay = delay.saturating_mul(2);
                    continue;
                };
                let attempt_result = tokio::select! {
                    () = supervisor_token.cancelled() => Err(TaskFailure::Cancelled),
                    value = CatchUnwindFuture::new(future) => match value {
                        Ok(value) => value,
                        Err(()) => Err(TaskFailure::Panicked),
                    },
                };
                match attempt_result {
                    Ok(()) => break Ok(SupervisionOutcome::Completed),
                    Err(TaskFailure::Cancelled) => break Err(TaskFailure::Cancelled),
                    Err(error) => {
                        if restart_or_quarantine(
                            &mut failures,
                            budget,
                            window,
                            sink.as_ref(),
                            &subject,
                            class,
                            &error,
                        ) {
                            break Ok(SupervisionOutcome::Quarantined);
                        }
                        tokio::select! {
                            () = supervisor_token.cancelled() => break Err(TaskFailure::Cancelled),
                            () = tokio::time::sleep(delay) => {}
                        }
                        delay = delay.saturating_mul(2);
                    }
                }
            };
            drop(permit);
            result
        });
        let cancel = CancelHandle {
            token,
            abort: join.abort_handle(),
        };
        SpawnDisposition::Admitted(SupervisedHandle { cancel, join })
    }
}

fn restart_or_quarantine(
    failures: &mut Vec<Instant>,
    budget: usize,
    window: Duration,
    sink: Option<&Arc<dyn ObservationSink>>,
    subject: &str,
    class: ChildClass,
    error: &TaskFailure,
) -> bool {
    let now = Instant::now();
    failures.retain(|started| now.duration_since(*started) <= window);
    if failures.len() >= budget {
        observe_safely(
            sink,
            RuntimeObservation {
                kind: ObservationKind::FailureOrRepair,
                subject: subject.to_owned(),
                detail: format!("{class:?} quarantined after restart budget"),
                state: ServiceProcessState::Quarantined,
            },
        );
        true
    } else {
        failures.push(now);
        observe_safely(
            sink,
            RuntimeObservation {
                kind: ObservationKind::FailureOrRepair,
                subject: subject.to_owned(),
                detail: format!("{class:?} restarting after {error:?}"),
                state: ServiceProcessState::RestartWait,
            },
        );
        false
    }
}

/// Converts a P-01 result to a framework-neutral signal.
pub fn platform_result<T>(result: PortOutcome<T>) -> RuntimeResult {
    match result {
        PortOutcome::Known(_) => RuntimeResult::Completed,
        PortOutcome::Partial { .. } | PortOutcome::Unknown(_) => RuntimeResult::Degraded,
        PortOutcome::Error(error) => RuntimeResult::Failed(match error {
            PortError::InvalidText { .. }
            | PortError::Duplicate { .. }
            | PortError::Ambiguous { .. }
            | PortError::InvalidFence
            | PortError::InvalidRequestMetadata
            | PortError::InvalidServiceProcessRecord
            | PortError::InvalidPath => RuntimeFailure::InvalidInput,
            PortError::IdentityConflict => RuntimeFailure::Conflict,
            PortError::Provider(provider)
            | PortError::ProviderReference {
                error: provider, ..
            } => provider_runtime_failure(provider),
        }),
    }
}

fn provider_runtime_failure(provider: ProviderError) -> RuntimeFailure {
    match provider.code {
        ProviderErrorCode::Unavailable => RuntimeFailure::Unavailable,
        ProviderErrorCode::PermissionDenied => RuntimeFailure::PermissionDenied,
        ProviderErrorCode::InvalidRequest => RuntimeFailure::InvalidInput,
        ProviderErrorCode::Timeout => RuntimeFailure::Timeout,
        ProviderErrorCode::Failed => RuntimeFailure::ProviderFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_platform::ProviderError;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::Barrier;
    use tokio::time::timeout;

    fn config() -> RuntimeConfig {
        RuntimeConfig {
            mailbox_capacity: 8,
            control_reserve: 8,
            concurrency: 1,
            control_concurrency_reserve: 1,
            fairness_quantum: 2,
            restart_budget: 2,
            restart_window: Duration::from_secs(1),
            restart_backoff: Duration::from_millis(1),
            shutdown_grace: Duration::from_millis(20),
        }
    }

    fn must<T, E: std::fmt::Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("expected success: {error:?}"),
        }
    }

    fn must_some<T>(value: Option<T>) -> T {
        match value {
            Some(value) => value,
            None => panic!("expected value"),
        }
    }

    fn admitted<H>(disposition: SpawnDisposition<H>) -> H {
        must_some(disposition.into_handle())
    }

    #[tokio::test]
    async fn mailbox_fairness_bounds_both_lane_streaks() {
        let (mailbox, mut receiver) = must(Mailbox::bounded(8, 8, 2));
        for value in 0..4 {
            assert_eq!(mailbox.try_send(value), SendResult::Accepted);
            assert_eq!(
                mailbox.try_send_control(ControlSignal::Cancel),
                SendResult::Accepted
            );
        }

        let mut lanes = Vec::new();
        for _ in 0..8 {
            lanes.push(match must_some(receiver.recv().await) {
                MailboxItem::Data(_) => Lane::Data,
                MailboxItem::Control(_) => Lane::Control,
            });
        }
        assert_eq!(
            lanes,
            vec![
                Lane::Control,
                Lane::Control,
                Lane::Data,
                Lane::Data,
                Lane::Control,
                Lane::Control,
                Lane::Data,
                Lane::Data,
            ]
        );
    }

    #[tokio::test]
    async fn data_saturation_cannot_starve_control_execution_reserve() {
        let runtime = must(Runtime::new(config(), None));
        let barrier = Arc::new(Barrier::new(2));
        let first_barrier = barrier.clone();
        let first = admitted(runtime.spawn("data-1", move |_| async move {
            first_barrier.wait().await;
            std::future::pending::<Result<(), TaskFailure>>().await
        }));
        barrier.wait().await;
        assert_eq!(runtime.available_capacity(ExecutionClass::Data), 0);

        let second_started = Arc::new(AtomicBool::new(false));
        let second_flag = second_started.clone();
        let _second = admitted(runtime.spawn("data-2", move |_| async move {
            second_flag.store(true, Ordering::Release);
            Ok(())
        }));
        let control_ran = Arc::new(AtomicBool::new(false));
        let control_flag = control_ran.clone();
        let control = admitted(runtime.spawn_control("control", move |_| async move {
            control_flag.store(true, Ordering::Release);
            Ok(())
        }));
        assert_eq!(control.join().await, Ok(()));
        assert!(control_ran.load(Ordering::Acquire));
        assert!(!second_started.load(Ordering::Acquire));
        first.cancellation().force_abort();
        let _ = first.join().await;
        let _ = runtime.shutdown().await;
    }

    #[tokio::test]
    async fn cancellation_is_sticky_even_before_first_poll() {
        let runtime = must(Runtime::new(config(), None));
        let handle = admitted(runtime.spawn("early-cancel", |token| async move {
            token.cancelled().await;
            token.checkpoint()
        }));
        assert_eq!(
            handle.cancellation().cancel(),
            CancellationDisposition::Requested
        );
        assert_eq!(handle.join().await, Err(TaskFailure::Cancelled));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn immediate_force_abort_before_first_poll_releases_registration() {
        let runtime = must(Runtime::new(config(), None));
        let polled = Arc::new(AtomicBool::new(false));
        let poll_flag = polled.clone();
        let handle = admitted(runtime.spawn("pre-poll-abort", move |_| async move {
            poll_flag.store(true, Ordering::Release);
            Ok(())
        }));
        assert!(!polled.load(Ordering::Acquire));
        assert_eq!(
            handle.cancellation().force_abort(),
            CancellationDisposition::Forced
        );
        assert_eq!(handle.join().await, Err(TaskFailure::Cancelled));
        assert!(!polled.load(Ordering::Acquire));
        assert_eq!(runtime.shared.registry.active.load(Ordering::Acquire), 0);
        let outcome = runtime.shutdown().await;
        assert!(outcome.no_orphans);
        assert_ne!(outcome.disposition, ShutdownDisposition::Incomplete);
    }

    #[tokio::test]
    async fn shutdown_is_sticky_and_denies_late_spawn() {
        let runtime = must(Runtime::new(config(), None));
        let shutdown = runtime.shutdown_handle();
        assert!(shutdown.request());
        assert!(!shutdown.request());
        assert!(matches!(
            runtime.spawn("late", |_| async { Ok(()) }),
            SpawnDisposition::DeniedShuttingDown
        ));
        assert_eq!(
            runtime.shutdown().await.disposition,
            ShutdownDisposition::Graceful
        );
    }

    struct DropProbe(Arc<AtomicBool>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    #[tokio::test]
    async fn supervised_attempt_is_nested_and_shutdown_leaves_no_orphan() {
        let runtime = must(Runtime::new(config(), None));
        let dropped = Arc::new(AtomicBool::new(false));
        let drop_flag = dropped.clone();
        let _handle = admitted(runtime.supervisor(SupervisionStrategy::OneForOne).spawn(
            "nested",
            ChildClass::Worker,
            move |_| {
                let probe = DropProbe(drop_flag.clone());
                async move {
                    let _probe = probe;
                    std::future::pending::<Result<(), TaskFailure>>().await
                }
            },
        ));
        tokio::task::yield_now().await;
        let outcome = runtime.shutdown().await;
        assert!(outcome.no_orphans);
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn poisoned_registry_is_recovered_without_runtime_panic() {
        let runtime = must(Runtime::new(config(), None));
        let registry = runtime.shared.registry.clone();
        let _ = catch_unwind(AssertUnwindSafe(|| {
            let _guard = must(registry.entries.lock());
            panic!("poison registry");
        }));
        let task = admitted(runtime.spawn("after-poison", |_| async { Ok(()) }));
        assert_eq!(task.join().await, Ok(()));
        assert!(runtime.shutdown().await.no_orphans);
    }

    struct PanicSink;

    impl ObservationSink for PanicSink {
        fn observe(&self, _observation: RuntimeObservation) {
            panic!("sink panic");
        }
    }

    #[tokio::test]
    async fn factory_future_and_sink_panics_are_contained_as_typed_outcomes() {
        let runtime = must(Runtime::new(config(), Some(Arc::new(PanicSink))));
        assert_eq!(
            runtime.observe(RuntimeObservation {
                kind: ObservationKind::TaskProgress,
                subject: "sink-probe".into(),
                detail: "typed containment".into(),
                state: ServiceProcessState::Ready,
            }),
            ObservationDisposition::SinkPanicked
        );
        let factory_panic = admitted(runtime.spawn("factory", |_| -> std::future::Ready<_> {
            panic!("factory panic")
        }));
        assert_eq!(factory_panic.join().await, Err(TaskFailure::Panicked));

        let future_panic = admitted(runtime.spawn("future", |_| async {
            tokio::task::yield_now().await;
            panic!("future panic")
        }));
        assert_eq!(future_panic.join().await, Err(TaskFailure::Panicked));

        let explicit_failure = admitted(runtime.spawn("sink", |_| async {
            Err(TaskFailure::Failed("expected".into()))
        }));
        assert_eq!(
            explicit_failure.join().await,
            Err(TaskFailure::Failed("expected".into()))
        );
    }

    #[tokio::test]
    async fn supervision_contains_factory_and_future_panics_then_quarantines() {
        let runtime = must(Runtime::new(config(), None));
        let attempts = Arc::new(AtomicUsize::new(0));
        let source = attempts.clone();
        let handle = admitted(runtime.supervisor(SupervisionStrategy::OneForOne).spawn(
            "restartable",
            ChildClass::Worker,
            move |_| {
                let attempt = source.fetch_add(1, Ordering::Relaxed);
                assert_ne!(attempt, 0, "first factory panic");
                async move {
                    assert_ne!(attempt, 1, "second future panic");
                    Err(TaskFailure::Failed("third failure".into()))
                }
            },
        ));
        assert_eq!(handle.join().await, Ok(SupervisionOutcome::Quarantined));
        assert_eq!(attempts.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn forced_shutdown_reports_typed_disposition() {
        let mut cfg = config();
        cfg.shutdown_grace = Duration::from_millis(1);
        let runtime = must(Runtime::new(cfg, None));
        let entered = Arc::new(AtomicBool::new(false));
        let entered_flag = entered.clone();
        let _task = admitted(runtime.spawn("blocking-poll", move |_| async move {
            entered_flag.store(true, Ordering::Release);
            std::future::pending::<Result<(), TaskFailure>>().await
        }));
        while !entered.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
        let outcome = runtime.shutdown().await;
        assert_eq!(outcome.disposition, ShutdownDisposition::Forced);
        assert_eq!(outcome.forced_tasks, 1);
        assert!(outcome.no_orphans);
    }

    #[test]
    fn supervision_scopes_and_contract_projection_are_explicit() {
        let runtime = must(Runtime::new(config(), None));
        assert_eq!(runtime.fairness_quantum(), 2);
        assert_eq!(
            platform_result(PortOutcome::known(())),
            RuntimeResult::Completed
        );
        assert_eq!(
            runtime
                .supervisor(SupervisionStrategy::OneForOne)
                .affected_children(1, 4),
            vec![1]
        );
        assert_eq!(
            runtime
                .supervisor(SupervisionStrategy::RestForOne)
                .affected_children(1, 4),
            vec![1, 2, 3]
        );
        assert_eq!(
            runtime
                .supervisor(SupervisionStrategy::OneForAll)
                .affected_children(1, 4),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn platform_errors_preserve_non_capacity_classification() {
        let cases = vec![
            (
                PortError::InvalidText {
                    field: "name".into(),
                },
                RuntimeFailure::InvalidInput,
            ),
            (PortError::IdentityConflict, RuntimeFailure::Conflict),
            (
                PortError::Provider(ProviderError {
                    code: ProviderErrorCode::PermissionDenied,
                    retryable: false,
                }),
                RuntimeFailure::PermissionDenied,
            ),
            (
                PortError::Provider(ProviderError {
                    code: ProviderErrorCode::Unavailable,
                    retryable: true,
                }),
                RuntimeFailure::Unavailable,
            ),
            (
                PortError::Provider(ProviderError {
                    code: ProviderErrorCode::Timeout,
                    retryable: true,
                }),
                RuntimeFailure::Timeout,
            ),
            (
                PortError::Provider(ProviderError {
                    code: ProviderErrorCode::Failed,
                    retryable: false,
                }),
                RuntimeFailure::ProviderFailed,
            ),
            (
                PortError::Provider(ProviderError {
                    code: ProviderErrorCode::InvalidRequest,
                    retryable: false,
                }),
                RuntimeFailure::InvalidInput,
            ),
        ];

        for (error, expected) in cases {
            let actual = platform_result::<()>(PortOutcome::Error(error));
            assert_eq!(actual, RuntimeResult::Failed(expected));
            assert_ne!(actual, RuntimeResult::Saturated);
        }
    }

    #[test]
    fn provider_reference_maps_without_changing_runtime_classification() {
        let outcome = PortOutcome::<()>::Error(PortError::ProviderReference {
            error: ProviderError {
                code: ProviderErrorCode::Failed,
                retryable: false,
            },
            reference: eliot_platform::PlatformHandle::new(
                "installer-root-win32-v2:create-directory:0000abcd",
            )
            .unwrap_or_else(|_| unreachable!()),
        });
        assert_eq!(
            platform_result(outcome),
            RuntimeResult::Failed(RuntimeFailure::ProviderFailed)
        );
    }

    #[test]
    fn public_source_does_not_name_tokio_in_public_signatures() {
        let source = include_str!("lib.rs");
        for line in source
            .lines()
            .filter(|line| line.trim_start().starts_with("pub "))
        {
            assert!(!line.contains("tokio::"), "public Tokio leak: {line}");
        }
    }

    #[tokio::test]
    async fn mailbox_control_reserve_survives_data_saturation() {
        let (mailbox, mut receiver) = must(Mailbox::bounded(1, 1, 1));
        assert_eq!(mailbox.try_send(1), SendResult::Accepted);
        assert_eq!(mailbox.try_send(2), SendResult::Saturated);
        assert_eq!(
            mailbox.try_send_control(ControlSignal::Shutdown),
            SendResult::Accepted
        );
        assert_eq!(
            must(timeout(Duration::from_millis(20), receiver.recv()).await),
            Some(MailboxItem::Control(ControlSignal::Shutdown))
        );
    }
}
