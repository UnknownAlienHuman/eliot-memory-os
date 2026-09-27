//! Kernel-owned persisted safe-shutdown/drain state machine (I14.23).
//!
//! Architecture: A13.2 Kernel and failure domains; ARCH-RES-01 fail locally,
//! recover globally; ARCH-RES-04 degradation is visible and local.
//! Implementation: I14.23 safe shutdown; I1.5 drain linearization
//! (`DrainCommitRecord`); I14.21 unknown-commit recovery precedent (pending
//! work is retained, never discarded).
//!
//! This module owns the Kernel slice of the shutdown sequence named by
//! I14.23: ordered persisted phases, the `DrainCommit` linearization decision,
//! the receipt-reconciliation gate, the canonical-data lease-zero gate, the
//! reverse-dependency quiescence order, the intentional/incomplete durable
//! terminals, and the wake/attach race table. Effects stay with their existing
//! owners: the composition root drives service transitions, the ORS gateway
//! reconciles staged rows, Host persists the `DrainCommitRecord` into its
//! journal, and Watchdog observes through the journal.
//!
//! Boundary to `eliot-host-state` (which this binary must not depend on and
//! must not move types across): [`DrainWakeDisposition`] mirrors the
//! `WakeDisposition` wire vocabulary as evidence strings, and
//! [`DrainCommitDecision`] documents the exact field contract Host carries
//! into `DrainCommitRecord` through its journal helper. The phase vocabulary
//! here is Kernel-owned; `DrainState` (`Requested`/`Draining`/`Cancelled`/
//! `Failed`) stays Host-journal owned.
//!
//! Handoffs (recorded, not implemented here): audit/outbox flush is
//! Governor/`eliotd`-owned — Kernel flushes ORS staged rows and records the
//! Governor flush as awaited via daemon quiescence; canonical-store internals
//! are store-bridge-owned — Kernel proves the lease-zero precondition and
//! records the store-stop request for Host to execute; job checkpoint
//! semantics are Governor-owned — Kernel observes the daemon contour and
//! closes admission through the existing `Draining` service gate.
//! I14.23 has no phase fields in `eliot-host-state` `DrainState`
//! (`Intentional`/`Incomplete` live here, kernel-side); no `model.rs` change
//! is made by this slice.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Bounded wait for in-flight receipt reconciliation before drain gives up
/// and records incomplete shutdown. Owns only drain timing; runtime task
/// grace stays with `RuntimeConfig::shutdown_grace`.
pub(crate) const DRAIN_RECEIPT_DEADLINE: Duration = Duration::from_secs(5);

/// Durable file carrying the Kernel drain state across restarts, so recovery
/// distinguishes an intentional stop (terminal persisted) from an interrupted
/// drain (requested without terminal; pending retained).
const DRAIN_STATE_FILE: &str = "kernel-shutdown-drain.json";
const DRAIN_STATE_VERSION: u32 = 1;

/// Poll interval for the bounded receipt-reconciliation wait.
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(10);

static DRAIN_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn durable_replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)?;
    File::open(destination)?.sync_all()?;
    #[cfg(unix)]
    {
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// F-LOG-KERNEL-4 style observation for the shutdown boundary: fixed event
/// plus bounded outcome only, never digests, epochs, or owner error strings.
fn observe_shutdown(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "shutdown drain observation"
    );
}

/// Ordered I14.23 shutdown phases. Discriminant order is the execution order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ShutdownPhase {
    AdmissionsClosed,
    AuthorityRevoked,
    JobsCheckpointed,
    CanonicalDrainReceiptsReconciled,
    FlushesCompleted,
    ModulesQuiescedReverse,
    StoreStopLeaseZero,
    IntentionalPublished,
}

impl ShutdownPhase {
    /// Every phase in execution order.
    pub(crate) const ORDERED: [Self; 8] = [
        Self::AdmissionsClosed,
        Self::AuthorityRevoked,
        Self::JobsCheckpointed,
        Self::CanonicalDrainReceiptsReconciled,
        Self::FlushesCompleted,
        Self::ModulesQuiescedReverse,
        Self::StoreStopLeaseZero,
        Self::IntentionalPublished,
    ];

    /// Phases that must precede the [`ShutdownDrainCoordinator::commit_drain`]
    /// linearization point.
    pub(crate) const PRE_COMMIT: [Self; 7] = [
        Self::AdmissionsClosed,
        Self::AuthorityRevoked,
        Self::JobsCheckpointed,
        Self::CanonicalDrainReceiptsReconciled,
        Self::FlushesCompleted,
        Self::ModulesQuiescedReverse,
        Self::StoreStopLeaseZero,
    ];

    pub(crate) const fn order(self) -> u8 {
        match self {
            Self::AdmissionsClosed => 0,
            Self::AuthorityRevoked => 1,
            Self::JobsCheckpointed => 2,
            Self::CanonicalDrainReceiptsReconciled => 3,
            Self::FlushesCompleted => 4,
            Self::ModulesQuiescedReverse => 5,
            Self::StoreStopLeaseZero => 6,
            Self::IntentionalPublished => 7,
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AdmissionsClosed => "admissions-closed",
            Self::AuthorityRevoked => "authority-revoked",
            Self::JobsCheckpointed => "jobs-checkpointed",
            Self::CanonicalDrainReceiptsReconciled => "canonical-drain-receipts-reconciled",
            Self::FlushesCompleted => "flushes-completed",
            Self::ModulesQuiescedReverse => "modules-quiesced-reverse",
            Self::StoreStopLeaseZero => "store-stop-lease-zero",
            Self::IntentionalPublished => "intentional-published",
        }
    }
}

/// Wake/attach race disposition, mirroring the `WakeDisposition` wire
/// vocabulary (`CANCEL_DRAIN` / `QUEUE_NEXT_GENERATION` / `REJECT_STALE`)
/// owned by `eliot-host-state`. `Proceed` covers "no drain in progress" and
/// never reaches the journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum DrainWakeDisposition {
    Proceed,
    CancelDrain,
    QueueNextGeneration,
    RejectStale,
}

impl DrainWakeDisposition {
    /// True for the post-linearization dispositions that must never operate
    /// with a pre-drain lease or handle.
    pub(crate) const fn fences_old_authority(self) -> bool {
        matches!(self, Self::QueueNextGeneration | Self::RejectStale)
    }
}

/// Durable terminal of one drain generation. `Incomplete` retains the pending
/// work that deadline expiry refused to discard.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum ShutdownTerminal {
    Intentional,
    Incomplete { pending: Vec<String> },
}

impl ShutdownTerminal {
    pub(crate) const fn as_str(&self) -> &'static str {
        match self {
            Self::Intentional => "intentional-shutdown",
            Self::Incomplete { .. } => "incomplete-shutdown",
        }
    }

    pub(crate) fn pending(&self) -> Vec<String> {
        match self {
            Self::Intentional => Vec::new(),
            Self::Incomplete { pending } => pending.clone(),
        }
    }
}

/// Kernel-owned `DrainCommit` linearization decision.
///
/// Field contract carried by Host into `DrainCommitRecord` through its journal
/// helper (no cross-binary type import): `generation` feeds
/// `drain_generation` correlation, `lease_and_pending_snapshot` feeds
/// `lease_and_pending_operation_snapshot` (empty here — the reconciliation
/// gate proved it), `authority_epochs_fenced` feeds
/// `authority_epochs_fenced`, `branches_to_stop` feeds
/// `processes_modules_and_store_branches_to_stop`, `wake_disposition` feeds
/// `wake_during_drain_disposition`, `irreversible_stage` feeds
/// `irreversible_stage`, and `recovery_owner` feeds `recovery_owner`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct DrainCommitDecision {
    pub(crate) generation: String,
    pub(crate) lease_and_pending_snapshot: Vec<String>,
    pub(crate) authority_epochs_fenced: Vec<String>,
    pub(crate) branches_to_stop: Vec<String>,
    pub(crate) wake_disposition: DrainWakeDisposition,
    pub(crate) irreversible_stage: String,
    pub(crate) recovery_owner: String,
}

/// Early halt of the ordered drain: the reason plus every pending item the
/// incomplete-shutdown terminal must retain.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DrainHalt {
    pub(crate) reason: &'static str,
    pub(crate) pending: Vec<String>,
}

impl DrainHalt {
    pub(crate) const fn new(reason: &'static str) -> Self {
        Self {
            reason,
            pending: Vec::new(),
        }
    }

    pub(crate) fn with_pending(reason: &'static str, pending: Vec<String>) -> Self {
        Self { reason, pending }
    }
}

/// Read-only publication consumed by Host (into `DrainCommitRecord`) and by
/// Watchdog (through the Host journal) over their existing control paths.
#[allow(
    clippy::struct_excessive_bools,
    reason = "the publication is a coherent one-reader snapshot; splitting it would fork the observed state"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShutdownPublication {
    pub(crate) generation: String,
    pub(crate) requested: bool,
    pub(crate) phases_completed: Vec<String>,
    pub(crate) committed: bool,
    pub(crate) cancelled: bool,
    pub(crate) recovered_interrupted: bool,
    pub(crate) terminal: Option<String>,
    pub(crate) pending: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableDrainState {
    version: u32,
    generation: String,
    requested: bool,
    cancelled: bool,
    phases: Vec<(u8, String)>,
    committed: Option<DrainCommitDecision>,
    terminal: Option<ShutdownTerminal>,
    pending: Vec<String>,
}

#[derive(Clone)]
struct CoordinatorState {
    generation: String,
    requested: bool,
    recovered_interrupted: bool,
    cancelled: bool,
    phases: BTreeMap<u8, String>,
    committed: Option<DrainCommitDecision>,
    terminal: Option<ShutdownTerminal>,
    pending: BTreeSet<String>,
}

impl CoordinatorState {
    fn fresh(generation: String) -> Self {
        Self {
            generation,
            requested: false,
            recovered_interrupted: false,
            cancelled: false,
            phases: BTreeMap::new(),
            committed: None,
            terminal: None,
            pending: BTreeSet::new(),
        }
    }
}

/// Kernel-owned persisted shutdown/drain coordinator.
///
/// One instance per `work_root`, shared process-wide through
/// [`coordinator_for`] so the control plane (`request_shutdown`,
/// wake/attach race) and the composition root (`shutdown`) observe one
/// durable state without growing the composition struct.
pub(crate) struct ShutdownDrainCoordinator {
    path: PathBuf,
    state: Mutex<CoordinatorState>,
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            duration.as_millis().try_into().unwrap_or(u64::MAX)
        })
}

fn fresh_generation() -> String {
    format!("drain-{}-{}", unix_ms(), std::process::id())
}

fn registry() -> &'static Mutex<BTreeMap<PathBuf, Arc<ShutdownDrainCoordinator>>> {
    static REGISTRY: OnceLock<Mutex<BTreeMap<PathBuf, Arc<ShutdownDrainCoordinator>>>> =
        OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn validate_durable_state(durable: &DurableDrainState) -> Result<(), String> {
    if durable.version != DRAIN_STATE_VERSION {
        return Err("shutdown state version is unsupported".to_owned());
    }
    if durable.generation.trim().is_empty() {
        return Err("shutdown state generation is empty".to_owned());
    }

    let mut phases = BTreeMap::new();
    for (order, evidence) in &durable.phases {
        if usize::from(*order) >= ShutdownPhase::ORDERED.len() || evidence.trim().is_empty() {
            return Err("shutdown state contains invalid phase evidence".to_owned());
        }
        if phases.insert(*order, evidence).is_some() {
            return Err("shutdown state contains duplicate phase evidence".to_owned());
        }
    }
    if let Some(last_order) = phases.keys().next_back().copied()
        && (0..=last_order).any(|order| !phases.contains_key(&order))
    {
        return Err("shutdown state phases are not an ordered prefix".to_owned());
    }
    if phases.contains_key(&ShutdownPhase::IntentionalPublished.order())
        && durable.committed.is_none()
    {
        return Err("shutdown state publishes before drain linearization".to_owned());
    }

    if let Some(committed) = &durable.committed {
        if !durable.requested
            || durable.cancelled
            || committed.generation != durable.generation
            || ShutdownPhase::PRE_COMMIT
                .iter()
                .any(|phase| !phases.contains_key(&phase.order()))
        {
            return Err("shutdown state has an invalid drain commit".to_owned());
        }
        if durable.terminal.is_none() && !durable.pending.is_empty() {
            return Err("committed shutdown has pending work without a terminal".to_owned());
        }
    }

    if let Some(terminal) = &durable.terminal {
        if !durable.requested {
            return Err("shutdown state has a terminal without a request".to_owned());
        }
        if matches!(terminal, ShutdownTerminal::Intentional)
            && (durable.committed.is_none()
                || durable.cancelled
                || !durable.pending.is_empty()
                || ShutdownPhase::ORDERED
                    .iter()
                    .any(|phase| !phases.contains_key(&phase.order())))
        {
            return Err("shutdown state has an invalid intentional terminal".to_owned());
        }
    } else if !durable.requested
        && (durable.cancelled || durable.committed.is_some() || !phases.is_empty())
    {
        return Err("shutdown state has drain progress without a request".to_owned());
    }
    Ok(())
}

/// Returns the process-wide coordinator for one Kernel `work_root`,
/// recovering durable state from a previous process when present.
pub(crate) fn coordinator_for(work_root: &Path) -> Result<Arc<ShutdownDrainCoordinator>, String> {
    let path = work_root.join(".eliot").join(DRAIN_STATE_FILE);
    let mut guard = registry()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(existing) = guard.get(&path) {
        return Ok(Arc::clone(existing));
    }
    let coordinator = Arc::new(ShutdownDrainCoordinator::load(path.clone())?);
    guard.insert(path, Arc::clone(&coordinator));
    Ok(coordinator)
}

impl ShutdownDrainCoordinator {
    fn load(path: PathBuf) -> Result<Self, String> {
        let mut state = match fs::read(&path) {
            Ok(bytes) => {
                let durable: DurableDrainState = serde_json::from_slice(&bytes)
                    .map_err(|error| format!("shutdown state is unreadable: {error}"))?;
                validate_durable_state(&durable)?;
                let mut state = CoordinatorState::fresh(durable.generation);
                state.requested = durable.requested;
                state.cancelled = durable.cancelled;
                state.phases = durable.phases.into_iter().collect();
                state.committed = durable.committed;
                state.terminal = durable.terminal;
                state.pending = durable.pending.into_iter().collect();
                state
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                CoordinatorState::fresh(fresh_generation())
            }
            Err(error) => {
                return Err(format!("shutdown state cannot be read: {error}"));
            }
        };
        // Requested without a terminal means a previous process died
        // mid-drain: an interrupted drain, not an intentional stop.
        // Pending work is already retained above; nothing is discarded.
        state.recovered_interrupted = state.requested && state.terminal.is_none();
        if state.recovered_interrupted {
            observe_shutdown("kernel.shutdown.interrupted_recovered", "recovered");
        }
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    fn persist_state(&self, state: &CoordinatorState) -> Result<(), String> {
        let durable = DurableDrainState {
            version: DRAIN_STATE_VERSION,
            generation: state.generation.clone(),
            requested: state.requested,
            cancelled: state.cancelled,
            phases: state
                .phases
                .iter()
                .map(|(order, evidence)| (*order, evidence.clone()))
                .collect(),
            committed: state.committed.clone(),
            terminal: state.terminal.clone(),
            pending: state.pending.iter().cloned().collect(),
        };
        let payload = match serde_json::to_vec(&durable) {
            Ok(payload) => payload,
            Err(error) => {
                observe_shutdown("kernel.shutdown.persist_failed", "rejected");
                return Err(format!("shutdown state serialization failed: {error}"));
            }
        };
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        if let Err(error) = fs::create_dir_all(parent) {
            observe_shutdown("kernel.shutdown.persist_failed", "rejected");
            return Err(format!(
                "shutdown state directory cannot be created: {error}"
            ));
        }

        let (temp_path, mut temp_file) = loop {
            let sequence = DRAIN_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let temp_path = parent.join(format!(
                "kernel-shutdown-drain-{}-{sequence}.tmp",
                std::process::id()
            ));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temp_path)
            {
                Ok(file) => break (temp_path, file),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    observe_shutdown("kernel.shutdown.persist_failed", "rejected");
                    return Err(format!("shutdown state staging failed: {error}"));
                }
            }
        };
        let write_result = temp_file
            .write_all(&payload)
            .and_then(|()| temp_file.sync_all());
        drop(temp_file);
        let stored = write_result.and_then(|()| durable_replace(&temp_path, &self.path));
        if let Err(error) = stored {
            let _ = fs::remove_file(&temp_path);
            observe_shutdown("kernel.shutdown.persist_failed", "rejected");
            return Err(format!("shutdown state persistence failed: {error}"));
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CoordinatorState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Records the shutdown request. Returns true for a new generation,
    /// including recovery of an interrupted drain; live repeats return false.
    pub(crate) fn request_shutdown(&self) -> Result<bool, String> {
        let mut state = self.lock();
        if state.requested && state.terminal.is_none() && !state.recovered_interrupted {
            return Ok(false);
        }
        // An interrupted generation cannot replay prior phase evidence as
        // current work. Start a fresh generation and retain unresolved work.
        let mut carried = state.pending.clone();
        if let Some(terminal) = &state.terminal {
            carried.extend(terminal.pending());
        }
        let mut candidate = CoordinatorState::fresh(fresh_generation());
        candidate.requested = true;
        candidate.pending = carried;
        self.persist_state(&candidate)?;
        *state = candidate;
        observe_shutdown("kernel.shutdown.requested", "admitted");
        Ok(true)
    }

    /// Current drain generation identity (linearization correlation).
    pub(crate) fn drain_generation(&self) -> String {
        self.lock().generation.clone()
    }

    /// Records one ordered phase with its evidence. Phases must arrive in
    /// order; identical repeats are idempotent. Only
    /// `IntentionalPublished` may follow the linearization point.
    ///
    /// # Errors
    ///
    /// Returns a reason when no drain was requested, a terminal is already
    /// recorded, an earlier phase is missing, or a pre-commit phase arrives
    /// after linearization.
    pub(crate) fn record_phase(
        &self,
        phase: ShutdownPhase,
        evidence: String,
    ) -> Result<(), String> {
        let mut state = self.lock();
        if !state.requested {
            return Err("no shutdown requested".to_owned());
        }
        if state.terminal.is_some() {
            return Err("drain generation already terminated".to_owned());
        }
        if phase != ShutdownPhase::IntentionalPublished && state.committed.is_some() {
            return Err("pre-commit phase after drain linearization".to_owned());
        }
        for earlier in ShutdownPhase::ORDERED {
            if earlier.order() >= phase.order() {
                break;
            }
            if !state.phases.contains_key(&earlier.order()) {
                return Err(format!(
                    "phase {} missing before {}",
                    earlier.as_str(),
                    phase.as_str()
                ));
            }
        }
        if phase == ShutdownPhase::IntentionalPublished && state.committed.is_none() {
            return Err("intentional publication before drain linearization".to_owned());
        }
        if let Some(existing) = state.phases.get(&phase.order()) {
            if existing != &evidence {
                return Err("phase evidence cannot be rewritten".to_owned());
            }
            return Ok(());
        }
        let mut candidate = state.clone();
        candidate.phases.insert(phase.order(), evidence);
        self.persist_state(&candidate)?;
        *state = candidate;
        Ok(())
    }

    /// Registers one pending receipt/operation that must resolve before the
    /// canonical-drain gate completes.
    pub(crate) fn register_pending_receipt(&self, identity: String) -> Result<(), String> {
        let mut state = self.lock();
        if identity.trim().is_empty() {
            return Ok(());
        }
        if state.committed.is_some() || state.terminal.is_some() {
            return Err("pending receipt registration after drain commit".to_owned());
        }
        if state.pending.contains(&identity) {
            return Ok(());
        }
        let mut candidate = state.clone();
        candidate.pending.insert(identity);
        self.persist_state(&candidate)?;
        *state = candidate;
        Ok(())
    }

    /// Marks one pending receipt/operation resolved. Resolution normally
    /// arrives through [`Self::reconcile_pending_to_deadline`]'s rescan;
    /// this covers resolvers that already hold the exact identity.
    pub(crate) fn resolve_pending_receipt(&self, identity: &str) -> Result<(), String> {
        let mut state = self.lock();
        let terminal_pending = matches!(
            &state.terminal,
            Some(ShutdownTerminal::Incomplete { pending })
                if pending
                    .iter()
                    .any(|pending_identity| pending_identity == identity)
        );
        if !state.pending.contains(identity) && !terminal_pending {
            return Ok(());
        }
        let mut candidate = state.clone();
        candidate.pending.remove(identity);
        if let Some(ShutdownTerminal::Incomplete { pending }) = &mut candidate.terminal {
            pending.retain(|pending_identity| pending_identity != identity);
        }
        self.persist_state(&candidate)?;
        *state = candidate;
        Ok(())
    }

    /// Currently unresolved pending receipts/operations.
    pub(crate) fn pending_receipts(&self) -> Vec<String> {
        self.lock().pending.iter().cloned().collect()
    }

    /// Requires the canonical-data lease-zero precondition before any
    /// store-stop request.
    pub(crate) const fn check_lease_zero(has_outstanding_lease: bool) -> Result<(), &'static str> {
        if has_outstanding_lease {
            Err("canonical-data lease outstanding")
        } else {
            Ok(())
        }
    }

    /// Bounded wait for pending receipts to resolve: merges the coordinator
    /// registry with the caller's rescan on every tick and returns the
    /// remainder at deadline. An empty return means reconciled; a non-empty
    /// return is retained by the caller into the incomplete terminal.
    pub(crate) async fn reconcile_pending_to_deadline(
        &self,
        deadline: Duration,
        mut rescan: impl FnMut() -> Result<Vec<String>, String>,
    ) -> Result<Vec<String>, String> {
        let start = Instant::now();
        loop {
            let baseline: BTreeSet<String> = self.pending_receipts().into_iter().collect();
            let rescanned: BTreeSet<String> = rescan()?
                .into_iter()
                .filter(|identity| !identity.trim().is_empty())
                .collect();
            let merged = {
                let mut state = self.lock();
                if state.committed.is_some() || state.terminal.is_some() {
                    return Err("receipt reconciliation after drain commit".to_owned());
                }
                let mut candidate = state.clone();
                // Only remove entries present in the snapshot being rescanned;
                // concurrent registrations remain pending for the next tick.
                for identity in baseline.difference(&rescanned) {
                    candidate.pending.remove(identity);
                }
                candidate.pending.extend(rescanned.iter().cloned());
                if candidate.pending != state.pending {
                    self.persist_state(&candidate)?;
                    *state = candidate;
                }
                state.pending.clone()
            };
            if merged.is_empty() {
                return Ok(Vec::new());
            }
            if start.elapsed() >= deadline {
                observe_shutdown("kernel.shutdown.receipt_deadline_expired", "incomplete");
                return Ok(merged.into_iter().collect());
            }
            tokio::time::sleep(RECEIPT_POLL_INTERVAL).await;
        }
    }

    /// The `DrainCommit` linearization point: irrevocably fixes the drain
    /// generation, the reconciled (empty) snapshot, the fenced authority,
    /// and the branches to stop. Requires every pre-commit phase and an
    /// empty pending registry.
    ///
    /// # Errors
    ///
    /// Returns a reason when the drain was cancelled by a pre-linearization
    /// wake, a pre-commit phase is missing, pending work remains, or the
    /// decision carries a foreign generation.
    pub(crate) fn commit_drain(&self, decision: DrainCommitDecision) -> Result<(), String> {
        let mut state = self.lock();
        if !state.requested {
            return Err("no shutdown requested".to_owned());
        }
        if state.terminal.is_some() {
            return Err("drain generation already terminated".to_owned());
        }
        if state.cancelled {
            return Err("drain cancelled by pre-linearization wake".to_owned());
        }
        if state.committed.is_some() {
            return Err("drain already linearized".to_owned());
        }
        for phase in ShutdownPhase::PRE_COMMIT {
            if !state.phases.contains_key(&phase.order()) {
                return Err(format!(
                    "phase {} missing before linearization",
                    phase.as_str()
                ));
            }
        }
        if !state.pending.is_empty() {
            return Err(format!(
                "{} pending receipts unresolved",
                state.pending.len()
            ));
        }
        if decision.generation != state.generation {
            return Err("drain decision carries a foreign generation".to_owned());
        }
        let mut candidate = state.clone();
        candidate.committed = Some(decision);
        self.persist_state(&candidate)?;
        *state = candidate;
        observe_shutdown("kernel.shutdown.drain_committed", "committed");
        Ok(())
    }

    /// Classifies one wake/attach request against the linearization point:
    /// pre-linearization cancels the drain (`CancelDrain`); post-linearization
    /// the caller must await a fresh generation (`QueueNextGeneration`);
    /// a pre-drain lease or handle presented after linearization is stale
    /// (`RejectStale`). Without an active drain the request proceeds.
    pub(crate) fn classify_wake(
        &self,
        lease_generation: Option<&str>,
    ) -> Result<DrainWakeDisposition, String> {
        let mut state = self.lock();
        if !state.requested {
            return Ok(DrainWakeDisposition::Proceed);
        }
        if let Some(committed) = state.committed.as_ref() {
            return Ok(match lease_generation {
                Some(presented) if presented == committed.generation => {
                    DrainWakeDisposition::RejectStale
                }
                _ => DrainWakeDisposition::QueueNextGeneration,
            });
        }
        if state.terminal.is_some() {
            return Ok(DrainWakeDisposition::QueueNextGeneration);
        }
        if !state.cancelled {
            let mut candidate = state.clone();
            candidate.cancelled = true;
            self.persist_state(&candidate)?;
            *state = candidate;
            observe_shutdown("kernel.shutdown.drain_cancelled_by_wake", "cancelled");
        }
        Ok(DrainWakeDisposition::CancelDrain)
    }

    /// Handles one activation request arriving during shutdown: cancels
    /// pre-linearization drain and proceeds, or denies post-linearization
    /// activation so the caller re-establishes a fresh generation. The Kernel
    /// service independently fences `Activate` from `Draining`; this records
    /// the race disposition for evidence.
    pub(crate) fn on_activate_request(&self) -> Result<DrainWakeDisposition, String> {
        self.classify_wake(None)
    }

    /// Records the durable terminal. The first terminal wins; `Incomplete`
    /// retains its pending work. Intentional requires a prior linearization.
    pub(crate) fn complete_terminal(&self, terminal: ShutdownTerminal) -> Result<(), String> {
        let mut state = self.lock();
        if let Some(existing) = &state.terminal {
            return if existing == &terminal {
                Ok(())
            } else {
                Err("drain generation already has a different terminal".to_owned())
            };
        }
        if !state.requested {
            return Err("no shutdown requested".to_owned());
        }
        let mut candidate = state.clone();
        let (terminal, event) = match terminal {
            ShutdownTerminal::Intentional => {
                if candidate.committed.is_none() {
                    return Err("intentional terminal before drain linearization".to_owned());
                }
                if candidate.cancelled {
                    return Err("cancelled drain cannot complete intentionally".to_owned());
                }
                if !candidate
                    .phases
                    .contains_key(&ShutdownPhase::IntentionalPublished.order())
                {
                    return Err("intentional publication phase is missing".to_owned());
                }
                if !candidate.pending.is_empty() {
                    return Err("pending work prevents intentional terminal".to_owned());
                }
                (
                    ShutdownTerminal::Intentional,
                    "kernel.shutdown.terminal_intentional",
                )
            }
            ShutdownTerminal::Incomplete { pending } => {
                candidate.pending.extend(
                    pending
                        .into_iter()
                        .filter(|identity| !identity.trim().is_empty()),
                );
                let retained = candidate.pending.iter().cloned().collect();
                (
                    ShutdownTerminal::Incomplete { pending: retained },
                    "kernel.shutdown.terminal_incomplete",
                )
            }
        };
        candidate.terminal = Some(terminal);
        self.persist_state(&candidate)?;
        *state = candidate;
        observe_shutdown(event, "recorded");
        Ok(())
    }

    /// Read-only bounded drain disposition for the Kernel operational view.
    ///
    /// Unlike [`Self::classify_wake`] and [`Self::on_activate_request`] this
    /// never mutates the durable drain state: a diagnostic projection must not
    /// cancel a drain, and a reported disposition must be the one already
    /// recorded, not one produced by looking.
    pub(crate) fn drain_disposition(&self) -> &'static str {
        let state = self.lock();
        if state.terminal.is_some() {
            return "terminated";
        }
        if state.committed.is_some() {
            return "queue-next-generation";
        }
        if state.cancelled {
            return "cancel-drain";
        }
        if state.requested {
            return "draining";
        }
        "proceed"
    }

    /// Read-only publication for Host and Watchdog over their existing
    /// control paths.
    pub(crate) fn publication(&self) -> ShutdownPublication {
        let state = self.lock();
        ShutdownPublication {
            generation: state.generation.clone(),
            requested: state.requested,
            phases_completed: ShutdownPhase::ORDERED
                .iter()
                .filter(|phase| state.phases.contains_key(&phase.order()))
                .map(|phase| phase.as_str().to_owned())
                .collect(),
            committed: state.committed.is_some(),
            cancelled: state.cancelled,
            recovered_interrupted: state.recovered_interrupted,
            terminal: state
                .terminal
                .as_ref()
                .map(ShutdownTerminal::as_str)
                .map(str::to_owned),
            pending: state.pending.iter().cloned().collect(),
        }
    }

    /// Emits the published terminal for Host/Watchdog observers: one fixed
    /// event with the durable outcome, never pending identities or digests.
    pub(crate) fn observe_published_state(&self) {
        let terminal = self.publication().terminal;
        let outcome = match terminal.as_deref() {
            Some("intentional-shutdown") => "intentional",
            Some("incomplete-shutdown") => "incomplete",
            _ => "unterminated",
        };
        observe_shutdown("kernel.shutdown.published", outcome);
    }
}

/// Returns modules in quiescence order: the exact reverse of dependency
/// (startup) order, so dependents stop before the stores and bridges they
/// depend on.
///
/// # Errors
///
/// Returns a reason when the contour is ambiguous (duplicate entries).
pub(crate) fn reverse_quiescence_order(dependency_order: &[String]) -> Result<Vec<String>, String> {
    let unique: BTreeSet<&String> = dependency_order.iter().collect();
    if unique.len() != dependency_order.len() {
        return Err("module contour contains duplicates".to_owned());
    }
    Ok(dependency_order.iter().rev().cloned().collect())
}

#[cfg(test)]
mod shutdown_drain_tests {
    #![allow(
        clippy::expect_used,
        reason = "focused drain proof uses expects for fixed-valid fixtures, matching the host-state test precedent"
    )]

    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_work_root(name: &str) -> PathBuf {
        let id = TEST_COUNTER.fetch_add(1, Ordering::AcqRel);
        let dir = std::env::temp_dir().join(format!(
            "eliot-shutdown-drain-test-{}-{}-{name}",
            std::process::id(),
            id
        ));
        let _ = std::fs::create_dir_all(&dir);
        dir
    }

    fn test_decision(generation: &str) -> DrainCommitDecision {
        DrainCommitDecision {
            generation: generation.to_owned(),
            lease_and_pending_snapshot: Vec::new(),
            authority_epochs_fenced: vec!["authority-epoch:1".to_owned()],
            branches_to_stop: vec!["daemon".to_owned(), "store-bridge".to_owned()],
            wake_disposition: DrainWakeDisposition::QueueNextGeneration,
            irreversible_stage: "authority-fenced".to_owned(),
            recovery_owner: "kernel-composition".to_owned(),
        }
    }

    fn record_pre_commit(coordinator: &ShutdownDrainCoordinator) {
        for phase in ShutdownPhase::PRE_COMMIT {
            coordinator
                .record_phase(phase, format!("{}-evidence", phase.as_str()))
                .expect("ordered pre-commit phase records");
        }
    }

    #[tokio::test]
    async fn normal_shutdown_records_ordered_phases_and_linearizes_to_intentional() {
        let root = test_work_root("normal");
        let coordinator = coordinator_for(&root).expect("new drain coordinator loads");
        assert!(coordinator.request_shutdown().expect("shutdown persists"));

        // Out-of-order phases are rejected: the receipt gate cannot precede
        // admission closure.
        assert!(
            coordinator
                .record_phase(
                    ShutdownPhase::CanonicalDrainReceiptsReconciled,
                    "too-early".to_owned()
                )
                .is_err()
        );
        record_pre_commit(&coordinator);

        // Receipt reconciliation gate: a pending receipt blocks linearization
        // until the bounded wait proves it resolved.
        coordinator
            .register_pending_receipt("rebind-op-1".to_owned())
            .expect("pending receipt persists");
        assert!(
            coordinator
                .commit_drain(test_decision(&coordinator.drain_generation()))
                .is_err()
        );
        let held = coordinator
            .reconcile_pending_to_deadline(Duration::from_millis(20), || {
                Ok(vec!["rebind-op-1".to_owned()])
            })
            .await
            .expect("receipt rescan succeeds");
        assert_eq!(held, vec!["rebind-op-1".to_owned()]);
        coordinator
            .resolve_pending_receipt("rebind-op-1")
            .expect("resolved receipt persists");
        let cleared = coordinator
            .reconcile_pending_to_deadline(Duration::from_millis(20), || Ok(Vec::new()))
            .await;
        assert!(cleared.expect("receipt rescan succeeds").is_empty());

        coordinator
            .commit_drain(test_decision(&coordinator.drain_generation()))
            .expect("linearization after ordered phases and reconciled receipts");
        // Post-linearization phases other than publication are rejected.
        assert!(
            coordinator
                .record_phase(ShutdownPhase::FlushesCompleted, "late".to_owned())
                .is_err()
        );
        coordinator
            .record_phase(
                ShutdownPhase::IntentionalPublished,
                "poisoned-and-published".to_owned(),
            )
            .expect("publication follows linearization");

        // Reverse-dependency quiescence order used by the composition root.
        assert_eq!(
            reverse_quiescence_order(&["store-bridge".to_owned(), "daemon".to_owned()])
                .expect("distinct contour reverses"),
            vec!["daemon".to_owned(), "store-bridge".to_owned()]
        );
        assert!(reverse_quiescence_order(&["daemon".to_owned(), "daemon".to_owned()]).is_err());

        // Canonical-data lease-zero precondition used by the composition root.
        assert!(ShutdownDrainCoordinator::check_lease_zero(false).is_ok());
        assert!(ShutdownDrainCoordinator::check_lease_zero(true).is_err());

        coordinator
            .complete_terminal(ShutdownTerminal::Intentional)
            .expect("intentional terminal persists");
        let publication = coordinator.publication();
        assert_eq!(publication.phases_completed.len(), 8);
        assert!(publication.committed);
        assert_eq!(
            publication.terminal.as_deref(),
            Some("intentional-shutdown")
        );
        assert!(publication.pending.is_empty());

        // Durable evidence survives: terminal persisted, reload distinguishes
        // the intentional stop from an interrupted drain.
        let raw = std::fs::read(root.join(".eliot").join(DRAIN_STATE_FILE))
            .expect("drain state persisted");
        let durable: DurableDrainState =
            serde_json::from_slice(&raw).expect("durable drain state decodes");
        assert!(matches!(
            durable.terminal,
            Some(ShutdownTerminal::Intentional)
        ));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn deadline_expiry_yields_incomplete_and_wake_race_fenced() {
        let root = test_work_root("race");
        let coordinator = coordinator_for(&root).expect("new drain coordinator loads");
        assert!(coordinator.request_shutdown().expect("shutdown persists"));

        // A wake arriving before linearization cancels the drain.
        assert_eq!(
            coordinator
                .on_activate_request()
                .expect("wake classification persists"),
            DrainWakeDisposition::CancelDrain
        );
        assert_eq!(
            coordinator
                .classify_wake(None)
                .expect("wake classification persists"),
            DrainWakeDisposition::CancelDrain
        );

        // Deadline expiry with pending work retains the pending list instead
        // of discarding it.
        coordinator
            .register_pending_receipt("rebind-op-9".to_owned())
            .expect("pending receipt persists");
        let remainder = coordinator
            .reconcile_pending_to_deadline(Duration::from_millis(30), || {
                Ok(vec!["rebind-op-9".to_owned()])
            })
            .await
            .expect("receipt rescan succeeds");
        assert_eq!(remainder, vec!["rebind-op-9".to_owned()]);
        coordinator
            .complete_terminal(ShutdownTerminal::Incomplete { pending: remainder })
            .expect("incomplete terminal persists");
        // Cancelled, unlinearized drain can never complete as intentional.
        let _ = coordinator.complete_terminal(ShutdownTerminal::Intentional);
        let publication = coordinator.publication();
        assert_eq!(publication.terminal.as_deref(), Some("incomplete-shutdown"));
        assert_eq!(publication.pending, vec!["rebind-op-9".to_owned()]);

        // Post-linearization race on a fresh drain: a pre-drain handle for
        // the committed generation is stale; anything else awaits a fresh
        // generation.
        let root2 = test_work_root("race-committed");
        let committed = coordinator_for(&root2).expect("second drain coordinator loads");
        assert!(committed.request_shutdown().expect("shutdown persists"));
        record_pre_commit(&committed);
        let generation = committed.drain_generation();
        committed
            .commit_drain(test_decision(&generation))
            .expect("linearization");
        assert_eq!(
            committed
                .classify_wake(Some(&generation))
                .expect("wake classification is read-only after commit"),
            DrainWakeDisposition::RejectStale
        );
        assert_eq!(
            committed
                .classify_wake(Some("drain-foreign-generation"))
                .expect("wake classification is read-only after commit"),
            DrainWakeDisposition::QueueNextGeneration
        );
        assert_eq!(
            committed
                .on_activate_request()
                .expect("wake classification is read-only after commit"),
            DrainWakeDisposition::QueueNextGeneration
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&root2);
    }
}
