use crate::{EngineError, ServiceContext, ServiceHandle, ServiceLifecycle, SingleInstanceRefusal};
use eliot_types::{
    AuthorityHeader, CausalityHeader, EliotExchangeEnvelope, EliotLogEvent, ExchangeKind,
    ExchangeParty, LogEventKind, LogLevel, ModuleCapability, ModuleEndpoint, ModuleHealth,
    ModuleKind, ModuleManifest, ModuleRegistryReport, ModuleResourceLimits, ModuleTransport,
    RedactionInfo, RuntimeHealthReport, RuntimeLogReport, RuntimeMode, SchemaRef,
    ServiceHealthState, ServiceRuntimeStatus, TaintClass,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

const DEFAULT_RESTART_BUDGET: u32 = 3;

pub struct ServiceSupervisor {
    services: Vec<Box<dyn ServiceLifecycle>>,
    statuses: BTreeMap<String, ServiceRuntimeStatus>,
    start_order: Vec<String>,
    shutdown_order: Vec<String>,
    restart_budget: u32,
}

impl ServiceSupervisor {
    pub fn new(services: Vec<Box<dyn ServiceLifecycle>>) -> Self {
        Self {
            services,
            statuses: BTreeMap::new(),
            start_order: Vec::new(),
            shutdown_order: Vec::new(),
            restart_budget: DEFAULT_RESTART_BUDGET,
        }
    }

    #[must_use]
    pub fn with_restart_budget(mut self, restart_budget: u32) -> Self {
        self.restart_budget = restart_budget;
        self
    }

    pub async fn start_all(&mut self, instance_id: &str) -> Result<(), EngineError> {
        for service in &self.services {
            let service_name = service.service_name().to_owned();
            let ctx = ServiceContext {
                service_name: service_name.clone(),
                instance_id: instance_id.to_owned(),
            };
            self.statuses.insert(
                service_name.clone(),
                ServiceRuntimeStatus {
                    service_name: service_name.clone(),
                    health: ServiceHealthState::Starting,
                    started: false,
                    restart_budget_remaining: self.restart_budget,
                    message: "starting".to_owned(),
                },
            );

            match service.start(ctx).await {
                Ok(handle) => {
                    self.start_order.push(handle.service_name.clone());
                    self.statuses.insert(
                        handle.service_name.clone(),
                        ServiceRuntimeStatus {
                            service_name: handle.service_name,
                            health: ServiceHealthState::Healthy,
                            started: true,
                            restart_budget_remaining: self.restart_budget,
                            message: "started".to_owned(),
                        },
                    );
                }
                Err(error) => {
                    self.statuses.insert(
                        service_name.clone(),
                        ServiceRuntimeStatus {
                            service_name: service_name.clone(),
                            health: ServiceHealthState::Failed,
                            started: false,
                            restart_budget_remaining: self.restart_budget.saturating_sub(1),
                            message: error.to_string(),
                        },
                    );
                    return Err(error);
                }
            }
        }
        Ok(())
    }

    pub async fn shutdown_all(&mut self, deadline: Instant) -> Result<(), EngineError> {
        for service in self.services.iter().rev() {
            service.shutdown(deadline).await?;
            let service_name = service.service_name().to_owned();
            self.shutdown_order.push(service_name.clone());
            self.statuses.insert(
                service_name.clone(),
                ServiceRuntimeStatus {
                    service_name,
                    health: ServiceHealthState::Stopped,
                    started: false,
                    restart_budget_remaining: self.restart_budget,
                    message: "stopped".to_owned(),
                },
            );
        }
        Ok(())
    }

    pub fn service_statuses(&self) -> Vec<ServiceRuntimeStatus> {
        self.statuses.values().cloned().collect()
    }

    pub fn start_order(&self) -> &[String] {
        &self.start_order
    }

    pub fn shutdown_order(&self) -> &[String] {
        &self.shutdown_order
    }
}

pub struct StaticRuntimeService {
    service_name: &'static str,
    health: ServiceHealthState,
    fail_start: bool,
}

impl StaticRuntimeService {
    pub const fn healthy(service_name: &'static str) -> Self {
        Self {
            service_name,
            health: ServiceHealthState::Healthy,
            fail_start: false,
        }
    }

    pub const fn failed(service_name: &'static str) -> Self {
        Self {
            service_name,
            health: ServiceHealthState::Failed,
            fail_start: true,
        }
    }
}

impl ServiceLifecycle for StaticRuntimeService {
    fn service_name(&self) -> &'static str {
        self.service_name
    }

    fn start(
        &self,
        ctx: ServiceContext,
    ) -> crate::BoxServiceFuture<'_, Result<ServiceHandle, EngineError>> {
        let service_name = self.service_name;
        let fail_start = self.fail_start;
        Box::pin(async move {
            if fail_start {
                return Err(EngineError::ServiceNotReady {
                    service: service_name.to_owned(),
                    reason: "configured test failure".to_owned(),
                });
            }
            Ok(ServiceHandle {
                service_name: ctx.service_name,
                started_at: Instant::now(),
            })
        })
    }

    fn shutdown(&self, _deadline: Instant) -> crate::BoxServiceFuture<'_, Result<(), EngineError>> {
        Box::pin(async { Ok(()) })
    }

    fn health(&self) -> eliot_types::ComponentHealth {
        eliot_types::ComponentHealth {
            component: self.service_name.to_owned(),
            status: if self.health.is_ready() {
                eliot_types::HealthStatus::Ready
            } else if self.health.is_degraded() {
                eliot_types::HealthStatus::Degraded
            } else {
                eliot_types::HealthStatus::NotReady
            },
            message: format!("{:?}", self.health),
        }
    }
}

pub struct LifecycleService {
    data_root: PathBuf,
}

impl LifecycleService {
    pub fn new(data_root: impl Into<PathBuf>) -> Self {
        Self {
            data_root: data_root.into(),
        }
    }

    pub fn acquire_single_instance(&self) -> Result<RuntimeLock, EngineError> {
        self.acquire_single_instance_with_observations(&SingleInstanceObservations::none())
    }

    /// Acquires the runtime-root single-instance lock, binding app-supplied
    /// owner observations into the one lifecycle-owned recovery protocol.
    ///
    /// `observations` carries file evidence the caller read (lock/PID bytes
    /// plus the app-validated publication owner PID). The lifecycle owner
    /// re-reads the bound runtime directory itself and refuses when the
    /// caller observation no longer matches local state, so a stale observer
    /// can never authorize mutation of a replacement owner's objects.
    ///
    /// At most one bounded recovery-to-reacquire attempt runs per call: a
    /// refused or failed recovery is returned with its cause preserved and
    /// is never retried here. Callers must not add a second retry loop.
    pub fn acquire_single_instance_with_observations(
        &self,
        observations: &SingleInstanceObservations,
    ) -> Result<RuntimeLock, EngineError> {
        let runtime_dir = self.data_root.join("runtime");
        std::fs::create_dir_all(&runtime_dir)?;
        let lock_path = runtime_dir.join("daemon.lock");
        match create_single_instance_lock_file(&lock_path) {
            LockCreateOutcome::Created(file) => {
                establish_single_instance_ownership(&runtime_dir, &lock_path, file)
            }
            LockCreateOutcome::Exists => {
                recover_stale_single_instance_lock(&self.data_root, observations)?;
                match create_single_instance_lock_file(&lock_path) {
                    LockCreateOutcome::Created(file) => {
                        establish_single_instance_ownership(&runtime_dir, &lock_path, file)
                    }
                    LockCreateOutcome::Exists => Err(single_instance_contention(
                        &lock_path,
                        SingleInstanceRefusal::ReplacementDetected,
                        "a competing starter holds the single-instance lock after one bounded recovery attempt",
                    )),
                    LockCreateOutcome::Io(error) => Err(EngineError::Io(error)),
                }
            }
            LockCreateOutcome::Io(error) => Err(EngineError::Io(error)),
        }
    }

    /// Runs one bounded stale-owner recovery attempt without acquiring.
    ///
    /// Client-side startup (which spawns the daemon child that will acquire)
    /// delegates unlink decisions to this lifecycle-owned protocol instead of
    /// implementing a second removal policy. Returns `Ok(true)` only when a
    /// stale lock proven to belong to a dead owner of this runtime root was
    /// reclaimed, `Ok(false)` when no lock needs recovery, and a typed
    /// contention/failure error otherwise. Recovery errors are never
    /// collapsed to `false`.
    pub fn try_recover_stale_single_instance(
        &self,
        observations: &SingleInstanceObservations,
    ) -> Result<bool, EngineError> {
        recover_stale_single_instance_lock(&self.data_root, observations)
    }

    pub fn status(&self) -> Result<Value, EngineError> {
        let runtime_dir = self.data_root.join("runtime");
        let lock_path = runtime_dir.join("daemon.lock");
        let pid_path = runtime_dir.join("daemon.pid");
        let pid = std::fs::read_to_string(&pid_path).ok();
        Ok(serde_json::json!({
            "component": "lifecycle",
            "single_instance_lock": lock_path.exists(),
            "pid": pid.map(|value| value.trim().to_owned()),
            "data_root": self.data_root,
        }))
    }
}

/// Owner observations supplied by app startup paths for one bound runtime
/// root.
///
/// File evidence distinguishes a missing file (no evidence) from an
/// unreadable one (refuse mutation) and from present bytes. The lifecycle
/// owner re-reads the same directory itself; caller evidence that no longer
/// matches local state proves the world rotated and refuses mutation.
/// `publication_pid` is the app-validated publication owner: it supplies an
/// observation, never authentication.
#[derive(Clone, Debug)]
pub struct SingleInstanceObservations {
    pub lock: SingleInstanceFileEvidence,
    pub pid_file: SingleInstanceFileEvidence,
    pub publication_pid: Option<u32>,
}

/// One observed file state: missing, inaccessible, or present bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SingleInstanceFileEvidence {
    Missing,
    Inaccessible { detail: String },
    Present(Vec<u8>),
}

impl SingleInstanceObservations {
    #[must_use]
    pub fn none() -> Self {
        Self {
            lock: SingleInstanceFileEvidence::Missing,
            pid_file: SingleInstanceFileEvidence::Missing,
            publication_pid: None,
        }
    }

    #[must_use]
    pub fn publication_owner(pid: u32) -> Self {
        Self {
            lock: SingleInstanceFileEvidence::Missing,
            pid_file: SingleInstanceFileEvidence::Missing,
            publication_pid: Some(pid),
        }
    }

    /// Reads local evidence for the bound runtime directory. Missing and
    /// inaccessible files are different outcomes; nothing here decides.
    pub fn read(runtime_dir: &Path) -> Self {
        Self {
            lock: read_file_evidence(&runtime_dir.join("daemon.lock")),
            pid_file: read_file_evidence(&runtime_dir.join("daemon.pid")),
            publication_pid: None,
        }
    }
}

/// Attempts the one lifecycle-owned recovery of a provably-dead
/// single-instance owner for `runtime_root`.
///
/// `runtime_root` is the data root whose `runtime/` subdirectory holds
/// `daemon.lock`, `daemon.pid`, `startup.marker`, and
/// `clean-shutdown.marker`.
///
/// Returns `Ok(true)` only when a stale `daemon.lock` was reclaimed after
/// the recorded owner PID was proven dead for this exact runtime root:
/// every present identity source (PID file, lock bytes, app-validated
/// publication) agrees on one PID, the liveness probe reports that PID
/// dead twice, and the lock file object is pinned with delete/write sharing
/// denied across validation (Windows) with a second pin proving the same
/// `FileIdentity` and bytes just before mutation, so two contenders cannot
/// both reclaim and a stale observer cannot unlink a replacement lock. A
/// live successor additionally holds its lock with delete sharing denied,
/// so a paused observer's removal fails into a typed refusal instead of
/// deleting the new owner's lock.
///
/// Returns `Ok(false)` — removing nothing — when no lock file exists.
/// A live owner, contradictory or malformed identity, inaccessible or
/// unknown-owner evidence, a replaced lock, or an unsupported platform
/// refuses mutation with a typed `SingleInstanceContention` error; genuine
/// I/O failures surface as `EngineError::Io`. The previous owner's clean
/// indication never decides recovery: a historic clean marker cannot make a
/// later crashed owner unrecoverable, and an ambiguous lineage is never
/// treated as clean.
pub fn recover_stale_single_instance_lock(
    runtime_root: &Path,
    observations: &SingleInstanceObservations,
) -> Result<bool, EngineError> {
    let runtime_dir = runtime_root.join("runtime");
    let lock_path = runtime_dir.join("daemon.lock");
    let pid_path = runtime_dir.join("daemon.pid");
    let local = SingleInstanceObservations::read(&runtime_dir);
    require_no_rotation(&lock_path, "daemon.lock", &observations.lock, &local.lock)?;
    require_no_rotation(
        &lock_path,
        "daemon.pid",
        &observations.pid_file,
        &local.pid_file,
    )?;
    let lock_snapshot = match &local.lock {
        SingleInstanceFileEvidence::Present(bytes) => bytes.clone(),
        SingleInstanceFileEvidence::Missing => return Ok(false),
        SingleInstanceFileEvidence::Inaccessible { detail } => {
            return Err(single_instance_contention(
                &lock_path,
                SingleInstanceRefusal::InaccessibleEvidence,
                format!("cannot read daemon.lock: {detail}"),
            ));
        }
    };
    let pid_snapshot = match &local.pid_file {
        SingleInstanceFileEvidence::Present(bytes) => Some(bytes.clone()),
        SingleInstanceFileEvidence::Missing => None,
        SingleInstanceFileEvidence::Inaccessible { detail } => {
            return Err(single_instance_contention(
                &lock_path,
                SingleInstanceRefusal::InaccessibleEvidence,
                format!("cannot read daemon.pid: {detail}"),
            ));
        }
    };
    let owner_pid = agree_single_owner_pid(
        &lock_path,
        pid_snapshot.as_deref(),
        Some(lock_snapshot.as_slice()),
        observations.publication_pid,
    )?;
    probe_owner_dead(&lock_path, owner_pid)?;
    // Exclusive-ownership guard spanning validation to mutation (Windows):
    // pin the validated lock object with delete/write sharing denied, so no
    // contender can replace or unlink it while this validation runs. The
    // held handle is the object-identity anchor: bytes are re-read from the
    // handle itself, and a second pin just before mutation must resolve to
    // the same `FileIdentity`. A byte re-read alone is insufficient without
    // this serialization, so it is not relied on here.
    #[cfg(windows)]
    let pinned = pin_single_instance_lock(&lock_path, &lock_snapshot)?;
    #[cfg(windows)]
    let pinned_identity = pinned.identity();
    // Re-verify the validated snapshot immediately before mutation. The
    // pinned handle above serializes validation against replacement; the
    // path re-reads below additionally refuse when caller-observed state
    // rotated before the pin was taken.
    if std::fs::read(&lock_path).ok().as_deref() != Some(lock_snapshot.as_slice()) {
        return Err(single_instance_contention(
            &lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            "daemon.lock was replaced during stale-owner validation; refusing removal",
        ));
    }
    if pid_snapshot.is_some() {
        confirm_pid_snapshot_unchanged(&lock_path, &pid_path, pid_snapshot.as_deref())?;
    } else if pid_path.exists() {
        return Err(single_instance_contention(
            &lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            "daemon.pid appeared during stale-owner validation; refusing removal",
        ));
    }
    probe_owner_dead(&lock_path, owner_pid)?;
    #[cfg(windows)]
    confirm_single_instance_identity(&lock_path, &lock_snapshot, pinned_identity)?;
    // Serialize PID retirement with the owned lock: while the pinned lock
    // object/path still blocks successor `create_new`, retire the exact old
    // PID object (identity + bytes) before the old lock becomes available.
    // A successor created after old-lock removal is therefore never touched
    // by this operation. The lock pin above stays live across the PID work.
    let pid_retired =
        retire_stale_pid_while_lock_held(&lock_path, &pid_path, pid_snapshot.as_deref())?;
    // The explicit drop is load-bearing: without it the pin above would deny
    // our own removal. The drop-to-remove window is closed by the owner's
    // deny-delete creation handle (a live successor's lock resists unlink)
    // plus the sharing-violation refusal below. The PID path is never touched
    // after this point.
    #[cfg(windows)]
    drop(pinned);
    match remove_reclaimed_lock(&lock_path) {
        Ok(()) => Ok(true),
        Err(error) if pid_retired => Err(single_instance_contention(
            &lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            format!(
                "stale PID retired but stale lock retained ({error}); subsequent bounded recovery can use the retained lock evidence"
            ),
        )),
        Err(error) => Err(error),
    }
}

/// Establishes coherent owner state on a freshly created exclusive lock.
///
/// Writes the owner PID through the owned handle, proves the path still
/// names the created owner bytes, records the PID file, retires the
/// previous owner's clean indication, and writes the new owner-scoped
/// startup state — all under the same ownership. A halfway failure removes
/// only objects proven to belong to this attempt and reports the cleanup
/// disposition with the primary failure, so the next contender meets a
/// recoverable state.
///
/// Serialization rests on the platform's exclusive-creation primitive and
/// on the owner's deny-delete creation handle (Windows): exactly one
/// `create_new` succeeds, a live owner's lock resists unlink by any stale
/// observer, every removal re-proves the expected bytes first, and a final
/// triple verification (lock bytes, PID bytes, startup owner) gates the
/// return, so a stale observer that outlived validation meets a
/// `ReplacementDetected` refusal instead of becoming a second owner.
fn establish_single_instance_ownership(
    runtime_dir: &Path,
    lock_path: &Path,
    mut file: File,
) -> Result<RuntimeLock, EngineError> {
    let owner_pid = std::process::id();
    let owner_text = owner_pid.to_string();
    let pid_path = runtime_dir.join("daemon.pid");
    let clean_marker_path = runtime_dir.join("clean-shutdown.marker");
    let startup_marker_path = runtime_dir.join("startup.marker");
    if file
        .write_all(owner_text.as_bytes())
        .and_then(|()| file.sync_all())
        .is_err()
    {
        drop(file);
        let cleanup = abandon_partial_claim(
            lock_path,
            &pid_path,
            &startup_marker_path,
            &clean_marker_path,
            owner_pid,
            MarkerBackup::Unknown,
            MarkerBackup::Unknown,
        );
        return Err(EngineError::SingleInstanceAcquisitionFailed {
            stage: "claim-lock".to_owned(),
            detail: format!("cannot record the owner PID in the created lock; {cleanup}"),
        });
    }
    if !path_names_owned_lock(lock_path, owner_text.as_bytes()) {
        return Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            "the lock path no longer names the created owner bytes; refusing to proceed on a replacement lock",
        ));
    }
    if let Err(error) = std::fs::write(&pid_path, &owner_text) {
        // Close the creation handle first so the partial-claim cleanup below
        // can remove our own lock; the handle denies delete sharing on
        // Windows while it is open.
        drop(file);
        let cleanup = abandon_partial_claim(
            lock_path,
            &pid_path,
            &startup_marker_path,
            &clean_marker_path,
            owner_pid,
            MarkerBackup::Unknown,
            MarkerBackup::Unknown,
        );
        return Err(EngineError::SingleInstanceAcquisitionFailed {
            stage: "record-pid".to_owned(),
            detail: format!("cannot record {error}; {cleanup}"),
        });
    }
    let backups = match establish_owner_markers(&startup_marker_path, &clean_marker_path, owner_pid)
    {
        Ok(backups) => backups,
        Err(failure) => {
            // Close the creation handle first so the partial-claim cleanup
            // below can remove our own lock; the handle denies delete sharing
            // on Windows while it is open. The single shared cleanup policy
            // lives in `abandon_partial_claim`; the marker helper only returns
            // the plan (backups + primary failure).
            drop(file);
            let cleanup = abandon_partial_claim(
                lock_path,
                &pid_path,
                &startup_marker_path,
                &clean_marker_path,
                owner_pid,
                failure.clean,
                failure.startup,
            );
            return Err(EngineError::SingleInstanceAcquisitionFailed {
                stage: failure.stage,
                detail: format!("{}; {cleanup}", failure.detail),
            });
        }
    };
    if !verify_owned_establishment(lock_path, &pid_path, &startup_marker_path, owner_pid) {
        // Close the creation handle first so the partial-claim cleanup below
        // can remove our own lock; the handle denies delete sharing on
        // Windows while it is open.
        drop(file);
        let cleanup = abandon_partial_claim(
            lock_path,
            &pid_path,
            &startup_marker_path,
            &clean_marker_path,
            owner_pid,
            backups.clean,
            backups.startup,
        );
        return Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            format!(
                "ownership verification failed after establishment; a replacement won the race; {cleanup}"
            ),
        ));
    }
    Ok(RuntimeLock {
        lock_path: lock_path.to_path_buf(),
        pid_path,
        clean_marker_path,
        owner_pid,
        lock_handle: Some(file),
        #[cfg(windows)]
        pid_identity: capture_pid_identity(runtime_dir, &owner_text),
    })
}

/// Owner-scoped marker state changes, run under the freshly created
/// exclusive lock: retire the previous owner's clean indication, then
/// record the new owner-scoped startup state.
///
/// The caller holds the owned creation handle live across this call. On
/// Windows that handle denies delete sharing, so cleanup must run only after
/// the caller deliberately closes it: this function never unlinks anything
/// itself and instead returns the captured backups with the primary failure
/// for the caller to clean up through the one shared `abandon_partial_claim`
/// path.
#[allow(clippy::too_many_arguments)]
fn establish_owner_markers(
    startup_marker_path: &Path,
    clean_marker_path: &Path,
    owner_pid: u32,
) -> Result<OwnerMarkerBackups, MarkerEstablishmentFailure> {
    let clean_backup = match MarkerBackup::capture(clean_marker_path) {
        Ok(backup) => backup,
        Err(detail) => {
            return Err(MarkerEstablishmentFailure {
                stage: "retire-clean-marker".to_owned(),
                detail: format!("cannot inspect the previous clean indication: {detail}"),
                clean: MarkerBackup::Unknown,
                startup: MarkerBackup::Unknown,
            });
        }
    };
    if let Err(error) = remove_optional_file(clean_marker_path) {
        return Err(MarkerEstablishmentFailure {
            stage: "retire-clean-marker".to_owned(),
            detail: format!("cannot retire the previous clean indication: {error}"),
            clean: clean_backup,
            startup: MarkerBackup::Unknown,
        });
    }
    let startup_backup = match MarkerBackup::capture(startup_marker_path) {
        Ok(backup) => backup,
        Err(detail) => {
            return Err(MarkerEstablishmentFailure {
                stage: "record-startup".to_owned(),
                detail: format!("cannot inspect the previous startup state: {detail}"),
                clean: clean_backup,
                startup: MarkerBackup::Unknown,
            });
        }
    };
    if let Err(error) = std::fs::write(startup_marker_path, format_owner_marker(owner_pid)) {
        return Err(MarkerEstablishmentFailure {
            stage: "record-startup".to_owned(),
            detail: format!("cannot record owner startup state: {error}"),
            clean: clean_backup,
            startup: startup_backup,
        });
    }
    Ok(OwnerMarkerBackups {
        clean: clean_backup,
        startup: startup_backup,
    })
}

struct MarkerEstablishmentFailure {
    stage: String,
    detail: String,
    clean: MarkerBackup,
    startup: MarkerBackup,
}

struct OwnerMarkerBackups {
    clean: MarkerBackup,
    startup: MarkerBackup,
}

/// Previous marker content captured before an owned overwrite, so a halfway
/// failure can restore exactly what it found. `Unknown` means the previous
/// state was never established: leave the marker alone.
#[derive(Clone)]
enum MarkerBackup {
    Unknown,
    WasMissing,
    Previous(Vec<u8>),
}

impl MarkerBackup {
    fn capture(path: &Path) -> Result<Self, String> {
        match read_optional_bytes(path) {
            Ok(None) => Ok(Self::WasMissing),
            Ok(Some(bytes)) => Ok(Self::Previous(bytes)),
            Err(detail) => Err(detail),
        }
    }
}

/// Final establishment gate: the lock path, the PID file, and the startup
/// marker must all name this owner at once. Any mismatch means a competing
/// starter replaced our objects after our last check; the caller unwinds
/// and refuses instead of running as a second owner.
fn verify_owned_establishment(
    lock_path: &Path,
    pid_path: &Path,
    startup_marker_path: &Path,
    owner_pid: u32,
) -> bool {
    let owner_text = owner_pid.to_string();
    path_names_owned_lock(lock_path, owner_text.as_bytes())
        && std::fs::read(pid_path).ok().as_deref() == Some(owner_text.as_bytes())
        && std::fs::read(startup_marker_path)
            .ok()
            .is_some_and(|current| parse_owner_marker(&current) == Some(owner_pid))
}

/// Removes only objects proven to belong to the failed acquisition attempt
/// and restores the previous marker indications when they were captured.
/// Never touches objects owned by anyone else; reports what was left behind
/// so the primary failure preserves its cleanup uncertainty.
#[allow(clippy::too_many_arguments)]
fn abandon_partial_claim(
    lock_path: &Path,
    pid_path: &Path,
    startup_marker_path: &Path,
    clean_marker_path: &Path,
    owner_pid: u32,
    clean_backup: MarkerBackup,
    startup_backup: MarkerBackup,
) -> String {
    let owner_text = owner_pid.to_string();
    let mut notes: Vec<String> = Vec::new();
    // Serialize with the lock path: the PID file is retired while the lock
    // path still exists, so no successor can have published yet. The lock is
    // removed only afterwards.
    match std::fs::read(pid_path).ok() {
        Some(current) if current == owner_text.as_bytes() => match std::fs::remove_file(pid_path) {
            Ok(()) => notes.push("removed own PID file".to_owned()),
            Err(_) => notes.push("own PID file removal failed; residue remains".to_owned()),
        },
        _ => notes.push("PID file left in place: not provably this attempt".to_owned()),
    }
    if path_names_owned_lock(lock_path, owner_text.as_bytes()) {
        match std::fs::remove_file(lock_path) {
            Ok(()) => notes.push("removed own lock".to_owned()),
            Err(error) => notes.push(match error.kind() {
                std::io::ErrorKind::NotFound => "own lock already gone".to_owned(),
                _ => "own lock removal failed; residue remains for bounded recovery".to_owned(),
            }),
        }
    } else {
        notes.push("lock left in place: not provably this attempt".to_owned());
    }
    restore_marker_or_remove(
        startup_marker_path,
        startup_backup,
        owner_pid,
        "startup marker",
        &mut notes,
    );
    restore_marker_or_remove(
        clean_marker_path,
        clean_backup,
        owner_pid,
        "clean marker",
        &mut notes,
    );
    format!("cleanup: {}", notes.join("; "))
}

fn restore_marker_or_remove(
    path: &Path,
    backup: MarkerBackup,
    owner_pid: u32,
    role: &str,
    notes: &mut Vec<String>,
) {
    match backup {
        MarkerBackup::Unknown => {
            notes.push(format!("{role} left in place: previous state unknown"));
        }
        MarkerBackup::WasMissing => {
            let own = std::fs::read(path)
                .ok()
                .is_some_and(|current| parse_owner_marker(&current) == Some(owner_pid));
            if own {
                match std::fs::remove_file(path) {
                    Ok(()) => notes.push(format!("removed own {role}")),
                    Err(_) => notes.push(format!("own {role} removal failed; residue remains")),
                }
            } else {
                notes.push(format!("{role} left in place: not provably this attempt"));
            }
        }
        MarkerBackup::Previous(previous) => {
            // Never overwrite a successor's marker publication: a failed
            // claimant that restores unconditionally could clobber objects a
            // new owner published after this attempt's lock was removed. Only
            // our own content or a missing marker may be restored. A present
            // but unreadable or partially written marker (legacy
            // bare-timestamp, halfway write, or successor partial) is not
            // ownerless evidence and is never overwritten.
            match std::fs::read(path) {
                Ok(current) if parse_owner_marker(&current) == Some(owner_pid) => {
                    match std::fs::write(path, &previous) {
                        Ok(()) => notes.push(format!("restored previous {role}")),
                        Err(_) => {
                            notes.push(format!(
                                "previous {role} restore failed; disposition uncertain"
                            ));
                        }
                    }
                }
                Ok(current) if matches!(parse_owner_marker(&current), Some(pid) if pid != owner_pid) =>
                {
                    notes.push(format!(
                        "{role} left in place: successor-owned; previous-state restore skipped"
                    ));
                }
                Ok(_) => {
                    notes.push(format!(
                        "{role} left in place: unreadable/partial marker content; previous-state restore skipped"
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    match std::fs::write(path, &previous) {
                        Ok(()) => notes.push(format!("restored previous {role}")),
                        Err(_) => {
                            notes.push(format!(
                                "previous {role} restore failed; disposition uncertain"
                            ));
                        }
                    }
                }
                Err(_) => {
                    notes.push(format!(
                        "{role} left in place: inaccessible marker; previous-state restore skipped"
                    ));
                }
            }
        }
    }
}

/// Windows share mode for the owned single-instance lock: read-only sharing
/// (`FILE_SHARE_READ`, numeric literal matching the `claim_root_lease`
/// precedent in `eliot-store`) denies concurrent write and delete access
/// while the owner holds the creation handle, so a stale observer or a
/// finishing old `Drop` cannot unlink a live owner's lock. A dead owner
/// holds no handle, so a proven-dead lock stays reclaimable.
#[cfg(windows)]
const SINGLE_INSTANCE_LOCK_SHARE_MODE: u32 = 1;

/// Exclusive-creation outcome. `Exists` means a competing starter holds the
/// path; only the lifecycle-owned recovery protocol may act on it.
enum LockCreateOutcome {
    Created(File),
    Exists,
    Io(std::io::Error),
}

fn create_single_instance_lock_file(lock_path: &Path) -> LockCreateOutcome {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.share_mode(SINGLE_INSTANCE_LOCK_SHARE_MODE);
    }
    match options.open(lock_path) {
        Ok(file) => LockCreateOutcome::Created(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            LockCreateOutcome::Exists
        }
        Err(error) => LockCreateOutcome::Io(error),
    }
}

fn single_instance_contention(
    lock_path: &Path,
    refusal: SingleInstanceRefusal,
    detail: impl Into<String>,
) -> EngineError {
    EngineError::SingleInstanceContention {
        lock_path: lock_path.to_path_buf(),
        refusal,
        detail: detail.into(),
    }
}

fn read_file_evidence(path: &Path) -> SingleInstanceFileEvidence {
    match std::fs::read(path) {
        Ok(bytes) => SingleInstanceFileEvidence::Present(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            SingleInstanceFileEvidence::Missing
        }
        Err(error) => SingleInstanceFileEvidence::Inaccessible {
            detail: error.to_string(),
        },
    }
}

/// Refuses when caller-supplied present evidence no longer matches the
/// locally re-read state: the world rotated between observation and
/// decision, so acting would risk a replacement owner's objects. A caller
/// observation of a now-vanished file is not a contradiction — there is
/// simply nothing left to unlink.
fn require_no_rotation(
    lock_path: &Path,
    role: &str,
    observed: &SingleInstanceFileEvidence,
    local: &SingleInstanceFileEvidence,
) -> Result<(), EngineError> {
    match (observed, local) {
        (
            SingleInstanceFileEvidence::Present(expected),
            SingleInstanceFileEvidence::Present(actual),
        ) if expected != actual => Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::ContradictoryIdentity,
            format!("{role} changed between observation and decision; refusing removal"),
        )),
        (SingleInstanceFileEvidence::Present(_), SingleInstanceFileEvidence::Missing) => {
            Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::ReplacementDetected,
                format!("{role} vanished between observation and decision; refusing removal"),
            ))
        }
        _ => Ok(()),
    }
}

/// Binds every present identity source to exactly one owner PID.
/// Empty byte sources carry no evidence (a halfway write), never identity;
/// non-empty unparseable sources, zero PIDs, and disagreements between the
/// PID file, the lock bytes, and the app-validated publication all refuse
/// mutation instead of guessing.
fn agree_single_owner_pid(
    lock_path: &Path,
    pid_file_bytes: Option<&[u8]>,
    lock_bytes: Option<&[u8]>,
    publication_pid: Option<u32>,
) -> Result<u32, EngineError> {
    let mut candidates = Vec::new();
    if let Some(bytes) = pid_file_bytes
        && let Some(pid) = parse_owner_pid_bytes(bytes, "daemon.pid", lock_path)?
    {
        candidates.push(pid);
    }
    if let Some(bytes) = lock_bytes
        && let Some(pid) = parse_owner_pid_bytes(bytes, "daemon.lock", lock_path)?
    {
        candidates.push(pid);
    }
    if let Some(pid) = publication_pid {
        candidates.push(pid);
    }
    candidates.sort_unstable();
    candidates.dedup();
    match candidates.as_slice() {
        [pid] => Ok(*pid),
        [] => Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::UnknownOwner,
            "no owner PID in the PID file, the lock, or the publication; refusing unproven removal",
        )),
        _ => Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::ContradictoryIdentity,
            format!("identity sources disagree on the lock owner {candidates:?}; refusing removal"),
        )),
    }
}

/// Parses one identity source. Empty content is absent evidence (`None`);
/// anything non-empty that is not a non-zero PID is malformed and refuses.
fn parse_owner_pid_bytes(
    bytes: &[u8],
    role: &str,
    lock_path: &Path,
) -> Result<Option<u32>, EngineError> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        single_instance_contention(
            lock_path,
            SingleInstanceRefusal::MalformedIdentity,
            format!("{role} owner identity is not UTF-8; refusing removal"),
        )
    })?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    let pid = trimmed.parse::<u32>().map_err(|_| {
        single_instance_contention(
            lock_path,
            SingleInstanceRefusal::MalformedIdentity,
            format!("{role} owner identity is not a PID; refusing removal"),
        )
    })?;
    if pid == 0 {
        return Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::MalformedIdentity,
            format!("{role} names the impossible zero PID; refusing removal"),
        ));
    }
    Ok(Some(pid))
}

/// Requires the agreed owner PID to be provably dead. A live owner, a
/// denied liveness probe, and an unsupported platform all refuse takeover;
/// only an observed death of the bound owner authorizes it. PID reuse can
/// never authorize: a recycled live PID reports live and refuses.
fn probe_owner_dead(lock_path: &Path, owner_pid: u32) -> Result<(), EngineError> {
    match probe_owner_liveness(owner_pid) {
        Ok(false) => Ok(()),
        Ok(true) => Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::LiveOwner,
            format!("owner PID {owner_pid} is alive; refusing competing startup"),
        )),
        Err(detail) => Err(single_instance_contention(
            lock_path,
            liveness_refusal(),
            format!("cannot prove owner PID {owner_pid} dead: {detail}"),
        )),
    }
}

#[cfg(windows)]
fn probe_owner_liveness(pid: u32) -> Result<bool, String> {
    eliot_windows_ipc::process_is_alive(pid).map_err(|error| error.to_string())
}

#[cfg(windows)]
fn liveness_refusal() -> SingleInstanceRefusal {
    SingleInstanceRefusal::InaccessibleEvidence
}

#[cfg(not(windows))]
fn probe_owner_liveness(_pid: u32) -> Result<bool, String> {
    Err("single-instance identity recovery is a Windows-runtime concern".to_owned())
}

#[cfg(not(windows))]
fn liveness_refusal() -> SingleInstanceRefusal {
    SingleInstanceRefusal::UnsupportedPlatform
}

/// Re-verifies the PID-file snapshot immediately before mutation: a
/// replaced or newly appeared PID file proves the world rotated and refuses
/// removal instead of unlinking a successor's evidence.
fn confirm_pid_snapshot_unchanged(
    lock_path: &Path,
    pid_path: &Path,
    pid_snapshot: Option<&[u8]>,
) -> Result<(), EngineError> {
    match std::fs::read(pid_path).ok() {
        Some(current) if Some(current.as_slice()) == pid_snapshot => Ok(()),
        _ => Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            "daemon.pid was replaced during stale-owner validation; refusing removal",
        )),
    }
}

/// Retires the exact stale PID object while the old lock pin still blocks
/// successor acquisition. Must be called with the validated lock pin live:
/// the lock path still exists, so no successor can create its lock or publish
/// its PID yet. Binds removal to object identity on Windows (same PID text on
/// a replacement object never authorizes deletion) and preserves the
/// Missing vs Inaccessible vs `ReplacementDetected` outcomes. Returns `true`
/// when the PID evidence is gone (removed or already absent) and `false` only
/// when there was no PID evidence to retire.
fn retire_stale_pid_while_lock_held(
    lock_path: &Path,
    pid_path: &Path,
    pid_snapshot: Option<&[u8]>,
) -> Result<bool, EngineError> {
    match pid_snapshot {
        None => {
            if pid_path.exists() {
                return Err(single_instance_contention(
                    lock_path,
                    SingleInstanceRefusal::ReplacementDetected,
                    "daemon.pid appeared during stale-owner validation; refusing removal",
                ));
            }
            Ok(false)
        }
        Some(snapshot) => {
            confirm_pid_snapshot_unchanged(lock_path, pid_path, Some(snapshot))?;
            #[cfg(windows)]
            {
                let pinned = pin_single_instance_pid(pid_path, snapshot, lock_path)?;
                let pinned_identity = pinned.identity();
                confirm_pid_identity(pid_path, snapshot, pinned_identity, lock_path)?;
                drop(pinned);
                confirm_pid_snapshot_unchanged(lock_path, pid_path, Some(snapshot))?;
            }
            match std::fs::remove_file(pid_path) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
                Err(error) => Err(EngineError::Io(error)),
            }
        }
    }
}

/// Pins the validated PID path with delete/write sharing denied and proves
/// the pinned object still carries the validated snapshot bytes. The caller
/// must hold the old lock pin live across this call, so no successor can
/// publish a replacement PID while the pin is held.
#[cfg(windows)]
fn pin_single_instance_pid(
    pid_path: &Path,
    pid_snapshot: &[u8],
    lock_path: &Path,
) -> Result<eliot_windows_ipc::PinnedFile, EngineError> {
    let mut pinned = match eliot_windows_ipc::PinnedFile::open(pid_path) {
        Ok(pinned) => pinned,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::ReplacementDetected,
                "daemon.pid vanished during stale-owner validation; refusing removal",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::MalformedIdentity,
                "daemon.pid is not a regular file; refusing removal",
            ));
        }
        Err(error) => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::InaccessibleEvidence,
                format!("cannot pin daemon.pid for validated removal: {error}"),
            ));
        }
    };
    match pinned.read_all() {
        Ok(bytes) if bytes == pid_snapshot => Ok(pinned),
        _ => Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            "daemon.pid changed during stale-owner validation; refusing removal",
        )),
    }
}

/// Proves the PID path still resolves to the pinned validation object just
/// before retirement: a fresh pin must expose the same `FileIdentity` and the
/// same snapshot bytes. A replacement PID file carrying identical bytes
/// resolves to a different object identity and is refused here instead of
/// unlinked under stale authority.
#[cfg(windows)]
fn confirm_pid_identity(
    pid_path: &Path,
    pid_snapshot: &[u8],
    pinned_identity: eliot_windows_ipc::FileIdentity,
    lock_path: &Path,
) -> Result<(), EngineError> {
    let mut fresh = match eliot_windows_ipc::PinnedFile::open(pid_path) {
        Ok(fresh) => fresh,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::ReplacementDetected,
                "daemon.pid vanished during stale-owner validation; refusing removal",
            ));
        }
        Err(error) => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::InaccessibleEvidence,
                format!("cannot re-pin daemon.pid before validated removal: {error}"),
            ));
        }
    };
    let bytes = match fresh.read_all() {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::InaccessibleEvidence,
                format!("cannot re-read daemon.pid before validated removal: {error}"),
            ));
        }
    };
    if fresh.identity() != pinned_identity || bytes != pid_snapshot {
        return Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            "daemon.pid was replaced during stale-owner validation; refusing removal",
        ));
    }
    Ok(())
}

/// Removes a validated stale lock. A vanished path means a competing starter
/// reclaimed it; a sharing/permission denial means a live owner holds the
/// lock with delete sharing denied — both refuse as replacement instead of
/// surfacing I/O noise. Genuine I/O failures stay typed.
fn remove_reclaimed_lock(lock_path: &Path) -> Result<(), EngineError> {
    match std::fs::remove_file(lock_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::ReplacementDetected,
                "daemon.lock vanished during stale-owner recovery; a competing starter reclaimed it",
            ))
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::WouldBlock
            ) =>
        {
            Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::ReplacementDetected,
                "daemon.lock is held by a live owner; refusing removal",
            ))
        }
        Err(error) => Err(EngineError::Io(error)),
    }
}

/// Pins the validated lock path with delete/write sharing denied and proves
/// the pinned object still carries the validated snapshot bytes.
///
/// The returned handle must stay alive across the remaining validation:
/// while it is open, no contender can replace or unlink the lock object,
/// and every byte re-read comes from the pinned object rather than a
/// re-resolved path, which a byte re-read alone cannot guarantee.
#[cfg(windows)]
fn pin_single_instance_lock(
    lock_path: &Path,
    lock_snapshot: &[u8],
) -> Result<eliot_windows_ipc::PinnedFile, EngineError> {
    let mut pinned = match eliot_windows_ipc::PinnedFile::open(lock_path) {
        Ok(pinned) => pinned,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::ReplacementDetected,
                "daemon.lock vanished during stale-owner validation; refusing removal",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::MalformedIdentity,
                "daemon.lock is not a regular file; refusing removal",
            ));
        }
        Err(error) => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::InaccessibleEvidence,
                format!("cannot pin daemon.lock for validated removal: {error}"),
            ));
        }
    };
    match pinned.read_all() {
        Ok(bytes) if bytes == lock_snapshot => Ok(pinned),
        _ => Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            "daemon.lock changed during stale-owner validation; refusing removal",
        )),
    }
}

/// Proves the lock path still resolves to the pinned validation object just
/// before mutation: a fresh pin must expose the same `FileIdentity` and the
/// same snapshot bytes. A replacement lock created after validation carries
/// a different object identity and is refused here instead of unlinked.
#[cfg(windows)]
fn confirm_single_instance_identity(
    lock_path: &Path,
    lock_snapshot: &[u8],
    pinned_identity: eliot_windows_ipc::FileIdentity,
) -> Result<(), EngineError> {
    let mut fresh = match eliot_windows_ipc::PinnedFile::open(lock_path) {
        Ok(fresh) => fresh,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::ReplacementDetected,
                "daemon.lock vanished during stale-owner validation; refusing removal",
            ));
        }
        Err(error) => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::InaccessibleEvidence,
                format!("cannot re-pin daemon.lock before validated removal: {error}"),
            ));
        }
    };
    let bytes = match fresh.read_all() {
        Ok(bytes) => bytes,
        Err(error) => {
            return Err(single_instance_contention(
                lock_path,
                SingleInstanceRefusal::InaccessibleEvidence,
                format!("cannot re-read daemon.lock before validated removal: {error}"),
            ));
        }
    };
    if fresh.identity() != pinned_identity || bytes != lock_snapshot {
        return Err(single_instance_contention(
            lock_path,
            SingleInstanceRefusal::ReplacementDetected,
            "daemon.lock was replaced during stale-owner validation; refusing removal",
        ));
    }
    Ok(())
}

/// Platform file-object identity backs the ownership proof on Windows via
/// `eliot_windows_ipc::PinnedFile` (deny-delete pin spanning validation to
/// mutation plus a `FileIdentity` comparison just before removal — see
/// `pin_single_instance_lock` and `confirm_single_instance_identity`). The
/// byte-content check below is the portable re-proof used at every removal
/// and establishment gate: the agreed owner PID is unique among live
/// processes, so a path carrying our PID bytes names our claim. Combined
/// with exclusive creation (exactly one `create_new` succeeds), the owner's
/// deny-delete creation handle (a live successor's lock resists unlink), and
/// the final triple verification in `establish_single_instance_ownership`, a
/// stale observer cannot unlink a replacement lock without meeting a
/// `ReplacementDetected` refusal instead of becoming a second owner.
fn path_names_owned_lock(lock_path: &Path, owner_bytes: &[u8]) -> bool {
    std::fs::read(lock_path).ok().as_deref() == Some(owner_bytes)
}

/// Captures the PID file object identity bound at establishment, so `Drop`
/// can refuse to unlink a replacement object carrying identical bytes. Best
/// effort: `None` preserves the portable byte-proof path when the PID file
/// cannot be pinned (the final triple verification above still gates the
/// return on exact bytes).
#[cfg(windows)]
fn capture_pid_identity(
    runtime_dir: &Path,
    owner_text: &str,
) -> Option<eliot_windows_ipc::FileIdentity> {
    let pid_path = runtime_dir.join("daemon.pid");
    let mut pinned = eliot_windows_ipc::PinnedFile::open(&pid_path).ok()?;
    let bytes = pinned.read_all().ok()?;
    if bytes != owner_text.as_bytes() {
        return None;
    }
    Some(pinned.identity())
}

/// Reads an optional marker file. Missing is `Ok(None)`; any read failure
/// is reported with its cause so owned setup can fail closed with the
/// reason preserved. Missing and inaccessible stay different outcomes:
/// only a missing marker lets setup proceed.
fn read_optional_bytes(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Removes a marker file that must already be absent-or-owned. A missing
/// file is fine; any other removal error is returned.
fn remove_optional_file(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Owner-scoped marker content binding the marker to one owner PID.
/// Legacy bare-timestamp markers parse to `None`: historic and ambiguous,
/// never attributed to any owner.
fn format_owner_marker(owner_pid: u32) -> String {
    format!(
        "owner_pid={owner_pid}\nestablished_at={}\n",
        OffsetDateTime::now_utc()
    )
}

fn parse_owner_marker(bytes: &[u8]) -> Option<u32> {
    let text = std::str::from_utf8(bytes).ok()?;
    let pid = text
        .lines()
        .next()?
        .strip_prefix("owner_pid=")?
        .trim()
        .parse::<u32>()
        .ok()?;
    if pid == 0 { None } else { Some(pid) }
}

pub struct RuntimeLock {
    lock_path: PathBuf,
    pid_path: PathBuf,
    clean_marker_path: PathBuf,
    owner_pid: u32,
    lock_handle: Option<File>,
    #[cfg(windows)]
    pid_identity: Option<eliot_windows_ipc::FileIdentity>,
}

impl RuntimeLock {
    /// Records a clean shutdown for this owner only, after IPC/publication
    /// and owned database shutdown have actually completed (the caller
    /// orders those first). Refuses to mark clean when the lock no longer
    /// proves this owner: a successor's objects are never unlinked and
    /// another owner is never marked clean. Missing and inaccessible lock
    /// files are different outcomes: a missing lock is a lost ownership
    /// refusal, a denied read refuses as inaccessible evidence.
    pub fn mark_clean_shutdown(&self) -> Result<(), EngineError> {
        let owner_text = self.owner_pid.to_string();
        match std::fs::read(&self.lock_path) {
            Ok(current) if current == owner_text.as_bytes() => {}
            Ok(_) => {
                return Err(single_instance_contention(
                    &self.lock_path,
                    SingleInstanceRefusal::ReplacementDetected,
                    "the lock no longer names this owner; refusing to mark another owner clean",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(single_instance_contention(
                    &self.lock_path,
                    SingleInstanceRefusal::ReplacementDetected,
                    "the lock is gone; refusing to mark a lost ownership clean",
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(single_instance_contention(
                    &self.lock_path,
                    SingleInstanceRefusal::InaccessibleEvidence,
                    format!("cannot prove lock ownership: access denied: {error}"),
                ));
            }
            Err(error) => return Err(EngineError::Io(error)),
        }
        if !(path_names_owned_lock(&self.lock_path, owner_text.as_bytes())
            && std::fs::read(&self.pid_path).ok().as_deref() == Some(owner_text.as_bytes()))
        {
            return Err(single_instance_contention(
                &self.lock_path,
                SingleInstanceRefusal::ReplacementDetected,
                "the lock or PID file no longer names this owner; refusing to mark another owner clean",
            ));
        }
        std::fs::write(&self.clean_marker_path, format_owner_marker(self.owner_pid))?;
        Ok(())
    }
}

impl Drop for RuntimeLock {
    fn drop(&mut self) {
        // Release only owned resources: a successor's lock, PID file, or
        // clean indication is never removed or written here.
        //
        // The PID file is retired while the owned creation handle is still
        // live: the lock path still exists at that point, so no successor can
        // have created its lock or published its PID yet. Only after the PID
        // retirement is the handle closed and the lock removed. A finishing
        // old Drop therefore cannot delete a successor's objects. On Windows
        // the PID unlink is additionally bound to the file-object identity
        // captured at establishment: identical bytes on a replacement object
        // never authorize deletion.
        retire_owned_pid_while_lock_held(self);
        drop(self.lock_handle.take());
        if path_names_owned_lock(&self.lock_path, self.owner_pid.to_string().as_bytes()) {
            let _ = std::fs::remove_file(&self.lock_path);
        }
    }
}

/// Best-effort PID retirement for `Drop`: removes the PID file only while the
/// owned lock handle is still live and only when the PID object proves this
/// owner (bytes plus, on Windows, file-object identity). Never panics and
/// never touches a successor or foreign object; any doubt leaves the file in
/// place for bounded recovery.
fn retire_owned_pid_while_lock_held(lock: &RuntimeLock) {
    if lock.lock_handle.is_none() {
        return;
    }
    let owner_text = lock.owner_pid.to_string();
    let owned_bytes = std::fs::read(&lock.pid_path).ok().as_deref() == Some(owner_text.as_bytes());
    if !owned_bytes {
        return;
    }
    #[cfg(windows)]
    {
        if !pid_drop_identity_permits_removal(lock, &owner_text) {
            return;
        }
    }
    let _ = std::fs::remove_file(&lock.pid_path);
}

/// Windows object-identity gate for `Drop` PID retirement: the current PID
/// path must resolve to the establishment-time object (or, when no identity
/// was captured, to one stable object across two fresh pins) with exact owner
/// bytes. Identical bytes on a different object refuse removal.
#[cfg(windows)]
fn pid_drop_identity_permits_removal(lock: &RuntimeLock, owner_text: &str) -> bool {
    let Ok(mut first) = eliot_windows_ipc::PinnedFile::open(&lock.pid_path) else {
        return false;
    };
    let Ok(first_bytes) = first.read_all() else {
        return false;
    };
    if first_bytes != owner_text.as_bytes() {
        return false;
    }
    let first_identity = first.identity();
    if let Some(expected) = lock.pid_identity
        && expected != first_identity
    {
        return false;
    }
    drop(first);
    let Ok(mut second) = eliot_windows_ipc::PinnedFile::open(&lock.pid_path) else {
        return false;
    };
    let Ok(second_bytes) = second.read_all() else {
        return false;
    };
    second_bytes == owner_text.as_bytes() && second.identity() == first_identity
}

pub struct HealthService;

impl HealthService {
    pub fn report(mode: RuntimeMode, services: Vec<ServiceRuntimeStatus>) -> RuntimeHealthReport {
        let mut degraded_reasons = Vec::new();
        let mut ready = true;
        let mut aggregate = ServiceHealthState::Healthy;
        for service in &services {
            if service.health == ServiceHealthState::Failed {
                ready = false;
                aggregate = ServiceHealthState::Failed;
                degraded_reasons.push(format!(
                    "{} failed: {}",
                    service.service_name, service.message
                ));
            } else if service.health.is_degraded() {
                ready = false;
                if aggregate != ServiceHealthState::Failed {
                    aggregate = service.health;
                }
                degraded_reasons.push(format!(
                    "{} degraded: {}",
                    service.service_name, service.message
                ));
            }
        }
        RuntimeHealthReport {
            component: "runtime_health".to_owned(),
            mode,
            ready,
            health: aggregate,
            degraded_reasons,
            services,
            generated_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn degraded_no_db(mode: RuntimeMode) -> RuntimeHealthReport {
        Self::report(
            mode,
            vec![ServiceRuntimeStatus {
                service_name: "memory_db".to_owned(),
                health: ServiceHealthState::DegradedNoDb,
                started: false,
                restart_budget_remaining: 0,
                message: "database unavailable; writes cannot be claimed successful".to_owned(),
            }],
        )
    }

    pub fn degraded_no_verifier(mode: RuntimeMode) -> RuntimeHealthReport {
        Self::report(
            mode,
            vec![ServiceRuntimeStatus {
                service_name: "verifier".to_owned(),
                health: ServiceHealthState::DegradedNoVerifier,
                started: false,
                restart_budget_remaining: 0,
                message: "verifier unavailable; DONE_VERIFIED cannot be granted".to_owned(),
            }],
        )
    }
}

pub struct LogService {
    log_path: PathBuf,
    max_file_bytes: u64,
}

impl LogService {
    pub fn new(log_root: impl Into<PathBuf>) -> Self {
        Self {
            log_path: log_root.into().join("eliot-governor.jsonl"),
            max_file_bytes: 10_485_760,
        }
    }

    #[must_use]
    pub fn with_max_file_bytes(mut self, max_file_bytes: u64) -> Self {
        self.max_file_bytes = max_file_bytes;
        self
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    pub fn write_event(&self, mut event: EliotLogEvent) -> Result<EliotLogEvent, EngineError> {
        self.rotate_if_needed()?;
        redact_event(&mut event);
        if let Some(parent) = self.log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        serde_json::to_writer(&mut file, &event)?;
        writeln!(file)?;
        Ok(event)
    }

    pub fn event(
        level: LogLevel,
        event_kind: LogEventKind,
        target: impl Into<String>,
        message: impl Into<String>,
        trace_id: Option<String>,
    ) -> EliotLogEvent {
        EliotLogEvent {
            timestamp: OffsetDateTime::now_utc(),
            level,
            target: target.into(),
            message: message.into(),
            trace_id,
            span_id: None,
            project_id: None,
            task_id: None,
            agent_session_id: None,
            work_item_id: None,
            work_lease_id: None,
            action_lease_id: None,
            patch_run_id: None,
            module_id: None,
            event_kind,
            fields_ref: None,
            redaction: RedactionInfo {
                secrets_redacted: false,
                raw_payload_redacted: false,
                redacted_fields: Vec::new(),
            },
        }
    }

    pub fn tail(&self, limit: usize) -> Result<Vec<EliotLogEvent>, EngineError> {
        let events = self.read_events()?;
        let start = events.len().saturating_sub(limit.max(1));
        Ok(events[start..].to_vec())
    }

    pub fn report(&self) -> Result<RuntimeLogReport, EngineError> {
        let events = self.read_events()?;
        Ok(RuntimeLogReport {
            component: "runtime_logs".to_owned(),
            log_path: self.log_path.display().to_string(),
            jsonl_parse_ok: true,
            event_count: events.len(),
            last_trace_id: events.iter().rev().find_map(|event| event.trace_id.clone()),
            redaction_checked: events.iter().any(|event| event.redaction.secrets_redacted),
            generated_at: OffsetDateTime::now_utc(),
        })
    }

    fn read_events(&self) -> Result<Vec<EliotLogEvent>, EngineError> {
        if !self.log_path.exists() {
            return Ok(Vec::new());
        }
        let content = std::fs::read_to_string(&self.log_path)?;
        content
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(serde_json::from_str)
            .collect::<Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    fn rotate_if_needed(&self) -> Result<(), EngineError> {
        if self.max_file_bytes == 0 || !self.log_path.exists() {
            return Ok(());
        }
        let metadata = std::fs::metadata(&self.log_path)?;
        if metadata.len() <= self.max_file_bytes {
            return Ok(());
        }
        let rotated_path = self.log_path.with_extension("jsonl.1");
        let _ = std::fs::remove_file(&rotated_path);
        std::fs::rename(&self.log_path, rotated_path)?;
        Ok(())
    }
}

pub struct ReportService {
    report_root: PathBuf,
}

impl ReportService {
    pub fn new(report_root: impl Into<PathBuf>) -> Self {
        Self {
            report_root: report_root.into(),
        }
    }

    pub fn write_latest<T: Serialize>(
        &self,
        section: &str,
        report: &T,
        markdown: &str,
    ) -> Result<(PathBuf, PathBuf), EngineError> {
        let dir = self.report_root.join(section);
        std::fs::create_dir_all(&dir)?;
        let json_path = dir.join("latest.json");
        let md_path = dir.join("latest.md");
        let json = serde_json::to_string_pretty(report)?;
        std::fs::write(&json_path, json)?;
        std::fs::write(&md_path, markdown)?;
        self.write_index(section, &json_path, &md_path)?;
        Ok((json_path, md_path))
    }

    fn write_index(
        &self,
        section: &str,
        json_path: &Path,
        md_path: &Path,
    ) -> Result<(), EngineError> {
        std::fs::create_dir_all(&self.report_root)?;
        let index_path = self.report_root.join("index.json");
        let index = serde_json::json!({
            "updated_section": section,
            "latest_json": json_path,
            "latest_md": md_path,
            "updated_at": OffsetDateTime::now_utc(),
        });
        std::fs::write(index_path, serde_json::to_string_pretty(&index)?)?;
        Ok(())
    }
}

pub struct ModuleRegistryService {
    manifests: Vec<ModuleManifest>,
}

impl ModuleRegistryService {
    pub fn new(manifests: Vec<ModuleManifest>) -> Result<Self, EngineError> {
        let service = Self { manifests };
        for manifest in &service.manifests {
            service.validate_manifest(manifest)?;
        }
        Ok(service)
    }

    pub fn builtin() -> Result<Self, EngineError> {
        Self::new(builtin_manifests())
    }

    pub fn manifests(&self) -> &[ModuleManifest] {
        &self.manifests
    }

    pub fn validate_manifest(&self, manifest: &ModuleManifest) -> Result<(), EngineError> {
        if manifest.name.trim().is_empty() {
            return Err(module_rejected("module name is required"));
        }
        if manifest.version.trim().is_empty() {
            return Err(module_rejected("module version is required"));
        }
        if manifest.authority_profile.can_write_truth
            || manifest.authority_profile.can_request_patch
            || manifest.authority_profile.can_finish_task
        {
            return Err(module_rejected(
                "module authority cannot grant truth, patch, or finish authority",
            ));
        }
        if manifest.module_kind == ModuleKind::CandidateAgentAdapter
            && manifest.transport != ModuleTransport::Disabled
        {
            return Err(module_rejected(
                "candidate agent adapters are schema-only and must be disabled",
            ));
        }
        if manifest
            .endpoints
            .iter()
            .any(|endpoint| endpoint.max_payload_bytes > manifest.resource_limits.max_payload_bytes)
        {
            return Err(module_rejected(
                "endpoint payload exceeds module resource limit",
            ));
        }
        Ok(())
    }

    pub fn capability_known(value: &str) -> bool {
        ModuleCapability::from_wire_name(value).is_some()
    }

    pub fn list_modules(&self) -> Vec<ModuleHealth> {
        self.manifests
            .iter()
            .map(|manifest| ModuleHealth {
                module_id: manifest.module_id,
                name: manifest.name.clone(),
                enabled: manifest.enabled_by_default
                    && manifest.transport != ModuleTransport::Disabled,
                health: if manifest.enabled_by_default
                    && manifest.transport != ModuleTransport::Disabled
                {
                    ServiceHealthState::Healthy
                } else {
                    ServiceHealthState::Stopped
                },
                message: if manifest.transport == ModuleTransport::Disabled {
                    "disabled module contract only".to_owned()
                } else {
                    "health-only internal module".to_owned()
                },
            })
            .collect()
    }

    pub fn report(&self) -> ModuleRegistryReport {
        ModuleRegistryReport {
            component: "module_registry".to_owned(),
            modules: self.list_modules(),
            manifests_loaded: self.manifests.len(),
            unknown_capabilities_denied: !Self::capability_known("raw_db"),
            authority_bypass_denied: self
                .manifests
                .iter()
                .all(|manifest| self.validate_manifest(manifest).is_ok()),
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct RuntimeAdapterSupervisorSkeleton;

impl RuntimeAdapterSupervisorSkeleton {
    pub fn health_only(manifests: &[ModuleManifest]) -> Vec<ModuleHealth> {
        manifests
            .iter()
            .map(|manifest| ModuleHealth {
                module_id: manifest.module_id,
                name: manifest.name.clone(),
                enabled: false,
                health: ServiceHealthState::Stopped,
                message: "adapter supervisor skeleton; external execution disabled".to_owned(),
            })
            .collect()
    }
}

pub struct ExchangeEnvelopeService;

impl ExchangeEnvelopeService {
    pub fn envelope<T: Serialize + Clone>(
        project_id: eliot_types::ProjectId,
        task_id: Option<eliot_types::TaskId>,
        source: ExchangeParty,
        destination: ExchangeParty,
        kind: ExchangeKind,
        authority: AuthorityHeader,
        payload: T,
    ) -> Result<EliotExchangeEnvelope<T>, EngineError> {
        let payload_bytes = serde_json::to_vec(&payload)?;
        let payload_hash = blake3::hash(&payload_bytes).to_hex().to_string();
        let now = OffsetDateTime::now_utc();
        Ok(EliotExchangeEnvelope {
            envelope_id: format!("envelope-{}-{payload_hash}", now.unix_timestamp_nanos()),
            schema_version: "1".to_owned(),
            project_id,
            task_id,
            source,
            destination,
            kind,
            causality: CausalityHeader {
                trace_id: format!("trace-{}", now.unix_timestamp_nanos()),
                parent_envelope_id: None,
                causation_id: None,
                correlation_id: None,
                sequence: 1,
            },
            authority,
            payload,
            payload_hash,
            payload_ref: None,
            created_at: now,
        })
    }

    pub fn module_blackboard_candidate(
        module_id: eliot_types::ModuleId,
        project_id: eliot_types::ProjectId,
        task_id: Option<eliot_types::TaskId>,
        payload: Value,
    ) -> Result<EliotExchangeEnvelope<Value>, EngineError> {
        Self::envelope(
            project_id,
            task_id,
            ExchangeParty::Module(module_id),
            ExchangeParty::Governor,
            ExchangeKind::BlackboardItem,
            AuthorityHeader {
                role: None,
                capabilities: vec![ModuleCapability::SubmitFindingCandidate],
                lease_refs: Vec::new(),
                taint: TaintClass::ExternalAgent,
            },
            payload,
        )
    }
}

pub fn default_runtime_services() -> Vec<Box<dyn ServiceLifecycle>> {
    vec![
        Box::new(StaticRuntimeService::healthy("lifecycle")),
        Box::new(StaticRuntimeService::healthy("memory")),
        Box::new(StaticRuntimeService::healthy("coordination")),
        Box::new(StaticRuntimeService::healthy("module_registry")),
        Box::new(StaticRuntimeService::healthy("adapter_supervisor")),
        Box::new(StaticRuntimeService::healthy("logs")),
        Box::new(StaticRuntimeService::healthy("reports")),
    ]
}

pub fn builtin_manifests() -> Vec<ModuleManifest> {
    vec![
        builtin_manifest(
            "builtin.memory",
            ModuleKind::InternalRust,
            vec![ModuleCapability::ReadMemory],
        ),
        builtin_manifest(
            "builtin.mailbox",
            ModuleKind::InternalRust,
            vec![
                ModuleCapability::HealthCheck,
                ModuleCapability::SubmitFindingCandidate,
            ],
        ),
        builtin_manifest(
            "builtin.codecortex",
            ModuleKind::InternalRust,
            vec![
                ModuleCapability::ReadMemory,
                ModuleCapability::SubmitFindingCandidate,
                ModuleCapability::HealthCheck,
            ],
        ),
        builtin_manifest(
            "builtin.verifier",
            ModuleKind::VerifierAdapter,
            vec![
                ModuleCapability::SubmitVerifierResult,
                ModuleCapability::RunVerifier,
                ModuleCapability::HealthCheck,
            ],
        ),
    ]
}

fn builtin_manifest(
    name: &str,
    module_kind: ModuleKind,
    capabilities: Vec<ModuleCapability>,
) -> ModuleManifest {
    let schema = SchemaRef {
        schema_id: format!("{name}.health"),
        version: "1".to_owned(),
    };
    ModuleManifest {
        module_id: eliot_types::ModuleId::new_v7(),
        name: name.to_owned(),
        version: "0.1.0".to_owned(),
        description: "built-in health-only module contract".to_owned(),
        module_kind,
        transport: ModuleTransport::InProcess,
        capabilities: capabilities.clone(),
        endpoints: vec![ModuleEndpoint {
            endpoint_id: "health".to_owned(),
            name: "health".to_owned(),
            direction: eliot_types::EndpointDirection::Bidirectional,
            schema: schema.clone(),
            max_payload_bytes: 4096,
            requires_ack: true,
        }],
        input_schemas: vec![schema.clone()],
        output_schemas: vec![schema],
        authority_profile: eliot_types::ModuleAuthorityProfile {
            allowed_projects: Vec::new(),
            allowed_roles: Vec::new(),
            allowed_capabilities: capabilities,
            can_write_truth: false,
            can_request_patch: false,
            can_finish_task: false,
        },
        resource_limits: ModuleResourceLimits::default(),
        enabled_by_default: true,
    }
}

fn redact_event(event: &mut EliotLogEvent) {
    let lowered = event.message.to_ascii_lowercase();
    let secret_like = ["password", "secret", "token", "bearer"]
        .iter()
        .any(|marker| lowered.contains(marker));
    if secret_like {
        "[redacted secret-like value]".clone_into(&mut event.message);
        event.redaction.secrets_redacted = true;
        event.redaction.redacted_fields.push("message".to_owned());
    }
}

fn module_rejected(reason: &str) -> EngineError {
    EngineError::ServiceNotReady {
        service: "module_registry".to_owned(),
        reason: reason.to_owned(),
    }
}

pub fn shutdown_deadline_after(duration: Duration) -> Instant {
    Instant::now() + duration
}
