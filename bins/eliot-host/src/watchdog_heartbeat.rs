//! Host-to-Watchdog heartbeat transport, Host side (Windows only).
//!
//! Architecture: A8.1 (independent supervision), A0.3 (fail closed where a
//! silent gap could become hidden authority). Implementation: I8.2
//! (named-pipe observation route with CONTINUOUS/PARTIAL/BLIND coverage),
//! I1.6 (explicit pipe ACLs plus handle-bound peer checks), I1.5 (no
//! supervised claim without a fresh observation).
//!
//! This child owns the per-instance rendezvous (pipe plus 256-bit
//! challenge), the ACL-restricted listener, the derived Host observation,
//! and the admission validator. It owns no SCM registration, lease
//! issuance, canonical, or Kernel authority. The admission path consumes
//! only the derived observation below, never raw pipe bytes.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use eliot_runtime_contracts::{
    HOST_HEARTBEAT_OBSERVATION_FILE_NAME, HOST_HEARTBEAT_OBSERVATION_SCHEMA,
    WATCHDOG_HEARTBEAT_PIPE_PREFIX, WATCHDOG_HEARTBEAT_PROTOCOL, WATCHDOG_HEARTBEAT_SERVICE,
    WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME, WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
};
use sha2::{Digest as _, Sha256};

use super::watchdog_publication::write_watchdog_publication_child;
use super::watchdog_service_start::VerifiedWatchdogScmRunning;
use super::{HostError, PlatformHandle, sha256_json, windows_paths_equal};
use eliot_platform_windows::fresh_service_registration_nonce;

/// Upper bound for one transport descriptor or observation file.
const TRANSPORT_FILE_LIMIT: u64 = 4096;
/// Upper bound for one pipe message, including the newline.
const MESSAGE_LIMIT: usize = 8192;
/// Exact length of the lowercase-hex host challenge.
const NONCE_HEX_LEN: usize = 64;
/// Exact length of the lowercase-hex service instance guid.
const GUID_HEX_LEN: usize = 32;
/// Transport-local bound for the installation identity echo.
const INSTALLATION_ID_LIMIT: usize = 128;
/// Freshness deadline expressed as a small multiple of the admitted tick,
/// per the writer field contract: a projection older than this without a
/// fresh admitted heartbeat is unresponsive, never current coverage.
const FRESHNESS_TICK_MULTIPLE: u64 = 3;
/// Bounded Host listen window per admission: four default watchdog ticks.
const ADMISSION_READ_TIMEOUT: Duration = Duration::from_secs(8);
/// Sanity bounds for a writer-advertised tick (50 ms through one hour).
const TICK_MIN_MS: u64 = 50;
const TICK_MAX_MS: u64 = 3_600_000;
/// Already-bound conflict detail shared by the bind error and the heal-path
/// matcher, so the start path recognizes exactly this conflict and nothing
/// else. The literal is the whole contract: keep it unchanged.
const ALREADY_BOUND_CONFLICT: &str =
    "heartbeat descriptor is already bound to another incarnation";
/// Lock-file name beside the transport descriptor. The descriptor file
/// itself cannot carry the mutex (readers open it lock-free and renames
/// replace it), so one stable sibling file owns the critical section for
/// every publish and bind rotation.
const TRANSPORT_LOCK_FILE_NAME: &str = "watchdog-heartbeat-transport.lock";
/// Bounded exclusive-lock acquisition attempts before failing closed.
/// Eighty attempts at a 25 ms backoff bound contention near two seconds;
/// writers never proceed unlocked.
const TRANSPORT_LOCK_ATTEMPTS: u32 = 80;
/// Backoff between exclusive-lock acquisition attempts.
const TRANSPORT_LOCK_RETRY_WAIT_MS: u64 = 25;
/// Host-issued rendezvous: per-instance pipe name plus 256-bit challenge,
/// bound to the installer-approved contour the Watchdog validates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatTransportDescriptor {
    /// Per-instance Host-owned pipe name.
    pub pipe_name: String,
    /// Per-instance 256-bit challenge the writer echoes per message.
    pub host_challenge_nonce: String,
    /// Pipe instance guid, also the unpredictable pipe name suffix.
    pub service_instance_guid: String,
    /// Installer-approved installation identity both sides hold.
    pub installation_id: String,
    /// Exact Watchdog transaction-plan generation from the approved SCM
    /// registration bootstrap both sides hold.
    pub transaction_plan_generation: u64,
    /// SCM-verified watchdog process incarnation (PID) this rendezvous is
    /// bound to. Zero while unbound: minted but not yet verified Running.
    pub watchdog_incarnation_pid: u32,
    /// SCM-verified watchdog process creation time (100ns ticks) paired
    /// with the PID above. PID equality alone cannot distinguish reuse, so
    /// both halves are always checked together; a half-bound pair is never
    /// valid.
    pub watchdog_incarnation_start_100ns: u64,
}

/// Canonical descriptor bytes. Field order is the wire contract shared with
/// the Watchdog reader: both sides serialize this exact shape and hash it
/// into the descriptor digest.
#[derive(serde::Serialize)]
struct HeartbeatDescriptorCanonical<'a> {
    schema: &'a str,
    pipe_name: &'a str,
    host_challenge_nonce: &'a str,
    service_instance_guid: &'a str,
    installation_id: &'a str,
    transaction_plan_generation: u64,
    watchdog_incarnation_pid: u32,
    watchdog_incarnation_start_100ns: u64,
}

/// Parsed descriptor wire shape.
#[derive(serde::Deserialize)]
struct HeartbeatDescriptorWire {
    schema: String,
    pipe_name: String,
    host_challenge_nonce: String,
    service_instance_guid: String,
    installation_id: String,
    transaction_plan_generation: u64,
    watchdog_incarnation_pid: u32,
    watchdog_incarnation_start_100ns: u64,
    descriptor_digest: String,
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_pipe_name(value: &str) -> bool {
    value.len() <= 256
        && value
            .strip_prefix(WATCHDOG_HEARTBEAT_PIPE_PREFIX)
            .is_some_and(|suffix| is_lower_hex(suffix, GUID_HEX_LEN))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
}

impl HeartbeatTransportDescriptor {
    fn canonical_bytes(&self) -> Result<Vec<u8>, HostError> {
        serde_json::to_vec(&HeartbeatDescriptorCanonical {
            schema: WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
            pipe_name: self.pipe_name.as_str(),
            host_challenge_nonce: self.host_challenge_nonce.as_str(),
            service_instance_guid: self.service_instance_guid.as_str(),
            installation_id: self.installation_id.as_str(),
            transaction_plan_generation: self.transaction_plan_generation,
            watchdog_incarnation_pid: self.watchdog_incarnation_pid,
            watchdog_incarnation_start_100ns: self.watchdog_incarnation_start_100ns,
        })
        .map_err(|error| HostError::Platform(error.to_string()))
    }

    fn validate(&self) -> Result<(), HostError> {
        if !valid_pipe_name(&self.pipe_name) {
            return Err(HostError::Platform(
                "heartbeat descriptor pipe name is not allow-listed".to_owned(),
            ));
        }
        if !is_lower_hex(&self.host_challenge_nonce, NONCE_HEX_LEN) {
            return Err(HostError::Platform(
                "heartbeat descriptor challenge is not 256-bit lowercase hex".to_owned(),
            ));
        }
        if !is_lower_hex(&self.service_instance_guid, GUID_HEX_LEN) {
            return Err(HostError::Platform(
                "heartbeat descriptor instance guid is not 128-bit lowercase hex".to_owned(),
            ));
        }
        if self.installation_id.is_empty()
            || self.installation_id.len() > INSTALLATION_ID_LIMIT
            || self.transaction_plan_generation == 0
        {
            return Err(HostError::Platform(
                "heartbeat descriptor bootstrap binding is not canonical".to_owned(),
            ));
        }
        if !self
            .pipe_name
            .ends_with(self.service_instance_guid.as_str())
        {
            return Err(HostError::Platform(
                "heartbeat descriptor pipe name does not carry its instance guid".to_owned(),
            ));
        }
        if (self.watchdog_incarnation_pid == 0)
            != (self.watchdog_incarnation_start_100ns == 0)
        {
            return Err(HostError::Platform(
                "heartbeat descriptor incarnation is half-bound".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns true once the SCM-verified watchdog incarnation is bound.
    /// Only a bound descriptor can arm admission: an unbound rendezvous
    /// carries no proven peer, so no heartbeat on it can become readiness
    /// evidence.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.watchdog_incarnation_pid != 0 && self.watchdog_incarnation_start_100ns != 0
    }

    /// Mints one per-instance rendezvous: a fresh 256-bit OS-random
    /// challenge plus a fresh instance guid that doubles as the
    /// unpredictable pipe name suffix.
    ///
    /// # Errors
    ///
    /// Returns an error when the OS RNG is unavailable (callers fail
    /// closed: no descriptor, no supervised claim) or the binding is not
    /// canonical.
    pub fn issue(
        installation_id: &str,
        transaction_plan_generation: u64,
    ) -> Result<Self, HostError> {
        let nonce = fresh_service_registration_nonce()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let guid = uuid::Uuid::new_v4().simple().to_string();
        let descriptor = Self {
            pipe_name: format!("{WATCHDOG_HEARTBEAT_PIPE_PREFIX}{guid}"),
            host_challenge_nonce: nonce.as_str().to_owned(),
            service_instance_guid: guid,
            installation_id: installation_id.to_owned(),
            transaction_plan_generation,
            watchdog_incarnation_pid: 0,
            watchdog_incarnation_start_100ns: 0,
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Publishes the descriptor below the Host state root with a pinned
    /// create-new plus readback, enforced file contour, and verified
    /// readback.
    ///
    /// A live bound prior is never removed: when the prior descriptor names
    /// a still-running incarnation, this rendezvous still belongs to that
    /// watchdog, so the prior file is kept as-is and its path returned.
    /// Rotating under a live writer would orphan its bound emissions and
    /// race the running incarnation. Only a stopped (or never-bound) prior
    /// is replaced by the fresh challenge. An unloadable prior file cannot
    /// prove a live owner, so it is replaced (fail-closed direction: the old
    /// writer no longer matches the fresh challenge).
    ///
    /// # Errors
    ///
    /// Returns an error when the prior instance cannot be retired or the
    /// new descriptor cannot be durably published under its file contour.
    pub fn publish(&self, host_state_root: &Path) -> Result<PathBuf, HostError> {
        let path = host_state_root.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME);
        // Serialize with concurrent Host-instance writers: the keep-prior
        // decision plus rotation holds the descriptor lock, so two
        // publishers cannot interleave decide-then-replace.
        let _lock = TransportDescriptorLock::acquire(host_state_root)?;
        // Retain only a fully trusted live binding: try_load proves the
        // bytes, the liveness probe proves the owner still runs, and the
        // contour check inside try_load proves exclusive Host ownership.
        // Anything else falls through to the atomic replace below, so a
        // noncompliant retained descriptor is securely replaced, never
        // silently kept.
        let keep_prior = match try_load_prior_descriptor(&path)? {
            Some(prior) => prior.is_bound() && prior_incarnation_live(&prior),
            None => false,
        };
        if keep_prior {
            return Ok(path);
        }
        self.publish_force_locked(host_state_root)
    }

    /// Unconditionally (re)publishes this descriptor through the atomic
    /// replace protocol: temp staging in the same directory, contour
    /// enforcement on the staging file, atomic rename over the target,
    /// contour verification, then a verified reload proving the file is
    /// the just-published descriptor. There is no remove-then-create
    /// window: readers never observe an absent or half-written rendezvous.
    ///
    /// # Errors
    ///
    /// Returns an error when this descriptor is not canonical or the
    /// atomic publish or its readback proof fails.
    ///
    /// The replace plus verified reload holds the cross-process descriptor
    /// lock; contention fails closed, never unlocked.
    fn publish_force(&self, host_state_root: &Path) -> Result<PathBuf, HostError> {
        let _lock = TransportDescriptorLock::acquire(host_state_root)?;
        self.publish_force_locked(host_state_root)
    }

    /// Locked half of `publish_force`: the caller already holds the
    /// descriptor lock across the replace plus verified reload, so this
    /// never acquires (exclusive byte locks are not reentrant across
    /// handles of one process).
    ///
    /// # Errors
    ///
    /// Returns an error when this descriptor is not canonical or the
    /// atomic publish or its readback proof fails.
    fn publish_force_locked(&self, host_state_root: &Path) -> Result<PathBuf, HostError> {
        self.validate().map_err(|error| match error {
            HostError::Platform(detail) => HostError::RecoveryRequired(detail),
            other => other,
        })?;
        let bytes = self.wire_bytes()?;
        let path = host_state_root.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME);
        atomic_replace_transport_file(&path, &bytes)?;
        let reloaded = Self::load(host_state_root)?.ok_or_else(|| {
            HostError::RecoveryRequired(
                "heartbeat descriptor is absent after atomic publish".to_owned(),
            )
        })?;
        if reloaded.host_challenge_nonce != self.host_challenge_nonce
            || reloaded.service_instance_guid != self.service_instance_guid
            || reloaded.pipe_name != self.pipe_name
        {
            return Err(HostError::RecoveryRequired(
                "heartbeat descriptor readback is not the published descriptor".to_owned(),
            ));
        }
        Ok(path)
    }

    /// Serializes this descriptor to its bounded wire bytes (canonical
    /// digest included). Callers validate first; this only bounds output.
    ///
    /// # Errors
    ///
    /// Returns an error when serialization fails or the bytes exceed the
    /// transport file limit.
    fn wire_bytes(&self) -> Result<Vec<u8>, HostError> {
        let canonical = self.canonical_bytes()?;
        let wire = serde_json::json!({
            "schema": WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
            "pipe_name": self.pipe_name,
            "host_challenge_nonce": self.host_challenge_nonce,
            "service_instance_guid": self.service_instance_guid,
            "installation_id": self.installation_id,
            "transaction_plan_generation": self.transaction_plan_generation,
            "watchdog_incarnation_pid": self.watchdog_incarnation_pid,
            "watchdog_incarnation_start_100ns": self.watchdog_incarnation_start_100ns,
            "descriptor_digest": sha256_hex(&canonical),
        });
        let bytes =
            serde_json::to_vec(&wire).map_err(|error| HostError::Platform(error.to_string()))?;
        if bytes.len() as u64 > TRANSPORT_FILE_LIMIT {
            return Err(HostError::Platform(
                "heartbeat descriptor exceeds its bounded size".to_owned(),
            ));
        }
        Ok(bytes)
    }

    /// Loads the current instance descriptor. Absent means the transport
    /// was never armed for this Host start (Ok(None), unchanged behavior
    /// downstream). A present-but-invalid file fails closed.
    ///
    /// # Errors
    ///
    /// Returns an error for oversize, unparsable, or binding-invalid files.
    pub fn load(host_state_root: &Path) -> Result<Option<Self>, HostError> {
        let path = host_state_root.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(HostError::Platform(error.to_string())),
        };
        if bytes.len() as u64 > TRANSPORT_FILE_LIMIT {
            return Err(HostError::RecoveryRequired(
                "heartbeat descriptor exceeds its bounded size".to_owned(),
            ));
        }
        let wire: HeartbeatDescriptorWire = serde_json::from_slice(&bytes)
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
        if wire.schema != WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA {
            return Err(HostError::RecoveryRequired(
                "heartbeat descriptor schema is unsupported".to_owned(),
            ));
        }
        let descriptor = Self {
            pipe_name: wire.pipe_name,
            host_challenge_nonce: wire.host_challenge_nonce,
            service_instance_guid: wire.service_instance_guid,
            installation_id: wire.installation_id,
            transaction_plan_generation: wire.transaction_plan_generation,
            watchdog_incarnation_pid: wire.watchdog_incarnation_pid,
            watchdog_incarnation_start_100ns: wire.watchdog_incarnation_start_100ns,
        };
        descriptor.validate().map_err(|error| match error {
            HostError::Platform(detail) => HostError::RecoveryRequired(detail),
            other => other,
        })?;
        let canonical = descriptor.canonical_bytes()?;
        if sha256_hex(&canonical) != wire.descriptor_digest {
            return Err(HostError::RecoveryRequired(
                "heartbeat descriptor digest does not match its canonical bytes".to_owned(),
            ));
        }
        verify_transport_file(&path)?;
        Ok(Some(descriptor))
    }

    /// Binds the published descriptor to the SCM-verified watchdog
    /// incarnation observed after start. The challenge, pipe, guid, and
    /// bootstrap binding are never rewritten here, only the incarnation
    /// pair; the digest is recomputed over the new canonical bytes and the
    /// file contour is re-enforced through the atomic replace protocol
    /// (temp staging plus rename, no remove-then-create window), and a
    /// verified reload proves the rebound file is the verified one. An
    /// already-identical binding is a no-op (no rewrite, no race window).
    /// A binding to any other incarnation fails closed: the rendezvous
    /// belongs to exactly one verified process, and rebinding under a
    /// live writer would split the sequence chain across incarnations.
    ///
    /// # Errors
    ///
    /// Returns an error for an unusable incarnation, an absent descriptor,
    /// a conflicting bound incarnation, or a failed rewrite.
    pub fn bind_incarnation(
        host_state_root: &Path,
        watchdog_pid: u32,
        watchdog_start_100ns: u64,
    ) -> Result<PathBuf, HostError> {
        // Serialize with concurrent Host-instance writers: the full
        // load-derive-replace-reload holds the descriptor lock, so two
        // binders cannot both observe unbound and last-writer-wins.
        let _lock = TransportDescriptorLock::acquire(host_state_root)?;
        Self::bind_incarnation_locked(host_state_root, watchdog_pid, watchdog_start_100ns)
    }

    /// Locked half of `bind_incarnation`: the caller already holds the
    /// descriptor lock across load-verify-replace-reload, so this never
    /// acquires (exclusive byte locks are not reentrant across handles
    /// of one process).
    ///
    /// # Errors
    ///
    /// Returns an error for an unusable incarnation, an absent descriptor,
    /// a conflicting bound incarnation, or a failed rewrite.
    fn bind_incarnation_locked(
        host_state_root: &Path,
        watchdog_pid: u32,
        watchdog_start_100ns: u64,
    ) -> Result<PathBuf, HostError> {
        if watchdog_pid == 0 || watchdog_start_100ns == 0 {
            return Err(HostError::Platform(
                "heartbeat incarnation binding is not usable".to_owned(),
            ));
        }
        let path = host_state_root.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME);
        let Some(current) = Self::load(host_state_root)? else {
            return Err(HostError::RecoveryRequired(
                "heartbeat descriptor is absent for incarnation binding".to_owned(),
            ));
        };
        if current.watchdog_incarnation_pid == watchdog_pid
            && current.watchdog_incarnation_start_100ns == watchdog_start_100ns
        {
            return Ok(path);
        }
        if current.is_bound() {
            return Err(HostError::RecoveryRequired(
                ALREADY_BOUND_CONFLICT.to_owned(),
            ));
        }
        let rebound = Self {
            watchdog_incarnation_pid: watchdog_pid,
            watchdog_incarnation_start_100ns: watchdog_start_100ns,
            ..current
        };
        rebound.validate().map_err(|error| match error {
            HostError::Platform(detail) => HostError::RecoveryRequired(detail),
            other => other,
        })?;
        let bytes = rebound.wire_bytes()?;
        atomic_replace_transport_file(&path, &bytes)?;
        // Version/CAS proof: the rebound file must reload as exactly the
        // verified descriptor. Any concurrent rotation or half-write that
        // changed the file fails closed instead of binding the wrong peer.
        let verified = Self::load(host_state_root)?.ok_or_else(|| {
            HostError::RecoveryRequired(
                "heartbeat descriptor is absent after incarnation binding".to_owned(),
            )
        })?;
        if verified != rebound {
            return Err(HostError::RecoveryRequired(
                "heartbeat incarnation binding readback changed".to_owned(),
            ));
        }
        Ok(path)
    }

    /// Binds the SCM-verified incarnation for the start path, healing the
    /// keep-prior rendezvous when the start replaced the watchdog: a plain
    /// bind dead-ends on already-bound after publish retained a live
    /// descriptor and this start brought a new SCM process. When the
    /// conflicting incarnation provably stopped since, this rotates to the
    /// caller-issued fresh challenge and binds the new process (retry
    /// heals); a still-live owner keeps the rendezvous and the conflict
    /// stands. Callers pass the descriptor they issued for this start.
    ///
    /// # Errors
    ///
    /// Returns an error for an unusable incarnation, an absent descriptor,
    /// a still-live conflicting binding, or a failed heal rotation.
    pub fn bind_incarnation_or_heal(
        fresh: &Self,
        host_state_root: &Path,
        watchdog_pid: u32,
        watchdog_start_100ns: u64,
    ) -> Result<PathBuf, HostError> {
        // One lock across the whole heal rotation (bind, liveness recheck,
        // fresh publish, rebind): the steps are a single critical section,
        // never separately raced windows.
        let _lock = TransportDescriptorLock::acquire(host_state_root)?;
        match Self::bind_incarnation_locked(host_state_root, watchdog_pid, watchdog_start_100ns) {
            Ok(path) => Ok(path),
            Err(error) if is_already_bound_conflict(&error) => {
                let path = host_state_root.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME);
                let Some(current) = Self::load(host_state_root)? else {
                    return Err(error);
                };
                if current.watchdog_incarnation_pid == watchdog_pid
                    && current.watchdog_incarnation_start_100ns == watchdog_start_100ns
                {
                    return Ok(path);
                }
                if !current.is_bound() {
                    return Self::bind_incarnation_locked(
                        host_state_root,
                        watchdog_pid,
                        watchdog_start_100ns,
                    );
                }
                if prior_incarnation_live(&current) {
                    return Err(error);
                }
                fresh.publish_force_locked(host_state_root)?;
                Self::bind_incarnation_locked(host_state_root, watchdog_pid, watchdog_start_100ns)
            }
            Err(error) => Err(error),
        }
    }
}
/// Cross-process exclusive guard for descriptor publish and bind rotation.
///
/// Atomic rename alone does not serialize concurrent Host-instance writers:
/// two processes can both load an unbound descriptor, derive a replacement,
/// and rename over each other, so the last writer silently clobbers the
/// first (the verified-reload check detects the damage only after it is
/// durable). Every rotation therefore holds this `LockFileEx` guard across
/// its full load-verify-replace-reload sequence; contention fails closed
/// after a bounded retry, never unlocked.
struct TransportDescriptorLock {
    file: std::fs::File,
}

impl TransportDescriptorLock {
    /// Acquires the exclusive descriptor lock for the state root, retrying
    /// contention for a bounded window before failing closed.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock file cannot be opened or the
    /// exclusive lock cannot be acquired in the bounded window. Rotation
    /// never proceeds unlocked.
    fn acquire(host_state_root: &Path) -> Result<Self, HostError> {
        // The crate forbids unsafe, so the OS primitive is reached through
        // the safe std wrapper: File::try_lock issues an exclusive
        // non-blocking LockFileEx on this handle. No rotation proceeds
        // without holding it.
        let lock_path = host_state_root.join(TRANSPORT_LOCK_FILE_NAME);
        let mut last_error = String::from("lock was never attempted");
        for attempt in 0..TRANSPORT_LOCK_ATTEMPTS {
            match Self::try_acquire_once(&lock_path) {
                Ok(guard) => return Ok(guard),
                Err(error) => {
                    last_error = error;
                    if attempt + 1 >= TRANSPORT_LOCK_ATTEMPTS {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(TRANSPORT_LOCK_RETRY_WAIT_MS));
                }
            }
        }
        Err(HostError::RecoveryRequired(format!(
            "heartbeat transport lock contention: {last_error}"
        )))
    }

    /// Opens the sibling lock file and takes the exclusive OS lock once,
    /// returning the held guard. Any failure (open contention or lock
    /// contention) reports a detail string for the bounded retry loop.
    fn try_acquire_once(lock_path: &Path) -> Result<Self, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)
            .map_err(|error| format!("lock open failed: {error}"))?;
        file.try_lock()
            .map_err(|error| format!("exclusive lock failed: {error}"))?;
        Ok(Self { file })
    }
}

impl Drop for TransportDescriptorLock {
    fn drop(&mut self) {
        // Best effort: the OS releases the exclusive lock on handle close
        // regardless, so an unlock failure cannot leave the mutex held.
        let _ = self.file.unlock();
    }
}

/// Atomically stages descriptor bytes beside the target and renames over
/// it, so the rendezvous is never absent or half-written. The staging
/// file is contour-enforced before the rename (the DACL travels with the
/// file object), the target contour is verified after, and callers prove
/// the result with a verified reload. A stale staging file from a crashed
/// attempt is removed first and on failure, never reused.
///
/// # Errors
///
/// Returns an error when staging, enforcement, the atomic rename, or the
/// target contour verification fails.
fn atomic_replace_transport_file(path: &Path, bytes: &[u8]) -> Result<(), HostError> {
    if bytes.len() as u64 > TRANSPORT_FILE_LIMIT {
        return Err(HostError::Platform(
            "heartbeat descriptor exceeds its bounded size".to_owned(),
        ));
    }
    let file_name = path.file_name().ok_or_else(|| {
        HostError::Platform("heartbeat descriptor path has no file name".to_owned())
    })?;
    let mut staging_name = file_name.to_owned();
    staging_name.push(format!(".tmp-{}", std::process::id()));
    let staging = path.with_file_name(staging_name);
    match std::fs::remove_file(&staging) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(HostError::Platform(error.to_string())),
    }
    let staged = (|| -> Result<(), HostError> {
        write_watchdog_publication_child(&staging, bytes)?;
        eliot_windows_ipc::restrict_file_to_current_user_and_system(&staging).map_err(|error| {
            HostError::RecoveryRequired(format!(
                "heartbeat transport staging DACL enforcement failed: {error}"
            ))
        })?;
        eliot_windows_ipc::atomic_replace_file(&staging, path).map_err(|error| {
            HostError::Platform(format!(
                "heartbeat descriptor atomic replace failed: {error}"
            ))
        })?;
        verify_transport_file(path)
    })();
    if staged.is_err() {
        let _ = std::fs::remove_file(&staging);
    }
    staged
}

/// Returns true only for the exact already-bound conflict, so the heal
/// path retries rotation solely on that conflict and never on unrelated
/// bind failures.
fn is_already_bound_conflict(error: &HostError) -> bool {
    matches!(error, HostError::RecoveryRequired(detail) if detail == ALREADY_BOUND_CONFLICT)
}

/// Probes the prior descriptor without trusting it: absent, oversize,
/// unparsable, digest-invalid, or contour-noncompliant files report None
/// so the publisher mints a fresh challenge. Only a fully valid bound
/// prior carrying the enforced file contour can prove a live owner (see
/// `prior_incarnation_live`); an unloadable or noncompliant prior cannot,
/// so rotation proceeds in the fail-closed direction (the old writer no
/// longer matches the fresh challenge). Pre-fix files predate the
/// contour, and this None is exactly their upgrade path: rotation, never
/// silent retention.
fn try_load_prior_descriptor(path: &Path) -> Result<Option<HeartbeatTransportDescriptor>, HostError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(HostError::Platform(error.to_string())),
    };
    if bytes.len() as u64 > TRANSPORT_FILE_LIMIT {
        return Ok(None);
    }
    let wire: HeartbeatDescriptorWire = match serde_json::from_slice(&bytes) {
        Ok(wire) => wire,
        Err(_) => return Ok(None),
    };
    if wire.schema != WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA {
        return Ok(None);
    }
    let descriptor = HeartbeatTransportDescriptor {
        pipe_name: wire.pipe_name,
        host_challenge_nonce: wire.host_challenge_nonce,
        service_instance_guid: wire.service_instance_guid,
        installation_id: wire.installation_id,
        transaction_plan_generation: wire.transaction_plan_generation,
        watchdog_incarnation_pid: wire.watchdog_incarnation_pid,
        watchdog_incarnation_start_100ns: wire.watchdog_incarnation_start_100ns,
    };
    if descriptor.validate().is_err() {
        return Ok(None);
    }
    let Ok(canonical) = descriptor.canonical_bytes() else {
        return Ok(None);
    };
    if sha256_hex(&canonical) != wire.descriptor_digest {
        return Ok(None);
    }
    // Retain-path contour enforcement: a descriptor that is valid but
    // carries a noncompliant owner or DACL cannot prove exclusive Host
    // ownership, so it never counts as a keepable prior. Returning None
    // rotates it through the atomic publish path (which enforces the
    // contour) instead of silently keeping it.
    if eliot_windows_ipc::verify_file_owner_and_dacl(path).is_err() {
        return Ok(None);
    }
    Ok(Some(descriptor))
}

/// Returns true only when the prior bound incarnation provably still owns
/// the rendezvous: the PID is alive AND its creation time still matches the
/// bound start (PID reuse without the same start is a different process).
/// Any query uncertainty keeps the prior (no rotation under doubt).
fn prior_incarnation_live(prior: &HeartbeatTransportDescriptor) -> bool {
    let pid = prior.watchdog_incarnation_pid;
    let Ok(alive) = eliot_windows_ipc::process_is_alive(pid) else {
        return true;
    };
    if !alive {
        return false;
    }
    match eliot_windows_ipc::process_creation_ticks(pid) {
        Ok(start) => start == prior.watchdog_incarnation_start_100ns,
        Err(_) => true,
    }
}

/// Enforces the transport file contour (token user plus System, protected)
/// and verifies it back. Every descriptor and observation write passes
/// here: a digest alone is never integrity.
fn restrict_and_verify_transport_file(path: &Path) -> Result<(), HostError> {
    eliot_windows_ipc::restrict_file_to_current_user_and_system(path).map_err(|error| {
        HostError::RecoveryRequired(format!("heartbeat transport file DACL enforcement failed: {error}"))
    })?;
    verify_transport_file(path)
}

/// Verifies the transport file contour (owner plus DACL) on read paths.
/// Write paths enforce first; this is the read-side half.
fn verify_transport_file(path: &Path) -> Result<(), HostError> {
    eliot_windows_ipc::verify_file_owner_and_dacl(path).map_err(|error| {
        HostError::RecoveryRequired(format!("heartbeat transport file contour is not intact: {error}"))
    })
}

/// Per-process Host boot identity. Continuity across windows is a live-sensor
/// claim, so it is only meaningful inside one Host process: a persisted
/// observation carrying another boot id can never extend to CONTINUOUS.
static HOST_BOOT_ID: OnceLock<u64> = OnceLock::new();
/// Per-process monotonic origin for Host-measured cadence. Wall time is
/// audit context only; continuity cadence is always measured on this clock.
static HOST_BOOT_INSTANT: OnceLock<Instant> = OnceLock::new();

/// Returns the calling Host process boot identity, minting it once from the
/// OS RNG. A restart always mints a fresh id, which is exactly the property
/// the continuity chain relies on.
///
/// # Errors
///
/// Returns an error when the OS RNG is unavailable.
pub(crate) fn host_boot_id() -> Result<u64, HostError> {
    if let Some(id) = HOST_BOOT_ID.get() {
        return Ok(*id);
    }
    let nonce = fresh_service_registration_nonce()
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let head = nonce
        .as_str()
        .get(..16)
        .ok_or_else(|| HostError::Platform("boot nonce is malformed".to_owned()))?;
    let id = u64::from_str_radix(head, 16)
        .map_err(|_| HostError::Platform("boot nonce is malformed".to_owned()))?;
    Ok(*HOST_BOOT_ID.get_or_init(|| id))
}

/// Milliseconds on the Host monotonic clock since process boot. Used for
/// every continuity cadence measurement, never wall time.
fn host_monotonic_ms() -> u64 {
    HOST_BOOT_INSTANT
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Host-side observation coverage for one heartbeat read (I8.2).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostHeartbeatCoverage {
    /// The sensor observed the interval live: contiguous sequence and a
    /// current cadence plus live process checks.
    Continuous,
    /// Some sequence ranges or cadence evidence are missing; the read is
    /// still a fresh admitted heartbeat but proves no continuity.
    Partial,
    /// No competent source covered the interval. A blind read is never
    /// admitted; this variant is produced by absence, never by a message.
    Blind,
}

impl HostHeartbeatCoverage {
    /// Returns the canonical coverage literal persisted per observation.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Continuous => "CONTINUOUS",
            Self::Partial => "PARTIAL",
            Self::Blind => "BLIND",
        }
    }
}

/// Raw pipe message shape. Unknown fields are ignored so a
/// forward-compatible writer cannot break this reader; every load-bearing
/// field below is still required and exact.
#[derive(serde::Deserialize)]
struct WatchdogHeartbeatWire {
    service: String,
    protocol: String,
    authority_state: String,
    coverage_claimed: bool,
    kernel_epoch: u64,
    watchdog_epoch: u64,
    tick_interval_ms: u64,
    service_instance_guid: String,
    host_challenge_nonce: String,
    watchdog_readiness_sequence: u64,
    watchdog_incarnation_pid: u32,
    watchdog_incarnation_start_100ns: u64,
}

/// Canonical derived-observation bytes hashed into the observation digest.
/// Field order is fixed so the digest is stable for identical observations.
#[derive(serde::Serialize)]
struct HeartbeatObservationCanonical<'a> {
    schema: &'a str,
    pipe_name: &'a str,
    service_instance_guid: &'a str,
    kernel_epoch: u64,
    watchdog_epoch: u64,
    tick_interval_ms: u64,
    watchdog_readiness_sequence: u64,
    watchdog_incarnation_pid: u32,
    watchdog_incarnation_start_100ns: u64,
    handshake_count: u64,
    host_boot_id: u64,
    host_receive_monotonic_ms: u64,
    host_receive_wall_ms: u64,
    coverage: &'a str,
}

/// The derived Host observation the admission path consumes. Raw pipe bytes
/// never cross into admission: construction below enforces the writer field
/// contract (`AdmittedHeartbeat`, coverage claimed, nonzero epochs, exact
/// nonce/guid/pipe binding, sane tick, admissible sequence) and stamps the
/// Host receive times.
#[derive(Clone, Debug)]
pub struct HostObservedWatchdogHeartbeat {
    /// Exact admitted kernel epoch echoed by the writer.
    pub kernel_epoch: u64,
    /// Exact admitted watchdog epoch echoed by the writer.
    pub watchdog_epoch: u64,
    /// Writer-advertised tick bound the freshness deadline derives from.
    pub tick_interval_ms: u64,
    /// Echoed pipe instance guid, already matched to the descriptor.
    pub service_instance_guid: String,
    /// Pipe the message arrived on, already matched to the descriptor.
    pub pipe_name: String,
    /// Admitted-stream sequence of this message (never zero).
    pub watchdog_readiness_sequence: u64,
    /// Bound watchdog incarnation PID echoed by the writer, already matched
    /// to the descriptor at derive time and to SCM at admission time.
    pub watchdog_incarnation_pid: u32,
    /// Bound watchdog incarnation start paired with the PID above.
    pub watchdog_incarnation_start_100ns: u64,
    /// 1-based count of Host-observed pipe handshakes delivering up to and
    /// including this message in the current window. Zero is impossible: a
    /// record with no Host handshake is writer self-report, never evidence.
    pub handshake_count: u64,
    /// Host boot identity owning the monotonic measurement below. A restart
    /// mints a fresh id, so continuity can never cross a Host restart.
    pub host_boot_id: u64,
    /// Host monotonic receive time (ms since boot) used for the continuity
    /// cadence measurement. Wall time stays audit context only.
    pub host_receive_monotonic_ms: u64,
    /// Monotonic receive time for freshness (in-process only).
    pub host_receive_monotonic: Instant,
    /// Wall receive time persisted for audit and restart-safe cadence.
    pub host_receive_wall_ms: u64,
    /// Receive wall time plus the freshness window.
    pub freshness_deadline_wall_ms: u64,
    /// Freshness window: a small multiple of the admitted tick.
    pub freshness_window: Duration,
    /// Coverage of this read against the persisted observation chain.
    pub coverage: HostHeartbeatCoverage,
    /// Digest over the canonical derived bytes, stored as evidence.
    pub observation_digest: String,
}

/// Persisted Host observation record: the audit twin of the derived
/// observation above, minus the in-process monotonic clock. Never
/// authority: admission always reads the pipe live.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct PersistedHeartbeatObservation {
    pub(crate) schema: String,
    pub(crate) pipe_name: String,
    pub(crate) service_instance_guid: String,
    pub(crate) kernel_epoch: u64,
    pub(crate) watchdog_epoch: u64,
    pub(crate) tick_interval_ms: u64,
    pub(crate) watchdog_readiness_sequence: u64,
    pub(crate) watchdog_incarnation_pid: u32,
    pub(crate) watchdog_incarnation_start_100ns: u64,
    pub(crate) handshake_count: u64,
    pub(crate) host_boot_id: u64,
    pub(crate) host_receive_monotonic_ms: u64,
    pub(crate) host_receive_wall_ms: u64,
    pub(crate) freshness_deadline_wall_ms: u64,
    pub(crate) coverage: String,
    pub(crate) observation_digest: String,
}

fn wall_now_ms() -> Result<u64, HostError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|error| HostError::Platform(error.to_string()))?
        .as_millis()
        .try_into()
        .map_err(|_| HostError::Platform("system time exceeds u64".to_owned()))
}

/// Parses and validates one raw pipe message against the bound rendezvous.
/// Every writer-controlled field is checked here; the Host-measured
/// coverage chain is derived separately from the returned value.
///
/// # Errors
///
/// Returns `RecoveryRequired` for any contract violation: a failed message
/// must never become a supervised claim.
fn parse_heartbeat_wire(
    raw: &[u8],
    descriptor: &HeartbeatTransportDescriptor,
    handshake_index: u64,
) -> Result<WatchdogHeartbeatWire, HostError> {
    if raw.len() > MESSAGE_LIMIT {
        return Err(HostError::RecoveryRequired(
            "heartbeat message exceeds its bounded size".to_owned(),
        ));
    }
    if handshake_index == 0 {
        return Err(HostError::RecoveryRequired(
            "heartbeat arrived with no Host-observed handshake".to_owned(),
        ));
    }
    let wire: WatchdogHeartbeatWire = serde_json::from_slice(raw)
        .map_err(|error| HostError::RecoveryRequired(error.to_string()))?;
    if wire.service != WATCHDOG_HEARTBEAT_SERVICE || wire.protocol != WATCHDOG_HEARTBEAT_PROTOCOL {
        return Err(HostError::RecoveryRequired(
            "heartbeat message is not a Watchdog readiness projection".to_owned(),
        ));
    }
    if wire.authority_state != "ADMITTED_HEARTBEAT" || !wire.coverage_claimed {
        return Err(HostError::RecoveryRequired(
            "heartbeat message claims no admitted heartbeat authority".to_owned(),
        ));
    }
    if wire.kernel_epoch == 0 || wire.watchdog_epoch == 0 {
        return Err(HostError::RecoveryRequired(
            "heartbeat message carries a zero epoch".to_owned(),
        ));
    }
    if wire.tick_interval_ms < TICK_MIN_MS || wire.tick_interval_ms > TICK_MAX_MS {
        return Err(HostError::RecoveryRequired(
            "heartbeat tick is outside its sanity bounds".to_owned(),
        ));
    }
    if wire.host_challenge_nonce != descriptor.host_challenge_nonce
        || wire.service_instance_guid != descriptor.service_instance_guid
    {
        return Err(HostError::RecoveryRequired(
            "heartbeat identity does not match this pipe instance".to_owned(),
        ));
    }
    if wire.watchdog_readiness_sequence == 0 {
        return Err(HostError::RecoveryRequired(
            "fence announce is never an admitted heartbeat".to_owned(),
        ));
    }
    if !descriptor.is_bound() {
        return Err(HostError::RecoveryRequired(
            "heartbeat descriptor carries no verified incarnation".to_owned(),
        ));
    }
    if wire.watchdog_incarnation_pid != descriptor.watchdog_incarnation_pid
        || wire.watchdog_incarnation_start_100ns != descriptor.watchdog_incarnation_start_100ns
    {
        return Err(HostError::RecoveryRequired(
            "heartbeat incarnation is not the bound watchdog incarnation".to_owned(),
        ));
    }
    Ok(wire)
}

/// Derives one Host observation from raw pipe bytes delivered by a
/// Host-observed handshake: validates the writer fields, then chains the
/// Host-measured coverage against the prior observation.
///
/// # Errors
///
/// Returns `RecoveryRequired` for any validation failure: an untrusted
/// heartbeat must never become a supervised claim.
pub(crate) fn derive_heartbeat_observation(
    raw: &[u8],
    descriptor: &HeartbeatTransportDescriptor,
    prior: Option<&PersistedHeartbeatObservation>,
    receive_monotonic: Instant,
    receive_wall_ms: u64,
    handshake_index: u64,
) -> Result<HostObservedWatchdogHeartbeat, HostError> {
    let wire = parse_heartbeat_wire(raw, descriptor, handshake_index)?;
    let freshness_window = Duration::from_millis(
        wire.tick_interval_ms
            .checked_mul(FRESHNESS_TICK_MULTIPLE)
            .ok_or_else(|| HostError::RecoveryRequired("heartbeat freshness window overflows".to_owned()))?,
    );
    let freshness_deadline_wall_ms = receive_wall_ms
        .checked_add(freshness_window.as_millis().try_into().map_err(|_| {
            HostError::RecoveryRequired("heartbeat freshness window overflows".to_owned())
        })?)
        .ok_or_else(|| HostError::RecoveryRequired("heartbeat freshness deadline overflows".to_owned()))?;
    // CONTINUOUS is a Host-sensor claim, never a writer claim: every binding
    // below must hold, otherwise the read is a fresh heartbeat with PARTIAL
    // coverage (still admittable, proving no continuity).
    let boot_id = host_boot_id()?;
    let monotonic_ms = host_monotonic_ms();
    let coverage = match prior {
        Some(previous)
            if continuous_chain_intact(
                &wire,
                descriptor,
                previous,
                boot_id,
                monotonic_ms,
                &freshness_window,
                handshake_index,
            ) =>
        {
            HostHeartbeatCoverage::Continuous
        }
        _ => HostHeartbeatCoverage::Partial,
    };
    let coverage_str = coverage.as_str().to_owned();
    let canonical = HeartbeatObservationCanonical {
        schema: HOST_HEARTBEAT_OBSERVATION_SCHEMA,
        pipe_name: descriptor.pipe_name.as_str(),
        service_instance_guid: wire.service_instance_guid.as_str(),
        kernel_epoch: wire.kernel_epoch,
        watchdog_epoch: wire.watchdog_epoch,
        tick_interval_ms: wire.tick_interval_ms,
        watchdog_readiness_sequence: wire.watchdog_readiness_sequence,
        watchdog_incarnation_pid: wire.watchdog_incarnation_pid,
        watchdog_incarnation_start_100ns: wire.watchdog_incarnation_start_100ns,
        handshake_count: handshake_index,
        host_boot_id: boot_id,
        host_receive_monotonic_ms: monotonic_ms,
        host_receive_wall_ms: receive_wall_ms,
        coverage: coverage_str.as_str(),
    };
    let observation_digest = sha256_json(&canonical)?;
    Ok(HostObservedWatchdogHeartbeat {
        kernel_epoch: wire.kernel_epoch,
        watchdog_epoch: wire.watchdog_epoch,
        tick_interval_ms: wire.tick_interval_ms,
        service_instance_guid: wire.service_instance_guid,
        pipe_name: descriptor.pipe_name.clone(),
        watchdog_readiness_sequence: wire.watchdog_readiness_sequence,
        watchdog_incarnation_pid: wire.watchdog_incarnation_pid,
        watchdog_incarnation_start_100ns: wire.watchdog_incarnation_start_100ns,
        handshake_count: handshake_index,
        host_boot_id: boot_id,
        host_receive_monotonic_ms: monotonic_ms,
        host_receive_monotonic: receive_monotonic,
        host_receive_wall_ms: receive_wall_ms,
        freshness_deadline_wall_ms,
        freshness_window,
        coverage,
        observation_digest,
    })
}

/// Checks the full CONTINUOUS chain: the prior observation was produced by
/// this same Host process (boot id), was itself Host-handshake-observed
/// (never a bare file), advances the handshake count by exactly one into
/// the current windowed accepts, is bound to the same descriptor, epochs,
/// incarnation, and tick, carries the immediately preceding sequence, and
/// the inter-arrival gap measured on the Host monotonic clock fits the
/// responsiveness window. A restarted or substituted writer (new
/// incarnation), a renewed lease (new epochs), a moved tick, a Host
/// restart, a replayed or skipped handshake position, or a slow gap all
/// degrade to PARTIAL instead.
fn continuous_chain_intact(
    wire: &WatchdogHeartbeatWire,
    descriptor: &HeartbeatTransportDescriptor,
    previous: &PersistedHeartbeatObservation,
    boot_id: u64,
    monotonic_ms: u64,
    freshness_window: &Duration,
    handshake_index: u64,
) -> bool {
    if previous.host_boot_id != boot_id {
        return false;
    }
    // Advancement bound to the current accepts: the prior chain position
    // must immediately precede this windowed handshake. Mere nonzero
    // never suffices: a replayed position or a skipped accept proves no
    // live-observed interval.
    if previous.handshake_count.checked_add(1) != Some(handshake_index) {
        return false;
    }
    if previous.pipe_name != descriptor.pipe_name
        || previous.service_instance_guid != wire.service_instance_guid
    {
        return false;
    }
    if previous.kernel_epoch != wire.kernel_epoch
        || previous.watchdog_epoch != wire.watchdog_epoch
    {
        return false;
    }
    if previous.tick_interval_ms != wire.tick_interval_ms {
        return false;
    }
    if previous.watchdog_incarnation_pid != wire.watchdog_incarnation_pid
        || previous.watchdog_incarnation_start_100ns != wire.watchdog_incarnation_start_100ns
    {
        return false;
    }
    if previous.watchdog_readiness_sequence.checked_add(1) != Some(wire.watchdog_readiness_sequence)
    {
        return false;
    }
    if monotonic_ms < previous.host_receive_monotonic_ms {
        return false;
    }
    let window_ms: u64 = freshness_window
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    monotonic_ms - previous.host_receive_monotonic_ms <= window_ms
}
impl HostObservedWatchdogHeartbeat {
    /// Projects the audit twin persisted per admission.
    fn persisted_view(&self) -> PersistedHeartbeatObservation {
        PersistedHeartbeatObservation {
            schema: HOST_HEARTBEAT_OBSERVATION_SCHEMA.to_owned(),
            pipe_name: self.pipe_name.clone(),
            service_instance_guid: self.service_instance_guid.clone(),
            kernel_epoch: self.kernel_epoch,
            watchdog_epoch: self.watchdog_epoch,
            tick_interval_ms: self.tick_interval_ms,
            watchdog_readiness_sequence: self.watchdog_readiness_sequence,
            watchdog_incarnation_pid: self.watchdog_incarnation_pid,
            watchdog_incarnation_start_100ns: self.watchdog_incarnation_start_100ns,
            handshake_count: self.handshake_count,
            host_boot_id: self.host_boot_id,
            host_receive_monotonic_ms: self.host_receive_monotonic_ms,
            host_receive_wall_ms: self.host_receive_wall_ms,
            freshness_deadline_wall_ms: self.freshness_deadline_wall_ms,
            coverage: self.coverage.as_str().to_owned(),
            observation_digest: self.observation_digest.clone(),
        }
    }
}

/// Persists the Host observation record separately from the journal: the
/// audit twin of the derived observation (payload digest, nonce-bound
/// pipe identity, sequence, receive times, coverage). Never authority.
///
/// # Errors
///
/// Returns an error when the prior instance cannot be retired or the new
/// record cannot be durably published.
pub fn persist_heartbeat_observation(
    host_state_root: &Path,
    observed: &HostObservedWatchdogHeartbeat,
) -> Result<PathBuf, HostError> {
    let path = host_state_root.join(HOST_HEARTBEAT_OBSERVATION_FILE_NAME);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(HostError::Platform(error.to_string())),
    }
    let bytes = serde_json::to_vec(&observed.persisted_view())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if bytes.len() as u64 > TRANSPORT_FILE_LIMIT {
        return Err(HostError::Platform(
            "heartbeat observation exceeds its bounded size".to_owned(),
        ));
    }
    write_watchdog_publication_child(&path, &bytes)?;
    restrict_and_verify_transport_file(&path)?;
    Ok(path)
}

/// Loads the prior persisted observation for coverage chaining. Absent or
/// corrupt files degrade to None (the next derive reports PARTIAL): a lost
/// audit twin must never block a fresh observation, and must never
/// manufacture continuity. A contour-violating file (owner/DACL) degrades
/// the same way: it cannot extend continuity, but it cannot block a fresh
/// live observation either.
pub(crate) fn load_prior_heartbeat_observation(
    host_state_root: &Path,
) -> Option<PersistedHeartbeatObservation> {
    let path = host_state_root.join(HOST_HEARTBEAT_OBSERVATION_FILE_NAME);
    let bytes = std::fs::read(&path).ok()?;
    if bytes.len() as u64 > TRANSPORT_FILE_LIMIT {
        return None;
    }
    let persisted: PersistedHeartbeatObservation = serde_json::from_slice(&bytes).ok()?;
    if persisted.schema != HOST_HEARTBEAT_OBSERVATION_SCHEMA {
        return None;
    }
    let canonical = HeartbeatObservationCanonical {
        schema: persisted.schema.as_str(),
        pipe_name: persisted.pipe_name.as_str(),
        service_instance_guid: persisted.service_instance_guid.as_str(),
        kernel_epoch: persisted.kernel_epoch,
        watchdog_epoch: persisted.watchdog_epoch,
        tick_interval_ms: persisted.tick_interval_ms,
        watchdog_readiness_sequence: persisted.watchdog_readiness_sequence,
        watchdog_incarnation_pid: persisted.watchdog_incarnation_pid,
        watchdog_incarnation_start_100ns: persisted.watchdog_incarnation_start_100ns,
        handshake_count: persisted.handshake_count,
        host_boot_id: persisted.host_boot_id,
        host_receive_monotonic_ms: persisted.host_receive_monotonic_ms,
        host_receive_wall_ms: persisted.host_receive_wall_ms,
        coverage: persisted.coverage.as_str(),
    };
    if sha256_json(&canonical).ok()? != persisted.observation_digest {
        return None;
    }
    if verify_transport_file(&path).is_err() {
        return None;
    }
    Some(persisted)
}

/// Handle-bound pipe peer: PID plus executable image resolved from the
/// live server handle at accept time (I1.6 independent observation).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatPipePeer {
    /// Connected client PID observed on the server handle.
    pub process_id: u32,
    /// Executable image queried from that PID at accept time.
    pub image_path: PathBuf,
}

/// One accepted heartbeat: raw bytes plus peer binding plus stamps.
struct AcceptedHeartbeat {
    raw: Vec<u8>,
    peer: HeartbeatPipePeer,
    receive_monotonic: Instant,
    receive_wall_ms: u64,
}

/// ACL-restricted Host listener for one pipe instance. The DACL grants
/// only the current process token user plus `LocalSystem` (shared,
/// NUL-guarded server factory); every accepted peer is still bound by
/// image, PID, nonce, and sequence before admission.
pub struct HeartbeatListener {
    server: tokio::net::windows::named_pipe::NamedPipeServer,
    pipe_name: String,
    allowed_sid: String,
    expected_incarnation_pid: u32,
    expected_incarnation_start_100ns: u64,
}

impl HeartbeatListener {
    /// Binds the first pipe instance for this Host start against the bound
    /// watchdog incarnation. An unbound rendezvous never reaches a
    /// listener: with no proven peer, every connect would be unadmittable.
    ///
    /// # Errors
    ///
    /// Returns an error when the incarnation is unbound, the token SID is
    /// unavailable, or the pipe cannot be created (a squatted name fails
    /// here via first-instance ownership).
    pub fn bind(
        pipe_name: &str,
        incarnation_pid: u32,
        incarnation_start_100ns: u64,
    ) -> Result<Self, HostError> {
        if incarnation_pid == 0 || incarnation_start_100ns == 0 {
            return Err(HostError::Platform(
                "heartbeat listener requires a bound incarnation".to_owned(),
            ));
        }
        let allowed_sid = eliot_windows_ipc::current_process_token_sid()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let server =
            eliot_windows_ipc::create_current_user_server(pipe_name, &allowed_sid, true)
                .map_err(|error| HostError::Platform(error.to_string()))?;
        Ok(Self {
            server,
            pipe_name: pipe_name.to_owned(),
            allowed_sid,
            expected_incarnation_pid: incarnation_pid,
            expected_incarnation_start_100ns: incarnation_start_100ns,
        })
    }

    /// Accepts one heartbeat before the deadline: connect, bind the pipe
    /// peer from the live handle, rotate the next instance first (so a
    /// racing writer still finds a listener), then read one bounded line.
    ///
    /// # Errors
    ///
    /// Returns an error on expiry, an unbindable peer, or a malformed
    /// line. Callers fail the armed admission closed on any error.
    async fn accept_one(&mut self, deadline: Instant) -> Result<AcceptedHeartbeat, HostError> {
        use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, BufReader};
        let budget = deadline.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            return Err(HostError::RecoveryRequired(
                "heartbeat listen window expired".to_owned(),
            ));
        }
        tokio::time::timeout(budget, self.server.connect())
            .await
            .map_err(|_| {
                HostError::RecoveryRequired("heartbeat listen window expired".to_owned())
            })?
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let peer = eliot_windows_ipc::named_pipe_client_process(&self.server).map_err(|error| {
            HostError::RecoveryRequired(format!("heartbeat peer is not bound: {error}"))
        })?;
        // Incarnation check at connect: the kernel-bound peer must be the
        // exact SCM-verified process the descriptor names. PID equality
        // alone cannot distinguish reuse, so the creation time is compared
        // too; a restarted or substituted writer fails here even when it
        // knows the challenge and the sequence.
        if peer.pid != self.expected_incarnation_pid {
            return Err(HostError::RecoveryRequired(
                "heartbeat peer is not the bound watchdog incarnation".to_owned(),
            ));
        }
        let peer_start = eliot_windows_ipc::process_creation_ticks(peer.pid).map_err(|error| {
            HostError::RecoveryRequired(format!("heartbeat peer incarnation is unknown: {error}"))
        })?;
        if peer_start != self.expected_incarnation_start_100ns {
            return Err(HostError::RecoveryRequired(
                "heartbeat peer is not the bound watchdog incarnation".to_owned(),
            ));
        }
        let next =
            eliot_windows_ipc::create_current_user_server(&self.pipe_name, &self.allowed_sid, false)
                .map_err(|error| HostError::Platform(error.to_string()))?;
        let mut current = std::mem::replace(&mut self.server, next);
        let budget = deadline.saturating_duration_since(Instant::now());
        if budget.is_zero() {
            return Err(HostError::RecoveryRequired(
                "heartbeat listen window expired".to_owned(),
            ));
        }
        let mut line = Vec::new();
        tokio::time::timeout(
            budget,
            BufReader::new(&mut current)
                .take(MESSAGE_LIMIT as u64)
                .read_until(b'\n', &mut line),
        )
        .await
        .map_err(|_| HostError::RecoveryRequired("heartbeat listen window expired".to_owned()))?
        .map_err(|error| HostError::Platform(error.to_string()))?;
        if line.len() < 2 || line.last() != Some(&b'\n') {
            return Err(HostError::RecoveryRequired(
                "heartbeat message is not a bounded newline-terminated line".to_owned(),
            ));
        }
        line.pop();
        if line.is_empty() {
            return Err(HostError::RecoveryRequired(
                "heartbeat message is empty".to_owned(),
            ));
        }
        Ok(AcceptedHeartbeat {
            raw: line,
            peer: HeartbeatPipePeer {
                process_id: peer.pid,
                image_path: peer.image,
            },
            receive_monotonic: Instant::now(),
            receive_wall_ms: wall_now_ms()?,
        })
    }
}
/// Admitted heartbeat: the validated observation plus the evidence refs
/// the readiness append stores alongside kernel readiness and the
/// watchdog-branch ref.
pub struct AdmittedHostHeartbeat {
    /// Validated derived observation.
    pub observation: HostObservedWatchdogHeartbeat,
    /// Evidence refs for the readiness observation record.
    pub evidence_refs: Vec<PlatformHandle>,
}

fn heartbeat_evidence_ref(value: String) -> Result<PlatformHandle, HostError> {
    PlatformHandle::new(value).map_err(|error| HostError::Platform(error.to_string()))
}

/// Host-observed pipe handshake history for one admission window: every
/// accepted connection is counted with its kernel-bound peer PID. The
/// admitted message must arrive inside this history; a record with no
/// handshake is writer self-report and can never become readiness evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostHandshakeSummary {
    /// Total accepted handshakes in this window. Always at least one when a
    /// message was admitted: the admitted message arrived on one of them.
    pub accept_count: u64,
    /// Distinct kernel-bound peer PIDs observed across the window. Exactly
    /// one entry (the admitted peer) is healthy; anything else fails
    /// closed.
    pub distinct_peer_pids: Vec<u32>,
}

/// Handshake-history admission, extracted so every fault stays explicit
/// without growing the admission function: no handshake, more than one
/// distinct peer PID, an admitted peer that never connected, or a
/// handshake count outside the observed accepts each fail closed on
/// their own.
///
/// # Errors
///
/// Returns an error for every failed history check: a message outside a
/// coherent Host-observed history must never become a supervised claim.
fn check_handshake_history(
    observed: &HostObservedWatchdogHeartbeat,
    peer: &HeartbeatPipePeer,
    handshake: &HostHandshakeSummary,
) -> Result<(), HostError> {
    if handshake.accept_count == 0 {
        return Err(HostError::RecoveryRequired(
            "heartbeat admission observed no pipe handshake".to_owned(),
        ));
    }
    if handshake.distinct_peer_pids.len() > 1 {
        return Err(HostError::RecoveryRequired(
            "heartbeat admission observed more than one peer process".to_owned(),
        ));
    }
    if handshake.distinct_peer_pids.first() != Some(&peer.process_id) {
        return Err(HostError::RecoveryRequired(
            "heartbeat peer is not the sole observed handshake peer".to_owned(),
        ));
    }
    if observed.handshake_count == 0 || observed.handshake_count > handshake.accept_count {
        return Err(HostError::RecoveryRequired(
            "heartbeat handshake count is outside the observed accept history".to_owned(),
        ));
    }
    Ok(())
}
///
/// Validates one derived observation against the admitted supervision
/// incarnation and the SCM-bound Watchdog process, then mints the stored
/// evidence refs. Fails closed on stale beats, epoch mismatch, coverage
/// blindness, instance drift, image substitution, PID mismatch, or a dead
/// peer. Consumes only the derived observation plus live process evidence
/// and the Host-observed handshake history, never raw pipe bytes.
///
/// # Errors
///
/// Returns `RecoveryRequired` for every failed check: an unproven
/// heartbeat must never become a supervised claim.
pub fn admit_heartbeat_observation(
    observed: HostObservedWatchdogHeartbeat,
    descriptor: &HeartbeatTransportDescriptor,
    expected_kernel_epoch: u64,
    expected_watchdog_epoch: u64,
    scm: &VerifiedWatchdogScmRunning,
    peer: &HeartbeatPipePeer,
    handshake: &HostHandshakeSummary,
) -> Result<AdmittedHostHeartbeat, HostError> {
    if observed.coverage == HostHeartbeatCoverage::Blind {
        return Err(HostError::RecoveryRequired(
            "blind heartbeat observation is never admitted".to_owned(),
        ));
    }
    if observed.host_receive_monotonic.elapsed() > observed.freshness_window {
        return Err(HostError::RecoveryRequired(
            "heartbeat observation is stale".to_owned(),
        ));
    }
    if observed.kernel_epoch != expected_kernel_epoch
        || observed.watchdog_epoch != expected_watchdog_epoch
    {
        return Err(HostError::RecoveryRequired(
            "heartbeat epochs do not match the admitted supervision incarnation".to_owned(),
        ));
    }
    if observed.service_instance_guid != descriptor.service_instance_guid
        || observed.pipe_name != descriptor.pipe_name
    {
        return Err(HostError::RecoveryRequired(
            "heartbeat instance does not match this pipe instance".to_owned(),
        ));
    }
    // SCM state-transition evidence: the incarnation named by the writer
    // must still be the exact process SCM reports Running for this
    // admission. Any restart between the bind and now changes the creation
    // time (PID reuse included) and fails closed here.
    if observed.watchdog_incarnation_pid != scm.process.process_id
        || observed.watchdog_incarnation_start_100ns != scm.process.start_time_100ns
    {
        return Err(HostError::RecoveryRequired(
            "heartbeat incarnation is not the SCM-verified watchdog incarnation".to_owned(),
        ));
    }
    // Independent-sensor gate: the admitted message must sit inside a
    // coherent Host-observed handshake history from this window. Each
    // fault below is explicit and fails closed on its own: a pure
    // writer-field record (no handshake, mixed peers, a peer that never
    // connected, or a count outside the observed accepts) can never
    // convert to readiness evidence.
    // Independent-sensor gate, checked explicitly per fault below: the
    // admitted message must sit inside a coherent Host-observed handshake
    // history from this window.
    check_handshake_history(&observed, peer, handshake)?;
    if peer.process_id == 0 || peer.process_id != scm.process.process_id {
        return Err(HostError::RecoveryRequired(
            "heartbeat peer is not the SCM-bound Watchdog process".to_owned(),
        ));
    }
    if !windows_paths_equal(&peer.image_path, Path::new(&scm.process.image_path)) {
        return Err(HostError::RecoveryRequired(
            "heartbeat peer image is not the approved Watchdog image".to_owned(),
        ));
    }
    let alive = eliot_windows_ipc::process_is_alive(peer.process_id).map_err(|error| {
        HostError::RecoveryRequired(format!("heartbeat peer liveness is unknown: {error}"))
    })?;
    if !alive {
        return Err(HostError::RecoveryRequired(
            "heartbeat peer process has exited".to_owned(),
        ));
    }
    let mut evidence_refs = Vec::with_capacity(7);
    evidence_refs.push(heartbeat_evidence_ref(format!(
        "host-heartbeat:{}",
        observed.observation_digest.as_str()
    ))?);
    evidence_refs.push(heartbeat_evidence_ref(format!(
        "host-heartbeat-coverage:{}",
        observed.coverage.as_str()
    ))?);
    evidence_refs.push(heartbeat_evidence_ref(format!(
        "host-heartbeat-received-wall-ms:{}",
        observed.host_receive_wall_ms
    ))?);
    evidence_refs.push(heartbeat_evidence_ref(format!(
        "host-heartbeat-sequence:{}",
        observed.watchdog_readiness_sequence
    ))?);
    // Independent-sensor refs: the kernel-bound peer incarnation observed
    // at connect, the SCM-verified incarnation for this admission, and the
    // Host-observed handshake count for the window. Readiness evidence
    // always names Host sensor facts, never writer fields alone.
    evidence_refs.push(heartbeat_evidence_ref(format!(
        "host-heartbeat-peer:{}:{}",
        observed.watchdog_incarnation_pid, observed.watchdog_incarnation_start_100ns
    ))?);
    evidence_refs.push(heartbeat_evidence_ref(format!(
        "host-heartbeat-scm:{}:{}",
        scm.process.process_id, scm.process.start_time_100ns
    ))?);
    evidence_refs.push(heartbeat_evidence_ref(format!(
        "host-heartbeat-handshakes:{}",
        handshake.accept_count
    ))?);
    Ok(AdmittedHostHeartbeat {
        observation: observed,
        evidence_refs,
    })
}

/// Observes one armed heartbeat admission window: binds the listener,
/// reads every heartbeat before the deadline, derives the chained
/// observations, admits the freshest against the supervision incarnation
/// and the SCM-bound process, and persists the audit twin.
///
/// A disarmed contour (no descriptor file) returns no refs and preserves
/// current behavior exactly. An armed contour with no fresh admitted
/// heartbeat fails closed: no supervised claim without fresh observation.
///
/// Callers run on the sync Host contour; the async accept loop drives on a
/// throwaway current-thread runtime (precedent: the Kernel `ProbeReady`
/// bridges in this crate).
///
/// # Errors
///
/// Returns an error for listener, read, derive, admission, or persistence
/// failures on an armed contour.
pub fn observe_armed_heartbeat(
    host_state_root: &Path,
    expected_kernel_epoch: u64,
    expected_watchdog_epoch: u64,
    scm: &VerifiedWatchdogScmRunning,
) -> Result<Vec<PlatformHandle>, HostError> {
    let Some(descriptor) = HeartbeatTransportDescriptor::load(host_state_root)? else {
        return Ok(Vec::new());
    };
    // An unbound rendezvous names no proven peer: bind (post-start SCM
    // verification) must complete before any admission window opens.
    if !descriptor.is_bound() {
        return Err(HostError::RecoveryRequired(
            "heartbeat descriptor carries no verified incarnation".to_owned(),
        ));
    }
    let prior = load_prior_heartbeat_observation(host_state_root);
    debug_assert!(
        tokio::runtime::Handle::try_current().is_err(),
        "heartbeat observation requires a sync contour"
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let deadline = Instant::now() + ADMISSION_READ_TIMEOUT;
    let accepted = runtime.block_on(async {
        // The listener binds inside the runtime: pipe creation registers
        // with the reactor.
        let mut listener = HeartbeatListener::bind(
            descriptor.pipe_name.as_str(),
            descriptor.watchdog_incarnation_pid,
            descriptor.watchdog_incarnation_start_100ns,
        )?;
        let mut out = Vec::new();
        loop {
            if Instant::now() >= deadline {
                break;
            }
            match listener.accept_one(deadline).await {
                Ok(accept) => out.push(accept),
                Err(error) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    return Err(error);
                }
            }
        }
        Ok(out)
    });
    let accepted: Vec<AcceptedHeartbeat> = accepted?;
    if accepted.is_empty() {
        return Err(HostError::RecoveryRequired(
            "armed heartbeat transport delivered no fresh heartbeat".to_owned(),
        ));
    }
    let mut previous = prior;
    let mut last_observed = None;
    for (index, accept) in accepted.iter().enumerate() {
        let handshake_index = u64::try_from(index + 1).map_err(|_| {
            HostError::RecoveryRequired("heartbeat handshake count overflows".to_owned())
        })?;
        let observed = derive_heartbeat_observation(
            accept.raw.as_slice(),
            &descriptor,
            previous.as_ref(),
            accept.receive_monotonic,
            accept.receive_wall_ms,
            handshake_index,
        )?;
        previous = Some(observed.persisted_view());
        last_observed = Some(observed);
    }
    let observed = last_observed.ok_or_else(|| {
        HostError::RecoveryRequired("armed heartbeat transport delivered no fresh heartbeat".to_owned())
    })?;
    let peer = accepted
        .last()
        .map(|accept| accept.peer.clone())
        .ok_or_else(|| {
            HostError::RecoveryRequired(
                "armed heartbeat transport delivered no fresh heartbeat".to_owned(),
            )
        })?;
    let mut distinct_peer_pids: Vec<u32> = Vec::new();
    for accept in &accepted {
        if !distinct_peer_pids.contains(&accept.peer.process_id) {
            distinct_peer_pids.push(accept.peer.process_id);
        }
    }
    let handshake = HostHandshakeSummary {
        accept_count: u64::try_from(accepted.len()).map_err(|_| {
            HostError::RecoveryRequired("heartbeat handshake count overflows".to_owned())
        })?,
        distinct_peer_pids,
    };
    let admitted = admit_heartbeat_observation(
        observed,
        &descriptor,
        expected_kernel_epoch,
        expected_watchdog_epoch,
        scm,
        &peer,
        &handshake,
    )?;
    persist_heartbeat_observation(host_state_root, &admitted.observation)?;
    Ok(admitted.evidence_refs)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn test_dir() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("eliot-host-hb-test-{}-{n}", std::process::id()))
    }

    fn test_descriptor() -> HeartbeatTransportDescriptor {
        HeartbeatTransportDescriptor::issue("test-installation-1750", 7)
            .unwrap_or_else(|_| panic!("test descriptor must issue"))
    }

    fn self_incarnation() -> (u32, u64) {
        let pid = std::process::id();
        let start = eliot_windows_ipc::process_creation_ticks(pid)
            .unwrap_or_else(|_| panic!("own creation ticks must query"));
        (pid, start)
    }

    fn test_bound_descriptor() -> HeartbeatTransportDescriptor {
        let mut descriptor = test_descriptor();
        let (pid, start) = self_incarnation();
        descriptor.watchdog_incarnation_pid = pid;
        descriptor.watchdog_incarnation_start_100ns = start;
        descriptor
    }

    fn test_summary() -> HostHandshakeSummary {
        HostHandshakeSummary {
            accept_count: 1,
            distinct_peer_pids: vec![std::process::id()],
        }
    }

    fn test_message(descriptor: &HeartbeatTransportDescriptor, sequence: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "service": WATCHDOG_HEARTBEAT_SERVICE,
            "protocol": WATCHDOG_HEARTBEAT_PROTOCOL,
            "authority_state": "ADMITTED_HEARTBEAT",
            "coverage_claimed": true,
            "kernel_epoch": 7,
            "watchdog_epoch": 11,
            "tick_interval_ms": 2000,
            "service_instance_guid": descriptor.service_instance_guid,
            "host_challenge_nonce": descriptor.host_challenge_nonce,
            "watchdog_readiness_sequence": sequence,
            "watchdog_incarnation_pid": descriptor.watchdog_incarnation_pid,
            "watchdog_incarnation_start_100ns": descriptor.watchdog_incarnation_start_100ns,
        }))
        .unwrap_or_else(|_| panic!("test message must encode"))
    }

    fn test_scm() -> VerifiedWatchdogScmRunning {
        let image = std::env::current_exe()
            .unwrap_or_else(|_| panic!("test image must resolve"))
            .to_string_lossy()
            .into_owned();
        let (pid, start) = self_incarnation();
        VerifiedWatchdogScmRunning {
            process: super::super::ProcessIdentity {
                process_id: pid,
                start_time_100ns: start,
                image_path: image.clone(),
            },
            wait_hint_ms: 0,
            approved_plan_generation: None,
        }
    }

    fn test_peer() -> HeartbeatPipePeer {
        let image = std::env::current_exe().unwrap_or_else(|_| panic!("test image must resolve"));
        HeartbeatPipePeer {
            process_id: std::process::id(),
            image_path: image,
        }
    }

    #[test]
    fn issue_publish_load_round_trip() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        let issued = test_descriptor();
        issued.publish(&dir).unwrap_or_else(|_| panic!("descriptor must publish"));
        let loaded = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("descriptor must load"))
            .unwrap_or_else(|| panic!("descriptor must be present"));
        assert_eq!(issued, loaded);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_absent_is_disarmed() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        let loaded = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("absent load must succeed"));
        assert!(loaded.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn canonical_field_order_is_pinned() {
        let descriptor = test_descriptor();
        let canonical = descriptor
            .canonical_bytes()
            .unwrap_or_else(|_| panic!("canonical bytes must encode"));
        let text =
            String::from_utf8(canonical).unwrap_or_else(|_| panic!("canonical is UTF-8"));
        let mut cursor = 0;
        for key in [
            "schema",
            "pipe_name",
            "host_challenge_nonce",
            "service_instance_guid",
            "installation_id",
            "transaction_plan_generation",
            "watchdog_incarnation_pid",
            "watchdog_incarnation_start_100ns",
        ] {
            let needle = format!("\"{key}\":");
            let at = text[cursor..]
                .find(needle.as_str())
                .unwrap_or_else(|| panic!("canonical bytes must carry {key} in order"));
            cursor += at + needle.len();
        }
    }

    #[test]
    fn token_sid_is_canonical() {
        let sid = eliot_windows_ipc::current_process_token_sid()
            .unwrap_or_else(|_| panic!("token SID must resolve"));
        assert!(sid.starts_with("S-"));
    }

    #[test]
    fn derive_first_read_is_partial_and_second_continuous() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let first = derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
            .unwrap_or_else(|_| panic!("first read must derive"));
        assert_eq!(first.coverage, HostHeartbeatCoverage::Partial);
        assert_eq!(first.watchdog_readiness_sequence, 1);
        assert_eq!(first.kernel_epoch, 7);
        assert_eq!(first.watchdog_epoch, 11);
        let prior = first.persisted_view();
        let second = derive_heartbeat_observation(
            &test_message(&descriptor, 2),
            &descriptor,
            Some(&prior),
            now,
            wall,
            2,
        )
        .unwrap_or_else(|_| panic!("second read must derive"));
        assert_eq!(second.coverage, HostHeartbeatCoverage::Continuous);
    }

    #[test]
    fn derive_rejects_faults() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let good = test_message(&descriptor, 1);
        let value: serde_json::Value = serde_json::from_slice(&good)
            .unwrap_or_else(|_| panic!("test message must be JSON"));
        for (field, bad) in [
            ("authority_state", serde_json::Value::String("RUNNING_NO_AUTHORITY".to_owned())),
            ("coverage_claimed", serde_json::Value::Bool(false)),
            ("kernel_epoch", serde_json::Value::Number(0.into())),
            ("watchdog_epoch", serde_json::Value::Number(0.into())),
            ("tick_interval_ms", serde_json::Value::Number(1.into())),
            (
                "host_challenge_nonce",
                serde_json::Value::String("0".repeat(64)),
            ),
            (
                "service_instance_guid",
                serde_json::Value::String("0".repeat(32)),
            ),
            ("watchdog_readiness_sequence", serde_json::Value::Number(0.into())),
            ("service", serde_json::Value::String("Other".to_owned())),
            (
                "watchdog_incarnation_pid",
                serde_json::Value::Number(0.into()),
            ),
            (
                "watchdog_incarnation_start_100ns",
                serde_json::Value::Number(0.into()),
            ),
        ] {
            let mut mutated = value.clone();
            mutated[field] = bad;
            let bytes = serde_json::to_vec(&mutated)
                .unwrap_or_else(|_| panic!("mutated message must encode"));
            assert!(
                derive_heartbeat_observation(&bytes, &descriptor, None, now, wall, 1).is_err(),
                "fault in {field} must be rejected"
            );
        }
        assert!(derive_heartbeat_observation(b"not json", &descriptor, None, now, wall, 1).is_err());
        // A pure writer-field record with no Host handshake is never evidence.
        assert!(
            derive_heartbeat_observation(&good, &descriptor, None, now, wall, 0).is_err()
        );
        // An unbound rendezvous names no proven peer.
        let unbound = test_descriptor();
        assert!(
            derive_heartbeat_observation(&test_message(&unbound, 1), &unbound, None, now, wall, 1)
                .is_err()
        );
    }

    #[test]
    fn derive_gap_is_partial() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let first = derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
            .unwrap_or_else(|_| panic!("first read must derive"));
        let prior = first.persisted_view();
        let gapped = derive_heartbeat_observation(
            &test_message(&descriptor, 3),
            &descriptor,
            Some(&prior),
            now,
            wall,
            2,
        )
        .unwrap_or_else(|_| panic!("gapped read must derive"));
        assert_eq!(gapped.coverage, HostHeartbeatCoverage::Partial);
    }

    #[test]
    fn admit_ok_and_evidence_refs() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let observed =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("read must derive"));
        let admitted =
            admit_heartbeat_observation(observed, &descriptor, 7, 11, &test_scm(), &test_peer(), &test_summary())
                .unwrap_or_else(|_| panic!("fresh heartbeat must admit"));
        assert_eq!(admitted.evidence_refs.len(), 7);
        let texts: Vec<String> = admitted
            .evidence_refs
            .iter()
            .map(|handle| handle.as_str().to_owned())
            .collect();
        assert!(texts[0].starts_with("host-heartbeat:"));
        assert_eq!(texts[1], "host-heartbeat-coverage:PARTIAL");
        assert!(texts[2].starts_with("host-heartbeat-received-wall-ms:"));
        assert_eq!(texts[3], "host-heartbeat-sequence:1");
        let (pid, start) = self_incarnation();
        assert_eq!(texts[4], format!("host-heartbeat-peer:{pid}:{start}"));
        assert_eq!(texts[5], format!("host-heartbeat-scm:{pid}:{start}"));
        assert_eq!(texts[6], "host-heartbeat-handshakes:1");
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        persist_heartbeat_observation(&dir, &admitted.observation)
            .unwrap_or_else(|_| panic!("observation must persist"));
        let prior = load_prior_heartbeat_observation(&dir)
            .unwrap_or_else(|| panic!("observation must reload"));
        assert_eq!(prior.watchdog_readiness_sequence, 1);
        assert_eq!(prior.observation_digest, admitted.observation.observation_digest);
        assert_eq!(prior.handshake_count, 1);
        assert_eq!(prior.watchdog_incarnation_pid, pid);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admit_rejects_epoch_pid_and_blind() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let observed =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("read must derive"));
        assert!(admit_heartbeat_observation(observed.clone(), &descriptor, 8, 11, &test_scm(), &test_peer(), &test_summary())
            .is_err());
        let mut foreign_peer = test_peer();
        foreign_peer.process_id = u32::try_from(observed.kernel_epoch)
            .unwrap_or_else(|_| panic!("epoch must fit u32"))
            .wrapping_add(1_000_000);
        if foreign_peer.process_id == std::process::id() {
            foreign_peer.process_id = foreign_peer.process_id.wrapping_add(1);
        }
        // The foreign peer carries its own coherent handshake so the peer
        // binding itself is what fails.
        let foreign_summary = HostHandshakeSummary {
            accept_count: 1,
            distinct_peer_pids: vec![foreign_peer.process_id],
        };
        assert!(admit_heartbeat_observation(observed.clone(), &descriptor, 7, 11, &test_scm(), &foreign_peer, &foreign_summary)
            .is_err());
        let mut blind = observed.clone();
        blind.coverage = HostHeartbeatCoverage::Blind;
        assert!(
            admit_heartbeat_observation(blind, &descriptor, 7, 11, &test_scm(), &test_peer(), &test_summary())
                .is_err()
        );
    }

    #[test]
    fn observe_disarmed_returns_no_refs() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        let refs = observe_armed_heartbeat(&dir, 7, 11, &test_scm())
            .unwrap_or_else(|_| panic!("disarmed observe must succeed"));
        assert!(refs.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn loopback_accept_derives_and_admits() {
        use tokio::io::AsyncWriteExt as _;
        let descriptor = test_bound_descriptor();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| panic!("test runtime must build"));
        let first_bytes = test_message(&descriptor, 1);
        let second_bytes = test_message(&descriptor, 2);
        let deadline = Instant::now() + Duration::from_secs(10);
        let accepted: Vec<AcceptedHeartbeat> = runtime.block_on(async {
            let mut listener = HeartbeatListener::bind(
                descriptor.pipe_name.as_str(),
                descriptor.watchdog_incarnation_pid,
                descriptor.watchdog_incarnation_start_100ns,
            )
            .unwrap_or_else(|_| panic!("loopback listener must bind"));
            let mut out = Vec::new();
            for message in [&first_bytes, &second_bytes] {
                let (accept, ()) = tokio::join!(
                    listener.accept_one(deadline),
                    async {
                        let mut client =
                            tokio::net::windows::named_pipe::ClientOptions::new()
                                .open(descriptor.pipe_name.as_str())
                                .unwrap_or_else(|_| panic!("loopback client must open"));
                        client
                            .write_all(message.as_slice())
                            .await
                            .unwrap_or_else(|_| panic!("loopback client must write"));
                        client
                            .write_all(b"\n")
                            .await
                            .unwrap_or_else(|_| panic!("loopback client must write"));
                        client
                            .flush()
                            .await
                            .unwrap_or_else(|_| panic!("loopback client must flush"));
                    }
                );
                out.push(accept.unwrap_or_else(|_| panic!("loopback accept must succeed")));
            }
            out
        });
        assert_eq!(accepted.len(), 2);
        assert_eq!(accepted[0].peer.process_id, std::process::id());
        // The first windowed read is PARTIAL (no prior chain); the second
        // chains to the first through Host-observed handshakes and the
        // bound incarnation, proving CONTINUOUS over a real pipe.
        let first = derive_heartbeat_observation(
            accepted[0].raw.as_slice(),
            &descriptor,
            None,
            accepted[0].receive_monotonic,
            accepted[0].receive_wall_ms,
            1,
        )
        .unwrap_or_else(|_| panic!("loopback read must derive"));
        assert_eq!(first.coverage, HostHeartbeatCoverage::Partial);
        let prior = first.persisted_view();
        let second = derive_heartbeat_observation(
            accepted[1].raw.as_slice(),
            &descriptor,
            Some(&prior),
            accepted[1].receive_monotonic,
            accepted[1].receive_wall_ms,
            2,
        )
        .unwrap_or_else(|_| panic!("loopback chained read must derive"));
        assert_eq!(second.coverage, HostHeartbeatCoverage::Continuous);
        let admitted = admit_heartbeat_observation(
            second,
            &descriptor,
            7,
            11,
            &test_scm(),
            &accepted[1].peer,
            &HostHandshakeSummary {
                accept_count: 2,
                distinct_peer_pids: vec![std::process::id()],
            },
        )
        .unwrap_or_else(|_| panic!("loopback heartbeat must admit"));
        assert_eq!(admitted.evidence_refs.len(), 7);
    }
    fn write_descriptor_bytes(dir: &Path, descriptor: &HeartbeatTransportDescriptor) {
        let canonical = descriptor
            .canonical_bytes()
            .unwrap_or_else(|_| panic!("canonical bytes must encode"));
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
            "pipe_name": descriptor.pipe_name,
            "host_challenge_nonce": descriptor.host_challenge_nonce,
            "service_instance_guid": descriptor.service_instance_guid,
            "installation_id": descriptor.installation_id,
            "transaction_plan_generation": descriptor.transaction_plan_generation,
            "watchdog_incarnation_pid": descriptor.watchdog_incarnation_pid,
            "watchdog_incarnation_start_100ns": descriptor.watchdog_incarnation_start_100ns,
            "descriptor_digest": sha256_hex(&canonical),
        }))
        .unwrap_or_else(|_| panic!("descriptor must encode"));
        std::fs::write(
            dir.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME),
            bytes,
        )
        .unwrap_or_else(|_| panic!("descriptor must write"));
    }

    #[test]
    fn publish_keeps_live_bound_prior_and_rotates_stopped_prior() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        // A bound prior naming this live process owns the rendezvous: a
        // fresh publish must keep it, never rotate under the live writer.
        let live = test_bound_descriptor();
        live.publish(&dir).unwrap_or_else(|_| panic!("live prior must publish"));
        let fresh = test_descriptor();
        fresh.publish(&dir).unwrap_or_else(|_| panic!("publish must keep live prior"));
        let loaded = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("descriptor must load"))
            .unwrap_or_else(|| panic!("descriptor must be present"));
        assert_eq!(loaded.host_challenge_nonce, live.host_challenge_nonce);
        assert_eq!(loaded.watchdog_incarnation_pid, std::process::id());
        // A prior naming a stopped incarnation proves the watchdog is gone:
        // rotation proceeds with the fresh challenge.
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .unwrap_or_else(|_| panic!("probe process must spawn"));
        let dead_pid = child.id();
        let dead_start = eliot_windows_ipc::process_creation_ticks(dead_pid)
            .unwrap_or_else(|_| panic!("probe incarnation must query"));
        child.wait().unwrap_or_else(|_| panic!("probe process must exit"));
        let mut stale = test_bound_descriptor();
        stale.watchdog_incarnation_pid = dead_pid;
        stale.watchdog_incarnation_start_100ns = dead_start;
        write_descriptor_bytes(&dir, &stale);
        fresh.publish(&dir).unwrap_or_else(|_| panic!("stopped prior must rotate"));
        let rotated = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("descriptor must load"))
            .unwrap_or_else(|| panic!("descriptor must be present"));
        assert_eq!(rotated.host_challenge_nonce, fresh.host_challenge_nonce);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bind_incarnation_round_trip_and_conflict() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        let issued = test_descriptor();
        issued.publish(&dir).unwrap_or_else(|_| panic!("descriptor must publish"));
        let (pid, start) = self_incarnation();
        HeartbeatTransportDescriptor::bind_incarnation(&dir, pid, start)
            .unwrap_or_else(|_| panic!("incarnation must bind"));
        let bound = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("descriptor must load"))
            .unwrap_or_else(|| panic!("descriptor must be present"));
        assert!(bound.is_bound());
        assert_eq!(bound.watchdog_incarnation_pid, pid);
        assert_eq!(bound.watchdog_incarnation_start_100ns, start);
        assert_eq!(bound.host_challenge_nonce, issued.host_challenge_nonce);
        // Rebinding the identical incarnation is a no-op, never a rewrite.
        HeartbeatTransportDescriptor::bind_incarnation(&dir, pid, start)
            .unwrap_or_else(|_| panic!("identical bind must succeed"));
        // Binding any other incarnation fails closed.
        assert!(
            HeartbeatTransportDescriptor::bind_incarnation(&dir, pid, start.wrapping_add(1))
                .is_err()
        );
        // A conflicting bind never mutates the file: the verified binding
        // survives intact, and no staging file leaks beside the descriptor.
        let intact = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("descriptor must load"))
            .unwrap_or_else(|| panic!("descriptor must be present"));
        assert_eq!(intact, bound);
        let staged: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|_| panic!("test dir must list"))
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".tmp-"))
            })
            .collect();
        assert!(staged.is_empty());
        assert!(HeartbeatTransportDescriptor::bind_incarnation(&dir, 0, 0).is_err());
        let missing = test_dir();
        std::fs::create_dir_all(&missing).unwrap_or_else(|_| panic!("test dir must build"));
        assert!(HeartbeatTransportDescriptor::bind_incarnation(&missing, pid, start).is_err());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&missing);
    }

    #[test]
    fn bind_heal_rotates_stopped_prior_and_binds_new() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        let fresh = test_descriptor();
        fresh.publish(&dir).unwrap_or_else(|_| panic!("descriptor must publish"));
        // Bind a now-dead incarnation: the conflicting owner is provably gone.
        let mut child = std::process::Command::new("cmd")
            .args(["/C", "exit 0"])
            .spawn()
            .unwrap_or_else(|_| panic!("probe process must spawn"));
        let dead_pid = child.id();
        let dead_start = eliot_windows_ipc::process_creation_ticks(dead_pid)
            .unwrap_or_else(|_| panic!("probe incarnation must query"));
        child.wait().unwrap_or_else(|_| panic!("probe process must exit"));
        HeartbeatTransportDescriptor::bind_incarnation(&dir, dead_pid, dead_start)
            .unwrap_or_else(|_| panic!("dead incarnation must bind"));
        // The heal path rotates to the issued challenge and binds the live
        // self incarnation instead of dead-ending on already-bound.
        let (pid, start) = self_incarnation();
        let issued = test_descriptor();
        HeartbeatTransportDescriptor::bind_incarnation_or_heal(&issued, &dir, pid, start)
            .unwrap_or_else(|_| panic!("heal must rotate and bind"));
        let healed = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("descriptor must load"))
            .unwrap_or_else(|| panic!("descriptor must be present"));
        assert_eq!(healed.host_challenge_nonce, issued.host_challenge_nonce);
        assert_eq!(healed.watchdog_incarnation_pid, pid);
        assert_eq!(healed.watchdog_incarnation_start_100ns, start);
        // Rehealing the identical binding is a no-op.
        HeartbeatTransportDescriptor::bind_incarnation_or_heal(&issued, &dir, pid, start)
            .unwrap_or_else(|_| panic!("identical heal must succeed"));
        // A still-live owner keeps the rendezvous: healing toward a foreign
        // incarnation fails closed and the verified binding survives.
        let foreign = test_descriptor();
        assert!(
            HeartbeatTransportDescriptor::bind_incarnation_or_heal(&foreign, &dir, dead_pid, dead_start)
                .is_err()
        );
        let intact = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("descriptor must load"))
            .unwrap_or_else(|| panic!("descriptor must be present"));
        assert_eq!(intact, healed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn concurrent_bind_incarnation_serializes_under_lock() {
        use std::sync::{Arc, Barrier};
        const WRITERS: usize = 8;
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        let issued = test_descriptor();
        issued.publish(&dir).unwrap_or_else(|_| panic!("descriptor must publish"));
        let barrier = Arc::new(Barrier::new(WRITERS));
        let winners: Vec<(u32, u64)> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..WRITERS)
                .map(|index| {
                    let barrier = Arc::clone(&barrier);
                    let dir = dir.clone();
                    scope.spawn(move || {
                        let _ = barrier.wait();
                        let pid = u32::try_from(index)
                            .unwrap_or_else(|_| panic!("writer index must fit u32"))
                            .wrapping_add(1000);
                        let start = index as u64 + 5000;
                        match HeartbeatTransportDescriptor::bind_incarnation(&dir, pid, start) {
                            Ok(_) => Some((pid, start)),
                            Err(_) => None,
                        }
                    })
                })
                .collect();
            handles
                .into_iter()
                .filter_map(|handle| {
                    handle.join().unwrap_or_else(|_| panic!("writer must join"))
                })
                .collect()
        });
        // Serialization means exactly one binder observes unbound and wins;
        // every other concurrent attempt fails closed on the already-bound
        // conflict instead of clobbering the winner.
        assert_eq!(winners.len(), 1, "exactly one concurrent bind must win");
        let (pid, start) = winners
            .into_iter()
            .next()
            .unwrap_or_else(|| panic!("one winner must exist"));
        let bound = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("descriptor must load"))
            .unwrap_or_else(|| panic!("descriptor must be present"));
        assert_eq!(bound.watchdog_incarnation_pid, pid);
        assert_eq!(bound.watchdog_incarnation_start_100ns, start);
        assert_eq!(bound.host_challenge_nonce, issued.host_challenge_nonce);
        assert_eq!(bound.service_instance_guid, issued.service_instance_guid);
        assert_eq!(bound.pipe_name, issued.pipe_name);
        // No half-written staging file leaks beside the descriptor.
        let staged: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|_| panic!("test dir must list"))
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.contains(".tmp-"))
            })
            .collect();
        assert!(staged.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn publish_replaces_contour_violating_prior() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        // Valid bound live bytes with no enforced contour: digest and
        // binding check out, but exclusive Host ownership is unproven.
        let live = test_bound_descriptor();
        write_descriptor_bytes(&dir, &live);
        let path = dir.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME);
        assert!(
            eliot_windows_ipc::verify_file_owner_and_dacl(&path).is_err(),
            "raw-written prior must miss the contour"
        );
        let fresh = test_descriptor();
        fresh.publish(&dir).unwrap_or_else(|_| panic!("publish must replace"));
        let rotated = HeartbeatTransportDescriptor::load(&dir)
            .unwrap_or_else(|_| panic!("descriptor must load"))
            .unwrap_or_else(|| panic!("descriptor must be present"));
        assert_eq!(rotated.host_challenge_nonce, fresh.host_challenge_nonce);
        eliot_windows_ipc::verify_file_owner_and_dacl(&path)
            .unwrap_or_else(|_| panic!("replacement must carry the contour"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admit_rejects_each_handshake_history_fault() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let pid = std::process::id();
        let first =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("read must derive"));
        // No handshake history: pure writer fields, never evidence.
        assert!(
            admit_heartbeat_observation(
                first.clone(),
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &HostHandshakeSummary {
                    accept_count: 0,
                    distinct_peer_pids: Vec::new(),
                },
            )
            .is_err()
        );
        // More than one distinct peer PID in one window.
        assert!(
            admit_heartbeat_observation(
                first.clone(),
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &HostHandshakeSummary {
                    accept_count: 2,
                    distinct_peer_pids: vec![pid, 4242],
                },
            )
            .is_err()
        );
        // Admitted peer never connected.
        assert!(
            admit_heartbeat_observation(
                first.clone(),
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &HostHandshakeSummary {
                    accept_count: 1,
                    distinct_peer_pids: vec![4242],
                },
            )
            .is_err()
        );
        // Accepts claimed but no peer recorded at all.
        assert!(
            admit_heartbeat_observation(
                first.clone(),
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &HostHandshakeSummary {
                    accept_count: 1,
                    distinct_peer_pids: Vec::new(),
                },
            )
            .is_err()
        );
        // The in-range count still admits.
        assert!(
            admit_heartbeat_observation(
                first,
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &test_summary(),
            )
            .is_ok()
        );
    }

    #[test]
    fn admit_rejects_out_of_range_handshake_count() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let pid = std::process::id();
        // Handshake count beyond the observed accepts.
        let ahead =
            derive_heartbeat_observation(&test_message(&descriptor, 2), &descriptor, None, now, wall, 2)
                .unwrap_or_else(|_| panic!("read must derive"));
        assert!(
            admit_heartbeat_observation(
                ahead,
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &test_summary(),
            )
            .is_err()
        );
        // Zero handshake count is writer self-report, never evidence.
        let first =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("read must derive"));
        let mut zero = first;
        zero.handshake_count = 0;
        assert!(
            admit_heartbeat_observation(
                zero,
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &test_summary(),
            )
            .is_err()
        );
        // The boundary count (equal to the accepts) still admits.
        let boundary =
            derive_heartbeat_observation(&test_message(&descriptor, 2), &descriptor, None, now, wall, 2)
                .unwrap_or_else(|_| panic!("read must derive"));
        assert!(
            admit_heartbeat_observation(
                boundary,
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &HostHandshakeSummary {
                    accept_count: 2,
                    distinct_peer_pids: vec![pid],
                },
            )
            .is_ok()
        );
    }

    #[test]
    fn continuity_requires_handshake_advancement() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let first =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("first read must derive"));
        let prior = first.persisted_view();
        // Replayed window position with the next sequence: nonzero prior,
        // but no advancement, so no continuity.
        let replayed = derive_heartbeat_observation(
            &test_message(&descriptor, 2),
            &descriptor,
            Some(&prior),
            Instant::now(),
            wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read")),
            1,
        )
        .unwrap_or_else(|_| panic!("replayed read must derive"));
        assert_eq!(replayed.coverage, HostHeartbeatCoverage::Partial);
        // Skipped window position: advancement by more than one proves a
        // missed accept, so no continuity either.
        let skipped = derive_heartbeat_observation(
            &test_message(&descriptor, 2),
            &descriptor,
            Some(&prior),
            Instant::now(),
            wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read")),
            3,
        )
        .unwrap_or_else(|_| panic!("skipped read must derive"));
        assert_eq!(skipped.coverage, HostHeartbeatCoverage::Partial);
        // Exact advancement into the current accepts chains CONTINUOUS.
        let chained = derive_heartbeat_observation(
            &test_message(&descriptor, 2),
            &descriptor,
            Some(&prior),
            Instant::now(),
            wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read")),
            2,
        )
        .unwrap_or_else(|_| panic!("chained read must derive"));
        assert_eq!(chained.coverage, HostHeartbeatCoverage::Continuous);
    }

    #[test]
    fn half_bound_descriptor_rejected() {
        let mut descriptor = test_descriptor();
        descriptor.watchdog_incarnation_pid = 12;
        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn restarted_writer_fails_closed_with_contiguous_sequence() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        // Prior window admitted sequence 1 on the bound incarnation.
        let first =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("first read must derive"));
        let prior = first.persisted_view();
        // A substituted writer knows the challenge and continues the
        // sequence, but on a new incarnation: derive rejects it outright.
        let mut impostor: serde_json::Value =
            serde_json::from_slice(&test_message(&descriptor, 2))
                .unwrap_or_else(|_| panic!("test message must be JSON"));
        impostor["watchdog_incarnation_pid"] = serde_json::Value::Number(4242.into());
        impostor["watchdog_incarnation_start_100ns"] = serde_json::Value::Number(999.into());
        let impostor_bytes = serde_json::to_vec(&impostor)
            .unwrap_or_else(|_| panic!("impostor message must encode"));
        assert!(
            derive_heartbeat_observation(&impostor_bytes, &descriptor, Some(&prior), now, wall, 2)
                .is_err()
        );
        // Continuity is never inherited across incarnations: a prior file
        // naming another incarnation downgrades to PARTIAL.
        let mut alien_prior = prior.clone();
        alien_prior.watchdog_incarnation_pid = 4242;
        alien_prior.watchdog_incarnation_start_100ns = 999;
        let downgraded = derive_heartbeat_observation(
            &test_message(&descriptor, 2),
            &descriptor,
            Some(&alien_prior),
            now,
            wall,
            2,
        )
        .unwrap_or_else(|_| panic!("downgraded read must derive"));
        assert_eq!(downgraded.coverage, HostHeartbeatCoverage::Partial);
        // Admission pins the SCM incarnation: the same message against a
        // drifted SCM incarnation (PID reuse with a new start) fails.
        let mut drifted_scm = test_scm();
        drifted_scm.process.start_time_100ns = 1;
        let observed =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("read must derive"));
        assert!(
            admit_heartbeat_observation(
                observed,
                &descriptor,
                7,
                11,
                &drifted_scm,
                &test_peer(),
                &test_summary()
            )
            .is_err()
        );
    }

    #[test]
    fn continuity_needs_same_boot_handshake_epochs_and_tick() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let first =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("first read must derive"));
        let base = first.persisted_view();
        let boot = host_boot_id().unwrap_or_else(|_| panic!("boot id must mint"));
        let mut rebooted = base.clone();
        rebooted.host_boot_id = boot.wrapping_add(1);
        let mut no_handshake = base.clone();
        no_handshake.handshake_count = 0;
        let mut new_epochs = base.clone();
        new_epochs.kernel_epoch = 8;
        let mut moved_tick = base.clone();
        moved_tick.tick_interval_ms = 4000;
        for prior in [&rebooted, &no_handshake, &new_epochs, &moved_tick] {
            let degraded = derive_heartbeat_observation(
                &test_message(&descriptor, 2),
                &descriptor,
                Some(prior),
                Instant::now(),
                wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read")),
                2,
            )
            .unwrap_or_else(|_| panic!("degraded read must derive"));
            assert_eq!(degraded.coverage, HostHeartbeatCoverage::Partial);
        }
    }

    #[test]
    fn continuity_cadence_is_measured_on_the_host_clock() {
        let descriptor = test_bound_descriptor();
        let wire: WatchdogHeartbeatWire =
            serde_json::from_slice(&test_message(&descriptor, 2))
                .unwrap_or_else(|_| panic!("test message must parse"));
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let first =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("first read must derive"));
        let window = Duration::from_secs(6);
        let boot = host_boot_id().unwrap_or_else(|_| panic!("boot id must mint"));
        let mut prior = first.persisted_view();
        // A wall-fresh but Host-clock-stale prior proves no continuity: the
        // gap is measured on the monotonic clock, never the writer tick.
        prior.host_receive_monotonic_ms = 0;
        assert!(!continuous_chain_intact(
            &wire, &descriptor, &prior, boot, 1_000_000, &window, 2
        ));
        // The live chain with a current monotonic reading holds.
        let live = first.persisted_view();
        let mono = host_monotonic_ms();
        assert!(continuous_chain_intact(
            &wire, &descriptor, &live, boot, mono, &window, 2
        ));
    }

    #[test]
    fn admit_rejects_incoherent_handshake_and_scm_drift() {
        let descriptor = test_bound_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let observed =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("read must derive"));
        let pid = std::process::id();
        // No handshake history: pure writer fields, never evidence.
        assert!(
            admit_heartbeat_observation(
                observed.clone(),
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &HostHandshakeSummary {
                    accept_count: 0,
                    distinct_peer_pids: Vec::new(),
                },
            )
            .is_err()
        );
        // Mixed peers in one window: something else connected.
        assert!(
            admit_heartbeat_observation(
                observed.clone(),
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &HostHandshakeSummary {
                    accept_count: 2,
                    distinct_peer_pids: vec![pid, 4242],
                },
            )
            .is_err()
        );
        // A peer that never connected cannot sponsor the message.
        assert!(
            admit_heartbeat_observation(
                observed.clone(),
                &descriptor,
                7,
                11,
                &test_scm(),
                &test_peer(),
                &HostHandshakeSummary {
                    accept_count: 1,
                    distinct_peer_pids: vec![4242],
                },
            )
            .is_err()
        );
        // SCM drift: PID reuse with a new creation time is a new process.
        let mut drifted = test_scm();
        drifted.process.start_time_100ns = drifted.process.start_time_100ns.wrapping_add(1);
        assert!(
            admit_heartbeat_observation(
                observed,
                &descriptor,
                7,
                11,
                &drifted,
                &test_peer(),
                &test_summary()
            )
            .is_err()
        );
    }

    #[test]
    fn transport_files_carry_the_contour() {
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        let descriptor = test_bound_descriptor();
        let descriptor_path = descriptor
            .publish(&dir)
            .unwrap_or_else(|_| panic!("descriptor must publish"));
        eliot_windows_ipc::verify_file_owner_and_dacl(&descriptor_path)
            .unwrap_or_else(|_| panic!("descriptor must carry the contour"));
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let observed =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall, 1)
                .unwrap_or_else(|_| panic!("read must derive"));
        let observation_path = persist_heartbeat_observation(&dir, &observed)
            .unwrap_or_else(|_| panic!("observation must persist"));
        eliot_windows_ipc::verify_file_owner_and_dacl(&observation_path)
            .unwrap_or_else(|_| panic!("observation must carry the contour"));
        assert!(HeartbeatTransportDescriptor::load(&dir).is_ok());
        assert!(load_prior_heartbeat_observation(&dir).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Frozen cross-crate wire pin: the exact canonical bytes of the fixed
    /// fixture hash to this digest on both the Host issuer and the
    /// Watchdog reader. Any field rename, reorder, or encoding drift on
    /// either side breaks this test the same way on both sides.
    #[test]
    fn golden_descriptor_digest_is_pinned() {
        let guid = "cd".repeat(16);
        let descriptor = HeartbeatTransportDescriptor {
            pipe_name: format!("{WATCHDOG_HEARTBEAT_PIPE_PREFIX}{guid}"),
            host_challenge_nonce: "ab".repeat(32),
            service_instance_guid: guid,
            installation_id: "test-installation-1750".to_owned(),
            transaction_plan_generation: 7,
            watchdog_incarnation_pid: 4242,
            watchdog_incarnation_start_100ns: 987_654_321,
        };
        let canonical = descriptor
            .canonical_bytes()
            .unwrap_or_else(|_| panic!("canonical bytes must encode"));
        assert_eq!(
            sha256_hex(&canonical),
            "37e86fc8c03877774c8ffe6c0f2de36db3fec230b0d9faf3448ba6a14ed9a411"
        );
    }
}
