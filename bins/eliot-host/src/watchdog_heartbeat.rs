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
        Ok(())
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
        };
        descriptor.validate()?;
        Ok(descriptor)
    }

    /// Publishes the descriptor below the Host state root with a pinned
    /// create-new plus readback, replacing a prior instance first so every
    /// Host start mints a fresh challenge (per-instance binding).
    ///
    /// # Errors
    ///
    /// Returns an error when the prior instance cannot be retired or the
    /// new descriptor cannot be durably published.
    pub fn publish(&self, host_state_root: &Path) -> Result<PathBuf, HostError> {
        let path = host_state_root.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(HostError::Platform(error.to_string())),
        }
        let canonical = self.canonical_bytes()?;
        let wire = serde_json::json!({
            "schema": WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
            "pipe_name": self.pipe_name,
            "host_challenge_nonce": self.host_challenge_nonce,
            "service_instance_guid": self.service_instance_guid,
            "installation_id": self.installation_id,
            "transaction_plan_generation": self.transaction_plan_generation,
            "descriptor_digest": sha256_hex(&canonical),
        });
        let bytes = serde_json::to_vec(&wire).map_err(|error| HostError::Platform(error.to_string()))?;
        if bytes.len() as u64 > TRANSPORT_FILE_LIMIT {
            return Err(HostError::Platform(
                "heartbeat descriptor exceeds its bounded size".to_owned(),
            ));
        }
        write_watchdog_publication_child(&path, &bytes)?;
        Ok(path)
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
        Ok(Some(descriptor))
    }
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

/// Derives one Host observation from raw pipe bytes. Fails closed on every
/// contract violation: wrong service/protocol, unadmitted authority, zero
/// epochs, nonce/guid/pipe mismatch, insane tick, or a fence sequence.
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
) -> Result<HostObservedWatchdogHeartbeat, HostError> {
    if raw.len() > MESSAGE_LIMIT {
        return Err(HostError::RecoveryRequired(
            "heartbeat message exceeds its bounded size".to_owned(),
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
    let coverage = match prior {
        None => HostHeartbeatCoverage::Partial,
        Some(previous) => {
            let contiguous = wire.watchdog_readiness_sequence
                == previous.watchdog_readiness_sequence.saturating_add(1);
            let cadence_current = receive_wall_ms.saturating_sub(previous.host_receive_wall_ms)
                <= freshness_window.as_millis().try_into().unwrap_or(u64::MAX);
            let same_instance = wire.service_instance_guid == previous.service_instance_guid;
            if contiguous && cadence_current && same_instance {
                HostHeartbeatCoverage::Continuous
            } else {
                HostHeartbeatCoverage::Partial
            }
        }
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
        host_receive_monotonic: receive_monotonic,
        host_receive_wall_ms: receive_wall_ms,
        freshness_deadline_wall_ms,
        freshness_window,
        coverage,
        observation_digest,
    })
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
    Ok(path)
}

/// Loads the prior persisted observation for coverage chaining. Absent or
/// corrupt files degrade to `None` (the next derive reports PARTIAL): a
/// lost audit twin must never block a fresh observation, and must never
/// manufacture continuity.
pub(crate) fn load_prior_heartbeat_observation(
    host_state_root: &Path,
) -> Option<PersistedHeartbeatObservation> {
    let bytes = std::fs::read(host_state_root.join(HOST_HEARTBEAT_OBSERVATION_FILE_NAME)).ok()?;
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
        host_receive_wall_ms: persisted.host_receive_wall_ms,
        coverage: persisted.coverage.as_str(),
    };
    if sha256_json(&canonical).ok()? != persisted.observation_digest {
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
}

impl HeartbeatListener {
    /// Binds the first pipe instance for this Host start.
    ///
    /// # Errors
    ///
    /// Returns an error when the token SID is unavailable or the pipe
    /// cannot be created (a squatted name fails here via first-instance
    /// ownership).
    pub fn bind(pipe_name: &str) -> Result<Self, HostError> {
        let allowed_sid = eliot_windows_ipc::current_process_token_sid()
            .map_err(|error| HostError::Platform(error.to_string()))?;
        let server =
            eliot_windows_ipc::create_current_user_server(pipe_name, &allowed_sid, true)
                .map_err(|error| HostError::Platform(error.to_string()))?;
        Ok(Self {
            server,
            pipe_name: pipe_name.to_owned(),
            allowed_sid,
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

/// Validates one derived observation against the admitted supervision
/// incarnation and the SCM-bound Watchdog process, then mints the stored
/// evidence refs. Fails closed on stale beats, epoch mismatch, coverage
/// blindness, instance drift, image substitution, PID mismatch, or a dead
/// peer. Consumes only the derived observation plus live process evidence,
/// never raw pipe bytes.
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
    let mut evidence_refs = Vec::with_capacity(4);
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
        let mut listener = HeartbeatListener::bind(descriptor.pipe_name.as_str())?;
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
    for accept in &accepted {
        let observed = derive_heartbeat_observation(
            accept.raw.as_slice(),
            &descriptor,
            previous.as_ref(),
            accept.receive_monotonic,
            accept.receive_wall_ms,
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
    let admitted = admit_heartbeat_observation(
        observed,
        &descriptor,
        expected_kernel_epoch,
        expected_watchdog_epoch,
        scm,
        &peer,
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
        }))
        .unwrap_or_else(|_| panic!("test message must encode"))
    }

    fn test_scm() -> VerifiedWatchdogScmRunning {
        let image = std::env::current_exe()
            .unwrap_or_else(|_| panic!("test image must resolve"))
            .to_string_lossy()
            .into_owned();
        VerifiedWatchdogScmRunning {
            process: super::super::ProcessIdentity {
                process_id: std::process::id(),
                start_time_100ns: 1,
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
        let descriptor = test_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let first = derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall)
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
        )
        .unwrap_or_else(|_| panic!("second read must derive"));
        assert_eq!(second.coverage, HostHeartbeatCoverage::Continuous);
    }

    #[test]
    fn derive_rejects_faults() {
        let descriptor = test_descriptor();
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
        ] {
            let mut mutated = value.clone();
            mutated[field] = bad;
            let bytes = serde_json::to_vec(&mutated)
                .unwrap_or_else(|_| panic!("mutated message must encode"));
            assert!(
                derive_heartbeat_observation(&bytes, &descriptor, None, now, wall).is_err(),
                "fault in {field} must be rejected"
            );
        }
        assert!(derive_heartbeat_observation(b"not json", &descriptor, None, now, wall).is_err());
    }

    #[test]
    fn derive_gap_is_partial() {
        let descriptor = test_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let first = derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall)
            .unwrap_or_else(|_| panic!("first read must derive"));
        let prior = first.persisted_view();
        let gapped = derive_heartbeat_observation(
            &test_message(&descriptor, 3),
            &descriptor,
            Some(&prior),
            now,
            wall,
        )
        .unwrap_or_else(|_| panic!("gapped read must derive"));
        assert_eq!(gapped.coverage, HostHeartbeatCoverage::Partial);
    }

    #[test]
    fn admit_ok_and_evidence_refs() {
        let descriptor = test_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let observed =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall)
                .unwrap_or_else(|_| panic!("read must derive"));
        let admitted =
            admit_heartbeat_observation(observed, &descriptor, 7, 11, &test_scm(), &test_peer())
                .unwrap_or_else(|_| panic!("fresh heartbeat must admit"));
        assert_eq!(admitted.evidence_refs.len(), 4);
        let texts: Vec<String> = admitted
            .evidence_refs
            .iter()
            .map(|handle| handle.as_str().to_owned())
            .collect();
        assert!(texts[0].starts_with("host-heartbeat:"));
        assert_eq!(texts[1], "host-heartbeat-coverage:PARTIAL");
        assert!(texts[2].starts_with("host-heartbeat-received-wall-ms:"));
        assert_eq!(texts[3], "host-heartbeat-sequence:1");
        let dir = test_dir();
        std::fs::create_dir_all(&dir).unwrap_or_else(|_| panic!("test dir must build"));
        persist_heartbeat_observation(&dir, &admitted.observation)
            .unwrap_or_else(|_| panic!("observation must persist"));
        let prior = load_prior_heartbeat_observation(&dir)
            .unwrap_or_else(|| panic!("observation must reload"));
        assert_eq!(prior.watchdog_readiness_sequence, 1);
        assert_eq!(prior.observation_digest, admitted.observation.observation_digest);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn admit_rejects_epoch_pid_and_blind() {
        let descriptor = test_descriptor();
        let now = Instant::now();
        let wall = wall_now_ms().unwrap_or_else(|_| panic!("wall clock must read"));
        let observed =
            derive_heartbeat_observation(&test_message(&descriptor, 1), &descriptor, None, now, wall)
                .unwrap_or_else(|_| panic!("read must derive"));
        assert!(admit_heartbeat_observation(observed.clone(), &descriptor, 8, 11, &test_scm(), &test_peer())
            .is_err());
        let mut foreign_peer = test_peer();
        foreign_peer.process_id = u32::try_from(observed.kernel_epoch)
            .unwrap_or_else(|_| panic!("epoch must fit u32"))
            .wrapping_add(1_000_000);
        if foreign_peer.process_id == std::process::id() {
            foreign_peer.process_id = foreign_peer.process_id.wrapping_add(1);
        }
        assert!(admit_heartbeat_observation(observed.clone(), &descriptor, 7, 11, &test_scm(), &foreign_peer)
            .is_err());
        let mut blind = observed.clone();
        blind.coverage = HostHeartbeatCoverage::Blind;
        assert!(
            admit_heartbeat_observation(blind, &descriptor, 7, 11, &test_scm(), &test_peer())
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
        let descriptor = test_descriptor();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| panic!("test runtime must build"));
        let message = test_message(&descriptor, 1);
        let deadline = Instant::now() + Duration::from_secs(10);
        let accepted = runtime.block_on(async {
            let mut listener = HeartbeatListener::bind(descriptor.pipe_name.as_str())
                .unwrap_or_else(|_| panic!("loopback listener must bind"));
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
            accept.unwrap_or_else(|_| panic!("loopback accept must succeed"))
        });
        assert_eq!(accepted.peer.process_id, std::process::id());
        let observed = derive_heartbeat_observation(
            accepted.raw.as_slice(),
            &descriptor,
            None,
            accepted.receive_monotonic,
            accepted.receive_wall_ms,
        )
        .unwrap_or_else(|_| panic!("loopback read must derive"));
        assert_eq!(observed.coverage, HostHeartbeatCoverage::Partial);
        let admitted = admit_heartbeat_observation(
            observed,
            &descriptor,
            7,
            11,
            &test_scm(),
            &accepted.peer,
        )
        .unwrap_or_else(|_| panic!("loopback heartbeat must admit"));
        assert_eq!(admitted.evidence_refs.len(), 4);
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
        };
        let canonical = descriptor
            .canonical_bytes()
            .unwrap_or_else(|_| panic!("canonical bytes must encode"));
        assert_eq!(
            sha256_hex(&canonical),
            "bb49f196da03bcc23d553e29068cdb0ad04ed12304a907c0b8271ffd03e024f1"
        );
    }
}
