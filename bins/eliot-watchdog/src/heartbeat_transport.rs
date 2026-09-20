//! Host-to-Watchdog heartbeat transport, writer side.
//!
//! Architecture: A8.1 (independent supervision), A13.2 (separate failure
//! domains). Implementation: I8.2 (named-pipe observation route), I1.6
//! (explicit pipe ACLs are owned by the Host listener; this writer only
//! connects), I1.7 (non-Windows containment: the transport never arms and
//! every emission is unavailable, while stdout readiness continues).
//!
//! This child owns only the Host-issued rendezvous read, the pipe writer,
//! and the admitted-emission sequence. It owns no SCM, lifecycle, lease,
//! canonical, or Kernel authority. A failed emission never fails the
//! supervision tick: the Watchdog stays live on stdout readiness and the
//! Host admission fails closed without a fresh heartbeat (A0.3).

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use eliot_runtime_contracts::{
    WATCHDOG_HEARTBEAT_PIPE_PREFIX, WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME,
    WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
};
use sha2::{Digest as _, Sha256};

use crate::watchdog_composition::{WatchdogAuthorityState, WatchdogReadiness};
use crate::{PROTOCOL_VERSION, SERVICE_NAME};

/// Upper bound for one transport descriptor file read.
const DESCRIPTOR_FILE_LIMIT: u64 = 4096;
/// Upper bound for one pipe message write, including the newline.
const MESSAGE_LIMIT: usize = 8192;
/// Exact length of the lowercase-hex host challenge echoed per message.
const NONCE_HEX_LEN: usize = 64;
/// Exact length of the lowercase-hex service instance guid.
const GUID_HEX_LEN: usize = 32;
/// Sequence carried by every fence or otherwise unadmitted announce. Only
/// admitted emissions consume sequence numbers, so a reader that observes
/// sequence zero knows no Kernel-accepted heartbeat was claimed.
pub const FENCE_SEQUENCE: u64 = 0;
/// Transport-local bound for the installation identity echo.
const INSTALLATION_ID_LIMIT: usize = 128;

/// Writer-side heartbeat transport failure. Every variant degrades to
/// stdout-only operation; none of them fails the supervision tick.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HeartbeatTransportError {
    /// The pipe writer is unavailable on this platform or contour.
    #[error("heartbeat transport is unavailable: {0}")]
    Unavailable(String),
    /// A present descriptor failed validation or binding.
    #[error("heartbeat descriptor is invalid: {0}")]
    InvalidDescriptor(String),
    /// One emission failed after validation.
    #[error("heartbeat emission failed: {0}")]
    Emit(String),
}

/// Host-issued rendezvous: pipe name plus per-instance challenge, bound to
/// the installer-approved bootstrap contour.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeartbeatTransportDescriptor {
    pipe_name: String,
    host_challenge_nonce: String,
    service_instance_guid: String,
    installation_id: String,
    transaction_plan_generation: u64,
}

impl HeartbeatTransportDescriptor {
    /// Returns the per-instance Host-owned pipe name.
    #[must_use]
    pub fn pipe_name(&self) -> &str {
        &self.pipe_name
    }

    /// Returns the per-instance challenge the writer echoes per message.
    #[must_use]
    pub fn host_challenge_nonce(&self) -> &str {
        &self.host_challenge_nonce
    }

    /// Returns the pipe instance guid the writer echoes per message.
    #[must_use]
    pub fn service_instance_guid(&self) -> &str {
        &self.service_instance_guid
    }
}

/// Canonical descriptor bytes. Field order is the wire contract shared with
/// the Host issuer: both sides serialize this exact shape and hash it into
/// the descriptor digest.
#[derive(serde::Serialize)]
struct HeartbeatDescriptorCanonical<'a> {
    schema: &'a str,
    pipe_name: &'a str,
    host_challenge_nonce: &'a str,
    service_instance_guid: &'a str,
    installation_id: &'a str,
    transaction_plan_generation: u64,
}

/// Parsed descriptor wire shape. Unknown fields are tolerated so a
/// forward-compatible issuer cannot break an older reader; every
/// load-bearing field below is still required and exact.
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

fn canonical_descriptor_bytes(
    schema: &str,
    pipe_name: &str,
    host_challenge_nonce: &str,
    service_instance_guid: &str,
    installation_id: &str,
    transaction_plan_generation: u64,
) -> Result<Vec<u8>, HeartbeatTransportError> {
    serde_json::to_vec(&HeartbeatDescriptorCanonical {
        schema,
        pipe_name,
        host_challenge_nonce,
        service_instance_guid,
        installation_id,
        transaction_plan_generation,
    })
    .map_err(|error| HeartbeatTransportError::InvalidDescriptor(error.to_string()))
}

fn descriptor_digest(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let mut text = String::with_capacity(64);
    for byte in digest.finalize() {
        use std::fmt::Write as _;
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// Parses and validates one descriptor file image against the exact
/// installer-bound bootstrap contour. Pure and platform-independent so unit
/// tests cover it on every platform.
fn parse_descriptor(
    bytes: &[u8],
    installation_id: &str,
    transaction_plan_generation: u64,
) -> Result<HeartbeatTransportDescriptor, HeartbeatTransportError> {
    let wire: HeartbeatDescriptorWire = serde_json::from_slice(bytes)
        .map_err(|error| HeartbeatTransportError::InvalidDescriptor(error.to_string()))?;
    if wire.schema != WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA {
        return Err(HeartbeatTransportError::InvalidDescriptor(
            "heartbeat descriptor schema is unsupported".to_owned(),
        ));
    }
    if !valid_pipe_name(&wire.pipe_name) {
        return Err(HeartbeatTransportError::InvalidDescriptor(
            "heartbeat descriptor pipe name is not allow-listed".to_owned(),
        ));
    }
    if !is_lower_hex(&wire.host_challenge_nonce, NONCE_HEX_LEN) {
        return Err(HeartbeatTransportError::InvalidDescriptor(
            "heartbeat descriptor challenge is not 256-bit lowercase hex".to_owned(),
        ));
    }
    if !is_lower_hex(&wire.service_instance_guid, GUID_HEX_LEN) {
        return Err(HeartbeatTransportError::InvalidDescriptor(
            "heartbeat descriptor instance guid is not 128-bit lowercase hex".to_owned(),
        ));
    }
    if wire.installation_id.is_empty()
        || wire.installation_id.len() > INSTALLATION_ID_LIMIT
        || wire.transaction_plan_generation == 0
    {
        return Err(HeartbeatTransportError::InvalidDescriptor(
            "heartbeat descriptor bootstrap binding is not canonical".to_owned(),
        ));
    }
    if wire.installation_id != installation_id
        || wire.transaction_plan_generation != transaction_plan_generation
    {
        return Err(HeartbeatTransportError::InvalidDescriptor(
            "heartbeat descriptor does not bind this bootstrap contour".to_owned(),
        ));
    }
    let canonical = canonical_descriptor_bytes(
        &wire.schema,
        &wire.pipe_name,
        &wire.host_challenge_nonce,
        &wire.service_instance_guid,
        &wire.installation_id,
        wire.transaction_plan_generation,
    )?;
    if descriptor_digest(&canonical) != wire.descriptor_digest {
        return Err(HeartbeatTransportError::InvalidDescriptor(
            "heartbeat descriptor digest does not match its canonical bytes".to_owned(),
        ));
    }
    Ok(HeartbeatTransportDescriptor {
        pipe_name: wire.pipe_name,
        host_challenge_nonce: wire.host_challenge_nonce,
        service_instance_guid: wire.service_instance_guid,
        installation_id: wire.installation_id,
        transaction_plan_generation: wire.transaction_plan_generation,
    })
}

/// Armed writer state: validated rendezvous plus the admitted sequence.
struct ArmedHeartbeat {
    descriptor: HeartbeatTransportDescriptor,
    sequence: u64,
    last_emit: Option<Instant>,
}

/// Shared writer-side heartbeat transport. The transport arms lazily from
/// the Host-issued descriptor file on first use, so a descriptor issued
/// after Watchdog start (pre-Phase-B fence, then Host start and Phase-B
/// materialization) is picked up without a restart. Sequence state is
/// internally synchronized so the composition tick and the process
/// entrypoint share one counter.
pub struct HeartbeatTransport {
    host_state_root: PathBuf,
    installation_id: String,
    transaction_plan_generation: u64,
    tick_interval: Duration,
    state: Mutex<Option<ArmedHeartbeat>>,
}

impl HeartbeatTransport {
    /// Binds the transport to this bootstrap contour. Performs no I/O: the
    /// descriptor file is read on first emission, so late issuance is safe.
    #[must_use]
    pub fn for_bootstrap(
        host_state_root: &Path,
        installation_id: &str,
        transaction_plan_generation: u64,
        tick_interval: Duration,
    ) -> Self {
        Self {
            host_state_root: host_state_root.to_path_buf(),
            installation_id: installation_id.to_owned(),
            transaction_plan_generation,
            tick_interval,
            state: Mutex::new(None),
        }
    }

    /// Loads the Host-issued rendezvous for tests and diagnostics: an
    /// absent file means disarmed (Ok(None)); a present-but-invalid file
    /// is an error the caller degrades to disarmed stdout-only operation.
    ///
    /// Non-Windows always reports disarmed (I1.7 containment).
    pub fn load(
        host_state_root: &Path,
        installation_id: &str,
        transaction_plan_generation: u64,
        tick_interval: Duration,
    ) -> Result<Option<Self>, HeartbeatTransportError> {
        #[cfg(not(windows))]
        {
            let _ = (
                host_state_root,
                installation_id,
                transaction_plan_generation,
                tick_interval,
            );
            return Ok(None);
        }
        #[cfg(windows)]
        {
            let transport = Self::for_bootstrap(
                host_state_root,
                installation_id,
                transaction_plan_generation,
                tick_interval,
            );
            match transport.ensure_armed() {
                Ok(()) => Ok(Some(transport)),
                Err(HeartbeatTransportError::Unavailable(_)) => Ok(None),
                Err(error) => Err(error),
            }
        }
    }

    /// Returns the echoed identity pair, or empty strings while disarmed.
    #[must_use]
    pub fn echo_identity(&self) -> (String, String) {
        match self.state.lock() {
            Ok(state) => match state.as_ref() {
                Some(armed) => (
                    armed.descriptor.service_instance_guid.clone(),
                    armed.descriptor.host_challenge_nonce.clone(),
                ),
                None => (String::new(), String::new()),
            },
            Err(_) => (String::new(), String::new()),
        }
    }

    /// Returns the last successfully emitted admitted sequence (zero when no
    /// admitted heartbeat was ever emitted).
    #[must_use]
    pub fn last_sequence(&self) -> u64 {
        match self.state.lock() {
            Ok(state) => match state.as_ref() {
                Some(armed) => armed.sequence,
                None => FENCE_SEQUENCE,
            },
            Err(_) => FENCE_SEQUENCE,
        }
    }

    /// Arms the transport from the Host-issued descriptor file. A missing
    /// file is disarmed-unavailable (the normal pre-Phase-B state), never
    /// an error that could fail supervision.
    fn ensure_armed(&self) -> Result<(), HeartbeatTransportError> {
        #[cfg(not(windows))]
        {
            return Err(HeartbeatTransportError::Unavailable(
                "named-pipe heartbeat transport is Windows-only".to_owned(),
            ));
        }
        #[cfg(windows)]
        {
            match self.state.lock() {
                Ok(state) => {
                    if state.is_some() {
                        return Ok(());
                    }
                }
                Err(_) => {
                    return Err(HeartbeatTransportError::Emit(
                        "heartbeat state is poisoned".to_owned(),
                    ));
                }
            }
            let path = self.host_state_root.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME);
            let bytes = match std::fs::read(&path) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Err(HeartbeatTransportError::Unavailable(
                        "heartbeat transport disarmed: no Host descriptor".to_owned(),
                    ));
                }
                Err(error) => {
                    return Err(HeartbeatTransportError::InvalidDescriptor(error.to_string()));
                }
            };
            if bytes.len() as u64 > DESCRIPTOR_FILE_LIMIT {
                return Err(HeartbeatTransportError::InvalidDescriptor(
                    "heartbeat descriptor exceeds its bounded size".to_owned(),
                ));
            }
            let descriptor =
                parse_descriptor(&bytes, &self.installation_id, self.transaction_plan_generation)?;
            match self.state.lock() {
                Ok(mut state) => {
                    if state.is_none() {
                        *state = Some(ArmedHeartbeat {
                            descriptor,
                            sequence: FENCE_SEQUENCE,
                            last_emit: None,
                        });
                    }
                    Ok(())
                }
                Err(_) => Err(HeartbeatTransportError::Emit(
                    "heartbeat state is poisoned".to_owned(),
                )),
            }
        }
    }

    /// Emits one fence announce (sequence zero, `RunningNoAuthority` only).
    /// Best-effort: failures degrade to stdout-only and are traced.
    pub async fn emit_fence(&self, fence: &WatchdogReadiness) {
        if fence.authority_state != WatchdogAuthorityState::RunningNoAuthority {
            return;
        }
        if self.ensure_armed().is_err() {
            return;
        }
        let (pipe_name, guid, nonce) = match self.state.lock() {
            Ok(state) => match state.as_ref() {
                Some(armed) => (
                    armed.descriptor.pipe_name.clone(),
                    armed.descriptor.service_instance_guid.clone(),
                    armed.descriptor.host_challenge_nonce.clone(),
                ),
                None => return,
            },
            Err(_) => return,
        };
        let message = WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            authority_state: WatchdogAuthorityState::RunningNoAuthority,
            coverage_claimed: false,
            kernel_epoch: 0,
            watchdog_epoch: 0,
            tick_interval_ms: fence.tick_interval_ms,
            service_instance_guid: guid,
            host_challenge_nonce: nonce,
            watchdog_readiness_sequence: FENCE_SEQUENCE,
        };
        let bytes = serde_json::to_vec(&message).unwrap_or_default();
        if bytes.is_empty() || bytes.len() > MESSAGE_LIMIT {
            return;
        }
        if let Err(error) = write_heartbeat_line(&pipe_name, &bytes).await {
            tracing::debug!(
                event = "watchdog.heartbeat.fence_skipped",
                observation = "attempted",
                error = error.to_string().as_str(),
                "heartbeat fence write skipped; stdout readiness continues"
            );
        }
    }

    /// Emits one admitted heartbeat after the Kernel port accepted it, with
    /// the next strictly increasing sequence. The sequence advances only on
    /// a successful write, so a Host reader never observes a gap for a
    /// message it could not have received. A call inside the tick cadence
    /// guard returns the current sequence without writing. No lock is held
    /// across the pipe write so the emission future stays Send.
    ///
    /// # Errors
    ///
    /// Returns a typed error for zero epochs, a disarmed contour, poisoned
    /// sequence state, an oversize message, or a failed pipe write. Callers
    /// trace and continue supervision; they never fail the tick for
    /// transport backpressure.
    pub async fn emit_admitted(
        &self,
        kernel_epoch: u64,
        watchdog_epoch: u64,
        tick_interval_ms: u128,
    ) -> Result<u64, HeartbeatTransportError> {
        if kernel_epoch == 0 || watchdog_epoch == 0 {
            return Err(HeartbeatTransportError::Emit(
                "admitted heartbeat carries a zero epoch".to_owned(),
            ));
        }
        self.ensure_armed()?;
        let (pipe_name, guid, nonce, sequence) = match self.state.lock() {
            Ok(state) => match state.as_ref() {
                Some(armed) => {
                    if armed.last_emit.is_some_and(|at| at.elapsed() < self.tick_interval) {
                        tracing::debug!(
                            event = "watchdog.heartbeat.cadence_guarded",
                            observation = "attempted",
                            "admitted heartbeat inside the tick cadence guard; sequence held"
                        );
                        return Ok(armed.sequence);
                    }
                    match armed.sequence.checked_add(1) {
                        Some(next) => (
                            armed.descriptor.pipe_name.clone(),
                            armed.descriptor.service_instance_guid.clone(),
                            armed.descriptor.host_challenge_nonce.clone(),
                            next,
                        ),
                        None => {
                            return Err(HeartbeatTransportError::Emit(
                                "heartbeat sequence exhausted".to_owned(),
                            ));
                        }
                    }
                }
                None => {
                    return Err(HeartbeatTransportError::Unavailable(
                        "heartbeat transport disarmed after arming".to_owned(),
                    ));
                }
            },
            Err(_) => {
                return Err(HeartbeatTransportError::Emit(
                    "heartbeat state is poisoned".to_owned(),
                ));
            }
        };
        let message = WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            authority_state: WatchdogAuthorityState::AdmittedHeartbeat,
            coverage_claimed: true,
            kernel_epoch,
            watchdog_epoch,
            tick_interval_ms,
            service_instance_guid: guid,
            host_challenge_nonce: nonce,
            watchdog_readiness_sequence: sequence,
        };
        let bytes = serde_json::to_vec(&message)
            .map_err(|error| HeartbeatTransportError::Emit(error.to_string()))?;
        if bytes.len() > MESSAGE_LIMIT {
            return Err(HeartbeatTransportError::Emit(
                "admitted heartbeat exceeds its bounded size".to_owned(),
            ));
        }
        write_heartbeat_line(&pipe_name, &bytes).await?;
        if let Ok(mut state) = self.state.lock()
            && let Some(armed) = state.as_mut()
        {
            armed.sequence = armed.sequence.max(sequence);
            armed.last_emit = Some(Instant::now());
        }
        Ok(sequence)
    }
}

/// Writes one newline-terminated heartbeat message to the Host-owned pipe.
/// Opening a pipe with no listening server fails fast instead of blocking,
/// so a disarmed contour only costs one failed open per emission attempt.
#[cfg(windows)]
async fn write_heartbeat_line(
    pipe_name: &str,
    message: &[u8],
) -> Result<(), HeartbeatTransportError> {
    use tokio::io::AsyncWriteExt as _;
    let mut client = tokio::net::windows::named_pipe::ClientOptions::new()
        .open(pipe_name)
        .map_err(|error| HeartbeatTransportError::Emit(error.to_string()))?;
    client
        .write_all(message)
        .await
        .map_err(|error| HeartbeatTransportError::Emit(error.to_string()))?;
    client
        .write_all(b"\n")
        .await
        .map_err(|error| HeartbeatTransportError::Emit(error.to_string()))?;
    client
        .flush()
        .await
        .map_err(|error| HeartbeatTransportError::Emit(error.to_string()))?;
    Ok(())
}

/// Non-Windows containment (I1.7): the pipe writer never exists.
#[cfg(not(windows))]
async fn write_heartbeat_line(
    _pipe_name: &str,
    _message: &[u8],
) -> Result<(), HeartbeatTransportError> {
    Err(HeartbeatTransportError::Unavailable(
        "named-pipe heartbeat transport is Windows-only".to_owned(),
    ))
}
#[cfg(test)]
mod tests {
    use super::*;
    use eliot_runtime_contracts::{WATCHDOG_HEARTBEAT_PROTOCOL, WATCHDOG_HEARTBEAT_SERVICE};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(1);

    struct Fixture {
        installation_id: String,
        generation: u64,
        pipe_name: String,
        nonce: String,
        guid: String,
    }

    fn fixture() -> Fixture {
        let guid = "cd".repeat(16);
        Fixture {
            installation_id: "test-installation-1750".to_owned(),
            generation: 7,
            pipe_name: format!("{WATCHDOG_HEARTBEAT_PIPE_PREFIX}{guid}"),
            nonce: "ab".repeat(32),
            guid,
        }
    }

    fn fixture_bytes(fixture: &Fixture) -> Vec<u8> {
        let canonical = canonical_descriptor_bytes(
            WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
            &fixture.pipe_name,
            &fixture.nonce,
            &fixture.guid,
            &fixture.installation_id,
            fixture.generation,
        )
        .unwrap_or_else(|_| panic!("canonical fixture bytes must encode"));
        let digest = descriptor_digest(&canonical);
        serde_json::to_vec(&serde_json::json!({
            "schema": WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
            "pipe_name": fixture.pipe_name,
            "host_challenge_nonce": fixture.nonce,
            "service_instance_guid": fixture.guid,
            "installation_id": fixture.installation_id,
            "transaction_plan_generation": fixture.generation,
            "descriptor_digest": digest,
        }))
        .unwrap_or_else(|_| panic!("fixture descriptor must encode"))
    }

    fn test_dir() -> PathBuf {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("eliot-hb-test-{}-{n}", std::process::id()))
    }

    fn armed_transport(dir: &Path, tick: Duration) -> HeartbeatTransport {
        let fixture = fixture();
        std::fs::create_dir_all(dir).unwrap_or_else(|_| panic!("test dir must build"));
        std::fs::write(
            dir.join(WATCHDOG_HEARTBEAT_TRANSPORT_FILE_NAME),
            fixture_bytes(&fixture),
        )
        .unwrap_or_else(|_| panic!("fixture descriptor must write"));
        HeartbeatTransport::for_bootstrap(
            dir,
            &fixture.installation_id,
            fixture.generation,
            tick,
        )
    }

    #[test]
    fn valid_descriptor_round_trip() {
        let fixture = fixture();
        let parsed = parse_descriptor(
            &fixture_bytes(&fixture),
            &fixture.installation_id,
            fixture.generation,
        )
        .unwrap_or_else(|_| panic!("valid fixture descriptor must parse"));
        assert_eq!(parsed.pipe_name(), fixture.pipe_name.as_str());
        assert_eq!(parsed.host_challenge_nonce(), fixture.nonce.as_str());
        assert_eq!(parsed.service_instance_guid(), fixture.guid.as_str());
    }

    #[test]
    fn canonical_field_order_is_pinned() {
        let fixture = fixture();
        let canonical = canonical_descriptor_bytes(
            WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
            &fixture.pipe_name,
            &fixture.nonce,
            &fixture.guid,
            &fixture.installation_id,
            fixture.generation,
        )
        .unwrap_or_else(|_| panic!("canonical fixture bytes must encode"));
        let text = String::from_utf8(canonical).unwrap_or_else(|_| panic!("canonical is UTF-8"));
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
    fn descriptor_rejects_each_fault() {
        let fixture = fixture();
        let good = fixture_bytes(&fixture);
        let value: serde_json::Value = serde_json::from_slice(&good)
            .unwrap_or_else(|_| panic!("fixture must be JSON"));
        let faults = [
            ("schema", "eliot.wrong.v9".to_owned()),
            ("pipe_name", "relative-pipe".to_owned()),
            ("pipe_name", format!("{WATCHDOG_HEARTBEAT_PIPE_PREFIX}../escape")),
            ("host_challenge_nonce", "ab".repeat(31)),
            ("host_challenge_nonce", "AB".repeat(32)),
            ("service_instance_guid", "cd".repeat(15)),
            ("installation_id", String::new()),
        ];
        for (field, bad) in faults {
            let mut mutated = value.clone();
            mutated[field] = serde_json::Value::String(bad);
            let bytes = serde_json::to_vec(&mutated)
                .unwrap_or_else(|_| panic!("mutated fixture must encode"));
            assert!(
                parse_descriptor(&bytes, &fixture.installation_id, fixture.generation).is_err(),
                "fault in {field} must be rejected"
            );
        }
    }

    #[test]
    fn descriptor_rejects_binding_and_digest_mismatch() {
        let fixture = fixture();
        let good = fixture_bytes(&fixture);
        assert!(parse_descriptor(&good, "other-installation", fixture.generation).is_err());
        assert!(parse_descriptor(&good, &fixture.installation_id, fixture.generation + 1).is_err());
        let mut value: serde_json::Value = serde_json::from_slice(&good)
            .unwrap_or_else(|_| panic!("fixture must be JSON"));
        value["descriptor_digest"] = serde_json::Value::String("0".repeat(64));
        let bytes =
            serde_json::to_vec(&value).unwrap_or_else(|_| panic!("mutated fixture must encode"));
        assert!(parse_descriptor(&bytes, &fixture.installation_id, fixture.generation).is_err());
        assert!(
            parse_descriptor(b"not json", &fixture.installation_id, fixture.generation).is_err()
        );
    }

    #[test]
    fn wire_consts_match_binary_consts() {
        assert_eq!(SERVICE_NAME, WATCHDOG_HEARTBEAT_SERVICE);
        assert_eq!(PROTOCOL_VERSION, WATCHDOG_HEARTBEAT_PROTOCOL);
    }
    /// Frozen cross-crate wire pin: the fixed fixture canonicalizes and
    /// hashes identically on the Watchdog reader and the Host issuer (see
    /// the mirrored golden test Host-side). Any field rename, reorder, or
    /// encoding drift on either side breaks this test the same way.
    #[test]
    fn golden_descriptor_digest_is_pinned() {
        let fixture = fixture();
        let canonical = canonical_descriptor_bytes(
            WATCHDOG_HEARTBEAT_TRANSPORT_SCHEMA,
            &fixture.pipe_name,
            &fixture.nonce,
            &fixture.guid,
            &fixture.installation_id,
            fixture.generation,
        )
        .unwrap_or_else(|_| panic!("canonical fixture bytes must encode"));
        assert_eq!(
            descriptor_digest(&canonical),
            "bb49f196da03bcc23d553e29068cdb0ad04ed12304a907c0b8271ffd03e024f1"
        );
    }

    #[test]
    fn zero_epochs_rejected_without_sequence_burn() {
        let dir = test_dir();
        let transport = armed_transport(&dir, Duration::from_secs(2));
        assert_eq!(transport.last_sequence(), FENCE_SEQUENCE);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| panic!("test runtime must build"));
        assert!(runtime.block_on(transport.emit_admitted(0, 11, 2000)).is_err());
        assert!(runtime.block_on(transport.emit_admitted(7, 0, 2000)).is_err());
        assert_eq!(transport.last_sequence(), FENCE_SEQUENCE);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_reports_disarmed_and_unavailable() {
        let dir = test_dir();
        let loaded = HeartbeatTransport::load(
            &dir,
            "test-installation-1750",
            7,
            Duration::from_secs(2),
        )
        .unwrap_or_else(|_| panic!("containment load must succeed"));
        assert!(loaded.is_none());
        let transport = armed_transport(&dir, Duration::from_secs(2));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap_or_else(|_| panic!("test runtime must build"));
        assert!(runtime.block_on(transport.emit_admitted(7, 11, 2000)).is_err());
        assert_eq!(transport.last_sequence(), FENCE_SEQUENCE);
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[cfg(windows)]
    fn loopback_pipe_name() -> String {
        let n = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        format!("{WATCHDOG_HEARTBEAT_PIPE_PREFIX}{pid:08x}{n:08x}0123456789abcdef")
    }

    #[cfg(windows)]
    fn loopback_transport(pipe_name: &str) -> HeartbeatTransport {
        HeartbeatTransport {
            host_state_root: PathBuf::from("loopback-root"),
            installation_id: "loopback".to_owned(),
            transaction_plan_generation: 3,
            tick_interval: Duration::ZERO,
            state: Mutex::new(Some(ArmedHeartbeat {
                descriptor: HeartbeatTransportDescriptor {
                    pipe_name: pipe_name.to_owned(),
                    host_challenge_nonce: "12".repeat(32),
                    service_instance_guid: "ef".repeat(16),
                    installation_id: "loopback".to_owned(),
                    transaction_plan_generation: 3,
                },
                sequence: FENCE_SEQUENCE,
                last_emit: None,
            })),
        }
    }

    #[cfg(windows)]
    async fn read_message_line(
        server: &mut tokio::net::windows::named_pipe::NamedPipeServer,
    ) -> serde_json::Value {
        use tokio::io::{AsyncBufReadExt as _, BufReader};
        let mut line = String::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            BufReader::new(server).read_line(&mut line),
        )
        .await
        .unwrap_or_else(|_| panic!("loopback read must complete"))
        .unwrap_or_else(|_| panic!("loopback read must succeed"));
        serde_json::from_str(&line).unwrap_or_else(|_| panic!("loopback line must be JSON"))
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn loopback_emission_carries_identity_and_sequence() {
        use tokio::net::windows::named_pipe::ServerOptions;
        let pipe_name = loopback_pipe_name();
        let transport = loopback_transport(&pipe_name);
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_name)
            .unwrap_or_else(|_| panic!("loopback server must bind"));
        let (connected, emitted) =
            tokio::join!(server.connect(), transport.emit_admitted(7, 11, 2000));
        connected.unwrap_or_else(|_| panic!("loopback client must connect"));
        assert_eq!(
            emitted.unwrap_or_else(|_| panic!("loopback emission must succeed")),
            1
        );
        let message = read_message_line(&mut server).await;
        assert_eq!(message["service"], serde_json::Value::String("EliotWatchdog".to_owned()));
        assert_eq!(
            message["protocol"],
            serde_json::Value::String("eliot.watchdog.v1".to_owned())
        );
        assert_eq!(message["authority_state"], serde_json::Value::String("ADMITTED_HEARTBEAT".to_owned()));
        assert_eq!(message["coverage_claimed"], serde_json::Value::Bool(true));
        assert_eq!(message["kernel_epoch"], serde_json::Value::Number(7.into()));
        assert_eq!(message["watchdog_epoch"], serde_json::Value::Number(11.into()));
        assert_eq!(message["tick_interval_ms"], serde_json::Value::Number(2000.into()));
        assert_eq!(message["service_instance_guid"], serde_json::Value::String("ef".repeat(16)));
        assert_eq!(message["host_challenge_nonce"], serde_json::Value::String("12".repeat(32)));
        assert_eq!(message["watchdog_readiness_sequence"], serde_json::Value::Number(1.into()));
        assert_eq!(transport.last_sequence(), 1);
        drop(server);
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn fence_announce_uses_sequence_zero_and_skips_admitted_state() {
        use tokio::net::windows::named_pipe::ServerOptions;
        let fence = WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            authority_state: WatchdogAuthorityState::RunningNoAuthority,
            coverage_claimed: false,
            kernel_epoch: 0,
            watchdog_epoch: 0,
            tick_interval_ms: 2000,
            service_instance_guid: String::new(),
            host_challenge_nonce: String::new(),
            watchdog_readiness_sequence: 0,
        };
        let fence_pipe = loopback_pipe_name();
        let fence_transport = loopback_transport(&fence_pipe);
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&fence_pipe)
            .unwrap_or_else(|_| panic!("loopback server must bind"));
        let (connected, ()) =
            tokio::join!(server.connect(), fence_transport.emit_fence(&fence));
        connected.unwrap_or_else(|_| panic!("loopback fence must connect"));
        let message = read_message_line(&mut server).await;
        assert_eq!(message["watchdog_readiness_sequence"], serde_json::Value::Number(0.into()));
        assert_eq!(message["authority_state"], serde_json::Value::String("RUNNING_NO_AUTHORITY".to_owned()));
        assert_eq!(message["service_instance_guid"], serde_json::Value::String("ef".repeat(16)));
        assert_eq!(message["host_challenge_nonce"], serde_json::Value::String("12".repeat(32)));
        assert_eq!(fence_transport.last_sequence(), FENCE_SEQUENCE);
        drop(server);
        let admitted = WatchdogReadiness {
            service: SERVICE_NAME,
            protocol: PROTOCOL_VERSION,
            authority_state: WatchdogAuthorityState::AdmittedHeartbeat,
            coverage_claimed: true,
            kernel_epoch: 7,
            watchdog_epoch: 11,
            tick_interval_ms: 2000,
            service_instance_guid: String::new(),
            host_challenge_nonce: String::new(),
            watchdog_readiness_sequence: 9,
        };
        let skip_pipe = loopback_pipe_name();
        let skip_transport = loopback_transport(&skip_pipe);
        let guard_server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&skip_pipe)
            .unwrap_or_else(|_| panic!("loopback server must bind"));
        let skipped = tokio::time::timeout(
            Duration::from_millis(300),
            async {
                let (connected, ()) =
                    tokio::join!(guard_server.connect(), skip_transport.emit_fence(&admitted));
                connected.unwrap_or_else(|_| panic!("no client may connect during a fence skip"));
            },
        )
        .await;
        assert!(skipped.is_err(), "admitted state must never ride a fence announce");
        assert_eq!(skip_transport.last_sequence(), FENCE_SEQUENCE);
    }
}
