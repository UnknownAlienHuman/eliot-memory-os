//! Validated dispatch material for the WASM P03 child contour (issue #1955).
//!
//! Session-bound dispatch material validated against itself, plus the
//! colocated guest bytes re-hashed against the bound digests. Carries
//! exactly what the parent drive binds: pre-binding derivation identities,
//! the validated grant funding the one-shot permit, the owner-measured host
//! digest, and the proven guest bytes.
//!
//! Wire contract: the owner publisher (`eliot-kernel-service::
//! wasm_dispatch`) stages the material envelope JSON plus the colocated
//! guest artifact/input files next to the installed image under the file
//! names below. The envelope field names and closed spelling sets are the
//! contract with that publisher; this module parses the staged envelope
//! bytes and enforces the same shapes the publisher enforces, so a mixed
//! or tampered envelope fails here before any authority, permit, or child
//! exists.
//!
//! Learning-ticket note: guest/input bytes cross this module opaquely.
//! Ticket screening is single-owned by the learning lane's guest gate
//! (`check_guest_tickets` over `AdmissionInput` in
//! `work/2376-guest-gate-ticket`); this module binds input digests and
//! never screens tickets, so no second admission surface is invented
//! here. Where the seated path must screen, the drive invokes the
//! caller-provided screen hook (see `dispatch_drive`), which the
//! integration owner wires to that exact screen call.

use eliot_contracts::{EpochId, StateFence, sha256_hex};
use eliot_wasm_runtime::Sha256Digest;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cli_contract::Profile;

/// Dispatch material file name the child reader derives from its executable
/// directory (`current_exe`, never argv/stdin/env). Duplicated here because
/// the host drive half owns its read path; the owner publisher stays the
/// authority for the staged value.
pub const WASM_HOST_MATERIAL_FILE_NAME: &str = "eliot-wasm-host.admitted-dispatch.json";
/// Colocated guest artifact file name staged with the material.
pub const WASM_HOST_GUEST_ARTIFACT_FILE_NAME: &str = "eliot-wasm-host.guest-artifact.bin";
/// Colocated guest input file name staged with the material.
pub const WASM_HOST_GUEST_INPUT_FILE_NAME: &str = "eliot-wasm-host.guest-input.bin";
/// Legacy single-fixed-file control name (issue #2896 item 13).
///
/// The pre-stream external control handoff: one mutable `WasmHostRequestFrame`
/// JSON document with no owner sequence, delivery generation, or receipt. The
/// versioned owner publisher never writes this name; it persists only so an
/// already-staged file is treated as unadmitted legacy evidence rather than
/// silently certified or silently erased. The reader joins it to the running
/// operation only while the versioned spool holds no delivery for this
/// generation (serialized owner rule: the sequenced stream always wins), and
/// retires it only after admission plus successful worker enqueue, by
/// exact-name byte-verified delete. Anything it cannot join stays in place
/// for its owner.
pub const WASM_HOST_CONTROL_FILE_NAME: &str = "eliot-wasm-host.control-request.json";
/// Legacy served-marker projection. New-format deliveries use the exact
/// per-slot `DISPOSITION.json` record; this fixed name is read only for
/// legacy classification and is never new-format ownership evidence.
pub const WASM_HOST_SERVED_FILE_NAME: &str = "eliot-wasm-host.served.json";
/// Legacy in-flight marker projection. New-format deliveries use the exact
/// per-slot `DISPOSITION.json` record; this fixed name is read only for
/// legacy classification and is never new-format ownership evidence.
pub const WASM_HOST_INFLIGHT_FILE_NAME: &str = "eliot-wasm-host.inflight.json";
/// Legacy fixed-name result record. New-format results are stored as `RESULT.json`
/// in the owner generation slot and bound to its disposition identity.
pub const WASM_HOST_SERVED_RESULT_FILE_NAME: &str = "eliot-wasm-host.served-result.json";
/// Served-result record allocation guard: it is also the retained-owner byte
/// budget for one operation's whole bounded result-event sequence, so the
/// aggregate is refused before it is built rather than after it is written.
/// The identity wrapper and commitment add a few hundred bytes on top of the
/// stored events; anything larger is refused before parsing, never truncated.
pub const SERVED_RESULT_MAX_BYTES: usize = 128 * 1024;
/// Material envelope wire identity, matched exactly with the publisher.
pub const WASM_DISPATCH_MATERIAL_WIRE_ID: &str = "eliot.wasm.dispatch-material";
/// Material envelope wire version, matched exactly with the publisher.
pub const WASM_DISPATCH_MATERIAL_WIRE_VERSION: u16 = 1;
/// Material staging allocation guard: guest inputs are small framed
/// vectors, never dumps.
pub const DISPATCH_MATERIAL_MAX_BYTES: u64 = 64 * 1024;

/// Owner generation-slot parent directory name, mirrored exactly with the
/// owner publisher (`eliot-kernel-service::wasm_dispatch`). Each owner
/// publication stages one immutable slot here before it exposes the
/// fixed-name set this reader consumes. Mirrored because the claim half
/// owns the read path; the owner publisher stays the authority for the
/// value.
pub const WASM_DELIVERY_SLOT_DIR_NAME: &str = "eliot-wasm-host.generations";
/// Owner pending-publication marker, mirrored exactly with the publisher.
pub const WASM_DELIVERY_PENDING_FILE_NAME: &str = "PENDING.json";
/// Owner ready-publication marker, mirrored exactly with the publisher. The
/// owner writes it last, so its presence is the owner's proof that the whole
/// immutable set was staged before the fixed names were exposed.
pub const WASM_DELIVERY_READY_FILE_NAME: &str = "READY.json";
/// Owner failed-publication marker, mirrored exactly with the publisher.
pub const WASM_DELIVERY_FAILED_FILE_NAME: &str = "FAILED.json";
/// Shared owner/child delivery claim and acknowledgement state. Unlike the
/// publication markers above, this record is rewritten by both processes
/// while holding the installation-root mutex.
pub const WASM_DELIVERY_DISPOSITION_FILE_NAME: &str = "DISPOSITION.json";
/// Exact bounded child result retained in the corresponding generation slot.
pub const WASM_DELIVERY_RESULT_FILE_NAME: &str = "RESULT.json";
/// Owner-issued delivery-identity wire version, mirrored exactly with the
/// publisher. A slot record carrying any other version is refused rather than
/// reinterpreted.
pub const WASM_DELIVERY_IDENTITY_VERSION: u16 = 1;

static NEXT_HOST_CLAIMANT_INCARNATION: AtomicU64 = AtomicU64::new(1);

/// Runs one bounded local filesystem transaction while the owner/child
/// installation-root mutex is held. The lock crate is Windows-only; on
/// other targets these authority-bearing operations fail closed.
fn with_installation_root_lock<T>(
    root: &std::path::Path,
    operation: impl FnOnce() -> Result<T, MaterialError>,
) -> Result<T, MaterialError> {
    #[cfg(windows)]
    {
        let _guard = eliot_windows_ipc::acquire_installation_root_lock(root)
            .map_err(|_| MaterialError::Unreadable("installation-root-lock".to_owned()))?;
        operation()
    }
    #[cfg(not(windows))]
    {
        let _ = root;
        let _ = operation;
        Err(MaterialError::Unreadable(
            "installation-root-lock-unavailable".to_owned(),
        ))
    }
}

/// IO-result adapter for the bounded marker/result writers.
fn with_installation_root_lock_io<T>(
    root: &std::path::Path,
    operation: impl FnOnce() -> std::io::Result<T>,
) -> std::io::Result<T> {
    with_installation_root_lock(root, || {
        operation().map_err(|error| MaterialError::Unreadable(error.kind().to_string()))
    })
    .map_err(|_| std::io::Error::other("installation-root-lock-or-io"))
}

/// Control-delivery envelope wire identity, mirrored exactly with the owner
/// publisher (`eliot-kernel-service::wasm_control`).
pub const WASM_CONTROL_DELIVERY_WIRE_ID: &str = "eliot.wasm.control-delivery";
/// Control-delivery envelope wire version, mirrored exactly with the owner.
pub const WASM_CONTROL_DELIVERY_WIRE_VERSION: u16 = 1;
/// Control-ack envelope wire identity, mirrored exactly with the owner.
pub const WASM_CONTROL_ACK_WIRE_ID: &str = "eliot.wasm.control-ack";
/// Control-ack envelope wire version, mirrored exactly with the owner.
pub const WASM_CONTROL_ACK_WIRE_VERSION: u16 = 1;
/// Spool filename prefix. The full delivery name appends
/// `{generation}-{sequence:06}` plus the kind suffix, so two owner controls
/// can never overwrite each other through one mutable pathname.
pub const WASM_CONTROL_FILE_PREFIX: &str = "eliot-wasm-host.control-g";
/// Bounded spool rows per running operation and generation: the reader
/// validates at most this many deliveries per poll and holds no per-file
/// memory beyond one pending and one accepted slot.
pub const WASM_CONTROL_SPOOL_MAX_DELIVERIES: usize = 8;
/// Bounded spool file bytes: a larger staged file is refused before parsing,
/// never truncated.
pub const WASM_CONTROL_MAX_FILE_BYTES: u64 = 64 * 1024;
/// Bounded directory entries advanced per poll. The reader resumes its cursor
/// on the next tick and retains at most this many same-generation names of
/// each slot class, so foreign entries cannot hide a later control delivery.
pub const WASM_CONTROL_SPOOL_SCAN_CAP: usize = 64;
/// Delivery validity window in milliseconds, mirroring the sixty-second
/// dispatch-grant contour: freshness opens at the origin decision, never at
/// derivation or observation time.
pub const WASM_CONTROL_GRANT_WINDOW_MS: u64 = 60_000;
/// Deterministic replay-key/digest domain, mirroring the dispatch derivation
/// domain pattern so control identities can never collide with dispatch ones.
pub const WASM_CONTROL_REPLAY_KEY_DOMAIN: &str = "eliot-wasm-host-control/v1";
/// Bounded ack/refusal detail text: refusal evidence stays small.
pub const WASM_CONTROL_MAX_DETAIL_BYTES: usize = 512;
/// Cancel spelling shared with the owner publisher.
pub const WASM_CONTROL_KIND_CANCEL: &str = "cancel";
/// Reconcile spelling shared with the owner publisher.
pub const WASM_CONTROL_KIND_RECONCILE: &str = "reconcile";
/// Shutdown spelling shared with the owner publisher.
pub const WASM_CONTROL_KIND_SHUTDOWN: &str = "shutdown";

/// Owner-issued control kind, mirrored field-for-field with the publisher.
/// The closed lowercase spelling is part of the digest and replay-key input,
/// so it must match exactly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WasmControlKind {
    /// Contain an uncertain outcome through the runtime owner.
    Cancel,
    /// Reconcile an uncertain outcome through its owners.
    Reconcile,
    /// Close admission and drain.
    Shutdown,
}

impl WasmControlKind {
    /// Returns the closed wire spelling shared with the owner publisher.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => WASM_CONTROL_KIND_CANCEL,
            Self::Reconcile => WASM_CONTROL_KIND_RECONCILE,
            Self::Shutdown => WASM_CONTROL_KIND_SHUTDOWN,
        }
    }
}

/// Versioned control-delivery identity binding, mirrored field-for-field with
/// the owner publisher. Field declaration order is load-bearing: it fixes the
/// canonical digest bytes, so it must stay identical on both sides.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDeliveryIdentity {
    /// Exact decided operation identity.
    pub operation_id: String,
    /// Invocation identity, always equal to `operation_id`.
    pub invocation_id: String,
    /// Admitted claim identity from the staged dispatch material.
    pub claim_id: String,
    /// Exact running process generation (non-zero).
    pub generation: u64,
    /// Control kind in the closed lifecycle spelling.
    pub control_kind: WasmControlKind,
    /// Monotonic owner sequence within this operation/generation spool.
    pub owner_sequence: u64,
    /// Live authority epoch bound at publication.
    pub authority_epoch: EpochId,
    /// Live state fence bound at publication.
    pub state_fence: StateFence,
    /// Admitted work-scope identity from the staged material work record.
    pub work_scope: String,
    /// Authenticated publisher principal digest from the owner binding.
    pub principal_digest: String,
    /// Publishing transport connection (correlation only).
    pub session_connection: String,
    /// Publishing transport session epoch (correlation only).
    pub session_epoch: u64,
    /// Dispatch-grant digest from the staged material.
    pub dispatch_grant_digest: String,
    /// Origin-control challenge identity funding this publication.
    pub publisher_challenge_id: String,
    /// Origin-control operation class funding this publication.
    pub publisher_operation: String,
    /// Origin-control decision time in Unix milliseconds.
    pub publisher_decided_at_unix_ms: u64,
    /// Delivery expiry in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// Deterministic replay key over domain, operation, generation, kind,
    /// and sequence; retries and restarts reconcile this key.
    pub replay_key: String,
    /// Digest of the previous retained delivery in sequence order, `None`
    /// at sequence zero; ordering evidence, not consensus.
    pub previous_delivery_digest: Option<String>,
}

/// Owner-published control delivery envelope, mirrored with the publisher.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmControlDelivery {
    /// Envelope wire identity (`WASM_CONTROL_DELIVERY_WIRE_ID`).
    pub wire_id: String,
    /// Envelope wire version (`WASM_CONTROL_DELIVERY_WIRE_VERSION`).
    pub wire_version: u16,
    /// Versioned identity binding.
    pub identity: ControlDeliveryIdentity,
    /// Lowercase SHA-256 over the canonical envelope bytes; acks bind to it.
    pub delivery_digest: String,
}

/// Child-to-owner acknowledgement phase, mirrored with the publisher.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlAckPhase {
    /// The child admitted the delivery and enqueued it to the worker owner
    /// (worker completion is reported separately).
    Enqueued,
    /// The child observed the exact outcome of the accepted control.
    Completed,
    /// The child refused the delivery (admission failure evidence).
    Refused,
}

/// Child-staged acknowledgement for one delivery, mirrored with the owner.
/// The owner joins it by replay key and delivery digest during reconcile.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmControlAck {
    /// Ack wire identity (`WASM_CONTROL_ACK_WIRE_ID`).
    pub wire_id: String,
    /// Ack wire version (`WASM_CONTROL_ACK_WIRE_VERSION`).
    pub wire_version: u16,
    /// Replay key of the acknowledged delivery.
    pub replay_key: String,
    /// Operation identity of the acknowledged delivery.
    pub operation_id: String,
    /// Generation of the acknowledged delivery.
    pub generation: u64,
    /// Owner sequence of the acknowledged delivery.
    pub owner_sequence: u64,
    /// Digest of the acknowledged delivery.
    pub delivery_digest: String,
    /// Acknowledgement phase in the closed spelling.
    pub phase: ControlAckPhase,
    /// Bounded refusal/observation detail; required for `refused`.
    pub detail: Option<String>,
    /// Exact outcome digest for `completed`, when the child reports one.
    pub outcome_digest: Option<String>,
}

/// Spool filename class the child acts on. Owner-private sidecars
/// (disposition, head) and staging temps share the prefix but are never
/// read, parsed, or deleted by the child; they are simply not deliveries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlFileClass {
    /// Immutable owner delivery.
    Delivery,
    /// Child acknowledgement.
    Ack,
}

/// Typed control-delivery refusal. Stable field names only — no digests,
/// paths, or payloads echoed. The field doubles as the bounded refused-ack
/// detail, so the owner always gets typed evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ControlRefusal {
    /// Stable field name.
    pub field: &'static str,
}

impl ControlRefusal {
    /// Builds the refusal for one stable field name.
    #[must_use]
    pub const fn new(field: &'static str) -> Self {
        Self { field }
    }
}

impl std::fmt::Display for ControlRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "WASM_CONTROL_REFUSED:{}", self.field)
    }
}

impl std::error::Error for ControlRefusal {}

/// Computes the deterministic replay key over the control identity.
#[must_use]
pub fn control_replay_key(
    operation_id: &str,
    generation: u64,
    kind: WasmControlKind,
    sequence: u64,
) -> String {
    sha256_hex(
        format!(
            "{WASM_CONTROL_REPLAY_KEY_DOMAIN}|{operation_id}|{generation}|{}|{sequence}",
            kind.as_str()
        )
        .as_bytes(),
    )
}

/// Computes the delivery digest over the canonical envelope bytes. The input
/// shape matches the publisher exactly: wire fields plus the identity in
/// declaration order.
pub fn control_delivery_digest(
    identity: &ControlDeliveryIdentity,
) -> Result<String, ControlRefusal> {
    #[derive(serde::Serialize)]
    struct DigestInput<'a> {
        wire_id: &'a str,
        wire_version: u16,
        identity: &'a ControlDeliveryIdentity,
    }
    let bytes = serde_json::to_vec(&DigestInput {
        wire_id: WASM_CONTROL_DELIVERY_WIRE_ID,
        wire_version: WASM_CONTROL_DELIVERY_WIRE_VERSION,
        identity,
    })
    .map_err(|_| ControlRefusal::new("control-digest"))?;
    Ok(sha256_hex(&bytes))
}

/// Returns the exact delivery filename for one generation and sequence.
#[must_use]
pub fn control_delivery_name(generation: u64, sequence: u64) -> String {
    format!("{WASM_CONTROL_FILE_PREFIX}{generation}-{sequence:06}.json")
}

/// Returns the exact ack filename for one generation and sequence.
#[must_use]
pub fn control_ack_name(generation: u64, sequence: u64) -> String {
    format!("{WASM_CONTROL_FILE_PREFIX}{generation}-{sequence:06}.ack.json")
}

/// Parses one spool filename into its generation, sequence, and class.
/// Returns `None` for names outside the delivery/ack vocabulary — including
/// owner-private sidecars, staging temps, and non-canonical padding — so two
/// names can never address one sequence and the child never touches files
/// outside its exact names.
#[must_use]
// Spool names are an exact-octet vocabulary (item 8): case-insensitive
// matching would alias distinct sequences, so the comparisons below stay
// byte-exact by contract, and the canonical-form check rejects twins.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
pub fn parse_control_name(name: &str) -> Option<(u64, u64, ControlFileClass)> {
    let rest = name.strip_prefix(WASM_CONTROL_FILE_PREFIX)?;
    if rest.ends_with(".tmp") || rest.ends_with(".disposition.json") || rest.ends_with(".head.json")
    {
        return None;
    }
    let (class, rest) = if let Some(rest) = rest.strip_suffix(".ack.json") {
        (ControlFileClass::Ack, rest)
    } else {
        let rest = rest.strip_suffix(".json")?;
        (ControlFileClass::Delivery, rest)
    };
    let (generation, sequence) = rest.rsplit_once('-')?;
    let generation = generation.parse::<u64>().ok()?;
    let sequence = sequence.parse::<u64>().ok()?;
    if generation == 0 || !control_sequence_is_canonical(sequence, rest) {
        return None;
    }
    Some((generation, sequence, class))
}

/// Reports whether the sequence renders in exactly the canonical zero-padded
/// form the publisher stages (`{sequence:06}`).
fn control_sequence_is_canonical(sequence: u64, rest: &str) -> bool {
    rest.rsplit_once('-').is_some_and(|(_, text)| {
        !text.is_empty()
            && text.bytes().all(|byte| byte.is_ascii_digit())
            && text == format!("{sequence:06}")
    })
}

/// Reads one control spool file under the allocation guard: the length is
/// checked before and after the read so a concurrently grown file is refused
/// rather than truncated. Returns [`MaterialError::Missing`] for an absent
/// file and [`MaterialError::TooLarge`] before allocating over the ceiling —
/// never a partial read.
pub fn read_control_bytes(path: &std::path::Path) -> Result<Vec<u8>, MaterialError> {
    let root = path.parent().ok_or(MaterialError::Malformed)?;
    with_installation_root_lock(root, || read_control_bytes_unlocked(path))
}

fn read_control_bytes_unlocked(path: &std::path::Path) -> Result<Vec<u8>, MaterialError> {
    let bytes = read_bounded_regular_file(path, WASM_CONTROL_MAX_FILE_BYTES as usize)?;
    if bytes.is_empty() {
        return Err(MaterialError::TooLarge);
    }
    Ok(bytes)
}

/// Stages one child-owned control file atomically while serialized with all
/// other fixed-name transitions under the installation root lock.
pub fn stage_control_bytes(path: &std::path::Path, bytes: &[u8]) -> Result<(), MaterialError> {
    if bytes.is_empty() || bytes.len() as u64 > WASM_CONTROL_MAX_FILE_BYTES {
        return Err(MaterialError::TooLarge);
    }
    let root = path.parent().ok_or(MaterialError::Malformed)?;
    with_installation_root_lock(root, || {
        write_atomic_locked(path, bytes, WASM_CONTROL_MAX_FILE_BYTES as usize)
            .map_err(|error| MaterialError::Unreadable(error.kind().to_string()))
    })
}

/// Retires a legacy fixed control file only while the exact admitted bytes
/// remain under that name; the entire read/compare/delete transaction shares
/// the installation-root lock with publication and delivery claims.
pub fn retire_legacy_control(path: &std::path::Path, admitted_digest: &str) -> bool {
    let Some(root) = path.parent() else {
        return false;
    };
    with_installation_root_lock(root, || {
        let bytes = match read_control_bytes_unlocked(path) {
            Ok(bytes) => bytes,
            Err(_) => return Ok(false),
        };
        if sha256_hex(&bytes) != admitted_digest {
            return Ok(false);
        }
        match std::fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(MaterialError::Unreadable(error.kind().to_string())),
        }
    })
    .unwrap_or(false)
}

/// The exact running-operation binding one control delivery must join.
/// Assembled once from the admitted dispatch material and the sealed
/// invocation; every field below is compared, none of it is minted.
#[derive(Clone, Debug)]
pub struct ExpectedControlBinding {
    /// Exact decided operation identity.
    pub operation_id: String,
    /// Sealed invocation identity.
    pub invocation_id: String,
    /// Admitted claim identity.
    pub claim_id: String,
    /// Exact running process generation.
    pub generation: u64,
    /// Grant digest funding the running operation.
    pub grant_digest: String,
    /// Admitted work-scope identity.
    pub work_scope: String,
    /// Canonical live-authority-epoch JSON bound at admission, parsed once.
    pub authority_epoch: serde_json::Value,
}

/// Parses and self-validates one staged delivery envelope: wire identity,
/// closed shapes, digest self-consistency, and replay-key self-consistency.
/// Binding against the running operation happens in
/// [`join_control_delivery`]; ordering against the retained stream is the
/// reader's cursor, which additionally checks the previous-digest link.
pub fn parse_control_delivery(bytes: &[u8]) -> Result<WasmControlDelivery, ControlRefusal> {
    let delivery: WasmControlDelivery =
        serde_json::from_slice(bytes).map_err(|_| ControlRefusal::new("control-envelope"))?;
    if delivery.wire_id != WASM_CONTROL_DELIVERY_WIRE_ID
        || delivery.wire_version != WASM_CONTROL_DELIVERY_WIRE_VERSION
    {
        return Err(ControlRefusal::new("control-wire"));
    }
    let identity = &delivery.identity;
    require_control_digest(&delivery.delivery_digest, "control-digest")?;
    require_control_digest(&identity.replay_key, "control-replay-key")?;
    require_control_digest(&identity.dispatch_grant_digest, "control-grant")?;
    require_control_digest(&identity.principal_digest, "control-principal")?;
    if let Some(previous) = identity.previous_delivery_digest.as_ref() {
        require_control_digest(previous, "control-previous")?;
    }
    require_control_nonblank(&identity.operation_id, "control-operation")?;
    require_control_nonblank(&identity.invocation_id, "control-invocation")?;
    require_control_nonblank(&identity.claim_id, "control-claim")?;
    require_control_nonblank(&identity.work_scope, "control-scope")?;
    require_control_nonblank(&identity.session_connection, "control-session")?;
    require_control_nonblank(&identity.publisher_challenge_id, "control-publisher")?;
    require_control_nonblank(&identity.publisher_operation, "control-publisher")?;
    if identity.generation == 0 {
        return Err(ControlRefusal::new("control-generation"));
    }
    if identity.publisher_decided_at_unix_ms == 0 {
        return Err(ControlRefusal::new("control-decided-at"));
    }
    if identity.owner_sequence > u64::from(u32::MAX) {
        return Err(ControlRefusal::new("control-sequence"));
    }
    let expected_key = control_replay_key(
        &identity.operation_id,
        identity.generation,
        identity.control_kind,
        identity.owner_sequence,
    );
    if expected_key != identity.replay_key {
        return Err(ControlRefusal::new("control-replay-key"));
    }
    let expected_digest = control_delivery_digest(identity)?;
    if expected_digest != delivery.delivery_digest {
        return Err(ControlRefusal::new("control-digest"));
    }
    Ok(delivery)
}

/// Joins one self-validated delivery to the exact running operation:
/// generation freshness, identity triple, grant, scope, authority epoch, and
/// the origin-decision deadline window. Publisher authentication stays with
/// the existing owner admission receipt; this join checks correlation, shape,
/// and expiry, and refuses anything else with a typed field the owner can
/// reconcile.
pub fn join_control_delivery(
    delivery: &WasmControlDelivery,
    expected: &ExpectedControlBinding,
    now_unix_ms: u64,
) -> Result<(), ControlRefusal> {
    let identity = &delivery.identity;
    if identity.generation < expected.generation {
        return Err(ControlRefusal::new("control-generation-stale"));
    }
    if identity.generation > expected.generation {
        return Err(ControlRefusal::new("control-generation-future"));
    }
    if identity.operation_id != expected.operation_id {
        return Err(ControlRefusal::new("control-operation"));
    }
    if identity.invocation_id != expected.invocation_id {
        return Err(ControlRefusal::new("control-invocation"));
    }
    if identity.claim_id != expected.claim_id {
        return Err(ControlRefusal::new("control-claim"));
    }
    if identity.dispatch_grant_digest != expected.grant_digest {
        return Err(ControlRefusal::new("control-grant"));
    }
    if identity.work_scope != expected.work_scope {
        return Err(ControlRefusal::new("control-scope"));
    }
    let epoch = serde_json::to_value(&identity.authority_epoch)
        .map_err(|_| ControlRefusal::new("control-authority-epoch"))?;
    if epoch != expected.authority_epoch {
        return Err(ControlRefusal::new("control-authority-epoch"));
    }
    let decided = identity.publisher_decided_at_unix_ms;
    let deadline = identity.deadline_unix_ms;
    if deadline <= decided || deadline > decided.saturating_add(WASM_CONTROL_GRANT_WINDOW_MS) {
        return Err(ControlRefusal::new("control-deadline"));
    }
    if now_unix_ms > deadline {
        return Err(ControlRefusal::new("control-expired"));
    }
    Ok(())
}

fn require_control_nonblank(value: &str, field: &'static str) -> Result<(), ControlRefusal> {
    if value.trim().is_empty() {
        return Err(ControlRefusal::new(field));
    }
    Ok(())
}

fn require_control_digest(value: &str, field: &'static str) -> Result<(), ControlRefusal> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ControlRefusal::new(field));
    }
    Ok(())
}

/// Fail-closed material errors. Stable codes only — no paths, digests, or
/// payloads echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaterialError {
    /// No material was delivered; the caller keeps its fail-closed path.
    Missing,
    /// A staged file exceeds the allocation guard.
    TooLarge,
    /// A staged file could not be read (kind string only).
    Unreadable(String),
    /// The material bytes are not a valid envelope.
    Malformed,
    /// An observed file digest does not match the bound record.
    DigestMismatch,
    /// A record failed shape checks.
    InvalidRecord {
        /// Stable field name.
        field: &'static str,
    },
}

impl MaterialError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Missing => "DISPATCH_MATERIAL_MISSING",
            Self::TooLarge => "DISPATCH_MATERIAL_TOO_LARGE",
            Self::Unreadable(_) => "DISPATCH_MATERIAL_UNREADABLE",
            Self::Malformed => "DISPATCH_MATERIAL_MALFORMED",
            Self::DigestMismatch => "DISPATCH_MATERIAL_DIGEST_MISMATCH",
            Self::InvalidRecord { .. } => "DISPATCH_MATERIAL_INVALID_RECORD",
        }
    }
}

impl std::fmt::Display for MaterialError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(kind) => {
                write!(formatter, "DISPATCH_MATERIAL_UNREADABLE:{kind}")
            }
            Self::InvalidRecord { field } => {
                write!(formatter, "DISPATCH_MATERIAL_INVALID_RECORD:{field}")
            }
            other => formatter.write_str(other.code()),
        }
    }
}

impl std::error::Error for MaterialError {}

fn invalid(field: &'static str) -> MaterialError {
    MaterialError::InvalidRecord { field }
}

fn require_nonblank(value: &str, field: &'static str) -> Result<(), MaterialError> {
    if value.trim().is_empty() {
        return Err(invalid(field));
    }
    Ok(())
}

fn hex_digest(hex: &str, field: &'static str) -> Result<Sha256Digest, MaterialError> {
    Sha256Digest::new(hex.to_owned()).map_err(|_| invalid(field))
}

fn require_spelling(
    value: &str,
    accepted: &[&str],
    field: &'static str,
) -> Result<(), MaterialError> {
    if accepted.contains(&value) {
        Ok(())
    } else {
        Err(invalid(field))
    }
}

/// Validated guest ceilings carried for intent derivation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedGuestCeilings {
    /// Pinned component identity.
    pub component_id: String,
    /// Re-proven artifact digest.
    pub artifact_digest: Sha256Digest,
    /// Re-proven input digest.
    pub input_digest: Sha256Digest,
    /// Output byte ceiling.
    pub max_output_bytes: u64,
    /// Fuel ceiling.
    pub max_fuel: u64,
    /// Memory byte ceiling.
    pub max_memory_bytes: u64,
    /// Wall deadline (ms).
    pub wall_deadline_ms: u64,
    /// Epoch deadline ticks.
    pub epoch_deadline_ticks: u64,
    /// Table element ceiling.
    pub table_elements: u64,
    /// Instance ceiling.
    pub max_instances: u64,
    /// Artifact-read count ceiling.
    pub artifact_access_reads: u64,
    /// Artifact-read byte ceiling.
    pub artifact_access_bytes: u64,
}

/// Validated owner-authored manifest record. Closed-world constants are
/// enforced by the contour admission (`contour::check_activation_imports`
/// over the admitted generation); the owner validates entry shapes here so
/// malformed records fail at binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedManifestRecord {
    /// Admitted component identity.
    pub component_id: String,
    /// Admitted world name.
    pub world: String,
    /// Admitted guest target.
    pub target: String,
    /// Owner-recorded source digest.
    pub source_digest: Sha256Digest,
    /// Owner-recorded state-contract digest.
    pub state_contract_digest: Sha256Digest,
    /// Owner-recorded required verifier.
    pub required_verifier: String,
    /// Owner-recorded admitted privacy classes (non-empty).
    pub privacy_classes: Vec<String>,
    /// Owned state class.
    pub state_class: String,
    /// Versioned state migration contract.
    pub migration_contract: String,
    /// Privacy policy binding.
    pub privacy_policy: String,
    /// Differential comparator binding.
    pub comparator: String,
    /// Rollback generation binding, when the comparator names one.
    pub rollback_generation: Option<String>,
}

/// Validated owner-authored work identity record. Enum spellings stay
/// verbatim here; the invocation adapter maps them strictly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWorkRecord {
    /// Admitted owner identity.
    pub owner: String,
    /// Admitted work-unit identity.
    pub work_unit: String,
    /// Admitted work-scope identity.
    pub work_scope: String,
    /// Optional task reference.
    pub task_ref: Option<String>,
    /// Admitted lease identity.
    pub lease_id: String,
    /// Lease scope reference (must equal the work scope).
    pub lease_scope_ref: String,
    /// Lease state marker.
    pub lease_state: String,
    /// Generation state marker.
    pub generation_state: String,
    /// Authority revision bound at admission.
    pub authority_revision: u64,
    /// Lifecycle revision bound at admission.
    pub lifecycle_revision: u64,
    /// Verification revision bound at admission.
    pub verification_revision: u64,
    /// Deterministic seed for the guest invocation.
    pub deterministic_seed: u64,
    /// Requested contour marker.
    pub contour: String,
    /// Owner-attested generation health dimensions in struct order.
    pub generation_health: Vec<String>,
}

/// Validated owner-authored assurance record, spellings verbatim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAssuranceRecord {
    /// Opaque source identity.
    pub source_ref: String,
    /// Stable provenance/locator reference.
    pub provenance_ref: String,
    /// Integrity statement spelling.
    pub integrity: String,
    /// Freshness statement spelling.
    pub freshness: String,
    /// Competence classification spelling.
    pub competence: String,
    /// Independence classification spelling.
    pub independence: String,
    /// Privacy class spelling.
    pub privacy_class: String,
    /// Instruction taint spelling.
    pub instruction_taint: String,
    /// Permitted epistemic use spellings.
    pub epistemic_use: Vec<String>,
    /// Effect ceiling spellings.
    pub effect_ceilings: Vec<String>,
    /// Required verifier (must equal the manifest verifier).
    pub required_verifier: String,
    /// Quarantine state spelling.
    pub quarantine: String,
}

/// Validated owner-authored promotion oracle record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPromotionRecord {
    /// Corpus digest.
    pub corpus_digest: Sha256Digest,
    /// Oracle result digest.
    pub expected_result_digest: Sha256Digest,
    /// Oracle effect digest.
    pub expected_effect_digest: Sha256Digest,
    /// Oracle state-delta digest.
    pub expected_state_delta_digest: Sha256Digest,
}

/// Validated owner-attested snapshot record. Fence/epoch agreement with
/// the dispatch grant is enforced by the authority join, which derives
/// every fence from the grant; the epoch travels here as the canonical
/// JSON the derivation hashes verbatim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSnapshotRecord {
    /// Fixed Kernel service identity.
    pub service: String,
    /// Exact negotiated protocol string.
    pub protocol: String,
    /// Active resource generation (must equal the grant fence generation).
    pub generation: u64,
    /// Canonical live-authority-epoch JSON (derivation input, never
    /// interpreted here).
    pub authority_epoch_json: String,
    /// Admitted Kernel artifact digest.
    pub artifact_digest: Sha256Digest,
    /// Protected handoff snapshot digest.
    pub protected_snapshot_digest: Sha256Digest,
    /// Authenticated Kernel principal identity.
    pub principal: String,
}

/// Validated dispatch grant funding the one-shot permit: the owner-issued
/// digest plus the fence/lease material the authority join rebuilds into
/// typed broker values. Window order is enforced at binding; liveness
/// against the wall clock stays with the permit issuance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDispatchGrant {
    /// Owner-issued grant digest binding the admission identity.
    pub grant_digest: Sha256Digest,
    /// Canonical live-authority-epoch JSON bound at admission.
    pub authority_epoch_json: String,
    /// Live activation generation bound at admission (non-zero).
    pub fence_generation: u64,
    /// Deterministic per-identity fence nonce.
    pub fence_nonce: String,
    /// Deterministic per-identity lease.
    pub idempotency_key: String,
    /// Durable admission time in Unix milliseconds (window opens).
    pub admitted_at_unix_ms: u64,
    /// Grant expiry in Unix milliseconds (window closes).
    pub expires_at: u64,
    /// Owner-measured SHA-256 of the installed child image bytes.
    pub host_artifact_digest: Sha256Digest,
}

/// Session-bound dispatch material validated against itself, plus the
/// colocated file bytes re-hashed against the bound records.
///
/// Carries exactly what the parent drive binds: pre-binding derivation
/// identities, the validated grant funding the one-shot permit, the
/// owner-measured host digest, and the proven guest bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDispatchMaterial {
    /// Admitted claim identity feeding the derivation base.
    pub claim_id: String,
    /// Admitted operation identity feeding the derivation base.
    pub operation_id: String,
    /// Claiming generation feeding the derivation base.
    pub generation: u64,
    /// Canonical live-authority-epoch JSON bound at admission.
    pub authority_epoch_json: String,
    /// Claim-bound launch nonce (derivation + permit nonce).
    pub launch_nonce: String,
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Validated grant funding the one-shot permit.
    pub grant: ValidatedDispatchGrant,
    /// Owner-measured installed-image digest.
    pub host_artifact_digest: Sha256Digest,
    /// Owner-selected composition profile, compiled into this binary.
    pub profile: Profile,
    /// Artifact digest of the prior conformance-verified run, when a
    /// Shadow operation must prove progression from it.
    pub prior_conformance_artifact: Option<Sha256Digest>,
    /// Validated manifest record.
    pub manifest: ValidatedManifestRecord,
    /// Validated work identity record.
    pub work: ValidatedWorkRecord,
    /// Validated assurance record.
    pub assurance: ValidatedAssuranceRecord,
    /// Validated promotion record.
    pub promotion: ValidatedPromotionRecord,
    /// Validated snapshot record.
    pub snapshot: ValidatedSnapshotRecord,
    /// Validated guest ceilings and pinned identities.
    pub ceilings: ValidatedGuestCeilings,
    /// Observed guest artifact bytes matching the bound digest.
    pub artifact_bytes: Vec<u8>,
    /// Observed guest input bytes matching the bound digest.
    pub input_bytes: Vec<u8>,
}

/// Typed material input: the already-parsed envelope records plus the
/// colocated bytes. The execution join produces this from the staged
/// envelope file; the drive binds it without re-parsing anything.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchMaterialInput {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Claiming generation.
    pub generation: u64,
    /// Canonical live-authority-epoch JSON.
    pub authority_epoch_json: String,
    /// Claim-bound launch nonce.
    pub launch_nonce: String,
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Owner-issued grant digest (hex).
    pub grant_digest: String,
    /// Grant fence generation.
    pub grant_fence_generation: u64,
    /// Grant fence nonce.
    pub grant_fence_nonce: String,
    /// Grant lease identity.
    pub grant_idempotency_key: String,
    /// Grant expiry in Unix milliseconds.
    pub grant_expires_at: u64,
    /// Owner-measured installed-image digest (hex).
    pub host_artifact_digest: String,
    /// Owner-selected composition profile spelling.
    pub profile: String,
    /// Prior conformance-verified artifact digest (hex), if any.
    pub prior_conformance_artifact: Option<String>,
    /// Guest ceilings record.
    pub ceilings: ValidatedGuestCeilingsInput,
    /// Manifest record.
    pub manifest: ValidatedManifestInput,
    /// Work identity record.
    pub work: ValidatedWorkInput,
    /// Assurance record.
    pub assurance: ValidatedAssuranceInput,
    /// Promotion oracle record (hex digests).
    pub promotion: ValidatedPromotionInput,
    /// Snapshot record.
    pub snapshot: ValidatedSnapshotInput,
    /// Observed guest artifact bytes.
    pub artifact_bytes: Vec<u8>,
    /// Observed guest input bytes.
    pub input_bytes: Vec<u8>,
}

/// Typed guest ceilings input (digests as hex, ceilings as values).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedGuestCeilingsInput {
    /// Pinned component identity.
    pub component_id: String,
    /// Artifact digest (hex).
    pub artifact_digest: String,
    /// Input digest (hex).
    pub input_digest: String,
    /// Output byte ceiling.
    pub max_output_bytes: u64,
    /// Fuel ceiling.
    pub max_fuel: u64,
    /// Memory byte ceiling.
    pub max_memory_bytes: u64,
    /// Wall deadline (ms).
    pub wall_deadline_ms: u64,
    /// Epoch deadline ticks.
    pub epoch_deadline_ticks: u64,
    /// Table element ceiling.
    pub table_elements: u64,
    /// Instance ceiling.
    pub max_instances: u64,
    /// Artifact-read count ceiling.
    pub artifact_access_reads: u64,
    /// Artifact-read byte ceiling.
    pub artifact_access_bytes: u64,
}

/// Typed manifest input (digests as hex).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedManifestInput {
    /// Admitted component identity.
    pub component_id: String,
    /// Admitted world name.
    pub world: String,
    /// Admitted guest target.
    pub target: String,
    /// Owner-recorded source digest (hex).
    pub source_digest: String,
    /// Owner-recorded state-contract digest (hex).
    pub state_contract_digest: String,
    /// Owner-recorded required verifier.
    pub required_verifier: String,
    /// Owner-recorded admitted privacy classes (non-empty).
    pub privacy_classes: Vec<String>,
    /// Owned state class.
    pub state_class: String,
    /// Versioned state migration contract.
    pub migration_contract: String,
    /// Privacy policy binding.
    pub privacy_policy: String,
    /// Differential comparator binding.
    pub comparator: String,
    /// Rollback generation binding, when the comparator names one.
    pub rollback_generation: Option<String>,
}

/// Typed work identity input (spellings verbatim).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedWorkInput {
    /// Admitted owner identity.
    pub owner: String,
    /// Admitted work-unit identity.
    pub work_unit: String,
    /// Admitted work-scope identity.
    pub work_scope: String,
    /// Optional task reference.
    pub task_ref: Option<String>,
    /// Admitted lease identity.
    pub lease_id: String,
    /// Lease scope reference (must equal the work scope).
    pub lease_scope_ref: String,
    /// Lease state marker.
    pub lease_state: String,
    /// Generation state marker.
    pub generation_state: String,
    /// Authority revision bound at admission.
    pub authority_revision: u64,
    /// Lifecycle revision bound at admission.
    pub lifecycle_revision: u64,
    /// Verification revision bound at admission.
    pub verification_revision: u64,
    /// Deterministic seed for the guest invocation.
    pub deterministic_seed: u64,
    /// Requested contour marker.
    pub contour: String,
    /// Owner-attested generation health dimensions (exactly six).
    pub generation_health: Vec<String>,
}

/// Typed assurance input (spellings verbatim).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedAssuranceInput {
    /// Opaque source identity.
    pub source_ref: String,
    /// Stable provenance/locator reference.
    pub provenance_ref: String,
    /// Integrity statement spelling.
    pub integrity: String,
    /// Freshness statement spelling.
    pub freshness: String,
    /// Competence classification spelling.
    pub competence: String,
    /// Independence classification spelling.
    pub independence: String,
    /// Privacy class spelling.
    pub privacy_class: String,
    /// Instruction taint spelling.
    pub instruction_taint: String,
    /// Permitted epistemic use spellings.
    pub epistemic_use: Vec<String>,
    /// Effect ceiling spellings.
    pub effect_ceilings: Vec<String>,
    /// Required verifier (must equal the manifest verifier).
    pub required_verifier: String,
    /// Quarantine state spelling.
    pub quarantine: String,
}

/// Typed promotion oracle input (hex digests).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPromotionInput {
    /// Corpus digest (hex).
    pub corpus_digest: String,
    /// Oracle result digest (hex).
    pub expected_result_digest: String,
    /// Oracle effect digest (hex).
    pub expected_effect_digest: String,
    /// Oracle state-delta digest (hex).
    pub expected_state_delta_digest: String,
}

/// Typed snapshot input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedSnapshotInput {
    /// Fixed Kernel service identity.
    pub service: String,
    /// Exact negotiated protocol string.
    pub protocol: String,
    /// Active resource generation.
    pub generation: u64,
    /// Canonical live-authority-epoch JSON.
    pub authority_epoch_json: String,
    /// Admitted Kernel artifact digest (hex).
    pub artifact_digest: String,
    /// Protected handoff snapshot digest (hex).
    pub protected_snapshot_digest: String,
    /// Authenticated Kernel principal identity.
    pub principal: String,
}

/// Derives the material file path from the executable directory.
/// `None` when the loader path is unavailable: no fallback source exists.
#[must_use]
pub fn admitted_material_path() -> Option<std::path::PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let directory = executable.parent()?;
    Some(directory.join(WASM_HOST_MATERIAL_FILE_NAME))
}

/// Reads one staged file under the allocation guard. Returns
/// [`MaterialError::Missing`] for an absent file and [`MaterialError::TooLarge`]
/// before allocating over the ceiling — never a partial read.
pub fn read_staged_bytes(path: &std::path::Path) -> Result<Vec<u8>, MaterialError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            MaterialError::Missing
        } else {
            MaterialError::Unreadable(error.kind().to_string())
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(MaterialError::Unreadable("not-regular-file".to_owned()));
    }
    if metadata.len() > DISPATCH_MATERIAL_MAX_BYTES {
        return Err(MaterialError::TooLarge);
    }
    let file = std::fs::File::open(path)
        .map_err(|error| MaterialError::Unreadable(error.kind().to_string()))?;
    let mut bounded = std::io::Read::take(file, DISPATCH_MATERIAL_MAX_BYTES + 1);
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut bounded, &mut bytes)
        .map_err(|error| MaterialError::Unreadable(error.kind().to_string()))?;
    if bytes.len() as u64 > DISPATCH_MATERIAL_MAX_BYTES {
        return Err(MaterialError::TooLarge);
    }
    Ok(bytes)
}

/// Typed per-file reclamation outcome (#2786 step 5). `NotFound`,
/// sharing-violation, access-denial, and `Preserved` are distinct
/// outcomes, never success: the caller preserves them as a bounded
/// residual instead of overwriting the primary execution result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReclaimOutcome {
    /// The claimed file was removed.
    Reclaimed,
    /// The fixed name held bytes that did not verify against the claim;
    /// they were restored (or left to a successor) and never deleted.
    Preserved,
    /// No file was present; an already-reclaimed or never-staged path.
    NotFound,
    /// The file is open without delete sharing (Windows `ERROR_SHARING_VIOLATION`).
    SharingViolation,
    /// Removal was denied by ACL or platform policy.
    AccessDenied,
    /// Removal failed with another platform error kind (kind string only).
    Other(String),
}

impl ReclaimOutcome {
    /// Whether this outcome removed the claimed bytes.
    #[must_use]
    pub const fn reclaimed(&self) -> bool {
        matches!(self, Self::Reclaimed)
    }

    /// Stable code for this outcome.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Reclaimed => "RECLAIM_RECLAIMED",
            Self::Preserved => "RECLAIM_PRESERVED",
            Self::NotFound => "RECLAIM_NOT_FOUND",
            Self::SharingViolation => "RECLAIM_SHARING_VIOLATION",
            Self::AccessDenied => "RECLAIM_ACCESS_DENIED",
            Self::Other(_) => "RECLAIM_OTHER",
        }
    }
}

impl std::fmt::Display for ReclaimOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(kind) => {
                write!(formatter, "RECLAIM_OTHER:{kind}")
            }
            other => formatter.write_str(other.code()),
        }
    }
}

/// Owner-issued delivery identity bound at claim time (#2786 steps 1/3).
///
/// Derived verbatim from the staged envelope plus re-proven digests against
/// the existing `WasmPublishedBundle`/`WasmJoinGate` wire shape (no field is
/// generated locally). A directory/path is only a locator: this identity —
/// claim, operation, generation, launch nonce, grant and fence generation,
/// artifact/input digests, admission and expiry window, authority epoch, the
/// material-set digest of the exact staged envelope bytes, and the
/// installation binding — is what the claim binds.
///
/// `envelope_digest` is the ORIGINAL recorded binding, measured once from the
/// exact envelope bytes this claim was parsed from. Every later comparison
/// re-hashes the bytes found on disk and compares them against this recorded
/// value; a re-parse of a replacement envelope that happens to carry the same
/// typed field values is a different delivery, never a match. The owner's
/// publication incarnation/revision stay in the owner slot record
/// ([`OwnerDeliveryIdentity`]) and are cross-checked there.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StagedDeliveryIdentity {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Claiming generation (non-zero).
    pub generation: u64,
    /// Claim-bound launch nonce.
    pub launch_nonce: String,
    /// Owner-issued grant digest (hex).
    pub grant_digest: String,
    /// Grant fence generation.
    pub fence_generation: u64,
    /// Re-proven artifact digest (hex).
    pub artifact_digest: String,
    /// Re-proven input digest (hex).
    pub input_digest: String,
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Grant expiry in Unix milliseconds.
    pub expires_at: u64,
    /// Canonical live-authority-epoch JSON bound at admission.
    pub authority_epoch_json: String,
    /// Measured digest of the exact staged envelope bytes this identity was
    /// parsed from (hex).
    pub envelope_digest: Sha256Digest,
    /// Owner-measured installed child image digest (hex): the installation
    /// binding the owner recorded for this delivery.
    pub host_artifact_digest: Sha256Digest,
    /// Publication incarnation read from the owner disposition. `None`
    /// exists only on the pre-claim envelope snapshot and is never accepted
    /// as authority for a new-format delivery.
    pub publication_incarnation: Option<u64>,
    /// Monotonic publication revision read from the owner disposition.
    pub publication_revision: Option<u64>,
}

impl StagedDeliveryIdentity {
    /// Captures the delivery identity from validated material plus the
    /// measured digest of the exact staged envelope bytes it was parsed
    /// from. No field is generated locally: every value is either carried
    /// by the envelope or measured over its bytes.
    #[must_use]
    pub fn from_material(
        material: &ValidatedDispatchMaterial,
        envelope_digest: Sha256Digest,
    ) -> Self {
        Self {
            claim_id: material.claim_id.clone(),
            operation_id: material.operation_id.clone(),
            generation: material.generation,
            launch_nonce: material.launch_nonce.clone(),
            grant_digest: material.grant.grant_digest.as_str().to_owned(),
            fence_generation: material.grant.fence_generation,
            artifact_digest: material.ceilings.artifact_digest.as_str().to_owned(),
            input_digest: material.ceilings.input_digest.as_str().to_owned(),
            admitted_at_unix_ms: material.admitted_at_unix_ms,
            expires_at: material.grant.expires_at,
            authority_epoch_json: material.authority_epoch_json.clone(),
            envelope_digest,
            host_artifact_digest: material.host_artifact_digest.clone(),
            publication_incarnation: None,
            publication_revision: None,
        }
    }
}

/// Exact-generation claim (#2786 step 3): the pre-read envelope identity
/// a claim-first read binds before the payload files are trusted.
/// Rechecked against owner state before reclamation. Same-delivery replay
/// matches this claim and returns the retained result; it never
/// recaptures current files as the old operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryClaim {
    /// Claimed delivery identity.
    identity: StagedDeliveryIdentity,
    /// Exact full owner identity read from the authoritative disposition.
    owner_identity: Option<OwnerDeliveryIdentity>,
    /// Exact owner join binding carried through every child transition.
    join: Option<OwnerJoinBinding>,
    /// Exact host invocation request digest, separate from the envelope
    /// commitment and from the owner's join invocation digest.
    runtime_request_digest: Option<Sha256Digest>,
    /// Owner-issued launch reservation incarnation.
    launch_incarnation: Option<String>,
    /// Child-local first-writer claim incarnation, distinct from operation ID.
    claimant_incarnation: Option<String>,
}

impl DeliveryClaim {
    /// Claims the exact ready generation named by claim-first material.
    /// The material bound only because its envelope snapshot survived the
    /// payload reads unchanged, and `envelope_digest` is measured over those
    /// exact bytes, so this claim is that pre-read identity — never a copy
    /// derived after the fact from whatever the fixed names hold now.
    #[must_use]
    pub fn from_material(
        material: &ValidatedDispatchMaterial,
        envelope_digest: Sha256Digest,
    ) -> Self {
        Self {
            identity: StagedDeliveryIdentity::from_material(material, envelope_digest),
            owner_identity: None,
            join: None,
            runtime_request_digest: None,
            launch_incarnation: None,
            claimant_incarnation: None,
        }
    }

    /// Borrows the claimed identity.
    #[must_use]
    pub fn identity(&self) -> &StagedDeliveryIdentity {
        &self.identity
    }

    /// Releases the claimed identity for served-set retention.
    #[must_use]
    pub fn into_identity(self) -> StagedDeliveryIdentity {
        self.identity
    }
}

/// Claimed reclamation result (#2786 steps 5/6): execution outcome, result
/// publication, owner acknowledgement, and physical reclamation stay
/// separate. Only an identity-matching staged set is reclaimed; a
/// replacement, an already-gone set, or an unreadable set is left untouched
/// with its exact identity preserved. Durable owner-side retirement awaits
/// the kernel publisher half; this child-side transition presents the exact
/// claimed identity against the same staged owner state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimedReclamation {
    /// The claimed generation was reclaimed with per-file outcomes.
    Reclaimed(DeliveryReclamation),
    /// A replacement generation owns the fixed names; left untouched.
    ReplacementPreserved { claimed: StagedDeliveryIdentity },
    /// No staged set remains; nothing to reclaim.
    AlreadyGone { claimed: StagedDeliveryIdentity },
    /// Staged set unreadable or invalid; identity+data retained for recovery.
    RetainedForRecovery { claimed: StagedDeliveryIdentity },
}

/// Per-file reclamation detail for one claimed generation (bounded: exactly
/// the three staged names, payloads first and envelope last so a crash
/// mid-reclaim leaves the envelope identity for recovery).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryReclamation {
    /// Reclaimed delivery identity.
    pub identity: StagedDeliveryIdentity,
    /// Guest artifact file outcome.
    pub artifact: ReclaimOutcome,
    /// Guest input file outcome.
    pub input: ReclaimOutcome,
    /// Material envelope file outcome.
    pub material: ReclaimOutcome,
}

impl DeliveryReclamation {
    /// Whether every claimed file was removed. A partial outcome is a
    /// bounded residual/maintenance obligation, never a primary-result
    /// overwrite.
    #[must_use]
    pub fn fully_reclaimed(&self) -> bool {
        self.artifact.reclaimed() && self.input.reclaimed() && self.material.reclaimed()
    }
}

/// Aside suffix for claim-by-rename reclamation. Distinct from the owner
/// publisher's `.partial` names by construction, so the two sides never
/// share a staging name; the publisher never touches aside names.
const RECLAIM_ASIDE_SUFFIX: &str = ".reclaiming";

/// Aside path for one fixed staging name under the claimed identity: the
/// fixed name is only a locator, and this claimed-identity name is the
/// only path ever deleted. The claim fragment is filename-sanitized and
/// truncated; the process id scopes forensics, never authority.
fn reclaim_aside_path(
    install_dir: &std::path::Path,
    file_name: &str,
    claim: &StagedDeliveryIdentity,
) -> std::path::PathBuf {
    let fragment: String = claim
        .claim_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '_'
            }
        })
        .take(48)
        .collect();
    install_dir.join(format!(
        ".{file_name}.g{:020}.p{:020}.r{:020}.{fragment}.{}{RECLAIM_ASIDE_SUFFIX}",
        claim.generation,
        claim.publication_incarnation.unwrap_or_default(),
        claim.publication_revision.unwrap_or_default(),
        claim.envelope_digest.as_str().get(..16).unwrap_or_default(),
    ))
}

/// Restores aside bytes to their fixed name only when no successor owns
/// it. The hard-link attempt is the atomic restore-if-absent path: it
/// fails when the publisher already staged a successor, so a replacement
/// is never clobbered. When the fixed name holds a successor, the aside
/// bytes remain as recovery evidence and are never discarded. When the
/// fixed name is absent and the filesystem lacks hard links, a plain
/// rename restores: safe on Windows (rename fails over an existing
/// destination), with a narrow clobber window against a concurrent
/// publisher on Unix. That window is the honest residual of filesystems
/// without atomic restore-if-absent.
fn restore_aside_if_absent(aside: &std::path::Path, fixed: &std::path::Path) {
    if std::fs::hard_link(aside, fixed).is_ok() {
        let _ = std::fs::remove_file(aside);
        return;
    }
    if std::fs::symlink_metadata(fixed).is_ok() {
        return;
    }
    let _ = std::fs::rename(aside, fixed);
}

/// Reclaims one fixed staging name by claim: renames the fixed name aside
/// under the claimed-identity name, re-verifies the aside bytes against
/// the claim, and deletes only the verified aside. A fixed name that went
/// missing answers `NotFound`; aside bytes that fail verification are
/// restored when no successor owns the name and answer `Preserved` — a
/// replacement landing between the set pre-check and this removal is
/// never deleted. Deletion targets the claimed aside path only, never a
/// generic current pathname.
#[must_use]
fn reclaim_claimed_file_unlocked(
    install_dir: &std::path::Path,
    file_name: &str,
    claim: &StagedDeliveryIdentity,
    verify: impl FnOnce(&[u8]) -> bool,
) -> ReclaimOutcome {
    let fixed = install_dir.join(file_name);
    let aside = reclaim_aside_path(install_dir, file_name, claim);
    match std::fs::symlink_metadata(&aside) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let Ok(bytes) = read_bounded_regular_file(
                &aside,
                crate::artifact_preflight::MAX_ARTIFACT_BYTES as usize,
            ) else {
                return ReclaimOutcome::Other("aside-unreadable".to_owned());
            };
            if !verify(&bytes) {
                return ReclaimOutcome::Preserved;
            }
            match std::fs::symlink_metadata(&fixed) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return consume_staged_unlocked(&aside);
                }
                Ok(_) => return ReclaimOutcome::Preserved,
                Err(error) => return ReclaimOutcome::Other(error.kind().to_string()),
            }
        }
        Ok(_) => return ReclaimOutcome::Preserved,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return ReclaimOutcome::Other(error.kind().to_string()),
    }
    match std::fs::symlink_metadata(&fixed) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ReclaimOutcome::NotFound;
        }
        Err(error) => return ReclaimOutcome::Other(error.kind().to_string()),
        Ok(metadata) if !metadata.file_type().is_file() => return ReclaimOutcome::Preserved,
        Ok(_) => {}
    }
    match std::fs::rename(&fixed, &aside) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return ReclaimOutcome::NotFound;
        }
        Err(error) if error.raw_os_error() == Some(32) => {
            return ReclaimOutcome::SharingViolation;
        }
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return ReclaimOutcome::AccessDenied;
        }
        Err(error) => return ReclaimOutcome::Other(error.kind().to_string()),
        Ok(()) => {}
    }
    let Ok(bytes) = read_bounded_regular_file(
        &aside,
        crate::artifact_preflight::MAX_ARTIFACT_BYTES as usize,
    ) else {
        restore_aside_if_absent(&aside, &fixed);
        return ReclaimOutcome::Other("aside-unreadable".to_owned());
    };
    if !verify(&bytes) {
        restore_aside_if_absent(&aside, &fixed);
        return ReclaimOutcome::Preserved;
    }
    consume_staged_unlocked(&aside)
}

/// Reclaims exactly the claimed generation from the install directory.
///
/// The set pre-check re-reads the staged set through the claim-first
/// loader and compares the full identity (claim, operation, generation,
/// nonce, grant/fence, digests, window, epoch, material-set digest,
/// installation binding); anything else is a replacement left untouched.
/// Each removal then re-verifies on its own: the fixed name is renamed
/// aside under the claimed-identity name and only aside bytes that still
/// verify against the claim are deleted, so a replacement B landing after
/// the pre-check is restored, never deleted. The envelope check re-hashes
/// the claimed aside bytes against the material-set digest recorded when
/// this claim was taken, so a replacement envelope that merely carries the
/// same typed field values is never deleted either. A matching readable
/// served marker is required before reclaim: absent or uncertain served
/// state leaves the claimed bytes for recovery. No single-owner condition
/// is asserted — the owner publisher stages replacements and retires
/// expired sets concurrently by design — which is exactly why every
/// deletion re-verifies after the move. Residual windows: the Unix restore
/// path without hard-link support (see `restore_aside_if_absent`), and a
/// crash between rename-aside and restore/delete orphaning one aside
/// (removed on the next reclaim; the fixed set heals on the owner's next
/// publication). The sibling kernel half fixes the analogous
/// publisher-side race; coordination is by protocol (aside names never
/// collide with publisher partials).
#[must_use]
pub fn reclaim_claimed_delivery(
    claim: &DeliveryClaim,
    install_dir: &std::path::Path,
) -> ClaimedReclamation {
    match with_installation_root_lock(install_dir, || {
        Ok(reclaim_claimed_delivery_unlocked(claim, install_dir))
    }) {
        Ok(outcome) => outcome,
        Err(_) => ClaimedReclamation::RetainedForRecovery {
            claimed: claim.identity().clone(),
        },
    }
}

fn reclaim_claimed_delivery_unlocked(
    claim: &DeliveryClaim,
    install_dir: &std::path::Path,
) -> ClaimedReclamation {
    let staged = match read_claimed_dispatch_material_unlocked(install_dir) {
        Ok(Some(current)) => current,
        Ok(None) => {
            return ClaimedReclamation::AlreadyGone {
                claimed: claim.identity().clone(),
            };
        }
        Err(_) => {
            return ClaimedReclamation::RetainedForRecovery {
                claimed: claim.identity().clone(),
            };
        }
    };
    if staged.0.identity().envelope_digest != claim.identity().envelope_digest
        || staged.0.identity().claim_id != claim.identity().claim_id
    {
        return ClaimedReclamation::ReplacementPreserved {
            claimed: claim.identity().clone(),
        };
    }
    let identity = claim.identity();
    let disposition_record = match read_owner_disposition_unlocked(install_dir, staged.0.identity())
    {
        Ok(record) => record,
        Err(_) => {
            return ClaimedReclamation::RetainedForRecovery {
                claimed: identity.clone(),
            };
        }
    };
    let owner_identity = disposition_record.disposition.identity().clone();
    if !owner_identity.names(staged.0.identity()) || !owner_identity.names(identity) {
        return ClaimedReclamation::ReplacementPreserved {
            claimed: identity.clone(),
        };
    }
    match read_delivery_publication_unlocked(install_dir, staged.0.identity()) {
        Ok(Some(publication))
            if publication.is_ready() && publication.identity() == &owner_identity => {}
        _ => {
            return ClaimedReclamation::RetainedForRecovery {
                claimed: identity.clone(),
            };
        }
    }
    let join = disposition_record.disposition.join().clone();
    if claim
        .join
        .as_ref()
        .is_some_and(|expected| expected != &join)
    {
        return ClaimedReclamation::RetainedForRecovery {
            claimed: identity.clone(),
        };
    }
    let mut effective_identity = identity.clone();
    effective_identity.publication_incarnation = Some(owner_identity.publication_incarnation);
    effective_identity.publication_revision = Some(owner_identity.publication_revision);
    let mut effective_claim = claim.clone();
    effective_claim.identity = effective_identity.clone();
    effective_claim.owner_identity = Some(owner_identity.clone());
    effective_claim.join = Some(join.clone());
    let disposition = disposition_record.disposition;
    match &disposition {
        OwnerDeliveryDisposition::Acknowledged {
            launch_incarnation,
            claimant_incarnation,
            runtime_request_digest,
            ..
        } => {
            if claim
                .runtime_request_digest
                .as_ref()
                .is_some_and(|current| current.as_str() != runtime_request_digest)
                || claim
                    .launch_incarnation
                    .as_ref()
                    .is_some_and(|current| current != launch_incarnation)
                || claim
                    .claimant_incarnation
                    .as_ref()
                    .is_some_and(|current| current != claimant_incarnation)
            {
                return ClaimedReclamation::RetainedForRecovery {
                    claimed: identity.clone(),
                };
            }
            effective_claim = match bind_claim_to_owner(
                &effective_claim,
                &owner_identity,
                &join,
                runtime_request_digest,
                launch_incarnation,
                claimant_incarnation,
            ) {
                Ok(bound) => bound,
                Err(_) => {
                    return ClaimedReclamation::RetainedForRecovery {
                        claimed: identity.clone(),
                    };
                }
            };
            if !disposition.is_claimed_by(&effective_claim)
                || !read_served_result_unlocked(install_dir, &effective_claim)
                    .is_ok_and(|result| result.is_some_and(|record| record.names(&effective_claim)))
            {
                return ClaimedReclamation::RetainedForRecovery {
                    claimed: identity.clone(),
                };
            }
        }
        OwnerDeliveryDisposition::RetiredNoEffect { .. } => {}
        _ => {
            return ClaimedReclamation::RetainedForRecovery {
                claimed: identity.clone(),
            };
        }
    }
    let artifact = reclaim_claimed_file_unlocked(
        install_dir,
        WASM_HOST_GUEST_ARTIFACT_FILE_NAME,
        &effective_identity,
        |bytes| {
            Sha256Digest::of_bytes(bytes).as_str() == effective_identity.artifact_digest.as_str()
        },
    );
    if matches!(&artifact, ReclaimOutcome::Preserved) {
        return ClaimedReclamation::ReplacementPreserved {
            claimed: effective_identity,
        };
    }
    if !matches!(
        &artifact,
        ReclaimOutcome::Reclaimed | ReclaimOutcome::NotFound
    ) {
        return ClaimedReclamation::Reclaimed(DeliveryReclamation {
            identity: effective_identity,
            artifact,
            input: ReclaimOutcome::Other("not-attempted-after-artifact-residual".to_owned()),
            material: ReclaimOutcome::Other("retained-for-recovery".to_owned()),
        });
    }
    let input = reclaim_claimed_file_unlocked(
        install_dir,
        WASM_HOST_GUEST_INPUT_FILE_NAME,
        &effective_identity,
        |bytes| Sha256Digest::of_bytes(bytes).as_str() == effective_identity.input_digest.as_str(),
    );
    if matches!(&input, ReclaimOutcome::Preserved) {
        return ClaimedReclamation::ReplacementPreserved {
            claimed: effective_identity,
        };
    }
    if !matches!(&input, ReclaimOutcome::Reclaimed | ReclaimOutcome::NotFound) {
        return ClaimedReclamation::Reclaimed(DeliveryReclamation {
            identity: effective_identity,
            artifact,
            input,
            material: ReclaimOutcome::Other("retained-for-recovery".to_owned()),
        });
    }
    let material = reclaim_claimed_file_unlocked(
        install_dir,
        WASM_HOST_MATERIAL_FILE_NAME,
        &effective_identity,
        |bytes| Sha256Digest::of_bytes(bytes) == effective_identity.envelope_digest,
    );
    // A preserved envelope or payload means a replacement owns the fixed
    // names now. Earlier exact payload removals are represented in the result;
    // the owner slot retains the complete recovery identity.
    if matches!(&material, ReclaimOutcome::Preserved) {
        return ClaimedReclamation::ReplacementPreserved {
            claimed: effective_identity,
        };
    }
    ClaimedReclamation::Reclaimed(DeliveryReclamation {
        identity: effective_identity,
        artifact,
        input,
        material,
    })
}

/// Requires one owner-recorded field to be a well-formed lowercase digest.
/// Shape only: the owner measured these values, so nothing is recomputed
/// here and no digest is trusted for a decision it did not record.
fn require_owner_digest(value: &str, field: &'static str) -> Result<(), MaterialError> {
    hex_digest(value, field).map(|_digest| ())
}

/// Owner-issued delivery-set identity as the owner recorded it in a
/// generation slot marker (#2786 steps 1/3/7). Wire mirror of
/// `eliot_kernel_service::WasmDeliveryIdentity`, field for field and
/// version for version; the owner publisher stays the sole issuer and
/// this struct never generates a value. Marker bodies and owner failure
/// reasons are never echoed to a caller.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerDeliveryIdentity {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Claiming generation (non-zero).
    pub generation: u64,
    /// Claim-bound launch nonce.
    pub launch_nonce: String,
    /// Owner-issued grant digest (hex).
    pub grant_digest: String,
    /// Grant fence generation.
    pub fence_generation: u64,
    /// Re-proven artifact digest (hex).
    pub artifact_digest: String,
    /// Re-proven input digest (hex).
    pub input_digest: String,
    /// Durable admission time in Unix milliseconds.
    pub admitted_at_unix_ms: u64,
    /// Grant expiry in Unix milliseconds.
    pub expires_at: u64,
    /// Canonical live-authority-epoch JSON bound at admission.
    pub authority_epoch_json: String,
    /// Delivery-identity wire version the owner issued.
    pub delivery_version: u16,
    /// Owner-measured material-set digest of the staged envelope (hex).
    pub envelope_digest: String,
    /// Owner-measured installed child image digest (hex).
    pub host_artifact_digest: String,
    /// Owner publication incarnation.
    pub publication_incarnation: u64,
    /// Owner publication revision.
    pub publication_revision: u64,
}

impl OwnerDeliveryIdentity {
    /// Whether this owner record names exactly the claimed delivery.
    /// Compared field-for-field against the values the owner recorded,
    /// never recomputed from what the child happens to hold: a matching
    /// pathname or a well-formed token is not a match.
    #[must_use]
    pub fn names(&self, claim: &StagedDeliveryIdentity) -> bool {
        self.claim_id == claim.claim_id
            && self.operation_id == claim.operation_id
            && self.generation == claim.generation
            && self.launch_nonce == claim.launch_nonce
            && self.grant_digest == claim.grant_digest
            && self.fence_generation == claim.fence_generation
            && self.artifact_digest == claim.artifact_digest
            && self.input_digest == claim.input_digest
            && self.admitted_at_unix_ms == claim.admitted_at_unix_ms
            && self.expires_at == claim.expires_at
            && self.authority_epoch_json == claim.authority_epoch_json
            && self.envelope_digest == claim.envelope_digest.as_str()
            && self.host_artifact_digest == claim.host_artifact_digest.as_str()
            && claim.publication_incarnation.map_or(true, |incarnation| {
                incarnation == self.publication_incarnation
            })
            && claim
                .publication_revision
                .map_or(true, |revision| revision == self.publication_revision)
    }

    /// Rejects a record the owner could not have issued under the mirrored
    /// version: an unknown identity version, a zero generation or
    /// publication revision, an empty window, or a malformed digest. A
    /// record that fails here is never reinterpreted under this version.
    ///
    /// # Errors
    ///
    /// Returns [`MaterialError`] when any field fails shape validation.
    fn validate(&self) -> Result<(), MaterialError> {
        if self.delivery_version != WASM_DELIVERY_IDENTITY_VERSION {
            return Err(MaterialError::Malformed);
        }
        require_nonblank(&self.claim_id, "owner-delivery-claim-id")?;
        require_nonblank(&self.operation_id, "owner-delivery-operation-id")?;
        require_nonblank(&self.launch_nonce, "owner-delivery-launch-nonce")?;
        require_nonblank(&self.authority_epoch_json, "owner-delivery-authority-epoch")?;
        if self.generation == 0
            || self.publication_incarnation == 0
            || self.publication_revision == 0
            || self.admitted_at_unix_ms == 0
            || self.expires_at <= self.admitted_at_unix_ms
        {
            return Err(MaterialError::Malformed);
        }
        require_owner_digest(&self.grant_digest, "owner-delivery-grant-digest")?;
        require_owner_digest(&self.artifact_digest, "owner-delivery-artifact-digest")?;
        require_owner_digest(&self.input_digest, "owner-delivery-input-digest")?;
        require_owner_digest(&self.envelope_digest, "owner-delivery-envelope-digest")?;
        require_owner_digest(
            &self.host_artifact_digest,
            "owner-delivery-host-artifact-digest",
        )?;
        Ok(())
    }
}

/// Owner publication state for one generation slot (#2786 steps 2/3/7):
/// wire mirror of `eliot_kernel_service::WasmPublicationState`. The owner
/// writes `PENDING` before staging payloads, the ready marker last, and
/// `FAILED` with recovery evidence when staging fails, so a slot without a
/// ready marker is never a complete set. The failure reason is retained
/// here for shape only and never echoed.
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub enum OwnerPublicationState {
    /// Publication started; the immutable set is not yet complete.
    Pending {
        /// Publishing delivery identity.
        identity: OwnerDeliveryIdentity,
    },
    /// Immutable slot set complete under this identity.
    Ready {
        /// Published delivery identity.
        identity: OwnerDeliveryIdentity,
    },
    /// Publication failed; the retained identity is recovery evidence.
    Failed {
        /// Failed delivery identity.
        identity: OwnerDeliveryIdentity,
        /// Stable owner failure reason. Parsed for shape and deliberately
        /// not retained: the reason is owner recovery evidence the child
        /// never interprets and never echoes.
        #[serde(rename = "reason")]
        _reason: String,
    },
}

impl OwnerPublicationState {
    /// Borrows the identity this state was recorded under.
    #[must_use]
    pub fn identity(&self) -> &OwnerDeliveryIdentity {
        match self {
            Self::Pending { identity }
            | Self::Ready { identity }
            | Self::Failed { identity, .. } => identity,
        }
    }

    /// Stable owner state code, mirrored from the publisher.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Pending { .. } => "DELIVERY_PENDING",
            Self::Ready { .. } => "DELIVERY_READY",
            Self::Failed { .. } => "DELIVERY_FAILED",
        }
    }

    /// Whether the owner recorded the immutable set complete.
    #[must_use]
    pub const fn is_ready(&self) -> bool {
        matches!(self, Self::Ready { .. })
    }

    /// Whether this owner state names exactly the claimed delivery.
    #[must_use]
    pub fn names(&self, claim: &StagedDeliveryIdentity) -> bool {
        self.identity().names(claim)
    }

    /// Validates the recorded identity under the mirrored version.
    ///
    /// # Errors
    ///
    /// Returns [`MaterialError`] when the recorded identity is malformed
    /// or carries an unsupported version.
    fn validate(&self) -> Result<(), MaterialError> {
        self.identity().validate()
    }
}

/// Owner-issued join binding mirrored from `WasmJoinGate`. The child reads
/// and preserves these exact values from the slot disposition; it never
/// reconstructs authority or substitutes a current request for the record.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerJoinBinding {
    /// Admitted claim identity.
    pub claim_id: String,
    /// Admitted operation identity.
    pub operation_id: String,
    /// Child-identical authority identity string.
    pub authority_id: String,
    /// Opaque owner-issued grant digest (hex).
    pub grant_digest: String,
    /// Owner-issued invocation commitment for the join table.
    pub invocation_digest: String,
    /// Grant expiry bounding the join window (Unix milliseconds).
    pub expires_at: u64,
}

impl OwnerJoinBinding {
    fn validate(&self, identity: &OwnerDeliveryIdentity) -> Result<(), MaterialError> {
        if self.claim_id != identity.claim_id
            || self.operation_id != identity.operation_id
            || self.grant_digest != identity.grant_digest
            || self.expires_at != identity.expires_at
        {
            return Err(MaterialError::Malformed);
        }
        require_nonblank(&self.authority_id, "owner-join-authority-id")?;
        require_owner_digest(&self.grant_digest, "owner-join-grant-digest")?;
        require_nonblank(&self.invocation_digest, "owner-join-invocation-digest")?;
        Ok(())
    }
}

/// Versioned owner/child claim state stored beside one immutable generation.
/// Every variant repeats the complete original owner identity, join binding,
/// and canonical-envelope commitment so a torn or substituted transition is
/// refused rather than treated as a legacy delivery.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum OwnerDeliveryDisposition {
    /// Publication complete and available for exactly one kernel launch.
    Ready {
        identity: OwnerDeliveryIdentity,
        join: OwnerJoinBinding,
        request_commitment: String,
    },
    /// Kernel has reserved the exact launch before starting the child.
    LaunchReserved {
        identity: OwnerDeliveryIdentity,
        join: OwnerJoinBinding,
        request_commitment: String,
        launch_incarnation: String,
    },
    /// Child has atomically claimed the reserved launch before guest effects.
    InFlight {
        identity: OwnerDeliveryIdentity,
        join: OwnerJoinBinding,
        request_commitment: String,
        launch_incarnation: String,
        claimant_incarnation: String,
        runtime_request_digest: String,
    },
    /// Exact result bytes were retained before they could be exposed.
    TerminalUnacknowledged {
        identity: OwnerDeliveryIdentity,
        join: OwnerJoinBinding,
        request_commitment: String,
        launch_incarnation: String,
        claimant_incarnation: String,
        runtime_request_digest: String,
        result_digest: String,
        result_sequence: u64,
    },
    /// Owner has recorded exact receiver acknowledgement and settled duties.
    Acknowledged {
        identity: OwnerDeliveryIdentity,
        join: OwnerJoinBinding,
        request_commitment: String,
        launch_incarnation: String,
        claimant_incarnation: String,
        runtime_request_digest: String,
        result_digest: String,
        result_sequence: u64,
        receiver_ack_identity: String,
        receiver_ack_digest: String,
        receiver_ack_sequence: u64,
        process_settlement_digest: String,
        material_settlement_digest: String,
    },
    /// Owner proved that this exact reservation had no guest effect.
    RetiredNoEffect {
        identity: OwnerDeliveryIdentity,
        join: OwnerJoinBinding,
        request_commitment: String,
        retirement_digest: String,
    },
}

impl OwnerDeliveryDisposition {
    fn identity(&self) -> &OwnerDeliveryIdentity {
        match self {
            Self::Ready { identity, .. }
            | Self::LaunchReserved { identity, .. }
            | Self::InFlight { identity, .. }
            | Self::TerminalUnacknowledged { identity, .. }
            | Self::Acknowledged { identity, .. }
            | Self::RetiredNoEffect { identity, .. } => identity,
        }
    }

    fn join(&self) -> &OwnerJoinBinding {
        match self {
            Self::Ready { join, .. }
            | Self::LaunchReserved { join, .. }
            | Self::InFlight { join, .. }
            | Self::TerminalUnacknowledged { join, .. }
            | Self::Acknowledged { join, .. }
            | Self::RetiredNoEffect { join, .. } => join,
        }
    }

    fn request_commitment(&self) -> &str {
        match self {
            Self::Ready {
                request_commitment, ..
            }
            | Self::LaunchReserved {
                request_commitment, ..
            }
            | Self::InFlight {
                request_commitment, ..
            }
            | Self::TerminalUnacknowledged {
                request_commitment, ..
            }
            | Self::Acknowledged {
                request_commitment, ..
            }
            | Self::RetiredNoEffect {
                request_commitment, ..
            } => request_commitment,
        }
    }

    fn validate(&self) -> Result<(), MaterialError> {
        self.identity().validate()?;
        self.join().validate(self.identity())?;
        if self.request_commitment() != self.identity().envelope_digest {
            return Err(MaterialError::Malformed);
        }
        match self {
            Self::Ready { .. } => {}
            Self::LaunchReserved {
                launch_incarnation, ..
            } => require_nonblank(launch_incarnation, "launch-incarnation")?,
            Self::InFlight {
                launch_incarnation,
                claimant_incarnation,
                runtime_request_digest,
                ..
            }
            | Self::TerminalUnacknowledged {
                launch_incarnation,
                claimant_incarnation,
                runtime_request_digest,
                ..
            }
            | Self::Acknowledged {
                launch_incarnation,
                claimant_incarnation,
                runtime_request_digest,
                ..
            } => {
                require_nonblank(launch_incarnation, "launch-incarnation")?;
                require_nonblank(claimant_incarnation, "claimant-incarnation")?;
                require_owner_digest(runtime_request_digest, "runtime-request-digest")?;
                match self {
                    Self::TerminalUnacknowledged {
                        result_digest,
                        result_sequence,
                        ..
                    }
                    | Self::Acknowledged {
                        result_digest,
                        result_sequence,
                        ..
                    } => {
                        require_owner_digest(result_digest, "delivery-result-digest")?;
                        // Sequence zero is valid and names the first result event.
                        let _sequence = result_sequence;
                    }
                    _ => {}
                }
                if let Self::Acknowledged {
                    receiver_ack_identity,
                    receiver_ack_digest,
                    receiver_ack_sequence,
                    process_settlement_digest,
                    material_settlement_digest,
                    ..
                } = self
                {
                    require_nonblank(receiver_ack_identity, "receiver-ack-identity")?;
                    require_owner_digest(receiver_ack_digest, "receiver-ack-digest")?;
                    require_owner_digest(process_settlement_digest, "process-settlement-digest")?;
                    require_owner_digest(material_settlement_digest, "material-settlement-digest")?;
                    // Sequence zero is valid for the receiver's first ACK.
                    let _sequence = receiver_ack_sequence;
                }
            }
            Self::RetiredNoEffect {
                retirement_digest, ..
            } => require_owner_digest(retirement_digest, "delivery-retirement-digest")?,
        }
        Ok(())
    }

    fn is_claimed_by(&self, claim: &DeliveryClaim) -> bool {
        let exact_common_binding = claim
            .owner_identity
            .as_ref()
            .is_some_and(|identity| identity == self.identity())
            && claim.join.as_ref().is_some_and(|join| join == self.join())
            && self.request_commitment() == claim.identity.envelope_digest.as_str();
        match self {
            Self::InFlight {
                launch_incarnation,
                claimant_incarnation,
                runtime_request_digest,
                ..
            }
            | Self::TerminalUnacknowledged {
                launch_incarnation,
                claimant_incarnation,
                runtime_request_digest,
                ..
            }
            | Self::Acknowledged {
                launch_incarnation,
                claimant_incarnation,
                runtime_request_digest,
                ..
            } => {
                exact_common_binding
                    && Some(launch_incarnation) == claim.launch_incarnation.as_ref()
                    && Some(claimant_incarnation) == claim.claimant_incarnation.as_ref()
                    && Some(runtime_request_digest.as_str())
                        == claim
                            .runtime_request_digest
                            .as_ref()
                            .map(Sha256Digest::as_str)
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerDeliveryDispositionRecord {
    record_version: u16,
    disposition: OwnerDeliveryDisposition,
}

impl OwnerDeliveryDispositionRecord {
    fn validate(&self) -> Result<(), MaterialError> {
        if self.record_version != 1 {
            return Err(MaterialError::Malformed);
        }
        self.disposition.validate()
    }
}

/// Immutable slot locator for one claimed delivery, derived exactly as the
/// owner publisher derives it: zero-padded generation plus the leading
/// material-set digest. The directory is only a locator; the identity in
/// the marker is what authorizes anything, and the digest used here comes
/// from the claim rather than from any owner input.
fn delivery_slot_dir(
    install_dir: &std::path::Path,
    claim: &StagedDeliveryIdentity,
) -> std::path::PathBuf {
    let digest = claim.envelope_digest.as_str();
    let prefix = digest.get(..16).unwrap_or(digest);
    install_dir
        .join(WASM_DELIVERY_SLOT_DIR_NAME)
        .join(format!("{:020}-{prefix}", claim.generation))
}

const OWNER_DISPOSITION_MAX_BYTES: usize = 32 * 1024;

fn read_bounded_regular_file(
    path: &std::path::Path,
    max_bytes: usize,
) -> Result<Vec<u8>, MaterialError> {
    use std::io::Read;

    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            MaterialError::Missing
        } else {
            MaterialError::Unreadable(error.kind().to_string())
        }
    })?;
    if !metadata.file_type().is_file() {
        return Err(MaterialError::Unreadable("not-regular-file".to_owned()));
    }
    if metadata.len() > max_bytes as u64 {
        return Err(MaterialError::TooLarge);
    }
    let file = std::fs::File::open(path)
        .map_err(|error| MaterialError::Unreadable(error.kind().to_string()))?;
    let mut bounded = file.take((max_bytes + 1) as u64);
    let mut bytes = Vec::new();
    bounded
        .read_to_end(&mut bytes)
        .map_err(|error| MaterialError::Unreadable(error.kind().to_string()))?;
    if bytes.len() > max_bytes {
        return Err(MaterialError::TooLarge);
    }
    Ok(bytes)
}

/// Atomically replaces one fixed protocol record. A leftover process-scoped
/// partial is retained as recovery evidence and blocks another write; it is
/// never deleted merely because it is old or has the expected name.
fn write_atomic_locked(
    target: &std::path::Path,
    bytes: &[u8],
    max_bytes: usize,
) -> std::io::Result<()> {
    use std::io::Write;

    if bytes.len() > max_bytes {
        return Err(std::io::Error::other("record-too-large"));
    }
    let file_name = target
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| std::io::Error::other("record-name"))?;
    let partial = target.with_file_name(format!(".{file_name}.partial"));
    match std::fs::symlink_metadata(&partial) {
        Ok(_) => return Err(std::io::Error::other("record-partial-retained")),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    {
        eliot_windows_ipc::atomic_replace_file(&partial, target)
    }
    #[cfg(not(windows))]
    {
        Err(std::io::Error::other("atomic-replace-unavailable"))
    }
}

fn read_delivery_publication_unlocked(
    install_dir: &std::path::Path,
    claim: &StagedDeliveryIdentity,
) -> Result<Option<OwnerPublicationState>, MaterialError> {
    let slot = delivery_slot_dir(install_dir, claim);
    for file_name in [
        WASM_DELIVERY_READY_FILE_NAME,
        WASM_DELIVERY_FAILED_FILE_NAME,
        WASM_DELIVERY_PENDING_FILE_NAME,
    ] {
        let bytes = match read_staged_bytes(&slot.join(file_name)) {
            Err(MaterialError::Missing) => continue,
            Err(error) => return Err(error),
            Ok(bytes) => bytes,
        };
        let state: OwnerPublicationState =
            serde_json::from_slice(&bytes).map_err(|_| MaterialError::Malformed)?;
        let expected = matches!(
            (&state, file_name),
            (
                OwnerPublicationState::Ready { .. },
                WASM_DELIVERY_READY_FILE_NAME
            ) | (
                OwnerPublicationState::Failed { .. },
                WASM_DELIVERY_FAILED_FILE_NAME
            ) | (
                OwnerPublicationState::Pending { .. },
                WASM_DELIVERY_PENDING_FILE_NAME
            )
        );
        if !expected {
            return Err(MaterialError::Malformed);
        }
        state.validate()?;
        return Ok(Some(state));
    }
    Ok(None)
}

fn read_owner_disposition_unlocked(
    install_dir: &std::path::Path,
    claim: &StagedDeliveryIdentity,
) -> Result<OwnerDeliveryDispositionRecord, MaterialError> {
    let bytes = read_bounded_regular_file(
        &delivery_slot_dir(install_dir, claim).join(WASM_DELIVERY_DISPOSITION_FILE_NAME),
        OWNER_DISPOSITION_MAX_BYTES,
    )?;
    let record: OwnerDeliveryDispositionRecord =
        serde_json::from_slice(&bytes).map_err(|_| MaterialError::Malformed)?;
    record.validate()?;
    if !record.disposition.identity().names(claim) {
        return Err(MaterialError::DigestMismatch);
    }
    Ok(record)
}

fn write_owner_disposition_unlocked(
    install_dir: &std::path::Path,
    claim: &StagedDeliveryIdentity,
    record: &OwnerDeliveryDispositionRecord,
) -> std::io::Result<()> {
    let bytes =
        serde_json::to_vec(record).map_err(|error| std::io::Error::other(error.to_string()))?;
    write_atomic_locked(
        &delivery_slot_dir(install_dir, claim).join(WASM_DELIVERY_DISPOSITION_FILE_NAME),
        &bytes,
        OWNER_DISPOSITION_MAX_BYTES,
    )
}

/// Exclusive outcome of the child-side launch claim. An unavailable or
/// conflicting state never authorizes guest effects; replay outcomes carry
/// the exact stored claim so only its result may be considered.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryClaimOutcome {
    /// This process atomically changed the owner reservation to InFlight.
    Acquired(DeliveryClaim),
    /// A prior claimant owns this exact delivery but has no terminal result.
    ExistingInFlight(DeliveryClaim),
    /// An exact terminal result is retained for replay, pending owner ACK.
    RetainedResult(DeliveryClaim),
    /// Current fixed names or authoritative owner state identify another
    /// delivery or a state that cannot be newly claimed.
    Conflict,
    /// Required state was missing, malformed, unreadable, or unbounded.
    Unavailable,
}

fn launch_incarnation(identity: &OwnerDeliveryIdentity) -> String {
    format!(
        "wasm-delivery:{}:{}:{}:{}",
        identity.generation,
        identity.envelope_digest,
        identity.publication_incarnation,
        identity.publication_revision
    )
}

fn claimant_incarnation() -> Option<String> {
    let sequence = NEXT_HOST_CLAIMANT_INCARNATION.fetch_add(1, Ordering::Relaxed);
    (sequence != 0 && sequence != u64::MAX)
        .then(|| format!("host:{}:{sequence}", std::process::id()))
}

fn bind_claim_to_owner(
    staged: &DeliveryClaim,
    identity: &OwnerDeliveryIdentity,
    join: &OwnerJoinBinding,
    runtime_request_digest: &str,
    launch: &str,
    claimant: &str,
) -> Result<DeliveryClaim, MaterialError> {
    let mut bound = staged.clone();
    bound.identity.publication_incarnation = Some(identity.publication_incarnation);
    bound.identity.publication_revision = Some(identity.publication_revision);
    bound.owner_identity = Some(identity.clone());
    bound.join = Some(join.clone());
    bound.runtime_request_digest = Some(hex_digest(
        runtime_request_digest,
        "runtime-request-digest",
    )?);
    bound.launch_incarnation = Some(launch.to_owned());
    bound.claimant_incarnation = Some(claimant.to_owned());
    Ok(bound)
}

/// Revalidates the fixed staged set and atomically claims only a matching
/// owner `LaunchReserved` disposition. This bounded local transaction holds
/// the shared installation-root mutex across reread, full comparison, and
/// the `InFlight` write. It never runs guest code or waits on another service.
pub fn acquire_delivery_claim(
    install_dir: &std::path::Path,
    staged: &DeliveryClaim,
    runtime_request_digest: Sha256Digest,
    now_ms: u64,
) -> Result<DeliveryClaimOutcome, MaterialError> {
    with_installation_root_lock(install_dir, || {
        let Some((current, _material)) = read_claimed_dispatch_material_unlocked(install_dir)?
        else {
            return Ok(DeliveryClaimOutcome::Conflict);
        };
        if current.identity != staged.identity {
            return Ok(DeliveryClaimOutcome::Conflict);
        }
        let Some(publication) = read_delivery_publication_unlocked(install_dir, &staged.identity)?
        else {
            return Ok(DeliveryClaimOutcome::Unavailable);
        };
        if !publication.is_ready() || !publication.names(&staged.identity) {
            return Ok(DeliveryClaimOutcome::Conflict);
        }
        let mut record = match read_owner_disposition_unlocked(install_dir, &staged.identity) {
            Ok(record) => record,
            Err(MaterialError::DigestMismatch) => return Ok(DeliveryClaimOutcome::Conflict),
            Err(_) => return Ok(DeliveryClaimOutcome::Unavailable),
        };
        if record.disposition.identity() != publication.identity()
            || !record.disposition.identity().names(&staged.identity)
            || record.disposition.request_commitment() != staged.identity.envelope_digest.as_str()
        {
            return Ok(DeliveryClaimOutcome::Conflict);
        }
        let identity = record.disposition.identity().clone();
        let join = record.disposition.join().clone();
        let expected_launch = launch_incarnation(&identity);
        match &record.disposition {
            OwnerDeliveryDisposition::LaunchReserved {
                launch_incarnation: reserved,
                ..
            } => {
                if reserved != &expected_launch || now_ms >= identity.expires_at {
                    return Ok(DeliveryClaimOutcome::Conflict);
                }
                let Some(claimant) = claimant_incarnation() else {
                    return Ok(DeliveryClaimOutcome::Unavailable);
                };
                record.disposition = OwnerDeliveryDisposition::InFlight {
                    identity: identity.clone(),
                    join: join.clone(),
                    request_commitment: identity.envelope_digest.clone(),
                    launch_incarnation: expected_launch.clone(),
                    claimant_incarnation: claimant.clone(),
                    runtime_request_digest: runtime_request_digest.as_str().to_owned(),
                };
                write_owner_disposition_unlocked(install_dir, &staged.identity, &record)
                    .map_err(|error| MaterialError::Unreadable(error.kind().to_string()))?;
                Ok(DeliveryClaimOutcome::Acquired(bind_claim_to_owner(
                    staged,
                    &identity,
                    &join,
                    runtime_request_digest.as_str(),
                    &expected_launch,
                    &claimant,
                )?))
            }
            OwnerDeliveryDisposition::InFlight {
                launch_incarnation: existing_launch,
                claimant_incarnation: existing_claimant,
                runtime_request_digest: existing_request,
                ..
            } => {
                if existing_launch != &expected_launch
                    || existing_request != runtime_request_digest.as_str()
                {
                    return Ok(DeliveryClaimOutcome::Conflict);
                }
                Ok(DeliveryClaimOutcome::ExistingInFlight(bind_claim_to_owner(
                    staged,
                    &identity,
                    &join,
                    existing_request,
                    existing_launch,
                    existing_claimant,
                )?))
            }
            OwnerDeliveryDisposition::TerminalUnacknowledged {
                launch_incarnation: existing_launch,
                claimant_incarnation: existing_claimant,
                runtime_request_digest: existing_request,
                ..
            }
            | OwnerDeliveryDisposition::Acknowledged {
                launch_incarnation: existing_launch,
                claimant_incarnation: existing_claimant,
                runtime_request_digest: existing_request,
                ..
            } => {
                if existing_launch != &expected_launch
                    || existing_request != runtime_request_digest.as_str()
                {
                    return Ok(DeliveryClaimOutcome::Conflict);
                }
                Ok(DeliveryClaimOutcome::RetainedResult(bind_claim_to_owner(
                    staged,
                    &identity,
                    &join,
                    existing_request,
                    existing_launch,
                    existing_claimant,
                )?))
            }
            OwnerDeliveryDisposition::Ready { .. }
            | OwnerDeliveryDisposition::RetiredNoEffect { .. } => {
                Ok(DeliveryClaimOutcome::Conflict)
            }
        }
    })
}

/// Reads the owner publication state for the claimed generation's slot.
///
/// Restart discovers owner publication state here, not arbitrary files
/// alone: the marker is looked up by the claim's own generation and
/// material-set digest, and a marker naming another delivery is reported
/// as such rather than treated as this claim's evidence. The owner's
/// precedence is mirrored exactly — ready, then failed, then pending — so a
/// slot that both failed and kept its pending marker reports the failure.
/// A slot with no parsable marker is not a state at all, never a complete
/// set.
///
/// `Ok(None)` means the owner recorded no publication for this delivery.
/// It is diagnostic absence only and never authorizes legacy execution; the
/// caller must use [`acquire_delivery_claim`] and fail closed when its
/// disposition is missing.
///
/// # Errors
///
/// Returns [`MaterialError`] when a marker is oversized, unreadable,
/// malformed, or records an identity the owner could not have issued
/// under the mirrored version.
pub fn read_delivery_publication(
    install_dir: &std::path::Path,
    claim: &StagedDeliveryIdentity,
) -> Result<Option<OwnerPublicationState>, MaterialError> {
    with_installation_root_lock(install_dir, || {
        read_delivery_publication_unlocked(install_dir, claim)
    })
}

/// Restart/discovery classification (#2786 step 7): `Replay` is a fail-closed
/// refusal based on prior local evidence. New-format execution authority
/// comes only from [`acquire_delivery_claim`] reading the owner disposition
/// under the installation-root lock. A missing new-format record cannot be
/// reinterpreted as legacy authorization; the compatibility state below is
/// retained for callers that report legacy evidence but must not execute it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StagedDeliveryState {
    /// Staged set matches served state: replay, no second guest effect.
    Replay { identity: StagedDeliveryIdentity },
    /// Legacy fixed-name set without a new-format owner claim; refuse execution.
    LegacyV1FixedName { identity: StagedDeliveryIdentity },
}

/// Classifies prior compatibility evidence. A missing or mismatched legacy
/// marker still refuses execution: only an exact owner claim can authorize a
/// new-format delivery. Same identity or spent grant evidence remains a
/// replay of one-shot authority.
///
/// The classification reads the claim taken before the payload bytes were
/// trusted, never a re-derivation from whatever the fixed names hold at
/// classification time.
#[must_use]
pub fn classify_staged_delivery(
    identity: &StagedDeliveryIdentity,
    served: &[StagedDeliveryIdentity],
    marker: Option<&ServedDeliveryMarker>,
    inflight: Option<&InFlightDeliveryMarker>,
) -> StagedDeliveryState {
    if served.contains(identity)
        || served
            .iter()
            .any(|prior| prior.grant_digest == identity.grant_digest)
    {
        return StagedDeliveryState::Replay {
            identity: identity.clone(),
        };
    }
    if let Some(mark) = inflight
        && (mark.names(identity) || mark.grant_digest == identity.grant_digest)
    {
        return StagedDeliveryState::Replay {
            identity: identity.clone(),
        };
    }
    match marker {
        Some(mark) if mark.names(identity) => StagedDeliveryState::Replay {
            identity: identity.clone(),
        },
        Some(mark) if mark.grant_digest == identity.grant_digest => StagedDeliveryState::Replay {
            identity: identity.clone(),
        },
        _ => StagedDeliveryState::Replay {
            identity: identity.clone(),
        },
    }
}

/// Legacy served-marker projection. Its partial identity can only cause a
/// conservative replay refusal; it is not ownership or reclamation evidence.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServedDeliveryMarker {
    /// Served operation identity.
    pub operation_id: String,
    /// Served generation.
    pub generation: u64,
    /// Served claim identity.
    pub claim_id: String,
    /// Served grant digest (hex).
    pub grant_digest: String,
    /// Wall-clock milliseconds when the marker was written.
    pub served_at_unix_ms: u64,
}

impl ServedDeliveryMarker {
    /// Captures the served record for one claimed identity.
    #[must_use]
    pub fn from_identity(identity: &StagedDeliveryIdentity, served_at_unix_ms: u64) -> Self {
        Self {
            operation_id: identity.operation_id.clone(),
            generation: identity.generation,
            claim_id: identity.claim_id.clone(),
            grant_digest: identity.grant_digest.clone(),
            served_at_unix_ms,
        }
    }

    /// Whether this marker names exactly the staged identity.
    #[must_use]
    pub fn names(&self, identity: &StagedDeliveryIdentity) -> bool {
        self.operation_id == identity.operation_id
            && self.generation == identity.generation
            && self.claim_id == identity.claim_id
            && self.grant_digest == identity.grant_digest
    }
}

/// Reads the durable served marker, if any. Only an absent marker answers
/// `Ok(None)`; read failures, oversize files, and malformed records fail
/// closed so callers cannot treat uncertain served state as a fresh delivery.
/// The bounded read accepts a few hundred bytes for a legitimate marker.
pub fn read_served_marker(
    install_dir: &std::path::Path,
) -> Result<Option<ServedDeliveryMarker>, MaterialError> {
    with_installation_root_lock(install_dir, || read_served_marker_unlocked(install_dir))
}

fn read_served_marker_unlocked(
    install_dir: &std::path::Path,
) -> Result<Option<ServedDeliveryMarker>, MaterialError> {
    const MAX_BYTES: usize = 4096;

    let path = install_dir.join(WASM_HOST_SERVED_FILE_NAME);
    let bytes = match read_bounded_regular_file(&path, MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(MaterialError::Missing) => return Ok(None),
        Err(error) => return Err(error),
    };
    let marker: ServedDeliveryMarker =
        serde_json::from_slice(&bytes).map_err(|_| MaterialError::Malformed)?;
    if marker.operation_id.trim().is_empty()
        || marker.claim_id.trim().is_empty()
        || marker.generation == 0
    {
        return Err(MaterialError::Malformed);
    }
    hex_digest(&marker.grant_digest, "served-marker-grant-digest")?;
    Ok(Some(marker))
}

/// A fixed legacy marker cannot represent the publication incarnation and
/// exact envelope commitment, so new-format served state is written only to
/// the owner slot disposition and result record.
pub fn write_served_marker(
    _install_dir: &std::path::Path,
    _identity: &StagedDeliveryIdentity,
    _served_at_unix_ms: u64,
) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "served-marker-replaced-by-owner-disposition",
    ))
}

/// Legacy in-flight marker projection. It lacks the complete publication
/// identity and cannot authorize or settle a new-format claim.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InFlightDeliveryMarker {
    /// Claimed operation identity.
    pub operation_id: String,
    /// Claimed generation.
    pub generation: u64,
    /// Claimed claim identity.
    pub claim_id: String,
    /// Claimed grant digest (hex).
    pub grant_digest: String,
    /// Wall-clock milliseconds when the marker was written.
    pub claimed_at_unix_ms: u64,
}

impl InFlightDeliveryMarker {
    /// Captures the claim record for one delivery identity.
    #[must_use]
    pub fn from_identity(identity: &StagedDeliveryIdentity, claimed_at_unix_ms: u64) -> Self {
        Self {
            operation_id: identity.operation_id.clone(),
            generation: identity.generation,
            claim_id: identity.claim_id.clone(),
            grant_digest: identity.grant_digest.clone(),
            claimed_at_unix_ms,
        }
    }

    /// Whether this marker names exactly the staged identity.
    #[must_use]
    pub fn names(&self, identity: &StagedDeliveryIdentity) -> bool {
        self.operation_id == identity.operation_id
            && self.generation == identity.generation
            && self.claim_id == identity.claim_id
            && self.grant_digest == identity.grant_digest
    }
}

/// Reads the durable `InFlight` marker, if any. Only an absent marker answers
/// `Ok(None)`; read failures, oversize files, and malformed records fail
/// closed so callers cannot treat an uncertain claim as a fresh delivery.
/// The bounded read accepts a few hundred bytes for a legitimate marker.
pub fn read_inflight_marker(
    install_dir: &std::path::Path,
) -> Result<Option<InFlightDeliveryMarker>, MaterialError> {
    with_installation_root_lock(install_dir, || read_inflight_marker_unlocked(install_dir))
}

fn read_inflight_marker_unlocked(
    install_dir: &std::path::Path,
) -> Result<Option<InFlightDeliveryMarker>, MaterialError> {
    const MAX_BYTES: usize = 4096;

    let path = install_dir.join(WASM_HOST_INFLIGHT_FILE_NAME);
    let bytes = match read_bounded_regular_file(&path, MAX_BYTES) {
        Ok(bytes) => bytes,
        Err(MaterialError::Missing) => return Ok(None),
        Err(error) => return Err(error),
    };
    let marker: InFlightDeliveryMarker =
        serde_json::from_slice(&bytes).map_err(|_| MaterialError::Malformed)?;
    if marker.operation_id.trim().is_empty()
        || marker.claim_id.trim().is_empty()
        || marker.generation == 0
    {
        return Err(MaterialError::Malformed);
    }
    hex_digest(&marker.grant_digest, "inflight-marker-grant-digest")?;
    Ok(Some(marker))
}

/// New-format claim transitions are persisted in `DISPOSITION.json` under the
/// shared installation-root lock, so the incomplete fixed-name projection is
/// deliberately not writable.
pub fn write_inflight_marker(
    _install_dir: &std::path::Path,
    _identity: &StagedDeliveryIdentity,
    _claimed_at_unix_ms: u64,
) -> std::io::Result<()> {
    Err(std::io::Error::other(
        "inflight-marker-replaced-by-owner-disposition",
    ))
}

/// Legacy marker projections omit publication incarnation/revision and the
/// exact envelope commitment, so they cannot authorize a safe removal. New
/// format recovery is represented by the slot disposition; this compatibility
/// entry point preserves the legacy marker and reports that it remains.
#[must_use]
pub fn clear_inflight_marker(
    _install_dir: &std::path::Path,
    _identity: &StagedDeliveryIdentity,
) -> bool {
    false
}

/// The exact bounded result-event sequence one drive retained for its served
/// identity (#2787 audit defect 2). It lives inside #2786's existing durable
/// result record — there is no second result database — and it replaces that
/// record's terminal-only payload, which could not describe a
/// `sequence=1, observation_predecessors=[0]` terminal whose predecessor was
/// never retained.
///
/// Events stay opaque JSON values here: typed interpretation, per-frame
/// validation, and stream-shape validation belong to the request-loop driver
/// that owns the result contract, so this module never depends on driver
/// types. What this module owns is the record's own integrity: exactly one
/// payload variant, a well-formed identity, and a well-formed commitment to
/// the exact stored event bytes.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedResultStream {
    /// The exact retained result events, in observation order. Only ever
    /// appended to by the writer; a prefix is never dropped to fit a bound.
    pub events: Vec<serde_json::Value>,
    /// Sequence number of the event that closed the stream, or `None` while
    /// the retained sequence is still an open prefix. `None` is an explicit
    /// incomplete state, never a synthesized terminal.
    pub terminal_sequence: Option<u64>,
    /// Commitment to the exact stored event bytes. The reader recomputes it
    /// from the ORIGINAL recorded values and compares, so a record whose
    /// stored bytes differ from what its writer committed fails closed.
    pub stream_digest: String,
}

/// The one result content a served-result record retains.
///
/// Exactly one variant is stored. This is the type a writer names and the
/// type a reader classifies, so the two can never disagree about what a
/// stored record is: a `Stream` is what current code writes, and a
/// `TerminalFrame` is the #2786 v1 shape that earlier code wrote and that
/// readback therefore still has to be able to see. `TerminalFrame` remains
/// readable as an explicitly incomplete prefix: its predecessors are never
/// synthesized on readback.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServedResultPayload {
    /// #2786 v1: only the terminal frame was retained. No current writer
    /// emits this; it exists so the readback of a record written before the
    /// stream shape existed is a shape the classifier actually receives.
    TerminalFrame {
        /// Exact retained terminal frame JSON.
        frame: serde_json::Value,
    },
    /// #2787 v2: the exact bounded retained result-event sequence.
    Stream(RetainedResultStream),
}

/// Durable result record: the exact bounded result content this drive
/// retained, bound to its served identity. Decisions match on identity only
/// (see [`names`](ServedResultRecord::names)); `retained_at_unix_ms` is
/// informational (wall-clock at write, never a derivation input). Both
/// payloads are opaque JSON here; typed interpretation belongs to the
/// request-loop driver that owns the frame contract, so this module never
/// depends on driver types.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServedResultRecord {
    /// Result wire version.
    pub record_version: u16,
    /// Exact owner-issued delivery identity, including publication revision.
    pub identity: OwnerDeliveryIdentity,
    /// Exact owner-issued join binding.
    pub join: OwnerJoinBinding,
    /// SHA-256 of the exact canonical material envelope.
    pub request_commitment: String,
    /// Owner-issued launch reservation incarnation.
    pub launch_incarnation: String,
    /// Child-local first-writer claim incarnation.
    pub claimant_incarnation: String,
    /// Runtime invocation request digest, separate from `request_commitment`.
    pub runtime_request_digest: String,
    /// Terminal event index, or absent for an incomplete retained prefix.
    pub result_sequence: Option<u64>,
    /// Wall-clock milliseconds when the record was written.
    pub retained_at_unix_ms: u64,
    /// #2786 v1 payload: the terminal frame alone. An explicitly incomplete
    /// prefix, retained so an older record stays readable as what it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frame: Option<serde_json::Value>,
    /// #2787 v2 payload: the exact bounded retained result-event sequence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<RetainedResultStream>,
}

impl ServedResultRecord {
    /// Captures one result snapshot for the exact acquired child claim.
    #[must_use]
    pub fn from_claim(
        claim: &DeliveryClaim,
        payload: ServedResultPayload,
        retained_at_unix_ms: u64,
    ) -> Result<Self, MaterialError> {
        let owner_identity = claim
            .owner_identity
            .as_ref()
            .ok_or(MaterialError::Malformed)?;
        let join = claim.join.as_ref().ok_or(MaterialError::Malformed)?;
        let launch_incarnation = claim
            .launch_incarnation
            .as_ref()
            .ok_or(MaterialError::Malformed)?;
        let claimant_incarnation = claim
            .claimant_incarnation
            .as_ref()
            .ok_or(MaterialError::Malformed)?;
        let runtime_request_digest = claim
            .runtime_request_digest
            .as_ref()
            .ok_or(MaterialError::Malformed)?;
        let (frame, stream) = match payload {
            ServedResultPayload::TerminalFrame { frame } => (Some(frame), None),
            ServedResultPayload::Stream(stream) => (None, Some(stream)),
        };
        Ok(Self {
            record_version: 1,
            identity: owner_identity.clone(),
            join: join.clone(),
            request_commitment: owner_identity.envelope_digest.clone(),
            launch_incarnation: launch_incarnation.clone(),
            claimant_incarnation: claimant_incarnation.clone(),
            runtime_request_digest: runtime_request_digest.as_str().to_owned(),
            result_sequence: stream.as_ref().and_then(|stream| stream.terminal_sequence),
            retained_at_unix_ms,
            frame,
            stream,
        })
    }

    /// Whether this record names the exact owner and runtime claim.
    #[must_use]
    pub fn names(&self, claim: &DeliveryClaim) -> bool {
        let Some(owner_identity) = claim.owner_identity.as_ref() else {
            return false;
        };
        let Some(join) = claim.join.as_ref() else {
            return false;
        };
        self.record_version == 1
            && &self.identity == owner_identity
            && &self.join == join
            && self.request_commitment == owner_identity.envelope_digest
            && claim.identity.publication_incarnation == Some(self.identity.publication_incarnation)
            && claim.identity.publication_revision == Some(self.identity.publication_revision)
            && Some(&self.launch_incarnation) == claim.launch_incarnation.as_ref()
            && Some(&self.claimant_incarnation) == claim.claimant_incarnation.as_ref()
            && Some(self.runtime_request_digest.as_str())
                == claim
                    .runtime_request_digest
                    .as_ref()
                    .map(Sha256Digest::as_str)
    }
}

/// Reads the durable served-result record, if any. Only an absent record
/// answers `Ok(None)`; read failures, oversize files, malformed records, and
/// records carrying zero or both result payloads fail closed so callers
/// cannot treat uncertain retained state as a fresh delivery or as another
/// identity's result. The retained content is returned opaquely: the driver
/// that owns the result contract performs the real per-frame and stream-shape
/// validation against the recorded values.
pub fn read_served_result(
    install_dir: &std::path::Path,
    claim: &DeliveryClaim,
) -> Result<Option<ServedResultRecord>, MaterialError> {
    with_installation_root_lock(install_dir, || {
        read_served_result_unlocked(install_dir, claim)
    })
}

fn read_served_result_unlocked(
    install_dir: &std::path::Path,
    claim: &DeliveryClaim,
) -> Result<Option<ServedResultRecord>, MaterialError> {
    let owner_identity = claim
        .owner_identity
        .as_ref()
        .ok_or(MaterialError::Malformed)?;
    let disposition = read_owner_disposition_unlocked(install_dir, &claim.identity)?;
    if !disposition.disposition.is_claimed_by(claim) {
        return Err(MaterialError::DigestMismatch);
    }
    let (expected_digest, expected_sequence) = match &disposition.disposition {
        OwnerDeliveryDisposition::TerminalUnacknowledged {
            result_digest,
            result_sequence,
            ..
        }
        | OwnerDeliveryDisposition::Acknowledged {
            result_digest,
            result_sequence,
            ..
        } => (Some(result_digest.as_str()), Some(*result_sequence)),
        OwnerDeliveryDisposition::InFlight { .. } => (None, None),
        _ => return Err(MaterialError::DigestMismatch),
    };
    let path = delivery_slot_dir(install_dir, &claim.identity).join(WASM_DELIVERY_RESULT_FILE_NAME);
    let bytes = match read_bounded_regular_file(&path, SERVED_RESULT_MAX_BYTES) {
        Err(MaterialError::Missing) if expected_digest.is_none() => return Ok(None),
        Err(error) => return Err(error),
        Ok(bytes) => bytes,
    };
    if let Some(expected) = expected_digest
        && Sha256Digest::of_bytes(&bytes).as_str() != expected
    {
        return Err(MaterialError::DigestMismatch);
    }
    let record: ServedResultRecord =
        serde_json::from_slice(&bytes).map_err(|_| MaterialError::Malformed)?;
    record.identity.validate()?;
    record.join.validate(&record.identity)?;
    require_owner_digest(
        &record.runtime_request_digest,
        "served-result-runtime-digest",
    )?;
    if record.retained_at_unix_ms == 0 || !record.names(claim) || record.identity != *owner_identity
    {
        return Err(MaterialError::Malformed);
    }
    // Exactly one payload: a record carrying both a terminal-only frame and a
    // retained stream, or neither, is malformed and never answered as one of
    // the two shapes. The content itself is validated by the driver that owns
    // the result contract; this reader only refuses what it can prove is
    // unreadable here.
    match (&record.frame, &record.stream) {
        (Some(_), None) | (None, Some(_)) => {}
        _ => return Err(MaterialError::Malformed),
    }
    if expected_digest.is_none()
        && (record.frame.is_some()
            || record
                .stream
                .as_ref()
                .map_or(true, |stream| stream.terminal_sequence.is_some()))
    {
        // RESULT may reach disk just before a crash that prevents the matching
        // terminal disposition write. Preserve the bytes, but never expose
        // them as a terminal replay until the owner state records that commit.
        return Err(MaterialError::DigestMismatch);
    }
    if let Some(stream) = record.stream.as_ref() {
        if stream.events.is_empty() {
            return Err(MaterialError::Malformed);
        }
        hex_digest(&stream.stream_digest, "served-result-stream-digest")?;
        if let Some(terminal) = stream.terminal_sequence {
            // A recorded terminal that names an event the record never
            // stored is malformed here, not a stream whose shape the driver
            // gets to decide.
            let index = usize::try_from(terminal).map_err(|_| MaterialError::Malformed)?;
            if stream.events.get(index).is_none() {
                return Err(MaterialError::Malformed);
            }
            if record.result_sequence != Some(terminal) {
                return Err(MaterialError::Malformed);
            }
        } else if record.result_sequence.is_some() {
            return Err(MaterialError::Malformed);
        }
    }
    if let Some(expected) = expected_sequence
        && record.result_sequence != Some(expected)
    {
        return Err(MaterialError::DigestMismatch);
    }
    Ok(Some(record))
}

/// Writes the served-result record atomically (process-scoped partial,
/// flushed, then renamed): the reader never observes partial JSON. The
/// record must fit [`SERVED_RESULT_MAX_BYTES`]; an oversize retained stream
/// fails here rather than truncating, and a caller must propagate a write
/// failure and retain the claimed set for recovery.
pub fn write_served_result(
    install_dir: &std::path::Path,
    claim: &DeliveryClaim,
    payload: ServedResultPayload,
    retained_at_unix_ms: u64,
) -> std::io::Result<()> {
    let record = ServedResultRecord::from_claim(claim, payload, retained_at_unix_ms)
        .map_err(|_| std::io::Error::other("delivery-claim-unbound"))?;
    if record.retained_at_unix_ms == 0 || record.frame.is_some() {
        return Err(std::io::Error::other("served-result-shape-unavailable"));
    }
    let stream = record
        .stream
        .as_ref()
        .ok_or_else(|| std::io::Error::other("served-result-stream-missing"))?;
    if stream.events.is_empty() {
        return Err(std::io::Error::other("served-result-stream-empty"));
    }
    hex_digest(&stream.stream_digest, "served-result-stream-digest")
        .map_err(|_| std::io::Error::other("served-result-stream-digest"))?;
    if let Some(sequence) = stream.terminal_sequence {
        let index = usize::try_from(sequence)
            .map_err(|_| std::io::Error::other("served-result-sequence"))?;
        if stream.events.get(index).is_none() || record.result_sequence != Some(sequence) {
            return Err(std::io::Error::other("served-result-sequence"));
        }
    } else if record.result_sequence.is_some() {
        return Err(std::io::Error::other("served-result-sequence"));
    }
    let bytes =
        serde_json::to_vec(&record).map_err(|error| std::io::Error::other(error.to_string()))?;
    if bytes.len() > SERVED_RESULT_MAX_BYTES {
        return Err(std::io::Error::other("served-result-too-large"));
    }
    with_installation_root_lock_io(install_dir, || {
        let mut disposition = read_owner_disposition_unlocked(install_dir, &claim.identity)
            .map_err(|_| std::io::Error::other("delivery-disposition-unavailable"))?;
        if !disposition.disposition.is_claimed_by(claim) {
            return Err(std::io::Error::other("delivery-claim-conflict"));
        }
        let slot = delivery_slot_dir(install_dir, &claim.identity);
        let result_path = slot.join(WASM_DELIVERY_RESULT_FILE_NAME);
        let old_exists = match read_bounded_regular_file(&result_path, SERVED_RESULT_MAX_BYTES) {
            Ok(_) => Some(()),
            Err(MaterialError::Missing) => None,
            Err(_) => return Err(std::io::Error::other("retained-result-unavailable")),
        };
        if old_exists.is_some() {
            let old = read_served_result_unlocked(install_dir, claim)
                .map_err(|_| std::io::Error::other("retained-result-unavailable"))?
                .ok_or_else(|| std::io::Error::other("retained-result-unavailable"))?;
            if !old.names(claim) {
                return Err(std::io::Error::other("retained-result-conflict"));
            }
            let old_stream = old
                .stream
                .as_ref()
                .ok_or_else(|| std::io::Error::other("retained-result-shape-conflict"))?;
            let new_stream = record
                .stream
                .as_ref()
                .ok_or_else(|| std::io::Error::other("retained-result-shape-conflict"))?;
            if old.frame.is_some()
                || old_stream.events.len() > new_stream.events.len()
                || old_stream.events != new_stream.events[..old_stream.events.len()]
                || (old_stream.events.len() == new_stream.events.len()
                    && old_stream.stream_digest != new_stream.stream_digest)
            {
                return Err(std::io::Error::other("retained-result-prefix-conflict"));
            }
            if matches!(
                &disposition.disposition,
                OwnerDeliveryDisposition::TerminalUnacknowledged { .. }
                    | OwnerDeliveryDisposition::Acknowledged { .. }
            ) {
                if old.stream == record.stream && old.frame == record.frame {
                    return Ok(());
                }
                return Err(std::io::Error::other("terminal-result-already-sealed"));
            }
        }
        if !matches!(
            &disposition.disposition,
            OwnerDeliveryDisposition::InFlight { .. }
        ) {
            return Err(std::io::Error::other("delivery-not-in-flight"));
        }
        write_atomic_locked(&result_path, &bytes, SERVED_RESULT_MAX_BYTES)?;
        if let Some(stream) = record.stream.as_ref()
            && let Some(result_sequence) = stream.terminal_sequence
        {
            let OwnerDeliveryDisposition::InFlight {
                identity,
                join,
                request_commitment,
                launch_incarnation,
                claimant_incarnation,
                runtime_request_digest,
            } = &disposition.disposition
            else {
                return Err(std::io::Error::other("delivery-not-in-flight"));
            };
            disposition.disposition = OwnerDeliveryDisposition::TerminalUnacknowledged {
                identity: identity.clone(),
                join: join.clone(),
                request_commitment: request_commitment.clone(),
                launch_incarnation: launch_incarnation.clone(),
                claimant_incarnation: claimant_incarnation.clone(),
                runtime_request_digest: runtime_request_digest.clone(),
                result_digest: Sha256Digest::of_bytes(&bytes).as_str().to_owned(),
                result_sequence,
            };
            write_owner_disposition_unlocked(install_dir, &claim.identity, &disposition)?;
        }
        Ok(())
    })
}

/// Wire mirror of the owner-published grant record, field-for-field with
/// the publisher. The authority epoch travels as canonical JSON and is
/// carried verbatim: fence construction from it belongs to the authority
/// join, never to this reader.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialGrantMirror {
    grant_digest: String,
    authority_epoch: serde_json::Value,
    fence_generation: u64,
    fence_nonce: String,
    idempotency_key: String,
    expires_at: u64,
    host_artifact_digest: String,
}

/// Wire mirror of the guest invocation ceilings record.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestCeilingsMirror {
    artifact_digest: String,
    input_digest: String,
    max_output_bytes: u64,
    max_fuel: u64,
    max_memory_bytes: u64,
    wall_deadline_ms: u64,
    epoch_deadline_ticks: u64,
    table_elements: u64,
    max_instances: u64,
    artifact_access_reads: u64,
    artifact_access_bytes: u64,
    component_id: String,
}

/// Wire mirror of the owner-authored manifest record.
///
/// Closed-world declaration lists (`allowed_imports`, `allowed_exports`,
/// `capability_grants`) are parsed and carried for envelope closure but
/// enforced by contour admission, not read here — hence the dead-code
/// allowance on the mirror.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
struct ManifestRecordMirror {
    component_id: String,
    world: String,
    target: String,
    source_digest: String,
    state_contract_digest: String,
    required_verifier: String,
    privacy_classes: Vec<String>,
    allowed_imports: Vec<String>,
    allowed_exports: Vec<String>,
    capability_grants: Vec<String>,
    state_class: String,
    migration_contract: String,
    privacy_policy: String,
    comparator: String,
    rollback_generation: Option<String>,
}

/// Wire mirror of the owner-authored work identity record.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkRecordMirror {
    owner: String,
    work_unit: String,
    work_scope: String,
    task_ref: Option<String>,
    lease_id: String,
    lease_scope_ref: String,
    lease_state: String,
    generation_state: String,
    authority_revision: u64,
    lifecycle_revision: u64,
    verification_revision: u64,
    deterministic_seed: u64,
    contour: String,
    generation_health: Vec<String>,
}

/// Wire mirror of the owner-authored assurance record. Enum spellings are
/// carried verbatim and mapped strictly by the binder; unknown spellings
/// fail closed there.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AssuranceRecordMirror {
    source_ref: String,
    provenance_ref: String,
    integrity: String,
    freshness: String,
    competence: String,
    independence: String,
    privacy_class: String,
    instruction_taint: String,
    epistemic_use: Vec<String>,
    effect_ceilings: Vec<String>,
    required_verifier: String,
    quarantine: String,
}

/// Wire mirror of the owner-authored promotion oracle record.
///
/// Field names mirror the publisher envelope exactly (hence the shared
/// `digest` postfix); renaming any of them breaks the closed envelope.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
struct PromotionRecordMirror {
    corpus_digest: String,
    expected_result_digest: String,
    expected_effect_digest: String,
    expected_state_delta_digest: String,
}

/// Wire mirror of the owner-attested snapshot record.
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRecordMirror {
    service: String,
    protocol: String,
    generation: u64,
    authority_epoch: serde_json::Value,
    artifact_digest: String,
    protected_snapshot_digest: String,
    principal: String,
}

/// Wire mirror of the dispatch material envelope, field-for-field with the
/// owner publisher (`WasmDispatchMaterial`).
#[derive(Clone, Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MaterialEnvelopeMirror {
    wire_id: String,
    wire_version: u16,
    claim_id: String,
    operation_id: String,
    generation: u64,
    authority_epoch: serde_json::Value,
    launch_nonce: String,
    admitted_at_unix_ms: u64,
    grant: MaterialGrantMirror,
    guest: GuestCeilingsMirror,
    profile: String,
    prior_conformance_artifact: Option<String>,
    manifest: ManifestRecordMirror,
    work: WorkRecordMirror,
    assurance: AssuranceRecordMirror,
    promotion: PromotionRecordMirror,
    snapshot: SnapshotRecordMirror,
}

/// Canonical epoch JSON carried verbatim. The publisher serializes the
/// canonical `EpochId` shape (`lineage_id` then `sequence`, sorted keys),
/// and this reader re-serializes the parsed value the same way, so the
/// derivation input is byte-stable across the round trip. Never
/// interpreted here: fence construction belongs to the authority join.
fn epoch_json_string(value: &serde_json::Value) -> Result<String, MaterialError> {
    if !value.is_object() {
        return Err(MaterialError::Malformed);
    }
    serde_json::to_string(value).map_err(|_| MaterialError::Malformed)
}

/// Parses staged envelope bytes into a typed material input. The wire
/// identity and version must match exactly; every record then flows
/// through the same typed binder the direct path uses, so a malformed
/// envelope and a malformed record fail with the same typed refusal —
/// never a panic, never a partial bind.
///
/// The body is one straight field mapping by design: envelope order
/// follows publisher order so reviewers can diff them side by side.
#[allow(clippy::too_many_lines)]
fn parse_envelope(bytes: &[u8]) -> Result<DispatchMaterialInput, MaterialError> {
    let envelope: MaterialEnvelopeMirror =
        serde_json::from_slice(bytes).map_err(|_| MaterialError::Malformed)?;
    if envelope.wire_id != WASM_DISPATCH_MATERIAL_WIRE_ID
        || envelope.wire_version != WASM_DISPATCH_MATERIAL_WIRE_VERSION
    {
        return Err(MaterialError::Malformed);
    }
    let authority_epoch_json = epoch_json_string(&envelope.authority_epoch)?;
    let snapshot_epoch_json = epoch_json_string(&envelope.snapshot.authority_epoch)?;
    let grant_epoch_json = epoch_json_string(&envelope.grant.authority_epoch)?;
    if grant_epoch_json != authority_epoch_json || snapshot_epoch_json != authority_epoch_json {
        return Err(invalid("epoch-agreement"));
    }
    Ok(DispatchMaterialInput {
        claim_id: envelope.claim_id,
        operation_id: envelope.operation_id,
        generation: envelope.generation,
        authority_epoch_json,
        launch_nonce: envelope.launch_nonce,
        admitted_at_unix_ms: envelope.admitted_at_unix_ms,
        grant_digest: envelope.grant.grant_digest,
        grant_fence_generation: envelope.grant.fence_generation,
        grant_fence_nonce: envelope.grant.fence_nonce,
        grant_idempotency_key: envelope.grant.idempotency_key,
        grant_expires_at: envelope.grant.expires_at,
        host_artifact_digest: envelope.grant.host_artifact_digest,
        profile: envelope.profile,
        prior_conformance_artifact: envelope.prior_conformance_artifact,
        ceilings: ValidatedGuestCeilingsInput {
            component_id: envelope.guest.component_id,
            artifact_digest: envelope.guest.artifact_digest,
            input_digest: envelope.guest.input_digest,
            max_output_bytes: envelope.guest.max_output_bytes,
            max_fuel: envelope.guest.max_fuel,
            max_memory_bytes: envelope.guest.max_memory_bytes,
            wall_deadline_ms: envelope.guest.wall_deadline_ms,
            epoch_deadline_ticks: envelope.guest.epoch_deadline_ticks,
            table_elements: envelope.guest.table_elements,
            max_instances: envelope.guest.max_instances,
            artifact_access_reads: envelope.guest.artifact_access_reads,
            artifact_access_bytes: envelope.guest.artifact_access_bytes,
        },
        manifest: ValidatedManifestInput {
            component_id: envelope.manifest.component_id,
            world: envelope.manifest.world,
            target: envelope.manifest.target,
            source_digest: envelope.manifest.source_digest,
            state_contract_digest: envelope.manifest.state_contract_digest,
            required_verifier: envelope.manifest.required_verifier,
            privacy_classes: envelope.manifest.privacy_classes,
            state_class: envelope.manifest.state_class,
            migration_contract: envelope.manifest.migration_contract,
            privacy_policy: envelope.manifest.privacy_policy,
            comparator: envelope.manifest.comparator,
            rollback_generation: envelope.manifest.rollback_generation,
        },
        work: ValidatedWorkInput {
            owner: envelope.work.owner,
            work_unit: envelope.work.work_unit,
            work_scope: envelope.work.work_scope,
            task_ref: envelope.work.task_ref,
            lease_id: envelope.work.lease_id,
            lease_scope_ref: envelope.work.lease_scope_ref,
            lease_state: envelope.work.lease_state,
            generation_state: envelope.work.generation_state,
            authority_revision: envelope.work.authority_revision,
            lifecycle_revision: envelope.work.lifecycle_revision,
            verification_revision: envelope.work.verification_revision,
            deterministic_seed: envelope.work.deterministic_seed,
            contour: envelope.work.contour,
            generation_health: envelope.work.generation_health,
        },
        assurance: ValidatedAssuranceInput {
            source_ref: envelope.assurance.source_ref,
            provenance_ref: envelope.assurance.provenance_ref,
            integrity: envelope.assurance.integrity,
            freshness: envelope.assurance.freshness,
            competence: envelope.assurance.competence,
            independence: envelope.assurance.independence,
            privacy_class: envelope.assurance.privacy_class,
            instruction_taint: envelope.assurance.instruction_taint,
            epistemic_use: envelope.assurance.epistemic_use,
            effect_ceilings: envelope.assurance.effect_ceilings,
            required_verifier: envelope.assurance.required_verifier,
            quarantine: envelope.assurance.quarantine,
        },
        promotion: ValidatedPromotionInput {
            corpus_digest: envelope.promotion.corpus_digest,
            expected_result_digest: envelope.promotion.expected_result_digest,
            expected_effect_digest: envelope.promotion.expected_effect_digest,
            expected_state_delta_digest: envelope.promotion.expected_state_delta_digest,
        },
        snapshot: ValidatedSnapshotInput {
            service: envelope.snapshot.service,
            protocol: envelope.snapshot.protocol,
            generation: envelope.snapshot.generation,
            authority_epoch_json: snapshot_epoch_json,
            artifact_digest: envelope.snapshot.artifact_digest,
            protected_snapshot_digest: envelope.snapshot.protected_snapshot_digest,
            principal: envelope.snapshot.principal,
        },
        artifact_bytes: Vec::new(),
        input_bytes: Vec::new(),
    })
}

/// Reads and validates one staged dispatch material set from the install
/// directory, claim-first: the small envelope file (claim/identity plus
/// digests) is snapshotted, hashed, and parsed BEFORE the payload files
/// read, the payload digests re-hash against that pre-read claim at bind,
/// and the envelope is re-read and confirmed byte-identical before anything
/// binds. The fixed names are dumb locators; the pre-read claim selects the
/// operation. A missing envelope is `Ok(None)` — the caller keeps its
/// fail-closed path; anything present but invalid, or an envelope that
/// moved during the payload reads, fails closed and never executes.
/// Identical payload bytes across generations are why the envelope
/// re-confirm exists: digests alone cannot tell them apart.
///
/// The claim-first reader
/// ([`read_claimed_dispatch_material_from`]) owns the read, because the
/// pre-read material-set digest it measures is part of the claim this
/// reader's callers must later re-verify; this entry point is that reader
/// without the claim.
///
/// Honest residual — cases this ordering cannot exclude, by protocol, not
/// by omission: no cross-process reservation or lease exists on the child
/// side, so (a) a replacement staged entirely BEFORE the snapshot reads
/// as one consistent set (it is the live set at read time), and (b) a
/// replacement staged entirely AFTER the bind executes from pinned
/// in-memory bytes while the fixed names advance (the
/// execution-bytes-pinned invariant; reclamation re-checks before
/// deleting). Publication serialization stays with the owner publisher
/// half (retire-or-backpressure); the claim orders the read, not the
/// publisher.
///
/// # Errors
///
/// Returns [`MaterialError`] when any staged file is oversized,
/// unreadable, malformed, or fails shape and byte binding.
pub fn read_dispatch_material_from(
    install_dir: &std::path::Path,
) -> Result<Option<ValidatedDispatchMaterial>, MaterialError> {
    read_claimed_dispatch_material_from(install_dir)
        .map(|staged| staged.map(|(_, material)| material))
}

/// Reads staged dispatch material from the executable directory
/// (`current_exe`, never argv/stdin/env). `None` when no material was
/// delivered or the loader path is unavailable.
///
/// # Errors
///
/// Returns [`MaterialError`] when staged files are present but invalid.
pub fn read_dispatch_material() -> Result<Option<ValidatedDispatchMaterial>, MaterialError> {
    let Some(path) = admitted_material_path() else {
        return Ok(None);
    };
    let Some(directory) = path.parent() else {
        return Ok(None);
    };
    read_dispatch_material_from(directory)
}

/// Claim-first read returning the pre-read claim with the material bound
/// under it: one call, one snapshot, so the claim the loop serves and
/// reclaims is the identity that selected the operation — never a copy
/// derived after the fact from whatever the names happen to hold. The
/// material-set digest in that claim is measured over the exact envelope
/// bytes this read snapshotted, before the payload reads and before the
/// envelope re-confirm, so every later comparison of the same fixed name
/// re-hashes what it finds against that original value.
///
/// # Errors
///
/// Returns [`MaterialError`] exactly as [`read_dispatch_material_from`].
pub fn read_claimed_dispatch_material_from(
    install_dir: &std::path::Path,
) -> Result<Option<(DeliveryClaim, ValidatedDispatchMaterial)>, MaterialError> {
    with_installation_root_lock(install_dir, || {
        read_claimed_dispatch_material_unlocked(install_dir)
    })
}

fn read_claimed_dispatch_material_unlocked(
    install_dir: &std::path::Path,
) -> Result<Option<(DeliveryClaim, ValidatedDispatchMaterial)>, MaterialError> {
    let material_path = install_dir.join(WASM_HOST_MATERIAL_FILE_NAME);
    let envelope_bytes = match read_staged_bytes(&material_path) {
        Err(MaterialError::Missing) => return Ok(None),
        Err(error) => return Err(error),
        Ok(bytes) => bytes,
    };
    let envelope_digest = Sha256Digest::of_bytes(&envelope_bytes);
    let mut input = parse_envelope(&envelope_bytes)?;
    input.artifact_bytes =
        read_staged_bytes(&install_dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME))?;
    input.input_bytes = read_staged_bytes(&install_dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME))?;
    // Envelope re-confirm BEFORE binding: a replacement staged during the
    // payload reads aborts here, never executes — even when the payload
    // bytes are identical across generations. Any drift, disappearance,
    // or re-read fault is a torn set, never absence.
    match read_staged_bytes(&material_path) {
        Ok(current) if current == envelope_bytes => {}
        _ => return Err(MaterialError::DigestMismatch),
    }
    let material = bind_dispatch_material(input)?;
    Ok(Some((
        DeliveryClaim::from_material(&material, envelope_digest),
        material,
    )))
}

/// Claim-first read from the executable directory (`current_exe`, never
/// argv/stdin/env). `None` when no material was delivered or the loader
/// path is unavailable.
///
/// # Errors
///
/// Returns [`MaterialError`] when staged files are present but invalid.
pub fn read_claimed_dispatch_material()
-> Result<Option<(DeliveryClaim, ValidatedDispatchMaterial)>, MaterialError> {
    let Some(path) = admitted_material_path() else {
        return Ok(None);
    };
    let Some(directory) = path.parent() else {
        return Ok(None);
    };
    read_claimed_dispatch_material_from(directory)
}

/// Binds one typed material input into validated dispatch material.
///
/// Every identity is non-blank, every digest hex-shaped and re-proven
/// against the colocated bytes, every ceiling non-zero, every enum
/// spelling drawn from the closed owner sets, the manifest and assurance
/// verifiers in agreement, and the grant window ordered. A mixed envelope
/// fails closed here, before any authority, permit, or child exists.
///
/// # Errors
///
/// Returns [`MaterialError`] when any record, digest, ceiling, spelling,
/// or byte binding fails closed.
#[allow(clippy::too_many_lines)]
pub fn bind_dispatch_material(
    input: DispatchMaterialInput,
) -> Result<ValidatedDispatchMaterial, MaterialError> {
    require_nonblank(&input.claim_id, "claim-id")?;
    require_nonblank(&input.operation_id, "operation-id")?;
    require_nonblank(&input.launch_nonce, "launch-nonce")?;
    require_nonblank(&input.authority_epoch_json, "authority-epoch")?;
    if input.generation == 0 {
        return Err(invalid("generation"));
    }
    if input.admitted_at_unix_ms == 0 {
        return Err(invalid("admitted-at"));
    }
    let profile: Profile = input.profile.parse().map_err(|_| invalid("profile"))?;
    if !profile.is_compiled() {
        return Err(invalid("profile"));
    }
    let prior_conformance_artifact = input
        .prior_conformance_artifact
        .as_deref()
        .map(|hex| hex_digest(hex, "prior-conformance"))
        .transpose()?;
    let grant = bind_grant(&input)?;
    let ceilings = bind_ceilings(&input.ceilings)?;
    let manifest = bind_manifest(&input.manifest)?;
    let work = bind_work(&input.work)?;
    let assurance = bind_assurance(&input.assurance)?;
    let promotion = bind_promotion(&input.promotion)?;
    let snapshot = bind_snapshot(&input.snapshot)?;
    if manifest.required_verifier != assurance.required_verifier {
        return Err(invalid("verifier-agreement"));
    }
    if snapshot.generation != grant.fence_generation {
        return Err(invalid("snapshot-generation"));
    }
    if input.generation != grant.fence_generation {
        return Err(invalid("generation-agreement"));
    }
    if input.artifact_bytes.is_empty() || input.input_bytes.is_empty() {
        return Err(invalid("guest-bytes"));
    }
    if Sha256Digest::of_bytes(&input.artifact_bytes) != ceilings.artifact_digest
        || Sha256Digest::of_bytes(&input.input_bytes) != ceilings.input_digest
    {
        return Err(MaterialError::DigestMismatch);
    }
    let host_artifact_digest = hex_digest(&input.host_artifact_digest, "host-digest")?;
    Ok(ValidatedDispatchMaterial {
        claim_id: input.claim_id,
        operation_id: input.operation_id,
        generation: input.generation,
        authority_epoch_json: input.authority_epoch_json,
        launch_nonce: input.launch_nonce,
        admitted_at_unix_ms: input.admitted_at_unix_ms,
        grant,
        host_artifact_digest,
        profile,
        prior_conformance_artifact,
        manifest,
        work,
        assurance,
        promotion,
        snapshot,
        ceilings,
        artifact_bytes: input.artifact_bytes,
        input_bytes: input.input_bytes,
    })
}

fn bind_grant(input: &DispatchMaterialInput) -> Result<ValidatedDispatchGrant, MaterialError> {
    let grant_digest = hex_digest(&input.grant_digest, "grant-digest")?;
    require_nonblank(&input.grant_fence_nonce, "grant-fence-nonce")?;
    require_nonblank(&input.grant_idempotency_key, "grant-lease")?;
    if input.grant_fence_generation == 0 {
        return Err(invalid("grant-generation"));
    }
    if input.admitted_at_unix_ms == 0 {
        return Err(invalid("grant-admission-time"));
    }
    if input.grant_expires_at <= input.admitted_at_unix_ms {
        return Err(invalid("grant-expiry"));
    }
    Ok(ValidatedDispatchGrant {
        grant_digest,
        authority_epoch_json: input.authority_epoch_json.clone(),
        fence_generation: input.grant_fence_generation,
        fence_nonce: input.grant_fence_nonce.clone(),
        idempotency_key: input.grant_idempotency_key.clone(),
        admitted_at_unix_ms: input.admitted_at_unix_ms,
        expires_at: input.grant_expires_at,
        host_artifact_digest: hex_digest(&input.host_artifact_digest, "host-digest")?,
    })
}

fn bind_ceilings(
    ceilings: &ValidatedGuestCeilingsInput,
) -> Result<ValidatedGuestCeilings, MaterialError> {
    require_nonblank(&ceilings.component_id, "guest-component-id")?;
    if ceilings.max_output_bytes == 0
        || ceilings.max_fuel == 0
        || ceilings.max_memory_bytes == 0
        || ceilings.wall_deadline_ms == 0
        || ceilings.epoch_deadline_ticks == 0
        || ceilings.table_elements == 0
        || ceilings.max_instances == 0
        || ceilings.artifact_access_reads == 0
        || ceilings.artifact_access_bytes == 0
    {
        return Err(invalid("guest-ceilings"));
    }
    Ok(ValidatedGuestCeilings {
        component_id: ceilings.component_id.clone(),
        artifact_digest: hex_digest(&ceilings.artifact_digest, "guest-artifact-digest")?,
        input_digest: hex_digest(&ceilings.input_digest, "guest-input-digest")?,
        max_output_bytes: ceilings.max_output_bytes,
        max_fuel: ceilings.max_fuel,
        max_memory_bytes: ceilings.max_memory_bytes,
        wall_deadline_ms: ceilings.wall_deadline_ms,
        epoch_deadline_ticks: ceilings.epoch_deadline_ticks,
        table_elements: ceilings.table_elements,
        max_instances: ceilings.max_instances,
        artifact_access_reads: ceilings.artifact_access_reads,
        artifact_access_bytes: ceilings.artifact_access_bytes,
    })
}

fn bind_manifest(
    manifest: &ValidatedManifestInput,
) -> Result<ValidatedManifestRecord, MaterialError> {
    require_nonblank(&manifest.component_id, "manifest-component-id")?;
    require_nonblank(&manifest.world, "manifest-world")?;
    require_nonblank(&manifest.target, "manifest-target")?;
    if manifest.privacy_classes.is_empty() {
        return Err(invalid("manifest-privacy"));
    }
    for value in &manifest.privacy_classes {
        require_nonblank(value, "manifest-entries")?;
    }
    require_nonblank(&manifest.required_verifier, "manifest-verifier")?;
    require_nonblank(&manifest.state_class, "manifest-state-class")?;
    require_nonblank(&manifest.migration_contract, "manifest-migration")?;
    require_nonblank(&manifest.privacy_policy, "manifest-privacy-policy")?;
    require_nonblank(&manifest.comparator, "manifest-comparator")?;
    Ok(ValidatedManifestRecord {
        component_id: manifest.component_id.clone(),
        world: manifest.world.clone(),
        target: manifest.target.clone(),
        source_digest: hex_digest(&manifest.source_digest, "manifest-source-digest")?,
        state_contract_digest: hex_digest(
            &manifest.state_contract_digest,
            "manifest-state-digest",
        )?,
        required_verifier: manifest.required_verifier.clone(),
        privacy_classes: manifest.privacy_classes.clone(),
        state_class: manifest.state_class.clone(),
        migration_contract: manifest.migration_contract.clone(),
        privacy_policy: manifest.privacy_policy.clone(),
        comparator: manifest.comparator.clone(),
        rollback_generation: manifest.rollback_generation.clone(),
    })
}

fn bind_work(work: &ValidatedWorkInput) -> Result<ValidatedWorkRecord, MaterialError> {
    require_nonblank(&work.owner, "work-owner")?;
    require_nonblank(&work.work_unit, "work-unit")?;
    require_nonblank(&work.work_scope, "work-scope")?;
    require_nonblank(&work.lease_id, "lease-id")?;
    require_nonblank(&work.lease_scope_ref, "lease-scope")?;
    if work.lease_scope_ref != work.work_scope {
        return Err(invalid("lease-scope"));
    }
    require_spelling(&work.lease_state, &["active"], "lease-state")?;
    require_spelling(
        &work.generation_state,
        &["ready", "active"],
        "generation-state",
    )?;
    if work.authority_revision == 0
        || work.lifecycle_revision == 0
        || work.verification_revision == 0
    {
        return Err(invalid("work-revisions"));
    }
    require_spelling(&work.contour, &["SHADOW", "CONFORMANCE"], "work-contour")?;
    if work.generation_health.len() != 6 {
        return Err(invalid("work-health"));
    }
    for value in &work.generation_health {
        require_spelling(
            value,
            &["UNKNOWN", "HEALTHY", "DEGRADED", "FAILED"],
            "work-health",
        )?;
    }
    Ok(ValidatedWorkRecord {
        owner: work.owner.clone(),
        work_unit: work.work_unit.clone(),
        work_scope: work.work_scope.clone(),
        task_ref: work.task_ref.clone(),
        lease_id: work.lease_id.clone(),
        lease_scope_ref: work.lease_scope_ref.clone(),
        lease_state: work.lease_state.clone(),
        generation_state: work.generation_state.clone(),
        authority_revision: work.authority_revision,
        lifecycle_revision: work.lifecycle_revision,
        verification_revision: work.verification_revision,
        deterministic_seed: work.deterministic_seed,
        contour: work.contour.clone(),
        generation_health: work.generation_health.clone(),
    })
}

fn bind_assurance(
    assurance: &ValidatedAssuranceInput,
) -> Result<ValidatedAssuranceRecord, MaterialError> {
    require_nonblank(&assurance.source_ref, "assurance-source")?;
    require_nonblank(&assurance.provenance_ref, "assurance-provenance")?;
    require_spelling(
        &assurance.integrity,
        &["VERIFIED", "UNVERIFIED", "MODIFIED", "CONFLICTED"],
        "assurance-integrity",
    )?;
    require_spelling(
        &assurance.freshness,
        &["CURRENT", "STALE", "UNKNOWN"],
        "assurance-freshness",
    )?;
    require_spelling(
        &assurance.competence,
        &["DOMAIN_VERIFIED", "ATTRIBUTED", "UNKNOWN"],
        "assurance-competence",
    )?;
    require_spelling(
        &assurance.independence,
        &["INDEPENDENT", "RELATED", "COMMON_MODE", "UNKNOWN"],
        "assurance-independence",
    )?;
    require_spelling(
        &assurance.privacy_class,
        &["PUBLIC", "INTERNAL", "PRIVATE", "SECRET", "LICENSED"],
        "assurance-privacy",
    )?;
    require_spelling(
        &assurance.instruction_taint,
        &["CLEARED", "DATA_ONLY", "UNTRUSTED", "COMMAND_LIKE"],
        "assurance-taint",
    )?;
    for value in &assurance.epistemic_use {
        require_spelling(
            value,
            &[
                "OBSERVATION",
                "ATTRIBUTED_INPUT",
                "CANDIDATE_EVIDENCE",
                "VERIFICATION_INPUT",
            ],
            "assurance-epistemic",
        )?;
    }
    for value in &assurance.effect_ceilings {
        require_spelling(
            value,
            &["READ_ONLY", "CANDIDATE_ONLY", "NO_EXTERNAL_EFFECT"],
            "assurance-effects",
        )?;
    }
    require_nonblank(&assurance.required_verifier, "assurance-verifier")?;
    require_spelling(
        &assurance.quarantine,
        &["NONE", "REVIEW_REQUIRED", "QUARANTINED", "RELEASED"],
        "assurance-quarantine",
    )?;
    Ok(ValidatedAssuranceRecord {
        source_ref: assurance.source_ref.clone(),
        provenance_ref: assurance.provenance_ref.clone(),
        integrity: assurance.integrity.clone(),
        freshness: assurance.freshness.clone(),
        competence: assurance.competence.clone(),
        independence: assurance.independence.clone(),
        privacy_class: assurance.privacy_class.clone(),
        instruction_taint: assurance.instruction_taint.clone(),
        epistemic_use: assurance.epistemic_use.clone(),
        effect_ceilings: assurance.effect_ceilings.clone(),
        required_verifier: assurance.required_verifier.clone(),
        quarantine: assurance.quarantine.clone(),
    })
}

fn bind_promotion(
    promotion: &ValidatedPromotionInput,
) -> Result<ValidatedPromotionRecord, MaterialError> {
    Ok(ValidatedPromotionRecord {
        corpus_digest: hex_digest(&promotion.corpus_digest, "promotion-corpus")?,
        expected_result_digest: hex_digest(&promotion.expected_result_digest, "promotion-result")?,
        expected_effect_digest: hex_digest(&promotion.expected_effect_digest, "promotion-effects")?,
        expected_state_delta_digest: hex_digest(
            &promotion.expected_state_delta_digest,
            "promotion-state-delta",
        )?,
    })
}

fn bind_snapshot(
    snapshot: &ValidatedSnapshotInput,
) -> Result<ValidatedSnapshotRecord, MaterialError> {
    require_nonblank(&snapshot.service, "snapshot-service")?;
    require_nonblank(&snapshot.protocol, "snapshot-protocol")?;
    require_nonblank(&snapshot.authority_epoch_json, "snapshot-epoch")?;
    require_nonblank(&snapshot.principal, "snapshot-principal")?;
    if snapshot.generation == 0 {
        return Err(invalid("snapshot-generation"));
    }
    Ok(ValidatedSnapshotRecord {
        service: snapshot.service.clone(),
        protocol: snapshot.protocol.clone(),
        generation: snapshot.generation,
        authority_epoch_json: snapshot.authority_epoch_json.clone(),
        artifact_digest: hex_digest(&snapshot.artifact_digest, "snapshot-artifact")?,
        protected_snapshot_digest: hex_digest(
            &snapshot.protected_snapshot_digest,
            "snapshot-protected",
        )?,
        principal: snapshot.principal.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn digest_of(bytes: &[u8]) -> String {
        Sha256Digest::of_bytes(bytes).as_str().to_owned()
    }

    fn test_input() -> DispatchMaterialInput {
        let artifact = b"material-artifact-bytes".to_vec();
        let input = b"material-input-bytes".to_vec();
        DispatchMaterialInput {
            claim_id: "claim-material-001".to_owned(),
            operation_id: "operation-material-001".to_owned(),
            generation: 7,
            authority_epoch_json:
                "{\"lineage_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"sequence\":3}"
                    .to_owned(),
            launch_nonce: "launch-nonce-material-0001".to_owned(),
            admitted_at_unix_ms: 4_000_000_000_000,
            grant_digest: "e".repeat(64),
            grant_fence_generation: 7,
            grant_fence_nonce: "wasm-host-launch-fence-aaaaaaaaaaaaaaaa".to_owned(),
            grant_idempotency_key: "wasm-host-launch-lease-aaaaaaaaaaaaaaaa".to_owned(),
            grant_expires_at: 4_000_000_060_000,
            host_artifact_digest: "d".repeat(64),
            profile: "D2_OPERATIONAL".to_owned(),
            prior_conformance_artifact: None,
            ceilings: ValidatedGuestCeilingsInput {
                component_id: "component-material".to_owned(),
                artifact_digest: digest_of(&artifact),
                input_digest: digest_of(&input),
                max_output_bytes: 4096,
                max_fuel: 100_000,
                max_memory_bytes: 536_870_912,
                wall_deadline_ms: 30_000,
                epoch_deadline_ticks: 100,
                table_elements: 64,
                max_instances: 2,
                artifact_access_reads: 2,
                artifact_access_bytes: 131_072,
            },
            manifest: ValidatedManifestInput {
                component_id: "component-material".to_owned(),
                world: "eliot:wasm/guest".to_owned(),
                target: "wasm32-wasip2".to_owned(),
                source_digest: "b".repeat(64),
                state_contract_digest: "f".repeat(64),
                required_verifier: "verifier:a12".to_owned(),
                privacy_classes: vec!["Internal".to_owned()],
                state_class: "stateless".to_owned(),
                migration_contract: "none".to_owned(),
                privacy_policy: "project_code".to_owned(),
                comparator: "shadow-exact".to_owned(),
                rollback_generation: None,
            },
            work: ValidatedWorkInput {
                owner: "owner-material".to_owned(),
                work_unit: "work-material".to_owned(),
                work_scope: "scope-material".to_owned(),
                task_ref: Some("task-material".to_owned()),
                lease_id: "lease-material".to_owned(),
                lease_scope_ref: "scope-material".to_owned(),
                lease_state: "active".to_owned(),
                generation_state: "ready".to_owned(),
                authority_revision: 1,
                lifecycle_revision: 1,
                verification_revision: 1,
                deterministic_seed: 7,
                contour: "CONFORMANCE".to_owned(),
                generation_health: vec!["HEALTHY".to_owned(); 6],
            },
            assurance: ValidatedAssuranceInput {
                source_ref: "source-material".to_owned(),
                provenance_ref: "provenance-material".to_owned(),
                integrity: "VERIFIED".to_owned(),
                freshness: "CURRENT".to_owned(),
                competence: "DOMAIN_VERIFIED".to_owned(),
                independence: "INDEPENDENT".to_owned(),
                privacy_class: "INTERNAL".to_owned(),
                instruction_taint: "DATA_ONLY".to_owned(),
                epistemic_use: vec!["VERIFICATION_INPUT".to_owned()],
                effect_ceilings: vec!["NO_EXTERNAL_EFFECT".to_owned()],
                required_verifier: "verifier:a12".to_owned(),
                quarantine: "NONE".to_owned(),
            },
            promotion: ValidatedPromotionInput {
                corpus_digest: "0".repeat(64),
                expected_result_digest: "1".repeat(64),
                expected_effect_digest: "2".repeat(64),
                expected_state_delta_digest: "3".repeat(64),
            },
            snapshot: ValidatedSnapshotInput {
                service: "eliot-kernel".to_owned(),
                protocol: "eliot.kernel.v1".to_owned(),
                generation: 7,
                authority_epoch_json:
                    "{\"lineage_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"sequence\":3}"
                        .to_owned(),
                artifact_digest: "a".repeat(64),
                protected_snapshot_digest: "b".repeat(64),
                principal: "S-1-5-18".to_owned(),
            },
            artifact_bytes: artifact,
            input_bytes: input,
        }
    }

    #[test]
    fn valid_material_binds_with_proven_bytes() {
        let material = bind_dispatch_material(test_input()).expect("material binds");
        assert_eq!(material.claim_id, "claim-material-001");
        assert_eq!(material.operation_id, "operation-material-001");
        assert_eq!(material.generation, 7);
        assert_eq!(material.profile, Profile::D2Operational);
        assert!(material.prior_conformance_artifact.is_none());
        assert_eq!(material.grant.expires_at, 4_000_000_060_000);
        assert_eq!(material.snapshot.service, "eliot-kernel");
        assert_eq!(
            material.ceilings.artifact_digest.as_str(),
            digest_of(b"material-artifact-bytes").as_str()
        );
    }

    #[test]
    fn tampered_bytes_deny_before_any_permit() {
        let mut tampered = test_input();
        tampered.artifact_bytes = b"tampered-artifact".to_vec();
        assert_eq!(
            bind_dispatch_material(tampered),
            Err(MaterialError::DigestMismatch)
        );
    }

    #[test]
    fn malformed_records_fail_closed() {
        // Blank claim.
        let mut blank = test_input();
        blank.claim_id.clear();
        assert_eq!(
            bind_dispatch_material(blank).map(|_| ()),
            Err(MaterialError::InvalidRecord { field: "claim-id" })
        );
        // Unknown profile spelling.
        let mut profile = test_input();
        profile.profile = "LABORATORY".to_owned();
        assert_eq!(
            bind_dispatch_material(profile).map(|_| ()),
            Err(MaterialError::InvalidRecord { field: "profile" })
        );
        // Verifier disagreement between manifest and assurance.
        let mut verifier = test_input();
        verifier.assurance.required_verifier = "verifier:foreign".to_owned();
        assert_eq!(
            bind_dispatch_material(verifier).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "verifier-agreement"
            })
        );
        // Lease scope must equal the work scope.
        let mut scope = test_input();
        scope.work.lease_scope_ref = "scope-foreign".to_owned();
        assert_eq!(
            bind_dispatch_material(scope).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "lease-scope"
            })
        );
        // Malformed prior digest fails closed.
        let mut prior = test_input();
        prior.prior_conformance_artifact = Some("not-a-digest".to_owned());
        assert_eq!(
            bind_dispatch_material(prior).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "prior-conformance"
            })
        );
        // Expired grant window fails closed.
        let mut window = test_input();
        window.grant_expires_at = window.admitted_at_unix_ms;
        assert_eq!(
            bind_dispatch_material(window).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "grant-expiry"
            })
        );
    }

    #[test]
    fn staged_reader_guards_absence_and_size() {
        let missing = std::path::Path::new("definitely-absent-2377-material.json");
        assert_eq!(read_staged_bytes(missing), Err(MaterialError::Missing));
        let path = std::env::temp_dir().join("eliot-2377-oversize-material.bin");
        std::fs::write(&path, vec![0xA5; DISPATCH_MATERIAL_MAX_BYTES as usize + 1])
            .expect("oversize fixture writable");
        assert_eq!(read_staged_bytes(&path), Err(MaterialError::TooLarge));
        let _ = std::fs::remove_file(&path);
    }

    fn test_envelope_json(input: &DispatchMaterialInput) -> Vec<u8> {
        let epoch: serde_json::Value =
            serde_json::from_str(&input.authority_epoch_json).expect("epoch parses");
        serde_json::to_vec(&serde_json::json!({
            "wire_id": WASM_DISPATCH_MATERIAL_WIRE_ID,
            "wire_version": WASM_DISPATCH_MATERIAL_WIRE_VERSION,
            "claim_id": input.claim_id,
            "operation_id": input.operation_id,
            "generation": input.generation,
            "authority_epoch": epoch,
            "launch_nonce": input.launch_nonce,
            "admitted_at_unix_ms": input.admitted_at_unix_ms,
            "grant": {
                "grant_digest": input.grant_digest,
                "authority_epoch": epoch,
                "fence_generation": input.grant_fence_generation,
                "fence_nonce": input.grant_fence_nonce,
                "idempotency_key": input.grant_idempotency_key,
                "expires_at": input.grant_expires_at,
                "host_artifact_digest": input.host_artifact_digest,
            },
            "guest": {
                "artifact_digest": input.ceilings.artifact_digest,
                "input_digest": input.ceilings.input_digest,
                "max_output_bytes": input.ceilings.max_output_bytes,
                "max_fuel": input.ceilings.max_fuel,
                "max_memory_bytes": input.ceilings.max_memory_bytes,
                "wall_deadline_ms": input.ceilings.wall_deadline_ms,
                "epoch_deadline_ticks": input.ceilings.epoch_deadline_ticks,
                "table_elements": input.ceilings.table_elements,
                "max_instances": input.ceilings.max_instances,
                "artifact_access_reads": input.ceilings.artifact_access_reads,
                "artifact_access_bytes": input.ceilings.artifact_access_bytes,
                "component_id": input.ceilings.component_id,
            },
            "profile": input.profile,
            "prior_conformance_artifact": input.prior_conformance_artifact,
            "manifest": {
                "component_id": input.manifest.component_id,
                "world": input.manifest.world,
                "target": input.manifest.target,
                "source_digest": input.manifest.source_digest,
                "state_contract_digest": input.manifest.state_contract_digest,
                "required_verifier": input.manifest.required_verifier,
                "privacy_classes": input.manifest.privacy_classes,
                "allowed_imports": [],
                "allowed_exports": ["run"],
                "capability_grants": [],
                "state_class": input.manifest.state_class,
                "migration_contract": input.manifest.migration_contract,
                "privacy_policy": input.manifest.privacy_policy,
                "comparator": input.manifest.comparator,
                "rollback_generation": input.manifest.rollback_generation,
            },
            "work": {
                "owner": input.work.owner,
                "work_unit": input.work.work_unit,
                "work_scope": input.work.work_scope,
                "task_ref": input.work.task_ref,
                "lease_id": input.work.lease_id,
                "lease_scope_ref": input.work.lease_scope_ref,
                "lease_state": input.work.lease_state,
                "generation_state": input.work.generation_state,
                "authority_revision": input.work.authority_revision,
                "lifecycle_revision": input.work.lifecycle_revision,
                "verification_revision": input.work.verification_revision,
                "deterministic_seed": input.work.deterministic_seed,
                "contour": input.work.contour,
                "generation_health": input.work.generation_health,
            },
            "assurance": {
                "source_ref": input.assurance.source_ref,
                "provenance_ref": input.assurance.provenance_ref,
                "integrity": input.assurance.integrity,
                "freshness": input.assurance.freshness,
                "competence": input.assurance.competence,
                "independence": input.assurance.independence,
                "privacy_class": input.assurance.privacy_class,
                "instruction_taint": input.assurance.instruction_taint,
                "epistemic_use": input.assurance.epistemic_use,
                "effect_ceilings": input.assurance.effect_ceilings,
                "required_verifier": input.assurance.required_verifier,
                "quarantine": input.assurance.quarantine,
            },
            "promotion": {
                "corpus_digest": input.promotion.corpus_digest,
                "expected_result_digest": input.promotion.expected_result_digest,
                "expected_effect_digest": input.promotion.expected_effect_digest,
                "expected_state_delta_digest": input.promotion.expected_state_delta_digest,
            },
            "snapshot": {
                "service": input.snapshot.service,
                "protocol": input.snapshot.protocol,
                "generation": input.snapshot.generation,
                "authority_epoch": epoch,
                "artifact_digest": input.snapshot.artifact_digest,
                "protected_snapshot_digest": input.snapshot.protected_snapshot_digest,
                "principal": input.snapshot.principal,
            },
        }))
        .expect("envelope serializes")
    }

    fn stage_envelope(name: &str, input: &DispatchMaterialInput) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&dir).expect("stage dir writable");
        std::fs::write(
            dir.join(WASM_HOST_MATERIAL_FILE_NAME),
            test_envelope_json(input),
        )
        .expect("envelope writable");
        std::fs::write(
            dir.join(WASM_HOST_GUEST_ARTIFACT_FILE_NAME),
            &input.artifact_bytes,
        )
        .expect("artifact writable");
        std::fs::write(
            dir.join(WASM_HOST_GUEST_INPUT_FILE_NAME),
            &input.input_bytes,
        )
        .expect("input writable");
        dir
    }

    /// Staged envelope end-to-end: the publisher-shaped JSON parses,
    /// binds, and re-hashes the colocated bytes; absence stays `None`.
    #[test]
    fn staged_envelope_parses_and_binds() {
        let input = test_input();
        let dir = stage_envelope("eliot-2377-envelope-ok", &input);
        let material = read_dispatch_material_from(&dir)
            .expect("envelope reads")
            .expect("material present");
        assert_eq!(material.claim_id, "claim-material-001");
        assert_eq!(material.profile, Profile::D2Operational);
        assert_eq!(
            material.authority_epoch_json, input.authority_epoch_json,
            "epoch JSON survives the envelope round trip verbatim"
        );
        let _ = std::fs::remove_dir_all(&dir);
        let absent = std::env::temp_dir().join("eliot-2377-envelope-absent");
        std::fs::create_dir_all(&absent).expect("absent dir writable");
        assert_eq!(read_dispatch_material_from(&absent), Ok(None));
        let _ = std::fs::remove_dir_all(&absent);
    }

    /// Envelope refusals are typed and fail closed: malformed JSON, a
    /// foreign wire identity, an unknown field, and epoch disagreement
    /// never bind.
    #[test]
    fn staged_envelope_refusals_fail_closed() {
        let input = test_input();
        // Malformed JSON.
        assert_eq!(
            parse_envelope(b"{not json").map(|_| ()),
            Err(MaterialError::Malformed)
        );
        // Foreign wire identity.
        let mut foreign = test_envelope_json(&input);
        let mut value: serde_json::Value =
            serde_json::from_slice(&foreign).expect("envelope parses");
        value["wire_id"] = serde_json::Value::String("foreign.envelope".to_owned());
        foreign = serde_json::to_vec(&value).expect("foreign serializes");
        assert_eq!(
            parse_envelope(&foreign).map(|_| ()),
            Err(MaterialError::Malformed)
        );
        // Unknown field denied by the closed envelope.
        let mut unknown = test_envelope_json(&input);
        let mut value: serde_json::Value =
            serde_json::from_slice(&unknown).expect("envelope parses");
        value["second_admission"] = serde_json::Value::Bool(true);
        unknown = serde_json::to_vec(&value).expect("unknown serializes");
        assert_eq!(
            parse_envelope(&unknown).map(|_| ()),
            Err(MaterialError::Malformed)
        );
        // Epoch disagreement between envelope and grant.
        let mut drifted = test_envelope_json(&input);
        let mut value: serde_json::Value =
            serde_json::from_slice(&drifted).expect("envelope parses");
        value["grant"]["authority_epoch"] = serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440001",
            "sequence": 3
        });
        drifted = serde_json::to_vec(&value).expect("drifted serializes");
        assert_eq!(
            parse_envelope(&drifted).map(|_| ()),
            Err(MaterialError::InvalidRecord {
                field: "epoch-agreement"
            })
        );
    }
}
