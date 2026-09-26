//! Owner-published replayable WASM control stream (issue #2896).
//!
//! The Kernel half of external WASM-host control delivery. The owner — the
//! same Kernel daemon that published the dispatch bundle and demand-started
//! the host parent — publishes versioned Cancel/Reconcile/Shutdown
//! deliveries through a generation-specific immutable spool colocated with
//! the delivery set, and retains each delivery's disposition until it is
//! terminal. The child never mints control authority: it validates,
//! admits, enqueues, and acknowledges what the owner published, and the
//! owner reconciles the same delivery on retry or restart instead of
//! minting a fresh command under a fresh identity.
//!
//! Wire contract (I7.2 durable-control envelope, I7.4 lifecycle vocabulary,
//! I5.27 canonical operation identity). The child crate cannot depend on
//! this service crate, so it mirrors these JSON shapes field-for-field;
//! the field names below are stable:
//!
//! ```text
//! delivery ("eliot.wasm.control-delivery", version 1):
//!   wire_id, wire_version,
//!   identity: { operation_id, invocation_id, claim_id, generation,
//!     control_kind, owner_sequence, authority_epoch, state_fence,
//!     work_scope, principal_digest, session_connection, session_epoch,
//!     dispatch_grant_digest, publisher_challenge_id, publisher_operation,
//!     publisher_decided_at_unix_ms, deadline_unix_ms, replay_key,
//!     previous_delivery_digest },
//!   delivery_digest
//! ack ("eliot.wasm.control-ack", version 1):
//!   wire_id, wire_version, replay_key, operation_id, generation,
//!   owner_sequence, delivery_digest, phase, detail, outcome_digest
//! disposition sidecar ("eliot.wasm.control-disposition", version 1):
//!   wire_id, wire_version, replay_key, operation_id, generation,
//!   owner_sequence, control_kind, disposition, reason,
//!   publisher_grant_digest, delivery_digest, updated_at_unix_ms
//! spool head ("eliot.wasm.control-spool-head", version 1):
//!   wire_id, wire_version, operation_id, generation, next_sequence,
//!   updated_at_unix_ms
//! ```
//!
//! Closed spellings: `control_kind` is `cancel | reconcile | shutdown`
//! (the child maps them onto its `wasm_guest_cancel`, `wasm_guest_reconcile`
//! and `wasm_host_shutdown` operations); `disposition` is
//! `PREPARED | OFFERED | ACCEPTED | COMPLETED | UNKNOWN | REFUSED`; ack
//! `phase` is `enqueued | completed | refused`.
//!
//! Spool layout (I14.3 bounded control capacity with a protected reserve;
//! I6.5 acknowledgement; I14.21 unknown-commit recovery). Every file is
//! immutable once staged; staging is write-temp-then-rename so the reader
//! never observes partial JSON, and retirement deletes exact
//! generation/sequence names only, never a shared mutable pathname:
//!
//! ```text
//! eliot-wasm-host.control-g{generation}-{seq}.json
//! eliot-wasm-host.control-g{generation}-{seq}.disposition.json  (owner)
//! eliot-wasm-host.control-g{generation}-{seq}.ack.json          (child)
//! eliot-wasm-host.control-g{generation}-{op16}.head.json        (owner)
//! ```
//!
//! The legacy single fixed file (`eliot-wasm-host.control-request.json`) is
//! never written here; legacy compatibility at the reader is the child
//! half's contract. Delivery-set reclamation across generations stays with
//! the delivery owner (#2786); this spool only retires its own terminal
//! triples under pressure, and the monotonic head never resets, so a
//! retired completed control is never revived under a reused sequence.

use eliot_contracts::{EpochId, StateFence, sha256_hex};

/// Delivery envelope wire identity, mirrored exactly by the child reader.
pub const WASM_CONTROL_DELIVERY_WIRE_ID: &str = "eliot.wasm.control-delivery";
/// Delivery envelope wire version, mirrored exactly by the child reader.
pub const WASM_CONTROL_DELIVERY_WIRE_VERSION: u16 = 1;
/// Ack envelope wire identity, mirrored exactly by the child publisher.
pub const WASM_CONTROL_ACK_WIRE_ID: &str = "eliot.wasm.control-ack";
/// Ack envelope wire version, mirrored exactly by the child publisher.
pub const WASM_CONTROL_ACK_WIRE_VERSION: u16 = 1;
/// Disposition sidecar wire identity (owner-private, still versioned).
pub const WASM_CONTROL_DISPOSITION_WIRE_ID: &str = "eliot.wasm.control-disposition";
/// Disposition sidecar wire version (owner-private, still versioned).
pub const WASM_CONTROL_DISPOSITION_WIRE_VERSION: u16 = 1;
/// Spool head wire identity (owner-private, still versioned).
pub const WASM_CONTROL_HEAD_WIRE_ID: &str = "eliot.wasm.control-spool-head";
/// Spool head wire version (owner-private, still versioned).
pub const WASM_CONTROL_HEAD_WIRE_VERSION: u16 = 1;
/// Spool filename prefix. The full delivery name appends
/// `{generation}-{sequence:06}` plus the kind suffix, so two owner
/// controls can never overwrite each other through one mutable pathname.
pub const WASM_CONTROL_FILE_PREFIX: &str = "eliot-wasm-host.control-g";
/// Bounded spool rows per running operation and generation (I14.3: every
/// bottleneck carries explicit capacity; deliveries are small JSON, so
/// eight rows bound the spool near sixteen kilobytes).
pub const WASM_CONTROL_SPOOL_MAX_DELIVERIES: usize = 8;
/// Protected reserve inside the spool for Cancel/Shutdown (I14.3: normal
/// workload cannot consume the control lane; here Reconcile is the
/// deferrable kind and Cancel/Shutdown may consume the last slots).
pub const WASM_CONTROL_SPOOL_RESERVE_SLOTS: usize = 2;
/// Bounded spool file bytes (I7.2 hot-response contour: 64 KiB; a larger
/// staged file is refused before parsing, never truncated).
pub const WASM_CONTROL_MAX_FILE_BYTES: u64 = 64 * 1024;
/// Bounded directory scan entries per reconcile (fail-closed backpressure
/// against a foreign-filled directory; one install directory hosts one
/// delivery set, so a legitimate spool never approaches this).
pub const WASM_CONTROL_SPOOL_SCAN_CAP: usize = 64;
/// Delivery validity window in milliseconds, mirroring the sixty-second
/// dispatch-grant contour: freshness opens at the origin decision, never
/// at derivation or observation time.
pub const WASM_CONTROL_GRANT_WINDOW_MS: u64 = 60_000;
/// Deterministic replay-key/digest domain, mirroring the dispatch
/// derivation domain pattern so control identities can never collide with
/// dispatch identities.
pub const WASM_CONTROL_REPLAY_KEY_DOMAIN: &str = "eliot-wasm-host-control/v1";
/// Bounded ack/detail/reason text (forensic evidence stays small).
pub const WASM_CONTROL_MAX_DETAIL_BYTES: usize = 512;
/// Cancel spelling shared with the child operation vocabulary.
pub const WASM_CONTROL_KIND_CANCEL: &str = "cancel";
/// Reconcile spelling shared with the child operation vocabulary.
pub const WASM_CONTROL_KIND_RECONCILE: &str = "reconcile";
/// Shutdown spelling shared with the child operation vocabulary.
pub const WASM_CONTROL_KIND_SHUTDOWN: &str = "shutdown";

/// Fail-closed owner-side control errors. No delivery content echoed.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WasmControlError {
    /// A control input, staged file, or spool path failed validation.
    #[error("WASM_CONTROL_INVALID:{0}")]
    InvalidControl(String),
    /// The bounded spool (or its protected reserve) has no free slot.
    #[error("WASM_CONTROL_SPOOL_SATURATED")]
    SpoolSaturated,
    /// A reused sequence binds different content (I5.27 identity conflict).
    #[error("WASM_CONTROL_IDENTITY_CONFLICT")]
    IdentityConflict,
}

fn invalid(field: &str) -> WasmControlError {
    WasmControlError::InvalidControl(field.to_owned())
}

fn require_digest(value: &str, field: &'static str) -> Result<(), WasmControlError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(invalid(field));
    }
    Ok(())
}

fn require_detail(value: &str, field: &'static str) -> Result<(), WasmControlError> {
    if value.len() > WASM_CONTROL_MAX_DETAIL_BYTES
        || value.chars().any(char::is_control)
        || value.trim().is_empty()
    {
        return Err(invalid(field));
    }
    Ok(())
}

/// Owner-issued control kind (I7.4 lifecycle vocabulary).
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
    /// Returns the closed wire spelling shared with the child reader.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancel => WASM_CONTROL_KIND_CANCEL,
            Self::Reconcile => WASM_CONTROL_KIND_RECONCILE,
            Self::Shutdown => WASM_CONTROL_KIND_SHUTDOWN,
        }
    }

    /// Reports whether this kind may consume the protected reserve slots.
    /// Cancel and Shutdown are the control lane (I14.3); Reconcile is
    /// deferrable and is refused while only reserve slots remain.
    #[must_use]
    pub const fn uses_reserve(self) -> bool {
        match self {
            Self::Cancel | Self::Shutdown => true,
            Self::Reconcile => false,
        }
    }
}

/// Versioned control-delivery identity binding (issue #2896 item 2).
///
/// Every value is owner-attested from existing identities, contours, and
/// receipts — the decided operation, the staged dispatch material, the
/// live session, and the origin-control grant — nothing invented. The
/// child-sealed request digest is deliberately absent: the owner cannot
/// recompute that crate-private seal, so it must not mint it; the child
/// cross-checks the operation/invocation/grant triple against its own
/// sealed binding instead.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDeliveryIdentity {
    /// Exact decided operation identity.
    pub operation_id: String,
    /// Invocation identity, always equal to `operation_id`: the child
    /// seals `InvocationId` from the material operation identity, so the
    /// owner binds the same value rather than minting a second one.
    pub invocation_id: String,
    /// Admitted claim identity from the staged dispatch material.
    pub claim_id: String,
    /// Exact running process generation (non-zero).
    pub generation: u64,
    /// Control kind in the closed lifecycle spelling.
    pub control_kind: WasmControlKind,
    /// Monotonic owner sequence within this operation/generation spool,
    /// starting at zero; the spool head never resets it.
    pub owner_sequence: u64,
    /// Live authority epoch bound at publication.
    pub authority_epoch: EpochId,
    /// Live state fence bound at publication.
    pub state_fence: StateFence,
    /// Admitted work-scope identity from the staged material work record.
    pub work_scope: String,
    /// Authenticated publisher principal digest from the owner binding.
    pub principal_digest: String,
    /// Publishing transport connection (correlation only, never
    /// persisted as process ownership).
    pub session_connection: String,
    /// Publishing transport session epoch (correlation only).
    pub session_epoch: u64,
    /// Dispatch-grant digest from the staged material: the admission
    /// receipt funding the running operation.
    pub dispatch_grant_digest: String,
    /// Origin-control challenge identity funding this publication: the
    /// publisher/admission receipt correlation.
    pub publisher_challenge_id: String,
    /// Origin-control operation class funding this publication.
    pub publisher_operation: String,
    /// Origin-control decision time in Unix milliseconds.
    pub publisher_decided_at_unix_ms: u64,
    /// Delivery expiry in Unix milliseconds (decision plus the grant
    /// window); a stale delivery is refused, never applied late.
    pub deadline_unix_ms: u64,
    /// Deterministic replay key over domain, operation, generation, kind,
    /// and sequence; retries and restarts reconcile this key.
    pub replay_key: String,
    /// Digest of the previous retained delivery in sequence order, `None`
    /// at sequence zero; ordering evidence, not consensus.
    pub previous_delivery_digest: Option<String>,
}

/// Owner-published control delivery envelope.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmControlDelivery {
    /// Envelope wire identity (`WASM_CONTROL_DELIVERY_WIRE_ID`).
    pub wire_id: String,
    /// Envelope wire version (`WASM_CONTROL_DELIVERY_WIRE_VERSION`).
    pub wire_version: u16,
    /// Versioned identity binding.
    pub identity: ControlDeliveryIdentity,
    /// Lowercase SHA-256 over the canonical envelope bytes (wire fields
    /// plus identity); acks bind to this digest.
    pub delivery_digest: String,
}

/// Child-to-owner acknowledgement phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ControlAckPhase {
    /// The child admitted the delivery and enqueued it to the worker
    /// owner (worker completion is reported separately).
    Enqueued,
    /// The child observed the exact outcome of the accepted control.
    Completed,
    /// The child refused the delivery (admission failure evidence).
    Refused,
}

/// Child-staged acknowledgement for one delivery. The child publishes
/// this beside the delivery under the exact ack name; the owner joins it
/// by replay key and delivery digest during reconcile.
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

/// Owner-retained delivery disposition (I7.2 ack phases, I14.21 unknown).
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlDisposition {
    /// Delivery file staged; no owner offer recorded yet (a crash
    /// between staging and the offer restarts here under the same
    /// identity).
    Prepared,
    /// Delivery offered to the child; no acknowledgement observed.
    Offered,
    /// Child acknowledged admission and worker enqueue; the exact
    /// outcome is still open.
    Accepted,
    /// Child reported the exact outcome; terminal, never revived.
    Completed,
    /// Response lost (supervised termination without ack, or an
    /// unreadable disposition record); preserved under the same
    /// identity, never silently re-sent as a fresh command.
    Unknown,
    /// Delivery refused with typed evidence; terminal.
    Refused,
}

impl ControlDisposition {
    /// Reports whether the disposition is terminal: completed and refused
    /// deliveries retire under pressure but are never re-offered.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        match self {
            Self::Completed | Self::Refused => true,
            Self::Prepared | Self::Offered | Self::Accepted | Self::Unknown => false,
        }
    }
}

/// Owner-retained disposition record, staged beside the delivery under
/// the exact disposition name. The full origin-grant tag lives here as
/// the publisher receipt (audit correlation; verification stays with the
/// origin authority, which owns the key).
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlDispositionRecord {
    /// Sidecar wire identity (`WASM_CONTROL_DISPOSITION_WIRE_ID`).
    pub wire_id: String,
    /// Sidecar wire version (`WASM_CONTROL_DISPOSITION_WIRE_VERSION`).
    pub wire_version: u16,
    /// Replay key of the delivery.
    pub replay_key: String,
    /// Operation identity of the delivery.
    pub operation_id: String,
    /// Generation of the delivery.
    pub generation: u64,
    /// Owner sequence of the delivery.
    pub owner_sequence: u64,
    /// Control kind of the delivery.
    pub control_kind: WasmControlKind,
    /// Current disposition.
    pub disposition: ControlDisposition,
    /// Bounded typed reason (refusal detail, termination evidence, or
    /// recovery marker).
    pub reason: Option<String>,
    /// Secret-bound origin-grant tag funding the publication.
    pub publisher_grant_digest: String,
    /// Digest of the retained delivery.
    pub delivery_digest: String,
    /// Last disposition update in Unix milliseconds.
    pub updated_at_unix_ms: u64,
}

/// Owner-side monotonic spool head for one operation and generation.
/// The head never resets — not under pressure, not across restarts — so a
/// retired completed sequence is never reused for a fresh command. The
/// child never reads this file.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WasmControlSpoolHead {
    /// Head wire identity (`WASM_CONTROL_HEAD_WIRE_ID`).
    wire_id: String,
    /// Head wire version (`WASM_CONTROL_HEAD_WIRE_VERSION`).
    wire_version: u16,
    /// Operation identity this head sequences.
    operation_id: String,
    /// Generation this head sequences.
    generation: u64,
    /// Next owner sequence to assign.
    next_sequence: u64,
    /// Last head update in Unix milliseconds.
    updated_at_unix_ms: u64,
}

/// One retained delivery as projected into spool status.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmControlDeliveryStatus {
    /// Replay key of the retained delivery.
    pub replay_key: String,
    /// Control kind of the retained delivery.
    pub control_kind: WasmControlKind,
    /// Owner sequence of the retained delivery.
    pub owner_sequence: u64,
    /// Current disposition of the retained delivery.
    pub disposition: ControlDisposition,
    /// Bounded typed reason carried by the disposition, if any.
    pub reason: Option<String>,
    /// Digest of the retained delivery.
    pub delivery_digest: String,
    /// Delivery expiry in Unix milliseconds.
    pub deadline_unix_ms: u64,
}

/// Owner spool readback for recovery and status (issue #2896 item 12).
/// Every retained delivery, its terminal-or-open disposition, and the
/// bounded foreign/malformed evidence the owner left untouched.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmControlSpoolStatus {
    /// Operation identity this status covers.
    pub operation_id: String,
    /// Generation this status covers.
    pub generation: u64,
    /// Retained deliveries in sequence order.
    pub deliveries: Vec<WasmControlDeliveryStatus>,
    /// Next owner sequence the head would assign.
    pub next_sequence: u64,
    /// Staged files naming another operation, generation, or publisher,
    /// left in place as bounded evidence.
    pub foreign_files: u64,
    /// Unparseable or self-inconsistent staged files, left in place as
    /// bounded evidence.
    pub malformed_files: u64,
    /// Whether the scan hit the entry cap; when true the counts are
    /// lower bounds and publication fails closed until the directory is
    /// reclaimed by its owner.
    pub capped: bool,
}

/// Receipt for one owner control publication.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WasmControlPublishReceipt {
    /// Replay key of the offered delivery (stable across retries).
    pub replay_key: String,
    /// Operation identity of the offered delivery.
    pub operation_id: String,
    /// Generation of the offered delivery.
    pub generation: u64,
    /// Control kind of the offered delivery.
    pub control_kind: WasmControlKind,
    /// Owner sequence of the offered delivery.
    pub owner_sequence: u64,
    /// Digest of the offered delivery.
    pub delivery_digest: String,
    /// Disposition recorded for the offered delivery.
    pub disposition: ControlDisposition,
    /// Whether this call re-offered an already retained delivery under
    /// its existing identity instead of staging a fresh command.
    pub replayed: bool,
    /// Staged delivery path.
    pub delivery_path: String,
    /// Delivery expiry in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// Digest of the previous retained delivery, if any.
    pub previous_delivery_digest: Option<String>,
}

/// Owner-attested inputs for one control publication. The dispatch
/// adapter assembles these from the decided operation, the staged
/// dispatch material it published, the live session, and the
/// origin-control grant — the publisher never mints identities.
#[derive(Clone, Debug)]
pub struct WasmControlPublishInputs {
    /// Owner-derived spool root: the install directory holding the
    /// delivery set (the host path's parent, never a caller string).
    pub install_dir: std::path::PathBuf,
    /// Exact decided operation identity.
    pub operation_id: String,
    /// Admitted claim identity from the staged dispatch material.
    pub claim_id: String,
    /// Exact running process generation (non-zero).
    pub generation: u64,
    /// Control kind to publish.
    pub control_kind: WasmControlKind,
    /// Live authority epoch bound at publication.
    pub authority_epoch: EpochId,
    /// Live state fence bound at publication.
    pub state_fence: StateFence,
    /// Admitted work-scope identity from the staged material.
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
    /// Secret-bound origin-grant tag (recorded in the owner sidecar,
    /// never in the child-visible delivery).
    pub publisher_grant_digest: String,
    /// Origin-control decision time in Unix milliseconds.
    pub decided_at_unix_ms: u64,
    /// Owner clock reading in Unix milliseconds.
    pub now_unix_ms: u64,
}

/// Computes the deterministic replay key over the control identity.
fn control_replay_key(
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

/// Computes the delivery digest over the canonical envelope bytes.
fn control_delivery_digest(identity: &ControlDeliveryIdentity) -> Result<String, WasmControlError> {
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
    .map_err(|_| WasmControlError::InvalidControl("control-digest".to_owned()))?;
    Ok(sha256_hex(&bytes))
}

/// Returns the short operation tag embedded in the spool head filename:
/// the first sixteen hex characters of the operation digest, mirroring
/// the dispatch `short` contour so filenames stay bounded.
fn control_operation_tag(operation_id: &str) -> String {
    sha256_hex(operation_id.as_bytes())
        .chars()
        .take(16)
        .collect()
}

/// Returns the exact delivery filename for one generation and sequence.
fn control_delivery_name(generation: u64, sequence: u64) -> String {
    format!("{WASM_CONTROL_FILE_PREFIX}{generation}-{sequence:06}.json")
}

/// Returns the exact disposition-sidecar filename for one delivery.
fn control_disposition_name(generation: u64, sequence: u64) -> String {
    format!("{WASM_CONTROL_FILE_PREFIX}{generation}-{sequence:06}.disposition.json")
}

/// Returns the exact ack filename for one delivery.
fn control_ack_name(generation: u64, sequence: u64) -> String {
    format!("{WASM_CONTROL_FILE_PREFIX}{generation}-{sequence:06}.ack.json")
}

/// Returns the exact spool-head filename for one operation/generation.
fn control_head_name(generation: u64, operation_id: &str) -> String {
    format!(
        "{WASM_CONTROL_FILE_PREFIX}{generation}-{}.head.json",
        control_operation_tag(operation_id)
    )
}

/// Parses one spool filename into its generation, sequence, and suffix
/// class. Returns `None` for names outside this spool's vocabulary.
fn parse_control_name(name: &str) -> Option<(u64, u64, ControlFileClass)> {
    let rest = name.strip_prefix(WASM_CONTROL_FILE_PREFIX)?;
    let (class, rest) = if let Some(rest) = rest.strip_suffix(".disposition.json") {
        (ControlFileClass::Disposition, rest)
    } else if let Some(rest) = rest.strip_suffix(".ack.json") {
        (ControlFileClass::Ack, rest)
    } else if let Some(rest) = rest.strip_suffix(".head.json") {
        (ControlFileClass::Head, rest)
    } else if let Some(rest) = rest.strip_suffix(".tmp") {
        // Stale staging temp; the generation/sequence parse below still
        // applies to its stem so foreign temps are never touched.
        let (generation, _) = rest.rsplit_once('-')?;
        let generation = generation.parse::<u64>().ok()?;
        return Some((generation, 0, ControlFileClass::Temp));
    } else {
        let rest = rest.strip_suffix(".json")?;
        (ControlFileClass::Delivery, rest)
    };
    if class == ControlFileClass::Head {
        // Head names carry the operation tag instead of a sequence.
        let (generation, _) = rest.rsplit_once('-')?;
        let generation = generation.parse::<u64>().ok()?;
        return Some((generation, 0, class));
    }
    let (generation, sequence) = rest.rsplit_once('-')?;
    let generation = generation.parse::<u64>().ok()?;
    let sequence = sequence.parse::<u64>().ok()?;
    if generation == 0 || !sequence_is_canonical(sequence, rest) {
        return None;
    }
    Some((generation, sequence, class))
}

/// Spool filename class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlFileClass {
    /// Immutable owner delivery.
    Delivery,
    /// Owner disposition sidecar.
    Disposition,
    /// Child acknowledgement.
    Ack,
    /// Owner monotonic head.
    Head,
    /// Stale staging temp, owned for cleanup by exact name.
    Temp,
}

/// Reports whether the sequence renders in exactly the canonical
/// zero-padded form the publisher stages (`{sequence:06}`): any other
/// padding names a foreign file, so two names can never address one
/// sequence.
fn sequence_is_canonical(sequence: u64, rest: &str) -> bool {
    rest.rsplit_once('-').is_some_and(|(_, text)| {
        !text.is_empty()
            && text.bytes().all(|byte| byte.is_ascii_digit())
            && text == format!("{sequence:06}")
    })
}

/// Reads one spool file with the bounded byte contour: the length is
/// checked before and after the read so a concurrently grown file is
/// refused rather than truncated.
fn read_spool_file(path: &std::path::Path) -> Result<Vec<u8>, WasmControlError> {
    let denied = |_| invalid("spool-io");
    let length = std::fs::metadata(path).map_err(denied)?.len();
    if length == 0 || length > WASM_CONTROL_MAX_FILE_BYTES {
        return Err(invalid("spool-file-bounds"));
    }
    let bytes = std::fs::read(path).map_err(denied)?;
    if bytes.is_empty()
        || u64::try_from(bytes.len()).unwrap_or(u64::MAX) > WASM_CONTROL_MAX_FILE_BYTES
    {
        return Err(invalid("spool-file-bounds"));
    }
    Ok(bytes)
}

/// Stages one spool file atomically: write-temp-then-rename, so the
/// reader never observes partial JSON. Single writer (the Kernel
/// owner for deliveries, sidecars, and heads); the child stages only
/// its own ack names. Concurrent same-operation publishes are outside
/// the model: there is no `O_EXCL`, so interleaved same-sequence
/// publishes last-writer-win at the filesystem, but the loser is
/// self-detecting — the head/digest/sidecar join fails closed on
/// mismatch rather than running a blended command.
fn stage_spool_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), WasmControlError> {
    let denied = |_| invalid("spool-io");
    let mut temp = path.as_os_str().to_owned();
    temp.push(".tmp");
    let temp = std::path::PathBuf::from(temp);
    std::fs::write(&temp, bytes).map_err(denied)?;
    std::fs::rename(&temp, path).map_err(denied)?;
    Ok(())
}

/// One retained delivery joined with its disposition and ack.
struct ScannedDelivery {
    /// Owner sequence (equals the filename sequence).
    sequence: u64,
    /// Validated delivery envelope.
    delivery: WasmControlDelivery,
    /// Current disposition after the ack join.
    disposition: ControlDisposition,
    /// Bounded reason carried by the disposition, if any.
    reason: Option<String>,
}

/// One spool scan: retained deliveries plus bounded foreign evidence.
struct ControlSpoolScan {
    /// Retained deliveries in sequence order, dispositions joined.
    deliveries: Vec<ScannedDelivery>,
    /// Next owner sequence the head assigns (self-healed against the
    /// retained maximum).
    next_sequence: u64,
    /// Staged files outside this operation/generation/publisher.
    foreign_files: u64,
    /// Unparseable or self-inconsistent staged files.
    malformed_files: u64,
    /// Whether the scan hit the entry cap.
    capped: bool,
}

/// Validates one parsed delivery against its filename coordinates and
/// the requesting operation. Every binding is re-derived, never
/// trusted: sequence/name agreement, operation/invocation/claim
/// identity, generation, digests, replay key, and window order.
fn validate_scanned_delivery(
    delivery: &WasmControlDelivery,
    name_generation: u64,
    name_sequence: u64,
    operation_id: &str,
) -> Result<(), ()> {
    let identity = &delivery.identity;
    if delivery.wire_id != WASM_CONTROL_DELIVERY_WIRE_ID
        || delivery.wire_version != WASM_CONTROL_DELIVERY_WIRE_VERSION
        || identity.operation_id != operation_id
        || identity.invocation_id != identity.operation_id
        || identity.generation != name_generation
        || identity.owner_sequence != name_sequence
        || identity.claim_id.trim().is_empty()
        || identity.work_scope.trim().is_empty()
        || identity.principal_digest.trim().is_empty()
        || identity.session_connection.trim().is_empty()
        || identity.session_epoch == 0
        || identity.publisher_challenge_id.trim().is_empty()
        || identity.publisher_operation.trim().is_empty()
        || identity.publisher_decided_at_unix_ms == 0
        || identity.deadline_unix_ms <= identity.publisher_decided_at_unix_ms
    {
        return Err(());
    }
    if identity.dispatch_grant_digest.len() != 64
        || !identity
            .dispatch_grant_digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(());
    }
    let replay_key = control_replay_key(
        &identity.operation_id,
        identity.generation,
        identity.control_kind,
        identity.owner_sequence,
    );
    if identity.replay_key != replay_key {
        return Err(());
    }
    let digest = control_delivery_digest(identity).map_err(|_| ())?;
    if delivery.delivery_digest != digest {
        return Err(());
    }
    Ok(())
}

/// Validates one parsed ack against the exact delivery it claims: wire,
/// replay key, operation, generation, sequence, and digest must all
/// agree, and phase/detail/outcome must follow the closed shapes.
fn validate_control_ack(ack: &WasmControlAck, delivery: &WasmControlDelivery) -> Result<(), ()> {
    let identity = &delivery.identity;
    if ack.wire_id != WASM_CONTROL_ACK_WIRE_ID
        || ack.wire_version != WASM_CONTROL_ACK_WIRE_VERSION
        || ack.replay_key != identity.replay_key
        || ack.operation_id != identity.operation_id
        || ack.generation != identity.generation
        || ack.owner_sequence != identity.owner_sequence
        || ack.delivery_digest != delivery.delivery_digest
    {
        return Err(());
    }
    match (&ack.phase, &ack.detail, &ack.outcome_digest) {
        (ControlAckPhase::Enqueued, detail, None) => {
            if let Some(detail) = detail {
                require_detail(detail, "ack-detail").map_err(|_| ())?;
            }
            Ok(())
        }
        (ControlAckPhase::Completed, detail, outcome) => {
            if let Some(detail) = detail {
                require_detail(detail, "ack-detail").map_err(|_| ())?;
            }
            if let Some(outcome) = outcome {
                require_digest(outcome, "ack-outcome").map_err(|_| ())?;
            }
            Ok(())
        }
        (ControlAckPhase::Refused, Some(detail), None) => {
            require_detail(detail, "ack-detail").map_err(|_| ())?;
            Ok(())
        }
        (ControlAckPhase::Refused, None, _) | (_, _, Some(_)) => Err(()),
    }
}

/// Validates one parsed disposition sidecar against the exact delivery
/// it records.
fn validate_disposition_record(
    record: &ControlDispositionRecord,
    delivery: &WasmControlDelivery,
) -> Result<(), ()> {
    let identity = &delivery.identity;
    if record.wire_id != WASM_CONTROL_DISPOSITION_WIRE_ID
        || record.wire_version != WASM_CONTROL_DISPOSITION_WIRE_VERSION
        || record.replay_key != identity.replay_key
        || record.operation_id != identity.operation_id
        || record.generation != identity.generation
        || record.owner_sequence != identity.owner_sequence
        || record.control_kind != identity.control_kind
        || record.delivery_digest != delivery.delivery_digest
        || record.publisher_grant_digest.trim().is_empty()
        || record.updated_at_unix_ms == 0
    {
        return Err(());
    }
    if let Some(reason) = &record.reason {
        require_detail(reason, "disposition-reason").map_err(|_| ())?;
    }
    Ok(())
}

/// Advances one disposition through a validated ack phase. Terminal
/// dispositions never move; anything else follows the ack, with
/// `completed` and `refused` closing the delivery.
fn advance_disposition(
    current: ControlDisposition,
    ack: &WasmControlAck,
    sidecar_valid: bool,
) -> (ControlDisposition, Option<String>) {
    if current.is_terminal() {
        return (current, None);
    }
    // A decisive ack over an unreadable sidecar still closes honestly,
    // but the recovery marker preserves the forensic trace.
    let recovered = |reason: Option<String>| {
        if sidecar_valid {
            reason
        } else {
            Some("recovered-after-unreadable-disposition".to_owned())
        }
    };
    match ack.phase {
        ControlAckPhase::Enqueued => (ControlDisposition::Accepted, recovered(None)),
        ControlAckPhase::Completed => (ControlDisposition::Completed, recovered(None)),
        ControlAckPhase::Refused => (ControlDisposition::Refused, recovered(ack.detail.clone())),
    }
}

/// Scans one operation/generation spool: classifies every staged file,
/// joins acks into dispositions (persisting advances), removes the
/// owner's own stale staging temps by exact name, and reports bounded
/// foreign/malformed evidence. Never deletes a delivery, sidecar, ack,
/// or head: retirement is the publisher's explicit pressure valve.
/// Reaps one staging temp when the owner staged it: a delivery,
/// sidecar, or head stem at this generation. Ack staging belongs to the
/// child and foreign temps are never touched.
fn reap_owner_temp(name: &str, path: &std::path::Path, generation: u64) {
    let Some(stem) = name.strip_suffix(".tmp") else {
        return;
    };
    let owner_temp = parse_control_name(stem).is_some_and(|(stem_generation, _, stem_class)| {
        stem_generation == generation
            && matches!(
                stem_class,
                ControlFileClass::Delivery | ControlFileClass::Disposition | ControlFileClass::Head
            )
    });
    if owner_temp {
        let _ = std::fs::remove_file(path);
    }
}

/// Joins one scanned delivery with its disposition sidecar and ack:
/// validated records decide; an unreadable sidecar rests at Unknown under
/// the same identity (never not-sent, never a fresh replay) until an ack
/// or a terminal note decides it; a valid ack advances the disposition and
/// the advance persists. Counter updates report foreign/malformed evidence
/// to the caller.
#[allow(clippy::too_many_arguments)]
fn join_scanned_delivery(
    install_dir: &std::path::Path,
    generation: u64,
    sequence: u64,
    delivery: &WasmControlDelivery,
    now_unix_ms: u64,
    foreign_files: &mut u64,
    malformed_files: &mut u64,
) -> Result<ScannedDelivery, WasmControlError> {
    let sidecar_path = install_dir.join(control_disposition_name(generation, sequence));
    let ack_path = install_dir.join(control_ack_name(generation, sequence));
    let (mut disposition, mut reason, sidecar_valid) = match std::fs::metadata(&sidecar_path) {
        Ok(_) => {
            let parsed = read_spool_file(&sidecar_path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<ControlDispositionRecord>(&bytes).ok());
            match parsed {
                Some(record) if validate_disposition_record(&record, delivery).is_ok() => {
                    (record.disposition, record.reason, true)
                }
                // An unreadable sidecar never degrades into
                // not-sent and never replays as fresh: it rests
                // at Unknown under the same identity until an
                // ack or a terminal note decides it.
                _ => {
                    *malformed_files = malformed_files.saturating_add(1);
                    (
                        ControlDisposition::Unknown,
                        Some("disposition-unreadable".to_owned()),
                        false,
                    )
                }
            }
        }
        Err(_) => (ControlDisposition::Prepared, None, true),
    };
    if std::fs::metadata(&ack_path).is_ok() {
        let parsed = read_spool_file(&ack_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<WasmControlAck>(&bytes).ok());
        match parsed {
            Some(ack) if validate_control_ack(&ack, delivery).is_ok() => {
                let (advanced, advanced_reason) =
                    advance_disposition(disposition, &ack, sidecar_valid);
                if advanced != disposition || advanced_reason != reason {
                    disposition = advanced;
                    reason = advanced_reason;
                    persist_disposition(
                        install_dir,
                        delivery,
                        disposition,
                        reason.clone(),
                        current_publisher_grant(install_dir, generation, sequence, delivery),
                        now_unix_ms,
                    )?;
                }
            }
            Some(_) => {
                *foreign_files = foreign_files.saturating_add(1);
            }
            None => {
                *malformed_files = malformed_files.saturating_add(1);
            }
        }
    }
    Ok(ScannedDelivery {
        sequence,
        delivery: delivery.clone(),
        disposition,
        reason,
    })
}

/// Folds one spool head file into the running head cursor: out-of-generation
/// or mismatched heads count as foreign, unparseable ones as malformed,
/// and a bound head raises the cursor to its next sequence.
#[allow(clippy::too_many_arguments)]
fn fold_head_file(
    path: &std::path::Path,
    name_generation: u64,
    generation: u64,
    operation_id: &str,
    head_next: u64,
    foreign_files: &mut u64,
    malformed_files: &mut u64,
) -> u64 {
    if name_generation != generation {
        *foreign_files = foreign_files.saturating_add(1);
        return head_next;
    }
    let parsed = read_spool_file(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<WasmControlSpoolHead>(&bytes).ok());
    let Some(head) = parsed else {
        *malformed_files = malformed_files.saturating_add(1);
        return head_next;
    };
    if head.wire_id != WASM_CONTROL_HEAD_WIRE_ID
        || head.wire_version != WASM_CONTROL_HEAD_WIRE_VERSION
        || head.generation != generation
        || head.operation_id != operation_id
    {
        *foreign_files = foreign_files.saturating_add(1);
        return head_next;
    }
    head_next.max(head.next_sequence)
}

fn scan_control_spool(
    install_dir: &std::path::Path,
    operation_id: &str,
    generation: u64,
    now_unix_ms: u64,
) -> Result<ControlSpoolScan, WasmControlError> {
    let denied = |_| invalid("spool-io");
    let mut deliveries: Vec<(u64, WasmControlDelivery)> = Vec::new();
    let mut head_next: u64 = 0;
    let mut foreign_files: u64 = 0;
    let mut malformed_files: u64 = 0;
    let mut classified: usize = 0;
    let mut capped = false;
    let foreign = |count: &mut u64| {
        *count = count.saturating_add(1);
    };
    let entries = std::fs::read_dir(install_dir).map_err(denied)?;
    for entry in entries {
        let entry = entry.map_err(denied)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Names outside this spool's vocabulary belong to the delivery
        // set or the legacy file: not ours, not counted.
        let Some((name_generation, name_sequence, class)) = parse_control_name(&name) else {
            continue;
        };
        classified = classified.saturating_add(1);
        if classified > WASM_CONTROL_SPOOL_SCAN_CAP {
            capped = true;
            break;
        }
        let path = entry.path();
        match class {
            ControlFileClass::Delivery => {
                if name_generation != generation {
                    foreign(&mut foreign_files);
                    continue;
                }
                let parsed = read_spool_file(&path)
                    .ok()
                    .and_then(|bytes| serde_json::from_slice::<WasmControlDelivery>(&bytes).ok());
                let Some(delivery) = parsed else {
                    foreign(&mut malformed_files);
                    continue;
                };
                if delivery.identity.operation_id != operation_id {
                    // Same directory, another operation's spool: leave it.
                    foreign(&mut foreign_files);
                    continue;
                }
                if validate_scanned_delivery(
                    &delivery,
                    name_generation,
                    name_sequence,
                    operation_id,
                )
                .is_err()
                {
                    foreign(&mut malformed_files);
                    continue;
                }
                deliveries.push((name_sequence, delivery));
            }
            ControlFileClass::Head => {
                head_next = fold_head_file(
                    &path,
                    name_generation,
                    generation,
                    operation_id,
                    head_next,
                    &mut foreign_files,
                    &mut malformed_files,
                );
            }
            ControlFileClass::Disposition | ControlFileClass::Ack => {
                // Sidecars and acks join by exact name below; only the
                // out-of-generation ones count here without a read.
                if name_generation != generation {
                    foreign(&mut foreign_files);
                }
            }
            ControlFileClass::Temp => reap_owner_temp(&name, &path, generation),
        }
    }
    deliveries.sort_by_key(|(sequence, _)| *sequence);
    let mut joined = Vec::with_capacity(deliveries.len());
    for (sequence, delivery) in &deliveries {
        joined.push(join_scanned_delivery(
            install_dir,
            generation,
            *sequence,
            delivery,
            now_unix_ms,
            &mut foreign_files,
            &mut malformed_files,
        )?);
    }
    let retained_max = joined.iter().map(|scanned| scanned.sequence).max();
    let mut next_sequence = head_next;
    if let Some(max) = retained_max {
        next_sequence = next_sequence.max(max.saturating_add(1));
    }
    Ok(ControlSpoolScan {
        deliveries: joined,
        next_sequence,
        foreign_files,
        malformed_files,
        capped,
    })
}

/// Returns the publisher-grant tag to retain when an ack advance rewrites
/// a sidecar: the existing valid record's tag, so the publisher receipt
/// survives the join; absent or invalid records cannot advance through
/// this path without one.
fn current_publisher_grant(
    install_dir: &std::path::Path,
    generation: u64,
    sequence: u64,
    delivery: &WasmControlDelivery,
) -> String {
    let path = install_dir.join(control_disposition_name(generation, sequence));
    let parsed = read_spool_file(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ControlDispositionRecord>(&bytes).ok());
    match parsed {
        Some(record) if validate_disposition_record(&record, delivery).is_ok() => {
            record.publisher_grant_digest
        }
        // No valid prior record: the ack joins a Prepared delivery whose
        // offer never recorded. The grant tag is unknown here, so the
        // join records the delivery's own publisher correlation instead
        // of minting a tag: challenge identity plus decision time.
        _ => format!(
            "challenge:{}@{}",
            delivery.identity.publisher_challenge_id,
            delivery.identity.publisher_decided_at_unix_ms
        ),
    }
}

/// Persists one disposition sidecar atomically under its exact name.
#[allow(clippy::too_many_arguments)]
fn persist_disposition(
    install_dir: &std::path::Path,
    delivery: &WasmControlDelivery,
    disposition: ControlDisposition,
    reason: Option<String>,
    publisher_grant_digest: String,
    now_unix_ms: u64,
) -> Result<(), WasmControlError> {
    let identity = &delivery.identity;
    let record = ControlDispositionRecord {
        wire_id: WASM_CONTROL_DISPOSITION_WIRE_ID.to_owned(),
        wire_version: WASM_CONTROL_DISPOSITION_WIRE_VERSION,
        replay_key: identity.replay_key.clone(),
        operation_id: identity.operation_id.clone(),
        generation: identity.generation,
        owner_sequence: identity.owner_sequence,
        control_kind: identity.control_kind,
        disposition,
        reason,
        publisher_grant_digest,
        delivery_digest: delivery.delivery_digest.clone(),
        updated_at_unix_ms: now_unix_ms,
    };
    let bytes = serde_json::to_vec(&record).map_err(|_| invalid("disposition-encode"))?;
    let path = install_dir.join(control_disposition_name(
        identity.generation,
        identity.owner_sequence,
    ));
    stage_spool_file(&path, &bytes)
}

fn require_token(value: &str, field: &'static str) -> Result<(), WasmControlError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(invalid(field));
    }
    Ok(())
}

/// Validates owner publication inputs: every identity is a bounded
/// control-free token, every digest hex-shaped, the generation and
/// session epoch non-zero, the fence live and bound to this generation
/// and epoch, and the decision window current (no skew, no stale
/// decision).
fn validate_publish_inputs(inputs: &WasmControlPublishInputs) -> Result<(), WasmControlError> {
    if !inputs.install_dir.is_absolute() {
        return Err(invalid("spool-root"));
    }
    require_token(&inputs.operation_id, "control-operation")?;
    require_token(&inputs.claim_id, "control-claim")?;
    require_token(&inputs.work_scope, "control-scope")?;
    require_token(&inputs.principal_digest, "control-principal")?;
    require_token(&inputs.session_connection, "control-session")?;
    require_token(&inputs.publisher_challenge_id, "control-challenge")?;
    require_token(&inputs.publisher_operation, "control-publisher-op")?;
    require_token(&inputs.publisher_grant_digest, "control-grant")?;
    require_digest(&inputs.dispatch_grant_digest, "control-dispatch-grant")?;
    if inputs.generation == 0 {
        return Err(invalid("control-generation"));
    }
    if inputs.session_epoch == 0 {
        return Err(invalid("control-session-epoch"));
    }
    if inputs.decided_at_unix_ms == 0 || inputs.now_unix_ms == 0 {
        return Err(invalid("control-time"));
    }
    if inputs.decided_at_unix_ms > inputs.now_unix_ms {
        return Err(invalid("control-skew"));
    }
    let deadline = inputs
        .decided_at_unix_ms
        .saturating_add(WASM_CONTROL_GRANT_WINDOW_MS);
    if deadline <= inputs.decided_at_unix_ms || inputs.now_unix_ms > deadline {
        return Err(invalid("control-window"));
    }
    inputs
        .state_fence
        .validate()
        .map_err(|_| invalid("control-fence"))?;
    if inputs.state_fence.resource_generation.value() != inputs.generation {
        return Err(invalid("control-fence-generation"));
    }
    if !inputs
        .state_fence
        .authority_epoch
        .is_same_authority(&inputs.authority_epoch)
    {
        return Err(invalid("control-epoch"));
    }
    Ok(())
}

/// Retires terminal delivery triples (delivery, sidecar, ack) by exact
/// name. Only `Completed` and `Refused` dispositions retire, and only
/// under publication pressure; open and unknown deliveries are never
/// touched, and deletion failures simply keep the files (and their
/// capacity pressure) in place.
fn retire_terminal_deliveries(
    install_dir: &std::path::Path,
    generation: u64,
    scan: &ControlSpoolScan,
) {
    for scanned in &scan.deliveries {
        if !scanned.disposition.is_terminal() {
            continue;
        }
        let _ = std::fs::remove_file(
            install_dir.join(control_delivery_name(generation, scanned.sequence)),
        );
        let _ = std::fs::remove_file(
            install_dir.join(control_disposition_name(generation, scanned.sequence)),
        );
        let _ =
            std::fs::remove_file(install_dir.join(control_ack_name(generation, scanned.sequence)));
    }
}

/// Advances the monotonic spool head to at least `next_sequence`. An
/// absent or lagging head self-heals; a head naming another operation
/// under this exact filename is a tag collision and fails closed
/// rather than overwriting a foreign sequence.
fn advance_spool_head(
    install_dir: &std::path::Path,
    operation_id: &str,
    generation: u64,
    next_sequence: u64,
    now_unix_ms: u64,
) -> Result<(), WasmControlError> {
    let path = install_dir.join(control_head_name(generation, operation_id));
    if std::fs::metadata(&path).is_ok() {
        let parsed = read_spool_file(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<WasmControlSpoolHead>(&bytes).ok());
        match parsed {
            Some(head)
                if head.wire_id == WASM_CONTROL_HEAD_WIRE_ID
                    && head.wire_version == WASM_CONTROL_HEAD_WIRE_VERSION
                    && head.generation == generation
                    && head.operation_id == operation_id => {}
            _ => return Err(WasmControlError::IdentityConflict),
        }
    }
    let head = WasmControlSpoolHead {
        wire_id: WASM_CONTROL_HEAD_WIRE_ID.to_owned(),
        wire_version: WASM_CONTROL_HEAD_WIRE_VERSION,
        operation_id: operation_id.to_owned(),
        generation,
        next_sequence,
        updated_at_unix_ms: now_unix_ms,
    };
    let bytes = serde_json::to_vec(&head).map_err(|_| invalid("head-encode"))?;
    stage_spool_file(&path, &bytes)
}

/// Publishes one owner control delivery for the exact running WASM
/// operation.
///
/// The spool is reconciled first (ack join, disposition advance), then
/// the replay rule applies: a retained same-kind delivery that is not
/// terminal is re-offered under its existing identity — a lost
/// response or a restart reconciles the same control, it never mints a
/// fresh command. Otherwise a fresh monotonic sequence stages under
/// capacity and reserve admission, chained to its predecessor, and the
/// offer is retained before the receipt returns.
///
/// # Errors
///
/// Returns [`WasmControlError`] when the inputs fail closed, the bounded
/// spool (or the Reconcile lane outside the reserve) is saturated, or a
/// reused sequence binds different content.
#[allow(clippy::too_many_lines)]
pub fn publish_wasm_control_delivery(
    inputs: &WasmControlPublishInputs,
) -> Result<WasmControlPublishReceipt, WasmControlError> {
    validate_publish_inputs(inputs)?;
    let install_dir = inputs.install_dir.as_path();
    let scan = scan_control_spool(
        install_dir,
        &inputs.operation_id,
        inputs.generation,
        inputs.now_unix_ms,
    )?;
    if scan.capped {
        return Err(WasmControlError::SpoolSaturated);
    }
    // Replay rule: the same control under the same identity, never a
    // fresh command for an open or unknown delivery.
    if let Some(replayed) = scan.deliveries.iter().find(|scanned| {
        scanned.delivery.identity.control_kind == inputs.control_kind
            && !scanned.disposition.is_terminal()
    }) {
        let previous = scan
            .deliveries
            .iter()
            .filter(|scanned| scanned.sequence < replayed.sequence)
            .map(|scanned| scanned.delivery.delivery_digest.clone())
            .next_back();
        let path = install_dir.join(control_delivery_name(inputs.generation, replayed.sequence));
        return Ok(WasmControlPublishReceipt {
            replay_key: replayed.delivery.identity.replay_key.clone(),
            operation_id: inputs.operation_id.clone(),
            generation: inputs.generation,
            control_kind: inputs.control_kind,
            owner_sequence: replayed.sequence,
            delivery_digest: replayed.delivery.delivery_digest.clone(),
            disposition: replayed.disposition,
            replayed: true,
            delivery_path: path.to_string_lossy().into_owned(),
            deadline_unix_ms: replayed.delivery.identity.deadline_unix_ms,
            previous_delivery_digest: previous,
        });
    }
    // Fresh command: retire terminal triples first, then admit under
    // capacity with the Cancel/Shutdown reserve preserved.
    retire_terminal_deliveries(install_dir, inputs.generation, &scan);
    let live = scan
        .deliveries
        .iter()
        .filter(|scanned| !scanned.disposition.is_terminal())
        .count();
    if live >= WASM_CONTROL_SPOOL_MAX_DELIVERIES
        || (!inputs.control_kind.uses_reserve()
            && live + WASM_CONTROL_SPOOL_RESERVE_SLOTS >= WASM_CONTROL_SPOOL_MAX_DELIVERIES)
    {
        return Err(WasmControlError::SpoolSaturated);
    }
    let sequence = scan.next_sequence;
    let previous = scan
        .deliveries
        .iter()
        .filter(|scanned| !scanned.disposition.is_terminal())
        .map(|scanned| scanned.delivery.delivery_digest.clone())
        .next_back();
    let deadline = inputs
        .decided_at_unix_ms
        .saturating_add(WASM_CONTROL_GRANT_WINDOW_MS);
    let identity = ControlDeliveryIdentity {
        operation_id: inputs.operation_id.clone(),
        invocation_id: inputs.operation_id.clone(),
        claim_id: inputs.claim_id.clone(),
        generation: inputs.generation,
        control_kind: inputs.control_kind,
        owner_sequence: sequence,
        authority_epoch: inputs.authority_epoch.clone(),
        state_fence: inputs.state_fence.clone(),
        work_scope: inputs.work_scope.clone(),
        principal_digest: inputs.principal_digest.clone(),
        session_connection: inputs.session_connection.clone(),
        session_epoch: inputs.session_epoch,
        dispatch_grant_digest: inputs.dispatch_grant_digest.clone(),
        publisher_challenge_id: inputs.publisher_challenge_id.clone(),
        publisher_operation: inputs.publisher_operation.clone(),
        publisher_decided_at_unix_ms: inputs.decided_at_unix_ms,
        deadline_unix_ms: deadline,
        replay_key: control_replay_key(
            &inputs.operation_id,
            inputs.generation,
            inputs.control_kind,
            sequence,
        ),
        previous_delivery_digest: previous.clone(),
    };
    let delivery = WasmControlDelivery {
        wire_id: WASM_CONTROL_DELIVERY_WIRE_ID.to_owned(),
        wire_version: WASM_CONTROL_DELIVERY_WIRE_VERSION,
        delivery_digest: control_delivery_digest(&identity)?,
        identity,
    };
    let bytes = serde_json::to_vec(&delivery).map_err(|_| invalid("control-encode"))?;
    let path = install_dir.join(control_delivery_name(inputs.generation, sequence));
    // Defense in depth: the computed sequence must be fresh. Byte-identical
    // content adopts the existing delivery as a replay; anything else is an
    // identity conflict, and the unexpected file stays as evidence.
    if std::fs::metadata(&path).is_ok() {
        let staged = read_spool_file(&path).map_err(|_| WasmControlError::IdentityConflict)?;
        if staged != bytes {
            return Err(WasmControlError::IdentityConflict);
        }
        let staged_delivery = serde_json::from_slice::<WasmControlDelivery>(&staged)
            .map_err(|_| WasmControlError::IdentityConflict)?;
        if validate_scanned_delivery(
            &staged_delivery,
            inputs.generation,
            sequence,
            &inputs.operation_id,
        )
        .is_err()
        {
            return Err(WasmControlError::IdentityConflict);
        }
        advance_spool_head(
            install_dir,
            &inputs.operation_id,
            inputs.generation,
            sequence.saturating_add(1),
            inputs.now_unix_ms,
        )?;
        let disposition = read_recorded_disposition(&staged_delivery, install_dir);
        return Ok(WasmControlPublishReceipt {
            replay_key: staged_delivery.identity.replay_key.clone(),
            operation_id: inputs.operation_id.clone(),
            generation: inputs.generation,
            control_kind: inputs.control_kind,
            owner_sequence: sequence,
            delivery_digest: staged_delivery.delivery_digest.clone(),
            disposition,
            replayed: true,
            delivery_path: path.to_string_lossy().into_owned(),
            deadline_unix_ms: staged_delivery.identity.deadline_unix_ms,
            previous_delivery_digest: previous,
        });
    }
    stage_spool_file(&path, &bytes)?;
    advance_spool_head(
        install_dir,
        &inputs.operation_id,
        inputs.generation,
        sequence.saturating_add(1),
        inputs.now_unix_ms,
    )?;
    persist_disposition(
        install_dir,
        &delivery,
        ControlDisposition::Offered,
        None,
        inputs.publisher_grant_digest.clone(),
        inputs.now_unix_ms,
    )?;
    Ok(WasmControlPublishReceipt {
        replay_key: delivery.identity.replay_key.clone(),
        operation_id: inputs.operation_id.clone(),
        generation: inputs.generation,
        control_kind: inputs.control_kind,
        owner_sequence: sequence,
        delivery_digest: delivery.delivery_digest.clone(),
        disposition: ControlDisposition::Offered,
        replayed: false,
        delivery_path: path.to_string_lossy().into_owned(),
        deadline_unix_ms: delivery.identity.deadline_unix_ms,
        previous_delivery_digest: previous,
    })
}

/// Reads the recorded disposition for one delivery without joining
/// acks: the valid sidecar's disposition, `Prepared` when absent, or
/// `Unknown` when unreadable.
fn read_recorded_disposition(
    delivery: &WasmControlDelivery,
    install_dir: &std::path::Path,
) -> ControlDisposition {
    let identity = &delivery.identity;
    let path = install_dir.join(control_disposition_name(
        identity.generation,
        identity.owner_sequence,
    ));
    if std::fs::metadata(&path).is_err() {
        return ControlDisposition::Prepared;
    }
    let parsed = read_spool_file(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ControlDispositionRecord>(&bytes).ok());
    match parsed {
        Some(record) if validate_disposition_record(&record, delivery).is_ok() => {
            record.disposition
        }
        _ => ControlDisposition::Unknown,
    }
}

/// Records supervised termination for one offered delivery (I14.21:
/// unknown commit recovery pauses and preserves instead of blindly
/// duplicating the effect).
///
/// After the gateway kill is acknowledged, a decisive ack still wins —
/// a `completed` ack proves the exact outcome was observed, a `refused`
/// ack proves the child refused — but anything else rests at `Unknown`
/// under the same identity: sent, response lost, never silently
/// re-sent as fresh and never revived once terminal.
///
/// # Errors
///
/// Returns [`WasmControlError`] when the coordinates fail closed, the
/// delivery is missing or foreign, or the owner cannot retain the note.
pub fn note_wasm_control_supervised_end(
    install_dir: &std::path::Path,
    operation_id: &str,
    generation: u64,
    owner_sequence: u64,
    termination: &str,
    now_unix_ms: u64,
) -> Result<ControlDispositionRecord, WasmControlError> {
    if !install_dir.is_absolute() {
        return Err(invalid("spool-root"));
    }
    require_token(operation_id, "control-operation")?;
    require_detail(termination, "control-termination")?;
    if generation == 0 || now_unix_ms == 0 {
        return Err(invalid("control-coordinates"));
    }
    let path = install_dir.join(control_delivery_name(generation, owner_sequence));
    let delivery = read_spool_file(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<WasmControlDelivery>(&bytes).ok())
        .ok_or_else(|| invalid("control-missing"))?;
    validate_scanned_delivery(&delivery, generation, owner_sequence, operation_id)
        .map_err(|()| invalid("control-binding"))?;
    let recorded = read_recorded_disposition(&delivery, install_dir);
    if recorded.is_terminal() {
        // Terminal dispositions never move; re-read the valid record.
        let sidecar = install_dir.join(control_disposition_name(generation, owner_sequence));
        let record = read_spool_file(&sidecar)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<ControlDispositionRecord>(&bytes).ok())
            .ok_or_else(|| invalid("control-missing"))?;
        return Ok(record);
    }
    // A decisive ack observed at termination time still decides.
    let ack_path = install_dir.join(control_ack_name(generation, owner_sequence));
    if std::fs::metadata(&ack_path).is_ok() {
        let parsed = read_spool_file(&ack_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<WasmControlAck>(&bytes).ok());
        if let Some(ack) = parsed
            && validate_control_ack(&ack, &delivery).is_ok()
        {
            match ack.phase {
                ControlAckPhase::Completed => {
                    return persist_termination_record(
                        install_dir,
                        &delivery,
                        ControlDisposition::Completed,
                        None,
                        now_unix_ms,
                    );
                }
                ControlAckPhase::Refused => {
                    return persist_termination_record(
                        install_dir,
                        &delivery,
                        ControlDisposition::Refused,
                        ack.detail.clone(),
                        now_unix_ms,
                    );
                }
                ControlAckPhase::Enqueued => {}
            }
        }
    }
    persist_termination_record(
        install_dir,
        &delivery,
        ControlDisposition::Unknown,
        Some(termination.to_owned()),
        now_unix_ms,
    )
}

/// Persists one termination disposition, retaining the existing valid
/// publisher-grant tag or the delivery's publisher correlation when no
/// valid record exists yet.
fn persist_termination_record(
    install_dir: &std::path::Path,
    delivery: &WasmControlDelivery,
    disposition: ControlDisposition,
    reason: Option<String>,
    now_unix_ms: u64,
) -> Result<ControlDispositionRecord, WasmControlError> {
    let identity = &delivery.identity;
    let grant = current_publisher_grant(
        install_dir,
        identity.generation,
        identity.owner_sequence,
        delivery,
    );
    persist_disposition(
        install_dir,
        delivery,
        disposition,
        reason.clone(),
        grant.clone(),
        now_unix_ms,
    )?;
    Ok(ControlDispositionRecord {
        wire_id: WASM_CONTROL_DISPOSITION_WIRE_ID.to_owned(),
        wire_version: WASM_CONTROL_DISPOSITION_WIRE_VERSION,
        replay_key: identity.replay_key.clone(),
        operation_id: identity.operation_id.clone(),
        generation: identity.generation,
        owner_sequence: identity.owner_sequence,
        control_kind: identity.control_kind,
        disposition,
        reason,
        publisher_grant_digest: grant,
        delivery_digest: delivery.delivery_digest.clone(),
        updated_at_unix_ms: now_unix_ms,
    })
}

/// Reconciles one operation/generation spool and reports its status
/// for recovery and status surfaces (issue #2896 item 12): acks join
/// into dispositions (advances are persisted), and every retained
/// delivery keeps its terminal-or-open distinction across restarts.
///
/// # Errors
///
/// Returns [`WasmControlError`] when the coordinates fail closed or the
/// owner cannot read or retain the spool.
pub fn reconcile_wasm_control_spool(
    install_dir: &std::path::Path,
    operation_id: &str,
    generation: u64,
    now_unix_ms: u64,
) -> Result<WasmControlSpoolStatus, WasmControlError> {
    if !install_dir.is_absolute() {
        return Err(invalid("spool-root"));
    }
    require_token(operation_id, "control-operation")?;
    if generation == 0 || now_unix_ms == 0 {
        return Err(invalid("control-coordinates"));
    }
    let scan = scan_control_spool(install_dir, operation_id, generation, now_unix_ms)?;
    Ok(WasmControlSpoolStatus {
        operation_id: operation_id.to_owned(),
        generation,
        deliveries: scan
            .deliveries
            .iter()
            .map(|scanned| WasmControlDeliveryStatus {
                replay_key: scanned.delivery.identity.replay_key.clone(),
                control_kind: scanned.delivery.identity.control_kind,
                owner_sequence: scanned.sequence,
                disposition: scanned.disposition,
                reason: scanned.reason.clone(),
                delivery_digest: scanned.delivery.delivery_digest.clone(),
                deadline_unix_ms: scanned.delivery.identity.deadline_unix_ms,
            })
            .collect(),
        next_sequence: scan.next_sequence,
        foreign_files: scan.foreign_files,
        malformed_files: scan.malformed_files,
        capped: scan.capped,
    })
}
