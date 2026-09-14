//! Kernel-side native-worker durable-replay envelope (T9-03, issue #22).
//!
//! Pure types plus validation for the owner-backed replay transport: the five
//! `DurableReplayPort` methods map 1:1 onto this wire family with no generic
//! JSON dispatcher:
//!
//! | `DurableReplayPort` method | request | reply |
//! | --- | --- | --- |
//! | `lookup_request` | [`NativeWorkerReplayLookupRequest`] | [`NativeWorkerReplayLookupReply`] |
//! | `begin_request` | [`NativeWorkerReplayBeginRequest`] | [`NativeWorkerReplayBeginReply`] |
//! | `append` | [`NativeWorkerReplayAppendRequest`] | [`NativeWorkerReplayAppendReply`] |
//! | `replay` | [`NativeWorkerReplayReplayRequest`] | [`NativeWorkerReplayReplayReply`] |
//! | `acknowledge` | [`NativeWorkerReplayAcknowledgeRequest`] | [`NativeWorkerReplayAcknowledgeReply`] |
//!
//! Stream identity is `(claim id, worker generation)`, rendered
//! [`replay_stream_id`] as `"{claim_id}/gen-{generation}"` (for example the
//! T9-02 fixture claim `stream-claim-t9-02-1` at generation 1 reads
//! `stream-claim-t9-02-1/gen-1`). The producer cursor advances only at
//! [`NativeWorkerReplayAckPhase::Durable`]; the consumer cursor advances only
//! at [`NativeWorkerReplayAckPhase::Applied`] or
//! [`NativeWorkerReplayAckPhase::Rejected`];
//! [`NativeWorkerReplayAckPhase::Unknown`] never advances either cursor and is
//! preserved end to end so a transport-level unknown can never impersonate an
//! application-level commit. Retention releases only on `APPLIED`/`REJECTED`
//! (see [`NativeWorkerReplayAckPhase::retention_releasable`]); reads stay
//! bounded through [`NATIVE_WORKER_REPLAY_MAX_PAGE`], which mirrors the ORS
//! `MAX_RECOVERY_PAGE = 256` precedent, so a new generation catches up on old
//! history in bounded pages and never executes under an old epoch.
//!
//! This is a new wire family, so it starts at version 1: it mirrors the claim
//! wire history, where the claim wire shipped at v1 and only moved to v2 at
//! `native_worker_claim.rs:51-70` when the executable-binding join landed. A
//! replay revision bump would follow the same explicit-reject precedent,
//! never a silent promotion.
//!
//! Every replay operation is admitted through [`admit_replay_request`], which
//! enforces the T9-02 gate on this transport: the presented stream binding
//! must name the exact `{claim}/gen-{generation}` construction, the carried
//! executable binding digest must equal the current owner digest, and the
//! presented epoch/fence must be current. A stale binding — changed digest,
//! advanced epoch, withdrawn authority, foreign claim — is refused; it needs
//! a new admission, never a local repair. Generation authorization splits
//! reads from acquires: `lookup`/`replay` may address old-generation history
//! (a new generation reads history); `begin`/`append`/`acknowledge` require
//! the current generation and epoch, because they claim identity or mutate
//! durable cursor state. Requiring currency for `acknowledge` is the
//! conservative read of the T9-03 slice: an ack mutates cursor state, so it
//! is an acquire, not a history read.
//!
//! Kernel validates identity, epoch, fence, and ordering only; it never
//! interprets task semantics, provider policy, payload meaning, or finish.
//! Event payloads cross this boundary as opaque digests plus bounded type
//! labels, never as content. Depending on `eliot-governor` or
//! `eliot-native-worker-core` from this C1 crate would invert the I2.3
//! dependency direction (C4 → C3 → C2 → C1 → C0), so the owner digest and the
//! draft/envelope/receipt shapes are carried by value and compared against
//! caller-supplied current owner records passed as plain parameters.

use eliot_contracts::{EpochId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{KernelServiceError, validate_text};

/// Stable identity for the Kernel-owned native-worker replay wire.
pub const NATIVE_WORKER_REPLAY_WIRE_ID: &str = "eliot.kernel.native-worker-replay";
/// Current version of the Kernel-owned native-worker replay wire.
///
/// This family is new at T9-03, so it starts at version 1, mirroring the
/// claim wire history (claim v1, then v2 when the executable join landed).
/// An unknown wire revision is rejected explicitly, never promoted.
pub const NATIVE_WORKER_REPLAY_WIRE_VERSION: u16 = 1;
/// Maximum events carried in one replay page.
///
/// Mirrors the ORS `MAX_RECOVERY_PAGE = 256` precedent: a new generation
/// catches up on old history in bounded pages, and retention holds only
/// until `APPLIED`/`REJECTED` plus this bounded window.
pub const NATIVE_WORKER_REPLAY_MAX_PAGE: u16 = 256;

/// Returns the canonical replay stream identity for one claim generation.
///
/// Renders `"{claim_id}/gen-{worker_generation}"`, matching the T9-02
/// fixture (`stream-claim-t9-02-1` at generation 1 binds
/// `stream-claim-t9-02-1/gen-1`). The `gen-` prefix keeps the numeric
/// generation distinct from claim-id text that may itself end in digits.
#[must_use]
pub fn replay_stream_id(claim_id: &str, worker_generation: u64) -> String {
    format!("{claim_id}/gen-{worker_generation}")
}

/// Returns true when the value is a lowercase SHA-256 digest.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Validates bounded wire text without carrying platform or secret material.
fn validate_wire_text(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    validate_text(value, field)
}

/// Validates a lowercase SHA-256 wire digest.
fn validate_wire_digest(value: &str, field: &'static str) -> Result<(), KernelServiceError> {
    if !is_lowercase_sha256(value) {
        return Err(KernelServiceError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Explicit cursor phase carried on every replay acknowledgement.
///
/// Transport receipt cannot impersonate application commit: the phase is
/// preserved end to end from the ack receipt into the ack reply, and cursor
/// advancement is derived from the phase alone (see
/// [`NativeWorkerReplayAckPhase::advances_producer_cursor`] and
/// [`NativeWorkerReplayAckPhase::advances_consumer_cursor`]), so `UNKNOWN`
/// can never carry a cursor advance.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeWorkerReplayAckPhase {
    /// Observed by transport only; advances no cursor.
    Received,
    /// Durable in the owner journal; advances the producer cursor only.
    Durable,
    /// Normalized; advances no cursor.
    Normalized,
    /// Applied by the consumer; advances the consumer cursor and releases
    /// retention.
    Applied,
    /// Rejected by the consumer; advances the consumer cursor and releases
    /// retention.
    Rejected,
    /// Outcome unknown; never advances any cursor, never releases retention.
    Unknown,
}

impl NativeWorkerReplayAckPhase {
    /// Returns true only at `DURABLE`: the producer cursor advances when the
    /// owner journal holds the event, never on transport receipt alone.
    #[must_use]
    pub const fn advances_producer_cursor(self) -> bool {
        matches!(self, Self::Durable)
    }

    /// Returns true only at `APPLIED`/`REJECTED`: the consumer cursor
    /// advances when the consumer commits an outcome, never on `UNKNOWN`.
    #[must_use]
    pub const fn advances_consumer_cursor(self) -> bool {
        matches!(self, Self::Applied | Self::Rejected)
    }

    /// Returns true only at `APPLIED`/`REJECTED`: retained history releases
    /// when the consumer commits an outcome, plus the bounded page window.
    #[must_use]
    pub const fn retention_releasable(self) -> bool {
        matches!(self, Self::Applied | Self::Rejected)
    }
}

/// Presented stream binding carried by value on every replay request.
///
/// `claim_id`/`worker_generation`/`stream_id` name the target stream;
/// `authority_epoch`/`state_fence` are the presenter current authority (a new
/// generation reads old history under its own current epoch, never under the
/// old epoch); `executable_binding_digest` is the opaque owner-produced
/// `NativeWorkerExecutableBinding` v1 digest the T9-02 gate compares for
/// equality. Kernel never mints or recomputes this digest here.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayStreamBinding {
    /// Claim identity that owns the stream.
    pub claim_id: String,
    /// Worker generation that owns the stream; may name old history on reads.
    pub worker_generation: u64,
    /// Stream identity; must equal `replay_stream_id(claim_id,
    /// worker_generation)`.
    pub stream_id: String,
    /// Presenter current authority epoch; must agree with `state_fence`.
    pub authority_epoch: EpochId,
    /// Presenter current immutable fence.
    pub state_fence: StateFence,
    /// Presented owner-produced executable digest, compared for equality
    /// against the current owner record at admission.
    pub executable_binding_digest: String,
}

impl NativeWorkerReplayStreamBinding {
    /// Validates the closed binding shape without treating it as authority.
    ///
    /// Checks bounded texts, digest shape, nonzero generation, fence
    /// validity, epoch/fence agreement, and the exact `{claim}/gen-{gen}`
    /// stream construction. Digest equality and currency against the current
    /// owner record are checked by [`admit_replay_request`], not here.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for a malformed shape or
    /// stream construction and [`KernelServiceError::HandshakeMismatch`] for
    /// epoch/fence disagreement.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.claim_id, "native_worker_replay.claim_id")?;
        validate_wire_text(&self.stream_id, "native_worker_replay.stream_id")?;
        validate_wire_digest(
            &self.executable_binding_digest,
            "native_worker_replay.executable_binding_digest",
        )?;
        if self.worker_generation == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay.worker_generation",
                reason: "generation must be non-zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::HandshakeMismatch {
                field: "native_worker_replay.state_fence",
            })?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_replay.epoch_fence",
            });
        }
        if self.stream_id != replay_stream_id(&self.claim_id, self.worker_generation) {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay.stream_id",
                reason: "stream identity must be the exact {claim_id}/gen-{generation} construction",
            });
        }
        Ok(())
    }
}

/// Current owner-produced replay authority one stream binding is checked
/// against.
///
/// The route builds this from the live claim, admission, activation, and
/// epoch records at admission time. Kernel never mints this value; it only
/// refuses presented bindings that disagree with it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayAuthority {
    /// Owner-current claim identity.
    pub claim_id: String,
    /// Owner-current worker generation; history reads address generations at
    /// or below this, acquires require exactly this.
    pub worker_generation: u64,
    /// Owner-current authority epoch.
    pub authority_epoch: EpochId,
    /// Owner-current immutable fence.
    pub state_fence: StateFence,
    /// Owner-current executable binding digest.
    pub executable_binding_digest: String,
}

impl NativeWorkerReplayAuthority {
    /// Validates the closed owner-record shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for a malformed shape
    /// and [`KernelServiceError::HandshakeMismatch`] for epoch/fence
    /// disagreement.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.claim_id, "native_worker_replay_authority.claim_id")?;
        validate_wire_digest(
            &self.executable_binding_digest,
            "native_worker_replay_authority.executable_binding_digest",
        )?;
        if self.worker_generation == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_authority.worker_generation",
                reason: "generation must be non-zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| KernelServiceError::HandshakeMismatch {
                field: "native_worker_replay_authority.state_fence",
            })?;
        if self.authority_epoch != self.state_fence.authority_epoch {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "native_worker_replay_authority.epoch_fence",
            });
        }
        Ok(())
    }
}

/// Current owner replay authority plus observed invalidation evidence.
///
/// Mirrors `NativeWorkerExecutableExpectation`: `current` is what the owner
/// says the replay authority is now, and `revoked` carries observed
/// invalidation evidence (the binding was withdrawn or superseded after
/// publication).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayExpectation {
    /// Owner-produced current replay authority.
    pub current: NativeWorkerReplayAuthority,
    /// True when current records show the authority withdrawn or superseded.
    pub revoked: bool,
}

impl NativeWorkerReplayExpectation {
    /// Validates the closed expectation shape.
    ///
    /// # Errors
    ///
    /// Returns the enclosed authority validation failure, if any.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        self.current.validate()
    }
}

/// Replay operation kind admitted through [`admit_replay_request`].
///
/// Reads (`Lookup`, `Replay`) may address old-generation history; acquires
/// (`Begin`, `Append`, `Acknowledge`) require the current generation and
/// epoch because they claim identity or mutate durable cursor state.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NativeWorkerReplayOperation {
    /// History-safe identity lookup without claiming.
    Lookup,
    /// Atomic claim of a validated request.
    Begin,
    /// Durable event append to the current stream.
    Append,
    /// Bounded history read.
    Replay,
    /// Durable cursor acknowledgement.
    Acknowledge,
}

impl NativeWorkerReplayOperation {
    /// Returns true for history reads (`Lookup`, `Replay`) that may address
    /// old generations, false for acquires that require the current
    /// generation and epoch.
    #[must_use]
    pub const fn is_history_read(self) -> bool {
        matches!(self, Self::Lookup | Self::Replay)
    }
}

/// Admits one presented replay stream binding against the current owner
/// authority.
///
/// Enforces the T9-02 gate on this transport: the binding must be
/// well-formed with the exact `{claim}/gen-{generation}` stream
/// construction, the authority must not be revoked, the claim must be the
/// owner-current claim, the carried executable digest must equal the current
/// owner digest, and the presented epoch/fence must be current (epoch
/// agreement always goes through `is_same_authority`, never through a raw
/// sequence comparison). Generation authorization then splits reads from
/// acquires: `Lookup`/`Replay` accept any nonzero generation at or below the
/// current generation so a new generation reads history; `Begin`/`Append`/
/// `Acknowledge` require exactly the current generation so a new generation
/// never executes or advances cursors under an old epoch. A stale binding is
/// refused; it needs a new admission, never a local repair.
///
/// # Errors
///
/// Returns [`KernelServiceError::InvalidField`] for a malformed shape, an
/// unknown or foreign identity, or an unauthorized generation, and
/// [`KernelServiceError::HandshakeMismatch`] for revocation or any
/// disagreement with the current owner authority. Stale, foreign, and
/// unknown presentations are rejected, never default-accepted.
pub fn admit_replay_request(
    binding: &NativeWorkerReplayStreamBinding,
    expected: &NativeWorkerReplayExpectation,
    operation: NativeWorkerReplayOperation,
) -> Result<(), KernelServiceError> {
    binding.validate()?;
    expected.validate()?;
    if expected.revoked {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_replay.executable_binding_revoked",
        });
    }
    if binding.claim_id != expected.current.claim_id {
        return Err(KernelServiceError::InvalidField {
            field: "native_worker_replay.claim_binding",
            reason: "replay claim does not match the current owner claim",
        });
    }
    if binding.executable_binding_digest != expected.current.executable_binding_digest {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_replay.executable_binding_digest",
        });
    }
    if !binding
        .authority_epoch
        .is_same_authority(&expected.current.authority_epoch)
    {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_replay.authority_epoch",
        });
    }
    if binding.state_fence != expected.current.state_fence {
        return Err(KernelServiceError::HandshakeMismatch {
            field: "native_worker_replay.state_fence",
        });
    }
    if operation.is_history_read() {
        if binding.worker_generation > expected.current.worker_generation {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay.generation",
                reason: "stream generation is ahead of the current owner generation",
            });
        }
    } else if binding.worker_generation != expected.current.worker_generation {
        return Err(KernelServiceError::InvalidField {
            field: "native_worker_replay.generation",
            reason: "only the current generation may acquire or mutate; history generations are read-only",
        });
    }
    Ok(())
}

/// Kernel-side projection of one durable event draft (append input).
///
/// Carries the stream binding cross-checks plus opaque payload references:
/// `payload_type` is a bounded type label and `payload_digest` is the
/// lowercase SHA-256 of the exact event payload bytes. Kernel compares
/// digests and labels for equality only; it never interprets payload
/// meaning.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayEventDraft {
    /// Target stream identity; must equal the bound stream.
    pub stream_id: String,
    /// Producer identity presenting the draft.
    pub producer_id: String,
    /// Producer generation; must equal the bound worker generation.
    pub producer_generation: u64,
    /// Durable request identity the event belongs to.
    pub request_id: String,
    /// Bounded payload type label, carried opaquely.
    pub payload_type: String,
    /// Lowercase SHA-256 of the exact event payload bytes, carried opaquely.
    pub payload_digest: String,
}

impl NativeWorkerReplayEventDraft {
    /// Validates the closed draft shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for a malformed shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        for (text, field) in [
            (&self.stream_id, "native_worker_replay_draft.stream_id"),
            (&self.producer_id, "native_worker_replay_draft.producer_id"),
            (&self.request_id, "native_worker_replay_draft.request_id"),
            (
                &self.payload_type,
                "native_worker_replay_draft.payload_type",
            ),
        ] {
            validate_wire_text(text, field)?;
        }
        validate_wire_digest(
            &self.payload_digest,
            "native_worker_replay_draft.payload_digest",
        )?;
        if self.producer_generation == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_draft.producer_generation",
                reason: "generation must be non-zero",
            });
        }
        Ok(())
    }
}

/// Kernel-side projection of one durable event envelope.
///
/// The owner assigns `event_id` and `sequence`; the payload crosses as an
/// opaque digest plus a bounded type label, never as interpreted content.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayEnvelope {
    /// Stream identity the event is durable under.
    pub stream_id: String,
    /// Producer identity that wrote the event.
    pub producer_id: String,
    /// Producer generation that wrote the event; nonzero.
    pub producer_generation: u64,
    /// Durable event identity assigned by the owner.
    pub event_id: String,
    /// Durable sequence assigned by the owner; nonzero.
    pub sequence: u64,
    /// Durable request identity the event belongs to.
    pub request_id: String,
    /// Bounded payload type label, carried opaquely.
    pub payload_type: String,
    /// Lowercase SHA-256 of the exact event payload bytes, carried opaquely.
    pub payload_digest: String,
}

impl NativeWorkerReplayEnvelope {
    /// Validates the closed envelope shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for a malformed shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        for (text, field) in [
            (&self.stream_id, "native_worker_replay_envelope.stream_id"),
            (
                &self.producer_id,
                "native_worker_replay_envelope.producer_id",
            ),
            (&self.event_id, "native_worker_replay_envelope.event_id"),
            (&self.request_id, "native_worker_replay_envelope.request_id"),
            (
                &self.payload_type,
                "native_worker_replay_envelope.payload_type",
            ),
        ] {
            validate_wire_text(text, field)?;
        }
        validate_wire_digest(
            &self.payload_digest,
            "native_worker_replay_envelope.payload_digest",
        )?;
        if self.producer_generation == 0 || self.sequence == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_envelope.bounded_fields",
                reason: "producer generation and sequence must be non-zero",
            });
        }
        Ok(())
    }
}

/// Kernel-side projection of one durable acknowledgement receipt.
///
/// The phase is preserved end to end into
/// [`NativeWorkerReplayAcknowledgeReply`]; cursor advancement is derived from
/// the phase alone, so `UNKNOWN` carries no cursor advance at the type
/// level.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayAckReceipt {
    /// Stream identity the acknowledged event is durable under.
    pub stream_id: String,
    /// Acknowledged durable event identity.
    pub event_id: String,
    /// Acknowledged durable sequence; nonzero.
    pub sequence: u64,
    /// Generation that produced the event; must equal the bound worker
    /// generation at admission.
    pub producer_generation: u64,
    /// Explicit cursor phase; preserved end to end.
    pub phase: NativeWorkerReplayAckPhase,
    /// Acknowledgement time in Unix milliseconds; nonzero.
    pub acknowledged_at_unix_ms: u64,
}

impl NativeWorkerReplayAckReceipt {
    /// Validates the closed receipt shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for a malformed shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.stream_id, "native_worker_replay_receipt.stream_id")?;
        validate_wire_text(&self.event_id, "native_worker_replay_receipt.event_id")?;
        if self.sequence == 0 || self.producer_generation == 0 || self.acknowledged_at_unix_ms == 0
        {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_receipt.bounded_fields",
                reason: "sequence, producer generation, and acknowledgement time must be non-zero",
            });
        }
        Ok(())
    }
}

/// Validates one replay wire envelope identity.
fn validate_replay_wire(wire_id: &str, wire_version: u16) -> Result<(), KernelServiceError> {
    if wire_id != NATIVE_WORKER_REPLAY_WIRE_ID || wire_version != NATIVE_WORKER_REPLAY_WIRE_VERSION
    {
        return Err(KernelServiceError::InvalidField {
            field: "native_worker_replay.wire",
            reason: "unsupported native-worker replay wire",
        });
    }
    Ok(())
}

/// Lookup request: durable identity probe without claiming (1:1 with
/// `DurableReplayPort::lookup_request`).
///
/// `fingerprint` is the opaque canonical request fingerprint carried by
/// value; Kernel compares it for equality only and never interprets it.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayLookupRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Presented stream binding.
    pub binding: NativeWorkerReplayStreamBinding,
    /// Durable request identity to look up.
    pub request_id: String,
    /// Opaque canonical request fingerprint, compared for equality only.
    pub fingerprint: String,
}

impl NativeWorkerReplayLookupRequest {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed lookup shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire or a
    /// malformed shape and [`KernelServiceError::HandshakeMismatch`] for
    /// epoch/fence disagreement.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_replay_wire(&self.wire_id, self.wire_version)?;
        self.binding.validate()?;
        validate_wire_text(&self.request_id, "native_worker_replay_lookup.request_id")?;
        validate_wire_text(&self.fingerprint, "native_worker_replay_lookup.fingerprint")?;
        Ok(())
    }

    /// Admits this lookup against the current owner authority.
    ///
    /// Lookups are history reads: they may address old-generation history so
    /// a new generation reads history, but the binding digest must equal the
    /// current owner digest and the epoch/fence must be current.
    ///
    /// # Errors
    ///
    /// Returns the [`NativeWorkerReplayLookupRequest::validate`] failure, if
    /// any, else the [`admit_replay_request`] refusal.
    pub fn admit(
        &self,
        expected: &NativeWorkerReplayExpectation,
    ) -> Result<(), KernelServiceError> {
        self.validate()?;
        admit_replay_request(&self.binding, expected, NativeWorkerReplayOperation::Lookup)
    }
}

/// Begin request: atomic claim of a validated request (1:1 with
/// `DurableReplayPort::begin_request`).
///
/// Acquires require the current generation and epoch: a new generation reads
/// history but never claims under an old epoch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayBeginRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Presented stream binding.
    pub binding: NativeWorkerReplayStreamBinding,
    /// Durable request identity to claim.
    pub request_id: String,
    /// Opaque canonical request fingerprint, compared for equality only.
    pub fingerprint: String,
}

impl NativeWorkerReplayBeginRequest {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed begin shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire or a
    /// malformed shape and [`KernelServiceError::HandshakeMismatch`] for
    /// epoch/fence disagreement.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_replay_wire(&self.wire_id, self.wire_version)?;
        self.binding.validate()?;
        validate_wire_text(&self.request_id, "native_worker_replay_begin.request_id")?;
        validate_wire_text(&self.fingerprint, "native_worker_replay_begin.fingerprint")?;
        Ok(())
    }

    /// Admits this claim against the current owner authority.
    ///
    /// # Errors
    ///
    /// Returns the [`NativeWorkerReplayBeginRequest::validate`] failure, if
    /// any, else the [`admit_replay_request`] refusal.
    pub fn admit(
        &self,
        expected: &NativeWorkerReplayExpectation,
    ) -> Result<(), KernelServiceError> {
        self.validate()?;
        admit_replay_request(&self.binding, expected, NativeWorkerReplayOperation::Begin)
    }
}

/// Append request: durable event write to the current stream (1:1 with
/// `DurableReplayPort::append`).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayAppendRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Presented stream binding.
    pub binding: NativeWorkerReplayStreamBinding,
    /// Exact event content handed to the durable replay owner.
    pub draft: NativeWorkerReplayEventDraft,
}

impl NativeWorkerReplayAppendRequest {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed append shape, including draft/stream agreement.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire, a
    /// malformed shape, or a draft that names a different stream or
    /// generation than the binding, and
    /// [`KernelServiceError::HandshakeMismatch`] for epoch/fence
    /// disagreement.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_replay_wire(&self.wire_id, self.wire_version)?;
        self.binding.validate()?;
        self.draft.validate()?;
        if self.draft.stream_id != self.binding.stream_id {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_append.draft.stream_binding",
                reason: "draft stream does not match the bound stream",
            });
        }
        if self.draft.producer_generation != self.binding.worker_generation {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_append.draft.producer_binding",
                reason: "draft producer generation does not match the bound generation",
            });
        }
        Ok(())
    }

    /// Admits this append against the current owner authority.
    ///
    /// Appends mutate durable state, so they require the current generation
    /// and epoch.
    ///
    /// # Errors
    ///
    /// Returns the [`NativeWorkerReplayAppendRequest::validate`] failure, if
    /// any, else the [`admit_replay_request`] refusal.
    pub fn admit(
        &self,
        expected: &NativeWorkerReplayExpectation,
    ) -> Result<(), KernelServiceError> {
        self.validate()?;
        admit_replay_request(&self.binding, expected, NativeWorkerReplayOperation::Append)
    }
}

/// Replay request: bounded history read past a cursor (1:1 with
/// `DurableReplayPort::replay`).
///
/// The stutter in the name is intentional: this pair maps exactly onto the
/// `replay` port method. `after_sequence` is the exclusive cursor (`0`
/// reads from genesis); `limit` is the bounded page size, `1..=256`.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayReplayRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Presented stream binding.
    pub binding: NativeWorkerReplayStreamBinding,
    /// Exclusive cursor; `0` reads from genesis.
    pub after_sequence: u64,
    /// Bounded page size; must be `1..=NATIVE_WORKER_REPLAY_MAX_PAGE`.
    pub limit: u16,
}

impl NativeWorkerReplayReplayRequest {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed replay shape, enforcing the page cap.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire, a
    /// malformed shape, or a page size outside `1..=256`, and
    /// [`KernelServiceError::HandshakeMismatch`] for epoch/fence
    /// disagreement.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_replay_wire(&self.wire_id, self.wire_version)?;
        self.binding.validate()?;
        if self.limit == 0 || self.limit > NATIVE_WORKER_REPLAY_MAX_PAGE {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_replay.limit",
                reason: "replay page size must be between 1 and 256",
            });
        }
        Ok(())
    }

    /// Admits this history read against the current owner authority.
    ///
    /// Reads may address old-generation history so a new generation catches
    /// up in bounded pages, but the binding digest must equal the current
    /// owner digest and the epoch/fence must be current.
    ///
    /// # Errors
    ///
    /// Returns the [`NativeWorkerReplayReplayRequest::validate`] failure, if
    /// any, else the [`admit_replay_request`] refusal.
    pub fn admit(
        &self,
        expected: &NativeWorkerReplayExpectation,
    ) -> Result<(), KernelServiceError> {
        self.validate()?;
        admit_replay_request(&self.binding, expected, NativeWorkerReplayOperation::Replay)
    }
}

/// Acknowledge request: durable cursor acknowledgement (1:1 with
/// `DurableReplayPort::acknowledge`).
///
/// The receipt phase is preserved end to end into
/// [`NativeWorkerReplayAcknowledgeReply`]; cursor advancement derives from
/// the phase alone, so `UNKNOWN` never advances.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayAcknowledgeRequest {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Presented stream binding.
    pub binding: NativeWorkerReplayStreamBinding,
    /// Durable acknowledgement receipt.
    pub receipt: NativeWorkerReplayAckReceipt,
}

impl NativeWorkerReplayAcknowledgeRequest {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed acknowledge shape, including receipt/stream
    /// agreement.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire, a
    /// malformed shape, or a receipt that names a different stream or
    /// producer generation than the binding, and
    /// [`KernelServiceError::HandshakeMismatch`] for epoch/fence
    /// disagreement.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_replay_wire(&self.wire_id, self.wire_version)?;
        self.binding.validate()?;
        self.receipt.validate()?;
        if self.receipt.stream_id != self.binding.stream_id {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_acknowledge.receipt.stream_binding",
                reason: "receipt stream does not match the bound stream",
            });
        }
        if self.receipt.producer_generation != self.binding.worker_generation {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_acknowledge.receipt.producer_binding",
                reason: "receipt producer generation does not match the bound generation",
            });
        }
        Ok(())
    }

    /// Admits this acknowledgement against the current owner authority.
    ///
    /// Acknowledgements mutate durable cursor state, so they require the
    /// current generation and epoch.
    ///
    /// # Errors
    ///
    /// Returns the [`NativeWorkerReplayAcknowledgeRequest::validate`]
    /// failure, if any, else the [`admit_replay_request`] refusal.
    pub fn admit(
        &self,
        expected: &NativeWorkerReplayExpectation,
    ) -> Result<(), KernelServiceError> {
        self.validate()?;
        admit_replay_request(
            &self.binding,
            expected,
            NativeWorkerReplayOperation::Acknowledge,
        )
    }
}

/// Fresh-stream position returned for a `New` lookup/begin decision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayStreamPosition {
    /// Stream identity the position belongs to.
    pub stream_id: String,
    /// Next durable sequence the owner will assign; nonzero.
    pub next_sequence: u64,
}

impl NativeWorkerReplayStreamPosition {
    /// Validates the closed position shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for a malformed shape.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.stream_id, "native_worker_replay_position.stream_id")?;
        if self.next_sequence == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_position.next_sequence",
                reason: "next sequence must be non-zero",
            });
        }
        Ok(())
    }
}

/// Bounded history page shared by the `Replay` decision and the replay reply.
///
/// `after_sequence` echoes the exclusive cursor the page was read past;
/// `events` holds at most [`NATIVE_WORKER_REPLAY_MAX_PAGE`] envelopes in
/// ascending sequence order. An empty page is a valid caught-up read; a
/// `Replay` lookup/begin decision must carry at least one event (see
/// [`NativeWorkerReplayDecision::validate`]).
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayPage {
    /// Stream identity the page was read from.
    pub stream_id: String,
    /// Exclusive cursor the page was read past.
    pub after_sequence: u64,
    /// Page events, at most 256.
    pub events: Vec<NativeWorkerReplayEnvelope>,
}

impl NativeWorkerReplayPage {
    /// Validates the closed page shape, enforcing the page cap.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for a malformed shape,
    /// an over-cap page, or an event that names a different stream.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.stream_id, "native_worker_replay_page.stream_id")?;
        if self.events.len() > usize::from(NATIVE_WORKER_REPLAY_MAX_PAGE) {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_page.events",
                reason: "replay page exceeds the bounded 256-event cap",
            });
        }
        for event in &self.events {
            event.validate()?;
            if event.stream_id != self.stream_id {
                return Err(KernelServiceError::InvalidField {
                    field: "native_worker_replay_page.events.stream_binding",
                    reason: "page event stream does not match the page stream",
                });
            }
        }
        Ok(())
    }
}

/// Changed-fingerprint conflict under one durable request identity.
///
/// Mirrors the claim conflict report for the replay contour: the same
/// request identity was presented with a different fingerprint, so the
/// conflicting presentation takes no effect. Fingerprints are opaque bounded
/// texts compared for inequality only.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayConflict {
    /// Stream identity both fingerprints were presented under.
    pub stream_id: String,
    /// Durable request identity both fingerprints were presented under.
    pub request_id: String,
    /// Fingerprint already recorded for the request identity.
    pub expected_fingerprint: String,
    /// Conflicting presented fingerprint.
    pub observed_fingerprint: String,
}

impl NativeWorkerReplayConflict {
    /// Validates the closed conflict shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for a malformed shape or
    /// for fingerprints that do not actually differ.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_wire_text(&self.stream_id, "native_worker_replay_conflict.stream_id")?;
        validate_wire_text(&self.request_id, "native_worker_replay_conflict.request_id")?;
        validate_wire_text(
            &self.expected_fingerprint,
            "native_worker_replay_conflict.expected_fingerprint",
        )?;
        validate_wire_text(
            &self.observed_fingerprint,
            "native_worker_replay_conflict.observed_fingerprint",
        )?;
        if self.expected_fingerprint == self.observed_fingerprint {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_conflict.observed_fingerprint",
                reason: "conflicting fingerprints must differ",
            });
        }
        Ok(())
    }
}

/// Kernel answer to one lookup/begin request.
///
/// Exactly one variant is returned: a fresh-stream position, a bounded
/// history page, or a changed-fingerprint conflict. A conflicting
/// presentation never claims a second live request under the same identity.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE",
    tag = "kind",
    content = "payload"
)]
pub enum NativeWorkerReplayDecision {
    /// No durable identity exists yet; the position is the claim proof.
    New(NativeWorkerReplayStreamPosition),
    /// Durable history already exists; the page carries it, bounded to 256.
    Replay(NativeWorkerReplayPage),
    /// The request identity conflicts with recorded history.
    Conflict(NativeWorkerReplayConflict),
}

impl NativeWorkerReplayDecision {
    /// Returns the stream identity this decision belongs to.
    #[must_use]
    pub fn stream_id(&self) -> &str {
        match self {
            Self::New(position) => &position.stream_id,
            Self::Replay(page) => &page.stream_id,
            Self::Conflict(conflict) => &conflict.stream_id,
        }
    }

    /// Validates the enclosed position, page, or conflict.
    ///
    /// A `Replay` decision must carry at least one event: an empty page is
    /// a valid caught-up read on the replay reply, never a decision.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an empty decision
    /// page or any enclosed shape failure.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        match self {
            Self::New(position) => position.validate(),
            Self::Replay(page) => {
                page.validate()?;
                if page.events.is_empty() {
                    return Err(KernelServiceError::InvalidField {
                        field: "native_worker_replay_page.events",
                        reason: "a replay decision must carry at least one event",
                    });
                }
                Ok(())
            }
            Self::Conflict(conflict) => conflict.validate(),
        }
    }
}

/// Validates one lookup/begin reply envelope and its decision/stream
/// agreement.
fn validate_decision_reply(
    wire_id: &str,
    wire_version: u16,
    stream_id: &str,
    decision: &NativeWorkerReplayDecision,
    reply_field: &'static str,
) -> Result<(), KernelServiceError> {
    validate_replay_wire(wire_id, wire_version)?;
    validate_wire_text(stream_id, reply_field)?;
    decision.validate()?;
    if decision.stream_id() != stream_id {
        return Err(KernelServiceError::InvalidField {
            field: "native_worker_replay.decision.stream_binding",
            reason: "decision stream does not match the reply stream",
        });
    }
    Ok(())
}

/// Lookup reply: durable identity probe answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayLookupReply {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Stream identity the decision belongs to.
    pub stream_id: String,
    /// Exactly one lookup outcome.
    pub decision: NativeWorkerReplayDecision,
}

impl NativeWorkerReplayLookupReply {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed lookup reply shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire, a
    /// malformed shape, or a decision that names a different stream.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_decision_reply(
            &self.wire_id,
            self.wire_version,
            &self.stream_id,
            &self.decision,
            "native_worker_replay_lookup_reply.stream_id",
        )
    }
}

/// Begin reply: atomic claim answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayBeginReply {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Stream identity the decision belongs to.
    pub stream_id: String,
    /// Exactly one claim outcome.
    pub decision: NativeWorkerReplayDecision,
}

impl NativeWorkerReplayBeginReply {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed begin reply shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire, a
    /// malformed shape, or a decision that names a different stream.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_decision_reply(
            &self.wire_id,
            self.wire_version,
            &self.stream_id,
            &self.decision,
            "native_worker_replay_begin_reply.stream_id",
        )
    }
}

/// Append reply: durable write receipt.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayAppendReply {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Stream identity the envelope is durable under.
    pub stream_id: String,
    /// Durable envelope assigned by the owner.
    pub envelope: NativeWorkerReplayEnvelope,
}

impl NativeWorkerReplayAppendReply {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed append reply shape.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire, a
    /// malformed shape, or an envelope that names a different stream.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_replay_wire(&self.wire_id, self.wire_version)?;
        validate_wire_text(
            &self.stream_id,
            "native_worker_replay_append_reply.stream_id",
        )?;
        self.envelope.validate()?;
        if self.envelope.stream_id != self.stream_id {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay.envelope.stream_binding",
                reason: "envelope stream does not match the reply stream",
            });
        }
        Ok(())
    }
}

/// Replay reply: bounded history page answer.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayReplayReply {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Bounded history page; empty when the cursor is caught up.
    pub page: NativeWorkerReplayPage,
}

impl NativeWorkerReplayReplayReply {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed replay reply shape, enforcing the page cap.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire, an
    /// over-cap page, or any enclosed shape failure.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_replay_wire(&self.wire_id, self.wire_version)?;
        self.page.validate()
    }
}

/// Acknowledge reply: cursor-advance receipt.
///
/// The echoed `phase` is the commit proof; the two advance flags must equal
/// the phase-derived values, so an `UNKNOWN` receipt can never claim a
/// cursor advance at the type level.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeWorkerReplayAcknowledgeReply {
    /// Wire identity.
    pub wire_id: String,
    /// Wire revision.
    pub wire_version: u16,
    /// Stream identity the acknowledged event is durable under.
    pub stream_id: String,
    /// Acknowledged durable event identity.
    pub event_id: String,
    /// Acknowledged durable sequence; nonzero.
    pub sequence: u64,
    /// Echoed cursor phase; preserved end to end from the receipt.
    pub phase: NativeWorkerReplayAckPhase,
    /// True only when `phase` is `DURABLE`.
    pub producer_cursor_advanced: bool,
    /// True only when `phase` is `APPLIED`/`REJECTED`.
    pub consumer_cursor_advanced: bool,
}

impl NativeWorkerReplayAcknowledgeReply {
    /// Current replay wire contract version.
    pub const CONTRACT_VERSION: u16 = NATIVE_WORKER_REPLAY_WIRE_VERSION;

    /// Validates the closed acknowledge reply shape, enforcing phase-derived
    /// cursor consistency.
    ///
    /// # Errors
    ///
    /// Returns [`KernelServiceError::InvalidField`] for an unknown wire, a
    /// malformed shape, or advance flags that disagree with the phase.
    pub fn validate(&self) -> Result<(), KernelServiceError> {
        validate_replay_wire(&self.wire_id, self.wire_version)?;
        validate_wire_text(
            &self.stream_id,
            "native_worker_replay_acknowledge_reply.stream_id",
        )?;
        validate_wire_text(
            &self.event_id,
            "native_worker_replay_acknowledge_reply.event_id",
        )?;
        if self.sequence == 0 {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_acknowledge_reply.sequence",
                reason: "sequence must be non-zero",
            });
        }
        if self.producer_cursor_advanced != self.phase.advances_producer_cursor() {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_acknowledge_reply.producer_cursor_advanced",
                reason: "producer advance must agree with the ack phase",
            });
        }
        if self.consumer_cursor_advanced != self.phase.advances_consumer_cursor() {
            return Err(KernelServiceError::InvalidField {
                field: "native_worker_replay_acknowledge_reply.consumer_cursor_advanced",
                reason: "consumer advance must agree with the ack phase",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod replay_wire_tests {
    use super::*;
    use eliot_contracts::{EpochLineageId, ResourceGeneration};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const CLAIM_ID: &str = "claim-t9-03-1";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE).expect("test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("test epoch")
    }

    fn live_fence() -> StateFence {
        StateFence::new(test_epoch(1), ResourceGeneration::genesis())
    }

    /// Stand-in for the Governor T9-01 publish output.
    ///
    /// Deterministic bounded lowercase hex, never hardcoded authority: the
    /// true digest is produced by `publish_native_worker_binding`, which this
    /// C1 crate cannot link without inverting the I2.3 dependency direction.
    /// The join compares it for equality only.
    fn owner_issued_digest() -> String {
        "d".repeat(64)
    }

    fn valid_binding() -> NativeWorkerReplayStreamBinding {
        NativeWorkerReplayStreamBinding {
            claim_id: CLAIM_ID.to_owned(),
            worker_generation: 1,
            stream_id: replay_stream_id(CLAIM_ID, 1),
            authority_epoch: test_epoch(1),
            state_fence: live_fence(),
            executable_binding_digest: owner_issued_digest(),
        }
    }

    fn current_authority() -> NativeWorkerReplayAuthority {
        NativeWorkerReplayAuthority {
            claim_id: CLAIM_ID.to_owned(),
            worker_generation: 1,
            authority_epoch: test_epoch(1),
            state_fence: live_fence(),
            executable_binding_digest: owner_issued_digest(),
        }
    }

    fn expectation() -> NativeWorkerReplayExpectation {
        NativeWorkerReplayExpectation {
            current: current_authority(),
            revoked: false,
        }
    }

    fn test_draft(stream_id: &str) -> NativeWorkerReplayEventDraft {
        NativeWorkerReplayEventDraft {
            stream_id: stream_id.to_owned(),
            producer_id: "producer-1".to_owned(),
            producer_generation: 1,
            request_id: "req-1".to_owned(),
            payload_type: "heartbeat".to_owned(),
            payload_digest: "c".repeat(64),
        }
    }

    fn test_envelope(stream_id: &str, sequence: u64) -> NativeWorkerReplayEnvelope {
        NativeWorkerReplayEnvelope {
            stream_id: stream_id.to_owned(),
            producer_id: "producer-1".to_owned(),
            producer_generation: 1,
            event_id: format!("event-{sequence}"),
            sequence,
            request_id: "req-1".to_owned(),
            payload_type: "heartbeat".to_owned(),
            payload_digest: "c".repeat(64),
        }
    }

    fn test_receipt(
        stream_id: &str,
        phase: NativeWorkerReplayAckPhase,
    ) -> NativeWorkerReplayAckReceipt {
        NativeWorkerReplayAckReceipt {
            stream_id: stream_id.to_owned(),
            event_id: "event-1".to_owned(),
            sequence: 1,
            producer_generation: 1,
            phase,
            acknowledged_at_unix_ms: 1_700_000_100_000,
        }
    }

    #[test]
    fn v1_request_wire_round_trips_end_to_end() {
        let binding = valid_binding();
        let expected = expectation();

        let lookup = NativeWorkerReplayLookupRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            request_id: "req-1".to_owned(),
            fingerprint: "{\"kind\":\"EXECUTE\"}".to_owned(),
        };
        let parsed: NativeWorkerReplayLookupRequest =
            serde_json::from_value(serde_json::to_value(&lookup).expect("lookup encodes"))
                .expect("v1 lookup parses");
        assert_eq!(parsed, lookup);
        parsed.validate().expect("lookup validates");
        parsed.admit(&expected).expect("lookup admits");

        let begin = NativeWorkerReplayBeginRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            request_id: "req-1".to_owned(),
            fingerprint: "{\"kind\":\"EXECUTE\"}".to_owned(),
        };
        let parsed: NativeWorkerReplayBeginRequest =
            serde_json::from_value(serde_json::to_value(&begin).expect("begin encodes"))
                .expect("v1 begin parses");
        assert_eq!(parsed, begin);
        parsed.admit(&expected).expect("begin admits");

        let append = NativeWorkerReplayAppendRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            draft: test_draft(&binding.stream_id),
        };
        let parsed: NativeWorkerReplayAppendRequest =
            serde_json::from_value(serde_json::to_value(&append).expect("append encodes"))
                .expect("v1 append parses");
        assert_eq!(parsed, append);
        parsed.admit(&expected).expect("append admits");

        let replay = NativeWorkerReplayReplayRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            after_sequence: 0,
            limit: NATIVE_WORKER_REPLAY_MAX_PAGE,
        };
        let parsed: NativeWorkerReplayReplayRequest =
            serde_json::from_value(serde_json::to_value(&replay).expect("replay encodes"))
                .expect("v1 replay parses");
        assert_eq!(parsed, replay);
        parsed.admit(&expected).expect("replay admits");

        let acknowledge = NativeWorkerReplayAcknowledgeRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            receipt: test_receipt(&binding.stream_id, NativeWorkerReplayAckPhase::Applied),
        };
        let parsed: NativeWorkerReplayAcknowledgeRequest =
            serde_json::from_value(serde_json::to_value(&acknowledge).expect("ack encodes"))
                .expect("v1 acknowledge parses");
        assert_eq!(parsed, acknowledge);
        assert_eq!(
            parsed.receipt.phase,
            NativeWorkerReplayAckPhase::Applied,
            "ack phase preserved end to end"
        );
        parsed.admit(&expected).expect("acknowledge admits");
    }

    #[test]
    fn v1_reply_wire_round_trips_end_to_end() {
        let binding = valid_binding();

        let lookup_reply = NativeWorkerReplayLookupReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            stream_id: binding.stream_id.clone(),
            decision: NativeWorkerReplayDecision::New(NativeWorkerReplayStreamPosition {
                stream_id: binding.stream_id.clone(),
                next_sequence: 1,
            }),
        };
        let parsed: NativeWorkerReplayLookupReply =
            serde_json::from_value(serde_json::to_value(&lookup_reply).expect("reply encodes"))
                .expect("v1 lookup reply parses");
        assert_eq!(parsed, lookup_reply);
        parsed.validate().expect("lookup reply validates");

        let page = NativeWorkerReplayPage {
            stream_id: binding.stream_id.clone(),
            after_sequence: 0,
            events: vec![test_envelope(&binding.stream_id, 1)],
        };
        let begin_reply = NativeWorkerReplayBeginReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            stream_id: binding.stream_id.clone(),
            decision: NativeWorkerReplayDecision::Replay(page.clone()),
        };
        let parsed: NativeWorkerReplayBeginReply =
            serde_json::from_value(serde_json::to_value(&begin_reply).expect("reply encodes"))
                .expect("v1 begin reply parses");
        assert_eq!(parsed, begin_reply);
        parsed.validate().expect("begin reply validates");

        let append_reply = NativeWorkerReplayAppendReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            stream_id: binding.stream_id.clone(),
            envelope: test_envelope(&binding.stream_id, 1),
        };
        let parsed: NativeWorkerReplayAppendReply =
            serde_json::from_value(serde_json::to_value(&append_reply).expect("reply encodes"))
                .expect("v1 append reply parses");
        assert_eq!(parsed, append_reply);
        parsed.validate().expect("append reply validates");

        let replay_reply = NativeWorkerReplayReplayReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            page,
        };
        let parsed: NativeWorkerReplayReplayReply =
            serde_json::from_value(serde_json::to_value(&replay_reply).expect("reply encodes"))
                .expect("v1 replay reply parses");
        assert_eq!(parsed, replay_reply);
        parsed.validate().expect("replay reply validates");

        let ack_reply = NativeWorkerReplayAcknowledgeReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            stream_id: binding.stream_id.clone(),
            event_id: "event-1".to_owned(),
            sequence: 1,
            phase: NativeWorkerReplayAckPhase::Applied,
            producer_cursor_advanced: false,
            consumer_cursor_advanced: true,
        };
        let parsed: NativeWorkerReplayAcknowledgeReply =
            serde_json::from_value(serde_json::to_value(&ack_reply).expect("reply encodes"))
                .expect("v1 ack reply parses");
        assert_eq!(parsed, ack_reply);
        parsed.validate().expect("ack reply validates");
    }

    #[test]
    fn unknown_wire_version_rejected() {
        let binding = valid_binding();
        let expected = expectation();
        let mut lookup = NativeWorkerReplayLookupRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: 9,
            binding,
            request_id: "req-1".to_owned(),
            fingerprint: "{\"kind\":\"EXECUTE\"}".to_owned(),
        };
        let error = lookup.validate().expect_err("unknown wire stays rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.wire"),
            "preserved unknown-wire arm, got {error:?}"
        );
        let error = lookup
            .admit(&expected)
            .expect_err("gate repeats the refusal");
        assert!(
            format!("{error:?}").contains("native_worker_replay.wire"),
            "admit repeats the wire rejection, got {error:?}"
        );
        lookup.wire_version = 0;
        let error = lookup.validate().expect_err("wire zero stays rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.wire"),
            "wire zero rejected, got {error:?}"
        );
        lookup.wire_version = NATIVE_WORKER_REPLAY_WIRE_VERSION;
        lookup.wire_id = "eliot.kernel.foreign-wire".to_owned();
        let error = lookup.validate().expect_err("foreign wire stays rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.wire"),
            "foreign wire rejected, got {error:?}"
        );

        let reply = NativeWorkerReplayLookupReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: 9,
            stream_id: replay_stream_id(CLAIM_ID, 1),
            decision: NativeWorkerReplayDecision::New(NativeWorkerReplayStreamPosition {
                stream_id: replay_stream_id(CLAIM_ID, 1),
                next_sequence: 1,
            }),
        };
        let error = reply.validate().expect_err("reply unknown wire rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.wire"),
            "reply wire arm, got {error:?}"
        );
    }

    #[test]
    fn stream_id_mismatch_rejected() {
        let mut binding = valid_binding();
        binding.stream_id = "foreign-stream/gen-1".to_owned();
        let error = binding
            .validate()
            .expect_err("off-construction stream rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.stream_id"),
            "stream construction arm, got {error:?}"
        );

        // Internally consistent but foreign to the current owner claim.
        let foreign = NativeWorkerReplayStreamBinding {
            claim_id: "claim-foreign".to_owned(),
            worker_generation: 1,
            stream_id: replay_stream_id("claim-foreign", 1),
            authority_epoch: test_epoch(1),
            state_fence: live_fence(),
            executable_binding_digest: owner_issued_digest(),
        };
        foreign.validate().expect("foreign binding is well-formed");
        let error = admit_replay_request(
            &foreign,
            &expectation(),
            NativeWorkerReplayOperation::Lookup,
        )
        .expect_err("foreign claim rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.claim_binding"),
            "foreign-claim arm, got {error:?}"
        );
    }

    #[test]
    fn stale_digest_rejected() {
        let expected = expectation();
        let mut binding = valid_binding();
        binding.executable_binding_digest = "e".repeat(64);
        binding.validate().expect("rotated digest is well-formed");
        let error = admit_replay_request(&binding, &expected, NativeWorkerReplayOperation::Replay)
            .expect_err("stale digest rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.executable_binding_digest"),
            "stale-digest arm, got {error:?}"
        );

        let revoked = NativeWorkerReplayExpectation {
            current: current_authority(),
            revoked: true,
        };
        let error = admit_replay_request(
            &valid_binding(),
            &revoked,
            NativeWorkerReplayOperation::Lookup,
        )
        .expect_err("revoked authority rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.executable_binding_revoked"),
            "revoked arm, got {error:?}"
        );

        // Well-formed under an advanced epoch, stale against current authority.
        let advanced = test_epoch(2);
        let stale_epoch = NativeWorkerReplayStreamBinding {
            authority_epoch: advanced.clone(),
            state_fence: StateFence::new(advanced, ResourceGeneration::genesis()),
            ..valid_binding()
        };
        stale_epoch
            .validate()
            .expect("advanced epoch is well-formed");
        let error =
            admit_replay_request(&stale_epoch, &expected, NativeWorkerReplayOperation::Lookup)
                .expect_err("stale epoch rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.authority_epoch"),
            "stale-epoch arm, got {error:?}"
        );
    }

    #[test]
    fn generation_authorization_splits_reads_from_acquires() {
        let advanced_generation = ResourceGeneration::new(2).expect("nonzero generation");
        let current_fence = StateFence::new(test_epoch(1), advanced_generation);
        let expected = NativeWorkerReplayExpectation {
            current: NativeWorkerReplayAuthority {
                claim_id: CLAIM_ID.to_owned(),
                worker_generation: 2,
                authority_epoch: test_epoch(1),
                state_fence: current_fence.clone(),
                executable_binding_digest: owner_issued_digest(),
            },
            revoked: false,
        };
        // Old-generation history read under the current epoch/fence.
        let history = NativeWorkerReplayStreamBinding {
            claim_id: CLAIM_ID.to_owned(),
            worker_generation: 1,
            stream_id: replay_stream_id(CLAIM_ID, 1),
            authority_epoch: test_epoch(1),
            state_fence: current_fence,
            executable_binding_digest: owner_issued_digest(),
        };
        admit_replay_request(&history, &expected, NativeWorkerReplayOperation::Lookup)
            .expect("old history lookup admits");
        admit_replay_request(&history, &expected, NativeWorkerReplayOperation::Replay)
            .expect("old history replay admits");
        for operation in [
            NativeWorkerReplayOperation::Begin,
            NativeWorkerReplayOperation::Append,
            NativeWorkerReplayOperation::Acknowledge,
        ] {
            let error = admit_replay_request(&history, &expected, operation)
                .expect_err("old generation must not acquire or mutate");
            assert!(
                format!("{error:?}").contains("native_worker_replay.generation"),
                "stale-generation arm, got {error:?}"
            );
        }
        // A future generation is unknown, even for reads.
        let future = NativeWorkerReplayStreamBinding {
            worker_generation: 3,
            stream_id: replay_stream_id(CLAIM_ID, 3),
            ..history.clone()
        };
        let error = admit_replay_request(&future, &expected, NativeWorkerReplayOperation::Replay)
            .expect_err("future generation rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay.generation"),
            "future-generation arm, got {error:?}"
        );
    }

    #[test]
    fn unknown_phase_ack_carries_no_cursor_advance() {
        let stream_id = replay_stream_id(CLAIM_ID, 1);
        let receipt = test_receipt(&stream_id, NativeWorkerReplayAckPhase::Unknown);
        let parsed: NativeWorkerReplayAckReceipt =
            serde_json::from_value(serde_json::to_value(&receipt).expect("receipt encodes"))
                .expect("unknown-phase receipt parses");
        assert_eq!(
            parsed.phase,
            NativeWorkerReplayAckPhase::Unknown,
            "unknown phase preserved end to end"
        );
        assert!(!parsed.phase.advances_producer_cursor());
        assert!(!parsed.phase.advances_consumer_cursor());
        assert!(!parsed.phase.retention_releasable());

        assert!(NativeWorkerReplayAckPhase::Durable.advances_producer_cursor());
        assert!(!NativeWorkerReplayAckPhase::Durable.advances_consumer_cursor());
        assert!(!NativeWorkerReplayAckPhase::Durable.retention_releasable());
        assert!(!NativeWorkerReplayAckPhase::Applied.advances_producer_cursor());
        assert!(NativeWorkerReplayAckPhase::Applied.advances_consumer_cursor());
        assert!(NativeWorkerReplayAckPhase::Applied.retention_releasable());
        assert!(NativeWorkerReplayAckPhase::Rejected.advances_consumer_cursor());
        assert!(NativeWorkerReplayAckPhase::Rejected.retention_releasable());
        assert!(!NativeWorkerReplayAckPhase::Received.advances_producer_cursor());
        assert!(!NativeWorkerReplayAckPhase::Received.advances_consumer_cursor());
        assert!(!NativeWorkerReplayAckPhase::Normalized.advances_consumer_cursor());

        let inflated = NativeWorkerReplayAcknowledgeReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            stream_id: stream_id.clone(),
            event_id: "event-1".to_owned(),
            sequence: 1,
            phase: NativeWorkerReplayAckPhase::Unknown,
            producer_cursor_advanced: true,
            consumer_cursor_advanced: false,
        };
        let error = inflated
            .validate()
            .expect_err("unknown cannot claim producer advance");
        assert!(
            format!("{error:?}").contains("producer_cursor_advanced"),
            "producer consistency arm, got {error:?}"
        );
        let inflated = NativeWorkerReplayAcknowledgeReply {
            producer_cursor_advanced: false,
            consumer_cursor_advanced: true,
            ..inflated
        };
        let error = inflated
            .validate()
            .expect_err("unknown cannot claim consumer advance");
        assert!(
            format!("{error:?}").contains("consumer_cursor_advanced"),
            "consumer consistency arm, got {error:?}"
        );
        let honest = NativeWorkerReplayAcknowledgeReply {
            producer_cursor_advanced: false,
            consumer_cursor_advanced: false,
            ..inflated
        };
        honest.validate().expect("honest unknown reply validates");
    }

    #[test]
    fn replay_page_cap_enforced() {
        let binding = valid_binding();
        let limited = NativeWorkerReplayReplayRequest {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            binding: binding.clone(),
            after_sequence: 0,
            limit: 0,
        };
        let error = limited.validate().expect_err("zero page rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay_replay.limit"),
            "page floor arm, got {error:?}"
        );
        let limited = NativeWorkerReplayReplayRequest {
            limit: NATIVE_WORKER_REPLAY_MAX_PAGE + 1,
            ..limited
        };
        let error = limited.validate().expect_err("over-cap page rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay_replay.limit"),
            "page cap arm, got {error:?}"
        );

        let over_cap: Vec<NativeWorkerReplayEnvelope> = (1_u64..=257)
            .map(|sequence| test_envelope(&binding.stream_id, sequence))
            .collect();
        assert_eq!(over_cap.len(), 257);
        let reply = NativeWorkerReplayReplayReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            page: NativeWorkerReplayPage {
                stream_id: binding.stream_id.clone(),
                after_sequence: 0,
                events: over_cap,
            },
        };
        let error = reply.validate().expect_err("over-cap page rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay_page.events"),
            "page event cap arm, got {error:?}"
        );

        let at_cap: Vec<NativeWorkerReplayEnvelope> = (1_u64..=256)
            .map(|sequence| test_envelope(&binding.stream_id, sequence))
            .collect();
        let reply = NativeWorkerReplayReplayReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            page: NativeWorkerReplayPage {
                stream_id: binding.stream_id.clone(),
                after_sequence: 0,
                events: at_cap,
            },
        };
        reply.validate().expect("at-cap page validates");

        let caught_up = NativeWorkerReplayReplayReply {
            wire_id: NATIVE_WORKER_REPLAY_WIRE_ID.to_owned(),
            wire_version: NATIVE_WORKER_REPLAY_WIRE_VERSION,
            page: NativeWorkerReplayPage {
                stream_id: binding.stream_id.clone(),
                after_sequence: 41,
                events: Vec::new(),
            },
        };
        caught_up
            .validate()
            .expect("empty caught-up page validates");

        let empty_decision = NativeWorkerReplayDecision::Replay(NativeWorkerReplayPage {
            stream_id: binding.stream_id.clone(),
            after_sequence: 41,
            events: Vec::new(),
        });
        let error = empty_decision
            .validate()
            .expect_err("empty decision page rejected");
        assert!(
            format!("{error:?}").contains("native_worker_replay_page.events"),
            "decision page floor arm, got {error:?}"
        );
    }
}
