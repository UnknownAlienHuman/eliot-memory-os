//! Process-stream sink port over the one active `BlobStoreService` owner
//! (issue #297).
//!
//! [`BlobStoreStreamSink`] implements the exact #296 sink client/session port
//! (`eliot-process` `stream_sink`) with durable bytes provided by the single
//! injected [`BlobStoreClient`] handle. The handle is shared, never re-owned:
//! cloning the service handle shares its core and never re-claims the root,
//! so this adapter cannot create a second blob root, log database, or
//! canonical writer. Blob durability proves bytes only; no semantic,
//! canonical, verification, or finish receipt is issued here.
//!
//! Design (one adapter instance serves one sink session):
//!
//! * Construction binds the one root lease, the stage/read operation/request
//!   contexts, the blob policy binding, and the residency template. No
//!   mapping is invented between process-side and blob-side identities.
//! * `open` pins the sink session (operation binding, stream kind, policy,
//!   limits, open digest). A reopened request with the same open digest
//!   returns the same session; a different digest is `OpenDigestMismatch`.
//! * `append` admits exact sequence/offset chunks into a staging buffer
//!   bounded by the session ceilings, with exact-replay acknowledgement and
//!   an explicit backpressure contract. Appends never touch storage, never
//!   wait and never retry.
//! * Backpressure isolation (issue #267 W5): the RETAINED bytes this session
//!   will keep and the QUEUED / IN-FLIGHT bytes it is holding right now are
//!   two separate accountings against two separate declared ceilings, and both
//!   are enforced. See [`PersistenceQueueBound`].
//! * The declared overflow disposition is `Backpressured`: a full persistence
//!   queue REFUSES the append, stages nothing and charges nothing, and the
//!   caller applies backpressure at its own end. This adapter holds no wait
//!   on the append path, so persistence pressure can never stall the pipe
//!   drain.
//! * `finalize` publishes only a gap-free, transport-complete source through
//!   one durable stage call, verifies the ready receipt, reads the object
//!   back, and only then mints the `COMPLETE_SOURCE` terminal. Anything else
//!   (gaps, policy prohibition, redaction failure, provider failure, digest
//!   mismatch, cancellation, unknown outcome) never becomes
//!   `COMPLETE_SOURCE`, and policy-prohibited or failed-redaction terminals
//!   never stage raw bytes.
//! * Staged plaintext is dropped when a terminal lands; only counts and the
//!   incremental transport digest survive for readback/replay.
//!
//! Finalization is a bounded phase machine, never a permanently reserved
//! flag (issue #297 external audit `5881604166`). The one terminal command of
//! a session owns exactly one [`FinalizeReservation`] whose phase is
//! `Reserved` (validated, nothing handed to the blob owner),
//! `StageOutcomeUnknown` (the exact stage request may or may not have taken
//! effect) or `ReadbackPending` (the owner returned a real
//! [`BlobReadyReceipt`], the readback is outstanding). The reservation is
//! bookkeeping bound to the same session, the same terminal command digest
//! and the same blob stage operation identity — it is not a second external
//! operation id, a second plaintext copy or a second blob root.
//!
//! * The real ready receipt and its exact byte commitment are retained
//!   immediately after `stage` returns and before the next await, so a failed
//!   readback resumes the read and never stages again.
//! * A failure whose effect provably cannot have occurred (stale/revoked
//!   admission, unclaimed key, invalid contract) releases the handoff back to
//!   `Reserved`; every other failure retains `StageOutcomeUnknown` so a lost
//!   response or a dropped future stays `UnknownOutcome` until owner evidence
//!   settles it.
//! * `reconcile` resolves the *original* stage identity against the injected
//!   owner. The owner is idempotent under its own operation identity, so an
//!   exact replay returns the same object and never a second one; a cache miss
//!   is not proof of non-publication.
//! * A local finalize owner is released only for its own incarnation, only
//!   while `Reserved`, and never across an await. There is no RPC in `Drop`,
//!   no detached task, and no reset to `Open` to bypass a possible effect.
//!
//! Whole-stream copies (I10.8.5): the publication path stages the admitted
//! plaintext ONCE through the one blob owner and never rematerializes it a
//! second time for comparison. `record_locked` drops the session's staged
//! bytes as soon as the owner receipt is recorded, and `publication_of`
//! compares the owner's READBACK against the digest the reservation already
//! sealed, so finalization verifies the staged object's exact length/digest
//! without rebuilding the plaintext to hash it again.
//!
//! The ticket receives a clone rather than a move, deliberately: the finalize
//! reservation retains the admitted DIGEST and never the bytes, so moving the
//! buffer out of the session would make a publish future dropped before the
//! owner call destroy the only copy and leave a reservation that can never be
//! satisfied. Two full-plaintext buffers are therefore live only for the
//! duration of one in-flight publication, and a dropped publication stays
//! recoverable. The append-only temporary object that removes this window
//! entirely is the #297 path named below.
//!
//! Shed bytes are never coverage (issue #267 W5). An append refused by the
//! persistence-queue ceiling is refused BEFORE anything is charged: it does
//! not reach `staged`, does not feed the transport digest or the preview, and
//! advances neither `next_sequence` nor `next_offset`. So a shed byte cannot
//! appear in the admitted digest, the admitted count, the published object or
//! any measure, and a session that shed is only ever publishable if its own
//! caller declared the matching gap. Bytes that are dropped are recorded by
//! the caller as `StreamEvidenceGap::PersistenceBackpressure`; this adapter
//! never mints a terminal that calls them covered.
//!
//! Publication coverage (audit `5881613195`): a terminal is always the one
//! [`BlobStreamPublication`] the session actually proved. A gapped,
//! policy-prohibited or failed-redaction finalize never calls the owner at
//! all, so no raw byte is staged to preserve coverage. A policy-prohibited or
//! failed-redaction terminal is additionally forbidden from carrying any
//! inline preview by the shared terminal-evidence invariant, so a raw
//! pre-policy preview can never reach the durable record.
//!
//! Transformation binding (issue #267 W7): this adapter applies NO byte-level
//! transformation. It normalizes nothing, decodes nothing, re-encodes nothing,
//! inserts no header or length prefix and joins no chunk boundary by rewriting
//! bytes — admitted chunks are staged verbatim and their SHA-256 is the
//! transport digest. The only byte-touching derivations are the two digests the
//! owner needs: BLAKE3 over the staged bytes for the store's content identity
//! ([`BlobStoreStreamSink::stage_request`]) and SHA-256 over them for the
//! ready-receipt and readback commitment.
//!
//! Because it holds no transformed bytes it can never OBSERVE a transformation's
//! output, so it refuses every terminal command that declares one
//! ([`refuse_transformation`]) instead of recording an unverified output digest.
//! A raw pre-policy preview therefore cannot reach the durable record through
//! this adapter in either direction: transformed output is refused outright, and
//! a policy-prohibited or failed-redaction terminal cannot carry an inline
//! preview at all.
//!
//! Owner boundary still open elsewhere: the transformer producer contract — the
//! owner that would stage transformed bytes together with their exact
//! input/output receipt — does not exist. `ProcessStreamTransformationBinding`
//! already carries the receipt, policy and redaction references the process
//! contract needs; what is missing is a caller that produces transformed bytes
//! and an append-shaped way to stage them under the one bound blob operation
//! identity (issue #297). No policy identifier or transformation enum was
//! invented here to fill that gap.
//!
//! Owner boundary still open elsewhere: the append-only *temporary* object
//! required by I10.8.5 needs an `append`-shaped operation on the one blob
//! owner (issue #297, `eliot-blob-api` + `eliot-blob` service). The bound
//! `stage` context here is a single operation identity, so a per-chunk append
//! cannot be expressed through it without inventing a second operation
//! identity space. This adapter therefore stages once, at finalization, and
//! never claims a durable per-chunk frontier.
//!
//! Governing fragments: I5.12 (single-owner CAS, BYTES-only durability),
//! I10.8.5 (bounded preview, append-only temporary evidence, final
//! BlobRef+digest), I5.27 (exact operation/session identity, no blind
//! retry), I7.2 (idempotent replay under an exact fence, no second object),
//! I14.21 (unknown commit recovery under the original idempotency key).

use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::Serialize;

use eliot_blob_api::{
    BlobError, BlobHash, BlobPolicyBinding, BlobReadRequest, BlobReadyReceipt, BlobReceiptContext,
    BlobRootLease, BlobStageRequest, BlobStoreClient, ObjectResidencyKey, VersionedContentDigest,
};
use eliot_process::{
    DurableProcessStreamSource, DurableStreamLocatorKind, DurableStreamRepresentation,
    PROCESS_STREAM_SINK_SCHEMA_VERSION, ProcessStreamDigestAlgorithm, ProcessStreamEvidence,
    ProcessStreamPrefixPreview, ProcessStreamSinkAbortReason, ProcessStreamSinkAbortRequest,
    ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition, ProcessStreamSinkClient,
    ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest, ProcessStreamSinkFuture,
    ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback, ProcessStreamSinkSession,
    ProcessStreamSinkSessionView, ProcessStreamSinkState, ProcessStreamSinkTerminal,
    ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkUnknownOutcome,
    ProcessStreamTransformationBinding, StreamByteRange, StreamEvidenceGap,
    StreamPersistenceStatus, StreamPreviewRepresentation, StreamTransportStatus,
};
use eliot_receipts::EffectClass;
use sha2::{Digest, Sha256};

/// The exact measures computed for one terminal while its bytes arrived.
///
/// Each measure names the bytes it covers, the byte length covered, the
/// versioned digest over exactly those bytes, and the exact ranges it does not
/// represent. A measure is never a stand-in for another: the transport, the
/// admissible source and the bounded preview are separate quantities over
/// separate byte sets, and each one states its own omissions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamEvidenceMeasures {
    /// Physical transport bytes of the process stream that this session
    /// admitted, in arrival order.
    pub transport: BlobStreamTransportMeasure,
    /// Admissible-source bytes after the declared policy transformation.
    pub admissible_source: BlobStreamAdmissibleSourceMeasure,
    /// The bounded inline preview and what it omits.
    pub bounded_preview: BlobStreamBoundedPreviewMeasure,
}

/// Byte count and full versioned digest of the physical transport bytes this
/// session admitted, in arrival order.
///
/// It is one pass over the arriving chunks, not a re-walk of the stream: the
/// running `Sha256` in [`SinkState::transport`] is fed once per admitted chunk
/// and finalized into this record. It describes the bytes this adapter was
/// given; it is never presented as the physical stream capture, which stays
/// with the `ProcessExecutor` owner (#1812).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamTransportMeasure {
    /// Digest revision this measure was computed under.
    pub digest_algorithm: ProcessStreamDigestAlgorithm,
    /// Admitted transport byte count.
    pub byte_count: u64,
    /// Full digest over exactly those admitted transport bytes.
    pub sha256: String,
}

/// The bounded inline preview plus the exact byte ranges it leaves out.
///
/// The preview is bounded, so what it omits is stated exactly: a reader can
/// tell precisely which byte range of the represented stream the retained
/// prefix does not stand for. The omitted range is half-open, in the byte
/// coordinates of [`BlobStreamBoundedPreviewMeasure::representation`], and it
/// starts exactly at the retained length — a truncated preview therefore never
/// reads as a complete one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamBoundedPreviewMeasure {
    /// Byte coordinates the retained prefix and its omission live in.
    pub representation: StreamPreviewRepresentation,
    /// Digest revision this measure was computed under.
    pub digest_algorithm: ProcessStreamDigestAlgorithm,
    /// Bytes the bounded preview actually retains.
    pub retained_byte_count: u64,
    /// Total bytes in the represented stream.
    pub represented_byte_count: u64,
    /// Digest over exactly the retained preview bytes.
    pub sha256: String,
    /// Exact omitted suffix, empty when the preview represents every byte.
    pub omitted_ranges: Vec<StreamByteRange>,
}

/// The owner-backed durable admitted prefix retained by one `Partial` abort.
///
/// This is boxed inside [`BlobStreamPublication::Partial`] for the same sizing
/// reason as [`BlobStreamCompleteSource`]: the locator, receipt and identity
/// fields would otherwise make the variant far larger than `Unavailable`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamPartialPrefix {
    /// Immutable locator of the retained prefix object.
    pub locator: String,
    /// Owner-issued receipt identity that resolves and verifies it.
    pub ready_receipt_ref: String,
    /// Exact durable byte length of the retained prefix.
    pub byte_length: u64,
    /// SHA-256 over exactly the retained prefix bytes.
    pub sha256: String,
}

/// The owner-backed durable expansion source of one `Complete` terminal.
///
/// This is boxed inside [`BlobStreamPublication::Complete`] so the enum stays
/// sized by its pointer: three inline measure records would otherwise make the
/// `Complete` variant far larger than `Unavailable` carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamCompleteSource {
    /// Immutable locator of the published object.
    pub locator: String,
    /// Owner-issued receipt identity that resolves and verifies it.
    pub ready_receipt_ref: String,
    /// Exact durable byte length of the published object.
    pub byte_length: u64,
    /// SHA-256 over exactly the published bytes.
    pub sha256: String,
    /// The measures computed for this terminal while its bytes arrived.
    pub measures: BlobStreamEvidenceMeasures,
}

/// What the durable expansion source of one terminal actually is.
///
/// This is the adapter's explicit publication outcome (issue #267 W4). Every
/// terminal carries exactly one of these, and the value is derived only from
/// owner-issued evidence — never from a nonempty locator, a fixture, or a
/// process-local counter.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BlobStreamPublication {
    /// The whole admissible representation is durable: the owner returned a
    /// real ready receipt for the exact admitted bytes and the readback of
    /// that very object matched its byte commitment.
    ///
    /// A zero-byte complete source is a real immutable object here too: its
    /// locator hash is the empty-content digest and it still resolves through
    /// its own ready receipt. It is never reported as "no source".
    ///
    /// The payload is boxed, and carries the measures of this terminal beside
    /// the owner-backed identity of the object.
    Complete(Box<BlobStreamCompleteSource>),
    /// The admitted prefix is durable as a real owner-staged object, but the
    /// source as a whole is not: the abort named an explicit coverage gap, so
    /// the terminal mints `PartialSource` with the prefix locator, length and
    /// digest. Only a cancellation, caller-shutdown or transport-failure abort
    /// with a nonempty admitted prefix lands here: a policy-prohibited or
    /// failed-redaction abort must never stage raw bytes, and an empty prefix
    /// retains nothing. The staged object is immutable and content-addressed,
    /// so a same-identity abort replay resolves the same object, never a
    /// second one.
    Partial(Box<BlobStreamPartialPrefix>),
    /// No durable expansion source exists for this terminal.
    ///
    /// `reason` names the exact blocking cause. A policy-prohibited or
    /// failed-redaction session always lands here and never stages raw bytes.
    Unavailable {
        /// Exact reason the source could not be produced.
        reason: BlobStreamUnavailableReason,
    },
}

/// The exact blocking cause of an unavailable durable source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlobStreamUnavailableReason {
    /// Current policy forbids durable retention or inline disclosure.
    PolicyProhibited,
    /// The configured redaction/transformation profile failed.
    RedactionFailed,
    /// The declared gaps mean the received bytes are not a complete source.
    CoverageGap,
    /// The provider was unavailable before any exact result.
    PersistenceUnavailable,
    /// The provider returned a known failure.
    PersistenceFailed,
    /// The provider effect may or may not have committed.
    PersistenceUnknownOutcome,
}

/// Locator scheme for blob-published stream sources.
///
/// The process contract forbids `raw:`, `memory:`, and `process-memory:`
/// locators; any other `scheme:remainder` shape is an opaque immutable
/// reference. `blob:<content-hash>` names the store class (matching the
/// `Blob` locator kind) with the exact content identity as remainder. It
/// carries no vendor path, generation, or residency detail into the process
/// contract; the ready receipt reference resolves and verifies the object.
const BLOB_SOURCE_LOCATOR_SCHEME: &str = "blob";

/// Serialized size of one `u64` field in a queue record.
///
/// A canonical serialization carries the value's decimal text, but the byte
/// width of the slot is used here as the FIXED per-record overhead, so the
/// charge is a floor: it can only understate a real digest string, and a real
/// digest string is added on top of it exactly. This is not a new limit — it
/// is the width of a field the record already has.
const U64_SERIALIZED_BYTES: u64 = 8;

/// Store-side identities bound once for one sink session.
///
/// The composition owner supplies the one root lease, one stage context
/// (reversible-mutation effect), one read context (read effect), one blob
/// policy binding, and one residency template. The template's content-digest
/// algorithm/version are reused; its digest value is replaced at finalize
/// with the BLAKE3 of the exact staged bytes, which is the content identity
/// the service addresses (and which `BlobLocator` validation requires to
/// equal the locator hash).
#[derive(Clone, Debug)]
pub struct BlobStreamSinkStoreBinding {
    root_lease: BlobRootLease,
    stage_context: BlobReceiptContext,
    read_context: BlobReceiptContext,
    policy: BlobPolicyBinding,
    residency: ObjectResidencyKey,
}

impl BlobStreamSinkStoreBinding {
    /// Binds the store-side identities after validating each one.
    pub fn new(
        root_lease: BlobRootLease,
        stage_context: BlobReceiptContext,
        read_context: BlobReceiptContext,
        policy: BlobPolicyBinding,
        residency: ObjectResidencyKey,
    ) -> Result<Self, BlobError> {
        root_lease.validate()?;
        root_lease.validate_context(&stage_context)?;
        root_lease.validate_context(&read_context)?;
        stage_context.validate_for(EffectClass::ReversibleMutation)?;
        read_context.validate_for(EffectClass::Read)?;
        policy.validate_for_residency(&residency)?;
        Ok(Self {
            root_lease,
            stage_context,
            read_context,
            policy,
            residency,
        })
    }

    /// The one bound root lease.
    #[must_use]
    pub const fn root_lease(&self) -> &BlobRootLease {
        &self.root_lease
    }

    /// The bound stage operation/request identity.
    #[must_use]
    pub const fn stage_context(&self) -> &BlobReceiptContext {
        &self.stage_context
    }

    /// The bound read operation/request identity.
    #[must_use]
    pub const fn read_context(&self) -> &BlobReceiptContext {
        &self.read_context
    }

    /// The bound blob policy binding.
    #[must_use]
    pub const fn policy(&self) -> &BlobPolicyBinding {
        &self.policy
    }

    /// The bound residency template (content digest replaced at finalize).
    #[must_use]
    pub const fn residency(&self) -> &ObjectResidencyKey {
        &self.residency
    }
}

/// The append-only temporary raw evidence object of
/// `docs/architecture/I10-08-05-ip3-streaming-evidence-and-normalization.md:9`.
/// Vec-backed seam; the durable append-only object replaces the backing in a
/// later task, the push-only API stays.
#[derive(Clone, Debug, Default)]
struct StagedPrefix {
    bytes: Vec<u8>,
}

impl StagedPrefix {
    fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn clear(&mut self) {
        self.bytes.clear();
    }
}

/// One validated abort: either a replay of the recorded terminal, or the
/// snapshot the terminal is minted from after the optional owner stage.
enum AbortSnapshot {
    /// The command identity already recorded this terminal.
    Replayed(ProcessStreamSinkTerminal),
    /// Validated inputs plus the exact admitted prefix to maybe retain.
    Prepared(AbortPrepared),
}

/// Everything `abort_async` needs after the owner stage resolves.
struct AbortPrepared {
    session: ProcessStreamSinkSession,
    request: ProcessStreamSinkAbortRequest,
    identity: ProcessStreamSinkTerminalCommandIdentity,
    reason: ProcessStreamSinkAbortReason,
    staged: Vec<u8>,
    next_sequence: u64,
    next_offset: u64,
    admitted_sha256: String,
    /// True only for a retaining reason with a nonempty admitted prefix.
    retain: bool,
}

struct SinkState {
    session: Option<ProcessStreamSinkSession>,
    /// Admitted-but-not-yet-published plaintext. It is handed to the publish
    /// ticket as a CLONE and stays in the session until `record_locked` drops
    /// it, so planning or dropping a publish never destroys the only copy.
    staged: StagedPrefix,
    /// The exact publication outcome proven for this session, once a terminal
    /// recorded it. `None` means no terminal has landed yet.
    publication: Option<BlobStreamPublication>,
    /// Running digest of the admitted transport bytes, fed once per admitted
    /// chunk. This is the one digester the adapter owns; the transport measure
    /// is its finalization and is never recomputed from another byte set.
    transport: TransportDigest,
    /// Bounded preview accumulation: the retained prefix bytes and their
    /// running digest. It stops filling at the session preview ceiling, so the
    /// preview cost is bounded independently of the staged plaintext.
    preview: BoundedPreviewDigest,
    admitted_chunks: Vec<AdmittedChunk>,
    /// The QUEUED / IN-FLIGHT half of the accounting, independent of the
    /// RETAINED half (`next_offset` against `max_total_admitted_bytes`).
    /// See [`PersistenceQueueBound`] for what each side bounds and why the
    /// overflow disposition is a refusal rather than a block.
    persistence_queue: PersistenceQueueBound,
    next_sequence: u64,
    next_offset: u64,
    terminal: Option<ProcessStreamSinkTerminal>,
    terminal_command: Option<ProcessStreamSinkTerminalCommandIdentity>,
    /// The one bounded phase record of the one reserved terminal command.
    finalization: Option<FinalizeReservation>,
    /// Monotonic local incarnation counter. A stale finalizer that outlived
    /// its reservation can never release the successor's reservation.
    finalization_incarnation: u64,
}

/// Running digest of the admitted physical transport bytes.
///
/// `Sha256` is the revision the session's `transport_digest_algorithm` names,
/// so the finalized digest is versioned by that session rather than by an
/// adapter-local choice. One instance accumulates exactly one operation's
/// bytes; it is never reused across sessions or re-seeded.
#[derive(Clone, Debug)]
struct TransportDigest {
    algorithm: ProcessStreamDigestAlgorithm,
    state: Sha256,
    byte_count: u64,
}

/// Bounded retained prefix of the admitted transport bytes and its digest.
///
/// The bytes are retained only while the prefix is still filling. Once the
/// session preview ceiling is reached the retained bytes are released and the
/// record keeps the digest alone, so a long stream does not retain a second
/// copy of its prefix after it stopped growing. When the staged bytes are
/// already gone — a resumed publish — the retained prefix was already proven
/// against them by `check_preview`, so an over-limit ceiling cannot leave a
/// growing digest claiming a whole-stream preview.
#[derive(Clone, Debug)]
struct BoundedPreviewDigest {
    algorithm: ProcessStreamDigestAlgorithm,
    state: Sha256,
    retained: Vec<u8>,
    retained_bytes: u64,
    truncated_at_ceiling: bool,
}

/// Admissible-source byte count/digest — the exact bytes this adapter stages.
///
/// This adapter stages the admitted transport stream verbatim and refuses any
/// command declaring a policy transformation (see [`refuse_transformation`]), so
/// the admissible source is always `ExactTransportBytes`: one measure over the
/// admitted byte set, identical in value to the transport measure and never a
/// digest derived by transforming it. The `representation` field stays because
/// the process contract's preview coordinates are expressed against it, but
/// `PolicyTransformed` is not a value this adapter can produce.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BlobStreamAdmissibleSourceMeasure {
    /// Relationship between this source and the physical transport bytes.
    pub representation: DurableStreamRepresentation,
    /// Digest revision this measure was computed under.
    pub digest_algorithm: ProcessStreamDigestAlgorithm,
    /// Admissible-source byte count after the declared transformation.
    pub byte_count: u64,
    /// Digest over exactly those admissible-source bytes.
    pub sha256: String,
}

/// One admitted chunk's queue metadata — no plaintext.
///
/// A record is what the persistence queue holds *beside* the plaintext: a
/// sequence, an offset, the exact byte length and the caller's per-chunk
/// digest string. It is why `max_in_flight_chunks` bounds records rather than
/// a claim, and it is why the in-flight byte charge is a serialization size
/// and not a `Vec::len()`: `Vec::len()` counts one chunk's payload only, and
/// is blind to this record and to the same bytes already copied into
/// [`SinkState::staged`].
struct AdmittedChunk {
    sequence: u64,
    offset: u64,
    length: u64,
    sha256: String,
}

/// The two INDEPENDENT accountings this adapter now keeps for one session.
///
/// They are deliberately separate quantities and neither is derived from the
/// other, because "bytes the sink will KEEP" and "bytes the sink is HOLDING
/// right now on behalf of persistence" have different ceilings and different
/// failure modes:
///
/// * **RETAINED** is the caller-supplied `max_total_admitted_bytes`. It is
///   what the terminal's coverage claim rests on, and it is charged against
///   `next_offset` — a monotone cursor that never runs back down, so a
///   released byte is never re-spendable and the total over a session's life
///   is bounded by the session, not by instantaneous occupancy.
/// * **QUEUED / IN-FLIGHT** is the declared `max_in_flight_chunks` and
///   `max_in_flight_bytes`. It is charged when an append is admitted and
///   released when the session's terminal is recorded. Until then the charge
///   is real memory this adapter is holding, so a full queue refuses the
///   *next* append immediately instead of waiting for room to appear.
///
/// The overflow disposition is `ProcessStreamSinkAppendDisposition::
/// Backpressured`: the append is REFUSED, nothing is staged, and the caller
/// applies backpressure at its own end and records the shed byte range as a
/// `StreamEvidenceGap`. This adapter never blocks, never sleeps, never retries
/// and never queues behind a provider call, so a full persistence queue
/// cannot stall the pipe drain.
///
/// Every dimension here is a ceiling this crate already READS from the
/// session (`ProcessStreamSinkLimits::max_in_flight_chunks` and
/// `::max_in_flight_bytes`), both of which the #296 constructor already
/// rejects at zero. No numeric limit is invented by this adapter.
struct PersistenceQueueBound {
    /// Queued/in-flight chunk records currently charged.
    queued_chunks: u32,
    /// Queued/in-flight bytes currently charged, measured as a serialization
    /// size (see [`PersistenceQueueBound::record_bytes`]).
    queued_bytes: u64,
    /// Latched once a queued/in-flight ceiling refused an append. It is never
    /// cleared, so once the persistence queue has overflowed every later
    /// append sheds too and the pipe keeps draining at full speed. Latching
    /// is what makes "cannot stall indefinitely" structural rather than a
    /// property of the caller noticing to stop retrying.
    overflowed: bool,
}

impl PersistenceQueueBound {
    /// Serialization size of one chunk's queue metadata plus its payload.
    ///
    /// The four `u64` slots are charged at their byte width (see
    /// [`U64_SERIALIZED_BYTES`]) and the digest at its exact hex length, so
    /// the fixed part is a floor rather than an over-count. A longer digest
    /// only ever RAISES the charge, so this can never under-count what the
    /// record really costs.
    fn record_bytes(length: u64, sha256_hex_len: usize) -> u64 {
        // The fixed fields are the sequence, the offset, the length and the
        // retained digest's own length — four `u64` slots.
        let fixed = 4 * U64_SERIALIZED_BYTES;
        let digest = u64::try_from(sha256_hex_len).unwrap_or(u64::MAX);
        fixed.saturating_add(digest).saturating_add(length)
    }
}

/// Bounded phase record for the one terminal command of one session.
///
/// Exactly one record exists per session, so it is bounded by the session's
/// own limits (the retained request's preview is already capped by
/// `max_preview_bytes` and its gaps by the protocol ceiling). The reservation
/// holds only counters, the admitted digest, and — once the owner returned
/// one — the real ready receipt. The staged plaintext is *cloned* out of
/// [`SinkState::staged`] into the publish ticket and dropped as soon as the
/// owner's ready receipt carries the same byte commitment, so the record
/// never retains a second copy of the stream and never takes the session's
/// only copy away from it.
struct FinalizeReservation {
    identity: ProcessStreamSinkTerminalCommandIdentity,
    incarnation: u64,
    /// The retained original finalize command, so `reconcile` can drive the
    /// same exact command without minting a second terminal request.
    request: ProcessStreamSinkFinalizeRequest,
    next_sequence: u64,
    next_offset: u64,
    admitted_sha256: String,
    stage_operation_id: String,
    stage_idempotency_key: String,
    phase: FinalizePhase,
}

enum FinalizePhase {
    /// Validated and reserved; nothing has been handed to the blob owner.
    Reserved,
    /// The exact stage request may or may not have taken effect. Only owner
    /// evidence settles it.
    StageOutcomeUnknown,
    /// The owner returned a real ready receipt; the readback is outstanding.
    ReadbackPending { ready: Box<BlobReadyReceipt> },
}

impl FinalizeReservation {
    /// True once an external effect became possible for this command.
    fn effect_possible(&self) -> bool {
        !matches!(self.phase, FinalizePhase::Reserved)
    }

    fn ready(&self) -> Option<&BlobReadyReceipt> {
        match &self.phase {
            FinalizePhase::ReadbackPending { ready } => Some(ready.as_ref()),
            FinalizePhase::Reserved | FinalizePhase::StageOutcomeUnknown => None,
        }
    }
}

/// What the next durable publication step must be for one reserved command.
enum PublishStep {
    /// Hand the exact admitted bytes to the one blob owner under the bound
    /// stage operation identity. The bytes are a clone of what the session
    /// still retains, so a dropped publication future stays recoverable.
    Stage { staged: Vec<u8> },
    /// The owner already returned a real ready receipt; resume the readback
    /// only. `stage` must not be called again for this command.
    Readback { ready: Box<BlobReadyReceipt> },
}

struct PublishTicket {
    session: ProcessStreamSinkSession,
    request: ProcessStreamSinkFinalizeRequest,
    identity: ProcessStreamSinkTerminalCommandIdentity,
    incarnation: u64,
    next_sequence: u64,
    next_offset: u64,
    admitted_sha256: String,
    /// The exact measures computed for this terminal while its bytes arrived.
    measures: BlobStreamEvidenceMeasures,
    step: PublishStep,
}

struct WithheldTicket {
    session: ProcessStreamSinkSession,
    request: ProcessStreamSinkFinalizeRequest,
    identity: ProcessStreamSinkTerminalCommandIdentity,
    next_sequence: u64,
    next_offset: u64,
    admitted_sha256: String,
    state: ProcessStreamSinkState,
    /// The exact reason no durable source exists for this terminal.
    publication: BlobStreamPublication,
}

enum FinalizePlan {
    /// The one terminal for this exact command already landed.
    Recorded(Box<ProcessStreamSinkTerminal>),
    /// Nothing durable is authorized: mint the withheld terminal locally.
    Withheld(Box<WithheldTicket>),
    /// A durable publication is reserved (or resumable) for this command.
    Publish(Box<PublishTicket>),
}

/// Canonical, deterministic description of the uncertain blob effect a
/// reservation may have caused. It binds the session, the exact terminal
/// command digest, the bound blob stage operation identity and the exact
/// admitted byte commitment, so a caller can only present the uncertainty
/// this exact reservation produced.
#[derive(Serialize)]
struct FinalizeUncertainty<'a> {
    schema_version: &'a str,
    session_id: &'a str,
    terminal_id: &'a str,
    open_request_sha256: &'a str,
    command_sha256: &'a str,
    stage_operation_id: &'a str,
    stage_idempotency_key: &'a str,
    admitted_sha256: &'a str,
    final_sequence: u64,
    final_offset: u64,
}

impl TransportDigest {
    fn new() -> Self {
        Self {
            algorithm: ProcessStreamDigestAlgorithm::Sha256,
            state: Sha256::new(),
            byte_count: 0,
        }
    }

    fn new_with(algorithm: ProcessStreamDigestAlgorithm) -> Self {
        Self {
            algorithm,
            ..Self::new()
        }
    }

    fn absorb(&mut self, bytes: &[u8]) {
        self.state.update(bytes);
        self.byte_count = self
            .byte_count
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
    }

    fn digest(&self) -> String {
        format!("{:x}", self.state.clone().finalize())
    }

    fn measure(&self) -> BlobStreamTransportMeasure {
        BlobStreamTransportMeasure {
            digest_algorithm: self.algorithm,
            byte_count: self.byte_count,
            sha256: self.digest(),
        }
    }
}

impl BoundedPreviewDigest {
    fn new() -> Self {
        Self {
            algorithm: ProcessStreamDigestAlgorithm::Sha256,
            state: Sha256::new(),
            retained: Vec::new(),
            retained_bytes: 0,
            truncated_at_ceiling: false,
        }
    }

    fn new_with(algorithm: ProcessStreamDigestAlgorithm) -> Self {
        Self {
            algorithm,
            ..Self::new()
        }
    }

    /// Folds one admitted chunk into the bounded preview.
    ///
    /// While the retained prefix is still within the ceiling the bytes are kept
    /// as well as hashed; once the ceiling is reached the retained bytes are
    /// released and only the digest keeps growing. The digest therefore always
    /// covers exactly the retained bytes the preview ends up representing, and
    /// the accumulated preview cost never exceeds the session ceiling.
    fn absorb(&mut self, bytes: &[u8], ceiling: u64) {
        self.state.update(bytes);
        let admitted = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self.truncated_at_ceiling {
            return;
        }
        if self.retained_bytes.saturating_add(admitted) > ceiling {
            self.truncated_at_ceiling = true;
            self.retained = Vec::new();
            return;
        }
        self.retained.extend_from_slice(bytes);
        self.retained_bytes = self.retained_bytes.saturating_add(admitted);
    }

    fn digest(&self) -> String {
        format!("{:x}", self.state.clone().finalize())
    }
}

impl SinkState {
    fn new() -> Self {
        Self {
            session: None,
            staged: StagedPrefix::new(),
            publication: None,
            transport: TransportDigest::new(),
            preview: BoundedPreviewDigest::new(),
            admitted_chunks: Vec::new(),
            persistence_queue: PersistenceQueueBound {
                queued_chunks: 0,
                queued_bytes: 0,
                overflowed: false,
            },
            next_sequence: 0,
            next_offset: 0,
            terminal: None,
            terminal_command: None,
            finalization: None,
            finalization_incarnation: 0,
        }
    }

    /// Binds the measure accumulators to the revisions the open session
    /// declared, once, when the session is pinned.
    ///
    /// A reopened session presenting the same open digest declares the same
    /// revisions, so re-binding is idempotent; a differing open digest is refused
    /// before this point, so a measure can never be stamped with a revision other
    /// than the one its session committed to.
    fn bind_measure_revisions(&mut self, session: &ProcessStreamSinkSession) {
        // W7: this used to be guarded by a `self.admissible_source` field that
        // was initialised to `None` and NEVER assigned anywhere, so the guard
        // could not fire and the field's own documentation ("`None` until a
        // terminal command declares a transformation") described behaviour that
        // did not exist. A declared-but-never-written revision check is the same
        // unaccounted-quantity shape as an unused ceiling: it reads as a live
        // invariant and proves nothing. The admissible source is derived per
        // terminal command by `admissible_source_measure`, so there is no stored
        // revision to disagree with, and the real binding — the transport
        // revision this session's measures are stamped with — is below.
        self.transport = TransportDigest::new_with(session.transport_digest_algorithm());
        self.preview = BoundedPreviewDigest::new_with(session.transport_digest_algorithm());
    }

    /// Feeds one admitted chunk into every measure that covers it.
    ///
    /// A single pass over the arriving bytes produces the transport count and
    /// digest, fills the bounded preview while it is still within the session
    /// ceiling, and accumulates the preview digest even after the retained bytes
    /// are released, so the preview digest always covers exactly the bytes the
    /// preview represents. The staged plaintext is extended in the same pass, so
    /// no measure re-walks or re-buffers the stream.
    fn absorb_admitted(&mut self, bytes: &[u8], preview_ceiling: u64) {
        self.transport.absorb(bytes);
        self.preview.absorb(bytes, preview_ceiling);
        self.staged.extend_from_slice(bytes);
    }

    /// The exact transport measure over the admitted physical bytes.
    fn transport_measure(&self) -> BlobStreamTransportMeasure {
        self.transport.measure()
    }

    /// The full admitted transport digest: the reservation's byte commitment.
    fn admitted_sha256(&self) -> String {
        self.transport.digest()
    }

    /// The exact admissible-source measure for one terminal command.
    ///
    /// No transformation reaches this function: every terminal command is
    /// refused by [`refuse_transformation`] before `measures_for` builds any
    /// measure, so the admissible source is ALWAYS the admitted transport stream
    /// itself and is named `ExactTransportBytes` — one measure over one byte
    /// set, never a digest derived from another and never an unobserved
    /// transformed output.
    ///
    /// A `DurableSourceBytes` preview still measures against this measure's
    /// `byte_count`, which is exactly the admitted length, so a durable-source
    /// preview cannot claim coordinates this adapter never covered.
    fn admissible_source_measure(&self) -> BlobStreamAdmissibleSourceMeasure {
        BlobStreamAdmissibleSourceMeasure {
            representation: DurableStreamRepresentation::ExactTransportBytes,
            digest_algorithm: self.transport.algorithm,
            byte_count: self.transport.byte_count,
            sha256: self.admitted_sha256(),
        }
    }

    /// The exact bounded-preview measure for one terminal command.
    ///
    /// The preview is bounded, so its omission is stated exactly: the single
    /// half-open suffix beginning at the retained length and running to the end of
    /// the represented stream, or no range at all when the preview represents
    /// every byte. Coordinates follow the declared preview representation, so a
    /// transport preview is measured against the transport stream and a
    /// durable-source preview against the declared admissible source; the omitted
    /// range is never given in coordinates the preview does not use.
    fn bounded_preview_measure(
        &self,
        request_preview: &ProcessStreamPrefixPreview,
        admissible_source: &BlobStreamAdmissibleSourceMeasure,
    ) -> Result<BlobStreamBoundedPreviewMeasure, ProcessStreamSinkError> {
        let represented_bytes = match request_preview.representation() {
            StreamPreviewRepresentation::TransportBytes => self.transport.byte_count,
            StreamPreviewRepresentation::DurableSourceBytes => admissible_source.byte_count,
            StreamPreviewRepresentation::WithheldByPolicy => 0,
        };
        let retained_bytes = request_preview.retained_bytes();
        if retained_bytes > represented_bytes {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "preview retains more bytes than the stream it represents".to_owned(),
            });
        }
        let sha256 = match request_preview.representation() {
            // The adapter's own preview accumulation, over exactly the retained
            // bytes and nothing else.
            StreamPreviewRepresentation::TransportBytes => self.preview.digest(),
            // This adapter never holds transformed bytes, so the digest of a
            // durable-source preview is the declared admissible-source identity
            // the caller built that preview from.
            StreamPreviewRepresentation::DurableSourceBytes => admissible_source.sha256.clone(),
            StreamPreviewRepresentation::WithheldByPolicy => sha256_hex(&[]),
        };
        let omitted_ranges = if retained_bytes == represented_bytes {
            Vec::new()
        } else {
            vec![
                StreamByteRange::new(retained_bytes, represented_bytes).map_err(|error| {
                    ProcessStreamSinkError::EvidenceInvariant {
                        reason: error.to_string(),
                    }
                })?,
            ]
        };
        Ok(BlobStreamBoundedPreviewMeasure {
            representation: request_preview.representation(),
            digest_algorithm: self.preview.algorithm,
            retained_byte_count: retained_bytes,
            represented_byte_count: represented_bytes,
            sha256,
            omitted_ranges,
        })
    }

    /// All three measures for one terminal command, bound to the exact
    /// admissible source this command declares.
    ///
    /// The admissible source is proven transform-free first, so no measure can
    /// ever be derived from a transformation output this adapter does not hold.
    fn measures_for(
        &self,
        request_preview: &ProcessStreamPrefixPreview,
        request_transformation: Option<&ProcessStreamTransformationBinding>,
    ) -> Result<BlobStreamEvidenceMeasures, ProcessStreamSinkError> {
        refuse_transformation(request_transformation)?;
        let admissible_source = self.admissible_source_measure();
        let bounded_preview = self.bounded_preview_measure(request_preview, &admissible_source)?;
        Ok(BlobStreamEvidenceMeasures {
            transport: self.transport_measure(),
            admissible_source,
            bounded_preview,
        })
    }
}

/// Exact #296 sink port over the one active blob owner.
///
/// `C` is the shared handle of the single active service (for example a
/// cloned [`BlobStoreService`](crate::BlobStoreService)); the adapter holds
/// it without claiming any root. One adapter instance serves one sink
/// session: `open` pins the session, later calls must present it exactly.
pub struct BlobStoreStreamSink<C> {
    store: C,
    binding: BlobStreamSinkStoreBinding,
    state: Mutex<SinkState>,
}

impl<C: BlobStoreClient> BlobStoreStreamSink<C> {
    /// Attaches the sink port to the shared store handle and binding.
    #[must_use]
    pub fn new(store: C, binding: BlobStreamSinkStoreBinding) -> Self {
        Self {
            store,
            binding,
            state: Mutex::new(SinkState::new()),
        }
    }

    /// The exact publication outcome this adapter actually proved for its one
    /// session.
    ///
    /// `None` means no terminal has landed yet: nothing is claimed about
    /// durability before an owner-issued ready receipt exists. A `Complete`
    /// value is only ever set from a real owner receipt whose readback matched
    /// its byte commitment; a nonempty locator or a fixture terminal can never
    /// produce one.
    #[must_use]
    pub fn publication(&self) -> Option<BlobStreamPublication> {
        self.lock().publication.clone()
    }

    fn lock(&self) -> MutexGuard<'_, SinkState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ready<T: Send + 'static>(
        result: Result<T, ProcessStreamSinkError>,
    ) -> ProcessStreamSinkFuture<'static, T> {
        Box::pin(async move { result })
    }

    /// Returns the admitted prefix slice when the coordinates are
    /// representable, without panicking or casting.
    fn admitted_prefix(state: &SinkState, offset: u64, length: u64) -> Option<&[u8]> {
        let start = usize::try_from(offset).ok()?;
        let length = usize::try_from(length).ok()?;
        let end = start.checked_add(length)?;
        state.staged.as_bytes().get(start..end)
    }

    fn check_session(
        state: &SinkState,
        session: &ProcessStreamSinkSession,
    ) -> Result<ProcessStreamSinkSession, ProcessStreamSinkError> {
        let existing = state
            .session
            .clone()
            .ok_or(ProcessStreamSinkError::ProviderUnavailable)?;
        if existing != *session {
            return Err(ProcessStreamSinkError::SessionMismatch);
        }
        Ok(existing)
    }

    fn check_observed(
        state: &SinkState,
        observed_sha256: &str,
        observed_bytes: u64,
    ) -> Result<(), ProcessStreamSinkError> {
        if observed_sha256 != state.admitted_sha256() || observed_bytes != state.next_offset {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "observed transport facts do not match admitted chunks".to_owned(),
            });
        }
        Ok(())
    }

    fn check_sequence_offset(
        state: &SinkState,
        sequence: u64,
        offset: u64,
    ) -> Result<(), ProcessStreamSinkError> {
        if sequence != state.next_sequence {
            return Err(ProcessStreamSinkError::SequenceGap {
                expected: state.next_sequence,
                observed: sequence,
            });
        }
        if offset != state.next_offset {
            return Err(ProcessStreamSinkError::OffsetMismatch {
                expected: state.next_offset,
                observed: offset,
            });
        }
        Ok(())
    }

    /// Verifies that a transport-bytes preview is exactly the admitted prefix.
    ///
    /// The retained bytes are checked against the admitted plaintext, and the
    /// preview digest against the digest this adapter accumulated incrementally,
    /// so a preview can only be a true prefix of the bytes this operation
    /// actually admitted.
    fn check_preview(
        state: &SinkState,
        preview: &ProcessStreamPrefixPreview,
    ) -> Result<(), ProcessStreamSinkError> {
        if preview.representation() != StreamPreviewRepresentation::TransportBytes {
            return Ok(());
        }
        let retained = usize::try_from(preview.retained_bytes()).map_err(|_| {
            ProcessStreamSinkError::EvidenceInvariant {
                reason: "preview retained length does not fit the platform".to_owned(),
            }
        })?;
        if retained > state.staged.len() || preview.bytes() != &state.staged.as_bytes()[..retained]
        {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "transport preview does not match admitted bytes".to_owned(),
            });
        }
        if state.preview.retained_bytes != preview.retained_bytes()
            || state.preview.retained.as_slice() != preview.bytes()
            || state.preview.digest() != preview.sha256()
        {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "transport preview does not match the incremental preview digest"
                    .to_owned(),
            });
        }
        Ok(())
    }

    /// The canonical uncertainty identity a reservation may present, bound to
    /// the same session, terminal command and blob stage operation.
    fn reservation_uncertainty(
        session: &ProcessStreamSinkSession,
        reservation: &FinalizeReservation,
    ) -> Result<ProcessStreamSinkUnknownOutcome, ProcessStreamSinkError> {
        let wire = FinalizeUncertainty {
            schema_version: PROCESS_STREAM_SINK_SCHEMA_VERSION,
            session_id: session.session_id().as_str(),
            terminal_id: reservation.identity.terminal_id().as_str(),
            open_request_sha256: session.open_request_sha256(),
            command_sha256: reservation.identity.request_sha256(),
            stage_operation_id: &reservation.stage_operation_id,
            stage_idempotency_key: &reservation.stage_idempotency_key,
            admitted_sha256: &reservation.admitted_sha256,
            final_sequence: reservation.next_sequence,
            final_offset: reservation.next_offset,
        };
        let bytes =
            serde_json::to_vec(&wire).map_err(|error| ProcessStreamSinkError::Serialization {
                field: "finalize_uncertainty",
                reason: error.to_string(),
            })?;
        ProcessStreamSinkUnknownOutcome::new(
            session.session_id().clone(),
            session.terminal_id().clone(),
            session.open_request_sha256().to_owned(),
            format!("{:x}", Sha256::digest(&bytes)),
        )
    }

    fn session_view(
        session: &ProcessStreamSinkSession,
        state: &SinkState,
    ) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
        let view = ProcessStreamSinkSessionView::new(
            session.session_id().clone(),
            session.source_id().clone(),
            session.terminal_id().clone(),
            if state.finalization.is_some() {
                ProcessStreamSinkState::Finalizing
            } else {
                ProcessStreamSinkState::Open
            },
            state.next_sequence,
            state.next_offset,
            state.next_sequence,
            state.next_offset,
            state.admitted_sha256(),
            session.open_request_sha256().to_owned(),
            None,
        )
        .map_err(|_| ProcessStreamSinkError::ProviderUnavailable)?;
        Ok(ProcessStreamSinkReadback::Session { view })
    }

    /// Exact bytes one arriving append charges the persistence queue.
    ///
    /// The charge is a SERIALIZATION size and not `request.byte_length()`: this
    /// adapter produces two live copies of every arriving byte — the caller's
    /// `ProcessStreamSinkAppend` and the copy this adapter extends into
    /// [`SinkState::staged`] — plus one queue record per chunk. Accounting only
    /// the payload would leave every record and the staged copy invisible to
    /// the byte ceiling, which is the finding the audit names: "not only
    /// `Vec::len()`".
    fn queue_charge_bytes(request: &ProcessStreamSinkAppend) -> u64 {
        PersistenceQueueBound::record_bytes(request.byte_length(), request.sha256().len())
    }

    fn append_locked(
        state: &mut SinkState,
        session: &ProcessStreamSinkSession,
        request: &ProcessStreamSinkAppend,
    ) -> Result<ProcessStreamSinkAppendDisposition, ProcessStreamSinkError> {
        if state.finalization.is_some() {
            return Err(ProcessStreamSinkError::AppendAfterFinalizing);
        }
        if let Some(terminal) = &state.terminal {
            return Ok(ProcessStreamSinkAppendDisposition::Terminal {
                state: terminal.state(),
                terminal_sha256: terminal.terminal_sha256().to_owned(),
            });
        }
        session.validate_append(request)?;
        if request.sequence() < state.next_sequence {
            let matches_admitted_chunk = usize::try_from(request.sequence())
                .ok()
                .and_then(|index| state.admitted_chunks.get(index))
                .is_some_and(|chunk| {
                    chunk.sequence == request.sequence()
                        && chunk.offset == request.offset()
                        && chunk.length == request.byte_length()
                        && chunk.sha256 == request.sha256()
                        && Self::admitted_prefix(state, chunk.offset, chunk.length)
                            == Some(request.bytes())
                });
            if matches_admitted_chunk {
                return Ok(ProcessStreamSinkAppendDisposition::Replayed {
                    next_sequence: state.next_sequence,
                    next_offset: state.next_offset,
                });
            }
            return Err(ProcessStreamSinkError::MismatchedReplay);
        }
        if request.sequence() > state.next_sequence {
            return Err(ProcessStreamSinkError::SequenceGap {
                expected: state.next_sequence,
                observed: request.sequence(),
            });
        }
        if request.offset() != state.next_offset {
            return Err(ProcessStreamSinkError::OffsetMismatch {
                expected: state.next_offset,
                observed: request.offset(),
            });
        }
        let limits = session.limits();
        if state.next_sequence >= limits.max_chunks() {
            return Err(ProcessStreamSinkError::ChunkCountLimitExceeded);
        }
        if request.byte_length()
            > limits
                .max_total_admitted_bytes()
                .saturating_sub(state.next_offset)
        {
            return Err(ProcessStreamSinkError::TotalLimitExceeded);
        }
        // PERSISTENCE QUEUE BOUND (issue #267 W5). This is the half of the
        // accounting the RETAINED ceiling above cannot express. `next_offset`
        // answers "how much will this session keep"; the ledger below answers
        // "how much is this adapter holding right now for persistence", and
        // the two have separate ceilings because a caller can be refused long
        // before its retained total is reached.
        //
        // The check is BEFORE any charge and before `staged` is extended, so a
        // refused append stages nothing, digests nothing and advances no
        // cursor: a shed byte can never reach the staged plaintext, the
        // transport digest or the admitted count, and therefore can never be
        // counted as covered.
        //
        // `retry_after_ms` is a hint, never a promise. This adapter holds no
        // wait on the append path — it never sleeps, never retries, never
        // queues behind a provider call — so `0` states the truth that room
        // only appears as a terminal or abort releases it. A caller that
        // retries immediately still gets an immediate, identical refusal
        // instead of a block, and the drain therefore cannot stall here.
        let charged_bytes = Self::queue_charge_bytes(request);
        if state.persistence_queue.overflowed
            || u64::from(state.persistence_queue.queued_chunks).saturating_add(1)
                > u64::from(limits.max_in_flight_chunks())
            || state
                .persistence_queue
                .queued_bytes
                .saturating_add(charged_bytes)
                > limits.max_in_flight_bytes()
        {
            // Latched, never cleared: once persistence has overflowed, every
            // later append sheds too. That is what makes the drain immune to
            // a stalled provider — a caller cannot grind through a full queue
            // by retrying, and a caller's failure to stop retrying costs it a
            // refusal per chunk, never the pipe.
            state.persistence_queue.overflowed = true;
            return Ok(ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 0 });
        }
        state.persistence_queue.queued_chunks =
            state.persistence_queue.queued_chunks.saturating_add(1);
        state.persistence_queue.queued_bytes = state
            .persistence_queue
            .queued_bytes
            .saturating_add(charged_bytes);
        state.admitted_chunks.push(AdmittedChunk {
            sequence: request.sequence(),
            offset: request.offset(),
            length: request.byte_length(),
            sha256: request.sha256().to_owned(),
        });
        // One pass over the arriving bytes feeds every measure that covers
        // them: the transport digest, the bounded preview accumulation and the
        // staged plaintext the publish ticket later clones.
        state.absorb_admitted(request.bytes(), limits.max_preview_bytes());
        state.next_sequence = state.next_sequence.saturating_add(1);
        state.next_offset = state.next_offset.saturating_add(request.byte_length());
        Ok(ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: state.next_sequence,
            next_offset: state.next_offset,
        })
    }

    fn abort_state(reason: ProcessStreamSinkAbortReason) -> ProcessStreamSinkState {
        match reason {
            ProcessStreamSinkAbortReason::Cancellation
            | ProcessStreamSinkAbortReason::CallerShutdown => ProcessStreamSinkState::Cancelled,
            ProcessStreamSinkAbortReason::PolicyProhibition => {
                ProcessStreamSinkState::PolicyProhibited
            }
            ProcessStreamSinkAbortReason::RedactionFailure => {
                ProcessStreamSinkState::RedactionFailed
            }
            ProcessStreamSinkAbortReason::TransportFailure => {
                ProcessStreamSinkState::SourceUnavailable
            }
        }
    }

    /// Validates one abort against the live session and snapshots everything
    /// the terminal needs, so the owner stage below can run without holding
    /// the session lock across its await (AUD2.7). The snapshot is exactly
    /// the admitted prefix: bytes, digest, sequence and offset under one lock
    /// hold. A concurrent append between this snapshot and the record faults
    /// the abort with `TerminalIdentityConflict` instead of minting a
    /// terminal over bytes it did not observe — the same refusal a racing
    /// append already earns against the live counters.
    fn abort_snapshot(
        state: &SinkState,
        session: &ProcessStreamSinkSession,
        request: &ProcessStreamSinkAbortRequest,
    ) -> Result<AbortSnapshot, ProcessStreamSinkError> {
        let existing = Self::check_session(state, session)?;
        let identity = request.command_identity()?;
        if let Some(terminal) = &state.terminal {
            return if state.terminal_command.as_ref() == Some(&identity) {
                Ok(AbortSnapshot::Replayed(terminal.clone()))
            } else {
                Err(ProcessStreamSinkError::TerminalIdentityConflict)
            };
        }
        // An abort never competes with a reserved publish. While a reservation exists
        // the durable effect of its command may already have happened, so no
        // non-publishing terminal may be minted for the same terminal id.
        if state.finalization.is_some() {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        existing.validate_abort(request)?;
        Self::check_sequence_offset(
            state,
            request.expected_final_sequence(),
            request.expected_final_offset(),
        )?;
        Self::check_observed(state, request.observed_sha256(), request.observed_bytes())?;
        // An abort never publishes, so it has nowhere to bind a
        // transformation receipt: the same refusal as `plan_finalize`, with
        // the same truthful cause (W7).
        refuse_transformation(request.transformation())?;
        // Only a cancellation, caller-shutdown or transport-failure abort
        // retains the admitted prefix, and only when the prefix is nonempty.
        // A policy-prohibited or failed-redaction abort stages nothing, so a
        // prohibited session can never stage raw bytes (W8); an empty prefix
        // retains nothing because there is no prefix to keep.
        let reason = request.reason();
        let retain = matches!(
            reason,
            ProcessStreamSinkAbortReason::TransportFailure
                | ProcessStreamSinkAbortReason::Cancellation
                | ProcessStreamSinkAbortReason::CallerShutdown
        ) && !state.staged.is_empty();
        Ok(AbortSnapshot::Prepared(AbortPrepared {
            session: existing.clone(),
            request: request.clone(),
            identity,
            reason,
            staged: state.staged.as_bytes().to_vec(),
            next_sequence: state.next_sequence,
            next_offset: state.next_offset,
            admitted_sha256: state.admitted_sha256(),
            retain,
        }))
    }

    /// Mints the abort terminal, retaining the admitted prefix as a real
    /// durable object when the snapshot asked for it.
    ///
    /// Retention stages the exact snapshotted bytes through the owner under
    /// the bound root lease and reads them back before minting anything, so
    /// the locator the terminal keeps names an object proven to exist — never
    /// a memory buffer relabelled as durable. Staging is content-addressed,
    /// so a same-identity abort replay resolves the same object, never a
    /// second one.
    async fn abort_async(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let snapshot = Self::abort_snapshot(&self.lock(), &session, &request)?;
        let prepared = match snapshot {
            AbortSnapshot::Replayed(terminal) => return Ok(terminal),
            AbortSnapshot::Prepared(prepared) => prepared,
        };
        let retained = if prepared.retain {
            Some(self.retain_aborted_prefix(&prepared.staged).await?)
        } else {
            None
        };
        let mut state = self.lock();
        let (persistence, source, terminal_state, publication) = match retained {
            Some(ready) => {
                let byte_length = ready.plaintext_length();
                let sha256 = ready.plaintext_sha256().to_owned();
                let locator = format!("{BLOB_SOURCE_LOCATOR_SCHEME}:{}", ready.locator().hash);
                let receipt_ref = ready.receipt().identity.receipt_id.to_string();
                let source = DurableProcessStreamSource::exact_transport(
                    DurableStreamLocatorKind::Blob,
                    locator.clone(),
                    receipt_ref.clone(),
                    sha256.clone(),
                    byte_length,
                )?;
                let publication =
                    BlobStreamPublication::Partial(Box::new(BlobStreamPartialPrefix {
                        locator,
                        ready_receipt_ref: receipt_ref,
                        byte_length,
                        sha256,
                    }));
                (
                    StreamPersistenceStatus::PartialSource,
                    Some(source),
                    ProcessStreamSinkState::PartialSource,
                    publication,
                )
            }
            None => {
                let reason = match prepared.reason {
                    ProcessStreamSinkAbortReason::PolicyProhibition => {
                        BlobStreamUnavailableReason::PolicyProhibited
                    }
                    ProcessStreamSinkAbortReason::RedactionFailure => {
                        BlobStreamUnavailableReason::RedactionFailed
                    }
                    ProcessStreamSinkAbortReason::TransportFailure
                    | ProcessStreamSinkAbortReason::Cancellation
                    | ProcessStreamSinkAbortReason::CallerShutdown => {
                        unavailable_reason(prepared.request.gaps())
                    }
                };
                (
                    StreamPersistenceStatus::SourceUnavailable,
                    None,
                    Self::abort_state(prepared.reason),
                    BlobStreamPublication::Unavailable { reason },
                )
            }
        };
        let evidence = ProcessStreamEvidence::new_raw(
            prepared.session.binding().clone(),
            prepared.session.stream(),
            prepared.session.policy().clone(),
            prepared.request.transport(),
            persistence,
            prepared.request.observed_sha256().to_owned(),
            prepared.request.observed_bytes(),
            prepared.request.preview().clone(),
            source,
            prepared.request.gaps().to_vec(),
        )?;
        let terminal = ProcessStreamSinkTerminal::from_abort(
            prepared.session,
            prepared.request,
            terminal_state,
            prepared.next_sequence,
            prepared.next_offset,
            prepared.admitted_sha256,
            evidence,
        )?;
        Self::record_locked(&mut state, prepared.identity, publication, terminal)
    }

    /// Stages one aborted prefix through the owner and proves it reads back.
    async fn retain_aborted_prefix(
        &self,
        staged: &[u8],
    ) -> Result<BlobReadyReceipt, ProcessStreamSinkError> {
        let request = self.stage_request(staged)?;
        let ready = self
            .store
            .stage(request)
            .await
            .map_err(|error| map_blob_error(&error))?;
        self.verify_readback(&ready).await?;
        Ok(ready)
    }

    /// Builds the one exact stage request for these bytes under the bound root
    /// lease, policy and stage operation identity. Deriving it twice from the
    /// same bytes reproduces the same canonical request, so an exact replay is
    /// an owner-side resolution of one operation, not a new command.
    fn stage_request(&self, staged: &[u8]) -> Result<BlobStageRequest, ProcessStreamSinkError> {
        let template = self.binding.residency();
        let digest = BlobHash::new(blake3::hash(staged).to_hex().to_string())
            .map_err(|error| map_blob_error(&error))?;
        let residency = ObjectResidencyKey {
            scope_domain_id: template.scope_domain_id.clone(),
            access_domain_id: template.access_domain_id.clone(),
            confidentiality_domain_id: template.confidentiality_domain_id.clone(),
            encryption_key_domain_id: template.encryption_key_domain_id.clone(),
            retention_domain_id: template.retention_domain_id.clone(),
            erasure_domain_id: template.erasure_domain_id.clone(),
            content_digest: VersionedContentDigest {
                algorithm: template.content_digest.algorithm.clone(),
                version: template.content_digest.version,
                digest,
            },
        };
        let request = BlobStageRequest {
            context: self.binding.stage_context().clone(),
            root_lease: self.binding.root_lease().clone(),
            bytes: staged.to_vec(),
            policy: self.binding.policy().clone(),
            residency,
        };
        request.validate().map_err(|error| map_blob_error(&error))?;
        Ok(request)
    }

    /// Hands the exact bytes to the one owner for the first time under this
    /// reservation, after marking the outcome as possibly having taken effect.
    /// The mark happens before the await so a dropped future stays unknown.
    async fn stage_once(
        &self,
        identity: &ProcessStreamSinkTerminalCommandIdentity,
        incarnation: u64,
        staged: &[u8],
    ) -> Result<BlobReadyReceipt, ProcessStreamSinkError> {
        self.mark_stage_handoff(identity, incarnation)?;
        let request = self.stage_request(staged)?;
        match self.store.stage(request).await {
            Ok(ready) => self.retain_ready(identity, incarnation, staged, ready),
            Err(error) => {
                // Only a provably pre-effect refusal may clear the handoff
                // mark. Every other outcome keeps the possible effect, so the
                // reservation stays reconcilable instead of becoming a
                // permanently reserved command.
                if !possible_blob_effect(&error) {
                    self.clear_stage_handoff(identity, incarnation);
                }
                Err(map_blob_error(&error))
            }
        }
    }

    /// Records that the exact stage request may or may not have taken effect.
    fn mark_stage_handoff(
        &self,
        identity: &ProcessStreamSinkTerminalCommandIdentity,
        incarnation: u64,
    ) -> Result<(), ProcessStreamSinkError> {
        let mut state = self.lock();
        let Some(reservation) = state.finalization.as_mut() else {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        };
        if reservation.identity != *identity || reservation.incarnation != incarnation {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        if !matches!(reservation.phase, FinalizePhase::Reserved) {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        reservation.phase = FinalizePhase::StageOutcomeUnknown;
        Ok(())
    }

    /// Clears a handoff mark that provably never reached a durable effect,
    /// returning the reservation to its resumable reserved phase.
    fn clear_stage_handoff(
        &self,
        identity: &ProcessStreamSinkTerminalCommandIdentity,
        incarnation: u64,
    ) {
        let mut state = self.lock();
        if let Some(reservation) = state.finalization.as_mut()
            && reservation.identity == *identity
            && reservation.incarnation == incarnation
            && matches!(reservation.phase, FinalizePhase::StageOutcomeUnknown)
        {
            reservation.phase = FinalizePhase::Reserved;
        }
    }

    /// Retains the real ready receipt and its exact byte commitment
    /// immediately after `stage` returned, before any further await. The
    /// staged plaintext is then dropped: the receipt carries the same
    /// commitment, so a resumed readback needs no second plaintext copy.
    fn retain_ready(
        &self,
        identity: &ProcessStreamSinkTerminalCommandIdentity,
        incarnation: u64,
        staged: &[u8],
        ready: BlobReadyReceipt,
    ) -> Result<BlobReadyReceipt, ProcessStreamSinkError> {
        ready.validate().map_err(|error| map_blob_error(&error))?;
        let staged_length =
            u64::try_from(staged.len()).map_err(|_| ProcessStreamSinkError::EvidenceInvariant {
                reason: "staged length does not fit the session counters".to_owned(),
            })?;
        if ready.plaintext_sha256() != sha256_hex(staged)
            || ready.plaintext_length() != staged_length
        {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "blob ready receipt does not describe the staged bytes".to_owned(),
            });
        }
        let mut state = self.lock();
        let Some(reservation) = state.finalization.as_mut() else {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        };
        if reservation.identity != *identity || reservation.incarnation != incarnation {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        if matches!(reservation.phase, FinalizePhase::Reserved) {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        reservation.phase = FinalizePhase::ReadbackPending {
            ready: Box::new(ready.clone()),
        };
        state.staged.clear();
        Ok(ready)
    }

    /// Reads the retained object back and proves it is the very object the
    /// ready receipt commits to. A zero-byte complete source verifies as a
    /// real immutable object with the same exact rules.
    async fn verify_readback(
        &self,
        ready: &BlobReadyReceipt,
    ) -> Result<(), ProcessStreamSinkError> {
        let chunk = self
            .store
            .read(BlobReadRequest {
                context: self.binding.read_context().clone(),
                root_lease: self.binding.root_lease().clone(),
                locator: ready.locator().clone(),
                expected_metadata_sha256: ready.metadata_sha256().to_owned(),
                expected_ready_receipt_id: ready.receipt().identity.receipt_id.to_string(),
                max_bytes: ready.plaintext_length().max(1),
            })
            .await
            .map_err(|error| map_blob_error(&error))?;
        chunk.validate().map_err(|error| map_blob_error(&error))?;
        let readback_length = u64::try_from(chunk.bytes().len()).map_err(|_| {
            ProcessStreamSinkError::EvidenceInvariant {
                reason: "readback length does not fit the session counters".to_owned(),
            }
        })?;
        // The retained receipt was already proven against the admitted bytes,
        // so verifying the readback against the same commitment closes the
        // chain without retaining another plaintext copy.
        if readback_length != ready.plaintext_length()
            || sha256_hex(chunk.bytes()) != ready.plaintext_sha256()
        {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "blob readback does not match the retained ready receipt".to_owned(),
            });
        }
        Ok(())
    }

    fn complete_source(
        session: &ProcessStreamSinkSession,
        request: &ProcessStreamSinkFinalizeRequest,
        admitted_sha256: &str,
        ready: &BlobReadyReceipt,
    ) -> Result<ProcessStreamEvidence, ProcessStreamSinkError> {
        let receipt_ref = ready.receipt().identity.receipt_id.to_string();
        let source = DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            format!("{BLOB_SOURCE_LOCATOR_SCHEME}:{}", ready.locator().hash),
            receipt_ref,
            admitted_sha256.to_owned(),
            ready.plaintext_length(),
        )?;
        ProcessStreamEvidence::new_raw(
            session.binding().clone(),
            session.stream(),
            session.policy().clone(),
            request.transport(),
            StreamPersistenceStatus::CompleteSource,
            request.observed_sha256().to_owned(),
            request.observed_bytes(),
            request.preview().clone(),
            Some(source),
            request.gaps().to_vec(),
        )
        .map_err(ProcessStreamSinkError::from)
    }

    /// The exact publication outcome proven by a real owner ready receipt.
    ///
    /// A zero-byte complete source still names the immutable object the owner
    /// returned: the blob locator hash is the empty-content digest, so the
    /// locator is present and resolvable. It is never reported as "no source".
    fn publication_of(
        admitted_sha256: &str,
        ready: &BlobReadyReceipt,
        measures: &BlobStreamEvidenceMeasures,
    ) -> Result<BlobStreamPublication, ProcessStreamSinkError> {
        if ready.plaintext_sha256() != admitted_sha256 {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "owner receipt does not describe the admitted transport bytes".to_owned(),
            });
        }
        Ok(BlobStreamPublication::Complete(Box::new(
            BlobStreamCompleteSource {
                locator: format!("{BLOB_SOURCE_LOCATOR_SCHEME}:{}", ready.locator().hash),
                ready_receipt_ref: ready.receipt().identity.receipt_id.to_string(),
                byte_length: ready.plaintext_length(),
                sha256: ready.plaintext_sha256().to_owned(),
                measures: measures.clone(),
            },
        )))
    }

    fn plan_finalize(
        &self,
        session: &ProcessStreamSinkSession,
        request: &ProcessStreamSinkFinalizeRequest,
    ) -> Result<FinalizePlan, ProcessStreamSinkError> {
        let mut state = self.lock();
        let existing = Self::check_session(&state, session)?;
        let identity = request.command_identity()?;
        if let Some(terminal) = &state.terminal {
            return if state.terminal_command.as_ref() == Some(&identity) {
                Ok(FinalizePlan::Recorded(Box::new(terminal.clone())))
            } else {
                Err(ProcessStreamSinkError::TerminalIdentityConflict)
            };
        }
        existing.validate_finalize(request)?;
        Self::check_sequence_offset(
            &state,
            request.expected_final_sequence(),
            request.expected_final_offset(),
        )?;
        Self::check_observed(&state, request.observed_sha256(), request.observed_bytes())?;
        let publishes =
            request.gaps().is_empty() && request.transport() == StreamTransportStatus::Complete;
        // This adapter stages EXACT admitted transport bytes and never transformed
        // output, so a finalize that declares a transformation is refused for
        // BOTH outcomes — not only the publishing one — and it is refused BEFORE
        // any measure is built. See [`refuse_transformation`] for the two W7
        // defects this closes; `measures_for` below is the single place that
        // enforcement happens, for finalize and abort alike.
        //
        // The three measures of THIS terminal, computed once here from the
        // digests accumulated while its bytes arrived and from this exact
        // command's preview. Every ticket below carries this one value; no site
        // re-derives it, so a resumed publish records the same measures its
        // first planning pass computed.
        let measures = state.measures_for(request.preview(), request.transformation())?;
        if publishes {
            // A reservation already holds the exact admitted byte commitment
            // it was created from, and a resumed publish has moved the staged
            // plaintext out of the session. Re-deriving the transport prefix
            // here would compare against an empty buffer and reject a
            // legitimate resume, so the check runs only for a first publish.
            if state.finalization.is_none() {
                Self::check_preview(&state, request.preview())?;
            }
        }
        let admitted_sha256 = state.admitted_sha256();

        // An existing reservation for this exact command is resumed, never
        // re-reserved: the same terminal id can never drive a second stage.
        // A reservation for a different command is a conflict, not a race.
        if state.finalization.is_some() {
            // The retained fields are copied into owned locals so the shared
            // borrow of the reservation ends before the staged plaintext is
            // *moved* out of the session; a resumed publish therefore never
            // clones the whole stream.
            let reservation = state
                .finalization
                .as_ref()
                .ok_or(ProcessStreamSinkError::TerminalIdentityConflict)?;
            if reservation.identity != identity {
                return Err(ProcessStreamSinkError::TerminalIdentityConflict);
            }
            let resumed_identity = reservation.identity.clone();
            let resumed_incarnation = reservation.incarnation;
            let resumed_next_sequence = reservation.next_sequence;
            let resumed_next_offset = reservation.next_offset;
            let resumed_admitted_sha256 = reservation.admitted_sha256.clone();
            let resumed_ready = reservation.ready().cloned();
            let step = match resumed_ready {
                Some(ready) => PublishStep::Readback {
                    ready: Box::new(ready),
                },
                None => PublishStep::Stage {
                    staged: state.staged.as_bytes().to_vec(),
                },
            };
            return Ok(FinalizePlan::Publish(Box::new(PublishTicket {
                session: existing,
                request: request.clone(),
                identity: resumed_identity,
                incarnation: resumed_incarnation,
                next_sequence: resumed_next_sequence,
                next_offset: resumed_next_offset,
                admitted_sha256: resumed_admitted_sha256,
                measures,
                step,
            })));
        }

        Ok(if publishes {
            // One reservation per session: bound to this session, this exact
            // command digest and the one bound blob stage operation.
            self.reserve_publish(
                &mut state,
                existing,
                request,
                identity,
                admitted_sha256,
                measures,
            )
        } else {
            Self::withheld_plan(&state, existing, request, identity, admitted_sha256)
        })
    }

    /// Builds the never-published terminal plan for a non-publishing
    /// finalize.
    ///
    /// No durable publication except for the complete-source path: a gapped,
    /// policy-prohibited, or failed-redaction finalize must not stage raw
    /// bytes as a second object. This step cannot fail, so it mints no error
    /// and reserves nothing.
    fn withheld_plan(
        state: &SinkState,
        session: ProcessStreamSinkSession,
        request: &ProcessStreamSinkFinalizeRequest,
        identity: ProcessStreamSinkTerminalCommandIdentity,
        admitted_sha256: String,
    ) -> FinalizePlan {
        let (withheld, reason) = if request
            .gaps()
            .contains(&StreamEvidenceGap::PolicyProhibited)
        {
            (
                ProcessStreamSinkState::PolicyProhibited,
                BlobStreamUnavailableReason::PolicyProhibited,
            )
        } else if request.gaps().contains(&StreamEvidenceGap::RedactionFailed) {
            (
                ProcessStreamSinkState::RedactionFailed,
                BlobStreamUnavailableReason::RedactionFailed,
            )
        } else {
            (
                ProcessStreamSinkState::SourceUnavailable,
                unavailable_reason(request.gaps()),
            )
        };
        FinalizePlan::Withheld(Box::new(WithheldTicket {
            session,
            request: request.clone(),
            identity,
            next_sequence: state.next_sequence,
            next_offset: state.next_offset,
            admitted_sha256,
            state: withheld,
            publication: BlobStreamPublication::Unavailable { reason },
        }))
    }

    /// Creates the one reservation of this session and its publish plan.
    ///
    /// One reservation per session, bound to this session, this exact command
    /// digest and the one bound blob stage operation. The phase starts
    /// `Reserved`: nothing has been handed to the blob owner yet.
    fn reserve_publish(
        &self,
        state: &mut SinkState,
        session: ProcessStreamSinkSession,
        request: &ProcessStreamSinkFinalizeRequest,
        identity: ProcessStreamSinkTerminalCommandIdentity,
        admitted_sha256: String,
        measures: BlobStreamEvidenceMeasures,
    ) -> FinalizePlan {
        let incarnation = state.finalization_incarnation.saturating_add(1);
        state.finalization_incarnation = incarnation;
        state.finalization = Some(FinalizeReservation {
            identity: identity.clone(),
            incarnation,
            request: request.clone(),
            next_sequence: state.next_sequence,
            next_offset: state.next_offset,
            admitted_sha256: admitted_sha256.clone(),
            stage_operation_id: self
                .binding
                .stage_context()
                .operation
                .operation_id
                .as_str()
                .to_owned(),
            stage_idempotency_key: self
                .binding
                .stage_context()
                .operation
                .idempotency_key
                .clone(),
            phase: FinalizePhase::Reserved,
        });
        FinalizePlan::Publish(Box::new(PublishTicket {
            session,
            request: request.clone(),
            identity,
            incarnation,
            next_sequence: state.next_sequence,
            next_offset: state.next_offset,
            admitted_sha256,
            // The measures of this terminal ride the ticket, so the
            // publication recorded after the readback describes the same
            // digests this planning pass measured.
            measures,
            // The staged plaintext is handed to the ticket as the one live
            // full-plaintext buffer. It is CLONED, not moved: the reservation
            // below retains only the admitted digest, never the bytes, so a
            // publish future dropped before `stage` completes would otherwise
            // destroy the only durable copy and leave a reservation that can
            // never be satisfied. The session keeps the bytes until
            // `record_locked` drops them, so a dropped future stays
            // recoverable and a retry re-derives the same terminal.
            step: PublishStep::Stage {
                staged: state.staged.as_bytes().to_vec(),
            },
        }))
    }

    /// Records the terminal exactly once under the command identity, drops
    /// the staged plaintext, records the exact publication outcome, and
    /// reconciles a same-identity replay to the existing terminal instead of
    /// a second object.
    fn record_locked(
        state: &mut SinkState,
        identity: ProcessStreamSinkTerminalCommandIdentity,
        publication: BlobStreamPublication,
        terminal: ProcessStreamSinkTerminal,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        if let Some(existing) = &state.terminal {
            return if state.terminal_command.as_ref() == Some(&identity) {
                Ok(existing.clone())
            } else {
                Err(ProcessStreamSinkError::TerminalIdentityConflict)
            };
        }
        if state
            .finalization
            .as_ref()
            .is_some_and(|reservation| reservation.identity != identity)
        {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        state.terminal_command = Some(identity);
        state.finalization = None;
        // The whole persistence-queue charge is released with the terminal,
        // because this is the last moment anything is retained: the staged
        // plaintext, the queue records and the queued byte count all go at
        // once. Releasing it here is also what bounds the charge's LIFETIME —
        // an adapter whose session never terminates keeps its charge, and that
        // is precisely the pressure the ceiling above is there to refuse.
        state.persistence_queue.queued_chunks = 0;
        state.persistence_queue.queued_bytes = 0;
        state.staged.clear();
        state.publication = Some(publication);
        state.terminal = Some(terminal.clone());
        Ok(terminal)
    }

    /// Publishes the reserved complete source: at most one stage under the
    /// original identity, then the readback, then the `CompleteSource`
    /// terminal. A failure leaves the phase advanced, never a bare flag.
    async fn publish_reserved(
        &self,
        ticket: PublishTicket,
        _hold: FinalizeHold<'_, C>,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let ready = match ticket.step {
            PublishStep::Readback { ready } => *ready,
            PublishStep::Stage { staged } => {
                // `staged` is the one live full-plaintext buffer. It is handed
                // to the owner and dropped when the call returns, so no
                // second simultaneous copy of the stream exists at any point.
                let ready = self
                    .stage_once(&ticket.identity, ticket.incarnation, &staged)
                    .await?;
                drop(staged);
                ready
            }
        };
        self.verify_readback(&ready).await?;
        let publication = Self::publication_of(&ticket.admitted_sha256, &ready, &ticket.measures)?;
        let evidence = Self::complete_source(
            &ticket.session,
            &ticket.request,
            &ticket.admitted_sha256,
            &ready,
        )?;
        let terminal = ProcessStreamSinkTerminal::from_finalize(
            ticket.session,
            ticket.request,
            ProcessStreamSinkState::CompleteSource,
            ticket.next_sequence,
            ticket.next_offset,
            ticket.admitted_sha256,
            evidence,
        )?;
        Self::record_locked(&mut self.lock(), ticket.identity, publication, terminal)
    }

    /// Mints the withheld (never-published) terminal for a gapped,
    /// policy-prohibited or failed-redaction finalize.
    ///
    /// The recorded outcome is exactly `Unavailable { reason }`: no durable
    /// source exists, and no raw byte was staged to manufacture coverage.
    fn withhold_reserved(
        &self,
        ticket: WithheldTicket,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let evidence = ProcessStreamEvidence::new_raw(
            ticket.session.binding().clone(),
            ticket.session.stream(),
            ticket.session.policy().clone(),
            ticket.request.transport(),
            StreamPersistenceStatus::SourceUnavailable,
            ticket.request.observed_sha256().to_owned(),
            ticket.request.observed_bytes(),
            ticket.request.preview().clone(),
            None,
            ticket.request.gaps().to_vec(),
        )?;
        let terminal = ProcessStreamSinkTerminal::from_finalize(
            ticket.session,
            ticket.request,
            ticket.state,
            ticket.next_sequence,
            ticket.next_offset,
            ticket.admitted_sha256,
            evidence,
        )?;
        Self::record_locked(
            &mut self.lock(),
            ticket.identity,
            ticket.publication,
            terminal,
        )
    }

    async fn finalize_async(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let plan = self.plan_finalize(&session, &request)?;
        match plan {
            FinalizePlan::Recorded(terminal) => Ok(*terminal),
            FinalizePlan::Withheld(ticket) => self.withhold_reserved(*ticket),
            FinalizePlan::Publish(ticket) => {
                let hold = FinalizeHold {
                    sink: self,
                    identity: ticket.identity.clone(),
                    incarnation: ticket.incarnation,
                };
                self.publish_reserved(*ticket, hold).await
            }
        }
    }

    /// Reconciles an uncertain provider effect under the original stage
    /// identity. Existing publication evidence is resolved first: a retained
    /// ready receipt resumes the readback without a second stage, and an
    /// unsettled handoff re-issues the exact original stage request, which the
    /// single owner resolves under its own idempotency identity. A cache miss
    /// is never treated as proof of non-publication.
    async fn reconcile_async(
        &self,
        session: ProcessStreamSinkSession,
        outcome: ProcessStreamSinkUnknownOutcome,
    ) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
        let request = {
            let state = self.lock();
            let existing = Self::check_session(&state, &session)?;
            outcome.validate_against_session(&existing)?;
            if let Some(terminal) = &state.terminal {
                return Ok(ProcessStreamSinkReadback::Terminal {
                    terminal: terminal.clone(),
                });
            }
            let Some(reservation) = state.finalization.as_ref() else {
                return Err(ProcessStreamSinkError::ProviderUnavailable);
            };
            if !reservation.effect_possible() {
                // The command never became uncertain for this session.
                return Err(ProcessStreamSinkError::ProviderUnavailable);
            }
            if Self::reservation_uncertainty(&existing, reservation)? != outcome {
                return Err(ProcessStreamSinkError::ProviderUnavailable);
            }
            reservation.request.clone()
        };
        // The retained command is re-driven, not replaced: the reservation it
        // owns decides whether only the readback or the exact stage follows.
        match self.finalize_async(session.clone(), request).await {
            Ok(terminal) => Ok(ProcessStreamSinkReadback::Terminal { terminal }),
            Err(_) => self.unsettled_readback(&session),
        }
    }

    /// Reports the retained phase of an unresolved effect instead of
    /// inventing a terminal. A `Reserved` phase released its provably absent
    /// handoff, so the command is simply not settled and stays retryable.
    fn unsettled_readback(
        &self,
        session: &ProcessStreamSinkSession,
    ) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
        let state = self.lock();
        let existing = Self::check_session(&state, session)?;
        if let Some(terminal) = &state.terminal {
            return Ok(ProcessStreamSinkReadback::Terminal {
                terminal: terminal.clone(),
            });
        }
        match state.finalization.as_ref() {
            Some(reservation) if reservation.effect_possible() => {
                Ok(ProcessStreamSinkReadback::UnknownOutcome {
                    outcome: Self::reservation_uncertainty(&existing, reservation)?,
                })
            }
            _ => Err(ProcessStreamSinkError::ProviderUnavailable),
        }
    }
}

/// Cancellation-safe local owner of one reserved finalize command.
///
/// `Drop` releases only this incarnation of a reservation that was never
/// handed to the blob owner. A reservation whose external effect became
/// possible keeps its phase, so a dropped future stays reconcilable instead of
/// silently reopening the session. There is no RPC in `Drop`, no detached
/// task, and no reset to `Open`.
struct FinalizeHold<'a, C: BlobStoreClient> {
    sink: &'a BlobStoreStreamSink<C>,
    identity: ProcessStreamSinkTerminalCommandIdentity,
    incarnation: u64,
}

impl<C: BlobStoreClient> Drop for FinalizeHold<'_, C> {
    fn drop(&mut self) {
        let mut state = self.sink.lock();
        let releasable = state.finalization.as_ref().is_some_and(|reservation| {
            reservation.identity == self.identity
                && reservation.incarnation == self.incarnation
                && matches!(reservation.phase, FinalizePhase::Reserved)
        });
        if releasable {
            state.finalization = None;
            state.finalization_incarnation = state.finalization_incarnation.saturating_add(1);
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Refuses a terminal command that declares a policy transformation (W7).
///
/// This adapter stages EXACT admitted transport bytes and holds no transformed
/// bytes, so it can never observe a transformation's output and can never bind
/// one to a durable object. Two defects are closed by this one refusal, applied
/// by BOTH terminal commands before any measure is built:
///
/// * **Unverified output, unverified input.** The declared transformation's
///   `input_sha256`/`input_byte_length` were previously read NOWHERE in this
///   file, so a caller could present a receipt claiming an arbitrary input
///   while the adapter copied only that receipt's unverified OUTPUT digest into
///   the admissible-source measure. Two different transformations that happen to
///   emit the same output for the same input produced the SAME recorded
///   `PolicyTransformed` measure, so a consumer could not tell which one ran.
/// * **Untruthful failure.** A gapped finalize or an abort carrying a
///   transformation fell through to terminal construction and failed with
///   `TerminalIdentityConflict`, naming an identity collision for what is
///   actually an unsupported transformation.
///
/// Refusing BEFORE any measure is derived also fixes the ordering the owner's
/// audit keeps finding: a result must never be counted before the
/// transformation that produced it is known, and here no admissible-source
/// identity is ever derived from a transformation at all.
///
/// Nothing is invented: no enum variant, no policy identifier, no
/// transformation type. `ProcessStreamTransformationBinding` already carries the
/// input/output receipt, policy reference and redaction reference; this adapter
/// simply cannot honour one and says so instead of half-recording it. Closing
/// the remaining half of W7 — actually STAGING transformed bytes with their
/// exact receipt — needs the transformer producer contract that no caller
/// supplies; that is the owner reported in the accompanying report, not a field
/// invented here.
fn refuse_transformation(
    request_transformation: Option<&ProcessStreamTransformationBinding>,
) -> Result<(), ProcessStreamSinkError> {
    if request_transformation.is_some() {
        return Err(ProcessStreamSinkError::EvidenceInvariant {
            reason: "adapter stages exact transport bytes only".to_owned(),
        });
    }
    Ok(())
}

/// The exact provider-side reason a durable source is unavailable.
///
/// The declared gaps are the only input, so this can never invent a cause the
/// caller did not declare.
///
/// * `PersistenceUnknownOutcome` / `PersistenceFailed` are the provider-side
///   causes and map straight through.
/// * `PersistenceBackpressure` means bytes were shed, so the received bytes
///   are a shorter prefix of the process stream and never a complete source:
///   the reason is the exact coverage gap, not a provider verdict.
/// * Anything else (cancellation, read failure, capture unavailable, or no
///   persistence gap at all) is a provider that produced no exact result.
fn unavailable_reason(gaps: &[StreamEvidenceGap]) -> BlobStreamUnavailableReason {
    if gaps.contains(&StreamEvidenceGap::PersistenceUnknownOutcome) {
        BlobStreamUnavailableReason::PersistenceUnknownOutcome
    } else if gaps.contains(&StreamEvidenceGap::PersistenceFailed) {
        BlobStreamUnavailableReason::PersistenceFailed
    } else if gaps.contains(&StreamEvidenceGap::PersistenceBackpressure) {
        BlobStreamUnavailableReason::CoverageGap
    } else {
        BlobStreamUnavailableReason::PersistenceUnavailable
    }
}

/// Whether a blob failure leaves an effect that must stay unresolved until
/// owner evidence settles it.
///
/// A stale/revoked root lease, a root owned elsewhere, contract rejection and
/// an unavailable key are all decided before any durable transition, so they
/// cannot have published anything and the reservation may be retried. Every
/// other outcome — unknown publish outcome, capacity exhaustion at or after a
/// journal write, transport loss, integrity failure, plan gap — keeps its
/// possible effect and is recovered only through `reconcile`.
fn possible_blob_effect(error: &BlobError) -> bool {
    !matches!(
        error,
        BlobError::InvalidField { .. }
            | BlobError::InvalidContract(_)
            | BlobError::AuthorityRequired(_)
            | BlobError::StaleFence
            | BlobError::OwnerConflict
            | BlobError::NotFound
            | BlobError::KeyUnavailable { .. }
    )
}

/// Maps a blob-layer failure onto the sink contract.
///
/// The mapping keeps the two vocabulary axes the contract already separates.
///
/// * Integrity and metadata/payload-coherence failures are evidence failures
///   (`EvidenceInvariant`); they are never retried and never a `CompleteSource`.
/// * Every other provider failure (transport, capacity, key, fence, unknown
///   outcome, incomplete publish) is the contract's typed provider-unavailable
///   signal. It is deliberately *not* widened into "safe to retry": the
///   recoverable distinction is carried by the retained reservation phase,
///   which `readback` exposes as `UnknownOutcome` for a possible effect and
///   as a resumable `Finalizing` session view for a provably absent one.
///
/// Both forms refuse a `COMPLETE_SOURCE` terminal by construction: they
/// return `Err` before any terminal exists.
fn map_blob_error(error: &BlobError) -> ProcessStreamSinkError {
    match error {
        BlobError::IntegrityMismatch | BlobError::MetadataPayloadMismatch => {
            ProcessStreamSinkError::EvidenceInvariant {
                reason: error.to_string(),
            }
        }
        _ => ProcessStreamSinkError::ProviderUnavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::StagedPrefix;

    /// Pins the whole push-only seam API so a later durable swap is caught by
    /// name.
    #[test]
    fn staged_prefix_push_and_len() {
        let mut staged = StagedPrefix::new();
        assert!(staged.is_empty());
        assert_eq!(staged.len(), 0);
        assert!(staged.as_bytes().is_empty());

        staged.extend_from_slice(b"ab");
        staged.extend_from_slice(b"c");

        assert!(!staged.is_empty());
        assert_eq!(staged.len(), 3);
        assert_eq!(staged.as_bytes(), b"abc");
    }

    /// Pins that clear drops every staged byte and leaves the seam reusable.
    #[test]
    fn staged_prefix_clear_drops_bytes() {
        let mut staged = StagedPrefix::new();
        staged.extend_from_slice(b"abc");
        assert_eq!(staged.as_bytes(), b"abc");

        staged.clear();

        assert!(staged.is_empty());
        assert_eq!(staged.len(), 0);
        assert!(staged.as_bytes().is_empty());
    }
}

impl<C: BlobStoreClient> ProcessStreamSinkClient for BlobStoreStreamSink<C> {
    fn open(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkSession> {
        let mut state = self.lock();
        let result = match state.session.as_ref() {
            Some(existing) if existing.open_request_sha256() == request.open_request_sha256() => {
                Ok(existing.clone())
            }
            Some(_) => Err(ProcessStreamSinkError::OpenDigestMismatch),
            None => ProcessStreamSinkSession::from_open_request(request).inspect(|session| {
                // The measures this session will be stamped with are bound
                // to the revisions its own open request declared.
                state.session = Some(session.clone());
                state.bind_measure_revisions(session);
            }),
        };
        Self::ready(result)
    }

    fn append(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkAppendDisposition> {
        let mut state = self.lock();
        let result = Self::check_session(&state, &session)
            .and_then(|existing| Self::append_locked(&mut state, &existing, &request));
        Self::ready(result)
    }

    fn finalize(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        Box::pin(async move { self.finalize_async(session, request).await })
    }

    /// Reconciles an uncertain provider effect for the one session this
    /// adapter serves.
    fn reconcile(
        &self,
        session: ProcessStreamSinkSession,
        outcome: ProcessStreamSinkUnknownOutcome,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        Box::pin(async move { self.reconcile_async(session, outcome).await })
    }

    fn abort(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        Box::pin(async move { self.abort_async(session, request).await })
    }

    fn readback(
        &self,
        session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let state = self.lock();
        let result = Self::check_session(&state, &session).and_then(|existing| {
            if let Some(terminal) = &state.terminal {
                return Ok(ProcessStreamSinkReadback::Terminal {
                    terminal: terminal.clone(),
                });
            }
            // A reservation whose external effect became possible is exposed
            // as the retained unknown outcome, never as an open session and
            // never as a success. A `Reserved` phase (nothing handed off) is
            // the only resumable nonterminal state.
            if let Some(reservation) = &state.finalization
                && reservation.effect_possible()
            {
                return Ok(ProcessStreamSinkReadback::UnknownOutcome {
                    outcome: Self::reservation_uncertainty(&existing, reservation)?,
                });
            }
            Self::session_view(&existing, &state)
        });
        Self::ready(result)
    }
}
