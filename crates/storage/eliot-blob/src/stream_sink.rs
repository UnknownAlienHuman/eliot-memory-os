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
//!   an explicit backpressure contract. Appends never touch storage.
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
//! Publication coverage (audit `5881613195`): a terminal is always the one
//! [`BlobStreamPublication`] the session actually proved. A gapped,
//! policy-prohibited or failed-redaction finalize never calls the owner at
//! all, so no raw byte is staged to preserve coverage. A policy-prohibited or
//! failed-redaction terminal is additionally forbidden from carrying any
//! inline preview by the shared terminal-evidence invariant, so a raw
//! pre-policy preview can never reach the durable record.
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
    DurableProcessStreamSource, DurableStreamLocatorKind, PROCESS_STREAM_SINK_SCHEMA_VERSION,
    ProcessStreamEvidence, ProcessStreamPrefixPreview, ProcessStreamSinkAbortReason,
    ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition,
    ProcessStreamSinkClient, ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest,
    ProcessStreamSinkFuture, ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback,
    ProcessStreamSinkSession, ProcessStreamSinkSessionView, ProcessStreamSinkState,
    ProcessStreamSinkTerminal, ProcessStreamSinkTerminalCommandIdentity,
    ProcessStreamSinkUnknownOutcome, StreamEvidenceGap, StreamPersistenceStatus,
    StreamPreviewRepresentation, StreamTransportStatus,
};
use eliot_receipts::EffectClass;
use sha2::{Digest, Sha256};

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
    Complete {
        /// Immutable locator of the published object.
        locator: String,
        /// Owner-issued receipt identity that resolves and verifies it.
        ready_receipt_ref: String,
        /// Exact durable byte length of the published object.
        byte_length: u64,
        /// SHA-256 over exactly the published bytes.
        sha256: String,
    },
    /// No durable expansion source exists for this terminal.
    ///
    /// `reason` names the exact blocking cause. A policy-prohibited or
    /// failed-redaction session always lands here and never stages raw bytes.
    ///
    /// This adapter does not mint a partial-durable-prefix value. A cancelled
    /// or read-failed session carries its admitted prefix and exact coverage
    /// in the terminal evidence itself (`StreamPersistenceStatus::
    /// SourceUnavailable` plus the admitted digest/count and the cancellation
    /// or read-failure gap), and this adapter stages nothing for it. Claiming
    /// `Partial` here would require an owner-issued receipt for the prefix,
    /// which only a publication path can produce; an unbacked prefix value
    /// would be exactly the "locator substitutes for owner evidence" defect
    /// the audit rejects. Retaining the admissible prefix as a real durable
    /// object is the #297 append-only staged-object path named above.
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

struct SinkState {
    session: Option<ProcessStreamSinkSession>,
    /// Admitted-but-not-yet-published plaintext. It is moved out with
    /// [`std::mem::take`] at publication time, so planning a publish never
    /// clones it and the session holds at most one full-plaintext buffer.
    staged: Vec<u8>,
    /// The exact publication outcome proven for this session, once a terminal
    /// recorded it. `None` means no terminal has landed yet.
    publication: Option<BlobStreamPublication>,
    digester: Sha256,
    admitted_chunks: Vec<AdmittedChunk>,
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

struct AdmittedChunk {
    sequence: u64,
    offset: u64,
    length: u64,
    sha256: String,
}

/// Bounded phase record for the one terminal command of one session.
///
/// Exactly one record exists per session, so it is bounded by the session's
/// own limits (the retained request's preview is already capped by
/// `max_preview_bytes` and its gaps by the protocol ceiling). The reservation
/// holds only counters, the admitted digest, and — once the owner returned
/// one — the real ready receipt. The staged plaintext is *moved* out of
/// [`SinkState::staged`] into the publish ticket and dropped as soon as the
/// owner's ready receipt carries the same byte commitment, so the record
/// never retains a second copy of the stream.
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

impl SinkState {
    fn new() -> Self {
        Self {
            session: None,
            staged: Vec::new(),
            publication: None,
            digester: Sha256::new(),
            admitted_chunks: Vec::new(),
            next_sequence: 0,
            next_offset: 0,
            terminal: None,
            terminal_command: None,
            finalization: None,
            finalization_incarnation: 0,
        }
    }

    fn admitted_sha256(&self) -> String {
        format!("{:x}", self.digester.clone().finalize())
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
        state.staged.get(start..end)
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
        if retained > state.staged.len() || preview.bytes() != &state.staged[..retained] {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "transport preview does not match admitted bytes".to_owned(),
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
        // This synchronous adapter has no append queue: each request is
        // admitted as one bounded chunk. The total byte and chunk ceilings
        // bound staged memory and reject overflow explicitly above. Since
        // each admitted sequence adds one record, max_chunks also bounds
        // this metadata without retaining another plaintext copy.
        state.admitted_chunks.push(AdmittedChunk {
            sequence: request.sequence(),
            offset: request.offset(),
            length: request.byte_length(),
            sha256: request.sha256().to_owned(),
        });
        state.digester.update(request.bytes());
        state.staged.extend_from_slice(request.bytes());
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

    fn abort_locked(
        state: &mut SinkState,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let existing = Self::check_session(state, &session)?;
        let identity = request.command_identity()?;
        if let Some(terminal) = &state.terminal {
            return if state.terminal_command.as_ref() == Some(&identity) {
                Ok(terminal.clone())
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
        existing.validate_abort(&request)?;
        Self::check_sequence_offset(
            state,
            request.expected_final_sequence(),
            request.expected_final_offset(),
        )?;
        Self::check_observed(state, request.observed_sha256(), request.observed_bytes())?;
        // Abort never publishes: no stage call for any reason, so a
        // policy-prohibited or failed-redaction session cannot stage raw
        // bytes. The staged plaintext is dropped with the terminal.
        let evidence = ProcessStreamEvidence::new_raw(
            existing.binding().clone(),
            existing.stream(),
            existing.policy().clone(),
            request.transport(),
            StreamPersistenceStatus::SourceUnavailable,
            request.observed_sha256().to_owned(),
            request.observed_bytes(),
            request.preview().clone(),
            None,
            request.gaps().to_vec(),
        )?;
        let reason = request.reason();
        let publication = BlobStreamPublication::Unavailable {
            reason: match reason {
                ProcessStreamSinkAbortReason::PolicyProhibition => {
                    BlobStreamUnavailableReason::PolicyProhibited
                }
                ProcessStreamSinkAbortReason::RedactionFailure => {
                    BlobStreamUnavailableReason::RedactionFailed
                }
                ProcessStreamSinkAbortReason::TransportFailure
                | ProcessStreamSinkAbortReason::Cancellation
                | ProcessStreamSinkAbortReason::CallerShutdown => {
                    unavailable_reason(request.gaps())
                }
            },
        };
        let terminal = ProcessStreamSinkTerminal::from_abort(
            session,
            request,
            Self::abort_state(reason),
            state.next_sequence,
            state.next_offset,
            state.admitted_sha256(),
            evidence,
        )?;
        Self::record_locked(state, identity, publication, terminal)
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
        state.staged = Vec::new();
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
    ) -> Result<BlobStreamPublication, ProcessStreamSinkError> {
        if ready.plaintext_sha256() != admitted_sha256 {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "owner receipt does not describe the admitted transport bytes".to_owned(),
            });
        }
        Ok(BlobStreamPublication::Complete {
            locator: format!("{BLOB_SOURCE_LOCATOR_SCHEME}:{}", ready.locator().hash),
            ready_receipt_ref: ready.receipt().identity.receipt_id.to_string(),
            byte_length: ready.plaintext_length(),
            sha256: ready.plaintext_sha256().to_owned(),
        })
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
        if publishes {
            if request.transformation().is_some() {
                return Err(ProcessStreamSinkError::EvidenceInvariant {
                    reason: "adapter stages exact transport bytes only".to_owned(),
                });
            }
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
                    staged: state.staged.clone(),
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
                step,
            })));
        }

        Ok(if publishes {
            // One reservation per session: bound to this session, this exact
            // command digest and the one bound blob stage operation.
            self.reserve_publish(&mut state, existing, request, identity, admitted_sha256)
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
            // The staged plaintext is handed to the ticket as the one live
            // full-plaintext buffer. It is CLONED, not moved: the reservation
            // below retains only the admitted digest, never the bytes, so a
            // publish future dropped before `stage` completes would otherwise
            // destroy the only durable copy and leave a reservation that can
            // never be satisfied. The session keeps the bytes until
            // `record_locked` drops them, so a dropped future stays
            // recoverable and a retry re-derives the same terminal.
            step: PublishStep::Stage {
                staged: state.staged.clone(),
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
        state.staged = Vec::new();
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
        let publication = Self::publication_of(&ticket.admitted_sha256, &ready)?;
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
                state.session = Some(session.clone());
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
        let mut state = self.lock();
        let result = Self::abort_locked(&mut state, session, request);
        Self::ready(result)
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
