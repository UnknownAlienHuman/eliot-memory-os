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
//! * `append` admits exact sequence/offset chunks into a bounded staging
//!   window and advances the incremental admissible-source identity (byte
//!   count plus the full SHA-256) as the bytes flow, so the durable source
//!   identity never needs a re-read of the window. Appends never touch
//!   storage and never await, so the pipe cannot be blocked here; a full
//!   window returns the one declared overflow disposition
//!   (`Backpressured`, carrying the session's own wait budget) and records
//!   the exact shed boundary, which finalize requires to be declared as
//!   `PERSISTENCE_BACKPRESSURE`.
//! * `finalize` decides from the declared gap set, through the contract's one
//!   disposition table, what may be staged and which terminal names it: a
//!   complete durable source, a shorter exact durable prefix with exact
//!   coverage, or an explicit unavailable/prohibited/failed terminal. A
//!   contradiction between the declared gaps and the declared byte coverage
//!   fails closed instead of minting a terminal.
//! * One durable stage call publishes the admitted prefix, verifies the ready
//!   receipt, reads the object back, and only then mints the terminal. A
//!   declared policy transformation binds the exact input/output receipt: the
//!   staged bytes must be the declared output and the inline preview must be
//!   a prefix of those transformed bytes in durable-source coordinates, so a
//!   raw pre-policy byte can never enter the record. Policy-prohibited or
//!   failed-redaction terminals never stage raw bytes at all.
//! * Staged plaintext is dropped when a terminal lands; only counts and the
//!   incremental admissible digest survive for readback/replay.
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
    ProcessStreamEvidence, ProcessStreamPersistenceDisposition, ProcessStreamPrefixPreview,
    ProcessStreamSinkAbortReason, ProcessStreamSinkAbortRequest, ProcessStreamSinkAppend,
    ProcessStreamSinkAppendDisposition, ProcessStreamSinkClient, ProcessStreamSinkError,
    ProcessStreamSinkFinalizeRequest, ProcessStreamSinkFuture, ProcessStreamSinkOpenRequest,
    ProcessStreamSinkReadback, ProcessStreamSinkSession, ProcessStreamSinkSessionView,
    ProcessStreamSinkState, ProcessStreamSinkTerminal, ProcessStreamSinkTerminalCommandIdentity,
    ProcessStreamSinkUnknownOutcome, ProcessStreamTransportPrefixIdentity, StreamEvidenceGap,
    StreamPersistenceStatus, StreamPreviewRepresentation, StreamTransportStatus,
};
use eliot_receipts::EffectClass;
use sha2::{Digest, Sha256};

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
    /// Bounded staging window of the admitted admissible bytes, capped by the
    /// session's `max_total_admitted_bytes` and `max_chunks` ceilings. It never
    /// holds a byte the caller did not admit under the bound policy.
    staged: Vec<u8>,
    /// Incremental admissible-source identity: the byte count and the full
    /// versioned digest over every admitted chunk, advanced as chunks flow.
    admitted: AdmittedAccount,
    /// The exact boundary at which the bounded staging window refused more
    /// bytes. `None` means this session never shed an append.
    overflow: Option<StagingOverflow>,
    admitted_chunks: Vec<AdmittedChunk>,
    next_sequence: u64,
    terminal: Option<ProcessStreamSinkTerminal>,
    terminal_command: Option<ProcessStreamSinkTerminalCommandIdentity>,
    /// The one bounded phase record of the one reserved terminal command.
    finalization: Option<FinalizeReservation>,
    /// Monotonic local incarnation counter. A stale finalizer that outlived
    /// its reservation can never release the successor's reservation.
    finalization_incarnation: u64,
}

/// Incremental admissible-source identity for one sink session.
///
/// The byte count and the full SHA-256 identity are advanced with every
/// admitted chunk, so the durable source identity is always available without
/// re-reading or re-hashing the staging window. The accumulator is the single
/// owner of both values: `SinkState` keeps no second byte counter.
struct AdmittedAccount {
    digester: Sha256,
    byte_length: u64,
}

impl AdmittedAccount {
    fn new() -> Self {
        Self {
            digester: Sha256::new(),
            byte_length: 0,
        }
    }

    /// Absorbs one admitted chunk as it flows.
    fn absorb(&mut self, bytes: &[u8]) {
        self.digester.update(bytes);
        self.byte_length = self.byte_length.saturating_add(bytes.len() as u64);
    }

    /// Number of admissible bytes admitted so far.
    const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    /// SHA-256 over every admissible byte admitted so far.
    fn sha256_hex(&self) -> String {
        format!("{:x}", self.digester.clone().finalize())
    }
}

/// The exact boundary where bounded staging refused to grow.
///
/// This is the recorded form of the declared overflow disposition: a session
/// that shed an append can never afterwards present its retained prefix as a
/// complete source, because finalize requires the matching
/// `PERSISTENCE_BACKPRESSURE` gap.
#[derive(Clone, Copy)]
struct StagingOverflow {
    sequence: u64,
    byte_length: u64,
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
/// `max_preview_bytes` and its gaps by the protocol ceiling). The staged
/// plaintext lives in [`SinkState::staged`] and is dropped as soon as the
/// owner's ready receipt carries the same byte commitment.
struct FinalizeReservation {
    identity: ProcessStreamSinkTerminalCommandIdentity,
    incarnation: u64,
    /// The retained original finalize command, so `reconcile` can drive the
    /// same exact command without minting a second terminal request.
    request: ProcessStreamSinkFinalizeRequest,
    next_sequence: u64,
    next_offset: u64,
    admitted_sha256: String,
    /// The exact terminal state this command was admitted to mint, decided once
    /// from the declared coverage so a resumed publish cannot rename itself.
    terminal_state: ProcessStreamSinkState,
    /// Whether the admitted admissible bytes are the whole declared physical
    /// transport stream, retained so the resumed readback keeps the exact
    /// coverage it was reserved with.
    coverage_complete: bool,
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
    /// stage operation identity.
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
    terminal_state: ProcessStreamSinkState,
    coverage_complete: bool,
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
            admitted: AdmittedAccount::new(),
            overflow: None,
            admitted_chunks: Vec::new(),
            next_sequence: 0,
            terminal: None,
            terminal_command: None,
            finalization: None,
            finalization_incarnation: 0,
        }
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

    /// Whether the admissible bytes this provider holds are provably the whole
    /// physical transport stream the command declared.
    ///
    /// The admissible set is a prefix of the physical stream, so the byte
    /// counts alone decide coverage; the digest equality for equal lengths is
    /// enforced by the contract in `ProcessStreamSinkTerminal`.
    fn coverage_complete(state: &SinkState, observed_bytes: u64) -> Result<bool, ProcessStreamSinkError> {
        if state.admitted.byte_length() > observed_bytes {
            return Err(ProcessStreamSinkError::OffsetMismatch {
                expected: observed_bytes,
                observed: state.admitted.byte_length(),
            });
        }
        Ok(state.admitted.byte_length() == observed_bytes)
    }

    /// Whether a staging-window overflow was declared on the command.
    ///
    /// A session that shed an append must not present its retained prefix as a
    /// complete source, so the declared gap set has to name the backpressure.
    fn check_overflow_declared(
        state: &SinkState,
        gaps: &[StreamEvidenceGap],
    ) -> Result<(), ProcessStreamSinkError> {
        if let Some(overflow) = state.overflow
            && !gaps.contains(&StreamEvidenceGap::PersistenceBackpressure)
        {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: format!(
                    "the staging window shed at sequence {} and {} admissible bytes, which must be declared as persistence backpressure",
                    overflow.sequence, overflow.byte_length
                ),
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
        if offset != state.admitted.byte_length() {
            return Err(ProcessStreamSinkError::OffsetMismatch {
                expected: state.admitted.byte_length(),
                observed: offset,
            });
        }
        Ok(())
    }

    /// Proves the command's inline preview is an exact prefix of the very bytes
    /// this provider will stage.
    ///
    /// Both coordinate systems are checked against the same staging window, so
    /// every inline byte in the durable record is an admissible-source byte. A
    /// declared policy transformation additionally requires the durable-source
    /// coordinate system, so a raw pre-policy transport preview can never enter
    /// the record of a transformed source, and the governing policy identity
    /// must be the one bound at session open.
    fn check_staged_preview(
        state: &SinkState,
        session: &ProcessStreamSinkSession,
        request: &ProcessStreamSinkFinalizeRequest,
    ) -> Result<(), ProcessStreamSinkError> {
        let preview = request.preview();
        let staged_length = u64::try_from(state.staged.len()).map_err(|_| {
            ProcessStreamSinkError::EvidenceInvariant {
                reason: "staged length does not fit the session counters".to_owned(),
            }
        })?;
        match request.transformation() {
            None => {
                if preview.representation() != StreamPreviewRepresentation::TransportBytes {
                    return Err(ProcessStreamSinkError::EvidenceInvariant {
                        reason: "an untransformed source cannot carry a durable-source preview"
                            .to_owned(),
                    });
                }
            }
            Some(transformation) => {
                if transformation.policy_ref() != session.policy().policy_ref()
                    || transformation.redaction_ref() != session.policy().redaction_ref()
                {
                    return Err(ProcessStreamSinkError::PolicyMismatch);
                }
                if preview.representation() != StreamPreviewRepresentation::DurableSourceBytes {
                    return Err(ProcessStreamSinkError::EvidenceInvariant {
                        reason: "a policy-transformed source cannot expose a raw transport preview"
                            .to_owned(),
                    });
                }
                if preview.represented_bytes() != staged_length {
                    return Err(ProcessStreamSinkError::EvidenceInvariant {
                        reason: "a transformed preview must use durable source coordinates"
                            .to_owned(),
                    });
                }
            }
        }
        let retained = usize::try_from(preview.retained_bytes()).map_err(|_| {
            ProcessStreamSinkError::EvidenceInvariant {
                reason: "preview retained length does not fit the platform".to_owned(),
            }
        })?;
        if retained > state.staged.len() || preview.bytes() != &state.staged[..retained] {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "the preview is not a prefix of the admissible source".to_owned(),
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
            state.admitted.byte_length(),
            state.next_sequence,
            state.admitted.byte_length(),
            state.admitted.sha256_hex(),
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
                    next_offset: state.admitted.byte_length(),
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
        if request.offset() != state.admitted.byte_length() {
            return Err(ProcessStreamSinkError::OffsetMismatch {
                expected: state.admitted.byte_length(),
                observed: request.offset(),
            });
        }
        let limits = session.limits();
        // Bounded staging, one declared overflow disposition. This adapter
        // never awaits and never performs provider I/O on the drain path, so
        // the pipe cannot be blocked here; a full window instead refuses the
        // append with the session's own declared backpressure disposition and
        // records the exact shed boundary. The caller keeps draining and
        // declares the shed tail as a persistence gap at finalize.
        if state.next_sequence >= limits.max_chunks()
            || request.byte_length()
                > limits
                    .max_total_admitted_bytes()
                    .saturating_sub(state.admitted.byte_length())
        {
            // The first shed boundary is the exact coverage this session can
            // still prove; later refusals report the same boundary.
            if state.overflow.is_none() {
                state.overflow = Some(StagingOverflow {
                    sequence: state.next_sequence,
                    byte_length: state.admitted.byte_length(),
                });
            }
            return Ok(Self::overflow_disposition(session));
        }
        // Each admitted sequence adds exactly one metadata record, so the
        // chunk ceiling bounds this list without retaining another plaintext
        // copy of the stream.
        state.admitted_chunks.push(AdmittedChunk {
            sequence: request.sequence(),
            offset: request.offset(),
            length: request.byte_length(),
            sha256: request.sha256().to_owned(),
        });
        state.admitted.absorb(request.bytes());
        state.staged.extend_from_slice(request.bytes());
        state.next_sequence = state.next_sequence.saturating_add(1);
        Ok(ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: state.next_sequence,
            next_offset: state.admitted.byte_length(),
        })
    }

    /// The one declared overflow disposition of the bounded staging window.
    ///
    /// The retry hint is the session's own declared append wait budget, so the
    /// caller learns the exact ceiling this session published at open instead
    /// of a private constant.
    fn overflow_disposition(
        session: &ProcessStreamSinkSession,
    ) -> ProcessStreamSinkAppendDisposition {
        ProcessStreamSinkAppendDisposition::Backpressured {
            retry_after_ms: session.limits().max_append_wait_ms(),
        }
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
        // The declared physical coverage may legitimately exceed the admitted
        // custody here; the abort terminal then names exactly that gap. The
        // staging overflow needs no gap declaration on this path: an abort
        // never publishes, so it can never claim a complete source.
        let _ = Self::coverage_complete(state, request.observed_bytes())?;
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
        let terminal = ProcessStreamSinkTerminal::from_abort(
            session,
            request,
            Self::abort_state(reason),
            state.next_sequence,
            state.admitted.byte_length(),
            state.admitted.sha256_hex(),
            evidence,
        )?;
        Self::record_locked(state, identity, terminal)
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

    /// Builds the terminal evidence for the published admissible prefix.
    ///
    /// The durable source identity comes from the owner-issued ready receipt,
    /// which `retain_ready` already proved against the staged bytes, so the
    /// locator, the length and the digest describe the very object the owner
    /// holds. A declared policy transformation additionally binds the exact
    /// input/output receipt: the staged bytes must be the declared output and
    /// the declared input must be the physical transport identity the command
    /// carries. The transport-prefix identity is present exactly when a shorter
    /// exact prefix is durable, and never for a transformed source, which
    /// cannot prove which part of its input it covers.
    fn publish_evidence(
        session: &ProcessStreamSinkSession,
        request: &ProcessStreamSinkFinalizeRequest,
        admitted_sha256: &str,
        coverage_complete: bool,
        ready: &BlobReadyReceipt,
    ) -> Result<ProcessStreamEvidence, ProcessStreamSinkError> {
        let receipt_ref = ready.receipt().identity.receipt_id.to_string();
        let locator = format!("{BLOB_SOURCE_LOCATOR_SCHEME}:{}", ready.locator().hash);
        let source = match request.transformation() {
            None => DurableProcessStreamSource::exact_transport(
                DurableStreamLocatorKind::Blob,
                locator,
                receipt_ref,
                admitted_sha256.to_owned(),
                ready.plaintext_length(),
            )?,
            Some(transformation) => {
                // The receipt must describe the staged bytes exactly, and its
                // declared input must be the physical stream this command
                // carries. Anything else is refused before a terminal exists.
                if ready.plaintext_sha256() != transformation.output_sha256()
                    || ready.plaintext_length() != transformation.output_byte_length()
                {
                    return Err(ProcessStreamSinkError::EvidenceInvariant {
                        reason: "the staged bytes are not the declared transformation output"
                            .to_owned(),
                    });
                }
                if transformation.input_sha256() != request.observed_sha256()
                    || transformation.input_byte_length() != request.observed_bytes()
                {
                    return Err(ProcessStreamSinkError::EvidenceInvariant {
                        reason: "the transformation input is not the declared transport stream"
                            .to_owned(),
                    });
                }
                DurableProcessStreamSource::policy_transformed(
                    DurableStreamLocatorKind::Blob,
                    locator,
                    receipt_ref,
                    transformation.output_sha256().to_owned(),
                    ready.plaintext_length(),
                    transformation.clone(),
                )?
            }
        };
        let prefix_identity = if coverage_complete || request.transformation().is_some() {
            None
        } else {
            Some(ProcessStreamTransportPrefixIdentity::new(
                admitted_sha256.to_owned(),
                ready.plaintext_length(),
            )?)
        };
        let persistence = if coverage_complete {
            StreamPersistenceStatus::CompleteSource
        } else {
            StreamPersistenceStatus::PartialSource
        };
        ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            session.binding().clone(),
            session.stream(),
            session.policy().clone(),
            request.transport(),
            persistence,
            request.observed_sha256().to_owned(),
            request.observed_bytes(),
            request.preview().clone(),
            Some(source),
            prefix_identity,
            request.gaps().to_vec(),
        )
        .map_err(ProcessStreamSinkError::from)
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
        let coverage_complete = Self::coverage_complete(&state, request.observed_bytes())?;
        Self::check_overflow_declared(&state, request.gaps())?;
        // The declared gap set, not an adapter-local comparison, decides what
        // may be staged and which terminal names the outcome.
        let disposition = ProcessStreamPersistenceDisposition::from_gaps(request.gaps());
        let named_state = disposition.terminal_state(coverage_complete)?;
        let publishes = disposition.stages_admissible_bytes(coverage_complete)
            && Self::publishable_transport(request, named_state);
        // A state that names a durable source while nothing was staged would be
        // an unprovable claim, so the honest terminal is the unavailable one:
        // the retained admissible bytes are custody, not a durable locator. A
        // withheld disposition keeps its own exact name.
        let terminal_state = if !publishes
            && matches!(
                named_state,
                ProcessStreamSinkState::CompleteSource | ProcessStreamSinkState::PartialSource
            )
        {
            ProcessStreamSinkState::SourceUnavailable
        } else {
            named_state
        };
        if publishes {
            Self::check_staged_preview(&state, &existing, request)?;
        }
        let admitted_sha256 = state.admitted.sha256_hex();

        // An existing reservation for this exact command is resumed, never
        // re-reserved: the same terminal id can never drive a second stage.
        // A reservation for a different command is a conflict, not a race.
        if let Some(reservation) = state.finalization.as_ref() {
            if reservation.identity != identity {
                return Err(ProcessStreamSinkError::TerminalIdentityConflict);
            }
            let step = match reservation.ready() {
                Some(ready) => PublishStep::Readback {
                    ready: Box::new(ready.clone()),
                },
                None => PublishStep::Stage {
                    staged: state.staged.clone(),
                },
            };
            return Ok(FinalizePlan::Publish(Box::new(PublishTicket {
                session: existing,
                request: request.clone(),
                identity: reservation.identity.clone(),
                incarnation: reservation.incarnation,
                next_sequence: reservation.next_sequence,
                next_offset: reservation.next_offset,
                admitted_sha256: reservation.admitted_sha256.clone(),
                terminal_state: reservation.terminal_state,
                coverage_complete: reservation.coverage_complete,
                step,
            })));
        }

        if !publishes {
            return Ok(Self::withheld_plan(
                &state,
                existing,
                request,
                identity,
                admitted_sha256,
                terminal_state,
            ));
        }

        // One reservation per session: bound to this session, this exact
        // command digest and the one bound blob stage operation.
        Ok(self.reserve_publish(
            &mut state,
            existing,
            request,
            identity,
            admitted_sha256,
            terminal_state,
            coverage_complete,
        ))
    }

    /// Whether the evidence contract can represent this durable publication.
    ///
    /// A complete source is always representable. A partial source must be an
    /// exact transport prefix, because a policy-transformed source has no
    /// transport-prefix identity and therefore cannot prove which part of its
    /// input it covers once the transport itself reached EOF. The evidence
    /// contract remains the final authority: this only avoids staging an object
    /// whose terminal could never be minted.
    fn publishable_transport(
        request: &ProcessStreamSinkFinalizeRequest,
        terminal_state: ProcessStreamSinkState,
    ) -> bool {
        match terminal_state {
            ProcessStreamSinkState::CompleteSource => true,
            ProcessStreamSinkState::PartialSource => {
                request.transformation().is_none()
                    || request.transport() != StreamTransportStatus::Complete
            }
            ProcessStreamSinkState::Opening
            | ProcessStreamSinkState::Open
            | ProcessStreamSinkState::Finalizing
            | ProcessStreamSinkState::SourceUnavailable
            | ProcessStreamSinkState::PolicyProhibited
            | ProcessStreamSinkState::RedactionFailed
            | ProcessStreamSinkState::PersistenceFailed
            | ProcessStreamSinkState::Cancelled
            | ProcessStreamSinkState::UnknownOutcome => false,
        }
    }

    /// Builds the never-published terminal plan for a non-publishing
    /// finalize.
    ///
    /// No durable publication except for the exact states named by the
    /// disposition table: a policy-prohibited, failed-redaction, or
    /// complete-coverage-contradicting finalize must not stage raw bytes as a
    /// second object. This step cannot fail, so it mints no error and reserves
    /// nothing.
    fn withheld_plan(
        state: &SinkState,
        session: ProcessStreamSinkSession,
        request: &ProcessStreamSinkFinalizeRequest,
        identity: ProcessStreamSinkTerminalCommandIdentity,
        admitted_sha256: String,
        withheld: ProcessStreamSinkState,
    ) -> FinalizePlan {
        FinalizePlan::Withheld(Box::new(WithheldTicket {
            session,
            request: request.clone(),
            identity,
            next_sequence: state.next_sequence,
            next_offset: state.admitted.byte_length(),
            admitted_sha256,
            state: withheld,
        }))
    }

    /// Creates the one reservation of this session and its publish plan.
    ///
    /// One reservation per session, bound to this session, this exact command
    /// digest and the one bound blob stage operation. The phase starts
    /// `Reserved`: nothing has been handed to the blob owner yet.
    #[allow(clippy::too_many_arguments)]
    fn reserve_publish(
        &self,
        state: &mut SinkState,
        session: ProcessStreamSinkSession,
        request: &ProcessStreamSinkFinalizeRequest,
        identity: ProcessStreamSinkTerminalCommandIdentity,
        admitted_sha256: String,
        terminal_state: ProcessStreamSinkState,
        coverage_complete: bool,
    ) -> FinalizePlan {
        let incarnation = state.finalization_incarnation.saturating_add(1);
        state.finalization_incarnation = incarnation;
        let next_sequence = state.next_sequence;
        let next_offset = state.admitted.byte_length();
        state.finalization = Some(FinalizeReservation {
            identity: identity.clone(),
            incarnation,
            request: request.clone(),
            next_sequence,
            next_offset,
            admitted_sha256: admitted_sha256.clone(),
            terminal_state,
            coverage_complete,
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
            next_sequence,
            next_offset,
            admitted_sha256,
            terminal_state,
            coverage_complete,
            step: PublishStep::Stage {
                staged: state.staged.clone(),
            },
        }))
    }

    /// Records the terminal exactly once under the command identity, drops
    /// the staged plaintext, and reconciles a same-identity replay to the
    /// existing terminal instead of a second object.
    fn record_locked(
        state: &mut SinkState,
        identity: ProcessStreamSinkTerminalCommandIdentity,
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
        state.terminal = Some(terminal.clone());
        Ok(terminal)
    }

    /// Publishes the reserved admissible source: at most one stage under the
    /// original identity, then the readback, then the reserved terminal. A
    /// failure leaves the phase advanced, never a bare flag.
    async fn publish_reserved(
        &self,
        ticket: PublishTicket,
        _hold: FinalizeHold<'_, C>,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let ready = match ticket.step {
            PublishStep::Readback { ready } => *ready,
            PublishStep::Stage { staged } => {
                self.stage_once(&ticket.identity, ticket.incarnation, &staged)
                    .await?
            }
        };
        self.verify_readback(&ready).await?;
        let evidence = Self::publish_evidence(
            &ticket.session,
            &ticket.request,
            &ticket.admitted_sha256,
            ticket.coverage_complete,
            &ready,
        )?;
        let terminal = ProcessStreamSinkTerminal::from_finalize(
            ticket.session,
            ticket.request,
            ticket.terminal_state,
            ticket.next_sequence,
            ticket.next_offset,
            ticket.admitted_sha256,
            evidence,
        )?;
        Self::record_locked(&mut self.lock(), ticket.identity, terminal)
    }

    /// Mints the withheld (never-published) terminal for a gapped,
    /// policy-prohibited or failed-redaction finalize.
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
        Self::record_locked(&mut self.lock(), ticket.identity, terminal)
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
