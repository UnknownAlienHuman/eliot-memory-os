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
//! Governing fragments: I5.12 (single-owner CAS, BYTES-only durability),
//! I10.8.5 (bounded preview, append-only temporary evidence, final
//! BlobRef+digest), I5.27 (exact operation/session identity, no blind
//! retry), I7.2 (idempotent replay under an exact fence, no second object).

use std::sync::{Mutex, MutexGuard, PoisonError};

use eliot_blob_api::{
    BlobError, BlobHash, BlobPolicyBinding, BlobReadRequest, BlobReadyReceipt, BlobReceiptContext,
    BlobRootLease, BlobStageRequest, BlobStoreClient, ObjectResidencyKey, VersionedContentDigest,
};
use eliot_process::{
    DurableProcessStreamSource, DurableStreamLocatorKind, ProcessStreamEvidence,
    ProcessStreamPrefixPreview, ProcessStreamSinkAbortReason, ProcessStreamSinkAbortRequest,
    ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition, ProcessStreamSinkClient,
    ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest, ProcessStreamSinkFuture,
    ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback, ProcessStreamSinkSession,
    ProcessStreamSinkSessionView, ProcessStreamSinkState, ProcessStreamSinkTerminal,
    ProcessStreamSinkTerminalCommandIdentity, ProcessStreamSinkUnknownOutcome, StreamEvidenceGap,
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
    staged: Vec<u8>,
    digester: Sha256,
    admitted_chunks: Vec<AdmittedChunk>,
    next_sequence: u64,
    next_offset: u64,
    terminal: Option<ProcessStreamSinkTerminal>,
    terminal_command: Option<ProcessStreamSinkTerminalCommandIdentity>,
    finalizing: Option<ProcessStreamSinkTerminalCommandIdentity>,
}

struct AdmittedChunk {
    sequence: u64,
    offset: u64,
    length: u64,
    sha256: String,
}

enum FinalizeKind {
    Publish {
        staged: Vec<u8>,
        admitted_sha256: String,
    },
    Withheld {
        state: ProcessStreamSinkState,
        admitted_sha256: String,
    },
}

struct FinalizePlan {
    session: ProcessStreamSinkSession,
    request: ProcessStreamSinkFinalizeRequest,
    identity: ProcessStreamSinkTerminalCommandIdentity,
    next_sequence: u64,
    next_offset: u64,
    kind: FinalizeKind,
}

impl SinkState {
    fn new() -> Self {
        Self {
            session: None,
            staged: Vec::new(),
            digester: Sha256::new(),
            admitted_chunks: Vec::new(),
            next_sequence: 0,
            next_offset: 0,
            terminal: None,
            terminal_command: None,
            finalizing: None,
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

    fn session_view(
        session: &ProcessStreamSinkSession,
        state: &SinkState,
    ) -> Result<ProcessStreamSinkReadback, ProcessStreamSinkError> {
        let view = ProcessStreamSinkSessionView::new(
            session.session_id().clone(),
            session.source_id().clone(),
            session.terminal_id().clone(),
            if state.finalizing.is_some() {
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
        if state.finalizing.is_some() {
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
        if state.finalizing.is_some() {
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
        let terminal = ProcessStreamSinkTerminal::from_abort(
            session,
            request,
            Self::abort_state(reason),
            state.next_sequence,
            state.next_offset,
            state.admitted_sha256(),
            evidence,
        )?;
        Self::record_locked(state, identity, terminal)
    }

    /// Stages the exact admitted bytes, verifies the ready receipt, and reads
    /// the object back. Any failure leaves the reserved command unresolved;
    /// it must not be blindly staged again.
    async fn publish_complete_source(
        &self,
        staged: Vec<u8>,
    ) -> Result<BlobReadyReceipt, ProcessStreamSinkError> {
        let template = self.binding.residency();
        let digest = BlobHash::new(blake3::hash(&staged).to_hex().to_string())
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
        let ready = self
            .store
            .stage(BlobStageRequest {
                context: self.binding.stage_context().clone(),
                root_lease: self.binding.root_lease().clone(),
                bytes: staged.clone(),
                policy: self.binding.policy().clone(),
                residency,
            })
            .await
            .map_err(|error| map_blob_error(&error))?;
        ready.validate().map_err(|error| map_blob_error(&error))?;
        let admitted_sha256 = format!("{:x}", Sha256::digest(&staged));
        let staged_length =
            u64::try_from(staged.len()).map_err(|_| ProcessStreamSinkError::EvidenceInvariant {
                reason: "staged length does not fit the session counters".to_owned(),
            })?;
        if ready.plaintext_sha256() != admitted_sha256 || ready.plaintext_length() != staged_length
        {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "blob ready receipt does not describe the staged bytes".to_owned(),
            });
        }
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
        if chunk.bytes() != staged.as_slice() {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "blob readback does not match the staged bytes".to_owned(),
            });
        }
        Ok(ready)
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

    fn plan_finalize(
        &self,
        session: &ProcessStreamSinkSession,
        request: &ProcessStreamSinkFinalizeRequest,
    ) -> Result<Option<FinalizePlan>, ProcessStreamSinkError> {
        let mut state = self.lock();
        let existing = Self::check_session(&state, session)?;
        let identity = request.command_identity()?;
        if state.terminal.is_some() {
            return if state.terminal_command.as_ref() == Some(&identity) {
                Ok(None)
            } else {
                Err(ProcessStreamSinkError::TerminalIdentityConflict)
            };
        }
        if let Some(finalizing) = &state.finalizing {
            return if finalizing == &identity {
                Ok(None)
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
        if request.transformation().is_some() {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "adapter stages exact transport bytes only".to_owned(),
            });
        }
        Self::check_preview(&state, request.preview())?;
        let reserved_identity = identity.clone();
        let plan = if request.gaps().is_empty()
            && request.transport() == StreamTransportStatus::Complete
        {
            FinalizePlan {
                session: existing,
                request: request.clone(),
                identity,
                next_sequence: state.next_sequence,
                next_offset: state.next_offset,
                kind: FinalizeKind::Publish {
                    staged: state.staged.clone(),
                    admitted_sha256: state.admitted_sha256(),
                },
            }
        } else {
            // No durable publication except for the complete-source path: a
            // gapped, policy-prohibited, or failed-redaction finalize must
            // not stage raw bytes as a second object.
            let withheld = if request
                .gaps()
                .contains(&StreamEvidenceGap::PolicyProhibited)
            {
                ProcessStreamSinkState::PolicyProhibited
            } else if request.gaps().contains(&StreamEvidenceGap::RedactionFailed) {
                ProcessStreamSinkState::RedactionFailed
            } else {
                ProcessStreamSinkState::SourceUnavailable
            };
            FinalizePlan {
                session: existing,
                request: request.clone(),
                identity,
                next_sequence: state.next_sequence,
                next_offset: state.next_offset,
                kind: FinalizeKind::Withheld {
                    state: withheld,
                    admitted_sha256: state.admitted_sha256(),
                },
            }
        };
        state.finalizing = Some(reserved_identity);
        Ok(Some(plan))
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
            .finalizing
            .as_ref()
            .is_some_and(|finalizing| finalizing != &identity)
        {
            return Err(ProcessStreamSinkError::TerminalIdentityConflict);
        }
        state.terminal_command = Some(identity);
        state.finalizing = None;
        state.staged = Vec::new();
        state.terminal = Some(terminal.clone());
        Ok(terminal)
    }

    async fn finalize_async(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let Some(plan) = self.plan_finalize(&session, &request)? else {
            let state = self.lock();
            return state
                .terminal
                .clone()
                .ok_or(ProcessStreamSinkError::ProviderUnavailable);
        };
        match plan {
            FinalizePlan {
                session,
                request,
                identity,
                next_sequence,
                next_offset,
                kind:
                    FinalizeKind::Publish {
                        staged,
                        admitted_sha256,
                    },
            } => {
                let ready = self.publish_complete_source(staged).await?;
                let evidence = Self::complete_source(&session, &request, &admitted_sha256, &ready)?;
                let terminal = ProcessStreamSinkTerminal::from_finalize(
                    session,
                    request,
                    ProcessStreamSinkState::CompleteSource,
                    next_sequence,
                    next_offset,
                    admitted_sha256,
                    evidence,
                )?;
                Self::record_locked(&mut self.lock(), identity, terminal)
            }
            FinalizePlan {
                session,
                request,
                identity,
                next_sequence,
                next_offset,
                kind:
                    FinalizeKind::Withheld {
                        state,
                        admitted_sha256,
                    },
            } => {
                let evidence = ProcessStreamEvidence::new_raw(
                    session.binding().clone(),
                    session.stream(),
                    session.policy().clone(),
                    request.transport(),
                    StreamPersistenceStatus::SourceUnavailable,
                    request.observed_sha256().to_owned(),
                    request.observed_bytes(),
                    request.preview().clone(),
                    None,
                    request.gaps().to_vec(),
                )?;
                let terminal = ProcessStreamSinkTerminal::from_finalize(
                    session,
                    request,
                    state,
                    next_sequence,
                    next_offset,
                    admitted_sha256,
                    evidence,
                )?;
                Self::record_locked(&mut self.lock(), identity, terminal)
            }
        }
    }
}

/// Maps a blob-layer failure onto the sink contract.
///
/// Integrity and metadata/payload-coherence failures are evidence failures;
/// every other provider failure (transport, capacity, key, fence, unknown
/// outcome, incomplete publish) is the contract's typed provider-unavailable
/// signal. Both forms refuse a `COMPLETE_SOURCE` terminal by construction:
/// they return `Err` before any terminal exists.
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
            Self::session_view(&existing, &state)
        });
        Self::ready(result)
    }

    fn reconcile(
        &self,
        session: ProcessStreamSinkSession,
        outcome: ProcessStreamSinkUnknownOutcome,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let state = self.lock();
        let result = Self::check_session(&state, &session).and_then(|existing| {
            outcome.validate_against_session(&existing)?;
            if let Some(terminal) = &state.terminal {
                return Ok(ProcessStreamSinkReadback::Terminal {
                    terminal: terminal.clone(),
                });
            }
            // The adapter has no durable provider reconciliation query. An
            // unresolved external effect remains nonterminal and unavailable;
            // cleanup or replay cannot convert it into success or restage it.
            Err(ProcessStreamSinkError::ProviderUnavailable)
        });
        Self::ready(result)
    }
}
