//! Testd-owned immutable stream retention (issue #456, WA11/WB1).
//!
//! This module is the production [`ProcessStreamSinkClient`] the composed
//! executor pumps policy-bound process output into, and the production
//! [`ProcessStreamSourceReadbackPort`] the finish path resolves admitted
//! sources through. Both roles share one [`TestdStore`] handle: finalize
//! persists exact bytes plus a [`TestdStreamSourceSidecar`] in a single
//! transaction, and readback serves only what the store re-verifies.
//!
//! Boundaries kept here (never crossed):
//!
//! - one drive, one job: a retention instance is fenced at construction for
//!   the driven job/attempt. Sessions are keyed by the deterministic sink
//!   open digest, so a second open of the same session returns the same live
//!   state and exactly one terminal ever lands per session. A new drive (a
//!   new attempt) builds a fresh instance over the same store file: finalized
//!   rows stay servable by locator without operation memory, while in-flight
//!   chunks of a dead drive are dropped with its instance instead of being
//!   mistaken for a new attempt's bytes;
//! - Blob locators are never served here: rows only ever carry
//!   [`DurableStreamLocatorKind::ImmutableArtifact`], and a readback request
//!   naming another locator class is refused. The Blob-backed adapter stays
//!   #297's contract; the core stays blob/filesystem-free;
//! - no parsing, evaluation, or finish authority: the port returns exact
//!   bytes plus the owner-issued observation, and the core verifies every
//!   binding itself. Policy-prohibited or redaction-failed streams never land
//!   a durable row, so no byte path exists for them;
//! - the pipe never blocks on persistence: every client call runs
//!   synchronously against memory plus one bounded store transaction and
//!   returns an immediately-ready future. A store failure surfaces as
//!   provider-unavailable, and the pump sheds with an explicit typed gap.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use eliot_contracts::{ClockReading, StateFence};
use eliot_process::{
    DurableProcessStreamSource, DurableStreamLocatorKind, ProcessStreamEvidence, ProcessStreamKind,
    ProcessStreamSinkAbortReason, ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition,
    ProcessStreamSinkClient, ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest,
    ProcessStreamSinkFuture, ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback,
    ProcessStreamSinkSession, ProcessStreamSinkSessionView, ProcessStreamSinkState,
    ProcessStreamSinkTerminal, ProcessStreamSinkTerminalCommandIdentity,
};
use eliot_testd_core::{
    ProcessStreamSourceReadbackObservation, ProcessStreamSourceReadbackPort,
    ProcessStreamSourceReadbackRequest, TestdEvidenceError, TestdStore, TestdStreamDisposition,
    TestdStreamSourceSidecar, sha256_hex,
};

/// Locator scheme for testd-retained immutable sources.
const RETAINED_LOCATOR_SCHEME: &str = "testd-retained";
/// Ready-receipt identity prefix minted at finalize.
const READY_RECEIPT_PREFIX: &str = "testd-ready";
/// Readback-receipt identity prefix minted at finalize.
const READBACK_RECEIPT_PREFIX: &str = "testd-readback";

/// Testd-owned retention over one store, fenced for one driven job/attempt.
///
/// Clone shares the live sessions: the executor's pumps (client role) and
/// the finish path (port role) observe one state.
#[derive(Clone)]
pub struct TestdStreamRetention {
    inner: Arc<RetentionInner>,
}

struct RetentionInner {
    store: Arc<TestdStore>,
    fence: StateFence,
    sessions: Mutex<BTreeMap<String, LiveSession>>,
}

/// One open sink session with its admitted prefix and optional terminal.
struct LiveSession {
    session: ProcessStreamSinkSession,
    locator: String,
    buffer: Vec<u8>,
    next_sequence: u64,
    next_offset: u64,
    terminal: Option<ProcessStreamSinkTerminal>,
    terminal_command: Option<ProcessStreamSinkTerminalCommandIdentity>,
}

impl TestdStreamRetention {
    /// Binds one retention to its store and attempt fence.
    ///
    /// The fence pins every row this instance finalizes: post-restart
    /// readback compares the pinned fence against the resolving attempt, so
    /// a new generation can never silently inherit an old row's bytes.
    pub fn new(store: Arc<TestdStore>, fence: StateFence) -> Self {
        Self {
            inner: Arc::new(RetentionInner {
                store,
                fence,
                sessions: Mutex::new(BTreeMap::new()),
            }),
        }
    }

    fn lock(
        &self,
    ) -> Result<MutexGuard<'_, BTreeMap<String, LiveSession>>, ProcessStreamSinkError> {
        self.inner
            .sessions
            .lock()
            .map_err(|_| ProcessStreamSinkError::ProviderUnavailable)
    }

    /// Derives the durable locator for one open session.
    ///
    /// The locator embeds the exact job/operation/stream the sink session
    /// was opened for, so rows of different attempts can never alias.
    fn locator_for(session: &ProcessStreamSinkSession) -> Result<String, ProcessStreamSinkError> {
        let job = session.binding().job_id().as_str();
        let operation = session.binding().operation_id().as_str();
        let stream = match session.stream() {
            ProcessStreamKind::Stdout => "stdout",
            ProcessStreamKind::Stderr => "stderr",
        };
        for (field, value) in [("job_id", job), ("operation_id", operation)] {
            if value.is_empty() || value.contains(':') || value.chars().any(char::is_control) {
                return Err(ProcessStreamSinkError::EvidenceInvariant {
                    reason: match field {
                        "job_id" => "sink session job identity cannot form a locator".to_owned(),
                        _ => "sink session operation identity cannot form a locator".to_owned(),
                    },
                });
            }
        }
        Ok(format!(
            "{RETAINED_LOCATOR_SCHEME}:{job}:{operation}:{stream}"
        ))
    }

    fn ready<T: Send + 'static>(
        result: Result<T, ProcessStreamSinkError>,
    ) -> ProcessStreamSinkFuture<'static, T> {
        Box::pin(async move { result })
    }

    /// Builds the durable terminal evidence for one finalized session.
    ///
    /// Mirrors the admitted #267 fake shape: the source is `Some` exactly on
    /// gap-free terminals and `None` otherwise, and the evidence fields echo
    /// the pump's exactly-observed transport facts.
    fn complete_evidence(
        live: &LiveSession,
        request: &ProcessStreamSinkFinalizeRequest,
        locator: &str,
        ready_receipt_ref: &str,
        digest: &str,
        byte_length: u64,
    ) -> Result<ProcessStreamEvidence, ProcessStreamSinkError> {
        let (persistence, source) = if request.gaps().is_empty() {
            let source = DurableProcessStreamSource::exact_transport(
                DurableStreamLocatorKind::ImmutableArtifact,
                locator.to_owned(),
                ready_receipt_ref.to_owned(),
                digest.to_owned(),
                byte_length,
            )?;
            (
                eliot_process::StreamPersistenceStatus::CompleteSource,
                Some(source),
            )
        } else {
            (
                eliot_process::StreamPersistenceStatus::SourceUnavailable,
                None,
            )
        };
        ProcessStreamEvidence::new_raw(
            live.session.binding().clone(),
            live.session.stream(),
            live.session.policy().clone(),
            request.transport(),
            persistence,
            request.observed_sha256().to_owned(),
            request.observed_bytes(),
            request.preview().clone(),
            source,
            request.gaps().to_vec(),
        )
        .map_err(|error| ProcessStreamSinkError::EvidenceInvariant {
            reason: error.to_string(),
        })
    }

    /// Serves the open session view for one live session.
    fn session_view(
        live: &LiveSession,
    ) -> Result<ProcessStreamSinkSessionView, ProcessStreamSinkError> {
        ProcessStreamSinkSessionView::new(
            live.session.session_id().clone(),
            live.session.source_id().clone(),
            live.session.terminal_id().clone(),
            ProcessStreamSinkState::Open,
            live.next_sequence,
            live.next_offset,
            live.next_sequence,
            live.next_offset,
            sha256_hex(&live.buffer),
            live.session.open_request_sha256().to_owned(),
            None,
        )
        .map_err(|error| ProcessStreamSinkError::EvidenceInvariant {
            reason: error.to_string(),
        })
    }

    /// Settles one session to exactly one terminal with its durable row.
    ///
    /// The terminal lands in memory only after the store transaction commits:
    /// a store failure reports provider-unavailable with no terminal, so the
    /// pump retries the identical finalize instead of serving lost bytes.
    /// Only gap-free terminals persist rows; every other terminal stays a
    /// memory-only record with no source locator.
    fn finalize_inner(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> Result<ProcessStreamSinkTerminal, ProcessStreamSinkError> {
        let key = session.open_request_sha256().to_owned();
        let mut sessions = self.lock()?;
        let live = sessions
            .get_mut(&key)
            .ok_or(ProcessStreamSinkError::ProviderUnavailable)?;
        if live.session != session {
            return Err(ProcessStreamSinkError::SessionMismatch);
        }
        let identity = request.command_identity()?;
        if let Some(terminal) = &live.terminal {
            return if live.terminal_command.as_ref() == Some(&identity) {
                Ok(terminal.clone())
            } else {
                Err(ProcessStreamSinkError::TerminalIdentityConflict)
            };
        }
        if request.expected_final_sequence() != live.next_sequence {
            return Err(ProcessStreamSinkError::SequenceGap {
                expected: live.next_sequence,
                observed: request.expected_final_sequence(),
            });
        }
        if request.expected_final_offset() != live.next_offset {
            return Err(ProcessStreamSinkError::OffsetMismatch {
                expected: live.next_offset,
                observed: request.expected_final_offset(),
            });
        }
        let digest = sha256_hex(&live.buffer);
        let byte_length = live.next_offset;
        if request.observed_sha256() != digest || request.observed_bytes() != byte_length {
            return Err(ProcessStreamSinkError::EvidenceInvariant {
                reason: "finalize observed facts do not match admitted chunks".to_owned(),
            });
        }
        let ready_receipt_ref = format!(
            "{READY_RECEIPT_PREFIX}:{}:{digest}",
            live.session.open_request_sha256()
        );
        let evidence = Self::complete_evidence(
            live,
            &request,
            live.locator.as_str(),
            &ready_receipt_ref,
            &digest,
            byte_length,
        )?;
        let state = if request.gaps().is_empty() {
            ProcessStreamSinkState::CompleteSource
        } else {
            ProcessStreamSinkState::SourceUnavailable
        };
        let terminal = ProcessStreamSinkTerminal::from_finalize(
            live.session.clone(),
            request,
            state,
            live.next_sequence,
            live.next_offset,
            digest.clone(),
            evidence,
        )?;
        if state == ProcessStreamSinkState::CompleteSource {
            let sidecar = TestdStreamSourceSidecar {
                locator: live.locator.clone(),
                locator_kind: DurableStreamLocatorKind::ImmutableArtifact,
                ready_receipt_ref,
                readback_receipt_id: format!(
                    "{READBACK_RECEIPT_PREFIX}:{}",
                    terminal.terminal_sha256()
                ),
                sha256: digest,
                byte_length,
                job_id: live.session.binding().job_id().as_str().to_owned(),
                stream: live.session.stream(),
                terminal_state: state,
                terminal_sha256: terminal.terminal_sha256().to_owned(),
                fence: self.inner.fence.clone(),
                observed_at_ms: current_clock_ms(),
            };
            self.inner
                .store
                .store_stream_source(&sidecar, &live.buffer)
                .map_err(|_| ProcessStreamSinkError::ProviderUnavailable)?;
        }
        live.terminal_command = Some(identity);
        live.terminal = Some(terminal.clone());
        Ok(terminal)
    }
}

impl ProcessStreamSinkClient for TestdStreamRetention {
    fn open(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkSession> {
        let result = (|| {
            let session = ProcessStreamSinkSession::from_open_request(request)?;
            let key = session.open_request_sha256().to_owned();
            let mut sessions = self.lock()?;
            if let Some(live) = sessions.get(&key) {
                if live.session == session {
                    return Ok(live.session.clone());
                }
                return Err(ProcessStreamSinkError::OpenDigestMismatch);
            }
            let locator = Self::locator_for(&session)?;
            sessions.insert(
                key,
                LiveSession {
                    session: session.clone(),
                    locator,
                    buffer: Vec::new(),
                    next_sequence: 0,
                    next_offset: 0,
                    terminal: None,
                    terminal_command: None,
                },
            );
            Ok(session)
        })();
        Self::ready(result)
    }

    fn append(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkAppendDisposition> {
        let result = (|| {
            let key = session.open_request_sha256().to_owned();
            let mut sessions = self.lock()?;
            let live = sessions
                .get_mut(&key)
                .ok_or(ProcessStreamSinkError::ProviderUnavailable)?;
            if live.session != session {
                return Err(ProcessStreamSinkError::SessionMismatch);
            }
            if let Some(terminal) = &live.terminal {
                return Ok(ProcessStreamSinkAppendDisposition::Terminal {
                    state: terminal.state(),
                    terminal_sha256: terminal.terminal_sha256().to_owned(),
                });
            }
            live.session.validate_append(&request)?;
            if request.wait_budget_ms() == 0 {
                return Ok(ProcessStreamSinkAppendDisposition::DeadlineExceeded);
            }
            if request.sequence() != live.next_sequence {
                return Err(if request.sequence() < live.next_sequence {
                    ProcessStreamSinkError::MismatchedReplay
                } else {
                    ProcessStreamSinkError::SequenceGap {
                        expected: live.next_sequence,
                        observed: request.sequence(),
                    }
                });
            }
            if request.offset() != live.next_offset {
                return Err(ProcessStreamSinkError::OffsetMismatch {
                    expected: live.next_offset,
                    observed: request.offset(),
                });
            }
            if live.next_sequence >= live.session.limits().max_chunks() {
                return Err(ProcessStreamSinkError::ChunkCountLimitExceeded);
            }
            if request.byte_length()
                > live
                    .session
                    .limits()
                    .max_total_admitted_bytes()
                    .saturating_sub(live.next_offset)
            {
                return Err(ProcessStreamSinkError::TotalLimitExceeded);
            }
            live.next_sequence = live.next_sequence.saturating_add(1);
            live.next_offset = live.next_offset.saturating_add(request.byte_length());
            live.buffer.extend_from_slice(request.bytes());
            Ok(ProcessStreamSinkAppendDisposition::Accepted {
                next_sequence: live.next_sequence,
                next_offset: live.next_offset,
            })
        })();
        Self::ready(result)
    }

    fn finalize(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let result = self.finalize_inner(session, request);
        Self::ready(result)
    }

    fn abort(
        &self,
        session: ProcessStreamSinkSession,
        request: eliot_process::ProcessStreamSinkAbortRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let result = (|| {
            let key = session.open_request_sha256().to_owned();
            let mut sessions = self.lock()?;
            let live = sessions
                .get_mut(&key)
                .ok_or(ProcessStreamSinkError::ProviderUnavailable)?;
            if live.session != session {
                return Err(ProcessStreamSinkError::SessionMismatch);
            }
            let identity = request.command_identity()?;
            if let Some(terminal) = &live.terminal {
                return if live.terminal_command.as_ref() == Some(&identity) {
                    Ok(terminal.clone())
                } else {
                    Err(ProcessStreamSinkError::TerminalIdentityConflict)
                };
            }
            if request.expected_final_sequence() != live.next_sequence {
                return Err(ProcessStreamSinkError::SequenceGap {
                    expected: live.next_sequence,
                    observed: request.expected_final_sequence(),
                });
            }
            if request.expected_final_offset() != live.next_offset {
                return Err(ProcessStreamSinkError::OffsetMismatch {
                    expected: live.next_offset,
                    observed: request.expected_final_offset(),
                });
            }
            let digest = sha256_hex(&live.buffer);
            if request.observed_sha256() != digest || request.observed_bytes() != live.next_offset {
                return Err(ProcessStreamSinkError::EvidenceInvariant {
                    reason: "abort observed facts do not match admitted chunks".to_owned(),
                });
            }
            let evidence = ProcessStreamEvidence::new_raw(
                live.session.binding().clone(),
                live.session.stream(),
                live.session.policy().clone(),
                request.transport(),
                eliot_process::StreamPersistenceStatus::SourceUnavailable,
                request.observed_sha256().to_owned(),
                request.observed_bytes(),
                request.preview().clone(),
                None,
                request.gaps().to_vec(),
            )
            .map_err(|error| ProcessStreamSinkError::EvidenceInvariant {
                reason: error.to_string(),
            })?;
            let state = match request.reason() {
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
            };
            let terminal = ProcessStreamSinkTerminal::from_abort(
                live.session.clone(),
                request,
                state,
                live.next_sequence,
                live.next_offset,
                digest,
                evidence,
            )?;
            live.terminal_command = Some(identity);
            live.terminal = Some(terminal.clone());
            Ok(terminal)
        })();
        Self::ready(result)
    }

    fn readback(
        &self,
        session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let result = (|| {
            let key = session.open_request_sha256().to_owned();
            let sessions = self.lock()?;
            let live = sessions
                .get(&key)
                .ok_or(ProcessStreamSinkError::SessionMismatch)?;
            if live.session != session {
                return Err(ProcessStreamSinkError::SessionMismatch);
            }
            if let Some(terminal) = &live.terminal {
                return Ok(ProcessStreamSinkReadback::Terminal {
                    terminal: terminal.clone(),
                });
            }
            Ok(ProcessStreamSinkReadback::Session {
                view: Self::session_view(live)?,
            })
        })();
        Self::ready(result)
    }

    fn reconcile(
        &self,
        session: ProcessStreamSinkSession,
        outcome: eliot_process::ProcessStreamSinkUnknownOutcome,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let result = (|| {
            let key = session.open_request_sha256().to_owned();
            let sessions = self.lock()?;
            let live = sessions
                .get(&key)
                .ok_or(ProcessStreamSinkError::SessionMismatch)?;
            if live.session != session {
                return Err(ProcessStreamSinkError::SessionMismatch);
            }
            outcome.validate_against_session(&live.session)?;
            if let Some(terminal) = &live.terminal {
                return Ok(ProcessStreamSinkReadback::Terminal {
                    terminal: terminal.clone(),
                });
            }
            Ok(ProcessStreamSinkReadback::UnknownOutcome { outcome })
        })();
        Self::ready(result)
    }
}

impl ProcessStreamSourceReadbackPort for TestdStreamRetention {
    /// Resolves one admitted locator to exact bytes plus the observation.
    ///
    /// Every binding is re-verified against the durable row before a byte is
    /// served: Blob locator classes are refused (they stay #297's contract),
    /// a row for another job is refused, and stored bytes that disagree with
    /// the sidecar fail closed instead of serving. Digest, length, ready
    /// receipt, and fence mismatches against the request are left for the
    /// core to record: the observation carries the row's truth, and
    /// [`verify_against`](ProcessStreamSourceReadbackObservation::verify_against)
    /// marks the slot.
    fn resolve(
        &self,
        request: &ProcessStreamSourceReadbackRequest,
    ) -> Result<ProcessStreamSourceReadbackObservation, TestdEvidenceError> {
        let stream = request.stream;
        request.validate()?;
        if request.locator_kind != DurableStreamLocatorKind::ImmutableArtifact {
            return Err(TestdEvidenceError::SourceUnavailable {
                stream,
                reason: "blob locators are served by the blob adapter, never by testd retention",
            });
        }
        let (sidecar, bytes) = match self.inner.store.load_stream_source(&request.locator) {
            Ok(Some(row)) => row,
            Ok(None) => {
                return Err(TestdEvidenceError::SourceUnavailable {
                    stream,
                    reason: "no source is retained under this locator",
                });
            }
            Err(error) => {
                return Err(TestdEvidenceError::SourceUnknownOutcome {
                    stream,
                    reason: match &error {
                        eliot_testd_core::TestdError::Corrupt(_) => {
                            "the retained row failed identity re-verification"
                        }
                        _ => "the retained source is unreachable",
                    },
                });
            }
        };
        if sidecar.job_id != request.job_id || request.binding.job_id().as_str() != request.job_id {
            return Err(TestdEvidenceError::SourceUnknownOutcome {
                stream,
                reason: "the retained source names another job",
            });
        }
        if sidecar.stream != stream {
            return Err(TestdEvidenceError::BindingMismatch {
                reason: "the retained source names another stream",
            });
        }
        if bytes.len() as u64 > request.max_bytes {
            return Err(TestdEvidenceError::SourceIntegrityBroken {
                stream,
                reason: "the retained source exceeds the admitted byte bound",
            });
        }
        Ok(ProcessStreamSourceReadbackObservation::new(
            bytes,
            sidecar.sha256.clone(),
            sidecar.byte_length,
            sidecar.locator_kind,
            sidecar.locator.clone(),
            sidecar.ready_receipt_ref.clone(),
            self.inner.fence.resource_generation.value(),
            sidecar.readback_receipt_id.clone(),
            sidecar.fence.clone(),
            serve_clock(),
            TestdStreamDisposition::CompleteSource,
        ))
    }
}

/// Serves the current wall clock as a readback observation timestamp.
fn serve_clock() -> ClockReading {
    let now = current_clock_ms().min(i64::MAX as u64) as i64;
    ClockReading {
        valid_time_ms: Some(now),
        known_time_ms: Some(now),
        transaction_sequence: None,
        monotonic_ns: None,
    }
}

fn current_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}
