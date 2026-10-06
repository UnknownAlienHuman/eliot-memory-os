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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "retention proofs panic on fixture construction failures by design"
)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use eliot_instrument_api::EvidenceAxes;
    use eliot_process::{ProcessEvidence, ProcessExecutionView, ProcessStreamPolicyBinding};
    use eliot_process_executor::{SinkAppendOutcome, StreamSinkPump};
    use eliot_testd_core::{
        EvidenceCollector, RetryPolicy, TestdReadbackContext, TestdStreamResolution,
    };
    use std::num::NonZeroU64;

    const JOB_ID: &str = "job-1";
    const INVOCATION_ID: &str = "invocation-1";

    fn test_epoch(sequence: u64) -> EpochId {
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
            .expect("canonical test lineage");
        EpochId::new(
            lineage,
            NonZeroU64::new(sequence).expect("non-zero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn test_fence() -> StateFence {
        StateFence::new(
            test_epoch(7),
            ResourceGeneration::new(1).expect("non-zero test generation"),
        )
    }

    fn test_binding() -> eliot_process::ProcessExecutionBinding {
        serde_json::from_value(serde_json::json!({
            "operation_id": "operation-1",
            "process_tree_id": "tree-1",
            "job_id": JOB_ID,
            "image_id": "image-1",
            "session_id": "session-1",
            "generation": 3,
            "action_lease_ref": "lease-1",
            "authority_id": "authority-1",
            "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 7},
            "state_fence": {
                "authority_epoch": {"lineage_id": "550e8400-e29b-41d4-a716-446655440000", "sequence": 7},
                "generation": 3,
                "nonce": "fence-1"
            },
            "request_digest": "a".repeat(64),
            "permit_digest": "b".repeat(64),
            "effect_digest": "c".repeat(64),
            "validation_revision": 2
        }))
        .expect("valid test binding")
    }

    fn test_policy() -> ProcessStreamPolicyBinding {
        ProcessStreamPolicyBinding::new(
            "p04:stream-policy:transport-preview-v1",
            "p04:privacy:raw-transport-preview",
            "p04:visibility:operation-diagnostic",
            "p04:retention:bounded-prefix-only",
            "p04:redaction:none-raw-preview",
        )
        .expect("valid test stream policy")
    }

    fn test_limits() -> eliot_process::ProcessStreamSinkLimits {
        eliot_process::ProcessStreamSinkLimits::new(
            8_192,
            1 << 20,
            1_024,
            4_096,
            8,
            65_536,
            2_000,
            2_000,
            2_000,
        )
        .expect("valid test sink limits")
    }

    fn test_store(label: &str) -> (std::path::PathBuf, TestdStore) {
        let dir = std::env::temp_dir().join(format!(
            "eliot-testd-retention-{label}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("retention test dir must create");
        let store = TestdStore::open(dir.join("testd-state.redb"), RetryPolicy::default())
            .expect("retention test store must open");
        (dir, store)
    }

    fn test_context() -> TestdReadbackContext {
        TestdReadbackContext {
            job_id: JOB_ID.to_owned(),
            invocation_id: INVOCATION_ID.to_owned(),
            fence: test_fence(),
            max_bytes: 1 << 20,
            deadline_ms: 5_000,
        }
    }

    fn test_view(binding: &eliot_process::ProcessExecutionBinding) -> ProcessExecutionView {
        serde_json::from_value(serde_json::json!({
            "binding": serde_json::to_value(binding).expect("binding serializes"),
            "lifecycle": "running",
            "health": {"status": "healthy", "ready": true, "observed_at_unix_ms": 10, "detail": null},
            "cancellation": "not_requested",
            "identity": null,
            "exit": null,
            "descendants": null
        }))
        .expect("valid test view")
    }

    fn pump(
        retention: &TestdStreamRetention,
        binding: eliot_process::ProcessExecutionBinding,
        stream: ProcessStreamKind,
    ) -> StreamSinkPump {
        StreamSinkPump::new(
            Arc::new(retention.clone()) as Arc<dyn ProcessStreamSinkClient>,
            binding,
            stream,
            test_policy(),
            test_limits(),
        )
    }

    fn resolved_bytes(resolution: TestdStreamResolution) -> Vec<u8> {
        match resolution {
            TestdStreamResolution::Resolved { bytes, .. } => bytes.bytes().to_vec(),
            TestdStreamResolution::Refused { error, .. } => {
                panic!("expected resolved source bytes, refused: {error:?}")
            }
        }
    }

    /// Issue #456 (WA11/WB1/I3): chunked stdout plus small stderr stream
    /// through a real pump into retained rows, then admit and resolve to
    /// byte-identical evidence with stable readback identities.
    #[test]
    fn retained_streams_round_trip_through_real_pump() {
        let (dir, store) = test_store("round-trip");
        let retention = TestdStreamRetention::new(Arc::new(store), test_fence());
        let binding = test_binding();

        let payload: Vec<u8> = (0..20_000_u32).map(|i| (i % 251) as u8).collect();
        let mut stdout_pump = pump(&retention, binding.clone(), ProcessStreamKind::Stdout);
        stdout_pump.open().expect("stdout session must open");
        for chunk in [
            &payload[..7_000],
            &payload[7_000..14_000],
            &payload[14_000..],
        ] {
            assert_eq!(
                stdout_pump.append(chunk).expect("chunk must admit"),
                SinkAppendOutcome::Admitted
            );
        }
        let stdout_terminal = stdout_pump.finalize_eof().expect("stdout must finalize");
        assert_eq!(
            stdout_terminal.state(),
            eliot_process::ProcessStreamSinkState::CompleteSource
        );
        let stdout_evidence = stdout_terminal.evidence().clone();
        let stdout_source = stdout_evidence
            .source()
            .expect("complete terminal must carry a durable source");
        assert!(
            stdout_source
                .locator()
                .starts_with("testd-retained:job-1:operation-1:stdout")
        );

        let stderr_bytes = b"stderr-line".to_vec();
        let mut stderr_pump = pump(&retention, binding.clone(), ProcessStreamKind::Stderr);
        stderr_pump.open().expect("stderr session must open");
        assert_eq!(
            stderr_pump
                .append(&stderr_bytes)
                .expect("stderr chunk must admit"),
            SinkAppendOutcome::Admitted
        );
        let stderr_terminal = stderr_pump.finalize_eof().expect("stderr must finalize");
        let stderr_evidence = stderr_terminal.evidence().clone();

        let record = ProcessEvidence::new_typed(
            test_view(&binding),
            Some(stdout_evidence),
            Some(stderr_evidence),
            EvidenceAxes::observed(),
        )
        .expect("pump terminal evidence must form a record");
        let collector = EvidenceCollector::default();
        eliot_process::ProcessEvidenceSink::record(&collector, record)
            .expect("terminal record must admit");
        let mut outcomes = collector
            .resolve_typed_sources(&retention, &test_context())
            .expect("resolution must run");
        assert_eq!(outcomes.len(), 1);
        let mut bundle_outcomes = outcomes.pop().expect("one bundle outcome");
        assert_eq!(bundle_outcomes.len(), 2);
        assert_eq!(
            resolved_bytes(bundle_outcomes.remove(0)),
            payload,
            "stdout must resolve to the exact pumped bytes"
        );
        assert_eq!(
            resolved_bytes(bundle_outcomes.remove(0)),
            stderr_bytes,
            "stderr must resolve to the exact pumped bytes"
        );
        let bundles = collector.typed_bundles();
        assert_eq!(bundles.len(), 1);
        assert_eq!(
            bundles[0].stdout.disposition,
            TestdStreamDisposition::CompleteSource
        );
        assert_eq!(
            bundles[0].stderr.disposition,
            TestdStreamDisposition::CompleteSource
        );
        assert!(
            bundles[0]
                .stdout
                .binding
                .as_ref()
                .expect("stdout binding")
                .gaps
                .is_empty()
        );
        let stdout_binding = bundles[0]
            .stdout
            .binding
            .as_ref()
            .expect("stdout slot must carry its binding");
        assert!(
            stdout_binding
                .readback_receipt_id
                .as_ref()
                .expect("resolved stdout must carry a readback receipt")
                .starts_with("testd-readback:")
        );
        assert!(
            stdout_binding
                .ready_receipt_ref
                .as_ref()
                .expect("resolved stdout must carry a ready receipt")
                .starts_with("testd-ready:")
        );
        drop(retention);
        std::fs::remove_dir_all(&dir).expect("retention test dir must clean");
    }

    /// Issue #456 (WB5): a zero-byte EOF finalizes to a real complete
    /// source, distinct from a stream that was never emitted or retained.
    #[test]
    fn zero_byte_eof_is_complete_and_missing_is_unavailable() {
        let (dir, store) = test_store("zero-byte");
        let retention = TestdStreamRetention::new(Arc::new(store), test_fence());
        let binding = test_binding();

        let mut stdout_pump = pump(&retention, binding.clone(), ProcessStreamKind::Stdout);
        stdout_pump.open().expect("stdout session must open");
        let terminal = stdout_pump.finalize_eof().expect("empty EOF must finalize");
        assert_eq!(
            terminal.state(),
            eliot_process::ProcessStreamSinkState::CompleteSource
        );
        assert_eq!(terminal.evidence().observed_bytes(), 0);

        let record = ProcessEvidence::new_typed(
            test_view(&binding),
            Some(terminal.evidence().clone()),
            None,
            EvidenceAxes::observed(),
        )
        .expect("zero-byte terminal evidence must form a record");
        let collector = EvidenceCollector::default();
        eliot_process::ProcessEvidenceSink::record(&collector, record)
            .expect("zero-byte record must admit");
        let mut outcomes = collector
            .resolve_typed_sources(&retention, &test_context())
            .expect("resolution must run");
        let mut bundle_outcomes = outcomes.pop().expect("one bundle outcome");
        assert_eq!(bundle_outcomes.len(), 2);
        let stdout_bytes = resolved_bytes(bundle_outcomes.remove(0));
        assert!(stdout_bytes.is_empty());
        match bundle_outcomes.remove(0) {
            TestdStreamResolution::Refused { .. } => {}
            TestdStreamResolution::Resolved { .. } => {
                panic!("a never-emitted stream must not resolve")
            }
        }
        let bundles = collector.typed_bundles();
        assert_eq!(
            bundles[0].stdout.disposition,
            TestdStreamDisposition::CompleteSource
        );
        assert_eq!(
            bundles[0].stderr.disposition,
            TestdStreamDisposition::StreamNotEmitted
        );

        // An unknown locator is unavailable, never an empty source.
        let mut foreign_context = test_context();
        foreign_context.job_id = "job-unknown".to_owned();
        let foreign = collector
            .resolve_typed_sources(&retention, &foreign_context)
            .expect("foreign resolution must run");
        assert!(
            foreign
                .iter()
                .flatten()
                .all(|outcome| matches!(outcome, TestdStreamResolution::Refused { .. }))
        );
        drop(retention);
        std::fs::remove_dir_all(&dir).expect("retention test dir must clean");
    }

    /// Issue #456 (WA11 boundary): Blob locator classes and foreign jobs are
    /// refused before any byte is served; the Blob adapter stays #297's.
    #[test]
    fn blob_locators_and_foreign_jobs_are_refused() {
        let (dir, store) = test_store("refusals");
        let retention = TestdStreamRetention::new(Arc::new(store), test_fence());
        let binding = test_binding();

        let payload = b"retained-bytes".to_vec();
        let mut pump = pump(&retention, binding.clone(), ProcessStreamKind::Stdout);
        pump.open().expect("session must open");
        pump.append(&payload).expect("chunk must admit");
        let terminal = pump.finalize_eof().expect("must finalize");
        let record = ProcessEvidence::new_typed(
            test_view(&binding),
            Some(terminal.evidence().clone()),
            None,
            EvidenceAxes::observed(),
        )
        .expect("terminal evidence must form a record");
        let collector = EvidenceCollector::default();
        eliot_process::ProcessEvidenceSink::record(&collector, record).expect("record must admit");
        let bundle = collector.typed_bundles().pop().expect("one bundle");
        let admitted = bundle.stdout.binding.as_ref().expect("stdout binding");
        let request = eliot_testd_core::ProcessStreamSourceReadbackRequest {
            job_id: JOB_ID.to_owned(),
            invocation_id: INVOCATION_ID.to_owned(),
            binding: binding.clone(),
            stream: ProcessStreamKind::Stdout,
            locator_kind: eliot_process::DurableStreamLocatorKind::Blob,
            locator: admitted.locator.clone().expect("admitted locator"),
            ready_receipt_ref: admitted
                .ready_receipt_ref
                .clone()
                .expect("admitted receipt"),
            expected_sha256: admitted.source_sha256.clone().expect("admitted digest"),
            expected_byte_length: admitted.source_byte_length.expect("admitted length"),
            policy: admitted.policy.clone(),
            fence: test_fence(),
            max_bytes: 1 << 20,
            deadline_ms: 5_000,
        };
        assert!(
            retention.resolve(&request).is_err(),
            "a Blob locator class must never resolve through testd retention"
        );

        let mut foreign_context = test_context();
        foreign_context.job_id = "job-foreign".to_owned();
        let foreign = collector
            .resolve_typed_sources(&retention, &foreign_context)
            .expect("foreign resolution must run");
        assert!(
            foreign
                .iter()
                .flatten()
                .all(|outcome| matches!(outcome, TestdStreamResolution::Refused { .. }))
        );
        drop(retention);
        std::fs::remove_dir_all(&dir).expect("retention test dir must clean");
    }

    /// A cancelled drain lands exactly one terminal with no durable source:
    /// nothing is retained, and admission stays explicitly unavailable.
    #[test]
    fn cancelled_drain_retains_no_source() {
        let (dir, store) = test_store("abort");
        let retention = TestdStreamRetention::new(Arc::new(store), test_fence());
        let binding = test_binding();

        let mut pump = pump(&retention, binding.clone(), ProcessStreamKind::Stdout);
        pump.open().expect("session must open");
        pump.append(b"partial-prefix")
            .expect("prefix chunk must admit");
        let terminal = pump.abort_cancelled().expect("cancel must settle");
        assert_eq!(
            terminal.state(),
            eliot_process::ProcessStreamSinkState::Cancelled
        );
        assert!(terminal.evidence().source().is_none());

        let record = ProcessEvidence::new_typed(
            test_view(&binding),
            Some(terminal.evidence().clone()),
            None,
            EvidenceAxes::observed(),
        )
        .expect("abort terminal evidence must form a record");
        let collector = EvidenceCollector::default();
        eliot_process::ProcessEvidenceSink::record(&collector, record)
            .expect("abort record must admit");
        let outcomes = collector
            .resolve_typed_sources(&retention, &test_context())
            .expect("resolution must run");
        assert!(
            outcomes
                .iter()
                .flatten()
                .all(|outcome| matches!(outcome, TestdStreamResolution::Refused { .. }))
        );
        let bundles = collector.typed_bundles();
        assert_eq!(
            bundles[0].stdout.disposition,
            TestdStreamDisposition::SourceUnavailable
        );
        drop(retention);
        std::fs::remove_dir_all(&dir).expect("retention test dir must clean");
    }

    /// Issue #456 (WD1/WD2): after the instance is dropped and the store is
    /// reopened, a fresh retention over the same file reopens the same
    /// identities and re-resolves byte-identical sources with no operation
    /// memory.
    #[test]
    fn restart_reopens_identical_evidence_without_operation_memory() {
        let (dir, store) = test_store("restart");
        let store_path = dir.join("testd-state.redb");
        let store_arc = Arc::new(store);
        let retention = TestdStreamRetention::new(Arc::clone(&store_arc), test_fence());
        let binding = test_binding();

        let payload = b"restart-proof-bytes".to_vec();
        let mut pump = pump(&retention, binding.clone(), ProcessStreamKind::Stdout);
        pump.open().expect("session must open");
        pump.append(&payload).expect("chunk must admit");
        let terminal = pump.finalize_eof().expect("must finalize");
        // The pump owns a client handle: release it so the store file can
        // be reopened below.
        drop(pump);
        let record = ProcessEvidence::new_typed(
            test_view(&binding),
            Some(terminal.evidence().clone()),
            None,
            EvidenceAxes::observed(),
        )
        .expect("terminal evidence must form a record");
        let collector = EvidenceCollector::default();
        eliot_process::ProcessEvidenceSink::record(&collector, record).expect("record must admit");
        collector
            .resolve_typed_sources(&retention, &test_context())
            .expect("resolution must run");
        let first_receipt = collector.typed_bundles()[0]
            .stdout
            .binding
            .as_ref()
            .expect("resolved binding")
            .readback_receipt_id
            .clone()
            .expect("readback receipt");
        let restart = collector
            .checkpoint_typed_evidence(JOB_ID, INVOCATION_ID, &test_fence())
            .expect("checkpoint must capture");
        // Persist, then drop every handle: the reopen below proves file
        // durability rather than memory aliasing.
        store_arc
            .persist_typed_evidence_restart(&restart)
            .expect("restart record must persist");
        drop(retention);
        drop(collector);
        drop(store_arc);

        let reopened_arc = Arc::new(
            TestdStore::open(&store_path, RetryPolicy::default()).expect("store must reopen"),
        );
        let reopened = TestdStreamRetention::new(Arc::clone(&reopened_arc), test_fence());
        let (bundles, mut outcomes) = reopened_arc
            .reopen_typed_evidence(JOB_ID, &reopened, 1 << 20, 5_000)
            .expect("reopen must succeed");
        assert_eq!(bundles.len(), 1);
        let receipt = bundles[0]
            .stdout
            .binding
            .as_ref()
            .expect("reopened binding")
            .readback_receipt_id
            .clone()
            .expect("reopened receipt");
        assert_eq!(receipt, first_receipt);
        let mut bundle_outcomes = outcomes.pop().expect("one bundle outcome");
        assert_eq!(resolved_bytes(bundle_outcomes.remove(0)), payload);
        drop(reopened);
        drop(reopened_arc);
        std::fs::remove_dir_all(&dir).expect("retention test dir must clean");
    }

    /// Issue #456 (WB6/I8): a legacy synthetic reference stays
    /// migration-required even after caller-supplied matching bytes arrive;
    /// it is never expanded and never satisfies verification.
    #[test]
    fn legacy_reference_never_upgrades_with_later_bytes() {
        let (dir, store) = test_store("legacy");
        let retention = TestdStreamRetention::new(Arc::new(store), test_fence());
        let binding = test_binding();

        let legacy = ProcessStreamEvidence::new_legacy_raw_reference(
            binding.clone(),
            ProcessStreamKind::Stderr,
            "raw:legacy-stderr",
        )
        .expect("valid legacy stderr evidence");
        let record = ProcessEvidence::new_typed(
            test_view(&binding),
            None,
            Some(legacy),
            EvidenceAxes::observed(),
        )
        .expect("legacy-bearing record must form");
        let collector = EvidenceCollector::default();
        eliot_process::ProcessEvidenceSink::record(&collector, record)
            .expect("legacy record must admit");
        let outcomes = collector
            .resolve_typed_sources(&retention, &test_context())
            .expect("resolution must run");
        assert!(
            outcomes
                .iter()
                .flatten()
                .all(|outcome| matches!(outcome, TestdStreamResolution::Refused { .. }))
        );
        // Later-supplied matching bytes change nothing on the typed path.
        collector
            .record_raw_artifact(
                "raw:legacy-stderr",
                "text/plain",
                b"legacy-bytes".to_vec(),
                false,
            )
            .expect("caller bytes record");
        let again = collector
            .resolve_typed_sources(&retention, &test_context())
            .expect("resolution must run");
        assert!(
            again
                .iter()
                .flatten()
                .all(|outcome| matches!(outcome, TestdStreamResolution::Refused { .. }))
        );
        let bundles = collector.typed_bundles();
        assert_eq!(
            bundles[0].stderr.disposition,
            TestdStreamDisposition::LegacyMigrationRequired
        );
        assert!(
            bundles[0]
                .stderr
                .binding
                .as_ref()
                .expect("legacy binding")
                .readback_receipt_id
                .is_none()
        );
        drop(retention);
        std::fs::remove_dir_all(&dir).expect("retention test dir must clean");
    }
}
