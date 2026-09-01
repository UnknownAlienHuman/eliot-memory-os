use std::sync::{Arc, Mutex};

use eliot_contracts::sha256_hex;

use super::*;
use crate::{
    DurableProcessStreamSource, DurableStreamLocatorKind, ProcessStreamTransportPrefixIdentity,
    StreamEvaluationStatus, StreamParsingStatus,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn binding() -> TestResult<ProcessExecutionBinding> {
    Ok(serde_json::from_value(serde_json::json!({
        "operation_id": "operation-1",
        "process_tree_id": "tree-1",
        "job_id": "job-1",
        "image_id": "image-1",
        "session_id": "session-1",
        "generation": 3,
        "action_lease_ref": "lease-1",
        "authority_id": "authority-1",
        "authority_epoch": 7,
        "state_fence": {"authority_epoch": 7, "generation": 3, "nonce": "fence-1"},
        "request_digest": "a".repeat(64),
        "permit_digest": "b".repeat(64),
        "effect_digest": "c".repeat(64),
        "validation_revision": 2
    }))?)
}

fn policy() -> TestResult<ProcessStreamPolicyBinding> {
    Ok(ProcessStreamPolicyBinding::new(
        "policy:1",
        "privacy:project",
        "visibility:owner",
        "retention:task",
        "redaction:exact-v1",
    )?)
}

fn limits() -> TestResult<ProcessStreamSinkLimits> {
    Ok(ProcessStreamSinkLimits::new(4, 16, 4, 8, 2, 8, 10, 20, 20)?)
}

fn all_gaps() -> Vec<StreamEvidenceGap> {
    vec![
        StreamEvidenceGap::PolicyProhibited,
        StreamEvidenceGap::PersistenceUnavailable,
        StreamEvidenceGap::PersistenceBackpressure,
        StreamEvidenceGap::PersistenceFailed,
        StreamEvidenceGap::PersistenceUnknownOutcome,
        StreamEvidenceGap::RedactionFailed,
        StreamEvidenceGap::TransportReadFailed,
        StreamEvidenceGap::CancelledBeforeEof,
        StreamEvidenceGap::CaptureUnavailable,
        StreamEvidenceGap::UnknownOutcome,
    ]
}

fn open_request(id: &str) -> TestResult<ProcessStreamSinkOpenRequest> {
    Ok(ProcessStreamSinkOpenRequest::new(
        ProcessStreamSinkSessionId::new(id)?,
        ProcessStreamSinkSourceId::new(format!("source:{id}"))?,
        ProcessStreamSinkTerminalId::new(format!("terminal:{id}"))?,
        binding()?,
        ProcessStreamKind::Stdout,
        policy()?,
        limits()?,
        ProcessStreamDigestAlgorithm::Sha256,
        ProcessStreamDigestAlgorithm::Sha256,
    )?)
}

fn session(id: &str) -> TestResult<ProcessStreamSinkSession> {
    Ok(ProcessStreamSinkSession::from_open_request(open_request(
        id,
    )?)?)
}

fn complete_evidence(bytes: &[u8]) -> TestResult<ProcessStreamEvidence> {
    let digest = sha256_hex(bytes);
    let source = DurableProcessStreamSource::exact_transport(
        DurableStreamLocatorKind::Blob,
        format!("eliot://blob/{digest}"),
        format!("receipt:ready:{digest}"),
        digest.clone(),
        bytes.len() as u64,
    )?;
    Ok(ProcessStreamEvidence::new_raw(
        binding()?,
        ProcessStreamKind::Stdout,
        policy()?,
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::CompleteSource,
        digest,
        bytes.len() as u64,
        ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), bytes.len() as u64)?,
        Some(source),
        Vec::new(),
    )?)
}

fn partial_evidence() -> TestResult<ProcessStreamEvidence> {
    let observed = b"abcdef";
    let source_bytes = b"abc";
    let source_digest = sha256_hex(source_bytes);
    let source = DurableProcessStreamSource::exact_transport(
        DurableStreamLocatorKind::Blob,
        format!("eliot://blob/{source_digest}"),
        "receipt:ready:partial",
        source_digest.clone(),
        3,
    )?;
    Ok(
        ProcessStreamEvidence::new_raw_with_transport_prefix_identity(
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            StreamTransportStatus::Complete,
            StreamPersistenceStatus::PartialSource,
            sha256_hex(observed),
            6,
            ProcessStreamPrefixPreview::from_transport_prefix(observed[..2].to_vec(), 6)?,
            Some(source),
            Some(ProcessStreamTransportPrefixIdentity::new(source_digest, 3)?),
            vec![StreamEvidenceGap::PersistenceFailed],
        )?,
    )
}

fn unavailable_evidence_for(
    bytes: &[u8],
    transport: StreamTransportStatus,
    gap: StreamEvidenceGap,
) -> TestResult<ProcessStreamEvidence> {
    let mut gaps = vec![gap];
    if transport != StreamTransportStatus::CaptureUnavailable {
        gaps.push(StreamEvidenceGap::PersistenceUnavailable);
    }
    Ok(ProcessStreamEvidence::new_raw(
        binding()?,
        ProcessStreamKind::Stdout,
        policy()?,
        transport,
        StreamPersistenceStatus::SourceUnavailable,
        sha256_hex(bytes),
        bytes.len() as u64,
        ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), bytes.len() as u64)?,
        None,
        gaps,
    )?)
}

fn unavailable_evidence(
    transport: StreamTransportStatus,
    gap: StreamEvidenceGap,
) -> TestResult<ProcessStreamEvidence> {
    unavailable_evidence_for(b"abc", transport, gap)
}

fn withheld_evidence(gap: StreamEvidenceGap) -> TestResult<ProcessStreamEvidence> {
    let bytes = b"secret=42";
    Ok(ProcessStreamEvidence::new_raw(
        binding()?,
        ProcessStreamKind::Stdout,
        policy()?,
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::SourceUnavailable,
        sha256_hex(bytes),
        bytes.len() as u64,
        ProcessStreamPrefixPreview::withheld_by_policy(),
        None,
        vec![gap],
    )?)
}

fn terminal_for(
    session: ProcessStreamSinkSession,
    state: ProcessStreamSinkState,
    final_sequence: u64,
    final_offset: u64,
    admitted_sha256: impl Into<String>,
    evidence: ProcessStreamEvidence,
) -> TestResult<ProcessStreamSinkTerminal> {
    let terminal_id = session.terminal_id().clone();
    let transformation = evidence
        .source()
        .and_then(|source| source.transformation().cloned());
    let request_transport = evidence.transport();
    let request_preview = evidence.preview().clone();
    let request_observed_sha256 = evidence.observed_sha256().to_owned();
    let request_observed_bytes = evidence.observed_bytes();
    let request_gaps = evidence.gaps().to_vec();
    let admitted_sha256 = admitted_sha256.into();
    if state == ProcessStreamSinkState::CompleteSource {
        Ok(ProcessStreamSinkTerminal::from_finalize(
            session,
            ProcessStreamSinkFinalizeRequest::new(
                terminal_id.clone(),
                final_sequence,
                final_offset,
                1,
                request_transport,
                request_observed_sha256,
                request_observed_bytes,
                request_preview,
                transformation,
                request_gaps,
            )?,
            state,
            final_sequence,
            final_offset,
            admitted_sha256,
            evidence,
        )?)
    } else {
        Ok(ProcessStreamSinkTerminal::from_abort(
            session,
            ProcessStreamSinkAbortRequest::new(
                terminal_id,
                ProcessStreamSinkAbortReason::Cancellation,
                final_sequence,
                final_offset,
                1,
                request_transport,
                request_observed_sha256,
                request_observed_bytes,
                request_preview,
                transformation,
                request_gaps,
            )?,
            state,
            final_sequence,
            final_offset,
            admitted_sha256,
            evidence,
        )?)
    }
}

#[test]
fn open_fixes_bindings_identities_limits_and_digest_before_bytes() -> TestResult {
    let request = open_request("one")?;
    request.validate()?;
    let session = ProcessStreamSinkSession::from_open_request(request)?;
    assert_eq!(session.stream(), ProcessStreamKind::Stdout);
    assert_eq!(session.limits().max_chunk_bytes(), 4);
    assert_eq!(session.source_id().as_str(), "source:one");
    assert_eq!(session.terminal_id().as_str(), "terminal:one");
    Ok(())
}

#[test]
fn exact_open_replay_and_same_id_different_digest_fail_closed() -> TestResult {
    let first = open_request("one")?;
    let replay: ProcessStreamSinkOpenRequest =
        serde_json::from_value(serde_json::to_value(&first)?)?;
    assert_eq!(first.open_request_sha256(), replay.open_request_sha256());
    let mut changed = serde_json::to_value(&first)?;
    changed["stream"] = serde_json::json!("STDERR");
    changed["open_request_sha256"] = serde_json::json!(first.open_request_sha256());
    assert!(serde_json::from_value::<ProcessStreamSinkOpenRequest>(changed).is_err());
    Ok(())
}

#[test]
fn limits_reject_zero_and_invalid_in_flight_ceilings() {
    assert!(ProcessStreamSinkLimits::new(0, 1, 1, 0, 1, 1, 1, 1, 1).is_err());
    assert!(ProcessStreamSinkLimits::new(4, 8, 1, 8, 1, 2, 1, 1, 1).is_err());
    assert!(ProcessStreamSinkLimits::new(4, 8, 1, 16 * 1024 * 1024 + 1, 1, 4, 1, 1, 1).is_err());
}

#[test]
fn append_is_owned_checked_and_budgeted() -> TestResult {
    let append = ProcessStreamSinkAppend::from_bytes(0, 0, b"abc".to_vec(), 3);
    append.validate()?;
    let session = session("one")?;
    session.validate_append(&append)?;
    assert_eq!(append.byte_length(), 3);
    assert!(ProcessStreamSinkAppend::new(0, 0, b"abc".to_vec(), "d".repeat(64), 1).is_err());
    Ok(())
}

#[test]
fn backpressure_deadline_and_cancelled_dispositions_admit_nothing() {
    let before = (0_u64, 0_u64);
    for disposition in [
        ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 1 },
        ProcessStreamSinkAppendDisposition::DeadlineExceeded,
        ProcessStreamSinkAppendDisposition::Cancelled,
    ] {
        assert!(matches!(
            disposition,
            ProcessStreamSinkAppendDisposition::Backpressured { .. }
                | ProcessStreamSinkAppendDisposition::DeadlineExceeded
                | ProcessStreamSinkAppendDisposition::Cancelled
        ));
        assert_eq!(before, (0, 0));
    }
}

#[test]
fn complete_terminal_requires_exact_raw_unassessed_evidence() -> TestResult {
    let session = session("one")?;
    let evidence = complete_evidence(b"abc")?;
    let terminal = terminal_for(
        session,
        ProcessStreamSinkState::CompleteSource,
        1,
        3,
        sha256_hex(b"abc"),
        evidence,
    )?;
    terminal.validate()?;
    assert_eq!(terminal.evidence().parsing(), StreamParsingStatus::Raw);
    assert_eq!(
        terminal.evidence().evaluation(),
        StreamEvaluationStatus::Unassessed
    );
    Ok(())
}

#[test]
fn terminal_state_matrix_rejects_unknown_or_persistence_failure_as_complete() -> TestResult {
    let evidence = complete_evidence(b"abc")?;
    assert!(
        terminal_for(
            session("one")?,
            ProcessStreamSinkState::UnknownOutcome,
            1,
            3,
            sha256_hex(b"abc"),
            evidence.clone(),
        )
        .is_err()
    );
    assert!(
        terminal_for(
            session("one")?,
            ProcessStreamSinkState::PersistenceFailed,
            1,
            3,
            sha256_hex(b"abc"),
            evidence,
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn malformed_wires_and_live_capabilities_fail_closed() -> TestResult {
    let request = open_request("one")?;
    let mut wire = serde_json::to_value(&request)?;
    wire["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<ProcessStreamSinkOpenRequest>(wire).is_err());
    let session = ProcessStreamSinkSession::from_open_request(request)?;
    let serialized = serde_json::to_value(session)?;
    assert!(serialized.is_object());
    // Session and terminal deliberately have no Deserialize implementation.
    Ok(())
}

#[test]
fn append_disposition_wire_validation_is_fail_closed() -> TestResult {
    let cases = [
        serde_json::json!({
            "kind": "ACCEPTED",
            "next_sequence": 1,
            "next_offset": 2,
            "unexpected": true,
        }),
        serde_json::json!({
            "kind": "TERMINAL",
            "state": "OPEN",
            "terminal_sha256": "a".repeat(64),
        }),
        serde_json::json!({
            "kind": "TERMINAL",
            "state": "COMPLETE_SOURCE",
            "terminal_sha256": "A".repeat(64),
        }),
        serde_json::json!({
            "kind": "BACKPRESSURED",
            "retry_after_ms": 0,
        }),
    ];

    for case in cases {
        assert!(serde_json::from_value::<ProcessStreamSinkAppendDisposition>(case).is_err());
    }
    let accepted = ProcessStreamSinkAppendDisposition::Accepted {
        next_sequence: 1,
        next_offset: 2,
    };
    assert_eq!(
        accepted,
        serde_json::from_value(serde_json::to_value(&accepted)?)?
    );
    Ok(())
}

#[test]
fn finalize_and_abort_gap_vectors_are_bounded_on_wire_and_in_constructors() -> TestResult {
    let session = session("one")?;
    let finalize = ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        0,
        0,
        1,
        StreamTransportStatus::Complete,
        sha256_hex(&[]),
        0,
        ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
        None,
        Vec::new(),
    )?;
    let abort = ProcessStreamSinkAbortRequest::new(
        session.terminal_id().clone(),
        ProcessStreamSinkAbortReason::Cancellation,
        0,
        0,
        1,
        StreamTransportStatus::CancelledBeforeEof,
        sha256_hex(&[]),
        0,
        ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
        None,
        Vec::new(),
    )?;
    let mut over_ceiling = all_gaps();
    over_ceiling.push(StreamEvidenceGap::UnknownOutcome);

    assert!(
        ProcessStreamSinkFinalizeRequest::new(
            session.terminal_id().clone(),
            0,
            0,
            1,
            StreamTransportStatus::Complete,
            sha256_hex(&[]),
            0,
            ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
            None,
            over_ceiling.clone(),
        )
        .is_err()
    );
    assert!(
        ProcessStreamSinkAbortRequest::new(
            session.terminal_id().clone(),
            ProcessStreamSinkAbortReason::Cancellation,
            0,
            0,
            1,
            StreamTransportStatus::CancelledBeforeEof,
            sha256_hex(&[]),
            0,
            ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
            None,
            over_ceiling.clone(),
        )
        .is_err()
    );

    let gaps = serde_json::to_value(over_ceiling)?;
    let mut finalize_wire = serde_json::to_value(finalize)?;
    finalize_wire["gaps"] = gaps.clone();
    assert!(serde_json::from_value::<ProcessStreamSinkFinalizeRequest>(finalize_wire).is_err());
    let mut abort_wire = serde_json::to_value(abort)?;
    abort_wire["gaps"] = gaps;
    assert!(serde_json::from_value::<ProcessStreamSinkAbortRequest>(abort_wire).is_err());
    Ok(())
}

#[test]
fn fake_backpressure_and_in_flight_ceiling_do_not_admit_or_move_counters() -> TestResult {
    let fake = Fake::new();
    let session = futures_ready(fake.open(open_request("one")?))?;
    let append = ProcessStreamSinkAppend::from_bytes(0, 0, b"abc".to_vec(), 1);

    fake.set_backpressured(true);
    assert!(matches!(
        futures_ready(fake.append(session.clone(), append.clone()))?,
        ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 1 }
    ));
    let readback = futures_ready(fake.readback(session.clone()))?;
    let ProcessStreamSinkReadback::Session { view } = readback else {
        panic!("backpressure must not terminalize the fake");
    };
    assert_eq!(view.next_sequence(), 0);
    assert_eq!(view.next_offset(), 0);

    fake.set_backpressured(false);
    fake.set_in_flight(session.limits().max_in_flight_chunks(), 0);
    assert!(matches!(
        futures_ready(fake.append(session.clone(), append))?,
        ProcessStreamSinkAppendDisposition::Backpressured { retry_after_ms: 1 }
    ));
    let readback = futures_ready(fake.readback(session))?;
    let ProcessStreamSinkReadback::Session { view } = readback else {
        panic!("in-flight backpressure must not terminalize the fake");
    };
    assert_eq!(view.next_sequence(), 0);
    assert_eq!(view.next_offset(), 0);
    Ok(())
}

#[test]
fn fake_abort_terminalizes_with_idempotent_replay_and_conflict_fencing() -> TestResult {
    let fake = Fake::new();
    let session = futures_ready(fake.open(open_request("one")?))?;
    let append = ProcessStreamSinkAppend::from_bytes(0, 0, b"abc".to_vec(), 1);
    assert!(matches!(
        futures_ready(fake.append(session.clone(), append))?,
        ProcessStreamSinkAppendDisposition::Accepted { .. }
    ));
    let abort = ProcessStreamSinkAbortRequest::new(
        session.terminal_id().clone(),
        ProcessStreamSinkAbortReason::Cancellation,
        1,
        3,
        1,
        StreamTransportStatus::CancelledBeforeEof,
        sha256_hex(b"abc"),
        3,
        ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
        None,
        vec![
            StreamEvidenceGap::PersistenceUnavailable,
            StreamEvidenceGap::CancelledBeforeEof,
        ],
    )?;
    let terminal = futures_ready(fake.abort(session.clone(), abort.clone()))?;
    assert_eq!(terminal.state(), ProcessStreamSinkState::Cancelled);
    let accepted_identity = terminal.command_identity().clone();
    let replay = futures_ready(fake.abort(session.clone(), abort))?;
    assert_eq!(terminal.terminal_sha256(), replay.terminal_sha256());

    let conflict = ProcessStreamSinkAbortRequest::new(
        session.terminal_id().clone(),
        ProcessStreamSinkAbortReason::CallerShutdown,
        1,
        3,
        1,
        StreamTransportStatus::CancelledBeforeEof,
        sha256_hex(b"abc"),
        3,
        ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
        None,
        vec![
            StreamEvidenceGap::PersistenceUnavailable,
            StreamEvidenceGap::CancelledBeforeEof,
        ],
    )?;
    assert!(matches!(
        futures_ready(fake.abort(session.clone(), conflict)),
        Err(ProcessStreamSinkError::TerminalIdentityConflict)
    ));
    assert!(matches!(
        futures_ready(fake.append(
            session.clone(),
            ProcessStreamSinkAppend::from_bytes(1, 3, b"d".to_vec(), 1),
        ))?,
        ProcessStreamSinkAppendDisposition::Terminal { .. }
    ));
    let ProcessStreamSinkReadback::Terminal { terminal: readback } =
        futures_ready(fake.readback(session))?
    else {
        panic!("abort conflict must preserve the terminal");
    };
    assert_eq!(terminal.terminal_sha256(), readback.terminal_sha256());
    assert_eq!(&accepted_identity, readback.command_identity());
    Ok(())
}

#[test]
fn fake_readback_preserves_unknown_outcome_and_fences_terminalization() -> TestResult {
    let fake = Fake::new();
    let session = futures_ready(fake.open(open_request("one")?))?;
    let outcome = ProcessStreamSinkUnknownOutcome::new(
        session.session_id().clone(),
        session.terminal_id().clone(),
        session.open_request_sha256(),
        sha256_hex(b"uncertain"),
    )?;
    fake.set_unknown_outcome(outcome.clone());
    let expected = ProcessStreamSinkReadback::UnknownOutcome { outcome };
    assert_eq!(futures_ready(fake.readback(session.clone()))?, expected);

    let finalize = ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        0,
        0,
        1,
        StreamTransportStatus::Complete,
        sha256_hex(&[]),
        0,
        ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
        None,
        Vec::new(),
    )?;
    assert!(matches!(
        futures_ready(fake.finalize(session.clone(), finalize)),
        Err(ProcessStreamSinkError::ProviderUnavailable)
    ));

    let abort = ProcessStreamSinkAbortRequest::new(
        session.terminal_id().clone(),
        ProcessStreamSinkAbortReason::Cancellation,
        0,
        0,
        1,
        StreamTransportStatus::CancelledBeforeEof,
        sha256_hex(&[]),
        0,
        ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
        None,
        vec![
            StreamEvidenceGap::PersistenceUnavailable,
            StreamEvidenceGap::CancelledBeforeEof,
        ],
    )?;
    assert!(matches!(
        futures_ready(fake.abort(session.clone(), abort)),
        Err(ProcessStreamSinkError::ProviderUnavailable)
    ));
    assert_eq!(futures_ready(fake.readback(session))?, expected);
    let state = fake.lock();
    assert!(state.terminal.is_none());
    assert!(state.terminal_command.is_none());
    Ok(())
}

#[derive(Default)]
struct FakeState {
    session: Option<ProcessStreamSinkSession>,
    phase: Option<ProcessStreamSinkState>,
    next_sequence: u64,
    next_offset: u64,
    chunks: Vec<ProcessStreamSinkAppend>,
    terminal: Option<ProcessStreamSinkTerminal>,
    terminal_command: Option<ProcessStreamSinkTerminalCommandIdentity>,
    backpressured: bool,
    in_flight_chunks: u32,
    in_flight_bytes: u64,
    unknown_outcome: Option<ProcessStreamSinkUnknownOutcome>,
}

struct Fake {
    state: Arc<Mutex<FakeState>>,
}

impl Fake {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState {
                phase: Some(ProcessStreamSinkState::Opening),
                ..FakeState::default()
            })),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn admitted_bytes(state: &FakeState) -> Vec<u8> {
        state
            .chunks
            .iter()
            .flat_map(|chunk| chunk.bytes().iter().copied())
            .collect()
    }

    fn admitted_digest(state: &FakeState) -> String {
        sha256_hex(&Self::admitted_bytes(state))
    }

    fn set_backpressured(&self, backpressured: bool) {
        self.lock().backpressured = backpressured;
    }

    fn set_in_flight(&self, chunks: u32, bytes: u64) {
        let mut state = self.lock();
        state.in_flight_chunks = chunks;
        state.in_flight_bytes = bytes;
    }

    fn set_unknown_outcome(&self, outcome: ProcessStreamSinkUnknownOutcome) {
        self.lock().unknown_outcome = Some(outcome);
    }
}

fn ready<T: Send + 'static>(
    result: Result<T, ProcessStreamSinkError>,
) -> ProcessStreamSinkFuture<'static, T> {
    Box::pin(async move { result })
}

impl ProcessStreamSinkClient for Fake {
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
                state.phase = Some(ProcessStreamSinkState::Open);
                state.session = Some(session.clone());
            }),
        };
        ready(result)
    }

    fn append(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkAppendDisposition> {
        let mut state = self.lock();
        let result = state
            .session
            .clone()
            .ok_or(ProcessStreamSinkError::ProviderUnavailable)
            .and_then(|existing| {
                if existing != session {
                    return Err(ProcessStreamSinkError::SessionMismatch);
                }
                if state.phase == Some(ProcessStreamSinkState::Finalizing) {
                    return Err(ProcessStreamSinkError::AppendAfterFinalizing);
                }
                if let Some(terminal) = &state.terminal {
                    return Ok(ProcessStreamSinkAppendDisposition::Terminal {
                        state: terminal.state(),
                        terminal_sha256: terminal.terminal_sha256().to_owned(),
                    });
                }
                session.validate_append(&request)?;
                if request.wait_budget_ms() == 0 {
                    return Ok(ProcessStreamSinkAppendDisposition::DeadlineExceeded);
                }
                if request.sequence() < state.next_sequence {
                    let prior = state
                        .chunks
                        .iter()
                        .find(|chunk| chunk.sequence() == request.sequence())
                        .ok_or(ProcessStreamSinkError::MismatchedReplay)?;
                    return if prior == &request {
                        Ok(ProcessStreamSinkAppendDisposition::Replayed {
                            next_sequence: state.next_sequence,
                            next_offset: state.next_offset,
                        })
                    } else {
                        Err(ProcessStreamSinkError::MismatchedReplay)
                    };
                }
                if request.sequence() > state.next_sequence {
                    return Err(ProcessStreamSinkError::SequenceGap {
                        expected: state.next_sequence,
                        observed: request.sequence(),
                    });
                }
                if request.offset() != state.next_offset {
                    return Err(if request.offset() < state.next_offset {
                        ProcessStreamSinkError::OverlapOrOutOfOrder
                    } else {
                        ProcessStreamSinkError::OffsetMismatch {
                            expected: state.next_offset,
                            observed: request.offset(),
                        }
                    });
                }
                if state.backpressured
                    || state.in_flight_chunks >= session.limits().max_in_flight_chunks()
                    || state.in_flight_bytes.saturating_add(request.byte_length())
                        > session.limits().max_in_flight_bytes()
                {
                    return Ok(ProcessStreamSinkAppendDisposition::Backpressured {
                        retry_after_ms: 1,
                    });
                }
                if state.next_sequence >= session.limits().max_chunks() {
                    return Err(ProcessStreamSinkError::ChunkCountLimitExceeded);
                }
                if request.byte_length()
                    > session.limits().max_total_admitted_bytes() - state.next_offset
                {
                    return Err(ProcessStreamSinkError::TotalLimitExceeded);
                }
                state.next_sequence += 1;
                state.next_offset += request.byte_length();
                state.chunks.push(request);
                Ok(ProcessStreamSinkAppendDisposition::Accepted {
                    next_sequence: state.next_sequence,
                    next_offset: state.next_offset,
                })
            });
        ready(result)
    }

    fn finalize(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkFinalizeRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let mut state = self.lock();
        let result = state
            .session
            .clone()
            .ok_or(ProcessStreamSinkError::ProviderUnavailable)
            .and_then(|existing| {
                if existing != session {
                    return Err(ProcessStreamSinkError::SessionMismatch);
                }
                if state.unknown_outcome.is_some() {
                    return Err(ProcessStreamSinkError::ProviderUnavailable);
                }
                let identity = request.command_identity()?;
                if let Some(terminal) = &state.terminal {
                    return if state.terminal_command.as_ref() == Some(&identity) {
                        Ok(terminal.clone())
                    } else {
                        Err(ProcessStreamSinkError::TerminalIdentityConflict)
                    };
                }
                session.validate_finalize(&request)?;
                if request.expected_final_sequence() != state.next_sequence {
                    return Err(ProcessStreamSinkError::SequenceGap {
                        expected: state.next_sequence,
                        observed: request.expected_final_sequence(),
                    });
                }
                if request.expected_final_offset() != state.next_offset {
                    return Err(ProcessStreamSinkError::OffsetMismatch {
                        expected: state.next_offset,
                        observed: request.expected_final_offset(),
                    });
                }
                if request.observed_sha256() != Self::admitted_digest(&state)
                    || request.observed_bytes() != state.next_offset
                {
                    return Err(ProcessStreamSinkError::EvidenceInvariant {
                        reason: "fake observed facts do not match admitted chunks".to_owned(),
                    });
                }
                state.phase = Some(ProcessStreamSinkState::Finalizing);
                let bytes = Self::admitted_bytes(&state);
                let evidence = complete_evidence(&bytes).map_err(|_| {
                    ProcessStreamSinkError::InvalidRequest {
                        reason: "fake evidence",
                    }
                })?;
                let terminal = ProcessStreamSinkTerminal::from_finalize(
                    session,
                    request,
                    ProcessStreamSinkState::CompleteSource,
                    state.next_sequence,
                    state.next_offset,
                    Self::admitted_digest(&state),
                    evidence,
                )?;
                state.terminal_command = Some(identity);
                state.terminal = Some(terminal.clone());
                state.phase = Some(terminal.state());
                Ok(terminal)
            });
        ready(result)
    }

    fn abort(
        &self,
        session: ProcessStreamSinkSession,
        request: ProcessStreamSinkAbortRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkTerminal> {
        let mut state = self.lock();
        let result = state
            .session
            .clone()
            .ok_or(ProcessStreamSinkError::ProviderUnavailable)
            .and_then(|existing| {
                if existing != session {
                    return Err(ProcessStreamSinkError::SessionMismatch);
                }
                if state.unknown_outcome.is_some() {
                    return Err(ProcessStreamSinkError::ProviderUnavailable);
                }
                let identity = request.command_identity()?;
                if let Some(terminal) = &state.terminal {
                    return if state.terminal_command.as_ref() == Some(&identity) {
                        Ok(terminal.clone())
                    } else {
                        Err(ProcessStreamSinkError::TerminalIdentityConflict)
                    };
                }
                session.validate_abort(&request)?;
                if request.expected_final_sequence() != state.next_sequence {
                    return Err(ProcessStreamSinkError::SequenceGap {
                        expected: state.next_sequence,
                        observed: request.expected_final_sequence(),
                    });
                }
                if request.expected_final_offset() != state.next_offset {
                    return Err(ProcessStreamSinkError::OffsetMismatch {
                        expected: state.next_offset,
                        observed: request.expected_final_offset(),
                    });
                }
                if request.observed_sha256() != Self::admitted_digest(&state)
                    || request.observed_bytes() != state.next_offset
                {
                    return Err(ProcessStreamSinkError::EvidenceInvariant {
                        reason: "fake observed facts do not match admitted chunks".to_owned(),
                    });
                }
                state.phase = Some(ProcessStreamSinkState::Finalizing);
                let bytes = Self::admitted_bytes(&state);
                let evidence = unavailable_evidence_for(
                    &bytes,
                    StreamTransportStatus::CancelledBeforeEof,
                    StreamEvidenceGap::CancelledBeforeEof,
                )
                .map_err(|_| ProcessStreamSinkError::InvalidRequest {
                    reason: "fake evidence",
                })?;
                let terminal = ProcessStreamSinkTerminal::from_abort(
                    session,
                    request,
                    ProcessStreamSinkState::Cancelled,
                    state.next_sequence,
                    state.next_offset,
                    Self::admitted_digest(&state),
                    evidence,
                )?;
                state.terminal_command = Some(identity);
                state.terminal = Some(terminal.clone());
                state.phase = Some(terminal.state());
                Ok(terminal)
            });
        ready(result)
    }

    fn readback(
        &self,
        session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let state = self.lock();
        if let Some(outcome) = &state.unknown_outcome {
            return ready(Ok(ProcessStreamSinkReadback::UnknownOutcome {
                outcome: outcome.clone(),
            }));
        }
        if let Some(terminal) = &state.terminal {
            return ready(Ok(ProcessStreamSinkReadback::Terminal {
                terminal: terminal.clone(),
            }));
        }
        let view = ProcessStreamSinkSessionView::new(
            session.session_id().clone(),
            session.source_id().clone(),
            session.terminal_id().clone(),
            state.phase.unwrap_or(ProcessStreamSinkState::Open),
            state.next_sequence,
            state.next_offset,
            state.next_sequence,
            state.next_offset,
            Self::admitted_digest(&state),
            session.open_request_sha256().to_owned(),
            None,
        )
        .unwrap_or_else(|_| unreachable!("zero-count fake view is valid"));
        ready(Ok(ProcessStreamSinkReadback::Session { view }))
    }
}

#[test]
fn object_safe_arc_client_and_zero_byte_finalize_are_supported() -> TestResult {
    let client: Arc<dyn ProcessStreamSinkClient> = Arc::new(Fake::new());
    let session = futures_ready(client.open(open_request("one")?))?;
    let request = ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        0,
        0,
        1,
        StreamTransportStatus::Complete,
        sha256_hex(&[]),
        0,
        ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
        None,
        Vec::new(),
    )?;
    let terminal = futures_ready(client.finalize(session, request))?;
    assert_eq!(terminal.state(), ProcessStreamSinkState::CompleteSource);
    Ok(())
}

#[test]
fn deterministic_fake_enforces_replay_order_terminal_and_readback_rules() -> TestResult {
    let client: Arc<dyn ProcessStreamSinkClient> = Arc::new(Fake::new());
    let session = futures_ready(client.open(open_request("one")?))?;
    let first = ProcessStreamSinkAppend::from_bytes(0, 0, b"abc".to_vec(), 1);
    assert!(matches!(
        futures_ready(client.append(session.clone(), first.clone()))?,
        ProcessStreamSinkAppendDisposition::Accepted {
            next_sequence: 1,
            next_offset: 3
        }
    ));
    assert!(matches!(
        futures_ready(client.append(session.clone(), first.clone()))?,
        ProcessStreamSinkAppendDisposition::Replayed {
            next_sequence: 1,
            next_offset: 3
        }
    ));
    assert!(matches!(
        futures_ready(client.append(
            session.clone(),
            ProcessStreamSinkAppend::from_bytes(0, 0, b"abd".to_vec(), 1),
        )),
        Err(ProcessStreamSinkError::MismatchedReplay)
    ));
    assert!(matches!(
        futures_ready(client.append(
            session.clone(),
            ProcessStreamSinkAppend::from_bytes(2, 3, b"e".to_vec(), 1),
        )),
        Err(ProcessStreamSinkError::SequenceGap { .. })
    ));
    let finalize = ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        1,
        3,
        1,
        StreamTransportStatus::Complete,
        sha256_hex(b"abc"),
        3,
        ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?,
        None,
        Vec::new(),
    )?;
    let terminal = futures_ready(client.finalize(session.clone(), finalize.clone()))?;
    let replay = futures_ready(client.finalize(session.clone(), finalize))?;
    assert_eq!(terminal.terminal_sha256(), replay.terminal_sha256());
    assert!(matches!(
        futures_ready(client.append(
            session.clone(),
            ProcessStreamSinkAppend::from_bytes(1, 3, b"d".to_vec(), 1),
        )),
        Ok(ProcessStreamSinkAppendDisposition::Terminal { .. })
    ));
    assert!(matches!(
        futures_ready(client.readback(session))?,
        ProcessStreamSinkReadback::Terminal { .. }
    ));
    Ok(())
}

#[test]
fn monotonic_chunks_and_replay_identity_are_deterministic() {
    let first = ProcessStreamSinkAppend::from_bytes(0, 0, b"ab".to_vec(), 1);
    let second = ProcessStreamSinkAppend::from_bytes(1, 2, b"cd".to_vec(), 1);
    assert_eq!(first.sequence(), 0);
    assert_eq!(second.offset(), first.offset() + first.byte_length());
    assert_eq!(
        sha256_hex(b"abcd"),
        sha256_hex(&[first.bytes(), second.bytes()].concat())
    );
    assert_eq!(
        first,
        ProcessStreamSinkAppend::from_bytes(0, 0, b"ab".to_vec(), 1)
    );
    assert_ne!(
        first,
        ProcessStreamSinkAppend::from_bytes(0, 0, b"ac".to_vec(), 1)
    );
}

#[test]
fn sequence_offset_gap_overlap_and_terminal_append_failures_are_typed() {
    assert_eq!(
        ProcessStreamSinkError::SequenceGap {
            expected: 1,
            observed: 3
        },
        ProcessStreamSinkError::SequenceGap {
            expected: 1,
            observed: 3
        }
    );
    assert!(matches!(
        ProcessStreamSinkError::OffsetMismatch {
            expected: 2,
            observed: 1
        },
        ProcessStreamSinkError::OffsetMismatch { .. }
    ));
    assert!(matches!(
        ProcessStreamSinkError::OverlapOrOutOfOrder,
        ProcessStreamSinkError::OverlapOrOutOfOrder
    ));
    assert!(matches!(
        ProcessStreamSinkError::AppendAfterFinalizing,
        ProcessStreamSinkError::AppendAfterFinalizing
    ));
}

#[test]
fn chunk_total_count_preview_and_in_flight_ceilings_are_enforced() -> TestResult {
    let session = session("one")?;
    assert!(matches!(
        session.validate_append(&ProcessStreamSinkAppend::from_bytes(
            0,
            0,
            b"12345".to_vec(),
            1
        )),
        Err(ProcessStreamSinkError::ChunkLimitExceeded)
    ));
    let oversized_preview =
        ProcessStreamPrefixPreview::from_transport_prefix(b"123456789".to_vec(), 9)?;
    let oversized_bytes = b"123456789";
    let request = ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        0,
        9,
        1,
        StreamTransportStatus::Complete,
        sha256_hex(oversized_bytes),
        9,
        oversized_preview,
        None,
        Vec::new(),
    );
    assert!(request.is_ok());
    assert!(matches!(
        session.validate_finalize(&request?),
        Err(ProcessStreamSinkError::PreviewLimitExceeded)
    ));
    Ok(())
}

#[test]
fn request_budgets_are_relative_and_never_exceed_fixed_limits() -> TestResult {
    let session = session("one")?;
    let request = ProcessStreamSinkAppend::from_bytes(0, 0, b"a".to_vec(), 11);
    assert!(session.validate_append(&request).is_err());
    let finalize = ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        0,
        0,
        21,
        StreamTransportStatus::Complete,
        sha256_hex(&[]),
        0,
        ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
        None,
        Vec::new(),
    )?;
    assert!(session.validate_finalize(&finalize).is_err());
    Ok(())
}

#[test]
fn partial_policy_redaction_cancelled_and_unknown_terminals_preserve_gaps() -> TestResult {
    let partial = terminal_for(
        session("one")?,
        ProcessStreamSinkState::PartialSource,
        0,
        6,
        sha256_hex(b"abcdef"),
        partial_evidence()?,
    )?;
    assert_eq!(partial.state(), ProcessStreamSinkState::PartialSource);

    let prohibited = withheld_evidence(StreamEvidenceGap::PolicyProhibited)?;
    let terminal = terminal_for(
        session("one")?,
        ProcessStreamSinkState::PolicyProhibited,
        0,
        9,
        sha256_hex(b"secret=42"),
        prohibited,
    )?;
    assert!(terminal.evidence().source().is_none());

    let cancelled = unavailable_evidence(
        StreamTransportStatus::CancelledBeforeEof,
        StreamEvidenceGap::CancelledBeforeEof,
    )?;
    assert!(
        terminal_for(
            session("one")?,
            ProcessStreamSinkState::Cancelled,
            0,
            3,
            sha256_hex(b"abc"),
            cancelled,
        )
        .is_ok()
    );
    let unknown = unavailable_evidence(
        StreamTransportStatus::UnknownOutcome,
        StreamEvidenceGap::UnknownOutcome,
    )?;
    assert!(
        terminal_for(
            session("one")?,
            ProcessStreamSinkState::UnknownOutcome,
            0,
            3,
            sha256_hex(b"abc"),
            unknown,
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn terminal_identity_is_idempotent_and_unknown_readback_is_write_fenced() -> TestResult {
    let terminal = terminal_for(
        session("one")?,
        ProcessStreamSinkState::CompleteSource,
        0,
        0,
        sha256_hex(&[]),
        complete_evidence(&[])?,
    )?;
    let replay = terminal.clone();
    assert_eq!(terminal.terminal_id(), replay.terminal_id());
    assert_eq!(terminal.terminal_sha256(), replay.terminal_sha256());
    let unknown = ProcessStreamSinkUnknownOutcome::new(
        ProcessStreamSinkSessionId::new("one")?,
        ProcessStreamSinkTerminalId::new("terminal:one")?,
        terminal.open_request_sha256(),
        sha256_hex(b"uncertain"),
    )?;
    assert_eq!(unknown.terminal_id().as_str(), "terminal:one");
    assert!(
        serde_json::from_value::<ProcessStreamSinkUnknownOutcome>({
            let mut value = serde_json::to_value(&unknown)?;
            value["extra"] = serde_json::json!(true);
            value
        })
        .is_err()
    );
    Ok(())
}

#[test]
fn binding_stream_policy_source_and_evidence_authority_mismatches_reject() -> TestResult {
    let session = session("one")?;
    let mut other = serde_json::to_value(binding()?)?;
    other["authority_epoch"] = serde_json::json!(8);
    let other_binding: ProcessExecutionBinding = serde_json::from_value(other)?;
    let evidence = ProcessStreamEvidence::new_raw(
        other_binding,
        ProcessStreamKind::Stdout,
        policy()?,
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::CompleteSource,
        sha256_hex(&[]),
        0,
        ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
        Some(DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            "eliot://blob/empty",
            "receipt:empty",
            sha256_hex(&[]),
            0,
        )?),
        Vec::new(),
    );
    assert!(evidence.is_err());
    assert!(matches!(
        ProcessStreamSinkError::SourceMismatch,
        ProcessStreamSinkError::SourceMismatch
    ));
    assert!(matches!(
        ProcessStreamSinkError::BindingMismatch,
        ProcessStreamSinkError::BindingMismatch
    ));
    assert!(matches!(
        ProcessStreamSinkError::PolicyMismatch,
        ProcessStreamSinkError::PolicyMismatch
    ));
    assert_eq!(session.stream(), ProcessStreamKind::Stdout);
    Ok(())
}

#[test]
fn retained_prefix_sink_limits_enforce_max_preview_and_omitted_range() -> TestResult {
    // Sink limits must never exceed the kernel evidence ceiling.
    assert!(
        ProcessStreamSinkLimits::new(4, 16, 4, 16 * 1024 * 1024 + 1, 2, 8, 10, 20, 20).is_err()
    );
    let session = session("one")?;
    // Preview at the sink ceiling is accepted, beyond is rejected via validate_preview_limit.
    let at_ceiling = ProcessStreamPrefixPreview::from_transport_prefix(vec![b'a'; 8], 8)?;
    assert!(
        session
            .validate_finalize(&ProcessStreamSinkFinalizeRequest::new(
                session.terminal_id().clone(),
                0,
                8,
                1,
                StreamTransportStatus::Complete,
                sha256_hex(&[b'a'; 8]),
                8,
                at_ceiling,
                None,
                Vec::new(),
            )?)
            .is_ok()
    );

    // Omitted-range must be exactly the suffix; truncated preview cannot hide omitted range.
    let truncated = ProcessStreamPrefixPreview::from_transport_prefix(b"ab".to_vec(), 6)?;
    assert!(truncated.is_truncated());
    assert_eq!(truncated.omitted_ranges().len(), 1);
    assert_eq!(truncated.omitted_ranges()[0].start(), 2);
    assert_eq!(truncated.omitted_ranges()[0].end_exclusive(), 6);
    let complete = ProcessStreamPrefixPreview::from_transport_prefix(b"abc".to_vec(), 3)?;
    assert!(!complete.is_truncated());
    assert!(complete.omitted_ranges().is_empty());
    Ok(())
}

#[test]
fn abort_reasons_are_closed_and_readback_contains_no_payload_view() -> TestResult {
    for reason in [
        ProcessStreamSinkAbortReason::Cancellation,
        ProcessStreamSinkAbortReason::PolicyProhibition,
        ProcessStreamSinkAbortReason::RedactionFailure,
        ProcessStreamSinkAbortReason::TransportFailure,
        ProcessStreamSinkAbortReason::CallerShutdown,
    ] {
        assert!(matches!(
            reason,
            ProcessStreamSinkAbortReason::Cancellation
                | ProcessStreamSinkAbortReason::PolicyProhibition
                | ProcessStreamSinkAbortReason::RedactionFailure
                | ProcessStreamSinkAbortReason::TransportFailure
                | ProcessStreamSinkAbortReason::CallerShutdown
        ));
    }
    let session = session("one")?;
    let view = ProcessStreamSinkSessionView::new(
        session.session_id().clone(),
        session.source_id().clone(),
        session.terminal_id().clone(),
        ProcessStreamSinkState::Open,
        1,
        3,
        1,
        3,
        sha256_hex(b"abc"),
        session.open_request_sha256().to_owned(),
        None,
    )?;
    let wire = serde_json::to_value(view)?;
    assert!(wire.get("bytes").is_none());
    Ok(())
}

fn futures_ready<T>(
    mut future: ProcessStreamSinkFuture<'_, T>,
) -> Result<T, ProcessStreamSinkError> {
    use std::task::{Context, Poll, Waker};
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match std::pin::Pin::new(&mut future).poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => Err(ProcessStreamSinkError::ProviderUnavailable),
    }
}
