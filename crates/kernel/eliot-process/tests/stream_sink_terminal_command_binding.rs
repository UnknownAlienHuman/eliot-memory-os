use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use eliot_contracts::sha256_hex;
use eliot_process::{
    DurableProcessStreamSource, DurableStreamLocatorKind, ProcessExecutionBinding,
    ProcessStreamEvidence, ProcessStreamKind, ProcessStreamPolicyBinding,
    ProcessStreamPrefixPreview, ProcessStreamSinkAbortReason, ProcessStreamSinkAbortRequest,
    ProcessStreamSinkAppend, ProcessStreamSinkAppendDisposition, ProcessStreamSinkClient,
    ProcessStreamSinkError, ProcessStreamSinkFinalizeRequest, ProcessStreamSinkFuture,
    ProcessStreamSinkLimits, ProcessStreamSinkOpenRequest, ProcessStreamSinkReadback,
    ProcessStreamSinkSession, ProcessStreamSinkSessionId, ProcessStreamSinkSourceId,
    ProcessStreamSinkState, ProcessStreamSinkTerminal, ProcessStreamSinkTerminalCommandIdentity,
    ProcessStreamSinkTerminalCommandKind, ProcessStreamSinkTerminalId,
    ProcessStreamSinkUnknownOutcome, StreamEvidenceGap, StreamPersistenceStatus,
    StreamTransportStatus,
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

fn open_request(id: &str) -> TestResult<ProcessStreamSinkOpenRequest> {
    Ok(ProcessStreamSinkOpenRequest::new(
        ProcessStreamSinkSessionId::new(id)?,
        ProcessStreamSinkSourceId::new(format!("source:{id}"))?,
        ProcessStreamSinkTerminalId::new(format!("terminal:{id}"))?,
        binding()?,
        ProcessStreamKind::Stdout,
        policy()?,
        limits()?,
        eliot_process::ProcessStreamDigestAlgorithm::Sha256,
        eliot_process::ProcessStreamDigestAlgorithm::Sha256,
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

fn finalize_request(
    session: &ProcessStreamSinkSession,
) -> TestResult<ProcessStreamSinkFinalizeRequest> {
    Ok(ProcessStreamSinkFinalizeRequest::new(
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
    )?)
}

fn abort_request(
    session: &ProcessStreamSinkSession,
    reason: ProcessStreamSinkAbortReason,
) -> TestResult<ProcessStreamSinkAbortRequest> {
    Ok(ProcessStreamSinkAbortRequest::new(
        session.terminal_id().clone(),
        reason,
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
    )?)
}

fn zero_finalize_request(
    session: &ProcessStreamSinkSession,
) -> TestResult<ProcessStreamSinkFinalizeRequest> {
    Ok(ProcessStreamSinkFinalizeRequest::new(
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
    )?)
}

fn empty_terminal(
    session: ProcessStreamSinkSession,
    request: ProcessStreamSinkFinalizeRequest,
) -> TestResult<ProcessStreamSinkTerminal> {
    Ok(ProcessStreamSinkTerminal::from_finalize(
        session,
        request,
        ProcessStreamSinkState::CompleteSource,
        0,
        0,
        sha256_hex(&[]),
        complete_evidence(&[])?,
    )?)
}

fn poll_ready<T>(mut future: ProcessStreamSinkFuture<'_, T>) -> Result<T, ProcessStreamSinkError> {
    let waker = Waker::noop();
    let mut context = Context::from_waker(waker);
    match std::pin::Pin::new(&mut future).poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => Err(ProcessStreamSinkError::ProviderUnavailable),
    }
}

#[test]
fn identical_finalize_request_has_identical_identity_and_terminal_digest() -> TestResult {
    let session = session("same")?;
    let request = zero_finalize_request(&session)?;
    let replay_request: ProcessStreamSinkFinalizeRequest =
        serde_json::from_value(serde_json::to_value(&request)?)?;
    assert_eq!(
        request.command_identity()?,
        replay_request.command_identity()?
    );
    let first = empty_terminal(session.clone(), request.clone())?;
    let replay = empty_terminal(session, replay_request)?;
    assert_eq!(first.command_identity(), replay.command_identity());
    assert_eq!(first.terminal_sha256(), replay.terminal_sha256());
    Ok(())
}

#[test]
fn every_finalize_field_family_changes_identity() -> TestResult {
    let session = session("fields")?;
    let request = finalize_request(&session)?;
    let original = request.command_identity()?;
    let mut cases = Vec::new();
    let wire = serde_json::to_value(&request)?;

    let mut changed = wire.clone();
    changed["terminal_id"] = serde_json::json!("terminal:other");
    cases.push(changed);
    for (field, value) in [
        ("expected_final_sequence", serde_json::json!(2)),
        ("expected_final_offset", serde_json::json!(4)),
        ("wait_budget_ms", serde_json::json!(2)),
        ("transport", serde_json::json!("READ_FAILED")),
        ("observed_sha256", serde_json::json!(sha256_hex(b"abd"))),
        ("observed_bytes", serde_json::json!(2)),
        (
            "preview",
            serde_json::to_value(ProcessStreamPrefixPreview::from_transport_prefix(
                b"ab".to_vec(),
                3,
            )?)?,
        ),
        (
            "transformation",
            serde_json::json!({
                "receipt_ref": "receipt:transform",
                "input_sha256": sha256_hex(b"abc"),
                "input_byte_length": 3,
                "output_sha256": sha256_hex(b"ab"),
                "output_byte_length": 2,
                "policy_ref": "policy:1",
                "redaction_ref": "redaction:exact-v1"
            }),
        ),
        ("gaps", serde_json::json!(["TRANSPORT_READ_FAILED"])),
    ] {
        changed = wire.clone();
        changed[field] = value;
        cases.push(changed);
    }
    for candidate in cases {
        assert!(
            match serde_json::from_value::<ProcessStreamSinkFinalizeRequest>(candidate) {
                Ok(candidate) => original != candidate.command_identity()?,
                Err(_) => true,
            }
        );
    }
    Ok(())
}

#[test]
fn finalize_and_abort_kinds_are_distinct() -> TestResult {
    let session = session("kinds")?;
    let finalize = zero_finalize_request(&session)?;
    let abort = abort_request(&session, ProcessStreamSinkAbortReason::Cancellation)?;
    assert_ne!(
        finalize.command_identity()?.kind(),
        abort.command_identity()?.kind()
    );
    assert_eq!(
        finalize.command_identity()?.kind(),
        ProcessStreamSinkTerminalCommandKind::Finalize
    );
    assert_eq!(
        abort.command_identity()?.kind(),
        ProcessStreamSinkTerminalCommandKind::Abort
    );
    Ok(())
}

#[test]
fn every_abort_reason_is_bound_to_a_distinct_identity() -> TestResult {
    let session = session("reasons")?;
    let mut identities = Vec::new();
    for reason in [
        ProcessStreamSinkAbortReason::Cancellation,
        ProcessStreamSinkAbortReason::PolicyProhibition,
        ProcessStreamSinkAbortReason::RedactionFailure,
        ProcessStreamSinkAbortReason::TransportFailure,
        ProcessStreamSinkAbortReason::CallerShutdown,
    ] {
        identities.push(abort_request(&session, reason)?.command_identity()?);
    }
    for (index, identity) in identities.iter().enumerate() {
        assert!(
            identities[index + 1..]
                .iter()
                .all(|other| other != identity)
        );
    }
    Ok(())
}

#[test]
fn command_identity_wire_is_strict_and_lowercase_digest_checked() -> TestResult {
    let session = session("wire")?;
    let identity = zero_finalize_request(&session)?.command_identity()?;
    let wire = serde_json::to_value(&identity)?;
    assert_eq!(identity, serde_json::from_value(wire.clone())?);

    for invalid in [
        {
            let mut value = wire.clone();
            value["extra"] = serde_json::json!(true);
            value
        },
        {
            let mut value = wire.clone();
            if let Some(object) = value.as_object_mut() {
                object.remove("request_sha256");
            }
            value
        },
        {
            let mut value = wire.clone();
            value["kind"] = serde_json::json!("UNKNOWN");
            value
        },
        {
            let mut value = wire.clone();
            value["kind"] = serde_json::json!("finalize");
            value
        },
        {
            let mut value = wire.clone();
            value["request_sha256"] = serde_json::json!("A".repeat(64));
            value
        },
        {
            let mut value = wire.clone();
            value["request_sha256"] = serde_json::json!("a".repeat(63));
            value
        },
        {
            let mut value = wire;
            value["request_sha256"] = serde_json::json!("g".repeat(64));
            value
        },
    ] {
        assert!(
            serde_json::from_value::<ProcessStreamSinkTerminalCommandIdentity>(invalid).is_err()
        );
    }
    Ok(())
}

#[test]
fn terminal_id_substitution_fails_before_terminal_construction() -> TestResult {
    let session = session("substitution")?;
    let mut wire = serde_json::to_value(zero_finalize_request(&session)?)?;
    wire["terminal_id"] = serde_json::json!("terminal:other");
    let request: ProcessStreamSinkFinalizeRequest = serde_json::from_value(wire)?;
    assert!(matches!(
        ProcessStreamSinkTerminal::from_finalize(
            session,
            request,
            ProcessStreamSinkState::CompleteSource,
            0,
            0,
            sha256_hex(&[]),
            complete_evidence(&[])?,
        ),
        Err(ProcessStreamSinkError::TerminalIdentityConflict)
    ));
    Ok(())
}

#[test]
fn terminal_construction_rejects_every_result_request_mismatch() -> TestResult {
    let session = session("facts")?;
    let request = zero_finalize_request(&session)?;
    let evidence = complete_evidence(&[])?;
    let mut cases = Vec::new();
    for (field, value) in [
        ("expected_final_sequence", serde_json::json!(1)),
        ("expected_final_offset", serde_json::json!(1)),
        ("observed_sha256", serde_json::json!(sha256_hex(b"x"))),
        ("observed_bytes", serde_json::json!(1)),
        ("transport", serde_json::json!("READ_FAILED")),
        (
            "preview",
            serde_json::to_value(ProcessStreamPrefixPreview::from_transport_prefix(
                b"x".to_vec(),
                1,
            )?)?,
        ),
        (
            "transformation",
            serde_json::json!({
                "receipt_ref": "receipt:transform",
                "input_sha256": sha256_hex(&[]),
                "input_byte_length": 0,
                "output_sha256": sha256_hex(b"x"),
                "output_byte_length": 1,
                "policy_ref": "policy:1",
                "redaction_ref": "redaction:exact-v1"
            }),
        ),
        ("gaps", serde_json::json!(["TRANSPORT_READ_FAILED"])),
    ] {
        let mut wire = serde_json::to_value(&request)?;
        wire[field] = value;
        cases.push(wire);
    }
    for candidate in cases {
        assert!(
            match serde_json::from_value::<ProcessStreamSinkFinalizeRequest>(candidate) {
                Ok(candidate) => {
                    ProcessStreamSinkTerminal::from_finalize(
                        session.clone(),
                        candidate,
                        ProcessStreamSinkState::CompleteSource,
                        0,
                        0,
                        sha256_hex(&[]),
                        evidence.clone(),
                    )
                    .is_err()
                }
                Err(_) => true,
            }
        );
    }
    Ok(())
}

#[test]
fn terminal_digest_includes_command_identity() -> TestResult {
    let session = session("digest")?;
    let first_request = zero_finalize_request(&session)?;
    let mut changed_wire = serde_json::to_value(&first_request)?;
    changed_wire["wait_budget_ms"] = serde_json::json!(2);
    let changed_request: ProcessStreamSinkFinalizeRequest = serde_json::from_value(changed_wire)?;
    let first = empty_terminal(session.clone(), first_request)?;
    let changed = empty_terminal(session, changed_request)?;
    assert_ne!(first.command_identity(), changed.command_identity());
    assert_ne!(first.terminal_sha256(), changed.terminal_sha256());
    Ok(())
}

#[test]
fn terminal_validators_accept_exact_request_and_reject_kind_or_identity_changes() -> TestResult {
    let session = session("validators")?;
    let finalize = zero_finalize_request(&session)?;
    let terminal = empty_terminal(session.clone(), finalize.clone())?;
    terminal.validate_against_finalize(&finalize)?;

    let mut changed_wire = serde_json::to_value(&finalize)?;
    changed_wire["wait_budget_ms"] = serde_json::json!(2);
    let changed: ProcessStreamSinkFinalizeRequest = serde_json::from_value(changed_wire)?;
    assert!(matches!(
        terminal.validate_against_finalize(&changed),
        Err(ProcessStreamSinkError::TerminalIdentityConflict)
    ));
    assert!(matches!(
        terminal.validate_against_abort(&abort_request(
            &session,
            ProcessStreamSinkAbortReason::Cancellation
        )?),
        Err(ProcessStreamSinkError::TerminalIdentityConflict)
    ));
    let mut foreign_wire = serde_json::to_value(&finalize)?;
    foreign_wire["terminal_id"] = serde_json::json!("terminal:foreign");
    let foreign: ProcessStreamSinkFinalizeRequest = serde_json::from_value(foreign_wire)?;
    assert!(matches!(
        terminal.validate_against_finalize(&foreign),
        Err(ProcessStreamSinkError::TerminalIdentityConflict)
    ));
    Ok(())
}

#[test]
fn fake_replay_and_cross_kind_conflicts_preserve_terminal_state() -> TestResult {
    let fake = OracleFake::new();
    let session = poll_ready(fake.open(open_request("fake")?))?;
    let finalize = zero_finalize_request(&session)?;
    let first = poll_ready(fake.finalize(session.clone(), finalize.clone()))?;
    let replay = poll_ready(fake.finalize(session.clone(), finalize))?;
    assert_eq!(first, replay);
    let before = first.terminal_sha256().to_owned();
    let mut changed_finalize = serde_json::to_value(zero_finalize_request(&session)?)?;
    changed_finalize["wait_budget_ms"] = serde_json::json!(2);
    let changed_finalize = serde_json::from_value(changed_finalize)?;
    assert!(matches!(
        poll_ready(fake.finalize(session.clone(), changed_finalize)),
        Err(ProcessStreamSinkError::TerminalIdentityConflict)
    ));
    assert!(matches!(
        poll_ready(fake.abort(
            session.clone(),
            abort_request(&session, ProcessStreamSinkAbortReason::Cancellation)?,
        )),
        Err(ProcessStreamSinkError::TerminalIdentityConflict)
    ));
    let ProcessStreamSinkReadback::Terminal { terminal } =
        poll_ready(fake.readback(session.clone()))?
    else {
        panic!("conflict must preserve the terminal");
    };
    assert_eq!(before, terminal.terminal_sha256());

    let other = OracleFake::new();
    let other_session = poll_ready(other.open(open_request("other")?))?;
    let abort = abort_request(&other_session, ProcessStreamSinkAbortReason::Cancellation)?;
    let aborted = poll_ready(other.abort(other_session.clone(), abort.clone()))?;
    let aborted_identity = aborted.command_identity().clone();
    assert_eq!(
        aborted,
        poll_ready(other.abort(other_session.clone(), abort))?
    );
    assert!(matches!(
        poll_ready(other.abort(
            other_session.clone(),
            abort_request(&other_session, ProcessStreamSinkAbortReason::CallerShutdown)?,
        )),
        Err(ProcessStreamSinkError::TerminalIdentityConflict)
    ));
    assert!(matches!(
        poll_ready(other.finalize(
            other_session.clone(),
            zero_finalize_request(&other_session)?,
        )),
        Err(ProcessStreamSinkError::TerminalIdentityConflict)
    ));
    let ProcessStreamSinkReadback::Terminal { terminal: readback } =
        poll_ready(other.readback(other_session))?
    else {
        panic!("abort conflict must preserve the terminal");
    };
    assert_eq!(aborted.terminal_sha256(), readback.terminal_sha256());
    assert_eq!(&aborted_identity, readback.command_identity());
    Ok(())
}

#[test]
fn terminal_readback_exposes_the_accepted_identity() -> TestResult {
    let fake = OracleFake::new();
    let session = poll_ready(fake.open(open_request("readback")?))?;
    let request = zero_finalize_request(&session)?;
    let terminal = poll_ready(fake.finalize(session.clone(), request.clone()))?;
    let ProcessStreamSinkReadback::Terminal { terminal: readback } =
        poll_ready(fake.readback(session))?
    else {
        panic!("terminal must be returned by terminal readback");
    };
    assert_eq!(terminal.command_identity(), readback.command_identity());
    assert_eq!(terminal.terminal_sha256(), readback.terminal_sha256());
    Ok(())
}

#[test]
fn unknown_outcome_is_readback_fenced_without_terminalization() -> TestResult {
    let fake = OracleFake::new();
    let session = poll_ready(fake.open(open_request("unknown")?))?;
    let outcome = ProcessStreamSinkUnknownOutcome::new(
        session.session_id().clone(),
        session.terminal_id().clone(),
        session.open_request_sha256(),
        sha256_hex(b"uncertain"),
    )?;
    fake.set_unknown(outcome.clone());
    let expected = ProcessStreamSinkReadback::UnknownOutcome { outcome };
    assert_eq!(poll_ready(fake.readback(session.clone()))?, expected);

    assert!(matches!(
        poll_ready(fake.finalize(session.clone(), zero_finalize_request(&session)?)),
        Err(ProcessStreamSinkError::ProviderUnavailable)
    ));
    assert!(matches!(
        poll_ready(fake.abort(
            session.clone(),
            abort_request(&session, ProcessStreamSinkAbortReason::Cancellation)?,
        )),
        Err(ProcessStreamSinkError::ProviderUnavailable)
    ));
    assert_eq!(poll_ready(fake.readback(session))?, expected);
    assert!(fake.lock().terminal.is_none());
    Ok(())
}

#[test]
fn every_nonterminal_session_view_rejects_terminal_digest_in_constructor_and_serde() -> TestResult {
    let session = session("view")?;
    for state in [
        ProcessStreamSinkState::Opening,
        ProcessStreamSinkState::Open,
        ProcessStreamSinkState::Finalizing,
    ] {
        let counters = if state == ProcessStreamSinkState::Opening {
            (0, 0)
        } else {
            (1, 3)
        };
        assert!(
            eliot_process::ProcessStreamSinkSessionView::new(
                session.session_id().clone(),
                session.source_id().clone(),
                session.terminal_id().clone(),
                state,
                counters.0,
                counters.1,
                counters.0,
                counters.1,
                sha256_hex(if counters.1 == 0 { &[] } else { b"abc" }),
                session.open_request_sha256().to_owned(),
                Some("a".repeat(64)),
            )
            .is_err()
        );
    }
    let valid = eliot_process::ProcessStreamSinkSessionView::new(
        session.session_id().clone(),
        session.source_id().clone(),
        session.terminal_id().clone(),
        ProcessStreamSinkState::Open,
        0,
        0,
        0,
        0,
        sha256_hex(&[]),
        session.open_request_sha256().to_owned(),
        None,
    )?;
    let replay: eliot_process::ProcessStreamSinkSessionView =
        serde_json::from_value(serde_json::to_value(&valid)?)?;
    assert_eq!(valid, replay);
    let mut wire = serde_json::to_value(valid)?;
    wire["terminal_sha256"] = serde_json::json!("a".repeat(64));
    assert!(serde_json::from_value::<eliot_process::ProcessStreamSinkSessionView>(wire).is_err());
    Ok(())
}

#[test]
fn zero_byte_finalize_is_command_bound() -> TestResult {
    let session = session("zero")?;
    let request = zero_finalize_request(&session)?;
    let terminal = empty_terminal(session, request.clone())?;
    assert_eq!(terminal.admitted_bytes(), 0);
    assert_eq!(terminal.command_identity(), &request.command_identity()?);
    Ok(())
}

#[test]
fn public_exports_and_object_safe_client_remain_intact() {
    fn accepts(_: Arc<dyn ProcessStreamSinkClient>) {}
    let _: Option<ProcessStreamSinkAppend> = None;
    let _: Option<ProcessStreamSinkAppendDisposition> = None;
    let _: Option<ProcessStreamSinkLimits> = None;
    accepts(Arc::new(OracleFake::new()));
}

#[derive(Default)]
struct OracleState {
    session: Option<ProcessStreamSinkSession>,
    terminal: Option<ProcessStreamSinkTerminal>,
    unknown: Option<ProcessStreamSinkUnknownOutcome>,
}

struct OracleFake {
    state: Arc<Mutex<OracleState>>,
}

impl OracleFake {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(OracleState::default())),
        }
    }

    fn set_unknown(&self, unknown: ProcessStreamSinkUnknownOutcome) {
        self.lock().unknown = Some(unknown);
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, OracleState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn ready<T: Send + 'static>(
    result: Result<T, ProcessStreamSinkError>,
) -> ProcessStreamSinkFuture<'static, T> {
    Box::pin(async move { result })
}

impl ProcessStreamSinkClient for OracleFake {
    fn open(
        &self,
        request: ProcessStreamSinkOpenRequest,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkSession> {
        let mut state = self.lock();
        let result = match state.session.as_ref() {
            Some(session) if session.open_request_sha256() == request.open_request_sha256() => {
                Ok(session.clone())
            }
            Some(_) => Err(ProcessStreamSinkError::OpenDigestMismatch),
            None => ProcessStreamSinkSession::from_open_request(request).inspect(|session| {
                state.session = Some(session.clone());
            }),
        };
        ready(result)
    }

    fn append(
        &self,
        _session: ProcessStreamSinkSession,
        _request: ProcessStreamSinkAppend,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkAppendDisposition> {
        ready(Err(ProcessStreamSinkError::ProviderUnavailable))
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
                if state.unknown.is_some() {
                    return Err(ProcessStreamSinkError::ProviderUnavailable);
                }
                if let Some(terminal) = &state.terminal {
                    return if terminal.command_identity() == &request.command_identity()? {
                        Ok(terminal.clone())
                    } else {
                        Err(ProcessStreamSinkError::TerminalIdentityConflict)
                    };
                }
                let terminal = empty_terminal(session, request).map_err(|_| {
                    ProcessStreamSinkError::InvalidRequest {
                        reason: "oracle fake evidence",
                    }
                })?;
                state.terminal = Some(terminal.clone());
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
                if state.unknown.is_some() {
                    return Err(ProcessStreamSinkError::ProviderUnavailable);
                }
                if let Some(terminal) = &state.terminal {
                    return if terminal.command_identity() == &request.command_identity()? {
                        Ok(terminal.clone())
                    } else {
                        Err(ProcessStreamSinkError::TerminalIdentityConflict)
                    };
                }
                let terminal = ProcessStreamSinkTerminal::from_abort(
                    session,
                    request,
                    ProcessStreamSinkState::Cancelled,
                    0,
                    0,
                    sha256_hex(&[]),
                    ProcessStreamEvidence::new_raw(
                        binding().map_err(|_| ProcessStreamSinkError::InvalidRequest {
                            reason: "oracle fake binding",
                        })?,
                        ProcessStreamKind::Stdout,
                        policy().map_err(|_| ProcessStreamSinkError::InvalidRequest {
                            reason: "oracle fake policy",
                        })?,
                        StreamTransportStatus::CancelledBeforeEof,
                        StreamPersistenceStatus::SourceUnavailable,
                        sha256_hex(&[]),
                        0,
                        ProcessStreamPrefixPreview::from_transport_prefix(Vec::new(), 0)?,
                        None,
                        vec![
                            StreamEvidenceGap::PersistenceUnavailable,
                            StreamEvidenceGap::CancelledBeforeEof,
                        ],
                    )?,
                )?;
                state.terminal = Some(terminal.clone());
                Ok(terminal)
            });
        ready(result)
    }

    fn readback(
        &self,
        _session: ProcessStreamSinkSession,
    ) -> ProcessStreamSinkFuture<'_, ProcessStreamSinkReadback> {
        let state = self.lock();
        if let Some(unknown) = &state.unknown {
            return ready(Ok(ProcessStreamSinkReadback::UnknownOutcome {
                outcome: unknown.clone(),
            }));
        }
        if let Some(terminal) = &state.terminal {
            return ready(Ok(ProcessStreamSinkReadback::Terminal {
                terminal: terminal.clone(),
            }));
        }
        ready(Err(ProcessStreamSinkError::ProviderUnavailable))
    }
}
