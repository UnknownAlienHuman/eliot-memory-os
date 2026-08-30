use eliot_contracts::sha256_hex;
use eliot_process::{
    DurableProcessStreamSource, DurableStreamLocatorKind, ProcessExecutionBinding,
    ProcessStreamDigestAlgorithm, ProcessStreamEvidence, ProcessStreamKind,
    ProcessStreamPolicyBinding, ProcessStreamPrefixPreview, ProcessStreamSinkAbortReason,
    ProcessStreamSinkAbortRequest, ProcessStreamSinkFinalizeRequest, ProcessStreamSinkLimits,
    ProcessStreamSinkOpenRequest, ProcessStreamSinkSession, ProcessStreamSinkSessionId,
    ProcessStreamSinkSessionView, ProcessStreamSinkSourceId, ProcessStreamSinkState,
    ProcessStreamSinkTerminal, ProcessStreamSinkTerminalCommandKind,
    ProcessStreamSinkTerminalId, StreamEvidenceGap, StreamPersistenceStatus,
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
        "state_fence": {
            "authority_epoch": 7,
            "generation": 3,
            "nonce": "fence-1"
        },
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

fn session() -> TestResult<ProcessStreamSinkSession> {
    Ok(ProcessStreamSinkSession::from_open_request(
        ProcessStreamSinkOpenRequest::new(
            ProcessStreamSinkSessionId::new("sink-session-1")?,
            ProcessStreamSinkSourceId::new("sink-source-1")?,
            ProcessStreamSinkTerminalId::new("sink-terminal-1")?,
            binding()?,
            ProcessStreamKind::Stdout,
            policy()?,
            limits()?,
            ProcessStreamDigestAlgorithm::Sha256,
            ProcessStreamDigestAlgorithm::Sha256,
        )?,
    )?)
}

fn complete_evidence(bytes: &[u8]) -> TestResult<ProcessStreamEvidence> {
    let digest = sha256_hex(bytes);
    Ok(ProcessStreamEvidence::new_raw(
        binding()?,
        ProcessStreamKind::Stdout,
        policy()?,
        StreamTransportStatus::Complete,
        StreamPersistenceStatus::CompleteSource,
        digest.clone(),
        bytes.len() as u64,
        ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), bytes.len() as u64)?,
        Some(DurableProcessStreamSource::exact_transport(
            DurableStreamLocatorKind::Blob,
            format!("eliot://blob/{digest}"),
            format!("receipt:ready:{digest}"),
            digest,
            bytes.len() as u64,
        )?),
        Vec::new(),
    )?)
}

fn cancelled_evidence(bytes: &[u8]) -> TestResult<ProcessStreamEvidence> {
    Ok(ProcessStreamEvidence::new_raw(
        binding()?,
        ProcessStreamKind::Stdout,
        policy()?,
        StreamTransportStatus::CancelledBeforeEof,
        StreamPersistenceStatus::SourceUnavailable,
        sha256_hex(bytes),
        bytes.len() as u64,
        ProcessStreamPrefixPreview::from_transport_prefix(bytes.to_vec(), bytes.len() as u64)?,
        None,
        vec![
            StreamEvidenceGap::PersistenceUnavailable,
            StreamEvidenceGap::CancelledBeforeEof,
        ],
    )?)
}

fn finalize_request(
    session: &ProcessStreamSinkSession,
    wait_budget_ms: u64,
) -> TestResult<ProcessStreamSinkFinalizeRequest> {
    Ok(ProcessStreamSinkFinalizeRequest::new(
        session.terminal_id().clone(),
        1,
        3,
        wait_budget_ms,
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
    )?)
}

#[test]
fn terminal_command_identity_distinguishes_kind_and_exact_request_bytes() -> TestResult {
    let session = session()?;
    let first = finalize_request(&session, 1)?;
    let replay = finalize_request(&session, 1)?;
    let changed = finalize_request(&session, 2)?;
    let abort = abort_request(&session, ProcessStreamSinkAbortReason::Cancellation)?;

    assert_eq!(first.command_identity()?, replay.command_identity()?);
    assert_ne!(first.command_identity()?, changed.command_identity()?);
    assert_ne!(first.command_identity()?, abort.command_identity()?);
    assert_eq!(
        first.command_identity()?.kind(),
        ProcessStreamSinkTerminalCommandKind::Finalize
    );
    assert_eq!(
        abort.command_identity()?.kind(),
        ProcessStreamSinkTerminalCommandKind::Abort
    );
    assert_eq!(
        first.command_identity()?.terminal_id(),
        session.terminal_id()
    );
    Ok(())
}

#[test]
fn terminal_identity_binds_exact_finalize_or_abort_command() -> TestResult {
    let session = session()?;
    let finalize = finalize_request(&session, 1)?;
    let finalize_terminal = ProcessStreamSinkTerminal::from_finalize(
        session.clone(),
        finalize.clone(),
        ProcessStreamSinkState::CompleteSource,
        1,
        3,
        sha256_hex(b"abc"),
        complete_evidence(b"abc")?,
    )?;
    assert_eq!(
        finalize_terminal.command_identity(),
        &finalize.command_identity()?
    );
    finalize_terminal.validate_against_finalize(&finalize)?;

    let cancellation = abort_request(&session, ProcessStreamSinkAbortReason::Cancellation)?;
    let shutdown = abort_request(&session, ProcessStreamSinkAbortReason::CallerShutdown)?;
    let cancellation_terminal = ProcessStreamSinkTerminal::from_abort(
        session.clone(),
        cancellation.clone(),
        ProcessStreamSinkState::Cancelled,
        1,
        3,
        sha256_hex(b"abc"),
        cancelled_evidence(b"abc")?,
    )?;
    let shutdown_terminal = ProcessStreamSinkTerminal::from_abort(
        session,
        shutdown.clone(),
        ProcessStreamSinkState::Cancelled,
        1,
        3,
        sha256_hex(b"abc"),
        cancelled_evidence(b"abc")?,
    )?;

    assert_ne!(
        cancellation.command_identity()?,
        shutdown.command_identity()?
    );
    assert_ne!(
        cancellation_terminal.terminal_sha256(),
        shutdown_terminal.terminal_sha256()
    );
    assert!(cancellation_terminal
        .validate_against_abort(&shutdown)
        .is_err());
    shutdown_terminal.validate_against_abort(&shutdown)?;
    Ok(())
}

#[test]
fn nonterminal_session_view_cannot_claim_terminal_result_digest() -> TestResult {
    let session = session()?;
    assert!(
        ProcessStreamSinkSessionView::new(
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
            Some("d".repeat(64)),
        )
        .is_err()
    );

    let wire = serde_json::json!({
        "session_id": session.session_id(),
        "source_id": session.source_id(),
        "terminal_id": session.terminal_id(),
        "state": "OPEN",
        "next_sequence": 1,
        "next_offset": 3,
        "admitted_chunks": 1,
        "admitted_bytes": 3,
        "admitted_sha256": sha256_hex(b"abc"),
        "open_request_sha256": session.open_request_sha256(),
        "terminal_sha256": "d".repeat(64)
    });
    assert!(serde_json::from_value::<ProcessStreamSinkSessionView>(wire).is_err());
    Ok(())
}
