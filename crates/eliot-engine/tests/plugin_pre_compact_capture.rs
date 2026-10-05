//! The pre-compaction capture gate (issue #1730, #984-adjacent plugin seam).
//!
//! The subject is one question: may the host destroy this session's conversational
//! state? The pre-compaction hook is the only ELIOT-controlled boundary that
//! destroys state, and before #1730 it answered that question on hook-spool size
//! alone — a local resource bound that says nothing about whether a handoff
//! checkpoint exists. These cases pin the capture half of the answer.
//!
//! Every case drives the real [`EliotHookService::process`] entry through
//! `HookEventKind::PreCompact` and asserts the typed decision, so none of them can
//! pass by proving a fixture rather than the gate. The capture ledger is the
//! contract's own [`HandoffCaptureLedger`], and the durable readback is produced by
//! the contract's own capture state machine — this file never hand-builds a state
//! the capture type cannot reach.

use eliot_agent_contracts::{
    AgentAttemptId, HandoffArtifactLease, HandoffCaptureBoundary, HandoffCaptureLedger,
    HandoffCaptureReadback, HandoffCaptureSource, HandoffCheckpointId, HandoffCursor,
    HandoffCursors, HandoffLeaseRelease, HandoffSourceGenerations, PublicReference, RevisionId,
    TargetId,
};
use eliot_contracts::{
    EpochId, EpochLineageId, OperationId, ResourceGeneration, StateFence, TaskId,
};
use eliot_engine::EliotHookService;
use eliot_types::{HookEventKind, HookProcessingStatus};
use serde_json::json;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// The attempt identity every case uses, so the ledger key is exact.
const ATTEMPT: &str = "attempt-pre-compact-1730";

fn runtime_root(name: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |value| value.as_nanos());
    let ordinal = COUNTER.fetch_add(1, Ordering::SeqCst);
    std::env::temp_dir().join(format!("eliot-plugin-precompact-{name}-{unique}-{ordinal}"))
}

/// An immutable digest-bound reference, which is the only shape a capture accepts.
fn reference(
    kind: &str,
    digest: &str,
) -> Result<PublicReference, Box<dyn std::error::Error + Send + Sync>> {
    Ok(PublicReference {
        kind: kind.to_owned(),
        id: TargetId::new(format!("{kind}-id-1730"))?,
        revision: RevisionId::new("1")?,
        digest: Some(digest.to_owned()),
    })
}

fn attempt_id() -> Result<AgentAttemptId, Box<dyn std::error::Error + Send + Sync>> {
    Ok(AgentAttemptId::new(ATTEMPT)?)
}

/// A genesis fence, built the same way the crate's own cases build one.
fn fence() -> Result<StateFence, Box<dyn std::error::Error + Send + Sync>> {
    let fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?,
            std::num::NonZeroU64::new(1).ok_or("non-zero epoch sequence")?,
        )?,
        ResourceGeneration::genesis(),
    );
    Ok(fence)
}

/// A complete, contract-valid capture source for the pre-compaction boundary.
fn capture_source() -> Result<HandoffCaptureSource, Box<dyn std::error::Error + Send + Sync>> {
    Ok(HandoffCaptureSource {
        capture_id: HandoffCheckpointId::new("capture-pre-compact-1730")?,
        operation_id: OperationId::new("capture-op-pre-compact-1730")?,
        boundary: HandoffCaptureBoundary::HostPreCompactHook,
        source_task_id: TaskId::new("task-pre-compact-1730")?,
        source_attempt_id: attempt_id()?,
        source_session_ref: reference("session", "session-digest-1730")?,
        source_plan_revision: RevisionId::new("1")?,
        source_acceptance_revision: RevisionId::new("1")?,
        source_fence: fence()?,
        source_generations: HandoffSourceGenerations {
            scope: ResourceGeneration::genesis(),
            world: ResourceGeneration::genesis(),
            module: ResourceGeneration::genesis(),
            route: ResourceGeneration::genesis(),
        },
        source_cursors: HandoffCursors {
            event: HandoffCursor::Observed {
                cursor: "event-cursor-1730".to_owned(),
            },
            outbox: HandoffCursor::Observed {
                cursor: "outbox-cursor-1730".to_owned(),
            },
        },
        frozen_diff: reference("diff", "diff-digest-1730")?,
        recorded_checkpoint_digest: "checkpoint-digest-1730".to_owned(),
        recorded_diff_digest: "diff-digest-1730".to_owned(),
        expected_retained_artifacts: vec![reference("blob", "blob-digest-1730")?],
        expected_pending_verifiers: Vec::new(),
        expected_pending_effects: Vec::new(),
    })
}

/// Registers a capture for the pre-compaction boundary and drives it to the state
/// the ledger's own `admits_destructive_compaction` requires.
///
/// The state is reached through the public capture operations in the order the
/// contract defines — capture, commit acknowledgement, then durable readback — and
/// the record is registered ONCE, at the end, carrying the state it actually
/// reached.
///
/// That order matters and is not cosmetic. Registering first and re-registering
/// afterwards does NOT work: the ledger treats an identical replay as
/// [`HandoffCaptureRegistration::Replayed`] and returns the ALREADY-REGISTERED
/// capture, so a readback recorded on the local copy would never reach the ledger
/// and the gate would keep refusing. This helper originally did that and the
/// "allowed" case failed, which is the contract behaving correctly rather than a
/// fixture problem.
fn register_durable_capture(
    ledger: &mut HandoffCaptureLedger,
    source_attempt: Option<AgentAttemptId>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use eliot_agent_contracts::{HandoffCapture, HandoffCaptureRegistration, HandoffCaptureState};
    let mut source = capture_source()?;
    if let Some(attempt) = source_attempt {
        source.source_attempt_id = attempt;
    }
    let leases = vec![HandoffArtifactLease {
        artifact_ref: reference("blob", "blob-digest-1730")?,
        retained_by_capture: source.capture_id.clone(),
        release: HandoffLeaseRelease::AfterResumeReconciled,
    }];
    let mut capture = HandoffCapture::capture(source, leases)?;
    assert_eq!(
        capture.state,
        HandoffCaptureState::Captured,
        "a capture starts Captured, before any transport acknowledgement"
    );
    capture.record_commit_transport("transport-ack-pre-compact-1730".to_owned())?;
    let readback = HandoffCaptureReadback {
        capture_id: capture.capture_id.clone(),
        operation_id: capture.operation_id.clone(),
        boundary: capture.boundary,
        read_generation: ResourceGeneration::genesis(),
        readback_checkpoint_digest: capture.recorded_checkpoint_digest.clone(),
        readback_diff_digest: capture.recorded_diff_digest.clone(),
        observed_retained_artifacts: capture.expected_retained_artifacts.clone(),
        observed_pending_verifiers: capture.expected_pending_verifiers.clone(),
        observed_pending_effects: capture.expected_pending_effects.clone(),
    };
    capture.record_readback(readback)?;
    assert!(
        capture.admits_destructive_compaction(),
        "a capture that reached a durable readback must admit on its own terms"
    );
    let registration = ledger.register(capture)?;
    assert!(
        matches!(registration, HandoffCaptureRegistration::First(_)),
        "a fresh ledger must register this capture as the first one"
    );
    Ok(())
}

// WORK_UNIT_CASE: 1730/W7-capture-required
#[test]
fn pre_compact_is_refused_when_the_session_attempt_has_no_capture() -> TestResult {
    let root = runtime_root("no-capture");
    std::fs::create_dir_all(&root)?;
    // An EMPTY ledger: the hook is bound to an ELIOT task and the session names an
    // attempt, but nothing captured it. This is the state the old spool-size-only
    // gate allowed.
    let service = EliotHookService::with_capture_ledger(&root, true, HandoffCaptureLedger::new());
    let result = service.process(
        HookEventKind::PreCompact,
        &json!({ "attempt_id": ATTEMPT, "session_id": "session-1730" }),
    )?;

    assert!(
        !result.decision.allow,
        "a destructive boundary must not allow on spool size alone"
    );
    assert_eq!(
        result.decision.processing_status,
        HookProcessingStatus::FailedClosed
    );
    let codes: Vec<&str> = result
        .decision
        .reasons
        .iter()
        .map(|reason| reason.code.as_str())
        .collect();
    assert!(
        codes.contains(&"handoff_capture_required"),
        "the refusal must name the missing capture, got {codes:?}"
    );
    // The spool directory the real path writes into stays under the OS temp dir:
    // cleaning it up here could mask a failure by deleting evidence first.
    Ok(())
}

// WORK_UNIT_CASE: 1730/W7-capture-admits
#[test]
fn pre_compact_is_allowed_once_the_capture_has_a_durable_readback() -> TestResult {
    let root = runtime_root("captured");
    std::fs::create_dir_all(&root)?;
    let mut ledger = HandoffCaptureLedger::new();
    register_durable_capture(&mut ledger, None)?;
    let service = EliotHookService::with_capture_ledger(&root, true, ledger);

    let result = service.process(
        HookEventKind::PreCompact,
        &json!({ "attempt_id": ATTEMPT, "session_id": "session-1730" }),
    )?;
    assert!(
        result.decision.allow,
        "a captured, durably read-back session may compact: {:?}",
        result.decision.reasons
    );
    assert_eq!(
        result.decision.processing_status,
        HookProcessingStatus::SpoolingPending,
        "an allowed hook is still spooled for governed memory discipline"
    );
    Ok(())
}

// WORK_UNIT_CASE: 1730/W7-capture-other-attempt
#[test]
fn pre_compact_is_refused_when_only_a_different_attempt_is_captured() -> TestResult {
    let root = runtime_root("other-attempt");
    std::fs::create_dir_all(&root)?;
    // A real, durably proved capture — but for ANOTHER attempt. The ledger is keyed
    // by (boundary, attempt), so this must not admit the session under test: the
    // exact-identity property is the whole point of asking per attempt.
    let mut ledger = HandoffCaptureLedger::new();
    let other = AgentAttemptId::new("attempt-somebody-else-1730")?;
    register_durable_capture(&mut ledger, Some(other))?;

    let service = EliotHookService::with_capture_ledger(&root, true, ledger);
    let result = service.process(
        HookEventKind::PreCompact,
        &json!({ "attempt_id": ATTEMPT, "session_id": "session-1730" }),
    )?;
    assert!(
        !result.decision.allow,
        "another attempt's durable capture must not admit this session"
    );
    Ok(())
}

// WORK_UNIT_CASE: 1730/W7-unbound-defers
#[test]
fn pre_compact_defers_for_a_session_that_names_no_attempt() -> TestResult {
    let root = runtime_root("no-attempt");
    std::fs::create_dir_all(&root)?;
    // A payload with no attempt identity owes no capture identity, so there is
    // nothing for the ledger to refuse. This case exists so the gate cannot be
    // "implemented" as an unconditional block, which would deny compaction to
    // every session that does not report an attempt.
    let service = EliotHookService::with_capture_ledger(&root, true, HandoffCaptureLedger::new());
    let result = service.process(
        HookEventKind::PreCompact,
        &json!({ "session_id": "session-1730" }),
    )?;
    assert!(
        result.decision.allow,
        "a session naming no attempt owes no capture: {:?}",
        result.decision.reasons
    );
    Ok(())
}
