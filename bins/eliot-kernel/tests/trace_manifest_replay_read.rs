//! Issue #1838 A1: the production replay read path of the sealed trace
//! manifest.
//!
//! I16.12 requires a replayable Material/Critical trace to carry the
//! Task/Action contract and State Fence, the Active View/packet manifest, the
//! principal/Session/lease/policy snapshots, the call input/output handles,
//! the receipts, the finish decision, and "missing parts explicitly listed",
//! and it states that "Missing trace does not invent failure or success; it
//! limits replay and may force `DEGRADED_NO_PROOF`." I16.7 makes the Diagnostic
//! Brief the operator read that joins "exact LogWindowRef/evidence handles" and
//! "unknowns and observation gaps".
//!
//! Two proofs, one per direction, both through the production entry point
//! `eliot_kernel::diagnostic_brief::compile_diagnostic_brief` (reached in
//! production by `KernelComposition::observe_diagnostic_problem`):
//!
//! - POSITIVE: a complete sealed manifest on the canonical chain is replayed
//!   whole, and the brief names the action contract, State Fence,
//!   caller/session, lease, requested and actual route, input/output handles,
//!   result receipt, and the recorded finish decision.
//! - REFUSAL: withholding one required evidence item names it in
//!   `missing_parts`, reports `DEGRADED_NO_PROOF`, and is not served as
//!   complete; a body that forges `VERIFIED_COMPLETE` over the very same
//!   withheld slots is refused by the manifest's own gate, so the brief
//!   reports the explicit gap instead of an unqualified trace.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup"
)]

use eliot_contracts::{EpochId, EpochLineageId, PolicyRevision, ResourceGeneration, StateFence};
use eliot_kernel::diagnostic_brief::{
    DiagnosticProblem, DiagnosticTrigger, DiagnosticWindow, ObservationGap, ObservationGapCode,
    compile_diagnostic_brief,
};
use eliot_kernel::kernel_audit::{
    AuditAssuranceClass, AuditCaptureMode, AuditEventKind, AuditLineage, AuditRecord,
};
use eliot_kernel::trace_manifest::{SealEvidence, TraceEvidence, TraceFinish, TraceManifest};
use eliot_ors::{
    HostRequestEffectEvidence, HostRequestKind, HostRequestRecord, HostRequestRetainedLineage,
    HostRequestRetainedResultClass, HostRequestState, OpaqueLabel, OperationIdentity,
};
use eliot_protocol::{HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestResultBody, LocalReadAttempt};
use eliot_security_contracts::{InfluenceState, PolicyFence};

const OPERATION_ID: &str =
    "hostreq:4444444444444444444444444444444444444444444444444444444444444444";
const RESULT_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REQUEST_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const INPUT_HANDLE: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const PRINCIPAL: &str = "principal:windows:replay-read";
const POLICY_SNAPSHOT: &str = "policy-snapshot:replay-read";
const VIEW_MANIFEST: &str = "campaign-view:replay-read";
const VERIFIER_RESULT: &str = "verifier:replay-read:accepted";

/// The one required class this proof withholds: the independent
/// verifier/artifact result, which I16.12 names as required trace content.
const WITHHELD_CLASS: &str = "verifier_result";

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("seq"),
    )
    .expect("epoch")
}

fn policy_bound_fence() -> StateFence {
    StateFence {
        authority_epoch: test_epoch(),
        resource_generation: ResourceGeneration::new(7).expect("generation"),
        task_revision: None,
        policy_revision: Some(PolicyRevision::new(4).expect("policy revision")),
        integration_revision: None,
    }
}

fn test_session() -> eliot_ipc::Session {
    let fence = policy_bound_fence();
    eliot_ipc::Session {
        connection_id: "replay-read-conn".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer: eliot_ipc::PeerIdentity::Unavailable {
            reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
        },
        authority_epoch: test_epoch(),
        module_generation: eliot_runtime_contracts::ModuleGeneration {
            module_id: eliot_contracts::ContractId::new("eliotd").expect("module id"),
            generation: fence.resource_generation,
            artifact_id: eliot_contracts::ArtifactId::new("a".repeat(64)).expect("artifact id"),
            state: eliot_runtime_contracts::ModuleGenerationState::Starting,
            health: eliot_runtime_contracts::HealthVector::healthy(),
            state_fence: fence,
        },
        launch_nonce: "replay-read-nonce".to_owned(),
        capabilities: Vec::new(),
        privacy_classes: Vec::new(),
        effects: Vec::new(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

fn retained_lineage() -> HostRequestRetainedLineage {
    HostRequestRetainedLineage {
        output_artifact_ref: None,
        output_digest: RESULT_DIGEST.to_owned(),
        producer_ref: Some(PRINCIPAL.to_owned()),
        source_revisions: None,
        source_state_fence: None,
        input_refs: None,
        transformation_lineage: None,
        closure_refs: None,
        policy_fence: Some(PolicyFence {
            policy_snapshot_id: POLICY_SNAPSHOT.to_owned(),
            state_fence: policy_bound_fence(),
        }),
        origin_evidence_refs: None,
        semantic_receipt_ref: None,
        result_class: HostRequestRetainedResultClass::ExistingEvidenceRead,
        proof_ceiling: None,
        influence_state: InfluenceState::Unknown,
        instruction_taint: None,
    }
}

fn durable_record() -> HostRequestRecord {
    HostRequestRecord {
        contract_version: 1,
        send_claim_protocol_version: 0,
        transport_channel_binding_sha256: None,
        operation_id: OperationIdentity::new(OPERATION_ID).expect("operation identity"),
        kind: HostRequestKind::Invocation,
        request_id: OpaqueLabel::new("replay-read-request").expect("request id"),
        correlation_projection: None,
        idempotency_key: OpaqueLabel::new("replay-read-request:invoke").expect("idempotency key"),
        cancellation_id: OpaqueLabel::new("replay-read-request:cancel").expect("cancel id"),
        parent_operation_id: None,
        request_digest: REQUEST_DIGEST.to_owned(),
        payload_digest: INPUT_HANDLE.to_owned(),
        payload_schema_id: Some(OpaqueLabel::new("eliot.mcp.tool-request.v1").expect("schema id")),
        payload_body: None,
        connection_ref: OpaqueLabel::new("replay-read-conn").expect("connection ref"),
        session_ref: Some(OpaqueLabel::new("replay-read-session").expect("session ref")),
        task_ref: Some(OpaqueLabel::new("replay-read-task").expect("task ref")),
        scope_ref: Some(OpaqueLabel::new("replay-read-scope").expect("scope ref")),
        capability_ref: OpaqueLabel::new("eliot.query").expect("capability ref"),
        fence_digest: "e".repeat(64),
        authority_epoch: test_epoch(),
        generation: 7,
        deadline_unix_ms: u64::MAX,
        state: HostRequestState::ResultReceived,
        attempt: None,
        attempt_history: Vec::new(),
        cancellation_target: None,
        result_digest: Some(RESULT_DIGEST.to_owned()),
        result_response: Some(serde_json::json!({"query": "replay-read"})),
        result_evidence: Some(HostRequestEffectEvidence {
            operation_id: OperationIdentity::new(OPERATION_ID).expect("evidence operation id"),
            input_handle: Some(INPUT_HANDLE.to_owned()),
            output_handle: Some(RESULT_DIGEST.to_owned()),
            side_effects: Some("none".to_owned()),
            actual_route: Some("query".to_owned()),
            invoked_operation: Some("local_read".to_owned()),
            adapter_identity: Some("replay-read-adapter".to_owned()),
            executor_identity: None,
        }),
        result_lineage: Some(retained_lineage()),
        commit_order: 1,
    }
}

fn result_body() -> HostRequestResultBody {
    HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: OPERATION_ID.to_owned(),
        request_sha256: REQUEST_DIGEST.to_owned(),
        result_digest: RESULT_DIGEST.to_owned(),
        response: serde_json::json!({"query": "replay-read"}),
        lineage: None,
        attempt: Some(LocalReadAttempt {
            wire_id: eliot_protocol::LOCAL_READ_ATTEMPT_WIRE_ID.to_owned(),
            wire_version: LocalReadAttempt::CONTRACT_VERSION,
            operation_id: OPERATION_ID.to_owned(),
            attempt_id: "replay-read-attempt".to_owned(),
            fencing_generation: 1,
            session_id: "replay-read-session".to_owned(),
            authority_epoch: test_epoch(),
            scope_id: "replay-read-scope".to_owned(),
            facet_method: "eliot.query".to_owned(),
            expires_at_unix_ms: u64::MAX,
            use_budget: 1,
        }),
        evidence: None,
    }
}

/// Seals through the production seal expression the two production sites use.
fn seal(observed: &TraceEvidence) -> TraceManifest {
    TraceManifest::seal(
        &test_session(),
        &result_body(),
        &durable_record(),
        None,
        "query",
        &SealEvidence {
            principal: None,
            active_view_packet_manifest: None,
            evidence: observed,
        },
    )
}

/// The production observation, with the two classes this seal site cannot
/// observe supplied so the recorded run observes every required I16.12 class.
fn complete_evidence() -> TraceEvidence {
    let mut evidence = TraceEvidence::observed(&durable_record(), Some(&policy_bound_fence()));
    evidence.active_view_packet_manifest = Some(VIEW_MANIFEST.to_owned());
    evidence.verifier_result = Some(VERIFIER_RESULT.to_owned());
    evidence
}

fn sealed_record(seq: u64, manifest: &TraceManifest) -> AuditRecord {
    let mut lineage = AuditLineage::empty();
    lineage.operation_id = Some(manifest.operation_id.clone());
    AuditRecord {
        format_version: 1,
        chain_id: "replay-read-chain".to_owned(),
        seq,
        prev_hash: "0".repeat(128),
        kind: AuditEventKind::TRACE_MANIFEST_SEALED.to_owned(),
        lineage,
        event_digest: "f".repeat(64),
        event_body: serde_json::to_value(manifest).expect("manifest serializes"),
        assurance: AuditAssuranceClass::Critical,
        capture_mode: AuditCaptureMode::Full,
        emitted_at_ms: 1,
        current_hash: "a".repeat(128),
    }
}

/// The problem trigger that opens the condition the brief is compiled for.
/// Its lineage carries the operation identity the replay read keys on, exactly
/// as the production `result.stale_quarantined` draft does.
fn trigger_record() -> AuditRecord {
    let fence = policy_bound_fence();
    let mut lineage = AuditLineage::empty();
    lineage.trace_id = Some("replay-read-request".to_owned());
    lineage.operation_id = Some(OPERATION_ID.to_owned());
    lineage.work_item = Some(OPERATION_ID.to_owned());
    lineage.session_id = Some("replay-read-session".to_owned());
    lineage.work_scope = Some("replay-read-scope".to_owned());
    lineage.task_id = Some("replay-read-task".to_owned());
    lineage.attempt_id = Some("replay-read-attempt".to_owned());
    lineage.environment_lease = Some("replay-read-attempt".to_owned());
    lineage.controller = Some("eliotd".to_owned());
    lineage.module_generation = Some("7".to_owned());
    lineage.authority_epoch = Some("550e8400-e29b-41d4-a716-446655440000:1".to_owned());
    lineage.state_fence = Some(fence);
    AuditRecord {
        format_version: 1,
        chain_id: "replay-read-chain".to_owned(),
        seq: 2,
        prev_hash: "a".repeat(128),
        kind: AuditEventKind::RESULT_STALE_QUARANTINED.to_owned(),
        lineage,
        event_digest: "c".repeat(64),
        event_body: serde_json::json!({"reason": "replay-read fixture"}),
        assurance: AuditAssuranceClass::Critical,
        capture_mode: AuditCaptureMode::Full,
        emitted_at_ms: 2,
        current_hash: "b".repeat(128),
    }
}

/// The observed condition plus the sealed manifest, on one gapless chain.
fn chain_with(manifest: &TraceManifest) -> Vec<AuditRecord> {
    vec![sealed_record(1, manifest), trigger_record()]
}

fn problem() -> DiagnosticProblem {
    DiagnosticProblem {
        trigger: DiagnosticTrigger::SecurityOrIntegrationGap,
        window: DiagnosticWindow {
            first_audit_seq: 1,
            last_audit_seq: 2,
        },
        log_windows: Vec::new(),
    }
}

fn has_gap(gaps: &[ObservationGap], code: ObservationGapCode) -> bool {
    gaps.iter().any(|gap| gap.code == code)
}

/// POSITIVE: the reader is reachable from the production compiler and replays
/// the persisted manifest whole, naming every class the acceptance lists.
#[test]
fn replay_read_surfaces_the_persisted_manifest_and_its_finish_decision() {
    let manifest = seal(&complete_evidence());
    assert_eq!(
        manifest.finish,
        TraceFinish::VerifiedComplete,
        "the fixture run observes every required class, so it seals complete"
    );

    let records = chain_with(&manifest);
    let brief = compile_diagnostic_brief(&records, &problem()).expect("brief compiles");

    assert!(
        !has_gap(
            &brief.observation_gaps,
            ObservationGapCode::ReplayableTraceUnservable
        ),
        "a servable sealed manifest leaves no replay gap, got {:?}",
        brief.observation_gaps
    );

    let replay = brief
        .trace_replay()
        .expect("the sealed manifest is replayed");
    assert_eq!(replay.trace_id, manifest.trace_id);
    assert_eq!(replay.operation_id, OPERATION_ID);
    // Action contract: the Task/Action contract selector and its exact payload.
    assert_eq!(replay.capability.as_deref(), Some("eliot.query"));
    assert_eq!(replay.payload_digest.as_deref(), Some(INPUT_HANDLE));
    // State Fence.
    assert_eq!(replay.state_fence.as_ref(), Some(&policy_bound_fence()));
    // Caller and session.
    assert_eq!(replay.connection_id.as_deref(), Some("replay-read-conn"));
    assert_eq!(replay.session_id.as_deref(), Some("replay-read-session"));
    // Lease.
    assert_eq!(
        replay.lease_attempt_id.as_deref(),
        Some("replay-read-attempt")
    );
    assert_eq!(replay.fencing_generation, Some(1));
    // Requested and actual route.
    assert_eq!(replay.requested_route.as_deref(), Some("eliot.query"));
    assert_eq!(replay.actual_route.as_deref(), Some("query"));
    // Local-port call input/output handles.
    assert_eq!(replay.invoked_operation.as_deref(), Some("local_read"));
    assert_eq!(replay.input_handle.as_deref(), Some(INPUT_HANDLE));
    assert_eq!(replay.output_handle.as_deref(), Some(RESULT_DIGEST));
    // Result receipt.
    assert_eq!(replay.result_digest.as_deref(), Some(RESULT_DIGEST));
    assert!(replay.durable_state.is_some());
    // I16.12 evidence classes and the recorded finish decision.
    assert_eq!(replay.principal.as_deref(), Some(PRINCIPAL));
    assert_eq!(replay.policy_snapshot.as_deref(), Some(POLICY_SNAPSHOT));
    assert_eq!(
        replay.active_view_packet_manifest.as_deref(),
        Some(VIEW_MANIFEST)
    );
    assert_eq!(replay.verifier_result.as_deref(), Some(VERIFIER_RESULT));
    assert_eq!(replay.finish, TraceFinish::VerifiedComplete);
    assert_eq!(replay.finish.as_str(), "VERIFIED_COMPLETE");
    assert!(brief.replay_missing_parts().is_empty());
    assert!(
        brief.replay_is_complete(),
        "a body whose own recorded slots carry its completion claim is complete"
    );
}

/// REFUSAL: withholding one required evidence item names it, degrades the
/// replay, and is never served as a complete trace; a body forging completion
/// over the same withheld slots is refused outright and reported as a gap.
#[test]
fn withheld_required_evidence_degrades_the_replay_and_a_forged_completion_is_refused() {
    let mut withheld_evidence = complete_evidence();
    withheld_evidence.verifier_result = None;
    let withheld = seal(&withheld_evidence);
    assert!(
        withheld.missing_parts.contains(&WITHHELD_CLASS.to_owned()),
        "withholding the verifier result names it as an explicit missing part, got {:?}",
        withheld.missing_parts
    );
    assert_eq!(withheld.finish, TraceFinish::DegradedNoProof);

    let records = chain_with(&withheld);
    let brief = compile_diagnostic_brief(&records, &problem()).expect("brief compiles");

    let replay = brief.trace_replay().expect("the degraded body is replayed");
    assert_eq!(replay.finish, TraceFinish::DegradedNoProof);
    assert_eq!(replay.finish.as_str(), "DEGRADED_NO_PROOF");
    assert_eq!(
        brief.replay_missing_parts(),
        withheld.missing_parts.as_slice(),
        "the recorded missing-parts list is carried through unchanged"
    );
    assert!(
        brief
            .replay_missing_parts()
            .contains(&WITHHELD_CLASS.to_owned()),
        "the withheld class is named explicitly, not hidden"
    );
    assert!(
        !brief.replay_is_complete(),
        "a body withholding a required class is never served as a complete trace"
    );

    // The forged body claims completion over the very slots it withholds: the
    // manifest's own recorded gate refuses it, so the reader reports the gap
    // instead of inventing a replayable trace.
    let forged = TraceManifest {
        finish: TraceFinish::VerifiedComplete,
        missing_parts: Vec::new(),
        unavailable: Vec::new(),
        ..withheld.clone()
    };
    let forged_records = chain_with(&forged);
    let refused = compile_diagnostic_brief(&forged_records, &problem()).expect("brief compiles");
    assert!(
        refused.trace_replay().is_none(),
        "a self-contradicting completion claim is refused on replay"
    );
    assert!(
        has_gap(
            &refused.observation_gaps,
            ObservationGapCode::ReplayableTraceUnservable
        ),
        "the refusal is reported as the explicit gap that names the missing record"
    );
    assert!(
        !refused.replay_is_complete(),
        "a refused replay is never reported as complete"
    );

    // The gap names the exact record that would close it.
    let gap = refused
        .observation_gaps
        .iter()
        .find(|gap| gap.code == ObservationGapCode::ReplayableTraceUnservable)
        .expect("the replay gap is reported");
    assert!(
        gap.required_observation
            .contains(AuditEventKind::TRACE_MANIFEST_SEALED),
        "the gap names the canonical event that would supply the trace, got {:?}",
        gap.required_observation
    );
    assert!(
        refused.reports_gap_not_cause(),
        "insufficient evidence returns a gap, never an invented diagnosis"
    );
}
