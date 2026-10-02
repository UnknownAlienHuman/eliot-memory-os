//! Issue #2564: the STATE readback arm's VALIDATING READER, executed.
//!
//! #2564 delivered `daemon_request_dispatch.rs::local_state_read_operation`,
//! whose defining property is that a retained `eliot.state` answer is served
//! through the SINGLE validating reader
//! `host_request_route::local_read_replay_response` instead of the unvalidated
//! `host_request_admitted_response` shape.
//!
//! ## What this file proves, and what it deliberately does not
//!
//! The FULL arm cannot be executed from a unit test, and this file does not
//! pretend otherwise. Reaching the arm means arriving through
//! `KernelComposition::local_read_operation`, which routes a pair only after
//! `enqueue_local_read_pair_under_transition` has queued it. That enqueue calls
//! `host_request_route.rs::host_request_connection_gate_under_transition`
//! (`host_request_route.rs:3447`), which fails closed on a missing published
//! bridge profile (`:2382`) and on an unregistered connection (`:2389`), and
//! the claim leg additionally needs a composed `dispatch_contour()` and
//! validates an OBSERVED PEER PROCESS IDENTITY (`agent_bridge.rs:475-481`).
//! That identity is observed from a live transport peer; it cannot be
//! synthesized honestly in a test, and this file does not fabricate one, add a
//! bypass, or fake reachability. The two re-proves the arm makes at its answer
//! boundary — that the DURABLE row's capability is the state capability, and
//! that the selectors' scope is one the DURABLE row names
//! (`daemon_request_dispatch.rs:10593-10610`) — live inside that unreachable
//! `&self` method and are therefore named here as unproven rather than
//! re-implemented as a weaker copy inside the test.
//!
//! What IS reachable, and what these tests exercise for real, is the validating
//! reader itself. `local_read_replay_response` is `pub(crate)`, pure (it
//! performs no dispatch and no Store IO), and takes `(receipt, record,
//! envelope)`. The durable `record` it reads is built by the crate's REAL ORS
//! result owner through `eliot_ors::persist_host_request_result`, which walks
//! the canonical `Admitted -> Routed -> Submitted -> ResultReceived` lifecycle
//! (`store.rs:11383-11395`) and persists the digest, body and retained lineage
//! itself. So the row under test is owner-stored, not a value the test
//! assembled, and the reader is the production function the arm calls. The
//! `receipt` is the real `eliot_protocol::HostRequestAdmissionReceipt::issue`,
//! and the pair is the real `host_request_route::check_local_state_admission`.
//!
//! Together these tests prove the validating READBACK contract over a genuine
//! State record: it returns the retained answer, it fails closed on a
//! substituted retained digest, on a forged retained lineage that breaks the
//! class/receipt binding, and on a half-present pair, and it serves the same
//! retained bytes on an exact replay. They do NOT prove dispatch, enqueue,
//! claim, submit, the source-revision head rejoin, or the live disclosure
//! re-evaluation — those are named above as the unreachable remainder.

#![cfg(windows)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "readback fixtures build envelopes and records through the real ORS owners and assert on them directly"
)]

use super::*;
use eliot_ors::{
    HostRequestRecord, HostRequestRetainedLineage, HostRequestRetainedResultClass,
    HostRequestState, InfluenceState, OperationIdentity,
};
use eliot_protocol::{
    HOST_REQUEST_WIRE_ID, HostRequestEnvelope, HostRequestIdentity, HostRequestKind,
};

fn tool_digest(tool: &serde_json::Value) -> String {
    let bytes = eliot_contracts::canonical_json_bytes(tool).expect("tool must canonicalize");
    eliot_contracts::sha256_hex(&bytes)
}

/// The bounded owner-backed `eliot.state` tool. `include` is the closed
/// selector list the state admission owner projects; it is never a Store
/// selector, only the disclosed field set.
fn state_tool() -> serde_json::Value {
    serde_json::json!({
        "name": "eliot.state",
        "arguments": { "include": ["task", "scope", "attention", "health"] }
    })
}

/// The one state envelope builder.
///
/// The invocation carries the same explicit host-correlation projection a real
/// host adapter projects: the opaque `Request`-domain occurrence whose exact
/// text is also the `request_id`, so `request_id` is taken from the
/// projection's own `occurrence_text()` rather than written independently —
/// the same round-trip both the protocol and ORS owners require.
fn state_envelope(
    fence: &StateFence,
    deadline_unix_ms: u64,
    request_id: &str,
    tool: &serde_json::Value,
) -> HostRequestEnvelope {
    let correlation_projection = eliot_contracts::HostCorrelationProjection::Opaque {
        domain: eliot_contracts::HostCorrelationDomain::Request,
        occurrence: request_id.to_owned(),
    };
    HostRequestEnvelope {
        wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
        wire_version: HostRequestEnvelope::CONTRACT_VERSION,
        kind: HostRequestKind::Invocation,
        connection_id: "conn-state-readback".to_owned(),
        identity: HostRequestIdentity {
            request_id: eliot_contracts::RequestId::new(correlation_projection.occurrence_text())
                .expect("valid request id"),
            correlation_projection: Some(correlation_projection),
            idempotency_key: format!("{request_id}:invoke"),
            cancellation_id: format!("{request_id}:invoke:cancel"),
            parent_operation_id: None,
            deadline_unix_ms,
            capability: host_request_route::local_read_state_capability().to_owned(),
            // `eliot.state` is not task-relative, so no-task discovery carries
            // no task id; the session is what names the disclosed scope.
            session_id: Some("kernel-session-1".to_owned()),
            task_id: None,
            work_scope_id: None,
            payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
            payload_sha256: tool_digest(tool),
        },
        state_fence: fence.clone(),
        descriptor_sha256: "d".repeat(64),
        peer_admission_receipt_sha256: "e".repeat(64),
        activation_binding: None,
        envelope_sha256: String::new(),
    }
    .with_computed_digest()
    .expect("envelope must digest")
}

/// One bounded owner-backed State preview.
///
/// It carries no `campaign_learning_state_view` key on purpose: a response
/// that projects a campaign view is treated by the ORS result owner as a
/// content-addressed publication with its own validation, which is the Packet
/// lane, not the State lane.
fn state_answer(revision: u64) -> serde_json::Value {
    serde_json::json!({
        "operation": "GetCurrentStateView",
        "preview": {
            "task": { "selected": true, "task_revision": revision },
            "scope": { "scope_id": "kernel-session-1" },
            "attention": { "status": "available" },
            "health": { "status": "ready" }
        },
        "revision_heads": [
            { "key": "scope:kernel-session-1", "revision": revision }
        ]
    })
}

fn state_result_digest(revision: u64) -> String {
    eliot_contracts::sha256_hex(
        &eliot_contracts::canonical_json_bytes(&state_answer(revision))
            .expect("answer canonicalizes"),
    )
}

/// The State's retained lineage, built by the same owner rules the real daemon
/// State leg is bound by: `output_digest` equals the retained result digest,
/// the class is a non-canonical `ExistingEvidenceRead`, and — because a
/// non-canonical row may NOT carry a semantic receipt — `semantic_receipt_ref`
/// stays `None`. The validating reader re-checks exactly these two facts
/// (`host_request_route.rs:9979-9994`).
fn state_lineage(envelope: &HostRequestEnvelope, revision: u64) -> HostRequestRetainedLineage {
    HostRequestRetainedLineage {
        output_artifact_ref: None,
        output_digest: state_result_digest(revision),
        producer_ref: Some("eliotd".to_owned()),
        source_revisions: None,
        source_state_fence: Some(envelope.state_fence.clone()),
        input_refs: None,
        transformation_lineage: None,
        closure_refs: None,
        policy_fence: None,
        origin_evidence_refs: None,
        semantic_receipt_ref: None,
        result_class: HostRequestRetainedResultClass::ExistingEvidenceRead,
        proof_ceiling: None,
        influence_state: InfluenceState::Unknown,
        instruction_taint: None,
    }
}

/// The admission receipt for one exact envelope, from the production issuer.
fn state_receipt(
    envelope: &HostRequestEnvelope,
) -> eliot_protocol::HostRequestAdmissionReceipt {
    eliot_protocol::HostRequestAdmissionReceipt::issue(envelope)
        .expect("admission receipt must issue for the exact envelope")
}

/// Stages and admits one State record through the real ORS lifecycle owner.
///
/// `requested_host_request_record` is the production projection of an envelope
/// onto a durable ORS row; `stage_host_request` and `advance_host_request` are
/// the owner's own persistence transitions. The row reaches `Admitted` with no
/// connection gate, no attempt claim and no peer identity — exactly the state
/// the real State arm admits at, and the state the ORS result owner walks
/// forward from.
fn stage_admitted_state(kernel: &KernelComposition, envelope: &HostRequestEnvelope) {
    let requested =
        host_request_route::requested_host_request_record(envelope).expect("state record builds");
    kernel
        .generation_gateway
        .ors
        .stage_host_request(&requested)
        .expect("stage must succeed");
    let operation_id = OperationIdentity::new(eliot_protocol::host_request_operation_id(envelope))
        .expect("operation identity");
    kernel
        .generation_gateway
        .ors
        .advance_host_request(
            &operation_id,
            &envelope.envelope_sha256,
            HostRequestState::Admitted,
            None,
        )
        .expect("advance must succeed")
        .expect("admitted record must read back");
}

/// Retains one State answer through the REAL ORS result owner and returns the
/// owner-stored `ResultReceived` row.
///
/// `persist_host_request_result` is the same owner the kernel's submit gate
/// ultimately commits through (`host_request_route.rs::submit_claimed_result`
/// -> `persist_host_request_result`); calling it directly is how a durable
/// State row is created WITHOUT routing through the unsynthesizable enqueue
/// connection gate. It validates the digest binding, walks the lifecycle to
/// `ResultReceived`, and persists the body and lineage itself, so the row the
/// validating reader sees is owner-stored.
fn retained_state_record(
    kernel: &KernelComposition,
    envelope: &HostRequestEnvelope,
    revision: u64,
) -> HostRequestRecord {
    stage_admitted_state(kernel, envelope);
    let operation_id = OperationIdentity::new(eliot_protocol::host_request_operation_id(envelope))
        .expect("operation identity");
    let digest = state_result_digest(revision);
    let lineage = state_lineage(envelope, revision);
    kernel
        .generation_gateway
        .ors
        .persist_host_request_result(
            &operation_id,
            &envelope.envelope_sha256,
            &digest,
            &state_answer(revision),
            None,
            Some(&lineage),
        )
        .expect("persist must not fail")
        .expect("the admitted record must retain a result")
}

/// Loads the durable record back out of the owner, so the reader is handed the
/// row AS STORED rather than an in-memory copy the test kept.
fn load_state_record(
    kernel: &KernelComposition,
    envelope: &HostRequestEnvelope,
) -> HostRequestRecord {
    let operation_id = OperationIdentity::new(eliot_protocol::host_request_operation_id(envelope))
        .expect("operation identity");
    kernel
        .generation_gateway
        .ors
        .load_host_request(&operation_id, &envelope.envelope_sha256)
        .expect("load must succeed")
        .expect("the state record must exist")
}

fn readback_kernel(name: &str) -> (std::path::PathBuf, KernelComposition, StateFence) {
    let root = std::env::temp_dir()
        .join(format!("eliot-kernel-state-readback-{name}-{}", std::process::id()));
    std::fs::remove_dir_all(&root).ok();
    std::fs::create_dir_all(&root).expect("test work root");
    let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
    let fence = kernel
        .front_door_policy
        .lock()
        .expect("front-door policy")
        .module_generation
        .state_fence
        .clone();
    (root, kernel, fence)
}

/// #2564 readback leg 1: a retained `eliot.state` answer is served through the
/// VALIDATING reader, and only the validating reader returns it.
///
/// An admitted State pair whose answer was retained through the real ORS result
/// owner produces a durable `ResultReceived` row; a later State read of that
/// same operation returns the exact stored body through
/// `host_request_route::local_read_replay_response`. The response is asserted
/// to equal the unvalidated `host_request_admitted_response` projection of the
/// SAME `(receipt, record)` — proving the validating reader serves the genuine
/// retained answer over the same durable values. The refusals that follow are
/// what make this "served WITH proof" rather than merely "served": the identical
/// triple with a substituted retained digest, and with a half-present pair, both
/// fail closed.
#[test]
fn retained_state_answer_is_served_by_the_validating_replay_reader() {
    let (root, kernel, fence) = readback_kernel("validating-reader");
    let tool = state_tool();
    let envelope =
        state_envelope(&fence, unix_ms().saturating_add(60_000), "host-request-state-1", &tool);
    let retained = retained_state_record(&kernel, &envelope, 3);

    // The durable row IS a real owner-stored State result under the state
    // capability; the validating reader is handed that stored row.
    assert_eq!(
        retained.state,
        HostRequestState::ResultReceived,
        "the retained state answer is an owner-closed ResultReceived row"
    );
    assert_eq!(
        retained.capability_ref.as_str(),
        host_request_route::local_read_state_capability(),
        "the retained row is stored under the STATE capability"
    );
    assert_eq!(
        retained.result_digest.as_deref(),
        Some(state_result_digest(3).as_str()),
        "the row records the exact result digest bound to its own preview bytes"
    );

    let stored = load_state_record(&kernel, &envelope);
    let receipt = state_receipt(&envelope);
    let served = host_request_route::local_read_replay_response(&receipt, &stored, &envelope)
        .expect("validating reader must not fail")
        .expect("a retained state row must replay");

    // The validating reader's answer is byte-identical to the admitted-response
    // projection of the same (receipt, record): it SERVES the genuine retained
    // answer, joined over the same durable values, not a recomputation.
    assert_eq!(
        served,
        host_request_route::host_request_admitted_response(&receipt, &stored),
        "the validating reader answers with the admitted-response projection of the SAME receipt and record"
    );
    assert_eq!(
        served["value"]["record"]["result_response"],
        state_answer(3),
        "the readback carries the exact retained preview bytes"
    );
    assert_eq!(
        served["value"]["record"]["result_digest"],
        serde_json::json!(state_result_digest(3)),
        "the readback carries the retained result digest, never a recomputed one over the caller's bytes"
    );

    // A substituted retained digest on the SAME row fails closed through the
    // validating reader: the stored lineage `output_digest` no longer matches
    // the (substituted) `result_digest`, so the reader refuses instead of
    // serving. This is the property the whole arm exists to add.
    let mut substituted = stored.clone();
    substituted.result_digest = Some("0".repeat(64));
    assert_eq!(
        host_request_route::local_read_replay_response(&receipt, &substituted, &envelope),
        Err(TransportError::SessionFenced),
        "the validating reader refuses a substituted retained digest that the unvalidated projection would still answer"
    );

    // A half-present pair (digest present, body absent) takes the fresh leg
    // (Ok(None)) and is never served as a partial answer.
    let mut half = stored.clone();
    half.result_response = None;
    assert_eq!(
        host_request_route::local_read_replay_response(&receipt, &half, &envelope)
            .expect("half-present pair must not fail"),
        None,
        "a half-present pair takes the fresh leg, never a partial serve"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

/// #2564 readback leg 2: the validating reader's retained-lineage binding fails
/// closed over a real State record.
///
/// The reader joins the RETAINED lineage `output_digest` against the RETAINED
/// `result_digest` (never a recomputed digest) and checks that the recorded
/// class is consistent with the recorded receipt (`host_request_route.rs:9979`-
/// `9994`). This drives both refusals over a genuine persisted row: a lineage
/// whose `output_digest` was substituted away from the stored digest, and a
/// non-canonical retained read forged to carry a semantic receipt it is not
/// classified for. Both must fail closed rather than serve or promote a
/// retained read into an admitted semantic record.
#[test]
fn validating_reader_refuses_a_forged_retained_lineage() {
    let (root, kernel, fence) = readback_kernel("forged-lineage");
    let tool = state_tool();
    let envelope = state_envelope(
        &fence,
        unix_ms().saturating_add(60_000),
        "host-request-state-forged",
        &tool,
    );
    let receipt = state_receipt(&envelope);
    retained_state_record(&kernel, &envelope, 3);
    let stored = load_state_record(&kernel, &envelope);

    // The genuine row is served, so the refusals below are the reader's own
    // proofs rather than a blanket denial.
    assert!(
        host_request_route::local_read_replay_response(&receipt, &stored, &envelope)
            .expect("validating reader must not fail")
            .is_some(),
        "the genuine retained state row is served"
    );

    // (a) A lineage whose recorded `output_digest` no longer equals the stored
    // `result_digest` is refused: nothing is recomputed here, so a forged
    // lineage cannot be made self-consistent from the caller's bytes.
    let mut substituted_lineage = stored.clone();
    let mut lineage = substituted_lineage
        .result_lineage
        .clone()
        .expect("the retained row records its lineage");
    lineage.output_digest = "1".repeat(64);
    substituted_lineage.result_lineage = Some(lineage);
    assert_eq!(
        host_request_route::local_read_replay_response(&receipt, &substituted_lineage, &envelope),
        Err(TransportError::SessionFenced),
        "a retained lineage whose output_digest does not bind the retained result digest is refused"
    );

    // (b) This row is a non-canonical ExistingEvidenceRead, which may NOT carry
    // a semantic receipt. Forging one makes the reader fail closed rather than
    // promote a retained read to an admitted semantic record.
    let mut forged_receipt_lineage = stored.clone();
    let mut lineage = forged_receipt_lineage
        .result_lineage
        .clone()
        .expect("the retained row records its lineage");
    lineage.semantic_receipt_ref = Some("semantic-receipt-forged".to_owned());
    forged_receipt_lineage.result_lineage = Some(lineage);
    assert_eq!(
        host_request_route::local_read_replay_response(&receipt, &forged_receipt_lineage, &envelope),
        Err(TransportError::SessionFenced),
        "a non-canonical retained read may not carry a semantic receipt"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}

/// #2564 readback leg 3: an exact replay of the retained State operation serves
/// the RETAINED historical result, byte for byte, and the durable row is
/// unchanged by serving it.
///
/// Replay preserves the original execution and result identity: the reader
/// re-executes nothing, overwrites nothing, and erases no earlier delivery, so
/// the same result identity and its recorded binding are what the caller sees.
/// What IS observable and asserted here is that the replay returns the
/// identical stored answer and that the durable row — including its commit
/// order — is byte-identical before and after the replay.
#[test]
fn exact_replay_serves_the_retained_result_and_leaves_the_row_unchanged() {
    let (root, kernel, fence) = readback_kernel("replay");
    let tool = state_tool();
    let envelope =
        state_envelope(&fence, unix_ms().saturating_add(60_000), "host-request-state-replay", &tool);
    let retained = retained_state_record(&kernel, &envelope, 3);
    let receipt = state_receipt(&envelope);

    let first = load_state_record(&kernel, &envelope);
    let served_first =
        host_request_route::local_read_replay_response(&receipt, &first, &envelope)
            .expect("validating reader must not fail")
            .expect("the retained state row must replay");
    assert_eq!(
        served_first["value"]["record"]["result_response"],
        state_answer(3),
        "the first readback serves the retained preview"
    );

    // An exact replay of the SAME operation returns the identical stored
    // answer, and leaves the durable row byte-identical: it re-executes nothing
    // and never advances the operation's commit order.
    let second = load_state_record(&kernel, &envelope);
    let served_second =
        host_request_route::local_read_replay_response(&receipt, &second, &envelope)
            .expect("validating reader must not fail")
            .expect("an exact replay must still serve");
    assert_eq!(
        served_second, served_first,
        "an exact replay returns the RETAINED historical result, byte for byte"
    );
    assert_eq!(
        served_second["value"]["record"]["result_response"],
        state_answer(3),
        "the replayed result is the ORIGINAL retained preview, not a recomputed one"
    );
    assert_eq!(
        second.commit_order, first.commit_order,
        "a replay never advances the operation's commit order"
    );
    assert_eq!(
        second, first,
        "serving a replay re-executes nothing: the durable row is byte-identical before and after"
    );
    assert_eq!(
        retained.commit_order, first.commit_order,
        "the retained row the owner persisted is the row replay reads"
    );

    drop(kernel);
    let _ = std::fs::remove_dir_all(root);
}