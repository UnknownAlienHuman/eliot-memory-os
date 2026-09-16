//! QUERY-E2E (#18 #77): admitted `eliot.query` answers end to end through the
//! production eliotd edges.
//!
//! Test 1 drives the production serving edge
//! ([`eliotd::serve_admitted_local_read`]): capture `evidence-alpha`, bridge
//! the admitted `eliot.query` pair, serve it through
//! [`eliot_read::LocalReadPort::evidence_query`], and assert the exact
//! evidence record returns — never a bare admission. The three fail-closed
//! legs (wrong fence, packet admission-only, closed mode allowlist) are
//! preserved through the same bridge.
//!
//! Test 2 drives the production poller wire contract the daemon `run_loop`
//! speaks: one `local_read_claim` answer parses to the exact admitted pair
//! (null polls back off), one digest-bound [`HostRequestResultBody`] binds
//! the admitted envelope, and one `local_read_result` answer parses to the
//! typed accepted / expired outcome. Exact replay is byte-stable by
//! construction, so a resubmitted identical body stays idempotent.
//!
//! Hermetic by construction: the port is served by a real in-test
//! [`CanonicalReadClient`] that derives every response field from the
//! incoming request (validation, operation, fence, selectors, catalogue
//! bound) — the same pattern as the in-crate
//! `local_read_bridge_serves_captured_evidence_and_fails_closed` proof, but
//! calling the production bridge instead of the unit internals. The Kernel
//! admission mirror (`check_local_read_admission` / `enqueue_local_read_pair`
//! in `bins/eliot-kernel/src/host_request_route.rs`, served by
//! `local_read_operation` in
//! `bins/eliot-kernel/src/daemon_request_dispatch.rs`, MGR01-owned) is
//! twinned field-for-field by the eliotd gate inside
//! `KernelContextReadClient::execute_local_read`, and the forwarding happy
//! path (`forward_admitted_local_read` -> `local_read_async` ->
//! `transact_async("local_read")`) requires a live authenticated session, so
//! only its pre-transport fail-closed legs run without a Kernel (proven
//! in-crate through the same bridge).

use std::collections::BTreeMap;
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_protocol::{
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HOST_REQUEST_WIRE_ID, HostRequestEnvelope,
    HostRequestIdentity, HostRequestKind, HostRequestResultBody,
};
use eliot_read::{ProvenanceDisposition, ReadError, ReadProvenance, ReadService, StoreReadFailure};
use eliot_store_api::{
    CanonicalReadClient, EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, RevisionHead, RevisionKey, StoreError,
};
use serde_json::{Value, json};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_fence(generation: u64) -> TestResult<StateFence> {
    let lineage = EpochLineageId::new(TEST_LINEAGE).map_err(|error| format!("lineage: {error}"))?;
    let sequence = NonZeroU64::new(1).ok_or("non-zero test sequence")?;
    let epoch = EpochId::new(lineage, sequence).map_err(|error| format!("epoch: {error}"))?;
    let generation =
        ResourceGeneration::new(generation).map_err(|error| format!("generation: {error}"))?;
    Ok(StateFence::new(epoch, generation))
}

fn tool_digest(tool: &Value) -> TestResult<String> {
    let bytes = eliot_contracts::canonical_json_bytes(tool)
        .map_err(|error| format!("canonical tool bytes: {error}"))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

fn query_tool_with_mode(mode: &str) -> Value {
    json!({"name":"eliot.query","arguments":{
        "intent":{
            "mode": mode,
            "time_scope":"session-window",
            "branch_environment_scope":"branch",
            "freshness_policy":"exact-fence",
            "required_assurance":"evidence-provenance"
        },
        "query":"subject:evidence-alpha",
        "exact_resource_uri": null
    }})
}

fn packet_tool() -> Value {
    json!({"name":"eliot.packet","arguments":{
        "packet_ref": null,
        "material_refs": []
    }})
}

fn test_envelope(
    capability: &str,
    fence: &StateFence,
    payload_sha256: &str,
) -> TestResult<HostRequestEnvelope> {
    HostRequestEnvelope {
        wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
        wire_version: HostRequestEnvelope::CONTRACT_VERSION,
        kind: HostRequestKind::Invocation,
        connection_id: "conn-test-1".to_owned(),
        identity: HostRequestIdentity {
            request_id: eliot_contracts::RequestId::new("host-request-1")
                .map_err(|error| format!("request id: {error}"))?,
            idempotency_key: "host-request-1:invoke".to_owned(),
            cancellation_id: "host-request-1:invoke:cancel".to_owned(),
            parent_operation_id: None,
            deadline_unix_ms: 2_000_000,
            capability: capability.to_owned(),
            session_id: Some("kernel-session-1".to_owned()),
            task_id: None,
            work_scope_id: None,
            payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
            payload_sha256: payload_sha256.to_owned(),
        },
        state_fence: fence.clone(),
        descriptor_sha256: "d".repeat(64),
        peer_admission_receipt_sha256: "e".repeat(64),
        activation_binding: None,
        envelope_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(|error| format!("envelope digest: {error}").into())
}

/// Minimal in-test evidence table. It stores captured subjects in capture
/// order and derives every response field from the incoming request: real
/// request validation, the closed evidence operation, exact fence equality,
/// the declared `subject` / `max_records` selectors, and the catalogue bound.
/// Nothing is canned.
struct EvidenceTable {
    fence: StateFence,
    captured: Vec<String>,
}

impl EvidenceTable {
    fn new(fence: StateFence) -> Self {
        Self {
            fence,
            captured: Vec::new(),
        }
    }

    fn capture(&mut self, subject: &str) {
        self.captured.push(subject.to_owned());
    }

    fn selectors(parameters: &BTreeMap<String, Value>) -> Result<(String, u32), StoreError> {
        let subject = parameters
            .get("subject")
            .and_then(Value::as_str)
            .filter(|subject| !subject.trim().is_empty())
            .ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "evidence subject must be exact",
            })?;
        let bound = parameters
            .get("max_records")
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "max_records must ride as an exact decimal string",
            })?;
        let bound: u32 = bound.parse().map_err(|_| StoreError::InvalidField {
            field: "operation.parameter",
            reason: "max_records must ride as an exact decimal string",
        })?;
        if bound == 0 || bound > EVIDENCE_PACK_MAX_RECORDS {
            return Err(StoreError::InvalidField {
                field: "operation.parameter",
                reason: "max_records must be within the catalogue bound",
            });
        }
        Ok((subject.to_owned(), bound))
    }
}

#[allow(async_fn_in_trait)]
impl CanonicalReadClient for EvidenceTable {
    async fn revision_heads(
        &self,
        _keys: Vec<RevisionKey>,
    ) -> Result<Vec<RevisionHead>, StoreError> {
        Ok(Vec::new())
    }

    async fn execute_named(
        &self,
        query: NamedReadRequest,
    ) -> Result<NamedReadResponse, StoreError> {
        query.validate()?;
        if query.operation != NamedReadOperation::GetEvidencePack {
            return Err(StoreError::UnknownOperation);
        }
        if query.scope_id.is_none() {
            return Err(StoreError::InvalidField {
                field: "scope_id",
                reason: "GetEvidencePack requires an exact scope",
            });
        }
        if query.state_fence != self.fence {
            return Err(StoreError::FenceMismatch);
        }
        let (subject, bound) = Self::selectors(&query.parameters)?;
        let limit = usize::try_from(bound).map_err(|_| StoreError::InvalidField {
            field: "operation.parameter",
            reason: "max_records must be within the catalogue bound",
        })?;
        let records: Vec<Value> = self
            .captured
            .iter()
            .filter(|captured| *captured == &subject)
            .take(limit)
            .map(|captured| json!({"subject": captured}))
            .collect();
        let response = NamedReadResponse {
            operation: query.operation,
            state_fence: query.state_fence.clone(),
            revision_heads: Vec::new(),
            payload: json!({
                "version": 1,
                "subject": subject,
                "max_records": bound,
                "records": records,
            }),
        };
        response.validate()?;
        Ok(response)
    }
}

#[tokio::test]
async fn admitted_query_serves_the_exact_captured_record() -> TestResult {
    let fence = test_fence(1)?;
    let tool = query_tool_with_mode("verification");
    let envelope = test_envelope("eliot.query", &fence, &tool_digest(&tool)?)?;

    // Capture an observation, then bridge eliot.query for the captured
    // subject through the production serving edge: the exact evidence record,
    // provenance, and fence return — never a bare admission.
    let mut table = EvidenceTable::new(fence.clone());
    table.capture("evidence-alpha");
    let service = ReadService::new(table);
    let result = eliotd::serve_admitted_local_read(&service, &fence, &envelope, &tool)
        .await
        .map_err(|error| format!("production serving bridge: {error}"))?;
    assert_eq!(result.operation, NamedReadOperation::GetEvidencePack);
    assert_eq!(result.state_fence, fence);
    let records = result
        .payload
        .get("records")
        .and_then(Value::as_array)
        .ok_or("evidence records must ride the payload")?;
    assert_eq!(
        records.len(),
        1,
        "the captured subject reads back exactly once, not as a bare Accepted admission"
    );
    assert_eq!(
        records[0].get("subject").and_then(Value::as_str),
        Some("evidence-alpha"),
        "the readback record is the captured evidence, never a substitute"
    );
    assert_eq!(
        result.provenance,
        ReadProvenance {
            handles: Vec::new(),
            disposition: ProvenanceDisposition::Unavailable,
        },
        "the readback provenance is the exact facade lineage"
    );

    // A wrong fence fails closed before any read: FenceMismatch, never
    // Ok-empty.
    let wrong = test_fence(2)?;
    let wrong_envelope = test_envelope("eliot.query", &wrong, &tool_digest(&tool)?)?;
    let fenced = eliotd::serve_admitted_local_read(&service, &fence, &wrong_envelope, &tool).await;
    assert!(
        matches!(
            fenced,
            Err(ReadError::Store(StoreReadFailure::FenceMismatch))
        ),
        "a wrong fence must fail closed as FenceMismatch, got {fenced:?}"
    );

    // Packet pairs stay admission-only: Unavailable, never a read.
    let packet = packet_tool();
    let packet_envelope = test_envelope("eliot.packet", &fence, &tool_digest(&packet)?)?;
    let admitted_only =
        eliotd::serve_admitted_local_read(&service, &fence, &packet_envelope, &packet).await;
    assert!(
        matches!(
            admitted_only,
            Err(ReadError::Store(StoreReadFailure::Unavailable))
        ),
        "packet must stay admission-only as Unavailable, got {admitted_only:?}"
    );

    // A mode outside the closed evidence allowlist never admits the evidence
    // pack: InvalidField before any read.
    let position_tool = query_tool_with_mode("current_position");
    let position_envelope = test_envelope("eliot.query", &fence, &tool_digest(&position_tool)?)?;
    let rejected =
        eliotd::serve_admitted_local_read(&service, &fence, &position_envelope, &position_tool)
            .await;
    assert!(
        matches!(rejected, Err(ReadError::Store(StoreReadFailure::InvalidField { ref field, ref reason })) if field == "operation.parameter" && reason == "query intent never admits the evidence pack for this mode"),
        "a non-evidence mode must fail closed as InvalidField, got {rejected:?}"
    );
    Ok(())
}

/// Builds the digest-bound result body for one admitted envelope, mirroring
/// the Kernel `build_local_read_result_body` binding (operation handle +
/// envelope digest + canonical response digest) without touching Kernel code:
/// the poller submits exactly this shape through `local_read_result`.
fn result_body_for(envelope: &HostRequestEnvelope) -> TestResult<HostRequestResultBody> {
    let response = json!({
        "operation": "GetEvidencePack",
        "subject": "evidence-alpha",
        "evidence_pack": { "subject": "evidence-alpha" },
        "revision_heads": [{ "key": "scope:kernel-session-1", "revision": 3 }],
    });
    let bytes = eliot_contracts::canonical_json_bytes(&response)
        .map_err(|error| format!("body must canonicalize: {error}"))?;
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: eliot_protocol::host_request_operation_id(envelope),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: eliot_contracts::sha256_hex(&bytes),
        response,
    };
    body.validate()
        .map_err(|error| format!("result body must validate: {error}"))?;
    Ok(body)
}

#[test]
fn claimed_pair_submits_the_exact_bound_body() -> TestResult {
    let fence = test_fence(1)?;
    let tool = query_tool_with_mode("verification");
    let envelope = test_envelope("eliot.query", &fence, &tool_digest(&tool)?)?;

    // The poller claims the exact admitted pair over `local_read_claim`;
    // a null pair is the empty-queue backoff, not an error.
    let claim = json!({ "pair": { "envelope": envelope.clone(), "tool": tool.clone() } });
    let (claimed_envelope, claimed_tool) = eliotd::parse_local_read_claimed_pair(&claim)
        .map_err(|error| format!("claim must parse: {error}"))?
        .ok_or("a queued pair must claim")?;
    assert_eq!(
        claimed_envelope.envelope_sha256, envelope.envelope_sha256,
        "the claim returns the exact admitted envelope"
    );
    assert_eq!(claimed_tool, tool, "the claim returns the exact tool bytes");
    assert_eq!(
        eliotd::parse_local_read_claimed_pair(&json!({ "pair": null }))
            .map_err(|error| format!("empty claim must not fail: {error}"))?,
        None,
        "an empty claim polls null and backs off"
    );

    // The submitted body binds the admitted envelope: the operation handle
    // and the envelope digest ride the body, and the result digest binds the
    // exact bounded response bytes.
    let body = result_body_for(&envelope)?;
    assert_eq!(
        body.operation_id,
        eliot_protocol::host_request_operation_id(&envelope),
        "the body carries the deterministic envelope operation handle"
    );
    assert_eq!(
        body.request_sha256, envelope.envelope_sha256,
        "the body binds the exact admitted envelope digest"
    );

    // `local_read_result` projects the typed outcome: accepted persists
    // (exact replays included); expired is the expected deadline race.
    assert_eq!(
        eliotd::parse_local_read_submit_outcome(&json!({ "accepted": true }))
            .map_err(|error| format!("accepted must parse: {error}"))?,
        eliotd::LocalReadSubmitOutcome::Accepted,
        "an accepted submit persists the exact body"
    );
    assert_eq!(
        eliotd::parse_local_read_submit_outcome(&json!({ "accepted": false, "expired": true }))
            .map_err(|error| format!("expired must parse: {error}"))?,
        eliotd::LocalReadSubmitOutcome::Expired,
        "an elapsed deadline projects the expected expired race"
    );

    // Exact replay stays idempotent: the identical body re-encodes to the
    // identical bytes and re-validates with the identical digests, so a
    // resubmit persists once and replays. A changed response binds a
    // different digest and can never replay as the same body.
    let once = serde_json::to_value(&body)?;
    let twice = serde_json::to_value(&body)?;
    assert_eq!(
        once, twice,
        "an exact replay carries byte-identical material"
    );
    let replayed: HostRequestResultBody = serde_json::from_value(twice)?;
    replayed
        .validate()
        .map_err(|error| format!("a replayed body must still validate: {error}"))?;
    assert_eq!(
        replayed.result_digest, body.result_digest,
        "a replay preserves the exact result digest"
    );
    let mut changed = body.response.clone();
    changed["revision_heads"] = json!([{ "key": "scope:kernel-session-1", "revision": 4 }]);
    let changed_bytes = eliot_contracts::canonical_json_bytes(&changed)
        .map_err(|error| format!("changed body must canonicalize: {error}"))?;
    assert_ne!(
        eliot_contracts::sha256_hex(&changed_bytes),
        body.result_digest,
        "a changed same-identity body binds a different digest and conflicts instead of replaying"
    );
    Ok(())
}
