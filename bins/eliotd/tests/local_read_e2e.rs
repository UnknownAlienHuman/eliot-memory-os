//! QUERY-E2E (#18): admitted `eliot.query` answers end to end through the
//! production serving bridge.
//!
//! This file drives the new production edge
//! ([`eliotd::serve_admitted_local_read`]): capture `evidence-alpha`, bridge
//! the admitted `eliot.query` pair, serve it through
//! [`eliot_read::LocalReadPort::evidence_query`], and assert the exact
//! evidence record returns — never a bare admission. The three fail-closed
//! legs (wrong fence, packet admission-only, closed mode allowlist) are
//! preserved through the same bridge.
//!
//! Hermetic by construction: the port is served by a real in-test
//! [`CanonicalReadClient`] that derives every response field from the
//! incoming request (validation, operation, fence, selectors, catalogue
//! bound) plus the captured subjects — the same pattern as the in-crate
//! `local_read_bridge_serves_captured_evidence_and_fails_closed` proof, but
//! calling the production bridge instead of the unit internals. No live
//! Kernel pipe is touched: the Kernel admission mirror
//! (`check_local_read_admission` at
//! `bins/eliot-kernel/src/host_request_route.rs:1157`, served by
//! `local_read_operation` at
//! `bins/eliot-kernel/src/daemon_request_dispatch.rs:648`, MGR01-owned) is
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
    HOST_REQUEST_WIRE_ID, HostRequestEnvelope, HostRequestIdentity, HostRequestKind,
};
use eliot_read::{ProvenanceDisposition, ReadError, ReadProvenance, ReadService};
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
        matches!(fenced, Err(ReadError::Store(ref reason)) if reason == &StoreError::FenceMismatch.to_string()),
        "a wrong fence must fail closed as FenceMismatch, got {fenced:?}"
    );

    // Packet pairs stay admission-only: Unavailable, never a read.
    let packet = packet_tool();
    let packet_envelope = test_envelope("eliot.packet", &fence, &tool_digest(&packet)?)?;
    let admitted_only =
        eliotd::serve_admitted_local_read(&service, &fence, &packet_envelope, &packet).await;
    assert!(
        matches!(admitted_only, Err(ReadError::Store(ref reason)) if reason == &StoreError::Unavailable.to_string()),
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
        matches!(rejected, Err(ReadError::Store(ref reason)) if reason == &StoreError::InvalidField { field: "operation.parameter", reason: "query intent never admits the evidence pack for this mode" }.to_string()),
        "a non-evidence mode must fail closed as InvalidField, got {rejected:?}"
    );
    Ok(())
}
