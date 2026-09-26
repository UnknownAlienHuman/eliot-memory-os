//! Production `eliot.finish` claim servicing for the current daemon (issue #1741).
//!
//! Kernel owns admission, queue ownership, and the fenced attempt
//! capability. This adapter decodes the digest-bound strict finish draft,
//! delegates evaluation to the single Governor finish owner
//! ([`GovernorComposition::finish_attempt`]), and submits the exact typed
//! result through Kernel. The Finish service rehydrates current durable state;
//! a caller-supplied proof never reaches the derivation.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_protocol::FinishResultBody;
use eliot_receipts::ProofCeiling;
use serde::Serialize;
use serde_json::json;

use crate::{DaemonComposition, daemon_kernel_client::FinishClaimedInvocation};

/// Rejection content for one refused finish attempt. Every Governor or
/// decode failure is projected as a typed rejected response body; a refusal
/// must never terminate the daemon or escape as an untyped poll error.
#[derive(Debug, Serialize)]
struct FinishRejection {
    status: String,
    reason: String,
}

fn rejection(reason: &str) -> FinishRejection {
    FinishRejection {
        status: "rejected".to_owned(),
        reason: reason.to_owned(),
    }
}

/// Builds one exact bounded finish response JSON for the admitted operation.
///
/// The stored body is the full `McpResponse` JSON the bridge serves for the
/// admitted operation: request correlation, canonical request digest over
/// the admitted triple, the closed `eliot.finish` tool name, and the exact
/// content bytes bound by `result_digest`. The shape mirrors
/// `eliot_mcp::McpResponse` field-for-field; the bridge re-parses it with
/// `deny_unknown_fields`, so no extra field can ride along.
fn finish_response_json(
    claimed: &FinishClaimedInvocation,
    kind: &str,
    content: &serde_json::Value,
    proof_ceiling: ProofCeiling,
) -> Result<serde_json::Value, String> {
    let canonical_request_sha256 = sha256_hex(
        &canonical_json_bytes(&(
            claimed.envelope.envelope_sha256.clone(),
            claimed.envelope.identity.request_id.clone(),
            claimed.envelope.identity.idempotency_key.clone(),
        ))
        .map_err(|error| format!("finish response serialization failed: {error}"))?,
    );
    Ok(json!({
        "request_id": claimed.envelope.identity.request_id.clone(),
        "idempotency_key": claimed.envelope.identity.idempotency_key.clone(),
        "canonical_request_sha256": canonical_request_sha256,
        "kind": kind,
        "canonical_tool_name": "eliot.finish",
        "content": content.clone(),
        "artifacts": [],
        "proof_ceiling": proof_ceiling,
        "resource": null,
        "job": null,
    }))
}

fn finish_result_body(
    claimed: &FinishClaimedInvocation,
    response: serde_json::Value,
) -> Result<FinishResultBody, String> {
    let response_bytes = canonical_json_bytes(&response)
        .map_err(|error| format!("finish result serialization failed: {error}"))?;
    let body = FinishResultBody {
        wire_id: eliot_protocol::FINISH_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::FINISH_RESULT_BODY_WIRE_VERSION,
        operation_id: claimed.operation_id.as_str().to_owned(),
        request_sha256: claimed.envelope.envelope_sha256.clone(),
        result_digest: sha256_hex(&response_bytes),
        response,
        attempt: claimed.attempt.clone(),
    };
    body.validate()
        .map_err(|error| format!("finish result validation failed: {error}"))?;
    Ok(body)
}

/// Serves one exact Kernel-claimed `eliot.finish` candidate.
///
/// The draft is decoded authoritatively here (`deny_unknown_fields`: the strict
/// candidate set and nothing else) and evaluated by the Governor finish
/// owner against rehydrated canonical state. A caller-supplied
/// `completion_proof` reaches the Finish service, which rejects it with
/// `CallerProofRejected`; no weaker path exists.
#[allow(
    clippy::large_futures,
    clippy::too_many_lines,
    reason = "the claim boundary preserves one exact owner evaluation and one fenced result body"
)]
pub async fn serve_finish_claim(
    composition: &mut DaemonComposition,
    claimed: FinishClaimedInvocation,
) -> Result<FinishResultBody, String> {
    let arguments = claimed
        .tool
        .get("arguments")
        .cloned()
        .ok_or_else(|| "claimed finish pair omits the admitted draft".to_owned())?;
    let draft: eliot_governor::FinishAttemptDraft = serde_json::from_value(arguments)
        .map_err(|error| format!("admitted finish draft does not decode: {error}"))?;
    let outcome = composition
        .finish_attempt(
            &claimed.request_identity,
            claimed.operation_id.clone(),
            draft,
        )
        .await;
    match outcome {
        Ok(receipt) => {
            let content = serde_json::to_value(&receipt)
                .map_err(|error| format!("finish decision projection failed: {error}"))?;
            let response = finish_response_json(
                &claimed,
                "CANDIDATE",
                &content,
                ProofCeiling::ScopedVerification,
            )?;
            finish_result_body(&claimed, response)
        }
        Err(error) => {
            let content = serde_json::to_value(rejection(&error.to_string()))
                .map_err(|error| format!("finish rejection projection failed: {error}"))?;
            let response =
                finish_response_json(&claimed, "PLAN_GAP", &content, ProofCeiling::Observation)?;
            finish_result_body(&claimed, response)
        }
    }
}
