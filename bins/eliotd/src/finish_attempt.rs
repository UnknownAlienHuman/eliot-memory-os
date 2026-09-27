//! Production `eliot.finish` claim servicing for the current daemon (issue #1741).
//!
//! Kernel owns admission, queue ownership, and the fenced attempt
//! capability. This adapter decodes the digest-bound strict candidate draft,
//! prepares the Governor-owned evidence and decision legs, exchanges each
//! immutable leg with the composition lock released, and revalidates each
//! completed leg against the live owner before continuing. It returns the
//! exact typed result body for the runtime to submit through Kernel. The Finish
//! service rehydrates current durable state; proof-like extra fields fail the
//! strict draft decode and never reach the service.

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_governor::FinishAttemptError;
use eliot_protocol::FinishResultBody;
use eliot_receipts::ProofCeiling;
use serde::Serialize;
use serde_json::json;

use crate::{DaemonComposition, DaemonKernelClient, daemon_kernel_client::FinishClaimedInvocation};

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

fn rejected_finish_result(
    claimed: &FinishClaimedInvocation,
    error: FinishAttemptError,
) -> Result<FinishResultBody, String> {
    let content = serde_json::to_value(rejection(&error.to_string()))
        .map_err(|error| format!("finish rejection projection failed: {error}"))?;
    let response = finish_response_json(claimed, "PLAN_GAP", &content, ProofCeiling::Observation)?;
    finish_result_body(claimed, response)
}

/// Serves one exact Kernel-claimed `eliot.finish` candidate.
///
/// The draft is decoded authoritatively here (`deny_unknown_fields`: the strict
/// candidate set and nothing else) and evaluated by the Governor finish
/// owner against rehydrated canonical state. A proof-like extra field fails
/// strict candidate deserialization before the Governor Finish service is
/// called; no weaker path exists.
#[allow(
    clippy::large_futures,
    clippy::too_many_lines,
    reason = "the claim boundary preserves one exact owner evaluation and one fenced result body"
)]
pub async fn serve_finish_claim(
    kernel: &DaemonKernelClient,
    composition: &std::sync::Arc<tokio::sync::Mutex<DaemonComposition>>,
    claimed: FinishClaimedInvocation,
) -> Result<FinishResultBody, String> {
    let arguments = claimed
        .tool
        .get("arguments")
        .cloned()
        .ok_or_else(|| "claimed finish pair omits the admitted draft".to_owned())?;
    let draft: eliot_governor::FinishAttemptDraft = serde_json::from_value(arguments)
        .map_err(|error| format!("admitted finish draft does not decode: {error}"))?;

    // Plan the evidence exchange while the composition is borrowed, then run
    // Kernel IO with no composition lock held.
    let evidence = {
        let guard = composition.lock().await;
        guard.prepare_finish_evidence(&claimed.request_identity, &claimed.operation_id, &draft)
    };
    let evidence = match evidence {
        Ok(evidence) => evidence,
        Err(error) => return rejected_finish_result(&claimed, error),
    };
    if let Some(prepared) = evidence.as_ref() {
        if let Err(error) = prepared.exchange(kernel).await {
            return rejected_finish_result(&claimed, error);
        }
        let accepted = {
            let guard = composition.lock().await;
            guard.accept_prepared_finish_exchange(prepared)
        };
        if let Err(error) = accepted {
            return rejected_finish_result(&claimed, error);
        }
    }

    // This refreshes the owner and derives the exact decision exchange from
    // the image published by the evidence leg. Its transport is also unlocked.
    let decision = {
        let mut guard = composition.lock().await;
        guard.prepare_finish_decision(&claimed.request_identity, &claimed.operation_id, draft)
    };
    let decision = match decision {
        Ok(decision) => decision,
        Err(error) => return rejected_finish_result(&claimed, error),
    };
    if let Some(prepared) = decision.exchange() {
        if let Err(error) = prepared.exchange(kernel).await {
            return rejected_finish_result(&claimed, error);
        }
        let accepted = {
            let guard = composition.lock().await;
            guard.accept_prepared_finish_exchange(prepared)
        };
        if let Err(error) = accepted {
            return rejected_finish_result(&claimed, error);
        }
    }
    let receipt = decision.into_decision();
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
