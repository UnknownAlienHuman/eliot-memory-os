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
use eliot_governor::{CompositionError, FinishAttemptError, KernelTransitionPort};
use eliot_protocol::{AgentResponseDisposition, FinishResultBody};
use eliot_receipts::ProofCeiling;
use eliot_store_api::{TransitionClass, WriteReceiptStatus};
use serde::Serialize;
use serde_json::json;

use crate::{
    DaemonComposition, DaemonKernelClient,
    daemon_kernel_client::{
        FinishClaimedInvocation, LEGACY_FINISH_PROOF_MEMBER, LEGACY_FINISH_PROOF_REJECTION,
    },
};

/// Rejection content for one refused finish attempt. Every Governor or
/// decode failure is projected as a typed rejected response body; a refusal
/// must never terminate the daemon or escape as an untyped poll error.
///
/// `status`/`reason` are the historical bridge-visible fields and are kept
/// verbatim; `disposition`/`reason_code` add the I7.20 agent-facing control
/// pair so a refusal never escapes as untyped prose. The response envelope
/// shape is unchanged.
#[derive(Debug, Serialize)]
struct FinishRejection {
    status: String,
    reason: String,
    disposition: String,
    reason_code: String,
}

fn rejection(reason: &str, cause: (AgentResponseDisposition, &'static str)) -> FinishRejection {
    FinishRejection {
        status: "rejected".to_owned(),
        reason: reason.to_owned(),
        disposition: cause.0.as_str().to_owned(),
        reason_code: cause.1.to_owned(),
    }
}

/// Projects one finish failure onto the I7.20 agent-facing control pair.
///
/// `reason` keeps the exact owner error verbatim, so unknown or future
/// failures are preserved rather than silently becoming success; this pair
/// adds the stable closed disposition plus the exact additive reason code.
/// Every code used here is a verbatim member of the `AGENT_REASON_CODES`
/// registry. A refused Finish decision means the decision context could not
/// be completed; a refused composition stays recovery-typed; a failed Kernel
/// transition or uncommitted mutation stays runtime-typed.
fn finish_rejection_cause(error: &FinishAttemptError) -> (AgentResponseDisposition, &'static str) {
    match error {
        FinishAttemptError::Composition(CompositionError::NotReady) => (
            AgentResponseDisposition::UnavailableOrCapacity,
            "DEFERRED_CAPACITY",
        ),
        FinishAttemptError::Composition(_) => (
            AgentResponseDisposition::RecoveryRequired,
            "RECOVERY_REQUIRED",
        ),
        FinishAttemptError::UnreconciledMaterialChange
        | FinishAttemptError::UnverifiedChangeHint => (
            AgentResponseDisposition::RecoveryRequired,
            "OBSERVATION_GAP",
        ),
        FinishAttemptError::Kernel(_) | FinishAttemptError::Store(_) => {
            (AgentResponseDisposition::Failed, "RUNTIME_FAILED")
        }
        // Issue #1741, I7.9: the contract owner's acceptance denominator could
        // not be rehydrated or disagrees with the plan's declared set. The
        // decision context is incomplete, so this is the same
        // `DECISION_CONTEXT_INCOMPLETE` refusal as a rehydrated owner state that
        // does not validate — never a degraded success and never the plan's own
        // list.
        FinishAttemptError::AcceptanceDenominator(_)
        | FinishAttemptError::Finish(_)
        | FinishAttemptError::Serialization(_) => (
            AgentResponseDisposition::Failed,
            "DECISION_CONTEXT_INCOMPLETE",
        ),
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

fn rejected_finish_result_with_detail(
    claimed: &FinishClaimedInvocation,
    reason: &str,
    cause: (AgentResponseDisposition, &'static str),
) -> Result<FinishResultBody, String> {
    let content = serde_json::to_value(rejection(reason, cause))
        .map_err(|error| format!("finish rejection projection failed: {error}"))?;
    let response = finish_response_json(claimed, "PLAN_GAP", &content, ProofCeiling::Observation)?;
    finish_result_body(claimed, response)
}

fn rejected_finish_result(
    claimed: &FinishClaimedInvocation,
    error: &FinishAttemptError,
) -> Result<FinishResultBody, String> {
    rejected_finish_result_with_detail(claimed, &error.to_string(), finish_rejection_cause(error))
}

/// Rejects one claimed candidate that carries a legacy caller-supplied proof.
///
/// I7.9 pins this exact code: the candidate is refused with
/// `LEGACY_FINISH_INPUT_REJECTED` and never evaluated. The refusal is
/// submitted as the typed result body for the admitted attempt — the same
/// submitted-rejection shape the lane already uses — so the poisoned claim is
/// consumed instead of stalling the queue as a poll error.
fn rejected_legacy_finish_proof(
    claimed: &FinishClaimedInvocation,
) -> Result<FinishResultBody, String> {
    rejected_finish_result_with_detail(
        claimed,
        LEGACY_FINISH_PROOF_REJECTION,
        (
            AgentResponseDisposition::InvalidRequest,
            "LEGACY_FINISH_INPUT_REJECTED",
        ),
    )
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
    // The claim parser already rejects the exact legacy proof member with its
    // pinned code; this re-check keeps the same typed refusal for any direct
    // caller of the serve path before strict decoding could only report a
    // generic unknown-field failure.
    if arguments.get(LEGACY_FINISH_PROOF_MEMBER).is_some() {
        return rejected_legacy_finish_proof(&claimed);
    }
    let draft: eliot_governor::FinishAttemptDraft = serde_json::from_value(arguments)
        .map_err(|error| format!("admitted finish draft does not decode: {error}"))?;

    // Exact retries are historical receipt reads. Refresh the persisted Finish
    // projection and match the original attempt before current task, plan,
    // attachment, or acceptance guards can turn a committed decision into a
    // stale-task refusal. A changed draft under the same admitted identity is
    // rejected by the owner receipt's original attempt digest.
    let historical = {
        let mut guard = composition.lock().await;
        if let Err(error) = guard.refresh_testd_terminal_owner() {
            return rejected_finish_result_with_detail(
                &claimed,
                &error.to_string(),
                (AgentResponseDisposition::RecoveryRequired, "RECOVERY_REQUIRED"),
            );
        }
        guard.historical_finish_receipt(
            &claimed.request_identity,
            &claimed.operation_id,
            &draft,
            &claimed.attempt,
        )
    };
    let historical = match historical {
        Ok(receipt) => receipt,
        Err(error) => return rejected_finish_result(&claimed, &error),
    };
    if let Some(receipt) = historical {
        let write_receipt = match kernel.receipt(claimed.operation_id.clone()).await {
            Ok(Some(receipt)) => receipt,
            Ok(None) => {
                return rejected_finish_result_with_detail(
                    &claimed,
                    "retained Finish decision has no canonical receipt for its original operation",
                    (AgentResponseDisposition::RecoveryRequired, "RECOVERY_REQUIRED"),
                );
            }
            Err(error) => {
                return rejected_finish_result_with_detail(
                    &claimed,
                    &format!("original Finish operation receipt read failed: {error}"),
                    (AgentResponseDisposition::RecoveryRequired, "RECOVERY_REQUIRED"),
                );
            }
        };
        if let Err(error) = write_receipt.validate() {
            return rejected_finish_result_with_detail(
                &claimed,
                &format!("original Finish operation receipt is invalid: {error}"),
                (AgentResponseDisposition::RecoveryRequired, "RECOVERY_REQUIRED"),
            );
        }
        if write_receipt.operation_id != claimed.operation_id
            || write_receipt.idempotency_key != claimed.request_identity.idempotency_key
            || write_receipt.state_fence != claimed.envelope.state_fence
            || write_receipt.transition_class != TransitionClass::RecoverySchema
            || write_receipt.status != WriteReceiptStatus::Committed
        {
            return rejected_finish_result_with_detail(
                &claimed,
                "canonical receipt does not bind the original committed Finish operation",
                (AgentResponseDisposition::RecoveryRequired, "RECOVERY_REQUIRED"),
            );
        }
        let content = serde_json::to_value(&receipt)
            .map_err(|error| format!("finish decision projection failed: {error}"))?;
        let response = finish_response_json(
            &claimed,
            "CANDIDATE",
            &content,
            ProofCeiling::ScopedVerification,
        )?;
        return finish_result_body(&claimed, response);
    }

    // Issue #1782 (I11.11 line 42, I14.24 line 23): "Any request to continue
    // Material work before that disposition returns
    // `EXTERNAL_ATTACH_RECONCILIATION_REQUIRED`", and "deny proof/finish and
    // further Material work until reconciliation". Historical committed
    // readback above is allowed; a genuinely new Finish remains subject to the
    // current attachment guard before evidence preparation.
    let attach_refusal = {
        let guard = composition.lock().await;
        guard
            .admit_material_continuation_after_attach(
                eliot_workscope::RequestedEffect::MaterialEffect,
            )
            .err()
            .map(|error| error.to_string())
    };
    if let Some(detail) = attach_refusal {
        return rejected_finish_result_with_detail(
            &claimed,
            &detail,
            (
                AgentResponseDisposition::Denied,
                crate::external_attach_reconciliation::EXTERNAL_ATTACH_RECONCILIATION_REQUIRED,
            ),
        );
    }

    // Issue #1741, I7.9: rehydrate the contract owner's acceptance-item
    // enumeration for this exact task id BEFORE any evidence is prepared. The
    // task revision is read by the Governor finish owner from its live
    // task-lifecycle record; this lane supplies only the task id, so the
    // denominator read can never be aimed at a revision the caller chose. This
    // is one bounded read on the existing authenticated Kernel named-read
    // route, so the composition borrow is held across it; the two write legs
    // below still run with no lock held across their exchange, as before. A
    // refusal here is a typed rejection body: the plan's own
    // `required_acceptance_item_ids` are never used as the denominator, so a
    // candidate whose plan narrows the contract's obligations cannot proceed.
    let task_id = eliot_contracts::TaskId::new(draft.task_id.clone())
        .map_err(|error| format!("admitted finish draft names an invalid task: {error}"))?;

    // Issue #1741, I7.9: the Finish service rehydrates the Task Controller's
    // current plan revision for this exact task before it reads any acceptance
    // denominator, because the denominator is joined against that plan and the
    // canonical owner carried no plan at all until this leg existed. The plan
    // identity is derived inside the Governor from the Task-selection owner's
    // own same-fence, task-bound accepted receipt and the live task record; this
    // lane supplies only the task id, so no caller can hand the canonical owner a
    // plan of its own choosing.
    //
    // It is prepared under the composition lock and exchanged with the lock
    // released, exactly like every other canonical owner leg here. When the owner
    // already holds this plan the Governor returns `None` and nothing is
    // exchanged, so a replayed candidate never mints a second owner revision.
    let plan_operation_id = eliot_contracts::OperationId::new(format!(
        "{}/current-plan",
        claimed.operation_id.as_str()
    ))
    .map_err(|error| format!("current-plan operation identity is invalid: {error}"))?;
    let current_plan = {
        let guard = composition.lock().await;
        guard.prepare_current_plan_admission(
            &claimed.request_identity,
            &plan_operation_id,
            &task_id,
        )
    };
    let current_plan = match current_plan {
        Ok(prepared) => prepared,
        Err(error) => return rejected_finish_result(&claimed, &error),
    };
    if let Some(prepared) = current_plan.as_ref() {
        if let Err(error) = prepared.exchange(kernel).await {
            return rejected_finish_result(&claimed, &error);
        }
        let accepted = {
            let guard = composition.lock().await;
            guard.accept_prepared_finish_exchange(prepared)
        };
        if let Err(error) = accepted {
            return rejected_finish_result(&claimed, &error);
        }
        // Issue #1741, I7.9: the committed plan has to reach the owner image
        // before the evidence leg is derived. `accept_prepared_finish_exchange`
        // re-checks only the pre-commit fence, so without this publication the
        // image still carries the all-absent `current_plan` and
        // `prepare_finish_evidence` refuses at `read_current_plan` — which would
        // leave exact artifacts, executed verifier runs and effect outcomes
        // unrehydrated on every live candidate. This is the one existing owner
        // publication entry point, the same
        // `DaemonComposition::refresh_testd_terminal_owner` the TestD terminal
        // ceremony already uses between its fact leg and its evidence leg, over
        // the same `refresh_from_kernel` recovery read. A second named entry
        // point for one action would be a second scheme, so there is none. A
        // refusal here is a typed rejected result body, never a locally derived
        // plan.
        let published = {
            let mut guard = composition.lock().await;
            guard.refresh_testd_terminal_owner()
        };
        if let Err(error) = published {
            return rejected_finish_result_with_detail(
                &claimed,
                &error.to_string(),
                (
                    AgentResponseDisposition::RecoveryRequired,
                    "RECOVERY_REQUIRED",
                ),
            );
        }
    }

    let contract_acceptance = {
        let guard = composition.lock().await;
        guard.rehydrate_task_contract_acceptance(&task_id).await
    };
    let contract_acceptance = match contract_acceptance {
        Ok(acceptance) => acceptance,
        Err(error) => return rejected_finish_result(&claimed, &error),
    };

    // Plan the evidence exchange while the composition is borrowed, then run
    // Kernel IO with no composition lock held.
    let evidence = {
        let guard = composition.lock().await;
        guard.prepare_finish_evidence(
            &claimed.request_identity,
            &claimed.operation_id,
            &draft,
            &contract_acceptance,
        )
    };
    let evidence = match evidence {
        Ok(evidence) => evidence,
        Err(error) => return rejected_finish_result(&claimed, &error),
    };
    if let Some(prepared) = evidence.as_ref() {
        if let Err(error) = prepared.exchange(kernel).await {
            return rejected_finish_result(&claimed, &error);
        }
        let accepted = {
            let guard = composition.lock().await;
            guard.accept_prepared_finish_exchange(prepared)
        };
        if let Err(error) = accepted {
            return rejected_finish_result(&claimed, &error);
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
        Err(error) => return rejected_finish_result(&claimed, &error),
    };
    if let Some(prepared) = decision.exchange() {
        if let Err(error) = prepared.exchange(kernel).await {
            return rejected_finish_result(&claimed, &error);
        }
        let accepted = {
            let guard = composition.lock().await;
            guard.accept_prepared_finish_exchange(prepared)
        };
        if let Err(error) = accepted {
            return rejected_finish_result(&claimed, &error);
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
