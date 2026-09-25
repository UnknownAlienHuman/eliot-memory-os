//! Skill pair dispatch for the daemon local-read poller (issue #1882).
//!
//! Serves claimed pairs whose tool name routes to a Skill kind (see
//! [`skill_tool_kind`](eliot_agent_bridge_core::skill_transport::skill_tool_kind))
//! locally through the composition-held Skill driver instead of forwarding
//! them on the Kernel `local_read` leg (which serves store reads only).
//! Intake pairs decode to the wire intake, resolve canonical procedure
//! acceptance over the authenticated Kernel route, and drive install→receipt
//! only for owner-accepted material (issue #1191); display pairs decode to
//! the wire display request and drive ack→display.
//! Every claimed pair settles through a result body — including refusals,
//! which persist as typed refusal outcomes — so no skill pair can poison the
//! poller into a crash loop. Only transport and submit-leg failures fail the
//! daemon closed.
//!
//! The pair arrives Kernel-admitted (capability linkage proven at intake);
//! the tool/capability coherence is re-checked here defensively, and the
//! admitted fence comes from the composition's live snapshot through the
//! existing injector and carry entries — never from a re-stated claim.

#![forbid(unsafe_code)]

use eliot_agent_bridge_core::{SkillResultEnvelope, SkillToolKind, skill_tool_kind};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_protocol::{
    HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestEnvelope, HostRequestResultBody, LocalReadAttempt,
};
use serde_json::Value;
use thiserror::Error;

use super::DaemonComposition;
use super::daemon_kernel_client::DaemonKernelClient;
///
/// Driver refusals (stale, drift, unavailable, fence) are NOT errors here —
/// they persist as typed refusal outcomes through [`SkillResultEnvelope`],
/// so every claimed pair settles through the submit leg.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum SkillDispatchError {
    /// Tool bytes are not a Skill request object.
    #[error("skill pair tool is not a well-formed skill request")]
    MalformedTool,
    /// Presented tool name does not match the admitted capability.
    #[error("skill pair capability does not match its tool name")]
    CapabilityMismatch,
    /// Result body fails its closed shape.
    #[error("skill pair result body fails its shape: {0}")]
    Body(String),
}

/// Routes one claimed pair tool to Skill handling, if it names one.
///
/// Thin predicate over the shared routing table for the poller: returns
/// `true` exactly when the tool JSON carries a Skill capability name. The
/// poller serves such pairs locally through [`serve_skill_pair`]; anything
/// else keeps the existing forward path byte-identical.
#[must_use]
pub fn is_skill_tool(tool: &Value) -> bool {
    tool.as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .is_some_and(|name| skill_tool_kind(name).is_some())
}

/// Serves one claimed skill pair through the canonical acceptance drive and
/// returns its submit-leg result body.
///
/// Recognizes the tool name through the shared routing predicate, checks
/// tool/capability coherence, decodes the versioned wire payload, resolves
/// canonical procedure acceptance over the authenticated Kernel route for
/// intake (driving install→receipt only for owner-accepted material) or
/// ack→display for display requests, and binds the outcome — receipt,
/// display, or typed refusal — into a digest-bound result body for the
/// submit leg. Async only for the acceptance read; the composition drive
/// itself stays synchronous with guards never crossing an await.
pub async fn serve_skill_pair(
    composition: &DaemonComposition,
    kernel: &DaemonKernelClient,
    envelope: &HostRequestEnvelope,
    tool: &Value,
    attempt: &LocalReadAttempt,
) -> HostRequestResultBody {
    let outcome = drive_accepted_skill_request(composition, kernel, envelope, tool).await;
    // Body construction is total over validated inputs; a failure here is a
    // local defect, failed closed by the caller, never a silent accept.
    skill_result_body(envelope, attempt, &outcome)
        .unwrap_or_else(|error| skill_refusal_body(envelope, attempt, &error.to_string()))
}

async fn drive_accepted_skill_request(
    composition: &DaemonComposition,
    kernel: &DaemonKernelClient,
    envelope: &HostRequestEnvelope,
    tool: &Value,
) -> SkillResultEnvelope {
    let name = tool
        .as_object()
        .and_then(|object| object.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("");
    let Some(kind) = skill_tool_kind(name) else {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::Surface(
            "not a Skill tool request".to_owned(),
        ));
    };
    if name != envelope.identity.capability {
        return SkillResultEnvelope::refused(&eliot_skill::SkillError::Surface(
            "presented tool does not match the admitted capability".to_owned(),
        ));
    }
    let arguments = tool
        .as_object()
        .and_then(|object| object.get("arguments"))
        .cloned()
        .unwrap_or(Value::Null);
    match kind {
        SkillToolKind::Inject => drive_accepted_inject(composition, kernel, &arguments).await,
        SkillToolKind::Display => drive_display(composition, &arguments),
    }
}

/// Drives one decoded intake through the canonical acceptance verdict.
///
/// The wire intake entry decodes once here, the presented package digest
/// resolves against the canonical committed lifecycle-policy rows, and the
/// canonical verdict — never the wire procedure stamp — decides the drive. Accepted intakes bind their
/// presented procedure to the committed row and drive the decoded payload
/// plus that owner provenance into the composition; Unknown digests (absent
/// rows, or rows superseded by a newer committed package) refuse: absence
/// of a row proves nothing, so a wire-claimed Accepted stamp with no owner
/// backing cannot bind material, provisional or otherwise — the intake
/// remains a reversible candidate until governed promotion commits a row
/// for it (I7.25).
async fn drive_accepted_inject(
    composition: &DaemonComposition,
    kernel: &DaemonKernelClient,
    arguments: &Value,
) -> SkillResultEnvelope {
    let bytes = match canonical_json_bytes(&arguments).map_err(|error| error.to_string()) {
        Ok(bytes) => bytes,
        Err(detail) => {
            return SkillResultEnvelope::refused(&eliot_skill::SkillError::Surface(format!(
                "intake arguments fail their shape: {detail}"
            )));
        }
    };
    let payload = match eliot_agent_bridge_core::SkillIntakePayload::decode(&bytes)
        .map_err(|error| error.to_string())
    {
        Ok(payload) => payload,
        Err(detail) => {
            return SkillResultEnvelope::refused(&eliot_skill::SkillError::Surface(format!(
                "intake arguments fail their shape: {detail}"
            )));
        }
    };
    let admitted = composition.kernel_snapshot().state_fence().clone();
    match super::skill_acceptance_read::resolve_intake_acceptance(
        kernel,
        &admitted,
        &payload.package.registration.skill_id,
        &payload.package.digests.source_digest,
    )
    .await
    {
        Ok(super::skill_acceptance_read::AcceptanceVerdict::Accepted(record)) => {
            if let Err(error) = bind_accepted_intake(&payload, &record) {
                return SkillResultEnvelope::refused(&error);
            }
            match composition.skill_ingest_accepted_intake(&payload, &record) {
                Ok((_, receipt)) => SkillResultEnvelope::receipt(receipt),
                Err(error) => SkillResultEnvelope::refused(&error),
            }
        }
        Ok(super::skill_acceptance_read::AcceptanceVerdict::Unknown) => {
            SkillResultEnvelope::refused(&eliot_skill::SkillError::InvalidField {
                field: "procedure.acceptance",
                reason: "no committed lifecycle row backs this package digest at the current revision; the intake remains a reversible candidate until governed promotion",
            })
        }
        Ok(super::skill_acceptance_read::AcceptanceVerdict::Revoked(_)) => {
            SkillResultEnvelope::refused(&eliot_skill::SkillError::InvalidField {
                field: "procedure.acceptance",
                reason: "canonical lifecycle revoked this package revision",
            })
        }
        Err(error) => {
            SkillResultEnvelope::refused(&eliot_skill::SkillError::Surface(error.to_string()))
        }
    }
}

/// Binds one presented wire intake to its canonical committed acceptance row.
///
/// Payload-level consistency for the Accepted drive: the presented skill and
/// package must be exactly the row's skill and accepted package digest, the
/// presented procedure verifier must name the row's accepting verifier, and
/// the presented procedure stamp must agree with the row's acceptance. Every
/// check is consistency with owner state, never authority from the wire —
/// the row decides acceptance, and the candidate-level binding (stamped
/// material, receipt verifier, fence, scope, task) runs inside the
/// composition rehydration against the same row.
///
/// The crate error travels by value here like the Governor lifecycle API it
/// feeds, so the size lint is allowed for this boundary function.
#[allow(clippy::result_large_err)]
fn bind_accepted_intake(
    payload: &eliot_agent_bridge_core::SkillIntakePayload,
    record: &super::skill_acceptance_read::AcceptanceRecord,
) -> Result<(), eliot_skill::SkillError> {
    if payload.package.registration.skill_id != record.skill_id {
        return Err(eliot_skill::SkillError::IdentityMismatch);
    }
    if payload.package.digests.source_digest != record.package_digest {
        return Err(eliot_skill::SkillError::IdentityMismatch);
    }
    if payload.candidate.procedure.verifier.verifier_ref != record.verifier_ref {
        return Err(eliot_skill::SkillError::InvalidField {
            field: "candidate.procedure.verifier",
            reason: "procedure verifier is not the canonically accepting verifier",
        });
    }
    if !matches!(
        payload.candidate.procedure.state,
        eliot_skill::ProcedureState::Accepted
    ) {
        return Err(eliot_skill::SkillError::InvalidField {
            field: "candidate.procedure.state",
            reason: "committed row accepts this package but the presented procedure disagrees",
        });
    }
    Ok(())
}

fn drive_display(composition: &DaemonComposition, arguments: &Value) -> SkillResultEnvelope {
    let payload = match canonical_json_bytes(&arguments)
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            eliot_agent_bridge_core::SkillDisplayPayload::decode(&bytes)
                .map_err(|error| error.to_string())
        }) {
        Ok(payload) => payload,
        Err(detail) => {
            return SkillResultEnvelope::refused(&eliot_skill::SkillError::Surface(format!(
                "display arguments fail their shape: {detail}"
            )));
        }
    };
    match composition.skill_carry_receipt_to_display(
        &payload.skill_id,
        payload.receipt,
        payload.ack,
    ) {
        Ok(display) => SkillResultEnvelope::display(display),
        Err(error) => SkillResultEnvelope::refused(&error),
    }
}

/// Binds one skill outcome into the submit-leg result body.
pub fn skill_result_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    outcome: &SkillResultEnvelope,
) -> Result<HostRequestResultBody, SkillDispatchError> {
    let response = serde_json::to_value(outcome)
        .map_err(|error| SkillDispatchError::Body(error.to_string()))?;
    if !response.is_object() {
        return Err(SkillDispatchError::Body(
            "skill outcome must encode as a JSON object".to_owned(),
        ));
    }
    let bytes = canonical_json_bytes(&response)
        .map_err(|error| SkillDispatchError::Body(error.to_string()))?;
    let body = HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: sha256_hex(&bytes),
        response,
        attempt: Some(attempt.clone()),
    };
    body.validate()
        .map_err(|error| SkillDispatchError::Body(error.to_string()))?;
    Ok(body)
}

fn skill_refusal_body(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
    detail: &str,
) -> HostRequestResultBody {
    // Last-resort body for local construction failures: fixed shape, bounded
    // detail, same digest binding. Infallible by construction for validated
    // inputs; a failure here would already have failed closed above.
    let response = serde_json::json!({
        "contract_version": eliot_agent_bridge_core::SKILL_TRANSPORT_VERSION,
        "outcome": {
            "Refused": {
                "code": "SURFACE",
                "detail": detail.chars().take(512).collect::<String>(),
            }
        }
    });
    let outcome = SkillResultEnvelope {
        contract_version: eliot_agent_bridge_core::SKILL_TRANSPORT_VERSION,
        outcome: eliot_agent_bridge_core::SkillResultOutcome::Refused {
            code: "SURFACE".to_owned(),
            detail: detail.chars().take(512).collect::<String>(),
        },
    };
    skill_result_body(envelope, attempt, &outcome).unwrap_or_else(|_| HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: attempt.operation_id.clone(),
        request_sha256: envelope.envelope_sha256.clone(),
        result_digest: sha256_hex(response.to_string().as_bytes()),
        response,
        attempt: Some(attempt.clone()),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};

    use eliot_protocol::{
        HOST_REQUEST_WIRE_ID, HostRequestIdentity, HostRequestKind, host_request_operation_id,
    };

    fn fence() -> eliot_contracts::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        StateFence::new(
            EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero")).expect("valid test epoch"),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn envelope() -> HostRequestEnvelope {
        HostRequestEnvelope {
            wire_id: HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: HostRequestEnvelope::CONTRACT_VERSION,
            kind: HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: HostRequestIdentity {
                request_id: eliot_contracts::RequestId::new("host-request-1").expect("request id"),
                idempotency_key: "host-request-1:invoke".to_owned(),
                cancellation_id: "host-request-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: "skill.inject".to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: "eliot.skill.transport/v2".to_owned(),
                payload_sha256: "d".repeat(64),
            },
            state_fence: fence(),
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("envelope digest")
    }

    fn attempt(envelope: &HostRequestEnvelope) -> LocalReadAttempt {
        let operation_id = host_request_operation_id(envelope);
        LocalReadAttempt {
            wire_id: eliot_protocol::LOCAL_READ_ATTEMPT_WIRE_ID.to_owned(),
            wire_version: LocalReadAttempt::CONTRACT_VERSION,
            operation_id: operation_id.clone(),
            attempt_id: format!("{operation_id}:attempt:test-boot:7:1"),
            fencing_generation: 1,
            session_id: "kernel-session-1".to_owned(),
            authority_epoch: envelope.state_fence.authority_epoch.clone(),
            scope_id: "kernel-session-1".to_owned(),
            facet_method: "skill.inject".to_owned(),
            expires_at_unix_ms: envelope.identity.deadline_unix_ms,
            use_budget: 1,
        }
    }

    #[test]
    fn result_body_binds_operation_request_response_and_attempt() {
        let envelope = envelope();
        let attempt = attempt(&envelope);
        let outcome = SkillResultEnvelope::refused(&eliot_skill::SkillError::FenceMismatch);
        let body = skill_result_body(&envelope, &attempt, &outcome).expect("result body builds");
        body.validate().expect("result body validates");
        assert_eq!(body.operation_id, attempt.operation_id);
        assert_eq!(body.request_sha256, envelope.envelope_sha256);
        let echoed = body.attempt.expect("attempt echoed");
        assert_eq!(echoed.attempt_id, attempt.attempt_id);
        assert_eq!(echoed.fencing_generation, attempt.fencing_generation);
    }
}
