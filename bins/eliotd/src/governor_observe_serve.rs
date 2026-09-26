//! Governor observe serving adapter (issue #2565).
//!
//! Per-claim decoder over one Kernel-admitted `eliot.observe` pair: proves
//! the closed linkage and fence binding the Kernel already admitted, decodes
//! only the closed shared tool vocabulary (the five I7.6 suboperations), and
//! routes each suboperation through the one explicit owner map below.
//!
//! Caller chain: daemon runtime observe poller -> this decoder ->
//! `DaemonKernelClient::defer_observe_claim_async` (pair retired, durable
//! record `Routed`) or, once the matching owner admission connects,
//! `DaemonKernelClient::submit_observe_result_async` (retained result).
//!
//! Production edges out of this module:
//! [`serve_admitted_observe`] serves one admitted pair as an honest
//! [`ObserveDeferral`] naming its exact owner and resume condition;
//! [`decode_observe_suboperation`] decodes the closed vocabulary;
//! [`observe_suboperation_owner`] is the single suboperation-to-owner map.
//!
//! The Governor observation owner has no connected MCP-observe admission on
//! this path yet, so every served pair defers: no effect is produced and
//! none is claimed. A deferral is never completion — the pending handle
//! stays live under the daemon owner, the status/resolve/rehydrate entries
//! keep serving the live record, and resubmitting the same logical request
//! once the owner connects re-enqueues the pair for execution without
//! duplicating anything. Missing handler semantics stay with their owners
//! and never justify a second semantic engine here.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_protocol::{HostRequestEnvelope, LocalReadAttempt, host_request_operation_id};

/// Admitted capability this adapter serves.
const OBSERVE_CAPABILITY: &str = "eliot.observe";

/// The closed five observe suboperations (`eliot.observe`, I7.6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObserveSuboperation {
    /// What was observed, with source/effect metadata.
    Observation,
    /// Chosen path, alternatives and revisit condition.
    Decision,
    /// Failed path, signature, evidence and next discriminator.
    Failure,
    /// Actual artifact/effect/verifier result.
    Outcome,
    /// How a delivered memory item affected the next public decision.
    InfluenceAck,
}

impl ObserveSuboperation {
    /// Stable wire discriminator for this suboperation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Observation => "observation",
            Self::Decision => "decision",
            Self::Failure => "failure",
            Self::Outcome => "outcome",
            Self::InfluenceAck => "influence_ack",
        }
    }
}

/// One explicit owner route for an observe suboperation (issue #2565 item
/// 7: one handler/capability map with the exact real caller and the residual
/// owner for everything not yet connected).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserveOwnerRoute {
    /// Routed suboperation.
    pub suboperation: ObserveSuboperation,
    /// Missing owner admission that must connect before execution.
    pub owner_capability: &'static str,
    /// Program that owns the missing semantics (never this adapter).
    pub residual_owner: &'static str,
    /// Exact condition that resumes the deferred pair.
    pub resume: &'static str,
}

/// Returns the single recorded owner route for one suboperation.
///
/// Exhaustive over [`ObserveSuboperation`]: a new suboperation is a compile
/// error here until its owner, residual program, and resume condition are
/// recorded. The real caller for every row today is the daemon observe
/// poller (`bins/eliotd/src/daemon_runtime.rs`); the residual owner is the
/// Governor semantic program that must connect the matching admission
/// (integration #18).
pub fn observe_suboperation_owner(suboperation: ObserveSuboperation) -> ObserveOwnerRoute {
    match suboperation {
        ObserveSuboperation::Observation => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-admission",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the observation admission connects; exact replay re-enqueues the pair",
        },
        ObserveSuboperation::Decision => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-decision",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the decision admission connects; exact replay re-enqueues the pair",
        },
        ObserveSuboperation::Failure => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-failure",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the failure admission connects; exact replay re-enqueues the pair",
        },
        ObserveSuboperation::Outcome => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-outcome",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the outcome admission connects; exact replay re-enqueues the pair",
        },
        ObserveSuboperation::InfluenceAck => ObserveOwnerRoute {
            suboperation,
            owner_capability: "governor-observation-owner.mcp-observe-influence-ack",
            residual_owner: "Governor observation admission (integration #18)",
            resume: "resubmit the same logical request once the influence-ack admission connects; exact replay re-enqueues the pair",
        },
    }
}

/// Decodes only the closed shared observe vocabulary from linked tool bytes.
///
/// Returns the suboperation discriminator. The tool name must be the
/// admitted capability and `arguments.kind` must name exactly one of the
/// five I7.6 suboperations; anything else fails closed. No semantic field is
/// interpreted here — routing only.
pub fn decode_observe_suboperation(
    tool: &serde_json::Value,
) -> Result<ObserveSuboperation, String> {
    let object = tool
        .as_object()
        .ok_or_else(|| "daemon observe pair tool is not an object".to_owned())?;
    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "daemon observe pair tool omits the canonical tool name".to_owned())?;
    if name != OBSERVE_CAPABILITY {
        return Err("daemon observe pair tool is not the admitted observe capability".to_owned());
    }
    let kind = object
        .get("arguments")
        .and_then(serde_json::Value::as_object)
        .and_then(|arguments| arguments.get("kind"))
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            "daemon observe pair tool omits the suboperation discriminator".to_owned()
        })?;
    match kind {
        "observation" => Ok(ObserveSuboperation::Observation),
        "decision" => Ok(ObserveSuboperation::Decision),
        "failure" => Ok(ObserveSuboperation::Failure),
        "outcome" => Ok(ObserveSuboperation::Outcome),
        "influence_ack" => Ok(ObserveSuboperation::InfluenceAck),
        _ => Err("daemon observe pair tool names an unknown suboperation".to_owned()),
    }
}

/// Honest deferral for one served observe pair.
///
/// Names the exact owner admission that must connect, the residual program
/// that owns it, and the resume condition — never a result, never a receipt.
/// The daemon flight records this through the Kernel defer leg (pair
/// retired, durable record `Routed`) and the waiter keeps the live pending
/// handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObserveDeferral {
    /// Served suboperation.
    pub suboperation: ObserveSuboperation,
    /// Missing owner admission that must connect before execution.
    pub owner_capability: &'static str,
    /// Program that owns the missing semantics.
    pub residual_owner: &'static str,
    /// Exact condition that resumes the deferred pair.
    pub resume: &'static str,
}

/// Serves one admitted observe pair through the closed vocabulary.
///
/// Re-proves the admitted linkage (capability echoes the tool name,
/// canonical tool bytes digest to the admitted payload digest), the admitted
/// envelope shape, and the attempt binding (operation handle plus validated
/// capability) before any defer touches the pair. Returns the honest
/// deferral with its exact owner and resume condition. Pure: no IO, no
/// semantic interpretation, no invented receipt.
pub fn serve_admitted_observe(
    envelope: &HostRequestEnvelope,
    tool: &serde_json::Value,
    attempt: &LocalReadAttempt,
) -> Result<ObserveDeferral, String> {
    envelope
        .validate()
        .map_err(|error| format!("daemon observe pair envelope is not admitted shape: {error}"))?;
    if envelope.identity.capability != OBSERVE_CAPABILITY {
        return Err(
            "daemon observe pair envelope is not the admitted observe capability".to_owned(),
        );
    }
    attempt
        .validate()
        .map_err(|error| format!("daemon observe pair attempt is not bound shape: {error}"))?;
    if attempt.operation_id != host_request_operation_id(envelope) {
        return Err("daemon observe pair attempt does not bind the envelope".to_owned());
    }
    let object = tool
        .as_object()
        .ok_or_else(|| "daemon observe pair tool is not an object".to_owned())?;
    let name = object
        .get("name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "daemon observe pair tool omits the canonical tool name".to_owned())?;
    if name != envelope.identity.capability {
        return Err("daemon observe pair tool does not match the admitted capability".to_owned());
    }
    let bytes = canonical_json_bytes(tool)
        .map_err(|error| format!("daemon observe pair tool cannot be canonicalized: {error}"))?;
    if sha256_hex(&bytes) != envelope.identity.payload_sha256 {
        return Err(
            "daemon observe pair payload does not match the admitted payload digest".to_owned(),
        );
    }
    let suboperation = decode_observe_suboperation(tool)?;
    let route = observe_suboperation_owner(suboperation);
    Ok(ObserveDeferral {
        suboperation: route.suboperation,
        owner_capability: route.owner_capability,
        residual_owner: route.residual_owner,
        resume: route.resume,
    })
}
