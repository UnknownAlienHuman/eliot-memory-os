//! Governor act serving adapter (issue #1739 W5 act-consumer join).
//!
//! Per-claim decoder over one Kernel-admitted digest-only `eliot.act`
//! invocation: proves the closed dispatch binding and fence binding the
//! Kernel already admitted, then routes the pair through the one explicit
//! owner below.
//!
//! Caller chain: daemon runtime act poller -> this decoder ->
//! `DaemonKernelClient::defer_act_claim_async` (pair retired, durable
//! record `Routed`) or, once the matching owner admission connects,
//! the Governor action-model owner's fenced result submit (a future join,
//! never here).
//!
//! Production edges out of this module:
//! [`serve_admitted_act`] serves one admitted pair as an honest
//! [`ActDeferral`] naming its exact owner and resume condition.
//!
//! The Governor action-model owner has no connected MCP-act admission on
//! this path yet, so every served pair defers: no effect is produced and
//! none is claimed. A deferral is never completion — the pending handle
//! stays live under the daemon owner, the status/resolve/rehydrate entries
//! keep serving the live record, and resubmitting the same logical request
//! once the owner connects re-enqueues the pair for execution without
//! duplicating anything. Requesting a lease is not executing arbitrary
//! caller code: the material floor/lineage/authority verdict belongs to the
//! owner's `eliot-context-admission::admit_material_decision` (I01-08
//! external effect path), never to this adapter. Missing handler semantics
//! stay with their owners and never justify a second semantic engine here.

#![forbid(unsafe_code)]

use eliot_protocol::{HostRequestEnvelope, LocalReadAttempt, host_request_operation_id};

/// Admitted capability this adapter serves.
const ACT_CAPABILITY: &str = "eliot.act";

/// Missing owner admission that must connect before act execution.
pub const ACT_OWNER_CAPABILITY: &str = "governor-action-model.mcp-act-admission";

/// Program that owns the missing act semantics (never this adapter).
pub const ACT_RESIDUAL_OWNER: &str =
    "Governor action model and Task Controller (integration #18; admit_material_decision owner)";

/// Exact condition that resumes a deferred act pair.
pub const ACT_RESUME: &str =
    "resubmit the same logical request once the action-model admission connects; exact replay re-enqueues the pair";

/// Honest deferral for one served act pair.
///
/// Names the exact owner admission that must connect, the residual program
/// that owns it, and the resume condition — never a result, never a receipt.
/// The daemon flight records this through the Kernel defer leg (pair
/// retired, durable record `Routed`) and the waiter keeps the live pending
/// handle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActDeferral {
    /// Missing owner admission that must connect before execution.
    pub owner_capability: &'static str,
    /// Program that owns the missing semantics.
    pub residual_owner: &'static str,
    /// Exact condition that resumes the deferred pair.
    pub resume: &'static str,
}

/// Serves one admitted act pair through the closed dispatch binding.
///
/// Re-proves the admitted linkage (the envelope names the admitted `eliot.act`
/// capability with the `Invocation` kind the submit entry serves), the
/// admitted envelope shape, and the attempt binding (operation handle plus
/// validated capability admitted for this facet) before any defer touches
/// the pair. Act submits carry no tool bytes — the envelope digest commits
/// to the exact canonical request through admission — so there is no payload
/// to re-link here; a swapped capability or a non-invocation kind fails
/// closed. Returns the honest deferral with its exact owner and resume
/// condition. Pure: no IO, no semantic interpretation, no invented receipt,
/// no effect.
pub fn serve_admitted_act(
    envelope: &HostRequestEnvelope,
    attempt: &LocalReadAttempt,
) -> Result<ActDeferral, String> {
    envelope
        .validate()
        .map_err(|error| format!("daemon act pair envelope is not admitted shape: {error}"))?;
    if envelope.identity.capability != ACT_CAPABILITY {
        return Err(
            "daemon act pair envelope is not the admitted act capability".to_owned(),
        );
    }
    if envelope.kind != eliot_protocol::HostRequestKind::Invocation {
        return Err(
            "daemon act pair envelope is not the admitted invocation kind".to_owned(),
        );
    }
    attempt
        .validate()
        .map_err(|error| format!("daemon act pair attempt is not bound shape: {error}"))?;
    if attempt.operation_id != host_request_operation_id(envelope) {
        return Err("daemon act pair attempt does not bind the envelope".to_owned());
    }
    // Issue #1739 W5: the claim joins the Governor dispatch only through
    // the attempt minted for this admitted operation. A capability minted
    // for another facet never dispatches here, even when its shape
    // validates — the defer leg would quarantine it, but the dispatch
    // refuses it before any owner routing.
    if attempt.facet_method != ACT_CAPABILITY {
        return Err(
            "daemon act pair attempt is not admitted for the act operation".to_owned(),
        );
    }
    Ok(ActDeferral {
        owner_capability: ACT_OWNER_CAPABILITY,
        residual_owner: ACT_RESIDUAL_OWNER,
        resume: ACT_RESUME,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds the smallest envelope JSON that decodes: every field present
    /// with admitting types. Shape validation still fails (digests,
    /// fence, identity separation), which is exactly the fail-closed
    /// property these tests pin: nothing unadmitted is ever served.
    fn undecodable_envelope() -> HostRequestEnvelope {
        serde_json::from_value(serde_json::json!({
            "wire_id": "bogus",
            "wire_version": 0,
            "kind": "Invocation",
            "connection_id": "conn",
            "identity": {},
            "state_fence": {},
            "descriptor_sha256": "x",
            "peer_admission_receipt_sha256": "x",
            "activation_binding": null,
            "envelope_sha256": "x",
        }))
        .expect("test envelope JSON must decode to the struct shape")
    }

    fn unbound_attempt() -> LocalReadAttempt {
        serde_json::from_value(serde_json::json!({
            "wire_id": "bogus",
            "wire_version": 0,
            "operation_id": "hostreq:00",
            "attempt_id": "attempt",
            "fencing_generation": 1,
            "session_id": "session",
            "authority_epoch": {},
            "scope_id": "scope",
            "facet_method": "eliot.act",
            "expires_at_unix_ms": 1,
            "use_budget": 1,
        }))
        .expect("test attempt JSON must decode to the struct shape")
    }

    #[test]
    fn act_serve_refuses_envelope_outside_admitted_shape() {
        let error = serve_admitted_act(&undecodable_envelope(), &unbound_attempt())
            .expect_err("an unadmitted envelope must never serve");
        assert!(
            error.contains("not admitted shape"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn act_serve_names_the_action_model_owner_without_effect() {
        // The deferral constants are the whole steady-state contract while
        // the owner admission is unconnected: exact owner, residual program,
        // and resume condition, with no result and no receipt.
        assert_eq!(ACT_OWNER_CAPABILITY, "governor-action-model.mcp-act-admission");
        assert!(ACT_RESIDUAL_OWNER.contains("admit_material_decision"));
        assert!(ACT_RESUME.contains("exact replay re-enqueues the pair"));
    }
}
