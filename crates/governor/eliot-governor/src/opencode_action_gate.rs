//! Narrow Governor/authority pre-effect `ActionGate` adapter (issue #2898).
//!
//! The Governor is the pre-effect decision owner. This module is the narrow
//! adapter that joins that owner to the `OpenCode` host-event ingress
//! (`tool.execute.before`) without moving any decision into the HTTP handler:
//! [`GovernorActionGate::decide`] evaluates one request through the existing
//! [`GovernanceProfile::authorizes`] decision primitive under the *current*
//! Governor policy revision, and echoes the exact request hash it evaluated.
//!
//! Nothing here is new policy. The adapter:
//!
//! * admits a request only when the retained event/effect/session/fence
//!   bindings still hold the live Governor policy revision and the live
//!   bridge/authority fence — a moved fence or revision is a refusal, never a
//!   permit;
//! * decides through [`GovernanceProfile::authorizes`], the same primitive the
//!   Governor already uses for coverage/enforcement authorization, with the
//!   mutation-gate requirements (`requires_enforced`, `requires_complete`);
//! * binds the result to the exact request hash, so a crossed or stale
//!   decision can never authorize this operation;
//! * returns [`GovernorActionGateVerdict::Deny`] for every refusal, and
//!   never a synthesized `allow`.
//!
//! The decision/result commitment and expiry are the Governor's: this adapter
//! derives the receipt reference from the exact evaluated request hash and the
//! policy revision it was evaluated under, so the persisted decision identity
//! is a function of the evaluation itself rather than a value the transport
//! supplies.

use eliot_contracts::{EpochId, canonical_json_bytes, sha256_hex};
use eliot_integration_coverage::GovernanceProfile;

/// Exact requirements one `tool.execute.before` gate evaluation places on the
/// Governor profile. A mutating tool requires both enforced pre-action
/// coverage and complete coverage authority; a weaker requirement would let
/// observation-only authority authorize an effect.
pub const MUTATION_GATE_REQUIRES_ENFORCED: bool = true;
/// See [`MUTATION_GATE_REQUIRES_ENFORCED`].
pub const MUTATION_GATE_REQUIRES_COMPLETE: bool = true;

/// One exact pre-effect evaluation request, projected from the ingress
/// `ActionGate` request by the bridge composition.
///
/// Every field is the retained event/effect/session/fence binding plus the
/// current owner-state generation/epoch. Nothing is copied from a request
/// payload the transport controls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernorActionGateRequest {
    /// Stable logical operation identity.
    pub operation_id: String,
    /// Canonical request hash the decision must echo.
    pub request_hash: String,
    /// Recomputed effect digest the decision binds to.
    pub effect_digest: String,
    /// Exact mutating tool identity.
    pub tool: String,
    /// Bridge generation bound from current owner state.
    pub bridge_generation: u64,
    /// Authority epoch bound from current owner state.
    pub authority_epoch: EpochId,
    /// State fence bound from current owner state.
    pub fence_id: String,
}

/// One Governor pre-effect verdict, with the exact bindings the ingress
/// response must carry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GovernorActionGateVerdict {
    /// True only when the Governor authorizes this exact effect.
    pub allow: bool,
    /// Current policy revision the decision was evaluated under.
    pub policy_revision: String,
    /// Authority revision (profile fingerprint) the decision was evaluated
    /// under.
    pub authority_revision: String,
    /// Decision/result commitment over the exact evaluated request.
    pub decision_receipt: String,
    /// Closed deny reason code; `None` only when `allow` is true.
    pub reason_code: Option<GovernorActionGateRefusal>,
}

/// Closed Governor refusal reasons. Every variant is a refusal; none grants
/// an effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernorActionGateRefusal {
    /// No current Governor policy profile has been derived.
    NoCurrentPolicy,
    /// The live bridge/authority fence moved since the request was bound.
    StaleFence,
    /// The live authority epoch moved since the request was bound.
    StaleAuthority,
    /// The current Governor profile does not authorize this effect.
    PolicyDenied,
}

impl GovernorActionGateRefusal {
    /// Returns the exact closed wire reason code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoCurrentPolicy => "POLICY_REVISION_UNAVAILABLE",
            Self::StaleFence => "STALE_STATE_FENCE",
            Self::StaleAuthority => "STALE_AUTHORITY_EPOCH",
            Self::PolicyDenied => "POLICY_DENIED",
        }
    }
}

/// Computes the exact decision/result commitment for one evaluation: a
/// SHA-256 digest over the canonical tuple naming the operation, the exact
/// evaluated request hash, the policy revision and authority revision the
/// decision was made under, and the decision itself. The commitment is a
/// function of the evaluation, so a decision cannot be re-pointed at a
/// different operation or policy without changing it.
#[must_use]
pub fn decision_commitment(
    request: &GovernorActionGateRequest,
    policy_revision: &str,
    authority_revision: &str,
    allow: bool,
) -> String {
    let canonical = serde_json::Value::Array(vec![
        serde_json::Value::String("eliot.opencode.action-gate-decision.v1".to_owned()),
        serde_json::Value::String(request.operation_id.clone()),
        serde_json::Value::String(request.request_hash.clone()),
        serde_json::Value::String(request.effect_digest.clone()),
        serde_json::Value::String(request.tool.clone()),
        serde_json::Value::String(request.fence_id.clone()),
        serde_json::Value::String(policy_revision.to_owned()),
        serde_json::Value::String(authority_revision.to_owned()),
        serde_json::Value::Bool(allow),
    ]);
    canonical_json_bytes(&canonical).map_or_else(|_| sha256_hex(b""), |bytes| sha256_hex(&bytes))
}

/// Evaluates one exact pre-effect request under the current Governor policy.
///
/// This is a **total, pure** decision: it performs no I/O, reads no clock and
/// mints no state. `current_profile` is the live Governor-derived
/// [`GovernanceProfile`] or `None` when nothing has been derived; the `live_*`
/// arguments are the live owner-state binding the request must still match.
#[must_use]
pub fn decide_pre_effect(
    current_profile: Option<&GovernanceProfile>,
    request: &GovernorActionGateRequest,
    live_authority_epoch: &EpochId,
    live_fence_id: &str,
    live_bridge_generation: u64,
) -> GovernorActionGateVerdict {
    let Some(profile) = current_profile else {
        return refusal(request, GovernorActionGateRefusal::NoCurrentPolicy, "0", "");
    };
    if !live_authority_epoch.is_same_authority(&request.authority_epoch) {
        return refusal(
            request,
            GovernorActionGateRefusal::StaleAuthority,
            &profile.revision.to_string(),
            &profile.fingerprint,
        );
    }
    if live_fence_id != request.fence_id || live_bridge_generation != request.bridge_generation {
        return refusal(
            request,
            GovernorActionGateRefusal::StaleFence,
            &profile.revision.to_string(),
            &profile.fingerprint,
        );
    }
    let allow = profile.authorizes(
        MUTATION_GATE_REQUIRES_ENFORCED,
        MUTATION_GATE_REQUIRES_COMPLETE,
    );
    if !allow {
        return refusal(
            request,
            GovernorActionGateRefusal::PolicyDenied,
            &profile.revision.to_string(),
            &profile.fingerprint,
        );
    }
    let policy_revision = profile.revision.to_string();
    let decision_receipt =
        decision_commitment(request, &policy_revision, &profile.fingerprint, true);
    GovernorActionGateVerdict {
        allow: true,
        policy_revision,
        authority_revision: profile.fingerprint.clone(),
        decision_receipt,
        reason_code: None,
    }
}

/// Builds one closed refusal verdict with the exact bindings it was refused
/// under. A refusal still carries a decision commitment, so the refusal
/// itself is durably identifiable and cannot be swapped for an `allow`.
fn refusal(
    request: &GovernorActionGateRequest,
    reason: GovernorActionGateRefusal,
    policy_revision: &str,
    authority_revision: &str,
) -> GovernorActionGateVerdict {
    GovernorActionGateVerdict {
        allow: false,
        policy_revision: policy_revision.to_owned(),
        authority_revision: authority_revision.to_owned(),
        decision_receipt: decision_commitment(request, policy_revision, authority_revision, false),
        reason_code: Some(reason),
    }
}
