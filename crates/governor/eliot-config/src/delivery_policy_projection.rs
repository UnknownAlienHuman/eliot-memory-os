//! O2 policy-owner projection: typed facts over live `ConfigPolicySnapshot`
//! owner state, plus the exact delivery-policy inventory with no live owner.
//!
//! Ownership (read first):
//! - The Governor `PolicyOwner`
//!   (`crates/governor/eliot-governor/src/composition.rs`) recovers one
//!   `ConfigPolicySnapshot` per kernel named-read reply (owner, fence,
//!   revision, and digest correlated against the actual canonical bytes).
//!   [`project_policy_owner_facts`] projects exactly that live snapshot:
//!   it validates first, then yields only owned facts with a computed
//!   digest. It takes the snapshot by borrow — never caller text — and
//!   holds no state across calls.
//! - The planner's `ReactiveDeliveryPolicy`
//!   (`crates/smart/eliot-reactive-context-plan/src/input.rs`) is a
//!   versioned, caller-supplied limits-and-choices input. No owner crate
//!   mints its 22 choice fields live (verified by grep at base `8eba4022`:
//!   the only constructors are test scaffolding). [`ConfigPolicySnapshot`]
//!   settings are opaque config entries (`key` / `value_ref` / `owner_ref`)
//!   and are NEVER converted into delivery bounds, modes, reserves,
//!   priorities, or disclosure rules — different vocabularies, no `From`
//!   bridge, by repository rule.
//!
//! Explicit non-mapping (`ConfigPolicySnapshot` → `ReactiveDeliveryPolicy`):
//!
//! ```text
//! snapshot.snapshot_id        → snapshot identity only (NOT policy.policy_id)
//! snapshot.revision           → config generation only (NOT policy.policy_revision)
//! snapshot.policy_owner       → Human identity ref only (NOT request/operation/idempotency)
//! snapshot.settings[*].key    → opaque config key only (NOT a bound, reserve, mode,
//!                               priority, disclosure rule, target event,
//!                               delivery contract, or delivery profile)
//! snapshot.state_fence        → fence binding only (NOT observed_at/team clock)
//! <no live owner>             → policy_id, policy_revision, request_id,
//!                               operation_id, idempotency_key, target_event_id,
//!                               target_event, delivery_profile,
//!                               delivery_contract, allowed_modes,
//!                               max_input_bytes, max_items, max_references,
//!                               max_work, max_delivery_bytes, max_delivery_stu,
//!                               fixed_reserve, protocol_reserve, output_reserve,
//!                               review_reserve, delivery_reserve, priority,
//!                               attention_disclosure
//! ```
//!
//! A resolver consumes [`project_policy_owner_facts`] for the live
//! policy-owner facts (revision, fence, owner, setting keys, digest) and
//! fails closed with [`missing_delivery_policy_facts`] for the rest, so it
//! drops into D2's `serve_live_six_slot` unchanged: same names, same
//! envelope-first order, never a forged envelope.

use eliot_contracts::{PolicyRevision, StateFence, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{ConfigError, ConfigPolicySnapshot, SourceCompleteness};

/// Live policy-owner facts projected from one validated snapshot.
///
/// Every field is owned by the snapshot; `facts_digest` is computed over
/// the canonical JSON of the owned facts (never caller-asserted, never
/// the caller-supplied snapshot digest echoed).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyOwnerFacts {
    /// Snapshot identity from the live policy owner.
    pub snapshot_id: String,
    /// Machine the snapshot applies to.
    pub machine_id: String,
    /// Scope the snapshot applies to.
    pub scope_id: String,
    /// Durable policy revision (config generation, not a delivery revision).
    pub revision: PolicyRevision,
    /// Source completeness admitted with the snapshot (always `Complete`
    /// after validation; carried so the digest binds it).
    pub source_completeness: SourceCompleteness,
    /// Human owner reference from the live policy owner.
    pub owner_ref: String,
    /// Opaque config setting keys, sorted. Keys only: values are
    /// owner-held references and are never delivery-policy content.
    pub setting_keys: Vec<String>,
    /// Exact owner fence of the snapshot.
    pub state_fence: StateFence,
    /// `sha256` over the canonical JSON of the owned facts above.
    pub facts_digest: String,
}

/// Canonical digest input: the owned facts without their stored digest.
#[derive(Serialize)]
struct CanonicalPolicyOwnerFacts<'a> {
    snapshot_id: &'a str,
    machine_id: &'a str,
    scope_id: &'a str,
    revision: PolicyRevision,
    source_completeness: SourceCompleteness,
    owner_ref: &'a str,
    setting_keys: &'a [String],
    state_fence: &'a StateFence,
}

/// Project the live policy-owner facts from one snapshot.
///
/// Validates the snapshot with its in-tree constructor
/// ([`ConfigPolicySnapshot::validate`]), sorts the opaque setting keys
/// deterministically, then computes `facts_digest` over the canonical JSON
/// of the owned facts and re-checks the digest shape (64 lowercase hex).
/// One causal read per call; holds no state.
///
/// # Errors
///
/// Returns [`ConfigError`] when the snapshot fails validation or its facts
/// cannot be canonicalized. Never invents a delivery-policy choice.
pub fn project_policy_owner_facts(
    snapshot: &ConfigPolicySnapshot,
) -> Result<PolicyOwnerFacts, ConfigError> {
    snapshot.validate()?;
    let mut setting_keys: Vec<String> = snapshot
        .settings
        .iter()
        .map(|setting| setting.key.clone())
        .collect();
    setting_keys.sort();
    let canonical = CanonicalPolicyOwnerFacts {
        snapshot_id: &snapshot.snapshot_id,
        machine_id: &snapshot.machine_id,
        scope_id: &snapshot.scope_id,
        revision: snapshot.revision,
        source_completeness: snapshot.source_completeness,
        owner_ref: &snapshot.policy_owner.owner_ref,
        setting_keys: &setting_keys,
        state_fence: &snapshot.state_fence,
    };
    let bytes = canonical_json_bytes(&canonical)
        .map_err(|_| ConfigError::InvalidSnapshot("policy facts not canonicalizable"))?;
    let facts_digest = sha256_hex(&bytes);
    Ok(PolicyOwnerFacts {
        snapshot_id: snapshot.snapshot_id.clone(),
        machine_id: snapshot.machine_id.clone(),
        scope_id: snapshot.scope_id.clone(),
        revision: snapshot.revision,
        source_completeness: snapshot.source_completeness,
        owner_ref: snapshot.policy_owner.owner_ref.clone(),
        setting_keys,
        state_fence: snapshot.state_fence.clone(),
        facts_digest,
    })
}

/// Exact delivery-policy envelope facts with no live owner, in D2
/// `resolve_policy_envelope` order.
///
/// Policy identities, target event, delivery contract/profile, bounds,
/// reserves, priority, and disclosure live with the policy owner, never
/// with the bridge or the Governor config snapshot. A resolver consumes
/// [`project_policy_owner_facts`] for the live owner facts and fails
/// closed with exactly these names for the rest, so it drops into
/// `serve_live_six_slot` unchanged.
#[must_use]
pub const fn missing_delivery_policy_facts() -> &'static [&'static str] {
    &[
        "policy.policy_id",
        "policy.policy_revision",
        "policy.request_id",
        "policy.operation_id",
        "policy.idempotency_key",
        "policy.target_event_id",
        "policy.target_event",
        "policy.delivery_profile",
        "policy.delivery_contract",
        "policy.max_input_bytes",
        "policy.max_items",
        "policy.max_references",
        "policy.max_work",
        "policy.max_delivery_bytes",
        "policy.max_delivery_stu",
        "policy.fixed_reserve",
        "policy.protocol_reserve",
        "policy.output_reserve",
        "policy.review_reserve",
        "policy.delivery_reserve",
        "policy.priority",
        "policy.attention_disclosure",
    ]
}
