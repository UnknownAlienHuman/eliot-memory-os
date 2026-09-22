//! O2 delivery-policy owner: actual owner state, authenticated admission,
//! canonical revisions, and the delivery-policy assembler.
//!
//! Ownership:
//! - [`DeliveryPolicyOwner`] is the sole holder of [`ChoiceSnapshot`]
//!   revisions: the 22 policy-owner choice fields (identities, target
//!   event, delivery contract/profile, bounds, reserves, priority,
//!   disclosure) under one revision and digest. It owns the *choices*;
//!   the live plan identity and observation clock arrive per assembly as
//!   bridge frame facts (same split as D2's `live_policy_frame`), and the
//!   `tie_break_revision = 1`, no-deadline, `cancelled = false` facts are
//!   contract-fixed, exactly as D2 records them.
//! - Admission ([`DeliveryPolicyOwner::admit`]) is the only write path. It
//!   takes typed [`DeliveryPolicyChoices`], validates every field against
//!   the same rules [`ReactiveDeliveryPolicy::validate`] enforces
//!   (same field/reason vocabulary, via the shared `pub(crate)`
//!   `text`/`digest` constructors), and fails closed otherwise. No second
//!   write path exists.
//! - [`assemble_delivery_policy`] reads one admitted snapshot plus the
//!   live frame facts, then yields the owner `ReactiveDeliveryPolicy`
//!   with its self-verifying `policy_digest` computed and revalidated.
//!   Nothing is caller-asserted.
//!
//! Fail-closed inventory: when no choices were admitted, the resolver
//! reports exactly D2's 22 `resolve_policy_envelope` names — never a
//! forged envelope, never a complete claim over unavailable facts.
//!
//! Non-mapping (by design, never converted, no `From` bridges):
//! Governor `ConfigPolicySnapshot` settings are opaque config entries and
//! are never delivery bounds, modes, reserves, priorities, or disclosure
//! rules. See `crates/governor/eliot-config/src/delivery_policy_projection.rs`.

use std::collections::BTreeSet;

use eliot_context_contracts::{ReactiveDeliveryMode, ReactiveInputError, SemanticRole};
use eliot_contracts::{
    ArtifactId, ClockReading, ContractIdentity, OperationId, RequestId, canonical_json_bytes,
    sha256_hex,
};
use eliot_protocol::ReactiveContextContentRef;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::input::{AttentionDisclosureRule, ReactiveDeliveryPolicy, digest, text};

/// Fail-closed delivery-policy owner errors. Field/reason vocabulary is
/// identical to [`ReactiveDeliveryPolicy::validate`] so delegation keeps
/// unchanged names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PolicyOwnerError {
    /// One choice failed its validated constructor.
    Invalid(ReactiveInputError),
    /// The admitted choices could not be canonicalized for their digest.
    SnapshotDigest,
}

impl core::fmt::Display for PolicyOwnerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(error) => write!(formatter, "delivery policy choice invalid: {error:?}"),
            Self::SnapshotDigest => write!(formatter, "delivery policy choices not canonicalizable"),
        }
    }
}

impl std::error::Error for PolicyOwnerError {}

/// Authenticated admission inputs for one policy-owner revision: the 22
/// policy-owner choice fields. No revision, no digest — those are minted
/// at admission, never supplied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeliveryPolicyChoices {
    /// Policy identity from the policy owner.
    pub policy_id: ArtifactId,
    /// Policy revision from the policy owner (non-zero).
    pub policy_revision: u32,
    /// Request identity from the policy owner.
    pub request_id: RequestId,
    /// Operation identity from the policy owner.
    pub operation_id: OperationId,
    /// Idempotency key from the policy owner.
    pub idempotency_key: String,
    /// Target event identity from the policy owner, when pinned.
    pub target_event_id: Option<ArtifactId>,
    /// Target event name from the policy owner.
    pub target_event: String,
    /// Delivery profile reference from the policy owner.
    pub delivery_profile: ReactiveContextContentRef,
    /// Delivery contract identity from the policy owner.
    pub delivery_contract: ContractIdentity,
    /// Allowed delivery modes from the policy owner.
    pub allowed_modes: Vec<ReactiveDeliveryMode>,
    /// Input byte ceiling from the policy owner.
    pub max_input_bytes: u64,
    /// Item ceiling from the policy owner.
    pub max_items: u64,
    /// Reference ceiling from the policy owner.
    pub max_references: u64,
    /// Planning-work ceiling from the policy owner.
    pub max_work: u64,
    /// Delivery byte ceiling from the policy owner.
    pub max_delivery_bytes: u64,
    /// Delivery STU ceiling from the policy owner, when bounded.
    pub max_delivery_stu: Option<u64>,
    /// Fixed reserve from the policy owner.
    pub fixed_reserve: u64,
    /// Protocol reserve from the policy owner.
    pub protocol_reserve: u64,
    /// Output reserve from the policy owner.
    pub output_reserve: u64,
    /// Review reserve from the policy owner.
    pub review_reserve: u64,
    /// Delivery reserve from the policy owner.
    pub delivery_reserve: u64,
    /// Priority order from the policy owner.
    pub priority: Vec<SemanticRole>,
    /// Attention disclosure rules from the policy owner.
    pub attention_disclosure: Vec<AttentionDisclosureRule>,
}

/// One admitted policy-owner revision: the 22 choice fields plus the
/// minted revision and snapshot digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ChoiceSnapshot {
    /// Admitted policy-owner choices.
    pub choices: DeliveryPolicyChoices,
    /// Minted revision (starts at 1, never zero while live).
    pub revision: u64,
    /// `sha256` over the canonical JSON of the admitted choices.
    pub snapshot_digest: String,
}

/// The delivery-policy owner: sole minter of [`ChoiceSnapshot`] revisions.
#[derive(Clone, Debug)]
pub struct DeliveryPolicyOwner {
    revision: u64,
    current: Option<ChoiceSnapshot>,
}

impl DeliveryPolicyOwner {
    /// Creates an empty owner with no admitted choices.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            revision: 0,
            current: None,
        }
    }

    /// Returns the current revision (zero when nothing was admitted).
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the live admitted snapshot, if one exists.
    #[must_use]
    pub fn current(&self) -> Option<&ChoiceSnapshot> {
        self.current.as_ref()
    }

    /// Admits one policy-owner revision.
    ///
    /// Validates every choice against the exact rules
    /// [`ReactiveDeliveryPolicy::validate`] enforces (identity text and
    /// digest shapes via the shared constructors; profile/contract
    /// validity; non-zero policy revision; unique non-empty modes;
    /// explicit irredundant priority; one disclosure rule per Attention
    /// identity with valid claim digests; finite non-zero limits within
    /// the contract ceilings), mints `revision = previous + 1` (starting
    /// at 1), and computes `snapshot_digest` over the canonical JSON of
    /// the admitted choices. Re-admission supersedes the previous
    /// revision; the owner retains only the live one. Returns the stored
    /// live snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyOwnerError`] when any choice is rejected or the
    /// choices cannot be canonicalized. Nothing is stored on failure.
    pub fn admit(
        &mut self,
        choices: DeliveryPolicyChoices,
    ) -> Result<&ChoiceSnapshot, PolicyOwnerError> {
        validate_choices(&choices)?;
        let revision = self.revision.saturating_add(1).max(1);
        let bytes = canonical_json_bytes(&choices).map_err(|_| PolicyOwnerError::SnapshotDigest)?;
        let snapshot = ChoiceSnapshot {
            choices,
            revision,
            snapshot_digest: sha256_hex(&bytes),
        };
        self.revision = revision;
        Ok(self.current.insert(snapshot))
    }
}

impl Default for DeliveryPolicyOwner {
    fn default() -> Self {
        Self::new()
    }
}

/// Validate choices against the exact [`ReactiveDeliveryPolicy`] rules
/// (`crates/smart/eliot-reactive-context-plan/src/input.rs`,
/// `validate` + `validate_selection_and_limits`): same fields, same
/// reasons. The plan identity, observation clock, tie-break revision,
/// deadline, and cancellation are frame/contract facts, never choices,
// so they are not validated here.
fn validate_choices(choices: &DeliveryPolicyChoices) -> Result<(), PolicyOwnerError> {
    validate_choice_identities(choices)?;
    validate_choice_selection(choices)?;
    if choices.max_input_bytes == 0
        || choices.max_input_bytes > 256 * 1024
        || choices.max_items == 0
        || choices.max_items > 256
        || choices.max_references == 0
        || choices.max_references > 512
        || choices.max_work == 0
        || choices.max_delivery_bytes == 0
        || choices.max_delivery_stu.is_some_and(|value| value == 0)
    {
        return Err(PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
            field: "policy.bounds",
            reason: "all scalar limits must be finite, non-zero and within the contract ceiling",
        }));
    }
    Ok(())
}

/// Validate choice identities, profile/contract handles, and the policy
/// revision: same fields and reasons as `ReactiveDeliveryPolicy::validate`.
fn validate_choice_identities(choices: &DeliveryPolicyChoices) -> Result<(), PolicyOwnerError> {
    text(choices.policy_id.as_str(), "policy.policy_id").map_err(PolicyOwnerError::Invalid)?;
    text(choices.request_id.as_str(), "policy.request_id").map_err(PolicyOwnerError::Invalid)?;
    text(choices.operation_id.as_str(), "policy.operation_id")
        .map_err(PolicyOwnerError::Invalid)?;
    text(&choices.idempotency_key, "policy.idempotency_key").map_err(PolicyOwnerError::Invalid)?;
    if let Some(event) = &choices.target_event_id {
        text(event.as_str(), "policy.target_event_id").map_err(PolicyOwnerError::Invalid)?;
    }
    text(&choices.target_event, "policy.target_event").map_err(PolicyOwnerError::Invalid)?;
    choices
        .delivery_profile
        .validate()
        .map_err(|_| {
            PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
                field: "policy.delivery_profile",
                reason: "invalid downstream delivery profile handle",
            })
        })?;
    choices
        .delivery_contract
        .validate()
        .map_err(|_| {
            PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
                field: "policy.delivery_contract",
                reason: "invalid downstream delivery contract identity",
            })
        })?;
    if choices.policy_revision == 0 {
        return Err(PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
            field: "policy.revision",
            reason: "policy revision must be non-zero and tie-break revision must be 1",
        }));
    }
    Ok(())
}

/// Validate choice selection (modes, priority, disclosure): same fields
/// and reasons as `ReactiveDeliveryPolicy::validate_selection_and_limits`.
fn validate_choice_selection(choices: &DeliveryPolicyChoices) -> Result<(), PolicyOwnerError> {
    if choices.allowed_modes.is_empty() {
        return Err(PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
            field: "policy.allowed_modes",
            reason: "at least one delivery mode is required",
        }));
    }
    {
        let mut modes = Vec::with_capacity(choices.allowed_modes.len());
        for mode in &choices.allowed_modes {
            if modes.contains(mode) {
                return Err(PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
                    field: "policy.allowed_modes",
                    reason: "delivery modes must be unique",
                }));
            }
            modes.push(*mode);
        }
    }
    if choices.priority.is_empty() {
        return Err(PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
            field: "policy.priority",
            reason: "priority order must be explicit",
        }));
    }
    {
        let mut priorities = BTreeSet::new();
        for role in &choices.priority {
            if !priorities.insert(*role) {
                return Err(PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
                    field: "policy.priority",
                    reason: "priority order must not repeat a disposition",
                }));
            }
        }
    }
    {
        let mut attention_ids = BTreeSet::new();
        for rule in &choices.attention_disclosure {
            text(
                rule.attention_id.as_str(),
                "policy.attention_disclosure.attention_id",
            )
            .map_err(PolicyOwnerError::Invalid)?;
            digest(
                &rule.claim_digest,
                "policy.attention_disclosure.claim_digest",
            )
            .map_err(PolicyOwnerError::Invalid)?;
            if !attention_ids.insert(&rule.attention_id) {
                return Err(PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
                    field: "policy.attention_disclosure",
                    reason: "one disclosure rule per Attention identity is required",
                }));
            }
        }
    }
    Ok(())
}

/// Assemble the owner `ReactiveDeliveryPolicy` from one admitted snapshot
/// plus the live frame facts.
///
/// Consumes the admitted choices with the bridge-supplied live `plan_id`
/// and `observed_at` (same split as D2's `live_policy_frame`), plus the
/// contract-fixed `tie_break_revision = 1`, no deadline, and
/// `cancelled = false`. The stored `policy_digest` is computed with the
/// self-verifying `canonical_digest` and the policy is revalidated before
/// return. Nothing is caller-asserted beyond the live frame the caller
/// owns.
///
/// # Errors
///
/// Returns [`PolicyOwnerError`] when the assembled policy fails its
/// in-tree validation or digest check.
pub fn assemble_delivery_policy(
    snapshot: &ChoiceSnapshot,
    plan_id: &ArtifactId,
    observed_at: ClockReading,
) -> Result<ReactiveDeliveryPolicy, PolicyOwnerError> {
    if snapshot.revision == 0 {
        return Err(PolicyOwnerError::Invalid(ReactiveInputError::InvalidField {
            field: "policy.revision",
            reason: "policy revision must be non-zero and tie-break revision must be 1",
        }));
    }
    let choices = &snapshot.choices;
    let mut policy = ReactiveDeliveryPolicy {
        policy_id: choices.policy_id.clone(),
        policy_revision: choices.policy_revision,
        policy_digest: String::new(),
        request_id: choices.request_id.clone(),
        operation_id: choices.operation_id.clone(),
        idempotency_key: choices.idempotency_key.clone(),
        plan_id: plan_id.clone(),
        target_event_id: choices.target_event_id.clone(),
        target_event: choices.target_event.clone(),
        delivery_profile: choices.delivery_profile.clone(),
        delivery_contract: choices.delivery_contract.clone(),
        allowed_modes: choices.allowed_modes.clone(),
        max_input_bytes: choices.max_input_bytes,
        max_items: choices.max_items,
        max_references: choices.max_references,
        max_work: choices.max_work,
        max_delivery_bytes: choices.max_delivery_bytes,
        max_delivery_stu: choices.max_delivery_stu,
        fixed_reserve: choices.fixed_reserve,
        protocol_reserve: choices.protocol_reserve,
        output_reserve: choices.output_reserve,
        review_reserve: choices.review_reserve,
        delivery_reserve: choices.delivery_reserve,
        priority: choices.priority.clone(),
        attention_disclosure: choices.attention_disclosure.clone(),
        tie_break_revision: 1,
        observed_at,
        deadline_ms: None,
        cancelled: false,
    };
    policy.policy_digest = policy
        .canonical_digest()
        .map_err(PolicyOwnerError::Invalid)?;
    policy.validate().map_err(PolicyOwnerError::Invalid)?;
    Ok(policy)
}
