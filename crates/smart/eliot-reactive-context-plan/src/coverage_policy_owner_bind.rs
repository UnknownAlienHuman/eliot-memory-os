//! D2 owner binding: actual coverage/policy owners + deterministic six-slot publication.
//!
//! The six deterministic slots, in fixed order, are:
//!
//! ```text
//! [view, cue_activation, session, attention, coverage, policy]
//! ```
//!
//! - `view` (`ContextPlanningView`) and `cue_activation`
//!   (`ReactiveCueActivation`): D1-served projections. Borrowed, validated,
//!   never minted here.
//! - `session` (`SessionDeliverySnapshot`) and `attention`
//!   (`CriticalAttentionProjection`): D2-published projections. Validated
//!   with their in-tree validated constructors; the caller requires their
//!   `session_id` / `task_id` / `scope_id` / `state_fence` to equal the live
//!   `LiveLedgerSession` observation (`session_id` / `fence`) published from
//!   the live ledger by
//!   `bins/eliot-agent-bridge/src/reactive_owner_publication.rs`
//!   (exact equality — never deserialize-success, URI, or provided-string
//!   inference).
//! - `coverage` (`eliot_context_contracts::IntegrationCoverageProfile`):
//!   the actual coverage owner. This is the planner's contract type
//!   (`crates/smart/eliot-context-contracts/src/reactive_coverage.rs`),
//!   validated with `IntegrationCoverageProfile::validate` and digested with
//!   `IntegrationCoverageProfile::canonical_digest`. The governor's
//!   `eliot-integration-coverage::IntegrationCoverageProfile`
//!   (fingerprint/verified candidate vocabulary,
//!   `crates/governor/eliot-integration-coverage/src/lib.rs`) is a
//!   DIFFERENT type and is never accepted here — there is no `From`/`Into`
//!   bridge between the duplicate names, by repository rule.
//! - `policy` (`ReactiveDeliveryPolicy`): the actual policy owner
//!   (`crates/smart/eliot-reactive-context-plan/src/input.rs`), validated
//!   with `ReactiveDeliveryPolicy::validate`, which requires the stored
//!   `policy_digest` to equal the self-verifying `canonical_digest`.
//!   `eliot_governor::PolicyOwner` / `HumanOwner` `policy_owner` snapshots
//!   are by-name lookalikes and are never accepted here.
//!
//! # Determinism
//!
//! [`bind_owner_publication`] validates all six projections, checks the
//! task/scope/fence cross-bindings (mirroring `drive_live_feed` in
//! `crates/smart/eliot-reactive-context-plan/src/settled_plan_feed.rs`),
//! then emits [`OwnerBoundPublication::publication_digest`] as
//! `canonical_planning_digest` over the six projections in the fixed slot
//! order above — the same order the planner preflights
//! (`crates/smart/eliot-reactive-context-plan/src/plan.rs`, `preflight_inputs`
//! and `derive_input_identity`). Repeated calls over unchanged projections
//! yield the same digest; this module holds no state, issues no receipt,
//! and grants nothing.
//!
//! # Registration
//!
//! This file is wired by the manager (manifests/registrations are
//! manager-owned). Required line in
//! `crates/smart/eliot-reactive-context-plan/src/lib.rs`:
//!
//! ```text
//! mod coverage_policy_owner_bind;
//! ```
//!
//! plus the chosen public re-export of `OwnerBoundSixSlot`,
//! `OwnerBoundPublication`, `OwnerBindError`, and `bind_owner_publication`.

use eliot_context_contracts::{
    ContextPlanningView, CriticalAttentionProjection, IntegrationCoverageProfile,
    ReactiveInputError, SessionDeliverySnapshot, canonical_planning_digest,
};

use crate::input::{ReactiveCueActivation, ReactiveDeliveryPolicy};

/// Borrowed owner projections for one deterministic publication.
///
/// Every field is an owner-issued immutable projection, never caller text.
/// `view` / `cue_activation` arrive D1-served; `session_snapshot` /
/// `critical_attention` arrive D2-published from the live ledger;
/// `integration_coverage` / `policy` arrive from the actual coverage and
/// policy owners.
#[derive(Clone, Copy, Debug)]
pub struct OwnerBoundSixSlot<'a> {
    /// Assembled A15 context view (context-assembly owner, D1-served).
    pub view: &'a ContextPlanningView,
    /// A10 activation request/result pair (cue-activation owner, D1-served).
    pub cue_activation: &'a ReactiveCueActivation,
    /// Immutable session delivery snapshot (session owner, D2-published).
    pub session_snapshot: &'a SessionDeliverySnapshot,
    /// Critical attention projection (attention owner, D2-published).
    pub critical_attention: &'a CriticalAttentionProjection,
    /// Integration coverage profile (coverage owner — the
    /// `eliot_context_contracts` contract type, never the governor
    /// fingerprint candidate type).
    pub integration_coverage: &'a IntegrationCoverageProfile,
    /// Versioned delivery policy with self-verifying digest (policy owner —
    /// `ReactiveDeliveryPolicy`, never a `PolicyOwner` lookalike).
    pub policy: &'a ReactiveDeliveryPolicy,
}

/// Deterministic digests of one bound six-slot publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerBoundPublication {
    /// `SessionDeliverySnapshot::canonical_digest`.
    pub session_digest: String,
    /// `CriticalAttentionProjection::canonical_digest`.
    pub attention_digest: String,
    /// `IntegrationCoverageProfile::canonical_digest` (contract type).
    pub coverage_digest: String,
    /// `ReactiveDeliveryPolicy::canonical_digest` (equals `policy_digest`).
    pub policy_digest: String,
    /// Deterministic digest over the six projections in fixed slot order
    /// `[view, cue_activation, session, attention, coverage, policy]`.
    pub publication_digest: String,
}

/// Fail-closed owner-bind errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OwnerBindError {
    /// One owner projection failed its in-tree validation.
    Invalid(ReactiveInputError),
    /// Individually valid projections disagree on their exact binding.
    /// `projection` names the disagreeing projection, `field` its exact
    /// binding field (same vocabulary as `StaleActivation` in
    /// `settled_plan_feed.rs`).
    CrossBinding {
        projection: &'static str,
        field: &'static str,
    },
    /// A canonical digest could not be computed.
    Digest(ReactiveInputError),
}

impl core::fmt::Display for OwnerBindError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Invalid(error) => write!(formatter, "owner projection invalid: {error:?}"),
            Self::CrossBinding { projection, field } => write!(
                formatter,
                "owner projections disagree: {projection}.{field}"
            ),
            Self::Digest(error) => write!(formatter, "owner digest failed: {error:?}"),
        }
    }
}

impl std::error::Error for OwnerBindError {}

fn cross(projection: &'static str, field: &'static str) -> OwnerBindError {
    OwnerBindError::CrossBinding { projection, field }
}

/// Bind the actual coverage/policy owners and emit the deterministic
/// six-slot publication.
///
/// Validates each projection with its in-tree validated constructor
/// (`ContextPlanningView::validate`,
/// `ReactiveCueActivation::validate_against`,
/// `SessionDeliverySnapshot::validate`,
/// `CriticalAttentionProjection::validate`,
/// `IntegrationCoverageProfile::validate` on the contract type,
/// `ReactiveDeliveryPolicy::validate` with its self-verifying digest),
/// checks task/scope/fence agreement across view, session, attention, and
/// coverage, then digests the six slots in fixed order. The caller binds
/// the result to liveness by requiring
/// `session_snapshot.session_id` / `session_snapshot.state_fence` to equal
/// the live-ledger session/fence published from the live ledger.
pub fn bind_owner_publication(
    inputs: OwnerBoundSixSlot<'_>,
) -> Result<OwnerBoundPublication, OwnerBindError> {
    let OwnerBoundSixSlot {
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    } = inputs;
    view.validate().map_err(OwnerBindError::Invalid)?;
    cue_activation
        .validate_against(view)
        .map_err(OwnerBindError::Invalid)?;
    session_snapshot
        .validate()
        .map_err(OwnerBindError::Invalid)?;
    critical_attention
        .validate()
        .map_err(OwnerBindError::Invalid)?;
    integration_coverage
        .validate()
        .map_err(OwnerBindError::Invalid)?;
    policy.validate().map_err(OwnerBindError::Invalid)?;

    let view_binding = &view.view.binding;
    if session_snapshot.task_id != view_binding.task_id {
        return Err(cross("session", "session.task_id"));
    }
    if session_snapshot.scope_id != view_binding.scope_id {
        return Err(cross("session", "session.scope_id"));
    }
    if session_snapshot.state_fence != view_binding.state_fence {
        return Err(cross("session", "session.state_fence"));
    }
    if critical_attention.task_id != view_binding.task_id {
        return Err(cross("attention", "attention.task_id"));
    }
    if critical_attention.scope_id != view_binding.scope_id {
        return Err(cross("attention", "attention.scope_id"));
    }
    if critical_attention.state_fence != view_binding.state_fence {
        return Err(cross("attention", "attention.state_fence"));
    }
    if integration_coverage.state_fence != view_binding.state_fence {
        return Err(cross("coverage", "coverage.state_fence"));
    }

    let session_digest = session_snapshot
        .canonical_digest()
        .map_err(OwnerBindError::Digest)?;
    let attention_digest = critical_attention
        .canonical_digest()
        .map_err(OwnerBindError::Digest)?;
    let coverage_digest = integration_coverage
        .canonical_digest()
        .map_err(OwnerBindError::Digest)?;
    let policy_digest = policy.canonical_digest().map_err(OwnerBindError::Digest)?;
    if policy_digest != policy.policy_digest {
        return Err(OwnerBindError::Invalid(
            eliot_context_contracts::ReactiveInputError::DigestMismatch {
                field: "policy.policy_digest",
            },
        ));
    }
    let publication_digest = canonical_planning_digest(&(
        view,
        cue_activation,
        session_snapshot,
        critical_attention,
        integration_coverage,
        policy,
    ))
    .map_err(OwnerBindError::Digest)?;
    Ok(OwnerBoundPublication {
        session_digest,
        attention_digest,
        coverage_digest,
        policy_digest,
        publication_digest,
    })
}
