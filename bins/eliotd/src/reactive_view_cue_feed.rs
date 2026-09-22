//! Narrow reactive view/cue feed hook over the real projection-inputs path.
//!
//! Lane D1 (#1942): the daemon plans and projects the T11.3
//! `GetUnderstandingProjectionInputs` read (the single read serving both the
//! cue-activation and negative-memory roles) in `daemon_runtime`, and serves
//! it through the Governor read port in `governor_local_read`. This module
//! holds both the narrow serving leg
//! ([`serve_projection_inputs_under_fence`], exact-fence gate over the
//! serving function) and the production caller composition
//! ([`drive_reactive_view_cue_feed`]): live seven-role reconstruction,
//! Governor-owned cue evaluation over the live candidate, pair binding,
//! cue activation assembly against the owner view, and the served-view feed
//! — all under one admitted fence.
//!
//! Real owner path, per value (all observed in-tree on current `main`):
//!
//! ```text
//! this hook (`serve_projection_inputs_under_fence`)
//! → `governor_local_read::answer_projection_inputs`
//!   (`bins/eliotd/src/governor_local_read.rs:107`, the serving function)
//! → `ReadService::projection_inputs` over the caller-owned
//!   `KernelContextReadClient` (`crates/governor/eliot-read/src/lib.rs:879`)
//! → closed named read `GetUnderstandingProjectionInputs`
//!   (`crates/storage/eliot-store-api/src/lib.rs:746`)
//!
//! this hook (`drive_reactive_view_cue_feed`, `drive_live_reactive_view_cue_feed`)
//! → `GovernorContextInputs::reconstruct` (live seven-role closure)
//! → `drive_live_cue_pair` (admission against canonical capture state,
//!   seed driving, evaluation over the live candidate, pair binding)
//! → `ReactiveCueActivation` assembly against the owner view (caller target
//!   bindings, verified by the serving gate — never invented here)
//! → `drive_served_view_feed` (serve under the bindings fence, then the
//!   settled-plan feed in one causal call).
//! ```
//!
//! Exact-fence discipline: the caller [`RequestMetadata`](eliot_contracts::RequestMetadata)
//! fence must equal the admitted fence before any read runs. A rotated fence
//! fails closed before any owner call — downstream gates, which only check
//! the projections against the admitted receipt they are given, can never
//! observe it. This mirrors the established `drive_live_feed` cadence in the
//! plan crate (gate on the live activation, then produce) without duplicating
//! it: the plan-crate gate stays the plan crate's.
//!
//! No new authority, no new semantics: the hook returns owner artifacts
//! unchanged (payloads, pairs, evaluations, plans). Payload interpretation
//! stays with the owning Governor reconstruction composition
//! (`GovernorContextInputs::reconstruct`,
//! `crates/governor/eliot-governor/src/context_inputs.rs:288`); evaluation
//! math stays with its evaluated core behind the Governor owner; delivery
//! receipts, stickiness, and session dedup stay with the bridge owner. A
//! genuine gateway failure (including a store generation without the
//! activated handler) surfaces with its exact typed identity — never
//! `Ok`-empty, never canned, never a facade-synthesized `Unavailable`
//! standing in for the store's own answer.
//!
//! Caller data is never owner proof: seeds, profiles, selectors, bindings,
//! and projections arrive as caller-owned artifacts and are proven here
//! against the live closure (fence, scope, operation, envelope currency,
//! owner admission) before anything plans.
//!
//! Registration (lane D1, this copy): `bins/eliotd/src/lib.rs` declares
//! `mod reactive_view_cue_feed;` plus a `pub use` of
//! [`serve_projection_inputs_under_fence`],
//! [`drive_reactive_view_cue_feed`], [`ReactiveViewCueOutcome`], and
//! [`ReactiveViewCueError`]. Manifest: this module needs the
//! `eliot-context-contracts`, `eliot-cue-contracts`, `eliot-cue-activation`,
//! and `eliot-reactive-context-plan` edges (all first-party path deps,
//! version `0.1.0`, declared in `bins/eliotd/Cargo.toml`). Do NOT register
//! it in `main.rs` (`daemon_runtime` is binary-private; this hook consumes
//! the lib-side owners).

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_contracts::{RequestMetadata, StateFence};
use eliot_context_contracts::{
    ContextPlanningView, CriticalAttentionProjection, IntegrationCoverageProfile,
    SessionDeliverySnapshot,
};
use eliot_cue_activation::ActivationProfile;
use eliot_cue_contracts::{NormalizationProfile, ObservedCue, SnapshotId};
use eliot_cue_normalizer::NormalizationPolicy;
use eliot_governor::{
    ContextInputsError, ContextReconstructionRequest, CuePairError, GovernorContextInputs,
    LiveCuePair, drive_live_cue_pair,
};
use eliot_read::{QueryResult, ReadError, ReadService};
use eliot_reactive_context_plan::{
    LiveActivationBindings, ReactiveCueActivation, ReactiveDeliveryPolicy, ReactiveTargetBinding,
    ServedViewFeed, ServedViewFeedError, SettledPlanFeedInputs, drive_served_view_feed,
};
use eliot_store_api::{RevisionKey, ScopeId};
use thiserror::Error;

use super::DaemonComposition;
use super::DaemonKernelClient;
use super::governor_local_read::answer_projection_inputs;

/// Serve one Governor projection-inputs read under the exact admitted fence.
///
/// Verifies `ctx.state_fence` equals `admitted_fence`, then consumes the
/// serving function
/// [`answer_projection_inputs`](super::governor_local_read::answer_projection_inputs)
/// with the closed `selector` / `max_records` selectors and the caller
/// `ExactFence` dependency revisions, and returns its
/// owner outcome unchanged: the exact record/provenance on success, or the
/// typed fail-closed error (`Unavailable` until the MGR04/#19 store slice
/// activates the operation). Holds no state; the composition retains no
/// client and no thread, so a Governor refresh surfaces as an exact fence
/// mismatch instead of silent divergence.
pub async fn serve_projection_inputs_under_fence(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    admitted_fence: &StateFence,
    ctx: &RequestMetadata,
    scope: ScopeId,
    selector: String,
    max_records: u32,
    dependency_revisions: BTreeMap<RevisionKey, u64>,
) -> Result<QueryResult, ReadError> {
    if ctx.state_fence != *admitted_fence {
        return Err(ReadError::InvalidField {
            field: "request_metadata.state_fence".to_owned(),
            reason: "caller fence does not equal the admitted fence; \
                     refresh the admission instead of serving a rotated view"
                .to_owned(),
        });
    }
    answer_projection_inputs(
        composition,
        kernel,
        ctx,
        scope,
        selector,
        max_records,
        dependency_revisions,
    )
    .await
}

/// One production caller evaluation through the coherent fence readset:
/// the live cue pair (evaluation, bound pair, exclusions) plus the
/// served-view feed outcome over the assembled owner projections.
#[derive(Debug)]
pub struct ReactiveViewCueOutcome {
    /// Live cue pair proven against the live closure.
    pub pair: LiveCuePair,
    /// Served mapping plus settled plan outcome in one causal call.
    pub feed: ServedViewFeed,
}

/// Fail-closed caller errors. Each stage surfaces distinctly: a fence or
/// composition failure, a reconstruction failure, a live-pair failure, a
/// resolver failure, or a serving/planning failure. Nothing downgrades.
#[derive(Debug, Error)]
pub enum ReactiveViewCueError {
    /// The caller fence does not equal the admitted fence.
    #[error("caller fence does not equal the admitted fence")]
    Fence,
    /// The daemon composition is not ready or has no read client.
    #[error("daemon composition: {0}")]
    Composition(super::DaemonError),
    /// The seven-role reconstruction failed.
    #[error("seven-role reconstruction failed: {0}")]
    Reconstruction(ContextInputsError),
    /// Live cue pair production failed (admission, driving, evaluation,
    /// or binding).
    #[error("live cue pair failed: {0}")]
    Pair(CuePairError),
    /// A six-slot resolver failed: `slot` names it (`session`,
    /// `coverage`, `policy`), `detail` carries its typed message.
    #[error("six-slot resolver failed: {slot}: {detail}")]
    Resolve {
        /// Resolver slot that failed.
        slot: &'static str,
        /// Resolver's typed failure message.
        detail: String,
    },
    /// The served-view feed rejected the assembled inputs.
    #[error("served-view feed failed: {0}")]
    Feed(ServedViewFeedError),
}

/// Live session-snapshot resolver port (O1 owner child).
///
/// Mirrors the D2 resolver call shape: the live fence in, the owner
/// session snapshot out, typed failure preserved. Implementations live
/// with the session owner; this hook only consumes through the port.
pub trait ReactiveSessionResolver {
    /// Resolver failure type (typed, displayable).
    type Error: std::fmt::Display;
    /// Resolves the live session snapshot under the fence.
    fn resolve_session(
        &self,
        fence: &StateFence,
    ) -> Result<SessionDeliverySnapshot, Self::Error>;
}

/// Live coverage-profile resolver port (O2 owner child).
///
/// Mirrors the D2 resolver call shape: the live fence in, the owner
/// coverage profile out, typed failure preserved.
pub trait ReactiveCoverageResolver {
    /// Resolver failure type (typed, displayable).
    type Error: std::fmt::Display;
    /// Resolves the live coverage profile under the fence.
    fn resolve_coverage(
        &self,
        fence: &StateFence,
    ) -> Result<IntegrationCoverageProfile, Self::Error>;
}

/// Live delivery-policy resolver port (O2 owner child).
///
/// Mirrors the D2 resolver call shape: the live fence in, the owner
/// delivery policy out, typed failure preserved.
pub trait ReactivePolicyResolver {
    /// Resolver failure type (typed, displayable).
    type Error: std::fmt::Display;
    /// Resolves the live delivery policy under the fence.
    fn resolve_policy(&self, fence: &StateFence) -> Result<ReactiveDeliveryPolicy, Self::Error>;
}

/// Drive the production reactive view/cue caller end to end under one fence.
///
/// Gathers the live seven-role closure through the Governor read owner,
/// drives the live cue pair (admission against canonical capture state,
/// seed driving, bounded evaluation, pair binding), assembles the cue
/// activation against the owner view with the caller target bindings, and
/// drives the served-view feed. Every stage binds `admitted_fence`: a
/// refresh anywhere fails closed before anything plans. Holds no state;
/// observations, profiles, bindings, and projections arrive as caller-owned
/// artifacts and are proven here, never trusted.
///
/// No new semantics live here: driving, reconstruction, evaluation,
/// binding, serving, and planning each run in their owning crate through
/// their exact public entrypoints; this hook only composes them in fence
/// order.
#[allow(clippy::too_many_arguments)]
pub async fn drive_reactive_view_cue_feed(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    admitted_fence: &StateFence,
    ctx: &RequestMetadata,
    reconstruction: &ContextReconstructionRequest,
    snapshot_id: SnapshotId,
    normalization_profile: NormalizationProfile,
    observations: Vec<ObservedCue>,
    normalization_policy: &NormalizationPolicy,
    activation_profile: &ActivationProfile,
    target_bindings: Vec<ReactiveTargetBinding>,
    view: &ContextPlanningView,
    session_snapshot: &SessionDeliverySnapshot,
    critical_attention: &CriticalAttentionProjection,
    integration_coverage: &IntegrationCoverageProfile,
    policy: &ReactiveDeliveryPolicy,
    bindings: &LiveActivationBindings,
) -> Result<ReactiveViewCueOutcome, ReactiveViewCueError> {
    if ctx.state_fence != *admitted_fence {
        return Err(ReactiveViewCueError::Fence);
    }
    let client = composition
        .context_read_client(kernel)
        .map_err(ReactiveViewCueError::Composition)?;
    let service = ReadService::new(client);
    let seven = GovernorContextInputs::borrow(&service)
        .reconstruct(ctx, reconstruction)
        .await
        .map_err(ReactiveViewCueError::Reconstruction)?;
    let pair = drive_live_cue_pair(
        &seven,
        reconstruction,
        snapshot_id,
        normalization_profile,
        observations,
        normalization_policy,
        activation_profile,
    )
    .map_err(ReactiveViewCueError::Pair)?;
    let cue_activation = ReactiveCueActivation {
        request: pair.bound.request.clone(),
        result: pair.bound.result.clone(),
        expected_view_id: Some(view.view_id.clone()),
        expected_admitted_set_digest: Some(view.admitted_canonical_sha256.clone()),
        target_bindings,
    };
    let feed = drive_served_view_feed(
        bindings,
        SettledPlanFeedInputs {
            view,
            cue_activation: &cue_activation,
            session_snapshot,
            critical_attention,
            integration_coverage,
            policy,
        },
    )
    .map_err(ReactiveViewCueError::Feed)?;
    Ok(ReactiveViewCueOutcome {
        pair,
        feed,
    })
}

/// Drive the live reactive view/cue caller with six-slot owner resolution.
///
/// Same composition as [`drive_reactive_view_cue_feed`], except the
/// session snapshot, coverage profile, and delivery policy resolve live
/// through their owner ports (O1 session envelopes, O2 coverage/policy)
/// under the admitted fence instead of arriving pre-resolved. The view and
/// critical attention projections arrive as owner artifacts (their resolvers
/// live in other lanes); everything else is identical, including fence
/// order and failure vocabulary. First failing resolver aborts the whole
/// call in resolver order (session → coverage → policy); nothing partial
/// is ever planned.
#[allow(clippy::too_many_arguments)]
pub async fn drive_live_reactive_view_cue_feed(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    admitted_fence: &StateFence,
    ctx: &RequestMetadata,
    reconstruction: &ContextReconstructionRequest,
    snapshot_id: SnapshotId,
    normalization_profile: NormalizationProfile,
    observations: Vec<ObservedCue>,
    normalization_policy: &NormalizationPolicy,
    activation_profile: &ActivationProfile,
    target_bindings: Vec<ReactiveTargetBinding>,
    view: &ContextPlanningView,
    critical_attention: &CriticalAttentionProjection,
    session: &impl ReactiveSessionResolver,
    coverage: &impl ReactiveCoverageResolver,
    policy_resolver: &impl ReactivePolicyResolver,
    bindings: &LiveActivationBindings,
) -> Result<ReactiveViewCueOutcome, ReactiveViewCueError> {
    let session_snapshot = session
        .resolve_session(admitted_fence)
        .map_err(|error| ReactiveViewCueError::Resolve {
            slot: "session",
            detail: error.to_string(),
        })?;
    let integration_coverage = coverage
        .resolve_coverage(admitted_fence)
        .map_err(|error| ReactiveViewCueError::Resolve {
            slot: "coverage",
            detail: error.to_string(),
        })?;
    let policy = policy_resolver
        .resolve_policy(admitted_fence)
        .map_err(|error| ReactiveViewCueError::Resolve {
            slot: "policy",
            detail: error.to_string(),
        })?;
    drive_reactive_view_cue_feed(
        composition,
        kernel,
        admitted_fence,
        ctx,
        reconstruction,
        snapshot_id,
        normalization_profile,
        observations,
        normalization_policy,
        activation_profile,
        target_bindings,
        view,
        &session_snapshot,
        critical_attention,
        &integration_coverage,
        &policy,
        bindings,
    )
    .await
}
