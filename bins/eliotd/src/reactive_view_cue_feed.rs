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
//! this hook (`drive_reactive_view_cue_feed`)
//! → `GovernorContextInputs::reconstruct` (live seven-role closure)
//! → `evaluate_live_cue_pair` (Governor-owned evaluation over the live
//!   candidate, caller seeds/profile)
//! → `bind_cue_pair_to_roles` (pair proven current for the live closure)
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
use eliot_cue_contracts::{NormalizationProfile, NormalizedCue, SnapshotId};
use eliot_governor::{
    BoundCuePair, ContextInputsError, ContextReconstructionRequest, CueEvaluationError,
    CuePairBindError, GovernorContextInputs, LiveCueEvaluation, bind_cue_pair_to_roles,
    evaluate_live_cue_pair,
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

/// One production caller evaluation through the coherent fence readset: the
/// evaluated output (carrying the admitted pair and its binding digests),
/// the pair bound current for the live closure, and the served-view feed
/// outcome over the assembled owner projections.
#[derive(Debug)]
pub struct ReactiveViewCueOutcome {
    /// Production evaluation output (admitted pair + binding digests).
    pub evaluation: eliot_cue_activation::CueActivationEvaluation,
    /// Pair proven current for the live seven-role closure.
    pub bound: BoundCuePair,
    /// Served mapping plus settled plan outcome in one causal call.
    pub feed: ServedViewFeed,
}

/// Fail-closed caller errors. Each stage surfaces distinctly: a fence or
/// composition failure, a reconstruction failure, an evaluation failure, a
/// binding failure, or a serving/planning failure. Nothing downgrades.
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
    /// The production cue evaluation failed.
    #[error("cue evaluation failed: {0}")]
    Evaluation(CueEvaluationError),
    /// The evaluated pair is not current for the live closure.
    #[error("cue pair binding failed: {0}")]
    Bind(CuePairBindError),
    /// The served-view feed rejected the assembled inputs.
    #[error("served-view feed failed: {0}")]
    Feed(ServedViewFeedError),
}

/// Drive the production reactive view/cue caller end to end under one fence.
///
/// Gathers the live seven-role closure through the Governor read owner,
/// evaluates the bounded cue activation over the live candidate plus the
/// caller seeds/profile, proves the pair current, assembles the cue
/// activation against the owner view with the caller target bindings, and
/// drives the served-view feed. Every stage binds `admitted_fence`: a
/// refresh anywhere fails closed before anything plans. Holds no state;
/// seeds, profiles, bindings, and projections arrive as caller-owned
/// artifacts and are proven here, never trusted.
///
/// No new semantics live here: reconstruction, evaluation, binding,
/// serving, and planning each run in their owning crate through their exact
/// public entrypoints; this hook only composes them in fence order.
#[allow(clippy::too_many_arguments)]
pub async fn drive_reactive_view_cue_feed(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    admitted_fence: &StateFence,
    ctx: &RequestMetadata,
    reconstruction: &ContextReconstructionRequest,
    snapshot_id: SnapshotId,
    normalization_profile: NormalizationProfile,
    seeds: Vec<NormalizedCue>,
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
    let evaluated = evaluate_live_cue_pair(
        &seven,
        snapshot_id,
        normalization_profile,
        seeds,
        activation_profile,
    )
    .map_err(ReactiveViewCueError::Evaluation)?;
    let LiveCueEvaluation { request, evaluation } = evaluated;
    let result = evaluation.result.clone();
    let bound = bind_cue_pair_to_roles(&seven, reconstruction, request, result)
        .map_err(ReactiveViewCueError::Bind)?;
    let cue_activation = ReactiveCueActivation {
        request: bound.request.clone(),
        result: bound.result.clone(),
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
        evaluation,
        bound,
        feed,
    })
}
