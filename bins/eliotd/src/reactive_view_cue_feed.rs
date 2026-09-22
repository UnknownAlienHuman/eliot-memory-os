//! Narrow reactive view/cue feed hook over the real projection-inputs path.
//!
//! Lane D1 (#1942): the daemon plans and projects the T11.3
//! `GetUnderstandingProjectionInputs` read (the single read serving both the
//! cue-activation and negative-memory roles) in `daemon_runtime`, and serves
//! it through the Governor read port in `governor_local_read`. Nothing calls
//! that serving function on the reactive feed's behalf under an exact-fence
//! gate. This module is that narrow hook: it consumes the serving function
//! and nothing else.
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
//! ```
//!
//! Exact-fence discipline: the caller [`RequestMetadata`](eliot_contracts::RequestMetadata)
//! fence must equal the admitted fence before any read runs. A rotated fence
//! fails closed here as `InvalidField` — the serving function, which only
//! checks the projections against the admitted receipt it is given, can never
//! observe it. This mirrors the established
//! This mirrors the established `drive_live_feed` cadence in the
//! plan crate (gate on the live activation, then produce) without duplicating
//! it: the plan-crate gate stays the plan crate's.
//!
//! No new authority, no new vocabulary: the hook returns the owner
//! [`QueryResult`](eliot_read::QueryResult) / [`ReadError`](eliot_read::ReadError)
//! unchanged. Payload interpretation stays with the owning Governor
//! reconstruction composition
//! (`GovernorContextInputs::reconstruct`,
//! `crates/governor/eliot-governor/src/context_inputs.rs:288`); delivery
//! receipts, stickiness, and session dedup stay with the bridge owner. At
//! base the store leg is `Unavailable` (MGR04/#19 owns the catalogue row,
//! parameter schema, and adapter handlers), so the hook surfaces that
//! `Unavailable` distinctly — never `Ok`-empty, never canned.
//!
//! Downstream handoff (no new import here): once the manager registers the
//! `eliot-reactive-context-plan` dependency, the integrator feeds the
//! reconstructed owner view + cue pair into
//! `eliot_reactive_context_plan::serve_view_cues_under_fence` under the same
//! admitted fence, then into `drive_live_feed`. That call lives with the
//! integrator (daemon central export, B2-owned), not in this hook, per
//! `bins/AGENTS.md` (no task/memory/policy semantics in the composition
//! binary).
//!
//! Registration (manager-owned, not this file): `bins/eliotd/src/lib.rs`
//! needs `mod reactive_view_cue_feed;` plus a `pub use` of
//! [`serve_projection_inputs_under_fence`]. No manifest change: this module
//! uses only the crate's existing dependencies. Do NOT register it in
//! `main.rs` (`daemon_runtime` is binary-private; this hook consumes the
//! lib-side serving function).

use std::sync::Arc;

use eliot_contracts::{RequestMetadata, StateFence};
use eliot_read::{QueryResult, ReadError};
use eliot_store_api::ScopeId;

use super::DaemonComposition;
use super::DaemonKernelClient;
use super::governor_local_read::answer_projection_inputs;

/// Serve one Governor projection-inputs read under the exact admitted fence.
///
/// Verifies `ctx.state_fence` equals `admitted_fence`, then consumes the
/// serving function
/// [`answer_projection_inputs`](super::governor_local_read::answer_projection_inputs)
/// with the validated `packet_ref` / `material_refs` shape and returns its
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
    packet_ref: Option<String>,
    material_refs: Vec<String>,
) -> Result<QueryResult, ReadError> {
    if ctx.state_fence != *admitted_fence {
        return Err(ReadError::InvalidField {
            field: "request_metadata.state_fence".to_owned(),
            reason: "caller fence does not equal the admitted fence; \
                     refresh the admission instead of serving a rotated view"
                .to_owned(),
        });
    }
    answer_projection_inputs(composition, kernel, ctx, scope, packet_ref, material_refs).await
}
