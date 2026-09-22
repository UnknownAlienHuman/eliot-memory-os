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
//! receipts, stickiness, and session dedup stay with the bridge owner. A
//! genuine gateway failure (including a store generation without the
//! activated handler) surfaces with its exact typed identity — never
//! `Ok`-empty, never canned, never a facade-synthesized `Unavailable`
//! standing in for the store's own answer.
//!
//! Downstream handoff (no new import here): the integrator feeds the
//! reconstructed owner view + cue pair into the plan crate's
//! `drive_served_view_feed` (serve under the admitted fence, then the
//! settled-plan feed in one causal call) under the same admitted fence.
//! That call lives with the integrator (daemon central export, B2-owned),
//! not in this hook, per `bins/AGENTS.md` (no task/memory/policy semantics
//! in the composition binary).
//!
//! Registration (lane D1, this copy): `bins/eliotd/src/lib.rs` declares
//! `mod reactive_view_cue_feed;` plus a `pub use` of
//! [`serve_projection_inputs_under_fence`]. No manifest change: this module
//! uses only the crate's existing dependencies. Do NOT register it in
//! `main.rs` (`daemon_runtime` is binary-private; this hook consumes the
//! lib-side serving function).

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_contracts::{RequestMetadata, StateFence};
use eliot_read::{QueryResult, ReadError};
use eliot_store_api::{RevisionKey, ScopeId};

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
