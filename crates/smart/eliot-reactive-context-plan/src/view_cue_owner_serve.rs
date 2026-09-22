//! Serve the live [`ContextPlanningView`](eliot_context_contracts::ContextPlanningView)
//! from the real projection-inputs path and map cue targets to owner atoms.
//!
//! Lane D1 (#1942): the planner already validates an owner-issued A15 view
//! against an owner-issued A10 cue pair
//! ([`plan_pending_context_injection`](crate::plan_pending_context_injection)),
//! but nothing serves the view itself from the projection-inputs acquisition
//! path, and nothing invokes the cue-owner target-to-atom join outside
//! planning. This module is that serving seam.
//!
//! Real owner path, per value (all observed in-tree on current `main`):
//!
//! ```text
//! store named read `GetUnderstandingProjectionInputs`
//!   (`crates/storage/eliot-store-api/src/lib.rs:746`, closed catalogue)
//! → `ReadService::projection_inputs` port shape
//!   (`crates/governor/eliot-read/src/lib.rs:879`; fail-closed `Unavailable`
//!   until the MGR04/#19 store slice activates the catalogue row, parameter
//!   schema, and adapter handlers)
//! → Governor seven-role reconstruction, cue + negative-memory roles
//!   (`crates/governor/eliot-governor/src/context_inputs.rs:308,416`)
//! → candidate-stage cue interpretation
//!   (`crates/smart/eliot-context-candidates/src/mapper.rs:748`)
//! → assembled A15 [`ContextPlanningView`](eliot_context_contracts::ContextPlanningView)
//!   (context-assembly owner, via the in-tree validated
//!   `ContextPlanningView::new` constructor)
//! → this serving function (exact-fence gate + cue-owner mapping)
//! → [`plan_pending_context_injection`](crate::plan_pending_context_injection)
//!   via the established [`drive_live_feed`](crate::drive_live_feed) cadence.
//! ```
//!
//! Cue-activation ownership: the evaluating prototype
//! (`crates/smart/eliot-cue-activation`, explicitly "no normalization,
//! indexing, I/O, admission, publication or authority decision") owns
//! nothing here. Admission is owned by `eliot-cue-contracts`:
//! [`ActivationResult::validate_against`](eliot_cue_contracts::ActivationResult::validate_against)
//! (`crates/smart/eliot-cue-contracts/src/activation.rs:747`) binds the exact
//! request, snapshot, profile, fence, budgets, membership, and output; the
//! target-to-atom join is owned by
//! [`ReactiveCueActivation::validate_against`](crate::ReactiveCueActivation::validate_against)
//! (`src/input.rs:328`), which requires every binding to name a rendered
//! owner atom with matching source revision and digest. This module invokes
//! exactly those two owner functions — never a deserialize-success, URI, or
//! provided-string inference — and then projects the mapping.
//!
//! Exact-fence discipline: the view binding fence must equal the admitted
//! fence (`view.view.binding.state_fence`, the same fence the Governor read
//! owner acquires every role under). The cue pair fences reach liveness
//! transitively: `validate_against` already requires the seed contexts and
//! the request fence to equal the view fence, so a view under the admitted
//! fence implies a cue pair under the admitted fence. A rotated or foreign
//! view fails closed here — the planner, which only checks the projections
//! against each other, can never observe it (same cadence as
//! [`drive_live_feed`](crate::drive_live_feed)).
//!
//! Store-leg status: the live payload leg (`GetUnderstandingProjectionInputs`
//! store handler) is MGR04/#19-owned and `Unavailable` at base, so this
//! function serves owner-constructed views through the in-tree validated
//! constructors and fails closed on any mismatch. It never synthesizes
//! projection data, never returns `Ok`-empty, and mints no receipts: delivery
//! receipts and stickiness stay with the bridge owner.
//!
//! Registration (manager-owned, not this file): `src/lib.rs` needs
//! `mod view_cue_owner_serve;` plus a `pub use` of
//! [`serve_view_cues_under_fence`], [`ServedViewCues`],
//! [`MappedCueTarget`], and [`UnmappedCueTarget`]. No manifest change: this
//! module uses only the crate's existing dependencies.

use eliot_contracts::{ArtifactId, StateFence};
use eliot_context_contracts::{ContextPlanningView, ReactiveInputError};
use eliot_cue_contracts::{ActivationStrength, TargetHandle};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::input::ReactiveCueActivation;

/// One cue hit mapped to its live owner atom.
///
/// The target handle comes from the admitted A10
/// [`ActivationResult`](eliot_cue_contracts::ActivationResult) (direct or
/// derived hit); the atom identity and source coordinates come from the live
/// rendered A15 view through the explicit
/// [`ReactiveTargetBinding`](crate::ReactiveTargetBinding) join. The mapping
/// carries owner values unchanged: no bytes, no digest recomputation, no
/// promotion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MappedCueTarget {
    /// Admitted cue target handle.
    pub target: TargetHandle,
    /// Live rendered atom the target binding names.
    pub item_id: ArtifactId,
    /// Owner source revision of that atom, echoed unchanged.
    pub source_revision: String,
    /// Owner source digest of that atom, echoed unchanged.
    pub source_digest: String,
    /// Hit strength from the admitted result.
    pub strength: ActivationStrength,
    /// Whether the hit is relation-derived (`true`) or direct (`false`).
    pub derived: bool,
}

/// One admitted cue hit with no target binding: activation frontier evidence.
///
/// Per the binding contract (`src/input.rs:55-56`), a target without an
/// explicit binding remains frontier evidence — never silently dropped and
/// never mapped to an inferred atom.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnmappedCueTarget {
    /// Admitted cue target handle with no binding.
    pub target: TargetHandle,
    /// Hit strength from the admitted result.
    pub strength: ActivationStrength,
    /// Whether the hit is relation-derived (`true`) or direct (`false`).
    pub derived: bool,
}

/// The served live view cues: every admitted hit either mapped to its owner
/// atom or reported as frontier, in deterministic result order (direct hits
/// first, then derived hits).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServedViewCues {
    /// Identity of the live view the mapping was computed against.
    pub view_id: ArtifactId,
    /// Mapped targets, in deterministic result order.
    pub mapped: Vec<MappedCueTarget>,
    /// Admitted hits without a binding (frontier evidence), in order.
    pub frontier: Vec<UnmappedCueTarget>,
}

/// Serve the live view cues from the real projection-inputs path under the
/// exact admitted fence.
///
/// Runs, in order: the owner intrinsic view validation
/// (`ContextPlanningView::validate`), the exact-fence gate (view binding
/// fence must equal `admitted_fence`), the actual cue-owner admission and
/// target-to-atom join (`ReactiveCueActivation::validate_against`, which
/// invokes `ActivationResult::validate_against` inside), and finally the
/// target projection below. Holds no state; repeated calls over unchanged
/// projections yield the same outcome.
///
/// Fails closed with the owner [`ReactiveInputError`] vocabulary: a rotated
/// fence, a forged pair, or a binding naming a non-atom surfaces as
/// `BindingMismatch`, never as a downgraded or empty mapping.
pub fn serve_view_cues_under_fence(
    admitted_fence: &StateFence,
    view: &ContextPlanningView,
    cue_activation: &ReactiveCueActivation,
) -> Result<ServedViewCues, ReactiveInputError> {
    view.validate()?;
    if view.view.binding.state_fence != *admitted_fence {
        return Err(ReactiveInputError::BindingMismatch {
            field: "view.binding.state_fence",
        });
    }
    cue_activation.validate_against(view)?;
    let mut mapped = Vec::new();
    let mut frontier = Vec::new();
    for hit in &cue_activation.result.direct {
        project_hit(
            view,
            cue_activation,
            hit.target.clone(),
            hit.strength,
            false,
            &mut mapped,
            &mut frontier,
        )?;
    }
    for hit in &cue_activation.result.derived {
        project_hit(
            view,
            cue_activation,
            hit.target.clone(),
            hit.strength,
            true,
            &mut mapped,
            &mut frontier,
        )?;
    }
    Ok(ServedViewCues {
        view_id: view.view_id.clone(),
        mapped,
        frontier,
    })
}

/// Project one admitted hit through the explicit target binding.
///
/// A hit whose target has a binding resolves to the binding's rendered owner
/// atom (already proven to exist with matching source coordinates by
/// `validate_against`, re-checked here against the same live view so the
/// projection cannot outlive its proof). A hit whose target has no binding
/// becomes frontier evidence.
#[allow(clippy::too_many_arguments)]
fn project_hit(
    view: &ContextPlanningView,
    cue_activation: &ReactiveCueActivation,
    target: TargetHandle,
    strength: ActivationStrength,
    derived: bool,
    mapped: &mut Vec<MappedCueTarget>,
    frontier: &mut Vec<UnmappedCueTarget>,
) -> Result<(), ReactiveInputError> {
    let Some(binding) = cue_activation
        .target_bindings
        .iter()
        .find(|binding| binding.target.as_str() == target.as_str())
    else {
        frontier.push(UnmappedCueTarget {
            target,
            strength,
            derived,
        });
        return Ok(());
    };
    let Some(atom) = view
        .view
        .rendered
        .iter()
        .find(|atom| atom.atom_id == binding.item_id)
    else {
        return Err(ReactiveInputError::BindingMismatch {
            field: "activation.target_bindings.item",
        });
    };
    if binding
        .source_revision
        .as_deref()
        .is_some_and(|revision| revision != atom.source_revision.as_str())
        || binding
            .source_digest
            .as_deref()
            .is_some_and(|digest| digest != atom.source_digest.as_str())
    {
        return Err(ReactiveInputError::BindingMismatch {
            field: "activation.target_bindings.source",
        });
    }
    mapped.push(MappedCueTarget {
        target,
        item_id: binding.item_id.clone(),
        source_revision: atom.source_revision.clone(),
        source_digest: atom.source_digest.clone(),
        strength,
        derived,
    });
    Ok(())
}
