#![forbid(unsafe_code)]

//! Governor injection points for the two admitted-stage owner records the
//! Orientation seam sits behind (issue #41, step 1).
//!
//! # Why this module exists
//!
//! `AuthenticatedKernelJobPort::submit` reaches
//! [`resolve_orientation_supply`](crate::AuthenticatedKernelJobPort) only after
//! two gates: [`controller::resolve_cycle_inputs`](crate::controller::resolve_cycle_inputs)
//! and [`bundle_stage::resolve_bundle_request`](crate::bundle_stage::resolve_bundle_request).
//! Both ended in a bare `Err(..)` on `main`, so neither the Orientation owner
//! channel nor anything downstream of it was reachable from a real run: the
//! gates were not merely unpopulated, they were *unaddressable*. This crate
//! already owns the shape that fixes that — [`CurationCarrierSource`](crate::CurationCarrierSource)
//! and [`OrientationSupplySource`](crate::OrientationSupplySource) are both
//! declared Governor injection points wired at `connect()` and replaceable
//! through a `with_*_source` builder — and this module adds the two missing
//! instances of exactly that shape rather than a new mechanism.
//!
//! # What a source may publish
//!
//! [`AdmittedStageMaterialSource`] publishes values the issuing owner already
//! produced through its own owner entry:
//!
//! * [`ControllerSnapshot`] — the frozen #806 controller state, the recorded
//!   owner observations, the frozen #806 cycle policy, and the observation time
//!   the owner observed;
//! * the A-04 [`AssemblyRequest`] — the owner-issued job recipe, the frozen
//!   manifest, the owner-supplied items and the qualified measurement profile.
//!
//! Both resolvers re-prove the published value against this exact claim before
//! the owner transition or the owner plan runs, and both owner entries then run
//! for real and may still refuse. Nothing here derives, defaults, or invents a
//! member: `Ok(None)` is the measured absence the carrier refuses on, and `Err`
//! is reserved for a genuine refusal (a record that is not this claim's).
//!
//! # What the production instance reports
//!
//! [`KERNEL_STAGED_STAGE_MATERIAL_SOURCE`] is the instance
//! [`AuthenticatedKernelJobPort::connect`](crate::AuthenticatedKernelJobPort::connect)
//! wires. It re-proves the admitted binding and then reports the absence it
//! actually measures.
//!
//! That absence is real and is not repaired here. The controller snapshot needs
//! a `CyclePolicy` whose per-phase `PhasePolicyRule` names the owner, product,
//! source, operation kind, effect class and proof ceiling for each phase, and
//! the bundle request needs a `DreamJobRecipe` with an owner-issued recipe
//! identity and revision, an `AssemblyReserveSet`, and a qualified
//! `MeasurementCompositionProfile`. None of those has an in-binary producer:
//! `git grep` finds no `pub fn` anywhere under `crates/` that builds a
//! `CyclePolicy`, a `PhasePolicyRule` or a `DreamJobRecipe`, and
//! `bins/eliot-kernel/src/dreamer_owner_record.rs` states the same fact from the
//! publishing side — "There is no in-binary producer of a canonical projection
//! set, a `PhasePolicyRule`, or a `DreamJobRecipe` here or in the Kernel crate,
//! and manufacturing one would be the self-issued authority the Orientation
//! carrier's own contract refuses." Filling either gate from this binary would
//! therefore be the fabricated policy the carrier refuses, so the production
//! answer stays the honest refusal and the channel is the place a real owner
//! record arrives.

use eliot_dreamer_bundle::AssemblyRequest;
use eliot_dreamer_cycle::{CyclePolicy, DreamerCycleState, ObservedOutcome};

use crate::controller::verify_admitted_binding;
use crate::{DreamJobInput, DreamerError, KernelJobAdmission};

/// The owner-published #806 controller snapshot for one admitted claim.
///
/// Every field is a value the issuing owner produced through its own entry. The
/// binary reads them, re-proves the binding, and hands them to the real
/// [`step_dreamer_cycle_at`](eliot_dreamer_cycle::step_dreamer_cycle_at); it
/// never fills one in locally.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControllerSnapshot {
    /// Frozen controller state the owner published for this claim.
    pub state: DreamerCycleState,
    /// Owner-issued observations already recorded against that state.
    pub observed: Vec<ObservedOutcome>,
    /// Frozen #806 cycle policy the transition must run under.
    pub policy: CyclePolicy,
    /// Observation time the owner observed, when it observed one.
    pub observation_time_ms: Option<i64>,
}

/// Governor injection point for the two admitted-stage owner records.
///
/// Object-safe by construction: no generic parameters, no lifetime on the trait
/// itself, and both methods return owned values, so the resolved record is never
/// entangled with the borrow of the source that published it. That is what lets
/// `submit` resolve both records before it runs any owner work and still hold
/// them across the pipeline.
pub trait AdmittedStageMaterialSource {
    /// Resolves the #806 controller snapshot for one admitted claim.
    ///
    /// `Ok(None)` means the owner published no controller snapshot for this
    /// claim, which leaves the controller gate refused rather than filled from a
    /// locally built state.
    fn resolve_controller_snapshot(
        &self,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<Option<ControllerSnapshot>, DreamerError>;

    /// Resolves the A-04 assembly request for one admitted claim.
    ///
    /// `Ok(None)` means the owner published no recipe, manifest, supplied item
    /// or measurement profile for this claim, which leaves the bundle gate
    /// refused rather than filled from a locally selected denominator.
    fn resolve_bundle_request(
        &self,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<Option<AssemblyRequest>, DreamerError>;
}

/// Production owner channel for the two admitted-stage records.
///
/// A unit type because the read is a function of the presented claim rather than
/// of retained adapter state: it stores no job, no snapshot and no cache, so one
/// instance serves every admitted job and nothing can go stale between
/// resolution and composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelStagedStageMaterialSource;

/// The single production instance wired by `AuthenticatedKernelJobPort::connect`.
///
/// A `static` rather than a local because the port holds the source by reference
/// for its whole lifetime and `connect` has no caller frame to borrow from. The
/// type is a unit struct with no interior mutability, so sharing one instance
/// raises no shared-state concern.
pub(crate) static KERNEL_STAGED_STAGE_MATERIAL_SOURCE: KernelStagedStageMaterialSource =
    KernelStagedStageMaterialSource;

impl AdmittedStageMaterialSource for KernelStagedStageMaterialSource {
    /// Reports the controller-snapshot absence this claim's owner channel has.
    ///
    /// The claim already proved the presented pair; this call re-proves it
    /// through the crate's existing
    /// [`verify_admitted_binding`](crate::controller::verify_admitted_binding) —
    /// the same gate every other admitted-stage resolver in this crate runs —
    /// before it reports anything, so a caller cannot present another claim's
    /// controller material under this admission.
    fn resolve_controller_snapshot(
        &self,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<Option<ControllerSnapshot>, DreamerError> {
        verify_admitted_binding(admission, job)?;
        Ok(None)
    }

    /// Reports the A-04 assembly-request absence this claim's owner channel has.
    ///
    /// The same binding re-proof runs first, for the same reason. The record the
    /// Kernel publishes alongside a submission is an
    /// [`OpaqueContentRef`](eliot_protocol::dreamer_job::OpaqueContentRef) — a
    /// digest, a byte length and an artifact handle — and this binary holds no
    /// content-retrieval capability that could turn that address into a typed
    /// member, so the measured answer is absence rather than a decoded
    /// lookalike.
    fn resolve_bundle_request(
        &self,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<Option<AssemblyRequest>, DreamerError> {
        verify_admitted_binding(admission, job)?;
        Ok(None)
    }
}
