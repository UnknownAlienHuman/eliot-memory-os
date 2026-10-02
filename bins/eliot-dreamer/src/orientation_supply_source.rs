//! Production [`OrientationSupplySource`](crate::OrientationSupplySource) for the
//! Orientation Product Pulse (issue #40).
//!
//! This module is the production implementor of the owner channel the crate
//! already declares. [`AuthenticatedKernelJobPort::connect`](crate::AuthenticatedKernelJobPort::connect)
//! wires it, and
//! [`AuthenticatedKernelJobPort::submit`](crate::AuthenticatedKernelJobPort::submit)
//! consults it for admitted `JobClass::Orientation` jobs through the existing
//! `resolve_orientation_supply` seam at lib.rs:802.
//!
//! # Reachability, measured rather than assumed
//!
//! `submit` is the only production caller of
//! [`OrientationSupplySource::resolve_supply`], but on the current tree it
//! never *reaches* that call. Two gates run first and both refuse
//! unconditionally: `controller::resolve_cycle_inputs` (controller.rs:66-82)
//! and `bundle_stage::resolve_bundle_request` (bundle_stage.rs:27-35) each end
//! in a bare `Err`. So this implementation is presently reachable only from the
//! crate's unit-level pipeline proofs, not from `main.rs`. That is a property of
//! the tree, stated here so the next attempt measures it rather than assuming
//! the seam is live.
//!
//! # What this source reads
//!
//! Two owner records reach this process, and both are proved rather than
//! assumed.
//!
//! The first is the closed semantic input the Kernel staged, presented as the
//! admitted [`DreamJobInput`](crate::DreamJobInput) beside the Kernel-issued
//! [`KernelJobAdmission`](crate::KernelJobAdmission). `staged_job_input`
//! digest-verifies those bytes against the owner's own `semantic_input`
//! reference at claim time.
//!
//! The second is the opaque, content-addressed owner record the Kernel
//! published with the job
//! (`KernelComposition::execute_dreamer_request` in
//! bins/eliot-kernel/src/dreamer_job_dispatch.rs publishes it, the durable owner
//! projects it, and `kernel_port::validate_owner_response_binding`
//! re-proves the ORIGINAL recorded digest and byte length without recomputing
//! them). That record is an `OpaqueContentRef`: a digest, a byte length and an
//! artifact handle, with no member in it. This binary holds no capability that
//! could resolve one — there is no blob or artifact read anywhere under
//! `bins/eliot-dreamer/src` — so the record is an address this process cannot
//! dereference, not a value it can supply.
//!
//! # What it does not publish
//!
//! [`OrientationSupply`](crate::OrientationSupply) carries twenty-five mandatory
//! members: the CC-004 canonical projection set, the Current Epistemic Position
//! handles, and the owner record set of every remaining mandatory stage. The
//! closed [`DreamJobInput`](crate::DreamJobInput) schema publishes the question,
//! the requester, the identity and fence, the five evidence handle families,
//! the declared conflicts and unknowns, the privacy profile, the allowed tools
//! and model routes, the budget units, the deadline, the output schema, and the
//! forbidden effects.
//!
//! The opaque owner record publishes no member either. It is a content
//! ADDRESS, not a typed value: `eliot-protocol` deliberately carries it without
//! a dependency on the crate that types the CC-004 projection set, so nothing in
//! this binary can decode it into a `CanonicalProjectionSet`, an epistemic
//! handle, or a stage-owner record. Until a typed seam exists, the record's
//! presence is a fact about the channel and not about any member — and treating
//! it as one would be exactly the fabricated member this channel refuses to
//! produce.
//!
//! # Consequence, stated rather than papered over
//!
//! The carrier admits no missing-stage partial, so the absence of any one
//! mandatory member leaves the whole channel absent. This source therefore
//! reports absence instead of filling a member, and the existing typed blocked
//! disposition publishes unchanged: `resolve_production_inputs` returns the
//! result built by
//! [`supply_missing_blocked`](crate::production_orientation::supply_missing_blocked),
//! carrying `OrientationDisposition::Blocked`, no packet, `CC004_MISSING` on
//! the CC-004 boundary record, and `missing_owners` naming the canonical
//! projection owner plus every stage owner.
//!
//! No default is substituted, no lookalike value is synthesized, no stage is
//! skipped to make a member fire, and no partial channel is invented that would
//! merely restate the blocked result.
//!
//! Typed failures stay typed across the layer boundary. A presented pair that
//! is not the claimed job is the crate's existing
//! [`verify_admitted_binding`](crate::controller::verify_admitted_binding)
//! refusal, and a carrier reached under a class other than Orientation is a
//! routing defect with its own typed refusal; both are errors. An owner record
//! that was never published is neither: it is the measured absence reported
//! here. This source never collapses one condition into another.
//!
//! There is deliberately no arm that returns a present channel. No owner
//! publishes these records to this process, and manufacturing the values that
//! would fill one is exactly the self-issued authority the carrier's own
//! contract forbids. When an owner channel is admitted, it arrives as a
//! different implementor of the same trait; this one keeps reporting the
//! absence it actually measures.

use crate::controller::verify_admitted_binding;
use crate::{
    DreamJobInput, DreamerError, JobClass, KernelJobAdmission, OrientationSupply,
    OrientationSupplySource,
};

/// Production owner channel for the mandatory Orientation carrier.
///
/// A unit type because the read is a function of the presented owner record
/// rather than of retained adapter state: this source stores no job, no
/// snapshot, and no cache, so one instance serves every admitted job and
/// nothing can go stale between resolution and composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KernelStagedOwnerRecordSource;

/// The single production instance wired by `AuthenticatedKernelJobPort::connect`.
///
/// A `static` rather than a local because the port holds the source by reference
/// for its whole lifetime and `connect` has no caller frame to borrow from. The
/// type is a unit struct with no interior mutability, so sharing one instance
/// raises no shared-state concern.
pub(crate) static KERNEL_STAGED_OWNER_RECORD_SOURCE: KernelStagedOwnerRecordSource =
    KernelStagedOwnerRecordSource;

impl OrientationSupplySource for KernelStagedOwnerRecordSource {
    /// Reports the mandatory-member absence this admitted job's owner channel
    /// actually has.
    ///
    /// The claim already proved the presented pair: the staged bytes matched the
    /// owner's `semantic_input` digest, and `job_id`, `scope_id`, and
    /// `state_fence` matched the staged material. This call re-proves that
    /// binding through the crate's existing `verify_admitted_binding` — the same
    /// gate every other admitted-stage resolver in this crate runs — before it
    /// reports anything, so a caller cannot present another job's owner record
    /// under this claim.
    ///
    /// It then reports the measured absence of the carrier's mandatory member
    /// set. That is the only honest answer here: the owner record proves the
    /// channel carries an owner-published *reference*, not that the reference
    /// names a typed member this binary can supply — and this binary has no
    /// content-retrieval capability that could turn one into the other. See the
    /// module documentation for the measured reason and for why no
    /// present-channel arm exists.
    fn resolve_supply<'s>(
        &'s self,
        admission: &KernelJobAdmission,
        job: &DreamJobInput,
    ) -> Result<Option<OrientationSupply<'s>>, DreamerError> {
        verify_admitted_binding(admission, job)?;
        if job.job_class != JobClass::Orientation {
            return Err(DreamerError::InvalidAdmission(
                "the orientation owner channel admits orientation jobs only",
            ));
        }
        Ok(None)
    }
}
