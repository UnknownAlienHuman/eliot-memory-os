//! Content-addressed owner-record publication on the live Dreamer job seam
//! (issue #40, W1/A1).
//!
//! # What this publishes
//!
//! The owner records the Orientation carrier needs are not a single typed
//! value: the CC-004 canonical projection set, the Current Epistemic Position
//! handles and every remaining mandatory stage record are separate records
//! published by separate owners. [`eliot-protocol`] must not grow a dependency
//! on the crate that types them, so the seam between the Kernel front door and
//! the managed worker carries the records as ONE opaque, content-addressed
//! reference per job: [`OpaqueContentRef`]. This module is the Kernel half of
//! that channel.
//!
//! # Who produces the record
//!
//! The producer is the owner that issued it, never this Kernel. The Kernel
//! holds the record only as the value its own front door was given on the
//! admitted request, and it publishes that exact reference. The digest and the
//! byte length were computed by the owner that produced the record; this
//! module re-proves them against the ORIGINAL RECORDED value through the
//! existing [`OpaqueContentRef::validate`] and never recomputes them here, so a
//! substituted or re-issued record cannot travel as the original one.
//!
//! # What this deliberately does not do
//!
//! It does not mint an owner record. There is no in-binary producer of a
//! canonical projection set, a `PhasePolicyRule`, or a `DreamJobRecipe` here or
//! in the Kernel crate, and manufacturing one would be the self-issued
//! authority the Orientation carrier's own contract refuses. A job whose owner
//! published no record keeps publishing `None`; that absence stays typed and is
//! never turned into an empty record, a zero length, or a synthesized member.
//!
//! # Production chain
//!
//! `KernelComposition::execute_dreamer_request`
//! (bins/eliot-kernel/src/dreamer_job_dispatch.rs) calls
//! [`publish_owner_record`] on its single admitted store answer, so the
//! publication happens on the live front door. The record then rides
//! [`DurableJobResponse::owner_record`] to the managed worker, whose
//! `kernel_port::validate_owner_response_binding`
//! (bins/eliot-dreamer/src/kernel_port.rs) re-proves the recorded value and
//! records its presence, digest and byte length without interpreting it.

use eliot_protocol::dreamer_job::{DurableJobRequest, DurableJobResponse, JobOperation};

use super::TransportError;

/// Publishes the owner record the Kernel front door holds onto one admitted
/// Dreamer answer.
///
/// Called once per admitted envelope from
/// [`KernelComposition::project_dreamer_call`](super::KernelComposition::project_dreamer_call),
/// which is the single rendering every production Dreamer reply passes
/// through.
///
/// A `SUBMIT_JOB` carries the owner's record on the submission, so the Kernel
/// holds it here: the record is re-proved against the original recorded value
/// and published onto the answer. An answer that contradicts it — a different
/// contract, revision, digest, byte length or artifact handle — fences, because
/// a durable owner that answered with a different record has not answered this
/// submission.
///
/// Every other closed operation (`LeaseExact`, `Start`, `Status`, …) carries no
/// submission, so the Kernel holds no owner record to publish for them and
/// publishes none: the durable owner's own retained projection travels
/// unchanged, and `None` is never written over a record the durable owner did
/// publish.
pub(crate) fn publish_owner_record(
    request: &DurableJobRequest,
    response: &mut DurableJobResponse,
) -> Result<(), TransportError> {
    let JobOperation::Submit { submission } = &request.operation else {
        return Ok(());
    };
    let Some(owner_record) = &submission.owner_record else {
        return Ok(());
    };
    owner_record
        .validate("owner_record.sha256")
        .map_err(|_| TransportError::SessionFenced)?;
    if let Some(published) = &response.owner_record
        && published != owner_record
    {
        return Err(TransportError::SessionFenced);
    }
    response.owner_record = Some(owner_record.clone());
    Ok(())
}
