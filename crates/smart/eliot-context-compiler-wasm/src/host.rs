//! Native host preflight composition for learning-marked retrieval (#1869).
//!
//! Host-only module: gated out of the `wasm32` guest build, so Governor
//! evidence can never enter the guest. The guest keeps calling plain
//! [`admit_context`](eliot_context_admission::admit_context) over verbatim
//! envelopes; verification happens here, on the host, before the native
//! invocation runs:
//!
//! 1. Envelope check (existing [`check_envelope`] rule).
//! 2. Owner rebind: [`verify_learning_admission`] rebinds the presented
//!    owner-issued permit to the live [`Governor`] and the compilation
//!    fence. Stale epoch/generation/fence or tampering refuses here.
//! 3. Host preflight: [`screen_admission_input_learning`] screens every
//!    learning-marked atom in the input. Any violation refuses here.
//! 4. Only then the real consumer invocation
//!    ([`handle_request_typed`]) runs.
//!
//! Refusals return a typed [`GuestResponse`] with `native_calls == 0`,
//! proving `admit_context` never ran: nothing surfaces. This is the
//! documented preflight the `eliot-wasm-host` composition root calls
//! before guest invocation for inputs carrying learning marks.

use eliot_context_admission::screen_admission_input_learning;
use eliot_contracts::fences_match_exact;
use eliot_governor::{
    Governor, LearningAdmissionError, LearningAdmissionPermit, verify_learning_admission,
};

use crate::conversion::{
    GuestError, GuestRequest, GuestResponse, check_envelope, handle_request_typed,
};

/// Map an owner verification failure onto the closed guest error set.
fn admission_error_to_guest(error: &LearningAdmissionError) -> GuestError {
    match error {
        LearningAdmissionError::MissingField(field) => {
            GuestError::MissingField((*field).to_owned())
        }
        LearningAdmissionError::UnsupportedSchema { version } => {
            GuestError::InvalidField(format!("learning.schema_version:{version}"))
        }
        LearningAdmissionError::NoInfluenceSubject => {
            GuestError::InvalidField("learning.subject".to_owned())
        }
        LearningAdmissionError::InvalidFence | LearningAdmissionError::StaleStateFence => {
            GuestError::InvalidFence
        }
        LearningAdmissionError::GovernorNotAdmitting => {
            GuestError::RejectedEnvelope("governor-not-admitting".to_owned())
        }
        LearningAdmissionError::StaleAuthorityEpoch
        | LearningAdmissionError::GenerationMismatch
        | LearningAdmissionError::DigestMismatch => GuestError::IdentityConflict,
    }
}

fn refused(request: &GuestRequest, error: GuestError) -> GuestResponse {
    GuestResponse {
        abi_version: request.abi_version,
        handler_subtype: request.handler_subtype.clone(),
        result: None,
        error: Some(error),
        native_calls: 0,
    }
}

/// Host preflight composition: verify, screen, then invoke.
///
/// `permit` is the owner-issued admission presented alongside the request
/// (opaque to transport; it never crosses the guest ABI). Every refusal
/// returns before the native gate runs.
pub fn compile_learning_context(
    governor: &Governor,
    permit: &LearningAdmissionPermit,
    request: &GuestRequest,
    now_unix_secs: u64,
) -> GuestResponse {
    if let Err(error) = check_envelope(request) {
        return refused(request, error);
    }
    // Compilation-level binding: the served task and fence must be the
    // admitted ones. Per-atom bindings are re-checked in the screen below;
    // this catches a foreign compilation embedding correctly-bound atoms.
    if request.input.binding.task_id.as_str() != permit.target_task_id() {
        return refused(request, GuestError::IdentityConflict);
    }
    if !fences_match_exact(&request.input.binding.state_fence, permit.fence()) {
        return refused(request, GuestError::InvalidFence);
    }
    let verified =
        match verify_learning_admission(governor, permit, &request.input.binding.state_fence) {
            Ok(verified) => verified,
            Err(error) => return refused(request, admission_error_to_guest(&error)),
        };
    if let Err(error) = screen_admission_input_learning(&request.input, &verified, now_unix_secs) {
        return refused(request, GuestError::from(&error));
    }
    handle_request_typed(request)
}
