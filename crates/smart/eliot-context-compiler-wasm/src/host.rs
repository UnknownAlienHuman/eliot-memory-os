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
//! 4. Only then the real native admission invocation runs. The guest's
//!    `handle_request_typed` closure is intentionally not used here: it
//!    rejects marked input because it has no owner evidence.
//!
//! Refusals return a typed [`GuestResponse`] with `native_calls == 0`,
//! proving `admit_context` never ran: nothing surfaces. This is the
//! documented preflight the `eliot-wasm-host` composition root calls
//! before guest invocation for inputs carrying learning marks.

use eliot_context_admission::{admit_context, screen_admission_input_learning};
use eliot_context_contracts::LearningRecordAdmissionTicket;
use eliot_contracts::fences_match_exact;
use eliot_governor::{
    Governor, LearningAdmissionError, LearningAdmissionPermit, LearningRecordIdentity,
    verify_learning_admission, verify_learning_record_admission, verify_learning_record_ticket,
};

use crate::conversion::{GuestError, GuestRequest, GuestResponse, check_envelope};

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
        | LearningAdmissionError::DigestMismatch
        | LearningAdmissionError::MissingRecordBinding
        | LearningAdmissionError::RecordIdentityMismatch
        | LearningAdmissionError::AdmissionExpired
        | LearningAdmissionError::MissingDurabilityEvidence
        | LearningAdmissionError::DurabilityEvidenceMismatch => GuestError::IdentityConflict,
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

fn invoke_native_after_preflight(request: &GuestRequest) -> GuestResponse {
    match admit_context(&request.input) {
        Ok(result) => GuestResponse {
            abi_version: request.abi_version,
            handler_subtype: request.handler_subtype.clone(),
            result: Some(result),
            error: None,
            native_calls: 1,
        },
        Err(error) => GuestResponse {
            abi_version: request.abi_version,
            handler_subtype: request.handler_subtype.clone(),
            result: None,
            error: Some(GuestError::from(&error)),
            native_calls: 1,
        },
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
    if !request.input.learning_tickets.is_empty()
        || request
            .input
            .candidates
            .candidates
            .iter()
            .any(|candidate| candidate.learning.is_some())
    {
        return refused(request, GuestError::LearningRequiresGovernedPath);
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
    invoke_native_after_preflight(request)
}

/// Record-bound host preflight for the production Context Compiler path.
///
/// The opaque permit, exact record identity, and serializable record ticket
/// must agree before any marked atom reaches native admission. This function
/// is deliberately separate from the legacy influence-only entrypoint above;
/// behavioral carriage cannot silently fall back to that contour.
pub fn compile_record_learning_context(
    governor: &Governor,
    permit: &LearningAdmissionPermit,
    record_identity: &LearningRecordIdentity,
    record_ticket: &LearningRecordAdmissionTicket,
    request: &GuestRequest,
    now_unix_secs: u64,
    now_unix_ms: u64,
) -> GuestResponse {
    if let Err(error) = check_envelope(request) {
        return refused(request, error);
    }
    if request.input.binding.task_id.as_str() != permit.target_task_id() {
        return refused(request, GuestError::IdentityConflict);
    }
    if !fences_match_exact(
        &request.input.binding.state_fence,
        &record_identity.state_fence,
    ) || !fences_match_exact(&request.input.binding.state_fence, permit.fence())
    {
        return refused(request, GuestError::InvalidFence);
    }
    let verified = match verify_learning_record_admission(
        governor,
        permit,
        &request.input.binding.state_fence,
        record_identity,
        now_unix_ms,
    ) {
        Ok(verified) => verified,
        Err(error) => return refused(request, admission_error_to_guest(&error)),
    };
    let expected_ticket = match permit.record_ticket() {
        Ok(ticket) => ticket,
        Err(error) => return refused(request, admission_error_to_guest(&error)),
    };
    if expected_ticket.digest != record_ticket.digest {
        return refused(request, GuestError::IdentityConflict);
    }
    let has_learning = request
        .input
        .candidates
        .candidates
        .iter()
        .any(|candidate| candidate.learning.is_some());
    if !request.input.learning_tickets.is_empty()
        && (!has_learning
            || request
                .input
                .learning_tickets
                .iter()
                .any(|ticket| ticket.digest != permit.digest()))
    {
        return refused(request, GuestError::IdentityConflict);
    }
    if let Err(error) = verify_learning_record_ticket(
        governor,
        record_ticket,
        &request.input.binding.state_fence,
        record_identity,
        now_unix_ms,
    ) {
        return refused(request, admission_error_to_guest(&error));
    }
    if let Err(error) = screen_admission_input_learning(&request.input, &verified, now_unix_secs) {
        return refused(request, GuestError::from(&error));
    }
    invoke_native_after_preflight(request)
}
