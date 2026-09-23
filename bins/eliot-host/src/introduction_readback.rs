//! Authenticated Kernel ORS introduction readback for cutover evidence
//! (issue #961, F-AUR-1).
//!
//! Reads current capability-introduction rows from the canonical ORS owner
//! through the existing authenticated Kernel front-door channel (same
//! transport discipline as the retirement barrier in
//! [`super::lease_drain`]: approved candidate binding, live process +
//! image authentication, framed request/response with digest echo, strict
//! response binding). Pure owner read: no state gate, no mutation, no
//! admission — absent rows refuse the whole query closed so a partial view
//! can never read as complete. Returned rows are owner-held evidence the
//! cutover contour compares against console-presented rows; they are never
//! authority by themselves.

use super::{
    HostComposition, HostError, connect_authenticated_kernel_front_door,
    kernel_control_request, validate_authenticated_kernel_peer,
};
use eliot_contracts::StateFence;
use eliot_kernel_service::{IntroductionReadbackQuery, IntroductionRow, KernelControlCommand};

/// Reads the complete live capability-introduction set from the Kernel ORS
/// owner through the authenticated front door.
///
/// Binds the approved Kernel candidate to the cutover fence, opens the
/// authenticated transport to the live Kernel process, sends one
/// full-enumeration readback query, and validates the response binding
/// (message/digest echo, no error, no unrelated receipts). Transport loss,
/// unknown outcomes, over-bound tables, and binding mismatches refuse
/// closed; callers compare the complete set exactly against presented
/// evidence — partial views never verify.
///
/// # Errors
///
/// Returns `HostError` when no approved candidate/process/image exists,
/// the candidate disagrees with the fence, transport fails, or the
/// response binding is not exact.
pub(crate) fn read_live_introductions(
    host: &HostComposition,
    fence: &StateFence,
    max_rows: u16,
) -> Result<Vec<IntroductionRow>, HostError> {
    let launch = host.jobs.launch.as_ref().ok_or_else(|| {
        HostError::ProcessContour(
            "introduction readback has no current approved Kernel launch".to_owned(),
        )
    })?;
    let candidate = host.jobs.kernel_candidate.as_ref().ok_or_else(|| {
        HostError::ProcessContour(
            "introduction readback has no approved Kernel candidate binding".to_owned(),
        )
    })?;
    if candidate.kernel_epoch != fence.authority_epoch {
        return Err(HostError::RecoveryRequired(
            "authenticated Kernel candidate does not match the readback fence".to_owned(),
        ));
    }
    let kernel = host.jobs.kernel.as_ref().ok_or_else(|| {
        HostError::ProcessContour(
            "introduction readback requires the live authenticated Kernel process".to_owned(),
        )
    })?;
    let kernel_process = kernel.evidence().process().clone();
    let expected_kernel_image = host.jobs.kernel_executable.as_ref().ok_or_else(|| {
        HostError::ProcessContour("approved Kernel image is missing".to_owned())
    })?;
    let query = IntroductionReadbackQuery {
        max_rows,
    };
    query
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let request = kernel_control_request(
        candidate,
        launch.authority_generation,
        KernelControlCommand::ReadIntroductionRows(query),
        1,
    )?;
    let connection_id = format!(
        "host-introduction-readback:{}:{}",
        candidate.activation_id.as_str(),
        fence.resource_generation.value()
    );
    let request_frame = eliot_kernel_service::control_request_frame(connection_id, &request)
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    let response = runtime.block_on(async {
        let mut transport =
            connect_authenticated_kernel_front_door(candidate, &kernel_process).await?;
        validate_authenticated_kernel_peer(
            transport.peer_identity(),
            kernel_process.process_id,
            kernel_process.start_time_100ns,
            expected_kernel_image,
        )?;
        let limits = eliot_ipc::TransportLimits::default();
        match transport.send_frame(&request_frame, limits).await.map_err(|error| {
            HostError::RecoveryRequired(error.to_string())
        })? {
            eliot_ipc::DeliveryOutcome::Delivered => {}
            eliot_ipc::DeliveryOutcome::UnknownOutcome => {
                return Err(HostError::RecoveryRequired(
                    "Kernel introduction readback delivery outcome is unknown".to_owned(),
                ));
            }
        }
        let frame = transport.receive_frame(limits).await.map_err(|error| {
            HostError::RecoveryRequired(error.to_string())
        })?;
        eliot_kernel_service::decode_control_response_frame(&frame)
            .map_err(|error| HostError::RecoveryRequired(error.to_string()))
    })?;
    response
        .validate()
        .map_err(|error| HostError::ProcessContour(error.to_string()))?;
    if response.message_id != request.message_id
        || response.request_digest != request.payload_digest
        || response.error.is_some()
        || response.receipt.is_some()
        || response.runtime_health.is_some()
        || response.activation_receipt.is_some()
        || response.store_rebind_receipt.is_some()
        || response.supervision_lease.is_some()
        || response.runtime_lease_census.is_some()
    {
        return Err(HostError::RecoveryRequired(
            "Kernel introduction readback response binding was not exact".to_owned(),
        ));
    }
    response.introduction_rows.ok_or_else(|| {
        HostError::RecoveryRequired(
            "Kernel omitted the introduction rows from the readback response".to_owned(),
        )
    })
}
