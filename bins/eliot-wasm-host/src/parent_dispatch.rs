//! Owner-admitted parent dispatch production entrypoint (issue #1955).
//!
//! Callable binding between staged owner-published dispatch material and an
//! injected [`WasmHostRunner`](crate::WasmHostRunner): pure admission over
//! admitted values, then contour-gated execution through the injected A-12
//! surface, then canonical result classification. This module builds no
//! ports, mints no permits, reads no clock, and fabricates no receipts:
//! the runner (with owner-built ports) and the material (owner-published)
//! are both caller-provided. Absent either, there is nothing to drive and
//! the caller must not call.

use crate::dispatch_drive::map_invocation_result;
use crate::dispatch_drive::{drive_admission, DispatchDriveResponse, DriveError};
use crate::dispatch_material::ValidatedDispatchMaterial;
use crate::WasmHostRunner;

/// Drives one owner-admitted parent dispatch to the canonical response.
///
/// Order: [`drive_admission`] (invocation assembly, contour-prior gate,
/// byte admission), optional learning screen over the admitted input
/// bytes, contour-gated execution via
/// [`WasmHostRunner::execute_admitted`], then [`map_invocation_result`]
/// classification. A contour-gate refusal surfaces as
/// [`DriveError::Admission`] with field `"contour-gate"`: fail-closed,
/// existing taxonomy, no new error kinds.
pub fn drive_parent_dispatch(
    material: &ValidatedDispatchMaterial,
    runner: &mut WasmHostRunner,
    screen: Option<&dyn Fn(&[u8]) -> Result<(), DriveError>>,
) -> Result<DispatchDriveResponse, DriveError> {
    let (request, admitted) = drive_admission(material)?;
    if let Some(screen) = screen {
        screen(&material.input_bytes)?;
    }
    let result =
        runner
            .execute_admitted(&admitted, request)
            .map_err(|_| DriveError::Admission {
                field: "contour-gate",
            })?;
    map_invocation_result(&result, material)
}
