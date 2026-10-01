//! Installation-contour migration for legacy loose scan-disclosure captures.
//!
//! No published legacy locator exists. This pass examines only the canonical
//! installation-protected state directory and retains each matching file as
//! opaque quarantine bytes. A filename or content hash never promotes a file
//! into a scan receipt. The caller must run this at installation bootstrap
//! after it has bound the exact installation's durable scan owner.

use std::path::Path;

use eliot_governor::{InstallationScanDisclosureStore, ScanDisclosureQuarantineHandle};
use eliot_platform_windows::ProtectedRootLease;

/// Reads and durably quarantines every bounded legacy capture from the exact
/// canonical protected-state contour.
///
/// The Governor owner writes the original bytes to its separate ORS
/// quarantine family and authenticates exact readback before each handle is
/// returned. If the pass stops partway through, retry is idempotent for prior
/// files and conflicts on changed bytes under an already-retained basename.
/// Source files are preserved; migration never adopts or deletes them.
///
/// # Errors
///
/// Returns a descriptive failure if the protected contour cannot be pinned,
/// enumeration or bounded reading fails, or any durable quarantine write or
/// readback is unavailable or conflicting. The caller must fail closed rather
/// than proceed as though the migration succeeded.
pub fn quarantine_loose_scan_disclosures(
    canonical_state_root: &Path,
    store: &InstallationScanDisclosureStore,
) -> Result<Vec<ScanDisclosureQuarantineHandle>, String> {
    let root = ProtectedRootLease::open_existing(canonical_state_root)
        .map_err(|error| format!("protected state root could not be pinned: {error}"))?;
    let captures = root
        .read_loose_scan_disclosure_captures()
        .map_err(|error| format!("protected loose-capture read failed: {error}"))?;
    let mut retained = Vec::with_capacity(captures.len());
    for (file_name, bytes) in captures {
        let handle = store
            .quarantine_loose_capture(&file_name, &bytes)
            .map_err(|error| format!("durable loose-capture quarantine failed: {error}"))?;
        retained.push(handle);
    }
    Ok(retained)
}
