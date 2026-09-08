//! Shared bounded-input preflight helpers.

use crate::CueContractError;
use eliot_evidence::Provenance;

/// Maximum bytes in one variable text field in this prototype.
pub const MAX_TEXT_BYTES: usize = 8_192;
/// Maximum canonical output bytes accepted by one contract record.
pub const MAX_OUTPUT_BYTES: usize = 4 * 1024 * 1024;

/// Rejects oversized text before scanning it for content rules.
pub(crate) fn text(value: &str, field: &'static str) -> Result<(), CueContractError> {
    if value.len() > MAX_TEXT_BYTES {
        return Err(CueContractError::BoundExceeded {
            field,
            limit: MAX_TEXT_BYTES,
        });
    }
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(CueContractError::InvalidText { field });
    }
    Ok(())
}

/// Rejects an oversized collection before traversing it.
pub(crate) fn collection<T>(
    values: &[T],
    limit: usize,
    field: &'static str,
) -> Result<(), CueContractError> {
    if values.len() > limit {
        return Err(CueContractError::BoundExceeded { field, limit });
    }
    Ok(())
}

/// Bounds every variable leaf in foundation provenance before owner validation
/// scans its strings.
pub(crate) fn provenance(value: &Provenance, field: &'static str) -> Result<(), CueContractError> {
    text(value.source_id.as_str(), field)?;
    text(value.capture_route.as_str(), field)?;
    text(value.scope.as_str(), field)?;
    if let Some(raw_handle) = value.raw_handle.as_deref() {
        text(raw_handle, field)?;
    }
    if let Some(revision) = value.revision.as_deref() {
        text(revision, field)?;
    }
    Ok(())
}

/// Adds byte counts without wrapping.
pub(crate) fn bytes(
    total: &mut usize,
    amount: usize,
    field: &'static str,
) -> Result<(), CueContractError> {
    *total = total
        .checked_add(amount)
        .ok_or(CueContractError::BoundExceeded {
            field,
            limit: MAX_OUTPUT_BYTES,
        })?;
    if *total > MAX_OUTPUT_BYTES {
        return Err(CueContractError::BoundExceeded {
            field,
            limit: MAX_OUTPUT_BYTES,
        });
    }
    Ok(())
}
