//! Local bounds and validation helpers for the probe planner.
//!
//! Mirrors the contracts-side validation pattern: bounded text, lowercase
//! SHA-256 digests, a wire-size preflight before canonical allocation, and a
//! canonical digest over validated shapes. Bounds failures fail closed with
//! [`ContractViolation`].

use eliot_dreamer_contracts::{
    ContractViolation,
    error::{check_vec_bound, is_hex64_lower, len_i64},
};
use serde::Serialize;

/// Wire revision for one closed probe plan.
pub const PROBE_PLAN_SCHEMA_VERSION: u32 = 1;
/// Maximum probes or omissions accepted in one plan.
pub const MAX_PROBE_PLAN_ITEMS: usize = 256;
/// Maximum merged duplicate identities recorded on one probe or omission.
pub const MAX_PROBE_PLAN_MERGED: usize = 256;
/// Maximum bounded text accepted in one plan field.
pub const MAX_PROBE_PLAN_TEXT_BYTES: usize = 4096;
/// Maximum canonical wire bytes accepted for one plan.
pub const MAX_PROBE_PLAN_WIRE_BYTES: usize = 4 * 1024 * 1024;

/// Rejects blank, over-long, or control-character text against the plan bound.
pub(crate) fn text(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    eliot_dreamer_contracts::error::check_text(value, field, MAX_PROBE_PLAN_TEXT_BYTES)
}

/// Rejects a digest that is not exactly 64 lowercase hex characters.
pub(crate) fn digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "expected a lowercase SHA-256 digest".to_owned(),
        })
    }
}

/// Rejects a sequence longer than the plan item bound.
pub(crate) fn sequence(len: usize, field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(len, MAX_PROBE_PLAN_ITEMS, field)
}

/// Bounds the canonical wire size before digest allocation; fails closed.
pub(crate) fn preflight<T: Serialize>(value: &T) -> Result<usize, ContractViolation> {
    let bytes = eliot_dreamer_contracts::canonical_bytes(value)?;
    if bytes.len() > MAX_PROBE_PLAN_WIRE_BYTES {
        return Err(ContractViolation::OutOfBounds {
            field: "probe_plan.canonical_preflight",
            min: 0,
            max: len_i64(MAX_PROBE_PLAN_WIRE_BYTES),
            got: len_i64(bytes.len()),
        });
    }
    Ok(bytes.len())
}

/// Returns the canonical digest over a validated shape, bounding wire first.
pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ContractViolation> {
    preflight(value)?;
    Ok(eliot_dreamer_contracts::digest_hex(
        &eliot_dreamer_contracts::canonical_bytes(value)?,
    ))
}
