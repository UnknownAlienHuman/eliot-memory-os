//! Bounds shared by the provider-neutral probe declaration records.

use crate::error::{ContractViolation, check_vec_bound, is_hex64_lower};

pub const PROBE_OBJECTIVE_SCHEMA_VERSION: u32 = 1;
pub const PROBE_RESULT_SCHEMA_VERSION: u32 = 1;
pub const MAX_PROBE_WIRE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_PROBE_ITEMS: usize = 256;
pub const MAX_PROBE_TEXT_BYTES: usize = 4096;
pub const MAX_PROBE_BRANCHES: usize = 256;
pub const MAX_PROBE_UPDATES_PER_BRANCH: usize = 256;

pub fn check_sequence(len: usize, field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(len, MAX_PROBE_ITEMS, field)
}

pub fn check_branches(len: usize, field: &'static str) -> Result<(), ContractViolation> {
    check_vec_bound(len, MAX_PROBE_BRANCHES, field)
}

pub fn check_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "expected a lowercase SHA-256 digest".to_owned(),
        })
    }
}
