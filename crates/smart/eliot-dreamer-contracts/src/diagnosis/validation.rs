//! Small bounded helpers shared by diagnosis evidence declarations.
//!
//! These helpers only check wire shape and compute canonical claim digests.
//! They do not authenticate a source, admit a run, or select a repair.

use std::{io, io::Write};

use eliot_contracts::{ArtifactId, ContractId};
use serde::Serialize;

use crate::error::check_text;
use crate::{ContractViolation, canonical_bytes, digest_hex, is_hex64_lower};

/// Maximum bytes accepted for one diagnosis text member.
pub const MAX_DIAGNOSIS_TEXT_BYTES: usize = 1024;
/// Maximum members in any diagnosis sequence owned by these helpers.
pub const MAX_DIAGNOSIS_SEQUENCE_ITEMS: usize = 256;

/// Checks bounded non-blank text using the crate's canonical text validator.
pub fn bounded_text(
    value: &str,
    field: &'static str,
    max_bytes: usize,
) -> Result<(), ContractViolation> {
    check_text(value, field, max_bytes)
}

/// Checks a supplied lowercase SHA-256 claim digest.
pub fn bounded_digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    if is_hex64_lower(value) {
        Ok(())
    } else {
        Err(ContractViolation::Malformed {
            field,
            reason: "digest must be lowercase SHA-256".to_owned(),
        })
    }
}

/// Checks one canonical foundation contract identifier without re-issuing it.
pub fn bounded_contract_id(
    value: &ContractId,
    field: &'static str,
) -> Result<(), ContractViolation> {
    bounded_text(value.as_str(), field, MAX_DIAGNOSIS_TEXT_BYTES)
}

/// Checks a bounded sequence of artifact references while preserving order.
pub fn bounded_artifact_refs(
    refs: &[ArtifactId],
    field: &'static str,
) -> Result<(), ContractViolation> {
    if refs.len() > MAX_DIAGNOSIS_SEQUENCE_ITEMS {
        return Err(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: i64::try_from(MAX_DIAGNOSIS_SEQUENCE_ITEMS).unwrap_or(i64::MAX),
            got: i64::try_from(refs.len()).unwrap_or(i64::MAX),
        });
    }
    for reference in refs {
        bounded_text(reference.as_str(), field, MAX_DIAGNOSIS_TEXT_BYTES)?;
    }
    for pair in refs.windows(2) {
        if pair[0] >= pair[1] {
            return Err(ContractViolation::BindingMismatch {
                field,
                reason: "artifact references must be unique and in canonical order".to_owned(),
            });
        }
    }
    Ok(())
}

/// Computes a canonical digest over a pre-bounded payload.
pub fn canonical_stream_digest<T: Serialize>(payload: &T) -> Result<String, ContractViolation> {
    preflight_canonical_stream(payload)?;
    Ok(digest_hex(&canonical_bytes(payload)?))
}

/// Streams a borrowed payload into a bounded counter without allocating its
/// canonical bytes. This checks only the wire-size ceiling; semantic checks
/// remain the responsibility of the owning declaration.
pub(super) fn preflight_canonical_stream<T: Serialize>(
    payload: &T,
) -> Result<usize, ContractViolation> {
    let mut writer = CountingWriter::new(MAX_DIAGNOSIS_CANONICAL_BYTES);
    serde_json::to_writer(&mut writer, payload).map_err(|error| ContractViolation::Malformed {
        field: "diagnosis.canonical_stream",
        reason: format!("bounded preflight serialization failed: {error}"),
    })?;
    Ok(writer.written)
}

/// Maximum canonical bytes allocated after the streaming preflight succeeds.
pub const MAX_DIAGNOSIS_CANONICAL_BYTES: usize = 4 * 1024 * 1024;

struct CountingWriter {
    written: usize,
    cap: usize,
}

impl CountingWriter {
    const fn new(cap: usize) -> Self {
        Self { written: 0, cap }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .written
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("canonical stream size overflow"))?;
        if next > self.cap {
            return Err(io::Error::other("canonical stream exceeds bounded size"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
