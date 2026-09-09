//! Canonical encoding helpers for versioned grounding preimages.

use crate::{ContractViolation, canonical_bytes, digest_hex};
use serde::Serialize;
use std::io::{self, Write};

/// The generic serializer is deliberately private to this namespace. Public
/// contracts expose typed digest methods, each of which supplies a borrowed
/// self-excluding preimage and performs this bounded pass first.
pub(super) fn digest<T: Serialize>(value: &T) -> Result<String, ContractViolation> {
    preflight(value)?;
    Ok(digest_hex(&canonical_bytes(value)?))
}

pub(super) fn preflight<T: Serialize>(value: &T) -> Result<usize, ContractViolation> {
    let mut writer = CountingWriter::new(super::MAX_HANDOFF_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|error| ContractViolation::Malformed {
        field: "grounding_encoding",
        reason: format!("typed preimage serialization failed: {error}"),
    })?;
    Ok(writer.count)
}

struct CountingWriter {
    count: usize,
    ceiling: usize,
}

impl CountingWriter {
    const fn new(ceiling: usize) -> Self {
        Self { count: 0, ceiling }
    }
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("preimage byte counter overflow"))?;
        if self.count > self.ceiling {
            return Err(io::Error::other("grounding preimage exceeds byte ceiling"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
