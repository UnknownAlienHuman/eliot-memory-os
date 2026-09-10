//! Intrinsic validation helpers for probe declarations.

use std::io::{self, Write};

use serde::Serialize;

use crate::{canonical_bytes, error::ContractViolation};

use super::bounds::{MAX_PROBE_TEXT_BYTES, MAX_PROBE_WIRE_BYTES, check_digest};

pub(crate) fn text(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    crate::error::check_text(value, field, MAX_PROBE_TEXT_BYTES)
}

pub(crate) fn digest(value: &str, field: &'static str) -> Result<(), ContractViolation> {
    check_digest(value, field)
}

pub(crate) fn preflight<T: Serialize>(value: &T) -> Result<usize, ContractViolation> {
    let mut writer = CountingWriter {
        count: 0,
        maximum: MAX_PROBE_WIRE_BYTES,
    };
    serde_json::to_writer(&mut writer, value).map_err(|error| ContractViolation::Malformed {
        field: "probe.canonical_preflight",
        reason: error.to_string(),
    })?;
    Ok(writer.count)
}

pub(crate) fn canonical_digest<T: Serialize>(value: &T) -> Result<String, ContractViolation> {
    preflight(value)?;
    Ok(crate::digest_hex(&canonical_bytes(value)?))
}

struct CountingWriter {
    count: usize,
    maximum: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self.count.checked_add(bytes.len()).ok_or_else(|| {
            io::Error::new(io::ErrorKind::OutOfMemory, "probe wire size overflow")
        })?;
        if next > self.maximum {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "probe wire size exceeds bound",
            ));
        }
        self.count = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
