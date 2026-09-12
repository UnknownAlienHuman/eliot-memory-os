use std::{collections::BTreeSet, io::{self, Write}};

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use serde::Serialize;
use serde_json::to_writer;

use crate::ImplementationBriefError;

pub(crate) const MAX_TEXT_BYTES: usize = 64 * 1024;
pub(crate) const MAX_ID_BYTES: usize = 512;
pub(crate) const MAX_ITEMS: usize = 4_096;
pub(crate) const MAX_WIRE_BYTES: usize = 16 * 1024 * 1024;

pub(crate) fn check_text(
    value: &str,
    field: &'static str,
    maximum: usize,
) -> Result<(), ImplementationBriefError> {
    if value.trim().is_empty() {
        return Err(ImplementationBriefError::Missing { field });
    }
    if value.len() > maximum {
        return Err(ImplementationBriefError::Bound {
            field,
            maximum,
            actual: value.len(),
        });
    }
    if value.chars().any(char::is_control) {
        return Err(ImplementationBriefError::Invalid {
            field,
            reason: "control characters are forbidden",
        });
    }
    Ok(())
}

pub(crate) fn check_id(
    value: &str,
    field: &'static str,
) -> Result<(), ImplementationBriefError> {
    check_text(value, field, MAX_ID_BYTES)
}

pub(crate) fn check_digest(
    value: &str,
    field: &'static str,
) -> Result<(), ImplementationBriefError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ImplementationBriefError::Invalid {
            field,
            reason: "expected lowercase SHA-256 hexadecimal",
        });
    }
    Ok(())
}

pub(crate) fn canonical_digest<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<String, ImplementationBriefError> {
    canonical_json_bytes(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| ImplementationBriefError::Encoding { field })
}

pub(crate) fn check_collection_len(
    actual: usize,
    maximum: usize,
    field: &'static str,
) -> Result<(), ImplementationBriefError> {
    if actual > maximum {
        return Err(ImplementationBriefError::Bound {
            field,
            maximum,
            actual,
        });
    }
    Ok(())
}

pub(crate) fn check_unique_texts(
    values: &[String],
    field: &'static str,
) -> Result<(), ImplementationBriefError> {
    check_collection_len(values.len(), MAX_ITEMS, field)?;
    let mut seen = BTreeSet::new();
    for value in values {
        check_id(value, field)?;
        if !seen.insert(value.as_str()) {
            return Err(ImplementationBriefError::Duplicate {
                field,
                value: value.clone(),
            });
        }
    }
    Ok(())
}

pub(crate) fn sorted_unique_strings(
    values: &[String],
    field: &'static str,
) -> Result<Vec<String>, ImplementationBriefError> {
    check_unique_texts(values, field)?;
    let mut result = values.to_vec();
    result.sort();
    Ok(result)
}

struct CountingWriter {
    written: usize,
    maximum: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self.written.saturating_add(bytes.len());
        if next > self.maximum {
            self.written = next;
            return Err(io::Error::other("canonical output bound"));
        }
        self.written = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) fn bounded_canonical_size<T: Serialize>(
    value: &T,
    maximum: usize,
    field: &'static str,
) -> Result<usize, ImplementationBriefError> {
    let mut writer = CountingWriter {
        written: 0,
        maximum,
    };
    to_writer(&mut writer, value).map_err(|_| ImplementationBriefError::Bound {
        field,
        maximum,
        actual: writer.written,
    })?;
    Ok(writer.written)
}
