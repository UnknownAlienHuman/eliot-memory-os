//! Bounded sizing for retained v2 A-05 outcomes.

use crate::error::DreamDraftValidationError;
use eliot_dreamer_contracts::ValidatedDreamDraft;
use eliot_dreamer_contracts::validation::MAX_CANONICAL_BYTES;
use eliot_dreamer_contracts::validation::structured::GroundingValidationInput;
use serde::Serialize;
use std::io::{self, Write};

pub(crate) fn stream_size<T: Serialize>(
    value: &T,
    field: &'static str,
    ceiling: usize,
) -> Result<usize, DreamDraftValidationError> {
    let mut writer = CountingWriter {
        count: 0,
        ceiling,
        exceeded: false,
    };
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.exceeded {
            return Err(DreamDraftValidationError::Bound {
                field,
                maximum: ceiling,
                actual: writer.count,
            });
        }
        return Err(DreamDraftValidationError::Encoding {
            field,
            detail: error.to_string(),
        });
    }
    Ok(writer.count)
}

pub(crate) fn policy_cap(input: &GroundingValidationInput) -> usize {
    usize::try_from(input.policy.max_canonical_bytes).unwrap_or(usize::MAX)
}

#[derive(Serialize)]
struct BorrowedCandidate<'a> {
    input: &'a GroundingValidationInput,
    validated: &'a ValidatedDreamDraft,
}

#[derive(Serialize)]
struct BorrowedRejection<'a> {
    input: &'a GroundingValidationInput,
    code: crate::RejectionCode,
    detail: &'a str,
    input_digest: &'a str,
}

#[derive(Serialize)]
enum BorrowedOutcome<'a> {
    Accepted(BorrowedCandidate<'a>),
    Rejected(BorrowedRejection<'a>),
}

pub(crate) fn stream_accepted_size(
    input: &GroundingValidationInput,
    validated: &ValidatedDreamDraft,
) -> Result<usize, DreamDraftValidationError> {
    let outcome = BorrowedOutcome::Accepted(BorrowedCandidate { input, validated });
    stream_size(&outcome, "structured.accepted", MAX_CANONICAL_BYTES)
}

pub(crate) fn stream_rejected_size(
    input: &GroundingValidationInput,
    code: crate::RejectionCode,
    detail: &str,
    input_digest: &str,
) -> Result<usize, DreamDraftValidationError> {
    let outcome = BorrowedOutcome::Rejected(BorrowedRejection {
        input,
        code,
        detail,
        input_digest,
    });
    stream_size(&outcome, "structured.rejection", MAX_CANONICAL_BYTES)
}

struct CountingWriter {
    count: usize,
    ceiling: usize,
    exceeded: bool,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.count = self
            .count
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("structured result byte counter overflow"))?;
        if self.count > self.ceiling {
            self.exceeded = true;
            return Err(io::Error::other("structured result exceeds byte ceiling"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
