//! Bounded receipt-excluded preimages for structured grounding validation.

use super::{GroundingValidationInput, ValidatedGroundingCandidate};
use crate::validation::{DreamDraftValidationError, MAX_CANONICAL_BYTES, PROOF_CEILING};
use serde::Serialize;
use std::io::{self, Write};

#[derive(Serialize)]
struct InputPreimage<'a> {
    schema_version: u32,
    validator_contract: &'static str,
    grounded: &'a crate::grounding::GroundedDreamDraft,
    policy: &'a crate::validation::ValidationPolicy,
    usage: crate::BudgetUsage,
    preservation: &'a crate::PreservationReport,
    observation_time_ms: Option<u64>,
    cancellation_requested: bool,
    rival_declarations: &'a Option<Box<crate::rival::RivalDeclarationSet>>,
}

#[derive(Serialize)]
struct OutputPreimage<'a> {
    schema_version: u32,
    input: InputPreimage<'a>,
    validator_contract: &'static str,
    validator_policy: &'a str,
    terminal_disposition: &'a str,
    proof_ceiling: &'a str,
    job_id: &'a str,
    draft_digest: &'a str,
    bundle_digest: &'a str,
    manifest_digest: &'a str,
    task_id: &'a str,
    scope_id: &'a str,
}

pub(super) fn input_digest_and_size(
    input: &GroundingValidationInput,
) -> Result<(String, usize), DreamDraftValidationError> {
    preflight_input(input)?;
    let preimage = input_preimage(input);
    digest(&preimage, "structured.validation.input")
}

pub(super) fn output_digest(
    candidate: &ValidatedGroundingCandidate,
) -> Result<String, DreamDraftValidationError> {
    output_digest_and_size(
        &candidate.input,
        &candidate.validated.receipt.terminal_disposition,
    )
    .map(|(value, _)| value)
}

pub(super) fn output_digest_and_size(
    input: &GroundingValidationInput,
    terminal_disposition: &str,
) -> Result<(String, usize), DreamDraftValidationError> {
    preflight_output_input(input, terminal_disposition)?;
    let preimage = output_preimage(input, terminal_disposition)?;
    digest(&preimage, "structured.validation.output")
}

pub(super) fn preflight_candidate(
    candidate: &ValidatedGroundingCandidate,
) -> Result<usize, DreamDraftValidationError> {
    let size = preflight(candidate, "structured.validation.aggregate")?;
    if size > MAX_CANONICAL_BYTES {
        return Err(DreamDraftValidationError::Bound {
            field: "structured.validation.aggregate",
            maximum: MAX_CANONICAL_BYTES,
            actual: size,
        });
    }
    Ok(size)
}

fn input_preimage(input: &GroundingValidationInput) -> InputPreimage<'_> {
    InputPreimage {
        schema_version: input.schema_version,
        validator_contract: super::STRUCTURED_VALIDATOR_CONTRACT,
        grounded: &input.grounded,
        policy: &input.policy,
        usage: input.usage,
        preservation: &input.preservation,
        observation_time_ms: input.observation_time_ms,
        cancellation_requested: input.cancellation_requested,
        rival_declarations: &input.rival_declarations,
    }
}

fn digest<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<(String, usize), DreamDraftValidationError> {
    let size = preflight(value, field)?;
    let bytes =
        crate::canonical_bytes(value).map_err(|error| DreamDraftValidationError::Encoding {
            field,
            detail: error.to_string(),
        })?;
    debug_assert_eq!(size, bytes.len());
    Ok((crate::digest_hex(&bytes), size))
}

pub(super) fn preflight<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<usize, DreamDraftValidationError> {
    let mut writer = CountingWriter::new(MAX_CANONICAL_BYTES);
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        DreamDraftValidationError::Encoding {
            field,
            detail: error.to_string(),
        }
    })?;
    Ok(writer.count)
}

fn input_limit(input: &GroundingValidationInput) -> usize {
    usize::try_from(input.policy.max_canonical_bytes).unwrap_or(usize::MAX)
}

pub(super) fn preflight_input(
    input: &GroundingValidationInput,
) -> Result<usize, DreamDraftValidationError> {
    let preimage = input_preimage(input);
    let size = preflight(&preimage, "structured.validation.input")?;
    if size > input_limit(input) {
        return Err(DreamDraftValidationError::Bound {
            field: "structured.validation.input",
            maximum: input_limit(input),
            actual: size,
        });
    }
    Ok(size)
}

pub(super) fn preflight_output(
    candidate: &ValidatedGroundingCandidate,
) -> Result<usize, DreamDraftValidationError> {
    preflight_output_input(
        &candidate.input,
        &candidate.validated.receipt.terminal_disposition,
    )
}

fn preflight_output_input(
    input: &GroundingValidationInput,
    terminal_disposition: &str,
) -> Result<usize, DreamDraftValidationError> {
    let preimage = output_preimage(input, terminal_disposition)?;
    let size = preflight(&preimage, "structured.validation.output")?;
    if size > input_limit(input) {
        return Err(DreamDraftValidationError::Bound {
            field: "structured.validation.output",
            maximum: input_limit(input),
            actual: size,
        });
    }
    Ok(size)
}

fn output_preimage<'a>(
    input: &'a GroundingValidationInput,
    terminal_disposition: &'a str,
) -> Result<OutputPreimage<'a>, DreamDraftValidationError> {
    if !matches!(terminal_disposition, "accepted" | "rejected" | "partial") {
        return Err(DreamDraftValidationError::InvalidContract {
            phase: "structured validation output",
            field: "terminal_disposition",
        });
    }
    let model = &input.grounded.input;
    Ok(OutputPreimage {
        schema_version: input.schema_version,
        input: input_preimage(input),
        validator_contract: super::STRUCTURED_VALIDATOR_CONTRACT,
        validator_policy: &input.policy.policy_id,
        terminal_disposition,
        proof_ceiling: PROOF_CEILING,
        job_id: &model.job_id,
        draft_digest: &model.draft_digest,
        bundle_digest: &model.bundle_digest,
        manifest_digest: &model.bundle.manifest_digest,
        task_id: input.grounded.task_id.as_str(),
        scope_id: &input.grounded.scope_id,
    })
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
            .ok_or_else(|| io::Error::other("structured preimage byte counter overflow"))?;
        if self.count > self.ceiling {
            return Err(io::Error::other("structured preimage exceeds byte ceiling"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
