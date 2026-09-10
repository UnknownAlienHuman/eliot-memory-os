//! Versioned, lossless bridge for grounding v2 and the A05 handoff.
//!
//! This module retains the complete A-14b grounding output and an optional
//! supplied rival declaration set. It performs bounded intrinsic validation
//! and exact owner joins only; A05 remains the semantic acceptance owner.

#![forbid(unsafe_code)]

mod binding;
mod encoding;

use crate::rival::RivalDeclarationSet;
use crate::validation::{DreamDraftValidationError, ValidationPolicy};
use crate::{BudgetUsage, PreservationReport, ValidatedDreamDraft};
use serde::{Deserialize, Serialize};

pub use binding::STRUCTURED_VALIDATOR_CONTRACT;

/// Wire version for the structured grounding validation bridge.
pub const STRUCTURED_VALIDATION_SCHEMA_VERSION: u32 = 1;

/// A bounded A05 input retaining the complete grounding v2 owner value.
///
/// The rival declaration attachment is supplied data. Its absence is
/// explicit and never filled from grounding prose, residues, or ledger
/// outcomes. The embedded grounding value owns the job, bundle, model,
/// manifest, and ledger identities, so this carrier has no duplicate copies.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroundingValidationInput {
    /// Exact bridge wire version.
    pub schema_version: u32,
    /// Complete A-14b grounding v2 output, including its input preimage.
    pub grounded: Box<crate::grounding::GroundedDreamDraft>,
    /// Independent A05 validation policy.
    pub policy: ValidationPolicy,
    /// Independent usage supplied to A05.
    pub usage: BudgetUsage,
    /// Seven-dimensional preservation report supplied to A05.
    pub preservation: PreservationReport,
    /// Explicit observation used for deadline checks.
    pub observation_time_ms: Option<u64>,
    /// Explicit cancellation observation.
    pub cancellation_requested: bool,
    /// Optional supplied rival declarations, retained before receipt binding.
    pub rival_declarations: Option<Box<RivalDeclarationSet>>,
}

impl GroundingValidationInput {
    /// Validates bounded shape, grounding owners, and optional rival joins.
    pub fn validate(&self) -> Result<(), DreamDraftValidationError> {
        binding::validate_input(self)
    }

    /// Computes the receipt-excluded structured input digest and byte size.
    pub fn input_digest_and_size(&self) -> Result<(String, usize), DreamDraftValidationError> {
        encoding::input_digest_and_size(self)
    }

    /// Computes a receipt-excluded output digest for an explicit A05
    /// terminal disposition, without constructing a provisional receipt.
    pub fn output_digest_and_size(
        &self,
        terminal_disposition: &str,
    ) -> Result<(String, usize), DreamDraftValidationError> {
        encoding::output_digest_and_size(self, terminal_disposition)
    }
}

/// A structured grounding value after the A05 receipt has been bound.
///
/// The receipt uses the existing `ValidationReceipt`/`ValidatedDreamDraft`
/// wire shapes with [`STRUCTURED_VALIDATOR_CONTRACT`]. This wrapper keeps the
/// full preimage available so its binding can be recomputed independently.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidatedGroundingCandidate {
    /// Complete structured input retained unchanged from the A05 call.
    pub input: GroundingValidationInput,
    /// Receipt-bound A05 result envelope.
    pub validated: ValidatedDreamDraft,
}

impl ValidatedGroundingCandidate {
    /// Recomputes intrinsic shape, owner joins, and structured receipt digests.
    ///
    /// This method does not issue a receipt, execute A05 policy, ground
    /// evidence, authorize a run, or promote a candidate to current truth.
    pub fn validate_binding(&self) -> Result<(), DreamDraftValidationError> {
        encoding::preflight_candidate(self)?;
        self.input.validate()?;
        binding::validate_receipt_binding(self)
    }

    /// Computes the receipt-excluded structured output digest.
    pub fn output_digest(&self) -> Result<String, DreamDraftValidationError> {
        encoding::output_digest(self)
    }
}

impl GroundingValidationInput {
    /// Creates a bounded input carrier after intrinsic validation.
    pub fn new(
        grounded: crate::grounding::GroundedDreamDraft,
        policy: ValidationPolicy,
        usage: BudgetUsage,
        preservation: PreservationReport,
        observation_time_ms: Option<u64>,
        cancellation_requested: bool,
        rival_declarations: Option<RivalDeclarationSet>,
    ) -> Result<Self, DreamDraftValidationError> {
        let input = Self {
            schema_version: STRUCTURED_VALIDATION_SCHEMA_VERSION,
            grounded: Box::new(grounded),
            policy,
            usage,
            preservation,
            observation_time_ms,
            cancellation_requested,
            rival_declarations: rival_declarations.map(Box::new),
        };
        input.validate()?;
        Ok(input)
    }
}

impl ValidatedGroundingCandidate {
    /// Creates a receipt-bound aggregate after validating the supplied receipt.
    pub fn new(
        input: GroundingValidationInput,
        validated: ValidatedDreamDraft,
    ) -> Result<Self, DreamDraftValidationError> {
        let candidate = Self { input, validated };
        candidate.validate_binding()?;
        Ok(candidate)
    }
}
