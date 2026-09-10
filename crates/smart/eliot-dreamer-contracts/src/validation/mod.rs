//! Shared validation contract pieces for Dreamer handoffs.
//!
//! A03 owns the complete retained aggregate and the receipt-excluded
//! preimages. The A05 crate owns the semantic gate and rejection outcomes.

#![forbid(unsafe_code)]

pub mod bounds;
pub mod encoding;
pub mod error;
pub mod policy;
pub mod structured;

use crate::{
    BudgetUsage, DreamInputBundle, DreamJobInput, GroundedDreamDraft, ModelDraft,
    PreservationReport, ValidatedDreamDraft,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use bounds::{MAX_CANONICAL_BYTES, MAX_RECORDS, preflight_inputs};
pub use encoding::{
    InputPreimage, OutputContext, PROOF_CEILING, VALIDATOR_CONTRACT, budget_digest, bundle_digest,
    input_digest_and_size, model_digest, output_digest, preservation_digest,
};
pub use error::DreamDraftValidationError;
pub use policy::ValidationPolicy;
pub use structured::{
    GroundingValidationInput, STRUCTURED_VALIDATION_SCHEMA_VERSION, STRUCTURED_VALIDATOR_CONTRACT,
    ValidatedGroundingCandidate,
};

/// Complete A03 aggregate retained after the A05 semantic gate.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidatedCandidate {
    /// Frozen job supplied to the gate.
    pub job: DreamJobInput,
    /// Exact input bundle, including materials and accounted omissions.
    pub bundle: DreamInputBundle,
    /// Original structured model value.
    pub model: ModelDraft,
    /// Original grounded value and every residue.
    pub grounded: GroundedDreamDraft,
    /// Exact seven-dimension preservation report.
    pub preservation: PreservationReport,
    /// Exact independent usage supplied to the validator.
    pub usage: BudgetUsage,
    /// Exact caller policy bound by the receipt input preimage.
    pub policy: ValidationPolicy,
    /// Explicit observation time used for deadline comparison.
    pub observation_time_ms: Option<u64>,
    /// Explicit cancellation input used by the gate.
    pub cancellation_requested: bool,
    /// A03 validated wrapper carrying the immutable validation receipt.
    pub validated: ValidatedDreamDraft,
}

impl ValidatedCandidate {
    /// Recomputes the complete intrinsic receipt binding from this aggregate.
    ///
    /// This checks supplied shape, bounds, identities and all receipt
    /// preimages. It does not ground evidence, admit a job, make a semantic
    /// decision, authorize a deadline, or promote authority.
    pub fn validate_binding(&self) -> Result<(), DreamDraftValidationError> {
        self.validate_shape()?;
        self.validate_identity()?;
        self.validate_digests()
    }

    fn validate_shape(&self) -> Result<(), DreamDraftValidationError> {
        // Bound all borrowed values before nested validators allocate or
        // canonicalize them.
        bounds::preflight_inputs(
            &self.job,
            &self.bundle,
            &self.model,
            &self.grounded,
            &self.preservation,
        )?;
        self.job
            .validate()
            .map_err(|error| error::summarize_contract("job", &error))?;
        self.bundle
            .validate()
            .map_err(|error| error::summarize_contract("bundle", &error))?;
        self.model
            .validate()
            .map_err(|error| error::summarize_contract("model draft", &error))?;
        self.grounded
            .validate()
            .map_err(|error| error::summarize_contract("grounded draft", &error))?;
        self.preservation
            .validate()
            .map_err(|error| error::summarize_contract("preservation report", &error))?;
        self.policy.validate()?;
        self.validated
            .validate()
            .map_err(|error| error::summarize_contract("validated draft", &error))?;
        Ok(())
    }

    fn validate_identity(&self) -> Result<(), DreamDraftValidationError> {
        let receipt = &self.validated.receipt;
        let job_id = self.job.canonical_id();
        if self.bundle.job_id != job_id
            || self.model.job_id != job_id
            || self.grounded.job_id != job_id
        {
            return Err(error::binding("job_id"));
        }
        if self.job.policy_ref != self.policy.policy_id {
            return Err(error::binding("policy_ref"));
        }
        if self.bundle.task_id != self.job.task_id
            || self.bundle.scope_id != self.job.scope_id
            || self.bundle.state_fence != self.job.state_fence
            || self.bundle.manifest_digest != self.job.frozen_manifest_digest
        {
            return Err(error::binding("bundle_lineage"));
        }
        if receipt.validator_contract != encoding::VALIDATOR_CONTRACT
            || receipt.proof_ceiling != encoding::PROOF_CEILING
        {
            return Err(error::binding("receipt_format"));
        }
        if !matches!(
            receipt.terminal_disposition.as_str(),
            "accepted" | "partial"
        ) {
            return Err(error::binding("terminal_disposition"));
        }
        if receipt.validator_policy != self.policy.policy_id
            || receipt.job_id != job_id
            || receipt.task_id != self.job.task_id
            || receipt.scope_id != self.job.scope_id
            || receipt.manifest_digest != self.bundle.manifest_digest
            || receipt.state_fence != self.job.state_fence
            || self.validated.state_fence != self.job.state_fence
            || self.validated.state_fence != receipt.state_fence
        {
            return Err(error::binding("receipt_identity"));
        }
        Ok(())
    }

    fn validate_digests(&self) -> Result<(), DreamDraftValidationError> {
        let receipt = &self.validated.receipt;
        let draft_digest = encoding::model_digest(&self.model)?;
        let bundle_digest = encoding::bundle_digest(&self.bundle)?;
        let preservation_digest = encoding::preservation_digest(&self.preservation)?;
        let budget_digest = encoding::budget_digest(&self.job, &self.usage)?;
        let input = encoding::InputPreimage {
            job: &self.job,
            bundle: &self.bundle,
            model: &self.model,
            grounded: &self.grounded,
            policy: &self.policy,
            usage: self.usage,
            preservation: &self.preservation,
            observation_time_ms: self.observation_time_ms,
            cancellation_requested: self.cancellation_requested,
        };
        let (input_digest, _) = encoding::input_digest_and_size(&input)?;
        let (output_digest, _) = encoding::output_digest(&encoding::OutputContext {
            job: &self.job,
            bundle: &self.bundle,
            model: &self.model,
            grounded: &self.grounded,
            preservation: &self.preservation,
            policy: &self.policy,
            usage: &self.usage,
            observation_time_ms: self.observation_time_ms,
            cancellation_requested: self.cancellation_requested,
            draft_digest: &draft_digest,
            bundle_digest: &bundle_digest,
            terminal_disposition: &receipt.terminal_disposition,
        })?;
        for (field, got, want) in [
            ("draft_digest", &receipt.draft_digest, &draft_digest),
            (
                "grounded.draft_digest",
                &self.grounded.draft_digest,
                &draft_digest,
            ),
            (
                "validated.draft_digest",
                &self.validated.draft_digest,
                &draft_digest,
            ),
            ("bundle_digest", &receipt.bundle_digest, &bundle_digest),
            (
                "preservation_digest",
                &receipt.preservation_digest,
                &preservation_digest,
            ),
            ("budget_digest", &receipt.budget_digest, &budget_digest),
            ("input_digest", &receipt.input_digest, &input_digest),
            ("output_digest", &receipt.output_digest, &output_digest),
        ] {
            if got != want {
                return Err(error::binding(field));
            }
        }
        Ok(())
    }
}
