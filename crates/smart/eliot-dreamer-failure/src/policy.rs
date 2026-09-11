//! Explicit, caller supplied limits for the Failure handler.

use eliot_dreamer_contracts::{
    ContractViolation, FailureInput, canonical_bytes, check_vec_bound, digest_hex, is_hex64_lower,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

const VERSION: u32 = 1;
const MAX_BYTES: u64 = 4 * 1024 * 1024;

/// Policy constrains local work; it never grants block, suppression, or write authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FailurePolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_revision: u64,
    pub digest: String,
    pub handler_id: String,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_history: u32,
    pub max_controls: u32,
    pub max_evidence: u32,
    pub max_work: u64,
    pub cancellation_requested: bool,
}

#[derive(Serialize)]
struct PolicyPreimage<'a> {
    schema_version: u32,
    policy_id: &'a str,
    policy_revision: u64,
    handler_id: &'a str,
    max_input_bytes: u64,
    max_output_bytes: u64,
    max_history: u32,
    max_controls: u32,
    max_evidence: u32,
    max_work: u64,
    cancellation_requested: bool,
}

impl Default for FailurePolicy {
    fn default() -> Self {
        Self::new("failure-default")
    }
}

impl FailurePolicy {
    /// Creates a conservative policy with an unsealed digest.
    #[must_use]
    pub fn new(policy_id: impl Into<String>) -> Self {
        Self {
            schema_version: VERSION,
            policy_id: policy_id.into(),
            policy_revision: 1,
            digest: String::new(),
            handler_id: super::HANDLER_ID.to_owned(),
            max_input_bytes: MAX_BYTES,
            max_output_bytes: MAX_BYTES,
            max_history: 1024,
            max_controls: 1024,
            max_evidence: 1024,
            max_work: 4 * 1024 * 1024,
            cancellation_requested: false,
        }
    }

    fn preimage(&self) -> PolicyPreimage<'_> {
        PolicyPreimage {
            schema_version: self.schema_version,
            policy_id: &self.policy_id,
            policy_revision: self.policy_revision,
            handler_id: &self.handler_id,
            max_input_bytes: self.max_input_bytes,
            max_output_bytes: self.max_output_bytes,
            max_history: self.max_history,
            max_controls: self.max_controls,
            max_evidence: self.max_evidence,
            max_work: self.max_work,
            cancellation_requested: self.cancellation_requested,
        }
    }

    /// Computes the digest over all policy fields except the stored digest.
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        self.validate_shape()?;
        Ok(digest_hex(&canonical_bytes(&self.preimage())?))
    }

    /// Seals the policy digest in place.
    pub fn seal(&mut self) -> Result<(), ContractViolation> {
        self.validate_shape()?;
        self.digest = self.computed_digest()?;
        Ok(())
    }

    /// Validates policy shape and its self digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_shape()?;
        if !is_hex64_lower(&self.digest) || self.computed_digest()? != self.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.policy.digest",
                reason: "policy digest does not cover policy fields".to_owned(),
            });
        }
        Ok(())
    }

    /// Checks policy identity and finite work bounds against an A03 closure.
    pub fn check_input(&self, input: &FailureInput) -> Result<(), ContractViolation> {
        self.validate()?;
        input.preflight()?;
        input.usage.fits(&input.job.budget)?;
        if input.job.deadline_ms.is_some() {
            return Err(ContractViolation::Budget {
                dimension: "deadline_ms",
                reason: "caller supplied no clock reading for deadline assessment".to_owned(),
            });
        }
        if input.policy_digest != self.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.policy_digest",
                reason: "input policy digest differs from supplied policy".to_owned(),
            });
        }
        if !serialized_within(input, self.max_input_bytes)? {
            return Err(ContractViolation::Budget {
                dimension: "failure.input_bytes",
                reason: "input exceeds policy bound".to_owned(),
            });
        }
        check_vec_bound(
            input.history.entries.len(),
            self.max_history as usize,
            "failure.history",
        )?;
        check_vec_bound(
            input.proposal.controls.len(),
            self.max_controls as usize,
            "failure.controls",
        )?;
        let evidence_count = input
            .action_evidence
            .evidence
            .len()
            .checked_add(input.history.historical_evidence.len())
            .ok_or(ContractViolation::Budget {
                dimension: "failure.evidence",
                reason: "combined evidence count overflow".to_owned(),
            })?;
        check_vec_bound(
            evidence_count,
            self.max_evidence as usize,
            "failure.evidence",
        )?;
        if work_bound(input)? > self.max_work {
            return Err(ContractViolation::Budget {
                dimension: "failure.work",
                reason: "semantic work exceeds policy bound".to_owned(),
            });
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "failure.policy.schema_version",
                min: i64::from(VERSION),
                max: i64::from(VERSION),
                got: i64::from(self.schema_version),
            });
        }
        eliot_dreamer_contracts::error::check_text(&self.policy_id, "failure.policy.id", 256)?;
        eliot_dreamer_contracts::error::check_text(
            &self.handler_id,
            "failure.policy.handler_id",
            256,
        )?;
        if self.handler_id != super::HANDLER_ID {
            return Err(ContractViolation::BindingMismatch {
                field: "failure.policy.handler_id",
                reason: "policy belongs to another handler".to_owned(),
            });
        }
        if self.policy_revision == 0
            || self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_history == 0
            || self.max_controls == 0
            || self.max_evidence == 0
            || self.max_work == 0
        {
            return Err(ContractViolation::Budget {
                dimension: "failure.policy",
                reason: "all limits must be positive".to_owned(),
            });
        }
        if self.max_input_bytes > MAX_BYTES || self.max_output_bytes > MAX_BYTES {
            return Err(ContractViolation::Budget {
                dimension: "failure.policy.bytes",
                reason: "byte limits exceed class ceiling".to_owned(),
            });
        }
        Ok(())
    }
}

/// Checked reservation for every bounded comparison performed by assessment.
/// This is a conservative quadratic reservation for the global retained /
/// omitted membership and deduplication scans. It is a work bound, not a
/// claim about elapsed CPU time or provider work.
pub(crate) fn work_bound(input: &FailureInput) -> Result<u64, ContractViolation> {
    let counts = [
        input.action_evidence.evidence.len(),
        input.action_evidence.receipts.len(),
        input.action_evidence.receipt_materials.len(),
        input.action_evidence.evidence_envelopes.len(),
        input.action_evidence.omitted_envelope_refs.len(),
        input.history.entries.len(),
        input.history.receipts.len(),
        input.history.receipt_materials.len(),
        input.history.historical_evidence.len(),
        input.history.historical_evidence_envelopes.len(),
        input.history.omitted_evidence_envelope_refs.len(),
        input.proposal.trigger.len(),
        input.proposal.comparison.dimensions.len(),
        input.proposal.controls.len(),
    ];
    let n = counts.into_iter().try_fold(1_u64, |total, count| {
        total
            .checked_add(u64::try_from(count).map_err(|_| ContractViolation::Budget {
                dimension: "failure.work",
                reason: "count conversion overflow".to_owned(),
            })?)
            .ok_or(ContractViolation::Budget {
                dimension: "failure.work",
                reason: "work count overflow".to_owned(),
            })
    })?;
    n.checked_mul(n).ok_or(ContractViolation::Budget {
        dimension: "failure.work",
        reason: "quadratic work reservation overflow".to_owned(),
    })
}

fn serialized_within<T: Serialize>(value: &T, limit: u64) -> Result<bool, ContractViolation> {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut writer = CappedWriter {
        used: 0,
        limit,
        exceeded: false,
    };
    match serde_json::to_writer(&mut writer, value) {
        Ok(()) => Ok(true),
        Err(_) if writer.exceeded => Ok(false),
        Err(error) => Err(ContractViolation::Malformed {
            field: "failure.policy.serialization",
            reason: error.to_string(),
        }),
    }
}

struct CappedWriter {
    used: usize,
    limit: usize,
    exceeded: bool,
}
impl Write for CappedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let Some(next) = self.used.checked_add(bytes.len()) else {
            self.exceeded = true;
            return Err(io::Error::other("serialization length overflow"));
        };
        if next > self.limit {
            self.exceeded = true;
            return Err(io::Error::other("serialization bound exceeded"));
        }
        self.used = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
