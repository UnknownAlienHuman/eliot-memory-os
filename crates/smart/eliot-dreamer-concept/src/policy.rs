//! Explicit limits for the pure Concept handler.

use eliot_dreamer_contracts::{
    ConceptInput, ContractViolation, canonical_bytes, digest_hex, is_hex64_lower,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Write};

const VERSION: u32 = 1;
const MAX_TEXT: usize = 256;

/// Caller-supplied limits and semantic switches for one Concept proposal.
///
/// A policy constrains a candidate and has no authority of its own. Its digest
/// must equal the digest carried by [`ConceptInput`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConceptPolicy {
    pub schema_version: u32,
    pub policy_id: String,
    pub policy_revision: u64,
    pub digest: String,
    pub handler_id: String,
    pub max_input_bytes: u64,
    pub max_output_bytes: u64,
    pub max_sources: u32,
    pub max_evidence: u32,
    pub max_criteria: u32,
    pub max_cases: u32,
    pub max_rivals: u32,
    pub max_dependencies: u32,
    pub max_neighborhood: u32,
    pub max_work: u64,
    pub max_stu: u64,
    pub require_discriminator: bool,
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
    max_sources: u32,
    max_evidence: u32,
    max_criteria: u32,
    max_cases: u32,
    max_rivals: u32,
    max_dependencies: u32,
    max_neighborhood: u32,
    max_work: u64,
    max_stu: u64,
    require_discriminator: bool,
    cancellation_requested: bool,
}

impl ConceptPolicy {
    /// Creates a conservative policy with digest unset.
    #[must_use]
    pub fn new(policy_id: impl Into<String>) -> Self {
        Self {
            schema_version: VERSION,
            policy_id: policy_id.into(),
            policy_revision: 1,
            digest: String::new(),
            handler_id: super::HANDLER_ID.to_owned(),
            max_input_bytes: 1_048_576,
            max_output_bytes: 1_048_576,
            max_sources: 256,
            max_evidence: 256,
            max_criteria: 256,
            max_cases: 256,
            max_rivals: 256,
            max_dependencies: 256,
            max_neighborhood: 256,
            max_work: 1_048_576,
            max_stu: 4_096,
            require_discriminator: true,
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
            max_sources: self.max_sources,
            max_evidence: self.max_evidence,
            max_criteria: self.max_criteria,
            max_cases: self.max_cases,
            max_rivals: self.max_rivals,
            max_dependencies: self.max_dependencies,
            max_neighborhood: self.max_neighborhood,
            max_work: self.max_work,
            max_stu: self.max_stu,
            require_discriminator: self.require_discriminator,
            cancellation_requested: self.cancellation_requested,
        }
    }

    /// Computes the canonical policy digest, excluding the stored digest.
    pub fn computed_digest(&self) -> Result<String, ContractViolation> {
        self.validate_shape()?;
        Ok(digest_hex(&canonical_bytes(&self.preimage())?))
    }

    /// Seals this policy by deriving its digest.
    pub fn seal(&mut self) -> Result<(), ContractViolation> {
        self.validate_shape()?;
        self.digest = self.computed_digest()?;
        Ok(())
    }

    /// Validates shape and the digest binding.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.validate_shape()?;
        if !is_hex64_lower(&self.digest) || self.computed_digest()? != self.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.policy.digest",
                reason: "policy digest does not cover policy fields".to_owned(),
            });
        }
        Ok(())
    }

    /// Checks the policy/input identity and all independent cardinality/work bounds.
    pub fn check_input(&self, input: &ConceptInput) -> Result<(), ContractViolation> {
        self.validate()?;
        input.preflight()?;
        if input.policy_digest != self.digest {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.policy_digest",
                reason: "input policy digest differs from supplied policy".to_owned(),
            });
        }
        if !serialized_within(input, self.max_input_bytes)? {
            return Err(ContractViolation::Budget {
                dimension: "concept.input_bytes",
                reason: "input exceeds policy bound".to_owned(),
            });
        }
        check_count(
            input.sources.sources.len(),
            self.max_sources,
            "concept.sources",
        )?;
        check_count(
            input.proposal.evidence.len(),
            self.max_evidence,
            "concept.evidence",
        )?;
        check_count(
            input.proposal.criteria.len(),
            self.max_criteria,
            "concept.criteria",
        )?;
        check_count(input.proposal.cases.len(), self.max_cases, "concept.cases")?;
        check_count(
            input.proposal.rivals.len(),
            self.max_rivals,
            "concept.rivals",
        )?;
        check_count(
            input.proposal.dependencies.len(),
            self.max_dependencies,
            "concept.dependencies",
        )?;
        check_count(
            input.neighborhood.concepts.len(),
            self.max_neighborhood,
            "concept.neighborhood",
        )?;
        let work = work_bound(input)?;
        if work > self.max_work {
            return Err(ContractViolation::Budget {
                dimension: "concept.work",
                reason: format!("work {work} exceeds policy bound {}", self.max_work),
            });
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != VERSION {
            return Err(ContractViolation::OutOfBounds {
                field: "concept.policy.schema_version",
                min: i64::from(VERSION),
                max: i64::from(VERSION),
                got: i64::from(self.schema_version),
            });
        }
        for (value, field) in [
            (&self.policy_id, "concept.policy.id"),
            (&self.handler_id, "concept.policy.handler_id"),
        ] {
            eliot_dreamer_contracts::error::check_text(value, field, MAX_TEXT)?;
        }
        if self.handler_id != super::HANDLER_ID {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.policy.handler_id",
                reason: "policy identity differs from this Concept handler".to_owned(),
            });
        }
        if !self.require_discriminator {
            return Err(ContractViolation::BindingMismatch {
                field: "concept.policy.require_discriminator",
                reason: "Concept handlers always require a grounded discriminator".to_owned(),
            });
        }
        if self.policy_revision == 0
            || self.max_input_bytes == 0
            || self.max_output_bytes == 0
            || self.max_sources == 0
            || self.max_evidence == 0
            || self.max_criteria == 0
            || self.max_cases == 0
            || self.max_rivals == 0
            || self.max_dependencies == 0
            || self.max_neighborhood == 0
            || self.max_work == 0
            || self.max_stu == 0
        {
            return Err(ContractViolation::Budget {
                dimension: "concept.policy",
                reason: "all work and cardinality limits must be positive".to_owned(),
            });
        }
        if self.max_input_bytes > 1_048_576 || self.max_output_bytes > 1_048_576 {
            return Err(ContractViolation::Budget {
                dimension: "concept.policy.bytes",
                reason: "byte limits exceed class ceiling".to_owned(),
            });
        }
        Ok(())
    }
}

fn check_count(got: usize, limit: u32, field: &'static str) -> Result<(), ContractViolation> {
    let got = u64::try_from(got).map_err(|_| ContractViolation::Budget {
        dimension: field,
        reason: "count conversion overflow".to_owned(),
    })?;
    if got > u64::from(limit) {
        return Err(ContractViolation::Budget {
            dimension: field,
            reason: format!("count {got} exceeds policy bound {limit}"),
        });
    }
    Ok(())
}

/// Checked semantic reservation for all bounded scans performed by the handler.
pub(crate) fn work_bound(input: &ConceptInput) -> Result<u64, ContractViolation> {
    let counts = [
        input.sources.sources.len(),
        input.proposal.evidence.len(),
        input.proposal.criteria.len(),
        input.proposal.cases.len(),
        input.proposal.rivals.len(),
        input.proposal.dependencies.len(),
        input.neighborhood.concepts.len(),
    ];
    let candidate_rows = counts.into_iter().try_fold(2_u64, |sum, count| {
        sum.checked_add(u64::try_from(count).map_err(|_| ContractViolation::Budget {
            dimension: "concept.work",
            reason: "count conversion overflow".to_owned(),
        })?)
        .ok_or(ContractViolation::Budget {
            dimension: "concept.work",
            reason: "work count overflow".to_owned(),
        })
    })?;
    let snapshot_rows = u64::try_from(input.neighborhood.concepts.len())
        .map_err(|_| ContractViolation::Budget {
            dimension: "concept.work",
            reason: "snapshot row conversion overflow".to_owned(),
        })?
        .checked_add(1)
        .ok_or(ContractViolation::Budget {
            dimension: "concept.work",
            reason: "snapshot row count overflow".to_owned(),
        })?;
    let row_visits =
        candidate_rows
            .checked_mul(snapshot_rows)
            .ok_or(ContractViolation::Budget {
                dimension: "concept.work",
                reason: "work row multiplication overflow".to_owned(),
            })?;
    let proposal_bytes = serialized_len(&input.proposal)?;
    let neighborhood_bytes = serialized_len(&input.neighborhood)?;
    let byte_scans = proposal_bytes
        .checked_mul(candidate_rows)
        .and_then(|value| value.checked_add(neighborhood_bytes.checked_mul(snapshot_rows)?))
        .ok_or(ContractViolation::Budget {
            dimension: "concept.work",
            reason: "work byte multiplication overflow".to_owned(),
        })?;
    row_visits
        .checked_add(byte_scans)
        .ok_or(ContractViolation::Budget {
            dimension: "concept.work",
            reason: "work byte sum overflow".to_owned(),
        })
}

fn serialized_len<T: Serialize>(value: &T) -> Result<u64, ContractViolation> {
    let mut writer = CappedWriter {
        used: 0,
        limit: usize::MAX,
        exceeded: false,
    };
    serde_json::to_writer(&mut writer, value).map_err(|error| ContractViolation::Malformed {
        field: "concept.policy.serialization",
        reason: error.to_string(),
    })?;
    u64::try_from(writer.used).map_err(|_| ContractViolation::Budget {
        dimension: "concept.work",
        reason: "serialized work length conversion overflow".to_owned(),
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
            field: "concept.policy.serialization",
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
