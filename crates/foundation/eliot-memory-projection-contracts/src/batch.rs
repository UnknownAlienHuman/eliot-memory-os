//! Bounded projection batches with shared-fence gating and coverage.
//!
//! A [`MemoryProjectionBatch`] carries one [`MemoryScopeBinding`]: every
//! record must name exactly the batch task, scope, and session, and every
//! record fence must be compatible with the batch fence. The batch also
//! carries the denominator context every consumer needs: how many canonical
//! records the read side observed, what was truncated or omitted, and whether
//! revalidation is required before use.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::MemoryProjectionError;
use crate::record::MemoryProjectionRecord;
use crate::record::MemoryScopeBinding;

/// Hard ceiling on records carried by one projection batch.
///
/// The provider truncates volume beyond this ceiling with an explicit
/// truncated flag and resume frontier, never silently.
pub const MEMORY_PROJECTION_MAX_RECORDS: usize = 256;
/// Hard ceiling on omission entries carried by one batch.
pub const MAX_BATCH_OMISSIONS: usize = 256;
/// Hard ceiling on frontier resume handles carried by one batch.
pub const MAX_BATCH_FRONTIER: usize = 256;

fn text(value: &str, field: &'static str) -> Result<(), MemoryProjectionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MemoryProjectionError::InvalidField {
            field,
            reason: "must be non-blank and free of control characters",
        });
    }
    Ok(())
}

/// Denominator context of a projection batch.
///
/// `Known` is the normal case: the read side counted its observed records.
/// `Unknown` preserves an explicit unknown (A0.4): the batch stays
/// representable, but evaluation fails closed because applicability without a
/// denominator is unprovable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", deny_unknown_fields)]
pub enum DenominatorState {
    /// Exact canonical records observed by the read side.
    #[serde(rename = "KNOWN")]
    Known {
        /// Total observed records, projected or omitted.
        total: usize,
    },
    /// The read side could not establish the denominator, with a reason.
    #[serde(rename = "UNKNOWN")]
    Unknown {
        /// Stable bounded reason class.
        reason: String,
    },
}

impl DenominatorState {
    /// Validate the denominator shape.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        match self {
            Self::Known { .. } => Ok(()),
            Self::Unknown { reason } => text(reason, "coverage.denominator.reason"),
        }
    }
}

/// One explicitly omitted record: handle plus the rule that omitted it.
///
/// Omissions are never silent loss: fence-incompatible, scope-mismatched, or
/// bound-truncated volume is named here with its exact reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageOmission {
    /// Handle of the omitted record.
    pub handle: eliot_contracts::ArtifactId,
    /// Stable bounded reason class for the omission.
    pub reason: String,
}

impl CoverageOmission {
    /// Validate the omission shape.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        text(&self.reason, "coverage.omissions.reason")
    }
}

/// Coverage accounting of one projection batch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProjectionCoverage {
    /// Denominator context of the read side.
    pub denominator: DenominatorState,
    /// Whether volume truncation cut the projected records.
    pub truncated: bool,
    /// Resume handles for truncated volume; nonempty exactly when truncated.
    pub frontier: Vec<String>,
    /// Named omissions with exact reasons.
    pub omissions: Vec<CoverageOmission>,
    /// Whether the consumer must revalidate before use.
    pub revalidation_required: bool,
}

impl ProjectionCoverage {
    /// Validate coverage shape (member accounting is checked by the batch,
    /// which sees the carried records).
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        self.denominator.validate()?;
        if self.frontier.len() > MAX_BATCH_FRONTIER {
            return Err(MemoryProjectionError::Bounds {
                field: "coverage.frontier",
            });
        }
        for handle in &self.frontier {
            text(handle, "coverage.frontier")?;
        }
        if self.omissions.len() > MAX_BATCH_OMISSIONS {
            return Err(MemoryProjectionError::Bounds {
                field: "coverage.omissions",
            });
        }
        for omission in &self.omissions {
            omission.validate()?;
        }
        Ok(())
    }
}

/// One bounded canonical memory projection read set.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemoryProjectionBatch {
    /// Contract version this batch was written against.
    pub contract_version: eliot_contracts::ContractVersion,
    /// Shared task/scope/session/fence binding every record must satisfy.
    pub binding: MemoryScopeBinding,
    /// Bounded projected records in deterministic provider order.
    pub records: Vec<MemoryProjectionRecord>,
    /// Denominator, truncation, omission, and revalidation context.
    pub coverage: ProjectionCoverage,
}

impl MemoryProjectionBatch {
    /// Validate the batch: shapes, shared-fence gating, scope equality,
    /// handle uniqueness, and coverage accounting.
    pub fn validate(&self) -> Result<(), MemoryProjectionError> {
        if self.contract_version != crate::CONTRACT_VERSION {
            return Err(MemoryProjectionError::VersionMismatch);
        }
        self.binding.validate()?;
        self.coverage.validate()?;
        if self.records.len() > MEMORY_PROJECTION_MAX_RECORDS {
            return Err(MemoryProjectionError::Bounds {
                field: "batch.records",
            });
        }
        let mut seen = BTreeSet::new();
        for record in &self.records {
            record.validate()?;
            if !seen.insert(record.handle.as_str().to_owned()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "batch.records",
                    value: record.handle.as_str().to_owned(),
                });
            }
            if record.binding.task_id != self.binding.task_id
                || record.binding.scope_id != self.binding.scope_id
                || record.binding.session_id != self.binding.session_id
            {
                return Err(MemoryProjectionError::ScopeMismatch {
                    reason: "record binding must equal the batch binding",
                });
            }
            if !record
                .state_fence
                .is_compatible_with(&self.binding.state_fence)
            {
                return Err(MemoryProjectionError::FenceMismatch {
                    left: "record.state_fence",
                    right: "batch.binding.state_fence",
                });
            }
        }
        // Every observed record is either projected or omitted: a known
        // denominator below the accounted volume contradicts the read side.
        if let DenominatorState::Known { total } = &self.coverage.denominator
            && *total < self.records.len() + self.coverage.omissions.len()
        {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "denominator is below projected plus omitted volume",
            });
        }
        // Volume truncation must name where to resume; a frontier without
        // truncation is unclaimed volume and is rejected.
        if self.coverage.truncated && self.coverage.frontier.is_empty() {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "truncated coverage must carry a resume frontier",
            });
        }
        if !self.coverage.truncated && !self.coverage.frontier.is_empty() {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "non-truncated coverage must not carry a frontier",
            });
        }
        // Truncation or omission always requires revalidation before use.
        let must_revalidate = self.coverage.truncated || !self.coverage.omissions.is_empty();
        if must_revalidate && !self.coverage.revalidation_required {
            return Err(MemoryProjectionError::CoverageMismatch {
                reason: "truncated or lossy coverage requires revalidation",
            });
        }
        Ok(())
    }
}
