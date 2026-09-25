//! Bounded projection batches with shared-fence gating and coverage.
//!
//! A [`MemoryProjectionBatch`] carries one [`MemoryScopeBinding`]: every
//! record must name exactly the batch task, scope, and session, and every
//! record fence must be compatible with the batch fence. The batch also
//! carries the denominator context every consumer needs: how many canonical
//! records the read side observed, what was truncated or omitted, and whether
//! revalidation is required before use.
//!
//! Coverage is accounted exactly, not conservatively. Under a known
//! denominator every observed record lands in exactly one of three places —
//! a projected record, a named omission, or a deferred resume-frontier handle
//! — the three lists are pairwise disjoint, and their combined length equals
//! the denominator. Completeness is therefore a property the batch proves
//! about itself, not a claim a consumer has to take on trust; a remainder that
//! nobody can name is refused at the boundary instead of surfacing later as a
//! quietly short read.

use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::contracts::error::MemoryProjectionError;
use crate::contracts::record::MemoryProjectionRecord;
use crate::contracts::record::MemoryScopeBinding;

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
        /// Total observed records: projected, omitted, or deferred to the
        /// resume frontier, counted once each.
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
    ///
    /// Each deferred record contributes one handle, so a truncated batch keeps
    /// the exact remainder it did not return and the place to resume from.
    pub frontier: Vec<String>,
    /// Named omissions with exact reasons.
    ///
    /// Handles are distinct from every projected record and from every other
    /// omission, so one observed record can never be both returned and lost.
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
    /// Validate the batch: shapes, shared-fence gating, scope equality, handle
    /// uniqueness across records, omissions and frontier, and exact disjoint
    /// coverage accounting against a known denominator.
    ///
    /// A `Known` denominator is an equality, not a lower bound: the projected
    /// records, the named omissions and the deferred resume frontier together
    /// account for exactly `total` distinct handles. `Unknown` stays
    /// representable — it claims no count, so nothing here can contradict it,
    /// and the consumers that need a count fail closed on it instead.
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
        // Exact, disjoint member accounting. Every canonical record the read
        // side observed is projected, omitted, or deferred to the resume
        // frontier, and it is exactly one of those three. The same handle may
        // not appear in two of them, and a known denominator must equal the
        // volume those three lists carry — no more, and no less. A total larger
        // than the accounted volume with nothing deferred and nothing omitted
        // is unclaimed completeness, not evidence of it, so it is refused here
        // rather than discovered later by whichever consumer happens to look.
        //
        // This is deliberately stricter than the r6 freeze note at
        // `cognitive-rev12-contract-schema-freeze.toml` ("Known{total} must
        // cover projected plus omitted volume"), which states a lower bound
        // and never mentions the frontier. That note under-specifies the rule;
        // it does not grant the remainder. The freeze is a published wave
        // revision under a recorded digest, so reconciling the wording is the
        // owner's revision decision and is escalated, not edited here.
        for omission in &self.coverage.omissions {
            if !seen.insert(omission.handle.as_str().to_owned()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "coverage.omissions",
                    value: omission.handle.as_str().to_owned(),
                });
            }
        }
        for handle in &self.coverage.frontier {
            if !seen.insert(handle.clone()) {
                return Err(MemoryProjectionError::Duplicate {
                    field: "coverage.frontier",
                    value: handle.clone(),
                });
            }
        }
        if let DenominatorState::Known { total } = &self.coverage.denominator {
            let accounted =
                self.records.len() + self.coverage.omissions.len() + self.coverage.frontier.len();
            if accounted != *total {
                return Err(MemoryProjectionError::CoverageMismatch {
                    reason: "known denominator must equal projected plus omitted plus deferred volume",
                });
            }
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
