//! Per-proposition support: results, validity bounds, and weakest-link.
//!
//! A [`SupportRecord`] states what one inquiry route observed for one
//! proposition inside explicit scope, time, version, and precision bounds,
//! with every evidence handle preserved. Handles are a set: order carries no
//! meaning. An unsupported-but-valid record is data, not an error —
//! `data insufficient` remains a valid outcome and reopen stays possible via
//! [`SupportRecord::reopen_reason`].
//!
//! Aggregation across routes uses [`weakest_link`]: the least supportive
//! result bounds the whole, so one strong route never silences a rival.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_contracts::{StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, validate_bounded_text, validate_digest,
};
use crate::identity::PropositionId;

/// What one inquiry route observed for one proposition.
///
/// `Supported` and `Partial` are the only results that license downstream
/// reliance; every other result preserves the unknown instead of smoothing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportResult {
    /// The proposition holds within the declared validity bounds.
    Supported,
    /// The proposition holds in part; the remainder stays unknown.
    Partial,
    /// Preserved counterevidence contradicts the proposition.
    Contradicted,
    /// Validly evaluated and not supported; data, not an error.
    Unsupported,
    /// The available material cannot establish a position.
    Unknown,
    /// The proposition is outside the admitted manifest.
    OutsideManifest,
    /// Once useful support whose freshness boundary has passed.
    Stale,
    /// Replaced by a later governed record, retained as history.
    Superseded,
    /// Support does not apply here for a recorded, bounded reason.
    JustifiedNotApplicable,
}

impl SupportResult {
    /// Returns the exact frozen wire name of this result.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Supported => "SUPPORTED",
            Self::Partial => "PARTIAL",
            Self::Contradicted => "CONTRADICTED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Unknown => "UNKNOWN",
            Self::OutsideManifest => "OUTSIDE_MANIFEST",
            Self::Stale => "STALE",
            Self::Superseded => "SUPERSEDED",
            Self::JustifiedNotApplicable => "JUSTIFIED_NOT_APPLICABLE",
        }
    }

    /// Weakest-link rank: lower bounds any aggregate it participates in.
    const fn link_rank(self) -> u8 {
        match self {
            Self::Contradicted => 0,
            Self::Unsupported => 1,
            Self::Stale | Self::Superseded => 2,
            Self::OutsideManifest | Self::Unknown => 3,
            Self::JustifiedNotApplicable => 4,
            Self::Partial => 5,
            Self::Supported => 6,
        }
    }
}

/// Returns the weakest of the supplied results.
///
/// The least supportive result bounds the whole: a `CONTRADICTED` route is
/// never outvoted by additional `SUPPORTED` routes. An empty input is an
/// error, never a silent success.
pub fn weakest_link(results: &[SupportResult]) -> Result<SupportResult, ContractError> {
    let mut iter = results.iter();
    let first = iter.next().ok_or(ContractError::EmptyCollection {
        field: "support.results",
    })?;
    let mut weakest = *first;
    for candidate in iter {
        if candidate.link_rank() < weakest.link_rank() {
            weakest = *candidate;
        }
    }
    Ok(weakest)
}

/// Scope, time, version, and precision bounds of one support observation.
///
/// A mismatch between these bounds and the question asked limits support
/// instead of failing: the record stays valid data about a narrower question.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ValidityBounds {
    /// Work-scope identity the observation applies to.
    pub scope: String,
    /// Start of the validity window in Unix milliseconds, when bounded.
    pub window_start_ms: Option<i64>,
    /// End of the validity window in Unix milliseconds, when bounded.
    pub window_end_ms: Option<i64>,
    /// Source or protocol version the observation applies to.
    pub version: String,
    /// Highest precision the observation supports, e.g. `file` or `symbol`.
    pub precision: String,
}

impl ValidityBounds {
    /// Constructs validity bounds, rejecting inverted windows.
    pub fn new(
        scope: impl Into<String>,
        window_start_ms: Option<i64>,
        window_end_ms: Option<i64>,
        version: impl Into<String>,
        precision: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let bounds = Self {
            scope: scope.into(),
            window_start_ms,
            window_end_ms,
            version: version.into(),
            precision: precision.into(),
        };
        bounds.validate()?;
        Ok(bounds)
    }

    /// Validates scope, version, precision, and window order.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.scope, "support.scope", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.version, "support.version", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.precision, "support.precision", MAX_SHORT_TEXT)?;
        if let (Some(start), Some(end)) = (self.window_start_ms, self.window_end_ms)
            && end < start
        {
            return Err(ContractError::InvertedInterval {
                field: "support.window",
            });
        }
        Ok(())
    }

    /// Returns whether these bounds cover the requested scope and instant.
    pub fn covers(&self, scope: &str, instant_ms: Option<i64>) -> bool {
        if self.scope != scope {
            return false;
        }
        match (self.window_start_ms, self.window_end_ms, instant_ms) {
            (Some(start), _, Some(instant)) if instant < start => false,
            (_, Some(end), Some(instant)) if instant > end => false,
            _ => true,
        }
    }
}

/// One route's support observation for one proposition, handles preserved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SupportRecord {
    /// Proposition this observation bears on.
    pub proposition: PropositionId,
    /// What the route observed.
    pub result: SupportResult,
    /// Every evidence handle behind the result; order carries no meaning.
    pub handles: BTreeSet<ArtifactId>,
    /// Scope, time, version, and precision bounds of the observation.
    pub validity: ValidityBounds,
    /// Task binding of the inquiry that produced the observation.
    pub task_id: TaskId,
    /// Fence under which the observation was captured.
    pub fence: StateFence,
    /// Bounded reason that reopens inquiry, required for stale/superseded.
    pub reopen_reason: Option<String>,
    /// Digest of the bounded proof payload behind this record.
    pub proof_digest: String,
}

impl SupportRecord {
    /// Constructs a support record after validating every bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        proposition: PropositionId,
        result: SupportResult,
        handles: BTreeSet<ArtifactId>,
        validity: ValidityBounds,
        task_id: TaskId,
        fence: StateFence,
        reopen_reason: Option<String>,
        proof_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let record = Self {
            proposition,
            result,
            handles,
            validity,
            task_id,
            fence,
            reopen_reason,
            proof_digest: proof_digest.into(),
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates bounds, handles, reopen discipline, and digests.
    ///
    /// `Unsupported` with valid handles and bounds is valid data and passes.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validity.validate()?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "support.fence",
            })?;
        if self.handles.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "support.handles",
            });
        }
        let handles_required = !matches!(
            self.result,
            SupportResult::Unknown
                | SupportResult::OutsideManifest
                | SupportResult::JustifiedNotApplicable
        );
        if handles_required && self.handles.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "support.handles",
            });
        }
        let reopen_required = matches!(
            self.result,
            SupportResult::Stale | SupportResult::Superseded
        );
        match (&self.reopen_reason, reopen_required) {
            (Some(reason), true) => {
                validate_bounded_text(reason.as_str(), "support.reopen_reason", MAX_SHORT_TEXT)?;
            }
            (None, true) => {
                return Err(ContractError::EmptyCollection {
                    field: "support.reopen_reason",
                });
            }
            (Some(_), false) => {
                return Err(ContractError::ImpossibleCombination {
                    field: "support.reopen_reason",
                });
            }
            (None, false) => {}
        }
        validate_digest(&self.proof_digest, "support.proof_digest")?;
        Ok(())
    }

    /// Validates this record against the requesting task, scope, and fence.
    pub fn validate_for(
        &self,
        task_id: &TaskId,
        scope: &str,
        fence: &StateFence,
    ) -> Result<(), ContractError> {
        self.validate()?;
        if &self.task_id != task_id {
            return Err(ContractError::TaskMismatch {
                field: "support.task_id",
            });
        }
        if self.validity.scope != scope {
            return Err(ContractError::ScopeMismatch {
                field: "support.scope",
            });
        }
        if !self.fence.is_compatible_with(fence) {
            return Err(ContractError::FenceMismatch {
                field: "support.fence",
            });
        }
        Ok(())
    }
}
