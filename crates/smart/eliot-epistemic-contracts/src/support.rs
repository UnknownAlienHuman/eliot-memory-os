//! Per-proposition support: results, validity bounds, and weakest-link.
//!
//! A [`SupportRecord`] states what one inquiry route observed for one proposition inside explicit scope, time,
//! version, and precision bounds, with every evidence handle preserved. An unsupported-but-valid record is data,
//! not an error. Aggregation uses [`weakest_link`].
use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_contracts::{StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, validate_bounded_text, validate_digest,
};
use crate::grade::GradeAssignment;
use crate::identity::PropositionId;
use crate::temporal::TemporalRecord;
use crate::verifier::SourceAssurance;

/// What one route observed: `Supported` and `Partial` license reliance; others preserve the unknown.
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
    /// Weakest-link rank: lower bounds any aggregate it participates in.
    pub(crate) const fn link_rank(self) -> u8 {
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

/// Returns the weakest of the supplied results (empty input is an error).
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

/// Scope, time, version, and precision bounds of one support observation: a mismatch with the question asked
/// limits support instead of failing; the record stays valid data about a narrower question.
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

/// Precision lattice, coarsest-first: coarser covers finer; off-lattice covers exact equality.
const PRECISION_LATTICE: [&str; 6] = [
    "repository",
    "package",
    "directory",
    "file",
    "symbol",
    "line",
];
fn precision_rank(precision: &str) -> Option<usize> {
    PRECISION_LATTICE
        .iter()
        .position(|known| *known == precision.trim().to_lowercase())
}

/// Returns whether `supported` precision covers an `asserted` precision.
pub(crate) fn precision_covers(supported: &str, asserted: &str) -> bool {
    match (precision_rank(supported), precision_rank(asserted)) {
        (Some(known), Some(wanted)) => wanted <= known,
        _ => supported == asserted,
    }
}

/// Returns whether the outer window contains the inner window (unbounded sides stay unbounded).
pub(crate) fn window_contains(
    outer: (Option<i64>, Option<i64>),
    inner: (Option<i64>, Option<i64>),
) -> bool {
    match (outer.0, inner.0) {
        (Some(lo), Some(inner_lo)) if inner_lo < lo => return false,
        _ => {}
    }
    match (outer.1, inner.1) {
        (Some(hi), Some(inner_hi)) if inner_hi > hi => return false,
        _ => {}
    }
    // A bounded outer window never contains an unbounded inner window: "any time" from "this week"
    // is a partial answer, never a covered one.
    if outer.0.is_some() && inner.0.is_none() {
        return false;
    }
    if outer.1.is_some() && inner.1.is_none() {
        return false;
    }
    true
}
/// Precision role (no canonical owner covers precision spellings).
pub struct Precision(pub String);
impl ValidityBounds {
    /// Constructs validity bounds, rejecting inverted windows.
    pub fn new(
        scope: impl Into<String>,
        window_start_ms: Option<i64>,
        window_end_ms: Option<i64>,
        version: impl Into<String>,
        precision: Precision,
    ) -> Result<Self, ContractError> {
        let bounds = Self {
            scope: scope.into(),
            window_start_ms,
            window_end_ms,
            version: version.into(),
            precision: precision.0,
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
    /// Returns whether these bounds cover the requested scope, instant,
    /// version, and precision. A mismatch limits support instead of failing.
    pub fn covers(
        &self,
        scope: &str,
        instant_ms: Option<i64>,
        version: &str,
        precision: &str,
    ) -> bool {
        if self.scope != scope {
            return false;
        }
        match (self.window_start_ms, self.window_end_ms, instant_ms) {
            (Some(start), _, Some(instant)) if instant < start => return false,
            (_, Some(end), Some(instant)) if instant > end => return false,
            _ => {}
        }
        if self.version != version {
            return false;
        }
        precision_covers(&self.precision, precision)
    }
    /// Returns whether these bounds cover a candidate window, version, and
    /// precision: same scope and version, containing window, covering
    /// precision.
    pub fn covers_candidate(
        &self,
        scope: &str,
        window: (Option<i64>, Option<i64>),
        version: &str,
        precision: &str,
    ) -> bool {
        if self.scope != scope || self.version != version {
            return false;
        }
        if !window_contains((self.window_start_ms, self.window_end_ms), window) {
            return false;
        }
        precision_covers(&self.precision, precision)
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
    /// Grade assignment of the observation; unknown stays unknown and caps.
    pub grade: GradeAssignment,
    /// Task binding of the inquiry that produced the observation.
    pub task_id: TaskId,
    /// Fence under which the observation was captured.
    pub fence: StateFence,
    /// Applicable temporal record, when the route timestamped its capture.
    /// The five roles stay separate; no role is merged into the window.
    pub temporal: Option<TemporalRecord>,
    /// Source assurance binding this record's proof to its actual source.
    pub assurance: Option<SourceAssurance>,
    /// Bounded reason that reopens inquiry, required for stale/superseded.
    pub reopen_reason: Option<String>,
    /// Digest of the bounded proof payload behind this record.
    pub proof_digest: String,
}
/// Named constructor arguments for [`SupportRecord::new`].
/// Named fields block transposition; text uses concrete [`String`].
#[derive(Clone, Debug)]
pub struct SupportRecordParams {
    pub proposition: PropositionId,
    pub result: SupportResult,
    pub handles: BTreeSet<ArtifactId>,
    pub validity: ValidityBounds,
    pub grade: GradeAssignment,
    pub task_id: TaskId,
    pub fence: StateFence,
    pub temporal: Option<TemporalRecord>,
    pub assurance: Option<SourceAssurance>,
    pub reopen_reason: Option<String>,
    pub proof_digest: String,
}
impl SupportRecord {
    /// Constructs a support record after validating every bound.
    pub fn new(params: SupportRecordParams) -> Result<Self, ContractError> {
        let record = Self {
            proposition: params.proposition,
            result: params.result,
            handles: params.handles,
            validity: params.validity,
            grade: params.grade,
            task_id: params.task_id,
            fence: params.fence,
            temporal: params.temporal,
            assurance: params.assurance,
            reopen_reason: params.reopen_reason,
            proof_digest: params.proof_digest,
        };
        record.validate()?;
        Ok(record)
    }
    /// Validates bounds, handles, reopen discipline, and digests.
    ///
    /// `Unsupported` with valid handles and bounds is valid data and passes.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validity.validate()?;
        self.grade.validate()?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "support.fence",
            })?;
        if let Some(temporal) = &self.temporal {
            temporal.validate()?;
        }
        if let Some(assurance) = &self.assurance {
            assurance.validate()?;
            if assurance.proof_digest != self.proof_digest {
                return Err(ContractError::DigestMismatch {
                    field: "support.assurance",
                });
            }
        }
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
