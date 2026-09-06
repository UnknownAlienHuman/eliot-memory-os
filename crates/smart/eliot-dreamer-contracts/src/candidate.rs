//! Inert Dreamer candidates with candidate-only ceilings.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! A [`CandidateResult`] proposes a ranked outcome for downstream selection.
//! It is inert: it carries no admitted, current-state, effect, delivery,
//! outcome, promotion, or finish evidence. Any such carry is rejected with
//! [`ContractViolation::ForbiddenCarry`]. Preservation is judged over seven
//! independent dimensions with no averaging: one failed or unknown dimension
//! fails the whole report.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractViolation;

/// Independent preservation dimensions, each judged on its own.
///
/// No averaging is permitted: [`PreservationReport::overall`] fails when any
/// single dimension fails or is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PreservationDimension {
    /// Nothing in scope was silently dropped.
    Coverage,
    /// The candidate says only what its sources support.
    Faithfulness,
    /// Every claim traces back to its source handles.
    Lineage,
    /// The proposal can be undone via its rollback note.
    Reversibility,
    /// The candidate claims no authority beyond proposal.
    AuthorityCeiling,
    /// All dependencies of the proposal are closed and named.
    DependencyClosure,
    /// Provenance records are retained, not rewritten.
    ProvenanceRetention,
}

impl PreservationDimension {
    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Coverage => "coverage",
            Self::Faithfulness => "faithfulness",
            Self::Lineage => "lineage",
            Self::Reversibility => "reversibility",
            Self::AuthorityCeiling => "authority_ceiling",
            Self::DependencyClosure => "dependency_closure",
            Self::ProvenanceRetention => "provenance_retention",
        }
    }

    /// Parses a wire spelling into a [`PreservationDimension`].
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::UnknownVariant`] for any unknown spelling.
    pub fn parse(value: &str) -> Result<Self, ContractViolation> {
        match value {
            "coverage" => Ok(Self::Coverage),
            "faithfulness" => Ok(Self::Faithfulness),
            "lineage" => Ok(Self::Lineage),
            "reversibility" => Ok(Self::Reversibility),
            "authority_ceiling" => Ok(Self::AuthorityCeiling),
            "dependency_closure" => Ok(Self::DependencyClosure),
            "provenance_retention" => Ok(Self::ProvenanceRetention),
            other => Err(ContractViolation::UnknownVariant {
                field: "preservation_dimension",
                value: other.to_owned(),
            }),
        }
    }
}

/// Canonical spellings of the seven preservation dimensions.
pub const PRESERVATION_DIMENSIONS: &[&str] = &[
    "coverage",
    "faithfulness",
    "lineage",
    "reversibility",
    "authority_ceiling",
    "dependency_closure",
    "provenance_retention",
];

/// Verdict for one preservation dimension.
///
/// `known = false` marks the dimension as unknown, which fails
/// [`PreservationReport::overall`] exactly like `passed = false`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DimensionVerdict {
    /// Dimension under judgement.
    pub dimension: PreservationDimension,
    /// Whether the dimension passed.
    pub passed: bool,
    /// Whether the dimension was actually judged (`false` means unknown).
    pub known: bool,
    /// Exact note supporting the verdict (non-blank).
    pub note: String,
}

/// Seven independent dimension verdicts with no averaging.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PreservationReport {
    /// Exactly seven verdicts, one per dimension.
    pub verdicts: Vec<DimensionVerdict>,
}

impl PreservationReport {
    /// Validates report shape: exactly seven verdicts, one per dimension,
    /// each with a non-blank note.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Preservation`] when the verdict count is
    /// not seven, any dimension repeats or is missing, or any note is blank.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.verdicts.len() != PRESERVATION_DIMENSIONS.len() {
            return Err(ContractViolation::Preservation(format!(
                "expected {} dimension verdicts, got {}",
                PRESERVATION_DIMENSIONS.len(),
                self.verdicts.len()
            )));
        }
        let mut seen: Vec<PreservationDimension> = Vec::with_capacity(7);
        for verdict in &self.verdicts {
            if verdict.note.trim().is_empty() {
                return Err(ContractViolation::Preservation(format!(
                    "dimension {} has a blank note",
                    verdict.dimension.as_str()
                )));
            }
            if seen.contains(&verdict.dimension) {
                return Err(ContractViolation::Preservation(format!(
                    "duplicate verdict for dimension {}",
                    verdict.dimension.as_str()
                )));
            }
            seen.push(verdict.dimension);
        }
        for spelling in PRESERVATION_DIMENSIONS {
            let dimension = PreservationDimension::parse(spelling)?;
            if !seen.contains(&dimension) {
                return Err(ContractViolation::Preservation(format!(
                    "missing verdict for dimension {spelling}"
                )));
            }
        }
        Ok(())
    }

    /// Judges the report with no averaging.
    ///
    /// Any verdict with `passed = false` or `known = false` fails the whole
    /// report: six passing dimensions can never outweigh one failed or
    /// unknown dimension.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Preservation`] when shape validation
    /// fails or any single dimension fails or is unknown.
    pub fn overall(&self) -> Result<(), ContractViolation> {
        self.validate()?;
        for verdict in &self.verdicts {
            if !verdict.known {
                return Err(ContractViolation::Preservation(format!(
                    "dimension {} is unknown",
                    verdict.dimension.as_str()
                )));
            }
            if !verdict.passed {
                return Err(ContractViolation::Preservation(format!(
                    "dimension {} failed",
                    verdict.dimension.as_str()
                )));
            }
        }
        Ok(())
    }
}

/// Closed candidate disposition states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CandidateDisposition {
    /// A live proposal awaiting selection.
    Candidate,
    /// A repeat of an already-proposed candidate.
    Duplicate,
    /// A proposal that conflicts with another candidate.
    Conflict,
    /// No proposal is offered.
    Abstention,
    /// Only a partial proposal could be formed.
    Partial,
    /// The proposal path is blocked.
    Blocked,
    /// The requested kind is not supported here.
    Unsupported,
    /// An internal defect stopped proposal formation.
    InternalDefect,
}

impl CandidateDisposition {
    /// Returns the canonical wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Candidate => "candidate",
            Self::Duplicate => "duplicate",
            Self::Conflict => "conflict",
            Self::Abstention => "abstention",
            Self::Partial => "partial",
            Self::Blocked => "blocked",
            Self::Unsupported => "unsupported",
            Self::InternalDefect => "internal_defect",
        }
    }

    /// Parses a wire spelling into a [`CandidateDisposition`].
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::UnknownVariant`] for any unknown spelling.
    pub fn parse(value: &str) -> Result<Self, ContractViolation> {
        match value {
            "candidate" => Ok(Self::Candidate),
            "duplicate" => Ok(Self::Duplicate),
            "conflict" => Ok(Self::Conflict),
            "abstention" => Ok(Self::Abstention),
            "partial" => Ok(Self::Partial),
            "blocked" => Ok(Self::Blocked),
            "unsupported" => Ok(Self::Unsupported),
            "internal_defect" => Ok(Self::InternalDefect),
            other => Err(ContractViolation::UnknownVariant {
                field: "candidate_disposition",
                value: other.to_owned(),
            }),
        }
    }
}

/// An inert candidate proposal.
///
/// Candidate-only ceiling: the forbidden carry fields must all stay `None`.
/// Setting any of them to `Some` claims admitted, current-state, effect,
/// delivery, outcome, promotion, or finish evidence that a candidate must
/// never carry, and [`CandidateResult::validate`] rejects it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateResult {
    /// Candidate identity (non-blank).
    pub candidate_id: String,
    /// Curation kind wire spelling (non-blank).
    pub kind_spelling: String,
    /// Curation family wire spelling (non-blank).
    pub family_spelling: String,
    /// Owning job identity (non-blank).
    pub job_id: String,
    /// Decision scope identity (non-blank).
    pub scope_id: String,
    /// Owning task identity (non-blank).
    pub task_id: String,
    /// Proposed statement (non-blank).
    pub statement: String,
    /// Candidate disposition.
    pub disposition: CandidateDisposition,
    /// Seven-dimension preservation report.
    pub preservation: PreservationReport,
    /// Support note (non-blank).
    pub support_note: String,
    /// Rollback note (non-blank).
    pub rollback_note: String,
    /// Source handles backing the lineage claim (non-empty, all non-blank).
    pub source_handles: Vec<String>,
    /// Forbidden: admitted-state evidence must never ride on a candidate.
    pub admitted_ref: Option<String>,
    /// Forbidden: current-state evidence must never ride on a candidate.
    pub current_state_ref: Option<String>,
    /// Forbidden: effect evidence must never ride on a candidate.
    pub effect_ref: Option<String>,
    /// Forbidden: executed-effect evidence must never ride on a candidate.
    pub executed_ref: Option<String>,
    /// Forbidden: delivery evidence must never ride on a candidate.
    pub delivery_ref: Option<String>,
    /// Forbidden: used-outcome evidence must never ride on a candidate.
    pub use_ref: Option<String>,
    /// Forbidden: outcome evidence must never ride on a candidate.
    pub outcome_ref: Option<String>,
    /// Forbidden: promotion evidence must never ride on a candidate.
    pub promotion_ref: Option<String>,
    /// Forbidden: finish evidence must never ride on a candidate.
    pub finish_ref: Option<String>,
}

impl CandidateResult {
    /// Validates lineage, preservation, notes, and the candidate-only ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] when any required field is blank,
    /// lineage handles are empty or blank, preservation fails, or any
    /// forbidden carry field is `Some`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        require_non_blank("candidate_id", &self.candidate_id)?;
        require_non_blank("kind_spelling", &self.kind_spelling)?;
        require_non_blank("family_spelling", &self.family_spelling)?;
        require_non_blank("job_id", &self.job_id)?;
        require_non_blank("scope_id", &self.scope_id)?;
        require_non_blank("task_id", &self.task_id)?;
        require_non_blank("statement", &self.statement)?;
        require_non_blank("support_note", &self.support_note)?;
        require_non_blank("rollback_note", &self.rollback_note)?;
        if self.source_handles.is_empty() {
            return Err(ContractViolation::MissingField("source_handles"));
        }
        for handle in &self.source_handles {
            if handle.trim().is_empty() {
                return Err(ContractViolation::Malformed {
                    field: "source_handles",
                    reason: "source handle must be non-blank".to_owned(),
                });
            }
        }
        self.preservation.overall()?;
        reject_carry("admitted_ref", self.admitted_ref.as_ref())?;
        reject_carry("current_state_ref", self.current_state_ref.as_ref())?;
        reject_carry("effect_ref", self.effect_ref.as_ref())?;
        reject_carry("executed_ref", self.executed_ref.as_ref())?;
        reject_carry("delivery_ref", self.delivery_ref.as_ref())?;
        reject_carry("use_ref", self.use_ref.as_ref())?;
        reject_carry("outcome_ref", self.outcome_ref.as_ref())?;
        reject_carry("promotion_ref", self.promotion_ref.as_ref())?;
        reject_carry("finish_ref", self.finish_ref.as_ref())?;
        Ok(())
    }
}

fn require_non_blank(field: &'static str, value: &str) -> Result<(), ContractViolation> {
    if value.trim().is_empty() {
        return Err(ContractViolation::MissingField(field));
    }
    Ok(())
}

fn reject_carry(field: &'static str, value: Option<&String>) -> Result<(), ContractViolation> {
    if value.is_some() {
        return Err(ContractViolation::ForbiddenCarry(field.to_owned()));
    }
    Ok(())
}

/// Proposes an inert candidate.
///
/// The constructor keeps every forbidden carry field at `None`, requires
/// non-blank lineage via `source_handles`, and enforces preservation with
/// no averaging.
///
/// # Errors
///
/// Returns [`ContractViolation`] when any required field is blank, lineage
/// handles are empty or blank, or preservation fails.
#[allow(clippy::too_many_arguments)]
pub fn propose_candidate(
    candidate_id: String,
    kind_spelling: String,
    family_spelling: String,
    job_id: String,
    scope_id: String,
    task_id: String,
    statement: String,
    disposition: CandidateDisposition,
    preservation: PreservationReport,
    support_note: String,
    rollback_note: String,
    source_handles: Vec<String>,
) -> Result<CandidateResult, ContractViolation> {
    let candidate = CandidateResult {
        candidate_id,
        kind_spelling,
        family_spelling,
        job_id,
        scope_id,
        task_id,
        statement,
        disposition,
        preservation,
        support_note,
        rollback_note,
        source_handles,
        admitted_ref: None,
        current_state_ref: None,
        effect_ref: None,
        executed_ref: None,
        delivery_ref: None,
        use_ref: None,
        outcome_ref: None,
        promotion_ref: None,
        finish_ref: None,
    };
    candidate.validate()?;
    Ok(candidate)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn passing_report() -> PreservationReport {
        PreservationReport {
            verdicts: PRESERVATION_DIMENSIONS
                .iter()
                .map(|spelling| DimensionVerdict {
                    dimension: PreservationDimension::parse(spelling)
                        .unwrap_or(PreservationDimension::Coverage),
                    passed: true,
                    known: true,
                    note: format!("{spelling} holds"),
                })
                .collect(),
        }
    }

    fn valid_candidate() -> CandidateResult {
        propose_candidate(
            "candidate-1".to_owned(),
            "dream.summary".to_owned(),
            "summary".to_owned(),
            "job-1".to_owned(),
            "scope-1".to_owned(),
            "task-1".to_owned(),
            "proposed statement".to_owned(),
            CandidateDisposition::Candidate,
            passing_report(),
            "supported by source-1".to_owned(),
            "drop candidate-1 to roll back".to_owned(),
            vec!["source-1".to_owned()],
        )
        .unwrap_or_else(|_| CandidateResult {
            candidate_id: "candidate-1".to_owned(),
            kind_spelling: "dream.summary".to_owned(),
            family_spelling: "summary".to_owned(),
            job_id: "job-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            statement: "proposed statement".to_owned(),
            disposition: CandidateDisposition::Candidate,
            preservation: passing_report(),
            support_note: "supported by source-1".to_owned(),
            rollback_note: "drop candidate-1 to roll back".to_owned(),
            source_handles: vec!["source-1".to_owned()],
            admitted_ref: None,
            current_state_ref: None,
            effect_ref: None,
            executed_ref: None,
            delivery_ref: None,
            use_ref: None,
            outcome_ref: None,
            promotion_ref: None,
            finish_ref: None,
        })
    }

    // WORK_UNIT_CASE: 578/35
    #[test]
    fn marker_35_disposition_states_distinct() {
        let states = [
            CandidateDisposition::Candidate,
            CandidateDisposition::Duplicate,
            CandidateDisposition::Conflict,
            CandidateDisposition::Abstention,
            CandidateDisposition::Partial,
            CandidateDisposition::Blocked,
            CandidateDisposition::Unsupported,
            CandidateDisposition::InternalDefect,
        ];
        assert_eq!(states.len(), 8);
        let mut spellings: Vec<&str> = states.iter().map(|state| state.as_str()).collect();
        spellings.sort_unstable();
        spellings.dedup();
        assert_eq!(spellings.len(), 8, "all dispositions must differ");
        for state in states {
            let parsed = CandidateDisposition::parse(state.as_str());
            assert_eq!(parsed, Ok(state));
            let bytes = serde_json::to_vec(&state).expect("disposition serializes");
            let decoded: CandidateDisposition =
                serde_json::from_slice(&bytes).expect("disposition roundtrips");
            assert_eq!(decoded, state);
        }
    }

    // WORK_UNIT_CASE: 578/38
    #[test]
    fn marker_38_seven_preservation_dimensions_independent() {
        assert_eq!(PRESERVATION_DIMENSIONS.len(), 7);
        let report = passing_report();
        assert!(report.validate().is_ok());
        assert!(report.overall().is_ok());
        for spelling in PRESERVATION_DIMENSIONS {
            let addressed: Vec<&DimensionVerdict> = report
                .verdicts
                .iter()
                .filter(|verdict| verdict.dimension.as_str() == *spelling)
                .collect();
            assert_eq!(addressed.len(), 1, "dimension {spelling} must appear once");
            assert!(addressed[0].passed && addressed[0].known);
        }
    }

    // WORK_UNIT_CASE: 578/39
    #[test]
    fn marker_39_failed_or_unknown_dimension_fails_overall() {
        let mut failed = passing_report();
        failed.verdicts[0].passed = false;
        assert!(failed.validate().is_ok());
        assert!(failed.overall().is_err());

        let mut unknown = passing_report();
        unknown.verdicts[3].known = false;
        assert!(unknown.validate().is_ok());
        assert!(unknown.overall().is_err());
    }

    // WORK_UNIT_CASE: 578/40
    #[test]
    fn marker_40_candidate_cannot_carry_terminal_evidence() {
        let mut candidate = valid_candidate();
        assert!(candidate.validate().is_ok());

        candidate.admitted_ref = Some("admitted-1".to_owned());
        assert!(matches!(
            candidate.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
        candidate.admitted_ref = None;

        candidate.current_state_ref = Some("current-1".to_owned());
        assert!(matches!(
            candidate.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
        candidate.current_state_ref = None;

        candidate.effect_ref = Some("effect-1".to_owned());
        assert!(matches!(
            candidate.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
        candidate.effect_ref = None;

        candidate.executed_ref = Some("executed-1".to_owned());
        assert!(matches!(
            candidate.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
        candidate.executed_ref = None;

        candidate.delivery_ref = Some("delivery-1".to_owned());
        assert!(matches!(
            candidate.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
        candidate.delivery_ref = None;

        candidate.use_ref = Some("used-1".to_owned());
        assert!(matches!(
            candidate.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
        candidate.use_ref = None;

        candidate.outcome_ref = Some("outcome-1".to_owned());
        assert!(matches!(
            candidate.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
        candidate.outcome_ref = None;

        candidate.promotion_ref = Some("promotion-1".to_owned());
        assert!(matches!(
            candidate.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
        candidate.promotion_ref = None;

        candidate.finish_ref = Some("finish-1".to_owned());
        assert!(matches!(
            candidate.validate(),
            Err(ContractViolation::ForbiddenCarry(_))
        ));
        candidate.finish_ref = None;

        assert!(candidate.validate().is_ok());
    }
}
