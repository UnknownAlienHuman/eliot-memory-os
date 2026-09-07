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

use crate::curation::{CurationKind, kind_family};
use crate::error::{ContractViolation, check_text, check_vec_bound, closed_wire_enum};

fn pres(dimension: &str, detail: &str) -> ContractViolation {
    ContractViolation::Preservation(format!("dimension {dimension} {detail}"))
}

fn dup_or_missing(kind: &str, dimension: &str) -> ContractViolation {
    ContractViolation::Preservation(format!("{kind} verdict for dimension {dimension}"))
}

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

closed_wire_enum!(assoc PreservationDimension, field = "preservation_dimension", [
    Coverage => "coverage",
    Faithfulness => "faithfulness",
    Lineage => "lineage",
    Reversibility => "reversibility",
    AuthorityCeiling => "authority_ceiling",
    DependencyClosure => "dependency_closure",
    ProvenanceRetention => "provenance_retention",
]);

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
        let (want, got) = (PRESERVATION_DIMENSIONS.len(), self.verdicts.len());
        if got != want {
            return Err(ContractViolation::Preservation(format!(
                "expected {want} dimension verdicts, got {got}"
            )));
        }
        let mut seen: Vec<PreservationDimension> = Vec::with_capacity(7);
        for verdict in &self.verdicts {
            let d = verdict.dimension.as_str();
            if verdict.note.trim().is_empty() {
                return Err(pres(d, "has a blank note"));
            }
            if verdict.note.len() > 1024 || verdict.note.chars().any(char::is_control) {
                return Err(pres(d, "note exceeds 1024 bytes or has control chars"));
            }
            if seen.contains(&verdict.dimension) {
                return Err(dup_or_missing("duplicate", d));
            }
            seen.push(verdict.dimension);
        }
        for spelling in PRESERVATION_DIMENSIONS {
            if !seen.contains(&PreservationDimension::parse(spelling)?) {
                return Err(dup_or_missing("missing", spelling));
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
                return Err(pres(verdict.dimension.as_str(), "is unknown"));
            }
            if !verdict.passed {
                return Err(pres(verdict.dimension.as_str(), "failed"));
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

closed_wire_enum!(assoc CandidateDisposition, field = "candidate_disposition", [
    Candidate => "candidate",
    Duplicate => "duplicate",
    Conflict => "conflict",
    Abstention => "abstention",
    Partial => "partial",
    Blocked => "blocked",
    Unsupported => "unsupported",
    InternalDefect => "internal_defect",
]);

/// An inert candidate proposal.
///
/// Carries are unrepresentable: `deny_unknown_fields` rejects unknown
/// injected keys at decode.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateResult {
    /// Candidate identity (non-blank).
    pub candidate_id: String,
    /// Curation kind.
    pub kind: CurationKind,
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
}

impl CandidateResult {
    /// Validates lineage, preservation, notes, and kind mapping.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] when any required field is blank,
    /// lineage handles are empty or blank, preservation fails, or the
    /// kind/family mapping mismatches.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.candidate_id, "candidate_id", 256)?;
        check_text(&self.family_spelling, "family_spelling", 256)?;
        check_text(&self.job_id, "job_id", 256)?;
        check_text(&self.scope_id, "scope_id", 256)?;
        check_text(&self.task_id, "task_id", 256)?;
        check_text(&self.statement, "statement", 256)?;
        check_text(&self.support_note, "support_note", 256)?;
        check_text(&self.rollback_note, "rollback_note", 256)?;
        let reason = "kind and family_spelling mismatch".to_owned();
        if kind_family(self.kind) != self.family_spelling.as_str() {
            return Err(ContractViolation::KindPayload(reason));
        }
        if self.source_handles.is_empty() {
            return Err(ContractViolation::MissingField("source_handles"));
        }
        check_vec_bound(self.source_handles.len(), 1024, "source_handles")?;
        let handles = &self.source_handles;
        let mut agg = 0usize;
        for handle in handles {
            agg = agg.saturating_add(handle.len());
        }
        check_vec_bound(agg, 1024 * 1024, "source_handles")?;
        for handle in &self.source_handles {
            check_text(handle, "source_handles", 128)?;
        }
        self.preservation.overall()?;
        Ok(())
    }
}

/// Named proposal for [`propose_candidate`]; replaces 12 positional parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CandidateProposal {
    pub candidate_id: String,
    pub kind: CurationKind,
    pub family_spelling: String,
    pub job_id: String,
    pub scope_id: String,
    pub task_id: String,
    pub statement: String,
    pub disposition: CandidateDisposition,
    pub preservation: PreservationReport,
    pub support_note: String,
    pub rollback_note: String,
    pub source_handles: Vec<String>,
}

/// Proposes an inert candidate with all forbidden carry fields `None`.
///
/// # Errors
///
/// Returns [`ContractViolation`] on blank fields, bad lineage, or failed preservation.
pub fn propose_candidate(p: CandidateProposal) -> Result<CandidateResult, ContractViolation> {
    let candidate = CandidateResult {
        candidate_id: p.candidate_id,
        kind: p.kind,
        family_spelling: p.family_spelling,
        job_id: p.job_id,
        scope_id: p.scope_id,
        task_id: p.task_id,
        statement: p.statement,
        disposition: p.disposition,
        preservation: p.preservation,
        support_note: p.support_note,
        rollback_note: p.rollback_note,
        source_handles: p.source_handles,
    };
    candidate.validate()?;
    Ok(candidate)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn verdict(s: &str) -> DimensionVerdict {
        let dimension = PreservationDimension::parse(s).unwrap_or(PreservationDimension::Coverage);
        DimensionVerdict {
            dimension,
            passed: true,
            known: true,
            note: format!("{s} holds"),
        }
    }

    fn passing_report() -> PreservationReport {
        PreservationReport {
            verdicts: PRESERVATION_DIMENSIONS.iter().map(|s| verdict(s)).collect(),
        }
    }

    fn valid_candidate() -> CandidateResult {
        propose_candidate(CandidateProposal {
            candidate_id: "candidate-1".to_owned(),
            kind: CurationKind::Classification,
            family_spelling: "classification".to_owned(),
            job_id: "job-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            statement: "proposed statement".to_owned(),
            disposition: CandidateDisposition::Candidate,
            preservation: passing_report(),
            support_note: "supported by source-1".to_owned(),
            rollback_note: "drop candidate-1 to roll back".to_owned(),
            source_handles: vec!["source-1".to_owned()],
        })
        .expect("valid candidate")
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
            let bytes = serde_json::to_vec(&state).expect("disposition serializes");
            let decoded: CandidateDisposition = serde_json::from_slice(&bytes).expect("roundtrips");
            assert!(CandidateDisposition::parse(state.as_str()) == Ok(state) && decoded == state);
        }
    }

    // WORK_UNIT_CASE: 578/38
    #[test]
    fn marker_38_seven_preservation_dimensions_independent() {
        let report = passing_report();
        assert_eq!(PRESERVATION_DIMENSIONS.len(), 7);
        assert!(report.validate().is_ok() && report.overall().is_ok());
        for spelling in PRESERVATION_DIMENSIONS {
            let addressed: Vec<&DimensionVerdict> = report
                .verdicts
                .iter()
                .filter(|v| v.dimension.as_str() == *spelling)
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
        assert!(failed.validate().is_ok() && failed.overall().is_err());

        let mut unknown = passing_report();
        unknown.verdicts[3].known = false;
        assert!(unknown.validate().is_ok() && unknown.overall().is_err());
    }

    // WORK_UNIT_CASE: 578/40
    #[test]
    fn marker_40_candidate_cannot_carry_terminal_evidence() {
        let wire = serde_json::to_string(&valid_candidate()).expect("candidate serializes");
        for field in [
            "admitted_ref",
            "current_state_ref",
            "effect_ref",
            "executed_ref",
            "delivery_ref",
            "use_ref",
            "outcome_ref",
            "promotion_ref",
            "finish_ref",
        ] {
            let injected = wire.replacen('{', &std::format!("{{\"{field}\":\"x\","), 1);
            assert!(serde_json::from_str::<CandidateResult>(&injected).is_err());
        }
        let mut mismatch = valid_candidate();
        mismatch.family_spelling = "memory_repair".to_owned();
        let r = mismatch.validate();
        assert!(matches!(r, Err(ContractViolation::KindPayload(_))));
        assert!(valid_candidate().validate().is_ok());
        let mut maxed = valid_candidate();
        maxed.candidate_id = "c".repeat(256);
        assert!(maxed.validate().is_ok());
        let mut over = valid_candidate();
        over.candidate_id = "c".repeat(257);
        let r = over.validate();
        assert!(matches!(r, Err(ContractViolation::OutOfBounds { .. })));
        let mut ctrl = valid_candidate();
        ctrl.source_handles = vec!["a\nb".to_owned()];
        let r = ctrl.validate();
        assert!(matches!(r, Err(ContractViolation::Malformed { .. })));
        let mut max_handles = valid_candidate();
        max_handles.source_handles = vec!["s".to_owned(); 1024];
        assert!(max_handles.validate().is_ok());
        let mut over_handles = valid_candidate();
        over_handles.source_handles = vec!["s".to_owned(); 1025];
        let r = over_handles.validate();
        assert!(matches!(r, Err(ContractViolation::OutOfBounds { .. })));
        let mut agg_over = valid_candidate();
        agg_over.source_handles = vec!["s".repeat(2048); 600];
        let r = agg_over.validate();
        assert!(matches!(r, Err(ContractViolation::OutOfBounds { .. })));
        let mut max_note = passing_report();
        max_note.verdicts[0].note = "n".repeat(1024);
        assert!(max_note.validate().is_ok());
        let mut over_note = passing_report();
        over_note.verdicts[0].note = "n".repeat(1025);
        let r = over_note.validate();
        assert!(matches!(r, Err(ContractViolation::Preservation(_))));
        let mut ctrl_note = passing_report();
        ctrl_note.verdicts[0].note = "a\nb".to_owned();
        let r = ctrl_note.validate();
        assert!(matches!(r, Err(ContractViolation::Preservation(_))));
    }
}
