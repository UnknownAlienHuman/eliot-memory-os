//! Evidence grade: the frozen I21.2 rigour ladder.
//!
//! Grade states how much rigour was **required**: `ORIENTING`, `GROUNDED`, `CORROBORATED`, `SCIENCE_GRADE`,
//! weakest-first, orthogonal to authority, support, and assertability. This module only checks supplied
//! ceilings — it never grades evidence. Quoting never upgrades; dependents never exceed their parent; unknown
//! stays distinct from the lowest known grade.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ContractError, validate_bounded_text};

/// Frozen I21.2 evidence grade names in canonical order.
///
/// The order is load-bearing: [`EvidenceGrade::rank`] increases with rigour.
pub const GRADE_ORDER: [EvidenceGrade; 4] = [
    EvidenceGrade::Orienting,
    EvidenceGrade::Grounded,
    EvidenceGrade::Corroborated,
    EvidenceGrade::ScienceGrade,
];

/// Exact I21.2 evidence grade.
///
/// Variants are listed weakest-first; declaration order is the rigour order.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceGrade {
    /// Bounded exact or cached answer; no claim of coverage; not admissible
    /// for a material decision.
    Orienting,
    /// Every material statement resolves to an exact source handle.
    Grounded,
    /// Independent source families or observation route; rivals represented;
    /// coverage denominator declared.
    Corroborated,
    /// Corroborated plus declared lane, frozen protocol/evaluator where
    /// confirmatory, evidence freeze, claim-level audit, explicit debts.
    ScienceGrade,
}

impl EvidenceGrade {
    /// Returns the rigour rank, weakest-first starting at zero.
    pub const fn rank(self) -> u8 {
        match self {
            Self::Orienting => 0,
            Self::Grounded => 1,
            Self::Corroborated => 2,
            Self::ScienceGrade => 3,
        }
    }

    /// Returns the exact frozen wire name of this grade.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Orienting => "ORIENTING",
            Self::Grounded => "GROUNDED",
            Self::Corroborated => "CORROBORATED",
            Self::ScienceGrade => "SCIENCE_GRADE",
        }
    }

    /// Returns the frozen grade names in canonical weakest-first order.
    pub fn ordered_names() -> [&'static str; 4] {
        [
            EvidenceGrade::Orienting.wire_name(),
            EvidenceGrade::Grounded.wire_name(),
            EvidenceGrade::Corroborated.wire_name(),
            EvidenceGrade::ScienceGrade.wire_name(),
        ]
    }

    /// Validates a supplied ceiling intrinsically: the claimed grade must not
    /// exceed the ceiling it was produced under. No grading is performed.
    pub fn check_ceiling(claimed: Self, ceiling: Self) -> Result<(), ContractError> {
        if claimed.rank() > ceiling.rank() {
            return Err(ContractError::CeilingViolation {
                field: "grade.ceiling",
            });
        }
        Ok(())
    }

    /// Quoting a claim never upgrades its parent's grade.
    ///
    /// Raising the requirement is prospective and never retroactive.
    pub fn check_dependent(parent: Self, dependent: Self) -> Result<(), ContractError> {
        if dependent.rank() > parent.rank() {
            return Err(ContractError::CeilingViolation {
                field: "grade.dependent",
            });
        }
        Ok(())
    }
}

/// A supplied grade keeping "unknown" distinct from the lowest known grade:
/// exactly one side is present, and unknown never satisfies a ceiling alone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GradeAssignment {
    /// Frozen grade carried by the claim, when known.
    pub grade: Option<EvidenceGrade>,
    /// Bounded reason why the grade is unknown, when the grade is absent.
    pub unknown_reason: Option<String>,
}

impl GradeAssignment {
    /// Assigns a known frozen grade.
    pub fn known(grade: EvidenceGrade) -> Self {
        Self {
            grade: Some(grade),
            unknown_reason: None,
        }
    }

    /// Records an unknown grade with its bounded reason.
    pub fn unknown(reason: impl Into<String>) -> Result<Self, ContractError> {
        let assignment = Self {
            grade: None,
            unknown_reason: Some(reason.into()),
        };
        assignment.validate()?;
        Ok(assignment)
    }

    /// Returns whether the grade is unknown.
    pub fn is_unknown(&self) -> bool {
        self.grade.is_none()
    }

    /// Validates that exactly one side is present.
    pub fn validate(&self) -> Result<(), ContractError> {
        match (&self.grade, &self.unknown_reason) {
            (Some(_), None) => Ok(()),
            (None, Some(reason)) => {
                validate_bounded_text(reason.as_str(), "grade.unknown_reason", 256)?;
                Ok(())
            }
            _ => Err(ContractError::ImpossibleCombination {
                field: "grade.assignment",
            }),
        }
    }

    /// Returns the known grade, or `None` when the grade is unknown.
    pub fn known_grade(&self) -> Option<EvidenceGrade> {
        self.grade
    }

    /// Returns the weakest of the supplied assignments: any unknown poisons
    /// the aggregate, otherwise the least rigorous known grade wins. Empty
    /// input errors.
    pub fn weakest(assignments: &[GradeAssignment]) -> Result<GradeAssignment, ContractError> {
        let mut iter = assignments.iter();
        let first = iter.next().ok_or(ContractError::EmptyCollection {
            field: "grade.assignment",
        })?;
        first.validate()?;
        let mut weakest = first.grade;
        let mut unknown = first.is_unknown();
        for assignment in iter {
            assignment.validate()?;
            if assignment.is_unknown() {
                unknown = true;
            } else if let Some(grade) = assignment.grade {
                weakest = Some(match weakest {
                    Some(current) if current.rank() < grade.rank() => current,
                    _ => grade,
                });
            }
        }
        if unknown {
            Ok(GradeAssignment {
                grade: None,
                unknown_reason: Some("weakest-link: grade unknown".to_owned()),
            })
        } else if let Some(grade) = weakest {
            Ok(GradeAssignment::known(grade))
        } else {
            Err(ContractError::EmptyCollection {
                field: "grade.assignment",
            })
        }
    }
}
