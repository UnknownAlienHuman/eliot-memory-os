//! Evidence grade: the frozen I21.2 rigour ladder.
//!
//! Grade states how much rigour was **required**, following I21.2 exactly:
//! `ORIENTING`, `GROUNDED`, `CORROBORATED`, `SCIENCE_GRADE`, in that order.
//! Grade is orthogonal to evidence authority, per-claim support, and
//! assertability: no axis can be inferred from another or collapsed into one
//! scalar. This module performs intrinsic ceiling checks only — it validates
//! supplied ceilings against each other and never grades evidence itself.
//!
//! A claim carries the grade it was produced under; quoting a claim never
//! upgrades it, dependents of a claim cannot claim a higher grade than the
//! claim they depend on, and an unknown grade is distinct from the lowest
//! known grade.

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

    /// Validates that a dependent claim does not raise its parent's grade.
    ///
    /// A later reader may not upgrade a claim by quoting it; raising the
    /// requirement is prospective and never retroactive.
    pub fn check_dependent(parent: Self, dependent: Self) -> Result<(), ContractError> {
        if dependent.rank() > parent.rank() {
            return Err(ContractError::CeilingViolation {
                field: "grade.dependent",
            });
        }
        Ok(())
    }
}

/// A supplied grade that keeps "unknown" distinct from the lowest known grade.
///
/// Exactly one side is present: either a frozen grade or a bounded reason why
/// the grade cannot be established. An unknown grade never decodes as
/// `ORIENTING` and never satisfies a grade ceiling on its own.
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
}
