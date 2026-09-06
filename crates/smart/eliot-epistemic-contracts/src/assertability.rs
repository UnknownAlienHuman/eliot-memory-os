//! Position assertability: what a position may be rendered as.
//!
//! Assertability is capped by grade, authority, support results, coverage,
//! conflict, proof, verifier competence, and disclosure together: the ceilings
//! intersect and the lowest one wins. The seven levels are distinct renderings
//! — observed fact, qualified inference, hypothesis candidate, conflict
//! qualification, quarantined unknown, planning-only, and material effect —
//! and planning-only material never grants a material effect, no matter how
//! useful the plan is.
//!
//! Support results participate directly: partial support caps at qualified
//! inference, and unknown, stale, outside-manifest, contradicted,
//! unsupported, or superseded support caps at hypothesis candidate, so none of
//! them can yield unconditional, elevated, or material-effect assertability.
//! Coverage completeness is never inferred from merely-empty unknowns or
//! conflicts: callers derive it from a terminal receipt over a complete
//! denominator (see [`EpistemicPositionCandidate::validate_closed`](crate::candidate::EpistemicPositionCandidate::validate_closed)).
//! Disclosure can only lower: restricted material never rises above qualified
//! inference and quarantined material renders only as quarantined unknown. A
//! material effect additionally requires a competent verifier over a current
//! freshness; without one the effect is not licensed.

use eliot_evidence::EvidenceAuthority;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractError;
use crate::grade::EvidenceGrade;
use crate::support::SupportResult;
use crate::verifier::{DisclosureClass, RequiredVerifier};

/// What a position may be rendered as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PositionAssertability {
    /// Directly observed fact inside its scope.
    ObservedFact,
    /// Inference qualified by its bounds and assumptions.
    QualifiedInference,
    /// Hypothesis held as a candidate, never stated as fact.
    HypothesisCandidate,
    /// Renderable only with its conflict qualification attached.
    ConflictQualificationRequired,
    /// Withheld and quarantined until revalidated.
    UnknownWithheldQuarantined,
    /// Usable for planning only; grants no material effect.
    PlanningOnly,
    /// May ground a material effect under full ceilings.
    MaterialEffect,
}

impl PositionAssertability {
    /// Returns the exact frozen wire name of this assertability.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::ObservedFact => "OBSERVED_FACT",
            Self::QualifiedInference => "QUALIFIED_INFERENCE",
            Self::HypothesisCandidate => "HYPOTHESIS_CANDIDATE",
            Self::ConflictQualificationRequired => "CONFLICT_QUALIFICATION_REQUIRED",
            Self::UnknownWithheldQuarantined => "UNKNOWN_WITHHELD_QUARANTINED",
            Self::PlanningOnly => "PLANNING_ONLY",
            Self::MaterialEffect => "MATERIAL_EFFECT",
        }
    }

    /// Strength rank: higher licenses stronger rendering.
    const fn strength(self) -> u8 {
        match self {
            Self::UnknownWithheldQuarantined => 0,
            Self::PlanningOnly => 1,
            Self::HypothesisCandidate => 2,
            Self::ConflictQualificationRequired => 3,
            Self::QualifiedInference => 4,
            Self::ObservedFact => 5,
            Self::MaterialEffect => 6,
        }
    }

    /// Maximum assertability admitted by one evidence grade.
    pub const fn grade_cap(grade: EvidenceGrade) -> Self {
        match grade {
            EvidenceGrade::Orienting => Self::PlanningOnly,
            EvidenceGrade::Grounded => Self::QualifiedInference,
            EvidenceGrade::Corroborated => Self::ObservedFact,
            EvidenceGrade::ScienceGrade => Self::MaterialEffect,
        }
    }

    /// Maximum assertability admitted by one evidence authority class.
    ///
    /// Heuristic and model-produced readings stay qualified no matter how
    /// complete the surrounding coverage is.
    pub const fn authority_cap(authority: EvidenceAuthority) -> Self {
        match authority {
            EvidenceAuthority::HeuristicStatic | EvidenceAuthority::ModelInterpretation => {
                Self::QualifiedInference
            }
            EvidenceAuthority::SourceIdentity
            | EvidenceAuthority::CompilerLanguage
            | EvidenceAuthority::CompilerDerivedSemantics
            | EvidenceAuthority::DeterministicRuntimeTest => Self::MaterialEffect,
        }
    }

    /// Intersects every ceiling into the strongest renderable assertability.
    ///
    /// Incomplete coverage, an open conflict, and missing proof can only
    /// lower the grade and authority caps; they never raise them.
    pub fn ceiling_for(
        grade: EvidenceGrade,
        authority: EvidenceAuthority,
        coverage_complete: bool,
        conflict_open: bool,
        proof_bound: bool,
    ) -> Self {
        let caps = [
            Self::grade_cap(grade).strength(),
            Self::authority_cap(authority).strength(),
            if coverage_complete {
                Self::MaterialEffect.strength()
            } else {
                Self::HypothesisCandidate.strength()
            },
            if conflict_open {
                Self::ConflictQualificationRequired.strength()
            } else {
                Self::MaterialEffect.strength()
            },
            if proof_bound {
                Self::MaterialEffect.strength()
            } else {
                Self::QualifiedInference.strength()
            },
        ];
        let mut strongest = Self::MaterialEffect.strength();
        for cap in caps {
            if cap < strongest {
                strongest = cap;
            }
        }
        Self::from_strength(strongest)
    }

    const fn from_strength(strength: u8) -> Self {
        match strength {
            0 => Self::UnknownWithheldQuarantined,
            1 => Self::PlanningOnly,
            2 => Self::HypothesisCandidate,
            3 => Self::ConflictQualificationRequired,
            4 => Self::QualifiedInference,
            5 => Self::ObservedFact,
            _ => Self::MaterialEffect,
        }
    }

    /// Validates that a claimed assertability sits at or below its ceilings.
    ///
    /// Planning-only input can never validate a material-effect claim:
    /// planning grants no effect.
    pub fn check(
        claimed: Self,
        grade: EvidenceGrade,
        authority: EvidenceAuthority,
        coverage_complete: bool,
        conflict_open: bool,
        proof_bound: bool,
    ) -> Result<(), ContractError> {
        if claimed == Self::MaterialEffect && grade != EvidenceGrade::ScienceGrade {
            return Err(ContractError::CeilingViolation {
                field: "assertability.grade",
            });
        }
        let ceiling = Self::ceiling_for(
            grade,
            authority,
            coverage_complete,
            conflict_open,
            proof_bound,
        );
        if claimed.strength() > ceiling.strength() {
            return Err(ContractError::CeilingViolation {
                field: "assertability.ceiling",
            });
        }
        Ok(())
    }

    /// Maximum assertability admitted by one support-results slice.
    ///
    /// All-supported support licenses the full ceilings below; partial (or
    /// justified-not-applicable) support caps at qualified inference; any
    /// contradicted, unsupported, unknown, outside-manifest, stale, or
    /// superseded result caps at hypothesis candidate. An empty slice is an
    /// error, never a silent success.
    pub fn support_cap(support: &[SupportResult]) -> Result<Self, ContractError> {
        let mut partial_only = false;
        for result in support {
            match result {
                SupportResult::Supported => {}
                SupportResult::Partial | SupportResult::JustifiedNotApplicable => {
                    partial_only = true;
                }
                SupportResult::Contradicted
                | SupportResult::Unsupported
                | SupportResult::Unknown
                | SupportResult::OutsideManifest
                | SupportResult::Stale
                | SupportResult::Superseded => {
                    return Ok(Self::HypothesisCandidate);
                }
            }
        }
        if support.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "assertability.support",
            });
        }
        if partial_only {
            Ok(Self::QualifiedInference)
        } else {
            Ok(Self::MaterialEffect)
        }
    }

    /// Maximum assertability admitted by one disclosure class.
    ///
    /// Disclosure is a ceiling, never evidence: restricted material never
    /// rises above qualified inference, quarantined material renders only as
    /// quarantined unknown, and open material is unbounded by disclosure.
    pub const fn disclosure_cap(disclosure: DisclosureClass) -> Self {
        match disclosure {
            DisclosureClass::Open => Self::MaterialEffect,
            DisclosureClass::Restricted => Self::QualifiedInference,
            DisclosureClass::Quarantined => Self::UnknownWithheldQuarantined,
        }
    }

    /// Intersects every ceiling — grade, authority, support results, coverage,
    /// conflict, proof, disclosure, and verifier competence — into the
    /// strongest renderable assertability.
    ///
    /// `coverage_complete` must be derived from a terminal receipt over a
    /// complete denominator, never from merely-empty unknowns or conflicts.
    /// A material-effect claim additionally requires a competent verifier over
    /// a current freshness; planning-only input still grants no effect.
    #[allow(clippy::too_many_arguments)]
    pub fn check_closed(
        claimed: Self,
        grade: EvidenceGrade,
        authority: EvidenceAuthority,
        support: &[SupportResult],
        coverage_complete: bool,
        conflict_open: bool,
        proof_bound: bool,
        disclosure: DisclosureClass,
        verifier: Option<&RequiredVerifier>,
    ) -> Result<(), ContractError> {
        Self::check(
            claimed,
            grade,
            authority,
            coverage_complete,
            conflict_open,
            proof_bound,
        )?;
        let support_ceiling = Self::support_cap(support)?;
        if claimed.strength() > support_ceiling.strength() {
            return Err(ContractError::CeilingViolation {
                field: "assertability.support",
            });
        }
        let disclosure_ceiling = Self::disclosure_cap(disclosure);
        if claimed.strength() > disclosure_ceiling.strength() {
            return Err(ContractError::CeilingViolation {
                field: "assertability.disclosure",
            });
        }
        if claimed == Self::MaterialEffect {
            let competent = verifier.is_some_and(RequiredVerifier::is_competent);
            if !competent {
                return Err(ContractError::CeilingViolation {
                    field: "assertability.verifier",
                });
            }
        }
        Ok(())
    }
}
