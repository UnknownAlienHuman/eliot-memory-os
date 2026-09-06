//! Causal claims: mechanism, rivals, confounders, and a limited ceiling.
//!
//! Association, correlation, dependency (precondition or enablement), and
//! mechanism are four separate readings. They serialize to four distinct wire
//! names and never cross-decode: chronological precedence is not correlation,
//! correlation is not a dependency, and none of the three is a causal
//! mechanism. A [`CausalClaim`] earns the mechanism reading only with a named
//! mechanism, preserved rivals and confounders, and non-empty evidence
//! references — and even then its grade ceiling is limited: a lone causal
//! claim never reaches science grade on its own.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ContractError, MAX_HANDLES, MAX_SHORT_TEXT, validate_bounded_text};
use crate::grade::EvidenceGrade;
use crate::identity::PropositionId;

/// Four separate causal readings; declaration order is not a ladder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CausalStatus {
    /// Joint occurrence without a dependence claim.
    Association,
    /// Behavioral co-variation without a dependence claim.
    Correlation,
    /// Precondition or enablement dependence without a mechanism claim.
    DependencyPreconditionEnablement,
    /// Claimed mechanism with rivals and evidence.
    Mechanism,
}

impl CausalStatus {
    /// Returns the exact frozen wire name of this status.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Association => "ASSOCIATION",
            Self::Correlation => "CORRELATION",
            Self::DependencyPreconditionEnablement => "DEPENDENCY_PRECONDITION_ENABLEMENT",
            Self::Mechanism => "MECHANISM",
        }
    }
}

/// One causal claim with its mechanism, rivals, confounders, and evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CausalClaim {
    /// Proposition the causal reading bears on.
    pub subject: PropositionId,
    /// Which of the four readings is claimed.
    pub status: CausalStatus,
    /// Named mechanism; required in full only for the mechanism reading, but
    /// a bounded mechanism sketch is carried for every reading so weaker
    /// readings stay falsifiable.
    pub mechanism: String,
    /// Preserved rival explanations; order carries no meaning.
    pub rivals: BTreeSet<String>,
    /// Preserved confounders and their dispositions; order carries no meaning.
    pub confounders: BTreeSet<String>,
    /// Evidence references behind the reading; order carries no meaning.
    pub evidence_refs: BTreeSet<ArtifactId>,
    /// Grade ceiling of this causal reading; always limited.
    pub ceiling: EvidenceGrade,
    /// Scope the reading applies to.
    pub scope: String,
}

impl CausalClaim {
    /// Constructs a causal claim after validation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        subject: PropositionId,
        status: CausalStatus,
        mechanism: impl Into<String>,
        rivals: BTreeSet<String>,
        confounders: BTreeSet<String>,
        evidence_refs: BTreeSet<ArtifactId>,
        ceiling: EvidenceGrade,
        scope: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let claim = Self {
            subject,
            status,
            mechanism: mechanism.into(),
            rivals,
            confounders,
            evidence_refs,
            ceiling,
            scope: scope.into(),
        };
        claim.validate()?;
        Ok(claim)
    }

    /// Validates mechanism, rivals, confounders, evidence, and the ceiling.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.mechanism, "causal.mechanism", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "causal.scope", MAX_SHORT_TEXT)?;
        if self.rivals.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "causal.rivals",
            });
        }
        if self.rivals.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "causal.rivals",
            });
        }
        for rival in &self.rivals {
            validate_bounded_text(rival.as_str(), "causal.rivals", MAX_SHORT_TEXT)?;
        }
        if self.confounders.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "causal.confounders",
            });
        }
        for confounder in &self.confounders {
            validate_bounded_text(confounder.as_str(), "causal.confounders", MAX_SHORT_TEXT)?;
        }
        if self.evidence_refs.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "causal.evidence_refs",
            });
        }
        if self.evidence_refs.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "causal.evidence_refs",
            });
        }
        if self.ceiling == EvidenceGrade::ScienceGrade {
            return Err(ContractError::CeilingViolation {
                field: "causal.ceiling",
            });
        }
        if matches!(
            self.status,
            CausalStatus::Association | CausalStatus::Correlation
        ) && self.ceiling.rank() > EvidenceGrade::Grounded.rank()
        {
            return Err(ContractError::CeilingViolation {
                field: "causal.ceiling",
            });
        }
        Ok(())
    }
}
