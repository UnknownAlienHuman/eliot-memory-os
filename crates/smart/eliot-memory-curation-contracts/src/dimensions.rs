use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContractError, FindingClass, FindingId, MemberDisposition, MemberId};

/// Five independent curation dimensions.
///
/// Each dimension is assessed from its own closed signal family and no
/// dimension may substitute for another: a `Clear` outcome in one dimension
/// can never compensate a `Flagged`, `Protected`, or `Unknown` outcome in a
/// different dimension. No scalar confidence, utility, popularity, retrieval
/// count, or model agreement participates in any dimension.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CurationDimension {
    /// The member projection exists and is structurally intact.
    Existence,
    /// Owner provenance and corroboration support the member.
    Support,
    /// No lifecycle transition is proposed or executed by a screen.
    Lifecycle,
    /// The member may be retained as downstream evidence or reference.
    Accessibility,
    /// The member may influence a later semantic curation decision.
    PermittedInfluence,
}

impl CurationDimension {
    /// All five dimensions in canonical assessment order.
    pub const ALL: [Self; 5] = [
        Self::Existence,
        Self::Support,
        Self::Lifecycle,
        Self::Accessibility,
        Self::PermittedInfluence,
    ];
}

impl FindingClass {
    /// Returns the single dimension that owns this structural finding class.
    ///
    /// Structural findings never touch [`CurationDimension::Lifecycle`] or
    /// [`CurationDimension::Accessibility`]: lifecycle candidacy is assessed
    /// from the owner-selected target/reference partition, and accessibility
    /// is assessed from owner protection evidence. Richer owner evidence
    /// remains an explicit gap rather than an inferred signal.
    #[must_use]
    pub const fn dimension(self) -> CurationDimension {
        match self {
            Self::MalformedIncomplete | Self::Unprocessed | Self::BoundedOut => {
                CurationDimension::Existence
            }
            Self::ProtectionGap => CurationDimension::PermittedInfluence,
            Self::Duplicate
            | Self::StaleSuperseded
            | Self::ProvenanceGap
            | Self::ConflictAmbiguity => CurationDimension::Support,
        }
    }
}

/// Closed per-dimension screening outcome. It carries no scalar, score, kind,
/// family, handler, lifecycle transition, or canonical action.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DimensionOutcome {
    /// No finding and no protection blocks this dimension.
    Clear,
    /// A structural finding was observed in this dimension.
    Flagged,
    /// Owner evidence protects the member in this dimension.
    Protected,
    /// Missing, stale, or unknown evidence blocks a safe conclusion.
    Unknown,
    /// The member is retained only as an immutable reference in this dimension.
    Reference,
}

/// One dimension verdict for one exact member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DimensionVerdict {
    /// Dimension assessed by this verdict.
    pub dimension: CurationDimension,
    /// Closed outcome for the dimension.
    pub outcome: DimensionOutcome,
    /// Findings observed in exactly this dimension.
    pub finding_ids: BTreeSet<FindingId>,
}

impl DimensionVerdict {
    /// Validates that only a flagged dimension retains finding identities.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.finding_ids.len() > 256 {
            return Err(ContractError::Bound {
                field: "dimension.finding_ids",
            });
        }
        let flagged = self.outcome == DimensionOutcome::Flagged;
        if flagged == self.finding_ids.is_empty() {
            return Err(ContractError::Reconciliation {
                field: "dimension.findings",
            });
        }
        Ok(())
    }
}

/// Five explicit dimension verdicts for one exact member.
///
/// The aggregate [`MemberDisposition`] is always derived from these verdicts
/// with no cross-subsidy between dimensions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberDimensions {
    /// Exact member identity.
    pub member_id: MemberId,
    /// Exactly one verdict per dimension.
    pub verdicts: Vec<DimensionVerdict>,
}

impl MemberDimensions {
    /// Returns the verdict for one dimension, if present.
    #[must_use]
    pub fn verdict(&self, dimension: CurationDimension) -> Option<&DimensionVerdict> {
        self.verdicts
            .iter()
            .find(|verdict| verdict.dimension == dimension)
    }

    /// Derives the single aggregate disposition with no cross-subsidy.
    ///
    /// A reference verdict in any dimension keeps the member as an immutable
    /// reference; otherwise any protection wins over any structural block, and
    /// any flagged or unknown dimension blocks eligibility. Only five clear
    /// dimensions yield [`MemberDisposition::Eligible`].
    pub fn derive_disposition(&self) -> Result<MemberDisposition, ContractError> {
        self.validate()?;
        let mut outcomes = BTreeSet::new();
        for verdict in &self.verdicts {
            outcomes.insert(verdict.outcome);
        }
        if outcomes.contains(&DimensionOutcome::Reference) {
            return Ok(MemberDisposition::PreservedReference);
        }
        if outcomes.contains(&DimensionOutcome::Protected) {
            return Ok(MemberDisposition::Protected);
        }
        if outcomes.contains(&DimensionOutcome::Flagged)
            || outcomes.contains(&DimensionOutcome::Unknown)
        {
            return Ok(MemberDisposition::Blocked);
        }
        Ok(MemberDisposition::Eligible)
    }

    /// Validates dimension completeness, uniqueness, and finding ownership.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.verdicts.len() != CurationDimension::ALL.len() {
            return Err(ContractError::Reconciliation {
                field: "dimensions.count",
            });
        }
        let mut dimensions = BTreeSet::new();
        let mut findings = BTreeSet::new();
        for verdict in &self.verdicts {
            verdict.validate()?;
            if !dimensions.insert(verdict.dimension) {
                return Err(ContractError::Duplicate {
                    field: "dimensions.dimension",
                });
            }
            for finding_id in &verdict.finding_ids {
                if !findings.insert(finding_id.clone()) {
                    return Err(ContractError::Duplicate {
                        field: "dimensions.findings",
                    });
                }
            }
        }
        Ok(())
    }
}
