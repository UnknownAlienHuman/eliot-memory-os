use std::collections::BTreeSet;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContractError, CurationFinding, FindingId, MemberId, ProfileId, ProtectionDecision,
    SourceIdentity, validate_findings,
};

/// Neutral result of structural screening. It carries no kind, family,
/// handler, lifecycle, or canonical action.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EligibilityStatus {
    /// Safe to hand to a later semantic curation owner.
    EligibleForSemanticCuration,
    /// Protected by current owner evidence.
    Protected,
    /// Source member shape is malformed.
    Malformed,
    /// Source is stale or unavailable.
    StaleUnavailable,
    /// Member is outside the requested scope.
    OutsideScope,
    /// Input is partial, truncated, or incomplete.
    IncompleteTruncated,
    /// Unknown protection or structural result blocks eligibility.
    UnknownBlocked,
}

/// Neutral eligibility result for one exact member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Eligibility {
    /// Source binding.
    pub source: SourceIdentity,
    /// Exact member identity.
    pub member_id: MemberId,
    /// Protection result used for fail-closed screening.
    pub protection: ProtectionDecision,
    /// Structural finding identities retained in this decision.
    pub finding_ids: BTreeSet<FindingId>,
    /// Neutral status.
    pub status: EligibilityStatus,
}
impl Eligibility {
    /// Validates that protected or unknown members cannot be eligible.
    pub fn validate(
        &self,
        findings: &[CurationFinding],
        profile_id: &ProfileId,
    ) -> Result<(), ContractError> {
        self.source.validate()?;
        validate_findings(findings, &self.source, profile_id)?;
        if self.status == EligibilityStatus::EligibleForSemanticCuration
            && !matches!(self.protection, ProtectionDecision::Unprotected)
        {
            return Err(ContractError::Reconciliation {
                field: "eligibility.protection",
            });
        }
        if matches!(
            self.protection,
            ProtectionDecision::Protected | ProtectionDecision::Unknown
        ) && self.status == EligibilityStatus::EligibleForSemanticCuration
        {
            return Err(ContractError::Reconciliation {
                field: "eligibility.fail_closed",
            });
        }
        if self.finding_ids.len() > 256 {
            return Err(ContractError::Bound {
                field: "eligibility.finding_ids",
            });
        }
        let finding_ids: BTreeSet<_> = findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect();
        if !self.finding_ids.is_subset(&finding_ids) {
            return Err(ContractError::BindingMismatch {
                field: "eligibility.findings",
            });
        }
        for finding_id in &self.finding_ids {
            if findings
                .iter()
                .find(|finding| finding.finding_id == *finding_id)
                .is_none_or(|finding| finding.member_id != self.member_id)
            {
                return Err(ContractError::BindingMismatch {
                    field: "eligibility.finding_member",
                });
            }
        }
        Ok(())
    }
}
