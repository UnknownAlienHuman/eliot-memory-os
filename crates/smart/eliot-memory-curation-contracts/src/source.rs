use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, TaskRevision};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{ContractError, Digest, MemberId, SourceIdentity, unique};

/// Closed kind vocabulary for canonical memory projections.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceMemberKind {
    /// Captured observation.
    Observation,
    /// Governed claim.
    Claim,
    /// Retained experience.
    Experience,
    /// Evidence relation.
    Relation,
}

/// Whether a source projection is complete for its declared scope.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenominatorCoverage {
    /// Every member is known.
    Complete,
    /// More members may exist.
    Partial,
}

/// Finite source denominator, retained even when no members are present.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FiniteDenominator {
    /// Complete or partial scope claim.
    pub coverage: DenominatorCoverage,
    /// Number of members in the declared scope.
    pub total_members: u64,
    /// Exact declared member order when the owner can enumerate the scope.
    pub declared_member_ids: Vec<MemberId>,
}
impl FiniteDenominator {
    /// Validates the declaration without comparing it to an observed page.
    pub fn validate_declared(&self) -> Result<(), ContractError> {
        unique(&self.declared_member_ids, "denominator.declared_member_ids")?;
        if self.total_members < self.declared_member_ids.len() as u64 {
            return Err(ContractError::Reconciliation {
                field: "denominator.total_members",
            });
        }
        if self.coverage == DenominatorCoverage::Complete
            && self.total_members != self.declared_member_ids.len() as u64
        {
            return Err(ContractError::Reconciliation {
                field: "denominator.count",
            });
        }
        Ok(())
    }
    /// Validates finite denominator arithmetic.
    pub fn validate(&self, observed: usize) -> Result<(), ContractError> {
        self.validate_declared()?;
        if self.total_members < observed as u64 {
            return Err(ContractError::Reconciliation {
                field: "denominator.total_members",
            });
        }
        Ok(())
    }
    /// Returns whether this is an authoritative complete scope.
    pub const fn is_complete(&self) -> bool {
        matches!(self.coverage, DenominatorCoverage::Complete)
    }
}

/// Source availability, independent from denominator coverage.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceAvailability {
    /// Source page is usable.
    Available,
    /// Source is explicitly incomplete.
    Partial,
    /// Source could not be read.
    Unavailable,
    /// Source was blocked.
    Blocked,
    /// Source is older than its fence.
    Stale,
    /// Source shape is invalid.
    Malformed,
    /// Availability is not known.
    Unknown,
}

/// Owner-issued references retained on each source member.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberEvidenceRefs {
    /// Immutable provenance/raw-history handles.
    pub provenance: BTreeSet<ArtifactId>,
    /// Owner-issued lifecycle/support/accessibility/influence references.
    pub owner_status: BTreeSet<ArtifactId>,
    /// Protected roles, minority/dissent and counterexample references.
    pub protection: BTreeSet<ArtifactId>,
    /// Conflict sets and negative-memory references.
    pub conflict: BTreeSet<ArtifactId>,
    /// Audit references.
    pub audit: BTreeSet<ArtifactId>,
}

/// One immutable member projection in meaningful source order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceMember {
    /// Stable member identity.
    pub member_id: MemberId,
    /// Canonical record kind.
    pub kind: SourceMemberKind,
    /// Member owner revision.
    pub revision: TaskRevision,
    /// Immutable content digest.
    pub content_digest: Digest,
    /// Owner and provenance evidence handles.
    pub evidence: MemberEvidenceRefs,
}
impl SourceMember {
    /// Validates intrinsic member fields.
    pub fn validate(&self) -> Result<(), ContractError> {
        for set in [
            &self.evidence.provenance,
            &self.evidence.owner_status,
            &self.evidence.protection,
            &self.evidence.conflict,
            &self.evidence.audit,
        ] {
            if set.len() > 256 {
                return Err(ContractError::Bound {
                    field: "member.evidence",
                });
            }
        }
        Ok(())
    }
}

/// Fixed target/reference partition selected with a source request.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberPartition {
    /// Members eligible for later semantic consideration.
    pub changed_targets: BTreeSet<MemberId>,
    /// Members retained only as immutable references.
    pub immutable_references: BTreeSet<MemberId>,
}
impl MemberPartition {
    /// Validates disjointness and exact coverage of declared members.
    pub fn validate(&self, denominator: &FiniteDenominator) -> Result<(), ContractError> {
        if self
            .changed_targets
            .iter()
            .any(|id| self.immutable_references.contains(id))
        {
            return Err(ContractError::Reconciliation {
                field: "partition.disjoint",
            });
        }
        let all: BTreeSet<_> = self
            .changed_targets
            .union(&self.immutable_references)
            .cloned()
            .collect();
        let declared: BTreeSet<_> = denominator.declared_member_ids.iter().cloned().collect();
        if all != declared {
            return Err(ContractError::Reconciliation {
                field: "partition.denominator",
            });
        }
        Ok(())
    }
}

/// Page and frontier metadata retained by the source owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourcePage {
    /// Zero-based page number.
    pub page_number: u64,
    /// Whether another source page may exist.
    pub has_more: bool,
    /// Exact ordered member IDs remaining after this page.
    pub frontier: Vec<MemberId>,
}
impl SourcePage {
    /// Validates page order and frontier identities.
    pub fn validate(&self) -> Result<(), ContractError> {
        unique(&self.frontier, "source.frontier")
    }
}

/// Immutable, finite source snapshot supplied by the canonical owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceSnapshot {
    /// Source/query/snapshot identity.
    pub identity: SourceIdentity,
    /// Complete or partial finite denominator.
    pub denominator: FiniteDenominator,
    /// Immutable target/reference partition.
    pub partition: MemberPartition,
    /// Source availability state.
    pub availability: SourceAvailability,
    /// Members in source order.
    pub members: Vec<SourceMember>,
    /// Page/frontier metadata.
    pub page: SourcePage,
}
impl SourceSnapshot {
    /// Validates all cross-record source bindings.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.identity.validate()?;
        self.denominator.validate(self.members.len())?;
        self.partition.validate(&self.denominator)?;
        self.page.validate()?;
        let mut seen = BTreeSet::new();
        for member in &self.members {
            member.validate()?;
            if !seen.insert(member.member_id.clone()) {
                return Err(ContractError::Duplicate {
                    field: "source.members",
                });
            }
        }
        let observed: Vec<_> = self
            .members
            .iter()
            .map(|member| member.member_id.clone())
            .collect();
        let declared = &self.denominator.declared_member_ids;
        if !declared.starts_with(&observed) {
            return Err(ContractError::Reconciliation {
                field: "source.member_order",
            });
        }
        let expected_frontier = declared.get(observed.len()..).unwrap_or(&[]).to_vec();
        if self.page.frontier != expected_frontier
            || self.page.has_more == expected_frontier.is_empty()
        {
            return Err(ContractError::Reconciliation {
                field: "source.frontier",
            });
        }
        if self.denominator.is_complete() && self.availability != SourceAvailability::Available {
            return Err(ContractError::BindingMismatch {
                field: "source.availability",
            });
        }
        Ok(())
    }
    /// Returns the source member identity set.
    pub fn member_ids(&self) -> BTreeSet<MemberId> {
        self.members
            .iter()
            .map(|member| member.member_id.clone())
            .collect()
    }
}

/// Convenience binding check for records produced against a source.
pub fn source_matches(left: &SourceIdentity, right: &SourceIdentity) -> Result<(), ContractError> {
    if left.product_id != right.product_id
        || left.source_id != right.source_id
        || left.snapshot_id != right.snapshot_id
        || left.query != right.query
        || left.revision != right.revision
        || left.digest != right.digest
        || left.scope != right.scope
        || left.state_fence != right.state_fence
    {
        return Err(ContractError::BindingMismatch {
            field: "source.identity",
        });
    }
    Ok(())
}
