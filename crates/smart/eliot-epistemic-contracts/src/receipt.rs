//! Coverage receipt: exactly one disposition per enumerated member.
//!
//! A [`CoverageReceipt`] binds query, frontier, denominator, task, scope, fence, policy, groups, omissions,
//! and proof of one frozen enumeration. Duplicate members are rejected and member-plus-omission arithmetic
//! must equal the denominator size.
use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_contracts::{StateFence, TaskId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::coverage::{CoverageDenominator, FrontierSpec, QuerySpec};
use crate::error::{
    ContractError, MAX_HANDLES, MAX_MEMBERS, MAX_SHORT_TEXT, check_frozen, shape_digest,
    validate_bounded_text, validate_digest,
};

/// What the enumeration observed for one member: mutually exclusive outcomes, not a ladder. `EXHAUSTION`
/// records that a budget ended the route, and never decodes as completeness.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemberDisposition {
    /// The member was observed in the frozen scope.
    Observed,
    /// The member is authoritatively absent from the frozen scope.
    AuthoritativeAbsence,
    /// The member could not be read; the gap stays explicit.
    Unavailable,
    /// The member was blocked by policy or scope fencing.
    Blocked,
    /// The member's capture is past its freshness boundary.
    Stale,
    /// The member failed shape validation; bytes are preserved elsewhere.
    Malformed,
    /// The member lies outside the frozen scope.
    OutOfScope,
    /// The member was omitted under an explicit, permitted reason.
    PermittedOmission,
    /// The route budget was exhausted before the member was reached.
    Exhaustion,
    /// The member duplicates an enumerated member and adds no coverage.
    DependentDuplicate,
    /// The member outcome cannot be established.
    Unknown,
}
impl MemberDisposition {
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Observed => "OBSERVED",
            Self::AuthoritativeAbsence => "AUTHORITATIVE_ABSENCE",
            Self::Unavailable => "UNAVAILABLE",
            Self::Blocked => "BLOCKED",
            Self::Stale => "STALE",
            Self::Malformed => "MALFORMED",
            Self::OutOfScope => "OUT_OF_SCOPE",
            Self::PermittedOmission => "PERMITTED_OMISSION",
            Self::Exhaustion => "EXHAUSTION",
            Self::DependentDuplicate => "DEPENDENT_DUPLICATE",
            Self::Unknown => "UNKNOWN",
        }
    }
    /// Returns whether this disposition is terminal: only observed presence and authoritative absence close.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Observed | Self::AuthoritativeAbsence)
    }
}

/// Exactly one disposition for one enumerated member under one admitted role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberOutcome {
    /// Enumerated member identity (same `ArtifactId` as the denominator members, no parallel owner).
    pub member: ArtifactId,
    /// Role the member was enumerated under (same role-name spelling as the denominator roles).
    pub role: String,
    /// The single disposition recorded for this member under this role.
    pub disposition: MemberDisposition,
}
impl MemberOutcome {
    /// Constructs a member outcome after validating its role binding.
    pub fn new(
        member: ArtifactId,
        role: impl Into<String>,
        disposition: MemberDisposition,
    ) -> Result<Self, ContractError> {
        let outcome = Self {
            member,
            role: role.into(),
            disposition,
        };
        outcome.validate()?;
        Ok(outcome)
    }
    /// Validates the role binding; the disposition vocabulary is closed by type.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.role, "receipt.role", MAX_SHORT_TEXT)
    }
}

/// One permitted omission with its bounded reason, in declaration order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OmittedMember {
    /// Omitted member identity.
    pub member: ArtifactId,
    /// Bounded reason the omission is permitted.
    pub reason: String,
}
impl OmittedMember {
    pub fn new(member: ArtifactId, reason: impl Into<String>) -> Result<Self, ContractError> {
        let omission = Self {
            member,
            reason: reason.into(),
        };
        omission.validate()?;
        Ok(omission)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.reason, "receipt.omission_reason", MAX_SHORT_TEXT)?;
        Ok(())
    }
}

/// The frozen receipt of one coverage enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageReceipt {
    /// Query executed against the frozen scope.
    pub query: QuerySpec,
    /// Frontier the enumeration traversed.
    pub frontier: FrontierSpec,
    /// Canonical digest of the denominator this receipt reports on.
    pub denominator: String,
    /// Size of the frozen denominator.
    pub denominator_size: u64,
    /// Task binding of the inquiry.
    pub task_id: TaskId,
    /// Scope the enumeration covered.
    pub scope: String,
    /// Fence the enumeration was frozen under.
    pub fence: StateFence,
    /// Policy revision admitting the enumeration, in exact form.
    pub policy: String,
    /// Dependence groups consulted; order carries no meaning.
    pub groups: BTreeSet<String>,
    /// One outcome per enumerated member, in declaration order.
    pub members: Vec<MemberOutcome>,
    /// Permitted omissions, in declaration order.
    pub omissions: Vec<OmittedMember>,
    /// Digest of the bounded proof payload behind this receipt.
    pub proof_digest: String,
    /// Canonical digest of the receipt shape, excluding this field.
    pub digest: String,
}
/// Named constructor arguments for [`CoverageReceipt::new`].
/// Named fields block transposition; text uses concrete [`String`].
#[derive(Clone, Debug)]
pub struct CoverageReceiptParams {
    pub query: QuerySpec,
    pub frontier: FrontierSpec,
    pub denominator: String,
    pub denominator_size: u64,
    pub task_id: TaskId,
    pub scope: String,
    pub fence: StateFence,
    pub policy: String,
    pub groups: BTreeSet<String>,
    pub members: Vec<MemberOutcome>,
    pub omissions: Vec<OmittedMember>,
    pub proof_digest: String,
}
impl CoverageReceipt {
    pub fn new(params: CoverageReceiptParams) -> Result<Self, ContractError> {
        let mut receipt = Self {
            query: params.query,
            frontier: params.frontier,
            denominator: params.denominator,
            denominator_size: params.denominator_size,
            task_id: params.task_id,
            scope: params.scope,
            fence: params.fence,
            policy: params.policy,
            groups: params.groups,
            members: params.members,
            omissions: params.omissions,
            proof_digest: params.proof_digest,
            digest: String::new(),
        };
        receipt.validate_shape()?;
        receipt.digest = receipt.compute_digest()?;
        Ok(receipt)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.query,
            &self.frontier,
            &self.denominator,
            &self.denominator_size,
            &self.task_id,
            &self.scope,
            &self.fence,
            &self.policy,
            &self.groups,
            &self.members,
            &self.omissions,
            &self.proof_digest,
        ))
    }
    /// Returns whether every member outcome is terminal.
    pub fn is_terminal(&self) -> bool {
        self.omissions.is_empty()
            && self
                .members
                .iter()
                .all(|outcome| outcome.disposition.is_terminal())
    }
    fn validate_shape(&self) -> Result<(), ContractError> {
        self.query.validate()?;
        self.frontier.validate()?;
        validate_digest(&self.denominator, "receipt.denominator")?;
        if self.denominator_size > MAX_MEMBERS as u64 {
            return Err(ContractError::TooMany {
                field: "receipt.denominator_size",
            });
        }
        validate_bounded_text(&self.scope, "receipt.scope", MAX_SHORT_TEXT)?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "receipt.fence",
            })?;
        validate_bounded_text(&self.policy, "receipt.policy", MAX_SHORT_TEXT)?;
        if self.groups.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "receipt.groups",
            });
        }
        for group in &self.groups {
            validate_bounded_text(group.as_str(), "receipt.groups", MAX_SHORT_TEXT)?;
        }
        if self.members.len() > MAX_MEMBERS {
            return Err(ContractError::TooMany {
                field: "receipt.members",
            });
        }
        if self.omissions.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "receipt.omissions",
            });
        }
        let mut seen_pairs = BTreeSet::new();
        let mut seen_members = BTreeSet::new();
        for outcome in &self.members {
            outcome.validate()?;
            if !seen_pairs.insert((outcome.member.clone(), outcome.role.clone())) {
                return Err(ContractError::Duplicate {
                    field: "receipt.members",
                });
            }
            seen_members.insert(outcome.member.clone());
        }
        for omission in &self.omissions {
            omission.validate()?;
            if !seen_members.insert(omission.member.clone()) {
                return Err(ContractError::Duplicate {
                    field: "receipt.omissions",
                });
            }
        }
        let accounted = (self.members.len() + self.omissions.len()) as u64;
        if accounted != self.denominator_size {
            return Err(ContractError::ArithmeticMismatch {
                field: "receipt.denominator_size",
            });
        }
        validate_digest(&self.proof_digest, "receipt.proof_digest")?;
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "receipt.digest")
    }
}

/// Reconciles member roles against the denominator product: every outcome names an admitted pair,
/// every required pair is present, duplicates fail in shape, and shared members need both pairs.
pub(crate) fn check_member_roles(
    receipt: &CoverageReceipt,
    denominator: &CoverageDenominator,
    field: &'static str,
) -> Result<(), ContractError> {
    let mut seen = BTreeSet::new();
    for outcome in &receipt.members {
        if !denominator.members.contains(&outcome.member) {
            return Err(ContractError::OutsideManifest { field });
        }
        if !denominator.roles.contains(&outcome.role) {
            return Err(ContractError::OutsideManifest { field });
        }
        if !seen.insert((outcome.member.clone(), outcome.role.clone())) {
            return Err(ContractError::Duplicate { field });
        }
    }
    for member in &denominator.members {
        for role in &denominator.roles {
            if !receipt
                .members
                .iter()
                .any(|outcome| &outcome.member == member && &outcome.role == role)
            {
                return Err(ContractError::MissingReference { field });
            }
        }
    }
    Ok(())
}
