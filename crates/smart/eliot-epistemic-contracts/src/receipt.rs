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

use crate::coverage::{FrontierSpec, QuerySpec};
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
    /// Returns the exact frozen wire name of this disposition.
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

    /// Returns whether this disposition is terminal for absence reasoning: only observed presence and
    /// authoritative absence close a member; every other disposition keeps the member unresolved.
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Observed | Self::AuthoritativeAbsence)
    }
}

/// Exactly one disposition for one enumerated member.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberOutcome {
    /// Enumerated member identity.
    pub member: ArtifactId,
    /// The single disposition recorded for this member.
    pub disposition: MemberDisposition,
}

impl MemberOutcome {
    /// Constructs a member outcome.
    pub fn new(member: ArtifactId, disposition: MemberDisposition) -> Self {
        Self {
            member,
            disposition,
        }
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
    /// Constructs an omission record after validation.
    pub fn new(member: ArtifactId, reason: impl Into<String>) -> Result<Self, ContractError> {
        let omission = Self {
            member,
            reason: reason.into(),
        };
        omission.validate()?;
        Ok(omission)
    }

    /// Validates the omission reason.
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

impl CoverageReceipt {
    /// Constructs a receipt and freezes its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        query: QuerySpec,
        frontier: FrontierSpec,
        denominator: impl Into<String>,
        denominator_size: u64,
        task_id: TaskId,
        scope: impl Into<String>,
        fence: StateFence,
        policy: impl Into<String>,
        groups: BTreeSet<String>,
        members: Vec<MemberOutcome>,
        omissions: Vec<OmittedMember>,
        proof_digest: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let mut receipt = Self {
            query,
            frontier,
            denominator: denominator.into(),
            denominator_size,
            task_id,
            scope: scope.into(),
            fence,
            policy: policy.into(),
            groups,
            members,
            omissions,
            proof_digest: proof_digest.into(),
            digest: String::new(),
        };
        receipt.validate_shape()?;
        receipt.digest = receipt.compute_digest()?;
        Ok(receipt)
    }

    /// Recomputes the canonical digest of the receipt shape.
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
        let mut seen = BTreeSet::new();
        for outcome in &self.members {
            if !seen.insert(outcome.member.clone()) {
                return Err(ContractError::Duplicate {
                    field: "receipt.members",
                });
            }
        }
        for omission in &self.omissions {
            omission.validate()?;
            if !seen.insert(omission.member.clone()) {
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

    /// Validates the receipt shape, arithmetic, and frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "receipt.digest")
    }
}
