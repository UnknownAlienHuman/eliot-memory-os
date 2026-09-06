//! Coverage denominator: the finite, exact, owned scope of an inquiry.
//!
//! A denominator declares exactly what was searched: member class, schema, scope, fence, members or typed
//! query/frontier, snapshot and owner, exclusions, pagination, and validity. Vague scopes and unowned empties
//! are rejected; the one exception is the known-empty complete case (complete marker plus the query, frontier,
//! and owner snapshot that read the emptiness). Only [`DenominatorKind::CompleteScope`] grounds absence; a
//! complete scope is never truncated and its total equals its member count.
use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, SourceId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_MEMBERS, MAX_SHORT_TEXT, check_frozen, shape_digest,
    validate_bounded_text,
};
use crate::support::ValidityBounds;

/// What the denominator enumerates: full scope, a sampled method, or unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DenominatorKind {
    /// The frozen scope was enumerated completely.
    CompleteScope,
    /// A bounded sample was taken under a declared method.
    SampledWithMethod,
    /// Coverage cannot be established.
    Unknown,
}

/// The typed query standing in for explicit member enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct QuerySpec {
    /// Exact query text executed against the frozen scope.
    pub query_text: String,
    /// Revision of the query definition.
    pub query_revision: String,
}
/// Query revision role (no canonical owner covers query revisions).
pub struct QueryRevision(pub String);
impl QuerySpec {
    pub fn new(
        query_text: impl Into<String>,
        query_revision: QueryRevision,
    ) -> Result<Self, ContractError> {
        let spec = Self {
            query_text: query_text.into(),
            query_revision: query_revision.0,
        };
        spec.validate()?;
        Ok(spec)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.query_text, "coverage.query_text", MAX_SHORT_TEXT)?;
        validate_bounded_text(
            &self.query_revision,
            "coverage.query_revision",
            MAX_SHORT_TEXT,
        )?;
        Ok(())
    }
}

/// The typed retrieval frontier standing in for explicit member enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrontierSpec {
    /// Identity of the frozen retrieval frontier.
    pub frontier_id: String,
    /// Revision of the frozen retrieval frontier.
    pub frontier_revision: String,
}
/// Frontier revision role (same rationale as [`QueryRevision`]).
pub struct FrontierRevision(pub String);
impl FrontierSpec {
    pub fn new(
        frontier_id: impl Into<String>,
        frontier_revision: FrontierRevision,
    ) -> Result<Self, ContractError> {
        let spec = Self {
            frontier_id: frontier_id.into(),
            frontier_revision: frontier_revision.0,
        };
        spec.validate()?;
        Ok(spec)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.frontier_id, "coverage.frontier_id", MAX_SHORT_TEXT)?;
        validate_bounded_text(
            &self.frontier_revision,
            "coverage.frontier_revision",
            MAX_SHORT_TEXT,
        )?;
        Ok(())
    }
}

/// The owned snapshot a denominator was frozen from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SnapshotRef {
    /// Identity of the frozen snapshot.
    pub snapshot_id: String,
    /// Owner that admits the snapshot revision.
    pub owner: SourceId,
}
impl SnapshotRef {
    pub fn new(snapshot_id: impl Into<String>, owner: SourceId) -> Result<Self, ContractError> {
        let snapshot = Self {
            snapshot_id: snapshot_id.into(),
            owner,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }
    /// Validates the snapshot identity; ownership is structural and explicit.
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.snapshot_id, "coverage.snapshot_id", MAX_SHORT_TEXT)?;
        Ok(())
    }
}

/// One declared exclusion with its bounded reason, in declaration order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExclusionRecord {
    /// Excluded member, class, or coordinate in exact form.
    pub excluded: String,
    /// Bounded reason for the exclusion.
    pub reason: String,
}
/// Exclusion reason role (no canonical owner covers exclusion prose).
pub struct ExclusionReason(pub String);
impl ExclusionRecord {
    pub fn new(
        excluded: impl Into<String>,
        reason: ExclusionReason,
    ) -> Result<Self, ContractError> {
        let record = Self {
            excluded: excluded.into(),
            reason: reason.0,
        };
        record.validate()?;
        Ok(record)
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.excluded, "coverage.excluded", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.reason, "coverage.exclusion_reason", MAX_SHORT_TEXT)?;
        Ok(())
    }
}

/// Pagination and truncation bounds of the frozen enumeration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PaginationBounds {
    /// Offset of the first returned member.
    pub offset: u64,
    /// Maximum members returned from the offset.
    pub limit: u64,
    /// Total members of the frozen scope.
    pub total: u64,
    /// Whether the enumeration was truncated before the total.
    pub truncated: bool,
}
impl PaginationBounds {
    pub fn new(
        offset: u64,
        limit: u64,
        total: u64,
        truncated: bool,
    ) -> Result<Self, ContractError> {
        let bounds = Self {
            offset,
            limit,
            total,
            truncated,
        };
        bounds.validate()?;
        Ok(bounds)
    }
    /// Validates that offset and limit reconcile with the total.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.limit == 0 {
            return Err(ContractError::OutOfRange {
                field: "coverage.limit",
            });
        }
        if self.total > MAX_MEMBERS as u64 {
            return Err(ContractError::TooMany {
                field: "coverage.total",
            });
        }
        if self.offset > self.total {
            return Err(ContractError::OutOfRange {
                field: "coverage.offset",
            });
        }
        if !self.truncated && self.offset + self.limit < self.total {
            return Err(ContractError::ArithmeticMismatch {
                field: "coverage.bounds",
            });
        }
        Ok(())
    }
}

/// Spellings that claim coverage without declaring it. Matching is exact on
/// the trimmed, lowercased value: near-miss prose stays reviewable data
/// elsewhere, but a denominator field carrying one of these is rejected.
const VAGUE_DENOMINATOR_TEXTS: [&str; 7] = [
    "all",
    "all-relevant",
    "all relevant",
    "everything",
    "*",
    "relevant",
    "unknown",
];
fn reject_vague(value: &str, field: &'static str) -> Result<(), ContractError> {
    let normalized = value.trim().to_lowercase();
    if VAGUE_DENOMINATOR_TEXTS.contains(&normalized.as_str()) {
        return Err(ContractError::VagueDenominator { field });
    }
    Ok(())
}

/// The finite, exact, owned denominator of one inquiry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CoverageDenominator {
    /// Member class under inquiry, e.g. `source-record`.
    pub class: String,
    /// Schema identity the members were read under.
    pub schema: String,
    /// Schema or source revision the members were read under.
    pub revision: String,
    /// Scope the denominator enumerates.
    pub scope: String,
    /// Fence the denominator was frozen under.
    pub fence: StateFence,
    /// Enumerated members; order carries no meaning.
    pub members: BTreeSet<ArtifactId>,
    /// Member roles admitted by the denominator; order carries no meaning.
    pub roles: BTreeSet<String>,
    /// Typed query standing in for enumeration, when members are not listed.
    pub query: Option<QuerySpec>,
    /// Typed frontier standing in for enumeration, when members are listed by route.
    pub frontier: Option<FrontierSpec>,
    /// Owned snapshot the denominator was frozen from.
    pub snapshot: SnapshotRef,
    /// Declared exclusions in declaration order.
    pub exclusions: Vec<ExclusionRecord>,
    /// Pagination and truncation bounds of the enumeration.
    pub bounds: PaginationBounds,
    /// Scope, time, version, and precision validity of the denominator.
    pub validity: ValidityBounds,
    /// Whether the scope was enumerated completely.
    pub kind: DenominatorKind,
    /// Canonical digest of the denominator shape, excluding this field.
    pub digest: String,
}
/// Named constructor arguments for [`CoverageDenominator::new`].
/// Named fields block transposition; text uses concrete [`String`].
#[derive(Clone, Debug)]
pub struct CoverageDenominatorParams {
    pub class: String,
    pub schema: String,
    pub revision: String,
    pub scope: String,
    pub fence: StateFence,
    pub members: BTreeSet<ArtifactId>,
    pub roles: BTreeSet<String>,
    pub query: Option<QuerySpec>,
    pub frontier: Option<FrontierSpec>,
    pub snapshot: SnapshotRef,
    pub exclusions: Vec<ExclusionRecord>,
    pub bounds: PaginationBounds,
    pub validity: ValidityBounds,
    pub kind: DenominatorKind,
}
impl CoverageDenominator {
    pub fn new(params: CoverageDenominatorParams) -> Result<Self, ContractError> {
        let mut denominator = Self {
            class: params.class,
            schema: params.schema,
            revision: params.revision,
            scope: params.scope,
            fence: params.fence,
            members: params.members,
            roles: params.roles,
            query: params.query,
            frontier: params.frontier,
            snapshot: params.snapshot,
            exclusions: params.exclusions,
            bounds: params.bounds,
            validity: params.validity,
            kind: params.kind,
            digest: String::new(),
        };
        denominator.validate_shape()?;
        denominator.digest = denominator.compute_digest()?;
        Ok(denominator)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.class,
            &self.schema,
            &self.revision,
            &self.scope,
            &self.fence,
            &self.members,
            &self.roles,
            &self.query,
            &self.frontier,
            &self.snapshot,
            &self.exclusions,
            &self.bounds,
            &self.validity,
            &self.kind,
        ))
    }
    fn validate_shape(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.class, "coverage.class", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.schema, "coverage.schema", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.revision, "coverage.revision", MAX_SHORT_TEXT)?;
        validate_bounded_text(&self.scope, "coverage.scope", MAX_SHORT_TEXT)?;
        reject_vague(&self.class, "coverage.class")?;
        reject_vague(&self.scope, "coverage.scope")?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "coverage.fence",
            })?;
        if self.members.len() > MAX_MEMBERS {
            return Err(ContractError::TooMany {
                field: "coverage.members",
            });
        }
        if self.roles.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "coverage.roles",
            });
        }
        for role in &self.roles {
            validate_bounded_text(role.as_str(), "coverage.roles", MAX_SHORT_TEXT)?;
        }
        if self.kind == DenominatorKind::CompleteScope {
            // A complete scope is arithmetically exact: never truncated, total equals member count.
            if self.bounds.truncated {
                return Err(ContractError::IncompleteDenominator {
                    field: "coverage.bounds",
                });
            }
            if self.bounds.total != self.members.len() as u64 {
                return Err(ContractError::ArithmeticMismatch {
                    field: "coverage.bounds",
                });
            }
            if self.members.is_empty() {
                // Known-empty is valid only as an owned, exact, bound empty: complete marker with the
                // query, frontier, and owner snapshot that read the emptiness.
                if self.query.is_none() || self.frontier.is_none() {
                    return Err(ContractError::IncompleteDenominator {
                        field: "coverage.members",
                    });
                }
            }
        } else if self.members.is_empty() && self.query.is_none() {
            return Err(ContractError::IncompleteDenominator {
                field: "coverage.members",
            });
        }
        if let Some(query) = &self.query {
            query.validate()?;
        }
        if let Some(frontier) = &self.frontier {
            frontier.validate()?;
        }
        self.snapshot.validate()?;
        if self.exclusions.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "coverage.exclusions",
            });
        }
        for exclusion in &self.exclusions {
            exclusion.validate()?;
        }
        self.bounds.validate()?;
        self.validity.validate()?;
        if self.validity.scope != self.scope {
            return Err(ContractError::ScopeMismatch {
                field: "coverage.validity",
            });
        }
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "coverage.digest")
    }
}

/// Binds a receipt's frozen query and frontier to the denominator by value
/// (both present, field-equal; a `None`-versus-`Some` pairing fails closed).
pub(crate) fn check_receipt_query_frontier(
    denominator: &CoverageDenominator,
    receipt: &crate::receipt::CoverageReceipt,
    query_field: &'static str,
    frontier_field: &'static str,
) -> Result<(), ContractError> {
    match &denominator.query {
        Some(query) if *query == receipt.query => {}
        Some(_) => {
            return Err(ContractError::DigestMismatch { field: query_field });
        }
        None => {
            return Err(ContractError::IncompleteDenominator { field: query_field });
        }
    }
    match &denominator.frontier {
        Some(frontier) if *frontier == receipt.frontier => {}
        Some(_) => {
            return Err(ContractError::DigestMismatch {
                field: frontier_field,
            });
        }
        None => {
            return Err(ContractError::IncompleteDenominator {
                field: frontier_field,
            });
        }
    }
    Ok(())
}
