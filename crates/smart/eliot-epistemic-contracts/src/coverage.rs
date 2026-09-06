//! Coverage denominator: the finite, exact, owned scope of an inquiry.
//!
//! A denominator declares exactly what was searched: the member class with
//! schema and revision, the scope and fence, the members or roles (or a typed
//! query/frontier specification standing in for explicit enumeration), the
//! snapshot and its owner, the exclusions with reasons, the pagination bounds,
//! and the validity window. Vague denominators such as an unbounded
//! "all relevant" scope, and unowned empty enumerations, are rejected: an
//! empty answer over an undeclared scope proves nothing.
//!
//! Only [`DenominatorKind::CompleteScope`] can ground a scoped absence claim;
//! sampled or unknown denominators stay honest partial results.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, SourceId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_MEMBERS, MAX_SHORT_TEXT, shape_digest, validate_bounded_text,
    validate_digest,
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

impl DenominatorKind {
    /// Returns the exact frozen wire name of this denominator kind.
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::CompleteScope => "COMPLETE_SCOPE",
            Self::SampledWithMethod => "SAMPLED_WITH_METHOD",
            Self::Unknown => "UNKNOWN",
        }
    }
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

impl QuerySpec {
    /// Constructs a query specification after validation.
    pub fn new(
        query_text: impl Into<String>,
        query_revision: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let spec = Self {
            query_text: query_text.into(),
            query_revision: query_revision.into(),
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validates the query text and revision.
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

impl FrontierSpec {
    /// Constructs a frontier specification after validation.
    pub fn new(
        frontier_id: impl Into<String>,
        frontier_revision: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let spec = Self {
            frontier_id: frontier_id.into(),
            frontier_revision: frontier_revision.into(),
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Validates the frontier identity and revision.
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
    /// Constructs a snapshot reference after validation.
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
///
/// Exclusions form a meaningful sequence: declaration order is preserved on
/// the wire so reviewers read them as written. Order never affects the digest
/// beyond byte identity; membership semantics come from the excluded handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExclusionRecord {
    /// Excluded member, class, or coordinate in exact form.
    pub excluded: String,
    /// Bounded reason for the exclusion.
    pub reason: String,
}

impl ExclusionRecord {
    /// Constructs an exclusion record after validation.
    pub fn new(
        excluded: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, ContractError> {
        let record = Self {
            excluded: excluded.into(),
            reason: reason.into(),
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates the excluded coordinate and its reason.
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
    /// Constructs pagination bounds after validation.
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

impl CoverageDenominator {
    /// Constructs a denominator and freezes its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        class: impl Into<String>,
        schema: impl Into<String>,
        revision: impl Into<String>,
        scope: impl Into<String>,
        fence: StateFence,
        members: BTreeSet<ArtifactId>,
        roles: BTreeSet<String>,
        query: Option<QuerySpec>,
        frontier: Option<FrontierSpec>,
        snapshot: SnapshotRef,
        exclusions: Vec<ExclusionRecord>,
        bounds: PaginationBounds,
        validity: ValidityBounds,
        kind: DenominatorKind,
    ) -> Result<Self, ContractError> {
        let mut denominator = Self {
            class: class.into(),
            schema: schema.into(),
            revision: revision.into(),
            scope: scope.into(),
            fence,
            members,
            roles,
            query,
            frontier,
            snapshot,
            exclusions,
            bounds,
            validity,
            kind,
            digest: String::new(),
        };
        denominator.validate_shape()?;
        denominator.digest = denominator.compute_digest()?;
        Ok(denominator)
    }

    /// Recomputes the canonical digest of the denominator shape.
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
        if self.members.is_empty() && self.query.is_none() {
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

    /// Validates the denominator shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        validate_digest(&self.digest, "coverage.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "coverage.digest",
            });
        }
        Ok(())
    }
}
