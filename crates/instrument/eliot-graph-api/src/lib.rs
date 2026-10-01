//! Store-neutral graph contracts.
//!
//! This crate describes coordinates, immutable projection revisions and query
//! results. It does not build an index, persist graph data, resolve anchors,
//! or grant proof/finish authority. A negative result is qualified only when
//! freshness, coverage, and an explicit absence record are all present.

#![forbid(unsafe_code)]

use std::fmt;

use eliot_contracts::{ContractVersion, RequestId, canonical_json_bytes, sha256_hex};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this contract surface.
pub const CONTRACT_NAME: &str = "eliot.graph.api";
/// Current wire revision of this contract surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Validation failures for graph coordinates and query results.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum GraphContractError {
    /// A required text value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A numeric revision is zero.
    #[error("{field} must be non-zero")]
    InvalidRevision { field: &'static str },
    /// A coordinate has an invalid line/column relationship.
    #[error("invalid graph coordinate: {reason}")]
    InvalidCoordinate { reason: &'static str },
    /// A result shape contradicts its status or evidence dimensions.
    #[error("invalid graph result: {reason}")]
    InvalidResult { reason: &'static str },
    /// A negative result is missing current complete evidence.
    #[error("negative graph result is not qualified by current complete evidence")]
    UnqualifiedNegativeResult,
    /// A contract could not be canonicalized.
    #[error("contract canonicalization failed: {0}")]
    Canonicalization(String),
}

fn validate_text(value: &str, field: &'static str) -> Result<(), GraphContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(GraphContractError::InvalidText { field });
    }
    Ok(())
}

/// Semantic granularity of a graph coordinate.
#[derive(
    Clone, Copy, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CoordinateKind {
    /// Package or crate.
    Package,
    /// Module path.
    Module,
    /// Source file.
    File,
    /// Symbol, function, or type.
    Symbol,
    /// Line/column source anchor.
    Span,
}

/// Store-neutral location in a source/code graph.
#[derive(
    Clone, Debug, Eq, Hash, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct GraphCoordinate {
    /// Graph granularity.
    pub kind: CoordinateKind,
    /// Stable package/crate identity.
    pub package: String,
    /// Workspace-relative path, when applicable.
    pub path: Option<String>,
    /// Fully-qualified symbol/module name, when applicable.
    pub symbol: Option<String>,
    /// One-based source line for a span coordinate.
    pub line: Option<u32>,
    /// One-based source column for a span coordinate.
    pub column: Option<u32>,
}

impl GraphCoordinate {
    /// Creates a package-level coordinate.
    pub fn package(package: impl Into<String>) -> Result<Self, GraphContractError> {
        let package = package.into();
        validate_text(&package, "package")?;
        Ok(Self {
            kind: CoordinateKind::Package,
            package,
            path: None,
            symbol: None,
            line: None,
            column: None,
        })
    }

    /// Validates coordinate identity and span fields.
    pub fn validate(&self) -> Result<(), GraphContractError> {
        validate_text(&self.package, "package")?;
        if let Some(path) = &self.path {
            validate_text(path, "path")?;
        }
        if let Some(symbol) = &self.symbol {
            validate_text(symbol, "symbol")?;
        }
        match self.kind {
            CoordinateKind::Span if self.line.is_none() || self.column.is_none() => {
                return Err(GraphContractError::InvalidCoordinate {
                    reason: "span requires line and column",
                });
            }
            CoordinateKind::Span => {}
            _ if self.column.is_some() => {
                return Err(GraphContractError::InvalidCoordinate {
                    reason: "column is only valid for span coordinates",
                });
            }
            _ => {}
        }
        if self.column == Some(0) || self.line == Some(0) {
            return Err(GraphContractError::InvalidCoordinate {
                reason: "line and column are one-based",
            });
        }
        Ok(())
    }
}

impl fmt::Display for GraphCoordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{:?}", self.package, self.kind)?;
        if let Some(path) = &self.path {
            write!(f, "/{path}")?;
        }
        if let Some(symbol) = &self.symbol {
            write!(f, "::{symbol}")?;
        }
        if let (Some(line), Some(column)) = (self.line, self.column) {
            write!(f, "@{line}:{column}")?;
        }
        Ok(())
    }
}

/// Monotonic identity of one rebuildable graph projection.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    JsonSchema,
    Ord,
    PartialEq,
    PartialOrd,
    Serialize,
    Deserialize,
)]
#[serde(transparent)]
pub struct GraphRevision(u64);

impl GraphRevision {
    /// Creates a non-zero graph revision.
    pub const fn new(value: u64) -> Result<Self, GraphContractError> {
        if value == 0 {
            Err(GraphContractError::InvalidRevision {
                field: "graph_revision",
            })
        } else {
            Ok(Self(value))
        }
    }

    /// Returns the numeric revision.
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Returns the next revision without wrapping.
    pub const fn next(self) -> Result<Self, GraphContractError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(GraphContractError::InvalidRevision {
                field: "graph_revision",
            }),
        }
    }
}

/// Compatibility spelling for the projection version.
pub type GraphVersion = GraphRevision;

/// Freshness of a graph projection relative to source scope.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphFreshness {
    /// Projection is built from the current source revision.
    Current,
    /// Projection is known to lag the source revision.
    Stale,
    /// Freshness cannot be established.
    Unknown,
    /// Projection is unavailable.
    Unavailable,
}

/// Coverage of a graph query scope.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphCoverage {
    /// Complete declared scope.
    Complete,
    /// Partial declared scope.
    Partial,
    /// Coverage cannot be established.
    Unknown,
}

/// Query class understood by graph adapters.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphQueryKind {
    /// Resolve one exact coordinate.
    Exact,
    /// Search a bounded text/name expression.
    Search,
    /// Return relationships from an exact coordinate.
    Impact,
}

/// Store-neutral graph query request.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphQuery {
    /// Idempotent request identity.
    pub query_id: RequestId,
    /// Query class.
    pub kind: GraphQueryKind,
    /// Expression supplied by the caller.
    pub expression: String,
    /// Declared source/workspace scope.
    pub scope: String,
    /// Optional exact root coordinate.
    pub root: Option<GraphCoordinate>,
    /// Revision the caller expects to observe.
    pub expected_revision: Option<GraphRevision>,
}

impl GraphQuery {
    /// Validates the request without executing it.
    pub fn validate(&self) -> Result<(), GraphContractError> {
        validate_text(&self.expression, "expression")?;
        validate_text(&self.scope, "scope")?;
        if let Some(root) = &self.root {
            root.validate()?;
        }
        Ok(())
    }
}

/// Node in a result projection.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphNode {
    /// Stable source coordinate.
    pub coordinate: GraphCoordinate,
    /// Adapter-defined node kind.
    pub kind: String,
    /// Optional display label.
    pub label: Option<String>,
}

impl GraphNode {
    /// Validates the node coordinate and kind.
    pub fn validate(&self) -> Result<(), GraphContractError> {
        self.coordinate.validate()?;
        validate_text(&self.kind, "node.kind")
    }
}

/// Typed relation between two graph coordinates.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphEdge {
    /// Source coordinate.
    pub from: GraphCoordinate,
    /// Destination coordinate.
    pub to: GraphCoordinate,
    /// Stable relation kind.
    pub relation: String,
}

impl GraphEdge {
    /// Validates endpoints and relation identity.
    pub fn validate(&self) -> Result<(), GraphContractError> {
        self.from.validate()?;
        self.to.validate()?;
        validate_text(&self.relation, "edge.relation")
    }
}

/// Whether the admitted instrument contract can prove absence at all.
///
/// I10.8.6 requires "the instrument contract can prove absence" as an
/// independent condition. Successful execution is not that capability: only
/// an instrument whose admitted contract names the queried relation as
/// absence-provable may report absence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstrumentAbsenceCapability {
    /// Identity of the admitted instrument contract.
    pub instrument_contract: String,
    /// Revision of that admitted contract.
    pub contract_revision: GraphRevision,
    /// Relation this contract was admitted to prove absent.
    pub admitted_relation: String,
}

impl InstrumentAbsenceCapability {
    /// Validates the admitted contract identity and relation.
    pub fn validate(&self) -> Result<(), GraphContractError> {
        validate_text(&self.instrument_contract, "capability.instrument_contract")?;
        validate_text(&self.admitted_relation, "capability.admitted_relation")
    }
}

/// How the no-higher-authority-contradiction precondition was established.
///
/// I10.8.6 requires "no higher-authority contradictory evidence exists".
/// Absence of a contradiction is a fact only when a bounded search actually
/// completed; a search that was never run or that did not cover the
/// applicable authorities has not established the precondition.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ContradictionCheck {
    /// A bounded counterevidence search completed over the applicable
    /// authorities and found nothing contradicting.
    CompletedBoundedSearch,
    /// No counterevidence search covered the applicable authorities, so the
    /// precondition is unattested and absence cannot be claimed.
    NotEstablished,
    /// A higher-authority source contradicts the absence; the claim is
    /// contested rather than absent.
    FoundContradiction,
}

/// Explicit evidence required before reporting absence.
///
/// I10.8.6: "Absence is a fact only when all conditions hold: freshness is
/// exact for the candidate and scope; coverage is complete for the queried
/// relation/scope; the instrument contract can prove absence; no
/// higher-authority contradictory evidence exists." All four are recorded
/// here independently and gated together by [`AbsenceEvidence::validate`];
/// three of four is not absence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbsenceEvidence {
    /// Scope exhaustively checked by the adapter.
    pub checked_scope: String,
    /// Number of graph records inspected.
    pub inspected_records: u64,
    /// Digest of the canonical query used for the absence check.
    pub query_digest: String,
    /// Revision at which absence was checked.
    pub checked_revision: GraphRevision,
    /// Admitted instrument contract able to prove absence for the relation.
    pub capability: InstrumentAbsenceCapability,
    /// How the no-higher-authority-contradiction precondition was resolved.
    pub contradiction_check: ContradictionCheck,
}

impl AbsenceEvidence {
    /// Validates the four absence preconditions as an AND-gate.
    ///
    /// I10.8.6: "Absence is a fact only when all conditions hold." Every
    /// precondition is checked; the first unmet one refuses the absence, so
    /// a three-of-four record is never qualified.
    pub fn validate(&self) -> Result<(), GraphContractError> {
        validate_text(&self.checked_scope, "absence.checked_scope")?;
        if self.inspected_records == 0 {
            return Err(GraphContractError::InvalidResult {
                reason: "absence check must inspect at least one record",
            });
        }
        if self.query_digest.len() != 64
            || self
                .query_digest
                .bytes()
                .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(GraphContractError::InvalidResult {
                reason: "absence query digest must be lowercase SHA-256",
            });
        }
        // Precondition: the instrument contract can prove absence.
        self.capability.validate()?;
        if self.capability.contract_revision != self.checked_revision {
            return Err(GraphContractError::UnqualifiedNegativeResult);
        }
        // Precondition: no higher-authority contradictory evidence exists.
        if !matches!(
            self.contradiction_check,
            ContradictionCheck::CompletedBoundedSearch
        ) {
            return Err(GraphContractError::UnqualifiedNegativeResult);
        }
        Ok(())
    }
}

/// Typed unknown reason for a lookup that cannot prove absence.
///
/// I10.8.6: "Otherwise ELIOT returns a typed unknown such as: ..."
/// The reasons stay distinct because "the tool failed" and "the scope was
/// partial" demand different next actions; collapsing them into one generic
/// unknown is how a partial result starts reading as an answer. Each variant
/// names exactly one of the seven reasons that block a sound absence claim.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphUnknownReason {
    /// Freshness is not exact for the candidate and scope.
    UnknownDueToStaleness,
    /// Coverage is not complete for the queried relation/scope.
    NotFoundInPartialIndex,
    /// Configuration or macro coverage excludes the queried scope.
    UnknownDueToCfgOrMacroCoverage,
    /// A worktree overlay splits the queried view.
    UnknownDueToWorktreeOverlay,
    /// Truncation prevents a sound answer.
    UnknownDueToTruncation,
    /// Tool failure prevents a sound answer.
    UnknownDueToToolFailure,
    /// The adapter cannot determine whether the relation is absent.
    UnknownDueToUndeterminableRelation,
}

impl GraphUnknownReason {
    /// Exact contract spelling of this unknown reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownDueToStaleness => "unknown_due_to_staleness",
            Self::NotFoundInPartialIndex => "not_found_in_partial_index",
            Self::UnknownDueToCfgOrMacroCoverage => "unknown_due_to_cfg_or_macro_coverage",
            Self::UnknownDueToWorktreeOverlay => "unknown_due_to_worktree_overlay",
            Self::UnknownDueToTruncation => "unknown_due_to_truncation",
            Self::UnknownDueToToolFailure => "unknown_due_to_tool_failure",
            Self::UnknownDueToUndeterminableRelation => "unknown_due_to_undeterminable_relation",
        }
    }
}

impl fmt::Display for GraphUnknownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Top-level query status retaining unknown/partial outcomes.
///
/// `NotFound` is a capability, not a value: it is only constructible from a
/// resolved [`AbsenceEvidence`] whose four preconditions hold, and every
/// non-absence outcome carries the specific reason it is unknown.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphQueryStatus {
    /// At least one matching node or edge was observed.
    Found,
    /// No match, with qualified absence evidence. Reachable only through
    /// [`GraphQueryResult::proved_absent`].
    NotFound,
    /// Some requested scope was observed but the answer is not complete;
    /// the reason it cannot be an absence is retained.
    Partial(GraphUnknownReason),
    /// Adapter could not answer safely; the blocking reason is retained.
    Unknown(GraphUnknownReason),
    /// Higher-authority evidence contradicts the absence; the claim is
    /// contested rather than absent, and is still not an absence.
    Contradicted,
    /// Graph capability unavailable.
    Unavailable,
}

impl GraphQueryStatus {
    /// Whether this status is a proved absence.
    ///
    /// An unknown or partial outcome is never proof, so this is the only
    /// question a finish/claim path may ask about a negative result.
    #[must_use]
    pub const fn is_absence(self) -> bool {
        matches!(self, Self::NotFound)
    }

    /// The typed unknown blocking an absence claim, when this status is one.
    #[must_use]
    pub const fn unknown_reason(self) -> Option<GraphUnknownReason> {
        match self {
            Self::Partial(reason) | Self::Unknown(reason) => Some(reason),
            Self::Found | Self::NotFound | Self::Contradicted | Self::Unavailable => None,
        }
    }

    /// Whether this status answered the queried relation negatively.
    ///
    /// `NotFound` is a proved absence; `Contradicted` answered the question
    /// and disagreed, which is still not proof of absence. `Partial`,
    /// `Unknown` and `Unavailable` did not answer at all.
    #[must_use]
    pub const fn is_negative_answer(self) -> bool {
        matches!(self, Self::NotFound | Self::Contradicted)
    }
}

/// Revision/freshness/coverage-bound graph query result.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphQueryResult {
    /// Query identity being answered.
    pub query_id: RequestId,
    /// Top-level result status.
    pub status: GraphQueryStatus,
    /// Projection revision used by the adapter.
    pub revision: GraphRevision,
    /// Freshness relative to requested source scope.
    pub freshness: GraphFreshness,
    /// Coverage of the requested scope.
    pub coverage: GraphCoverage,
    /// Matching nodes.
    pub nodes: Vec<GraphNode>,
    /// Matching relations.
    pub edges: Vec<GraphEdge>,
    /// Qualification for a `NOT_FOUND` answer.
    pub absence: Option<AbsenceEvidence>,
    /// Non-authoritative adapter diagnostics.
    pub diagnostics: Vec<String>,
}

/// Facts one adapter established about a lookup, before the absence gate.
///
/// Each field is one of the four I10.8.6 preconditions, resolved by the
/// adapter that owns the relevant join. Nothing here is inferred from whether
/// the lookup returned items: an empty result is an observation, not a
/// coverage measurement.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbsenceResolution {
    /// Freshness of the analyzed view for the queried candidate and scope.
    pub freshness: GraphFreshness,
    /// Coverage of the queried relation and scope.
    pub coverage: GraphCoverage,
    /// Admitted instrument contract able to prove absence for the relation.
    pub capability: Option<InstrumentAbsenceCapability>,
    /// How the no-higher-authority-contradiction precondition resolved.
    pub contradiction_check: ContradictionCheck,
    /// Whether configuration/macro coverage excluded part of the scope.
    pub cfg_or_macro_coverage_limited: bool,
    /// Whether a worktree overlay split the queried view.
    pub worktree_overlay_present: bool,
    /// Whether the adapter's output was truncated.
    pub truncated: bool,
    /// Whether the adapter's execution failed.
    pub tool_failed: bool,
}

impl AbsenceResolution {
    /// Runs the four-precondition AND-gate and returns the status an empty
    /// lookup must carry.
    ///
    /// I10.8.6: "Absence is a fact only when all conditions hold ... Otherwise
    /// ELIOT returns a typed unknown." The four are evaluated in root-cause
    /// order, so the returned unknown names the reason that actually blocks
    /// the claim rather than its symptom: a failed or truncated adapter is
    /// reported as such instead of as staleness, and an instrument that
    /// cannot prove absence at all is reported as undeterminable rather than
    /// as a complete-but-empty index.
    #[must_use]
    pub fn classify_empty_lookup(&self) -> GraphQueryStatus {
        if matches!(
            self.contradiction_check,
            ContradictionCheck::FoundContradiction
        ) {
            return GraphQueryStatus::Contradicted;
        }
        if self.tool_failed {
            return GraphQueryStatus::Unknown(GraphUnknownReason::UnknownDueToToolFailure);
        }
        if self.truncated {
            return GraphQueryStatus::Unknown(GraphUnknownReason::UnknownDueToTruncation);
        }
        // Precondition: the instrument contract can prove absence. An adapter
        // with no admitted capability has not established this, whatever its
        // freshness and coverage say.
        let Some(capability) = &self.capability else {
            return GraphQueryStatus::Unknown(
                GraphUnknownReason::UnknownDueToUndeterminableRelation,
            );
        };
        if self.cfg_or_macro_coverage_limited {
            return GraphQueryStatus::Partial(GraphUnknownReason::UnknownDueToCfgOrMacroCoverage);
        }
        if self.worktree_overlay_present {
            return GraphQueryStatus::Partial(GraphUnknownReason::UnknownDueToWorktreeOverlay);
        }
        if !matches!(self.freshness, GraphFreshness::Current) {
            return GraphQueryStatus::Unknown(GraphUnknownReason::UnknownDueToStaleness);
        }
        if !matches!(self.coverage, GraphCoverage::Complete) {
            return GraphQueryStatus::Partial(GraphUnknownReason::NotFoundInPartialIndex);
        }
        if !matches!(
            self.contradiction_check,
            ContradictionCheck::CompletedBoundedSearch
        ) {
            return GraphQueryStatus::Unknown(
                GraphUnknownReason::UnknownDueToUndeterminableRelation,
            );
        }
        debug_assert!(capability.validate().is_ok());
        GraphQueryStatus::NotFound
    }
}

impl GraphQueryResult {
    /// Validates result shape and guards unqualified negative answers.
    ///
    /// I10.8.6 makes absence an AND-gate over four independent preconditions;
    /// a three-of-four record is refused here, so a lookup that cannot
    /// establish all four cannot produce an absence status at all.
    pub fn validate(&self) -> Result<(), GraphContractError> {
        for node in &self.nodes {
            node.validate()?;
        }
        for edge in &self.edges {
            edge.validate()?;
        }
        if matches!(self.status, GraphQueryStatus::Found)
            && self.nodes.is_empty()
            && self.edges.is_empty()
        {
            return Err(GraphContractError::InvalidResult {
                reason: "FOUND requires at least one node or edge",
            });
        }
        if self.status.is_absence() {
            // Precondition 1: freshness is exact for the candidate and scope.
            // Precondition 2: coverage is complete for the queried
            // relation/scope.
            if !matches!(self.freshness, GraphFreshness::Current)
                || !matches!(self.coverage, GraphCoverage::Complete)
            {
                return Err(GraphContractError::UnqualifiedNegativeResult);
            }
            // Preconditions 3 and 4: the instrument contract can prove
            // absence, and no higher-authority contradictory evidence exists.
            match &self.absence {
                Some(absence) => absence.validate()?,
                None => return Err(GraphContractError::UnqualifiedNegativeResult),
            }
        }
        if !self.status.is_absence() && self.absence.is_some() {
            return Err(GraphContractError::InvalidResult {
                reason: "absence evidence is only valid for NOT_FOUND",
            });
        }
        Ok(())
    }

    /// Returns the typed unknown this result carries, when it is not an
    /// absence. A finish/claim path must consult this rather than treating a
    /// non-absence status as a negative answer.
    #[must_use]
    pub const fn unknown_reason(&self) -> Option<GraphUnknownReason> {
        self.status.unknown_reason()
    }

    /// Computes a stable digest for a canonical query representation.
    pub fn query_digest(query: &GraphQuery) -> Result<String, GraphContractError> {
        canonical_json_bytes(query)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| GraphContractError::Canonicalization(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> GraphQuery {
        GraphQuery {
            query_id: RequestId::new("graph-query-1").unwrap_or_else(|_| unreachable!()),
            kind: GraphQueryKind::Exact,
            expression: "eliot_engine::run".to_owned(),
            scope: "workspace".to_owned(),
            root: Some(GraphCoordinate::package("eliot-engine").unwrap_or_else(|_| unreachable!())),
            expected_revision: Some(GraphRevision::new(3).unwrap_or_else(|_| unreachable!())),
        }
    }

    fn absence(query: &GraphQuery) -> AbsenceEvidence {
        AbsenceEvidence {
            checked_scope: query.scope.clone(),
            inspected_records: 12,
            query_digest: GraphQueryResult::query_digest(query).unwrap_or_else(|_| unreachable!()),
            checked_revision: GraphRevision::new(3).unwrap_or_else(|_| unreachable!()),
            capability: InstrumentAbsenceCapability {
                instrument_contract: "scip-index/v1".to_owned(),
                contract_revision: GraphRevision::new(3).unwrap_or_else(|_| unreachable!()),
                admitted_relation: "references".to_owned(),
            },
            contradiction_check: ContradictionCheck::CompletedBoundedSearch,
        }
    }

    #[test]
    fn coordinate_roundtrip_and_invalid_span() {
        let coordinate = GraphCoordinate {
            kind: CoordinateKind::Span,
            package: "eliot-engine".to_owned(),
            path: Some("src/lib.rs".to_owned()),
            symbol: Some("run".to_owned()),
            line: Some(12),
            column: Some(4),
        };
        assert!(coordinate.validate().is_ok());
        let encoded = serde_json::to_string(&coordinate).unwrap_or_default();
        let decoded: GraphCoordinate =
            serde_json::from_str(&encoded).unwrap_or_else(|_| unreachable!());
        assert_eq!(decoded, coordinate);
        assert!(
            GraphCoordinate {
                line: Some(1),
                column: None,
                ..coordinate
            }
            .validate()
            .is_err()
        );
    }

    #[test]
    fn revision_is_monotonic_and_zero_is_invalid() {
        assert!(GraphRevision::new(0).is_err());
        let revision = GraphRevision::new(4).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            revision.next().unwrap_or_else(|_| unreachable!()).value(),
            5
        );
    }

    #[test]
    fn qualified_negative_result_is_valid() {
        let query = query();
        let result = GraphQueryResult {
            query_id: query.query_id.clone(),
            status: GraphQueryStatus::NotFound,
            revision: GraphRevision::new(3).unwrap_or_else(|_| unreachable!()),
            freshness: GraphFreshness::Current,
            coverage: GraphCoverage::Complete,
            nodes: Vec::new(),
            edges: Vec::new(),
            absence: Some(absence(&query)),
            diagnostics: Vec::new(),
        };
        assert!(result.validate().is_ok());
    }

    #[test]
    fn stale_negative_result_is_rejected() {
        let query = query();
        let result = GraphQueryResult {
            query_id: query.query_id.clone(),
            status: GraphQueryStatus::NotFound,
            revision: GraphRevision::new(2).unwrap_or_else(|_| unreachable!()),
            freshness: GraphFreshness::Stale,
            coverage: GraphCoverage::Complete,
            nodes: Vec::new(),
            edges: Vec::new(),
            absence: Some(absence(&query)),
            diagnostics: vec!["projection behind source".to_owned()],
        };
        assert!(matches!(
            result.validate(),
            Err(GraphContractError::UnqualifiedNegativeResult)
        ));
    }

    #[test]
    fn found_result_rejects_empty_projection() {
        let query = query();
        let result = GraphQueryResult {
            query_id: query.query_id,
            status: GraphQueryStatus::Found,
            revision: GraphRevision::new(3).unwrap_or_else(|_| unreachable!()),
            freshness: GraphFreshness::Current,
            coverage: GraphCoverage::Complete,
            nodes: Vec::new(),
            edges: Vec::new(),
            absence: None,
            diagnostics: Vec::new(),
        };
        assert!(result.validate().is_err());
    }

    #[test]
    fn query_schema_roundtrips_and_rejects_unknown_fields() {
        let request = query();
        request.validate().unwrap_or_else(|_| unreachable!());
        let encoded = serde_json::to_string(&request).unwrap_or_default();
        let decoded: GraphQuery = serde_json::from_str(&encoded).unwrap_or_else(|_| unreachable!());
        assert_eq!(decoded, request);
        let malformed = serde_json::json!({
            "query_id": "graph-query-1", "kind": "EXACT", "expression": "x",
            "scope": "workspace", "root": null, "expected_revision": null, "unknown": true
        });
        assert!(serde_json::from_value::<GraphQuery>(malformed).is_err());
        let schema = schemars::schema_for!(GraphQueryResult);
        assert!(serde_json::to_vec(&schema).is_ok_and(|bytes| !bytes.is_empty()));
    }

    #[test]
    fn graph_edges_are_store_neutral() {
        let from = GraphCoordinate::package("a").unwrap_or_else(|_| unreachable!());
        let to = GraphCoordinate::package("b").unwrap_or_else(|_| unreachable!());
        let result = GraphQueryResult {
            query_id: query().query_id,
            status: GraphQueryStatus::Found,
            revision: GraphRevision::new(3).unwrap_or_else(|_| unreachable!()),
            freshness: GraphFreshness::Current,
            coverage: GraphCoverage::Complete,
            nodes: vec![GraphNode {
                coordinate: from.clone(),
                kind: "package".to_owned(),
                label: Some("a".to_owned()),
            }],
            edges: vec![GraphEdge {
                from,
                to,
                relation: "depends_on".to_owned(),
            }],
            absence: None,
            diagnostics: Vec::new(),
        };
        assert!(result.validate().is_ok());
    }
}
