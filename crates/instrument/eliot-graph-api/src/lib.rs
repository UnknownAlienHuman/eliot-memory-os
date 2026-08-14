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

/// Explicit evidence required before reporting absence.
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
}

impl AbsenceEvidence {
    /// Validates explicit absence qualification.
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
        Ok(())
    }
}

/// Top-level query status retaining unknown/partial outcomes.
#[derive(Clone, Copy, Debug, Eq, Hash, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GraphQueryStatus {
    /// At least one matching node or edge was observed.
    Found,
    /// No match, with qualified absence evidence.
    NotFound,
    /// Some requested scope was observed.
    Partial,
    /// Adapter could not answer safely.
    Unknown,
    /// Graph capability unavailable.
    Unavailable,
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

impl GraphQueryResult {
    /// Validates result shape and guards unqualified negative answers.
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
        if matches!(self.status, GraphQueryStatus::NotFound) {
            if !matches!(self.freshness, GraphFreshness::Current)
                || !matches!(self.coverage, GraphCoverage::Complete)
            {
                return Err(GraphContractError::UnqualifiedNegativeResult);
            }
            match &self.absence {
                Some(absence) => absence.validate()?,
                None => return Err(GraphContractError::UnqualifiedNegativeResult),
            }
        }
        if !matches!(self.status, GraphQueryStatus::NotFound) && self.absence.is_some() {
            return Err(GraphContractError::InvalidResult {
                reason: "absence evidence is only valid for NOT_FOUND",
            });
        }
        Ok(())
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
