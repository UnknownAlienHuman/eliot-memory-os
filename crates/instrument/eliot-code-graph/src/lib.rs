//! Durable ownership of derived code-relationship graph projections.
//!
//! The owner is deliberately narrower than a parser or semantic authority. It
//! validates adapter output, assigns one monotonic publication revision, keeps
//! one published view per source scope, and answers bounded queries against that
//! view. Persistence is a rebuildable projection: corruption or an interrupted
//! publication is reported rather than turned into an empty, confident answer.

#![forbid(unsafe_code)]

use eliot_graph_api::{
    GraphContractError, GraphCoordinate, GraphCoverage, GraphEdge, GraphFreshness, GraphNode,
    GraphQuery, GraphQueryKind, GraphQueryResult, GraphQueryStatus, GraphRevision,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.code-graph";
pub const CONTRACT_VERSION: &str = "1.0.0";
const FORMAT_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum CodeGraphError {
    #[error("graph contract rejected input: {0}")]
    Contract(#[from] GraphContractError),
    #[error("scope must be non-blank")]
    InvalidScope,
    #[error("query revision {expected} does not match published revision {actual}")]
    RevisionMismatch { expected: u64, actual: u64 },
    #[error("graph revision exhausted")]
    RevisionExhausted,
    #[error("durable graph I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("durable graph encoding failed: {0}")]
    Codec(#[from] serde_json::Error),
    #[error("durable graph state is corrupt: {0}")]
    CorruptState(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PersistedState {
    format_version: u32,
    next_revision: u64,
    projections: BTreeMap<String, GraphQueryResult>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PersistedEnvelope {
    state: PersistedState,
    state_digest: String,
}

/// The immutable result of one accepted publication.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GraphPublicationReceipt {
    pub scope: String,
    pub revision: GraphRevision,
    pub projection_digest: String,
}

/// A durable owner for derived code graph projections.
pub struct CodeGraphOwner {
    path: Option<PathBuf>,
    state: PersistedState,
}

/// Compatibility name for callers that describe the owner as a store.
pub type CodeGraphStore = CodeGraphOwner;
/// Compatibility name used by instrument composition code.
pub type DurableCodeGraph = CodeGraphOwner;

impl CodeGraphOwner {
    /// Creates an empty, non-persisted owner.
    pub fn new() -> Self {
        Self {
            path: None,
            state: PersistedState {
                format_version: FORMAT_VERSION,
                next_revision: 1,
                projections: BTreeMap::new(),
            },
        }
    }

    /// Opens a durable owner, creating its file with an empty state if absent.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, CodeGraphError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            let mut owner = Self::new();
            owner.path = Some(path);
            owner.persist()?;
            return Ok(owner);
        }
        let bytes = fs::read(&path)?;
        let envelope: PersistedEnvelope = serde_json::from_slice(&bytes)?;
        validate_envelope(&envelope)?;
        Ok(Self {
            path: Some(path),
            state: envelope.state,
        })
    }

    /// Returns an in-memory owner whose future publications are not persisted.
    pub fn in_memory() -> Self {
        Self::new()
    }

    /// Returns the latest published revision, or revision one for an empty owner.
    pub fn revision(&self) -> GraphRevision {
        GraphRevision::new(self.state.next_revision.saturating_sub(1))
            .unwrap_or_else(|_| GraphRevision::new(1).unwrap_or_default())
    }

    /// Returns the exact published projection for a scope.
    pub fn projection(&self, scope: &str) -> Option<&GraphQueryResult> {
        self.state.projections.get(scope)
    }

    /// Publishes a complete replacement for one source scope.
    pub fn publish(
        &mut self,
        scope: impl Into<String>,
        mut result: GraphQueryResult,
    ) -> Result<GraphPublicationReceipt, CodeGraphError> {
        let scope = scope.into();
        validate_scope(&scope)?;
        result.validate()?;
        let revision = GraphRevision::new(self.state.next_revision)
            .map_err(|_| CodeGraphError::RevisionExhausted)?;
        result.revision = revision;
        let digest = digest(&result)?;
        let old_next_revision = self.state.next_revision;
        let previous = self.state.projections.insert(scope.clone(), result);
        self.state.next_revision = self
            .state
            .next_revision
            .checked_add(1)
            .ok_or(CodeGraphError::RevisionExhausted)?;
        if let Err(error) = self.persist() {
            if let Some(old) = previous {
                self.state.projections.insert(scope, old);
            } else {
                self.state.projections.remove(&scope);
            }
            self.state.next_revision = old_next_revision;
            return Err(error);
        }
        Ok(GraphPublicationReceipt {
            scope,
            revision,
            projection_digest: digest,
        })
    }

    /// Removes one projection and durably publishes the resulting view.
    pub fn remove(&mut self, scope: &str) -> Result<bool, CodeGraphError> {
        validate_scope(scope)?;
        let removed = self.state.projections.remove(scope).is_some();
        if removed {
            self.state.next_revision = self
                .state
                .next_revision
                .checked_add(1)
                .ok_or(CodeGraphError::RevisionExhausted)?;
            self.persist()?;
        }
        Ok(removed)
    }

    /// Answers a bounded query without treating an empty or stale view as absence.
    pub fn query(&self, query: &GraphQuery) -> Result<GraphQueryResult, CodeGraphError> {
        query.validate()?;
        let current = self.revision();
        if let Some(expected) = query.expected_revision {
            if expected != current {
                return Err(CodeGraphError::RevisionMismatch {
                    expected: expected.value(),
                    actual: current.value(),
                });
            }
        }
        let projections = self
            .state
            .projections
            .iter()
            .filter(|(scope, _)| scope_matches(scope, &query.scope));
        let mut nodes = BTreeMap::new();
        let mut edges = BTreeMap::new();
        let mut freshness = GraphFreshness::Current;
        let mut coverage = GraphCoverage::Complete;
        let mut inspected = 0_u64;
        for (_, projection) in projections {
            inspected = inspected.saturating_add(
                projection
                    .nodes
                    .len()
                    .saturating_add(projection.edges.len()) as u64,
            );
            freshness = combine_freshness(freshness, projection.freshness);
            coverage = combine_coverage(coverage, projection.coverage);
            for node in &projection.nodes {
                if node_matches(node, query) {
                    nodes.insert(node.coordinate.to_string(), node.clone());
                }
            }
            for edge in &projection.edges {
                if edge_matches(edge, query) {
                    let key = format!("{}|{}|{}", edge.from, edge.relation, edge.to);
                    edges.insert(key, edge.clone());
                }
            }
        }
        let mut result = GraphQueryResult {
            query_id: query.query_id.clone(),
            status: if nodes.is_empty() && edges.is_empty() {
                if inspected == 0 {
                    GraphQueryStatus::Unknown
                } else if matches!(freshness, GraphFreshness::Current)
                    && matches!(coverage, GraphCoverage::Complete)
                {
                    GraphQueryStatus::NotFound
                } else {
                    GraphQueryStatus::Partial
                }
            } else if matches!(freshness, GraphFreshness::Current)
                && matches!(coverage, GraphCoverage::Complete)
            {
                GraphQueryStatus::Found
            } else {
                GraphQueryStatus::Partial
            },
            revision: current,
            freshness,
            coverage,
            nodes: nodes.into_values().collect(),
            edges: edges.into_values().collect(),
            absence: None,
            diagnostics: Vec::new(),
        };
        if matches!(result.status, GraphQueryStatus::NotFound) {
            result.absence = Some(eliot_graph_api::AbsenceEvidence {
                checked_scope: query.scope.clone(),
                inspected_records: inspected,
                query_digest: GraphQueryResult::query_digest(query)?,
                checked_revision: current,
            });
        }
        Ok(result)
    }

    fn persist(&self) -> Result<(), CodeGraphError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let state_bytes = serde_json::to_vec(&self.state)?;
        let envelope = PersistedEnvelope {
            state: self.state.clone(),
            state_digest: hex_digest(&state_bytes),
        };
        let bytes = serde_json::to_vec_pretty(&envelope)?;
        atomic_write(path, &bytes)
    }
}

impl Default for CodeGraphOwner {
    fn default() -> Self {
        Self::new()
    }
}

fn validate_scope(scope: &str) -> Result<(), CodeGraphError> {
    if scope.trim().is_empty() || scope.chars().any(char::is_control) {
        Err(CodeGraphError::InvalidScope)
    } else {
        Ok(())
    }
}

fn scope_matches(candidate: &str, requested: &str) -> bool {
    candidate == requested
        || requested == "*"
        || candidate.starts_with(&(requested.to_owned() + "/"))
}

fn node_matches(node: &GraphNode, query: &GraphQuery) -> bool {
    match query.kind {
        GraphQueryKind::Exact => query
            .root
            .as_ref()
            .is_some_and(|root| root == &node.coordinate),
        GraphQueryKind::Search | GraphQueryKind::Impact => {
            text_matches(&node.coordinate, &query.expression)
        }
    }
}

fn edge_matches(edge: &GraphEdge, query: &GraphQuery) -> bool {
    match query.kind {
        GraphQueryKind::Impact => query
            .root
            .as_ref()
            .is_some_and(|root| &edge.from == root || &edge.to == root),
        GraphQueryKind::Exact => query
            .root
            .as_ref()
            .is_some_and(|root| &edge.from == root || &edge.to == root),
        GraphQueryKind::Search => {
            edge.relation.contains(&query.expression)
                || text_matches(&edge.from, &query.expression)
                || text_matches(&edge.to, &query.expression)
        }
    }
}

fn text_matches(coordinate: &GraphCoordinate, expression: &str) -> bool {
    coordinate.package.contains(expression)
        || coordinate
            .path
            .as_deref()
            .is_some_and(|value| value.contains(expression))
        || coordinate
            .symbol
            .as_deref()
            .is_some_and(|value| value.contains(expression))
}

fn combine_freshness(left: GraphFreshness, right: GraphFreshness) -> GraphFreshness {
    if left == GraphFreshness::Unavailable || right == GraphFreshness::Unavailable {
        GraphFreshness::Unavailable
    } else if left == GraphFreshness::Unknown || right == GraphFreshness::Unknown {
        GraphFreshness::Unknown
    } else if left == GraphFreshness::Stale || right == GraphFreshness::Stale {
        GraphFreshness::Stale
    } else {
        GraphFreshness::Current
    }
}

fn combine_coverage(left: GraphCoverage, right: GraphCoverage) -> GraphCoverage {
    if left == GraphCoverage::Unknown || right == GraphCoverage::Unknown {
        GraphCoverage::Unknown
    } else if left == GraphCoverage::Partial || right == GraphCoverage::Partial {
        GraphCoverage::Partial
    } else {
        GraphCoverage::Complete
    }
}

fn digest(result: &GraphQueryResult) -> Result<String, CodeGraphError> {
    Ok(hex_digest(&serde_json::to_vec(result)?))
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn validate_envelope(envelope: &PersistedEnvelope) -> Result<(), CodeGraphError> {
    if envelope.state.format_version != FORMAT_VERSION {
        return Err(CodeGraphError::CorruptState(
            "unsupported format version".to_owned(),
        ));
    }
    let bytes = serde_json::to_vec(&envelope.state)?;
    if envelope.state_digest != hex_digest(&bytes) {
        return Err(CodeGraphError::CorruptState(
            "state digest mismatch".to_owned(),
        ));
    }
    if envelope.state.next_revision == 0 {
        return Err(CodeGraphError::CorruptState(
            "revision head is zero".to_owned(),
        ));
    }
    for (scope, projection) in &envelope.state.projections {
        validate_scope(scope)?;
        projection.validate()?;
    }
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CodeGraphError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let temp = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    replace_file(&temp, path)
}

fn replace_file(temp: &Path, destination: &Path) -> Result<(), CodeGraphError> {
    if destination.exists() {
        let backup = destination.with_extension(format!("bak-{}", std::process::id()));
        let _ = fs::remove_file(&backup);
        fs::rename(destination, &backup)?;
        if let Err(error) = fs::rename(temp, destination) {
            let _ = fs::rename(&backup, destination);
            let _ = fs::remove_file(temp);
            return Err(error.into());
        }
        fs::remove_file(backup)?;
    } else {
        fs::rename(temp, destination)?;
    }
    if let Ok(file) = File::open(destination) {
        let _ = file.sync_all();
    }
    Ok(())
}
