//! Evidence-only semantic composition for bounded code understanding.
//!
//! `CodeCortex` deliberately has no parser, process runner, persistence engine,
//! or truth authority.  Adapters admit graph projections and normalized
//! instrument evidence; this crate indexes those immutable observations and
//! composes a task-scoped report while retaining freshness, coverage, and
//! disagreement.

#![forbid(unsafe_code)]

use eliot_graph_api::{
    GraphCoverage, GraphEdge, GraphFreshness, GraphNode, GraphQueryResult, GraphRevision,
};
use eliot_instrument_api::{EvidenceCoverage, EvidenceFreshness, NormalizedEvidence};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.code-cortex";
pub const CONTRACT_VERSION: &str = "1.0.0";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CodeCortexError {
    #[error("task and scope must be non-blank")]
    InvalidScope,
    #[error("maximum records must be non-zero")]
    InvalidLimit,
    #[error("graph result is invalid: {0}")]
    InvalidGraph(String),
    #[error("evidence is invalid: {0}")]
    InvalidEvidence(String),
    #[error("index revision overflow")]
    RevisionOverflow,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CompositionRequest {
    pub task_id: String,
    pub goal: String,
    pub scope: String,
    pub max_relations: usize,
    pub max_nodes: usize,
}

impl CompositionRequest {
    pub fn validate(&self) -> Result<(), CodeCortexError> {
        if self.task_id.trim().is_empty()
            || self.goal.trim().is_empty()
            || self.scope.trim().is_empty()
        {
            return Err(CodeCortexError::InvalidScope);
        }
        if self.max_relations == 0 || self.max_nodes == 0 {
            return Err(CodeCortexError::InvalidLimit);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationAuthority {
    ExactGraph,
    InstrumentObservation,
    Heuristic,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationFreshness {
    Current,
    Stale,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationCoverage {
    Complete,
    Partial,
    NotApplicable,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SemanticRelation {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub authority: RelationAuthority,
    pub freshness: RelationFreshness,
    pub coverage: RelationCoverage,
    pub source_handles: Vec<String>,
    pub dependencies: Vec<String>,
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SemanticAnchor {
    pub handle: String,
    pub label: String,
    pub source_handle: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CoverageGap {
    pub scope: String,
    pub reason: String,
    pub cheapest_probe: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SemanticConflict {
    pub subject: String,
    pub alternatives: Vec<String>,
    pub source_handles: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodeCortexReport {
    pub task_id: String,
    pub goal: String,
    pub scope: String,
    pub index_revision: GraphRevision,
    pub nodes: Vec<GraphNode>,
    pub relations: Vec<SemanticRelation>,
    pub entrypoints: Vec<SemanticAnchor>,
    pub evidence_handles: Vec<String>,
    pub conflicts: Vec<SemanticConflict>,
    pub coverage_gaps: Vec<CoverageGap>,
    pub expansion_handles: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndexSnapshot {
    pub revision: GraphRevision,
    pub graph_results: Vec<GraphQueryResult>,
    pub instrument_evidence: Vec<NormalizedEvidence>,
}

#[derive(Clone, Debug, Default)]
pub struct SemanticIndex {
    revision: u64,
    graphs: BTreeMap<String, GraphQueryResult>,
    evidence: BTreeMap<String, NormalizedEvidence>,
}

impl SemanticIndex {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn revision(&self) -> Result<GraphRevision, CodeCortexError> {
        GraphRevision::new(self.revision.max(1)).map_err(|_| CodeCortexError::RevisionOverflow)
    }

    pub fn admit_graph(
        &mut self,
        result: GraphQueryResult,
    ) -> Result<GraphRevision, CodeCortexError> {
        result
            .validate()
            .map_err(|error| CodeCortexError::InvalidGraph(error.to_string()))?;
        let key = result.query_id.to_string();
        self.graphs.insert(key, result);
        self.bump()
    }

    pub fn admit_evidence(
        &mut self,
        evidence: NormalizedEvidence,
    ) -> Result<GraphRevision, CodeCortexError> {
        evidence
            .validate()
            .map_err(|error| CodeCortexError::InvalidEvidence(error.to_string()))?;
        let key = evidence.evidence_id.to_string();
        self.evidence.insert(key, evidence);
        self.bump()
    }

    pub fn snapshot(&self) -> IndexSnapshot {
        let revision = self
            .revision()
            .unwrap_or_else(|_| GraphRevision::new(1).unwrap_or_default());
        IndexSnapshot {
            revision,
            graph_results: self.graphs.values().cloned().collect(),
            instrument_evidence: self.evidence.values().cloned().collect(),
        }
    }

    fn bump(&mut self) -> Result<GraphRevision, CodeCortexError> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(CodeCortexError::RevisionOverflow)?;
        self.revision()
    }
}

pub struct CodeCortexService {
    index: SemanticIndex,
}

impl CodeCortexService {
    pub fn new(index: SemanticIndex) -> Self {
        Self { index }
    }

    pub fn index(&self) -> &SemanticIndex {
        &self.index
    }

    pub fn index_mut(&mut self) -> &mut SemanticIndex {
        &mut self.index
    }

    pub fn compose(
        &self,
        request: &CompositionRequest,
    ) -> Result<CodeCortexReport, CodeCortexError> {
        request.validate()?;
        compose_snapshot(request, &self.index.snapshot())
    }
}

#[allow(clippy::too_many_lines)]
pub fn compose_snapshot(
    request: &CompositionRequest,
    snapshot: &IndexSnapshot,
) -> Result<CodeCortexReport, CodeCortexError> {
    request.validate()?;
    let mut nodes = BTreeMap::<String, GraphNode>::new();
    let mut relations = BTreeMap::<String, SemanticRelation>::new();
    let mut conflicts = Vec::new();
    let mut gaps = Vec::new();
    let mut handles = BTreeSet::new();

    for result in &snapshot.graph_results {
        let source = result.query_id.to_string();
        handles.insert(source.clone());
        if !matches!(result.freshness, GraphFreshness::Current) {
            gaps.push(CoverageGap {
                scope: request.scope.clone(),
                reason: "graph projection is stale or unknown".to_owned(),
                cheapest_probe: Some(
                    "refresh the graph projection for the exact candidate".to_owned(),
                ),
            });
        }
        if matches!(
            result.coverage,
            GraphCoverage::Partial | GraphCoverage::Unknown
        ) {
            gaps.push(CoverageGap {
                scope: request.scope.clone(),
                reason: "graph coverage is incomplete".to_owned(),
                cheapest_probe: Some("expand the declared graph scope".to_owned()),
            });
        }
        for node in &result.nodes {
            if nodes.len() < request.max_nodes {
                nodes.insert(node.coordinate.to_string(), node.clone());
            }
        }
        for edge in &result.edges {
            if relations.len() >= request.max_relations {
                break;
            }
            add_edge(&mut relations, edge, &source, result, &mut conflicts);
        }
    }

    for evidence in &snapshot.instrument_evidence {
        let source = evidence.evidence_id.to_string();
        handles.insert(source.clone());
        if matches!(
            evidence.freshness,
            EvidenceFreshness::Stale
                | EvidenceFreshness::KnownOlderSnapshot
                | EvidenceFreshness::Unknown
        ) {
            gaps.push(CoverageGap {
                scope: request.scope.clone(),
                reason: "instrument evidence cannot establish current freshness".to_owned(),
                cheapest_probe: Some(
                    "capture the same observation at the current candidate".to_owned(),
                ),
            });
        }
        if matches!(
            evidence.coverage,
            EvidenceCoverage::PartialForScope | EvidenceCoverage::Unknown
        ) {
            gaps.push(CoverageGap {
                scope: request.scope.clone(),
                reason: "instrument evidence covers only part of scope".to_owned(),
                cheapest_probe: Some(
                    "run the owning instrument profile for the missing scope".to_owned(),
                ),
            });
        }
    }

    let entrypoints = nodes
        .values()
        .take(request.max_nodes)
        .map(|node| SemanticAnchor {
            handle: node.coordinate.to_string(),
            label: node.label.clone().unwrap_or_else(|| node.kind.clone()),
            source_handle: node
                .coordinate
                .path
                .clone()
                .unwrap_or_else(|| node.coordinate.package.clone()),
        })
        .collect();
    let expansion_handles = relations
        .values()
        .flat_map(|relation| relation.source_handles.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(CodeCortexReport {
        task_id: request.task_id.clone(),
        goal: request.goal.clone(),
        scope: request.scope.clone(),
        index_revision: snapshot.revision,
        nodes: nodes.into_values().collect(),
        relations: relations.into_values().collect(),
        entrypoints,
        evidence_handles: handles.into_iter().collect(),
        conflicts,
        coverage_gaps: gaps,
        expansion_handles,
    })
}

fn add_edge(
    relations: &mut BTreeMap<String, SemanticRelation>,
    edge: &GraphEdge,
    source: &str,
    result: &GraphQueryResult,
    conflicts: &mut Vec<SemanticConflict>,
) {
    let from = edge.from.to_string();
    let to = edge.to.to_string();
    let key = format!("{from}|{}|{to}", edge.relation);
    let candidate = SemanticRelation {
        from: from.clone(),
        to: to.clone(),
        kind: edge.relation.clone(),
        authority: RelationAuthority::ExactGraph,
        freshness: match result.freshness {
            GraphFreshness::Current => RelationFreshness::Current,
            GraphFreshness::Stale => RelationFreshness::Stale,
            _ => RelationFreshness::Unknown,
        },
        coverage: match result.coverage {
            GraphCoverage::Complete => RelationCoverage::Complete,
            GraphCoverage::Partial => RelationCoverage::Partial,
            GraphCoverage::Unknown => RelationCoverage::Unknown,
        },
        source_handles: vec![source.to_owned()],
        dependencies: Vec::new(),
        conflicts: Vec::new(),
    };
    if let Some(existing) = relations.get_mut(&key) {
        if existing.freshness != candidate.freshness || existing.coverage != candidate.coverage {
            let detail = format!(
                "{}:{:?}/{:?}",
                source, candidate.freshness, candidate.coverage
            );
            existing.conflicts.push(detail.clone());
            conflicts.push(SemanticConflict {
                subject: key,
                alternatives: vec![
                    "graph observations disagree on freshness or coverage".to_owned(),
                ],
                source_handles: vec![source.to_owned()],
            });
        }
        existing.source_handles.push(source.to_owned());
    } else {
        relations.insert(key, candidate);
    }
}

pub fn report_digest(report: &CodeCortexReport) -> Result<String, CodeCortexError> {
    let bytes = serde_json::to_vec(report)
        .map_err(|error| CodeCortexError::InvalidEvidence(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(format!("{:x}", digest.finalize()))
}
