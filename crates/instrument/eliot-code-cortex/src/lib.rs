//! Evidence-only semantic composition for bounded code understanding.
//!
//! `CodeCortex` deliberately has no parser, process runner, persistence engine,
//! or truth authority.  Adapters admit graph projections and normalized
//! instrument evidence; this crate indexes those immutable observations and
//! composes a task-scoped report while retaining freshness, coverage, and
//! disagreement.

#![forbid(unsafe_code)]

use eliot_graph_api::{
    CoordinateKind, GraphCoordinate, GraphCoverage, GraphEdge, GraphFreshness, GraphNode,
    GraphQueryResult, GraphRevision,
};
use eliot_instrument_api::{EvidenceAxes, EvidenceCoverage, EvidenceFreshness, NormalizedEvidence};
use eliot_lsp_bridge::{
    Coverage as LspCoverage, DiagnosticSeverity, FailureDisposition, LspRawOutputKind,
    NormalizedResult, RetainedLspObservationV1, SemanticOperation, adopt_retained_observation,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.code-cortex";
pub const CONTRACT_VERSION: &str = "1.0.0";
/// Stable normalized-evidence kind for a historically adopted LSP observation.
pub const LSP_NORMALIZED_EVIDENCE_KIND: &str = "eliot.lsp.normalized-observation.v1";
const MAX_RETAINED_LSP_OBSERVATIONS: usize = 32;

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
    retained_lsp: BTreeMap<String, RetainedLspProjection>,
}

#[derive(Clone, Debug)]
struct RetainedLspProjection {
    workspace_root: String,
    source_handle: String,
    raw_handles: Vec<String>,
    result: NormalizedResult,
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

    /// Admits a batch of already-normalized instrument evidence atomically:
    /// every item is validated before any item is indexed, so one invalid
    /// observation can never leave a partially admitted index behind.
    /// Validation failure reports the first offending item; no evidence is
    /// rerun, reparsed, or re-observed here - the caller supplies normalized
    /// evidence the owning instrument already produced (I10.8.10: `CodeCortex`
    /// consumes existing instrument evidence and does not rerun diagnostics
    /// privately).
    pub fn admit_evidence_batch(
        &mut self,
        evidence: Vec<NormalizedEvidence>,
    ) -> Result<GraphRevision, CodeCortexError> {
        for item in &evidence {
            item.validate()
                .map_err(|error| CodeCortexError::InvalidEvidence(error.to_string()))?;
        }
        let mut revision = self.revision()?;
        for item in evidence {
            revision = self.admit_evidence(item)?;
        }
        Ok(revision)
    }

    /// Validates and retains one original LSP envelope as historical evidence.
    ///
    /// Adoption revalidates the exact retained raw bytes and full normalized
    /// result through the bridge's historical validator. That validator keeps
    /// the observation stale because the current source and process owners are
    /// not supplied here. The index retains the normalized result's actual
    /// items and projects them as stale nodes during composition; it never
    /// launches an analyzer or creates an observation receipt.
    pub fn admit_retained_lsp_observation(
        &mut self,
        record: RetainedLspObservationV1,
    ) -> Result<GraphRevision, CodeCortexError> {
        if self.retained_lsp.len() >= MAX_RETAINED_LSP_OBSERVATIONS {
            return Err(CodeCortexError::InvalidLimit);
        }

        let source_kind = match &record.operation {
            SemanticOperation::Diagnostics | SemanticOperation::ProbeVersion => {
                LspRawOutputKind::Stdout
            }
            SemanticOperation::Definitions { .. }
            | SemanticOperation::References { .. }
            | SemanticOperation::Symbols { .. }
            | SemanticOperation::Rename { .. } => LspRawOutputKind::ScipSidecar,
        };
        let raw = record
            .raw_outputs
            .iter()
            .find(|output| output.kind == source_kind)
            .ok_or_else(|| {
                CodeCortexError::InvalidEvidence(
                    "retained LSP observation lacks the raw stream for its operation".to_owned(),
                )
            })?;
        let raw_artifact_id = raw.evidence.artifact_id.clone();
        let evidence_id = raw_artifact_id.to_string();
        let raw_handles = record
            .raw_outputs
            .iter()
            .map(|output| output.evidence.artifact_id.to_string())
            .collect::<Vec<_>>();
        let workspace_root = record.source_candidate.workspace_root.clone();
        let normalizer = record.registry_identity.normalizer.clone();
        let raw_metadata = record
            .raw_outputs
            .iter()
            .map(|output| {
                serde_json::json!({
                    "kind": output.kind,
                    "artifact_id": output.evidence.artifact_id.to_string(),
                    "sha256": output.evidence.sha256,
                    "source": output.evidence.source,
                    "truncated": output.evidence.truncated,
                })
            })
            .collect::<Vec<_>>();
        let result = adopt_retained_observation(record)
            .map_err(|error| CodeCortexError::InvalidEvidence(error.to_string()))?;
        if !matches!(
            &result.receipt().freshness,
            eliot_lsp_bridge::Freshness::Stale { .. }
        ) {
            return Err(CodeCortexError::InvalidEvidence(
                "historical LSP adoption did not preserve stale freshness".to_owned(),
            ));
        }
        let coverage = match &result.receipt().coverage {
            LspCoverage::ProbeOnly => EvidenceCoverage::NotApplicable,
            _ if matches!(
                &result.receipt().disposition,
                FailureDisposition::Success
            ) => {
                EvidenceCoverage::CompleteForScope
            }
            _ => EvidenceCoverage::PartialForScope,
        };
        let value = serde_json::json!({
            "receipt_kind": eliot_lsp_bridge::LSP_TOOL_OBSERVATION_RECEIPT_KIND,
            "result": &result,
            "raw_outputs": raw_metadata,
        });
        let evidence = NormalizedEvidence {
            evidence_id: raw_artifact_id.clone(),
            raw_artifact_id,
            normalizer,
            kind: LSP_NORMALIZED_EVIDENCE_KIND.to_owned(),
            summary: "bridge-validated historical LSP observation; stale freshness retained"
                .to_owned(),
            value,
            axes: EvidenceAxes::observed(),
            freshness: EvidenceFreshness::Stale,
            coverage,
        };
        evidence
            .validate()
            .map_err(|error| CodeCortexError::InvalidEvidence(error.to_string()))?;
        let key = format!("{}:{}", evidence_id, self.retained_lsp.len());
        self.evidence.insert(key.clone(), evidence);
        self.retained_lsp.insert(
            key,
            RetainedLspProjection {
                workspace_root,
                source_handle: evidence_id,
                raw_handles,
                result,
            },
        );
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

    /// Builds a service over caller-supplied normalized instrument evidence.
    ///
    /// This is the consumption seam the diagnostics bridge feeds: the caller
    /// hands over evidence the owning instruments already normalized, and the
    /// service indexes it without spawning a process, reading a tool stream,
    /// or re-observing anything. An invalid batch fails closed with an empty
    /// index rather than a partially supplied one.
    pub fn with_evidence(evidence: Vec<NormalizedEvidence>) -> Result<Self, CodeCortexError> {
        let mut index = SemanticIndex::new();
        index.admit_evidence_batch(evidence)?;
        Ok(Self { index })
    }

    /// Builds a service from caller-supplied original bridge observations.
    ///
    /// Each envelope is independently re-adopted from its retained bytes and
    /// represented as stale evidence. This entrypoint does not accept an
    /// already-normalized JSON value as proof of a bridge invocation.
    pub fn with_retained_lsp_observations(
        records: Vec<RetainedLspObservationV1>,
    ) -> Result<Self, CodeCortexError> {
        if records.len() > MAX_RETAINED_LSP_OBSERVATIONS {
            return Err(CodeCortexError::InvalidLimit);
        }
        let mut index = SemanticIndex::new();
        for record in records {
            index.admit_retained_lsp_observation(record)?;
        }
        Ok(Self { index })
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
        let mut report = compose_snapshot(request, &self.index.snapshot())?;
        project_retained_lsp_observations(request, &self.index.retained_lsp, &mut report)?;
        Ok(report)
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

fn project_retained_lsp_observations(
    request: &CompositionRequest,
    observations: &BTreeMap<String, RetainedLspProjection>,
    report: &mut CodeCortexReport,
) -> Result<(), CodeCortexError> {
    for (evidence_id, observation) in observations {
        if observation.workspace_root != request.scope {
            report.coverage_gaps.push(CoverageGap {
                scope: request.scope.clone(),
                reason: format!(
                    "retained LSP evidence {evidence_id} belongs to a different workspace scope"
                ),
                cheapest_probe: None,
            });
            continue;
        }
        for handle in &observation.raw_handles {
            if !report.evidence_handles.contains(handle) {
                report.evidence_handles.push(handle.clone());
            }
        }
        report.coverage_gaps.push(CoverageGap {
            scope: request.scope.clone(),
            reason: format!(
                "retained LSP evidence {evidence_id} is historical and stale; source and process-owner state were not revalidated"
            ),
            cheapest_probe: Some(
                "obtain a current source-bound observation through the owning process path"
                    .to_owned(),
            ),
        });

        let mut node_limit_reached = false;
        let mut relation_limit_reached = false;
        match &observation.result {
            NormalizedResult::Definitions { items, .. } => {
                for item in items {
                    let symbol = lsp_symbol_coordinate(&observation.workspace_root, &item.symbol);
                    let location = lsp_span_coordinate(
                        &observation.workspace_root,
                        &item.path,
                        Some(&item.symbol),
                        item.line,
                        item.column,
                    );
                    if !admit_lsp_node(
                        request,
                        report,
                        symbol.clone(),
                        "stale_lsp_symbol_observation",
                        Some(item.symbol.clone()),
                        &observation.source_handle,
                    )? || !admit_lsp_node(
                        request,
                        report,
                        location.clone(),
                        "stale_lsp_definition_observation",
                        Some(item.symbol.clone()),
                        &observation.source_handle,
                    )? {
                        node_limit_reached = true;
                        break;
                    }
                    if !admit_lsp_relation(
                        request,
                        report,
                        symbol,
                        location,
                        "lsp_definition_observed",
                        &observation.source_handle,
                    ) {
                        relation_limit_reached = true;
                        break;
                    }
                }
            }
            NormalizedResult::References { items, .. } => {
                for item in items {
                    let symbol = lsp_symbol_coordinate(&observation.workspace_root, &item.symbol);
                    let location = lsp_span_coordinate(
                        &observation.workspace_root,
                        &item.path,
                        Some(&item.symbol),
                        item.line,
                        item.column,
                    );
                    if !admit_lsp_node(
                        request,
                        report,
                        symbol.clone(),
                        "stale_lsp_symbol_observation",
                        Some(item.symbol.clone()),
                        &observation.source_handle,
                    )? || !admit_lsp_node(
                        request,
                        report,
                        location.clone(),
                        "stale_lsp_reference_observation",
                        Some(item.symbol.clone()),
                        &observation.source_handle,
                    )? {
                        node_limit_reached = true;
                        break;
                    }
                    if !admit_lsp_relation(
                        request,
                        report,
                        symbol,
                        location,
                        "lsp_reference_observed",
                        &observation.source_handle,
                    ) {
                        relation_limit_reached = true;
                        break;
                    }
                }
            }
            NormalizedResult::Symbols { items, receipt } => {
                let path_scope = match &receipt.coverage {
                    LspCoverage::SymbolSubset { path_scope } if !path_scope.is_empty() => {
                        Some(path_scope.clone())
                    }
                    _ => None,
                };
                for item in items {
                    let coordinate = GraphCoordinate {
                        kind: CoordinateKind::Symbol,
                        package: observation.workspace_root.clone(),
                        path: path_scope.clone(),
                        symbol: Some(item.symbol.clone()),
                        line: None,
                        column: None,
                    };
                    if !admit_lsp_node(
                        request,
                        report,
                        coordinate,
                        format!("stale_lsp_symbol_kind_{}", item.kind),
                        item.display_name.clone(),
                        &observation.source_handle,
                    )? {
                        node_limit_reached = true;
                        break;
                    }
                }
            }
            NormalizedResult::Diagnostics { observations, .. } => {
                for item in observations {
                    let severity = match item.severity {
                        DiagnosticSeverity::Error => "error",
                        DiagnosticSeverity::Warning => "warning",
                        DiagnosticSeverity::Information => "information",
                        DiagnosticSeverity::Hint => "hint",
                        DiagnosticSeverity::Unknown => "unknown",
                    };
                    if !admit_lsp_node(
                        request,
                        report,
                        lsp_span_coordinate(
                            &observation.workspace_root,
                            &item.file,
                            None,
                            item.line,
                            item.column,
                        ),
                        format!("stale_lsp_diagnostic_{severity}"),
                        Some(item.code.clone()),
                        &observation.source_handle,
                    )? {
                        node_limit_reached = true;
                        break;
                    }
                }
            }
            NormalizedResult::Rename { candidate, .. } => {
                if candidate.applied {
                    return Err(CodeCortexError::InvalidEvidence(
                        "bridge adoption returned an applied rename candidate".to_owned(),
                    ));
                }
                let symbol = lsp_symbol_coordinate(&observation.workspace_root, &candidate.symbol);
                if !admit_lsp_node(
                    request,
                    report,
                    symbol.clone(),
                    "stale_lsp_symbol_observation",
                    Some(candidate.symbol.clone()),
                    &observation.source_handle,
                )? {
                    node_limit_reached = true;
                }
                for edit in &candidate.edits {
                    if node_limit_reached || relation_limit_reached {
                        break;
                    }
                    let location = lsp_span_coordinate(
                        &observation.workspace_root,
                        &edit.path,
                        Some(&candidate.symbol),
                        edit.line,
                        edit.column,
                    );
                    if !admit_lsp_node(
                        request,
                        report,
                        location.clone(),
                        "stale_lsp_unapplied_rename_candidate",
                        Some(candidate.new_name.clone()),
                        &observation.source_handle,
                    )? {
                        node_limit_reached = true;
                        break;
                    }
                    if !admit_lsp_relation(
                        request,
                        report,
                        symbol.clone(),
                        location,
                        "lsp_rename_candidate_observed",
                        &observation.source_handle,
                    ) {
                        relation_limit_reached = true;
                        break;
                    }
                }
            }
            NormalizedResult::Version { .. } => {}
        }
        if node_limit_reached {
            report.coverage_gaps.push(CoverageGap {
                scope: request.scope.clone(),
                reason: format!(
                    "retained LSP evidence {evidence_id} was projected only up to the requested node limit"
                ),
                cheapest_probe: None,
            });
        }
        if relation_limit_reached {
            report.coverage_gaps.push(CoverageGap {
                scope: request.scope.clone(),
                reason: format!(
                    "retained LSP evidence {evidence_id} was projected only up to the requested relation limit"
                ),
                cheapest_probe: None,
            });
        }
    }
    Ok(())
}

fn lsp_symbol_coordinate(workspace_root: &str, symbol: &str) -> GraphCoordinate {
    GraphCoordinate {
        kind: CoordinateKind::Symbol,
        package: workspace_root.to_owned(),
        path: None,
        symbol: Some(symbol.to_owned()),
        line: None,
        column: None,
    }
}

fn admit_lsp_node(
    request: &CompositionRequest,
    report: &mut CodeCortexReport,
    coordinate: GraphCoordinate,
    kind: impl Into<String>,
    label: Option<String>,
    evidence_id: &str,
) -> Result<bool, CodeCortexError> {
    add_lsp_node(
        request,
        report,
        GraphNode {
            coordinate,
            kind: kind.into(),
            label,
        },
        evidence_id,
    )
}

fn admit_lsp_relation(
    request: &CompositionRequest,
    report: &mut CodeCortexReport,
    from: GraphCoordinate,
    to: GraphCoordinate,
    kind: &str,
    evidence_id: &str,
) -> bool {
    let from = from.to_string();
    let to = to.to_string();
    if let Some(existing) = report.relations.iter_mut().find(|relation| {
        relation.from == from
            && relation.to == to
            && relation.kind == kind
            && relation.authority == RelationAuthority::InstrumentObservation
    }) {
        if !existing.source_handles.iter().any(|handle| handle == evidence_id) {
            existing.source_handles.push(evidence_id.to_owned());
        }
        return true;
    }
    if report.relations.len() >= request.max_relations {
        return false;
    }
    if report.relations.iter().any(|relation| {
        relation.from == from && relation.to == to && relation.kind == kind
    }) {
        report.conflicts.push(SemanticConflict {
            subject: format!("{from}|{kind}|{to}"),
            alternatives: vec![
                "exact graph relation".to_owned(),
                "historical LSP instrument observation".to_owned(),
            ],
            source_handles: vec![evidence_id.to_owned()],
        });
    }
    report.relations.push(SemanticRelation {
        from,
        to,
        kind: kind.to_owned(),
        authority: RelationAuthority::InstrumentObservation,
        freshness: RelationFreshness::Stale,
        coverage: RelationCoverage::Partial,
        source_handles: vec![evidence_id.to_owned()],
        dependencies: Vec::new(),
        conflicts: Vec::new(),
    });
    true
}

fn lsp_span_coordinate(
    workspace_root: &str,
    path: &str,
    symbol: Option<&str>,
    line_zero_based: u32,
    column_zero_based: u32,
) -> GraphCoordinate {
    GraphCoordinate {
        kind: CoordinateKind::Span,
        package: workspace_root.to_owned(),
        path: Some(path.to_owned()),
        symbol: symbol.map(str::to_owned),
        line: Some(line_zero_based.saturating_add(1)),
        column: Some(column_zero_based.saturating_add(1)),
    }
}

fn add_lsp_node(
    request: &CompositionRequest,
    report: &mut CodeCortexReport,
    node: GraphNode,
    evidence_id: &str,
) -> Result<bool, CodeCortexError> {
    node.validate()
        .map_err(|error| CodeCortexError::InvalidEvidence(error.to_string()))?;
    if let Some(existing) = report
        .nodes
        .iter()
        .find(|existing| existing.coordinate == node.coordinate)
    {
        if existing.kind != node.kind || existing.label != node.label {
            report.conflicts.push(SemanticConflict {
                subject: node.coordinate.to_string(),
                alternatives: vec![
                    format!("existing graph node: {}", existing.kind),
                    format!("LSP observation node: {}", node.kind),
                ],
                source_handles: vec![evidence_id.to_owned()],
            });
        }
        return Ok(true);
    }
    if report.nodes.len() >= request.max_nodes {
        return Ok(false);
    }
    let handle = node.coordinate.to_string();
    let source_handle = node
        .coordinate
        .path
        .clone()
        .unwrap_or_else(|| node.coordinate.package.clone());
    let label = node.label.clone().unwrap_or_else(|| node.kind.clone());
    report.entrypoints.push(SemanticAnchor {
        handle,
        label,
        source_handle,
    });
    report.nodes.push(node);
    Ok(true)
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
