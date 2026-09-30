//! Evidence-only semantic composition for bounded code understanding.
//!
//! `CodeCortex` deliberately has no parser, process runner, persistence engine,
//! or truth authority.  Adapters admit graph projections and normalized
//! instrument evidence; this crate indexes those immutable observations and
//! composes a task-scoped report while retaining freshness, coverage, and
//! disagreement.

#![forbid(unsafe_code)]

use eliot_blob_api::BlobReadChunk;
use eliot_contracts::ArtifactId;
use eliot_graph_api::{
    CoordinateKind, GraphCoordinate, GraphCoverage, GraphEdge, GraphFreshness, GraphNode,
    GraphQueryResult, GraphRevision,
};
use eliot_instrument_api::{EvidenceAxes, EvidenceCoverage, EvidenceFreshness, NormalizedEvidence};
use eliot_receipts::{CausalBinding, TaskBinding};
use eliot_store_api::CapturedBlobPayloadRefV1;
use eliot_lsp_bridge::{
    adopt_captured_observation_from_blob_readback, adopt_retained_observation,
    BridgeError as LspBridgeError, Coverage as LspCoverage, DiagnosticObservation,
    DiagnosticSeverity, FailureDisposition, Freshness as LspFreshness, LspAdoptionProjection,
    LspRawOutputKind, NormalizedResult, RenameCandidate, RetainedLspObservationV1,
    SemanticOperation, SymbolInfo,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const CONTRACT_NAME: &str = "eliot.code-cortex";
pub const CONTRACT_VERSION: &str = "1.0.0";
/// Stable normalized-evidence kind for a historically adopted LSP observation.
pub const LSP_NORMALIZED_EVIDENCE_KIND: &str = "eliot.lsp.normalized-observation.v1";

#[derive(Debug, Error)]
pub enum CodeCortexError {
    #[error("task and scope must be non-blank")]
    InvalidScope,
    #[error("maximum records must be non-zero")]
    InvalidLimit,
    #[error("graph result is invalid: {0}")]
    InvalidGraph(String),
    #[error("evidence is invalid: {0}")]
    InvalidEvidence(String),
    #[error("captured LSP payload reference is invalid: {0}")]
    CapturedLspPayloadReference(#[from] eliot_store_api::StoreError),
    #[error("captured LSP observation adoption failed: {0}")]
    CapturedLspAdoption(#[from] LspBridgeError),
    #[error("captured LSP pointer and owner receipts do not join")]
    CapturedLspBindingMismatch,
    #[error("captured LSP evidence is bound to another task")]
    TaskBindingMismatch,
    #[error("index revision overflow")]
    RevisionOverflow,
}

/// One exact Store pointer, its owner-authenticated immutable Blob readback,
/// and the historical task binding attached to the captured Store row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedLspObservation {
    pub reference: CapturedBlobPayloadRefV1,
    pub readback: BlobReadChunk,
    pub historical_task_binding: TaskBinding,
}

impl CapturedLspObservation {
    #[must_use]
    pub fn new(
        reference: CapturedBlobPayloadRefV1,
        readback: BlobReadChunk,
        historical_task_binding: TaskBinding,
    ) -> Self {
        Self {
            reference,
            readback,
            historical_task_binding,
        }
    }
}

fn validate_current_read_binding(
    task_binding: &TaskBinding,
    causal_binding: &CausalBinding,
) -> Result<(), CodeCortexError> {
    if task_binding.state_fence != causal_binding.state_fence {
        return Err(CodeCortexError::CapturedLspBindingMismatch);
    }
    Ok(())
}

fn validate_captured_lsp_payload_reference(
    reference: &CapturedBlobPayloadRefV1,
) -> Result<(), CodeCortexError> {
    reference.validate()?;
    if reference.receipt_kind != eliot_lsp_bridge::LSP_TOOL_OBSERVATION_RECEIPT_KIND {
        return Err(CodeCortexError::CapturedLspBindingMismatch);
    }
    Ok(())
}

fn validate_captured_lsp_task_join(
    captured: &CapturedLspObservation,
    record: &RetainedLspObservationV1,
    current_read_task_binding: &TaskBinding,
    current_read_causal_binding: &CausalBinding,
) -> Result<(), CodeCortexError> {
    let invalid = || CodeCortexError::CapturedLspBindingMismatch;
    let readback = &captured.readback;
    let ready_capability = readback.ready_receipt();
    let staged_payload_receipt = ready_capability.receipt();
    let current_read_receipt = readback.receipt();
    let reference = &captured.reference;
    if &reference.locator != ready_capability.locator()
        || reference.metadata_sha256 != ready_capability.metadata_sha256()
        || reference.ready_receipt_id != staged_payload_receipt.identity.receipt_id.to_string()
        || reference.plaintext_length != ready_capability.plaintext_length()
        || reference.plaintext_sha256 != ready_capability.plaintext_sha256()
        || staged_payload_receipt.core.task.as_ref() != Some(&captured.historical_task_binding)
        || staged_payload_receipt.core.request.metadata.task_id.as_ref()
            != Some(&captured.historical_task_binding.task_id)
        || staged_payload_receipt.core.request.state_fence
            != captured.historical_task_binding.state_fence
        || staged_payload_receipt.core.request.metadata.state_fence
            != captured.historical_task_binding.state_fence
        || staged_payload_receipt.core.causal.state_fence
            != captured.historical_task_binding.state_fence
        || current_read_receipt.core.task.as_ref() != Some(current_read_task_binding)
        || &current_read_receipt.core.causal != current_read_causal_binding
        || current_read_receipt.core.request.metadata.task_id.as_ref()
            != Some(&current_read_task_binding.task_id)
        || current_read_receipt.core.request.state_fence != current_read_task_binding.state_fence
        || current_read_receipt.core.request.metadata.state_fence
            != current_read_task_binding.state_fence
        || record.instrument_invocation.request.task_id.as_ref()
            != Some(&captured.historical_task_binding.task_id)
        || record.instrument_invocation.request.state_fence
            != captured.historical_task_binding.state_fence
    {
        return Err(invalid());
    }
    Ok(())
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
    process_operation_id: String,
    raw_handles: Vec<String>,
    evidence: NormalizedEvidence,
    result: NormalizedResult,
    currentness: LspFreshness,
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
    /// launches an analyzer or creates an observation receipt. Live callers
    /// should use [`Self::admit_lsp_adoption_projection`] when they have the
    /// original owner-adopted projection.
    pub fn admit_retained_lsp_observation(
        &mut self,
        record: RetainedLspObservationV1,
    ) -> Result<GraphRevision, CodeCortexError> {
        let process_operation_id = record.process_evidence.operation_id().as_str().to_owned();
        let result = adopt_retained_observation(record.clone())
            .map_err(|error| CodeCortexError::InvalidEvidence(error.to_string()))?;
        self.admit_lsp_observation(
            &record,
            result,
            process_operation_id,
            LspFreshness::Stale {
                reason: "retained envelope supplied without live source-owner adoption".to_owned(),
            },
        )
    }

    /// Admits an original LSP observation together with the separate
    /// currentness projection produced by its live process/source owners.
    /// The projection is bound to this exact retained envelope, and the
    /// bridge revalidates the original raw bytes before `CodeCortex` indexes
    /// the unchanged normalized result.
    pub fn admit_lsp_adoption_projection(
        &mut self,
        record: RetainedLspObservationV1,
        projection: &LspAdoptionProjection,
    ) -> Result<GraphRevision, CodeCortexError> {
        if !projection.matches_retained_observation(&record) {
            return Err(CodeCortexError::InvalidEvidence(
                "LSP adoption projection is bound to a different retained observation".to_owned(),
            ));
        }
        let process_operation_id = record.process_evidence.operation_id().as_str().to_owned();
        let result = adopt_retained_observation(record.clone())
            .map_err(|error| CodeCortexError::InvalidEvidence(error.to_string()))?;
        if projection.observation() != &result {
            return Err(CodeCortexError::InvalidEvidence(
                "LSP adoption projection changed the bridge-validated normalized result".to_owned(),
            ));
        }
        self.admit_lsp_observation(
            &record,
            result,
            process_operation_id,
            projection.currentness().clone(),
        )
    }

    fn admit_lsp_observation(
        &mut self,
        record: &RetainedLspObservationV1,
        result: NormalizedResult,
        process_operation_id: String,
        currentness: LspFreshness,
    ) -> Result<GraphRevision, CodeCortexError> {
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
        let raw_handles = record
            .raw_outputs
            .iter()
            .map(|output| output.evidence.artifact_id.to_string())
            .collect::<Vec<_>>();
        let workspace_root = record.source_candidate.workspace_root.clone();
        let evidence = normalized_lsp_evidence(record, &result, &currentness, raw_artifact_id)?;
        if self.retained_lsp.contains_key(&process_operation_id) {
            return Err(CodeCortexError::InvalidEvidence(
                "the original process operation is already retained".to_owned(),
            ));
        }
        self.retained_lsp.insert(
            process_operation_id.clone(),
            RetainedLspProjection {
                workspace_root,
                process_operation_id,
                raw_handles,
                evidence,
                result,
                currentness,
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
            instrument_evidence: self
                .evidence
                .values()
                .cloned()
                .chain(
                    self.retained_lsp
                        .values()
                        .map(|observation| observation.evidence.clone()),
                )
                .collect(),
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

fn normalized_lsp_evidence(
    record: &RetainedLspObservationV1,
    result: &NormalizedResult,
    currentness: &LspFreshness,
    raw_artifact_id: ArtifactId,
) -> Result<NormalizedEvidence, CodeCortexError> {
    if !matches!(&result.receipt().freshness, LspFreshness::Stale { .. }) {
        return Err(CodeCortexError::InvalidEvidence(
            "LSP adoption did not preserve the original stale observation receipt".to_owned(),
        ));
    }
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
    let coverage = match (&result.receipt().coverage, &result.receipt().disposition) {
        (LspCoverage::ProbeOnly, _) => EvidenceCoverage::NotApplicable,
        (LspCoverage::Workspace { .. }, FailureDisposition::Success) => {
            EvidenceCoverage::CompleteForScope
        }
        _ => EvidenceCoverage::PartialForScope,
    };
    let value = serde_json::json!({
        "receipt_kind": eliot_lsp_bridge::LSP_TOOL_OBSERVATION_RECEIPT_KIND,
        "operation": &record.operation,
        "config": &record.config,
        "source_candidate": &record.source_candidate,
        "instrument_invocation": &record.instrument_invocation,
        "process_intent": &record.process_intent,
        "invocation_digest": &record.invocation_digest,
        "resolved_executable": &record.resolved_executable,
        "instrument_spec": &record.instrument_spec,
        "registry_identity": &record.registry_identity,
        "process_evidence": &record.process_evidence,
        "adoption_currentness": currentness,
        "result": result,
        "raw_outputs": raw_metadata,
    });
    let evidence = NormalizedEvidence {
        evidence_id: raw_artifact_id.clone(),
        raw_artifact_id,
        normalizer: record.registry_identity.normalizer.clone(),
        kind: LSP_NORMALIZED_EVIDENCE_KIND.to_owned(),
        summary: match currentness {
            LspFreshness::Current => {
                "bridge-validated LSP observation with live source-owner currentness".to_owned()
            }
            LspFreshness::Stale { .. } => {
                "bridge-validated LSP observation with stale or unavailable currentness".to_owned()
            }
        },
        value,
        axes: EvidenceAxes::observed(),
        freshness: match currentness {
            LspFreshness::Current => EvidenceFreshness::ExactCandidate,
            LspFreshness::Stale { .. } => EvidenceFreshness::Stale,
        },
        coverage,
    };
    evidence
        .validate()
        .map_err(|error| CodeCortexError::InvalidEvidence(error.to_string()))?;
    Ok(evidence)
}

pub struct CodeCortexService {
    index: SemanticIndex,
    current_task_binding: Option<TaskBinding>,
}

impl CodeCortexService {
    pub fn new(index: SemanticIndex) -> Self {
        Self {
            index,
            current_task_binding: None,
        }
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
        Ok(Self {
            index,
            current_task_binding: None,
        })
    }

    /// Builds a service from caller-supplied original bridge observations.
    ///
    /// Each envelope is independently re-adopted from its retained bytes and
    /// represented as stale evidence. This entrypoint does not accept an
    /// already-normalized JSON value as proof of a bridge invocation.
    pub fn with_retained_lsp_observations(
        records: Vec<RetainedLspObservationV1>,
    ) -> Result<Self, CodeCortexError> {
        let mut index = SemanticIndex::new();
        for record in records {
            index.admit_retained_lsp_observation(record)?;
        }
        Ok(Self {
            index,
            current_task_binding: None,
        })
    }

    /// Builds a service from original bridge observations paired with the
    /// separate currentness result established by their live source/process
    /// owners. Each pair is checked against the exact retained envelope
    /// before its unchanged semantic result is indexed.
    pub fn with_lsp_adoption_projections(
        observations: Vec<(RetainedLspObservationV1, LspAdoptionProjection)>,
    ) -> Result<Self, CodeCortexError> {
        let mut index = SemanticIndex::new();
        for (record, projection) in observations {
            index.admit_lsp_adoption_projection(record, &projection)?;
        }
        Ok(Self {
            index,
            current_task_binding: None,
        })
    }

    /// Builds a stale-only service from exact captured LSP payload references
    /// and the original Blob owner's non-deserializable read capabilities.
    /// It validates the current read receipt separately from the historical
    /// task binding, re-adopts the original bytes through the bridge, and
    /// preserves each original LSP observation receipt unchanged.
    pub fn with_captured_lsp_observations(
        current_read_task_binding: TaskBinding,
        current_read_causal_binding: &CausalBinding,
        observations: Vec<CapturedLspObservation>,
    ) -> Result<Self, CodeCortexError> {
        validate_current_read_binding(
            &current_read_task_binding,
            current_read_causal_binding,
        )?;
        let mut index = SemanticIndex::new();
        for observation in observations {
            validate_captured_lsp_payload_reference(&observation.reference)?;
            let (record, result) =
                adopt_captured_observation_from_blob_readback(&observation.readback)?;
            validate_captured_lsp_task_join(
                &observation,
                &record,
                &current_read_task_binding,
                current_read_causal_binding,
            )?;
            let process_operation_id = record.process_evidence.operation_id().as_str().to_owned();
            index.admit_lsp_observation(
                &record,
                result,
                process_operation_id,
                LspFreshness::Stale {
                    reason: "captured immutable bytes lack current process and source-owner reconciliation".to_owned(),
                },
            )?;
        }
        Ok(Self {
            index,
                current_task_binding: Some(current_read_task_binding),
        })
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
        if self.current_task_binding.as_ref().is_some_and(|binding| {
            request.task_id != binding.task_id.to_string()
        }) {
            return Err(CodeCortexError::TaskBindingMismatch);
        }
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
        project_retained_lsp_observation(request, evidence_id, observation, report)?;
    }
    Ok(())
}

fn project_retained_lsp_observation(
    request: &CompositionRequest,
    evidence_id: &str,
    observation: &RetainedLspProjection,
    report: &mut CodeCortexReport,
) -> Result<(), CodeCortexError> {
    let observation_is_current = matches!(&observation.currentness, LspFreshness::Current);
    for handle in &observation.raw_handles {
        if !report.evidence_handles.contains(handle) {
            report.evidence_handles.push(handle.clone());
        }
    }
    if !report
        .evidence_handles
        .contains(&observation.process_operation_id)
    {
        report
            .evidence_handles
            .push(observation.process_operation_id.clone());
    }
    let receipt = observation.result.receipt();
    let workspace_complete = matches!(&receipt.coverage, LspCoverage::Workspace { .. })
        && matches!(&receipt.disposition, FailureDisposition::Success);
    if let LspFreshness::Stale { reason } = &observation.currentness {
        report.coverage_gaps.push(CoverageGap {
            scope: request.scope.clone(),
            reason: format!("LSP evidence {evidence_id} is stale at owner adoption: {reason}"),
            cheapest_probe: Some(
                "obtain a current source-bound observation through the owning process path"
                    .to_owned(),
            ),
        });
    } else if !workspace_complete {
        report.coverage_gaps.push(CoverageGap {
            scope: request.scope.clone(),
            reason: format!(
                "current LSP evidence {evidence_id} covers only its declared operation scope, not the requested workspace scope"
            ),
            cheapest_probe: Some(
                "obtain a successful workspace-scoped observation for workspace coverage"
                    .to_owned(),
            ),
        });
    }
    if has_empty_lookup_result(&observation.result) {
        report.coverage_gaps.push(CoverageGap {
            scope: request.scope.clone(),
            reason: format!(
                "empty LSP lookup evidence {evidence_id} is not a qualified absence result; #1815 owns absence qualification"
            ),
            cheapest_probe: None,
        });
    }
    let freshness = if observation_is_current {
        RelationFreshness::Current
    } else {
        RelationFreshness::Stale
    };
    let (node_limit_reached, relation_limit_reached) =
        project_lsp_result(request, observation, report, freshness)?;
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
    Ok(())
}

fn project_lsp_result(
    request: &CompositionRequest,
    observation: &RetainedLspProjection,
    report: &mut CodeCortexReport,
    freshness: RelationFreshness,
) -> Result<(bool, bool), CodeCortexError> {
    let node_freshness = if freshness == RelationFreshness::Current {
        "current"
    } else {
        "stale"
    };
    match &observation.result {
        NormalizedResult::Definitions { items, .. } => project_lsp_locations(
            request,
            observation,
            report,
            items
                .iter()
                .map(|item| (item.symbol.as_str(), item.path.as_str(), item.line, item.column)),
            "definition_observation",
            "lsp_definition_observed",
            freshness,
        ),
        NormalizedResult::References { items, .. } => project_lsp_locations(
            request,
            observation,
            report,
            items
                .iter()
                .map(|item| (item.symbol.as_str(), item.path.as_str(), item.line, item.column)),
            "reference_observation",
            "lsp_reference_observed",
            freshness,
        ),
        NormalizedResult::Symbols { items, receipt } => project_lsp_symbols(
            request,
            observation,
            report,
            items,
            &receipt.coverage,
            node_freshness,
        ),
        NormalizedResult::Diagnostics { observations, .. } => project_lsp_diagnostics(
            request,
            observation,
            report,
            observations,
            node_freshness,
        ),
        NormalizedResult::Rename { candidate, .. } => project_lsp_rename(
            request,
            observation,
            report,
            candidate,
            node_freshness,
            freshness,
        ),
        NormalizedResult::Version { .. } => Ok((false, false)),
    }
}

fn project_lsp_locations<'a>(
    request: &CompositionRequest,
    observation: &RetainedLspProjection,
    report: &mut CodeCortexReport,
    items: impl Iterator<Item = (&'a str, &'a str, u32, u32)>,
    location_node_kind: &str,
    relation_kind: &str,
    freshness: RelationFreshness,
) -> Result<(bool, bool), CodeCortexError> {
    let node_freshness = if freshness == RelationFreshness::Current {
        "current"
    } else {
        "stale"
    };
    let mut node_limit_reached = false;
    let mut relation_limit_reached = false;
    for (symbol_name, path, line, column) in items {
        let symbol = lsp_symbol_coordinate(&observation.workspace_root, symbol_name);
        let location = lsp_span_coordinate(
            &observation.workspace_root,
            path,
            Some(symbol_name),
            line,
            column,
        );
        if !admit_lsp_node(
            request,
            report,
            symbol.clone(),
            format!("{node_freshness}_lsp_symbol_observation"),
            Some(symbol_name.to_owned()),
            &observation.process_operation_id,
        )? || !admit_lsp_node(
            request,
            report,
            location.clone(),
            format!("{node_freshness}_lsp_{location_node_kind}"),
            Some(symbol_name.to_owned()),
            &observation.process_operation_id,
        )? {
            node_limit_reached = true;
            break;
        }
        if !admit_lsp_relation(
            request,
            report,
            &symbol,
            &location,
            relation_kind,
            &observation.process_operation_id,
            freshness,
        ) {
            relation_limit_reached = true;
            break;
        }
    }
    Ok((node_limit_reached, relation_limit_reached))
}

fn project_lsp_symbols(
    request: &CompositionRequest,
    observation: &RetainedLspProjection,
    report: &mut CodeCortexReport,
    items: &[SymbolInfo],
    coverage: &LspCoverage,
    node_freshness: &str,
) -> Result<(bool, bool), CodeCortexError> {
    let path_scope = match coverage {
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
            format!("{node_freshness}_lsp_symbol_kind_{}", item.kind),
            item.display_name.clone(),
            &observation.process_operation_id,
        )? {
            return Ok((true, false));
        }
    }
    Ok((false, false))
}

fn project_lsp_diagnostics(
    request: &CompositionRequest,
    observation: &RetainedLspProjection,
    report: &mut CodeCortexReport,
    items: &[DiagnosticObservation],
    node_freshness: &str,
) -> Result<(bool, bool), CodeCortexError> {
    for item in items {
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
            format!("{node_freshness}_lsp_diagnostic_{severity}"),
            Some(item.code.clone()),
            &observation.process_operation_id,
        )? {
            return Ok((true, false));
        }
    }
    Ok((false, false))
}

fn project_lsp_rename(
    request: &CompositionRequest,
    observation: &RetainedLspProjection,
    report: &mut CodeCortexReport,
    candidate: &RenameCandidate,
    node_freshness: &str,
    freshness: RelationFreshness,
) -> Result<(bool, bool), CodeCortexError> {
    if candidate.applied {
        return Err(CodeCortexError::InvalidEvidence(
            "bridge adoption returned an applied rename candidate".to_owned(),
        ));
    }
    let symbol = lsp_symbol_coordinate(&observation.workspace_root, &candidate.symbol);
    let mut node_limit_reached = !admit_lsp_node(
        request,
        report,
        symbol.clone(),
        format!("{node_freshness}_lsp_symbol_observation"),
        Some(candidate.symbol.clone()),
        &observation.process_operation_id,
    )?;
    let mut relation_limit_reached = false;
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
            format!("{node_freshness}_lsp_unapplied_rename_candidate"),
            Some(candidate.new_name.clone()),
            &observation.process_operation_id,
        )? {
            node_limit_reached = true;
            break;
        }
        if !admit_lsp_relation(
            request,
            report,
            &symbol,
            &location,
            "lsp_rename_candidate_observed",
            &observation.process_operation_id,
            freshness,
        ) {
            relation_limit_reached = true;
        }
    }
    Ok((node_limit_reached, relation_limit_reached))
}

fn has_empty_lookup_result(result: &NormalizedResult) -> bool {
    match result {
        NormalizedResult::Definitions { items, .. } => items.is_empty(),
        NormalizedResult::References { items, .. } => items.is_empty(),
        NormalizedResult::Symbols { items, .. } => items.is_empty(),
        NormalizedResult::Diagnostics { observations, .. } => observations.is_empty(),
        NormalizedResult::Rename { .. } | NormalizedResult::Version { .. } => false,
    }
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
    from: &GraphCoordinate,
    to: &GraphCoordinate,
    kind: &str,
    evidence_id: &str,
    freshness: RelationFreshness,
) -> bool {
    let from = from.to_string();
    let to = to.to_string();
    if report.relations.iter().any(|relation| {
        relation.from == from
            && relation.to == to
            && relation.kind == kind
            && relation.authority == RelationAuthority::InstrumentObservation
            && relation.freshness == freshness
            && relation
                .source_handles
                .iter()
                .any(|handle| handle == evidence_id)
    }) {
        return true;
    }
    if report.relations.len() >= request.max_relations {
        return false;
    }
    if report.relations.iter().any(|relation| {
        relation.from == from
            && relation.to == to
            && relation.kind == kind
            && relation.authority != RelationAuthority::InstrumentObservation
    }) {
        report.conflicts.push(SemanticConflict {
            subject: format!("{from}|{kind}|{to}"),
            alternatives: vec![
                "exact graph relation".to_owned(),
                "LSP instrument observation".to_owned(),
            ],
            source_handles: vec![evidence_id.to_owned()],
        });
    }
    report.relations.push(SemanticRelation {
        from,
        to,
        kind: kind.to_owned(),
        authority: RelationAuthority::InstrumentObservation,
        freshness,
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
    let coordinate_handle = node.coordinate.to_string();
    if let Some(existing) = report
        .nodes
        .iter()
        .find(|existing| existing.coordinate == node.coordinate)
    {
        let existing_is_current = existing.kind.starts_with("current_lsp_");
        let incoming_is_current = node.kind.starts_with("current_lsp_");
        let existing_is_stale = existing.kind.starts_with("stale_lsp_");
        let incoming_is_stale = node.kind.starts_with("stale_lsp_");
        if (existing_is_stale && incoming_is_current) || (existing_is_current && incoming_is_stale)
        {
            if report.nodes.len() >= request.max_nodes {
                return Ok(false);
            }
            add_lsp_anchor(report, &node, &coordinate_handle, evidence_id);
            report.nodes.push(node);
            return Ok(true);
        }
        if existing.kind == node.kind && existing.label == node.label {
            add_lsp_anchor(report, &node, &coordinate_handle, evidence_id);
            return Ok(true);
        }
        let mut source_handles = report
            .entrypoints
            .iter()
            .filter(|anchor| anchor.handle == coordinate_handle)
            .map(|anchor| anchor.source_handle.clone())
            .collect::<BTreeSet<_>>();
        source_handles.insert(evidence_id.to_owned());
        report.conflicts.push(SemanticConflict {
            subject: coordinate_handle.clone(),
            alternatives: vec![
                format!("existing graph node: {}", existing.kind),
                format!("LSP observation node: {}", node.kind),
            ],
            source_handles: source_handles.into_iter().collect(),
        });
        add_lsp_anchor(report, &node, &coordinate_handle, evidence_id);
        return Ok(true);
    }
    if report.nodes.len() >= request.max_nodes {
        return Ok(false);
    }
    add_lsp_anchor(report, &node, &coordinate_handle, evidence_id);
    report.nodes.push(node);
    Ok(true)
}

fn add_lsp_anchor(
    report: &mut CodeCortexReport,
    node: &GraphNode,
    coordinate_handle: &str,
    evidence_id: &str,
) {
    if report
        .entrypoints
        .iter()
        .any(|anchor| anchor.handle == coordinate_handle && anchor.source_handle == evidence_id)
    {
        return;
    }
    report.entrypoints.push(SemanticAnchor {
        handle: coordinate_handle.to_owned(),
        label: node.label.clone().unwrap_or_else(|| node.kind.clone()),
        source_handle: evidence_id.to_owned(),
    });
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
