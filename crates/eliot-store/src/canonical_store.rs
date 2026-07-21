use crate::surreal_server::SurrealServerSupervisor;
use crate::{
    CanonicalAutonomyRunView, CanonicalLifecycleView, CanonicalRecord, CanonicalReplayView,
    CanonicalSleepView, MAX_CANONICAL_RECORDS, NamedSurqlOp, SleepCandidatesResponse, StoreError,
    SurqlTemplateRegistry,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use eliot_types::{
    AutonomyRunContract, AutonomyRunTransitionReceipt, BlobReachabilityRef, BlobReferenceSnapshot,
    BlobRetentionClass, BlobRetentionRef, CanonicalMetaMetricEvidence,
    CanonicalReplayExecutionRecord, CanonicalTraceCompletenessContract, ClaimId,
    CurrentStateRequest, CurrentStateResponse, EpistemicStatus, ExperimentalMetaPolicyCandidate,
    FetchAtomsL2Request, FetchAtomsL2Response, GraphHealthResponse, HarnessExperimentRecord,
    LifecycleStatus, MemoryRevision, MemoryStateTransition, MemoryTrajectoryCorrectness,
    MemoryWriteEnvelope, MetaIsolationRejectionRecord, MetaPolicyExecutionAction,
    MetaPolicyExecutionReceipt, MinorityPressureRecord, ProjectId, ProjectSequence,
    RecallL0Request, RecallL0Response, ReplayAudit, ReplayRun, SealedReplayCaseRecord,
    SealedReplayInputSnapshotRecord, SealedReplaySetRecord, SleepCandidateArtifact,
    SleepConsolidationBundle, SleepConsolidationRun, SurrealServerConfig, TaintClass, TaskContract,
    TaskId, ToolObservation, VerificationId, VerificationRun, Visibility, WriteId, WriteReceipt,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use time::OffsetDateTime;
use tokio::time::{Duration, sleep};

const SCHEMA_MIGRATE_RETRY_ATTEMPTS: u8 = 30;
const SCHEMA_MIGRATE_RETRY_BASE_MS: u64 = 50;
const SCHEMA_MIGRATE_RETRY_MAX_MS: u64 = 500;
const MAX_BLOB_REFERENCE_RECORDS: u16 = 512;
const MAX_EXACT_L2_HANDLES: usize = 64;
const MAX_EXACT_L2_REQUEST_HANDLES: usize = 512;
const MAX_EXACT_L2_HANDLE_BYTES: usize = 512;
const SECRET_SCAN_PAGE_SIZE: usize = 50;
const SECRET_SCAN_MAX_RECORDS_PER_TABLE: usize = 10_000;
const SECRET_SCAN_TABLES: &[&str] = &[
    "scope_head",
    "task_contract",
    "source_snapshot",
    "evidence_atom",
    "tool_observation",
    "claim_card",
    "verification_run",
    "failure_fingerprint",
    "write_receipt",
    "memory_transition",
    "canonical_record",
    "trace_span",
    "context_packet_receipt",
    "supports",
    "verified_by",
    "contradicts",
    "supersedes",
    "mentions",
    "belongs_to",
    "produced_by",
    "invalidated_by",
];

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CanonicalSecretScanFinding {
    pub table: String,
    pub record_ordinal: u64,
    pub value_fingerprint: String,
    pub secret_kind: String,
    pub active_credential: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
pub struct CanonicalSecretScanReport {
    pub schema_version: String,
    pub scanner_version: String,
    pub complete: bool,
    pub tables_scanned: usize,
    pub records_scanned: u64,
    pub bytes_scanned: u64,
    pub findings: Vec<CanonicalSecretScanFinding>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum L2HandleKind {
    Any,
    Claim,
    Evidence,
    Verification,
    Observation,
    Failure,
}

#[derive(Clone, Debug)]
struct L2Selector {
    kind: L2HandleKind,
    identity: String,
    public_handle: String,
}

#[derive(serde::Serialize)]
struct ExactL2Bindings {
    claims: Vec<Vec<String>>,
    evidence: Vec<Vec<String>>,
    verifications: Vec<Vec<String>>,
    observations: Vec<Vec<String>>,
    failures: Vec<Vec<String>>,
    relations: Vec<Vec<String>>,
}

fn parse_l2_selector(raw: &str) -> (L2HandleKind, &str, &'static str) {
    for (prefix, kind, canonical) in [
        ("claim:", L2HandleKind::Claim, "claim:"),
        ("claim_card:", L2HandleKind::Claim, "claim:"),
        ("evidence:", L2HandleKind::Evidence, "evidence:"),
        ("evidence_atom:", L2HandleKind::Evidence, "evidence:"),
        ("verification:", L2HandleKind::Verification, "verification:"),
        (
            "verification_run:",
            L2HandleKind::Verification,
            "verification:",
        ),
        ("observation:", L2HandleKind::Observation, "observation:"),
        (
            "tool_observation:",
            L2HandleKind::Observation,
            "observation:",
        ),
        ("failure:", L2HandleKind::Failure, "failure:"),
        ("failure_fingerprint:", L2HandleKind::Failure, "failure:"),
    ] {
        if let Some(identity) = raw.strip_prefix(prefix) {
            return (kind, identity, canonical);
        }
    }
    (L2HandleKind::Any, raw, "")
}

fn exact_l2_bindings(
    handles: &[String],
    continuation: Option<&str>,
) -> Result<(Vec<L2Selector>, ExactL2Bindings, Option<String>), StoreError> {
    let all_selectors = normalize_l2_selectors(handles)?;
    let (selectors, next_continuation) = l2_selector_page(all_selectors, continuation)?;
    let identities = |kind| l2_selector_identities(&selectors, kind);
    let bindings = ExactL2Bindings {
        claims: l2_fragment_lists(&identities(L2HandleKind::Claim)),
        evidence: l2_fragment_lists(&identities(L2HandleKind::Evidence)),
        verifications: l2_fragment_lists(&identities(L2HandleKind::Verification)),
        observations: l2_fragment_lists(&identities(L2HandleKind::Observation)),
        failures: l2_fragment_lists(&identities(L2HandleKind::Failure)),
        relations: l2_fragment_lists(&l2_relation_identities(&selectors)),
    };
    Ok((selectors, bindings, next_continuation))
}

fn normalize_l2_selectors(handles: &[String]) -> Result<Vec<L2Selector>, StoreError> {
    if handles.len() > MAX_EXACT_L2_REQUEST_HANDLES {
        return Err(StoreError::PolicyViolation(format!(
            "exact L2 handles exceed the request limit of {MAX_EXACT_L2_REQUEST_HANDLES}"
        )));
    }
    let mut all_selectors = Vec::with_capacity(handles.len());
    for raw in handles {
        let value = raw.trim();
        if value.is_empty() || value.len() > MAX_EXACT_L2_HANDLE_BYTES {
            return Err(StoreError::PolicyViolation(format!(
                "exact L2 handles must be non-empty and at most {MAX_EXACT_L2_HANDLE_BYTES} bytes"
            )));
        }
        let (kind, identity, canonical_prefix) = parse_l2_selector(value);
        if identity.is_empty() {
            return Err(StoreError::PolicyViolation(
                "exact L2 typed handle has an empty identity".to_owned(),
            ));
        }
        let duplicate = all_selectors.iter().any(|selector: &L2Selector| {
            selector.identity == identity
                && (selector.kind == kind
                    || selector.kind == L2HandleKind::Any
                    || kind == L2HandleKind::Any)
        });
        if !duplicate {
            all_selectors.push(L2Selector {
                kind,
                identity: identity.to_owned(),
                public_handle: format!("{canonical_prefix}{identity}"),
            });
        }
    }
    Ok(all_selectors)
}

fn l2_selector_page(
    all_selectors: Vec<L2Selector>,
    continuation: Option<&str>,
) -> Result<(Vec<L2Selector>, Option<String>), StoreError> {
    let selector_hash = blake3::hash(
        &serde_json::to_vec(
            &all_selectors
                .iter()
                .map(|selector| &selector.public_handle)
                .collect::<Vec<_>>(),
        )
        .map_err(|error| StoreError::Decode(error.to_string()))?,
    )
    .to_hex()
    .to_string();
    let start = match continuation {
        None => 0,
        Some(token) => {
            let parts = token.split(':').collect::<Vec<_>>();
            if parts.len() != 3 || parts[0] != "l2" || parts[2] != &selector_hash[..16] {
                return Err(StoreError::PolicyViolation(
                    "exact L2 continuation is invalid for this normalized handle list".to_owned(),
                ));
            }
            let start = usize::from_str_radix(parts[1], 16).map_err(|_| {
                StoreError::PolicyViolation("exact L2 continuation offset is invalid".to_owned())
            })?;
            if start > all_selectors.len() || start % MAX_EXACT_L2_HANDLES != 0 {
                return Err(StoreError::PolicyViolation(
                    "exact L2 continuation offset is outside the bounded result set".to_owned(),
                ));
            }
            start
        }
    };
    let total_selectors = all_selectors.len();
    let selectors = all_selectors
        .into_iter()
        .skip(start)
        .take(MAX_EXACT_L2_HANDLES)
        .collect::<Vec<_>>();
    let next_start = start.saturating_add(selectors.len());
    let next_continuation = (next_start < total_selectors)
        .then(|| format!("l2:{next_start:x}:{}", &selector_hash[..16]));
    Ok((selectors, next_continuation))
}

fn l2_selector_identities(selectors: &[L2Selector], kind: L2HandleKind) -> Vec<String> {
    selectors
        .iter()
        .filter(|selector| matches!(selector.kind, L2HandleKind::Any) || selector.kind == kind)
        .map(|selector| selector.identity.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn l2_relation_identities(selectors: &[L2Selector]) -> Vec<String> {
    let mut relation_ids = BTreeSet::new();
    for selector in selectors {
        relation_ids.insert(selector.identity.clone());
        for prefix in [
            "claim:",
            "claim_card:",
            "evidence:",
            "evidence_atom:",
            "verification:",
            "verification_run:",
            "observation:",
            "tool_observation:",
            "failure:",
            "failure_fingerprint:",
        ] {
            relation_ids.insert(format!("{prefix}{}", selector.identity));
        }
    }
    relation_ids.into_iter().collect()
}

fn l2_fragment_lists(values: &[String]) -> Vec<Vec<String>> {
    values.iter().map(|value| string_fragments(value)).collect()
}

fn selector_matches(selector: &L2Selector, kind: L2HandleKind, identity: &str) -> bool {
    selector.identity == identity && (selector.kind == L2HandleKind::Any || selector.kind == kind)
}

fn selector_position(selectors: &[L2Selector], kind: L2HandleKind, identity: &str) -> usize {
    selectors
        .iter()
        .position(|selector| selector_matches(selector, kind, identity))
        .unwrap_or(usize::MAX)
}

fn finalize_exact_l2_response(
    response: &mut FetchAtomsL2Response,
    selectors: &[L2Selector],
    continuation: Option<String>,
) {
    sort_exact_l2_response(response, selectors);
    classify_exact_l2_handles(response, selectors);
    response.continuation = continuation;
    response.truncation.truncated |= response.continuation.is_some();
    response.truncation.limit = MAX_EXACT_L2_HANDLES;
    response.truncation.returned = response.evidence_atoms.len()
        + response.claims.len()
        + response.verification_runs.len()
        + response.tool_observations.len()
        + response.failure_fingerprints.len()
        + response.relations.len();
}

fn sort_exact_l2_response(response: &mut FetchAtomsL2Response, selectors: &[L2Selector]) {
    response.evidence_atoms.sort_by_cached_key(|record| {
        let identity = record.evidence_id.to_string();
        (
            selector_position(selectors, L2HandleKind::Evidence, &identity),
            identity,
        )
    });
    response.claims.sort_by_cached_key(|record| {
        let identity = record.claim_id.to_string();
        (
            selector_position(selectors, L2HandleKind::Claim, &identity),
            identity,
        )
    });
    response.verification_runs.sort_by_cached_key(|record| {
        let identity = record.verification_id.to_string();
        (
            selector_position(selectors, L2HandleKind::Verification, &identity),
            identity,
        )
    });
    response.tool_observations.sort_by_cached_key(|record| {
        (
            selector_position(selectors, L2HandleKind::Observation, &record.observation_id),
            record.observation_id.clone(),
        )
    });
    response.failure_fingerprints.sort_by_cached_key(|record| {
        (
            selector_position(selectors, L2HandleKind::Failure, &record.fingerprint),
            record.fingerprint.clone(),
        )
    });
    response.relations.sort_by_key(|relation| {
        (
            relation.from.clone(),
            relation.to.clone(),
            format!("{:?}", relation.relation_type),
        )
    });
}

fn resolved_exact_l2_handles(response: &FetchAtomsL2Response) -> HashSet<(L2HandleKind, String)> {
    let mut resolved = HashSet::new();
    resolved.extend(
        response
            .claims
            .iter()
            .map(|record| (L2HandleKind::Claim, record.claim_id.to_string())),
    );
    resolved.extend(
        response
            .evidence_atoms
            .iter()
            .map(|record| (L2HandleKind::Evidence, record.evidence_id.to_string())),
    );
    resolved.extend(response.verification_runs.iter().map(|record| {
        (
            L2HandleKind::Verification,
            record.verification_id.to_string(),
        )
    }));
    resolved.extend(
        response
            .tool_observations
            .iter()
            .map(|record| (L2HandleKind::Observation, record.observation_id.clone())),
    );
    resolved.extend(
        response
            .failure_fingerprints
            .iter()
            .map(|record| (L2HandleKind::Failure, record.fingerprint.clone())),
    );
    resolved
}

fn classify_exact_l2_handles(response: &mut FetchAtomsL2Response, selectors: &[L2Selector]) {
    let resolved = resolved_exact_l2_handles(response);
    let forbidden_typed = response
        .forbidden_handles
        .iter()
        .map(|handle| {
            let (kind, identity, _) = parse_l2_selector(handle);
            (kind, identity.to_owned())
        })
        .collect::<HashSet<_>>();
    response.requested_handles = selectors
        .iter()
        .map(|selector| selector.public_handle.clone())
        .collect();
    response.returned_handles.clear();
    response.missing_handles.clear();
    response.forbidden_handles.clear();
    for selector in selectors {
        let is_resolved = resolved
            .iter()
            .any(|(kind, identity)| selector_matches(selector, *kind, identity));
        let is_forbidden = forbidden_typed
            .iter()
            .any(|(kind, identity)| selector_matches(selector, *kind, identity));
        if is_resolved {
            response
                .returned_handles
                .push(selector.public_handle.clone());
        } else if is_forbidden {
            response
                .forbidden_handles
                .push(selector.public_handle.clone());
        } else {
            response
                .missing_handles
                .push(selector.public_handle.clone());
        }
    }
}

#[derive(Clone, Debug)]
pub struct CanonicalStore {
    config: SurrealServerConfig,
    registry: SurqlTemplateRegistry,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CanonicalToolObservation {
    pub observation_id: String,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub scope: String,
    pub authority: String,
    pub tool_name: String,
    pub observation: String,
    pub payload: Value,
    pub memory_revision: MemoryRevision,
    pub project_sequence: ProjectSequence,
    pub write_id: WriteId,
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct CanonicalClaimCard {
    pub claim_id: ClaimId,
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub scope: String,
    pub status: EpistemicStatus,
    pub lifecycle_status: LifecycleStatus,
    pub visibility: Visibility,
    pub taint: TaintClass,
    pub authority: String,
    pub statement: String,
    pub payload: Value,
    pub memory_revision: MemoryRevision,
    pub project_sequence: ProjectSequence,
    pub write_id: WriteId,
}

struct ReplayIntegrityRecords {
    trace_contracts: Vec<CanonicalRecord<CanonicalTraceCompletenessContract>>,
    sealed_sets: Vec<CanonicalRecord<SealedReplaySetRecord>>,
    sealed_cases: Vec<CanonicalRecord<SealedReplayCaseRecord>>,
    sealed_snapshots: Vec<CanonicalRecord<SealedReplayInputSnapshotRecord>>,
    sealed_executions: Vec<CanonicalRecord<CanonicalReplayExecutionRecord>>,
}

struct MetaIntegrityRecords {
    metrics: Vec<CanonicalRecord<CanonicalMetaMetricEvidence>>,
    isolation_rejections: Vec<CanonicalRecord<MetaIsolationRejectionRecord>>,
    policy_candidates: Vec<CanonicalRecord<ExperimentalMetaPolicyCandidate>>,
    policy_executions: Vec<CanonicalRecord<MetaPolicyExecutionReceipt>>,
}

impl CanonicalStore {
    pub fn new(config: SurrealServerConfig) -> Self {
        Self {
            config,
            registry: SurqlTemplateRegistry::default(),
        }
    }

    pub async fn migrate_schema(&self) -> Result<Value, StoreError> {
        let vars = Value::Object(serde_json::Map::new());
        let mut attempts = 0u8;
        loop {
            match self
                .execute_value(NamedSurqlOp::SchemaMigrate, vars.clone())
                .await
            {
                Ok(value) => return Ok(value),
                Err(error)
                    if is_retryable_schema_conflict(&error)
                        && attempts < SCHEMA_MIGRATE_RETRY_ATTEMPTS =>
                {
                    attempts = attempts.saturating_add(1);
                    let delay_ms = (SCHEMA_MIGRATE_RETRY_BASE_MS * u64::from(attempts))
                        .min(SCHEMA_MIGRATE_RETRY_MAX_MS);
                    sleep(Duration::from_millis(delay_ms)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Privileged deterministic secret scan over canonical records. Raw rows
    /// and credential material never leave the store boundary.
    pub async fn privileged_secret_scan(&self) -> Result<CanonicalSecretScanReport, StoreError> {
        let supervisor = SurrealServerSupervisor::new(self.config.clone());
        let server = supervisor.start_or_connect().await?;
        let report_result = async {
            let mut report = CanonicalSecretScanReport {
                schema_version: "eliot-canonical-secret-scan-v1".to_owned(),
                scanner_version: "l14-canonical-secret-scan-v1".to_owned(),
                complete: true,
                tables_scanned: 0,
                records_scanned: 0,
                bytes_scanned: 0,
                findings: Vec::new(),
            };
            for table in SECRET_SCAN_TABLES {
                report.tables_scanned += 1;
                let mut start = 0usize;
                loop {
                    let sql = format!(
                        "SELECT * FROM {table} LIMIT {SECRET_SCAN_PAGE_SIZE} START {start};"
                    );
                    let raw = server
                        .transport()
                        .query(&sql, Value::Object(serde_json::Map::new()))
                        .await?;
                    let records = secret_scan_query_records(table, &raw)?;
                    if records.is_empty() {
                        break;
                    }
                    for (page_index, record) in records.iter().enumerate() {
                        let bytes = serde_json::to_vec(record)
                            .map_err(|error| StoreError::Decode(error.to_string()))?;
                        report.records_scanned = report.records_scanned.saturating_add(1);
                        report.bytes_scanned = report
                            .bytes_scanned
                            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
                        let active_fingerprint =
                            supervisor.active_credential_fingerprint_if_exposed(&bytes)?;
                        let boundary = eliot_types::inspect_secret_bytes(&bytes).err();
                        if active_fingerprint.is_some() || boundary.is_some() {
                            let active_credential = active_fingerprint.is_some();
                            let value_fingerprint = active_fingerprint
                                .unwrap_or_else(|| format!("{:x}", Sha256::digest(&bytes)));
                            report.findings.push(CanonicalSecretScanFinding {
                                table: (*table).to_owned(),
                                record_ordinal: u64::try_from(start.saturating_add(page_index))
                                    .unwrap_or(u64::MAX),
                                value_fingerprint,
                                secret_kind: if active_credential {
                                    "active_database_credential".to_owned()
                                } else {
                                    boundary.map_or_else(
                                        || "unknown".to_owned(),
                                        |violation| violation.rule.as_str().to_owned(),
                                    )
                                },
                                active_credential,
                            });
                        }
                    }
                    start = start.saturating_add(records.len());
                    if records.len() < SECRET_SCAN_PAGE_SIZE {
                        break;
                    }
                    if start >= SECRET_SCAN_MAX_RECORDS_PER_TABLE {
                        report.complete = false;
                        break;
                    }
                }
            }
            Ok::<CanonicalSecretScanReport, StoreError>(report)
        }
        .await;
        let shutdown_result = server.shutdown_if_spawned().await;
        let report = report_result?;
        shutdown_result?;
        Ok(report)
    }

    pub async fn apply_write_envelope(
        &self,
        envelope: &MemoryWriteEnvelope,
    ) -> Result<WriteReceipt, StoreError> {
        let canonical_payloads = canonical_payloads(envelope)?;
        let value = self
            .execute_value(
                NamedSurqlOp::ApplyWriteEnvelope,
                json!({
                    "envelope": envelope,
                    "canonical_payloads": canonical_payloads,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::ApplyWriteEnvelope, value)
    }

    pub async fn current_state(
        &self,
        request: &CurrentStateRequest,
    ) -> Result<CurrentStateResponse, StoreError> {
        let value = self
            .execute_value(NamedSurqlOp::CurrentState, json!({ "request": request }))
            .await?;
        decode_value(NamedSurqlOp::CurrentState, value)
    }

    pub async fn recall_l0(
        &self,
        request: &RecallL0Request,
    ) -> Result<RecallL0Response, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::RecallL0,
                json!({
                    "request": request,
                    "query_fragments": string_fragments(&request.query),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::RecallL0, value)
    }

    pub async fn fetch_atoms_l2(
        &self,
        request: &FetchAtomsL2Request,
    ) -> Result<FetchAtomsL2Response, StoreError> {
        let (selectors, exact, continuation) =
            exact_l2_bindings(&request.handles, request.continuation.as_deref())?;
        let op = if selectors.is_empty() {
            NamedSurqlOp::FetchAtomsL2Legacy
        } else {
            NamedSurqlOp::FetchAtomsL2
        };
        let value = self
            .execute_value(op, json!({ "request": request, "exact": exact }))
            .await?;
        let mut response = decode_value(op, value)?;
        if !selectors.is_empty() {
            finalize_exact_l2_response(&mut response, &selectors, continuation);
        }
        Ok(response)
    }

    pub async fn graph_health(&self) -> Result<GraphHealthResponse, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::GraphHealth,
                Value::Object(serde_json::Map::new()),
            )
            .await?;
        decode_value(NamedSurqlOp::GraphHealth, value)
    }

    pub async fn writer_receipts(&self) -> Result<Value, StoreError> {
        self.execute_value(
            NamedSurqlOp::WriterReceipts,
            Value::Object(serde_json::Map::new()),
        )
        .await
    }

    pub async fn write_receipt_by_id(
        &self,
        write_id: &eliot_types::WriteId,
    ) -> Result<Option<WriteReceipt>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::WriteReceiptById,
                json!({ "write_id": write_id }),
            )
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        decode_value(NamedSurqlOp::WriteReceiptById, value).map(Some)
    }

    pub async fn tool_observations_by_write_id(
        &self,
        write_id: &WriteId,
    ) -> Result<Vec<CanonicalToolObservation>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::ToolObservationByWriteId,
                json!({ "write_id": write_id }),
            )
            .await?;
        decode_value(NamedSurqlOp::ToolObservationByWriteId, value)
    }

    pub async fn latest_authority_observations_by_entity(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        entity_kind: &str,
        entity_ref: &str,
    ) -> Result<Vec<CanonicalToolObservation>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LatestAuthorityObservationsByEntity,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "has_task_id": task_id.is_some(),
                    "entity_kind": entity_kind,
                    "entity_ref_fragments": string_fragments(entity_ref),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::LatestAuthorityObservationsByEntity, value)
    }

    pub async fn task_contract_by_id(
        &self,
        task_id: TaskId,
    ) -> Result<Option<TaskContract>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::TaskContractById,
                json!({ "task_id": task_id }),
            )
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        decode_value(NamedSurqlOp::TaskContractById, value).map(Some)
    }

    pub async fn tool_observations_by_kind(
        &self,
        project_id: eliot_types::ProjectId,
        task_id: TaskId,
        receipt_kind: &str,
    ) -> Result<Vec<ToolObservation>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::ToolObservationsByKind,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "receipt_kind": receipt_kind,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::ToolObservationsByKind, value)
    }

    pub async fn experience_pattern_revisions_by_id(
        &self,
        project_id: eliot_types::ProjectId,
        task_id: TaskId,
        pattern_id: &str,
    ) -> Result<Vec<CanonicalToolObservation>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::ExperiencePatternRevisionsById,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "pattern_id": pattern_id,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::ExperiencePatternRevisionsById, value)
    }

    pub async fn tool_observation_by_id(
        &self,
        observation_id: &str,
    ) -> Result<Option<ToolObservation>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::ToolObservationById,
                json!({ "observation_id": observation_id }),
            )
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        decode_value(NamedSurqlOp::ToolObservationById, value).map(Some)
    }

    pub async fn semantic_records_by_kind(
        &self,
        project_id: eliot_types::ProjectId,
        receipt_kind: &str,
    ) -> Result<Vec<ToolObservation>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::SemanticRecordsByKind,
                json!({
                    "project_id": project_id,
                    "receipt_kind": receipt_kind,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::SemanticRecordsByKind, value)
    }

    pub async fn claim_card_by_id(
        &self,
        project_id: ProjectId,
        claim_id: ClaimId,
    ) -> Result<Option<CanonicalClaimCard>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::ClaimCardById,
                json!({
                    "project_id": project_id,
                    "claim_id": claim_id,
                }),
            )
            .await?;
        let mut claims: Vec<CanonicalClaimCard> = decode_value(NamedSurqlOp::ClaimCardById, value)?;
        if claims.len() > 1 {
            return Err(StoreError::Decode(format!(
                "claim_id {claim_id} resolved to multiple canonical claim cards"
            )));
        }
        Ok(claims.pop())
    }

    pub async fn canonical_record_by_write_id<T>(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt_kinds: &[&str],
        write_id: WriteId,
    ) -> Result<Option<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        let value = self
            .execute_value(
                NamedSurqlOp::CanonicalRecordByWriteId,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "receipt_kinds": receipt_kinds,
                    "write_id": write_id,
                }),
            )
            .await?;
        let mut records: Vec<CanonicalRecord<T>> =
            decode_value(NamedSurqlOp::CanonicalRecordByWriteId, value)?;
        if records.len() > 1 {
            return Err(StoreError::Decode(format!(
                "canonical write_id {write_id} resolved to multiple records"
            )));
        }
        Ok(records.pop())
    }

    pub async fn canonical_record_page(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt_kinds: &[&str],
        start: u64,
        limit: u16,
    ) -> Result<Vec<CanonicalRecord<Value>>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::CanonicalRecordPage,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "receipt_kinds": receipt_kinds,
                    "start": start,
                    "limit": limit.clamp(1, 100),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::CanonicalRecordPage, value)
    }

    pub async fn curation_record_page(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        at_revision: MemoryRevision,
        start: u64,
        limit: u16,
    ) -> Result<Vec<CanonicalRecord<Value>>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::CurationRecordPage,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "at_revision": at_revision,
                    "start": start,
                    "limit": limit.clamp(1, 100),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::CurationRecordPage, value)
    }

    pub async fn canonical_records_by_subject_ref<T>(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt_kinds: &[&str],
        subject_ref: &str,
        limit: u16,
    ) -> Result<Vec<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        let value = self
            .execute_value(
                NamedSurqlOp::CanonicalRecordsBySubjectRef,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "receipt_kinds": receipt_kinds,
                    "subject_ref_fragments": string_fragments(subject_ref),
                    "limit": limit.clamp(1, MAX_CANONICAL_RECORDS),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::CanonicalRecordsBySubjectRef, value)
    }

    pub async fn canonical_records_by_kind<T>(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt_kinds: &[&str],
        limit: u16,
    ) -> Result<Vec<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        self.canonical_records(project_id, task_id, receipt_kinds, None, limit)
            .await
    }

    pub async fn meta_policy_actions_by_candidate(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        candidate_id: &str,
        action: MetaPolicyExecutionAction,
    ) -> Result<Vec<CanonicalRecord<MetaPolicyExecutionReceipt>>, StoreError> {
        let action = match action {
            MetaPolicyExecutionAction::Promote => "promote",
            MetaPolicyExecutionAction::Rollback => "rollback",
        };
        let value = self
            .execute_value(
                NamedSurqlOp::MetaPolicyActionsByCandidate,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "candidate_id_fragments": string_fragments(candidate_id),
                    "action_fragments": string_fragments(action),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::MetaPolicyActionsByCandidate, value)
    }

    pub async fn canonical_trace_by_trace_ref(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        trace_ref: &str,
    ) -> Result<Option<CanonicalRecord<CanonicalTraceCompletenessContract>>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::CanonicalTraceByTraceRef,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "trace_ref_fragments": string_fragments(trace_ref),
                }),
            )
            .await?;
        let mut records: Vec<CanonicalRecord<CanonicalTraceCompletenessContract>> =
            decode_value(NamedSurqlOp::CanonicalTraceByTraceRef, value)?;
        if records.len() > 1 {
            return Err(StoreError::Decode(format!(
                "canonical trace_ref {trace_ref} resolved to multiple records"
            )));
        }
        Ok(records.pop())
    }

    pub async fn lifecycle_view(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        subject_ref: Option<&str>,
        limit: u16,
    ) -> Result<CanonicalLifecycleView, StoreError> {
        let mut transitions = self
            .canonical_records::<MemoryStateTransition>(
                project_id,
                task_id,
                &["state_transition"],
                subject_ref,
                limit,
            )
            .await?;
        for record in &mut transitions {
            record.receipt_body.write_receipt = Some(record.canonical_receipt.clone());
        }
        let mut trajectories = self
            .canonical_records::<MemoryTrajectoryCorrectness>(
                project_id,
                task_id,
                &["memory_trajectory_correctness"],
                subject_ref,
                limit,
            )
            .await?;
        for record in &mut trajectories {
            record.receipt_body.write_receipt = Some(record.canonical_receipt.clone());
        }
        let mut minority_pressure = self
            .canonical_records::<MinorityPressureRecord>(
                project_id,
                task_id,
                &["minority_pressure_record"],
                subject_ref,
                limit,
            )
            .await?;
        for record in &mut minority_pressure {
            record.receipt_body.write_receipt = Some(record.canonical_receipt.clone());
        }
        Ok(CanonicalLifecycleView {
            transitions,
            trajectories,
            minority_pressure,
        })
    }

    pub async fn replay_view(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        limit: u16,
    ) -> Result<CanonicalReplayView, StoreError> {
        let integrity = self
            .replay_integrity_records(project_id, task_id, limit)
            .await?;
        let meta = self
            .meta_integrity_records(project_id, task_id, limit)
            .await?;
        let replay_runs = self
            .canonical_records::<ReplayRun>(project_id, task_id, &["replay_run"], None, limit)
            .await?;
        let replay_audits = self
            .canonical_records::<ReplayAudit>(project_id, task_id, &["replay_audit"], None, limit)
            .await?;
        let mut harness_experiments = self
            .canonical_records::<HarnessExperimentRecord>(
                project_id,
                task_id,
                &["harness_experiment", "harness_disposition"],
                None,
                limit,
            )
            .await?;
        for record in &mut harness_experiments {
            if record.receipt_kind == "harness_disposition" {
                record.receipt_body.disposition_receipt = Some(record.canonical_receipt.clone());
            }
        }
        Ok(CanonicalReplayView {
            trace_contracts: integrity.trace_contracts,
            sealed_sets: integrity.sealed_sets,
            sealed_cases: integrity.sealed_cases,
            sealed_snapshots: integrity.sealed_snapshots,
            sealed_executions: integrity.sealed_executions,
            replay_runs,
            replay_audits,
            harness_experiments,
            meta_metrics: meta.metrics,
            isolation_rejections: meta.isolation_rejections,
            policy_candidates: meta.policy_candidates,
            policy_executions: meta.policy_executions,
        })
    }

    async fn replay_integrity_records(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        limit: u16,
    ) -> Result<ReplayIntegrityRecords, StoreError> {
        let trace_contracts = self
            .canonical_records(
                project_id,
                task_id,
                &["trace_completeness_contract"],
                None,
                limit,
            )
            .await?;
        let sealed_sets = self
            .canonical_records(project_id, task_id, &["replay_set"], None, limit)
            .await?;
        let sealed_cases = self
            .canonical_records(project_id, task_id, &["replay_case"], None, limit)
            .await?;
        let sealed_snapshots = self
            .canonical_records(project_id, task_id, &["replay_input_snapshot"], None, limit)
            .await?;
        let sealed_executions = self
            .canonical_records(project_id, task_id, &["sealed_replay_run"], None, limit)
            .await?;
        Ok(ReplayIntegrityRecords {
            trace_contracts,
            sealed_sets,
            sealed_cases,
            sealed_snapshots,
            sealed_executions,
        })
    }

    async fn meta_integrity_records(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        limit: u16,
    ) -> Result<MetaIntegrityRecords, StoreError> {
        let metrics = self
            .canonical_records(project_id, task_id, &["meta_metric_evidence"], None, limit)
            .await?;
        let isolation_rejections = self
            .canonical_records(
                project_id,
                task_id,
                &["meta_isolation_rejection"],
                None,
                limit,
            )
            .await?;
        let policy_candidates = self
            .canonical_records(
                project_id,
                task_id,
                &["experimental_policy_candidate"],
                None,
                limit,
            )
            .await?;
        let policy_executions = self
            .canonical_records(
                project_id,
                task_id,
                &["meta_policy_promotion", "meta_policy_rollback"],
                None,
                limit,
            )
            .await?;
        Ok(MetaIntegrityRecords {
            metrics,
            isolation_rejections,
            policy_candidates,
            policy_executions,
        })
    }

    pub async fn autonomy_run_view(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        autonomy_run_id: &str,
        limit: u16,
    ) -> Result<CanonicalAutonomyRunView, StoreError> {
        let mut contracts = self
            .canonical_records::<AutonomyRunContract>(
                project_id,
                Some(task_id),
                &["autonomy_run_contract"],
                Some(autonomy_run_id),
                limit,
            )
            .await?;
        let mut transitions = self
            .canonical_records::<AutonomyRunTransitionReceipt>(
                project_id,
                Some(task_id),
                &["autonomy_run_transition"],
                Some(autonomy_run_id),
                limit,
            )
            .await?;
        for record in &mut transitions {
            record.receipt_body.canonical_receipt = Some(record.canonical_receipt.clone());
        }
        let budget_ledgers = self
            .canonical_records(
                project_id,
                Some(task_id),
                &["autonomy_budget_ledger"],
                Some(autonomy_run_id),
                limit,
            )
            .await?;
        let work_graphs = self
            .canonical_records(
                project_id,
                Some(task_id),
                &["autonomy_work_graph"],
                Some(autonomy_run_id),
                limit,
            )
            .await?;
        let tripwires = self
            .canonical_records(
                project_id,
                Some(task_id),
                &["autonomy_tripwire"],
                Some(autonomy_run_id),
                limit,
            )
            .await?;
        let recoveries = self
            .canonical_records(
                project_id,
                Some(task_id),
                &["autonomy_recovery"],
                Some(autonomy_run_id),
                limit,
            )
            .await?;
        Ok(CanonicalAutonomyRunView {
            contract: contracts.pop(),
            transitions,
            budget_ledgers,
            work_graphs,
            tripwires,
            recoveries,
        })
    }

    pub async fn sleep_candidates(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        limit: u16,
    ) -> Result<SleepCandidatesResponse, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::SleepCandidates,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "limit": limit.clamp(1, MAX_CANONICAL_RECORDS),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::SleepCandidates, value)
    }

    pub async fn sleep_view(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        limit: u16,
    ) -> Result<CanonicalSleepView, StoreError> {
        let bundles = self
            .canonical_records::<SleepConsolidationBundle>(
                project_id,
                task_id,
                &["sleep_consolidation_bundle"],
                None,
                limit,
            )
            .await?;
        let runs = self
            .canonical_records::<SleepConsolidationRun>(
                project_id,
                task_id,
                &["sleep_consolidation_run"],
                None,
                limit,
            )
            .await?;
        let artifacts = self
            .canonical_records::<SleepCandidateArtifact>(
                project_id,
                task_id,
                &[
                    "procedure_candidate",
                    "forgetting_candidate",
                    "test_candidate",
                    "replay_case_candidate",
                    "dream_candidate",
                ],
                None,
                limit,
            )
            .await?;
        Ok(CanonicalSleepView {
            bundles,
            runs,
            artifacts,
        })
    }

    pub async fn verification_run_by_id(
        &self,
        verification_id: VerificationId,
    ) -> Result<Option<VerificationRun>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::VerificationRunById,
                json!({ "verification_id": verification_id }),
            )
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        decode_value(NamedSurqlOp::VerificationRunById, value).map(Some)
    }

    pub async fn blob_reference_snapshot(
        &self,
        scope: &str,
        limit: u16,
    ) -> Result<BlobReferenceSnapshot, StoreError> {
        if scope.trim().is_empty() {
            return Err(StoreError::ConfigMessage(
                "blob reference scan scope must not be empty".to_owned(),
            ));
        }
        let limit = limit.clamp(1, MAX_BLOB_REFERENCE_RECORDS);
        let value = self
            .execute_value(NamedSurqlOp::BlobReferenceScan, json!({ "limit": limit }))
            .await?;
        build_blob_reference_snapshot(&self.config, scope, limit, &value)
    }

    async fn canonical_records<T>(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt_kinds: &[&str],
        subject_ref: Option<&str>,
        limit: u16,
    ) -> Result<Vec<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        let has_subject_ref = subject_ref.is_some();
        let subject_ref_fragments = subject_ref.map_or_else(Vec::new, string_fragments);
        let value = self
            .execute_value(
                NamedSurqlOp::CanonicalRecords,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "receipt_kinds": receipt_kinds,
                    "has_subject_ref": has_subject_ref,
                    "subject_ref_fragments": subject_ref_fragments,
                    "limit": limit.clamp(1, MAX_CANONICAL_RECORDS),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::CanonicalRecords, value)
    }

    async fn execute_value(&self, op: NamedSurqlOp, vars: Value) -> Result<Value, StoreError> {
        let template = self
            .registry
            .get(op)
            .ok_or_else(|| StoreError::ConfigMessage(format!("missing template {}", op.name())))?;
        let server = SurrealServerSupervisor::new(self.config.clone())
            .start_or_connect()
            .await?;
        let raw_result = server.transport().query(template.sql, vars).await;
        let shutdown_result = server.shutdown_if_spawned().await;
        let raw = raw_result?;
        shutdown_result?;
        let bytes =
            serde_json::to_vec(&raw).map_err(|error| StoreError::Decode(error.to_string()))?;
        if bytes.len() > template.max_result_bytes {
            return Err(StoreError::ResultTooLarge {
                bytes: bytes.len(),
                limit: template.max_result_bytes,
            });
        }
        last_query_result(op, &raw)
    }
}

fn build_blob_reference_snapshot(
    config: &SurrealServerConfig,
    scope: &str,
    limit: u16,
    value: &Value,
) -> Result<BlobReferenceSnapshot, StoreError> {
    let records = value
        .get("records")
        .and_then(Value::as_array)
        .ok_or_else(|| StoreError::Decode("blob reference scan omitted records".to_owned()))?;
    let scope_heads = value
        .get("scope_heads")
        .and_then(Value::as_array)
        .ok_or_else(|| StoreError::Decode("blob reference scan omitted scope heads".to_owned()))?;
    let complete = records.len() <= usize::from(limit)
        && scope_heads.len() <= usize::from(limit)
        && records.iter().chain(scope_heads).all(has_scan_record_ref);
    let bounded_records = records.iter().take(usize::from(limit)).collect::<Vec<_>>();
    let bounded_heads = scope_heads
        .iter()
        .take(usize::from(limit))
        .collect::<Vec<_>>();
    let mut reachable = BTreeMap::<(String, String), BlobReachabilityRef>::new();
    let mut retained = BTreeMap::<(String, String), BlobRetentionRef>::new();
    for record in &bounded_records {
        let record_ref = record
            .get("gc_record_ref")
            .and_then(Value::as_str)
            .unwrap_or("missing-canonical-record-ref");
        scan_blob_refs(record, record_ref, None, &mut reachable, &mut retained);
    }
    let source_store = format!("{}|{}|{}", config.endpoint, config.ns, config.db);
    let query_hash = blake3::hash(
        format!(
            "{}\nlimit={limit}\nscope={scope}",
            NamedSurqlOp::BlobReferenceScan.template()
        )
        .as_bytes(),
    )
    .to_hex()
    .to_string();
    let source_revision = blake3::hash(
        &serde_json::to_vec(&json!({
            "scope_heads": bounded_heads,
            "records": bounded_records,
        }))
        .map_err(|error| StoreError::Decode(error.to_string()))?,
    )
    .to_hex()
    .to_string();
    let reachable_refs = reachable.into_values().collect::<Vec<_>>();
    let retention_refs = retained.into_values().collect::<Vec<_>>();
    let snapshot_id = blake3::hash(
        &serde_json::to_vec(&json!({
            "source_store": source_store,
            "source_revision": source_revision,
            "scope": scope,
            "query_hash": query_hash,
            "complete": complete,
            "reachable_refs": reachable_refs,
            "retention_refs": retention_refs,
        }))
        .map_err(|error| StoreError::Decode(error.to_string()))?,
    )
    .to_hex()
    .to_string();
    Ok(BlobReferenceSnapshot {
        snapshot_id,
        source_store,
        source_revision,
        scope: scope.to_owned(),
        query_hash,
        created_at: OffsetDateTime::now_utc(),
        complete,
        records_scanned: u32::try_from(bounded_records.len()).unwrap_or(u32::MAX),
        reachable_refs,
        retention_refs,
    })
}

fn has_scan_record_ref(record: &Value) -> bool {
    record
        .get("gc_record_ref")
        .and_then(Value::as_str)
        .is_some_and(|value| !value.is_empty())
}

fn scan_blob_refs(
    value: &Value,
    record_ref: &str,
    inherited_retention: Option<BlobRetentionClass>,
    reachable: &mut BTreeMap<(String, String), BlobReachabilityRef>,
    retained: &mut BTreeMap<(String, String), BlobRetentionRef>,
) {
    match value {
        Value::Object(object) => {
            let retention = strongest_retention(typed_blob_retention(object), inherited_retention);
            if let (Some(algorithm), Some(blob_hash), Some(relative_path)) = (
                object.get("algorithm").and_then(Value::as_str),
                object.get("digest_hex").and_then(Value::as_str),
                object.get("relative_path").and_then(Value::as_str),
            ) && algorithm.eq_ignore_ascii_case("blake3")
                && is_blake3_hex(blob_hash)
                && !relative_path.trim().is_empty()
            {
                let key = (blob_hash.to_owned(), record_ref.to_owned());
                reachable
                    .entry(key.clone())
                    .or_insert_with(|| BlobReachabilityRef {
                        blob_hash: blob_hash.to_owned(),
                        canonical_record_ref: record_ref.to_owned(),
                    });
                if let Some(retention) = retention.filter(|class| {
                    matches!(
                        class,
                        BlobRetentionClass::AuditRetained | BlobRetentionClass::LegalHold
                    )
                }) {
                    retained.insert(
                        key,
                        BlobRetentionRef {
                            blob_hash: blob_hash.to_owned(),
                            canonical_record_ref: record_ref.to_owned(),
                            retention,
                        },
                    );
                }
            }
            for child in object.values() {
                scan_blob_refs(child, record_ref, retention, reachable, retained);
            }
        }
        Value::Array(values) => {
            for child in values {
                scan_blob_refs(child, record_ref, inherited_retention, reachable, retained);
            }
        }
        _ => {}
    }
}

fn typed_blob_retention(object: &serde_json::Map<String, Value>) -> Option<BlobRetentionClass> {
    ["blob_retention", "retention_class", "retention"]
        .into_iter()
        .filter_map(|field| object.get(field).and_then(Value::as_str))
        .find_map(|value| match value {
            "audit_retained" => Some(BlobRetentionClass::AuditRetained),
            "legal_hold" => Some(BlobRetentionClass::LegalHold),
            "standard" => Some(BlobRetentionClass::Standard),
            _ => None,
        })
}

fn strongest_retention(
    left: Option<BlobRetentionClass>,
    right: Option<BlobRetentionClass>,
) -> Option<BlobRetentionClass> {
    [left, right]
        .into_iter()
        .flatten()
        .max_by_key(|class| match class {
            BlobRetentionClass::Standard => 0,
            BlobRetentionClass::AuditRetained => 1,
            BlobRetentionClass::LegalHold => 2,
        })
}

fn is_blake3_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn canonical_payloads(envelope: &MemoryWriteEnvelope) -> Result<Vec<Value>, StoreError> {
    envelope
        .tool_observations
        .iter()
        .filter_map(|observation| {
            observation
                .payload
                .get("receipt_body")
                .filter(|body| !body.is_null())
                .map(|body| (observation, body))
        })
        .map(|(observation, body)| {
            let body_bytes =
                serde_json::to_vec(body).map_err(|error| StoreError::Decode(error.to_string()))?;
            let subject_ref = canonical_subject_ref(
                observation
                    .payload
                    .get("receipt_kind")
                    .and_then(Value::as_str),
                body,
            )
            .unwrap_or(&observation.observation_id);
            Ok(json!({
                "observation_id": observation.observation_id,
                "receipt_body_json_b64": STANDARD_NO_PAD.encode(body_bytes),
                "subject_ref_fragments": string_fragments(subject_ref),
                "trace_ref_fragments": canonical_field_fragments(body, "trace_ref"),
                "candidate_id_fragments": canonical_field_fragments(body, "candidate_id"),
                "action_fragments": canonical_field_fragments(body, "action"),
            }))
        })
        .collect()
}

fn canonical_field_fragments(body: &Value, field: &str) -> Vec<String> {
    body.get(field)
        .and_then(Value::as_str)
        .map_or_else(Vec::new, string_fragments)
}

fn canonical_subject_ref<'a>(receipt_kind: Option<&str>, body: &'a Value) -> Option<&'a str> {
    let exact_field = match receipt_kind {
        Some("procedure_skill_candidate" | "procedure_promotion_disposition") => {
            Some("candidate_ref")
        }
        Some("agent_result" | "agent_result_disposition") => Some("result_id"),
        Some("candidate_diff" | "candidate_review") => Some("candidate_diff_id"),
        Some("worktree_lease") => Some("worktree_lease_id"),
        Some("work_lease") => Some("work_lease_id"),
        Some("controller_lease") => Some("controller_lease_id"),
        Some("operation_job") => Some("job_id"),
        Some("agent_invocation_request") => Some("invocation_id"),
        Some("managed_finalization_intent" | "managed_finalization_aggregate") => {
            Some("finalization_id")
        }
        Some("cognitive_tool_observation") => Some("call_subject_ref"),
        Some(
            "cognitive_run_contract"
            | "cognitive_run_attempt"
            | "cognitive_raw_verifier"
            | "cognitive_run_terminal",
        ) => Some("run_id"),
        _ => None,
    };
    if let Some(field) = exact_field {
        return body.get(field).and_then(Value::as_str);
    }
    [
        "target_ref",
        "minority_claim_ref",
        "replay_run_id",
        "harness_experiment_record_id",
        "contract_id",
        "trace_ref",
        "execution_id",
        "sealed_hash",
        "candidate_id",
        "source_experiment_ref",
        "evidence_hash",
        "artifact_id",
        "autonomy_run_id",
        "sleep_run_id",
        "bundle_id",
    ]
    .into_iter()
    .find_map(|field| body.get(field).and_then(Value::as_str))
}

fn string_fragments(value: &str) -> Vec<String> {
    value
        .chars()
        .map(|character| character.to_string())
        .collect()
}

fn is_retryable_schema_conflict(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::QueryFailed { message, .. }
            if message.contains("Transaction conflict") || message.contains("can be retried")
    )
}

fn secret_scan_query_records(table: &str, raw: &Value) -> Result<Vec<Value>, StoreError> {
    let Value::Array(results) = raw else {
        return Err(StoreError::QueryFailed {
            op: "privileged_secret_scan".to_owned(),
            message: format!("canonical table {table} response was not an array"),
            raw: Value::Null,
        });
    };
    let mut records = Vec::new();
    for result in results {
        if result.get("status").and_then(Value::as_str) == Some("ERR") {
            return Err(StoreError::QueryFailed {
                op: "privileged_secret_scan".to_owned(),
                message: format!("canonical table {table} scan query failed"),
                raw: Value::Null,
            });
        }
        if let Some(values) = result.get("result").and_then(Value::as_array) {
            records.extend(values.iter().cloned());
        }
    }
    Ok(records)
}

fn last_query_result(op: NamedSurqlOp, raw: &Value) -> Result<Value, StoreError> {
    let Value::Array(results) = raw else {
        return Err(StoreError::QueryFailed {
            op: op.name().to_owned(),
            message: "query response was not an array".to_owned(),
            raw: raw.clone(),
        });
    };

    let mut last = Value::Null;
    for result in results {
        if result.get("status").and_then(Value::as_str) == Some("ERR") {
            let message = result
                .get("result")
                .and_then(Value::as_str)
                .unwrap_or("SurrealDB query returned ERR")
                .to_owned();
            return Err(StoreError::QueryFailed {
                op: op.name().to_owned(),
                message,
                raw: raw.clone(),
            });
        }
        if let Some(value) = result.get("result") {
            last = value.clone();
        }
    }

    Ok(last)
}

fn decode_value<T>(op: NamedSurqlOp, value: Value) -> Result<T, StoreError>
where
    T: DeserializeOwned,
{
    serde_json::from_value(value)
        .map_err(|error| StoreError::Decode(format!("{} output decode failed: {error}", op.name())))
}
