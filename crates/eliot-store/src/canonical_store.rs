use crate::surreal_server::{ReadySurrealServer, SurrealServerSupervisor};
use crate::{
    CanonicalAutonomyRunView, CanonicalLifecycleView, CanonicalRecord, CanonicalReplayView,
    CanonicalSleepView, DbClientSet, MAX_CANONICAL_RECORDS, NamedSurqlOp, SleepCandidatesResponse,
    StoreError, SurqlTemplateRegistry,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use eliot_types::{
    AutonomyRunContract, AutonomyRunTransitionReceipt, BlobReachabilityRef, BlobReferenceSnapshot,
    BlobRetentionClass, BlobRetentionRef, CanonicalMetaMetricEvidence,
    CanonicalReplayExecutionRecord, CanonicalTraceCompletenessContract, ClaimId, CueIndexRow,
    CueRecordSource, CurrentStateRequest, CurrentStateResponse, EpistemicStatus,
    ExperimentalMetaPolicyCandidate, FetchAtomsL2Request, FetchAtomsL2Response,
    GraphHealthResponse, HarnessExperimentRecord, InjectionReceipt, L0CollapsedDuplicateTrace,
    L0FeatureScore, L0RankTrace, L0SuppressionTrace, LifecycleStatus, MemoryConfidence,
    MemoryHandlePreview, MemoryInfluenceTrace, MemoryRevision, MemoryStateTransition,
    MemoryTrajectoryCorrectness, MemoryWriteEnvelope, MetaIsolationRejectionRecord,
    MetaPolicyExecutionAction, MetaPolicyExecutionReceipt, MinorityPressureRecord,
    ObservabilityKind, ObservabilityWriteEnvelope, ObservabilityWriteReceipt,
    ObservabilityWriteStatus, ProjectId, ProjectSequence, RecallL0Request, RecallL0Response,
    ReplayAudit, ReplayRun, SealedReplayCaseRecord, SealedReplayInputSnapshotRecord,
    SealedReplaySetRecord, SleepCandidateArtifact, SleepConsolidationBundle, SleepConsolidationRun,
    SurrealServerConfig, TaintClass, TaskContract, TaskId, ToolObservation, TruncationInfo,
    VerificationId, VerificationRun, Visibility, WriteId, WriteReceipt, WriteStatus,
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
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
    "produces",
    "invalidated_by",
    "co_change",
    "concept_implemented_by",
    "concept_depends_on",
    "capsule_covers",
    "card_covers",
];

const RECALL_CANDIDATE_PAGE_SIZE: usize = 128;
const MAX_RECALL_SCAN_CANDIDATES: usize = 65_536;
const RECALL_REVISION_RESTART_ATTEMPTS: usize = 3;
const RECALL_CANDIDATE_KINDS: &[&str] = &[
    "claim",
    "evidence",
    "verification",
    "observation",
    "failure",
    "artifact",
];
const MAX_RECALL_RESULTS: usize = 12;
const MAX_MEMORY_SEARCH_CANDIDATES: usize = 256;
const MAX_MEMORY_SEARCH_QUERY_TERMS: usize = 12;
const MAX_MEMORY_SEARCH_POSTINGS_PER_ROW: usize = 128;
const MAX_MEMORY_SEARCH_DOCUMENT_TERMS: usize = 2048;
const MEMORY_SEARCH_DISPATCH_BATCH_SIZE: usize = 512;
const MEMORY_SEARCH_FTS_PROJECTION_FORMAT: &str = "fts_v1";

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[allow(clippy::struct_excessive_bools)]
struct RecallCandidateRow {
    #[serde(default)]
    record_ref: String,
    handle: String,
    record_type: String,
    preview: String,
    search_text: String,
    #[serde(default)]
    cue_text: String,
    #[serde(default)]
    scope_text: String,
    #[serde(default)]
    concept_text: String,
    #[serde(default)]
    task_id: Option<TaskId>,
    status: String,
    lifecycle_state: Option<eliot_types::MemoryLifecycleState>,
    authority_rank: i32,
    negative_memory: bool,
    #[serde(default)]
    memory_revision: Option<MemoryRevision>,
    #[serde(default)]
    project_sequence: Option<ProjectSequence>,
    #[serde(default)]
    verification_value: i32,
    #[serde(default)]
    known_decision_delta: i32,
    #[serde(default)]
    prior_beneficial_use: i32,
    #[serde(default)]
    contradiction_signal: bool,
    #[serde(default)]
    harm_signal: bool,
    #[serde(default)]
    repetition_signal: bool,
    #[serde(default)]
    distraction_signal: bool,
}

#[derive(Debug, serde::Deserialize)]
struct RecallCandidateLoad {
    at_revision: MemoryRevision,
    candidates: Vec<RecallCandidateRow>,
    truncated: bool,
}

#[derive(Debug, serde::Deserialize)]
struct MemorySearchCandidateLoad {
    at_revision: MemoryRevision,
    #[serde(default)]
    projection_revision: Option<MemoryRevision>,
    #[serde(default)]
    projection_format: Option<String>,
    #[serde(default)]
    ordered_handles: Vec<String>,
    candidates: Vec<RecallCandidateRow>,
    truncated: bool,
}

#[derive(Clone)]
struct RankedRecallCandidate {
    row: RecallCandidateRow,
    score: L0FeatureScore,
}

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
    File,
    Claim,
    Evidence,
    Verification,
    Observation,
    Failure,
    Card,
    Capsule,
    Charter,
    Map,
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
    cards: Vec<Vec<String>>,
    capsules: Vec<Vec<String>>,
    charters: Vec<Vec<String>>,
    maps: Vec<Vec<String>>,
    relations: Vec<Vec<String>>,
}

fn parse_l2_selector(raw: &str) -> (L2HandleKind, &str, &'static str) {
    for (prefix, kind, canonical) in [
        ("file:", L2HandleKind::File, "file:"),
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
        ("card:", L2HandleKind::Card, "card:"),
        ("capsule:", L2HandleKind::Capsule, "capsule:"),
        ("charter:", L2HandleKind::Charter, "charter:"),
        ("map:", L2HandleKind::Map, "map:"),
        ("system-map:", L2HandleKind::Map, "map:"),
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
        cards: l2_fragment_lists(&identities(L2HandleKind::Card)),
        capsules: l2_fragment_lists(&identities(L2HandleKind::Capsule)),
        charters: l2_fragment_lists(&identities(L2HandleKind::Charter)),
        maps: l2_fragment_lists(&identities(L2HandleKind::Map)),
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
        relation_ids.insert(selector.public_handle.clone());
        relation_ids.insert(selector.identity.clone());
        if selector.kind == L2HandleKind::File {
            continue;
        }
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
            "card:",
            "capsule:",
            "charter:",
            "map:",
            "system-map:",
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
        + response.ul_artifacts.len()
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
    response.ul_artifacts.sort_by_cached_key(|record| {
        let (kind, identity, _) = parse_l2_selector(&record.handle);
        (
            selector_position(selectors, kind, identity),
            record.handle.clone(),
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
    for artifact in &response.ul_artifacts {
        let (kind, identity, _) = parse_l2_selector(&artifact.handle);
        resolved.insert((kind, identity.to_owned()));
    }
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
    for relation in &response.relations {
        for endpoint in [&relation.from, &relation.to] {
            if let Some(path) = endpoint.strip_prefix("file:") {
                resolved.insert((L2HandleKind::File, path.to_owned()));
            }
        }
    }
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

fn rank_recall_candidates(
    request: &RecallL0Request,
    load: RecallCandidateLoad,
) -> RecallL0Response {
    let query_tokens = eliot_types::normalize_query_tokens(&request.query);
    let normalized_query = query_tokens.join(" ");
    let exact_query = request.query.trim().to_lowercase();
    let candidates_considered = load.candidates.len();
    let mut lifecycle_suppressions = Vec::new();
    let mut scope_suppressions = Vec::new();
    let mut filtered = Vec::with_capacity(load.candidates.len());
    for row in load.candidates {
        if !request.lifecycle_audit && !is_default_visible_lifecycle(row.lifecycle_state) {
            lifecycle_suppressions.push(L0SuppressionTrace {
                handle: row.handle,
                reason: format!(
                    "lifecycle_{}",
                    row.lifecycle_state
                        .map_or_else(|| "unknown".to_owned(), |state| format!("{state:?}"))
                        .to_ascii_lowercase()
                ),
            });
            continue;
        }
        let Some(scope_fit) = recall_scope_fit(&row.scope_text, &request.scope_refs) else {
            scope_suppressions.push(L0SuppressionTrace {
                handle: row.handle,
                reason: "scope_mismatch".to_owned(),
            });
            continue;
        };
        filtered.push((row, scope_fit));
    }
    let (collapsed, collapsed_duplicates) = collapse_recall_candidates(filtered);
    let mut admitted = collapsed
        .into_iter()
        .filter_map(|(row, scope_fit)| {
            rank_recall_candidate(
                row,
                scope_fit,
                request,
                load.at_revision,
                &query_tokens,
                &normalized_query,
                &exact_query,
            )
        })
        .collect::<Vec<_>>();
    admitted.sort_by(|left, right| {
        right
            .score
            .total
            .cmp(&left.score.total)
            .then_with(|| right.row.authority_rank.cmp(&left.row.authority_rank))
            .then_with(|| left.row.handle.cmp(&right.row.handle))
    });
    let admitted_count = admitted.len();
    admitted.truncate(MAX_RECALL_RESULTS);
    let top_score = admitted.first().map(|candidate| candidate.score.total);
    let memory_confidence = MemoryConfidence::from_top_score(top_score);
    let handles = admitted
        .iter()
        .map(|candidate| MemoryHandlePreview {
            handle: candidate.row.handle.clone(),
            record_type: candidate.row.record_type.clone(),
            preview: candidate.row.preview.clone(),
            lifecycle_state: candidate.row.lifecycle_state,
            lifecycle_badge: None,
        })
        .collect::<Vec<_>>();
    let feature_scores = admitted
        .into_iter()
        .map(|candidate| candidate.score)
        .collect::<Vec<_>>();
    let candidates_returned = handles.len();
    let query_mode = "unicode_multi_kind_lifecycle_aware_v4".to_owned();

    RecallL0Response {
        project_id: request.project_id,
        at_revision: load.at_revision,
        handles,
        memory_confidence,
        query_mode: query_mode.clone(),
        rank_trace: L0RankTrace {
            query: request.query.clone(),
            normalized_query,
            candidates_considered,
            candidates_returned,
            feature_scores,
            lifecycle_suppressions,
            scope_suppressions,
            collapsed_duplicates,
            no_useful_memory: candidates_returned == 0,
            query_mode,
        },
        truncation: TruncationInfo {
            truncated: load.truncated || admitted_count > MAX_RECALL_RESULTS,
            limit: MAX_RECALL_RESULTS,
            returned: candidates_returned,
        },
    }
}

#[allow(clippy::too_many_lines)]
fn rank_recall_candidate(
    row: RecallCandidateRow,
    scope_fit: i32,
    request: &RecallL0Request,
    at_revision: MemoryRevision,
    query_tokens: &[String],
    normalized_query: &str,
    exact_query: &str,
) -> Option<RankedRecallCandidate> {
    let candidate_tokens = eliot_types::normalize_query_tokens(&row.search_text);
    let preview_tokens = eliot_types::normalize_query_tokens(&row.preview);
    let cue_tokens = eliot_types::normalize_query_tokens(&row.cue_text);
    let concept_tokens = eliot_types::normalize_query_tokens(&row.concept_text);
    let normalized_preview = preview_tokens.join(" ");
    let overlap = query_tokens
        .iter()
        .filter(|token| candidate_tokens.contains(token))
        .count();
    let overlap_score = i32::try_from(overlap).unwrap_or(i32::MAX);
    let exact_identifier = i32::from(row.handle.to_lowercase() == exact_query) * 1_000;
    let subject_identity =
        i32::from(!query_tokens.is_empty() && overlap == query_tokens.len()) * 200;
    let exact_preview =
        i32::from(!normalized_query.is_empty() && normalized_preview == normalized_query) * 250;
    let preview_contains =
        i32::from(!normalized_query.is_empty() && normalized_preview.contains(normalized_query))
            * 140;
    let lexical_overlap = overlap_score * 40 + exact_preview + preview_contains;
    let normalized_cues = cue_tokens.join(" ");
    let query_exact_cue = i32::from(
        !normalized_query.is_empty()
            && (normalized_cues == normalized_query || normalized_cues.contains(normalized_query)),
    ) * 180;
    let requested_cue_hits = request
        .task_class_cues
        .iter()
        .flat_map(|cue| eliot_types::normalize_query_tokens(cue))
        .filter(|cue| cue_tokens.contains(cue))
        .count();
    let exact_cue = query_exact_cue + i32::try_from(requested_cue_hits.min(4)).unwrap_or(4) * 40;
    let task_relation = i32::from(
        request.task_id.is_some() && row.task_id.is_some() && request.task_id == row.task_id,
    ) * 120;
    let concept_query_overlap = query_tokens
        .iter()
        .filter(|token| concept_tokens.contains(token))
        .count();
    let requested_concept_hits = request
        .concept_refs
        .iter()
        .flat_map(|concept| eliot_types::normalize_query_tokens(concept))
        .filter(|token| concept_tokens.contains(token))
        .count();
    let concept_relation = i32::try_from(concept_query_overlap.min(4)).unwrap_or(4) * 25
        + i32::try_from(requested_concept_hits.min(4)).unwrap_or(4) * 40;
    let lifecycle_fit = match row.lifecycle_state {
        Some(
            eliot_types::MemoryLifecycleState::Active | eliot_types::MemoryLifecycleState::Restored,
        )
        | None => 20,
        Some(eliot_types::MemoryLifecycleState::Dormant) => -20,
        _ => 0,
    };
    let evidence_authority = row.authority_rank.clamp(0, 100);
    let revision_distance = row.memory_revision.map_or(u64::MAX, |revision| {
        at_revision.value().saturating_sub(revision.value())
    });
    let freshness_fit = match revision_distance {
        0 => 40,
        1..=5 => 20,
        6..=50 => 5,
        _ => 0,
    };
    let negative_memory_value = i32::from(row.negative_memory && overlap > 0) * 80;
    let known_decision_delta = i32::from(row.known_decision_delta > 0 && overlap > 0) * 60;
    let prior_beneficial_use = row.prior_beneficial_use.clamp(0, 10) * 5;
    let verification_value = if overlap > 0 {
        row.verification_value.clamp(0, 100)
    } else {
        0
    };
    let context_cost = -i32::try_from(row.preview.len().div_ceil(64).min(40)).unwrap_or(40);
    let stale_penalty = if matches!(
        row.lifecycle_state,
        Some(eliot_types::MemoryLifecycleState::Stale)
    ) || row.status.eq_ignore_ascii_case("stale")
    {
        -300
    } else {
        0
    };
    let contradiction_penalty = i32::from(row.contradiction_signal) * -120;
    let harm_penalty = i32::from(row.harm_signal) * -250;
    let repetition_penalty = i32::from(row.repetition_signal) * -40;
    let weak_single_token = query_tokens.len() > 2 && overlap == 1;
    let distraction_penalty = i32::from(row.distraction_signal || weak_single_token) * -60;
    let total = exact_identifier
        + subject_identity
        + lexical_overlap
        + exact_cue
        + task_relation
        + scope_fit
        + concept_relation
        + lifecycle_fit
        + freshness_fit
        + evidence_authority
        + negative_memory_value
        + known_decision_delta
        + prior_beneficial_use
        + verification_value
        + context_cost
        + stale_penalty
        + contradiction_penalty
        + harm_penalty
        + repetition_penalty
        + distraction_penalty;
    let retrieval_signal = overlap > 0
        || exact_preview > 0
        || preview_contains > 0
        || exact_cue > 0
        || concept_relation > 0;
    if exact_identifier == 0 && (!retrieval_signal || total < 80) {
        return None;
    }
    let mut reasons = Vec::new();
    if exact_identifier > 0 {
        reasons.push("exact_handle".to_owned());
    }
    if subject_identity > 0 {
        reasons.push("all_query_tokens".to_owned());
    }
    if overlap > 0 {
        reasons.push(format!("token_overlap:{overlap}"));
    }
    if exact_preview > 0 {
        reasons.push("exact_preview".to_owned());
    }
    if preview_contains > 0 {
        reasons.push("preview_contains_query".to_owned());
    }
    if exact_cue > 0 {
        reasons.push("exact_normalized_cue".to_owned());
    }
    if task_relation > 0 {
        reasons.push("current_task_relation".to_owned());
    }
    if scope_fit > 0 {
        reasons.push("scope_fit".to_owned());
    }
    if concept_relation > 0 {
        reasons.push("concept_relation".to_owned());
    }
    if negative_memory_value > 0 {
        reasons.push("negative_memory_overlap".to_owned());
    }
    if known_decision_delta > 0 {
        reasons.push("known_decision_delta".to_owned());
    }
    if prior_beneficial_use > 0 {
        reasons.push("prior_beneficial_use".to_owned());
    }
    if verification_value > 0 {
        reasons.push("verification_value".to_owned());
    }
    if stale_penalty < 0 {
        reasons.push("stale_penalty".to_owned());
    }
    if contradiction_penalty < 0 {
        reasons.push("contradiction_penalty".to_owned());
    }
    if harm_penalty < 0 {
        reasons.push("harm_penalty".to_owned());
    }
    if repetition_penalty < 0 {
        reasons.push("repetition_penalty".to_owned());
    }
    if distraction_penalty < 0 {
        reasons.push("distraction_penalty".to_owned());
    }
    Some(RankedRecallCandidate {
        score: L0FeatureScore {
            handle: row.handle.clone(),
            exact_identifier,
            subject_identity,
            lexical_overlap,
            task_relation,
            scope_fit,
            lifecycle_fit,
            evidence_authority,
            prior_decision_delta: negative_memory_value,
            exact_cue,
            concept_relation,
            freshness_fit,
            negative_memory_value,
            known_decision_delta,
            prior_beneficial_use,
            verification_value,
            context_cost,
            stale_penalty,
            contradiction_penalty,
            harm_penalty,
            repetition_penalty,
            distraction_penalty,
            total,
            reasons,
        },
        row,
    })
}

fn is_default_visible_lifecycle(state: Option<eliot_types::MemoryLifecycleState>) -> bool {
    !matches!(
        state,
        Some(
            eliot_types::MemoryLifecycleState::Suppressed
                | eliot_types::MemoryLifecycleState::Archived
                | eliot_types::MemoryLifecycleState::Quarantined
                | eliot_types::MemoryLifecycleState::Forgotten
                | eliot_types::MemoryLifecycleState::HardDeleted
        )
    )
}

fn normalize_scope(value: &str) -> String {
    value
        .trim()
        .replace('\\', "/")
        .trim_matches('/')
        .to_lowercase()
}

fn recall_scope_fit(candidate_scope: &str, requested_scopes: &[String]) -> Option<i32> {
    if requested_scopes.is_empty() || candidate_scope.trim().is_empty() {
        return Some(0);
    }
    let candidate = normalize_scope(candidate_scope);
    requested_scopes
        .iter()
        .map(|scope| normalize_scope(scope))
        .any(|scope| {
            !scope.is_empty()
                && (candidate == scope
                    || candidate.starts_with(&format!("{scope}/"))
                    || scope.starts_with(&format!("{candidate}/")))
        })
        .then_some(90)
}

fn recall_candidate_preference(row: &RecallCandidateRow) -> (u64, u64, i32) {
    (
        row.memory_revision.map_or(0, MemoryRevision::value),
        row.project_sequence.map_or(0, ProjectSequence::value),
        row.authority_rank,
    )
}

fn choose_authoritative_candidate(
    mut rows: Vec<(RecallCandidateRow, i32)>,
    reason: &str,
    traces: &mut Vec<L0CollapsedDuplicateTrace>,
) -> (RecallCandidateRow, i32) {
    rows.sort_by(|(left, _), (right, _)| {
        recall_candidate_preference(right)
            .cmp(&recall_candidate_preference(left))
            .then_with(|| left.handle.cmp(&right.handle))
            .then_with(|| left.record_ref.cmp(&right.record_ref))
    });
    let authoritative = rows.remove(0);
    if !rows.is_empty() {
        traces.push(L0CollapsedDuplicateTrace {
            authoritative_handle: authoritative.0.handle.clone(),
            collapsed_record_refs: rows
                .into_iter()
                .map(|(row, _)| {
                    if row.record_ref.is_empty() {
                        row.handle
                    } else {
                        row.record_ref
                    }
                })
                .collect(),
            reason: reason.to_owned(),
        });
    }
    authoritative
}

fn collapse_recall_candidates(
    candidates: Vec<(RecallCandidateRow, i32)>,
) -> (
    Vec<(RecallCandidateRow, i32)>,
    Vec<L0CollapsedDuplicateTrace>,
) {
    let mut traces = Vec::new();
    let mut by_handle = BTreeMap::<String, Vec<(RecallCandidateRow, i32)>>::new();
    for candidate in candidates {
        by_handle
            .entry(candidate.0.handle.clone())
            .or_default()
            .push(candidate);
    }
    let current = by_handle
        .into_values()
        .map(|rows| choose_authoritative_candidate(rows, "superseded_revision", &mut traces))
        .collect::<Vec<_>>();

    let mut by_semantics = BTreeMap::<String, Vec<(RecallCandidateRow, i32)>>::new();
    for candidate in current {
        let preview = eliot_types::normalize_query_tokens(&candidate.0.preview).join(" ");
        let semantics = if preview.is_empty() {
            candidate.0.handle.clone()
        } else {
            format!(
                "{}|{}|{}|{}|{}|{}",
                candidate.0.record_type,
                preview,
                normalize_scope(&candidate.0.scope_text),
                eliot_types::normalize_query_tokens(&candidate.0.concept_text).join(" "),
                candidate.0.status.to_ascii_lowercase(),
                candidate.0.negative_memory
            )
        };
        by_semantics.entry(semantics).or_default().push(candidate);
    }
    let deduplicated = by_semantics
        .into_values()
        .map(|rows| choose_authoritative_candidate(rows, "semantic_duplicate", &mut traces))
        .collect();
    (deduplicated, traces)
}

fn serialized_name<T: serde::Serialize>(value: T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn searchable_value(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(value) => value.clone(),
        _ => serde_json::to_string(value).unwrap_or_default(),
    }
}

fn searchable_field(value: &Value, field: &str) -> String {
    value.get(field).map_or_else(String::new, searchable_value)
}

fn joined_search_fields(value: &Value, fields: &[&str]) -> String {
    fields
        .iter()
        .map(|field| searchable_field(value, field))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn payload_bool(payload: &Value, field: &str) -> bool {
    payload.get(field).and_then(Value::as_bool).unwrap_or(false)
}

fn payload_i32(payload: &Value, field: &str) -> i32 {
    payload
        .get(field)
        .and_then(Value::as_i64)
        .and_then(|value| i32::try_from(value).ok())
        .unwrap_or(0)
}

fn normalized_memory_lifecycle(status: LifecycleStatus) -> eliot_types::MemoryLifecycleState {
    use eliot_types::MemoryLifecycleState as Memory;
    match status {
        LifecycleStatus::Active => Memory::Active,
        LifecycleStatus::Dormant => Memory::Dormant,
        LifecycleStatus::Suppressed => Memory::Suppressed,
        LifecycleStatus::Archived => Memory::Archived,
        LifecycleStatus::Quarantined => Memory::Quarantined,
        LifecycleStatus::Forgotten => Memory::Forgotten,
        LifecycleStatus::Restored => Memory::Restored,
        LifecycleStatus::HardDeleted | LifecycleStatus::Deleted => Memory::HardDeleted,
        LifecycleStatus::Superseded => Memory::Superseded,
        LifecycleStatus::Stale => Memory::Stale,
    }
}

struct RecallCandidateInput<'a> {
    record_ref: String,
    handle: String,
    record_type: String,
    preview: String,
    search_text: String,
    cue_text: String,
    scope_text: String,
    concept_text: String,
    task_id: Option<TaskId>,
    status: String,
    lifecycle_state: eliot_types::MemoryLifecycleState,
    authority_rank: i32,
    negative_memory: bool,
    memory_revision: MemoryRevision,
    project_sequence: ProjectSequence,
    verification_value: i32,
    known_decision_delta: i32,
    prior_beneficial_use: i32,
    contradiction_signal: bool,
    payload: &'a Value,
}

fn recall_candidate(input: RecallCandidateInput<'_>) -> RecallCandidateRow {
    RecallCandidateRow {
        record_ref: input.record_ref,
        handle: input.handle,
        record_type: input.record_type,
        preview: input.preview,
        search_text: input.search_text,
        cue_text: input.cue_text,
        scope_text: input.scope_text,
        concept_text: input.concept_text,
        task_id: input.task_id,
        status: input.status,
        lifecycle_state: Some(input.lifecycle_state),
        authority_rank: input.authority_rank,
        negative_memory: input.negative_memory,
        memory_revision: Some(input.memory_revision),
        project_sequence: Some(input.project_sequence),
        verification_value: input.verification_value,
        known_decision_delta: input.known_decision_delta,
        prior_beneficial_use: input.prior_beneficial_use,
        contradiction_signal: input.contradiction_signal,
        harm_signal: payload_bool(input.payload, "harmful"),
        repetition_signal: payload_bool(input.payload, "repeated"),
        distraction_signal: payload_bool(input.payload, "distraction"),
    }
}

fn projection_row(
    project_id: ProjectId,
    row: &RecallCandidateRow,
    updated_revision: MemoryRevision,
) -> Result<Value, StoreError> {
    let mut value =
        serde_json::to_value(row).map_err(|error| StoreError::Decode(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        StoreError::Decode("memory search projection row was not an object".to_owned())
    })?;
    object.remove("handle");
    object.remove("record_ref");
    let lifecycle = object.remove("lifecycle_state").unwrap_or(Value::Null);
    object.insert(
        "projection_id".to_owned(),
        Value::String(derived_row_key(&format!("{project_id}:{}", row.handle))),
    );
    object.insert(
        "record_kind".to_owned(),
        Value::String(row.record_type.clone()),
    );
    object.insert(
        "handle_parts".to_owned(),
        json!(string_fragments(&row.handle)),
    );
    object.insert(
        "record_ref_parts".to_owned(),
        json!(string_fragments(&row.record_ref)),
    );
    object.insert("lifecycle".to_owned(), lifecycle);
    object.insert("updated_revision".to_owned(), json!(updated_revision));
    object.insert(
        "visible".to_owned(),
        Value::Bool(is_default_visible_lifecycle(row.lifecycle_state)),
    );

    let document_terms = memory_search_document_terms(row);
    object.insert(
        "search_document".to_owned(),
        Value::String(document_terms.join(" ")),
    );
    let postings = document_terms
        .into_iter()
        .take(MAX_MEMORY_SEARCH_POSTINGS_PER_ROW)
        .map(|token| {
            json!({
                "posting_id": derived_row_key(&format!("{project_id}:{token}:{}", row.handle)),
                "token": token,
            })
        })
        .collect::<Vec<_>>();
    object.insert("postings".to_owned(), Value::Array(postings));
    Ok(value)
}

#[allow(clippy::too_many_lines)]
fn envelope_projection_rows(
    envelope: &MemoryWriteEnvelope,
    receipt: &WriteReceipt,
) -> Result<Vec<Value>, StoreError> {
    let memory_revision = receipt.memory_revision.ok_or_else(|| {
        StoreError::PolicyViolation(
            "committed write receipt omitted the memory revision required by the search projection"
                .to_owned(),
        )
    })?;
    let project_sequence = receipt.project_sequence.ok_or_else(|| {
        StoreError::PolicyViolation(
            "committed write receipt omitted the project sequence required by the search projection"
                .to_owned(),
        )
    })?;
    let lifecycle = normalized_memory_lifecycle(envelope.lifecycle.status);
    let mut rows = Vec::with_capacity(
        envelope.claims.len()
            + envelope.evidence_atoms.len()
            + envelope.verification_runs.len()
            + envelope.tool_observations.len() * 2
            + envelope.failures.len(),
    );

    for claim in &envelope.claims {
        let status = serialized_name(claim.status);
        let row = recall_candidate(RecallCandidateInput {
            record_ref: format!("claim_card:{}", claim.claim_id),
            handle: format!("claim:{}", claim.claim_id),
            record_type: "claim_card".to_owned(),
            preview: claim.statement.clone(),
            search_text: format!(
                "{} {} {}",
                claim.statement,
                joined_search_fields(
                    &claim.payload,
                    &[
                        "topic",
                        "where_applicable",
                        "where_not_applicable",
                        "negative_constraints",
                        "freshness_rule",
                    ],
                ),
                searchable_value(&claim.payload),
            ),
            cue_text: joined_search_fields(
                &claim.payload,
                &["path", "symbol", "error", "task_class"],
            ),
            scope_text: envelope.scope.clone(),
            concept_text: joined_search_fields(
                &claim.payload,
                &["concept_id", "concept_refs", "subsystem"],
            ),
            task_id: envelope.task_id,
            status: status.clone(),
            lifecycle_state: lifecycle,
            authority_rank: match claim.status {
                EpistemicStatus::Verified => 80,
                EpistemicStatus::Supported => 50,
                EpistemicStatus::Candidate => 10,
                _ => 0,
            },
            negative_memory: false,
            memory_revision,
            project_sequence,
            verification_value: 0,
            known_decision_delta: i32::from(payload_bool(&claim.payload, "changed_outcome")),
            prior_beneficial_use: payload_i32(&claim.payload, "beneficial_use_count"),
            contradiction_signal: matches!(
                claim.status,
                EpistemicStatus::Contested | EpistemicStatus::Rejected
            ),
            payload: &claim.payload,
        });
        rows.push(projection_row(envelope.project_id, &row, memory_revision)?);
    }

    for evidence in &envelope.evidence_atoms {
        let row = recall_candidate(RecallCandidateInput {
            record_ref: format!("evidence_atom:{}", evidence.evidence_id),
            handle: format!("evidence:{}", evidence.evidence_id),
            record_type: "evidence_atom".to_owned(),
            preview: evidence.summary.clone(),
            search_text: format!(
                "{} {} {}",
                evidence.summary,
                searchable_value(&evidence.payload),
                evidence.source_id,
            ),
            cue_text: joined_search_fields(
                &evidence.payload,
                &["path", "symbol", "error", "task_class"],
            ),
            scope_text: envelope.scope.clone(),
            concept_text: joined_search_fields(&evidence.payload, &["concept_id", "concept_refs"]),
            task_id: envelope.task_id,
            status: "observed".to_owned(),
            lifecycle_state: lifecycle,
            authority_rank: 35,
            negative_memory: false,
            memory_revision,
            project_sequence,
            verification_value: 25,
            known_decision_delta: i32::from(payload_bool(&evidence.payload, "changed_outcome")),
            prior_beneficial_use: payload_i32(&evidence.payload, "beneficial_use_count"),
            contradiction_signal: false,
            payload: &evidence.payload,
        });
        rows.push(projection_row(envelope.project_id, &row, memory_revision)?);
    }

    for verification in &envelope.verification_runs {
        let status = serialized_name(verification.result);
        let row = recall_candidate(RecallCandidateInput {
            record_ref: format!("verification_run:{}", verification.verification_id),
            handle: format!("verification:{}", verification.verification_id),
            record_type: "verification_run".to_owned(),
            preview: verification.summary.clone(),
            search_text: format!(
                "{} {} {} {} {}",
                verification.summary,
                verification.verifier,
                status,
                verification
                    .claim_id
                    .map_or_else(String::new, |id| id.to_string()),
                searchable_value(&verification.payload),
            ),
            cue_text: joined_search_fields(
                &verification.payload,
                &["path", "symbol", "error", "task_class"],
            ),
            scope_text: envelope.scope.clone(),
            concept_text: joined_search_fields(
                &verification.payload,
                &["concept_id", "concept_refs"],
            ),
            task_id: envelope.task_id,
            status,
            lifecycle_state: lifecycle,
            authority_rank: match verification.result {
                eliot_types::VerificationResult::Passed => 70,
                eliot_types::VerificationResult::Failed => 60,
                eliot_types::VerificationResult::Inconclusive => 20,
            },
            negative_memory: verification.result == eliot_types::VerificationResult::Failed,
            memory_revision,
            project_sequence,
            verification_value: match verification.result {
                eliot_types::VerificationResult::Passed => 80,
                eliot_types::VerificationResult::Failed => 60,
                eliot_types::VerificationResult::Inconclusive => 10,
            },
            known_decision_delta: i32::from(payload_bool(&verification.payload, "changed_outcome")),
            prior_beneficial_use: payload_i32(&verification.payload, "beneficial_use_count"),
            contradiction_signal: verification.result == eliot_types::VerificationResult::Failed,
            payload: &verification.payload,
        });
        rows.push(projection_row(envelope.project_id, &row, memory_revision)?);
    }

    for observation in &envelope.tool_observations {
        let row = recall_candidate(RecallCandidateInput {
            record_ref: format!("tool_observation:{}", observation.observation_id),
            handle: format!("observation:{}", observation.observation_id),
            record_type: "tool_observation".to_owned(),
            preview: observation.observation.clone(),
            search_text: format!(
                "{} {} {}",
                observation.observation,
                observation.tool_name,
                searchable_value(&observation.payload),
            ),
            cue_text: joined_search_fields(
                &observation.payload,
                &["path", "symbol", "error", "task_class"],
            ),
            scope_text: envelope.scope.clone(),
            concept_text: joined_search_fields(
                &observation.payload,
                &["concept_id", "concept_refs"],
            ),
            task_id: envelope.task_id,
            status: "observed".to_owned(),
            lifecycle_state: lifecycle,
            authority_rank: 20,
            negative_memory: false,
            memory_revision,
            project_sequence,
            verification_value: 10,
            known_decision_delta: i32::from(payload_bool(&observation.payload, "changed_outcome")),
            prior_beneficial_use: payload_i32(&observation.payload, "beneficial_use_count"),
            contradiction_signal: false,
            payload: &observation.payload,
        });
        rows.push(projection_row(envelope.project_id, &row, memory_revision)?);

        let Some(receipt_kind) = observation
            .payload
            .get("receipt_kind")
            .and_then(Value::as_str)
        else {
            continue;
        };
        let Some(body) = observation.payload.get("receipt_body") else {
            continue;
        };
        let (prefix, identity_field) = match receipt_kind {
            "module_card" => ("card", "card_id"),
            "subsystem_capsule" => ("capsule", "capsule_id"),
            "project_charter" => ("charter", "charter_id"),
            "system_map" => ("map", "map_id"),
            _ => continue,
        };
        let Some(identity) = body.get(identity_field).and_then(Value::as_str) else {
            continue;
        };
        let artifact_status = body
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("supported")
            .to_owned();
        let artifact_lifecycle = body
            .get("lifecycle")
            .cloned()
            .and_then(|value| serde_json::from_value(value).ok())
            .unwrap_or(eliot_types::MemoryLifecycleState::Active);
        let artifact = recall_candidate(RecallCandidateInput {
            record_ref: format!("canonical_record:{}", observation.observation_id),
            handle: format!("{prefix}:{identity}"),
            record_type: receipt_kind.to_owned(),
            preview: searchable_field(body, "body_md"),
            search_text: joined_search_fields(
                body,
                &[
                    "body_md",
                    "path",
                    "concept_id",
                    "source_refs",
                    "concept_refs",
                    "subsystem_concept_refs",
                ],
            ),
            cue_text: joined_search_fields(body, &["path", "symbol", "error", "task_class"]),
            scope_text: searchable_field(body, "path"),
            concept_text: joined_search_fields(
                body,
                &["concept_id", "concept_refs", "subsystem_concept_refs"],
            ),
            task_id: envelope.task_id,
            status: artifact_status.clone(),
            lifecycle_state: artifact_lifecycle,
            authority_rank: match artifact_status.as_str() {
                "verified" => 80,
                "candidate" => 10,
                _ => 50,
            },
            negative_memory: false,
            memory_revision,
            project_sequence,
            verification_value: 30,
            known_decision_delta: i32::from(payload_bool(body, "changed_outcome")),
            prior_beneficial_use: payload_i32(body, "beneficial_use_count"),
            contradiction_signal: matches!(artifact_status.as_str(), "contested" | "rejected"),
            payload: body,
        });
        rows.push(projection_row(
            envelope.project_id,
            &artifact,
            memory_revision,
        )?);
    }

    for failure in &envelope.failures {
        let row = recall_candidate(RecallCandidateInput {
            record_ref: format!("failure_fingerprint:{}", failure.fingerprint),
            handle: format!("failure:{}", failure.fingerprint),
            record_type: "failure_fingerprint".to_owned(),
            preview: failure.summary.clone(),
            search_text: format!("{} {}", failure.summary, searchable_value(&failure.payload)),
            cue_text: joined_search_fields(
                &failure.payload,
                &["path", "symbol", "error", "task_class"],
            ),
            scope_text: envelope.scope.clone(),
            concept_text: joined_search_fields(&failure.payload, &["concept_id", "concept_refs"]),
            task_id: envelope.task_id,
            status: "observed".to_owned(),
            lifecycle_state: lifecycle,
            authority_rank: 50,
            negative_memory: true,
            memory_revision,
            project_sequence,
            verification_value: 35,
            known_decision_delta: 1,
            prior_beneficial_use: payload_i32(&failure.payload, "beneficial_use_count"),
            contradiction_signal: false,
            payload: &failure.payload,
        });
        rows.push(projection_row(envelope.project_id, &row, memory_revision)?);
    }
    Ok(rows)
}

fn ordered_memory_search_terms<'a>(
    sources: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Vec<String> {
    let mut terms = Vec::with_capacity(limit);
    let mut seen = HashSet::with_capacity(limit);
    for source in sources {
        if terms.len() == limit {
            break;
        }
        for term in eliot_types::normalize_query_tokens(source) {
            if seen.insert(term.clone()) {
                terms.push(term);
                if terms.len() == limit {
                    break;
                }
            }
        }
    }
    terms
}

fn memory_search_terms(request: &RecallL0Request) -> Vec<String> {
    ordered_memory_search_terms(
        std::iter::once(request.query.as_str())
            .chain(request.task_class_cues.iter().map(String::as_str))
            .chain(request.concept_refs.iter().map(String::as_str)),
        MAX_MEMORY_SEARCH_QUERY_TERMS,
    )
}

fn memory_search_query_text(request: &RecallL0Request) -> String {
    memory_search_terms(request).join(" ")
}

fn memory_search_document_terms(row: &RecallCandidateRow) -> Vec<String> {
    ordered_memory_search_terms(
        [
            row.handle.as_str(),
            row.record_ref.as_str(),
            row.cue_text.as_str(),
            row.concept_text.as_str(),
            row.preview.as_str(),
            row.search_text.as_str(),
            row.scope_text.as_str(),
        ],
        MAX_MEMORY_SEARCH_DOCUMENT_TERMS,
    )
}

fn rank_memory_search_candidates(
    request: &RecallL0Request,
    mut load: MemorySearchCandidateLoad,
) -> RecallL0Response {
    let positions = load
        .ordered_handles
        .iter()
        .enumerate()
        .map(|(position, handle)| (handle.as_str(), position))
        .collect::<BTreeMap<_, _>>();
    load.candidates.sort_by_key(|row| {
        positions
            .get(row.handle.as_str())
            .copied()
            .unwrap_or(usize::MAX)
    });
    rank_recall_candidates(
        request,
        RecallCandidateLoad {
            at_revision: load.at_revision,
            candidates: load.candidates,
            truncated: load.truncated,
        },
    )
}

fn exact_memory_search_handle(query: &str) -> Option<String> {
    let query = query.trim();
    (!query.is_empty() && query.contains(':') && !query.chars().any(char::is_whitespace))
        .then(|| query.to_owned())
}

fn memory_search_projection_dispatch_vars(
    project_id: ProjectId,
    write_id: WriteId,
    updated_revision: MemoryRevision,
    rows: &[Value],
    advance_state: bool,
    projection_format: Option<&str>,
) -> Value {
    json!({
        "project_id": project_id,
        "write_id": write_id,
        "updated_revision": updated_revision,
        "rows": rows,
        "advance_state": advance_state,
        "projection_format": projection_format,
    })
}

#[derive(Clone, Debug)]
pub struct CanonicalStore {
    config: SurrealServerConfig,
    registry: SurqlTemplateRegistry,
    client_set: Option<Arc<DbClientSet>>,
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

#[derive(serde::Deserialize)]
struct RawActivationRelation {
    from_ref: String,
    to_ref: String,
}

#[derive(serde::Deserialize)]
struct RawActivationGraphRows {
    #[serde(default)]
    co_change: Vec<eliot_types::CoChangeEdge>,
    #[serde(default)]
    card_covers: Vec<RawActivationRelation>,
    #[serde(default)]
    capsule_covers: Vec<RawActivationRelation>,
    #[serde(default)]
    concept_implemented_by: Vec<RawActivationRelation>,
    #[serde(default)]
    concept_depends_on: Vec<RawActivationRelation>,
    #[serde(default)]
    supports: Vec<RawActivationRelation>,
    #[serde(default)]
    verified_by: Vec<RawActivationRelation>,
}

impl CanonicalStore {
    pub fn new(config: SurrealServerConfig) -> Self {
        Self {
            config,
            registry: SurqlTemplateRegistry::default(),
            client_set: None,
        }
    }

    #[must_use]
    pub fn from_client_set(client_set: Arc<DbClientSet>) -> Self {
        Self {
            config: client_set.config().clone(),
            registry: SurqlTemplateRegistry::default(),
            client_set: Some(client_set),
        }
    }

    pub async fn migrate_schema(&self) -> Result<Value, StoreError> {
        let mut value = Value::Null;
        for op in [
            NamedSurqlOp::SchemaMigrate,
            NamedSurqlOp::SchemaMigrateObservability,
            NamedSurqlOp::SchemaMigrateUl,
            NamedSurqlOp::SchemaMigrateUlDelivery,
            NamedSurqlOp::SchemaMigrateUlArtifacts,
            NamedSurqlOp::SchemaMigrateUlPyramid,
            NamedSurqlOp::SchemaMigrateUlMeasurement,
            NamedSurqlOp::SchemaMigrateUlDependencyActivation,
            NamedSurqlOp::SchemaMigrateUlTokenPolicy,
            NamedSurqlOp::SchemaMigrateMemorySearch,
            NamedSurqlOp::SchemaMigrateMemorySearchFts,
        ] {
            value = self.migrate_schema_op(op).await?;
        }
        Ok(value)
    }

    async fn migrate_schema_op(&self, op: NamedSurqlOp) -> Result<Value, StoreError> {
        let vars = Value::Object(serde_json::Map::new());
        let mut attempts = 0u8;
        loop {
            match self.execute_value(op, vars.clone()).await {
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
        let server = if self.client_set.is_some() {
            None
        } else {
            Some(supervisor.start_or_connect().await?)
        };
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
                    let raw = self.secret_scan_query(server.as_ref(), &sql).await?;
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
        if let Some(server) = server {
            let shutdown_result = server.shutdown_if_spawned().await;
            let report = report_result?;
            shutdown_result?;
            Ok(report)
        } else {
            report_result
        }
    }

    async fn secret_scan_query(
        &self,
        transient_server: Option<&ReadySurrealServer>,
        sql: &str,
    ) -> Result<Value, StoreError> {
        let vars = Value::Object(serde_json::Map::new());
        if let Some(client_set) = self.client_set.as_ref() {
            return client_set.execute_admin_sql(sql, vars).await;
        }
        let server = transient_server.ok_or_else(|| {
            StoreError::PolicyViolation(
                "secret scan has neither persistent nor transient admin transport".to_owned(),
            )
        })?;
        server.transport()?.query(sql, vars).await
    }

    pub async fn apply_write_envelope(
        &self,
        envelope: &MemoryWriteEnvelope,
    ) -> Result<WriteReceipt, StoreError> {
        let canonical_payloads = canonical_payloads(envelope)?;
        let relation_payloads = relation_payloads(envelope);
        let value = self
            .execute_value(
                NamedSurqlOp::ApplyWriteEnvelope,
                json!({
                    "envelope": envelope,
                    "canonical_payloads": canonical_payloads,
                    "relation_payloads": relation_payloads,
                }),
            )
            .await?;
        let receipt: WriteReceipt = decode_value(NamedSurqlOp::ApplyWriteEnvelope, value)?;
        if matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        ) {
            let rows = envelope_projection_rows(envelope, &receipt)?;
            self.dispatch_memory_search_projection(
                envelope.project_id,
                envelope.write_id,
                receipt.memory_revision.ok_or_else(|| {
                    StoreError::PolicyViolation(
                        "committed write receipt omitted the search projection revision".to_owned(),
                    )
                })?,
                &rows,
                None,
            )
            .await?;
        }
        Ok(receipt)
    }

    async fn dispatch_memory_search_projection(
        &self,
        project_id: ProjectId,
        write_id: WriteId,
        updated_revision: MemoryRevision,
        rows: &[Value],
        projection_format: Option<&str>,
    ) -> Result<(), StoreError> {
        if rows.is_empty() {
            self.execute_value(
                NamedSurqlOp::UpsertMemorySearchProjection,
                memory_search_projection_dispatch_vars(
                    project_id,
                    write_id,
                    updated_revision,
                    &[],
                    true,
                    projection_format,
                ),
            )
            .await?;
            return Ok(());
        }
        let chunk_count = rows.len().div_ceil(MEMORY_SEARCH_DISPATCH_BATCH_SIZE);
        for (index, chunk) in rows.chunks(MEMORY_SEARCH_DISPATCH_BATCH_SIZE).enumerate() {
            self.execute_value(
                NamedSurqlOp::UpsertMemorySearchProjection,
                memory_search_projection_dispatch_vars(
                    project_id,
                    write_id,
                    updated_revision,
                    chunk,
                    index + 1 == chunk_count,
                    projection_format,
                ),
            )
            .await?;
        }
        Ok(())
    }

    pub async fn apply_observability(
        &self,
        envelope: &ObservabilityWriteEnvelope,
    ) -> Result<ObservabilityWriteReceipt, StoreError> {
        let injection_payload = if envelope.kind == ObservabilityKind::InjectionReceipt {
            let receipt: InjectionReceipt = serde_json::from_value(envelope.payload.clone())
                .map_err(|error| StoreError::Decode(error.to_string()))?;
            json!({
                "injection_id_parts": cue_string_parts(&receipt.injection_id),
                "session_id_parts": vec![receipt.session_id.to_string()],
                "task_id_parts": receipt
                    .task_id
                    .map(|task_id| vec![task_id.to_string()]),
                "surface_parts": cue_string_parts(&receipt.surface),
                "item_ref_parts": cue_string_parts(&receipt.item_ref),
                "render_form_parts": cue_string_parts(&receipt.render_form),
                "fired_cues": receipt.fired_cues.iter().map(|cue| json!({
                    "kind": cue.kind,
                    "value_parts": cue_string_parts(&cue.value),
                })).collect::<Vec<_>>(),
                "token_cost": receipt.token_cost,
                "source_fingerprint_parts": cue_string_parts(&receipt.source_fingerprint),
                "outcome_parts": cue_string_parts(&receipt.outcome),
                "policy_reason_parts": receipt
                    .policy_reason
                    .as_deref()
                    .map(cue_string_parts),
            })
        } else {
            Value::Null
        };
        let memory_influence_payload = if envelope.kind == ObservabilityKind::MemoryInfluenceTrace {
            let trace: MemoryInfluenceTrace = serde_json::from_value(envelope.payload.clone())
                .map_err(|error| StoreError::Decode(error.to_string()))?;
            json!({
                "task_id_parts": vec![trace.task_id.to_string()],
                "session_id_parts": vec![trace.session_id.to_string()],
                "memory_handle_parts": cue_string_parts(&trace.memory_handle),
                "packet_id_parts": cue_string_parts(&trace.packet_id),
                "admission_decision": trace.admission_decision,
                "inclusion_reason_parts": cue_string_parts(
                    &trace.inclusion_or_suppression_reason
                ),
                "epistemic_status_parts": cue_string_parts(&trace.epistemic_status_at_use),
                "cited_in_understanding_proof": trace.cited_in_understanding_proof,
                "action_or_probe_changed": trace.action_or_probe_changed,
                "write_set_changed": trace.write_set_changed,
                "verifier_changed": trace.verifier_changed,
                "repeated_failure_prevented": trace.repeated_failure_prevented,
                "suppressed_as_stale_or_wrong_scope": trace
                    .suppressed_as_stale_or_wrong_scope,
                "downstream_outcome_ref_parts": trace
                    .downstream_outcome_ref
                    .as_deref()
                    .map(cue_string_parts),
                "influence_class": trace.influence_class,
            })
        } else {
            Value::Null
        };
        let value = self
            .execute_value(
                NamedSurqlOp::ApplyObservability,
                json!({
                    "envelope": envelope,
                    "target_table": envelope.kind.table_name(),
                    "injection_payload": injection_payload,
                    "memory_influence_payload": memory_influence_payload,
                }),
            )
            .await?;
        let receipt =
            decode_value::<ObservabilityWriteReceipt>(NamedSurqlOp::ApplyObservability, value)?;
        if receipt.status == ObservabilityWriteStatus::Rejected {
            return Err(StoreError::ObservabilityConflict);
        }
        Ok(receipt)
    }

    pub async fn observability_receipt(
        &self,
        write_id: WriteId,
    ) -> Result<Option<ObservabilityWriteReceipt>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::ObservabilityReceiptById,
                json!({ "write_id": write_id }),
            )
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        decode_value(NamedSurqlOp::ObservabilityReceiptById, value).map(Some)
    }

    pub async fn observability_records_by_kind<T: DeserializeOwned>(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        kind: ObservabilityKind,
    ) -> Result<Vec<T>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::ObservabilityRecordsByKind,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "has_task_id": task_id.is_some(),
                    "kind": kind,
                    "target_table": kind.table_name(),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::ObservabilityRecordsByKind, value)
    }

    pub async fn replace_cue_rows(
        &self,
        project_id: ProjectId,
        record_ref: &str,
        rows: &[CueIndexRow],
    ) -> Result<(), StoreError> {
        let op = if rows.is_empty() {
            NamedSurqlOp::DeleteCueRows
        } else {
            NamedSurqlOp::UpsertCueRows
        };
        let projection_rows = cue_projection_rows(rows);
        self.execute_value(
            op,
            json!({
                "project_id": project_id,
                "replace_project": false,
                "record_ref_parts": cue_string_parts(record_ref),
                "record_ref_key": cue_record_ref_key(record_ref),
                "rows": projection_rows,
            }),
        )
        .await?;
        Ok(())
    }

    pub async fn replace_project_cue_rows(
        &self,
        project_id: ProjectId,
        rows: &[CueIndexRow],
    ) -> Result<(), StoreError> {
        self.execute_value(
            NamedSurqlOp::UpsertCueRows,
            json!({
                "project_id": project_id,
                "replace_project": true,
                "record_ref_parts": [],
                "record_ref_key": "",
                "rows": cue_projection_rows(rows),
            }),
        )
        .await?;
        Ok(())
    }

    pub async fn load_cue_rows(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<CueIndexRow>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadCueRows,
                json!({ "project_id": project_id }),
            )
            .await?;
        if value.get("truncated").and_then(Value::as_bool) == Some(true) {
            return Err(StoreError::PolicyViolation(
                "cue index exceeded the 10,000 row project cap".to_owned(),
            ));
        }
        let rows = value
            .get("rows")
            .cloned()
            .ok_or_else(|| StoreError::Decode("cue index response omitted rows".to_owned()))?;
        serde_json::from_value(rows).map_err(|error| StoreError::Decode(error.to_string()))
    }

    pub async fn load_cue_records(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<CueRecordSource>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadCueRecords,
                json!({ "project_id": project_id }),
            )
            .await?;
        if value.get("truncated").and_then(Value::as_bool) == Some(true) {
            return Err(StoreError::PolicyViolation(
                "canonical cue sources exceeded the 10,000 record project cap".to_owned(),
            ));
        }
        let records = value
            .get("records")
            .cloned()
            .ok_or_else(|| StoreError::Decode("cue source response omitted records".to_owned()))?;
        serde_json::from_value(records).map_err(|error| StoreError::Decode(error.to_string()))
    }

    pub async fn load_injection_receipts(
        &self,
        project_id: ProjectId,
        session_id: eliot_types::SessionId,
    ) -> Result<Vec<InjectionReceipt>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadInjectionReceipts,
                json!({
                    "project_id": project_id,
                    "session_id": session_id,
                }),
            )
            .await?;
        if value.get("truncated").and_then(Value::as_bool) == Some(true) {
            return Err(StoreError::PolicyViolation(
                "injection receipts exceeded the 10,000 session cap".to_owned(),
            ));
        }
        let receipts = value.get("receipts").cloned().ok_or_else(|| {
            StoreError::Decode("injection receipt response omitted receipts".to_owned())
        })?;
        serde_json::from_value(receipts).map_err(|error| StoreError::Decode(error.to_string()))
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
        if request.lifecycle_audit {
            return self.recall_l0_paged(request).await;
        }
        for _attempt in 0..RECALL_REVISION_RESTART_ATTEMPTS {
            let value = self
                .execute_value(
                    NamedSurqlOp::LoadMemorySearchCandidates,
                    json!({
                        "project_id": request.project_id,
                        "exact_handle_parts": exact_memory_search_handle(&request.query)
                            .map(|handle| string_fragments(&handle)),
                        "tokens": memory_search_terms(request),
                        "query_text": memory_search_query_text(request),
                        "candidate_limit": MAX_MEMORY_SEARCH_CANDIDATES,
                    }),
                )
                .await?;
            let load: MemorySearchCandidateLoad =
                decode_value(NamedSurqlOp::LoadMemorySearchCandidates, value)?;
            if load.projection_revision != Some(load.at_revision) {
                self.rebuild_memory_search_projection(request.project_id)
                    .await?;
                continue;
            }
            return Ok(rank_memory_search_candidates(request, load));
        }
        Err(StoreError::PolicyViolation(
            "memory search projection could not catch up to a stable project revision after 3 attempts"
                .to_owned(),
        ))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn recall_l0_fts_candidate(
        &self,
        request: &RecallL0Request,
    ) -> Result<RecallL0Response, StoreError> {
        if request.lifecycle_audit {
            return Err(StoreError::PolicyViolation(
                "the FTS candidate path does not serve lifecycle-audit recall".to_owned(),
            ));
        }
        let value = self
            .execute_value(
                NamedSurqlOp::LoadMemorySearchFtsCandidates,
                json!({
                    "project_id": request.project_id,
                    "exact_handle_parts": exact_memory_search_handle(&request.query)
                        .map(|handle| string_fragments(&handle)),
                    "query_text": memory_search_query_text(request),
                    "candidate_limit": MAX_MEMORY_SEARCH_CANDIDATES,
                }),
            )
            .await?;
        let load: MemorySearchCandidateLoad =
            decode_value(NamedSurqlOp::LoadMemorySearchFtsCandidates, value)?;
        if load.projection_format.as_deref() != Some(MEMORY_SEARCH_FTS_PROJECTION_FORMAT) {
            return Err(StoreError::PolicyViolation(
                "the FTS candidate path requires an explicit fts_v1 full rebuild".to_owned(),
            ));
        }
        if load.projection_revision != Some(load.at_revision) {
            return Err(StoreError::PolicyViolation(
                "the FTS candidate projection is not at the current project revision".to_owned(),
            ));
        }
        Ok(rank_memory_search_candidates(request, load))
    }

    async fn recall_l0_paged(
        &self,
        request: &RecallL0Request,
    ) -> Result<RecallL0Response, StoreError> {
        let load = self
            .load_paged_recall_candidates(request.project_id, true, MAX_RECALL_SCAN_CANDIDATES)
            .await?;
        Ok(rank_recall_candidates(request, load))
    }

    async fn load_paged_recall_candidates(
        &self,
        project_id: ProjectId,
        lifecycle_audit: bool,
        max_candidates: usize,
    ) -> Result<RecallCandidateLoad, StoreError> {
        for _attempt in 0..RECALL_REVISION_RESTART_ATTEMPTS {
            let mut at_revision = None;
            let mut candidates = Vec::new();
            let mut scan_truncated = false;
            let mut revision_drift = false;
            'projection: for kind in RECALL_CANDIDATE_KINDS {
                let mut start = 0;
                loop {
                    let value = self
                        .execute_value(
                            NamedSurqlOp::LoadRecallCandidates,
                            json!({
                                "project_id": project_id,
                                "kind": kind,
                                "start": start,
                                "limit": RECALL_CANDIDATE_PAGE_SIZE,
                                "lifecycle_audit": lifecycle_audit,
                            }),
                        )
                        .await?;
                    let mut page: RecallCandidateLoad =
                        decode_value(NamedSurqlOp::LoadRecallCandidates, value)?;
                    if at_revision.is_some_and(|revision| revision != page.at_revision) {
                        revision_drift = true;
                        break 'projection;
                    }
                    at_revision.get_or_insert(page.at_revision);
                    let page_len = page.candidates.len();
                    let remaining = max_candidates.saturating_sub(candidates.len());
                    if page_len > remaining {
                        page.candidates.truncate(remaining);
                        scan_truncated = true;
                    }
                    candidates.append(&mut page.candidates);
                    if scan_truncated {
                        break 'projection;
                    }
                    if !page.truncated {
                        break;
                    }
                    if page_len == 0 {
                        return Err(StoreError::PolicyViolation(
                            "recall candidate projection returned an empty truncated page"
                                .to_owned(),
                        ));
                    }
                    start += page_len;
                }
            }
            if revision_drift {
                continue;
            }
            let head_value = self
                .execute_value(
                    NamedSurqlOp::LoadRecallCandidates,
                    json!({
                        "project_id": project_id,
                        "kind": "head",
                        "start": 0,
                        "limit": 1,
                        "lifecycle_audit": lifecycle_audit,
                    }),
                )
                .await?;
            let head: RecallCandidateLoad =
                decode_value(NamedSurqlOp::LoadRecallCandidates, head_value)?;
            if at_revision.is_some_and(|revision| revision != head.at_revision) {
                continue;
            }
            return Ok(RecallCandidateLoad {
                at_revision: head.at_revision,
                candidates,
                truncated: scan_truncated,
            });
        }
        Err(StoreError::PolicyViolation(
            "recall candidate projection could not obtain a stable project revision after 3 attempts"
                .to_owned(),
        ))
    }

    /// Rebuilds the derived search projection from canonical rows. Canonical
    /// tables remain the source of truth; a revision drift leaves the state
    /// marker behind the head so the next read retries instead of trusting a
    /// mixed snapshot.
    pub async fn rebuild_memory_search_projection(
        &self,
        project_id: ProjectId,
    ) -> Result<MemoryRevision, StoreError> {
        const MAX_REBUILD_CANDIDATES: usize = 250_000;
        let load = self
            .load_paged_recall_candidates(project_id, true, MAX_REBUILD_CANDIDATES)
            .await?;
        if load.truncated {
            return Err(StoreError::PolicyViolation(format!(
                "memory search rebuild exceeded the {MAX_REBUILD_CANDIDATES} candidate safety cap"
            )));
        }
        let rows = load
            .candidates
            .iter()
            .map(|row| projection_row(project_id, row, load.at_revision))
            .collect::<Result<Vec<_>, _>>()?;
        self.execute_value(
            NamedSurqlOp::ResetMemorySearchProjection,
            json!({ "project_id": project_id }),
        )
        .await?;
        self.dispatch_memory_search_projection(
            project_id,
            WriteId::new_v7(),
            load.at_revision,
            &rows,
            Some(MEMORY_SEARCH_FTS_PROJECTION_FORMAT),
        )
        .await?;
        Ok(load.at_revision)
    }

    pub async fn memory_search_query_plan(
        &self,
        project_id: ProjectId,
        query: &str,
    ) -> Result<Value, StoreError> {
        let tokens = eliot_types::normalize_query_tokens(query)
            .into_iter()
            .take(MAX_MEMORY_SEARCH_QUERY_TERMS)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        self.execute_value(
            NamedSurqlOp::ExplainMemorySearchPostings,
            json!({
                "project_id": project_id,
                "tokens": tokens,
                "candidate_limit": MAX_MEMORY_SEARCH_CANDIDATES,
            }),
        )
        .await
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn memory_search_fts_query_plan(
        &self,
        project_id: ProjectId,
        query: &str,
    ) -> Result<Value, StoreError> {
        let query_text =
            ordered_memory_search_terms([query], MAX_MEMORY_SEARCH_QUERY_TERMS).join(" ");
        self.execute_value(
            NamedSurqlOp::ExplainMemorySearchFts,
            json!({
                "project_id": project_id,
                "exact_handle_parts": exact_memory_search_handle(query)
                    .map(|handle| string_fragments(&handle)),
                "query_text": query_text,
                "candidate_limit": MAX_MEMORY_SEARCH_CANDIDATES,
            }),
        )
        .await
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

    pub async fn graph_health(
        &self,
        project_id: ProjectId,
    ) -> Result<GraphHealthResponse, StoreError> {
        const GRAPH_HEALTH_SCAN_LIMIT: u64 = 10_000;
        let schema = self
            .execute_value(
                NamedSurqlOp::GraphHealthCapabilities,
                Value::Object(serde_json::Map::new()),
            )
            .await?;
        let tables = schema
            .get("tables")
            .and_then(Value::as_object)
            .ok_or_else(|| {
                StoreError::Decode(
                    "graph_health_capabilities output omitted the database table map".to_owned(),
                )
            })?;
        let value = self
            .execute_value(
                NamedSurqlOp::GraphHealth,
                json!({
                    "project_id": project_id,
                    "scan_limit": GRAPH_HEALTH_SCAN_LIMIT,
                    "scan_fetch_limit": GRAPH_HEALTH_SCAN_LIMIT + 1,
                    "has_invalidated_by": tables.contains_key("invalidated_by"),
                    "has_scope_head": tables.contains_key("scope_head"),
                    "has_write_receipt": tables.contains_key("write_receipt"),
                }),
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
        self.canonical_record_page_at_revision(
            project_id,
            task_id,
            receipt_kinds,
            None,
            start,
            limit,
        )
        .await
    }

    pub async fn canonical_record_page_at_revision(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        receipt_kinds: &[&str],
        at_revision: Option<MemoryRevision>,
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
                    "at_revision": at_revision,
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

    pub async fn ul_artifact_by_id<T>(
        &self,
        project_id: ProjectId,
        receipt_kind: &str,
        artifact_id: &str,
    ) -> Result<Option<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        let mut records = self
            .canonical_records_by_subject_ref(project_id, None, &[receipt_kind], artifact_id, 2)
            .await?;
        if records.len() > 1 {
            return Err(StoreError::Decode(format!(
                "UL artifact {artifact_id} resolved to multiple canonical records"
            )));
        }
        Ok(records.pop())
    }

    pub async fn ul_artifacts_by_kind<T>(
        &self,
        project_id: ProjectId,
        receipt_kind: &str,
        limit: u16,
    ) -> Result<Vec<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        self.canonical_records_by_kind(project_id, None, &[receipt_kind], limit)
            .await
    }

    pub async fn load_ul_artifacts<T>(
        &self,
        project_id: ProjectId,
        receipt_kinds: &[&str],
        page_size: u16,
    ) -> Result<Vec<CanonicalRecord<T>>, StoreError>
    where
        T: DeserializeOwned,
    {
        let page_size = page_size.clamp(1, crate::UL_ARTIFACT_PAGE_SIZE);
        let mut records = Vec::new();
        loop {
            let value = self
                .execute_value(
                    NamedSurqlOp::LoadUlArtifacts,
                    json!({
                        "project_id": project_id,
                        "receipt_kinds": receipt_kinds,
                        "start": records.len(),
                        "limit": page_size,
                    }),
                )
                .await?;
            let page: Vec<CanonicalRecord<T>> = decode_value(NamedSurqlOp::LoadUlArtifacts, value)?;
            if records.len().saturating_add(page.len()) > crate::MAX_CURRENT_UL_ARTIFACTS {
                return Err(StoreError::Decode(format!(
                    "current UL projection exceeds the explicit {}-artifact safety bound",
                    crate::MAX_CURRENT_UL_ARTIFACTS
                )));
            }
            let complete = page.len() < usize::from(page_size);
            records.extend(page);
            if complete {
                return Ok(records);
            }
        }
    }

    pub async fn replace_ul_reverse_dependencies(
        &self,
        project_id: ProjectId,
        target_kind: eliot_types::PyramidTargetKind,
        target_id: &str,
        build_id: &str,
        dependencies: &[eliot_types::UlDependencyRef],
    ) -> Result<(), StoreError> {
        let mut dependencies = dependencies.to_vec();
        dependencies.sort();
        dependencies.dedup();
        let value = self
            .execute_value(
                NamedSurqlOp::ReplaceUlReverseDependencies,
                json!({
                    "project_id": project_id,
                    "target_kind": target_kind,
                    "target_id": target_id,
                    "build_id": build_id,
                    "dependencies": dependencies,
                }),
            )
            .await?;
        let _: Vec<eliot_types::UlReverseDependencyRow> =
            decode_value(NamedSurqlOp::ReplaceUlReverseDependencies, value)?;
        Ok(())
    }

    pub async fn load_ul_reverse_dependents(
        &self,
        project_id: ProjectId,
        dependencies: &[eliot_types::UlDependencyRef],
    ) -> Result<Vec<eliot_types::UlReverseDependencyRow>, StoreError> {
        let expected = dependencies.iter().cloned().collect::<BTreeSet<_>>();
        if expected.is_empty() {
            return Ok(Vec::new());
        }
        let dependency_kinds = expected
            .iter()
            .map(|dependency| dependency.kind)
            .collect::<BTreeSet<_>>();
        let dependency_keys = expected
            .iter()
            .map(|dependency| dependency.key.clone())
            .collect::<BTreeSet<_>>();
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlReverseDependents,
                json!({
                    "project_id": project_id,
                    "dependency_kinds": dependency_kinds,
                    "dependency_keys": dependency_keys,
                }),
            )
            .await?;
        let mut rows: Vec<eliot_types::UlReverseDependencyRow> =
            decode_value(NamedSurqlOp::LoadUlReverseDependents, value)?;
        rows.retain(|row| expected.contains(&row.dependency));
        rows.sort_by(|left, right| {
            left.target_kind
                .cmp(&right.target_kind)
                .then_with(|| left.target_id.cmp(&right.target_id))
                .then_with(|| left.dependency.cmp(&right.dependency))
        });
        rows.dedup();
        Ok(rows)
    }

    pub async fn mark_ul_artifact_dirty(
        &self,
        state: &eliot_types::UlArtifactDirtyState,
    ) -> Result<(), StoreError> {
        let mut state = state.clone();
        state.reasons.sort();
        state.reasons.dedup();
        let state_key = blake3::hash(
            format!(
                "{}|{:?}|{}",
                state.project_id, state.target_kind, state.target_id
            )
            .as_bytes(),
        )
        .to_hex()
        .to_string();
        let value = self
            .execute_value(
                NamedSurqlOp::UpsertUlArtifactDirty,
                json!({ "state_key": state_key, "state": state }),
            )
            .await?;
        let _: eliot_types::UlArtifactDirtyState =
            decode_value(NamedSurqlOp::UpsertUlArtifactDirty, value)?;
        Ok(())
    }

    pub async fn load_ul_dirty_artifacts(
        &self,
        project_id: ProjectId,
        limit: u16,
    ) -> Result<Vec<eliot_types::UlArtifactDirtyState>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlArtifactDirty,
                json!({ "project_id": project_id, "limit": limit.clamp(1, 512) }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadUlArtifactDirty, value)
    }

    pub async fn clear_ul_artifact_dirty(
        &self,
        project_id: ProjectId,
        target_kind: eliot_types::PyramidTargetKind,
        target_id: &str,
        superseding_build_id: &str,
    ) -> Result<(), StoreError> {
        let _ = self
            .execute_value(
                NamedSurqlOp::ClearUlArtifactDirty,
                json!({
                    "project_id": project_id,
                    "target_kind": target_kind,
                    "target_id": target_id,
                    "superseding_build_id": superseding_build_id,
                }),
            )
            .await?;
        Ok(())
    }

    pub async fn load_ul_activation_graph(
        &self,
        project_id: ProjectId,
    ) -> Result<eliot_types::UlActivationGraphRows, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlActivationGraph,
                json!({ "project_id": project_id }),
            )
            .await?;
        let mut raw: RawActivationGraphRows =
            decode_value(NamedSurqlOp::LoadUlActivationGraph, value)?;
        let mut seen_co_change = std::collections::BTreeSet::new();
        raw.co_change
            .retain(|edge| seen_co_change.insert(edge.edge_id.clone()));
        raw.co_change
            .sort_by(|left, right| left.edge_id.cmp(&right.edge_id));
        let mut relations = Vec::new();
        append_activation_relations(
            &mut relations,
            raw.card_covers,
            eliot_types::ActivationEdgeKind::CardCovers,
        );
        append_activation_relations(
            &mut relations,
            raw.capsule_covers,
            eliot_types::ActivationEdgeKind::CapsuleCovers,
        );
        append_activation_relations(
            &mut relations,
            raw.concept_implemented_by,
            eliot_types::ActivationEdgeKind::ConceptImplementedBy,
        );
        append_activation_relations(
            &mut relations,
            raw.concept_depends_on,
            eliot_types::ActivationEdgeKind::ConceptDependsOn,
        );
        append_activation_relations(
            &mut relations,
            raw.supports,
            eliot_types::ActivationEdgeKind::Supports,
        );
        append_activation_relations(
            &mut relations,
            raw.verified_by,
            eliot_types::ActivationEdgeKind::VerifiedBy,
        );
        relations.sort_by(|left, right| {
            left.from_ref
                .cmp(&right.from_ref)
                .then_with(|| left.to_ref.cmp(&right.to_ref))
                .then_with(|| left.kind.cmp(&right.kind))
        });
        relations.dedup();
        Ok(eliot_types::UlActivationGraphRows {
            co_change: raw.co_change,
            relations,
        })
    }

    pub async fn upsert_ul_task_ledger(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        delta: &eliot_types::UlLedgerDelta,
    ) -> Result<eliot_types::UlTaskLedger, StoreError> {
        let ledger_key = format!("{project_id}:{task_id}");
        let value = self
            .execute_value(
                NamedSurqlOp::UpsertUlTaskLedger,
                json!({
                    "ledger_key": ledger_key,
                    "project_id": project_id,
                    "task_id": task_id,
                    "delta": delta,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::UpsertUlTaskLedger, value)
    }

    pub async fn assign_ul_experiment_arm(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        task_class: &eliot_types::UlTaskClass,
        config_hash: &str,
    ) -> Result<eliot_types::UlTaskExperimentAssignment, StoreError> {
        let task_class_key = task_class.key();
        let assignment_key = derived_row_key(&format!("ul-experiment|{project_id}|{task_id}"));
        let counter_key = derived_row_key(&format!("ul-ab-counter|{project_id}|{task_class_key}"));
        let value = self
            .execute_value(
                NamedSurqlOp::AssignUlExperimentArm,
                json!({
                    "assignment_key": assignment_key,
                    "counter_key": counter_key,
                    "project_id": project_id,
                    "task_id": task_id,
                    "task_class": task_class,
                    "task_class_key": task_class_key,
                    "config_hash": config_hash,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::AssignUlExperimentArm, value)
    }

    pub async fn upsert_ul_experiment_assignment_explicit(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        task_class: &eliot_types::UlTaskClass,
        arm: eliot_types::UlExperimentArm,
        injection_mode: eliot_types::UlInjectionMode,
        config_hash: &str,
    ) -> Result<eliot_types::UlTaskExperimentAssignment, StoreError> {
        let task_class_key = task_class.key();
        let assignment_key = derived_row_key(&format!("ul-experiment|{project_id}|{task_id}"));
        let value = self
            .execute_value(
                NamedSurqlOp::UpsertUlExperimentAssignmentExplicit,
                json!({
                    "assignment_key": assignment_key,
                    "project_id": project_id,
                    "task_id": task_id,
                    "task_class": task_class,
                    "task_class_key": task_class_key,
                    "arm": arm,
                    "injection_mode": injection_mode,
                    "config_hash": config_hash,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::UpsertUlExperimentAssignmentExplicit, value)
    }
    pub async fn load_ul_experiment_assignment(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
    ) -> Result<Option<eliot_types::UlTaskExperimentAssignment>, StoreError> {
        let assignment_key = derived_row_key(&format!("ul-experiment|{project_id}|{task_id}"));
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlExperimentAssignment,
                json!({ "assignment_key": assignment_key }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadUlExperimentAssignment, value)
    }

    pub async fn load_ul_task_class_ledgers(
        &self,
        project_id: ProjectId,
        task_class_key: &str,
    ) -> Result<Vec<eliot_types::UlTaskLedger>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlTaskClassLedgers,
                json!({
                    "project_id": project_id,
                    "task_class_key": task_class_key,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadUlTaskClassLedgers, value)
    }

    pub async fn upsert_ul_task_class_policy(
        &self,
        policy: &eliot_types::UlTaskClassPolicy,
    ) -> Result<eliot_types::UlTaskClassPolicy, StoreError> {
        let policy_key = derived_row_key(&format!(
            "ul-task-class-policy|{}|{}",
            policy.project_id, policy.task_class_key
        ));
        let value = self
            .execute_value(
                NamedSurqlOp::UpsertUlTaskClassPolicy,
                json!({
                    "policy_key": policy_key,
                    "policy": policy,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::UpsertUlTaskClassPolicy, value)
    }

    pub async fn load_ul_task_class_policy(
        &self,
        project_id: ProjectId,
        task_class_key: &str,
    ) -> Result<Option<eliot_types::UlTaskClassPolicy>, StoreError> {
        let policy_key = derived_row_key(&format!(
            "ul-task-class-policy|{project_id}|{task_class_key}"
        ));
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlTaskClassPolicy,
                json!({ "policy_key": policy_key }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadUlTaskClassPolicy, value)
    }

    pub async fn load_ul_metrics(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<eliot_types::UlTaskLedger>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlMetrics,
                json!({ "project_id": project_id }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadUlMetrics, value)
    }

    pub async fn load_ul_readiness_inventory(
        &self,
        project_id: ProjectId,
    ) -> Result<eliot_types::UlGraphInventory, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadUlReadiness,
                json!({ "project_id": project_id }),
            )
            .await?;
        let mut inventory: eliot_types::UlGraphInventory =
            decode_value(NamedSurqlOp::LoadUlReadiness, value)?;
        inventory.total_ul_edges = inventory
            .co_change_edges
            .saturating_add(inventory.card_covers_edges)
            .saturating_add(inventory.concept_implemented_by_edges)
            .saturating_add(inventory.concept_depends_on_edges)
            .saturating_add(inventory.capsule_covers_edges);
        Ok(inventory)
    }

    pub async fn load_predictions(
        &self,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        verifier: Option<&str>,
        unresolved_only: bool,
        created_before: Option<time::OffsetDateTime>,
    ) -> Result<Vec<eliot_types::PredictionRecord>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadPredictions,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "has_task_id": task_id.is_some(),
                    "verifier": verifier.unwrap_or_default(),
                    "has_verifier": verifier.is_some(),
                    "unresolved_only": unresolved_only,
                    "created_before": created_before.unwrap_or_else(time::OffsetDateTime::now_utc),
                    "has_created_before": created_before.is_some(),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadPredictions, value)
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
        let raw = if let Some(client_set) = self.client_set.as_ref() {
            client_set.execute_named(op, vars).await?
        } else {
            let server = SurrealServerSupervisor::new(self.config.clone())
                .start_or_connect()
                .await?;
            let raw_result = server.transport()?.query(template.sql, vars).await;
            let shutdown_result = server.shutdown_if_spawned().await;
            let raw = raw_result?;
            shutdown_result?;
            raw
        };
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

fn append_activation_relations(
    output: &mut Vec<eliot_types::UlActivationGraphEdge>,
    rows: Vec<RawActivationRelation>,
    kind: eliot_types::ActivationEdgeKind,
) {
    output.extend(
        rows.into_iter()
            .map(|row| eliot_types::UlActivationGraphEdge {
                from_ref: row.from_ref,
                to_ref: row.to_ref,
                kind,
            }),
    );
}

fn cue_string_parts(value: &str) -> Vec<&str> {
    value.split(':').collect()
}

fn cue_record_ref_key(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

fn cue_projection_rows(rows: &[CueIndexRow]) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            json!({
                "row_id_parts": cue_string_parts(&row.row_id),
                "project_id": row.project_id,
                "cue_kind": row.cue_kind,
                "cue_value_parts": cue_string_parts(&row.cue_value_norm),
                "match_mode": row.match_mode,
                "record_ref_parts": cue_string_parts(&row.record_ref),
                "record_ref_key": cue_record_ref_key(&row.record_ref),
                "record_kind": row.record_kind,
                "strength": row.strength,
                "negative_memory": row.negative_memory,
                "lifecycle": row.lifecycle,
                "token_estimate": row.token_estimate,
            })
        })
        .collect()
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
                "cue_preview_fragments": canonical_field_fragments(body, "body_md"),
            }))
        })
        .collect()
}

fn relation_payloads(envelope: &MemoryWriteEnvelope) -> Vec<Value> {
    envelope
        .relations
        .iter()
        .map(|relation| {
            json!({
                "relation_type": relation.relation_type,
                "from_fragments": string_fragments(&relation.from),
                "to_fragments": string_fragments(&relation.to),
            })
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

fn derived_row_key(value: &str) -> String {
    blake3::hash(value.as_bytes()).to_hex().to_string()
}

#[cfg(test)]
mod fts_live_tests;

#[cfg(test)]
mod memory_search_selector_tests {
    use super::*;

    fn recall_request() -> RecallL0Request {
        RecallL0Request {
            project_id: ProjectId::new_v7(),
            query: "zeta alpha shared".to_owned(),
            consistency: eliot_types::ReadConsistencyMode::Latest,
            at_least_revision: None,
            lifecycle_audit: false,
            task_id: None,
            task_class_cues: vec!["shared omega beta".to_owned(), "gamma".to_owned()],
            scope_refs: Vec::new(),
            concept_refs: vec![
                "concept0 beta concept1 concept2".to_owned(),
                "concept3 concept4 concept5 concept6".to_owned(),
            ],
        }
    }

    fn candidate_row() -> RecallCandidateRow {
        RecallCandidateRow {
            record_ref: "claim_card:Opaque-ID".to_owned(),
            handle: "claim:Opaque-ID".to_owned(),
            record_type: "claim_card".to_owned(),
            preview: "Preview path".to_owned(),
            search_text: "Remaining Preview".to_owned(),
            cue_text: "path Symbol".to_owned(),
            scope_text: "Scope Remaining".to_owned(),
            concept_text: "Concept Symbol".to_owned(),
            task_id: None,
            status: "supported".to_owned(),
            lifecycle_state: Some(eliot_types::MemoryLifecycleState::Active),
            authority_rank: 100,
            negative_memory: false,
            memory_revision: Some(MemoryRevision::new(7)),
            project_sequence: Some(ProjectSequence::new(9)),
            verification_value: 1,
            known_decision_delta: 2,
            prior_beneficial_use: 3,
            contradiction_signal: false,
            harm_signal: false,
            repetition_signal: false,
            distraction_signal: false,
        }
    }

    #[test]
    fn query_selector_is_stable_priority_ordered_deduplicated_and_capped() {
        let request = recall_request();
        let expected = vec![
            "zeta", "alpha", "shared", "omega", "beta", "gamma", "concept0", "concept1",
            "concept2", "concept3", "concept4", "concept5",
        ];

        assert_eq!(memory_search_terms(&request), expected);
        assert_eq!(memory_search_query_text(&request), expected.join(" "));
    }

    #[test]
    fn document_selector_preserves_field_priority_and_projection_persists_it()
    -> Result<(), StoreError> {
        let row = candidate_row();
        let expected = vec![
            "claim",
            "opaque",
            "id",
            "card",
            "path",
            "symbol",
            "concept",
            "preview",
            "remaining",
            "scope",
        ];

        assert_eq!(memory_search_document_terms(&row), expected);
        let projection = projection_row(ProjectId::new_v7(), &row, MemoryRevision::new(7))?;
        let expected_document = expected.join(" ");
        assert_eq!(
            projection.get("search_document").and_then(Value::as_str),
            Some(expected_document.as_str())
        );
        let posting_tokens = projection
            .get("postings")
            .and_then(Value::as_array)
            .and_then(|postings| {
                postings
                    .iter()
                    .map(|posting| posting.get("token").and_then(Value::as_str))
                    .collect::<Option<Vec<_>>>()
            });
        assert_eq!(posting_tokens, Some(expected));
        Ok(())
    }

    #[test]
    fn document_selector_caps_after_higher_priority_fields() {
        let mut row = candidate_row();
        row.search_text = (0..MAX_MEMORY_SEARCH_DOCUMENT_TERMS)
            .map(|index| format!("search{index:04}"))
            .collect::<Vec<_>>()
            .join(" ");
        row.scope_text = "scope_tail".to_owned();

        let terms = memory_search_document_terms(&row);

        assert_eq!(terms.len(), MAX_MEMORY_SEARCH_DOCUMENT_TERMS);
        assert_eq!(
            &terms[..8],
            [
                "claim", "opaque", "id", "card", "path", "symbol", "concept", "preview",
            ]
        );
        assert_eq!(terms[8], "search0000");
        assert!(!terms.iter().any(|term| term == "scope" || term == "tail"));
    }

    #[test]
    fn projection_format_is_explicit_only_for_full_rebuild_dispatch() {
        let project_id = ProjectId::new_v7();
        let write_id = WriteId::new_v7();
        let revision = MemoryRevision::new(11);
        let incremental =
            memory_search_projection_dispatch_vars(project_id, write_id, revision, &[], true, None);
        let full_rebuild = memory_search_projection_dispatch_vars(
            project_id,
            write_id,
            revision,
            &[],
            true,
            Some(MEMORY_SEARCH_FTS_PROJECTION_FORMAT),
        );

        assert_eq!(incremental["projection_format"], Value::Null);
        assert_eq!(
            full_rebuild["projection_format"],
            MEMORY_SEARCH_FTS_PROJECTION_FORMAT
        );
    }

    #[test]
    fn fts_candidate_load_decodes_projection_format() -> Result<(), serde_json::Error> {
        let load: MemorySearchCandidateLoad = serde_json::from_value(json!({
            "at_revision": 13,
            "projection_revision": 13,
            "projection_format": MEMORY_SEARCH_FTS_PROJECTION_FORMAT,
            "ordered_handles": [],
            "candidates": [],
            "truncated": false,
        }))?;

        assert_eq!(
            load.projection_format.as_deref(),
            Some(MEMORY_SEARCH_FTS_PROJECTION_FORMAT)
        );
        Ok(())
    }

    #[test]
    fn fts_candidate_helper_is_phase_wired() {
        let _ = CanonicalStore::recall_l0_fts_candidate;
    }
}
