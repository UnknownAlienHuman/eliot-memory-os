use crate::blob_store::verify_canonical_memory_child_set;
use crate::surreal_server::SurrealServerSupervisor;
use crate::{
    BlobStore, CanonicalAutonomyRunView, CanonicalLifecycleView, CanonicalRecord,
    CanonicalSleepView, DbClientSet, MAX_CANONICAL_RECORDS, NamedSurqlOp, SleepCandidatesResponse,
    StoreError, SurqlTemplateRegistry,
};

#[path = "canonical_secret_report.rs"]
mod canonical_secret_report;
mod capacity;
mod recall_ranking;
mod replay_view;
mod ul_artifact_loaders;
use crate::canonical_activation_graph_models::{RawActivationGraphRows, RawActivationRelation};
pub use crate::canonical_cognitive_projection::{
    CognitiveProjectionBacklog, CognitiveProjectionFamily, CognitiveProjectionFamilyCounts,
    CognitiveProjectionFamilyState, CognitiveProjectionIntentReceipt, CognitiveProjectionLease,
    CognitiveProjectionProject, CognitiveProjectionProjectPage,
    CognitiveProjectionPublicationStatus,
};
use crate::canonical_cognitive_projection::{
    CognitiveProjectionClaimLoad, CognitiveProjectionMutationResult,
};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
pub use canonical_secret_report::{CanonicalSecretScanFinding, CanonicalSecretScanReport};
use capacity::{
    capacity_manifests, is_blake3_hex, is_lower_blake3_hex, strongest_retention,
    validate_capacity_receipt,
};
use eliot_types::{
    AutonomyRunContract, AutonomyRunTransitionReceipt, BlobReachabilityRef, BlobReferenceSnapshot,
    BlobRetentionClass, BlobRetentionRef, CanonicalMemoryL2Page, CanonicalMemoryManifest,
    CanonicalMemorySegment, CanonicalMemorySegmentRef, CanonicalTraceCompletenessContract, ClaimId,
    CognitiveProjectionReadState, CueBindingPage, CueIndexRow, CueRecordSource,
    CurrentStateRequest, CurrentStateResponse, EpistemicStatus, FetchAtomsL2Request,
    FetchAtomsL2Response, GraphHealthResponse, InjectionReceipt, LifecycleStatus,
    MemoryGrantOfferRecord, MemoryInfluenceTrace, MemoryRevision, MemoryStateTransition,
    MemoryTrajectoryCorrectness, MemoryWriteEnvelope, MetaPolicyExecutionAction,
    MetaPolicyExecutionReceipt, MinorityPressureRecord, ObservabilityKind,
    ObservabilityWriteEnvelope, ObservabilityWriteReceipt, ObservabilityWriteStatus, ProjectId,
    ProjectSequence, RecallL0Request, RecallL0Response, SessionId, SleepCandidateArtifact,
    SleepConsolidationBundle, SleepConsolidationRun, SurrealServerConfig, TaskContract, TaskId,
    ToolObservation, VerificationId, VerificationRun, WriteId, WriteReceipt, WriteStatus,
};
use recall_ranking::{is_default_visible_lifecycle, rank_recall_candidates};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::time::{Duration, sleep};

const SCHEMA_MIGRATE_RETRY_ATTEMPTS: u8 = 30;
const SCHEMA_MIGRATE_RETRY_BASE_MS: u64 = 50;
const SCHEMA_MIGRATE_RETRY_MAX_MS: u64 = 500;
const MAX_BLOB_REFERENCE_RECORDS: u16 = 512;
const MAX_EXACT_L2_HANDLES: usize = 64;
const MAX_EXACT_L2_REQUEST_HANDLES: usize = 512;
const MAX_EXACT_L2_HANDLE_BYTES: usize = 512;
const CANONICAL_MEMORY_L2_PAGE_SIZE: u16 = 32;
const CANONICAL_MEMORY_L2_MANIFEST_PAGE_SIZE: u16 = 1;
const CANONICAL_MEMORY_L2_MAX_SCANNED_ROWS: u64 = 4_096;
const CANONICAL_MEMORY_ADMISSION_PAGE_SIZE: u16 = 1;
const CANONICAL_MEMORY_ADMISSION_MAX_SCANNED_ROWS: u64 = 4_096;
const CANONICAL_MEMORY_CHILD_BODY_MAX_BYTES: usize = 128 * 1024;

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
const MAX_MEMORY_SEARCH_DOCUMENT_TERMS: usize = 2048;
const MEMORY_SEARCH_DISPATCH_BATCH_SIZE: usize = 512;
const MEMORY_SEARCH_FTS_PROJECTION_FORMAT: &str = "fts_v1";
const MAX_COGNITIVE_PROJECTION_LEASE_ROWS: u16 = 512;
const MAX_COGNITIVE_PROJECTION_LEASE_SECONDS: u64 = 3_600;
const COGNITIVE_PROJECTION_PROJECT_PAGE_SIZE: usize = 100;

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
    source_segment_ordinal: Option<u64>,
    #[serde(default)]
    source_segment_count: Option<u64>,
    #[serde(default)]
    source_byte_start: Option<u64>,
    #[serde(default)]
    source_byte_end_exclusive: Option<u64>,
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
    projection_status: Option<CognitiveProjectionPublicationStatus>,
    #[serde(default)]
    family_target_revision: Option<MemoryRevision>,
    #[serde(default)]
    family_applied_revision: Option<MemoryRevision>,
    #[serde(default)]
    ordered_handles: Vec<String>,
    candidates: Vec<RecallCandidateRow>,
    truncated: bool,
}

#[derive(Debug, serde::Deserialize)]
struct CanonicalMemoryL2Load {
    #[serde(default)]
    requested_segment_body_b64: Option<String>,
    #[serde(default)]
    manifest_bodies_b64: Vec<String>,
    truncated: bool,
}

#[derive(Debug, serde::Deserialize)]
struct CanonicalMemoryAdmissionChildLoad {
    #[serde(default)]
    bodies_b64: Vec<String>,
    truncated: bool,
}

#[derive(Debug, serde::Deserialize)]
struct CanonicalMemoryProjectionRecord {
    record_id: String,
    receipt_body: CanonicalMemorySegment,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum L2HandleKind {
    Any,
    CanonicalMemory,
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
        (
            "memory-segment:",
            L2HandleKind::CanonicalMemory,
            "memory-segment:",
        ),
        ("memory:", L2HandleKind::CanonicalMemory, "memory:"),
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
        if selector.kind == L2HandleKind::CanonicalMemory {
            continue;
        }
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
        + response.canonical_memory_pages.len()
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
    response.canonical_memory_pages.sort_by_cached_key(|page| {
        let (kind, identity, _) = parse_l2_selector(&page.requested_handle);
        (
            selector_position(selectors, kind, identity),
            page.requested_handle.clone(),
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
    for page in &response.canonical_memory_pages {
        if page.manifest.is_some()
            && (!page.requested_handle.starts_with("memory-segment:")
                || page
                    .segments
                    .iter()
                    .any(|segment| segment.segment_id == page.requested_handle))
        {
            let (_, identity, _) = parse_l2_selector(&page.requested_handle);
            resolved.insert((L2HandleKind::CanonicalMemory, identity.to_owned()));
        }
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
        source_segment_ordinal: None,
        source_segment_count: None,
        source_byte_start: None,
        source_byte_end_exclusive: None,
        verification_value: input.verification_value,
        known_decision_delta: input.known_decision_delta,
        prior_beneficial_use: input.prior_beneficial_use,
        contradiction_signal: input.contradiction_signal,
        harm_signal: payload_bool(input.payload, "harmful"),
        repetition_signal: payload_bool(input.payload, "repeated"),
        distraction_signal: payload_bool(input.payload, "distraction"),
    }
}

#[derive(Clone, Copy, Debug)]
struct ProjectionSegmentSource {
    source_ordinal: u64,
    source_count: u64,
    byte_start: Option<u64>,
    byte_end_exclusive: Option<u64>,
}

fn projection_rows(
    project_id: ProjectId,
    row: &RecallCandidateRow,
    updated_revision: MemoryRevision,
) -> Result<Vec<Value>, StoreError> {
    let source = ProjectionSegmentSource {
        source_ordinal: row.source_segment_ordinal.unwrap_or_default(),
        source_count: row.source_segment_count.unwrap_or(1),
        byte_start: row.source_byte_start,
        byte_end_exclusive: row.source_byte_end_exclusive,
    };
    projection_rows_for_source(project_id, row, updated_revision, source)
}

fn projection_rows_for_source(
    project_id: ProjectId,
    row: &RecallCandidateRow,
    updated_revision: MemoryRevision,
    source: ProjectionSegmentSource,
) -> Result<Vec<Value>, StoreError> {
    let mut value =
        serde_json::to_value(row).map_err(|error| StoreError::Decode(error.to_string()))?;
    let object = value.as_object_mut().ok_or_else(|| {
        StoreError::Decode("memory search projection row was not an object".to_owned())
    })?;
    object.remove("handle");
    object.remove("record_ref");
    let lifecycle = object.remove("lifecycle_state").unwrap_or(Value::Null);
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
    object.insert(
        "parent_handle_parts".to_owned(),
        json!(string_fragments(&row.handle)),
    );
    object.insert(
        "source_record_ref_parts".to_owned(),
        json!(string_fragments(&row.record_ref)),
    );
    object.insert(
        "source_segment_ordinal".to_owned(),
        json!(source.source_ordinal),
    );
    object.insert(
        "source_segment_count".to_owned(),
        json!(source.source_count),
    );
    object.insert("source_byte_start".to_owned(), json!(source.byte_start));
    object.insert(
        "source_byte_end_exclusive".to_owned(),
        json!(source.byte_end_exclusive),
    );
    object.insert("lifecycle".to_owned(), lifecycle);
    object.insert("updated_revision".to_owned(), json!(updated_revision));
    object.insert(
        "visible".to_owned(),
        Value::Bool(is_default_visible_lifecycle(row.lifecycle_state)),
    );

    let document_terms = memory_search_document_terms(row);
    let fts_segment_count = document_terms
        .len()
        .div_ceil(MAX_MEMORY_SEARCH_DOCUMENT_TERMS)
        .max(1);
    let term_chunks = if document_terms.is_empty() {
        vec![&[][..]]
    } else {
        document_terms
            .chunks(MAX_MEMORY_SEARCH_DOCUMENT_TERMS)
            .collect::<Vec<_>>()
    };
    term_chunks
        .into_iter()
        .enumerate()
        .map(|(fts_ordinal, terms)| {
            let fts_ordinal_u64 =
                u64::try_from(fts_ordinal).map_err(|_| StoreError::BlobTooLarge)?;
            let term_start = fts_ordinal.saturating_mul(MAX_MEMORY_SEARCH_DOCUMENT_TERMS);
            let term_end_exclusive = term_start.saturating_add(terms.len());
            let mut segment = value.clone();
            let segment_object = segment.as_object_mut().ok_or_else(|| {
                StoreError::Decode("memory search projection segment was not an object".to_owned())
            })?;
            segment_object.insert(
                "projection_id".to_owned(),
                Value::String(derived_row_key(&format!(
                    "{project_id}:{}:{}:{fts_ordinal_u64}",
                    row.handle, source.source_ordinal
                ))),
            );
            segment_object.insert("fts_segment_ordinal".to_owned(), json!(fts_ordinal_u64));
            segment_object.insert("fts_segment_count".to_owned(), json!(fts_segment_count));
            segment_object.insert("term_start".to_owned(), json!(term_start));
            segment_object.insert("term_end_exclusive".to_owned(), json!(term_end_exclusive));
            segment_object.insert("search_document".to_owned(), Value::String(terms.join(" ")));
            Ok(segment)
        })
        .collect()
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
        rows.extend(projection_rows(envelope.project_id, &row, memory_revision)?);
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
        rows.extend(projection_rows(envelope.project_id, &row, memory_revision)?);
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
        rows.extend(projection_rows(envelope.project_id, &row, memory_revision)?);
    }

    for observation in &envelope.tool_observations {
        let receipt_kind = observation
            .payload
            .get("receipt_kind")
            .and_then(Value::as_str);
        if matches!(
            receipt_kind,
            Some("memory_blob_segment" | "memory_blob_manifest" | "cue_binding_page")
        ) {
            continue;
        }
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
        rows.extend(projection_rows(envelope.project_id, &row, memory_revision)?);

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
        rows.extend(projection_rows(
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
        rows.extend(projection_rows(envelope.project_id, &row, memory_revision)?);
    }
    Ok(rows)
}

fn ordered_memory_search_terms<'a>(
    sources: impl IntoIterator<Item = &'a str>,
    limit: usize,
) -> Vec<String> {
    let initial_capacity = limit.min(MAX_MEMORY_SEARCH_DOCUMENT_TERMS);
    let mut terms = Vec::with_capacity(initial_capacity);
    let mut seen = HashSet::with_capacity(initial_capacity);
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
        usize::MAX,
    )
}

fn rank_memory_search_candidates(
    request: &RecallL0Request,
    mut load: MemorySearchCandidateLoad,
) -> RecallL0Response {
    let projection_revision = load.projection_revision;
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
    let mut response = rank_recall_candidates(
        request,
        RecallCandidateLoad {
            at_revision: load.at_revision,
            candidates: load.candidates,
            truncated: load.truncated,
        },
    );
    response.projection_revision = projection_revision;
    response
}

fn exact_memory_search_handle(query: &str) -> Option<String> {
    let query = query.trim();
    (!query.is_empty() && query.contains(':') && !query.chars().any(char::is_whitespace))
        .then(|| query.to_owned())
}

fn parse_canonical_memory_l2_continuation(
    memory_handle: &str,
    continuation: Option<&str>,
) -> Result<(u64, Option<String>), StoreError> {
    let Some(continuation) = continuation else {
        return Ok((0, None));
    };
    let mut parts = continuation.split(':');
    let prefix = parts.next();
    let start = parts.next().and_then(|value| value.parse::<u64>().ok());
    let fence = parts.next();
    if prefix != Some("memory-l2")
        || start.is_none()
        || fence.is_none()
        || parts.next().is_some()
        || fence.is_some_and(|value| {
            value.len() != 16 || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(StoreError::PolicyViolation(
            "canonical memory L2 continuation is malformed".to_owned(),
        ));
    }
    let _ = memory_handle;
    Ok((start.unwrap_or_default(), fence.map(str::to_owned)))
}

fn canonical_memory_l2_fence(
    memory_handle: &str,
    manifest: &CanonicalMemoryManifest,
    start: u64,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(memory_handle.as_bytes());
    hasher.update(manifest.manifest_id.as_bytes());
    hasher.update(&start.to_le_bytes());
    hasher.finalize().to_hex()[..16].to_owned()
}

fn decode_canonical_memory_body_b64<T>(encoded: &str, label: &str) -> Result<T, StoreError>
where
    T: DeserializeOwned,
{
    let bytes = STANDARD_NO_PAD.decode(encoded).map_err(|error| {
        StoreError::Decode(format!(
            "canonical memory {label} body base64 was invalid: {error}"
        ))
    })?;
    if bytes.len() > CANONICAL_MEMORY_CHILD_BODY_MAX_BYTES {
        return Err(StoreError::Decode(format!(
            "canonical memory {label} body exceeded the {CANONICAL_MEMORY_CHILD_BODY_MAX_BYTES}-byte lossless transport bound"
        )));
    }
    serde_json::from_slice(&bytes).map_err(|error| {
        StoreError::Decode(format!(
            "canonical memory {label} body JSON was invalid: {error}"
        ))
    })
}

fn canonical_memory_manifest_matches_segment(
    manifest: &CanonicalMemoryManifest,
    segment: &CanonicalMemorySegment,
) -> bool {
    manifest.memory_handle == segment.parent_handle
        && manifest.logical_kind == segment.logical_kind
        && manifest.blob == segment.blob
        && manifest.segment_count == segment.segment_count
        && manifest.segment_set_hash_blake3 == segment.segment_set_hash_blake3
}

fn unresolved_canonical_memory_l2_page(requested_handle: &str) -> CanonicalMemoryL2Page {
    CanonicalMemoryL2Page {
        requested_handle: requested_handle.to_owned(),
        resolved_parent_handle: None,
        requested_segment_id: None,
        manifest: None,
        segments: Vec::new(),
        continuation: None,
        truncated: false,
    }
}

fn validate_canonical_memory_l2_page(
    manifest: Option<&CanonicalMemoryManifest>,
    start: u64,
    segments: &[CanonicalMemorySegmentRef],
) -> Result<(), StoreError> {
    let Some(manifest) = manifest else {
        if segments.is_empty() {
            return Ok(());
        }
        return Err(StoreError::Decode(
            "canonical memory L2 returned segments without a manifest".to_owned(),
        ));
    };
    for (offset, segment) in segments.iter().enumerate() {
        let expected_ordinal =
            start.saturating_add(u64::try_from(offset).map_err(|_| StoreError::BlobTooLarge)?);
        if segment.parent_handle != manifest.memory_handle
            || segment.blob != manifest.blob
            || segment.segment_count != manifest.segment_count
            || segment.segment_set_hash_blake3 != manifest.segment_set_hash_blake3
            || segment.ordinal != expected_ordinal
            || segment.byte_end_exclusive < segment.byte_start
            || segment.byte_end_exclusive > manifest.blob.size_bytes
            || !is_lower_blake3_hex(&segment.segment_hash_blake3)
        {
            return Err(StoreError::Decode(
                "canonical memory L2 segment metadata is inconsistent".to_owned(),
            ));
        }
    }
    Ok(())
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

fn bounded_projection_detail<'a>(value: &'a str, label: &str) -> Result<&'a str, StoreError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 2_048 {
        return Err(StoreError::PolicyViolation(format!(
            "{label} must contain 1..=2048 bytes"
        )));
    }
    Ok(value)
}

fn surreal_datetime_binding(value: OffsetDateTime, label: &str) -> Result<String, StoreError> {
    value.format(&Rfc3339).map_err(|error| {
        StoreError::ConfigMessage(format!("could not encode {label} as RFC3339: {error}"))
    })
}

#[derive(Clone, Debug)]
pub struct CanonicalStore {
    config: SurrealServerConfig,
    registry: SurqlTemplateRegistry,
    client_set: Option<Arc<DbClientSet>>,
    blob_store: Option<BlobStore>,
}

pub use crate::canonical_observation_models::{CanonicalClaimCard, CanonicalToolObservation};

impl CanonicalStore {
    pub fn new(config: SurrealServerConfig) -> Self {
        Self {
            config,
            registry: SurqlTemplateRegistry::default(),
            client_set: None,
            blob_store: None,
        }
    }

    /// Checks the configured canonical target before a caller enters a
    /// persistent write path. The supervisor owns the reserved-store policy,
    /// so this boundary cannot drift from lifecycle admission.
    pub fn validate_admission(&self) -> Result<(), StoreError> {
        SurrealServerSupervisor::new(self.config.clone()).validate_admission()
    }

    #[must_use]
    pub fn from_client_set(client_set: Arc<DbClientSet>) -> Self {
        Self {
            config: client_set.config().clone(),
            registry: SurqlTemplateRegistry::default(),
            client_set: Some(client_set),
            blob_store: None,
        }
    }

    /// Attaches the process-owned content-addressed store so canonical-memory
    /// parent admission verifies both declared metadata and the actual bytes.
    #[must_use]
    pub fn with_blob_store(mut self, blob_store: BlobStore) -> Self {
        self.blob_store = Some(blob_store);
        self
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

    pub async fn apply_write_envelope(
        &self,
        envelope: &MemoryWriteEnvelope,
    ) -> Result<WriteReceipt, StoreError> {
        self.apply_write_envelope_bound(envelope, false).await
    }

    async fn apply_write_envelope_bound(
        &self,
        envelope: &MemoryWriteEnvelope,
        fail_before_projection_outbox: bool,
    ) -> Result<WriteReceipt, StoreError> {
        let canonical_payloads = canonical_payloads(envelope)?;
        let relation_payloads = relation_payloads(envelope);
        for manifest in capacity_manifests(envelope)? {
            self.verify_canonical_memory_manifest_children(envelope.project_id, &manifest)
                .await?;
        }
        let now = surreal_datetime_binding(OffsetDateTime::now_utc(), "canonical outbox time")?;
        let value = self
            .execute_value(
                NamedSurqlOp::ApplyWriteEnvelope,
                json!({
                    "envelope": envelope,
                    "canonical_payloads": canonical_payloads,
                    "relation_payloads": relation_payloads,
                    "memory_grant_ref_schema_version": eliot_types::ACTION_MEMORY_GRANT_REF_SCHEMA_VERSION,
                    "memory_grant_redemption_schema_version": eliot_types::ACTION_MEMORY_GRANT_REDEMPTION_SCHEMA_VERSION,
                    "fail_before_projection_outbox": fail_before_projection_outbox,
                    "now": now,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::ApplyWriteEnvelope, value)
    }

    async fn verify_canonical_memory_manifest_children(
        &self,
        project_id: ProjectId,
        manifest: &CanonicalMemoryManifest,
    ) -> Result<(), StoreError> {
        let segment_bodies = self
            .load_canonical_memory_admission_children(
                project_id,
                manifest,
                "segment",
                CANONICAL_MEMORY_ADMISSION_PAGE_SIZE,
            )
            .await?;
        let segments = segment_bodies
            .into_iter()
            .map(|body| {
                serde_json::from_value(body).map_err(|error| StoreError::Decode(error.to_string()))
            })
            .collect::<Result<Vec<CanonicalMemorySegment>, _>>()?
            .into_iter()
            .filter(|segment| {
                segment.segment_set_hash_blake3 == manifest.segment_set_hash_blake3
                    && segment.blob == manifest.blob
            })
            .collect::<Vec<_>>();
        let cue_page_bodies = self
            .load_canonical_memory_admission_children(
                project_id,
                manifest,
                "cue_page",
                CANONICAL_MEMORY_ADMISSION_PAGE_SIZE,
            )
            .await?;
        let cue_pages = cue_page_bodies
            .into_iter()
            .map(|body| {
                serde_json::from_value(body).map_err(|error| StoreError::Decode(error.to_string()))
            })
            .collect::<Result<Vec<CueBindingPage>, _>>()?
            .into_iter()
            .filter(|page| {
                page.page_set_hash_blake3 == manifest.cue_page_set_hash_blake3
                    && page.blob == manifest.blob
            })
            .collect::<Vec<_>>();
        verify_canonical_memory_child_set(self.blob_store.as_ref(), manifest, &segments, &cue_pages)
    }

    async fn load_canonical_memory_admission_children(
        &self,
        project_id: ProjectId,
        manifest: &CanonicalMemoryManifest,
        child_kind: &'static str,
        page_limit: u16,
    ) -> Result<Vec<Value>, StoreError> {
        let mut start = 0u64;
        let mut bodies = Vec::new();
        loop {
            let value = self
                .execute_value(
                    NamedSurqlOp::LoadCanonicalMemoryAdmissionChildren,
                    json!({
                        "project_id": project_id,
                        "memory_handle_parts": string_fragments(&manifest.memory_handle),
                        "child_kind": child_kind,
                        "start": start,
                        "limit": page_limit,
                    }),
                )
                .await?;
            let page: CanonicalMemoryAdmissionChildLoad =
                decode_value(NamedSurqlOp::LoadCanonicalMemoryAdmissionChildren, value)?;
            let page_len =
                u64::try_from(page.bodies_b64.len()).map_err(|_| StoreError::BlobTooLarge)?;
            if page.truncated && page_len == 0 {
                return Err(StoreError::Decode(
                    "canonical memory child page claimed truncation without rows".to_owned(),
                ));
            }
            for encoded in page.bodies_b64 {
                bodies.push(decode_canonical_memory_body_b64(&encoded, child_kind)?);
            }
            if !page.truncated {
                return Ok(bodies);
            }
            start = start
                .checked_add(page_len)
                .ok_or(StoreError::BlobTooLarge)?;
            if start >= CANONICAL_MEMORY_ADMISSION_MAX_SCANNED_ROWS {
                return Err(StoreError::PolicyViolation(format!(
                    "canonical memory handle {} exceeds the {}-row admission scan bound for {child_kind}",
                    manifest.memory_handle, CANONICAL_MEMORY_ADMISSION_MAX_SCANNED_ROWS
                )));
            }
        }
    }

    #[cfg(test)]
    async fn apply_write_envelope_with_outbox_failure(
        &self,
        envelope: &MemoryWriteEnvelope,
    ) -> Result<WriteReceipt, StoreError> {
        self.apply_write_envelope_bound(envelope, true).await
    }

    /// Applies the search delta retained in a committed envelope. This is a
    /// coordinator-only derived write; canonical commit success never depends
    /// on this projection succeeding.
    pub async fn apply_memory_search_projection_for_envelope(
        &self,
        envelope: &MemoryWriteEnvelope,
        receipt: &WriteReceipt,
    ) -> Result<MemoryRevision, StoreError> {
        if !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        ) || receipt.write_id != envelope.write_id
            || receipt.project_id != envelope.project_id
        {
            return Err(StoreError::PolicyViolation(
                "search projection dispatch requires the matching committed write receipt"
                    .to_owned(),
            ));
        }
        let updated_revision = receipt.memory_revision.ok_or_else(|| {
            StoreError::PolicyViolation(
                "committed write receipt omitted the search projection revision".to_owned(),
            )
        })?;
        let mut rows = envelope_projection_rows(envelope, receipt)?;
        for manifest in capacity_manifests(envelope)? {
            rows.extend(
                self.canonical_memory_projection_rows(envelope, receipt, &manifest)
                    .await?,
            );
        }
        self.dispatch_memory_search_projection(
            envelope.project_id,
            envelope.write_id,
            updated_revision,
            &rows,
            None,
            true,
        )
        .await?;
        Ok(updated_revision)
    }

    #[allow(clippy::too_many_lines)]
    async fn canonical_memory_projection_rows(
        &self,
        envelope: &MemoryWriteEnvelope,
        receipt: &WriteReceipt,
        manifest: &CanonicalMemoryManifest,
    ) -> Result<Vec<Value>, StoreError> {
        let memory_revision = receipt.memory_revision.ok_or_else(|| {
            StoreError::PolicyViolation(
                "committed capacity manifest omitted its memory revision".to_owned(),
            )
        })?;
        let project_sequence = receipt.project_sequence.ok_or_else(|| {
            StoreError::PolicyViolation(
                "committed capacity manifest omitted its project sequence".to_owned(),
            )
        })?;
        let lifecycle = normalized_memory_lifecycle(envelope.lifecycle.status);
        let mut start = 0u64;
        let mut expected_ordinal = 0u64;
        let mut rows = Vec::new();
        loop {
            let value = self
                .execute_value(
                    NamedSurqlOp::LoadCanonicalMemoryProjectionSegments,
                    json!({
                        "project_id": envelope.project_id,
                        "memory_handle_parts": string_fragments(&manifest.memory_handle),
                        "blob_digest_parts": string_fragments(&manifest.blob.digest_hex),
                        "blob_relative_path_parts": string_fragments(&manifest.blob.relative_path),
                        "blob_size_bytes": manifest.blob.size_bytes,
                        "logical_kind_parts": string_fragments(&manifest.logical_kind),
                        "segment_count": manifest.segment_count,
                        "segment_set_hash_parts": string_fragments(
                            &manifest.segment_set_hash_blake3
                        ),
                        "start": start,
                        "limit": CANONICAL_MEMORY_L2_PAGE_SIZE,
                    }),
                )
                .await?;
            let page: Vec<CanonicalMemoryProjectionRecord> =
                decode_value(NamedSurqlOp::LoadCanonicalMemoryProjectionSegments, value)?;
            if page.is_empty() {
                break;
            }
            for record in page {
                let segment = record.receipt_body;
                if segment.parent_handle != manifest.memory_handle
                    || segment.blob != manifest.blob
                    || segment.logical_kind != manifest.logical_kind
                    || segment.segment_count != manifest.segment_count
                    || segment.segment_set_hash_blake3 != manifest.segment_set_hash_blake3
                    || segment.ordinal != expected_ordinal
                {
                    return Err(StoreError::Decode(
                        "canonical capacity projection segment sequence is inconsistent".to_owned(),
                    ));
                }
                let payload = serde_json::to_value(&segment)
                    .map_err(|error| StoreError::Decode(error.to_string()))?;
                let row = recall_candidate(RecallCandidateInput {
                    record_ref: format!("canonical_record:{}", record.record_id),
                    handle: segment.parent_handle.clone(),
                    record_type: "memory_blob_segment".to_owned(),
                    preview: segment.preview_text.clone(),
                    search_text: segment.search_text.clone(),
                    cue_text: String::new(),
                    scope_text: envelope.scope.clone(),
                    concept_text: String::new(),
                    task_id: envelope.task_id,
                    status: "observed".to_owned(),
                    lifecycle_state: lifecycle,
                    authority_rank: 35,
                    negative_memory: false,
                    memory_revision,
                    project_sequence,
                    verification_value: 20,
                    known_decision_delta: 0,
                    prior_beneficial_use: 0,
                    contradiction_signal: false,
                    payload: &payload,
                });
                rows.extend(projection_rows_for_source(
                    envelope.project_id,
                    &row,
                    memory_revision,
                    ProjectionSegmentSource {
                        source_ordinal: segment.ordinal,
                        source_count: segment.segment_count,
                        byte_start: Some(segment.byte_start),
                        byte_end_exclusive: Some(segment.byte_end_exclusive),
                    },
                )?);
                expected_ordinal = expected_ordinal.saturating_add(1);
            }
            start = expected_ordinal;
            if start >= manifest.segment_count {
                break;
            }
        }
        if expected_ordinal != manifest.segment_count {
            return Err(StoreError::Decode(format!(
                "canonical capacity projection loaded {expected_ordinal} of {} admitted segments",
                manifest.segment_count
            )));
        }
        Ok(rows)
    }

    async fn dispatch_memory_search_projection(
        &self,
        project_id: ProjectId,
        write_id: WriteId,
        updated_revision: MemoryRevision,
        rows: &[Value],
        projection_format: Option<&str>,
        advance_state_at_end: bool,
    ) -> Result<(), StoreError> {
        if rows.is_empty() {
            self.execute_value(
                NamedSurqlOp::UpsertMemorySearchProjection,
                memory_search_projection_dispatch_vars(
                    project_id,
                    write_id,
                    updated_revision,
                    &[],
                    advance_state_at_end,
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
                    advance_state_at_end && index + 1 == chunk_count,
                    projection_format,
                ),
            )
            .await?;
        }
        Ok(())
    }

    /// Persists a minimal non-canonical projection intent. Exact changed paths
    /// remain an in-memory optimization; restart recovery is project-scoped.
    pub async fn enqueue_cognitive_projection_intent(
        &self,
        project_id: ProjectId,
        event_id: &str,
        updated_revision: MemoryRevision,
        families: &[CognitiveProjectionFamily],
    ) -> Result<CognitiveProjectionIntentReceipt, StoreError> {
        let event_id = event_id.trim();
        if event_id.is_empty() || event_id.len() > 512 {
            return Err(StoreError::PolicyViolation(
                "cognitive projection event_id must contain 1..=512 bytes".to_owned(),
            ));
        }
        let families = families.iter().copied().collect::<BTreeSet<_>>();
        if families.is_empty() {
            return Err(StoreError::PolicyViolation(
                "cognitive projection intent requires at least one family".to_owned(),
            ));
        }
        if families.contains(&CognitiveProjectionFamily::Utility) {
            return Err(StoreError::PolicyViolation(
                "utility projection intents remain unavailable until the utility projection is materialized"
                    .to_owned(),
            ));
        }
        let family_names = families
            .into_iter()
            .map(CognitiveProjectionFamily::as_str)
            .collect::<Vec<_>>();
        let mark_dependency_dirty_stale = event_id.starts_with("dependency-dirty:")
            && family_names.contains(&CognitiveProjectionFamily::DependencyDirty.as_str());
        let now = surreal_datetime_binding(OffsetDateTime::now_utc(), "projection intent time")?;
        let value = self
            .execute_value(
                NamedSurqlOp::EnqueueCognitiveProjectionIntent,
                json!({
                    "intent_id": derived_row_key(&format!("{project_id}:{event_id}")),
                    "event_id_parts": string_fragments(event_id),
                    "project_id": project_id,
                    "updated_revision": updated_revision,
                    "families": family_names,
                    "mark_dependency_dirty_stale": mark_dependency_dirty_stale,
                    "dependency_state_id": derived_row_key(&format!(
                        "{project_id}:{}",
                        CognitiveProjectionFamily::DependencyDirty.as_str()
                    )),
                    "now": now,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::EnqueueCognitiveProjectionIntent, value)
    }

    /// Claims the one strict per-project head row. An older blocked,
    /// not-yet-due retry or active lease is a barrier; an expired head lease is
    /// eligible for deterministic reclaim. The input limit is retained for API
    /// compatibility while contiguous-prefix batching remains unimplemented.
    pub async fn claim_cognitive_projection_project(
        &self,
        lease_owner: &str,
        lease_seconds: u64,
        batch_limit: u16,
    ) -> Result<Option<CognitiveProjectionLease>, StoreError> {
        let lease_owner = lease_owner.trim();
        if lease_owner.is_empty() || lease_owner.len() > 256 {
            return Err(StoreError::PolicyViolation(
                "cognitive projection lease_owner must contain 1..=256 bytes".to_owned(),
            ));
        }
        let now = OffsetDateTime::now_utc();
        let lease_seconds = lease_seconds.clamp(1, MAX_COGNITIVE_PROJECTION_LEASE_SECONDS);
        let lease_seconds = i64::try_from(lease_seconds).map_err(|error| {
            StoreError::ConfigMessage(format!("invalid projection lease duration: {error}"))
        })?;
        let lease_expires_at = now + TimeDuration::seconds(lease_seconds);
        let now_binding = surreal_datetime_binding(now, "projection claim time")?;
        let lease_expires_at_binding =
            surreal_datetime_binding(lease_expires_at, "projection lease expiry")?;
        let lease_id = WriteId::new_v7().to_string();
        let value = self
            .execute_value(
                NamedSurqlOp::ClaimCognitiveProjectionProject,
                json!({
                    "lease_id": lease_id,
                    "lease_owner": lease_owner,
                    "lease_expires_at": lease_expires_at_binding,
                    "batch_limit": batch_limit.clamp(1, MAX_COGNITIVE_PROJECTION_LEASE_ROWS),
                    "now": now_binding,
                }),
            )
            .await?;
        let load: CognitiveProjectionClaimLoad =
            decode_value(NamedSurqlOp::ClaimCognitiveProjectionProject, value)?;
        let Some(first) = load.rows.first() else {
            return Ok(None);
        };
        if load
            .rows
            .iter()
            .any(|row| row.project_id != first.project_id)
        {
            return Err(StoreError::PolicyViolation(
                "cognitive projection claim crossed project boundaries".to_owned(),
            ));
        }
        let project_id = first.project_id;
        let through_revision = load
            .rows
            .iter()
            .map(|row| row.updated_revision)
            .max()
            .ok_or_else(|| StoreError::Decode("projection claim omitted revision".to_owned()))?;
        let families = load
            .rows
            .iter()
            .flat_map(|row| row.families.iter().copied())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let write_ids = load
            .rows
            .iter()
            .map(|row| row.write_id.clone())
            .collect::<Vec<_>>();
        let max_attempt_count = load
            .rows
            .iter()
            .map(|row| row.attempt_count)
            .max()
            .unwrap_or(0);
        Ok(Some(CognitiveProjectionLease {
            lease_id,
            lease_owner: lease_owner.to_owned(),
            project_id,
            through_revision,
            claimed_rows: write_ids.len(),
            write_ids,
            families,
            max_attempt_count,
            lease_expires_at,
        }))
    }

    pub async fn complete_cognitive_projection_through(
        &self,
        lease: &CognitiveProjectionLease,
    ) -> Result<usize, StoreError> {
        self.mutate_cognitive_projection_lease(
            NamedSurqlOp::CompleteCognitiveProjectionThrough,
            lease,
            json!({}),
        )
        .await
    }

    pub async fn fail_cognitive_projection_retryable(
        &self,
        lease: &CognitiveProjectionLease,
        error: &str,
        retry_after_seconds: u64,
    ) -> Result<usize, StoreError> {
        let error = bounded_projection_detail(error, "retryable projection error")?;
        let now = OffsetDateTime::now_utc();
        let retry_after_seconds =
            i64::try_from(retry_after_seconds.clamp(1, 86_400)).map_err(|conversion_error| {
                StoreError::ConfigMessage(format!(
                    "invalid projection retry duration: {conversion_error}"
                ))
            })?;
        let next_attempt_at = surreal_datetime_binding(
            now + TimeDuration::seconds(retry_after_seconds),
            "projection retry time",
        )?;
        self.mutate_cognitive_projection_lease(
            NamedSurqlOp::FailCognitiveProjectionRetryable,
            lease,
            json!({
                "error": error,
                "next_attempt_at": next_attempt_at,
            }),
        )
        .await
    }

    pub async fn block_cognitive_projection(
        &self,
        lease: &CognitiveProjectionLease,
        reason: &str,
    ) -> Result<usize, StoreError> {
        let reason = bounded_projection_detail(reason, "projection block reason")?;
        self.mutate_cognitive_projection_lease(
            NamedSurqlOp::BlockCognitiveProjection,
            lease,
            json!({ "reason": reason }),
        )
        .await
    }

    async fn mutate_cognitive_projection_lease(
        &self,
        op: NamedSurqlOp,
        lease: &CognitiveProjectionLease,
        extra: Value,
    ) -> Result<usize, StoreError> {
        if lease.write_ids.is_empty() || lease.claimed_rows != lease.write_ids.len() {
            return Err(StoreError::PolicyViolation(
                "cognitive projection lease has an inconsistent claimed row set".to_owned(),
            ));
        }
        let now = surreal_datetime_binding(OffsetDateTime::now_utc(), "projection mutation time")?;
        let mut vars = json!({
            "project_id": lease.project_id,
            "lease_id": lease.lease_id,
            "lease_owner": lease.lease_owner,
            "through_revision": lease.through_revision,
            "write_id_parts": lease
                .write_ids
                .iter()
                .map(|write_id| string_fragments(write_id))
                .collect::<Vec<_>>(),
            "families": lease
                .families
                .iter()
                .copied()
                .map(CognitiveProjectionFamily::as_str)
                .collect::<Vec<_>>(),
            "dependency_state_id": derived_row_key(&format!(
                "{}:{}",
                lease.project_id,
                CognitiveProjectionFamily::DependencyDirty.as_str()
            )),
            "now": now,
        });
        let vars_object = vars.as_object_mut().ok_or_else(|| {
            StoreError::Decode("projection lease bindings were not an object".to_owned())
        })?;
        let extra_object = extra.as_object().ok_or_else(|| {
            StoreError::Decode("projection lease extra bindings were not an object".to_owned())
        })?;
        vars_object.extend(extra_object.clone());
        let value = self.execute_value(op, vars).await?;
        let result: CognitiveProjectionMutationResult = decode_value(op, value)?;
        if result.rows_updated != lease.claimed_rows {
            return Err(StoreError::PolicyViolation(format!(
                "cognitive projection lease mutated {} of {} claimed rows",
                result.rows_updated, lease.claimed_rows
            )));
        }
        Ok(result.rows_updated)
    }

    pub async fn cognitive_projection_backlog(
        &self,
    ) -> Result<CognitiveProjectionBacklog, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadCognitiveProjectionBacklog,
                Value::Object(serde_json::Map::new()),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadCognitiveProjectionBacklog, value)
    }

    pub async fn load_cognitive_projection_projects(
        &self,
        start: usize,
        limit: usize,
    ) -> Result<CognitiveProjectionProjectPage, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadCognitiveProjectionProjects,
                json!({
                    "start": start,
                    "limit": limit.clamp(1, COGNITIVE_PROJECTION_PROJECT_PAGE_SIZE),
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadCognitiveProjectionProjects, value)
    }

    /// Persists independent family publication truth. For search this mirrors
    /// `memory_search_state` for observability and is never a second read fence.
    pub async fn publish_cognitive_projection_family_state(
        &self,
        project_id: ProjectId,
        family: CognitiveProjectionFamily,
        target_revision: MemoryRevision,
        applied_revision: Option<MemoryRevision>,
        status: CognitiveProjectionPublicationStatus,
        last_error: Option<&str>,
    ) -> Result<CognitiveProjectionFamilyState, StoreError> {
        if status == CognitiveProjectionPublicationStatus::Published
            && applied_revision != Some(target_revision)
        {
            return Err(StoreError::PolicyViolation(
                "published cognitive projection state requires applied_revision == target_revision"
                    .to_owned(),
            ));
        }
        let last_error = last_error
            .map(|detail| bounded_projection_detail(detail, "projection state error"))
            .transpose()?;
        let now = surreal_datetime_binding(OffsetDateTime::now_utc(), "projection state time")?;
        let value = self
            .execute_value(
                NamedSurqlOp::PublishCognitiveProjectionFamilyState,
                json!({
                    "state_id": derived_row_key(&format!("{project_id}:{}", family.as_str())),
                    "project_id": project_id,
                    "family": family.as_str(),
                    "target_revision": target_revision,
                    "applied_revision": applied_revision,
                    "status": status.as_str(),
                    "last_error": last_error,
                    "now": now,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::PublishCognitiveProjectionFamilyState, value)
    }

    pub async fn cognitive_projection_family_states(
        &self,
        project_id: ProjectId,
    ) -> Result<Vec<CognitiveProjectionFamilyState>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadCognitiveProjectionFamilyStates,
                json!({ "project_id": project_id }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadCognitiveProjectionFamilyStates, value)
    }

    /// Explicit offline Admin cutover. It pages every project first and refuses
    /// to remove postings unless each authoritative search projection is `fts_v1`
    /// at the current head; the Admin template repeats the gate transactionally.
    pub async fn cutover_legacy_memory_search_postings(&self) -> Result<Value, StoreError> {
        let mut start = 0usize;
        loop {
            let page = self
                .load_cognitive_projection_projects(start, COGNITIVE_PROJECTION_PROJECT_PAGE_SIZE)
                .await?;
            for project in &page.projects {
                if project.search_projection_format.as_deref()
                    != Some(MEMORY_SEARCH_FTS_PROJECTION_FORMAT)
                    || project.search_applied_revision != Some(project.head_revision)
                {
                    return Err(StoreError::PolicyViolation(format!(
                        "memory search cutover refused stale project {}",
                        project.project_id
                    )));
                }
            }
            let Some(next_start) = page.next_start else {
                break;
            };
            if !page.truncated || next_start <= start {
                return Err(StoreError::PolicyViolation(
                    "cognitive projection project inventory did not advance".to_owned(),
                ));
            }
            start = next_start;
        }
        self.execute_value(
            NamedSurqlOp::CutoverLegacyMemorySearchPostings,
            Value::Object(serde_json::Map::new()),
        )
        .await
    }

    pub async fn apply_observability(
        &self,
        envelope: &ObservabilityWriteEnvelope,
    ) -> Result<ObservabilityWriteReceipt, StoreError> {
        if envelope.kind == ObservabilityKind::MemoryGrantOffer {
            let offer: MemoryGrantOfferRecord = serde_json::from_value(envelope.payload.clone())
                .map_err(|error| StoreError::Decode(error.to_string()))?;
            if offer.schema_version != eliot_types::MEMORY_DELIVERY_GRANT_SCHEMA_VERSION
                || offer.grant_id != envelope.record_id
                || offer.offer_write_id != envelope.write_id
                || offer.project_id != envelope.project_id
                || Some(offer.task_id) != envelope.task_id
                || Some(offer.session_id) != envelope.session_id
                || offer.offered_at != envelope.created_at
            {
                return Err(StoreError::PolicyViolation(
                    "memory grant offer identity does not match its observability envelope"
                        .to_owned(),
                ));
            }
        }
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

    pub async fn memory_grant_offer_by_id(
        &self,
        project_id: ProjectId,
        task_id: TaskId,
        session_id: SessionId,
        grant_id: &str,
    ) -> Result<Option<MemoryGrantOfferRecord>, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::MemoryGrantOfferById,
                json!({
                    "project_id": project_id,
                    "task_id": task_id,
                    "session_id": session_id,
                    "grant_id": grant_id,
                }),
            )
            .await?;
        if value.is_null() {
            return Ok(None);
        }
        decode_value(NamedSurqlOp::MemoryGrantOfferById, value).map(Some)
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
        let mut load: MemorySearchCandidateLoad =
            decode_value(NamedSurqlOp::LoadMemorySearchFtsCandidates, value)?;
        let projection_state = match load.projection_status {
            Some(CognitiveProjectionPublicationStatus::Blocked) => {
                CognitiveProjectionReadState::Blocked
            }
            Some(CognitiveProjectionPublicationStatus::Unavailable) => {
                CognitiveProjectionReadState::Unavailable
            }
            Some(CognitiveProjectionPublicationStatus::Stale) => {
                CognitiveProjectionReadState::Stale
            }
            None => CognitiveProjectionReadState::Unavailable,
            _ if load.projection_format.as_deref() != Some(MEMORY_SEARCH_FTS_PROJECTION_FORMAT) => {
                CognitiveProjectionReadState::Unavailable
            }
            _ if load.projection_revision != Some(load.at_revision)
                || load.family_target_revision != Some(load.at_revision)
                || load.family_applied_revision != Some(load.at_revision) =>
            {
                CognitiveProjectionReadState::Stale
            }
            Some(CognitiveProjectionPublicationStatus::Published) => {
                CognitiveProjectionReadState::Published
            }
        };
        if !projection_state.is_published() {
            load.ordered_handles.clear();
            load.candidates.clear();
            load.truncated = false;
        }
        let mut response = rank_memory_search_candidates(request, load);
        response.projection_state = projection_state;
        Ok(response)
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

    async fn load_recall_projection_page(
        &self,
        project_id: ProjectId,
        kind: &str,
        start: usize,
        limit: usize,
        lifecycle_audit: bool,
    ) -> Result<RecallCandidateLoad, StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::LoadRecallCandidates,
                json!({
                    "project_id": project_id,
                    "kind": kind,
                    "start": start,
                    "limit": limit,
                    "lifecycle_audit": lifecycle_audit,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadRecallCandidates, value)
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
                    let mut page = self
                        .load_recall_projection_page(
                            project_id,
                            kind,
                            start,
                            RECALL_CANDIDATE_PAGE_SIZE,
                            lifecycle_audit,
                        )
                        .await?;
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
            let head = self
                .load_recall_projection_page(project_id, "head", 0, 1, lifecycle_audit)
                .await?;
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
        for _attempt in 0..RECALL_REVISION_RESTART_ATTEMPTS {
            let head = self
                .load_recall_projection_page(project_id, "head", 0, 1, true)
                .await?;
            let target_revision = head.at_revision;
            self.execute_value(
                NamedSurqlOp::ResetMemorySearchProjection,
                json!({ "project_id": project_id }),
            )
            .await?;
            let rebuild_write_id = WriteId::new_v7();
            let mut revision_drift = false;
            'kinds: for kind in RECALL_CANDIDATE_KINDS {
                let mut start = 0usize;
                loop {
                    let page = self
                        .load_recall_projection_page(
                            project_id,
                            kind,
                            start,
                            RECALL_CANDIDATE_PAGE_SIZE,
                            true,
                        )
                        .await?;
                    if page.at_revision != target_revision {
                        revision_drift = true;
                        break 'kinds;
                    }
                    let page_len = page.candidates.len();
                    let rows = page
                        .candidates
                        .iter()
                        .map(|row| projection_rows(project_id, row, target_revision))
                        .collect::<Result<Vec<_>, _>>()?
                        .into_iter()
                        .flatten()
                        .collect::<Vec<_>>();
                    self.dispatch_memory_search_projection(
                        project_id,
                        rebuild_write_id,
                        target_revision,
                        &rows,
                        None,
                        false,
                    )
                    .await?;
                    if !page.truncated {
                        break;
                    }
                    if page_len == 0 {
                        return Err(StoreError::PolicyViolation(
                            "memory search rebuild returned an empty truncated page".to_owned(),
                        ));
                    }
                    start = start.saturating_add(page_len);
                }
            }
            if revision_drift {
                continue;
            }
            let final_head = self
                .load_recall_projection_page(project_id, "head", 0, 1, true)
                .await?;
            if final_head.at_revision != target_revision {
                continue;
            }
            self.dispatch_memory_search_projection(
                project_id,
                rebuild_write_id,
                target_revision,
                &[],
                Some(MEMORY_SEARCH_FTS_PROJECTION_FORMAT),
                true,
            )
            .await?;
            self.publish_cognitive_projection_family_state(
                project_id,
                CognitiveProjectionFamily::Search,
                target_revision,
                Some(target_revision),
                CognitiveProjectionPublicationStatus::Published,
                None,
            )
            .await?;
            return Ok(target_revision);
        }
        Err(StoreError::PolicyViolation(
            "memory search rebuild could not obtain a stable project revision after 3 attempts"
                .to_owned(),
        ))
    }

    pub async fn memory_search_query_plan(
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

    async fn load_canonical_memory_l2_identity(
        &self,
        project_id: ProjectId,
        requested_handle: &str,
        requested_segment_record_id: Option<&str>,
        start: u64,
    ) -> Result<CanonicalMemoryL2Load, StoreError> {
        let requested_is_segment = requested_segment_record_id.is_some();
        let value = self
            .execute_value(
                NamedSurqlOp::LoadCanonicalMemoryL2,
                json!({
                    "project_id": project_id,
                    "memory_handle_parts": string_fragments(requested_handle),
                    "requested_segment_record_id_parts": requested_segment_record_id
                        .map_or_else(Vec::new, string_fragments),
                    "requested_is_segment": requested_is_segment,
                    "start": start,
                    "limit": CANONICAL_MEMORY_L2_MANIFEST_PAGE_SIZE,
                }),
            )
            .await?;
        decode_value(NamedSurqlOp::LoadCanonicalMemoryL2, value)
    }

    async fn load_exact_canonical_memory_segment(
        &self,
        project_id: ProjectId,
        segment_id: &str,
    ) -> Result<Option<CanonicalMemorySegment>, StoreError> {
        let record_id = format!(
            "capacity:{}",
            derived_row_key(&format!("{project_id}:{segment_id}"))
        );
        let load = self
            .load_canonical_memory_l2_identity(project_id, segment_id, Some(&record_id), 0)
            .await?;
        if load.truncated || !load.manifest_bodies_b64.is_empty() {
            return Err(StoreError::Decode(
                "canonical memory exact-segment lookup returned manifest pagination state"
                    .to_owned(),
            ));
        }
        let Some(encoded) = load.requested_segment_body_b64 else {
            return Ok(None);
        };
        let segment: CanonicalMemorySegment =
            decode_canonical_memory_body_b64(&encoded, "segment")?;
        if segment.segment_id != segment_id {
            return Err(StoreError::Decode(
                "canonical memory exact-segment lookup resolved a different segment".to_owned(),
            ));
        }
        Ok(Some(segment))
    }

    async fn load_canonical_memory_manifest(
        &self,
        project_id: ProjectId,
        parent_handle: &str,
        matching_segment: Option<&CanonicalMemorySegment>,
    ) -> Result<Option<CanonicalMemoryManifest>, StoreError> {
        let mut start = 0u64;
        loop {
            let load = self
                .load_canonical_memory_l2_identity(project_id, parent_handle, None, start)
                .await?;
            if load.requested_segment_body_b64.is_some() {
                return Err(StoreError::Decode(
                    "canonical memory manifest lookup returned segment state".to_owned(),
                ));
            }
            let page_len = u64::try_from(load.manifest_bodies_b64.len())
                .map_err(|_| StoreError::BlobTooLarge)?;
            if load.truncated && page_len == 0 {
                return Err(StoreError::Decode(
                    "canonical memory manifest page claimed truncation without rows".to_owned(),
                ));
            }
            for encoded in load.manifest_bodies_b64 {
                let manifest: CanonicalMemoryManifest =
                    decode_canonical_memory_body_b64(&encoded, "manifest")?;
                if manifest.memory_handle != parent_handle {
                    return Err(StoreError::Decode(
                        "canonical memory manifest lookup resolved a different parent".to_owned(),
                    ));
                }
                if matching_segment.is_none_or(|segment| {
                    canonical_memory_manifest_matches_segment(&manifest, segment)
                }) {
                    return Ok(Some(manifest));
                }
            }
            if !load.truncated {
                return Ok(None);
            }
            start = start
                .checked_add(page_len)
                .ok_or(StoreError::BlobTooLarge)?;
            if start >= CANONICAL_MEMORY_L2_MAX_SCANNED_ROWS {
                return Err(StoreError::PolicyViolation(format!(
                    "canonical memory handle {parent_handle} exceeds the {CANONICAL_MEMORY_L2_MAX_SCANNED_ROWS}-row manifest scan bound"
                )));
            }
        }
    }

    async fn load_canonical_memory_segment_set(
        &self,
        project_id: ProjectId,
        manifest: &CanonicalMemoryManifest,
    ) -> Result<Vec<CanonicalMemorySegmentRef>, StoreError> {
        let segment_bodies = self
            .load_canonical_memory_admission_children(
                project_id,
                manifest,
                "segment",
                CANONICAL_MEMORY_ADMISSION_PAGE_SIZE,
            )
            .await?;
        let mut segments = segment_bodies
            .into_iter()
            .map(|body| {
                serde_json::from_value::<CanonicalMemorySegment>(body)
                    .map_err(|error| StoreError::Decode(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .filter(|segment| canonical_memory_manifest_matches_segment(manifest, segment))
            .map(|segment| CanonicalMemorySegmentRef::from(&segment))
            .collect::<Vec<_>>();
        segments.sort_by_key(|segment| segment.ordinal);
        if u64::try_from(segments.len()).map_err(|_| StoreError::BlobTooLarge)?
            != manifest.segment_count
        {
            return Err(StoreError::Decode(
                "canonical memory L2 could not resolve the manifest's complete segment set"
                    .to_owned(),
            ));
        }
        validate_canonical_memory_l2_page(Some(manifest), 0, &segments)?;
        Ok(segments)
    }

    /// Metadata-only exact-L2 expansion for a large canonical memory handle.
    /// Raw blob bytes never cross this response; callers page deterministic
    /// range/hash references and expand them locally through `BlobStore`.
    pub async fn canonical_memory_l2(
        &self,
        project_id: ProjectId,
        memory_handle: &str,
        continuation: Option<&str>,
    ) -> Result<CanonicalMemoryL2Page, StoreError> {
        let memory_handle = memory_handle.trim();
        if memory_handle.is_empty() || memory_handle.len() > MAX_EXACT_L2_HANDLE_BYTES {
            return Err(StoreError::PolicyViolation(
                "canonical memory L2 handle must contain 1..=512 bytes".to_owned(),
            ));
        }
        let segment_request = memory_handle.starts_with("memory-segment:");
        if segment_request && continuation.is_some() {
            return Err(StoreError::PolicyViolation(
                "canonical memory segment L2 requests do not accept continuation tokens".to_owned(),
            ));
        }
        let (start, continuation_fence) =
            parse_canonical_memory_l2_continuation(memory_handle, continuation)?;
        let requested_segment = if segment_request {
            self.load_exact_canonical_memory_segment(project_id, memory_handle)
                .await?
        } else {
            None
        };
        if segment_request && requested_segment.is_none() {
            return Ok(unresolved_canonical_memory_l2_page(memory_handle));
        }
        let resolved_parent_handle = requested_segment
            .as_ref()
            .map_or(memory_handle, |segment| segment.parent_handle.as_str());
        let manifest = self
            .load_canonical_memory_manifest(
                project_id,
                resolved_parent_handle,
                requested_segment.as_ref(),
            )
            .await?;
        let Some(manifest) = manifest else {
            if continuation.is_some() {
                return Err(StoreError::PolicyViolation(
                    "canonical memory L2 continuation lost its manifest".to_owned(),
                ));
            }
            return Ok(unresolved_canonical_memory_l2_page(memory_handle));
        };
        if let Some(expected) = continuation_fence.as_deref()
            && expected != canonical_memory_l2_fence(memory_handle, &manifest, start)
        {
            return Err(StoreError::PolicyViolation(
                "canonical memory L2 continuation is stale".to_owned(),
            ));
        }

        if let Some(segment) = requested_segment {
            let segment = CanonicalMemorySegmentRef::from(&segment);
            validate_canonical_memory_l2_page(
                Some(&manifest),
                segment.ordinal,
                std::slice::from_ref(&segment),
            )?;
            return Ok(CanonicalMemoryL2Page {
                requested_handle: memory_handle.to_owned(),
                resolved_parent_handle: Some(manifest.memory_handle.clone()),
                requested_segment_id: Some(segment.segment_id.clone()),
                manifest: Some(manifest),
                segments: vec![segment],
                continuation: None,
                truncated: false,
            });
        }

        let all_segments = self
            .load_canonical_memory_segment_set(project_id, &manifest)
            .await?;
        let start_index = usize::try_from(start).map_err(|_| StoreError::BlobTooLarge)?;
        let segments = all_segments
            .into_iter()
            .skip(start_index)
            .take(usize::from(CANONICAL_MEMORY_L2_PAGE_SIZE))
            .collect::<Vec<_>>();
        validate_canonical_memory_l2_page(Some(&manifest), start, &segments)?;
        let next_start = start
            .saturating_add(u64::try_from(segments.len()).map_err(|_| StoreError::BlobTooLarge)?);
        let truncated = next_start < manifest.segment_count;
        let next = if truncated {
            Some(format!(
                "memory-l2:{next_start}:{}",
                canonical_memory_l2_fence(memory_handle, &manifest, next_start)
            ))
        } else {
            None
        };
        Ok(CanonicalMemoryL2Page {
            requested_handle: memory_handle.to_owned(),
            resolved_parent_handle: Some(manifest.memory_handle.clone()),
            requested_segment_id: None,
            manifest: Some(manifest),
            segments,
            continuation: next,
            truncated,
        })
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
        let mut response: FetchAtomsL2Response = decode_value(op, value)?;
        if !selectors.is_empty() {
            for selector in selectors
                .iter()
                .filter(|selector| selector.kind == L2HandleKind::CanonicalMemory)
            {
                let page = self
                    .canonical_memory_l2(request.project_id, &selector.public_handle, None)
                    .await?;
                if page.manifest.is_some() {
                    response.canonical_memory_pages.push(page);
                }
            }
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

    /// Cold project rebuild boundary. The coordinator must publish the
    /// `dependency_dirty` family as stale before invoking this reset.
    pub async fn reset_ul_reverse_dependency_project(
        &self,
        project_id: ProjectId,
    ) -> Result<(), StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::ResetUlReverseDependencyProject,
                json!({ "project_id": project_id }),
            )
            .await?;
        if value.get("reset").and_then(Value::as_bool) != Some(true) {
            return Err(StoreError::Decode(
                "reverse dependency project reset omitted confirmation".to_owned(),
            ));
        }
        Ok(())
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

    /// Cold project scan boundary for the derived dirty projection. This does
    /// not alter canonical artifacts or dependency records.
    pub async fn reset_ul_artifact_dirty_project(
        &self,
        project_id: ProjectId,
    ) -> Result<(), StoreError> {
        let value = self
            .execute_value(
                NamedSurqlOp::ResetUlArtifactDirtyProject,
                json!({ "project_id": project_id }),
            )
            .await?;
        if value.get("reset").and_then(Value::as_bool) != Some(true) {
            return Err(StoreError::Decode(
                "artifact dirty project reset omitted confirmation".to_owned(),
            ));
        }
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
            let receipt_kind = observation
                .payload
                .get("receipt_kind")
                .and_then(Value::as_str);
            validate_capacity_receipt(receipt_kind, body)?;
            let body_bytes =
                serde_json::to_vec(body).map_err(|error| StoreError::Decode(error.to_string()))?;
            if matches!(
                receipt_kind,
                Some(
                    "memory_blob_segment" | "cue_binding_page" | "memory_blob_manifest"
                )
            ) && body_bytes.len() > CANONICAL_MEMORY_CHILD_BODY_MAX_BYTES
            {
                return Err(StoreError::PolicyViolation(format!(
                    "canonical memory child body is {} bytes; admission transport allows {CANONICAL_MEMORY_CHILD_BODY_MAX_BYTES}",
                    body_bytes.len()
                )));
            }
            let subject_ref =
                canonical_subject_ref(receipt_kind, body).unwrap_or(&observation.observation_id);
            let canonical_record_id = capacity_record_id(receipt_kind, body).map_or_else(
                || observation.observation_id.clone(),
                |capacity_id| {
                    format!(
                        "capacity:{}",
                        derived_row_key(&format!("{}:{capacity_id}", envelope.project_id))
                    )
                },
            );
            Ok(json!({
                "observation_id": observation.observation_id,
                "canonical_record_id_fragments": string_fragments(&canonical_record_id),
                "canonical_record_ref_fragments": string_fragments(
                    &format!("canonical_record:{canonical_record_id}")
                ),
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

fn capacity_record_id<'a>(receipt_kind: Option<&str>, body: &'a Value) -> Option<&'a str> {
    match receipt_kind {
        Some("memory_blob_segment") => body.get("segment_id").and_then(Value::as_str),
        Some("cue_binding_page") => body.get("page_id").and_then(Value::as_str),
        Some("memory_blob_manifest") => body.get("manifest_id").and_then(Value::as_str),
        _ => None,
    }
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
        Some("memory_blob_segment" | "cue_binding_page") => Some("parent_handle"),
        Some("memory_blob_manifest") => Some("memory_handle"),
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
mod canonical_capacity_unit_tests {
    use super::{
        CANONICAL_MEMORY_ADMISSION_PAGE_SIZE, CANONICAL_MEMORY_CHILD_BODY_MAX_BYTES,
        CANONICAL_MEMORY_L2_MANIFEST_PAGE_SIZE, canonical_memory_manifest_matches_segment,
    };
    use eliot_types::{BlobRef, CanonicalMemoryManifest, CanonicalMemorySegment};

    #[test]
    fn admission_transport_budget_covers_body_and_lookahead() {
        const BASE64_BODY_BYTES: usize = (CANONICAL_MEMORY_CHILD_BODY_MAX_BYTES * 4).div_ceil(3);
        const RESPONSE_OVERHEAD_BUDGET: usize = 16 * 1024;

        assert_eq!(BASE64_BODY_BYTES, 174_763);
        assert!(
            (usize::from(CANONICAL_MEMORY_ADMISSION_PAGE_SIZE) + 1) * BASE64_BODY_BYTES
                + RESPONSE_OVERHEAD_BUDGET
                <= 512 * 1024
        );
    }

    #[test]
    fn normal_l2_transport_budget_covers_manifest_and_lookahead() {
        const BASE64_BODY_BYTES: usize = (CANONICAL_MEMORY_CHILD_BODY_MAX_BYTES * 4).div_ceil(3);
        const RESPONSE_OVERHEAD_BUDGET: usize = 16 * 1024;

        assert_eq!(CANONICAL_MEMORY_L2_MANIFEST_PAGE_SIZE, 1);
        assert!(
            (usize::from(CANONICAL_MEMORY_L2_MANIFEST_PAGE_SIZE) + 1) * BASE64_BODY_BYTES
                + RESPONSE_OVERHEAD_BUDGET
                <= 512 * 1024
        );
    }

    #[test]
    fn normal_l2_generation_match_binds_set_hash_and_blob_ref() {
        let blob = BlobRef {
            algorithm: "blake3".to_owned(),
            digest_hex: "1".repeat(64),
            size_bytes: 64,
            relative_path: "blake3/11/blob".to_owned(),
        };
        let manifest = CanonicalMemoryManifest {
            schema_version: eliot_types::CANONICAL_MEMORY_SCHEMA_VERSION.to_owned(),
            manifest_id: "manifest:generation-a".to_owned(),
            memory_handle: "memory:parent".to_owned(),
            logical_kind: "source".to_owned(),
            media_type: "text/plain".to_owned(),
            blob: blob.clone(),
            segment_count: 1,
            segment_target_bytes: 24 * 1024,
            segment_set_hash_blake3: "2".repeat(64),
            cue_page_count: 0,
            cue_page_set_hash_blake3: "3".repeat(64),
        };
        let segment = CanonicalMemorySegment {
            schema_version: eliot_types::CANONICAL_MEMORY_SCHEMA_VERSION.to_owned(),
            segment_id: "memory-segment:generation-a:0".to_owned(),
            parent_handle: manifest.memory_handle.clone(),
            logical_kind: manifest.logical_kind.clone(),
            blob,
            ordinal: 0,
            segment_count: 1,
            segment_set_hash_blake3: manifest.segment_set_hash_blake3.clone(),
            byte_start: 0,
            byte_end_exclusive: 64,
            segment_hash_blake3: "4".repeat(64),
            search_text: String::new(),
            preview_text: String::new(),
        };

        assert!(canonical_memory_manifest_matches_segment(
            &manifest, &segment
        ));
        let mut other_set = manifest.clone();
        other_set.segment_set_hash_blake3 = "5".repeat(64);
        assert!(!canonical_memory_manifest_matches_segment(
            &other_set, &segment
        ));
        let mut other_blob = manifest;
        other_blob.blob.digest_hex = "6".repeat(64);
        assert!(!canonical_memory_manifest_matches_segment(
            &other_blob,
            &segment
        ));
    }
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
            source_segment_ordinal: None,
            source_segment_count: None,
            source_byte_start: None,
            source_byte_end_exclusive: None,
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
    fn exact_l2_capacity_selectors_preserve_parent_and_segment_handles() {
        let selectors = normalize_l2_selectors(&[
            "memory:capacity-parent".to_owned(),
            format!("memory-segment:{}", "a".repeat(64)),
        ])
        .unwrap_or_else(|error| panic!("capacity selectors: {error}"));

        assert_eq!(selectors.len(), 2);
        assert!(
            selectors
                .iter()
                .all(|selector| selector.kind == L2HandleKind::CanonicalMemory)
        );
        assert_eq!(selectors[0].public_handle, "memory:capacity-parent");
        assert_eq!(
            selectors[1].public_handle,
            format!("memory-segment:{}", "a".repeat(64))
        );
        assert!(l2_relation_identities(&selectors).is_empty());
    }

    #[test]
    fn exact_l2_file_selector_expands_its_relation_identity_only() -> Result<(), StoreError> {
        let selectors = normalize_l2_selectors(&[
            "file:src/a.rs".to_owned(),
            "memory:unrelated-parent".to_owned(),
        ])?;

        let relation_ids = l2_relation_identities(&selectors);

        assert_eq!(
            relation_ids,
            vec!["file:src/a.rs".to_owned(), "src/a.rs".to_owned()]
        );
        Ok(())
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
        let projections = projection_rows(ProjectId::new_v7(), &row, MemoryRevision::new(7))?;
        assert_eq!(projections.len(), 1);
        let projection = &projections[0];
        let expected_document = expected.join(" ");
        assert_eq!(
            projection.get("search_document").and_then(Value::as_str),
            Some(expected_document.as_str())
        );
        assert!(projection.get("postings").is_none());
        Ok(())
    }

    #[test]
    fn fts_capacity_segments_without_losing_lower_priority_tail() -> Result<(), StoreError> {
        let mut row = candidate_row();
        row.search_text = (0..MAX_MEMORY_SEARCH_DOCUMENT_TERMS)
            .map(|index| format!("search{index:04}"))
            .collect::<Vec<_>>()
            .join(" ");
        row.scope_text = "scope_tail".to_owned();

        let terms = memory_search_document_terms(&row);

        assert_eq!(terms.len(), MAX_MEMORY_SEARCH_DOCUMENT_TERMS + 10);
        assert_eq!(
            &terms[..8],
            [
                "claim", "opaque", "id", "card", "path", "symbol", "concept", "preview",
            ]
        );
        assert_eq!(terms[8], "search0000");
        assert!(terms.iter().any(|term| term == "scope"));
        assert!(terms.iter().any(|term| term == "tail"));

        let projections = projection_rows(ProjectId::new_v7(), &row, MemoryRevision::new(7))?;
        assert_eq!(projections.len(), 2);
        let persisted_terms = projections
            .iter()
            .flat_map(|projection| {
                projection["search_document"]
                    .as_str()
                    .unwrap_or_default()
                    .split_whitespace()
            })
            .collect::<Vec<_>>();
        assert_eq!(persisted_terms, terms);
        assert!(projections.iter().all(|projection| {
            projection["search_document"]
                .as_str()
                .unwrap_or_default()
                .split_whitespace()
                .count()
                <= MAX_MEMORY_SEARCH_DOCUMENT_TERMS
        }));
        Ok(())
    }

    #[test]
    fn fts_capacity_projects_every_bounded_segment_with_exact_ranges() -> Result<(), StoreError> {
        let mut row = candidate_row();
        row.handle = "memory:projection-capacity".to_owned();
        row.record_ref = "canonical_record:segment-2".to_owned();
        row.search_text = (0..5_000)
            .map(|index| format!("unique{index:04}"))
            .collect::<Vec<_>>()
            .join(" ");
        let all_terms = memory_search_document_terms(&row);
        let projections = projection_rows_for_source(
            ProjectId::new_v7(),
            &row,
            MemoryRevision::new(9),
            ProjectionSegmentSource {
                source_ordinal: 2,
                source_count: 4,
                byte_start: Some(49_152),
                byte_end_exclusive: Some(73_728),
            },
        )?;

        assert_eq!(projections.len(), all_terms.len().div_ceil(2_048));
        assert!(projections.len() >= 3);
        let mut projected_terms = Vec::new();
        for (ordinal, projection) in projections.iter().enumerate() {
            assert_eq!(projection["source_segment_ordinal"], 2);
            assert_eq!(projection["source_segment_count"], 4);
            assert_eq!(projection["source_byte_start"], 49_152);
            assert_eq!(projection["source_byte_end_exclusive"], 73_728);
            assert_eq!(projection["fts_segment_ordinal"], ordinal);
            assert_eq!(projection["term_start"], ordinal * 2_048);
            let terms = projection["search_document"]
                .as_str()
                .unwrap_or_default()
                .split_whitespace()
                .collect::<Vec<_>>();
            assert!(terms.len() <= MAX_MEMORY_SEARCH_DOCUMENT_TERMS);
            projected_terms.extend(terms);
        }
        assert_eq!(projected_terms, all_terms);
        assert_eq!(
            projections
                .iter()
                .filter_map(|projection| projection["projection_id"].as_str())
                .collect::<HashSet<_>>()
                .len(),
            projections.len()
        );
        Ok(())
    }

    #[test]
    fn fallback_capacity_scores_tail_segment_before_parent_dedup() {
        let project_id = ProjectId::new_v7();
        let request = RecallL0Request {
            project_id,
            query: "tailneedle".to_owned(),
            consistency: eliot_types::ReadConsistencyMode::Latest,
            at_least_revision: None,
            lifecycle_audit: false,
            task_id: None,
            task_class_cues: Vec::new(),
            scope_refs: Vec::new(),
            concept_refs: Vec::new(),
        };
        let mut head = candidate_row();
        head.handle = "memory:fallback-tail".to_owned();
        head.record_ref = "canonical_record:head-segment".to_owned();
        head.record_type = "memory_blob_segment".to_owned();
        head.preview = "head segment".to_owned();
        head.search_text = "unrelated beginning".to_owned();
        head.cue_text.clear();
        head.concept_text.clear();
        head.source_segment_ordinal = Some(0);
        head.source_segment_count = Some(2);
        head.memory_revision = Some(MemoryRevision::new(12));

        let mut tail = head.clone();
        tail.record_ref = "canonical_record:tail-segment".to_owned();
        tail.preview = "tail segment".to_owned();
        tail.search_text = "tailneedle decisive evidence".to_owned();
        tail.source_segment_ordinal = Some(1);
        tail.memory_revision = Some(MemoryRevision::new(11));

        let response = rank_recall_candidates(
            &request,
            RecallCandidateLoad {
                at_revision: MemoryRevision::new(13),
                candidates: vec![head, tail],
                truncated: false,
            },
        );
        assert_eq!(response.handles.len(), 1);
        assert_eq!(response.handles[0].handle, "memory:fallback-tail");
        assert_eq!(response.handles[0].preview, "tail segment");
        assert!(response.rank_trace.feature_scores[0].lexical_overlap > 0);
        assert!(
            response
                .rank_trace
                .collapsed_duplicates
                .iter()
                .any(|trace| {
                    trace.reason == "parent_segment_dedup_after_scoring"
                        && trace.collapsed_record_refs == ["canonical_record:head-segment"]
                })
        );
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
    fn cold_rebuild_capacity_streams_every_page_without_semantic_cap() {
        let source = include_str!("canonical_store.rs");
        let Some(start) = source.find("pub async fn rebuild_memory_search_projection") else {
            panic!("rebuild source anchor");
        };
        let tail = &source[start..];
        let Some(end) = tail.find("pub async fn memory_search_query_plan") else {
            panic!("rebuild end anchor");
        };
        let rebuild = &tail[..end];
        assert!(rebuild.contains("for kind in RECALL_CANDIDATE_KINDS"));
        assert!(rebuild.contains("RECALL_CANDIDATE_PAGE_SIZE"));
        assert!(rebuild.contains("start = start.saturating_add(page_len)"));
        assert!(rebuild.contains("target_revision"));
        assert!(!rebuild.contains("250_000"));
        assert!(!rebuild.contains("MAX_REBUILD_CANDIDATES"));
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
    fn public_recall_is_phase_wired() {
        let _ = CanonicalStore::recall_l0;
    }
}
