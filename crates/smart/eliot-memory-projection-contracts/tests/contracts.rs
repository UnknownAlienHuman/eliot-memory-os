use eliot_contracts::{
    ArtifactId, AuthorityEpoch, OperationId, RequestId, ResourceGeneration, StateFence,
};
use eliot_evidence::{Assertability, EpistemicStatus, LifecycleState};
use eliot_memory_projection_contracts::{
    CanonicalMemoryReadRequest, CanonicalMemoryReadSnapshot, MemoryAccessibility, MemoryCandidate,
    MemoryCandidateRepresentation, MemoryCandidateSet, MemoryCoverageDenominator,
    MemoryProjectionError, MemoryProjectionRecord, MemoryReadCoverage, MemoryRecordKind,
    MemorySelectionAssessment, MemorySelectionDimension, PermittedInfluence,
    SelectionDimensionResult, memory_candidate_set_digest, memory_read_snapshot_digest,
    validate_memory_candidate_set, validate_memory_read_snapshot,
};

fn fence(generation: u64) -> StateFence {
    StateFence::new(
        AuthorityEpoch::genesis(),
        ResourceGeneration::new(generation).expect("generation"),
    )
}

fn request(maximum_records: u32) -> CanonicalMemoryReadRequest {
    CanonicalMemoryReadRequest {
        request_id: RequestId::new("memory-read-1").expect("id"),
        read_operation_id: OperationId::new("memory-op-1").expect("id"),
        scope_id: "scope-1".to_owned(),
        task_id: None,
        canonical_revision: 1,
        state_fence: fence(1),
        requested_kinds: vec![],
        maximum_records,
    }
}

fn record(id: &str) -> MemoryProjectionRecord {
    MemoryProjectionRecord {
        record_handle: ArtifactId::new(id).expect("id"),
        payload_handle: Some(ArtifactId::new(format!("payload-{id}")).expect("id")),
        kind: MemoryRecordKind::SemanticClaim,
        scope: "scope-1".to_owned(),
        source_revision: "canonical-1".to_owned(),
        epistemic_status: EpistemicStatus::Supported,
        lifecycle: LifecycleState::Active,
        accessibility: MemoryAccessibility::Payload,
        permitted_influence: PermittedInfluence::Candidate,
        assertability: Assertability::Assertable,
        provenance_handles: vec![ArtifactId::new(format!("source-{id}")).expect("id")],
        state_fence: fence(1),
        bounded_preview: Some(format!("preview {id}")),
        negative_memory: false,
        minority_or_counterevidence: false,
    }
}

fn snapshot(records: Vec<MemoryProjectionRecord>) -> CanonicalMemoryReadSnapshot {
    let mut value = CanonicalMemoryReadSnapshot {
        request: request(records.len() as u32 + 1),
        read_receipt_handle: Some(ArtifactId::new("read-receipt-1").expect("id")),
        coverage: MemoryReadCoverage::Complete,
        denominator: Some(MemoryCoverageDenominator {
            source_ref: "governor.memory-read-v1".to_owned(),
            revision: "canonical-1".to_owned(),
            expected_records: Some(records.len() as u32),
            partitions: vec!["scope-1".to_owned()],
        }),
        records,
        missing_owner_refs: vec![],
        snapshot_sha256: String::new(),
    };
    value.snapshot_sha256 = memory_read_snapshot_digest(&value).expect("digest");
    value
}

#[test]
fn empty_complete_is_distinct_from_unavailable() {
    let complete = snapshot(vec![]);
    validate_memory_read_snapshot(&complete).expect("complete empty read");

    let mut unavailable = CanonicalMemoryReadSnapshot {
        request: request(1),
        read_receipt_handle: None,
        coverage: MemoryReadCoverage::Unavailable,
        denominator: None,
        records: vec![],
        missing_owner_refs: vec!["canonical-store".to_owned()],
        snapshot_sha256: String::new(),
    };
    unavailable.snapshot_sha256 = memory_read_snapshot_digest(&unavailable).expect("digest");
    validate_memory_read_snapshot(&unavailable).expect("explicit unavailable read");
    assert_ne!(complete.coverage, unavailable.coverage);
}

#[test]
fn inaccessible_record_cannot_directly_influence_selection() {
    let mut item = record("record-1");
    item.accessibility = MemoryAccessibility::Suppressed;
    item.permitted_influence = PermittedInfluence::Candidate;
    let value = snapshot(vec![item]);
    assert_eq!(
        validate_memory_read_snapshot(&value),
        Err(MemoryProjectionError::DimensionCollapsed(
            "inaccessible record cannot directly influence selection"
        ))
    );
}

#[test]
fn snapshot_digest_is_order_independent() {
    let left = snapshot(vec![record("b"), record("a")]);
    let right = snapshot(vec![record("a"), record("b")]);
    assert_eq!(left.snapshot_sha256, right.snapshot_sha256);
    validate_memory_read_snapshot(&left).expect("left");
    validate_memory_read_snapshot(&right).expect("right");
}

#[test]
fn candidate_trace_must_reconcile() {
    let candidate = MemoryCandidate {
        record_handle: ArtifactId::new("candidate-a").expect("id"),
        representation: MemoryCandidateRepresentation::ExactHandle {
            handle: ArtifactId::new("payload-a").expect("id"),
        },
        kind: MemoryRecordKind::SemanticClaim,
        epistemic_status: EpistemicStatus::Supported,
        accessibility: MemoryAccessibility::HandleOnly,
        permitted_influence: PermittedInfluence::Candidate,
        assessments: vec![MemorySelectionAssessment {
            dimension: MemorySelectionDimension::DecisionRelevance,
            result: SelectionDimensionResult::Unknown,
        }],
        source_handles: vec![ArtifactId::new("source-a").expect("id")],
    };
    let mut set = MemoryCandidateSet {
        snapshot_sha256: "a".repeat(64),
        state_fence: fence(1),
        candidates: vec![candidate],
        considered_handles: vec![ArtifactId::new("candidate-a").expect("id")],
        selected_handles: vec![],
        set_sha256: String::new(),
    };
    set.set_sha256 = memory_candidate_set_digest(&set).expect("digest");
    assert_eq!(
        validate_memory_candidate_set(&set),
        Err(MemoryProjectionError::TraceInvalid(
            "selected, considered, and candidate handles do not reconcile"
        ))
    );
}
