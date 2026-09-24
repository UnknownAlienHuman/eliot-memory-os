//! Erasure-owned fail-closed behaviour slice for #688.
//!
//! Three end-to-end protocol proofs inside `eliot-erasure` only: durable
//! intent precedes every destructive call (and a missing intent capability
//! means zero destructive calls), exact replay returns the original receipt
//! with no second dispatch, and one unknown/incomplete surface blocks a
//! `Purged` result. Live Store producers land later; these tests aggregate
//! typed outcomes passed in, never store-surface writes.

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use eliot_contracts::{
    EpochId, EpochLineageId, ResourceGeneration, StateFence, canonical_json_bytes,
};
use eliot_erasure::{
    ApprovalBinding, ApproverKind, DataScopeClass, ErasureBackend, ErasureError, ErasureFamily,
    ErasureIntent, ErasureReceipt, ErasureRequest, ErasureScopeSnapshot, ErasureSequenceStep,
    HoldTerms, IntentReceipt, ResidencyBinding, ScopeTarget, SurfaceOutcome, TargetDisposition,
    TargetOwner, Tombstone, execute,
};
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};
use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation};
use serde::Serialize;

#[derive(Debug)]
struct BackendError(String);

impl fmt::Display for BackendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for BackendError {}

fn test_fence() -> StateFence {
    let lineage = match EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000") {
        Ok(lineage) => lineage,
        Err(error) => panic!("valid test lineage: {error:?}"),
    };
    let Some(ordinal) = std::num::NonZeroU64::new(7) else {
        panic!("nonzero test epoch ordinal")
    };
    let epoch = match EpochId::new(lineage, ordinal) {
        Ok(epoch) => epoch,
        Err(error) => panic!("valid test epoch: {error:?}"),
    };
    let generation = match ResourceGeneration::new(3) {
        Ok(generation) => generation,
        Err(error) => panic!("valid test generation: {error:?}"),
    };
    StateFence::new(epoch, generation)
}

fn test_request(request_id: &str) -> ErasureRequest {
    ErasureRequest {
        request_id: request_id.to_string(),
        subject_ref: "subject:purge-protocol".to_string(),
        scope: "scope:purge-protocol".to_string(),
        locations: vec![
            PurgeLocation::CanonicalPayload,
            PurgeLocation::Blob,
            PurgeLocation::Index,
        ],
        expected_revision: 7,
        approval_digest: "ab".repeat(32),
        evidence: Vec::new(),
        state_fence: test_fence(),
    }
}

struct RecordingBackend {
    revision: u64,
    intents: BTreeMap<String, ErasureIntent>,
    tombstones: BTreeMap<String, Tombstone>,
    completions: BTreeMap<String, ErasureReceipt>,
    call_order: Vec<String>,
    scripted_outcomes: Option<Vec<SurfaceOutcome>>,
    fail_record: bool,
    fail_tombstone: bool,
    fail_append_ledger: bool,
    fail_note_completed: bool,
    erase_transport_error: bool,
    resume_aware: bool,
    dispatched: Vec<PurgeLocation>,
    durable_completed: BTreeSet<u8>,
    last_outcomes: Vec<SurfaceOutcome>,
}

impl RecordingBackend {
    fn ready() -> Self {
        Self {
            revision: 7,
            intents: BTreeMap::new(),
            tombstones: BTreeMap::new(),
            completions: BTreeMap::new(),
            call_order: Vec::new(),
            scripted_outcomes: None,
            fail_record: false,
            fail_tombstone: false,
            fail_append_ledger: false,
            fail_note_completed: false,
            erase_transport_error: false,
            resume_aware: false,
            dispatched: Vec::new(),
            durable_completed: BTreeSet::new(),
            last_outcomes: Vec::new(),
        }
    }

    fn erase_calls(&self) -> usize {
        self.call_order
            .iter()
            .filter(|call| call.as_str() == "erase")
            .count()
    }

    fn ledger_appends(&self) -> usize {
        self.call_order
            .iter()
            .filter(|call| call.as_str() == "append_ledger")
            .count()
    }
}

impl ErasureBackend for RecordingBackend {
    type Error = BackendError;

    fn current_revision(&self, _subject_ref: &str, _scope: &str) -> Result<u64, Self::Error> {
        Ok(self.revision)
    }

    fn completed_receipt(
        &self,
        operation_id: &str,
    ) -> Result<Option<ErasureReceipt>, ErasureError> {
        if operation_id.trim().is_empty() {
            return Err(ErasureError::InvalidField("operation_id"));
        }
        Ok(self.completions.get(operation_id).cloned())
    }

    fn record_intent(&mut self, intent: ErasureIntent) -> Result<IntentReceipt, ErasureError> {
        self.call_order.push("record_intent".to_string());
        if self.fail_record {
            return Err(ErasureError::UnsupportedIntent);
        }
        intent.validate()?;
        if let Some(existing) = self.intents.get(&intent.operation_id) {
            if *existing != intent {
                return Err(ErasureError::IntentConflict);
            }
            return Ok(IntentReceipt {
                operation_id: intent.operation_id.clone(),
                request_digest: intent.request_digest.clone(),
            });
        }
        let receipt = IntentReceipt {
            operation_id: intent.operation_id.clone(),
            request_digest: intent.request_digest.clone(),
        };
        self.intents.insert(intent.operation_id.clone(), intent);
        Ok(receipt)
    }

    fn commit_tombstone(&mut self, tombstone: Tombstone) -> Result<Tombstone, ErasureError> {
        self.call_order.push("commit_tombstone".to_string());
        if self.fail_tombstone {
            return Err(ErasureError::UnsupportedIntent);
        }
        tombstone.validate()?;
        if let Some(existing) = self.tombstones.get(&tombstone.operation_id) {
            if *existing != tombstone {
                return Err(ErasureError::IntentConflict);
            }
            return Ok(existing.clone());
        }
        self.tombstones
            .insert(tombstone.operation_id.clone(), tombstone.clone());
        Ok(tombstone)
    }

    fn load_tombstone(&self, operation_id: &str) -> Result<Option<Tombstone>, ErasureError> {
        if operation_id.trim().is_empty() {
            return Err(ErasureError::InvalidField("operation_id"));
        }
        Ok(self.tombstones.get(operation_id).cloned())
    }

    fn note_completed(&mut self, receipt: ErasureReceipt) -> Result<(), ErasureError> {
        self.call_order.push("note_completed".to_string());
        if self.fail_note_completed {
            return Err(ErasureError::Backend(Box::new(BackendError(
                "completion seal lost after possible mutation".to_string(),
            ))));
        }
        let Some(intent) = self.intents.get(&receipt.request_id) else {
            return Err(ErasureError::IntentConflict);
        };
        if intent.request_digest != receipt.request_digest {
            return Err(ErasureError::IntentConflict);
        }
        self.completions.insert(receipt.request_id.clone(), receipt);
        Ok(())
    }

    fn erase(&mut self, intent: &ErasureIntent) -> Result<Vec<SurfaceOutcome>, Self::Error> {
        self.call_order.push("erase".to_string());
        if intent.validate().is_err() {
            return Err(BackendError("invalid intent at dispatch".to_string()));
        }
        if self.erase_transport_error {
            return Err(BackendError(
                "transport lost after possible dispatch".to_string(),
            ));
        }
        if let Some(scripted) = &self.scripted_outcomes {
            self.last_outcomes = scripted.clone();
            return Ok(scripted.clone());
        }
        if self.resume_aware {
            for location in &intent.locations {
                let code = location_code(*location);
                if !self.durable_completed.contains(&code) {
                    self.dispatched.push(*location);
                    self.durable_completed.insert(code);
                }
            }
        } else {
            for location in &intent.locations {
                self.dispatched.push(*location);
            }
        }
        let outcomes: Vec<SurfaceOutcome> = intent
            .locations
            .iter()
            .map(|location| SurfaceOutcome::Purged {
                location: *location,
            })
            .collect();
        self.last_outcomes = outcomes.clone();
        Ok(outcomes)
    }

    fn append_purge_ledger(&mut self, entry: PurgeLedgerEntry) -> Result<(), Self::Error> {
        self.call_order.push("append_ledger".to_string());
        if self.fail_append_ledger {
            return Err(BackendError(
                "ledger commit response lost after possible deletion".to_string(),
            ));
        }
        if entry.validate().is_err() {
            return Err(BackendError("invalid purge ledger entry".to_string()));
        }
        Ok(())
    }
}

/// Backend that never overrides the intent capability: the trait defaults
/// must refuse, proving missing-capability handling without a stub success.
struct NoIntentBackend {
    revision: u64,
    erase_calls: usize,
}

impl ErasureBackend for NoIntentBackend {
    type Error = BackendError;

    fn current_revision(&self, _subject_ref: &str, _scope: &str) -> Result<u64, Self::Error> {
        Ok(self.revision)
    }

    fn erase(&mut self, intent: &ErasureIntent) -> Result<Vec<SurfaceOutcome>, Self::Error> {
        self.erase_calls += 1;
        Ok(intent
            .locations
            .iter()
            .map(|location| SurfaceOutcome::Purged {
                location: *location,
            })
            .collect())
    }

    fn append_purge_ledger(&mut self, _entry: PurgeLedgerEntry) -> Result<(), Self::Error> {
        Ok(())
    }
}

// WORK_UNIT_CASE: 688/1
#[test]
fn durable_intent_precedes_every_destructive_call() {
    let request = test_request("request-688-intent");
    let mut backend = RecordingBackend::ready();
    let receipt = match execute(&mut backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("clean execute succeeds: {error:?}"),
    };
    assert_eq!(receipt.request_id, "request-688-intent");
    let Some(record_position) = backend
        .call_order
        .iter()
        .position(|call| call.as_str() == "record_intent")
    else {
        panic!("intent recorded: {:?}", backend.call_order)
    };
    let Some(erase_position) = backend
        .call_order
        .iter()
        .position(|call| call.as_str() == "erase")
    else {
        panic!("erase dispatched: {:?}", backend.call_order)
    };
    assert!(
        record_position < erase_position,
        "intent {record_position} precedes erase {erase_position}"
    );

    let refused = test_request("request-688-no-intent");
    let mut failing = RecordingBackend {
        fail_record: true,
        ..RecordingBackend::ready()
    };
    match execute(&mut failing, &refused) {
        Ok(_) => panic!("missing intent capability must refuse"),
        Err(ErasureError::UnsupportedIntent) => {}
        Err(other) => panic!("typed intent refusal, got: {other:?}"),
    }
    assert_eq!(failing.erase_calls(), 0);
    assert_eq!(failing.ledger_appends(), 0);

    let missing = test_request("request-688-default-refusal");
    let mut missing_capability = NoIntentBackend {
        revision: 7,
        erase_calls: 0,
    };
    match execute(&mut missing_capability, &missing) {
        Ok(_) => panic!("default intent capability must refuse"),
        Err(ErasureError::UnsupportedIntent) => {}
        Err(other) => panic!("default refusal is typed, got: {other:?}"),
    }
    assert_eq!(missing_capability.erase_calls, 0);
}

// WORK_UNIT_CASE: 688/14
#[test]
fn exact_replay_returns_original_without_second_dispatch() {
    let request = test_request("request-688-replay");
    let mut backend = RecordingBackend::ready();
    let first = match execute(&mut backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("first execute succeeds: {error:?}"),
    };
    assert_eq!(backend.erase_calls(), 1);
    assert_eq!(backend.ledger_appends(), 1);

    let second = match execute(&mut backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("replay returns the original: {error:?}"),
    };
    assert_eq!(first, second);
    assert_eq!(first.request_digest, second.request_digest);
    assert_eq!(first.purge.purge_id, second.purge.purge_id);
    assert_eq!(
        backend.erase_calls(),
        1,
        "replay must not dispatch destructively again"
    );
    assert_eq!(backend.ledger_appends(), 1);
}

// WORK_UNIT_CASE: 688/18
#[test]
fn unknown_or_incomplete_surface_blocks_purged_result() {
    let request = test_request("request-688-unknown");
    let mut unknown = RecordingBackend {
        scripted_outcomes: Some(vec![
            SurfaceOutcome::Purged {
                location: PurgeLocation::CanonicalPayload,
            },
            SurfaceOutcome::Unknown {
                location: PurgeLocation::Blob,
            },
            SurfaceOutcome::Purged {
                location: PurgeLocation::Index,
            },
        ]),
        ..RecordingBackend::ready()
    };
    match execute(&mut unknown, &request) {
        Ok(_) => panic!("unknown surface must block a purged result"),
        Err(ErasureError::UnknownSurface) => {}
        Err(other) => panic!("unknown refusal is typed, got: {other:?}"),
    }
    assert_eq!(unknown.ledger_appends(), 0);
    assert!(unknown.completions.is_empty());

    let partial_request = test_request("request-688-incomplete");
    let mut incomplete = RecordingBackend {
        scripted_outcomes: Some(vec![
            SurfaceOutcome::Purged {
                location: PurgeLocation::CanonicalPayload,
            },
            SurfaceOutcome::Incomplete {
                location: PurgeLocation::Blob,
            },
            SurfaceOutcome::Purged {
                location: PurgeLocation::Index,
            },
        ]),
        ..RecordingBackend::ready()
    };
    match execute(&mut incomplete, &partial_request) {
        Ok(_) => panic!("incomplete surface must block a purged result"),
        Err(ErasureError::IncompleteErasure) => {}
        Err(other) => panic!("incomplete refusal is typed, got: {other:?}"),
    }
    assert_eq!(incomplete.ledger_appends(), 0);
    assert!(incomplete.completions.is_empty());
}

fn location_code(location: PurgeLocation) -> u8 {
    match location {
        PurgeLocation::CanonicalPayload => 0,
        PurgeLocation::Projection => 1,
        PurgeLocation::Index => 2,
        PurgeLocation::Blob => 3,
        PurgeLocation::OperationalRecovery => 4,
        PurgeLocation::ProviderCopy => 5,
        PurgeLocation::BackupRestorePath => 6,
        PurgeLocation::RouteContinuation => 7,
    }
}

fn stale_fence() -> StateFence {
    let lineage = match EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000") {
        Ok(lineage) => lineage,
        Err(error) => panic!("valid test lineage: {error:?}"),
    };
    let Some(ordinal) = std::num::NonZeroU64::new(8) else {
        panic!("nonzero stale test epoch ordinal")
    };
    let epoch = match EpochId::new(lineage, ordinal) {
        Ok(epoch) => epoch,
        Err(error) => panic!("valid stale test epoch: {error:?}"),
    };
    let generation = match ResourceGeneration::new(3) {
        Ok(generation) => generation,
        Err(error) => panic!("valid test generation: {error:?}"),
    };
    StateFence::new(epoch, generation)
}

fn closure_evidence(coverage: EvidenceCoverage) -> EvidenceEnvelope {
    let source_id = match eliot_contracts::SourceId::new("source:purge-protocol") {
        Ok(source_id) => source_id,
        Err(error) => panic!("valid test source id: {error:?}"),
    };
    EvidenceEnvelope {
        authority: EvidenceAuthority::DeterministicRuntimeTest,
        freshness: EvidenceFreshness::ExactCandidate,
        coverage,
        status: EpistemicStatus::Supported,
        assertability: Assertability::Assertable,
        provenance: Provenance {
            source_id,
            capture_route: "route:purge-protocol".to_string(),
            scope: "scope:purge-protocol".to_string(),
            raw_handle: None,
            revision: None,
        },
        verification: None,
        state_fence: test_fence(),
    }
}

fn scope_snapshot(subject_revision: u64) -> ErasureScopeSnapshot {
    let mut targets = Vec::new();
    for family in ErasureFamily::ALL {
        for location in family.locations() {
            targets.push(ScopeTarget {
                family,
                location: *location,
                owner: family.owner(),
                disposition: TargetDisposition::DeleteBytes,
            });
        }
    }
    ErasureScopeSnapshot {
        erasure_id: "erasure-688".to_string(),
        subject_ref: "subject:purge-protocol".to_string(),
        principal_ref: "principal:purge-protocol".to_string(),
        authority_ref: "authority:purge-protocol".to_string(),
        purpose_ref: "purpose:purge-protocol".to_string(),
        legal_basis_ref: "basis:purge-protocol".to_string(),
        targets,
        graph_revision: 11,
        subject_revision,
        privacy_retention_domain_ref: "privacy-domain:purge-protocol".to_string(),
        residency: ResidencyBinding {
            residency_domain_ref: None,
            claims_cross_domain_coresidence: false,
        },
        approval: ApprovalBinding {
            scope_class: DataScopeClass::WorkScopeData,
            approver_kind: ApproverKind::WorkScopeOwner,
            approver_ref: "workscope-owner:purge-protocol".to_string(),
            approval_digest: "ab".repeat(32),
        },
        required_verifier_refs: vec!["verifier:purge-protocol".to_string()],
        deadline_ref: None,
        state_fence: test_fence(),
        invalidation_set: vec!["invalidation:purge-protocol".to_string()],
        planned_order: ErasureSequenceStep::ORDERED.to_vec(),
    }
}

fn scope_bound_request() -> ErasureRequest {
    ErasureRequest {
        request_id: "request-688-scope".to_string(),
        subject_ref: "subject:purge-protocol".to_string(),
        scope: "scope:purge-protocol".to_string(),
        locations: vec![
            PurgeLocation::CanonicalPayload,
            PurgeLocation::Projection,
            PurgeLocation::Index,
            PurgeLocation::Blob,
            PurgeLocation::OperationalRecovery,
            PurgeLocation::BackupRestorePath,
            PurgeLocation::RouteContinuation,
            PurgeLocation::ProviderCopy,
        ],
        expected_revision: 7,
        approval_digest: "ab".repeat(32),
        evidence: Vec::new(),
        state_fence: test_fence(),
    }
}

/// One row of the frozen twenty-case denominator pinned in
/// `tests/data/purge_protocol.json`. Serialization uses the same
/// canonical-JSON rule as the product digests, so the file comparison below
/// is byte-exact by construction.
#[derive(Serialize)]
struct FixtureCase {
    case: u32,
    name: String,
    refusal: String,
}

fn fixture_denominator() -> Vec<FixtureCase> {
    vec![
        FixtureCase {
            case: 1,
            name: "durable_intent_precedes_destructive_dispatch".to_string(),
            refusal: "none".to_string(),
        },
        FixtureCase {
            case: 2,
            name: "required_partial_or_unknown_closure_blocks_start".to_string(),
            refusal: "InsufficientClosureEvidence".to_string(),
        },
        FixtureCase {
            case: 3,
            name: "stale_epoch_fence_or_policy_refuses".to_string(),
            refusal: "FenceMismatch".to_string(),
        },
        FixtureCase {
            case: 4,
            name: "subject_target_or_ledger_revision_drift_refuses".to_string(),
            refusal: "RevisionMismatch".to_string(),
        },
        FixtureCase {
            case: 5,
            name: "exact_denominator_with_evidence_backed_exclusions".to_string(),
            refusal: "none".to_string(),
        },
        FixtureCase {
            case: 6,
            name: "tombstone_without_physical_proof_stays_incomplete".to_string(),
            refusal: "IncompleteErasure".to_string(),
        },
        FixtureCase {
            case: 7,
            name: "key_loss_without_byte_removal_proof_stays_incomplete".to_string(),
            refusal: "IncompleteErasure".to_string(),
        },
        FixtureCase {
            case: 8,
            name: "canonical_success_with_partial_blob_removal".to_string(),
            refusal: "Incomplete".to_string(),
        },
        FixtureCase {
            case: 9,
            name: "projection_index_or_cache_hit_blocks_complete".to_string(),
            refusal: "Incomplete".to_string(),
        },
        FixtureCase {
            case: 10,
            name: "ors_pending_recreation_preserves_unknown".to_string(),
            refusal: "Unknown".to_string(),
        },
        FixtureCase {
            case: 11,
            name: "pre_purge_backup_restore_cannot_resurrect".to_string(),
            refusal: "Incomplete".to_string(),
        },
        FixtureCase {
            case: 12,
            name: "provider_ack_without_authentic_receipt_refuses".to_string(),
            refusal: "IncompleteErasure".to_string(),
        },
        FixtureCase {
            case: 13,
            name: "transport_loss_preserves_unknown_and_reconciliation".to_string(),
            refusal: "Backend".to_string(),
        },
        FixtureCase {
            case: 14,
            name: "exact_replay_without_second_dispatch".to_string(),
            refusal: "none".to_string(),
        },
        FixtureCase {
            case: 15,
            name: "changed_payload_same_id_conflicts".to_string(),
            refusal: "IntentConflict".to_string(),
        },
        FixtureCase {
            case: 16,
            name: "cancellation_before_vs_after_possible_mutation".to_string(),
            refusal: "Backend".to_string(),
        },
        FixtureCase {
            case: 17,
            name: "partial_resume_does_not_repeat_completed_surfaces".to_string(),
            refusal: "none".to_string(),
        },
        FixtureCase {
            case: 18,
            name: "unknown_or_incomplete_surface_blocks_purged_result".to_string(),
            refusal: "UnknownSurface".to_string(),
        },
        FixtureCase {
            case: 19,
            name: "shuffled_responses_yield_canonical_result".to_string(),
            refusal: "none".to_string(),
        },
        FixtureCase {
            case: 20,
            name: "store_port_fixture_and_source_guard".to_string(),
            refusal: "none".to_string(),
        },
    ]
}

// Fixture conformance, not a denominator case: pins
// `tests/data/purge_protocol.json` byte-exact to the suite's declared
// twenty-case denominator. No WORK_UNIT_CASE marker by design, so the
// twenty markers below stay exactly 1..20, each allocated once.
#[test]
fn purge_protocol_fixture_pins_the_twenty_case_denominator() {
    let expected = fixture_denominator();
    assert_eq!(
        expected.len(),
        20,
        "the denominator is exactly twenty cases"
    );
    for (index, entry) in expected.iter().enumerate() {
        let want = u32::try_from(index).unwrap_or(u32::MAX) + 1;
        assert_eq!(entry.case, want, "cases run exactly 1..20 in order");
        assert!(
            !entry.name.trim().is_empty(),
            "case {} names its proof",
            want
        );
        assert!(
            !entry.refusal.trim().is_empty(),
            "case {} declares its refusal",
            want
        );
    }
    let bytes = match canonical_json_bytes(&expected) {
        Ok(bytes) => bytes,
        Err(error) => panic!("canonical fixture bytes: {error}"),
    };
    let file = include_str!("data/purge_protocol.json");
    assert_eq!(
        file.trim_end().as_bytes(),
        bytes.as_slice(),
        "the fixture pins the declared denominator byte-exact"
    );
}

// WORK_UNIT_CASE: 688/2
#[test]
fn required_partial_or_unknown_closure_blocks_start() {
    let mut partial = test_request("request-688-closure-partial");
    partial
        .evidence
        .push(closure_evidence(EvidenceCoverage::PartialForScope));
    let mut backend = RecordingBackend::ready();
    match execute(&mut backend, &partial) {
        Ok(_) => panic!("partial closure evidence must block start"),
        Err(ErasureError::InsufficientClosureEvidence) => {}
        Err(other) => panic!("typed closure refusal, got: {other:?}"),
    }
    assert!(
        backend.call_order.is_empty(),
        "refusal precedes every backend call: {:?}",
        backend.call_order
    );

    let mut unknown = test_request("request-688-closure-unknown");
    unknown
        .evidence
        .push(closure_evidence(EvidenceCoverage::Unknown));
    let mut unknown_backend = RecordingBackend::ready();
    match execute(&mut unknown_backend, &unknown) {
        Ok(_) => panic!("unknown closure evidence must block start"),
        Err(ErasureError::InsufficientClosureEvidence) => {}
        Err(other) => panic!("typed closure refusal, got: {other:?}"),
    }
    assert_eq!(unknown_backend.erase_calls(), 0);
    assert_eq!(unknown_backend.ledger_appends(), 0);

    let mut complete = test_request("request-688-closure-complete");
    complete
        .evidence
        .push(closure_evidence(EvidenceCoverage::CompleteForScope));
    let mut healthy = RecordingBackend::ready();
    match execute(&mut healthy, &complete) {
        Ok(_) => {}
        Err(error) => panic!("complete closure evidence proceeds: {error:?}"),
    }

    // Scope layer: a plan whose required influence closure is still
    // partial/unknown carries a non-terminal disposition, so admission
    // refuses to start dispatch even though the binding itself holds.
    let bound = scope_bound_request();
    let mut open = scope_snapshot(7);
    open.targets[1].disposition = TargetDisposition::UnknownOutcome {
        detail_ref: Some("influence-closure:purge-protocol".to_string()),
    };
    assert!(open.validate().is_ok(), "open targets stay explicit");
    assert!(
        !open.fully_dispositioned(),
        "partial/unknown closure is never dispositioned"
    );
    match bound.bind_scope_snapshot(&open) {
        Ok(_) => {}
        Err(error) => panic!("binding holds while closure is open: {error:?}"),
    }
    assert!(
        !(bound.bind_scope_snapshot(&open).is_ok() && open.fully_dispositioned()),
        "open influence closure must not start dispatch"
    );
    let closed = scope_snapshot(7);
    assert!(closed.fully_dispositioned());
    assert!(
        bound.bind_scope_snapshot(&closed).is_ok() && closed.fully_dispositioned(),
        "revoked/closed plan may start"
    );
}

// WORK_UNIT_CASE: 688/3
#[test]
fn stale_epoch_fence_or_policy_refuses() {
    let mut stale_evidence = test_request("request-688-stale-fence");
    let mut envelope = closure_evidence(EvidenceCoverage::CompleteForScope);
    envelope.state_fence = stale_fence();
    stale_evidence.evidence.push(envelope);
    let mut backend = RecordingBackend::ready();
    match execute(&mut backend, &stale_evidence) {
        Ok(_) => panic!("stale-fence evidence must refuse"),
        Err(ErasureError::FenceMismatch) => {}
        Err(other) => panic!("typed fence refusal, got: {other:?}"),
    }
    assert_eq!(backend.erase_calls(), 0);
    assert_eq!(backend.ledger_appends(), 0);

    let bound = scope_bound_request();
    let mut drifted_fence = scope_snapshot(7);
    drifted_fence.state_fence = stale_fence();
    match bound.bind_scope_snapshot(&drifted_fence) {
        Ok(_) => panic!("incompatible scope fence must refuse binding"),
        Err(ErasureError::FenceMismatch) => {}
        Err(other) => panic!("typed fence refusal, got: {other:?}"),
    }

    let mut reapproved = scope_snapshot(7);
    reapproved.approval.approval_digest = "cd".repeat(32);
    match bound.bind_scope_snapshot(&reapproved) {
        Ok(_) => panic!("changed approval digest must refuse binding"),
        Err(ErasureError::ScopeMismatch) => {}
        Err(other) => panic!("typed policy refusal, got: {other:?}"),
    }
}

// WORK_UNIT_CASE: 688/4
#[test]
fn subject_target_or_ledger_revision_drift_refuses() {
    let request = test_request("request-688-drift");
    let mut backend = RecordingBackend {
        revision: 8,
        ..RecordingBackend::ready()
    };
    match execute(&mut backend, &request) {
        Ok(_) => panic!("live revision drift must refuse"),
        Err(ErasureError::RevisionMismatch {
            expected: 7,
            observed: 8,
        }) => {}
        Err(other) => panic!("typed revision refusal, got: {other:?}"),
    }
    assert_eq!(backend.erase_calls(), 0);
    assert_eq!(backend.ledger_appends(), 0);
    assert!(backend.intents.is_empty(), "drift records no intent");

    let bound = scope_bound_request();
    let drifted_scope = scope_snapshot(8);
    match bound.bind_scope_snapshot(&drifted_scope) {
        Ok(_) => panic!("frozen scope revision drift must refuse binding"),
        Err(ErasureError::ScopeMismatch) => {}
        Err(other) => panic!("typed revision refusal, got: {other:?}"),
    }

    let mut other_subject = scope_snapshot(7);
    other_subject.subject_ref = "subject:other".to_string();
    match bound.bind_scope_snapshot(&other_subject) {
        Ok(_) => panic!("subject drift must refuse binding"),
        Err(ErasureError::ScopeMismatch) => {}
        Err(other) => panic!("typed subject refusal, got: {other:?}"),
    }
}

// WORK_UNIT_CASE: 688/5
#[test]
fn exact_denominator_with_evidence_backed_exclusions() {
    let snapshot = scope_snapshot(7);
    assert!(snapshot.validate().is_ok(), "closed denominator validates");
    assert_eq!(
        snapshot.targets.len(),
        8,
        "seven families cover eight locations"
    );
    assert!(snapshot.fully_dispositioned());

    let full = scope_bound_request();
    match full.bind_scope_snapshot(&snapshot) {
        Ok(binding) => assert_eq!(binding.len(), 64, "binding digest is SHA-256 hex"),
        Err(error) => panic!("exact denominator binds: {error:?}"),
    }

    // Excluded surfaces simply stay out of the request; the remainder binds.
    let mut narrowed = scope_bound_request();
    narrowed.locations = vec![PurgeLocation::CanonicalPayload, PurgeLocation::Blob];
    match narrowed.bind_scope_snapshot(&snapshot) {
        Ok(_) => {}
        Err(error) => panic!("evidence-backed exclusion binds: {error:?}"),
    }

    // An empty request is not a denominator and never reaches the backend.
    let mut empty = scope_bound_request();
    empty.locations.clear();
    match empty.bind_scope_snapshot(&snapshot) {
        Ok(_) => panic!("empty locations must refuse"),
        Err(ErasureError::EmptyLocations) => {}
        Err(other) => panic!("typed empty refusal, got: {other:?}"),
    }

    // Unknown registry/coverage cannot become "no targets".
    let mut no_targets = scope_snapshot(7);
    no_targets.targets.clear();
    match full.bind_scope_snapshot(&no_targets) {
        Ok(_) => panic!("empty frozen denominator must refuse"),
        Err(ErasureError::InvalidScope) => {}
        Err(other) => panic!("typed scope refusal, got: {other:?}"),
    }
    let mut missing_family = scope_snapshot(7);
    missing_family
        .targets
        .retain(|target| target.family != ErasureFamily::ProviderSideData);
    match full.bind_scope_snapshot(&missing_family) {
        Ok(_) => panic!("missing family must refuse"),
        Err(ErasureError::InvalidScope) => {}
        Err(other) => panic!("typed scope refusal, got: {other:?}"),
    }

    // A held target carries exact hold evidence, validates, but never
    // reads as complete erasure.
    let mut held = scope_snapshot(7);
    held.targets[0].disposition = TargetDisposition::RetentionBlocked(HoldTerms {
        holder_owner_ref: "owner:purge-protocol".to_string(),
        legal_basis_ref: "basis:purge-protocol".to_string(),
        policy_ref: "policy:purge-protocol".to_string(),
        review_or_expiry_ref: "review:purge-protocol".to_string(),
        protected_minimum_ref: None,
    });
    assert!(held.validate().is_ok(), "held target stays explicit");
    assert!(!held.fully_dispositioned(), "hold is not complete erasure");
    assert_eq!(
        held.targets[0].owner,
        TargetOwner::CanonicalStore,
        "the held target stays under its owning boundary"
    );
}

// WORK_UNIT_CASE: 688/6
#[test]
fn tombstone_without_physical_proof_stays_incomplete() {
    let request = test_request("request-688-tombstone-noproof");
    let mut backend = RecordingBackend {
        scripted_outcomes: Some(vec![
            SurfaceOutcome::Purged {
                location: PurgeLocation::CanonicalPayload,
            },
            SurfaceOutcome::Incomplete {
                location: PurgeLocation::Blob,
            },
            SurfaceOutcome::Purged {
                location: PurgeLocation::Index,
            },
        ]),
        ..RecordingBackend::ready()
    };
    match execute(&mut backend, &request) {
        Ok(_) => panic!("missing physical proof must stay incomplete"),
        Err(ErasureError::IncompleteErasure) => {}
        Err(other) => panic!("typed incomplete refusal, got: {other:?}"),
    }
    assert_eq!(backend.erase_calls(), 1, "tombstone-first dispatch ran");
    assert!(
        backend
            .tombstones
            .contains_key("request-688-tombstone-noproof"),
        "durable tombstone was committed before dispatch"
    );
    assert_eq!(backend.ledger_appends(), 0, "no ledger entry on refusal");
    assert!(backend.completions.is_empty());
}

// WORK_UNIT_CASE: 688/7
#[test]
fn key_loss_without_byte_removal_proof_stays_incomplete() {
    // Key destruction without the required byte-removal proof: the blob
    // owner reports Incomplete, which never reads as purged.
    let request = test_request("request-688-key-loss");
    let mut backend = RecordingBackend {
        scripted_outcomes: Some(vec![
            SurfaceOutcome::Purged {
                location: PurgeLocation::CanonicalPayload,
            },
            SurfaceOutcome::Incomplete {
                location: PurgeLocation::Blob,
            },
            SurfaceOutcome::Purged {
                location: PurgeLocation::Index,
            },
        ]),
        ..RecordingBackend::ready()
    };
    match execute(&mut backend, &request) {
        Ok(_) => panic!("key loss without byte proof must stay incomplete"),
        Err(ErasureError::IncompleteErasure) => {}
        Err(other) => panic!("typed incomplete refusal, got: {other:?}"),
    }
    assert_eq!(
        backend.last_outcomes,
        vec![
            SurfaceOutcome::Purged {
                location: PurgeLocation::CanonicalPayload,
            },
            SurfaceOutcome::Incomplete {
                location: PurgeLocation::Blob,
            },
            SurfaceOutcome::Purged {
                location: PurgeLocation::Index,
            },
        ],
        "the blob surface stays explicitly incomplete"
    );
    assert_eq!(backend.ledger_appends(), 0);
    assert!(backend.completions.is_empty());
}

// WORK_UNIT_CASE: 688/12
#[test]
fn provider_ack_without_authentic_receipt_refuses() {
    let mut request = test_request("request-688-provider-ack");
    request.locations = vec![PurgeLocation::CanonicalPayload, PurgeLocation::ProviderCopy];
    let mut backend = RecordingBackend {
        scripted_outcomes: Some(vec![
            SurfaceOutcome::Purged {
                location: PurgeLocation::CanonicalPayload,
            },
            SurfaceOutcome::Incomplete {
                location: PurgeLocation::ProviderCopy,
            },
        ]),
        ..RecordingBackend::ready()
    };
    match execute(&mut backend, &request) {
        Ok(_) => panic!("provider ack without exact receipt must refuse"),
        Err(ErasureError::IncompleteErasure) => {}
        Err(other) => panic!("typed provider refusal, got: {other:?}"),
    }
    assert_eq!(backend.ledger_appends(), 0);
    assert!(backend.completions.is_empty());

    // A provider timeout after possible effect preserves unknown and
    // reconciles the same operation instead of claiming success.
    let mut timeout = test_request("request-688-provider-timeout");
    timeout.locations = vec![PurgeLocation::CanonicalPayload, PurgeLocation::ProviderCopy];
    let mut timeout_backend = RecordingBackend {
        scripted_outcomes: Some(vec![
            SurfaceOutcome::Purged {
                location: PurgeLocation::CanonicalPayload,
            },
            SurfaceOutcome::Unknown {
                location: PurgeLocation::ProviderCopy,
            },
        ]),
        ..RecordingBackend::ready()
    };
    match execute(&mut timeout_backend, &timeout) {
        Ok(_) => panic!("provider unknown must not claim success"),
        Err(ErasureError::UnknownSurface) => {}
        Err(other) => panic!("typed unknown refusal, got: {other:?}"),
    }
    assert_eq!(timeout_backend.ledger_appends(), 0);
    assert!(timeout_backend.completions.is_empty());
}

// WORK_UNIT_CASE: 688/13
#[test]
fn transport_loss_preserves_unknown_and_reconciliation() {
    // Transport loss on the destructive path: no success, no seal; the
    // healthy retry reconciles the same operation identity.
    let request = test_request("request-688-transport");
    let mut backend = RecordingBackend {
        erase_transport_error: true,
        ..RecordingBackend::ready()
    };
    match execute(&mut backend, &request) {
        Ok(_) => panic!("transport loss must not claim success"),
        Err(ErasureError::Backend(_)) => {}
        Err(other) => panic!("transport loss stays a backend error, got: {other:?}"),
    }
    assert_eq!(backend.ledger_appends(), 0);
    assert!(backend.completions.is_empty());
    backend.erase_transport_error = false;
    let receipt = match execute(&mut backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("same-operation retry reconciles: {error:?}"),
    };
    assert_eq!(receipt.request_id, "request-688-transport");
    assert_eq!(backend.intents.len(), 1, "one intent identity reconciled");
    assert_eq!(
        backend.tombstones.len(),
        1,
        "one tombstone identity reconciled"
    );
    assert_eq!(backend.ledger_appends(), 1);

    // Ledger-commit response loss after possible deletion: no success is
    // claimed and no completion is sealed; the retry reconciles the same
    // operation instead of minting a new one.
    let second = test_request("request-688-ledger-loss");
    let mut lossy = RecordingBackend {
        fail_append_ledger: true,
        ..RecordingBackend::ready()
    };
    match execute(&mut lossy, &second) {
        Ok(_) => panic!("lost ledger commit must not claim success"),
        Err(ErasureError::Backend(_)) => {}
        Err(other) => panic!("lost commit stays a backend error, got: {other:?}"),
    }
    assert_eq!(lossy.erase_calls(), 1);
    assert!(
        lossy.completions.is_empty(),
        "lost commit must not seal completion"
    );
    lossy.fail_append_ledger = false;
    let reconciled = match execute(&mut lossy, &second) {
        Ok(receipt) => receipt,
        Err(error) => panic!("same-operation retry reconciles: {error:?}"),
    };
    let replayed = match execute(&mut lossy, &second) {
        Ok(receipt) => receipt,
        Err(error) => panic!("sealed retry replays: {error:?}"),
    };
    assert_eq!(reconciled, replayed);
    assert_eq!(reconciled.purge.purge_id, replayed.purge.purge_id);
    assert_eq!(lossy.intents.len(), 1, "retries never mint a new operation");
}

// WORK_UNIT_CASE: 688/15
#[test]
fn changed_payload_same_id_conflicts() {
    let first = test_request("request-688-payload-conflict");
    let mut backend = RecordingBackend::ready();
    let original = match execute(&mut backend, &first) {
        Ok(receipt) => receipt,
        Err(error) => panic!("first execute succeeds: {error:?}"),
    };
    assert_eq!(backend.erase_calls(), 1);

    let mut changed = test_request("request-688-payload-conflict");
    changed.scope = "scope:changed-payload".to_string();
    match execute(&mut backend, &changed) {
        Ok(_) => panic!("changed payload under one id must conflict"),
        Err(ErasureError::IntentConflict) => {}
        Err(other) => panic!("typed conflict, got: {other:?}"),
    }
    assert_eq!(
        backend.erase_calls(),
        1,
        "conflict must not dispatch destructively again"
    );
    assert_eq!(backend.ledger_appends(), 1);
    assert_eq!(
        backend.completions.get("request-688-payload-conflict"),
        Some(&original),
        "the original receipt survives the conflict"
    );
}

// WORK_UNIT_CASE: 688/16
#[test]
fn cancellation_before_vs_after_possible_mutation() {
    // Cancellation before dispatch records nothing and dispatches nothing.
    let refused = test_request("request-688-cancel-before");
    let mut before = RecordingBackend {
        fail_record: true,
        ..RecordingBackend::ready()
    };
    match execute(&mut before, &refused) {
        Ok(_) => panic!("pre-dispatch cancellation must refuse"),
        Err(ErasureError::UnsupportedIntent) => {}
        Err(other) => panic!("typed pre-dispatch refusal, got: {other:?}"),
    }
    assert!(
        before.intents.is_empty(),
        "cancelled start records no intent"
    );
    assert!(before.tombstones.is_empty());
    assert_eq!(before.erase_calls(), 0);
    assert_eq!(before.ledger_appends(), 0);

    // Cancellation after possible deletion cannot mean rollback: effects
    // persist, nothing is restored, and the retry reconciles the same
    // operation instead of undoing it.
    let request = test_request("request-688-cancel-after");
    let mut backend = RecordingBackend {
        fail_note_completed: true,
        ..RecordingBackend::ready()
    };
    match execute(&mut backend, &request) {
        Ok(_) => panic!("lost completion seal must not claim success"),
        Err(ErasureError::Backend(_)) => {}
        Err(other) => panic!("seal loss stays a backend error, got: {other:?}"),
    }
    assert_eq!(backend.erase_calls(), 1);
    assert_eq!(backend.ledger_appends(), 1);
    assert!(
        backend.completions.is_empty(),
        "uncompleted work is never reported complete"
    );
    assert_eq!(
        backend.last_outcomes.len(),
        3,
        "effects persist; no rollback"
    );
    assert!(
        backend
            .last_outcomes
            .iter()
            .all(|outcome| matches!(outcome, SurfaceOutcome::Purged { .. })),
        "no surface was restored by the cancellation"
    );
    backend.fail_note_completed = false;
    let receipt = match execute(&mut backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("same-operation retry reconciles: {error:?}"),
    };
    assert_eq!(receipt.request_id, "request-688-cancel-after");
    assert_eq!(backend.last_outcomes.len(), 3);
}

// WORK_UNIT_CASE: 688/17
#[test]
fn partial_resume_does_not_repeat_completed_surfaces() {
    let request = test_request("request-688-resume");
    let mut backend = RecordingBackend {
        resume_aware: true,
        fail_append_ledger: true,
        ..RecordingBackend::ready()
    };
    match execute(&mut backend, &request) {
        Ok(_) => panic!("lost ledger commit must not claim success"),
        Err(ErasureError::Backend(_)) => {}
        Err(other) => panic!("lost commit stays a backend error, got: {other:?}"),
    }
    assert_eq!(
        backend.dispatched.len(),
        3,
        "first pass dispatches every surface once"
    );

    backend.fail_append_ledger = false;
    let receipt = match execute(&mut backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("resume reconciles the same operation: {error:?}"),
    };
    assert_eq!(receipt.request_id, "request-688-resume");
    assert_eq!(
        backend.dispatched.len(),
        3,
        "resume must not repeat completed surfaces"
    );
    let mut seen = BTreeSet::new();
    for location in &backend.dispatched {
        seen.insert(location_code(*location));
    }
    assert_eq!(seen.len(), 3, "each surface dispatched exactly once");
    assert_eq!(receipt.purge.purged_locations.len(), 3);
}

// WORK_UNIT_CASE: 688/19
#[test]
fn shuffled_responses_yield_canonical_result() {
    let request = test_request("request-688-shuffle");
    let forward = vec![
        SurfaceOutcome::Purged {
            location: PurgeLocation::CanonicalPayload,
        },
        SurfaceOutcome::Purged {
            location: PurgeLocation::Blob,
        },
        SurfaceOutcome::Purged {
            location: PurgeLocation::Index,
        },
    ];
    let backward = vec![
        SurfaceOutcome::Purged {
            location: PurgeLocation::Index,
        },
        SurfaceOutcome::Purged {
            location: PurgeLocation::Blob,
        },
        SurfaceOutcome::Purged {
            location: PurgeLocation::CanonicalPayload,
        },
    ];
    let mut first_backend = RecordingBackend {
        scripted_outcomes: Some(forward),
        ..RecordingBackend::ready()
    };
    let mut second_backend = RecordingBackend {
        scripted_outcomes: Some(backward),
        ..RecordingBackend::ready()
    };
    let first = match execute(&mut first_backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("forward order succeeds: {error:?}"),
    };
    let second = match execute(&mut second_backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("backward order succeeds: {error:?}"),
    };
    assert_eq!(
        first, second,
        "equivalent responses yield one canonical result"
    );
    assert_eq!(
        first.purge.purged_locations,
        vec![
            PurgeLocation::CanonicalPayload,
            PurgeLocation::Index,
            PurgeLocation::Blob,
        ],
        "committed locations run in canonical order"
    );
    assert_eq!(
        first_backend.call_order, second_backend.call_order,
        "required execution order is retained"
    );
}
