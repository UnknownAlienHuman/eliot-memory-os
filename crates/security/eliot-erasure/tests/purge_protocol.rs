//! Erasure-owned fail-closed behaviour slice for #688.
//!
//! Three end-to-end protocol proofs inside `eliot-erasure` only: durable
//! intent precedes every destructive call (and a missing intent capability
//! means zero destructive calls), exact replay returns the original receipt
//! with no second dispatch, and one unknown/incomplete surface blocks a
//! `Purged` result. Live Store producers land later; these tests aggregate
//! typed outcomes passed in, never store-surface writes.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_erasure::{
    ErasureBackend, ErasureError, ErasureIntent, ErasureReceipt, ErasureRequest, IntentReceipt,
    SurfaceOutcome, Tombstone, execute,
};
use eliot_security_contracts::{PurgeLedgerEntry, PurgeLocation};

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
        let Some(intent) = self.intents.get(&receipt.request_id) else {
            return Err(ErasureError::IntentConflict);
        };
        if intent.request_digest != receipt.request_digest {
            return Err(ErasureError::IntentConflict);
        }
        self.completions
            .insert(receipt.request_id.clone(), receipt);
        Ok(())
    }

    fn erase(&mut self, intent: &ErasureIntent) -> Result<Vec<SurfaceOutcome>, Self::Error> {
        self.call_order.push("erase".to_string());
        if intent.validate().is_err() {
            return Err(BackendError("invalid intent at dispatch".to_string()));
        }
        if let Some(scripted) = &self.scripted_outcomes {
            return Ok(scripted.clone());
        }
        Ok(intent
            .locations
            .iter()
            .map(|location| SurfaceOutcome::Purged { location: *location })
            .collect())
    }

    fn append_purge_ledger(&mut self, entry: PurgeLedgerEntry) -> Result<(), Self::Error> {
        self.call_order.push("append_ledger".to_string());
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
            .map(|location| SurfaceOutcome::Purged { location: *location })
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
        Err(ErasureError::UnsupportedIntent) => {},
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
        Err(ErasureError::UnsupportedIntent) => {},
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
        Err(ErasureError::UnknownSurface) => {},
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
        Err(ErasureError::IncompleteErasure) => {},
        Err(other) => panic!("incomplete refusal is typed, got: {other:?}"),
    }
    assert_eq!(incomplete.ledger_appends(), 0);
    assert!(incomplete.completions.is_empty());
}
