//! Tombstone-first adversarial closure for #1130.
//!
//! Proves the tombstone lifecycle inside `eliot-erasure` only: the durable
//! tombstone commits before every destructive call, tombstone failure yields
//! zero destructive effects, a missing tombstone (or missing capability)
//! fails closed, replay without the tombstone refuses, and a changed scope
//! under one operation identity conflicts instead of overwriting.

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
        subject_ref: "subject:tombstone-closure".to_string(),
        scope: "scope:tombstone-closure".to_string(),
        locations: vec![PurgeLocation::CanonicalPayload, PurgeLocation::Blob],
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
        self.completions.insert(receipt.request_id.clone(), receipt);
        Ok(())
    }

    fn erase(&mut self, intent: &ErasureIntent) -> Result<Vec<SurfaceOutcome>, Self::Error> {
        self.call_order.push("erase".to_string());
        if intent.validate().is_err() {
            return Err(BackendError("invalid intent at dispatch".to_string()));
        }
        if !self.tombstones.contains_key(&intent.operation_id) {
            return Err(BackendError(
                "erase dispatched without a tombstone".to_string(),
            ));
        }
        Ok(intent
            .locations
            .iter()
            .map(|location| SurfaceOutcome::Purged {
                location: *location,
            })
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

/// Backend that never overrides tombstone capability: trait defaults refuse.
struct NoTombstoneBackend {
    revision: u64,
    intents: BTreeMap<String, ErasureIntent>,
    erase_calls: usize,
}

impl ErasureBackend for NoTombstoneBackend {
    type Error = BackendError;

    fn current_revision(&self, _subject_ref: &str, _scope: &str) -> Result<u64, Self::Error> {
        Ok(self.revision)
    }

    fn completed_receipt(
        &self,
        _operation_id: &str,
    ) -> Result<Option<ErasureReceipt>, ErasureError> {
        Ok(None)
    }

    fn record_intent(&mut self, intent: ErasureIntent) -> Result<IntentReceipt, ErasureError> {
        intent.validate()?;
        self.intents
            .insert(intent.operation_id.clone(), intent.clone());
        Ok(IntentReceipt {
            operation_id: intent.operation_id.clone(),
            request_digest: intent.request_digest.clone(),
        })
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

// WORK_UNIT_CASE: 1130/tombstone-first
#[test]
fn tombstone_commits_before_every_destructive_call() {
    let request = test_request("request-1130-tombstone-order");
    let mut backend = RecordingBackend::ready();
    let receipt = match execute(&mut backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("clean execute succeeds: {error:?}"),
    };
    assert!(!receipt.purge.tombstone_digest.is_empty());
    let stored = backend
        .tombstones
        .get("request-1130-tombstone-order")
        .unwrap_or_else(|| panic!("tombstone persisted"));
    assert_eq!(stored.tombstone_digest, receipt.purge.tombstone_digest);
    let tombstone_pos = backend
        .call_order
        .iter()
        .position(|call| call.as_str() == "commit_tombstone")
        .unwrap_or_else(|| panic!("tombstone committed: {:?}", backend.call_order));
    let erase_pos = backend
        .call_order
        .iter()
        .position(|call| call.as_str() == "erase")
        .unwrap_or_else(|| panic!("erase dispatched: {:?}", backend.call_order));
    assert!(
        tombstone_pos < erase_pos,
        "tombstone {tombstone_pos} precedes erase {erase_pos}"
    );
}

// WORK_UNIT_CASE: 1130/tombstone-failure
#[test]
fn tombstone_failure_yields_zero_destructive_effects() {
    let request = test_request("request-1130-tombstone-fails");
    let mut backend = RecordingBackend {
        fail_tombstone: true,
        ..RecordingBackend::ready()
    };
    match execute(&mut backend, &request) {
        Ok(_) => panic!("tombstone failure must refuse"),
        Err(ErasureError::UnsupportedIntent) => {}
        Err(other) => panic!("typed tombstone refusal, got: {other:?}"),
    }
    assert_eq!(backend.erase_calls(), 0);
    assert_eq!(backend.ledger_appends(), 0);
    assert!(backend.completions.is_empty());
}

// WORK_UNIT_CASE: 1130/missing-tombstone
#[test]
fn missing_tombstone_capability_fails_closed() {
    let request = test_request("request-1130-no-tombstone-cap");
    let mut backend = NoTombstoneBackend {
        revision: 7,
        intents: BTreeMap::new(),
        erase_calls: 0,
    };
    match execute(&mut backend, &request) {
        Ok(_) => panic!("missing tombstone capability must refuse"),
        Err(ErasureError::UnsupportedIntent) => {}
        Err(other) => panic!("default tombstone refusal is typed, got: {other:?}"),
    }
    assert_eq!(backend.erase_calls, 0);
}

// WORK_UNIT_CASE: 1130/replay-tombstone
#[test]
fn replay_without_tombstone_fails_closed() {
    let request = test_request("request-1130-replay-tombstone");
    let mut backend = RecordingBackend::ready();
    let first = match execute(&mut backend, &request) {
        Ok(receipt) => receipt,
        Err(error) => panic!("first execute succeeds: {error:?}"),
    };
    assert_eq!(backend.erase_calls(), 1);
    backend.tombstones.clear();
    match execute(&mut backend, &request) {
        Ok(_) => panic!("replay without tombstone must refuse"),
        Err(ErasureError::MissingTombstone) => {}
        Err(other) => panic!("replay tombstone refusal is typed, got: {other:?}"),
    }
    assert_eq!(
        backend.erase_calls(),
        1,
        "refused replay must not dispatch again"
    );
    assert_eq!(
        first.purge.state,
        eliot_security_contracts::PurgeState::Purged
    );
}

// WORK_UNIT_CASE: 1130/identity-conflict
#[test]
fn changed_scope_under_same_identity_conflicts() {
    let mut backend = RecordingBackend::ready();
    let first = test_request("request-1130-identity");
    match execute(&mut backend, &first) {
        Ok(_) => {}
        Err(error) => panic!("first execute succeeds: {error:?}"),
    }
    let mut second = test_request("request-1130-identity");
    second.locations.push(PurgeLocation::Index);
    match execute(&mut backend, &second) {
        Ok(_) => panic!("changed scope under one identity must conflict"),
        Err(ErasureError::IntentConflict) => {}
        Err(other) => panic!("identity conflict is typed, got: {other:?}"),
    }
    assert_eq!(backend.erase_calls(), 1);
}
