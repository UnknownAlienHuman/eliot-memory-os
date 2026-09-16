//! `SurrealDB` Dreamer ledger edge (S1, owner #775).
//!
//! Implements [`CanonicalStoreClient::dreamer_job`](eliot_store_api::CanonicalStoreClient)
//! for [`SurrealStoreAdapter`](crate::SurrealStoreAdapter) inside the existing
//! `recovery_job` table. One versioned Dreamer namespace carries four
//! discriminated key families (`job:`, `event:`, `op:`, `receipt:`); a single
//! provider transaction commits all four rows atomically.
//!
//! Reuses the S0 closed named family from `eliot-store-api::dreamer_job`
//! (ledger record/event types, digests, bundle validation) and the K0 control
//! contracts from `eliot-protocol::dreamer_job`. No second public database
//! client, table, or semantic decoder: physical namespace, key layout and
//! `SurrealQL` stay private to this module plus [`crate::schema`].
//!
//! Scope (B-DRM-S1 #775, full ledger edge): all twelve K0 operations are
//! durably implemented with compare-and-swap exclusion and exact-replay vs
//! changed-content discrimination. Every mutation commits record, monotonic
//! event, unique operation-idempotency evidence and immutable receipt rows in
//! one provider transaction. No in-memory stand-in: persistence is proven by
//! reopening the adapter over the same `SurrealKV` files, and exclusion by
//! concurrent callers racing one expected revision in real provider
//! transactions. The adapter-wide `write_lock` is deliberately *not* taken
//! here so the CAS outcome is decided by the database, not by a process mutex.
//!
//! Corrected lifecycle (I14.20):
//! `NOT_STARTED → QUEUED → LEASED → RUNNING ↔ CHECKPOINTED → VERIFYING →`
//! terminal (`COMPLETED | PARTIAL | FAILED | CANCELLED | UNKNOWN_OUTCOME`).
//! Cancellation-requested is recorded evidence, never a job state; a
//! result-under-verification is never a terminal outcome; a committed semantic
//! `UNKNOWN_OUTCOME` is independent from Store commit uncertainty.

use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::SurrealStoreAdapter;
use crate::client;
use crate::error::AdapterError;
use crate::schema;
use eliot_protocol::dreamer_job::{
    DurableJobRecord, DurableJobRequest, DurableJobResponse, JobLease, JobOperation, JobRole,
    JobState, LeaseSelector, MutationDisposition,
};
use eliot_store_api::{
    DreamerJobLedgerEvent, DreamerJobLedgerRecord, DreamerJobMutationIdentity,
    MAX_DREAMER_JOB_HISTORY, OperationId, RecoveryRecord, RecoveryRecordKey,
    RequestMeta, StateFence, StoreError, canonical_json_bytes, dreamer_job_queue_key,
    map_durable_error, sha256_hex, validate_ledger_bundle,
};

/// Outer CAS generation for the first Dreamer mutation of a job.
const FIRST_OUTER_REVISION: u64 = 1;
/// Outer CAS generation after the first lease (submit cursor 1 -> lease 2).
const LEASE_OUTER_REVISION: u64 = 2;
/// Lease time-to-live in milliseconds.
const LEASE_TTL_MS: u64 = 60_000;

/// Stored mutation outcome bound to one operation identity.
///
/// The full first [`DurableJobResponse`] is persisted as canonical JSON so an
/// exact replay (same operation id plus same canonical hash) can return the
/// original outcome with the retry's fresh correlation swapped in. A changed
/// hash under the same operation id is a deterministic conflict.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredMutation {
    operation_id: String,
    idempotency_key: String,
    canonical_request_hash: String,
    operation_kind: String,
    response: DurableJobResponse,
}

impl StoredMutation {
    fn validate(&self) -> Result<(), AdapterError> {
        if self.operation_id.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
            || self.operation_kind.trim().is_empty()
        {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "dreamer_job.mutation",
                reason: "blank identity",
            }));
        }
        if self.canonical_request_hash.len() != 64 {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "dreamer_job.canonical_request_hash",
                reason: "must be lowercase SHA-256",
            }));
        }
        self.response
            .validate()
            .map_err(map_durable_error)
            .map_err(AdapterError::Store)?;
        Ok(())
    }
}

/// Stored receipt binding for one committed mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
    operation_id: String,
    receipt_id: String,
    job_id: String,
    attempt_id: String,
    revision: u64,
}

/// Returns the discriminated job key for one job/attempt pair.
///
/// Values avoid `:` (see `schema::dreamer`); job and attempt identities are
/// never parsed back out of the key (matching uses the decoded ledger), so
/// any identifier charset stays safe.
#[must_use]
pub(crate) fn dreamer_job_row_key(job_id: &str, attempt_id: &str) -> String {
    format!("{}{job_id}_{attempt_id}", schema::dreamer::KEY_JOB_PREFIX)
}

/// Returns the discriminated event key for one cursor.
#[must_use]
pub(crate) fn dreamer_event_row_key(job_id: &str, attempt_id: &str, cursor: u64) -> String {
    format!(
        "{}{job_id}_{attempt_id}_{cursor:016}",
        schema::dreamer::KEY_EVENT_PREFIX
    )
}

/// Returns the discriminated operation key for one operation id.
#[must_use]
pub(crate) fn dreamer_operation_row_key(operation_id: &str) -> String {
    format!("{}{operation_id}", schema::dreamer::KEY_OPERATION_PREFIX)
}

/// Returns the discriminated receipt key for one operation id.
#[must_use]
pub(crate) fn dreamer_receipt_row_key(operation_id: &str) -> String {
    format!("{}{operation_id}", schema::dreamer::KEY_RECEIPT_PREFIX)
}

/// Derives the deterministic Surreal record ID for one Dreamer row, mirroring
/// the genesis `recovery_owner_id` construction.
fn dreamer_record_id(namespace: &str, key: &str) -> Result<String, AdapterError> {
    let record_key = RecoveryRecordKey {
        namespace: namespace.to_owned(),
        key: key.to_owned(),
    };
    let bytes = canonical_json_bytes(&record_key)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn encode_canonical<T: Serialize>(value: &T) -> Result<(Vec<u8>, String), AdapterError> {
    let bytes = canonical_json_bytes(value)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    let digest = sha256_hex(&bytes);
    Ok((bytes, digest))
}

fn build_recovery_row(
    key: String,
    fence: &StateFence,
    outer_revision: u64,
    schema_str: &str,
    payload: Vec<u8>,
) -> Result<RecoveryRecord, AdapterError> {
    let value_digest = sha256_hex(&payload);
    let record = RecoveryRecord {
        namespace: schema::dreamer::NAMESPACE.to_owned(),
        key,
        state_fence: fence.clone(),
        revision: outer_revision,
        schema: schema_str.to_owned(),
        payload,
        value_digest,
    };
    record.validate().map_err(AdapterError::Store)?;
    Ok(record)
}

fn mutation_identity(request: &DurableJobRequest) -> DreamerJobMutationIdentity {
    DreamerJobMutationIdentity {
        operation_id: request.request_identity.operation.operation_id.clone(),
        idempotency_key: request.request_identity.operation.idempotency_key.clone(),
        canonical_request_hash: request.request_identity.canonical_request_hash.clone(),
        operation_kind: request.operation.kind().as_str().to_owned(),
    }
}

/// Parses one bounded identifier from text without naming a transitive
/// contract crate: validation runs inside the target type's own
/// `Deserialize` impl, and the concrete type is inferred from use.
fn validated_id<T>(text: String) -> Result<T, AdapterError>
where
    T: for<'de> serde::Deserialize<'de>,
{
    serde_json::from_value(serde_json::Value::String(text)).map_err(|_| {
        AdapterError::Store(StoreError::InvalidField {
            field: "dreamer_job.receipt_id",
            reason: "receipt binding failed",
        })
    })
}

fn receipt_id_text(operation_id: &OperationId) -> String {
    format!("dreamer-receipt-{}", operation_id.as_str())
}

fn now_unix_ms() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => elapsed.as_millis().try_into().unwrap_or(u64::MAX),
        Err(_) => 1_000,
    }
}

/// Reads one Dreamer row by key; `Ok(None)` when absent. Malformed provider
/// rows fail closed (never panicking, never repaired).
async fn read_dreamer_row(
    db: &client::RpcTransport,
    config: &crate::config::SurrealAdapterConfig,
    key: &str,
) -> Result<Option<RecoveryRecord>, AdapterError> {
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "dreamer_namespace".to_owned(),
        serde_json::Value::String(schema::dreamer::NAMESPACE.to_owned()),
    );
    bindings.insert(
        "dreamer_key".to_owned(),
        serde_json::Value::String(key.to_owned()),
    );
    let mut response = client::query(
        db,
        config,
        "dreamer.read_row",
        schema::READ_DREAMER_BY_KEY,
        bindings,
    )
    .await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let rows: Vec<RecoveryRecord> = response.take(0)?;
    match rows.into_iter().next() {
        Some(record) => {
            record.validate().map_err(AdapterError::Store)?;
            if record.namespace != schema::dreamer::NAMESPACE || record.key != key {
                return Err(AdapterError::Store(StoreError::IdentityConflict));
            }
            Ok(Some(record))
        }
        None => Ok(None),
    }
}

fn decode_ledger_record(record: &RecoveryRecord) -> Result<DreamerJobLedgerRecord, AdapterError> {
    serde_json::from_slice::<DreamerJobLedgerRecord>(&record.payload)
        .map_err(|error| AdapterError::Serialization(error.to_string()))
}

fn decode_stored_mutation(record: &RecoveryRecord) -> Result<StoredMutation, AdapterError> {
    let stored: StoredMutation = serde_json::from_slice(&record.payload)
        .map_err(|error| AdapterError::Serialization(error.to_string()))?;
    stored.validate()?;
    Ok(stored)
}

/// Entry point for `CanonicalStoreClient::dreamer_job` (S1 #775).
pub(crate) async fn dreamer_job(
    adapter: &SurrealStoreAdapter,
    ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    ctx.validate()
        .map_err(StoreError::Foundation)
        .map_err(AdapterError::Store)?;
    request
        .validate()
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    if ctx.state_fence != request.request_identity.operation.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    // Deliberately no `write_lock`: exclusion is decided by provider
    // CAS inside one transaction, so concurrent callers genuinely race.
    // The closed denominator stays the single advertisement gate even though
    // the dispatch below is exhaustive: an unadvertised kind fails here.
    if !is_supported_operation(&request.operation) {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let db = crate::apply::client(adapter).await?;
    crate::apply::ensure_ready(adapter, db).await?;
    match &request.operation {
        JobOperation::Submit { .. } => submit(adapter, db, ctx, request).await,
        JobOperation::LeaseNext { .. } => op_lease_next(adapter, db, ctx, request).await,
        JobOperation::LeaseExact { .. } => lease_exact(adapter, db, ctx, request).await,
        JobOperation::Renew { .. } => op_renew(adapter, db, ctx, request).await,
        JobOperation::Start { .. } => op_start(adapter, db, ctx, request).await,
        JobOperation::Checkpoint { .. } => op_checkpoint(adapter, db, ctx, request).await,
        JobOperation::Resume { .. } => op_resume(adapter, db, ctx, request).await,
        JobOperation::BeginVerification { .. } => {
            op_begin_verification(adapter, db, ctx, request).await
        }
        JobOperation::Publish { .. } => op_publish(adapter, db, ctx, request).await,
        JobOperation::Status { .. } => status(db, &adapter.config, ctx, request).await,
        JobOperation::RequestCancel { .. } => op_request_cancel(adapter, db, ctx, request).await,
        JobOperation::Reconcile { .. } => op_reconcile(adapter, db, ctx, request).await,
    }
}

#[allow(clippy::too_many_lines)]
async fn submit(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::Submit { submission } = &request.operation else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if request.role != eliot_protocol::dreamer_job::JobRole::Requester {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let job_id = submission.job_id.to_string();
    let attempt_id = submission.attempt_id.to_string();
    let row_key = dreamer_job_row_key(&job_id, &attempt_id);
    let operation_id = request.request_identity.operation.operation_id.to_string();
    let op_key = dreamer_operation_row_key(&operation_id);

    // Idempotency pre-read: exact operation replay returns the original
    // outcome; a changed hash under the same operation id conflicts.
    if let Some(existing) = read_dreamer_row(db, &adapter.config, &op_key).await? {
        let stored = decode_stored_mutation(&existing)?;
        if stored.canonical_request_hash == request.request_identity.canonical_request_hash
            && stored.operation_kind == request.operation.kind().as_str()
        {
            let mut replayed = stored.response;
            replayed.request_identity = request.request_identity.clone();
            replayed
                .validate_for(&request)
                .map_err(map_durable_error)
                .map_err(AdapterError::Store)?;
            return Ok(replayed);
        }
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    // Same job with a new operation identity is a duplicate creation, not an
    // idempotent replay (replay keys on operation id). The existing row is
    // decoded to fail closed on corruption, then the duplicate conflicts.
    if let Some(existing_job) = read_dreamer_row(db, &adapter.config, &row_key).await? {
        decode_ledger_record(&existing_job)?;
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }

    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: submission.job_id.clone(),
        attempt_id: submission.attempt_id.clone(),
        scope: submission.work_scope.clone(),
        revision: FIRST_OUTER_REVISION,
        state: JobState::Queued,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: None,
        checkpoint: None,
        result_under_verification: None,
        outcome: None,
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;

    let queue_key = dreamer_job_queue_key(&submission.job_id, &submission.attempt_id);
    let mutation = mutation_identity(&request);
    let record_state = DurableJobRecord {
        submission: submission.as_ref().clone(),
        state: JobState::Queued,
        revision: FIRST_OUTER_REVISION,
        lease: None,
        checkpoint: None,
        cancellation: eliot_protocol::dreamer_job::CancellationState::None,
        outcome: None,
    };
    let mut ledger = DreamerJobLedgerRecord {
        record: record_state,
        event_cursor: FIRST_OUTER_REVISION,
        queue_key,
        active_lease: None,
        lease_history: Vec::new(),
        result_under_verification: None,
        last_mutation: mutation.clone(),
        last_receipt_id: Some(receipt_id.clone()),
        record_digest: "0".repeat(64),
    };
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;

    let mut event = DreamerJobLedgerEvent {
        job_id: submission.job_id.clone(),
        attempt_id: submission.attempt_id.clone(),
        prior_state: JobState::NotStarted,
        next_state: JobState::Queued,
        prior_revision: 0,
        next_revision: FIRST_OUTER_REVISION,
        event_cursor: FIRST_OUTER_REVISION,
        operation: request.operation.clone(),
        role: request.role,
        lease: None,
        checkpoint: None,
        result_under_verification: None,
        mutation: mutation.clone(),
        receipt_id: Some(receipt_id.clone()),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    validate_ledger_bundle(&request, &response, &ledger, &event).map_err(AdapterError::Store)?;

    let stored = StoredMutation {
        operation_id: operation_id.clone(),
        idempotency_key: request.request_identity.operation.idempotency_key.clone(),
        canonical_request_hash: request.request_identity.canonical_request_hash.clone(),
        operation_kind: request.operation.kind().as_str().to_owned(),
        response: response.clone(),
    };
    let receipt_row = StoredReceipt {
        operation_id: operation_id.clone(),
        receipt_id: receipt_id.to_string(),
        job_id: job_id.clone(),
        attempt_id: attempt_id.clone(),
        revision: FIRST_OUTER_REVISION,
    };

    let fence = submission.work_scope.state_fence.clone();
    let (job_payload, _) = encode_canonical(&ledger)?;
    let (event_payload, _) = encode_canonical(&event)?;
    let (op_payload, _) = encode_canonical(&stored)?;
    let (receipt_payload, _) = encode_canonical(&receipt_row)?;
    let job_row = build_recovery_row(
        row_key.clone(),
        &fence,
        FIRST_OUTER_REVISION,
        schema::dreamer::SCHEMA_LEDGER_RECORD,
        job_payload,
    )?;
    let event_row = build_recovery_row(
        dreamer_event_row_key(&job_id, &attempt_id, FIRST_OUTER_REVISION),
        &fence,
        FIRST_OUTER_REVISION,
        schema::dreamer::SCHEMA_LEDGER_EVENT,
        event_payload,
    )?;
    let op_row = build_recovery_row(
        op_key.clone(),
        &fence,
        FIRST_OUTER_REVISION,
        schema::dreamer::SCHEMA_MUTATION,
        op_payload,
    )?;
    let receipt_record = build_recovery_row(
        dreamer_receipt_row_key(&operation_id),
        &fence,
        FIRST_OUTER_REVISION,
        schema::dreamer::SCHEMA_RECEIPT,
        receipt_payload,
    )?;

    match commit_four(
        db,
        &adapter.config,
        &operation_id,
        [&job_row, &event_row, &op_row, &receipt_record],
    )
    .await
    {
        Ok(()) => Ok(response),
        Err(AdapterError::ProviderConflict) => {
            // Concurrent winner committed first: re-read to classify exact
            // replay vs changed-content conflict.
            if let Some(existing) = read_dreamer_row(db, &adapter.config, &op_key).await? {
                let stored = decode_stored_mutation(&existing)?;
                if stored.canonical_request_hash == request.request_identity.canonical_request_hash
                    && stored.operation_kind == request.operation.kind().as_str()
                {
                    let mut replayed = stored.response;
                    replayed.request_identity = request.request_identity.clone();
                    replayed
                        .validate_for(&request)
                        .map_err(map_durable_error)
                        .map_err(AdapterError::Store)?;
                    return Ok(replayed);
                }
            }
            Err(AdapterError::Store(StoreError::IdentityConflict))
        }
        Err(error) => Err(error),
    }
}

#[allow(clippy::too_many_lines)]
async fn lease_exact(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::LeaseExact { selector, job_id } = &request.operation else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if request.role != eliot_protocol::dreamer_job::JobRole::Worker {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let operation_id = request.request_identity.operation.operation_id.to_string();
    let op_key = dreamer_operation_row_key(&operation_id);

    // Owner retry: same operation id plus same hash returns the same lease.
    if let Some(existing) = read_dreamer_row(db, &adapter.config, &op_key).await? {
        let stored = decode_stored_mutation(&existing)?;
        if stored.canonical_request_hash == request.request_identity.canonical_request_hash
            && stored.operation_kind == request.operation.kind().as_str()
        {
            let mut replayed = stored.response;
            replayed.request_identity = request.request_identity.clone();
            replayed
                .validate_for(&request)
                .map_err(map_durable_error)
                .map_err(AdapterError::Store)?;
            return Ok(replayed);
        }
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }

    // Resolve the single attempt for this job by scanning the caller's known
    // attempt space is impossible without an index; S1 leases the attempt
    // recorded under the submitted job id. The job row key needs the attempt,
    // so locate it via the submission attempt bound in the selector scope:
    // load candidates is out of scope for the exact edge, therefore the
    // caller must target a job whose attempt shares the job id namespace.
    // Practical S1 rule: the job row key uses the requested job id plus the
    // attempt recorded at submit time, discovered through the operation
    // history is unavailable, so require the job row to be addressable via a
    // bounded scan of the Dreamer namespace filtered in Rust.
    let candidate = find_job_for_lease(db, &adapter.config, job_id.as_str()).await?;
    let Some((row_key, job_row, mut ledger)) = candidate else {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    if ledger.record.submission.job_id.to_string() != job_id.to_string() {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if selector.expected_fence != ledger.record.submission.work_scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if selector.scope_id != ledger.record.submission.work_scope.scope_id {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if selector.expected_revision != ledger.record.revision {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    }
    if ledger.record.state != JobState::Queued {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    }
    if ledger.active_lease.is_some() || ledger.record.lease.is_some() {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    }
    let expected_outer = job_row.revision;

    let lease_value = format!("dreamer-{}", &sha256_hex(operation_id.as_bytes())[..40]);
    // `WorkLeaseId` has no string-issuance constructor by design; it is built
    // through its canonical wire shape so validation stays inside its owner.
    // The lease value is deterministic per operation id so an owner retry
    // replays the identical lease.
    let issued = now_unix_ms();
    let lease: JobLease = serde_json::from_value(serde_json::json!({
        "job_id": ledger.record.submission.job_id,
        "attempt_id": ledger.record.submission.attempt_id,
        "lease_id": {
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": lease_value,
        },
        "owner_artifact_id": selector.worker_artifact_id,
        "resource_generation": ledger.record.submission.work_scope.resource_generation,
        "state_fence": ledger.record.submission.work_scope.state_fence,
        "issued_at_unix_ms": issued,
        "expires_at_unix_ms": issued.saturating_add(LEASE_TTL_MS).max(issued + 1),
        "revision": FIRST_OUTER_REVISION,
    }))
    .map_err(|error| AdapterError::Serialization(error.to_string()))?;

    let attempt_id = ledger.record.submission.attempt_id.clone();
    let job_id_text = ledger.record.submission.job_id.to_string();
    let attempt_id_text = attempt_id.to_string();
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: selector.expected_revision,
        state: JobState::Leased,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: Some(lease.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: None,
        outcome: None,
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;

    // Advance the ledger: same inner revision (the lease edge keeps the K0
    // revision so the response still binds `expected_revision`), outer
    // revision plus cursor advance for CAS.
    ledger.record.state = JobState::Leased;
    ledger.record.lease = Some(lease.clone());
    ledger.event_cursor = ledger
        .event_cursor
        .saturating_add(1)
        .max(LEASE_OUTER_REVISION);
    ledger.active_lease = Some(lease.clone());
    ledger.last_mutation = mutation_identity(&request);
    ledger.last_receipt_id = Some(receipt_id.clone());
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;

    let cursor = ledger.event_cursor;
    let mut event = DreamerJobLedgerEvent {
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: attempt_id.clone(),
        prior_state: JobState::Queued,
        next_state: JobState::Leased,
        prior_revision: selector.expected_revision,
        next_revision: selector.expected_revision,
        event_cursor: cursor,
        operation: request.operation.clone(),
        role: request.role,
        lease: Some(lease.clone()),
        checkpoint: None,
        result_under_verification: None,
        mutation: mutation_identity(&request),
        receipt_id: Some(receipt_id.clone()),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    validate_ledger_bundle(&request, &response, &ledger, &event).map_err(AdapterError::Store)?;

    let stored = StoredMutation {
        operation_id: operation_id.clone(),
        idempotency_key: request.request_identity.operation.idempotency_key.clone(),
        canonical_request_hash: request.request_identity.canonical_request_hash.clone(),
        operation_kind: request.operation.kind().as_str().to_owned(),
        response: response.clone(),
    };
    let receipt_row = StoredReceipt {
        operation_id: operation_id.clone(),
        receipt_id: receipt_id.to_string(),
        job_id: job_id_text.clone(),
        attempt_id: attempt_id_text.clone(),
        revision: selector.expected_revision,
    };

    let fence = ledger.record.submission.work_scope.state_fence.clone();
    let new_outer = expected_outer.saturating_add(1).max(LEASE_OUTER_REVISION);
    let (job_payload, _) = encode_canonical(&ledger)?;
    let (event_payload, _) = encode_canonical(&event)?;
    let (op_payload, _) = encode_canonical(&stored)?;
    let (receipt_payload, _) = encode_canonical(&receipt_row)?;
    let new_job_row = build_recovery_row(
        row_key.clone(),
        &fence,
        new_outer,
        schema::dreamer::SCHEMA_LEDGER_RECORD,
        job_payload,
    )?;
    let event_row = build_recovery_row(
        dreamer_event_row_key(&job_id_text, &attempt_id_text, cursor),
        &fence,
        cursor,
        schema::dreamer::SCHEMA_LEDGER_EVENT,
        event_payload,
    )?;
    let op_row = build_recovery_row(
        op_key.clone(),
        &fence,
        cursor,
        schema::dreamer::SCHEMA_MUTATION,
        op_payload,
    )?;
    let receipt_record = build_recovery_row(
        dreamer_receipt_row_key(&operation_id),
        &fence,
        cursor,
        schema::dreamer::SCHEMA_RECEIPT,
        receipt_payload,
    )?;

    match cas_job_plus_three(
        db,
        &adapter.config,
        &operation_id,
        &new_job_row,
        &row_key,
        expected_outer,
        &fence,
        [&event_row, &op_row, &receipt_record],
    )
    .await
    {
        Ok(()) => Ok(response),
        Err(AdapterError::ProviderConflict) => {
            if let Some(existing) = read_dreamer_row(db, &adapter.config, &op_key).await? {
                let stored = decode_stored_mutation(&existing)?;
                if stored.canonical_request_hash == request.request_identity.canonical_request_hash
                    && stored.operation_kind == request.operation.kind().as_str()
                {
                    let mut replayed = stored.response;
                    replayed.request_identity = request.request_identity.clone();
                    replayed
                        .validate_for(&request)
                        .map_err(map_durable_error)
                        .map_err(AdapterError::Store)?;
                    return Ok(replayed);
                }
                return Err(AdapterError::Store(StoreError::IdentityConflict));
            }
            Err(AdapterError::Store(StoreError::RevisionConflict))
        }
        Err(error) => Err(error),
    }
}

async fn status(
    db: &client::RpcTransport,
    config: &crate::config::SurrealAdapterConfig,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::Status {
        job_id,
        attempt_id,
        expected_revision,
        expected_fence,
    } = &request.operation
    else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    let row_key = dreamer_job_row_key(&job_id.to_string(), &attempt_id.to_string());
    let Some(job_row) = read_dreamer_row(db, config, &row_key).await? else {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    let ledger = decode_ledger_record(&job_row)?;
    ledger.validate().map_err(AdapterError::Store)?;
    if ledger.record.submission.job_id.to_string() != job_id.to_string()
        || ledger.record.submission.attempt_id.to_string() != attempt_id.to_string()
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    if *expected_fence != ledger.record.submission.work_scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    if *expected_revision != ledger.record.revision {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    }
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: ledger.record.revision,
        state: ledger.record.state,
        disposition: None,
        receipt_id: None,
        lease: ledger.active_lease.clone(),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: ledger.result_under_verification.clone(),
        outcome: ledger.record.outcome.clone(),
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    Ok(response)
}

/// Maximum `LeaseNext` candidates observed in one selection page. It equals
/// the ledger history bound so one page can never overflow the record.
const MAX_LEASE_CANDIDATES: usize = MAX_DREAMER_JOB_HISTORY;
/// Bounded Dreamer namespace scan backing deterministic selection.
const JOB_SCAN_LIMIT: usize = 256;

/// Resolves one operation-idempotency row: exact hash/kind replay returns the
/// original outcome with fresh correlation swapped in, changed content under
/// the same identity conflicts, and absence yields `Ok(None)`.
async fn replay_or_conflict(
    db: &client::RpcTransport,
    config: &crate::config::SurrealAdapterConfig,
    op_key: &str,
    request: &DurableJobRequest,
) -> Result<Option<DurableJobResponse>, AdapterError> {
    let Some(existing) = read_dreamer_row(db, config, op_key).await? else {
        return Ok(None);
    };
    let stored = decode_stored_mutation(&existing)?;
    if stored.canonical_request_hash == request.request_identity.canonical_request_hash
        && stored.operation_kind == request.operation.kind().as_str()
    {
        let mut replayed = stored.response;
        replayed.request_identity = request.request_identity.clone();
        replayed
            .validate_for(request)
            .map_err(map_durable_error)
            .map_err(AdapterError::Store)?;
        return Ok(Some(replayed));
    }
    Err(AdapterError::Store(StoreError::IdentityConflict))
}

/// Loads and validates one job ledger by job/attempt identity; `Ok(None)`
/// when absent. Malformed provider rows fail closed, never repaired.
async fn load_ledger(
    db: &client::RpcTransport,
    config: &crate::config::SurrealAdapterConfig,
    job_id: &str,
    attempt_id: &str,
) -> Result<Option<(String, RecoveryRecord, DreamerJobLedgerRecord)>, AdapterError> {
    let row_key = dreamer_job_row_key(job_id, attempt_id);
    let Some(job_row) = read_dreamer_row(db, config, &row_key).await? else {
        return Ok(None);
    };
    if job_row.schema != schema::dreamer::SCHEMA_LEDGER_RECORD {
        return Err(AdapterError::Store(StoreError::InvalidField {
            field: "dreamer_job.schema",
            reason: "job row carries an unexpected schema",
        }));
    }
    let ledger = decode_ledger_record(&job_row)?;
    ledger.validate().map_err(AdapterError::Store)?;
    if ledger.record.submission.job_id.as_str() != job_id
        || ledger.record.submission.attempt_id.as_str() != attempt_id
    {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    Ok(Some((row_key, job_row, ledger)))
}

/// Scans the versioned Dreamer namespace in deterministic key order,
/// returning every valid job ledger. Malformed rows fail the scan closed.
async fn scan_ledgers(
    db: &client::RpcTransport,
    config: &crate::config::SurrealAdapterConfig,
) -> Result<Vec<(String, RecoveryRecord, DreamerJobLedgerRecord)>, AdapterError> {
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "dreamer_namespace".to_owned(),
        serde_json::Value::String(schema::dreamer::NAMESPACE.to_owned()),
    );
    bindings.insert(
        "dreamer_limit".to_owned(),
        serde_json::Value::from(JOB_SCAN_LIMIT),
    );
    // Bounded scan ordered by key; filtering to the exact job happens in Rust
    // below so no substring match lives in the query string.
    let sql = "SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_job WHERE namespace = $dreamer_namespace ORDER BY key LIMIT $dreamer_limit;";
    let mut response = client::query(db, config, "dreamer.scan_jobs", sql, bindings).await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let rows: Vec<RecoveryRecord> = response.take(0)?;
    let mut ledgers = Vec::new();
    for row in rows {
        row.validate().map_err(AdapterError::Store)?;
        if row.namespace != schema::dreamer::NAMESPACE {
            continue;
        }
        if !row.key.starts_with(schema::dreamer::KEY_JOB_PREFIX) {
            continue;
        }
        if row.schema != schema::dreamer::SCHEMA_LEDGER_RECORD {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "dreamer_job.schema",
                reason: "job row carries an unexpected schema",
            }));
        }
        let ledger = decode_ledger_record(&row)?;
        ledger.validate().map_err(AdapterError::Store)?;
        ledgers.push((row.key.clone(), row, ledger));
    }
    Ok(ledgers)
}

/// Requires the presented lease to be the exact active owner. A superseded,
/// revoked, foreign, or absent lease is deterministic not-applied, never a
/// revival. Lease-window validity itself is enforced by K0 against the
/// server-issued window, not by a caller-chosen clock.
fn require_active_lease(
    ledger: &DreamerJobLedgerRecord,
    lease: &JobLease,
) -> Result<(), AdapterError> {
    match &ledger.active_lease {
        Some(active) if active == lease => Ok(()),
        _ => Err(AdapterError::Store(StoreError::RevisionConflict)),
    }
}

/// Issues one deterministic lease binding for an operation identity: the lease
/// value derives from the operation id so an owner retry replays the identical
/// lease, while issuance/owner evidence comes from the admitted selector and
/// the provider-observed clock.
fn issue_lease(
    operation_id: &str,
    ledger: &DreamerJobLedgerRecord,
    selector: &LeaseSelector,
) -> Result<JobLease, AdapterError> {
    let lease_value = format!("dreamer-{}", &sha256_hex(operation_id.as_bytes())[..40]);
    let issued = now_unix_ms();
    serde_json::from_value(serde_json::json!({
        "job_id": ledger.record.submission.job_id,
        "attempt_id": ledger.record.submission.attempt_id,
        "lease_id": {
            "namespace": "eliot.governor.work-lease",
            "revision": "v1",
            "value": lease_value,
        },
        "owner_artifact_id": selector.worker_artifact_id,
        "resource_generation": ledger.record.submission.work_scope.resource_generation,
        "state_fence": ledger.record.submission.work_scope.state_fence,
        "issued_at_unix_ms": issued,
        "expires_at_unix_ms": issued.saturating_add(LEASE_TTL_MS).max(issued + 1),
        "revision": FIRST_OUTER_REVISION,
    }))
    .map_err(|error| AdapterError::Serialization(error.to_string()))
}

/// Commits one validated ledger mutation: the job row swaps via outer-revision
/// CAS while its event, operation-idempotency and receipt rows create in the
/// same provider transaction. A CAS loser re-reads to classify exact replay
/// versus stale conflict; any other provider error stays unknown-outcome.
#[allow(clippy::too_many_arguments)]
async fn commit_ledger_mutation(
    db: &client::RpcTransport,
    config: &crate::config::SurrealAdapterConfig,
    request: &DurableJobRequest,
    row_key: &str,
    expected_outer: u64,
    ledger: &DreamerJobLedgerRecord,
    event: &DreamerJobLedgerEvent,
    response: DurableJobResponse,
) -> Result<DurableJobResponse, AdapterError> {
    validate_ledger_bundle(request, &response, ledger, event).map_err(AdapterError::Store)?;
    let operation_id = request
        .request_identity
        .operation
        .operation_id
        .to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    let stored = StoredMutation {
        operation_id: operation_id.clone(),
        idempotency_key: request
            .request_identity
            .operation
            .idempotency_key
            .clone(),
        canonical_request_hash: request.request_identity.canonical_request_hash.clone(),
        operation_kind: request.operation.kind().as_str().to_owned(),
        response: response.clone(),
    };
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;
    let receipt_row = StoredReceipt {
        operation_id: operation_id.clone(),
        receipt_id: receipt_id.to_string(),
        job_id: ledger.record.submission.job_id.to_string(),
        attempt_id: ledger.record.submission.attempt_id.to_string(),
        revision: response.revision,
    };
    let fence = ledger
        .record
        .submission
        .work_scope
        .state_fence
        .clone();
    let new_outer = expected_outer.saturating_add(1);
    let cursor = ledger.event_cursor;
    let (job_payload, _) = encode_canonical(ledger)?;
    let (event_payload, _) = encode_canonical(event)?;
    let (op_payload, _) = encode_canonical(&stored)?;
    let (receipt_payload, _) = encode_canonical(&receipt_row)?;
    let new_job_row = build_recovery_row(
        row_key.to_owned(),
        &fence,
        new_outer,
        schema::dreamer::SCHEMA_LEDGER_RECORD,
        job_payload,
    )?;
    let event_row = build_recovery_row(
        dreamer_event_row_key(
            &ledger.record.submission.job_id.to_string(),
            &ledger.record.submission.attempt_id.to_string(),
            cursor,
        ),
        &fence,
        cursor,
        schema::dreamer::SCHEMA_LEDGER_EVENT,
        event_payload,
    )?;
    let op_row = build_recovery_row(
        op_key.clone(),
        &fence,
        cursor,
        schema::dreamer::SCHEMA_MUTATION,
        op_payload,
    )?;
    let receipt_record = build_recovery_row(
        dreamer_receipt_row_key(&operation_id),
        &fence,
        cursor,
        schema::dreamer::SCHEMA_RECEIPT,
        receipt_payload,
    )?;
    match cas_job_plus_three(
        db,
        config,
        &operation_id,
        &new_job_row,
        row_key,
        expected_outer,
        &fence,
        [&event_row, &op_row, &receipt_record],
    )
    .await
    {
        Ok(()) => Ok(response),
        Err(AdapterError::ProviderConflict) => match replay_or_conflict(db, config, &op_key, request)
            .await?
        {
            Some(replayed) => Ok(replayed),
            None => Err(AdapterError::Store(StoreError::RevisionConflict)),
        },
        Err(error) => Err(error),
    }
}

/// Advances one ledger cursor for a new mutation, returning the cursor.
fn advance_cursor(ledger: &mut DreamerJobLedgerRecord) -> u64 {
    ledger.event_cursor = ledger.event_cursor.saturating_add(1).max(1);
    ledger.event_cursor
}

#[allow(clippy::too_many_lines)]
async fn op_lease_next(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::LeaseNext { selector } = &request.operation else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if request.role != JobRole::Worker {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    if usize::try_from(selector.max_candidates).unwrap_or(usize::MAX) > MAX_LEASE_CANDIDATES {
        return Err(AdapterError::Store(StoreError::PayloadTooLarge));
    }
    let operation_id = request
        .request_identity
        .operation
        .operation_id
        .to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    if let Some(replayed) = replay_or_conflict(db, &adapter.config, &op_key, &request).await? {
        return Ok(replayed);
    }
    let ledgers = scan_ledgers(db, &adapter.config).await?;
    let mut scoped: Vec<&(String, RecoveryRecord, DreamerJobLedgerRecord)> = ledgers
        .iter()
        .filter(|(_, _, ledger)| {
            ledger.record.submission.work_scope.scope_id == selector.scope_id
                && ledger.record.submission.work_scope.state_fence == selector.expected_fence
        })
        .collect();
    scoped.sort_by(|left, right| left.0.cmp(&right.0));
    if scoped.is_empty() {
        // Complete-empty selection is distinct from stale, partial, and
        // unavailable: no candidate exists in this scope and fence.
        return Err(AdapterError::Store(StoreError::Empty {
            field: "dreamer_job.selection",
        }));
    }
    let coverage: Vec<String> = scoped
        .iter()
        .take(
            usize::try_from(selector.max_candidates).unwrap_or(usize::MAX),
        )
        .map(|(_, _, ledger)| ledger.record.submission.job_id.to_string())
        .collect();
    let Some((row_key, job_row, mut ledger)) = scoped
        .iter()
        .find(|(_, _, ledger)| {
            ledger.record.state == JobState::Queued
                && ledger.record.revision == selector.expected_revision
                && ledger.active_lease.is_none()
                && ledger.record.lease.is_none()
        })
        .map(|(row_key, job_row, ledger)| (row_key.clone(), job_row.clone(), ledger.clone()))
    else {
        // Candidates exist but none is leasable at the expected revision:
        // exhausted or stale, deterministically not-applied.
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    let expected_outer = job_row.revision;
    let lease = issue_lease(&operation_id, &ledger, selector)?;
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: selector.expected_revision,
        state: JobState::Leased,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: Some(lease.clone()),
        checkpoint: None,
        result_under_verification: None,
        outcome: None,
        selection_coverage: coverage,
        selection_frontier: Some(ledger.queue_key.clone()),
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;
    ledger.record.state = JobState::Leased;
    ledger.record.lease = Some(lease.clone());
    advance_cursor(&mut ledger);
    ledger.active_lease = Some(lease.clone());
    ledger.last_mutation = mutation_identity(&request);
    ledger.last_receipt_id = Some(receipt_id.clone());
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;
    let cursor = ledger.event_cursor;
    let mut event = DreamerJobLedgerEvent {
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        prior_state: JobState::Queued,
        next_state: JobState::Leased,
        prior_revision: selector.expected_revision,
        next_revision: selector.expected_revision,
        event_cursor: cursor,
        operation: request.operation.clone(),
        role: request.role,
        lease: Some(lease),
        checkpoint: None,
        result_under_verification: None,
        mutation: mutation_identity(&request),
        receipt_id: Some(receipt_id),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    commit_ledger_mutation(
        db,
        &adapter.config,
        &request,
        &row_key,
        expected_outer,
        &ledger,
        &event,
        response,
    )
    .await
}

async fn op_renew(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::Renew { lease, now_unix_ms } = &request.operation else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if request.role != JobRole::Worker {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let operation_id = request
        .request_identity
        .operation
        .operation_id
        .to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    if let Some(replayed) = replay_or_conflict(db, &adapter.config, &op_key, &request).await? {
        return Ok(replayed);
    }
    let Some((row_key, job_row, mut ledger)) = load_ledger(
        db,
        &adapter.config,
        &lease.job_id.to_string(),
        &lease.attempt_id.to_string(),
    )
    .await?
    else {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    if lease.state_fence != ledger.record.submission.work_scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    require_active_lease(&ledger, lease)?;
    // Renewal extends only the expiry from the accepted observation time; it
    // cannot change owner, route, budget, or resurrect superseded ownership.
    let mut renewed = lease.clone();
    renewed.expires_at_unix_ms = now_unix_ms.saturating_add(LEASE_TTL_MS).max(*now_unix_ms);
    renewed
        .validate_active_at(*now_unix_ms)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let expected_outer = job_row.revision;
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: ledger.record.revision,
        state: ledger.record.state,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: Some(renewed.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: ledger.result_under_verification.clone(),
        outcome: ledger.record.outcome.clone(),
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;
    let prior_state = ledger.record.state;
    let prior_revision = ledger.record.revision;
    ledger.record.lease = Some(renewed.clone());
    advance_cursor(&mut ledger);
    ledger.active_lease = Some(renewed.clone());
    ledger.last_mutation = mutation_identity(&request);
    ledger.last_receipt_id = Some(receipt_id.clone());
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;
    let cursor = ledger.event_cursor;
    let mut event = DreamerJobLedgerEvent {
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        prior_state,
        next_state: prior_state,
        prior_revision,
        next_revision: prior_revision,
        event_cursor: cursor,
        operation: request.operation.clone(),
        role: request.role,
        lease: Some(renewed),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: ledger.result_under_verification.clone(),
        mutation: mutation_identity(&request),
        receipt_id: Some(receipt_id),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    commit_ledger_mutation(
        db,
        &adapter.config,
        &request,
        &row_key,
        expected_outer,
        &ledger,
        &event,
        response,
    )
    .await
}

async fn op_start(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::Start { lease, .. } = &request.operation else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if request.role != JobRole::Worker {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let operation_id = request
        .request_identity
        .operation
        .operation_id
        .to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    if let Some(replayed) = replay_or_conflict(db, &adapter.config, &op_key, &request).await? {
        return Ok(replayed);
    }
    let Some((row_key, job_row, mut ledger)) = load_ledger(
        db,
        &adapter.config,
        &lease.job_id.to_string(),
        &lease.attempt_id.to_string(),
    )
    .await?
    else {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    if lease.state_fence != ledger.record.submission.work_scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    require_active_lease(&ledger, lease)?;
    let expected_outer = job_row.revision;
    let prior_state = ledger.record.state;
    let prior_revision = ledger.record.revision;
    ledger
        .record
        .transition(JobState::Running)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: ledger.record.revision,
        state: JobState::Running,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: Some(lease.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: None,
        outcome: None,
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;
    advance_cursor(&mut ledger);
    ledger.last_mutation = mutation_identity(&request);
    ledger.last_receipt_id = Some(receipt_id.clone());
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;
    let cursor = ledger.event_cursor;
    let mut event = DreamerJobLedgerEvent {
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        prior_state,
        next_state: JobState::Running,
        prior_revision,
        next_revision: ledger.record.revision,
        event_cursor: cursor,
        operation: request.operation.clone(),
        role: request.role,
        lease: Some(lease.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: None,
        mutation: mutation_identity(&request),
        receipt_id: Some(receipt_id),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    commit_ledger_mutation(
        db,
        &adapter.config,
        &request,
        &row_key,
        expected_outer,
        &ledger,
        &event,
        response,
    )
    .await
}

/// Locates the single job row for a `LeaseExact` request.
///
/// S1 jobs are addressed by job id; the attempt is the one recorded at
/// submit time. The Dreamer namespace is scanned in Rust (bounded by the
/// recovery packet limits) and filtered to the exact `job:` key family plus
/// job id, so selection stays deterministic without a new index.
async fn find_job_for_lease(
    db: &client::RpcTransport,
    config: &crate::config::SurrealAdapterConfig,
    job_id: &str,
) -> Result<Option<(String, RecoveryRecord, DreamerJobLedgerRecord)>, AdapterError> {
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "dreamer_namespace".to_owned(),
        serde_json::Value::String(schema::dreamer::NAMESPACE.to_owned()),
    );
    // Bounded scan of the versioned Dreamer namespace; filtering to the exact
    // job happens in Rust below so no substring match in the query string.
    // Ordered by key so multi-attempt first-match selection stays
    // deterministic (full bounded selection belongs to a later slice).
    let sql = "SELECT VALUE { namespace: namespace, key: key, state_fence: state_fence, revision: revision, schema: schema, payload: payload, value_digest: value_digest } FROM recovery_job WHERE namespace = $dreamer_namespace ORDER BY key LIMIT 256;";
    let mut response = client::query(db, config, "dreamer.scan_jobs", sql, bindings).await?;
    if !response.take_errors().is_empty() {
        return Err(AdapterError::PartialOutcome);
    }
    let rows: Vec<RecoveryRecord> = response.take(0)?;
    for row in rows {
        row.validate().map_err(AdapterError::Store)?;
        if row.namespace != schema::dreamer::NAMESPACE {
            continue;
        }
        if !row.key.starts_with(schema::dreamer::KEY_JOB_PREFIX) {
            continue;
        }
        if row.schema != schema::dreamer::SCHEMA_LEDGER_RECORD {
            return Err(AdapterError::Store(StoreError::InvalidField {
                field: "dreamer_job.schema",
                reason: "job row carries an unexpected schema",
            }));
        }
        // Match on the decoded submission identity, never by parsing the
        // opaque key: identifier charsets stay unrestricted.
        let ledger = decode_ledger_record(&row)?;
        if ledger.record.submission.job_id.as_str() != job_id {
            continue;
        }
        return Ok(Some((row.key.clone(), row, ledger)));
    }
    Ok(None)
}

#[allow(clippy::too_many_lines)]
async fn op_checkpoint(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::Checkpoint {
        lease, checkpoint, ..
    } = &request.operation
    else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if request.role != JobRole::Worker {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let operation_id = request
        .request_identity
        .operation
        .operation_id
        .to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    if let Some(replayed) = replay_or_conflict(db, &adapter.config, &op_key, &request).await? {
        return Ok(replayed);
    }
    let Some((row_key, job_row, mut ledger)) = load_ledger(
        db,
        &adapter.config,
        &lease.job_id.to_string(),
        &lease.attempt_id.to_string(),
    )
    .await?
    else {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    if lease.state_fence != ledger.record.submission.work_scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    require_active_lease(&ledger, lease)?;
    let expected_outer = job_row.revision;
    let prior_state = ledger.record.state;
    let prior_revision = ledger.record.revision;
    ledger
        .record
        .transition(JobState::Checkpointed)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    ledger.record.checkpoint = Some(checkpoint.as_ref().clone());
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: ledger.record.revision,
        state: JobState::Checkpointed,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: Some(lease.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: None,
        outcome: None,
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;
    advance_cursor(&mut ledger);
    ledger.last_mutation = mutation_identity(&request);
    ledger.last_receipt_id = Some(receipt_id.clone());
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;
    let cursor = ledger.event_cursor;
    let mut event = DreamerJobLedgerEvent {
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        prior_state,
        next_state: JobState::Checkpointed,
        prior_revision,
        next_revision: ledger.record.revision,
        event_cursor: cursor,
        operation: request.operation.clone(),
        role: request.role,
        lease: Some(lease.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: None,
        mutation: mutation_identity(&request),
        receipt_id: Some(receipt_id),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    commit_ledger_mutation(
        db,
        &adapter.config,
        &request,
        &row_key,
        expected_outer,
        &ledger,
        &event,
        response,
    )
    .await
}

async fn op_resume(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::Resume {
        lease, checkpoint, ..
    } = &request.operation
    else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if request.role != JobRole::Worker {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let operation_id = request
        .request_identity
        .operation
        .operation_id
        .to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    if let Some(replayed) = replay_or_conflict(db, &adapter.config, &op_key, &request).await? {
        return Ok(replayed);
    }
    let Some((row_key, job_row, mut ledger)) = load_ledger(
        db,
        &adapter.config,
        &lease.job_id.to_string(),
        &lease.attempt_id.to_string(),
    )
    .await?
    else {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    if lease.state_fence != ledger.record.submission.work_scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    require_active_lease(&ledger, lease)?;
    // Resume binds the exact stored checkpoint; a different checkpoint under
    // the same identity is a conflict, never a silent substitution.
    if ledger.record.checkpoint.as_ref() != Some(checkpoint.as_ref()) {
        return Err(AdapterError::Store(StoreError::IdentityConflict));
    }
    let expected_outer = job_row.revision;
    let prior_state = ledger.record.state;
    let prior_revision = ledger.record.revision;
    ledger
        .record
        .transition(JobState::Running)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: ledger.record.revision,
        state: JobState::Running,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: Some(lease.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: None,
        outcome: None,
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;
    advance_cursor(&mut ledger);
    ledger.last_mutation = mutation_identity(&request);
    ledger.last_receipt_id = Some(receipt_id.clone());
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;
    let cursor = ledger.event_cursor;
    let mut event = DreamerJobLedgerEvent {
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        prior_state,
        next_state: JobState::Running,
        prior_revision,
        next_revision: ledger.record.revision,
        event_cursor: cursor,
        operation: request.operation.clone(),
        role: request.role,
        lease: Some(lease.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: None,
        mutation: mutation_identity(&request),
        receipt_id: Some(receipt_id),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    commit_ledger_mutation(
        db,
        &adapter.config,
        &request,
        &row_key,
        expected_outer,
        &ledger,
        &event,
        response,
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn op_begin_verification(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::BeginVerification { lease, result, .. } = &request.operation else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if request.role != JobRole::Worker {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let operation_id = request
        .request_identity
        .operation
        .operation_id
        .to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    if let Some(replayed) = replay_or_conflict(db, &adapter.config, &op_key, &request).await? {
        return Ok(replayed);
    }
    let Some((row_key, job_row, mut ledger)) = load_ledger(
        db,
        &adapter.config,
        &lease.job_id.to_string(),
        &lease.attempt_id.to_string(),
    )
    .await?
    else {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    if lease.state_fence != ledger.record.submission.work_scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    require_active_lease(&ledger, lease)?;
    let expected_outer = job_row.revision;
    let prior_state = ledger.record.state;
    let prior_revision = ledger.record.revision;
    // Only a checkpointed job may enter verification: publishing a terminal
    // candidate directly from running is an illegal transition, and the
    // result-under-verification is never itself a terminal outcome.
    ledger
        .record
        .transition(JobState::Verifying)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    ledger.result_under_verification = Some(result.as_ref().clone());
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: ledger.record.revision,
        state: JobState::Verifying,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: Some(lease.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: ledger.result_under_verification.clone(),
        outcome: None,
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;
    advance_cursor(&mut ledger);
    ledger.last_mutation = mutation_identity(&request);
    ledger.last_receipt_id = Some(receipt_id.clone());
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;
    let cursor = ledger.event_cursor;
    let mut event = DreamerJobLedgerEvent {
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        prior_state,
        next_state: JobState::Verifying,
        prior_revision,
        next_revision: ledger.record.revision,
        event_cursor: cursor,
        operation: request.operation.clone(),
        role: request.role,
        lease: Some(lease.clone()),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: ledger.result_under_verification.clone(),
        mutation: mutation_identity(&request),
        receipt_id: Some(receipt_id),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    commit_ledger_mutation(
        db,
        &adapter.config,
        &request,
        &row_key,
        expected_outer,
        &ledger,
        &event,
        response,
    )
    .await
}

#[allow(clippy::too_many_lines)]
async fn op_publish(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::Publish { lease, outcome, .. } = &request.operation else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    if request.role != JobRole::Worker {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    }
    let operation_id = request
        .request_identity
        .operation
        .operation_id
        .to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    if let Some(replayed) = replay_or_conflict(db, &adapter.config, &op_key, &request).await? {
        return Ok(replayed);
    }
    let Some((row_key, job_row, mut ledger)) = load_ledger(
        db,
        &adapter.config,
        &lease.job_id.to_string(),
        &lease.attempt_id.to_string(),
    )
    .await?
    else {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    if lease.state_fence != ledger.record.submission.work_scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    require_active_lease(&ledger, lease)?;
    let expected_outer = job_row.revision;
    let prior_state = ledger.record.state;
    let prior_revision = ledger.record.revision;
    // The closed K0 matrix decides the terminal edge: `Completed`/`Partial`
    // only from `Verifying`; `Failed`/`Cancelled`/`UnknownOutcome` from
    // `Running`, `Checkpointed`, or `Verifying`. Terminal history is immutable
    // afterwards. A committed semantic `UNKNOWN_OUTCOME` stays a stored job
    // result and never upgrades Store commit uncertainty.
    ledger
        .record
        .transition(outcome.state)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    ledger.record.outcome = Some(outcome.as_ref().clone());
    // Terminal publication releases active ownership while retaining the final
    // lease as history: terminal records carry no active lease.
    if let Some(active) = ledger.active_lease.take() {
        ledger.lease_history.push(active);
    }
    ledger.record.lease = None;
    ledger.result_under_verification = None;
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: ledger.record.revision,
        state: outcome.state,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: None,
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: None,
        outcome: ledger.record.outcome.clone(),
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;
    advance_cursor(&mut ledger);
    ledger.last_mutation = mutation_identity(&request);
    ledger.last_receipt_id = Some(receipt_id.clone());
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;
    let cursor = ledger.event_cursor;
    let mut event = DreamerJobLedgerEvent {
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        prior_state,
        next_state: outcome.state,
        prior_revision,
        next_revision: ledger.record.revision,
        event_cursor: cursor,
        operation: request.operation.clone(),
        role: request.role,
        lease: None,
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: None,
        mutation: mutation_identity(&request),
        receipt_id: Some(receipt_id),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    commit_ledger_mutation(
        db,
        &adapter.config,
        &request,
        &row_key,
        expected_outer,
        &ledger,
        &event,
        response,
    )
    .await
}

async fn op_request_cancel(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::RequestCancel {
        job_id,
        attempt_id,
        reason,
        requested_at_unix_ms,
        expected_fence,
    } = &request.operation
    else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    // Cancellation is requested by the requester or controller roles; the
    // recorded principal names the authenticated role class, never a
    // caller-supplied identity string.
    let principal = match request.role {
        JobRole::Requester => "requester",
        JobRole::Controller => "controller",
        JobRole::Worker => return Err(AdapterError::Store(StoreError::UnknownOperation)),
    };
    let operation_id = request
        .request_identity
        .operation
        .operation_id
        .to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    if let Some(replayed) = replay_or_conflict(db, &adapter.config, &op_key, &request).await? {
        return Ok(replayed);
    }
    let Some((row_key, job_row, mut ledger)) =
        load_ledger(db, &adapter.config, &job_id.to_string(), &attempt_id.to_string()).await?
    else {
        return Err(AdapterError::Store(StoreError::RevisionConflict));
    };
    if *expected_fence != ledger.record.submission.work_scope.state_fence {
        return Err(AdapterError::Store(StoreError::FenceMismatch));
    }
    let expected_outer = job_row.revision;
    let prior_state = ledger.record.state;
    let prior_revision = ledger.record.revision;
    // Records cancellation intent only: the job state is unchanged, so this is
    // never the terminal `CANCELLED` outcome. Terminal history rejects it.
    ledger
        .record
        .request_cancel(
            principal.to_owned(),
            reason.clone(),
            request.request_identity.operation.operation_id.clone(),
            *requested_at_unix_ms,
        )
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let response = DurableJobResponse {
        request_identity: request.request_identity.clone(),
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        scope: ledger.record.submission.work_scope.clone(),
        revision: ledger.record.revision,
        state: prior_state,
        disposition: Some(MutationDisposition::Committed),
        receipt_id: Some(validated_id(receipt_id_text(
            &request.request_identity.operation.operation_id,
        ))?),
        lease: ledger.active_lease.clone(),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: ledger.result_under_verification.clone(),
        outcome: None,
        selection_coverage: Vec::new(),
        selection_frontier: None,
    };
    response
        .validate_for(&request)
        .map_err(map_durable_error)
        .map_err(AdapterError::Store)?;
    let receipt_id = response
        .receipt_id
        .clone()
        .ok_or(AdapterError::Store(StoreError::InvalidReceipt))?;
    advance_cursor(&mut ledger);
    ledger.last_mutation = mutation_identity(&request);
    ledger.last_receipt_id = Some(receipt_id.clone());
    ledger.record_digest = ledger.compute_digest().map_err(AdapterError::Store)?;
    ledger.validate().map_err(AdapterError::Store)?;
    let cursor = ledger.event_cursor;
    let mut event = DreamerJobLedgerEvent {
        job_id: ledger.record.submission.job_id.clone(),
        attempt_id: ledger.record.submission.attempt_id.clone(),
        prior_state,
        next_state: prior_state,
        prior_revision,
        next_revision: ledger.record.revision,
        event_cursor: cursor,
        operation: request.operation.clone(),
        role: request.role,
        lease: ledger.active_lease.clone(),
        checkpoint: ledger.record.checkpoint.clone(),
        result_under_verification: ledger.result_under_verification.clone(),
        mutation: mutation_identity(&request),
        receipt_id: Some(receipt_id),
        event_digest: "0".repeat(64),
    };
    event.event_digest = event.compute_digest().map_err(AdapterError::Store)?;
    event.validate().map_err(AdapterError::Store)?;
    commit_ledger_mutation(
        db,
        &adapter.config,
        &request,
        &row_key,
        expected_outer,
        &ledger,
        &event,
        response,
    )
    .await
}

/// Reconciles one mutation by exact operation identity. This is a pure
/// observation: it never mutates the ledger, never replays a commit, and never
/// authorizes a retry. A stored operation with matching hash proves the
/// commit; only an independently proven absence (no operation row, hence the
/// atomic commit never ran) may answer not-applied; anything unbindable stays
/// `MissingReceiptEnvelope` still-unknown. A missing or mismatched receipt is
/// never committed success.
async fn op_reconcile(
    adapter: &SurrealStoreAdapter,
    db: &client::RpcTransport,
    _ctx: &RequestMeta,
    request: DurableJobRequest,
) -> Result<DurableJobResponse, AdapterError> {
    let JobOperation::Reconcile { mutation } = &request.operation else {
        return Err(AdapterError::Store(StoreError::UnknownOperation));
    };
    // Every role may reconcile; K0 already enforced the permission.
    let operation_id = mutation.operation.operation_id.to_string();
    let op_key = dreamer_operation_row_key(&operation_id);
    let existing = read_dreamer_row(db, &adapter.config, &op_key).await?;
    match existing {
        Some(op_row) => {
            let stored = decode_stored_mutation(&op_row)?;
            if stored.canonical_request_hash != mutation.canonical_request_hash
                || stored.operation_kind != mutation.operation.operation_kind
            {
                return Err(AdapterError::Store(StoreError::IdentityConflict));
            }
            if mutation.disposition != MutationDisposition::Committed {
                // The operation provably committed; a contrary claim conflicts
                // instead of rewriting history.
                return Err(AdapterError::Store(StoreError::IdentityConflict));
            }
            let Some((_, _, ledger)) = load_ledger(
                db,
                &adapter.config,
                &mutation.job_id.to_string(),
                &mutation.attempt_id.to_string(),
            )
            .await?
            else {
                return Err(AdapterError::Store(StoreError::InvalidReceipt));
            };
            if mutation.operation.state_fence != ledger.record.submission.work_scope.state_fence {
                return Err(AdapterError::Store(StoreError::FenceMismatch));
            }
            if mutation.committed_state != Some(ledger.record.state)
                || mutation.receipt_id != ledger.last_receipt_id
            {
                return Err(AdapterError::Store(StoreError::InvalidReceipt));
            }
            let response = DurableJobResponse {
                request_identity: request.request_identity.clone(),
                job_id: ledger.record.submission.job_id.clone(),
                attempt_id: ledger.record.submission.attempt_id.clone(),
                scope: ledger.record.submission.work_scope.clone(),
                revision: ledger.record.revision,
                state: ledger.record.state,
                disposition: Some(MutationDisposition::Committed),
                receipt_id: ledger.last_receipt_id.clone(),
                lease: ledger.active_lease.clone(),
                checkpoint: ledger.record.checkpoint.clone(),
                result_under_verification: ledger.result_under_verification.clone(),
                outcome: ledger.record.outcome.clone(),
                selection_coverage: Vec::new(),
                selection_frontier: None,
            };
            response
                .validate_for(&request)
                .map_err(map_durable_error)
                .map_err(AdapterError::Store)?;
            Ok(response)
        }
        None => {
            if mutation.disposition == MutationDisposition::Committed {
                // No operation row, no receipt: not committed success.
                return Err(AdapterError::Store(StoreError::InvalidReceipt));
            }
            let Some((_, _, ledger)) = load_ledger(
                db,
                &adapter.config,
                &mutation.job_id.to_string(),
                &mutation.attempt_id.to_string(),
            )
            .await?
            else {
                // Nothing to bind scope or revision to: honestly still-unknown
                // rather than a fabricated not-applied answer.
                return Err(AdapterError::Store(StoreError::MissingReceiptEnvelope));
            };
            if mutation.operation.state_fence != ledger.record.submission.work_scope.state_fence {
                return Err(AdapterError::Store(StoreError::FenceMismatch));
            }
            // Proven absence: the atomic commit always writes the operation
            // row, so its absence proves this mutation never applied. The
            // current record binds scope and revision without changing it.
            let response = DurableJobResponse {
                request_identity: request.request_identity.clone(),
                job_id: ledger.record.submission.job_id.clone(),
                attempt_id: ledger.record.submission.attempt_id.clone(),
                scope: ledger.record.submission.work_scope.clone(),
                revision: ledger.record.revision,
                state: ledger.record.state,
                disposition: Some(mutation.disposition),
                receipt_id: None,
                lease: ledger.active_lease.clone(),
                checkpoint: ledger.record.checkpoint.clone(),
                result_under_verification: ledger.result_under_verification.clone(),
                outcome: ledger.record.outcome.clone(),
                selection_coverage: Vec::new(),
                selection_frontier: None,
            };
            response
                .validate_for(&request)
                .map_err(map_durable_error)
                .map_err(AdapterError::Store)?;
            Ok(response)
        }
    }
}

/// Commits four Dreamer rows (job, event, operation, receipt) in one provider
/// transaction via insert-if-absent creates.
async fn commit_four(
    db: &client::RpcTransport,
    config: &crate::config::SurrealAdapterConfig,
    operation_id: &str,
    rows: [&RecoveryRecord; 4],
) -> Result<(), AdapterError> {
    let mut sql = String::from(schema::TX_BEGIN);
    let mut bindings = serde_json::Map::new();
    bindings.insert(
        "dreamer_table0".to_owned(),
        serde_json::Value::String(schema::table::RECOVERY_JOB.to_owned()),
    );
    for (index, row) in rows.iter().enumerate() {
        let suffix = index.to_string();
        let template = schema::indexed(schema::TX_DREAMER_CREATE, index);
        sql.push_str(&template);
        bindings.insert(
            format!("dreamer_table{suffix}"),
            serde_json::Value::String(schema::table::RECOVERY_JOB.to_owned()),
        );
        bindings.insert(
            format!("dreamer_id{suffix}"),
            serde_json::Value::String(dreamer_record_id(&row.namespace, &row.key)?),
        );
        bindings.insert(
            format!("dreamer_record{suffix}"),
            serde_json::to_value(row)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?,
        );
    }
    sql.push_str(schema::TX_COMMIT);
    let mut response = match client::query(db, config, "dreamer.submit", &sql, bindings).await {
        Ok(response) => response,
        Err(AdapterError::ProviderUnavailable) => {
            return Err(AdapterError::UnknownOutcome {
                operation_id: operation_id.to_owned(),
            });
        }
        Err(error) => return Err(error),
    };
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(());
    }
    if errors
        .iter()
        .any(|error| client::is_dreamer_conflict(error))
    {
        return Err(AdapterError::ProviderConflict);
    }
    Err(AdapterError::UnknownOutcome {
        operation_id: operation_id.to_owned(),
    })
}

/// Atomically swaps one job row via outer-revision CAS while creating its
/// three companion rows (event, operation, receipt) in the same transaction.
#[allow(clippy::too_many_arguments)]
async fn cas_job_plus_three(
    db: &client::RpcTransport,
    config: &crate::config::SurrealAdapterConfig,
    operation_id: &str,
    new_job: &RecoveryRecord,
    job_key: &str,
    expected_outer: u64,
    fence: &StateFence,
    rows: [&RecoveryRecord; 3],
) -> Result<(), AdapterError> {
    let mut sql = String::from(schema::TX_BEGIN);
    let mut bindings = serde_json::Map::new();
    sql.push_str(&schema::indexed(schema::TX_DREAMER_CAS_JOB, 0));
    bindings.insert(
        "dreamer_table0".to_owned(),
        serde_json::Value::String(schema::table::RECOVERY_JOB.to_owned()),
    );
    bindings.insert(
        "dreamer_id0".to_owned(),
        serde_json::Value::String(dreamer_record_id(&new_job.namespace, job_key)?),
    );
    bindings.insert(
        "dreamer_record0".to_owned(),
        serde_json::to_value(new_job)
            .map_err(|error| AdapterError::Serialization(error.to_string()))?,
    );
    bindings.insert(
        "dreamer_namespace0".to_owned(),
        serde_json::Value::String(schema::dreamer::NAMESPACE.to_owned()),
    );
    bindings.insert(
        "dreamer_key0".to_owned(),
        serde_json::Value::String(job_key.to_owned()),
    );
    bindings.insert(
        "dreamer_expected_revision0".to_owned(),
        serde_json::Value::from(expected_outer),
    );
    bindings.insert(
        "dreamer_expected_fence0".to_owned(),
        serde_json::to_value(fence)
            .map_err(|error| AdapterError::Serialization(error.to_string()))?,
    );
    for (offset, row) in rows.iter().enumerate() {
        let index = offset + 1;
        sql.push_str(&schema::indexed(schema::TX_DREAMER_CREATE, index));
        let suffix = index.to_string();
        bindings.insert(
            format!("dreamer_table{suffix}"),
            serde_json::Value::String(schema::table::RECOVERY_JOB.to_owned()),
        );
        bindings.insert(
            format!("dreamer_id{suffix}"),
            serde_json::Value::String(dreamer_record_id(&row.namespace, &row.key)?),
        );
        bindings.insert(
            format!("dreamer_record{suffix}"),
            serde_json::to_value(row)
                .map_err(|error| AdapterError::Serialization(error.to_string()))?,
        );
    }
    sql.push_str(schema::TX_COMMIT);
    let mut response = match client::query(db, config, "dreamer.lease_exact", &sql, bindings).await
    {
        Ok(response) => response,
        Err(AdapterError::ProviderUnavailable) => {
            return Err(AdapterError::UnknownOutcome {
                operation_id: operation_id.to_owned(),
            });
        }
        Err(error) => return Err(error),
    };
    let errors = response.take_errors();
    if errors.is_empty() {
        return Ok(());
    }
    if errors
        .iter()
        .any(|error| client::is_dreamer_conflict(error))
    {
        return Err(AdapterError::ProviderConflict);
    }
    Err(AdapterError::UnknownOutcome {
        operation_id: operation_id.to_owned(),
    })
}

/// Full capability denominator: every closed K0 operation is implemented and
/// advertised. The match is exhaustive (no wildcard) so a future thirteenth
/// operation variant fails the build instead of silently defaulting.
#[must_use]
pub(crate) fn is_supported_operation(operation: &JobOperation) -> bool {
    matches!(
        operation,
        JobOperation::Submit { .. }
            | JobOperation::LeaseNext { .. }
            | JobOperation::LeaseExact { .. }
            | JobOperation::Renew { .. }
            | JobOperation::Start { .. }
            | JobOperation::Checkpoint { .. }
            | JobOperation::Resume { .. }
            | JobOperation::BeginVerification { .. }
            | JobOperation::Publish { .. }
            | JobOperation::Status { .. }
            | JobOperation::RequestCancel { .. }
            | JobOperation::Reconcile { .. }
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn dreamer_keys_are_namespaced_and_discriminated() {
        // `TEMP-DEBUG-T12-02`: colon-free bisect expectations.
        assert_eq!(
            dreamer_job_row_key("job-1", "attempt-1"),
            "job_job-1_attempt-1"
        );
        assert_eq!(
            dreamer_event_row_key("job-1", "attempt-1", 2),
            "event_job-1_attempt-1_0000000000000002"
        );
        assert_eq!(dreamer_operation_row_key("op-1"), "op_op-1");
        assert_eq!(dreamer_receipt_row_key("op-1"), "receipt_op-1");
        assert_eq!(schema::dreamer::NAMESPACE, "dreamer-job-v1");
        // All four families share one namespace but never collide on keys.
        let keys = [
            dreamer_job_row_key("a", "b"),
            dreamer_event_row_key("a", "b", 1),
            dreamer_operation_row_key("a"),
            dreamer_receipt_row_key("a"),
        ];
        let mut sorted = keys.to_vec();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 4);
    }

    #[test]
    fn dreamer_record_ids_are_deterministic() {
        let first = dreamer_record_id("dreamer-job-v1", "job:a:b").expect("id");
        let second = dreamer_record_id("dreamer-job-v1", "job:a:b").expect("id");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        let other = dreamer_record_id("dreamer-job-v1", "op:a").expect("id");
        assert_ne!(first, other);
    }

    #[test]
    fn supported_operations_cover_the_closed_twelve() {
        // Deserialization only: support is a kind denominator, not validity.
        let lease = serde_json::to_value(test_lease()).expect("lease json");
        let fence = serde_json::to_value(test_fence()).expect("fence json");
        let operations: Vec<JobOperation> = vec![
            serde_json::from_value(serde_json::json!({
                "operation": "SUBMIT_JOB",
                "submission": serde_json::to_value(test_submission()).expect("submission json"),
            }))
            .expect("submit"),
            serde_json::from_value(serde_json::json!({
                "operation": "LEASE_NEXT",
                "selector": test_selector_json(),
            }))
            .expect("lease next"),
            serde_json::from_value(serde_json::json!({
                "operation": "LEASE_EXACT",
                "selector": test_selector_json(),
                "job_id": "job",
            }))
            .expect("lease exact"),
            serde_json::from_value(serde_json::json!({
                "operation": "RENEW_LEASE",
                "lease": lease,
                "observed_at_unix_ms": 50,
            }))
            .expect("renew"),
            serde_json::from_value(serde_json::json!({
                "operation": "START_JOB",
                "lease": lease,
                "observed_at_unix_ms": 50,
            }))
            .expect("start"),
            serde_json::from_value(serde_json::json!({
                "operation": "CHECKPOINT_JOB",
                "lease": lease,
                "checkpoint": test_checkpoint_json(),
                "observed_at_unix_ms": 50,
            }))
            .expect("checkpoint"),
            serde_json::from_value(serde_json::json!({
                "operation": "RESUME_JOB",
                "lease": lease,
                "checkpoint": test_checkpoint_json(),
                "observed_at_unix_ms": 50,
            }))
            .expect("resume"),
            serde_json::from_value(serde_json::json!({
                "operation": "BEGIN_VERIFICATION",
                "lease": lease,
                "result": test_content_json("result"),
                "evidence": [test_artifact_json()],
                "observed_at_unix_ms": 50,
            }))
            .expect("begin verification"),
            serde_json::from_value(serde_json::json!({
                "operation": "PUBLISH_OUTCOME",
                "lease": lease,
                "outcome": test_outcome_json(),
                "observed_at_unix_ms": 50,
            }))
            .expect("publish"),
            serde_json::from_value(serde_json::json!({
                "operation": "STATUS",
                "job_id": "job",
                "attempt_id": "attempt",
                "expected_revision": 1,
                "expected_fence": fence,
            }))
            .expect("status"),
            serde_json::from_value(serde_json::json!({
                "operation": "REQUEST_CANCEL",
                "job_id": "job",
                "attempt_id": "attempt",
                "reason": "probe",
                "requested_at_unix_ms": 60,
                "expected_fence": fence,
            }))
            .expect("request cancel"),
            JobOperation::Reconcile {
                mutation: Box::new(test_reconciliation()),
            },
        ];
        assert_eq!(operations.len(), 12);
        for operation in &operations {
            assert!(
                is_supported_operation(operation),
                "operation kind is advertised: {}",
                operation.kind()
            );
        }
    }

    #[test]
    fn stored_receipt_round_trip_preserves_binding() {
        let receipt = StoredReceipt {
            operation_id: "op-1".to_owned(),
            receipt_id: "dreamer-receipt-op-1".to_owned(),
            job_id: "job".to_owned(),
            attempt_id: "attempt".to_owned(),
            revision: 1,
        };
        let bytes = serde_json::to_vec(&receipt).expect("encode");
        let decoded: StoredReceipt = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(decoded, receipt);
    }

    #[test]
    fn dreamer_conflict_classifier_covers_cas_and_duplicates() {
        assert!(crate::client::is_dreamer_conflict(
            "THROW 'dreamer_job_cas_conflict'"
        ));
        assert!(crate::client::is_dreamer_conflict(
            "Specify the record id, as the record already exists"
        ));
        assert!(crate::client::is_dreamer_conflict(
            "Found duplicate record for unique index rj_namespace_key"
        ));
        assert!(!crate::client::is_dreamer_conflict(
            "provider outcome is unknown"
        ));
        assert!(!crate::client::is_dreamer_conflict(""));
    }

    fn test_selector_json() -> serde_json::Value {
        serde_json::json!({
            "scope_id": "scope-dreamer",
            "expected_revision": 1,
            "expected_fence": serde_json::to_value(test_fence()).expect("fence json"),
            "worker_artifact_id": "worker",
            "max_candidates": 8,
        })
    }

    fn test_content_json(revision: &str) -> serde_json::Value {
        serde_json::json!({
            "contract": {
                "name": "eliot.smart.dreamer.contracts",
                "version": {"major": 1, "minor": 0, "patch": 0},
                "shape_sha256": "0".repeat(64),
            },
            "source_revision": revision,
            "byte_length": 8,
            "sha256": "1".repeat(64),
            "artifact_id": format!("artifact-{revision}"),
        })
    }

    fn test_checkpoint_json() -> serde_json::Value {
        serde_json::json!({
            "checkpoint_id": "checkpoint-1",
            "reference": {
                "contract": {
                    "name": "eliot.smart.dreamer.contracts",
                    "version": {"major": 1, "minor": 0, "patch": 0},
                    "shape_sha256": "0".repeat(64),
                },
                "source_revision": "checkpoint-1",
                "byte_length": 8,
                "sha256": "1".repeat(64),
                "artifact_id": "checkpoint-1",
            },
            "completed_phases": ["phase-a"],
            "remaining_phases": ["phase-b"],
            "budget_remaining": 7,
            "possible_effects": ["CANDIDATE"],
            "state_fence": serde_json::to_value(test_fence()).expect("fence json"),
        })
    }

    fn test_artifact_json() -> serde_json::Value {
        serde_json::json!({
            "artifact_id": "artifact-evidence-1",
            "sha256": "2".repeat(64),
            "role": "ARTIFACT",
            "source_revision": "rev-1",
        })
    }

    fn test_outcome_json() -> serde_json::Value {
        serde_json::json!({
            "state": "COMPLETED",
            "result": test_content_json("output"),
            "evidence": [test_artifact_json()],
            "verifier": null,
            "proof_ceiling": "CANDIDATE_ARTIFACT",
            "abstention_reason": null,
            "unresolved": [],
        })
    }

    fn test_fence() -> eliot_store_api::StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage");
        let epoch =
            EpochId::new(lineage, std::num::NonZeroU64::new(1).expect("seq")).expect("epoch");
        eliot_store_api::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    fn test_lease() -> JobLease {
        serde_json::from_value(serde_json::json!({
            "job_id": "job",
            "attempt_id": "attempt",
            "lease_id": {
                "namespace": "eliot.governor.work-lease",
                "revision": "v1",
                "value": "lease-1"
            },
            "owner_artifact_id": "worker",
            "resource_generation": 1,
            "state_fence": test_fence(),
            "issued_at_unix_ms": 10,
            "expires_at_unix_ms": 100,
            "revision": 1
        }))
        .expect("lease")
    }

    /// Builds one valid `Submit` operation without naming the transitive
    /// receipt types: the nested scope/admission bindings deserialize through
    /// the submission's own `Deserialize` impl.
    fn test_submission() -> eliot_protocol::dreamer_job::JobSubmission {
        let fence = serde_json::to_value(test_fence()).expect("fence json");
        serde_json::from_value(serde_json::json!({
            "job_id": "job",
            "attempt_id": "attempt",
            "work_scope": {
                "scope_id": "scope",
                "product_id": "product",
                "resource_generation": 1,
                "state_fence": fence,
            },
            "semantic_input": {
                "contract": {
                    "name": "eliot.smart.dreamer.contracts",
                    "version": {"major": 1, "minor": 0, "patch": 0},
                    "shape_sha256": "0".repeat(64),
                },
                "source_revision": "input",
                "byte_length": 1,
                "sha256": "0".repeat(64),
                "artifact_id": "artifact-input",
            },
            "output_contract": {
                "contract": {
                    "name": "eliot.smart.dreamer.contracts",
                    "version": {"major": 1, "minor": 0, "patch": 0},
                    "shape_sha256": "0".repeat(64),
                },
                "source_revision": "output",
                "byte_length": 1,
                "sha256": "0".repeat(64),
                "artifact_id": "artifact-output",
            },
            "admission": {
                "authority": {
                    "authority_id": "kernel",
                    "authority_owner": "kernel",
                    "authority_epoch": fence.get("authority_epoch").cloned().unwrap_or(serde_json::Value::Null),
                    "state_fence": fence,
                    "allowed_effect": "CANDIDATE",
                    "proof_ceiling": "CANDIDATE_ARTIFACT",
                },
                "requester_principal": "requester",
                "session": null,
                "scope": {
                    "scope_id": "scope",
                    "product_id": "product",
                    "resource_generation": 1,
                    "state_fence": fence,
                },
                "capability": "dreamer.submit",
                "route_class": "bounded",
                "budget_units": 1,
                "deadline_unix_ms": 100,
                "validity_epoch": fence.get("authority_epoch").cloned().unwrap_or(serde_json::Value::Null),
                "resource_generation": 1,
                "admission_receipt": "admission",
            },
            "cancellation_id": "cancel",
        }))
        .expect("submission")
    }

    /// Builds one `Reconcile` mutation shell for the unadvertised-branch
    /// check; content validity is irrelevant, only the operation kind matters.
    fn test_reconciliation() -> eliot_protocol::dreamer_job::MutationReconciliation {
        let fence = serde_json::to_value(test_fence()).expect("fence json");
        serde_json::from_value(serde_json::json!({
            "job_id": "job",
            "attempt_id": "attempt",
            "operation": {
                "operation_id": "op-1",
                "request_id": "origin",
                "idempotency_key": "idem-1",
                "operation_kind": "SUBMIT_JOB",
                "effect": "CANDIDATE",
                "state_fence": fence,
            },
            "canonical_request_hash": "a".repeat(64),
            "disposition": "COMMITTED",
            "evidence": [],
        }))
        .expect("reconciliation")
    }
}
