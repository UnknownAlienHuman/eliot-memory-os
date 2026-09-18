//! Store-neutral Dreamer ledger contract (S0 named family, owner #773).
//!
//! This module publishes one closed named family over the twelve K0
//! [`JobOperation`](eliot_protocol::dreamer_job::JobOperation) variants. It
//! composes K0 control values with a store-owned event cursor, expected-state
//! compare-and-swap, immutable mutation identity, deterministic digests, and
//! real receipt references. It never persists data, starts a provider, or
//! invents a second lifecycle: all lifecycle edges reuse K0
//! [`JobState`](eliot_protocol::dreamer_job::JobState).
//!
//! Active ownership and historical lease evidence stay distinct: the ledger
//! record carries at most one [`JobLease`](eliot_protocol::dreamer_job::JobLease)
//! as active owner plus a bounded history of superseded leases. Terminal
//! publication retains lease history while releasing active ownership.
//! Result-under-verification is preserved only while verifying; terminal
//! outcomes carry their own evidence.

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, OperationId, ReceiptId, StateFence, TaskId, canonical_json_bytes, sha256_hex,
};
use eliot_protocol::dreamer_job::{
    DurableJobError, DurableJobRecord, DurableJobRequest, DurableJobResponse, JobCheckpoint,
    JobLease, JobOperation, JobRole, JobState, OpaqueContentRef,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::StoreError;

/// Versioned schema bound into ledger digests.
pub const DREAMER_JOB_LEDGER_SCHEMA: &str = "eliot.storage.dreamer-job.v1";
/// Hard bound for lease-history and bounded text lists in this family.
pub const MAX_DREAMER_JOB_HISTORY: usize = 256;
/// Hard bound for queue-key bytes.
pub const MAX_DREAMER_JOB_QUEUE_KEY_BYTES: usize = 256;
/// Hard bound for free-text fields in this family.
pub const MAX_DREAMER_JOB_TEXT_BYTES: usize = 16 * 1024;

/// Deterministically maps a K0 validation failure to the store boundary.
///
/// The mapping preserves typed identity, CAS, lease, checkpoint, receipt,
/// coverage, cancellation, unknown-commit, and internal error classes without
/// echoing supplied payloads.
#[must_use]
pub fn map_durable_error(error: DurableJobError) -> StoreError {
    match error {
        DurableJobError::Protocol(error) => StoreError::Serialization(error.to_string()),
        DurableJobError::Foundation(error) => StoreError::Foundation(error),
        DurableJobError::InvalidField { field, reason } => {
            StoreError::InvalidField { field, reason }
        }
        DurableJobError::LimitExceeded(_) => StoreError::PayloadTooLarge,
        DurableJobError::Serialization(reason) => StoreError::Serialization(reason),
        DurableJobError::FenceMismatch => StoreError::FenceMismatch,
        DurableJobError::OperationMismatch => StoreError::IdentityConflict,
        DurableJobError::CapabilityDenied => StoreError::UnknownOperation,
        DurableJobError::LeaseInvalid | DurableJobError::TerminalImmutable => {
            StoreError::RevisionConflict
        }
        DurableJobError::IllegalTransition { .. } => StoreError::InvalidProjection,
        DurableJobError::InvalidOutcome | DurableJobError::OutcomeMismatch => {
            StoreError::InvalidReceipt
        }
        DurableJobError::ProofOverclaim => StoreError::EffectCeilingExceeded,
        DurableJobError::RevisionOverflow => StoreError::InvalidField {
            field: "revision",
            reason: "overflow",
        },
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    if value.len() > MAX_DREAMER_JOB_TEXT_BYTES {
        return Err(StoreError::PayloadTooLarge);
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(StoreError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        });
    }
    Ok(())
}

fn ensure_same_fence(left: &StateFence, right: &StateFence) -> Result<(), StoreError> {
    if left != right {
        return Err(StoreError::FenceMismatch);
    }
    Ok(())
}

/// Checks the closed twelve-kind operation vocabulary without accepting a
/// generic command string.
fn validate_closed_operation_kind(kind: &str) -> Result<(), StoreError> {
    const CLOSED: &[&str] = &[
        "SUBMIT_JOB",
        "LEASE_NEXT",
        "LEASE_EXACT",
        "RENEW_LEASE",
        "START_JOB",
        "CHECKPOINT_JOB",
        "RESUME_JOB",
        "BEGIN_VERIFICATION",
        "PUBLISH_OUTCOME",
        "STATUS",
        "REQUEST_CANCEL",
        "RECONCILE_MUTATION",
    ];
    if CLOSED.contains(&kind) {
        Ok(())
    } else {
        Err(StoreError::UnknownOperation)
    }
}

/// Validates one lease shape without requiring it to be currently active.
///
/// Historical leases are expired by definition, so expiry is checked only as
/// ordering (`expires_at` strictly after `issued_at`), mirroring the K0 shape
/// rule without calling its private helper.
fn validate_lease_shape(lease: &JobLease) -> Result<(), StoreError> {
    lease
        .state_fence
        .validate()
        .map_err(StoreError::Foundation)?;
    if lease.resource_generation != lease.state_fence.resource_generation {
        return Err(StoreError::FenceMismatch);
    }
    if lease.revision == 0 {
        return Err(StoreError::InvalidField {
            field: "lease.revision",
            reason: "must be positive",
        });
    }
    if lease.expires_at_unix_ms <= lease.issued_at_unix_ms {
        return Err(StoreError::RevisionConflict);
    }
    Ok(())
}

/// Immutable stable mutation identity.
///
/// The operation identifier, idempotency key, and canonical request hash come
/// from the answered K0 request; the operation kind must name the closed
/// twelve-operation vocabulary. Proposed ledger digests live on the record
/// and event themselves (see their `compute_digest` methods) so this
/// identity stays free of self-referential hashes. No payload bytes travel
/// here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerJobMutationIdentity {
    pub operation_id: OperationId,
    pub idempotency_key: String,
    pub canonical_request_hash: String,
    pub operation_kind: String,
}

impl DreamerJobMutationIdentity {
    /// Validates bounded identity fields and the closed operation vocabulary.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.idempotency_key, "dreamer_job.idempotency_key")?;
        validate_digest(
            &self.canonical_request_hash,
            "dreamer_job.canonical_request_hash",
        )?;
        validate_closed_operation_kind(&self.operation_kind)?;
        Ok(())
    }
}

/// Expected-state compare-and-swap for one ledger mutation.
///
/// `expected_revision` and `expected_event_cursor` are zero only for the
/// all-absent submit edge (`NotStarted`); every other edge binds a positive
/// revision and cursor plus the exact fence and applicable lease/checkpoint
/// pins.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerJobExpectedState {
    pub expected_state: JobState,
    pub expected_revision: u64,
    pub expected_event_cursor: u64,
    pub state_fence: StateFence,
    pub lease_revision: Option<u64>,
    pub checkpoint_id: Option<ArtifactId>,
}

impl DreamerJobExpectedState {
    /// Validates the CAS denominator without assigning a new revision.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.expected_state == JobState::NotStarted {
            if self.expected_revision != 0 || self.expected_event_cursor != 0 {
                return Err(StoreError::InvalidField {
                    field: "dreamer_job.expected_revision",
                    reason: "absent state requires zero revision and cursor",
                });
            }
        } else if self.expected_revision == 0 || self.expected_event_cursor == 0 {
            return Err(StoreError::InvalidField {
                field: "dreamer_job.expected_revision",
                reason: "must be positive past the absent edge",
            });
        }
        if let Some(revision) = self.lease_revision
            && revision == 0
        {
            return Err(StoreError::InvalidField {
                field: "dreamer_job.lease_revision",
                reason: "must be positive",
            });
        }
        Ok(())
    }
}

/// Returns the deterministic queue key for one job/attempt pair.
#[must_use]
pub fn dreamer_job_queue_key(job_id: &TaskId, attempt_id: &ArtifactId) -> String {
    format!("dreamer-job:{}:{}", job_id.as_str(), attempt_id.as_str())
}

/// Store-owned ledger record: one K0 history plus cursor, queue key, active
/// versus historical leases, preserved verification result, immutable
/// mutation identity, real receipt reference, and digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerJobLedgerRecord {
    pub record: DurableJobRecord,
    pub event_cursor: u64,
    pub queue_key: String,
    pub active_lease: Option<JobLease>,
    pub lease_history: Vec<JobLease>,
    pub result_under_verification: Option<OpaqueContentRef>,
    pub last_mutation: DreamerJobMutationIdentity,
    pub last_receipt_id: Option<ReceiptId>,
    pub record_digest: String,
}

impl DreamerJobLedgerRecord {
    /// Returns the canonical bytes covered by [`Self::record_digest`].
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, StoreError> {
        let mut unsigned = self.clone();
        unsigned.record_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| StoreError::Serialization(error.to_string()))
    }

    /// Computes the deterministic record digest over every field except the
    /// digest itself.
    pub fn compute_digest(&self) -> Result<String, StoreError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Validates K0 history, cursor, queue key, lease split, verification
    /// preservation, mutation identity, receipt presence, history bounds, and
    /// digest binding.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.record.validate().map_err(map_durable_error)?;
        if self.event_cursor == 0 {
            return Err(StoreError::InvalidField {
                field: "dreamer_job.event_cursor",
                reason: "must be positive",
            });
        }
        self.validate_queue_key()?;
        self.validate_lease_split()?;
        self.validate_verification()?;
        self.validate_mutation_receipt_digest()?;
        Ok(())
    }

    fn validate_queue_key(&self) -> Result<(), StoreError> {
        if self.queue_key.len() > MAX_DREAMER_JOB_QUEUE_KEY_BYTES {
            return Err(StoreError::PayloadTooLarge);
        }
        validate_text(&self.queue_key, "dreamer_job.queue_key")?;
        let expected_key = dreamer_job_queue_key(
            &self.record.submission.job_id,
            &self.record.submission.attempt_id,
        );
        if self.queue_key != expected_key {
            return Err(StoreError::InvalidField {
                field: "dreamer_job.queue_key",
                reason: "must bind job and attempt",
            });
        }
        Ok(())
    }

    fn validate_lease_split(&self) -> Result<(), StoreError> {
        if self.lease_history.len() > MAX_DREAMER_JOB_HISTORY {
            return Err(StoreError::PayloadTooLarge);
        }
        for lease in &self.lease_history {
            validate_lease_shape(lease)?;
        }
        let mut seen_lease_ids = BTreeSet::new();
        for lease in &self.lease_history {
            if !seen_lease_ids.insert(lease.lease_id.clone()) {
                return Err(StoreError::Duplicate {
                    field: "dreamer_job.lease_history",
                });
            }
        }
        if let Some(active) = &self.active_lease {
            validate_lease_shape(active)?;
            if active.job_id != self.record.submission.job_id
                || active.attempt_id != self.record.submission.attempt_id
            {
                return Err(StoreError::IdentityConflict);
            }
            ensure_same_fence(
                &active.state_fence,
                &self.record.submission.work_scope.state_fence,
            )?;
            if self.record.lease.as_ref() != Some(active) {
                return Err(StoreError::IdentityConflict);
            }
            if seen_lease_ids.contains(&active.lease_id) {
                return Err(StoreError::Duplicate {
                    field: "dreamer_job.active_lease",
                });
            }
            if self.record.state.is_terminal() {
                return Err(StoreError::RevisionConflict);
            }
        } else if self.record.lease.is_some() {
            return Err(StoreError::IdentityConflict);
        }
        if self.record.state.is_terminal() {
            if self.active_lease.is_some() {
                return Err(StoreError::RevisionConflict);
            }
            if self.lease_history.is_empty() && self.record.state != JobState::Queued {
                return Err(StoreError::InvalidField {
                    field: "dreamer_job.lease_history",
                    reason: "terminal records retain lease history",
                });
            }
        }
        Ok(())
    }

    fn validate_verification(&self) -> Result<(), StoreError> {
        if let Some(result) = &self.result_under_verification {
            result
                .validate("result_under_verification.sha256")
                .map_err(map_durable_error)?;
            if self.record.state != JobState::Verifying {
                return Err(StoreError::InvalidField {
                    field: "dreamer_job.result_under_verification",
                    reason: "only admitted while verifying",
                });
            }
        } else if self.record.state == JobState::Verifying {
            return Err(StoreError::InvalidField {
                field: "dreamer_job.result_under_verification",
                reason: "verifying records require a result under verification",
            });
        }
        Ok(())
    }

    fn validate_mutation_receipt_digest(&self) -> Result<(), StoreError> {
        self.last_mutation.validate()?;
        if self.record.state == JobState::NotStarted {
            if self.last_receipt_id.is_some() {
                return Err(StoreError::InvalidReceipt);
            }
        } else if self.last_receipt_id.is_none() {
            return Err(StoreError::InvalidReceipt);
        }
        validate_digest(&self.record_digest, "dreamer_job.record_digest")?;
        if self.record_digest != self.compute_digest()? {
            return Err(StoreError::InvalidField {
                field: "dreamer_job.record_digest",
                reason: "does not match canonical ledger record",
            });
        }
        Ok(())
    }
}

/// Store-owned ledger event: one exact prior-to-next edge with canonical
/// operation, actor role and lease, changed checkpoint/result, immutable
/// mutation identity, receipt reference, and digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamerJobLedgerEvent {
    pub job_id: TaskId,
    pub attempt_id: ArtifactId,
    pub prior_state: JobState,
    pub next_state: JobState,
    pub prior_revision: u64,
    pub next_revision: u64,
    pub event_cursor: u64,
    pub operation: JobOperation,
    pub role: JobRole,
    pub lease: Option<JobLease>,
    pub checkpoint: Option<JobCheckpoint>,
    pub result_under_verification: Option<OpaqueContentRef>,
    pub mutation: DreamerJobMutationIdentity,
    pub receipt_id: Option<ReceiptId>,
    pub event_digest: String,
}

impl DreamerJobLedgerEvent {
    /// Returns the canonical bytes covered by [`Self::event_digest`].
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, StoreError> {
        let mut unsigned = self.clone();
        unsigned.event_digest.clear();
        canonical_json_bytes(&unsigned)
            .map_err(|error| StoreError::Serialization(error.to_string()))
    }

    /// Computes the deterministic event digest over every field except the
    /// digest itself.
    pub fn compute_digest(&self) -> Result<String, StoreError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Validates the closed operation, actor permission, state edge, revision
    /// step, cursor, lease/checkpoint/result bindings, mutation kind, receipt
    /// presence, and digest.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.operation.validate().map_err(map_durable_error)?;
        if !self.role.permits(self.operation.kind()) {
            return Err(StoreError::UnknownOperation);
        }
        if self.event_cursor == 0 {
            return Err(StoreError::InvalidField {
                field: "dreamer_job.event_cursor",
                reason: "must be positive",
            });
        }
        if !self.prior_state.can_transition_to(self.next_state) {
            return Err(StoreError::InvalidProjection);
        }
        let is_status = matches!(self.operation, JobOperation::Status { .. });
        if is_status {
            if self.prior_state != self.next_state || self.prior_revision != self.next_revision {
                return Err(StoreError::InvalidField {
                    field: "dreamer_job.status_event",
                    reason: "observations do not advance state or revision",
                });
            }
            if self.receipt_id.is_some() {
                return Err(StoreError::InvalidReceipt);
            }
        } else if self.next_revision != self.prior_revision
            && self.next_revision != self.prior_revision.saturating_add(1)
        {
            return Err(StoreError::RevisionConflict);
        }
        if self.mutation.operation_kind != self.operation.kind().as_str() {
            return Err(StoreError::IdentityConflict);
        }
        self.mutation.validate()?;
        if let Some(lease) = &self.lease {
            validate_lease_shape(lease)?;
            if lease.job_id != self.job_id || lease.attempt_id != self.attempt_id {
                return Err(StoreError::IdentityConflict);
            }
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate().map_err(map_durable_error)?;
        }
        if let Some(result) = &self.result_under_verification {
            result
                .validate("result_under_verification.sha256")
                .map_err(map_durable_error)?;
            if self.next_state != JobState::Verifying {
                return Err(StoreError::InvalidField {
                    field: "dreamer_job.result_under_verification",
                    reason: "only admitted while verifying",
                });
            }
        } else if self.next_state == JobState::Verifying
            && matches!(self.operation, JobOperation::BeginVerification { .. })
        {
            return Err(StoreError::InvalidField {
                field: "dreamer_job.result_under_verification",
                reason: "verification events require a result under verification",
            });
        }
        let needs_receipt = !is_status && !matches!(self.operation, JobOperation::Reconcile { .. });
        if needs_receipt && self.receipt_id.is_none() {
            return Err(StoreError::InvalidReceipt);
        }
        if is_status && self.receipt_id.is_some() {
            return Err(StoreError::InvalidReceipt);
        }
        validate_digest(&self.event_digest, "dreamer_job.event_digest")?;
        if self.event_digest != self.compute_digest()? {
            return Err(StoreError::InvalidField {
                field: "dreamer_job.event_digest",
                reason: "does not match canonical ledger event",
            });
        }
        Ok(())
    }
}

/// Validates one committed or observed ledger bundle: the K0 request/response
/// binding plus mutually consistent record, event, mutation identity, lease,
/// verification result, and receipt references.
///
/// This is intrinsic validation only; it never proves that a database
/// transaction ran. Status bundles are pure observations with no mutation
/// disposition or receipt; every other operation carries both.
pub fn validate_ledger_bundle(
    request: &DurableJobRequest,
    response: &DurableJobResponse,
    record: &DreamerJobLedgerRecord,
    event: &DreamerJobLedgerEvent,
) -> Result<(), StoreError> {
    request.validate().map_err(map_durable_error)?;
    response.validate_for(request).map_err(map_durable_error)?;
    record.validate()?;
    event.validate()?;
    validate_bundle_identities(request, response, record, event)?;
    validate_bundle_revision_state(request, response, record, event)?;
    validate_bundle_mutation_receipt(request, response, record, event)?;
    validate_bundle_leases_results(request, response, record, event)
}

/// Binds job, attempt, scope, and fence across request, response, record, and
/// event.
fn validate_bundle_identities(
    request: &DurableJobRequest,
    response: &DurableJobResponse,
    record: &DreamerJobLedgerRecord,
    event: &DreamerJobLedgerEvent,
) -> Result<(), StoreError> {
    if response.job_id != record.record.submission.job_id
        || response.attempt_id != record.record.submission.attempt_id
        || event.job_id != record.record.submission.job_id
        || event.attempt_id != record.record.submission.attempt_id
    {
        return Err(StoreError::IdentityConflict);
    }
    if response.scope != record.record.submission.work_scope {
        return Err(StoreError::FenceMismatch);
    }
    ensure_same_fence(
        &response.scope.state_fence,
        &request.request_identity.operation.state_fence,
    )?;
    ensure_same_fence(
        &record.record.submission.work_scope.state_fence,
        &request.request_identity.operation.state_fence,
    )?;
    match &request.operation {
        JobOperation::Submit { submission } => {
            if response.job_id != submission.job_id || response.attempt_id != submission.attempt_id
            {
                return Err(StoreError::IdentityConflict);
            }
        }
        JobOperation::LeaseNext { .. } => {
            // Scope binding is already enforced through K0
            // `validate_response_operation`; the ledger only re-checks fence.
        }
        JobOperation::LeaseExact { job_id, .. } => {
            if response.job_id != *job_id {
                return Err(StoreError::IdentityConflict);
            }
        }
        JobOperation::Renew { lease, .. }
        | JobOperation::Start { lease, .. }
        | JobOperation::Checkpoint { lease, .. }
        | JobOperation::Resume { lease, .. }
        | JobOperation::BeginVerification { lease, .. }
        | JobOperation::Publish { lease, .. } => {
            if response.job_id != lease.job_id || response.attempt_id != lease.attempt_id {
                return Err(StoreError::IdentityConflict);
            }
        }
        JobOperation::Status {
            job_id, attempt_id, ..
        }
        | JobOperation::RequestCancel {
            job_id, attempt_id, ..
        } => {
            if response.job_id != *job_id || response.attempt_id != *attempt_id {
                return Err(StoreError::IdentityConflict);
            }
        }
        JobOperation::Reconcile { mutation } => {
            if response.job_id != mutation.job_id || response.attempt_id != mutation.attempt_id {
                return Err(StoreError::IdentityConflict);
            }
        }
    }
    Ok(())
}

/// Binds revision, cursor, and lifecycle state across response, record, and
/// event for the closed twelve-operation family.
#[allow(clippy::too_many_lines)]
fn validate_bundle_revision_state(
    request: &DurableJobRequest,
    response: &DurableJobResponse,
    record: &DreamerJobLedgerRecord,
    event: &DreamerJobLedgerEvent,
) -> Result<(), StoreError> {
    if response.revision != record.record.revision || response.revision != event.next_revision {
        return Err(StoreError::RevisionConflict);
    }
    if record.event_cursor != event.event_cursor {
        return Err(StoreError::RevisionConflict);
    }
    if response.state != record.record.state || response.state != event.next_state {
        return Err(StoreError::InvalidProjection);
    }
    match &request.operation {
        JobOperation::Submit { .. } => {
            if event.prior_state != JobState::NotStarted || event.next_state != JobState::Queued {
                return Err(StoreError::InvalidProjection);
            }
        }
        JobOperation::LeaseNext { .. } | JobOperation::LeaseExact { .. } => {
            if response.state != JobState::Leased {
                return Err(StoreError::InvalidProjection);
            }
        }
        JobOperation::Renew { .. } => {
            if response.state != event.next_state {
                return Err(StoreError::InvalidProjection);
            }
        }
        JobOperation::Start { .. } | JobOperation::Resume { .. } => {
            if response.state != JobState::Running {
                return Err(StoreError::InvalidProjection);
            }
        }
        JobOperation::Checkpoint { .. } => {
            if response.state != JobState::Checkpointed {
                return Err(StoreError::InvalidProjection);
            }
        }
        JobOperation::BeginVerification { .. } => {
            if response.state != JobState::Verifying {
                return Err(StoreError::InvalidProjection);
            }
        }
        JobOperation::Publish { .. } => {
            if !response.state.is_terminal() {
                return Err(StoreError::InvalidReceipt);
            }
        }
        JobOperation::Status { .. } => {
            if response.disposition.is_some() {
                return Err(StoreError::IdentityConflict);
            }
        }
        JobOperation::RequestCancel { .. } => {
            if response.job_id != event.job_id {
                return Err(StoreError::IdentityConflict);
            }
        }
        JobOperation::Reconcile { mutation } => {
            if response.disposition != Some(mutation.disposition) {
                return Err(StoreError::IdentityConflict);
            }
        }
    }
    Ok(())
}

/// Binds stable mutation identity, digests, and receipt references across the
/// bundle.
///
/// Mutating operations require exact agreement across request, record, event,
/// and response. Status is a pure observation: its event carries the Status
/// identity with no receipt while the record retains the last committed
/// mutation and receipt.
fn validate_bundle_mutation_receipt(
    request: &DurableJobRequest,
    response: &DurableJobResponse,
    record: &DreamerJobLedgerRecord,
    event: &DreamerJobLedgerEvent,
) -> Result<(), StoreError> {
    let stable = &request.request_identity;
    if matches!(request.operation, JobOperation::Status { .. }) {
        let event_mutation = &event.mutation;
        if event_mutation.operation_id != stable.operation.operation_id
            || event_mutation.idempotency_key != stable.operation.idempotency_key
            || event_mutation.canonical_request_hash != stable.canonical_request_hash
            || event_mutation.operation_kind != stable.operation.operation_kind
            || event_mutation.operation_kind != request.operation.kind().as_str()
        {
            return Err(StoreError::IdentityConflict);
        }
        if response.receipt_id.is_some() || event.receipt_id.is_some() {
            return Err(StoreError::InvalidReceipt);
        }
        if record.last_receipt_id.is_none() {
            return Err(StoreError::InvalidReceipt);
        }
        return Ok(());
    }
    for identity in [&record.last_mutation, &event.mutation] {
        if identity.operation_id != stable.operation.operation_id
            || identity.idempotency_key != stable.operation.idempotency_key
            || identity.canonical_request_hash != stable.canonical_request_hash
            || identity.operation_kind != stable.operation.operation_kind
        {
            return Err(StoreError::IdentityConflict);
        }
    }
    if record.last_mutation.operation_kind != request.operation.kind().as_str()
        || event.mutation.operation_kind != request.operation.kind().as_str()
    {
        return Err(StoreError::IdentityConflict);
    }
    if response.receipt_id != record.last_receipt_id || response.receipt_id != event.receipt_id {
        return Err(StoreError::InvalidReceipt);
    }
    Ok(())
}

/// Binds active versus historical leases, checkpoints, verification results,
/// and terminal outcomes across the bundle.
fn validate_bundle_leases_results(
    _request: &DurableJobRequest,
    response: &DurableJobResponse,
    record: &DreamerJobLedgerRecord,
    event: &DreamerJobLedgerEvent,
) -> Result<(), StoreError> {
    if response.lease != record.active_lease {
        return Err(StoreError::IdentityConflict);
    }
    if response.lease.as_ref() != event.lease.as_ref()
        && event.lease.is_some()
        && response.lease.is_some()
    {
        return Err(StoreError::IdentityConflict);
    }
    if response.checkpoint != record.record.checkpoint {
        return Err(StoreError::IdentityConflict);
    }
    if response.result_under_verification != record.result_under_verification
        || response.result_under_verification != event.result_under_verification
    {
        return Err(StoreError::IdentityConflict);
    }
    if response.outcome != record.record.outcome {
        return Err(StoreError::InvalidReceipt);
    }
    if record.record.state.is_terminal() && record.active_lease.is_some() {
        return Err(StoreError::RevisionConflict);
    }
    Ok(())
}
