//! Provider-neutral control contracts for durable Dreamer jobs.
//!
//! This module is a shape and transition boundary.  It does not persist a job,
//! start a provider, select a route, apply a candidate, or grant authority.
//! The authority, request, operation, lease, receipt and proof values carried
//! here are projections owned by their foundation crates.

use std::fmt;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractIdentity, ContractVersion, OperationId, ReceiptId,
    ResourceGeneration, StateFence, TaskId, canonical_json_bytes, sha256_hex,
};
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, OperationBinding, ProofCeiling, SessionBinding,
    VerifierBinding, WorkScopeBinding, WorkScopeId,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of the `DurableJob` control family.
pub const DURABLE_JOB_CONTRACT_NAME: &str = "eliot.foundation.protocol.durable-job";
/// Current semantic revision of the `DurableJob` control family.
pub const DURABLE_JOB_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);
/// Versioned namespace used when hashing a mutation request.
pub const DURABLE_JOB_CANONICAL_ENCODING: &str = "eliot.durable-job.canonical.v1";
/// Maximum bounded text field size in bytes.
pub const DURABLE_JOB_MAX_TEXT_BYTES: usize = 16 * 1024;
/// Maximum number of references in one bounded control value.
pub const DURABLE_JOB_MAX_REFERENCES: usize = 256;

/// Canonical I14.20 Durable Job execution state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobState {
    NotStarted,
    Queued,
    Leased,
    Running,
    Checkpointed,
    Verifying,
    Completed,
    Partial,
    Failed,
    Cancelled,
    UnknownOutcome,
}

impl JobState {
    /// Returns whether this state is immutable execution history.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Partial | Self::Failed | Self::Cancelled | Self::UnknownOutcome
        )
    }

    /// Checks one legal I14.20 state edge.  Replaying the same state is valid.
    #[must_use]
    pub fn can_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        matches!(
            (self, next),
            (Self::NotStarted, Self::Queued)
                | (Self::Queued, Self::Leased)
                | (Self::Leased | Self::Checkpointed, Self::Running)
                | (
                    Self::Running,
                    Self::Checkpointed | Self::Failed | Self::Cancelled | Self::UnknownOutcome
                )
                | (
                    Self::Checkpointed,
                    Self::Verifying | Self::Failed | Self::Cancelled | Self::UnknownOutcome
                )
                | (
                    Self::Verifying,
                    Self::Completed
                        | Self::Partial
                        | Self::Failed
                        | Self::Cancelled
                        | Self::UnknownOutcome
                )
        )
    }
}

/// Closed operation vocabulary for the `DurableJob` control surface.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobOperationKind {
    #[serde(rename = "SUBMIT_JOB")]
    Submit,
    LeaseNext,
    LeaseExact,
    #[serde(rename = "RENEW_LEASE")]
    Renew,
    #[serde(rename = "START_JOB")]
    Start,
    #[serde(rename = "CHECKPOINT_JOB")]
    Checkpoint,
    #[serde(rename = "RESUME_JOB")]
    Resume,
    BeginVerification,
    #[serde(rename = "PUBLISH_OUTCOME")]
    Publish,
    Status,
    RequestCancel,
    #[serde(rename = "RECONCILE_MUTATION")]
    Reconcile,
}

impl JobOperationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Submit => "SUBMIT_JOB",
            Self::LeaseNext => "LEASE_NEXT",
            Self::LeaseExact => "LEASE_EXACT",
            Self::Renew => "RENEW_LEASE",
            Self::Start => "START_JOB",
            Self::Checkpoint => "CHECKPOINT_JOB",
            Self::Resume => "RESUME_JOB",
            Self::BeginVerification => "BEGIN_VERIFICATION",
            Self::Publish => "PUBLISH_OUTCOME",
            Self::Status => "STATUS",
            Self::RequestCancel => "REQUEST_CANCEL",
            Self::Reconcile => "RECONCILE_MUTATION",
        }
    }
}

impl fmt::Display for JobOperationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Authenticated role projection.  A value in a payload never grants this role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobRole {
    Requester,
    Worker,
    Controller,
}

/// Operation capability projection used for local shape checks.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum JobCapability {
    Submit,
    Lease,
    Renew,
    Start,
    Checkpoint,
    Resume,
    Verify,
    Publish,
    Status,
    RequestCancel,
    Reconcile,
}

impl JobRole {
    /// Returns the closed capability projection for the role.
    #[must_use]
    pub const fn capabilities(self) -> &'static [JobCapability] {
        match self {
            Self::Requester => &[
                JobCapability::Submit,
                JobCapability::Status,
                JobCapability::RequestCancel,
                JobCapability::Reconcile,
            ],
            Self::Worker => &[
                JobCapability::Lease,
                JobCapability::Renew,
                JobCapability::Start,
                JobCapability::Checkpoint,
                JobCapability::Resume,
                JobCapability::Verify,
                JobCapability::Publish,
                JobCapability::Status,
                JobCapability::Reconcile,
            ],
            Self::Controller => &[
                JobCapability::Status,
                JobCapability::RequestCancel,
                JobCapability::Reconcile,
            ],
        }
    }

    #[must_use]
    pub fn permits(self, operation: JobOperationKind) -> bool {
        let capability = match operation {
            JobOperationKind::Submit => JobCapability::Submit,
            JobOperationKind::LeaseNext | JobOperationKind::LeaseExact => JobCapability::Lease,
            JobOperationKind::Renew => JobCapability::Renew,
            JobOperationKind::Start => JobCapability::Start,
            JobOperationKind::Checkpoint => JobCapability::Checkpoint,
            JobOperationKind::Resume => JobCapability::Resume,
            JobOperationKind::BeginVerification => JobCapability::Verify,
            JobOperationKind::Publish => JobCapability::Publish,
            JobOperationKind::Status => JobCapability::Status,
            JobOperationKind::RequestCancel => JobCapability::RequestCancel,
            JobOperationKind::Reconcile => JobCapability::Reconcile,
        };
        self.capabilities().contains(&capability)
    }
}

/// Opaque semantic input or output reference.  Foundation binds bytes and
/// digest; this module never interprets A-03 content or its enum vocabulary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OpaqueContentRef {
    pub contract: ContractIdentity,
    pub source_revision: String,
    pub byte_length: u64,
    pub sha256: String,
    pub artifact_id: Option<ArtifactId>,
}

impl OpaqueContentRef {
    pub fn validate(&self, field: &'static str) -> Result<(), DurableJobError> {
        self.contract
            .validate()
            .map_err(DurableJobError::Foundation)?;
        bounded_text(&self.source_revision, "source_revision")?;
        if self.byte_length == 0 {
            return Err(DurableJobError::InvalidField {
                field,
                reason: "byte_length must be greater than zero",
            });
        }
        if self.artifact_id.is_none() {
            return Err(DurableJobError::InvalidField {
                field,
                reason: "must carry an immutable artifact handle",
            });
        }
        lowercase_digest(&self.sha256, field)
    }
}

/// Fresh transport correlation, separate from the stable mutation identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DurableRequestIdentity {
    /// Fresh transport correlation owned by the parent EBP protocol.
    pub request: super::RequestIdentity,
    pub operation: OperationBinding,
    /// Hash of canonical mutation bytes; this does not include this fresh ID.
    pub canonical_request_hash: String,
}

impl DurableRequestIdentity {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        self.request.validate()?;
        self.operation
            .state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        if self.operation.idempotency_key.trim().is_empty()
            || self.operation.operation_kind.trim().is_empty()
        {
            return Err(DurableJobError::OperationMismatch);
        }
        if self.operation.state_fence != self.request.request.state_fence {
            return Err(DurableJobError::FenceMismatch);
        }
        lowercase_digest(&self.canonical_request_hash, "canonical_request_hash")
    }

    /// Computes a versioned mutation digest from stable fields only.
    pub fn digest_for(
        operation: &OperationBinding,
        request: &super::RequestIdentity,
        payload: &JobOperation,
        role: JobRole,
    ) -> Result<String, DurableJobError> {
        bounded_text(&operation.idempotency_key, "idempotency_key")?;
        bounded_text(&operation.operation_kind, "operation_kind")?;
        let bytes = canonical_json_bytes(&(
            DURABLE_JOB_CANONICAL_ENCODING,
            operation,
            serde_json::json!({
                // Request correlation and transport clock are deliberately
                // excluded so a retry can use a fresh transport identity.
                "session_id": request.request.metadata.session_id,
                "task_id": request.request.metadata.task_id,
                "product_id": request.request.metadata.product_id,
                "source_id": request.request.metadata.source_id,
                "state_fence": request.request.metadata.state_fence,
            }),
            canonical_operation_payload(payload),
            role,
        ))
        .map_err(|error| DurableJobError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

fn canonical_operation_payload(operation: &JobOperation) -> serde_json::Value {
    match operation {
        JobOperation::Submit { submission } => serde_json::json!({
            "operation": "SUBMIT_JOB",
            "job_id": submission.job_id,
            "attempt_id": submission.attempt_id,
            "work_scope": submission.work_scope,
            "semantic_input": submission.semantic_input,
            "output_contract": submission.output_contract,
            "admission": submission.admission,
            "cancellation_id": submission.cancellation_id,
        }),
        JobOperation::LeaseNext { selector } => {
            serde_json::json!({ "operation": "LEASE_NEXT", "selector": selector })
        }
        JobOperation::LeaseExact { selector, job_id } => {
            serde_json::json!({ "operation": "LEASE_EXACT", "selector": selector, "job_id": job_id })
        }
        JobOperation::Renew { lease, now_unix_ms } => {
            serde_json::json!({ "operation": "RENEW_LEASE", "lease": lease, "observed_at_unix_ms": now_unix_ms })
        }
        JobOperation::Start { lease, now_unix_ms } => {
            serde_json::json!({ "operation": "START_JOB", "lease": lease, "observed_at_unix_ms": now_unix_ms })
        }
        JobOperation::Checkpoint {
            lease,
            checkpoint,
            now_unix_ms,
        } => {
            serde_json::json!({ "operation": "CHECKPOINT_JOB", "lease": lease, "checkpoint": checkpoint, "observed_at_unix_ms": now_unix_ms })
        }
        JobOperation::Resume {
            lease,
            checkpoint,
            now_unix_ms,
        } => {
            serde_json::json!({ "operation": "RESUME_JOB", "lease": lease, "checkpoint": checkpoint, "observed_at_unix_ms": now_unix_ms })
        }
        JobOperation::BeginVerification {
            lease,
            result,
            evidence,
            now_unix_ms,
        } => {
            serde_json::json!({ "operation": "BEGIN_VERIFICATION", "lease": lease, "result": result, "evidence": evidence, "observed_at_unix_ms": now_unix_ms })
        }
        JobOperation::Publish {
            lease,
            outcome,
            now_unix_ms,
        } => {
            serde_json::json!({ "operation": "PUBLISH_OUTCOME", "lease": lease, "outcome": outcome, "observed_at_unix_ms": now_unix_ms })
        }
        JobOperation::Status {
            job_id,
            attempt_id,
            expected_revision,
            expected_fence,
        } => {
            serde_json::json!({ "operation": "STATUS", "job_id": job_id, "attempt_id": attempt_id, "expected_revision": expected_revision, "expected_fence": expected_fence })
        }
        JobOperation::RequestCancel {
            job_id,
            attempt_id,
            reason,
            requested_at_unix_ms,
            expected_fence,
        } => {
            serde_json::json!({ "operation": "REQUEST_CANCEL", "job_id": job_id, "attempt_id": attempt_id, "reason": reason, "requested_at_unix_ms": requested_at_unix_ms, "expected_fence": expected_fence })
        }
        JobOperation::Reconcile { mutation } => {
            serde_json::json!({ "operation": "RECONCILE_MUTATION", "mutation": mutation })
        }
    }
}

/// Admission reference supplied by the owning Kernel/Governor boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRef {
    pub authority: AuthorityBinding,
    pub requester_principal: String,
    pub session: Option<SessionBinding>,
    pub scope: WorkScopeBinding,
    pub capability: String,
    pub route_class: String,
    pub budget_units: u64,
    pub deadline_unix_ms: u64,
    pub validity_epoch: AuthorityEpoch,
    pub resource_generation: ResourceGeneration,
    pub admission_receipt: ReceiptId,
}

impl AdmissionRef {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        bounded_text(&self.authority.authority_owner, "authority.authority_owner")?;
        self.authority
            .state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        self.scope
            .state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        if self.authority.authority_epoch != self.validity_epoch
            || self.authority.state_fence.authority_epoch != self.authority.authority_epoch
            || self.scope.resource_generation != self.resource_generation
            || self.scope.state_fence.resource_generation != self.scope.resource_generation
            || self.scope.state_fence != self.authority.state_fence
        {
            return Err(DurableJobError::FenceMismatch);
        }
        for (field, value) in [
            ("requester_principal", self.requester_principal.as_str()),
            ("capability", self.capability.as_str()),
            ("route_class", self.route_class.as_str()),
        ] {
            bounded_text(value, field)?;
        }
        if self.budget_units == 0 || self.deadline_unix_ms == 0 {
            return Err(DurableJobError::InvalidField {
                field: "admission",
                reason: "budget and deadline must be greater than zero",
            });
        }
        if let Some(session) = &self.session
            && session.authority_epoch != self.validity_epoch
        {
            return Err(DurableJobError::FenceMismatch);
        }
        Ok(())
    }
}

/// The exact input admitted for one attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobSubmission {
    pub job_id: TaskId,
    pub attempt_id: ArtifactId,
    pub work_scope: WorkScopeBinding,
    pub semantic_input: OpaqueContentRef,
    pub output_contract: OpaqueContentRef,
    pub admission: AdmissionRef,
    pub cancellation_id: String,
}

impl JobSubmission {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        self.semantic_input.validate("semantic_input.sha256")?;
        self.output_contract.validate("output_contract.sha256")?;
        self.admission.validate()?;
        self.work_scope
            .state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        if self.work_scope != self.admission.scope {
            return Err(DurableJobError::FenceMismatch);
        }
        bounded_text(&self.cancellation_id, "cancellation_id")
    }
}

/// Lease selector with an explicit denominator and no provider semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LeaseSelector {
    pub scope_id: WorkScopeId,
    pub expected_revision: u64,
    pub expected_fence: StateFence,
    pub worker_artifact_id: ArtifactId,
    pub max_candidates: u32,
}

impl LeaseSelector {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        if self.expected_revision == 0 || self.max_candidates == 0 {
            return Err(DurableJobError::InvalidField {
                field: "lease_selector",
                reason: "revision and candidate denominator must be positive",
            });
        }
        self.expected_fence
            .validate()
            .map_err(DurableJobError::Foundation)
    }
}

/// One active lease projection.  It is not proof that execution has started.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobLease {
    pub job_id: TaskId,
    pub attempt_id: ArtifactId,
    pub lease_id: eliot_contracts::WorkLeaseId,
    pub owner_artifact_id: ArtifactId,
    pub resource_generation: ResourceGeneration,
    pub state_fence: StateFence,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub revision: u64,
}

impl JobLease {
    fn validate_shape(&self) -> Result<(), DurableJobError> {
        self.state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        if self.resource_generation != self.state_fence.resource_generation
            || self.revision == 0
            || self.expires_at_unix_ms <= self.issued_at_unix_ms
        {
            return Err(DurableJobError::LeaseInvalid);
        }
        Ok(())
    }

    pub fn validate_active_at(&self, now_unix_ms: u64) -> Result<(), DurableJobError> {
        self.validate_shape()?;
        if now_unix_ms < self.issued_at_unix_ms || now_unix_ms >= self.expires_at_unix_ms {
            return Err(DurableJobError::LeaseInvalid);
        }
        Ok(())
    }
}

/// Immutable checkpoint reference and bounded phase frontier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobCheckpoint {
    pub checkpoint_id: ArtifactId,
    pub reference: OpaqueContentRef,
    pub completed_phases: Vec<String>,
    pub remaining_phases: Vec<String>,
    pub budget_remaining: u64,
    pub possible_effects: Vec<String>,
    pub state_fence: StateFence,
}

impl JobCheckpoint {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        self.reference.validate("checkpoint.reference.sha256")?;
        if self.reference.artifact_id.as_ref() != Some(&self.checkpoint_id) {
            return Err(DurableJobError::InvalidField {
                field: "checkpoint.reference.artifact_id",
                reason: "must match checkpoint_id",
            });
        }
        self.state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        validate_text_list(&self.completed_phases, "completed_phases")?;
        validate_text_list(&self.remaining_phases, "remaining_phases")?;
        validate_text_list(&self.possible_effects, "possible_effects")
    }
}

/// Cancellation is a requested projection until a terminal outcome is proven.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "state")]
pub enum CancellationState {
    None,
    Requested {
        requester_principal: String,
        reason: String,
        operation_id: OperationId,
        requested_at_unix_ms: u64,
    },
}

impl CancellationState {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        if let Self::Requested {
            requester_principal,
            reason,
            requested_at_unix_ms,
            ..
        } = self
        {
            bounded_text(requester_principal, "cancellation.requester_principal")?;
            bounded_text(reason, "cancellation.reason")?;
            if *requested_at_unix_ms == 0 {
                return Err(DurableJobError::InvalidField {
                    field: "cancellation.requested_at_unix_ms",
                    reason: "must be greater than zero",
                });
            }
        }
        Ok(())
    }
}

/// Terminal result projection.  A complete result may be abstention with no
/// candidate; this type does not contain task-close or authority fields.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobOutcome {
    pub state: JobState,
    pub result: Option<OpaqueContentRef>,
    pub evidence: Vec<ArtifactBinding>,
    pub verifier: Option<VerifierBinding>,
    pub proof_ceiling: ProofCeiling,
    pub abstention_reason: Option<String>,
    pub unresolved: Vec<String>,
}

impl JobOutcome {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        if !self.state.is_terminal() {
            return Err(DurableJobError::InvalidOutcome);
        }
        if self.evidence.is_empty() {
            return Err(DurableJobError::InvalidOutcome);
        }
        validate_artifacts(&self.evidence, "outcome.evidence")?;
        if let Some(result) = &self.result {
            result.validate("outcome.result.sha256")?;
        }
        if self.state == JobState::Completed
            && self.result.is_none()
            && self.abstention_reason.is_none()
        {
            return Err(DurableJobError::InvalidOutcome);
        }
        if self.state == JobState::Partial && self.unresolved.is_empty() {
            return Err(DurableJobError::InvalidOutcome);
        }
        if let Some(reason) = &self.abstention_reason {
            bounded_text(reason, "outcome.abstention_reason")?;
        }
        validate_text_list(&self.unresolved, "outcome.unresolved")?;
        if self.evidence.len() > DURABLE_JOB_MAX_REFERENCES {
            return Err(DurableJobError::LimitExceeded("outcome.evidence"));
        }
        if let Some(verifier) = &self.verifier {
            verifier
                .state_fence
                .validate()
                .map_err(DurableJobError::Foundation)?;
            if verifier.artifact_ids.is_empty() {
                return Err(DurableJobError::InvalidOutcome);
            }
            if verifier.artifact_ids.len() > DURABLE_JOB_MAX_REFERENCES {
                return Err(DurableJobError::LimitExceeded(
                    "outcome.verifier.artifact_ids",
                ));
            }
            let mut seen = std::collections::BTreeSet::new();
            if verifier.artifact_ids.iter().any(|id| !seen.insert(id)) {
                return Err(DurableJobError::InvalidOutcome);
            }
            if self.proof_ceiling > verifier.proof_ceiling {
                return Err(DurableJobError::ProofOverclaim);
            }
        }
        Ok(())
    }
}

/// Store/transport mutation outcome.  It is deliberately separate from the
/// semantic `UNKNOWN_OUTCOME` execution state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MutationDisposition {
    Committed,
    ProvenNotApplied,
    StillUnknown,
    Irreconcilable,
}

/// Reconciliation keeps the original stable operation identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MutationReconciliation {
    pub job_id: TaskId,
    pub attempt_id: ArtifactId,
    pub operation: OperationBinding,
    pub canonical_request_hash: String,
    pub disposition: MutationDisposition,
    pub committed_state: Option<JobState>,
    pub receipt_id: Option<ReceiptId>,
    pub evidence: Vec<ArtifactBinding>,
}

impl MutationReconciliation {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        self.operation
            .state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        bounded_text(
            &self.operation.idempotency_key,
            "reconciliation.idempotency_key",
        )?;
        bounded_text(
            &self.operation.operation_kind,
            "reconciliation.operation_kind",
        )?;
        lowercase_digest(&self.canonical_request_hash, "canonical_request_hash")?;
        validate_artifacts(&self.evidence, "reconciliation.evidence")?;
        if self.disposition == MutationDisposition::Committed
            && (self.committed_state.is_none() || self.receipt_id.is_none())
        {
            return Err(DurableJobError::InvalidField {
                field: "reconciliation",
                reason: "committed mutation requires exact state and receipt",
            });
        }
        if self.disposition == MutationDisposition::Committed && self.evidence.is_empty() {
            return Err(DurableJobError::InvalidField {
                field: "reconciliation.evidence",
                reason: "committed mutation requires evidence",
            });
        }
        if self.disposition == MutationDisposition::ProvenNotApplied && self.evidence.is_empty() {
            return Err(DurableJobError::InvalidField {
                field: "reconciliation.evidence",
                reason: "proven-not-applied mutation requires evidence",
            });
        }
        if self.disposition != MutationDisposition::Committed
            && (self.committed_state.is_some() || self.receipt_id.is_some())
        {
            return Err(DurableJobError::InvalidField {
                field: "reconciliation",
                reason: "uncommitted dispositions cannot claim state or receipt",
            });
        }
        Ok(())
    }
}

/// Strictly typed operation payloads.  There is no arbitrary next-state or
/// generic patch variant.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "operation")]
pub enum JobOperation {
    #[serde(rename = "SUBMIT_JOB")]
    Submit {
        submission: Box<JobSubmission>,
    },
    LeaseNext {
        selector: LeaseSelector,
    },
    LeaseExact {
        selector: LeaseSelector,
        job_id: TaskId,
    },
    #[serde(rename = "RENEW_LEASE")]
    Renew {
        lease: JobLease,
        now_unix_ms: u64,
    },
    #[serde(rename = "START_JOB")]
    Start {
        lease: JobLease,
        now_unix_ms: u64,
    },
    #[serde(rename = "CHECKPOINT_JOB")]
    Checkpoint {
        lease: JobLease,
        checkpoint: Box<JobCheckpoint>,
        now_unix_ms: u64,
    },
    #[serde(rename = "RESUME_JOB")]
    Resume {
        lease: JobLease,
        checkpoint: Box<JobCheckpoint>,
        now_unix_ms: u64,
    },
    BeginVerification {
        lease: JobLease,
        result: Box<OpaqueContentRef>,
        evidence: Vec<ArtifactBinding>,
        now_unix_ms: u64,
    },
    #[serde(rename = "PUBLISH_OUTCOME")]
    Publish {
        lease: JobLease,
        outcome: Box<JobOutcome>,
        now_unix_ms: u64,
    },
    Status {
        job_id: TaskId,
        attempt_id: ArtifactId,
        expected_revision: u64,
        expected_fence: StateFence,
    },
    RequestCancel {
        job_id: TaskId,
        attempt_id: ArtifactId,
        reason: String,
        requested_at_unix_ms: u64,
        expected_fence: StateFence,
    },
    #[serde(rename = "RECONCILE_MUTATION")]
    Reconcile {
        mutation: Box<MutationReconciliation>,
    },
}

impl JobOperation {
    #[must_use]
    pub const fn kind(&self) -> JobOperationKind {
        match self {
            Self::Submit { .. } => JobOperationKind::Submit,
            Self::LeaseNext { .. } => JobOperationKind::LeaseNext,
            Self::LeaseExact { .. } => JobOperationKind::LeaseExact,
            Self::Renew { .. } => JobOperationKind::Renew,
            Self::Start { .. } => JobOperationKind::Start,
            Self::Checkpoint { .. } => JobOperationKind::Checkpoint,
            Self::Resume { .. } => JobOperationKind::Resume,
            Self::BeginVerification { .. } => JobOperationKind::BeginVerification,
            Self::Publish { .. } => JobOperationKind::Publish,
            Self::Status { .. } => JobOperationKind::Status,
            Self::RequestCancel { .. } => JobOperationKind::RequestCancel,
            Self::Reconcile { .. } => JobOperationKind::Reconcile,
        }
    }

    pub fn validate(&self) -> Result<(), DurableJobError> {
        match self {
            Self::Submit { submission } => submission.validate(),
            Self::LeaseNext { selector } | Self::LeaseExact { selector, .. } => selector.validate(),
            Self::Renew { lease, now_unix_ms } | Self::Start { lease, now_unix_ms } => {
                lease.validate_active_at(*now_unix_ms)
            }
            Self::Checkpoint {
                lease,
                checkpoint,
                now_unix_ms,
            }
            | Self::Resume {
                lease,
                checkpoint,
                now_unix_ms,
            } => {
                lease.validate_active_at(*now_unix_ms)?;
                if checkpoint.state_fence != lease.state_fence {
                    return Err(DurableJobError::FenceMismatch);
                }
                checkpoint.validate()
            }
            Self::BeginVerification {
                lease,
                result,
                evidence,
                now_unix_ms,
            } => {
                lease.validate_active_at(*now_unix_ms)?;
                if evidence.is_empty() {
                    return Err(DurableJobError::InvalidField {
                        field: "verification.evidence",
                        reason: "must contain at least one artifact",
                    });
                }
                validate_artifacts(evidence, "verification.evidence")?;
                result.validate("verification.result.sha256")
            }
            Self::Publish {
                lease,
                outcome,
                now_unix_ms,
            } => {
                lease.validate_active_at(*now_unix_ms)?;
                outcome.validate()
            }
            Self::Status {
                expected_revision,
                expected_fence,
                ..
            } => {
                if *expected_revision == 0 {
                    return Err(DurableJobError::InvalidField {
                        field: "expected_revision",
                        reason: "must be positive",
                    });
                }
                expected_fence
                    .validate()
                    .map_err(DurableJobError::Foundation)
            }
            Self::RequestCancel {
                reason,
                requested_at_unix_ms,
                expected_fence,
                ..
            } => {
                bounded_text(reason, "cancel.reason")?;
                if *requested_at_unix_ms == 0 {
                    return Err(DurableJobError::InvalidField {
                        field: "cancel.requested_at_unix_ms",
                        reason: "must be positive",
                    });
                }
                expected_fence
                    .validate()
                    .map_err(DurableJobError::Foundation)
            }
            Self::Reconcile { mutation } => mutation.validate(),
        }
    }
}

/// Fresh request plus one closed operation.  The request ID is correlation;
/// the operation ID, idempotency key and canonical hash are mutation identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DurableJobRequest {
    pub request_identity: DurableRequestIdentity,
    pub role: JobRole,
    pub operation: JobOperation,
}

impl DurableJobRequest {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        self.request_identity.validate()?;
        self.operation.validate()?;
        if !matches!(self.operation, JobOperation::Reconcile { .. })
            && self.request_identity.operation.operation_kind != self.operation.kind().as_str()
        {
            return Err(DurableJobError::OperationMismatch);
        }
        validate_operation_fence(
            &self.operation,
            &self.request_identity.operation.state_fence,
        )?;
        if let JobOperation::Reconcile { mutation } = &self.operation {
            if mutation.operation != self.request_identity.operation
                || mutation.canonical_request_hash != self.request_identity.canonical_request_hash
            {
                return Err(DurableJobError::OperationMismatch);
            }
        } else {
            let expected_hash = DurableRequestIdentity::digest_for(
                &self.request_identity.operation,
                &self.request_identity.request,
                &self.operation,
                self.role,
            )?;
            if expected_hash != self.request_identity.canonical_request_hash {
                return Err(DurableJobError::OperationMismatch);
            }
        }
        if !self.role.permits(self.operation.kind()) {
            return Err(DurableJobError::CapabilityDenied);
        }
        Ok(())
    }
}

/// Pure reference history for one attempt.  It can reject illegal transitions
/// but cannot prove a database race or commit; Store owns those proofs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DurableJobRecord {
    pub submission: JobSubmission,
    pub state: JobState,
    pub revision: u64,
    pub lease: Option<JobLease>,
    pub checkpoint: Option<JobCheckpoint>,
    pub cancellation: CancellationState,
    pub outcome: Option<JobOutcome>,
}

impl DurableJobRecord {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        self.submission.validate()?;
        if self.revision == 0 {
            return Err(DurableJobError::InvalidField {
                field: "revision",
                reason: "must be positive",
            });
        }
        self.cancellation.validate()?;
        if let Some(lease) = &self.lease {
            lease.validate_shape()?;
            if lease.job_id != self.submission.job_id
                || lease.attempt_id != self.submission.attempt_id
                || lease.resource_generation != self.submission.work_scope.resource_generation
                || lease.state_fence != self.submission.work_scope.state_fence
            {
                return Err(DurableJobError::FenceMismatch);
            }
        }
        if matches!(
            self.state,
            JobState::Leased | JobState::Running | JobState::Checkpointed | JobState::Verifying
        ) && self.lease.is_none()
        {
            return Err(DurableJobError::LeaseInvalid);
        }
        if self.state == JobState::Checkpointed && self.checkpoint.is_none() {
            return Err(DurableJobError::InvalidField {
                field: "checkpoint",
                reason: "checkpointed records require a checkpoint",
            });
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate()?;
            if checkpoint.state_fence != self.submission.work_scope.state_fence {
                return Err(DurableJobError::FenceMismatch);
            }
            if let Some(lease) = &self.lease
                && checkpoint.state_fence != lease.state_fence
            {
                return Err(DurableJobError::FenceMismatch);
            }
        }
        if let Some(outcome) = &self.outcome {
            outcome.validate()?;
            if outcome.proof_ceiling > self.submission.admission.authority.proof_ceiling {
                return Err(DurableJobError::ProofOverclaim);
            }
            if outcome.state != self.state {
                return Err(DurableJobError::OutcomeMismatch);
            }
            if let Some(result) = &outcome.result
                && result.contract != self.submission.output_contract.contract
            {
                return Err(DurableJobError::OutcomeMismatch);
            }
            if let Some(verifier) = &outcome.verifier
                && verifier.state_fence != self.submission.work_scope.state_fence
            {
                return Err(DurableJobError::FenceMismatch);
            }
        }
        if self.state.is_terminal() && self.outcome.is_none() {
            return Err(DurableJobError::InvalidOutcome);
        }
        Ok(())
    }

    /// Applies only the lifecycle edge; persistence and receipt issuance are
    /// intentionally outside this contract.
    pub fn transition(&mut self, next: JobState) -> Result<(), DurableJobError> {
        if self.state.is_terminal() && self.state != next {
            return Err(DurableJobError::TerminalImmutable);
        }
        if !self.state.can_transition_to(next) {
            return Err(DurableJobError::IllegalTransition {
                from: self.state,
                to: next,
            });
        }
        if self.state == next {
            return Ok(());
        }
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableJobError::RevisionOverflow)?;
        self.state = next;
        self.revision = revision;
        Ok(())
    }

    /// Records cancellation intent without pretending the process stopped.
    pub fn request_cancel(
        &mut self,
        requester_principal: String,
        reason: String,
        operation_id: OperationId,
        requested_at_unix_ms: u64,
    ) -> Result<(), DurableJobError> {
        if self.state.is_terminal() {
            return Err(DurableJobError::TerminalImmutable);
        }
        let cancellation = CancellationState::Requested {
            requester_principal,
            reason,
            operation_id,
            requested_at_unix_ms,
        };
        cancellation.validate()?;
        let revision = self
            .revision
            .checked_add(1)
            .ok_or(DurableJobError::RevisionOverflow)?;
        self.cancellation = cancellation;
        self.revision = revision;
        Ok(())
    }
}

/// Validation failures remain bounded and do not echo supplied payloads.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DurableJobError {
    #[error("protocol request identity: {0}")]
    Protocol(#[from] super::ProtocolError),
    #[error("foundation contract: {0}")]
    Foundation(#[from] eliot_contracts::ContractError),
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
    #[error("field exceeds the bounded wire limit: {0}")]
    LimitExceeded(&'static str),
    #[error("canonical serialization failed: {0}")]
    Serialization(String),
    #[error("admission or state fence mismatch")]
    FenceMismatch,
    #[error("operation identity does not match its typed operation")]
    OperationMismatch,
    #[error("role does not have the requested capability")]
    CapabilityDenied,
    #[error("invalid or expired active lease")]
    LeaseInvalid,
    #[error("illegal lifecycle transition from {from:?} to {to:?}")]
    IllegalTransition { from: JobState, to: JobState },
    #[error("terminal execution history is immutable")]
    TerminalImmutable,
    #[error("terminal outcome is invalid")]
    InvalidOutcome,
    #[error("outcome does not match record state")]
    OutcomeMismatch,
    #[error("proof ceiling is overclaimed")]
    ProofOverclaim,
    #[error("revision overflow")]
    RevisionOverflow,
}

fn bounded_text(value: &str, field: &'static str) -> Result<(), DurableJobError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(DurableJobError::InvalidField {
            field,
            reason: "must be non-blank and contain no control characters",
        });
    }
    if value.len() > DURABLE_JOB_MAX_TEXT_BYTES {
        return Err(DurableJobError::LimitExceeded(field));
    }
    Ok(())
}

fn validate_text_list(values: &[String], field: &'static str) -> Result<(), DurableJobError> {
    if values.len() > DURABLE_JOB_MAX_REFERENCES {
        return Err(DurableJobError::LimitExceeded(field));
    }
    for value in values {
        bounded_text(value, field)?;
    }
    Ok(())
}

fn validate_artifacts(
    values: &[ArtifactBinding],
    field: &'static str,
) -> Result<(), DurableJobError> {
    if values.len() > DURABLE_JOB_MAX_REFERENCES {
        return Err(DurableJobError::LimitExceeded(field));
    }
    for artifact in values {
        if artifact.artifact_id.as_str().trim().is_empty() {
            return Err(DurableJobError::InvalidField {
                field,
                reason: "artifact_id must be non-blank",
            });
        }
        lowercase_digest(&artifact.sha256, field)?;
        if let Some(revision) = &artifact.source_revision {
            bounded_text(revision, field)?;
        }
    }
    Ok(())
}

fn validate_operation_fence(
    operation: &JobOperation,
    fence: &StateFence,
) -> Result<(), DurableJobError> {
    let target_fence = match operation {
        JobOperation::Submit { submission } => Some(&submission.work_scope.state_fence),
        JobOperation::LeaseNext { selector } | JobOperation::LeaseExact { selector, .. } => {
            Some(&selector.expected_fence)
        }
        JobOperation::Renew { lease, .. }
        | JobOperation::Start { lease, .. }
        | JobOperation::BeginVerification { lease, .. }
        | JobOperation::Publish { lease, .. } => Some(&lease.state_fence),
        JobOperation::Checkpoint {
            lease, checkpoint, ..
        }
        | JobOperation::Resume {
            lease, checkpoint, ..
        } => {
            if checkpoint.state_fence != lease.state_fence {
                return Err(DurableJobError::FenceMismatch);
            }
            Some(&lease.state_fence)
        }
        JobOperation::Status { expected_fence, .. }
        | JobOperation::RequestCancel { expected_fence, .. } => Some(expected_fence),
        JobOperation::Reconcile { mutation } => Some(&mutation.operation.state_fence),
    };
    if target_fence.is_some_and(|target| target != fence) {
        return Err(DurableJobError::FenceMismatch);
    }
    Ok(())
}

fn lowercase_digest(value: &str, field: &'static str) -> Result<(), DurableJobError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(DurableJobError::InvalidField {
            field,
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Returns the deterministic identity of the control family.
pub fn durable_job_contract_identity() -> Result<ContractIdentity, DurableJobError> {
    let shape = serde_json::json!({
        "contract": DURABLE_JOB_CONTRACT_NAME,
        "version": DURABLE_JOB_CONTRACT_VERSION,
        "encoding": DURABLE_JOB_CANONICAL_ENCODING,
        "states": ["NOT_STARTED", "QUEUED", "LEASED", "RUNNING", "CHECKPOINTED", "VERIFYING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "UNKNOWN_OUTCOME"],
        "operations": ["SUBMIT_JOB", "LEASE_NEXT", "LEASE_EXACT", "RENEW_LEASE", "START_JOB", "CHECKPOINT_JOB", "RESUME_JOB", "BEGIN_VERIFICATION", "PUBLISH_OUTCOME", "STATUS", "REQUEST_CANCEL", "RECONCILE_MUTATION"],
    });
    eliot_contracts::contract_identity(
        DURABLE_JOB_CONTRACT_NAME,
        DURABLE_JOB_CONTRACT_VERSION,
        &shape,
    )
    .map_err(DurableJobError::Foundation)
}
