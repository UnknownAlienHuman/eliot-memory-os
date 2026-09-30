//! Provider-neutral control contracts for durable Dreamer jobs.
//!
//! This module is a shape and transition boundary.  It does not persist a job,
//! start a provider, select a route, apply a candidate, or grant authority.
//! The authority, request, operation, lease, receipt and proof values carried
//! here are projections owned by their foundation crates.

use std::fmt;

use eliot_contracts::{
    ArtifactId, ContractIdentity, ContractVersion, EpochId, OperationId, ReceiptId,
    ResourceGeneration, StateFence, TaskId, canonical_json_bytes, contract_identity, sha256_hex,
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
pub const DURABLE_JOB_CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 3, 0);
/// Versioned namespace used when hashing a mutation request.
pub const DURABLE_JOB_CANONICAL_ENCODING: &str = "eliot.durable-job.canonical.v1";
/// Stable owner identity of the optional Orientation runtime execution input.
pub const RUNTIME_OWNER_EXECUTION_INPUT_CONTRACT_NAME: &str =
    "eliot.foundation.protocol.dreamer-runtime-owner-execution-input";
/// Current semantic revision of the optional runtime owner input.
pub const RUNTIME_OWNER_EXECUTION_INPUT_CONTRACT_VERSION: ContractVersion =
    ContractVersion::new(1, 0, 0);
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
    #[serde(rename = "RECORD_APPLICABILITY")]
    RecordApplicability,
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
            Self::RecordApplicability => "RECORD_APPLICABILITY",
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
    RecordApplicability,
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
                JobCapability::RecordApplicability,
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
            JobOperationKind::RecordApplicability => JobCapability::RecordApplicability,
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

    /// Verifies optional original semantic-input bytes against this exact
    /// owner-issued reference without interpreting their content.
    pub fn validate_semantic_input_bytes(
        &self,
        bytes: &[u8],
    ) -> Result<(), DurableJobError> {
        let byte_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self.byte_length != byte_length || self.sha256 != sha256_hex(bytes) {
            return Err(DurableJobError::SemanticInputMismatch);
        }
        Ok(())
    }

    /// Verifies retained bytes against this exact opaque content reference.
    pub fn validate_original_bytes(&self, bytes: &[u8]) -> Result<(), DurableJobError> {
        let byte_length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if self.byte_length != byte_length || self.sha256 != sha256_hex(bytes) {
            return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
        }
        Ok(())
    }
}

/// Typed owner material retained for the exact submitted attempt and consumed
/// by the claimed runtime. Its canonical bytes are carried beside an opaque
/// content reference in `JobSubmission` and echoed by every durable response.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DurableJobRuntimeOwnerExecutionInput {
    /// Original task identity from the admitted request metadata.
    pub task_id: TaskId,
    /// Original K0 job identity.
    pub job_id: TaskId,
    /// Original K0 attempt identity.
    pub attempt_id: ArtifactId,
    /// Original admitted scope, including its generation and fence.
    pub work_scope: WorkScopeBinding,
    /// Explicit duplicate fence for child-side direct comparison.
    pub state_fence: StateFence,
    /// Exact Kernel-issued native-worker claim ID returned by the original
    /// native launch admission. It is the lookup key for the owner's current
    /// prelaunch request/receipt/ORS readback.
    pub native_worker_claim_id: String,
    /// Exact `ContextInput` value carried by the original authenticated
    /// `TaskController` invocation.
    pub context_input: serde_json::Value,
    /// Exact rich `ContextRecipe` carried by the original invocation.
    pub context_campaign_recipe: serde_json::Value,
    /// Exact `ContextRecipePolicy` carried by the original invocation.
    pub context_campaign_recipe_policy: serde_json::Value,
    /// Exact authenticated result of the original `ContextReconstruction` query,
    /// including its owner readback, source attempt, request selectors and
    /// existing result digest.
    pub context_reconstruction_result: crate::HostRequestResultBody,
    /// Exact versioned Context compiler supplier input from the authenticated
    /// Orientation publisher. It remains separate from `ContextInput`, the
    /// recipe catalogue and `ContextReconstruction` readback.
    pub context_compilation_input: serde_json::Value,
    /// Original Governor `CampaignSourceRevisionRead` for the Orientation
    /// classification profile. The daemon preserves it opaquely; Governor
    /// performs native decoding and validates the record, receipt and fence.
    pub orientation_classification_source_readback: serde_json::Value,
    /// Original semantic-source named-read claim.
    pub semantic_source: crate::task_controller::TaskControllerOrientationSourceClaim,
    /// Original output-contract reference.
    pub output_contract: OpaqueContentRef,
    /// Original recipe's `OutputSchema` tuple.
    pub output_schema_recipe:
        crate::task_controller::TaskControllerOrientationOutputSchemaRecipe,
    /// Original named-read claim for the output schema artifact.
    pub schema_source: crate::task_controller::TaskControllerOrientationSourceClaim,
    /// Original bounded evidence-material claims.
    pub materials: Vec<crate::task_controller::TaskControllerOrientationSourceClaim>,
    /// Original source and byte limits admitted for this job.
    pub budget: crate::task_controller::TaskControllerOrientationMaterialBudget,
}

impl DurableJobRuntimeOwnerExecutionInput {
    /// Returns the declared content-addressed schema identity for this payload.
    pub fn contract_identity() -> Result<ContractIdentity, DurableJobError> {
        let shape = schemars::schema_for!(Self);
        contract_identity(
            RUNTIME_OWNER_EXECUTION_INPUT_CONTRACT_NAME,
            RUNTIME_OWNER_EXECUTION_INPUT_CONTRACT_VERSION,
            &shape,
        )
        .map_err(DurableJobError::Foundation)
    }

    /// Checks the publication's internal source and original-scope bindings.
    pub fn validate(&self) -> Result<(), DurableJobError> {
        self.validate_original_scope_and_sources()?;
        self.validate_context_reconstruction_owner_result()?;
        self.validate_source_claims()
    }

    fn validate_original_scope_and_sources(&self) -> Result<(), DurableJobError> {
        self.output_contract.validate("output_contract.sha256")?;
        self.state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        if self.work_scope.state_fence != self.state_fence
            || self.work_scope.resource_generation != self.state_fence.resource_generation
            || !self.context_input.is_object()
            || !self.context_campaign_recipe.is_object()
            || !self.context_campaign_recipe_policy.is_object()
            || !self.context_compilation_input.is_object()
            || self
                .context_compilation_input
                .get("schema_version")
                .and_then(serde_json::Value::as_u64)
                != Some(1)
            || !self.orientation_classification_source_readback.is_object()
            || self.native_worker_claim_id.trim().is_empty()
            || self.native_worker_claim_id.chars().any(char::is_control)
            || self.output_schema_recipe.schema_version == 0
            || self.output_schema_recipe.schema_digest != self.output_contract.sha256
            || self.output_contract.artifact_id.as_ref()
                != Some(&self.output_schema_recipe.schema_id)
            || self.schema_source.expected_digest != self.output_schema_recipe.schema_digest
            || self.schema_source.expected_byte_length != self.output_contract.byte_length
            || self.semantic_source.source_handle == self.schema_source.source_handle
            || self.budget.max_sources == 0
            || self.budget.max_total_bytes == 0
            || self.budget.max_source_bytes == 0
        {
            return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
        }
        Ok(())
    }

    fn validate_context_reconstruction_owner_result(&self) -> Result<(), DurableJobError> {
        self.context_reconstruction_result
            .validate_local_read_submission()
            .map_err(|_| DurableJobError::RuntimeOwnerExecutionInputMismatch)?;
        let result = &self.context_reconstruction_result;
        let response = &result.response;
        let owner_publication = response
            .get("context_reconstruction_owner_publication")
            .and_then(serde_json::Value::as_object)
            .ok_or(DurableJobError::RuntimeOwnerExecutionInputUnavailable)?;
        let request = owner_publication
            .get("request")
            .and_then(serde_json::Value::as_object)
            .ok_or(DurableJobError::RuntimeOwnerExecutionInputUnavailable)?;
        let task_plan = owner_publication
            .get("task_plan")
            .and_then(serde_json::Value::as_object)
            .ok_or(DurableJobError::RuntimeOwnerExecutionInputUnavailable)?;
        let context_recipe = owner_publication
            .get("context_recipe")
            .and_then(serde_json::Value::as_object)
            .ok_or(DurableJobError::RuntimeOwnerExecutionInputUnavailable)?;
        if response.get("operation").and_then(serde_json::Value::as_str)
            != Some("context_reconstruction")
            || response.get("task_id").and_then(serde_json::Value::as_str)
                != Some(self.task_id.as_str())
            || response.get("scope_id").and_then(serde_json::Value::as_str)
                != Some(self.work_scope.scope_id.as_str())
            || response.get("context_reconstruction").is_none()
            || request.get("task_id").and_then(serde_json::Value::as_str)
                != Some(self.task_id.as_str())
            || request.get("scope_id").and_then(serde_json::Value::as_str)
                != Some(self.work_scope.scope_id.as_str())
            || request.get("evidence_subject").and_then(serde_json::Value::as_str)
                .is_none_or(str::is_empty)
            || owner_publication.get("source_envelope").is_none()
            || owner_publication.get("source_attempt").is_none()
            || task_plan.get("recipe").is_none()
            || task_plan.get("read").is_none()
            || task_plan.get("response").is_none()
            || context_recipe.get("body").is_none()
            || context_recipe.get("read").is_none()
            || context_recipe.get("response").is_none()
        {
            return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
        }
        let envelope: crate::HostRequestEnvelope = serde_json::from_value(
            owner_publication
                .get("source_envelope")
                .cloned()
                .ok_or(DurableJobError::RuntimeOwnerExecutionInputUnavailable)?,
        )
        .map_err(|_| DurableJobError::RuntimeOwnerExecutionInputMismatch)?;
        let source_attempt: crate::LocalReadAttempt = serde_json::from_value(
            owner_publication
                .get("source_attempt")
                .cloned()
                .ok_or(DurableJobError::RuntimeOwnerExecutionInputUnavailable)?,
        )
        .map_err(|_| DurableJobError::RuntimeOwnerExecutionInputMismatch)?;
        envelope
            .validate()
            .map_err(|_| DurableJobError::RuntimeOwnerExecutionInputMismatch)?;
        source_attempt
            .validate()
            .map_err(|_| DurableJobError::RuntimeOwnerExecutionInputMismatch)?;
        if envelope.state_fence != self.state_fence
            || envelope.envelope_sha256 != result.request_sha256
            || envelope.identity.task_id.as_deref() != Some(self.task_id.as_str())
            || envelope.identity.work_scope_id.as_deref()
                != Some(self.work_scope.scope_id.as_str())
            || envelope.identity.capability != "eliot.query"
            || source_attempt.authority_epoch != self.state_fence.authority_epoch
            || source_attempt != *result.attempt.as_ref().ok_or(
                DurableJobError::RuntimeOwnerExecutionInputUnavailable,
            )?
            || source_attempt.scope_id != self.work_scope.scope_id.as_str()
        {
            return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
        }
        Ok(())
    }

    fn validate_source_claims(&self) -> Result<(), DurableJobError> {
        for claim in std::iter::once(&self.semantic_source)
            .chain(std::iter::once(&self.schema_source))
            .chain(self.materials.iter())
        {
            if claim.source_handle.trim().is_empty()
                || claim.source_handle.chars().any(char::is_control)
                || claim.privacy_class.trim().is_empty()
                || claim.privacy_class.chars().any(char::is_control)
                || claim.route_class.trim().is_empty()
                || claim.route_class.chars().any(char::is_control)
                || claim.expected_byte_length == 0
                || claim.expected_digest.len() != 64
                || claim
                    .expected_digest
                    .bytes()
                    .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
            {
                return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
            }
        }
        if self.semantic_source.expected_digest.len() != 64
            || self.semantic_source.expected_byte_length == 0
            || self.materials.iter().any(|claim| {
                claim.source_handle == self.semantic_source.source_handle
                    || claim.source_handle == self.schema_source.source_handle
            })
        {
            return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
        }
        Ok(())
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
        JobOperation::Submit { submission } => canonical_submit_payload(submission),
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
        JobOperation::RecordApplicability { update } => {
            serde_json::json!({ "operation": "RECORD_APPLICABILITY", "update": update })
        }
    }
}

fn canonical_submit_payload(submission: &JobSubmission) -> serde_json::Value {
    let mut payload = serde_json::Map::from_iter([
        ("operation".to_owned(), serde_json::json!("SUBMIT_JOB")),
        ("job_id".to_owned(), serde_json::json!(submission.job_id)),
        ("attempt_id".to_owned(), serde_json::json!(submission.attempt_id)),
        ("work_scope".to_owned(), serde_json::json!(submission.work_scope)),
        (
            "semantic_input".to_owned(),
            serde_json::json!(submission.semantic_input),
        ),
        (
            "output_contract".to_owned(),
            serde_json::json!(submission.output_contract),
        ),
        ("admission".to_owned(), serde_json::json!(submission.admission)),
        (
            "cancellation_id".to_owned(),
            serde_json::json!(submission.cancellation_id),
        ),
    ]);
    if let Some(bytes) = &submission.semantic_input_bytes {
        payload.insert(
            "semantic_input_bytes".to_owned(),
            serde_json::json!(bytes),
        );
    }
    if let Some(reference) = &submission.runtime_owner_execution_input {
        payload.insert(
            "runtime_owner_execution_input".to_owned(),
            serde_json::json!(reference),
        );
    }
    if let Some(bytes) = &submission.runtime_owner_execution_input_bytes {
        payload.insert(
            "runtime_owner_execution_input_bytes".to_owned(),
            serde_json::json!(bytes),
        );
    }
    serde_json::Value::Object(payload)
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
    pub validity_epoch: EpochId,
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
        // Exact-tuple authority checks (Implements #64): equal sequences from
        // different lineages are unrelated. `AuthorityBinding`/`SessionBinding`
        // epoch fields migrate to `EpochId` with eliot-receipts (residual owner);
        // until then this crate assumes their `EpochId` shape.
        if !self
            .authority
            .authority_epoch
            .is_same_authority(&self.validity_epoch)
            || !self
                .authority
                .state_fence
                .authority_epoch
                .is_same_authority(&self.authority.authority_epoch)
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
            && !session
                .authority_epoch
                .is_same_authority(&self.validity_epoch)
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
    /// Original inline bytes for sources that can retain them alongside the
    /// opaque identity. Absence is preserved for legacy/non-inline sources.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_input_bytes: Option<Vec<u8>>,
    /// Original runtime-owner publication reference, present only for jobs
    /// whose claimed runtime requires that owner handoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_owner_execution_input: Option<OpaqueContentRef>,
    /// Exact original canonical bytes named by `runtime_owner_execution_input`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_owner_execution_input_bytes: Option<Vec<u8>>,
    pub output_contract: OpaqueContentRef,
    pub admission: AdmissionRef,
    pub cancellation_id: String,
}

impl JobSubmission {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        self.semantic_input.validate("semantic_input.sha256")?;
        if let Some(bytes) = &self.semantic_input_bytes {
            self.semantic_input.validate_semantic_input_bytes(bytes)?;
        }
        self.output_contract.validate("output_contract.sha256")?;
        let _ = self.decode_runtime_owner_execution_input()?;
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

    /// Decodes and validates an optional original runtime owner publication.
    /// Legacy submissions preserve absence; incomplete pairs are refused.
    pub fn decode_runtime_owner_execution_input(
        &self,
    ) -> Result<Option<DurableJobRuntimeOwnerExecutionInput>, DurableJobError> {
        let (Some(reference), Some(bytes)) = (
            self.runtime_owner_execution_input.as_ref(),
            self.runtime_owner_execution_input_bytes.as_ref(),
        ) else {
            return if self.runtime_owner_execution_input.is_none()
                && self.runtime_owner_execution_input_bytes.is_none()
            {
                Ok(None)
            } else {
                Err(DurableJobError::RuntimeOwnerExecutionInputUnavailable)
            };
        };
        reference.validate("runtime_owner_execution_input.sha256")?;
        reference.validate_original_bytes(bytes)?;
        if reference.contract != DurableJobRuntimeOwnerExecutionInput::contract_identity()? {
            return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
        }
        let input: DurableJobRuntimeOwnerExecutionInput = serde_json::from_slice(bytes)
            .map_err(|_| DurableJobError::RuntimeOwnerExecutionInputMismatch)?;
        if canonical_json_bytes(&input)
            .map_err(|_| DurableJobError::RuntimeOwnerExecutionInputMismatch)?
            != *bytes
        {
            return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
        }
        input.validate()?;
        if input.job_id != self.job_id
            || input.attempt_id != self.attempt_id
            || input.work_scope != self.work_scope
            || input.state_fence != self.work_scope.state_fence
            || input.native_worker_claim_id.trim().is_empty()
            || input.semantic_source.expected_digest != self.semantic_input.sha256
            || input.semantic_source.expected_byte_length != self.semantic_input.byte_length
            || input.output_contract != self.output_contract
        {
            return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
        }
        Ok(Some(input))
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

    /// Returns the canonical digest used to bind later applicability evidence
    /// to this immutable terminal outcome.
    pub fn canonical_digest(&self) -> Result<String, DurableJobError> {
        self.validate()?;
        let bytes = canonical_json_bytes(self)
            .map_err(|error| DurableJobError::Serialization(error.to_string()))?;
        Ok(sha256_hex(&bytes))
    }
}

/// A reason an existing output can no longer be treated as applicable.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutputApplicabilityAxis {
    StateFence,
    Route,
    Dependency,
    Parent,
}

/// Applicability can only be withheld; this contract has no positive freshness
/// or verification disposition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutputApplicabilityDisposition {
    Unknown,
    NotApplicable,
    Stale,
}

/// Next owner action after applicability is withheld.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutputApplicabilityNextAction {
    ReconcileOwner,
    Revalidate,
    NewAdmission,
}

/// One exact source-to-observed change that invalidates an output projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputApplicabilityChange {
    pub axis: OutputApplicabilityAxis,
    pub source_ref: String,
    pub observed_ref: String,
    pub observed_state_fence: Option<StateFence>,
    pub evidence: Vec<ArtifactBinding>,
}

impl OutputApplicabilityChange {
    pub fn validate(&self, current_state_fence: &StateFence) -> Result<(), DurableJobError> {
        bounded_text(&self.source_ref, "applicability_change.source_ref")?;
        bounded_text(&self.observed_ref, "applicability_change.observed_ref")?;
        validate_artifacts(&self.evidence, "applicability_change.evidence")?;
        if self.evidence.is_empty() {
            return Err(DurableJobError::InvalidField {
                field: "applicability_change.evidence",
                reason: "a changed basis requires evidence",
            });
        }
        match (self.axis, &self.observed_state_fence) {
            (OutputApplicabilityAxis::StateFence, Some(observed)) => {
                observed.validate().map_err(DurableJobError::Foundation)?;
                if observed != current_state_fence {
                    return Err(DurableJobError::FenceMismatch);
                }
            }
            (OutputApplicabilityAxis::StateFence, None) | (_, Some(_)) => {
                return Err(DurableJobError::InvalidField {
                    field: "applicability_change.observed_state_fence",
                    reason: "required only for a StateFence change and must match the current fence",
                });
            }
            (_, None) => {}
        }
        Ok(())
    }
}

/// Authenticated request to withhold applicability from an existing result.
/// The Store binds the original outcome and source fence from durable history.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobOutputApplicabilityUpdate {
    pub job_id: TaskId,
    pub attempt_id: ArtifactId,
    pub expected_applicability_revision: u64,
    pub current_state_fence: StateFence,
    pub disposition: OutputApplicabilityDisposition,
    pub changed_axes: Vec<OutputApplicabilityChange>,
    pub evidence: Vec<ArtifactBinding>,
    pub next_action: OutputApplicabilityNextAction,
}

impl JobOutputApplicabilityUpdate {
    pub fn validate(&self) -> Result<(), DurableJobError> {
        if self.expected_applicability_revision > DURABLE_JOB_MAX_REFERENCES as u64 {
            return Err(DurableJobError::LimitExceeded(
                "applicability.expected_revision",
            ));
        }
        self.current_state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        if self.changed_axes.is_empty() || self.changed_axes.len() > DURABLE_JOB_MAX_REFERENCES {
            return Err(DurableJobError::InvalidField {
                field: "applicability.changed_axes",
                reason: "must contain a bounded changed basis",
            });
        }
        for change in &self.changed_axes {
            change.validate(&self.current_state_fence)?;
        }
        validate_artifacts(&self.evidence, "applicability.evidence")?;
        if self.evidence.is_empty() {
            return Err(DurableJobError::InvalidField {
                field: "applicability.evidence",
                reason: "an applicability update requires evidence",
            });
        }
        if self.disposition == OutputApplicabilityDisposition::Unknown
            && self.next_action != OutputApplicabilityNextAction::ReconcileOwner
        {
            return Err(DurableJobError::InvalidField {
                field: "applicability.next_action",
                reason: "UNKNOWN applicability requires owner reconciliation",
            });
        }
        Ok(())
    }
}

/// Immutable history entry preserving the execution outcome while recording
/// why its existing artifacts must be withheld from current proof/integration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct JobOutputApplicabilityRevision {
    pub job_id: TaskId,
    pub attempt_id: ArtifactId,
    pub revision: u64,
    pub original_state_fence: StateFence,
    pub original_outcome_digest: String,
    pub original_result: Option<OpaqueContentRef>,
    pub original_evidence: Vec<ArtifactBinding>,
    pub current_state_fence: StateFence,
    pub disposition: OutputApplicabilityDisposition,
    pub changed_axes: Vec<OutputApplicabilityChange>,
    pub evidence: Vec<ArtifactBinding>,
    pub next_action: OutputApplicabilityNextAction,
}

impl JobOutputApplicabilityRevision {
    /// Constructs one invalidation revision from the exact immutable outcome
    /// already recorded on the job. It cannot make an output current.
    pub fn from_update(
        update: &JobOutputApplicabilityUpdate,
        record: &DurableJobRecord,
        revision: u64,
    ) -> Result<Self, DurableJobError> {
        update.validate()?;
        if !record.state.is_terminal()
            || record.submission.job_id != update.job_id
            || record.submission.attempt_id != update.attempt_id
            || update.expected_applicability_revision.checked_add(1) != Some(revision)
        {
            return Err(DurableJobError::OperationMismatch);
        }
        let outcome = record
            .outcome
            .as_ref()
            .ok_or(DurableJobError::InvalidOutcome)?;
        let applicability = Self {
            job_id: update.job_id.clone(),
            attempt_id: update.attempt_id.clone(),
            revision,
            original_state_fence: record.submission.work_scope.state_fence.clone(),
            original_outcome_digest: outcome.canonical_digest()?,
            original_result: outcome.result.clone(),
            original_evidence: outcome.evidence.clone(),
            current_state_fence: update.current_state_fence.clone(),
            disposition: update.disposition,
            changed_axes: update.changed_axes.clone(),
            evidence: update.evidence.clone(),
            next_action: update.next_action,
        };
        applicability.validate_against_record(record)?;
        Ok(applicability)
    }

    pub fn validate(&self) -> Result<(), DurableJobError> {
        if self.revision == 0 || self.revision > DURABLE_JOB_MAX_REFERENCES as u64 {
            return Err(DurableJobError::InvalidField {
                field: "applicability.revision",
                reason: "must be positive and bounded",
            });
        }
        self.original_state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        self.current_state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        lowercase_digest(
            &self.original_outcome_digest,
            "applicability.original_outcome_digest",
        )?;
        if let Some(result) = &self.original_result {
            result.validate("applicability.original_result.sha256")?;
        }
        validate_artifacts(&self.original_evidence, "applicability.original_evidence")?;
        if self.original_evidence.is_empty()
            || self.changed_axes.is_empty()
            || self.changed_axes.len() > DURABLE_JOB_MAX_REFERENCES
        {
            return Err(DurableJobError::InvalidField {
                field: "applicability",
                reason: "original outcome evidence and a bounded changed basis are required",
            });
        }
        for change in &self.changed_axes {
            change.validate(&self.current_state_fence)?;
            if change.axis == OutputApplicabilityAxis::StateFence
                && change.observed_state_fence.as_ref() == Some(&self.original_state_fence)
            {
                return Err(DurableJobError::InvalidField {
                    field: "applicability.changed_axes",
                    reason: "StateFence invalidation must observe a different fence",
                });
            }
        }
        validate_artifacts(&self.evidence, "applicability.evidence")?;
        if self.evidence.is_empty() {
            return Err(DurableJobError::InvalidField {
                field: "applicability.evidence",
                reason: "an applicability revision requires evidence",
            });
        }
        if self.disposition == OutputApplicabilityDisposition::Unknown
            && self.next_action != OutputApplicabilityNextAction::ReconcileOwner
        {
            return Err(DurableJobError::InvalidField {
                field: "applicability.next_action",
                reason: "UNKNOWN applicability requires owner reconciliation",
            });
        }
        Ok(())
    }

    /// Verifies that this revision is bound to the durable execution result it
    /// describes; applicability evidence cannot replace or rewrite that result.
    pub fn validate_against_record(
        &self,
        record: &DurableJobRecord,
    ) -> Result<(), DurableJobError> {
        record.validate()?;
        if !record.state.is_terminal() {
            return Err(DurableJobError::InvalidOutcome);
        }
        let outcome = record
            .outcome
            .as_ref()
            .ok_or(DurableJobError::InvalidOutcome)?;
        if self.job_id != record.submission.job_id
            || self.attempt_id != record.submission.attempt_id
            || self.original_state_fence != record.submission.work_scope.state_fence
            || self.original_outcome_digest != outcome.canonical_digest()?
            || self.original_result != outcome.result
            || self.original_evidence != outcome.evidence
        {
            return Err(DurableJobError::OperationMismatch);
        }
        self.validate_against_outcome(outcome, &record.submission.work_scope.state_fence)?;
        for change in &self.changed_axes {
            if change.axis == OutputApplicabilityAxis::Route
                && change.source_ref != record.submission.admission.route_class
            {
                return Err(DurableJobError::OperationMismatch);
            }
        }
        Ok(())
    }

    /// Verifies outcome identity and ensures that the selected next action does
    /// not exceed the execution or freshness evidence.
    pub fn validate_against_outcome(
        &self,
        outcome: &JobOutcome,
        source_state_fence: &StateFence,
    ) -> Result<(), DurableJobError> {
        self.validate()?;
        if self.original_state_fence != *source_state_fence
            || self.original_outcome_digest != outcome.canonical_digest()?
            || self.original_result != outcome.result
            || self.original_evidence != outcome.evidence
        {
            return Err(DurableJobError::OperationMismatch);
        }
        let state_fence_changed = self.changed_axes.iter().any(|change| {
            change.axis == OutputApplicabilityAxis::StateFence
                && change.observed_state_fence.as_ref() != Some(source_state_fence)
        });
        let expected_action = if outcome.state == JobState::UnknownOutcome
            || self.disposition == OutputApplicabilityDisposition::Unknown
        {
            OutputApplicabilityNextAction::ReconcileOwner
        } else if self.disposition == OutputApplicabilityDisposition::Stale || state_fence_changed {
            OutputApplicabilityNextAction::NewAdmission
        } else {
            self.next_action
        };
        if self.next_action != expected_action {
            return Err(DurableJobError::InvalidField {
                field: "applicability.next_action",
                reason: "next action exceeds the outcome or freshness evidence",
            });
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

/// Ordering Scopes one closed Dreamer operation can prove it belongs to.
///
/// I5.5 requires the complete `ordering_scopes` set of a write envelope to be
/// declared before staging, and I14.21 requires an unknown commit to pause the
/// affected Ordering Scope instead of guessing a retry.  This value is the
/// protocol's own statement of which ordering identities a closed operation
/// carries, so an owner that has to fence, pause or display an ambiguous
/// mutation reads it instead of inferring one.
///
/// Both members are existing closed identities rather than a new taxonomy:
/// `work_scope` is the [`WorkScopeId`] the job's ledger record is ordered
/// inside, and `job_ledger` is the exact `(TaskId, ArtifactId)` pair whose one
/// ordered ledger record the operation is a compare-and-swap against.  This
/// value deliberately renders neither of them: the canonical spelling of a
/// Store ordering stream belongs to the Store contract, so no second name for
/// the same stream is minted here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DreamerOrderingScopes<'a> {
    /// The Work Scope this operation's ledger record is ordered inside, when
    /// the closed kind carries that identity on the request itself.
    pub work_scope: Option<&'a WorkScopeId>,
    /// The exact job attempt whose single ordered ledger record this
    /// operation mutates, when the closed kind binds one.
    pub job_ledger: Option<(&'a TaskId, &'a ArtifactId)>,
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
    #[serde(rename = "RECORD_APPLICABILITY")]
    RecordApplicability {
        update: Box<JobOutputApplicabilityUpdate>,
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
            Self::RecordApplicability { .. } => JobOperationKind::RecordApplicability,
        }
    }

    /// Returns the Ordering Scopes this closed operation proves it belongs to.
    ///
    /// Every kind of the closed vocabulary binds at least one, so no admitted
    /// Dreamer mutation has to reach an Ordering Scope by guesswork:
    ///
    /// ```text
    /// SUBMIT_JOB          -> work scope of the submission + its job/attempt
    /// LEASE_NEXT          -> work scope of the selector
    /// LEASE_EXACT         -> work scope of the selector
    /// RENEW_LEASE         -> the leased job/attempt ledger
    /// START_JOB           -> the leased job/attempt ledger
    /// CHECKPOINT_JOB      -> the leased job/attempt ledger
    /// RESUME_JOB          -> the leased job/attempt ledger
    /// BEGIN_VERIFICATION  -> the leased job/attempt ledger
    /// PUBLISH_OUTCOME     -> the leased job/attempt ledger
    /// STATUS              -> the observed job/attempt ledger
    /// REQUEST_CANCEL      -> the addressed job/attempt ledger
    /// RECONCILE_MUTATION  -> the reconciled job/attempt ledger
    /// ```
    ///
    /// `LEASE_EXACT` also names a `job_id`, but the attempt it will lease is
    /// resolved by the Store and is not carried on the request — its selector
    /// names the claiming worker, not the attempt — so it proves the selector's
    /// work scope and never guesses a job ledger.  The kinds that bind only a
    /// `JobLease` or a job id deliberately do not claim a work scope they do
    /// not carry; the link from their job ledger up to the Work Scope belongs
    /// to the record the Store already owns, not to the request.
    #[must_use]
    pub fn ordering_scopes(&self) -> DreamerOrderingScopes<'_> {
        match self {
            Self::Submit { submission } => DreamerOrderingScopes {
                work_scope: Some(&submission.work_scope.scope_id),
                job_ledger: Some((&submission.job_id, &submission.attempt_id)),
            },
            Self::LeaseNext { selector } | Self::LeaseExact { selector, .. } => {
                DreamerOrderingScopes {
                    work_scope: Some(&selector.scope_id),
                    job_ledger: None,
                }
            }
            Self::Renew { lease, .. }
            | Self::Start { lease, .. }
            | Self::Checkpoint { lease, .. }
            | Self::Resume { lease, .. }
            | Self::BeginVerification { lease, .. }
            | Self::Publish { lease, .. } => DreamerOrderingScopes {
                work_scope: None,
                job_ledger: Some((&lease.job_id, &lease.attempt_id)),
            },
            Self::Status {
                job_id, attempt_id, ..
            }
            | Self::RequestCancel {
                job_id, attempt_id, ..
            } => DreamerOrderingScopes {
                work_scope: None,
                job_ledger: Some((job_id, attempt_id)),
            },
            Self::RecordApplicability { update } => DreamerOrderingScopes {
                work_scope: None,
                job_ledger: Some((&update.job_id, &update.attempt_id)),
            },
            Self::Reconcile { mutation } => DreamerOrderingScopes {
                work_scope: None,
                job_ledger: Some((&mutation.job_id, &mutation.attempt_id)),
            },
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
            Self::RecordApplicability { update } => update.validate(),
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
        if let JobOperation::Submit { submission } = &self.operation
            && let Some(runtime_input) = submission.decode_runtime_owner_execution_input()?
        {
            let metadata = &self.request_identity.request.request.metadata;
            if metadata.task_id.as_ref() != Some(&runtime_input.task_id)
                || metadata.state_fence != runtime_input.state_fence
                || self.request_identity.operation.state_fence != runtime_input.state_fence
            {
                return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
            }
        }
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

/// Pure request-response binding: one owner-issued answer to one closed
/// `DurableJobRequest`.  Shape and validation only; it never persists a job,
/// issues authority, opens a transport, or launches a worker.
///
/// Denominator coverage (T12-00):
/// - fresh correlation plus stable operation/idempotency/hash: exact echo of
///   the answered `request_identity` (fresh transport correlation plus stable
///   `OperationBinding` and `canonical_request_hash`; a retry keeps the stable
///   half while the fresh half must match the answered request);
/// - job/attempt/scope/fence/epoch/generation: `job_id`, `attempt_id`, `scope`
///   (epoch and generation ride inside the scope fence and generation);
/// - exact record revision: `revision`;
/// - separate mutation disposition vs semantic lifecycle: `disposition`
///   (`None` for pure observations such as `Status`) vs `state`;
/// - owner receipt reference/digest: `receipt_id` (reference) plus the echoed
///   `canonical_request_hash` (digest);
/// - result-under-verification/result/checkpoint/lease: optional projections
///   bound below;
/// - bounded selection coverage/frontier: `selection_coverage` /
///   `selection_frontier` (`LeaseNext` only);
/// - separate applicability: the echoed identity binds which fresh request and
///   which stable mutation this response applies to; the per-kind content
///   rules in [`DurableJobResponse::validate_for`] enforce it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DurableJobResponse {
    /// Exact identity of the answered request: fresh correlation plus stable
    /// mutation binding and canonical digest.
    pub request_identity: DurableRequestIdentity,
    /// Job bound by this response.
    pub job_id: TaskId,
    /// Attempt bound by this response.
    pub attempt_id: ArtifactId,
    /// Scope/epoch/generation/fence projection for the bound job.
    pub scope: WorkScopeBinding,
    /// Original semantic input reference retained by the durable job owner.
    ///
    /// Older owner records and fixtures may not carry this projection. Such
    /// absence remains explicit (`None`) and is never treated as a ready
    /// semantic input. New Submit replies must echo the exact reference from
    /// `JobSubmission`; subsequent owner replies project it from the retained
    /// `DurableJobRecord`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_input: Option<OpaqueContentRef>,
    /// Original inline bytes retained by the durable owner when the source
    /// supplied them. Absence remains explicit for legacy/non-inline jobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_input_bytes: Option<Vec<u8>>,
    /// Original runtime-owner execution-input reference retained by the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_owner_execution_input: Option<OpaqueContentRef>,
    /// Exact original runtime-owner execution-input bytes retained by the job.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_owner_execution_input_bytes: Option<Vec<u8>>,
    /// Original output contract retained by the durable job owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_contract: Option<OpaqueContentRef>,
    /// Exact record revision observed for this response.
    pub revision: u64,
    /// Semantic lifecycle state, separate from the mutation disposition.
    pub state: JobState,
    /// Store/transport mutation outcome; `None` for pure observations.
    pub disposition: Option<MutationDisposition>,
    /// Owner receipt reference when the owner issued one.
    pub receipt_id: Option<ReceiptId>,
    /// Active lease projection when the bound state carries one.
    pub lease: Option<JobLease>,
    /// Checkpoint history when the owner retains one.
    pub checkpoint: Option<JobCheckpoint>,
    /// Result currently under verification (`Verifying` only).
    pub result_under_verification: Option<OpaqueContentRef>,
    /// Terminal outcome (terminal states only).
    pub outcome: Option<JobOutcome>,
    /// Append-only output applicability history. Missing/empty history means
    /// applicability is unknown, never implicitly current.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applicability_history: Vec<JobOutputApplicabilityRevision>,
    /// Bounded candidate coverage for `LeaseNext` selection.
    pub selection_coverage: Vec<String>,
    /// Opaque frontier cursor for `LeaseNext` selection.
    pub selection_frontier: Option<String>,
}

impl DurableJobResponse {
    /// Returns `UNKNOWN` when no applicability revision is recorded; absence
    /// of invalidation evidence never proves freshness.
    #[must_use]
    pub fn output_applicability(&self) -> OutputApplicabilityDisposition {
        self.applicability_history
            .last()
            .map_or(OutputApplicabilityDisposition::Unknown, |revision| {
                revision.disposition
            })
    }

    /// Returns the owner action for the latest applicability revision, or
    /// reconciliation when legacy history has no applicability evidence.
    #[must_use]
    pub fn next_applicability_action(&self) -> OutputApplicabilityNextAction {
        self.applicability_history
            .last()
            .map_or(OutputApplicabilityNextAction::ReconcileOwner, |revision| {
                revision.next_action
            })
    }

    /// Validates response shape without binding it to a request.
    pub fn validate(&self) -> Result<(), DurableJobError> {
        self.validate_retained_owner_inputs()?;
        self.validate_fence_and_lifecycle()?;
        self.validate_outcome_and_selection()
    }

    fn validate_retained_owner_inputs(&self) -> Result<(), DurableJobError> {
        self.request_identity.validate()?;
        if let Some(semantic_input) = &self.semantic_input {
            semantic_input.validate("semantic_input.sha256")?;
        }
        if let Some(bytes) = &self.semantic_input_bytes {
            let semantic_input = self
                .semantic_input
                .as_ref()
                .ok_or(DurableJobError::SemanticInputUnavailable)?;
            semantic_input.validate_semantic_input_bytes(bytes)?;
        }
        match (
            self.runtime_owner_execution_input.as_ref(),
            self.runtime_owner_execution_input_bytes.as_ref(),
        ) {
            (None, None) => {}
            (Some(reference), Some(bytes)) => {
                reference.validate("runtime_owner_execution_input.sha256")?;
                reference.validate_original_bytes(bytes)?;
                if reference.contract != DurableJobRuntimeOwnerExecutionInput::contract_identity()? {
                    return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
                }
                let input: DurableJobRuntimeOwnerExecutionInput = serde_json::from_slice(bytes)
                    .map_err(|_| DurableJobError::RuntimeOwnerExecutionInputMismatch)?;
                if canonical_json_bytes(&input)
                    .map_err(|_| DurableJobError::RuntimeOwnerExecutionInputMismatch)?
                    != *bytes
                {
                    return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
                }
                input.validate()?;
                if input.job_id != self.job_id
                    || input.attempt_id != self.attempt_id
                    || input.work_scope != self.scope
                    || input.state_fence != self.scope.state_fence
                {
                    return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch);
                }
                let semantic_input = self
                    .semantic_input
                    .as_ref()
                    .ok_or(DurableJobError::SemanticInputUnavailable)?;
                let semantic_input_bytes = self
                    .semantic_input_bytes
                    .as_ref()
                    .ok_or(DurableJobError::SemanticInputUnavailable)?;
                if input.semantic_source.expected_digest != semantic_input.sha256
                    || input.semantic_source.expected_byte_length != semantic_input.byte_length
                {
                    return Err(DurableJobError::SemanticInputMismatch);
                }
                semantic_input.validate_semantic_input_bytes(semantic_input_bytes)?;
                match self.output_contract.as_ref() {
                    Some(output_contract) if output_contract == &input.output_contract => {}
                    None => return Err(DurableJobError::OutputContractUnavailable),
                    Some(_) => return Err(DurableJobError::OutputContractMismatch),
                }
            }
            _ => return Err(DurableJobError::RuntimeOwnerExecutionInputUnavailable),
        }
        if let Some(output_contract) = &self.output_contract {
            output_contract.validate("output_contract.sha256")?;
        }
        Ok(())
    }

    fn validate_fence_and_lifecycle(&self) -> Result<(), DurableJobError> {
        if self.revision == 0 {
            return Err(DurableJobError::InvalidField {
                field: "revision",
                reason: "must be positive",
            });
        }
        self.scope
            .state_fence
            .validate()
            .map_err(DurableJobError::Foundation)?;
        if self.scope.resource_generation != self.scope.state_fence.resource_generation {
            return Err(DurableJobError::FenceMismatch);
        }
        if let Some(lease) = &self.lease {
            lease.validate_shape()?;
            if lease.job_id != self.job_id
                || lease.attempt_id != self.attempt_id
                || lease.resource_generation != self.scope.resource_generation
                || lease.state_fence != self.scope.state_fence
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
                reason: "checkpointed responses require a checkpoint",
            });
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate()?;
            if checkpoint.state_fence != self.scope.state_fence {
                return Err(DurableJobError::FenceMismatch);
            }
        }
        if self.state == JobState::Verifying && self.result_under_verification.is_none() {
            return Err(DurableJobError::InvalidField {
                field: "result_under_verification",
                reason: "verifying responses require a result under verification",
            });
        }
        if let Some(result) = &self.result_under_verification {
            result.validate("result_under_verification.sha256")?;
            if self.state != JobState::Verifying {
                return Err(DurableJobError::InvalidField {
                    field: "result_under_verification",
                    reason: "only admitted while verifying",
                });
            }
        }
        Ok(())
    }

    fn validate_outcome_and_selection(&self) -> Result<(), DurableJobError> {
        if let Some(outcome) = &self.outcome {
            outcome.validate()?;
            if outcome.state != self.state {
                return Err(DurableJobError::OutcomeMismatch);
            }
        }
        if self.state.is_terminal() && self.outcome.is_none() {
            return Err(DurableJobError::InvalidOutcome);
        }
        if !self.state.is_terminal() && self.outcome.is_some() {
            return Err(DurableJobError::InvalidOutcome);
        }
        self.validate_applicability_history()?;
        if self.disposition == Some(MutationDisposition::Committed) && self.receipt_id.is_none() {
            return Err(DurableJobError::InvalidField {
                field: "receipt_id",
                reason: "committed mutation requires owner receipt",
            });
        }
        validate_text_list(&self.selection_coverage, "selection_coverage")?;
        if let Some(frontier) = &self.selection_frontier {
            bounded_text(frontier, "selection_frontier")?;
        }
        Ok(())
    }

    fn validate_applicability_history(&self) -> Result<(), DurableJobError> {
        if self.applicability_history.len() > DURABLE_JOB_MAX_REFERENCES {
            return Err(DurableJobError::LimitExceeded("applicability.history"));
        }
        for (index, applicability) in self.applicability_history.iter().enumerate() {
            applicability.validate()?;
            let outcome = self
                .outcome
                .as_ref()
                .ok_or(DurableJobError::InvalidOutcome)?;
            if applicability.job_id != self.job_id
                || applicability.attempt_id != self.attempt_id
                || applicability.revision != index as u64 + 1
            {
                return Err(DurableJobError::OperationMismatch);
            }
            applicability.validate_against_outcome(outcome, &self.scope.state_fence)?;
        }
        Ok(())
    }

    /// Validates that this response answers `request`: exact identity echo
    /// (fresh correlation plus stable operation/idempotency/hash), per-kind
    /// job/scope/revision binding, disposition presence, and selection rules.
    /// Changed content under the same identity fails; an exact replay passes.
    pub fn validate_for(&self, request: &DurableJobRequest) -> Result<(), DurableJobError> {
        request.validate()?;
        self.validate()?;
        self.validate_request_identity_binding(request)?;
        self.validate_response_disposition(request)?;
        self.validate_response_operation(&request.operation)
    }

    fn validate_request_identity_binding(
        &self,
        request: &DurableJobRequest,
    ) -> Result<(), DurableJobError> {
        if self.request_identity != request.request_identity {
            return Err(DurableJobError::OperationMismatch);
        }
        let records_applicability =
            matches!(request.operation, JobOperation::RecordApplicability { .. });
        if !records_applicability
            && self.scope.state_fence != request.request_identity.operation.state_fence
        {
            return Err(DurableJobError::FenceMismatch);
        }
        if let JobOperation::RecordApplicability { update } = &request.operation
            && update.current_state_fence != request.request_identity.operation.state_fence
        {
            return Err(DurableJobError::FenceMismatch);
        }
        Ok(())
    }

    fn validate_response_disposition(
        &self,
        request: &DurableJobRequest,
    ) -> Result<(), DurableJobError> {
        let is_status = matches!(request.operation, JobOperation::Status { .. });
        if is_status != self.disposition.is_none() {
            // `Status` is a pure observation with no mutation disposition;
            // every other operation must carry one.
            return Err(DurableJobError::OperationMismatch);
        }
        let is_lease_next = matches!(request.operation, JobOperation::LeaseNext { .. });
        if !is_lease_next
            && (!self.selection_coverage.is_empty() || self.selection_frontier.is_some())
        {
            // Only `LeaseNext` performs selection; exact and direct
            // operations carry no coverage or frontier.
            return Err(DurableJobError::OperationMismatch);
        }
        Ok(())
    }

    /// Binds response content to one closed operation: job/scope/revision,
    /// published outcome, reconciled disposition, and selection coverage.
    fn validate_response_operation(&self, operation: &JobOperation) -> Result<(), DurableJobError> {
        match operation {
            JobOperation::Submit { submission } => self.validate_submit_response(submission),
            JobOperation::LeaseNext { selector } => {
                if self.scope.scope_id != selector.scope_id {
                    return Err(DurableJobError::OperationMismatch);
                }
                if self.revision != selector.expected_revision {
                    return Err(DurableJobError::OperationMismatch);
                }
                self.validate_response_selection()
            }
            JobOperation::LeaseExact { selector, job_id } => {
                if self.job_id != *job_id || self.scope.scope_id != selector.scope_id {
                    return Err(DurableJobError::OperationMismatch);
                }
                if self.revision != selector.expected_revision {
                    return Err(DurableJobError::OperationMismatch);
                }
                Ok(())
            }
            JobOperation::Renew { lease, .. }
            | JobOperation::Start { lease, .. }
            | JobOperation::Checkpoint { lease, .. }
            | JobOperation::Resume { lease, .. } => {
                validate_response_lease(self, lease)?;
                if self.revision < lease.revision {
                    // Record history only moves forward past the lease pin.
                    return Err(DurableJobError::OperationMismatch);
                }
                Ok(())
            }
            JobOperation::BeginVerification { lease, .. } => {
                validate_response_lease(self, lease)?;
                if self.revision < lease.revision || self.state != JobState::Verifying {
                    return Err(DurableJobError::OperationMismatch);
                }
                Ok(())
            }
            JobOperation::Publish { lease, outcome, .. } => {
                validate_response_lease(self, lease)?;
                if self.revision < lease.revision {
                    return Err(DurableJobError::OperationMismatch);
                }
                if self.outcome.as_ref() != Some(outcome.as_ref()) {
                    return Err(DurableJobError::OperationMismatch);
                }
                Ok(())
            }
            JobOperation::Status {
                job_id,
                attempt_id,
                expected_revision,
                ..
            } => self.validate_response_job_revision(job_id, attempt_id, *expected_revision),
            JobOperation::RequestCancel {
                job_id, attempt_id, ..
            } => self.validate_response_job_identity(job_id, attempt_id),
            JobOperation::Reconcile { mutation } => {
                if self.job_id != mutation.job_id
                    || self.attempt_id != mutation.attempt_id
                    || self.disposition != Some(mutation.disposition)
                {
                    return Err(DurableJobError::OperationMismatch);
                }
                Ok(())
            }
            JobOperation::RecordApplicability { update } => {
                self.validate_response_applicability(update)
            }
        }
    }

    fn validate_submit_response(
        &self,
        submission: &JobSubmission,
    ) -> Result<(), DurableJobError> {
        if self.job_id != submission.job_id || self.attempt_id != submission.attempt_id {
            return Err(DurableJobError::OperationMismatch);
        }
        if self.scope != submission.work_scope {
            return Err(DurableJobError::FenceMismatch);
        }
        let semantic_input = self
            .semantic_input
            .as_ref()
            .ok_or(DurableJobError::SemanticInputUnavailable)?;
        if semantic_input != &submission.semantic_input {
            return Err(DurableJobError::SemanticInputMismatch);
        }
        if self.semantic_input_bytes != submission.semantic_input_bytes {
            return Err(DurableJobError::SemanticInputMismatch);
        }
        match (
            submission.runtime_owner_execution_input.as_ref(),
            submission.runtime_owner_execution_input_bytes.as_ref(),
            self.runtime_owner_execution_input.as_ref(),
            self.runtime_owner_execution_input_bytes.as_ref(),
        ) {
            (None, None, None, None) => {}
            (Some(expected_ref), Some(expected_bytes), Some(observed_ref), Some(observed_bytes))
                if expected_ref == observed_ref && expected_bytes == observed_bytes => {}
            (Some(_), Some(_), None, None) => {
                return Err(DurableJobError::RuntimeOwnerExecutionInputUnavailable);
            }
            _ => return Err(DurableJobError::RuntimeOwnerExecutionInputMismatch),
        }
        match self.output_contract.as_ref() {
            Some(output_contract) if output_contract == &submission.output_contract => Ok(()),
            None => Err(DurableJobError::OutputContractUnavailable),
            Some(_) => Err(DurableJobError::OutputContractMismatch),
        }
    }

    fn validate_response_job_identity(
        &self,
        job_id: &TaskId,
        attempt_id: &ArtifactId,
    ) -> Result<(), DurableJobError> {
        if self.job_id == *job_id && self.attempt_id == *attempt_id {
            Ok(())
        } else {
            Err(DurableJobError::OperationMismatch)
        }
    }

    fn validate_response_job_revision(
        &self,
        job_id: &TaskId,
        attempt_id: &ArtifactId,
        expected_revision: u64,
    ) -> Result<(), DurableJobError> {
        self.validate_response_job_identity(job_id, attempt_id)?;
        if self.revision == expected_revision {
            Ok(())
        } else {
            Err(DurableJobError::OperationMismatch)
        }
    }

    fn validate_response_applicability(
        &self,
        update: &JobOutputApplicabilityUpdate,
    ) -> Result<(), DurableJobError> {
        if self.job_id != update.job_id || self.attempt_id != update.attempt_id {
            return Err(DurableJobError::OperationMismatch);
        }
        let latest = self
            .applicability_history
            .last()
            .ok_or(DurableJobError::OperationMismatch)?;
        if latest.revision != update.expected_applicability_revision.saturating_add(1)
            || latest.current_state_fence != update.current_state_fence
            || latest.disposition != update.disposition
            || latest.changed_axes != update.changed_axes
            || latest.evidence != update.evidence
            || latest.next_action != update.next_action
        {
            return Err(DurableJobError::OperationMismatch);
        }
        Ok(())
    }

    /// Requires `LeaseNext` coverage to name the bound job.
    fn validate_response_selection(&self) -> Result<(), DurableJobError> {
        if self.selection_coverage.is_empty()
            || !self
                .selection_coverage
                .iter()
                .any(|candidate| candidate.as_str() == self.job_id.as_str())
        {
            return Err(DurableJobError::OperationMismatch);
        }
        Ok(())
    }
}

/// Binds a lease-carrying response to its pinned lease identity and fence.
fn validate_response_lease(
    response: &DurableJobResponse,
    lease: &JobLease,
) -> Result<(), DurableJobError> {
    if response.job_id != lease.job_id || response.attempt_id != lease.attempt_id {
        return Err(DurableJobError::OperationMismatch);
    }
    if response.scope.state_fence != lease.state_fence {
        return Err(DurableJobError::FenceMismatch);
    }
    Ok(())
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
    #[error("runtime owner execution input reference or bytes are unavailable")]
    RuntimeOwnerExecutionInputUnavailable,
    #[error("runtime owner execution input does not match its original identity")]
    RuntimeOwnerExecutionInputMismatch,
    #[error("output contract does not match the original submission")]
    OutputContractMismatch,
    #[error("original output contract is unavailable")]
    OutputContractUnavailable,
    #[error("original semantic input reference is unavailable")]
    SemanticInputUnavailable,
    #[error(
        "semantic input reference or supplied bytes differ from the original owner record"
    )]
    SemanticInputMismatch,
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
        JobOperation::RecordApplicability { update } => Some(&update.current_state_fence),
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
        "operations": ["SUBMIT_JOB", "LEASE_NEXT", "LEASE_EXACT", "RENEW_LEASE", "START_JOB", "CHECKPOINT_JOB", "RESUME_JOB", "BEGIN_VERIFICATION", "PUBLISH_OUTCOME", "STATUS", "REQUEST_CANCEL", "RECONCILE_MUTATION", "RECORD_APPLICABILITY"],
    });
    eliot_contracts::contract_identity(
        DURABLE_JOB_CONTRACT_NAME,
        DURABLE_JOB_CONTRACT_VERSION,
        &shape,
    )
    .map_err(DurableJobError::Foundation)
}
