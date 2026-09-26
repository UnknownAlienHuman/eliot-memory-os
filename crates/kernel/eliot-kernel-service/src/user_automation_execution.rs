//! Production execution joins for the Kernel-owned UserAutomation service.
//!
//! The service owns the causal ordering at the boundary: authenticate and
//! validate the owner-issued projection, run the model-free Kernel preflight,
//! then hand an admitted occurrence to the existing Durable Job/WakeIntent
//! owners. Configuration failures go through the existing authenticated
//! notification route. This module owns no scheduler, job journal, Store,
//! authority, notification ledger, or model/provider call.

use std::collections::BTreeSet;

use eliot_contracts::{RequestMetadata, StateFence};
use eliot_kernel_core::UserAutomationOperatorIntent;
use eliot_kernel_core::user_automation::{
    AutomationCapabilityProfile, AutomationExecutionReference, AutomationReconciliationCause,
    AutomationWorkClass, ProviderFingerprintPolicy, UserAutomationConfigurationState,
    UserAutomationError, UserAutomationExecutionMode, UserAutomationExecutionProjection,
    UserAutomationFailureProjection, UserAutomationInvocation, UserAutomationPreflightContext,
    UserAutomationPreflightDecision, UserAutomationPreflightProjection,
    UserAutomationPreflightReceipt, UserAutomationRevision,
};
use eliot_protocol::dreamer_job::{DurableJobRequest, JobOperation, JobRole};
use eliot_runtime_contracts::{WakeIntent, WakeIntentState};
use eliot_store_api::{OperationId, OperationIdentity, WriteReceipt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    UserAutomationMutationResult, UserAutomationReadResult, UserAutomationService,
    UserAutomationServiceError, UserAutomationServiceRequest, UserAutomationStoreOutcome,
    UserAutomationStorePort,
};

/// Errors returned by an existing Durable Job, WakeIntent, or notification
/// owner. The service never turns an unknown owner outcome into success.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UserAutomationRuntimeError {
    /// The existing owner is not available for this operation.
    #[error("UserAutomation runtime owner is unavailable: {0}")]
    Unavailable(String),
    /// The existing owner cannot determine whether the effect was applied.
    #[error("UserAutomation runtime owner returned an unknown outcome: {0}")]
    UnknownOutcome(String),
    /// The existing owner rejected the typed request.
    #[error("UserAutomation runtime owner rejected the request: {0}")]
    Rejected(String),
    /// The existing owner returned a response for another identity.
    #[error("UserAutomation runtime owner returned a foreign identity")]
    IdentityConflict,
}

/// Errors raised while joining one authenticated occurrence to existing
/// runtime owners.
#[derive(Debug, Error)]
pub enum UserAutomationExecutionError {
    /// The authenticated service request was rejected.
    #[error("UserAutomation service: {0}")]
    Service(#[from] UserAutomationServiceError),
    /// The Kernel-owned projection failed deterministic validation.
    #[error("UserAutomation execution contract: {0}")]
    Contract(#[from] UserAutomationError),
    /// Request metadata was not valid at the execution boundary.
    #[error("UserAutomation execution metadata is invalid: {0}")]
    Metadata(String),
    /// An existing runtime owner returned a closed error.
    #[error("UserAutomation runtime: {0}")]
    Runtime(#[from] UserAutomationRuntimeError),
    /// The caller selected an operation that is not an execution join.
    #[error("UserAutomation operation is not valid for this execution join: {0}")]
    OperationMismatch(&'static str),
    /// A runtime response did not bind to the occurrence/fence that was sent.
    #[error("UserAutomation runtime response mismatch: {0}")]
    RuntimeResponseMismatch(&'static str),
}

/// Owner-issued Durable Job material for one admitted UserAutomation
/// occurrence.
///
/// The service cannot derive this request from an automation revision. The
/// existing Durable Job owner supplies the complete K0 submission, including
/// its job/attempt identities, content references, admission receipt, and
/// canonical request hash. The occurrence binding is carried beside that
/// request so the runtime adapter can prove which automation occurrence the
/// owner material belongs to.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationDurableJobMaterial {
    /// Stable UserAutomation occurrence bound by the owner.
    pub occurrence_id: String,
    /// Immutable qualified task/script identity the owner admitted.
    ///
    /// Deterministic mode is only honoured when this value is carried: a
    /// generic forwarded job without the qualified identity cannot prove that
    /// the artifact excludes model-provider access, so it is refused here
    /// instead of being handed to the Durable Job owner.
    pub qualified_ref: String,
    /// Execution mode the material was issued for.
    pub mode: UserAutomationExecutionMode,
    /// Capability profile certified by the qualified owner for this material.
    pub capability_profile: AutomationCapabilityProfile,
    /// Complete owner-issued Durable Job submission request.
    pub request: DurableJobRequest,
}

impl UserAutomationDurableJobMaterial {
    /// Validates the complete owner material against the authenticated
    /// occurrence that is about to be admitted.
    ///
    /// The capability profile is the deterministic-mode exclusion proof: a
    /// material issued for [`UserAutomationExecutionMode::DeterministicProcess`]
    /// must carry a profile without `model_access`, `provider_access`, or
    /// `automation_scheduling`, so neither a direct LLM call nor an indirect
    /// provider route is reachable through the submitted job. A generic
    /// forwarded `DurableJobRequest` that does not carry the qualified
    /// identity and a certified profile cannot satisfy this and is refused
    /// before the Durable Job owner is called.
    pub fn validate_for(
        &self,
        context: &RequestMetadata,
        authenticated_principal: &str,
        invocation: &UserAutomationInvocation,
    ) -> Result<(), UserAutomationExecutionError> {
        validate_text(&self.occurrence_id, "runtime.durable_job.occurrence_id")?;
        validate_text(&self.qualified_ref, "runtime.durable_job.qualified_ref")?;
        self.request.validate().map_err(|_| {
            UserAutomationExecutionError::RuntimeResponseMismatch("durable job material shape")
        })?;
        if self.request.role != JobRole::Requester
            || !matches!(self.request.operation, JobOperation::Submit { .. })
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material operation",
            ));
        }
        if self.occurrence_id != invocation.occurrence_identity()? {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material occurrence",
            ));
        }
        if self.mode != invocation.mode {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material mode",
            ));
        }
        if self.mode == UserAutomationExecutionMode::DeterministicProcess
            && (self.capability_profile.model_access
                || self.capability_profile.provider_access
                || self.capability_profile.automation_scheduling)
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material excludes model-provider access",
            ));
        }
        if self.request.request_identity.request.request.metadata != *context
            || self.request.request_identity.request.request.state_fence != context.state_fence
            || self.request.request_identity.operation.state_fence != context.state_fence
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material fence",
            ));
        }
        let JobOperation::Submit { submission } = &self.request.operation else {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material operation",
            ));
        };
        if submission.admission.requester_principal != authenticated_principal
            || submission.work_scope.product_id.as_str() != context.product_id.as_str()
            || submission.work_scope.state_fence != context.state_fence
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material principal",
            ));
        }
        Ok(())
    }

    /// Cross-checks the material against the preflight-approved immutable
    /// revision before the occurrence joins the existing Durable Job path.
    ///
    /// The qualified task/script identity, the execution mode, and the
    /// capability profile must equal the revision the deterministic preflight
    /// approved, so a substituted artifact or a widened profile fails closed
    /// instead of reaching a model/provider route.
    pub fn validate_for_revision(
        &self,
        context: &RequestMetadata,
        authenticated_principal: &str,
        invocation: &UserAutomationInvocation,
        revision: &UserAutomationRevision,
    ) -> Result<(), UserAutomationExecutionError> {
        self.validate_for(context, authenticated_principal, invocation)?;
        if self.mode != revision.mode
            || self.qualified_ref != revision.task.qualified_ref
            || self.capability_profile != revision.task.capability_profile
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material qualified binding",
            ));
        }
        if self.mode == UserAutomationExecutionMode::DeterministicProcess
            && (revision.work_class == AutomationWorkClass::ModelJobs
                || !matches!(
                    revision.provider_policy,
                    ProviderFingerprintPolicy::DeterministicOnly
                ))
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material deterministic revision",
            ));
        }
        Ok(())
    }
}

/// Exact owner-issued Host wake identity supplied for a cancellation.
///
/// Host resolves this identity against its canonical journal before changing
/// anything. The carrier deliberately contains no replacement record: all
/// Host-owned fence, timing, capability, safety, budget, and evidence fields
/// are copied from the journal's existing record and only the lifecycle state
/// may change.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeCancellationTarget {
    /// Automation identity assigned by the owner that selected this target.
    pub automation_id: String,
    /// Immutable revision identity assigned by the owner.
    pub automation_revision: String,
    /// Exact Host wake identity.
    pub wake_id: String,
    /// Exact Host journal operation identity.
    pub operation_id: String,
    /// Exact Host journal idempotency key.
    pub idempotency_key: String,
    /// Digest of the complete current Host wake record.
    pub record_checksum: String,
    /// Kernel State Fence carried by the existing wake intent.
    pub state_fence: StateFence,
}

impl UserAutomationWakeCancellationTarget {
    /// Validates one owner-issued target and its parent cancellation binding.
    pub fn validate_for(
        &self,
        cancellation: &UserAutomationWakeCancellation,
    ) -> Result<(), UserAutomationExecutionError> {
        for (value, field) in [
            (&self.automation_id, "cancellation.target.automation_id"),
            (
                &self.automation_revision,
                "cancellation.target.automation_revision",
            ),
            (&self.wake_id, "cancellation.target.wake_id"),
            (&self.operation_id, "cancellation.target.operation_id"),
            (&self.idempotency_key, "cancellation.target.idempotency_key"),
        ] {
            validate_text(value, field)?;
        }
        validate_digest(&self.record_checksum, "cancellation.target.record_checksum")?;
        self.state_fence
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        if self.automation_id != cancellation.automation_id
            || self.automation_revision != cancellation.automation_revision
            || self.state_fence != cancellation.state_fence
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation target binding",
            ));
        }
        Ok(())
    }
}

/// Authenticated occurrence request constructed by the Kernel selector.
///
/// The caller supplies the complete owner-issued preflight projection. It does
/// not supply ambient settings, a second principal, provider credentials, or
/// scheduler state. The service validates that projection against the live
/// request metadata before calling any runtime owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationExecutionRequest {
    /// Live authenticated request metadata and State Fence.
    pub context: RequestMetadata,
    /// Principal authenticated by the Kernel/Host route.
    pub authenticated_principal: String,
    /// Exact parent operation identity, including the canonical request digest.
    pub identity: OperationIdentity,
    /// Occurrence selected by the authenticated scheduler or Human operator.
    pub invocation: UserAutomationInvocation,
    /// Complete projection issued by the canonical configuration/preflight owner.
    pub projection: UserAutomationPreflightProjection,
    /// Existing pending wake that led to this occurrence.
    pub wake_intent: WakeIntent,
}

impl UserAutomationExecutionRequest {
    /// Validates the authenticated envelope and the immutable occurrence/wake
    /// bindings before the deterministic preflight runs.
    pub fn validate(&self) -> Result<(), UserAutomationExecutionError> {
        self.context
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        self.identity
            .validate()
            .map_err(UserAutomationServiceError::Store)
            .map_err(UserAutomationExecutionError::Service)?;
        validate_text(
            &self.authenticated_principal,
            "execution.authenticated_principal",
        )?;
        self.invocation.validate()?;
        self.wake_intent
            .validate()
            .map_err(|_| UserAutomationError::Invalid("execution.wake_intent"))?;
        if self.wake_intent.state != WakeIntentState::Pending {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "execution wake is not pending",
            ));
        }
        if self.wake_intent.state_fence != self.context.state_fence {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "execution wake fence",
            ));
        }
        let occurrence_id = self.invocation.occurrence_identity()?;
        if self.wake_intent.wake_id != occurrence_id
            || self.projection.occurrence_id != occurrence_id
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "execution occurrence identity",
            ));
        }
        if self.projection.automation_id != self.invocation.automation_id
            || self.projection.automation_revision != self.invocation.automation_revision
            || self.projection.mode != self.invocation.mode
            || self.projection.trigger_origin != self.invocation.trigger_origin
            || self.projection.child_depth != self.invocation.child_depth
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "execution projection identity",
            ));
        }
        if self.projection.revision.owner_principal != self.authenticated_principal {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "execution principal",
            ));
        }
        validate_human_invocation_source(&self.context, &self.identity, &self.invocation)?;
        Ok(())
    }
}

fn validate_human_invocation_source(
    context: &RequestMetadata,
    identity: &OperationIdentity,
    invocation: &UserAutomationInvocation,
) -> Result<(), UserAutomationExecutionError> {
    if invocation.trigger_origin
        != eliot_kernel_core::user_automation::UserAutomationTriggerOrigin::Human
    {
        return Ok(());
    }
    let provenance = invocation.require_run_now_provenance(&context.state_fence)?;
    if provenance.request_metadata != *context
        || provenance.operation_id != identity.operation_id
        || provenance.idempotency_key != identity.idempotency_key
        || provenance.canonical_request_hash != identity.canonical_request_hash
    {
        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
            "human invocation source identity",
        ));
    }
    Ok(())
}

/// Exact admitted input sent to the existing Durable Job/WakeIntent owners.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationRuntimeAdmission {
    /// Live authenticated request metadata and State Fence.
    pub context: RequestMetadata,
    /// Principal authenticated by Kernel/Host.
    pub authenticated_principal: String,
    /// Exact parent operation identity and canonical request digest.
    pub identity: OperationIdentity,
    /// Immutable revision selected by the preflight projection.
    pub revision: UserAutomationRevision,
    /// Authenticated scheduled/manual occurrence.
    pub invocation: UserAutomationInvocation,
    /// Deterministic preflight receipt that permits admission.
    pub preflight: UserAutomationPreflightReceipt,
    /// Existing pending WakeIntent bound to this occurrence.
    pub wake_intent: WakeIntent,
    /// Complete owner-issued Durable Job material. Concrete production
    /// adapters reject an admission that omits this material.
    #[serde(default)]
    pub durable_job: Option<UserAutomationDurableJobMaterial>,
}

impl UserAutomationRuntimeAdmission {
    /// Validates the exact input that an existing Durable Job owner receives.
    pub fn validate(&self) -> Result<(), UserAutomationExecutionError> {
        self.context
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        self.identity
            .validate()
            .map_err(UserAutomationServiceError::Store)
            .map_err(UserAutomationExecutionError::Service)?;
        validate_text(
            &self.authenticated_principal,
            "runtime.authenticated_principal",
        )?;
        self.revision.validate()?;
        self.invocation.validate()?;
        validate_human_invocation_source(&self.context, &self.identity, &self.invocation)?;
        self.preflight
            .source_receipt
            .validate()
            .map_err(|error| UserAutomationError::Receipt(error.to_string()))?;
        self.wake_intent
            .validate()
            .map_err(|_| UserAutomationError::Invalid("runtime.wake_intent"))?;
        if self.preflight.configuration_state != UserAutomationConfigurationState::Active
            || self.wake_intent.state != WakeIntentState::Pending
            || self.preflight.config_snapshot_id != self.preflight.config_snapshot.snapshot_id
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "runtime admission state",
            ));
        }
        if self.revision.owner_principal != self.authenticated_principal
            || self.invocation.principal_ref != self.authenticated_principal
            || self.preflight.automation_id != self.revision.automation_id
            || self.preflight.automation_revision != self.revision.revision
            || self.invocation.mode != self.revision.mode
            || self.preflight.work_class != self.revision.work_class
            || self.preflight.model_access_allowed_after_admission
                != matches!(
                    self.revision.mode,
                    eliot_kernel_core::UserAutomationExecutionMode::Agent
                )
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "runtime admission revision",
            ));
        }
        let occurrence_id = self.invocation.occurrence_identity()?;
        if self.preflight.occurrence_id != occurrence_id
            || self.wake_intent.wake_id != occurrence_id
            || self.wake_intent.state_fence != self.context.state_fence
            || self.preflight.source_receipt.core.request.state_fence != self.context.state_fence
            || self.preflight.source_receipt.core.request.metadata != self.context
            || self.preflight.source_receipt.core.work_scope.product_id != self.context.product_id
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "runtime admission occurrence/fence",
            ));
        }
        if let Some(material) = &self.durable_job {
            material.validate_for_revision(
                &self.context,
                &self.authenticated_principal,
                &self.invocation,
                &self.revision,
            )?;
        }
        Ok(())
    }
}

/// Request to the existing scheduler owner to cancel only future, unadmitted
/// wake intents for a retired revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeCancellation {
    /// Live authenticated request metadata and State Fence.
    pub context: RequestMetadata,
    /// Principal authenticated by Kernel/Host.
    pub authenticated_principal: String,
    /// Exact parent remove operation identity.
    pub identity: OperationIdentity,
    /// Retired automation identity.
    pub automation_id: String,
    /// Retired immutable revision.
    pub automation_revision: String,
    /// Fence under which the remove transition was committed.
    pub state_fence: StateFence,
    /// Fixed safety pin: admitted Durable Jobs are never cancelled here.
    pub only_unadmitted: bool,
    /// Exact owner-issued Host wake targets. Host never discovers targets by
    /// parsing a wake reason or deriving an identity.
    #[serde(default)]
    pub targets: Vec<UserAutomationWakeCancellationTarget>,
}

impl UserAutomationWakeCancellation {
    /// Validates the scheduler-owner cancellation request.
    pub fn validate(&self) -> Result<(), UserAutomationExecutionError> {
        self.context
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        self.identity
            .validate()
            .map_err(UserAutomationServiceError::Store)
            .map_err(UserAutomationExecutionError::Service)?;
        validate_text(
            &self.authenticated_principal,
            "cancellation.authenticated_principal",
        )?;
        validate_text(&self.automation_id, "cancellation.automation_id")?;
        validate_text(
            &self.automation_revision,
            "cancellation.automation_revision",
        )?;
        if !self.only_unadmitted || self.state_fence != self.context.state_fence {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation must be same-fence and unadmitted-only",
            ));
        }
        let mut wake_ids = BTreeSet::new();
        for target in &self.targets {
            target.validate_for(self)?;
            if !wake_ids.insert(target.wake_id.as_str()) {
                return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                    "duplicate cancellation target",
                ));
            }
        }
        Ok(())
    }
}

/// Exact authenticated lookup for one persisted UserAutomation wake.
///
/// The wake identity is derived from the owner-issued invocation. Callers do
/// not supply a replacement `WakeIntent`; the existing Host journal returns
/// the record that it actually retains.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeReadRequest {
    /// Original authenticated Human RunNow request metadata.
    pub context: RequestMetadata,
    /// Principal authenticated by Kernel/Host.
    pub authenticated_principal: String,
    /// Exact committed RunNow operation identity.
    pub identity: OperationIdentity,
    /// Invocation read back from the canonical UserAutomation owner.
    pub invocation: UserAutomationInvocation,
}

impl UserAutomationWakeReadRequest {
    /// Validates the request and returns its exact owner-issued occurrence ID.
    pub fn validate(&self) -> Result<String, UserAutomationExecutionError> {
        self.context
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        self.identity
            .validate()
            .map_err(UserAutomationServiceError::Store)
            .map_err(UserAutomationExecutionError::Service)?;
        validate_text(
            &self.authenticated_principal,
            "wake_read.authenticated_principal",
        )?;
        self.invocation.validate()?;
        if self.invocation.trigger_origin
            != eliot_kernel_core::user_automation::UserAutomationTriggerOrigin::Human
            || self.invocation.principal_ref != self.authenticated_principal
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake read Human source",
            ));
        }
        validate_human_invocation_source(&self.context, &self.identity, &self.invocation)?;
        self.invocation
            .occurrence_identity()
            .map_err(UserAutomationExecutionError::Contract)
    }
}

/// Exact readback from the existing Host wake journal.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeReadback {
    /// Persisted wake intent returned by the Host owner.
    pub intent: WakeIntent,
    /// Host journal operation identity for the retained wake record.
    pub operation_id: String,
    /// Host journal idempotency identity for the retained wake record.
    pub idempotency_key: String,
    /// Checksum of the exact retained Host journal record.
    pub record_checksum: String,
}

impl UserAutomationWakeReadback {
    /// Validates the persisted record against the exact Human occurrence.
    pub fn validate_for(
        &self,
        request: &UserAutomationWakeReadRequest,
    ) -> Result<(), UserAutomationExecutionError> {
        let occurrence_id = request.validate()?;
        validate_text(&self.operation_id, "wake_read.operation_id")?;
        validate_text(&self.idempotency_key, "wake_read.idempotency_key")?;
        if !is_sha256_digest(&self.record_checksum) {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake read record checksum",
            ));
        }
        self.intent.validate().map_err(|_| {
            UserAutomationExecutionError::RuntimeResponseMismatch("wake read intent shape")
        })?;
        if self.intent.wake_id != occurrence_id
            || self.intent.state_fence != request.context.state_fence
            || self.intent.state != WakeIntentState::Pending
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake read occurrence/fence/state",
            ));
        }
        Ok(())
    }
}

fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Failure record sent to the existing canonical failure-history and notify
/// owners. The stable dedup identity is the immutable revision plus the owner
/// issued failure fingerprint; the occurrence is retained as history context.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationFailureRecord {
    /// Live authenticated request metadata and State Fence.
    pub context: RequestMetadata,
    /// Principal authenticated by Kernel/Host.
    pub authenticated_principal: String,
    /// Exact parent operation identity and canonical request digest.
    pub identity: OperationIdentity,
    /// Immutable revision that owns the failure class.
    pub revision: UserAutomationRevision,
    /// Occurrence that was blocked before any model/provider call.
    pub invocation: UserAutomationInvocation,
    /// Owner-issued preflight receipt.
    pub preflight: UserAutomationPreflightReceipt,
    /// Owner-issued failure content and deterministic class fingerprint.
    pub failure: UserAutomationFailureProjection,
}

impl UserAutomationFailureRecord {
    /// Validates failure identity and same-fence notification inputs.
    pub fn validate(&self) -> Result<(), UserAutomationExecutionError> {
        self.context
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        self.identity
            .validate()
            .map_err(UserAutomationServiceError::Store)
            .map_err(UserAutomationExecutionError::Service)?;
        validate_text(
            &self.authenticated_principal,
            "failure.authenticated_principal",
        )?;
        self.revision.validate()?;
        self.invocation.validate()?;
        self.preflight
            .source_receipt
            .validate()
            .map_err(|error| UserAutomationError::Receipt(error.to_string()))?;
        self.failure
            .validate(&self.revision, &self.context.state_fence)?;
        let occurrence_id = self.invocation.occurrence_identity()?;
        if self.revision.owner_principal != self.authenticated_principal
            || self.preflight.automation_id != self.revision.automation_id
            || self.preflight.automation_revision != self.revision.revision
            || self.preflight.occurrence_id != occurrence_id
            || self.preflight.source_receipt.core.request.state_fence != self.context.state_fence
            || self.preflight.source_receipt.core.request.metadata != self.context
            || self.preflight.source_receipt.core.work_scope.product_id != self.context.product_id
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "failure identity/fence",
            ));
        }
        Ok(())
    }
}

/// Canonical result returned after failure history and notification
/// publication. `notification_receipt_ref` may be absent only when the
/// existing notification owner reported an unknown delivery outcome.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationFailurePublication {
    /// Exact parent operation identity answered by the owner.
    pub operation_id: OperationId,
    /// Parent idempotency key echoed by the owner.
    pub idempotency_key: String,
    /// Parent canonical request digest echoed by the owner.
    pub canonical_request_hash: String,
    /// Same fence under which the failure was recorded.
    pub state_fence: StateFence,
    /// Immutable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub automation_revision: String,
    /// Stable failure class fingerprint.
    pub failure_fingerprint: String,
    /// Stable occurrence retained as historical context.
    pub occurrence_id: String,
    /// Canonical failure-history record reference.
    pub history_ref: String,
    /// Notification owner deduplication key.
    pub dedup_key: String,
    /// Whether this publication converged to an existing failure class.
    pub deduplicated: bool,
    /// Existing authenticated notification delivery receipt/handle, when known.
    pub notification_receipt_ref: Option<String>,
}

impl UserAutomationFailurePublication {
    /// Validates the owner response against the exact failure record.
    pub fn validate_for(
        &self,
        request: &UserAutomationFailureRecord,
    ) -> Result<(), UserAutomationExecutionError> {
        validate_text(&self.idempotency_key, "failure.publication.idempotency_key")?;
        validate_text(
            &self.canonical_request_hash,
            "failure.publication.canonical_request_hash",
        )?;
        validate_text(&self.history_ref, "failure.publication.history_ref")?;
        validate_text(&self.dedup_key, "failure.publication.dedup_key")?;
        if let Some(receipt) = &self.notification_receipt_ref {
            validate_text(receipt, "failure.publication.notification_receipt_ref")?;
        }
        let occurrence_id = request.invocation.occurrence_identity()?;
        if self.operation_id != request.identity.operation_id
            || self.idempotency_key != request.identity.idempotency_key
            || self.canonical_request_hash != request.identity.canonical_request_hash
            || self.state_fence != request.context.state_fence
            || self.automation_id != request.revision.automation_id
            || self.automation_revision != request.revision.revision
            || self.failure_fingerprint != request.failure.failure_fingerprint
            || self.occurrence_id != occurrence_id
            || self.dedup_key != request.failure.notification.canonical.dedup_key
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "failure publication identity",
            ));
        }
        Ok(())
    }
}

/// Result of one preflight-to-runtime execution join.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationExecutionOutcome {
    /// The occurrence was admitted to the existing Durable Job lifecycle.
    Admitted {
        /// Deterministic preflight receipt.
        receipt: UserAutomationPreflightReceipt,
        /// Existing Durable Job reference returned by its owner.
        execution: AutomationExecutionReference,
    },
    /// The occurrence remains unadmitted under an existing owner policy.
    Deferred {
        /// Deterministic preflight receipt.
        receipt: UserAutomationPreflightReceipt,
        /// Explicit defer reason.
        reason: eliot_kernel_core::UserAutomationDeferReason,
    },
    /// Configuration failure was recorded and routed to the existing notify
    /// owner before any model/provider call.
    BlockedConfig {
        /// Deterministic preflight receipt.
        receipt: UserAutomationPreflightReceipt,
        /// Revision-bound failure content.
        failure: UserAutomationFailureProjection,
        /// Canonical history/notification publication result.
        publication: UserAutomationFailurePublication,
    },
}

/// Result of retiring one automation revision and cancelling future wakes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationRemovalResult {
    /// Retired immutable revision returned by the canonical Store.
    pub revision: UserAutomationRevision,
    /// Canonical Store receipt for the retirement transition.
    pub receipt: WriteReceipt,
    /// Future, unadmitted wake identities cancelled by the existing scheduler.
    pub cancelled_wake_ids: Vec<String>,
    /// Whether the Store response was an exact replay.
    pub replayed: bool,
}

/// Existing runtime composition owner for UserAutomation execution joins.
///
/// Implementations adapt these three calls to the already-owned Durable Job,
/// WakeIntent/Task Scheduler, canonical failure-history, and authenticated
/// notify routes. This trait creates no state owner and is intentionally
/// called by the production service method, not only by tests.
#[allow(async_fn_in_trait)]
pub trait UserAutomationRuntimePort: Send + Sync {
    /// Admits one preflight-approved occurrence to the existing Durable Job
    /// and WakeIntent owners.
    async fn admit_occurrence(
        &self,
        request: UserAutomationRuntimeAdmission,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError>;

    /// Cancels only future, unadmitted wakes for a retired revision.
    async fn cancel_pending_wakes(
        &self,
        request: UserAutomationWakeCancellation,
    ) -> Result<Vec<String>, UserAutomationRuntimeError>;

    /// Writes immutable failure history and calls the existing authenticated
    /// `deliver_user_automation_failure` notification route.
    async fn deliver_user_automation_failure(
        &self,
        request: UserAutomationFailureRecord,
    ) -> Result<UserAutomationFailurePublication, UserAutomationRuntimeError>;
}

/// Canonical failure-history result returned by the existing Store owner.
///
/// The Store owner must echo the complete immutable failure identity. The
/// service uses this response to prevent a history row for another operation,
/// revision, occurrence, or State Fence from being presented as success.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationFailureHistory {
    /// Exact parent operation answered by the Store owner.
    pub operation_id: OperationId,
    /// Parent idempotency key echoed by the Store owner.
    pub idempotency_key: String,
    /// Parent canonical request digest echoed by the Store owner.
    pub canonical_request_hash: String,
    /// Fence under which the history row was observed.
    pub state_fence: StateFence,
    /// Immutable automation identity.
    pub automation_id: String,
    /// Immutable revision identity.
    pub automation_revision: String,
    /// Stable failure class fingerprint.
    pub failure_fingerprint: String,
    /// Stable occurrence retained by failure history.
    pub occurrence_id: String,
    /// Canonical failure-history record reference.
    pub history_ref: String,
    /// Store-side deduplication key for this failure class.
    pub dedup_key: String,
    /// Whether the Store converged to an existing failure row.
    pub deduplicated: bool,
}

impl UserAutomationFailureHistory {
    /// Validates the Store response against the exact failure record sent.
    pub fn validate_for(
        &self,
        request: &UserAutomationFailureRecord,
    ) -> Result<(), UserAutomationExecutionError> {
        validate_text(&self.idempotency_key, "failure.history.idempotency_key")?;
        validate_text(
            &self.canonical_request_hash,
            "failure.history.canonical_request_hash",
        )?;
        validate_text(&self.history_ref, "failure.history.history_ref")?;
        validate_text(&self.dedup_key, "failure.history.dedup_key")?;
        let occurrence_id = request.invocation.occurrence_identity()?;
        if self.operation_id != request.identity.operation_id
            || self.idempotency_key != request.identity.idempotency_key
            || self.canonical_request_hash != request.identity.canonical_request_hash
            || self.state_fence != request.context.state_fence
            || self.automation_id != request.revision.automation_id
            || self.automation_revision != request.revision.revision
            || self.failure_fingerprint != request.failure.failure_fingerprint
            || self.occurrence_id != occurrence_id
            || self.dedup_key != request.failure.notification.canonical.dedup_key
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "failure history identity",
            ));
        }
        Ok(())
    }
}

/// Authenticated notification result returned by the B3 notification owner.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationNotificationDelivery {
    /// State Fence observed by the notification owner.
    pub state_fence: StateFence,
    /// Notification deduplication key echoed by the owner.
    pub dedup_key: String,
    /// Whether notification delivery converged to an existing notification.
    pub deduplicated: bool,
    /// Existing authenticated notification receipt, when delivery is known.
    pub notification_receipt_ref: Option<String>,
}

impl UserAutomationNotificationDelivery {
    /// Validates the notification response against the exact failure record.
    pub fn validate_for(
        &self,
        request: &UserAutomationFailureRecord,
    ) -> Result<(), UserAutomationExecutionError> {
        validate_text(&self.dedup_key, "notification.delivery.dedup_key")?;
        if let Some(receipt) = &self.notification_receipt_ref {
            validate_text(receipt, "notification.delivery.receipt_ref")?;
        }
        if self.state_fence != request.context.state_fence
            || self.dedup_key != request.failure.notification.canonical.dedup_key
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "notification delivery identity",
            ));
        }
        Ok(())
    }
}

/// Existing Durable Job owner used by the production runtime composition.
///
/// The admitted occurrence is the same typed projection the authenticated Host
/// carrier holds, so the port accepts it owned or already boxed and the
/// boundary keeps one payload shape either way.
#[allow(async_fn_in_trait)]
pub trait UserAutomationDurableJobPort: Send + Sync {
    /// Admits one preflight-approved occurrence to the existing job lifecycle.
    async fn admit_occurrence(
        &self,
        request: impl Into<Box<UserAutomationRuntimeAdmission>>,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError>;
}

/// Existing WakeIntent/Task Scheduler owner used by the production runtime
/// composition.
///
/// Both wake payloads take the same owned-or-boxed form as
/// [`UserAutomationDurableJobPort::admit_occurrence`].
#[allow(async_fn_in_trait)]
pub trait UserAutomationWakePort: Send + Sync {
    /// Reads one exact persisted Pending wake from the existing owner.
    /// Implementations without a readback path fail closed.
    async fn read_pending_wake(
        &self,
        _request: impl Into<Box<UserAutomationWakeReadRequest>>,
    ) -> Result<UserAutomationWakeReadback, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "UserAutomation wake readback is unavailable".to_owned(),
        ))
    }

    /// Cancels only unadmitted wakes for a retired revision.
    async fn cancel_pending_wakes(
        &self,
        request: impl Into<Box<UserAutomationWakeCancellation>>,
    ) -> Result<Vec<String>, UserAutomationRuntimeError>;
}

/// Existing canonical Store owner used to persist immutable failure history.
#[allow(async_fn_in_trait)]
pub trait UserAutomationFailureHistoryPort: Send + Sync {
    /// Records or replays one revision-bound failure-history row.
    async fn record_failure(
        &self,
        request: UserAutomationFailureRecord,
    ) -> Result<UserAutomationFailureHistory, UserAutomationRuntimeError>;
}

/// Existing authenticated B3 notification owner.
#[allow(async_fn_in_trait)]
pub trait UserAutomationNotificationPort: Send + Sync {
    /// Delivers or reconciles one already-recorded automation failure.
    async fn deliver_user_automation_failure(
        &self,
        request: UserAutomationFailureRecord,
    ) -> Result<UserAutomationNotificationDelivery, UserAutomationRuntimeError>;
}

/// Production composition of the existing UserAutomation runtime owners.
///
/// This adapter owns no mutable state. It only sequences the already-owned
/// ports: Durable Job admission, WakeIntent cancellation, canonical failure
/// history, and the authenticated B3 notification route. The failure path
/// records history before notification so a notification retry can reconcile
/// against one immutable history identity.
pub struct UserAutomationRuntimeComposition<'a, D: ?Sized, W: ?Sized, H: ?Sized, N: ?Sized> {
    durable_job: &'a D,
    wake: &'a W,
    failure_history: &'a H,
    notification: &'a N,
}

impl<'a, D: ?Sized, W: ?Sized, H: ?Sized, N: ?Sized>
    UserAutomationRuntimeComposition<'a, D, W, H, N>
{
    /// Borrows the already-composed owner ports without creating a lifecycle.
    #[must_use]
    pub const fn new(
        durable_job: &'a D,
        wake: &'a W,
        failure_history: &'a H,
        notification: &'a N,
    ) -> Self {
        Self {
            durable_job,
            wake,
            failure_history,
            notification,
        }
    }
}

impl<'a, D: ?Sized, W: ?Sized, H: ?Sized, N: ?Sized> UserAutomationRuntimePort
    for UserAutomationRuntimeComposition<'a, D, W, H, N>
where
    D: UserAutomationDurableJobPort,
    W: UserAutomationWakePort,
    H: UserAutomationFailureHistoryPort,
    N: UserAutomationNotificationPort,
{
    async fn admit_occurrence(
        &self,
        request: UserAutomationRuntimeAdmission,
    ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let execution = self.durable_job.admit_occurrence(request).await?;
        execution
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        Ok(execution)
    }

    async fn cancel_pending_wakes(
        &self,
        request: UserAutomationWakeCancellation,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let cancelled = self.wake.cancel_pending_wakes(request).await?;
        validate_unique_text_list(&cancelled, "cancelled_wake_ids")
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        Ok(cancelled)
    }

    async fn deliver_user_automation_failure(
        &self,
        request: UserAutomationFailureRecord,
    ) -> Result<UserAutomationFailurePublication, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let history = self.failure_history.record_failure(request.clone()).await?;
        history
            .validate_for(&request)
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let delivery = self
            .notification
            .deliver_user_automation_failure(request.clone())
            .await?;
        delivery
            .validate_for(&request)
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        Ok(UserAutomationFailurePublication {
            operation_id: request.identity.operation_id,
            idempotency_key: request.identity.idempotency_key,
            canonical_request_hash: request.identity.canonical_request_hash,
            state_fence: request.context.state_fence,
            automation_id: request.revision.automation_id,
            automation_revision: request.revision.revision,
            failure_fingerprint: request.failure.failure_fingerprint,
            occurrence_id: request
                .invocation
                .occurrence_identity()
                .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?,
            history_ref: history.history_ref,
            dedup_key: history.dedup_key,
            deduplicated: history.deduplicated || delivery.deduplicated,
            notification_receipt_ref: delivery.notification_receipt_ref,
        })
    }
}

impl<'a, P: UserAutomationStorePort + ?Sized> UserAutomationService<'a, P> {
    /// Runs deterministic preflight and then joins one occurrence to the
    /// existing Durable Job/WakeIntent composition.
    ///
    /// No model/provider call is reachable before `preflight` returns
    /// `Admitted`; blocked configuration calls the existing failure/notify
    /// owner and returns its identity-bound publication.
    pub async fn execute_occurrence<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationExecutionRequest,
        runtime: &R,
    ) -> Result<UserAutomationExecutionOutcome, UserAutomationExecutionError> {
        self.execute_occurrence_with_material(request, None, runtime)
            .await
    }

    /// Executes one occurrence with the complete owner-issued Durable Job
    /// material. This is the production entry point used by the authenticated
    /// selector once the existing Durable Job owner has supplied its typed
    /// submission.
    pub async fn execute_occurrence_with_durable_job<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationExecutionRequest,
        durable_job: UserAutomationDurableJobMaterial,
        runtime: &R,
    ) -> Result<UserAutomationExecutionOutcome, UserAutomationExecutionError> {
        self.execute_occurrence_with_material(request, Some(durable_job), runtime)
            .await
    }

    async fn execute_occurrence_with_material<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationExecutionRequest,
        durable_job: Option<UserAutomationDurableJobMaterial>,
        runtime: &R,
    ) -> Result<UserAutomationExecutionOutcome, UserAutomationExecutionError> {
        request.validate()?;
        // Execution admission consumes the complete, fail-closed owner view, not
        // a bounded subset of it (issue #2808). An occurrence denominator the
        // owner could not prove complete is missing coverage evidence, which is
        // `unknown` rather than "no unresolved effect" (I5.16), so it is refused
        // here instead of being reported as an ordinary preflight deferral that a
        // caller could retry as if it were transient capacity. Preflight still
        // owns the genuinely unresolved-effect case, where the correct outcome is
        // `Deferred { ReconciliationRequired }`.
        require_complete_occurrence_view(&request.projection.execution)?;
        let context = UserAutomationPreflightContext {
            request_metadata: request.context.clone(),
        };
        let decision = request
            .projection
            .preflight(&request.invocation, &context)?;
        match decision {
            UserAutomationPreflightDecision::Admitted { receipt } => {
                let admission = UserAutomationRuntimeAdmission {
                    context: request.context,
                    authenticated_principal: request.authenticated_principal,
                    identity: request.identity,
                    revision: request.projection.revision,
                    invocation: request.invocation,
                    preflight: receipt.clone(),
                    wake_intent: request.wake_intent,
                    durable_job,
                };
                admission.validate()?;
                let execution = runtime.admit_occurrence(admission).await?;
                execution.validate()?;
                if execution.occurrence_id != receipt.occurrence_id {
                    return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                        "durable job occurrence",
                    ));
                }
                Ok(UserAutomationExecutionOutcome::Admitted { receipt, execution })
            }
            UserAutomationPreflightDecision::Deferred { receipt, reason } => {
                Ok(UserAutomationExecutionOutcome::Deferred { receipt, reason })
            }
            UserAutomationPreflightDecision::BlockedConfig { receipt, failure } => {
                let failure_record = UserAutomationFailureRecord {
                    context: request.context,
                    authenticated_principal: request.authenticated_principal,
                    identity: request.identity,
                    revision: request.projection.revision,
                    invocation: request.invocation,
                    preflight: receipt.clone(),
                    failure: failure.clone(),
                };
                failure_record.validate()?;
                let publication = runtime
                    .deliver_user_automation_failure(failure_record.clone())
                    .await?;
                publication.validate_for(&failure_record)?;
                Ok(UserAutomationExecutionOutcome::BlockedConfig {
                    receipt,
                    failure,
                    publication,
                })
            }
        }
    }

    /// Executes a canonical `run-now` Store operation and then joins its
    /// explicit manual-nonce occurrence through the same preflight/runtime
    /// path used by scheduled wakes.
    pub async fn run_now_and_execute<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        projection: UserAutomationPreflightProjection,
        runtime: &R,
    ) -> Result<UserAutomationExecutionOutcome, UserAutomationExecutionError> {
        self.run_now_and_execute_with_material(request, projection, None, runtime)
            .await
    }

    /// Runs a canonical `run-now` operation and joins its occurrence with
    /// complete owner-issued Durable Job material.
    pub async fn run_now_and_execute_with_durable_job<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        projection: UserAutomationPreflightProjection,
        durable_job: UserAutomationDurableJobMaterial,
        runtime: &R,
    ) -> Result<UserAutomationExecutionOutcome, UserAutomationExecutionError> {
        self.run_now_and_execute_with_material(request, projection, Some(durable_job), runtime)
            .await
    }

    async fn run_now_and_execute_with_material<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        projection: UserAutomationPreflightProjection,
        durable_job: Option<UserAutomationDurableJobMaterial>,
        runtime: &R,
    ) -> Result<UserAutomationExecutionOutcome, UserAutomationExecutionError> {
        if !matches!(
            &request.intent.operation,
            eliot_kernel_core::UserAutomationOperation::RunNow { .. }
        ) {
            return Err(UserAutomationExecutionError::OperationMismatch(
                "execution method requires run-now",
            ));
        }
        let response = self.dispatch(request.clone()).await?;
        let (result, _replayed) = match response.outcome {
            UserAutomationStoreOutcome::Committed { result, .. } => (result, false),
            UserAutomationStoreOutcome::Replayed { result, .. } => (result, true),
            UserAutomationStoreOutcome::Read { .. } => {
                return Err(UserAutomationExecutionError::OperationMismatch(
                    "run-now returned a read response",
                ));
            }
        };
        let UserAutomationMutationResult::RunNow {
            invocation,
            wake_intent,
        } = result
        else {
            return Err(UserAutomationExecutionError::OperationMismatch(
                "run-now returned a non-run result",
            ));
        };
        self.execute_occurrence_with_material(
            UserAutomationExecutionRequest {
                context: request.context,
                authenticated_principal: request.authenticated_principal,
                identity: request.identity,
                invocation,
                projection,
                wake_intent,
            },
            durable_job,
            runtime,
        )
        .await
    }

    /// Retires one revision through the canonical Store and then asks the
    /// existing scheduler owner to cancel only unadmitted future wakes.
    pub async fn remove_and_cancel<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        runtime: &R,
    ) -> Result<UserAutomationRemovalResult, UserAutomationExecutionError> {
        self.remove_and_cancel_with_targets(request, Vec::new(), runtime)
            .await
    }

    /// Reads the complete owner execution view for one automation through the
    /// same `Status` read every other consumer uses, and refuses when the
    /// declared occurrence denominator is not owner-proven complete.
    ///
    /// The Store adapter builds `unresolved_reconciliation_refs` over the
    /// complete declared denominator by paging it under one owner-issued read
    /// revision, and records a denominator it could not prove complete as an
    /// [`AutomationReconciliationCause::IncompleteDenominator`] obligation
    /// carrying the durable owner query handle rather than as an empty set
    /// (issue #2808, I5.16). Reading it here is what makes the runtime
    /// boundaries — execution admission and wake cancellation — consume that
    /// complete view instead of a bounded subset of it.
    ///
    /// The read is deliberately bounded: the projection carries typed
    /// references plus one durable query handle, never unbounded history rows,
    /// and `current_execution_refs` stays the stored Durable Job projection, so
    /// Durable Job history is not duplicated. The `Status` leg is the canonical
    /// read for exactly this reason; `History` carries the same projection but
    /// additionally walks the immutable revision denominator, which the runtime
    /// boundary does not need.
    ///
    /// The read reuses the caller's admitted operation identity rather than
    /// minting one: this service never creates a canonical operation identity,
    /// it only carries the identity the authenticated route admitted. The read
    /// issues no transition and no receipt, so the retirement or execution the
    /// caller came for is unaffected by it.
    pub async fn owner_execution_view(
        &self,
        request: &UserAutomationServiceRequest,
        automation_id: &str,
    ) -> Result<UserAutomationExecutionProjection, UserAutomationExecutionError> {
        let response = self
            .dispatch(UserAutomationServiceRequest {
                context: request.context.clone(),
                authenticated_principal: request.authenticated_principal.clone(),
                identity: request.identity.clone(),
                intent: UserAutomationOperatorIntent {
                    intent_id: format!("{}:owner-execution-view", request.intent.intent_id),
                    principal_ref: request.authenticated_principal.clone(),
                    state_fence: request.context.state_fence.clone(),
                    operation: eliot_kernel_core::UserAutomationOperation::Status {
                        automation_id: automation_id.to_owned(),
                    },
                },
            })
            .await?;
        match response.outcome {
            UserAutomationStoreOutcome::Read {
                result: UserAutomationReadResult::Status { execution, .. },
            } => {
                require_complete_occurrence_view(&execution)?;
                Ok(execution)
            }
            _ => Err(UserAutomationExecutionError::OperationMismatch(
                "owner execution view did not return a status projection",
            )),
        }
    }

    /// Retires one revision and cancels the exact owner-issued pending wake
    /// targets observed for that revision.
    pub async fn remove_and_cancel_with_targets<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        targets: Vec<UserAutomationWakeCancellationTarget>,
        runtime: &R,
    ) -> Result<UserAutomationRemovalResult, UserAutomationExecutionError> {
        let (automation_id, automation_revision) = match &request.intent.operation {
            eliot_kernel_core::UserAutomationOperation::Remove {
                automation_id,
                automation_revision,
            } => (automation_id.clone(), automation_revision.clone()),
            _ => {
                return Err(UserAutomationExecutionError::OperationMismatch(
                    "remove-and-cancel requires remove",
                ));
            }
        };
        // Wake cancellation acts on the same complete, fail-closed owner view as
        // execution admission (issue #2808). `remove_and_cancel_with_targets`
        // is one of the four consumer legs of the single `execution_projection`
        // constructor, and the Store's retirement gate refuses to commit the
        // transition unless the declared occurrence denominator is owner-proven
        // complete at one read revision. Asserting the same gate on the
        // cancellation that follows the commit means the scheduler owner is
        // never asked to cancel from a bounded subset, and a Store adapter that
        // did not gate the retirement is caught here rather than silently
        // proceeding. Retirement itself is never refused because an effect is
        // unresolved: those obligations are preserved verbatim.
        let owner_view = self.owner_execution_view(&request, &automation_id).await?;
        require_complete_occurrence_view(&owner_view)?;
        let response = self.dispatch(request.clone()).await?;
        let (receipt, result, replayed) = match response.outcome {
            UserAutomationStoreOutcome::Committed { receipt, result } => (receipt, result, false),
            UserAutomationStoreOutcome::Replayed { receipt, result } => (receipt, result, true),
            UserAutomationStoreOutcome::Read { .. } => {
                return Err(UserAutomationExecutionError::OperationMismatch(
                    "remove returned a read response",
                ));
            }
        };
        let UserAutomationMutationResult::Revision { revision, .. } = result else {
            return Err(UserAutomationExecutionError::OperationMismatch(
                "remove returned a non-revision result",
            ));
        };
        if revision.automation_id != automation_id
            || revision.revision != automation_revision
            || revision.configuration_state != UserAutomationConfigurationState::Retired
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "remove revision",
            ));
        }
        let cancellation = UserAutomationWakeCancellation {
            context: request.context.clone(),
            authenticated_principal: request.authenticated_principal,
            identity: request.identity,
            automation_id,
            automation_revision,
            state_fence: request.context.state_fence.clone(),
            only_unadmitted: true,
            targets,
        };
        cancellation.validate()?;
        let cancelled_wake_ids = runtime.cancel_pending_wakes(cancellation).await?;
        validate_unique_text_list(&cancelled_wake_ids, "cancelled_wake_ids")?;
        Ok(UserAutomationRemovalResult {
            revision,
            receipt,
            cancelled_wake_ids,
            replayed,
        })
    }
}

/// Refuses a runtime boundary whose owner view is not a complete, fail-closed
/// occurrence denominator.
///
/// The canonical Store adapter builds `unresolved_reconciliation_refs` over the
/// complete declared denominator, paging it under one owner-issued read
/// revision, and encodes a denominator it could not prove complete as an
/// [`AutomationReconciliationCause::IncompleteDenominator`] obligation carrying
/// the durable owner query handle — never as an empty set (issue #2808, I5.16).
///
/// This is the shared fail-closed gate for the two runtime boundaries that act
/// on automation state: execution admission (`execute_occurrence_with_material`)
/// and wake cancellation (`remove_and_cancel_with_targets`). An unresolved
/// effect on any page therefore blocks identically to one on the first page, and
/// an incomplete denominator blocks as recovery-required instead of letting the
/// boundary act on a bounded subset. The gate reads only the caller's typed
/// projection: it loads no extra history, and Durable Job history is not
/// duplicated because `current_execution_refs` stays the stored Durable Job
/// projection.
fn require_complete_occurrence_view(
    execution: &UserAutomationExecutionProjection,
) -> Result<(), UserAutomationExecutionError> {
    if execution
        .unresolved_reconciliation_refs
        .iter()
        .any(|obligation| obligation.cause == AutomationReconciliationCause::IncompleteDenominator)
    {
        return Err(UserAutomationExecutionError::Contract(
            UserAutomationError::Invalid("execution.occurrence_denominator"),
        ));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), UserAutomationExecutionError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(UserAutomationExecutionError::Contract(
            UserAutomationError::Invalid(field),
        ));
    }
    Ok(())
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), UserAutomationExecutionError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(UserAutomationExecutionError::Contract(
            UserAutomationError::Invalid(field),
        ));
    }
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        return Err(UserAutomationExecutionError::Contract(
            UserAutomationError::Invalid(field),
        ));
    }
    Ok(())
}

fn validate_unique_text_list(
    values: &[String],
    field: &'static str,
) -> Result<(), UserAutomationExecutionError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !unique.insert(value) {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "duplicate cancellation identity",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, PolicyRevision, ProductId, RequestId,
        ResourceGeneration, SessionId, SourceId,
    };
    use eliot_kernel_core::user_automation::{
        AutomationCapabilityProfile, AutomationDeliveryTarget, AutomationResourceCeiling,
        AutomationTaskBinding, AutomationTaskKind, AutomationWorkClass, AutomationWorkScope,
        DeliveryChannel, DstFoldPolicy, DstGapPolicy, NormalizedSchedule, NotificationDraft,
        OverlapPolicy, ProviderFingerprintPolicy, RecursionPolicy, RouteCostPolicy, ScheduleKind,
        USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION, USER_AUTOMATION_SCOPE,
        UserAutomationExecutionMode, UserAutomationExecutionProjection,
        UserAutomationFailureReason, UserAutomationTrigger, UserAutomationTriggerOrigin,
    };
    use eliot_kernel_core::{
        AutomationExecutionReference, AutomationFailureNotificationProjection,
        UserAutomationConfigurationState,
    };
    use eliot_protocol::JobState;
    use eliot_receipts::ReceiptEnvelope;
    use eliot_store_api::{StoreError, WriteReceipt};
    use std::num::NonZeroU64;
    use std::sync::{Arc, Mutex};

    fn state_fence() -> StateFence {
        let epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
            NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        let mut fence = StateFence::new(epoch, ResourceGeneration::genesis());
        fence.policy_revision = Some(PolicyRevision::genesis());
        fence
    }

    fn metadata() -> RequestMetadata {
        RequestMetadata {
            request_id: RequestId::new("automation-request").expect("request"),
            session_id: Some(SessionId::new("session-1").expect("session")),
            task_id: None,
            product_id: ProductId::new("eliot-test").expect("product"),
            source_id: SourceId::new("eliot-user-automation").expect("source"),
            state_fence: state_fence(),
            clock: ClockReading {
                valid_time_ms: Some(1),
                known_time_ms: Some(1),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
        }
    }

    fn revision(state: UserAutomationConfigurationState) -> UserAutomationRevision {
        UserAutomationRevision {
            automation_id: "automation-1".to_owned(),
            revision: "revision-7".to_owned(),
            supersedes: None,
            owner_principal: "human-1".to_owned(),
            work_scope: AutomationWorkScope {
                scope_id: "scope-1".to_owned(),
                product_id: "eliot-test".to_owned(),
                workdir_ref: "workdir-1".to_owned(),
            },
            natural_language_intent: "run the qualified deterministic check".to_owned(),
            schedule: NormalizedSchedule {
                kind: ScheduleKind::Recurring,
                expression: "at 12:00".to_owned(),
                calendar: "gregorian".to_owned(),
                timezone: "America/New_York".to_owned(),
                dst_fold: DstFoldPolicy::First,
                dst_gap: DstGapPolicy::ShiftForward,
                start_at: "2026-09-21T00:00:00Z".to_owned(),
                end_at: None,
                next_occurrences: vec!["2026-09-21T12:00:00-04:00".to_owned()],
            },
            mode: UserAutomationExecutionMode::DeterministicProcess,
            task: AutomationTaskBinding {
                qualified_ref: "script:checks/v1".to_owned(),
                kind: AutomationTaskKind::QualifiedScript,
                capability_profile: AutomationCapabilityProfile {
                    model_access: false,
                    provider_access: false,
                    automation_scheduling: false,
                },
            },
            portable_skill_package_revision_refs: vec!["skill-package@1".to_owned()],
            workdir_ref: "workdir-1".to_owned(),
            route_cost_policy: RouteCostPolicy {
                route_ref: "deterministic-local".to_owned(),
                max_cost_units: 1,
                max_duration_ms: 1_000,
                policy_revision: Some(PolicyRevision::genesis()),
            },
            provider_policy: ProviderFingerprintPolicy::DeterministicOnly,
            delivery_target: AutomationDeliveryTarget {
                target_ref: "human-1".to_owned(),
                channels: vec![DeliveryChannel::ControlBoard],
                recipient_refs: vec!["human-1".to_owned()],
            },
            preflight_contract_revision: USER_AUTOMATION_PREFLIGHT_CONTRACT_REVISION.to_owned(),
            resource_ceiling: AutomationResourceCeiling {
                max_runtime_ms: 1_000,
                max_output_bytes: 4_096,
                max_child_count: 0,
            },
            overlap_policy: OverlapPolicy::ForbidOverlap,
            recursion_policy: RecursionPolicy {
                allow_child_automation: false,
                max_child_depth: 0,
            },
            configuration_state: state,
            work_class: AutomationWorkClass::Maintenance,
            current_execution_refs: Vec::new(),
            execution_history_query_ref: "history:automation-1".to_owned(),
        }
    }

    fn source_receipt(context: &RequestMetadata) -> ReceiptEnvelope {
        let core: eliot_receipts::ReceiptCore = serde_json::from_value(serde_json::json!({
            "contract": eliot_receipts::contract_identity().expect("contract"),
            "kind": "VERIFICATION",
            "work_scope": {
                "scope_id": "scope-1",
                "product_id": "eliot-test",
                "resource_generation": context.state_fence.resource_generation,
                "state_fence": context.state_fence
            },
            "task": null,
            "session": {
                "session_id": context.session_id,
                "authority_epoch": context.state_fence.authority_epoch,
                "state_fence": context.state_fence
            },
            "causal": {
                "state_fence": context.state_fence,
                "transaction_sequence": 1,
                "parent_receipt_id": null,
                "predecessor_receipt_ids": []
            },
            "request": {"metadata": context, "state_fence": context.state_fence},
            "operation": {
                "operation_id": "operation-g08",
                "request_id": context.request_id,
                "idempotency_key": "source-key",
                "operation_kind": "g08_notification_projection",
                "effect": "READ",
                "state_fence": context.state_fence
            },
            "authority": {
                "authority_id": "authority-g08",
                "authority_owner": "G-08",
                "authority_epoch": context.state_fence.authority_epoch,
                "state_fence": context.state_fence,
                "allowed_effect": "READ",
                "proof_ceiling": "SCOPED_VERIFICATION"
            },
            "artifacts": [],
            "verifier": null,
            "problem": null,
            "coordination": null,
            "disposition": {"kind": "SUCCESS", "proof": "SCOPED_VERIFICATION"}
        }))
        .expect("receipt core");
        ReceiptEnvelope::issue(core).expect("receipt")
    }

    fn failure_notification(context: &RequestMetadata) -> AutomationFailureNotificationProjection {
        AutomationFailureNotificationProjection {
            canonical: NotificationDraft {
                notification_id: eliot_platform::PlatformHandle::new("caller-id").expect("id"),
                severity: eliot_kernel_core::NotificationSeverity::ActionRequired,
                subject: "Automation blocked".to_owned(),
                summary: "Configuration requires attention".to_owned(),
                evidence_handles: vec!["preflight-receipt".to_owned()],
                affected_scope: "automation-1".to_owned(),
                owner: "UserAutomation".to_owned(),
                required_action: "Review configuration".to_owned(),
                deadline_or_review: None,
                dedup_key: "caller-key".to_owned(),
                delivery_channels: vec![DeliveryChannel::ControlBoard],
                state_fence: context.state_fence.clone(),
            },
            subject: "Automation blocked".to_owned(),
            summary: "Configuration requires attention".to_owned(),
            recipients: vec![eliot_kernel_core::AutomationRecipient {
                principal: eliot_platform::PlatformHandle::new("human-1").expect("principal"),
                role: eliot_kernel_core::AutomationRecipientRole::AuthorizedRole,
            }],
        }
    }

    fn projection(
        context: &RequestMetadata,
        state: UserAutomationConfigurationState,
    ) -> (
        UserAutomationInvocation,
        UserAutomationPreflightProjection,
        WakeIntent,
    ) {
        let revision = revision(state);
        let invocation = UserAutomationInvocation {
            automation_id: revision.automation_id.clone(),
            automation_revision: revision.revision.clone(),
            trigger: UserAutomationTrigger::Scheduled {
                occurrence_key: revision.schedule.next_occurrences[0].clone(),
            },
            mode: revision.mode,
            principal_ref: revision.owner_principal.clone(),
            work_scope_ref: revision.work_scope.scope_id.clone(),
            workdir_ref: revision.workdir_ref.clone(),
            trigger_origin: UserAutomationTriggerOrigin::ScheduledWake,
            child_depth: 0,
            provenance: None,
        };
        let occurrence_id = invocation.occurrence_identity().expect("occurrence");
        let wake_intent = revision
            .compile_wake_intent(&occurrence_id, context.state_fence.clone())
            .expect("wake");
        let mut projection = UserAutomationPreflightProjection {
            automation_id: revision.automation_id.clone(),
            automation_revision: revision.revision.clone(),
            mode: revision.mode,
            occurrence_id,
            revision,
            configuration_state: state,
            config_snapshot: serde_json::from_value(serde_json::json!({
                "snapshot_id": "snapshot-1",
                "machine_id": "machine-1",
                "scope_id": USER_AUTOMATION_SCOPE,
                "revision": PolicyRevision::genesis(),
                "source_completeness": "COMPLETE",
                "settings": [],
                "policy_owner": {"owner_ref": "human-1"},
                "policy_fence": {
                    "policy_snapshot_id": "snapshot-1",
                    "state_fence": context.state_fence
                },
                "state_fence": context.state_fence,
                "parent_snapshot_id": null,
                "rollback_of": null
            }))
            .expect("config snapshot"),
            source_receipt: source_receipt(context),
            execution: UserAutomationExecutionProjection {
                current_execution_refs: Vec::new(),
                unresolved_reconciliation_refs: Vec::new(),
                history_query_ref: "history:automation-1".to_owned(),
            },
            observed_provider_fingerprint: None,
            trusted_skill_package_revision_refs: vec!["skill-package@1".to_owned()],
            trusted_tool_definition_refs: vec!["tool-def@1".to_owned()],
            delivery_available: true,
            trigger_origin: UserAutomationTriggerOrigin::ScheduledWake,
            child_depth: 0,
            failure: None,
        };
        if state == UserAutomationConfigurationState::BlockedConfig {
            let reason = UserAutomationFailureReason::CanonicalBlockedConfig {
                class: "provider-fingerprint".to_owned(),
            };
            projection.failure = Some(UserAutomationFailureProjection {
                failure_fingerprint: projection
                    .revision
                    .failure_fingerprint(&reason)
                    .expect("fingerprint"),
                reason,
                notification: failure_notification(context),
            });
        }
        (invocation, projection, wake_intent)
    }

    fn execution_request(
        context: RequestMetadata,
        invocation: UserAutomationInvocation,
        projection: UserAutomationPreflightProjection,
        wake_intent: WakeIntent,
    ) -> UserAutomationExecutionRequest {
        UserAutomationExecutionRequest {
            context,
            authenticated_principal: "human-1".to_owned(),
            identity: OperationIdentity {
                operation_id: OperationId::new("automation-execution").expect("operation"),
                idempotency_key: "automation-execution-key".to_owned(),
                canonical_request_hash: "a".repeat(64),
            },
            invocation,
            projection,
            wake_intent,
        }
    }

    struct UnusedStore;

    #[allow(async_fn_in_trait)]
    impl UserAutomationStorePort for UnusedStore {
        async fn execute_user_automation(
            &self,
            _request: crate::UserAutomationStoreRequest,
        ) -> Result<crate::UserAutomationStoreResponse, StoreError> {
            Err(StoreError::Unavailable)
        }

        async fn receipt(
            &self,
            _operation_id: OperationId,
        ) -> Result<Option<WriteReceipt>, StoreError> {
            Ok(None)
        }
    }

    #[derive(Default)]
    struct RecordingRuntime {
        admissions: Arc<Mutex<Vec<UserAutomationRuntimeAdmission>>>,
        failures: Arc<Mutex<Vec<UserAutomationFailureRecord>>>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    #[allow(async_fn_in_trait)]
    impl UserAutomationDurableJobPort for RecordingRuntime {
        async fn admit_occurrence(
            &self,
            request: impl Into<Box<UserAutomationRuntimeAdmission>>,
        ) -> Result<AutomationExecutionReference, UserAutomationRuntimeError> {
            let request: Box<UserAutomationRuntimeAdmission> = request.into();
            let occurrence_id = request
                .invocation
                .occurrence_identity()
                .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
            self.admissions
                .lock()
                .expect("admissions lock")
                .push(*request);
            self.events.lock().expect("events lock").push("admission");
            Ok(AutomationExecutionReference {
                occurrence_id,
                durable_job_ref: "job-automation-1".to_owned(),
                state: JobState::Queued,
            })
        }
    }

    #[allow(async_fn_in_trait)]
    impl UserAutomationWakePort for RecordingRuntime {
        async fn cancel_pending_wakes(
            &self,
            _request: impl Into<Box<UserAutomationWakeCancellation>>,
        ) -> Result<Vec<String>, UserAutomationRuntimeError> {
            self.events.lock().expect("events lock").push("cancel");
            Ok(vec!["wake-automation-1".to_owned()])
        }
    }

    #[allow(async_fn_in_trait)]
    impl UserAutomationFailureHistoryPort for RecordingRuntime {
        async fn record_failure(
            &self,
            request: UserAutomationFailureRecord,
        ) -> Result<UserAutomationFailureHistory, UserAutomationRuntimeError> {
            let occurrence_id = request
                .invocation
                .occurrence_identity()
                .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
            self.events.lock().expect("events lock").push("history");
            Ok(UserAutomationFailureHistory {
                operation_id: request.identity.operation_id.clone(),
                idempotency_key: request.identity.idempotency_key.clone(),
                canonical_request_hash: request.identity.canonical_request_hash.clone(),
                state_fence: request.context.state_fence.clone(),
                automation_id: request.revision.automation_id.clone(),
                automation_revision: request.revision.revision.clone(),
                failure_fingerprint: request.failure.failure_fingerprint.clone(),
                occurrence_id,
                history_ref: "history-failure-1".to_owned(),
                dedup_key: request.failure.notification.canonical.dedup_key.clone(),
                deduplicated: false,
            })
        }
    }

    #[allow(async_fn_in_trait)]
    impl UserAutomationNotificationPort for RecordingRuntime {
        async fn deliver_user_automation_failure(
            &self,
            request: UserAutomationFailureRecord,
        ) -> Result<UserAutomationNotificationDelivery, UserAutomationRuntimeError> {
            self.events
                .lock()
                .expect("events lock")
                .push("notification");
            self.failures.lock().expect("failures lock").push(request);
            let failure = self
                .failures
                .lock()
                .expect("failures lock")
                .last()
                .expect("failure recorded")
                .clone();
            Ok(UserAutomationNotificationDelivery {
                state_fence: failure.context.state_fence,
                dedup_key: failure.failure.notification.canonical.dedup_key,
                deduplicated: false,
                notification_receipt_ref: Some("notification-receipt-1".to_owned()),
            })
        }
    }

    #[tokio::test]
    async fn production_join_admits_or_publishes_before_runtime_effect() {
        let store = UnusedStore;
        let service = UserAutomationService::new(&store);

        let active_context = metadata();
        let (active_invocation, active_projection, active_wake) =
            projection(&active_context, UserAutomationConfigurationState::Active);
        let active_runtime = RecordingRuntime::default();
        let active_composition = UserAutomationRuntimeComposition::new(
            &active_runtime,
            &active_runtime,
            &active_runtime,
            &active_runtime,
        );
        let admitted = service
            .execute_occurrence(
                execution_request(
                    active_context,
                    active_invocation,
                    active_projection,
                    active_wake,
                ),
                &active_composition,
            )
            .await
            .expect("active occurrence joins existing runtime");
        assert!(matches!(
            admitted,
            UserAutomationExecutionOutcome::Admitted { .. }
        ));
        assert_eq!(active_runtime.admissions.lock().expect("lock").len(), 1);
        assert!(active_runtime.failures.lock().expect("lock").is_empty());
        assert_eq!(
            active_runtime.events.lock().expect("lock").as_slice(),
            ["admission"]
        );

        let cancellation_context = metadata();
        let cancellation = UserAutomationWakeCancellation {
            state_fence: cancellation_context.state_fence.clone(),
            context: cancellation_context,
            authenticated_principal: "human-1".to_owned(),
            identity: OperationIdentity {
                operation_id: OperationId::new("automation-remove").expect("operation"),
                idempotency_key: "automation-remove-key".to_owned(),
                canonical_request_hash: "b".repeat(64),
            },
            automation_id: "automation-1".to_owned(),
            automation_revision: "revision-7".to_owned(),
            only_unadmitted: true,
            targets: Vec::new(),
        };
        let cancelled = active_composition
            .cancel_pending_wakes(cancellation)
            .await
            .expect("retired revision cancels only unadmitted wakes");
        assert_eq!(cancelled, ["wake-automation-1"]);
        assert_eq!(
            active_runtime.events.lock().expect("lock").as_slice(),
            ["admission", "cancel"]
        );

        let blocked_context = metadata();
        let (blocked_invocation, blocked_projection, blocked_wake) = projection(
            &blocked_context,
            UserAutomationConfigurationState::BlockedConfig,
        );
        let blocked_runtime = RecordingRuntime::default();
        let blocked_composition = UserAutomationRuntimeComposition::new(
            &blocked_runtime,
            &blocked_runtime,
            &blocked_runtime,
            &blocked_runtime,
        );
        let blocked = service
            .execute_occurrence(
                execution_request(
                    blocked_context,
                    blocked_invocation,
                    blocked_projection,
                    blocked_wake,
                ),
                &blocked_composition,
            )
            .await
            .expect("blocked occurrence publishes failure");
        assert!(matches!(
            blocked,
            UserAutomationExecutionOutcome::BlockedConfig { .. }
        ));
        assert!(blocked_runtime.admissions.lock().expect("lock").is_empty());
        assert_eq!(blocked_runtime.failures.lock().expect("lock").len(), 1);
        assert_eq!(
            blocked_runtime.events.lock().expect("lock").as_slice(),
            ["history", "notification"]
        );
    }
}
