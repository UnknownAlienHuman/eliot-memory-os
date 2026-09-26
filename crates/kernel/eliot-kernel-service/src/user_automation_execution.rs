//! Production execution joins for the Kernel-owned UserAutomation service.
//!
//! The service owns the causal ordering at the boundary: authenticate and
//! validate the owner-issued projection, run the model-free Kernel preflight,
//! then hand an admitted occurrence to the existing Durable Job/WakeIntent
//! owners. Configuration failures go through the existing authenticated
//! notification route. This module owns no scheduler, job journal, Store,
//! authority, notification ledger, or model/provider call.

use std::collections::BTreeSet;

use eliot_contracts::{RequestMetadata, StateFence, canonical_json_bytes, sha256_hex};
use eliot_kernel_core::UserAutomationOperatorIntent;
use eliot_kernel_core::user_automation::{
    AutomationCapabilityProfile, AutomationExecutionReference, AutomationOccurrenceIdentity,
    AutomationReconciliationCause, AutomationReconciliationReference, AutomationWorkClass,
    ProviderFingerprintPolicy, UserAutomationConfigurationState, UserAutomationError,
    UserAutomationExecutionMode, UserAutomationExecutionProjection,
    UserAutomationFailureProjection, UserAutomationInvocation, UserAutomationPreflightContext,
    UserAutomationPreflightDecision, UserAutomationPreflightProjection,
    UserAutomationPreflightReceipt, UserAutomationRevision, UserAutomationTrigger,
    UserAutomationTriggerOrigin,
};
use eliot_protocol::dreamer_job::{DurableJobRequest, JobOperation, JobRole};
use eliot_runtime_contracts::{WakeIntent, WakeIntentState};
use eliot_store_api::{OperationId, OperationIdentity, WriteReceipt};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::{
    UserAutomationMutationResult, UserAutomationOwnerSnapshot, UserAutomationReadResult,
    UserAutomationService, UserAutomationServiceError, UserAutomationServiceRequest,
    UserAutomationStoreOutcome, UserAutomationStorePort,
};

/// Errors returned by an existing Durable Job, WakeIntent, or notification
/// owner. The service never turns an unknown owner outcome into success.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum UserAutomationRuntimeError {
    /// The existing owner is not available for this operation.
    #[error("UserAutomation runtime owner is unavailable: {0}")]
    Unavailable(String),
    /// The existing owner read its own authoritative state and definitively
    /// retains no such record.
    ///
    /// This is a COMPLETE negative answer, not an absence of coverage: the owner
    /// reached the state it is the sole owner of and found nothing there. It is
    /// therefore never produced for an owner that could not be reached, whose
    /// state could not be read, or whose answer was lost — those remain
    /// [`UserAutomationRuntimeError::Unavailable`] and
    /// [`UserAutomationRuntimeError::UnknownOutcome`].
    ///
    /// The distinction is load-bearing. A wake read that finds no retained
    /// pending record proves there is no unadmitted wake to cancel, while a wake
    /// read against an unreadable owner proves nothing at all. Reporting both as
    /// the same value would make a retirement that provably has nothing to cancel
    /// indistinguishable from one whose target set is unknown, and would leave
    /// every already-settled automation permanently reconciling.
    #[error("UserAutomation runtime owner definitively retains no such record: {0}")]
    NotRetained(String),
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
    /// The declared occurrence denominator was not owner-proven complete, so a
    /// runtime boundary refused rather than acting on a bounded subset of it.
    ///
    /// The whole obligation travels with the refusal, not just its cause. The
    /// durable owner query handle is the only route by which a caller can finish
    /// enumerating the denominator, so a refusal that dropped it would be
    /// strictly worse than the deferral it replaces: the caller would know the
    /// work is blocked and have no way to unblock it.
    #[error(
        "UserAutomation occurrence denominator is not owner-proven complete: \
         cause={:?} read_revision={} denominator_query_ref={}",
        .0.cause,
        .0.read_revision,
        .0.denominator_query_ref.as_deref().unwrap_or("<none>")
    )]
    OccurrenceDenominatorIncomplete(AutomationReconciliationReference),
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
        if self.invocation.principal_ref != self.authenticated_principal {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake read principal",
            ));
        }
        // The authenticated wake owner retains both owner-issued occurrence
        // kinds, so the readback contract names the source kind instead of
        // accepting only the Human run-now one. Each kind keeps its own
        // provenance proof: a `Human` run-now occurrence must still match the
        // exact committed parent operation identity, and a `ScheduledWake`
        // occurrence must name a calendar occurrence of the normalized set
        // rather than a manual nonce. An admitted child is neither a published
        // wake nor a trigger this contour reads back.
        match self.invocation.trigger_origin {
            UserAutomationTriggerOrigin::Human => {
                validate_human_invocation_source(&self.context, &self.identity, &self.invocation)?;
            }
            UserAutomationTriggerOrigin::ScheduledWake => {
                if !matches!(
                    self.invocation.trigger,
                    UserAutomationTrigger::Scheduled { .. }
                ) {
                    return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                        "scheduled wake must name a calendar occurrence",
                    ));
                }
            }
            UserAutomationTriggerOrigin::AutomationChild => {
                return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                    "an admitted child is not an owner wake",
                ));
            }
        }
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

/// Closed reason one bounded recurring horizon is published or advanced.
///
/// The reason selects which slice of the immutable normalized denominator the
/// wake owner is asked to retain. It is closed so a caller cannot name an
/// ad-hoc slice: every member of every slice is an occurrence of the accepted
/// revision's own normalized contract, and the reason only selects where that
/// bounded slice starts.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationHorizonTrigger {
    /// First publication for an accepted active revision (`Create`).
    AcceptedRevision,
    /// Publication for a new active revision committed by a superseding `Edit`.
    SupersedingEdit,
    /// Publication for the same immutable revision after `Resume`.
    ResumedRevision,
    /// The next bounded slice after one occurrence reached an owner-acknowledged
    /// disposition.
    DispositionAdvance,
}

impl UserAutomationHorizonTrigger {
    /// Reports whether this trigger names a whole-denominator first publication
    /// rather than a post-disposition slice.
    #[must_use]
    pub const fn publishes_whole_denominator(self) -> bool {
        !matches!(self, Self::DispositionAdvance)
    }
}

/// One occurrence of the accepted normalized denominator that the existing
/// `WakeIntent` owner must retain.
///
/// Every member is compiled from the immutable revision: the occurrence key is
/// the owner-normalized calendar encoding produced by the pinned zone
/// contract, and `source_digest` is the compiled digest binding that key to the
/// declared expression and calendar. Nothing here is a time Kernel derived,
/// shifted, folded, or extrapolated.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeHorizonEntry {
    /// Stable revision-bound occurrence identity.
    pub occurrence_id: String,
    /// Exact owner-normalized calendar occurrence key, carrying the resolved
    /// instant, the applied offset, and the applied fold or gap disposition.
    pub occurrence_key: String,
    /// Compiled digest binding this occurrence to the declared expression and
    /// calendar of the accepted revision.
    pub source_digest: String,
    /// Inert owner-contract wake intent compiled by the revision for exactly
    /// this occurrence under the publishing State Fence.
    pub wake_intent: WakeIntent,
}

/// Bounded wake horizon requested from the existing WakeIntent/Task Scheduler
/// owner for one immutable revision.
///
/// The request carries three separate things so none of them can be inferred
/// from another: the complete normalized `denominator` the revision owns, the
/// bounded `entries` slice being published now, and the `identity` of the one
/// operation that publishes it. A `WakeIntent` grants no execution authority by
/// itself, so this request is a publication obligation and never permission to
/// pre-admit a Durable Job.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeHorizonPublication {
    /// Live authenticated request metadata and State Fence.
    pub context: RequestMetadata,
    /// Principal authenticated by Kernel/Host.
    pub authenticated_principal: String,
    /// Exact operation identity that owns this publication. A replay of the
    /// same identity re-requests the same slice and mints no second wake.
    pub identity: OperationIdentity,
    /// Stable automation identity.
    pub automation_id: String,
    /// Immutable revision identity whose normalized contract is published.
    pub automation_revision: String,
    /// Immutable digest of that revision. An advance that observes a different
    /// digest is a different revision, not a continuation of this cursor.
    pub revision_digest: String,
    /// Fence under which the publication is issued.
    pub state_fence: StateFence,
    /// Closed reason selecting this bounded slice.
    pub trigger: UserAutomationHorizonTrigger,
    /// Complete occurrence denominator of the accepted revision, in the
    /// revision's own normalized order.
    pub denominator_occurrence_ids: Vec<String>,
    /// The bounded slice published now, a contiguous run of the denominator in
    /// the same order.
    pub entries: Vec<UserAutomationWakeHorizonEntry>,
    /// Fixed safety pin: only not-yet-admitted future wakes are published.
    pub only_unadmitted_future: bool,
    /// Occurrence already consumed by the slice, present exactly for
    /// [`UserAutomationHorizonTrigger::DispositionAdvance`].
    pub consumed_occurrence_id: Option<String>,
}

impl UserAutomationWakeHorizonPublication {
    /// Validates the request shape.
    ///
    /// The checks that need the immutable revision live in
    /// [`Self::validate_against_revision`], which every production caller
    /// reaches through [`compile_wake_horizon`] and [`advance_wake_horizon`].
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
            "horizon.authenticated_principal",
        )?;
        validate_text(&self.automation_id, "horizon.automation_id")?;
        validate_text(&self.automation_revision, "horizon.automation_revision")?;
        validate_digest(&self.revision_digest, "horizon.revision_digest")?;
        if !self.only_unadmitted_future || self.state_fence != self.context.state_fence {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "horizon must be same-fence and unadmitted-only",
            ));
        }
        self.state_fence
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        validate_unique_horizon_list(
            &self.denominator_occurrence_ids,
            "horizon.denominator_occurrence_ids",
        )?;
        if self.entries.is_empty() {
            return Err(UserAutomationExecutionError::Contract(
                UserAutomationError::Invalid("horizon.entries"),
            ));
        }
        for entry in &self.entries {
            validate_text(&entry.occurrence_id, "horizon.entry.occurrence_id")?;
            validate_text(&entry.occurrence_key, "horizon.entry.occurrence_key")?;
            validate_digest(&entry.source_digest, "horizon.entry.source_digest")?;
            entry
                .wake_intent
                .validate()
                .map_err(|_| UserAutomationError::Invalid("horizon.entry.wake_intent"))?;
            if entry.wake_intent.wake_id != entry.occurrence_id
                || entry.wake_intent.state != WakeIntentState::Pending
                || entry.wake_intent.state_fence != self.state_fence
            {
                return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                    "horizon entry occurrence/fence/state",
                ));
            }
        }
        if self.trigger.publishes_whole_denominator() {
            if self.consumed_occurrence_id.is_some() {
                return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                    "whole-denominator publication cannot name a consumed occurrence",
                ));
            }
        } else {
            let Some(consumed) = self.consumed_occurrence_id.as_deref() else {
                return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                    "a disposition advance must name the consumed occurrence",
                ));
            };
            validate_text(consumed, "horizon.consumed_occurrence_id")?;
        }
        Ok(())
    }

    /// Cross-checks the request against the exact immutable revision.
    ///
    /// The retained denominator must equal what this revision's normalized
    /// contract compiles, every entry must be one of those occurrences with the
    /// revision's own compiled source digest, and the published slice must be a
    /// contiguous run of the denominator in the revision's own order. A
    /// disposition advance must additionally start immediately after its
    /// consumed occurrence, so no future time is ever invented past the
    /// revision's normalized contract.
    pub fn validate_against_revision(
        &self,
        revision: &UserAutomationRevision,
    ) -> Result<(), UserAutomationExecutionError> {
        self.validate()?;
        revision
            .validate()
            .map_err(UserAutomationExecutionError::Contract)?;
        if revision.automation_id != self.automation_id
            || revision.revision != self.automation_revision
            || revision.owner_principal != self.authenticated_principal
            || revision
                .digest()
                .map_err(UserAutomationExecutionError::Contract)?
                != self.revision_digest
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "horizon revision binding",
            ));
        }
        let source_digest = revision
            .schedule
            .source_digest()
            .map_err(UserAutomationExecutionError::Contract)?;
        let identities = revision
            .compile_occurrence_identities()
            .map_err(UserAutomationExecutionError::Contract)?;
        let denominator = identities
            .iter()
            .map(|identity| identity.occurrence_id.clone())
            .collect::<Vec<_>>();
        if denominator != self.denominator_occurrence_ids {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "horizon denominator is not the revision normalized set",
            ));
        }
        let start = horizon_slice_start(
            &denominator,
            self.trigger,
            self.consumed_occurrence_id.as_deref(),
        )?;
        if start + self.entries.len() > denominator.len() {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "horizon slice is not a bounded run of the revision denominator",
            ));
        }
        for (entry, occurrence_id) in self
            .entries
            .iter()
            .zip(&denominator[start..start + self.entries.len()])
        {
            if &entry.occurrence_id != occurrence_id || entry.source_digest != source_digest {
                return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                    "horizon entry occurrence/source digest",
                ));
            }
        }
        Ok(())
    }

    /// Returns the exact occurrence identities this request publishes now.
    #[must_use]
    pub fn requested_occurrence_ids(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|entry| entry.occurrence_id.clone())
            .collect()
    }

    /// Returns the stable replay handle a caller re-presents to finish an
    /// unacknowledged remainder.
    ///
    /// It grants nothing: it names work, it does not authorize it.
    pub fn retry_handle(
        &self,
        remaining_occurrence_ids: &[String],
    ) -> Result<String, UserAutomationExecutionError> {
        horizon_retry_handle(
            &self.identity,
            &self.revision_digest,
            remaining_occurrence_ids,
        )
    }
}

/// Domain separator for the deterministic horizon retry handle.
const HORIZON_RETRY_HANDLE_DOMAIN: &str = "eliot.user_automation.horizon-retry.v1";

/// Returns the index at which a bounded horizon slice starts inside the
/// immutable revision's normalized denominator.
fn horizon_slice_start(
    denominator: &[String],
    trigger: UserAutomationHorizonTrigger,
    consumed_occurrence_id: Option<&str>,
) -> Result<usize, UserAutomationExecutionError> {
    if trigger.publishes_whole_denominator() {
        if consumed_occurrence_id.is_some() {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "whole-denominator publication cannot name a consumed occurrence",
            ));
        }
        return Ok(0);
    }
    let consumed =
        consumed_occurrence_id.ok_or(UserAutomationExecutionError::RuntimeResponseMismatch(
            "a disposition advance must name the consumed occurrence",
        ))?;
    let position = denominator
        .iter()
        .position(|candidate| candidate == consumed)
        .ok_or(UserAutomationExecutionError::RuntimeResponseMismatch(
            "the consumed occurrence is not a member of this revision denominator",
        ))?;
    Ok(position + 1)
}

/// Derives the stable replay handle for one unacknowledged horizon remainder.
///
/// The handle is a pure function of the operation identity that owns the
/// publication, the immutable revision digest it publishes for, and the exact
/// remaining occurrence set. A retry of the same remainder under the same
/// identity is therefore recognisable as the same operation, while any change
/// to the remainder or the revision produces a different handle. It is derived
/// by this boundary rather than requested from an owner, because an absent owner
/// is precisely the case a caller must still be able to name; it grants nothing
/// and authorizes nothing.
pub fn horizon_retry_handle(
    identity: &OperationIdentity,
    revision_digest: &str,
    remaining_occurrence_ids: &[String],
) -> Result<String, UserAutomationExecutionError> {
    validate_unique_horizon_list(remaining_occurrence_ids, "horizon.retry_handle.remaining")?;
    validate_digest(revision_digest, "horizon.retry_handle.revision_digest")?;
    let bytes = canonical_json_bytes(&(
        HORIZON_RETRY_HANDLE_DOMAIN,
        identity.operation_id.as_str(),
        identity.idempotency_key.as_str(),
        revision_digest,
        remaining_occurrence_ids,
    ))
    .map_err(|error| {
        UserAutomationExecutionError::Contract(UserAutomationError::Serialization(
            error.to_string(),
        ))
    })?;
    Ok(format!("ua-horizon-retry:{}", sha256_hex(&bytes)))
}

/// Owner's answer to one bounded horizon publication request.
///
/// The owner must echo the exact publication identity and account for every
/// requested occurrence. An occurrence it did not acknowledge is retained here
/// as the exact remaining set together with the replay handle; it is never
/// dropped, because a dropped occurrence is indistinguishable from an
/// occurrence that was never requested.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakePublication {
    /// Stable automation identity the owner published for.
    pub automation_id: String,
    /// Immutable revision identity the owner published for.
    pub automation_revision: String,
    /// Immutable revision digest the owner observed.
    pub revision_digest: String,
    /// Fence the owner acknowledged under.
    pub state_fence: StateFence,
    /// Owner-issued identity of the publication operation itself.
    pub publication_operation_id: OperationId,
    /// Owner-issued idempotency identity of that publication.
    pub publication_idempotency_key: String,
    /// Exact occurrences the owner acknowledged as retained.
    pub acknowledged_occurrence_ids: Vec<String>,
    /// Exact occurrences of the request the owner did not acknowledge.
    pub remaining_occurrence_ids: Vec<String>,
    /// Stable handle a caller re-presents for the remaining set.
    pub retry_handle: String,
}

impl UserAutomationWakePublication {
    /// Validates the owner answer against the exact request sent.
    ///
    /// The acknowledged and remaining sets must together be exactly the
    /// requested set, disjoint, and free of duplicates, and the owner must
    /// echo the immutable revision identity and publication identity. A
    /// remaining set that does not match the request is an owner answer this
    /// boundary refuses rather than reports as a partial success.
    pub fn validate_for(
        &self,
        request: &UserAutomationWakeHorizonPublication,
    ) -> Result<(), UserAutomationExecutionError> {
        request.validate()?;
        validate_text(
            &self.publication_idempotency_key,
            "publication.publication_idempotency_key",
        )?;
        validate_digest(&self.revision_digest, "publication.revision_digest")?;
        validate_text(&self.retry_handle, "publication.retry_handle")?;
        self.state_fence
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        if self.automation_id != request.automation_id
            || self.automation_revision != request.automation_revision
            || self.revision_digest != request.revision_digest
            || self.state_fence != request.state_fence
            || self.publication_operation_id != request.identity.operation_id
            || self.publication_idempotency_key != request.identity.idempotency_key
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "publication identity binding",
            ));
        }
        let mut accounted: BTreeSet<&str> = BTreeSet::new();
        for (values, field) in [
            (
                &self.acknowledged_occurrence_ids,
                "publication.acknowledged_occurrence_ids",
            ),
            (
                &self.remaining_occurrence_ids,
                "publication.remaining_occurrence_ids",
            ),
        ] {
            validate_unique_horizon_list(values, field)?;
            for value in values {
                if !accounted.insert(value.as_str()) {
                    return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                        "publication accounts for one occurrence twice",
                    ));
                }
            }
        }
        let requested = request.requested_occurrence_ids();
        if accounted.len() != requested.len()
            || !requested
                .iter()
                .all(|occurrence_id| accounted.contains(occurrence_id.as_str()))
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "publication does not account for the requested horizon",
            ));
        }
        if self.retry_handle != request.retry_handle(&self.remaining_occurrence_ids)? {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "publication retry handle",
            ));
        }
        Ok(())
    }

    /// Reports whether the owner acknowledged the complete requested horizon.
    #[must_use]
    pub fn acknowledged_all(&self) -> bool {
        self.remaining_occurrence_ids.is_empty()
    }
}

/// Compiles the bounded wake horizon of one accepted immutable revision.
///
/// The whole compiler is derived from the revision: its normalized occurrence
/// denominator and stable occurrence identities, the compiled schedule trigger
/// basis, and the inert owner-contract wake intent it produces for each
/// occurrence. The slice is the whole denominator for a first publication, and
/// the run strictly after `consumed_occurrence_id` for a disposition advance.
/// No time is derived, shifted, or extrapolated here, so this function cannot
/// widen a schedule.
pub fn compile_wake_horizon(
    revision: &UserAutomationRevision,
    context: RequestMetadata,
    authenticated_principal: String,
    identity: OperationIdentity,
    state_fence: StateFence,
    trigger: UserAutomationHorizonTrigger,
    consumed_occurrence_id: Option<&str>,
) -> Result<UserAutomationWakeHorizonPublication, UserAutomationExecutionError> {
    revision
        .validate()
        .map_err(UserAutomationExecutionError::Contract)?;
    if revision.owner_principal != authenticated_principal {
        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
            "horizon principal is not the revision owner",
        ));
    }
    let digest = revision
        .digest()
        .map_err(UserAutomationExecutionError::Contract)?;
    let source_digest = revision
        .schedule
        .source_digest()
        .map_err(UserAutomationExecutionError::Contract)?;
    let identities = revision
        .compile_occurrence_identities()
        .map_err(UserAutomationExecutionError::Contract)?;
    let denominator_occurrence_ids = identities
        .iter()
        .map(|identity| identity.occurrence_id.clone())
        .collect::<Vec<_>>();
    let start = horizon_slice_start(&denominator_occurrence_ids, trigger, consumed_occurrence_id)?;
    if start >= identities.len() {
        return Err(UserAutomationExecutionError::Contract(
            UserAutomationError::Invalid("horizon.entries"),
        ));
    }
    let mut entries = Vec::with_capacity(identities.len() - start);
    for identity in &identities[start..] {
        let UserAutomationTrigger::Scheduled { occurrence_key } = &identity.trigger else {
            return Err(UserAutomationExecutionError::Contract(
                UserAutomationError::Invalid("horizon.entry.occurrence_key"),
            ));
        };
        entries.push(UserAutomationWakeHorizonEntry {
            occurrence_id: identity.occurrence_id.clone(),
            occurrence_key: occurrence_key.clone(),
            source_digest: source_digest.clone(),
            wake_intent: revision
                .compile_wake_intent(&identity.occurrence_id, state_fence.clone())
                .map_err(UserAutomationExecutionError::Contract)?,
        });
    }
    let publication = UserAutomationWakeHorizonPublication {
        context,
        authenticated_principal,
        identity,
        automation_id: revision.automation_id.clone(),
        automation_revision: revision.revision.clone(),
        revision_digest: digest,
        state_fence,
        trigger,
        denominator_occurrence_ids,
        entries,
        only_unadmitted_future: true,
        consumed_occurrence_id: consumed_occurrence_id.map(str::to_owned),
    };
    publication.validate_against_revision(revision)?;
    Ok(publication)
}

/// Advances the recurring horizon from owner state after one occurrence reached
/// an owner-acknowledged disposition.
///
/// The cursor is revision-bound: the denominator is recompiled from the exact
/// immutable revision the due wake resolved against, and the cursor position is
/// the consumed occurrence's own place in that denominator. Because the revision
/// is immutable and its digest is carried by the resolution, the recompiled
/// denominator is provably the one any earlier publication of that revision
/// carried, so no prior publication record is needed to continue it and none is
/// invented here. The advance therefore never mutates the revision, never mints a
/// second occurrence identity, and never produces a time outside the revision's
/// normalized contract.
pub fn advance_wake_horizon(
    resolution: &UserAutomationDueWakeResolution,
    consumed_occurrence_id: &str,
    context: RequestMetadata,
    authenticated_principal: String,
    identity: OperationIdentity,
    state_fence: StateFence,
) -> Result<UserAutomationWakeHorizonPublication, UserAutomationExecutionError> {
    resolution
        .revision
        .validate()
        .map_err(UserAutomationExecutionError::Contract)?;
    if resolution
        .revision
        .digest()
        .map_err(UserAutomationExecutionError::Contract)?
        != resolution.revision_digest
    {
        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
            "horizon advance revision digest is not the resolved immutable revision",
        ));
    }
    if resolution.revision.owner_principal != authenticated_principal {
        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
            "horizon advance principal is not the resolved revision owner",
        ));
    }
    compile_wake_horizon(
        &resolution.revision,
        context,
        authenticated_principal,
        identity,
        state_fence,
        UserAutomationHorizonTrigger::DispositionAdvance,
        Some(consumed_occurrence_id),
    )
}

/// Closed cause by which one authenticated owner wake is refused before any
/// execution effect is requested.
#[derive(Clone, Copy, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UserAutomationDueWakeRejectionCause {
    /// The carrier did not arrive as an existing scheduler wake.
    NotScheduledWakeOrigin,
    /// A scheduler wake named something other than a calendar occurrence.
    NotCalendarOccurrence,
    /// An admitted child requested a trigger this contour does not consume.
    NestedChildOccurrence,
    /// The authenticated principal, owner, or work scope does not match.
    ForeignPrincipal,
    /// The occurrence belongs to a revision that has been superseded.
    SupersededRevision,
    /// The occurrence belongs to a revision that is no longer the current one.
    StaleRevision,
    /// The current configuration state admits no occurrence.
    OwnerNotActive,
    /// The occurrence is not a member of the current normalized set.
    UnnormalizedOccurrence,
    /// The carried occurrence identity is not the one the current revision
    /// compiles.
    OccurrenceIdentityMismatch,
    /// The wake owner retains no such published wake.
    WakeNotRetained,
    /// The retained wake is no longer a pending, unadmitted intent.
    WakeAlreadyConsumed,
    /// The retained wake belongs to another occurrence, revision, or fence.
    ForeignWake,
    /// The occurrence already has an admitted Durable Job reference.
    OccurrenceAlreadyAdmitted,
}

/// One refused due wake, with its closed cause and the exact evidence it was
/// refused against.
///
/// A refusal is a typed decision, not prose: `cause` is what the boundary
/// rejected, `owner_configuration_state` is the live admission state when that
/// is the cause, and `occurrence_id` is the exact stable occurrence the wake
/// named. Nothing here is inferred from the absence of a damage signature.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationDueWakeRejection {
    /// Closed cause of the refusal.
    pub cause: UserAutomationDueWakeRejectionCause,
    /// Stable occurrence the refused wake named.
    pub occurrence_id: String,
    /// Live owner configuration state, present exactly when the cause is
    /// [`UserAutomationDueWakeRejectionCause::OwnerNotActive`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_configuration_state: Option<UserAutomationConfigurationState>,
    /// Already-admitted Durable Job reference this duplicate delivery resolves
    /// to, present exactly when the cause is
    /// [`UserAutomationDueWakeRejectionCause::OccurrenceAlreadyAdmitted`].
    ///
    /// A duplicate delivery therefore returns the existing operation instead of
    /// prose: the caller reconciles that reference rather than admitting a
    /// second one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_execution: Option<AutomationExecutionReference>,
    /// Closed reason the boundary refused this wake before any effect.
    pub reason: String,
}

impl UserAutomationDueWakeRejection {
    /// Builds one typed refusal with its named reason.
    #[must_use]
    pub fn new(
        cause: UserAutomationDueWakeRejectionCause,
        occurrence_id: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            cause,
            occurrence_id: occurrence_id.into(),
            owner_configuration_state: None,
            existing_execution: None,
            reason: reason.into(),
        }
    }

    /// Builds the closed refusal for a current owner state that admits nothing.
    #[must_use]
    pub fn owner_not_active(
        occurrence_id: impl Into<String>,
        state: UserAutomationConfigurationState,
    ) -> Self {
        let occurrence_id = occurrence_id.into();
        let reason = format!(
            "occurrence {occurrence_id} is refused because the current owner configuration state \
             is {state:?}, which admits no occurrence; the wake is cancelled or expired by the \
             schedule owner rather than executed"
        );
        Self {
            cause: UserAutomationDueWakeRejectionCause::OwnerNotActive,
            occurrence_id,
            owner_configuration_state: Some(state),
            existing_execution: None,
            reason,
        }
    }

    /// Builds the closed refusal for a duplicate delivery of an occurrence that
    /// already has an admitted Durable Job reference.
    #[must_use]
    pub fn occurrence_already_admitted(
        occurrence_id: impl Into<String>,
        existing: AutomationExecutionReference,
    ) -> Self {
        let occurrence_id = occurrence_id.into();
        let reason = format!(
            "occurrence {occurrence_id} already has Durable Job reference {} in state {:?} in the \
             complete owner execution projection, so this delivery is a duplicate of that \
             operation and returns it instead of admitting a second one",
            existing.durable_job_ref, existing.state
        );
        Self {
            cause: UserAutomationDueWakeRejectionCause::OccurrenceAlreadyAdmitted,
            occurrence_id,
            owner_configuration_state: None,
            existing_execution: Some(existing),
            reason,
        }
    }
}

/// Resolved, owner-proven identity of one due authenticated wake.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationDueWakeResolution {
    /// Exact current immutable revision the wake resolved to.
    pub revision: UserAutomationRevision,
    /// Occurrence re-derived by that current revision from its own normalized
    /// set, with the `ScheduledWake` origin.
    pub invocation: UserAutomationInvocation,
    /// Immutable revision digest the resolution was made against.
    pub revision_digest: String,
}

impl UserAutomationDueWakeResolution {
    /// Validates that the resolution still binds the carrier it resolved.
    pub fn validate_for(
        &self,
        request: &UserAutomationRuntimeAdmission,
    ) -> Result<(), UserAutomationExecutionError> {
        self.revision
            .validate()
            .map_err(UserAutomationExecutionError::Contract)?;
        self.invocation
            .validate()
            .map_err(UserAutomationExecutionError::Contract)?;
        validate_digest(&self.revision_digest, "due_wake.revision_digest")?;
        let digest = self
            .revision
            .digest()
            .map_err(UserAutomationExecutionError::Contract)?;
        let occurrence_id = self
            .invocation
            .occurrence_identity()
            .map_err(UserAutomationExecutionError::Contract)?;
        if digest != self.revision_digest
            || self.revision != request.revision
            || self.invocation != request.invocation
            || occurrence_id != request.preflight.occurrence_id
            || occurrence_id != request.wake_intent.wake_id
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "due wake resolution binding",
            ));
        }
        Ok(())
    }
}

/// Resolves the exact current automation, revision, and occurrence of one
/// authenticated owner wake, refusing every wake the current owner no longer
/// admits before any execution effect is requested.
///
/// This is the pre-execution gate of issue #2806 item 5. It performs no IO, no
/// model or provider call, and no scheduler call: it compares the carrier
/// against the canonical owner snapshot and the complete owner execution
/// projection, so a stale, paused, removed, superseded, already-admitted,
/// duplicate, or foreign wake is refused on evidence rather than admitted and
/// discovered later. A `WakeIntent` grants no execution authority by itself;
/// every one of these refusals exists because of that.
pub fn resolve_due_wake(
    owner: &UserAutomationOwnerSnapshot,
    request: &UserAutomationRuntimeAdmission,
    expected_principal: &str,
    execution: &UserAutomationExecutionProjection,
) -> Result<UserAutomationDueWakeResolution, UserAutomationDueWakeRejection> {
    let carried_occurrence = request
        .invocation
        .occurrence_identity()
        .unwrap_or_else(|_| String::from("<unresolvable>"));
    refuse_foreign_due_wake_shape(request, &carried_occurrence)?;
    refuse_foreign_due_wake_principal(owner, request, expected_principal, &carried_occurrence)?;
    refuse_stale_due_wake_revision(owner, request, &carried_occurrence)?;
    refuse_unadmitted_due_wake_owner(owner, &carried_occurrence)?;
    refuse_already_admitted_due_wake(execution, &carried_occurrence)?;
    compile_due_wake_occurrence(owner, request, expected_principal, &carried_occurrence)
}

/// Refuses a carrier that is not a due scheduler wake for a top-level calendar
/// occurrence of this automation.
fn refuse_foreign_due_wake_shape(
    request: &UserAutomationRuntimeAdmission,
    carried_occurrence: &str,
) -> Result<(), UserAutomationDueWakeRejection> {
    if request.invocation.trigger_origin != UserAutomationTriggerOrigin::ScheduledWake {
        return Err(UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::NotScheduledWakeOrigin,
            carried_occurrence,
            "an owner wake must arrive as a ScheduledWake occurrence; a Human run-now occurrence \
             and an admitted child are not consumed by this ingress",
        ));
    }
    if !matches!(
        request.invocation.trigger,
        UserAutomationTrigger::Scheduled { .. }
    ) {
        return Err(UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::NotCalendarOccurrence,
            carried_occurrence,
            "a scheduled wake must name an owner-normalized calendar occurrence, never a manual \
             run-now nonce",
        ));
    }
    if request.invocation.child_depth != 0 {
        return Err(UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::NestedChildOccurrence,
            carried_occurrence,
            "an admitted child occurrence cannot be re-entered as a schedule wake; scheduling \
             authority requires a separate exact Human-approved operation",
        ));
    }
    Ok(())
}

/// Refuses a wake issued for another principal or another automation.
fn refuse_foreign_due_wake_principal(
    owner: &UserAutomationOwnerSnapshot,
    request: &UserAutomationRuntimeAdmission,
    expected_principal: &str,
    carried_occurrence: &str,
) -> Result<(), UserAutomationDueWakeRejection> {
    if request.authenticated_principal != expected_principal
        || request.invocation.principal_ref != expected_principal
        || owner.authenticated_principal != expected_principal
        || owner.revision.owner_principal != expected_principal
    {
        return Err(UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::ForeignPrincipal,
            carried_occurrence,
            "the wake principal, the authenticated session principal, and the canonical owner \
             principal are not the same principal, so this wake is not issued for this owner",
        ));
    }
    if owner.automation_id != request.invocation.automation_id
        || request.revision.automation_id != owner.automation_id
    {
        return Err(UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::ForeignPrincipal,
            carried_occurrence,
            "the wake names a different automation than the canonical owner it was resolved \
             against",
        ));
    }
    Ok(())
}

/// Refuses a wake of a superseded revision or of a revision the canonical owner
/// no longer serves.
fn refuse_stale_due_wake_revision(
    owner: &UserAutomationOwnerSnapshot,
    request: &UserAutomationRuntimeAdmission,
    carried_occurrence: &str,
) -> Result<(), UserAutomationDueWakeRejection> {
    if owner.revision.revision != request.invocation.automation_revision {
        return Err(UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::SupersededRevision,
            carried_occurrence,
            format!(
                "the wake names revision {} of {}, but the canonical current revision is {}; the \
                 named revision is superseded and its not-yet-admitted wakes are cancelled rather \
                 than executed",
                request.invocation.automation_revision,
                owner.automation_id,
                owner.revision.revision
            ),
        ));
    }
    if owner.revision != request.revision {
        return Err(UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::StaleRevision,
            carried_occurrence,
            "the immutable revision carried by the wake is not the current canonical revision, so \
             the occurrence cannot be preflighted against the live owner state",
        ));
    }
    Ok(())
}

/// Refuses a wake of a revision whose current configuration state admits no
/// occurrence.
fn refuse_unadmitted_due_wake_owner(
    owner: &UserAutomationOwnerSnapshot,
    carried_occurrence: &str,
) -> Result<(), UserAutomationDueWakeRejection> {
    if owner.current_configuration_state != UserAutomationConfigurationState::Active {
        return Err(UserAutomationDueWakeRejection::owner_not_active(
            carried_occurrence,
            owner.current_configuration_state,
        ));
    }
    Ok(())
}

/// Refuses a duplicate delivery of an occurrence that already has an admitted
/// Durable Job reference, returning that operation instead of admitting a second
/// one.
fn refuse_already_admitted_due_wake(
    execution: &UserAutomationExecutionProjection,
    carried_occurrence: &str,
) -> Result<(), UserAutomationDueWakeRejection> {
    if let Some(existing) = execution
        .current_execution_refs
        .iter()
        .find(|reference| reference.occurrence_id == carried_occurrence)
        .cloned()
    {
        return Err(UserAutomationDueWakeRejection::occurrence_already_admitted(
            carried_occurrence,
            existing,
        ));
    }
    Ok(())
}

/// Re-derives the wake occurrence from the current revision's own normalized set
/// and returns the resolved occurrence with that revision's immutable digest.
fn compile_due_wake_occurrence(
    owner: &UserAutomationOwnerSnapshot,
    request: &UserAutomationRuntimeAdmission,
    expected_principal: &str,
    carried_occurrence: &str,
) -> Result<UserAutomationDueWakeResolution, UserAutomationDueWakeRejection> {
    let unnormalized = |error: UserAutomationError| {
        UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::UnnormalizedOccurrence,
            carried_occurrence,
            format!("the current revision normalized set does not compile this wake: {error}"),
        )
    };
    let UserAutomationTrigger::Scheduled { occurrence_key } = &request.invocation.trigger else {
        return Err(UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::NotCalendarOccurrence,
            carried_occurrence,
            "a scheduled wake must name an owner-normalized calendar occurrence",
        ));
    };
    let invocation = owner
        .revision
        .scheduled_invocation(
            occurrence_key,
            expected_principal,
            UserAutomationTriggerOrigin::ScheduledWake,
            0,
        )
        .map_err(unnormalized)?;
    let occurrence_id = invocation.occurrence_identity().map_err(unnormalized)?;
    if occurrence_id != carried_occurrence {
        return Err(UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::OccurrenceIdentityMismatch,
            carried_occurrence,
            format!(
                "the carried occurrence identity does not match the identity the current revision \
                 compiles for the same calendar occurrence ({occurrence_id})"
            ),
        ));
    }
    let revision_digest = owner.revision.digest().map_err(|error| {
        UserAutomationDueWakeRejection::new(
            UserAutomationDueWakeRejectionCause::UnnormalizedOccurrence,
            carried_occurrence,
            format!("the current revision digest could not be derived: {error}"),
        )
    })?;
    Ok(UserAutomationDueWakeResolution {
        revision: owner.revision.clone(),
        invocation,
        revision_digest,
    })
}

/// Refuses a retained wake that the schedule owner no longer offers as a
/// pending, unadmitted intent for the resolved occurrence.
pub fn refuse_consumed_wake(
    occurrence_id: &str,
    intent: &WakeIntent,
) -> Option<UserAutomationDueWakeRejection> {
    if intent.state == WakeIntentState::Pending {
        return None;
    }
    Some(UserAutomationDueWakeRejection::new(
        UserAutomationDueWakeRejectionCause::WakeAlreadyConsumed,
        occurrence_id.to_owned(),
        format!(
            "the schedule owner retains occurrence {occurrence_id} in lifecycle state {:?}, which \
             is not a pending unadmitted intent, so this delivery is a duplicate or a superseded \
             delivery and returns the existing operation instead of admitting a second one",
            intent.state
        ),
    ))
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
    /// Publishes one bounded recurring horizon to the existing WakeIntent/Task
    /// Scheduler owner.
    ///
    /// The owner is the sole writer of its wake journal, so the request is
    /// already bound to one immutable revision, one State Fence, and the
    /// revision's own normalized occurrence denominator: an implementation
    /// cannot widen, reorder, or extend that denominator. The answer must
    /// account for every requested occurrence, and only an owner acknowledgement
    /// makes a horizon published.
    ///
    /// The default refuses with a named unavailability instead of inferring a
    /// publication. That is the correct answer for a contour with no schedule
    /// owner: a `WakeIntent` publication is an owner effect, and a caller must
    /// never be able to make an absent owner look like a retained wake.
    async fn publish_wake_horizon(
        &self,
        _request: impl Into<Box<UserAutomationWakeHorizonPublication>>,
    ) -> Result<UserAutomationWakePublication, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "UserAutomation wake horizon publication is unavailable at this boundary: the existing \
             WakeIntent/Task Scheduler owner publishes no horizon operation over the admitted \
             channel, so nothing was sent and no wake was retained"
                .to_owned(),
        ))
    }

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
    ///
    /// This is the production retirement contour of the authenticated
    /// `Remove` operator route: `KernelStoreGateway::remove_handoff` reads the
    /// complete fail-closed owner execution view, enumerates the owner-issued
    /// targets from the wake owner itself, and then calls this method so the
    /// cancellation and the retirement share one owner view, one admitted
    /// identity, and one runtime port.
    ///
    /// The targets are never empty on this path. An empty list is structurally
    /// valid for the request but asks the wake owner to cancel nothing while
    /// reporting that nothing needed cancelling, which is exactly the
    /// absence-of-evidence-as-success failure this method must not perform; the
    /// concrete Host owner refuses an empty list for the same reason. A
    /// retirement whose targets are not owner-proven is reported as an
    /// unresolved wake phase by the caller instead of reaching this method.
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

/// Closed outcome of reading the exact owner-issued pending wake targets of one
/// retired revision from the existing wake owner.
///
/// A target is never derived, guessed, reconstructed from a wake reason, or
/// indexed: every field of one is transcribed from a record the wake owner
/// itself returned for one exact occurrence of the committed revision's own
/// normalized occurrence denominator.
///
/// `Proven` means the owner answered for every occurrence, so the set is
/// complete. An empty `targets` under `Proven` is a PROVEN absence: the owner
/// read its own state for every committed occurrence and definitively retains no
/// unadmitted wake for any of them. It is not a partial list — a partial list is
/// `Unproven`, because it is indistinguishable from a complete one at the
/// cancellation owner (issue #2808, I5.16).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UserAutomationWakeTargetEnumeration {
    /// The wake owner answered for every committed occurrence: it returned an
    /// exact retained pending record for the ones it still holds, and a
    /// definitive "retains no such record" for the rest.
    Proven {
        /// Exact owner-issued targets, one per retained pending wake. Empty only
        /// when the owner proved there is no unadmitted wake to cancel.
        targets: Vec<UserAutomationWakeCancellationTarget>,
    },
    /// No complete exact target list is owner-proven, so no cancellation is
    /// issued and the wake handoff of this retirement stays unresolved.
    Unproven {
        /// Closed reason the enumeration is not owner-proven.
        reason: String,
    },
}

/// Reads the exact owner-issued pending wake targets of one retired revision.
///
/// The occurrence set asked about is the committed revision's own normalized
/// occurrence denominator — the same bounded set the horizon publication owner
/// compiles from that revision, not a page of execution history and not the
/// Durable Job history this projection already references. Each member is read
/// back from the existing wake owner, which resolves it against its own journal
/// and returns the record it actually retains; only that returned record
/// supplies the wake identity, journal operation identity, idempotency key,
/// record checksum and State Fence a cancellation target carries.
///
/// Each read has exactly two honest answers, and the walk keeps them apart. A
/// returned record is a target. A
/// [`UserAutomationRuntimeError::NotRetained`] is the owner's complete negative
/// answer for that occurrence — it read its own state and definitively retains
/// no such record — so the walk continues with that occurrence accounted for and
/// nothing to cancel there. Every other answer, including
/// [`UserAutomationRuntimeError::Unavailable`] for an owner that could not be
/// read, makes the whole walk `Unproven`: an unknown target set is never
/// reported as a partial one, and "nothing needs cancelling" is never inferred
/// from an owner that could not answer.
///
/// A committed revision that declares no occurrence identity is `Unproven` as
/// well. The walk asked nobody, so it proved nothing; an empty denominator is
/// not evidence of an empty wake set. A valid normalized schedule always
/// declares at least one occurrence, so this is a fail-closed guard rather than
/// a reachable product state.
pub async fn read_retirement_wake_targets<R>(
    revision: &UserAutomationRevision,
    context: &RequestMetadata,
    identity: &OperationIdentity,
    runtime: &R,
) -> Result<UserAutomationWakeTargetEnumeration, UserAutomationExecutionError>
where
    R: UserAutomationWakePort + ?Sized,
{
    let identities = revision
        .compile_occurrence_identities()
        .map_err(UserAutomationExecutionError::Contract)?;
    // The read is authenticated as the revision's own owner principal: a
    // published calendar wake belongs to the revision owner, and the wake read
    // refuses a request whose principal does not name the invocation it
    // selects. The carrier identity is the caller's already-admitted remove
    // identity, so this read mints no canonical operation of its own.
    let mut targets: Vec<UserAutomationWakeCancellationTarget> = Vec::new();
    for occurrence in &identities {
        let request = retirement_wake_read_request(revision, occurrence, context, identity)?;
        let read_request = request.clone();
        match UserAutomationWakePort::read_pending_wake(runtime, request).await {
            Ok(readback) => {
                readback.validate_for(&read_request)?;
                targets.push(UserAutomationWakeCancellationTarget {
                    automation_id: revision.automation_id.clone(),
                    automation_revision: revision.revision.clone(),
                    wake_id: readback.intent.wake_id.clone(),
                    operation_id: readback.operation_id.clone(),
                    idempotency_key: readback.idempotency_key.clone(),
                    record_checksum: readback.record_checksum.clone(),
                    state_fence: readback.intent.state_fence.clone(),
                });
            }
            // The owner is the sole writer of its wake journal and has just read
            // it, so retaining no record for this exact occurrence is a complete
            // negative answer: there is no unadmitted wake here to cancel. The
            // walk continues, and the set stays provable.
            Err(UserAutomationRuntimeError::NotRetained(_)) => {}
            Err(error) => {
                return Ok(UserAutomationWakeTargetEnumeration::Unproven {
                    reason: format!(
                        "the wake owner did not answer for occurrence {} of retired revision {}: \
                         {error}; the exact unadmitted set is unknown, so no cancellation is \
                         issued from a partial denominator",
                        occurrence.occurrence_id, revision.revision
                    ),
                });
            }
        }
    }
    if identities.is_empty() {
        // The walk asked nobody, so it proved nothing. An empty denominator is
        // not evidence of an empty wake set, and reporting it as a proven
        // absence would be exactly the failure this function refuses elsewhere.
        return Ok(UserAutomationWakeTargetEnumeration::Unproven {
            reason: format!(
                "retired revision {} of {} declares no committed occurrence identity, so no wake \
                 owner was asked and the unadmitted wake set is unknown rather than proven empty",
                revision.revision, revision.automation_id
            ),
        });
    }
    // Every committed occurrence was answered: a retained record became a target
    // and a definitive `NotRetained` was accounted for. An empty set here is a
    // proven absence, not a missing answer.
    Ok(UserAutomationWakeTargetEnumeration::Proven { targets })
}

/// Builds the exact wake-owner read request for one committed occurrence of a
/// retired revision.
///
/// Every field is owner-issued. The automation, immutable revision and calendar
/// trigger come from the committed revision's own occurrence compiler, and the
/// principal, `WorkScope`, workdir and mode come from that same committed
/// revision document. Nothing here consults an ambient identity, a clock, a
/// reason string, or a row index, and the request names no wake: the wake
/// identity, journal operation identity, idempotency key, record checksum and
/// State Fence of a cancellation target are all returned by the wake owner.
fn retirement_wake_read_request(
    revision: &UserAutomationRevision,
    occurrence: &AutomationOccurrenceIdentity,
    context: &RequestMetadata,
    identity: &OperationIdentity,
) -> Result<UserAutomationWakeReadRequest, UserAutomationExecutionError> {
    if occurrence.automation_id != revision.automation_id
        || occurrence.revision != revision.revision
        || occurrence.occurrence_id
            != UserAutomationInvocation::occurrence_identity_for(
                &revision.automation_id,
                &revision.revision,
                &occurrence.trigger,
            )
            .map_err(UserAutomationExecutionError::Contract)?
    {
        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
            "retirement wake occurrence is not a member of the committed revision",
        ));
    }
    Ok(UserAutomationWakeReadRequest {
        context: context.clone(),
        authenticated_principal: revision.owner_principal.clone(),
        identity: identity.clone(),
        invocation: UserAutomationInvocation {
            automation_id: revision.automation_id.clone(),
            automation_revision: revision.revision.clone(),
            trigger: occurrence.trigger.clone(),
            mode: revision.mode,
            principal_ref: revision.owner_principal.clone(),
            work_scope_ref: revision.work_scope.scope_id.clone(),
            workdir_ref: revision.workdir_ref.clone(),
            trigger_origin: UserAutomationTriggerOrigin::ScheduledWake,
            // A published calendar occurrence of this revision is not an
            // admitted child of another automation, so its own lineage depth is
            // the root one.
            child_depth: 0,
            provenance: None,
        },
    })
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
    // The obligation itself is the error payload, not just its cause: the
    // durable `denominator_query_ref` inside it is the caller's only route to
    // finish enumerating the denominator, and `IncompleteDenominator` is defined
    // to carry one. Reducing this to a field name would leave the caller knowing
    // the work is blocked with no way to unblock it.
    if let Some(obligation) = execution
        .unresolved_reconciliation_refs
        .iter()
        .find(|obligation| obligation.cause == AutomationReconciliationCause::IncompleteDenominator)
    {
        return Err(
            UserAutomationExecutionError::OccurrenceDenominatorIncomplete(obligation.clone()),
        );
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

/// Unique non-blank occurrence identity list for a compiled horizon.
///
/// Same shape gate as [`validate_unique_text_list`] with the horizon-specific
/// refusal, because one stable occurrence identity appearing twice in a horizon
/// is a schedule defect, not a cancellation defect.
fn validate_unique_horizon_list(
    values: &[String],
    field: &'static str,
) -> Result<(), UserAutomationExecutionError> {
    let mut unique = BTreeSet::new();
    for value in values {
        validate_text(value, field)?;
        if !unique.insert(value) {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "duplicate UserAutomation occurrence identity in the horizon",
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
