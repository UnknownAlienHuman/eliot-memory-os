//! Production execution joins for the Kernel-owned UserAutomation service.
//!
//! The service owns the causal ordering at the boundary: authenticate and
//! validate the owner-issued projection, run the model-free Kernel preflight,
//! then hand an admitted occurrence to the existing Durable Job/WakeIntent
//! owners. Configuration failures go through the existing authenticated
//! notification route. This module owns no scheduler, job journal, Store,
//! authority, notification ledger, or model/provider call.

use std::collections::BTreeSet;

use eliot_contracts::{
    ArtifactId, ReceiptId, RequestMetadata, StateFence, TaskId, canonical_json_bytes, sha256_hex,
};
use eliot_kernel_core::UserAutomationOperatorIntent;
use eliot_kernel_core::user_automation::{
    AutomationCapabilityProfile, AutomationDeliveryTarget, AutomationExecutionReference,
    AutomationOccurrenceIdentity, AutomationReconciliationCause, AutomationReconciliationReference,
    AutomationResourceCeiling, AutomationWorkClass, DeliveryChannel, ProviderFingerprintPolicy,
    UserAutomationConfigurationState, UserAutomationError, UserAutomationExecutionMode,
    UserAutomationExecutionProjection, UserAutomationFailureProjection, UserAutomationInvocation,
    UserAutomationPreflightContext, UserAutomationPreflightDecision,
    UserAutomationPreflightProjection, UserAutomationPreflightReceipt, UserAutomationRevision,
    UserAutomationTrigger, UserAutomationTriggerOrigin,
};
use eliot_protocol::RequestIdentity as ProtocolRequestIdentity;
use eliot_protocol::dreamer_job::{
    AdmissionRef, DurableJobRequest, DurableRequestIdentity, JobOperation, JobOperationKind,
    JobRole, JobSubmission, OpaqueContentRef, durable_job_contract_identity,
};
use eliot_receipts::{OperationBinding, RequestBinding, WorkScopeBinding};
use eliot_runtime_contracts::{WakeIntent, WakeIntentState};
use eliot_store_api::{
    CAPABILITY_DREAMER_JOB_SUBMIT, OperationId, OperationIdentity, WriteReceipt,
};

/// Domain separator of the closed semantic-input document one admitted
/// occurrence submits to the Durable Job owner.
const USER_AUTOMATION_SEMANTIC_INPUT_DOMAIN: &str =
    "eliot.kernel.user-automation.durable-job.semantic-input.v1";

/// Domain separator of the declared output envelope one admitted occurrence
/// submits to the Durable Job owner.
const USER_AUTOMATION_OUTPUT_ENVELOPE_DOMAIN: &str =
    "eliot.kernel.user-automation.durable-job.output-envelope.v1";

/// Output disposition inside the declared byte ceiling (I11.12:49).
const USER_AUTOMATION_OUTPUT_VERBATIM: &str = "exact_stdout_stderr_verbatim";

/// Output disposition beyond the declared byte ceiling (I11.12:49).
const USER_AUTOMATION_OUTPUT_REVERSIBLE: &str = "reversible_payload_contract";

/// The exact semantic input one admitted occurrence submits.
///
/// Every member is already admitted: the qualified artifact identity and its
/// certified capability profile, the declared Skill/Tool closure, the bound
/// work scope and workdir, the declared resource ceiling and delivery target,
/// the preflight contract revision, the admitted config snapshot, and the
/// request fence. Nothing here is a model, provider, or scheduler decision.
#[derive(Serialize)]
struct UserAutomationSemanticInput<'a> {
    domain: &'static str,
    automation_id: &'a str,
    automation_revision: &'a str,
    occurrence_id: &'a str,
    mode: UserAutomationExecutionMode,
    qualified_ref: &'a str,
    capability_profile: &'a AutomationCapabilityProfile,
    skill_package_revision_refs: &'a [String],
    tool_definition_refs: &'a [String],
    work_scope: &'a WorkScopeBinding,
    workdir_ref: &'a str,
    resource_ceiling: &'a AutomationResourceCeiling,
    delivery_target: &'a AutomationDeliveryTarget,
    preflight_contract_revision: &'a str,
    config_snapshot_id: &'a str,
    state_fence: &'a StateFence,
}

/// The exact output envelope one admitted occurrence declares.
#[derive(Serialize)]
struct UserAutomationOutputEnvelope<'a> {
    domain: &'static str,
    within_limits: &'static str,
    beyond_limits: &'static str,
    max_output_bytes: u64,
    target_ref: &'a str,
    channels: &'a [DeliveryChannel],
    recipient_refs: &'a [String],
    preflight_contract_revision: &'a str,
}

/// Content-addresses one closed submission document.
///
/// The digest is computed over the exact canonical bytes this call submits, so
/// any reader can recompute it from the same admitted members, and the artifact
/// handle is that digest: the reference names the bytes it certifies rather
/// than a blob this boundary never wrote. The contract identity is the
/// existing Durable Job wire identity, not a new contract surface.
fn content_address<T: Serialize>(
    document: T,
    source_revision: &str,
) -> Result<OpaqueContentRef, UserAutomationExecutionError> {
    let bytes = canonical_json_bytes(&document).map_err(|error| {
        UserAutomationExecutionError::Metadata(format!(
            "the Durable Job submission document could not be canonically encoded: {error}"
        ))
    })?;
    let sha256 = sha256_hex(&bytes);
    Ok(OpaqueContentRef {
        contract: durable_job_contract_identity().map_err(|error| {
            UserAutomationExecutionError::Metadata(format!(
                "the existing Durable Job contract identity could not be read: {error}"
            ))
        })?,
        source_revision: source_revision.to_owned(),
        byte_length: bytes.len() as u64,
        artifact_id: Some(ArtifactId::new(sha256.clone()).map_err(|error| {
            UserAutomationExecutionError::Metadata(format!(
                "the Durable Job submission content address is not a valid artifact handle: \
                 {error}"
            ))
        })?),
        sha256,
    })
}

/// Derives the admitted submission deadline from the authenticated clock.
///
/// The deadline is the revision's own declared runtime ceiling added to the
/// authenticated request's observed clock reading, so it is bounded by a value
/// the owner declared rather than by a wall clock read at submission time. A
/// request that carries no observed time, or a ceiling that does not fit it,
/// has no derivable deadline and is refused instead of being padded.
fn admitted_deadline(
    context: &RequestMetadata,
    ceiling: &AutomationResourceCeiling,
) -> Result<u64, UserAutomationExecutionError> {
    let observed_ms = context
        .clock
        .known_time_ms
        .or(context.clock.valid_time_ms)
        .ok_or(UserAutomationExecutionError::RuntimeResponseMismatch(
            "the authenticated request carries no observed clock reading, so the Durable Job \
             admission has no derivable deadline",
        ))?;
    u64::try_from(observed_ms)
        .ok()
        .and_then(|observed| observed.checked_add(ceiling.max_runtime_ms))
        .ok_or(UserAutomationExecutionError::RuntimeResponseMismatch(
            "the declared runtime ceiling does not fit the authenticated clock reading",
        ))
}

/// Content-addresses the exact semantic input one occurrence submits.
///
/// The document names the qualified artifact and its certified capability
/// profile, the declared Skill/Tool closure, the bound work scope and workdir,
/// the declared resource ceiling and delivery target, the preflight contract
/// revision, the admitted config snapshot, and the request fence. Every member
/// is already admitted, and the digest is taken over the exact bytes submitted,
/// so a reader recomputes it from the same members.
fn admitted_semantic_input<'a>(
    admission: &'a UserAutomationRuntimeAdmission,
    occurrence_id: &'a str,
    work_scope: &'a WorkScopeBinding,
) -> Result<OpaqueContentRef, UserAutomationExecutionError> {
    let revision = &admission.revision;
    content_address(
        UserAutomationSemanticInput {
            domain: USER_AUTOMATION_SEMANTIC_INPUT_DOMAIN,
            automation_id: &revision.automation_id,
            automation_revision: &revision.revision,
            occurrence_id,
            mode: revision.mode,
            qualified_ref: &revision.task.qualified_ref,
            capability_profile: &revision.task.capability_profile,
            skill_package_revision_refs: &revision.portable_skill_package_revision_refs,
            tool_definition_refs: &revision.trusted_tool_definition_refs,
            work_scope,
            workdir_ref: &revision.workdir_ref,
            resource_ceiling: &revision.resource_ceiling,
            delivery_target: &revision.delivery_target,
            preflight_contract_revision: &revision.preflight_contract_revision,
            config_snapshot_id: &admission.preflight.config_snapshot_id,
            state_fence: &admission.context.state_fence,
        },
        &revision.revision,
    )
}

/// Content-addresses the declared output envelope one occurrence submits.
///
/// I11.12:49 requires exact stdout/stderr to be delivered verbatim within
/// policy and size limits and the reversible payload contract of I7.26 beyond
/// them, with neither path summarized by a model. The envelope declares both
/// dispositions, the byte ceiling that separates them, and the delivery target
/// they are delivered through.
fn admitted_output_envelope(
    admission: &UserAutomationRuntimeAdmission,
) -> Result<OpaqueContentRef, UserAutomationExecutionError> {
    let revision = &admission.revision;
    content_address(
        UserAutomationOutputEnvelope {
            domain: USER_AUTOMATION_OUTPUT_ENVELOPE_DOMAIN,
            within_limits: USER_AUTOMATION_OUTPUT_VERBATIM,
            beyond_limits: USER_AUTOMATION_OUTPUT_REVERSIBLE,
            max_output_bytes: revision.resource_ceiling.max_output_bytes,
            target_ref: &revision.delivery_target.target_ref,
            channels: &revision.delivery_target.channels,
            recipient_refs: &revision.delivery_target.recipient_refs,
            preflight_contract_revision: &revision.preflight_contract_revision,
        },
        &admission.preflight.config_snapshot_id,
    )
}

/// Reads the job admission reference from the committed source receipt.
///
/// Every binding here is copied from a value the admitted occurrence already
/// carries: the authority, session and epoch are the committed receipt's own
/// bindings, the requester is the authenticated principal, the route class and
/// cost ceiling are the revision's declared ones, and the admission receipt is
/// the committed source receipt's own identity — the receipt whose commit
/// admitted this occurrence. Nothing is minted for the admission, so the
/// reference can only ever name work the canonical Store already committed.
fn admitted_job_ref(
    admission: &UserAutomationRuntimeAdmission,
    scope: &WorkScopeBinding,
    budget_units: u64,
    deadline_unix_ms: u64,
) -> Result<AdmissionRef, UserAutomationExecutionError> {
    let core = &admission.preflight.source_receipt.core;
    let revision = &admission.revision;
    Ok(AdmissionRef {
        authority: core.authority.clone(),
        requester_principal: admission.authenticated_principal.clone(),
        session: core.session.clone(),
        scope: scope.clone(),
        capability: CAPABILITY_DREAMER_JOB_SUBMIT.to_owned(),
        route_class: revision.route_cost_policy.route_ref.clone(),
        budget_units,
        deadline_unix_ms,
        validity_epoch: core.authority.authority_epoch.clone(),
        resource_generation: admission.context.state_fence.resource_generation,
        admission_receipt: ReceiptId::new(
            admission
                .preflight
                .source_receipt
                .identity
                .receipt_id
                .as_str(),
        )
        .map_err(|_| {
            UserAutomationExecutionError::RuntimeResponseMismatch(
                "the committed source receipt identity is not a valid admission receipt",
            )
        })?,
    })
}

/// Builds one contract identity value, reporting which member was refused.
fn typed_id<T>(
    build: fn(String) -> Result<T, eliot_contracts::ContractError>,
    value: &str,
) -> Result<T, UserAutomationExecutionError>
where
    T: Clone,
{
    build(value.to_owned()).map_err(|error| {
        UserAutomationExecutionError::Metadata(format!(
            "the Durable Job submission identity {value} was refused: {error}"
        ))
    })
}
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
    /// The mutation's disposition is proven by exact receipt evidence, but the
    /// ledger answer for it is still unread.
    ///
    /// Issue #2764 item 6: this is a complete answer about the mutation and an
    /// incomplete one about the ledger, and the two are different facts. The
    /// distinction is load-bearing for the same reason `NotRetained` is
    /// separated from `UnknownOutcome`: a caller that can see "the commit
    /// provably happened" must not have to re-derive it from prose, and a caller
    /// that sees this must not treat the operation as possibly-unapplied.
    #[error("UserAutomation runtime owner mutation disposition is settled: {0}")]
    OutcomeSettled(String),
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
/// The complete K0 submission travels with the occurrence binding so the
/// runtime adapter can prove which automation occurrence the owner material
/// belongs to. [`UserAutomationDurableJobMaterial::from_admitted_occurrence`]
/// compiles that submission from members the admitted revision and its
/// committed source receipt already carry; a caller that holds a submission
/// from the Durable Job owner may still supply it directly, and both shapes go
/// through the same [`Self::validate_for`] and
/// [`Self::validate_for_revision`] checks.
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
    /// Exact Skill package revisions certified by the qualified owner for the
    /// dependency closure this material submits.
    ///
    /// The revision the deterministic preflight approved declares the admitted
    /// closure; the material repeats it so a substituted artifact with an
    /// equal top-level profile but a different transitive closure fails closed
    /// instead of reaching a model/provider route. Older material without the
    /// closure still decodes and is refused at revision binding, never admitted.
    #[serde(default)]
    pub skill_package_revision_refs: Vec<String>,
    /// Exact Tool Definition revisions certified by the qualified owner for the
    /// dependency closure this material submits, with the same binding rule as
    /// the Skill revisions above.
    #[serde(default)]
    pub tool_definition_refs: Vec<String>,
    /// Complete owner-issued Durable Job submission request.
    pub request: DurableJobRequest,
}

impl UserAutomationDurableJobMaterial {
    /// Compiles the complete Durable Job submission for one admitted
    /// occurrence.
    ///
    /// Every member is read from an owner the admitted occurrence already
    /// carries; nothing is asserted on the owner's behalf:
    ///
    /// - the job identity and the idempotency key are the stable occurrence
    ///   identity, so re-admitting the same occurrence replays the same
    ///   mutation instead of minting a second one, and a different occurrence
    ///   can never reuse this one;
    /// - the attempt identity and the semantic-input artifact handle are the
    ///   content address of the exact closed semantic-input document below, so
    ///   the digest a reviewer recomputes is the digest the submission carries;
    /// - the output envelope is the declared envelope of this revision — the
    ///   verbatim stdout/stderr bound with its declared byte ceiling, and the
    ///   reversible payload contract that takes over beyond it (I11.12:49);
    /// - the work scope, authority, session, validity epoch, resource
    ///   generation, effect class and admission receipt are the committed
    ///   source receipt's own bindings, which `UserAutomationRuntimeAdmission`
    ///   has already bound to this request fence and product;
    /// - the requester principal is the authenticated principal, the capability
    ///   is the Store's own closed name for a `SUBMIT_JOB`, the route class is
    ///   the revision's declared route, the budget is its declared cost
    ///   ceiling, and the deadline is its declared runtime ceiling added to
    ///   the authenticated clock reading.
    ///
    /// A revision with no declared cost ceiling, a request whose authenticated
    /// clock reading carries no time, or an identity the contract types reject
    /// is refused here with the exact member, so a submission is never padded
    /// with a value no owner declared.
    pub fn from_admitted_occurrence(
        admission: &UserAutomationRuntimeAdmission,
    ) -> Result<Self, UserAutomationExecutionError> {
        let revision = &admission.revision;
        let context = &admission.context;
        let core = &admission.preflight.source_receipt.core;
        let occurrence_id = admission.invocation.occurrence_identity()?;
        let budget_units = revision.route_cost_policy.max_cost_units;
        if budget_units == 0 {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "the revision declares no route cost ceiling, so the Durable Job admission has \
                 no admitted budget",
            ));
        }
        let deadline_unix_ms = admitted_deadline(context, &revision.resource_ceiling)?;
        let work_scope = WorkScopeBinding {
            scope_id: core.work_scope.scope_id.clone(),
            product_id: core.work_scope.product_id.clone(),
            resource_generation: core.work_scope.resource_generation,
            state_fence: core.work_scope.state_fence.clone(),
        };
        let semantic_input = admitted_semantic_input(admission, &occurrence_id, &work_scope)?;
        let output_envelope = admitted_output_envelope(admission)?;
        let job_id = typed_id(TaskId::new, &format!("user-automation:{occurrence_id}"))?;
        let attempt_id = typed_id(ArtifactId::new, &semantic_input.sha256)?;
        let submission = JobSubmission {
            job_id: job_id.clone(),
            attempt_id,
            work_scope: work_scope.clone(),
            semantic_input,
            output_contract: output_envelope,
            admission: admitted_job_ref(admission, &work_scope, budget_units, deadline_unix_ms)?,
            cancellation_id: format!("user-automation:{occurrence_id}:cancellation"),
        };
        let operation = JobOperation::Submit {
            submission: Box::new(submission.clone()),
        };
        let operation_binding = OperationBinding {
            operation_id: typed_id(
                OperationId::new,
                &format!(
                    "user-automation:{occurrence_id}:{}",
                    JobOperationKind::Submit.as_str()
                ),
            )?,
            request_id: context.request_id.clone(),
            idempotency_key: format!("user-automation:{occurrence_id}:durable-job-submit"),
            operation_kind: JobOperationKind::Submit.as_str().to_owned(),
            effect: core.operation.effect,
            state_fence: context.state_fence.clone(),
        };
        let request = ProtocolRequestIdentity {
            request: RequestBinding {
                metadata: context.clone(),
                state_fence: context.state_fence.clone(),
            },
            idempotency_key: operation_binding.idempotency_key.clone(),
            deadline_unix_ms,
            cancellation_id: submission.cancellation_id.clone(),
        };
        let canonical_request_hash = DurableRequestIdentity::digest_for(
            &operation_binding,
            &request,
            &operation,
            JobRole::Requester,
        )
        .map_err(|error| {
            UserAutomationExecutionError::Metadata(format!(
                "the Durable Job submission digest could not be computed: {error}"
            ))
        })?;
        let material = Self {
            occurrence_id,
            qualified_ref: revision.task.qualified_ref.clone(),
            mode: revision.mode,
            capability_profile: revision.task.capability_profile.clone(),
            skill_package_revision_refs: revision.portable_skill_package_revision_refs.clone(),
            tool_definition_refs: revision.trusted_tool_definition_refs.clone(),
            request: DurableJobRequest {
                request_identity: DurableRequestIdentity {
                    request,
                    operation: operation_binding,
                    canonical_request_hash,
                },
                role: JobRole::Requester,
                operation,
            },
        };
        material.validate_for(
            &admission.context,
            &admission.authenticated_principal,
            &admission.invocation,
        )?;
        material.validate_for_revision(
            &admission.context,
            &admission.authenticated_principal,
            &admission.invocation,
            revision,
        )?;
        Ok(material)
    }

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
        for reference in self
            .skill_package_revision_refs
            .iter()
            .chain(self.tool_definition_refs.iter())
        {
            validate_text(reference, "runtime.durable_job.dependency_closure")?;
        }
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
        // Transitive provider/tool reachability is bound through the admitted
        // dependency closure, not through the top-level profile alone: the
        // material must repeat exactly the Skill revisions the revision admits,
        // and its Tool Definitions must be a non-empty exact set. A substituted
        // artifact whose closure reaches a provider the revision never admitted
        // cannot satisfy this equality, so indirect provider access fails closed
        // here instead of reaching the Durable Job owner.
        if self.skill_package_revision_refs != revision.portable_skill_package_revision_refs
            || self.tool_definition_refs.is_empty()
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "durable job material dependency closure",
            ));
        }
        for reference in &self.tool_definition_refs {
            validate_text(reference, "runtime.durable_job.tool_definition")?;
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
    /// Complete Durable Job material. A caller that holds a submission from the
    /// Durable Job owner supplies it here; when it is absent, the concrete
    /// production adapter compiles it from this admission and revalidates the
    /// whole request before calling the owner.
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
    /// Exact complete owner receipt from which these targets were selected.
    /// Missing values are legacy/unqualified cancellation requests and are not
    /// accepted by the concrete Host cancellation owner.
    #[serde(default)]
    pub enumeration_receipt: Option<Box<UserAutomationWakeEnumerationReceipt>>,
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
        let receipt = self.enumeration_receipt.as_deref().ok_or(
            UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation requires a complete owner enumeration receipt",
            ),
        )?;
        receipt.validate_integrity()?;
        if receipt.automation_id != self.automation_id
            || receipt.automation_revision != self.automation_revision
            || receipt.parent_operation_identity != self.identity
            || receipt.state_fence != self.state_fence
            || receipt.authenticated_owner_identity != self.authenticated_principal
            || receipt.cancellation_targets()? != self.targets
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation enumeration receipt binding",
            ));
        }
        Ok(())
    }

    /// Checks the atomic Host answer against the exact ordered target batch.
    /// Host applies the batch in request order; a subset, extra wake, or
    /// reordered answer is not evidence that this request was completed.
    pub fn validate_cancelled_wake_ids(
        &self,
        cancelled_wake_ids: &[String],
    ) -> Result<(), UserAutomationExecutionError> {
        self.validate()?;
        if self.targets.is_empty() {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation has no owner-issued targets",
            ));
        }
        validate_unique_text_list(cancelled_wake_ids, "cancelled_wake_ids")?;
        if cancelled_wake_ids.len() != self.targets.len()
            || cancelled_wake_ids
                .iter()
                .zip(&self.targets)
                .any(|(wake_id, target)| wake_id != &target.wake_id)
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancelled wakes do not match the exact owner-issued target batch",
            ));
        }
        Ok(())
    }

    /// Computes the exact Host batch identity from the ordered owner-issued
    /// targets. The Host adapter uses the same function before append and
    /// during readback, so a caller cannot substitute another target set.
    pub fn host_batch_operation_identity(
        &self,
    ) -> Result<(String, String), UserAutomationExecutionError> {
        self.validate()?;
        if self.targets.is_empty() {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation has no owner-issued targets",
            ));
        }
        let members: Vec<(&str, &str)> = self
            .targets
            .iter()
            .map(|target| (target.wake_id.as_str(), target.record_checksum.as_str()))
            .collect();
        let bytes = serde_json::to_vec(&(
            "eliot.user_automation.wake-cancellation-batch.v1",
            self.identity.operation_id.as_str(),
            self.identity.idempotency_key.as_str(),
            members,
        ))
        .map_err(|_| {
            UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation batch identity encoding",
            )
        })?;
        let digest = sha256_hex(&bytes);
        Ok((
            format!("ua-wake-cancel-batch:{digest}"),
            format!("ua-wake-cancel-batch-key:{digest}"),
        ))
    }

    /// Canonical commitment retained by the Host batch record for this exact
    /// typed request, including its owner-issued target and enumeration proof.
    pub fn request_commitment_sha256(&self) -> Result<String, UserAutomationExecutionError> {
        self.validate()?;
        canonical_json_bytes(self)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|_| {
                UserAutomationExecutionError::RuntimeResponseMismatch(
                    "cancellation request commitment encoding",
                )
            })
    }
}

/// Exact result read back from the Host journal for one original cancellation
/// request. This is distinct from a current-wake lookup: it proves the named
/// batch operation and request commitment were durably committed.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeCancellationReadback {
    /// Host batch operation identity selected by the original request.
    pub batch_operation_id: String,
    /// Host batch idempotency key selected by the original request.
    pub batch_idempotency_key: String,
    /// Canonical commitment of the exact typed cancellation request.
    pub request_commitment_sha256: String,
    /// Checksum of the retained Host cancellation-batch record.
    pub record_checksum: String,
    /// Sequence of the committed journal append.
    pub journal_sequence: u64,
    /// Transaction identity of the committed journal append.
    pub journal_transaction_id: String,
    /// Ordered exact wake identities in the committed cancellation batch.
    pub cancelled_wake_ids: Vec<String>,
}

impl UserAutomationWakeCancellationReadback {
    /// Validates the exact operation, request bytes, and ordered targets.
    pub fn validate_for(
        &self,
        request: &UserAutomationWakeCancellation,
    ) -> Result<(), UserAutomationExecutionError> {
        request.validate()?;
        let (expected_operation, expected_key) = request.host_batch_operation_identity()?;
        let expected_commitment = request.request_commitment_sha256()?;
        request.validate_cancelled_wake_ids(&self.cancelled_wake_ids)?;
        for (value, field) in [
            (
                &self.batch_operation_id,
                "cancellation_readback.batch_operation_id",
            ),
            (
                &self.batch_idempotency_key,
                "cancellation_readback.batch_idempotency_key",
            ),
            (
                &self.journal_transaction_id,
                "cancellation_readback.journal_transaction_id",
            ),
        ] {
            validate_text(value, field)?;
        }
        validate_digest(
            &self.request_commitment_sha256,
            "cancellation_readback.request_commitment_sha256",
        )?;
        validate_digest(
            &self.record_checksum,
            "cancellation_readback.record_checksum",
        )?;
        if self.journal_sequence == 0
            || self.batch_operation_id != expected_operation
            || self.batch_idempotency_key != expected_key
            || self.request_commitment_sha256 != expected_commitment
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation owner readback does not match the original request",
            ));
        }
        Ok(())
    }

    /// Computes the commitment of the exact Host batch and append receipt.
    pub fn owner_receipt_commitment_sha256(&self) -> Result<String, UserAutomationExecutionError> {
        canonical_json_bytes(&(
            "eliot.user_automation.wake-cancellation-owner-receipt.v1",
            &self.batch_operation_id,
            &self.batch_idempotency_key,
            &self.request_commitment_sha256,
            &self.record_checksum,
            self.journal_sequence,
            &self.journal_transaction_id,
            &self.cancelled_wake_ids,
        ))
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|_| {
            UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation owner receipt commitment encoding",
            )
        })
    }
}

/// Exact cancellation-batch result carried over a newly authenticated Host
/// channel. The channel digest is separate from the retained batch commitment:
/// it authenticates this readback connection without rewriting the original
/// send attempt's channel evidence.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationAuthenticatedWakeCancellationReadback {
    /// Server-authenticated channel used to query the Host journal.
    pub authenticated_channel_binding_sha256: String,
    /// Exact retained batch and journal append evidence.
    pub readback: Box<UserAutomationWakeCancellationReadback>,
}

impl UserAutomationAuthenticatedWakeCancellationReadback {
    /// Validates the readback result and its independent authenticated channel.
    pub fn validate_for(
        &self,
        request: &UserAutomationWakeCancellation,
        authenticated_channel_binding_sha256: &str,
    ) -> Result<(), UserAutomationExecutionError> {
        validate_digest(
            &self.authenticated_channel_binding_sha256,
            "cancellation_readback.authenticated_channel_binding_sha256",
        )?;
        if self.authenticated_channel_binding_sha256 != authenticated_channel_binding_sha256 {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "cancellation readback channel binding",
            ));
        }
        self.readback.validate_for(request)
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

/// Request for one owner snapshot that accounts for the complete committed
/// occurrence denominator of a retired immutable revision.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeEnumerationRequest {
    /// Authenticated operator request metadata and State Fence.
    pub context: RequestMetadata,
    /// Principal authenticated by Kernel/Host for the immutable revision owner.
    pub authenticated_principal: String,
    /// Exact parent remove operation identity.
    pub identity: OperationIdentity,
    /// Retired automation identity.
    pub automation_id: String,
    /// Retired immutable revision identity.
    pub automation_revision: String,
    /// Canonical digest of the committed immutable revision.
    pub revision_digest: String,
    /// Complete committed occurrence denominator in canonical owner order.
    pub denominator: Vec<AutomationOccurrenceIdentity>,
    /// Canonical digest of the complete denominator.
    pub denominator_digest: String,
}

impl UserAutomationWakeEnumerationRequest {
    /// Validates every identity and recomputes the complete denominator digest.
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
            "wake_enumeration.authenticated_principal",
        )?;
        validate_text(&self.automation_id, "wake_enumeration.automation_id")?;
        validate_text(
            &self.automation_revision,
            "wake_enumeration.automation_revision",
        )?;
        validate_digest(&self.revision_digest, "wake_enumeration.revision_digest")?;
        validate_digest(
            &self.denominator_digest,
            "wake_enumeration.denominator_digest",
        )?;
        validate_wake_occurrence_denominator(
            &self.automation_id,
            &self.automation_revision,
            &self.denominator,
        )?;
        let expected = wake_occurrence_denominator_digest(&self.denominator)?;
        if self.denominator_digest != expected {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration denominator digest",
            ));
        }
        Ok(())
    }
}

/// Version of the provider-neutral owner-issued wake enumeration receipt.
pub const USER_AUTOMATION_WAKE_ENUMERATION_RECEIPT_VERSION: u16 = 1;

/// Exact Host journal location used to prove one occurrence's disposition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeOwnerEvidence {
    /// Occurrence identity this owner evidence answers.
    pub occurrence_id: String,
    /// Exact Host installation identity from the Host owner epoch.
    pub host_owner_identity: String,
    /// Canonical Host owner epoch digest; the receipt separately binds the
    /// journal sequence and last checksum within that generation.
    pub host_owner_generation: String,
    /// Monotonic Host journal sequence of the one shared snapshot.
    pub journal_sequence: u64,
    /// Last durable journal checksum in that snapshot, absent only at genesis.
    pub journal_last_checksum: Option<String>,
    /// Canonical digest of the exact Host snapshot projection.
    pub snapshot_digest: String,
    /// Exact retained wake-record checksum, present when the snapshot has a
    /// single matching record rather than a proven absence.
    pub wake_record_checksum: Option<String>,
    /// Exact lifecycle state of that matching record, when one is retained.
    pub wake_state: Option<WakeIntentState>,
}

/// One denominator member's complete owner-issued disposition.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum UserAutomationWakeOccurrenceDisposition {
    /// The Host owner retains this exact unadmitted pending wake.
    PendingTarget {
        /// Exact journal-backed cancellation target.
        target: UserAutomationWakeCancellationTarget,
    },
    /// The Host owner snapshot proves no unadmitted pending target is retained.
    /// Evidence may cite a matching wake already claimed, started, or terminal.
    NotRetained {
        /// Exact per-occurrence reference into the shared owner snapshot.
        evidence: UserAutomationWakeOwnerEvidence,
    },
    /// The owner snapshot could not classify this member safely.
    Unresolved {
        /// Exact per-occurrence reference into the shared owner snapshot.
        evidence: UserAutomationWakeOwnerEvidence,
        /// Closed reason this member prevents cancellation.
        reason: String,
    },
}

/// Counts proving that each committed denominator member appears exactly once.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeEnumerationCoverage {
    /// Number of immutable committed occurrences.
    pub denominator_count: u64,
    /// Number of occurrences represented by exactly one disposition.
    pub covered_count: u64,
    /// Number represented as retained pending targets.
    pub pending_target_count: u64,
    /// Number represented as owner-proven not retained.
    pub not_retained_count: u64,
    /// Number represented explicitly as unresolved.
    pub unresolved_count: u64,
    /// Whether every denominator member has one disposition.
    pub complete: bool,
}

/// Versioned provider-neutral projection of one durable Host owner snapshot.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserAutomationWakeEnumerationReceipt {
    /// Receipt schema version.
    pub version: u16,
    /// Automation bound by the committed revision.
    pub automation_id: String,
    /// Immutable revision identity.
    pub automation_revision: String,
    /// Canonical immutable revision digest.
    pub revision_digest: String,
    /// Exact remove operation identity that asked the Host owner.
    pub parent_operation_identity: OperationIdentity,
    /// Complete committed occurrence denominator, in canonical owner order.
    pub denominator: Vec<AutomationOccurrenceIdentity>,
    /// Canonical digest of the complete denominator.
    pub denominator_digest: String,
    /// Exact Host installation identity that owns the journal snapshot.
    pub host_owner_identity: String,
    /// Exact sequence-bound Host owner generation.
    pub host_owner_generation: String,
    /// Digest of the server-authored Host channel and peer-admission evidence.
    pub authenticated_channel_binding_sha256: String,
    /// Monotonic Host journal sequence of the shared snapshot.
    pub journal_sequence: u64,
    /// Last durable journal checksum in that snapshot, absent only at genesis.
    pub journal_last_checksum: Option<String>,
    /// Canonical digest of the exact Host snapshot projection.
    pub snapshot_digest: String,
    /// State Fence under which the authenticated retirement was requested.
    pub state_fence: StateFence,
    /// Authenticated immutable revision owner principal.
    pub authenticated_owner_identity: String,
    /// One disposition for every denominator member, in denominator order.
    pub dispositions: Vec<UserAutomationWakeOccurrenceDisposition>,
    /// Explicit denominator coverage counts and completeness bit.
    pub coverage: UserAutomationWakeEnumerationCoverage,
    /// Canonical digest over this receipt with this field empty.
    pub canonical_digest: String,
}

impl UserAutomationWakeEnumerationReceipt {
    /// Recomputes coverage and canonical digest and binds the receipt to the
    /// exact committed revision and request that asked the owner.
    pub fn validate_for(
        &self,
        request: &UserAutomationWakeEnumerationRequest,
    ) -> Result<(), UserAutomationExecutionError> {
        request.validate()?;
        if self.version != USER_AUTOMATION_WAKE_ENUMERATION_RECEIPT_VERSION
            || self.automation_id != request.automation_id
            || self.automation_revision != request.automation_revision
            || self.revision_digest != request.revision_digest
            || self.denominator != request.denominator
            || self.denominator_digest != request.denominator_digest
            || self.parent_operation_identity != request.identity
            || self.state_fence != request.context.state_fence
            || self.authenticated_owner_identity != request.authenticated_principal
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration receipt binding",
            ));
        }
        validate_text(
            &self.host_owner_identity,
            "wake_enumeration.host_owner_identity",
        )?;
        validate_digest(
            &self.host_owner_generation,
            "wake_enumeration.host_owner_generation",
        )?;
        validate_digest(
            &self.authenticated_channel_binding_sha256,
            "wake_enumeration.authenticated_channel_binding_sha256",
        )?;
        validate_digest(&self.snapshot_digest, "wake_enumeration.snapshot_digest")?;
        self.state_fence
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        self.validate_integrity()?;
        Ok(())
    }

    /// Validates the self-contained receipt without comparing it to a newer
    /// caller State Fence. Used when reading a previously retained receipt.
    pub fn validate_integrity(&self) -> Result<(), UserAutomationExecutionError> {
        if self.version != USER_AUTOMATION_WAKE_ENUMERATION_RECEIPT_VERSION {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration receipt version",
            ));
        }
        self.parent_operation_identity
            .validate()
            .map_err(UserAutomationServiceError::Store)
            .map_err(UserAutomationExecutionError::Service)?;
        validate_text(&self.automation_id, "wake_enumeration.automation_id")?;
        validate_text(
            &self.automation_revision,
            "wake_enumeration.automation_revision",
        )?;
        validate_digest(&self.revision_digest, "wake_enumeration.revision_digest")?;
        validate_digest(
            &self.denominator_digest,
            "wake_enumeration.denominator_digest",
        )?;
        validate_wake_occurrence_denominator(
            &self.automation_id,
            &self.automation_revision,
            &self.denominator,
        )?;
        if wake_occurrence_denominator_digest(&self.denominator)? != self.denominator_digest {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration receipt denominator digest",
            ));
        }
        validate_text(
            &self.host_owner_identity,
            "wake_enumeration.host_owner_identity",
        )?;
        validate_digest(
            &self.host_owner_generation,
            "wake_enumeration.host_owner_generation",
        )?;
        validate_digest(
            &self.authenticated_channel_binding_sha256,
            "wake_enumeration.authenticated_channel_binding_sha256",
        )?;
        validate_digest(&self.snapshot_digest, "wake_enumeration.snapshot_digest")?;
        validate_text(
            &self.authenticated_owner_identity,
            "wake_enumeration.authenticated_owner_identity",
        )?;
        self.state_fence
            .validate()
            .map_err(|error| UserAutomationExecutionError::Metadata(error.to_string()))?;
        if let Some(checksum) = &self.journal_last_checksum {
            validate_digest(checksum, "wake_enumeration.journal_last_checksum")?;
        }
        self.validate_dispositions()?;
        if self.canonical_digest != self.compute_digest()? {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration receipt digest",
            ));
        }
        Ok(())
    }

    /// Returns the exact pending targets only when the complete receipt has no
    /// unresolved member.
    pub fn cancellation_targets(
        &self,
    ) -> Result<Vec<UserAutomationWakeCancellationTarget>, UserAutomationExecutionError> {
        self.validate_dispositions()?;
        if !self.coverage.complete || self.coverage.unresolved_count != 0 {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration contains unresolved denominator members",
            ));
        }
        Ok(self
            .dispositions
            .iter()
            .filter_map(|disposition| match disposition {
                UserAutomationWakeOccurrenceDisposition::PendingTarget { target } => {
                    Some(target.clone())
                }
                UserAutomationWakeOccurrenceDisposition::NotRetained { .. }
                | UserAutomationWakeOccurrenceDisposition::Unresolved { .. } => None,
            })
            .collect())
    }

    /// Verifies that the owner bound its receipt to the exact authenticated
    /// Host channel that carried the batch request.
    pub fn validate_authenticated_channel(
        &self,
        expected_channel_binding_sha256: &str,
    ) -> Result<(), UserAutomationExecutionError> {
        validate_digest(
            expected_channel_binding_sha256,
            "wake_enumeration.expected_channel_binding_sha256",
        )?;
        if self.authenticated_channel_binding_sha256 != expected_channel_binding_sha256 {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration authenticated channel binding",
            ));
        }
        Ok(())
    }

    /// Recomputes the canonical receipt digest with the digest field cleared.
    pub fn compute_digest(&self) -> Result<String, UserAutomationExecutionError> {
        let mut unsigned = self.clone();
        unsigned.canonical_digest.clear();
        let bytes = canonical_json_bytes(&unsigned).map_err(|_| {
            UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration receipt encoding",
            )
        })?;
        Ok(sha256_hex(&bytes))
    }

    fn validate_dispositions(&self) -> Result<(), UserAutomationExecutionError> {
        if self.denominator.is_empty() || self.dispositions.len() != self.denominator.len() {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration receipt coverage",
            ));
        }
        let mut pending = 0_u64;
        let mut not_retained = 0_u64;
        let mut unresolved = 0_u64;
        for (occurrence, disposition) in self.denominator.iter().zip(&self.dispositions) {
            match disposition {
                UserAutomationWakeOccurrenceDisposition::PendingTarget { target } => {
                    validate_text(&target.wake_id, "wake_enumeration.target.wake_id")?;
                    validate_text(&target.operation_id, "wake_enumeration.target.operation_id")?;
                    validate_text(
                        &target.idempotency_key,
                        "wake_enumeration.target.idempotency_key",
                    )?;
                    validate_digest(
                        &target.record_checksum,
                        "wake_enumeration.target.record_checksum",
                    )?;
                    target.state_fence.validate().map_err(|error| {
                        UserAutomationExecutionError::Metadata(error.to_string())
                    })?;
                    if target.automation_id != self.automation_id
                        || target.automation_revision != self.automation_revision
                        || target.wake_id != occurrence.occurrence_id
                        || target.state_fence != self.state_fence
                    {
                        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                            "wake enumeration target binding",
                        ));
                    }
                    pending += 1;
                }
                UserAutomationWakeOccurrenceDisposition::NotRetained { evidence } => {
                    validate_wake_owner_evidence(self, occurrence, evidence)?;
                    if evidence.wake_state == Some(WakeIntentState::Pending) {
                        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                            "pending wake cannot be classified as not retained",
                        ));
                    }
                    not_retained += 1;
                }
                UserAutomationWakeOccurrenceDisposition::Unresolved { evidence, reason } => {
                    validate_wake_owner_evidence(self, occurrence, evidence)?;
                    validate_text(reason, "wake_enumeration.unresolved.reason")?;
                    unresolved += 1;
                }
            }
        }
        let denominator_count = self.denominator.len() as u64;
        let expected_coverage = UserAutomationWakeEnumerationCoverage {
            denominator_count,
            covered_count: denominator_count,
            pending_target_count: pending,
            not_retained_count: not_retained,
            unresolved_count: unresolved,
            complete: true,
        };
        if self.coverage != expected_coverage {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration coverage counts",
            ));
        }
        Ok(())
    }
}

fn validate_wake_owner_evidence(
    receipt: &UserAutomationWakeEnumerationReceipt,
    occurrence: &AutomationOccurrenceIdentity,
    evidence: &UserAutomationWakeOwnerEvidence,
) -> Result<(), UserAutomationExecutionError> {
    validate_text(
        &evidence.occurrence_id,
        "wake_enumeration.evidence.occurrence_id",
    )?;
    validate_text(
        &evidence.host_owner_identity,
        "wake_enumeration.evidence.host_owner_identity",
    )?;
    validate_digest(
        &evidence.host_owner_generation,
        "wake_enumeration.evidence.host_owner_generation",
    )?;
    validate_digest(
        &evidence.snapshot_digest,
        "wake_enumeration.evidence.snapshot_digest",
    )?;
    if let Some(checksum) = &evidence.journal_last_checksum {
        validate_digest(checksum, "wake_enumeration.evidence.journal_last_checksum")?;
    }
    if let Some(checksum) = &evidence.wake_record_checksum {
        validate_digest(checksum, "wake_enumeration.evidence.wake_record_checksum")?;
    }
    if evidence.wake_record_checksum.is_some() != evidence.wake_state.is_some() {
        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
            "wake enumeration retained-record evidence pair",
        ));
    }
    if evidence.occurrence_id != occurrence.occurrence_id
        || evidence.host_owner_identity != receipt.host_owner_identity
        || evidence.host_owner_generation != receipt.host_owner_generation
        || evidence.journal_sequence != receipt.journal_sequence
        || evidence.journal_last_checksum != receipt.journal_last_checksum
        || evidence.snapshot_digest != receipt.snapshot_digest
    {
        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
            "wake enumeration owner evidence binding",
        ));
    }
    Ok(())
}

/// Computes the canonical digest of one complete committed denominator.
pub fn wake_occurrence_denominator_digest(
    denominator: &[AutomationOccurrenceIdentity],
) -> Result<String, UserAutomationExecutionError> {
    let bytes = canonical_json_bytes(&denominator).map_err(|_| {
        UserAutomationExecutionError::RuntimeResponseMismatch(
            "wake enumeration denominator encoding",
        )
    })?;
    Ok(sha256_hex(&bytes))
}

fn validate_wake_occurrence_denominator(
    automation_id: &str,
    automation_revision: &str,
    denominator: &[AutomationOccurrenceIdentity],
) -> Result<(), UserAutomationExecutionError> {
    if denominator.is_empty() {
        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
            "wake enumeration denominator is empty",
        ));
    }
    let mut seen = BTreeSet::new();
    for occurrence in denominator {
        if occurrence.automation_id != automation_id
            || occurrence.revision != automation_revision
            || occurrence.occurrence_id
                != UserAutomationInvocation::occurrence_identity_for(
                    &occurrence.automation_id,
                    &occurrence.revision,
                    &occurrence.trigger,
                )
                .map_err(UserAutomationExecutionError::Contract)?
            || !seen.insert(occurrence.occurrence_id.as_str())
        {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "wake enumeration denominator identity",
            ));
        }
    }
    Ok(())
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

    /// Returns the denominator members past the slice cursor that this bounded
    /// flight did not carry (issue #2806 item 10).
    ///
    /// The request always carries the complete denominator beside its bounded
    /// entries, so a caller whose owner acknowledged only the entries can still
    /// name exactly what remains: the owner's own remaining set plus this tail.
    /// An empty tail means this flight carried the whole slice from the cursor.
    pub fn uncapped_tail_ids(&self) -> Result<Vec<String>, UserAutomationExecutionError> {
        self.validate()?;
        let start = horizon_slice_start(
            &self.denominator_occurrence_ids,
            self.trigger,
            self.consumed_occurrence_id.as_deref(),
        )?;
        let end = start.saturating_add(self.entries.len());
        if end > self.denominator_occurrence_ids.len() {
            return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                "horizon slice runs past the revision denominator",
            ));
        }
        Ok(self.denominator_occurrence_ids[end..].to_vec())
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

/// Maximum occurrences carried in one bounded horizon publication request.
///
/// One publication is one owner round-trip over the bounded Kernel-to-Host
/// transport: the request carries a full compiled [`WakeIntent`] per entry, so
/// an unbounded normalized denominator would turn one publication into an
/// unbounded frame. The slice published now is capped here; the remainder is
/// never dropped silently. A first publication that exceeds the bound is
/// reported `Partial` with the exact remaining set and retry handle once the
/// owner acknowledges the prefix, and the disposition advance continues the
/// cursor — so the bound limits one flight, never the horizon. (Issue #2806
/// item 10.)
pub const USER_AUTOMATION_HORIZON_ENTRY_BOUND: usize = 256;

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
    let end = start
        .saturating_add(USER_AUTOMATION_HORIZON_ENTRY_BOUND)
        .min(identities.len());
    // One flight is bounded (issue #2806 item 10): the published slice is a
    // prefix of at most `USER_AUTOMATION_HORIZON_ENTRY_BOUND` occurrences from
    // the cursor. The capped tail is not dropped — the publication still
    // carries the complete denominator, the owner acknowledgement accounts for
    // the requested prefix, and the exact remainder keeps its retry handle, so
    // the disposition advance continues the same cursor.
    let mut entries = Vec::with_capacity(end - start);
    for identity in &identities[start..end] {
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
///
/// The same shape serves the remove, pause, and superseding-edit cancellation
/// joins (issue #2806 item 6): `revision` is always the affected immutable
/// revision whose unadmitted wakes were cancelled — the committed document for
/// remove and pause, the immutable predecessor for a superseding edit — and
/// `receipt` is the canonical Store receipt of the transition that owns the
/// cancellation.
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

/// Which committed transition a wake cancellation replays and which revision
/// it cancels (issue #2806 item 6).
///
/// A remove or pause cancels the committed document itself, which must show
/// the expected terminal state. A superseding edit cancels the immutable
/// predecessor named by the edit intent: the replayed commit must be the new
/// revision linked from that predecessor, and the predecessor must equal the
/// intent's own previous revision, so no caller can substitute an unrelated
/// denominator.
#[derive(Clone, Debug)]
enum CancellingCommit {
    /// The affected revision is the committed document in this exact state.
    CommittedRevision {
        /// Stable automation identity named by the operator intent.
        automation_id: String,
        /// Immutable revision named by the operator intent.
        automation_revision: String,
        /// Configuration state the committed document must show.
        expected_state: UserAutomationConfigurationState,
    },
    /// The affected revision is the superseded predecessor of a committed edit.
    SupersededPredecessor {
        /// Immutable predecessor whose unadmitted wakes are invalidated, boxed
        /// because the revision dwarfs the committed-identity variant.
        superseded: Box<UserAutomationRevision>,
    },
}

impl CancellingCommit {
    /// Returns the automation identity whose complete owner view gates the
    /// cancellation.
    fn automation_id(
        &self,
        request: &UserAutomationServiceRequest,
    ) -> Result<String, UserAutomationExecutionError> {
        match self {
            Self::CommittedRevision { automation_id, .. } => Ok(automation_id.clone()),
            Self::SupersededPredecessor { superseded } => {
                let automation_id = match &request.intent.operation {
                    eliot_kernel_core::UserAutomationOperation::Edit { revision, .. } => {
                        revision.automation_id.clone()
                    }
                    _ => {
                        return Err(UserAutomationExecutionError::OperationMismatch(
                            "edit-and-cancel requires edit",
                        ));
                    }
                };
                if superseded.automation_id != automation_id {
                    return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                        "superseded predecessor automation",
                    ));
                }
                Ok(automation_id)
            }
        }
    }

    /// Checks the replayed commit against the operator intent and returns the
    /// affected immutable revision whose unadmitted wakes are cancelled.
    fn check_committed(
        &self,
        request: &UserAutomationServiceRequest,
        committed: &UserAutomationRevision,
    ) -> Result<UserAutomationRevision, UserAutomationExecutionError> {
        match self {
            Self::CommittedRevision {
                automation_id,
                automation_revision,
                expected_state,
            } => {
                if committed.automation_id != *automation_id
                    || committed.revision != *automation_revision
                    || committed.configuration_state != *expected_state
                {
                    return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                        "cancel-with-targets revision",
                    ));
                }
                Ok(committed.clone())
            }
            Self::SupersededPredecessor { superseded } => {
                let eliot_kernel_core::UserAutomationOperation::Edit {
                    previous_revision,
                    revision,
                } = &request.intent.operation
                else {
                    return Err(UserAutomationExecutionError::OperationMismatch(
                        "edit-and-cancel requires edit",
                    ));
                };
                if superseded.as_ref() != previous_revision.as_ref() {
                    return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                        "superseded predecessor is not the edit intent previous revision",
                    ));
                }
                if committed.automation_id != revision.automation_id
                    || committed.revision != revision.revision
                {
                    return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
                        "cancel-with-targets revision",
                    ));
                }
                committed
                    .validate_supersedes(superseded.as_ref())
                    .map_err(UserAutomationExecutionError::Contract)?;
                Ok(superseded.as_ref().clone())
            }
        }
    }
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

    /// Cancels wakes through a transport that durably reports each boundary.
    /// The default refuses; callers must not fall back to the plain method for
    /// an operation whose retained row uses the versioned send-claim protocol.
    async fn cancel_pending_wakes_observed(
        &self,
        _request: UserAutomationWakeCancellation,
        _observer: &dyn super::user_automation_execution_client::UserAutomationHostExecutionObserver,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "UserAutomation cancellation transport has no custody observer".to_owned(),
        ))
    }

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

    /// Reconciles one exact horizon publication with its schedule owner after
    /// an unknown handoff. An implementation must return only the owner's
    /// retained acknowledgement for this immutable revision, fence, and
    /// occurrence denominator; an absent or inconclusive lookup is an error,
    /// never proof that publication did not occur. A contour with no schedule
    /// owner reports typed unavailability and cannot turn a retained horizon
    /// into a possible-effect or published claim.
    async fn read_wake_horizon_publication(
        &self,
        _request: impl Into<Box<UserAutomationWakeHorizonPublication>>,
    ) -> Result<UserAutomationWakePublication, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "exact owner wake-horizon publication readback is unavailable".to_owned(),
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

    /// Reads the exact committed Host cancellation batch for restart recovery.
    /// Implementations without the named authenticated journal query fail
    /// closed; current wake-row absence is not a substitute.
    async fn read_cancellation_batch(
        &self,
        _request: impl Into<Box<UserAutomationWakeCancellation>>,
    ) -> Result<UserAutomationAuthenticatedWakeCancellationReadback, UserAutomationRuntimeError>
    {
        Err(UserAutomationRuntimeError::Unavailable(
            "exact Host wake-cancellation batch readback is unavailable".to_owned(),
        ))
    }

    /// Host-side query path after the execution endpoint validates its
    /// server-authenticated session. Owner adapters receive the authenticated
    /// channel digest rather than trusting a caller-carried value.
    async fn read_cancellation_batch_authenticated(
        &self,
        _request: impl Into<Box<UserAutomationWakeCancellation>>,
        _authenticated_channel_binding_sha256: String,
    ) -> Result<UserAutomationWakeCancellationReadback, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "authenticated exact Host wake-cancellation query is unavailable".to_owned(),
        ))
    }

    /// Returns one owner-issued receipt for the complete occurrence denominator
    /// from one owner snapshot. An owner without this exact batch path fails
    /// closed; repeated single-occurrence reads are not a substitute.
    async fn enumerate_pending_wakes(
        &self,
        _request: impl Into<Box<UserAutomationWakeEnumerationRequest>>,
    ) -> Result<UserAutomationWakeEnumerationReceipt, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "UserAutomation complete wake enumeration is unavailable".to_owned(),
        ))
    }

    /// Host-only form supplied after the server-authored execution session has
    /// authenticated this exact channel. The default fails closed.
    async fn enumerate_pending_wakes_authenticated(
        &self,
        _request: impl Into<Box<UserAutomationWakeEnumerationRequest>>,
        _authenticated_channel_binding_sha256: String,
    ) -> Result<UserAutomationWakeEnumerationReceipt, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "authenticated UserAutomation wake enumeration is unavailable".to_owned(),
        ))
    }

    /// Cancels only unadmitted wakes for a retired revision.
    async fn cancel_pending_wakes(
        &self,
        request: impl Into<Box<UserAutomationWakeCancellation>>,
    ) -> Result<Vec<String>, UserAutomationRuntimeError>;

    /// Cancellation leg that is admissible for versioned send-claim rows.
    /// Adapters without source-backed transport custody fail closed.
    async fn cancel_pending_wakes_observed(
        &self,
        _request: impl Into<Box<UserAutomationWakeCancellation>>,
        _observer: &dyn super::user_automation_execution_client::UserAutomationHostExecutionObserver,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        Err(UserAutomationRuntimeError::Unavailable(
            "wake owner has no observed cancellation transport".to_owned(),
        ))
    }
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
        let cancelled = self.wake.cancel_pending_wakes(request.clone()).await?;
        request.validate_cancelled_wake_ids(&cancelled).map_err(|error| {
            UserAutomationRuntimeError::UnknownOutcome(format!(
                "wake owner returned a conflicting answer after cancellation was issued: {error}"
            ))
        })?;
        Ok(cancelled)
    }

    async fn cancel_pending_wakes_observed(
        &self,
        request: UserAutomationWakeCancellation,
        observer: &dyn super::user_automation_execution_client::UserAutomationHostExecutionObserver,
    ) -> Result<Vec<String>, UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let cancelled = self
            .wake
            .cancel_pending_wakes_observed(request.clone(), observer)
            .await?;
        request
            .validate_cancelled_wake_ids(&cancelled)
            .map_err(|error| {
                UserAutomationRuntimeError::UnknownOutcome(format!(
                    "wake owner returned a conflicting answer after observed cancellation: {error}"
                ))
            })?;
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
                Ok(*execution)
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
        enumeration_receipt: UserAutomationWakeEnumerationReceipt,
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
        self.cancel_affected_wakes_with_targets(
            request,
            CancellingCommit::CommittedRevision {
                automation_id,
                automation_revision,
                expected_state: UserAutomationConfigurationState::Retired,
            },
            targets,
            enumeration_receipt,
            runtime,
            None,
        )
        .await
    }

    /// Remove cancellation routed through the durable transport-custody
    /// observer. Versioned send-claim rows use this method exclusively.
    pub async fn remove_and_cancel_with_targets_observed<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        targets: Vec<UserAutomationWakeCancellationTarget>,
        enumeration_receipt: UserAutomationWakeEnumerationReceipt,
        runtime: &R,
        observer: &dyn super::user_automation_execution_client::UserAutomationHostExecutionObserver,
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
        self.cancel_affected_wakes_with_targets(
            request,
            CancellingCommit::CommittedRevision {
                automation_id,
                automation_revision,
                expected_state: UserAutomationConfigurationState::Retired,
            },
            targets,
            enumeration_receipt,
            runtime,
            Some(observer),
        )
        .await
    }

    /// Pauses one revision and cancels the exact owner-issued pending wake
    /// targets observed for that revision (issue #2806 item 6).
    ///
    /// This is the production pause contour of the authenticated `Pause`
    /// operator route: the gateway commits the pause, enumerates the affected
    /// revision's owner `Pending` targets from the wake owner itself, and then
    /// calls this method so the cancellation and the pause share one owner
    /// view, one admitted identity, and one runtime port. Already admitted
    /// jobs, completed occurrences, and unknown effects are never rewritten:
    /// the cancellation is unadmitted-only and the committed paused revision is
    /// preserved verbatim.
    pub async fn pause_and_cancel_with_targets<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        targets: Vec<UserAutomationWakeCancellationTarget>,
        enumeration_receipt: UserAutomationWakeEnumerationReceipt,
        runtime: &R,
    ) -> Result<UserAutomationRemovalResult, UserAutomationExecutionError> {
        let (automation_id, automation_revision) = match &request.intent.operation {
            eliot_kernel_core::UserAutomationOperation::Pause {
                automation_id,
                automation_revision,
            } => (automation_id.clone(), automation_revision.clone()),
            _ => {
                return Err(UserAutomationExecutionError::OperationMismatch(
                    "pause-and-cancel requires pause",
                ));
            }
        };
        self.cancel_affected_wakes_with_targets(
            request,
            CancellingCommit::CommittedRevision {
                automation_id,
                automation_revision,
                expected_state: UserAutomationConfigurationState::Paused,
            },
            targets,
            enumeration_receipt,
            runtime,
            None,
        )
        .await
    }

    /// Pause cancellation routed through the durable transport-custody
    /// observer. Versioned send-claim rows use this method exclusively.
    pub async fn pause_and_cancel_with_targets_observed<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        targets: Vec<UserAutomationWakeCancellationTarget>,
        enumeration_receipt: UserAutomationWakeEnumerationReceipt,
        runtime: &R,
        observer: &dyn super::user_automation_execution_client::UserAutomationHostExecutionObserver,
    ) -> Result<UserAutomationRemovalResult, UserAutomationExecutionError> {
        let (automation_id, automation_revision) = match &request.intent.operation {
            eliot_kernel_core::UserAutomationOperation::Pause {
                automation_id,
                automation_revision,
            } => (automation_id.clone(), automation_revision.clone()),
            _ => {
                return Err(UserAutomationExecutionError::OperationMismatch(
                    "pause-and-cancel requires pause",
                ));
            }
        };
        self.cancel_affected_wakes_with_targets(
            request,
            CancellingCommit::CommittedRevision {
                automation_id,
                automation_revision,
                expected_state: UserAutomationConfigurationState::Paused,
            },
            targets,
            enumeration_receipt,
            runtime,
            Some(observer),
        )
        .await
    }

    /// Cancels the exact owner-issued pending wake targets of the revision a
    /// superseding `Edit` replaced (issue #2806 item 6).
    ///
    /// The affected revision is the immutable predecessor, not the committed
    /// document: the commit this method replays must be the new revision linked
    /// from that predecessor, and the cancellation carries the predecessor's
    /// own occurrence denominator. Per I11.12 a superseding edit invalidates
    /// the not-yet-admitted wake intents of the superseded revision while the
    /// new revision keeps its own horizon; admitted jobs and immutable history
    /// are preserved either way.
    pub async fn edit_and_cancel_with_targets<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        superseded: UserAutomationRevision,
        targets: Vec<UserAutomationWakeCancellationTarget>,
        enumeration_receipt: UserAutomationWakeEnumerationReceipt,
        runtime: &R,
    ) -> Result<UserAutomationRemovalResult, UserAutomationExecutionError> {
        match &request.intent.operation {
            eliot_kernel_core::UserAutomationOperation::Edit { .. } => {}
            _ => {
                return Err(UserAutomationExecutionError::OperationMismatch(
                    "edit-and-cancel requires edit",
                ));
            }
        }
        self.cancel_affected_wakes_with_targets(
            request,
            CancellingCommit::SupersededPredecessor {
                superseded: Box::new(superseded),
            },
            targets,
            enumeration_receipt,
            runtime,
            None,
        )
        .await
    }

    /// Superseding-edit cancellation routed through the durable
    /// transport-custody observer. Versioned send-claim rows use this method.
    pub async fn edit_and_cancel_with_targets_observed<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        superseded: UserAutomationRevision,
        targets: Vec<UserAutomationWakeCancellationTarget>,
        enumeration_receipt: UserAutomationWakeEnumerationReceipt,
        runtime: &R,
        observer: &dyn super::user_automation_execution_client::UserAutomationHostExecutionObserver,
    ) -> Result<UserAutomationRemovalResult, UserAutomationExecutionError> {
        if !matches!(
            &request.intent.operation,
            eliot_kernel_core::UserAutomationOperation::Edit { .. }
        ) {
            return Err(UserAutomationExecutionError::OperationMismatch(
                "edit-and-cancel requires edit",
            ));
        }
        self.cancel_affected_wakes_with_targets(
            request,
            CancellingCommit::SupersededPredecessor {
                superseded: Box::new(superseded),
            },
            targets,
            enumeration_receipt,
            runtime,
            Some(observer),
        )
        .await
    }

    /// Cancels the exact owner-issued pending wake targets of one affected
    /// revision after replaying the committed transition that owns them.
    ///
    /// This is the one mechanism behind the remove, pause, and superseding-edit
    /// cancellation joins: the same complete, fail-closed owner view gate, the
    /// same replay-under-the-admitted-identity discipline, and the same exact
    /// ordered cancellation accounting. Only the committed-transition check
    /// differs, because a remove/pause cancels the committed document while a
    /// superseding edit cancels its immutable predecessor.
    async fn cancel_affected_wakes_with_targets<R: UserAutomationRuntimePort + ?Sized>(
        &self,
        request: UserAutomationServiceRequest,
        commit: CancellingCommit,
        targets: Vec<UserAutomationWakeCancellationTarget>,
        enumeration_receipt: UserAutomationWakeEnumerationReceipt,
        runtime: &R,
        observer: Option<
            &dyn super::user_automation_execution_client::UserAutomationHostExecutionObserver,
        >,
    ) -> Result<UserAutomationRemovalResult, UserAutomationExecutionError> {
        // Wake cancellation acts on the same complete, fail-closed owner view as
        // execution admission (issue #2808). Every cancellation join is a
        // consumer leg of the single `execution_projection` constructor, and the
        // Store's retirement gate refuses to commit the transition unless the
        // declared occurrence denominator is owner-proven complete at one read
        // revision. Asserting the same gate on the cancellation that follows the
        // commit means the scheduler owner is never asked to cancel from a
        // bounded subset, and a Store adapter that did not gate the transition
        // is caught here rather than silently proceeding. The committed
        // configuration itself is never refused because an effect is
        // unresolved: those obligations are preserved verbatim.
        let owner_view = self
            .owner_execution_view(&request, &commit.automation_id(&request)?)
            .await?;
        require_complete_occurrence_view(&owner_view)?;
        let response = self.dispatch(request.clone()).await?;
        let (receipt, result, replayed) = match response.outcome {
            UserAutomationStoreOutcome::Committed { receipt, result } => (receipt, result, false),
            UserAutomationStoreOutcome::Replayed { receipt, result } => (receipt, result, true),
            UserAutomationStoreOutcome::Read { .. } => {
                return Err(UserAutomationExecutionError::OperationMismatch(
                    "cancel-with-targets returned a read response",
                ));
            }
        };
        let UserAutomationMutationResult::Revision { revision, .. } = result else {
            return Err(UserAutomationExecutionError::OperationMismatch(
                "cancel-with-targets returned a non-revision result",
            ));
        };
        let affected = commit.check_committed(&request, &revision)?;
        enumeration_receipt.validate_integrity()?;
        let cancellation = UserAutomationWakeCancellation {
            context: request.context.clone(),
            authenticated_principal: request.authenticated_principal,
            identity: request.identity,
            automation_id: affected.automation_id.clone(),
            automation_revision: affected.revision.clone(),
            state_fence: request.context.state_fence.clone(),
            only_unadmitted: true,
            targets,
            enumeration_receipt: Some(Box::new(enumeration_receipt)),
        };
        cancellation.validate()?;
        let cancelled_wake_ids = match observer {
            Some(observer) => {
                runtime
                    .cancel_pending_wakes_observed(cancellation.clone(), observer)
                    .await
            }
            None => runtime.cancel_pending_wakes(cancellation.clone()).await,
        }
            .map_err(|error| match error {
                UserAutomationRuntimeError::IdentityConflict => {
                    UserAutomationRuntimeError::UnknownOutcome(
                        "wake owner returned a foreign cancellation answer after the request was issued"
                            .to_owned(),
                    )
                }
                other => other,
            })?;
        cancellation
            .validate_cancelled_wake_ids(&cancelled_wake_ids)
            .map_err(|error| {
                UserAutomationRuntimeError::UnknownOutcome(format!(
                    "wake owner returned a conflicting answer after cancellation was issued: {error}"
                ))
            })?;
        Ok(UserAutomationRemovalResult {
            revision: affected,
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
    /// The wake owner returned one validated receipt covering every committed
    /// occurrence from one exact Host journal snapshot.
    Proven {
        /// Complete versioned receipt, including every positive and negative
        /// disposition and the shared owner snapshot reference.
        receipt: UserAutomationWakeEnumerationReceipt,
    },
    /// No complete exact target list is owner-proven, so no cancellation is
    /// issued and the wake handoff of this retirement stays unresolved.
    Unproven {
        /// Closed reason the enumeration is not owner-proven.
        reason: String,
        /// Typed owner evidence when the Host answered but some member remains
        /// explicitly unresolved. Absent only when no receipt was returned.
        receipt: Option<UserAutomationWakeEnumerationReceipt>,
    },
}

/// Requests one versioned Host-owner receipt over a retired revision's complete
/// committed occurrence denominator.
///
/// The request binds the immutable revision and canonical denominator digest.
/// The Host producer takes one journal snapshot and returns one ordered
/// disposition per occurrence: an exact pending cancellation target, exact
/// owner evidence that no unadmitted pending target is retained, or an explicit
/// unresolved result. The receipt also binds that snapshot's owner identity,
/// generation, sequence, State Fence, authenticated principal and channel. A
/// missing member, incomplete coverage or unresolved result prevents
/// cancellation; there is no series of per-occurrence reads and no inference
/// from omitted targets.
///
/// A committed revision that declares no occurrence identity is `Unproven`.
/// The owner asked about no members, so the empty denominator is not evidence
/// that the Host retains no wakes.
pub async fn read_retirement_wake_targets<R>(
    revision: &UserAutomationRevision,
    context: &RequestMetadata,
    authenticated_principal: &str,
    identity: &OperationIdentity,
    runtime: &R,
) -> Result<UserAutomationWakeTargetEnumeration, UserAutomationExecutionError>
where
    R: UserAutomationWakePort + ?Sized,
{
    let request =
        retirement_wake_enumeration_request(revision, context, authenticated_principal, identity)?;
    let receipt = match UserAutomationWakePort::enumerate_pending_wakes(runtime, request.clone())
        .await
    {
        Ok(receipt) => receipt,
        Err(error) => {
            return Ok(UserAutomationWakeTargetEnumeration::Unproven {
                reason: format!(
                    "the wake owner did not return one complete snapshot receipt for retired revision {}: {error}; no cancellation is issued",
                    revision.revision
                ),
                receipt: None,
            });
        }
    };
    receipt.validate_for(&request)?;
    if !receipt.coverage.complete || receipt.coverage.unresolved_count != 0 {
        return Ok(UserAutomationWakeTargetEnumeration::Unproven {
            reason: format!(
                "the Host owner receipt for retired revision {} represents the complete denominator but contains {} unresolved occurrence(s); no cancellation is issued",
                revision.revision, receipt.coverage.unresolved_count
            ),
            receipt: Some(receipt),
        });
    }
    Ok(UserAutomationWakeTargetEnumeration::Proven { receipt })
}

/// Constructs the exact owner enumeration request from the immutable revision
/// and already authenticated remove operation.
pub fn retirement_wake_enumeration_request(
    revision: &UserAutomationRevision,
    context: &RequestMetadata,
    authenticated_principal: &str,
    identity: &OperationIdentity,
) -> Result<UserAutomationWakeEnumerationRequest, UserAutomationExecutionError> {
    validate_text(
        authenticated_principal,
        "wake_enumeration.authenticated_principal",
    )?;
    if revision.owner_principal != authenticated_principal {
        return Err(UserAutomationExecutionError::RuntimeResponseMismatch(
            "authenticated principal does not own the committed automation revision",
        ));
    }
    let denominator = revision
        .compile_occurrence_identities()
        .map_err(UserAutomationExecutionError::Contract)?;
    let revision_digest = revision
        .digest()
        .map_err(UserAutomationExecutionError::Contract)?;
    let request = UserAutomationWakeEnumerationRequest {
        context: context.clone(),
        authenticated_principal: authenticated_principal.to_owned(),
        identity: identity.clone(),
        automation_id: revision.automation_id.clone(),
        automation_revision: revision.revision.clone(),
        revision_digest,
        denominator_digest: wake_occurrence_denominator_digest(&denominator)?,
        denominator,
    };
    request.validate()?;
    Ok(request)
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
                // This fixture carries a retired shape-only occurrence key, so
                // the owning calendar adapter has not issued a normalization
                // binding for it and the revision requires re-normalization.
                // Empty evidence can never satisfy the required binding, so the
                // fixture stays refused instead of becoming admitted.
                normalization_receipt: Box::new(
                    eliot_kernel_core::user_automation::ScheduleNormalizationReceipt {
                        receipt_id: String::new(),
                        normalizer_authority: String::new(),
                        source_digest: String::new(),
                        zone_database_revision:
                            eliot_kernel_core::user_automation::PINNED_ZONE_DATABASE_REVISION
                                .to_owned(),
                        occurrences_digest: String::new(),
                    },
                ),
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
            trusted_tool_definition_refs: vec!["skill-package@1".to_owned()],
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
            enumeration_receipt: None,
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
