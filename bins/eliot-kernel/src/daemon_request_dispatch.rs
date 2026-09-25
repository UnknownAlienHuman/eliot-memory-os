//! Authenticated daemon operation dispatch.
//!
//! Architecture traceability: `A12.3`, `A13.2`, `A13.6`, `ARCH-AUTH-01`,
//! `ARCH-SEC-02`, and `ARCH-RES-01` require one fenced Kernel route and an
//! honest recovery boundary. Implementation anchors are `I1.8`, `I5`, `B.1`,
//! `B.2`, `P.3`, and `I14.21`: Store owns durable state, Kernel verifies the
//! authenticated route/fence, and Governor remains the semantic owner.
//!
//! This module does not decode Governor owner payloads, advertise capabilities,
//! choose retry/default/cache policy, or turn an uncertain genesis into
//! success. The existing wildcard import is retained as a parent-module
//! dispatch convention; the new Store carriers below are explicitly typed.

use super::*;
#[path = "store_receipt_dispatch.rs"]
mod store_receipt_dispatch;
use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_kernel_service::AuthenticatedHostSession;
#[cfg(windows)]
use eliot_kernel_service::{
    AuthenticatedUserAutomationHostExecutionTransport, UserAutomationDurableJobPort,
    UserAutomationHostExecutionClient, UserAutomationHostExecutionOperation,
    UserAutomationHostExecutionTransport, UserAutomationOwnerLookup,
    UserAutomationRuntimeAdmission, UserAutomationRuntimeError, UserAutomationWakeCancellation,
    UserAutomationWakePort, UserAutomationWakeReadRequest,
};
use eliot_process::{
    OperationId, OriginChallengeRequest, OriginControlOperation, OriginControlPresentation,
    ProcessExecutionView, ProcessLifecycle,
};
use eliot_protocol::{
    HostRequestEnvelope, HostRequestResultBody, LocalReadAttempt, RequestIdentity,
    TaskControllerResultBody, host_request_operation_id,
};
use eliot_store_api::{
    CampaignLearningStateViewLookup, CampaignLearningStateViewRead,
    CampaignLearningStateViewReadStatus, CampaignSourcePublication, CampaignSourceRevisionLookup,
    CampaignSourceRevisionRef, CanonicalRequestView, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OperationIdentity, OrderingHeadExpectation, PreparedTransition,
    ReadConsistency, RecoveryRecord, RecoveryRecordKey, RequestMeta, RevisionHeadExpectation,
    StoreError, StoreGenesisRequest, StoreRecoveryRequest, StoreRecoverySnapshot, WriteReceipt,
    WriteReceiptStatus, verify_canonical_request_hash,
};
use serde::{Deserialize, Serialize};

use super::generation_control::{
    ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION, ActiveGenerationRegistryProjection,
    ActiveGenerationRegistryQuery,
};

/// Governor's existing authenticated publish operation. The semantic
/// `EliotdStartupEvidence` carrier remains bin-owned; Kernel consumes its
/// canonical JSON mechanically and never imports `bins/eliotd`.
pub(crate) const DAEMON_STARTUP_EVIDENCE_OPERATION: &str = "daemon_startup_evidence";
/// Authenticated daemon route that drives the typed Host `UserAutomation`
/// transport.  The daemon session supplies the outer authority; the Host
/// open handshake supplies the channel evidence and the Host owner supplies
/// the Durable Job/Wake effects.
pub(crate) const USER_AUTOMATION_RUNTIME_OPERATION: &str = "user_automation_runtime";

const STARTUP_EVIDENCE_FIELDS: [&str; 8] = [
    "transport_binding",
    "state_fence",
    "config_mirror_digest",
    "policy_mirror_digest",
    "capability_registry_digest",
    "required_capabilities",
    "capability_outcomes",
    "evidence_refs",
];

const CAPABILITY_OUTCOME_FIELDS: [&str; 12] = [
    "capability",
    "requested_mode",
    "effective_mode",
    "degradation_scope",
    "reason",
    "evidence_refs",
    "affected_outputs_or_operations",
    "proof_ceiling",
    "recovery_requalification_or_expiry",
    "scope_owner",
    "generation_fingerprint",
    "valid_until_unix_ms",
];

/// Mechanical view of the Governor-owned startup carrier.
///
/// This is deliberately not `CapabilityOutcome` or `EliotdStartupEvidence`:
/// those semantic types remain in their owning binary. The view only retains
/// fields needed for Kernel authentication, exact fence binding, and the
/// documented registry-digest comparison.
#[derive(Debug)]
struct StartupEvidenceView {
    transport_binding: RequestIdentity,
    state_fence: StateFence,
    config_mirror_digest: PlatformHandle,
    policy_mirror_digest: Option<PlatformHandle>,
    capability_registry_digest: Option<String>,
    required_capabilities: Option<Vec<String>>,
    capability_outcomes: Option<Vec<serde_json::Value>>,
}

fn exact_object_fields(
    object: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
) -> Result<(), TransportError> {
    if object.len() != expected.len() || expected.iter().any(|field| !object.contains_key(*field)) {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn required_text(value: &serde_json::Value) -> Result<&str, TransportError> {
    value
        .as_str()
        .filter(|text| !text.trim().is_empty())
        .ok_or(TransportError::SessionFenced)
}

fn platform_handle(value: &serde_json::Value) -> Result<PlatformHandle, TransportError> {
    PlatformHandle::new(required_text(value)?.to_owned()).map_err(|_| TransportError::SessionFenced)
}

fn optional_platform_handle(
    value: &serde_json::Value,
) -> Result<Option<PlatformHandle>, TransportError> {
    if value.is_null() {
        Ok(None)
    } else {
        platform_handle(value).map(Some)
    }
}

fn lower_hex_digest(value: &serde_json::Value) -> Result<String, TransportError> {
    let digest = required_text(value)?;
    if digest.len() != 64
        || !digest.bytes().all(|byte| {
            byte.is_ascii_digit() || byte.is_ascii_lowercase() && byte.is_ascii_hexdigit()
        })
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(digest.to_owned())
}

fn optional_registry_digest(value: &serde_json::Value) -> Result<Option<String>, TransportError> {
    if value.is_null() {
        Ok(None)
    } else {
        lower_hex_digest(value).map(Some)
    }
}

fn optional_string_set(value: &serde_json::Value) -> Result<Option<Vec<String>>, TransportError> {
    if value.is_null() {
        return Ok(None);
    }
    let values = value.as_array().ok_or(TransportError::SessionFenced)?;
    let mut unique = BTreeSet::new();
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let text = required_text(value)?.to_owned();
        if !unique.insert(text.clone()) {
            return Err(TransportError::SessionFenced);
        }
        result.push(text);
    }
    Ok(Some(result))
}

fn string_array(value: &serde_json::Value) -> Result<(), TransportError> {
    let values = value.as_array().ok_or(TransportError::SessionFenced)?;
    if values.iter().any(|value| required_text(value).is_err()) {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn validate_capability_outcome_shape(value: &serde_json::Value) -> Result<(), TransportError> {
    let object = value.as_object().ok_or(TransportError::SessionFenced)?;
    exact_object_fields(object, &CAPABILITY_OUTCOME_FIELDS)?;
    for field in [
        "capability",
        "requested_mode",
        "effective_mode",
        "degradation_scope",
        "reason",
        "proof_ceiling",
        "recovery_requalification_or_expiry",
        "scope_owner",
        "generation_fingerprint",
    ] {
        let _ = required_text(object.get(field).ok_or(TransportError::SessionFenced)?)?;
    }
    string_array(
        object
            .get("evidence_refs")
            .ok_or(TransportError::SessionFenced)?,
    )?;
    string_array(
        object
            .get("affected_outputs_or_operations")
            .ok_or(TransportError::SessionFenced)?,
    )?;
    let valid_until = object
        .get("valid_until_unix_ms")
        .ok_or(TransportError::SessionFenced)?;
    if !valid_until.is_null() && valid_until.as_u64().is_none() {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn parse_startup_evidence(
    payload: &serde_json::Value,
) -> Result<StartupEvidenceView, TransportError> {
    let object = payload.as_object().ok_or(TransportError::SessionFenced)?;
    exact_object_fields(object, &STARTUP_EVIDENCE_FIELDS)?;

    let transport_binding: RequestIdentity = serde_json::from_value(
        object
            .get("transport_binding")
            .cloned()
            .ok_or(TransportError::SessionFenced)?,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    transport_binding
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;

    let state_fence: StateFence = serde_json::from_value(
        object
            .get("state_fence")
            .cloned()
            .ok_or(TransportError::SessionFenced)?,
    )
    .map_err(|_| TransportError::SessionFenced)?;
    state_fence
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;

    let required_capabilities = optional_string_set(
        object
            .get("required_capabilities")
            .ok_or(TransportError::SessionFenced)?,
    )?;
    let capability_outcomes = match object
        .get("capability_outcomes")
        .ok_or(TransportError::SessionFenced)?
    {
        value if value.is_null() => None,
        value => {
            let outcomes = value.as_array().ok_or(TransportError::SessionFenced)?;
            for outcome in outcomes {
                validate_capability_outcome_shape(outcome)?;
            }
            Some(outcomes.clone())
        }
    };

    let evidence_refs_value = object
        .get("evidence_refs")
        .ok_or(TransportError::SessionFenced)?;
    for evidence_ref in evidence_refs_value
        .as_array()
        .ok_or(TransportError::SessionFenced)?
    {
        platform_handle(evidence_ref)?;
    }

    Ok(StartupEvidenceView {
        transport_binding,
        state_fence,
        config_mirror_digest: platform_handle(
            object
                .get("config_mirror_digest")
                .ok_or(TransportError::SessionFenced)?,
        )?,
        policy_mirror_digest: optional_platform_handle(
            object
                .get("policy_mirror_digest")
                .ok_or(TransportError::SessionFenced)?,
        )?,
        capability_registry_digest: optional_registry_digest(
            object
                .get("capability_registry_digest")
                .ok_or(TransportError::SessionFenced)?,
        )?,
        required_capabilities,
        capability_outcomes,
    })
}

fn daemon_capability_registry_digest(
    outcomes: &[serde_json::Value],
) -> Result<String, TransportError> {
    let mut serialized = outcomes
        .iter()
        .map(|outcome| serde_json::to_string(outcome).map_err(|_| TransportError::SessionFenced))
        .collect::<Result<Vec<_>, _>>()?;
    serialized.sort_unstable();
    Ok(sha256_hex(serialized.concat().as_bytes()))
}

fn observe_daemon_request(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "daemon request observation"
    );
}

fn observe_daemon_operation(operation: &str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let op_bound = bound_field(operation);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = "kernel.daemon_request_operation",
        operation = op_bound.text(),
        outcome = outcome_bound.text(),
        "daemon request operation observation"
    );
}

fn daemon_terminal_code(error: &TransportError) -> &'static str {
    match error {
        TransportError::SessionFenced => "daemon_fenced",
        TransportError::PeerIdentityUnavailable => "daemon_peer_unavailable",
        TransportError::Timeout => "daemon_timeout",
        TransportError::UnknownRequest => "daemon_unknown_request",
        TransportError::UnknownOutcome => "daemon_unknown_outcome",
        TransportError::IdentityConflict => "daemon_identity_conflict",
        TransportError::Cancelled => "daemon_cancelled",
        TransportError::Backpressure => "daemon_backpressure",
        TransportError::InvalidLimits => "daemon_invalid_limits",
        TransportError::UnauthenticatedPeer => "daemon_unauthenticated_peer",
        TransportError::InvalidPipeName => "daemon_invalid_pipe",
        TransportError::RegistryFull => "daemon_registry_full",
        TransportError::Io(_) => "daemon_io",
        TransportError::PlanGap { .. } => "daemon_plan_gap",
        TransportError::Protocol(_) => "daemon_protocol",
    }
}

fn trusted_daemon_operation(operation: &str) -> &'static str {
    match operation {
        "snapshot" => "snapshot",
        "daemon_ready" => "daemon_ready",
        "origin_challenge_issue" => "origin_challenge_issue",
        "origin_control_decide" => "origin_control_decide",
        ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION => ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION,
        DAEMON_STARTUP_EVIDENCE_OPERATION => DAEMON_STARTUP_EVIDENCE_OPERATION,
        USER_AUTOMATION_RUNTIME_OPERATION => USER_AUTOMATION_RUNTIME_OPERATION,
        "health" => "health",
        "store_recovery" => "store_recovery",
        "store_initialize_genesis" => "store_initialize_genesis",
        "apply_prepared" => "apply_prepared",
        "receipt" => "receipt",
        "store_named" => "store_named",
        "local_read" => "local_read",
        "daemon_degraded" => "daemon_degraded",
        "daemon_fatal" => "daemon_fatal",
        "agent_activation_claim" => "agent_activation_claim",
        "agent_activation_submit" => "agent_activation_submit",
        "agent_activation_reconcile" => "agent_activation_reconcile",
        "local_read_claim" => "local_read_claim",
        "local_read_result" => "local_read_result",
        "task_controller_claim" => "task_controller_claim",
        "task_controller_result" => "task_controller_result",
        "agent_host_request_submit" => "agent_host_request_submit",
        "agent_host_request_cancel" => "agent_host_request_cancel",
        "publish_owner_bundle" => "publish_owner_bundle",
        "query_owner_bundle" => "query_owner_bundle",
        "activate_grant" => "activate_grant",
        "revoke_grant" => "revoke_grant",
        "activate_introduction" => "activate_introduction",
        "revoke_introduction" => "revoke_introduction",
        "publish_wasm_dispatch_bundle" => "publish_wasm_dispatch_bundle",
        "bind_notify_launch_grant" => "bind_notify_launch_grant",
        "agent_host_request_reconcile" => "agent_host_request_reconcile",
        "agent_host_request_rehydrate" => "agent_host_request_rehydrate",
        _ => "untrusted_operation",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreNamedOperation {
    request: NamedReadRequest,
}

/// Closed local-read envelope for one admitted `eliot.query` (Implements #18).
///
/// Carries the exact admitted envelope plus the exact canonical tool bytes it
/// admits — the same linkage-checked pair as the invoke-read frame payload —
/// so the read leg re-proves capability + payload-digest binding before any
/// Gateway IO. The Kernel-issued attempt capability is required: the sync leg
/// never mints authority and never bypasses the claim record. `eliot.packet`
/// pairs decode here but are admitted, never read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalReadOperation {
    envelope: HostRequestEnvelope,
    tool: serde_json::Value,
    attempt: LocalReadAttempt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreRecoveryOperation {
    request: StoreRecoveryRequest,
}

/// Closed Governor owner-bundle publish operation (`#2100`).
///
/// Carries the canonical restore plus the exact expected graph revision.
/// The Kernel binds (or refreshes) its retained P-07 owner through the
/// composition owner step and acknowledges the bound revision; a
/// disagreeing bundle fails closed as an identity conflict.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerPublishOperation {
    bundle: super::GovernorClosureRestore,
    expected_revision: u64,
}

/// Closed P-07 grant activation operation (`#1110`).
///
/// Mirrors the authenticated `KernelAuthorityClient` payload: string
/// identities plus the exact presented authority binding. The dispatcher
/// decodes, rechecks the binding against the authenticated session, and
/// routes through the retained P-07 owner port; it never mints authority.
/// Unknown fields fail closed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantActivationOperation {
    grant_id: String,
    snapshot_id: String,
    binding: eliot_receipts::AuthorityBinding,
}

/// Closed P-07 grant revocation operation (`#1110`). Same shape and
/// fail-closed contract as the activation operation; revocation fences
/// closure through the retained port before the dispatcher acknowledges.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantRevocationOperation {
    grant_id: String,
    snapshot_id: String,
    binding: eliot_receipts::AuthorityBinding,
}

/// Closed P-07 introduction activation operation (`#1110`). Same shape and
/// fail-closed contract as the grant activation operation, keyed by
/// introduction identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntroductionActivationOperation {
    introduction_id: String,
    snapshot_id: String,
    binding: eliot_receipts::AuthorityBinding,
}

/// Closed P-07 introduction revocation operation (`#1110`). Same shape and
/// fail-closed contract as the grant revocation operation, keyed by
/// introduction identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntroductionRevocationOperation {
    introduction_id: String,
    snapshot_id: String,
    binding: eliot_receipts::AuthorityBinding,
}

/// Canonical installed WASM-host image filename pinned by the
/// installer-owned binding chain. Mirrors the `eliot-wasm-host.exe` pin the
/// installation descriptor validates before releasing its
/// `wasm_host_artifact_binding()`: any divergence fails closed here, the
/// same way `bind_notify_launch_grant` pins its own canonical image name.
const WASM_HOST_IMAGE_FILE_NAME: &str = "eliot-wasm-host.exe";

/// Closed owner-side WASM dispatch publication (`#1780` D4a, `#1955`).
///
/// Carries the installation-observed host binding (path + digest, re-hashed
/// against real file bytes before publication — never trusted from config)
/// plus every admitted owner record and the exact guest bytes to stage. The
/// install directory derives as the host path's parent, never from a caller
/// string. Unknown fields fail closed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WasmDispatchBundleOperation {
    host_executable_path: String,
    host_artifact_digest: String,
    claim_id: String,
    operation_id: String,
    generation: u64,
    authority_epoch: eliot_contracts::EpochId,
    launch_nonce: String,
    admitted_at_unix_ms: u64,
    identity_digest: String,
    guest: eliot_kernel_service::WasmGuestCeilings,
    profile: String,
    manifest: eliot_kernel_service::WasmManifestRecord,
    work: eliot_kernel_service::WasmWorkRecord,
    assurance: eliot_kernel_service::WasmAssuranceRecord,
    promotion: eliot_kernel_service::WasmPromotionRecord,
    snapshot: eliot_kernel_service::WasmSnapshotRecord,
    prior_conformance_artifact: Option<String>,
    artifact_bytes: Vec<u8>,
    input_bytes: Vec<u8>,
}

/// Closed normal Notify launch-grant request (`#1780` D4b).
///
/// Carries the canonical notification reference plus the installer-observed
/// launch artifact (path + digest, re-hashed against real file bytes before
/// binding). Session evidence is threaded from the live authenticated
/// session, never from the payload. Unknown fields fail closed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotifyLaunchGrantOperation {
    notification_id: String,
    notification_digest: String,
    executable_path: String,
    artifact_digest: String,
}

/// Checks every admitted binding in the bundle against the authenticated
/// session authority: the bundle must describe authority this session may
/// fence. A single crossing binding refuses the whole publish.
fn owner_bundle_agrees_with_session(
    bundle: &super::GovernorClosureRestore,
    session: &Session,
) -> bool {
    let mut bindings = bundle
        .members
        .iter()
        .map(|member| &member.intent.binding)
        .chain(bundle.roots.iter().map(|root| &root.intent.binding))
        .chain(
            bundle
                .introductions
                .iter()
                .map(|hydration| &hydration.intent.binding),
        );
    bindings.all(|binding| {
        binding
            .authority_epoch
            .is_same_authority(&session.authority_epoch)
    })
}

/// Rechecks one presented P-07 binding against the authenticated session
/// before the dispatcher touches the retained owner: the fence must validate,
/// the binding epoch must agree with the fence epoch, the binding authority
/// must be the session authority, and the presented fence must be the session
/// generation fence. Anything else fails closed before mutation.
fn p07_binding_agrees_with_session(
    binding: &eliot_receipts::AuthorityBinding,
    session: &Session,
) -> Result<(), TransportError> {
    binding
        .state_fence
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if binding.authority_epoch != binding.state_fence.authority_epoch
        || !binding
            .authority_epoch
            .is_same_authority(&session.authority_epoch)
        || binding.state_fence != session.module_generation.state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

/// Maps one retained-port refusal to the typed dispatch failure. Admission
/// refusals and an unready production route fail closed as fenced without
/// minting authority; a binding that disagrees with retained owner state under
/// a known identity (changed payload, stale revision, disagreeing material)
/// conflicts so the caller re-serves fresh state instead of retrying blindly —
/// the same contract as the owner-bundle publish arm. Only a possible commit
/// with a lost acknowledgement surfaces as an unknown outcome for exact
/// reconciliation.
fn map_p07_port_error(error: &eliot_authority::P07PortError) -> TransportError {
    match error {
        eliot_authority::P07PortError::UnknownOutcome { .. } => TransportError::UnknownOutcome,
        eliot_authority::P07PortError::InvalidBinding => TransportError::IdentityConflict,
        eliot_authority::P07PortError::NotAdmitted | eliot_authority::P07PortError::Unavailable => {
            TransportError::SessionFenced
        }
    }
}

impl KernelComposition {
    /// Locks the retained P-07 owner bound by the Governor feed. An unbound
    /// composition withholds unsupported authority instead of routing to a
    /// no-authority port: the production path never selects
    /// `UnavailableP07AuthorityPort`.
    fn retained_p07_owner(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, Option<BoundCanonicalOwner>>, TransportError> {
        let guard = self
            .p07_owner
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        if guard.is_none() {
            return Err(TransportError::SessionFenced);
        }
        Ok(guard)
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreInitializeGenesisOperation {
    context: RequestMeta,
    request: StoreGenesisRequest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreApplyOperation {
    context: RequestMeta,
    transition: PreparedTransition,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

#[allow(
    clippy::too_many_lines,
    reason = "the closed campaign publication admission path keeps the source transition, owner matrix, and recipe binding together"
)]
fn campaign_source_publications_for_transition(
    transition: &PreparedTransition,
    request_id: &eliot_contracts::RequestId,
) -> Result<Vec<CampaignSourcePublication>, String> {
    let mut task_operation = None;
    let mut task_recipe: Option<eliot_store_api::LearningStateViewRecipe> = None;
    let mut campaign_matrix_complete = false;
    let mut publications = Vec::new();
    for operation in &transition.named_operations {
        if operation.operation != eliot_store_api::NamedMutationOperation::UpdateTaskState {
            if operation
                .parameters
                .contains_key("campaign_source_publications_json")
            {
                return Err(
                    "campaign source publication must be carried by the owner transition".into(),
                );
            }
            continue;
        }
        if task_operation.is_some() {
            return Err("campaign publication transition must contain one task update".into());
        }
        let task_id = operation
            .parameters
            .get("task_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| "task update lacks its exact task identity".to_owned())?;
        task_operation = Some(task_id.to_owned());
        if let Some(value) = operation
            .parameters
            .get("campaign_source_publications_json")
        {
            publications = serde_json::from_value(value.clone()).map_err(|_| {
                "campaign source publications are not the closed typed list".to_owned()
            })?;
        }
        if let Some(value) = operation.parameters.get("campaign_source_matrix_complete") {
            campaign_matrix_complete = match value.as_str() {
                Some("true") => true,
                Some("false") => false,
                _ => {
                    return Err(
                        "campaign source matrix completeness marker is not a boolean wire value"
                            .into(),
                    );
                }
            };
        }
        if let Some(value) = operation
            .parameters
            .get("campaign_learning_state_recipe_json")
        {
            let text = value.as_str().ok_or_else(|| {
                "campaign learning-state recipe parameter is not a JSON string".to_owned()
            })?;
            task_recipe = Some(serde_json::from_str(text).map_err(|_| {
                "campaign learning-state recipe parameter is not the closed typed recipe".to_owned()
            })?);
        }
    }
    if campaign_matrix_complete && task_recipe.is_none() {
        return Err("complete campaign source matrix requires its bound recipe".into());
    }
    if publications.is_empty() {
        if task_recipe.is_some() {
            return Err(
                "campaign learning-state recipe requires its atomic source publications".into(),
            );
        }
        return Ok(publications);
    }
    let task_id = task_operation
        .ok_or_else(|| "campaign source publication has no task update".to_owned())?;
    if transition.transition_class != eliot_store_api::TransitionClass::TaskControl
        || transition.task_id.as_deref() != Some(task_id.as_str())
        || transition.state_fence.task_revision.is_none()
    {
        return Err("campaign sources require the exact TaskControl task/fence binding".into());
    }
    let task_revision = transition
        .state_fence
        .task_revision
        .as_ref()
        .ok_or_else(|| "campaign sources require an exact task revision fence".to_owned())?;
    let task_record_id = eliot_store_api::CampaignOwnerRecordId::Task(
        eliot_contracts::TaskId::new(task_id.clone()).map_err(|error| error.to_string())?,
    );
    let mut by_role = BTreeMap::new();
    for publication in &publications {
        publication.validate().map_err(|error| error.to_string())?;
        let record = &publication.record;
        match &publication.state {
            eliot_store_api::CampaignSourcePublicationState::NewRevision { .. }
                if record.recorded_state_fence != transition.state_fence =>
            {
                return Err(
                    "new campaign source must carry the exact admitted transition fence".into(),
                );
            }
            eliot_store_api::CampaignSourcePublicationState::CurrentReference { .. }
                if publication.read_receipt.read_state_fence != transition.state_fence =>
            {
                return Err(
                    "current campaign source reference must carry the exact admitted read fence"
                        .into(),
                );
            }
            _ => {}
        }
        if !campaign_matrix_complete
            && !matches!(
                record.role,
                eliot_store_api::CampaignSourceRole::TaskObjective
                    | eliot_store_api::CampaignSourceRole::TaskAcceptance
                    | eliot_store_api::CampaignSourceRole::TaskPlan
                    | eliot_store_api::CampaignSourceRole::TaskOpenItems
            )
        {
            return Err(
                "partial campaign source publication may carry only Task Controller rows".into(),
            );
        }
        if by_role.insert(record.role, publication).is_some() {
            return Err("campaign source publication matrix contains a duplicate role".into());
        }
        if matches!(
            record.role,
            eliot_store_api::CampaignSourceRole::TaskObjective
                | eliot_store_api::CampaignSourceRole::TaskPlan
        ) && (record.record_id != task_record_id
            || record.revision != eliot_store_api::CampaignOwnerRevision::Task(*task_revision))
        {
            return Err(
                "Task Controller source identity must match the admitted task revision".into(),
            );
        }
    }

    let task_roles = [
        eliot_store_api::CampaignSourceRole::TaskObjective,
        eliot_store_api::CampaignSourceRole::TaskAcceptance,
        eliot_store_api::CampaignSourceRole::TaskPlan,
        eliot_store_api::CampaignSourceRole::TaskOpenItems,
    ];
    if campaign_matrix_complete {
        let Some(recipe) = task_recipe.as_ref() else {
            return Err("complete campaign source matrix requires its bound recipe".into());
        };
        let expected_publications = recipe
            .source_requirements
            .iter()
            .filter(|requirement| {
                requirement.source_binding
                    != eliot_store_api::CampaignSourceBinding::ExplicitlyAbsent
            })
            .count();
        if by_role.len() != expected_publications {
            return Err(format!(
                "complete campaign source matrix requires {expected_publications} publications after explicit absences, observed {}",
                by_role.len()
            ));
        }
        for requirement in &recipe.source_requirements {
            match requirement.source_binding {
                eliot_store_api::CampaignSourceBinding::ExplicitlyAbsent => {
                    if by_role.contains_key(&requirement.role) {
                        return Err(format!(
                            "explicitly absent campaign role {:?} must not have a publication",
                            requirement.role
                        ));
                    }
                }
                _ => {
                    if !by_role.contains_key(&requirement.role) {
                        return Err(format!(
                            "complete campaign source matrix omits declared role {:?}",
                            requirement.role
                        ));
                    }
                }
            }
        }
    } else if by_role.len() != task_roles.len()
        || task_roles.iter().any(|role| !by_role.contains_key(role))
    {
        return Err(
            "partial campaign source publication must contain the four Task Controller rows".into(),
        );
    }

    if let Some(recipe) = task_recipe {
        recipe.validate().map_err(|error| error.to_string())?;
        for role in by_role.keys() {
            if !recipe
                .source_requirements
                .iter()
                .any(|requirement| requirement.role == *role)
            {
                return Err("campaign source publication contains an undeclared role".into());
            }
        }
        let mut history_count = 0usize;
        for publication in &publications {
            history_count = history_count.saturating_add(publication.record.history_plans.len());
            for history in &publication.record.history_plans {
                history
                    .validate_for_source(recipe.campaign_id.as_str(), &publication.record.owner_id)
                    .map_err(|error| error.to_string())?;
            }
        }
        if campaign_matrix_complete && history_count == 0 {
            return Err("complete campaign source matrix requires owner-produced history".into());
        }
        if recipe.binding.task_id.as_str() != task_id
            || recipe.binding.request_id != *request_id
            || recipe.binding.operation_id != transition.identity.operation_id
            || recipe.binding.state_fence != transition.state_fence
        {
            return Err("TaskPlan recipe does not bind the admitted task operation".into());
        }
        let task_plan = by_role
            .get(&eliot_store_api::CampaignSourceRole::TaskPlan)
            .ok_or_else(|| "TaskPlan source publication is missing".to_owned())?;
        let task_plan_recipe: eliot_store_api::LearningStateViewRecipe =
            serde_json::from_value(task_plan.record.document.body.clone())
                .map_err(|_| "TaskPlan is not the typed learning-state recipe".to_owned())?;
        if task_plan_recipe != recipe {
            return Err("TaskPlan publication and recipe parameter are not byte-equivalent".into());
        }
        if task_plan.record.record_id
            != eliot_store_api::CampaignOwnerRecordId::Task(
                eliot_contracts::TaskId::new(task_id.clone()).map_err(|error| error.to_string())?,
            )
            || task_plan.record.revision
                != eliot_store_api::CampaignOwnerRevision::Task(*task_revision)
            || task_plan.record.recorded_state_fence != recipe.binding.state_fence
        {
            return Err("TaskPlan publication does not bind the admitted task identity".into());
        }
        let anchor = recipe
            .source_requirements
            .iter()
            .find(|requirement| requirement.role == eliot_store_api::CampaignSourceRole::TaskPlan)
            .ok_or_else(|| "TaskPlan recipe lacks its authenticated anchor".to_owned())?;
        if anchor.owner.as_str() != eliot_store_api::TASK_CONTROLLER_CAMPAIGN_OWNER_ID
            || anchor.source_binding
                != eliot_store_api::CampaignSourceBinding::AuthenticatedTaskAnchor
            || anchor.expected_reference.is_some()
        {
            return Err("TaskPlan recipe has an invalid authenticated owner anchor".into());
        }
        let objective_requirement = recipe
            .source_requirements
            .iter()
            .find(|requirement| {
                requirement.role == eliot_store_api::CampaignSourceRole::TaskObjective
            })
            .ok_or_else(|| "TaskPlan recipe lacks its TaskObjective source".to_owned())?;
        let objective_publication = by_role
            .get(&eliot_store_api::CampaignSourceRole::TaskObjective)
            .ok_or_else(|| "TaskObjective source publication is missing".to_owned())?;
        let expected_objective = objective_requirement
            .expected_reference
            .as_ref()
            .ok_or_else(|| "TaskObjective recipe reference is missing".to_owned())?;
        let observed_objective = CampaignSourceRevisionRef {
            role: objective_publication.record.role,
            owner: objective_publication.record.owner_id.clone(),
            record_id: objective_publication.record.record_id.clone(),
            revision: objective_publication.record.revision.clone(),
            content_digest: objective_publication.record.content_digest.clone(),
            slot_projection_digests: objective_publication.record.slot_projection_digests.clone(),
            recorded_state_fence: objective_publication.record.recorded_state_fence.clone(),
        };
        if &observed_objective != expected_objective {
            return Err(
                "TaskPlan reference does not bind the owner-issued TaskObjective row".into(),
            );
        }
        for requirement in &recipe.source_requirements {
            let Some(publication) = by_role.get(&requirement.role) else {
                if requirement.source_binding
                    == eliot_store_api::CampaignSourceBinding::ExplicitlyAbsent
                    || (!campaign_matrix_complete
                        && !matches!(
                            requirement.role,
                            eliot_store_api::CampaignSourceRole::TaskObjective
                                | eliot_store_api::CampaignSourceRole::TaskPlan
                        ))
                {
                    continue;
                }
                return Err("campaign source publication matrix omits a declared owner".into());
            };
            if requirement.source_binding
                == eliot_store_api::CampaignSourceBinding::ExplicitlyAbsent
            {
                return Err("an explicitly absent source cannot be published".into());
            }
            if requirement.source_binding == eliot_store_api::CampaignSourceBinding::ExactReference
            {
                let expected = requirement.expected_reference.as_ref().ok_or_else(|| {
                    "exact source requirement lacks its owner reference".to_owned()
                })?;
                let observed = CampaignSourceRevisionRef {
                    role: publication.record.role,
                    owner: publication.record.owner_id.clone(),
                    record_id: publication.record.record_id.clone(),
                    revision: publication.record.revision.clone(),
                    content_digest: publication.record.content_digest.clone(),
                    slot_projection_digests: publication.record.slot_projection_digests.clone(),
                    recorded_state_fence: publication.record.recorded_state_fence.clone(),
                };
                if &observed != expected {
                    return Err("published source does not match the recipe owner reference".into());
                }
            }
        }
    } else if by_role
        .keys()
        .any(|role| !matches!(role, eliot_store_api::CampaignSourceRole::TaskObjective))
    {
        return Err("owner-specific campaign sources require the bound recipe".into());
    }
    Ok(publications)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginChallengeIssueOperation {
    operation_id: OperationId,
    request: OriginChallengeRequest,
    expires_at_unix_ms: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginControlDecideOperation {
    operation_id: OperationId,
    presentation: serde_json::Value,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAutomationRuntimeOperation {
    operation: String,
    #[serde(default)]
    request: Option<UserAutomationHostExecutionOperation>,
    #[serde(default)]
    trigger: Option<UserAutomationDaemonTrigger>,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAutomationDaemonTrigger {
    /// Stable automation identity selected by the operator.
    automation_id: String,
    /// Immutable revision selector; Kernel verifies it against the current row.
    requested_revision: String,
    /// Human-issued nonce; Kernel binds it into the owner-derived occurrence.
    manual_nonce: String,
}

#[cfg(windows)]
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UserAutomationPolicyOwnerSnapshotWire {
    state_fence: StateFence,
    revision: u64,
    policy_digest: String,
    snapshot: eliot_kernel_core::user_automation::ConfigPolicySnapshot,
}

impl KernelComposition {
    /// Executes one authenticated daemon lifecycle request.  Only the
    /// narrow handshake/health dispositions are handled here; semantic
    /// Governor mutations remain owned by `eliotd` and the existing Kernel
    /// transition gateway.
    #[allow(
        clippy::too_many_lines,
        reason = "the closed daemon dispatcher keeps authenticated lifecycle operations and their exact response projection in one audited gateway"
    )]
    pub async fn execute_daemon_request(
        &self,
        session: &Session,
        request_id: RequestId,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        Box::pin(
            self.execute_daemon_request_observed(session, request_id, operation, payload, None),
        )
        .await
    }

    /// Executes one daemon request with the identity admitted on the same
    /// front-door frame.  The compatibility wrapper above remains available
    /// to non-semantic lifecycle callers, but `UserAutomation` production
    /// ingress uses this method so the route can bind owner provenance to the
    /// authenticated request rather than to the daemon peer alone.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_daemon_request_with_identity(
        &self,
        session: &Session,
        request_id: RequestId,
        request_identity: RequestIdentity,
        operation: &str,
        payload: serde_json::Value,
    ) -> Result<Frame, TransportError> {
        request_identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if request_identity.request.metadata.request_id != request_id
            || request_identity.request.state_fence != session.module_generation.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        Box::pin(self.execute_daemon_request_observed(
            session,
            request_id,
            operation,
            payload,
            Some(request_identity),
        ))
        .await
    }

    async fn execute_daemon_request_observed(
        &self,
        session: &Session,
        request_id: RequestId,
        operation: &str,
        payload: serde_json::Value,
        request_identity: Option<RequestIdentity>,
    ) -> Result<Frame, TransportError> {
        observe_daemon_request("kernel.daemon_request_received", "attempt");
        observe_daemon_operation(trusted_daemon_operation(operation), "received");
        let result = Box::pin(self.execute_daemon_request_inner(
            session,
            request_id,
            operation,
            &payload,
            request_identity.as_ref(),
        ))
        .await;
        match &result {
            Ok(_) => {
                observe_daemon_request("kernel.daemon_request_validated", "success");
                observe_daemon_request("kernel.daemon_request_admitted", "success");
                observe_daemon_operation(trusted_daemon_operation(operation), "dispatched");
                observe_daemon_request("kernel.daemon_response_prepared", "success");
                observe_daemon_request("kernel.daemon_response_delivered", "success");
            }
            Err(error) => {
                observe_daemon_request("kernel.daemon_request_validated", "fenced");
                observe_daemon_operation(trusted_daemon_operation(operation), "fenced");
                super::kernel_diagnostics::observe_terminal_error(daemon_terminal_code(error));
            }
        }
        result
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the closed daemon dispatcher keeps authenticated lifecycle operations and their exact response projection in one audited gateway"
    )]
    async fn execute_daemon_request_inner(
        &self,
        session: &Session,
        request_id: RequestId,
        operation: &str,
        payload: &serde_json::Value,
        request_identity: Option<&RequestIdentity>,
    ) -> Result<Frame, TransportError> {
        if session.module_generation.module_id.as_str() != ACTIVE_DAEMON_CALLER {
            return Err(TransportError::SessionFenced);
        }
        #[cfg(windows)]
        self.require_current_daemon_session(session)?;
        let result = match operation {
            "snapshot" => self.daemon_snapshot().map(|value| {
                serde_json::json!({
                    "status": "known",
                    "value": value,
                    "recovery": null,
                })
            }),
            "daemon_ready" => {
                let generation = payload
                    .get("generation")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or(TransportError::SessionFenced)?;
                let authority_epoch: eliot_contracts::EpochId = serde_json::from_value(
                    payload
                        .get("authority_epoch")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                if generation != session.module_generation.generation.value()
                    || !authority_epoch.is_same_authority(&session.authority_epoch)
                {
                    return Err(TransportError::SessionFenced);
                }
                #[cfg(windows)]
                {
                    let (launch, process) = self
                        .validated_authenticated_daemon_ready_inputs()
                        .await
                        .map_err(|_| TransportError::SessionFenced)?;
                    let (contour, snapshot) = self
                        .establish_daemon_supervision(session, &process)
                        .map_err(|_| TransportError::SessionFenced)?;
                    if snapshot.record.lease_id.as_str() != contour.incarnation.supervision_lease_id
                    {
                        return Err(TransportError::SessionFenced);
                    }
                    let ready = Self::eliotd_live_ready_evidence(session, &request_id, payload)
                        .map_err(|_| TransportError::SessionFenced)?;
                    {
                        let mut state = self
                            .daemon_runtime
                            .lock()
                            .map_err(|_| TransportError::SessionFenced)?;
                        if state
                            .supervision
                            .as_ref()
                            .is_some_and(|bound| bound != &contour)
                        {
                            return Err(TransportError::SessionFenced);
                        }
                        state
                            .bind_live_receipt_publication_operation(&ready)
                            .map_err(|_| TransportError::SessionFenced)?;
                        state.supervision = Some(contour.clone());
                    }
                    self.publish_eliotd_live_receipt(&launch, &process, &ready, &contour, None)
                        .map_err(|_| TransportError::SessionFenced)?;
                }
                self.mark_daemon_ready()
                    .map_err(|_| TransportError::SessionFenced)
                    .and_then(|()| {
                        self.record_startup_evidence(7)
                            .map_err(|_| TransportError::SessionFenced)?;
                        Ok(Self::accepted_daemon_response())
                    })
            }
            "origin_challenge_issue" => {
                self.origin_challenge_issue_operation(session, payload.clone())
                    .await
            }
            "origin_control_decide" => {
                self.origin_control_decide_operation(session, payload.clone())
                    .await
            }
            ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION => {
                self.generation_registry_active_query_operation(session, payload.clone())
            }
            DAEMON_STARTUP_EVIDENCE_OPERATION => {
                self.daemon_startup_evidence_operation(session, &request_id, payload)
            }
            #[cfg(windows)]
            USER_AUTOMATION_RUNTIME_OPERATION => {
                Box::pin(self.user_automation_runtime_operation(
                    session,
                    payload.clone(),
                    request_identity.ok_or(TransportError::SessionFenced)?,
                ))
                .await
            }
            "health" => self
                .daemon_health()
                .await
                .map_err(|_| TransportError::SessionFenced)
                .map(|health| Self::daemon_health_response(&health)),
            "store_recovery" => {
                self.store_recovery_operation(session, payload.clone())
                    .await
            }
            "store_initialize_genesis" => {
                self.store_initialize_genesis_operation(session, payload.clone())
                    .await
            }
            "apply_prepared" => {
                Box::pin(self.store_apply_operation(session, request_id.clone(), payload.clone()))
                    .await
            }
            "receipt" => store_receipt_dispatch::dispatch(self, session, payload.clone()).await,
            "store_named" => self.store_named_operation(session, payload.clone()).await,
            "local_read" => self.local_read_operation(session, payload.clone()).await,
            "daemon_degraded" => {
                let reason = payload
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| {
                        !value.trim().is_empty()
                            && value.len() <= 512
                            && !value.chars().any(char::is_control)
                    })
                    .ok_or(TransportError::SessionFenced)?
                    .to_owned();
                self.mark_daemon_degraded(reason)
                    .map_err(|_| TransportError::SessionFenced)
                    .map(|()| Self::accepted_daemon_response())
            }
            "daemon_fatal" => {
                let reason = payload
                    .get("reason")
                    .and_then(serde_json::Value::as_str)
                    .filter(|value| {
                        !value.trim().is_empty()
                            && value.len() <= 512
                            && !value.chars().any(char::is_control)
                    })
                    .ok_or(TransportError::SessionFenced)?
                    .to_owned();
                self.mark_daemon_failed(reason)
                    .map_err(|_| TransportError::SessionFenced)
                    .map(|()| Self::accepted_daemon_response())
            }
            "agent_activation_claim" => {
                #[cfg(windows)]
                {
                    if payload.as_object().is_none_or(|object| object.len() != 1) {
                        return Err(TransportError::SessionFenced);
                    }
                    self.claim_agent_activation_ticket().map(|ticket| {
                        serde_json::json!({
                            "status": "known",
                            "value": { "ticket": ticket },
                            "recovery": null,
                        })
                    })
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "agent_activation_submit" => {
                #[cfg(windows)]
                {
                    // The closed submit operation carries exactly one resolver
                    // outcome in one of two result shapes: the production v2
                    // typed submit envelope carrying one
                    // AgentActivationResolutionResult (unknown envelope
                    // versions are rejected before adoption), or the
                    // unenveloped P-04 typed result shape covering the same
                    // seven closed dispositions. The v2 envelope is trial-decoded first so
                    // production traffic keeps its typed acknowledgement and
                    // reconcile support; the two result shapes share the
                    // ticket ledger but keep independent
                    // exact-replay/conflict accounting. The legacy
                    // success-only `decision` key is no longer accepted
                    // (#204 v1 removal): a payload carrying it, or carrying
                    // no `result`, is fail-closed.
                    let has_legacy_decision = payload
                        .get("decision")
                        .is_some_and(|value| !value.is_null());
                    let has_result = payload.get("result").is_some_and(|value| !value.is_null());
                    if has_legacy_decision || !has_result {
                        return Err(TransportError::SessionFenced);
                    }
                    {
                        let result_value = payload
                            .get("result")
                            .cloned()
                            .ok_or(TransportError::SessionFenced)?;
                        if let Ok(submit) = serde_json::from_value::<AgentActivationResultSubmit>(
                            result_value.clone(),
                        ) {
                            match self.submit_agent_activation_result(submit) {
                                Ok(ack) => Ok(Self::activation_result_daemon_response(&ack)),
                                // Deadline expiry is an expected race at this
                                // boundary, not a daemon-fatal transport failure.
                                // Return an explicit known outcome so the caller can
                                // retain liveness without parsing error strings.
                                // A retained terminal result never takes this
                                // path: exact replay stays idempotent across the
                                // deadline.
                                Err(TransportError::Timeout) => {
                                    Ok(Self::expired_activation_daemon_response())
                                }
                                Err(error) => Err(error),
                            }
                        } else {
                            let result: AgentActivationResolutionResult =
                                serde_json::from_value(result_value)
                                    .map_err(|_| TransportError::SessionFenced)?;
                            match self.submit_agent_activation_resolution_result(result) {
                                Ok(()) => Ok(Self::accepted_daemon_response()),
                                // Same deadline-expiry race as the v2 path:
                                // the ticket lapsed before the typed result
                                // arrived, so the caller observes expiry without
                                // losing daemon liveness.
                                Err(TransportError::Timeout) => {
                                    Ok(Self::expired_activation_daemon_response())
                                }
                                Err(error) => Err(error),
                            }
                        }
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "agent_activation_reconcile" => {
                #[cfg(windows)]
                {
                    // Lost-acknowledgement reconcile: answered purely from
                    // the retained per-ticket record, never by recomputing
                    // semantics or reading the Governor a second time. An
                    // unknown ticket yields a typed Unknown acknowledgement
                    // (the daemon then resubmits its retained result); a
                    // digest mismatch is an identity conflict.
                    let query_value = payload
                        .get("reconcile")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?;
                    let query: AgentActivationResultReconcile = serde_json::from_value(query_value)
                        .map_err(|_| TransportError::SessionFenced)?;
                    self.reconcile_agent_activation_result(&query)
                        .map(|ack| Self::reconciled_activation_daemon_response(&ack))
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "local_read_claim" => {
                // Outbound-only eliotd poller for admitted `eliot.query` pairs
                // (Implements #18): mirrors `agent_activation_claim` —
                // same session/auth/ready/fence gates via the dispatcher head
                // and `frame_dispatch` allowlist, same single-`operation`-key
                // payload shape, same null poll (not error) when empty. The
                // claimed pair carries the Kernel-minted fenced attempt
                // capability the daemon must present back on the read leg and
                // the submit leg; no time lease is involved.
                #[cfg(windows)]
                {
                    if payload.as_object().is_none_or(|object| object.len() != 1) {
                        return Err(TransportError::SessionFenced);
                    }
                    self.claim_local_read_pair(session).map(|pair| match pair {
                        Some((envelope, tool, attempt)) => serde_json::json!({
                            "status": "known",
                            "value": { "pair": { "envelope": envelope, "tool": tool, "attempt": attempt } },
                            "recovery": null,
                        }),
                        None => serde_json::json!({
                            "status": "known",
                            "value": { "pair": null },
                            "recovery": null,
                        }),
                    })
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "local_read_result" => {
                // Daemon submit leg for the claimed pair (Implements #18):
                // validates plus fence-checks the submitted
                // `HostRequestResultBody` and binds it to the waiting host
                // request through the ORS result path. Only the current
                // fencing generation presented by the owning session persists;
                // a late, duplicate, or revoked attempt projects as a known
                // stale outcome (never a bound result, never a transport
                // error). Exact replay stays idempotent (even across deadline
                // expiry); a changed body under the same identity conflicts;
                // an elapsed deadline is the expected race and projects as a
                // known expired outcome so the caller retains liveness without
                // parsing errors.
                #[cfg(windows)]
                {
                    let result_value = payload
                        .get("result")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?;
                    let body: HostRequestResultBody = serde_json::from_value(result_value)
                        .map_err(|_| TransportError::SessionFenced)?;
                    match self.submit_local_read_result(session, &body) {
                        Ok(host_request_route::LocalReadSubmitDisposition::Persisted(_)) => {
                            Ok(Self::accepted_daemon_response())
                        }
                        Ok(host_request_route::LocalReadSubmitDisposition::StaleAttempt(
                            observation,
                        )) => Ok(Self::stale_attempt_daemon_response(&observation)),
                        Err(TransportError::Timeout) => {
                            Ok(Self::expired_activation_daemon_response())
                        }
                        Err(error) => Err(error),
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "task_controller_claim" => {
                #[cfg(windows)]
                {
                    if payload.as_object().is_none_or(|object| object.len() != 1) {
                        return Err(TransportError::SessionFenced);
                    }
                    self.claim_task_controller_pair(session)
                        .map(|pair| match pair {
                            Some((envelope, tool, invocation, attempt)) => serde_json::json!({
                                "status": "known",
                                "value": {
                                    "pair": {
                                        "invocation": invocation,
                                        "envelope": envelope,
                                        "tool": tool,
                                        "operation_id": attempt.operation_id,
                                        "attempt": attempt,
                                    }
                                },
                                "recovery": null,
                            }),
                            None => serde_json::json!({
                                "status": "known",
                                "value": { "pair": null },
                                "recovery": null,
                            }),
                        })
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "task_controller_result" => {
                #[cfg(windows)]
                {
                    let result_value = payload
                        .get("result")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?;
                    let body: TaskControllerResultBody = serde_json::from_value(result_value)
                        .map_err(|_| TransportError::SessionFenced)?;
                    match self.submit_task_controller_result(session, &body) {
                        Ok(host_request_route::LocalReadSubmitDisposition::Persisted(_)) => {
                            Ok(Self::accepted_daemon_response())
                        }
                        Ok(host_request_route::LocalReadSubmitDisposition::StaleAttempt(
                            observation,
                        )) => Ok(Self::stale_attempt_daemon_response(&observation)),
                        Err(TransportError::Timeout) => {
                            Ok(Self::expired_activation_daemon_response())
                        }
                        Err(error) => Err(error),
                    }
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            #[cfg(windows)]
            "agent_host_request_submit" => {
                // Typed P-04 host-request envelopes through the same closed
                // daemon dispatcher. The admit path owns every
                // connection/descriptor/fence/generation/durability join; a
                // changed binding under a known identity conflicts, an unknown
                // parent is unknown, and an elapsed deadline times out there.
                let envelope = host_request_route::host_request_envelope_from_payload(payload)?;
                let (receipt, record) = self.admit_host_request_envelope(&envelope)?;
                Ok(host_request_route::host_request_admitted_response(
                    &receipt, &record,
                ))
            }
            #[cfg(windows)]
            "agent_host_request_cancel" => {
                let envelope = host_request_route::host_request_envelope_from_payload(payload)?;
                let (receipt, record) = self.cancel_host_request(&envelope)?;
                Ok(host_request_route::host_request_admitted_response(
                    &receipt, &record,
                ))
            }
            #[cfg(windows)]
            "agent_host_request_reconcile" => {
                let envelope = host_request_route::host_request_envelope_from_payload(payload)?;
                let (receipt, record) = self.reconcile_host_request(&envelope)?;
                Ok(host_request_route::host_request_admitted_response(
                    &receipt, &record,
                ))
            }
            #[cfg(windows)]
            "agent_host_request_rehydrate" => {
                let envelope = host_request_route::host_request_envelope_from_payload(payload)?;
                let receipt = host_request_route::host_request_receipt_from_payload(payload)?;
                let record = self.rehydrate_host_request(&envelope, &receipt)?;
                Ok(host_request_route::host_request_rehydrated_response(
                    &record,
                ))
            }
            "publish_owner_bundle" => {
                let operation: OwnerPublishOperation = serde_json::from_value(payload.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                if operation.expected_revision == 0 {
                    return Err(TransportError::SessionFenced);
                }
                // Session-authority agreement under the existing session
                // authorities: every admitted binding must share the
                // authenticated session authority, or the bundle does not
                // describe authority this session may fence.
                if !owner_bundle_agrees_with_session(&operation.bundle, session) {
                    return Err(TransportError::SessionFenced);
                }
                match self.recover_p07_owner(operation.bundle, operation.expected_revision) {
                    Ok(revision) => Ok(serde_json::json!({
                        "kind": "owner_bundle_receipt",
                        "value": { "revision": revision, "status": "bound" },
                    })),
                    // The presented bundle conflicts with Kernel owner
                    // state (stale revision, disagreeing material): the
                    // caller re-serves fresh state, never retries blindly.
                    Err(KernelBuildError::Core(_)) => Err(TransportError::IdentityConflict),
                    Err(_) => Err(TransportError::SessionFenced),
                }
            }
            "query_owner_bundle" => {
                let (bound, revision, digest) = self.p07_owner_readback();
                Ok(serde_json::json!({
                    "kind": "owner_bundle_readback",
                    "value": {
                        "bound": bound,
                        "revision": revision,
                        "digest": digest,
                    },
                }))
            }
            "activate_grant" => {
                let operation: GrantActivationOperation =
                    serde_json::from_value(payload.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.grant_id.trim().is_empty() || operation.snapshot_id.trim().is_empty() {
                    return Err(TransportError::SessionFenced);
                }
                p07_binding_agrees_with_session(&operation.binding, session)?;
                let request = eliot_authority::GrantActivationRequest {
                    grant_id: eliot_authority::GrantId::new(operation.grant_id)
                        .map_err(|_| TransportError::SessionFenced)?,
                    snapshot_id: eliot_authority::SnapshotId::new(operation.snapshot_id)
                        .map_err(|_| TransportError::SessionFenced)?,
                    binding: operation.binding,
                };
                let owner = self.retained_p07_owner()?;
                let bound = owner.as_ref().ok_or(TransportError::SessionFenced)?;
                let receipt =
                    eliot_authority::P07AuthorityPort::activate_grant(bound.port(), &request)
                        .map_err(|error| map_p07_port_error(&error))?;
                let value =
                    serde_json::to_value(&receipt).map_err(|_| TransportError::SessionFenced)?;
                Ok(serde_json::json!({
                    "kind": "authority_activation_receipt",
                    "value": value,
                }))
            }
            "revoke_grant" => {
                let operation: GrantRevocationOperation =
                    serde_json::from_value(payload.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.grant_id.trim().is_empty() || operation.snapshot_id.trim().is_empty() {
                    return Err(TransportError::SessionFenced);
                }
                p07_binding_agrees_with_session(&operation.binding, session)?;
                let request = eliot_authority::GrantRevocationRequest {
                    grant_id: eliot_authority::GrantId::new(operation.grant_id)
                        .map_err(|_| TransportError::SessionFenced)?,
                    snapshot_id: eliot_authority::SnapshotId::new(operation.snapshot_id)
                        .map_err(|_| TransportError::SessionFenced)?,
                    binding: operation.binding,
                };
                let owner = self.retained_p07_owner()?;
                let bound = owner.as_ref().ok_or(TransportError::SessionFenced)?;
                let receipt =
                    eliot_authority::P07AuthorityPort::revoke_grant(bound.port(), &request)
                        .map_err(|error| map_p07_port_error(&error))?;
                let value =
                    serde_json::to_value(&receipt).map_err(|_| TransportError::SessionFenced)?;
                Ok(serde_json::json!({
                    "kind": "authority_revocation_receipt",
                    "value": value,
                }))
            }
            "activate_introduction" => {
                let operation: IntroductionActivationOperation =
                    serde_json::from_value(payload.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.introduction_id.trim().is_empty()
                    || operation.snapshot_id.trim().is_empty()
                {
                    return Err(TransportError::SessionFenced);
                }
                p07_binding_agrees_with_session(&operation.binding, session)?;
                let request = eliot_authority::IntroductionActivationRequest {
                    introduction_id: eliot_authority::IntroductionId::new(
                        operation.introduction_id,
                    )
                    .map_err(|_| TransportError::SessionFenced)?,
                    snapshot_id: eliot_authority::SnapshotId::new(operation.snapshot_id)
                        .map_err(|_| TransportError::SessionFenced)?,
                    binding: operation.binding,
                };
                let owner = self.retained_p07_owner()?;
                let bound = owner.as_ref().ok_or(TransportError::SessionFenced)?;
                let receipt = eliot_authority::P07AuthorityPort::activate_introduction(
                    bound.port(),
                    &request,
                )
                .map_err(|error| map_p07_port_error(&error))?;
                let value =
                    serde_json::to_value(&receipt).map_err(|_| TransportError::SessionFenced)?;
                Ok(serde_json::json!({
                    "kind": "authority_activation_receipt",
                    "value": value,
                }))
            }
            "revoke_introduction" => {
                let operation: IntroductionRevocationOperation =
                    serde_json::from_value(payload.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.introduction_id.trim().is_empty()
                    || operation.snapshot_id.trim().is_empty()
                {
                    return Err(TransportError::SessionFenced);
                }
                p07_binding_agrees_with_session(&operation.binding, session)?;
                let request = eliot_authority::IntroductionRevocationRequest {
                    introduction_id: eliot_authority::IntroductionId::new(
                        operation.introduction_id,
                    )
                    .map_err(|_| TransportError::SessionFenced)?,
                    snapshot_id: eliot_authority::SnapshotId::new(operation.snapshot_id)
                        .map_err(|_| TransportError::SessionFenced)?,
                    binding: operation.binding,
                };
                let owner = self.retained_p07_owner()?;
                let bound = owner.as_ref().ok_or(TransportError::SessionFenced)?;
                let receipt =
                    eliot_authority::P07AuthorityPort::revoke_introduction(bound.port(), &request)
                        .map_err(|error| map_p07_port_error(&error))?;
                let value =
                    serde_json::to_value(&receipt).map_err(|_| TransportError::SessionFenced)?;
                Ok(serde_json::json!({
                    "kind": "authority_revocation_receipt",
                    "value": value,
                }))
            }
            "publish_wasm_dispatch_bundle" => {
                self.wasm_dispatch_bundle_operation(session, payload.clone())
            }
            "bind_notify_launch_grant" => {
                self.notify_launch_grant_operation(session, payload.clone())
                    .await
            }
            _ => return Err(TransportError::SessionFenced),
        };
        let value = result.map_err(|_| TransportError::SessionFenced)?;
        let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, value)?;
        frame.request_id = Some(request_id);
        frame.validate()?;
        Ok(frame)
    }

    fn accepted_daemon_response() -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": { "accepted": true },
            "recovery": null,
        })
    }

    #[cfg(windows)]
    /// Drives one real `UserAutomation` owner operation from the authenticated
    /// daemon session through the server-authored Host channel.
    ///
    /// The daemon payload contains only the closed typed operation.  The
    /// channel, descriptor digest, peer receipt digest, and connection id are
    /// obtained from the Host open handshake; a request fence that disagrees
    /// with the daemon session is rejected before opening the owner channel.
    /// Runtime owner failures remain typed projections so an uncertain send
    /// can be reconciled by its original operation identity.
    #[allow(
        clippy::too_many_lines,
        reason = "issue #18 audited gateway dispatch; staged extraction follows"
    )]
    async fn user_automation_runtime_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
        request_identity: &RequestIdentity,
    ) -> Result<serde_json::Value, TransportError> {
        request_identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if request_identity.request.state_fence != session.module_generation.state_fence {
            return Err(TransportError::SessionFenced);
        }
        let envelope: UserAutomationRuntimeOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        if envelope.operation != USER_AUTOMATION_RUNTIME_OPERATION {
            return Err(TransportError::SessionFenced);
        }
        if envelope.request.is_some() == envelope.trigger.is_some() {
            return Err(TransportError::SessionFenced);
        }
        let Some(request) = envelope.request else {
            let Some(trigger) = envelope.trigger else {
                return Err(TransportError::SessionFenced);
            };
            return Box::pin(self.user_automation_owner_trigger_operation(
                session,
                trigger,
                request_identity,
            ))
            .await;
        };

        let request_fence = match &request {
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                if let Err(error) = request.validate() {
                    return Ok(Self::user_automation_runtime_error_response(
                        UserAutomationRuntimeError::Rejected(error.to_string()),
                    ));
                }
                &request.context.state_fence
            }
            UserAutomationHostExecutionOperation::CancelPendingWakes { request } => {
                if let Err(error) = request.validate() {
                    return Ok(Self::user_automation_runtime_error_response(
                        UserAutomationRuntimeError::Rejected(error.to_string()),
                    ));
                }
                &request.state_fence
            }
            UserAutomationHostExecutionOperation::ReadPendingWake { request } => {
                if let Err(error) = request.validate() {
                    return Ok(Self::user_automation_runtime_error_response(
                        UserAutomationRuntimeError::Rejected(error.to_string()),
                    ));
                }
                &request.context.state_fence
            }
        };
        if request_fence != &session.module_generation.state_fence {
            return Err(TransportError::SessionFenced);
        }

        let owner_check = match &request {
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                self.revalidate_user_automation_admission(session, request)
                    .await
            }
            UserAutomationHostExecutionOperation::CancelPendingWakes { request } => {
                self.revalidate_user_automation_cancellation(session, request)
                    .await
            }
            UserAutomationHostExecutionOperation::ReadPendingWake { request } => {
                self.revalidate_user_automation_wake_read(session, request)
                    .await
            }
        };
        if let Err(error) = owner_check {
            return Ok(Self::user_automation_runtime_error_response(error));
        }

        let transport =
            match AuthenticatedUserAutomationHostExecutionTransport::connect_server_authored(
                self.ipc_limits().operation_timeout,
            )
            .await
            {
                Ok(transport) => transport,
                Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
            };
        if transport.channel_binding().state_fence != session.module_generation.state_fence {
            return Err(TransportError::SessionFenced);
        }
        let client = match UserAutomationHostExecutionClient::new(transport) {
            Ok(client) => client,
            Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
        };

        // The Host open handshake may have taken long enough for the current
        // pointer or owner invocation to change. Re-read the canonical owner
        // immediately before crossing into the effect owner; the earlier
        // shape/fence check is not an effect-time admission proof.
        let owner_check = match &request {
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                self.revalidate_user_automation_admission(session, request)
                    .await
            }
            UserAutomationHostExecutionOperation::CancelPendingWakes { request } => {
                self.revalidate_user_automation_cancellation(session, request)
                    .await
            }
            UserAutomationHostExecutionOperation::ReadPendingWake { request } => {
                self.revalidate_user_automation_wake_read(session, request)
                    .await
            }
        };
        if let Err(error) = owner_check {
            return Ok(Self::user_automation_runtime_error_response(error));
        }

        match request {
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                match Box::pin(client.admit_occurrence(request)).await {
                    Ok(execution) => Ok(serde_json::json!({
                        "status": "known",
                        "value": {
                            "outcome": "admitted",
                            "execution": execution,
                        },
                        "recovery": null,
                    })),
                    Err(error) => Ok(Self::user_automation_runtime_error_response(error)),
                }
            }
            UserAutomationHostExecutionOperation::CancelPendingWakes { request } => {
                match Box::pin(client.cancel_pending_wakes(request)).await {
                    Ok(wake_ids) => Ok(serde_json::json!({
                        "status": "known",
                        "value": {
                            "outcome": "cancelled",
                            "wake_ids": wake_ids,
                        },
                        "recovery": null,
                    })),
                    Err(error) => Ok(Self::user_automation_runtime_error_response(error)),
                }
            }
            UserAutomationHostExecutionOperation::ReadPendingWake { request } => {
                match Box::pin(client.read_pending_wake(request)).await {
                    Ok(readback) => Ok(serde_json::json!({
                        "status": "known",
                        "value": {
                            "outcome": "wake_readback",
                            "readback": readback,
                        },
                        "recovery": null,
                    })),
                    Err(error) => Ok(Self::user_automation_runtime_error_response(error)),
                }
            }
        }
    }

    #[cfg(windows)]
    /// Acquires the canonical owner material for a daemon/operator trigger.
    ///
    /// The wire carrier is only `(automation_id, requested_revision,
    /// manual_nonce)`. Principal and State Fence come from the authenticated
    /// Kernel session, while the immutable revision and current pointer come
    /// from the generation-routed canonical Store owner. No caller-supplied
    /// preflight, invocation, or Host authority is accepted here.
    #[allow(
        clippy::too_many_lines,
        reason = "issue #18 audited gateway dispatch; staged extraction follows"
    )]
    async fn user_automation_owner_trigger_operation(
        &self,
        session: &Session,
        trigger: UserAutomationDaemonTrigger,
        request_identity: &RequestIdentity,
    ) -> Result<serde_json::Value, TransportError> {
        request_identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if request_identity.request.state_fence != session.module_generation.state_fence {
            return Err(TransportError::SessionFenced);
        }
        validate_user_automation_trigger_text(&trigger.automation_id, "automation_id")?;
        validate_user_automation_trigger_text(&trigger.requested_revision, "requested_revision")?;
        validate_user_automation_trigger_text(&trigger.manual_nonce, "manual_nonce")?;
        session
            .peer
            .validate()
            .map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let authenticated_principal = authenticated_user_automation_principal(session)?;
        let manual_nonce = trigger.manual_nonce.clone();
        let lookup = UserAutomationOwnerLookup {
            automation_id: trigger.automation_id,
            requested_revision: trigger.requested_revision,
            authenticated_principal,
            state_fence: session.module_generation.state_fence.clone(),
        };
        let gateway = self.retained_store_gateway()?;
        let owner = gateway
            .read_user_automation_owner(&lookup)
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        if owner.current_configuration_state
            != eliot_kernel_core::user_automation::UserAutomationConfigurationState::Active
        {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::Rejected(
                    "UserAutomation owner current configuration is not active".to_owned(),
                ),
            ));
        }
        let manual_trigger = eliot_kernel_core::user_automation::UserAutomationTrigger::Manual {
            nonce: manual_nonce.clone(),
        };
        let occurrence_id =
            eliot_kernel_core::user_automation::UserAutomationInvocation::occurrence_identity_for(
                &owner.revision.automation_id,
                &owner.revision.revision,
                &manual_trigger,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        let invocation = gateway
            .read_user_automation_invocation(
                &lookup.state_fence,
                &lookup.automation_id,
                &occurrence_id,
            )
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        if invocation.automation_id != owner.revision.automation_id
            || invocation.automation_revision != owner.revision.revision
            || invocation.trigger != manual_trigger
            || invocation.principal_ref != owner.authenticated_principal
            || invocation.mode != owner.revision.mode
            || invocation.work_scope_ref != owner.revision.work_scope.scope_id
            || invocation.workdir_ref != owner.revision.workdir_ref
        {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::Rejected(
                    "stored UserAutomation invocation does not bind to the owner revision"
                        .to_owned(),
                ),
            ));
        }
        let provenance = match invocation.require_run_now_provenance(&lookup.state_fence) {
            Ok(provenance) => provenance,
            Err(error) => {
                return Ok(Self::user_automation_runtime_error_response(
                    UserAutomationRuntimeError::Rejected(error.to_string()),
                ));
            }
        };
        let source_identity = OperationIdentity {
            operation_id: provenance.operation_id.clone(),
            idempotency_key: provenance.idempotency_key.clone(),
            canonical_request_hash: provenance.canonical_request_hash.clone(),
        };
        let source_store_receipt = match ensure_user_automation_run_now_receipt(
            &*gateway,
            &lookup.state_fence,
            &source_identity,
            &invocation,
        )
        .await
        {
            Ok(receipt) => receipt,
            Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
        };
        let Some(source_receipt) = source_store_receipt.envelope.as_ref() else {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::UnknownOutcome(
                    "canonical UserAutomation source receipt envelope is not retained".to_owned(),
                ),
            ));
        };
        if source_receipt.core.request.metadata != provenance.request_metadata
            || source_receipt.core.request.state_fence != lookup.state_fence
            || source_receipt.core.work_scope.product_id != provenance.request_metadata.product_id
        {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::IdentityConflict,
            ));
        }
        let preflight_owner_snapshot = match self
            .read_user_automation_preflight_owner_snapshot(&lookup.state_fence)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
        };
        let policy_snapshot = match Self::user_automation_policy_snapshot_from_recovery(
            &preflight_owner_snapshot,
            &lookup.state_fence,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
        };
        let wake_request = UserAutomationWakeReadRequest {
            context: provenance.request_metadata.clone(),
            authenticated_principal: lookup.authenticated_principal.clone(),
            identity: source_identity.clone(),
            invocation: invocation.clone(),
        };
        if let Err(error) = wake_request.validate() {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::Rejected(error.to_string()),
            ));
        }
        let host_transport =
            match AuthenticatedUserAutomationHostExecutionTransport::connect_server_authored(
                self.ipc_limits().operation_timeout,
            )
            .await
            {
                Ok(transport) => transport,
                Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
            };
        if host_transport.channel_binding().state_fence != lookup.state_fence {
            return Err(TransportError::SessionFenced);
        }
        let host_client = match UserAutomationHostExecutionClient::new(host_transport) {
            Ok(client) => client,
            Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
        };
        let wake_readback =
            match Box::pin(host_client.read_pending_wake(wake_request.clone())).await {
                Ok(readback) => readback,
                Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
            };
        let owner_after = gateway
            .read_user_automation_owner(&lookup)
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        if owner_after.automation_id != owner.automation_id
            || owner_after.revision != owner.revision
            || owner_after.current_configuration_state != owner.current_configuration_state
        {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::Rejected(
                    "UserAutomation owner changed during trigger preflight".to_owned(),
                ),
            ));
        }
        let invocation_after = gateway
            .read_user_automation_invocation(
                &lookup.state_fence,
                &lookup.automation_id,
                &occurrence_id,
            )
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        let preflight_owner_snapshot_after = match self
            .read_user_automation_preflight_owner_snapshot(&lookup.state_fence)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
        };
        let policy_snapshot_after = match Self::user_automation_policy_snapshot_from_recovery(
            &preflight_owner_snapshot_after,
            &lookup.state_fence,
        ) {
            Ok(snapshot) => snapshot,
            Err(error) => return Ok(Self::user_automation_runtime_error_response(error)),
        };
        if preflight_owner_snapshot_after != preflight_owner_snapshot
            || policy_snapshot_after != policy_snapshot
        {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::IdentityConflict,
            ));
        }
        if invocation_after != invocation
            || ensure_user_automation_run_now_receipt(
                &*gateway,
                &lookup.state_fence,
                &source_identity,
                &invocation_after,
            )
            .await
            .is_err()
        {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::IdentityConflict,
            ));
        }
        let preflight_owner_readback_digest = match canonical_json_bytes(&preflight_owner_snapshot)
        {
            Ok(bytes) => sha256_hex(&bytes),
            Err(error) => {
                return Ok(Self::user_automation_runtime_error_response(
                    UserAutomationRuntimeError::Rejected(format!(
                        "canonical UserAutomation preflight readback encoding failed: {error}"
                    )),
                ));
            }
        };
        Ok(serde_json::json!({
            "status": "known",
            "value": {
                "outcome": "owner_acquired",
                "owner": owner,
                "invocation": invocation,
                "occurrence_id": occurrence_id,
                "source_receipt": source_receipt,
                "wake_readback": wake_readback,
                "policy_snapshot": policy_snapshot,
                "preflight_owner_readback_digest": preflight_owner_readback_digest,
            },
            "recovery": null,
        }))
    }

    #[cfg(windows)]
    /// Reads the canonical owner and Durable Job inputs for one `UserAutomation`
    /// preflight at a single Store State Fence. This remains a mechanical
    /// Kernel join: payloads stay opaque, but Store record identity, schema,
    /// canonical bytes, and any embedded fence must agree before the caller
    /// can use the readback as preflight evidence.
    async fn read_user_automation_preflight_owner_snapshot(
        &self,
        state_fence: &StateFence,
    ) -> Result<StoreRecoverySnapshot, UserAutomationRuntimeError> {
        state_fence
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let records = ["config", "policy", "task", "skill", "module_registry"]
            .into_iter()
            .map(|key| {
                RecoveryRecordKey::new("owner", key)
                    .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let expected_records = records.iter().cloned().collect::<BTreeSet<_>>();
        let request = StoreRecoveryRequest {
            contract_version: eliot_store_api::CONTRACT_VERSION,
            state_fence: state_fence.clone(),
            records,
            include_receipts: false,
            include_jobs: true,
        };
        let gateway = self.retained_store_gateway().map_err(|_| {
            UserAutomationRuntimeError::Unavailable(
                "canonical UserAutomation preflight Store route is unavailable".to_owned(),
            )
        })?;
        let recovery = gateway
            .recovery(request)
            .await
            .map_err(UserAutomationRuntimeError::Unavailable)?;
        recovery
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let observed_records = recovery
            .owner_records
            .iter()
            .map(RecoveryRecord::record_key)
            .collect::<BTreeSet<_>>();
        if recovery.state_fence != *state_fence
            || recovery.canonical_scope.state_fence != *state_fence
            || recovery.owner_records.len() != expected_records.len()
            || observed_records != expected_records
            || !recovery.receipts.is_empty()
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        for record in &recovery.owner_records {
            Self::validate_user_automation_preflight_record(record, state_fence, true)?;
        }
        for record in &recovery.job_records {
            Self::validate_user_automation_preflight_record(record, state_fence, false)?;
        }
        Ok(recovery)
    }

    #[cfg(windows)]
    fn validate_user_automation_preflight_record(
        record: &RecoveryRecord,
        state_fence: &StateFence,
        owner_record: bool,
    ) -> Result<(), UserAutomationRuntimeError> {
        record
            .validate()
            .map_err(|_| UserAutomationRuntimeError::IdentityConflict)?;
        if record.state_fence != *state_fence
            || (owner_record && record.schema != eliot_store_api::OWNER_SNAPSHOT_SCHEMA)
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let payload: serde_json::Value = serde_json::from_slice(&record.payload).map_err(|_| {
            UserAutomationRuntimeError::Rejected(
                "canonical UserAutomation preflight owner payload is invalid JSON".to_owned(),
            )
        })?;
        let canonical = canonical_json_bytes(&payload).map_err(|error| {
            UserAutomationRuntimeError::Rejected(format!(
                "canonical UserAutomation preflight owner encoding failed: {error}"
            ))
        })?;
        if canonical != record.payload {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Self::validate_embedded_user_automation_fences(&payload, state_fence)
    }

    #[cfg(windows)]
    fn validate_embedded_user_automation_fences(
        value: &serde_json::Value,
        expected: &StateFence,
    ) -> Result<(), UserAutomationRuntimeError> {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    Self::validate_embedded_user_automation_fences(value, expected)?;
                }
            }
            serde_json::Value::Object(fields) => {
                if let Some(fence_value) = fields.get("state_fence") {
                    let observed: StateFence = serde_json::from_value(fence_value.clone())
                        .map_err(|_| UserAutomationRuntimeError::IdentityConflict)?;
                    if &observed != expected {
                        return Err(UserAutomationRuntimeError::IdentityConflict);
                    }
                }
                for value in fields.values() {
                    Self::validate_embedded_user_automation_fences(value, expected)?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    #[cfg(windows)]
    /// Reads the exact retained Governor Policy owner record from Store.
    ///
    /// This route deliberately accepts no handshake digest as snapshot data:
    /// the Store record key, owner schema, canonical bytes, owner revision,
    /// policy digest, embedded fence, and embedded revision must all correlate.
    async fn read_user_automation_policy_snapshot(
        &self,
        state_fence: &StateFence,
    ) -> Result<eliot_kernel_core::user_automation::ConfigPolicySnapshot, UserAutomationRuntimeError>
    {
        let recovery = self
            .read_user_automation_preflight_owner_snapshot(state_fence)
            .await?;
        Self::user_automation_policy_snapshot_from_recovery(&recovery, state_fence)
    }

    #[cfg(windows)]
    fn user_automation_policy_snapshot_from_recovery(
        recovery: &StoreRecoverySnapshot,
        state_fence: &StateFence,
    ) -> Result<eliot_kernel_core::user_automation::ConfigPolicySnapshot, UserAutomationRuntimeError>
    {
        let record = recovery
            .owner_records
            .iter()
            .find(|record| record.namespace == "owner" && record.key == "policy")
            .ok_or(UserAutomationRuntimeError::IdentityConflict)?;
        if recovery.state_fence != *state_fence
            || record.state_fence != *state_fence
            || record.schema != eliot_store_api::OWNER_SNAPSHOT_SCHEMA
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let owner: UserAutomationPolicyOwnerSnapshotWire = serde_json::from_slice(&record.payload)
            .map_err(|_| {
                UserAutomationRuntimeError::Rejected(
                    "canonical Policy owner snapshot schema is invalid".to_owned(),
                )
            })?;
        let canonical_owner = canonical_json_bytes(&owner).map_err(|error| {
            UserAutomationRuntimeError::Rejected(format!(
                "canonical Policy owner snapshot encoding failed: {error}"
            ))
        })?;
        let snapshot_bytes = canonical_json_bytes(&owner.snapshot).map_err(|error| {
            UserAutomationRuntimeError::Rejected(format!(
                "canonical Policy snapshot encoding failed: {error}"
            ))
        })?;
        owner.snapshot.validate().map_err(|error| {
            UserAutomationRuntimeError::Rejected(format!(
                "canonical Policy owner snapshot is invalid: {error}"
            ))
        })?;
        if canonical_owner != record.payload
            || owner.state_fence != *state_fence
            || owner.revision != record.revision
            || owner.revision == 0
            || owner.snapshot.state_fence != *state_fence
            || owner.snapshot.revision.value() != owner.revision
            || owner.policy_digest != sha256_hex(&snapshot_bytes)
            || owner.policy_digest.len() != 64
            || !owner
                .policy_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Ok(owner.snapshot)
    }

    #[cfg(windows)]
    /// Revalidates a caller-supplied admission carrier against the canonical
    /// owner immediately before the Host effect. The typed carrier remains a
    /// compatibility surface, but it is never an authority source: current
    /// revision, live configuration state, persisted invocation lineage, and
    /// the committed Store operation are all recovered or checked here.
    async fn revalidate_user_automation_admission(
        &self,
        session: &Session,
        request: &UserAutomationRuntimeAdmission,
    ) -> Result<(), UserAutomationRuntimeError> {
        let authenticated_principal =
            authenticated_user_automation_principal(session).map_err(|_| {
                UserAutomationRuntimeError::Rejected(
                    "UserAutomation session principal is unavailable".to_owned(),
                )
            })?;
        if request.authenticated_principal != authenticated_principal {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let lookup = UserAutomationOwnerLookup {
            automation_id: request.invocation.automation_id.clone(),
            requested_revision: request.invocation.automation_revision.clone(),
            authenticated_principal,
            state_fence: session.module_generation.state_fence.clone(),
        };
        let gateway = self.retained_store_gateway().map_err(|_| {
            UserAutomationRuntimeError::Unavailable(
                "canonical UserAutomation Store owner is unavailable".to_owned(),
            )
        })?;
        let owner = gateway
            .read_user_automation_owner(&lookup)
            .await
            .map_err(UserAutomationRuntimeError::Unavailable)?;
        if owner.current_configuration_state
            != eliot_kernel_core::user_automation::UserAutomationConfigurationState::Active
        {
            return Err(UserAutomationRuntimeError::Rejected(
                "UserAutomation owner current configuration is not active".to_owned(),
            ));
        }
        let occurrence_id = request
            .invocation
            .occurrence_identity()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        if request.revision != owner.revision
            || request.preflight.occurrence_id != occurrence_id
            || request.preflight.automation_id != owner.automation_id
            || request.preflight.automation_revision != owner.revision.revision
            || request.preflight.configuration_state
                != eliot_kernel_core::user_automation::UserAutomationConfigurationState::Active
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let persisted = gateway
            .read_user_automation_invocation(
                &lookup.state_fence,
                &lookup.automation_id,
                &occurrence_id,
            )
            .await
            .map_err(UserAutomationRuntimeError::Unavailable)?;
        if persisted != request.invocation {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let source_receipt = ensure_user_automation_run_now_receipt(
            &gateway,
            &lookup.state_fence,
            &request.identity,
            &request.invocation,
        )
        .await?;
        let Some(source_receipt_envelope) = source_receipt.envelope.as_ref() else {
            return Err(UserAutomationRuntimeError::UnknownOutcome(
                "canonical UserAutomation source receipt envelope is not retained".to_owned(),
            ));
        };
        if &request.preflight.source_receipt != source_receipt_envelope {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let policy_snapshot = self
            .read_user_automation_policy_snapshot(&lookup.state_fence)
            .await?;
        if request.preflight.config_snapshot_id != policy_snapshot.snapshot_id
            || request.preflight.config_snapshot != policy_snapshot
            || policy_snapshot.state_fence != lookup.state_fence
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Ok(())
    }

    #[cfg(windows)]
    /// Revalidates an exact persisted-wake read against the authenticated
    /// session and canonical `RunNow` owner before crossing to Host.
    async fn revalidate_user_automation_wake_read(
        &self,
        session: &Session,
        request: &UserAutomationWakeReadRequest,
    ) -> Result<(), UserAutomationRuntimeError> {
        request
            .validate()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let authenticated_principal =
            authenticated_user_automation_principal(session).map_err(|_| {
                UserAutomationRuntimeError::Rejected(
                    "UserAutomation session principal is unavailable".to_owned(),
                )
            })?;
        if request.authenticated_principal != authenticated_principal
            || request.context.state_fence != session.module_generation.state_fence
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let occurrence_id = request
            .invocation
            .occurrence_identity()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        let lookup = UserAutomationOwnerLookup {
            automation_id: request.invocation.automation_id.clone(),
            requested_revision: request.invocation.automation_revision.clone(),
            authenticated_principal: authenticated_principal.clone(),
            state_fence: session.module_generation.state_fence.clone(),
        };
        let gateway = self.retained_store_gateway().map_err(|_| {
            UserAutomationRuntimeError::Unavailable(
                "canonical UserAutomation Store owner is unavailable".to_owned(),
            )
        })?;
        let owner = gateway
            .read_user_automation_owner(&lookup)
            .await
            .map_err(UserAutomationRuntimeError::Unavailable)?;
        if owner.current_configuration_state
            != eliot_kernel_core::user_automation::UserAutomationConfigurationState::Active
            || owner.revision.owner_principal != authenticated_principal
            || owner.revision.revision != request.invocation.automation_revision
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let persisted = gateway
            .read_user_automation_invocation(
                &lookup.state_fence,
                &lookup.automation_id,
                &occurrence_id,
            )
            .await
            .map_err(UserAutomationRuntimeError::Unavailable)?;
        if persisted != request.invocation {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        ensure_user_automation_run_now_receipt(
            &gateway,
            &lookup.state_fence,
            &request.identity,
            &request.invocation,
        )
        .await?;
        Ok(())
    }

    #[cfg(windows)]
    /// Revalidates a compatibility cancellation carrier against the committed
    /// owner remove operation and current retained revision. Cancellation may
    /// target a retired current pointer, so it does not require ACTIVE state.
    async fn revalidate_user_automation_cancellation(
        &self,
        session: &Session,
        request: &UserAutomationWakeCancellation,
    ) -> Result<(), UserAutomationRuntimeError> {
        let authenticated_principal =
            authenticated_user_automation_principal(session).map_err(|_| {
                UserAutomationRuntimeError::Rejected(
                    "UserAutomation session principal is unavailable".to_owned(),
                )
            })?;
        if request.authenticated_principal != authenticated_principal {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let lookup = UserAutomationOwnerLookup {
            automation_id: request.automation_id.clone(),
            requested_revision: request.automation_revision.clone(),
            authenticated_principal,
            state_fence: session.module_generation.state_fence.clone(),
        };
        let gateway = self.retained_store_gateway().map_err(|_| {
            UserAutomationRuntimeError::Unavailable(
                "canonical UserAutomation Store owner is unavailable".to_owned(),
            )
        })?;
        let owner = gateway
            .read_user_automation_owner(&lookup)
            .await
            .map_err(UserAutomationRuntimeError::Unavailable)?;
        if owner.automation_id != request.automation_id
            || owner.revision.revision != request.automation_revision
            || owner.revision.owner_principal != request.authenticated_principal
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        ensure_user_automation_store_receipt(&*gateway, &lookup.state_fence, &request.identity)
            .await
            .map(|_| ())
    }

    #[cfg(windows)]
    fn user_automation_runtime_error_response(
        error: UserAutomationRuntimeError,
    ) -> serde_json::Value {
        match error {
            UserAutomationRuntimeError::Unavailable(reason) => serde_json::json!({
                "status": "unknown",
                "value": { "outcome": "unavailable" },
                "recovery": { "kind": "unavailable", "reason": reason },
            }),
            UserAutomationRuntimeError::UnknownOutcome(reason) => serde_json::json!({
                "status": "unknown",
                "value": { "outcome": "unknown_outcome" },
                "recovery": { "kind": "unknown_outcome", "reason": reason },
            }),
            UserAutomationRuntimeError::Rejected(reason) => serde_json::json!({
                "status": "known",
                "value": {
                    "accepted": false,
                    "outcome": "rejected",
                    "reason": reason,
                },
                "recovery": null,
            }),
            UserAutomationRuntimeError::IdentityConflict => serde_json::json!({
                "status": "known",
                "value": {
                    "accepted": false,
                    "outcome": "identity_conflict",
                },
                "recovery": null,
            }),
        }
    }

    async fn origin_challenge_issue_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: OriginChallengeIssueOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        validate_origin_session_fence(session, operation.request.state_fence())?;
        let (owner, _) =
            super::caller_binding(session).map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let gateway = self
            .process_gateway
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let view = gateway
            .inspect(&owner, operation.operation_id.clone())
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        validate_origin_inspection(&view, &operation.operation_id, &operation.request)?;
        let challenge = gateway
            .issue_origin_challenge(&operation.request, operation.expires_at_unix_ms)
            .map_err(|_| TransportError::SessionFenced)?;
        let challenge_value: serde_json::Value = serde_json::from_slice(
            &challenge
                .to_json_bytes()
                .map_err(|_| TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        Ok(serde_json::json!({
            "status": "known",
            "value": {
                "kind": "origin_challenge",
                "challenge": challenge_value,
            },
            "recovery": null,
        }))
    }

    async fn origin_control_decide_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: OriginControlDecideOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        let presentation_bytes = serde_json::to_vec(&operation.presentation)
            .map_err(|_| TransportError::SessionFenced)?;
        let presentation = OriginControlPresentation::from_json_bytes(&presentation_bytes)
            .map_err(|_| TransportError::SessionFenced)?;
        validate_origin_session_fence(session, presentation.request().state_fence())?;
        validate_origin_control_operation(presentation.request().operation())?;
        let (owner, _) =
            super::caller_binding(session).map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let gateway = self
            .process_gateway
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let view = gateway
            .inspect(&owner, operation.operation_id.clone())
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        validate_origin_inspection(&view, &operation.operation_id, presentation.request())?;
        let grant = gateway
            .decide_origin_control(&presentation)
            .map_err(|_| TransportError::SessionFenced)?;
        let cancelled = gateway
            .cancel_with_origin_grant(&owner, operation.operation_id, &grant)
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(serde_json::json!({
            "status": "known",
            "value": {
                "kind": "origin_control_kill",
                "grant": grant,
                "cancelled": cancelled,
            },
            "recovery": null,
        }))
    }

    fn generation_registry_active_query_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let query: ActiveGenerationRegistryQuery =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        let projection = self
            .active_generation_registry_query(&query, &session.module_generation.state_fence)
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(Self::generation_registry_projection_response(&projection))
    }

    fn generation_registry_projection_response(
        projection: &ActiveGenerationRegistryProjection,
    ) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": projection.response(),
            "recovery": null,
        })
    }

    /// Consumes the authenticated Governor startup receipt without importing
    /// the bin-owned `CapabilityOutcome`. The carrier is only a mechanical
    /// evidence boundary: missing canonical Policy/R2 semantic owner reads
    /// leave steps 8/9 absent and never become a local success default.
    fn daemon_startup_evidence_operation(
        &self,
        session: &Session,
        request_id: &RequestId,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let evidence = parse_startup_evidence(payload)?;

        let session_fence = &session.module_generation.state_fence;
        let binding = &evidence.transport_binding;
        if evidence.state_fence != *session_fence
            || binding.request.state_fence != *session_fence
            || &binding.request.metadata.request_id != request_id
            || binding.request.metadata.product_id.as_str() != ACTIVE_DAEMON_CALLER
            || binding.request.metadata.source_id.as_str() != ACTIVE_DAEMON_CALLER
        {
            return Err(TransportError::SessionFenced);
        }

        let projection = self
            .active_generation_registry_projection("daemon")
            .map_err(|_| TransportError::SessionFenced)?;
        if projection.state_fence() != session_fence {
            return Err(TransportError::SessionFenced);
        }

        self.validate_daemon_config_mirror(&evidence.config_mirror_digest)?;
        let capabilities_complete = match (
            &evidence.required_capabilities,
            &evidence.capability_outcomes,
            &evidence.capability_registry_digest,
        ) {
            (None, None, None) => false,
            (Some(required), Some(outcomes), Some(registry)) => {
                Self::validate_daemon_capability_evidence(
                    required,
                    outcomes,
                    registry,
                    projection.generation_fingerprint(),
                )?;
                true
            }
            _ => return Err(TransportError::SessionFenced),
        };

        // There is no Kernel-owned PolicyOwnerSnapshot or Governor semantic
        // eligibility result in this checkout. A present self-reported policy
        // digest is therefore still insufficient for step 8; the active R1
        // owner must supply the authenticated canonical read before these
        // steps can advance. Likewise, mechanical R4/capability checks do not
        // replace the Governor's R2/R3 attestation for step 9.
        let reason = if evidence.policy_mirror_digest.is_none() {
            "policy_owner_snapshot_absent"
        } else if !capabilities_complete {
            "required_capability_owner_snapshot_absent"
        } else {
            "governor_semantic_attestation_unavailable"
        };
        Ok(Self::incomplete_startup_evidence_response(reason))
    }

    fn validate_daemon_config_mirror(
        &self,
        config_mirror_digest: &PlatformHandle,
    ) -> Result<(), TransportError> {
        let policy = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let protected_snapshot_digest = policy
            .config_snapshot
            .get("protected_snapshot_digest")
            .and_then(serde_json::Value::as_str)
            .filter(|digest| !digest.trim().is_empty())
            .ok_or(TransportError::SessionFenced)?;
        if protected_snapshot_digest != config_mirror_digest.as_str() {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    fn validate_daemon_capability_evidence(
        required: &[String],
        outcomes: &[serde_json::Value],
        registry: &str,
        expected_generation_fingerprint: &str,
    ) -> Result<(), TransportError> {
        let mut required_names = BTreeSet::new();
        for name in required {
            if name.trim().is_empty() || !required_names.insert(name.as_str()) {
                return Err(TransportError::SessionFenced);
            }
        }
        let mut observed_names = BTreeSet::new();
        for outcome in outcomes {
            let object = outcome.as_object().ok_or(TransportError::SessionFenced)?;
            let capability = object
                .get("capability")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or(TransportError::SessionFenced)?;
            let fingerprint = object
                .get("generation_fingerprint")
                .and_then(serde_json::Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .ok_or(TransportError::SessionFenced)?;
            if fingerprint != expected_generation_fingerprint {
                return Err(TransportError::SessionFenced);
            }
            observed_names.insert(capability);
        }
        if !required_names.is_subset(&observed_names)
            || daemon_capability_registry_digest(outcomes)? != registry
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    fn incomplete_startup_evidence_response(reason: &'static str) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": {
                "accepted": false,
                "recorded": false,
                "steps_recorded": [],
                "reason": reason,
            },
            "recovery": null,
        })
    }

    fn expired_activation_daemon_response() -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": { "accepted": false, "expired": true },
            "recovery": null,
        })
    }

    /// Typed outcome for a stale local-read submit: a late, duplicate, or
    /// revoked attempt quarantined as a noncanonical observation.
    ///
    /// Carries the audit receipt (operation, presented/current generation,
    /// stable reason code) so the caller can distinguish replacement from
    /// revocation without parsing error strings; the waiter never observes
    /// the stale result.
    fn stale_attempt_daemon_response(
        observation: &host_request_route::StaleLocalReadObservation,
    ) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": {
                "accepted": false,
                "stale": true,
                "reason": observation.reason.as_str(),
                "operation_id": observation.operation_id,
                "presented_generation": observation.presented_generation,
                "current_generation": observation.current_generation,
            },
            "recovery": null,
        })
    }

    /// Typed acknowledgement for a v2 semantic-result submit: the exact
    /// retained result (with its full disposition) travels inside `ack`, so
    /// the daemon leg stays lossless without parsing error strings.
    fn activation_result_daemon_response(ack: &AgentActivationResultAck) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": { "accepted": true, "ack": ack },
            "recovery": null,
        })
    }

    /// Typed answer for a lost-acknowledgement reconcile query, served from
    /// retention only. `ack` carries outcome `Reconciled` with the retained
    /// result, or `Unknown` when nothing is retained for the ticket.
    fn reconciled_activation_daemon_response(ack: &AgentActivationResultAck) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": { "ack": ack },
            "recovery": null,
        })
    }

    #[cfg(windows)]
    async fn store_recovery_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: StoreRecoveryOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.request.validate() {
            return Ok(Self::store_error_response_text(
                "store_recovery",
                &error.to_string(),
            ));
        }
        validate_store_session_fence(session, &operation.request.state_fence)?;
        let gateway = self.retained_store_gateway()?;
        match gateway.recovery(operation.request).await {
            Ok(snapshot) => Ok(store_recovery_response(&snapshot)),
            Err(error) => Ok(Self::store_error_response_text("store_recovery", &error)),
        }
    }

    #[cfg(not(windows))]
    async fn store_recovery_operation(
        &self,
        _session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    #[cfg(windows)]
    async fn store_initialize_genesis_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: StoreInitializeGenesisOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        operation
            .context
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.request.validate_for_context(&operation.context) {
            return Ok(Self::store_error_response_text(
                "store_initialize_genesis",
                &error.to_string(),
            ));
        }
        validate_store_session_fence(session, &operation.context.state_fence)?;
        if operation.request.state_fence != operation.context.state_fence {
            return Err(TransportError::SessionFenced);
        }
        let gateway = self.retained_store_gateway()?;
        match gateway
            .initialize_genesis(&operation.context, operation.request)
            .await
        {
            Ok(receipt) => Ok(store_genesis_response(&receipt)),
            Err(error) => Ok(Self::store_error_response_text(
                "store_initialize_genesis",
                &error,
            )),
        }
    }

    #[cfg(not(windows))]
    async fn store_initialize_genesis_operation(
        &self,
        _session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the authenticated store admission path retains the complete prepared-transition and source-publication checks"
    )]
    async fn store_apply_operation(
        &self,
        session: &Session,
        request_id: RequestId,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: StoreApplyOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        if operation.context.request_id != request_id {
            return Err(TransportError::SessionFenced);
        }
        operation
            .context
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.transition.validate() {
            return Ok(Self::store_error_response_text(
                "write_receipt",
                &error.to_string(),
            ));
        }
        validate_store_session_fence(session, &operation.context.state_fence)?;
        if operation.transition.state_fence != operation.context.state_fence {
            return Err(TransportError::SessionFenced);
        }
        for head in &operation.expected_revision_heads {
            if let Err(error) = head.validate() {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    &error.to_string(),
                ));
            }
            if head.state_fence != operation.context.state_fence {
                return Err(TransportError::SessionFenced);
            }
        }
        for head in &operation.expected_ordering_heads {
            if let Err(error) = head.validate() {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    &error.to_string(),
                ));
            }
            if head.state_fence != operation.context.state_fence {
                return Err(TransportError::SessionFenced);
            }
        }
        // RECHECK-63 slice B: recompute the canonical request hash from the
        // exact values about to be executed (context + transition + expected
        // heads) and reject divergence before the gateway call. The view is
        // built from these references — not re-forwarded copies — so a
        // mutation after admission fails here with the typed mismatch,
        // rendered through the existing store-error response shape.
        {
            let view = CanonicalRequestView::from_apply(
                &operation.context,
                &operation.transition,
                &operation.expected_revision_heads,
                &operation.expected_ordering_heads,
            );
            if let Err(error) = verify_canonical_request_hash(
                &view,
                &operation.transition.identity.canonical_request_hash,
            ) {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    &error.to_string(),
                ));
            }
        }
        if let Some(rejection) = self.normal_write_admission_response() {
            return Ok(rejection);
        }
        let campaign_source_publications = match campaign_source_publications_for_transition(
            &operation.transition,
            &operation.context.request_id,
        ) {
            Ok(publications) => publications,
            Err(error) => {
                return Ok(Self::store_error_response_text("write_receipt", &error));
            }
        };
        let campaign_source_operation_id = operation.transition.identity.operation_id.clone();
        let campaign_source_request_digest =
            operation.transition.identity.canonical_request_hash.clone();
        if !campaign_source_publications.is_empty()
            && let Err(error) = self.p07_ors.reserve_campaign_source_publications(
                &campaign_source_operation_id,
                &campaign_source_request_digest,
                &campaign_source_publications,
            )
        {
            return Ok(Self::store_error_response_text(
                "write_receipt",
                &error.to_string(),
            ));
        }
        let gateway = self.retained_store_gateway()?;
        match gateway
            .apply(
                &operation.context,
                operation.transition,
                operation.expected_revision_heads,
                operation.expected_ordering_heads,
            )
            .await
        {
            Ok(receipt) => {
                if !campaign_source_publications.is_empty() {
                    if receipt.status == WriteReceiptStatus::Committed {
                        if let Err(error) = self.p07_ors.commit_campaign_source_publications(
                            &campaign_source_operation_id,
                            &campaign_source_request_digest,
                            &campaign_source_publications,
                            &receipt,
                        ) {
                            // Keep the source reservation. An exact replay of
                            // this same canonical operation obtains the
                            // durable receipt and completes ORS reconciliation.
                            return Ok(Self::store_error_response_text(
                                "write_receipt",
                                &error.to_string(),
                            ));
                        }
                    } else if let Err(error) = self.p07_ors.abort_campaign_source_publications(
                        &campaign_source_operation_id,
                        &campaign_source_request_digest,
                        &campaign_source_publications,
                    ) {
                        return Ok(Self::store_error_response_text(
                            "write_receipt",
                            &error.to_string(),
                        ));
                    }
                }
                Ok(store_apply_response(&receipt))
            }
            Err(error) => Ok(Self::store_error_response_text("write_receipt", &error)),
        }
    }

    #[cfg(not(windows))]
    async fn store_apply_operation(
        &self,
        _session: &Session,
        _request_id: RequestId,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed named-read route keeps fence, catalogue, and owner-source admission together"
    )]
    async fn store_named_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: StoreNamedOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.request.validate() {
            return Ok(Self::store_error_response_text(
                "store_named",
                &error.to_string(),
            ));
        }
        validate_store_session_fence(session, &operation.request.state_fence)?;
        if operation.request.operation == NamedReadOperation::GetCampaignLearningStateView {
            let lookup: CampaignLearningStateViewLookup = operation
                .request
                .parameters
                .get("lookup")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
                .ok_or(TransportError::SessionFenced)?;
            lookup
                .validate()
                .map_err(|_| TransportError::SessionFenced)?;
            if operation
                .request
                .scope_id
                .as_ref()
                .map(eliot_store_api::ScopeId::as_str)
                != Some(lookup.scope_id.as_str())
            {
                return Err(TransportError::SessionFenced);
            }
            let read = match self
                .p07_ors
                .load_campaign_learning_state_view(&lookup.view_id)
            {
                Ok(Some(publication))
                    if publication.task_id == lookup.task_id
                        && publication.scope_id == lookup.scope_id =>
                {
                    CampaignLearningStateViewRead {
                        status: CampaignLearningStateViewReadStatus::Current,
                        publication: Some(publication),
                        read_state_fence: operation.request.state_fence.clone(),
                    }
                }
                Ok(Some(_) | None) => CampaignLearningStateViewRead {
                    status: CampaignLearningStateViewReadStatus::Missing,
                    publication: None,
                    read_state_fence: operation.request.state_fence.clone(),
                },
                Err(error) => {
                    return Ok(Self::store_error_response_text(
                        "store_named",
                        &error.to_string(),
                    ));
                }
            };
            read.validate().map_err(|_| TransportError::SessionFenced)?;
            let response = NamedReadResponse {
                operation: NamedReadOperation::GetCampaignLearningStateView,
                state_fence: operation.request.state_fence,
                revision_heads: Vec::new(),
                payload: serde_json::json!({"campaign_learning_state_view": read}),
            };
            return Ok(store_named_response(&response));
        }
        if operation.request.operation == NamedReadOperation::GetCampaignSourceRevision {
            if operation.request.scope_id.is_none() {
                return Err(TransportError::SessionFenced);
            }
            let lookup: CampaignSourceRevisionLookup = operation
                .request
                .parameters
                .get("lookup")
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok())
                .ok_or(TransportError::SessionFenced)?;
            lookup
                .validate()
                .map_err(|_| TransportError::SessionFenced)?;
            let read = self
                .p07_ors
                .load_campaign_source_revision(&lookup, &operation.request.state_fence)
                .map_err(|_| TransportError::SessionFenced)?;
            if let Some(source) = &read.source
                && source.document.schema
                    == eliot_store_api::CampaignSourceDocumentSchema::LearningStateViewRecipe
            {
                let recipe_scope = source
                    .document
                    .body
                    .pointer("/binding/scope_id")
                    .and_then(serde_json::Value::as_str);
                if recipe_scope
                    != operation
                        .request
                        .scope_id
                        .as_ref()
                        .map(eliot_store_api::ScopeId::as_str)
                {
                    return Err(TransportError::SessionFenced);
                }
            }
            read.validate().map_err(|_| TransportError::SessionFenced)?;
            let response = NamedReadResponse {
                operation: NamedReadOperation::GetCampaignSourceRevision,
                state_fence: operation.request.state_fence,
                revision_heads: Vec::new(),
                payload: serde_json::json!({"campaign_source_revision": read}),
            };
            return Ok(store_named_response(&response));
        }
        // Authority-history reads are Kernel-owned fence state (`#2100`):
        // serve durable closure-fence history from the retained ORS instead
        // of forwarding to the store bridge. The store catalogue truthfully
        // still lists the operation unsupported because the store never
        // serves it; every other named read forwards unchanged below. The
        // live session fence binds the served view: the projector refuses
        // a request fence that disagrees with it.
        if operation.request.operation
            == eliot_store_api::NamedReadOperation::GetAuthorityRevocationHistory
        {
            return match eliot_kernel_service::serve_authority_revocation_history(
                self.p07_ors.as_ref(),
                &operation.request,
                &session.module_generation.state_fence,
            ) {
                Ok(response) => Ok(store_named_response(&response)),
                Err(error) => Ok(Self::store_error_response_text(
                    "store_named",
                    &error.to_string(),
                )),
            };
        }
        let gateway = self.retained_store_gateway()?;
        match gateway.execute_named(operation.request).await {
            Ok(response) => Ok(store_named_response(&response)),
            Err(error) => Ok(Self::store_error_response_text("store_named", &error)),
        }
    }

    #[cfg(not(windows))]
    async fn store_named_operation(
        &self,
        _session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    /// Executes one closed local read for an admitted query or campaign packet.
    ///
    /// The `local_read` kind is the authenticated dispatch sibling of
    /// `store_named` on the same authenticated daemon session: no new
    /// transport, pipe, or listener. Rejection happens before reading —
    /// linkage plus closed selectors are proven (pure, no IO), then the full
    /// admission gate runs, then an exact replay of a resulted operation
    /// serves its stored bounded body without re-dispatch and without Gateway
    /// IO, then the presented attempt capability is proven current against
    /// the live claim record before any Gateway IO. Only a fresh admitted
    /// query with a current attempt reaches the Gateway, over the admitted
    /// fence with the explicit scope, exact subject, and catalogue-bound
    /// `max_records`; the bounded answer is projected through the MCP
    /// evidence-pack projection and completed through the shared submit gate
    /// ([`KernelComposition::submit_local_read_result`]), so the sync leg can
    /// never bypass attempt ownership: persistence, exact-replay, conflict,
    /// expiry, fence, and staleness joins are identical to the async submit
    /// leg. A stale attempt fails closed here (never a bound result);
    /// `eliot.packet` pairs are admitted, queued, and claimed through the
    /// same attempt-bound lifecycle; the daemon campaign compiler performs
    /// their owner reads and result construction before the shared submit
    /// leg.
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the closed local-read leg keeps linkage, admission, replay, gateway, projection, and persistence joins in one audited order"
    )]
    async fn local_read_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        // Closed decode first: unknown fields never reach the read leg, and a
        // read without the Kernel-issued attempt capability never decodes.
        let operation: LocalReadOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        let envelope = operation.envelope;
        let tool = operation.tool;
        let attempt = operation.attempt;
        attempt
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        // Rejection-before-reading: linkage plus closed selectors next. This
        // validation is pure, so a changed payload digest, a forged
        // descriptor, or a malformed selector never reaches Gateway IO.
        let admission = host_request_route::check_local_read_admission(&envelope, &tool)?;
        let (receipt, record) = self.admit_host_request_envelope(&envelope)?;
        if let Some(replayed) =
            host_request_route::local_read_replay_response(&receipt, &record, &envelope)?
        {
            return Ok(replayed);
        }
        let selectors = match admission {
            host_request_route::LocalReadAdmission::Query(selectors) => selectors,
            host_request_route::LocalReadAdmission::CampaignPacket { .. } => {
                // The packet compiler is a daemon-owned, task-bound step. A
                // direct synchronous local_read request still receives an
                // honest admission response and is queued for the production
                // poller; it never becomes a GetEvidencePack request.
                self.enqueue_local_read_pair(&envelope, &tool)?;
                return Ok(host_request_route::host_request_admitted_response(
                    &receipt, &record,
                ));
            }
        };
        // No bypass: the presented attempt must be the live claim-record
        // attempt owned by the presenting session before any Gateway IO. A
        // replaced, retired, or revoked attempt fails closed here. Full
        // capability equality proves every echoed field is exactly what the
        // Kernel minted for this envelope; a substituted echo fails closed.
        let operation_id = host_request_operation_id(&envelope);
        let live = self.live_local_read_attempt(&operation_id, &envelope.envelope_sha256)?;
        let current = match live {
            Some(state)
                if state.attempt_id == attempt.attempt_id
                    && state.generation == attempt.fencing_generation
                    && state.is_owned_by(session) =>
            {
                state
            }
            _ => return Err(TransportError::SessionFenced),
        };
        if attempt != self.local_read_attempt_capability(&envelope, &operation_id, &current)? {
            return Err(TransportError::SessionFenced);
        }
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "subject".to_owned(),
            serde_json::Value::String(selectors.subject.clone()),
        );
        parameters.insert(
            "max_records".to_owned(),
            serde_json::Value::String(selectors.max_records.to_string()),
        );
        let read = NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(selectors.scope_id.clone()),
            consistency: ReadConsistency::Eventual,
            state_fence: envelope.state_fence.clone(),
            parameters,
        };
        if let Err(error) = check_local_read_request(&read) {
            return Ok(Self::store_error_response_text("local_read", &error));
        }
        validate_store_session_fence(session, &read.state_fence)?;
        let gateway = self.retained_store_gateway()?;
        let response = match gateway.execute_named(read).await {
            Ok(response) => response,
            Err(error) => return Ok(Self::store_error_response_text("local_read", &error)),
        };
        if response.operation != NamedReadOperation::GetEvidencePack {
            return Ok(Self::store_error_response_text(
                "local_read",
                "named-read operation does not match request",
            ));
        }
        let (digest, body) = AuthenticatedHostSession::build_local_read_result_body(
            &envelope,
            selectors.scope_id.as_str(),
            &selectors.subject,
            selectors.max_records,
            &selectors.intent_mode,
            response.payload,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        // The sync leg completes through the shared submit gate, never
        // through a private persist: attempt currency, deadline, fence, and
        // staleness joins are identical to the async submit leg. A concurrent
        // invalidation between the pre-check above and this commit surfaces
        // as stale and fails closed; only the current attempt persists.
        let submission = HostRequestResultBody {
            wire_id: eliot_protocol::HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
            wire_version: HostRequestResultBody::CONTRACT_VERSION,
            operation_id: operation_id.clone(),
            request_sha256: envelope.envelope_sha256.clone(),
            result_digest: digest,
            response: body,
            attempt: Some(attempt),
        };
        submission
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let resulted = match self.submit_local_read_result(session, &submission)? {
            host_request_route::LocalReadSubmitDisposition::Persisted(record) => record,
            host_request_route::LocalReadSubmitDisposition::StaleAttempt(_) => {
                return Err(TransportError::SessionFenced);
            }
        };
        if host_request_route::local_read_replay_response(&receipt, &resulted, &envelope)?.is_none()
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(host_request_route::host_request_admitted_response(
            &receipt, &resulted,
        ))
    }

    #[cfg(not(windows))]
    async fn local_read_operation(
        &self,
        _session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let _ = payload;
        Err(TransportError::SessionFenced)
    }

    /// Publishes one owner-side WASM dispatch bundle on the admitted path
    /// (`#1780` D4a, `#1955`): the production caller of
    /// `eliot_kernel_service::publish_wasm_dispatch_bundle`.
    ///
    /// The `WasmOwnerClaim` is built from admitted owner material carried in
    /// the closed payload; guest/input digests re-hash against those exact
    /// bytes inside the publisher. Host facts arrive as presented evidence
    /// and are proven here, not trusted: the path must be absolute and name
    /// the installer-pinned image, and the real file bytes must re-hash to
    /// the presented digest. (`eliot-installation` is not a dependency of
    /// this composition root, so the validated
    /// `wasm_host_artifact_binding()` accessor cannot be called here; the
    /// path pin plus byte re-hash is the fail-closed equivalent — the same
    /// proof the P03 executor repeats at launch.) The install directory is
    /// the host path's parent, never a caller string. Publication requires
    /// a fence-bound session on a Ready, unfenced Kernel; the claim and its
    /// snapshot must speak for this session's authority at this generation.
    /// The computed one-shot join gate is projected into the receipt so the
    /// live join table can close over it; no second registry is retained
    /// here.
    #[allow(
        clippy::too_many_lines,
        reason = "the admitted-path bundle publication keeps decode, fence/ready/claim/snapshot gates, host re-hash, publish, and receipt projection in one audited order"
    )]
    fn wasm_dispatch_bundle_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: WasmDispatchBundleOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        // Guest byte vectors must each fit one transport frame
        // (`eliot_protocol::MAX_FRAME_BYTES`): anything larger could not
        // have arrived intact, and unbounded staging buffers are refused.
        if operation.artifact_bytes.is_empty()
            || operation.input_bytes.is_empty()
            || operation.artifact_bytes.len() > eliot_protocol::MAX_FRAME_BYTES
            || operation.input_bytes.len() > eliot_protocol::MAX_FRAME_BYTES
        {
            return Err(TransportError::SessionFenced);
        }
        // Live session fence first: the presenting session must itself be
        // exactly fence-bound before any owner material is honored.
        validate_store_session_fence(session, &session.module_generation.state_fence)?;
        // Ready/unfenced Kernel admission: publication is normal work, never
        // fenced-drive output.
        {
            let service = self
                .service
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            if service.state() != KernelServiceState::Ready || service.generation_fenced() {
                return Err(TransportError::SessionFenced);
            }
        }
        // Claim-to-session binding: admitted owner material must describe
        // authority this session fences, at this generation.
        if !operation
            .authority_epoch
            .is_same_authority(&session.authority_epoch)
            || operation.generation != session.module_generation.generation.value()
            || operation.generation == 0
        {
            return Err(TransportError::SessionFenced);
        }
        // Snapshot-to-claim binding: the owner-attested snapshot must speak
        // for the same authority and generation the grant funds. (Record
        // shape is the publisher's; the child re-derives every fence from
        // the grant.)
        if !operation
            .snapshot
            .authority_epoch
            .is_same_authority(&operation.authority_epoch)
            || operation.snapshot.generation != operation.generation
        {
            return Err(TransportError::SessionFenced);
        }
        let host_executable_path = operation.host_executable_path.clone();
        let host_artifact_digest = operation.host_artifact_digest.clone();
        // Installation-observed host binding: absolute path, canonical image
        // name (the installer's pin), then re-hash of the real file bytes
        // against the presented digest. A missing, renamed, or re-written
        // image fails closed here, never inside the publisher.
        let host_path = std::path::Path::new(host_executable_path.as_str());
        if !host_path.is_absolute()
            || host_path.file_name().and_then(|name| name.to_str())
                != Some(WASM_HOST_IMAGE_FILE_NAME)
        {
            return Err(TransportError::SessionFenced);
        }
        let install_dir = host_path.parent().ok_or(TransportError::SessionFenced)?;
        let observed_host_bytes =
            std::fs::read(host_path).map_err(|_| TransportError::SessionFenced)?;
        if sha256_hex(&observed_host_bytes) != host_artifact_digest {
            return Err(TransportError::SessionFenced);
        }
        let claim = eliot_kernel_service::WasmOwnerClaim {
            claim_id: operation.claim_id,
            operation_id: operation.operation_id,
            generation: operation.generation,
            authority_epoch: operation.authority_epoch,
            launch_nonce: operation.launch_nonce,
            admitted_at_unix_ms: operation.admitted_at_unix_ms,
            identity_digest: operation.identity_digest,
            guest: operation.guest,
            profile: operation.profile,
            manifest: operation.manifest,
            work: operation.work,
            assurance: operation.assurance,
            promotion: operation.promotion,
            snapshot: operation.snapshot,
            prior_conformance_artifact: operation.prior_conformance_artifact,
            artifact_bytes: operation.artifact_bytes,
            input_bytes: operation.input_bytes,
        };
        let mut joins = eliot_kernel_service::WasmJoinTable::default();
        let bundle = eliot_kernel_service::publish_wasm_dispatch_bundle(
            host_executable_path.as_str(),
            host_artifact_digest.as_str(),
            install_dir,
            &claim,
            &mut joins,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let material_digest = sha256_hex(
            &eliot_kernel_service::material_bytes(&bundle.material)
                .map_err(|_| TransportError::SessionFenced)?,
        );
        Ok(serde_json::json!({
            "kind": "wasm_dispatch_bundle_receipt",
            "value": {
                "claim_id": bundle.material.claim_id,
                "operation_id": bundle.material.operation_id,
                "grant_digest": bundle.material.grant.grant_digest,
                "invocation_digest": bundle.join.invocation_digest,
                "expires_at": bundle.join.expires_at,
                "material_digest": material_digest,
                "material_path": bundle.material_path.to_string_lossy(),
                "artifact_path": bundle.artifact_path.to_string_lossy(),
                "input_path": bundle.input_path.to_string_lossy(),
            },
        }))
    }

    /// Binds one normal Notify launch grant on the admitted path (`#1780`
    /// D4b): the production caller of
    /// `eliot_kernel_service::bind_notify_launch_grant`, the
    /// minter-to-durable-state + `ApprovedLaunch` invocation.
    ///
    /// The canonical notification reference and the installer-observed
    /// launch artifact arrive as closed payload evidence; the artifact
    /// digest is proven here by re-hashing the real installed bytes (the
    /// binder checks shape, this dispatch proves bytes). The grant never
    /// binds to a merely presented reference: the durable canonical record
    /// is read back from the retained store by `notification_id` first under
    /// the live session fence — the minter-to-durable-state join. A missing
    /// record, a fence disagreement, or an unavailable store fails closed
    /// before binding. The presented `notification_digest` stays opaque here
    /// (shape-checked by the binder; no digest derivation is specified in
    /// `notify_grant.rs`, so this dispatch never invents one). Session evidence
    /// is threaded from the live authenticated session — connection, exact
    /// epoch, exact fence — never from the payload. Ready state, unfenced
    /// generation, and exact epoch/fence currency are enforced inside the
    /// binder; any denial fails closed here.
    #[allow(
        clippy::too_many_lines,
        reason = "the admitted-path notify grant keeps decode, fence gate, artifact re-hash, session threading, bind, and receipt projection in one audited order"
    )]
    async fn notify_launch_grant_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: NotifyLaunchGrantOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        validate_store_session_fence(session, &session.module_generation.state_fence)?;
        // Installer-observed launch artifact first: absolute path plus the
        // canonical image name (re-checked by the binder), then re-hash of
        // the real installed bytes against the presented digest.
        let executable_path = std::path::Path::new(operation.executable_path.as_str());
        if !executable_path.is_absolute()
            || executable_path.file_name().and_then(|name| name.to_str())
                != Some(eliot_kernel_service::NOTIFY_IMAGE_FILE_NAME)
        {
            return Err(TransportError::SessionFenced);
        }
        let observed_bytes =
            std::fs::read(executable_path).map_err(|_| TransportError::SessionFenced)?;
        if sha256_hex(&observed_bytes) != operation.artifact_digest {
            return Err(TransportError::SessionFenced);
        }
        // Minter-to-durable-state join: the grant binds only to a persisted
        // canonical record read back under the session fence. This is a
        // read-only existence/digest proof — canonical writes stay on the
        // `eliotd` admission path, never in this composition root.
        self.require_durable_notification_record(
            session,
            operation.notification_id.as_str(),
            operation.notification_digest.as_str(),
        )
        .await?;
        // Session evidence threaded from the live authenticated session.
        // `SessionBinding` lives in `eliot-receipts` (no direct dependency
        // edge from this composition root under single-file ownership); its
        // `Deserialize` impl plus struct-field inference carries the exact
        // evidence type — connection, epoch, fence — without a new
        // dependency or a caller-asserted session.
        let session_evidence = serde_json::json!({
            "session_id": &session.connection_id,
            "authority_epoch": &session.authority_epoch,
            "state_fence": &session.module_generation.state_fence,
        });
        let session_binding =
            serde_json::from_value(session_evidence).map_err(|_| TransportError::SessionFenced)?;
        let inputs = eliot_kernel_service::NotifyGrantInputs {
            notification_id: operation.notification_id,
            notification_digest: operation.notification_digest,
            executable_path: operation.executable_path,
            artifact_digest: operation.artifact_digest,
            session: session_binding,
        };
        let service = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let authorization = eliot_kernel_service::bind_notify_launch_grant(&service, &inputs)
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(serde_json::json!({
            "kind": "notify_launch_grant",
            "value": {
                "operation_id": authorization.operation_id(),
                "notification_id": authorization.notification_id(),
                "notification_digest": authorization.notification_digest(),
                "executable_path": authorization.executable_path(),
                "artifact_digest": authorization.artifact_digest(),
                "generation": authorization.generation().value(),
                "authority_epoch": authorization.authority_epoch(),
                "state_fence": authorization.state_fence(),
            },
        }))
    }

    /// Proves the presented notification reference against durable canonical
    /// state before a Notify launch grant binds (`#1780` W2).
    ///
    /// Reads back the canonical `GetNotificationState` projection for
    /// `notification_id` through the retained store gateway under the live
    /// session fence, then requires one same-fence record with that exact
    /// identity. An unavailable store, a failed read, a missing record, or a
    /// fence disagreement fails closed. The presented digest is intentionally
    /// opaque here (no derivation is specified; shape is enforced by the
    /// binder). This performs no canonical write: record creation stays on
    /// the owning admission path; the grant only proceeds when the record
    /// already persists.
    #[cfg(windows)]
    async fn require_durable_notification_record(
        &self,
        session: &Session,
        notification_id: &str,
        _notification_digest: &str,
    ) -> Result<(), TransportError> {
        let fence = session.module_generation.state_fence.clone();
        let query = eliot_store_api::notification_read_request(
            None,
            None,
            Some(notification_id.to_owned()),
            true,
            1,
            None,
            fence.clone(),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let gateway = self.retained_store_gateway()?;
        let response = gateway
            .execute_named(query)
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        if response.operation != eliot_store_api::NamedReadOperation::GetNotificationState
            || response.state_fence != fence
        {
            return Err(TransportError::SessionFenced);
        }
        let records = response
            .payload
            .get("records")
            .and_then(serde_json::Value::as_array)
            .ok_or(TransportError::SessionFenced)?;
        let record = records
            .iter()
            .find(|value| {
                value
                    .get("notification_id")
                    .and_then(serde_json::Value::as_str)
                    == Some(notification_id)
            })
            .ok_or(TransportError::SessionFenced)?;
        let record_fence: StateFence = serde_json::from_value(
            record
                .get("state_fence")
                .cloned()
                .ok_or(TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        if record_fence != fence {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// No durable notification state exists off Windows: the retained store
    /// gateway is a Windows-only contour, so the minter-to-durable-state
    /// join is unprovable here and the grant fails closed.
    #[cfg(not(windows))]
    async fn require_durable_notification_record(
        &self,
        _session: &Session,
        _notification_id: &str,
        _notification_digest: &str,
    ) -> Result<(), TransportError> {
        Err(TransportError::SessionFenced)
    }

    #[cfg(windows)]
    fn retained_store_gateway(&self) -> Result<Arc<KernelStoreGateway>, TransportError> {
        self.canonical_store_gateway
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .clone()
            .ok_or(TransportError::SessionFenced)
    }

    /// Returns the existing store-error projection when startup has not
    /// admitted normal canonical writes. This is deliberately kept directly
    /// before the retained gateway call in `apply_prepared`, so a fenced
    /// request cannot enter the Store backend.
    fn normal_write_admission_response(&self) -> Option<serde_json::Value> {
        self.admit_normal_write()
            .err()
            .map(|error| Self::store_error_response_text("write_receipt", &error.to_string()))
    }

    fn store_error_response_text(kind: &str, error: &str) -> serde_json::Value {
        let status = if error == StoreError::MissingReceiptEnvelope.to_string() {
            "unknown"
        } else {
            "error"
        };
        serde_json::json!({
            "status": status,
            "value": { "kind": kind, "value": null },
            "recovery": null,
        })
    }
}

#[cfg(windows)]
fn authenticated_user_automation_principal(session: &Session) -> Result<String, TransportError> {
    match &session.peer {
        PeerIdentity::Authenticated { user_identity, .. }
            if !user_identity.trim().is_empty() && !user_identity.chars().any(char::is_control) =>
        {
            Ok(user_identity.clone())
        }
        PeerIdentity::Authenticated { .. } => Err(TransportError::PeerIdentityUnavailable),
        PeerIdentity::Unavailable { .. } => Err(TransportError::PeerIdentityUnavailable),
    }
}

#[cfg(windows)]
async fn ensure_user_automation_run_now_receipt(
    gateway: &eliot_kernel_service::KernelStoreGateway,
    state_fence: &StateFence,
    identity: &OperationIdentity,
    invocation: &eliot_kernel_core::user_automation::UserAutomationInvocation,
) -> Result<eliot_store_api::WriteReceipt, UserAutomationRuntimeError> {
    let provenance = invocation
        .require_run_now_provenance(state_fence)
        .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
    if provenance.operation_id != identity.operation_id
        || provenance.idempotency_key != identity.idempotency_key
        || provenance.canonical_request_hash != identity.canonical_request_hash
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    ensure_user_automation_store_receipt(gateway, state_fence, identity).await
}

#[cfg(windows)]
async fn ensure_user_automation_store_receipt(
    gateway: &eliot_kernel_service::KernelStoreGateway,
    state_fence: &StateFence,
    identity: &OperationIdentity,
) -> Result<eliot_store_api::WriteReceipt, UserAutomationRuntimeError> {
    identity
        .validate()
        .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
    let receipt = gateway
        .receipt(state_fence, identity.operation_id.clone())
        .await
        .map_err(UserAutomationRuntimeError::Unavailable)?
        .ok_or_else(|| {
            UserAutomationRuntimeError::UnknownOutcome(
                "canonical UserAutomation Store receipt is not retained".to_owned(),
            )
        })?;
    receipt
        .validate()
        .map_err(|error| UserAutomationRuntimeError::Unavailable(error.to_string()))?;
    if receipt.operation_id != identity.operation_id
        || receipt.idempotency_key != identity.idempotency_key
        || receipt.canonical_request_hash != identity.canonical_request_hash
        || receipt.state_fence != *state_fence
    {
        return Err(UserAutomationRuntimeError::IdentityConflict);
    }
    if receipt.status != eliot_store_api::WriteReceiptStatus::Committed {
        return Err(UserAutomationRuntimeError::Rejected(
            "canonical UserAutomation Store operation is not committed".to_owned(),
        ));
    }
    receipt
        .require_reconciliation_envelope()
        .map_err(|error| UserAutomationRuntimeError::UnknownOutcome(error.to_string()))?;
    Ok(receipt)
}

#[cfg(windows)]
fn validate_user_automation_trigger_text(
    value: &str,
    field: &'static str,
) -> Result<(), TransportError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) || value.len() > 256 {
        return Err(TransportError::SessionFenced);
    }
    let _ = field;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn apply_prepared_admission_rejects_before_backend_entry() {
        let root = std::env::temp_dir().join(format!(
            "eliot-kernel-apply-prepared-gate-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test work root");
        let kernel = KernelComposition::new(KernelConfig::new(&root)).expect("kernel composition");
        let mut backend_called = false;
        let response = if let Some(response) = kernel.normal_write_admission_response() {
            response
        } else {
            backend_called = true;
            serde_json::Value::Null
        };

        assert!(
            !backend_called,
            "startup gate must fence before Store entry"
        );
        assert_eq!(response["status"], "error");
        assert_eq!(response["value"]["kind"], "write_receipt");
        assert_eq!(
            kernel
                .startup_status(GovernanceProfile::minimal())
                .blocking_prerequisite,
            Some("epoch-recovery")
        );

        drop(kernel);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn origin_selectors_are_trusted_and_effect_route_is_kill_only() {
        assert_eq!(
            trusted_daemon_operation("origin_challenge_issue"),
            "origin_challenge_issue"
        );
        assert_eq!(
            trusted_daemon_operation("origin_control_decide"),
            "origin_control_decide"
        );
        assert!(validate_origin_control_operation(OriginControlOperation::Kill).is_ok());
        for operation in [
            OriginControlOperation::Adopt,
            OriginControlOperation::Mutate,
            OriginControlOperation::AttachCredential,
        ] {
            assert!(
                validate_origin_control_operation(operation).is_err(),
                "unsupported origin effect must fail closed before executor entry"
            );
        }
    }
}

fn validate_origin_control_operation(
    operation: OriginControlOperation,
) -> Result<(), TransportError> {
    if operation == OriginControlOperation::Kill {
        Ok(())
    } else {
        Err(TransportError::SessionFenced)
    }
}

fn validate_origin_session_fence(
    session: &Session,
    fence: &StateFence,
) -> Result<(), TransportError> {
    fence
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if session.module_generation.state_fence != *fence
        || !session
            .authority_epoch
            .is_same_authority(&fence.authority_epoch)
        || session.module_generation.generation.value() != fence.resource_generation.value()
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn validate_origin_inspection(
    view: &ProcessExecutionView,
    operation_id: &OperationId,
    request: &OriginChallengeRequest,
) -> Result<(), TransportError> {
    if view.operation_id() != operation_id
        || view.lifecycle() != ProcessLifecycle::Running
        || !view
            .binding()
            .authority_epoch()
            .is_same_authority(&request.state_fence().authority_epoch)
        || view.binding().state_fence().generation().get() != request.generation().get()
    {
        return Err(TransportError::SessionFenced);
    }
    let identity = view.identity().ok_or(TransportError::SessionFenced)?;
    if identity.generation() != request.generation() || identity.physical() != request.physical() {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn validate_store_session_fence(
    session: &Session,
    state_fence: &StateFence,
) -> Result<(), TransportError> {
    state_fence
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    if !session
        .authority_epoch
        .is_same_authority(&state_fence.authority_epoch)
        || session.module_generation.generation != state_fence.resource_generation
        || session.module_generation.state_fence != *state_fence
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn store_recovery_response(snapshot: &StoreRecoverySnapshot) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "store_recovery", "value": snapshot },
        "recovery": null,
    })
}

fn store_genesis_response(receipt: &WriteReceipt) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "store_initialize_genesis", "value": receipt },
        "recovery": null,
    })
}

fn store_apply_response(receipt: &WriteReceipt) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "write_receipt", "value": receipt },
        "recovery": null,
    })
}

/// Requires a local-read store request to be the closed evidence-pack read.
///
/// `local_read` is the `GetEvidencePack`-only sibling of `store_named`: any
/// other catalogue operation (including the packet projection-inputs read) is
/// refused here, so the packet path stays unavailable on this leg. Shape
/// validation is the Store-owned request check, unchanged and never weakened.
fn check_local_read_request(request: &NamedReadRequest) -> Result<(), String> {
    if request.operation != NamedReadOperation::GetEvidencePack {
        return Err(
            "local_read admits only GetEvidencePack; packet and position reads stay unavailable"
                .to_owned(),
        );
    }
    request.validate().map_err(|error| error.to_string())
}

fn store_named_response(response: &NamedReadResponse) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "store_named", "value": response },
        "recovery": null,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod store_named_dispatch_tests {
    use super::*;

    #[test]
    fn store_named_operation_rejects_unknown_fields_and_projects_typed_response() {
        let fence = StateFence::new(
            eliot_contracts::EpochId::new(
                eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("lineage"),
                std::num::NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            eliot_contracts::ResourceGeneration::genesis(),
        );
        let request = NamedReadRequest {
            operation: eliot_store_api::NamedReadOperation::GetEvidencePack,
            scope_id: None,
            consistency: eliot_store_api::ReadConsistency::ExactFence,
            state_fence: fence.clone(),
            parameters: std::collections::BTreeMap::new(),
        };
        let mut payload = serde_json::to_value(&request).expect("request encodes");
        if let serde_json::Value::Object(map) = &mut payload {
            map.insert("unknown_field".to_owned(), serde_json::Value::Null);
        }
        let rejected: Result<StoreNamedOperation, _> = serde_json::from_value(serde_json::json!({
            "request": payload,
        }));
        assert!(
            rejected.is_err(),
            "deny_unknown_fields must reject a widened named-read envelope"
        );

        let response = NamedReadResponse {
            operation: eliot_store_api::NamedReadOperation::GetEvidencePack,
            state_fence: fence,
            revision_heads: Vec::new(),
            payload: serde_json::json!({ "version": 1 }),
        };
        let projected = store_named_response(&response);
        assert_eq!(projected.get("status"), Some(&serde_json::json!("known")));
        assert_eq!(
            projected.get("value").and_then(|value| value.get("kind")),
            Some(&serde_json::json!("store_named"))
        );
        let expected = serde_json::to_value(&response).expect("response encodes");
        assert_eq!(
            projected.get("value").and_then(|value| value.get("value")),
            Some(&expected)
        );
        assert_eq!(projected.get("recovery"), Some(&serde_json::Value::Null));
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod local_read_dispatch_tests {
    use super::*;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn tool_digest(tool: &serde_json::Value) -> String {
        let bytes = eliot_contracts::canonical_json_bytes(tool).expect("tool must canonicalize");
        eliot_contracts::sha256_hex(&bytes)
    }

    fn query_tool() -> serde_json::Value {
        serde_json::json!({"name":"eliot.query","arguments":{
            "intent":{
                "mode":"verification",
                "time_scope":"session-window",
                "branch_environment_scope":"branch",
                "freshness_policy":"exact-fence",
                "required_assurance":"evidence-provenance"
            },
            "query":"subject:evidence-alpha",
            "exact_resource_uri": null
        }})
    }

    fn test_fence() -> StateFence {
        StateFence::new(
            eliot_contracts::EpochId::new(
                eliot_contracts::EpochLineageId::new(TEST_LINEAGE).expect("lineage"),
                std::num::NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            eliot_contracts::ResourceGeneration::genesis(),
        )
    }

    fn test_envelope(capability: &str, payload_sha256: &str) -> HostRequestEnvelope {
        eliot_protocol::HostRequestEnvelope {
            wire_id: eliot_protocol::HOST_REQUEST_WIRE_ID.to_owned(),
            wire_version: eliot_protocol::HostRequestEnvelope::CONTRACT_VERSION,
            kind: eliot_protocol::HostRequestKind::Invocation,
            connection_id: "conn-test-1".to_owned(),
            identity: eliot_protocol::HostRequestIdentity {
                request_id: eliot_contracts::RequestId::new("host-request-1")
                    .expect("valid request id"),
                idempotency_key: "host-request-1:invoke".to_owned(),
                cancellation_id: "host-request-1:invoke:cancel".to_owned(),
                parent_operation_id: None,
                deadline_unix_ms: 2_000_000,
                capability: capability.to_owned(),
                session_id: Some("kernel-session-1".to_owned()),
                task_id: None,
                work_scope_id: None,
                payload_schema_id: "eliot.mcp.tool-request.v1".to_owned(),
                payload_sha256: payload_sha256.to_owned(),
            },
            state_fence: test_fence(),
            descriptor_sha256: "d".repeat(64),
            peer_admission_receipt_sha256: "e".repeat(64),
            activation_binding: None,
            envelope_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("envelope must digest")
    }

    #[test]
    fn local_read_operation_rejects_unknown_fields() {
        let tool = query_tool();
        let envelope = test_envelope("eliot.query", &tool_digest(&tool));
        let operation_id = eliot_protocol::host_request_operation_id(&envelope);
        let authority_epoch = serde_json::to_value(envelope.state_fence.clone())
            .expect("fence encodes")["authority_epoch"]
            .clone();
        let attempt = serde_json::json!({
            "wire_id": eliot_protocol::LOCAL_READ_ATTEMPT_WIRE_ID,
            "wire_version": eliot_protocol::LocalReadAttempt::CONTRACT_VERSION,
            "operation_id": operation_id,
            "attempt_id": format!("{operation_id}:attempt:1:1:1"),
            "fencing_generation": 1,
            "session_id": "kernel-session-1",
            "authority_epoch": authority_epoch,
            "scope_id": "kernel-session-1",
            "facet_method": "eliot.query",
            "expires_at_unix_ms": 2_000_000,
            "use_budget": 1,
        });
        let valid = serde_json::json!({"envelope": envelope, "tool": tool, "attempt": attempt});
        let decoded: LocalReadOperation =
            serde_json::from_value(valid).expect("closed envelope+tool+attempt must decode");
        assert_eq!(decoded.tool, tool);
        assert_eq!(
            decoded.envelope.envelope_sha256, envelope.envelope_sha256,
            "the admitted digest rides the closed carrier"
        );
        assert_eq!(
            decoded.attempt.operation_id, operation_id,
            "the attempt binds the exact operation handle"
        );

        let widened = serde_json::json!({
            "envelope": envelope,
            "tool": tool,
            "attempt": attempt,
            "unknown_field": null,
        });
        assert!(
            serde_json::from_value::<LocalReadOperation>(widened).is_err(),
            "deny_unknown_fields must reject a widened local-read envelope"
        );

        // A read without the attempt capability never decodes: no bypass.
        let missing = serde_json::json!({
            "envelope": envelope,
            "tool": tool,
        });
        assert!(
            serde_json::from_value::<LocalReadOperation>(missing).is_err(),
            "a local-read call without the attempt capability must not decode"
        );
    }

    #[test]
    fn local_read_gate_admits_only_evidence_pack() {
        let parameters = BTreeMap::from([
            (
                "subject".to_owned(),
                serde_json::Value::String("evidence-alpha".to_owned()),
            ),
            (
                "max_records".to_owned(),
                serde_json::Value::String("10".to_owned()),
            ),
        ]);
        let read = NamedReadRequest {
            operation: NamedReadOperation::GetEvidencePack,
            scope_id: Some(eliot_store_api::ScopeId::new("scope-1").expect("valid test scope")),
            consistency: ReadConsistency::Eventual,
            state_fence: test_fence(),
            parameters,
        };
        assert!(
            check_local_read_request(&read).is_ok(),
            "the closed evidence-pack read must pass the gate"
        );

        // Any other catalogue operation — including the packet
        // projection-inputs read — stays unavailable on this leg.
        for operation in [
            NamedReadOperation::GetCurrentEpistemicPosition,
            NamedReadOperation::GetRevisionHeads,
            NamedReadOperation::GetUnderstandingProjectionInputs,
        ] {
            let mut other = read.clone();
            other.operation = operation;
            assert!(
                check_local_read_request(&other).is_err(),
                "non-evidence operations must be refused before any store work"
            );
        }
    }
}
