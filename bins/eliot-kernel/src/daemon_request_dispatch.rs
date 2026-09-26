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
    AuthenticatedUserAutomationHostExecutionTransport, UserAutomationDueWakeRejection,
    UserAutomationDueWakeResolution, UserAutomationDurableJobPort, UserAutomationHorizonOutcome,
    UserAutomationHorizonPhase, UserAutomationHorizonTrigger, UserAutomationHostExecutionClient,
    UserAutomationHostExecutionOperation, UserAutomationHostExecutionTransport,
    UserAutomationOwnerLookup, UserAutomationRuntimeAdmission, UserAutomationRuntimeError,
    UserAutomationWakeCancellation, UserAutomationWakeHorizonPublication, UserAutomationWakePort,
    UserAutomationWakePublication, UserAutomationWakeReadRequest, UserAutomationWakeReadback,
    advance_wake_horizon, horizon_retry_handle, refuse_consumed_wake, resolve_due_wake,
};
use eliot_process::{
    OperationId, OriginChallengeRequest, OriginControlOperation, OriginControlPresentation,
    ProcessExecutionView, ProcessLifecycle,
};
use eliot_protocol::{
    AgentActivationClaimRequest, HostRequestEnvelope, HostRequestResultBody, LocalReadAttempt,
    RequestIdentity, TaskControllerResultBody, host_request_operation_id,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    DaemonChannelCursor, DaemonProgressObservation, DaemonSupervisionRenewalDecision,
    DaemonSupervisionRenewalReceipt, SupervisionLeasePredecessorProof,
};
use eliot_store_api::{
    CampaignLearningStateViewLookup, CampaignLearningStateViewRead,
    CampaignLearningStateViewReadStatus, CampaignSourcePublication, CampaignSourceRevisionLookup,
    CampaignSourceRevisionRef, CanonicalRequestView, NamedReadOperation, NamedReadRequest,
    NamedReadResponse, OperationIdentity, OrderingHeadExpectation, PreparedTransition,
    ReadConsistency, RecoveryRecord, RecoveryRecordKey, RequestMeta, RevisionHeadExpectation,
    StoreError, StoreGenesisRequest, StoreRecoveryRequest, StoreRecoverySnapshot, WriteReceipt,
    WriteReceiptStatus, verify_canonical_request_hash, verify_ordering_scope_binding,
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
/// Authenticated daemon operation carrying one per-tick
/// `DaemonSupervisionRenewalRequest` (Implements #88, wave 3). The daemon
/// submits observed progress evidence; the Kernel alone decides renewal
/// through the single timing owner and always answers with its exact durable
/// head so the producer converges after renewals on any path.
pub(crate) const DAEMON_SUPERVISION_PROGRESS_OPERATION: &str = "daemon_supervision_progress";
/// Authenticated daemon route that drives the typed Host `UserAutomation`
/// transport.  The daemon session supplies the outer authority; the Host
/// open handshake supplies the channel evidence and the Host owner supplies
/// the Durable Job/Wake effects.
pub(crate) const USER_AUTOMATION_RUNTIME_OPERATION: &str = "user_automation_runtime";
/// Authenticated owner route carrying one canonical notification lifecycle
/// transition (issue #1780, I11.5/I11.7).
///
/// The marker is the canonical store contract's own closed mutation name
/// (`eliot_store_api::NOTIFICATION_STATE_MUTATION_NAME`, i.e.
/// `ApplyNotificationState`) and not a second Kernel vocabulary: the same
/// string is the mutation leg marker multiplexed by the notification
/// surface's `eliot.notify.state.v1` selector, so surface and Kernel cannot
/// drift into two spellings of one canonical write.
pub(crate) const NOTIFICATION_STATE_MUTATION_OPERATION: &str =
    eliot_store_api::NOTIFICATION_STATE_MUTATION_NAME;
/// Authenticated owner route serving one bounded canonical notification inbox
/// page (issue #1780). The marker is the store contract's own closed read name
/// (`eliot_store_api::NOTIFICATION_STATE_READ_NAME`, i.e.
/// `GetNotificationState`), the same selector the `ControlBoard` inbox read
/// already exercises through `store_named`.
pub(crate) const NOTIFICATION_STATE_READ_OPERATION: &str =
    eliot_store_api::NOTIFICATION_STATE_READ_NAME;
/// Response `kind` of the committed notification transition projection.
#[cfg(windows)]
const NOTIFICATION_STATE_RESPONSE_KIND: &str = "notification_state";
/// Response `kind` of the bounded notification inbox projection.
#[cfg(windows)]
const NOTIFICATION_STATE_PAGE_RESPONSE_KIND: &str = "notification_state_page";

/// Authenticated P-07 read route answering the completed canonical second
/// phases of one authority root (issue #2100, `R6`).
///
/// The Kernel commits the immutable first-phase grant-closure row and the
/// canonical receipt identity as two separate ORS records, and it owns ORS in
/// its own process. Without this route the daemon can observe that a closure
/// was fenced but can never learn whether its canonical second phase already
/// completed, so it can neither complete a pending one nor avoid re-presenting
/// a completed one. The route is read-only: it never links, never fences, and
/// never mints authority, and it requires no bound P-07 owner so the very first
/// feed pass can learn the links of a lineage whose owner is not bound yet.
pub(crate) const QUERY_GRANT_CLOSURE_LINKS_OPERATION: &str =
    "query_grant_closure_canonical_receipts";
/// Typed receipt kind answered by the canonical second-phase read arm.
const GRANT_CLOSURE_LINKS_KIND: &str = "grant_closure_canonical_receipts";
/// Typed refusal kind answered by the same arm, carrying the durable reason a
/// read could not be served. A refusal is never an empty link set.
const GRANT_CLOSURE_LINKS_REFUSAL_KIND: &str = "grant_closure_canonical_receipts_refused";
/// Authenticated operator selector for the `UserAutomation` CLI/MCP route.
///
/// This is the exact string published as `USER_AUTOMATION_ROUTE` in
/// `crates/surfaces/eliot-mcp/src/contract.rs` and used by
/// `crates/surfaces/eliot-cli/src/lib.rs`. It carries the closed I11.12
/// vocabulary `create; list/status/history; pause/resume; edit; run-now;
/// remove; inspect last failure`. The Kernel derives the principal, State
/// Fence, operation identity, and canonical request hash from authenticated
/// evidence, so the selector itself grants no authority.
pub(crate) const USER_AUTOMATION_OPERATOR_OPERATION: &str = "eliot_user_automation";

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
        NOTIFICATION_STATE_MUTATION_OPERATION => NOTIFICATION_STATE_MUTATION_OPERATION,
        NOTIFICATION_STATE_READ_OPERATION => NOTIFICATION_STATE_READ_OPERATION,
        "local_read" => "local_read",
        "daemon_degraded" => "daemon_degraded",
        "daemon_fatal" => "daemon_fatal",
        DAEMON_SUPERVISION_PROGRESS_OPERATION => DAEMON_SUPERVISION_PROGRESS_OPERATION,
        "agent_activation_claim" => "agent_activation_claim",
        "agent_activation_submit" => "agent_activation_submit",
        "agent_activation_reconcile" => "agent_activation_reconcile",
        "local_read_claim" => "local_read_claim",
        "local_read_result" => "local_read_result",
        "semantic_observe_claim" => "semantic_observe_claim",
        "semantic_observe_result" => "semantic_observe_result",
        "semantic_observe_deferred" => "semantic_observe_deferred",
        "campaign_packet_claim" => "campaign_packet_claim",
        "campaign_packet_result" => "campaign_packet_result",
        "task_controller_claim" => "task_controller_claim",
        "task_controller_result" => "task_controller_result",
        "agent_host_request_submit" => "agent_host_request_submit",
        "agent_host_request_cancel" => "agent_host_request_cancel",
        "publish_owner_bundle" => "publish_owner_bundle",
        "query_owner_bundle" => "query_owner_bundle",
        "initialize_owner_revision" => "initialize_owner_revision",
        "activate_grant" => "activate_grant",
        "revoke_grant" => "revoke_grant",
        "activate_introduction" => "activate_introduction",
        "revoke_introduction" => "revoke_introduction",
        QUERY_GRANT_CLOSURE_LINKS_OPERATION => QUERY_GRANT_CLOSURE_LINKS_OPERATION,
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

/// Strips the daemon transport's routing key from one application body.
///
/// The retained daemon client inserts `operation` into every JSON body so the
/// dispatcher can route it (`bins/eliotd/src/daemon_kernel_client/handshake.rs::operation_payload`),
/// and the frame loop routes on exactly that key. A carrier that decodes the
/// **whole** body with `#[serde(deny_unknown_fields)]` therefore sees a key it
/// never declared, refuses the body, and the daemon frame loop propagates the
/// resulting `SessionFenced` with `?` — fencing the Kernel connection, not just
/// the one request. Removing the key before the closed decode is the shape the
/// dispatcher already establishes for its own nested carriers
/// (`daemon_supervision_progress_operation` removes its wrapper key before
/// decoding, and `OwnerPublishOperation` *declares* `operation` and has its
/// feeder omit it).
///
/// Only the carriers that need it call this. The key is routing, not
/// application data: it is already bound to the dispatched `operation` string,
/// so removing it cannot lose or invent a request field, and a body that is
/// not an object still fails closed exactly as before.
fn without_daemon_routing_key(
    payload: serde_json::Value,
) -> Result<serde_json::Value, TransportError> {
    match payload {
        serde_json::Value::Object(mut object) => {
            object.remove("operation");
            Ok(serde_json::Value::Object(object))
        }
        _ => Err(TransportError::SessionFenced),
    }
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
    operation: String,
    bundle: super::GovernorClosureRestore,
    expected_revision: u64,
}

/// Closed owner-lineage revision initialization operation (`#2100`).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnerRevisionOperation {
    authority_root_ref: String,
    expected_revision: u64,
    state_fence: StateFence,
}

/// Closed P-07 grant activation operation (`#1110`).
///
/// Mirrors the authenticated `KernelAuthorityClient` payload: string
/// identities, the exact presented authority binding, and the presented
/// principal/session/scope subject. The dispatcher decodes, rechecks both
/// against the authenticated session, and routes through the retained P-07
/// owner port; it never mints authority. Unknown or absent fields fail
/// closed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantActivationOperation {
    grant_id: String,
    snapshot_id: String,
    binding: eliot_receipts::AuthorityBinding,
    subject: eliot_receipts::AuthorityRequestSubject,
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
    subject: eliot_receipts::AuthorityRequestSubject,
}

/// Closed P-07 introduction activation operation (`#1110`). Same shape
/// and fail-closed contract as the grant activation operation, keyed by
/// introduction identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntroductionActivationOperation {
    introduction_id: String,
    snapshot_id: String,
    binding: eliot_receipts::AuthorityBinding,
    subject: eliot_receipts::AuthorityRequestSubject,
}

/// Closed P-07 introduction revocation operation (`#1110`). Same shape
/// and fail-closed contract as the grant revocation operation, keyed by
/// introduction identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntroductionRevocationOperation {
    introduction_id: String,
    snapshot_id: String,
    binding: eliot_receipts::AuthorityBinding,
    subject: eliot_receipts::AuthorityRequestSubject,
}

/// Canonical installed WASM-host image filename pinned by the
/// installer-owned binding chain. Mirrors the `eliot-wasm-host.exe` pin the
/// installation descriptor validates before releasing its
/// `wasm_host_artifact_binding()`: any divergence fails closed here, the
/// same way `bind_notify_launch_grant` pins its own canonical image name.
const WASM_HOST_IMAGE_FILE_NAME: &str = "eliot-wasm-host.exe";

/// Stable module identity the demanded `eliot-wasm-host.exe` parent runs
/// under. Mirrors the `front_door_session` worker spellings
/// (`eliot-doctor`, `eliot-testd`, `eliot-native-worker`): the binary's own
/// name, bound by the Kernel at spawn through the admitted process owner,
/// never self-asserted by the child.
const WASM_HOST_MODULE_ID: &str = "eliot-wasm-host";

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
    let Some(history) = &bundle.revocation_history else {
        return false;
    };
    if history.state_fence != session.module_generation.state_fence {
        return false;
    }
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
        binding.authority_epoch == session.authority_epoch
            && binding.state_fence == session.module_generation.state_fence
    })
}

/// Rechecks one presented P-07 binding and subject against the authenticated
/// session before the dispatcher touches the retained owner, and therefore
/// before any authority mutation.
///
/// Four independent closed checks, none of them satisfied by caller material
/// alone:
///
/// - the presented subject is a well-formed principal/session/scope triple
///   (no blank or control-bearing identity, and no secret, provider detail,
///   arbitrary payload or free prose);
/// - the presented principal is exactly the caller the authenticated
///   handshake proved, so a cross-principal presentation is refused;
/// - the presented session is exactly the authenticated transport session, so
///   a request replayed or forwarded on another session is refused;
/// - the presented scope is one the authenticated session actually holds, so
///   a cross-scope presentation is refused even on the right session;
///
/// plus the compact binding: the fence must validate, the binding epoch must
/// agree with the fence epoch, the binding authority must be the session
/// authority, and the presented fence must be the session generation fence.
/// Anything else fails closed before mutation.
fn p07_binding_agrees_with_session(
    binding: &eliot_receipts::AuthorityBinding,
    subject: &eliot_receipts::AuthorityRequestSubject,
    session: &Session,
) -> Result<(), TransportError> {
    binding
        .state_fence
        .validate()
        .map_err(|_| TransportError::SessionFenced)?;
    subject
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
    if !subject.is_principal(session.module_generation.module_id.as_str())
        || !subject.is_session(session.connection_id.as_str())
        || !session
            .capabilities
            .iter()
            .any(|capability| subject.is_scope(capability.as_str()))
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

/// Canonical notification transition carrier for the
/// [`NOTIFICATION_STATE_MUTATION_OPERATION`] route (issue #1780).
///
/// The owner submits the already-admitted plan exactly as the
/// `apply_prepared` route requires; the Kernel never mints the operation
/// identity, the admission digests, or the mutation plan digest here. The
/// route exists so the canonical notification lifecycle has one admitted,
/// Kernel-owned entry instead of riding the general transition route
/// unreviewed.
#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationStateApplyOperation {
    context: RequestMeta,
    transition: PreparedTransition,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
}

/// Bounded canonical notification inbox selectors for the
/// [`NOTIFICATION_STATE_READ_OPERATION`] route (issue #1780).
///
/// Exactly the store contract's closed `GetNotificationState` selector set:
/// no quiet-hours field, no delivery-visibility field, and no role filter can
/// travel here, so a read can never be narrowed by a suppression policy.
#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationStateReadOperation {
    state_fence: StateFence,
    scope: Option<String>,
    dedup_key: Option<String>,
    notification_id: Option<String>,
    include_resolved: bool,
    page_limit: u16,
    cursor: Option<String>,
}

/// One bounded canonical notification page query (issue #1780).
///
/// The typed parameter of the single notification read seam
/// ([`KernelComposition::read_notification_page`]): the store contract's
/// closed `GetNotificationState` selector set together with the fence the
/// page must be served and proved under. The fence is a named field rather
/// than a sibling argument because that is the whole hazard this value
/// removes — a selector set and the fence it is served under are one fact
/// about one read, and a caller can no longer hand `read_notification_page` a
/// query built for one fence and check the echoed fence against another.
///
/// Exactly the closed selector set, nothing else: no quiet-hours field, no
/// delivery-visibility field, and no role filter, so no read resolved through
/// this value can be narrowed by a suppression policy (I11.7, I11.10).
#[cfg(windows)]
struct NotificationPageQuery {
    /// The exact fence the page is served and proved under.
    state_fence: StateFence,
    /// Optional canonical scope selector.
    scope: Option<String>,
    /// Optional deduplication-index selector.
    dedup_key: Option<String>,
    /// Optional canonical notification-identity selector.
    notification_id: Option<String>,
    /// Whether resolved records join the page.
    include_resolved: bool,
    /// Bounded page size; the store contract rejects an out-of-range value.
    page_limit: u16,
    /// Opaque page cursor.
    cursor: Option<String>,
}

#[cfg(windows)]
impl NotificationPageQuery {
    /// Folds the peer-presented selectors of the
    /// [`NOTIFICATION_STATE_READ_OPERATION`] route into the page query, so
    /// the route cannot re-spell, drop, or default one of them.
    fn from_read_operation(operation: &NotificationStateReadOperation) -> Self {
        Self {
            state_fence: operation.state_fence.clone(),
            scope: operation.scope.clone(),
            dedup_key: operation.dedup_key.clone(),
            notification_id: operation.notification_id.clone(),
            include_resolved: operation.include_resolved,
            page_limit: operation.page_limit,
            cursor: operation.cursor.clone(),
        }
    }

    /// The addressed-record page: exactly the record one lifecycle leg names,
    /// resolved at the fence that leg was admitted under.
    ///
    /// The single named constructor for the two read-backs that must agree —
    /// the committed transition's post-commit read-back and the Notify launch
    /// grant's durable-record join. Both ask "does this exact record persist
    /// at this exact fence", so both build the same value here instead of
    /// repeating the selector spelling at two call sites.
    fn addressed_record(
        state_fence: &StateFence,
        dedup_key: Option<String>,
        notification_id: Option<String>,
    ) -> Self {
        Self {
            state_fence: state_fence.clone(),
            scope: None,
            dedup_key,
            notification_id,
            include_resolved: true,
            page_limit: 1,
            cursor: None,
        }
    }

    /// The store contract's own closed `GetNotificationState` request for
    /// these selectors. The contract builder stays the only encoder of the
    /// parameter set and the only range check on the page limit.
    fn read_request(&self) -> Result<NamedReadRequest, StoreError> {
        eliot_store_api::notification_read_request(
            self.scope.clone(),
            self.dedup_key.clone(),
            self.notification_id.clone(),
            self.include_resolved,
            self.page_limit,
            self.cursor.clone(),
            self.state_fence.clone(),
        )
    }
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
        if publication.read_receipt.read_state_fence != transition.state_fence {
            return Err(
                "campaign source publication is not bound to the admitted read fence".into(),
            );
        }
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
                    .validate_for_source_at_fence(
                        recipe.campaign_id.as_str(),
                        &publication.record.owner_id,
                        &transition.state_fence,
                    )
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
    /// Front-door-authenticated request identity copied by the frame router.
    ///
    /// The daemon frame action carries no separate identity argument, so the
    /// exact identity the front door already bound to this session travels
    /// here and is re-validated against the session State Fence and request id
    /// before any owner effect.
    #[serde(default)]
    request_identity: Option<RequestIdentity>,
}

#[cfg(windows)]
/// Routing envelope read only to recover the front-door request identity.
///
/// The closed `UserAutomationRuntimeOperation` envelope owns the full shape
/// check, so this envelope neither widens nor narrows it.
#[derive(Deserialize)]
struct UserAutomationRouteIdentity {
    operation: String,
    #[serde(default)]
    request_identity: Option<RequestIdentity>,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAutomationOperatorRoute {
    operation: String,
    /// Front-door-authenticated request identity copied by the frame router.
    request_identity: RequestIdentity,
    payload: UserAutomationOperatorIntent,
}

#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAutomationOperatorIntent {
    /// Closed operator operation selected by the authenticated surface.
    operation: eliot_kernel_core::UserAutomationOperation,
    /// Retry-stable idempotency key contributed by the caller.
    idempotency_key: String,
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
                // F-LOG-KERNEL-1 (#897 W3): prepared, delivered and unknown
                // are three independent records. `delivered` marks the reply
                // value delivered to the immediate caller at this dispatch
                // boundary (the transport handoff), never the wire write: the
                // only wire-delivery witness is the driver-owned
                // `send_checked` write (`front_door_driver.rs`, outside #897
                // scope), so the post-handoff transport outcome stays
                // `unknown` at this boundary.
                observe_daemon_request("kernel.daemon_response_delivered", "success");
                observe_daemon_request("kernel.daemon_response_unknown", "unknown");
                observe_daemon_request("kernel.daemon_request_cleanup", "complete");
            }
            Err(error) => {
                observe_daemon_request("kernel.daemon_request_validated", "fenced");
                observe_daemon_operation(trusted_daemon_operation(operation), "fenced");
                if matches!(error, TransportError::Cancelled) {
                    // F-LOG-KERNEL-1 (#897 W3): cancellation observed as the
                    // terminal disposition, distinct from the cancellation
                    // request (`kernel.daemon_cancel_requested`). Info only;
                    // the terminal below stays the single designated terminal.
                    observe_daemon_request("kernel.daemon_cancel_observed", "cancelled");
                }
                super::kernel_diagnostics::observe_terminal_error(daemon_terminal_code(error));
                observe_daemon_request("kernel.daemon_request_cleanup", "fenced");
            }
        }
        result
    }

    #[cfg(windows)]
    pub(crate) fn validate_activation_submitter(
        session: &Session,
        request_identity: Option<&RequestIdentity>,
    ) -> Result<(), TransportError> {
        let identity = request_identity.ok_or(TransportError::SessionFenced)?;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if identity.request.metadata.product_id.as_str() != ACTIVE_DAEMON_CALLER
            || identity.request.metadata.source_id.as_str() != ACTIVE_DAEMON_CALLER
            || identity.request.metadata.session_id.is_some()
            || identity.request.metadata.task_id.is_some()
            || identity.request.state_fence != session.module_generation.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        let (owner, _) =
            super::caller_binding(session).map_err(|_| TransportError::PeerIdentityUnavailable)?;
        if owner.module_id() != ACTIVE_DAEMON_CALLER
            || owner.generation().get() != session.module_generation.generation.value()
            || !owner
                .authority_epoch()
                .is_same_authority(&session.authority_epoch)
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
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
        #[cfg(windows)]
        if operation == USER_AUTOMATION_OPERATOR_OPERATION {
            // The closed UserAutomation operator vocabulary is authenticated by
            // the front-door session, not by the daemon module binding: the
            // principal comes from the authenticated peer, the State Fence from
            // the session, and the canonical request hash is sealed by the
            // canonical Store owner over the exact prepared transition. No
            // other daemon operation is reachable from this branch.
            session
                .peer
                .validate()
                .map_err(|_| TransportError::PeerIdentityUnavailable)?;
            let value = Box::pin(self.user_automation_operator_operation(
                session,
                request_id.clone(),
                payload,
            ))
            .await?;
            let mut frame = status_frame(session, FrameKind::Response, MessageType::Result, value)?;
            frame.request_id = Some(request_id);
            frame.validate()?;
            return Ok(frame);
        }
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
                let ready_supervision: Option<serde_json::Value> = {
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
                        let fresh_binding = state.supervision.is_none();
                        state
                            .bind_live_receipt_publication_operation(&ready)
                            .map_err(|_| TransportError::SessionFenced)?;
                        state.supervision = Some(contour.clone());
                        if fresh_binding {
                            // Issue #88, wave 3: a newly bound generation
                            // starts unbound continuity. The first
                            // shape-valid observation pins boot, session, and
                            // monotonic evidence anew, so a restarted or
                            // replaced daemon generation can never continue
                            // the old series or cite the old predecessor.
                            state.supervision_progress = DaemonSupervisionProgressState::unbound();
                            state.last_progress_observation = None;
                            state.supervision_expired = false;
                        }
                    }
                    self.publish_eliotd_live_receipt(&launch, &process, &ready, &contour, None)
                        .map_err(|_| TransportError::SessionFenced)?;
                    let supervision = Self::daemon_ready_supervision_bundle(&contour, &snapshot)
                        .map_err(|_| TransportError::SessionFenced)?;
                    Some(supervision)
                };
                #[cfg(not(windows))]
                let ready_supervision: Option<serde_json::Value> = { None };
                #[cfg(windows)]
                let ready_answer = Self::daemon_ready_response(ready_supervision);
                #[cfg(not(windows))]
                let ready_answer = {
                    let _ = ready_supervision;
                    Self::accepted_daemon_response()
                };
                self.mark_daemon_ready()
                    .map_err(|_| TransportError::SessionFenced)
                    .and_then(|()| {
                        self.record_startup_evidence(7)
                            .map_err(|_| TransportError::SessionFenced)?;
                        Ok(ready_answer)
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
                let route: UserAutomationRouteIdentity = serde_json::from_value(payload.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                if route.operation != USER_AUTOMATION_RUNTIME_OPERATION {
                    return Err(TransportError::SessionFenced);
                }
                let Some(identity) = request_identity.cloned().or(route.request_identity) else {
                    return Err(TransportError::SessionFenced);
                };
                Box::pin(self.user_automation_runtime_operation(
                    session,
                    payload.clone(),
                    &identity,
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
            NOTIFICATION_STATE_MUTATION_OPERATION => {
                Box::pin(self.notification_state_operation(
                    session,
                    request_id.clone(),
                    payload.clone(),
                ))
                .await
            }
            NOTIFICATION_STATE_READ_OPERATION => {
                Box::pin(self.notification_state_read_operation(session, payload.clone())).await
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
            DAEMON_SUPERVISION_PROGRESS_OPERATION => {
                #[cfg(windows)]
                {
                    self.daemon_supervision_progress_operation(payload.clone())
                }
                #[cfg(not(windows))]
                {
                    let _ = payload;
                    Err(TransportError::SessionFenced)
                }
            }
            "agent_activation_claim" => {
                #[cfg(windows)]
                {
                    let object = payload.as_object().ok_or(TransportError::SessionFenced)?;
                    if object.len() != 2
                        || object.get("operation").and_then(serde_json::Value::as_str)
                            != Some("agent_activation_claim")
                        || !object.contains_key("claim")
                    {
                        return Err(TransportError::SessionFenced);
                    }
                    // Issue #1115: the closed claim operation carries exactly
                    // one typed `AgentActivationClaimRequest` naming the
                    // dependency the claimant is bound to; the shape was already
                    // closed above by the exact two-key envelope check.
                    // Main's material-authority admission still runs first, so a
                    // claimant without fresh material authority never reaches
                    // the claim step at all.
                    self.admit_material_authority_for_fence(
                        GovernanceProfile::full(),
                        &session.module_generation.state_fence,
                    )
                    .map_err(|_| TransportError::SessionFenced)?;
                    let claim: AgentActivationClaimRequest = serde_json::from_value(
                        object
                            .get("claim")
                            .cloned()
                            .ok_or(TransportError::SessionFenced)?,
                    )
                    .map_err(|_| TransportError::SessionFenced)?;
                    claim
                        .validate()
                        .map_err(|_| TransportError::SessionFenced)?;
                    self.claim_agent_activation_ticket(
                        &claim.dependency_ref,
                        &claim.dependency_revision,
                    )
                    .map(|ticket| {
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
                    // The production operation is exactly one closed v2
                    // envelope. There is no bare-result fallback and a legacy
                    // `decision` key is rejected even when it is null.
                    //
                    // This is main's fail-closed `#204` v1 removal, kept whole
                    // and made stricter: main rejected a *non-null* `decision`
                    // or a missing/non-null `result`; rejecting the key whenever
                    // it is present covers the non-null case, and the exact
                    // two-key envelope check below covers a missing `result`.
                    let object = payload.as_object().ok_or(TransportError::SessionFenced)?;
                    if object.contains_key("decision") {
                        // Historical v1 bytes are decoded only by the
                        // namespaced import module. Production dispatch rejects
                        // the key without invoking that decoder, including when
                        // its value is null, so v1 can never become a fallback.
                        return Err(TransportError::SessionFenced);
                    }
                    if object.len() != 2
                        || object.get("operation").and_then(serde_json::Value::as_str)
                            != Some("agent_activation_submit")
                        || !object.contains_key("result")
                    {
                        return Err(TransportError::SessionFenced);
                    }
                    let submit = eliot_protocol::decode_agent_activation_result_submit(
                        object.get("result").ok_or(TransportError::SessionFenced)?,
                    )
                    .map_err(|_| TransportError::SessionFenced)?;
                    Self::validate_activation_submitter(session, request_identity)?;
                    let identity = request_identity.ok_or(TransportError::SessionFenced)?;
                    match self.submit_agent_activation_result_authenticated(
                        submit,
                        Some(session),
                        Some(identity),
                    ) {
                        Ok(ack) => Ok(Self::activation_result_daemon_response(&ack)),
                        // Deadline expiry is an expected race at this
                        // boundary, not a daemon-fatal transport failure.
                        // A retained terminal result never takes this path:
                        // exact replay stays idempotent across the deadline.
                        Err(TransportError::Timeout) => {
                            // F-LOG-KERNEL-1 (#897 T19): timeout after
                            // possible work stays `unknown` in the diagnostic
                            // stream alongside the folded expired response.
                            // Observation only.
                            observe_daemon_request("kernel.daemon_response_unknown", "unknown");
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
            "agent_activation_reconcile" => {
                #[cfg(windows)]
                {
                    // Reconcile is a closed, typed query and is answered only
                    // from durable retention. No result payload or alternate
                    // decoder is admitted on this route.
                    let object = payload.as_object().ok_or(TransportError::SessionFenced)?;
                    if object.len() != 2
                        || object.get("operation").and_then(serde_json::Value::as_str)
                            != Some("agent_activation_reconcile")
                        || !object.contains_key("reconcile")
                    {
                        return Err(TransportError::SessionFenced);
                    }
                    let query: AgentActivationResultReconcile = serde_json::from_value(
                        object
                            .get("reconcile")
                            .cloned()
                            .ok_or(TransportError::SessionFenced)?,
                    )
                    .map_err(|_| TransportError::SessionFenced)?;
                    Self::validate_activation_submitter(session, request_identity)?;
                    let identity = request_identity.ok_or(TransportError::SessionFenced)?;
                    self.reconcile_agent_activation_result_authenticated(
                        &query,
                        Some(session),
                        Some(identity),
                    )
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
                            // F-LOG-KERNEL-1 (#897 T19): timeout after
                            // possible work stays `unknown` in the diagnostic
                            // stream alongside the folded expired response.
                            // Observation only.
                            observe_daemon_request("kernel.daemon_response_unknown", "unknown");
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
            "semantic_observe_claim" => {
                // Outbound-only eliotd observe poller for admitted
                // `eliot.observe` pairs (issue #2565): mirrors
                // `local_read_claim` — same session/auth/ready/fence gates
                // via the dispatcher head and `frame_dispatch` allowlist,
                // same single-`operation`-key payload shape, same null poll
                // (not error) when empty. The claimed pair carries the
                // Kernel-minted fenced attempt capability (admitted
                // `facet_method: eliot.observe`) the daemon must present back
                // on the submit and defer legs; no time lease is involved.
                // Local-read pairs are never served here.
                #[cfg(windows)]
                {
                    if payload.as_object().is_none_or(|object| object.len() != 1) {
                        return Err(TransportError::SessionFenced);
                    }
                    self.claim_observe_pair(session).map(|pair| match pair {
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
            "semantic_observe_result" => {
                // Daemon submit leg for the claimed observe pair (issue
                // #2565): validates plus fence-checks the submitted
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
                    match self.submit_observe_result(session, &body) {
                        Ok(host_request_route::LocalReadSubmitDisposition::Persisted(_)) => {
                            Ok(Self::accepted_daemon_response())
                        }
                        Ok(host_request_route::LocalReadSubmitDisposition::StaleAttempt(
                            observation,
                        )) => Ok(Self::stale_attempt_daemon_response(&observation)),
                        Err(TransportError::Timeout) => {
                            // F-LOG-KERNEL-1 (#897 T19): timeout after
                            // possible work stays `unknown` in the diagnostic
                            // stream alongside the folded expired response.
                            // Observation only.
                            observe_daemon_request("kernel.daemon_response_unknown", "unknown");
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
            "semantic_observe_deferred" => {
                // Daemon deferral leg for the claimed observe pair (issue
                // #2565): the flight consumed the pair but the Governor
                // observation owner has no connected admission yet, so no
                // effect was produced and none is claimed. The presenting
                // attempt must be the live triple; anything else quarantines
                // as the known stale outcome. The durable record advances
                // `Admitted -> Routed`, the queue pair retires, and the
                // pending handle stays live with its exact resume condition
                // (resubmit the same logical request once the owner
                // connects). An already-terminal record settles: consult it.
                #[cfg(windows)]
                {
                    let operation_id = payload
                        .get("operation_id")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(TransportError::SessionFenced)?;
                    let request_digest = payload
                        .get("request_digest")
                        .and_then(serde_json::Value::as_str)
                        .ok_or(TransportError::SessionFenced)?;
                    let attempt_value = payload
                        .get("attempt")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?;
                    let attempt: LocalReadAttempt = serde_json::from_value(attempt_value)
                        .map_err(|_| TransportError::SessionFenced)?;
                    match self.defer_observe_claim(session, operation_id, request_digest, &attempt)
                    {
                        Ok(host_request_route::ObserveDeferDisposition::Deferred(record)) => Ok(
                            Self::deferred_observe_daemon_response(record.operation_id.as_str()),
                        ),
                        Ok(host_request_route::ObserveDeferDisposition::Settled(record)) => Ok(
                            Self::settled_observe_daemon_response(record.operation_id.as_str()),
                        ),
                        Ok(host_request_route::ObserveDeferDisposition::StaleAttempt(
                            observation,
                        )) => Ok(Self::stale_attempt_daemon_response(&observation)),
                        Err(TransportError::Timeout) => {
                            // F-LOG-KERNEL-1 (#897 T19): timeout after
                            // possible work stays `unknown` in the diagnostic
                            // stream alongside the folded expired response.
                            // Observation only.
                            observe_daemon_request("kernel.daemon_response_unknown", "unknown");
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
            "campaign_packet_claim" => {
                // Campaign packets have their own closed queue and attempt
                // ledger. This route never scans the `eliot.query` queue and
                // never derives evidence-pack selectors from packet material.
                #[cfg(windows)]
                {
                    if payload.as_object().is_none_or(|object| object.len() != 1) {
                        return Err(TransportError::SessionFenced);
                    }
                    self.claim_campaign_packet_pair(session)
                        .map(|pair| match pair {
                            Some((envelope, tool, attempt)) => serde_json::json!({
                                "status": "known",
                                "value": {
                                    "pair": {
                                        "envelope": envelope,
                                        "tool": tool,
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
            "campaign_packet_result" => {
                // A packet result is submitted through the packet queue only;
                // the shared result gate still proves the exact attempt,
                // envelope fence, owner publication binding, and digest.
                #[cfg(windows)]
                {
                    let result_value = payload
                        .get("result")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?;
                    let body: HostRequestResultBody = serde_json::from_value(result_value)
                        .map_err(|_| TransportError::SessionFenced)?;
                    match self.submit_campaign_packet_result(session, &body) {
                        Ok(host_request_route::LocalReadSubmitDisposition::Persisted(_)) => {
                            Ok(Self::accepted_daemon_response())
                        }
                        Ok(host_request_route::LocalReadSubmitDisposition::StaleAttempt(
                            observation,
                        )) => Ok(Self::stale_attempt_daemon_response(&observation)),
                        Err(TransportError::Timeout) => {
                            // F-LOG-KERNEL-1 (#897 T19): timeout after
                            // possible work stays `unknown` in the diagnostic
                            // stream alongside the folded expired response.
                            // Observation only.
                            observe_daemon_request("kernel.daemon_response_unknown", "unknown");
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
                            // F-LOG-KERNEL-1 (#897 T19): timeout after
                            // possible work stays `unknown` in the diagnostic
                            // stream alongside the folded expired response.
                            // Observation only.
                            observe_daemon_request("kernel.daemon_response_unknown", "unknown");
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
                // Observe bytes ride this entry exactly like the bridge
                // front-door submit arm (issue #2565): linkage before
                // staging, retention enqueue after admission.
                let envelope = host_request_route::host_request_envelope_from_payload(payload)?;
                let observe_tool = payload.get("tool").cloned();
                if let Some(ref tool) = observe_tool
                    && envelope.identity.capability == host_request_route::OBSERVE_CAPABILITY
                {
                    host_request_route::check_observe_tool_linkage(&envelope, tool)?;
                }
                let (receipt, record) = self.admit_host_request_envelope(&envelope)?;
                self.maybe_enqueue_observe_pair_for_submit(
                    &envelope,
                    &record,
                    observe_tool.as_ref(),
                );
                Ok(host_request_route::host_request_admitted_response(
                    &receipt, &record,
                ))
            }
            #[cfg(windows)]
            "agent_host_request_cancel" => {
                // F-LOG-KERNEL-1 (#897 W3): cancellation requested through the
                // closed daemon dispatcher. Info only; the observed wrapper
                // owns the single designated terminal for this operation.
                observe_daemon_request("kernel.daemon_cancel_requested", "attempt");
                let envelope = host_request_route::host_request_envelope_from_payload(payload)?;
                let cancel = self.cancel_host_request(&envelope);
                match &cancel {
                    Ok(_) => {
                        observe_daemon_request("kernel.daemon_cancel_requested", "success");
                        // F-LOG-KERNEL-1 (#897 T18): the typed cancellation
                        // owner admitted the cancellation, so the requested
                        // cancellation is observed as effected here. This is
                        // the production-reachable observation half of the
                        // request/observed pair; the `Cancelled` terminal
                        // disposition below stays for the error path. Info
                        // only; the observed wrapper owns the terminal.
                        observe_daemon_request("kernel.daemon_cancel_observed", "cancelled");
                    }
                    Err(_) => observe_daemon_request("kernel.daemon_cancel_requested", "fenced"),
                }
                let (receipt, record) = cancel?;
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
            "initialize_owner_revision" => {
                let operation: OwnerRevisionOperation = serde_json::from_value(payload.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                if operation.state_fence != session.module_generation.state_fence {
                    return Err(TransportError::SessionFenced);
                }
                let revision = self
                    .initialize_p07_owner_revision(
                        &operation.authority_root_ref,
                        operation.expected_revision,
                        &operation.state_fence,
                    )
                    .map_err(|error| match error {
                        KernelBuildError::Core(_) => TransportError::IdentityConflict,
                        _ => TransportError::SessionFenced,
                    })?;
                Ok(serde_json::json!({
                    "kind": "owner_revision_receipt",
                    "value": { "revision": revision },
                }))
            }
            "publish_owner_bundle" => {
                let operation: OwnerPublishOperation = serde_json::from_value(payload.clone())
                    .map_err(|_| TransportError::SessionFenced)?;
                if operation.operation != "publish_owner_bundle" || operation.expected_revision == 0
                {
                    return Err(TransportError::SessionFenced);
                }
                // Session-authority agreement under the existing session
                // authorities: every admitted binding must share the
                // authenticated session authority, or the bundle does not
                // describe authority this session may fence.
                if !owner_bundle_agrees_with_session(&operation.bundle, session) {
                    return Err(TransportError::SessionFenced);
                }
                self.admit_material_authority_for_fence(
                    GovernanceProfile::full(),
                    &session.module_generation.state_fence,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                // Restart recovery (`#1110`): a process that retained an
                // owner only rotates it through the exact-revision refresh
                // gate, while a process that retained none is a Kernel/daemon
                // restart and `bind_canonical_owner` rebuilds live authority
                // state from ORS plus the canonical rehydration before the
                // owner is retained. The receipt shape is unchanged: the
                // readback route and the existing publisher decode it
                // strictly.
                match self.recover_p07_owner(operation.bundle, operation.expected_revision) {
                    Ok(revision) => Ok(serde_json::json!({
                        "status": "known",
                        "value": {
                            "kind": "owner_bundle_receipt",
                            "value": { "revision": revision, "status": "bound" },
                        },
                        "recovery": null,
                    })),
                    // The presented bundle or a durable row disagrees with
                    // Kernel owner state (stale revision, disagreeing
                    // material, an unprovable rehydration): the caller
                    // re-serves fresh state, never retries blindly.
                    Err(KernelBuildError::Core(_)) => Err(TransportError::IdentityConflict),
                    Err(_) => Err(TransportError::SessionFenced),
                }
            }
            "query_owner_bundle" => {
                let object = payload.as_object().ok_or(TransportError::SessionFenced)?;
                if object.len() != 1
                    || object.get("operation").and_then(serde_json::Value::as_str)
                        != Some("query_owner_bundle")
                {
                    return Err(TransportError::SessionFenced);
                }
                let (bound, revision, digest) = self.p07_owner_readback();
                Ok(serde_json::json!({
                    "status": "known",
                    "value": {
                        "kind": "owner_bundle_readback",
                        "value": {
                            "bound": bound,
                            "revision": revision,
                            "digest": digest,
                        },
                    },
                    "recovery": null,
                }))
            }
            QUERY_GRANT_CLOSURE_LINKS_OPERATION => {
                let query: eliot_kernel_service::GrantClosureCanonicalLinksQuery =
                    serde_json::from_value(payload.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                // The live session fence binds the served view, exactly as the
                // authority-history read binds it: a query presented under any
                // other fence is refused before the durable store is touched.
                if query.state_fence != session.module_generation.state_fence {
                    return Err(TransportError::SessionFenced);
                }
                match eliot_kernel_service::grant_closure_canonical_links(
                    self.p07_ors.as_ref(),
                    &query,
                    &session.module_generation.state_fence,
                ) {
                    Ok(links) => Ok(serde_json::json!({
                        "kind": GRANT_CLOSURE_LINKS_KIND,
                        "value": links,
                    })),
                    // A refusal keeps its durable reason and stays a refusal:
                    // the daemon must never read it as "no second phase
                    // completed here".
                    Err(error) => Ok(serde_json::json!({
                        "kind": GRANT_CLOSURE_LINKS_REFUSAL_KIND,
                        "value": { "reason": error.to_string() },
                    })),
                }
            }
            "activate_grant" => {
                let operation: GrantActivationOperation =
                    serde_json::from_value(payload.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.grant_id.trim().is_empty() || operation.snapshot_id.trim().is_empty() {
                    return Err(TransportError::SessionFenced);
                }
                p07_binding_agrees_with_session(&operation.binding, &operation.subject, session)?;
                self.admit_material_authority_for_fence(
                    GovernanceProfile::full(),
                    &session.module_generation.state_fence,
                )
                .map_err(|_| TransportError::SessionFenced)?;
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
                p07_binding_agrees_with_session(&operation.binding, &operation.subject, session)?;
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
                p07_binding_agrees_with_session(&operation.binding, &operation.subject, session)?;
                self.admit_material_authority_for_fence(
                    GovernanceProfile::full(),
                    &session.module_generation.state_fence,
                )
                .map_err(|_| TransportError::SessionFenced)?;
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
                p07_binding_agrees_with_session(&operation.binding, &operation.subject, session)?;
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
                    .await
            }
            "bind_notify_launch_grant" => {
                self.notify_launch_grant_operation(session, payload.clone())
                    .await
            }
            _ => return Err(TransportError::SessionFenced),
        };
        // Typed refusal propagation (`#1110`): the arm already decided the
        // closed disposition. Collapsing every one of them into
        // `SessionFenced` here erased the typed P-07 `IdentityConflict` and
        // `UnknownOutcome` observations (`map_p07_port_error`) and the owner
        // publish/revision conflicts before they reached the operator
        // observation (`daemon_terminal_code`) or the agent-facing surface, so
        // a changed payload under one operation identity was indistinguishable
        // from a missing owner. Propagate the decided variant unchanged.
        let value = result?;
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

    /// Builds the exact durable predecessor proof for one ORS head. The proof
    /// is what the daemon cites back on its next submit; a moved head makes
    /// the stale citation fail closed with a typed mismatch instead of
    /// renewing from the wrong revision.
    #[cfg(windows)]
    fn supervision_head_proof(
        snapshot: &SupervisionLeaseSnapshot,
    ) -> Result<SupervisionLeasePredecessorProof, TransportError> {
        snapshot
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let envelope_sha256 = snapshot
            .record
            .artifact
            .envelope_digest()
            .map_err(|_| TransportError::SessionFenced)?;
        let proof = SupervisionLeasePredecessorProof {
            lease_id: snapshot.record.lease_id.as_str().to_owned(),
            record_id: snapshot.record.record_id.as_str().to_owned(),
            lease_revision: snapshot.record.revision,
            receipt_sha256: snapshot.receipt.receipt_sha256.clone(),
            envelope_sha256,
        };
        proof
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(proof)
    }

    /// Assembles the once-per-generation supervision bundle for the
    /// `daemon_ready` answer: the authority lineage the daemon echoes back on
    /// every submit plus the exact current lease head it cites first. Every
    /// echoed field is re-verified against the supervision contour on submit.
    #[cfg(windows)]
    fn daemon_ready_supervision_bundle(
        contour: &DaemonSupervisionContour,
        snapshot: &SupervisionLeaseSnapshot,
    ) -> Result<serde_json::Value, TransportError> {
        let proof = Self::supervision_head_proof(snapshot)?;
        serde_json::to_value(serde_json::json!({
            "lineage": {
                "installation_id": contour.incarnation.installation_id,
                "activation_id": contour.incarnation.activation_id,
                "activation_generation": contour.activation.generation.value(),
                "generation_binding": contour.generation_binding,
                "kernel_epoch": contour.activation.authority_epoch,
                "state_fence": contour.state_fence,
            },
            "head": {
                "predecessor": proof,
                "lease_issued_at_ms": snapshot.record.binding.issued_at_ms,
                "lease_expires_at_ms": snapshot.record.binding.expires_at_ms,
            },
        }))
        .map_err(|_| TransportError::SessionFenced)
    }

    /// Wraps the ready answer with the supervision bundle when the Kernel
    /// bound one. The pre-supervision shape stays byte-identical otherwise.
    #[cfg(windows)]
    fn daemon_ready_response(ready_supervision: Option<serde_json::Value>) -> serde_json::Value {
        match ready_supervision {
            Some(supervision) => serde_json::json!({
                "status": "known",
                "value": { "accepted": true, "supervision": supervision },
                "recovery": null,
            }),
            None => Self::accepted_daemon_response(),
        }
    }

    /// Answers one progress submit in the closed envelope. A decision and a
    /// refusal never co-occur; the exact durable predecessor and the accepted
    /// cursors are always present so the producer converges after renewals on
    /// any path, including the Host-driven `ProbeReady` path.
    #[cfg(windows)]
    fn progress_answer_envelope(
        decision: Option<&DaemonSupervisionRenewalDecision>,
        receipt: Option<&DaemonSupervisionRenewalReceipt>,
        refusal_code: Option<&str>,
        predecessor: &SupervisionLeasePredecessorProof,
        accepted_cursors: &[DaemonChannelCursor],
    ) -> Result<serde_json::Value, TransportError> {
        let decision_value = decision
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| TransportError::SessionFenced)?;
        let receipt_value = receipt
            .map(serde_json::to_value)
            .transpose()
            .map_err(|_| TransportError::SessionFenced)?;
        let predecessor_value =
            serde_json::to_value(predecessor).map_err(|_| TransportError::SessionFenced)?;
        let accepted_value =
            serde_json::to_value(accepted_cursors).map_err(|_| TransportError::SessionFenced)?;
        Ok(serde_json::json!({
            "status": "known",
            "value": {
                "outcome": decision.map(|decided| decided.outcome),
                "refusal_code": refusal_code,
                "decision": decision_value,
                "receipt": receipt_value,
                "predecessor": predecessor_value,
                "accepted_cursors": accepted_value,
            },
            "recovery": null,
        }))
    }

    /// Puts back Kernel-owned progress continuity after one renewal evaluation
    /// and records the submitted observation and the expiry mark. Continuity
    /// is never dropped: refusals keep their miss accounting and renewals
    /// keep their recorded cursors.
    #[cfg(windows)]
    fn retain_supervision_progress(
        &self,
        progress: DaemonSupervisionProgressState,
        observation: Option<DaemonProgressObservation>,
        expired: Option<bool>,
    ) -> Result<(), TransportError> {
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        state.supervision_progress = progress;
        if observation.is_some() {
            state.last_progress_observation = observation;
        }
        if let Some(expired) = expired {
            state.supervision_expired = expired;
        }
        Ok(())
    }

    /// Revokes daemon-dependent effect admission after the progress route
    /// reports terminal supervision lease expiry (issue #88, A6).
    ///
    /// Uses the same production revocation as the degraded/failed paths:
    /// removing the promoted agent-bridge profile revokes every pending
    /// connection from the expired lineage. `ProbeReady` already fails closed
    /// on the expired marker, so no new admission can be promoted until a
    /// new admitted generation rebinds and clears the marker. The caller
    /// retains progress (releasing the runtime lock) before this runs, so
    /// the bridge locks are taken after, matching the degraded/failed
    /// order.
    ///
    /// I1.5 (#1750): the expired generation remains fenced until a newly
    /// admitted generation rebinds; a later `ProbeReady` or heartbeat cannot
    /// revive it.
    #[cfg(windows)]
    fn revoke_supervision_expired_effect_admission(&self) -> Result<(), TransportError> {
        self.promote_agent_bridge_profile(None)?;
        observe_daemon_request(
            "kernel.daemon.supervision_expired_effects_revoked",
            "success",
        );
        Ok(())
    }

    /// Answers a refused renewal with its stable code plus the exact durable
    /// head. A refusal never mints authority and never asserts process death;
    /// terminal lease expiry additionally marks the supervision claim so the
    /// expired lease stays visibly degraded until a new admitted generation
    /// rebinds.
    #[cfg(windows)]
    fn progress_refusal_answer(
        &self,
        lease_id: &str,
        error: &DaemonSupervisionHeartbeatError,
    ) -> Result<serde_json::Value, TransportError> {
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let head = authority
            .current_snapshot(lease_id)
            .map_err(|_| TransportError::SessionFenced)?
            .ok_or(TransportError::SessionFenced)?;
        let proof = Self::supervision_head_proof(&head)?;
        let accepted = self
            .daemon_runtime
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .supervision_progress
            .accepted_cursors
            .clone();
        Self::progress_answer_envelope(None, None, Some(error.code()), &proof, &accepted)
    }

    /// Drives one per-tick progress submit from observed daemon evidence
    /// through the typed renewal route (Implements #88, wave 3).
    ///
    /// The request is joined against the exact durable head through the
    /// single timing owner. `Renewed` commits exactly one successor and
    /// completes its receipt only after live-receipt publication, so a
    /// renewal never ships without publication evidence. Every other decided
    /// outcome returns the unchanged head with its complete receipt and no
    /// commit. Typed join refusals answer with the refusal code and the
    /// current head; durable authority failures fence the operation. The
    /// producer halts itself on terminal expiry; the Kernel never revives an
    /// expired lease from further heartbeats.
    #[cfg(windows)]
    fn daemon_supervision_progress_operation(
        &self,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let request_value = match payload {
            serde_json::Value::Object(mut object) => object
                .remove("request")
                .ok_or(TransportError::SessionFenced)?,
            _ => return Err(TransportError::SessionFenced),
        };
        let request: DaemonSupervisionRenewalRequest =
            serde_json::from_value(request_value).map_err(|_| TransportError::SessionFenced)?;
        request
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let lease_id = request.observation.lease_id.clone();
        let (contour, process, ready, launch, mut progress) = {
            let mut state = self
                .daemon_runtime
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            if state.status != DaemonRuntimeStatus::Ready {
                return Err(TransportError::SessionFenced);
            }
            let contour = state
                .supervision
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            let process = state.receipt.clone().ok_or(TransportError::SessionFenced)?;
            let ready = state
                .live_ready
                .clone()
                .ok_or(TransportError::SessionFenced)?;
            let progress = std::mem::replace(
                &mut state.supervision_progress,
                DaemonSupervisionProgressState::unbound(),
            );
            drop(state);
            let launch = self
                .active_daemon_launch()
                .map_err(|_| TransportError::SessionFenced)?
                .ok_or(TransportError::SessionFenced)?;
            (contour, process, ready, launch, progress)
        };
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let renewal = Self::renew_current_supervision_with_progress(
            authority.as_ref(),
            &contour,
            &request,
            &mut progress,
            &SUPERVISION_LEASE_RENEWAL_POLICY,
            unix_ms(),
        );
        let (snapshot, decision, receipt) = match renewal {
            Ok(decided) => decided,
            Err(SupervisionProgressRenewalError::Heartbeat(error)) => {
                let expired = error == DaemonSupervisionHeartbeatError::SupervisionLeaseExpired;
                self.retain_supervision_progress(
                    progress,
                    Some(request.observation.clone()),
                    Some(expired),
                )?;
                if expired {
                    self.revoke_supervision_expired_effect_admission()?;
                }
                return self.progress_refusal_answer(&lease_id, &error);
            }
            Err(SupervisionProgressRenewalError::Authority(_)) => {
                self.retain_supervision_progress(progress, None, None)?;
                return Err(TransportError::SessionFenced);
            }
        };
        self.retain_supervision_progress(progress, Some(request.observation.clone()), Some(false))?;
        let receipt = if decision.outcome == DaemonSupervisionRenewalOutcome::Renewed {
            let published = self
                .publish_eliotd_live_receipt(&launch, &process, &ready, &contour, Some(&snapshot))
                .map_err(|_| TransportError::SessionFenced)?;
            let live_sha256 = sha256_hex(
                &canonical_json_bytes(&published).map_err(|_| TransportError::SessionFenced)?,
            );
            daemon_renewal_receipt_for_decision(
                &decision,
                Some(snapshot.receipt.receipt_sha256.clone()),
                Some(live_sha256),
            )
            .map_err(|_| TransportError::SessionFenced)?
        } else {
            receipt.ok_or(TransportError::SessionFenced)?
        };
        let proof = Self::supervision_head_proof(&snapshot)?;
        let accepted = self
            .daemon_runtime
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .supervision_progress
            .accepted_cursors
            .clone();
        Self::progress_answer_envelope(Some(&decision), Some(&receipt), None, &proof, &accepted)
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
        // The payload copy of the front-door identity and the identity this
        // route was invoked with must be the same value. A caller cannot
        // substitute one, and neither copy widens the session authority.
        if envelope
            .request_identity
            .as_ref()
            .is_some_and(|embedded| embedded != request_identity)
        {
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
            UserAutomationHostExecutionOperation::AdmitOccurrence { request }
                if is_due_scheduler_wake(request) =>
            {
                Self::user_automation_due_wake_owner_check(
                    self.revalidate_user_automation_due_wake(session, request)
                        .await,
                )
            }
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_admission(session, request)
                        .await,
                )
            }
            UserAutomationHostExecutionOperation::CancelPendingWakes { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_cancellation(session, request)
                        .await,
                )
            }
            UserAutomationHostExecutionOperation::ReadPendingWake { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_wake_read(session, request)
                        .await,
                )
            }
        };
        if let Some(answer) = owner_check {
            return Ok(answer);
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
            UserAutomationHostExecutionOperation::AdmitOccurrence { request }
                if is_due_scheduler_wake(request) =>
            {
                Self::user_automation_due_wake_owner_check(
                    self.revalidate_user_automation_due_wake(session, request)
                        .await,
                )
            }
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_admission(session, request)
                        .await,
                )
            }
            UserAutomationHostExecutionOperation::CancelPendingWakes { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_cancellation(session, request)
                        .await,
                )
            }
            UserAutomationHostExecutionOperation::ReadPendingWake { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_wake_read(session, request)
                        .await,
                )
            }
        };
        if let Some(answer) = owner_check {
            return Ok(answer);
        }

        match request {
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                self.admit_material_authority_for_fence(
                    GovernanceProfile::full(),
                    &session.module_generation.state_fence,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                if is_due_scheduler_wake(&request) {
                    Box::pin(self.user_automation_due_wake_operation(session, *request, &client))
                        .await
                } else {
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
    /// Serves the authenticated `eliot_user_automation` operator route.
    ///
    /// The route implements the I11.12 operations `create;
    /// list/status/history; pause/resume; edit; run-now; remove; inspect last
    /// failure`. The selector carries only the closed operation plus the
    /// caller's retry-stable idempotency key; the principal comes from the
    /// authenticated peer, the State Fence and `RequestMetadata` from the
    /// front-door identity, and the canonical Store operation identity and
    /// canonical request hash are sealed by the canonical Store owner over the
    /// exact prepared transition. The route therefore creates no authority, no
    /// principal, and no second canonical writer.
    ///
    /// The answer is one post-commit orchestration transition. The canonical
    /// Store commit, the wake publication/cancellation handoff over the
    /// authenticated `USER_AUTOMATION_RUNTIME_OPERATION` channel, and the
    /// execution disposition are reported as three separate typed phases, and
    /// the top-level `status`/`recovery` pair is computed from those phases: a
    /// required handoff that is absent or unknown can never answer `known` with
    /// `recovery: null` (issue #2806, I11.12).
    pub(crate) async fn user_automation_operator_operation(
        &self,
        session: &Session,
        request_id: RequestId,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let route: UserAutomationOperatorRoute =
            serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
        if route.operation != USER_AUTOMATION_OPERATOR_OPERATION {
            return Err(TransportError::SessionFenced);
        }
        let identity = route.request_identity;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if identity.request.metadata.request_id != request_id
            || identity.request.state_fence != session.module_generation.state_fence
            || route.payload.idempotency_key != identity.idempotency_key
        {
            return Err(TransportError::SessionFenced);
        }
        validate_user_automation_trigger_text(&route.payload.idempotency_key, "idempotency_key")?;
        let principal = authenticated_user_automation_principal(session)?;
        let operation_id = eliot_contracts::OperationId::new(format!(
            "user-automation-operation:{}",
            route.payload.idempotency_key
        ))
        .map_err(|_| TransportError::SessionFenced)?;
        let intent = eliot_kernel_core::UserAutomationOperatorIntent {
            intent_id: format!("user-automation-intent:{}", route.payload.idempotency_key),
            principal_ref: principal.clone(),
            state_fence: session.module_generation.state_fence.clone(),
            operation: route.payload.operation,
        };
        let request = eliot_kernel_service::UserAutomationServiceRequest {
            context: identity.request.metadata.clone(),
            authenticated_principal: principal,
            identity: OperationIdentity {
                operation_id,
                idempotency_key: route.payload.idempotency_key,
                canonical_request_hash: String::new(),
            },
            intent,
        };
        // The existing authenticated Host execution channel is composed for
        // exactly the operations that own a wake or execution handoff, so a
        // read-only answer never depends on the Host contour. The composed
        // `UserAutomationOperatorRuntime` is the concrete runtime port the
        // post-commit transition calls; no second transport or route is created.
        let runtime_channel = match self
            .user_automation_operator_runtime_channel(
                &request.intent.operation,
                &session.module_generation.state_fence,
            )
            .await
        {
            Ok(channel) => channel,
            Err(error) => {
                return Ok(Self::user_automation_runtime_error_response(error));
            }
        };
        let runtime = runtime_channel
            .as_ref()
            .map(eliot_kernel_service::UserAutomationOperatorRuntime::new);
        let gateway = self.retained_store_gateway()?;
        let transition =
            Box::pin(gateway.execute_user_automation_operation(request.clone(), runtime.as_ref()))
                .await
                .map_err(|_error| {
                    // F-LOG-KERNEL-1 (#897 W5): correlated subordinate phase
                    // observation only. The single designated terminal for
                    // this failed operation is emitted by
                    // `execute_daemon_request_observed`; a second terminal
                    // here would inflate one store failure into two.
                    observe_daemon_request(
                        "kernel.daemon_user_automation_operator_store",
                        "fenced",
                    );
                    TransportError::SessionFenced
                })?;
        // The Human inspect surface shows the deterministic schedule
        // projection before activation: the same normalized occurrence set the
        // trigger contract uses, compiled here into the immutable
        // revision-bound occurrence identities. A schedule the compiler cannot
        // compile fails closed instead of projecting a guessed occurrence.
        let occurrences =
            Self::user_automation_inspection_occurrences(&transition).map_err(|_error| {
                // F-LOG-KERNEL-1 (#897 W5): correlated subordinate phase
                // observation only; `execute_daemon_request_observed` owns
                // the single designated terminal for this failed operation.
                observe_daemon_request(
                    "kernel.daemon_user_automation_occurrence_projection",
                    "fenced",
                );
                TransportError::SessionFenced
            })?;
        let recovery = transition.recovery();
        let known = transition.is_known();
        if !known {
            // F-LOG-KERNEL-1 (#897 T19): the store transition reports an
            // unknown wake/execution outcome after possible work. The
            // response body carries `"status": "unknown"` below; this record
            // keeps the diagnostic stream honest alongside it. Observation
            // only; the response value is unchanged.
            observe_daemon_request("kernel.daemon_response_unknown", "unknown");
        }
        Ok(serde_json::json!({
            "status": if known { "known" } else { "unknown" },
            "value": {
                "identity": transition.identity,
                "state_fence": transition.state_fence,
                "configuration": transition.configuration,
                "wake": transition.wake,
                "horizon": transition.horizon,
                "execution": transition.execution,
                "occurrences": occurrences,
            },
            "recovery": recovery,
        }))
    }

    /// Composes the existing authenticated Host execution channel for the
    /// operations that own a wake or execution handoff.
    ///
    /// The channel is the same server-authored `user_automation_runtime`
    /// transport the runtime route already serves, so this adds no authority and
    /// no new operation name. A read-only answer composes nothing, so it never
    /// depends on the Host contour.
    ///
    /// An operation that only publishes a bounded recurring horizon may reach its
    /// owner later: an unreachable Host contour composes nothing and the
    /// publication is reported as unavailable with the exact remaining occurrence
    /// set and replay handle, so the canonical commit still happens and the
    /// obligation stays visible. An operation that owns an execution or
    /// cancellation effect is refused outright, because answering that path
    /// without its owner would be a Store-only success.
    #[cfg(windows)]
    async fn user_automation_operator_runtime_channel(
        &self,
        operation: &eliot_kernel_core::UserAutomationOperation,
        state_fence: &StateFence,
    ) -> Result<
        Option<
            UserAutomationHostExecutionClient<AuthenticatedUserAutomationHostExecutionTransport>,
        >,
        UserAutomationRuntimeError,
    > {
        let need = user_automation_runtime_handoff_need(operation);
        if need == UserAutomationRuntimeHandoffNeed::None {
            return Ok(None);
        }
        let transport =
            match AuthenticatedUserAutomationHostExecutionTransport::connect_server_authored(
                self.ipc_limits().operation_timeout,
            )
            .await
            {
                Ok(transport) => transport,
                Err(_) if need == UserAutomationRuntimeHandoffNeed::PublicationOnly => {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            };
        if transport.channel_binding().state_fence != *state_fence {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Ok(Some(UserAutomationHostExecutionClient::new(transport)?))
    }

    /// Compiles the deterministic next-occurrence projection of every revision
    /// a read operation returned.
    ///
    /// A mutation answer carries no schedule projection, so it yields an empty
    /// list rather than re-deriving a revision the caller did not ask for.
    #[cfg(windows)]
    fn user_automation_inspection_occurrences(
        transition: &eliot_kernel_service::UserAutomationOperatorTransition,
    ) -> Result<Vec<serde_json::Value>, UserAutomationRuntimeError> {
        use eliot_kernel_service::UserAutomationReadResult;
        let eliot_kernel_service::UserAutomationConfigurationPhase::Read { result } =
            &transition.configuration
        else {
            return Ok(Vec::new());
        };
        let revisions: Vec<&eliot_kernel_core::UserAutomationRevision> = match result.as_ref() {
            UserAutomationReadResult::List { revisions } => revisions.iter().collect(),
            UserAutomationReadResult::Status { revision, .. }
            | UserAutomationReadResult::InspectLastFailure { revision, .. } => vec![revision],
            UserAutomationReadResult::History { .. } => Vec::new(),
        };
        let mut projections = Vec::with_capacity(revisions.len());
        for revision in revisions {
            let identities = revision
                .compile_occurrence_identities()
                .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
            // Each compiled identity is projected together with the
            // deterministic successor the same revision compiler resolves. The
            // Human surface therefore sees the whole next-occurrence chain,
            // including the terminal occurrence whose successor is `None`,
            // instead of an unlabelled list it would have to re-derive.
            let mut occurrences = Vec::with_capacity(identities.len());
            for identity in &identities {
                let occurrence_key = match &identity.trigger {
                    eliot_kernel_core::user_automation::UserAutomationTrigger::Scheduled {
                        occurrence_key,
                    } => occurrence_key.as_str(),
                    eliot_kernel_core::user_automation::UserAutomationTrigger::Manual {
                        ..
                    } => {
                        return Err(UserAutomationRuntimeError::Rejected(
                            "compiled UserAutomation occurrence is not a calendar occurrence"
                                .to_owned(),
                        ));
                    }
                };
                let next_occurrence = revision
                    .next_occurrence_after(occurrence_key)
                    .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
                occurrences.push(serde_json::json!({
                    "identity": identity,
                    "next_occurrence": next_occurrence,
                }));
            }
            projections.push(
                serde_json::to_value(serde_json::json!({
                    "automation_id": revision.automation_id,
                    "revision": revision.revision,
                    "kind": revision.schedule.kind,
                    "expression": revision.schedule.expression,
                    "calendar": revision.schedule.calendar,
                    "timezone": revision.schedule.timezone,
                    "dst_fold": revision.schedule.dst_fold,
                    "dst_gap": revision.schedule.dst_gap,
                    "configuration_state": revision.configuration_state,
                    "occurrences": occurrences,
                }))
                .map_err(|error| {
                    UserAutomationRuntimeError::Rejected(format!(
                        "UserAutomation occurrence projection encoding failed: {error}"
                    ))
                })?,
            );
        }
        Ok(projections)
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
        // The run-now trigger is compiled by the same immutable revision
        // compiler that compiles a calendar occurrence, so the explicit manual
        // nonce is validated against the stored revision and receives a
        // distinct, stable, revision-bound identity instead of a value built
        // here beside the schedule. A nonce the revision cannot compile is a
        // typed rejection, not a second trigger vocabulary.
        let manual_trigger = match owner.revision.manual_trigger(&manual_nonce) {
            Ok(trigger) => trigger,
            Err(error) => {
                return Ok(Self::user_automation_runtime_error_response(
                    UserAutomationRuntimeError::Rejected(error.to_string()),
                ));
            }
        };
        let occurrence_id = match owner.revision.occurrence_identity_for(&manual_trigger) {
            Ok(occurrence_id) => occurrence_id,
            Err(error) => {
                return Ok(Self::user_automation_runtime_error_response(
                    UserAutomationRuntimeError::Rejected(error.to_string()),
                ));
            }
        };
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
    /// Revalidates one due scheduler wake against the canonical owner before any
    /// execution effect is requested.
    ///
    /// A scheduled occurrence has no committed `RunNow` receipt, so this leg
    /// proves the occurrence against the current owner projection and the live
    /// policy owner instead of against a Store receipt the owner never issued.
    /// The revalidation is deterministic: it reads the canonical current
    /// revision, its complete execution projection, and the same config/policy
    /// snapshot the owner-issued preflight receipt carries, and it reaches no
    /// model, provider, or scheduler call. A wake that is stale, paused,
    /// removed, superseded, already admitted, duplicate, or foreign is refused
    /// here with its closed cause, before any effect owner is contacted.
    async fn revalidate_user_automation_due_wake(
        &self,
        session: &Session,
        request: &UserAutomationRuntimeAdmission,
    ) -> Result<UserAutomationDueWakeResolution, UserAutomationDueWakeOutcome> {
        let runtime = |error| UserAutomationDueWakeOutcome::Runtime(error);
        let authenticated_principal =
            authenticated_user_automation_principal(session).map_err(|_| {
                runtime(UserAutomationRuntimeError::Rejected(
                    "UserAutomation session principal is unavailable".to_owned(),
                ))
            })?;
        request
            .validate()
            .map_err(|error| runtime(UserAutomationRuntimeError::Rejected(error.to_string())))?;
        if request.context.state_fence != session.module_generation.state_fence
            || request.authenticated_principal != authenticated_principal
        {
            return Err(runtime(UserAutomationRuntimeError::IdentityConflict));
        }
        let gateway = self.retained_store_gateway().map_err(|_| {
            runtime(UserAutomationRuntimeError::Unavailable(
                "canonical UserAutomation Store owner is unavailable".to_owned(),
            ))
        })?;
        let lookup = UserAutomationOwnerLookup {
            automation_id: request.invocation.automation_id.clone(),
            requested_revision: request.invocation.automation_revision.clone(),
            authenticated_principal: authenticated_principal.clone(),
            state_fence: session.module_generation.state_fence.clone(),
        };
        let owner = gateway
            .read_user_automation_owner(&lookup)
            .await
            .map_err(|error| runtime(UserAutomationRuntimeError::Unavailable(error)))?;
        let execution =
            Self::user_automation_owner_execution_projection(&gateway, &lookup, request)
                .await
                .map_err(runtime)?;
        let resolution = resolve_due_wake(&owner, request, &authenticated_principal, &execution)
            .map_err(UserAutomationDueWakeOutcome::Refused)?;
        resolution
            .validate_for(request)
            .map_err(|error| runtime(UserAutomationRuntimeError::Rejected(error.to_string())))?;
        // The owner-issued preflight receipt is deterministic evidence, not a
        // claim: it is re-compared here against the live policy owner and the
        // live admission state, so a receipt produced against a superseded
        // snapshot cannot carry a due wake into the effect owner.
        let policy_snapshot = self
            .read_user_automation_policy_snapshot(&lookup.state_fence)
            .await
            .map_err(runtime)?;
        let occurrence_id = resolution
            .invocation
            .occurrence_identity()
            .map_err(|error| runtime(UserAutomationRuntimeError::Rejected(error.to_string())))?;
        if request.preflight.automation_id != owner.automation_id
            || request.preflight.automation_revision != owner.revision.revision
            || request.preflight.occurrence_id != occurrence_id
            || request.preflight.work_class != owner.revision.work_class
            || request.preflight.config_snapshot_id != policy_snapshot.snapshot_id
            || request.preflight.config_snapshot != policy_snapshot
            || request.preflight.config_snapshot_id != request.preflight.config_snapshot.snapshot_id
            || request.preflight.configuration_state
                != eliot_kernel_core::user_automation::UserAutomationConfigurationState::Active
            || request.preflight.source_receipt.core.request.state_fence != lookup.state_fence
            || request.preflight.source_receipt.core.request.metadata != request.context
            || policy_snapshot.state_fence != lookup.state_fence
        {
            return Err(runtime(UserAutomationRuntimeError::IdentityConflict));
        }
        Ok(resolution)
    }

    /// Projects a decided owner revalidation into the answer to return, or
    /// `None` when the revalidation proved the operation.
    #[cfg(windows)]
    fn user_automation_owner_check(
        check: Result<(), UserAutomationRuntimeError>,
    ) -> Option<serde_json::Value> {
        match check {
            Ok(()) => None,
            Err(error) => Some(Self::user_automation_runtime_error_response(error)),
        }
    }

    /// Projects one due-wake revalidation into the answer to return, or `None`
    /// when the wake is still admissible.
    #[cfg(windows)]
    fn user_automation_due_wake_owner_check(
        check: Result<UserAutomationDueWakeResolution, UserAutomationDueWakeOutcome>,
    ) -> Option<serde_json::Value> {
        match check {
            Ok(_) => None,
            Err(UserAutomationDueWakeOutcome::Refused(rejection)) => {
                Some(Self::user_automation_due_wake_refused_response(&rejection))
            }
            Err(UserAutomationDueWakeOutcome::Runtime(error)) => {
                Some(Self::user_automation_runtime_error_response(error))
            }
        }
    }

    #[cfg(windows)]
    /// Reads the complete owner execution projection for one due wake.
    ///
    /// The read goes through the same `Status` projection the Durable Job owner
    /// maintains, and it inherits the complete-denominator gate, so the
    /// duplicate guard can never answer "no admitted job" from a bounded
    /// denominator. It reuses the carrier's admitted operation identity and
    /// issues no transition, so it mints no canonical identity.
    async fn user_automation_owner_execution_projection(
        gateway: &eliot_kernel_service::KernelStoreGateway,
        lookup: &UserAutomationOwnerLookup,
        request: &UserAutomationRuntimeAdmission,
    ) -> Result<
        eliot_kernel_core::user_automation::UserAutomationExecutionProjection,
        UserAutomationRuntimeError,
    > {
        gateway
            .read_user_automation_owner_execution_view(
                &eliot_kernel_service::UserAutomationServiceRequest {
                    context: request.context.clone(),
                    authenticated_principal: request.authenticated_principal.clone(),
                    identity: request.identity.clone(),
                    intent: eliot_kernel_core::UserAutomationOperatorIntent {
                        intent_id: format!(
                            "{}:due-wake-owner-execution-view",
                            request.identity.operation_id.as_str()
                        ),
                        principal_ref: request.authenticated_principal.clone(),
                        state_fence: lookup.state_fence.clone(),
                        operation: eliot_kernel_core::UserAutomationOperation::Status {
                            automation_id: lookup.automation_id.clone(),
                        },
                    },
                },
                &lookup.automation_id,
            )
            .await
            .map_err(UserAutomationRuntimeError::Unavailable)
    }

    /// Consumes one authenticated owner wake (issue #2806 items 5 and 6).
    ///
    /// The order is fixed: resolve the exact current automation, revision, and
    /// occurrence; prove the retained wake is the owner's own pending record for
    /// that occurrence; then cross into the same execution join `run-now` uses.
    /// Every refusal happens before the effect owner is contacted, and a refusal
    /// returns the closed cause and the existing operation rather than prose.
    ///
    /// After the Durable Job owner acknowledges the admission, the next bounded
    /// recurring horizon slice is requested through the same schedule owner
    /// (item 6). The advance recompiles the denominator from the immutable
    /// revision the wake resolved against, so it never mutates that revision and
    /// never produces a time outside its normalized contract.
    #[cfg(windows)]
    async fn user_automation_due_wake_operation(
        &self,
        session: &Session,
        request: UserAutomationRuntimeAdmission,
        client: &UserAutomationHostExecutionClient<
            AuthenticatedUserAutomationHostExecutionTransport,
        >,
    ) -> Result<serde_json::Value, TransportError> {
        let resolution = match self
            .revalidate_user_automation_due_wake(session, &request)
            .await
        {
            Ok(resolution) => resolution,
            Err(UserAutomationDueWakeOutcome::Refused(rejection)) => {
                return Ok(Self::user_automation_due_wake_refused_response(&rejection));
            }
            Err(UserAutomationDueWakeOutcome::Runtime(error)) => {
                return Ok(Self::user_automation_runtime_error_response(error));
            }
        };
        let occurrence_id = match request.invocation.occurrence_identity() {
            Ok(occurrence_id) => occurrence_id,
            Err(error) => {
                return Ok(Self::user_automation_runtime_error_response(
                    UserAutomationRuntimeError::Rejected(error.to_string()),
                ));
            }
        };
        let read_request = UserAutomationWakeReadRequest {
            context: request.context.clone(),
            authenticated_principal: request.authenticated_principal.clone(),
            identity: request.identity.clone(),
            invocation: request.invocation.clone(),
        };
        let readback = match Self::user_automation_due_wake_readback(
            session,
            &occurrence_id,
            &read_request,
            client,
        )
        .await
        {
            UserAutomationDueWakeRead::Proven(readback) => readback,
            UserAutomationDueWakeRead::Answer(answer) => return Ok(answer),
        };
        // One stable occurrence may produce at most one admitted job/effect. The
        // carrier is the same owner-issued admission `run-now` uses, so the
        // Durable Job owner's own operation identity is the at-most-once
        // boundary; the revalidation above already refused any occurrence that
        // the complete owner projection shows as already admitted.
        let execution = match client.admit_occurrence(request.clone()).await {
            Ok(execution) => execution,
            Err(error) => {
                // No owner acknowledged a disposition, so the recurring horizon
                // does not advance: this wake is still unconsumed and a later
                // owner-issued submission can admit it.
                return Ok(Self::user_automation_runtime_error_response(error));
            }
        };
        if let Err(error) = execution.validate() {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::Rejected(error.to_string()),
            ));
        }
        if execution.occurrence_id != occurrence_id {
            return Ok(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::IdentityConflict,
            ));
        }
        let horizon = Self::user_automation_due_wake_horizon(
            session,
            &resolution,
            &occurrence_id,
            &request,
            client,
        )
        .await;
        let recovery = Self::user_automation_horizon_recovery(&horizon);
        Ok(serde_json::json!({
            "status": if recovery.is_none() { "known" } else { "unknown" },
            "value": {
                "outcome": "admitted",
                "execution": execution,
                "resolution": resolution,
                "wake_readback": readback,
                "horizon": horizon,
            },
            "recovery": recovery,
        }))
    }

    /// Proves the retained wake is the schedule owner's own pending record for
    /// the resolved occurrence.
    ///
    /// The wake owner is the sole writer of its journal, so the only proof that
    /// this occurrence was published as a pending wake is the owner's own
    /// retained record read back over the authenticated channel. A `WakeIntent`
    /// that merely exists grants nothing; a record the owner no longer offers as
    /// pending is a duplicate or a superseded delivery and is refused here,
    /// before any effect owner is contacted.
    #[cfg(windows)]
    async fn user_automation_due_wake_readback(
        session: &Session,
        occurrence_id: &str,
        read_request: &UserAutomationWakeReadRequest,
        client: &UserAutomationHostExecutionClient<
            AuthenticatedUserAutomationHostExecutionTransport,
        >,
    ) -> UserAutomationDueWakeRead {
        let readback: UserAutomationWakeReadback = match client
            .read_pending_wake(read_request.clone())
            .await
        {
            Ok(readback) => readback,
            Err(UserAutomationRuntimeError::Unavailable(reason)) => {
                return UserAutomationDueWakeRead::Answer(
                        Self::user_automation_due_wake_refused_response(
                            &UserAutomationDueWakeRejection::new(
                                eliot_kernel_service::UserAutomationDueWakeRejectionCause::WakeNotRetained,
                                occurrence_id.to_owned(),
                                format!(
                                    "the schedule owner retains no pending wake for this \
                                     occurrence: {reason}"
                                ),
                            ),
                        ),
                    );
            }
            Err(error) => {
                return UserAutomationDueWakeRead::Answer(
                    Self::user_automation_runtime_error_response(error),
                );
            }
        };
        if let Some(rejection) = refuse_consumed_wake(occurrence_id, &readback.intent) {
            return UserAutomationDueWakeRead::Answer(
                Self::user_automation_due_wake_refused_response(&rejection),
            );
        }
        if readback.intent.wake_id != occurrence_id
            || readback.intent.state_fence != session.module_generation.state_fence
        {
            return UserAutomationDueWakeRead::Answer(
                Self::user_automation_due_wake_refused_response(
                    &UserAutomationDueWakeRejection::new(
                        eliot_kernel_service::UserAutomationDueWakeRejectionCause::ForeignWake,
                        occurrence_id.to_owned(),
                        "the retained wake belongs to another occurrence or State Fence than the \
                         occurrence the canonical owner resolved",
                    ),
                ),
            );
        }
        if let Err(error) = readback.validate_for(read_request) {
            return UserAutomationDueWakeRead::Answer(
                Self::user_automation_runtime_error_response(UserAutomationRuntimeError::Rejected(
                    error.to_string(),
                )),
            );
        }
        UserAutomationDueWakeRead::Proven(readback)
    }

    /// Requests the next bounded recurring horizon slice after an
    /// owner-acknowledged admission (issue #2806 item 6).
    ///
    /// The advance happens only after the Durable Job owner acknowledged the
    /// occurrence, and its cursor is the consumed occurrence's place in the
    /// immutable revision's own normalized denominator. A request that was never
    /// sent, or whose answer was lost, keeps the exact remaining occurrence set
    /// and the replay handle instead of reporting a published horizon.
    #[cfg(windows)]
    async fn user_automation_due_wake_horizon(
        session: &Session,
        resolution: &UserAutomationDueWakeResolution,
        occurrence_id: &str,
        request: &UserAutomationRuntimeAdmission,
        client: &UserAutomationHostExecutionClient<
            AuthenticatedUserAutomationHostExecutionTransport,
        >,
    ) -> UserAutomationHorizonPhase {
        let denominator_occurrence_ids = resolution
            .revision
            .compile_occurrence_identities()
            .map(|identities| {
                identities
                    .iter()
                    .map(|identity| identity.occurrence_id.clone())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        let publication = match advance_wake_horizon(
            resolution,
            occurrence_id,
            request.context.clone(),
            request.authenticated_principal.clone(),
            request.identity.clone(),
            session.module_generation.state_fence.clone(),
        ) {
            Ok(publication) => publication,
            Err(error) => {
                return Self::user_automation_unacknowledged_horizon(
                    resolution,
                    &denominator_occurrence_ids,
                    &request.identity,
                    &format!(
                        "the next bounded horizon slice for the resolved revision could not be \
                         compiled from its own normalized contract: {error}"
                    ),
                    false,
                );
            }
        };
        let requested_occurrence_ids = publication.requested_occurrence_ids();
        if requested_occurrence_ids.is_empty() {
            return Self::user_automation_unacknowledged_horizon(
                resolution,
                &denominator_occurrence_ids,
                &request.identity,
                "the resolved revision has no remaining occurrence after the admitted one, so there \
                 is no next horizon slice to request",
                false,
            );
        }
        match UserAutomationWakePort::publish_wake_horizon(client, publication.clone()).await {
            Ok(acknowledgement) => Self::user_automation_acknowledged_horizon(
                resolution,
                &publication,
                &requested_occurrence_ids,
                acknowledgement,
            ),
            Err(error) => {
                let reason = error.to_string();
                let unknown = !matches!(error, UserAutomationRuntimeError::Unavailable(_));
                Self::user_automation_unacknowledged_horizon(
                    resolution,
                    &denominator_occurrence_ids,
                    &request.identity,
                    &reason,
                    unknown,
                )
            }
        }
    }

    /// Projects one horizon the schedule owner did not acknowledge.
    ///
    /// The remainder retained here is the resolved revision's own complete
    /// normalized denominator: it is the exact set an owner still has to be asked
    /// about, and it is derived from the immutable revision rather than from the
    /// failed call. An empty set would claim that nothing is outstanding, which is
    /// exactly what this contour cannot prove, and the replay handle is derived
    /// from that same immutable digest and the parent operation identity, so it
    /// names the retry without authorizing it.
    #[cfg(windows)]
    fn user_automation_unacknowledged_horizon(
        resolution: &UserAutomationDueWakeResolution,
        denominator_occurrence_ids: &[String],
        identity: &OperationIdentity,
        reason: &str,
        unknown: bool,
    ) -> UserAutomationHorizonPhase {
        let requested = denominator_occurrence_ids.to_vec();
        let outcome = if unknown {
            UserAutomationHorizonOutcome::UnknownOutcome {
                reason: reason.to_owned(),
            }
        } else {
            UserAutomationHorizonOutcome::Unavailable {
                reason: reason.to_owned(),
            }
        };
        let retry_handle = horizon_retry_handle(
            identity,
            &resolution.revision_digest,
            denominator_occurrence_ids,
        )
        .unwrap_or_else(|_| {
            format!(
                "ua-horizon-retry:unresolved:{}:{}",
                identity.operation_id.as_str(),
                resolution.revision_digest
            )
        });
        UserAutomationHorizonPhase {
            trigger: UserAutomationHorizonTrigger::DispositionAdvance,
            automation_id: resolution.revision.automation_id.clone(),
            automation_revision: resolution.revision.revision.clone(),
            revision_digest: resolution.revision_digest.clone(),
            remaining_occurrence_ids: requested.clone(),
            requested_occurrence_ids: requested,
            retry_handle,
            outcome,
        }
    }

    /// Projects one owner-acknowledged horizon answer.
    ///
    /// A published horizon is an owner acknowledgement of every requested
    /// occurrence. A partial answer keeps the exact remaining set and the owner's
    /// own replay handle beside the reason, so it can never be read as a
    /// published wake set. An answer that does not account for the request is
    /// treated as unknown rather than as a partial success, because a
    /// mismatched remainder is not evidence about any occurrence.
    #[cfg(windows)]
    fn user_automation_acknowledged_horizon(
        resolution: &UserAutomationDueWakeResolution,
        publication: &UserAutomationWakeHorizonPublication,
        requested_occurrence_ids: &[String],
        acknowledgement: UserAutomationWakePublication,
    ) -> UserAutomationHorizonPhase {
        if let Err(error) = acknowledgement.validate_for(publication) {
            return Self::user_automation_unacknowledged_horizon(
                resolution,
                requested_occurrence_ids,
                &publication.identity,
                &format!(
                    "the schedule owner answer does not account for the requested horizon: {error}"
                ),
                true,
            );
        }
        let publication_operation_id = Box::new(acknowledgement.publication_operation_id.clone());
        let outcome = if acknowledgement.acknowledged_all() {
            UserAutomationHorizonOutcome::Published {
                publication_operation_id,
            }
        } else {
            UserAutomationHorizonOutcome::Partial {
                publication_operation_id,
                reason: format!(
                    "the schedule owner acknowledged {} of the {} occurrences that follow the \
                     admitted one; the exact remaining set is retained and must be replayed under \
                     its handle",
                    acknowledgement.acknowledged_occurrence_ids.len(),
                    requested_occurrence_ids.len()
                ),
            }
        };
        UserAutomationHorizonPhase {
            trigger: publication.trigger,
            automation_id: publication.automation_id.clone(),
            automation_revision: publication.automation_revision.clone(),
            revision_digest: publication.revision_digest.clone(),
            remaining_occurrence_ids: acknowledgement.remaining_occurrence_ids,
            requested_occurrence_ids: requested_occurrence_ids.to_vec(),
            retry_handle: acknowledgement.retry_handle,
            outcome,
        }
    }

    /// Projects the recovery directive of one bounded horizon, including the
    /// exact remaining occurrence set and the replay handle the caller must use.
    #[cfg(windows)]
    fn user_automation_horizon_recovery(
        horizon: &UserAutomationHorizonPhase,
    ) -> Option<serde_json::Value> {
        let (kind, reason) = match &horizon.outcome {
            UserAutomationHorizonOutcome::Published { .. } => return None,
            UserAutomationHorizonOutcome::Partial { reason, .. }
            | UserAutomationHorizonOutcome::UnknownOutcome { reason } => {
                ("unknown_outcome", reason)
            }
            UserAutomationHorizonOutcome::Unavailable { reason } => ("unavailable", reason),
        };
        Some(serde_json::json!({
            "kind": kind,
            "reason": reason,
            "automation_id": horizon.automation_id,
            "automation_revision": horizon.automation_revision,
            "remaining_occurrence_ids": horizon.remaining_occurrence_ids,
            "retry_handle": horizon.retry_handle,
        }))
    }

    /// Projects one refused due wake.
    ///
    /// A refusal is a decided answer, not an unknown one: the wake was refused
    /// before any effect, nothing is pending, and nothing was admitted. The
    /// closed cause and, for a duplicate delivery, the already-admitted Durable
    /// Job reference are returned so the caller reconciles that same operation
    /// instead of issuing a new one.
    #[cfg(windows)]
    fn user_automation_due_wake_refused_response(
        rejection: &UserAutomationDueWakeRejection,
    ) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": {
                "accepted": false,
                "outcome": "due_wake_refused",
                "cause": rejection.cause,
                "occurrence_id": rejection.occurrence_id,
                "owner_configuration_state": rejection.owner_configuration_state,
                "existing_execution": rejection.existing_execution,
                "reason": rejection.reason,
            },
            "recovery": null,
        })
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
        // Implements #1967 W3: an origin-control grant issues authority, so
        // the decide path requires Material admission (startup gates plus a
        // material-grade profile) before touching the process gateway. The
        // rejection names the unmet prerequisite. Emergency process kills
        // continue through the Job/watchdog owners, never this grant path.
        if let Some(rejection) = self.material_authority_admission_response() {
            return Ok(rejection);
        }
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
        // Implements #1967 W4 (I1.11 step 8): the rebuilt Config mirror is
        // byte-equal to the Kernel-protected snapshot digest, so the mirror
        // half of step 8 is proven by the Kernel-owned comparison above.
        // Policy-snapshot ownership stays with its future R1 owner: presence
        // is reported below but never synthesized into a success claim.
        self.record_startup_evidence(8)
            .map_err(|_| TransportError::SessionFenced)?;
        let mut steps_recorded = vec![8_u8];
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
        if capabilities_complete {
            // Implements #1967 W4 (I1.11 step 9): the required set is covered
            // by live outcomes bound to the active generation fingerprint and
            // the registry digest recomputes exactly, so the
            // required-capability evaluation is proven mechanically.
            // Optional failures surface through `daemon_degraded`, never as
            // silent Material.
            self.record_startup_evidence(9)
                .map_err(|_| TransportError::SessionFenced)?;
            steps_recorded.push(9);
        }

        if evidence.policy_mirror_digest.is_none() {
            return Ok(Self::partial_startup_evidence_response(
                &steps_recorded,
                "policy_owner_snapshot_absent",
            ));
        }
        if !capabilities_complete {
            return Ok(Self::partial_startup_evidence_response(
                &steps_recorded,
                "required_capability_owner_snapshot_absent",
            ));
        }
        Ok(Self::accepted_startup_evidence_response(&steps_recorded))
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

    /// Reports validated Governor evidence with the steps it actually
    /// recorded. `accepted` means the payload was well-formed, fence-bound,
    /// and mechanically validated; `reason` names the owner input still
    /// missing for complete evidence. Partial progress is recorded, never
    /// synthesized: absent markers leave their steps absent.
    fn partial_startup_evidence_response(
        steps_recorded: &[u8],
        reason: &'static str,
    ) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": {
                "accepted": true,
                "recorded": true,
                "steps_recorded": steps_recorded,
                "reason": reason,
            },
            "recovery": null,
        })
    }

    /// Reports fully validated Governor evidence with every recorded step.
    fn accepted_startup_evidence_response(steps_recorded: &[u8]) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": {
                "accepted": true,
                "recorded": true,
                "steps_recorded": steps_recorded,
                "reason": null,
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

    /// Typed outcome for an honestly deferred observe pair (issue #2565).
    ///
    /// The flight consumed the claimed pair and the durable record advanced
    /// to `Routed`, but the Governor observation owner has no connected
    /// admission yet: no effect was produced and none is claimed. `accepted`
    /// records the deferral itself (pair retired, phase advanced); `deferred`
    /// distinguishes it from a result persist, and the operation identity is
    /// the exact resume handle the waiter keeps polling.
    fn deferred_observe_daemon_response(operation_id: &str) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": {
                "accepted": true,
                "deferred": true,
                "operation_id": operation_id,
            },
            "recovery": null,
        })
    }

    /// Typed outcome when a deferral arrives for an already-terminal record.
    ///
    /// Nothing is outstanding: the waiter path serves the stored truth, so
    /// the daemon idles. `settled` distinguishes this from a fresh deferral;
    /// the operation identity names the record to consult.
    fn settled_observe_daemon_response(operation_id: &str) -> serde_json::Value {
        serde_json::json!({
            "status": "known",
            "value": {
                "accepted": true,
                "settled": true,
                "operation_id": operation_id,
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
            Ok(snapshot) => {
                // Implements #1967 W4 (I1.11 step 6): the gateway returns
                // only a validated same-fence snapshot (shape, fence, and
                // record binding are checked inside `recovery`), so a
                // successful recovery proves pending/unknown operations are
                // reconciled before normal writes are enabled.
                self.record_startup_evidence(6)
                    .map_err(|_| TransportError::SessionFenced)?;
                Ok(store_recovery_response(&snapshot))
            }
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
        if let Some(rejection) =
            self.material_write_admission_response(&operation.context.state_fence)
        {
            return Ok(rejection);
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
        // rendered through the existing store-error response shape. The
        // carried ordering scopes must also still equal the hashed expected
        // ordering heads: a post-admission scope edit leaves the shared
        // digest unchanged but changes head advancement, so it fails here
        // with the same typed mismatch.
        {
            if let Err(error) = verify_ordering_scope_binding(
                &operation.transition,
                &operation.expected_ordering_heads,
            ) {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    &error.to_string(),
                ));
            }
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
        let gateway = self.retained_store_gateway()?;
        if let Some(replayed) = self
            .replay_committed_apply_receipt(&gateway, &operation)
            .await?
        {
            return Ok(replayed);
        }
        if let Some(rejection) =
            self.material_write_admission_response(&operation.context.state_fence)
        {
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

    /// Resolves an already-committed `Apply` receipt for this exact operation
    /// identity.
    ///
    /// A committed receipt is an exact, read-only replay result, so it is
    /// resolved before the Material gate and response-loss recovery stays
    /// reachable while degraded. The receipt must be the same terminal receipt
    /// for the same operation: a different operation identity, idempotency
    /// key, canonical request hash, State Fence, or a non-committed status is
    /// an identity conflict and never a fresh write. An unreadable receipt
    /// read is not a coverage observation either, so it yields `None` and
    /// leaves the decision to the callers below.
    #[cfg(windows)]
    async fn replay_committed_apply_receipt(
        &self,
        gateway: &Arc<KernelStoreGateway>,
        operation: &StoreApplyOperation,
    ) -> Result<Option<serde_json::Value>, TransportError> {
        let Ok(Some(receipt)) = gateway
            .receipt(
                &operation.context.state_fence,
                operation.transition.identity.operation_id.clone(),
            )
            .await
        else {
            return Ok(None);
        };
        if receipt.operation_id != operation.transition.identity.operation_id
            || receipt.idempotency_key != operation.transition.identity.idempotency_key
            || receipt.canonical_request_hash
                != operation.transition.identity.canonical_request_hash
            || receipt.state_fence != operation.context.state_fence
            || receipt.status != eliot_store_api::WriteReceiptStatus::Committed
        {
            return Err(TransportError::IdentityConflict);
        }
        receipt
            .validate()
            .map_err(|_| TransportError::IdentityConflict)?;
        Ok(Some(store_apply_response(&receipt)))
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

    /// Admits one canonical notification lifecycle transition (issue #1780).
    ///
    /// This is the Kernel-owned write route for all four I11.5/I11.7 legs.
    /// The authenticated owner session submits an already-admitted plan whose
    /// only named operation is the store contract's
    /// `ApplyNotificationState`; the Kernel re-checks the closed transition
    /// class, the fixed notification scope and ordering scope, and the closed
    /// leg parameter set against the store contract itself, recomputes the
    /// canonical request hash, and dispatches exactly once through the
    /// retained production store gateway (the spawned
    /// `eliot-store-surreal.exe` bridge, not the Kernel's ORS file).
    ///
    /// The committed receipt is then proved by a same-fence read-back of the
    /// addressed record. That read-back is what makes "created or updated
    /// before the delivery attempt" observable: the caller learns the
    /// canonical record exists at the admitted fence, and the Notify launch
    /// grant's own durable-record join ([`Self::require_durable_notification_record`])
    /// can then refuse a delivery attempt for a record that does not persist.
    /// Any other class, scope, or leg fails closed before the gateway is
    /// entered; an uncommitted or misfenced outcome never reports success.
    #[cfg(windows)]
    async fn notification_state_operation(
        &self,
        session: &Session,
        request_id: RequestId,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        // The daemon client routes on the `operation` key it inserts into every
        // body; this carrier decodes the whole body, so that routing key is
        // removed before the closed decode instead of being refused as unknown
        // (see `without_daemon_routing_key`).
        let operation: NotificationStateApplyOperation =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        if let Some(refusal) =
            Self::validate_notification_state_apply(session, &request_id, &operation)?
        {
            return Ok(refusal);
        }
        if let Some(rejection) = self.normal_write_admission_response() {
            return Ok(rejection);
        }
        let (dedup_key, notification_id) =
            notification_state_read_selectors(&operation.transition)?;
        let state_fence = operation.transition.state_fence.clone();
        let gateway = self.retained_store_gateway()?;
        let receipt = match gateway
            .apply(
                &operation.context,
                operation.transition,
                operation.expected_revision_heads,
                operation.expected_ordering_heads,
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => {
                return Ok(Self::store_error_response_text(
                    NOTIFICATION_STATE_RESPONSE_KIND,
                    &error,
                ));
            }
        };
        if receipt.status != eliot_store_api::WriteReceiptStatus::Committed {
            return Ok(Self::store_error_response_text(
                NOTIFICATION_STATE_RESPONSE_KIND,
                "canonical notification transition was not committed",
            ));
        }
        if receipt.state_fence != state_fence {
            return Err(TransportError::SessionFenced);
        }
        // Same-fence read-back: the receipt alone is not the record. A commit
        // whose record is not readable at the admitted fence is not a
        // successful canonical write and never reports one.
        let page = self
            .read_notification_page(&NotificationPageQuery::addressed_record(
                &state_fence,
                dedup_key,
                notification_id,
            ))
            .await?;
        if page
            .get(eliot_store_api::NOTIFY_PAGE_RECORDS)
            .and_then(serde_json::Value::as_array)
            .is_none_or(Vec::is_empty)
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(serde_json::json!({
            "status": "known",
            "value": {
                "kind": NOTIFICATION_STATE_RESPONSE_KIND,
                "value": { "receipt": receipt, "page": page },
            },
            "recovery": null,
        }))
    }

    /// Every closed-plan check the canonical notification write must pass
    /// before the store gateway is entered (issue #1780).
    ///
    /// `Ok(None)` means the transition is proved and may be dispatched;
    /// `Ok(Some(text))` is a fail-closed refusal the route returns verbatim;
    /// `Err` is the session-fence refusal, which never becomes a store error
    /// response because it is not an owner rejection.
    ///
    /// The order is fixed and is the audited one: request-identity binding,
    /// request-metadata validation, the transition's own validation, the
    /// closed notification-state plan check, the store session fence, the
    /// transition/context fence agreement, every expected head's own
    /// validation and fence agreement, the ordering-scope binding, and finally
    /// the canonical request hash recomputed from the exact values about to be
    /// executed — a plan edited after admission fails here instead of entering
    /// the store bridge.
    #[cfg(windows)]
    fn validate_notification_state_apply(
        session: &Session,
        request_id: &RequestId,
        operation: &NotificationStateApplyOperation,
    ) -> Result<Option<serde_json::Value>, TransportError> {
        if operation.context.request_id != *request_id {
            return Err(TransportError::SessionFenced);
        }
        operation
            .context
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.transition.validate() {
            return Ok(Some(Self::store_error_response_text(
                NOTIFICATION_STATE_RESPONSE_KIND,
                &error.to_string(),
            )));
        }
        if let Err(error) = validate_notification_state_transition(&operation.transition) {
            return Ok(Some(Self::store_error_response_text(
                NOTIFICATION_STATE_RESPONSE_KIND,
                &error,
            )));
        }
        validate_store_session_fence(session, &operation.context.state_fence)?;
        if operation.transition.state_fence != operation.context.state_fence {
            return Err(TransportError::SessionFenced);
        }
        for head in &operation.expected_revision_heads {
            if let Err(error) = head.validate() {
                return Ok(Some(Self::store_error_response_text(
                    NOTIFICATION_STATE_RESPONSE_KIND,
                    &error.to_string(),
                )));
            }
            if head.state_fence != operation.context.state_fence {
                return Err(TransportError::SessionFenced);
            }
        }
        for head in &operation.expected_ordering_heads {
            if let Err(error) = head.validate() {
                return Ok(Some(Self::store_error_response_text(
                    NOTIFICATION_STATE_RESPONSE_KIND,
                    &error.to_string(),
                )));
            }
            if head.state_fence != operation.context.state_fence {
                return Err(TransportError::SessionFenced);
            }
        }
        if let Err(error) =
            verify_ordering_scope_binding(&operation.transition, &operation.expected_ordering_heads)
        {
            return Ok(Some(Self::store_error_response_text(
                NOTIFICATION_STATE_RESPONSE_KIND,
                &error.to_string(),
            )));
        }
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
            return Ok(Some(Self::store_error_response_text(
                NOTIFICATION_STATE_RESPONSE_KIND,
                &error.to_string(),
            )));
        }
        Ok(None)
    }

    /// No durable canonical store exists off Windows: the retained store
    /// gateway is a Windows-only contour, so the canonical notification write
    /// is unprovable here and the route fails closed.
    #[cfg(not(windows))]
    async fn notification_state_operation(
        &self,
        _session: &Session,
        _request_id: RequestId,
        _payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        Err(TransportError::SessionFenced)
    }

    /// Serves one bounded canonical notification inbox page (issue #1780).
    ///
    /// Same-fence projection only, through the same retained production store
    /// gateway the transition route uses. The selectors are the store
    /// contract's closed set, so an unresolved acknowledged record, an
    /// unresolved failed-delivery record, and an unresolved critical record
    /// all stay visible: there is no quiet-hours, role, or delivery-visibility
    /// input this read could be narrowed by (I11.7, I11.10).
    #[cfg(windows)]
    async fn notification_state_read_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: NotificationStateReadOperation =
            serde_json::from_value(payload).map_err(|_| TransportError::SessionFenced)?;
        validate_store_session_fence(session, &operation.state_fence)?;
        let page = self
            .read_notification_page(&NotificationPageQuery::from_read_operation(&operation))
            .await?;
        Ok(serde_json::json!({
            "status": "known",
            "value": { "kind": NOTIFICATION_STATE_PAGE_RESPONSE_KIND, "value": page },
            "recovery": null,
        }))
    }

    #[cfg(not(windows))]
    async fn notification_state_read_operation(
        &self,
        _session: &Session,
        _payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        Err(TransportError::SessionFenced)
    }

    /// Reads one bounded canonical notification page through the retained
    /// production store gateway and proves the echoed operation and fence.
    ///
    /// The one read seam both notification routes share: the transition's
    /// post-commit read-back, the owner inbox read, and the Notify launch
    /// grant's durable-record join all resolve the record through this single
    /// call, so none of them can observe a different projection shape. The
    /// selectors and the fence arrive as one [`NotificationPageQuery`], so the
    /// echoed fence is proved against the same fence the query was built for.
    #[cfg(windows)]
    async fn read_notification_page(
        &self,
        query: &NotificationPageQuery,
    ) -> Result<serde_json::Value, TransportError> {
        let request = query
            .read_request()
            .map_err(|_| TransportError::SessionFenced)?;
        let gateway = self.retained_store_gateway()?;
        let response = gateway
            .execute_named(request)
            .await
            .map_err(|_| TransportError::SessionFenced)?;
        if response.operation != eliot_store_api::NamedReadOperation::GetNotificationState
            || response.state_fence != query.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(response.payload)
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
        // The daemon client routes on the `operation` key it inserts into every
        // body; this carrier decodes the whole body, so that routing key is
        // removed before the closed decode instead of being refused as unknown
        // (see `without_daemon_routing_key`).
        let operation: StoreNamedOperation =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
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
        let selectors = match admission {
            host_request_route::LocalReadAdmission::Query(selectors) => selectors,
            host_request_route::LocalReadAdmission::CampaignPacket { .. } => {
                // `local_read` is the query-only Gateway leg. A campaign
                // packet is served only by the dedicated packet claim/compile/
                // result flight; admitting it here would risk reinterpreting
                // packet material as `GetEvidencePack` selectors.
                return Err(TransportError::SessionFenced);
            }
        };
        let (receipt, record) = self.admit_host_request_envelope(&envelope)?;
        if let Some(replayed) =
            host_request_route::local_read_replay_response(&receipt, &record, &envelope)?
        {
            return Ok(replayed);
        }
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
    /// (`#1780` D4a, `#1955`) and demand-starts its installation-approved
    /// host parent (`#2568` A1): the production caller of
    /// `eliot_kernel_service::publish_wasm_dispatch_bundle` and of
    /// [`Self::start_wasm_host_parent`].
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
    /// After staging, the re-hashed host image is started through the
    /// admitted process gateway with argv from the validated material, so a
    /// real ordinary request reaches the host request loop; a refused start
    /// fails the operation closed (the staged set stays for the delivery
    /// owner — cleanup is `#2786` territory, never an invented delete
    /// here). The computed one-shot join gate is projected into the receipt
    /// so the live join table can close over it; no second registry is
    /// retained here.
    #[allow(
        clippy::too_many_lines,
        reason = "the admitted-path bundle publication keeps decode, fence/ready/claim/snapshot gates, host re-hash, publish, demand-start, and receipt projection in one audited order"
    )]
    async fn wasm_dispatch_bundle_operation(
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
        self.admit_material_authority_for_fence(
            GovernanceProfile::full(),
            &session.module_generation.state_fence,
        )
        .map_err(|_| TransportError::SessionFenced)?;
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
        let launch = self
            .start_wasm_host_parent(
                &bundle,
                host_executable_path.as_str(),
                host_artifact_digest.as_str(),
                install_dir,
            )
            .await?;
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
                "launch": "started",
                "launch_request_digest": launch.request_digest(),
                "launch_permit_digest": launch.permit_digest(),
            },
        }))
    }

    /// Demand-starts the installation-approved `eliot-wasm-host.exe` parent
    /// for one published dispatch bundle through the admitted process
    /// gateway (`#2568` A1): the governed demand-start half of bundle
    /// publication (I1.5 startup: start only the remaining capabilities
    /// required by the admitted request).
    ///
    /// The P-03 intent carries the re-hashed host image, the install
    /// directory as its working directory, and argv assembled from the
    /// validated material only (`--profile <profile>` — the closed
    /// publisher-checked spelling the host CLI requires before it reaches
    /// `run_ordinary_request_loop`; no nonce, handle, or path travels on
    /// the command line). The intent operation is the admitted claim
    /// operation, so the receipt's `operation_id` is exactly the supervised
    /// process's operation; tree/job/image/session, fence, and lease derive
    /// from it under the `wasm-host-launch` prefix, mirroring the
    /// Doctor/testd/native-worker dispatch contour (`spawn_ready_child`).
    /// Environment is secret-free, limits are the same bounded contour, and
    /// supervision stays with the gateway owner (replay begin for exact
    /// resubmits, path-lease re-proof at launch, inspect/cancel by
    /// operation). Every refusal — no gateway, stale snapshot, an image
    /// outside the retained root, or an unknown spawn outcome — fails
    /// closed; the staged set is left for the delivery owner (`#2786`), and
    /// no launch table or reconciler is kept here.
    #[cfg(windows)]
    async fn start_wasm_host_parent(
        &self,
        bundle: &eliot_kernel_service::WasmPublishedBundle,
        host_executable_path: &str,
        host_artifact_digest: &str,
        install_dir: &std::path::Path,
    ) -> Result<ProcessStartReceipt, TransportError> {
        let material = &bundle.material;
        let operation_id = OperationId::new(material.operation_id.clone())
            .map_err(|_| TransportError::SessionFenced)?;
        let short: String = operation_id.as_str().chars().take(16).collect();
        let generation =
            Generation::new(material.generation).map_err(|_| TransportError::SessionFenced)?;
        let working_directory = install_dir.to_str().ok_or(TransportError::SessionFenced)?;
        let intent = ProcessIntent::new(
            operation_id,
            ProcessTreeId::new(format!("wasm-host-launch-tree-{short}"))
                .map_err(|_| TransportError::SessionFenced)?,
            JobId::new(format!("wasm-host-launch-job-{short}"))
                .map_err(|_| TransportError::SessionFenced)?,
            ImageId::new(format!("wasm-host-launch-image-{short}"))
                .map_err(|_| TransportError::SessionFenced)?,
            SessionId::new(format!("wasm-host-launch-session-{short}"))
                .map_err(|_| TransportError::SessionFenced)?,
            generation,
            host_executable_path.to_owned(),
            host_artifact_digest.to_owned(),
            vec!["--profile".to_owned(), material.profile.clone()],
            working_directory.to_owned(),
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .map_err(|_| TransportError::SessionFenced)?,
            ResourceLimits::new(86_400_000, None, None, 64 * 1024, 64 * 1024, 4)
                .map_err(|_| TransportError::SessionFenced)?,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let fence = FencingToken::new(
            material.authority_epoch.clone(),
            generation,
            format!("wasm-host-launch-fence-{short}"),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let admission = ProcessExecutionAdmissionRequest::new(
            WASM_HOST_MODULE_ID,
            intent,
            ActionLeaseRef::new(format!("wasm-host-launch-kernel-launch-{short}"))
                .map_err(|_| TransportError::SessionFenced)?,
            fence,
            unix_ms().saturating_add(60_000),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        admission
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let gateway = self
            .process_gateway
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let expectation = super::current_process_named_pipe_expectation()
            .map_err(|_| TransportError::SessionFenced)?;
        let owner = ProcessOwnerBinding::new(
            WASM_HOST_MODULE_ID,
            super::runtime_identity::stable_owner_principal_digest(
                expectation.expected_sid(),
                WASM_HOST_MODULE_ID,
                &material.authority_epoch,
                generation,
            ),
            material.authority_epoch.clone(),
            generation,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        self.admit_material_process_start(&admission)
            .map_err(|_| TransportError::SessionFenced)?;
        let proof = self
            .retain_process_path_proof(&admission)
            .map_err(|_| TransportError::SessionFenced)?;
        gateway
            .start(&owner, admission, proof)
            .await
            .map_err(|_| TransportError::SessionFenced)
    }

    /// Demand-start fails closed off the Windows process contour: the
    /// installer-pinned `.exe` image cannot run there, so no silent
    /// publish-only success is reported.
    #[cfg(not(windows))]
    async fn start_wasm_host_parent(
        &self,
        _bundle: &eliot_kernel_service::WasmPublishedBundle,
        _host_executable_path: &str,
        _host_artifact_digest: &str,
        _install_dir: &std::path::Path,
    ) -> Result<ProcessStartReceipt, TransportError> {
        Err(TransportError::SessionFenced)
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
        self.admit_material_authority_for_fence(
            GovernanceProfile::full(),
            &session.module_generation.state_fence,
        )
        .map_err(|_| TransportError::SessionFenced)?;
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
    /// binder). This performs no canonical write: record creation is the
    /// owner's job on the admitted [`NOTIFICATION_STATE_MUTATION_OPERATION`]
    /// route, and this join only proves that record already persists before a
    /// Notify launch is admitted.
    #[cfg(windows)]
    async fn require_durable_notification_record(
        &self,
        session: &Session,
        notification_id: &str,
        _notification_digest: &str,
    ) -> Result<(), TransportError> {
        let fence = session.module_generation.state_fence.clone();
        let page = self
            .read_notification_page(&NotificationPageQuery::addressed_record(
                &fence,
                None,
                Some(notification_id.to_owned()),
            ))
            .await?;
        let records = page
            .get(eliot_store_api::NOTIFY_PAGE_RECORDS)
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
    ///
    /// Implements #1967 A1: the rejection carries the named unmet startup
    /// prerequisite (read from the production [`Self::startup_status`]
    /// surface) instead of collapsing to a bare null-valued store error.
    /// The `status`/`value.kind` shape is unchanged; the name travels in
    /// `recovery` so existing `write_receipt` consumers keep parsing.
    fn normal_write_admission_response(&self) -> Option<serde_json::Value> {
        let error = self.admit_normal_write().err()?;
        let status = self.startup_status(GovernanceProfile::minimal());
        let prerequisite = status.blocking_prerequisite.unwrap_or("startup-incomplete");
        Some(serde_json::json!({
            "status": "error",
            "value": { "kind": "write_receipt", "value": null },
            "recovery": {
                "prerequisite": prerequisite,
                "message": error.to_string(),
            },
        }))
    }

    /// Returns the typed rejection when startup or the Governance Profile
    /// has not admitted Material authority for one origin-control decision.
    ///
    /// Implements #1967 W3/A1: origin-control grants issue authority, so the
    /// decide path consults [`Self::admit_material_authority`] (startup gates
    /// first, then the profile ceiling) rather than inferring authority from
    /// pipe liveness. The named prerequisite and the current ceiling travel
    /// in `recovery`; `status`/`value.kind` keep the existing error shape.
    /// Origin-control decisions require a material-grade profile: once every
    /// mandatory prerequisite completes, the profile ceiling alone decides.
    fn material_authority_admission_response(&self) -> Option<serde_json::Value> {
        let profile = GovernanceProfile::material_grade();
        if self.admit_material_authority(profile).is_ok() {
            return None;
        }
        let status = self.startup_status(GovernanceProfile::minimal());
        let ceiling = self.startup_authority_ceiling(profile);
        let prerequisite = status
            .blocking_prerequisite
            .unwrap_or("governance-profile-ceiling");
        Some(serde_json::json!({
            "status": "error",
            "value": { "kind": "origin_control_decide", "value": null },
            "recovery": {
                "prerequisite": prerequisite,
                "authority_ceiling": ceiling.as_str(),
            },
        }))
    }

    /// Store apply is the production Material/Critical admission boundary.
    /// It keeps the existing helper seam used by the package-local gate proof,
    /// but now requires the owner-backed current Watchdog observation before
    /// the retained Store gateway can be entered.
    ///
    /// The answer uses the daemon's `error` wire variant. A refusal must be
    /// decodable by the client: an unrecognised `status` would be surfaced as an
    /// unknown transport outcome, which is exactly the ambiguity this
    /// fail-closed path exists to avoid.
    fn material_write_admission_response(&self, target: &StateFence) -> Option<serde_json::Value> {
        self.admit_material_authority_for_fence(GovernanceProfile::full(), target)
            .err()
            .map(|_| {
                serde_json::json!({
                    "status": "error",
                    "code": eliot_kernel_service::ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
                    "reason": "independent Host-observed Watchdog coverage is not integrated; no Material/Critical effect was admitted",
                    "value": {
                        "kind": "material_authority",
                        "code": eliot_kernel_service::ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE,
                        "degraded_profile": "runtime-degraded-v3",
                        "human_risk_path_required": true,
                    },
                    "recovery": null,
                })
            })
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

/// What kind of runtime handoff one closed operator operation owns.
///
/// The distinction is load-bearing for the schedule owner. An operation that
/// owns a wake publication may answer `Unknown`/`Unavailable` with the exact
/// remaining occurrence set when the Host contour cannot be reached, so its
/// canonical commit still happens and the publication obligation stays visible.
/// An operation that owns an effect or a cancellation is refused outright when
/// its owner is unreachable, because answering that path without the owner
/// would be a Store-only success.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserAutomationRuntimeHandoffNeed {
    /// The operation owns no runtime handoff.
    None,
    /// The operation only publishes a bounded recurring wake horizon.
    PublicationOnly,
    /// The operation crosses into an execution or cancellation owner.
    Effect,
}

/// Reports whether one admitted occurrence carrier arrived as a due scheduler
/// wake rather than as a Human `run-now` occurrence.
///
/// The two are different owner ingresses over the same authenticated channel: a
/// `run-now` occurrence is proved against its committed Store receipt, and a
/// `ScheduledWake` occurrence is proved against the current owner projection and
/// the retained wake record. Neither is inferred from the carrier shape, and
/// neither is granted authority by the selector.
#[cfg(windows)]
fn is_due_scheduler_wake(request: &UserAutomationRuntimeAdmission) -> bool {
    request.invocation.trigger_origin
        == eliot_kernel_core::user_automation::UserAutomationTriggerOrigin::ScheduledWake
}

/// Closed outcome of one due-wake pre-execution revalidation.
///
/// A refusal and an unavailable owner are different answers: a refusal is a
/// decided rejection with a closed cause and no recovery work, while a runtime
/// failure leaves an obligation the caller must retry or reconcile. Collapsing
/// them would make a stale wake look like an outage.
#[cfg(windows)]
enum UserAutomationDueWakeOutcome {
    /// The wake was refused before any effect owner was contacted.
    Refused(UserAutomationDueWakeRejection),
    /// The canonical owner or its policy projection could not be read.
    Runtime(UserAutomationRuntimeError),
}

/// Closed outcome of one due-wake retained-wake proof.
#[cfg(windows)]
enum UserAutomationDueWakeRead {
    /// The schedule owner retains exactly this occurrence as a pending,
    /// unadmitted wake under the current State Fence.
    Proven(UserAutomationWakeReadback),
    /// The wake is refused or the owner could not be read; this is the answer
    /// to return instead of admitting the occurrence.
    Answer(serde_json::Value),
}

/// Classifies the runtime handoff one closed operator operation owns.
///
/// `Create`, `Resume`, and `Edit` own a bounded recurring horizon publication;
/// `run-now`, `remove`, and `pause` cross into an execution or cancellation
/// owner. A read or a configuration query owns none, so it composes no runtime
/// channel and reports both handoff phases as not applicable instead of implying
/// an absent owner.
#[cfg(windows)]
fn user_automation_runtime_handoff_need(
    operation: &eliot_kernel_core::UserAutomationOperation,
) -> UserAutomationRuntimeHandoffNeed {
    match operation {
        eliot_kernel_core::UserAutomationOperation::Create { .. }
        | eliot_kernel_core::UserAutomationOperation::Resume { .. } => {
            UserAutomationRuntimeHandoffNeed::PublicationOnly
        }
        eliot_kernel_core::UserAutomationOperation::RunNow { .. }
        | eliot_kernel_core::UserAutomationOperation::Remove { .. }
        | eliot_kernel_core::UserAutomationOperation::Pause { .. }
        | eliot_kernel_core::UserAutomationOperation::Edit { .. } => {
            UserAutomationRuntimeHandoffNeed::Effect
        }
        eliot_kernel_core::UserAutomationOperation::List { .. }
        | eliot_kernel_core::UserAutomationOperation::Status { .. }
        | eliot_kernel_core::UserAutomationOperation::History { .. }
        | eliot_kernel_core::UserAutomationOperation::InspectLastFailure { .. } => {
            UserAutomationRuntimeHandoffNeed::None
        }
    }
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

/// Requires one closed canonical notification plan before any store IO
/// (issue #1780).
///
/// The store contract — not this route — owns the leg discriminator and its
/// complete parameter set, so this only proves the plan *is* a canonical
/// notification transition: the fixed `NotificationState` class, the fixed
/// notification scope and ordering scope, exactly one named operation, and a
/// decodable leg. A plan that smuggles another class, another scope, or a
/// second named operation is refused before the gateway is entered.
#[cfg(windows)]
fn validate_notification_state_transition(transition: &PreparedTransition) -> Result<(), String> {
    if transition.transition_class != eliot_store_api::TransitionClass::NotificationState {
        return Err(
            "ApplyNotificationState admits only the NotificationState transition class".to_owned(),
        );
    }
    if transition.scope_id.as_str() != eliot_store_api::NOTIFICATION_STATE_SCOPE
        || transition.ordering_scopes.len() != 1
        || transition.ordering_scopes[0].as_str() != eliot_store_api::NOTIFICATION_STATE_SCOPE
    {
        return Err(
            "canonical notification transitions use the fixed notification-state scope".to_owned(),
        );
    }
    if transition.named_operations.len() != 1
        || transition.named_operations[0].operation
            != eliot_store_api::NamedMutationOperation::ApplyNotificationState
    {
        return Err(
            "canonical notification transitions carry exactly one ApplyNotificationState operation"
                .to_owned(),
        );
    }
    eliot_store_api::decode_notification_mutation(&transition.named_operations[0].parameters)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

/// Returns the closed read selectors addressing the record one notification
/// transition just wrote: the dedup key for the create/coalesce leg, and the
/// canonical notification identity for every other lifecycle leg. The store
/// bridge resolves the non-upsert legs against its own dedup index, so a
/// caller can never substitute a dedup key on the delivery, acknowledgement,
/// or resolution legs.
#[cfg(windows)]
fn notification_state_read_selectors(
    transition: &PreparedTransition,
) -> Result<(Option<String>, Option<String>), TransportError> {
    let parameters = &transition.named_operations[0].parameters;
    let decoded = eliot_store_api::decode_notification_mutation(parameters)
        .map_err(|_| TransportError::SessionFenced)?;
    Ok(match decoded {
        eliot_store_api::DecodedNotificationMutation::Upsert { dedup_key, .. } => {
            (Some(dedup_key), None)
        }
        eliot_store_api::DecodedNotificationMutation::Delivery {
            notification_id, ..
        }
        | eliot_store_api::DecodedNotificationMutation::Acknowledge {
            notification_id, ..
        }
        | eliot_store_api::DecodedNotificationMutation::Resolve {
            notification_id, ..
        } => (None, Some(notification_id)),
    })
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
