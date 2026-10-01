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
use tracing::Instrument;
#[path = "store_receipt_dispatch.rs"]
mod store_receipt_dispatch;
use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_kernel_service::AuthenticatedHostSession;
#[cfg(windows)]
use eliot_ors::HostRequestRecord;
// Issue #1872: the I5.11 `canonical_store` storage-replacement ingress. The
// coordinator itself is the existing owner in `eliot_kernel_service`; this
// import is the closed wire vocabulary the ingress projects out of it, never a
// second stage machine or a second cutover gate.
#[cfg(windows)]
use eliot_kernel_service::MaintenanceTriggerDeliveryError;
#[cfg(windows)]
use eliot_kernel_service::StagedReservedWriteError;
#[cfg(windows)]
use eliot_kernel_service::{
    AuthenticatedUserAutomationHostExecutionTransport, NamedReadGatewayError, PreStageRejection,
    StoreApplyRefusal, UserAutomationDueWakeRejection, UserAutomationDueWakeResolution,
    UserAutomationDurableJobPort, UserAutomationHorizonOutcome, UserAutomationHorizonPhase,
    UserAutomationHorizonPublicationRefusal, UserAutomationHorizonTrigger,
    UserAutomationHostExecutionClient, UserAutomationHostExecutionOperation,
    UserAutomationHostExecutionTransport, UserAutomationOperatorRuntime, UserAutomationOwnerLookup,
    UserAutomationRuntimeAdmission, UserAutomationRuntimeError, UserAutomationRuntimeObligation,
    UserAutomationWakeCancellation, UserAutomationWakeEnumerationReceipt,
    UserAutomationWakeEnumerationRequest, UserAutomationWakeHorizonPublication,
    UserAutomationWakeOccurrenceDisposition, UserAutomationWakePort, UserAutomationWakePublication,
    UserAutomationWakeReadRequest, UserAutomationWakeReadback, advance_wake_horizon,
    horizon_retry_handle, refuse_consumed_wake, resolve_due_wake,
};
use eliot_kernel_service::{
    BorrowedCanonicalStoreClient, IrreversibleStorageEffect, ObservedHead, ReservationSeed,
    StorageReplacement, StorageReplacementCutoverReceipt, StorageReplacementStage,
    StorageReplacementTransfer, StorageRollbackDisposition,
    gateway_seed_from_protected_original_operation,
};
use eliot_process::{
    OperationId, OriginChallengeRequest, OriginControlGrant, OriginControlOperation,
    OriginControlPresentation, ProcessExecutionError, ProcessExecutionView, ProcessLifecycle,
};
use eliot_protocol::{
    AgentActivationClaimRequest, HostRequestEnvelope, HostRequestResultBody,
    HostRequestResultLineage, HostRequestResultSourceRevision, LocalReadAttempt,
    LocalReadExecutionEvidence, RequestIdentity, TaskControllerAttempt,
    TaskControllerResultBody,
    host_request_operation_id,
};
#[cfg(windows)]
use eliot_protocol::{MaintenanceTriggerIntakeReceipt, MaintenanceTriggerRecord, ProtocolError};
use eliot_runtime_contracts::GenerationCutoverState;
#[cfg(windows)]
use eliot_runtime_contracts::{
    DaemonChannelCursor, DaemonProgressObservation, DaemonSupervisionRenewalDecision,
    DaemonSupervisionRenewalReceipt, SupervisionLeasePredecessorProof,
};
use eliot_store_api::{
    CampaignLearningStateViewLookup, CampaignLearningStateViewRead,
    CampaignLearningStateViewReadStatus, CampaignSourcePublication, CampaignSourceRevisionLookup,
    CampaignSourceRevisionRef, CanonicalRequestView, CanonicalStoreClient,
    MAX_RECOVERY_OWNER_RECORDS, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    OperationIdentity, OrderingHeadExpectation, PreparedTransition, ReadConsistency,
    RecoveryRecord, RecoveryRecordKey, RequestMeta, RevisionHeadExpectation, StoreError,
    StoreFailure, StoreFailureIdentityContext, StoreGenesisRequest, StoreRecoveryRequest,
    StoreRecoverySnapshot, WriteReceipt,
    StoreWorkScopeOwnerRequest,
    WriteReceiptStatus, verify_canonical_request_hash, verify_ordering_scope_binding,
};
use serde::Deserialize;

use super::generation_control::{
    ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION, ActiveGenerationRegistryProjection,
    ActiveGenerationRegistryQuery, GENERATION_CUTOVER_OPERATION, GenerationCutoverRequest,
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
/// Authenticated Governor publish operation carrying one live-derivation
/// projection (issue #1935 AUD1, I7.16). The Governor-owned derivation
/// publishes its exact revision, exact active fingerprint, and exact
/// authorization axes; Kernel maps the axes to its existing three-axis
/// profile and records the projection, so Material/Critical gates admit
/// only under current owner-issued authority.
pub(crate) const PUBLISH_GOVERNOR_AUTHORITY_OPERATION: &str = "publish_governor_authority";
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

/// Response `kind` of the ORS process-stream recovery view (issue #269, I14.26).
///
/// Availability and the exact gap set, and nothing else: no stream bytes and no
/// parser, evaluator, task or finish claim. It rides the same-fence
/// `store_recovery` answer because that is the recovery readback the retained
/// daemon client already performs, so the ORS half reaches its reader without a
/// second recovery operation or a second dispatch vocabulary.
#[cfg(windows)]
const PROCESS_STREAM_RECOVERY_STATUS_KIND: &str = "process_stream_recovery_status";
/// Per-operation status when ORS retained a readable recovery row.
#[cfg(windows)]
const PROCESS_STREAM_RECOVERY_RETAINED_KIND: &str = "retained";
/// Per-operation status when ORS could not produce the row at all. The typed
/// disposition beside it names which of the two failure classes it was.
#[cfg(windows)]
const PROCESS_STREAM_RECOVERY_UNREADABLE_KIND: &str = "unreadable";

/// Authenticated P-07 root-transition activation route (`#2962`).
///
/// A DISTINCT Kernel-owned front-door operation: the presented payload is the
/// complete typed root-transition operation, and the reply is the
/// transition-specific activation receipt. It is never an `activate_grant`
/// overload, and the dispatcher never reads transition fields out of an
/// untyped map.
pub(crate) const ACTIVATE_ROOT_TRANSITION_OPERATION: &str = "activate_root_transition";

/// Typed receipt kind answered by the root-transition activation arm.
pub(crate) const ROOT_TRANSITION_RECEIPT_KIND: &str = "authority_root_transition_receipt";

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

/// Authenticated P-07 read route answering the committed first-phase closure
/// receipt of one exact target grant (issue #686).
///
/// The projection above answers whether a second phase already COMPLETED; this
/// route answers whether a first phase committed at all for the grant the
/// daemon is revoking, and it answers from the same bound P-07 owner that
/// committed it. Without it the revocation ingress on the far side of the
/// transport can never learn the committed closure and must stay unestablished.
/// The route is read-only and serves the owner's committed bytes verbatim: it
/// never links, never fences, and never derives a closure.
pub(crate) const GRANT_CLOSURE_RECEIPT_OPERATION: &str = "grant_closure_receipt";
/// Authenticated P-07 write route recording the canonical second-phase
/// receipt link against one committed closure first phase (issue #686).
///
/// The sibling read above can observe a completed second phase but cannot
/// create one, so a pending canonical reconciliation has no route to complete
/// itself. This route records the link against the same durable ORS row the
/// read projects and proves the read-back before it answers. It grants no
/// authority: it only makes an already fenced closure's canonical
/// reconciliation durable, and it is idempotent for one identical link.
pub(crate) const LINK_GRANT_CLOSURE_RECEIPT_OPERATION: &str =
    "link_grant_closure_canonical_receipt";
/// Typed receipt kind answered by the closure-receipt read arm.
const GRANT_CLOSURE_RECEIPT_KIND: &str = "grant_closure_receipt";
/// Typed refusal kind answered by the same arm. A refusal is never an absent
/// closure read as "this grant was never revoked".
const GRANT_CLOSURE_RECEIPT_REFUSAL_KIND: &str = "grant_closure_receipt_refused";
/// Typed receipt kind answered by the canonical second-phase link arm.
const GRANT_CLOSURE_LINK_KIND: &str = "grant_closure_canonical_receipt_link";
/// Typed refusal kind answered by the same arm. A refusal is never an empty
/// link read as "canonical reconciliation completed".
const GRANT_CLOSURE_LINK_REFUSAL_KIND: &str = "grant_closure_canonical_receipt_link_refused";
/// Typed refusal kind answered by the P-07 authority arms (`#1110`).
/// Refusals are completed application answers, never missing frames or receipts.
const P07_AUTHORITY_REFUSAL_KIND: &str = "authority_operation_refused";
/// I7.20 dispositions emitted only where the P-07 variant establishes a
/// precise agent-facing classification.
const P07_DISPOSITION_STALE_OR_CONFLICT: &str = "STALE_OR_CONFLICT";
const P07_DISPOSITION_RECOVERY_REQUIRED: &str = "RECOVERY_REQUIRED";
const P07_DISPOSITION_INVALID_REQUEST: &str = "INVALID_REQUEST";
const P07_DISPOSITION_DENIED: &str = "DENIED";
const P07_DISPOSITION_FAILED: &str = "FAILED";
const P07_DISPOSITION_UNAVAILABLE_OR_CAPACITY: &str = "UNAVAILABLE_OR_CAPACITY";

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

/// Authenticated named-read selector serving the complete owner-issued
/// `UserAutomation` preflight projection (issue #1779, I11.12).
///
/// This is the exact string the Kernel core contract already publishes as
/// `USER_AUTOMATION_PREFLIGHT_SELECTOR` and the notify client already sends as
/// its outer frame selector, multiplexing the inner
/// `GetUserAutomationPreflightProjection` marker. Until this arm existed the
/// selector fell through every frame predicate and fenced the session, so a
/// client asked and nothing answered. The arm below serves the projection from
/// the same canonical owners the run-now path assembles from; it mints no
/// receipt, publishes no wake, and admits no execution.
pub(crate) const USER_AUTOMATION_PREFLIGHT_SELECTOR: &str =
    eliot_kernel_core::user_automation::USER_AUTOMATION_PREFLIGHT_SELECTOR;

/// Authenticated daemon operation that drives the Kernel-owned I5.11
/// `canonical_store` storage-replacement coordinator (issue #1872).
///
/// The coordinator is `eliot_kernel_service::StorageReplacement`, the existing
/// owner of the eleven ordered I5.11 stages, the two `I5.10` transfer records,
/// the irreversible-effect ledger, the ORS-re-derived cutover receipt and the
/// rollback classifier. This operation is the production ingress that reaches
/// it, and it is a selector on the same admitted daemon dispatch channel as
/// `GENERATION_CUTOVER_OPERATION`: one closed request type, the same admission
/// gates, the same `{"status","value","recovery"}` response discipline, and no
/// second transport, pipe, or parallel dispatch table.
///
/// **Availability is stated, not assumed.** The arm below is served, but the
/// front-door frame selector that lets a frame *reach* a daemon arm is
/// `frame_dispatch::is_daemon_operation`, a separate closed mirror of this
/// table, which has already cost one operation its ingress: a marker absent
/// there falls through every predicate, fails the generic decode, and fences
/// the session, exactly as `GENERATION_CUTOVER_OPERATION` did before its mirror
/// entry existed. [`STORAGE_REPLACEMENT_OPERATION`] is now present in that
/// mirror, so the frame reaches the arm.
///
/// Reaching the arm is not the same as a cutover being available. The arm admits
/// the exact session fence and generation and then drives the coordinator, which
/// re-derives the route scope and cutover state from the committed ORS
/// cutover-ownership record rather than the payload — and the durable
/// `StorageReplacementCutoverReceiptRecord` is **not yet** in `eliot-ors`, so
/// after a crash the operator must still hold the receipt. The operation is
/// honestly *reachable and admitted*,
/// not *durably recoverable*; the missing record is named in the issue's
/// remaining work.
pub(crate) const STORAGE_REPLACEMENT_OPERATION: &str = "daemon_storage_replacement";

/// Authenticated daemon operation that reconstructs an I5.11 replacement whose
/// `canonical_store` route cutover is already committed.
///
/// This is the path a retry of a committed cutover reaches, and the only one:
/// [`STORAGE_REPLACEMENT_OPERATION`] itself refuses a candidate generation that
/// already owns the pinned route through a committed cutover. It carries the same
/// availability caveat as that operation — it is recognized here and unreachable
/// from the front door until `frame_dispatch::is_daemon_operation` lists it.
pub(crate) const STORAGE_REPLACEMENT_RESUME_OPERATION: &str = "daemon_storage_replacement_resume";

/// Authenticated daemon operation that answers one I5.14 rollback request for a
/// committed I5.11 replacement.
///
/// Separate from the reconstruction above because the answer differs: this one
/// reaches [`StorageReplacement::request_rollback`], which reloads the
/// ORS-committed cut ownership row its receipt names and refuses the request as
/// a generation rollback once an irreversible migration or external effect is
/// recorded. It carries the same availability caveat as
/// [`STORAGE_REPLACEMENT_OPERATION`].
pub(crate) const STORAGE_REPLACEMENT_ROLLBACK_OPERATION: &str =
    "daemon_storage_replacement_rollback";

/// Authenticated daemon operation that admits one ORS-staged maintenance
/// trigger before acknowledging intake (issue #1694 W2).
///
/// Persist before ack: the arm admits the ORS-staged input through the
/// existing gateway owner entry
/// (`KernelStoreGateway::admit_maintenance_trigger`) BEFORE issuing any
/// intake acknowledgement. The complete opaque input must already be staged
/// through the ORS owner; exact identity/hash replay returns the same
/// staging obligation, changed content conflicts, and any capacity, key,
/// integrity, or durable-write failure is answered with the exact bounded
/// failure — never an acknowledgement — so the producer keeps its retry
/// identity and its cursor must not advance. No new owner, database, or
/// poller; no Governor types in ORS.
///
/// It carries the same front-door caveat as
/// [`STORAGE_REPLACEMENT_RESUME_OPERATION`]: it is recognized here and
/// unreachable from the front door until
/// `frame_dispatch::is_daemon_operation` lists it.
pub(crate) const MAINTENANCE_TRIGGER_INTAKE_OPERATION: &str = "maintenance_trigger_intake";

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
        TransportError::LegacyCorrelationUnresolved => "daemon_legacy_correlation_unresolved",
        TransportError::Cancelled => "daemon_cancelled",
        TransportError::Backpressure | TransportError::AttributedBackpressure(_) => {
            "daemon_backpressure"
        }
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
        "origin_grant_reconcile" => "origin_grant_reconcile",
        ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION => ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION,
        GENERATION_CUTOVER_OPERATION => GENERATION_CUTOVER_OPERATION,
        STORAGE_REPLACEMENT_OPERATION => STORAGE_REPLACEMENT_OPERATION,
        STORAGE_REPLACEMENT_RESUME_OPERATION => STORAGE_REPLACEMENT_RESUME_OPERATION,
        STORAGE_REPLACEMENT_ROLLBACK_OPERATION => STORAGE_REPLACEMENT_ROLLBACK_OPERATION,
        MAINTENANCE_TRIGGER_INTAKE_OPERATION => MAINTENANCE_TRIGGER_INTAKE_OPERATION,
        DAEMON_STARTUP_EVIDENCE_OPERATION => DAEMON_STARTUP_EVIDENCE_OPERATION,
        USER_AUTOMATION_RUNTIME_OPERATION => USER_AUTOMATION_RUNTIME_OPERATION,
        "health" => "health",
        "store_recovery" => "store_recovery",
        "store_initialize_genesis" => "store_initialize_genesis",
        "store_work_scope_owner" => "store_work_scope_owner",
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
        "finish_claim" => "finish_claim",
        "finish_result" => "finish_result",
        "agent_host_request_submit" => "agent_host_request_submit",
        "agent_host_request_cancel" => "agent_host_request_cancel",
        "publish_owner_bundle" => "publish_owner_bundle",
        "query_owner_bundle" => "query_owner_bundle",
        "initialize_owner_revision" => "initialize_owner_revision",
        PUBLISH_GOVERNOR_AUTHORITY_OPERATION => PUBLISH_GOVERNOR_AUTHORITY_OPERATION,
        "activate_grant" => "activate_grant",
        "revoke_grant" => "revoke_grant",
        "activate_introduction" => "activate_introduction",
        "revoke_introduction" => "revoke_introduction",
        ACTIVATE_ROOT_TRANSITION_OPERATION => ACTIVATE_ROOT_TRANSITION_OPERATION,
        QUERY_GRANT_CLOSURE_LINKS_OPERATION => QUERY_GRANT_CLOSURE_LINKS_OPERATION,
        GRANT_CLOSURE_RECEIPT_OPERATION => GRANT_CLOSURE_RECEIPT_OPERATION,
        LINK_GRANT_CLOSURE_RECEIPT_OPERATION => LINK_GRANT_CLOSURE_RECEIPT_OPERATION,
        "publish_wasm_dispatch_bundle" => "publish_wasm_dispatch_bundle",
        "bind_notify_launch_grant" => "bind_notify_launch_grant",
        "bind_operator_session_token" => "bind_operator_session_token",
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
    /// Issue #269 / I14.26: exact process-operation identities whose retained
    /// ORS stream-recovery state the Kernel additionally serves on this
    /// same-fence recovery read.
    ///
    /// The selector is a Kernel-owned field on the Kernel-owned carrier, not a
    /// Store field, and it names a DIFFERENT identity space than
    /// `request.records`: those are `(namespace, key)` Store recovery records,
    /// while these are process-operation identities whose durable ORS key is
    /// `(operation_id, stream)`. Reading one through the other would be a
    /// category error, so the two never share a selector.
    ///
    /// `None` — the shape every existing caller sends — answers explicit `null`
    /// and reads no ORS row, so this addition changes no existing answer and
    /// costs the retained daemon no extra read. The selector is bounded by the
    /// Store's own recovery-record denominator so the extra view can never grow
    /// wider than the recovery packet it rides on, and every entry is proved as
    /// a real ORS operation identity before the durable read.
    #[serde(default)]
    process_stream_recovery_operations: Option<Vec<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreWorkScopeOwnerOperation {
    operation_id: String,
    request_sha256: String,
    attempt: TaskControllerAttempt,
    request: StoreWorkScopeOwnerRequest,
}

/// Compares the durable owner projection with the exact proposal retained in
/// the original admitted Task Controller tool. Kernel treats the snapshot as
/// opaque canonical JSON and checks only byte-bound structure; Governor owns
/// semantic interpretation and admission.
fn validate_work_scope_record_against_retained_input(
    record: &RecoveryRecord,
    task_input: &serde_json::Value,
    work_scope_id: &str,
) -> Result<(), TransportError> {
    if record.namespace != "owner" || record.key != "work_scope" {
        return Err(TransportError::SessionFenced);
    }
    let owner_snapshot: serde_json::Value = serde_json::from_slice(&record.payload)
        .map_err(|_| TransportError::SessionFenced)?;
    let canonical_payload = canonical_json_bytes(&owner_snapshot)
        .map_err(|_| TransportError::SessionFenced)?;
    if canonical_payload != record.payload
        || owner_snapshot.get("state_fence")
            != Some(&serde_json::to_value(&record.state_fence).map_err(|_| TransportError::SessionFenced)?)
        || owner_snapshot.get("owner_revision").and_then(serde_json::Value::as_u64)
            != Some(record.revision)
    {
        return Err(TransportError::SessionFenced);
    }
    let task_input = task_input
        .as_object()
        .ok_or(TransportError::SessionFenced)?;
    if task_input.len() != 9
        || task_input.keys().any(|key| {
            !matches!(
                key.as_str(),
                "explicit_root"
                    | "descriptor"
                    | "binding"
                    | "sources"
                    | "privacy"
                    | "source_candidates"
                    | "declared_precedences"
                    | "absence_reason_ref"
                    | "admission_deadline"
            )
        })
    {
        return Err(TransportError::SessionFenced);
    }
    let binding = task_input.get("binding").ok_or(TransportError::SessionFenced)?;
    let sources = task_input.get("sources").ok_or(TransportError::SessionFenced)?;
    let privacy = task_input.get("privacy").ok_or(TransportError::SessionFenced)?;
    let owner_binding = owner_snapshot
        .get("binding")
        .ok_or(TransportError::SessionFenced)?;
    let source_closure = owner_snapshot
        .get("source_closure")
        .and_then(serde_json::Value::as_array)
        .filter(|closure| closure.len() == 2)
        .ok_or(TransportError::SessionFenced)?;
    if owner_binding != binding
        || source_closure[0] != *sources
        || source_closure[1] != *privacy
        || owner_binding
            .get("scope")
            .and_then(|scope| scope.get("scope_ref"))
            .and_then(serde_json::Value::as_str)
            != Some(work_scope_id)
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(())
}

fn work_scope_owner_store_failure_response(
    error: StoreError,
    context: &RequestMeta,
    operation_id: &eliot_store_api::OperationId,
    idempotency_key: &str,
) -> Result<serde_json::Value, TransportError> {
    let failure = StoreFailure::from_store_error(
        error,
        StoreFailureIdentityContext {
            request_id: Some(context.request_id.clone()),
            operation_id: Some(operation_id.clone()),
            idempotency_key_ref_or_digest: Some(idempotency_key.to_owned()),
            state_fence_ref_or_exact_safe_projection: Some(context.state_fence.clone()),
            evidence_ref: None,
            transport_unavailable: false,
        },
    )
    .map_err(|_| TransportError::SessionFenced)?;
    if failure.validate().is_err()
        || failure.request_id.as_ref() != Some(&context.request_id)
        || failure.operation_id.as_ref() != Some(operation_id)
        || failure.idempotency_key_ref_or_digest.as_deref() != Some(idempotency_key)
        || failure.state_fence_ref_or_exact_safe_projection.as_ref()
            != Some(&context.state_fence)
    {
        return Err(TransportError::SessionFenced);
    }
    Ok(serde_json::json!({
        "status": "error",
        "code": "STORE_FAILURE",
        "reason": "The canonical WorkScope owner write was refused.",
        "value": { "kind": "store_work_scope_owner", "value": null },
        "failure": failure,
    }))
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

/// Closed Governor-derived authority publish operation (`#1935` AUD1).
///
/// Carries the live Governor-owned derivation's exact revision, exact active
/// fingerprint, and exact authorization axes (`verified`,
/// `authorizes_enforcement`, `authorizes_complete_coverage_ops`): the owner
/// `GovernanceProfile::authorizes` vocabulary, not a third profile. The
/// dispatcher maps the axes to the existing three-axis profile and records
/// the projection under the strictly-advancing revision rule, so a replayed
/// or older revision fails closed and revoked authority can never be
/// resurrected by re-presenting superseded bytes. Unknown or absent fields
/// fail closed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GovernorAuthorityPublishOperation {
    operation: String,
    revision: u64,
    fingerprint: String,
    verified: bool,
    authorizes_enforcement: bool,
    authorizes_complete_coverage_ops: bool,
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

/// Closed P-07 root-transition activation operation (`#2962`).
///
/// This is a DISTINCT front-door operation, not an `activate_grant` overload:
/// it carries the complete typed root-transition operation — operation
/// identity, idempotency key, both grant identities AND their immutable
/// commitments, both authority roots, the graph snapshot and its
/// predecessor/expected-next revisions, policy revision, deadline, effect
/// ceiling, semantic decision reference, canonical request digest, the
/// presented authority binding, and the presented principal/session/scope
/// subject. The dispatcher decodes it closed, rechecks binding and subject
/// against the authenticated session, and routes it through the retained
/// P-07 owner port; it never mints authority and never reads the transition
/// fields out of an untyped map. Unknown or absent fields fail closed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootTransitionActivationOperation {
    operation_id: String,
    idempotency_key: String,
    transition_id: String,
    parent_grant_id: String,
    child_grant_id: String,
    parent_grant_commitment: String,
    child_grant_commitment: String,
    from_authority_root_ref: String,
    to_authority_root_ref: String,
    issuer: String,
    graph_snapshot_id: String,
    predecessor_graph_revision: u64,
    expected_next_graph_revision: u64,
    policy_revision: String,
    deadline_unix_ms: u64,
    effect_ceiling: eliot_receipts::EffectClass,
    semantic_decision_ref: String,
    canonical_request_digest: String,
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

/// Closed Operator session-token request (`#1777` I11.8).
///
/// Carries the exact binding evidence the requesting User Broker observed for
/// one connecting UI process: its live Kernel registration identity, the
/// one-shot handoff nonce it issued for this binding, the OS-observed Windows
/// SID/session/process tuple, and the exact requested role and capability set.
/// Session evidence is threaded from the live authenticated session, never from
/// the payload. Unknown fields fail closed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorSessionTokenOperation {
    registration_digest: String,
    handoff_nonce: String,
    windows_sid: String,
    interactive_session_id: String,
    client_process_id: String,
    client_image_path: String,
    role: String,
    capabilities: Vec<String>,
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

/// One P-07 refusal projected to the Kernel observation and a wire payload
/// that preserves the exact P-07 variant. I7.20 fields are present only where
/// the variant establishes a precise disposition and reason.
struct P07PortRefusal {
    transport: TransportError,
    p07_error: &'static str,
    snapshot_id: Option<String>,
    disposition: Option<&'static str>,
    reason_code: Option<&'static str>,
    /// Exact typed I7.20 cause of the refusal, present only where the Kernel
    /// has already proven it. It is absent, never invented, for a variant whose
    /// producers live behind a boundary this frame cannot see.
    cause: Option<eliot_authority::P07RefusalCause>,
    /// Closed typed I7.20 Recovery/Conflict Directive that applies to `cause`.
    directive: Option<eliot_authority::P07RefusalDirective>,
}

/// The exact I7.20 classification one proven P-07 cause establishes.
///
/// I7.20 owns `disposition` as a small closed control enum and `reason_code` as
/// an exact member of the open additive registry; this is the one place the
/// Kernel decides which of them a proven cause is. Every reason code named here
/// is a current member of that registry and is re-checked against it when the
/// frame is built, so no code can be introduced that the catalogue does not
/// define. `ROUTE_MISMATCH` has no `eliot-kernel-service` constant, so it is
/// named here and proved against the same registry.
///
/// The Kernel observation travels with the classification for the same reason:
/// a cause about the presented identity reports an identity problem, and a
/// cause about the frame the Kernel itself answered with reports a fenced
/// session, so the terminal diagnostic never misattributes one as the other.
fn p07_cause_classification(
    cause: eliot_authority::P07RefusalCause,
) -> (
    &'static str,
    &'static str,
    eliot_authority::P07RefusalDirective,
    TransportError,
) {
    use eliot_authority::{P07RefusalCause as Cause, P07RefusalDirective as Directive};
    const ROUTE_MISMATCH: &str = "ROUTE_MISMATCH";
    match cause {
        // A presentation that contradicts itself: the fence, the epoch it
        // carries, or the session subject it is built from is repaired, never
        // retried as presented.
        Cause::StateFenceUnvalidated
        | Cause::AuthorityEpochDisagreesWithFence
        | Cause::SessionSubjectUnbindable
        | Cause::InvalidOwnerField => (
            eliot_kernel_service::REASON_INVALID_ARGUMENT,
            P07_DISPOSITION_INVALID_REQUEST,
            Directive::RepairPresentedBinding,
            TransportError::IdentityConflict,
        ),
        // The presented fence was compared against the live Kernel snapshot and
        // is not it: a genuine Kernel refusal, distinct from a presentation
        // that contradicts itself.
        Cause::StaleStateFence => (
            eliot_kernel_service::REASON_STALE_STATE_FENCE,
            P07_DISPOSITION_STALE_OR_CONFLICT,
            Directive::StaleFenceFailClosed,
            TransportError::IdentityConflict,
        ),
        Cause::StaleAuthorityEpoch | Cause::CrossLineageAuthorityEpoch => (
            eliot_kernel_service::REASON_STALE_AUTHORITY_EPOCH,
            P07_DISPOSITION_STALE_OR_CONFLICT,
            Directive::RefreshAuthorityEpoch,
            TransportError::IdentityConflict,
        ),
        Cause::P07OwnerUnavailable => (
            eliot_kernel_service::REASON_CAPABILITY_UNAVAILABLE,
            P07_DISPOSITION_UNAVAILABLE_OR_CAPACITY,
            Directive::OwnerEscalation,
            TransportError::SessionFenced,
        ),
        Cause::AuthorityReceiptExpired => (
            "DEADLINE_EXCEEDED",
            P07_DISPOSITION_DENIED,
            Directive::OwnerEscalation,
            TransportError::SessionFenced,
        ),
        // Issue #1679 A9-4 P07 (caller STITCH): the versioned I14
        // backpressure directive for these capacity causes is whole-or-null,
        // and at this call site it is honestly null. This classifier is a
        // pure function of the proven cause: it holds no front-door reserve
        // handle, no owner-measured partition reading, no operation
        // identity, no profile revision, and no state fence, so naming an
        // exhausted bottleneck dimension or a revision here would fabricate
        // capacity evidence this path never observed (cf. the owner-side
        // `control_reserve_rejection` builders, which refuse to emit unless
        // the live partition actually reads saturated). The typed
        // `OwnerEscalation` directive, disposition, and reason code below
        // are unchanged. A later slice threads the reserve owner's live
        // measurement into the `p07_refusal_response` `"recovery"` slot;
        // until that owner call site exists the answer keeps this
        // disposition and code with a null versioned directive rather than
        // a partial one.
        Cause::ControlReserveExhausted
        | Cause::NormalCapacityExhausted
        | Cause::ProtectedReserveExhausted
        | Cause::EmergencySlotUnavailable => (
            "DEFERRED_CAPACITY",
            P07_DISPOSITION_UNAVAILABLE_OR_CAPACITY,
            Directive::OwnerEscalation,
            TransportError::SessionFenced,
        ),
        // Issue #1679 A9-4 P07 (caller STITCH): same whole-or-null seam as
        // the capacity arm above. Guarantee loss and recovery failure carry
        // no owner-measured observation at this pure-cause call site — no
        // last-resort path reading, no recording operation identity, no
        // profile revision, no state fence — so the versioned directive is
        // honestly null here rather than a fabricated guarantee-loss
        // record. Placement is the same `p07_refusal_response` `"recovery"`
        // slot, fed later by the reserve owner's `guarantee_lost_response`
        // measurement; the typed `OwnerEscalation` directive, disposition,
        // and code below are unchanged.
        Cause::ControlGuaranteeLost | Cause::RecoveryUnavailable | Cause::RecoveryStateFailure => (
            "RECOVERY_REQUIRED",
            P07_DISPOSITION_RECOVERY_REQUIRED,
            Directive::OwnerEscalation,
            TransportError::SessionFenced,
        ),
        Cause::DependencyUnavailable => (
            "ENVIRONMENT_UNAVAILABLE",
            P07_DISPOSITION_UNAVAILABLE_OR_CAPACITY,
            Directive::OwnerEscalation,
            TransportError::SessionFenced,
        ),
        // The answered frame is not the receipt kind this operation returns, or
        // the refusal frame cannot be classified at all: the Kernel cannot serve
        // this answer, so the session is fenced rather than blamed on identity.
        Cause::ResponseRouteMismatch => (
            ROUTE_MISMATCH,
            P07_DISPOSITION_FAILED,
            Directive::OwnerEscalation,
            TransportError::SessionFenced,
        ),
        Cause::RefusalFrameIncompatible => (
            eliot_kernel_service::REASON_PROTOCOL_INCOMPATIBLE,
            P07_DISPOSITION_FAILED,
            Directive::OwnerEscalation,
            TransportError::SessionFenced,
        ),
        Cause::OperationIdentityAlreadyCommitted => (
            eliot_kernel_service::REASON_IDENTITY_CONFLICT,
            P07_DISPOSITION_STALE_OR_CONFLICT,
            Directive::ResubmitFromCurrentState,
            TransportError::IdentityConflict,
        ),
        Cause::CommitOutcomeUnproven => (
            eliot_kernel_service::REASON_UNKNOWN_OUTCOME,
            P07_DISPOSITION_RECOVERY_REQUIRED,
            Directive::ReconcileExactSnapshot,
            TransportError::UnknownOutcome,
        ),
    }
}

/// Builds the refusal answer for one proven typed cause, using the transport
/// failure that same cause establishes.
fn p07_classified_refusal(cause: eliot_authority::P07RefusalCause) -> P07PortRefusal {
    let (reason_code, disposition, directive, transport) = p07_cause_classification(cause);
    P07PortRefusal {
        transport,
        p07_error: "Refused",
        snapshot_id: None,
        disposition: Some(disposition),
        reason_code: Some(reason_code),
        cause: Some(cause),
        directive: Some(directive),
    }
}

/// Maps one retained-port refusal to the existing typed dispatch failure and
/// P-07 wire variant. Only identity conflict and unknown outcome establish an
/// exact I7.20 classification here; only unknown outcome may report a possible
/// commit, and it retains its original snapshot identity.
///
/// A `Refused` refusal already carries the cause its producer proved, so it is
/// classified by that cause rather than collapsed. `InvalidBinding`,
/// `NotAdmitted`, and `Unavailable` keep their exact existing projection: their
/// producers sit behind a boundary this frame cannot see, so no cause,
/// disposition, or reason code is invented for them.
fn map_p07_port_error(error: &eliot_authority::P07PortError) -> P07PortRefusal {
    match error {
        eliot_authority::P07PortError::UnknownOutcome { snapshot_id } => P07PortRefusal {
            transport: TransportError::UnknownOutcome,
            p07_error: "UnknownOutcome",
            snapshot_id: Some(snapshot_id.as_str().to_owned()),
            disposition: Some(P07_DISPOSITION_RECOVERY_REQUIRED),
            reason_code: Some(eliot_kernel_service::REASON_UNKNOWN_OUTCOME),
            cause: Some(eliot_authority::P07RefusalCause::CommitOutcomeUnproven),
            directive: Some(eliot_authority::P07RefusalDirective::ReconcileExactSnapshot),
        },
        eliot_authority::P07PortError::IdentityConflict => P07PortRefusal {
            transport: TransportError::IdentityConflict,
            p07_error: "IdentityConflict",
            snapshot_id: None,
            disposition: Some(P07_DISPOSITION_STALE_OR_CONFLICT),
            reason_code: Some(eliot_kernel_service::REASON_IDENTITY_CONFLICT),
            cause: Some(eliot_authority::P07RefusalCause::OperationIdentityAlreadyCommitted),
            directive: Some(eliot_authority::P07RefusalDirective::ResubmitFromCurrentState),
        },
        eliot_authority::P07PortError::Refused { cause } => p07_classified_refusal(*cause),
        eliot_authority::P07PortError::InvalidBinding => P07PortRefusal {
            transport: TransportError::IdentityConflict,
            p07_error: "InvalidBinding",
            snapshot_id: None,
            disposition: None,
            reason_code: None,
            cause: None,
            directive: None,
        },
        eliot_authority::P07PortError::NotAdmitted => P07PortRefusal {
            transport: TransportError::SessionFenced,
            p07_error: "NotAdmitted",
            snapshot_id: None,
            disposition: None,
            reason_code: None,
            cause: None,
            directive: None,
        },
        eliot_authority::P07PortError::Unavailable => P07PortRefusal {
            transport: TransportError::SessionFenced,
            p07_error: "Unavailable",
            snapshot_id: None,
            disposition: None,
            reason_code: None,
            cause: None,
            directive: None,
        },
    }
}

/// Accepts only the closed I7.20 disposition vocabulary the canonical protocol
/// enum defines, so a new or misspelled control value is never published.
fn is_i720_disposition(value: &str) -> bool {
    serde_json::from_value::<eliot_protocol::AgentResponseDisposition>(serde_json::Value::String(
        value.to_owned(),
    ))
    .is_ok()
}

/// Classifies one refusal for the wire.
///
/// A classified refusal may only claim a disposition and a reason code that the
/// canonical I7.20 vocabularies actually define, and both must be the ones its
/// own proven cause establishes. A refusal that fails that check is still a
/// *decided* refusal, so it stays a decided answer and is downgraded to the
/// unclassifiable cause rather than reported as a lost acknowledgement: this
/// check exists so no invented control value can reach the operator surface.
fn p07_wire_refusal(error: &eliot_authority::P07PortError) -> P07PortRefusal {
    let refusal = map_p07_port_error(error);
    let Some(cause) = refusal.cause else {
        return refusal;
    };
    let (reason_code, disposition, directive, _) = p07_cause_classification(cause);
    let classified = refusal.reason_code == Some(reason_code)
        && refusal.disposition == Some(disposition)
        && refusal.directive == Some(directive)
        && is_i720_disposition(disposition)
        && eliot_protocol::agent_reason_code(reason_code).is_some();
    if classified {
        refusal
    } else {
        p07_classified_refusal(eliot_authority::P07RefusalCause::RefusalFrameIncompatible)
    }
}

/// Completes a decided P-07 refusal as a normal, closed `WireOutcome` answer.
/// A missing frame is indistinguishable from a lost acknowledgement and makes
/// a refusal that certainly did not commit look like an unknown commit.
fn p07_refusal_response(
    operation: &'static str,
    error: &eliot_authority::P07PortError,
) -> serde_json::Value {
    let refusal = p07_wire_refusal(error);
    super::kernel_diagnostics::observe_terminal_error(daemon_terminal_code(&refusal.transport));
    serde_json::json!({
        "status": "known",
        "value": {
            "kind": P07_AUTHORITY_REFUSAL_KIND,
            "value": {
                "disposition": refusal.disposition,
                "reason_code": refusal.reason_code,
                "directive": refusal.directive.map(eliot_authority::P07RefusalDirective::as_str),
                "cause": refusal.cause.map(eliot_authority::P07RefusalCause::as_str),
                "p07_error": refusal.p07_error,
                "snapshot_id": refusal.snapshot_id,
                "operation": operation,
            },
        },
        "recovery": null,
    })
}

/// Builds the ordinary correlated response frame for a front-door P-07
/// preflight refusal discovered before the owner port is called.
fn p07_refusal_frame(
    session: &Session,
    request_id: RequestId,
    operation: &'static str,
    error: &eliot_authority::P07PortError,
) -> Result<Frame, TransportError> {
    let mut frame = status_frame(
        session,
        FrameKind::Response,
        MessageType::Result,
        p07_refusal_response(operation, error),
    )?;
    frame.request_id = Some(request_id);
    frame.validate()?;
    Ok(frame)
}

/// P-07 lifecycle targets are resolved against the owner-projected classes in
/// the current `GrantGraph` snapshot; no second membership rule is introduced.
#[derive(Clone, Copy, Debug)]
enum P07LifecycleTarget<'a> {
    Grant(&'a str),
    Introduction(&'a str),
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

    /// Confirms that the exact grant or introduction and snapshot are present
    /// in the current, internally consistent owner revision before mutation.
    ///
    /// `restrictive` selects the W4 revocation rule: a restriction must bind
    /// the EXACT committed target. When the target already carries a committed
    /// mechanical activation, the presented snapshot and the grant-graph
    /// revision the activation committed at must both be the committed ones, so
    /// a revocation presented against an obsolete revision cannot reach an
    /// unrelated replacement. A target that was never activated has no
    /// committed activation to bind and keeps the existing reconciling path.
    fn admit_p07_target_against_current_grant_graph(
        &self,
        target: P07LifecycleTarget<'_>,
        snapshot_id: &str,
        restrictive: bool,
    ) -> Result<(), eliot_authority::P07PortError> {
        use eliot_kernel_core::RootGrantHydrationSource as _;

        let guard = self
            .p07_owner
            .lock()
            .map_err(|_| eliot_authority::P07PortError::Unavailable)?;
        let Some(bound) = guard.as_ref() else {
            return Err(eliot_authority::P07PortError::Refused {
                cause: eliot_authority::P07RefusalCause::P07OwnerUnavailable,
            });
        };
        let current_revision = bound.bound_revision();
        if current_revision == 0 || bound.source().revision() != current_revision {
            return Err(eliot_authority::P07PortError::Unavailable);
        }
        let admitted = match target {
            P07LifecycleTarget::Grant(grant_id) => bound
                .source()
                .admitted_grant_hydrations()
                .map_err(|_| eliot_authority::P07PortError::Unavailable)?
                .into_iter()
                .find(|hydration| hydration.intent.grant_id == grant_id)
                .map(|hydration| {
                    (
                        hydration.intent.snapshot_id,
                        hydration.intent.grant_graph_revision,
                    )
                }),
            P07LifecycleTarget::Introduction(introduction_id) => bound
                .source()
                .admitted_introductions()
                .map_err(|_| eliot_authority::P07PortError::Unavailable)?
                .into_iter()
                .find(|hydration| hydration.intent.introduction_id == introduction_id)
                .map(|hydration| {
                    (
                        hydration.intent.snapshot_id,
                        hydration.intent.grant_graph_revision,
                    )
                }),
        };
        let Some((admitted_snapshot_id, admitted_revision)) = admitted else {
            return Err(eliot_authority::P07PortError::NotAdmitted);
        };
        if admitted_snapshot_id != snapshot_id || admitted_revision != current_revision {
            return Err(eliot_authority::P07PortError::IdentityConflict);
        }
        if restrictive
            && let P07LifecycleTarget::Grant(grant_id) = target
            && let Some((committed, _subset)) = bound.port().committed_activation(grant_id)
            && (committed.receipt.snapshot_id != snapshot_id
                || committed.grant_graph_revision != current_revision)
        {
            // The restriction does not name the committed activation, so it is
            // aimed at a revision that is no longer the effective one.
            return Err(eliot_authority::P07PortError::IdentityConflict);
        }
        Ok(())
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreInitializeGenesisOperation {
    context: RequestMeta,
    request: StoreGenesisRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StoreApplyOperation {
    pub(crate) context: RequestMeta,
    pub(crate) transition: PreparedTransition,
    pub(crate) expected_revision_heads: Vec<RevisionHeadExpectation>,
    pub(crate) expected_ordering_heads: Vec<OrderingHeadExpectation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) original_write_submission: Option<eliot_store_api::OriginalWriteSubmission>,
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

/// Crash/lost-response reconciliation for one grant-funded kill effect.
///
/// Both fields are front-door envelope values, never proof content: the
/// gateway authorizes the caller against the retained operation record,
/// then cross-checks the envelope operation against the operation the
/// journaled one-shot was decided for before any effect or live read.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OriginGrantReconcileOperation {
    operation_id: OperationId,
    request_nonce: String,
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

/// Closed named-read route for one complete `UserAutomation` preflight
/// projection (issue #1779, I11.12).
///
/// The shape mirrors [`UserAutomationOperatorRoute`]: the outer `operation` is
/// the admitted frame selector the front door routed on, `request_identity` is
/// the front-door-authenticated identity the frame router copied verbatim, and
/// `payload` is the caller's closed read request. The inner payload repeats
/// the exact fields the notify client sends — including the `trigger` and
/// `mode` it read from its own invocation — so the owner can compare each one
/// with its live state instead of merely receiving an automation identity.
#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAutomationPreflightReadRoute {
    operation: String,
    /// Front-door-authenticated request identity copied by the frame router.
    request_identity: RequestIdentity,
    payload: UserAutomationPreflightReadPayload,
}

/// Closed `GetUserAutomationPreflightProjection` read request.
#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserAutomationPreflightReadPayload {
    operation: String,
    context: eliot_contracts::RequestMetadata,
    state_fence: StateFence,
    automation_id: String,
    automation_revision: String,
    occurrence_id: String,
    trigger: eliot_kernel_core::user_automation::UserAutomationTrigger,
    mode: eliot_kernel_core::user_automation::UserAutomationExecutionMode,
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

/// One recorded I5.11 stage an admitted replacement drive presents.
///
/// The stage is named by its own stable stage name
/// ([`StorageReplacementStage::name`]) rather than by an ordinal this file
/// could drift from, and the coordinator resolves it back through
/// [`StorageReplacementStage::from_name`]. The Kernel never interprets the
/// evidence: it is bounded opaque text the Store/candidate-bridge owner
/// recorded, and the coordinator orders it.
///
/// `transfer` is present exactly for the two stages that move `I5.10` data into
/// the candidate (snapshot import, canonical event tail). The two legs are
/// mutually exclusive and the ingress enforces that before calling the
/// coordinator, so a transferring stage can never be recorded without its
/// transfer record and a non-transferring stage can never smuggle one.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageReplacementStageEvidence {
    /// Exact I5.11 stage name.
    stage: String,
    /// Bounded opaque evidence the performing owner recorded.
    evidence: String,
    /// The `I5.10` transfer, for the two transferring stages only.
    #[serde(default)]
    transfer: Option<StorageReplacementTransfer>,
}

/// Exact request payload for [`STORAGE_REPLACEMENT_OPERATION`].
///
/// The caller names ONE replacement identity, the two store generations it is
/// switching between, the ordered stage evidence its owners recorded, the
/// irreversible effects it observed, and the identity of the ORS-committed cut
/// ownership record the route cutover is proven against. It never supplies a
/// route scope, a route-scope hash, a cutover state, a state-migration decision
/// or a linearization record: the pinned `canonical_store` scope is declared by
/// the coordinator, and every cutover field is re-derived by the coordinator
/// from the durable ORS row this identity names. A request therefore cannot
/// assert an authority field the ORS linearization point never recorded.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageReplacementDriveRequest {
    /// Version of the authenticated replacement drive request.
    version: u8,
    /// Exact State Fence carried by the admitted daemon session.
    state_fence: StateFence,
    /// Exact replacement identity this drive is for.
    replacement_id: String,
    /// The store generation that owned the route before the cutover.
    incumbent_generation: Option<ResourceGeneration>,
    /// The store generation that will own the route after the cutover.
    candidate_generation: ResourceGeneration,
    /// Irreversible migrations/effects observed before the cutover. The
    /// coordinator's ledger only grows, and the committed ORS row's
    /// `migration` decision must agree with it exactly, so this list cannot
    /// make a forward-repair cutover look reversible.
    irreversible_effects: BTreeSet<IrreversibleStorageEffect>,
    /// The I5.11 stages in the order the performing owners reached them.
    stages: Vec<StorageReplacementStageEvidence>,
    /// Identity of the ORS-committed cut ownership record the route cutover is
    /// re-derived from. The coordinator loads it; it is never accepted inline.
    cutover_id: String,
    /// Bounded opaque evidence recorded for the I5.11 stage-8 route cutover.
    cutover_evidence: String,
}

/// Exact request payload for [`STORAGE_REPLACEMENT_RESUME_OPERATION`].
///
/// The caller names the replacement identity, the two store generations, the
/// cutover receipt the committed cutover produced, and the post-cutover I5.11
/// stages its owners reached after the restart. It never supplies a route scope,
/// a cutover state, or a rollback disposition.
///
/// `stages` is what makes this the path that finishes a replacement rather than
/// only reconstructing it. The reconstruction resumes at I5.11 stage 9, so the
/// canary, the read-only rollback window and the retirement are recorded here —
/// and stage 11 is still refused by the coordinator until the receipt exists,
/// which the same reconstruction guarantees. Pre-cutover stages are *not*
/// accepted here: the reconstructed coordinator is positioned after the
/// committed cutover, so a presented pre-cutover stage is refused by the
/// coordinator's exact-predecessor rule rather than replayed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageReplacementResumeRequest {
    /// Version of the authenticated post-cutover request.
    version: u8,
    /// Exact State Fence carried by the admitted daemon session.
    state_fence: StateFence,
    /// Exact replacement identity this request is for.
    replacement_id: String,
    /// The store generation that owned the route before the cutover.
    incumbent_generation: Option<ResourceGeneration>,
    /// The store generation that owns the route after the cutover.
    candidate_generation: ResourceGeneration,
    /// The cutover receipt the committed cutover produced. The coordinator
    /// validates it and re-derives it from the ORS row it names, so a
    /// hand-built receipt cannot survive the reconstruction.
    receipt: StorageReplacementCutoverReceipt,
    /// The post-cutover I5.11 stages, in the order their owners reached them.
    stages: Vec<StorageReplacementStageEvidence>,
}

/// Exact request payload for [`STORAGE_REPLACEMENT_ROLLBACK_OPERATION`].
///
/// The caller names the replacement identity, the two store generations, and the
/// cutover receipt. It carries no stage evidence and no disposition: the I5.14
/// decision is the coordinator's, reloaded from the durable ORS row the receipt
/// names.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageReplacementRollbackRequest {
    /// Version of the authenticated rollback request.
    version: u8,
    /// Exact State Fence carried by the admitted daemon session.
    state_fence: StateFence,
    /// Exact replacement identity this request is for.
    replacement_id: String,
    /// The store generation that owned the route before the cutover.
    incumbent_generation: Option<ResourceGeneration>,
    /// The store generation that owns the route after the cutover.
    candidate_generation: ResourceGeneration,
    /// The cutover receipt the committed cutover produced. The coordinator
    /// validates it and re-derives it from the ORS row it names, so a
    /// hand-built receipt cannot obtain a rollback decision.
    receipt: StorageReplacementCutoverReceipt,
}

/// The identity, generations and receipt every post-cutover action presents.
///
/// Both post-cutover request shapes decode into this one carrier, so the two
/// markers cannot drift into two admission vocabularies or two ways of naming a
/// replacement, and the shared reconstruction boundary below is reached with
/// exactly one identity.
struct StorageReplacementResumption {
    /// Exact replacement identity.
    replacement_id: String,
    /// The store generation that owned the route before the cutover.
    incumbent_generation: Option<ResourceGeneration>,
    /// The store generation that owns the route after the cutover.
    candidate_generation: ResourceGeneration,
    /// The cutover receipt.
    receipt: StorageReplacementCutoverReceipt,
}

/// The I5.14 rollback answer projected on the admitted reply.
///
/// `disposition` is the coordinator's own stable disposition name, so the reply
/// carries the decision rather than a re-derivation of it here.
#[derive(Serialize)]
struct StorageRollbackAnswer {
    /// The coordinator's rollback disposition.
    disposition: String,
    /// The cutover state a refused rollback leaves behind. `None` when a
    /// generation rollback is permitted, and `None` when the request was
    /// refused before the disposition was reached at all.
    forward_repair_state: Option<GenerationCutoverState>,
}

/// Closed outcome of one admitted storage-replacement request.
///
/// `terminal_code` is the ONE stable diagnostic code for a refused request and
/// is `None` only when the coordinator actually answered. So "requested",
/// "refused" and "committed" never collapse into one answer: a cutover receipt
/// is present only when the coordinator constructed one from a committed ORS
/// row, and a refusal that may have left the route already switched is reported
/// as a refusal, never as a committed replacement.
#[derive(Serialize)]
struct StorageReplacementOutcome {
    /// Version of the authenticated replacement outcome.
    version: u8,
    /// Terminal diagnostic code of the refused request, `None` when answered.
    terminal_code: Option<&'static str>,
    /// The I5.11 stages this replacement has recorded, in stage order. Empty
    /// for a replacement reconstructed after a restart, because pre-cutover
    /// per-stage evidence is not durable material.
    recorded_stages: Vec<&'static str>,
    /// The irreversible effects on the coordinator's append-only ledger.
    irreversible_effects: Vec<IrreversibleStorageEffect>,
    /// The cutover receipt, present only once the `canonical_store` route
    /// cutover committed.
    cutover_receipt: Option<StorageReplacementCutoverReceipt>,
    /// The I5.14 rollback answer, present only for the rollback operation.
    rollback: Option<StorageRollbackAnswer>,
}

/// Maps one storage-replacement coordinator refusal to its stable diagnostic
/// code.
///
/// Only the variant is emitted; the `String` payload and the refusal's own
/// `field` are never logged. The arms are the coordinator's own refusal classes
/// one-for-one, so a refused stage, a stale fence, a missing ORS record and a
/// fenced generation stay distinguishable on the admitted reply and none of them
/// collapses into an effect-free success.
fn storage_replacement_terminal_code(error: &KernelServiceError) -> &'static str {
    match error {
        KernelServiceError::InvalidField { .. } => "REPLACEMENT_INVALID_FIELD",
        KernelServiceError::IllegalTransition { .. } => "REPLACEMENT_ILLEGAL_TRANSITION",
        KernelServiceError::HandshakeMismatch { .. } => "REPLACEMENT_HANDSHAKE_MISMATCH",
        KernelServiceError::MissingContainmentEvidence => "REPLACEMENT_MISSING_CONTAINMENT",
        KernelServiceError::ReadinessNotProven => "REPLACEMENT_READINESS_NOT_PROVEN",
        KernelServiceError::AdmissionClosed(_) => "REPLACEMENT_ADMISSION_CLOSED",
        KernelServiceError::GenerationFenced => "REPLACEMENT_GENERATION_FENCED",
        KernelServiceError::RestartBudgetExhausted => "REPLACEMENT_RESTART_BUDGET_EXHAUSTED",
        KernelServiceError::ControlReserveExhausted => "REPLACEMENT_RESERVE_EXHAUSTED",
        KernelServiceError::Platform(_) => "REPLACEMENT_PLATFORM",
        KernelServiceError::Core(_) => "REPLACEMENT_CORE",
    }
}

/// Projects the coordinator's own durable position on the admitted reply.
///
/// Both the position and the refusal code are read from the same coordinator
/// value, so a reply can never claim a stage the coordinator did not record, a
/// receipt it did not construct, or a rollback answer it did not classify.
fn storage_replacement_outcome(
    replacement: &StorageReplacement,
    terminal_code: Option<&'static str>,
    rollback: Option<StorageRollbackAnswer>,
) -> StorageReplacementOutcome {
    StorageReplacementOutcome {
        version: 1,
        terminal_code,
        recorded_stages: replacement
            .recorded_evidence()
            .keys()
            .copied()
            .map(StorageReplacementStage::name)
            .collect(),
        irreversible_effects: replacement.irreversible_effects().iter().copied().collect(),
        cutover_receipt: replacement.cutover_receipt().cloned(),
        rollback,
    }
}

/// The admitted-reply envelope, identical to every other arm on this channel.
fn storage_replacement_response(outcome: &StorageReplacementOutcome) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": outcome,
        "recovery": null,
    })
}

/// The outcome of a request the coordinator refused before it could construct a
/// replacement to project a position from.
///
/// Every position field is empty on purpose: a request that never reached the
/// coordinator's state machine has recorded no stage, holds no irreversible
/// effect, owns no receipt and answers no rollback question. Reporting the
/// refusal code alone is the honest shape — a refused request is not a
/// replacement that made no progress, and it must not read as one.
fn storage_replacement_refusal_outcome(terminal_code: &'static str) -> StorageReplacementOutcome {
    StorageReplacementOutcome {
        version: 1,
        terminal_code: Some(terminal_code),
        recorded_stages: Vec::new(),
        irreversible_effects: Vec::new(),
        cutover_receipt: None,
        rollback: None,
    }
}

/// Records one presented stage on the coordinator.
///
/// Which coordinator entry point a stage reaches is decided by the coordinator's
/// own `transfers_data` classification, never by whether the request happened to
/// carry a transfer: the two are required to agree, and a request that disagrees
/// is refused here as an invalid field before the stage machine is touched. The
/// coordinator then owns the ordering rule, so a skipped, repeated or
/// out-of-order stage is refused by the owner rather than reordered here.
fn record_storage_replacement_stage(
    replacement: &mut StorageReplacement,
    stage_evidence: &StorageReplacementStageEvidence,
) -> Result<(), KernelServiceError> {
    let stage = StorageReplacementStage::from_name(&stage_evidence.stage).ok_or(
        KernelServiceError::InvalidField {
            field: "storage_replacement.stage",
            reason: "the presented stage is not one of the I5.11 ordered replacement stages",
        },
    )?;
    let transfer = stage_evidence.transfer.as_ref();
    if stage.transfers_data() != transfer.is_some() {
        return Err(KernelServiceError::InvalidField {
            field: "storage_replacement.stage_transfer",
            reason: "exactly the snapshot import and the canonical event tail carry an I5.10 transfer record",
        });
    }
    match transfer {
        Some(transfer) => {
            replacement.record_transfer_stage(stage, transfer, &stage_evidence.evidence)?;
        }
        None => {
            replacement.record_stage(stage, &stage_evidence.evidence)?;
        }
    }
    Ok(())
}

impl KernelComposition {
    /// Drives one admitted I5.11 storage replacement from the first stage through
    /// the committed `canonical_store` route cutover.
    ///
    /// The operation selector only picks this entry. The closed request carries
    /// the replacement identity, the two store generations, the ordered stage
    /// evidence its owners recorded, the observed irreversible effects, and the
    /// identity of the ORS-committed cut ownership record; the pinned
    /// `canonical_store` `CapabilityRouteScope` is declared by the coordinator
    /// and every cutover field is re-derived from that durable row. A malformed
    /// request, a fence that is not the exact admitted session fence, an
    /// unsupported version, an out-of-order stage, or a cutover the durable row
    /// does not prove is answered with the coordinator's own stable refusal code
    /// and never with a fabricated cutover or success answer.
    ///
    /// A second cutover for a candidate generation that already owns the route
    /// is refused by [`StorageReplacement::begin`] itself, and a stage recorded
    /// twice is refused by the coordinator's exact-predecessor rule, so this
    /// ingress cannot reach a committed cutover twice. What a retry after a
    /// committed cutover reaches instead is
    /// [`Self::storage_replacement_resume_operation`].
    fn storage_replacement_drive_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let request: StorageReplacementDriveRequest =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        Self::validate_storage_replacement_fence(session, request.version, &request.state_fence)?;
        if request.stages.len() > StorageReplacementStage::ORDER.len() {
            return Err(TransportError::SessionFenced);
        }
        let ors = self.p07_ors.as_ref();
        // `begin` is the coordinator's own restart guard: a candidate generation
        // that already owns the pinned route through a committed cutover is
        // refused here, so a replay of this request cannot reopen a replacement
        // from the top. Its refusal is reported as a refusal.
        let mut replacement = match StorageReplacement::begin(
            ors,
            request.replacement_id.clone(),
            request.incumbent_generation,
            request.candidate_generation,
        ) {
            Ok(replacement) => replacement,
            Err(error) => {
                return Ok(storage_replacement_response(
                    &storage_replacement_refusal_outcome(storage_replacement_terminal_code(&error)),
                ));
            }
        };
        for effect in &request.irreversible_effects {
            replacement.record_irreversible_effect(*effect);
        }
        for stage_evidence in &request.stages {
            if let Err(error) = record_storage_replacement_stage(&mut replacement, stage_evidence) {
                // The stages already recorded are still reported: an effect that
                // may have happened must not collapse into an effect-free
                // refusal, and the operator has to see how far the machine went.
                return Ok(storage_replacement_response(&storage_replacement_outcome(
                    &replacement,
                    Some(storage_replacement_terminal_code(&error)),
                    None,
                )));
            }
        }
        // Stage 8. The coordinator loads the ORS-committed cut ownership record
        // and refuses anything that is not committed, so the receipt below is
        // constructed only from a durable linearization point. A refusal here
        // still reports the recorded stages and no receipt, because none was
        // constructed.
        let terminal_code = match replacement.commit_canonical_store_route_cutover(
            ors,
            &request.cutover_id,
            &request.cutover_evidence,
        ) {
            Ok(_) => None,
            Err(error) => Some(storage_replacement_terminal_code(&error)),
        };
        Ok(storage_replacement_response(&storage_replacement_outcome(
            &replacement,
            terminal_code,
            None,
        )))
    }

    /// Reconstructs an already-committed I5.11 replacement after a restart.
    ///
    /// This is the only path a retry of a committed cutover reaches, and it is
    /// the coordinator's own reconstruction: the presented receipt is validated
    /// and then re-derived from the ORS row it names, so it cannot be asserted.
    /// The reconstructed replacement starts at the stage after the committed
    /// cutover and carries the irreversible-effect ledger the receipt fixed at
    /// the cutover, so a post-cutover request cannot silently reopen a
    /// generation rollback either.
    fn storage_replacement_resume_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let request: StorageReplacementResumeRequest =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        Self::validate_storage_replacement_fence(session, request.version, &request.state_fence)?;
        if request.stages.len() > StorageReplacementStage::ORDER.len() {
            return Err(TransportError::SessionFenced);
        }
        let mut replacement = match self.storage_replacement_resumption(
            STORAGE_REPLACEMENT_RESUME_OPERATION,
            StorageReplacementResumption {
                replacement_id: request.replacement_id,
                incumbent_generation: request.incumbent_generation,
                candidate_generation: request.candidate_generation,
                receipt: request.receipt,
            },
        ) {
            Ok(replacement) => replacement,
            Err(terminal_code) => {
                return Ok(storage_replacement_response(
                    &storage_replacement_refusal_outcome(terminal_code),
                ));
            }
        };
        let mut terminal_code = None;
        for stage_evidence in &request.stages {
            if let Err(error) = record_storage_replacement_stage(&mut replacement, stage_evidence) {
                // The post-cutover stages already recorded are still reported:
                // an effect that may have happened must not collapse into an
                // effect-free refusal.
                terminal_code = Some(storage_replacement_terminal_code(&error));
                break;
            }
        }
        Ok(storage_replacement_response(&storage_replacement_outcome(
            &replacement,
            terminal_code,
            None,
        )))
    }

    /// Answers one I5.14 rollback request for an already-committed I5.11
    /// replacement.
    ///
    /// The decision is the coordinator's own and is not re-derived here:
    /// [`StorageReplacement::request_rollback`] reloads the ORS-committed cut
    /// ownership row the receipt names, so a durable `forward_repair_required`
    /// migration refuses the request even when the in-process ledger is silent.
    /// A refused rollback is answered as a refusal carrying the coordinator's
    /// disposition and the cutover state it leaves behind — never as a
    /// switched-back route and never as an effect-free success.
    fn storage_replacement_rollback_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let request: StorageReplacementRollbackRequest =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        Self::validate_storage_replacement_fence(session, request.version, &request.state_fence)?;
        let replacement = match self.storage_replacement_resumption(
            STORAGE_REPLACEMENT_ROLLBACK_OPERATION,
            StorageReplacementResumption {
                replacement_id: request.replacement_id,
                incumbent_generation: request.incumbent_generation,
                candidate_generation: request.candidate_generation,
                receipt: request.receipt,
            },
        ) {
            Ok(replacement) => replacement,
            // The receipt did not re-derive against the durable ORS row, so there
            // is no replacement to answer a rollback question about. The refusal
            // is reported and no disposition is projected: naming one here would
            // be inventing a decision the coordinator never made.
            Err(terminal_code) => {
                return Ok(storage_replacement_response(
                    &storage_replacement_refusal_outcome(terminal_code),
                ));
            }
        };
        let (rollback, terminal_code) = match replacement.request_rollback(self.p07_ors.as_ref()) {
            Ok(disposition) => (
                Some(StorageRollbackAnswer {
                    disposition: disposition.to_string(),
                    forward_repair_state: None,
                }),
                None,
            ),
            // The I5.14 refusal: an irreversible migration or external effect is
            // recorded, so the request is refused as a generation rollback and
            // the disposition names the forward-repair state that follows. The
            // state is the coordinator's own classification, read back from it.
            Err(error @ KernelServiceError::GenerationFenced) => {
                let disposition = replacement.rollback_disposition();
                (
                    Some(StorageRollbackAnswer {
                        disposition: disposition.to_string(),
                        forward_repair_state: match disposition {
                            StorageRollbackDisposition::ForwardRepairRequired { state } => {
                                Some(state)
                            }
                            StorageRollbackDisposition::GenerationRollbackPermitted => None,
                        },
                    }),
                    Some(storage_replacement_terminal_code(&error)),
                )
            }
            // Any other refusal never reached the disposition at all.
            Err(error) => (None, Some(storage_replacement_terminal_code(&error))),
        };
        Ok(storage_replacement_response(&storage_replacement_outcome(
            &replacement,
            terminal_code,
            rollback,
        )))
    }

    /// The one admission gate every storage-replacement request passes.
    ///
    /// Three checks, and they are the same ones the existing generation-cutover
    /// arm applies (`generation_control::KernelComposition::apply_authenticated_generation_cutover`):
    /// the request's own State Fence must be well formed, the version must be
    /// the one this arm speaks, and the presented fence must be the **exact**
    /// admitted session fence — a compatible-but-different fence is still stale
    /// for this observation. A request failing any of them is fenced at the
    /// transport, before the coordinator is touched, so an unfenced or
    /// stale-fenced request never reaches a stage machine or a cutover.
    fn validate_storage_replacement_fence(
        session: &Session,
        version: u8,
        state_fence: &StateFence,
    ) -> Result<(), TransportError> {
        state_fence
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if version != 1 || state_fence != &session.module_generation.state_fence {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }

    /// Shared reconstruction for the two post-cutover operations.
    ///
    /// A refused reconstruction is reported with the coordinator's own stable
    /// code rather than fenced, so the operator learns *why* a receipt did not
    /// re-derive against the durable row instead of only learning that the
    /// session was fenced. Both markers reach this one boundary with one
    /// identity shape, so the two post-cutover actions cannot drift into two
    /// admission vocabularies or two ways of reconstructing a replacement.
    fn storage_replacement_resumption(
        &self,
        operation: &str,
        resumption: StorageReplacementResumption,
    ) -> Result<StorageReplacement, &'static str> {
        observe_daemon_operation(operation, "replacement_committed_requested");
        StorageReplacement::resume_after_committed_cutover(
            self.p07_ors.as_ref(),
            resumption.replacement_id,
            resumption.incumbent_generation,
            resumption.candidate_generation,
            &resumption.receipt,
        )
        .map_err(|error| storage_replacement_terminal_code(&error))
    }
}

/// Exact request payload for [`MAINTENANCE_TRIGGER_INTAKE_OPERATION`].
///
/// The caller presents the complete retained trigger record plus the exact
/// admitted session fence. The record carries the ORS envelope reference and
/// payload hash; the intake operation proves staging through the ORS owner
/// before any intake acknowledgement is issued. The caller never supplies
/// authority, a receipt, or a delivery identity: those are owner-issued on
/// admission, never asserted.
#[cfg(windows)]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MaintenanceTriggerIntakeRequest {
    /// Version of the authenticated intake request.
    version: u8,
    /// Exact State Fence carried by the admitted daemon session.
    state_fence: StateFence,
    /// Complete retained trigger record to stage-admit.
    record: MaintenanceTriggerRecord,
}

/// Closed intake failure for one maintenance-trigger intake (issue #1694 W2).
///
/// Variants name the failure kind only: exact source errors stay with their
/// owners (retry under the same identity re-observes them) and never enter
/// logs or responses, so a refusal carries its stable code and nothing
/// privacy-sensitive. An ORS/staging fault, a protocol or changed-content
/// conflict, a fenced generation, and a live-authority refusal stay
/// distinguishable and never collapse into an acknowledgement. Any failure
/// admits nothing and acknowledges nothing: the producer keeps its retry
/// identity and its cursor must not advance.
#[cfg(windows)]
enum MaintenanceTriggerIntakeFailure {
    /// The ORS owner could not prove the staged opaque input: capacity, key,
    /// integrity, or durable-write failure.
    OrsStaging,
    /// The presented record failed protocol validation, or changed content
    /// under the same identity conflicted with staged bytes (`ReplayConflict`).
    Protocol(ProtocolError),
    /// The live generation is fenced for this intake.
    FencedGeneration,
    /// Live Kernel authority refused session or admission; fails closed.
    LiveAuthority,
    /// The Kernel owner could not reach its service or ledger state.
    OwnerUnavailable,
    /// The canonical Store refused the backing read.
    Store,
    /// A ledger-level refusal owned by another transition (claim/ack paths).
    /// Intake admission never produces one; it is preserved exactly and
    /// fails closed here rather than becoming an acknowledgement.
    UnexpectedLedgerRefusal,
}

#[cfg(windows)]
impl From<MaintenanceTriggerDeliveryError> for MaintenanceTriggerIntakeFailure {
    /// Classifies one owner-side admission outcome into the closed intake
    /// failure.
    ///
    /// Exact source errors are preserved in their variant; only the stable
    /// code reads the classification. The five ledger-level refusals owned
    /// by the claim/ack transitions can never be produced by intake
    /// admission and fail closed as ledger refusals, never as
    /// acknowledgements. STITCH (issue #1694): when the gateway half lands
    /// `MaintenanceTriggerDeliveryError::LedgerAuthority` plus its
    /// `from_ledger_admission_error` mapper in
    /// `crates/kernel/eliot-kernel-service/src/store_gateway.rs`, this match
    /// intentionally breaks until that variant is classified here — no
    /// wildcard arm may absorb it.
    fn from(error: MaintenanceTriggerDeliveryError) -> Self {
        match error {
            MaintenanceTriggerDeliveryError::StagingProof(_) => Self::OrsStaging,
            MaintenanceTriggerDeliveryError::Protocol(error) => Self::Protocol(error),
            MaintenanceTriggerDeliveryError::Service(KernelServiceError::GenerationFenced) => {
                Self::FencedGeneration
            }
            MaintenanceTriggerDeliveryError::Service(_) => Self::LiveAuthority,
            MaintenanceTriggerDeliveryError::OwnerUnavailable(_) => Self::OwnerUnavailable,
            MaintenanceTriggerDeliveryError::Store(_) => Self::Store,
            MaintenanceTriggerDeliveryError::UnknownTrigger
            | MaintenanceTriggerDeliveryError::ClaimConflict
            | MaintenanceTriggerDeliveryError::RevokedConsumer
            | MaintenanceTriggerDeliveryError::ExpiredEligibility
            | MaintenanceTriggerDeliveryError::MirrorRecoveryRequired => {
                Self::UnexpectedLedgerRefusal
            }
        }
    }
}

/// Maps one intake failure to its stable diagnostic code.
///
/// Only the variant is emitted; the `String` payloads and the source errors'
/// own fields are never logged. Changed-content conflicts stay
/// distinguishable from other protocol rejections, and a fenced generation
/// stays distinguishable from a live-authority refusal, so none of them
/// collapses into an effect-free success. The match stays exhaustive with no
/// wildcard: a new failure variant breaks here loudly.
#[cfg(windows)]
fn maintenance_trigger_intake_terminal_code(
    failure: &MaintenanceTriggerIntakeFailure,
) -> &'static str {
    match failure {
        MaintenanceTriggerIntakeFailure::OrsStaging => "INTAKE_STAGING_UNAVAILABLE",
        MaintenanceTriggerIntakeFailure::Protocol(error) => {
            if *error == ProtocolError::ReplayConflict {
                "INTAKE_REPLAY_CONFLICT"
            } else {
                "INTAKE_PROTOCOL_REJECTED"
            }
        }
        MaintenanceTriggerIntakeFailure::FencedGeneration => "INTAKE_GENERATION_FENCED",
        MaintenanceTriggerIntakeFailure::LiveAuthority => "INTAKE_LIVE_AUTHORITY_REFUSED",
        MaintenanceTriggerIntakeFailure::OwnerUnavailable => "INTAKE_OWNER_UNAVAILABLE",
        MaintenanceTriggerIntakeFailure::Store => "INTAKE_STORE_REFUSED",
        MaintenanceTriggerIntakeFailure::UnexpectedLedgerRefusal => "INTAKE_LEDGER_REFUSED",
    }
}

/// Closed outcome of one admitted maintenance-trigger intake.
///
/// `terminal_code` is the ONE stable diagnostic code for a refused intake
/// and is `None` only when the gateway owner actually admitted the staged
/// input and issued its receipt. A receipt is present only when the owner
/// constructed one after proving ORS staging, so "requested", "refused",
/// and "admitted" never collapse into one answer.
#[cfg(windows)]
#[derive(Serialize)]
struct MaintenanceTriggerIntakeAnswer {
    /// Version of the authenticated intake answer.
    version: u8,
    /// Terminal diagnostic code of the refused intake, `None` when admitted.
    terminal_code: Option<&'static str>,
    /// The owner's intake receipt, present only when admitted.
    receipt: Option<MaintenanceTriggerIntakeReceipt>,
}

/// The admitted-reply envelope, identical to every other arm on this channel.
#[cfg(windows)]
fn maintenance_trigger_intake_response(
    answer: &MaintenanceTriggerIntakeAnswer,
) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": answer,
        "recovery": null,
    })
}

/// The outcome of an intake the owner refused before it could admit.
///
/// Every position field is empty on purpose: an intake that never reached
/// admission staged nothing new, holds no obligation, and owns no receipt.
/// Reporting the refusal code alone is the honest shape — a refused intake
/// is not an admitted trigger that made no progress, and the producer keeps
/// its retry identity.
#[cfg(windows)]
fn maintenance_trigger_intake_refusal_answer(
    terminal_code: &'static str,
) -> MaintenanceTriggerIntakeAnswer {
    MaintenanceTriggerIntakeAnswer {
        version: 1,
        terminal_code: Some(terminal_code),
        receipt: None,
    }
}

#[cfg(windows)]
impl KernelComposition {
    /// Admits one ORS-staged maintenance trigger before acknowledging intake.
    ///
    /// The operation selector only picks this entry. The closed request
    /// carries the complete retained trigger record and the exact admitted
    /// session fence; the principal comes from the authenticated session
    /// module binding, never from the request DTO. A malformed request or a
    /// fence that is not the exact admitted session fence is fenced at the
    /// transport, before the gateway is touched.
    ///
    /// Admission itself is the existing gateway owner entry
    /// (`KernelStoreGateway::admit_maintenance_trigger`), which proves
    /// ORS staging first and validates the record with the existing wire
    /// validators: the complete opaque input must already be staged, exact
    /// identity/hash replay returns the same staging receipt, and changed
    /// content conflicts. Any failure is answered with the intake's own
    /// stable refusal code and never with an acknowledgement, so the
    /// producer keeps its retry identity and its cursor must not advance.
    fn maintenance_trigger_intake_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let request: MaintenanceTriggerIntakeRequest =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        Self::validate_maintenance_trigger_intake_fence(
            session,
            request.version,
            &request.state_fence,
        )?;
        let gateway = self.retained_store_gateway()?;
        match gateway
            .admit_maintenance_trigger(session.module_generation.module_id.as_str(), request.record)
        {
            Ok((receipt, _)) => Ok(maintenance_trigger_intake_response(
                &MaintenanceTriggerIntakeAnswer {
                    version: 1,
                    terminal_code: None,
                    receipt: Some(receipt),
                },
            )),
            Err(error) => Ok(maintenance_trigger_intake_response(
                &maintenance_trigger_intake_refusal_answer(
                    maintenance_trigger_intake_terminal_code(
                        &MaintenanceTriggerIntakeFailure::from(error),
                    ),
                ),
            )),
        }
    }

    /// The one admission gate every maintenance-trigger intake request passes.
    ///
    /// The same three checks the storage-replacement ingress applies: the
    /// request's own State Fence must be well formed, the version must be
    /// the one this arm speaks, and the presented fence must be the
    /// **exact** admitted session fence. A request failing any of them is
    /// fenced at the transport, before the gateway is touched.
    fn validate_maintenance_trigger_intake_fence(
        session: &Session,
        version: u8,
        state_fence: &StateFence,
    ) -> Result<(), TransportError> {
        state_fence
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if version != 1 || state_fence != &session.module_generation.state_fence {
            return Err(TransportError::SessionFenced);
        }
        Ok(())
    }
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
        let context = super::kernel_diagnostics::operation_context(
            Some(request_id.as_str()),
            None,
            None,
            None,
        );
        let bounded_request_id = super::kernel_diagnostics::bound_field(request_id.as_str());
        context.record("request_id", bounded_request_id.text());
        context.record(
            "request_id_redaction",
            bounded_request_id.redaction_status().unwrap_or("none"),
        );
        context.in_scope(|| observe_daemon_request("kernel.daemon_request_received", "attempt"));
        context
            .in_scope(|| observe_daemon_operation(trusted_daemon_operation(operation), "received"));
        let mut subordinate_terminal_emitted = false;
        let result = Box::pin(self.execute_daemon_request_inner(
            session,
            request_id,
            operation,
            &payload,
            request_identity.as_ref(),
            &mut subordinate_terminal_emitted,
        ))
        .instrument(context.clone())
        .await;
        match &result {
            Ok(_) => {
                context.in_scope(|| {
                    observe_daemon_request("kernel.daemon_request_validated", "success");
                });
                context.in_scope(|| {
                    observe_daemon_request("kernel.daemon_request_admitted", "success");
                });
                context.in_scope(|| {
                    observe_daemon_operation(trusted_daemon_operation(operation), "dispatched");
                });
                context.in_scope(|| {
                    observe_daemon_request("kernel.daemon_response_prepared", "success");
                });
                // F-LOG-KERNEL-1 (#897 W3): prepared, delivered and unknown
                // are three independent records. `delivered` marks the reply
                // value delivered to the immediate caller at this dispatch
                // boundary (the transport handoff), never the wire write: the
                // only wire-delivery witness is the driver-owned
                // `send_checked` write (`front_door_driver.rs`, outside #897
                // scope), so the post-handoff transport outcome stays
                // `unknown` at this boundary.
                context.in_scope(|| {
                    observe_daemon_request("kernel.daemon_response_delivered", "success");
                });
                context.in_scope(|| {
                    observe_daemon_request("kernel.daemon_response_unknown", "unknown");
                });
                context.in_scope(|| {
                    observe_daemon_request("kernel.daemon_request_cleanup", "complete");
                });
            }
            Err(error) => {
                context.in_scope(|| {
                    observe_daemon_request("kernel.daemon_request_validated", "fenced");
                });
                context.in_scope(|| {
                    observe_daemon_operation(trusted_daemon_operation(operation), "fenced");
                });
                if matches!(error, TransportError::Cancelled) {
                    // F-LOG-KERNEL-1 (#897 W3): cancellation observed as the
                    // terminal disposition, distinct from the cancellation
                    // request (`kernel.daemon_cancel_requested`). Info only;
                    // the terminal below stays the single designated terminal.
                    context.in_scope(|| {
                        observe_daemon_request("kernel.daemon_cancel_observed", "cancelled");
                    });
                }
                // F-LOG-KERNEL-1 (#897 T20): a failed receipt sub-dispatch
                // already owns that operation's single designated terminal,
                // so a second terminal here would inflate one failure into
                // two records. Pre-match gates and the post-match frame
                // build emit no subordinate terminal, so they still
                // terminalise here: exactly one terminal either way. The
                // fenced observations above stay unconditional.
                if !subordinate_terminal_emitted {
                    super::kernel_diagnostics::observe_terminal_error_in_context(
                        daemon_terminal_code(error),
                        &context,
                    );
                }
                context
                    .in_scope(|| observe_daemon_request("kernel.daemon_request_cleanup", "fenced"));
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
        subordinate_terminal_emitted: &mut bool,
    ) -> Result<Frame, TransportError> {
        let context = tracing::Span::current();
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
        #[cfg(windows)]
        if operation == USER_AUTOMATION_PREFLIGHT_SELECTOR {
            // The complete preflight projection is a front-door read, not a
            // daemon-module operation: the principal comes from the
            // authenticated peer, the State Fence from the session, and every
            // projection member from the canonical owner that attests it. No
            // other daemon operation is reachable from this branch, and the
            // branch mints nothing: no receipt, no wake, no execution.
            session
                .peer
                .validate()
                .map_err(|_| TransportError::PeerIdentityUnavailable)?;
            let value = Box::pin(self.user_automation_preflight_projection_operation(
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
            #[cfg(windows)]
            scan_disclosure_route::OPERATION => {
                self.scan_disclosure_owner_operation(session, payload)
            }
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
                        .validated_authenticated_daemon_ready_inputs(
                            &context,
                            subordinate_terminal_emitted,
                        )
                        .await
                        .map_err(|_| TransportError::SessionFenced)?;
                    let (contour, snapshot) = self
                        .establish_daemon_supervision(
                            session,
                            &process,
                            &context,
                            subordinate_terminal_emitted,
                        )
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
                    self.publish_eliotd_live_receipt(
                        &launch, &process, &ready, &contour, None, &context,
                    )
                    .map_err(|_| {
                        *subordinate_terminal_emitted = true;
                        TransportError::SessionFenced
                    })?;
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
                self.origin_challenge_issue_operation(
                    session,
                    payload.clone(),
                    &context,
                    subordinate_terminal_emitted,
                )
                .await
            }
            "origin_control_decide" => {
                self.origin_control_decide_operation(
                    session,
                    payload.clone(),
                    &context,
                    subordinate_terminal_emitted,
                )
                .await
            }
            "origin_grant_reconcile" => {
                self.origin_grant_reconcile_operation(session, payload.clone())
            }
            ACTIVE_GENERATION_REGISTRY_QUERY_OPERATION => {
                self.generation_registry_active_query_operation(session, payload.clone())
            }
            GENERATION_CUTOVER_OPERATION => {
                self.generation_cutover_operation(session, payload.clone())
            }
            // Issue #1872: the I5.11 `canonical_store` storage-replacement
            // ingress. The three markers are the same admitted daemon channel
            // `GENERATION_CUTOVER_OPERATION` above already uses, and the arms
            // reach the Kernel-owned `StorageReplacement` coordinator — they do
            // not implement a stage machine here. Each arm proves the daemon
            // module binding, the admitted session State Fence and the exact
            // request fence, and every route scope, cutover state, migration
            // decision and linearization record is read from the coordinator or
            // re-derived by it from the durable ORS row, never from the payload.
            STORAGE_REPLACEMENT_OPERATION => {
                self.storage_replacement_drive_operation(session, payload.clone())
            }
            STORAGE_REPLACEMENT_RESUME_OPERATION => {
                self.storage_replacement_resume_operation(session, payload.clone())
            }
            STORAGE_REPLACEMENT_ROLLBACK_OPERATION => {
                self.storage_replacement_rollback_operation(session, payload.clone())
            }
            // Issue #1694 W2: the persist-before-ack maintenance-trigger
            // intake. The arm admits the ORS-staged record through the
            // existing gateway owner entry before issuing any intake
            // acknowledgement; every route scope, receipt, and delivery
            // identity on the reply is owner-issued, never from the payload.
            #[cfg(windows)]
            MAINTENANCE_TRIGGER_INTAKE_OPERATION => {
                self.maintenance_trigger_intake_operation(session, payload.clone())
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
                Box::pin(self.store_recovery_operation(session, payload.clone())).await
            }
            "store_initialize_genesis" => {
                self.store_initialize_genesis_operation(session, payload.clone())
                    .await
            }
            "store_work_scope_owner" => {
                self.store_work_scope_owner_operation(
                    session,
                    request_identity,
                    payload.clone(),
                )
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
            "receipt" => {
                // F-LOG-KERNEL-1 (#897 T20): only a dispatch failure carries
                // the subordinate designated terminal, so only that leg
                // transfers terminal ownership to the sub-dispatch.
                let outcome =
                    store_receipt_dispatch::dispatch(self, session, payload.clone()).await;
                if outcome.is_err() {
                    *subordinate_terminal_emitted = true;
                }
                outcome
            }
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
                    self.daemon_supervision_progress_operation(
                        payload.clone(),
                        &context,
                        subordinate_terminal_emitted,
                    )
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
                    self.admit_material_authority_for_governor_issued_fence(
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
                    // I1.11 step 10 (issue #1892 W5): the ordered startup
                    // gate owns the queued-attach release. A claim made before
                    // the gate reports front-door readiness is refused with the
                    // named unmet startup prerequisite, mirroring the
                    // normal-write refusal shape, so no queued ticket is
                    // consumed, ordered, or leased and the claimant simply
                    // re-observes readiness on its next poll. This is the only
                    // place the gate is applied on the release path; a claim
                    // failure inside the open gate still fences exactly as
                    // before, so the closed gate adds no new refusal path.
                    match self.admit_queued_attach_release() {
                        Ok(()) => self
                            .claim_agent_activation_ticket(
                                &claim.dependency_ref,
                                &claim.dependency_revision,
                            )
                            .map(|ticket| {
                                serde_json::json!({
                                    "status": "known",
                                    "value": { "ticket": ticket },
                                    "recovery": null,
                                })
                            }),
                        Err(rejection) => {
                            observe_daemon_request(
                                "kernel.daemon_queued_attach_release",
                                "startup_gate_closed",
                            );
                            Ok(Self::queued_attach_release_gate_response(
                                self,
                                &rejection.to_string(),
                            ))
                        }
                    }
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
                        Ok(host_request_route::LocalReadSubmitDisposition::StagedWrite(_)) => {
                            Err(TransportError::SessionFenced)
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
                        Some(pair) => serde_json::json!({
                            "status": "known",
                            "value": { "pair": {
                                "record": pair.record,
                                "durable_attempt": pair.durable_attempt,
                                "envelope": pair.envelope,
                                "tool": pair.tool,
                                "attempt": pair.result_attempt,
                                "source_request_identity": pair.source_request_identity,
                            } },
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
                        Ok(host_request_route::LocalReadSubmitDisposition::StagedWrite(
                            submission,
                        )) => Ok(store_apply_staged_response(&submission)),
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
                        Ok(
                            host_request_route::ObserveDeferDisposition::ReconciliationRequired(
                                record,
                            ),
                        ) => Ok(Self::unknown_observe_daemon_response(
                            record.operation_id.as_str(),
                        )),
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
                        Ok(host_request_route::LocalReadSubmitDisposition::StagedWrite(_)) => {
                            Err(TransportError::SessionFenced)
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
                            Some((
                                envelope,
                                tool,
                                invocation,
                                attempt,
                                authenticated_principal,
                            )) => serde_json::json!({
                                "status": "known",
                                "value": {
                                    "pair": {
                                        "invocation": invocation,
                                        "authenticated_principal": authenticated_principal,
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
                        Ok(host_request_route::LocalReadSubmitDisposition::StagedWrite(_)) => {
                            Err(TransportError::SessionFenced)
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
            "finish_claim" => {
                #[cfg(windows)]
                {
                    if payload.as_object().is_none_or(|object| object.len() != 1) {
                        return Err(TransportError::SessionFenced);
                    }
                    self.claim_finish_pair(session).map(|pair| match pair {
                        Some((envelope, tool, attempt)) => serde_json::json!({
                            "status": "known",
                            "value": {
                                "pair": {
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
            "finish_result" => {
                #[cfg(windows)]
                {
                    let result_value = payload
                        .get("result")
                        .cloned()
                        .ok_or(TransportError::SessionFenced)?;
                    let body: eliot_protocol::FinishResultBody =
                        serde_json::from_value(result_value)
                            .map_err(|_| TransportError::SessionFenced)?;
                    match self.submit_finish_result(session, &body) {
                        Ok(host_request_route::LocalReadSubmitDisposition::Persisted(_)) => {
                            Ok(Self::accepted_daemon_response())
                        }
                        Ok(host_request_route::LocalReadSubmitDisposition::StagedWrite(_)) => {
                            Err(TransportError::SessionFenced)
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
                // front-door submit arm (issue #2565): linkage and a bounded
                // queue reservation precede admission and payload handoff.
                // Issue #1742 W4 (caller STITCH): the Governor owner's
                // material gate (`eliot-context-admission` admit, dispatch
                // binding, and dispatch-time revalidation over
                // owner-resolved inputs) runs Governor-side, never here:
                // the Kernel owns only the mechanical dispatch binding and
                // must not mint floor, lineage, or authority verdicts
                // (I01-08 canonical write path). That call site is the
                // Governor owner's to write, and is named here rather than
                // faked with a consumer in this crate.
                let envelope = host_request_route::host_request_envelope_from_payload(payload)?;
                let observe_tool = payload.get("tool").cloned();
                let (receipt, record) = self.admit_and_queue_observe_submit(
                    &envelope,
                    observe_tool.as_ref(),
                    request_identity,
                )?;
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
                // Issue #1742 W6 (caller STITCH): resuming under retained
                // history (admission over #1730's retained checkpoint plus
                // its revalidation, then a resume-phase dispatch binding
                // with dispatch-time revalidation) is the resume owner's
                // join in `eliot-context-admission`: unavailable or
                // erased originals stay explicit and a derived summary never
                // replaces the original checkpoint. This mechanical readback
                // serves the durable record and stages no new authority
                // either way; that call site is the resume owner's to write,
                // and is named here rather than faked with a consumer here.
                let envelope = host_request_route::host_request_envelope_from_payload(payload)?;
                let receipt = host_request_route::host_request_receipt_from_payload(payload)?;
                let record = self.rehydrate_host_request(&envelope, &receipt)?;
                let stage = self.validated_original_staged_observe_submission(&record)?;
                Ok(host_request_route::host_request_rehydrated_response(
                    &record,
                    stage.as_ref(),
                ))
            }
            "initialize_owner_revision" => {
                let operation: OwnerRevisionOperation =
                    serde_json::from_value(without_daemon_routing_key(payload.clone())?)
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
                self.admit_material_authority_for_governor_issued_fence(
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
            PUBLISH_GOVERNOR_AUTHORITY_OPERATION => {
                let operation: GovernorAuthorityPublishOperation =
                    serde_json::from_value(payload.clone())
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.operation != PUBLISH_GOVERNOR_AUTHORITY_OPERATION {
                    return Err(TransportError::SessionFenced);
                }
                // Issue #1935 AUD1: the live Governor-owned derivation
                // projects its exact revision, exact active fingerprint, and
                // exact authorization axes across this authenticated boundary.
                // The axes map to the existing three-axis profile and record
                // under the strictly-advancing revision rule, so a newer
                // degraded projection revokes everything issued under the old
                // one. Until the first publish records, every
                // Material/Critical gate refuses closed.
                self.record_governor_issued_coverage_projection(
                    operation.revision,
                    operation.fingerprint,
                    operation.verified,
                    operation.authorizes_enforcement,
                    operation.authorizes_complete_coverage_ops,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                Ok(serde_json::json!({
                    "status": "known",
                    "value": {
                        "kind": "governor_authority_receipt",
                        "value": { "revision": operation.revision, "status": "recorded" },
                    },
                    "recovery": null,
                }))
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
                    serde_json::from_value(without_daemon_routing_key(payload.clone())?)
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
            GRANT_CLOSURE_RECEIPT_OPERATION => {
                let query: eliot_kernel_service::GrantClosureReceiptQuery =
                    serde_json::from_value(without_daemon_routing_key(payload.clone())?)
                        .map_err(|_| TransportError::SessionFenced)?;
                // Same-fence admission, exactly as the sibling read does it:
                // the query is refused before the retained owner is even
                // locked.
                if query.state_fence != session.module_generation.state_fence {
                    return Err(TransportError::SessionFenced);
                }
                // The owner that committed the first phase is the only accepted
                // source; an unbound composition withholds the read rather than
                // routing to a no-authority port.
                let owner = self.retained_p07_owner()?;
                let bound = owner.as_ref().ok_or(TransportError::SessionFenced)?;
                match eliot_kernel_service::serve_grant_closure_receipt(
                    bound.port(),
                    &query,
                    &session.module_generation.state_fence,
                ) {
                    // The owner's committed bytes, verbatim.
                    Ok(receipt) => Ok(serde_json::json!({
                        "kind": GRANT_CLOSURE_RECEIPT_KIND,
                        "value": receipt,
                    })),
                    // A refusal keeps its durable reason and stays a refusal:
                    // the daemon must never read "no committed closure" as
                    // "this grant needs no closure".
                    Err(error) => Ok(serde_json::json!({
                        "kind": GRANT_CLOSURE_RECEIPT_REFUSAL_KIND,
                        "value": { "reason": error.to_string() },
                    })),
                }
            }
            LINK_GRANT_CLOSURE_RECEIPT_OPERATION => {
                let request: eliot_kernel_service::GrantClosureCanonicalLinkRequest =
                    serde_json::from_value(without_daemon_routing_key(payload.clone())?)
                        .map_err(|_| TransportError::SessionFenced)?;
                if request.state_fence != session.module_generation.state_fence {
                    return Err(TransportError::SessionFenced);
                }
                // The Kernel owns ORS in its own process, so the link is
                // recorded against the one durable store that holds the
                // immutable first-phase row this operation names.
                match eliot_kernel_service::commit_grant_closure_canonical_link(
                    self.p07_ors.as_ref(),
                    &request,
                    &session.module_generation.state_fence,
                ) {
                    // The proved read-back of the durable link, so the caller
                    // never has to take the store's word for it.
                    Ok(projection) => Ok(serde_json::json!({
                        "kind": GRANT_CLOSURE_LINK_KIND,
                        "value": projection,
                    })),
                    // An uncommitted first phase, an immutable conflict, or a
                    // transient failure all refuse with their durable reason;
                    // none of them is a completed link.
                    Err(error) => Ok(serde_json::json!({
                        "kind": GRANT_CLOSURE_LINK_REFUSAL_KIND,
                        "value": { "reason": error.to_string() },
                    })),
                }
            }
            "activate_grant" => {
                let operation: GrantActivationOperation =
                    serde_json::from_value(without_daemon_routing_key(payload.clone())?)
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.grant_id.trim().is_empty() || operation.snapshot_id.trim().is_empty() {
                    return Err(TransportError::SessionFenced);
                }
                p07_binding_agrees_with_session(&operation.binding, &operation.subject, session)?;
                if let Err(refusal) = self.admit_p07_target_against_current_grant_graph(
                    P07LifecycleTarget::Grant(&operation.grant_id),
                    &operation.snapshot_id,
                    false,
                ) {
                    return p07_refusal_frame(
                        session,
                        request_id.clone(),
                        "activate_grant",
                        &refusal,
                    );
                }
                self.admit_material_authority_for_governor_issued_fence(
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
                match eliot_authority::P07AuthorityPort::activate_grant(bound.port(), &request) {
                    Ok(receipt) => {
                        let value = serde_json::to_value(&receipt)
                            .map_err(|_| TransportError::SessionFenced)?;
                        Ok(serde_json::json!({
                            "status": "known",
                            "value": {
                                "kind": "authority_activation_receipt",
                                "value": value,
                            },
                            "recovery": null,
                        }))
                    }
                    Err(refusal) => Ok(p07_refusal_response("activate_grant", &refusal)),
                }
            }
            "revoke_grant" => {
                let operation: GrantRevocationOperation =
                    serde_json::from_value(without_daemon_routing_key(payload.clone())?)
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.grant_id.trim().is_empty() || operation.snapshot_id.trim().is_empty() {
                    return Err(TransportError::SessionFenced);
                }
                p07_binding_agrees_with_session(&operation.binding, &operation.subject, session)?;
                if let Err(refusal) = self.admit_p07_target_against_current_grant_graph(
                    P07LifecycleTarget::Grant(&operation.grant_id),
                    &operation.snapshot_id,
                    true,
                ) {
                    return p07_refusal_frame(
                        session,
                        request_id.clone(),
                        "revoke_grant",
                        &refusal,
                    );
                }
                let request = eliot_authority::GrantRevocationRequest {
                    grant_id: eliot_authority::GrantId::new(operation.grant_id)
                        .map_err(|_| TransportError::SessionFenced)?,
                    snapshot_id: eliot_authority::SnapshotId::new(operation.snapshot_id)
                        .map_err(|_| TransportError::SessionFenced)?,
                    binding: operation.binding,
                };
                let owner = self.retained_p07_owner()?;
                let bound = owner.as_ref().ok_or(TransportError::SessionFenced)?;
                match eliot_authority::P07AuthorityPort::revoke_grant(bound.port(), &request) {
                    Ok(receipt) => {
                        let value = serde_json::to_value(&receipt)
                            .map_err(|_| TransportError::SessionFenced)?;
                        Ok(serde_json::json!({
                            "status": "known",
                            "value": {
                                "kind": "authority_revocation_receipt",
                                "value": value,
                            },
                            "recovery": null,
                        }))
                    }
                    Err(refusal) => Ok(p07_refusal_response("revoke_grant", &refusal)),
                }
            }
            "activate_introduction" => {
                let operation: IntroductionActivationOperation =
                    serde_json::from_value(without_daemon_routing_key(payload.clone())?)
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.introduction_id.trim().is_empty()
                    || operation.snapshot_id.trim().is_empty()
                {
                    return Err(TransportError::SessionFenced);
                }
                p07_binding_agrees_with_session(&operation.binding, &operation.subject, session)?;
                if let Err(refusal) = self.admit_p07_target_against_current_grant_graph(
                    P07LifecycleTarget::Introduction(&operation.introduction_id),
                    &operation.snapshot_id,
                    false,
                ) {
                    return p07_refusal_frame(
                        session,
                        request_id.clone(),
                        "activate_introduction",
                        &refusal,
                    );
                }
                self.admit_material_authority_for_governor_issued_fence(
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
                match eliot_authority::P07AuthorityPort::activate_introduction(
                    bound.port(),
                    &request,
                ) {
                    Ok(receipt) => {
                        let value = serde_json::to_value(&receipt)
                            .map_err(|_| TransportError::SessionFenced)?;
                        Ok(serde_json::json!({
                            "status": "known",
                            "value": {
                                "kind": "authority_activation_receipt",
                                "value": value,
                            },
                            "recovery": null,
                        }))
                    }
                    Err(refusal) => Ok(p07_refusal_response("activate_introduction", &refusal)),
                }
            }
            "revoke_introduction" => {
                let operation: IntroductionRevocationOperation =
                    serde_json::from_value(without_daemon_routing_key(payload.clone())?)
                        .map_err(|_| TransportError::SessionFenced)?;
                if operation.introduction_id.trim().is_empty()
                    || operation.snapshot_id.trim().is_empty()
                {
                    return Err(TransportError::SessionFenced);
                }
                p07_binding_agrees_with_session(&operation.binding, &operation.subject, session)?;
                if let Err(refusal) = self.admit_p07_target_against_current_grant_graph(
                    P07LifecycleTarget::Introduction(&operation.introduction_id),
                    &operation.snapshot_id,
                    true,
                ) {
                    return p07_refusal_frame(
                        session,
                        request_id.clone(),
                        "revoke_introduction",
                        &refusal,
                    );
                }
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
                match eliot_authority::P07AuthorityPort::revoke_introduction(bound.port(), &request)
                {
                    Ok(receipt) => {
                        let value = serde_json::to_value(&receipt)
                            .map_err(|_| TransportError::SessionFenced)?;
                        Ok(serde_json::json!({
                            "status": "known",
                            "value": {
                                "kind": "authority_revocation_receipt",
                                "value": value,
                            },
                            "recovery": null,
                        }))
                    }
                    Err(refusal) => Ok(p07_refusal_response("revoke_introduction", &refusal)),
                }
            }
            ACTIVATE_ROOT_TRANSITION_OPERATION => {
                let operation: RootTransitionActivationOperation =
                    serde_json::from_value(without_daemon_routing_key(payload.clone())?)
                        .map_err(|_| TransportError::SessionFenced)?;
                // Binding and subject are rechecked against the authenticated
                // session BEFORE the retained owner is touched, so a stale or
                // cross-session crossing never reaches the port.
                p07_binding_agrees_with_session(&operation.binding, &operation.subject, session)?;
                self.admit_material_authority_for_governor_issued_fence(
                    &session.module_generation.state_fence,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                let record = eliot_authority::RootTransitionRecord {
                    transition_id: operation.transition_id,
                    operation_id: operation.operation_id,
                    idempotency_key: operation.idempotency_key,
                    parent_grant_id: operation.parent_grant_id,
                    child_grant_id: operation.child_grant_id,
                    parent_grant_commitment: operation.parent_grant_commitment,
                    child_grant_commitment: operation.child_grant_commitment,
                    from_authority_root_ref: operation.from_authority_root_ref,
                    to_authority_root_ref: operation.to_authority_root_ref,
                    issuer: operation.issuer,
                    graph_snapshot_id: operation.graph_snapshot_id,
                    predecessor_graph_revision: operation.predecessor_graph_revision,
                    expected_next_graph_revision: operation.expected_next_graph_revision,
                    admitted_at_revision: operation.expected_next_graph_revision,
                    policy_revision: operation.policy_revision,
                    deadline_unix_ms: operation.deadline_unix_ms,
                    effect_ceiling: operation.effect_ceiling,
                    semantic_decision_ref: operation.semantic_decision_ref,
                    binding: operation.binding,
                };
                // The presented canonical request digest must be the one this
                // exact operation produces: a recomputed digest is authority
                // readback over the presented bytes, not caller assertion.
                let request = eliot_authority::RootTransitionActivationRequest::new(
                    record,
                    operation.subject,
                )
                .map_err(|_| TransportError::SessionFenced)?;
                if request.canonical_request_digest() != operation.canonical_request_digest {
                    return Err(TransportError::IdentityConflict);
                }
                let owner = self.retained_p07_owner()?;
                let bound = owner.as_ref().ok_or(TransportError::SessionFenced)?;
                // A decided port refusal is a completed application answer, not
                // a lost acknowledgement: it is answered with its exact typed
                // cause, I7.20 classification and snapshot, like the four
                // lifecycle arms, instead of collapsing to one bare transport
                // code that the daemon can only read as a generic failure.
                match eliot_authority::P07AuthorityPort::activate_root_transition(
                    bound.port(),
                    &request,
                ) {
                    Ok(receipt) => {
                        receipt
                            .validate(&request)
                            .map_err(|_| TransportError::SessionFenced)?;
                        let value = serde_json::to_value(&receipt)
                            .map_err(|_| TransportError::SessionFenced)?;
                        Ok(serde_json::json!({
                            "kind": ROOT_TRANSITION_RECEIPT_KIND,
                            "value": value,
                        }))
                    }
                    Err(refusal) => Ok(p07_refusal_response(
                        ACTIVATE_ROOT_TRANSITION_OPERATION,
                        &refusal,
                    )),
                }
            }
            "publish_wasm_dispatch_bundle" => {
                self.wasm_dispatch_bundle_operation(
                    session,
                    payload.clone(),
                    &context,
                    subordinate_terminal_emitted,
                )
                .await
            }
            "bind_notify_launch_grant" => {
                self.notify_launch_grant_operation(session, payload.clone())
                    .await
            }
            "bind_operator_session_token" => {
                self.operator_session_token_operation(session, payload.clone())
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
    fn revoke_supervision_expired_effect_admission(
        &self,
        lease_id: &str,
    ) -> Result<(), TransportError> {
        self.promote_agent_bridge_profile(None)?;
        observe_daemon_request(
            "kernel.daemon.supervision_expired_effects_revoked",
            "success",
        );
        // Issue #1837: durable audit evidence for lease expiry. The expired
        // head's binding fence is read best-effort: observation never fails
        // the revocation.
        let snapshot = self
            .supervision_lease_authority
            .as_ref()
            .and_then(|authority| authority.current_snapshot(lease_id).ok().flatten());
        self.audit_observe(AuditEventDraft::lease_supervision_expired(
            snapshot.as_ref(),
        ));
        // Issue #1844: a forced lease expiry is the repeated-no-progress
        // signal; compile its brief.
        self.observe_diagnostic_problem(
            super::diagnostic_brief::DiagnosticTrigger::RepeatedFailureOrNoProgress,
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

    #[cfg(windows)]
    fn supervision_kernel_artifact(&self) -> Result<&str, TransportError> {
        self.kernel_artifact_sha256
            .as_deref()
            .ok_or(TransportError::SessionFenced)
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
    #[allow(
        clippy::too_many_lines,
        reason = "progress dispatch keeps renewal, cleanup, publication and its propagated terminal-owner signal in their original order"
    )]
    fn daemon_supervision_progress_operation(
        &self,
        payload: serde_json::Value,
        context: &tracing::Span,
        subordinate_terminal_emitted: &mut bool,
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
        record_daemon_progress_operation_context(context, &request);
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
        super::daemon_live_receipt::record_process_receipt_context(context, &process);
        // Keep the current validated progress operation's references while
        // carrying the original process receipt's physical identity.
        record_daemon_progress_operation_context(context, &request);
        let authority = self
            .supervision_lease_authority
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let artifact = self.supervision_kernel_artifact()?;
        let mut child_terminal_owned = false;
        let renewal = Self::renew_current_supervision_with_progress(
            authority.as_ref(),
            &contour,
            &request,
            &mut progress,
            &SUPERVISION_LEASE_RENEWAL_POLICY,
            unix_ms(),
            artifact,
            context,
            &mut child_terminal_owned,
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
                    self.revoke_supervision_expired_effect_admission(&lease_id)?;
                }
                return self.progress_refusal_answer(&lease_id, &error);
            }
            Err(SupervisionProgressRenewalError::Authority(_)) => {
                if child_terminal_owned {
                    *subordinate_terminal_emitted = true;
                }
                self.retain_supervision_progress(progress, None, None)
                    .inspect_err(|_| {
                        if child_terminal_owned {
                            tracing::warn!(
                                target: super::kernel_diagnostics::KERNEL_DIAGNOSTICS_TARGET,
                                parent: context,
                                event = "kernel.supervision.progress_cleanup_refused",
                                outcome = "unavailable",
                                "cleanup failed after an already-owned operation terminal"
                            );
                        }
                    })?;
                return Err(TransportError::SessionFenced);
            }
        };
        self.retain_supervision_progress(progress, Some(request.observation.clone()), Some(false))?;
        let receipt = if decision.outcome == DaemonSupervisionRenewalOutcome::Renewed {
            let published = self
                .publish_eliotd_live_receipt(
                    &launch,
                    &process,
                    &ready,
                    &contour,
                    Some(&snapshot),
                    context,
                )
                .map_err(|_| {
                    *subordinate_terminal_emitted = true;
                    TransportError::SessionFenced
                })?;
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
            UserAutomationHostExecutionOperation::CancelPendingWakes { request }
            | UserAutomationHostExecutionOperation::ReadCancellationBatch { request } => {
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
            UserAutomationHostExecutionOperation::EnumeratePendingWakes { request } => {
                if let Err(error) = request.validate() {
                    return Ok(Self::user_automation_runtime_error_response(
                        UserAutomationRuntimeError::Rejected(error.to_string()),
                    ));
                }
                &request.context.state_fence
            }
            UserAutomationHostExecutionOperation::PublishWakeHorizon { request }
            | UserAutomationHostExecutionOperation::ReadWakeHorizonPublication { request } => {
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
            UserAutomationHostExecutionOperation::CancelPendingWakes { request }
            | UserAutomationHostExecutionOperation::ReadCancellationBatch { request } => {
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
            UserAutomationHostExecutionOperation::EnumeratePendingWakes { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_enumeration(session, request)
                        .await,
                )
            }
            UserAutomationHostExecutionOperation::PublishWakeHorizon { request }
            | UserAutomationHostExecutionOperation::ReadWakeHorizonPublication { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_horizon(session, request)
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
            UserAutomationHostExecutionOperation::CancelPendingWakes { request }
            | UserAutomationHostExecutionOperation::ReadCancellationBatch { request } => {
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
            UserAutomationHostExecutionOperation::EnumeratePendingWakes { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_enumeration(session, request)
                        .await,
                )
            }
            UserAutomationHostExecutionOperation::PublishWakeHorizon { request }
            | UserAutomationHostExecutionOperation::ReadWakeHorizonPublication { request } => {
                Self::user_automation_owner_check(
                    self.revalidate_user_automation_horizon(session, request)
                        .await,
                )
            }
        };
        if let Some(answer) = owner_check {
            return Ok(answer);
        }

        match request {
            UserAutomationHostExecutionOperation::AdmitOccurrence { request } => {
                self.admit_material_authority_for_governor_issued_fence(
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
            UserAutomationHostExecutionOperation::ReadCancellationBatch { request } => {
                match Box::pin(client.read_cancellation_batch(request)).await {
                    Ok(readback) => Ok(serde_json::json!({
                        "status": "known",
                        "value": {
                            "outcome": "cancellation_batch_readback",
                            "readback": readback,
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
            UserAutomationHostExecutionOperation::EnumeratePendingWakes { request } => {
                let receipt = match Box::pin(client.enumerate_pending_wakes(request)).await {
                    Ok(receipt) => receipt,
                    Err(error) => {
                        return Ok(Self::user_automation_runtime_error_response(error));
                    }
                };
                Ok(Self::user_automation_wake_enumeration_response(&receipt))
            }
            UserAutomationHostExecutionOperation::PublishWakeHorizon { request } => {
                let answer = match Box::pin(client.publish_wake_horizon(request.clone())).await {
                    Ok(answer) => answer,
                    Err(error) => {
                        return Ok(Self::user_automation_runtime_error_response(error));
                    }
                };
                Ok(Self::user_automation_horizon_publication_response(
                    "wake_horizon_published",
                    request.as_ref(),
                    &answer,
                ))
            }
            UserAutomationHostExecutionOperation::ReadWakeHorizonPublication { request } => {
                let answer =
                    match Box::pin(client.read_wake_horizon_publication(request.clone())).await {
                        Ok(answer) => answer,
                        Err(error) => {
                            return Ok(Self::user_automation_runtime_error_response(error));
                        }
                    };
                Ok(Self::user_automation_horizon_publication_response(
                    "wake_horizon_publication_readback",
                    request.as_ref(),
                    &answer,
                ))
            }
        }
    }

    #[cfg(windows)]
    /// Projects one schedule owner's horizon answer against the exact request it
    /// was asked for (issue #2806 items 4 and 9).
    ///
    /// The owner's acknowledgement is validated against the exact publication
    /// through `UserAutomationWakePublication::validate_for`, which requires the
    /// acknowledged and remaining sets to partition the requested set exactly.
    /// An answer that does not account for the request is reported as unknown
    /// rather than as a partial success, because a mismatched remainder is not
    /// evidence about any occurrence.
    ///
    /// A remainder is never projected as completion. When the owner leaves
    /// occurrences unacknowledged, the exact remaining set and the owner's own
    /// replay handle are returned as the recovery directive, which forces
    /// `status: "unknown"`; only an answer that acknowledged the whole requested
    /// set settles the route.
    ///
    /// The answer is borrowed rather than taken by value: it is read twice — once
    /// to validate it against the request and once to project it — and
    /// `serde_json::json!` borrows every interpolated expression, so a by-value
    /// parameter would be copied in and never consumed.
    #[cfg(windows)]
    fn user_automation_horizon_publication_response(
        outcome: &str,
        request: &UserAutomationWakeHorizonPublication,
        answer: &UserAutomationWakePublication,
    ) -> serde_json::Value {
        if let Err(error) = answer.validate_for(request) {
            return Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::UnknownOutcome(format!(
                    "the schedule owner answer does not account for the requested horizon: {error}"
                )),
            );
        }
        let recovery = if answer.acknowledged_all() {
            None
        } else {
            Some(serde_json::json!({
                "kind": "partial_horizon",
                "reason": "the schedule owner did not acknowledge every requested occurrence, so \
                           the exact remaining set is retained and must be replayed under its \
                           handle",
                "automation_id": &answer.automation_id,
                "automation_revision": &answer.automation_revision,
                "remaining_occurrence_ids": &answer.remaining_occurrence_ids,
                "retry_handle": &answer.retry_handle,
            }))
        };
        serde_json::json!({
            "status": if recovery.is_none() { "known" } else { "unknown" },
            "value": {
                "outcome": outcome,
                "publication": answer,
            },
            "recovery": recovery,
        })
    }

    #[cfg(windows)]
    /// Projects one complete owner wake enumeration against the exact request it
    /// was asked for (issue #2806 item 9).
    ///
    /// An enumeration receipt is not a completeness proof. `Unresolved` is the
    /// owner's own disposition for a denominator member its one Host snapshot
    /// could not classify: a duplicated record, a retained record identity that
    /// conflicts with the denominator member, or a retained pending record under
    /// a different State Fence. The owner answers with the typed
    /// `UserAutomationWakeOccurrenceDisposition::Unresolved` per-member
    /// reference in `evidence` plus a closed `reason`. The same crate already
    /// refuses to derive a cancellation target set from such a receipt:
    /// `UserAutomationWakeEnumerationReceipt::cancellation_targets` and
    /// `KernelStoreGateway`'s retirement path both reject a non-zero
    /// `coverage.unresolved_count`.
    ///
    /// Reporting such a receipt as `status: "known"` with `recovery: null` told
    /// the caller that nothing was outstanding, which is exactly the claim the
    /// owner refused to make. No complete owner-issued pending-wake set is
    /// proven, so a `cancelled_wake_ids` list derived from it would be a short
    /// page rather than evidence that no wake exists. An unresolved member is
    /// therefore reported as an incomplete owner query, never as completion.
    ///
    /// The outstanding set is read from the receipt's own validated
    /// `dispositions`, which is the owner's answer rather than a list this
    /// function built, and the reconciliation handle is the receipt's own
    /// `parent_operation_identity`: the exact operation identity the Host owner
    /// must be asked about again under. A receipt whose denominator is fully
    /// classified, every member either `PendingTarget` or `NotRetained`, is a
    /// complete enumeration and still settles, because only then is the derived
    /// target set the complete one the owner proved.
    fn user_automation_wake_enumeration_response(
        receipt: &UserAutomationWakeEnumerationReceipt,
    ) -> serde_json::Value {
        let unresolved_occurrence_ids = receipt
            .dispositions
            .iter()
            .filter_map(|disposition| match disposition {
                UserAutomationWakeOccurrenceDisposition::Unresolved { evidence, .. } => {
                    Some(evidence.occurrence_id.clone())
                }
                UserAutomationWakeOccurrenceDisposition::PendingTarget { .. }
                | UserAutomationWakeOccurrenceDisposition::NotRetained { .. } => None,
            })
            .collect::<Vec<String>>();
        let recovery = if unresolved_occurrence_ids.is_empty() {
            None
        } else {
            Some(serde_json::json!({
                "kind": "unknown_outcome",
                "reason": "the schedule owner accounted for every committed occurrence of this \
                           revision but left the members below unclassified, so no complete \
                           owner-issued pending-wake set is proven and no cancellation set may be \
                           derived from this answer; each member carries its own owner evidence \
                           and closed reason inside the enumeration receipt, and the exact \
                           unresolved set must be reconciled under its parent operation identity",
                "automation_id": &receipt.automation_id,
                "automation_revision": &receipt.automation_revision,
                "unresolved_occurrence_ids": unresolved_occurrence_ids,
                "unresolved_occurrence_count": receipt.coverage.unresolved_count,
                "parent_operation_identity": &receipt.parent_operation_identity,
                "host_owner_identity": &receipt.host_owner_identity,
                "host_owner_generation": &receipt.host_owner_generation,
                "journal_sequence": receipt.journal_sequence,
                "snapshot_digest": &receipt.snapshot_digest,
            }))
        };
        serde_json::json!({
            "status": if recovery.is_none() { "known" } else { "unknown" },
            "value": {
                "outcome": "wake_enumeration",
                "receipt": receipt,
            },
            "recovery": recovery,
        })
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
    /// The closed vocabulary is not the same set as `UserAutomationOperation`:
    /// the I12.24:65 owner decision appears in the latter and is refused at this
    /// boundary, because the automation Store has no automation identity to
    /// commit it under and this route will not report a durable outcome for a
    /// decision it cannot record.
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
        let request = Self::build_user_automation_operator_request(session, &request_id, payload)?;
        match eliot_kernel_service::KernelStoreGateway::validate_user_automation_request(&request) {
            Ok(()) => {}
            Err(eliot_kernel_service::UserAutomationExecutionError::Contract(error)) => {
                return Self::bind_user_automation_operator_response(
                    &request,
                    &Self::user_automation_precommit_refusal_response(&request, &error),
                );
            }
            Err(_) => {
                return Self::bind_user_automation_operator_response(
                    &request,
                    &Self::user_automation_runtime_error_response(
                        UserAutomationRuntimeError::UnknownOutcome(
                            "user_automation_request_validation_outcome_unavailable".to_owned(),
                        ),
                    ),
                );
            }
        }
        let transition = match self
            .dispatch_user_automation_operator_transition(session, &request)
            .await
        {
            Ok(transition) => transition,
            Err(response) => {
                return Self::bind_user_automation_operator_response(&request, &response);
            }
        };
        if !transition.is_known() {
            // F-LOG-KERNEL-1 (#897 T19): the store transition reports an
            // unknown wake/execution outcome after possible work. The
            // response body carries `"status": "unknown"` below; this record
            // keeps the diagnostic stream honest alongside it. Observation
            // only; the response value is unchanged.
            observe_daemon_request("kernel.daemon_response_unknown", "unknown");
        }
        let Ok(envelope) =
            eliot_kernel_service::UserAutomationOperatorResultEnvelope::from_transition(
                &request, transition,
            )
        else {
            // F-LOG-KERNEL-1 (#897 W5): correlated subordinate phase
            // observation only; `execute_daemon_request_observed` owns
            // the single designated terminal for this failed operation.
            observe_daemon_request(
                "kernel.daemon_user_automation_occurrence_projection",
                "unknown",
            );
            return Self::bind_user_automation_operator_response(
                &request,
                &Self::user_automation_runtime_error_response(
                    UserAutomationRuntimeError::UnknownOutcome(
                        "user_automation_occurrence_projection_requires_reconciliation".to_owned(),
                    ),
                ),
            );
        };
        serde_json::to_value(envelope).map_err(|_| TransportError::SessionFenced)
    }

    #[cfg(windows)]
    fn bind_user_automation_operator_response(
        request: &eliot_kernel_service::UserAutomationServiceRequest,
        response: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let envelope =
            eliot_kernel_service::UserAutomationOperatorResultEnvelope::bind_internal_response(
                request, response,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        serde_json::to_value(envelope).map_err(|_| TransportError::SessionFenced)
    }

    /// Serves one complete owner-issued `UserAutomation` preflight projection
    /// (issue #1779 W4/A3, I11.12).
    ///
    /// The client already asks for this named read and the projection type
    /// already knows how to assemble itself; what was missing was the
    /// Kernel-side production owner that serves it. This route is that owner.
    /// Every one of the fifteen members comes from the owner that attests it:
    /// the immutable revision and the live configuration pointer from the
    /// canonical owner readback, the persisted invocation lineage from the
    /// Store, the complete config snapshot from the B-owned policy owner, the
    /// source verification receipt from the committed `RunNow` Store receipt,
    /// the execution projection from the Durable Job/history `Status` owner,
    /// the normalization envelope the revision row retained, the Skill and
    /// Tool Definition revisions the revision declares, and delivery
    /// capability from the named platform observation. The observed provider
    /// fingerprint stays absent because this boundary issues no provider call
    /// before preflight — which is exactly what deterministic mode requires —
    /// and `UserAutomationPreflightProjection::assemble` refuses every other
    /// gap instead of letting it through. A member no reachable owner attests
    /// is a typed refusal naming that owner, never a default.
    #[cfg(windows)]
    async fn user_automation_preflight_projection_operation(
        &self,
        session: &Session,
        request_id: RequestId,
        payload: &serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let route: UserAutomationPreflightReadRoute =
            serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
        if route.operation != USER_AUTOMATION_PREFLIGHT_SELECTOR
            || route.payload.operation
                != eliot_kernel_core::user_automation::USER_AUTOMATION_PREFLIGHT_OPERATION
        {
            return Err(TransportError::SessionFenced);
        }
        let identity = route.request_identity;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if identity.request.metadata.request_id != request_id
            || identity.request.state_fence != session.module_generation.state_fence
            || route.payload.context != identity.request.metadata
            || route.payload.state_fence != session.module_generation.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        let principal = authenticated_user_automation_principal(session)?;
        // Boxed because the join below is a large composed future; the box
        // keeps this arm's own future small without changing what it awaits.
        match Box::pin(self.read_user_automation_preflight_projection(
            session,
            &principal,
            &route.payload,
        ))
        .await
        {
            Ok(projection) => {
                let value =
                    serde_json::to_value(projection).map_err(|_| TransportError::SessionFenced)?;
                Ok(serde_json::json!({
                    "status": "known",
                    "value": value,
                    "recovery": null,
                }))
            }
            Err(error) => Ok(Self::user_automation_runtime_error_response(error)),
        }
    }

    /// Joins the live owner readbacks behind one preflight projection.
    ///
    /// The join order is fixed: bind the current owner revision and its live
    /// configuration pointer, then the persisted invocation lineage, then the
    /// policy, execution, receipt, and normalization owners, and only then
    /// assemble. A scheduled occurrence carries no committed `RunNow`
    /// provenance, so it has no committed `RunNow` source receipt either, and
    /// it is refused here by name rather than answered from an unrelated
    /// receipt. A `blocked_config` pointer needs its owner-issued failure
    /// projection, which only the Store-gateway run-now join can read, so it
    /// is refused here by name rather than answered without its failure. Both
    /// refusals name the missing owner instead of substituting a member.
    #[cfg(windows)]
    async fn read_user_automation_preflight_projection(
        &self,
        session: &Session,
        principal: &str,
        read: &UserAutomationPreflightReadPayload,
    ) -> Result<
        eliot_kernel_core::user_automation::UserAutomationPreflightProjection,
        UserAutomationRuntimeError,
    > {
        use eliot_kernel_core::user_automation::UserAutomationConfigurationState;

        let unavailable = UserAutomationRuntimeError::Unavailable;
        let fence = session.module_generation.state_fence.clone();
        let gateway = self.retained_store_gateway().map_err(|_| {
            unavailable("canonical UserAutomation Store owner is unavailable".to_owned())
        })?;
        let (owner, invocation) = self
            .user_automation_preflight_occurrence(&gateway, principal, read, &fence, unavailable)
            .await?;
        // The source verification receipt is the committed `RunNow` Store
        // receipt's reconciliation envelope, proved under the provenance the
        // persisted invocation carries. A scheduled occurrence never committed
        // one, so there is no owner-issued receipt to serve here; that is a
        // named missing owner, not a receipt this route may borrow from
        // another occurrence.
        let (source_receipt, provenance) = self
            .user_automation_preflight_source_receipt(&gateway, &invocation, &fence)
            .await?;
        let source_identity = OperationIdentity {
            operation_id: provenance.operation_id.clone(),
            idempotency_key: provenance.idempotency_key.clone(),
            canonical_request_hash: provenance.canonical_request_hash.clone(),
        };
        let provenance_context = provenance.request_metadata.clone();

        let config_snapshot = self.read_user_automation_policy_snapshot(&fence).await?;
        let execution = self
            .user_automation_preflight_execution_view(
                &gateway,
                principal,
                &owner,
                &provenance_context,
                &source_identity,
                &fence,
            )
            .await?;
        if execution.history_query_ref != owner.revision.execution_history_query_ref {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        // The blocked failure projection is owner-issued by the Store-gateway
        // run-now join, which this binary cannot reach without sealing a
        // canonical Store transition for a read. A `blocked_config` pointer
        // therefore cannot be answered here; it is refused by name rather than
        // served without its failure. Every other state assembles with no
        // failure, and assembly itself refuses a failure where none belongs.
        let failure = match owner.current_configuration_state {
            UserAutomationConfigurationState::BlockedConfig => {
                return Err(unavailable(
                    "the current owner configuration state is blocked_config but its \
                     owner-issued failure projection is readable only from the Store-gateway \
                     run-now owner, so no preflight projection can be reported"
                        .to_owned(),
                ));
            }
            _ => None,
        };
        // The normalization envelope is the retained bytes the revision row
        // carries, selected by the content-derived identity the immutable
        // revision names — the same selection the run-now assembler makes —
        // and assembly re-checks that those bytes name the compiled occurrence
        // digest. A row that retained none leaves the occurrence unadmitted by
        // name instead of receiving a substituted receipt.
        let normalization_receipts = Self::user_automation_preflight_normalization_receipts(
            &owner.revision,
            owner.normalization_receipt.as_ref(),
            unavailable,
        )?;
        // Live evidence below the Kernel decoding boundary. This read issues
        // no provider call before preflight, so the only honest provider
        // observation is none — which is exactly what deterministic mode
        // requires and what assembly enforces for every other mode through the
        // revision's own provider policy. The Tool Definition set is the exact
        // closure the canonical owner revision declares, repeated here so
        // assembly can compare the two instead of trusting this member.
        let evidence = eliot_kernel_core::user_automation::UserAutomationPreflightEvidence {
            observed_provider_fingerprint: None,
            trusted_tool_definition_refs: owner.revision.trusted_tool_definition_refs.clone(),
            delivery_available: Self::user_automation_preflight_delivery_capability(
                &owner.revision,
            ),
            failure,
        };
        eliot_kernel_core::user_automation::UserAutomationPreflightProjection::assemble(
            &eliot_kernel_core::user_automation::UserAutomationPreflightAssembly {
                revision: &owner.revision,
                configuration_state: owner.current_configuration_state,
                config_snapshot: &config_snapshot,
                source_receipt: &source_receipt,
                normalization_receipts: &normalization_receipts,
                execution: &execution,
                invocation: &invocation,
                request_metadata: &read.context,
                evidence: &evidence,
            },
        )
        .map_err(|error| {
            UserAutomationRuntimeError::UnknownOutcome(format!(
                "UserAutomation preflight assembly is not admitted: {error}"
            ))
        })
    }

    /// Reads and proves the owner revision and the persisted occurrence.
    ///
    /// Both readbacks are joined to the REQUEST, not merely to each other: the
    /// owner snapshot must name the requested automation, revision and mode
    /// under the requesting principal and the session fence, and the persisted
    /// invocation must recompute to the requested occurrence identity while
    /// agreeing with that owner on revision, trigger, mode, principal, work
    /// scope and workdir. A disagreement on any axis is an identity conflict
    /// rather than a projection of whichever record happened to be read.
    #[cfg(windows)]
    async fn user_automation_preflight_occurrence(
        &self,
        gateway: &eliot_kernel_service::KernelStoreGateway,
        principal: &str,
        read: &UserAutomationPreflightReadPayload,
        fence: &StateFence,
        unavailable: fn(String) -> UserAutomationRuntimeError,
    ) -> Result<
        (
            eliot_kernel_service::UserAutomationOwnerSnapshot,
            eliot_kernel_core::user_automation::UserAutomationInvocation,
        ),
        UserAutomationRuntimeError,
    > {
        let lookup = eliot_kernel_service::UserAutomationOwnerLookup {
            automation_id: read.automation_id.clone(),
            requested_revision: read.automation_revision.clone(),
            authenticated_principal: principal.to_owned(),
            state_fence: fence.clone(),
        };
        let owner = gateway
            .read_user_automation_owner(&lookup)
            .await
            .map_err(unavailable)?;
        if owner.automation_id != read.automation_id
            || owner.revision.revision != read.automation_revision
            || owner.revision.automation_id != read.automation_id
            || owner.revision.mode != read.mode
            || owner.authenticated_principal != principal
            || owner.state_fence != *fence
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        let invocation = gateway
            .read_user_automation_invocation(fence, &read.automation_id, &read.occurrence_id)
            .await
            .map_err(unavailable)?;
        let occurrence_id = invocation
            .occurrence_identity()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        if occurrence_id != read.occurrence_id
            || invocation.automation_id != owner.revision.automation_id
            || invocation.automation_revision != owner.revision.revision
            || invocation.trigger != read.trigger
            || invocation.mode != owner.revision.mode
            || invocation.principal_ref != owner.authenticated_principal
            || invocation.work_scope_ref != owner.revision.work_scope.scope_id
            || invocation.workdir_ref != owner.revision.workdir_ref
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Ok((owner, invocation))
    }

    /// Reads the Durable Job / history projection for this occurrence.
    ///
    /// The view reuses the committed occurrence identity the run-now provenance
    /// already proved, and the leg is the closed `Status` operation, so it
    /// issues no transition and mints no canonical identity: a read that sealed
    /// a write would turn a projection request into a mutation.
    #[cfg(windows)]
    async fn user_automation_preflight_execution_view(
        &self,
        gateway: &eliot_kernel_service::KernelStoreGateway,
        principal: &str,
        owner: &eliot_kernel_service::UserAutomationOwnerSnapshot,
        provenance_context: &eliot_contracts::RequestMetadata,
        source_identity: &OperationIdentity,
        fence: &StateFence,
    ) -> Result<
        eliot_kernel_core::user_automation::UserAutomationExecutionProjection,
        UserAutomationRuntimeError,
    > {
        let unavailable = UserAutomationRuntimeError::Unavailable;
        let sealed = eliot_kernel_service::UserAutomationServiceRequest {
            context: provenance_context.clone(),
            authenticated_principal: principal.to_owned(),
            identity: source_identity.clone(),
            intent: eliot_kernel_core::UserAutomationOperatorIntent {
                intent_id: format!(
                    "{}:preflight-owner-execution-view",
                    source_identity.operation_id.as_str()
                ),
                principal_ref: principal.to_owned(),
                state_fence: fence.clone(),
                operation: eliot_kernel_core::UserAutomationOperation::Status {
                    automation_id: owner.automation_id.clone(),
                },
            },
        };
        gateway
            .read_user_automation_owner_execution_view(&sealed, &owner.automation_id)
            .await
            .map_err(unavailable)
    }

    /// Resolves the committed `RunNow` source receipt for one persisted
    /// occurrence.
    ///
    /// The receipt is the Store owner's own record for the exact operation the
    /// invocation's run-now provenance names, so the lookup key is derived from
    /// that provenance rather than from the request. An occurrence with no
    /// committed run-now provenance has no owner-issued source receipt to serve
    /// and is refused by name; borrowing a receipt from another occurrence would
    /// attest this occurrence with another's evidence.
    ///
    /// The provenance is returned alongside the envelope because the run-now
    /// join proves the receipt's own request binding against the provenance the
    /// invocation committed, and this read performs that same proof rather than
    /// accepting the envelope on identity alone.
    #[cfg(windows)]
    async fn user_automation_preflight_source_receipt(
        &self,
        gateway: &eliot_kernel_service::KernelStoreGateway,
        invocation: &eliot_kernel_core::user_automation::UserAutomationInvocation,
        fence: &StateFence,
    ) -> Result<
        (
            eliot_receipts::ReceiptEnvelope,
            eliot_kernel_core::user_automation::UserAutomationInvocationProvenance,
        ),
        UserAutomationRuntimeError,
    > {
        let provenance = invocation.require_run_now_provenance(fence).map_err(|error| {
            UserAutomationRuntimeError::Rejected(format!(
                "UserAutomation preflight source receipt requires committed run-now provenance: {error}"
            ))
        })?;
        let identity = OperationIdentity {
            operation_id: provenance.operation_id.clone(),
            idempotency_key: provenance.idempotency_key.clone(),
            canonical_request_hash: provenance.canonical_request_hash.clone(),
        };
        let receipt = ensure_user_automation_store_receipt(gateway, fence, &identity).await?;
        let envelope = receipt
            .require_reconciliation_envelope()
            .cloned()
            .map_err(|error| {
                UserAutomationRuntimeError::UnknownOutcome(format!(
                    "canonical UserAutomation source receipt envelope is not retained: {error}"
                ))
            })?;
        // The envelope must be THIS provenance's receipt, proven against the
        // envelope's own request binding and work scope — the same joint the
        // run-now join makes. An envelope that merely exists for some other
        // operation, or one whose request body differs from the committed
        // provenance, is not this occurrence's source evidence.
        if envelope.core.request.metadata != provenance.request_metadata
            || envelope.core.work_scope.product_id != provenance.request_metadata.product_id
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        Ok((envelope, provenance.clone()))
    }

    /// Selects the retained normalization envelopes the immutable revision names.
    ///
    /// Selection is by the content-derived receipt identity the revision declares,
    /// never by position or by trusting the caller, and an empty selection is a
    /// refusal rather than a default: a row that retained no matching envelope
    /// leaves the compiled occurrence set self-asserted, which is exactly the
    /// state the occurrence must not be admitted from.
    #[cfg(windows)]
    fn user_automation_preflight_normalization_receipts(
        revision: &eliot_kernel_core::user_automation::UserAutomationRevision,
        retained: Option<&eliot_receipts::ReceiptEnvelope>,
        unavailable: fn(String) -> UserAutomationRuntimeError,
    ) -> Result<Vec<eliot_receipts::ReceiptEnvelope>, UserAutomationRuntimeError> {
        let declared = &revision.schedule.normalization_receipt;
        let selected = retained
            .filter(|envelope| {
                envelope.identity.receipt_id.as_str() == declared.receipt_id.as_str()
            })
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();
        if selected.is_empty() {
            return Err(unavailable(
                "no owner-issued schedule normalization receipt envelope is retained under this \
                 State Fence for the receipt identity the immutable revision names, so the \
                 compiled occurrence set stays self-asserted and the occurrence is not admitted"
                    .to_owned(),
            ));
        }
        Ok(selected)
    }

    /// Observes whether the declared delivery target is currently capable.
    ///
    /// This is the same named observation the run-now assembler applies: of
    /// the canonical channels only native toast is gated on a live interactive
    /// user session, so a declared toast target with no session behind it
    /// reports the capability it actually observed instead of defaulting to
    /// capable. The rule lives in one sentence here rather than behind a
    /// second helper because the owner it observes — the platform session —
    /// is the same one.
    #[cfg(windows)]
    fn user_automation_preflight_delivery_capability(
        revision: &eliot_kernel_core::user_automation::UserAutomationRevision,
    ) -> bool {
        !revision
            .delivery_target
            .channels
            .contains(&eliot_kernel_core::user_automation::DeliveryChannel::NativeToast)
            || eliot_platform_windows::interactive_user_session_available()
    }

    #[cfg(windows)]
    fn build_user_automation_operator_request(
        session: &Session,
        request_id: &RequestId,
        payload: &serde_json::Value,
    ) -> Result<eliot_kernel_service::UserAutomationServiceRequest, TransportError> {
        let route: UserAutomationOperatorRoute =
            serde_json::from_value(payload.clone()).map_err(|_| TransportError::SessionFenced)?;
        if route.operation != USER_AUTOMATION_OPERATOR_OPERATION {
            return Err(TransportError::SessionFenced);
        }
        let identity = route.request_identity;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        if &identity.request.metadata.request_id != request_id
            || identity.request.state_fence != session.module_generation.state_fence
            || route.payload.idempotency_key != identity.idempotency_key
        {
            return Err(TransportError::SessionFenced);
        }
        validate_user_automation_trigger_text(&route.payload.idempotency_key, "idempotency_key")?;
        // I12.24:65's "decision owner selects reject / investigate / work item /
        // experiment" is a closed operation on this boundary, and this route is
        // not the seam that can record one. The operation carries `brief_id`
        // and no `automation_id`, while every row, ordering scope and mutation
        // projection the canonical Store below owns is keyed by an automation
        // identity. Admitting it here would force one of two fabrications:
        // hang the decision on an invented automation so it could reach a
        // writer that cannot interpret it, or let it fall through to a Store
        // refusal after this route had already reported a reconcilable outcome
        // that no Store call ever backed. The second is the worse one, because
        // the recoverable answer this route hands back asserts "prior_attempt_
        // may_have_committed" about a Store that was never entered.
        //
        // Refusing here changes nothing about the brief, the candidate or
        // their authority: I12.24:82 makes the advisory class "default;
        // changes nothing until owner acts" and I12.24:3 states that ELIOT
        // "never silently rewrites code, policy or memory authority". What is
        // refused is only this route's claim to own a decision it cannot
        // durably record. The improvement owner is the single writer of that
        // record, and it must take the deciding principal from an
        // authenticated Session of its own — A12.02:3's "Identity is not a
        // model's self-declared string" is why the decision cannot be
        // forwarded over a payload and re-attributed there, and why an ingress
        // that could not bind the session principal has no honest way to
        // complete the selection at all.
        if matches!(
            route.payload.operation,
            eliot_kernel_core::UserAutomationOperation::DecideImprovementBrief { .. }
        ) {
            return Err(TransportError::SessionFenced);
        }
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
        Ok(eliot_kernel_service::UserAutomationServiceRequest {
            context: identity.request.metadata.clone(),
            authenticated_principal: principal,
            identity: OperationIdentity {
                operation_id,
                idempotency_key: route.payload.idempotency_key,
                canonical_request_hash: String::new(),
            },
            intent,
        })
    }

    /// Composes the existing Host runtime and executes the canonical operator
    /// transition. An error is already projected as the route's structured
    /// response; unknown post-Store failures remain reconcilable.
    #[cfg(windows)]
    async fn dispatch_user_automation_operator_transition(
        &self,
        session: &Session,
        request: &eliot_kernel_service::UserAutomationServiceRequest,
    ) -> Result<eliot_kernel_service::UserAutomationOperatorTransition, serde_json::Value> {
        // The existing authenticated Host execution channel is composed for
        // exactly the operations that own a wake or execution handoff, so a
        // read-only answer never depends on the Host contour. This reuses the
        // existing route and transport rather than creating new authority.
        let runtime_channel = self
            .user_automation_operator_runtime_channel(
                &request.intent.operation,
                &session.module_generation.state_fence,
            )
            .await
            .map_err(Self::user_automation_runtime_error_response)?;
        let runtime = runtime_channel
            .as_ref()
            .map(eliot_kernel_service::UserAutomationOperatorRuntime::new);
        let Ok(gateway) = self.retained_store_gateway() else {
            return Err(Self::user_automation_runtime_error_response(
                UserAutomationRuntimeError::Unavailable(
                    "canonical UserAutomation Store owner is unavailable".to_owned(),
                ),
            ));
        };
        match Box::pin(gateway.execute_user_automation_operation(request.clone(), runtime.as_ref()))
            .await
        {
            Ok(transition) => Ok(transition),
            Err(eliot_kernel_service::UserAutomationExecutionError::Contract(error)) => Err(
                Self::user_automation_precommit_refusal_response(request, &error),
            ),
            Err(_error) => {
                // F-LOG-KERNEL-1 (#897 W5): correlated subordinate phase
                // observation only. The single designated terminal for
                // this failed operation is emitted by
                // `execute_daemon_request_observed`; a second terminal
                // here would inflate one store failure into two.
                observe_daemon_request("kernel.daemon_user_automation_operator_store", "unknown");
                Err(Self::user_automation_runtime_error_response(
                    UserAutomationRuntimeError::UnknownOutcome(
                        "user_automation_operator_transition_requires_reconciliation".to_owned(),
                    ),
                ))
            }
        }
    }

    #[cfg(windows)]
    fn user_automation_precommit_refusal_response(
        request: &eliot_kernel_service::UserAutomationServiceRequest,
        error: &eliot_kernel_core::user_automation::UserAutomationError,
    ) -> serde_json::Value {
        use eliot_kernel_core::user_automation::UserAutomationError;

        let (code, field) = match error {
            UserAutomationError::ZoneTableIntegrity => {
                return Self::user_automation_runtime_error_response(
                    UserAutomationRuntimeError::Unavailable(
                        "pinned UserAutomation zone table integrity failure".to_owned(),
                    ),
                );
            }
            UserAutomationError::Invalid("schedule.occurrence_key.encoding") => (
                "unsupported_contract_version",
                Some("schedule.occurrence_key.encoding"),
            ),
            UserAutomationError::LegacyScheduleEncoding(field) => ("legacy_encoding", Some(*field)),
            UserAutomationError::SubMinuteZoneOffset { field, .. } => {
                ("unrepresentable_zone_offset", Some(*field))
            }
            UserAutomationError::ZoneDatabaseRevision(field) => {
                ("stale_normalization_revision", Some(*field))
            }
            UserAutomationError::Invalid("schedule.occurrence_key.source_digest") => (
                "stale_normalization_revision",
                Some("schedule.occurrence_key.source_digest"),
            ),
            UserAutomationError::Receipt(_) | UserAutomationError::ReceiptBinding => {
                ("invalid_or_moved_receipt", None)
            }
            UserAutomationError::Invalid(field)
            | UserAutomationError::LimitExceeded(field)
            | UserAutomationError::UnknownZone(field)
            | UserAutomationError::ZoneEvidence(field)
            | UserAutomationError::ZoneTableWindow { field, .. } => {
                ("semantic_rejection", Some(*field))
            }
            UserAutomationError::InvalidSupersession => {
                ("semantic_rejection", Some("revision.supersedes"))
            }
            UserAutomationError::Config(_)
            | UserAutomationError::RevisionMismatch
            | UserAutomationError::OccurrenceMismatch
            | UserAutomationError::FailureProjectionMissing
            | UserAutomationError::FailureFingerprintMismatch
            | UserAutomationError::Serialization(_) => ("semantic_rejection", None),
        };
        let mut refusal = serde_json::Map::new();
        refusal.insert("code".to_owned(), serde_json::json!(code));
        if let Some(field) = field {
            refusal.insert("field".to_owned(), serde_json::json!(field));
        }
        if let UserAutomationError::SubMinuteZoneOffset {
            zone,
            offset_seconds,
            ..
        } = error
        {
            refusal.insert("zone".to_owned(), serde_json::json!(zone));
            refusal.insert(
                "offset_seconds".to_owned(),
                serde_json::json!(offset_seconds),
            );
        }
        // The caller key was already capped at 256 UTF-8 bytes. The request ID
        // and StateFence have closed validated shapes. Refusal fields are static
        // contract names; the optional zone is a pinned table member.
        serde_json::json!({
            "status": "unknown",
            "value": {
                "kind": "user_automation_refusal",
                "schema_version": 1,
                "operation": {
                    "operation_id": request.identity.operation_id.as_str(),
                    "request_id": &request.context.request_id,
                    "idempotency_key": request.identity.idempotency_key.as_str(),
                },
                "state_fence": &request.context.state_fence,
                "attempt_state": "store_not_called",
                "refusal": refusal,
            },
            "recovery": {
                "kind": "unknown_outcome",
                "reason": "prior_attempt_may_have_committed",
            },
        })
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
        let policy_snapshot = match eliot_kernel_service::KernelStoreGateway::user_automation_policy_snapshot_from_recovery(
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
        let policy_snapshot_after = match eliot_kernel_service::KernelStoreGateway::user_automation_policy_snapshot_from_recovery(
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
    /// The decode lives in the canonical Store gateway so the typed snapshot
    /// has one producer; this route only projects the gateway answer.
    async fn read_user_automation_policy_snapshot(
        &self,
        state_fence: &StateFence,
    ) -> Result<eliot_kernel_core::user_automation::ConfigPolicySnapshot, UserAutomationRuntimeError>
    {
        let gateway = self.retained_store_gateway().map_err(|_| {
            UserAutomationRuntimeError::Unavailable(
                "canonical UserAutomation preflight Store route is unavailable".to_owned(),
            )
        })?;
        gateway
            .read_user_automation_policy_snapshot(state_fence)
            .await
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
    /// After the Durable Job owner issues an owner-acknowledged disposition —
    /// an admission, or a refusal it answered before any owner effect — the
    /// next bounded recurring horizon slice is requested through the same
    /// schedule owner (item 6). The advance recompiles the denominator from the
    /// immutable revision the wake resolved against, so it never mutates that
    /// revision and never produces a time outside its normalized contract. A
    /// disposition the owner could not issue, or could not confirm, advances
    /// nothing.
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
        // The occurrence is proved from here on: the resolution above is the
        // canonical revision this carrier was read against and the readback
        // above is the schedule owner's own pending record for it. Every step
        // below reports, joins or advances THIS occurrence, so the six facts
        // that identify it are bound once here instead of being restated as
        // trailing parameters on each of those steps.
        let proven = UserAutomationProvenDueWake {
            session,
            occurrence_id: &occurrence_id,
            client,
            request: &request,
            resolution: &resolution,
            readback: &readback,
        };
        // One stable occurrence may produce at most one admitted job/effect. The
        // carrier is the same owner-issued admission `run-now` uses, so the
        // Durable Job owner's own operation identity is the at-most-once
        // boundary; the revalidation above already refused any occurrence that
        // the complete owner projection shows as already admitted.
        //
        // The admission is assembled from what the owners proved on this very
        // delivery rather than forwarded from the caller's asserted carrier: the
        // current canonical revision, the invocation `scheduled_invocation`
        // re-derived from that revision for this occurrence, and the WakeIntent
        // the schedule owner read back from its own journal. Nothing here is
        // recomputed or re-derived by spelling.
        //
        // It is then submitted through the same execution join a committed `run-now`
        // occurrence crosses. `KernelStoreGateway::due_wake_execution_join`
        // assembles the complete owner-issued preflight projection from the live
        // owners and calls `UserAutomationService::execute_occurrence_with_durable_job`,
        // which runs the deterministic preflight decision and the
        // complete-denominator refusal immediately before it reaches an effect
        // owner, and resolves the complete owner-issued
        // `UserAutomationDurableJobMaterial` through
        // `UserAutomationDurableJobMaterial::from_admitted_occurrence`. The
        // transport it submits over is `UserAutomationOperatorRuntime` — the
        // production `UserAutomationRuntimePort` over this already-authenticated
        // Host channel — and the owner's answer is validated there. Calling
        // `UserAutomationDurableJobPort::admit_occurrence` on the bare client,
        // as this contour did, reached the Durable Job owner without ever running
        // the deterministic preflight, which is the blind rerun I11.12:59 and
        // I14.21 forbid.
        let outcome = match Self::user_automation_due_wake_join(
            self,
            client,
            &request,
            &resolution,
            &readback,
        )
        .await
        {
            Ok(outcome) => outcome,
            // Item 6, terminal leg. A refusal the Durable Job owner answered
            // before any owner effect is a decided disposition about this
            // occurrence, exactly as an admission is: the occurrence will not be
            // admitted now, so leaving the recurring horizon pinned to it would
            // wedge every later occurrence of the revision behind one
            // permanently-refused wake. It advances through the same
            // owner-acknowledged path the admitted branch uses, and it is
            // reported as its own disposition rather than as a success.
            //
            // `Unavailable`, `NotRetained`, `UnknownOutcome` and
            // `OutcomeSettled` deliberately do not reach this arm: none of them
            // is an owner-acknowledged disposition about this occurrence. They
            // respectively mean the owner could not answer, it answered about
            // another record, it cannot say whether the effect landed, and the
            // effect provably landed. Those keep the pre-existing fail-closed
            // projection and do not advance.
            Err(UserAutomationRuntimeError::Rejected(reason)) => {
                return self
                    .user_automation_due_wake_decided_response(
                        &proven,
                        DecidedDisposition {
                            outcome: "rejected",
                            reason,
                        },
                    )
                    .await;
            }
            Err(error) => {
                // No owner acknowledged a disposition, so the recurring horizon
                // does not advance: this wake is still unconsumed and a later
                // owner-issued submission can admit it.
                return Ok(Self::user_automation_runtime_error_response(error));
            }
        };
        // The join's own answer is the last step this contour owns, and
        // materialising it into this route's response is one step of its own:
        // either the occurrence is reported under the closed disposition the
        // owner decided before any effect, or the one execution reference the
        // owner issued is validated against the occurrence the schedule owner
        // resolved and the recurring horizon advances beside it.
        self.user_automation_due_wake_execution_response(&proven, outcome)
            .await
    }

    /// Materialises the execution join's own answer into this route's response
    /// (issue #2806 items 5 and 6).
    ///
    /// The deterministic preflight is a decided answer about this occurrence
    /// before any owner effect, exactly like an admission and exactly like a
    /// Durable Job refusal, so it reaches the same owner-acknowledged
    /// disposition arm. A deferral is reported under its own owner reason and
    /// never re-labelled as a rejection; a blocked configuration is reported
    /// under its stable failure fingerprint and never as a success. Neither
    /// carries a Durable Job reference, because none was issued.
    /// `BlockedConfig` is structurally unreachable on this route - the preflight
    /// projection this leg assembles is refused by the Store owner rather than
    /// returned blocked - and the arm is retained because the join's answer is a
    /// closed vocabulary this contour maps completely, not because that member
    /// can be observed here.
    ///
    /// The admitted arm validates the owner's own reference against the resolved
    /// occurrence before it reports anything, and then advances the recurring
    /// horizon through the same `user_automation_due_wake_admitted_value`
    /// projection an admitted occurrence has always used.
    ///
    /// This step opens, closes and commits no store transaction of its own: the
    /// revalidation that precedes it, the recurring-window derivation inside the
    /// existing horizon slice request, and the durable append inside the two
    /// existing response projections all stay with their existing owners, in that
    /// order.
    #[cfg(windows)]
    async fn user_automation_due_wake_execution_response(
        &self,
        proven: &UserAutomationProvenDueWake<'_>,
        outcome: eliot_kernel_service::UserAutomationExecutionOutcome,
    ) -> Result<serde_json::Value, TransportError> {
        let occurrence_id = proven.occurrence_id;
        let execution = match outcome {
            eliot_kernel_service::UserAutomationExecutionOutcome::Admitted {
                execution, ..
            } => execution,
            eliot_kernel_service::UserAutomationExecutionOutcome::Deferred { reason, .. } => {
                return self
                    .user_automation_due_wake_decided_response(
                        proven,
                        DecidedDisposition {
                            outcome: "deferred",
                            reason: format!(
                                "the deterministic preflight deferred occurrence {occurrence_id} \
                                 with reason {reason:?}, before any model or provider call"
                            ),
                        },
                    )
                    .await;
            }
            eliot_kernel_service::UserAutomationExecutionOutcome::BlockedConfig {
                failure, ..
            } => {
                return self
                    .user_automation_due_wake_decided_response(
                        proven,
                        DecidedDisposition {
                            outcome: "blocked_config",
                            reason: format!(
                                "occurrence {occurrence_id} entered blocked_config under failure \
                                 fingerprint {} before any model call",
                                failure.failure_fingerprint
                            ),
                        },
                    )
                    .await;
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
        Ok(self
            .user_automation_due_wake_admitted_value(proven, execution)
            .await)
    }

    /// Advances the recurring horizon after an owner-acknowledged admission and
    /// reports the occurrence as admitted (issue #2806 item 6).
    ///
    /// The `status`/`recovery` pair is derived from the advance alone, exactly as
    /// before: only a fully acknowledged published horizon reports a settled
    /// answer, and every partial, unknown or unavailable remainder keeps its
    /// exact remaining occurrence set and replay handle. A consumed denominator
    /// also reports a settled answer, because the resolved revision owns no wake
    /// horizon after the admitted occurrence rather than because an owner was
    /// missing.
    ///
    /// The durable obligation the advance retained is reported beside that phase
    /// under its ORIGINAL owner operation identity, so a horizon whose owner
    /// answer was lost is reported as an outstanding durable record a later
    /// attempt resumes, not only as a phase whose remainder has to be re-derived
    /// from the committed configuration.
    #[cfg(windows)]
    async fn user_automation_due_wake_admitted_value(
        &self,
        proven: &UserAutomationProvenDueWake<'_>,
        execution: eliot_kernel_core::user_automation::AutomationExecutionReference,
    ) -> serde_json::Value {
        let advance = self.user_automation_due_wake_horizon(proven).await;
        let recovery = Self::user_automation_horizon_recovery(&advance);
        serde_json::json!({
            "status": if recovery.is_none() { "known" } else { "unknown" },
            "value": {
                "outcome": "admitted",
                "execution": execution,
                "resolution": proven.resolution,
                "wake_readback": proven.readback,
                "horizon": Self::user_automation_horizon_value(&advance),
                "horizon_obligation": Self::user_automation_horizon_obligation(&advance),
            },
            "recovery": recovery,
        })
    }

    /// Submits one due occurrence to the deterministic execution join and
    /// returns the owner's answer (issue #2806 items 5 and 6).
    ///
    /// The join runs entirely inside this contour, so
    /// `user_automation_due_wake_operation` never holds the join's own state
    /// across its awaits. It assembles the complete owner-issued preflight
    /// projection for the resolved occurrence from the live owners the canonical
    /// Store gateway already reads, completes the owner-issued
    /// `UserAutomationDurableJobMaterial`, and then crosses
    /// `UserAutomationService::execute_occurrence_with_durable_job` - the same
    /// join a committed `run-now` occurrence crosses, and the one that runs the
    /// deterministic preflight decision and the complete-denominator refusal
    /// immediately before it reaches an effect owner. That compiler holds a
    /// whole canonical-JSON K0 `JobSubmission` and its digest inputs on the
    /// stack, so the gateway polls it through its own box; the transient
    /// allocation is released as soon as the owner's answer is back.
    ///
    /// The transport is already authenticated and bound to the current State
    /// Fence by the caller, so this adds no channel, no retry and no second
    /// admission: it is exactly the `UserAutomationOperatorRuntime` over that one
    /// channel.
    #[cfg(windows)]
    async fn user_automation_due_wake_join(
        &self,
        client: &UserAutomationHostExecutionClient<
            AuthenticatedUserAutomationHostExecutionTransport,
        >,
        request: &UserAutomationRuntimeAdmission,
        resolution: &UserAutomationDueWakeResolution,
        readback: &UserAutomationWakeReadback,
    ) -> Result<eliot_kernel_service::UserAutomationExecutionOutcome, UserAutomationRuntimeError>
    {
        let gateway = self.retained_store_gateway().map_err(|_| {
            UserAutomationRuntimeError::Unavailable(
                "canonical UserAutomation Store owner is unavailable".to_owned(),
            )
        })?;
        let runtime = UserAutomationOperatorRuntime::new(client);
        Box::pin(gateway.due_wake_execution_join(
            request,
            resolution,
            readback.intent.clone(),
            &runtime,
        ))
        .await
    }

    /// Advances the recurring horizon after an owner-acknowledged decided
    /// disposition and reports the occurrence under that disposition (issue #2806
    /// item 6).
    ///
    /// Every disposition that reaches here is decided before any owner effect:
    /// the deterministic preflight deferred or blocked this occurrence, or the
    /// Durable Job owner refused it. None of them will be admitted now, so leaving
    /// the recurring horizon pinned to it would wedge every later occurrence of
    /// the revision behind one permanently-unadmitted wake. The horizon therefore
    /// advances exactly as it does after an admission, through the same
    /// `user_automation_due_wake_horizon` slice request, and its outcome and
    /// replay handle travel beside the disposition.
    ///
    /// The occurrence is reported as `accepted: false` under its own closed
    /// `outcome` and the owner's own reason. It is not published, not admitted,
    /// and it carries no Durable Job reference, so nothing here can be read as a
    /// success, and one disposition is never re-labelled as another. The
    /// route-level `recovery` stays derived from the horizon advance alone and is
    /// never fabricated: a decided disposition with a fully acknowledged or
    /// consumed horizon owes the caller nothing, which is the same convention
    /// `user_automation_runtime_error_response` already uses for
    /// `UserAutomationRuntimeError::Rejected`.
    ///
    /// The durable obligation the advance retained is reported beside that phase
    /// under its ORIGINAL owner operation identity, for the same reason the
    /// admitted arm reports it: a decided occurrence still advances a real wake
    /// horizon, and an advance whose owner answer was lost is an outstanding
    /// durable record rather than only a remainder.
    #[cfg(windows)]
    async fn user_automation_due_wake_decided_response(
        &self,
        proven: &UserAutomationProvenDueWake<'_>,
        disposition: DecidedDisposition<'_>,
    ) -> Result<serde_json::Value, TransportError> {
        let advance = self.user_automation_due_wake_horizon(proven).await;
        let recovery = Self::user_automation_horizon_recovery(&advance);
        Ok(serde_json::json!({
            "status": if recovery.is_none() { "known" } else { "unknown" },
            "value": {
                "accepted": false,
                "outcome": disposition.outcome,
                "reason": disposition.reason,
                "occurrence_id": proven.occurrence_id,
                "resolution": proven.resolution,
                "wake_readback": proven.readback,
                "horizon": Self::user_automation_horizon_value(&advance),
                "horizon_obligation": Self::user_automation_horizon_obligation(&advance),
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
            // The owner read its own journal and definitively retains no such
            // record. That is a complete negative answer about this delivery, so
            // it is refused with the same typed cause as before rather than with
            // an ad-hoc body: a duplicate or superseded delivery is refused here,
            // before any effect owner is contacted.
            Err(UserAutomationRuntimeError::NotRetained(reason)) => {
                return UserAutomationDueWakeRead::Answer(
                    Self::user_automation_due_wake_refused_response(
                        &UserAutomationDueWakeRejection::new(
                            eliot_kernel_service::UserAutomationDueWakeRejectionCause::WakeNotRetained,
                            occurrence_id.to_owned(),
                            format!(
                                "the schedule owner read its own journal and definitively retains \
                                 no pending wake for this occurrence: {reason}"
                            ),
                        ),
                    ),
                );
            }
            // `Unavailable` on this route is now only a journal the owner could
            // not read, which proves nothing about this occurrence. No
            // `UserAutomationDueWakeRejectionCause` expresses "the owner could
            // not answer", and reusing `WakeNotRetained` here would assert a
            // proven absence that was never proven, so it keeps the existing
            // generic projection: an unknown answer with a recovery directive,
            // which is fail-closed and cannot be read as a normal empty result.
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
    ///
    /// **A consumed denominator is finished, not unavailable.** The cursor rule
    /// is the same one the horizon compiler uses: the slice starts immediately
    /// after the consumed occurrence's own place in the revision's recompiled
    /// denominator. When that occurrence is the LAST member, the revision's
    /// complete normalized set is consumed and there is no next slice to
    /// compile. That is a settled fact about the revision, and it is reported as
    /// [`UserAutomationHorizonAdvance::Exhausted`] with no owner call at all,
    /// because the honest owner was available the whole time and there was simply
    /// nothing to ask it about. The digest and owner-principal bindings the
    /// compiler itself proves are proved here first, so a resolution that does
    /// not name this exact immutable revision under its own owner can never be
    /// reported as a complete horizon.
    ///
    /// The denominator is therefore compiled once, before anything is issued, and
    /// a revision that cannot compile it yields
    /// [`UserAutomationHorizonAdvance::Unresolved`] naming that refusal. The
    /// failure projection below can consequently always be handed a non-empty
    /// remainder; an empty set there would claim that nothing is outstanding,
    /// which is the one answer this contour cannot prove.
    ///
    /// **The slice leaves this contour as a durable obligation, not as a bare
    /// owner call.** The advance is issued through
    /// `KernelStoreGateway::publish_due_wake_horizon_advance`, which retains the
    /// publication's intent in the composition-bound durable outbox under the
    /// admitted due-wake carrier's own parent identity BEFORE anything is handed
    /// to the schedule owner, and settles the owner's answer as that record's
    /// retained body. A lost response therefore leaves a record that a later
    /// attempt of the same parent operation finds, and a later calendar
    /// occurrence advances a different slice and so keys a different record -
    /// I11.12's "a later calendar occurrence is a different identity" held in the
    /// durable store rather than only in the compiler. The obligation the route
    /// returns travels in the response beside the phase so an outstanding record
    /// and its original owner operation identity are reportable.
    #[cfg(windows)]
    async fn user_automation_due_wake_horizon(
        &self,
        proven: &UserAutomationProvenDueWake<'_>,
    ) -> UserAutomationHorizonAdvance {
        // The advance is issued for the occurrence the schedule owner still
        // offers as a pending wake, and that proof is what the resolution above
        // was reached under. The readback BODY is not read again here: it names
        // the intent this slice supersedes, and the publication request already
        // carries that through the carrier, so re-reading it would be a second
        // derivation rather than a fact.
        let UserAutomationProvenDueWake {
            session,
            occurrence_id,
            request,
            resolution,
            client,
            readback: _,
        } = *proven;
        // The two refusals below keep their `Err` binding inside the divergent
        // arm, because each one quotes the compiler's own closed reason in the
        // text a caller reads, and a `let...else` cannot carry that binding
        // across the divergence. They are `match`es by necessity, not by
        // preference; the Store-owner arm further down has no such binding and
        // is written as the `let...else` it is.
        let identities = match resolution.revision.compile_occurrence_identities() {
            Ok(identities) => identities,
            Err(error) => {
                return UserAutomationHorizonAdvance::Unresolved {
                    reason: format!(
                        "revision {} of automation {} does not compile its own normalized \
                         occurrence denominator, so the exact remaining occurrence set this \
                         advance owns cannot be named and no schedule owner is asked: {error}",
                        resolution.revision.revision, resolution.revision.automation_id,
                    ),
                };
            }
        };
        let denominator_occurrence_ids = identities
            .iter()
            .map(|identity| identity.occurrence_id.clone())
            .collect::<Vec<_>>();
        if Self::user_automation_horizon_cursor_is_consumed(
            resolution,
            &identities,
            occurrence_id,
            &request.authenticated_principal,
        ) {
            return UserAutomationHorizonAdvance::Exhausted;
        }
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
                return UserAutomationHorizonAdvance::Answered {
                    phase: Box::new(Self::user_automation_unacknowledged_horizon(
                        resolution,
                        &denominator_occurrence_ids,
                        &request.identity,
                        &format!(
                            "the next bounded horizon slice for the resolved revision could not be \
                             compiled from its own normalized contract: {error}"
                        ),
                        false,
                    )),
                    // The slice was refused before this contour could hand one to
                    // the retained-obligation route, so nothing was retained and
                    // there is no record to report.
                    obligation: None,
                };
            }
        };
        // No empty-slice guard is needed and none is kept: the compiler refuses
        // an exhausted cursor before it builds entries, and a consumed occurrence
        // that is not a member of the denominator is refused as a binding
        // mismatch, so a publication reaching this point always carries at least
        // one occurrence. An empty requested set here would be a claim that the
        // revision is finished, which this contour does not decide. The requested
        // set itself is now the retained route's own input, so this arm does not
        // recompute it a second time.
        //
        // The slice is issued through the canonical Store owner's retained
        // obligation route, not by calling the schedule owner from here. That
        // route - `KernelStoreGateway::publish_due_wake_horizon_advance` - is the
        // SAME `retain_and_publish_wake_horizon` the operator route runs for a
        // committed `Create`/`Resume`/`Edit`, over the SAME composition-bound
        // durable outbox and the SAME `retained_user_automation_obligation` ->
        // possible-effect marking -> acknowledgement settlement sequence. Calling
        // `UserAutomationWakePort::publish_wake_horizon` from this composition
        // binary, as this arm did, reached the owner with no retained record
        // behind it, so a lost response to a post-disposition slice had nothing to
        // resume from: that is the issue #2806 `W8` and lost-response `A3` gap,
        // and re-deriving the obligation here instead would be a second durable
        // write path and a second copy of the classification, which
        // `bins/AGENTS.md` forbids in a composition root.
        //
        // The composition gateway is read and the lock released before the await,
        // exactly as `user_automation_due_wake_join` does for the execution join,
        // so no composition mutex is held across the owner call. The future is
        // boxed for the same reason: the compiled denominator and the bounded
        // publication both live across it.
        let Ok(gateway) = self.retained_store_gateway() else {
            // The route that retains this obligation is the canonical Store
            // owner itself, so without it nothing can be retained and no
            // schedule owner may be asked. That is not a clean absence: the
            // whole compiled denominator is still owed, and it is reported
            // under the exact remaining set and replay handle with an unknown
            // outcome, so the response owes the caller a recovery directive
            // rather than reporting the horizon finished.
            return UserAutomationHorizonAdvance::Answered {
                phase: Box::new(Self::user_automation_unacknowledged_horizon(
                    resolution,
                    &denominator_occurrence_ids,
                    &request.identity,
                    "the canonical UserAutomation Store owner that retains this advance's \
                     obligation is unavailable, so nothing was retained, no schedule owner \
                     was asked and nothing was issued",
                    true,
                )),
                obligation: None,
            };
        };
        let runtime = UserAutomationOperatorRuntime::new(client);
        let answer = Box::pin(gateway.publish_due_wake_horizon_advance(
            request,
            resolution,
            &publication,
            &runtime,
        ))
        .await;
        Self::user_automation_horizon_owner_answer(
            answer,
            resolution,
            &denominator_occurrence_ids,
            &request.identity,
        )
    }

    /// Projects the canonical Store owner's own answer to one retained bounded
    /// slice request into the closed advance vocabulary.
    ///
    /// The two arms are answers from the same owner about the same slice, and
    /// both are projected over the SAME exact remaining occurrence set and the
    /// replay handle derived from the immutable revision, so neither is a clean
    /// absence of outstanding work.
    #[cfg(windows)]
    fn user_automation_horizon_owner_answer(
        answer: Result<
            (
                Option<UserAutomationRuntimeObligation>,
                UserAutomationHorizonPhase,
            ),
            UserAutomationHorizonPublicationRefusal,
        >,
        resolution: &UserAutomationDueWakeResolution,
        denominator_occurrence_ids: &[String],
        identity: &OperationIdentity,
    ) -> UserAutomationHorizonAdvance {
        match answer {
            // A retained obligation is present exactly when a durable record backs
            // this publication. It is reported under its ORIGINAL owner operation
            // identity, which is the due-wake carrier's own parent identity rather
            // than an identity minted for the advance, so a later attempt of the
            // same parent operation resumes this record instead of publishing the
            // slice a second time.
            //
            // A horizon phase alone could not carry that: it names the remaining
            // set and a replay handle derived from the immutable revision, not the
            // owner operation identity the record is written and reconciled
            // under. Both travel together, or the caller could not tell a
            // retained obligation from one that was never written.
            Ok((obligation, phase)) => UserAutomationHorizonAdvance::Answered {
                phase: Box::new(phase),
                obligation,
            },
            // This refusal is a slice the retained route could not bind, name or
            // project: a fence, carrier or revision-relative mismatch, a durable
            // write that failed, or an owner answer it could not turn into a
            // phase. It is projected as an unknown outcome over the exact
            // remaining set, never as a clean absence.
            //
            // The two arms are NOT the same fact and must not render one claim.
            // `Retained` means the durable record was written and its owner
            // answer settled before this projection step failed: the record
            // exists, it lives under the ORIGINAL owner operation identity the
            // route derived, and it is the only handle that can reconcile it.
            // `NothingRetained` means the route failed before that identity
            // existed, so nothing was ever created and nothing needs deleting.
            // Rendering one sentence for both is the defect this arm exists to
            // remove: a status line that denies a retained record while the
            // record sits behind it leaves the slice permanently unreconcilable,
            // which is exactly what I14.21 forbids.
            //
            // `detail` is rendered BEFORE the move, so both arms quote the
            // route's own closed reason verbatim rather than a paraphrase.
            Err(refusal) => {
                // The route's own rendering is taken BY REFERENCE first, because
                // the typed arm is consumed on the next line and a `Display` text
                // about a record that exists must not be re-derived by hand here.
                // On `Retained` this text already ends with the owner operation
                // identity the record lives under; on `NothingRetained` it is the
                // bare closed reason.
                let detail = refusal.to_string();
                let obligation = refusal.into_retained_obligation();
                UserAutomationHorizonAdvance::Answered {
                    phase: Box::new(Self::user_automation_unacknowledged_horizon(
                        resolution,
                        denominator_occurrence_ids,
                        identity,
                        &match obligation {
                            None => format!(
                                "the canonical UserAutomation Store owner returned no retained \
                                 obligation for this bounded slice and established no owner \
                                 operation identity for it, so no record exists to reconcile: \
                                 {detail}"
                            ),
                            Some(ref retained) => format!(
                                "the canonical UserAutomation Store owner retained this bounded \
                                 slice under owner operation identity {} and settled the owner's \
                                 answer into it, so the record must be reported and reconciled \
                                 under that original identity and must not be re-issued: \
                                 {detail}",
                                retained.owner_operation_id
                            ),
                        },
                        true,
                    )),
                    obligation,
                }
            }
        }
    }

    /// Reports whether the consumed occurrence is the last member of the
    /// resolved revision's own normalized denominator, which is the same cursor
    /// rule the horizon compiler applies when it refuses a slice that would start
    /// past the end of that denominator.
    ///
    /// The revision digest and the owner principal are proved first because they
    /// are the two bindings `advance_wake_horizon` proves before it will slice at
    /// all. A resolution that fails either of them is not this revision under
    /// this owner, so it can be neither advanced past its end nor reported as a
    /// complete horizon; it falls through to the compiler, which returns the
    /// typed refusal.
    #[cfg(windows)]
    fn user_automation_horizon_cursor_is_consumed(
        resolution: &UserAutomationDueWakeResolution,
        identities: &[eliot_kernel_core::user_automation::AutomationOccurrenceIdentity],
        occurrence_id: &str,
        authenticated_principal: &str,
    ) -> bool {
        resolution.revision.owner_principal == authenticated_principal
            && resolution
                .revision
                .digest()
                .is_ok_and(|digest| digest == resolution.revision_digest)
            && identities
                .last()
                .is_some_and(|last| last.occurrence_id == occurrence_id)
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

    /// Projects the recovery directive of one post-disposition horizon advance,
    /// including the exact remaining occurrence set and the replay handle the
    /// caller must use.
    ///
    /// The three arms of [`UserAutomationHorizonAdvance`] produce three different
    /// answers, and the second is the one that must not borrow the first's: an
    /// owner-acknowledged phase keeps its own derived directive over the exact
    /// remainder, an exhausted denominator owes the caller nothing and gets no
    /// directive, and a horizon that could not be composed at all is unresolved
    /// with the revision's own compile refusal beside it instead of a directive
    /// over a remainder that cannot be named. The last arm deliberately carries
    /// neither a `remaining_occurrence_ids` nor a `retry_handle`, because a
    /// recovery directive naming a set nobody can compute is not a recovery.
    #[cfg(windows)]
    fn user_automation_horizon_recovery(
        advance: &UserAutomationHorizonAdvance,
    ) -> Option<serde_json::Value> {
        let horizon = match advance {
            UserAutomationHorizonAdvance::Answered { phase, .. } => phase,
            // The resolved revision's complete normalized denominator is
            // consumed at this occurrence, so this advance owns no wake-horizon
            // obligation and there is no owner effect to reconcile. A recovery
            // directive here would invent recovery work that does not exist.
            UserAutomationHorizonAdvance::Exhausted => return None,
            UserAutomationHorizonAdvance::Unresolved { reason } => {
                return Some(serde_json::json!({
                    "kind": "unknown_outcome",
                    "reason": reason,
                }));
            }
        };
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

    /// Projects the horizon value one due-wake answer reports beside its own
    /// recovery directive.
    ///
    /// An absent horizon and a settled answer are the same thing on this route:
    /// [`UserAutomationHorizonAdvance::Exhausted`] is the only arm that produces
    /// it, because the next-slice request is attempted on every decided
    /// disposition, so an absent horizon here says the resolved revision's
    /// normalized denominator is consumed and no wake-horizon obligation remains
    /// to be asked, published, or reconciled.
    #[cfg(windows)]
    fn user_automation_horizon_value(
        advance: &UserAutomationHorizonAdvance,
    ) -> Option<&UserAutomationHorizonPhase> {
        match advance {
            UserAutomationHorizonAdvance::Answered { phase, .. } => Some(phase.as_ref()),
            UserAutomationHorizonAdvance::Exhausted
            | UserAutomationHorizonAdvance::Unresolved { .. } => None,
        }
    }

    /// Projects the durable obligation one post-disposition horizon advance
    /// retained, beside that advance's own phase.
    ///
    /// The advance now issues its slice through the canonical Store owner's
    /// retained-obligation route, and that route returns the obligation it
    /// actually wrote. Reporting only the phase would drop the one field that
    /// says WHICH record exists: `owner_operation_id` is the original owner
    /// operation identity the record is written and reconciled under, and the
    /// horizon phase carries only a replay handle derived from the immutable
    /// revision. A caller that lost a publication response needs both to resume
    /// the same record rather than re-derive a handle from the committed
    /// configuration.
    ///
    /// `None` is reported as an explicit absence of a REPORTED record, not as an
    /// implied settled horizon, and it is the honest answer for the arms that
    /// never reach the owner at all: a consumed denominator, a revision that
    /// cannot compile its own denominator, and a canonical Store owner that could
    /// not be reached all retain nothing, so there is no record a reconciliation
    /// could read. A slice the retained route refused is reported the same way,
    /// because that route returned no obligation - the accompanying reason says
    /// so rather than claiming that no record was written. Those arms still owe
    /// the caller their exact remaining set and recovery directive through the
    /// phase.
    #[cfg(windows)]
    fn user_automation_horizon_obligation(
        advance: &UserAutomationHorizonAdvance,
    ) -> Option<&UserAutomationRuntimeObligation> {
        match advance {
            UserAutomationHorizonAdvance::Answered { obligation, .. } => obligation.as_ref(),
            UserAutomationHorizonAdvance::Exhausted
            | UserAutomationHorizonAdvance::Unresolved { .. } => None,
        }
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
    /// Revalidates a complete committed-revision enumeration request against
    /// the authenticated owner and canonical parent operation receipt before Host.
    async fn revalidate_user_automation_enumeration(
        &self,
        session: &Session,
        request: &UserAutomationWakeEnumerationRequest,
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
        let lookup = UserAutomationOwnerLookup {
            automation_id: request.automation_id.clone(),
            requested_revision: request.automation_revision.clone(),
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
        let owner_denominator = owner
            .revision
            .compile_occurrence_identities()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?;
        if owner.automation_id != request.automation_id
            || owner.revision.revision != request.automation_revision
            || owner.revision.owner_principal != authenticated_principal
            || owner
                .revision
                .digest()
                .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?
                != request.revision_digest
            || owner_denominator != request.denominator
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        ensure_user_automation_store_receipt(&gateway, &lookup.state_fence, &request.identity)
            .await
            .map(|_| ())
    }

    #[cfg(windows)]
    /// Revalidates one bounded recurring wake horizon against the authenticated
    /// owner and the canonical parent operation receipt before Host.
    ///
    /// A horizon publication belongs to the read/observation family, not the
    /// occurrence family: it names an immutable revision and a State Fence but
    /// no occurrence. `revalidate_user_automation_enumeration` is therefore its
    /// exact analogue — the same `UserAutomationOwnerLookup`, the same canonical
    /// owner readback, the same owner-recompiled occurrence denominator, and the
    /// same parent Store receipt proof. `revalidate_user_automation_wake_read` is
    /// not usable here because it keys on a `UserAutomationWakeReadRequest` and
    /// its invocation.
    ///
    /// The caller-carried publication is never an authority source. The
    /// automation identity, the revision, the owner principal and the complete
    /// occurrence denominator are all recompiled from the canonical current
    /// revision, and the carried `revision_digest` must equal that revision's
    /// own `digest()` — a digest a caller could compute for itself would
    /// otherwise name another revision's cursor. This is issue #2806 item 2's
    /// "revalidate principal, revision, State Fence and owner denominator
    /// before each owner call", applied to the publish leg and the read-back leg
    /// alike.
    async fn revalidate_user_automation_horizon(
        &self,
        session: &Session,
        request: &UserAutomationWakeHorizonPublication,
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
        let lookup = UserAutomationOwnerLookup {
            automation_id: request.automation_id.clone(),
            requested_revision: request.automation_revision.clone(),
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
        let owner_occurrence_ids = owner
            .revision
            .compile_occurrence_identities()
            .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?
            .iter()
            .map(|identity| identity.occurrence_id.clone())
            .collect::<Vec<_>>();
        if owner.automation_id != request.automation_id
            || owner.revision.revision != request.automation_revision
            || owner.revision.owner_principal != authenticated_principal
            || owner
                .revision
                .digest()
                .map_err(|error| UserAutomationRuntimeError::Rejected(error.to_string()))?
                != request.revision_digest
            || owner_occurrence_ids != request.denominator_occurrence_ids
        {
            return Err(UserAutomationRuntimeError::IdentityConflict);
        }
        ensure_user_automation_store_receipt(&gateway, &lookup.state_fence, &request.identity)
            .await
            .map(|_| ())
    }

    #[cfg(windows)]
    fn user_automation_runtime_error_response(
        error: UserAutomationRuntimeError,
    ) -> serde_json::Value {
        match error {
            // A complete negative answer from the owner: it read its own state
            // and definitively retains no such record. This is a known outcome,
            // not an unknown one, so it is reported as a definitive
            // non-acceptance with nothing left to reconcile. It is deliberately
            // not folded into `unavailable`, which means the owner could not
            // answer at all.
            //
            // The due-wake readback does not reach this arm: it refuses a proven
            // absence itself with the typed
            // `UserAutomationDueWakeRejectionCause::WakeNotRetained`, because its
            // consumer is the wake-owner contract and not this JSON projection.
            // This arm serves the remaining readback call sites that forward an
            // owner error verbatim: the `USER_AUTOMATION_RUNTIME_OPERATION`
            // route's `ReadPendingWake` operation, and the run-now trigger
            // preflight readback.
            UserAutomationRuntimeError::NotRetained(reason) => serde_json::json!({
                "status": "known",
                "value": {
                    "accepted": false,
                    "outcome": "not_retained",
                    "reason": reason,
                },
                "recovery": null,
            }),
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
            // The mutation's disposition is proven by exact receipt evidence
            // and only the ledger answer is unread (issue #2764 item 6). It is
            // deliberately NOT folded into `unknown_outcome`, which means the
            // owner cannot tell whether the mutation committed at all:
            // reporting a proven commit under that value would make the two
            // indistinguishable and would keep an already-settled operation
            // reconciling forever.
            //
            // It is also deliberately NOT shaped like `rejected`/`not_retained`.
            // Those carry `accepted: false`, which is accurate for a refusal
            // and for a proven absence, but would be a false statement here:
            // something provably DID happen, and a client keying on
            // `accepted == false` would read a proven commit as a refusal. The
            // operation was accepted — its commit is proven — so the accepted
            // flag stays true and the remaining ledger read is reported as the
            // structured `recovery` obligation it is, not as English prose.
            UserAutomationRuntimeError::OutcomeSettled(reason) => serde_json::json!({
                "status": "known",
                "value": {
                    "accepted": true,
                    "outcome": "outcome_settled",
                    "reason": reason,
                },
                "recovery": { "kind": "ledger_read_owed", "reason": reason },
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
        context: &tracing::Span,
        terminal_owned: &mut bool,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: OriginChallengeIssueOperation =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        validate_origin_session_fence(session, operation.request.state_fence())?;
        let (owner, _) =
            super::caller_binding(session).map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let gateway = self
            .process_gateway
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let view = gateway
            .inspect_in_context(&owner, operation.operation_id.clone(), context)
            .await
            .map_err(|_| {
                *terminal_owned = true;
                TransportError::SessionFenced
            })?;
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
        context: &tracing::Span,
        terminal_owned: &mut bool,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: OriginControlDecideOperation =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        let presentation_bytes = serde_json::to_vec(&operation.presentation)
            .map_err(|_| TransportError::SessionFenced)?;
        let presentation = OriginControlPresentation::from_json_bytes(&presentation_bytes)
            .map_err(|_| TransportError::SessionFenced)?;
        validate_origin_session_fence(session, presentation.request().state_fence())?;
        validate_origin_control_operation(presentation.request().operation())?;
        // Implements #1967 W3: an origin-control grant issues authority, so
        // the decide path requires Material admission before touching the
        // process gateway. Issue #1892 W4: that admission runs through the
        // one production Material/Critical gate
        // (`admit_material_authority_for_governor_issued_fence`) under the
        // current Governor-issued governance profile, for the exact target
        // fence this decision presents. No compile-time profile constant is
        // injected, so an unrecorded Governor derivation fails this grant
        // closed. The rejection names the unmet prerequisite. Emergency
        // process kills continue through the Job/watchdog owners, never this
        // grant path.
        if let Some(rejection) =
            self.material_authority_admission_response(presentation.request().state_fence())
        {
            return Ok(rejection);
        }
        let (owner, _) =
            super::caller_binding(session).map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let gateway = self
            .process_gateway
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        let view = gateway
            .inspect_in_context(&owner, operation.operation_id.clone(), context)
            .await
            .map_err(|_| {
                *terminal_owned = true;
                TransportError::SessionFenced
            })?;
        validate_origin_inspection(&view, &operation.operation_id, presentation.request())?;
        let grant = gateway
            .decide_origin_control(&presentation)
            .map_err(|_| TransportError::SessionFenced)?;
        // Graceful WASM ladder (`#2896` W1/A1): when the decided
        // operation is a supervised WASM-host parent, the owner first
        // offers the ordered Reconcile/Cancel/Shutdown ladder through
        // its replayable control spool — the exact A4 ordered pairs —
        // so the host loop can reconcile the uncertain outcome,
        // contain guest work, and close admission before the gateway
        // kill lands. A foreign image skips this half with the response
        // unchanged; a proven WASM operation that cannot stage or
        // retain its control fails closed before the kill.
        let wasm_control = Self::publish_wasm_host_control_sequence(
            session,
            &owner,
            &operation.operation_id,
            presentation.request(),
            &grant,
        )?;
        let cancelled = gateway
            .cancel_with_origin_grant_in_context(
                &owner,
                operation.operation_id.clone(),
                Some(&grant),
                context,
            )
            .await
            .map_err(|_| {
                *terminal_owned = true;
                TransportError::SessionFenced
            })?;
        // CHILD-1/CHILD-2 (#1918): closing the kill produces the
        // descendant-closure receipt as durable audit evidence. The kill
        // receipt stays authoritative: a close fault keeps its own terminal
        // diagnostic from the close boundary and never loses the kill.
        if let Ok(receipt) = gateway
            .close_registered_descendant_in_context(&owner, operation.operation_id.clone(), context)
            .await
        {
            self.audit_observe(AuditEventDraft::descendant_closure(&receipt));
        }
        let mut value = serde_json::json!({
            "kind": "origin_control_kill",
            "grant": grant,
            "cancelled": cancelled,
        });
        // Post-kill control projection is honest-degraded, never fatal:
        // the kill receipt is authoritative, so a spool fault here marks
        // the control unrecorded instead of losing the receipt.
        match wasm_control {
            WasmHostControlOutcome::Foreign => {}
            WasmHostControlOutcome::NotStaged { reason } => {
                if let Some(object) = value.as_object_mut() {
                    object.insert(
                        "control".to_owned(),
                        serde_json::json!({"staged": false, "reason": reason}),
                    );
                }
            }
            WasmHostControlOutcome::Published {
                receipts,
                install_dir,
            } => {
                if let Some(object) = value.as_object_mut() {
                    object.insert(
                        "control".to_owned(),
                        wasm_host_control_projection(&install_dir, &receipts),
                    );
                }
            }
        }
        Ok(serde_json::json!({
            "status": "known",
            "value": value,
            "recovery": null,
        }))
    }

    /// Reconciles one grant-funded kill effect after crash or lost response
    /// (issue #1775 A-crash).
    ///
    /// The reachable front-door caller for the durable authority journal's
    /// reconciliation query path: the envelope carries only the operation
    /// and the consumed one-shot nonce, and the gateway authorizes the
    /// caller against the retained operation record, cross-checks the
    /// envelope operation and the live installation against the journaled
    /// original, and then either replays the preserved original kill
    /// receipt or answers reconciliation-required — never re-executing and
    /// never minting a fresh nonce. A proven (`Effected`) effect projects
    /// the preserved receipt; an unproven (`Unknown`) effect projects a
    /// structured `reconciliation_required` recovery obligation, not prose;
    /// every authorization or binding failure fences the session before any
    /// effect or live read.
    fn origin_grant_reconcile_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: OriginGrantReconcileOperation =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        let (owner, _) =
            super::caller_binding(session).map_err(|_| TransportError::PeerIdentityUnavailable)?;
        let gateway = self
            .process_gateway
            .as_ref()
            .ok_or(TransportError::SessionFenced)?;
        match gateway.reconcile_origin_grant_effect(
            &owner,
            &operation.operation_id,
            &operation.request_nonce,
        ) {
            Ok(receipt) => Ok(serde_json::json!({
                "status": "known",
                "value": {
                    "kind": "origin_grant_reconcile",
                    "effect": "effected",
                    "receipt": receipt,
                },
                "recovery": null,
            })),
            Err(ProcessExecutionError::UnknownOutcome) => Ok(serde_json::json!({
                "status": "known",
                "value": {
                    "kind": "origin_grant_reconcile",
                    "effect": "unknown",
                },
                "recovery": {
                    "kind": "reconciliation_required",
                    "operation_id": operation.operation_id.as_str(),
                },
            })),
            Err(_) => Err(TransportError::SessionFenced),
        }
    }

    fn generation_registry_active_query_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let query: ActiveGenerationRegistryQuery =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
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

    /// Drives one authenticated generation cutover through the Kernel's sole
    /// semantic gateway and projects the gateway's own terminal code back on
    /// the authenticated reply.
    ///
    /// The operation selector only picks this entry. The closed request carries
    /// a cutover identity and the admitted session State Fence and nothing
    /// else, so the generation, epoch, route scope, and cutover state all come
    /// from the owner's committed ORS cutover-ownership record inside
    /// [`super::generation_control::KernelComposition::apply_authenticated_generation_cutover`].
    /// A malformed request, a fence that is not the exact admitted session
    /// fence, an absent record, a non-committed record, or a stale/foreign epoch
    /// fences the session with the exact typed transport error; none of them
    /// fabricates a cutover or a success answer.
    fn generation_cutover_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let request: GenerationCutoverRequest =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        let outcome = self
            .apply_authenticated_generation_cutover(
                &request,
                &session.module_generation.state_fence,
            )
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(serde_json::json!({
            "status": "known",
            "value": outcome,
            "recovery": null,
        }))
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

    /// Typed outcome for a protected Observe pair whose published claim did
    /// not yield a canonical owner receipt. Its durable row is `Unknown` and
    /// may only advance through explicit reconciliation.
    fn unknown_observe_daemon_response(operation_id: &str) -> serde_json::Value {
        serde_json::json!({
            "status": "unknown",
            "value": {
                "outcome": "unknown_outcome",
                "operation_id": operation_id,
            },
            "recovery": {
                "kind": "unknown_outcome",
                "reason": "published_observe_pair_requires_reconciliation",
            },
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
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        if let Err(error) = operation.request.validate() {
            return Ok(Self::store_error_response_text(
                "store_recovery",
                &error.to_string(),
            ));
        }
        validate_store_session_fence(session, &operation.request.state_fence)?;
        // Rejection before reading, exactly as the sibling routes do it: the
        // process-stream selector is proved here, while it is still pure, so a
        // blank, unusable or over-bound entry never reaches the gateway or the
        // retained ORS.
        let stream_identities = match Self::admit_process_stream_recovery_operations(
            operation.process_stream_recovery_operations.as_deref(),
        ) {
            Ok(identities) => identities,
            Err(reason) => {
                return Ok(Self::store_error_response_text("store_recovery", &reason));
            }
        };
        let gateway = self.retained_store_gateway()?;
        let recovery_fence = operation.request.state_fence.clone();
        match gateway.recovery(operation.request).await {
            Ok(snapshot) => {
                // Implements #1925 W3 (I1.11 step 6, I5.2): the Store snapshot
                // alone does not prove that the ORS staged write envelopes are
                // reconciled. The same route now runs the ORS pending-reservation
                // reconciliation over the composition-bound ORS, revalidates
                // every reported staged envelope through its owner, and reports
                // the durable Recovery Problems a corrupted or unreadable staged
                // payload leaves behind. Step 6 is recorded only when that scan
                // is exhaustive and clean; an unresolved reservation, a retained
                // problem, or a truncated scan keeps normal writes gated, and
                // The resume helper uses only this exact inventory and each
                // original protected operation; any residual problem keeps
                // normal writes gated.
                let mut staged = match gateway
                    .reconcile_staged_writes(&recovery_fence, eliot_ors::MAX_RECOVERY_PAGE)
                    .await
                {
                    Ok(staged) => staged,
                    Err(error) => {
                        return Ok(Self::store_error_response_text("store_recovery", &error));
                    }
                };
                if staged.readiness() == eliot_kernel_service::StagedWriteReadiness::Blocked {
                    if let Err(error) = self
                        .resume_staged_observe_reservations(&gateway, &staged)
                        .await
                    {
                        return Ok(Self::store_error_response_text("store_recovery", &error));
                    }
                    staged = match gateway
                        .reconcile_staged_writes(&recovery_fence, eliot_ors::MAX_RECOVERY_PAGE)
                        .await
                    {
                        Ok(staged) => staged,
                        Err(error) => {
                            return Ok(Self::store_error_response_text("store_recovery", &error));
                        }
                    };
                }
                if staged.readiness() == eliot_kernel_service::StagedWriteReadiness::Ready {
                    // The Store snapshot is same-fence validated above and the
                    // staged envelopes are reconciled under that same fence, so
                    // both halves of step 6 now hold.
                    self.record_startup_evidence(6)
                        .map_err(|_| TransportError::SessionFenced)?;
                }
                Ok(store_recovery_response(
                    &snapshot,
                    &self.process_stream_recovery_status_view(&stream_identities),
                    &staged_write_recovery_view(&staged),
                ))
            }
            Err(error) => Ok(Self::store_error_response_text("store_recovery", &error)),
        }
    }

    /// Proves the process-stream recovery selector before any durable read.
    ///
    /// Pure, so an empty, over-bound or unusable selector is refused here rather
    /// than after the Store recovery has already answered. An absent selector is
    /// the existing caller's shape and yields an empty view, which the response
    /// projects as explicit `null` rather than as an empty family.
    #[cfg(windows)]
    fn admit_process_stream_recovery_operations(
        requested: Option<&[String]>,
    ) -> Result<Vec<eliot_ors::OperationIdentity>, String> {
        let Some(requested) = requested else {
            return Ok(Vec::new());
        };
        if requested.is_empty() {
            return Err(
                "process_stream_recovery_operations must name at least one operation".to_owned(),
            );
        }
        if requested.len() > MAX_RECOVERY_OWNER_RECORDS {
            return Err(format!(
                "process_stream_recovery_operations exceeds the bounded recovery denominator of {MAX_RECOVERY_OWNER_RECORDS}"
            ));
        }
        requested
            .iter()
            .map(|value| {
                eliot_ors::OperationIdentity::new(value.clone())
                    .map_err(|error| format!("process_stream_recovery_operations: {error}"))
            })
            .collect()
    }

    /// Serves the ORS process-stream recovery status for the selected
    /// operations (issue #269 W6, I14.26).
    ///
    /// I14.26 states that the Kernel assembles the recovery view from ORS, and
    /// the retained daemon client already reads recovery status on this exact
    /// operation, so the ORS half is served beside the Store snapshot rather
    /// than through a second recovery vocabulary.
    ///
    /// Three properties are load-bearing and none of them is a claim about
    /// stream content:
    ///
    /// - The durable read is
    ///   [`RedbRecoveryStore::process_stream_recovery_status`] and the projection
    ///   is the ORS-owned [`eliot_ors::ProcessStreamRecoveryStatusProjection`].
    ///   Nothing is recomputed here: availability, the exact gap set, the
    ///   immutable locator handle, the ready-receipt handle, the exact durable
    ///   coverage and both typed state axes are copied field for field.
    /// - No raw bytes cross. The ORS view has no byte-bearing field at all, so
    ///   stdout/stderr payload is structurally absent from the answer rather
    ///   than redacted from it.
    /// - No semantic proof is asserted. There is no parser, evaluator, task or
    ///   finish field to project, `evidence_scope` is a single-variant value
    ///   that names exactly bytes-and-coverage, and `reports_complete_evidence`
    ///   is ORS's own conjunction over the copied typed axes.
    ///
    /// An unreadable row is answered as ORS's own typed disposition
    /// (codec-version mismatch versus interrupted read) instead of being
    /// flattened into a transport error, so a caller can tell a stale codec from
    /// an interrupted read, and an empty stream list means ORS retains no row
    /// for that operation — never that the operation had no streams.
    #[cfg(windows)]
    fn process_stream_recovery_status_view(
        &self,
        identities: &[eliot_ors::OperationIdentity],
    ) -> serde_json::Value {
        if identities.is_empty() {
            return serde_json::Value::Null;
        }
        let operations = identities
            .iter()
            .map(|identity| {
                let status = match self.p07_ors.process_stream_recovery_status(identity) {
                    Ok(views) => serde_json::json!({
                        "kind": PROCESS_STREAM_RECOVERY_RETAINED_KIND,
                        "streams": views
                            .iter()
                            .map(process_stream_recovery_stream_view)
                            .collect::<Vec<_>>(),
                    }),
                    Err(error) => serde_json::json!({
                        "kind": PROCESS_STREAM_RECOVERY_UNREADABLE_KIND,
                        "disposition": process_stream_recovery_load_disposition(&error),
                    }),
                };
                serde_json::json!({
                    "operation_id": identity.as_str(),
                    "status": status,
                })
            })
            .collect::<Vec<_>>();
        serde_json::json!({
            "kind": PROCESS_STREAM_RECOVERY_STATUS_KIND,
            "operations": operations,
        })
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
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
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

    #[cfg(windows)]
    async fn store_work_scope_owner_operation(
        &self,
        session: &Session,
        request_identity: Option<&RequestIdentity>,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: StoreWorkScopeOwnerOperation =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        let identity = request_identity.ok_or(TransportError::SessionFenced)?;
        identity
            .validate()
            .map_err(|_| TransportError::SessionFenced)?;
        let context = &identity.request.metadata;
        if context.product_id.as_str() != ACTIVE_DAEMON_CALLER
            || context.source_id.as_str() != ACTIVE_DAEMON_CALLER
            || context.session_id.as_deref() != Some(operation.attempt.session_id.as_str())
            || context.task_id.as_ref() != Some(&operation.attempt.task_id)
            || identity.request.state_fence != operation.attempt.state_fence
            || identity.deadline_unix_ms != operation.attempt.expires_at_unix_ms
        {
            return Err(TransportError::SessionFenced);
        }
        if operation.request.state_fence != context.state_fence
            || operation.attempt.state_fence != context.state_fence
            || operation.operation_id != operation.attempt.operation_id
            || operation.request.operation_id.as_str() != operation.operation_id
            || operation.request.idempotency_key != identity.idempotency_key
            || operation.request_sha256.trim().is_empty()
            || operation.request_sha256.chars().any(char::is_control)
        {
            return Err(TransportError::SessionFenced);
        }
        if let Err(error) = operation.request.validate_for_context(context) {
            return work_scope_owner_store_failure_response(
                error,
                context,
                &operation.request.operation_id,
                &operation.request.idempotency_key,
            );
        }
        validate_store_session_fence(session, &context.state_fence)?;
        if let Some(rejection) = self.material_write_admission_response(&context.state_fence) {
            return Ok(rejection);
        }
        let (envelope, invocation, _tool, _principal) = self
            .admit_task_controller_work_scope_owner_write(
                session,
                &operation.operation_id,
                &operation.request_sha256,
                &operation.attempt,
            )?;
        if invocation.action != eliot_protocol::TaskControllerAction::BindScope
            || context.task_id.as_ref() != Some(&invocation.task_id)
            || context.state_fence != envelope.state_fence
            || context.request_id != envelope.identity.request_id
            || context.session_id.as_ref().map(|id| id.as_str())
                != envelope.identity.session_id.as_deref()
            || operation.request.operation_id.as_str() != operation.operation_id
            || operation.request.idempotency_key != envelope.identity.idempotency_key
            || identity.idempotency_key != envelope.identity.idempotency_key
            || identity.deadline_unix_ms != envelope.identity.deadline_unix_ms
            || identity.cancellation_id != envelope.identity.cancellation_id
        {
            return Err(TransportError::SessionFenced);
        }
        validate_work_scope_record_against_retained_input(
            &operation.request.owner_record,
            &invocation.task_input,
            &invocation.work_scope_id,
        )?;
        let protected_snapshot_digest = self
            .front_door_policy
            .lock()
            .map_err(|_| TransportError::SessionFenced)?
            .config_snapshot
            .get("protected_snapshot_digest")
            .and_then(serde_json::Value::as_str)
            .ok_or(TransportError::SessionFenced)?;
        if operation.request.protected_snapshot_digest != protected_snapshot_digest {
            return Err(TransportError::SessionFenced);
        }
        let failure_operation_id = operation.request.operation_id.clone();
        let failure_idempotency_key = operation.request.idempotency_key.clone();
        let gateway = self.retained_store_gateway()?;
        match gateway
            .write_work_scope_owner(context, operation.request)
            .await
        {
            Ok(response) => Ok(serde_json::json!({
                "kind": "store_work_scope_owner",
                "value": response.record,
            })),
            Err(NamedReadGatewayError::Store(error)) => {
                work_scope_owner_store_failure_response(
                    error,
                    context,
                    &failure_operation_id,
                    &failure_idempotency_key,
                )
            }
            Err(NamedReadGatewayError::GatewayRefusal(_)) => Ok(serde_json::json!({
                "status": "error",
                "code": "KERNEL_GATEWAY_REFUSAL",
                "reason": "The canonical WorkScope owner route refused the request.",
                "value": { "kind": "store_work_scope_owner", "value": null },
                "recovery": null,
            })),
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

    #[cfg(not(windows))]
    async fn store_work_scope_owner_operation(
        &self,
        _session: &Session,
        _request_identity: Option<&RequestIdentity>,
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
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        if operation.context.request_id != request_id {
            return Err(TransportError::SessionFenced);
        }
        validate_store_session_fence(session, &operation.context.state_fence)?;
        // Issue #1796 (I6.8): the pre-stage admission boundary emits one typed
        // rejection carrying every detected defect with `stage_state: none`,
        // `ordering_sequence_assigned: false`, `write_mutation_status:
        // NOT_ATTEMPTED`, and no `write_intent_id`. Exact same-hash retry
        // replays the same rejection identity; changed canonical bytes under
        // one idempotency key yield `IDENTITY_CONFLICT`. The gate allocates no
        // ordering sequence, mints no `write_intent_id`, and records no
        // effect, so a refusal never reaches the Store backend below. An
        // admitted resubmission presenting exactly the corrected identity a
        // retained refusal issued additionally returns its verified correction
        // lineage, which travels on the commit response below. The retained
        // refusals are the Kernel-owned durable pre-stage journal (issue
        // #1796 F1): they are restored from disk when the process starts
        // with an empty cache and persisted write-ahead of the commit they
        // authorize, so a restart replays the same lineage. The response
        // stays a projection of that record, never a second ledger.
        let restore_outcome =
            restore_pre_stage_corrections(&self.work_root, &self.pre_stage_identity_cache);
        let (gate_outcome, pending_journal) = {
            let mut cache = self
                .pre_stage_identity_cache
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let gate_outcome = eliot_kernel_service::pre_stage_check(
                &mut cache,
                &operation.context,
                &operation.transition,
                &operation.expected_revision_heads,
                &operation.expected_ordering_heads,
            );
            // Taken, not written, under the lock: the file write below never
            // holds the cache across I/O.
            let pending_journal = cache.take_journal_snapshot();
            (gate_outcome, pending_journal)
        };
        // Write-ahead and best-effort: the helper below acknowledges the
        // exact saved revision only after the checked durable replacement
        // commits, so a failed save stays pending and is offered again
        // by the next take. The typed outcome is consumed below but never
        // fails the write whose retain it records.
        let persist_outcome = pending_journal.as_ref().map(|snapshot| {
            persist_pre_stage_corrections(&self.work_root, &self.pre_stage_identity_cache, snapshot)
        });
        // Consume the restore/save outcomes before admitting a dependent
        // write (issue #1796, audit 5890973032 defect 2): a failed recovery
        // or a failed save is reported on the commit response, and the write
        // carries no correction lineage it cannot prove. Admission itself is
        // unchanged: the write still proceeds, independent reads and
        // unrelated subsystems are not stopped.
        let journal_issue: Option<&'static str> = match restore_outcome {
            JournalRestoreOutcome::RecoveryRequired => {
                Some(JournalPersistOutcome::RecoveryRequired.issue_code())
            }
            JournalRestoreOutcome::Ready => match persist_outcome {
                None | Some(JournalPersistOutcome::Persisted) => None,
                Some(outcome) => Some(outcome.issue_code()),
            },
        };
        let mut verified_correction = match gate_outcome {
            Err(rejection) => {
                return Ok(Self::pre_stage_rejection_response(&rejection));
            }
            Ok(link) => link,
        };
        if journal_issue.is_some() {
            verified_correction = None;
        }
        super::blackboard::validate_blackboard_transition(session, &operation.transition)?;
        let gateway = self.retained_store_gateway()?;
        if let Some(replayed) = self
            .replay_committed_apply_receipt(
                &gateway,
                &operation,
                verified_correction.as_ref(),
                journal_issue,
            )
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
        let is_observation_capture = operation.transition.transition_class
            == eliot_store_api::TransitionClass::CaptureCandidate
            && operation.transition.named_operations.iter().any(|named| {
                named.operation == eliot_store_api::NamedMutationOperation::CaptureObservation
            });
        if is_observation_capture && !campaign_source_publications.is_empty() {
            return Ok(Self::store_error_response_text(
                "write_receipt",
                "protected Observe capture cannot share a campaign-source publication",
            ));
        }
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
            return Ok(Self::store_staging_refusal_response(
                "write_receipt",
                campaign_source_operation_id.as_str(),
                &error.to_string(),
            ));
        }
        let gateway = self.retained_store_gateway()?;
        let reserved_seed = match self
            .observe_reservation_seed(
                &gateway,
                &operation,
                operation.original_write_submission.as_ref(),
            )
            .await
        {
            Ok(seed) => seed,
            Err(error) => return Ok(Self::store_error_response_text("write_receipt", &error)),
        };
        if is_observation_capture && reserved_seed.is_none() {
            return Ok(Self::store_error_response_text(
                "write_receipt",
                "observation capture lacks its protected original host request binding",
            ));
        }
        if let Some((seed, deadline_unix_ms)) = reserved_seed {
            let Some(original_submission) = operation.original_write_submission.as_ref() else {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    "protected Observe apply has no original write submission",
                ));
            };
            if original_submission.validate().is_err() {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    "original write submission is invalid",
                ));
            }
            if !campaign_source_publications.is_empty() {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    "protected Observe capture cannot share a campaign-source publication",
                ));
            }
            let original_submission = original_submission.clone();
            return Ok(self
                .run_reserved_observe_write(
                    Arc::clone(&gateway),
                    operation,
                    seed,
                    original_submission,
                    deadline_unix_ms,
                )
                .await);
        }
        let apply_result = {
            if operation.original_write_submission.is_some() {
                return Ok(Self::store_error_response_text(
                    "write_receipt",
                    "original write submission is only valid for protected Observe capture",
                ));
            }
            match gateway
                .apply(
                    &operation.context,
                    operation.transition,
                    operation.expected_revision_heads,
                    operation.expected_ordering_heads,
                )
                .await
            {
                Ok(receipt) => Ok(receipt),
                Err(error) => Err(Self::store_apply_refusal_response("write_receipt", &error)),
            }
        };
        match apply_result {
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
                Ok(store_apply_response(
                    &receipt,
                    verified_correction.as_ref(),
                    journal_issue,
                ))
            }
            Err(response) => Ok(response),
        }
    }

    /// Builds a reserved-write seed only for a protected, durably claimed
    /// Observe submission. Its canonical head evidence comes from current
    /// Store owner readbacks, while its access class and deadline are copied
    /// from the exact retained host request.
    #[cfg(windows)]
    async fn observe_reservation_seed(
        &self,
        gateway: &Arc<KernelStoreGateway>,
        operation: &StoreApplyOperation,
        original_submission: Option<&eliot_store_api::OriginalWriteSubmission>,
    ) -> Result<Option<(ReservationSeed, u64)>, String> {
        let transition = &operation.transition;
        let operation_identity =
            eliot_ors::OperationIdentity::new(transition.identity.operation_id.as_str())
                .map_err(|error| error.to_string())?;
        let Some(record) = self
            .generation_gateway
            .ors
            .load_host_request_by_operation(&operation_identity)
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let Some(input) = Self::retained_observe_reservation_input(&record, operation)? else {
            return Ok(None);
        };
        let original_submission = original_submission.ok_or_else(|| {
            "protected Observe request is missing its original write submission".to_owned()
        })?;
        self.validate_original_write_submission_source(&record, original_submission)
            .map_err(|error| format!("original Observe write source mismatch: {error}"))?;
        let current_time_ms = unix_ms();
        if current_time_ms >= record.deadline_unix_ms {
            return Err("protected Observe request deadline has expired".to_owned());
        }
        let created_at_ms = i64::try_from(current_time_ms)
            .map_err(|_| "Kernel clock is outside the reservation time range".to_owned())?;
        let expires_at_ms = i64::try_from(record.deadline_unix_ms).map_err(|_| {
            "host request deadline is outside the reservation time range".to_owned()
        })?;

        let observed_heads = self
            .read_observe_reservation_heads(gateway, operation)
            .await?;
        let access = input
            .protected_envelope
            .privacy_and_visibility_class
            .clone();
        access.validate().map_err(|error| error.to_string())?;
        let protected_operation_bytes =
            canonical_json_bytes(operation).map_err(|error| error.to_string())?;
        let protected_operation = self
            .platform
            .protect_secret(&protected_operation_bytes)
            .map_err(|error| error.to_string())?;
        let operation_id = transition.identity.operation_id.as_str().to_owned();
        let seed = ReservationSeed {
            reservation_id: operation_id.clone(),
            operation_id,
            recovery_owner: "kernel-composition".to_owned(),
            payload_bytes: protected_operation.as_bytes().to_vec(),
            key_provider: eliot_kernel_service::RESERVATION_KEY_PROVIDER.to_owned(),
            key_name: eliot_kernel_service::RESERVATION_KEY_NAME.to_owned(),
            recovery_access_class: access,
            created_at_ms,
            known_at_ms: created_at_ms,
            expires_at_ms,
            heads: observed_heads,
        };
        let seed = gateway_seed_from_protected_original_operation(transition, seed)
            .map_err(|error| error.to_string())?;
        Ok(Some((seed, record.deadline_unix_ms)))
    }

    #[cfg(windows)]
    async fn run_reserved_observe_write(
        &self,
        gateway: Arc<KernelStoreGateway>,
        operation: StoreApplyOperation,
        seed: ReservationSeed,
        original_submission: eliot_store_api::OriginalWriteSubmission,
        deadline_unix_ms: u64,
    ) -> serde_json::Value {
        use eliot_runtime::{SpawnDisposition, TaskFailure};

        let (staged_sender, staged_receiver) = tokio::sync::oneshot::channel();
        let (receipt_sender, receipt_receiver) = tokio::sync::oneshot::channel();
        let expected_operation_id = operation
            .transition
            .identity
            .operation_id
            .as_str()
            .to_owned();
        let expected_request_hash = operation.transition.identity.canonical_request_hash.clone();
        let response_mode = original_submission.response_mode.clone();
        let staged = self.runtime.spawn(
            "kernel.observe-reserved-write",
            move |cancellation| async move {
                if unix_ms() >= deadline_unix_ms {
                    let _ = staged_sender.send(Err(StagedReservedWriteError::Refused {
                        detail: "protected Observe request expired before durable staging"
                            .to_owned(),
                    }));
                    return Ok::<(), TaskFailure>(());
                }
                let accepted = match gateway
                    .stage_reserved_with_original_submission(
                        &operation.context,
                        operation.transition.clone(),
                        operation.expected_revision_heads.clone(),
                        operation.expected_ordering_heads.clone(),
                        seed,
                        &original_submission,
                    )
                    .await
                {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        let _ = staged_sender.send(Err(error));
                        return Ok::<(), TaskFailure>(());
                    }
                };
                let submission = accepted.submission().clone();
                let token = accepted.token().clone();
                if !write_submission_matches_staged_operation(
                    &submission,
                    &expected_operation_id,
                    &expected_request_hash,
                ) {
                    let _ = staged_sender.send(Err(StagedReservedWriteError::OutcomeUnknown {
                        operation_id: expected_operation_id,
                        detail: "durable Observe stage did not match the original operation"
                            .to_owned(),
                    }));
                    return Ok::<(), TaskFailure>(());
                }
                let _ = staged_sender.send(Ok(submission));
                let receipt = Box::pin(Self::execute_or_resume_reserved_observe_write(
                    &gateway,
                    accepted,
                    operation,
                    token,
                    &expected_operation_id,
                    cancellation,
                ))
                .await;
                let _ = receipt_sender.send(receipt);
                Ok::<(), TaskFailure>(())
            },
        );
        match staged {
            SpawnDisposition::DeniedShuttingDown => {
                return Self::store_error_response_text(
                    "write_receipt",
                    "Kernel runtime is shutting down before protected Observe staging",
                );
            }
            SpawnDisposition::Admitted(handle) => drop(handle),
        }

        Self::finish_reserved_observe_response(
            staged_receiver,
            receipt_receiver,
            response_mode,
            deadline_unix_ms,
        )
        .await
    }

    #[cfg(windows)]
    async fn finish_reserved_observe_response(
        staged_receiver: tokio::sync::oneshot::Receiver<
            Result<eliot_store_api::WriteSubmission, StagedReservedWriteError>,
        >,
        receipt_receiver: tokio::sync::oneshot::Receiver<
            Result<WriteReceipt, StagedReservedWriteError>,
        >,
        response_mode: String,
        deadline_unix_ms: u64,
    ) -> serde_json::Value {
        let write_submission = match staged_receiver.await {
            Ok(Ok(submission)) => submission,
            Ok(Err(error)) => {
                return Self::store_error_response_text("write_receipt", &error.to_string());
            }
            Err(_) => {
                return Self::store_error_response_text(
                    "write_receipt",
                    "protected Observe staging task ended before returning its durable stage",
                );
            }
        };
        if response_mode == "accept_after_stage" {
            return store_apply_staged_response(&write_submission);
        }
        let remaining_ms = deadline_unix_ms.saturating_sub(unix_ms());
        match tokio::time::timeout(
            std::time::Duration::from_millis(remaining_ms),
            receipt_receiver,
        )
        .await
        {
            Ok(Ok(Ok(receipt))) => store_apply_response(&receipt, None, None),
            Ok(Ok(Err(error))) => {
                Self::store_error_response_text("write_receipt", &error.to_string())
            }
            Ok(Err(_)) | Err(_) => store_apply_staged_response(&write_submission),
        }
    }

    #[cfg(windows)]
    async fn execute_or_resume_reserved_observe_write(
        gateway: &KernelStoreGateway,
        accepted: eliot_kernel_service::AcceptedReservedWrite,
        operation: StoreApplyOperation,
        token: eliot_ors::WriterReservationToken,
        expected_operation_id: &str,
        cancellation: eliot_runtime::CancellationToken,
    ) -> Result<WriteReceipt, StagedReservedWriteError> {
        let original_submission =
            operation
                .original_write_submission
                .as_ref()
                .ok_or_else(|| StagedReservedWriteError::Refused {
                    detail: "protected Observe operation has no original write source".to_owned(),
                })?;
        let mut result = gateway.execute_staged_reserved(accepted).await;
        loop {
            let pending_operation = match &result {
                Err(StagedReservedWriteError::RetryablePredecessorPending { operation_id }) => {
                    Some(operation_id.as_str())
                }
                _ => None,
            };
            let Some(pending_operation) = pending_operation else {
                return result;
            };
            if pending_operation != expected_operation_id
                || token.operation_id.as_str() != expected_operation_id
                || operation.transition.identity.operation_id.as_str() != expected_operation_id
            {
                return Err(StagedReservedWriteError::OutcomeUnknown {
                    operation_id: expected_operation_id.to_owned(),
                    detail: "predecessor wait did not name the original Store operation".to_owned(),
                });
            }
            if cancellation.is_cancelled() {
                return Err(StagedReservedWriteError::OutcomeUnknown {
                    operation_id: expected_operation_id.to_owned(),
                    detail: "runtime shutdown interrupted the retained predecessor wait".to_owned(),
                });
            }
            tokio::select! {
                () = cancellation.cancelled() => {
                    return Err(StagedReservedWriteError::OutcomeUnknown {
                        operation_id: expected_operation_id.to_owned(),
                        detail: "runtime shutdown interrupted the retained predecessor wait"
                            .to_owned(),
                    });
                }
                waited = gateway.wait_for_staged_predecessor(
                    &operation.context,
                    &operation.transition,
                    &token,
                ) => waited?,
            }
            if cancellation.is_cancelled() {
                return Err(StagedReservedWriteError::OutcomeUnknown {
                    operation_id: expected_operation_id.to_owned(),
                    detail: "runtime shutdown interrupted the retained predecessor wait".to_owned(),
                });
            }
            result = gateway
                .restore_staged_reserved(
                    &operation.context,
                    operation.transition.clone(),
                    operation.expected_revision_heads.clone(),
                    operation.expected_ordering_heads.clone(),
                    original_submission,
                    token.clone(),
                )
                .await;
        }
    }

    pub(crate) fn retained_observe_reservation_input<'a>(
        record: &'a HostRequestRecord,
        operation: &StoreApplyOperation,
    ) -> Result<Option<&'a eliot_ors::HostRequestExecutableInput>, String> {
        let Some(input) = record.executable_input.as_ref() else {
            if record.kind == eliot_ors::HostRequestKind::Invocation
                && record.capability_ref.as_str() == "eliot.observe"
            {
                return Err("Observe request has no retained executable input".to_owned());
            }
            return Ok(None);
        };
        record.validate().map_err(|error| error.to_string())?;
        input
            .validate_for(record)
            .map_err(|error| error.to_string())?;
        let attempt = record
            .attempt
            .as_ref()
            .ok_or_else(|| "protected Observe row has no durable claim attempt".to_owned())?;
        if record.kind != eliot_ors::HostRequestKind::Invocation
            || record.capability_ref.as_str() != "eliot.observe"
            || record.state != eliot_ors::HostRequestState::Submitted
            || attempt.phase != eliot_ors::HostRequestAttemptPhase::Claimed
            || attempt.input_commitment_sha256.as_deref() != Some(input.commitment_sha256.as_str())
        {
            return Err(
                "protected Observe row is not the exact durably claimed submission".to_owned(),
            );
        }
        let transition = &operation.transition;
        let app = &input.application_binding;
        let scope_ref = record
            .scope_ref
            .as_ref()
            .ok_or_else(|| "protected Observe row has no owner-resolved scope".to_owned())?;
        if record.operation_id.as_str() != transition.identity.operation_id.as_str()
            || record.idempotency_key.as_str() != transition.identity.idempotency_key.as_str()
            || app.state_fence != operation.context.state_fence
            || app.state_fence != transition.state_fence
            || transition.scope_id.as_str() != scope_ref.as_str()
            || app.scope_ref.as_ref() != Some(scope_ref)
            || transition.transition_class != eliot_store_api::TransitionClass::CaptureCandidate
            || transition.named_operations.len() != 1
            || transition.named_operations[0].operation
                != eliot_store_api::NamedMutationOperation::CaptureObservation
        {
            return Err(
                "prepared observation does not match the retained host request binding".to_owned(),
            );
        }
        Ok(Some(input))
    }

    async fn read_observe_reservation_heads(
        &self,
        gateway: &Arc<KernelStoreGateway>,
        operation: &StoreApplyOperation,
    ) -> Result<Vec<ObservedHead>, String> {
        let store = BorrowedCanonicalStoreClient::new(gateway);
        let actual_revision_heads = store
            .revision_heads(
                operation
                    .expected_revision_heads
                    .iter()
                    .map(|head| head.key.clone())
                    .collect(),
            )
            .await
            .map_err(|error| format!("could not observe canonical revision heads: {error}"))?;
        if actual_revision_heads.len() != operation.expected_revision_heads.len() {
            return Err("canonical revision-head observation is incomplete".to_owned());
        }
        let expected_revisions: BTreeMap<_, _> = operation
            .expected_revision_heads
            .iter()
            .map(|head| {
                (
                    head.key.as_str(),
                    (head.expected_revision, &head.state_fence),
                )
            })
            .collect();
        let mut seen_revision_keys = BTreeSet::new();
        for head in &actual_revision_heads {
            head.validate().map_err(|error| error.to_string())?;
            if !seen_revision_keys.insert(head.key.as_str()) {
                return Err("canonical revision-head observation contains duplicates".to_owned());
            }
            if expected_revisions
                .get(head.key.as_str())
                .is_none_or(|(revision, fence)| {
                    *revision != head.revision || **fence != head.state_fence
                })
            {
                return Err("canonical revision heads changed before reservation".to_owned());
            }
        }
        if seen_revision_keys.len() != expected_revisions.len() {
            return Err(
                "canonical revision-head observation does not cover the admitted keys".to_owned(),
            );
        }

        let actual_ordering_heads = store
            .ordering_head_readbacks(operation.transition.ordering_scopes.clone())
            .await
            .map_err(|error| format!("could not observe canonical ordering heads: {error}"))?;
        if actual_ordering_heads.len() != operation.expected_ordering_heads.len() {
            return Err("canonical ordering-head observation is incomplete".to_owned());
        }
        let expected_ordering: BTreeMap<_, _> = operation
            .expected_ordering_heads
            .iter()
            .map(|head| {
                (
                    head.scope.as_str(),
                    (head.expected_sequence, &head.state_fence),
                )
            })
            .collect();
        let mut observed_heads = Vec::with_capacity(actual_ordering_heads.len());
        let mut seen_ordering_scopes = BTreeSet::new();
        for readback in actual_ordering_heads {
            let head = readback.head;
            head.validate().map_err(|error| error.to_string())?;
            if !seen_ordering_scopes.insert(head.scope.clone()) {
                return Err("canonical ordering-head observation contains duplicates".to_owned());
            }
            let canonical_head = canonical_json_bytes(&head).map_err(|error| error.to_string())?;
            if canonical_head != readback.canonical_bytes
                || sha256_hex(&readback.canonical_bytes) != readback.canonical_sha256
                || head.state_fence != operation.context.state_fence
                || expected_ordering
                    .get(head.scope.as_str())
                    .is_none_or(|(sequence, fence)| {
                        *sequence != head.sequence || **fence != head.state_fence
                    })
            {
                return Err("canonical ordering heads changed or failed exact readback".to_owned());
            }
            observed_heads.push(ObservedHead {
                scope: head.scope.as_str().to_owned(),
                expected_sequence: head.sequence,
                expected_head_digest: readback.canonical_sha256,
                revision_head: None,
            });
        }
        if seen_ordering_scopes.len() != expected_ordering.len() {
            return Err(
                "canonical ordering-head observation does not cover admitted scopes".to_owned(),
            );
        }

        Ok(observed_heads)
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
        verified_correction: Option<&eliot_kernel_service::VerifiedCorrectionLink>,
        journal_issue: Option<&str>,
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
        Ok(Some(store_apply_response(
            &receipt,
            verified_correction,
            journal_issue,
        )))
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
                return Ok(Self::store_apply_refusal_response(
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
        let page = match self
            .read_notification_page(&NotificationPageQuery::addressed_record(
                &state_fence,
                dedup_key,
                notification_id,
            ))
            .await?
        {
            Ok(page) => page,
            // The record could not be READ. Reporting the committed receipt
            // over an unreadable record would present a write this seam never
            // proved, and substituting an empty page would present a read the
            // Store never made. The answer is the typed unavailable disposition
            // with the shared directive, under the same fence the read asked
            // for, and this read owns no admitted handle of its own to
            // preserve.
            Err(error) => {
                return Ok(Self::store_read_failure_response(
                    NOTIFICATION_STATE_RESPONSE_KIND,
                    &state_fence,
                    None,
                    &error,
                ));
            }
        };
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
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        validate_store_session_fence(session, &operation.state_fence)?;
        let page = match self
            .read_notification_page(&NotificationPageQuery::from_read_operation(&operation))
            .await?
        {
            Ok(page) => page,
            // The inbox read has no answer: the Store did not make it. The
            // disposition names the cause and the fence the read was bound to
            // and carries the shared directive; it never yields an empty page
            // that reads as a successful inbox with nothing in it.
            Err(error) => {
                return Ok(Self::store_read_failure_response(
                    NOTIFICATION_STATE_PAGE_RESPONSE_KIND,
                    &operation.state_fence,
                    None,
                    &error,
                ));
            }
        };
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
    ///
    /// The canonical Store's own typed refusal is handed back to the caller
    /// instead of being collapsed into a fence (issue #1681 W3, I14.11). An
    /// unreachable Store produces no page, and this read carries no admitted
    /// Kernel-issued operation handle of its own, so the caller cannot be told
    /// a current answer — only the closed `DB_UNAVAILABLE` disposition with the
    /// shared directive, which names the cause and the fence it was observed
    /// against. Reporting the outage as a fencing refusal instead would name
    /// neither, and would let an owner outage be read as proof the generation
    /// had moved.
    ///
    /// `Ok(Err(..))` is "the Store could not answer this read";
    /// `Err(..)` remains the session/route fence refusal that is not an owner
    /// answer at all. Neither arm ever yields a page, so a read the Store did
    /// not make cannot leave here as a page that looks successfully empty.
    #[cfg(windows)]
    async fn read_notification_page(
        &self,
        query: &NotificationPageQuery,
    ) -> Result<Result<serde_json::Value, NamedReadGatewayError>, TransportError> {
        let request = query
            .read_request()
            .map_err(|_| TransportError::SessionFenced)?;
        let gateway = self.retained_store_gateway()?;
        let response = match gateway.execute_named_with_error(request).await {
            Ok(response) => response,
            Err(error) => return Ok(Err(error)),
        };
        if response.operation != eliot_store_api::NamedReadOperation::GetNotificationState
            || response.state_fence != query.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        Ok(Ok(response.payload))
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
        let read_fence = operation.request.state_fence.clone();
        match gateway.execute_named_with_error(operation.request).await {
            Ok(response) => Ok(store_named_response(&response)),
            // This route is a bare closed named read with no Kernel-issued
            // operation handle, so the directive carries no preserved identity
            // rather than one invented at refusal time.
            Err(error) => Ok(Self::store_read_failure_response(
                "store_named",
                &read_fence,
                None,
                &error,
            )),
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
    /// serves its stored bounded body without re-dispatch — rejoined first to
    /// the current source revisions its own lineage records, which is one
    /// bounded head read and never a re-execution — then the presented
    /// attempt capability is proven current against the live claim record
    /// before any Gateway IO. Only a fresh admitted
    /// query with a current attempt reaches the evidence Gateway, over the admitted
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
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
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
            host_request_route::LocalReadAdmission::CampaignPacket { .. }
            | host_request_route::LocalReadAdmission::Skill => {
                // `local_read` is the query-only Gateway leg. A campaign
                // packet has its dedicated claim/compile/result flight; Skill
                // tools are served by the daemon's Skill dispatcher. Neither
                // may be reinterpreted as `GetEvidencePack` selectors.
                return Err(TransportError::SessionFenced);
            }
        };
        let (receipt, record) = self.admit_host_request_envelope(&envelope)?;
        if let Some(replayed) =
            host_request_route::local_read_replay_response(&receipt, &record, &envelope)?
        {
            // Replay preserves the original execution and result identity, but
            // the retained answer is a dependent branch: it was derived from
            // the source revisions its own lineage records. Rejoining that
            // branch to the CURRENT source revisions is what revokes it when a
            // source moved (I15.7); nothing is re-executed, overwritten, or
            // narrowed here. The observed heads come from the Store's own head
            // read, so this is a causal join rather than a self-match.
            //
            // When the canonical Store is unreachable the join is
            // UNESTABLISHED rather than disproved: the retained bytes are
            // withheld and the caller receives the typed unavailable answer with
            // the full directive, so a cached view is never presented as current
            // merely because the source that would disprove it was unreachable.
            if let Err(error) = self
                .check_retained_local_read_source_revisions(&record, &envelope)
                .await?
            {
                return Ok(Self::store_read_failure_response(
                    "local_read",
                    &envelope.state_fence,
                    Some(&host_request_operation_id(&envelope)),
                    &error,
                ));
            }
            // The bytes are about to leave this process, so the CURRENT
            // disclosure permission is re-evaluated now, at the moment of
            // redelivery, against the durable row and the live owner reads —
            // never against the value captured when the result was first
            // produced and never against anything the presenting caller
            // supplies. A changed permission withholds the bytes; it does not
            // re-execute, does not overwrite the retained result, and does not
            // erase an earlier delivery observation. A delivery whose outcome
            // was never proven keeps its reconciliation obligation, because
            // this leg only refuses and writes nothing.
            self.reevaluate_retained_disclosure_permission(&record, session, &envelope)?;
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
        let response = match gateway.execute_named_with_error(read).await {
            Ok(response) => response,
            Err(error) => {
                // The Kernel-issued host-request handle is the admitted read's
                // own identity, so the directive preserves THAT handle and the
                // caller retries this read rather than a fresh one.
                return Ok(Self::store_read_failure_response(
                    "local_read",
                    &envelope.state_fence,
                    Some(&operation_id),
                    &error,
                ));
            }
        };
        if response.operation != NamedReadOperation::GetEvidencePack
            || response.state_fence != envelope.state_fence
        {
            return Ok(Self::store_error_response_text(
                "local_read",
                "named-read operation or State Fence does not match request",
            ));
        }
        let (digest, body) = AuthenticatedHostSession::build_local_read_result_body(
            &envelope,
            selectors.scope_id.as_str(),
            &selectors.subject,
            selectors.max_records,
            &selectors.intent_mode,
            response.payload.clone(),
            Some(&response),
        )
        .map_err(|_| TransportError::SessionFenced)?;
        let lineage = HostRequestResultLineage {
            output_artifact_ref: None,
            output_digest: digest.clone(),
            producer_ref: None,
            source_revisions: Some(
                response
                    .revision_heads
                    .iter()
                    .map(|head| HostRequestResultSourceRevision {
                        key: head.key.as_str().to_owned(),
                        revision: head.revision,
                        state_fence: head.state_fence.clone(),
                    })
                    .collect(),
            ),
            source_state_fence: Some(response.state_fence),
            input_refs: None,
            transformation_lineage: None,
            closure_refs: None,
            policy_fence: None,
            origin_evidence_refs: None,
            // This leg read already-retained canonical evidence through the
            // named-read gateway. Under I1.8 that is a read with its actual
            // revision and provenance, not a newly generated record, so it
            // declares the read class and carries NO semantic receipt: it did
            // not commit anything and admits nothing about the content.
            semantic_receipt_ref: None,
            result_class: eliot_protocol::HostRequestResultClass::ExistingEvidenceRead,
            proof_ceiling: None,
            influence_state: eliot_security_contracts::InfluenceState::Unknown,
            instruction_taint: None,
        };
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
            result_digest: digest.clone(),
            response: body,
            attempt: Some(attempt),
            lineage: Some(lineage),
            // Issue #1838: this leg executed the read, so it reports its own
            // execution evidence for the sealed trace manifest. The read-only
            // leg produces no external effect; the executor has no stable
            // self-identity at this site, so that slot stays honestly absent.
            evidence: Some(LocalReadExecutionEvidence {
                wire_id: eliot_protocol::LOCAL_READ_EXECUTION_EVIDENCE_WIRE_ID.to_owned(),
                wire_version: LocalReadExecutionEvidence::CONTRACT_VERSION,
                operation_id: operation_id.clone(),
                invoked_operation: Some("local_read".to_owned()),
                actual_route: Some(receipt.receipt_sha256.clone()),
                adapter_identity: Some(session.connection_id.clone()),
                executor_identity: None,
                input_handle: Some(envelope.envelope_sha256.clone()),
                output_handle: Some(digest),
                side_effects: Some(eliot_protocol::LOCAL_READ_EXECUTION_NO_SIDE_EFFECTS.to_owned()),
            }),
        };
        submission
            .validate_local_read_submission()
            .map_err(|_| TransportError::SessionFenced)?;
        let resulted = match self.submit_local_read_result(session, &submission)? {
            host_request_route::LocalReadSubmitDisposition::Persisted(record) => record,
            host_request_route::LocalReadSubmitDisposition::StagedWrite(_) => {
                return Err(TransportError::SessionFenced);
            }
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

    /// Revalidates one retained local-read result against the CURRENT source
    /// revision it was derived from (issue #1809 item 5).
    ///
    /// A retained read is a dependent retrieval branch: the answer, its
    /// ranking and its counts all descend from the source revisions the
    /// result's own retained lineage names. I15.7 makes final-result filtering
    /// defense in depth, not the boundary — "If such content participated in a
    /// retrieval/scoring branch, the whole contaminated branch … is discarded
    /// and replanned under the latest grant/policy". So the branch is rejoined
    /// to the source revision, not filtered down to a permitted row.
    ///
    /// The observation is a bounded owner read: the keys come from the durable
    /// row's own recorded lineage, never from the presenting request, and the
    /// comparison happens against the Store's current heads under the same
    /// admitted fence the result was served under. A row that records no
    /// source revision names no join, so nothing is read for it and the
    /// existing result-class refusals keep owning that case.
    ///
    /// This never re-executes the read, never rewrites the retained record,
    /// never erases an earlier delivery, and never spends another budget: a
    /// moved source simply fails the replay closed, leaving the original
    /// result identity and its evidence intact for its owner to replan.
    ///
    /// An unavailable canonical Store is returned as the typed cause rather than
    /// collapsed into a fence, because freshness is then unestablished rather
    /// than disproved: the caller reports the cached view's stale/unavailable
    /// boundary with the full directive instead of presenting the retained bytes
    /// as current or hiding why they were withheld.
    #[cfg(windows)]
    async fn check_retained_local_read_source_revisions(
        &self,
        record: &eliot_ors::HostRequestRecord,
        envelope: &HostRequestEnvelope,
    ) -> Result<Result<(), NamedReadGatewayError>, TransportError> {
        let keys = host_request_route::retained_source_revision_keys(record)?;
        if keys.is_empty() {
            return Ok(Ok(()));
        }
        let gateway = self.retained_store_gateway()?;
        let response = match gateway
            .execute_named_with_error(NamedReadRequest {
                operation: NamedReadOperation::GetRevisionHeads,
                scope_id: None,
                consistency: ReadConsistency::ExactFence,
                state_fence: envelope.state_fence.clone(),
                parameters: BTreeMap::new(),
            })
            .await
        {
            Ok(response) => response,
            // The Store's own typed refusal travels intact; only this one cause
            // is distinguished, because it is the one where the source is
            // unreachable rather than observed to have moved.
            Err(NamedReadGatewayError::Store(StoreError::Unavailable)) => {
                return Ok(Err(NamedReadGatewayError::Store(StoreError::Unavailable)));
            }
            Err(_) => return Err(TransportError::SessionFenced),
        };
        if response.operation != NamedReadOperation::GetRevisionHeads
            || response.state_fence != envelope.state_fence
        {
            return Err(TransportError::SessionFenced);
        }
        let mut observed = Vec::with_capacity(keys.len());
        for key in keys {
            // A key the Store no longer reports is a changed source, not an
            // absent proof of agreement: the head read is the completeness
            // side, so nothing is inferred from the request's own key list.
            let head = response
                .revision_heads
                .iter()
                .find(|head| head.key == key)
                .cloned()
                .ok_or(TransportError::SessionFenced)?;
            observed.push(head);
        }
        host_request_route::check_retained_source_revisions(record, &observed)?;
        Ok(Ok(()))
    }

    /// Re-evaluates the CURRENT disclosure permission for one retained
    /// local-read result immediately before its bytes are re-sent (issue #1809
    /// item 6).
    ///
    /// The permission is read from its real owner at the moment of
    /// redelivery, in two independent halves that no caller can supply:
    ///
    /// * [`host_request_route::check_retained_disclosure_permission`] joins
    ///   the durable row to the live authenticated `Session`: the row must be
    ///   one ORS closed as a result, its retained delivery evidence must still
    ///   describe its own recorded result under the existing ORS validator,
    ///   and the live session's authority LINEAGE must still be the one the
    ///   row was produced under. The session is established by the
    ///   authenticated transport, so the presented envelope contributes
    ///   nothing to this half.
    /// * [`Self::admit_material_authority_for_governor_issued_fence`] — the
    ///   SAME live owner read the fresh leg clears at
    ///   [`Self::local_read_operation`]. It resolves the currently recorded
    ///   Governor-issued coverage revision and active fingerprint, runs the
    ///   unchanged fence, ceiling and Watchdog-supervision decision, and
    ///   re-checks revision currency before admitting. The fresh leg reaches
    ///   it because its record is not yet terminal; a replayed terminal record
    ///   deliberately skips it inside envelope admission, which is exactly the
    ///   gap this leg closes: the current permission that admitted the first
    ///   delivery is re-read here rather than assumed. The profile, revision
    ///   and fingerprint come from the owner, so no presented value can stand
    ///   in for them; only the target fence is presented, and it is bound to
    ///   the retained row by the first join.
    ///
    /// A refusal here is the only outcome. It never re-executes the read, so
    /// a changed permission cannot consume another attempt or budget; it
    /// performs no ORS write, so the retained result and any earlier delivery
    /// observation are untouched; and because the refusal is not an answer and
    /// not a state advance, a delivery whose external outcome was never proven
    /// keeps its reconciliation obligation rather than being resolved into a
    /// success or a failure by this leg.
    #[cfg(windows)]
    fn reevaluate_retained_disclosure_permission(
        &self,
        record: &eliot_ors::HostRequestRecord,
        session: &Session,
        envelope: &HostRequestEnvelope,
    ) -> Result<(), TransportError> {
        host_request_route::check_retained_disclosure_permission(record, session)?;
        self.admit_material_authority_for_governor_issued_fence(&envelope.state_fence)
            .map_err(|_| TransportError::SessionFenced)
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
    /// here). The computed one-shot join gate is projected into the receipt,
    /// and the composition-retained join table holds the one-shot
    /// consumption across calls, so an exact same-delivery replay answers
    /// spent state instead of relaunching the guest.
    #[allow(
        clippy::too_many_lines,
        reason = "the admitted-path bundle publication keeps decode, fence/ready/claim/snapshot gates, host re-hash, publish, demand-start, and receipt projection in one audited order"
    )]
    async fn wasm_dispatch_bundle_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
        context: &tracing::Span,
        subordinate_terminal_emitted: &mut bool,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: WasmDispatchBundleOperation =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
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
        self.admit_material_authority_for_governor_issued_fence(
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
        // Publisher concurrency (#2786 step 4): sessions run as `JoinSet`
        // tasks on the multi-threaded `#[tokio::main]` runtime, so two
        // `publish_wasm_dispatch_bundle` calls can interleave on different
        // threads — no single-publisher ownership is claimed. The
        // publisher serializes replacements only through the live-envelope
        // gate (claim-by-rename plus per-step re-verification), not a
        // lock; the residual per-file window is stated at the reclaim.
        let mut joins = eliot_kernel_service::WasmJoinTable::default();
        let bundle = match eliot_kernel_service::publish_wasm_dispatch_bundle(
            host_executable_path.as_str(),
            host_artifact_digest.as_str(),
            install_dir,
            &claim,
            &mut joins,
        ) {
            Ok(bundle) => bundle,
            // Typed bounded backpressure (#2786 step 4): another live
            // delivery owns the fixed names, so this publication is
            // refused without touching a byte. The exact retry condition
            // is retained in the response, never collapsed into a fence.
            Err(eliot_kernel_service::WasmDispatchError::Backpressure(live)) => {
                // Issue #1679 (caller STITCH): the versioned I14 directive
                // rides alongside the typed backpressure kind/value, never
                // replacing them. The observation is whole-or-null — `null`
                // while the publishing owner supplies no complete directive.
                let directive = wasm_dispatch_backpressure_directive(claim.operation_id.as_str());
                return Ok(serde_json::json!({
                    "kind": "wasm_dispatch_backpressure",
                    "value": {
                        "live_generation": live.live_generation,
                        "live_operation_id": live.live_operation_id,
                        "live_expires_at": live.live_expires_at,
                        "retry_condition": live.retry_condition,
                    },
                    "recovery": {
                        "backpressure_directive": directive,
                    },
                }));
            }
            Err(_) => return Err(TransportError::SessionFenced),
        };
        // Launch-gate admission (#2786 steps 3 and 8): the staged bundle
        // executes only against its matching owner join/grant. The local
        // table above stays publish scratch (file staging never runs under
        // the retained lock); the published bundle merges into the
        // composition-retained join table and admits under one short lock
        // holding no file I/O and never crossing an await, so concurrent
        // same-delivery calls linearize here: the first consumes the
        // one-shot admission and any exact replay observes the spent
        // record. Expiry is re-verified at launch instant (closing the
        // validation-to-start window), so this is a real expiry gate
        // (`Stale` can fire here). A failed launch stays consumed — an
        // unknown outcome reconciles, it is never blindly retried under
        // the same delivery — and recovery resubmits under fresh claim
        // authority (#2786 A7). Anything else fails closed before the
        // child starts.
        let admission = {
            let mut retained = self
                .wasm_join_table
                .lock()
                .map_err(|_| TransportError::SessionFenced)?;
            let now_ms = unix_ms();
            retained.prune(now_ms);
            retained.register_delivery(&bundle.join, &bundle.delivery);
            retained.admit_claim(
                bundle.material.claim_id.as_str(),
                bundle.material.operation_id.as_str(),
                bundle.join.invocation_digest.as_str(),
                bundle.delivery.envelope_digest.as_str(),
                now_ms,
            )
        };
        match admission {
            Ok(()) => {}
            // Same-delivery replay (#2786 step 3): the retained spent
            // record stands and no second guest effect starts. The caller
            // receives the exact spent identity, never a fresh launch.
            Err(eliot_kernel_service::JoinDeny::Replayed) => {
                return Ok(serde_json::json!({
                    "kind": "wasm_dispatch_replay",
                    "value": {
                        "claim_id": bundle.material.claim_id,
                        "operation_id": bundle.material.operation_id,
                        "expires_at": bundle.join.expires_at,
                        "retry_condition": "resubmit under fresh claim authority",
                    },
                }));
            }
            Err(_) => return Err(TransportError::SessionFenced),
        }
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
                context,
                subordinate_terminal_emitted,
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
        context: &tracing::Span,
        subordinate_terminal_emitted: &mut bool,
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
        let outer_binding = self
            .admit_material_process_start(&admission)
            .map_err(|_| TransportError::SessionFenced)?;
        let proof = self
            .retain_process_path_proof(&admission)
            .map_err(|_| TransportError::SessionFenced)?;
        gateway
            .start_in_context(&owner, admission, proof, outer_binding, context)
            .await
            .map_err(|_| {
                *subordinate_terminal_emitted = true;
                TransportError::SessionFenced
            })
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
        _context: &tracing::Span,
        _subordinate_terminal_emitted: &mut bool,
    ) -> Result<ProcessStartReceipt, TransportError> {
        Err(TransportError::SessionFenced)
    }

    /// Publishes one graceful owner control for a decided WASM-host
    /// operation (`#2896`): the production Kernel call behind one
    /// external Cancel/Reconcile/Shutdown delivery, reached per kind
    /// from [`Self::publish_wasm_host_control_sequence`] after the
    /// origin grant issues and before the gateway kill lands.
    ///
    /// The publisher authenticates through the existing process/control
    /// owner contract, never through path correlation alone: the image
    /// path is the executor-observed physical binding already matched
    /// against the inspected running process, the install directory is
    /// that path's parent, and every delivery identity re-binds the
    /// staged dispatch material this daemon published (claim, operation,
    /// generation, grant, work scope), the live session (epoch, fence,
    /// principal, connection), and the origin grant funding the decision
    /// (challenge, operation class, decision time). The running image
    /// bytes re-hash to the staged grant digest — the same fail-closed
    /// contour as launch — and the child-sealed request digest is never
    /// minted here; the child cross-checks the operation/invocation/grant
    /// triple against its own sealed binding.
    ///
    /// A foreign image answers `Foreign` with the decide response
    /// unchanged. A WASM-host image whose delivery set is absent,
    /// oversize, malformed, or disagreeing answers `NotStaged` with an
    /// honest reason while the kill proceeds. A bound operation stages
    /// through [`eliot_kernel_service::publish_wasm_control_delivery`]:
    /// same-kind retries re-offer the retained identity, and any staging
    /// or retention fault fails the decision closed before the kill.
    fn publish_wasm_host_control(
        session: &Session,
        owner: &ProcessOwnerBinding,
        operation_id: &OperationId,
        request: &OriginChallengeRequest,
        grant: &OriginControlGrant,
        control_kind: eliot_kernel_service::WasmControlKind,
    ) -> Result<WasmHostControlOutcome, TransportError> {
        let image_path = std::path::Path::new(request.physical().image_path());
        if !image_path.is_absolute()
            || image_path.file_name().and_then(|name| name.to_str())
                != Some(WASM_HOST_IMAGE_FILE_NAME)
        {
            return Ok(WasmHostControlOutcome::Foreign);
        }
        let install_dir = image_path.parent().ok_or(TransportError::SessionFenced)?;
        // Owner readback of the staged dispatch material: the delivery
        // set is consumed only at loop end, so a running operation still
        // stages it. Anything else marks not-staged honestly; no binding
        // is ever inferred from the image path alone.
        let material_path = install_dir.join(eliot_kernel_service::WASM_HOST_MATERIAL_FILE_NAME);
        let Ok(material_bytes) = std::fs::read(&material_path) else {
            return Ok(WasmHostControlOutcome::NotStaged {
                reason: "delivery-set-absent",
            });
        };
        if material_bytes.len() > eliot_protocol::MAX_FRAME_BYTES {
            return Ok(WasmHostControlOutcome::NotStaged {
                reason: "delivery-set-oversize",
            });
        }
        let material: eliot_kernel_service::WasmDispatchMaterial =
            match serde_json::from_slice(&material_bytes) {
                Ok(material) => material,
                Err(_) => {
                    return Ok(WasmHostControlOutcome::NotStaged {
                        reason: "delivery-set-malformed",
                    });
                }
            };
        if material.operation_id != operation_id.as_str() {
            return Ok(WasmHostControlOutcome::NotStaged {
                reason: "operation-mismatch",
            });
        }
        if material.generation != request.generation().get() {
            return Ok(WasmHostControlOutcome::NotStaged {
                reason: "generation-mismatch",
            });
        }
        if !material
            .authority_epoch
            .is_same_authority(&session.authority_epoch)
        {
            return Ok(WasmHostControlOutcome::NotStaged {
                reason: "epoch-mismatch",
            });
        }
        let Ok(observed_image) = std::fs::read(image_path) else {
            return Ok(WasmHostControlOutcome::NotStaged {
                reason: "image-unreadable",
            });
        };
        if sha256_hex(&observed_image) != material.grant.host_artifact_digest {
            return Ok(WasmHostControlOutcome::NotStaged {
                reason: "image-diverged",
            });
        }
        let inputs = eliot_kernel_service::WasmControlPublishInputs {
            install_dir: install_dir.to_path_buf(),
            operation_id: operation_id.as_str().to_owned(),
            claim_id: material.claim_id.clone(),
            generation: material.generation,
            control_kind,
            authority_epoch: session.authority_epoch.clone(),
            state_fence: session.module_generation.state_fence.clone(),
            work_scope: material.work.work_scope.clone(),
            principal_digest: owner.principal_digest().to_owned(),
            session_connection: session.connection_id.clone(),
            session_epoch: session.session_epoch,
            dispatch_grant_digest: material.grant.grant_digest.clone(),
            publisher_challenge_id: grant.challenge_id().to_owned(),
            publisher_operation: grant.operation().operation_label().to_owned(),
            publisher_grant_digest: grant.grant_digest().to_owned(),
            decided_at_unix_ms: grant.decided_at_unix_ms(),
            now_unix_ms: unix_ms(),
        };
        let receipt = eliot_kernel_service::publish_wasm_control_delivery(&inputs)
            .map_err(|_| TransportError::SessionFenced)?;
        Ok(WasmHostControlOutcome::Published {
            receipts: vec![receipt],
            install_dir: install_dir.to_path_buf(),
        })
    }

    /// Publishes the ordered graceful owner-control ladder for a
    /// decided WASM-host operation (`#2896` W1/A1): Reconcile, then
    /// Cancel, then Shutdown — the exact A4 ordered pairs — through
    /// the existing owner spool before the gateway kill lands.
    ///
    /// The origin-control Kill decision is the sole production trigger
    /// that binds the exact running WASM operation (inspected
    /// process, origin grant, live session); it funds the whole
    /// ladder, so the child never mints its own control authority.
    /// Shutdown keeps its terminal position closing admission; Cancel
    /// contains the uncertain outcome first (I2.4 cancellation before
    /// forced termination) and Reconcile resolves it while authority
    /// is still live (the host's own settle-while-live ladder,
    /// mirrored owner-side). Each kind reuses the single
    /// authenticated publisher [`Self::publish_wasm_host_control`],
    /// so same-kind retries re-offer the retained identity and any
    /// staging or retention fault fails the decision closed before
    /// the kill, exactly like the single publish.
    ///
    /// The outcome merge is total: publishes accumulate in owner
    /// order and the first non-published kind short-circuits. When at
    /// least one delivery staged, the ladder reports `Published` with
    /// every staged receipt and the kill proceeds; otherwise the
    /// binding outcome propagates (`Foreign` leaves the response
    /// unchanged, `NotStaged` carries its honest reason and the kill
    /// proceeds).
    fn publish_wasm_host_control_sequence(
        session: &Session,
        owner: &ProcessOwnerBinding,
        operation_id: &OperationId,
        request: &OriginChallengeRequest,
        grant: &OriginControlGrant,
    ) -> Result<WasmHostControlOutcome, TransportError> {
        match Self::publish_wasm_host_control(
            session,
            owner,
            operation_id,
            request,
            grant,
            eliot_kernel_service::WasmControlKind::Reconcile,
        )? {
            WasmHostControlOutcome::Published {
                mut receipts,
                install_dir,
            } => {
                for control_kind in [
                    eliot_kernel_service::WasmControlKind::Cancel,
                    eliot_kernel_service::WasmControlKind::Shutdown,
                ] {
                    match Self::publish_wasm_host_control(
                        session,
                        owner,
                        operation_id,
                        request,
                        grant,
                        control_kind,
                    )? {
                        WasmHostControlOutcome::Published {
                            receipts: staged, ..
                        } => {
                            receipts.extend(staged);
                        }
                        // Partial ladder: an operation that unbinds
                        // mid-sequence keeps every staged delivery; the
                        // kill proceeds and the projection notes each
                        // staged sequence honestly.
                        _ => break,
                    }
                }
                Ok(WasmHostControlOutcome::Published {
                    receipts,
                    install_dir,
                })
            }
            outcome => Ok(outcome),
        }
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
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        validate_store_session_fence(session, &session.module_generation.state_fence)?;
        self.admit_material_authority_for_governor_issued_fence(
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

    /// Binds one fresh, short-lived Operator session token on the admitted path
    /// (`#1777` I11.8): the production caller of
    /// `eliot_kernel_service::bind_operator_session_token`, the minter of the
    /// Kernel challenge/session token the `WinUI` client then presents at
    /// redemption.
    ///
    /// The binding evidence arrives as closed payload evidence from the
    /// requesting User Broker; session evidence is threaded from the live
    /// authenticated session - connection, exact epoch, exact fence - never
    /// from the payload, and the binder re-proves it against live Kernel
    /// admission together with Ready state, unfenced generation, and the exact
    /// epoch/fence currency. The token and its bounded lease are derived here
    /// from the observed authority triple, so this composition root never mints
    /// one itself.
    ///
    /// The grant binds and echoes the presented peer tuple; it does not claim
    /// that a presented process id owns a channel. The connected-peer proof
    /// belongs to the pipe owner in the broker
    /// (`bins/eliot-user-broker/src/main.rs::serve_operator_pipe_connection`),
    /// which compares this echoed evidence with the OS-observed peer before it
    /// accepts any redemption.
    pub(crate) fn operator_session_token_operation(
        &self,
        session: &Session,
        payload: serde_json::Value,
    ) -> Result<serde_json::Value, TransportError> {
        let operation: OperatorSessionTokenOperation =
            serde_json::from_value(without_daemon_routing_key(payload)?)
                .map_err(|_| TransportError::SessionFenced)?;
        validate_store_session_fence(session, &session.module_generation.state_fence)?;
        self.admit_material_authority_for_governor_issued_fence(
            &session.module_generation.state_fence,
        )
        .map_err(|_| TransportError::SessionFenced)?;
        // Session evidence threaded from the live authenticated session, the
        // same `SessionBinding` projection the notify grant binds with.
        let session_evidence = serde_json::json!({
            "session_id": &session.connection_id,
            "authority_epoch": &session.authority_epoch,
            "state_fence": &session.module_generation.state_fence,
        });
        let session_binding =
            serde_json::from_value(session_evidence).map_err(|_| TransportError::SessionFenced)?;
        let inputs = eliot_kernel_service::OperatorSessionTokenInputs {
            registration_digest: operation.registration_digest,
            handoff_nonce: operation.handoff_nonce,
            windows_sid: operation.windows_sid,
            interactive_session_id: operation.interactive_session_id,
            client_process_id: operation.client_process_id,
            client_image_path: operation.client_image_path,
            role: operation.role,
            capabilities: operation.capabilities,
            session: session_binding,
        };
        let service = self
            .service
            .lock()
            .map_err(|_| TransportError::SessionFenced)?;
        let authorization = eliot_kernel_service::bind_operator_session_token(&service, &inputs)
            .map_err(|_| TransportError::SessionFenced)?;
        let bound = authorization.inputs();
        Ok(serde_json::json!({
            "kind": "operator_session_token",
            "value": {
                "operation_id": authorization.operation_id(),
                "token": authorization.token(),
                "issued_at_unix_ms": authorization.issued_at_unix_ms(),
                "expires_at_unix_ms": authorization.expires_at_unix_ms(),
                "generation": authorization.generation().value(),
                "authority_epoch": authorization.authority_epoch(),
                "state_fence": authorization.state_fence(),
                "registration_digest": &bound.registration_digest,
                "handoff_nonce": &bound.handoff_nonce,
                "windows_sid": &bound.windows_sid,
                "interactive_session_id": &bound.interactive_session_id,
                "client_process_id": &bound.client_process_id,
                "client_image_path": &bound.client_image_path,
                "role": &bound.role,
                "capabilities": &bound.capabilities,
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
            .await?
            .map_err(|_| TransportError::SessionFenced)?;
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
    pub(crate) fn retained_store_gateway(&self) -> Result<Arc<KernelStoreGateway>, TransportError> {
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

    /// Returns the typed refusal when the ordered startup gate has not yet
    /// reported front-door readiness, so a queued attach is not released
    /// (I1.11 step 10, issue #1892 W5).
    ///
    /// Implements #1892 A3: the named unmet startup prerequisite travels in
    /// `recovery` exactly as the normal-write and Material-authority refusals
    /// report it, and is read from the production [`Self::startup_status`]
    /// surface rather than from a second readiness source. `status` and
    /// `value.kind` keep the existing `agent_activation_claim` response shape,
    /// so a polling daemon parses it unchanged and re-observes readiness on its
    /// next poll instead of learning that a queued ticket was consumed.
    fn queued_attach_release_gate_response(&self, message: &str) -> serde_json::Value {
        let status = self.startup_status(GovernanceProfile::minimal());
        let prerequisite = status
            .blocking_prerequisite
            .unwrap_or("front-door-readiness");
        serde_json::json!({
            "status": "error",
            "value": { "kind": "agent_activation_claim", "value": null },
            "recovery": {
                "prerequisite": prerequisite,
                "message": message,
            },
        })
    }

    /// Returns the typed rejection when the current Governor-issued
    /// Governance Profile has not admitted Material authority for one
    /// origin-control decision.
    ///
    /// Implements #1967 W3/A1: origin-control grants issue authority, so the
    /// decide path consults the single production Material/Critical gate
    /// rather than inferring authority from pipe liveness. Issue #1892 W4
    /// restores the missing half: the gate is
    /// [`Self::admit_material_authority_for_governor_issued_fence`], the same
    /// one every other Material/Critical route uses, and it admits under the
    /// **recorded** Governor derivation for the exact target fence this
    /// decision presents. A compile-time `GovernanceProfile` constant no
    /// longer reaches this path: `current_governor_issued_authority()` is
    /// `None` until a Governor derivation is recorded, and `None` refuses
    /// closed rather than defaulting to a material-grade preset. The named
    /// prerequisite and the recorded ceiling travel in `recovery`;
    /// `status`/`value.kind` keep the existing error shape. The reported
    /// ceiling is the recorded one, and `null` when no derivation is
    /// recorded, because the gate refuses before any ceiling is consulted.
    fn material_authority_admission_response(
        &self,
        target: &StateFence,
    ) -> Option<serde_json::Value> {
        if self
            .admit_material_authority_for_governor_issued_fence(target)
            .is_ok()
        {
            return None;
        }
        let recorded = self
            .startup_coordinator
            .lock()
            .ok()
            .and_then(|coordinator| coordinator.current_governor_issued_authority())
            .map(|issued| issued.profile());
        let status = self.startup_status(GovernanceProfile::minimal());
        // An incomplete mandatory gate keeps the existing fixed startup
        // vocabulary. With every mandatory gate complete the blocking
        // prerequisite is the current Governor-derived profile, which
        // [`StartupCoordinator::admit_governor_issued_authority`] itself
        // names as the I1.11 step 11 supervision/enforcement prerequisite.
        let prerequisite = status
            .blocking_prerequisite
            .unwrap_or("supervision-evidence");
        let ceiling = recorded.map(|profile| self.startup_authority_ceiling(profile));
        Some(serde_json::json!({
            "status": "error",
            "value": { "kind": "origin_control_decide", "value": null },
            "recovery": {
                "prerequisite": prerequisite,
                "authority_ceiling": ceiling.as_ref().map(|ceiling| ceiling.as_str()),
            },
        }))
    }

    /// Store apply is the production Material/Critical admission boundary.
    /// It keeps the existing helper seam used by the package-local gate proof,
    /// but now requires the recorded Governor-issued projection plus the
    /// owner-backed current Watchdog observation before the retained Store
    /// gateway can be entered.
    ///
    /// The answer uses the daemon's `error` wire variant. A refusal must be
    /// decodable by the client: an unrecognised `status` would be surfaced as an
    /// unknown transport outcome, which is exactly the ambiguity this
    /// fail-closed path exists to avoid.
    fn material_write_admission_response(&self, target: &StateFence) -> Option<serde_json::Value> {
        self.admit_material_authority_for_governor_issued_fence(target)
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

    /// Renders one typed I6.8 pre-stage rejection (issue #1796) as the
    /// `write_receipt` error response. The full typed record — stage state,
    /// ordering flag, decision, defect codes, mutation status, and retry rule
    /// — travels in `recovery` so the client can distinguish schema-invalid,
    /// identity-conflict, and staged outcomes without parsing prose.
    #[cfg(windows)]
    fn pre_stage_rejection_response(rejection: &PreStageRejection) -> serde_json::Value {
        serde_json::json!({
            "status": "error",
            "value": { "kind": "write_receipt", "value": null },
            "recovery": {
                "pre_stage_rejection": rejection,
            },
        })
    }

    /// Renders one refused Store `apply` as the operation's error response.
    ///
    /// A typed I5.19 admission decision is the one refusal that carries
    /// evidence rather than prose, so the full typed `WriteSubmission` —
    /// submission id, state, reason codes, retry-identity rule, and next
    /// allowed action — travels in `recovery` exactly as the I6.8
    /// [`Self::pre_stage_rejection_response`] record does. That is what lets a
    /// client tell a `not_accepted` submission from any other failure without
    /// parsing the operator line, and it is I5.19 line 21: a syntax/shape
    /// refusal is an operational response, so it is reported as one.
    ///
    /// Every other refusal is handed to [`Self::store_error_response_text`]
    /// with its preserved text, so no other route's response changes.
    #[cfg(windows)]
    fn store_apply_refusal_response(kind: &str, error: &StoreApplyRefusal) -> serde_json::Value {
        match error.admission_decision() {
            Some(submission) => serde_json::json!({
                "status": "error",
                "value": { "kind": kind, "value": null },
                "recovery": {
                    "write_submission": submission,
                },
            }),
            None => Self::store_error_response_text(kind, &error.to_string()),
        }
    }

    /// Renders one refused pre-call durable staging attempt as the operation's
    /// error response (issue #1681 W4, I5.6, I14.4; issue #1679 A9-1).
    ///
    /// This refusal is reached only BEFORE any possible Store call: the ORS
    /// reservation above is the durable intent record that must precede every
    /// canonical send on this route, so its failure means the complete opaque
    /// operation was not durably staged. `I5.2` therefore forbids
    /// `ACCEPTED_PENDING` here, and this response does not claim it: it reports
    /// `STORAGE_BACKPRESSURE` (the `I14.4` name for "no durable staging was
    /// available") and carries no stage receipt, no poll handle, and no
    /// resubmission instruction, because nothing was staged to poll.
    ///
    /// The complete versioned #1679 directive travels whole in
    /// `recovery.staging_directive`: cause, ORS durable-bytes bottleneck,
    /// commit status, preserved state and evidence, forbidden actions, the
    /// preserved operation identity, the authorized bounded fallback, the next
    /// action, authority, escalation, and the profile revision. Nothing is
    /// dropped, and a directive that fails the existing contract check is
    /// never partially emitted: the answer keeps the same error status and
    /// code with a `null` directive rather than a half-populated one.
    ///
    /// The exact admitted operation identity is preserved verbatim so the caller
    /// retries THIS operation rather than a fresh one, and the ORS refusal text
    /// is carried through unchanged instead of being replaced with a generic
    /// error string. It is not read from the absence of a receipt: this arm is
    /// entered only on a real `reserve_campaign_source_publications` error, so
    /// the durable staging attempt is known to have failed rather than inferred
    /// from a later check being absent.
    #[cfg(windows)]
    fn store_staging_refusal_response(
        kind: &str,
        operation_id: &str,
        refusal: &str,
    ) -> serde_json::Value {
        let directive = store_staging_backpressure_directive(operation_id);
        serde_json::json!({
            "status": "error",
            "code": "STORAGE_BACKPRESSURE",
            "reason": refusal,
            "value": { "kind": kind, "value": null },
            "recovery": { "staging_directive": directive },
        })
    }

    /// Renders one refused canonical read as the truthful `DB_UNAVAILABLE`
    /// answer (issue #1681 W3, I14.11, I14.5).
    ///
    /// The `Store` cause is read off the typed [`NamedReadGatewayError`] arm, so
    /// the closed `DB_UNAVAILABLE` disposition follows from the enum variant the
    /// Store API returned rather than from matching rendered text. The complete
    /// versioned #1679 directive travels whole in `recovery`: commit status,
    /// preserved state and evidence, forbidden actions, retry-versus-poll, the
    /// preserved operation identity, the authorized bounded fallback, the next
    /// action, and the escalation boundary. Nothing is dropped, and a directive
    /// that fails the existing contract check is never partially emitted: the
    /// answer keeps the same error status and code with a `null` directive rather
    /// than a half-populated one.
    ///
    /// The read itself is never re-read, re-executed, or served from cache on
    /// this path, and the answer carries no payload: an unavailable canonical
    /// Store yields no result rather than an empty or stale one.
    #[cfg(windows)]
    fn store_read_failure_response(
        kind: &str,
        state_fence: &StateFence,
        operation_id: Option<&str>,
        error: &NamedReadGatewayError,
    ) -> serde_json::Value {
        let NamedReadGatewayError::Store(StoreError::Unavailable) = error else {
            return Self::store_error_response_text(kind, &error.to_string());
        };
        let directive = store_read_unavailable_directive(state_fence, operation_id);
        serde_json::json!({
            "status": "error",
            "code": "DB_UNAVAILABLE",
            "reason": "Canonical Store is unavailable; named read was not completed.",
            "value": { "kind": kind, "value": null },
            "recovery": { "read_directive": directive },
        })
    }
}

/// Builds the complete versioned I14.5 directive for one unavailable read, or
/// `None` when the owner refuses to produce a valid one.
///
/// `operation_id` is the exact handle the admitted read already carries, so the
/// directive preserves and the caller retries THAT read rather than a fresh one.
/// A caller that holds no admitted read handle passes `None` and the directive
/// reports that absence honestly instead of minting an identity for work that
/// was never admitted.
#[cfg(windows)]
fn store_read_unavailable_directive(
    state_fence: &StateFence,
    operation_id: Option<&str>,
) -> Option<serde_json::Value> {
    // `eliot_contracts::OperationId` is the I14.5 directive's operation identity
    // and is distinct from this module's process-lane `OperationId` import.
    let operation_id =
        operation_id.map(|handle| eliot_contracts::OperationId::new(handle.to_owned()));
    let operation_id = match operation_id {
        Some(Err(_)) => return None,
        Some(Ok(operation_id)) => Some(operation_id),
        None => None,
    };
    let profile_revision = eliot_kernel_service::store_read_profile_revision().ok()?;
    eliot_kernel_service::store_read_unavailable_response(
        state_fence,
        operation_id.as_ref(),
        &profile_revision,
    )
    .ok()
    .and_then(|directive| serde_json::to_value(directive).ok())
}

/// Builds the complete versioned I14.5 directive for one refused durable
/// staging attempt, or `None` when the owner refuses to produce a valid one.
///
/// `operation_id` is the exact handle the admitted write already carries, so
/// the directive preserves and the caller retries THAT operation rather than
/// a fresh one.
///
/// Issue #1679 A9-1 (caller STITCH): the remaining directive inputs are
/// genuinely unavailable at this call site, so this helper emits `None`
/// rather than a partial directive. `reserve_campaign_source_publications`
/// fails with a prose `OrsError` that carries no owner-measured ORS durable
/// queue reading — neither the requested staging bytes nor the available
/// bytes the `STORAGE_BACKPRESSURE` contract requires — and that failure may
/// be a CAS identity conflict, contract rejection, or storage fault
/// rather than measured byte exhaustion, so minting an exhausted-bytes
/// observation here would fabricate capacity evidence. There is likewise no
/// owner-produced staging-profile artifact at this call site (the existing
/// `store_read_profile_revision` names the read-profile catalogue and must
/// not be relabeled as staging provenance). The ORS reserve owner is the
/// party that can supply both; until that owner call site exists, the answer
/// keeps its error status and code with a `null` directive.
#[cfg(windows)]
fn store_staging_backpressure_directive(operation_id: &str) -> Option<serde_json::Value> {
    // `eliot_contracts::OperationId` is the I14.5 directive's operation identity
    // and is distinct from this module's process-lane `OperationId` import.
    // The admitted identity is available and well formed here, but the
    // owner-measured byte pressure and staging profile revision above are
    // not, so the directive is honestly null rather than partial.
    let _operation_id = eliot_contracts::OperationId::new(operation_id.to_owned()).ok()?;
    None
}

/// Builds the complete versioned I14 directive for one backpressured WASM
/// dispatch publication, or `None` when the owner refuses to produce a valid one.
///
/// `operation_id` is the exact handle the admitted publication already
/// carries, so the directive preserves and the caller retries THAT operation
/// rather than a fresh one.
///
/// Issue #1679 (caller STITCH): the remaining directive inputs are genuinely
/// unavailable at this call site, so this helper emits `None` rather than a
/// partial directive. The typed [`WasmDeliveryBackpressure`] the
/// `WasmDispatchError::Backpressure` arm carries names the live delivery
/// holding the fixed names plus a prose retry condition — identities only,
/// never an owner-measured exhausted bottleneck dimension — and this edge
/// owns no capacity-profile revision artifact or state fence to bind. A BUSY
/// directive validates only with a claimed, observed exhausted dimension plus
/// the owner-produced compiled profile revision, so naming one here would
/// fabricate capacity evidence the publish path never observed. The WASM
/// dispatch owner is the party that can supply both; until that owner call
/// site exists, the answer keeps its kind and value with a `null` directive.
///
/// [`WasmDeliveryBackpressure`]: eliot_kernel_service::WasmDeliveryBackpressure
fn wasm_dispatch_backpressure_directive(operation_id: &str) -> Option<serde_json::Value> {
    // `eliot_contracts::OperationId` is the I14 directive's operation identity
    // and is distinct from this module's process-lane `OperationId` import.
    // The admitted identity is available and well formed here, but the
    // owner-measured capacity pressure and dispatch profile revision above are
    // not, so the directive is honestly null rather than partial.
    let _operation_id = eliot_contracts::OperationId::new(operation_id.to_owned()).ok()?;
    None
}

/// Closed outcome of the graceful WASM control half of one
/// origin-control decision (`#2896`).
enum WasmHostControlOutcome {
    /// The decided image is not a WASM host: plain gateway kill with
    /// the decide response unchanged.
    Foreign,
    /// A WASM-host image whose delivery set cannot bind a control.
    /// The kill proceeds; the response carries the honest marker.
    NotStaged {
        /// Stable reason code (never a path or digest).
        reason: &'static str,
    },
    /// Versioned controls were offered through the owner spool: a
    /// full Reconcile/Cancel/Shutdown ladder, or the staged prefix
    /// when the operation unbound mid-sequence.
    Published {
        /// Staged delivery receipts in owner-sequence order (non-empty).
        receipts: Vec<eliot_kernel_service::WasmControlPublishReceipt>,
        /// Spool root the deliveries staged into.
        install_dir: std::path::PathBuf,
    },
}

/// Projects the post-kill control status for the published WASM
/// control ladder (`#2896` item 12): the supervised-termination note
/// lands per staged delivery (a decisive ack still wins over `Unknown`
/// on each), then a fresh spool reconcile reports every retained
/// delivery and its terminal-or-open disposition.
///
/// Never fails the decide response: the kill receipt is authoritative,
/// so a spool fault degrades to an honest `unrecorded` marker instead
/// of losing the receipt.
fn wasm_host_control_projection(
    install_dir: &std::path::Path,
    receipts: &[eliot_kernel_service::WasmControlPublishReceipt],
) -> serde_json::Value {
    let Some(head) = receipts.first() else {
        return serde_json::json!({"staged": false, "reason": "ladder-empty"});
    };
    let now = unix_ms();
    let mut noted = true;
    for receipt in receipts {
        noted &= eliot_kernel_service::note_wasm_control_supervised_end(
            install_dir,
            receipt.operation_id.as_str(),
            receipt.generation,
            receipt.owner_sequence,
            "origin-kill-acknowledged",
            now,
        )
        .is_ok();
    }
    let spool = eliot_kernel_service::reconcile_wasm_control_spool(
        install_dir,
        head.operation_id.as_str(),
        head.generation,
        now,
    );
    let (spool_value, spool_ok) = match spool {
        Ok(status) => (
            serde_json::to_value(status).unwrap_or(serde_json::Value::Null),
            true,
        ),
        Err(_) => (serde_json::Value::Null, false),
    };
    let mut control = serde_json::json!({
        "staged": true,
        "publishes": receipts,
        "spool": spool_value,
    });
    if (!noted || !spool_ok)
        && let Some(object) = control.as_object_mut()
    {
        if !noted {
            object.insert(
                "termination_note".to_owned(),
                serde_json::json!("unrecorded"),
            );
        }
        if !spool_ok {
            object.insert("spool_note".to_owned(), serde_json::json!("unrecorded"));
        }
    }
    control
}

#[cfg(windows)]
fn authenticated_user_automation_principal(session: &Session) -> Result<String, TransportError> {
    match &session.peer {
        PeerIdentity::Authenticated { user_identity, .. }
            if !user_identity.trim().is_empty() && !user_identity.chars().any(char::is_control) =>
        {
            Ok(user_identity.clone())
        }
        PeerIdentity::Authenticated { .. } | PeerIdentity::Unavailable { .. } => {
            Err(TransportError::PeerIdentityUnavailable)
        }
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

/// Closed outcome of the post-disposition horizon advance one due-wake
/// occurrence owns (issue #2806 item 6).
///
/// The arms are three different facts, and the wire keeps them apart. `Answered`
/// is one real owner round-trip and carries that owner's own
/// [`UserAutomationHorizonPhase`]. `Exhausted` is a complete answer about the
/// revision itself: the consumed occurrence is the last member of the immutable
/// revision's normalized denominator, so no next slice exists and no owner is
/// asked. `Unresolved` is the refusal to compose either, because a resolution
/// whose own revision does not compile its denominator cannot name the exact
/// remainder at all.
///
/// Folding the last two into `UserAutomationHorizonOutcome::Unavailable` would
/// make a finished horizon a claim that the schedule owner was not reachable,
/// which is a false claim about the owner rather than a disposition, and it is
/// why the two non-answer arms exist here instead of inside that closed
/// vocabulary. `Exhausted` is a settled answer and therefore owes the caller no
/// recovery; `Unresolved` owes one and says so.
#[cfg(windows)]
enum UserAutomationHorizonAdvance {
    /// The schedule owner answered one bounded slice request.
    ///
    /// The phase and the obligation travel together because neither identifies
    /// the publication on its own. The phase names WHAT is still owed; the
    /// obligation names the durable record that was written for it, under the
    /// ORIGINAL owner operation identity the record is issued and reconciled
    /// under. A later attempt of the same parent operation resumes that record
    /// instead of publishing the slice again, so a response that reported only
    /// the phase would name a remaining set with no record to resume from.
    Answered {
        /// The schedule owner's own horizon phase, or the refusal projection
        /// this contour composes when no such answer arrived.
        ///
        /// Boxed so the closed advance stays a value this contour can hold, move
        /// and return the way the other two arms are, instead of making every
        /// `Answered` move carry the whole compiled phase inline while
        /// `Exhausted` and `Unresolved` carry almost nothing. The box is an
        /// allocation detail only: `Box<T>` serializes and deserializes exactly
        /// as `T`, so the reported `horizon` value is byte-identical, and this
        /// enum derives no schema of its own - the phase is projected into
        /// `serde_json::json!` by reference, through
        /// [`Self::user_automation_horizon_value`], so no wire output moves.
        phase: Box<UserAutomationHorizonPhase>,
        /// The retained obligation, or `None` when this answer was reached before
        /// anything was retained and therefore wrote no record.
        obligation: Option<UserAutomationRuntimeObligation>,
    },
    /// The resolved revision's complete normalized denominator is consumed at
    /// this occurrence, so this advance owns no wake-horizon obligation.
    Exhausted,
    /// Neither a slice nor its completeness could be established, and the exact
    /// remaining occurrence set could not be named.
    Unresolved {
        /// Closed reason the horizon could not be composed at all.
        reason: String,
    },
}

/// The owner-proven resolution of exactly one due authenticated wake.
///
/// A due wake is proved once, in two steps no later step repeats:
/// `revalidate_user_automation_due_wake` resolves the carrier against the
/// canonical revision the Store owner currently retains, and
/// `user_automation_due_wake_readback` proves the schedule owner still offers
/// this occurrence as a pending wake. Everything downstream of that proof - the
/// horizon advance, the execution join and both response projections - reads
/// the same facts about the same occurrence, and spelling them out as five
/// trailing parameters on each of those steps is what pushed three of them past
/// the arity the compiler accepts. Binding them once names the thing they
/// already are rather than inventing a carrier for them.
///
/// `session` and `client` are part of the proof and not ambient context: the
/// State Fence in `session` is the fence the resolution and the readback were
/// read at, and `client` is the already-authenticated Host channel the two
/// owners answered on. A step handed a resolution without them could name a
/// different fence, or ask a different channel, than the one that proved it.
///
/// `occurrence_id` is the occurrence re-derived from the resolved revision's
/// own normalized denominator and proved against the owner's journal. It is
/// carried rather than re-derived because re-deriving it per step would be a
/// second derivation of an identity the contour has already fixed, and every
/// step here reports that exact id as the occurrence the answer is about.
#[cfg(windows)]
struct UserAutomationProvenDueWake<'a> {
    /// Authenticated session both proofs were read under.
    session: &'a Session,
    /// Exact occurrence the schedule owner still offers as a pending wake.
    occurrence_id: &'a str,
    /// Authenticated Host execution channel bound to the current State Fence.
    client:
        &'a UserAutomationHostExecutionClient<AuthenticatedUserAutomationHostExecutionTransport>,
    /// The admitted due-wake carrier this occurrence was proved from.
    request: &'a UserAutomationRuntimeAdmission,
    /// The owner-proven resolution of that carrier against the canonical revision.
    resolution: &'a UserAutomationDueWakeResolution,
    /// The schedule owner's own retained record read back for this occurrence.
    readback: &'a UserAutomationWakeReadback,
}

/// The decided disposition one terminal due-wake occurrence reports.
///
/// The disposition name and the owner-issued reason that accompanies it are one
/// value rather than two arguments because neither is meaningful apart from the
/// other: the reason is the owner's own explanation of that name and of no
/// other, so a signature accepting them separately would permit a caller to
/// pair a name with the reason belonging to a different disposition. Binding
/// them into one value also keeps the closed pair inside this module's private
/// vocabulary instead of leaving it spelled as two trailing parameters that
/// widen the arity of every step reporting a decided disposition.
///
/// The decided arm deliberately does not carry the whole
/// `UserAutomationRuntimeError` it replaced: a disposition reached here is
/// always owner-acknowledged, so the variants expressing an unanswered or
/// ambiguous owner cannot be represented, and admitting them again would let an
/// unacknowledged answer reach a projection that reports decided outcomes.
#[cfg(windows)]
struct DecidedDisposition<'a> {
    /// The closed disposition name reported under `outcome`.
    outcome: &'a str,
    /// The owner-issued reason reported under `reason`.
    reason: String,
}

/// Classifies the runtime handoff one closed operator operation owns.
///
/// `Create`, `Resume`, and `Edit` own a bounded recurring horizon publication;
/// `run-now`, `remove`, and `pause` cross into an execution or cancellation
/// owner. A read or a configuration query owns none, so it composes no runtime
/// channel and reports both handoff phases as not applicable instead of implying
/// an absent owner. The I12.24:65 owner decision is in that last group.
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
        // I12.24:65's "decision owner selects reject / investigate / work item
        // / experiment" joins the reads here, and for the same structural
        // reason. It selects one disposition against one brief and owns no
        // wake horizon, because a recurring horizon belongs to a committed
        // automation configuration revision and this operation names none. It
        // publishes nothing, cancels nothing and crosses into no execution
        // owner; I12.24:82 makes the advisory class "default; changes nothing
        // until owner acts" and I12.24:3 states that ELIOT "never silently
        // rewrites code, policy or memory authority", so recording a
        // disposition emits no effect to hand off. `None` is therefore the
        // honest classification, and it keeps the Host contour out of an
        // answer that owes no runtime owner anything.
        eliot_kernel_core::UserAutomationOperation::List { .. }
        | eliot_kernel_core::UserAutomationOperation::Status { .. }
        | eliot_kernel_core::UserAutomationOperation::History { .. }
        | eliot_kernel_core::UserAutomationOperation::InspectLastFailure { .. }
        | eliot_kernel_core::UserAutomationOperation::DecideImprovementBrief { .. } => {
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
    // The packaged operation must equal the envelope operation the live
    // view was just read under: a request packaged for one operation can
    // never be issued or decided under another.
    if request.operation_id() != operation_id {
        return Err(TransportError::SessionFenced);
    }
    // The packaged installation is caller text until it is proven against
    // the Kernel-retained composition identity: a foreign installation
    // fails here, before any challenge is minted or decided. An uncomposed
    // Kernel has no installation identity at all and refuses.
    let live = super::dispatch_contour().map_or(
        "",
        super::dispatch_launch::ComposedDispatchContour::installation_id,
    );
    if live.trim().is_empty() || request.installation_id() != live {
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

/// Projects one ORS process-stream recovery view onto the wire (issue #269).
///
/// Every value is the ORS view's own field, serialized by ORS's own
/// `Serialize` impls, so the Kernel neither re-derives nor reshapes it. `None`
/// stays an explicit `null` rather than an omitted key (I5.16), and the
/// `reports_complete_evidence` flag is ORS's own conjunction over the typed axes
/// that are projected beside it — it is a mechanical restatement, never an
/// independent judgement about the stream.
#[cfg(windows)]
fn process_stream_recovery_stream_view(
    view: &eliot_ors::ProcessStreamRecoveryStatusProjection,
) -> serde_json::Value {
    serde_json::json!({
        "operation_id": view.operation_id,
        "stream": view.stream,
        "transport": view.transport,
        "persistence": view.persistence,
        "availability": view.availability,
        "durable_locator": view.durable_locator,
        "ready_receipt_ref": view.ready_receipt_ref,
        "durable_coverage": view.durable_coverage,
        "gaps": view.gaps,
        "reconciliation": view.reconciliation,
        "activation": view.activation,
        "evidence_scope": view.evidence_scope,
        "reports_complete_evidence": view.reports_complete_evidence(),
    })
}

/// Projects ORS's typed recovery-load disposition without collapsing it.
///
/// The two variants stay distinguishable on the wire, because they call for
/// different actions: a codec-version mismatch means this ORS build must not
/// read the row at all, while an interrupted read means the row itself is not
/// currently readable. Neither becomes a generic code or a bare string.
#[cfg(windows)]
fn process_stream_recovery_load_disposition(
    error: &eliot_ors::ProcessStreamRecoveryLoadError,
) -> serde_json::Value {
    match error {
        eliot_ors::ProcessStreamRecoveryLoadError::CodecVersionMismatch { found, current } => {
            serde_json::json!({
                "kind": "codec_version_mismatch",
                "found_contract_version": found,
                "current_contract_version": current,
            })
        }
        eliot_ors::ProcessStreamRecoveryLoadError::InterruptedRead { reason } => {
            serde_json::json!({
                "kind": "interrupted_read",
                "reason": reason,
            })
        }
    }
}

/// Same-fence Store recovery answer, plus the ORS process-stream recovery view
/// and the ORS staged write recovery view.
///
/// Both extra members are SIBLINGS of `kind`/`value` inside the typed
/// application object, so the retained daemon client's `kind_value` reader —
/// which resolves `kind` then `value` by name — keeps decoding the identical
/// `StoreRecoverySnapshot` it always did. `process_stream_recovery` is explicit
/// `null` when the request selected no operation (I5.16: a field that does not
/// apply stays explicit `None`), never omitted, so the answer shape is stable.
fn store_recovery_response(
    snapshot: &StoreRecoverySnapshot,
    process_stream_recovery: &serde_json::Value,
    staged_write_recovery: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": {
            "kind": "store_recovery",
            "value": snapshot,
            "process_stream_recovery": process_stream_recovery,
            "staged_write_recovery": staged_write_recovery,
        },
        "recovery": null,
    })
}

/// Projects the ORS staged write recovery report for the daemon (issue #1925,
/// I5.2/I5.6).
///
/// Diagnostic projection of owner-validated state only. The staged payload
/// bytes are never read, decoded, or carried here: each envelope appears as the
/// operation identity it was enumerated under, its lifecycle state, and the
/// integrity bindings the owner already validated. The reservation digest is
/// the owner's own scan digest, and `readiness` is the same verdict that gates
/// I1.11 step 6, so an operator reads the gate's actual state rather than a
/// derived claim about it. The `control_*` fields restate the ORS control
/// projection coverage that same digest binds, so a partial obligation scan is
/// visible rather than reported as no obligations.
fn staged_write_recovery_view(
    staged: &eliot_kernel_service::StagedWriteRecovery,
) -> serde_json::Value {
    let reservations = &staged.reservations;
    let envelopes: Vec<serde_json::Value> = staged
        .envelopes
        .iter()
        .map(|envelope| {
            serde_json::json!({
                "operation_id": envelope.operation_id,
                "reservation_order": envelope.reservation_order,
                "state": reservation_state_label(envelope.state),
                "contract_version": envelope.contract_version,
                "payload_kind": envelope.payload_kind,
                "payload_sha256": envelope.payload_sha256,
                "payload_length": envelope.payload_length,
                "authority_epoch": {
                    "lineage_id": envelope.authority_epoch_lineage,
                    "epoch": envelope.authority_epoch_sequence,
                },
                "state_fence_sha256": envelope.state_fence_sha256,
            })
        })
        .collect();
    let problems: Vec<serde_json::Value> = staged
        .problems
        .iter()
        .map(|problem| {
            serde_json::json!({
                "operation_id": problem.operation_id,
                "reservation_order": problem.reservation_order,
                "reason": problem.reason,
            })
        })
        .collect();
    let retained_problems: Vec<serde_json::Value> = staged
        .retained_problems
        .iter()
        .map(|problem| {
            // Bound outside the `json!` literal: the macro would otherwise wrap
            // each accessor in a redundant closure.
            let operation_id = problem.operation_or_checkpoint_id.as_str();
            let reservation_id = problem
                .reservation_id
                .as_ref()
                .map(eliot_ors::OpaqueLabel::as_str);
            let detail = problem.detail.as_str();
            let recovery_owner = problem.recovery_owner.as_str();
            serde_json::json!({
                "operation_id": operation_id,
                "reservation_id": reservation_id,
                "kind": recovery_problem_kind_label(problem.kind),
                "detail": detail,
                "payload_sha256": problem.payload_sha256,
                "envelope_sha256": problem.envelope_sha256,
                "recovery_owner": recovery_owner,
                "resolved": problem.is_resolved(),
            })
        })
        .collect();
    serde_json::json!({
        "scan_source": reservations.scan_source,
        "fence": reservations.fence,
        "digest": reservations.digest,
        "scanned": reservations.scanned,
        "scan_limit": reservations.scan_limit,
        "cursor_start_after_order": reservations.cursor_start_after_order,
        "last_reservation_order": reservations.last_reservation_order,
        "next_after_order": reservations.next_after_order,
        "truncated": reservations.truncated,
        "control_scan_source": reservations.control_scan_source,
        "control_scanned": reservations.control_scanned,
        "control_cursor_start_after_order": reservations.control_cursor_start_after_order,
        "control_next_after_order": reservations.control_next_after_order,
        "control_truncated": reservations.control_truncated,
        "job_checkpoint_refs": reservations.job_checkpoint_refs,
        "delivery_cursor_refs": reservations.delivery_cursor_refs,
        "recovery_inbox_refs": reservations.recovery_inbox_refs,
        "pending": reservations.pending.iter().map(startup_pending_view).collect::<Vec<_>>(),
        "unknown": reservations.unknown.iter().map(startup_unknown_view).collect::<Vec<_>>(),
        "envelopes": envelopes,
        "envelope_problems": problems,
        "retained_problems": retained_problems,
        "readiness": match staged.readiness() {
            eliot_kernel_service::StagedWriteReadiness::Ready => "ready",
            eliot_kernel_service::StagedWriteReadiness::Blocked => "blocked",
        },
    })
}

/// Fixed lifecycle label for one recovered reservation state.
fn reservation_state_label(state: eliot_ors::ReservationState) -> &'static str {
    match state {
        eliot_ors::ReservationState::Reserved => "reserved",
        eliot_ors::ReservationState::Eligible => "eligible",
        eliot_ors::ReservationState::Executing => "executing",
        eliot_ors::ReservationState::Reconciling => "reconciling",
        eliot_ors::ReservationState::Finalized => "finalized",
        eliot_ors::ReservationState::Released => "released",
    }
}

/// Fixed label for one durable Recovery Problem kind.
fn recovery_problem_kind_label(kind: eliot_ors::RecoveryProblemKind) -> &'static str {
    match kind {
        eliot_ors::RecoveryProblemKind::HashMismatch => "hash-mismatch",
        eliot_ors::RecoveryProblemKind::EnvelopeIntegrity => "envelope-integrity",
        eliot_ors::RecoveryProblemKind::MissingKey => "missing-key",
        eliot_ors::RecoveryProblemKind::DecryptionFailure => "decryption-failure",
        eliot_ors::RecoveryProblemKind::UnsupportedPreparedTransition => {
            "unsupported-prepared-transition"
        }
    }
}

fn startup_pending_view(
    operation: &eliot_kernel_service::StartupPendingOperation,
) -> serde_json::Value {
    serde_json::json!({
        "operation_id": operation.operation_id,
        "reservation_order": operation.reservation_order,
        "scopes": operation.scopes,
        "state": reservation_state_label(operation.state),
        "recovery_owner": operation.recovery_owner,
        "reason": operation.reason,
    })
}

fn startup_unknown_view(
    operation: &eliot_kernel_service::StartupUnknownOperation,
) -> serde_json::Value {
    serde_json::json!({
        "operation_id": operation.operation_id,
        "reservation_order": operation.reservation_order,
        "scopes": operation.scopes,
        "state": reservation_state_label(operation.state),
        "recovery_owner": operation.recovery_owner,
        "reason": operation.reason,
    })
}

fn store_genesis_response(receipt: &WriteReceipt) -> serde_json::Value {
    serde_json::json!({
        "status": "known",
        "value": { "kind": "store_initialize_genesis", "value": receipt },
        "recovery": null,
    })
}

/// Renders one committed `store.apply` receipt (issue #1796, I6.8).
///
/// A resubmission the pre-stage gate verified as a correction carries its
/// proven lineage on the response, so the committed write is observably
/// linked to the rejected operation it corrects. Any other write renders
/// exactly the historical shape: lineage is never stamped without the
/// gate's verified link.
///
/// Durable pre-stage journal file (issue #1796 F1) backing the restore and
/// persist helpers below: every retained refusal, so a restart replays the
/// same lineage. The response stays a projection of that record, never a
/// second decision ledger (I06-11:7).
#[cfg(windows)]
const PRE_STAGE_CORRECTION_JOURNAL_FILE: &str = "pre-stage-correction-journal.json";

/// Resolves the durable pre-stage journal path under the daemon work root.
#[cfg(windows)]
fn pre_stage_correction_journal_path(work_root: &std::path::Path) -> std::path::PathBuf {
    work_root
        .join(".eliot")
        .join(PRE_STAGE_CORRECTION_JOURNAL_FILE)
}

/// Serializes publication of the Kernel-owned durable pre-stage journal
/// (issue #1796, audit 5890973032 defect 1): the single publication owner
/// for this journal, separate from the cache's short state lock.
///
/// Held across freshness checking, owned temporary-file creation/write,
/// checked durable replacement, and exact acknowledgement, so a stale saver
/// can never replace newer acknowledged content. The cache mutex is still
/// never held across filesystem I/O: only short state locks are taken while
/// holding this guard. There is exactly one journal, and this is its one
/// publication guard.
#[cfg(windows)]
static PRE_STAGE_JOURNAL_PUBLICATION: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Owned temporary-file sequence for journal publication, mirroring the
/// shutdown-drain staging owner: every save stages a uniquely named file
/// created with `create_new`, so two savers never share one temporary path.
#[cfg(windows)]
static PRE_STAGE_JOURNAL_TEMP_SEQUENCE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Typed outcome of one durable pre-stage journal restore attempt (issue
/// #1796, audit 5890973032 defect 2).
///
/// Distinguishes genuine first-use absence from failed recovery at the caller
/// boundary instead of leaving both as an empty cache.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalRestoreOutcome {
    /// Genuine first-use absent journal or a validated restore: the cache
    /// is the journal.
    Ready,
    /// An existing journal could not be read, decoded, or validated, or the
    /// cache could not be reached: the cache is unrestored and the old
    /// journal must be preserved, never overwritten as fresh state.
    RecoveryRequired,
}

/// Records what one restore attempt proved about the durable pre-stage
/// journal on the cache's explicit readiness state, independently of
/// `is_empty()`, and returns the typed outcome for the caller boundary.
#[cfg(windows)]
fn record_journal_restore(
    cache: &std::sync::Mutex<eliot_kernel_service::PreStageIdentityCache>,
    outcome: JournalRestoreOutcome,
) -> JournalRestoreOutcome {
    let readiness = match outcome {
        JournalRestoreOutcome::Ready => eliot_kernel_service::PreStageJournalReadiness::Ready,
        JournalRestoreOutcome::RecoveryRequired => {
            eliot_kernel_service::PreStageJournalReadiness::RecoveryRequired
        }
    };
    match cache.lock() {
        Ok(mut guard) => {
            guard.set_journal_readiness(readiness);
            outcome
        }
        // The cache cannot even be reached: nothing is proven, so the
        // caller must treat the journal as unrecovered.
        Err(_) => JournalRestoreOutcome::RecoveryRequired,
    }
}

/// Restores retained refusals from the Kernel-owned durable pre-stage
/// journal into a freshly started gate cache (issue #1796 F1).
///
/// A legitimate first-use absent journal restores nothing, which is exactly
/// the pre-journal behavior, and records `Ready`. An existing journal that
/// cannot be read, decoded, or validated records `RecoveryRequired` and
/// leaves the cache unrestored instead of being claimed as an empty cache:
/// it is re-read on the next request while it still holds no live refusal,
/// and until then the gate issues no correction lineage at all rather than
/// stamping an unproven one. A cache that already holds a live refusal is
/// never overwritten by stale disk state. No store, receipt, or envelope
/// format is touched.
#[cfg(windows)]
fn restore_pre_stage_corrections(
    work_root: &std::path::Path,
    cache: &std::sync::Mutex<eliot_kernel_service::PreStageIdentityCache>,
) -> JournalRestoreOutcome {
    // A cache that already reports its posture keeps it: `Ready` needs no
    // re-read, live refusals are never overwritten, and a `RecoveryRequired`
    // cache that still holds no live refusal re-attempts the read below, so
    // a repaired journal heals on the next request.
    if let Ok(guard) = cache.lock() {
        let settled = match guard.journal_readiness() {
            eliot_kernel_service::PreStageJournalReadiness::Ready => true,
            eliot_kernel_service::PreStageJournalReadiness::RecoveryRequired => !guard.is_empty(),
            eliot_kernel_service::PreStageJournalReadiness::Uninitialized => false,
        };
        if settled {
            return match guard.journal_readiness() {
                eliot_kernel_service::PreStageJournalReadiness::Ready => {
                    JournalRestoreOutcome::Ready
                }
                _ => JournalRestoreOutcome::RecoveryRequired,
            };
        }
    } else {
        return JournalRestoreOutcome::RecoveryRequired;
    }
    let bytes = match std::fs::read(pre_stage_correction_journal_path(work_root)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return record_journal_restore(cache, JournalRestoreOutcome::Ready);
        }
        Err(_) => {
            return record_journal_restore(cache, JournalRestoreOutcome::RecoveryRequired);
        }
        Ok(bytes) => bytes,
    };
    let Ok(snapshot) =
        serde_json::from_slice::<eliot_kernel_service::PreStageIdentitySnapshot>(&bytes)
    else {
        return record_journal_restore(cache, JournalRestoreOutcome::RecoveryRequired);
    };
    match cache.lock() {
        Ok(mut guard) => {
            if guard.is_empty() {
                // Validated merge: an inconsistent snapshot is refused
                // without partial mutation, and a successful merge carries
                // the coherent revision baseline, so the cache stays empty
                // for the next attempt on failure and continues the sequence
                // on success.
                if guard.restore(snapshot).is_err() {
                    guard.set_journal_readiness(
                        eliot_kernel_service::PreStageJournalReadiness::RecoveryRequired,
                    );
                    return JournalRestoreOutcome::RecoveryRequired;
                }
                guard.set_journal_readiness(eliot_kernel_service::PreStageJournalReadiness::Ready);
                JournalRestoreOutcome::Ready
            } else {
                // A retain landed while restoring: keep the live refusals
                // and keep whatever posture the retain path already proved.
                match guard.journal_readiness() {
                    eliot_kernel_service::PreStageJournalReadiness::Ready => {
                        JournalRestoreOutcome::Ready
                    }
                    _ => JournalRestoreOutcome::RecoveryRequired,
                }
            }
        }
        Err(_) => JournalRestoreOutcome::RecoveryRequired,
    }
}

/// Typed outcome of one durable pre-stage journal write attempt (issue
/// #1796 AUD2): a file-write attempt is reported, never treated as a
/// persistence acknowledgement.
#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JournalPersistOutcome {
    /// The rename committed and the exact saved revision was acknowledged,
    /// or another saver already made that exact revision durable.
    Persisted,
    /// The snapshot could not be encoded; nothing reached the disk.
    SerializeFailed,
    /// The journal directory could not be prepared; nothing was written.
    JournalDirUnreachable,
    /// The temporary journal file could not be written.
    JournalWriteFailed,
    /// The temporary journal file could not be committed over the journal.
    JournalCommitFailed,
    /// A newer retain landed while this save was in flight; the older save
    /// retired nothing and wrote nothing over the newer state.
    Superseded,
    /// The cache is unrestored (`RecoveryRequired`): the existing journal
    /// is preserved and nothing was written over it as fresh state.
    RecoveryRequired,
}

#[cfg(windows)]
impl JournalPersistOutcome {
    /// Stable report code for the commit response: the local
    /// recovery/persistence failure is reported without claiming durable
    /// lineage, and carries no path or digest.
    fn issue_code(self) -> &'static str {
        match self {
            JournalPersistOutcome::Persisted => "pre_stage_journal_persisted",
            JournalPersistOutcome::SerializeFailed => "pre_stage_journal_serialize_failed",
            JournalPersistOutcome::JournalDirUnreachable => "pre_stage_journal_dir_unreachable",
            JournalPersistOutcome::JournalWriteFailed => "pre_stage_journal_write_failed",
            JournalPersistOutcome::JournalCommitFailed => "pre_stage_journal_commit_failed",
            JournalPersistOutcome::Superseded => "pre_stage_journal_superseded",
            JournalPersistOutcome::RecoveryRequired => "pre_stage_journal_recovery_required",
        }
    }
}

/// Persists retained refusals to the Kernel-owned durable pre-stage journal
/// (issue #1796 F1).
///
/// Called write-ahead of the commit the retain authorizes, so a restart
/// between commit and response still replays the lineage. Best-effort: a
/// failed write keeps the in-memory behavior and never fails the write it
/// records. The pending journal stays pending until its exact revision is
/// acknowledged after the checked durable replacement commits, so a failed
/// save is offered again instead of being forgotten.
///
/// The whole publication serializes under the one journal publication guard:
/// staleness is checked while holding publication ownership, an obsolete
/// save is rejected before replacing the destination, every save stages an
/// owned temporary file, and the exact acknowledgement happens under the
/// same guard. A delayed older saver therefore cannot replace newer
/// acknowledged content, and two savers never share one temporary path. The
/// cache mutex itself is never held across filesystem I/O: only short state
/// locks are taken while holding the publication guard. The checked durable
/// replacement mirrors the shutdown-drain owner: the staged file is synced
/// before the rename, and the replaced destination is synced after it, so a
/// rename alone is never the durability acknowledgement. The tmp-plus-rename
/// keeps a crash from leaving a half-written journal behind.
#[cfg(windows)]
fn persist_pre_stage_corrections(
    work_root: &std::path::Path,
    cache: &std::sync::Mutex<eliot_kernel_service::PreStageIdentityCache>,
    snapshot: &eliot_kernel_service::PreStageIdentitySnapshot,
) -> JournalPersistOutcome {
    let Ok(_publication) = PRE_STAGE_JOURNAL_PUBLICATION.lock() else {
        return JournalPersistOutcome::Superseded;
    };
    let (pending, acked, readiness) = match cache.lock() {
        Ok(guard) => (
            guard.pending_journal_revision(),
            guard.acked_journal_revision(),
            guard.journal_readiness(),
        ),
        Err(_) => return JournalPersistOutcome::Superseded,
    };
    if readiness == eliot_kernel_service::PreStageJournalReadiness::RecoveryRequired {
        // The cache is unrestored: preserve the existing journal and never
        // overwrite it as fresh state.
        return JournalPersistOutcome::RecoveryRequired;
    }
    if pending != Some(snapshot.revision()) {
        if acked >= snapshot.revision() {
            // Another saver already made this exact revision durable while
            // holding publication ownership; there is nothing to replace.
            return JournalPersistOutcome::Persisted;
        }
        return JournalPersistOutcome::Superseded;
    }
    let Ok(bytes) = serde_json::to_vec_pretty(snapshot) else {
        return JournalPersistOutcome::SerializeFailed;
    };
    let path = pre_stage_correction_journal_path(work_root);
    let Some(dir) = path.parent() else {
        return JournalPersistOutcome::JournalDirUnreachable;
    };
    if std::fs::create_dir_all(dir).is_err() {
        return JournalPersistOutcome::JournalDirUnreachable;
    }
    let (tmp, mut tmp_file) = loop {
        let sequence =
            PRE_STAGE_JOURNAL_TEMP_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = dir.join(format!(
            "{}-{}.{}.{sequence}.tmp",
            PRE_STAGE_CORRECTION_JOURNAL_FILE,
            std::process::id(),
            snapshot.revision()
        ));
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
        {
            Ok(file) => break (tmp, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(_) => return JournalPersistOutcome::JournalWriteFailed,
        }
    };
    if std::io::Write::write_all(&mut tmp_file, &bytes)
        .and_then(|()| tmp_file.sync_all())
        .is_err()
    {
        let _ = std::fs::remove_file(&tmp);
        return JournalPersistOutcome::JournalWriteFailed;
    }
    drop(tmp_file);
    if std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return JournalPersistOutcome::JournalCommitFailed;
    }
    if std::fs::File::open(&path)
        .and_then(|file| file.sync_all())
        .is_err()
    {
        return JournalPersistOutcome::JournalCommitFailed;
    }
    let acknowledged = match cache.lock() {
        Ok(mut guard) => guard.acknowledge_journal_save(snapshot.revision()),
        Err(_) => false,
    };
    if acknowledged {
        JournalPersistOutcome::Persisted
    } else {
        JournalPersistOutcome::Superseded
    }
}
fn store_apply_response(
    receipt: &WriteReceipt,
    verified_correction: Option<&eliot_kernel_service::VerifiedCorrectionLink>,
    journal_issue: Option<&str>,
) -> serde_json::Value {
    let mut response = serde_json::json!({
        "status": "known",
        "value": { "kind": "write_receipt", "value": receipt },
        "recovery": null,
    });
    // A local recovery/persistence failure is reported here without claiming
    // durable lineage: the caller already stripped the correction link, so a
    // commit that cannot prove its lineage carries the stable issue code
    // instead. Carries no path or digest.
    if let Some(issue) = journal_issue {
        response["recovery"] = serde_json::json!({
            "pre_stage_journal_issue": issue,
        });
    }
    if let Some(link) = verified_correction {
        response["correction_lineage"] = serde_json::json!({
            "corrected_operation_id": link.corrected_operation_id,
            "corrected_from_operation_id": link.corrected_from_operation_id,
            "correction_rejection_id": link.correction_rejection_id,
        });
    }
    response
}

#[cfg(windows)]
fn store_apply_staged_response(submission: &eliot_store_api::WriteSubmission) -> serde_json::Value {
    serde_json::json!({
        "status": "accepted_pending",
        "value": { "kind": "write_submission", "value": submission },
        "recovery": null,
    })
}

#[cfg(windows)]
fn write_submission_matches_staged_operation(
    submission: &eliot_store_api::WriteSubmission,
    operation_id: &str,
    request_hash: &str,
) -> bool {
    submission.validate().is_ok()
        && submission.state == eliot_store_api::WriteSubmissionState::Staged
        && submission.operation_id.as_str() == operation_id
        && submission.request_hash == request_hash
        && submission.ors_stage_ref.is_some()
        && submission.canonical_receipt_ref.is_none()
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
                "mode":"verification"
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
                correlation_projection: None,
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
