//! Owner-side canonical acknowledgement proposer for `eliotd`
//! (issue #1780, A2; I11.5 / I11.7, I1.8, A0.3).
//!
//! This module is the acknowledgement leg the shipped tree names but never
//! proposes: `eliotd` takes an admitted acknowledgement (canonical record
//! identity plus acknowledging principal), checks it against the canonical
//! record through the store's own read, and proposes one canonical
//! `PreparedTransition` carrying exactly the closed `ACKNOWLEDGE` leg. Kernel
//! mechanically rechecks identity, authority, State Fence, idempotency and
//! ordering on the admitted `ApplyNotificationState` route; the store bridge
//! resolves the leg against its own dedup index and persists the
//! acknowledgement. Nothing here mints a principal, resolves a notification,
//! opens a Store client, or re-decides delivery.
//!
//! # Why the owner proposes the acknowledgement instead of the adapter
//!
//! The `eliot-notify` one-shot adapter's `mutate` sends the frame with the
//! surface selector `eliot.notify.state.v1` as the frame operation
//! (`bins/eliot-notify/src/lib.rs`, `KernelNotificationState::mutate`) and a
//! body shaped `{operation, context, state_fence, mutation}`. That selector is
//! admitted by no `frame_dispatch.rs` route predicate, so the frame falls
//! through every predicate and never reaches
//! `daemon_request_dispatch.rs::notification_state_operation`; the body would
//! not decode there either, because the admitted
//! `NotificationStateApplyOperation` carrier is the flat four-field contract
//! `{context, transition, expected_revision_heads, expected_ordering_heads}`
//! with `deny_unknown_fields`. The refutation in the issue record measured
//! both halves. Per I11.6 the adapter is not the canonical owner (adapter
//! loss degrades delivery only) and per A0.3 a second ungoverned canonical
//! write path fails closed, so the adapter frame is not renamed or widened
//! here: the owner proposes the leg through the one admitted owner route.
//!
//! # The guard is the record, not a shape
//!
//! I11.7 fixes the behavior this leg must produce: "acknowledgement
//! suppresses repeated toast, not problem". The store's own `acknowledge`
//! sets only `acknowledgement` and leaves `resolution_ref` unset, so the
//! unresolved problem and its critical attention stay visible in the
//! `ControlBoard` inbox; I11.5 keeps `acknowledgement` and `resolution_ref`
//! as separate record fields and states "Delivery and resolution are
//! separate." This emitter therefore refuses to propose unless the addressed
//! record is present at this fence, names the notified identity, is still
//! unacknowledged, and is still unresolved:
//!
//! * absent record: there is nothing to acknowledge, and the `ACKNOWLEDGE`
//!   leg cannot create it (the store refuses `UnknownNotification`), so the
//!   call returns `Ok(None)` before any write;
//! * identity mismatch between the addressed `dedup_key` and the named
//!   `notification_id`: fail closed rather than acknowledge a record the
//!   caller did not name (the admitted route resolves non-upsert legs against
//!   the store's own dedup index precisely so a caller can never substitute a
//!   `dedup_key` on this leg);
//! * already acknowledged: a repeat acknowledgement must not mint a duplicate
//!   transition — the toast-suppression state is already recorded;
//! * already resolved: the store refuses the leg with `AlreadyResolved`, so
//!   the call returns `Ok(None)` before the write; reopening a key after a
//!   Human disposition is the resolve leg's concern, not this emitter's.
//!
//! A record from another fence is not this record at this fence: reporting
//! it as present would suppress the acknowledgement the current fence owes,
//! so it is treated as absent. No clock, counter, or invented interval
//! enters the guard: the authoritative source is the store's own
//! `GetNotificationState` page, built by the store's own
//! `notification_read_request` keyed by `dedup_key`.
//!
//! # The principal is data, never minted authority
//!
//! ASSUMPTION: the acknowledging principal arrives admitted from the Human
//! acknowledgement intake and is recorded verbatim as record data. The four
//! governing sections name the behavior (I11.7) and the record field (I11.5)
//! but do not name which intake supplies the principal to `eliotd`; the most
//! specific implemented rule is the broker edge's own refusal of a blank or
//! control-character principal (`render_notify_acknowledge_line`), which this
//! emitter mirrors. This module admits no principal of its own, proves none,
//! and carries none in authority bindings: a heartbeat, timer, or retry
//! caller must never supply one, because an acknowledgement with no Human
//! actor is not a Human action.
//!
//! # STITCH: no production caller in this slice
//!
//! STITCH. This path is public and uncalled until the acknowledgement intake
//! lane forwards its admitted triple. The designated caller is the admitted
//! Human acknowledgement intake — today the broker `Request::NotifyAcknowledge`
//! arm (`bins/eliot-user-broker/src/notify_launch_callin.rs`), which reaches
//! the store only through the dead adapter frame above. That lane forwards
//! its admitted `(dedup_key, notification_id, principal)` — recovering the
//! `dedup_key` through the admitted `GetNotificationState` read when its
//! request names only the `notification_id` — to
//! [`emit_notification_acknowledgement`] instead of spawning the one-shot
//! adapter. Wiring a timer, heartbeat, or daemon-runtime arm as the caller
//! here would mint acknowledgements without a Human actor and is explicitly
//! not done.
//!
//! # Transport notes shared with the upsert leg
//!
//! The submitted payload is the same flat four-field contract
//! `apply_prepared` uses (`context`, `transition`,
//! `expected_revision_heads`, `expected_ordering_heads`) under operation
//! `ApplyNotificationState` over the same single authenticated daemon
//! transport, so this is the one write path, not a second one. The daemon
//! transport's `operation` routing key is stripped by the admitted route's
//! own `without_daemon_routing_key` before the closed decode, and the
//! `KernelStoreGateway::apply` source gate admits only the daemon identity
//! this emitter binds, so no `kernel_transition_client.rs`, `handshake.rs`,
//! `frame_dispatch.rs`, `daemon_request_dispatch.rs`, or `store_gateway.rs`
//! change is needed for this leg.
//!
//! Both Kernel routes are `#[cfg(windows)]`. On a non-Windows build this
//! emitter still evaluates and still derives its guard, but the exchange
//! resolves to the transport's own typed `Unsupported` refusal, which the
//! caller records as a typed diagnostics gap rather than as a committed
//! acknowledgement.
//!
//! Governed by `AGENTS.md`, `bins/AGENTS.md`, and
//! `docs/architecture/READING_PROTOCOL.md`. Implementation: I1.8, I11.5,
//! I11.7. Architecture: A0.3.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_contracts::{
    ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence, canonical_json_bytes,
    sha256_hex,
};
use eliot_protocol::RequestIdentity;
use eliot_receipts::RequestBinding;
use eliot_store_api::{
    CanonicalReadClient, NOTIFICATION_STATE_MUTATION_NAME, NOTIFY_MUTATION_ACKNOWLEDGE,
    NOTIFY_PAGE_RECORDS, NOTIFY_PARAM_MUTATION, NOTIFY_PARAM_NOTIFICATION_ID,
    NOTIFY_PARAM_PRINCIPAL, NamedReadResponse, StoreError, WriteReceipt, WriteReceiptStatus,
    notification_read_request,
};

use super::notification_state_emit::{
    NotificationEmitError, NotificationStateEmit, read_notification_ordering_head,
};
use super::{
    DaemonKernelClient, KernelContextReadClient, SERVICE_NAME,
    daemon_kernel_client::kernel_port_error, daemon_kernel_port_adapters::kind_value, unix_ms,
    unix_ms_i64,
};

/// Closed response `kind` of the committed canonical notification transition
/// projection served by the admitted `ApplyNotificationState` route.
///
/// The same literal the upsert leg decodes: the route serves one projection
/// kind for every lifecycle leg, so a second spelling here would be a second
/// vocabulary for one answer.
const NOTIFICATION_STATE_RESPONSE_KIND: &str = "notification_state";

/// Bounded absolute deadline applied to one acknowledgement commit, in Unix
/// milliseconds, matching the retained daemon transport's own operation bound.
const NOTIFICATION_COMMIT_DEADLINE_MS: u64 = 30_000;

/// Proposes one canonical acknowledgement for the addressed record.
///
/// The whole owner-side leg runs in the order I1.8 fixes: validate the named
/// leg inputs, ask the canonical store whether the `dedup_key` record exists
/// at this fence and still needs an acknowledgement, read the live ordering
/// head, derive the admitted ingress identity from those same observed facts,
/// prepare the one canonical `PreparedTransition` carrying exactly the closed
/// `ACKNOWLEDGE` leg, and submit it to the admitted `ApplyNotificationState`
/// route — which rechecks the fixed scope, ordering scope, transition class,
/// and closed leg parameters and requires a same-fence record read-back
/// before it reports success.
///
/// An absent record, an identity mismatch, an already-acknowledged record,
/// or a resolved record returns `Ok(None)` without touching the store: none
/// of them is a new acknowledgement, and the `ACKNOWLEDGE` leg can create,
/// rename, or reopen nothing. The acknowledgement suppresses repeated toast
/// attempts (the delivery selection reads it) and leaves `resolution_ref`
/// unset, so the unresolved problem stays visible in the `ControlBoard` inbox
/// (I11.7).
///
/// # Errors
///
/// Returns [`NotificationEmitError`] when a named input is not admittable
/// text; when the store contract refuses either read or the leg parameters;
/// when canonical admission refuses the prepared transition; or when the
/// authenticated Kernel exchange refuses or cannot complete it.
pub async fn emit_notification_acknowledgement(
    kernel: &Arc<DaemonKernelClient>,
    state_fence: StateFence,
    dedup_key: &str,
    notification_id: &str,
    principal: &str,
) -> Result<Option<NotificationStateEmit>, NotificationEmitError> {
    require_leg_text("notification.dedup_key", dedup_key)?;
    require_leg_text("notification.notification_id", notification_id)?;
    require_leg_text("notification.principal", principal)?;
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    if !acknowledgement_still_owed(&reads, &state_fence, dedup_key, notification_id).await? {
        return Ok(None);
    }
    let ordering_head = read_notification_ordering_head(&reads).await?;
    // The submission identity is derived from the exact compare-and-swap state
    // this transition observed: the same acknowledgement resubmitted against
    // the same ordering sequence is the same operation and replays
    // idempotently, while the sequence's own advance after a commit gives a
    // later leg its own identity. No counter, clock, or random value is
    // involved.
    let operation_text = format!(
        "notify-state:{dedup_key}:acknowledge:seq{}",
        ordering_head.expected_sequence
    );
    let identity = acknowledge_commit_identity(&operation_text, &state_fence)?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        NOTIFY_PARAM_MUTATION.to_owned(),
        serde_json::Value::String(NOTIFY_MUTATION_ACKNOWLEDGE.to_owned()),
    );
    parameters.insert(
        NOTIFY_PARAM_NOTIFICATION_ID.to_owned(),
        serde_json::Value::String(notification_id.to_owned()),
    );
    parameters.insert(
        NOTIFY_PARAM_PRINCIPAL.to_owned(),
        serde_json::Value::String(principal.to_owned()),
    );
    // The admitted semantic contract set for this leg is the canonical-JSON
    // digest of exactly what was admitted — the addressed `dedup_key`, the
    // named `notification_id`, and the acknowledging `principal` — so a
    // substituted plan fails the canonical request hash rather than reaching
    // the store.
    let admitted_content_digest = sha256_hex(
        &canonical_json_bytes(&(dedup_key, notification_id, principal))
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    );
    // Issue #1927: the one I5.6 admission sequence, shared with the upsert
    // leg. The plan it returns is the plan that is submitted, over the exact
    // context and head lists its recorded canonical request hash was verified
    // against.
    let submitted = super::notification_plan_admission::admit_notification_transition(
        &super::notification_plan_admission::NotificationPlanAdmission {
            identity: &identity,
            operation_text: &operation_text,
            admission_contract_set_digest: &admitted_content_digest,
            parameters,
            ordering_head: &ordering_head,
        },
    )?;
    let answer = kernel
        .transact_async_with_identity(
            NOTIFICATION_STATE_MUTATION_NAME,
            serde_json::json!({
                "context": submitted.context,
                "transition": submitted.transition,
                "expected_revision_heads": submitted.expected_revision_heads,
                "expected_ordering_heads": submitted.expected_ordering_heads,
            }),
            identity,
        )
        .await
        .map_err(kernel_port_error)?;
    let committed = kind_value(&answer, NOTIFICATION_STATE_RESPONSE_KIND)?;
    let committed_receipt = committed.get("receipt").cloned().ok_or_else(|| {
        StoreError::Serialization(
            "committed acknowledgement answer carries no store receipt".to_owned(),
        )
    })?;
    let receipt: WriteReceipt = serde_json::from_value(committed_receipt)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    receipt.validate()?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(StoreError::Serialization(
            "canonical acknowledgement transition was not committed".to_owned(),
        )
        .into());
    }
    Ok(Some(NotificationStateEmit::Committed {
        dedup_key: dedup_key.to_owned(),
        notification_id: notification_id.to_owned(),
        operation_id: receipt.operation_id.to_string(),
    }))
}

/// Refuses a leg input that is not admittable text.
///
/// Mirrors the store contract's own `require_text` for the closed mutation
/// legs (`validate_notification_mutation_params`) and the broker edge's own
/// principal rule: blank or control-character input is not an acknowledgement
/// actor, record identity, or index key. The refusal stays the store
/// contract's typed `InvalidField`, not prose.
///
/// # Errors
///
/// Returns [`StoreError::InvalidField`] when `value` is blank or carries a
/// control character.
fn require_leg_text(field: &'static str, value: &str) -> Result<(), StoreError> {
    if !value.trim().is_empty() && !value.chars().any(char::is_control) {
        return Ok(());
    }
    Err(StoreError::InvalidField {
        field,
        reason: "leg parameter must be non-blank text",
    })
}

/// Reports whether the addressed record still owes an acknowledgement.
///
/// The store's own `GetNotificationState` page keyed by `dedup_key` is the
/// authoritative source: the emitter asks it through the admitted
/// `KernelContextReadClient` and proposes only when the record is present at
/// this fence, names the notified identity, and carries neither an
/// acknowledgement nor a resolution. Every other case is `Ok(false)` — never
/// a write. Content is compared, not shape: the `notification_id` on the
/// stored record must equal the named one, so a substituted key cannot
/// acknowledge a record the caller did not name.
///
/// # Errors
///
/// Returns [`StoreError`] when the closed read is not admitted, the transport
/// refuses it, or the answer is not a decodable notification page.
async fn acknowledgement_still_owed(
    reads: &KernelContextReadClient,
    state_fence: &StateFence,
    dedup_key: &str,
    notification_id: &str,
) -> Result<bool, StoreError> {
    // The store catalogue's own exact read selector for one record, built by
    // the store's own request builder so the bound and the selector stay the
    // store contract's, not a second spelling of it. `include_resolved` is
    // true so a resolved record is seen and refused here rather than
    // re-proposed into the store's own `AlreadyResolved` refusal.
    let request = notification_read_request(
        None,
        Some(dedup_key.to_owned()),
        None,
        true,
        1,
        None,
        state_fence.clone(),
    )?;
    let response: NamedReadResponse = reads.execute_named(request).await?;
    let records = response
        .payload
        .get(NOTIFY_PAGE_RECORDS)
        .and_then(serde_json::Value::as_array)
        .ok_or(StoreError::InvalidField {
            field: "notification.records",
            reason: "notification page payload must carry records",
        })?;
    if records.is_empty() {
        return Ok(false);
    }
    let record: eliot_kernel_core::Notification = serde_json::from_value(records[0].clone())
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    // A record from another fence is not this record at this fence: reporting
    // it as owed would acknowledge under a fence that did not observe it.
    if record.state_fence != *state_fence {
        return Ok(false);
    }
    // The addressed key and the named identity must agree: the admitted route
    // resolves this leg against the store's own dedup index, so a mismatch
    // here is a substituted address, not an acknowledgement.
    if record.notification_id.as_str() != notification_id {
        return Ok(false);
    }
    // A recorded acknowledgement already suppresses the repeated toast: a
    // second transition would mint a duplicate, not a state change.
    if record.acknowledgement.is_some() {
        return Ok(false);
    }
    // A resolved record refuses this leg at the store (`AlreadyResolved`);
    // reopening it after a Human disposition is the resolve leg's concern.
    Ok(record.resolution_ref.is_none())
}

/// Derives the admitted ingress identity for one acknowledgement commit.
///
/// The daemon's own request metadata at the fence the composition admitted,
/// with `source_id` bound to the daemon identity: `KernelStoreGateway::apply`
/// refuses any other caller, so a substituted source would be fenced rather
/// than written. The same derivation the upsert leg uses, because the gate
/// admits one owner identity for every notification leg.
///
/// # Errors
///
/// Returns [`StoreError`] when an identity is not a valid contract value or
/// the metadata does not validate.
fn acknowledge_commit_identity(
    operation_text: &str,
    state_fence: &StateFence,
) -> Result<RequestIdentity, StoreError> {
    let now = unix_ms_i64();
    let metadata = RequestMetadata {
        request_id: RequestId::new(format!("{SERVICE_NAME}:{operation_text}"))
            .map_err(StoreError::Foundation)?,
        session_id: None,
        task_id: None,
        product_id: ProductId::new(SERVICE_NAME).map_err(StoreError::Foundation)?,
        source_id: SourceId::new(SERVICE_NAME).map_err(StoreError::Foundation)?,
        state_fence: state_fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(now),
            known_time_ms: Some(now),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    metadata.validate().map_err(StoreError::Foundation)?;
    Ok(RequestIdentity {
        request: RequestBinding {
            metadata,
            state_fence: state_fence.clone(),
        },
        idempotency_key: format!("{SERVICE_NAME}:{operation_text}"),
        deadline_unix_ms: unix_ms().saturating_add(NOTIFICATION_COMMIT_DEADLINE_MS),
        cancellation_id: format!("{SERVICE_NAME}:{operation_text}:cancel"),
    })
}

