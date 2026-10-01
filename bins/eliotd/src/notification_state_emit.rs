//! Owner-side canonical notification-state proposer for `eliotd`
//! (issue #1780, I11.5 / I11.7 / I11.12, I1.8).
//!
//! This module is the producer I1.8 names and no shipped code contained:
//! `eliotd` interprets the semantic decision and proposes one canonical
//! `PreparedTransition`; Kernel mechanically rechecks identity, authority,
//! State Fence, idempotency and ordering; the store bridge persists only that
//! already-prepared transition. Nothing here re-decides the maintenance
//! decision, resolves a notification, or opens a Store client.
//!
//! # The trigger is a real admitted decision, not a manufactured event
//!
//! The single production call path is the daemon health heartbeat's
//! `note_maintenance_trigger_at` arm (`bins/eliotd/src/daemon_runtime.rs`). Its
//! [`eliot_maintenance::AutomationTriggerDecision`] carries `trigger_id`,
//! `family`, `scope_ref`, `decision`, `reason`, `admits_job` and
//! `durable_job_ref`. `admits_job == false` is precisely "admitted automation
//! work that cannot start", which I11.5 requires to become one persistent
//! notification instead of a log line. Per #1693's registered family catalog
//! every one of the fifteen families currently resolves to a start that
//! `MaintenanceRoute::admits_start()` refuses, so the arm really fires.
//!
//! # Deduplication is the record id, not one alert per observation
//!
//! I11.12 is explicit: "A repeated failure class updates one persistent
//! notification keyed by automation revision and failure fingerprint. It does
//! not emit one alert per occurrence; a material revision, verified recovery or
//! Human disposition reopens that notification key." [`AutomationFailureKey`] is
//! therefore the recommendation's stable identity — `family`, `scope_ref`,
//! `reason` and policy episode. Trigger/job identities and requested/actual
//! route evidence remain on the notification body and source receipt, but are
//! not key material: another trigger or route observation in the same policy
//! episode must coalesce onto the same Human obligation, not mint another one.
//!
//! Read that sentence against the store's own upsert, because it decides what
//! this emitter may do. `NotificationStore::upsert` refuses a draft that does
//! not `matches_draft` the stored record (`IdentityConflict`; the comparison
//! includes `state_fence`) and otherwise does exactly one thing, increments
//! `occurrences`. So a re-submitted unchanged decision writes a canonical
//! transition per heartbeat, grows `occurrences` without bound, and is refused
//! outright once the fence moves under an unchanged key. "Updates one persistent
//! notification" is therefore satisfied by recording the record once and leaving
//! it standing: [`notification_already_recorded`] asks the store and the
//! emitter submits only an absent record. Nothing here invents a cadence.
//!
//! `scope_ref` carries the authority lineage, epoch sequence, and resource
//! generation, so a new generation is a different key and correctly gets its
//! own record rather than mutating one bound to a superseded fence. Note the
//! direction of I11.12's last clause: a material revision "reopens that
//! notification key" — the *same* key, after a Human disposition or verified
//! recovery. Reopening under the same key is the resolve leg's concern
//! (`upsert` refuses `AlreadyResolved` while `resolution_ref` is set) and is
//! **not** claimed here.
//!
//! # The ordering head is read, never synthesized
//!
//! The admission sequence derives `ordering_scopes` from
//! `expected_ordering_heads`, and `PreparedTransition::validate` refuses an
//! empty `ordering_scopes` (`StoreError::Empty { field: "ordering_scopes" }`).
//! An owner-side envelope therefore cannot declare a no-ordering-contract leg,
//! and inventing a sequence number would be a fabricated compare-and-swap
//! expectation on a durability record. This module resolves that by admitting
//! the real read: [`read_notification_ordering_head`] issues one closed,
//! scope-free, `ExactFence`, parameter-free `GetOrderingHeads` named read
//! through the retained [`KernelContextReadClient`] and submits the observed
//! sequence. See [`FRESH_ORDERING_SEQUENCE`] for the only value the store
//! admits for a scope with no stored head yet.
//!
//! # The I5.6 admission sequence is not restated here
//!
//! Issue #1927 makes the plan an `eliotd` product with a single owner. This
//! module derives the semantic inputs — the failure key, the record draft, the
//! source receipt, the live ordering head — and hands them to
//! `super::notification_plan_admission::admit_notification_transition`, which
//! binds the eighteen I5.6 plan keys, builds the immutable plan, checks it
//! against current admissible support, and returns the exact submission its
//! recorded canonical request hash was verified against. The acknowledgement leg
//! in `notification_acknowledge_emit.rs` builds the same plan through the same
//! call, so neither leg restates the field list.
//!
//! # Why the `ApplyNotificationState` route and not `apply_prepared`
//!
//! `GovernorComposition::commit_canonical` reaches the store through
//! `CanonicalTransitionOwner::commit`, which hardcodes the `apply_prepared`
//! operation name. That route runs the generic `store_apply_operation` checks,
//! which do not include the canonical notification re-checks, so a notification
//! submitted through it would skip exactly the validation this issue is about.
//! The admitted `ApplyNotificationState` route adds it: the fixed
//! `NotificationState` class, the fixed `notification-state` scope and its
//! single ordering scope, exactly one named operation, a decodable leg, and a
//! same-fence record read-back after the commit. The submitted payload is the
//! same flat four-field contract `apply_prepared` uses (`context`,
//! `transition`, `expected_revision_heads`, `expected_ordering_heads`) over the
//! same single authenticated daemon transport, so this is the one write path,
//! not a second one.
//!
//! That choice is also why this leg does not run through
//! [`DaemonComposition::commit_canonical_and_refresh`], and the reason is the
//! operation name, not convenience:
//!
//! * that entry's only store route is `apply_prepared`, which — as above —
//!   never calls `validate_notification_state_transition`;
//! * its `check_canonical_write_work_scope` gate (#1787) is a *quarantine* that
//!   engages only "when a `WorkScope` binding is retained"; with no retained
//!   binding there is nothing to revalidate and the write proceeds, so the gate
//!   is not what this leg would be escaping;
//! * `admit_canonical_write` (#1929) resolves the caller's compiled readiness
//!   receipt, and this observation carries none — there is no `TaskSelection`
//!   to bind, and `task_id` is `None` on the envelope.
//!
//! What that entry would additionally do — `refresh_from_kernel()` and the #18
//! W6/A5 cached-revision-fence recheck — is deliberately absent and is stated
//! rather than skipped silently: a notification record is not part of any
//! Governor projection this composition caches, and the write does not move a
//! fence, so there is no dependent view to refresh and no cache key to
//! invalidate. The admitted route's own same-fence record read-back is the
//! proof this leg owes.
//!
//! Forbidden authority: no Store or provider client, no retry or default
//! synthesis, no alternative transport, no second notification model, and no
//! decision this module did not receive from its owner.
//!
//! # The daemon transport's routing key, and why this leg is Windows-live
//!
//! Both exchanges this module makes travel the retained daemon transport, which
//! inserts a routing key named `operation` into the JSON body
//! (`daemon_kernel_client/handshake.rs::operation_payload`). The Kernel routes
//! that decode the **whole** body with `#[serde(deny_unknown_fields)]` reject
//! that key as unknown, and the daemon frame loop propagates the resulting
//! `SessionFenced` with `?` (`front_door_driver.rs`, `KernelFrameAction::Daemon`),
//! so a mismatch here fences the Kernel connection, not just one request.
//! `daemon_request_dispatch.rs` therefore strips the routing key from exactly
//! the two whole-body carriers this module uses — the notification write and
//! the `GetOrderingHeads` read — through one shared helper, and leaves every
//! other carrier of that frame alone.
//!
//! Both Kernel routes are `#[cfg(windows)]`. On a non-Windows build this
//! emitter still evaluates and still derives its key, but the exchange resolves
//! to the transport's own typed `Unsupported` refusal, which the caller records
//! as a typed diagnostics gap rather than as a committed notification.
//!
//! Governed by `AGENTS.md`, `bins/AGENTS.md`, and
//! `docs/architecture/READING_PROTOCOL.md`. Implementation: I1.8, I11.2, I11.5,
//! I11.6, I11.7, I11.10, I11.12. Architecture: A0.3, A2.3, A12.3, A13.2.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use eliot_contracts::{
    ArtifactId, ClockReading, ContractId, OperationId, ProductId, RequestId, RequestMetadata,
    SourceId, StateFence, TransactionSequence, canonical_json_bytes, sha256_hex,
};
use eliot_governor::{
    CompositionError, KernelGenerationSnapshotProvider, KernelPortError,
};
use eliot_kernel_core::{
    DeadlineOrReview, DeliveryChannel, NotificationDraft, NotificationSeverity,
};
use eliot_maintenance::{
    AutomationTriggerDecision, MaintenanceAutomationMode, MaintenancePolicyEvidence,
    MaintenanceRouteEvidence,
};
use eliot_platform::PlatformHandle;
use eliot_protocol::RequestIdentity;
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, OperationBinding, ProofCeiling, ReceiptCore,
    ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding, WorkScopeBinding,
    WorkScopeId,
};
use eliot_store_api::{
    CanonicalReadClient, NOTIFICATION_STATE_MUTATION_NAME, NOTIFICATION_STATE_SCOPE,
    NOTIFY_MUTATION_UPSERT, NOTIFY_PARAM_DEDUP_KEY, NOTIFY_PARAM_MUTATION,
    NOTIFY_PARAM_RECORD_JSON, NOTIFY_PARAM_SOURCE_RECEIPT_JSON, NamedReadOperation,
    NamedReadRequest, OrderingHead, OrderingHeadExpectation, OrderingScopeId, ReadConsistency,
    StoreError, WriteReceipt, WriteReceiptStatus, notification_read_request,
};
use serde::Serialize;
use thiserror::Error;

use super::{
    DaemonKernelClient, KernelContextReadClient, SERVICE_NAME,
    daemon_kernel_client::kernel_port_error, daemon_kernel_port_adapters::kind_value,
    maintenance_dispatch::MaintenanceDispatch, unix_ms, unix_ms_i64,
};

/// Closed response `kind` of the committed canonical notification transition
/// projection served by the admitted `ApplyNotificationState` route.
const NOTIFICATION_STATE_RESPONSE_KIND: &str = "notification_state";

/// The store's own baseline for an ordering scope that has no stored head yet.
///
/// This is read out of the store contract, not chosen here:
/// `OrderingHeadExpectation::validate` refuses `expected_sequence == 0`, and
/// the adapter's `check_expected_orderings` admits an *absent* current head
/// **only** at `1` (`None if item.expected_sequence != 1 => OrderingConflict`),
/// matching the plan's own `before = current.map_or(1, ..)` increment baseline.
/// Any other value is refused as `StoreError::OrderingConflict`, so a fresh
/// scope has exactly one admissible expectation and this is it.
const FRESH_ORDERING_SEQUENCE: u64 = 1;

/// Bounded absolute deadline applied to one notification commit, in Unix
/// milliseconds, matching the retained daemon transport's own operation bound.
const NOTIFICATION_COMMIT_DEADLINE_MS: u64 = 30_000;

/// Lifecycle owner of every maintenance automation decision this daemon
/// evaluates. Recorded identically as the record's `owner` and as the source
/// receipt's `authority_owner`, so a later authorized disposition matches.
const MAINTENANCE_AUTHORITY_OWNER: &str = "eliotd.maintenance";

/// Closed contract identity of the maintenance trigger evaluation whose
/// observation this notification is sourced from.
const MAINTENANCE_OPERATION_KIND: &str = "maintenance.evaluate_trigger";

/// Review handle recorded on the record's `deadline_or_review`: I11.5 lets a
/// notification carry a review reference instead of a deadline, and this one
/// points the operator at the maintenance trigger owner rather than inventing a
/// deadline nobody published.
const MAINTENANCE_REVIEW_REF: &str = "eliotd:maintenance-trigger-review";

/// Fail-closed refusals of the owner-side notification proposer.
///
/// Every variant keeps its owner's own typed failure: the store contract
/// refusal stays a [`StoreError`], canonical admission stays on the
/// composition's own [`CompositionError`] channel, and the authenticated
/// exchange stays a [`KernelPortError`]. No code is folded into prose between
/// layers.
#[derive(Debug, Error)]
pub enum NotificationEmitError {
    /// The ordering-head read, the leg parameters, the receipt, or the
    /// envelope inputs were refused by the store contract.
    #[error("canonical notification state: {0}")]
    Store(#[from] StoreError),
    /// Governor-owned canonical admission refused the prepared transition.
    #[error("canonical notification admission: {0}")]
    Admission(#[from] CompositionError),
    /// The authenticated Kernel exchange refused or could not complete the
    /// notification transition.
    #[error("canonical notification transition: {0}")]
    Kernel(#[from] KernelPortError),
}

/// Typed outcome of one owner-side notification emission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotificationStateEmit {
    /// One canonical record was committed at the admitted fence.
    Committed {
        /// The failure fingerprint key the one record is stored under.
        dedup_key: String,
        /// The canonical notification identity of that one record.
        notification_id: String,
        /// The commit identity the store receipt carries.
        operation_id: String,
    },
}

/// Policy, actual-route and trigger-site evidence observed for the decision
/// being recorded.
///
/// The policy is bound to the decision's family and scope before it can affect
/// the fingerprint or canonical record. Optional publisher fields remain
/// absent until their owners publish them; this type does not synthesize policy
/// revisions or route identities. The trigger event the Governor evaluated
/// travels on the decision itself; the concrete evidence identities the
/// trigger site actually saw travel here, beside the owner evidence rather
/// than inside it, so the record can bind each one separately.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceNotificationEvidence {
    /// Human-owned policy evidence selected for this family and scope.
    pub policy: MaintenancePolicyEvidence,
    /// Actual admitted route evidence, when an owner has published it.
    pub route: MaintenanceRouteEvidence,
    /// Evidence identities actually observed at the trigger site.
    ///
    /// These state what this evaluation saw, never the catalog's requirement
    /// list: `MaintenanceRecommendation::evidence` states the evidence kinds a
    /// future result must carry, while this states the receipts already
    /// observed. Empty states explicitly that none was bound on this leg; the
    /// notification renders that as `unobserved` rather than projecting the
    /// requirement names.
    pub observed_refs: Vec<String>,
}

impl MaintenanceNotificationEvidence {
    /// Refuses policy evidence issued for a different family, scope, or mode.
    pub fn validate_for(&self, decision: &AutomationTriggerDecision) -> Result<(), StoreError> {
        if self.policy.family != decision.family {
            return Err(StoreError::InvalidField {
                field: "maintenance_policy.family",
                reason: "policy evidence family must match the trigger decision",
            });
        }
        if self.policy.scope_ref != decision.scope_ref {
            return Err(StoreError::InvalidField {
                field: "maintenance_policy.scope_ref",
                reason: "policy evidence scope must match the trigger decision",
            });
        }
        if self.policy.mode != super::maintenance_family_catalog::entry_for(decision.family).mode {
            return Err(StoreError::InvalidField {
                field: "maintenance_policy.mode",
                reason: "policy evidence mode must match the registered family mode",
            });
        }
        Ok(())
    }
}

/// The stable failure fingerprint of one admitted automation decision.
///
/// This is I11.12's "automation revision and failure fingerprint": the
/// decision's own identity plus its bound policy and route evidence, never a
/// fresh value per observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AutomationFailureKey {
    /// The store's record id and coalescing index: exactly one record.
    pub dedup_key: String,
    /// Stable canonical identity of that one record.
    pub notification_id: String,
    /// SHA-256 over the exact decision identity tuple. Also the source
    /// receipt's artifact digest, so the record's evidence is receipt-bound.
    pub fingerprint: String,
    /// Operator-facing subject line.
    pub subject: String,
    /// Operator-facing summary of the blocked automation.
    pub summary: String,
    /// The action the operator is required to take.
    pub required_action: String,
    /// Canonical lifecycle owner of the decision.
    pub owner: String,
    /// Work or resource scope the decision affected.
    pub affected_scope: String,
}

/// Derives the one stable failure fingerprint of an admitted automation
/// decision.
///
/// The key is the canonical-JSON digest of the decision identity, policy
/// episode, requested catalog route and actual admitted route evidence. Missing
/// publisher fields remain `None` in that identity. Replaying the same decision
/// under unchanged evidence yields the same key; a material policy or route
/// change yields a distinct canonical record.
///
/// # Errors
///
/// Returns [`StoreError`] when evidence is bound to a different family/scope,
/// a closed discriminator does not render its declared wire form, or the
/// identity cannot be serialized canonically.
pub fn automation_failure_key(
    decision: &AutomationTriggerDecision,
    evidence: &MaintenanceNotificationEvidence,
) -> Result<AutomationFailureKey, StoreError> {
    evidence.validate_for(decision)?;
    let family_decision =
        super::maintenance_family_catalog::entry_for(decision.family).decide(decision);
    let dispatch = MaintenanceDispatch::for_decision(decision, &family_decision);
    automation_failure_key_with_family_decision(decision, &family_decision, &dispatch, evidence)
}

fn automation_failure_key_with_family_decision(
    decision: &AutomationTriggerDecision,
    family_decision: &super::maintenance_family_catalog::MaintenanceFamilyDecision,
    dispatch: &MaintenanceDispatch,
    evidence: &MaintenanceNotificationEvidence,
) -> Result<AutomationFailureKey, StoreError> {
    let family = closed_wire_name(decision.family)?;
    let reason = closed_wire_name(decision.reason)?;
    let outcome = closed_wire_name(decision.decision)?;
    let trigger_event = closed_wire_name(decision.trigger)?;
    let mode = closed_wire_name(evidence.policy.mode)?;
    let requested_route = (
        family_decision.route.target(),
        family_decision.route.missing(),
    );
    // The canonical Human-board obligation is one per family/scope/reason and
    // policy episode. Keep volatile trigger/job/route observations in the
    // record below; including them here would create a new notification for
    // each poll, replacement trigger, or route observation. The trigger event
    // and the concrete observed evidence travel in the summary body instead:
    // bound separately beside the policy revision, the actual route result
    // and the board/job receipt, never projected from the catalog's
    // requirement list and never keyed.
    let identity = (
        family.as_str(),
        decision.scope_ref.as_str(),
        reason.as_str(),
        mode.as_str(),
        evidence.policy.revision,
        evidence.policy.digest.as_deref(),
        evidence.policy.override_provenance.as_deref(),
    );
    let fingerprint = sha256_hex(
        &canonical_json_bytes(&identity)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    );
    Ok(AutomationFailureKey {
        dedup_key: format!("automation-{fingerprint}"),
        notification_id: format!("notification-automation-{fingerprint}"),
        subject: dispatch.subject(&decision.family),
        summary: format!(
            "maintenance automation {family} at {} raised by trigger event {trigger_event} evaluated {outcome} for reason {reason}; \
             Governor admits job: {}; catalog route admits start: {}; trigger identity {}; \
             observed evidence {}; job identity {}; policy episode {}; requested route {} (missing {}); actual route {}; \
             next allowed action: {}; {}",
            decision.scope_ref,
            decision.admits_job,
            family_decision.admits_start,
            decision.trigger_id,
            observed_evidence_summary(evidence),
            decision
                .durable_job_ref
                .as_deref()
                .unwrap_or("not allocated"),
            policy_episode_summary(&mode, evidence),
            requested_route.0,
            requested_route.1,
            actual_route_summary(evidence),
            family_decision.recommendation.required_action,
            dispatch.detail(),
        ),
        // Preserve the exact decision and route evidence in the summary, and
        // retain the catalog's typed recommendation fields in the action.
        // Runtime cost and a maintenance expiry are unpublished, so say so
        // explicitly instead of presenting a budget class as a cost estimate.
        required_action: render_maintenance_recommendation(
            &family_decision.recommendation,
            requested_route,
        ),
        fingerprint,
        owner: MAINTENANCE_AUTHORITY_OWNER.to_owned(),
        affected_scope: decision.scope_ref.clone(),
    })
}

fn render_maintenance_recommendation(
    recommendation: &super::maintenance_family_catalog::MaintenanceRecommendation,
    requested_route: (&str, &str),
) -> String {
    format!(
        "Next allowed action: {}. Deferred reason: {}. Requested route: {} (missing {}). \
         Evidence required: {}. Expected benefit hypothesis: {}. Cost: unknown until an \
         admitted route provides an estimate; budget class: {}. Effect policy: {}. Expiry: {}. \
         Safe deferral consequence: {}.",
        recommendation.required_action,
        recommendation.reason,
        requested_route.0,
        requested_route.1,
        recommendation.evidence.join("+"),
        recommendation.expected_benefit,
        recommendation.cost.class_name(),
        recommendation.effect_policy.effect_description(),
        recommendation.expiry,
        recommendation.deferral_consequence,
    )
}

/// Renders one closed maintenance discriminator in its own declared wire form.
///
/// Every maintenance enum already fixes its stable spelling
/// (`SCREAMING_SNAKE_CASE`, with a matching `Display` for `MaintenanceFamily`).
/// Reusing that declared form is what keeps this emitter from minting a second
/// vocabulary beside its owner's.
fn closed_wire_name<T: Serialize>(value: T) -> Result<String, StoreError> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(name)) => Ok(name),
        _ => Err(StoreError::Serialization(
            "maintenance discriminator is not a closed wire string".to_owned(),
        )),
    }
}

/// Reads the live `notification-state` ordering head through the daemon's own
/// admitted named-read path.
///
/// One closed, scope-free, `ExactFence`, parameter-free `GetOrderingHeads`
/// request travels the retained [`KernelContextReadClient`], and the sequence
/// observed for the fixed notification ordering scope becomes the submitted
/// compare-and-swap expectation. An absent scope resolves to
/// [`FRESH_ORDERING_SEQUENCE`], the only value the store admits for one; a
/// stored head from another fence fails closed as [`StoreError::FenceMismatch`].
///
/// # Errors
///
/// Returns [`StoreError`] when the read is not admitted, the fence moved, the
/// answer is not an ordering-head set, or the notification ordering scope is
/// not a valid store identity.
pub async fn read_notification_ordering_head(
    reads: &KernelContextReadClient,
) -> Result<OrderingHeadExpectation, StoreError> {
    let state_fence = reads.kernel().snapshot().state_fence().clone();
    let response = reads
        .execute_named(NamedReadRequest {
            operation: NamedReadOperation::GetOrderingHeads,
            scope_id: None,
            consistency: ReadConsistency::ExactFence,
            state_fence: state_fence.clone(),
            parameters: BTreeMap::new(),
        })
        .await?;
    let heads: Vec<OrderingHead> = serde_json::from_value(response.payload)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let scope = OrderingScopeId::new(NOTIFICATION_STATE_SCOPE)?;
    let observed = heads.iter().find(|head| head.scope == scope);
    if let Some(head) = observed
        && head.state_fence != state_fence
    {
        return Err(StoreError::FenceMismatch);
    }
    Ok(OrderingHeadExpectation {
        scope,
        expected_sequence: observed.map_or(FRESH_ORDERING_SEQUENCE, |head| head.sequence),
        state_fence,
    })
}

/// Reports whether the canonical store already holds this failure's record.
///
/// I11.12 is explicit that a repeated failure "does not emit one alert per
/// occurrence", and the store's own upsert proves why that is a hard rule and
/// not a nicety: `NotificationStore::upsert` refuses any draft that does not
/// `matches_draft` the stored record with `IdentityConflict` (the comparison
/// includes `state_fence`), and otherwise does exactly one thing — increments
/// `occurrences`. Re-submitting an unchanged decision every heartbeat would
/// therefore write a canonical transition per tick, grow `occurrences` without
/// bound, and be refused outright the moment the fence moves under an
/// unchanged key. The store already holds the answer, so the emitter asks it
/// through the admitted `GetNotificationState` read and submits only when the
/// record is genuinely absent.
///
/// A record that is present but resolved is still present: the upsert leg
/// refuses `AlreadyResolved`, and reopening a key after a Human disposition is
/// the resolve leg's own concern, not this emitter's.
///
/// # Errors
///
/// Returns [`StoreError`] when the closed read is not admitted, the transport
/// refuses it, or the answer is not a decodable notification page.
pub async fn notification_already_recorded(
    reads: &KernelContextReadClient,
    key: &AutomationFailureKey,
    state_fence: &StateFence,
) -> Result<bool, StoreError> {
    // The store catalogue's own exact read selector for one record, built by
    // the store's own request builder so the bound and the selector set stay
    // the store contract's, not a second spelling of it.
    let request = notification_read_request(
        None,
        Some(key.dedup_key.clone()),
        None,
        true,
        1,
        None,
        state_fence.clone(),
    )?;
    let response = reads.execute_named(request).await?;
    let records = response
        .payload
        .get(eliot_store_api::NOTIFY_PAGE_RECORDS)
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
    // it as present would suppress the notification the current fence owes.
    Ok(record.state_fence == *state_fence)
}

/// Persists one persistent canonical notification for an admitted automation
/// decision that could not start.
///
/// The whole owner-side leg runs in the order I1.8 fixes: derive the decision's
/// stable failure fingerprint, ask the canonical store whether that record
/// already exists, read the live ordering head, derive the admitted ingress
/// identity and the source-verification receipt from those same observed facts,
/// prepare the one canonical `PreparedTransition`, and submit it to the admitted
/// `ApplyNotificationState` route — which rechecks the fixed scope, ordering
/// scope, transition class, and closed leg parameters and requires a same-fence
/// record read-back before it reports success.
///
/// A decision that admits a job is not a notification-worthy failure, and a
/// decision whose record is already stored is I11.12's repeat rather than a
/// new occurrence; both return `Ok(None)` without touching the store.
///
/// `Off` withholds proactive recommendations before route-unavailability
/// handling. This path has no verified mandatory safety/recovery publisher,
/// so no decision under `Off` bypasses the mode gate. For an allowed
/// recommendation, a replay re-derives the same family/scope/reason/policy
/// episode key and checks the canonical store before writing; an existing
/// item stays the single canonical record.
///
/// Stated rather than implied: the start arm is currently unreachable because
/// `MaintenanceRoute::admits_start` requires an implemented family route on
/// top of clear shared wiring, and the three owner blockers remain present for
/// every registered family. If those owners later publish the missing route,
/// the notification is suppressed only after the decision carries the
/// Durable Job reference that proves the existing admission owner accepted it.
///
/// The record binds each leg separately: the trigger event the Governor
/// evaluated, the concrete evidence identities the trigger site observed, the
/// selected policy revision, the actual admitted route result, and the
/// board/job receipt each render in the summary body beside the others. The
/// catalog's requirement names stay a requirement in the action field and are
/// never projected as observed receipts, and none of the volatile bindings
/// enters the dedup key, so a replay re-derives the same record.
///
/// # Errors
///
/// Returns [`NotificationEmitError`] when the store contract refuses the
/// envelope, the leg parameters, or either read; when canonical admission
/// refuses the prepared transition; or when the authenticated Kernel exchange
/// refuses or cannot complete it.
pub async fn emit_blocked_automation_notification(
    kernel: &Arc<DaemonKernelClient>,
    state_fence: StateFence,
    decision: &AutomationTriggerDecision,
    evidence: &MaintenanceNotificationEvidence,
) -> Result<Option<NotificationStateEmit>, NotificationEmitError> {
    evidence.validate_for(decision)?;
    // Off is checked before resolving the family route or deriving a failure
    // key: route unavailability cannot produce a proactive item while
    // automation is disabled. Verified mandatory safety/recovery evidence is
    // not published to this path and therefore cannot bypass this gate.
    if evidence.policy.mode == MaintenanceAutomationMode::Off {
        return Ok(None);
    }
    let family_entry = super::maintenance_family_catalog::entry_for(decision.family);
    let family_decision = family_entry.decide(decision);
    let dispatch = MaintenanceDispatch::for_decision(decision, &family_decision);
    let retained_record_owed = match &dispatch {
        MaintenanceDispatch::ExistingDurableJob { .. } => false,
        MaintenanceDispatch::StartDurableJob { .. } => decision.durable_job_ref.is_none(),
        MaintenanceDispatch::SuggestBoardItem { .. }
        | MaintenanceDispatch::Defer { .. }
        | MaintenanceDispatch::Block { .. }
        | MaintenanceDispatch::Escalate { .. } => true,
    };
    if !retained_record_owed {
        return Ok(None);
    }
    let key = automation_failure_key_with_family_decision(
        decision,
        &family_decision,
        &dispatch,
        evidence,
    )?;
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
    if notification_already_recorded(&reads, &key, &state_fence).await? {
        return Ok(None);
    }
    let ordering_head = read_notification_ordering_head(&reads).await?;
    // The submission identity is derived from the exact compare-and-swap state
    // this transition observed: the same failure resubmitted against the same
    // ordering sequence is the same operation and replays idempotently, while
    // the sequence's own advance after a commit gives the next occurrence its
    // own identity. No counter, clock, or random value is involved.
    let operation_text = format!(
        "notify-state:{}:upsert:seq{}",
        key.dedup_key, ordering_head.expected_sequence
    );
    let identity = notification_commit_identity(&operation_text, &state_fence)?;
    let record_json = notification_record_json(&key, &state_fence)?;
    let source_receipt = source_receipt_json(&key, decision, &identity, &state_fence)?;
    let mut parameters = BTreeMap::new();
    parameters.insert(
        NOTIFY_PARAM_MUTATION.to_owned(),
        serde_json::Value::String(NOTIFY_MUTATION_UPSERT.to_owned()),
    );
    parameters.insert(
        NOTIFY_PARAM_DEDUP_KEY.to_owned(),
        serde_json::Value::String(key.dedup_key.clone()),
    );
    parameters.insert(NOTIFY_PARAM_RECORD_JSON.to_owned(), record_json);
    parameters.insert(NOTIFY_PARAM_SOURCE_RECEIPT_JSON.to_owned(), source_receipt);
    // Issue #1927: the whole I5.6 admission sequence runs in one place, and
    // the plan it returns is the plan that is submitted. The admitted semantic
    // contract set for this notification is exactly the decision's own
    // identity, so its digest is that identity's canonical-JSON digest — the
    // same value the record's evidence handle and the source receipt's artifact
    // carry.
    let submitted = super::notification_plan_admission::admit_notification_transition(
        &super::notification_plan_admission::NotificationPlanAdmission {
            identity: &identity,
            operation_text: &operation_text,
            admission_contract_set_digest: &key.fingerprint,
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
            "committed notification answer carries no store receipt".to_owned(),
        )
    })?;
    let receipt: WriteReceipt = serde_json::from_value(committed_receipt)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    receipt.validate()?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(StoreError::Serialization(
            "canonical notification transition was not committed".to_owned(),
        )
        .into());
    }
    Ok(Some(NotificationStateEmit::Committed {
        dedup_key: key.dedup_key,
        notification_id: key.notification_id,
        operation_id: receipt.operation_id.to_string(),
    }))
}

fn policy_episode_summary(mode: &str, evidence: &MaintenanceNotificationEvidence) -> String {
    if evidence.policy.revision.is_none()
        && evidence.policy.digest.is_none()
        && evidence.policy.override_provenance.is_none()
    {
        return "unpublished".to_owned();
    }
    format!(
        "mode={mode}, revision={:?}, digest={}, override_provenance={}",
        evidence.policy.revision,
        evidence.policy.digest.as_deref().unwrap_or("unpublished"),
        if evidence.policy.override_provenance.is_some() {
            "present"
        } else {
            "unpublished"
        },
    )
}

fn actual_route_summary(evidence: &MaintenanceNotificationEvidence) -> String {
    format!(
        "fingerprint={}, generation={:?}, credential_ref={}, unattended_suitable={}",
        evidence
            .route
            .capability_fingerprint
            .as_deref()
            .unwrap_or("unpublished"),
        evidence.route.generation,
        evidence
            .route
            .credential_ref
            .as_deref()
            .unwrap_or("unpublished"),
        evidence.route.unattended_suitable,
    )
}

/// Renders the concrete evidence identities the trigger site observed.
///
/// These are receipts already seen, never the catalog's requirement list: an
/// empty binding states explicitly that nothing was observed on this leg
/// rather than projecting the requirement names into the record.
fn observed_evidence_summary(evidence: &MaintenanceNotificationEvidence) -> String {
    if evidence.observed_refs.is_empty() {
        return "unobserved".to_owned();
    }
    evidence.observed_refs.join("+")
}

/// Derives the admitted ingress identity for one notification commit.
///
/// The daemon's own request metadata at the fence the composition read from its
/// retained Governor snapshot, with `source_id` bound to the daemon identity:
/// `KernelStoreGateway::apply` refuses any other caller, so a substituted
/// source would be fenced rather than written.
///
/// # Errors
///
/// Returns [`StoreError`] when an identity is not a valid contract value or the
/// metadata does not validate.
fn notification_commit_identity(
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

/// Renders the canonical I11.5 record draft for one blocked automation.
///
/// Every field is a function of the decision's stable identity plus the
/// admitted fence, so a repeat produces byte-equal input and the shared model
/// coalesces it onto the one stored record instead of creating a second one.
/// Delivery is requested on the Control Board channel only: I11.7 keeps a
/// canonical record on the board and confines quiet hours to popup selection,
/// and this emitter performs no delivery attempt of its own.
///
/// # Errors
///
/// Returns [`StoreError`] when the derived identity is not a valid platform
/// handle or the draft cannot be serialized.
fn notification_record_json(
    key: &AutomationFailureKey,
    state_fence: &StateFence,
) -> Result<serde_json::Value, StoreError> {
    let draft = NotificationDraft {
        notification_id: PlatformHandle::new(key.notification_id.clone()).map_err(|_| {
            StoreError::InvalidField {
                field: "notification.notification_id",
                reason: "derived identity is not a valid platform handle",
            }
        })?,
        // I11.5: "ActionRequired - approval, blocked task, failed
        // credential/repair". Admitted automation that cannot start is blocked
        // work, not a degraded hook and not verified completion.
        severity: NotificationSeverity::ActionRequired,
        subject: key.subject.clone(),
        summary: key.summary.clone(),
        // The receipt-bound artifact digest, so the record's evidence is
        // exactly what its source receipt verifies.
        evidence_handles: vec![key.fingerprint.clone()],
        affected_scope: key.affected_scope.clone(),
        owner: key.owner.clone(),
        required_action: key.required_action.clone(),
        deadline_or_review: Some(DeadlineOrReview {
            deadline_unix_ms: None,
            review_ref: Some(MAINTENANCE_REVIEW_REF.to_owned()),
        }),
        dedup_key: key.dedup_key.clone(),
        delivery_channels: vec![DeliveryChannel::ControlBoard],
        state_fence: state_fence.clone(),
    };
    serde_json::to_value(&draft).map_err(|error| StoreError::Serialization(error.to_string()))
}

/// Issues the source-verification receipt the upsert leg must carry.
///
/// The receipt records exactly what this daemon observed: one read-only
/// maintenance trigger evaluation under the admitted fence, owned by the
/// maintenance authority, carrying the decision identity as its one artifact
/// and claiming no verification beyond an observation. `ReceiptEnvelope::issue`
/// derives the identity from the canonical core bytes, so this is
/// content-addressed evidence rather than a self-asserted success claim.
///
/// # Errors
///
/// Returns [`StoreError`] when the receipt contract rejects the core or the
/// envelope cannot be serialized.
fn source_receipt_json(
    key: &AutomationFailureKey,
    decision: &AutomationTriggerDecision,
    identity: &RequestIdentity,
    state_fence: &StateFence,
) -> Result<serde_json::Value, StoreError> {
    let core = ReceiptCore {
        contract: eliot_receipts::contract_identity().map_err(StoreError::Receipt)?,
        kind: ReceiptKind::Operation,
        work_scope: WorkScopeBinding {
            scope_id: WorkScopeId::new(key.affected_scope.clone()).map_err(StoreError::Receipt)?,
            product_id: identity.request.metadata.product_id.clone(),
            resource_generation: state_fence.resource_generation,
            state_fence: state_fence.clone(),
        },
        task: None,
        session: None,
        causal: CausalBinding {
            state_fence: state_fence.clone(),
            transaction_sequence: TransactionSequence::genesis(),
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: identity.request.clone(),
        operation: OperationBinding {
            operation_id: OperationId::new(identity.idempotency_key.clone())
                .map_err(StoreError::Foundation)?,
            request_id: identity.request.metadata.request_id.clone(),
            idempotency_key: identity.idempotency_key.clone(),
            operation_kind: MAINTENANCE_OPERATION_KIND.to_owned(),
            effect: eliot_receipts::EffectClass::Read,
            state_fence: state_fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new(format!("{SERVICE_NAME}:maintenance-authority"))
                .map_err(StoreError::Foundation)?,
            authority_owner: key.owner.clone(),
            authority_epoch: state_fence.authority_epoch.clone(),
            state_fence: state_fence.clone(),
            allowed_effect: eliot_receipts::EffectClass::Read,
            proof_ceiling: ProofCeiling::Observation,
        },
        artifacts: vec![ArtifactBinding {
            artifact_id: ArtifactId::new(format!(
                "maintenance-decision-{fingerprint}",
                fingerprint = key.fingerprint
            ))
            .map_err(StoreError::Foundation)?,
            sha256: key.fingerprint.clone(),
            role: ReceiptKind::Artifact,
            source_revision: Some(decision.trigger_id.clone()),
        }],
        // No verifier is claimed: this daemon observed its own owner's
        // deterministic evaluation, it did not verify an external effect.
        verifier: None,
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::Observation,
        },
    };
    let receipt = ReceiptEnvelope::issue(core).map_err(StoreError::Receipt)?;
    serde_json::to_value(&receipt).map_err(|error| StoreError::Serialization(error.to_string()))
}

