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
//! not emit one alert per occurrence." [`AutomationFailureKey`] is therefore
//! the decision's *own* stable identity — `family`, `scope_ref`, `reason`,
//! `decision`, `trigger_id` — and nothing else. No clock, counter, or
//! per-observation value enters the key, so a repeat of the same failure under
//! the same admitted fence yields the same `dedup_key`, and the store's
//! in-transaction revision compare-and-set then UPDATEs that one record (its
//! `occurrences` grows) instead of creating a second one. `scope_ref` carries
//! the authority lineage, epoch sequence, and resource generation, so a new
//! generation is I11.12's own "material revision" and correctly opens its own
//! key instead of mutating a record bound to a superseded fence.
//!
//! # The ordering head is read, never synthesized
//!
//! `CanonicalWriteEnvelope::prepare` *derives* `ordering_scopes` from
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
//! # Why the `ApplyNotificationState` route and not `apply_prepared`
//!
//! `GovernorComposition::commit_canonical` reaches the store through
//! `CanonicalTransitionOwner::commit`, which hardcodes the `apply_prepared`
//! operation name. That route runs the generic `store_apply_operation` checks,
//! which do not include the canonical notification re-checks. The admitted
//! `ApplyNotificationState` route adds exactly what issue #1780 requires: the
//! fixed `NotificationState` class, the fixed `notification-state` scope and
//! its single ordering scope, exactly one named operation, a decodable leg,
//! and a same-fence record read-back after the commit. The submitted payload is
//! the same flat four-field contract `apply_prepared` uses (`context`,
//! `transition`, `expected_revision_heads`, `expected_ordering_heads`) over the
//! same single authenticated daemon transport, so this is the one write path,
//! not a second one.
//!
//! Forbidden authority: no Store or provider client, no retry or default
//! synthesis, no alternative transport, no second notification model, and no
//! decision this module did not receive from its owner.
//!
//! # Source-level observation the integration owner must resolve first
//!
//! Both exchanges this module makes travel the retained daemon transport, which
//! inserts a routing key named `operation` into the JSON body
//! (`daemon_kernel_client/handshake.rs::operation_payload`), while the Kernel
//! routes that decode the **whole** body with `#[serde(deny_unknown_fields)]`
//! reject that key as unknown. Read by source, the affected carriers are
//! `StoreNamedOperation` (the `GetOrderingHeads` read),
//! `NotificationStateApplyOperation` (this write), `StoreApplyOperation`,
//! `StoreRecoveryOperation`, `StoreInitializeGenesisOperation`,
//! `LocalReadOperation`, `GrantActivationOperation`, and the other whole-body
//! carriers in `bins/eliot-kernel/src/daemon_request_dispatch.rs`; each answers
//! `SessionFenced` on its first line. `OwnerPublishOperation` in the same file
//! is the counterexample that fixes the shape: it declares `operation: String`,
//! and its daemon feeder (`owner_feed.rs::publish_owner_bundle`) omits the key
//! from its own body. `daemon_supervision_progress_operation` in the same
//! dispatcher is the other established shape: it removes the routing key before
//! decoding.
//!
//! Both ends are outside this piece's mutable path scope, so this module does
//! not work around them: it is written against the admitted routes exactly as
//! the store contract and the Kernel's own re-checks specify, and it becomes
//! live when the routing key is honored on the carriers above.
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
    CanonicalWriteEnvelope, CompositionError, KernelGenerationSnapshotProvider, KernelPortError,
};
use eliot_kernel_core::{
    DeadlineOrReview, DeliveryChannel, NotificationDraft, NotificationSeverity,
};
use eliot_maintenance::AutomationTriggerDecision;
use eliot_platform::PlatformHandle;
use eliot_protocol::RequestIdentity;
use eliot_receipts::{
    ArtifactBinding, AuthorityBinding, CausalBinding, OperationBinding, ProofCeiling, ReceiptCore,
    ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding, WorkScopeBinding,
    WorkScopeId,
};
use eliot_store_api::{
    CanonicalReadClient, EffectClass, EventProjectionRelationIntents,
    NOTIFICATION_STATE_MUTATION_NAME, NOTIFICATION_STATE_SCOPE, NOTIFY_MUTATION_UPSERT,
    NOTIFY_PARAM_DEDUP_KEY, NOTIFY_PARAM_MUTATION, NOTIFY_PARAM_RECORD_JSON,
    NOTIFY_PARAM_SOURCE_RECEIPT_JSON, NamedReadOperation, NamedReadRequest, OrderingHead,
    OrderingHeadExpectation, OrderingScopeId, PreparedTransition, ReadConsistency,
    RevisionHeadExpectation, ScopeId, SecurityContext, StoreError, TransitionClass, WriteReceipt,
    WriteReceiptStatus,
};
use serde::Serialize;
use thiserror::Error;

use super::{
    DaemonKernelClient, KernelContextReadClient, SERVICE_NAME,
    daemon_kernel_client::kernel_port_error, daemon_kernel_port_adapters::kind_value, unix_ms,
    unix_ms_i64,
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

/// The stable failure fingerprint of one admitted automation decision.
///
/// This is I11.12's "automation revision and failure fingerprint" and nothing
/// else: the decision's own identity, never a fresh value per observation.
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
/// The key is the canonical-JSON digest of exactly `(family, scope_ref,
/// reason, decision, trigger_id)`. Every component is the decision's own stable
/// identity as produced by the Governor-owned evaluator, so two evaluations of
/// the same failure under the same admitted fence yield the same key and
/// therefore update one record.
///
/// # Errors
///
/// Returns [`StoreError`] when a closed maintenance discriminator does not
/// render its declared wire form or the identity cannot be serialized
/// canonically.
pub fn automation_failure_key(
    decision: &AutomationTriggerDecision,
) -> Result<AutomationFailureKey, StoreError> {
    let family = closed_wire_name(decision.family)?;
    let reason = closed_wire_name(decision.reason)?;
    let outcome = closed_wire_name(decision.decision)?;
    let identity = (
        family.as_str(),
        decision.scope_ref.as_str(),
        reason.as_str(),
        outcome.as_str(),
        decision.trigger_id.as_str(),
    );
    let fingerprint = sha256_hex(
        &canonical_json_bytes(&identity)
            .map_err(|error| StoreError::Serialization(error.to_string()))?,
    );
    Ok(AutomationFailureKey {
        dedup_key: format!("automation-{fingerprint}"),
        notification_id: format!("notification-automation-{fingerprint}"),
        subject: format!("blocked maintenance automation {family}"),
        summary: format!(
            "maintenance automation {family} at {} evaluated {outcome} for reason {reason} \
             and admits no job; trigger identity {}",
            decision.scope_ref, decision.trigger_id
        ),
        required_action: format!(
            "restore the absent maintenance Durable Job admission for {family}"
        ),
        fingerprint,
        owner: MAINTENANCE_AUTHORITY_OWNER.to_owned(),
        affected_scope: decision.scope_ref.clone(),
    })
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

/// Persists one persistent canonical notification for an admitted automation
/// decision that could not start.
///
/// The whole owner-side leg runs in the order I1.8 fixes: derive the decision's
/// stable failure fingerprint, read the live ordering head, derive the admitted
/// ingress identity and the source-verification receipt from those same
/// observed facts, prepare the one canonical `PreparedTransition`, and submit
/// it to the admitted `ApplyNotificationState` route — which rechecks the fixed
/// scope, ordering scope, transition class, and closed leg parameters and
/// requires a same-fence record read-back before it reports success.
///
/// A decision that admits a job is not a notification-worthy failure and
/// returns `Ok(None)` without touching the store.
///
/// # Errors
///
/// Returns [`NotificationEmitError`] when the store contract refuses the
/// envelope, the leg parameters, or the ordering-head read; when canonical
/// admission refuses the prepared transition; or when the authenticated Kernel
/// exchange refuses or cannot complete it.
pub async fn emit_blocked_automation_notification(
    kernel: &Arc<DaemonKernelClient>,
    state_fence: StateFence,
    decision: &AutomationTriggerDecision,
) -> Result<Option<NotificationStateEmit>, NotificationEmitError> {
    if decision.admits_job {
        return Ok(None);
    }
    let key = automation_failure_key(decision)?;
    let reads = KernelContextReadClient::new(Arc::clone(kernel));
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
    let transition = notification_transition(
        &identity,
        &operation_text,
        &key,
        record_json,
        source_receipt,
        &ordering_head,
    )?;
    // The submitted expectation is the very value the envelope was prepared
    // from, not a second formatting of it: the prepared transition already
    // carries it inside its derived ordering scopes and its canonical request
    // hash, so any substitution is refused at every recheck.
    let submitted = NotificationCommit {
        context: identity.request.metadata.clone(),
        transition,
        // No revision head is compared: the notification record is not derived
        // from a canonical revision head, and the store's revision advance for
        // the fixed notification scope is driven by the ordering head alone.
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![ordering_head],
    };
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

/// The exact four-field flat apply contract the admitted Kernel route decodes.
///
/// Mirrors `bins/eliotd/src/kernel_transition_client.rs`'s `apply_prepared`
/// payload field-for-field; grouping it keeps the submitted head the same value
/// the envelope was prepared from.
struct NotificationCommit {
    context: RequestMetadata,
    transition: PreparedTransition,
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
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

/// Prepares the one canonical `NotificationState` transition for this commit.
///
/// The envelope is the owner-side proposal only: `CanonicalWriteEnvelope::
/// prepare` derives the ordering scopes from the submitted head, binds the
/// issue-#18 digests, and returns the single `PreparedTransition` that Kernel
/// and the store bridge execute. `task_id` stays `None` because a notification
/// record is not task-bound, which is also what keeps this leg out of the
/// task-scope and `CaptureObservation` admission rules.
///
/// # Errors
///
/// Returns [`StoreError`] when the envelope inputs are refused, and
/// [`CompositionError`] when canonical admission refuses the prepared
/// transition — projected on the same owner channel
/// `eliot_governor::commit_experience_bank` uses, because `eliot-canonical` is
/// not a direct dependency of this composition root and no second canonical
/// dependency path is added for one error type.
fn notification_transition(
    identity: &RequestIdentity,
    operation_text: &str,
    key: &AutomationFailureKey,
    record_json: serde_json::Value,
    source_receipt: serde_json::Value,
    ordering_head: &OrderingHeadExpectation,
) -> Result<PreparedTransition, NotificationEmitError> {
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
    let envelope = CanonicalWriteEnvelope {
        operation_id: OperationId::new(operation_text).map_err(StoreError::Foundation)?,
        request: identity.request.metadata.clone(),
        idempotency_key: identity.idempotency_key.clone(),
        scope_id: ScopeId::new(NOTIFICATION_STATE_SCOPE)?,
        task_id: None,
        transition_class: TransitionClass::NotificationState,
        // Exactly the class maximum, never a wider ceiling.
        requested_effect_ceiling: EffectClass::ReversibleMutation,
        // The admitted semantic contract set for this notification is exactly
        // the decision's own identity, so its digest is that identity's
        // canonical-JSON digest — the same value the record's evidence handle
        // and the source receipt's artifact carry.
        admission_contract_set_digest: key.fingerprint.clone(),
        operation_manifest_digest: eliot_store_api::operation_manifest_set_digest(
            &eliot_store_api::generated_operation_manifests()?,
        )?,
        // Exactly one named command: the closed upsert leg.
        semantic_commands: vec![eliot_store_api::notification_mutation_request(parameters)],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        // Proof/approval handles are an erasure-only requirement; this
        // reversible class carries none.
        required_proof_and_approval_refs: Vec::new(),
        // No semantic source revisions: the notification record is not derived
        // from a canonical revision head, and declaring one would bind a head
        // this transition does not compare-and-swap.
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: vec![ordering_head.clone()],
    };
    envelope.prepare().map_err(|error| {
        NotificationEmitError::Admission(CompositionError::Owner(error.to_string()))
    })
}
