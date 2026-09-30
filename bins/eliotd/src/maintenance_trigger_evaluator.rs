//! Production call site for the Governor-owned maintenance trigger
//! evaluator (I14.22, issue #1688).
//!
//! The evaluator itself is **not** defined here.
//! [`eliot_maintenance::MaintenanceController::evaluate_trigger`] already
//! implements the whole deterministic decision surface, and the Governor
//! already composes exactly one instance of it as
//! [`eliot_governor::GovernorOwners::maintenance`]. This module is the
//! `eliotd` seam that reaches that one owner from the daemon's real durable
//! runtime path and turns the typed [`AutomationTriggerDecision`] into an
//! inspectable record.
//!
//! Three properties are load-bearing here:
//!
//! * **Single producer.** The decision comes from the composed Governor owner
//!   through `owners().maintenance`. This module never constructs a
//!   [`MaintenanceController`], never re-implements a mode, a family or a
//!   decision vocabulary, and never adds a queue, a scheduler, a timer thread
//!   or a background maintenance loop. Evaluation is a pure read of the
//!   owner's decision over an input this daemon observed.
//! * **No fabricated authority.** Every
//!   [`MaintenanceTriggerInput`] field is filled from something this daemon
//!   genuinely observed — the live admitted fence, the validated Kernel-issued
//!   owner session, the activation flight state, the caller-carried evidence
//!   identities — or is deliberately held at its fail-closed value because the
//!   owning authority for it does not exist yet. Those held fields are named in
//!   [`UNRESOLVED_AUTHORITIES`] and are the reason several decision values are
//!   unreachable today; they are never guessed.
//! * **Typed end to end.** A rejected evaluation propagates the Governor's own
//!   [`MaintenanceError`] through [`DaemonError::Maintenance`]; it is never
//!   stringified into a lifecycle or transport message.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::Arc;

use eliot_contracts::{OperationId, canonical_json_bytes, sha256_hex};
use eliot_governor::{CompositionError, KernelPortError, KernelTransitionPort};
use eliot_maintenance::{
    AutomationTriggerDecision, CONTRACT_NAME, CONTRACT_VERSION, MaintenanceBrokerEvidence,
    MaintenanceBudgetEvidence, MaintenanceError, MaintenanceFamily, MaintenancePolicyEvidence,
    MaintenanceResultObligation, MaintenanceRouteEvidence, MaintenanceSafetyEvidence,
    MaintenanceScheduleEvidence, MaintenanceTrigger, MaintenanceTriggerInput,
    maintenance_observation_record,
};
use eliot_protocol::{
    MAINTENANCE_TRIGGER_ACK_WIRE_ID, MAINTENANCE_TRIGGER_ACK_WIRE_VERSION,
    MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_ID,
    MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_VERSION, MaintenanceTriggerAck, MaintenanceTriggerClaim,
    MaintenanceTriggerDecisionReceipt, MaintenanceTriggerGapKind,
    MaintenanceTriggerPendingSummary, MaintenanceTriggerRecord, ProtocolError,
};
use eliot_store_api::{StoreError, WriteReceiptStatus};
use thiserror::Error;

use super::DaemonComposition;
use super::DaemonError;
use super::DaemonKernelClient;
use super::notification_state_emit::{
    MaintenanceNotificationEvidence, NotificationEmitError, NotificationStateEmit,
    emit_blocked_automation_notification,
};

/// The maintenance families whose policy owner this daemon cannot yet resolve,
/// as one constant a reader can inspect instead of a scattered `false`.
///
/// Every field held below is held **fail-closed**, never permissively:
///
/// | Held field | Value | Why it is not `true` | Owning issue |
/// |---|---|---|---|
/// | `mode` | [`Off`](eliot_maintenance::MaintenanceAutomationMode::Off) | No Human maintenance-policy owner exists in `eliotd`; `eliot-config` owns only a one-shot *first-run* decision that the daemon runtime never reads. `Off` is I14.22's own "no automatic job or proactive recommendation" value, so an unresolved policy denies automation instead of defaulting to permissive. Since #1693 the catalog in [`maintenance_family_catalog`] is the single place that states the selected mode per registered family, and this seam reads it from there rather than repeating the literal. | #1692, #1693 |
/// | `scheduled_window` | `false` | `eliotd` holds no Host wake / Task Scheduler occurrence. Inventing a window is exactly the "locally invented occurrence" #1692 forbids. | #1692 |
/// | `route_available` | `false` | No maintenance route/credential owner publishes a service-safe route to this daemon. | #1692 |
/// | `budget_available` | `false` | No maintenance budget/quota owner publishes one. | #1692 |
/// | `user_session_required` | `false` | The `interactive_maintenance` policy that would set it does not exist here. Held `false` grants nothing: `route_available` is already `false`, so no route can be selected. | #1692 |
/// | `user_session_available` | `false` | The authenticated daemon transport is not User Broker registration/lease evidence, and Kernel exposes no current broker-status query to this caller. | #1692, #23 |
/// | `explicit_request` | `false` | `eliotd` exposes no authenticated Human UI/CLI maintenance-request ingress; an untrusted flag is not a request. | #1692 |
/// | `safety_required` | `false` | No owner publishes a verified mandatory safety/recovery obligation to this daemon, and the flag must never be asserted to bypass authentication. | #1692 |
/// | `active_job_id` | `None` | [`MaintenanceController`] exposes no probe for an existing active job, so duplicate suppression cannot be fed. | #1694 |
/// | `expires_at_ms` | `None` | No expiry policy is published to this daemon. | #1694 |
///
/// `user_session_available` remains false until the Kernel's User Broker
/// owner exposes a current authenticated registration/lease observation.
pub const UNRESOLVED_AUTHORITIES: &str = "mode,scheduled_window,route_available,budget_available,user_session_required,user_session_available,explicit_request,safety_required,active_job_id,expires_at_ms";

/// The durable maintenance trigger origins this daemon can genuinely observe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceTriggerOrigin {
    /// Governor owner recovery finished; the freshly rebuilt owners must be
    /// reconciled for pending maintenance at the current fence.
    StartupReconciliation,
    /// The declared startup binding ledger completed, so the obligations that
    /// only exist once the daemon is whole became visible.
    ColdStartCompletion,
    /// An admitted store-health observation arrived on the health heartbeat.
    AdmittedObservation,
    /// The activation poll observed no in-flight admitted activation, so no
    /// conflicting interactive work owns the scope.
    IdleTransition,
}

impl MaintenanceTriggerOrigin {
    /// Stable wire name. Part of the deterministic trigger identity, so it is
    /// fixed text rather than anything derived from the clock or a counter.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StartupReconciliation => "STARTUP_RECONCILIATION",
            Self::ColdStartCompletion => "COLD_START_COMPLETION",
            Self::AdmittedObservation => "ADMITTED_OBSERVATION",
            Self::IdleTransition => "IDLE_TRANSITION",
        }
    }

    /// I14.22's job-origin classification for this trigger.
    ///
    /// `StartupReconciliation` and `IdleTransition` are approved
    /// policy-driven occurrences ("Human-approved idle/scheduled policy"),
    /// `ColdStartCompletion` is a first-run/onboarding occurrence, and
    /// `AdmittedObservation` is an admitted problem/signal occurrence
    /// (Watchdog/Doctor problem recipe). The I14.22 origin enum has no
    /// finer-grained member than these four, so the mapping is exhaustive.
    #[must_use]
    const fn maintenance_trigger(self) -> MaintenanceTrigger {
        match self {
            Self::StartupReconciliation | Self::IdleTransition => MaintenanceTrigger::Policy,
            Self::ColdStartCompletion => MaintenanceTrigger::Onboarding,
            Self::AdmittedObservation => MaintenanceTrigger::WatchdogProblem,
        }
    }
}

/// Facts this daemon genuinely observed, and nothing it inferred.
///
/// Every other input field is observed by the composition itself (the live
/// admitted fence, the retained Kernel-issued owner session, the wall clock)
/// so a caller cannot pass a stale fence or claim a session it never had.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MaintenanceObservation {
    /// Which durable event produced this evaluation.
    pub origin: MaintenanceTriggerOrigin,
    /// The registered family this trigger concerns.
    ///
    /// #1693 owns the per-family catalog in [`maintenance_family_catalog`], and
    /// this seam resolves every family through it. The family still arrives
    /// from the caller because it is the caller's real observation: the
    /// catalog decides the mode, the conditions, the deduplication scope and
    /// the route for a family, but it cannot invent which family an observed
    /// signal concerns.
    pub family: MaintenanceFamily,
    /// Real evidence identities observed at the call site.
    ///
    /// Must be non-empty and duplicate-free: the evaluator rejects an empty
    /// evidence set, so a trigger with no observed evidence fails closed
    /// instead of being treated as maintenance-relevant.
    pub evidence_refs: Vec<String>,
    /// Whether an admitted activation is in flight right now.
    pub activation_in_flight: bool,
}

impl DaemonComposition {
    /// Evaluates one durable maintenance trigger through the Governor-owned
    /// evaluator and returns its typed decision (I14.22, issue #1688).
    ///
    /// Readiness is checked first, mirroring every other composition seam, so
    /// the decision is only ever produced on the admitted path. The input is
    /// built from live observations and the composed owner's
    /// [`MaintenanceController`] does the deciding; this method adds no policy.
    ///
    /// Since #1693 the per-family facts are read from the registered
    /// maintenance-family catalog instead of being restated here: the selected
    /// automation mode and the idempotency/deduplication scope both come from
    /// the family's own entry, and the entry records the resolved route
    /// alongside the decision. The catalog does not loosen any gate below and
    /// does not choose the family; it only supplies what the family owns.
    ///
    /// The decision is emitted through the existing minimal operational
    /// diagnostics by
    /// [`emit_maintenance_trigger_decision`](crate::diagnostics::emit_maintenance_trigger_decision)
    /// on every successful evaluation, and the catalog's route and its one
    /// actionable recommendation are emitted next to it, so the decision is
    /// inspectable whether or not the caller keeps the returned value.
    ///
    /// # Errors
    ///
    /// [`DaemonError::Composition`] when the Governor is not ready, or
    /// [`DaemonError::Maintenance`] carrying the owner's own
    /// `MaintenanceError` unchanged.
    pub fn evaluate_maintenance_trigger(
        &self,
        observation: MaintenanceObservation,
    ) -> Result<AutomationTriggerDecision, DaemonError> {
        self.evaluate_maintenance_trigger_with_evidence(observation)
            .map(|(decision, _)| decision)
    }

    /// Evaluates one trigger and retains the exact policy and route evidence
    /// that the canonical notification owner needs for its failure identity.
    ///
    /// # Errors
    ///
    /// Returns the same readiness or maintenance error as
    /// [`Self::evaluate_maintenance_trigger`].
    pub fn evaluate_maintenance_trigger_with_evidence(
        &self,
        observation: MaintenanceObservation,
    ) -> Result<(AutomationTriggerDecision, MaintenanceNotificationEvidence), DaemonError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(DaemonError::Composition(
                eliot_governor::CompositionError::NotReady,
            ));
        }
        // The registered entry for the observed family. The lookup is total
        // over `MaintenanceFamily`, so no family can be unregistered here and
        // no caller-supplied family is ever treated as unrecognised.
        let entry = crate::maintenance_family_catalog::entry_for(observation.family);
        // The live admitted fence is read here, never taken from the caller:
        // a transported fence claim is not a current observation.
        let state_fence = self.governor.kernel_snapshot().state_fence().clone();
        let scope_ref = scope_ref_for(&state_fence);
        // The trigger identity is the catalog's canonical deduplication key,
        // so the identity that duplicate suppression compares states which
        // family, event, scope, subset and generation it is, and
        // `MaintenanceController::admit`'s job identity inherits it. The board
        // lookup and the job lookup both consume this same key. This daemon
        // observes no subset identity, so a `FamilyScopeAndSubset` trigger
        // fails closed here rather than coalescing work across subsets it
        // cannot distinguish.
        let trigger_id = entry.dedup.dedup_key(
            &crate::maintenance_family_catalog::MaintenanceDedupIdentity {
                family: observation.family,
                origin: observation.origin.as_str(),
                scope_ref: &scope_ref,
                subset_ref: None,
                resource_generation: state_fence.resource_generation.value(),
            },
        )?;
        let (input, notification_evidence) = {
            // Owner evidence for every gate (I14.22/I14.24, issue #1692). Each
            // value is derived from a Governor-owned evidence owner or held at
            // its fail-closed value because the owning authority does not
            // exist yet (`UNRESOLVED_AUTHORITIES`, and the module-level
            // table); no caller-supplied flag enters the input, so a forged
            // mode/safety/session flag grants nothing. The Human policy owner
            // is unpublished, so the policy evidence records unpublished
            // provenance (no revision/digest, no override provenance, no
            // separate `interactive_maintenance` permission, no effect/budget
            // ceilings) around the registry-selected mode, which is `Off` for
            // every family while no publisher exists; the mode value itself
            // comes from the registered catalog, so no second mode source is
            // invented. The five non-Off modes are enforced by
            // `MaintenanceController::evaluate_trigger` and become reachable
            // only when a publisher appears. The transport session this
            // composition retains is explicitly not User Broker evidence.
            // No accepted Kernel owner query supplies the broker
            // registration/lease/revocation state, so the interactive session
            // gate remains unavailable.
            let policy = MaintenancePolicyEvidence::unpublished(
                entry.mode,
                observation.family,
                scope_ref.clone(),
            );
            let route = MaintenanceRouteEvidence::unpublished();
            let budget = MaintenanceBudgetEvidence::unpublished();
            let schedule = MaintenanceScheduleEvidence::unpublished();
            let broker = MaintenanceBrokerEvidence::owner_query_unavailable();
            let safety = MaintenanceSafetyEvidence::unpublished();
            let input = MaintenanceTriggerInput {
                trigger_id,
                evidence_refs: observation.evidence_refs,
                family: observation.family,
                scope_ref,
                mode: policy.mode(),
                trigger: observation.origin.maintenance_trigger(),
                explicit_request: false,
                // The one gate read from a real observation.
                idle: !observation.activation_in_flight,
                scheduled_window: schedule.is_current_window(),
                route_available: route.is_service_safe(),
                budget_available: budget.has_budget(),
                // Fail closed until the Kernel owner supplies a current
                // authenticated broker registration/lease observation.
                user_session_available: broker.authenticated_session_available(),
                user_session_required: policy.requires_interactive_session(),
                safety_required: safety.is_required(),
                now_ms: crate::unix_ms_i64(),
                expires_at_ms: None,
                active_job_id: None,
            };
            (input, MaintenanceNotificationEvidence { policy, route })
        };
        let decision = self
            .governor
            .owners()
            .maintenance
            .evaluate_trigger(&input)?;
        let _ = crate::diagnostics::emit_maintenance_trigger_decision(&input, &decision);
        // The catalog's half of the record: which registered family this was,
        // where its start would have to go, and the exact unavailable
        // dependency or absent Durable Job route that stops it today. A
        // triggered family is therefore never silently ignored, and no family
        // is ever reported as having run.
        //
        // The observed evidence is bound separately from the Governor
        // projection: the trigger event, the evidence identities actually
        // seen at this call site, and the selected policy revision travel
        // beside the decision rather than being projected from the catalog's
        // requirement lists, and each missing binding stays explicit.
        let observed = crate::maintenance_family_catalog::MaintenanceObservedEvidence {
            trigger_event: observation.origin.as_str(),
            observed_refs: input.evidence_refs.clone(),
            policy_revision: notification_evidence.policy.revision,
        };
        let family_decision = entry.record_start_route(&decision, observed);
        crate::maintenance_dispatch::MaintenanceDispatch::for_decision(&decision, &family_decision)
            .record(&decision);
        Ok((decision, notification_evidence))
    }

    /// Evaluates one durable maintenance trigger and never fails the caller.
    ///
    /// This is the entry the daemon runtime loop uses. A trigger that cannot
    /// be evaluated — the Governor is not ready yet, or the owner rejected the
    /// input — is recorded as an explicit typed gap through the same minimal
    /// operational diagnostics and the daemon continues. A maintenance
    /// observation is never allowed to become a startup gate, a readiness
    /// gate, or a silent drop: I14.22 keeps the trigger durable and surfaces
    /// it on the next eligible startup instead.
    pub fn note_maintenance_trigger(&self, observation: MaintenanceObservation) {
        if let Err(error) = self.evaluate_maintenance_trigger(observation) {
            let _ = crate::diagnostics::ErrorRecord::of_daemon_error(&error).emit();
        }
    }
}

/// What the publication of one maintenance source result actually did.
///
/// Every terminal store receipt is returned as issued. `Reconciled` is a real
/// publication proven by the exact store receipt, and it is the same value a
/// first attempt returns for an identical retry — the store identity, not this
/// enum, is what distinguishes a replay from a first commit. There is no
/// "logged" or "attempted" variant: a diagnostic line is never publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceResultPublication {
    /// The canonical observation is admitted and the exact store receipt is in
    /// hand, whether by the first commit or by reconciling an identical retry.
    Reconciled {
        /// The exact store receipt the canonical owner returned.
        receipt: eliot_store_api::WriteReceipt,
    },
}

/// Bounded absolute deadline applied to one maintenance result publication, in
/// Unix milliseconds, matching the retained daemon transport's own operation
/// bound used by the notification commit beside it.
const MAINTENANCE_RESULT_PUBLISH_DEADLINE_MS: u64 = 30_000;

/// Derives the admitted publication identity for one maintenance source result.
///
/// The identity is the daemon's own ingress identity at the live admitted fence,
/// with the source result's own publication identity as the idempotency key. It
/// is therefore a pure function of the source event: an identical retry produces
/// byte-equal identity bytes, so the store's
/// `(operation_id, canonical_request_hash)` identity reconciles the retry onto
/// the first commit instead of writing a second record, and a changed result
/// under the same identity fails closed. No clock-derived value, per-call
/// counter, or caller-supplied source enters the key.
///
/// The source and product identities are bound to the daemon service name
/// because `KernelStoreGateway::apply` fences any other caller: a substituted
/// source would be refused rather than written.
///
/// # Errors
///
/// Returns [`ProtocolError::InvalidField`] when the publication identity is not
/// a valid contract value or the derived request metadata does not validate.
fn publication_identity(
    publication_id: &str,
    state_fence: &eliot_contracts::StateFence,
) -> Result<eliot_protocol::RequestIdentity, ProtocolError> {
    let now = crate::unix_ms_i64();
    let operation_text = format!(
        "{}:maintenance-result:{publication_id}",
        crate::SERVICE_NAME
    );
    let invalid = |field: &'static str| ProtocolError::InvalidField {
        field,
        reason: "maintenance result publication identity is not a valid contract value",
    };
    let metadata = eliot_contracts::RequestMetadata {
        request_id: eliot_contracts::RequestId::new(operation_text.clone())
            .map_err(|_| invalid("maintenance_result.request_id"))?,
        session_id: None,
        task_id: None,
        product_id: eliot_contracts::ProductId::new(crate::SERVICE_NAME)
            .map_err(|_| invalid("maintenance_result.product_id"))?,
        source_id: eliot_contracts::SourceId::new(crate::SERVICE_NAME)
            .map_err(|_| invalid("maintenance_result.source_id"))?,
        // The live admitted fence, read from the retained Governor snapshot and
        // never taken from the caller: a transported or cached fence must not be
        // able to substitute for the one the result is admitted under.
        state_fence: state_fence.clone(),
        clock: eliot_contracts::ClockReading {
            valid_time_ms: Some(now),
            known_time_ms: Some(now),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    metadata
        .validate()
        .map_err(|_| invalid("maintenance_result.request_metadata"))?;
    Ok(eliot_protocol::RequestIdentity {
        request: eliot_receipts::RequestBinding {
            metadata,
            state_fence: state_fence.clone(),
        },
        idempotency_key: operation_text,
        deadline_unix_ms: crate::unix_ms().saturating_add(MAINTENANCE_RESULT_PUBLISH_DEADLINE_MS),
        cancellation_id: format!(
            "{}:maintenance-result:{publication_id}:cancel",
            crate::SERVICE_NAME
        ),
    })
}

/// Fail-closed refusals of the maintenance result publication path.
///
/// [`DaemonError`] already carries this composition's canonical-admission
/// (`CompositionError`) and maintenance-owner (`MaintenanceError`) refusals as
/// its own typed variants, so those are reused rather than restated here; this
/// enum adds only the protocol-identity refusal the daemon composition does not
/// already own. Nothing is folded into prose between layers, and no refusal is
/// reported as a publication.
#[derive(Debug, Error)]
pub enum MaintenanceResultPublishError {
    /// The publication identity or its base operation is not a valid contract
    /// value.
    #[error("maintenance result publication protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// The canonical route returned a terminal receipt that did not commit, so
    /// the observation was not admitted and the obligation stays owed.
    #[error(
        "maintenance result was not admitted: publication {publication_id} returned {status:?} for {operation_id}"
    )]
    NotAdmitted {
        /// The stable publication identity that was offered.
        publication_id: String,
        /// The exact operation the store issued the terminal receipt for.
        operation_id: OperationId,
        /// The terminal store status, exactly as issued.
        status: WriteReceiptStatus,
    },
    /// The composition, the canonical admission, or the maintenance owner
    /// refused the publication, each in its own typed variant.
    #[error("maintenance result publication: {0}")]
    Daemon(#[from] DaemonError),
}

impl DaemonComposition {
    /// Publishes one maintenance source result into the canonical observation
    /// path and returns the exact store receipt.
    ///
    /// This is the production caller of
    /// `observation_adapters::ForwardingObservationReconciliation::admit_maintenance_result`.
    /// The maintained subsystem's owner produces the obligation, the owner
    /// validates and projects it into the observation-family record, the
    /// Governor checks authority, fence and identity, and the Store returns its
    /// own receipt. The publication identity comes from the source event, so an
    /// identical retry reconciles the existing receipt instead of writing a
    /// second record, and a lost acknowledgement is read back through the same
    /// operation rather than committed again.
    ///
    /// This covers every applicable source result, not only the success branch:
    /// a completion, a bounded partial, a failure, a cancellation, an unknown
    /// outcome and a no-attempt non-execution decision each publish here, and a
    /// failure or an unknown is never dropped for not being a success. A later
    /// reconciliation appends a linked obligation rather than replacing the
    /// earlier one, so the original uncertainty stays visible next to its
    /// resolution.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceResultPublishError`] when the composition is not
    /// ready, the owner refuses the obligation or the record it projects, the
    /// publication identity is not a contract value, or the canonical commit
    /// cannot be completed or reconciled. Every one of those is a refusal, not a
    /// publication, and the caller keeps the obligation durable for the retry.
    pub async fn publish_maintenance_result(
        &self,
        base_operation_text: &str,
        obligation: &MaintenanceResultObligation,
    ) -> Result<MaintenanceResultPublication, MaintenanceResultPublishError> {
        let observed_at_unix_ms = u64::try_from(crate::unix_ms_i64()).unwrap_or_default();
        // The record is built and validated by the maintained subsystem's own
        // owner before it reaches the canonical route, so a malformed obligation
        // never becomes a store write. The owner's own refusal travels on the
        // daemon's existing typed maintenance channel unchanged.
        let record = maintenance_observation_record(obligation, observed_at_unix_ms)
            .map_err(DaemonError::Maintenance)?;
        let base_operation = OperationId::new(base_operation_text.to_owned()).map_err(|_| {
            ProtocolError::InvalidField {
                field: "maintenance_result.base_operation",
                reason: "maintenance result base operation is not a valid contract value",
            }
        })?;
        // The live admitted fence is read here, never taken from the caller.
        let live_fence = self.governor.kernel_snapshot().state_fence().clone();
        let identity = publication_identity(&obligation.publication_id, &live_fence)?;
        // The canonical route's own admission refusal is a
        // `CompositionError`, and this enum reuses [`DaemonError::Composition`]
        // to carry it unchanged rather than restating the cause or reducing it
        // to prose. The readiness refusal of `observation_reconciliation` and
        // the admission refusal below therefore stay distinguishable by variant.
        let receipt = self
            .observation_reconciliation()?
            .admit_maintenance_result(&identity, &base_operation, &record)
            .await
            .map_err(DaemonError::Composition)?;
        // A terminal non-committed receipt is not publication. The route
        // returns every terminal status exactly as issued, so this is where a
        // rejected or dead-lettered observation stops being an admission: it
        // never becomes a receipt the maintenance owner could record as one.
        if receipt.status != WriteReceiptStatus::Committed {
            return Err(MaintenanceResultPublishError::NotAdmitted {
                publication_id: obligation.publication_id.clone(),
                operation_id: receipt.operation_id,
                status: receipt.status,
            });
        }
        Ok(MaintenanceResultPublication::Reconciled { receipt })
    }

    /// Admits the canonical receipt for one published maintenance result onto
    /// the retained durable job revision.
    ///
    /// This is the production call that makes the second of the three states
    /// durable: the maintenance owner already recorded that the work happened
    /// and that an observation was owed, and this records that the observation
    /// was admitted, under the exact receipt the store returned. It settles
    /// only the delivery state — never the lifecycle state, the outcome
    /// reference, or any earlier obligation — so a receipt cannot rewrite the
    /// execution history it observes, and no outcome is ever written here.
    ///
    /// Replaying the same receipt is a reconciliation and persists nothing; a
    /// different receipt under one identity is refused by the owner as a
    /// conflict rather than replacing the first admission.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceResultPublishError`] when the composition is not
    /// ready or the retained-job write is refused. The maintenance owner's own
    /// refusal travels unchanged inside [`DaemonError::Composition`], so a
    /// dangling publication identity stays distinguishable from a transport
    /// failure.
    pub fn admit_maintenance_observation_receipt(
        &mut self,
        job_id: &str,
        publication_id: &str,
        observation_receipt_ref: &str,
    ) -> Result<eliot_maintenance::MaintenanceJob, MaintenanceResultPublishError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(MaintenanceResultPublishError::Daemon(
                DaemonError::Composition(CompositionError::NotReady),
            ));
        }
        self.governor
            .admit_maintenance_observation_receipt(job_id, publication_id, observation_receipt_ref)
            .map_err(|error| MaintenanceResultPublishError::Daemon(DaemonError::Composition(error)))
    }

    /// Records the explicit coverage gap for one maintenance result writeback
    /// the canonical route refused with a terminal non-committed receipt.
    ///
    /// This is the production call that keeps a refused writeback from
    /// disappearing. The obligation is already durable on the maintenance
    /// store, so nothing is lost either way — but a `Pending` obligation is
    /// indistinguishable from one that was never attempted, and the daemon has
    /// no other durable place to say "the store refused this exact publication
    /// and here is the gap". This settles that on the same Kernel durable-job
    /// ledger the transitions already write through.
    ///
    /// `refused_operation_id` and `refused_status` must be the exact values
    /// [`MaintenanceResultPublishError::NotAdmitted`] carries. A readiness or
    /// transport refusal produced no terminal receipt and must not call this:
    /// the owner has no `Committed` member in its refusal vocabulary precisely
    /// so an admission cannot be recorded twice, once as a receipt and once as
    /// a gap.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceResultPublishError::Daemon`] with
    /// [`DaemonError::Composition`] when the composition is not ready or the
    /// retained-job write is refused. The maintenance owner's own refusal
    /// travels unchanged inside that variant, so a dangling publication
    /// identity and an already-admitted observation stay distinguishable from a
    /// transport failure.
    pub fn record_maintenance_observation_gap(
        &mut self,
        job_id: &str,
        publication_id: &str,
        refused_operation_id: &str,
        refused_status: eliot_maintenance::RefusedReceiptStatus,
    ) -> Result<eliot_maintenance::MaintenanceJob, MaintenanceResultPublishError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(MaintenanceResultPublishError::Daemon(
                DaemonError::Composition(CompositionError::NotReady),
            ));
        }
        self.governor
            .record_maintenance_observation_gap(
                job_id,
                publication_id,
                refused_operation_id,
                refused_status,
            )
            .map_err(|error| MaintenanceResultPublishError::Daemon(DaemonError::Composition(error)))
    }
}

/// Builds the affected-scope identity from the live admitted fence.
///
/// The scope is the canonical generation the evaluation actually runs under:
/// the authority lineage plus its sequence and the resource generation. It
/// carries no clock, counter or process-local value, so the same admitted
/// fence always yields the same scope and therefore the same trigger identity.
fn scope_ref_for(state_fence: &eliot_contracts::StateFence) -> String {
    format!(
        "{}:{}@{}:{}",
        crate::SERVICE_NAME,
        state_fence.authority_epoch.lineage_id,
        state_fence.authority_epoch.sequence.get(),
        state_fence.resource_generation.value()
    )
}

/// The family this daemon's wired trigger sites name for its OWN health and
/// maintenance debt.
///
/// Every trigger origin that observes the daemon's own admitted health and
/// maintenance debt concerns exactly what I14.22's `SelfQualityDebt` family
/// ("self-quality, feedback and maintenance-debt review") covers, so the idle
/// cadence trigger and the admitted store-health observation name it
/// unconditionally. It is also the family the startup and improvement-intake
/// sites name when their own declared-capability evidence shows no gap; when a
/// gap IS observed they name `MaintenanceFamily::DonorConformance` instead,
/// through the daemon runtime's own `conformance_observed_family` (issue
/// #1867 W2/A1). The family is therefore no longer one constant for every
/// site, and this one is no longer a stand-in for families the daemon has no
/// observation for.
///
/// #1693 supplied the registered per-family catalog, so this is no longer a
/// catalog limit: `MaintenanceFamily` carries all fifteen families and
/// [`maintenance_family_catalog::entry_for`] resolves any of them, and
/// [`DaemonComposition::evaluate_maintenance_trigger`] routes whichever one the
/// caller observes. This constant remains the family the daemon's own
/// observable health-and-debt trigger sites name, because the family is the
/// caller's real observation and the catalog must not invent which family an
/// observed signal concerns.
pub const SELF_OBSERVED_FAMILY: MaintenanceFamily = MaintenanceFamily::SelfQualityDebt;

/// Fail-closed refusals of the owner-side maintenance decision commit.
///
/// Every variant keeps its owner's own typed failure: the store contract
/// refusal stays a [`StoreError`], canonical admission stays a
/// [`CompositionError`], the authenticated exchange stays a
/// [`KernelPortError`], the maintenance owner refusal stays a
/// [`MaintenanceError`], and wire validation stays a [`ProtocolError`]. The
/// daemon composition refusal stays a [`DaemonError`] unchanged, so readiness
/// and evaluation denials keep their exact shape. No code is folded into
/// prose between layers.
#[derive(Debug, Error)]
pub enum MaintenanceDecisionCommitError {
    /// The store contract refused the intent commit, the commit receipt, or
    /// the bound decision receipt inputs.
    #[error("maintenance decision commit store: {0}")]
    Store(#[from] StoreError),
    /// Governor-owned canonical admission refused the commit.
    #[error("maintenance decision commit admission: {0}")]
    Admission(#[from] CompositionError),
    /// The authenticated Kernel exchange refused or could not complete the
    /// intent commit or the receipt read-back.
    #[error("maintenance decision commit transport: {0}")]
    Kernel(#[from] KernelPortError),
    /// The maintenance owner refused the commit bindings (stale fence or
    /// claim, or a malformed binding identity).
    #[error("maintenance decision commit owner: {0}")]
    Maintenance(#[from] MaintenanceError),
    /// The retained record, the claim, or the bound receipt failed wire
    /// validation, or the evaluated decision answers a different trigger.
    #[error("maintenance decision commit protocol: {0}")]
    Protocol(#[from] ProtocolError),
    /// The daemon composition refused the commit (not ready, not
    /// authenticated, or the owner's own evaluation denial).
    #[error("maintenance decision commit daemon: {0}")]
    Daemon(#[from] DaemonError),
}

impl DaemonComposition {
    /// Commits one retained maintenance trigger decision before any delivery
    /// acknowledgement (I14.22, issue #1694 W4).
    ///
    /// The authenticated daemon resolves the current #1692 policy and the
    /// #1688 decision by reusing
    /// [`Self::evaluate_maintenance_trigger_with_evidence`]: no policy or
    /// evaluation logic is restated here. The durable downstream intent is
    /// retained through its existing outbox owner — the canonical
    /// notification leg for a decision that cannot start — which submits the
    /// Governor `PreparedTransition` to the admitted `ApplyNotificationState`
    /// route over the same authenticated daemon transport (Governor
    /// `PreparedTransition` → Kernel → named Store transaction, I1.8). The
    /// returned [`MaintenanceTriggerDecisionReceipt`] binds the retained
    /// trigger identity and operation hash, the claim row revision, the
    /// evaluator and policy revisions, the affected scope, the
    /// job/recommendation/wake intent references, and the canonical Store
    /// receipt identity with the digest of its exact bytes.
    ///
    /// A decision plus a durable downstream intent is distinct from an
    /// executed job or a delivered notification: this method never admits or
    /// starts a job and never delivers anything. It only records the
    /// commitment the Kernel ledger must validate before acknowledging the
    /// trigger.
    ///
    /// The commit is explicit about what it cannot do yet, and invents
    /// nothing in its place:
    ///
    /// * `Ok(None)` means no durable intent was admitted — automation is off,
    ///   the intent record already stands, or the only intent names a job
    ///   whose canonical commit receipt is not in hand. The trigger stays
    ///   retained under its existing claim; nothing is dropped and no receipt
    ///   is fabricated. Recording that bound receipt into the Kernel delivery
    ///   ledger travels the follow-up daemon-to-Kernel decision route.
    /// * A lost or ambiguous commit receipt read-back is also `Ok(None)`:
    ///   receipt absence during an outage is not proof of non-commit, so the
    ///   trigger stays open for receipt-lookup reconciliation instead of
    ///   being reported either way.
    /// * No wake intent is bound: no wake scheduler publishes to this daemon,
    ///   so `wake_ref` stays `None` rather than naming an owner that does not
    ///   exist. Trigger expiry enforcement stays with the Kernel ledger
    ///   acknowledgement, which refuses stale eligibility; this commit binds
    ///   the live fence and the live claim deadline only.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] keeping each owner's typed
    /// refusal: stale fence or claim deadline, unknown or conflicting trigger
    /// identity, evaluation denial, intent-commit refusal, or an unbound
    /// commit receipt.
    pub async fn commit_maintenance_trigger_decision(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        observation: MaintenanceObservation,
        record: &MaintenanceTriggerRecord,
        claim: &MaintenanceTriggerClaim,
    ) -> Result<Option<MaintenanceTriggerDecisionReceipt>, MaintenanceDecisionCommitError> {
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(MaintenanceDecisionCommitError::Admission(
                CompositionError::NotReady,
            ));
        }
        if self.owner_session.is_none() {
            return Err(MaintenanceDecisionCommitError::Daemon(
                DaemonError::Lifecycle(
                    "owner session is not bound; drop and re-run authenticated connect+start"
                        .to_owned(),
                ),
            ));
        }
        record.validate()?;
        claim.validate()?;
        // The commit authorizes under the live admitted fence only: a claim
        // bound to a superseded generation must fail here, never commit under
        // it. Claim/session echo and revocation stay the Kernel ledger's check
        // at acknowledgement time.
        let live_fence = self.governor.kernel_snapshot().state_fence().clone();
        if claim.daemon_fence != live_fence {
            return Err(MaintenanceDecisionCommitError::Maintenance(
                MaintenanceError::FenceMismatch,
            ));
        }
        if claim.claim_deadline_unix_ms < crate::unix_ms() {
            return Err(MaintenanceDecisionCommitError::Maintenance(
                MaintenanceError::FenceMismatch,
            ));
        }
        if claim.trigger_id != record.trigger_id {
            return Err(MaintenanceDecisionCommitError::Protocol(
                ProtocolError::ReplayConflict,
            ));
        }
        if claim.revision == 0 {
            return Err(MaintenanceDecisionCommitError::Maintenance(
                MaintenanceError::InvalidField("maintenance_trigger_claim.revision"),
            ));
        }
        let (decision, evidence) = self
            .evaluate_maintenance_trigger_with_evidence(observation)
            .map_err(MaintenanceDecisionCommitError::Daemon)?;
        // The decision must answer this exact retained trigger: identical
        // identity and scope. Changed content conflicts; it never re-binds.
        if decision.trigger_id != record.trigger_id || decision.scope_ref != record.scope.reference
        {
            return Err(MaintenanceDecisionCommitError::Protocol(
                ProtocolError::ReplayConflict,
            ));
        }
        // A job reference names an already-durable job only; it is bound as a
        // reference, never admitted or started here. A blank reference binds
        // nothing: the receipt validator would refuse it, so it is dropped up
        // front under the same nonblank rule.
        let job_ref = decision
            .durable_job_ref
            .clone()
            .filter(|reference| is_commit_ref_text(reference));
        // The durable downstream intent through its existing outbox owner.
        // The leg submits the Governor prepared transition to the admitted
        // notification route and proves the canonical commit receipt in hand;
        // `Ok(None)` (automation off, record already standing) admits no
        // intent and therefore binds no receipt.
        let committed =
            emit_blocked_automation_notification(kernel, live_fence, &decision, &evidence)
                .await
                .map_err(|error| match error {
                    NotificationEmitError::Store(error) => {
                        MaintenanceDecisionCommitError::Store(error)
                    }
                    NotificationEmitError::Admission(error) => {
                        MaintenanceDecisionCommitError::Admission(error)
                    }
                    NotificationEmitError::Kernel(error) => {
                        MaintenanceDecisionCommitError::Kernel(error)
                    }
                })?;
        let Some(NotificationStateEmit::Committed {
            notification_id,
            operation_id,
            ..
        }) = committed
        else {
            return Ok(None);
        };
        Self::bind_committed_decision_receipt(
            kernel,
            record,
            DecisionReceiptBindings {
                claim_revision: claim.revision,
                scope_ref: decision.scope_ref.clone(),
                job_ref,
                policy_revision: policy_revision(&evidence.policy),
                notification_id,
            },
            operation_id,
        )
        .await
    }

    /// Binds the canonical commit receipt for an admitted downstream intent.
    ///
    /// The committed intent identity is looked up through the owning read
    /// path rather than trusted from the request. Absence is the ambiguous
    /// case — the commit may have happened across an outage boundary — so
    /// this returns open instead of proof either way.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] for an unbound identity, a
    /// refused or uncommitted receipt, or an unserializable receipt.
    async fn bind_committed_decision_receipt(
        kernel: &Arc<DaemonKernelClient>,
        record: &MaintenanceTriggerRecord,
        bindings: DecisionReceiptBindings,
        operation_id: String,
    ) -> Result<Option<MaintenanceTriggerDecisionReceipt>, MaintenanceDecisionCommitError> {
        // The exact canonical identity of the committed intent, looked up
        // through the owning read path rather than trusted from the request.
        // Absence here is the ambiguous case: the commit may have happened
        // across an outage boundary, so this returns open instead of proof.
        let operation_id = OperationId::new(operation_id).map_err(StoreError::Foundation)?;
        let Some(receipt) = kernel.receipt(operation_id).await? else {
            return Ok(None);
        };
        receipt.validate()?;
        if receipt.status != WriteReceiptStatus::Committed {
            return Err(MaintenanceDecisionCommitError::Store(
                StoreError::Serialization(
                    "maintenance decision intent transition was not committed".to_owned(),
                ),
            ));
        }
        let receipt_bytes = canonical_json_bytes(&receipt)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let decision_receipt = MaintenanceTriggerDecisionReceipt {
            wire_id: MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_ID.to_owned(),
            wire_version: MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_VERSION,
            trigger_id: record.trigger_id.clone(),
            operation_hash: record.operation_hash.clone(),
            revision: bindings.claim_revision,
            evaluation_revision: format!("{CONTRACT_NAME}:{CONTRACT_VERSION}"),
            policy_revision: bindings.policy_revision,
            scope_ref: bindings.scope_ref,
            job_ref: bindings.job_ref,
            recommendation_ref: Some(bindings.notification_id),
            wake_ref: None,
            canonical_receipt_ref: receipt.operation_id.to_string(),
            receipt_digest: sha256_hex(&receipt_bytes),
        };
        decision_receipt.validate()?;
        Ok(Some(decision_receipt))
    }
}

/// Finite claim lease requested for one retained-trigger delivery attempt.
///
/// Five minutes: finite and well inside the Kernel ledger's own fifteen-minute
/// claim bound, leaving the daemon room to resolve policy, evaluate, and
/// commit one decision while letting a replacement generation reclaim the
/// trigger promptly after daemon loss. Timeout permits owner-mediated
/// redelivery under the same trigger identity, never a new trigger ID.
const MAINTENANCE_TRIGGER_CLAIM_LEASE_MS: u64 = 5 * 60 * 1_000;

/// Terminal outcome of driving one retained maintenance trigger to its next
/// durable state (issue #1694 W3/W5/W7).
///
/// Every variant carries the stable trigger identity it settled; none carries
/// a receipt, a claim, or payload content. `Acknowledged` closed the full
/// claim→evaluate→commit→record→ack path under one finite claim.
/// `AmbiguousMarked` left the row visibly reconciling after a lost commit-side
/// response. `OpenForReconciliation` admitted no intent, so the row stays
/// claimed for owner-mediated redelivery or timeout release.
/// `ExpiredRecorded` terminally expired a past-window trigger with its
/// identity and evidence preserved. Rows that already committed complete by
/// their existing receipt inside the reclaim walk, with each validated echo
/// checked before continuing; they carry no separate outcome because the
/// ledger acknowledgement itself is the evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MaintenanceTriggerDriveOutcome {
    /// The decision committed and the exact receipt was acknowledged.
    Acknowledged {
        /// Stable trigger identity that completed delivery.
        trigger_id: String,
    },
    /// A lost commit-side response left the row visibly reconciling.
    AmbiguousMarked {
        /// Stable trigger identity awaiting receipt reconciliation.
        trigger_id: String,
    },
    /// No intent was admitted; the row stays open, never dropped.
    OpenForReconciliation {
        /// Stable trigger identity left open under its claim.
        trigger_id: String,
    },
    /// Past-window eligibility terminally expired, evidence preserved.
    ExpiredRecorded {
        /// Stable trigger identity that received its terminal disposition.
        trigger_id: String,
    },
}

impl DaemonComposition {
    /// Drives one retained trigger through claim, evaluation, commit, record,
    /// and acknowledgement under a single finite claim (issue #1694 W3/W5).
    ///
    /// The claim binds the live admitted fence, this daemon's retained owner
    /// session, the row revision, and a fresh delivery identity; the replayed
    /// record is re-presented to the Governor-owned evaluator through
    /// [`Self::commit_maintenance_trigger_decision`], whose bound receipt is
    /// then recorded and acknowledged through the Kernel ledger. A past-window
    /// record expires instead of executing. A lost record/ack-side response
    /// after a bound receipt marks the row reconciling rather than repeating
    /// the downstream effect; receipt absence with no bound receipt leaves
    /// the row open for redelivery instead of reporting either way.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] keeping each owner's typed
    /// refusal: not ready or unbound session, stale fence or claim, unknown
    /// or conflicting trigger, evaluation denial, or a refused transport
    /// exchange. Every refusal leaves the trigger retained; nothing is
    /// dropped and no receipt is fabricated.
    pub async fn drive_retained_maintenance_trigger(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        observation: MaintenanceObservation,
        record: &MaintenanceTriggerRecord,
    ) -> Result<MaintenanceTriggerDriveOutcome, MaintenanceDecisionCommitError> {
        let owner_session = self.owner_session.as_ref().ok_or_else(|| {
            MaintenanceDecisionCommitError::Daemon(DaemonError::Lifecycle(
                "owner session is not bound; drop and re-run authenticated connect+start".to_owned(),
            ))
        })?;
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(MaintenanceDecisionCommitError::Admission(
                CompositionError::NotReady,
            ));
        }
        record.validate()?;
        let live_fence = self.governor.kernel_snapshot().state_fence().clone();
        let now = crate::unix_ms();
        if record.validate_at(now).is_err() {
            return self
                .expire_retained_trigger(kernel, record, &live_fence, now)
                .await;
        }
        let daemon_session = owner_session.session_binding().to_owned();
        let delivery_id = format!(
            "{}:delivery:{}:{now}",
            crate::SERVICE_NAME,
            record.trigger_id
        );
        let claim = kernel.claim_maintenance_trigger(
            &live_fence,
            &record.trigger_id,
            &live_fence,
            &daemon_session,
            &delivery_id,
            now.saturating_add(MAINTENANCE_TRIGGER_CLAIM_LEASE_MS),
            &live_fence,
            now,
        )?;
        claim.authorize_for(record, &live_fence, now)?;
        let Some(receipt) = self
            .commit_maintenance_trigger_decision(kernel, observation, record, &claim)
            .await?
        else {
            return Ok(MaintenanceTriggerDriveOutcome::OpenForReconciliation {
                trigger_id: record.trigger_id.clone(),
            });
        };
        match self
            .record_and_acknowledge(kernel, record, &claim, &receipt, &live_fence)
            .await
        {
            Ok(()) => Ok(MaintenanceTriggerDriveOutcome::Acknowledged {
                trigger_id: record.trigger_id.clone(),
            }),
            Err(_) => {
                let _revision = kernel.mark_maintenance_trigger_ambiguous(
                    &live_fence,
                    &record.trigger_id,
                    crate::unix_ms(),
                )?;
                Ok(MaintenanceTriggerDriveOutcome::AmbiguousMarked {
                    trigger_id: record.trigger_id.clone(),
                })
            }
        }
    }

    /// Reclaims the bounded retained-trigger set after an evaluator outage
    /// (issue #1694 W3/W5/W7).
    ///
    /// Walks the Kernel ledger's bounded pages from the start cursor through
    /// each stable continuation — a repeated continuation fails closed
    /// instead of looping — replays every listed member, expires past-window
    /// records with their evidence preserved, completes rows that already
    /// committed by their existing receipt without re-evaluating, and returns
    /// the still-eligible records for the owning trigger sites to drive with
    /// their real observations. A member whose replay fails and whose receipt
    /// recovery also fails stops the walk with the recovery error: the Kernel
    /// cursor never advances on a failure, so the next run resumes honestly.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] on the first refusal that
    /// cannot be settled per-row. One damaged row never aborts silently: an
    /// identity-mismatched replay is recorded as a visible `CorruptPayload`
    /// gap and skipped, while an unrecoverable member fails the walk.
    pub async fn reclaim_pending_maintenance_triggers(
        &self,
        kernel: &Arc<DaemonKernelClient>,
    ) -> Result<Vec<MaintenanceTriggerRecord>, MaintenanceDecisionCommitError> {
        let owner_session = self.owner_session.as_ref().ok_or_else(|| {
            MaintenanceDecisionCommitError::Daemon(DaemonError::Lifecycle(
                "owner session is not bound; drop and re-run authenticated connect+start".to_owned(),
            ))
        })?;
        if self.readiness() != eliot_governor::CompositionReadiness::Ready {
            return Err(MaintenanceDecisionCommitError::Admission(
                CompositionError::NotReady,
            ));
        }
        let live_fence = self.governor.kernel_snapshot().state_fence().clone();
        let daemon_session = owner_session.session_binding().to_owned();
        let mut eligible = Vec::new();
        let mut continuation: Option<String> = None;
        let mut seen_continuations = BTreeSet::new();
        loop {
            let now = crate::unix_ms();
            let page = kernel.pending_maintenance_trigger_page(
                &live_fence,
                continuation.as_deref(),
                now,
            )?;
            for member in &page.members {
                let record =
                    match kernel.replay_maintenance_trigger(&live_fence, &member.trigger_id) {
                        Ok(record) => record,
                        Err(_) => {
                            self.reuse_committed_receipt(
                                kernel,
                                member,
                                &daemon_session,
                                &live_fence,
                                now,
                            )
                            .await?;
                            continue;
                        }
                    };
                if record.trigger_id != member.trigger_id
                    || record.operation_hash != member.operation_hash
                {
                    let _gap = kernel.record_maintenance_trigger_gap(
                        &live_fence,
                        &member.trigger_id,
                        MaintenanceTriggerGapKind::CorruptPayload,
                        "replayed record identity differs from its page member",
                        crate::unix_ms(),
                    )?;
                    continue;
                }
                if record.validate_at(crate::unix_ms()).is_err() {
                    self.expire_retained_trigger(kernel, &record, &live_fence, crate::unix_ms())
                        .await?;
                    continue;
                }
                eligible.push(record);
            }
            if !page.has_more {
                break;
            }
            let next = page.continuation.clone().ok_or(
                MaintenanceDecisionCommitError::Protocol(ProtocolError::InvalidField {
                    field: "maintenance_trigger_page.continuation",
                    reason: "a further page must carry its resume cursor",
                }),
            )?;
            if !seen_continuations.insert(next.clone()) {
                return Err(MaintenanceDecisionCommitError::Protocol(
                    ProtocolError::InvalidField {
                        field: "maintenance_trigger_page.continuation",
                        reason: "pending page continuation did not advance",
                    },
                ));
            }
            continuation = Some(next);
        }
        Ok(eligible)
    }

    /// Records one bound decision receipt and acknowledges it under the live
    /// claim, without another job, recommendation, or wake.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] when the record or the ack
    /// exchange is refused. The caller marks the row reconciling on this
    /// path: the receipt is already bound, so the effect must not repeat.
    async fn record_and_acknowledge(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        record: &MaintenanceTriggerRecord,
        claim: &MaintenanceTriggerClaim,
        receipt: &MaintenanceTriggerDecisionReceipt,
        live_fence: &eliot_contracts::StateFence,
    ) -> Result<(), MaintenanceDecisionCommitError> {
        let recorded =
            kernel.record_maintenance_trigger_decision(live_fence, &record.trigger_id, receipt)?;
        let now = crate::unix_ms();
        let ack = MaintenanceTriggerAck {
            wire_id: MAINTENANCE_TRIGGER_ACK_WIRE_ID.to_owned(),
            wire_version: MAINTENANCE_TRIGGER_ACK_WIRE_VERSION,
            trigger_id: record.trigger_id.clone(),
            delivery_id: claim.delivery_id.clone(),
            daemon_fence: claim.daemon_fence.clone(),
            daemon_session: claim.daemon_session.clone(),
            decision_receipt: recorded,
        };
        ack.validate_for_claim(claim, record, live_fence, now)?;
        kernel.acknowledge_maintenance_trigger(live_fence, live_fence, &ack, now)?;
        Ok(())
    }

    /// Completes one already-committed row by its existing receipt (issue
    /// #1694 W5).
    ///
    /// Claims under a fresh delivery identity, checks the recovered receipt
    /// against the listed page member (identity, operation hash, revision),
    /// reuses it through an idempotent record, and acknowledges — never
    /// re-evaluating and never repeating the downstream effect. Called when
    /// a member's replay is refused because its decision already committed.
    /// The full ack-against-claim-and-record proof runs on the Kernel owner,
    /// which holds the retained record; this side validates the closed ack
    /// shape before sending.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] when the row holds no
    /// committed receipt, the receipt answers a different member, or any
    /// exchange is refused. Every failure leaves the row retained for the
    /// next run.
    async fn reuse_committed_receipt(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        member: &MaintenanceTriggerPendingSummary,
        daemon_session: &str,
        live_fence: &eliot_contracts::StateFence,
        now: u64,
    ) -> Result<(), MaintenanceDecisionCommitError> {
        let receipt =
            kernel.recover_maintenance_trigger_commit(live_fence, &member.trigger_id)?;
        if receipt.operation_hash != member.operation_hash || receipt.revision != member.revision
        {
            return Err(MaintenanceDecisionCommitError::Protocol(
                ProtocolError::ReplayConflict,
            ));
        }
        let delivery_id = format!(
            "{}:delivery:{}:{now}",
            crate::SERVICE_NAME,
            member.trigger_id
        );
        let claim = kernel.claim_maintenance_trigger(
            live_fence,
            &member.trigger_id,
            live_fence,
            daemon_session,
            &delivery_id,
            now.saturating_add(MAINTENANCE_TRIGGER_CLAIM_LEASE_MS),
            live_fence,
            now,
        )?;
        let recorded = kernel.record_maintenance_trigger_decision(
            live_fence,
            &member.trigger_id,
            &receipt,
        )?;
        let ack = MaintenanceTriggerAck {
            wire_id: MAINTENANCE_TRIGGER_ACK_WIRE_ID.to_owned(),
            wire_version: MAINTENANCE_TRIGGER_ACK_WIRE_VERSION,
            trigger_id: member.trigger_id.clone(),
            delivery_id: claim.delivery_id.clone(),
            daemon_fence: claim.daemon_fence.clone(),
            daemon_session: claim.daemon_session.clone(),
            decision_receipt: recorded,
        };
        ack.validate()?;
        kernel.acknowledge_maintenance_trigger(live_fence, live_fence, &ack, crate::unix_ms())?;
        Ok(())
    }

    /// Records terminal expiry for one past-window retained trigger (issue
    /// #1694 W7).
    ///
    /// Expired eligibility blocks stale execution but never deletes the row,
    /// its record, or its evidence locators: the echoed disposition is
    /// validated before reporting the outcome.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceDecisionCommitError`] when the expiry exchange
    /// is refused. The trigger stays retained for the next run.
    async fn expire_retained_trigger(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        record: &MaintenanceTriggerRecord,
        live_fence: &eliot_contracts::StateFence,
        now: u64,
    ) -> Result<MaintenanceTriggerDriveOutcome, MaintenanceDecisionCommitError> {
        let _disposition = kernel.expire_maintenance_trigger(
            live_fence,
            &record.trigger_id,
            "applicability window elapsed before redelivery",
            now,
        )?;
        Ok(MaintenanceTriggerDriveOutcome::ExpiredRecorded {
            trigger_id: record.trigger_id.clone(),
        })
    }
}

/// Receipt bindings carried into [`DaemonComposition::bind_committed_decision_receipt`].
///
/// Bundled so the helper stays within the owner argument budget; every field
/// is the exact value the receipt validator checks.
struct DecisionReceiptBindings {
    /// Claim row revision the decision commits under.
    claim_revision: u64,
    /// Affected scope the decision answers.
    scope_ref: String,
    /// Already-durable job reference, if the decision named one.
    job_ref: Option<String>,
    /// Policy revision resolved at decision time.
    policy_revision: String,
    /// Committed notification intent identity.
    notification_id: String,
}

/// Renders the opaque policy revision resolved at decision time.
///
/// A published Human policy revision names its own revision and digest. While
/// no publisher exists the label records the fail-closed provenance — the
/// registry-selected mode the evaluation actually ran under — and never a
/// guessed publisher revision.
fn policy_revision(policy: &MaintenancePolicyEvidence) -> String {
    match (policy.revision, policy.digest.as_deref()) {
        (Some(revision), Some(digest)) => format!("rev{revision}:{digest}"),
        (Some(revision), None) => format!("rev{revision}:unpublished"),
        (None, _) => format!("unpublished:{:?}", policy.mode()),
    }
}

/// Mirrors the protocol's nonblank reference rule for intent bindings.
///
/// A blank, padded, or control-carrying reference binds nothing: the receipt
/// validator would refuse it, so callers drop it up front instead of
/// submitting a receipt that cannot validate.
fn is_commit_ref_text(value: &str) -> bool {
    !value.trim().is_empty() && value.trim() == value && !value.chars().any(char::is_control)
}
