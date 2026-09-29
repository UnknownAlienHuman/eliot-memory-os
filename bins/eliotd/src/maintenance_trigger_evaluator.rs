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

use std::sync::Arc;

use eliot_contracts::{OperationId, canonical_json_bytes, sha256_hex};
use eliot_governor::{CompositionError, KernelPortError, KernelTransitionPort};
use eliot_maintenance::{
    AutomationTriggerDecision, CONTRACT_NAME, CONTRACT_VERSION, MaintenanceBrokerEvidence,
    MaintenanceBudgetEvidence, MaintenanceError, MaintenanceFamily, MaintenancePolicyEvidence,
    MaintenanceRouteEvidence, MaintenanceSafetyEvidence, MaintenanceScheduleEvidence,
    MaintenanceTrigger, MaintenanceTriggerInput,
};
use eliot_protocol::{
    MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_ID,
    MAINTENANCE_TRIGGER_DECISION_RECEIPT_WIRE_VERSION, MaintenanceTriggerClaim,
    MaintenanceTriggerDecisionReceipt, MaintenanceTriggerRecord, ProtocolError,
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
/// | `explicit_request` | `false` | `eliotd` exposes no authenticated Human UI/CLI maintenance-request ingress; an untrusted flag is not a request. | #1692 |
/// | `safety_required` | `false` | No owner publishes a verified mandatory safety/recovery obligation to this daemon, and the flag must never be asserted to bypass authentication. | #1692 |
/// | `active_job_id` | `None` | [`MaintenanceController`] exposes no probe for an existing active job, so duplicate suppression cannot be fed. | #1694 |
/// | `expires_at_ms` | `None` | No expiry policy is published to this daemon. | #1694 |
///
/// The one gate that **is** filled from a real observation is
/// `user_session_available`, read from the validated Kernel-issued owner
/// session the daemon already retains.
pub const UNRESOLVED_AUTHORITIES: &str = "mode,scheduled_window,route_available,budget_available,user_session_required,explicit_request,safety_required,active_job_id,expires_at_ms";

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
            let policy = MaintenancePolicyEvidence::unpublished(
                entry.mode,
                observation.family,
                scope_ref.clone(),
            );
            let route = MaintenanceRouteEvidence::unpublished();
            let budget = MaintenanceBudgetEvidence::unpublished();
            let schedule = MaintenanceScheduleEvidence::unpublished();
            let broker = MaintenanceBrokerEvidence::transport_only(self.owner_session.is_some());
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
                // Observed, not claimed: transport presence carried by the
                // broker evidence type, which never promotes it to broker
                // admission; the separate interactive permission above stays
                // denied.
                user_session_available: broker.transport_present(),
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
        entry.record_start_route(&decision, observed);
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

/// The family this daemon's wired trigger sites name.
///
/// Every trigger origin currently concerns the daemon's own admitted health
/// and maintenance debt, which is exactly what I14.22's `SelfQualityDebt`
/// family ("self-quality, feedback and maintenance-debt review") covers.
///
/// #1693 supplied the registered per-family catalog, so this is no longer a
/// catalog limit: `MaintenanceFamily` carries all fifteen families and
/// [`maintenance_family_catalog::entry_for`] resolves any of them, and
/// [`DaemonComposition::evaluate_maintenance_trigger`] routes whichever one the
/// caller observes. This constant remains the family the daemon's own
/// observable trigger sites name, because the family is the caller's real
/// observation and the catalog must not invent which family an observed signal
/// concerns.
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
        if decision.trigger_id != record.trigger_id
            || decision.scope_ref != record.scope.reference
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
        let committed = emit_blocked_automation_notification(
            kernel,
            live_fence,
            &decision,
            &evidence,
        )
        .await
        .map_err(|error| match error {
            NotificationEmitError::Store(error) => MaintenanceDecisionCommitError::Store(error),
            NotificationEmitError::Admission(error) => {
                MaintenanceDecisionCommitError::Admission(error)
            }
            NotificationEmitError::Kernel(error) => MaintenanceDecisionCommitError::Kernel(error),
        })?;
        let Some(NotificationStateEmit::Committed {
            notification_id,
            operation_id,
            ..
        }) = committed
        else {
            return Ok(None);
        };
        // The exact canonical identity of the committed intent, looked up
        // through the owning read path rather than trusted from the request.
        // Absence here is the ambiguous case: the commit may have happened
        // across an outage boundary, so this returns open instead of proof.
        let operation_id =
            OperationId::new(operation_id).map_err(StoreError::Foundation)?;
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
            revision: claim.revision,
            evaluation_revision: format!("{CONTRACT_NAME}:{CONTRACT_VERSION}"),
            policy_revision: policy_revision(&evidence.policy),
            scope_ref: decision.scope_ref.clone(),
            job_ref,
            recommendation_ref: Some(notification_id),
            wake_ref: None,
            canonical_receipt_ref: receipt.operation_id.to_string(),
            receipt_digest: sha256_hex(&receipt_bytes),
        };
        decision_receipt.validate()?;
        Ok(Some(decision_receipt))
    }
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
