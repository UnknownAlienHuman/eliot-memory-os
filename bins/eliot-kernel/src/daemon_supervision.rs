//! Daemon supervision ordinary module extracted from the Kernel composition root.
//!
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04
//! Implementation: I1.4, I1.5, I2.23, I8.1, I8.2, I8.3, I8.4, I14.10, I14.15
//! Forbidden authority: no semantic oracle, alternate lease authority, unbounded restart, or daemon-owned canonical transition.

#![forbid(unsafe_code)]

#[cfg(windows)]
use eliot_contracts::ResourceGeneration;
use eliot_contracts::StateFence;
#[cfg(windows)]
use eliot_kernel_service::KernelServiceState;
use eliot_kernel_service::{KernelActivationReceipt, KernelServiceError};
use eliot_ors::{SupervisionLeaseOperation, SupervisionLeaseSnapshot};
#[cfg(not(windows))]
use eliot_process::ProcessStartReceipt;
#[cfg(windows)]
use eliot_process::{
    EliotdLiveReadyEvidence, EliotdLiveReceipt, ExitDisposition, ProcessExecutionView,
    ProcessStartReceipt,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    AutomaticRestartDecision, DaemonChannelCursor, DaemonProgressObservation,
    DaemonSupervisionRenewalPolicy, RestartFailureEvidence, RestartIdentityEvidence,
    RestartOwnerLifecycle, RestartPolicyAdmissionBinding, RestartPolicyError, RestartPolicyV1,
    decide_automatic_restart,
};
use eliot_runtime_contracts::{
    LeaseState, SupervisionGenerationBinding, SupervisionLeaseIncarnationBinding,
    SupervisionLeasePredecessorIdentity,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum DaemonRuntimeStatus {
    NotLaunched,
    Launching,
    Running,
    Ready,
    Degraded(String),
    Failed(String),
}

/// F-LOG-KERNEL-3 (#901): supervision boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.supervision.*` event
/// names plus a bounded stable outcome. Subordinate infos only; the single
/// terminal for a failed supervision operation stays with the owning
/// publication/renewal boundary. Never carries lease material, cursors,
/// digests, evidence, or owner error strings (I15.4, I07.20).
fn observe_supervision(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "daemon supervision observation"
    );
}

pub(crate) const fn daemon_status_proves_ready(status: &DaemonRuntimeStatus) -> bool {
    matches!(status, DaemonRuntimeStatus::Ready)
}

// ============================================================================
// Automatic-restart decisions for the Kernel-supervised child (I14.10, #1682 W3).
//
// The class rule itself - permanent, transient, temporary - lives in
// `eliot_runtime_contracts::restart_policy::decide_automatic_restart`, and it is
// not restated here. This module only supplies what that rule cannot know:
// the owner's own lifecycle, and the exit and health evidence the process owner
// and the Kernel's readiness record already prove. The declared class and the
// eight `RestartIntensityPolicy` numbers come from the admitted configuration
// (`KernelConfig::daemon_restart_policy`, retained on the composition and
// validated at assembly); no number is declared in this file, because I08.12
// keeps the exact values in the approved config and fault profiles.
//
// The direction of the distinction matters and is the whole content of the
// item. A missing or ambiguous exit identity is NOT a proved normal or
// abnormal exit and must never permit a replacement: that case is refused
// outright by `daemon_refuses_replacement`, before any class is read. A
// *classifiable* exit is a different case. The process owner did establish what
// happened, and only then does the class rule decide whether that class of exit
// may buy a replacement. Reading an unproved exit as permission is the defect
// this binding prevents.
//
// Nothing here grants launch, effect or budget authority: `Eligible` only means
// the declared class permits a replacement of this exact reconciled generation.
// The owner's bounded recovery budget, its own effect authorization and the
// existing readiness rendezvous still decide whether anything is dispatched.

/// Why the Kernel refuses an automatic replacement for one observed previous
/// generation.
#[cfg(windows)]
pub(crate) enum DaemonRestartRefusal {
    /// The owner is draining, stopping, retiring or not yet admitted, so a
    /// deliberate going-away is not a failure to retry.
    OwnerLifecycle,
    /// The process owner recorded no exit, or recorded one it could not
    /// classify. That is not a proved normal exit and not a proved abnormal
    /// one, so it may not buy a replacement under any class.
    ExitIdentityNotProved,
    /// No versioned restart policy was admitted for this child, so no restart
    /// class exists to permit a replacement. This is the fail-closed reading of
    /// an absent declaration, never an unlimited budget.
    PolicyNotAdmitted,
    /// A declaration was admitted, but its digest is not bound to the
    /// admitted generation and state fence of the generation being replaced,
    /// so no class may be read for this identity. This is what keeps the
    /// binding a binding: a declaration validated and then dropped would let
    /// any policy justify any generation.
    PolicyNotBoundToAdmittedGeneration,
    /// The admitted declaration is one the shared contract does not admit, so
    /// no class is read. Assembly already refuses such a value; this arm keeps
    /// the decision fail-closed if one ever reaches the replacement path.
    PolicyRejected,
    /// The declared class does not permit a replacement for this classifiable
    /// exit under the rule's own verdict, carrying that verdict's fixed
    /// diagnostic code.
    ClassWithholds(&'static str),
}

/// Maps the owner's own lifecycle onto the value the class rule reads, so a
/// deliberate going-away is never mistaken for a failure to retry.
///
/// Draining and stopping are planned shutdown; `ManualRecovery` is retirement;
/// the pre-activation states and a closed-admission failure are quiescing.
/// Only an admitted, control-open state is `Running`, so a planned shutdown,
/// a cancellation and a retirement cannot provoke an automatic-restart loop.
#[cfg(windows)]
const fn daemon_owner_restart_lifecycle(state: KernelServiceState) -> RestartOwnerLifecycle {
    match state {
        KernelServiceState::Activating
        | KernelServiceState::Ready
        | KernelServiceState::Degraded => RestartOwnerLifecycle::Running,
        KernelServiceState::Draining | KernelServiceState::Stopped => {
            RestartOwnerLifecycle::PlannedShutdown
        }
        KernelServiceState::ManualRecovery => RestartOwnerLifecycle::Retiring,
        KernelServiceState::Cold
        | KernelServiceState::Reconciling
        | KernelServiceState::ShadowNoAuthority
        | KernelServiceState::HandoffPrepared
        | KernelServiceState::Failed => RestartOwnerLifecycle::Quiescing,
    }
}

/// Returns the refusal that applies to one observed previous generation, or
/// `None` when neither precondition blocks a replacement.
///
/// `view` is the process owner's exact observation of the generation being
/// replaced, not liveness and not a PID. The physical `ExitDisposition` it
/// records is the only exit identity that exists: a clean exit code, a signal
/// or resource-limit stop, and a deliberate cancel are all classifiable, and
/// which of them may buy a replacement is the class rule's decision, not this
/// function's. Only the unclassifiable case is refused here.
#[cfg(windows)]
pub(crate) fn daemon_refuses_replacement(
    owner_state: KernelServiceState,
    view: &ProcessExecutionView,
) -> Option<DaemonRestartRefusal> {
    if daemon_owner_restart_lifecycle(owner_state) != RestartOwnerLifecycle::Running {
        return Some(DaemonRestartRefusal::OwnerLifecycle);
    }
    match view.exit() {
        None => Some(DaemonRestartRefusal::ExitIdentityNotProved),
        Some(exit) => match exit.disposition() {
            ExitDisposition::Unknown => Some(DaemonRestartRefusal::ExitIdentityNotProved),
            ExitDisposition::Completed
            | ExitDisposition::Signalled
            | ExitDisposition::ResourceLimit
            | ExitDisposition::Cancelled => None,
        },
    }
}

/// Classifies one reconciled generation into the evidence the class rule reads.
///
/// `view` is the process owner's exact observation and `previous_status` is the
/// Kernel's own readiness record for the same generation; neither is inferred
/// from liveness, a PID or a name.
///
/// * an absent exit observation, or one the process owner recorded as
///   unclassifiable, is `MissingOrAmbiguous`: not a proved normal exit and not a
///   proved abnormal one, so no class can read it as permission;
/// * a signal or a resource-limit stop is an abnormal exit;
/// * a tree the owner deliberately cancelled is a planned stop, which is not
///   itself a failure to retry;
/// * a clean exit of a generation that never proved ready failed this child's
///   health contract, which is the second condition the transient class rests
///   on besides an abnormal exit;
/// * a clean exit of a generation that did prove ready is a normal exit.
///
/// Every classifiable disposition is `Exact` identity: the process owner did
/// establish what happened, which is exactly the case where the class - not
/// this function - decides whether a replacement may follow.
#[cfg(windows)]
fn daemon_restart_evidence(
    previous_status: &DaemonRuntimeStatus,
    view: &ProcessExecutionView,
) -> (RestartIdentityEvidence, RestartFailureEvidence) {
    let Some(exit) = view.exit() else {
        return (
            RestartIdentityEvidence::MissingOrAmbiguous,
            RestartFailureEvidence::NoRestartCondition,
        );
    };
    match exit.disposition() {
        ExitDisposition::Unknown => (
            RestartIdentityEvidence::MissingOrAmbiguous,
            RestartFailureEvidence::NoRestartCondition,
        ),
        ExitDisposition::Signalled | ExitDisposition::ResourceLimit => (
            RestartIdentityEvidence::Exact,
            RestartFailureEvidence::AbnormalExit,
        ),
        ExitDisposition::Cancelled => (
            RestartIdentityEvidence::Exact,
            RestartFailureEvidence::NoRestartCondition,
        ),
        ExitDisposition::Completed if !daemon_status_proves_ready(previous_status) => (
            RestartIdentityEvidence::Exact,
            RestartFailureEvidence::FailedHealthContract,
        ),
        ExitDisposition::Completed => (
            RestartIdentityEvidence::Exact,
            RestartFailureEvidence::NormalExit,
        ),
    }
}

/// Bounded diagnostic code for one class-rule verdict. It is a fixed vocabulary
/// derived only from the decision variant, so no owner payload can reach an
/// observation.
#[cfg(windows)]
const fn daemon_restart_decision_reason(decision: AutomaticRestartDecision) -> &'static str {
    match decision {
        AutomaticRestartDecision::Eligible => "class_permits_replacement",
        AutomaticRestartDecision::SuppressedByOwnerLifecycle => "owner_lifecycle_suppressed",
        AutomaticRestartDecision::TemporaryChild => "temporary_child_never_restarts",
        AutomaticRestartDecision::NoMatchingFailureCondition => "no_matching_failure_condition",
        AutomaticRestartDecision::BlockedByUncertainIdentity => "exit_identity_not_proved",
    }
}

/// One admitted versioned restart policy, bound to the admitted generation and
/// the exact admitted state fence it was admitted under (I14.10, I08.12,
/// #1682 W1).
///
/// The declaration itself is `eliot_runtime_contracts::RestartPolicyV1`; this
/// is its admission. The shared contract already owns the whole shape - the
/// restart class, the group id and strategy, the required/optional/advisory
/// dependency edges with their exact invalidation triggers, the eight
/// `RestartIntensityPolicy` numbers, the quarantine/escalation declaration and
/// the source manifest/profile revision - plus the canonical digest, so this
/// type adds no field, no number and no rule of its own. I08.12 keeps the exact
/// values in the approved config and fault profiles: none is declared here.
///
/// The digest is produced by the contract's own `bind`, which proves the fence
/// and requires the admitted generation to be that fence's generation, and the
/// resulting `RestartPolicyAdmissionBinding` is *retained* here rather than
/// validated and dropped. That retention is the whole point: a policy that was
/// only checked at assembly and then discarded cannot distinguish the
/// declaration admitted for this generation from any other declaration.
///
/// Reading it back is not free either. `policy_for_generation` re-proves the
/// retained binding with the contract's own `validate_for` against the
/// *original* admitted declaration and the generation/fence the caller
/// independently observed, so the class is never read from a declaration whose
/// digest no longer matches the identity it claims to govern.
#[cfg(windows)]
pub(crate) struct AdmittedDaemonRestartPolicy {
    policy: RestartPolicyV1,
    binding: RestartPolicyAdmissionBinding,
}

#[cfg(windows)]
impl AdmittedDaemonRestartPolicy {
    /// Admits one declared policy under one admitted generation and state
    /// fence, and retains the resulting binding.
    ///
    /// The original declared value is validated by the shared contract, both
    /// inside `bind` and again through the binding's own `validate_for`; a
    /// declaration this contract does not admit is refused here rather than
    /// read under a permissive interpretation.
    pub(crate) fn admit(
        policy: RestartPolicyV1,
        admitted_generation: ResourceGeneration,
        state_fence: StateFence,
    ) -> Result<Self, RestartPolicyError> {
        let binding = policy.bind(admitted_generation, state_fence.clone())?;
        binding.validate_for(&policy, &admitted_generation, &state_fence)?;
        Ok(Self { policy, binding })
    }

    /// Returns the admitted declaration only while it is still bound to the
    /// exact admitted generation and state fence the caller observed.
    ///
    /// The caller supplies the generation and fence from the owner's own
    /// admission record rather than from this value, so a binding made for one
    /// generation cannot authorize a replacement of another. The returned
    /// reference is the retained declaration itself: the class rule reads the
    /// admitted policy, never a reconstruction of it.
    pub(crate) fn policy_for_generation(
        &self,
        admitted_generation: ResourceGeneration,
        state_fence: &StateFence,
    ) -> Result<&RestartPolicyV1, RestartPolicyError> {
        self.binding
            .validate_for(&self.policy, &admitted_generation, state_fence)?;
        Ok(&self.policy)
    }
}

/// Applies the declared restart class to one reconciled generation, and returns
/// the refusal that withholds a replacement, or `None` when the class permits
/// one.
///
/// `policy` is the admitted declaration for this child, exactly as
/// `KernelConfig::daemon_restart_policy` injected it and as the admitted
/// generation's `RestartPolicyAdmissionBinding` retains it. The class rule is
/// not restated here: the rule body, its refusal order and its owner-neutral
/// inputs are
/// `eliot_runtime_contracts::restart_policy::decide_automatic_restart`, and
/// this function only supplies the lifecycle and the exit/health evidence that
/// the rule cannot observe for itself.
///
/// `admitted_generation` and `state_fence` are the generation being replaced and
/// the exact fence admitted for it, so the class is read only under a digest
/// that is still bound to that identity.
///
/// `None` is returned only for `Eligible`, which is not launch, effect or
/// budget authority: the owner's own bounded recovery budget and effect
/// authorization still decide whether a replacement is dispatched.
#[cfg(windows)]
pub(crate) fn daemon_class_withholds_replacement(
    policy: Option<&AdmittedDaemonRestartPolicy>,
    admitted_generation: ResourceGeneration,
    state_fence: &StateFence,
    owner_state: KernelServiceState,
    previous_status: &DaemonRuntimeStatus,
    view: &ProcessExecutionView,
) -> Option<DaemonRestartRefusal> {
    // An absent declaration has no class to permit anything. It is refused here
    // rather than defaulted to the widest authority.
    let Some(admitted) = policy else {
        return Some(DaemonRestartRefusal::PolicyNotAdmitted);
    };
    // A declaration admitted for a different generation, or whose digest no
    // longer matches the value it was admitted from, is refused before any
    // class is read. This is the check that makes the retained binding mean
    // something at the point the decision is actually taken.
    let policy = match admitted.policy_for_generation(admitted_generation, state_fence) {
        Ok(policy) => policy,
        Err(_) => return Some(DaemonRestartRefusal::PolicyNotBoundToAdmittedGeneration),
    };
    let (identity, failure) = daemon_restart_evidence(previous_status, view);
    let lifecycle = daemon_owner_restart_lifecycle(owner_state);
    let Ok(decision) = decide_automatic_restart(policy, lifecycle, identity, failure) else {
        return Some(DaemonRestartRefusal::PolicyRejected);
    };
    if decision == AutomaticRestartDecision::Eligible {
        return None;
    }
    Some(DaemonRestartRefusal::ClassWithholds(
        daemon_restart_decision_reason(decision),
    ))
}

/// Bounded reason for a refusal, for the diagnostics facade. It is a fixed
/// vocabulary, so no owner payload can reach an observation.
#[cfg(windows)]
pub(crate) const fn daemon_restart_refusal_reason(refusal: &DaemonRestartRefusal) -> &'static str {
    match refusal {
        DaemonRestartRefusal::OwnerLifecycle => "owner_lifecycle_suppressed",
        DaemonRestartRefusal::ExitIdentityNotProved => "exit_identity_not_proved",
        DaemonRestartRefusal::PolicyNotAdmitted => "restart_policy_not_admitted",
        DaemonRestartRefusal::PolicyNotBoundToAdmittedGeneration => {
            "restart_policy_not_bound_to_admitted_generation"
        }
        DaemonRestartRefusal::PolicyRejected => "restart_policy_rejected_by_contract",
        DaemonRestartRefusal::ClassWithholds(reason) => reason,
    }
}

pub(crate) struct DaemonRuntimeState {
    pub(crate) status: DaemonRuntimeStatus,
    pub(crate) receipt: Option<ProcessStartReceipt>,
    pub(crate) recovery_fenced: bool,
    #[cfg(windows)]
    pub(crate) supervision: Option<DaemonSupervisionContour>,
    #[cfg(windows)]
    pub(crate) live_ready: Option<EliotdLiveReadyEvidence>,
    /// Kernel-owned progress continuity for the active lease (issue #88,
    /// wave 3). Reset whenever supervision binds from unset so a restarted or
    /// replaced daemon generation can never continue the old monotonic
    /// series or cite the old predecessor.
    #[cfg(windows)]
    pub(crate) supervision_progress: DaemonSupervisionProgressState,
    /// Latest daemon-submitted observation retained for the `ProbeReady`
    /// progress route. Evidence only; every renewal re-decides against the
    /// exact durable head.
    #[cfg(windows)]
    pub(crate) last_progress_observation: Option<DaemonProgressObservation>,
    /// Set when the progress route reports terminal lease expiry. The expired
    /// supervision claim stays degraded and visible until a new admitted
    /// generation rebinds; it never auto-revives and never asserts process
    /// death by itself.
    #[cfg(windows)]
    pub(crate) supervision_expired: bool,
}

#[cfg(windows)]
impl DaemonRuntimeState {
    pub(crate) fn bind_live_receipt_publication_operation(
        &mut self,
        ready: &EliotdLiveReadyEvidence,
    ) -> Result<(), KernelServiceError> {
        if !matches!(
            self.status,
            DaemonRuntimeStatus::Running | DaemonRuntimeStatus::Ready
        ) || self.receipt.is_none()
            || self.live_ready.as_ref().is_some_and(|bound| bound != ready)
        {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        self.live_ready = Some(ready.clone());
        Ok(())
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonSupervisionContour {
    pub(crate) candidate_digest: String,
    pub(crate) incarnation: SupervisionLeaseIncarnationBinding,
    pub(crate) activation: KernelActivationReceipt,
    pub(crate) generation_binding: SupervisionGenerationBinding,
    pub(crate) state_fence: StateFence,
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EliotdSupervisionSuccessorEvidence {
    pub(crate) operation: SupervisionLeaseOperation,
    pub(crate) state: LeaseState,
    pub(crate) lease_id: String,
    pub(crate) revision: u64,
    pub(crate) receipt_sha256: String,
    pub(crate) previous_receipt_sha256: Option<String>,
}

#[cfg(windows)]
impl From<&SupervisionLeaseSnapshot> for EliotdSupervisionSuccessorEvidence {
    fn from(snapshot: &SupervisionLeaseSnapshot) -> Self {
        Self {
            operation: snapshot.record.operation,
            state: snapshot.record.state,
            lease_id: snapshot.record.lease_id.as_str().to_owned(),
            revision: snapshot.record.revision,
            receipt_sha256: snapshot.receipt.receipt_sha256.clone(),
            previous_receipt_sha256: snapshot.record.previous_receipt_sha256.clone(),
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EliotdLiveReceiptDisposition {
    ExactReplay,
    ReplaceActivationPredecessor,
    ReplaceRenewalPredecessor,
}

#[cfg(windows)]
pub(crate) fn classify_eliotd_live_receipt_transition(
    old: &EliotdLiveReceipt,
    expected: &EliotdLiveReceipt,
    status_is_ready: bool,
    activation_predecessor: Option<&SupervisionLeasePredecessorIdentity>,
    supervision_successor: Option<&EliotdSupervisionSuccessorEvidence>,
) -> Result<EliotdLiveReceiptDisposition, KernelServiceError> {
    if old == expected {
        // F-LOG-KERNEL-3 (#901): exact replay is an observation of the
        // existing receipt, not another publication.
        observe_supervision("kernel.supervision.receipt_replayed", "success");
        return Ok(EliotdLiveReceiptDisposition::ExactReplay);
    }
    let exact_activation_predecessor = activation_predecessor.is_some_and(|predecessor| {
        predecessor.supervision_lease_id == old.supervision.lease_id
            && predecessor.ors_receipt_sha256 == old.supervision.receipt_sha256
            && old.installation_id == expected.installation_id
            && old.runtime_state_roots_digest == expected.runtime_state_roots_digest
            && old.supervision.public_key_fingerprint == expected.supervision.public_key_fingerprint
    });
    if !status_is_ready && exact_activation_predecessor {
        observe_supervision(
            "kernel.supervision.receipt_replaced",
            "activation_predecessor",
        );
        return Ok(EliotdLiveReceiptDisposition::ReplaceActivationPredecessor);
    }
    let exact_renewal_predecessor = supervision_successor.is_some_and(|successor| {
        successor.operation == SupervisionLeaseOperation::Renew
            && successor.state == LeaseState::Active
            && successor.lease_id == expected.supervision.lease_id
            && successor.revision == expected.supervision.revision
            && successor.receipt_sha256 == expected.supervision.receipt_sha256
            && successor.previous_receipt_sha256.as_deref()
                == Some(old.supervision.receipt_sha256.as_str())
            && old.supervision.revision.checked_add(1) == Some(expected.supervision.revision)
            && old.process == expected.process
            && old.ready == expected.ready
            && old.receipt_root_identity_sha256 == expected.receipt_root_identity_sha256
            && old.runtime_state_roots_digest == expected.runtime_state_roots_digest
            && old.installation_id == expected.installation_id
            && old.approved_generation == expected.approved_generation
            && old.generation == expected.generation
            && old.authority_epoch == expected.authority_epoch
            && old.config_descriptor_sha256 == expected.config_descriptor_sha256
            && old.descriptor_sha256 == expected.descriptor_sha256
            && old.kernel_artifact_sha256 == expected.kernel_artifact_sha256
            && old.supervision.lease_id == expected.supervision.lease_id
            && old.supervision.public_key_fingerprint == expected.supervision.public_key_fingerprint
    });
    if status_is_ready && exact_renewal_predecessor {
        observe_supervision("kernel.supervision.receipt_replaced", "renewal_predecessor");
        return Ok(EliotdLiveReceiptDisposition::ReplaceRenewalPredecessor);
    }
    // Subordinate observation only; the owning publication boundary emits the
    // single terminal for the rejected transition.
    observe_supervision("kernel.supervision.receipt_rejected", "fenced");
    Err(KernelServiceError::ReadinessNotProven)
}

// ============================================================================
// Kernel-owned daemon progress continuity (issue #88, wave 2).
//
// The Kernel retains per-channel accepted cursors, the last accepted monotonic
// evidence, the last recorded renewal identity, a consecutive-miss counter,
// and the reconciliation flag. The daemon (wave 3, `eliotd` per-tick
// observation) submits candidate observations; it never writes this state.
// `StoreHealth` carries no cursor and therefore can never advance it.
//
// Owner defaults enforced with this state (see
// `SUPERVISION_LEASE_RENEWAL_POLICY` for the timing owner):
// - stale-cursor horizon: three missed renewal intervals
//   (`3 * renew_after_ms`) with no eligible observation, or three consecutive
//   blocked renewals, expires the lease (`SupervisionLeaseExpired`). An
//   expired lease requires a new admission; it never auto-revives.
// - a `Failed` health dimension on a degraded observation blocks renewal
//   fail-closed (`DegradedNoRenewal`, reported, no successor, never skipped).
// - `NoProgress` / `ObservationGap` / rollback / skew / stale
//   generation-session-epoch-fence-boot / predecessor mismatch all fail
//   closed through the contract join; exact replay stays idempotent and a
//   mutated retry reports `IDENTITY_CONFLICT`.
//
// Wave-3 handoff (MGR02): the `eliotd` per-tick observation producer binds
// this tracker to the live runtime (retention + first-use boot/session
// pinning below stays valid); this file owns the shape, not the producer.

/// Consecutive blocked renewals (or equivalent silence) that stale-expire a
/// supervision lease. The time horizon is the same count of renewal
/// intervals: `3 * renew_after_ms`.
#[cfg(windows)]
pub(crate) const SUPERVISION_PROGRESS_STALE_MISSED_INTERVALS: u64 = 3;

/// Kernel-owned progress continuity for one supervised daemon generation.
#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaemonSupervisionProgressState {
    /// Last cursor accepted by the Kernel per progress channel.
    pub(crate) accepted_cursors: Vec<DaemonChannelCursor>,
    /// Currently admitted idle contract, when one is admitted.
    pub(crate) admitted_idle_contract: Option<String>,
    /// Boot identity pinned on first use; later mismatch fails closed.
    pub(crate) boot_id: Option<String>,
    /// Transport-session binding pinned on first use; reconnects need an
    /// explicit rebinding path (mismatch fails closed until then).
    pub(crate) transport_session_evidence: Option<String>,
    /// Last accepted monotonic evidence in milliseconds (never regresses).
    pub(crate) last_monotonic_ms: u64,
    /// Request identity of the last recorded renewal, if any.
    pub(crate) last_request_id: Option<String>,
    /// Canonical digest of the last recorded observation, if any.
    pub(crate) last_observation_sha256: Option<String>,
    /// Successor revision created by the last recorded renewal, if any.
    pub(crate) last_successor_revision: Option<u64>,
    /// Consecutive blocked renewals with no eligible observation.
    pub(crate) missed_renewals: u64,
    /// Decision time of the last eligible observation that renewed, if any.
    pub(crate) last_eligible_observation_ms: Option<u64>,
    /// True while an unknown ORS/live-receipt publication outcome is still
    /// unreconciled; blocks every new successor until exact reconciliation.
    pub(crate) reconciliation_pending: bool,
}

#[cfg(windows)]
impl DaemonSupervisionProgressState {
    /// Returns the unbound continuity for a freshly bound supervision: no
    /// accepted cursors, no admitted idle contract, no boot/session pinning,
    /// no monotonic evidence, no recorded renewal, no misses, and no pending
    /// reconciliation. The first shape-valid observation pins boot, session,
    /// and monotonic evidence anew.
    pub(crate) fn unbound() -> Self {
        Self {
            accepted_cursors: Vec::new(),
            admitted_idle_contract: None,
            boot_id: None,
            transport_session_evidence: None,
            last_monotonic_ms: 0,
            last_request_id: None,
            last_observation_sha256: None,
            last_successor_revision: None,
            missed_renewals: 0,
            last_eligible_observation_ms: None,
            reconciliation_pending: false,
        }
    }

    /// Returns the stale-expiry horizon in milliseconds for a policy.
    pub(crate) fn stale_horizon_ms(policy: &DaemonSupervisionRenewalPolicy) -> u64 {
        policy
            .renew_after_ms
            .saturating_mul(SUPERVISION_PROGRESS_STALE_MISSED_INTERVALS)
    }

    /// Returns true once the lease must expire instead of retrying: three
    /// consecutive blocked renewals, or silence past the stale horizon with
    /// no eligible observation. A lease with no recorded eligibility yet
    /// (first renewal) is never stale on time alone.
    pub(crate) fn stale_renewal_expired(
        &self,
        policy: &DaemonSupervisionRenewalPolicy,
        now_ms: u64,
    ) -> bool {
        if self.missed_renewals >= SUPERVISION_PROGRESS_STALE_MISSED_INTERVALS {
            return true;
        }
        self.last_eligible_observation_ms.is_some_and(|eligible| {
            now_ms.saturating_sub(eligible) >= Self::stale_horizon_ms(policy)
        })
    }

    /// Pins the Kernel-owned boot/session continuity from the first
    /// shape-valid observation. Later observations must match exactly; a
    /// changed boot or session fails closed in the renewal join.
    pub(crate) fn admit_boot_session_binding(&mut self, observation: &DaemonProgressObservation) {
        if self.boot_id.is_none() {
            self.boot_id = Some(observation.boot_id.clone());
        }
        if self.transport_session_evidence.is_none() {
            self.transport_session_evidence = Some(observation.transport_session_evidence.clone());
        }
    }

    /// Advances the last accepted monotonic evidence; it never regresses, so
    /// rolled-back observations stay detectable after refusals.
    pub(crate) fn advance_monotonic_ms(&mut self, observed_monotonic_ms: u64) {
        self.last_monotonic_ms = self.last_monotonic_ms.max(observed_monotonic_ms);
    }

    /// Records one blocked (non-renewing) evaluation. The request identity is
    /// deliberately not recorded: refusals re-evaluate deterministically, and
    /// only recorded renewals participate in replay/identity-conflict.
    pub(crate) fn note_missed_renewal(&mut self) {
        // F-LOG-KERNEL-3 (#901): blocked-renewal observation; the stale-expiry
        // decision stays with the renewal join.
        observe_supervision("kernel.supervision.renewal_missed", "deferred");
        self.missed_renewals = self.missed_renewals.saturating_add(1);
    }

    /// Records a verified renewal: advances the channel cursor, the
    /// monotonic evidence, and the idempotency triple, resets the miss
    /// counter, stamps eligibility, and clears reconciliation. Call only
    /// after the ORS commit and post-verify both succeed.
    pub(crate) fn record_renewed(
        &mut self,
        observation: &DaemonProgressObservation,
        observation_sha256: String,
        successor_revision: u64,
        now_ms: u64,
    ) {
        if let Some(entry) = self
            .accepted_cursors
            .iter_mut()
            .find(|entry| entry.channel == observation.progress_channel)
        {
            entry.cursor = observation.progress_cursor;
        } else {
            self.accepted_cursors.push(DaemonChannelCursor {
                channel: observation.progress_channel,
                cursor: observation.progress_cursor,
            });
        }
        self.advance_monotonic_ms(observation.observed_monotonic_ms);
        self.last_request_id = Some(observation.observation_id.clone());
        self.last_observation_sha256 = Some(observation_sha256);
        self.last_successor_revision = Some(successor_revision);
        self.missed_renewals = 0;
        self.last_eligible_observation_ms = Some(now_ms);
        self.reconciliation_pending = false;
        // F-LOG-KERNEL-3 (#901): verified-renewal observation. Only the
        // outcome is logged; cursors, digests, and revision identities stay
        // with the owner.
        observe_supervision("kernel.supervision.renewal_recorded", "success");
    }

    /// Marks the durable outcome unknown after a failed renew commit. The
    /// renewal join then reports `ReconciliationRequired` instead of minting
    /// a successor until exact reconciliation.
    pub(crate) fn note_reconciliation_pending(&mut self) {
        // F-LOG-KERNEL-3 (#901): unknown-outcome observation; the outcome
        // stays unknown until the owner reconciles it exactly.
        observe_supervision("kernel.supervision.reconciliation_required", "unknown");
        self.reconciliation_pending = true;
    }
}

#[cfg(all(test, windows))]
mod daemon_supervision_diagnostics_tests {
    //! F-LOG-KERNEL-3 (#901) focused diagnostics proof: readiness versus
    //! liveness, blocked-renewal stale expiry, unknown-outcome blocking, and
    //! secret-free capture for the supervision observations added above.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(run: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
        }
        String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned()
    }

    fn test_progress() -> DaemonSupervisionProgressState {
        DaemonSupervisionProgressState {
            accepted_cursors: Vec::new(),
            admitted_idle_contract: None,
            boot_id: None,
            transport_session_evidence: None,
            last_monotonic_ms: 0,
            last_request_id: None,
            last_observation_sha256: None,
            last_successor_revision: None,
            missed_renewals: 0,
            last_eligible_observation_ms: None,
            reconciliation_pending: false,
        }
    }

    fn test_policy() -> DaemonSupervisionRenewalPolicy {
        DaemonSupervisionRenewalPolicy {
            validity_ms: 60_000,
            renew_after_ms: 30_000,
            max_observation_age_ms: 10_000,
            max_wall_skew_ms: 5_000,
            require_watchdog_coverage: false,
        }
    }

    #[test]
    fn supervision_diagnostics_readiness_and_renewal_boundaries() {
        // Liveness is not readiness: only `Ready` proves ready. Status
        // payloads stay with the owner; observations below carry fixed names.
        assert!(!daemon_status_proves_ready(
            &DaemonRuntimeStatus::NotLaunched
        ));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Launching));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Running));
        assert!(daemon_status_proves_ready(&DaemonRuntimeStatus::Ready));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Degraded(
            "degraded-canary".to_owned()
        )));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Failed(
            "failed-canary".to_owned()
        )));

        // Three consecutive blocked renewals stale-expire the lease; fewer do
        // not. The counting behavior is unchanged, only observed.
        let policy = test_policy();
        let mut progress = test_progress();
        assert!(!progress.stale_renewal_expired(&policy, 1_000_000));
        progress.note_missed_renewal();
        progress.note_missed_renewal();
        assert!(!progress.stale_renewal_expired(&policy, 1_000_000));
        assert_eq!(progress.missed_renewals, 2);
        progress.note_missed_renewal();
        assert!(progress.stale_renewal_expired(&policy, 1_000_000));

        // An unknown outcome blocks successors until exact reconciliation.
        assert!(!progress.reconciliation_pending);
        progress.note_reconciliation_pending();
        assert!(progress.reconciliation_pending);

        // Monotonic evidence never regresses, so rolled-back observations
        // stay detectable after refusals.
        progress.advance_monotonic_ms(500);
        progress.advance_monotonic_ms(100);
        assert_eq!(progress.last_monotonic_ms, 500);

        // Captured diagnostics carry fixed events only; owner payloads never
        // reach the sink (helpers accept `&'static str`, so no `String`
        // payload can be passed at all).
        let text = capture(|| {
            observe_supervision("kernel.supervision.renewal_missed", "deferred");
            observe_supervision("kernel.supervision.reconciliation_required", "unknown");
            observe_supervision("kernel.supervision.renewal_recorded", "success");
            observe_supervision("kernel.supervision.receipt_replayed", "success");
        });
        for marker in [
            "kernel.supervision.renewal_missed",
            "kernel.supervision.reconciliation_required",
            "kernel.supervision.renewal_recorded",
            "kernel.supervision.receipt_replayed",
        ] {
            assert!(text.contains(marker), "missing diagnostics marker {marker}");
        }
        for canary in ["degraded-canary", "failed-canary"] {
            assert!(!text.contains(canary), "owner payload leaked: {canary}");
        }
    }
}
