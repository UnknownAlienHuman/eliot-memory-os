//! Kernel daemon runtime and status lifecycle closure.
//!
//! Owns the `eliotd` launch descriptor and runtime status transitions with bounded recovery.
//! Architecture: A8.1, A13.2, A13.3, ARCH-WDG-01, ARCH-RES-01, ARCH-RES-04.
//! Implementation: I1.4, I1.5, I8.1, I8.2, I8.3, I8.4, I14.10, I14.15; extraction topology I2.23.
//! Forbidden: no semantic readiness oracle, alternate authority, unbounded restart, or fabricated launch success.

use std::sync::atomic::Ordering;
use std::time::Duration;

use eliot_kernel_core::RouteScope;
use eliot_kernel_service::{
    EliotdLaunchDescriptor, KernelControlCommand, KernelServiceError, KernelServiceState,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    current_process_named_pipe_expectation, observe_named_pipe_peer_process,
};
use eliot_process::{
    CancellationStatus, Generation, ProcessExecutionError, ProcessExecutionView, ProcessLifecycle,
    ProcessOwnerBinding, ProcessStartReceipt,
};

use super::diagnostic_brief::DiagnosticTrigger;
use super::kernel_audit::{AuditEventDraft, AuditEventKind};
use super::{
    ACTIVE_DAEMON_CALLER, DaemonRuntimeStatus, KernelBuildError, KernelComposition,
    daemon_class_withholds_replacement, daemon_refuses_replacement, daemon_restart_refusal_reason,
    daemon_status_proves_ready, eliotd_launch_attempt_identity, eliotd_operation_id,
    fresh_eliotd_launch_descriptor, probe_ready_state_admitted, sha256_hex,
    stable_owner_principal_digest,
};
#[cfg(windows)]
use super::{AdmittedDaemonRestartPolicy, DaemonRestartRefusal};

/// F-LOG-KERNEL-4 (#903): daemon-runtime boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.daemon.*` event names
/// plus a bounded stable outcome. Never carries launch descriptors, nonces,
/// receipts, digests, paths, supervision material, or owner error strings
/// (I15.4, I07.20).
fn observe_daemon_runtime(event: &'static str, outcome: &'static str) {
    observe_daemon_runtime_in_context(event, outcome, &tracing::Span::current());
}

fn observe_daemon_runtime_in_context(
    event: &'static str,
    outcome: &'static str,
    context: &tracing::Span,
) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        parent: context,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "daemon runtime observation"
    );
}

/// Maps one daemon-recovery failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload is never logged. The
/// `RECOVERY_` prefix keeps recovery-operation terminals distinct from the
/// launch-operation codes (`daemon_process_launch.rs`).
#[cfg(windows)]
fn daemon_recovery_terminal_code(error: &KernelBuildError) -> &'static str {
    match error {
        KernelBuildError::Platform(_) => "RECOVERY_PLATFORM",
        KernelBuildError::Transport(_) => "RECOVERY_TRANSPORT",
        KernelBuildError::Runtime(_) => "RECOVERY_RUNTIME",
        KernelBuildError::Ors(_) => "RECOVERY_ORS",
        KernelBuildError::Core(_) => "RECOVERY_CORE",
        KernelBuildError::Service(_) => "RECOVERY_SERVICE",
        KernelBuildError::StoreBootstrapRequired => "RECOVERY_STORE_BOOTSTRAP_REQUIRED",
        KernelBuildError::StoreAlreadyConnected => "RECOVERY_STORE_ALREADY_CONNECTED",
        KernelBuildError::Principal(_) => "RECOVERY_PRINCIPAL",
    }
}

/// The manifest-bound outcome of one production launch of the `eliotd` child
/// (issue #1884; I1.9).
///
/// It is produced for BOTH production launch arms — the first launch of the
/// child and the replacement of a failed generation — because both reach the
/// same launch primitive, and that primitive takes a sealed binding as an
/// argument. `Admitted` carries the sealed
/// [`eliot_ors::BoundKernelExecutionManifest`] the ORS verifier issued for this
/// exact module and generation, so the artifact/config identity, the launch
/// coordinates and the bounded restart budget the attempt is decided under are
/// read out of the immutable manifest rather than out of contemporaneous
/// configuration. It is the only value a launch may take its recorded identity
/// from: the type has no public constructor and no `Deserialize`, so this file
/// cannot assemble one and can only obtain one from the verifier.
/// `Refused` carries the daemon's own typed restart refusal, mapped from the ORS
/// reconciliation cause so that cause survives the layer boundary instead of
/// being flattened into one refusal.
#[cfg(windows)]
enum DaemonRestartManifestAdmission {
    /// The verifier admitted this launch under the sealed immutable manifest.
    ///
    /// Boxed because the sealed binding is far larger than the refusal beside it,
    /// and this enum crosses the launch path by value.
    Admitted(Box<eliot_ors::BoundKernelExecutionManifest>),
    /// A typed refusal withholds the launch.
    Refused(DaemonRestartRefusal),
}

/// Projects one recorded ORS manifest cause onto the daemon's own typed restart
/// refusal.
///
/// The recorded budget exhaustion keeps the existing
/// [`DaemonRestartRefusal::RestartBudgetExhausted`], which is exactly what it
/// is. Every other manifest-side cause keeps its own bounded reason code, so an
/// absent, receipt-less, stale, incompatible, revoked or identity-mismatched
/// manifest is never reported as a spent budget, and a refusal that IS a spent
/// budget is never reported as one of those. A cause that names one substituted
/// authority or launch coordinate keeps its own code as well, so a substituted
/// restart budget is not reported as a spent one. The codes are a fixed
/// vocabulary derived only from the ORS cause, so no recorded payload can reach
/// an observation.
///
/// The effect-lease family of causes belongs to the effect-replay verifier and
/// cannot be produced by the launch verifier, so those variants share one
/// bounded code rather than each claiming a launch-specific meaning.
#[cfg(windows)]
const fn daemon_restart_refusal_for_manifest_cause(
    kind: eliot_ors::KernelReconciliationKind,
) -> DaemonRestartRefusal {
    use eliot_ors::KernelReconciliationKind as Cause;
    match kind {
        Cause::ManifestRestartBudgetExhausted => DaemonRestartRefusal::RestartBudgetExhausted,
        Cause::ManifestAbsent => DaemonRestartRefusal::ClassWithholds("restart_manifest_absent"),
        Cause::ManifestIdentityMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_identity_mismatch")
        }
        Cause::ManifestCandidateBindingMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_candidate_binding_mismatch")
        }
        Cause::ManifestIncompatible => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_incompatible")
        }
        Cause::ManifestRevoked => DaemonRestartRefusal::ClassWithholds("restart_manifest_revoked"),
        Cause::ManifestReceiptless => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_receiptless")
        }
        Cause::ManifestForeignEpoch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_foreign_epoch")
        }
        Cause::ManifestInvalid => DaemonRestartRefusal::ClassWithholds("restart_manifest_invalid"),
        Cause::ManifestCatalogPolicyStale => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_catalog_policy_stale")
        }
        Cause::ManifestRevocationUnacknowledged => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_revocation_unacknowledged")
        }
        Cause::ManifestDeliveryGapOpen => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_delivery_gap_open")
        }
        Cause::ManifestNotEffectCapable => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_not_effect_capable")
        }
        // A sealed Governor admission defect is the manifest's own structural
        // refusal, so it keeps its own code rather than being reported as the
        // undifferentiated "not admitted" reading.
        Cause::GovernorAdmissionSealAbsent => {
            DaemonRestartRefusal::ClassWithholds("restart_governor_admission_seal_absent")
        }
        Cause::GovernorAdmissionSealWithheld => {
            DaemonRestartRefusal::ClassWithholds("restart_governor_admission_seal_withheld")
        }
        Cause::GovernorAdmissionSealMalformed => {
            DaemonRestartRefusal::ClassWithholds("restart_governor_admission_seal_malformed")
        }
        Cause::GovernorAdmissionSealIdentityMismatch => DaemonRestartRefusal::ClassWithholds(
            "restart_governor_admission_seal_identity_mismatch",
        ),
        Cause::GovernorAdmissionSealRevisionMismatch => DaemonRestartRefusal::ClassWithholds(
            "restart_governor_admission_seal_revision_mismatch",
        ),
        Cause::GovernorAdmissionSealStateFenceAbsent => DaemonRestartRefusal::ClassWithholds(
            "restart_governor_admission_seal_state_fence_absent",
        ),
        Cause::GovernorAdmissionSealOwnerDigestMismatch => DaemonRestartRefusal::ClassWithholds(
            "restart_governor_admission_seal_owner_digest_mismatch",
        ),
        // A substituted AUTHORITY coordinate is refused as itself. Each of the
        // seven admission and launch coordinates ORS compares one at a time keeps
        // its own bounded code, so a substituted class, ceiling, route-scope
        // set, dependency order, Job Object limit set, readiness contract or
        // restart budget is never reported as one of its neighbours and never as
        // the undifferentiated "not admitted" reading. A substituted budget is
        // deliberately distinct from `ManifestRestartBudgetExhausted` above:
        // that cause means the recorded budget is already SPENT, while this one
        // means the candidate offered a budget the record does not carry.
        Cause::ManifestRestartAuthorizationClassMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_authorization_class_mismatch")
        }
        Cause::ManifestAdmittedEffectCeilingMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_effect_ceiling_mismatch")
        }
        Cause::ManifestAdmittedAllowedScopesMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_allowed_scopes_mismatch")
        }
        Cause::ManifestDependencyOrderMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_dependency_order_mismatch")
        }
        Cause::ManifestResourceLimitsMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_resource_limits_mismatch")
        }
        Cause::ManifestReadinessContractMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_readiness_contract_mismatch")
        }
        Cause::ManifestRestartBudgetMismatch => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_restart_budget_mismatch")
        }
        // An UNOBSERVED coordinate is refused as itself and is deliberately a
        // different refusal from the substituted one above: the descriptor stated
        // nothing at all to compare, so the launch is refused instead of being
        // admitted on the assumption that the owner would have stated the
        // recorded value. The two keep separate codes for exactly that reason.
        Cause::ManifestResourceLimitsUnobserved => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_resource_limits_unobserved")
        }
        Cause::ManifestReadinessContractUnobserved => {
            DaemonRestartRefusal::ClassWithholds("restart_manifest_readiness_contract_unobserved")
        }
        // The last resort, and it is reachable by exactly one documented family:
        // the `Effect*` causes of the ORS vocabulary belong to the exact-effect
        // replay verifier, which verifies an unexpired lease for one operation and
        // never a whole-generation launch, so a launch gate cannot produce one. A
        // cause added to ORS without a launch-specific meaning lands here too,
        // which is why the wildcard stays one bounded code rather than a
        // per-cause claim this file cannot make.
        _ => DaemonRestartRefusal::ClassWithholds("restart_manifest_not_admitted"),
    }
}

/// The launch coordinates this owner OBSERVES on the Host-approved launch
/// descriptor for the exact candidate it intends to run (issue #1884; I1.9).
///
/// This is the INDEPENDENT side of the launch-binding comparison. It is built
/// from `EliotdLaunchDescriptor`, which is loaded from a separately
/// digest-bound approved file and is explicitly not inferred from the Kernel
/// executable, the current directory or the environment
/// (`crates/kernel/eliot-kernel-service/src/protocol.rs:550`). The immutable
/// manifest row is never read here: restating the recorded values would compare
/// the manifest with itself and could never fail.
///
/// * `artifact_sha256` is the descriptor's own `executable_sha256`, the digest
///   of the approved `eliotd.exe` bytes;
/// * `config_sha256` is its own `config_descriptor_sha256`, the digest of the
///   exact daemon configuration bytes;
/// * `protocol_sha256` is its own `protected_snapshot_digest`, the
///   domain-separated identity of the protected Kernel/eliotd snapshot, which
///   the descriptor's own contract keeps distinct from the configuration digest;
/// * `start_command` is projected from the descriptor's own exact child
///   contour: the approved executable followed by the exact child argv
///   excluding `argv[0]`, in the declared order, joined by one space, WITH THE
///   `--launch-nonce <launch_nonce>` PAIR LEFT OUT. The descriptor states that
///   contour as separate fields and carries no rendered command text, so the
///   projection is the render.
///
/// The ONE excluded argv component is the launch-correlation pair, and it is
/// excluded because the descriptor's own field documentation excludes it as
/// identity. `EliotdLaunchDescriptor::launch_nonce` is a "Public
/// launch-correlation nonce carried through the explicit argv contract. It is
/// not a secret or an authority credential; authenticated process/Job/pipe
/// evidence remains the authority proof"
/// (`crates/kernel/eliot-kernel-service/src/protocol.rs:621`). `validate` fixes
/// that pair at argv indices 4 and 5 and `fresh_eliotd_launch_descriptor`
/// (`bins/eliot-kernel/src/runtime_identity.rs`) derives a NEW value for it on
/// every attempt from the previous descriptor digest, the previous nonce, the
/// attempt ordinal and the wall clock. A per-attempt correlation value therefore
/// cannot be a component of a RECORDED launch identity: rendering it made the
/// compared value differ from the recorded one for every restart BY
/// CONSTRUCTION, so every restart was refused as
/// `ManifestCandidateBindingMismatch` for a reason that was not a substitution.
///
/// The pair is left out whole and nothing else is: no placeholder token is
/// substituted for it, no template spelling is invented for it, and no other
/// argument is dropped or reordered. The config path, the config digest and the
/// executable digest all stay in the compared string, because those ARE
/// identity.
///
/// A descriptor whose argv or executable changes therefore changes this value
/// and is refused, which is the point: an equality that a manifest's own value
/// can satisfy is not a check.
///
/// RESIDUAL CONTRACT GAP (reported, deliberately not repaired here). The
/// RECORDED `start_command` is not composed by this file. It is the Module
/// Catalog's own `command_ref`, projected into the recorded manifest by
/// `admitted_execution_projection`
/// (`crates/governor/eliot-module-registry/src/lib.rs`). No document in this
/// repository defines how a catalog `command_ref` is SPELLED relative to the
/// canonical child argv: whether it carries the executable path, whether it
/// carries the flags, whether it carries the nonce. The compared form is
/// therefore exactly the canonical argv minus the nonce pair, the recorded form
/// is the catalog's own text, and the relation between the two is undefined by
/// any document here. Nothing in this file normalises, tolerates or falls back
/// on that relation, because inventing a spelling, a normaliser or a tolerant
/// comparison for it would be a second and unauthoritative definition of what
/// the manifest records.
#[cfg(windows)]
fn daemon_candidate_launch_binding(
    launch: &EliotdLaunchDescriptor,
) -> eliot_ors::KernelLaunchBinding {
    // The `--launch-nonce` flag is LOCATED in the descriptor's own canonical
    // argv rather than assumed at a fixed index, and the pair it introduces is
    // dropped whole: the flag and the value behind it are one correlation
    // component, and skipping either alone would render half of it.
    let nonce_flag = launch
        .arguments
        .iter()
        .position(|argument| argument.as_str() == "--launch-nonce");
    let mut start_command = launch.executable.as_str().to_owned();
    for (index, argument) in launch.arguments.iter().enumerate() {
        if nonce_flag.is_some_and(|flag| index == flag || index == flag + 1) {
            continue;
        }
        start_command.push(' ');
        start_command.push_str(argument.as_str());
    }
    eliot_ors::KernelLaunchBinding {
        artifact_sha256: launch.executable_sha256.clone(),
        config_sha256: launch.config_descriptor_sha256.clone(),
        protocol_sha256: launch.protected_snapshot_digest.clone(),
        start_command,
    }
}

/// The dependency order and bounded restart budget this owner OBSERVES for the
/// exact child it intends to run, read from the admitted restart declaration
/// (issue #1884; I1.9).
///
/// The declaration is the admitted owner of both: `RestartPolicyV1` carries the
/// typed dependency edges with their invalidation triggers and the bounded
/// attempt window, backoff, jitter, cooldown, healthy-reset condition, quarantine
/// threshold and escalation target. It is read through
/// [`AdmittedDaemonRestartPolicy::policy_for_generation`], which re-proves the
/// retained binding — the declared digest and both source revisions — against the
/// very generation and State Fence the descriptor states, so a declaration
/// admitted for another generation cannot supply this launch's coordinates.
///
/// * the start order is the declared dependency vector's own position. The
///   admitted declaration states no separate order field, so this file reads the
///   declaration order and does not invent a topology of its own; the recorded
///   manifest must carry the same order for the two to be equal;
/// * the budget ceiling is the declared `max_attempts_in_window` and the
///   quarantine rule is the declared `escalation_target`, the two values the
///   declaration states for exactly this pair.
///
/// A descriptor that states no admitted declaration has neither coordinate. That
/// absence is refused as `PolicyNotAdmitted` — the fail-closed disposition the
/// declaration's own contract describes ("no admitted declaration means no
/// automatic restart at all for this child") — and a declaration whose binding no
/// longer proves this generation is refused as
/// `PolicyNotBoundToAdmittedGeneration`. Neither is defaulted into a budget.
#[cfg(windows)]
fn daemon_candidate_restart_coordinates(
    admitted: Option<&AdmittedDaemonRestartPolicy>,
    launch: &EliotdLaunchDescriptor,
) -> Result<
    (
        Vec<eliot_ors::ManifestDependencyEntry>,
        eliot_ors::ManifestRestartBudget,
    ),
    DaemonRestartRefusal,
> {
    let admitted = admitted.ok_or(DaemonRestartRefusal::PolicyNotAdmitted)?;
    let state_fence =
        eliot_contracts::StateFence::new(launch.authority_epoch.clone(), launch.generation);
    let policy = admitted
        .policy_for_generation(launch.generation, &state_fence)
        .map_err(|_error| DaemonRestartRefusal::PolicyNotBoundToAdmittedGeneration)?;
    let dependency_order = policy
        .dependencies
        .iter()
        .enumerate()
        .map(|(position, edge)| eliot_ors::ManifestDependencyEntry {
            module_id: edge.dependency_id.clone(),
            startup_order: u32::try_from(position).unwrap_or(u32::MAX),
        })
        .collect();
    Ok((
        dependency_order,
        eliot_ors::ManifestRestartBudget {
            max_restarts: policy.intensity.max_attempts_in_window,
            quarantine_rule: policy.intensity.escalation_target.clone(),
        },
    ))
}

/// The Job Object/resource limits and the health/readiness contract reference
/// this owner OBSERVES on the Host-approved launch descriptor for the exact
/// child it intends to run (issue #1884; I1.9, AUD3).
///
/// Both are read from `EliotdLaunchDescriptor`'s OWN `job_object_limits` and
/// `health_readiness_contract_ref` fields, so the comparison against the
/// immutable manifest keeps an independent side. The descriptor is loaded from a
/// separately digest-bound approved file and is not inferred from the Kernel
/// executable, the current directory or the environment, so a descriptor whose
/// Job Object limits or readiness contract no longer stand for the admitted
/// manifest changes what this returns and is refused by the verifier.
///
/// `None` means the DESCRIPTOR states none, and that is a legitimate
/// observation rather than a shape error:
/// `KernelExecutionRestartRequest` carries both coordinates as `Option` exactly
/// so a caller that can observe neither can say "I observed nothing" instead of
/// inventing a value. The absence is forwarded unchanged and the DECISION
/// refuses it, under `ManifestResourceLimitsUnobserved` or
/// `ManifestReadinessContractUnobserved`; this file projects that recorded kind
/// through `daemon_restart_refusal_for_manifest_cause` like every other one. An
/// unobservable coordinate is never assumed equal to the recorded one and is
/// never defaulted into a permissive one.
///
/// The immutable manifest row is never read here. Restating the recorded values
/// from it would compare the manifest with itself and could never fail, which is
/// the vacuous comparison this delivery removes.
#[cfg(windows)]
fn daemon_candidate_observed_job_object_limits_and_readiness(
    launch: &EliotdLaunchDescriptor,
) -> (Option<eliot_ors::ManifestResourceLimits>, Option<String>) {
    (
        launch.job_object_limits.clone(),
        launch.health_readiness_contract_ref.clone(),
    )
}

#[cfg(windows)]
fn record_daemon_recovery_operation_context(
    context: &tracing::Span,
    receipt: Option<&ProcessStartReceipt>,
) {
    let receipt = receipt.filter(|receipt| receipt.validate().is_ok());
    let generation = receipt.map(|receipt| receipt.accepted_generation().get().to_string());
    let epoch = receipt.and_then(|receipt| {
        eliot_contracts::StateFence::canonical_epoch_digest(receipt.binding().authority_epoch())
            .ok()
    });
    let state_fence = receipt.zip(epoch.as_ref()).map(|(receipt, epoch)| {
        format!(
            "epoch={};resource_generation={}",
            epoch.as_str(),
            receipt.binding().state_fence().generation().get()
        )
    });
    for (field, original) in [
        (
            "operation",
            receipt.map(|receipt| receipt.operation_id().as_str()),
        ),
        ("generation", generation.as_deref()),
        ("state_fence", state_fence.as_deref()),
        (
            "authority_epoch",
            epoch.as_ref().map(eliot_contracts::LowercaseSha256::as_str),
        ),
    ] {
        if let Some(original) = original {
            let value = super::kernel_diagnostics::bound_field(original);
            context.record(field, value.text());
        }
    }
    if let Some(receipt) = receipt {
        super::daemon_live_receipt::record_process_receipt_context(context, receipt);
        let process_tree =
            super::kernel_diagnostics::bound_field(receipt.binding().process_tree_id().as_str());
        context.record("process_tree", process_tree.text());
    }
}

impl KernelComposition {
    /// Returns the immutable approved child contour, if integrated startup
    /// supplied one.  Absence is an integration error, not a permission to
    /// infer a sibling executable.
    ///
    /// Diagnostic read (F-LOG-KERNEL-4, #903): only contour presence is
    /// observed; the descriptor itself is never logged.
    #[must_use]
    pub fn daemon_launch(&self) -> Option<&EliotdLaunchDescriptor> {
        let launch = self.daemon_launch.as_ref();
        observe_daemon_runtime(
            "kernel.daemon.contour_observed",
            if launch.is_some() {
                "present"
            } else {
                "absent"
            },
        );
        launch
    }

    pub(crate) fn active_daemon_launch(
        &self,
    ) -> Result<Option<EliotdLaunchDescriptor>, KernelServiceError> {
        self.daemon_active_launch
            .lock()
            .map(|launch| launch.clone())
            .map_err(|_| KernelServiceError::Platform("daemon launch lock poisoned".to_owned()))
    }

    /// Returns whether `eliotd` has completed its authenticated ready report.
    #[must_use]
    pub fn daemon_ready(&self) -> bool {
        self.daemon_runtime
            .lock()
            .is_ok_and(|state| daemon_status_proves_ready(&state.status))
    }

    fn daemon_failure_error(&self, reason: String) -> KernelBuildError {
        let mut terminal = reason;
        if let Err(error) = self.mark_daemon_failed(terminal.clone()) {
            terminal.push_str("; failed to record and fence eliotd failure: ");
            terminal.push_str(&error.to_string());
        }
        KernelBuildError::Service(terminal)
    }

    #[cfg(windows)]
    fn revoke_daemon_agent_bridge_profile(&self) -> Result<(), KernelServiceError> {
        self.promote_agent_bridge_profile(None).map_err(|error| {
            KernelServiceError::Platform(format!(
                "eliotd agent-bridge profile revocation failed: {error}"
            ))
        })
    }

    #[cfg(windows)]
    pub(crate) async fn await_daemon_ready(
        &self,
        launched: &ProcessStartReceipt,
        timeout: Duration,
        context: &tracing::Span,
    ) -> Result<(), KernelBuildError> {
        enum AwaitDecision {
            Ready,
            Running,
            Rejected(&'static str, KernelBuildError),
        }

        // F-LOG-KERNEL-4 (#903): readiness-rendezvous observations. This
        // rendezvous is always a subordinate phase of a larger operation
        // (recovery, control request, or probe), so every outcome here is an
        // info; the owning operation emits the single terminal. Liveness
        // (a running process) is never logged as readiness.
        observe_daemon_runtime_in_context("kernel.daemon.await_requested", "attempt", context);
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let changed = self.daemon_status_changed.notified();
            let decision = {
                let state = self.daemon_runtime.lock().map_err(|_| {
                    KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
                })?;
                if state.receipt.as_ref() == Some(launched) {
                    match &state.status {
                        DaemonRuntimeStatus::Ready => AwaitDecision::Ready,
                        DaemonRuntimeStatus::Running => AwaitDecision::Running,
                        DaemonRuntimeStatus::Degraded(reason) => AwaitDecision::Rejected(
                            "degraded_before_ready",
                            KernelBuildError::Service(format!(
                                "eliotd degraded before authenticated readiness: {reason}"
                            )),
                        ),
                        DaemonRuntimeStatus::Failed(reason) => AwaitDecision::Rejected(
                            "failed_before_ready",
                            KernelBuildError::Service(format!(
                                "eliotd failed before authenticated readiness: {reason}"
                            )),
                        ),
                        DaemonRuntimeStatus::NotLaunched | DaemonRuntimeStatus::Launching => {
                            AwaitDecision::Rejected(
                                "not_launched",
                                KernelBuildError::Service(
                                    "eliotd readiness wait has no launched process".to_owned(),
                                ),
                            )
                        }
                    }
                } else {
                    AwaitDecision::Rejected(
                        "receipt_mismatch",
                        KernelBuildError::Service(
                            "eliotd readiness is not bound to the exact launched process receipt"
                                .to_owned(),
                        ),
                    )
                }
            };
            match decision {
                AwaitDecision::Ready => {
                    observe_daemon_runtime_in_context(
                        "kernel.daemon.await_satisfied",
                        "success",
                        context,
                    );
                    return Ok(());
                }
                AwaitDecision::Running => {}
                AwaitDecision::Rejected(outcome, error) => {
                    observe_daemon_runtime_in_context(
                        "kernel.daemon.await_rejected",
                        outcome,
                        context,
                    );
                    return Err(error);
                }
            }
            if tokio::time::timeout_at(deadline, changed).await.is_err() {
                observe_daemon_runtime_in_context(
                    "kernel.daemon.await_rejected",
                    "timeout",
                    context,
                );
                let reason = format!(
                    "eliotd did not complete authenticated Governor recovery and report_ready within {} ms",
                    timeout.as_millis()
                );
                return Err(self.daemon_failure_error(reason));
            }
        }
    }

    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "recovery closure keeps exact disposition inspection and terminal proof ordered"
    )]
    pub(super) async fn close_previous_daemon_process(
        &self,
        launch: &EliotdLaunchDescriptor,
        receipt: &ProcessStartReceipt,
        context: &tracing::Span,
        child_terminal_owned: &mut bool,
    ) -> Result<ProcessExecutionView, KernelBuildError> {
        let gateway = self.process_gateway.as_ref().ok_or_else(|| {
            KernelBuildError::Service(
                "process authority is required for eliotd recovery".to_owned(),
            )
        })?;
        receipt
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let generation = Generation::new(launch.generation.value())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let kernel_process = observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let launch_identity = eliotd_launch_attempt_identity(
            launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )?;
        let expected_operation = eliotd_operation_id(generation, &launch_identity)?;
        // INTENDED EpochId shape (B→A→C): exact-tuple is_same_authority, no
        // scalar !=, no .value() coercion.
        if receipt.operation_id() != &expected_operation
            || receipt.accepted_generation().get() != launch.generation.value()
            || !receipt
                .binding()
                .state_fence()
                .authority_epoch()
                .is_same_authority(&launch.authority_epoch)
            || receipt.binding().state_fence().generation() != generation
            || receipt.identity().executable_sha256() != launch.executable_sha256
            || !receipt
                .identity()
                .physical()
                .image_path()
                .eq_ignore_ascii_case(launch.executable.as_str())
        {
            return Err(KernelBuildError::Service(
                "eliotd recovery refused a stale or substituted process receipt".to_owned(),
            ));
        }
        let kernel_expectation = current_process_named_pipe_expectation()
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let owner = ProcessOwnerBinding::new(
            ACTIVE_DAEMON_CALLER,
            stable_owner_principal_digest(
                kernel_expectation.expected_sid(),
                ACTIVE_DAEMON_CALLER,
                &launch.authority_epoch,
                generation,
            ),
            launch.authority_epoch.clone(),
            generation,
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let view = match gateway
            .inspect_in_context(&owner, receipt.operation_id().clone(), context)
            .await
        {
            Ok(view) => view,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                *child_terminal_owned = true;
                return Err(KernelBuildError::Service(
                    "eliotd previous process outcome is unknown; recovery is fenced".to_owned(),
                ));
            }
            Err(error) => {
                *child_terminal_owned = true;
                return Err(KernelBuildError::Service(error.to_string()));
            }
        };
        if view.binding() != receipt.binding() || view.identity() != Some(receipt.identity()) {
            return Err(KernelBuildError::Service(
                "eliotd previous process inspection does not match its receipt".to_owned(),
            ));
        }
        match view.lifecycle() {
            ProcessLifecycle::Exited | ProcessLifecycle::Failed | ProcessLifecycle::Reconciled => {
                let closed = self
                    .reconcile_closed_daemon_process(
                        gateway,
                        &owner,
                        launch,
                        receipt,
                        context,
                        child_terminal_owned,
                    )
                    .await?;
                self.close_restarted_daemon_descendant(
                    gateway,
                    &owner,
                    receipt,
                    context,
                    child_terminal_owned,
                )
                .await?;
                Ok(closed)
            }
            ProcessLifecycle::Running => {
                let cancellation = gateway
                    .cancel_in_context(&owner, receipt.operation_id().clone(), context)
                    .await
                    .map_err(|error| {
                        *child_terminal_owned = true;
                        KernelBuildError::Service(error.to_string())
                    })?;
                if cancellation.binding() != receipt.binding() {
                    return Err(KernelBuildError::Service(
                        "eliotd previous process cancellation binding changed".to_owned(),
                    ));
                }
                let cancelled = gateway
                    .inspect_in_context(&owner, receipt.operation_id().clone(), context)
                    .await
                    .map_err(|error| {
                        *child_terminal_owned = true;
                        KernelBuildError::Service(error.to_string())
                    })?;
                if cancelled.binding() != receipt.binding()
                    || cancelled.identity() != Some(receipt.identity())
                    || cancelled.lifecycle() != ProcessLifecycle::Exited
                    || cancelled.cancellation() != CancellationStatus::Completed
                    || !cancelled.descendants().is_some_and(|descendants| {
                        descendants.complete() && descendants.tree_terminated()
                    })
                {
                    return Err(KernelBuildError::Service(
                        "eliotd previous process tree closure was not proven".to_owned(),
                    ));
                }
                let closed = self
                    .reconcile_closed_daemon_process(
                        gateway,
                        &owner,
                        launch,
                        receipt,
                        context,
                        child_terminal_owned,
                    )
                    .await?;
                self.close_restarted_daemon_descendant(
                    gateway,
                    &owner,
                    receipt,
                    context,
                    child_terminal_owned,
                )
                .await?;
                Ok(closed)
            }
            ProcessLifecycle::Quarantined => {
                // Issue #1839 (I16.4 quarantine): the previous lineage is
                // fenced for manual recovery, so restart recovery refuses it
                // instead of adopting a quarantined process.
                self.audit_observe(AuditEventDraft::process_daemon_status(
                    AuditEventKind::PROCESS_QUARANTINED,
                    Some(receipt),
                    "previous_process_quarantined:restart_refused",
                    self.current_state_fence().as_ref(),
                ));
                Err(KernelBuildError::Service(
                    "eliotd previous process is quarantined for manual recovery".to_owned(),
                ))
            }
            ProcessLifecycle::Created
            | ProcessLifecycle::Starting
            | ProcessLifecycle::Cancelling
            | ProcessLifecycle::UnknownOutcome => Err(KernelBuildError::Service(
                "eliotd previous process is not in a known terminal state".to_owned(),
            )),
        }
    }

    /// Produces the descendant-closure receipt for one restarted daemon
    /// generation as durable audit evidence (CHILD-1/CHILD-2, #1918). The
    /// restart proof above already established tree closure; a close fault
    /// here fails the restart instead of asserting an unrecorded closure.
    #[cfg(windows)]
    async fn close_restarted_daemon_descendant(
        &self,
        gateway: &std::sync::Arc<super::process_execution::ProcessExecutionGateway>,
        owner: &ProcessOwnerBinding,
        receipt: &ProcessStartReceipt,
        context: &tracing::Span,
        child_terminal_owned: &mut bool,
    ) -> Result<(), KernelBuildError> {
        let closure = gateway
            .close_registered_descendant_in_context(owner, receipt.operation_id().clone(), context)
            .await
            .map_err(|error| {
                *child_terminal_owned = true;
                KernelBuildError::Service(error.to_string())
            })?;
        self.audit_observe(AuditEventDraft::descendant_closure(&closure));
        Ok(())
    }

    /// Reconciles one already-closed supervised `eliotd` generation by its
    /// original operation identity and links the ORS cutover readback.
    ///
    /// T2-S08K (Implements #100): the close path observes (`inspect`) and
    /// cancels (`cancel`) the exact supervised generation, then reconciles it
    /// without minting a fresh operation identity. Unknown keeps its original
    /// identity and fails fenced for bounded drain instead of blind retry.
    /// The durable link is a read-only ORS projection through the existing
    /// generation coordinator contour (`reconcile_staged_*` +
    /// `latest_generation_cutovers`, as seeded by `recover` at startup) plus
    /// the active daemon-route projection check. No new launcher, no new
    /// public process signature, no Doctor/epoch edits.
    #[cfg(windows)]
    async fn reconcile_closed_daemon_process(
        &self,
        gateway: &super::ProcessExecutionGateway,
        owner: &ProcessOwnerBinding,
        launch: &EliotdLaunchDescriptor,
        receipt: &ProcessStartReceipt,
        context: &tracing::Span,
        child_terminal_owned: &mut bool,
    ) -> Result<ProcessExecutionView, KernelBuildError> {
        let evidence = match gateway
            .reconcile_in_context(owner, receipt.operation_id().clone(), context)
            .await
        {
            Ok(evidence) => evidence,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                *child_terminal_owned = true;
                return Err(KernelBuildError::Service(
                    "eliotd previous process outcome is unknown; recovery is fenced".to_owned(),
                ));
            }
            Err(error) => {
                *child_terminal_owned = true;
                return Err(KernelBuildError::Service(error.to_string()));
            }
        };
        if evidence.operation_id() != receipt.operation_id()
            || evidence.binding() != receipt.binding()
        {
            return Err(KernelBuildError::Service(
                "eliotd previous process reconcile binding changed".to_owned(),
            ));
        }
        if evidence.view().identity() != Some(receipt.identity()) {
            return Err(KernelBuildError::Service(
                "eliotd previous process reconcile identity changed".to_owned(),
            ));
        }
        if !matches!(
            evidence.view().lifecycle(),
            ProcessLifecycle::Exited | ProcessLifecycle::Failed | ProcessLifecycle::Reconciled
        ) {
            return Err(KernelBuildError::Service(
                "eliotd previous process reconcile was not terminal".to_owned(),
            ));
        }
        self.generation_gateway
            .ors
            .reconcile_staged_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd ORS staged cutover reconciliation failed: {error}"
                ))
            })?;
        self.generation_gateway
            .ors
            .latest_generation_cutovers(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| {
                KernelBuildError::Service(format!("eliotd ORS cutover readback failed: {error}"))
            })?;
        let scope = RouteScope::new("daemon")
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let generations = self
            .generations
            .lock()
            .map_err(|_| KernelBuildError::Service("generation lock poisoned".to_owned()))?;
        // The canonical router owns this admission rule (Implements #64), so the
        // route is not compared inline here any more. The launch descriptor
        // carries no physical process generation and no fence nonce, so it is
        // presented to the router's supervised-generation entry point, which
        // applies the same exact-tuple epoch guard and the same exact
        // generation comparison as the `RouteFence` path: a supervised launch
        // from a different lineage at the same sequence is not the active
        // daemon route, and a fenced or unactivated epoch cannot match the
        // route either.
        generations
            .route_for_supervised_generation(&scope, launch.generation, &launch.authority_epoch)
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd supervised generation is not the active daemon route: {error}"
                ))
            })?;
        // The reconciled terminal view is returned so the caller's declared
        // restart class is evaluated against the exact exit evidence the
        // process owner recorded for this generation, not against a guess.
        Ok(evidence.view().clone())
    }

    /// The admission dispatcher the BOUNDED RECOVERY launch arm passes through
    /// (issue #1884; I1.9, AUD3, W1.5).
    ///
    /// It chooses between the two dispositions the recovery arm can be in, and
    /// both of them land on the same sealed
    /// [`eliot_ors::BoundKernelExecutionManifest`] the launch primitive requires,
    /// or on a typed refusal. The operator activation arm reaches the same
    /// first-launch disposition directly, through
    /// `KernelComposition::admit_daemon_restart_under_manifest` with a zero
    /// recorded spend, because an activation names no previous generation to
    /// replace; `KernelComposition::launch_eliotd_for_activation_under_manifest`
    /// is that entry. There is no production launch arm that reaches a process
    /// launch without that sealed binding.
    ///
    /// Only the REPLACEMENT carries restart-specific machinery, and it is
    /// restart-specific by definition rather than by exemption:
    ///
    /// * a replacement is additionally decided by the admitted restart
    ///   declaration, the durable restart record for this child identity and
    ///   generation, and the declared attempt threshold, so a restart cannot hand
    ///   out a fresh window;
    /// * a first launch has no previous generation to replace, so it consumes no
    ///   restart budget, reads no restart record and is admitted straight against
    ///   the sealed manifest for this exact generation.
    ///
    /// Both arms refuse before the previous generation is closed, so a withheld
    /// launch never destroys a child it cannot replace.
    #[cfg(windows)]
    fn admit_daemon_launch_under_manifest(
        &self,
        launch: &EliotdLaunchDescriptor,
        attempt: u64,
        previous_receipt: Option<&ProcessStartReceipt>,
    ) -> Result<DaemonRestartManifestAdmission, KernelBuildError> {
        match previous_receipt {
            Some(receipt) => self.admit_daemon_restart_attempt(launch, attempt, Some(receipt)),
            None => self.admit_daemon_restart_under_manifest(launch, 0),
        }
    }

    /// Decides one automatic restart attempt against the owner's DURABLE
    /// restart record and the immutable execution manifest bound to the
    /// admitted generation, and returns either the sealed manifest-bound
    /// authority the replacement may run under or the refusal that withholds it.
    ///
    /// This is the REPLACEMENT arm of
    /// [`KernelComposition::admit_daemon_launch_under_manifest`]; a first launch
    /// does not come here, from either production entry, because it is not a
    /// restart and spends no budget.
    ///
    /// `attempt` is the Kernel's restart ordinal for this process lifetime and
    /// is NOT the budget: it names the replacement generation and is compared
    /// against the threshold the admitted declaration itself declares. The
    /// decision that must survive a daemon restart is the durable one, and it
    /// is read from this owner's retained ORS restart record - keyed to the
    /// supervised child's stable identity (`ACTIVE_DAEMON_CALLER`) and to the
    /// admitted generation being replaced.
    ///
    /// The refusals that can arise here are absences rather than defaults:
    ///
    /// * no admitted restart policy means this child has no declared restart
    ///   budget at all, so its replacement is refused as
    ///   `DaemonRestartRefusal::PolicyNotAdmitted` BEFORE the previous
    ///   generation is closed. That ordering matters: a withheld replacement
    ///   must never destroy a child it cannot replace.
    /// * a durable record that already exists under this child's identity and
    ///   admitted generation means the restart disposition for this lineage was
    ///   already decided durably, so the attempt is refused and no fresh window
    ///   is opened. That record is what a recreated supervisor reads back, and
    ///   it is read back as the decision it is: the recorded cause is projected
    ///   through [`daemon_restart_refusal_for_manifest_cause`], so a recorded
    ///   manifest defect keeps its own reason instead of being reported as a
    ///   spent budget. This boundary never rewrites a row it did not read as
    ///   absent: an existing durable disposition is never treated as permission
    ///   and never replaced by a locally recomputed one.
    ///
    /// The remaining outcomes are an unreadable or invalid durable record and
    /// an unreadable manifest row, both of which are returned as mechanical
    /// failures: an unreadable record is never read as an absent one and never
    /// as permission.
    #[cfg(windows)]
    fn admit_daemon_restart_attempt(
        &self,
        launch: &EliotdLaunchDescriptor,
        attempt: u64,
        previous_receipt: Option<&ProcessStartReceipt>,
    ) -> Result<DaemonRestartManifestAdmission, KernelBuildError> {
        let admitted_generation = launch.generation;
        let admitted_state_fence =
            eliot_contracts::StateFence::new(launch.authority_epoch.clone(), admitted_generation);
        let Some(admitted) = self.daemon_restart_policy.as_ref() else {
            return Ok(DaemonRestartManifestAdmission::Refused(
                DaemonRestartRefusal::PolicyNotAdmitted,
            ));
        };
        // The threshold is read only while the retained binding still proves
        // the exact admitted generation and fence the caller observed. A
        // binding that does not prove them is the same defect the class rule
        // already names for this identity, so it is refused with that same
        // reason instead of being reported as a budget of its own.
        let Ok(declared_threshold) =
            admitted.declared_attempt_threshold(admitted_generation, &admitted_state_fence)
        else {
            return Ok(DaemonRestartManifestAdmission::Refused(
                DaemonRestartRefusal::PolicyNotBoundToAdmittedGeneration,
            ));
        };
        let store = self.generation_gateway.ors.as_ref();
        let recorded = store
            .load_kernel_restart_reconciliation(ACTIVE_DAEMON_CALLER, admitted_generation.value())
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd durable restart record is unreadable: {error}"
                ))
            })?;
        // A durable row under this child's identity and generation is the
        // decision it was committed as, read back unchanged and never replaced
        // by a locally recomputed one. Its recorded CAUSE is projected through
        // the shared mapping, so a recorded manifest defect keeps its own
        // reason instead of every cause collapsing into one budget refusal.
        if let Some(recorded) = recorded {
            return Ok(DaemonRestartManifestAdmission::Refused(
                daemon_restart_refusal_for_manifest_cause(recorded.kind),
            ));
        }
        // Issue #1884 (I1.9): the restart disposition is decided against the
        // immutable `KernelExecutionManifest` recorded for this exact module
        // and generation, and never against contemporaneous configuration.
        // `load_and_verify_kernel_execution_restart` loads that manifest by the
        // request's own identity, re-verifies its recorded bound digest on
        // readback, and then runs the pure verifier over the candidate
        // coordinates this owner OBSERVED, the Authority Epoch, the I1.12
        // evidence and the recorded restart budget. A missing, receipt-less,
        // stale, incompatible, revoked or identity-mismatched manifest therefore
        // refuses the restart instead of admitting it, and the ORS owner persists
        // that refusal's reconciliation item and moves the generation lifecycle
        // before returning, so the affected generation stays visibly degraded.
        //
        // `restarts_spent` is the durably recorded spend, which is exactly zero
        // on this arm: the durable record above is the spend record and it was
        // read back as absent. The process-local `attempt` ordinal is NOT spent
        // and is never substituted for it; the recorded budget ceiling is read
        // from the immutable manifest inside the verifier.
        let bound = match self.admit_daemon_restart_under_manifest(launch, 0)? {
            DaemonRestartManifestAdmission::Admitted(bound) => bound,
            DaemonRestartManifestAdmission::Refused(refusal) => {
                return Ok(DaemonRestartManifestAdmission::Refused(refusal));
            }
        };
        if attempt < u64::from(declared_threshold) {
            return Ok(DaemonRestartManifestAdmission::Admitted(bound));
        }
        let observed_at_ms = i64::try_from(super::unix_ms()).unwrap_or(i64::MAX);
        store
            .persist_kernel_restart_reconciliation(&eliot_ors::KernelReconciliationItem {
                kind: eliot_ors::KernelReconciliationKind::ManifestRestartBudgetExhausted,
                module_id: ACTIVE_DAEMON_CALLER.to_owned(),
                generation: admitted_generation,
                bound_manifest_sha256: Some(bound.manifest_sha256().to_owned()),
                recorded_manifest_sha256: Some(bound.manifest_sha256().to_owned()),
                lease_id: None,
                operation_id: None,
                observed_at_ms,
            })
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd durable restart record could not be persisted: {error}"
                ))
            })?;
        // Issue #1839 (I16.4 restart-intensity exhaustion): the bounded
        // recovery budget admitted no further restart for this child identity.
        // The observation is subordinate; the refusal above owns the terminal.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_RESTART_INTENSITY_EXHAUSTED,
            previous_receipt,
            "eliotd bounded restart budget is spent for this child identity",
            self.current_state_fence().as_ref(),
        ));
        Ok(DaemonRestartManifestAdmission::Refused(
            DaemonRestartRefusal::RestartBudgetExhausted,
        ))
    }

    /// Reads the immutable execution manifest recorded for this exact module and
    /// generation and asks its owner in ORS to verify this launch against it
    /// (issue #1884; I1.9, W1.5, AUD3).
    ///
    /// This is the ONE manifest gate both production launch arms reach: a first
    /// launch of the child and the replacement of a failed generation. It admits
    /// nothing by itself — it returns the sealed binding the launch primitive
    /// requires, or a typed refusal.
    ///
    /// `restarts_spent` is the durably recorded restart spend this attempt is
    /// decided under; the recorded budget CEILING is never supplied here, it is
    /// read from the immutable manifest by the verifier itself.
    ///
    /// Every request field is stated from an independent observation, a durable
    /// readback, or an explicit fail-closed reading. Nothing here rebuilds,
    /// defaults or reconstructs a manifest, and nothing here restates a recorded
    /// value back into the comparison that is supposed to check it:
    ///
    /// * the module identity is this supervised child's stable identity, the
    ///   same identity an admitted restart policy's `subject_id` must name, and
    ///   the generation is the admitted generation being launched;
    /// * the bound manifest digest is the digest the Generation Registry row
    ///   records for exactly this module and generation;
    /// * `candidate` is the launch contour this owner OBSERVES on the
    ///   Host-approved descriptor it would actually launch from, built by
    ///   [`daemon_candidate_launch_binding`]. The recorded binding is never fed
    ///   back in, so a descriptor whose artifact, config, protocol snapshot or
    ///   child argv no longer stands for the admitted manifest is refused here
    ///   rather than confirming itself;
    /// * `candidate_dependency_order` and `candidate_restart_budget` are read
    ///   through the admitted restart declaration this composition retains, whose
    ///   own accessors re-prove its digest against the generation and State
    ///   Fence the descriptor states. A child whose descriptor states no
    ///   admitted declaration has neither coordinate and is refused as
    ///   `PolicyNotAdmitted`: that is the fail-closed disposition the
    ///   declaration's own contract describes, never an unlimited budget;
    /// * `candidate_resource_limits` and `candidate_health_readiness_contract_ref`
    ///   are read from the Host-approved descriptor's OWN `job_object_limits` and
    ///   `health_readiness_contract_ref` fields by
    ///   `daemon_candidate_observed_job_object_limits_and_readiness` and are
    ///   forwarded exactly as stated, including a stated absence. The request
    ///   type carries both as `Option` so this owner never has to invent one, and
    ///   a descriptor that states neither is refused by the ORS verifier under
    ///   its own recorded kind (`ManifestResourceLimitsUnobserved`,
    ///   `ManifestReadinessContractUnobserved`) rather than by a local shape
    ///   check here: an unobserved coordinate is the decision's refusal, not a
    ///   malformed request, and the ORS owner records it durably like any other;
    /// * `current_authority_epoch` is this child's own retained launch epoch read
    ///   as the Kernel authority epoch counter, exactly as this owner's process
    ///   execution gate reads it for an exact effect replay
    ///   (`require_effect_replay_authority`);
    /// * `current_catalog_revision` and `current_policy_revision` are the
    ///   recorded admission's accepted revisions, and `catalog_view` is
    ///   [`eliot_ors::CatalogPolicyView::Unavailable`] because this owner holds
    ///   no live Module Catalog/Policy readback — there is none in ORS or on the
    ///   control wire, which is the same absence ORS records as its own
    ///   assumption at `authorize_effect_replay_for_operation`. The absent
    ///   readback keeps the fail-closed reading, so an effect-capable manifest is
    ///   capped at shadow diagnostics and is refused below rather than opened as
    ///   normal-effect service. It is never flipped to `Current`;
    /// * `revocation` is
    ///   [`eliot_ors::RevocationAcknowledgement::Unacknowledged`] and `delivery`
    ///   is [`eliot_ors::EffectDeliveryAcknowledgement::GapOpen`] because the only
    ///   revocation-event and delivery-state readbacks ORS owns are keyed by
    ///   EFFECT OPERATION LEASE identity (`load_revocation_event` and
    ///   `load_effect_delivery_record` both take an `OperationIdentity`), and a
    ///   general launch names no lease, so no row can be read here. An absent
    ///   readback keeps the fail-closed reading: an unobservable clearance is not
    ///   a clearance, exactly as ORS itself reads it for the leased path;
    /// * `compatibility` is the I1.12 verdict recorded for this exact module and
    ///   generation, read back from the durable versioned-artifact registry. A
    ///   generation with no recorded verdict is refused and never given a
    ///   synthesised one;
    /// * the generation's own lifecycle readback
    ///   (`RedbRecoveryStore::load_generation_lifecycle`) is consulted before the
    ///   request is built: a generation ORS has already recorded as `Degraded` or
    ///   `Quarantined` is refused under the cause that record carries, so a
    ///   durable refusal is a real lifecycle state a later attempt reads back
    ///   instead of a side-table row nobody consumes. An ABSENT row is not a
    ///   refusal here and is not read as one: no degradation recorded means no
    ///   degradation happened, and the admission still requires the recorded
    ///   immutable manifest, which
    ///   `RedbRecoveryStore::load_observed_generation_lifecycle` composes with
    ///   that absence into the one observation the ORS verifier itself checks. The
    ///   store owns that composition, so this owner cannot present a clearance it
    ///   built out of an absence - it either has the recorded degradation or it
    ///   has nothing to say.
    #[cfg(windows)]
    fn admit_daemon_restart_under_manifest(
        &self,
        launch: &EliotdLaunchDescriptor,
        restarts_spent: u32,
    ) -> Result<DaemonRestartManifestAdmission, KernelBuildError> {
        let store = self.generation_gateway.ors.as_ref();
        let observed_at_ms = i64::try_from(super::unix_ms()).unwrap_or(i64::MAX);
        let generation = launch.generation;
        let manifest = store
            .load_kernel_execution_manifest(ACTIVE_DAEMON_CALLER, generation.value())
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd immutable execution manifest is unreadable: {error}"
                ))
            })?;
        // A generation with no recorded manifest can name no bound manifest
        // digest, so no request can be stated for it at all. The absence is
        // recorded durably under ORS's own typed kind and refused, so the
        // affected generation stays visibly degraded instead of restarting.
        let Some(manifest) = manifest else {
            return self.refuse_daemon_restart_under_manifest(
                ACTIVE_DAEMON_CALLER,
                eliot_ors::KernelReconciliationKind::ManifestAbsent,
                generation,
                None,
                None,
                observed_at_ms,
            );
        };
        // A receipt-less manifest records no accepted Catalog/Policy revision,
        // so this owner can state no current one and cannot construct the request
        // at all. It is refused under ORS's own receipt-less kind rather than
        // being given a synthesised revision.
        if !manifest.has_governor_admission() {
            return self.refuse_daemon_restart_under_manifest(
                ACTIVE_DAEMON_CALLER,
                eliot_ors::KernelReconciliationKind::ManifestReceiptless,
                generation,
                None,
                Some(manifest.manifest_sha256.as_str()),
                observed_at_ms,
            );
        }
        // The generation's own lifecycle row is the REAL lifecycle owner, and it
        // is read before anything is launched: a generation ORS has already
        // recorded as `Degraded` or `Quarantined` for a recorded manifest refusal
        // launches nothing.
        if let Some(cause) = self.daemon_generation_launch_blocker(generation)? {
            return self.refuse_daemon_restart_under_manifest(
                ACTIVE_DAEMON_CALLER,
                cause,
                generation,
                None,
                Some(manifest.manifest_sha256.as_str()),
                observed_at_ms,
            );
        }
        let compatibility = store
            .load_versioned_artifact_registry(eliot_ors::MAX_RECOVERY_PAGE)
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd recorded I1.12 verdicts are unreadable: {error}"
                ))
            })?
            .compatibility(ACTIVE_DAEMON_CALLER, generation.value())
            .cloned();
        let Some(compatibility) = compatibility else {
            // No recorded I1.12 verdict means this owner can state no
            // compatibility evidence, so no request can be built for this
            // generation. It is refused under ORS's own incompatible kind, which
            // is the cause its verifier produces for a candidate that fails
            // I1.12 evidence, and the refusal is recorded durably so the
            // affected generation stays visibly degraded instead of restarting.
            return self.refuse_daemon_restart_under_manifest(
                ACTIVE_DAEMON_CALLER,
                eliot_ors::KernelReconciliationKind::ManifestIncompatible,
                generation,
                None,
                Some(manifest.manifest_sha256.as_str()),
                observed_at_ms,
            );
        };
        self.verify_daemon_launch_under_manifest(
            launch,
            &manifest,
            compatibility,
            restarts_spent,
            observed_at_ms,
        )
    }

    /// The recorded cause that blocks any launch of this generation, read from
    /// the Generation Registry's own lifecycle row (issue #1884; I1.9, AUD5).
    ///
    /// This is the real lifecycle owner the refusal path moves, and the launch
    /// path consults: a `Degraded` or `Quarantined` generation launches nothing,
    /// and it is refused under the cause that row KEEPS. `GenerationLifecycleRecord`
    /// never replaces its first cause, so a later and different observation for
    /// the same generation cannot erase the reason the generation degraded.
    ///
    /// `Ok(None)` means the row admits a launch. An ABSENT row is deliberately
    /// not read as `Undegraded`: ORS records `Undegraded` only for a generation
    /// whose admitted manifest it persisted, so an absent row is an unrecorded
    /// generation and it is left to the manifest checks, which refuse it. An
    /// unreadable row is a mechanical failure, never a permission.
    #[cfg(windows)]
    fn daemon_generation_launch_blocker(
        &self,
        generation: eliot_contracts::ResourceGeneration,
    ) -> Result<Option<eliot_ors::KernelReconciliationKind>, KernelBuildError> {
        let lifecycle = self
            .generation_gateway
            .ors
            .as_ref()
            .load_generation_lifecycle(ACTIVE_DAEMON_CALLER, generation.value())
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd generation lifecycle readback is unreadable: {error}"
                ))
            })?;
        let Some(lifecycle) = lifecycle else {
            return Ok(None);
        };
        if lifecycle.admits_launch() {
            return Ok(None);
        }
        match lifecycle.first_refusal_cause {
            Some(cause) => Ok(Some(cause)),
            None => Err(KernelBuildError::Service(
                "eliotd generation lifecycle row refuses launch with no recorded cause".to_owned(),
            )),
        }
    }

    /// Builds the manifest-bound launch request out of the independent
    /// observations and asks the ORS owner to verify this exact launch against
    /// the immutable manifest (issue #1884; I1.9, W1.5).
    ///
    /// `load_and_verify_kernel_execution_restart` loads the manifest by this
    /// request's own identity, re-verifies its recorded bound digest on
    /// readback, and then runs the pure verifier over the observed candidate
    /// coordinates, the Authority Epoch, the I1.12 evidence, the recorded
    /// compatibility evidence and the recorded restart budget. A missing,
    /// receipt-less, stale, incompatible, revoked or identity-mismatched
    /// manifest therefore refuses the launch instead of admitting it, and the
    /// ORS owner persists that refusal's reconciliation item and moves the real
    /// generation lifecycle before returning, so the affected generation stays
    /// visibly degraded.
    ///
    /// Every coordinate below is this owner's own observation. The recorded
    /// manifest row is read only for the two values that are BY DEFINITION the
    /// record's own identity — the bound digest and the accepted Catalog/Policy
    /// revisions the admission sealed — and never as a substitute for an
    /// observation.
    #[cfg(windows)]
    fn verify_daemon_launch_under_manifest(
        &self,
        launch: &EliotdLaunchDescriptor,
        manifest: &eliot_ors::KernelExecutionManifest,
        compatibility: eliot_ors::CompatibilityEvidence,
        restarts_spent: u32,
        observed_at_ms: i64,
    ) -> Result<DaemonRestartManifestAdmission, KernelBuildError> {
        let store = self.generation_gateway.ors.as_ref();
        let generation = launch.generation;
        // The candidate contour is read from the descriptor this owner would
        // actually launch from, so the comparison has an independent side.
        let candidate = daemon_candidate_launch_binding(launch);
        // The dependency order and the bounded restart budget are the admitted
        // restart declaration's, read through the retained binding so the
        // declaration's own digest is re-proved against this generation and
        // State Fence. A child with no admitted declaration states neither
        // coordinate and is refused, which is that declaration's own fail-closed
        // disposition rather than a synthesised budget.
        let (candidate_dependency_order, candidate_restart_budget) =
            match daemon_candidate_restart_coordinates(self.daemon_restart_policy.as_ref(), launch)
            {
                Ok(coordinates) => coordinates,
                Err(refusal) => {
                    return Ok(DaemonRestartManifestAdmission::Refused(refusal));
                }
            };
        // The Job Object/resource limits and the health/readiness contract
        // reference are the two coordinates the descriptor states or states
        // none of, and both are forwarded exactly as observed. A stated absence
        // is not a local refusal: it is a legitimate observation the ORS verifier
        // refuses under its own recorded kind, so the request is built either
        // way and the decision owns the disposition.
        let (candidate_resource_limits, candidate_health_readiness_contract_ref) =
            daemon_candidate_observed_job_object_limits_and_readiness(launch);
        let current_authority_epoch = eliot_contracts::AuthorityEpoch::new(
            launch.authority_epoch.sequence.get(),
        )
        .map_err(|error| {
            KernelBuildError::Service(format!(
                "eliotd retained epoch is not a Kernel authority epoch: {error}"
            ))
        })?;
        let request = eliot_ors::KernelExecutionRestartRequest {
            module_id: ACTIVE_DAEMON_CALLER.to_owned(),
            generation,
            bound_manifest_sha256: manifest.manifest_sha256.clone(),
            candidate,
            candidate_dependency_order,
            candidate_resource_limits,
            candidate_health_readiness_contract_ref,
            candidate_restart_budget,
            current_authority_epoch,
            current_catalog_revision: manifest.admission.catalog_revision,
            current_policy_revision: manifest.admission.policy_revision,
            catalog_view: eliot_ors::CatalogPolicyView::Unavailable,
            revocation: eliot_ors::RevocationAcknowledgement::Unacknowledged,
            delivery: eliot_ors::EffectDeliveryAcknowledgement::GapOpen,
            compatibility,
            restarts_spent,
            observed_at_ms,
        };
        let decision = store
            .load_and_verify_kernel_execution_restart(&request)
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd manifest-bound launch verification failed: {error}"
                ))
            })?;
        match &decision.admission {
            // Only a normal-service admission carries launch authority, and it
            // carries the sealed manifest the launch must be bound to.
            eliot_ors::KernelServiceAdmission::ReadRebuildService(bound)
            | eliot_ors::KernelServiceAdmission::EffectService(bound) => Ok(
                DaemonRestartManifestAdmission::Admitted(Box::new(bound.clone())),
            ),
            // `None` starts nothing, and shadow diagnostics carry no external
            // effect and no canonical write admission, so neither is a normal
            // launch. Both are refused with the decision's own recorded cause,
            // which the ORS owner has already persisted.
            eliot_ors::KernelServiceAdmission::ShadowDiagnosticsOnly(_)
            | eliot_ors::KernelServiceAdmission::None => {
                Ok(DaemonRestartManifestAdmission::Refused(
                    Self::daemon_manifest_restart_cause(&decision),
                ))
            }
        }
    }

    /// The typed refusal one refused manifest-bound decision carries.
    ///
    /// The decision's own first durable reconciliation item is the cause, so the
    /// ORS refusal survives the layer boundary instead of being reported as an
    /// unrelated budget or class verdict. The admission-derived codes below are
    /// only reached if a decision ever refused without recording a cause.
    #[cfg(windows)]
    fn daemon_manifest_restart_cause(
        decision: &eliot_ors::KernelRestartDecision,
    ) -> DaemonRestartRefusal {
        if let Some(item) = decision.reconciliation.first() {
            return daemon_restart_refusal_for_manifest_cause(item.kind);
        }
        match decision.admission {
            eliot_ors::KernelServiceAdmission::ShadowDiagnosticsOnly(_) => {
                DaemonRestartRefusal::ClassWithholds("restart_manifest_shadow_diagnostics_only")
            }
            eliot_ors::KernelServiceAdmission::None => {
                DaemonRestartRefusal::ClassWithholds("restart_manifest_declined")
            }
            eliot_ors::KernelServiceAdmission::ReadRebuildService(_)
            | eliot_ors::KernelServiceAdmission::EffectService(_) => {
                DaemonRestartRefusal::ClassWithholds("restart_manifest_cause_unrecorded")
            }
        }
    }

    /// Records one manifest-bound launch refusal durably and returns it as this
    /// file's typed refusal carrying the ORS kind's own bounded reason code.
    ///
    /// The write goes through the ORS owner, which appends the escalation under
    /// its own attempt ordinal and moves the generation's real lifecycle record
    /// in the same transaction, so a later attempt reads the degradation back
    /// instead of recomputing it.
    ///
    /// `module_id` and `generation` are the affected pair the caller proved, not
    /// this file's assumption about it: the lifecycle row that moves is the one
    /// keyed by exactly that pair, so a caller that holds a sealed binding reads
    /// both from the binding's own recorded admission.
    #[cfg(windows)]
    fn refuse_daemon_restart_under_manifest(
        &self,
        module_id: &str,
        kind: eliot_ors::KernelReconciliationKind,
        generation: eliot_contracts::ResourceGeneration,
        bound_manifest_sha256: Option<&str>,
        recorded_manifest_sha256: Option<&str>,
        observed_at_ms: i64,
    ) -> Result<DaemonRestartManifestAdmission, KernelBuildError> {
        self.generation_gateway
            .ors
            .as_ref()
            .persist_kernel_restart_reconciliation(&eliot_ors::KernelReconciliationItem {
                kind,
                module_id: module_id.to_owned(),
                generation,
                bound_manifest_sha256: bound_manifest_sha256.map(str::to_owned),
                recorded_manifest_sha256: recorded_manifest_sha256.map(str::to_owned),
                lease_id: None,
                operation_id: None,
                observed_at_ms,
            })
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd manifest-bound restart refusal could not be persisted: {error}"
                ))
            })?;
        Ok(DaemonRestartManifestAdmission::Refused(
            daemon_restart_refusal_for_manifest_cause(kind),
        ))
    }

    /// Refuses the launch unless the observed launch binding is the WHOLE
    /// recorded launch binding the sealed manifest carries (issue #1884; I1.9,
    /// AUD3).
    ///
    /// The immutable bytes, the exact daemon configuration, the protected
    /// snapshot identity and the rendered child command this launch would start
    /// are compared against the RECORDED launch binding, never against the
    /// retained descriptor alone and never against the manifest with itself, so
    /// a descriptor whose recorded launch identity no longer stands for the
    /// admitted manifest is refused instead of being launched.
    ///
    /// The comparison is over all FOUR `eliot_ors::KernelLaunchBinding` fields
    /// as ONE record. It was previously narrowed to `artifact_sha256` and
    /// `config_sha256` alone, which is precisely the two fields a per-attempt
    /// refresh does NOT mutate: the refresh changes the launch nonce and the
    /// descriptor digest, so the narrowed form covered neither the rendered
    /// `start_command` nor the protected `protocol_sha256` while this function's
    /// own documentation claimed it re-checked "the recorded launch identity". A
    /// whole-record equality cannot silently narrow again the way a pair of named
    /// scalars could: a future field added to `KernelLaunchBinding` enters this
    /// comparison structurally, with no edit to this function.
    ///
    /// `observed` and `bound` are two DISTINCT values and neither stands in for
    /// the other: `observed` is the projected candidate
    /// ([`daemon_candidate_launch_binding`]) built from the descriptor that will
    /// actually be launched, and `bound` is the sealed record. What is COMPARED
    /// comes from `observed`; what is APPLIED, in
    /// [`KernelComposition::launch_eliotd_under_manifest`], comes from `bound`.
    ///
    /// It is checked twice on purpose and by the same rule: once before the
    /// active launch descriptor and the runtime status are replaced, so a
    /// withheld launch never installs a contour the manifest does not record, and
    /// once inside the launch primitive itself, so no future caller of that
    /// primitive can reach a process start without the check.
    ///
    /// A refusal is RECORDED, not merely returned (issue #1884; I1.9, AUD5).
    /// Before the error is built, the disagreement is escalated through
    /// [`KernelComposition::refuse_daemon_restart_under_manifest`] — the SAME
    /// durable path every other refusal in this contour takes — which calls
    /// `RedbRecoveryStore::persist_kernel_restart_reconciliation` in
    /// `crates/kernel/eliot-ors/src/store.rs`. That owner appends the escalation
    /// under its own attempt ordinal and moves the affected generation's real
    /// `GENERATION_LIFECYCLES` row in the same transaction, so the generation is
    /// visibly degraded and
    /// [`KernelComposition::daemon_generation_launch_blocker`] blocks its next
    /// attempt instead of an improvised restart being tried again. The recorded
    /// kind is
    /// [`eliot_ors::KernelReconciliationKind::ManifestCandidateBindingMismatch`],
    /// this file's own recorded cause for a launch-identity disagreement, and the
    /// affected identity is read from the sealed binding's own recorded admission
    /// through `BoundKernelExecutionManifest::manifest` rather than assumed. The
    /// observable refusal reason below is unchanged: the durable cause and the
    /// bounded diagnostic code are separate vocabularies.
    #[cfg(windows)]
    fn require_recorded_launch_identity(
        &self,
        observed: &eliot_ors::KernelLaunchBinding,
        bound: &eliot_ors::BoundKernelExecutionManifest,
        context: &tracing::Span,
    ) -> Result<(), KernelBuildError> {
        let binding = bound.launch_binding();
        if observed == &binding {
            return Ok(());
        }
        // The evidence is durable BEFORE the error is returned, and a failure to
        // record it is itself an error rather than a silently dropped refusal.
        // The admission this call projects is deliberately not read: it is this
        // branch's own refusal, already decided, and the value that matters - the
        // appended `KERNEL_RESTART_RECONCILIATIONS` row and the lifecycle move
        // the append performed - is the store's own effect, which the `?` below
        // makes a precondition of returning at all. The reason this function
        // returns is its own bounded code, not the ORS projection.
        self.refuse_daemon_restart_under_manifest(
            bound.manifest().admission.module_id.as_str(),
            eliot_ors::KernelReconciliationKind::ManifestCandidateBindingMismatch,
            bound.manifest().admission.generation,
            Some(bound.manifest().manifest_sha256.as_str()),
            Some(bound.manifest().manifest_sha256.as_str()),
            i64::try_from(super::unix_ms()).unwrap_or(i64::MAX),
        )?;
        let reason = daemon_restart_refusal_reason(&DaemonRestartRefusal::ClassWithholds(
            "restart_launch_identity_not_the_recorded_manifest",
        ));
        observe_daemon_runtime_in_context("kernel.daemon.restart_refused", reason, context);
        Err(self.daemon_failure_error(format!("eliotd automatic restart refused: {reason}")))
    }

    /// The ONE production launch primitive for the supervised `eliotd` child
    /// (issue #1884; I1.9, AUD3, W1.5).
    ///
    /// It takes the sealed `BoundKernelExecutionManifest` as an argument and
    /// there is no way to obtain one without the ORS verifier: the type has a
    /// private field, a private constructor and no `Deserialize`, so no caller
    /// and no request can assemble one. That is the compile-time guard the audit
    /// asks for: this function is unreachable without a sealed manifest binding,
    /// and every launch this file performs goes through it. A launch path that
    /// wants to skip the manifest cannot call the primitive at all.
    ///
    /// The recorded launch identity is re-checked here through
    /// [`KernelComposition::require_recorded_launch_identity`] immediately before
    /// the process authority is reached, and it is re-checked as a WHOLE
    /// [`eliot_ors::KernelLaunchBinding`] record — all four fields, the observed
    /// one against the sealed one — so the primitive is not a way to launch a
    /// contour the manifest does not record, and so no future caller of it can
    /// narrow the check to the two digest scalars the check used to compare.
    ///
    /// `observed` is the candidate THIS launch would run and `bound` is the
    /// sealed record the gate admitted. They are two distinct values and neither
    /// stands in for the other: `observed` is only ever COMPARED, and everything
    /// this function APPLIES is projected from `bound`.
    ///
    /// The two remaining recorded launch coordinates are APPLIED from the SAME
    /// sealed binding this gate admitted, never from a second observation of
    /// owner state. `bound` is handed to the process primitive unchanged, and
    /// the OS-level ceilings that primitive installs are projected from
    /// `bound`'s own `resource_limits()` by
    /// `KernelComposition::eliotd_manifest_bound_resource_limits`
    /// (`bins/eliot-kernel/src/daemon_process_launch.rs`). The ACTIVE
    /// Host-approved descriptor is not re-read here, so what is applied is the
    /// sealed manifest's own `resource_limits()`, structurally, whatever the
    /// active slot holds at the moment of the process start. The applied
    /// ceilings and the applied readiness contract are named on the launch span
    /// below from that same binding, so the launch is observably the one the
    /// manifest records.
    ///
    /// What the removed second read did NOT do is worth stating, because it is
    /// the substitution the ORS owner already refuses: comparing the active
    /// descriptor's `job_object_limits` against `bound.resource_limits()` here
    /// re-derived a check the admission had already made coordinate by
    /// coordinate, through
    /// [`KernelComposition::verify_daemon_launch_under_manifest`] and
    /// `daemon_candidate_observed_job_object_limits_and_readiness`, and it
    /// refused with a reason this file recorded nowhere in ORS. A descriptor that
    /// states limits the manifest does not record is still refused, and durably,
    /// by that decision under `ManifestResourceLimitsMismatch`; a descriptor that
    /// states none at all is still refused, and durably, under
    /// `ManifestResourceLimitsUnobserved`, because the absence is forwarded to
    /// the decision rather than shaped into a request error here. The applied
    /// ceilings no longer depend on which of the two survived.
    #[cfg(windows)]
    async fn launch_eliotd_under_manifest(
        &self,
        observed: &eliot_ors::KernelLaunchBinding,
        bound: &eliot_ors::BoundKernelExecutionManifest,
        context: &tracing::Span,
    ) -> Result<ProcessStartReceipt, KernelBuildError> {
        self.require_recorded_launch_identity(observed, bound, context)?;
        // The applied Job Object/resource limits and the applied readiness
        // contract are read out of the sealed binding, once, and the very same
        // `bound` is what the primitive below receives. Nothing this launch
        // applies is projected from a re-read of the active descriptor.
        let applied_limits = bound.resource_limits();
        let applied_readiness = bound.health_readiness_contract_ref();
        let applied_max_processes = applied_limits.max_processes.to_string();
        let applied_max_working_set_bytes = applied_limits.max_working_set_bytes.to_string();
        let applied_cpu_rate_control = applied_limits.cpu_rate_control_percent.to_string();
        for (field, applied) in [
            (
                "job_object_policy",
                applied_limits.job_object_policy.as_str(),
            ),
            ("max_processes", applied_max_processes.as_str()),
            (
                "max_working_set_bytes",
                applied_max_working_set_bytes.as_str(),
            ),
            (
                "cpu_rate_control_percent",
                applied_cpu_rate_control.as_str(),
            ),
            ("readiness_contract", applied_readiness),
        ] {
            context.record(
                field,
                super::kernel_diagnostics::bound_field(applied).text(),
            );
        }
        self.launch_eliotd_in_context(context, bound).await
    }

    /// The one production launch entry for the operator-facing activation
    /// contour: it admits the activation's exact generation under the sealed
    /// immutable manifest and then launches through
    /// `KernelComposition::launch_eliotd_under_manifest` (issue #1884; I1.9).
    ///
    /// `KernelControlCommand::Activate` in
    /// `bins/eliot-kernel/src/control_plane.rs` is a production launch, not a
    /// recovery: it starts the child for the generation the activation names. It
    /// therefore reaches the process authority through the same manifest gate as
    /// a bounded recovery, and never around it.
    ///
    /// This is the FIRST-LAUNCH arm, so it selects exactly the arm
    /// `KernelComposition::admit_daemon_launch_under_manifest` takes with no
    /// previous receipt — a zero recorded restart spend, and none of the
    /// replacement-only policy, durable-record and threshold machinery.
    ///
    /// A generation with no recorded manifest, a receipt-less manifest, no
    /// recorded I1.12 verdict, a `Degraded`/`Quarantined` lifecycle row, or a
    /// candidate binding the manifest does not record launches nothing here. The
    /// refusal is persisted through
    /// `RedbRecoveryStore::persist_kernel_restart_reconciliation` inside that
    /// admission and returned as this file's own typed refusal, so the affected
    /// generation stays visibly degraded instead of starting.
    ///
    /// The generation and Authority Epoch are read from the ACTIVE Host-approved
    /// launch descriptor — the same descriptor the launch primitive will run
    /// from — so the manifest lookup names the identity that is actually
    /// launched.
    #[cfg(windows)]
    pub(crate) async fn launch_eliotd_for_activation_under_manifest(
        &self,
        context: &tracing::Span,
    ) -> Result<ProcessStartReceipt, KernelBuildError> {
        let launch = self
            .active_daemon_launch()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?
            .ok_or_else(|| {
                KernelBuildError::Service("eliotd launch descriptor is required".to_owned())
            })?;
        // `restarts_spent` is zero on this arm and is not an assumption: a first
        // launch has no previous generation to replace, so there is no restart to
        // spend. The recorded budget CEILING is not supplied here either — the
        // verifier reads it from the immutable manifest itself.
        let bound = match self.admit_daemon_restart_under_manifest(&launch, 0)? {
            DaemonRestartManifestAdmission::Admitted(bound) => bound,
            DaemonRestartManifestAdmission::Refused(refusal) => {
                let reason = daemon_restart_refusal_reason(&refusal);
                observe_daemon_runtime_in_context("kernel.daemon.restart_refused", reason, context);
                return Err(self
                    .daemon_failure_error(format!("eliotd activation launch refused: {reason}")));
            }
        };
        // The candidate the gate admitted and the primitive re-checks is projected from
        // the very descriptor this activation launches, which is the ACTIVE
        // Host-approved one read above. Projecting it here and again inside the
        // admission would be the same pure projection of the same value, so the
        // two sides of the comparison stay one value by construction.
        let observed = daemon_candidate_launch_binding(&launch);
        self.launch_eliotd_under_manifest(&observed, bound.as_ref(), context)
            .await
    }

    /// Performs one Kernel-owned bounded recovery of a failed daemon
    /// attempt. The old process effect must be known terminal before the
    /// active descriptor, nonce, and operation identity are replaced.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-4, #903): each failed recovery has
    /// one terminal owner. Recovery-owned failures use the recovery code;
    /// launch, readiness, and process-gateway failures propagate their
    /// already-owned terminal without emitting a second one here.
    #[cfg(windows)]
    pub async fn recover_eliotd(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
        let parent = tracing::Span::current();
        let parent = if parent.is_none() {
            super::kernel_diagnostics::operation_context(None, None, None, None)
        } else {
            parent
        };
        let mut terminal_owned = false;
        self.recover_eliotd_in_context(&parent, &mut terminal_owned)
            .await
    }

    #[cfg(windows)]
    async fn recover_eliotd_in_context(
        &self,
        parent: &tracing::Span,
        terminal_owned: &mut bool,
    ) -> Result<ProcessStartReceipt, KernelBuildError> {
        let context = parent;
        observe_daemon_runtime_in_context("kernel.daemon.recovery_requested", "attempt", context);
        let mut child_terminal_owned = false;
        match self
            .recover_eliotd_inner(context, &mut child_terminal_owned)
            .await
        {
            Ok(receipt) => {
                *terminal_owned = false;
                observe_daemon_runtime_in_context(
                    "kernel.daemon.recovery_committed",
                    "success",
                    context,
                );
                Ok(receipt)
            }
            Err(error) => {
                observe_daemon_runtime_in_context(
                    "kernel.daemon.recovery_failed",
                    "rejected",
                    context,
                );
                *terminal_owned = true;
                if !child_terminal_owned {
                    super::kernel_diagnostics::observe_terminal_error_in_context(
                        daemon_recovery_terminal_code(&error),
                        context,
                    );
                }
                Err(error)
            }
        }
    }

    /// Bounded disposition, fresh binding, and readiness rendezvous; every
    /// disposition check precedes the single relaunch. See
    /// [`KernelComposition::recover_eliotd`].
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "bounded recovery keeps disposition, fresh binding, and readiness rendezvous ordered"
    )]
    async fn recover_eliotd_inner(
        &self,
        context: &tracing::Span,
        child_terminal_owned: &mut bool,
    ) -> Result<ProcessStartReceipt, KernelBuildError> {
        let _recovery_gate = self.daemon_recovery_gate.lock().await;
        let service_state = self
            .service_state()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        if !probe_ready_state_admitted(service_state) {
            return Err(KernelBuildError::Service(
                "eliotd recovery requires an admitted Activating, Ready, or Degraded Kernel state"
                    .to_owned(),
            ));
        }
        let launch = self
            .active_daemon_launch()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?
            .ok_or_else(|| {
                KernelBuildError::Service("eliotd launch descriptor is required".to_owned())
            })?;
        let (status, previous_receipt, recovery_fenced) = {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            (
                state.status.clone(),
                state.receipt.clone(),
                state.recovery_fenced,
            )
        };
        record_daemon_recovery_operation_context(context, previous_receipt.as_ref());
        if recovery_fenced {
            return Err(KernelBuildError::Service(
                "eliotd previous process start has an unknown outcome; recovery is fenced"
                    .to_owned(),
            ));
        }
        if matches!(status, DaemonRuntimeStatus::Ready) {
            if let Some(receipt) = previous_receipt {
                if self
                    .validate_daemon_process_readiness_in_context(&launch, &receipt, context, true)
                    .await
                    .is_err()
                {
                    *child_terminal_owned = true;
                    return Err(KernelBuildError::Service(
                        "eliotd Ready receipt is no longer physically proven".to_owned(),
                    ));
                }
                return Ok(receipt);
            }
            return Err(KernelBuildError::Service(
                "eliotd Ready state has no exact process receipt".to_owned(),
            ));
        }
        if matches!(status, DaemonRuntimeStatus::Launching) && previous_receipt.is_none() {
            return Err(KernelBuildError::Service(
                "eliotd launch is still awaiting its process receipt".to_owned(),
            ));
        }
        let attempt = self.daemon_recovery_attempts.fetch_add(1, Ordering::AcqRel);
        // I14.10 / I08.12 / #1682 W4: the bounded restart budget is a DURABLE
        // operational fact of the supervised child, not process-local state.
        // `attempt` above is only the ordinal that names the replacement
        // generation; it is not a budget, and the budget is not recomputed from
        // it. The decision below is read from this owner's retained ORS
        // restart record, which is keyed to the child's stable identity
        // (`ACTIVE_DAEMON_CALLER`, the very identity an admitted restart
        // policy's `subject_id` must name) and to the admitted generation being
        // replaced, and is written through that same ORS owner before the
        // refusal is returned. A daemon restart therefore cannot hand out a
        // fresh window: the record IS the window.
        //
        // Absence stays absence. An admitted disposition means this child's
        // declared budget was never recorded as spent and that the immutable
        // manifest bound to the admitted generation admitted the replacement;
        // neither is ever widened into an unlimited budget, and an unreadable
        // or invalid record is a mechanical failure, not a permission. The
        // declared THRESHOLD is read only from an admitted policy, and a child
        // with no admitted policy has no declared budget at all, so its
        // replacement is refused as `PolicyNotAdmitted` rather than being given
        // a synthesised default.
        //
        // Issue #1884 (I1.9, AUD3, W1.5): the admitted disposition carries the
        // sealed `BoundKernelExecutionManifest` the ORS verifier issued, and that
        // is the only value the launch below may take its identity from.
        //
        // BOTH arms pass through the same gate. A first launch of the child is
        // not a restart and spends no restart budget, but it is a production
        // launch, so it is admitted under the same sealed manifest binding
        // instead of around it; only the restart-specific policy, durable-record
        // and threshold machinery is replacement-only. There is no branch left in
        // which this file reaches a process launch without a sealed binding.
        //
        // The FRESH descriptor is derived HERE, before the gate, and it is the one
        // the gate is handed. That is the whole reason for the position: the gate
        // must compare the descriptor that will ACTUALLY be launched, and the
        // launch primitive builds its `ProcessIntent` from the descriptor
        // installed in the active slot below, which is this refreshed one.
        // Admitting the PRE-refresh descriptor would compare a contour the launch
        // never runs, and because the refresh rewrites the launch nonce it made
        // every such comparison disagree by construction.
        //
        // Deriving the descriptor installs nothing: the active launch slot, the
        // front-door policy nonce, the runtime status and the previous process
        // are all still untouched at this point, and the recorded-row read, the
        // generation lifecycle read, the request build and the decision order
        // inside the gate are unchanged. A refused admission therefore leaves the
        // previous generation's descriptor, nonce and operation identity exactly
        // as they were, which is what "a withheld replacement must never destroy
        // a child it cannot replace" requires.
        let next_launch = fresh_eliotd_launch_descriptor(&launch, attempt + 1)?;
        // One projection of that refreshed descriptor, used by BOTH the gate and
        // the launch primitive's re-check. It is a pure function of the
        // descriptor, so the two call sites cannot drift apart, and it is the
        // descriptor that will be launched rather than a re-read of the active
        // slot.
        let observed_launch_binding = daemon_candidate_launch_binding(&next_launch);
        let bound_restart_manifest = match self.admit_daemon_launch_under_manifest(
            &next_launch,
            attempt,
            previous_receipt.as_ref(),
        )? {
            DaemonRestartManifestAdmission::Admitted(bound) => bound,
            DaemonRestartManifestAdmission::Refused(refusal) => {
                let reason = daemon_restart_refusal_reason(&refusal);
                observe_daemon_runtime("kernel.daemon.restart_refused", reason);
                return Err(self
                    .daemon_failure_error(format!("eliotd automatic restart refused: {reason}")));
            }
        };
        // The two refusals that no declared restart class may bypass (I14.10)
        // are decided here, on the exact reconciled evidence of the generation
        // being replaced: after its process is proven terminal and before any
        // replacement is launched. An exit the process owner could not
        // classify is not read as a normal exit and cannot buy a replacement.
        //
        // A classifiable exit is the other case: the process owner did establish
        // what happened, so the admitted restart class for this child decides
        // whether that class of exit may buy a replacement. The rule is the
        // shared `decide_automatic_restart`, read from the admission retained on
        // this composition; this module only supplies the owner lifecycle and
        // the exit/health evidence. No policy means no class, and an absent
        // declaration is refused rather than widened into an unlimited budget.
        if let Some(receipt) = previous_receipt.as_ref() {
            let closed = match self
                .close_previous_daemon_process(&launch, receipt, context, child_terminal_owned)
                .await
            {
                Ok(closed) => closed,
                Err(error) => return Err(self.daemon_failure_error(error.to_string())),
            };
            if let Some(refusal) = daemon_refuses_replacement(service_state, &closed) {
                let reason = daemon_restart_refusal_reason(&refusal);
                observe_daemon_runtime_in_context("kernel.daemon.restart_refused", reason, context);
                let reason = format!("eliotd automatic restart refused: {reason}");
                return Err(self.daemon_failure_error(reason));
            }
            // The class is read only under a policy digest still bound to the
            // admitted generation this replacement would take. That generation
            // and its fence are taken from the Host-approved launch descriptor
            // that produced the process being reconciled, which is an
            // independent record of the admitted identity: a policy admitted
            // for one generation cannot buy a replacement of another. An
            // admitted digest whose binding no longer matches is refused here,
            // not defaulted to a wider authority.
            let admitted_generation = launch.generation;
            let admitted_state_fence = eliot_contracts::StateFence::new(
                launch.authority_epoch.clone(),
                admitted_generation,
            );
            let restart_policy = self.daemon_restart_policy.as_ref();
            if let Some(refusal) = daemon_class_withholds_replacement(
                restart_policy,
                admitted_generation,
                &admitted_state_fence,
                service_state,
                &status,
                &closed,
            ) {
                let reason = daemon_restart_refusal_reason(&refusal);
                observe_daemon_runtime_in_context("kernel.daemon.restart_refused", reason, context);
                let reason = format!("eliotd automatic restart refused: {reason}");
                return Err(self.daemon_failure_error(reason));
            }
        } else if !matches!(
            status,
            DaemonRuntimeStatus::NotLaunched | DaemonRuntimeStatus::Failed(_)
        ) {
            let reason = "eliotd recovery has no exact prior process disposition".to_owned();
            return Err(self.daemon_failure_error(reason));
        }
        // The recorded-identity check happens HERE, before the active descriptor
        // and the runtime status are replaced, so a launch withheld for a contour
        // the manifest does not record never installs it. It compares the SAME
        // projected binding the gate admitted and the primitive re-checks — the
        // whole record, every field of it — and not a re-read of anything else.
        // The launch primitive applies the same rule again.
        self.require_recorded_launch_identity(
            &observed_launch_binding,
            &bound_restart_manifest,
            context,
        )?;
        {
            let mut policy = self.front_door_policy.lock().map_err(|_| {
                KernelBuildError::Service("front-door policy lock poisoned".to_owned())
            })?;
            if policy.module_generation.generation != next_launch.generation
                || !policy
                    .module_generation
                    .state_fence
                    .authority_epoch
                    .is_same_authority(&next_launch.authority_epoch)
            {
                return Err(KernelBuildError::Service(
                    "eliotd recovery descriptor has the wrong generation or authority".to_owned(),
                ));
            }
            next_launch
                .launch_nonce
                .as_str()
                .clone_into(&mut policy.launch_nonce);
        }
        *self
            .daemon_active_launch
            .lock()
            .map_err(|_| KernelBuildError::Service("daemon launch lock poisoned".to_owned()))? =
            Some(next_launch);
        {
            let mut state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            state.status = DaemonRuntimeStatus::NotLaunched;
            state.receipt = None;
            state.recovery_fenced = false;
            state.supervision = None;
            state.live_ready = None;
        }
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
        // Issue #1884 (I1.9): the single launch primitive, reached only with the
        // sealed manifest binding admitted above and with the observed binding
        // projected from the very descriptor installed in the active slot.
        let launched = match self
            .launch_eliotd_under_manifest(
                &observed_launch_binding,
                &bound_restart_manifest,
                context,
            )
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => {
                *child_terminal_owned = true;
                return Err(self.daemon_failure_error(error.to_string()));
            }
        };
        self.await_daemon_ready(&launched, self.ipc_limits().operation_timeout, context)
            .await?;
        // Issue #1839 (I16.4 restart): the recovered generation restarted
        // after its previous process closed; the launch commit itself stays
        // on `process.launch_committed`.
        let detail = format!(
            "recovered_generation={}",
            launched.accepted_generation().get()
        );
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_RESTARTED,
            Some(&launched),
            &detail,
            self.current_state_fence().as_ref(),
        ));
        Ok(launched)
    }

    #[cfg(windows)]
    pub(crate) async fn ensure_daemon_ready_for_probe_in_context(
        &self,
        parent: &tracing::Span,
        terminal_owned: &mut bool,
    ) -> Result<ProcessStartReceipt, KernelServiceError> {
        *terminal_owned = false;
        let launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        let (status, receipt) = {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelServiceError::Platform("daemon runtime lock poisoned".to_owned())
            })?;
            (state.status.clone(), state.receipt.clone())
        };
        if let Some(receipt) = receipt.as_ref() {
            if status == DaemonRuntimeStatus::Ready {
                if self
                    .validate_daemon_process_readiness_in_context(&launch, receipt, parent, false)
                    .await
                    .is_ok()
                {
                    return Ok(receipt.clone());
                }
                // A rejected proof is a subordinate phase while bounded
                // recovery may still complete this operation successfully.
            } else if status == DaemonRuntimeStatus::Running
                && self
                    .await_daemon_ready(receipt, self.ipc_limits().operation_timeout, parent)
                    .await
                    .is_ok()
            {
                if self
                    .validate_daemon_process_readiness_in_context(&launch, receipt, parent, true)
                    .await
                    .is_err()
                {
                    *terminal_owned = true;
                    return Err(KernelServiceError::ReadinessNotProven);
                }
                return Ok(receipt.clone());
            }
        }
        let mut recovery_terminal_owned = false;
        let Ok(recovered) = self
            .recover_eliotd_in_context(parent, &mut recovery_terminal_owned)
            .await
        else {
            *terminal_owned = recovery_terminal_owned;
            return Err(KernelServiceError::ReadinessNotProven);
        };
        *terminal_owned = false;
        let current_launch = self
            .active_daemon_launch()?
            .ok_or(KernelServiceError::ReadinessNotProven)?;
        if self
            .validate_daemon_process_readiness_in_context(&current_launch, &recovered, parent, true)
            .await
            .is_err()
        {
            *terminal_owned = true;
            return Err(KernelServiceError::ReadinessNotProven);
        }
        Ok(recovered)
    }

    /// Records an authenticated daemon-ready report after generation checks
    /// have been performed by the front-door dispatcher.
    ///
    /// Subordinate boundary (F-LOG-KERNEL-4, #903): the ready report is
    /// always a phase of the authenticated daemon request, so every outcome
    /// here is an info; the request dispatcher owns the single terminal for
    /// the mapped failure. Ready versus running versus liveness stay
    /// distinct: only an exact already-ready receipt is read back, never
    /// promoted from a merely running process.
    pub fn mark_daemon_ready(&self) -> Result<(), KernelServiceError> {
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?;
        #[cfg(windows)]
        if state.receipt.is_some()
            && state.status == DaemonRuntimeStatus::Ready
            && state.supervision.is_some()
        {
            drop(state);
            observe_daemon_runtime("kernel.daemon.ready_reported", "already_ready");
            return Ok(());
        }
        #[cfg(windows)]
        if state.supervision.is_none() {
            drop(state);
            observe_daemon_runtime("kernel.daemon.ready_reported", "supervision_unproven");
            return Err(KernelServiceError::ReadinessNotProven);
        }
        if state.receipt.is_none() || state.status != DaemonRuntimeStatus::Running {
            drop(state);
            observe_daemon_runtime("kernel.daemon.ready_reported", "readiness_unproven");
            return Err(KernelServiceError::ReadinessNotProven);
        }
        state.status = DaemonRuntimeStatus::Ready;
        let receipt = state.receipt.clone();
        drop(state);
        #[cfg(windows)]
        self.note_agent_bridge_peer_set_change();
        self.daemon_status_changed.notify_one();
        observe_daemon_runtime("kernel.daemon.ready_proven", "success");
        // Issue #1837: durable audit evidence for process lifecycle.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_READY_PROVEN,
            receipt.as_ref(),
            "ready",
            self.current_state_fence().as_ref(),
        ));
        Ok(())
    }

    /// Records a bounded authenticated daemon degradation.
    pub fn mark_daemon_degraded(&self, reason: String) -> Result<(), KernelServiceError> {
        {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelServiceError::Platform("daemon runtime lock poisoned".to_owned())
            })?;
            if state.receipt.is_none() {
                return Err(KernelServiceError::ReadinessNotProven);
            }
        }
        #[cfg(windows)]
        self.revoke_daemon_agent_bridge_profile()?;
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?;
        if state.receipt.is_none() {
            return Err(KernelServiceError::ReadinessNotProven);
        }
        let receipt = state.receipt.clone();
        let detail = reason.clone();
        state.status = DaemonRuntimeStatus::Degraded(reason);
        drop(state);
        self.daemon_status_changed.notify_one();
        // Issue #1837: durable audit evidence for process lifecycle.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_DEGRADED,
            receipt.as_ref(),
            &detail,
            self.current_state_fence().as_ref(),
        ));
        // Issue #1844: a degradation opens a problem; compile its brief.
        self.observe_diagnostic_problem(DiagnosticTrigger::ProblemOpenedOrUpdated);
        Ok(())
    }

    /// Records a bounded authenticated daemon fatal disposition and closes
    /// normal admission without fencing the generation. Kernel remains the
    /// sole lifecycle owner and may consume its one fresh recovery attempt.
    pub fn mark_daemon_failed(&self, reason: impl Into<String>) -> Result<(), KernelServiceError> {
        let reason = reason.into();
        self.record_daemon_failed(&reason, false)
    }

    pub(crate) fn record_daemon_failed(
        &self,
        reason: &str,
        recovery_fenced: bool,
    ) -> Result<(), KernelServiceError> {
        #[cfg(windows)]
        self.revoke_daemon_agent_bridge_profile()?;
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelServiceError::Platform("daemon runtime lock poisoned".to_owned()))?;
        let receipt = state.receipt.clone();
        state.status = DaemonRuntimeStatus::Failed(reason.to_owned());
        state.recovery_fenced |= recovery_fenced;
        #[cfg(windows)]
        {
            state.supervision = None;
            state.live_ready = None;
        }
        drop(state);
        self.daemon_status_changed.notify_one();
        let mut service = self
            .service
            .lock()
            .map_err(|_| KernelServiceError::Platform("service lock poisoned".to_owned()))?;
        if matches!(
            service.state(),
            KernelServiceState::Activating
                | KernelServiceState::Ready
                | KernelServiceState::Degraded
        ) {
            let reason_handle =
                PlatformHandle::new(format!("eliotd-failed:{}", sha256_hex(reason.as_bytes())))
                    .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
            service.apply(KernelControlCommand::Degrade(reason_handle))?;
        }
        // Issue #1837: durable audit evidence for process lifecycle.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_FAILED,
            receipt.as_ref(),
            reason,
            self.current_state_fence().as_ref(),
        ));
        // Issue #1839 (I16.4 crash): the same observed failure is a crash
        // transition, distinct from the failure disposition above.
        self.audit_observe(AuditEventDraft::process_daemon_status(
            AuditEventKind::PROCESS_CRASHED,
            receipt.as_ref(),
            reason,
            self.current_state_fence().as_ref(),
        ));
        // Issue #1844: a daemon crash compiles its brief.
        self.observe_diagnostic_problem(DiagnosticTrigger::ModuleCrashOrRestartExhaustion);
        Ok(())
    }
}

#[cfg(all(test, windows))]
mod daemon_manifest_restart_admission_tests {
    //! Issue #1884 (I1.9, AUD3, AUD5, W1.5) package-local negative proof for the
    //! manifest-bound `eliotd` launch gate's refusal vocabulary, and for WHERE that
    //! gate records a launch-identity refusal (I1.9, AUD5).
    //!
    //! The causal property is that ONE recorded ORS reconciliation cause projects
    //! into that cause's OWN bounded reason code, so a manifest defect is never
    //! reported as a spent restart budget, a spent budget is never reported as a
    //! manifest defect, a substituted launch coordinate is never reported as its
    //! neighbour, and the single fallback code is reached only by the documented
    //! effect-lease family the restart verifier cannot produce.
    //!
    //! What this module is NOT: a store-backed wiring proof. It pins the mapping
    //! table, and it pins WHERE
    //! `KernelComposition::require_recorded_launch_identity` records its refusal
    //! by reading this file's own source at compile time. The other half of
    //! `bins/AGENTS.md:86` — that no production launch reaches a process start
    //! without a sealed `BoundKernelExecutionManifest` — is carried by the
    //! signature of `KernelComposition::launch_eliotd_under_manifest` and by the
    //! fact that BOTH production launch arms enter the sealed gate before they
    //! reach it: the bounded recovery through
    //! `KernelComposition::admit_daemon_launch_under_manifest` in
    //! `recover_eliotd_inner`, and the operator activation through
    //! `KernelComposition::launch_eliotd_for_activation_under_manifest`. It is a
    //! type-level fact rather than something a table can assert.
    //!
    //! Every test here is pure and falsifiable, and they come in two shapes:
    //! assertions over the real `eliot_ors` types this crate already depends on,
    //! and source guards that read this file's own source at compile time through
    //! `THIS_FILE`. Every refusal-vocabulary assertion goes through
    //! `daemon_restart_refusal_reason`, because `DaemonRestartRefusal` derives
    //! nothing and is compared by its projected code.
    //! `DaemonRestartManifestAdmission::Admitted` is deliberately not exercised:
    //! `BoundKernelExecutionManifest` has a private field, a private
    //! `const fn verified` and no `Deserialize`, so a locally built enum would
    //! assert nothing about the real gate.
    //!
    //! For the same reason the DURABLE write of that gate cannot be exercised
    //! here, and no store is faked for it. Reaching it needs a real sealed
    //! binding, and the only ingress that mints one
    //! (`RedbRecoveryStore::persist_admitted_kernel_execution_manifest`) verifies
    //! the canonical Governor owner receipt against the admission seal field by
    //! field before it writes, so a manifest row is reachable only through the
    //! Governor accept path in `eliot-module-registry` — a crate this composition
    //! root does not depend on and must not grow an edge to from a test. The
    //! ordering claim is therefore measured against the source that decides it,
    //! which is the strongest thing this crate can falsify on its own.

    use super::*;
    use eliot_ors::KernelReconciliationKind as Cause;

    /// The reason the wildcard arm is allowed to produce.
    const FALLBACK_REASON: &str = "restart_manifest_not_admitted";

    /// Every cause the gate maps to a cause-specific reason, with the exact code
    /// that reason must be. The table is the specification, not a count: adding a
    /// cause to ORS means classifying it in `placement_of`, listing it in
    /// `EVERY_RECORDED_CAUSE` and giving it a row here, and a cause that keeps
    /// its own code can never be confused with another one that does.
    const MAPPED_CAUSES: &[(Cause, &str)] = &[
        (
            Cause::ManifestRestartBudgetExhausted,
            "restart_budget_exhausted_durably",
        ),
        (Cause::ManifestAbsent, "restart_manifest_absent"),
        (
            Cause::ManifestIdentityMismatch,
            "restart_manifest_identity_mismatch",
        ),
        (
            Cause::ManifestCandidateBindingMismatch,
            "restart_manifest_candidate_binding_mismatch",
        ),
        (Cause::ManifestIncompatible, "restart_manifest_incompatible"),
        (Cause::ManifestRevoked, "restart_manifest_revoked"),
        (Cause::ManifestReceiptless, "restart_manifest_receiptless"),
        (
            Cause::ManifestForeignEpoch,
            "restart_manifest_foreign_epoch",
        ),
        (Cause::ManifestInvalid, "restart_manifest_invalid"),
        (
            Cause::ManifestCatalogPolicyStale,
            "restart_manifest_catalog_policy_stale",
        ),
        (
            Cause::ManifestRevocationUnacknowledged,
            "restart_manifest_revocation_unacknowledged",
        ),
        (
            Cause::ManifestDeliveryGapOpen,
            "restart_manifest_delivery_gap_open",
        ),
        (
            Cause::ManifestNotEffectCapable,
            "restart_manifest_not_effect_capable",
        ),
        (
            Cause::GovernorAdmissionSealAbsent,
            "restart_governor_admission_seal_absent",
        ),
        (
            Cause::GovernorAdmissionSealWithheld,
            "restart_governor_admission_seal_withheld",
        ),
        (
            Cause::GovernorAdmissionSealMalformed,
            "restart_governor_admission_seal_malformed",
        ),
        (
            Cause::GovernorAdmissionSealIdentityMismatch,
            "restart_governor_admission_seal_identity_mismatch",
        ),
        (
            Cause::GovernorAdmissionSealRevisionMismatch,
            "restart_governor_admission_seal_revision_mismatch",
        ),
        (
            Cause::GovernorAdmissionSealStateFenceAbsent,
            "restart_governor_admission_seal_state_fence_absent",
        ),
        (
            Cause::GovernorAdmissionSealOwnerDigestMismatch,
            "restart_governor_admission_seal_owner_digest_mismatch",
        ),
        (
            Cause::ManifestRestartAuthorizationClassMismatch,
            "restart_manifest_authorization_class_mismatch",
        ),
        (
            Cause::ManifestAdmittedEffectCeilingMismatch,
            "restart_manifest_effect_ceiling_mismatch",
        ),
        (
            Cause::ManifestAdmittedAllowedScopesMismatch,
            "restart_manifest_allowed_scopes_mismatch",
        ),
        (
            Cause::ManifestDependencyOrderMismatch,
            "restart_manifest_dependency_order_mismatch",
        ),
        (
            Cause::ManifestResourceLimitsMismatch,
            "restart_manifest_resource_limits_mismatch",
        ),
        (
            Cause::ManifestReadinessContractMismatch,
            "restart_manifest_readiness_contract_mismatch",
        ),
        (
            Cause::ManifestRestartBudgetMismatch,
            "restart_manifest_restart_budget_mismatch",
        ),
        (
            Cause::ManifestResourceLimitsUnobserved,
            "restart_manifest_resource_limits_unobserved",
        ),
        (
            Cause::ManifestReadinessContractUnobserved,
            "restart_manifest_readiness_contract_unobserved",
        ),
    ];

    /// Which of the two proven tables one recorded cause belongs to.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CausePlacement {
        /// Keeps its own bounded reason code.
        OwnCode,
        /// Belongs to the effect-lease family a whole-generation launch gate
        /// cannot produce, and reaches the one fallback code.
        EffectLeaseFamily,
    }

    /// Classifies EVERY variant of the ORS reconciliation vocabulary.
    ///
    /// The `match` is exhaustive on purpose and carries NO wildcard arm, so a
    /// variant added to `eliot_ors::KernelReconciliationKind` makes this
    /// function stop compiling until it is classified. That is what makes "only
    /// the effect family falls back" a checked claim rather than an assertion:
    /// a new cause cannot reach the wildcard arm of
    /// `daemon_restart_refusal_for_manifest_cause` while this proof still
    /// passes. The completeness assertion in the test below is what then forces
    /// the classification to be mirrored as a row in the matching table.
    fn placement_of(cause: Cause) -> CausePlacement {
        match cause {
            Cause::ManifestAbsent
            | Cause::ManifestIdentityMismatch
            | Cause::ManifestCandidateBindingMismatch
            | Cause::ManifestIncompatible
            | Cause::ManifestRevoked
            | Cause::ManifestReceiptless
            | Cause::ManifestForeignEpoch
            | Cause::ManifestRestartBudgetExhausted
            | Cause::ManifestInvalid
            | Cause::ManifestCatalogPolicyStale
            | Cause::ManifestRevocationUnacknowledged
            | Cause::ManifestDeliveryGapOpen
            | Cause::ManifestNotEffectCapable
            | Cause::GovernorAdmissionSealAbsent
            | Cause::GovernorAdmissionSealWithheld
            | Cause::GovernorAdmissionSealMalformed
            | Cause::GovernorAdmissionSealIdentityMismatch
            | Cause::GovernorAdmissionSealRevisionMismatch
            | Cause::GovernorAdmissionSealStateFenceAbsent
            | Cause::GovernorAdmissionSealOwnerDigestMismatch
            | Cause::ManifestRestartAuthorizationClassMismatch
            | Cause::ManifestAdmittedEffectCeilingMismatch
            | Cause::ManifestAdmittedAllowedScopesMismatch
            | Cause::ManifestDependencyOrderMismatch
            | Cause::ManifestResourceLimitsMismatch
            | Cause::ManifestReadinessContractMismatch
            | Cause::ManifestRestartBudgetMismatch
            | Cause::ManifestResourceLimitsUnobserved
            | Cause::ManifestReadinessContractUnobserved => CausePlacement::OwnCode,
            Cause::EffectLeaseAbsent
            | Cause::EffectLeaseInvalid
            | Cause::EffectOperationIdentityMismatch
            | Cause::EffectReceiptMismatch
            | Cause::EffectScopeMismatch
            | Cause::EffectManifestMismatch
            | Cause::EffectEpochMismatch
            | Cause::EffectCatalogPolicyStale
            | Cause::EffectLeaseExpired
            | Cause::EffectLeaseRevoked
            | Cause::EffectLeaseRevocationUnacknowledged
            | Cause::EffectLeaseNotActive
            | Cause::EffectDeliveryGapOpen
            | Cause::EffectGenerationDegraded
            | Cause::EffectGenerationLifecycleUnrecorded
            | Cause::EffectLeaseIdentityAbsent
            | Cause::EffectLeaseIdentityMismatch => CausePlacement::EffectLeaseFamily,
        }
    }

    /// Every variant of `eliot_ors::KernelReconciliationKind`, enumerated as the
    /// source declares it and re-checked against `placement_of` below. The two
    /// tables above are counted against THIS list, so a variant that is
    /// classified but given no row fails the test rather than passing silently.
    const EVERY_RECORDED_CAUSE: &[Cause] = &[
        Cause::ManifestAbsent,
        Cause::ManifestIdentityMismatch,
        Cause::ManifestCandidateBindingMismatch,
        Cause::ManifestIncompatible,
        Cause::ManifestRevoked,
        Cause::ManifestReceiptless,
        Cause::ManifestForeignEpoch,
        Cause::ManifestRestartBudgetExhausted,
        Cause::ManifestInvalid,
        Cause::ManifestCatalogPolicyStale,
        Cause::ManifestRevocationUnacknowledged,
        Cause::ManifestDeliveryGapOpen,
        Cause::ManifestNotEffectCapable,
        Cause::EffectLeaseAbsent,
        Cause::EffectLeaseInvalid,
        Cause::EffectOperationIdentityMismatch,
        Cause::EffectReceiptMismatch,
        Cause::EffectScopeMismatch,
        Cause::EffectManifestMismatch,
        Cause::EffectEpochMismatch,
        Cause::EffectCatalogPolicyStale,
        Cause::EffectLeaseExpired,
        Cause::EffectLeaseRevoked,
        Cause::EffectLeaseRevocationUnacknowledged,
        Cause::EffectLeaseNotActive,
        Cause::EffectDeliveryGapOpen,
        Cause::EffectGenerationDegraded,
        Cause::EffectGenerationLifecycleUnrecorded,
        Cause::GovernorAdmissionSealAbsent,
        Cause::GovernorAdmissionSealWithheld,
        Cause::GovernorAdmissionSealMalformed,
        Cause::GovernorAdmissionSealIdentityMismatch,
        Cause::GovernorAdmissionSealRevisionMismatch,
        Cause::GovernorAdmissionSealStateFenceAbsent,
        Cause::GovernorAdmissionSealOwnerDigestMismatch,
        Cause::EffectLeaseIdentityAbsent,
        Cause::EffectLeaseIdentityMismatch,
        Cause::ManifestRestartAuthorizationClassMismatch,
        Cause::ManifestAdmittedEffectCeilingMismatch,
        Cause::ManifestAdmittedAllowedScopesMismatch,
        Cause::ManifestDependencyOrderMismatch,
        Cause::ManifestResourceLimitsMismatch,
        Cause::ManifestReadinessContractMismatch,
        Cause::ManifestRestartBudgetMismatch,
        Cause::ManifestResourceLimitsUnobserved,
        Cause::ManifestReadinessContractUnobserved,
    ];

    /// The effect-lease family, which the wildcard covers: these causes belong
    /// to the exact-effect replay verifier, which decides one leased operation
    /// and never a whole-generation launch, so a launch gate cannot produce one.
    /// The list is the whole `Effect*` part of the ORS vocabulary, so the
    /// distinctness of the explicit table below it is checkable by eye.
    const EFFECT_LEASE_FAMILY: &[Cause] = &[
        Cause::EffectLeaseAbsent,
        Cause::EffectLeaseInvalid,
        Cause::EffectOperationIdentityMismatch,
        Cause::EffectReceiptMismatch,
        Cause::EffectScopeMismatch,
        Cause::EffectManifestMismatch,
        Cause::EffectEpochMismatch,
        Cause::EffectCatalogPolicyStale,
        Cause::EffectLeaseExpired,
        Cause::EffectLeaseRevoked,
        Cause::EffectLeaseRevocationUnacknowledged,
        Cause::EffectLeaseNotActive,
        Cause::EffectDeliveryGapOpen,
        Cause::EffectGenerationDegraded,
        Cause::EffectGenerationLifecycleUnrecorded,
        Cause::EffectLeaseIdentityAbsent,
        Cause::EffectLeaseIdentityMismatch,
    ];

    /// The reason one recorded cause projects into.
    fn reason_for(cause: Cause) -> &'static str {
        daemon_restart_refusal_reason(&daemon_restart_refusal_for_manifest_cause(cause))
    }

    #[test]
    fn recorded_manifest_absence_keeps_its_own_reason_and_is_not_a_spent_budget() {
        // The pre-delivery gate reported every recorded cause as a spent budget
        // (`if recorded.is_some() { RestartBudgetExhausted }`), which made an
        // absent manifest indistinguishable from an exhausted one.
        let absent = reason_for(Cause::ManifestAbsent);
        let spent = reason_for(Cause::ManifestRestartBudgetExhausted);
        assert_eq!(absent, "restart_manifest_absent");
        assert_eq!(spent, "restart_budget_exhausted_durably");
        assert_ne!(absent, spent);
        // The converse half. Without it a whole-table inversion — every cause
        // mapped to one literal — would satisfy the assertions above.
        assert_ne!(reason_for(Cause::ManifestRestartBudgetMismatch), spent);
        assert_eq!(
            reason_for(Cause::ManifestRestartBudgetMismatch),
            "restart_manifest_restart_budget_mismatch"
        );
    }

    #[test]
    fn every_mapped_cause_keeps_its_own_reason_and_only_the_effect_family_falls_back() {
        // COMPLETENESS against the whole ORS vocabulary, measured rather than
        // claimed. `placement_of` classifies every variant the source declares,
        // and the two tables are counted against that classification, so a cause
        // classified `OwnCode` without its own row — or classified into the
        // effect family without being listed there — fails here instead of
        // quietly reaching the wildcard arm.
        let classified_own_code = EVERY_RECORDED_CAUSE
            .iter()
            .filter(|cause| placement_of(**cause) == CausePlacement::OwnCode)
            .count();
        let classified_effect_family = EVERY_RECORDED_CAUSE
            .iter()
            .filter(|cause| placement_of(**cause) == CausePlacement::EffectLeaseFamily)
            .count();
        assert_eq!(
            classified_own_code,
            MAPPED_CAUSES.len(),
            "a recorded cause classified as keeping its own reason has no row in MAPPED_CAUSES"
        );
        assert_eq!(
            classified_effect_family,
            EFFECT_LEASE_FAMILY.len(),
            "a recorded cause classified into the effect-lease family is not in EFFECT_LEASE_FAMILY"
        );
        assert_eq!(
            MAPPED_CAUSES.len() + EFFECT_LEASE_FAMILY.len(),
            EVERY_RECORDED_CAUSE.len(),
            "the two proven tables do not cover the recorded cause vocabulary"
        );
        for (cause, expected) in MAPPED_CAUSES {
            assert_eq!(
                placement_of(*cause),
                CausePlacement::OwnCode,
                "cause {cause:?} is classified out of the own-code table"
            );
            assert_eq!(
                reason_for(*cause),
                *expected,
                "cause {cause:?} lost its own reason"
            );
            assert_ne!(
                *expected, FALLBACK_REASON,
                "cause {cause:?} collapsed into the fallback code"
            );
        }
        // The wildcard is reached by the documented family and by nothing else:
        // every effect-lease cause is one bound restart cannot produce, and each
        // of them is projected as the last resort rather than as a claim this
        // file cannot make about a whole-generation launch.
        for cause in EFFECT_LEASE_FAMILY {
            assert_eq!(
                placement_of(*cause),
                CausePlacement::EffectLeaseFamily,
                "cause {cause:?} is classified out of the effect-lease family"
            );
            assert_eq!(
                reason_for(*cause),
                FALLBACK_REASON,
                "cause {cause:?} left the family"
            );
        }
        // Additional, and deliberately not sufficient on its own: mapping every
        // explicit cause to one literal and deleting another would keep a bare
        // count intact, and two causes swapping literals would pass a count too.
        // The value assertions above are what make the claim; this only says the
        // codes are pairwise distinct.
        for (index, (cause, reason)) in MAPPED_CAUSES.iter().enumerate() {
            for (other_cause, other_reason) in &MAPPED_CAUSES[index + 1..] {
                assert_ne!(
                    reason, other_reason,
                    "causes {cause:?} and {other_cause:?} share one reason code"
                );
            }
        }
    }

    /// This file's own source, resolved at compile time, so a running Kernel never
    /// locates a file to read it.
    const THIS_FILE: &str = include_str!("daemon_runtime.rs");

    /// The body of `KernelComposition::require_recorded_launch_identity`, from its
    /// own definition up to the launch primitive that follows it.
    ///
    /// Both boundaries are exact spellings, so a moved or renamed gate fails the
    /// lookup instead of silently proving an empty slice.
    fn launch_identity_gate_source() -> &'static str {
        let start = THIS_FILE
            .find("    fn require_recorded_launch_identity(")
            .expect("the launch-identity gate is defined in this file");
        let end = THIS_FILE[start..]
            .find("    #[cfg(windows)]\n    async fn launch_eliotd_under_manifest(")
            .map(|offset| start + offset)
            .expect("the launch primitive follows the launch-identity gate");
        &THIS_FILE[start..end]
    }

    /// The refusal case (issue #1884; I1.9, AUD5): a launch whose candidate
    /// digests are not the sealed binding's own recorded launch binding is
    /// refused AND is recorded durably under the ORS kind this file already maps
    /// for a launch-identity disagreement, before the error is returned.
    #[test]
    fn a_launch_identity_disagreement_is_recorded_under_its_own_kind_before_the_error_is_built() {
        // The DURABLE cause and the OBSERVABLE refusal reason are two separate
        // vocabularies, and recording the first must not change the second.
        assert_eq!(
            reason_for(Cause::ManifestCandidateBindingMismatch),
            "restart_manifest_candidate_binding_mismatch"
        );
        let gate_reason = daemon_restart_refusal_reason(&DaemonRestartRefusal::ClassWithholds(
            "restart_launch_identity_not_the_recorded_manifest",
        ));
        assert_eq!(
            gate_reason, "restart_launch_identity_not_the_recorded_manifest",
            "the gate's returned refusal reason changed"
        );
        assert_ne!(
            gate_reason,
            reason_for(Cause::ManifestCandidateBindingMismatch),
            "the returned reason must stay the gate's own code, not the ORS projection"
        );
        // The recorded kind is this file's own kind for a launch-identity
        // disagreement, and never the fallback, a spent budget, or the
        // record-identity cause it must stay distinguishable from.
        for other in [
            FALLBACK_REASON,
            reason_for(Cause::ManifestRestartBudgetExhausted),
            reason_for(Cause::ManifestIdentityMismatch),
        ] {
            assert_ne!(
                reason_for(Cause::ManifestCandidateBindingMismatch),
                other,
                "the launch-identity cause collapsed into {other}"
            );
        }

        let gate = launch_identity_gate_source();
        // The check itself still decides the refusal: it reads the sealed
        // binding's recorded launch binding and returns `Ok` only on a WHOLE
        // record equality. Which fields that equality covers — and the proof that
        // the narrowed two-scalar form is gone — is measured by
        // `the_identity_gate_compares_whole_records_and_admits_the_refreshed_descriptor`.
        assert!(
            gate.contains("let binding = bound.launch_binding();"),
            "the gate no longer reads the sealed binding's recorded launch binding"
        );
        assert!(
            gate.contains("if observed == &binding {"),
            "the gate no longer decides admission on a whole-record equality of the observed and recorded launch bindings"
        );
        // The refusal is recorded through the ONE escalation path this contour
        // already uses — the same `KernelComposition::refuse_daemon_restart_under_manifest`
        // that reaches `RedbRecoveryStore::persist_kernel_restart_reconciliation`
        // and moves the real generation lifecycle — under this file's own kind for
        // a launch-identity disagreement.
        let record = gate
            .find("self.refuse_daemon_restart_under_manifest(")
            .expect("the launch-identity refusal is not recorded durably");
        assert!(
            gate.contains("KernelReconciliationKind::ManifestCandidateBindingMismatch"),
            "the launch-identity refusal is not recorded under ManifestCandidateBindingMismatch"
        );
        // ORDER, which is the whole causal property: the comparison still decides
        // the refusal first, the durable write happens next, and only then is the
        // error built and returned. An evidence write after the return is exactly
        // the defect this closes.
        let check = gate
            .find("let binding = bound.launch_binding();")
            .expect("the recorded-digest check is gone");
        let observed = gate
            .find("observe_daemon_runtime_in_context(")
            .expect("the bounded observation is gone");
        let returned = gate
            .find("self.daemon_failure_error(")
            .expect("the gate no longer returns a typed failure");
        assert!(
            check < record && record < observed && observed < returned,
            "the launch-identity refusal must compare, then record durably, then observe, then return"
        );
        // The positive arm of the very same check, measured on the same source: a
        // contour whose candidate digests ARE the recorded ones returns before the
        // escalation call, so a launch the manifest does record publishes no
        // refusal and moves no generation lifecycle row.
        let admitted = gate
            .find("return Ok(());")
            .expect("the gate no longer admits a contour the manifest records");
        assert!(
            admitted < record,
            "a contour the manifest does record must not be recorded as a refusal"
        );
        // BOTH production call sites reach this instrumented function and nothing
        // else does, so neither arm can launch a contour the manifest does not
        // record without the escalation being published. The count is the shape
        // claim: a THIRD call site would have to be classified here.
        let call_sites = THIS_FILE
            .matches("self.require_recorded_launch_identity(")
            .count();
        assert_eq!(
            call_sites, 2,
            "the launch-identity gate has {call_sites} call sites; the bounded recovery and the operator activation arms are the two that exist"
        );
        let test_module = THIS_FILE
            .find("mod daemon_manifest_restart_admission_tests")
            .expect("this module is declared in this file");
        for (index, offset) in THIS_FILE
            .match_indices("self.require_recorded_launch_identity(")
            .map(|(offset, _matched)| offset)
            .enumerate()
        {
            assert!(
                offset < test_module,
                "launch-identity gate call site {index} is not production code"
            );
        }
    }

    /// One exact span of this file's source, from an exact opening spelling to
    /// the exact spelling that follows it.
    ///
    /// Both boundaries are exact spellings, so a moved or renamed function fails
    /// the lookup instead of silently proving an empty slice.
    fn source_between(open: &str, close: &str) -> &'static str {
        let start = THIS_FILE
            .find(open)
            .expect("the opening spelling is not in this file");
        let end = THIS_FILE[start..]
            .find(close)
            .map(|offset| start + offset)
            .expect("the closing spelling does not follow the opening one");
        &THIS_FILE[start..end]
    }

    /// This file's PRODUCTION code: every comment line removed, and everything
    /// from this test module onwards cut off.
    ///
    /// Comments are removed because the launch gate's own documentation names the
    /// refused ORS kinds and the descriptor's field names in full, and a guard
    /// that cannot tell a documented kind from a constructed one either passes
    /// vacuously or fails on its own prose. This module is cut off because a
    /// guard written inside a test must not be able to satisfy itself.
    fn production_code_without_comments() -> String {
        let test_module = THIS_FILE
            .find("mod daemon_manifest_restart_admission_tests")
            .expect("this module is declared in this file");
        let mut code = String::new();
        for line in THIS_FILE[..test_module].lines() {
            if !line.trim_start().starts_with("//") {
                code.push_str(line);
                code.push('\n');
            }
        }
        code
    }

    /// A changed Job Object limit set — including a change confined to
    /// `job_object_policy` ALONE, with every other field equal — is refused
    /// (issue #1884; I1.9, AUD3).
    ///
    /// `job_object_policy` is a policy identity token with NO OS representation:
    /// the process adapter installs the three numeric ceilings, and the token
    /// names the isolation policy in the manifest and on the launch span. It is
    /// therefore exactly the field a comparison that reaches for the ceilings
    /// alone would silently drop, so the totality of the comparison over that one
    /// field is MEASURED on the real `eliot_ors::ManifestResourceLimits` this gate
    /// hands to the decision, over the real derived equality the decision runs,
    /// rather than described.
    ///
    /// The other half is provenance, and both halves are needed: a total
    /// comparison over a value this file could reshape proves nothing, and a
    /// faithfully forwarded value compared over a dropped field proves nothing.
    /// So this also pins that the compared value IS the ACTIVE Host-approved
    /// descriptor's own `job_object_limits`, moved into the ORS request by bare
    /// field initialisation, with the recorded manifest never read on that side —
    /// the comparison keeps an independent side and cannot satisfy itself.
    #[test]
    fn a_changed_job_object_limit_including_the_policy_token_alone_is_refused() {
        let recorded = eliot_ors::ManifestResourceLimits {
            job_object_policy: "job-object-recorded-1884".to_owned(),
            max_processes: 4,
            max_working_set_bytes: 1_073_741_824,
            cpu_rate_control_percent: 50,
        };
        // A token-only substitution is a VALID limit set in its own right, so what
        // it earns is a substitution refusal and not a shape error.
        assert!(
            recorded.validate().is_ok(),
            "the recorded limit set is not a valid one"
        );
        let mut token_only = recorded.clone();
        token_only.job_object_policy = "job-object-substituted-1884".to_owned();
        assert!(
            token_only.validate().is_ok(),
            "a token-only substitution stopped being a valid limit set, so this case would now measure a shape error"
        );
        assert_ne!(
            recorded, token_only,
            "a limit set differing only in `job_object_policy` compares equal, so a substituted Job Object policy is invisible to the gate"
        );
        // Not vacuously unequal: an identical record is equal, so the assertion
        // above measured a difference and not an always-false comparison.
        assert_eq!(recorded, recorded.clone());
        // Nor is the token the ONLY discriminating field, which a comparison
        // narrowed to the token alone would break in the other direction.
        let mut processes = recorded.clone();
        processes.max_processes = 8;
        assert_ne!(
            recorded, processes,
            "a changed process-count ceiling compares equal"
        );
        let mut working_set = recorded.clone();
        working_set.max_working_set_bytes = 2_147_483_648;
        assert_ne!(
            recorded, working_set,
            "a changed working-set ceiling compares equal"
        );
        let mut cpu = recorded.clone();
        cpu.cpu_rate_control_percent = 25;
        assert_ne!(
            recorded, cpu,
            "a changed CPU rate-control ceiling compares equal"
        );

        // PROVENANCE. The other side of the comparison is the descriptor's own
        // field, and it is the very ORS record the recorded limits are.
        let observed = source_between(
            "fn daemon_candidate_observed_job_object_limits_and_readiness(",
            "#[cfg(windows)]\nfn record_daemon_recovery_operation_context(",
        );
        assert!(
            observed.contains("Option<eliot_ors::ManifestResourceLimits>"),
            "the observed limits are no longer the very ORS record the recorded limits are"
        );
        assert!(
            observed.contains("launch.job_object_limits.clone(),"),
            "the observed limits are no longer the descriptor's own `job_object_limits`"
        );
        assert!(
            !observed.contains("resource_limits()"),
            "the observed side reads the recorded limits, so the comparison lost its independent side"
        );
        // FORWARDING. Bare field initialisation, so no local step can reshape the
        // value between the descriptor and the decision.
        let verifier = source_between(
            "    fn verify_daemon_launch_under_manifest(",
            "    /// The typed refusal one refused manifest-bound decision carries.",
        );
        for coordinate in [
            "\n            candidate_resource_limits,\n",
            "\n            candidate_health_readiness_contract_ref,\n",
        ] {
            assert!(
                verifier.contains(coordinate),
                "the observed coordinate `{coordinate}` no longer reaches the ORS request unchanged"
            );
        }
        assert!(
            !verifier.contains("candidate_resource_limits:"),
            "the request's limits coordinate is now assigned instead of forwarded unchanged"
        );
        // The token is never WRITTEN in production code: a local normalization, a
        // local default or a local comparison over the token would each add one of
        // these two spellings, and any of them would make the descriptor's token
        // something other than the token the gate compared.
        let code = production_code_without_comments();
        for written in ["job_object_policy =", "job_object_policy:"] {
            assert!(
                !code.contains(written),
                "the Job Object policy token is written in production code (`{written}`), so the descriptor's token is no longer the token that is compared or applied"
            );
        }
        // The kind that answers a substituted limit set is named in this file in
        // exactly one production place, and that place is the projection of a
        // RECORDED ORS cause. So a token-only substitution has one owner for its
        // refusal, and this file never decides the comparison itself.
        assert_eq!(
            code.matches("ManifestResourceLimitsMismatch").count(),
            1,
            "the resource-limits substitution kind is named in more than one production place"
        );
        assert_eq!(
            code.matches("Cause::ManifestResourceLimitsMismatch")
                .count(),
            1,
            "the resource-limits substitution kind is constructed outside this file's recorded-cause projection"
        );
        // And it is reported as a substituted LIMIT SET, not as the substituted
        // launch identity a field with no OS representation could be mistaken for.
        assert_eq!(
            reason_for(Cause::ManifestResourceLimitsMismatch),
            "restart_manifest_resource_limits_mismatch"
        );
        assert_ne!(
            reason_for(Cause::ManifestResourceLimitsMismatch),
            reason_for(Cause::ManifestCandidateBindingMismatch),
            "a substituted Job Object limit is reported as a substituted launch identity"
        );
        // The token also reaches the launch observably, out of the sealed binding.
        let primitive = source_between(
            "    async fn launch_eliotd_under_manifest(",
            "    /// The one production launch entry for the operator-facing activation",
        );
        assert!(
            primitive
                .contains("(\"job_object_policy\", applied_limits.job_object_policy.as_str()),"),
            "the launch no longer names the applied Job Object policy token"
        );
    }

    /// An ABSENT Job Object limit set or health/readiness contract reference is
    /// the ORS decision's own recorded refusal, and this file has no second,
    /// local refusal arm for either coordinate (issue #1884; I1.9, AUD3).
    ///
    /// `eliot_ors::KernelExecutionRestartRequest` carries both coordinates as
    /// `Option` so this owner can say "I observed nothing" instead of inventing a
    /// value, and `manifest_blocking_defect` refuses the absence under
    /// `ManifestResourceLimitsUnobserved` /
    /// `ManifestReadinessContractUnobserved`. What reaches this file's own
    /// bounded code is then the kind of the decision's FIRST DURABLE
    /// reconciliation item, so the refusal reported is the decision's recorded
    /// kind rather than a shape check invented here.
    ///
    /// The claim that matters for a substitution-proof gate is the NEGATIVE one.
    /// A local arm for these two coordinates would report "this owner stated
    /// nothing" as something it is not, and would leave it unrecorded in ORS, so
    /// the affected generation would never become degraded. That is why the counts
    /// below are exact and measured over production CODE: any arm this file grew
    /// for either kind shows up as a second occurrence under its own spelling.
    #[test]
    fn an_absent_limit_or_readiness_coordinate_is_the_decisions_own_refusal_and_has_no_local_arm() {
        let observed = source_between(
            "fn daemon_candidate_observed_job_object_limits_and_readiness(",
            "#[cfg(windows)]\nfn record_daemon_recovery_operation_context(",
        );
        // Both coordinates keep a spelling for an absent observation, and both are
        // the descriptor's own fields, forwarded as stated.
        assert!(
            observed.contains("Option<eliot_ors::ManifestResourceLimits>"),
            "the observed limits no longer carry an absent observation"
        );
        assert!(
            observed.contains("Option<String>"),
            "the observed readiness reference no longer carries an absent observation"
        );
        for forwarded in [
            "launch.job_object_limits.clone(),",
            "launch.health_readiness_contract_ref.clone(),",
        ] {
            assert!(
                observed.contains(forwarded),
                "the observed side no longer forwards `{forwarded}` as stated"
            );
        }
        // No default, no substitution and no synthetic value on the observed side:
        // a stated absence must reach the decision as a stated absence.
        for shaped in ["Some(", "unwrap_or", "or_default", "unwrap_or_default"] {
            assert!(
                !observed.contains(shaped),
                "the observed coordinates are shaped by `{shaped}` instead of being forwarded as stated"
            );
        }
        let verifier = source_between(
            "    fn verify_daemon_launch_under_manifest(",
            "    /// The typed refusal one refused manifest-bound decision carries.",
        );
        for coordinate in [
            "\n            candidate_resource_limits,\n",
            "\n            candidate_health_readiness_contract_ref,\n",
        ] {
            assert!(
                verifier.contains(coordinate),
                "the observed coordinate `{coordinate}` is no longer forwarded to the decision"
            );
        }
        // ONE local refusal arm in this function, and it belongs to the dependency
        // order and restart budget, which have no unobserved case. A second arm for
        // the limits or the readiness reference would make this count wrong.
        assert_eq!(
            verifier
                .matches("DaemonRestartManifestAdmission::Refused(")
                .count(),
            2,
            "verify_daemon_launch_under_manifest no longer has exactly one local refusal arm and one decision-projected refusal"
        );
        let local = verifier
            .find("Err(refusal) => {")
            .expect("the dependency-order/restart-budget refusal arm is gone");
        let projected = verifier
            .find("Self::daemon_manifest_restart_cause(&decision)")
            .expect("the refused decision is no longer projected from the ORS decision");
        assert!(
            local < projected,
            "the decision-projected refusal now precedes the one local arm, so a local arm answers for the decision"
        );
        // The projected kind is the DECISION's own recorded kind, read from its
        // first durable reconciliation item rather than reconstructed here.
        let cause = source_between(
            "    fn daemon_manifest_restart_cause(",
            "    /// Records one manifest-bound launch refusal durably",
        );
        assert!(
            cause.contains("decision.reconciliation.first()"),
            "the refusal is no longer read from the decision's own recorded reconciliation item"
        );
        assert!(
            cause.contains("daemon_restart_refusal_for_manifest_cause(item.kind)"),
            "the refusal is no longer projected from the recorded item's own kind"
        );
        // NO second local arm anywhere in production code: each unobserved kind is
        // named in exactly one production place, and that place is the projection.
        let code = production_code_without_comments();
        for kind in [
            "ManifestResourceLimitsUnobserved",
            "ManifestReadinessContractUnobserved",
        ] {
            assert_eq!(
                code.matches(kind).count(),
                1,
                "the unobserved kind `{kind}` is named in more than one production place, so a local refusal arm for it exists"
            );
            assert_eq!(
                code.matches(&format!("Cause::{kind}")).count(),
                1,
                "the unobserved kind `{kind}` is constructed outside this file's recorded-cause projection"
            );
        }
        // "Stated nothing" stays a different refusal from "stated something else",
        // so an absent coordinate is never reported as a substitution.
        assert_eq!(
            reason_for(Cause::ManifestResourceLimitsUnobserved),
            "restart_manifest_resource_limits_unobserved"
        );
        assert_ne!(
            reason_for(Cause::ManifestResourceLimitsUnobserved),
            reason_for(Cause::ManifestResourceLimitsMismatch),
            "an unobserved limit set is reported as a substituted one"
        );
        assert_ne!(
            reason_for(Cause::ManifestReadinessContractUnobserved),
            reason_for(Cause::ManifestReadinessContractMismatch),
            "an unobserved readiness contract is reported as a substituted one"
        );
    }

    /// The launch primitive ITSELF is the gate, it runs before the process launch
    /// is reached, and the sealed binding is what it launches (issue #1884;
    /// I1.9, AUD3, W1.5).
    ///
    /// `KernelComposition::require_recorded_launch_identity` is checked twice on
    /// the bounded recovery arm and by the same rule: once in
    /// `recover_eliotd_inner` before the active descriptor and the runtime status
    /// are replaced, so a withheld contour is never installed, and once INSIDE
    /// `launch_eliotd_under_manifest` before the process authority is reached, so
    /// no future caller of that primitive can reach a process start without the
    /// check. The DURABLE recording of that refusal through
    /// `KernelComposition::refuse_daemon_restart_under_manifest`, before the
    /// error is built, is proved by
    /// `a_launch_identity_disagreement_is_recorded_under_its_own_kind_before_the_error_is_built`
    /// above; what is added here is where the second check sits.
    ///
    /// What the primitive launches is also pinned: the applied Job Object limits
    /// and the applied readiness contract are read out of the SAME sealed binding
    /// the gate admitted, and never out of a re-read of the active descriptor, so
    /// what the process adapter installs is the sealed manifest's own record
    /// whatever the active slot holds at the moment of the process start. That is
    /// why a descriptor swapped in after the comparison cannot widen this launch.
    #[test]
    fn the_launch_primitive_rechecks_the_identity_and_launches_only_the_sealed_binding() {
        let primitive = source_between(
            "    async fn launch_eliotd_under_manifest(",
            "    /// The one production launch entry for the operator-facing activation",
        );
        assert!(
            primitive.contains("bound: &eliot_ors::BoundKernelExecutionManifest,"),
            "the launch primitive no longer takes the sealed binding as an argument"
        );
        let identity = primitive
            .find("self.require_recorded_launch_identity(")
            .expect("the launch primitive no longer re-checks the recorded launch identity");
        let process = primitive
            .find("self.launch_eliotd_in_context(")
            .expect("the launch primitive no longer reaches the process launch");
        assert!(
            identity < process,
            "the recorded-identity check now runs after the process launch is reached"
        );
        for applied in [
            "let applied_limits = bound.resource_limits();",
            "let applied_readiness = bound.health_readiness_contract_ref();",
        ] {
            assert!(
                primitive.contains(applied),
                "the applied launch coordinate `{applied}` is no longer read from the sealed binding"
            );
        }
        assert!(
            !primitive.contains("active_daemon_launch"),
            "the launch primitive re-reads the active launch descriptor, so what it applies is no longer the sealed manifest's own record"
        );
        // The very same binding, not a projection of it, is what the process
        // launch receives.
        assert!(
            primitive.contains("self.launch_eliotd_in_context(context, bound).await"),
            "the process launch is no longer handed the sealed binding itself"
        );
        // And this file reaches the process launch from exactly one place, so a
        // new reach would have to enter the sealed gate too.
        let code = production_code_without_comments();
        assert_eq!(
            code.matches("launch_eliotd_in_context(").count(),
            1,
            "this file now reaches the process launch from more than one place, and a new reach is not covered by this guard"
        );
        // The other half of "inside the primitive as well as before it": the
        // bounded recovery arm checks BEFORE it installs the fresh contour and
        // before it enters the gate.
        let recovery = source_between(
            "    async fn recover_eliotd_inner(",
            "    #[cfg(windows)]\n    pub(crate) async fn ensure_daemon_ready_for_probe_in_context(",
        );
        let identity = recovery
            .find("self.require_recorded_launch_identity(")
            .expect("the bounded recovery arm no longer checks the recorded launch identity");
        let installed = recovery
            .find(".daemon_active_launch")
            .expect("the bounded recovery arm no longer installs a fresh active launch descriptor");
        let launched = recovery
            .find(".launch_eliotd_under_manifest(")
            .expect("the bounded recovery arm no longer launches through the manifest gate");
        assert!(
            identity < installed,
            "the recovery arm now installs the fresh contour before checking the recorded launch identity"
        );
        assert!(
            identity < launched,
            "the recovery arm now reaches the manifest-bound launch before checking the recorded launch identity"
        );
    }

    /// The exact argv component
    /// `EliotdLaunchDescriptor::validate` fixes at indices 4 and 5, and which
    /// `daemon_candidate_launch_binding` leaves out. Spelled once here so the
    /// fixture's canonical argv cannot drift from the production comparison
    /// without the `validate` assertions below failing.
    const NONCE_ARGUMENT_FLAG: &str = "--launch-nonce";

    /// The eight-value canonical child argv `EliotdLaunchDescriptor::validate`
    /// fixes, with the launch nonce as the supplied value.
    ///
    /// The order is the contract's own order — config descriptor, config digest,
    /// launch nonce, executable digest — and `validate()` is asserted on every
    /// fixture in the tests below, so a fixture that stopped being a contour the
    /// gate could be handed fails there instead of quietly measuring nothing.
    fn canonical_arguments(
        config_path: &str,
        config_sha256: &str,
        executable_sha256: &str,
        nonce: &PlatformHandle,
    ) -> Vec<PlatformHandle> {
        let handle = |value: &str| PlatformHandle::new(value).expect("descriptor handle");
        vec![
            handle("--config-descriptor"),
            handle(config_path),
            handle("--config-descriptor-sha256"),
            handle(config_sha256),
            handle(NONCE_ARGUMENT_FLAG),
            nonce.clone(),
            handle("--executable-sha256"),
            handle(executable_sha256),
        ]
    }

    /// One Host-approved `eliotd` descriptor over the canonical argv, with the
    /// four values the compared `start_command` is rendered from supplied by the
    /// caller and everything else held at a fixed valid value.
    ///
    /// Every case recomputes its OWN digest through the descriptor's own
    /// `with_computed_digest`, exactly as the production refresh does, so no
    /// case asserts against a stale or hand-written digest.
    fn launch_descriptor(
        executable: &str,
        config_path: &str,
        config_sha256: &str,
        executable_sha256: &str,
        nonce: &PlatformHandle,
    ) -> EliotdLaunchDescriptor {
        let handle = |value: &str| PlatformHandle::new(value).expect("descriptor handle");
        EliotdLaunchDescriptor {
            wire_id: "eliot.kernel.eliotd-launch".to_owned(),
            wire_version: EliotdLaunchDescriptor::CONTRACT_VERSION,
            executable: handle(executable),
            executable_sha256: executable_sha256.to_owned(),
            arguments: canonical_arguments(config_path, config_sha256, executable_sha256, nonce),
            working_directory: handle("C:/eliot"),
            config_descriptor: handle(config_path),
            config_descriptor_sha256: config_sha256.to_owned(),
            protected_snapshot_digest: "c".repeat(64),
            launch_nonce: nonce.clone(),
            authority_epoch: eliot_contracts::EpochId::new(
                eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("lineage"),
                std::num::NonZeroU64::new(3).expect("sequence"),
            )
            .expect("authority epoch"),
            generation: eliot_contracts::ResourceGeneration::new(7).expect("resource generation"),
            restart_policy: None,
            job_object_limits: None,
            health_readiness_contract_ref: None,
            descriptor_sha256: String::new(),
        }
        .with_computed_digest()
        .expect("descriptor digest")
    }

    /// One launch-correlation nonce in the descriptor's own `eliotd:` opaque
    /// format.
    fn launch_nonce_handle(suffix: &str) -> PlatformHandle {
        PlatformHandle::new(format!("eliotd:{suffix}")).expect("launch nonce handle")
    }

    /// The compared `start_command` is the canonical argv with ONLY the
    /// `--launch-nonce <nonce>` pair left out; everything else the descriptor
    /// states is identity and stays in it.
    ///
    /// The nonce is per attempt by construction:
    /// `fresh_eliotd_launch_descriptor`
    /// (`bins/eliot-kernel/src/runtime_identity.rs`) rewrites it from the previous
    /// descriptor digest, the previous nonce, the attempt ordinal and
    /// `unix_ms()`. Rendering it made the compared value differ from the recorded
    /// one for every restart without anything being substituted, so this measures
    /// the exclusion and, just as importantly, that the exclusion is confined to
    /// that one pair.
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the projection case keeps the excluded pair, every retained component, and the four single-field substitutions in one measured order"
    )]
    fn the_projection_excludes_the_nonce_pair_and_keeps_every_other_component() {
        let executable_sha256 = "a".repeat(64);
        let config_sha256 = "b".repeat(64);
        let executable = "C:/eliot/eliotd.exe";
        let config_path = "C:/eliot/eliotd-governor.json";
        let first_nonce = launch_nonce_handle("0123456789abcdef0123456789abcdef");
        let second_nonce = launch_nonce_handle("fedcba9876543210fedcba9876543210");
        assert_ne!(first_nonce, second_nonce);

        let baseline = launch_descriptor(
            executable,
            config_path,
            &config_sha256,
            &executable_sha256,
            &first_nonce,
        );
        // The fixture is a contour the launch gate could actually be handed:
        // `validate` is the descriptor's OWN contract, and a fixture that stops
        // satisfying it would measure nothing below.
        assert!(
            baseline.validate().is_ok(),
            "the launch-descriptor fixture is not a descriptor the gate could be handed"
        );
        assert_eq!(
            baseline.arguments[4].as_str(),
            NONCE_ARGUMENT_FLAG,
            "the fixture's canonical argv no longer carries the nonce flag where the descriptor's contract fixes it"
        );
        assert_eq!(
            baseline.arguments[5].as_str(),
            first_nonce.as_str(),
            "the fixture's canonical argv no longer carries the nonce where the descriptor's contract fixes it"
        );
        let baseline_binding = daemon_candidate_launch_binding(&baseline);

        // THE EXCLUSION. A descriptor differing ONLY in the per-attempt launch
        // nonce — and therefore only in the argv's index 5 — projects to the SAME
        // compared command, so a restart can equal the recorded command at all.
        let refreshed = launch_descriptor(
            executable,
            config_path,
            &config_sha256,
            &executable_sha256,
            &second_nonce,
        );
        assert!(
            refreshed.validate().is_ok(),
            "the refreshed launch-descriptor fixture is not a descriptor the gate could be handed"
        );
        assert_ne!(
            baseline.launch_nonce, refreshed.launch_nonce,
            "the two fixtures no longer differ in the launch nonce, so this case would measure nothing"
        );
        assert_ne!(
            baseline.arguments[5].as_str(),
            refreshed.arguments[5].as_str(),
            "the two fixtures' canonical argv no longer differ at the nonce index"
        );
        assert_ne!(
            baseline.descriptor_sha256, refreshed.descriptor_sha256,
            "the refresh does not change the descriptor digest, so it is not the same contour the contract describes"
        );
        let refreshed_binding = daemon_candidate_launch_binding(&refreshed);
        assert_eq!(
            baseline_binding.start_command, refreshed_binding.start_command,
            "a per-attempt launch nonce changed the compared start command, so every restart disagrees with the recorded command by construction"
        );
        // Both halves of the pair are out: the flag and the value behind it are
        // ONE correlation component, and rendering either alone would render half
        // of a per-attempt value.
        for (label, binding, nonce) in [
            ("baseline", &baseline_binding, &first_nonce),
            ("refreshed", &refreshed_binding, &second_nonce),
        ] {
            assert!(
                !binding.start_command.contains(NONCE_ARGUMENT_FLAG),
                "the {label} compared command still carries the launch-nonce flag"
            );
            assert!(
                !binding.start_command.contains(nonce.as_str()),
                "the {label} compared command still carries its launch nonce value"
            );
        }
        // NOTHING ELSE IS LEFT OUT. The config path, the config digest and the
        // executable digest are identity and must survive the projection, or the
        // exclusion has silently grown.
        for kept in [
            executable,
            "--config-descriptor",
            config_path,
            "--config-descriptor-sha256",
            config_sha256.as_str(),
            "--executable-sha256",
            executable_sha256.as_str(),
        ] {
            assert!(
                baseline_binding.start_command.contains(kept),
                "the compared command dropped `{kept}`, so the exclusion is wider than the launch-nonce pair"
            );
        }
        // And the exclusion is confined to the command text: the three digest
        // coordinates of the binding are untouched by a nonce refresh.
        assert_eq!(
            baseline_binding.artifact_sha256, refreshed_binding.artifact_sha256,
            "a per-attempt launch nonce changed the observed artifact digest"
        );
        assert_eq!(
            baseline_binding.config_sha256, refreshed_binding.config_sha256,
            "a per-attempt launch nonce changed the observed config digest"
        );
        assert_eq!(
            baseline_binding.protocol_sha256, refreshed_binding.protocol_sha256,
            "a per-attempt launch nonce changed the observed protocol digest"
        );

        // EVERY OTHER COMPONENT STILL REFUSES. Each of these four descriptors is
        // valid in its own right and differs from the baseline in exactly one
        // identity component, so each projects to a DIFFERENT compared command:
        // excluding the nonce pair must not have relaxed anything else into
        // equality.
        for (component, changed) in [
            (
                "the executable",
                launch_descriptor(
                    "C:/eliot/other/eliotd.exe",
                    config_path,
                    &config_sha256,
                    &executable_sha256,
                    &first_nonce,
                ),
            ),
            (
                "the config path",
                launch_descriptor(
                    executable,
                    "C:/eliot/other-governor.json",
                    &config_sha256,
                    &executable_sha256,
                    &first_nonce,
                ),
            ),
            (
                "the config digest",
                launch_descriptor(
                    executable,
                    config_path,
                    &"d".repeat(64),
                    &executable_sha256,
                    &first_nonce,
                ),
            ),
            (
                "the executable digest",
                launch_descriptor(
                    executable,
                    config_path,
                    &config_sha256,
                    &"e".repeat(64),
                    &first_nonce,
                ),
            ),
        ] {
            assert!(
                changed.validate().is_ok(),
                "the `{component}` substitution is not a descriptor the gate could be handed"
            );
            assert_ne!(
                baseline_binding.start_command,
                daemon_candidate_launch_binding(&changed).start_command,
                "a descriptor differing in {component} projects to the same compared command, so that substitution is invisible to the gate"
            );
        }
    }

    /// A `KernelLaunchBinding` that differs in ANY ONE of its four fields is
    /// unequal to the recorded one, and an identical clone is equal — so the
    /// primitive's whole-record comparison is a real comparison over the whole
    /// record and not an always-false one.
    ///
    /// This is the value the gate now compares, so it is measured on the real
    /// `eliot_ors` record rather than on a local proxy.
    #[test]
    fn a_whole_record_substitution_in_any_one_field_is_refused() {
        let recorded = eliot_ors::KernelLaunchBinding {
            artifact_sha256: "a".repeat(64),
            config_sha256: "b".repeat(64),
            protocol_sha256: "c".repeat(64),
            start_command: "C:/eliot/eliotd.exe --config-descriptor C:/eliot/eliotd-governor.json"
                .to_owned(),
        };
        assert!(
            recorded.validate().is_ok(),
            "the recorded launch binding is not a valid one, so the cases below would measure a shape error"
        );
        // Not vacuously unequal: an identical record is equal, so every `assert_ne!`
        // below measured a DIFFERENCE and not an always-false comparison.
        assert_eq!(
            recorded,
            recorded.clone(),
            "an identical launch binding compares unequal, so the gate would refuse every launch"
        );
        for (field, substituted) in [
            (
                "artifact_sha256",
                eliot_ors::KernelLaunchBinding {
                    artifact_sha256: "d".repeat(64),
                    ..recorded.clone()
                },
            ),
            (
                "config_sha256",
                eliot_ors::KernelLaunchBinding {
                    config_sha256: "d".repeat(64),
                    ..recorded.clone()
                },
            ),
            (
                "protocol_sha256",
                eliot_ors::KernelLaunchBinding {
                    protocol_sha256: "d".repeat(64),
                    ..recorded.clone()
                },
            ),
            (
                "start_command",
                eliot_ors::KernelLaunchBinding {
                    start_command: "C:/eliot/eliotd.exe --config-descriptor C:/eliot/other.json"
                        .to_owned(),
                    ..recorded.clone()
                },
            ),
        ] {
            assert!(
                substituted.validate().is_ok(),
                "the `{field}` substitution is not a valid launch binding, so this case would measure a shape error"
            );
            assert_ne!(
                recorded, substituted,
                "a launch binding differing only in `{field}` compares equal, so the identity gate is narrowed to a field set that does not cover it"
            );
        }
        // The two fields a per-attempt refresh does NOT touch are not the whole
        // record, which is why comparing only them let a substituted `start_command`
        // and a substituted `protocol_sha256` through.
        let narrowed = eliot_ors::KernelLaunchBinding {
            artifact_sha256: "d".repeat(64),
            config_sha256: "d".repeat(64),
            ..recorded.clone()
        };
        assert_ne!(
            recorded, narrowed,
            "a binding differing only in the two previously compared digests compares equal"
        );
    }

    /// The identity gate compares the WHOLE projected binding rather than two
    /// named digest scalars, and the recovery contour hands its gate the
    /// REFRESHED descriptor rather than the one it is about to replace.
    ///
    /// Both halves are source guards, because `BoundKernelExecutionManifest` is
    /// sealed — one private field, a private `const fn verified` and no
    /// `Deserialize` — so a test in this crate cannot construct one and cannot
    /// reach the gate with a real pair of values. The structural half is measured
    /// on the real `KernelLaunchBinding` in
    /// `a_whole_record_substitution_in_any_one_field_is_refused`.
    #[test]
    fn the_identity_gate_compares_whole_records_and_admits_the_refreshed_descriptor() {
        let gate = launch_identity_gate_source();
        for signature in [
            "observed: &eliot_ors::KernelLaunchBinding,",
            "bound: &eliot_ors::BoundKernelExecutionManifest,",
            "context: &tracing::Span,",
        ] {
            assert!(
                gate.contains(signature),
                "the identity gate's parameter list no longer declares `{signature}`, so it does not receive the observed binding"
            );
        }
        assert!(
            gate.contains("if observed == &binding {"),
            "the identity gate no longer decides admission on a whole-record equality"
        );
        // The narrowed form is GONE, measured over production CODE with the
        // comments stripped, so this file's own documentation about the old form
        // cannot satisfy it and a guard written inside a test cannot satisfy
        // itself.
        let code = production_code_without_comments();
        for narrowed in ["candidate_artifact_sha256", "candidate_config_sha256"] {
            assert!(
                !code.contains(narrowed),
                "production code still names `{narrowed}`, so the identity gate still compares named digest scalars rather than the whole projected binding"
            );
        }
        // And it compares no field of the sealed record BY NAME either, which is
        // what a whole-record equality looks like and what a narrowing would undo.
        for field in [
            "binding.artifact_sha256",
            "binding.config_sha256",
            "binding.protocol_sha256",
            "binding.start_command",
        ] {
            assert!(
                !gate.contains(field),
                "the identity gate still reaches into `{field}`, so the comparison is narrowed to named fields"
            );
        }

        // THE RECOVERY CONTOUR. The refresh must precede the admission, and the
        // admission must be handed the refreshed descriptor, or the gate compares
        // a contour the launch never runs.
        let recovery = source_between(
            "    async fn recover_eliotd_inner(",
            "    #[cfg(windows)]\n    pub(crate) async fn ensure_daemon_ready_for_probe_in_context(",
        );
        let refresh = recovery
            .find("fresh_eliotd_launch_descriptor(")
            .expect("the bounded recovery arm no longer refreshes the launch descriptor");
        let observed = recovery
            .find("let observed_launch_binding = daemon_candidate_launch_binding(&next_launch);")
            .expect("the bounded recovery arm no longer projects the candidate binding");
        let admitted = recovery
            .find("self.admit_daemon_launch_under_manifest(")
            .expect("the bounded recovery arm no longer admits its launch under the manifest");
        assert!(
            refresh < observed,
            "the bounded recovery arm now projects the candidate before the descriptor is refreshed"
        );
        assert!(
            observed < admitted,
            "the bounded recovery arm now admits the PRE-refresh descriptor, so the gate compares a contour the launch never runs"
        );
        assert!(
            recovery.contains("&next_launch,\n            attempt,"),
            "the bounded recovery arm no longer admits the refreshed descriptor it will install"
        );
        // The SAME projected value reaches the gate and the launch primitive, and
        // it reaches both by reference: one projection, two comparisons, no
        // second observation that could disagree with the first.
        let identity = recovery
            .find("self.require_recorded_launch_identity(")
            .expect("the bounded recovery arm no longer checks the recorded launch identity");
        let launched = recovery
            .find(".launch_eliotd_under_manifest(")
            .expect("the bounded recovery arm no longer launches through the manifest gate");
        assert!(
            identity < launched,
            "the bounded recovery arm now reaches the manifest-bound launch before checking the recorded launch identity"
        );
        assert_eq!(
            recovery.matches("&observed_launch_binding,").count(),
            2,
            "the projected binding does not reach both the identity gate and the launch primitive unchanged"
        );
        // And the activation arm projects from the ACTIVE descriptor it launches.
        let activation = source_between(
            "    pub(crate) async fn launch_eliotd_for_activation_under_manifest(",
            "    /// Performs one Kernel-owned bounded recovery of a failed daemon",
        );
        assert!(
            activation.contains("let observed = daemon_candidate_launch_binding(&launch);"),
            "the operator activation arm no longer projects the candidate binding from the descriptor it launches"
        );
        assert!(
            activation
                .contains("self.launch_eliotd_under_manifest(&observed, bound.as_ref(), context)"),
            "the operator activation arm no longer hands the projected binding and the sealed binding to the launch primitive as two distinct values"
        );
    }
}

/// Issue #903 (F-LOG-KERNEL-4) daemon-lifecycle observation proof: case 6 (an
/// activation request is not an owner observation), case 19 (liveness is not
/// semantic readiness), case 18 (the armed daemon states stay distinct, two of
/// them sharing one outcome literal) and case 22 (an exact replay is a readback,
/// not a duplicate transition success).
///
/// WHY THIS IS ITS OWN `#[cfg(test)]` MODULE rather than four more tests inside
/// `daemon_manifest_restart_admission_tests`: that module is
/// `#[cfg(all(test, windows))]` (issue #1884), so a test living in it is not
/// merely DEFERRED on another target — it does not exist there, and nothing
/// about its header says so. Here the whole block is `#[cfg(test)]` on every
/// target, and each test that needs a `#[cfg(windows)]` ITEM is gated on that
/// item individually. The per-test matrix, stated rather than implied:
///
/// * `an_alive_daemon_without_a_receipt_and_a_running_status_never_reaches_readiness`
///   (case 19) — EVERY target. It reaches no platform-gated production item:
///   `mark_daemon_ready` (:2184) and the readiness predicate (:507) carry no
///   platform attribute, and the rest is source text. The three verdicts it
///   asserts are all decided by the one guard at :2204 on every target, because
///   the two arms above it (:2190-2192 and :2198-2203) are `#[cfg(windows)]` and
///   are not reached by any arm here. The bound supervision contour it records is
///   a `#[cfg(windows)]` field (`daemon_supervision.rs:458-459`), so its three
///   writes are routed through one `#[cfg]`-gated fixture item and the arms
///   differ only in the receipt and status slots off Windows.
/// * `an_activation_request_is_not_an_owner_readiness_observation` (case 6) —
///   `#[cfg(windows)]`. Its captured owner-leg refusal is the
///   `supervision_unproven` verdict (:2198-2203), which exists only where the
///   supervision slot exists.
/// * `the_daemon_lifecycle_states_stay_distinct_and_liveness_is_never_promoted`
///   (case 18) — `#[cfg(windows)]`. It drives `await_daemon_ready` (attribute at
///   :531, definition at :532), which is compiled on no other target.
/// * `an_exact_replay_returns_the_recorded_outcome_without_a_second_transition`
///   (case 22) — `#[cfg(windows)]`. What it measures IS that readback arm: the
///   three owner slots at :2190-2192 do not exist off Windows, the supervision
///   slot it restores does not exist off Windows, and its exactness tail reads
///   the receipt comparison at `daemon_runtime.rs:557` inside the same `#[cfg(windows)]` wait. Off
///   Windows `mark_daemon_ready` has no readback arm, so there is nothing there
///   for this test to be honest about.
///
/// Every premise below is read back through the SAME `self.daemon_runtime`
/// mutex production writes through (daemon_supervision.rs:454-479), holding the
/// real `DaemonRuntimeStatus` and the real `ProcessStartReceipt`, and every
/// observed record is the bytes the real `KernelComposition` emitted through
/// the #895 facade's own `tracing` seam. Apart from the three comparisons that
/// announce themselves, where they are used, as NON-VACUITY CONTROLS on a
/// comparison that IS falsifiable (the two distinct fixture receipts in case 22,
/// the two distinct enum values in case 19, and the pairwise distinctness of the
/// five read-back statuses in case 18, which only makes the word "collapsed"
/// meaningful there), no premise compares two objects this test built on its
/// own, so a production change reddens it.
///
/// The two load-bearing distinctions are: an activation REQUEST is not an owner
/// OBSERVATION, and LIVENESS is not READINESS.
///
/// Doc anchors, CONDENSED from the read fragments in
/// `.eliot/docs-read-bundle-903.md` — the fragments' own line breaks are
/// reflowed to fit a comment, their `→` glyphs are reproduced as they are
/// spelled, and `...` marks fragment lines a quote skips:
/// * I14.20: "Process liveness/readiness and capability-generation state
///   remain separate."
/// * I14.20 service process (the `Service process` transition block, ONE SOURCE
///   LINE PER QUOTED SPAN so that no punctuation is invented between transitions):
///   "STOPPED → STARTING", "STARTING → RECOVERING | READY", ... "READY | DEGRADED → QUIESCING → STOPPED".
/// * I1.5: "The activation is not reported fully healthy merely because Host
///   and Kernel are alive."
/// * I1.5: "An installed agent shim, hook, plugin or MCP bridge is a
///   demand-start trigger only; it stores no semantic state or authority."
/// * I14.21: "Human/Doctor chooses evidence-backed reconciliation; no blind
///   duplicate effect."
/// * I1.8: "Kernel rechecks only properties it owns and binds the
///   activation/staging receipt to the same `admission_decision_digest`."
///
/// What this proof is NOT, and says so rather than faking: the card DEFERs live
/// `#[cfg(windows)]` kernel-owner and daemon-launch EXECUTION, so no test here
/// launches a process, mints a store row or drives a real Host. The diagnostic
/// semantics are proved through the recorded owner slots and the emitted
/// records, which is what a synthetic owner evidence claim means here. Case 18
/// is NOT PROVEN as the card words it — one rendezvous deciding five lifecycle
/// states including a draining and a stopped daemon — and this block says which
/// part of it is measured and which part is not, rather than pretending to the
/// difference.
#[cfg(test)]
mod daemon_lifecycle_observation_tests {
    #![allow(
        clippy::expect_used,
        clippy::unwrap_used,
        reason = "the only sites these two lints reach in this module are source_between's two exact-spelling boundary lookups, where a failed lookup means a pinned production spelling is gone and this proof's premise is void rather than a production fault reported to an operator; every other fixture path spells its failure as assert!, a let-else panic, or unwrap_or_else(|_| panic!) carrying its own message, so unwrap_used covers no call site here at all"
    )]

    use super::*;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex, MutexGuard};

    use super::super::{DaemonRuntimeState, KernelConfig};

    // The bound supervision contour is a `#[cfg(windows)]` OWNER SLOT
    // (`daemon_supervision.rs:458-459`) and the crate root re-exports its type
    // only under `#[cfg(windows)]` (lib.rs:371-373), so every fixture import
    // that exists only to build that contour is gated with it. Case 19 is the
    // one cross-platform test and it records the contour through one
    // `#[cfg]`-gated fixture item, asserting the same three verdicts without it
    // elsewhere.
    #[cfg(windows)]
    use super::super::DaemonSupervisionContour;
    #[cfg(windows)]
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    #[cfg(windows)]
    use eliot_kernel_service::KernelActivationReceipt;
    #[cfg(windows)]
    use eliot_runtime_contracts::{
        RegisteredActivityWakePolicy, SupervisionGenerationBinding, SupervisionJournalEpoch,
        SupervisionLeaseIncarnationBinding, SupervisionObservationScope,
    };

    /// This file's own source, resolved at compile time, so a running Kernel
    /// never locates a file to read it. Read by the source pins in cases 6 and
    /// 19; identical in shape to the reader in
    /// `daemon_manifest_restart_admission_tests`, duplicated per module rather
    /// than shared, because that module's readers are `#[cfg(windows)]`.
    const THIS_FILE: &str = include_str!("daemon_runtime.rs");

    /// One exact span of this file's source, from an exact opening spelling to
    /// the exact spelling that follows it.
    ///
    /// Both boundaries are exact spellings, so a moved or renamed decision fails
    /// the lookup instead of silently proving an empty slice. A source pin
    /// written inside this module cannot satisfy itself from a test module's
    /// own prose the way a whole-file scan can, because the boundaries are
    /// production signatures.
    fn source_between(open: &str, close: &str) -> &'static str {
        let start = THIS_FILE
            .find(open)
            .expect("the opening spelling is not in this file");
        let end = THIS_FILE[start..]
            .find(close)
            .map(|offset| start + offset)
            .expect("the closing spelling does not follow the opening one");
        &THIS_FILE[start..end]
    }

    /// Bounded root guard for one fixture composition. Returned FIRST by
    /// `daemon_case_kernel`, so the composition (which holds the fixture's open
    /// ORS file) drops before the guard removes the work root.
    struct DaemonCaseRoot(PathBuf);

    impl DaemonCaseRoot {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for DaemonCaseRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn daemon_case_root(tag: &str) -> DaemonCaseRoot {
        let root = std::env::temp_dir().join(format!(
            "eliot-903-daemon-case-{tag}-{pid}-{now}",
            pid = std::process::id(),
            now = super::super::unix_ms()
        ));
        assert!(
            std::fs::create_dir_all(&root).is_ok(),
            "the fixture work root is creatable"
        );
        DaemonCaseRoot(root)
    }

    /// One real `KernelComposition` over a real (empty) work root, so every
    /// daemon observation below is emitted by the production owner and not by a
    /// stand-in.
    fn daemon_case_kernel(tag: &str) -> (DaemonCaseRoot, KernelComposition) {
        let root = daemon_case_root(tag);
        let Ok(kernel) = KernelComposition::new(KernelConfig::new(root.path())) else {
            panic!("the fixture work root does not assemble a kernel composition")
        };
        (root, kernel)
    }

    /// The owner's own daemon-state guard, so every premise reads the record
    /// production writes through the same lock.
    fn daemon_case_state(kernel: &KernelComposition) -> MutexGuard<'_, DaemonRuntimeState> {
        kernel
            .daemon_runtime
            .lock()
            .unwrap_or_else(|_| panic!("the daemon runtime lock is poisoned"))
    }

    /// A platform handle for the contour fixture. `#[cfg(windows)]` with the
    /// contour slot it only feeds.
    #[cfg(windows)]
    fn daemon_case_handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value)
            .unwrap_or_else(|_| panic!("the fixture value is not an accepted platform handle"))
    }

    #[cfg(windows)]
    fn daemon_case_generation(generation: u64) -> ResourceGeneration {
        ResourceGeneration::new(generation)
            .unwrap_or_else(|_| panic!("the fixture generation is not a resource generation"))
    }

    #[cfg(windows)]
    fn daemon_case_epoch() -> EpochId {
        let Ok(lineage) = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000") else {
            panic!("the fixture epoch lineage is accepted")
        };
        let Some(sequence) = std::num::NonZeroU64::new(1) else {
            panic!("one is a non-zero sequence")
        };
        EpochId::new(lineage, sequence).unwrap_or_else(|_| panic!("the fixture epoch is an epoch"))
    }

    /// One real `ProcessStartReceipt` for the given admitted generation, decoded
    /// through the contract's own `Deserialize` and then accepted by its own
    /// `validate`, so the fixture is a receipt production could hold rather than
    /// a value this test decided was one. Nothing here decides liveness: the
    /// receipt is the executor's record, and the whole point of case 19 is that
    /// holding it is not readiness.
    fn daemon_case_receipt(generation: u64) -> ProcessStartReceipt {
        // The wire shape is built first so the decoded type is named at the
        // ONE call site that decodes it: `from_value` is generic, so a bare call
        // inside this `match` leaves `T` unconstrained (E0282) and the arms
        // mismatch (E0308) even though the annotation is right there.
        let wire = serde_json::json!({
            "binding": {
                "operation_id": "eliotd-903-receipt-operation",
                "process_tree_id": "eliotd-903-receipt-tree",
                "job_id": "eliotd-903-receipt-job",
                "image_id": "eliotd-903-receipt-image",
                "session_id": "eliotd-903-receipt-session",
                "generation": generation,
                "action_lease_ref": "eliotd-903-receipt-lease",
                "authority_id": "eliotd",
                "authority_epoch": {
                    "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                    "sequence": 1
                },
                "state_fence": {
                    "authority_epoch": {
                        "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
                        "sequence": 1
                    },
                    "generation": generation,
                    "nonce": "eliotd-903-receipt-fence"
                },
                "request_digest": "a".repeat(64),
                "permit_digest": "b".repeat(64),
                "effect_digest": "c".repeat(64),
                "validation_revision": 1
            },
            "identity": {
                "suspended": {
                    "process_id": "eliotd-903-receipt-process",
                    "process_tree_id": "eliotd-903-receipt-tree",
                    "job_id": "eliotd-903-receipt-job",
                    "image_id": "eliotd-903-receipt-image",
                    "session_id": "eliotd-903-receipt-session",
                    "generation": generation,
                    "physical": {
                        "process_id": 4501,
                        "start_time_100ns": 1,
                        "image_path": r"C:\ProgramData\Eliot\bin\eliotd.exe",
                        "executor_job_name": r"Local\Eliot-P04-903"
                    },
                    "created_suspended_at_unix_ms": 1,
                    "executable_sha256": "a".repeat(64)
                },
                "resumed_at_unix_ms": 2
            },
            "lifecycle": "running"
        });
        match serde_json::from_value::<ProcessStartReceipt>(wire) {
            Ok(receipt) => {
                assert!(
                    receipt.validate().is_ok(),
                    "the fixture receipt satisfies the contract validator"
                );
                receipt
            }
            Err(error) => panic!("the fixture process start receipt decodes: {error}"),
        }
    }

    #[cfg(windows)]
    fn daemon_case_incarnation() -> SupervisionLeaseIncarnationBinding {
        let epoch = SupervisionJournalEpoch {
            lineage_id: "host-lineage-903".to_owned(),
            sequence: 1,
        };
        (SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-supervision-scope:v1:903".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: "installation-903".to_owned(),
            host_epoch: epoch.clone(),
            activation_id: "activation-903".to_owned(),
            activation_generation: epoch.clone(),
            kernel_generation: epoch.clone(),
            watchdog_epoch: epoch,
            observation_scope: SupervisionObservationScope {
                targets: vec!["eliot-kernel".to_owned()],
                sensor_profile: "eliot-runtime-live-v3".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live-v3".to_owned(),
            },
            wake_policy: RegisteredActivityWakePolicy::Disabled,
            predecessor: None,
        })
        .with_derived_ids()
        .unwrap_or_else(|_| panic!("the fixture supervision incarnation is not a sealed one"))
    }

    /// One real bound supervision contour: the third slot the owner's readiness
    /// verdict reads (`daemon_runtime.rs:2192`). Case 22 proves that removing it
    /// changes that verdict, so it is fixture data and not decoration.
    ///
    /// `#[cfg(windows)]` with that slot: the field it fills does not exist on
    /// another target (`daemon_supervision.rs:458-459`), so a fixture for it
    /// would not compile there and case 19 records it under the same gate.
    #[cfg(windows)]
    fn daemon_case_contour(generation: u64) -> DaemonSupervisionContour {
        DaemonSupervisionContour {
            candidate_digest: "a".repeat(64),
            incarnation: daemon_case_incarnation(),
            activation: KernelActivationReceipt {
                operation_id: daemon_case_handle("eliot-903-activation-operation"),
                candidate_binding_digest: "a".repeat(64),
                prior_kernel_disposition_digest: "b".repeat(64),
                journal_transaction_id: daemon_case_handle("eliot-903-journal-transaction"),
                journal_sequence: 1,
                generation: daemon_case_generation(generation),
                authority_epoch: daemon_case_epoch(),
                activation_nonce_digest: "c".repeat(64),
            },
            generation_binding: SupervisionGenerationBinding {
                target_id: "eliot-903-artifact".to_owned(),
                target_generation: daemon_case_generation(generation),
                module_id: "eliotd".to_owned(),
                module_generation: daemon_case_generation(generation),
                process_id: "pid:4501:start:1".to_owned(),
                process_generation: daemon_case_generation(generation),
            },
            state_fence: StateFence::new(daemon_case_epoch(), daemon_case_generation(generation)),
        }
    }

    /// The bound supervision write, as ONE fixture ITEM rather than three
    /// per-statement attributes: attributes on expressions are still unstable
    /// (rust-lang/rust#15701), so a `#[cfg]` sitting on
    /// `state.supervision = Some(...)` is rejected in that position and the
    /// gate has to be a declaration instead.
    ///
    /// On Windows this writes the same contour the arms wrote before into the
    /// third slot production's own guard reads (`daemon_runtime.rs:2192`).
    /// Off Windows the field does not exist at all
    /// (`daemon_supervision.rs:458-459`), so the non-Windows twin below
    /// performs no write and names no supervision type in its signature — that
    /// is what lets the shared call site be written once and stay legal on
    /// both targets, leaving each arm differing only in its receipt and status
    /// slots exactly as before.
    #[cfg(windows)]
    fn daemon_case_bind_supervision(state: &mut MutexGuard<'_, DaemonRuntimeState>) {
        state.supervision = Some(daemon_case_contour(1));
    }

    /// The same call where the slot does not exist. An empty body with no
    /// supervision type in its signature is deliberate: naming one would not
    /// compile off Windows.
    #[cfg(not(windows))]
    fn daemon_case_bind_supervision(_state: &mut MutexGuard<'_, DaemonRuntimeState>) {}

    // Capture seam. Per-file duplication of the #895 `tracing` sink, which is
    // the house pattern for a crate-internal proof file.
    #[derive(Clone, Default)]
    struct DaemonCaseSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for DaemonCaseSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            match self.bytes.lock() {
                Ok(mut bytes) => bytes.extend_from_slice(buf),
                Err(_) => return Err(std::io::Error::other("the capture lock is poisoned")),
            }
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Runs `run` with the real facade subscriber installed over an in-memory
    /// sink and returns the bytes production actually emitted. The subscriber is
    /// the #895 writer shape, so what is captured is the record a reader of the
    /// installed stderr sink would see.
    fn daemon_case_capture_with<F, R>(run: F) -> (String, R)
    where
        F: FnOnce() -> R,
    {
        let sink = DaemonCaseSink::default();
        let writer_sink = sink.clone();
        let result = {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run)
        };
        let bytes = sink
            .bytes
            .lock()
            .unwrap_or_else(|_| panic!("the capture lock is poisoned"))
            .clone();
        (String::from_utf8_lossy(&bytes).into_owned(), result)
    }

    /// EVERY `event="` value on the WHOLE captured surface, in emission order.
    ///
    /// Absence claims in this block read this whole list (and the raw bytes),
    /// never a hand-listed set of names, so an event added under a spelling this
    /// test never anticipated still appears in the comparison.
    fn daemon_case_events(logs: &str) -> Vec<String> {
        let needle = "event=\"";
        logs.match_indices(needle)
            .map(|(at, _matched)| &logs[at + needle.len()..])
            .filter_map(|rest| rest.find('"').map(|end| rest[..end].to_owned()))
            .collect()
    }

    /// The `kernel.daemon.*` records on the captured surface, in emission order.
    ///
    /// The daemon observation namespace is this issue's whole claim in this
    /// block, and it is read as a NAMESPACE rather than as a hand-listed set of
    /// names: a record added under a spelling no assertion here anticipates
    /// still appears in the comparison and breaks it. Records another subsystem
    /// emits on the same contour — the audit cascade's own terminal, for one —
    /// are deliberately outside it, because they are not this file's
    /// observation and pinning them here would measure another owner's
    /// behaviour. The absence claims read the WHOLE raw surface, not this list.
    fn daemon_case_daemon_events(logs: &str) -> Vec<String> {
        daemon_case_events(logs)
            .into_iter()
            .filter(|event| event.starts_with("kernel.daemon."))
            .collect()
    }

    /// The `outcome` value production emitted for one event, read back out of
    /// the captured line.
    fn daemon_case_outcome(logs: &str, event: &str) -> String {
        let needle = format!("event=\"{event}\"");
        let Some(line) = logs.lines().find(|line| line.contains(&needle)) else {
            panic!("no captured line carries {needle}: {logs}");
        };
        let key = "outcome=\"";
        let Some(at) = line.rfind(key) else {
            panic!("the captured line for {event} carries no outcome: {line}");
        };
        let at = at + key.len();
        let Some(end) = line[at..].find('"') else {
            panic!("the captured outcome for {event} is unterminated: {line}");
        };
        line[at..at + end].to_owned()
    }

    /// Drives the REAL `KernelComposition::await_daemon_ready` over the recorded
    /// owner slots, with `awaited` as the receipt the caller claims to be
    /// waiting on and `recorded` as the receipt the owner actually holds.
    ///
    /// Splitting the two is the whole of the exactness claim: the production
    /// comparison at `daemon_runtime.rs:557` is
    /// `state.receipt.as_ref() == Some(launched)`, so a different recorded
    /// receipt must refuse rather than satisfy. Nothing here waits on a real
    /// process; the timeout arm is a real timed wait that expires because no
    /// owner observation arrives, which is exactly the unanswered request.
    ///
    /// `#[cfg(windows)]` with `await_daemon_ready` itself (attribute at :531),
    /// which is the only production item this helper reaches; the tests that
    /// need it (cases 18 and 22) carry the same gate individually.
    #[cfg(windows)]
    fn daemon_case_await(
        kernel: &KernelComposition,
        recorded: DaemonRuntimeStatus,
        held: &ProcessStartReceipt,
        awaited: &ProcessStartReceipt,
        timeout: Duration,
    ) -> (String, Result<(), KernelBuildError>) {
        {
            let mut state = daemon_case_state(kernel);
            state.status = recorded;
            state.receipt = Some(held.clone());
            state.supervision = Some(daemon_case_contour(1));
        }
        daemon_case_capture_with(|| {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                panic!("a current-thread runtime is available for the rendezvous")
            };
            runtime.block_on(kernel.await_daemon_ready(awaited, timeout, &tracing::Span::none()))
        })
    }

    /// The daemon lifecycle's own discriminating label.
    ///
    /// The `match` is exhaustive on purpose and carries NO wildcard arm, so a
    /// variant added to `DaemonRuntimeStatus` (`daemon_supervision.rs:36-43`)
    /// makes this stop compiling until it is classified. That is what makes the
    /// vocabulary claim below a checked fact rather than an assertion about a
    /// shape nobody enumerated.
    fn daemon_case_state_label(status: &DaemonRuntimeStatus) -> &'static str {
        match status {
            DaemonRuntimeStatus::NotLaunched => "not_launched",
            DaemonRuntimeStatus::Launching => "launching",
            DaemonRuntimeStatus::Running => "running",
            DaemonRuntimeStatus::Ready => "ready",
            DaemonRuntimeStatus::Degraded(_) => "degraded",
            DaemonRuntimeStatus::Failed(_) => "failed",
        }
    }

    /// `daemon_supervision.rs` read at compile time, for the ONE production
    /// decision this file does not own: whether a planned shutdown is a failure
    /// to retry. It is read here rather than called because
    /// `daemon_owner_restart_lifecycle` is a private `const fn` of that module
    /// (`daemon_supervision.rs:173`) and a test may not widen its visibility.
    ///
    /// `#[cfg(windows)]` because the decision it reads is itself
    /// `#[cfg(windows)]` (`daemon_supervision.rs:172`) and is not compiled on
    /// another target; case 18, its only reader, carries the same gate. The
    /// health-view codes read alongside it in `health_view.rs` are NOT gated
    /// there, and are noted at their own pin.
    #[cfg(windows)]
    const DAEMON_SUPERVISION_SOURCE: &str = include_str!("daemon_supervision.rs");

    /// `health_view.rs` read at compile time, for the ONE owner that keeps
    /// `Draining` and `Stopped` apart as they reach an operator: the bounded
    /// `KernelActivationView.service_state` code map. `health_view.rs` belongs to
    /// another writer and is only ever READ here; `kernel_service_state_code` is
    /// a module-private `const fn` (`health_view.rs:74`) whose result is
    /// reachable only through a real `activation_operational_view` call, which
    /// needs the owner's live state machine, so the source pin is what this file
    /// can measure without widening visibility or driving a lifecycle.
    #[cfg(windows)]
    const HEALTH_VIEW_SOURCE: &str = include_str!("health_view.rs");

    /// One span of [`DAEMON_SUPERVISION_SOURCE`], from an exact opening spelling to
    /// the exact spelling that follows it.
    ///
    /// Both boundaries are exact spellings, so a moved or renamed decision fails
    /// the lookup instead of silently proving an empty slice. This is a second
    /// reader rather than a second scheme: the `source_between` above is bound to
    /// `THIS_FILE`, and the decision this case measures is not in this file.
    #[cfg(windows)]
    fn supervision_source_between(open: &str, close: &str) -> &'static str {
        let Some(start) = DAEMON_SUPERVISION_SOURCE.find(open) else {
            panic!("the opening spelling is in daemon_supervision.rs");
        };
        let Some(offset) = DAEMON_SUPERVISION_SOURCE[start..].find(close) else {
            panic!("the closing spelling follows the opening one in daemon_supervision.rs");
        };
        &DAEMON_SUPERVISION_SOURCE[start..start + offset]
    }

    /// LIVENESS IS NOT READINESS (case 19).
    ///
    /// Every target. `mark_daemon_ready` (:2184) carries no platform attribute, and
    /// all three verdicts asserted below are decided by its one guard at
    /// :2204 on every target — the two arms above that guard (the `already_ready`
    /// readback at :2190-2192 and the `supervision_unproven` refusal at
    /// :2198-2203) are `#[cfg(windows)]` and no arm here reaches either. The
    /// bound supervision contour is recorded under `#[cfg(windows)]` because the
    /// slot is `#[cfg(windows)]` (`daemon_supervision.rs:458-459`); off Windows
    /// the arms differ only in the receipt and status slots and the verdicts are
    /// the same three.
    ///
    /// Docs, condensed from the read fragments (line breaks reflowed; the
    /// fragments' own spelling otherwise reproduced):
    /// * I14.20: "Process liveness/readiness and capability-generation state
    ///   remain separate."
    /// * I1.5: "The activation is not reported fully healthy merely because Host
    ///   and Kernel are alive."
    /// * I1.5: "An installed agent shim, hook, plugin or MCP bridge is a
    ///   demand-start trigger only; it stores no semantic state or authority."
    ///
    /// The causal property: a daemon that holds the executor's exact
    /// `ProcessStartReceipt` — and, where the slot exists, a bound supervision
    /// contour — is ALIVE, and neither of those facts nor the `Running` status
    /// alone reaches the owner's readiness verdict, because the verdict promotes
    /// only from a `Running` state that still holds its receipt (:2204).
    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "each liveness arm, its readback and its source pin are one measured order"
    )]
    fn an_alive_daemon_without_a_receipt_and_a_running_status_never_reaches_readiness() {
        let (_root, kernel) = daemon_case_kernel("liveness-not-readiness");
        let receipt = daemon_case_receipt(1);

        // ARM ONE. Every liveness coordinate production reads is present: the
        // exact executor receipt and, where the slot exists, the bound
        // supervision contour. Only the semantic status differs, and it is the
        // STARTING one. A mutation that read `!= Ready` here instead of
        // `!= Running`, or that dropped the receipt clause, promotes this daemon
        // and fails the assertions.
        {
            let mut state = daemon_case_state(&kernel);
            state.status = DaemonRuntimeStatus::Launching;
            state.receipt = Some(receipt.clone());
            daemon_case_bind_supervision(&mut state);
        }
        let (starting_logs, starting) = daemon_case_capture_with(|| kernel.mark_daemon_ready());
        assert!(
            matches!(&starting, Err(KernelServiceError::ReadinessNotProven)),
            "a STARTING daemon must not reach the readiness verdict: {starting:?}"
        );
        assert_eq!(
            daemon_case_daemon_events(&starting_logs),
            vec!["kernel.daemon.ready_reported".to_owned()],
            "the whole captured daemon surface of a refused owner report: {starting_logs}"
        );
        assert_eq!(
            daemon_case_outcome(&starting_logs, "kernel.daemon.ready_reported"),
            "readiness_unproven",
            "{starting_logs}"
        );
        // The readback is production's own record, through the lock production
        // writes through: the refusal applied nothing.
        {
            let state = daemon_case_state(&kernel);
            assert_eq!(
                state.status,
                DaemonRuntimeStatus::Launching,
                "the refused report promoted the recorded daemon status"
            );
            assert_eq!(
                state.receipt.as_ref(),
                Some(&receipt),
                "the refused report disturbed the recorded receipt"
            );
        }
        assert!(
            !kernel.daemon_ready(),
            "the recorded status {} is not the one the readiness predicate accepts",
            daemon_case_state_label(&DaemonRuntimeStatus::Launching),
        );

        // ARM TWO. The other half of the same guard: the status IS the live
        // `Running` one and the supervision contour is bound, but the owner
        // holds NO receipt, so there is no process the readiness report could be
        // about. Liveness was asserted by this test, not proven by the owner.
        {
            let mut state = daemon_case_state(&kernel);
            state.status = DaemonRuntimeStatus::Running;
            state.receipt = None;
            daemon_case_bind_supervision(&mut state);
        }
        let (receiptless_logs, receiptless) =
            daemon_case_capture_with(|| kernel.mark_daemon_ready());
        assert!(
            matches!(&receiptless, Err(KernelServiceError::ReadinessNotProven)),
            "a Running status with no receipt must not reach the readiness verdict: {receiptless:?}"
        );
        assert_eq!(
            daemon_case_daemon_events(&receiptless_logs),
            vec!["kernel.daemon.ready_reported".to_owned()],
            "{receiptless_logs}"
        );
        assert_eq!(
            daemon_case_outcome(&receiptless_logs, "kernel.daemon.ready_reported"),
            "readiness_unproven",
            "{receiptless_logs}"
        );
        {
            let state = daemon_case_state(&kernel);
            assert_eq!(
                state.status,
                DaemonRuntimeStatus::Running,
                "the refused report promoted the recorded daemon status"
            );
            assert!(
                state.receipt.is_none(),
                "the refused report installed a receipt the owner never held"
            );
        }
        assert!(
            !kernel.daemon_ready(),
            "a Running daemon with no receipt is not the readiness the predicate accepts; the recorded status is {}",
            daemon_case_state_label(&DaemonRuntimeStatus::Running),
        );

        // ABSENCE over the WHOLE captured surface of both refused arms, not a
        // hand-listed name set. The mutation each one breaks is a `ready_proven`
        // emission on a refused arm: the only `ready_proven` callsite in this
        // file is daemon_runtime.rs:2215, which production reaches ONLY after the
        // guard at :2204 passed. The positive role of both scans is the
        // `ready_reported` record each capture is asserted to carry above.
        for (label, logs) in [
            ("the STARTING arm", &starting_logs),
            ("the receipt-less arm", &receiptless_logs),
        ] {
            assert!(
                !logs.contains("ready_proven"),
                "{label} reached the readiness verdict in the whole capture: {logs}"
            );
            assert!(
                !logs.contains("_requested"),
                "{label} recorded a request observation on the owner-observation leg: {logs}"
            );
        }

        // ARM THREE. The same composition, the same receipt and, where the slot
        // exists, the same bound supervision contour, with the status the owner
        // actually records before accepting an authenticated ready report. This
        // is the only positive arm, and it is what makes the two refusals above
        // measurements rather than a pair of always-false assertions.
        {
            let mut state = daemon_case_state(&kernel);
            state.status = DaemonRuntimeStatus::Running;
            state.receipt = Some(receipt.clone());
            daemon_case_bind_supervision(&mut state);
        }
        let (accepted_logs, accepted) = daemon_case_capture_with(|| kernel.mark_daemon_ready());
        assert!(
            accepted.is_ok(),
            "the accepted owner report must succeed with the same live evidence: {accepted:?}"
        );
        assert_eq!(
            daemon_case_daemon_events(&accepted_logs),
            vec!["kernel.daemon.ready_proven".to_owned()],
            "the whole captured daemon surface of an accepted owner report: {accepted_logs}"
        );
        assert_eq!(
            daemon_case_outcome(&accepted_logs, "kernel.daemon.ready_proven"),
            "success",
            "{accepted_logs}"
        );
        assert!(
            kernel.daemon_ready(),
            "the recorded status {} is now the one the readiness predicate accepts",
            daemon_case_state_label(&DaemonRuntimeStatus::Ready),
        );

        // WHICH SLOT PRODUCTION READS, measured on the production source of the
        // owner's own guard rather than described. A guard that consulted a
        // different slot, or one whose promotion wrote a different status, breaks
        // these spellings.
        let owner = source_between(
            "    pub fn mark_daemon_ready(&self) -> Result<(), KernelServiceError> {",
            "    /// Records a bounded authenticated daemon degradation.",
        );
        assert!(
            owner.contains(
                "if state.receipt.is_none() || state.status != DaemonRuntimeStatus::Running {"
            ),
            "the owner no longer refuses on the receipt slot AND the Running status"
        );
        let Some(guard) = owner
            .find("if state.receipt.is_none() || state.status != DaemonRuntimeStatus::Running {")
        else {
            panic!("the owner's refusal guard is present");
        };
        let Some(promote) = owner.find("state.status = DaemonRuntimeStatus::Ready;") else {
            panic!("the owner still promotes the recorded status to Ready");
        };
        assert!(
            guard < promote,
            "the owner promotes the recorded status before it refuses on the status slot"
        );
        // And the public verdict is decided by that same slot alone, through the
        // owner's own predicate, which matches `Ready` and nothing else.
        let verdict = source_between(
            "    /// Returns whether `eliotd` has completed its authenticated ready report.",
            "    fn daemon_failure_error(&self, reason: String) -> KernelBuildError {",
        );
        assert!(
            verdict.contains("daemon_status_proves_ready(&state.status)"),
            "the public readiness verdict no longer reads the recorded status through the owner's predicate"
        );
        assert!(
            !verdict.contains("state.receipt"),
            "the public readiness verdict now consults the receipt slot, so a live process would decide readiness"
        );
        assert!(daemon_status_proves_ready(&DaemonRuntimeStatus::Ready));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Running));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Launching));
        assert!(!daemon_status_proves_ready(&DaemonRuntimeStatus::Degraded(
            String::new()
        )));
        // Not vacuously unequal: the status comparison the readbacks above rely
        // on is a real one, so "the recorded status changed" would be measurable.
        assert_ne!(
            DaemonRuntimeStatus::Ready,
            DaemonRuntimeStatus::Running,
            "the daemon status compares equal regardless of the recorded value, so every readback above would measure nothing"
        );
    }

    /// AN ACTIVATION REQUEST IS NOT AN OWNER OBSERVATION (case 6).
    ///
    /// `#[cfg(windows)]`: the captured owner-leg refusal asserted below is the
    /// `supervision_unproven` verdict (:2198-2203), which is compiled only where
    /// the supervision slot is (`daemon_supervision.rs:458-459`). The request-leg
    /// source pins above it are not platform-specific; they are gated with the
    /// capture they share rather than split into a second test over the same
    /// source.
    ///
    /// Docs, condensed from the read fragments (line breaks reflowed; the
    /// fragments' own `→` glyphs reproduced):
    /// * I1.5: "An installed agent shim, hook, plugin or MCP bridge is a
    ///   demand-start trigger only; it stores no semantic state or authority."
    /// * I1.5 activation contour (two consecutive `→`-led steps of that
    ///   fragment's activation block): "→ start only the remaining capabilities
    ///   required by the admitted request → return the activation/readiness
    ///   delta to the caller."
    /// * I1.8: "Kernel rechecks only properties it owns and binds the
    ///   activation/staging receipt to the same `admission_decision_digest`."
    /// * I14.20: "Process liveness/readiness and capability-generation state
    ///   remain separate."
    ///
    /// The causal property: the request legs (`recovery_requested` at :1791,
    /// `await_requested` at :549) and the owner-observation legs
    /// (`ready_reported` at :2195/:2201/:2206 and `ready_proven` at :2215) are
    /// four different production callsites with four disjoint event names, so a
    /// mutation that emitted a request observation where the owner observation
    /// belongs — or the reverse — reddens both the captured record and the
    /// source pins.
    #[test]
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the two legs, the captured record and the disjointness pins are one measured order"
    )]
    fn an_activation_request_is_not_an_owner_readiness_observation() {
        let (_root, kernel) = daemon_case_kernel("request-versus-observation");

        // THE REQUEST LEG is real and it is recorded BEFORE the operation it
        // requests runs. This is measured on production source because the card
        // DEFERS live daemon-launch execution: driving `recover_eliotd` would
        // launch a process, and a claim about a launch this test never performs
        // is not a claim it can make.
        let request = source_between(
            "    async fn recover_eliotd_in_context(",
            "    /// Bounded disposition, fresh binding, and readiness rendezvous; every",
        );
        assert!(
            request.contains(
                "observe_daemon_runtime_in_context(\"kernel.daemon.recovery_requested\", \"attempt\", context);"
            ),
            "the recovery request leg no longer records its own bounded request before doing anything"
        );
        let Some(asked) = request.find("\"kernel.daemon.recovery_requested\"") else {
            panic!("the recovery request literal is present");
        };
        let Some(ran) = request.find(".recover_eliotd_inner(") else {
            panic!("the recovery request leg no longer reaches the recovery it requests");
        };
        assert!(
            asked < ran,
            "the recovery request observation is now recorded after the recovery it requested; both offsets are located in this one request slice, and the call needle is the leading-dot spelling because production puts `match self` on :1793 and `.recover_eliotd_inner(` on :1794, so `self.recover_eliotd_inner(` is never contiguous"
        );
        // The request leg answers a QUESTION. It carries no readiness claim and
        // no owner verdict, so it may never name either owner event.
        for owner_event in ["kernel.daemon.ready_proven", "kernel.daemon.ready_reported"] {
            assert!(
                !request.contains(owner_event),
                "the recovery request leg records the owner observation `{owner_event}`"
            );
        }
        let rendezvous = source_between(
            "    pub(crate) async fn await_daemon_ready(",
            "    pub(super) async fn close_previous_daemon_process(",
        );
        assert!(
            rendezvous.contains(
                "observe_daemon_runtime_in_context(\"kernel.daemon.await_requested\", \"attempt\", context);"
            ),
            "the readiness rendezvous no longer records its own request before waiting"
        );
        for owner_event in ["kernel.daemon.ready_proven", "kernel.daemon.ready_reported"] {
            assert!(
                !rendezvous.contains(owner_event),
                "the readiness rendezvous records the owner observation `{owner_event}` while only waiting"
            );
        }

        // THE OWNER-OBSERVATION LEG is a real, separate callsite with its own
        // vocabulary: three refusals on the report and one acceptance, and not
        // one request-shaped name. Counted over this function's own source
        // slice, which starts at its signature, so this test's comments cannot
        // satisfy the count.
        let owner = source_between(
            "    pub fn mark_daemon_ready(&self) -> Result<(), KernelServiceError> {",
            "    /// Records a bounded authenticated daemon degradation.",
        );
        assert_eq!(
            owner.matches("kernel.daemon.").count(),
            4,
            "the owner-observation leg no longer carries exactly its four bounded records"
        );
        assert_eq!(
            owner.matches("\"kernel.daemon.ready_proven\"").count(),
            1,
            "the owner-observation leg no longer claims readiness at exactly one place"
        );
        assert_eq!(
            owner.matches("\"kernel.daemon.ready_reported\"").count(),
            3,
            "the owner-observation leg no longer names its own refusals at three places"
        );
        assert!(
            !owner.contains("_requested"),
            "the owner-observation leg now records a request observation"
        );
        // The two vocabularies are DISJOINT as EVENT names, which is what makes
        // a mutation that swapped one leg's record for the other's a loud red.
        // The EVENT name is the discriminator and not the outcome, because the
        // outcome vocabulary genuinely overlaps: `recovery_committed` and
        // `ready_proven` both report `success`. That overlap is measured below
        // rather than papered over, and it is exactly why this case is an
        // event-level claim.
        let request_events: [&str; 2] = [
            "kernel.daemon.recovery_requested",
            "kernel.daemon.await_requested",
        ];
        let observation_events: [&str; 2] =
            ["kernel.daemon.ready_reported", "kernel.daemon.ready_proven"];
        for request_event in request_events {
            assert!(
                !owner.contains(request_event),
                "the owner-observation leg records the request event `{request_event}`"
            );
        }
        // And the positive direction: each owner-observation name is written on
        // the owner leg, so the disjointness above is not satisfied by deleting
        // the owner's own vocabulary instead.
        for observation_event in observation_events {
            assert!(
                owner.contains(observation_event),
                "the owner-observation leg no longer records `{observation_event}` at all"
            );
        }
        assert!(
            request.contains("\"kernel.daemon.recovery_committed\"")
                && request.contains("\"kernel.daemon.recovery_failed\""),
            "the recovery request leg no longer names its own commit and failure outcomes separately from its request"
        );
        // The overlap itself, asserted rather than described: the same outcome
        // literal is used by one record on each leg, so the event name is the
        // only thing that keeps the legs apart.
        assert!(
            request.contains(
                "\"kernel.daemon.recovery_committed\",\n                    \"success\","
            ) && owner.contains("\"kernel.daemon.ready_proven\", \"success\""),
            "the shared `success` outcome literal is no longer what the two legs both report, so the overlap note above is stale"
        );

        // The record the owner leg ACTUALLY emits, captured from the real owner,
        // for both of its verdict shapes. The exact list is the whole captured
        // event surface, so the request leg appearing here — under any spelling
        // this test never listed — breaks the equality.
        {
            let mut state = daemon_case_state(&kernel);
            state.status = DaemonRuntimeStatus::Running;
            state.receipt = Some(daemon_case_receipt(1));
        }
        let (unproven_logs, unproven) = daemon_case_capture_with(|| kernel.mark_daemon_ready());
        assert!(unproven.is_err(), "{unproven:?}");
        assert_eq!(
            daemon_case_daemon_events(&unproven_logs),
            vec!["kernel.daemon.ready_reported".to_owned()],
            "the owner leg's refusal record is not exactly one owner-observation event: {unproven_logs}"
        );
        {
            let mut state = daemon_case_state(&kernel);
            state.status = DaemonRuntimeStatus::Running;
            state.receipt = Some(daemon_case_receipt(1));
            state.supervision = Some(daemon_case_contour(1));
        }
        let (proven_logs, proven) = daemon_case_capture_with(|| kernel.mark_daemon_ready());
        assert!(proven.is_ok(), "{proven:?}");
        assert_eq!(
            daemon_case_daemon_events(&proven_logs),
            vec!["kernel.daemon.ready_proven".to_owned()],
            "the owner leg's acceptance record is not exactly one owner-observation event: {proven_logs}"
        );
        // REGRESSION GUARD (absence), over the WHOLE captured surface of both
        // owner-leg records. The mutation each breaks is an emission of a
        // REQUEST event from `mark_daemon_ready`: the request vocabulary
        // reachable from this file is written only at :549 and :1791, and the one
        // other request event in the composition is the launch module's own
        // `kernel.daemon.launch_requested` (`daemon_process_launch.rs:127`, its
        // own facade), so any request-shaped name appearing on the owner leg is a
        // leg swap. The positive role of both scans is the single-event equality
        // each capture is asserted to carry above.
        for logs in [&unproven_logs, &proven_logs] {
            assert!(
                !logs.contains("_requested"),
                "the owner-observation leg emitted a request record: {logs}"
            );
        }
    }

    /// THE ARMED DAEMON STATES STAY DISTINCT (case 18), with LIVENESS never
    /// promoted to READINESS and an unanswered request staying unknown.
    ///
    /// `#[cfg(windows)]`: it drives `await_daemon_ready` (attribute at :531),
    /// the rendezvous it measures, and records the `#[cfg(windows)]` supervision
    /// slot through the same fixture helper.
    ///
    /// WHAT IS MEASURED, in the shape the code actually has and not in the
    /// shape the card words it: one production rendezvous decides FIVE ARMED
    /// daemon states out of the recorded owner slots — NOT a REQUESTED, a
    /// STARTING, a READY, a DRAINING, a STOPPING and a FAILED one. Two of the
    /// five share ONE outcome literal (`NotLaunched` and `Launching` both reach
    /// `not_launched`, pinned by design at :573), and DRAINING and STOPPED are
    /// not deciders of this rendezvous at all: `DaemonRuntimeStatus`
    /// (`daemon_supervision.rs:36-43`) has no such variants, so no state this
    /// owner records can be draining or stopped. That pair is therefore measured
    /// where its owner decides it, at the end of this test, and this file does
    /// not claim the rendezvous distinguishes them.
    ///
    /// Docs, condensed from the read fragments (line breaks reflowed; the
    /// fragments' own `→` glyphs reproduced; `...` marks lines a quote skips):
    /// * I14.20 service process (one source line per quoted span): "STOPPED →
    ///   STARTING", "STARTING → RECOVERING | READY", ... "READY | DEGRADED →
    ///   QUIESCING → STOPPED", and "Process liveness/readiness and capability-generation state remain separate."
    /// * I14.24 containment-matrix ROW for the `eliotd` crash, reflowed from the
    ///   fragment's table row onto comment lines: "| `eliotd` crash | Kernel
    ///   revokes daemon epoch | external effects stop; recovery/control remain |
    ///   compatible daemon generation; rebuild hot mirrors |"
    /// * I14.21: "if unknown → pause Ordering Scope, preserve operation and open
    ///   Problem State; Human/Doctor chooses evidence-backed reconciliation; no
    ///   blind duplicate effect."
    /// * I1.3: "A persistent Doctor agent is prohibited."
    ///
    /// The causal property: the owner status slot is the discriminator of the
    /// rendezvous, each armed state reaches its own recorded verdict through it,
    /// the wait never reaches the readiness verdict on its own authority, and a
    /// `Running` daemon that never reports stays unknown until the wait itself
    /// expires into a refusal — never into a synthesised readiness.
    #[test]
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "five measured verdicts, the unanswered request and the draining/stopped pins are one order"
    )]
    fn the_daemon_lifecycle_states_stay_distinct_and_liveness_is_never_promoted() {
        let (_root, kernel) = daemon_case_kernel("five-lifecycle-states");
        let canary = "degraded-903-owner-status-canary";
        let exact = daemon_case_receipt(1);
        let unanswered = Duration::from_millis(1);

        // Each arm records the SAME exact executor receipt and the SAME bound
        // supervision contour, and differs only in the owner's recorded status,
        // so every difference in the verdict below is attributable to the slot
        // production reads and to nothing this test supplied.
        let arms: Vec<(DaemonRuntimeStatus, bool, &str, &str)> = vec![
            (
                DaemonRuntimeStatus::NotLaunched,
                false,
                "kernel.daemon.await_rejected",
                "not_launched",
            ),
            (
                DaemonRuntimeStatus::Launching,
                false,
                "kernel.daemon.await_rejected",
                "not_launched",
            ),
            (
                DaemonRuntimeStatus::Ready,
                true,
                "kernel.daemon.await_satisfied",
                "success",
            ),
            (
                DaemonRuntimeStatus::Degraded(canary.to_owned()),
                false,
                "kernel.daemon.await_rejected",
                "degraded_before_ready",
            ),
            (
                DaemonRuntimeStatus::Failed(canary.to_owned()),
                false,
                "kernel.daemon.await_rejected",
                "failed_before_ready",
            ),
        ];

        // `measured` is filled ONLY from what production did: the recorded status
        // production wrote and this test read back through the same mutex, the
        // outcome token parsed out of the captured line for whichever verdict
        // EVENT production actually emitted, and the `Result` the real
        // rendezvous returned. The fixture's own expectations are compared
        // against production one arm at a time below and are never copied into
        // `measured`, so no comparison over `measured` can be satisfied by two
        // values this test supplied.
        let mut measured: Vec<(DaemonRuntimeStatus, String, bool)> = Vec::new();
        let mut captures: Vec<String> = Vec::new();
        for (status, expected_ok, expected_event, expected_outcome) in &arms {
            let (logs, outcome) =
                daemon_case_await(&kernel, status.clone(), &exact, &exact, unanswered);
            // The REQUEST leg precedes the decision in every arm: the wait is
            // recorded as a request first, so a satisfied wait is a request plus
            // an answer, never an answer standing in for a request.
            assert_eq!(
                daemon_case_daemon_events(&logs),
                vec![
                    "kernel.daemon.await_requested".to_owned(),
                    (*expected_event).to_owned(),
                ],
                "the rendezvous surface for the {} arm is not the request then its own verdict: {logs}",
                daemon_case_state_label(status),
            );
            assert_eq!(
                daemon_case_outcome(&logs, expected_event),
                *expected_outcome,
                "the {} arm verdict changed: {logs}",
                daemon_case_state_label(status),
            );
            assert_eq!(
                outcome.is_ok(),
                *expected_ok,
                "the {} arm reached the wrong result: {outcome:?}",
                daemon_case_state_label(status),
            );
            // The readback is production's own record: a rejected verdict applied
            // nothing to the slot it decided on. It is the value the pairwise
            // discriminator comparison below runs on, taken from the lock
            // production writes through rather than from the armed fixture.
            let recorded = {
                let state = daemon_case_state(&kernel);
                assert_eq!(
                    &state.status,
                    status,
                    "the {} arm rewrote the recorded daemon status",
                    daemon_case_state_label(status),
                );
                assert_eq!(
                    state.receipt.as_ref(),
                    Some(&exact),
                    "the {} arm rewrote the recorded receipt",
                    daemon_case_state_label(status),
                );
                state.status.clone()
            };
            // And the verdict EVENT is read off the captured surface rather than
            // off the fixture: the equality above proved the daemon surface is
            // exactly the request record plus one verdict record, so the record at
            // index 1 is the one production emitted.
            let Some(verdict_event) = daemon_case_daemon_events(&logs).get(1).cloned() else {
                panic!(
                    "the {} arm emitted no verdict record: {logs}",
                    daemon_case_state_label(status)
                );
            };
            measured.push((
                recorded,
                daemon_case_outcome(&logs, &verdict_event),
                outcome.is_ok(),
            ));
            captures.push(logs);
        }

        // THE STATES ARE DISTINCT FROM ONE ANOTHER, not collapsed into a
        // ready/not-ready pair. TWO measurements, both over production values:
        //
        // * the DISCRIMINATOR — the `DaemonRuntimeStatus` production wrote into
        //   the owner record and this test read back through the same mutex — is
        //   pairwise distinct across the five arms. This one is a NON-VACUITY
        //   CONTROL on the word "collapsed" in the next bullet, and is labelled
        //   as such: five different armed states would still produce five
        //   different recorded statuses whether or not production treated them
        //   alike, so on its own it pins no production decision.
        // * the RECORD — the outcome production emitted for whichever event it
        //   emitted, read out of that captured line, together with the `Result`
        //   the real rendezvous returned — must be exactly the set of verdicts
        //   this owner produces. THIS is the falsifiable half: a production that
        //   merged two states onto one verdict, or invented a verdict nobody
        //   emits, reddens it, and neither value in it was supplied here.
        for (index, (left_status, _left_outcome, _left_ok)) in measured.iter().enumerate() {
            for (right_status, _right_outcome, _right_ok) in &measured[index + 1..] {
                assert_ne!(
                    left_status,
                    right_status,
                    "the armed daemon states no longer read back as distinct recorded statuses: {} and {}",
                    daemon_case_state_label(left_status),
                    daemon_case_state_label(right_status),
                );
            }
        }
        let mut verdicts: Vec<(&str, bool)> = Vec::new();
        for (_recorded_status, outcome, ok) in &measured {
            let key = (outcome.as_str(), *ok);
            if !verdicts.contains(&key) {
                verdicts.push(key);
            }
        }
        assert_eq!(
            verdicts,
            vec![
                ("not_launched", false),
                ("success", true),
                ("degraded_before_ready", false),
                ("failed_before_ready", false),
            ],
            "the recorded verdicts are no longer exactly the set this owner produces"
        );

        // MEASURED LIMIT, reported rather than hidden: production's OUTCOME
        // vocabulary collapses REQUESTED and STARTING onto ONE literal, because
        // `await_daemon_ready` reaches both through the single
        // `NotLaunched | Launching` arm at :573. What is measured here is the
        // CAPTURED SURFACE of those two arms and the RECORDS production holds for
        // them — not this test's fixture: the `await_rejected` outcome production
        // emitted is the same for both, and the recorded statuses production
        // holds are two different records. So a production that later SPLIT the
        // literal reddens the equality below and this note is then stale rather
        // than silently wrong; a split that also RENAMED the verdict event
        // reddens the per-arm event equality inside the arm loop instead. It is
        // not an endorsement of the collapse.
        assert_eq!(
            daemon_case_outcome(&captures[0], "kernel.daemon.await_rejected"),
            daemon_case_outcome(&captures[1], "kernel.daemon.await_rejected"),
            "the outcome vocabulary now separates REQUESTED from STARTING, so this limit note is stale"
        );
        assert_ne!(
            measured[0].0, measured[1].0,
            "the two arms sharing one outcome literal no longer hold two different recorded daemon statuses, so the collapse above is no longer a collapse"
        );

        // AN UNANSWERED REQUEST STAYS UNKNOWN. The `Running` arm is the live,
        // not-ready daemon whose owner never reported: the wait is a real timed
        // wait that expires, and the expired wait is a refusal with its own
        // bounded outcome. Production never synthesises a readiness for it and
        // never synthesises a success either — the owner's own status slot is
        // what records what happened.
        let (timeout_logs, timeout) = daemon_case_await(
            &kernel,
            DaemonRuntimeStatus::Running,
            &exact,
            &exact,
            unanswered,
        );
        assert!(
            timeout.is_err(),
            "a live daemon that never reported satisfied the readiness wait"
        );
        assert_eq!(
            daemon_case_daemon_events(&timeout_logs),
            vec![
                "kernel.daemon.await_requested".to_owned(),
                "kernel.daemon.await_rejected".to_owned(),
            ],
            "the unanswered request is not a request plus its own refusal: {timeout_logs}"
        );
        assert_eq!(
            daemon_case_outcome(&timeout_logs, "kernel.daemon.await_rejected"),
            "timeout",
            "{timeout_logs}"
        );
        captures.push(timeout_logs);

        // REGRESSION GUARD (absence), over the WHOLE captured surface of every
        // arm above rather than a hand-listed name set. The mutation each breaks
        // is a readiness claim emitted by the WAIT itself: the four
        // `observe_daemon_runtime_in_context` callsites of `await_daemon_ready`
        // (:549, :595, :604, :613) name only `await_requested`,
        // `await_satisfied` and `await_rejected`, so any owner-readiness name on
        // this surface is the wait deciding readiness on the owner's behalf. The
        // positive role of the scan is the six request-plus-verdict records
        // asserted above.
        for (index, logs) in captures.iter().enumerate() {
            assert!(
                !logs.contains("ready_proven"),
                "the rendezvous arm {index} claimed readiness on the owner's behalf: {logs}"
            );
            assert!(
                !logs.contains("ready_reported"),
                "the rendezvous arm {index} recorded an owner readiness report it cannot own: {logs}"
            );
            // REGRESSION GUARD (absence), the same surface: the owner's status
            // payload. The mutation each breaks is an emission carrying
            // `status.to_string()` or the rejection `reason` — the rejection at
            // :563-565 builds an error string from it, and that string is
            // returned, never logged. The positive role is the six records each
            // capture is asserted to carry above.
            assert!(
                !logs.contains(canary),
                "the owner's daemon status payload reached the sink on arm {index}: {logs}"
            );
        }

        // DRAINING AND STOPPED ARE NOT A LIVE OR READY STATE, AND THE OWNER
        // LIFECYCLE KEEPS THE TWO TOGETHER AS ONE PLANNED SHUTDOWN. That pair
        // has no `DaemonRuntimeStatus` variant at all — the exhaustive label
        // match in `daemon_case_state_label` is the evidence, because it carries
        // no wildcard arm and adding a variant would stop this file compiling —
        // so production's own decision for it lives in the supervision module
        // and is read there: `daemon_owner_restart_lifecycle`
        // (daemon_supervision.rs:173) maps `Draining` and `Stopped` onto ONE
        // shared arm producing `PlannedShutdown` and never `Running`, and that
        // mapped value is what `daemon_refuses_replacement` (:204) compares
        // against `Running`. It is read rather than called because that
        // `const fn` is private to its module and this test may not widen its
        // visibility.
        let owner_lifecycle = supervision_source_between(
            "const fn daemon_owner_restart_lifecycle(",
            "/// Returns the refusal that applies to one observed previous generation",
        );
        assert!(
            owner_lifecycle
                .contains("KernelServiceState::Draining | KernelServiceState::Stopped => {"),
            "the daemon owner lifecycle no longer maps draining and stopped through ONE shared arm, so the collapse this assertion pins is gone"
        );
        assert!(
            owner_lifecycle.contains("RestartOwnerLifecycle::PlannedShutdown"),
            "the daemon owner lifecycle no longer names the planned-shutdown value"
        );
        for live in [
            "KernelServiceState::Activating\n",
            "| KernelServiceState::Ready\n",
            "| KernelServiceState::Degraded => RestartOwnerLifecycle::Running",
        ] {
            assert!(
                owner_lifecycle.contains(live),
                "the daemon owner lifecycle no longer maps `{live}` to the running value"
            );
        }
        // AND THE OWNER THAT DOES KEEP THEM APART, so the reading above is not
        // read as a claim that the two are indistinguishable.
        // `kernel_service_state_code` (health_view.rs:74) is the bounded code map
        // behind `KernelActivationView.service_state`, and it gives `Draining` and
        // `Stopped` two DIFFERENT codes (health_view.rs:83-84). That is the
        // operator-visible distinction between the pair; the restart lifecycle
        // above deliberately declines to make it. `health_view.rs` is another
        // writer's file and is only READ here, at compile time, because
        // `kernel_service_state_code` is module-private and its result is
        // reachable only through a real `activation_operational_view` call on a
        // live owner.
        for (state, code) in [
            ("KernelServiceState::Draining", "draining"),
            ("KernelServiceState::Stopped", "stopped"),
        ] {
            assert!(
                HEALTH_VIEW_SOURCE.contains(&format!("{state} => \"{code}\",")),
                "the activation view no longer maps {state} to its own `{code}` code, so the operator-visible distinction between draining and stopped is gone"
            );
        }
        let replacement = supervision_source_between(
            "pub(crate) fn daemon_refuses_replacement(",
            "/// Classifies one reconciled generation into the evidence the class rule reads.",
        );
        assert!(
            replacement.contains(
                "if daemon_owner_restart_lifecycle(owner_state) != RestartOwnerLifecycle::Running {"
            ),
            "the replacement refusal no longer gates on the mapped owner lifecycle"
        );
    }

    /// AN EXACT REPLAY IS A READBACK (case 22): the already-recorded outcome is
    /// returned from the owner, and no second transition success is claimed.
    ///
    /// `#[cfg(windows)]`, and NOT as a matter of convenience: what this test
    /// measures IS the readback arm, and that arm is `#[cfg(windows)]`
    /// (`daemon_runtime.rs:2189-2197`) and keyed on a supervision slot that does
    /// not exist off Windows (`daemon_supervision.rs:458-459`). Off Windows
    /// `mark_daemon_ready` has no readback arm at all — a second call on a
    /// `Ready` record refuses with `readiness_unproven` instead — so there is no
    /// readback here to prove, and the exactness tail reads the receipt
    /// comparison at `daemon_runtime.rs:557` inside the same `#[cfg(windows)]` wait.
    ///
    /// Docs, condensed from the read fragments (line breaks reflowed; the
    /// fragments' own `→` glyphs reproduced):
    /// * I14.21: "Kernel queries `WriteReceipt` by idempotency key; if committed →
    ///   reconcile ORS", and "Human/Doctor chooses evidence-backed
    ///   reconciliation; no blind duplicate effect."
    /// * I14.20: "Rollback is never a backward state transition."
    /// * I1.8: "A digest, source-revision or mutation-plan mismatch returns
    ///   `TRANSITION_DIGEST_MISMATCH`/conflict and never retries as the same
    ///   decision."
    ///
    /// The causal property: `mark_daemon_ready` is idempotent only through its
    /// readback arm, which is keyed on THREE owner slots (:2190-2192). The first
    /// accepted report is the transition and is recorded once; the second call on
    /// the same owner record returns the recorded outcome, changes nothing, and
    /// claims nothing new. A mutation that made the replay a second application
    /// — or that dropped any one of the three slots from the readback condition
    /// — reddens here.
    #[test]
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the transition, the readback and the three per-slot cases are one measured order"
    )]
    fn an_exact_replay_returns_the_recorded_outcome_without_a_second_transition() {
        let (_root, kernel) = daemon_case_kernel("replay-readback");
        let receipt = daemon_case_receipt(1);
        let contour = daemon_case_contour(1);
        let foreign = daemon_case_receipt(2);
        assert_ne!(
            receipt, foreign,
            "the two fixture receipts are the same record, so the exactness case measures nothing"
        );

        // THE TRANSITION. The owner records the authenticated ready report once,
        // from a live `Running` daemon that still holds its exact receipt and its
        // bound supervision contour.
        {
            let mut state = daemon_case_state(&kernel);
            state.status = DaemonRuntimeStatus::Running;
            state.receipt = Some(receipt.clone());
            state.supervision = Some(contour.clone());
        }
        let (transition_logs, transition) = daemon_case_capture_with(|| kernel.mark_daemon_ready());
        assert!(transition.is_ok(), "{transition:?}");
        assert_eq!(
            daemon_case_daemon_events(&transition_logs),
            vec!["kernel.daemon.ready_proven".to_owned()],
            "the transition is not exactly one readiness record: {transition_logs}"
        );
        assert_eq!(
            daemon_case_outcome(&transition_logs, "kernel.daemon.ready_proven"),
            "success",
            "{transition_logs}"
        );
        let Some(recorded_supervision) = ({
            let state = daemon_case_state(&kernel);
            assert_eq!(
                state.status,
                DaemonRuntimeStatus::Ready,
                "the accepted transition did not record the owner status"
            );
            assert_eq!(
                state.receipt.as_ref(),
                Some(&receipt),
                "the accepted transition did not keep the owner's own receipt"
            );
            state.supervision.clone()
        }) else {
            panic!("the accepted transition dropped the bound supervision contour")
        };

        // THE REPLAY. The same owner record, presented again. The owner returns
        // the already-recorded outcome and claims no new transition.
        let (replay_logs, replay) = daemon_case_capture_with(|| kernel.mark_daemon_ready());
        assert!(
            replay.is_ok(),
            "the readback arm must return the recorded outcome: {replay:?}"
        );
        assert_eq!(
            daemon_case_daemon_events(&replay_logs),
            vec!["kernel.daemon.ready_reported".to_owned()],
            "the replay is not exactly one owner report record: {replay_logs}"
        );
        assert_eq!(
            daemon_case_outcome(&replay_logs, "kernel.daemon.ready_reported"),
            "already_ready",
            "{replay_logs}"
        );
        // THE REPLAY APPLIED NOTHING. Read back through the same mutex: this is
        // what separates "the owner returned its recorded outcome" from "a second
        // application happened to produce the same answer".
        {
            let state = daemon_case_state(&kernel);
            assert_eq!(
                state.status,
                DaemonRuntimeStatus::Ready,
                "the replay rewrote the recorded status"
            );
            assert_eq!(
                state.receipt.as_ref(),
                Some(&receipt),
                "the replay rewrote the recorded receipt"
            );
            assert_eq!(
                state.supervision.as_ref(),
                Some(&recorded_supervision),
                "the replay disturbed the recorded supervision contour"
            );
        }
        assert!(
            kernel.daemon_ready(),
            "the recorded owner state is still ready"
        );

        // EXACTLY ONE SUCCESS CLAIM across the WHOLE captured surface of both
        // calls, not a per-capture hand list. The mutation this breaks is a
        // second `ready_proven` emission on the readback arm: the only such
        // callsite in this file is :2215, reached only after the guard at :2204.
        let whole = format!("{transition_logs}{replay_logs}");
        assert_eq!(
            daemon_case_events(&whole)
                .iter()
                .filter(|event| event.as_str() == "kernel.daemon.ready_proven")
                .count(),
            1,
            "the replay claimed a second transition success: {whole}"
        );
        assert_eq!(
            daemon_case_events(&replay_logs)
                .iter()
                .filter(|event| event.as_str() == "kernel.daemon.ready_proven")
                .count(),
            0,
            "the replay recorded a readiness success: {replay_logs}"
        );

        // WHICH SLOTS THE READBACK READS, one at a time. Each case restores an owner
        // record and removes exactly ONE of the three conditions at :2190-2192,
        // so a readback condition dropped or widened in production reddens the
        // case for that slot and not for the others. What the remaining two slots
        // DO with the record differs — the refusal guard refuses one, and the
        // promotion path treats the other as a fresh report — so each case pins
        // its own real verdict rather than one invented outcome.
        for (slot, recorded, expected_event, expected_outcome, expected_ok) in [
            (
                "the receipt slot",
                (DaemonRuntimeStatus::Ready, None, Some(contour.clone())),
                "kernel.daemon.ready_reported",
                "readiness_unproven",
                false,
            ),
            (
                "the status slot",
                (
                    DaemonRuntimeStatus::Running,
                    Some(receipt.clone()),
                    Some(contour.clone()),
                ),
                "kernel.daemon.ready_proven",
                "success",
                true,
            ),
            (
                "the supervision slot",
                (DaemonRuntimeStatus::Ready, Some(receipt.clone()), None),
                "kernel.daemon.ready_reported",
                "supervision_unproven",
                false,
            ),
        ] {
            {
                let mut state = daemon_case_state(&kernel);
                state.status = recorded.0;
                state.receipt = recorded.1;
                state.supervision = recorded.2;
            }
            let (logs, outcome) = daemon_case_capture_with(|| kernel.mark_daemon_ready());
            assert_eq!(
                outcome.is_ok(),
                expected_ok,
                "{slot}: the arm reached the wrong result: {outcome:?}"
            );
            assert_eq!(
                daemon_case_daemon_events(&logs),
                vec![expected_event.to_owned()],
                "{slot}: the whole daemon observation surface is not that one record: {logs}"
            );
            assert!(
                !logs.contains("already_ready"),
                "the readback no longer reads {slot}, so a replay with that slot absent is still a readback: {logs}"
            );
            assert_eq!(
                daemon_case_outcome(&logs, expected_event),
                expected_outcome,
                "{slot}: the verdict changed: {logs}"
            );
            // And the record itself still names no readiness claim on the two
            // refusal arms. The whole raw surface is scanned, so the absence is
            // not read off a list this test wrote. The mutation each breaks is a
            // `ready_proven` emission reached before the guard at :2204.
            if !expected_ok {
                assert!(
                    !logs.contains("ready_proven"),
                    "{slot}: a refused replay still claimed readiness: {logs}"
                );
            }
        }

        // EXACTNESS OF THE RECEIPT THE READBACK ANSWERS. The owner's wait binds
        // readiness to the whole receipt record (:557), not to the mere presence
        // of one, so a request naming a different launched receipt is refused
        // instead of reading the owner's readiness back.
        let (bound_logs, bound) = daemon_case_await(
            &kernel,
            DaemonRuntimeStatus::Ready,
            &receipt,
            &receipt,
            Duration::from_millis(1),
        );
        assert!(
            bound.is_ok(),
            "the exact recorded receipt must be read back: {bound:?}"
        );
        assert_eq!(
            daemon_case_daemon_events(&bound_logs),
            vec![
                "kernel.daemon.await_requested".to_owned(),
                "kernel.daemon.await_satisfied".to_owned(),
            ],
            "{bound_logs}"
        );
        assert_eq!(
            daemon_case_outcome(&bound_logs, "kernel.daemon.await_satisfied"),
            "success",
            "{bound_logs}"
        );
        let (foreign_logs, foreign_outcome) = daemon_case_await(
            &kernel,
            DaemonRuntimeStatus::Ready,
            &receipt,
            &foreign,
            Duration::from_millis(1),
        );
        assert!(
            foreign_outcome.is_err(),
            "a different launched receipt satisfied the readiness wait"
        );
        assert_eq!(
            daemon_case_daemon_events(&foreign_logs),
            vec![
                "kernel.daemon.await_requested".to_owned(),
                "kernel.daemon.await_rejected".to_owned(),
            ],
            "{foreign_logs}"
        );
        assert_eq!(
            daemon_case_outcome(&foreign_logs, "kernel.daemon.await_rejected"),
            "receipt_mismatch",
            "{foreign_logs}"
        );
        // REGRESSION GUARD (absence), over the WHOLE captured surface of the
        // refused readback. The mutation each breaks is a readiness claim derived
        // from the mere presence of a receipt rather than from its exact value —
        // the `receipt_mismatch` refusal at :583-589 exists precisely so an
        // unanswered-for receipt cannot be reported as the owner's readiness. The
        // positive role is the `await_requested`/`await_rejected` record the same
        // capture is asserted to carry above.
        assert!(
            !foreign_logs.contains("await_satisfied") && !foreign_logs.contains("ready_proven"),
            "a mismatched receipt was reported as a satisfied readback: {foreign_logs}"
        );
    }
}
