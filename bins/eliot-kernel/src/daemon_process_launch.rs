//! Kernel approved `eliotd` launch contour.
//!
//! Architecture: ARCH-MOD-01, A13.2, A13.3 (Kernel and failure domains).
//! Implementation: R1 and I2.23 capability-family topology and crate extraction.
//! Forbidden authority: no Store/Governor/Host semantic authority, no route/default/retry/adoption/mint.
//! This module owns exactly `KernelComposition::launch_eliotd` and `KernelComposition::retain_eliotd_path_proof` and no additional route, default, retry, adoption, or mint authority.
//! Keeps signatures, bodies, ordering, visibility, routes, protocol and authority unchanged; `control_plane.rs` and `daemon_runtime.rs` callers remain untouched.
//! No Store/Governor/Host semantic decisions, no alternate lease or oracle, no unbounded recovery.
//!
//! #1678 W5/REQ7: the `eliotd` process launch is a real process/provider launch
//! path, so it holds the SAME launch prerequisite the native-worker contour
//! holds: the ORS owner's
//! [`verify_admission_reservation_launch_prerequisite`] must prove an `ACTIVE`
//! admission reservation carrying both its activation and canonical admission
//! receipts before any process start, path-lease retention or runtime state
//! transition. The gate is the existing owner verifier, not a second scheme,
//! and it runs before every effect below.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use eliot_contracts::sha256_hex;
use eliot_ors::{
    AdmissionReservationClaimRef, AdmissionReservationClaims, AdmissionReservationIdentityInput,
    AdmissionReservationLaunchPrerequisite, OpaqueLabel, OperationIdentity,
    OperationalRecoveryStore, StateFenceSnapshot, admission_reservation_identity,
    epoch_lineage_for, verify_admission_reservation_launch_prerequisite,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::WindowsPlatform;
use eliot_receipts::ReceiptIdentity;
use serde::Serialize;

use super::ACTIVE_DAEMON_CALLER;
use super::ActionLeaseRef;
use super::DaemonRuntimeStatus;
use super::EliotdLaunchDescriptor;
use super::EnvironmentInheritance;
use super::EnvironmentProjection;
use super::FencingToken;
use super::Generation;
use super::ImageId;
use super::JobId;
use super::KernelBuildError;
use super::KernelComposition;
use super::ProcessCallerSession;
use super::ProcessExecutionAdmissionRequest;
use super::ProcessExecutionError;
use super::ProcessIntent;
use super::ProcessOwnerBinding;
use super::ProcessPathProof;
use super::ProcessSessionClass;
use super::ProcessStartReceipt;
use super::ProcessTreeId;
use super::ResourceLimits;
use super::SessionId;
use super::current_process_named_pipe_expectation;
use super::diagnostic_brief::DiagnosticTrigger;
use super::eliotd_launch_attempt_identity;
use super::eliotd_operation_id;
use super::kernel_audit::AuditEventDraft;
use super::observe_named_pipe_peer_process;
use super::stable_owner_principal_digest;
use super::unix_ms;

/// F-LOG-KERNEL-3 (#901): daemon-launch boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.daemon.*` event names
/// plus a bounded stable outcome. Never carries executable paths, argument
/// material, digests, lease references, or owner error strings (I15.4).
#[cfg(windows)]
fn observe_daemon_launch(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "daemon launch observation"
    );
}

/// Maps one daemon-launch build failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload is never logged.
#[cfg(windows)]
fn daemon_launch_terminal_code(error: &KernelBuildError) -> &'static str {
    match error {
        KernelBuildError::Platform(_) => "PLATFORM",
        KernelBuildError::Transport(_) => "TRANSPORT",
        KernelBuildError::Runtime(_) => "RUNTIME",
        KernelBuildError::Ors(_) => "ORS",
        KernelBuildError::Core(_) => "CORE",
        KernelBuildError::Service(_) => "SERVICE",
        KernelBuildError::StoreBootstrapRequired => "STORE_BOOTSTRAP_REQUIRED",
        KernelBuildError::StoreAlreadyConnected => "STORE_ALREADY_CONNECTED",
        KernelBuildError::Principal(_) => "PRINCIPAL",
    }
}

/// The five admission-reservation claims for one `eliotd` launch.
///
/// Every reference is the owner identity of the claim's role and every digest
/// is the descriptor's own content digest, so nothing durable is recomputed in
/// order to be trusted; the ORS owner re-validates every value on the row it
/// actually reads back. The claim set is built from the Host-approved
/// descriptor the launch already validated, not from anything the caller
/// supplies at launch time.
fn eliotd_admission_reservation_claims(
    launch: &EliotdLaunchDescriptor,
    operation_id: &str,
) -> Result<AdmissionReservationClaims, KernelBuildError> {
    fn digest<T: Serialize>(value: &T) -> Result<String, KernelBuildError> {
        serde_json::to_vec(value)
            .map(|bytes| sha256_hex(&bytes))
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd admission reservation claim digest cannot be canonicalized: {error}"
                ))
            })
    }
    fn reference(value: &str, role: &'static str) -> Result<OpaqueLabel, KernelBuildError> {
        OpaqueLabel::new(value).map_err(|error| {
            KernelBuildError::Service(format!(
                "eliotd admission reservation {role} claim reference is not a usable label: {error}"
            ))
        })
    }
    Ok(AdmissionReservationClaims {
        resources: AdmissionReservationClaimRef {
            reference: reference(launch.executable.as_str(), "resource")?,
            sha256: digest(&(
                launch.executable.as_str(),
                launch.executable_sha256.as_str(),
                launch.protected_snapshot_digest.as_str(),
            ))?,
        },
        lane: AdmissionReservationClaimRef {
            reference: reference(launch.wire_id.as_str(), "lane")?,
            sha256: digest(&(launch.wire_id.as_str(), launch.wire_version))?,
        },
        environment: AdmissionReservationClaimRef {
            reference: reference(launch.config_descriptor.as_str(), "environment")?,
            sha256: digest(&(
                launch.config_descriptor.as_str(),
                launch.config_descriptor_sha256.as_str(),
                launch.working_directory.as_str(),
            ))?,
        },
        effects: AdmissionReservationClaimRef {
            reference: reference(operation_id, "effect")?,
            sha256: digest(&(
                operation_id,
                launch.launch_nonce.as_str(),
                &launch
                    .arguments
                    .iter()
                    .map(PlatformHandle::as_str)
                    .collect::<Vec<_>>(),
            ))?,
        },
        quota_view: AdmissionReservationClaimRef {
            reference: reference(
                &format!("quota-view:{}", launch.generation.value()),
                "quota-view",
            )?,
            sha256: digest(&(
                launch.generation.value(),
                launch.authority_epoch.sequence.get(),
                launch.authority_epoch.lineage_id.as_str(),
            ))?,
        },
    })
}

/// Turns the owner's launch-prerequisite verdict into this path's outcome.
///
/// Only `Active` proceeds, and only after BOTH owner receipts are read off the
/// sealed typestate. Every other disposition is a typed refusal whose message
/// names the exact state, so a refused launch says which state refused it
/// rather than collapsing into one opaque error.
fn eliotd_launch_prerequisite_outcome(
    prerequisite: AdmissionReservationLaunchPrerequisite,
    reservation_label: &str,
) -> Result<ReceiptIdentity, KernelBuildError> {
    match prerequisite {
        AdmissionReservationLaunchPrerequisite::Active(active) => {
            let activation_receipt = active.activation_receipt().map_err(|error| {
                KernelBuildError::Service(format!(
                    "active eliotd admission reservation {reservation_label} carries no activation receipt: {error}"
                ))
            })?;
            active.canonical_admission_receipt().map_err(|error| {
                KernelBuildError::Service(format!(
                    "active eliotd admission reservation {reservation_label} carries no canonical admission receipt: {error}"
                ))
            })?;
            Ok(activation_receipt.clone())
        }
        AdmissionReservationLaunchPrerequisite::Missing {
            work_item_id,
            proposed_attempt_id,
        } => Err(KernelBuildError::Service(format!(
            "eliotd launch refused: no admission reservation covers work item {} and proposed attempt {}",
            work_item_id.as_str(),
            proposed_attempt_id.as_str()
        ))),
        AdmissionReservationLaunchPrerequisite::Staged { reservation } => {
            Err(KernelBuildError::Service(format!(
                "eliotd launch refused: admission reservation {} is STAGED_INACTIVE and grants no launch authority",
                reservation.reservation_id.as_str()
            )))
        }
        AdmissionReservationLaunchPrerequisite::Released { reservation } => {
            Err(KernelBuildError::Service(format!(
                "eliotd launch refused: admission reservation {} is RELEASED with disposition {:?}",
                reservation.reservation_id.as_str(),
                reservation.disposition_reason
            )))
        }
        AdmissionReservationLaunchPrerequisite::Expired { reservation } => {
            Err(KernelBuildError::Service(format!(
                "eliotd launch refused: admission reservation {} is EXPIRED at {} and grants no launch authority",
                reservation.reservation_id.as_str(),
                reservation.expires_at_ms
            )))
        }
        AdmissionReservationLaunchPrerequisite::Reconciling { reservation } => {
            Err(KernelBuildError::Service(format!(
                "eliotd launch refused: admission reservation {} is RECONCILING and cannot create a new effect",
                reservation.reservation_id.as_str()
            )))
        }
        AdmissionReservationLaunchPrerequisite::StaleFence {
            reservation,
            expected_state_fence,
        } => Err(KernelBuildError::Service(format!(
            "eliotd launch refused: admission reservation {} was staged under State Fence {} but the launch verifies against {}",
            reservation.reservation_id.as_str(),
            reservation.state_fence.sha256,
            expected_state_fence.sha256
        ))),
        AdmissionReservationLaunchPrerequisite::ForeignOwner {
            reservation,
            expected_authority_epoch,
        } => Err(KernelBuildError::Service(format!(
            "eliotd launch refused: admission reservation {} is owned by Authority Epoch {} lineage {}, not by the launching epoch {} lineage {}",
            reservation.reservation_id.as_str(),
            reservation.authority_epoch.current.epoch,
            reservation.authority_epoch.current.lineage_id.as_str(),
            expected_authority_epoch.current.epoch,
            expected_authority_epoch.current.lineage_id.as_str()
        ))),
        AdmissionReservationLaunchPrerequisite::IdentityConflict {
            reservation,
            expected_work_item_id,
            expected_proposed_attempt_id,
        } => Err(KernelBuildError::Service(format!(
            "eliotd launch refused: admission reservation {} covers work item {} and proposed attempt {}, not {} and {}",
            reservation.reservation_id.as_str(),
            reservation.work_item_id.as_str(),
            reservation.proposed_attempt_id.as_str(),
            expected_work_item_id.as_str(),
            expected_proposed_attempt_id.as_str()
        ))),
    }
}

impl KernelComposition {
    /// Launches the approved `eliotd` through the existing Kernel process
    /// authority.  Store bootstrap must already be connected; the child is
    /// never spawned from a raw command or an ambient environment.
    ///
    /// Diagnostic wrapper (F-LOG-KERNEL-3, #901): exactly one terminal is
    /// emitted per failed launch; the admitted receipt versus the failure
    /// record stay distinct, and no launch material is logged.
    #[cfg(windows)]
    pub async fn launch_eliotd(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
        observe_daemon_launch("kernel.daemon.launch_requested", "attempt");
        match self.launch_eliotd_inner().await {
            Ok(receipt) => {
                observe_daemon_launch("kernel.daemon.launch_committed", "success");
                // Issue #1837: durable audit evidence for process lifecycle.
                self.audit_observe(AuditEventDraft::process_launch_committed(&receipt));
                Ok(receipt)
            }
            Err(error) => {
                observe_daemon_launch("kernel.daemon.launch_failed", "rejected");
                super::kernel_diagnostics::observe_terminal_error(daemon_launch_terminal_code(
                    &error,
                ));
                // Issue #1837: durable audit evidence for process lifecycle.
                self.audit_observe(AuditEventDraft::process_launch_failed(
                    daemon_launch_terminal_code(&error),
                    self.current_state_fence().as_ref(),
                ));
                // Issue #1844: a launch failure compiles its brief.
                self.observe_diagnostic_problem(DiagnosticTrigger::ModuleCrashOrRestartExhaustion);
                Err(error)
            }
        }
    }

    /// Refuses the `eliotd` process launch unless the ORS owner proves its
    /// admission reservation is currently `ACTIVE` under this launch's own
    /// authority (#1678 W5, REQ7, A5, A8).
    ///
    /// This calls the existing owner verifier
    /// [`verify_admission_reservation_launch_prerequisite`] — the single
    /// issuance point for the sealed `ActiveAdmissionReservation` typestate —
    /// and owns no decision of its own. Every non-`Active` disposition
    /// (missing, staged, released, expired, reconciling, stale fence, foreign
    /// owner, identity conflict) is a typed refusal naming the exact state, so
    /// a canonical admission without a matching reservation and a staged
    /// reservation without a matching canonical receipt both stay
    /// non-launchable.
    ///
    /// The reservation identity is DERIVED from the immutable launch binding
    /// (work item = the launch attempt identity, proposed attempt = the launch
    /// operation identity, revision = the descriptor digest), exactly as the
    /// native-worker contour derives it from its claim binding. No identity is
    /// minted here, so a launch can never point at a reservation it did not
    /// derive.
    #[cfg(windows)]
    fn verify_eliotd_launch_prerequisite(
        &self,
        launch: &EliotdLaunchDescriptor,
        launch_identity: &str,
        operation_id: &str,
    ) -> Result<ReceiptIdentity, KernelBuildError> {
        let authority_epoch = epoch_lineage_for(&launch.authority_epoch, None)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        // The launch's own State Fence is captured from the same
        // `FencingToken` the process admission below is built from and
        // validated with the owner's validator against the canonical
        // `EpochId`, so the fence/epoch comparison is between owner-validated
        // values rather than a recomputed digest.
        let generation = Generation::new(launch.generation.value())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let state_fence_token = FencingToken::new(
            launch.authority_epoch.clone(),
            generation,
            format!("eliotd-launch-fence-{launch_identity}"),
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let state_fence =
            StateFenceSnapshot::capture(&state_fence_token, launch.authority_epoch.sequence.get())
                .and_then(|snapshot| {
                    snapshot
                        .validate_against_epoch(&launch.authority_epoch)
                        .map(|()| snapshot)
                })
                .map_err(|error| {
                    KernelBuildError::Service(format!(
                        "eliotd admission reservation has no valid State Fence: {error}"
                    ))
                })?;
        // The complete claim set is projected from the Host-approved descriptor
        // the launch already validated. Each reference is the owner identity of
        let claims = eliotd_admission_reservation_claims(launch, operation_id)?;
        claims
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let identity_input = AdmissionReservationIdentityInput {
            work_item_id: OperationIdentity::new(launch_identity)
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
            proposed_attempt_id: OperationIdentity::new(operation_id)
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
            semantic_admission_revision: launch.descriptor_sha256.clone(),
            claims,
            state_fence: state_fence.clone(),
            authority_epoch: authority_epoch.clone(),
        };
        let reservation_id = admission_reservation_identity(&identity_input).map_err(|error| {
            KernelBuildError::Service(format!(
                "eliotd admission reservation identity cannot be derived from the launch descriptor: {error}"
            ))
        })?;
        // `OpaqueLabel` has no `Display`; its own accessor is the only honest way
        // to name it, and every refusal below names the reservation it refused
        // on.
        let reservation_label = reservation_id.as_str();
        let current = self
            .generation_gateway
            .ors
            .load_kernel_admission_reservation(&reservation_id)
            .map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd admission reservation {reservation_label} cannot be read back: {error}"
                ))
            })?;
        let prerequisite = verify_admission_reservation_launch_prerequisite(
            current.as_ref(),
            &identity_input.work_item_id,
            &identity_input.proposed_attempt_id,
            &authority_epoch,
            &state_fence,
            i64::try_from(unix_ms()).map_err(|error| {
                KernelBuildError::Service(format!(
                    "eliotd admission reservation verification time is not representable: {error}"
                ))
            })?,
        )
        .map_err(|error| {
            KernelBuildError::Service(format!(
                "eliotd admission reservation launch prerequisite for {reservation_label} is not verifiable: {error}"
            ))
        })?;
        eliotd_launch_prerequisite_outcome(prerequisite, reservation_label)
    }

    /// Admitted-launch sequence; every authority check precedes the single
    /// process start. See [`KernelComposition::launch_eliotd`].
    #[cfg(windows)]
    #[allow(
        clippy::too_many_lines,
        reason = "the launch admission sequence is intentionally contiguous so every authority check precedes the single process start"
    )]
    async fn launch_eliotd_inner(&self) -> Result<ProcessStartReceipt, KernelBuildError> {
        let launch = self
            .active_daemon_launch()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?
            .ok_or_else(|| {
                KernelBuildError::Service("eliotd launch descriptor is required".to_owned())
            })?;
        launch
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let gateway = self.process_gateway.as_ref().ok_or_else(|| {
            KernelBuildError::Service(
                "process authority is required before eliotd launch".to_owned(),
            )
        })?;
        {
            let state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            if state.receipt.is_some() {
                return Err(KernelBuildError::Service(
                    "eliotd launch was already admitted for this Kernel generation".to_owned(),
                ));
            }
        }
        let generation = Generation::new(launch.generation.value())
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let kernel_process = observe_named_pipe_peer_process(std::process::id())
            .map_err(|error| KernelBuildError::Principal(error.to_string()))?;
        let launch_identity = eliotd_launch_attempt_identity(
            &launch,
            kernel_process.process_id(),
            kernel_process.start_time_100ns(),
            kernel_process.image_path(),
        )?;
        let operation_id = eliotd_operation_id(generation, &launch_identity)?;
        // #1678 W5/REQ7/A5/A8: the launch prerequisite gate. This is the
        // FIRST check that can refuse an `eliotd` process start with no effect,
        // so it runs before the process intent/lease/owner are built, before
        // the path lease is retained, before the runtime state moves to
        // `Launching` and before `gateway.start`. A missing, staged, released,
        // expired, reconciling, stale-fence, foreign-owner or identity-
        // conflicting reservation refuses HERE, so no process, provider,
        // environment, credential or route effect can begin from it. The
        // returned owner activation receipt is the receipt this launch is
        // authorized under.
        let _activation_receipt = self.verify_eliotd_launch_prerequisite(
            &launch,
            &launch_identity,
            operation_id.as_str(),
        )?;
        let process_tree_id = ProcessTreeId::new(format!("eliotd-tree-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let job_id = JobId::new(format!("eliotd-job-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let image_id = ImageId::new(format!("eliotd-image-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let session_id = SessionId::new(format!("eliotd-session-{}", &launch_identity[..16]))
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let arguments = launch
            .arguments
            .iter()
            .map(|argument| argument.as_str().to_owned())
            .collect::<Vec<_>>();
        let intent = ProcessIntent::new(
            operation_id.clone(),
            process_tree_id,
            job_id,
            image_id,
            session_id,
            generation,
            launch.executable.as_str(),
            launch.executable_sha256.clone(),
            arguments,
            launch.working_directory.as_str(),
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
            ResourceLimits::new(86_400_000, None, None, 64 * 1024, 64 * 1024, 4)
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        // INTENDED EpochId shape (Split A/B cutover, B→A→C): FencingToken::new
        // takes EpochId, getter &EpochId, is_same_authority. Do not edit A/B
        // files to make this compile in isolation.
        let state_fence = FencingToken::new(
            launch.authority_epoch.clone(),
            generation,
            format!("eliotd-launch-fence-{launch_identity}"),
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let admission = ProcessExecutionAdmissionRequest::new(
            ACTIVE_DAEMON_CALLER,
            intent,
            ActionLeaseRef::new(format!("eliotd-kernel-launch-{launch_identity}"))
                .map_err(|error| KernelBuildError::Service(error.to_string()))?,
            state_fence,
            unix_ms().saturating_add(60_000),
        )
        .map_err(|error| KernelBuildError::Service(error.to_string()))?;
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
        let proof = Self::retain_eliotd_path_proof(&launch, &admission)?;
        // Issue #79: the service-owned launch joins the same typed session
        // validation the frame gateway enforces. The admitted caller session
        // carries the just-minted intent session under the daemon-generation
        // class (server-minted, never wire-supplied); any future mint skew
        // between intent, owner, and fence fails here instead of spawning an
        // unbound process.
        let caller_session = ProcessCallerSession::new(
            ProcessSessionClass::EliotdGeneration,
            owner.clone(),
            admission.intent().session_id().clone(),
        )
        .map_err(|error| {
            KernelBuildError::Service(format!("eliotd caller session binding failed: {error}"))
        })?;
        eliot_process::validate_process_intent_session(
            admission.intent(),
            &caller_session,
            &owner,
            admission.state_fence(),
        )
        .map_err(|error| {
            KernelBuildError::Service(format!("eliotd intent session binding failed: {error}"))
        })?;
        let (candidate, activation) = {
            let service = self
                .service
                .lock()
                .map_err(|_| KernelBuildError::Service("service lock poisoned".to_owned()))?;
            if service.generation_fenced()
                || !matches!(
                    service.state(),
                    super::KernelServiceState::Activating | super::KernelServiceState::Ready
                )
            {
                return Err(KernelBuildError::Service(
                    "eliotd launch has no current authenticated activation".to_owned(),
                ));
            }
            let candidate = service.candidate_binding().cloned().ok_or_else(|| {
                KernelBuildError::Service(
                    "eliotd launch has no current Host Kernel candidate binding".to_owned(),
                )
            })?;
            let activation = service.activation_receipt().cloned().ok_or_else(|| {
                KernelBuildError::Service(
                    "eliotd launch has no authenticated activation receipt".to_owned(),
                )
            })?;
            (candidate, activation)
        };
        candidate
            .validate()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let candidate_digest = candidate
            .compute_digest()
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        if activation.candidate_binding_digest != candidate_digest
            || activation.authority_epoch != launch.authority_epoch
            || activation.generation != launch.generation
            || candidate.kernel_epoch != launch.authority_epoch
            || admission.state_fence().authority_epoch() != &activation.authority_epoch
            || admission.state_fence().generation().get() != activation.generation.value()
        {
            return Err(KernelBuildError::Service(
                "eliotd launch candidate differs from its authenticated activation".to_owned(),
            ));
        }
        self.validate_candidate_process_binding(&candidate)
            .map_err(|error| KernelBuildError::Service(error.to_string()))?;
        let outer_binding = candidate;
        {
            let mut state = self.daemon_runtime.lock().map_err(|_| {
                KernelBuildError::Service("daemon runtime lock poisoned".to_owned())
            })?;
            if state.receipt.is_some() || state.status != DaemonRuntimeStatus::NotLaunched {
                return Err(KernelBuildError::Service(
                    "eliotd launch state changed before process resume".to_owned(),
                ));
            }
            state.status = DaemonRuntimeStatus::Launching;
            state.supervision = None;
            state.live_ready = None;
        }
        let receipt = match gateway.start(&owner, admission, proof, outer_binding).await {
            Ok(receipt) => receipt,
            Err(error) => {
                let reason = format!("eliotd process start failed: {error}");
                let unknown_outcome = matches!(&error, ProcessExecutionError::UnknownOutcome);
                let _ = self.record_daemon_failed(&reason, unknown_outcome);
                return Err(KernelBuildError::Service(error.to_string()));
            }
        };
        let mut state = self
            .daemon_runtime
            .lock()
            .map_err(|_| KernelBuildError::Service("daemon runtime lock poisoned".to_owned()))?;
        state.status = DaemonRuntimeStatus::Running;
        state.receipt = Some(receipt.clone());
        drop(state);
        self.note_agent_bridge_peer_set_change();
        Ok(receipt)
    }

    #[cfg(windows)]
    fn retain_eliotd_path_proof(
        launch: &EliotdLaunchDescriptor,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> Result<ProcessPathProof, KernelBuildError> {
        let executable = PathBuf::from(launch.executable.as_str());
        let working_directory = PathBuf::from(launch.working_directory.as_str());
        let daemon_platform =
            WindowsPlatform::new(working_directory.clone()).map_err(KernelBuildError::Platform)?;
        let lease = daemon_platform
            .retain_process_path_lease(
                &executable,
                &working_directory,
                admission.intent().executable_sha256(),
            )
            .map_err(KernelBuildError::Platform)?;
        Ok(ProcessPathProof {
            executable,
            working_directory,
            lease: Arc::new(lease),
        })
    }
}
