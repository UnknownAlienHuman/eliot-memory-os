//! Kernel-owned normal Notify launch grant (issue #1780, I11.6).
//!
//! Normal delivery launches the installed `eliot-notify.exe` through the
//! authorized User Broker on a Kernel-authorized grant. This module binds
//! that grant: it reads live Kernel admission (Ready state, unfenced
//! generation, current authority epoch and fence) and joins it to explicit
//! retained evidence — the canonical notification reference plus the
//! verified launch artifact (installed path and observed digest produced by
//! the installer-owned binding chain). Nothing is minted from configured
//! paths, loader locations, build outputs, or environment; stale epochs,
//! fences, malformed evidence, or a non-Ready/fenced service fail closed.
//!
//! The returned [`NotifyLaunchAuthorization`] is a Kernel-side value. The
//! central composition (Beauvoir lane) maps it onto the broker
//! `ApprovedLaunch` at the boundary; this module never constructs broker
//! wire types and never spawns a process. The fallback scheduler route is
//! a separate path and shares no logic here.

use eliot_contracts::{EpochId, ResourceGeneration, StateFence};
use eliot_receipts::SessionBinding;

use crate::{KernelService, KernelServiceError, KernelServiceState};

/// Operation-id prefix for Notify launch grants. The id is deterministic in
/// the notification digest (idempotent restaging), mirroring the
/// `hostreq:` convention for host requests.
pub const NOTIFY_GRANT_OPERATION_PREFIX: &str = "notify:";

/// Canonical installed image filename pinned by the installer-owned binding
/// chain (I11.6). Mirrors `eliot_notify::NOTIFY_IMAGE_FILE_NAME`, which this
/// Kernel-side module must not depend on (dependency direction); both pins
/// enforce the same canonical name and any divergence fails closed here.
pub const NOTIFY_IMAGE_FILE_NAME: &str = "eliot-notify.exe";

/// Explicit retained evidence for one normal Notify launch grant. The
/// notification reference comes from canonical notification state; the
/// artifact fields come from the verified installed binding; the session
/// comes from retained Kernel-issued session evidence. Every field is
/// caller-supplied and re-validated here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyGrantInputs {
    /// Canonical notification identity (non-empty, no controls).
    pub notification_id: String,
    /// Canonical notification envelope digest (lowercase SHA-256).
    pub notification_digest: String,
    /// Absolute installed image path.
    pub executable_path: String,
    /// Observed image digest (lowercase SHA-256).
    pub artifact_digest: String,
    /// Retained Kernel-issued session evidence, checked for currency
    /// against live admission below.
    pub session: SessionBinding,
}

/// Kernel-bound normal Notify launch authorization.
///
/// Carries the live authority epoch, state fence, and generation observed
/// at bind time plus the validated evidence. The central composition maps
/// these fields onto the broker grant; the mapping itself lives outside
/// this module.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyLaunchAuthorization {
    operation_id: String,
    session: SessionBinding,
    authority_epoch: EpochId,
    state_fence: StateFence,
    generation: ResourceGeneration,
    notification_id: String,
    notification_digest: String,
    executable_path: String,
    artifact_digest: String,
}

impl NotifyLaunchAuthorization {
    /// Deterministic operation identity (`notify:<envelope-digest>`).
    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.operation_id
    }

    /// Retained session evidence bound at grant time.
    #[must_use]
    pub const fn session(&self) -> &SessionBinding {
        &self.session
    }

    /// Live authority epoch observed at grant time.
    #[must_use]
    pub const fn authority_epoch(&self) -> &EpochId {
        &self.authority_epoch
    }

    /// Live state fence observed at grant time.
    #[must_use]
    pub const fn state_fence(&self) -> &StateFence {
        &self.state_fence
    }

    /// Live generation observed at grant time.
    #[must_use]
    pub const fn generation(&self) -> ResourceGeneration {
        self.generation
    }

    /// Canonical notification identity.
    #[must_use]
    pub fn notification_id(&self) -> &str {
        &self.notification_id
    }

    /// Canonical notification envelope digest.
    #[must_use]
    pub fn notification_digest(&self) -> &str {
        &self.notification_digest
    }

    /// Verified installed executable path.
    #[must_use]
    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    /// Observed image digest.
    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn validate_notify_grant_inputs(inputs: &NotifyGrantInputs) -> Result<(), KernelServiceError> {
    if inputs.notification_id.trim().is_empty()
        || inputs.notification_id.chars().any(char::is_control)
    {
        return Err(KernelServiceError::InvalidField {
            field: "notify.notification_id",
            reason: "must be non-empty and free of controls",
        });
    }
    if !valid_sha256(&inputs.notification_digest) {
        return Err(KernelServiceError::InvalidField {
            field: "notify.notification_digest",
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    let path = std::path::Path::new(inputs.executable_path.as_str());
    if !path.is_absolute() {
        return Err(KernelServiceError::InvalidField {
            field: "notify.executable_path",
            reason: "must be an absolute path",
        });
    }
    if path.file_name().and_then(|name| name.to_str()) != Some(NOTIFY_IMAGE_FILE_NAME) {
        return Err(KernelServiceError::InvalidField {
            field: "notify.executable_path",
            reason: "must name the canonical installed notify image",
        });
    }
    if !valid_sha256(&inputs.artifact_digest) {
        return Err(KernelServiceError::InvalidField {
            field: "notify.artifact_digest",
            reason: "must be a lowercase SHA-256 digest",
        });
    }
    Ok(())
}

/// Binds one normal Notify launch authorization against live Kernel
/// admission.
///
/// Reads Ready state, unfenced generation, and the current authority
/// epoch/fence from the live service; requires the retained session
/// evidence to match that exact epoch and fence; validates the
/// notification reference and the verified artifact fields. The returned
/// authorization carries observed (not caller-asserted) authority.
///
/// # Errors
///
/// Returns [`KernelServiceError::GenerationFenced`] when the generation is
/// fenced, [`KernelServiceError::AdmissionClosed`] when the service is not
/// `Ready`, [`KernelServiceError::ReadinessNotProven`] when no activation
/// lineage is retained, or [`KernelServiceError::InvalidField`] for stale
/// session authority or malformed evidence.
pub fn bind_notify_launch_grant(
    service: &KernelService,
    inputs: &NotifyGrantInputs,
) -> Result<NotifyLaunchAuthorization, KernelServiceError> {
    if service.generation_fenced() {
        return Err(KernelServiceError::GenerationFenced);
    }
    if service.state() != KernelServiceState::Ready {
        return Err(KernelServiceError::AdmissionClosed(service.state()));
    }
    let activation = service
        .activation_receipt()
        .ok_or(KernelServiceError::ReadinessNotProven)?;
    let authority_epoch = service.authority_epoch();
    let expected_fence = StateFence::new(authority_epoch.clone(), activation.generation);
    if !inputs
        .session
        .authority_epoch
        .is_same_authority(&authority_epoch)
        || inputs.session.state_fence != expected_fence
    {
        return Err(KernelServiceError::InvalidField {
            field: "notify.session-authority",
            reason: "stale-authority-epoch-or-fence",
        });
    }
    validate_notify_grant_inputs(inputs)?;
    Ok(NotifyLaunchAuthorization {
        operation_id: format!(
            "{NOTIFY_GRANT_OPERATION_PREFIX}{}",
            inputs.notification_digest
        ),
        session: inputs.session.clone(),
        authority_epoch,
        state_fence: expected_fence,
        generation: activation.generation,
        notification_id: inputs.notification_id.clone(),
        notification_digest: inputs.notification_digest.clone(),
        executable_path: inputs.executable_path.clone(),
        artifact_digest: inputs.artifact_digest.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    // Ready-service driver values mirror the proven shapes in
    // notification_state_tests (candidate/permit/receipt fixtures); only the
    // fields this grant reads (epoch, fence, generation) participate below.
    const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch() -> EpochId {
        EpochId::new(
            eliot_contracts::EpochLineageId::new(LINEAGE).expect("lineage"),
            std::num::NonZeroU64::new(4).expect("sequence"),
        )
        .expect("epoch")
    }

    fn test_generation() -> ResourceGeneration {
        ResourceGeneration::new(7).expect("generation")
    }

    fn live_session() -> SessionBinding {
        let epoch = test_epoch();
        SessionBinding {
            session_id: eliot_contracts::SessionId::new("session-notify-test").expect("session"),
            authority_epoch: epoch.clone(),
            state_fence: StateFence::new(epoch, test_generation()),
        }
    }

    fn test_epoch_stale() -> EpochId {
        EpochId::new(
            eliot_contracts::EpochLineageId::new(LINEAGE).expect("lineage"),
            std::num::NonZeroU64::new(9).expect("sequence"),
        )
        .expect("epoch")
    }

    fn valid_inputs() -> NotifyGrantInputs {
        NotifyGrantInputs {
            notification_id: "notification-disk-full".to_owned(),
            notification_digest: "ab".repeat(32),
            executable_path: "C:\\Eliot\\eliot-notify.exe".to_owned(),
            artifact_digest: "cd".repeat(32),
            session: live_session(),
        }
    }

    #[test]
    fn grant_inputs_reject_malformed_evidence() {
        let base = valid_inputs();
        assert!(validate_notify_grant_inputs(&base).is_ok());
        let mut empty_id = base.clone();
        empty_id.notification_id = "  ".to_owned();
        assert!(validate_notify_grant_inputs(&empty_id).is_err());
        let mut bad_digest = base.clone();
        bad_digest.notification_digest = "NOT-HEX".to_owned();
        assert!(validate_notify_grant_inputs(&bad_digest).is_err());
        let mut relative = base.clone();
        relative.executable_path = "eliot-notify.exe".to_owned();
        assert!(validate_notify_grant_inputs(&relative).is_err());
        let mut wrong_name = base.clone();
        wrong_name.executable_path = "C:\\Eliot\\eliot-evil.exe".to_owned();
        assert!(validate_notify_grant_inputs(&wrong_name).is_err());
    }

    #[test]
    fn bind_fails_closed_before_ready_admission() {
        let service = KernelService::new([7; 32], 2, 4).expect("cold test service");
        assert_ne!(service.state(), KernelServiceState::Ready);
        let error = bind_notify_launch_grant(&service, &valid_inputs())
            .expect_err("cold service must not grant");
        assert!(matches!(error, KernelServiceError::AdmissionClosed(_)));
    }

    // Ready-service driver: fixture values mirror the proven shapes in
    // notification_state_tests (candidate/permit/receipt chain); only the
    // epoch, fence, and generation participate in grant binding.
    fn ready_service() -> KernelService {
        use crate::{
            HostFileIdentity, HostJobBinding, HostJobIdentity, HostJobRoot,
            HostKernelCandidateBinding, HostProcessBinding, KernelActivationPermit,
            KernelControlCommand, KernelReadyReceipt, ProcessObservation, RestartBudget,
        };
        use eliot_contracts::AuthorityEpoch;
        use eliot_platform::KernelActivationNonce;
        use eliot_runtime_contracts::{
            HealthVector, RegisteredActivityWakePolicy, ServiceProcessState,
            SupervisionJournalEpoch, SupervisionLeaseIncarnationBinding,
            SupervisionObservationScope,
        };

        let incarnation = SupervisionLeaseIncarnationBinding {
            supervision_lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
            supervision_lease_id: String::new(),
            scope_ref_digest: String::new(),
            installation_id: "installation-1".to_owned(),
            host_epoch: SupervisionJournalEpoch {
                lineage_id: "host-lineage-1".to_owned(),
                sequence: 1,
            },
            activation_id: "activation-1".to_owned(),
            activation_generation: SupervisionJournalEpoch {
                lineage_id: "activation-lineage-1".to_owned(),
                sequence: 1,
            },
            kernel_generation: SupervisionJournalEpoch {
                lineage_id: "kernel-lineage-1".to_owned(),
                sequence: 1,
            },
            watchdog_epoch: SupervisionJournalEpoch {
                lineage_id: "watchdog-lineage-1".to_owned(),
                sequence: 1,
            },
            observation_scope: SupervisionObservationScope {
                targets: vec!["eliot-kernel".to_owned()],
                sensor_profile: "eliot-runtime-live-v3".to_owned(),
                claimed_coverage: vec!["process".to_owned(), "job".to_owned()],
                governance_axis: "runtime-live-v3".to_owned(),
            },
            wake_policy: RegisteredActivityWakePolicy::Disabled,
            predecessor: None,
        }
        .with_derived_ids()
        .expect("valid test incarnation");
        let handle =
            |value: &str| eliot_platform::PlatformHandle::new(value).expect("valid test handle");
        let candidate = HostKernelCandidateBinding {
            installation_id: handle("installation-1"),
            host_epoch: AuthorityEpoch::new(1).expect("non-zero test epoch"),
            kernel_epoch: test_epoch(),
            activation_id: handle("activation-1"),
            artifact_hash: handle("artifact-1"),
            config_hash: handle("config-1"),
            job_object_id: handle("Local\\Eliot-Host-Kernel-test"),
            pipe_identity: handle("\\\\.\\pipe\\eliot-kernel-test"),
            host_process: HostProcessBinding {
                process_id: 7,
                start_time_100ns: 9,
                image_path: "C:\\eliot\\host.exe".to_owned(),
            },
            job_binding: HostJobBinding {
                job: HostJobIdentity {
                    name: "Local\\Eliot-Host-Kernel-test".to_owned(),
                },
                root: HostJobRoot {
                    process: HostProcessBinding {
                        process_id: 42,
                        start_time_100ns: 10,
                        image_path: "C:\\eliot\\kernel.exe".to_owned(),
                    },
                    executable: HostFileIdentity {
                        volume_serial_number: 1,
                        file_index: 2,
                    },
                },
            },
            supervision_incarnation: incarnation,
            restart_budget: RestartBudget::new(1, 1).expect("valid test budget"),
            agent_bridge_admission: None,
            containment_action: None,
        };
        let permit = KernelActivationPermit {
            operation_id: handle("activation-operation-1"),
            candidate_binding_digest: candidate.compute_digest().expect("candidate digest"),
            prior_kernel_disposition_digest: "b".repeat(64),
            journal_transaction_id: handle("journal-transaction-1"),
            journal_sequence: 7,
            generation: test_generation(),
            authority_epoch: candidate.kernel_epoch.clone(),
            activation_nonce: KernelActivationNonce::new(handle(&"a".repeat(64)))
                .expect("valid test nonce"),
        };
        let mut service = KernelService::new([7; 32], 2, 4).expect("test service");
        service.reconcile(candidate.clone()).expect("reconcile");
        service.apply(KernelControlCommand::Shadow).expect("shadow");
        service
            .apply(KernelControlCommand::PrepareHandoff)
            .expect("handoff");
        let activation = service
            .activate_permit(&permit, test_generation(), "c".repeat(64))
            .expect("activation");
        service
            .publish_ready(KernelReadyReceipt {
                activation_id: candidate.activation_id.clone(),
                activation_operation_id: activation.operation_id.clone(),
                activation_nonce_digest: activation.activation_nonce_digest.clone(),
                process: ProcessObservation {
                    process_id: handle("pid:42:start:10"),
                    job_object_id: candidate.job_object_id.clone(),
                    state: ServiceProcessState::Ready,
                    health: HealthVector::healthy(),
                    evidence_refs: vec![handle("process-evidence")],
                },
                health: HealthVector::healthy(),
                evidence_refs: vec![handle("ready-evidence")],
            })
            .expect("ready");
        assert_eq!(service.state(), KernelServiceState::Ready);
        service
    }

    #[test]
    fn bind_grant_against_live_ready_admission() {
        let service = ready_service();
        // Session evidence tracks the exact live epoch and fence observed
        // above; hardcoding either value here would couple the test to
        // lifecycle internals instead of the bind contract.
        let epoch = service.authority_epoch();
        let fence = StateFence::new(epoch.clone(), test_generation());
        let mut inputs = valid_inputs();
        inputs.session = SessionBinding {
            session_id: eliot_contracts::SessionId::new("session-notify-test").expect("session"),
            authority_epoch: epoch.clone(),
            state_fence: fence,
        };
        let granted = bind_notify_launch_grant(&service, &inputs).expect("ready service grants");
        assert_eq!(
            granted.operation_id(),
            format!("notify:{}", "ab".repeat(32))
        );
        assert_eq!(granted.notification_id(), "notification-disk-full");
        assert_eq!(granted.artifact_digest(), "cd".repeat(32));
        assert_eq!(granted.executable_path(), "C:\\Eliot\\eliot-notify.exe");
        assert_eq!(granted.authority_epoch(), &epoch);
        assert_eq!(granted.generation(), test_generation());
        assert_eq!(granted.session().authority_epoch, epoch);
    }

    #[test]
    fn bind_rejects_stale_session_authority() {
        let service = ready_service();
        let epoch = service.authority_epoch();
        let mut inputs = valid_inputs();
        inputs.session = SessionBinding {
            session_id: eliot_contracts::SessionId::new("session-notify-test").expect("session"),
            authority_epoch: test_epoch_stale(),
            state_fence: StateFence::new(epoch, test_generation()),
        };
        let error =
            bind_notify_launch_grant(&service, &inputs).expect_err("stale session must not grant");
        assert!(matches!(
            error,
            KernelServiceError::InvalidField {
                field: "notify.session-authority",
                ..
            }
        ));
        let mut fenced = valid_inputs();
        let live_epoch = service.authority_epoch();
        fenced.session = SessionBinding {
            session_id: eliot_contracts::SessionId::new("session-notify-test").expect("session"),
            authority_epoch: live_epoch.clone(),
            state_fence: StateFence::new(
                live_epoch,
                ResourceGeneration::new(8).expect("generation"),
            ),
        };
        assert!(matches!(
            bind_notify_launch_grant(&service, &fenced),
            Err(KernelServiceError::InvalidField {
                field: "notify.session-authority",
                ..
            })
        ));
    }
}
