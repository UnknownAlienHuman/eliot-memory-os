#![forbid(unsafe_code)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::too_many_lines)]

use std::fmt;
#[cfg(not(windows))]
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use eliot_host_service::runtime_control::{
    HostKernelRestartReceipt, HostRuntimeControlOperation, HostRuntimeControlRequest,
    HostRuntimeControlResponse, HostStoreRecoveryReceipt, decode_runtime_control_response_frame,
    runtime_control_request_frame,
};
use eliot_host_state::{
    HostState, RedbJournalBackend, StoreRebindState, readonly_project_host_state,
    reconstruct_current_supervision_incarnation,
};
use eliot_platform::PlatformHandle;
use eliot_runtime_status::{RuntimeStatusReport, ServiceRegistrationState, collect_status};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const CANARY_SCHEMA: &str = "eliot.runtime.live-canary.v4";
pub const DEFAULT_DEADLINE_MS: u64 = 30_000;
pub const MAX_DEADLINE_MS: u64 = 120_000;
const MAX_EVIDENCE_BYTES: usize = 128 * 1024;
const MAX_STORE_ATTESTATION_FILE_BYTES: u64 = 512 * 1024 * 1024;
const JOURNAL_FILE_NAME: &str = "host-state-journal.redb";
const PULSE_FIVE_CLEANUP_GRACE_MS: u64 = 30_000;
pub const HOST_RUNTIME_CONTROL_PIPE: &str = r"\\.\pipe\eliot\host\runtime-control-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Pulse {
    One = 1,
    Two = 2,
    Three = 3,
    Four = 4,
    Five = 5,
}

impl TryFrom<u8> for Pulse {
    type Error = CanaryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            4 => Ok(Self::Four),
            5 => Ok(Self::Five),
            _ => Err(CanaryError::Invalid(format!(
                "pulse must be one of 1, 2, 3, 4, 5 (got {value})"
            ))),
        }
    }
}

impl Pulse {
    const fn number(self) -> u8 {
        self as u8
    }
}

#[derive(Debug, Error)]
pub enum CanaryError {
    #[error("invalid canary input: {0}")]
    Invalid(String),
    #[error("read-only runtime observation failed: {0}")]
    Observation(String),
    #[error("runtime-control protocol failed: {0}")]
    Protocol(String),
    #[error("evidence publication failed: {0}")]
    Evidence(String),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProcessSnapshot {
    pub process_id: u32,
    pub start_time_100ns: u64,
    pub image_path: String,
    pub job_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContourSnapshot {
    pub host_epoch_lineage: String,
    pub host_epoch_sequence: u64,
    pub host_epoch_parent_lineage: Option<String>,
    pub host_epoch_parent_sequence: Option<u64>,
    pub host_process_nonce_digest: String,
    pub activation_id: Option<String>,
    pub activation_generation: Option<String>,
    pub activation_state: Option<String>,
    pub sequence: u64,
    pub last_checksum: Option<String>,
    pub kernel: Option<ProcessSnapshot>,
    pub kernel_generation: Option<String>,
    pub kernel_generation_digest: Option<String>,
    pub kernel_activation_nonce_digest: Option<String>,
    pub kernel_state: Option<String>,
    pub store: Option<ProcessSnapshot>,
    pub store_generation: Option<String>,
    pub store_fence: Option<String>,
    pub store_request_digest: Option<String>,
    pub ready_receipt_digest: Option<String>,
    pub readiness_observation_digest: Option<String>,
    pub clean_marker_last_sequence: Option<u64>,
    pub clean_marker_last_checksum: Option<String>,
    pub integrity_gaps: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScmProcessSnapshot {
    pub process_id: u32,
    pub start_time_100ns: u64,
    pub image_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ScmRuntimeSnapshot {
    pub service_name: String,
    pub configuration_digest: String,
    pub state: String,
    pub runtime_identity_digest: Option<String>,
    pub process: Option<ScmProcessSnapshot>,
}

/// Retained, no-follow proof that the live Store bridge and materialized
/// configuration match the exact active installer approval.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PulseFiveStoreArtifactEvidence {
    pub approved_generation: String,
    pub candidate_manifest_digest: String,
    pub authority_generation: u64,
    pub approved_executable_path: String,
    pub observed_executable_path: String,
    pub approved_executable_digest: String,
    pub observed_executable_digest: String,
    pub executable_file_identity: eliot_platform_windows::FileIdentity,
    pub process: ProcessSnapshot,
    pub approved_config_path: String,
    pub observed_config_path: String,
    pub approved_config_digest: String,
    pub observed_config_digest: String,
    pub config_file_identity: eliot_platform_windows::FileIdentity,
    pub phase_b_receipt_digest: String,
    pub phase_b_host_epoch_lineage: String,
    pub phase_b_host_epoch_sequence: u64,
    pub phase_b_host_process_nonce_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PulseFiveScmEvidence {
    pub approved_generation: String,
    pub host_before: ScmRuntimeSnapshot,
    pub host_stopped: ScmRuntimeSnapshot,
    pub host_after: ScmRuntimeSnapshot,
    pub watchdog_before: ScmRuntimeSnapshot,
    pub watchdog_while_host_stopped: ScmRuntimeSnapshot,
    pub watchdog_after: ScmRuntimeSnapshot,
    pub stopped_runtime_status: String,
    pub stopped_runtime_status_digest: String,
    pub owner_release_digest: String,
    pub store_before: PulseFiveStoreArtifactEvidence,
    pub store_after: PulseFiveStoreArtifactEvidence,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DynamicSupervisionEvidence {
    /// Current dynamic identity, never a Phase-A/static scope identifier.
    pub lease_id: String,
    pub lease_scope_id: String,
    pub incarnation_digest: String,
    pub ors_record_id: String,
    pub ors_revision: u64,
    pub receipt_digest: String,
    pub verification_context_digest: String,
    pub publication_digest: String,
    pub observed_generation: String,
}

impl DynamicSupervisionEvidence {
    pub fn validate(&self) -> Result<(), CanaryError> {
        if self.lease_id.trim().is_empty()
            || self.lease_scope_id.trim().is_empty()
            || self.ors_record_id.trim().is_empty()
            || self.ors_revision == 0
            || !is_lower_hex(&self.incarnation_digest)
            || self.receipt_digest.len() != 64
            || !is_lower_hex(&self.receipt_digest)
            || !is_lower_hex(&self.verification_context_digest)
            || !is_lower_hex(&self.publication_digest)
            || self.observed_generation.trim().is_empty()
        {
            return Err(CanaryError::Invalid(
                "dynamic supervision evidence is not an exact current lease/receipt binding"
                    .to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PulseEvidence {
    pub schema: String,
    pub pulse: Pulse,
    pub outcome: String,
    pub host_state_root_digest: String,
    pub status_digest: String,
    pub journal_digest: String,
    pub status: String,
    pub before: Option<ContourSnapshot>,
    pub after: Option<ContourSnapshot>,
    pub stop_boundary: Option<ContourSnapshot>,
    pub pulse_five_scm: Option<PulseFiveScmEvidence>,
    pub request_digest: Option<String>,
    pub receipt_digest: Option<String>,
    pub dynamic_supervision: Option<DynamicSupervisionEvidence>,
    pub redaction: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockedPulse {
    pub pulse: Pulse,
    pub reason: String,
    pub seam: String,
    pub host_state_root_digest: String,
    pub status_digest: Option<String>,
    pub journal_digest: Option<String>,
    pub redaction: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FailedPulse {
    pub pulse: Pulse,
    pub reason: String,
    pub host_state_root_digest: String,
    pub status_digest: Option<String>,
    pub journal_digest: Option<String>,
    pub redaction: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "disposition", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PulseDisposition {
    Pass(Box<PulseEvidence>),
    Blocked(BlockedPulse),
    FailClosed(FailedPulse),
}

impl PulseDisposition {
    pub const fn is_pass(&self) -> bool {
        matches!(self, Self::Pass(_))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CanaryRun {
    pub schema: String,
    pub pulse: Pulse,
    pub disposition: PulseDisposition,
    pub evidence_path: String,
    pub evidence_digest: String,
}

#[derive(Clone, Debug)]
pub struct CanaryConfig {
    pub host_state_root: PathBuf,
    pub evidence_dir: PathBuf,
    pub pulse: Pulse,
    pub deadline: Duration,
    pub execute_faults: bool,
}

impl CanaryConfig {
    pub fn validate(&self) -> Result<(), CanaryError> {
        if !self.host_state_root.is_absolute() || !self.evidence_dir.is_absolute() {
            return Err(CanaryError::Invalid(
                "host-state-root and evidence-dir must be absolute".to_owned(),
            ));
        }
        let deadline_ms = self.deadline.as_millis();
        if deadline_ms == 0 || deadline_ms > u128::from(MAX_DEADLINE_MS) {
            return Err(CanaryError::Invalid(format!(
                "deadline must be between 1 and {MAX_DEADLINE_MS} ms"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct RuntimeObservation {
    report: RuntimeStatusReport,
    status_digest: String,
    journal_digest: String,
    contour: ContourSnapshot,
    dynamic_supervision: Option<DynamicSupervisionEvidence>,
}

struct PassEvidenceInput {
    pulse: Pulse,
    before: Option<ContourSnapshot>,
    after: Option<ContourSnapshot>,
    stop_boundary: Option<ContourSnapshot>,
    pulse_five_scm: Option<PulseFiveScmEvidence>,
    request_digest: Option<String>,
    receipt_digest: Option<String>,
    dynamic_supervision: Option<DynamicSupervisionEvidence>,
}

impl RuntimeObservation {
    fn root_digest(root: &Path) -> String {
        exact_path_identity_digest(root)
    }

    fn canonical_root_digest(&self) -> String {
        Self::root_digest(Path::new(&self.report.host_state_root))
    }

    fn pass_evidence(&self, input: PassEvidenceInput) -> Box<PulseEvidence> {
        Box::new(PulseEvidence {
            schema: CANARY_SCHEMA.to_owned(),
            pulse: input.pulse,
            outcome: "PASS".to_owned(),
            host_state_root_digest: self.canonical_root_digest(),
            status_digest: self.status_digest.clone(),
            journal_digest: self.journal_digest.clone(),
            status: self.report.status.clone(),
            before: input.before,
            after: input.after,
            stop_boundary: input.stop_boundary,
            pulse_five_scm: input.pulse_five_scm,
            request_digest: input.request_digest,
            receipt_digest: input.receipt_digest,
            dynamic_supervision: input.dynamic_supervision,
            redaction: "request payloads, nonces and raw secret material omitted".to_owned(),
        })
    }

    fn blocked(
        &self,
        pulse: Pulse,
        root: &Path,
        reason: impl Into<String>,
        seam: impl Into<String>,
    ) -> PulseDisposition {
        PulseDisposition::Blocked(BlockedPulse {
            pulse,
            reason: redact_message(&reason.into(), root),
            seam: seam.into(),
            host_state_root_digest: self.canonical_root_digest(),
            status_digest: Some(self.status_digest.clone()),
            journal_digest: Some(self.journal_digest.clone()),
            redaction: "request payloads, nonces and raw secret material omitted".to_owned(),
        })
    }

    fn fail(&self, pulse: Pulse, root: &Path, reason: impl Into<String>) -> PulseDisposition {
        PulseDisposition::FailClosed(FailedPulse {
            pulse,
            reason: redact_message(&reason.into(), root),
            host_state_root_digest: self.canonical_root_digest(),
            status_digest: Some(self.status_digest.clone()),
            journal_digest: Some(self.journal_digest.clone()),
            redaction: "request payloads, nonces and raw secret material omitted".to_owned(),
        })
    }
}

pub struct ProductionCanary {
    config: CanaryConfig,
}

impl ProductionCanary {
    pub fn new(config: CanaryConfig) -> Result<Self, CanaryError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub async fn run(&self) -> PulseDisposition {
        let pulse = self.config.pulse;
        let root = self.config.host_state_root.clone();
        let deadline = Instant::now() + self.config.deadline;
        let result = tokio::time::timeout(
            canary_outer_timeout(pulse, self.config.deadline),
            self.run_bounded(deadline),
        )
        .await;
        match result {
            Ok(disposition) => disposition,
            Err(_) => PulseDisposition::FailClosed(FailedPulse {
                pulse,
                reason: "bounded canary deadline exceeded; no completion claim is made".to_owned(),
                host_state_root_digest: RuntimeObservation::root_digest(&root),
                status_digest: None,
                journal_digest: None,
                redaction: "request payloads, nonces and raw secret material omitted".to_owned(),
            }),
        }
    }

    async fn run_bounded(&self, deadline: Instant) -> PulseDisposition {
        let pulse = self.config.pulse;
        let observation = match observe_runtime(&self.config.host_state_root, deadline) {
            Ok(value) => value,
            Err(error) => {
                return PulseDisposition::FailClosed(FailedPulse {
                    pulse,
                    reason: redact_message(&error.to_string(), &self.config.host_state_root),
                    host_state_root_digest: RuntimeObservation::root_digest(
                        &self.config.host_state_root,
                    ),
                    status_digest: None,
                    journal_digest: None,
                    redaction: "request payloads, nonces and raw secret material omitted"
                        .to_owned(),
                });
            }
        };

        match pulse {
            Pulse::One => self.run_pulse_one(&observation),
            Pulse::Two => self.run_pulse_two(&observation),
            Pulse::Three => self.run_pulse_three(observation, deadline).await,
            Pulse::Four => self.run_pulse_four(observation, deadline).await,
            Pulse::Five => self.run_pulse_five(observation, deadline).await,
        }
    }

    fn run_pulse_one(&self, observation: &RuntimeObservation) -> PulseDisposition {
        let report = &observation.report;
        let root = &self.config.host_state_root;
        if !report.components.installation_registry.is_healthy() {
            return observation.fail(
                Pulse::One,
                root,
                "installation registry is not Healthy; Pulse 1 is read-only and refuses an incomplete root",
            );
        }
        if !report.host_journal.state.is_healthy() {
            return observation.fail(
                Pulse::One,
                root,
                "Host journal is not Healthy; retained runtime root cannot be admitted",
            );
        }
        if !service_registration_is_exact(&report.services.host_service_registration)
            || !service_registration_is_exact(&report.services.watchdog_service_registration)
        {
            return observation.fail(
                Pulse::One,
                root,
                "Host/Watchdog SCM registration is not an exact Running handle-bound observation",
            );
        }
        PulseDisposition::Pass(observation.pass_evidence(PassEvidenceInput {
            pulse: Pulse::One,
            before: None,
            after: Some(observation.contour.clone()),
            stop_boundary: None,
            pulse_five_scm: None,
            request_digest: None,
            receipt_digest: None,
            dynamic_supervision: observation.dynamic_supervision.clone(),
        }))
    }

    fn run_pulse_two(&self, observation: &RuntimeObservation) -> PulseDisposition {
        if let Err(error) = validate_runtime_live_contour(&observation.report) {
            return observation.fail(Pulse::Two, &self.config.host_state_root, error);
        }
        let Some(dynamic) = observation.dynamic_supervision.clone() else {
            return observation.fail(
                Pulse::Two,
                &self.config.host_state_root,
                "current Active supervision evidence is missing or not equal to the retained Host journal",
            );
        };
        if let Err(error) = dynamic.validate() {
            return observation.fail(Pulse::Two, &self.config.host_state_root, error.to_string());
        }
        PulseDisposition::Pass(observation.pass_evidence(PassEvidenceInput {
            pulse: Pulse::Two,
            before: Some(observation.contour.clone()),
            after: Some(observation.contour.clone()),
            stop_boundary: None,
            pulse_five_scm: None,
            request_digest: None,
            receipt_digest: Some(dynamic.receipt_digest.clone()),
            dynamic_supervision: Some(dynamic),
        }))
    }

    async fn run_pulse_three(
        &self,
        before: RuntimeObservation,
        deadline: Instant,
    ) -> PulseDisposition {
        if let Some(blocked) = self.fault_gate(Pulse::Three, &before) {
            return blocked;
        }
        if let Some(blocked) =
            require_restart_baseline(Pulse::Three, &before, &self.config.host_state_root)
        {
            return blocked;
        }
        let host_server = match approved_host_server_expectation(
            &before.report.services.host_service_registration,
        ) {
            Ok(expectation) => expectation,
            Err(error) => {
                return before.blocked(
                    Pulse::Three,
                    &self.config.host_state_root,
                    error,
                    "exact SCM-observed EliotHost LocalService process binding",
                );
            }
        };
        let request = match new_request(HostRuntimeControlOperation::RestartKernel, Pulse::Three) {
            Ok(request) => request,
            Err(error) => {
                return before.fail(
                    Pulse::Three,
                    &self.config.host_state_root,
                    error.to_string(),
                );
            }
        };
        let control = match send_or_reconcile(request, false, deadline, &host_server).await {
            Ok(value) => value,
            Err(ControlError::NotSent(reason)) => {
                return before.blocked(
                    Pulse::Three,
                    &self.config.host_state_root,
                    reason,
                    "authenticated Host runtime-control request was not delivered; no raw kill/SCM fallback exists",
                );
            }
            Err(ControlError::Unknown(reason)) => {
                return before.fail(Pulse::Three, &self.config.host_state_root, reason);
            }
        };
        let after = match observe_runtime(&self.config.host_state_root, deadline) {
            Ok(value) => value,
            Err(error) => {
                return before.fail(
                    Pulse::Three,
                    &self.config.host_state_root,
                    format!("post-restart readback failed: {error}"),
                );
            }
        };
        if let Err(error) =
            validate_kernel_restart(&before.contour, &after.contour, &control.receipt)
        {
            return before.fail(Pulse::Three, &self.config.host_state_root, error);
        }
        if let Err(error) = validate_post_runtime(&before, &after, true) {
            return before.fail(Pulse::Three, &self.config.host_state_root, error);
        }
        PulseDisposition::Pass(after.pass_evidence(PassEvidenceInput {
            pulse: Pulse::Three,
            before: Some(before.contour),
            after: Some(after.contour.clone()),
            stop_boundary: None,
            pulse_five_scm: None,
            request_digest: Some(control.request_digest),
            receipt_digest: Some(control.receipt_digest),
            dynamic_supervision: after.dynamic_supervision.clone(),
        }))
    }

    async fn run_pulse_four(
        &self,
        before: RuntimeObservation,
        deadline: Instant,
    ) -> PulseDisposition {
        if let Some(blocked) = self.fault_gate(Pulse::Four, &before) {
            return blocked;
        }
        if let Some(blocked) =
            require_store_baseline(Pulse::Four, &before, &self.config.host_state_root)
        {
            return blocked;
        }
        let host_server = match approved_host_server_expectation(
            &before.report.services.host_service_registration,
        ) {
            Ok(expectation) => expectation,
            Err(error) => {
                return before.blocked(
                    Pulse::Four,
                    &self.config.host_state_root,
                    error,
                    "exact SCM-observed EliotHost LocalService process binding",
                );
            }
        };
        let request = match new_request(HostRuntimeControlOperation::RecoverStore, Pulse::Four) {
            Ok(request) => request,
            Err(error) => {
                return before.fail(Pulse::Four, &self.config.host_state_root, error.to_string());
            }
        };
        let control = match send_or_reconcile(request, true, deadline, &host_server).await {
            Ok(value) => value,
            Err(ControlError::NotSent(reason)) => {
                return before.blocked(
                    Pulse::Four,
                    &self.config.host_state_root,
                    reason,
                    "authenticated Host runtime-control request was not delivered; Pulse 4 never stops Host or uses SCM stop/start",
                );
            }
            Err(ControlError::Unknown(reason)) => {
                return before.fail(Pulse::Four, &self.config.host_state_root, reason);
            }
        };
        let after = match observe_runtime(&self.config.host_state_root, deadline) {
            Ok(value) => value,
            Err(error) => {
                return before.fail(
                    Pulse::Four,
                    &self.config.host_state_root,
                    format!("post-store-recovery readback failed: {error}"),
                );
            }
        };
        if let Err(error) =
            validate_store_recovery(&before.contour, &after.contour, &control.receipt)
        {
            return before.fail(Pulse::Four, &self.config.host_state_root, error);
        }
        if let Err(error) = validate_post_runtime(&before, &after, false) {
            return before.fail(Pulse::Four, &self.config.host_state_root, error);
        }
        if !service_registration_is_exact(&after.report.services.host_service_registration) {
            return before.fail(
                Pulse::Four,
                &self.config.host_state_root,
                "Host SCM registration is not Running after Store recovery; Host must never be stopped by Pulse 4",
            );
        }
        PulseDisposition::Pass(after.pass_evidence(PassEvidenceInput {
            pulse: Pulse::Four,
            before: Some(before.contour),
            after: Some(after.contour.clone()),
            stop_boundary: None,
            pulse_five_scm: None,
            request_digest: Some(control.request_digest),
            receipt_digest: Some(control.receipt_digest),
            dynamic_supervision: after.dynamic_supervision.clone(),
        }))
    }

    async fn run_pulse_five(
        &self,
        before: RuntimeObservation,
        deadline: Instant,
    ) -> PulseDisposition {
        if let Some(blocked) = self.fault_gate(Pulse::Five, &before) {
            return blocked;
        }
        if let Some(blocked) =
            require_pulse_five_baseline(Pulse::Five, &before, &self.config.host_state_root)
        {
            return blocked;
        }
        #[cfg(windows)]
        {
            match run_windows_pulse_five(&self.config.host_state_root, &before, deadline).await {
                Ok(result) => {
                    PulseDisposition::Pass(result.after.pass_evidence(PassEvidenceInput {
                        pulse: Pulse::Five,
                        before: Some(before.contour),
                        after: Some(result.after.contour.clone()),
                        stop_boundary: Some(result.stop_boundary),
                        pulse_five_scm: Some(result.scm_evidence.clone()),
                        request_digest: Some(result.request_digest),
                        receipt_digest: Some(result.receipt_digest),
                        dynamic_supervision: result.after.dynamic_supervision.clone(),
                    }))
                }
                Err(error) => before.fail(
                    Pulse::Five,
                    &self.config.host_state_root,
                    format!("Pulse 5 Host stop/start failed closed: {error}"),
                ),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = deadline;
            before.blocked(
                Pulse::Five,
                &self.config.host_state_root,
                "Pulse 5 requires the Windows exact-registration SCM adapter",
                "eliot-platform-windows::WindowsPlatform",
            )
        }
    }

    fn fault_gate(
        &self,
        pulse: Pulse,
        observation: &RuntimeObservation,
    ) -> Option<PulseDisposition> {
        if !self.config.execute_faults {
            return Some(observation.blocked(
                pulse,
                &self.config.host_state_root,
                "fault execution is disabled; add --execute-faults",
                "CLI mutation gate",
            ));
        }
        #[cfg(windows)]
        {
            match eliot_platform_windows::is_process_elevated() {
                Ok(true) => {}
                Ok(false) => {
                    return Some(observation.blocked(
                        pulse,
                        &self.config.host_state_root,
                        "the current token is not elevated; no runtime-control request was sent",
                        "eliot-platform-windows::is_process_elevated",
                    ));
                }
                Err(error) => {
                    return Some(observation.blocked(
                        pulse,
                        &self.config.host_state_root,
                        format!("elevation state is unknown: {error}"),
                        "eliot-platform-windows::is_process_elevated",
                    ));
                }
            }
            match eliot_platform_windows::is_process_builtin_administrator() {
                Ok(true) => {}
                Ok(false) => {
                    return Some(observation.blocked(
                        pulse,
                        &self.config.host_state_root,
                        "the current elevated token does not have enabled BUILTIN\\Administrators membership",
                        "eliot-platform-windows::is_process_builtin_administrator",
                    ));
                }
                Err(error) => {
                    return Some(observation.blocked(
                        pulse,
                        &self.config.host_state_root,
                        format!("BUILTIN\\Administrators membership is unknown: {error}"),
                        "eliot-platform-windows::is_process_builtin_administrator",
                    ));
                }
            }
        }
        #[cfg(not(windows))]
        {
            return Some(observation.blocked(
                pulse,
                &self.config.host_state_root,
                "fault execution requires the Windows authenticated named-pipe adapter",
                "eliot-ipc::NamedPipeTransport::connect_authenticated",
            ));
        }
        None
    }
}

fn canary_outer_timeout(pulse: Pulse, operational_deadline: Duration) -> Duration {
    if pulse == Pulse::Five {
        operational_deadline
            .checked_add(Duration::from_millis(PULSE_FIVE_CLEANUP_GRACE_MS))
            .unwrap_or(Duration::MAX)
    } else {
        operational_deadline
    }
}

fn service_registration_is_exact(
    registration: &eliot_runtime_status::ServiceRegistrationState,
) -> bool {
    registration.registration == "Matching"
        && registration.state == "Running"
        && registration
            .observed_runtime
            .as_ref()
            .is_some_and(|runtime| {
                runtime.process_id != 0
                    && runtime.start_time_100ns != 0
                    && Path::new(&runtime.image_path).is_absolute()
                    && is_lower_hex(&runtime.runtime_identity_digest)
            })
}

fn validate_host_server_contour(
    registration: &ServiceRegistrationState,
    observed: &eliot_platform_windows::ProcessIdentity,
    expected_sid: &str,
    expected_session_id: u32,
) -> Result<(), String> {
    if expected_sid != eliot_installation::LOCAL_SERVICE_SID || expected_session_id != 0 {
        return Err("EliotHost pipe server must be exact LocalService session 0".to_owned());
    }
    if !service_registration_is_exact(registration) {
        return Err("EliotHost SCM registration/runtime contour is not exact Running".to_owned());
    }
    let runtime = registration
        .observed_runtime
        .as_ref()
        .ok_or_else(|| "EliotHost SCM runtime identity is missing".to_owned())?;
    if observed.process_id != runtime.process_id
        || observed.start_time_100ns != runtime.start_time_100ns
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&observed.image_path),
            Path::new(&runtime.image_path),
        )
    {
        return Err(
            "SCM-selected EliotHost PID/start/image differs from status registration readback"
                .to_owned(),
        );
    }
    Ok(())
}

fn approved_host_server_expectation(
    registration: &ServiceRegistrationState,
) -> Result<eliot_platform_windows::NamedPipePeerExpectation, String> {
    let binding = eliot_platform_windows::observe_running_eliot_host_process()
        .map_err(|error| format!("SCM EliotHost process observation failed: {error}"))?;
    validate_host_server_contour(
        registration,
        binding.identity(),
        eliot_installation::LOCAL_SERVICE_SID,
        0,
    )?;
    let expectation = eliot_platform_windows::NamedPipePeerExpectation::new_with_process_binding(
        eliot_installation::LOCAL_SERVICE_SID,
        0,
        binding,
    )
    .map_err(|error| format!("EliotHost LocalService process expectation failed: {error}"))?;
    if expectation.expected_sid() != eliot_installation::LOCAL_SERVICE_SID
        || expectation.expected_session_id() != 0
        || expectation.requires_builtin_administrators()
        || expectation.approved_process_binding().is_none()
    {
        return Err("EliotHost server expectation lost its exact LocalService binding".to_owned());
    }
    Ok(expectation)
}

fn require_restart_baseline(
    pulse: Pulse,
    observation: &RuntimeObservation,
    root: &Path,
) -> Option<PulseDisposition> {
    let c = &observation.contour;
    if c.kernel.is_none()
        || c.store.is_none()
        || c.ready_receipt_digest.is_none()
        || c.readiness_observation_digest.is_none()
        || !c.integrity_gaps.is_empty()
        || observation.dynamic_supervision.is_none()
    {
        return Some(observation.blocked(
            pulse,
            root,
            "Kernel restart requires exact current Kernel/Store process identities and a fresh ProbeReady receipt in the retained journal",
            "eliot-runtime-status + eliot-host-state read-only contour",
        ));
    }
    if observation.report.status != "RUNTIME_LIVE" {
        return Some(observation.blocked(
            pulse,
            root,
            format!(
                "Kernel restart requires RUNTIME_LIVE baseline, observed {}",
                observation.report.status
            ),
            "eliot-runtime-status::RuntimeStatusReport",
        ));
    }
    None
}

fn require_store_baseline(
    pulse: Pulse,
    observation: &RuntimeObservation,
    root: &Path,
) -> Option<PulseDisposition> {
    let c = &observation.contour;
    if c.kernel.is_none()
        || c.store.is_none()
        || c.store_fence.is_none()
        || c.ready_receipt_digest.is_none()
        || c.readiness_observation_digest.is_none()
        || !c.integrity_gaps.is_empty()
        || observation.dynamic_supervision.is_none()
    {
        return Some(observation.blocked(
            pulse,
            root,
            "Store recovery requires exact current Kernel/Store Job/process identities, committed StoreRebind and a fresh ProbeReady receipt",
            "eliot-runtime-status + eliot-host-state read-only StoreRebind contour",
        ));
    }
    if observation.report.status != "RUNTIME_LIVE" {
        return Some(observation.blocked(
            pulse,
            root,
            format!(
                "Store recovery requires RUNTIME_LIVE baseline, observed {}",
                observation.report.status
            ),
            "eliot-runtime-status::RuntimeStatusReport",
        ));
    }
    None
}

fn require_pulse_five_baseline(
    pulse: Pulse,
    observation: &RuntimeObservation,
    root: &Path,
) -> Option<PulseDisposition> {
    if let Err(error) = validate_runtime_live_contour(&observation.report) {
        return Some(observation.blocked(
            pulse,
            root,
            format!("Host restart requires an exact RUNTIME_LIVE baseline: {error}"),
            "eliot-runtime-status full runtime contour",
        ));
    }
    let contour = &observation.contour;
    if contour.activation_state.as_deref() != Some("Active")
        || contour.kernel_state.as_deref() != Some("Active")
        || contour.kernel.is_none()
        || contour.store.is_none()
        || contour.store_generation.is_none()
        || contour.store_fence.is_none()
        || contour.store_request_digest.is_none()
        || contour.kernel_activation_nonce_digest.is_none()
        || contour.ready_receipt_digest.is_none()
        || contour.readiness_observation_digest.is_none()
        || !contour.integrity_gaps.is_empty()
        || observation.dynamic_supervision.is_none()
    {
        return Some(observation.blocked(
            pulse,
            root,
            "Host restart requires exact Active Host/Kernel/Store, consumed activation nonce, fresh readiness and dynamic supervision evidence",
            "eliot-host-state retained active contour",
        ));
    }
    None
}

fn validate_post_runtime(
    before: &RuntimeObservation,
    after: &RuntimeObservation,
    require_new_lease_id: bool,
) -> Result<(), String> {
    validate_runtime_live_contour(&after.report)
        .map_err(|error| format!("post-operation {error}"))?;
    let before_supervision = before
        .dynamic_supervision
        .as_ref()
        .ok_or("baseline has no verified current dynamic supervision evidence")?;
    let after_supervision = after
        .dynamic_supervision
        .as_ref()
        .ok_or("post-operation status has no verified current dynamic supervision evidence")?;
    before_supervision
        .validate()
        .map_err(|error| error.to_string())?;
    after_supervision
        .validate()
        .map_err(|error| error.to_string())?;
    if require_new_lease_id && before_supervision.lease_id == after_supervision.lease_id {
        return Err("Kernel restart reused the predecessor supervision lease identity".to_owned());
    }
    Ok(())
}

fn validate_runtime_live_contour(report: &RuntimeStatusReport) -> Result<(), String> {
    let components = &report.components;
    let services = &report.services;
    if report.status != "RUNTIME_LIVE"
        || report.deadline_exceeded
        || !components.installation_registry.is_healthy()
        || !components.host_journal.is_healthy()
        || !components.ors_supervision.is_healthy()
        || !components.kernel.is_healthy()
        || !components.store.is_healthy()
        || !components.eliotd.is_healthy()
        || !components.watchdog.is_healthy()
        || !report.host_journal.state.is_healthy()
        || !report.ors.state.is_healthy()
        || !services.kernel.is_healthy()
        || !services.store.is_healthy()
        || !services.eliotd.is_healthy()
        || !services.watchdog.is_healthy()
        || !service_registration_is_exact(&services.host_service_registration)
        || !service_registration_is_exact(&services.watchdog_service_registration)
    {
        return Err(
            "runtime is not the exact full RUNTIME_LIVE component and Host/Watchdog registration contour"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct PulseFiveStoreApproval {
    approved_generation: String,
    candidate_manifest_digest: String,
    authority_generation: u64,
    executable_path: PathBuf,
    executable_digest: PlatformHandle,
    working_directory: PathBuf,
    config_path: PathBuf,
    config_digest: PlatformHandle,
    phase_b_receipt_digest: PlatformHandle,
    phase_b_host_epoch_lineage: String,
    phase_b_host_epoch_sequence: u64,
    phase_b_host_process_nonce_digest: String,
    profile_anchor_root: PathBuf,
}

#[cfg(windows)]
struct PulseFiveAuthority {
    platform: eliot_platform_windows::WindowsPlatform,
    store_platform: eliot_platform_windows::WindowsPlatform,
    host_request: eliot_platform_windows::ServiceRegistrationRequest,
    watchdog_request: eliot_platform_windows::ServiceRegistrationRequest,
    installation_id: PlatformHandle,
    approved_generation: String,
    store_approval: PulseFiveStoreApproval,
    _host_root_lease: eliot_platform_windows::ProtectedRootLease,
}

#[cfg(windows)]
struct PulseFiveResult {
    after: RuntimeObservation,
    stop_boundary: ContourSnapshot,
    scm_evidence: PulseFiveScmEvidence,
    request_digest: String,
    receipt_digest: String,
}

#[cfg(windows)]
#[derive(Default)]
struct PulseFiveMutationLedger {
    stop_calls: u8,
    start_calls: u8,
    stopped_readback_proven: bool,
    stopped_clean_proven: bool,
    owner_released_proven: bool,
}

#[cfg(windows)]
impl PulseFiveMutationLedger {
    fn stop_once<T>(&mut self, effect: impl FnOnce() -> T) -> Result<T, String> {
        if self.stop_calls != 0 || self.start_calls != 0 {
            return Err("Pulse 5 permits exactly one ordered Host stop call".to_owned());
        }
        self.stop_calls = 1;
        Ok(effect())
    }

    fn record_stopped_clean(&mut self) -> Result<(), String> {
        if self.stop_calls != 1
            || self.start_calls != 0
            || !self.stopped_readback_proven
            || self.stopped_clean_proven
        {
            return Err("StoppedClean proof is out of order or duplicated".to_owned());
        }
        self.stopped_clean_proven = true;
        Ok(())
    }

    fn record_stopped_readback(&mut self) -> Result<(), String> {
        if self.stop_calls != 1 || self.start_calls != 0 || self.stopped_readback_proven {
            return Err("definitive Stopped readback is out of order or duplicated".to_owned());
        }
        self.stopped_readback_proven = true;
        Ok(())
    }

    fn record_owner_released(&mut self) -> Result<(), String> {
        if !self.stopped_clean_proven || self.start_calls != 0 || self.owner_released_proven {
            return Err("owner release must follow the sole StoppedClean proof".to_owned());
        }
        self.owner_released_proven = true;
        Ok(())
    }

    fn start_once<T>(
        &mut self,
        cleanup_after_proof_error: bool,
        effect: impl FnOnce() -> T,
    ) -> Result<T, String> {
        if self.stop_calls != 1
            || self.start_calls != 0
            || !self.stopped_readback_proven
            || (!cleanup_after_proof_error
                && (!self.stopped_clean_proven || !self.owner_released_proven))
        {
            return Err(
                "Pulse 5 permits one Host start only after definitive Stopped readback; PASS also requires StoppedClean and owner release"
                    .to_owned()
            );
        }
        self.start_calls = 1;
        Ok(effect())
    }

    fn validate_complete(&self) -> Result<(), String> {
        if self.stop_calls == 1
            && self.start_calls == 1
            && self.stopped_readback_proven
            && self.stopped_clean_proven
            && self.owner_released_proven
        {
            Ok(())
        } else {
            Err("Pulse 5 did not execute exactly one Host stop and one Host start".to_owned())
        }
    }
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
enum PulseFiveStartAttempt {
    Started,
    AlreadyRunning,
    AlreadyStarting,
    EffectUnknown,
    Failed(String),
}

#[cfg(windows)]
impl PulseFiveStartAttempt {
    const fn is_owned_start(&self) -> bool {
        matches!(self, Self::Started)
    }

    fn description(&self) -> &str {
        match self {
            Self::Started => "Started",
            Self::AlreadyRunning => "AlreadyRunning",
            Self::AlreadyStarting => "AlreadyStarting",
            Self::EffectUnknown => "EffectUnknown",
            Self::Failed(error) => error,
        }
    }
}

#[cfg(windows)]
fn resolve_post_stop_reconcile<T, O>(
    stopped_proof: Result<T, String>,
    start_attempt: &PulseFiveStartAttempt,
    host_after: Result<O, String>,
) -> Result<(T, O), String> {
    let proof = match stopped_proof {
        Ok(proof) => proof,
        Err(proof_error) => {
            let cleanup = match host_after {
                Ok(_) => "exact EliotHost registration reconciled to Running".to_owned(),
                Err(error) => format!("EliotHost Running cleanup failed: {error}"),
            };
            return Err(format!(
                "{proof_error}; post-Stop cleanup outcome {}: {cleanup}; start was not resent",
                start_attempt.description()
            ));
        }
    };
    if !start_attempt.is_owned_start() {
        let reconciliation = match host_after {
            Ok(_) => "exact EliotHost registration reconciled to Running".to_owned(),
            Err(error) => format!("EliotHost Running reconciliation failed: {error}"),
        };
        return Err(format!(
            "Pulse 5 did not own the exact Host start ({}); {reconciliation}; start was not resent",
            start_attempt.description()
        ));
    }
    host_after.map(|host| (proof, host))
}

#[cfg(windows)]
fn inspect_pulse_five_registry(
    root: &Path,
) -> Result<(PathBuf, eliot_installation::ApprovedGenerationRegistry), String> {
    use eliot_installation::RedbInstallationRegistry;
    use eliot_platform_windows::ProtectedRootLease;

    let registry_root = ProtectedRootLease::open_existing(root)
        .map_err(|error| format!("retain Host root for installer registry: {error}"))?;
    let canonical = registry_root
        .canonical_path()
        .map_err(|error| format!("resolve retained Host root: {error}"))?;
    registry_root
        .verify_stable_identity()
        .map_err(|error| format!("verify retained Host root: {error}"))?;
    if !eliot_platform_windows::windows_paths_equal(root, &canonical) {
        return Err("caller Host root differs from the retained OS identity".to_owned());
    }
    let registry = RedbInstallationRegistry::inspect_existing_at(registry_root)
        .map_err(|error| format!("inspect retained installation registry: {error}"))?
        .ok_or_else(|| "retained installation registry is absent".to_owned())?;
    registry
        .validate()
        .map_err(|error| format!("validate retained installation registry: {error}"))?;
    Ok((canonical, registry))
}

#[cfg(windows)]
fn pulse_five_store_approval(
    registry: &eliot_installation::ApprovedGenerationRegistry,
    contour: &ContourSnapshot,
) -> Result<PulseFiveStoreApproval, String> {
    use eliot_installation::InstallationProfile;

    let active = registry
        .active()
        .ok_or_else(|| "installation registry has no exact active generation".to_owned())?;
    let manifest = &active.manifest;
    manifest
        .validate()
        .map_err(|error| format!("validate active candidate manifest: {error}"))?;
    if manifest.runtime_launch.profile != InstallationProfile::SystemService {
        return Err("Pulse 5 SCM recovery requires the active SystemService profile".to_owned());
    }
    let manifest_digest = manifest
        .compute_digest()
        .map_err(|error| format!("digest active candidate manifest: {error}"))?;
    let committed = registry
        .last_committed_activation_fence()
        .ok_or_else(|| "active generation has no committed activation fence".to_owned())?;
    if committed.generation != manifest.generation
        || committed.config_digest != manifest.config_digest
        || committed.authority_generation != manifest.runtime_launch.authority_generation
    {
        return Err("active manifest and committed activation authority disagree".to_owned());
    }
    let (
        config_digest,
        phase_b_receipt_digest,
        phase_b_host_epoch_lineage,
        phase_b_host_epoch_sequence,
        phase_b_host_process_nonce_digest,
    ) = if let Some(rebind) = registry.active_phase_b_rebind() {
        rebind
            .validate()
            .map_err(|error| format!("validate current active Phase-B rebind: {error}"))?;
        let receipt = rebind
            .receipt
            .as_ref()
            .ok_or_else(|| "active Phase-B rebind lacks its exact no-follow receipt".to_owned())?;
        if receipt.manifest_digest != manifest_digest {
            return Err("active Phase-B rebind names a foreign manifest".to_owned());
        }
        (
            receipt.config_file_digest.clone(),
            receipt.receipt_digest.clone(),
            receipt.host_epoch_lineage.as_str().to_owned(),
            receipt.host_epoch_sequence,
            receipt.host_process_nonce_digest.as_str().to_owned(),
        )
    } else {
        let binding = committed.phase_b_live_binding.as_ref().ok_or_else(|| {
            "committed activation lacks its exact Phase-B live binding".to_owned()
        })?;
        if binding.manifest_digest != manifest_digest
            || binding.config_file_digest != committed.materialized_config_digest
        {
            return Err("committed Phase-B config binding is inconsistent".to_owned());
        }
        (
            binding.config_file_digest.clone(),
            binding.receipt_digest.clone(),
            binding.host_epoch_lineage.as_str().to_owned(),
            binding.host_epoch_sequence,
            binding.host_process_nonce_digest.as_str().to_owned(),
        )
    };
    if phase_b_host_epoch_lineage != contour.host_epoch_lineage
        || phase_b_host_epoch_sequence != contour.host_epoch_sequence
        || phase_b_host_process_nonce_digest != contour.host_process_nonce_digest
    {
        return Err(
            "current Phase-B config receipt is not bound to the observed Host epoch/nonce"
                .to_owned(),
        );
    }
    let authority_generation = manifest.runtime_launch.authority_generation.value();
    let store_generation = contour
        .store_generation
        .as_deref()
        .ok_or_else(|| "current StoreRebind generation is absent".to_owned())?
        .parse::<u64>()
        .map_err(|_| "current StoreRebind generation is not an integer".to_owned())?;
    if store_generation != authority_generation {
        return Err(
            "current StoreRebind generation differs from the active manifest authority generation"
                .to_owned(),
        );
    }
    let (_, executable_digest) = manifest
        .host_child_artifact_digests()
        .map_err(|error| format!("read approved Store bridge digest: {error}"))?;
    let (_, executable_path, config_path) = manifest.host_child_paths();
    Ok(PulseFiveStoreApproval {
        approved_generation: manifest.generation.as_str().to_owned(),
        candidate_manifest_digest: manifest_digest.as_str().to_owned(),
        authority_generation,
        executable_path: PathBuf::from(executable_path.as_str()),
        executable_digest: executable_digest.clone(),
        working_directory: PathBuf::from(
            manifest
                .runtime_launch
                .runtime_state_roots
                .store_work_root
                .as_str(),
        ),
        config_path: PathBuf::from(config_path.as_str()),
        config_digest,
        phase_b_receipt_digest,
        phase_b_host_epoch_lineage,
        phase_b_host_epoch_sequence,
        phase_b_host_process_nonce_digest,
        profile_anchor_root: PathBuf::from(
            manifest
                .runtime_launch
                .runtime_state_roots
                .profile_anchor_root
                .as_str(),
        ),
    })
}

#[cfg(windows)]
fn load_pulse_five_authority(
    root: &Path,
    before: &RuntimeObservation,
) -> Result<PulseFiveAuthority, String> {
    use eliot_installation::InstallerServiceRole;
    use eliot_platform_windows::ProtectedRootLease;

    let (canonical, registry) = inspect_pulse_five_registry(root)?;
    let active = registry
        .active()
        .ok_or_else(|| "installation registry has no exact active generation".to_owned())?;
    let generation = active.manifest.generation.clone();
    let committed = registry
        .last_committed_activation_fence()
        .ok_or_else(|| "active generation has no committed activation fence".to_owned())?;
    if committed.generation != generation
        || committed.config_digest != active.manifest.config_digest
        || active.manifest.runtime_launch.generation != generation
    {
        return Err(
            "active manifest, committed activation fence and runtime launch generation disagree"
                .to_owned(),
        );
    }
    let manifest_root = Path::new(
        active
            .manifest
            .runtime_launch
            .runtime_state_roots
            .host_state_root
            .as_str(),
    );
    if !eliot_platform_windows::windows_paths_equal(&canonical, manifest_root) {
        return Err(
            "caller Host root is not the active manifest-derived host_state_root".to_owned(),
        );
    }
    let (journal_state, journal_contour, journal_digest) =
        inspect_journal_contour(&canonical).map_err(|error| error.to_string())?;
    if journal_digest != before.journal_digest
        || journal_contour != before.contour
        || journal_state.host.installation
            != active
                .manifest
                .runtime_launch
                .installation_epoch
                .installation
    {
        return Err(
            "Host journal changed or names a different installation while SCM authority was loaded"
                .to_owned(),
        );
    }
    let store_approval = pulse_five_store_approval(&registry, &before.contour)?;
    let host_request = registry
        .service_registration_approval(&generation, InstallerServiceRole::Host)
        .ok_or_else(|| "active generation has no installer-owned EliotHost approval".to_owned())?
        .service_registration_request()
        .map_err(|error| format!("reconstruct approved EliotHost request: {error}"))?;
    let watchdog_request = registry
        .service_registration_approval(&generation, InstallerServiceRole::Watchdog)
        .ok_or_else(|| {
            "active generation has no installer-owned EliotWatchdog approval".to_owned()
        })?
        .service_registration_request()
        .map_err(|error| format!("reconstruct approved EliotWatchdog request: {error}"))?;
    let retained = ProtectedRootLease::open_existing(&canonical)
        .map_err(|error| format!("retain Host root for Pulse 5 lifetime: {error}"))?;
    retained
        .verify_stable_identity()
        .map_err(|error| format!("verify Pulse 5 Host root lifetime lease: {error}"))?;
    let platform = eliot_platform_windows::WindowsPlatform::new(canonical)
        .map_err(|error| format!("bind Windows adapter to retained Host root: {error}"))?;
    let store_platform =
        eliot_platform_windows::WindowsPlatform::new(store_approval.profile_anchor_root.clone())
            .map_err(|error| {
                format!("bind Windows adapter to retained Store profile root: {error}")
            })?;
    Ok(PulseFiveAuthority {
        platform,
        store_platform,
        host_request,
        watchdog_request,
        installation_id: journal_state.host.installation,
        approved_generation: generation.as_str().to_owned(),
        store_approval,
        _host_root_lease: retained,
    })
}

#[cfg(windows)]
fn validate_pulse_five_store_artifact_evidence(
    evidence: &PulseFiveStoreArtifactEvidence,
    contour: &ContourSnapshot,
) -> Result<(), String> {
    let store = contour
        .store
        .as_ref()
        .ok_or_else(|| "Store artifact evidence has no journaled process/Job contour".to_owned())?;
    let generation = contour
        .store_generation
        .as_deref()
        .ok_or_else(|| "Store artifact evidence has no journaled authority generation".to_owned())?
        .parse::<u64>()
        .map_err(|_| "journaled Store authority generation is not an integer".to_owned())?;
    if evidence.approved_generation.trim().is_empty()
        || !is_lower_hex(&evidence.candidate_manifest_digest)
        || evidence.authority_generation == 0
        || generation != evidence.authority_generation
        || !Path::new(&evidence.approved_executable_path).is_absolute()
        || !Path::new(&evidence.observed_executable_path).is_absolute()
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&evidence.approved_executable_path),
            Path::new(&evidence.observed_executable_path),
        )
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&evidence.observed_executable_path),
            Path::new(&evidence.process.image_path),
        )
        || evidence.approved_executable_digest != evidence.observed_executable_digest
        || !is_lower_hex(&evidence.approved_executable_digest)
        || !Path::new(&evidence.approved_config_path).is_absolute()
        || !Path::new(&evidence.observed_config_path).is_absolute()
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&evidence.approved_config_path),
            Path::new(&evidence.observed_config_path),
        )
        || evidence.approved_config_digest != evidence.observed_config_digest
        || !is_lower_hex(&evidence.approved_config_digest)
        || !is_lower_hex(&evidence.phase_b_receipt_digest)
        || evidence.phase_b_host_epoch_lineage != contour.host_epoch_lineage
        || evidence.phase_b_host_epoch_sequence != contour.host_epoch_sequence
        || evidence.phase_b_host_process_nonce_digest != contour.host_process_nonce_digest
        || &evidence.process != store
    {
        return Err(
            "Store artifact/config evidence is not the exact active manifest, Phase-B and journal contour"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn validate_pulse_five_store_artifact_transition(
    before: &PulseFiveStoreArtifactEvidence,
    after: &PulseFiveStoreArtifactEvidence,
) -> Result<(), String> {
    if before.approved_generation != after.approved_generation
        || before.candidate_manifest_digest != after.candidate_manifest_digest
        || before.authority_generation != after.authority_generation
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&before.approved_executable_path),
            Path::new(&after.approved_executable_path),
        )
        || before.approved_executable_digest != after.approved_executable_digest
        || before.executable_file_identity != after.executable_file_identity
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&before.approved_config_path),
            Path::new(&after.approved_config_path),
        )
        || before.approved_config_digest == after.approved_config_digest
        || before.config_file_identity == after.config_file_identity
        || before.phase_b_receipt_digest == after.phase_b_receipt_digest
    {
        return Err(
            "post-start Store artifact/config proof changed immutable approval, replaced the retained executable, or reused the prior config/Phase-B receipt"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn observed_protected_file_digest(
    lease: &eliot_platform_windows::ProtectedPathLease,
    expected: &PlatformHandle,
    label: &str,
) -> Result<String, String> {
    if !is_lower_hex(expected.as_str()) {
        return Err(format!("{label} approval digest is not exact SHA-256"));
    }
    lease
        .verify_stable_identity()
        .and_then(|()| lease.verify_path_identity())
        .map_err(|error| format!("verify retained {label} identity: {error}"))?;
    let bytes = lease
        .read_bounded(MAX_STORE_ATTESTATION_FILE_BYTES)
        .map_err(|error| format!("read retained {label} bytes: {error}"))?;
    let observed = digest_bytes(&bytes);
    if observed != expected.as_str() {
        return Err(format!(
            "retained {label} bytes differ from active installer approval"
        ));
    }
    Ok(observed)
}

#[cfg(windows)]
fn attest_pulse_five_store_artifacts(
    executable_lease: &eliot_platform_windows::RetainedProcessPathLease,
    approval: &PulseFiveStoreApproval,
    contour: &ContourSnapshot,
) -> Result<PulseFiveStoreArtifactEvidence, String> {
    use eliot_platform_windows::{ProtectedPathLease, observe_named_pipe_peer_process_in_job};

    let store = contour
        .store
        .as_ref()
        .ok_or_else(|| "journaled Store process/Job contour is absent".to_owned())?;
    let process = executable_lease
        .validate_process_identity(
            store.process_id,
            &approval.executable_path,
            &approval.working_directory,
            approval.executable_digest.as_str(),
        )
        .map_err(|error| format!("verify retained Store executable/process identity: {error}"))?;
    let job = observe_named_pipe_peer_process_in_job(&store.job_name, store.process_id)
        .map_err(|error| format!("verify live Store Job membership: {error}"))?;
    if job.process_binding().identity() != &process
        || job.job_name() != store.job_name
        || process.process_id != store.process_id
        || process.start_time_100ns != store.start_time_100ns
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&process.image_path),
            Path::new(&store.image_path),
        )
    {
        return Err("live Store process/Job differs from the journaled contour".to_owned());
    }

    let executable_file_lease =
        ProtectedPathLease::open_existing_absolute(&approval.executable_path)
            .map_err(|error| format!("retain approved Store executable bytes: {error}"))?;
    let executable_canonical = executable_file_lease
        .canonical_path()
        .map_err(|error| format!("resolve retained Store executable: {error}"))?;
    if !eliot_platform_windows::windows_paths_equal(
        &approval.executable_path,
        &executable_canonical,
    ) || executable_file_lease.identity() != executable_lease.executable_identity()
    {
        return Err("retained Store executable path/object identity was substituted".to_owned());
    }
    let observed_executable_digest = observed_protected_file_digest(
        &executable_file_lease,
        &approval.executable_digest,
        "Store executable",
    )?;

    let config_lease = ProtectedPathLease::open_existing_absolute(&approval.config_path)
        .map_err(|error| format!("retain materialized Store config: {error}"))?;
    let config_canonical = config_lease
        .canonical_path()
        .map_err(|error| format!("resolve retained Store config: {error}"))?;
    if !eliot_platform_windows::windows_paths_equal(&approval.config_path, &config_canonical) {
        return Err("materialized Store config differs from the approved path".to_owned());
    }
    let observed_config_digest = observed_protected_file_digest(
        &config_lease,
        &approval.config_digest,
        "materialized Store config",
    )?;
    let approved_executable_path = approval
        .executable_path
        .to_str()
        .ok_or_else(|| "approved Store executable path is not Unicode".to_owned())?
        .to_owned();
    let approved_config_path = approval
        .config_path
        .to_str()
        .ok_or_else(|| "approved Store config path is not Unicode".to_owned())?
        .to_owned();
    let observed_config_path = config_canonical
        .to_str()
        .ok_or_else(|| "retained Store config path is not Unicode".to_owned())?
        .to_owned();
    let evidence = PulseFiveStoreArtifactEvidence {
        approved_generation: approval.approved_generation.clone(),
        candidate_manifest_digest: approval.candidate_manifest_digest.clone(),
        authority_generation: approval.authority_generation,
        approved_executable_path,
        observed_executable_path: process.image_path.clone(),
        approved_executable_digest: approval.executable_digest.as_str().to_owned(),
        observed_executable_digest,
        executable_file_identity: executable_lease.executable_identity(),
        process: ProcessSnapshot {
            process_id: process.process_id,
            start_time_100ns: process.start_time_100ns,
            image_path: process.image_path,
            job_name: job.job_name().to_owned(),
        },
        approved_config_path,
        observed_config_path,
        approved_config_digest: approval.config_digest.as_str().to_owned(),
        observed_config_digest,
        config_file_identity: config_lease.identity(),
        phase_b_receipt_digest: approval.phase_b_receipt_digest.as_str().to_owned(),
        phase_b_host_epoch_lineage: approval.phase_b_host_epoch_lineage.clone(),
        phase_b_host_epoch_sequence: approval.phase_b_host_epoch_sequence,
        phase_b_host_process_nonce_digest: approval.phase_b_host_process_nonce_digest.clone(),
    };
    validate_pulse_five_store_artifact_evidence(&evidence, contour)?;
    Ok(evidence)
}

#[cfg(windows)]
fn scm_state_name(observation: &eliot_platform_windows::ServiceRuntimeObservation) -> String {
    if observation.is_running() {
        "Running"
    } else if observation.is_starting() {
        "Starting"
    } else if observation.is_stopping() {
        "Stopping"
    } else if observation.is_stopped() {
        "Stopped"
    } else {
        "Unknown"
    }
    .to_owned()
}

#[cfg(windows)]
fn scm_snapshot(
    observation: &eliot_platform_windows::ServiceRuntimeObservation,
) -> ScmRuntimeSnapshot {
    ScmRuntimeSnapshot {
        service_name: observation.service_name().to_owned(),
        configuration_digest: observation.configuration_digest().to_owned(),
        state: scm_state_name(observation),
        runtime_identity_digest: observation.runtime_identity_digest(),
        process: observation.process().map(|process| ScmProcessSnapshot {
            process_id: process.process_id,
            start_time_100ns: process.start_time_100ns,
            image_path: process.image_path.clone(),
        }),
    }
}

#[cfg(windows)]
fn inspect_exact_scm(
    authority: &PulseFiveAuthority,
    request: &eliot_platform_windows::ServiceRegistrationRequest,
    role: &str,
) -> Result<eliot_platform_windows::ServiceRuntimeObservation, String> {
    match authority
        .platform
        .inspect_service_registration_runtime(request)
    {
        eliot_platform_windows::ServiceRegistrationRuntimeInspection::Matching { observation }
            if observation.configuration_digest() == request.expected_configuration_digest() =>
        {
            Ok(observation)
        }
        eliot_platform_windows::ServiceRegistrationRuntimeInspection::Matching { .. } => Err(
            format!("{role} SCM configuration digest differs from installer approval"),
        ),
        eliot_platform_windows::ServiceRegistrationRuntimeInspection::Absent => {
            Err(format!("{role} SCM registration is absent"))
        }
        eliot_platform_windows::ServiceRegistrationRuntimeInspection::Mismatched => {
            Err(format!("{role} SCM registration is substituted"))
        }
        eliot_platform_windows::ServiceRegistrationRuntimeInspection::Unknown => Err(format!(
            "{role} SCM registration/runtime readback is Unknown"
        )),
    }
}

#[cfg(windows)]
fn require_running_scm(
    authority: &PulseFiveAuthority,
    request: &eliot_platform_windows::ServiceRegistrationRequest,
    role: &str,
) -> Result<eliot_platform_windows::ServiceRuntimeObservation, String> {
    let observation = inspect_exact_scm(authority, request, role)?;
    if !observation.is_running()
        || observation.process().is_none()
        || observation.runtime_identity_digest().is_none()
    {
        return Err(format!(
            "{role} is not exact Running PID/start/image/config evidence"
        ));
    }
    Ok(observation)
}

#[cfg(windows)]
fn require_same_watchdog(
    before: &eliot_platform_windows::ServiceRuntimeObservation,
    observed: &eliot_platform_windows::ServiceRuntimeObservation,
) -> Result<(), String> {
    if !observed.is_running()
        || before.configuration_digest() != observed.configuration_digest()
        || before.runtime_identity_digest() != observed.runtime_identity_digest()
        || before.process() != observed.process()
    {
        return Err(
            "EliotWatchdog sibling did not retain the exact Running PID/start/image/config identity"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn validate_status_registration_against_scm(
    registration: &ServiceRegistrationState,
    observation: &eliot_platform_windows::ServiceRuntimeObservation,
    role: &str,
) -> Result<(), String> {
    let expected = observation
        .process()
        .ok_or_else(|| format!("{role} SCM process identity is absent"))?;
    let projected = registration
        .observed_runtime
        .as_ref()
        .ok_or_else(|| format!("{role} runtime-status process identity is absent"))?;
    if registration.registration != "Matching"
        || registration.state != "Running"
        || projected.process_id != expected.process_id
        || projected.start_time_100ns != expected.start_time_100ns
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&projected.image_path),
            Path::new(&expected.image_path),
        )
        || observation.runtime_identity_digest().as_deref()
            != Some(projected.runtime_identity_digest.as_str())
    {
        return Err(format!(
            "{role} runtime-status projection differs from exact SCM readback"
        ));
    }
    Ok(())
}

#[cfg(windows)]
async fn wait_for_host_state(
    authority: &PulseFiveAuthority,
    want_running: bool,
    watchdog_before: &eliot_platform_windows::ServiceRuntimeObservation,
    deadline: Instant,
) -> Result<eliot_platform_windows::ServiceRuntimeObservation, String> {
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "deadline exceeded while waiting for EliotHost {}",
                if want_running { "Running" } else { "Stopped" }
            ));
        }
        let watchdog =
            require_running_scm(authority, &authority.watchdog_request, "EliotWatchdog")?;
        require_same_watchdog(watchdog_before, &watchdog)?;
        let host = inspect_exact_scm(authority, &authority.host_request, "EliotHost")?;
        if (want_running && host.is_running()) || (!want_running && host.is_stopped()) {
            if want_running
                && (host.process().is_none() || host.runtime_identity_digest().is_none())
            {
                return Err("Running EliotHost lacks exact runtime identity".to_owned());
            }
            if !want_running && host.process().is_some() {
                return Err("Stopped EliotHost still exposes a live process identity".to_owned());
            }
            return Ok(host);
        }
        let expected_transition = if want_running {
            host.is_starting()
        } else {
            host.is_stopping()
        };
        if !expected_transition {
            return Err(format!(
                "EliotHost entered unexpected SCM state {} during {}",
                scm_state_name(&host),
                if want_running { "start" } else { "stop" }
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait =
            Duration::from_millis(u64::from(host.wait_hint_ms()).clamp(50, 500)).min(remaining);
        tokio::time::sleep(wait).await;
    }
}

#[cfg(windows)]
async fn reconcile_host_running_after_start(
    authority: &PulseFiveAuthority,
    deadline: Instant,
) -> Result<eliot_platform_windows::ServiceRuntimeObservation, String> {
    loop {
        if Instant::now() >= deadline {
            return Err("deadline exceeded while reconciling EliotHost Running cleanup".to_owned());
        }
        let host = inspect_exact_scm(authority, &authority.host_request, "EliotHost")?;
        if host.is_running() {
            if host.process().is_none() || host.runtime_identity_digest().is_none() {
                return Err("Running EliotHost lacks exact runtime identity".to_owned());
            }
            return Ok(host);
        }
        if !host.is_starting() {
            return Err(format!(
                "EliotHost entered unexpected SCM state {} during Running cleanup",
                scm_state_name(&host)
            ));
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let wait =
            Duration::from_millis(u64::from(host.wait_hint_ms()).clamp(50, 500)).min(remaining);
        tokio::time::sleep(wait).await;
    }
}

#[cfg(windows)]
fn validate_stopped_boundary(
    before: &ContourSnapshot,
    state: &HostState,
    stopped: &ContourSnapshot,
) -> Result<(), String> {
    validate_stopped_contour(before, stopped)?;
    let activation = state
        .activation
        .as_ref()
        .ok_or_else(|| "stopped Host journal has no activation record".to_owned())?;
    let marker = state
        .clean_marker
        .as_ref()
        .ok_or_else(|| "stopped Host journal has no CleanMarker".to_owned())?;
    if activation.state != eliot_host_state::ActivationState::StoppedClean {
        return Err("Host did not durably reach StoppedClean before SCM start".to_owned());
    }
    if marker.manifest.last_sequence <= before.sequence
        || marker.manifest.last_sequence.checked_add(1) != Some(state.sequence)
        || stopped.clean_marker_last_sequence != Some(marker.manifest.last_sequence)
        || stopped.clean_marker_last_checksum.as_deref()
            != Some(marker.manifest.last_checksum.as_str())
    {
        return Err(
            "CleanMarker is not the final verified journal record covering the pre-stop sequence"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
fn validate_stopped_contour(
    before: &ContourSnapshot,
    stopped: &ContourSnapshot,
) -> Result<(), String> {
    if stopped.activation_state.as_deref() != Some("StoppedClean")
        || stopped.clean_marker_last_sequence.is_none()
        || stopped.clean_marker_last_checksum.is_none()
        || stopped
            .clean_marker_last_sequence
            .is_some_and(|sequence| sequence <= before.sequence)
        || stopped
            .clean_marker_last_sequence
            .and_then(|sequence| sequence.checked_add(1))
            != Some(stopped.sequence)
    {
        return Err(
            "stopped contour lacks a final CleanMarker covering the pre-stop journal".to_owned(),
        );
    }
    if stopped.host_epoch_lineage != before.host_epoch_lineage
        || stopped.host_epoch_sequence != before.host_epoch_sequence
        || stopped.host_process_nonce_digest != before.host_process_nonce_digest
        || stopped.activation_id != before.activation_id
        || stopped.activation_generation != before.activation_generation
    {
        return Err("Host stop changed the active epoch/activation identity in place".to_owned());
    }
    Ok(())
}

#[cfg(windows)]
fn prove_owner_released(installation: &PlatformHandle) -> Result<String, String> {
    let mut lease = eliot_platform_windows::HostOwnerLease::acquire(installation)
        .map_err(|error| format!("HostOwnerLease was not cleanly released: {error}"))?;
    if !lease.is_for_installation(installation) {
        return Err("owner-lease probe selected a foreign installation".to_owned());
    }
    let name = lease.name().to_owned();
    lease
        .release()
        .map_err(|error| format!("owner-lease probe release became Unknown: {error}"))?;
    Ok(digest_bytes(
        format!("eliot.pulse5.owner-released.v1:{name}").as_bytes(),
    ))
}

#[cfg(windows)]
fn validate_fresh_pulse_five_contour(
    before: &RuntimeObservation,
    stopped: &ContourSnapshot,
    after: &RuntimeObservation,
    scm: &PulseFiveScmEvidence,
) -> Result<(), String> {
    validate_runtime_live_contour(&before.report)?;
    validate_runtime_live_contour(&after.report)?;
    let old = &before.contour;
    let new = &after.contour;
    if scm.store_before.approved_generation != scm.approved_generation
        || scm.store_after.approved_generation != scm.approved_generation
    {
        return Err("Store artifact evidence names a foreign active generation".to_owned());
    }
    validate_pulse_five_store_artifact_evidence(&scm.store_before, old)?;
    validate_pulse_five_store_artifact_evidence(&scm.store_after, new)?;
    validate_pulse_five_store_artifact_transition(&scm.store_before, &scm.store_after)?;
    if before.report.active_generation.as_deref() != Some(scm.approved_generation.as_str())
        || after.report.active_generation != before.report.active_generation
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&before.report.host_state_root),
            Path::new(&after.report.host_state_root),
        )
    {
        return Err(
            "post-start Store status is not bound to the same approved generation/config/root"
                .to_owned(),
        );
    }
    if new.host_epoch_lineage != old.host_epoch_lineage
        || old.host_epoch_sequence.checked_add(1) != Some(new.host_epoch_sequence)
        || new.host_epoch_parent_lineage.as_deref() != Some(old.host_epoch_lineage.as_str())
        || new.host_epoch_parent_sequence != Some(old.host_epoch_sequence)
    {
        return Err("restarted Host epoch is not the exact direct child".to_owned());
    }
    if new.host_process_nonce_digest == old.host_process_nonce_digest
        || new.activation_id == old.activation_id
        || new.activation_generation == old.activation_generation
        || new.kernel_generation_digest == old.kernel_generation_digest
        || new.kernel_activation_nonce_digest == old.kernel_activation_nonce_digest
        || new.ready_receipt_digest == old.ready_receipt_digest
        || new.readiness_observation_digest == old.readiness_observation_digest
    {
        return Err(
            "Host restart reused a predecessor Host/activation/Kernel/readiness identity"
                .to_owned(),
        );
    }
    if new.activation_state.as_deref() != Some("Active")
        || new.kernel_state.as_deref() != Some("Active")
        || !new.integrity_gaps.is_empty()
        || stopped.activation_state.as_deref() != Some("StoppedClean")
    {
        return Err(
            "post-start Host/Kernel contour is not exact Active after StoppedClean".to_owned(),
        );
    }
    let old_store = old
        .store
        .as_ref()
        .ok_or_else(|| "baseline Store process/Job evidence is absent".to_owned())?;
    let new_store = new
        .store
        .as_ref()
        .ok_or_else(|| "post-start Store process/Job evidence is absent".to_owned())?;
    if (new_store.process_id, new_store.start_time_100ns)
        == (old_store.process_id, old_store.start_time_100ns)
        || new_store.job_name == old_store.job_name
    {
        return Err("post-start Store reused the predecessor process or Job authority".to_owned());
    }
    if !eliot_platform_windows::windows_paths_equal(
        Path::new(&old_store.image_path),
        Path::new(&new_store.image_path),
    ) {
        return Err("post-start Store changed the approved executable path".to_owned());
    }
    if new.store_fence.as_ref().is_none_or(|fence| {
        old.store_fence
            .as_ref()
            .is_some_and(|old_fence| old_fence == fence)
    }) || new.store_request_digest.as_ref().is_none_or(|request| {
        old.store_request_digest
            .as_ref()
            .is_some_and(|old_request| old_request == request)
    }) {
        return Err(
            "post-start Store did not preserve the approved static generation with a causally fresh fence/request"
                .to_owned(),
        );
    }
    let old_supervision = before
        .dynamic_supervision
        .as_ref()
        .ok_or_else(|| "baseline dynamic supervision is absent".to_owned())?;
    let new_supervision = after
        .dynamic_supervision
        .as_ref()
        .ok_or_else(|| "post-start dynamic supervision is absent".to_owned())?;
    if old_supervision.lease_id == new_supervision.lease_id
        || old_supervision.receipt_digest == new_supervision.receipt_digest
        || old_supervision.publication_digest == new_supervision.publication_digest
    {
        return Err(
            "post-start eliotd/ORS supervision reused predecessor lease/receipt/publication"
                .to_owned(),
        );
    }
    validate_pulse_five_scm_evidence(scm)
}

#[cfg(windows)]
fn validate_pulse_five_scm_evidence(scm: &PulseFiveScmEvidence) -> Result<(), String> {
    let before_host = scm
        .host_before
        .process
        .as_ref()
        .ok_or_else(|| "pre-stop Host process evidence is absent".to_owned())?;
    let after_host = scm
        .host_after
        .process
        .as_ref()
        .ok_or_else(|| "post-start Host process evidence is absent".to_owned())?;
    if scm.approved_generation.trim().is_empty()
        || scm.host_before.service_name != eliot_platform_windows::ELIOT_HOST_SERVICE_NAME
        || scm.host_stopped.service_name != eliot_platform_windows::ELIOT_HOST_SERVICE_NAME
        || scm.host_after.service_name != eliot_platform_windows::ELIOT_HOST_SERVICE_NAME
        || scm.host_before.configuration_digest != scm.host_stopped.configuration_digest
        || scm.host_before.configuration_digest != scm.host_after.configuration_digest
        || scm.host_before.runtime_identity_digest.is_none()
        || scm.host_after.runtime_identity_digest.is_none()
        || scm.host_before.runtime_identity_digest == scm.host_after.runtime_identity_digest
        || scm.host_stopped.runtime_identity_digest.is_some()
        || scm.host_before.state != "Running"
        || scm.host_stopped.state != "Stopped"
        || scm.host_stopped.process.is_some()
        || scm.host_after.state != "Running"
        || (before_host.process_id == after_host.process_id
            && before_host.start_time_100ns == after_host.start_time_100ns)
        || !eliot_platform_windows::windows_paths_equal(
            Path::new(&before_host.image_path),
            Path::new(&after_host.image_path),
        )
    {
        return Err(
            "Host SCM stop/start did not produce a fresh exact process identity".to_owned(),
        );
    }
    if scm.watchdog_before.service_name != eliot_platform_windows::ELIOT_WATCHDOG_SERVICE_NAME
        || scm.watchdog_before.state != "Running"
        || scm.watchdog_before != scm.watchdog_while_host_stopped
        || scm.watchdog_before != scm.watchdog_after
    {
        return Err("Watchdog sibling identity changed across Host stop/start".to_owned());
    }
    if scm.stopped_runtime_status == "RUNTIME_LIVE"
        || !is_lower_hex(&scm.stopped_runtime_status_digest)
        || !is_lower_hex(&scm.owner_release_digest)
    {
        return Err(
            "stopped Host boundary retained stale Healthy or incomplete evidence".to_owned(),
        );
    }
    Ok(())
}

#[cfg(windows)]
async fn wait_for_runtime_live(
    root: &Path,
    deadline: Instant,
) -> Result<RuntimeObservation, String> {
    let mut last = "runtime has not yet been observed".to_owned();
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "deadline exceeded before fresh full RUNTIME_LIVE: {last}"
            ));
        }
        match observe_runtime(root, deadline) {
            Ok(observation) => match validate_runtime_live_contour(&observation.report) {
                Ok(()) if observation.dynamic_supervision.is_some() => return Ok(observation),
                Ok(()) => {
                    last.clear();
                    last.push_str("dynamic supervision evidence is absent");
                }
                Err(error) => last = error,
            },
            Err(error) => last = error.to_string(),
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        tokio::time::sleep(Duration::from_millis(250).min(remaining)).await;
    }
}

#[cfg(windows)]
async fn run_windows_pulse_five(
    root: &Path,
    before: &RuntimeObservation,
    deadline: Instant,
) -> Result<PulseFiveResult, String> {
    let authority = load_pulse_five_authority(root, before)?;
    let fresh_before = observe_runtime(root, deadline).map_err(|error| error.to_string())?;
    if fresh_before.status_digest != before.status_digest
        || fresh_before.journal_digest != before.journal_digest
        || fresh_before.contour != before.contour
        || fresh_before.dynamic_supervision != before.dynamic_supervision
    {
        return Err("runtime changed after baseline and before the Host stop boundary".to_owned());
    }
    let store_executable_lease = authority
        .store_platform
        .retain_process_path_lease(
            &authority.store_approval.executable_path,
            &authority.store_approval.working_directory,
            authority.store_approval.executable_digest.as_str(),
        )
        .map_err(|error| format!("retain approved Store executable contour: {error}"))?;
    let store_before = attest_pulse_five_store_artifacts(
        &store_executable_lease,
        &authority.store_approval,
        &before.contour,
    )?;
    let host_before = require_running_scm(&authority, &authority.host_request, "EliotHost")?;
    let watchdog_before =
        require_running_scm(&authority, &authority.watchdog_request, "EliotWatchdog")?;
    validate_status_registration_against_scm(
        &before.report.services.host_service_registration,
        &host_before,
        "EliotHost",
    )?;
    validate_status_registration_against_scm(
        &before.report.services.watchdog_service_registration,
        &watchdog_before,
        "EliotWatchdog",
    )?;
    let host_runtime_digest = host_before
        .runtime_identity_digest()
        .ok_or_else(|| "pre-stop Host runtime identity digest is absent".to_owned())?;
    let stop_request = authority
        .host_request
        .clone()
        .with_expected_runtime_identity_digest(host_runtime_digest)
        .map_err(|error| format!("bind exact pre-stop Host identity: {error}"))?;
    let mut mutations = PulseFiveMutationLedger::default();
    match mutations
        .stop_once(|| authority.platform.stop_service_registration(&stop_request))?
        .map_err(|error| format!("Host stop failed before classification: {error}"))?
    {
        eliot_platform_windows::ServiceStopOutcome::Stopped { .. } => {}
        eliot_platform_windows::ServiceStopOutcome::AlreadyStopped { .. } => {
            return Err("Host was already Stopped; Pulse 5 did not own a stop".to_owned());
        }
        eliot_platform_windows::ServiceStopOutcome::AlreadyStopping { .. } => {
            return Err("Host was already Stopping; Pulse 5 did not own a stop".to_owned());
        }
        eliot_platform_windows::ServiceStopOutcome::EffectUnknown => {
            return Err("Host stop outcome is Unknown; no stop or start is resent".to_owned());
        }
    }
    let host_stopped = wait_for_host_state(&authority, false, &watchdog_before, deadline).await?;
    mutations.record_stopped_readback()?;
    let stopped_proof = (|| {
        let watchdog_stopped =
            require_running_scm(&authority, &authority.watchdog_request, "EliotWatchdog")?;
        require_same_watchdog(&watchdog_before, &watchdog_stopped)?;
        let (stopped_state, stop_boundary, _) =
            inspect_journal_contour(root).map_err(|error| error.to_string())?;
        validate_stopped_boundary(&before.contour, &stopped_state, &stop_boundary)?;
        mutations.record_stopped_clean()?;
        let stopped_status = collect_status(root, deadline)
            .map_err(|error| format!("read stopped runtime status: {error}"))?;
        if !root_matches_report(root, &stopped_status)
            || stopped_status.status == "RUNTIME_LIVE"
            || stopped_status.components.kernel.is_healthy()
            || stopped_status.components.store.is_healthy()
            || stopped_status.components.eliotd.is_healthy()
            || stopped_status.services.kernel.is_healthy()
            || stopped_status.services.store.is_healthy()
            || stopped_status.services.eliotd.is_healthy()
        {
            return Err(
                "stopped Host boundary was substituted or retained stale Kernel/Store/eliotd Healthy evidence"
                    .to_owned(),
            );
        }
        let stopped_status_digest =
            digest_json(&stopped_status).map_err(|error| error.to_string())?;
        let owner_release_digest = prove_owner_released(&authority.installation_id)?;
        mutations.record_owner_released()?;
        Ok::<_, String>((
            stop_boundary,
            stopped_status.status,
            stopped_status_digest,
            owner_release_digest,
            watchdog_stopped,
        ))
    })();
    let cleanup_after_proof_error = stopped_proof.is_err();
    let start_attempt = mutations.start_once(cleanup_after_proof_error, || {
        match authority
            .platform
            .start_service_registration(&authority.host_request)
        {
            Ok(eliot_platform_windows::ServiceStartOutcome::Started { .. }) => {
                PulseFiveStartAttempt::Started
            }
            Ok(eliot_platform_windows::ServiceStartOutcome::AlreadyRunning { .. }) => {
                PulseFiveStartAttempt::AlreadyRunning
            }
            Ok(eliot_platform_windows::ServiceStartOutcome::AlreadyStarting { .. }) => {
                PulseFiveStartAttempt::AlreadyStarting
            }
            Ok(eliot_platform_windows::ServiceStartOutcome::EffectUnknown) => {
                PulseFiveStartAttempt::EffectUnknown
            }
            Err(error) => PulseFiveStartAttempt::Failed(format!(
                "Host start failed before authoritative classification: {error}"
            )),
        }
    })?;
    let reconcile_deadline = deadline.max(
        Instant::now()
            .checked_add(Duration::from_millis(PULSE_FIVE_CLEANUP_GRACE_MS))
            .unwrap_or(deadline),
    );
    // This read-only reconciliation runs for every classified/unknown start
    // outcome. The approved start effect above is never resent.
    let host_after_result =
        reconcile_host_running_after_start(&authority, reconcile_deadline).await;
    let (
        (
            stop_boundary,
            stopped_runtime_status,
            stopped_status_digest,
            owner_release_digest,
            watchdog_stopped,
        ),
        host_after,
    ) = resolve_post_stop_reconcile(stopped_proof, &start_attempt, host_after_result)?;
    let watchdog_after =
        require_running_scm(&authority, &authority.watchdog_request, "EliotWatchdog")?;
    require_same_watchdog(&watchdog_before, &watchdog_after)?;
    let after = wait_for_runtime_live(root, deadline).await?;
    validate_status_registration_against_scm(
        &after.report.services.host_service_registration,
        &host_after,
        "EliotHost",
    )?;
    validate_status_registration_against_scm(
        &after.report.services.watchdog_service_registration,
        &watchdog_after,
        "EliotWatchdog",
    )?;
    let (post_registry_root, post_registry) = inspect_pulse_five_registry(root)?;
    if !eliot_platform_windows::windows_paths_equal(root, &post_registry_root) {
        return Err("post-start registry inspection selected a foreign Host root".to_owned());
    }
    let post_store_approval = pulse_five_store_approval(&post_registry, &after.contour)?;
    if post_store_approval.approved_generation != authority.approved_generation
        || post_store_approval.candidate_manifest_digest
            != authority.store_approval.candidate_manifest_digest
        || post_store_approval.authority_generation != authority.store_approval.authority_generation
        || !eliot_platform_windows::windows_paths_equal(
            &post_store_approval.profile_anchor_root,
            &authority.store_approval.profile_anchor_root,
        )
    {
        return Err(
            "post-start Store approval differs from the pre-stop active manifest".to_owned(),
        );
    }
    let store_after = attest_pulse_five_store_artifacts(
        &store_executable_lease,
        &post_store_approval,
        &after.contour,
    )?;
    mutations.validate_complete()?;
    let scm_evidence = PulseFiveScmEvidence {
        approved_generation: authority.approved_generation,
        host_before: scm_snapshot(&host_before),
        host_stopped: scm_snapshot(&host_stopped),
        host_after: scm_snapshot(&host_after),
        watchdog_before: scm_snapshot(&watchdog_before),
        watchdog_while_host_stopped: scm_snapshot(&watchdog_stopped),
        watchdog_after: scm_snapshot(&watchdog_after),
        stopped_runtime_status,
        stopped_runtime_status_digest: stopped_status_digest,
        owner_release_digest,
        store_before,
        store_after,
    };
    validate_fresh_pulse_five_contour(before, &stop_boundary, &after, &scm_evidence)?;
    let request_digest = digest_json(&(
        "eliot.live-canary.pulse5.request.v1",
        &scm_evidence.approved_generation,
        &scm_evidence.host_before,
        &scm_evidence.watchdog_before,
        &before.journal_digest,
    ))
    .map_err(|error| error.to_string())?;
    let receipt_digest = digest_json(&(
        "eliot.live-canary.pulse5.receipt.v1",
        &request_digest,
        &stop_boundary,
        &scm_evidence,
        &after.journal_digest,
        &after.status_digest,
        &after.dynamic_supervision,
    ))
    .map_err(|error| error.to_string())?;
    Ok(PulseFiveResult {
        after,
        stop_boundary,
        scm_evidence,
        request_digest,
        receipt_digest,
    })
}

fn new_request(
    operation: HostRuntimeControlOperation,
    pulse: Pulse,
) -> Result<HostRuntimeControlRequest, CanaryError> {
    let request_id = PlatformHandle::new(format!(
        "live-canary:pulse-{}:{}",
        pulse.number(),
        Uuid::new_v4()
    ))
    .map_err(|error| CanaryError::Protocol(error.to_string()))?;
    HostRuntimeControlRequest::new(operation, request_id).map_err(CanaryError::Protocol)
}

#[derive(Debug)]
enum ControlError {
    NotSent(String),
    Unknown(String),
}

#[derive(Debug)]
struct ControlSuccess {
    request_digest: String,
    receipt_digest: String,
    receipt: ControlReceipt,
}

#[derive(Debug)]
enum ControlReceipt {
    Kernel(HostKernelRestartReceipt),
    Store(HostStoreRecoveryReceipt),
}

async fn send_or_reconcile(
    request: HostRuntimeControlRequest,
    store: bool,
    deadline: Instant,
    host_server: &eliot_platform_windows::NamedPipePeerExpectation,
) -> Result<ControlSuccess, ControlError> {
    let first = send_once(&request, deadline, host_server).await;
    let response = match first {
        Ok(value) => value,
        Err(SendError::NotSent(reason)) => return Err(ControlError::NotSent(reason)),
        Err(SendError::AfterSend(reason)) => {
            return reconcile_after_unknown(&request, store, deadline, reason, host_server).await;
        }
    };
    match response {
        HostRuntimeControlResponse::Restarted { receipt, .. } if !store => {
            if receipt.mutation_digest != request.mutation_digest
                || receipt.request_digest != request.request_digest
            {
                return Err(ControlError::Unknown(
                    "Kernel restart receipt is not bound to the exact request".to_owned(),
                ));
            }
            Ok(ControlSuccess {
                request_digest: request.request_digest.as_str().to_owned(),
                receipt_digest: receipt.receipt_digest.as_str().to_owned(),
                receipt: ControlReceipt::Kernel(receipt),
            })
        }
        HostRuntimeControlResponse::StoreRecovered { receipt, .. } if store => {
            if receipt.external_control_mutation_digest != request.mutation_digest
                || receipt.request_digest != request.request_digest
            {
                return Err(ControlError::Unknown(
                    "Store recovery receipt is not bound to the exact request".to_owned(),
                ));
            }
            Ok(ControlSuccess {
                request_digest: request.request_digest.as_str().to_owned(),
                receipt_digest: receipt.receipt_digest.as_str().to_owned(),
                receipt: ControlReceipt::Store(receipt),
            })
        }
        HostRuntimeControlResponse::Unknown { pending_ref, .. } => {
            if !unknown_ref_matches_request(&pending_ref, &request) {
                return Err(ControlError::Unknown(
                    "Host returned an unknown reference not bound to the exact request".to_owned(),
                ));
            }
            reconcile_after_unknown(
                &request,
                store,
                deadline,
                "Host returned a durable unknown outcome".to_owned(),
                host_server,
            )
            .await
        }
        _ => Err(ControlError::Unknown(
            "Host runtime-control response operation did not match the requested pulse".to_owned(),
        )),
    }
}

async fn reconcile_after_unknown(
    request: &HostRuntimeControlRequest,
    store: bool,
    deadline: Instant,
    cause: String,
    host_server: &eliot_platform_windows::NamedPipePeerExpectation,
) -> Result<ControlSuccess, ControlError> {
    let reconcile = if store {
        HostRuntimeControlRequest::new_store_reconcile(
            request.request_id.clone(),
            request.mutation_digest.clone(),
        )
    } else {
        HostRuntimeControlRequest::new_reconcile(
            request.request_id.clone(),
            request.mutation_digest.clone(),
        )
    }
    .map_err(ControlError::Unknown)?;
    let response = match send_once(&reconcile, deadline, host_server).await {
        Ok(value) => value,
        Err(SendError::NotSent(reason)) => {
            return Err(ControlError::Unknown(format!(
                "{cause}; exact reconciliation was not delivered: {reason}"
            )));
        }
        Err(SendError::AfterSend(reason)) => {
            return Err(ControlError::Unknown(format!(
                "{cause}; exact reconciliation outcome remains unknown: {reason}"
            )));
        }
    };
    match response {
        HostRuntimeControlResponse::Restarted { receipt, .. } if !store => {
            if receipt.mutation_digest != reconcile.mutation_digest
                || receipt.request_digest != reconcile.request_digest
            {
                return Err(ControlError::Unknown(
                    "reconciled Kernel receipt is not bound to the exact mutation/request"
                        .to_owned(),
                ));
            }
            Ok(ControlSuccess {
                request_digest: reconcile.request_digest.as_str().to_owned(),
                receipt_digest: receipt.receipt_digest.as_str().to_owned(),
                receipt: ControlReceipt::Kernel(receipt),
            })
        }
        HostRuntimeControlResponse::StoreRecovered { receipt, .. } if store => {
            if receipt.external_control_mutation_digest != reconcile.mutation_digest
                || receipt.request_digest != reconcile.request_digest
            {
                return Err(ControlError::Unknown(
                    "reconciled Store receipt is not bound to the exact mutation/request"
                        .to_owned(),
                ));
            }
            Ok(ControlSuccess {
                request_digest: reconcile.request_digest.as_str().to_owned(),
                receipt_digest: receipt.receipt_digest.as_str().to_owned(),
                receipt: ControlReceipt::Store(receipt),
            })
        }
        HostRuntimeControlResponse::Unknown { .. } => Err(ControlError::Unknown(format!(
            "{cause}; exact reconciliation remained unknown; no new mutation was attempted"
        ))),
        _ => Err(ControlError::Unknown(
            "reconciliation response operation did not match the requested pulse".to_owned(),
        )),
    }
}

#[derive(Debug)]
enum SendError {
    NotSent(String),
    AfterSend(String),
}

async fn send_once(
    request: &HostRuntimeControlRequest,
    deadline: Instant,
    host_server: &eliot_platform_windows::NamedPipePeerExpectation,
) -> Result<HostRuntimeControlResponse, SendError> {
    #[cfg(windows)]
    {
        if Instant::now() >= deadline {
            return Err(SendError::NotSent(
                "deadline expired before connect".to_owned(),
            ));
        }
        let timeout = deadline.saturating_duration_since(Instant::now());
        let mut transport = eliot_ipc::NamedPipeTransport::connect_authenticated(
            HOST_RUNTIME_CONTROL_PIPE,
            timeout,
            host_server,
        )
        .await
        .map_err(|error| SendError::NotSent(format!("authenticated Host pipe connect: {error}")))?;
        let connection_id = format!("live-canary:{}", Uuid::new_v4());
        let frame = runtime_control_request_frame(connection_id.clone(), request)
            .map_err(SendError::NotSent)?;
        let limits = eliot_ipc::TransportLimits {
            operation_timeout: timeout,
            ..Default::default()
        };
        match transport.send_frame(&frame, limits).await {
            Ok(eliot_ipc::DeliveryOutcome::Delivered) => {}
            Ok(eliot_ipc::DeliveryOutcome::UnknownOutcome) => {
                return Err(SendError::AfterSend(
                    "Host request write crossed the transport uncertainty boundary".to_owned(),
                ));
            }
            Err(error) => {
                return Err(SendError::AfterSend(format!(
                    "Host request send failed after authentication: {error}"
                )));
            }
        }
        let response_frame = transport
            .receive_frame(limits)
            .await
            .map_err(|error| SendError::AfterSend(format!("Host response read: {error}")))?;
        if response_frame.connection_id != connection_id {
            return Err(SendError::AfterSend(
                "Host response connection identity was substituted".to_owned(),
            ));
        }
        decode_runtime_control_response_frame(&response_frame)
            .map_err(|error| SendError::AfterSend(format!("Host response frame: {error}")))
    }
    #[cfg(not(windows))]
    {
        let _ = (request, deadline, host_server);
        Err(SendError::NotSent(
            "Host runtime-control named pipe is Windows-only".to_owned(),
        ))
    }
}

fn observe_runtime(root: &Path, deadline: Instant) -> Result<RuntimeObservation, CanaryError> {
    if Instant::now() >= deadline {
        return Err(CanaryError::Observation(
            "deadline exceeded before status inspection".to_owned(),
        ));
    }
    let report = collect_status(root, deadline)
        .map_err(|error| CanaryError::Observation(error.to_string()))?;
    if !root_matches_report(root, &report) {
        return Err(CanaryError::Observation(
            "status returned a Host state root different from the retained caller root".to_owned(),
        ));
    }
    let (state, contour, journal_digest) = inspect_journal_contour(root)?;
    if Instant::now() >= deadline {
        return Err(CanaryError::Observation(
            "deadline exceeded after journal replay".to_owned(),
        ));
    }
    let dynamic_supervision = bind_dynamic_supervision(&report, &state)?;
    let status_digest = digest_json(&report)?;
    Ok(RuntimeObservation {
        report,
        status_digest,
        journal_digest,
        contour,
        dynamic_supervision,
    })
}

fn inspect_journal_contour(
    root: &Path,
) -> Result<(HostState, ContourSnapshot, String), CanaryError> {
    let journal_path = root.join(JOURNAL_FILE_NAME);
    let inspection = RedbJournalBackend::inspect_existing_at(&journal_path)
        .map_err(|error| CanaryError::Observation(format!("journal inspect: {error}")))?
        .ok_or_else(|| {
            CanaryError::Observation(
                "Host journal is absent; no fallback path is admitted".to_owned(),
            )
        })?;
    let state = readonly_project_host_state(&inspection.image)
        .map_err(|error| CanaryError::Observation(format!("journal replay: {error}")))?;
    let contour = contour_from_state(&state)?;
    let digest = digest_json(&contour)?;
    Ok((state, contour, digest))
}

fn bind_dynamic_supervision(
    report: &RuntimeStatusReport,
    state: &HostState,
) -> Result<Option<DynamicSupervisionEvidence>, CanaryError> {
    let Some(evidence) = report.ors.current_supervision.as_ref() else {
        return Ok(None);
    };
    evidence
        .validate()
        .map_err(|error| CanaryError::Observation(format!("supervision evidence: {error}")))?;
    if !report.components.ors_supervision.is_healthy() {
        return Err(CanaryError::Observation(
            "current supervision evidence was projected from a non-Healthy ORS contour".to_owned(),
        ));
    }
    let (reconstructed, current_identity) = reconstruct_current_supervision_incarnation(
        state,
        &evidence.incarnation.supervision_lease_scope_id,
        &evidence.incarnation.observation_scope,
        &evidence.incarnation.wake_policy,
    )
    .map_err(|error| {
        CanaryError::Observation(format!("Host journal supervision reconstruction: {error}"))
    })?;
    if reconstructed != evidence.incarnation
        || current_identity.supervision_lease_id != evidence.incarnation.supervision_lease_id
        || current_identity.ors_receipt_sha256 != evidence.ors_receipt_sha256
    {
        return Err(CanaryError::Observation(
            "status supervision evidence differs from the retained Host journal identity"
                .to_owned(),
        ));
    }
    let dynamic = DynamicSupervisionEvidence {
        lease_id: evidence.incarnation.supervision_lease_id.clone(),
        lease_scope_id: evidence.incarnation.supervision_lease_scope_id.clone(),
        incarnation_digest: evidence.incarnation_sha256.clone(),
        ors_record_id: evidence.ors_record_id.clone(),
        ors_revision: evidence.ors_revision,
        receipt_digest: evidence.ors_receipt_sha256.clone(),
        verification_context_digest: evidence.verification_context_sha256.clone(),
        publication_digest: evidence.watchdog_publication_sha256.clone(),
        observed_generation: format!(
            "{}:{}",
            evidence.incarnation.kernel_generation.lineage_id,
            evidence.incarnation.kernel_generation.sequence
        ),
    };
    dynamic.validate()?;
    Ok(Some(dynamic))
}

fn root_matches_report(root: &Path, report: &RuntimeStatusReport) -> bool {
    eliot_platform_windows::windows_paths_equal(root, Path::new(&report.host_state_root))
}

fn contour_from_state(state: &HostState) -> Result<ContourSnapshot, CanaryError> {
    let mut integrity_gaps = Vec::new();
    let host_process_nonce_digest = digest_bytes(state.host.nonce.as_str().as_bytes());
    let activation_id = state
        .activation
        .as_ref()
        .map(|record| record.activation_id.as_str().to_owned());
    let activation_generation = state.activation.as_ref().map(|record| {
        format!(
            "{}:{}",
            record.fence.activation_generation.current.lineage.as_str(),
            record.fence.activation_generation.current.sequence
        )
    });
    let activation_state = state
        .activation
        .as_ref()
        .map(|record| format!("{:?}", record.state));
    let kernel = state.kernel.as_ref().and_then(|record| {
        let process = record.process.as_ref()?;
        let job = record.candidate_job_binding.as_ref()?;
        let (process_id, start_time_100ns) = match parse_process_identity(&process.process_id) {
            Ok(value) => value,
            Err(error) => {
                integrity_gaps.push(format!("Kernel process identity: {error}"));
                return None;
            }
        };
        if process_id != job.root_pid || start_time_100ns != job.root_start_time_100ns {
            integrity_gaps
                .push("Kernel process identity differs from retained Job root".to_owned());
            return None;
        }
        Some(ProcessSnapshot {
            process_id,
            start_time_100ns,
            image_path: job.root_image_path.as_str().to_owned(),
            job_name: job.job_name.as_str().to_owned(),
        })
    });
    let (kernel_generation, kernel_generation_digest) = state
        .kernel
        .as_ref()
        .map(|record| {
            let label = format!(
                "{}:{}",
                record.kernel_generation.current.lineage.as_str(),
                record.kernel_generation.current.sequence
            );
            let digest = digest_json(&record.kernel_generation)?;
            Ok::<_, CanaryError>((Some(label), Some(digest)))
        })
        .transpose()?
        .unwrap_or((None, None));
    let kernel_activation_nonce_digest = state
        .kernel
        .as_ref()
        .and_then(|record| record.one_time_nonce.activation_nonce_digest());
    let kernel_state = state
        .kernel
        .as_ref()
        .map(|record| format!("{:?}", record.state));
    if state.kernel.is_some() && kernel.is_none() {
        integrity_gaps.push("Kernel exact process/Job contour is unavailable".to_owned());
    }

    let current_store = state.store_rebinds.last();
    let store = current_store.and_then(|record| {
        if record.state != StoreRebindState::Committed {
            integrity_gaps.push(format!(
                "current StoreRebind is {:?}, not Committed",
                record.state
            ));
            return None;
        }
        Some(ProcessSnapshot {
            process_id: record.process_id,
            start_time_100ns: record.process_start_time_100ns,
            image_path: record.process_image_path.as_str().to_owned(),
            job_name: record.job_name.as_str().to_owned(),
        })
    });
    let ready_receipt_digest = state
        .readiness_observations
        .last()
        .map(|observation| observation.ready_receipt_digest.as_str().to_owned());
    let readiness_observation_digest = state
        .readiness_observations
        .last()
        .map(digest_json)
        .transpose()?;
    if ready_receipt_digest.is_none() {
        integrity_gaps.push("no retained Kernel ProbeReady observation".to_owned());
    }
    Ok(ContourSnapshot {
        host_epoch_lineage: state.host.epoch.current.lineage.as_str().to_owned(),
        host_epoch_sequence: state.host.epoch.current.sequence,
        host_epoch_parent_lineage: state
            .host
            .epoch
            .parent
            .as_ref()
            .map(|parent| parent.lineage.as_str().to_owned()),
        host_epoch_parent_sequence: state
            .host
            .epoch
            .parent
            .as_ref()
            .map(|parent| parent.sequence),
        host_process_nonce_digest,
        activation_id,
        activation_generation,
        activation_state,
        sequence: state.sequence,
        last_checksum: state.last_checksum.as_ref().map(ToString::to_string),
        kernel,
        kernel_generation,
        kernel_generation_digest,
        kernel_activation_nonce_digest,
        kernel_state,
        store,
        store_generation: current_store.map(|record| record.generation.to_string()),
        store_fence: current_store.map(|record| record.store_fence.as_str().to_owned()),
        store_request_digest: current_store.map(|record| record.request_digest.as_str().to_owned()),
        ready_receipt_digest,
        readiness_observation_digest,
        clean_marker_last_sequence: state
            .clean_marker
            .as_ref()
            .map(|marker| marker.manifest.last_sequence),
        clean_marker_last_checksum: state
            .clean_marker
            .as_ref()
            .map(|marker| marker.manifest.last_checksum.as_str().to_owned()),
        integrity_gaps,
    })
}

fn parse_process_identity(value: &str) -> Result<(u32, u64), String> {
    let rest = value
        .strip_prefix("pid:")
        .ok_or_else(|| "missing pid prefix".to_owned())?;
    let (pid, start) = rest
        .split_once(":start:")
        .ok_or_else(|| "missing start separator".to_owned())?;
    let pid = pid.parse::<u32>().map_err(|_| "invalid pid".to_owned())?;
    let start = start
        .parse::<u64>()
        .map_err(|_| "invalid start time".to_owned())?;
    if pid == 0 || start == 0 {
        return Err("pid/start must be non-zero".to_owned());
    }
    Ok((pid, start))
}

fn validate_kernel_restart(
    before: &ContourSnapshot,
    after: &ContourSnapshot,
    receipt: &ControlReceipt,
) -> Result<(), String> {
    let ControlReceipt::Kernel(receipt) = receipt else {
        return Err("Kernel restart received a non-Kernel receipt".to_owned());
    };
    receipt.validate()?;
    let before_kernel = before
        .kernel
        .as_ref()
        .ok_or("Kernel pre-process identity missing")?;
    let after_kernel = after
        .kernel
        .as_ref()
        .ok_or("Kernel post-process identity missing")?;
    let before_store = before
        .store
        .as_ref()
        .ok_or("Store pre-process identity missing")?;
    let after_store = after
        .store
        .as_ref()
        .ok_or("Store post-process identity missing")?;
    if after.sequence <= before.sequence
        || before.ready_receipt_digest == after.ready_receipt_digest
        || before.readiness_observation_digest == after.readiness_observation_digest
        || after.ready_receipt_digest.is_none()
        || after.readiness_observation_digest.is_none()
    {
        return Err(
            "Kernel restart did not append a distinct causally fresh ProbeReady observation"
                .to_owned(),
        );
    }
    if before_kernel == after_kernel {
        return Err("Kernel restart did not produce a distinct post process identity".to_owned());
    }
    if before.kernel_generation_digest == after.kernel_generation_digest {
        return Err("Kernel restart did not produce a distinct post generation".to_owned());
    }
    if before_store != after_store {
        return Err("Kernel restart changed the Store process contour".to_owned());
    }
    if before.store_fence != after.store_fence {
        return Err("Kernel restart changed the Store fence".to_owned());
    }
    if receipt.old_kernel_generation.as_str()
        != before
            .kernel_generation_digest
            .as_deref()
            .ok_or("Kernel pre-generation digest missing")?
        || receipt.new_kernel_generation.as_str()
            != after
                .kernel_generation_digest
                .as_deref()
                .ok_or("Kernel post-generation digest missing")?
    {
        return Err(
            "Kernel receipt generation digests do not match exact pre/post journal readback"
                .to_owned(),
        );
    }
    if receipt.store_fence.as_str()
        != after
            .store_fence
            .as_deref()
            .ok_or("Store fence missing after Kernel restart")?
        || receipt.ready_receipt_digest.as_str()
            != after
                .ready_receipt_digest
                .as_deref()
                .ok_or("ProbeReady receipt missing after Kernel restart")?
    {
        return Err(
            "Kernel receipt is not bound to post-restart Store fence/ProbeReady".to_owned(),
        );
    }
    Ok(())
}

fn validate_store_recovery(
    before: &ContourSnapshot,
    after: &ContourSnapshot,
    receipt: &ControlReceipt,
) -> Result<(), String> {
    let ControlReceipt::Store(receipt) = receipt else {
        return Err("Store recovery received a non-Store receipt".to_owned());
    };
    receipt.validate()?;
    let before_kernel = before
        .kernel
        .as_ref()
        .ok_or("Kernel pre-process identity missing")?;
    let after_kernel = after
        .kernel
        .as_ref()
        .ok_or("Kernel post-process identity missing")?;
    let before_store = before
        .store
        .as_ref()
        .ok_or("Store pre-process identity missing")?;
    let after_store = after
        .store
        .as_ref()
        .ok_or("Store post-process identity missing")?;
    if after.sequence <= before.sequence
        || before.ready_receipt_digest == after.ready_receipt_digest
        || before.readiness_observation_digest == after.readiness_observation_digest
        || after.ready_receipt_digest.is_none()
        || after.readiness_observation_digest.is_none()
    {
        return Err(
            "Store recovery did not append a distinct causally fresh ProbeReady observation"
                .to_owned(),
        );
    }
    if before_kernel != after_kernel
        || before.kernel_generation_digest != after.kernel_generation_digest
    {
        return Err("Store recovery changed the Kernel process or generation".to_owned());
    }
    if before_store == after_store {
        return Err("Store recovery did not produce a distinct post process identity".to_owned());
    }
    if before.store_fence == after.store_fence {
        return Err(
            "Store recovery did not produce a distinct committed StoreRebind fence".to_owned(),
        );
    }
    let (pid, start) = parse_process_identity(receipt.new_store_process_id.as_str())?;
    if pid != after_store.process_id || start != after_store.start_time_100ns {
        return Err(
            "Store recovery receipt process identity does not match post Job readback".to_owned(),
        );
    }
    if receipt.kernel_generation.as_str()
        != after
            .kernel_generation_digest
            .as_deref()
            .ok_or("Kernel generation digest missing after Store recovery")?
        || receipt.store_fence.as_str()
            != after
                .store_fence
                .as_deref()
                .ok_or("Store fence missing after recovery")?
        || receipt.ready_receipt_digest.as_str()
            != after
                .ready_receipt_digest
                .as_deref()
                .ok_or("ProbeReady receipt missing after recovery")?
    {
        return Err(
            "Store recovery receipt is not bound to exact post StoreRebind/ProbeReady readback"
                .to_owned(),
        );
    }
    Ok(())
}

fn unknown_ref_matches_request(
    pending_ref: &PlatformHandle,
    request: &HostRuntimeControlRequest,
) -> bool {
    let mut parts = pending_ref.as_str().splitn(4, ':');
    if parts.next() != Some("eliot.host.runtime-control.v2") || parts.next() != Some("unknown") {
        return false;
    }
    let Some(reason) = parts.next() else {
        return false;
    };
    if reason.trim().is_empty() || parts.next().is_none() {
        return false;
    }
    let payload = pending_ref
        .as_str()
        .splitn(4, ':')
        .nth(3)
        .unwrap_or_default();
    let Ok((operation, request_id, mutation_digest, request_digest)) =
        serde_json::from_str::<(String, String, String, String)>(payload)
    else {
        return false;
    };
    operation == operation_name(&request.operation)
        && request_id == request.request_id.as_str()
        && mutation_digest == request.mutation_digest.as_str()
        && request_digest == request.request_digest.as_str()
}

fn operation_name(operation: &HostRuntimeControlOperation) -> &'static str {
    match operation {
        HostRuntimeControlOperation::RestartKernel => "RestartKernel",
        HostRuntimeControlOperation::ReconcileKernelRestart => "ReconcileKernelRestart",
        HostRuntimeControlOperation::RecoverStore => "RecoverStore",
        HostRuntimeControlOperation::ReconcileStoreRecovery => "ReconcileStoreRecovery",
    }
}

pub fn write_evidence(
    evidence_dir: &Path,
    pulse: Pulse,
    disposition: &PulseDisposition,
) -> Result<(PathBuf, String), CanaryError> {
    let _evidence_contour = validate_evidence_dir(evidence_dir)?;
    let bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schema": CANARY_SCHEMA,
        "pulse": pulse.number(),
        "disposition": disposition,
    }))
    .map_err(|error| CanaryError::Evidence(error.to_string()))?;
    if bytes.len() > MAX_EVIDENCE_BYTES {
        return Err(CanaryError::Evidence(
            "evidence exceeds bounded size".to_owned(),
        ));
    }
    let final_name = format!("pulse-{}-{}.json", pulse.number(), Uuid::new_v4());
    let final_path = evidence_dir.join(final_name);
    write_new_evidence_file(&final_path, &bytes).map_err(|error| {
        CanaryError::Evidence(format!("create-new no-follow evidence: {error}"))
    })?;
    let persisted = read_pinned_evidence_file(&final_path)
        .map_err(|error| CanaryError::Evidence(format!("readback evidence: {error}")))?;
    if persisted != bytes {
        return Err(CanaryError::Evidence(
            "evidence readback differs from synced bytes".to_owned(),
        ));
    }
    Ok((final_path, digest_bytes(&persisted)))
}

#[cfg(windows)]
fn write_new_evidence_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    eliot_windows_ipc::write_new_pinned_file(path, bytes)
}

#[cfg(not(windows))]
fn write_new_evidence_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(windows)]
fn read_pinned_evidence_file(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut pinned = eliot_windows_ipc::PinnedFile::open(path)?;
    pinned.read_all()
}

#[cfg(not(windows))]
fn read_pinned_evidence_file(path: &Path) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}

struct EvidenceDirectoryContour {
    #[cfg(windows)]
    _pins: Vec<eliot_windows_ipc::PinnedDirectory>,
}

fn validate_evidence_dir(path: &Path) -> Result<EvidenceDirectoryContour, CanaryError> {
    if !path.is_absolute() {
        return Err(CanaryError::Evidence(
            "evidence directory must be absolute".to_owned(),
        ));
    }
    #[cfg(windows)]
    let mut pins = Vec::new();
    for ancestor in path.ancestors().collect::<Vec<_>>().into_iter().rev() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            CanaryError::Evidence(format!(
                "evidence directory ancestor {}: {error}",
                ancestor.display()
            ))
        })?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata_is_reparse(&metadata)
        {
            return Err(CanaryError::Evidence(
                "evidence directory contour contains a non-directory link/reparse substitute"
                    .to_owned(),
            ));
        }
        #[cfg(windows)]
        pins.push(
            eliot_windows_ipc::PinnedDirectory::open(ancestor).map_err(|error| {
                CanaryError::Evidence(format!(
                    "retain evidence directory ancestor {}: {error}",
                    ancestor.display()
                ))
            })?,
        );
    }
    Ok(EvidenceDirectoryContour {
        #[cfg(windows)]
        _pins: pins,
    })
}

#[cfg(windows)]
fn metadata_is_reparse(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse(_metadata: &std::fs::Metadata) -> bool {
    false
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, CanaryError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        CanaryError::Observation(format!("canonical digest serialization: {error}"))
    })?;
    Ok(digest_bytes(&bytes))
}

fn digest_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn exact_path_identity_digest(path: &Path) -> String {
    let mut bytes = b"eliot.runtime-live.canary.path-identity.v1\0".to_vec();
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;

        let units = path.as_os_str().encode_wide().collect::<Vec<_>>();
        bytes.extend_from_slice(&(units.len() as u64).to_le_bytes());
        for unit in units {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
    }
    #[cfg(not(windows))]
    {
        let encoded = path.as_os_str().as_encoded_bytes();
        bytes.extend_from_slice(&(encoded.len() as u64).to_le_bytes());
        bytes.extend_from_slice(encoded);
    }
    digest_bytes(&bytes)
}

fn is_lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn redact_message(message: &str, root: &Path) -> String {
    let root_text = root.to_string_lossy();
    message
        .replace(root_text.as_ref(), "<host-state-root>")
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .collect()
}

impl fmt::Display for Pulse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_platform::PlatformHandle;

    fn handle(value: &str) -> PlatformHandle {
        PlatformHandle::new(value.to_owned()).unwrap_or_else(|_| unreachable!())
    }

    fn digest(seed: &str) -> PlatformHandle {
        handle(&digest_bytes(seed.as_bytes()))
    }

    fn process(pid: u32, start: u64, image: &str, job: &str) -> ProcessSnapshot {
        ProcessSnapshot {
            process_id: pid,
            start_time_100ns: start,
            image_path: image.to_owned(),
            job_name: job.to_owned(),
        }
    }

    fn contour() -> ContourSnapshot {
        let store_image = if cfg!(windows) {
            r"C:\Program Files\Eliot\eliot-store-bridge.exe"
        } else {
            "/opt/eliot/eliot-store-bridge"
        };
        ContourSnapshot {
            host_epoch_lineage: "host-lineage".to_owned(),
            host_epoch_sequence: 3,
            host_epoch_parent_lineage: Some("host-lineage".to_owned()),
            host_epoch_parent_sequence: Some(2),
            host_process_nonce_digest: digest_bytes(b"host-nonce-before"),
            activation_id: Some("activation-before".to_owned()),
            activation_generation: Some("activation-lineage:3".to_owned()),
            activation_state: Some("Active".to_owned()),
            sequence: 3,
            last_checksum: Some("a".repeat(64)),
            kernel: Some(process(10, 100, "kernel.exe", "kernel-job")),
            kernel_generation: Some("lineage:3".to_owned()),
            kernel_generation_digest: Some(digest_bytes(b"kernel-before")),
            kernel_activation_nonce_digest: Some(digest_bytes(b"kernel-nonce-before")),
            kernel_state: Some("Active".to_owned()),
            store: Some(process(20, 200, store_image, "store-job")),
            store_generation: Some("3".to_owned()),
            store_fence: Some("b".repeat(64)),
            store_request_digest: Some("c".repeat(64)),
            ready_receipt_digest: Some("d".repeat(64)),
            readiness_observation_digest: Some("e".repeat(64)),
            clean_marker_last_sequence: None,
            clean_marker_last_checksum: None,
            integrity_gaps: Vec::new(),
        }
    }

    fn dynamic(seed: char) -> DynamicSupervisionEvidence {
        DynamicSupervisionEvidence {
            lease_id: format!("eliot-supervision-lease:v1:{seed}"),
            lease_scope_id: "eliot-supervision-scope:v1:test".to_owned(),
            incarnation_digest: seed.to_string().repeat(64),
            ors_record_id: format!("record-{seed}"),
            ors_revision: 1,
            receipt_digest: seed.to_string().repeat(64),
            verification_context_digest: seed.to_string().repeat(64),
            publication_digest: seed.to_string().repeat(64),
            observed_generation: format!("kernel:{seed}"),
        }
    }

    fn runtime_report(status: &str) -> RuntimeStatusReport {
        let image = if cfg!(windows) {
            r"C:\Program Files\Eliot\eliot-host.exe"
        } else {
            "/opt/eliot/eliot-host"
        };
        serde_json::from_value(serde_json::json!({
            "contract":"eliot.runtime.live","contract_version":"1.1.0","status":status,
            "host_state_root":if cfg!(windows) {"C:\\ProgramData\\Eliot\\runtime"} else {"/var/lib/eliot/runtime"},
            "active_generation":"g","last_known_good_generation":"g","generations":["g"],
            "host_journal":{"state":"Healthy","clean":true,"sequence":1,"last_checksum":null,"prior_kernel_unknown":false,"gap":""},
            "ors":{"state":"Healthy","current_supervision":null,"gap":""},
            "transaction_stage":{"state":"Healthy","stage":"COMPLETED","gap":""},
            "services":{
              "kernel":"Healthy","store":"Healthy","eliotd":"Healthy","watchdog":"Healthy",
              "host_service_registration":{"registration":"Matching","state":"Running","observed_process":null,"observed_runtime":{"process_id":1,"start_time_100ns":2,"image_path":image,"runtime_identity_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"gap":""},
              "watchdog_service_registration":{"registration":"Matching","state":"Running","observed_process":null,"observed_runtime":{"process_id":2,"start_time_100ns":3,"image_path":image,"runtime_identity_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"gap":""}
            },
            "readiness":{"proof_status":"Healthy","age_gap":""},"recovery_command":"","gaps":[],
            "components":{"installation_registry":"Healthy","host_journal":"Healthy","ors_supervision":"Healthy","kernel":"Healthy","store":"Healthy","eliotd":"Healthy","watchdog":"Healthy"},"deadline_exceeded":false
        }))
        .unwrap_or_else(|_| unreachable!())
    }

    fn runtime_observation(
        status: &str,
        dynamic: Option<DynamicSupervisionEvidence>,
    ) -> RuntimeObservation {
        RuntimeObservation {
            report: runtime_report(status),
            status_digest: "a".repeat(64),
            journal_digest: "b".repeat(64),
            contour: contour(),
            dynamic_supervision: dynamic,
        }
    }

    #[cfg(windows)]
    fn scm_runtime(
        service_name: &str,
        state: &str,
        configuration_seed: char,
        runtime_seed: Option<char>,
        process: Option<(u32, u64, &str)>,
    ) -> ScmRuntimeSnapshot {
        ScmRuntimeSnapshot {
            service_name: service_name.to_owned(),
            configuration_digest: configuration_seed.to_string().repeat(64),
            state: state.to_owned(),
            runtime_identity_digest: runtime_seed.map(|seed| seed.to_string().repeat(64)),
            process: process.map(
                |(process_id, start_time_100ns, image_path)| ScmProcessSnapshot {
                    process_id,
                    start_time_100ns,
                    image_path: image_path.to_owned(),
                },
            ),
        }
    }

    #[cfg(windows)]
    fn store_artifact_evidence(
        contour: &ContourSnapshot,
        phase_seed: char,
        config_seed: char,
        config_file_index: u64,
    ) -> PulseFiveStoreArtifactEvidence {
        let store = contour
            .store
            .as_ref()
            .unwrap_or_else(|| unreachable!())
            .clone();
        PulseFiveStoreArtifactEvidence {
            approved_generation: "g".to_owned(),
            candidate_manifest_digest: "c".repeat(64),
            authority_generation: 3,
            approved_executable_path: store.image_path.clone(),
            observed_executable_path: store.image_path.clone(),
            approved_executable_digest: "d".repeat(64),
            observed_executable_digest: "d".repeat(64),
            executable_file_identity: eliot_platform_windows::FileIdentity {
                volume_serial_number: 10,
                file_index: 20,
            },
            process: store,
            approved_config_path: r"C:\ProgramData\Eliot\runtime\store\config.json".to_owned(),
            observed_config_path: r"C:\ProgramData\Eliot\runtime\store\config.json".to_owned(),
            approved_config_digest: config_seed.to_string().repeat(64),
            observed_config_digest: config_seed.to_string().repeat(64),
            config_file_identity: eliot_platform_windows::FileIdentity {
                volume_serial_number: 10,
                file_index: config_file_index,
            },
            phase_b_receipt_digest: phase_seed.to_string().repeat(64),
            phase_b_host_epoch_lineage: contour.host_epoch_lineage.clone(),
            phase_b_host_epoch_sequence: contour.host_epoch_sequence,
            phase_b_host_process_nonce_digest: contour.host_process_nonce_digest.clone(),
        }
    }

    #[cfg(windows)]
    fn pulse_five_fixture() -> (
        RuntimeObservation,
        ContourSnapshot,
        RuntimeObservation,
        PulseFiveScmEvidence,
    ) {
        let before = runtime_observation("RUNTIME_LIVE", Some(dynamic('a')));
        let mut stopped = before.contour.clone();
        stopped.activation_state = Some("StoppedClean".to_owned());
        stopped.clean_marker_last_sequence = Some(9);
        stopped.clean_marker_last_checksum = Some("9".repeat(64));
        stopped.sequence = 10;

        let mut after = runtime_observation("RUNTIME_LIVE", Some(dynamic('b')));
        after.status_digest = "c".repeat(64);
        after.journal_digest = "d".repeat(64);
        after.contour.host_epoch_sequence = before.contour.host_epoch_sequence + 1;
        after.contour.host_epoch_parent_lineage = Some(before.contour.host_epoch_lineage.clone());
        after.contour.host_epoch_parent_sequence = Some(before.contour.host_epoch_sequence);
        after.contour.host_process_nonce_digest = digest_bytes(b"host-nonce-after");
        after.contour.activation_id = Some("activation-after".to_owned());
        after.contour.activation_generation = Some("activation-lineage:4".to_owned());
        after.contour.kernel_generation = Some("kernel-lineage:4".to_owned());
        after.contour.kernel_generation_digest = Some(digest_bytes(b"kernel-after"));
        after.contour.kernel_activation_nonce_digest = Some(digest_bytes(b"kernel-nonce-after"));
        after.contour.store = Some(process(
            21,
            300,
            r"C:\Program Files\Eliot\eliot-store-bridge.exe",
            "store-job-after",
        ));
        // Store's authority generation is the immutable manifest generation;
        // Host restart freshness comes from process/Job and rebind fence/request.
        after.contour.store_generation = before.contour.store_generation.clone();
        after.contour.store_fence = Some("3".repeat(64));
        after.contour.store_request_digest = Some("4".repeat(64));
        after.contour.ready_receipt_digest = Some("1".repeat(64));
        after.contour.readiness_observation_digest = Some("2".repeat(64));

        let host_before = scm_runtime(
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
            "Running",
            '3',
            Some('4'),
            Some((100, 1_000, r"C:\Program Files\Eliot\eliot-host.exe")),
        );
        let host_stopped = scm_runtime(
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
            "Stopped",
            '3',
            None,
            None,
        );
        let host_after = scm_runtime(
            eliot_platform_windows::ELIOT_HOST_SERVICE_NAME,
            "Running",
            '3',
            Some('5'),
            Some((101, 2_000, r"C:\Program Files\Eliot\eliot-host.exe")),
        );
        let watchdog = scm_runtime(
            eliot_platform_windows::ELIOT_WATCHDOG_SERVICE_NAME,
            "Running",
            '6',
            Some('7'),
            Some((200, 500, r"C:\Program Files\Eliot\eliot-watchdog.exe")),
        );
        let store_before = store_artifact_evidence(&before.contour, 'a', 'e', 30);
        let store_after = store_artifact_evidence(&after.contour, 'b', 'f', 31);
        let scm = PulseFiveScmEvidence {
            approved_generation: "g".to_owned(),
            host_before,
            host_stopped,
            host_after,
            watchdog_before: watchdog.clone(),
            watchdog_while_host_stopped: watchdog.clone(),
            watchdog_after: watchdog,
            stopped_runtime_status: "READINESS_DEGRADED".to_owned(),
            stopped_runtime_status_digest: "8".repeat(64),
            owner_release_digest: "9".repeat(64),
            store_before,
            store_after,
        };
        (before, stopped, after, scm)
    }

    #[cfg(windows)]
    #[test]
    fn pulse_five_exact_one_stop_and_one_start_are_ordered_after_durable_fences() {
        let mut ledger = PulseFiveMutationLedger::default();
        let mut effects = Vec::new();
        assert!(
            ledger
                .start_once(false, || effects.push("start-early"))
                .is_err()
        );
        assert!(effects.is_empty());
        ledger
            .stop_once(|| effects.push("stop"))
            .unwrap_or_else(|_| unreachable!());
        assert!(ledger.stop_once(|| effects.push("stop-again")).is_err());
        assert_eq!(effects, vec!["stop"]);
        assert!(
            ledger
                .start_once(false, || effects.push("start-early"))
                .is_err()
        );
        ledger
            .record_stopped_readback()
            .unwrap_or_else(|_| unreachable!());
        assert!(
            ledger
                .start_once(false, || effects.push("start-early"))
                .is_err()
        );
        ledger
            .record_stopped_clean()
            .unwrap_or_else(|_| unreachable!());
        assert!(
            ledger
                .start_once(false, || effects.push("start-early"))
                .is_err()
        );
        ledger
            .record_owner_released()
            .unwrap_or_else(|_| unreachable!());
        ledger
            .start_once(false, || effects.push("start"))
            .unwrap_or_else(|_| unreachable!());
        assert!(
            ledger
                .start_once(false, || effects.push("start-again"))
                .is_err()
        );
        assert_eq!(effects, vec!["stop", "start"]);
        assert!(ledger.validate_complete().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn pulse_five_post_stop_proof_error_still_attempts_exactly_one_start_cleanup() {
        let mut ledger = PulseFiveMutationLedger::default();
        let mut starts = 0_u8;
        ledger.stop_once(|| ()).unwrap_or_else(|_| unreachable!());
        ledger
            .record_stopped_readback()
            .unwrap_or_else(|_| unreachable!());
        let attempt = ledger
            .start_once(true, || {
                starts += 1;
                PulseFiveStartAttempt::EffectUnknown
            })
            .unwrap_or_else(|_| unreachable!());
        assert_eq!(attempt, PulseFiveStartAttempt::EffectUnknown);
        assert_eq!(starts, 1);
        assert!(ledger.start_once(true, || starts += 1).is_err());
        assert_eq!(starts, 1);
        assert!(ledger.validate_complete().is_err());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn pulse_five_outer_timeout_preserves_fail_closed_cleanup_after_stopped() {
        let operational_deadline = Duration::from_millis(5);
        assert_eq!(
            canary_outer_timeout(Pulse::Four, operational_deadline),
            operational_deadline
        );
        let result = tokio::time::timeout(
            canary_outer_timeout(Pulse::Five, operational_deadline),
            async {
                let mut ledger = PulseFiveMutationLedger::default();
                let mut starts = 0_u8;
                ledger.stop_once(|| ()).unwrap_or_else(|_| unreachable!());
                ledger
                    .record_stopped_readback()
                    .unwrap_or_else(|_| unreachable!());
                tokio::time::sleep(operational_deadline + Duration::from_millis(5)).await;
                let attempt = ledger
                    .start_once(true, || {
                        starts += 1;
                        PulseFiveStartAttempt::Started
                    })
                    .unwrap_or_else(|_| unreachable!());
                let disposition = resolve_post_stop_reconcile::<(), ()>(
                    Err("post-Stop proof deadline exceeded".to_owned()),
                    &attempt,
                    Ok(()),
                );
                (starts, ledger.start_calls, disposition)
            },
        )
        .await
        .unwrap_or_else(|_| unreachable!());
        assert_eq!(result.0, 1);
        assert_eq!(result.1, 1);
        assert!(result.2.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pulse_five_production_callsite_binds_typed_effects_to_the_ordering_guard() {
        let source = include_str!("lib.rs");
        let production = source
            .split_once("async fn run_windows_pulse_five")
            .and_then(|(_, rest)| rest.split_once("fn new_request"))
            .map_or("", |(body, _)| body);
        assert_eq!(production.matches(".stop_once(||").count(), 1);
        assert_eq!(
            production
                .matches(".start_once(cleanup_after_proof_error, ||")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches(".stop_service_registration(&stop_request)")
                .count(),
            1
        );
        assert_eq!(
            production
                .matches(".start_service_registration(&authority.host_request)")
                .count(),
            1
        );
        assert!(production.contains("EffectUnknown =>"));
        assert!(production.contains("reconcile_host_running_after_start"));
        assert!(production.contains("resolve_post_stop_reconcile("));
        assert_eq!(
            production
                .matches("attest_pulse_five_store_artifacts(")
                .count(),
            2
        );
        assert!(production.contains("inspect_pulse_five_registry(root)"));
        assert!(!production.contains("ServiceOperation::Stop"));
        assert!(!production.contains("ServiceOperation::Start"));
    }

    #[cfg(windows)]
    #[test]
    fn pulse_five_requires_stable_watchdog_and_stopped_clean_marker() {
        let (before, stopped, _after, mut scm) = pulse_five_fixture();
        assert!(validate_stopped_contour(&before.contour, &stopped).is_ok());
        assert!(validate_pulse_five_scm_evidence(&scm).is_ok());

        let mut missing_marker = stopped.clone();
        missing_marker.clean_marker_last_sequence = None;
        assert!(validate_stopped_contour(&before.contour, &missing_marker).is_err());

        scm.watchdog_after
            .runtime_identity_digest
            .clone_from(&Some("a".repeat(64)));
        assert!(validate_pulse_five_scm_evidence(&scm).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pulse_five_requires_direct_child_host_epoch_fresh_nonces_and_readiness() {
        let (before, stopped, after, scm) = pulse_five_fixture();
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &after, &scm).is_ok());

        let mut foreign_parent = after.clone();
        foreign_parent.contour.host_epoch_parent_lineage = Some("foreign-host".to_owned());
        assert!(
            validate_fresh_pulse_five_contour(&before, &stopped, &foreign_parent, &scm).is_err()
        );

        let mut reused_nonce = after.clone();
        reused_nonce
            .contour
            .kernel_activation_nonce_digest
            .clone_from(&before.contour.kernel_activation_nonce_digest);
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &reused_nonce, &scm).is_err());

        let mut stale_readiness = after.clone();
        stale_readiness
            .contour
            .ready_receipt_digest
            .clone_from(&before.contour.ready_receipt_digest);
        assert!(
            validate_fresh_pulse_five_contour(&before, &stopped, &stale_readiness, &scm).is_err()
        );

        let mut stale_eliotd = after;
        stale_eliotd.dynamic_supervision = before.dynamic_supervision.clone();
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &stale_eliotd, &scm).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pulse_five_rejects_stale_store_process_job_rebind_and_status_substitution() {
        let (before, stopped, after, scm) = pulse_five_fixture();

        let old_store = before
            .contour
            .store
            .as_ref()
            .unwrap_or_else(|| unreachable!());
        let mut stale_process = after.clone();
        let stale_process_snapshot = stale_process
            .contour
            .store
            .as_mut()
            .unwrap_or_else(|| unreachable!());
        stale_process_snapshot.process_id = old_store.process_id;
        stale_process_snapshot.start_time_100ns = old_store.start_time_100ns;
        assert!(
            validate_fresh_pulse_five_contour(&before, &stopped, &stale_process, &scm).is_err()
        );

        let mut stale_generation = after.clone();
        stale_generation.contour.store_generation = Some("4".to_owned());
        assert!(
            validate_fresh_pulse_five_contour(&before, &stopped, &stale_generation, &scm).is_err()
        );

        let mut stale_fence = after.clone();
        stale_fence
            .contour
            .store_fence
            .clone_from(&before.contour.store_fence);
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &stale_fence, &scm).is_err());

        let mut stale_request = after.clone();
        stale_request
            .contour
            .store_request_digest
            .clone_from(&before.contour.store_request_digest);
        assert!(
            validate_fresh_pulse_five_contour(&before, &stopped, &stale_request, &scm).is_err()
        );

        let mut stale_job = after.clone();
        stale_job
            .contour
            .store
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .job_name
            .clone_from(
                &before
                    .contour
                    .store
                    .as_ref()
                    .unwrap_or_else(|| unreachable!())
                    .job_name,
            );
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &stale_job, &scm).is_err());

        let mut foreign_image = after.clone();
        foreign_image
            .contour
            .store
            .as_mut()
            .unwrap_or_else(|| unreachable!())
            .image_path = r"C:\foreign\store.exe".to_owned();
        assert!(
            validate_fresh_pulse_five_contour(&before, &stopped, &foreign_image, &scm).is_err()
        );

        let mut foreign_root = after.clone();
        foreign_root.report.host_state_root = r"C:\foreign\runtime".to_owned();
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &foreign_root, &scm).is_err());

        let mut foreign_approval = after;
        foreign_approval.report.active_generation = Some("foreign-generation".to_owned());
        assert!(
            validate_fresh_pulse_five_contour(&before, &stopped, &foreign_approval, &scm).is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn pulse_five_static_store_generation_passes_only_with_dynamic_freshness() {
        let (before, stopped, after, scm) = pulse_five_fixture();
        assert_eq!(
            before.contour.store_generation,
            after.contour.store_generation
        );
        assert_eq!(scm.store_before.authority_generation, 3);
        assert_eq!(scm.store_after.authority_generation, 3);
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &after, &scm).is_ok());

        let mut substituted = after.clone();
        substituted.contour.store_generation = Some("4".to_owned());
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &substituted, &scm).is_err());

        let mut stale_fence = after;
        stale_fence
            .contour
            .store_fence
            .clone_from(&before.contour.store_fence);
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &stale_fence, &scm).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn pulse_five_rejects_same_path_store_binary_replacement() {
        let (before, stopped, after, scm) = pulse_five_fixture();

        let mut changed_bytes = scm.clone();
        changed_bytes.store_after.observed_executable_digest = "a".repeat(64);
        assert_eq!(
            changed_bytes.store_after.approved_executable_path,
            changed_bytes.store_after.observed_executable_path
        );
        assert!(
            validate_fresh_pulse_five_contour(&before, &stopped, &after, &changed_bytes).is_err()
        );

        let mut replaced_identity = scm;
        replaced_identity
            .store_after
            .executable_file_identity
            .file_index += 1;
        assert_eq!(
            replaced_identity.store_before.approved_executable_digest,
            replaced_identity.store_after.approved_executable_digest
        );
        assert!(
            validate_fresh_pulse_five_contour(&before, &stopped, &after, &replaced_identity)
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn pulse_five_rejects_same_path_materialized_config_substitution() {
        let (before, stopped, after, mut scm) = pulse_five_fixture();
        scm.store_after.observed_config_digest = "a".repeat(64);
        assert_eq!(
            scm.store_after.approved_config_path,
            scm.store_after.observed_config_path
        );
        assert!(validate_fresh_pulse_five_contour(&before, &stopped, &after, &scm).is_err());
    }

    fn kernel_receipt(
        before: &ContourSnapshot,
        after: &ContourSnapshot,
    ) -> Result<ControlReceipt, String> {
        let old_generation = before
            .kernel_generation_digest
            .as_deref()
            .ok_or("missing pre-kernel generation")?;
        let new_generation = after
            .kernel_generation_digest
            .as_deref()
            .ok_or("missing post-kernel generation")?;
        let store_fence = after.store_fence.as_deref().ok_or("missing store fence")?;
        let ready_receipt = after
            .ready_receipt_digest
            .as_deref()
            .ok_or("missing ready receipt")?;
        let mut receipt = HostKernelRestartReceipt {
            mutation_digest: digest("mutation"),
            request_digest: digest("request"),
            old_kernel_generation: handle(old_generation),
            new_kernel_generation: handle(new_generation),
            store_fence: handle(store_fence),
            activation_receipt_digest: digest("activation"),
            ready_receipt_digest: handle(ready_receipt),
            receipt_digest: digest("placeholder"),
        };
        receipt.receipt_digest = handle(
            &receipt
                .computed_digest()
                .map_err(|error| error.clone())?
                .to_string(),
        );
        Ok(ControlReceipt::Kernel(receipt))
    }

    #[test]
    fn pulse_two_fails_closed_without_dynamic_incarnation() {
        let mut report = serde_json::from_value::<RuntimeStatusReport>(serde_json::json!({
            "contract":"eliot.runtime.live","contract_version":"1.1.0","status":"RUNTIME_LIVE",
            "host_state_root":"C:\\\\ProgramData\\\\Eliot\\\\runtime","active_generation":"g",
            "last_known_good_generation":"g","generations":["g"],
            "host_journal":{"state":"Healthy","clean":true,"sequence":1,"last_checksum":null,"prior_kernel_unknown":false,"gap":""},
            "ors":{"state":"Healthy","current_supervision":null,"gap":""},
            "transaction_stage":{"state":"Healthy","stage":"COMPLETED","gap":""},
            "services":{
              "kernel":"Healthy","store":"Healthy","eliotd":"Healthy","watchdog":"Healthy",
              "host_service_registration":{"registration":"Matching","state":"Running","observed_process":null,"observed_runtime":{"process_id":1,"start_time_100ns":2,"image_path":"host.exe","runtime_identity_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"gap":""},
              "watchdog_service_registration":{"registration":"Matching","state":"Running","observed_process":null,"observed_runtime":{"process_id":2,"start_time_100ns":3,"image_path":"watchdog.exe","runtime_identity_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"gap":""}
            },
            "readiness":{"proof_status":"Healthy","age_gap":""},"recovery_command":"","gaps":[],
            "components":{"installation_registry":"Healthy","host_journal":"Healthy","ors_supervision":"Healthy","kernel":"Healthy","store":"Healthy","eliotd":"Healthy","watchdog":"Healthy"},"deadline_exceeded":false
        })).unwrap_or_else(|_| unreachable!());
        report.status = "RUNTIME_LIVE".to_owned();
        let observation = RuntimeObservation {
            status_digest: "a".repeat(64),
            journal_digest: "b".repeat(64),
            contour: contour(),
            report,
            dynamic_supervision: None,
        };
        let canary = ProductionCanary {
            config: CanaryConfig {
                host_state_root: PathBuf::from("C:\\ProgramData\\Eliot\\runtime"),
                evidence_dir: PathBuf::from("C:\\ProgramData\\Eliot\\canary"),
                pulse: Pulse::Two,
                deadline: Duration::from_secs(1),
                execute_faults: false,
            },
        };
        assert!(matches!(
            canary.run_pulse_two(&observation),
            PulseDisposition::FailClosed(_)
        ));
    }

    #[test]
    fn pulse_two_rejects_healthy_ors_with_nonhealthy_runtime_component() {
        let mut observation = runtime_observation("RUNTIME_LIVE", Some(dynamic('a')));
        observation.report.components.kernel = eliot_runtime_status::ComponentState::NotHealthy {
            reason: "Kernel is dead".to_owned(),
        };
        observation.report.services.kernel = eliot_runtime_status::ComponentState::NotHealthy {
            reason: "Kernel is dead".to_owned(),
        };
        assert!(observation.report.components.ors_supervision.is_healthy());
        let canary = ProductionCanary {
            config: CanaryConfig {
                host_state_root: PathBuf::from("C:\\ProgramData\\Eliot\\runtime"),
                evidence_dir: PathBuf::from("C:\\ProgramData\\Eliot\\canary"),
                pulse: Pulse::Two,
                deadline: Duration::from_secs(1),
                execute_faults: false,
            },
        };
        assert!(matches!(
            canary.run_pulse_two(&observation),
            PulseDisposition::FailClosed(_)
        ));
    }

    #[test]
    fn kernel_receipt_binds_exact_pre_and_post_generations() {
        let before = contour();
        let mut after = before.clone();
        after.sequence += 1;
        after.kernel = Some(process(11, 101, "kernel.exe", "kernel-job"));
        after.kernel_generation_digest = Some(digest_bytes(b"kernel-after"));
        after.ready_receipt_digest = Some(digest_bytes(b"ready-after"));
        after.readiness_observation_digest = Some(digest_bytes(b"observation-after"));
        let receipt = kernel_receipt(&before, &after).unwrap_or_else(|_| unreachable!());
        assert!(validate_kernel_restart(&before, &after, &receipt).is_ok());
        let mut substituted = after.clone();
        substituted.kernel_generation_digest = Some(digest_bytes(b"substituted"));
        assert!(validate_kernel_restart(&before, &substituted, &receipt).is_err());

        let mut stale_readiness = after.clone();
        stale_readiness.ready_receipt_digest = before.ready_receipt_digest.clone();
        stale_readiness.readiness_observation_digest = before.readiness_observation_digest.clone();
        assert!(validate_kernel_restart(&before, &stale_readiness, &receipt).is_err());
    }

    #[test]
    fn post_operation_rejects_not_healthy_and_reused_kernel_lease() {
        let before = runtime_observation("RUNTIME_LIVE", Some(dynamic('a')));
        let mut after = runtime_observation("NOT_HEALTHY", Some(dynamic('b')));
        assert!(validate_post_runtime(&before, &after, true).is_err());
        after.report.status = "RUNTIME_LIVE".to_owned();
        after.dynamic_supervision = before.dynamic_supervision.clone();
        assert!(validate_post_runtime(&before, &after, true).is_err());
    }

    #[test]
    fn unknown_reference_binds_operation_and_all_request_digests() {
        let request = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("request-1"),
        )
        .unwrap_or_else(|_| unreachable!());
        let reference = eliot_host_service::runtime_control::runtime_control_unknown_ref(
            "kernel-restart",
            &request,
        );
        assert!(unknown_ref_matches_request(&reference, &request));
        let foreign = HostRuntimeControlRequest::new(
            HostRuntimeControlOperation::RestartKernel,
            handle("request-2"),
        )
        .unwrap_or_else(|_| unreachable!());
        assert!(!unknown_ref_matches_request(&reference, &foreign));
    }

    #[test]
    fn evidence_redaction_removes_root() {
        let message = redact_message(
            "C:\\ProgramData\\Eliot\\runtime failed",
            Path::new("C:\\ProgramData\\Eliot\\runtime"),
        );
        assert!(!message.contains("C:\\ProgramData\\Eliot\\runtime"));
        assert!(message.contains("<host-state-root>"));
    }

    #[test]
    fn host_server_contour_rejects_pid_start_image_and_sid_substitution() {
        let image = if cfg!(windows) {
            r"C:\Program Files\Eliot\eliot-host.exe"
        } else {
            "/opt/eliot/eliot-host"
        };
        let registration = ServiceRegistrationState {
            registration: "Matching".to_owned(),
            state: "Running".to_owned(),
            observed_process: None,
            observed_runtime: Some(eliot_runtime_status::ServiceRuntimeIdentity {
                process_id: 41,
                start_time_100ns: 42,
                image_path: image.to_owned(),
                runtime_identity_digest: "a".repeat(64),
            }),
            gap: "exact".to_owned(),
        };
        let observed = eliot_platform_windows::ProcessIdentity {
            process_id: 41,
            start_time_100ns: 42,
            image_path: image.to_owned(),
        };
        assert!(
            validate_host_server_contour(
                &registration,
                &observed,
                eliot_installation::LOCAL_SERVICE_SID,
                0,
            )
            .is_ok()
        );
        let mut substituted = observed.clone();
        substituted.process_id += 1;
        assert!(
            validate_host_server_contour(
                &registration,
                &substituted,
                eliot_installation::LOCAL_SERVICE_SID,
                0,
            )
            .is_err()
        );
        substituted = observed.clone();
        substituted.start_time_100ns += 1;
        assert!(
            validate_host_server_contour(
                &registration,
                &substituted,
                eliot_installation::LOCAL_SERVICE_SID,
                0,
            )
            .is_err()
        );
        substituted = observed.clone();
        substituted.image_path = if cfg!(windows) {
            r"C:\Program Files\Eliot\substituted.exe".to_owned()
        } else {
            "/opt/eliot/substituted".to_owned()
        };
        assert!(
            validate_host_server_contour(
                &registration,
                &substituted,
                eliot_installation::LOCAL_SERVICE_SID,
                0,
            )
            .is_err()
        );
        assert!(validate_host_server_contour(&registration, &observed, "S-1-5-18", 0).is_err());
    }

    #[test]
    fn exact_path_digest_binds_versioned_non_ascii_path_identity() {
        let first = Path::new(r"C:\Данные\Eliot\runtime");
        let substituted = Path::new(r"C:\Данные\Eliot\runtimе");
        assert_eq!(
            exact_path_identity_digest(first),
            exact_path_identity_digest(first)
        );
        assert_ne!(
            exact_path_identity_digest(first),
            exact_path_identity_digest(substituted)
        );
        assert_ne!(
            exact_path_identity_digest(first),
            digest_bytes(first.to_string_lossy().as_bytes())
        );
    }

    #[test]
    fn evidence_publication_is_create_new_and_no_clobber() {
        let directory = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let disposition = PulseDisposition::Blocked(BlockedPulse {
            pulse: Pulse::One,
            reason: "test".to_owned(),
            seam: "test".to_owned(),
            host_state_root_digest: "a".repeat(64),
            status_digest: None,
            journal_digest: None,
            redaction: "test".to_owned(),
        });
        let (path, digest) = write_evidence(directory.path(), Pulse::One, &disposition)
            .unwrap_or_else(|_| unreachable!());
        assert!(path.is_file());
        assert_eq!(digest.len(), 64);
        let bytes = std::fs::read(path).unwrap_or_else(|_| unreachable!());
        assert!(String::from_utf8_lossy(&bytes).contains("BLOCKED"));

        let fixed = directory.path().join("fixed-evidence.json");
        assert!(write_new_evidence_file(&fixed, b"first").is_ok());
        assert!(write_new_evidence_file(&fixed, b"second").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn evidence_directory_rejects_junction_ancestor() {
        let root = tempfile::tempdir().unwrap_or_else(|_| unreachable!());
        let target = root.path().join("target");
        let target_child = target.join("child");
        std::fs::create_dir_all(&target_child).unwrap_or_else(|_| unreachable!());
        let junction = root.path().join("junction");
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&target)
            .output()
            .unwrap_or_else(|_| unreachable!());
        assert!(
            output.status.success(),
            "junction fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(validate_evidence_dir(&junction.join("child")).is_err());
        std::fs::remove_dir(&junction).unwrap_or_else(|_| unreachable!());
    }
}
