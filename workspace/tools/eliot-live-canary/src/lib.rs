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

pub const CANARY_SCHEMA: &str = "eliot.runtime.live-canary.v2";
pub const DEFAULT_DEADLINE_MS: u64 = 30_000;
pub const MAX_DEADLINE_MS: u64 = 120_000;
const MAX_EVIDENCE_BYTES: usize = 128 * 1024;
const JOURNAL_FILE_NAME: &str = "host-state-journal.redb";
pub const HOST_RUNTIME_CONTROL_PIPE: &str = r"\\.\pipe\eliot\host\runtime-control-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Pulse {
    One = 1,
    Two = 2,
    Three = 3,
    Four = 4,
}

impl TryFrom<u8> for Pulse {
    type Error = CanaryError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            3 => Ok(Self::Three),
            4 => Ok(Self::Four),
            _ => Err(CanaryError::Invalid(format!(
                "pulse must be one of 1, 2, 3, 4 (got {value})"
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
    pub sequence: u64,
    pub last_checksum: Option<String>,
    pub kernel: Option<ProcessSnapshot>,
    pub kernel_generation: Option<String>,
    pub kernel_generation_digest: Option<String>,
    pub store: Option<ProcessSnapshot>,
    pub store_generation: Option<String>,
    pub store_fence: Option<String>,
    pub store_request_digest: Option<String>,
    pub ready_receipt_digest: Option<String>,
    pub readiness_observation_digest: Option<String>,
    pub integrity_gaps: Vec<String>,
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
        let result = tokio::time::timeout(self.config.deadline, self.run_bounded(deadline)).await;
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
            request_digest: Some(control.request_digest),
            receipt_digest: Some(control.receipt_digest),
            dynamic_supervision: after.dynamic_supervision.clone(),
        }))
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
    if Instant::now() >= deadline {
        return Err(CanaryError::Observation(
            "deadline exceeded after journal replay".to_owned(),
        ));
    }
    let contour = contour_from_state(&state)?;
    let dynamic_supervision = bind_dynamic_supervision(&report, &state)?;
    let journal_digest = digest_json(&contour)?;
    let status_digest = digest_json(&report)?;
    Ok(RuntimeObservation {
        report,
        status_digest,
        journal_digest,
        contour,
        dynamic_supervision,
    })
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
        sequence: state.sequence,
        last_checksum: state.last_checksum.as_ref().map(ToString::to_string),
        kernel,
        kernel_generation,
        kernel_generation_digest,
        store,
        store_generation: current_store.map(|record| record.generation.to_string()),
        store_fence: current_store.map(|record| record.store_fence.as_str().to_owned()),
        store_request_digest: current_store.map(|record| record.request_digest.as_str().to_owned()),
        ready_receipt_digest,
        readiness_observation_digest,
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
        ContourSnapshot {
            sequence: 3,
            last_checksum: Some("a".repeat(64)),
            kernel: Some(process(10, 100, "kernel.exe", "kernel-job")),
            kernel_generation: Some("lineage:3".to_owned()),
            kernel_generation_digest: Some(digest_bytes(b"kernel-before")),
            store: Some(process(20, 200, "store.exe", "store-job")),
            store_generation: Some("3".to_owned()),
            store_fence: Some("b".repeat(64)),
            store_request_digest: Some("c".repeat(64)),
            ready_receipt_digest: Some("d".repeat(64)),
            readiness_observation_digest: Some("e".repeat(64)),
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
