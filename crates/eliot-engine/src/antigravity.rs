use crate::work::WorkState;
use crate::worktree::{CandidateDiffCaptureInput, CandidateDiffService, WorktreeCleanupService};
use crate::{
    EngineError, ExternalReviewNormalizer, ProviderCallReservationOwner, ProviderInvocationJournal,
    ProviderOutputSpool, work_lease_is_active,
};
use eliot_types::{
    AntigravityArgvPolicy, AntigravityAuthCheck, AntigravityAuthCheckMethod, AntigravityAuthStatus,
    AntigravityBinaryCandidate, AntigravityBinaryCandidateSource, AntigravityBinaryResolution,
    AntigravityBinaryResolutionStatus, AntigravityBinaryResolverConfig,
    AntigravityBinarySignatureStatus, AntigravityCapabilities, AntigravityCapabilityProbe,
    AntigravityCommandContract, AntigravityContractSource, AntigravityDisableReceipt,
    AntigravityDisposableWorktreeSmokeEvidence, AntigravityDoctorStatus,
    AntigravityEnablementReceipt, AntigravityEnablementScope, AntigravityEnablementState,
    AntigravityEnvPolicy, AntigravityExecutionGateDecision, AntigravityExecutionGateDecisionKind,
    AntigravityGuiProcessProbe, AntigravityLiveSmokeMode, AntigravityLiveSmokeRequest,
    AntigravityLiveSmokeResult, AntigravityLiveSmokeStatus, AntigravityLiveTreeSnapshot,
    AntigravityLogFilePolicy, AntigravityMcpConfigStatus, AntigravityMcpConfigSurface,
    AntigravityMcpInvocationReceipt, AntigravityMcpRegistrationReceipt,
    AntigravityNormalizedResult, AntigravityOfficialCliInstallerReceipt,
    AntigravityOfficialPluginInstallReceipt, AntigravityOfficialPluginStatus,
    AntigravityOutputMode, AntigravityOutputRedactionReceipt, AntigravityPromptPolicy,
    AntigravityProviderState, AntigravityRealDoctorStatus, AntigravityRealReport,
    AntigravityReport, AntigravityReviewMode, AntigravityReviewRequest, AntigravityRun,
    AntigravityRunState, AntigravitySafetyReceipt, AntigravitySandboxPolicy,
    AntigravitySensitivePathPolicy, AntigravitySessionPolicy, AntigravityStdinMode,
    AntigravityTelemetryReport, AntigravityTrustReceipt, AntigravityVersionGateResult,
    AntigravityVersionGateStatus, AntigravityVisibilityReport, AntigravityWindowsInstallDiscovery,
    AntigravityWorkdirPolicy, BlobRef, CandidateDiff, ExternalOutputSchemaKind,
    ExternalReviewBudget, ExternalReviewJob, ExternalReviewJobStatus, ExternalReviewRequest,
    ExternalReviewRole, ProcessReapReceipt, ProjectId, ProviderInvocationAttempt,
    ProviderInvocationState, ProviderRoutePolicy, ProviderTimeoutClass, TaintClass, TaskId,
    WorkLease, WorkLeaseId, WorktreeLease, WorktreeLeaseId, WorktreeLeaseState, WriteId,
    inspect_secret_bytes,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
#[cfg(test)]
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{Duration as StdDuration, Instant};
use time::{Duration, OffsetDateTime};

// The official CLI contract uses --print-timeout=300s. The governor timeout must
// remain bounded while allowing the CLI to emit its own normalized timeout result.
const DEFAULT_TIMEOUT_MS: u64 = 310_000;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 64 * 1024;
const HELP_PROBE_TIMEOUT_MS: u64 = 2_000;
const VERSION_PROBE_TIMEOUT_MS: u64 = 2_000;
const MINIMUM_AGY_VERSION: (u64, u64, u64) = (1, 1, 1);
const MINIMUM_AGY_VERSION_TEXT: &str = "1.1.1";
const ELIOT_MCP_SERVER_NAME: &str = "eliot-governor";
const OFFICIAL_PLUGIN_SCHEMA: &str = "https://antigravity.google/schemas/v1/plugin.json";
const OFFICIAL_PLUGIN_NAME: &str = "eliot-antigravity";
#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityBinaryResolver;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityCapabilityProbeService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityCommandContractService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityEnvPolicyService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravitySafetyPolicy;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityExecutionGate;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityRunner;

#[derive(Clone)]
pub struct ProviderProcessSpec {
    pub operation_id: String,
    pub invocation_id: Option<String>,
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: Vec<(OsString, OsString)>,
    pub stdin_payload: Option<Vec<u8>>,
    pub route_policy: ProviderRoutePolicy,
    pub cancellation: crate::runtime_supervision::CancellationToken,
    pub deadline: tokio::time::Instant,
    pub runtime_contract_sha256: Option<String>,
    pub role_lease_id: Option<String>,
    pub role_lease_epoch: Option<u64>,
}

#[derive(Clone, Debug)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "the process result records independent bounded-cleanup outcomes"
)]
pub struct ProviderProcessOutcome {
    pub exit_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_total_bytes: u64,
    pub stderr_total_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub timed_out: bool,
    pub timeout_class: Option<ProviderTimeoutClass>,
    pub cancelled: bool,
    pub worker_error: Option<String>,
    pub observed_processes: Vec<eliot_windows_ipc::ProcessImageIdentity>,
    pub process_started_at: OffsetDateTime,
    pub first_output_at: Option<OffsetDateTime>,
    pub last_output_at: Option<OffsetDateTime>,
    pub process_exit_at: Option<OffsetDateTime>,
    pub cleanup_completed_at: OffsetDateTime,
    pub reap_receipt: ProcessReapReceipt,
}

pub type BoxProviderProcessFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ProviderProcessOutcome, EngineError>> + Send + 'a>>;

pub trait ProviderProcessRunner: Send + Sync {
    fn run<'a>(
        &'a self,
        spec: ProviderProcessSpec,
        on_spawned: &'a mut (dyn FnMut(u32) -> Result<(), EngineError> + Send),
    ) -> BoxProviderProcessFuture<'a>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityTextOutputNormalizer;

#[derive(Clone, Copy, Debug, Default)]
pub struct AgyMcpCompatibilityAuditService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityTelemetryService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityDoctorIntegration;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityMcpBoundaryService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityEnablementService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityAuthCheckService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityLiveSmokeService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityRollbackService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityRealExecutionDoctor;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityGuiProcessProbeService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityWindowsInstallDiscoveryService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityVersionGateService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityOfficialCliInstallerService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityMcpConfigService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityOfficialPluginService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityVisibilityService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityDisposableWorktreeSmokeService;

impl AntigravityBinaryResolver {
    pub fn default_config() -> AntigravityBinaryResolverConfig {
        AntigravityBinaryResolverConfig {
            explicit_binary: None,
            search_path_names: vec!["agy".to_owned(), "antigravity".to_owned()],
            reject_temp_download_paths: true,
            allow_install: false,
        }
    }

    pub fn resolve(&self, config: &AntigravityBinaryResolverConfig) -> AntigravityBinaryResolution {
        let local_app_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
        self.resolve_with_local_app_data(config, local_app_data.as_deref())
    }

    pub fn resolve_with_local_app_data(
        &self,
        config: &AntigravityBinaryResolverConfig,
        local_app_data: Option<&Path>,
    ) -> AntigravityBinaryResolution {
        let mut candidates = Vec::new();
        let mut detection_commands = Vec::new();
        if let Some(path) = &config.explicit_binary {
            candidates.push(Self::evaluate_candidate_with_policy(
                Path::new(path),
                AntigravityBinaryCandidateSource::ExplicitConfig,
                config.reject_temp_download_paths,
                cfg!(windows),
            ));
        }
        if let Some(local_app_data) = local_app_data {
            let path = Self::official_windows_cli_path(local_app_data);
            detection_commands.push(format!("filesystem probe {}", path_for_record(&path)));
            if path.exists() {
                candidates.push(Self::evaluate_candidate_with_policy(
                    &path,
                    AntigravityBinaryCandidateSource::LocalAppDataOfficialInstall,
                    config.reject_temp_download_paths,
                    cfg!(windows),
                ));
            }
        }
        for name in &config.search_path_names {
            detection_commands.push(format!("where.exe {name}"));
            for path in where_command_hits(name) {
                let source = if name == "agy" {
                    AntigravityBinaryCandidateSource::WhereAgy
                } else {
                    AntigravityBinaryCandidateSource::WhereAntigravity
                };
                candidates.push(Self::evaluate_candidate_with_policy(
                    &path,
                    source,
                    config.reject_temp_download_paths,
                    cfg!(windows),
                ));
            }
        }
        Self::finish_resolution(candidates, detection_commands)
    }

    pub fn official_windows_cli_path(local_app_data: &Path) -> PathBuf {
        local_app_data.join("agy").join("bin").join("agy.exe")
    }

    pub fn resolve_known_paths(
        &self,
        paths: Vec<(PathBuf, AntigravityBinaryCandidateSource)>,
        reject_temp_download_paths: bool,
    ) -> AntigravityBinaryResolution {
        let candidates = paths
            .into_iter()
            .map(|(path, source)| {
                self.evaluate_candidate(&path, source, reject_temp_download_paths)
            })
            .collect::<Vec<_>>();
        Self::finish_resolution(
            candidates,
            vec![
                "where.exe agy".to_owned(),
                "where.exe antigravity".to_owned(),
            ],
        )
    }

    pub fn evaluate_candidate(
        &self,
        path: &Path,
        source: AntigravityBinaryCandidateSource,
        reject_temp_download_paths: bool,
    ) -> AntigravityBinaryCandidate {
        Self::evaluate_candidate_with_policy(path, source, reject_temp_download_paths, false)
    }

    fn evaluate_candidate_with_policy(
        path: &Path,
        source: AntigravityBinaryCandidateSource,
        reject_temp_download_paths: bool,
        require_valid_signature: bool,
    ) -> AntigravityBinaryCandidate {
        let mut reasons = Vec::new();
        let exists = path.exists();
        if !exists {
            reasons.push("binary path does not exist".to_owned());
        }
        if exists && path.is_dir() {
            reasons.push("binary path is a directory".to_owned());
        }
        if reject_temp_download_paths && looks_untrusted_download_or_temp(path) {
            reasons.push("binary path is under temp/downloads".to_owned());
        }
        if exists && !path.is_dir() && !looks_executable(path) {
            reasons.push("binary path does not look executable".to_owned());
        }
        let (signature_status, signature_subject) = if exists && !path.is_dir() {
            if require_valid_signature {
                authenticode_signature(path)
            } else {
                (AntigravityBinarySignatureStatus::NotChecked, None)
            }
        } else {
            (AntigravityBinarySignatureStatus::NotChecked, None)
        };
        if require_valid_signature && signature_status != AntigravityBinarySignatureStatus::Valid {
            reasons.push("binary does not have a valid Authenticode signature".to_owned());
        } else if require_valid_signature
            && !signature_subject
                .as_deref()
                .is_some_and(|subject| subject.to_ascii_lowercase().contains("google"))
        {
            reasons
                .push("binary Authenticode signer is not the official Google publisher".to_owned());
        }
        let canonical_path = path.canonicalize().ok().as_deref().map(path_for_record);
        let accepted = reasons.is_empty();
        let trust_receipt = AntigravityTrustReceipt {
            candidate_path: path_for_record(path),
            canonical_path: canonical_path.clone(),
            source,
            accepted,
            signature_status,
            signature_subject: signature_subject.clone(),
            reasons: if accepted {
                vec!["candidate accepted by local trust policy".to_owned()]
            } else {
                reasons.clone()
            },
            created_at: OffsetDateTime::now_utc(),
        };
        AntigravityBinaryCandidate {
            path: path_for_record(path),
            canonical_path,
            source,
            accepted,
            signature_status,
            signature_subject,
            rejection_reasons: reasons,
            trust_receipt,
        }
    }

    fn finish_resolution(
        candidates: Vec<AntigravityBinaryCandidate>,
        detection_commands: Vec<String>,
    ) -> AntigravityBinaryResolution {
        let accepted = candidates
            .iter()
            .filter(|candidate| candidate.accepted)
            .collect::<Vec<_>>();
        let selected_path = accepted.first().and_then(|candidate| {
            candidate
                .canonical_path
                .clone()
                .or_else(|| Some(candidate.path.clone()))
        });
        let status = match (selected_path.is_some(), candidates.is_empty()) {
            (true, _) => AntigravityBinaryResolutionStatus::Resolved,
            (false, true) => AntigravityBinaryResolutionStatus::NotFound,
            (false, false) => AntigravityBinaryResolutionStatus::Rejected,
        };
        let message = match status {
            AntigravityBinaryResolutionStatus::Resolved => {
                "Antigravity CLI candidate resolved but remains disabled by default".to_owned()
            }
            AntigravityBinaryResolutionStatus::NotFound => {
                "Antigravity CLI was not found by governed probes".to_owned()
            }
            AntigravityBinaryResolutionStatus::Rejected => {
                "Antigravity CLI candidates were rejected by local trust policy".to_owned()
            }
            AntigravityBinaryResolutionStatus::Ambiguous => {
                "Antigravity CLI resolution was ambiguous".to_owned()
            }
        };
        AntigravityBinaryResolution {
            status,
            selected_path,
            candidates,
            detection_commands,
            install_attempted: false,
            plain_agy_invoked: false,
            message,
            resolved_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityGuiProcessProbeService {
    pub fn probe(&self) -> AntigravityGuiProcessProbe {
        let names = vec![
            "Antigravity.exe".to_owned(),
            "Antigravity Helper.exe".to_owned(),
        ];
        let output = ProcessCommand::new("tasklist.exe")
            .args(["/FO", "CSV", "/NH"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();
        match output {
            Ok(output) if output.status.success() => self.from_process_listing(
                &String::from_utf8_lossy(&output.stdout),
                &names,
                Some("tasklist.exe /FO CSV /NH".to_owned()),
            ),
            Ok(_) => AntigravityGuiProcessProbe {
                component: "antigravity_gui_process_probe".to_owned(),
                process_names_checked: names,
                matching_processes: Vec::new(),
                gui_running: false,
                command_invoked: Some("tasklist.exe /FO CSV /NH".to_owned()),
                probe_succeeded: false,
                warnings: vec!["tasklist process probe returned a failure status".to_owned()],
                checked_at: OffsetDateTime::now_utc(),
            },
            Err(error) => AntigravityGuiProcessProbe {
                component: "antigravity_gui_process_probe".to_owned(),
                process_names_checked: names,
                matching_processes: Vec::new(),
                gui_running: false,
                command_invoked: Some("tasklist.exe /FO CSV /NH".to_owned()),
                probe_succeeded: false,
                warnings: vec![format!("tasklist process probe failed: {error}")],
                checked_at: OffsetDateTime::now_utc(),
            },
        }
    }

    pub fn from_process_listing(
        &self,
        listing: &str,
        process_names: &[String],
        command_invoked: Option<String>,
    ) -> AntigravityGuiProcessProbe {
        let lower = listing.to_ascii_lowercase();
        let matching_processes = process_names
            .iter()
            .filter(|name| lower.contains(&name.to_ascii_lowercase()))
            .cloned()
            .collect::<Vec<_>>();
        AntigravityGuiProcessProbe {
            component: "antigravity_gui_process_probe".to_owned(),
            process_names_checked: process_names.to_vec(),
            gui_running: !matching_processes.is_empty(),
            matching_processes,
            command_invoked,
            probe_succeeded: true,
            warnings: Vec::new(),
            checked_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityWindowsInstallDiscoveryService {
    pub fn discover(&self, local_app_data: Option<&Path>) -> AntigravityWindowsInstallDiscovery {
        let official_cli_path =
            local_app_data.map(AntigravityBinaryResolver::official_windows_cli_path);
        let official_cli_exists = official_cli_path
            .as_ref()
            .is_some_and(|path| path.is_file());
        let (signature_status, signature_subject) = official_cli_path
            .as_deref()
            .filter(|_| official_cli_exists)
            .map_or(
                (AntigravityBinarySignatureStatus::NotChecked, None),
                authenticode_signature,
            );
        AntigravityWindowsInstallDiscovery {
            component: "antigravity_windows_install_discovery".to_owned(),
            local_app_data: local_app_data.map(path_for_record),
            official_cli_path: official_cli_path.as_deref().map(path_for_record),
            official_cli_exists,
            candidate_source: AntigravityBinaryCandidateSource::LocalAppDataOfficialInstall,
            signature_status,
            signature_subject,
            detection_only: true,
            discovered_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityVersionGateService {
    pub fn evaluate_output(&self, output: &str) -> AntigravityVersionGateResult {
        let parsed = parse_semantic_version(output);
        let (status, allowed, reasons) = match parsed.as_ref() {
            Some((major, minor, patch, _)) if (*major, *minor, *patch) >= MINIMUM_AGY_VERSION => (
                AntigravityVersionGateStatus::Compatible,
                true,
                vec![format!(
                    "Antigravity CLI satisfies minimum version {MINIMUM_AGY_VERSION_TEXT}"
                )],
            ),
            Some((major, minor, patch, _)) => (
                AntigravityVersionGateStatus::TooOld,
                false,
                vec![format!(
                    "Antigravity CLI {major}.{minor}.{patch} is older than required {MINIMUM_AGY_VERSION_TEXT}"
                )],
            ),
            None => (
                AntigravityVersionGateStatus::Unparseable,
                false,
                vec![
                    "Antigravity CLI version output did not contain a semantic version".to_owned(),
                ],
            ),
        };
        AntigravityVersionGateResult {
            component: "antigravity_version_gate".to_owned(),
            command: "agy.exe --version".to_owned(),
            raw_output: truncate_text(output.trim(), 2_000),
            parsed_version: parsed.map(|(_, _, _, text)| text),
            minimum_version: MINIMUM_AGY_VERSION_TEXT.to_owned(),
            status,
            allowed,
            reasons,
            checked_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn probe(&self, binary: &Path) -> AntigravityVersionGateResult {
        match run_bounded_command(binary, &["--version"], VERSION_PROBE_TIMEOUT_MS) {
            Ok((output, true, _)) => AntigravityVersionGateResult {
                component: "antigravity_version_gate".to_owned(),
                command: format!("{} --version", path_for_record(binary)),
                raw_output: truncate_text(&output, 2_000),
                parsed_version: None,
                minimum_version: MINIMUM_AGY_VERSION_TEXT.to_owned(),
                status: AntigravityVersionGateStatus::ProbeTimedOut,
                allowed: false,
                reasons: vec!["Antigravity CLI version probe timed out".to_owned()],
                checked_at: OffsetDateTime::now_utc(),
            },
            Ok((output, false, true)) => {
                let mut result = self.evaluate_output(&output);
                result.command = format!("{} --version", path_for_record(binary));
                result
            }
            Ok((output, false, false)) => AntigravityVersionGateResult {
                component: "antigravity_version_gate".to_owned(),
                command: format!("{} --version", path_for_record(binary)),
                raw_output: truncate_text(&output, 2_000),
                parsed_version: None,
                minimum_version: MINIMUM_AGY_VERSION_TEXT.to_owned(),
                status: AntigravityVersionGateStatus::ProbeFailed,
                allowed: false,
                reasons: vec!["Antigravity CLI version probe returned failure".to_owned()],
                checked_at: OffsetDateTime::now_utc(),
            },
            Err(error) => AntigravityVersionGateResult {
                component: "antigravity_version_gate".to_owned(),
                command: format!("{} --version", path_for_record(binary)),
                raw_output: String::new(),
                parsed_version: None,
                minimum_version: MINIMUM_AGY_VERSION_TEXT.to_owned(),
                status: AntigravityVersionGateStatus::ProbeFailed,
                allowed: false,
                reasons: vec![format!("Antigravity CLI version probe failed: {error}")],
                checked_at: OffsetDateTime::now_utc(),
            },
        }
    }

    pub async fn probe_supervised(
        &self,
        binary: &Path,
        runner: &dyn ProviderProcessRunner,
    ) -> AntigravityVersionGateResult {
        match run_supervised_provider_probe(
            binary,
            "--version",
            "antigravity-version-probe",
            VERSION_PROBE_TIMEOUT_MS,
            runner,
        )
        .await
        {
            Ok((output, true, _)) => AntigravityVersionGateResult {
                component: "antigravity_version_gate".to_owned(),
                command: format!("{} --version", path_for_record(binary)),
                raw_output: truncate_text(&output, 2_000),
                parsed_version: None,
                minimum_version: MINIMUM_AGY_VERSION_TEXT.to_owned(),
                status: AntigravityVersionGateStatus::ProbeTimedOut,
                allowed: false,
                reasons: vec!["Antigravity CLI version probe timed out".to_owned()],
                checked_at: OffsetDateTime::now_utc(),
            },
            Ok((output, false, true)) => {
                let mut result = self.evaluate_output(&output);
                result.command = format!("{} --version", path_for_record(binary));
                result
            }
            Ok((output, false, false)) => AntigravityVersionGateResult {
                component: "antigravity_version_gate".to_owned(),
                command: format!("{} --version", path_for_record(binary)),
                raw_output: truncate_text(&output, 2_000),
                parsed_version: None,
                minimum_version: MINIMUM_AGY_VERSION_TEXT.to_owned(),
                status: AntigravityVersionGateStatus::ProbeFailed,
                allowed: false,
                reasons: vec!["Antigravity CLI version probe returned failure".to_owned()],
                checked_at: OffsetDateTime::now_utc(),
            },
            Err(error) => AntigravityVersionGateResult {
                component: "antigravity_version_gate".to_owned(),
                command: format!("{} --version", path_for_record(binary)),
                raw_output: String::new(),
                parsed_version: None,
                minimum_version: MINIMUM_AGY_VERSION_TEXT.to_owned(),
                status: AntigravityVersionGateStatus::ProbeFailed,
                allowed: false,
                reasons: vec![format!("Antigravity CLI version probe failed: {error}")],
                checked_at: OffsetDateTime::now_utc(),
            },
        }
    }
}

impl AntigravityOfficialCliInstallerService {
    pub fn status_receipt(
        &self,
        discovery: &AntigravityWindowsInstallDiscovery,
        version_gate: Option<&AntigravityVersionGateResult>,
    ) -> AntigravityOfficialCliInstallerReceipt {
        AntigravityOfficialCliInstallerReceipt {
            component: "antigravity_official_cli_installer_receipt".to_owned(),
            installer_url: "https://antigravity.google/cli/install.ps1".to_owned(),
            installed_path: discovery.official_cli_path.clone().unwrap_or_default(),
            attempted: false,
            installed: discovery.official_cli_exists,
            signature_verified: discovery.signature_status
                == AntigravityBinarySignatureStatus::Valid,
            version_gate_passed: version_gate.is_some_and(|gate| gate.allowed),
            install_command_exposed: false,
            reasons: vec![
                "status-only receipt; Governor does not download or execute installer scripts"
                    .to_owned(),
            ],
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityCapabilityProbeService {
    pub fn probe_from_resolution(
        &self,
        resolution: &AntigravityBinaryResolution,
    ) -> AntigravityCapabilityProbe {
        let Some(binary_path) = &resolution.selected_path else {
            return Self::disabled_probe(
                resolution,
                AntigravityProviderState::NotInstalled,
                "no Antigravity CLI binary selected",
            );
        };
        match run_help_probe(Path::new(binary_path), HELP_PROBE_TIMEOUT_MS) {
            Ok((text, timed_out)) => {
                if timed_out {
                    AntigravityCapabilityProbe {
                        provider_state: AntigravityProviderState::Incompatible,
                        binary_path: Some(binary_path.clone()),
                        help_probe_command: Some(format!("{binary_path} --help")),
                        capabilities: AntigravityCapabilities::default(),
                        timeout_enforced: true,
                        plain_agy_invoked: false,
                        install_attempted: false,
                        output_excerpt: truncate_text(&text, 2_000),
                        message: "Antigravity help probe timed out".to_owned(),
                        probed_at: OffsetDateTime::now_utc(),
                    }
                } else {
                    self.probe_from_help(binary_path, &text)
                }
            }
            Err(error) => AntigravityCapabilityProbe {
                provider_state: AntigravityProviderState::Incompatible,
                binary_path: Some(binary_path.clone()),
                help_probe_command: Some(format!("{binary_path} --help")),
                capabilities: AntigravityCapabilities::default(),
                timeout_enforced: true,
                plain_agy_invoked: false,
                install_attempted: false,
                output_excerpt: String::new(),
                message: format!("Antigravity help probe failed: {error}"),
                probed_at: OffsetDateTime::now_utc(),
            },
        }
    }

    pub async fn probe_from_resolution_supervised(
        &self,
        resolution: &AntigravityBinaryResolution,
        runner: &dyn ProviderProcessRunner,
    ) -> AntigravityCapabilityProbe {
        let Some(binary_path) = &resolution.selected_path else {
            return Self::disabled_probe(
                resolution,
                AntigravityProviderState::NotInstalled,
                "no Antigravity CLI binary selected",
            );
        };
        match run_supervised_provider_probe(
            Path::new(binary_path),
            "--help",
            "antigravity-help-probe",
            HELP_PROBE_TIMEOUT_MS,
            runner,
        )
        .await
        {
            Ok((text, true, _)) => AntigravityCapabilityProbe {
                provider_state: AntigravityProviderState::Incompatible,
                binary_path: Some(binary_path.clone()),
                help_probe_command: Some(format!("{binary_path} --help")),
                capabilities: AntigravityCapabilities::default(),
                timeout_enforced: true,
                plain_agy_invoked: false,
                install_attempted: false,
                output_excerpt: truncate_text(&text, 2_000),
                message: "Antigravity help probe timed out".to_owned(),
                probed_at: OffsetDateTime::now_utc(),
            },
            Ok((text, false, _)) => self.probe_from_help(binary_path, &text),
            Err(error) => AntigravityCapabilityProbe {
                provider_state: AntigravityProviderState::Incompatible,
                binary_path: Some(binary_path.clone()),
                help_probe_command: Some(format!("{binary_path} --help")),
                capabilities: AntigravityCapabilities::default(),
                timeout_enforced: true,
                plain_agy_invoked: false,
                install_attempted: false,
                output_excerpt: String::new(),
                message: format!("Antigravity help probe failed: {error}"),
                probed_at: OffsetDateTime::now_utc(),
            },
        }
    }

    pub fn probe_from_help(
        &self,
        binary_path: &str,
        help_text: &str,
    ) -> AntigravityCapabilityProbe {
        let capabilities = parse_capabilities(help_text);
        let provider_state = if capabilities.print_mode && capabilities.prompt_arg {
            AntigravityProviderState::DetectedDisabled
        } else {
            AntigravityProviderState::Incompatible
        };
        AntigravityCapabilityProbe {
            provider_state,
            binary_path: Some(binary_path.to_owned()),
            help_probe_command: Some(format!("{binary_path} --help")),
            capabilities,
            timeout_enforced: true,
            plain_agy_invoked: false,
            install_attempted: false,
            output_excerpt: truncate_text(help_text, 2_000),
            message: if provider_state == AntigravityProviderState::DetectedDisabled {
                "Antigravity CLI supports governed text print mode and remains disabled by default"
                    .to_owned()
            } else {
                "Antigravity CLI help did not expose required noninteractive flags".to_owned()
            },
            probed_at: OffsetDateTime::now_utc(),
        }
    }

    fn disabled_probe(
        resolution: &AntigravityBinaryResolution,
        state: AntigravityProviderState,
        message: &str,
    ) -> AntigravityCapabilityProbe {
        AntigravityCapabilityProbe {
            provider_state: state,
            binary_path: resolution.selected_path.clone(),
            help_probe_command: None,
            capabilities: AntigravityCapabilities::default(),
            timeout_enforced: true,
            plain_agy_invoked: false,
            install_attempted: false,
            output_excerpt: String::new(),
            message: message.to_owned(),
            probed_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityCommandContractService {
    pub fn build(
        &self,
        resolution: &AntigravityBinaryResolution,
        probe: &AntigravityCapabilityProbe,
    ) -> AntigravityCommandContract {
        let mut limitations = Vec::new();
        if probe.capabilities.dangerously_skip_permissions_seen {
            limitations
                .push("--dangerously-skip-permissions is visible but always forbidden".into());
        }
        if !probe.capabilities.model_cli_arg {
            limitations.push("model selection is not exposed as a governed CLI flag".into());
        }
        if probe.provider_state == AntigravityProviderState::NotInstalled {
            limitations.push("Antigravity CLI is not installed or not found".into());
        }
        let noninteractive_supported =
            probe.capabilities.print_mode && probe.capabilities.prompt_arg;
        let review_args = if noninteractive_supported {
            let mut args = vec!["--mode=plan".to_owned(), "--print".to_owned()];
            if probe.capabilities.print_timeout {
                args.push("--print-timeout=300s".to_owned());
            }
            if probe.capabilities.sandbox {
                args.push("--sandbox=true".to_owned());
            }
            args
        } else {
            Vec::new()
        };
        AntigravityCommandContract {
            provider_id: "antigravity-cli".to_owned(),
            binary_path: resolution.selected_path.clone(),
            source: if noninteractive_supported {
                AntigravityContractSource::HelpProbe
            } else if resolution.selected_path.is_some() {
                AntigravityContractSource::Disabled
            } else {
                AntigravityContractSource::Fixture
            },
            noninteractive_supported,
            review_args,
            argv_policy: default_argv_policy(),
            prompt_policy: default_prompt_policy(),
            env_policy: default_env_policy(),
            sensitive_path_policy: default_sensitive_path_policy(),
            stdin_mode: AntigravityStdinMode::DevNull,
            output_mode: AntigravityOutputMode::Text,
            workdir_policy: AntigravityWorkdirPolicy::DisposableWorktreeForCandidateImplementation,
            sandbox_policy: if probe.capabilities.sandbox {
                AntigravitySandboxPolicy::RequiredWhenSupported
            } else {
                AntigravitySandboxPolicy::Unavailable
            },
            log_file_policy: AntigravityLogFilePolicy {
                capture_to_blob: true,
                expose_raw_path: false,
            },
            session_policy: AntigravitySessionPolicy {
                allow_continue: false,
                allow_conversation_id_from_user: false,
                drop_ungoverned_conversation_env: true,
            },
            dangerous_flags_forbidden: true,
            json_output_required: false,
            model_cli_arg_supported: probe.capabilities.model_cli_arg,
            model_selection_message: "No governed --model flag is used unless local help proves one; configure model in Antigravity itself."
                .to_owned(),
            limitations,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn fixture_contract(&self) -> AntigravityCommandContract {
        let resolution = AntigravityBinaryResolution {
            status: AntigravityBinaryResolutionStatus::NotFound,
            selected_path: None,
            candidates: Vec::new(),
            detection_commands: vec![
                "where.exe agy".to_owned(),
                "where.exe antigravity".to_owned(),
            ],
            install_attempted: false,
            plain_agy_invoked: false,
            message: "fixture contract because agy is absent".to_owned(),
            resolved_at: OffsetDateTime::now_utc(),
        };
        let probe = AntigravityCapabilityProbe {
            provider_state: AntigravityProviderState::NotInstalled,
            binary_path: None,
            help_probe_command: None,
            capabilities: AntigravityCapabilities::default(),
            timeout_enforced: true,
            plain_agy_invoked: false,
            install_attempted: false,
            output_excerpt: String::new(),
            message: "fixture only".to_owned(),
            probed_at: OffsetDateTime::now_utc(),
        };
        self.build(&resolution, &probe)
    }

    pub fn typed_review_argv(
        &self,
        contract: &AntigravityCommandContract,
        prompt: &str,
    ) -> Result<Vec<String>, EngineError> {
        AntigravitySafetyPolicy.validate_prompt(prompt, &contract.prompt_policy)?;
        let binary = contract
            .binary_path
            .clone()
            .unwrap_or_else(|| "agy-fixture".to_owned());
        let mut argv = vec![binary];
        argv.extend(contract.review_args.clone());
        argv.push(fused_arg("--prompt", prompt)?);
        if argv
            .iter()
            .any(|arg| arg == "--dangerously-skip-permissions")
        {
            return Err(rejected(
                "dangerous Antigravity permission bypass flag rejected",
            ));
        }
        Ok(argv)
    }

    pub fn reject_shell_interpolation(&self, value: &str) -> Result<(), EngineError> {
        if contains_shell_interpolation(value) {
            return Err(rejected(
                "shell interpolation is not allowed in Antigravity prompts",
            ));
        }
        Ok(())
    }
}

impl AntigravityEnvPolicyService {
    pub fn filtered_env(&self, input: &[(String, String)]) -> Vec<(String, String)> {
        let mut output = Vec::new();
        for (name, value) in input {
            if should_drop_env_name(name) {
                continue;
            }
            output.push((name.clone(), value.clone()));
        }
        output.push(("AGY_CLI_DISABLE_AUTO_UPDATE".to_owned(), "1".to_owned()));
        output.push(("AGY_CLI_HIDE_ACCOUNT_INFO".to_owned(), "1".to_owned()));
        output
    }

    pub fn minimal_windows_env(&self, input: &[(String, String)]) -> Vec<(String, String)> {
        let filtered = self.filtered_env(input);
        filtered
            .into_iter()
            .filter(|(name, _)| {
                is_safe_runtime_env_name(name)
                    || matches!(
                        name.as_str(),
                        "AGY_CLI_DISABLE_AUTO_UPDATE" | "AGY_CLI_HIDE_ACCOUNT_INFO"
                    )
            })
            .collect()
    }

    pub fn dropped_names(&self, input: &[(String, String)]) -> Vec<String> {
        input
            .iter()
            .filter_map(|(name, _value)| {
                if should_drop_env_name(name) {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn minimal_windows_dropped_names(&self, input: &[(String, String)]) -> Vec<String> {
        input
            .iter()
            .filter(|(name, _value)| should_drop_env_name(name) || !is_safe_runtime_env_name(name))
            .map(|(name, _value)| name.clone())
            .collect()
    }
}

impl AntigravitySafetyPolicy {
    pub fn validate_prompt(
        &self,
        prompt: &str,
        policy: &AntigravityPromptPolicy,
    ) -> Result<(), EngineError> {
        if prompt.len() > policy.max_prompt_bytes {
            return Err(rejected("Antigravity prompt exceeds max prompt bytes"));
        }
        let lower = prompt.to_ascii_lowercase();
        if policy.deny_remote_pipe_install
            && ((lower.contains("curl") && lower.contains('|'))
                || (lower.contains("irm ") && lower.contains("iex")))
        {
            return Err(rejected("remote pipe install command is forbidden"));
        }
        if policy.deny_destructive_commands
            && [
                "remove-item -recurse",
                "rm -rf",
                "git reset --hard",
                "del /s",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
        {
            return Err(rejected("destructive command is forbidden"));
        }
        if policy.deny_sensitive_paths
            && [
                "id_rsa",
                ".ssh",
                "appdata",
                "credential",
                "token",
                ".eliot-governor/data",
            ]
            .iter()
            .any(|needle| lower.contains(needle))
        {
            return Err(rejected(
                "sensitive path or credential reference is forbidden",
            ));
        }
        AntigravityCommandContractService.reject_shell_interpolation(prompt)
    }
}

impl AntigravityExecutionGate {
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &self,
        request: &AntigravityReviewRequest,
        resolution: &AntigravityBinaryResolution,
        probe: &AntigravityCapabilityProbe,
        contract: &AntigravityCommandContract,
        work_lease: Option<&WorkLease>,
        worktree_lease: Option<&WorktreeLease>,
        provider_gate_passed: bool,
        incident_lockdown: bool,
        dry_run: bool,
    ) -> AntigravityExecutionGateDecision {
        let mut reasons = Vec::new();
        if incident_lockdown {
            return gate(
                AntigravityExecutionGateDecisionKind::Deny,
                vec!["incident lockdown blocks Antigravity execution".to_owned()],
            );
        }
        if dry_run {
            return AntigravityExecutionGateDecision {
                decision: AntigravityExecutionGateDecisionKind::AllowDryRun,
                reasons: vec![
                    "dry-run uses fixture runner and performs no provider execution".to_owned(),
                ],
                candidate_only: true,
                patch_permission_granted: false,
            };
        }
        if !provider_gate_passed {
            return gate(
                AntigravityExecutionGateDecisionKind::RequireProviderGate,
                vec!["provider integration eval gate has not passed".to_owned()],
            );
        }
        if !request.provider_enabled {
            return gate(
                AntigravityExecutionGateDecisionKind::RequireProviderEnable,
                vec!["real Antigravity provider execution is disabled by default".to_owned()],
            );
        }
        if request.mode == AntigravityReviewMode::CandidateImplementation
            && request
                .last_accepted_packet_id
                .as_deref()
                .is_none_or(|packet_id| packet_id.trim().is_empty())
        {
            return gate(
                AntigravityExecutionGateDecisionKind::RequireAcceptedPacket,
                vec![
                    "mutating Antigravity role launch requires the last accepted UL packet gate"
                        .to_owned(),
                ],
            );
        }
        if resolution.selected_path.is_none()
            || !contract.noninteractive_supported
            || probe.provider_state == AntigravityProviderState::NotInstalled
        {
            return gate(
                AntigravityExecutionGateDecisionKind::Deny,
                vec!["Antigravity binary or governed command contract is unavailable".to_owned()],
            );
        }
        let Some(work_lease) = work_lease.filter(|lease| {
            request.work_lease_id == Some(lease.work_lease_id)
                && work_lease_is_active(lease)
                && lease.project_id == request.project_id
                && lease.task_id == request.task_id
        }) else {
            return gate(
                AntigravityExecutionGateDecisionKind::RequireWorkLease,
                vec![
                    "real Antigravity execution requires the active matching WorkLease".to_owned(),
                ],
            );
        };
        reasons.push("active matching WorkLease present".to_owned());

        let Some(_worktree_lease) = worktree_lease.filter(|lease| {
            lease.state == WorktreeLeaseState::Active
                && lease.expires_at >= OffsetDateTime::now_utc()
                && request.worktree_lease_id == Some(lease.worktree_lease_id)
                && lease.work_lease_id == work_lease.work_lease_id
                && lease.project_id == request.project_id
                && lease.task_id == request.task_id
                && lease.work_item_id == work_lease.work_item_id
                && lease.holder_session_id == work_lease.agent_session_id
        }) else {
            return gate(
                AntigravityExecutionGateDecisionKind::RequireWorktreeLease,
                vec![
                    "every real Antigravity execution requires an active matching disposable WorktreeLease"
                        .to_owned(),
                ],
            );
        };
        reasons.push("active matching disposable WorktreeLease present".to_owned());
        AntigravityExecutionGateDecision {
            decision: AntigravityExecutionGateDecisionKind::AllowRealRun,
            reasons,
            candidate_only: true,
            patch_permission_granted: false,
        }
    }
}

impl AntigravityEnablementService {
    pub fn state_from_probe(
        &self,
        probe: &AntigravityCapabilityProbe,
        auth: Option<&AntigravityAuthCheck>,
    ) -> AntigravityEnablementState {
        match probe.provider_state {
            AntigravityProviderState::NotInstalled => AntigravityEnablementState::NotInstalled,
            AntigravityProviderState::Incompatible
            | AntigravityProviderState::DetectedButNoNonInteractiveMode => {
                AntigravityEnablementState::InstalledNoNonInteractiveMode
            }
            AntigravityProviderState::BlockedByPolicy => {
                AntigravityEnablementState::BlockedByPolicy
            }
            _ if auth
                .is_some_and(|check| check.status == AntigravityAuthStatus::NotAuthenticated) =>
            {
                AntigravityEnablementState::InstalledNotAuthenticated
            }
            _ => AntigravityEnablementState::ReadyDisabled,
        }
    }

    pub fn enable(
        &self,
        previous_state: AntigravityEnablementState,
        scope: AntigravityEnablementScope,
        admin_confirmed: bool,
        reasons: Vec<String>,
    ) -> Result<AntigravityEnablementReceipt, EngineError> {
        if !admin_confirmed {
            return Err(rejected(
                "Antigravity real enablement requires explicit admin CLI confirmation",
            ));
        }
        if matches!(
            previous_state,
            AntigravityEnablementState::NotInstalled
                | AntigravityEnablementState::InstalledNoNonInteractiveMode
                | AntigravityEnablementState::BlockedByPolicy
        ) {
            return Err(rejected("Antigravity cannot be enabled from current state"));
        }
        let requested_state = match scope {
            AntigravityEnablementScope::DisposableWorktreeAuditOnly
            | AntigravityEnablementScope::SessionOnly => {
                AntigravityEnablementState::EnabledForDisposableWorktreeAudit
            }
            AntigravityEnablementScope::DisposableWorktreeCandidateOnly => {
                AntigravityEnablementState::EnabledForDisposableWorktreeCandidateSmoke
            }
            AntigravityEnablementScope::PersistentLocalAdmin => {
                AntigravityEnablementState::EnabledPersistentByAdminReceipt
            }
        };
        let expires_at = match scope {
            AntigravityEnablementScope::PersistentLocalAdmin => None,
            _ => Some(OffsetDateTime::now_utc() + time::Duration::minutes(30)),
        };
        Ok(AntigravityEnablementReceipt {
            receipt_id: new_id("antigravity-enable"),
            provider_id: "antigravity-cli".to_owned(),
            requested_state,
            previous_state,
            approved_by: "local-admin-cli".to_owned(),
            approval_scope: scope,
            expires_at,
            reasons,
            created_at: OffsetDateTime::now_utc(),
        })
    }

    pub fn receipt_allows_disposable_worktree_audit(
        &self,
        receipt: &AntigravityEnablementReceipt,
    ) -> bool {
        !Self::receipt_expired(receipt)
            && matches!(
                receipt.approval_scope,
                AntigravityEnablementScope::DisposableWorktreeAuditOnly
                    | AntigravityEnablementScope::SessionOnly
                    | AntigravityEnablementScope::PersistentLocalAdmin
            )
    }

    pub fn receipt_allows_disposable_worktree_candidate(
        &self,
        receipt: &AntigravityEnablementReceipt,
    ) -> bool {
        !Self::receipt_expired(receipt)
            && matches!(
                receipt.approval_scope,
                AntigravityEnablementScope::DisposableWorktreeCandidateOnly
                    | AntigravityEnablementScope::PersistentLocalAdmin
            )
    }

    pub fn disable(
        &self,
        previous_state: AntigravityEnablementState,
        reason: &str,
    ) -> AntigravityDisableReceipt {
        AntigravityDisableReceipt {
            receipt_id: new_id("antigravity-disable"),
            provider_id: "antigravity-cli".to_owned(),
            previous_state,
            new_state: AntigravityEnablementState::DisabledAfterSmoke,
            reason: reason.to_owned(),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    fn receipt_expired(receipt: &AntigravityEnablementReceipt) -> bool {
        receipt
            .expires_at
            .is_some_and(|expires_at| expires_at < OffsetDateTime::now_utc())
    }
}

impl AntigravityAuthCheckService {
    pub fn help_only(
        &self,
        probe: &AntigravityCapabilityProbe,
        evidence_refs: Vec<String>,
    ) -> AntigravityAuthCheck {
        let status = match probe.provider_state {
            AntigravityProviderState::NotInstalled => AntigravityAuthStatus::ProviderError,
            AntigravityProviderState::Incompatible
            | AntigravityProviderState::DetectedButNoNonInteractiveMode => {
                AntigravityAuthStatus::Unknown
            }
            _ => AntigravityAuthStatus::Unknown,
        };
        AntigravityAuthCheck {
            check_id: new_id("antigravity-auth"),
            provider_id: "antigravity-cli".to_owned(),
            method: AntigravityAuthCheckMethod::HelpOnlyNoAuthCheck,
            status,
            evidence_refs,
            warnings: vec![
                "auth-check did not read token files, keyring contents, browser state, or private localhost APIs"
                    .to_owned(),
            ],
            checked_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn from_probe_output(
        &self,
        text: &str,
        timed_out: bool,
        evidence_refs: Vec<String>,
    ) -> AntigravityAuthCheck {
        let lower = text.to_ascii_lowercase();
        let status = if timed_out {
            AntigravityAuthStatus::AuthTimeout
        } else if lower.contains("sign in")
            || lower.contains("signin")
            || lower.contains("login")
            || lower.contains("oauth")
            || lower.contains("not authenticated")
            || lower.contains("unauthenticated")
        {
            AntigravityAuthStatus::NotAuthenticated
        } else if lower.contains("region")
            || lower.contains("quota")
            || lower.contains("plan")
            || lower.contains("not available")
        {
            AntigravityAuthStatus::RegionOrPlanUnavailable
        } else if lower.contains("eliot_antigravity_smoke_ok") {
            AntigravityAuthStatus::Authenticated
        } else {
            AntigravityAuthStatus::ProviderError
        };
        AntigravityAuthCheck {
            check_id: new_id("antigravity-auth"),
            provider_id: "antigravity-cli".to_owned(),
            method: AntigravityAuthCheckMethod::LogInferenceNoTokenRead,
            status,
            evidence_refs,
            warnings: vec![
                "auth inferred only from bounded provider output; no token or keyring contents were read"
                    .to_owned(),
            ],
            checked_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityLiveSmokeService {
    pub const EXPECTED_MARKER: &'static str = "ELIOT_ANTIGRAVITY_SMOKE_OK";
    pub const MCP_CALL_MARKER: &'static str = "ELIOT_MCP_CALL_OK tool=eliot_runtime_status";
    pub const CANDIDATE_FINAL_LINE: &'static str =
        "candidate_only; requires Governor reconciliation and verifier evidence before activation";

    pub fn disposable_worktree_prompt(&self) -> String {
        [
            "You are being invoked through ELIOT Governor inside a detached disposable worktree.",
            "Operate only inside the current disposable worktree and its WorktreeLease scope.",
            "Do not access or modify the controller's live tree.",
            "Do not request secrets.",
            "Use the eliot-governor MCP server and call exactly one tool: eliot_runtime_status.",
            "After a successful tool response, include: ELIOT_MCP_CALL_OK tool=eliot_runtime_status status=<short-status>.",
            "Produce only candidate evidence and include marker:",
            Self::EXPECTED_MARKER,
            "The final line must be exactly:",
            Self::CANDIDATE_FINAL_LINE,
        ]
        .join("\n")
    }

    pub fn build_request(
        &self,
        project_id: ProjectId,
        work_lease_ref: WorkLeaseId,
        worktree_lease_ref: Option<WorktreeLeaseId>,
        mode: AntigravityLiveSmokeMode,
    ) -> AntigravityLiveSmokeRequest {
        AntigravityLiveSmokeRequest {
            smoke_id: new_id("antigravity-smoke"),
            mode,
            project_id,
            work_lease_ref,
            worktree_lease_ref,
            prompt_ref: "antigravity:prompt:disposable-worktree-smoke".to_owned(),
            expected_marker: Self::EXPECTED_MARKER.to_owned(),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn result_from_run(
        &self,
        smoke: &AntigravityLiveSmokeRequest,
        run: &AntigravityRun,
    ) -> AntigravityLiveSmokeResult {
        let marker_seen = run
            .stdout_excerpt
            .to_ascii_uppercase()
            .contains(Self::EXPECTED_MARKER);
        let mcp_call_marker_seen = run.stdout_excerpt.contains(Self::MCP_CALL_MARKER);
        let normalized_ok = run.normalized_result.as_ref().is_some_and(|result| {
            result.candidate_only && result.taint == TaintClass::ExternalAgent && !result.rejected
        });
        let candidate_final_line_seen = run
            .stdout_excerpt
            .lines()
            .next_back()
            .is_some_and(|line| line.trim() == Self::CANDIDATE_FINAL_LINE);
        let status = match run.state {
            AntigravityRunState::Succeeded
                if marker_seen
                    && mcp_call_marker_seen
                    && normalized_ok
                    && candidate_final_line_seen =>
            {
                AntigravityLiveSmokeStatus::Passed
            }
            AntigravityRunState::TimedOut => AntigravityLiveSmokeStatus::Timeout,
            AntigravityRunState::Blocked => AntigravityLiveSmokeStatus::PolicyBlocked,
            AntigravityRunState::Failed
                if run.stderr_excerpt.to_ascii_lowercase().contains("auth") =>
            {
                AntigravityLiveSmokeStatus::NotAuthenticated
            }
            AntigravityRunState::Failed => AntigravityLiveSmokeStatus::Failed,
            _ if !marker_seen => AntigravityLiveSmokeStatus::MalformedOutput,
            _ => AntigravityLiveSmokeStatus::Failed,
        };
        AntigravityLiveSmokeResult {
            result_id: new_id("antigravity-smoke-result"),
            smoke_ref: smoke.smoke_id.clone(),
            run_ref: run.run_id.clone(),
            status,
            marker_seen,
            mcp_call_marker_seen,
            output_blob_ref: run
                .stdout_blob_ref
                .as_ref()
                .map(|blob| blob.relative_path.clone()),
            normalized_result_ref: run
                .normalized_result
                .as_ref()
                .map(|result| result.result_id.clone()),
            telemetry_refs: vec![format!("antigravity-telemetry:{}", run.run_id)],
            warnings: [
                (!marker_seen)
                    .then(|| "expected smoke marker was not present in provider output".to_owned()),
                (!mcp_call_marker_seen).then(|| {
                    "provider output did not contain the required ELIOT MCP call marker".to_owned()
                }),
                (!candidate_final_line_seen).then(|| {
                    "provider output did not end with the required candidate-only line".to_owned()
                }),
            ]
            .into_iter()
            .flatten()
            .collect(),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn provider_unavailable_result(
        &self,
        smoke: &AntigravityLiveSmokeRequest,
        warning: impl Into<String>,
    ) -> AntigravityLiveSmokeResult {
        AntigravityLiveSmokeResult {
            result_id: new_id("antigravity-smoke-result"),
            smoke_ref: smoke.smoke_id.clone(),
            run_ref: "antigravity-run:unavailable".to_owned(),
            status: AntigravityLiveSmokeStatus::ProviderUnavailable,
            marker_seen: false,
            mcp_call_marker_seen: false,
            output_blob_ref: None,
            normalized_result_ref: None,
            telemetry_refs: Vec::new(),
            warnings: vec![warning.into()],
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub const fn included_in_normal_l3(&self, _result: &AntigravityLiveSmokeResult) -> bool {
        false
    }
}

impl AntigravityDisposableWorktreeSmokeService {
    pub const fn requires_worktree_lease(&self, _mode: AntigravityLiveSmokeMode) -> bool {
        true
    }

    pub fn snapshot_live_tree(
        &self,
        repo_root: &Path,
    ) -> Result<AntigravityLiveTreeSnapshot, EngineError> {
        let repo_root = repo_root.canonicalize()?;
        let head = git_text_sync(&repo_root, &["rev-parse", "HEAD"])?;
        let status_porcelain = git_text_raw_sync(
            &repo_root,
            &["status", "--porcelain=v1", "--untracked-files=all"],
        )?;
        let binary_diff = git_bytes_sync(
            &repo_root,
            &["diff", "--binary", "--no-ext-diff", "HEAD", "--"],
        )?;
        Ok(AntigravityLiveTreeSnapshot {
            repo_root: path_for_record(&repo_root),
            head,
            status_porcelain,
            binary_diff_hash: blake3::hash(&binary_diff).to_hex().to_string(),
            binary_diff_bytes: binary_diff.len(),
            captured_at: OffsetDateTime::now_utc(),
        })
    }

    pub async fn create_disposable_worktree(
        &self,
        state: &mut WorkState,
        work_lease: &WorkLease,
        worktree_root: &Path,
        ttl_minutes: i64,
    ) -> Result<WorktreeLease, EngineError> {
        validate_active_work_lease_in_state(state, work_lease)?;
        if state.worktree_leases.iter().any(|lease| {
            lease.work_lease_id == work_lease.work_lease_id
                && matches!(
                    lease.state,
                    WorktreeLeaseState::Created | WorktreeLeaseState::Active
                )
        }) {
            return Err(rejected(
                "active disposable WorktreeLease already exists for WorkLease",
            ));
        }

        let repo_root = Path::new(&work_lease.scope.repo_root).canonicalize()?;
        fs::create_dir_all(worktree_root)?;
        let worktree_root = worktree_root.canonicalize()?;
        if worktree_root == repo_root || worktree_root.starts_with(&repo_root) {
            return Err(rejected(
                "disposable worktree root must be outside the controller tree",
            ));
        }

        let head = git_text_sync(&repo_root, &["rev-parse", "HEAD"])?;
        let worktree_lease_id = WorktreeLeaseId::new_v7();
        let worktree_path = worktree_root.join(worktree_lease_id.to_string());
        if worktree_path.parent() != Some(worktree_root.as_path()) {
            return Err(rejected("disposable worktree path escaped its root"));
        }
        let worktree_path_arg = path_for_record(&worktree_path);
        git_status_async(
            &repo_root,
            &["worktree", "add", "--detach", &worktree_path_arg, &head],
        )
        .await?;

        let now = OffsetDateTime::now_utc();
        let lease = WorktreeLease {
            worktree_lease_id,
            project_id: work_lease.project_id,
            task_id: work_lease.task_id,
            work_item_id: work_lease.work_item_id,
            work_lease_id: work_lease.work_lease_id,
            holder_session_id: work_lease.agent_session_id,
            repo_root: path_for_record(&repo_root),
            worktree_path: path_for_record(&worktree_path),
            branch_name: format!("detached-{worktree_lease_id}"),
            base_commit: head,
            allowed_read_set: work_lease.scope.read_set.clone(),
            allowed_write_set: work_lease.scope.write_set.clone(),
            state: WorktreeLeaseState::Active,
            issued_at: now,
            expires_at: now + Duration::minutes(ttl_minutes.max(1)),
            cleaned_at: None,
            write_receipt: None,
        };
        state.worktree_leases.push(lease.clone());
        Ok(lease)
    }

    pub async fn capture_candidate_diff(
        &self,
        state: &mut WorkState,
        worktree_lease_id: WorktreeLeaseId,
        diff_root: &Path,
        max_diff_bytes: usize,
    ) -> Result<CandidateDiff, EngineError> {
        CandidateDiffService
            .capture(
                state,
                CandidateDiffCaptureInput {
                    worktree_lease_id,
                    diff_root: diff_root.to_path_buf(),
                    max_diff_bytes,
                },
            )
            .await
    }

    pub async fn cleanup_disposable_worktree(
        &self,
        state: &mut WorkState,
        worktree_lease_id: WorktreeLeaseId,
    ) -> Result<WorktreeLease, EngineError> {
        WorktreeCleanupService
            .cleanup(state, worktree_lease_id)
            .await
    }

    pub fn live_tree_unchanged(
        &self,
        before: &AntigravityLiveTreeSnapshot,
        after: &AntigravityLiveTreeSnapshot,
    ) -> bool {
        before.repo_root == after.repo_root
            && before.head == after.head
            && before.status_porcelain == after.status_porcelain
            && before.binary_diff_hash == after.binary_diff_hash
            && before.binary_diff_bytes == after.binary_diff_bytes
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn capture_cleanup_and_compare(
        &self,
        state: &mut WorkState,
        live_before: &AntigravityLiveTreeSnapshot,
        worktree_lease_id: WorktreeLeaseId,
        diff_root: &Path,
        max_diff_bytes: usize,
        marker_seen: bool,
    ) -> Result<AntigravityDisposableWorktreeSmokeEvidence, EngineError> {
        let lease = state
            .worktree_leases
            .iter()
            .find(|lease| lease.worktree_lease_id == worktree_lease_id)
            .cloned()
            .ok_or_else(|| rejected("disposable WorktreeLease is missing"))?;
        let candidate_diff = match self
            .capture_candidate_diff(state, worktree_lease_id, diff_root, max_diff_bytes)
            .await
        {
            Ok(diff) => diff,
            Err(error) => {
                let _ = WorktreeCleanupService.revoke(state, worktree_lease_id);
                let _ = WorktreeCleanupService
                    .cleanup(state, worktree_lease_id)
                    .await;
                return Err(error);
            }
        };
        let cleaned = self
            .cleanup_disposable_worktree(state, worktree_lease_id)
            .await?;
        let live_after = self.snapshot_live_tree(Path::new(&lease.repo_root))?;
        let live_tree_unchanged = self.live_tree_unchanged(live_before, &live_after);
        Ok(AntigravityDisposableWorktreeSmokeEvidence {
            component: "antigravity_disposable_worktree_smoke_evidence".to_owned(),
            work_lease_id: lease.work_lease_id,
            worktree_lease_id,
            worktree_path: lease.worktree_path,
            live_before: live_before.clone(),
            live_after,
            live_tree_unchanged,
            candidate_diff_id: candidate_diff.candidate_diff_id,
            candidate_diff_status: candidate_diff.capture_status,
            cleanup_state: cleaned.state,
            marker_seen,
            candidate_only: true,
            taint: TaintClass::ExternalAgent,
            warnings: if live_tree_unchanged {
                Vec::new()
            } else {
                vec!["controller live tree changed during disposable worktree smoke".to_owned()]
            },
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

impl AntigravityMcpConfigService {
    pub fn config_paths(&self, home: &Path) -> [(AntigravityMcpConfigSurface, PathBuf); 2] {
        [
            (
                AntigravityMcpConfigSurface::Gui,
                home.join(".gemini").join("config").join("mcp_config.json"),
            ),
            (
                AntigravityMcpConfigSurface::Cli,
                home.join(".gemini")
                    .join("antigravity-cli")
                    .join("mcp_config.json"),
            ),
        ]
    }

    pub fn desired_server_value(&self, eliot_exe: &Path) -> Result<Value, EngineError> {
        self.desired_server_value_with_profile(eliot_exe, None)
    }

    pub fn desired_server_value_with_profile(
        &self,
        eliot_exe: &Path,
        profile: Option<&str>,
    ) -> Result<Value, EngineError> {
        let command = validate_eliot_mcp_executable(eliot_exe)?;
        let mut args = vec!["mcp", "stdio", "--host", "antigravity"];
        if let Some(profile) = profile {
            if profile.trim().is_empty() {
                return Err(rejected("Antigravity MCP profile must not be empty"));
            }
            args.extend(["--profile", profile]);
        }
        args.extend(["--instance", "default"]);
        Ok(json!({
            "command": command,
            "args": args
        }))
    }

    pub fn desired_server_value_for_project(
        &self,
        eliot_exe: &Path,
        project_root: &Path,
    ) -> Result<Value, EngineError> {
        let mut desired = self.desired_server_value(eliot_exe)?;
        let _project_root = validate_project_root(project_root)?;
        let object = desired
            .as_object_mut()
            .ok_or_else(|| rejected("internal ELIOT MCP entry is not an object"))?;
        object.insert("disabled".to_owned(), Value::Bool(false));
        Ok(desired)
    }

    pub fn merge_config(&self, existing: &Value, eliot_exe: &Path) -> Result<Value, EngineError> {
        let desired = self.desired_server_value(eliot_exe)?;
        Self::merge_config_value(existing, &desired)
    }

    pub fn merge_config_for_project(
        &self,
        existing: &Value,
        eliot_exe: &Path,
        project_root: &Path,
    ) -> Result<Value, EngineError> {
        let desired = self.desired_server_value_for_project(eliot_exe, project_root)?;
        Self::merge_config_value(existing, &desired)
    }

    fn merge_config_value(existing: &Value, desired: &Value) -> Result<Value, EngineError> {
        let mut merged = existing.clone();
        let root = merged
            .as_object_mut()
            .ok_or_else(|| rejected("Antigravity MCP config root must be a JSON object"))?;
        let servers = root
            .entry("mcpServers")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| rejected("Antigravity MCP mcpServers must be a JSON object"))?;
        let mut server = servers
            .get(ELIOT_MCP_SERVER_NAME)
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        for secret_field in ["env", "headers", "oauth", "serverUrl"] {
            server.remove(secret_field);
        }
        let desired = desired
            .as_object()
            .ok_or_else(|| rejected("internal ELIOT MCP entry is not an object"))?;
        for (name, value) in desired {
            server.insert(name.clone(), value.clone());
        }
        servers.insert(ELIOT_MCP_SERVER_NAME.to_owned(), Value::Object(server));
        Ok(merged)
    }

    pub fn status(&self, home: &Path) -> Vec<AntigravityMcpConfigStatus> {
        self.config_paths(home)
            .into_iter()
            .map(|(surface, path)| self.status_for_path(surface, &path))
            .collect()
    }

    pub fn status_for_path(
        &self,
        surface: AntigravityMcpConfigSurface,
        path: &Path,
    ) -> AntigravityMcpConfigStatus {
        let checked_at = OffsetDateTime::now_utc();
        let exists = path.is_file();
        let parsed = fs::read(path)
            .map_err(|error| error.to_string())
            .and_then(|bytes| {
                serde_json::from_slice::<Value>(&bytes).map_err(|error| error.to_string())
            });
        let entry = parsed
            .as_ref()
            .ok()
            .and_then(|root| root.get("mcpServers"))
            .and_then(|servers| servers.get(ELIOT_MCP_SERVER_NAME));
        let command = entry
            .and_then(|entry| entry.get("command"))
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        let command_absolute = command
            .as_deref()
            .is_some_and(|command| Path::new(command).is_absolute());
        let command_exists = command.as_deref().is_some_and(|command| {
            let path = Path::new(command);
            path.is_file() && looks_executable(path)
        });
        let profile_args_exact = entry.and_then(|entry| entry.get("args"))
            == Some(&json!([
                "mcp",
                "stdio",
                "--host",
                "antigravity",
                "--instance",
                "default"
            ]));
        let secret_fields_present = entry.is_some_and(mcp_entry_has_secret_fields);
        let recursion_detected = command.as_deref().is_some_and(command_is_antigravity);
        let error = if exists {
            parsed.as_ref().err().cloned()
        } else {
            None
        };
        AntigravityMcpConfigStatus {
            component: "antigravity_mcp_config_status".to_owned(),
            surface,
            config_path: path_for_record(path),
            exists,
            registered: entry.is_some()
                && command_absolute
                && command_exists
                && profile_args_exact
                && !secret_fields_present
                && !recursion_detected,
            command,
            command_absolute,
            command_exists,
            profile_args_exact,
            secret_fields_present,
            recursion_detected,
            error,
            checked_at,
        }
    }

    pub fn register_home(
        &self,
        home: &Path,
        eliot_exe: &Path,
    ) -> Result<Vec<AntigravityMcpRegistrationReceipt>, EngineError> {
        let command = validate_eliot_mcp_executable(eliot_exe)?;
        self.config_paths(home)
            .into_iter()
            .map(|(surface, path)| self.register_path(surface, &path, eliot_exe, None, &command))
            .collect()
    }

    pub fn register_home_for_project(
        &self,
        home: &Path,
        eliot_exe: &Path,
        project_root: &Path,
    ) -> Result<Vec<AntigravityMcpRegistrationReceipt>, EngineError> {
        let command = validate_eliot_mcp_executable(eliot_exe)?;
        self.config_paths(home)
            .into_iter()
            .map(|(surface, path)| {
                self.register_path(surface, &path, eliot_exe, Some(project_root), &command)
            })
            .collect()
    }

    pub fn register_gui_for_project(
        &self,
        home: &Path,
        eliot_exe: &Path,
        project_root: &Path,
    ) -> Result<AntigravityMcpRegistrationReceipt, EngineError> {
        let command = validate_eliot_mcp_executable(eliot_exe)?;
        let (surface, path) = self.config_paths(home)[0].clone();
        self.register_path(surface, &path, eliot_exe, Some(project_root), &command)
    }

    fn register_path(
        self,
        surface: AntigravityMcpConfigSurface,
        path: &Path,
        eliot_exe: &Path,
        project_root: Option<&Path>,
        command: &str,
    ) -> Result<AntigravityMcpRegistrationReceipt, EngineError> {
        let existing = if path.is_file() {
            serde_json::from_slice::<Value>(&fs::read(path)?)?
        } else {
            json!({})
        };
        let merged = if let Some(project_root) = project_root {
            self.merge_config_for_project(&existing, eliot_exe, project_root)?
        } else {
            self.merge_config(&existing, eliot_exe)?
        };
        let unknown_servers_preserved = unknown_servers_preserved(&existing, &merged);
        let unknown_fields_preserved = unknown_root_fields_preserved(&existing, &merged);
        let backup_path = atomic_backup_and_replace_json(path, &merged)?;
        Ok(AntigravityMcpRegistrationReceipt {
            component: "antigravity_mcp_registration_receipt".to_owned(),
            surface,
            config_path: path_for_record(path),
            backup_path: backup_path.as_deref().map(path_for_record),
            server_name: ELIOT_MCP_SERVER_NAME.to_owned(),
            command: command.to_owned(),
            args: vec![
                "mcp".to_owned(),
                "stdio".to_owned(),
                "--host".to_owned(),
                "antigravity".to_owned(),
                "--instance".to_owned(),
                "default".to_owned(),
            ],
            merged: true,
            atomic_write: true,
            unknown_fields_preserved,
            unknown_servers_preserved,
            secret_values_written: false,
            created_at: OffsetDateTime::now_utc(),
        })
    }
}

impl AntigravityOfficialPluginService {
    pub fn plugin_roots(&self, home: &Path) -> (PathBuf, PathBuf) {
        (
            home.join(".gemini")
                .join("config")
                .join("plugins")
                .join(OFFICIAL_PLUGIN_NAME),
            home.join(".gemini")
                .join("antigravity-cli")
                .join("plugins")
                .join(OFFICIAL_PLUGIN_NAME),
        )
    }

    pub fn manifest_value(&self) -> Value {
        json!({
            "$schema": OFFICIAL_PLUGIN_SCHEMA,
            "name": OFFICIAL_PLUGIN_NAME,
            "description": "Governed ELIOT auditor integration for Antigravity"
        })
    }

    pub fn official_manifest_valid(&self, manifest: &Value) -> bool {
        let Some(object) = manifest.as_object() else {
            return false;
        };
        object.get("$schema").and_then(Value::as_str) == Some(OFFICIAL_PLUGIN_SCHEMA)
            && object
                .get("name")
                .and_then(Value::as_str)
                .is_some_and(valid_plugin_name)
    }

    pub fn status(&self, home: &Path) -> AntigravityOfficialPluginStatus {
        let (gui_root, cli_root) = self.plugin_roots(home);
        let gui_installed = valid_plugin_at(&gui_root, false);
        let cli_installed = valid_plugin_at(&cli_root, true);
        let official_schema_valid = [&gui_root, &cli_root].into_iter().any(|root| {
            read_json_if_present(&root.join("plugin.json"))
                .is_some_and(|value| self.official_manifest_valid(&value))
        });
        let mcp_config_present = [&gui_root, &cli_root]
            .into_iter()
            .any(|root| root.join("mcp_config.json").is_file());
        let skill_visible = [&gui_root, &cli_root]
            .into_iter()
            .any(|root| directory_contains_file_named(&root.join("skills"), "SKILL.md"));
        let agent_visible = [&gui_root, &cli_root]
            .into_iter()
            .any(|root| directory_contains_file_named(&root.join("agents"), "agent.md"));
        let rule_visible = [&gui_root, &cli_root]
            .into_iter()
            .any(|root| directory_has_files(&root.join("rules")));
        AntigravityOfficialPluginStatus {
            component: "antigravity_official_plugin_status".to_owned(),
            gui_plugin_root: path_for_record(&gui_root),
            cli_plugin_root: path_for_record(&cli_root),
            gui_installed,
            cli_installed,
            official_schema_valid,
            mcp_config_present,
            skill_visible,
            agent_visible,
            rule_visible,
            warnings: if gui_installed || cli_installed {
                Vec::new()
            } else {
                vec!["official ELIOT Antigravity plugin is not installed".to_owned()]
            },
            checked_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn status_only_install_receipt(
        &self,
        status: &AntigravityOfficialPluginStatus,
    ) -> AntigravityOfficialPluginInstallReceipt {
        AntigravityOfficialPluginInstallReceipt {
            component: "antigravity_official_plugin_install_receipt".to_owned(),
            plugin_name: OFFICIAL_PLUGIN_NAME.to_owned(),
            gui_plugin_root: status.gui_plugin_root.clone(),
            cli_plugin_root: status.cli_plugin_root.clone(),
            attempted: false,
            install_command_succeeded: false,
            listed_by_agy: false,
            installed: status.gui_installed || status.cli_installed,
            files_written: Vec::new(),
            official_schema_valid: status.official_schema_valid,
            agent_visible: status.agent_visible,
            skill_visible: status.skill_visible,
            reasons: vec![
                "status-only helper; engine does not write Antigravity application or plugin files"
                    .to_owned(),
            ],
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn install_receipt(
        &self,
        status: &AntigravityOfficialPluginStatus,
        install_command_succeeded: bool,
        plugin_list_output: &str,
        files_written: Vec<String>,
    ) -> AntigravityOfficialPluginInstallReceipt {
        let listed_by_agy = plugin_list_output
            .to_ascii_lowercase()
            .contains(OFFICIAL_PLUGIN_NAME);
        let installed = install_command_succeeded
            && listed_by_agy
            && status.gui_installed
            && status.official_schema_valid
            && status.skill_visible;
        AntigravityOfficialPluginInstallReceipt {
            component: "antigravity_official_plugin_install_receipt".to_owned(),
            plugin_name: OFFICIAL_PLUGIN_NAME.to_owned(),
            gui_plugin_root: status.gui_plugin_root.clone(),
            cli_plugin_root: status.cli_plugin_root.clone(),
            attempted: true,
            install_command_succeeded,
            listed_by_agy,
            installed,
            files_written,
            official_schema_valid: status.official_schema_valid,
            agent_visible: status.agent_visible,
            skill_visible: status.skill_visible,
            reasons: if installed {
                vec![
                    "official plugin install, listing, schema, and skill checks passed; the default Antigravity agent consumes the package without a required custom agent"
                        .to_owned(),
                ]
            } else {
                vec![
                    "official plugin install requires command success, agy listing, valid installed schema, and skill"
                        .to_owned(),
                ]
            },
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityVisibilityService {
    #[allow(clippy::too_many_arguments)]
    pub fn report(
        &self,
        gui: AntigravityGuiProcessProbe,
        windows_install: AntigravityWindowsInstallDiscovery,
        version_gate: Option<AntigravityVersionGateResult>,
        mcp_configs: Vec<AntigravityMcpConfigStatus>,
        mcp_invocation: Option<AntigravityMcpInvocationReceipt>,
        official_plugin: AntigravityOfficialPluginStatus,
        live_smoke: Option<AntigravityLiveSmokeResult>,
        disposable_worktree_smoke: Option<AntigravityDisposableWorktreeSmokeEvidence>,
    ) -> AntigravityVisibilityReport {
        AntigravityVisibilityReport {
            component: "antigravity_visibility_report".to_owned(),
            gui,
            windows_install,
            version_gate,
            mcp_configs,
            mcp_invocation,
            official_plugin,
            live_smoke,
            disposable_worktree_smoke,
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityRollbackService {
    pub fn rollback(
        &self,
        previous_state: AntigravityEnablementState,
        reason: &str,
    ) -> AntigravityDisableReceipt {
        AntigravityEnablementService.disable(previous_state, reason)
    }

    pub const fn cancels_process_group(&self) -> bool {
        true
    }
}

impl AntigravityRealExecutionDoctor {
    #[allow(clippy::too_many_arguments)]
    pub fn status(
        &self,
        resolution: &AntigravityBinaryResolution,
        probe: &AntigravityCapabilityProbe,
        contract: &AntigravityCommandContract,
        auth: &AntigravityAuthCheck,
        enablement_state: AntigravityEnablementState,
        live_smoke: Option<&AntigravityLiveSmokeResult>,
        disable: Option<&AntigravityDisableReceipt>,
        telemetry_recorded: bool,
    ) -> AntigravityRealDoctorStatus {
        AntigravityRealDoctorStatus {
            component: "antigravity_real_doctor".to_owned(),
            binary_resolved: resolution.status == AntigravityBinaryResolutionStatus::Resolved,
            capability_contract_valid: contract.noninteractive_supported
                && probe.capabilities.text_output_supported,
            auth_status: auth.status,
            enablement_state,
            last_live_smoke_status: live_smoke.map(|smoke| smoke.status),
            last_disable_receipt_ref: disable.map(|receipt| receipt.receipt_id.clone()),
            live_tree_unchanged: true,
            telemetry_recorded,
            provider_disabled_after_smoke: disable.is_some()
                || enablement_state == AntigravityEnablementState::DisabledAfterSmoke,
            message: real_doctor_message(resolution, auth, live_smoke),
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityRunner {
    pub fn run_real(
        &self,
        _request: &AntigravityReviewRequest,
        _contract: &AntigravityCommandContract,
        _worktree_lease: &WorktreeLease,
        _effective_cwd: &Path,
    ) -> Result<AntigravityRun, EngineError> {
        Err(rejected(
            "legacy unsupervised Antigravity execution is disabled; use run_real_supervised",
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "provider execution is one ordered security and supervision transaction"
    )]
    pub async fn run_real_supervised(
        &self,
        request: &AntigravityReviewRequest,
        contract: &AntigravityCommandContract,
        worktree_lease: &WorktreeLease,
        effective_cwd: &Path,
        runner: &dyn ProviderProcessRunner,
    ) -> Result<AntigravityRun, EngineError> {
        if std::env::var_os("ELIOT_DISABLE_REAL_PROVIDER").is_some() {
            return Err(rejected(
                "real Antigravity execution is disabled for provider-free verification",
            ));
        }
        inspect_secret_bytes(request.question.as_bytes()).map_err(|violation| {
            rejected(&format!(
                "secret boundary rejected provider input: {}",
                violation.rule
            ))
        })?;
        let effective_cwd = validate_real_worktree(request, worktree_lease, effective_cwd)?;
        let argv =
            AntigravityCommandContractService.typed_review_argv(contract, &request.question)?;
        let binary = argv
            .first()
            .ok_or_else(|| rejected("Antigravity real run has no binary argv"))?;
        let version_gate = AntigravityVersionGateService
            .probe_supervised(Path::new(binary), runner)
            .await;
        if !version_gate.allowed {
            return Err(rejected(&format!(
                "Antigravity version gate blocked real execution: {}",
                version_gate.reasons.join("; ")
            )));
        }
        let source_env = std::env::vars().collect::<Vec<_>>();
        let mut process_env = AntigravityEnvPolicyService.minimal_windows_env(&source_env);
        for fixed in &contract.env_policy.fixed_vars {
            if !process_env.iter().any(|(name, _)| name == &fixed.0) {
                process_env.push(fixed.clone());
            }
        }
        let dropped_names = AntigravityEnvPolicyService.minimal_windows_dropped_names(&source_env);
        let started = OffsetDateTime::now_utc();
        let route_policy = ProviderRoutePolicy::for_route(
            eliot_types::AgentHostId::Antigravity,
            "antigravity-real-review",
            eliot_types::ProviderDeclaredBudget::new(
                DEFAULT_TIMEOUT_MS,
                DEFAULT_MAX_OUTPUT_BYTES as u64,
            ),
        );
        let output = runner
            .run(
                ProviderProcessSpec {
                    operation_id: new_id("antigravity-process"),
                    invocation_id: Some(request.request_id.clone()),
                    executable: PathBuf::from(binary),
                    args: argv.iter().skip(1).map(OsString::from).collect(),
                    cwd: effective_cwd.clone(),
                    environment: process_env
                        .iter()
                        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                        .collect(),
                    stdin_payload: None,
                    route_policy,
                    cancellation: crate::runtime_supervision::CancellationToken::new(),
                    deadline: tokio::time::Instant::now()
                        + std::time::Duration::from_millis(DEFAULT_TIMEOUT_MS),
                    runtime_contract_sha256: None,
                    role_lease_id: None,
                    role_lease_epoch: None,
                },
                &mut |_| Ok(()),
            )
            .await?;
        if !output.reap_receipt.proves_complete_reap() {
            return Err(rejected(
                "supervised Antigravity process returned an incomplete reap receipt",
            ));
        }
        if let Some(violation) = inspect_secret_bytes(&output.stdout)
            .err()
            .or_else(|| inspect_secret_bytes(&output.stderr).err())
        {
            return Err(rejected(&format!(
                "secret boundary rejected provider output: {}",
                violation.rule
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let redacted_stdout = redact_output(&stdout);
        let redacted_stderr = redact_output(&stderr);
        let redaction_receipt =
            merge_redaction_receipts(&redacted_stdout.receipt, &redacted_stderr.receipt);
        let combined = output_text(
            redacted_stdout.text.as_bytes(),
            redacted_stderr.text.as_bytes(),
        );
        let normalized = AntigravityTextOutputNormalizer.normalize_text(request, &combined);
        let exit_success = output.exit_code == Some(0);
        let state = if output.timed_out {
            AntigravityRunState::TimedOut
        } else if exit_success {
            AntigravityRunState::Succeeded
        } else {
            AntigravityRunState::Failed
        };
        let (receipt_argv, prompt_hash_blake3) = safety_argv_receipt(&argv, &request.question);
        Ok(AntigravityRun {
            run_id: new_id("antigravity-run"),
            request_id: request.request_id.clone(),
            state,
            provider_state: if exit_success {
                AntigravityProviderState::ReadyEnabled
            } else {
                AntigravityProviderState::DetectedDisabled
            },
            dry_run: false,
            fixture_runner: false,
            binary_path: contract.binary_path.clone(),
            effective_cwd: path_for_record(&effective_cwd),
            stdout_blob_ref: Some(blob_ref(
                "antigravity/stdout.txt",
                redacted_stdout.text.len(),
            )),
            stderr_blob_ref: Some(blob_ref(
                "antigravity/stderr.txt",
                redacted_stderr.text.len(),
            )),
            log_blob_ref: Some(blob_ref("antigravity/log.txt", combined.len())),
            stdout_excerpt: truncate_text(&redacted_stdout.text, 2_000),
            stderr_excerpt: truncate_text(&redacted_stderr.text, 2_000),
            safety_receipt: AntigravitySafetyReceipt {
                typed_argv: receipt_argv,
                prompt_hash_blake3,
                shell_false: true,
                stdin_devnull: true,
                process_group_kill_on_timeout: true,
                timeout_ms: DEFAULT_TIMEOUT_MS,
                max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
                effective_cwd: path_for_record(&effective_cwd),
                env_fixed_vars: process_env,
                env_dropped_names: dropped_names,
            },
            redaction_receipt,
            normalized_result: Some(normalized),
            message: if output.timed_out {
                "real Antigravity run timed out and its supervised Job Object was reaped".to_owned()
            } else if exit_success {
                "real Antigravity run completed through the shared supervised process primitive"
                    .to_owned()
            } else {
                "real Antigravity run failed; supervised output was captured".to_owned()
            },
            created_at: started,
            completed_at: Some(OffsetDateTime::now_utc()),
        })
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub fn run_real_recorded(
        &self,
        _request: &AntigravityReviewRequest,
        _contract: &AntigravityCommandContract,
        _worktree_lease: &WorktreeLease,
        _effective_cwd: &Path,
        _data_root: &Path,
        _reservation_owner: &ProviderCallReservationOwner,
        _reservation_id: &str,
        _journal: &ProviderInvocationJournal,
        _attempt: &mut ProviderInvocationAttempt,
    ) -> Result<AntigravityRun, EngineError> {
        Err(rejected(
            "legacy unsupervised recorded Antigravity execution is disabled; use run_real_recorded_supervised",
        ))
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    pub async fn run_real_recorded_supervised(
        &self,
        request: &AntigravityReviewRequest,
        contract: &AntigravityCommandContract,
        worktree_lease: &WorktreeLease,
        effective_cwd: &Path,
        data_root: &Path,
        reservation_owner: &ProviderCallReservationOwner,
        reservation_id: &str,
        journal: &ProviderInvocationJournal,
        attempt: &mut ProviderInvocationAttempt,
        runner: &dyn ProviderProcessRunner,
    ) -> Result<AntigravityRun, EngineError> {
        if std::env::var_os("ELIOT_DISABLE_REAL_PROVIDER").is_some() {
            return Err(rejected(
                "real Antigravity execution is disabled for provider-free verification",
            ));
        }
        inspect_secret_bytes(request.question.as_bytes()).map_err(|violation| {
            rejected(&format!(
                "secret boundary rejected provider input: {}",
                violation.rule
            ))
        })?;
        let effective_cwd = validate_real_worktree(request, worktree_lease, effective_cwd)?;
        let argv =
            AntigravityCommandContractService.typed_review_argv(contract, &request.question)?;
        let binary = argv
            .first()
            .ok_or_else(|| rejected("Antigravity real run has no binary argv"))?;
        let version_gate = AntigravityVersionGateService
            .probe_supervised(Path::new(binary), runner)
            .await;
        if !version_gate.allowed {
            return Err(rejected(&format!(
                "Antigravity version gate blocked real execution: {}",
                version_gate.reasons.join("; ")
            )));
        }
        let source_env = std::env::vars().collect::<Vec<_>>();
        let mut process_env = AntigravityEnvPolicyService.minimal_windows_env(&source_env);
        for fixed in &contract.env_policy.fixed_vars {
            if !process_env.iter().any(|(name, _)| name == &fixed.0) {
                process_env.push(fixed.clone());
            }
        }
        let dropped_names = AntigravityEnvPolicyService.minimal_windows_dropped_names(&source_env);
        journal.transition(
            attempt,
            ProviderInvocationState::DispatchStarting,
            vec!["durable dispatch-starting receipt precedes supervised spawn".to_owned()],
        )?;
        let started = OffsetDateTime::now_utc();
        let route_policy = crate::antigravity_plan_route_policy();
        let process_spec = ProviderProcessSpec {
            operation_id: format!(
                "antigravity-recorded-{}",
                safe_invocation_component(&attempt.invocation_attempt_id)
            ),
            invocation_id: Some(attempt.invocation_attempt_id.clone()),
            executable: PathBuf::from(binary),
            args: argv.iter().skip(1).map(OsString::from).collect(),
            cwd: effective_cwd.clone(),
            environment: process_env
                .iter()
                .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                .collect(),
            stdin_payload: None,
            route_policy,
            cancellation: crate::runtime_supervision::CancellationToken::new(),
            deadline: tokio::time::Instant::now()
                + std::time::Duration::from_millis(DEFAULT_TIMEOUT_MS),
            runtime_contract_sha256: None,
            role_lease_id: None,
            role_lease_epoch: None,
        };
        let execution = {
            let mut on_spawned = |pid| {
                reservation_owner.mark_dispatched(reservation_id, &request.request_id)?;
                attempt.process_started_at = Some(OffsetDateTime::now_utc());
                attempt.dispatch_started_at = attempt.process_started_at;
                attempt.external_invocation_ref = Some(request.request_id.clone());
                attempt.process_or_job_identity = Some(format!("pid:{pid};supervised=true"));
                journal.persist(attempt)?;
                journal.transition(
                    attempt,
                    ProviderInvocationState::Dispatched,
                    vec![format!("external_invocation_ref:{}", request.request_id)],
                )?;
                journal.transition(
                    attempt,
                    ProviderInvocationState::Running,
                    vec![format!("pid:{pid}")],
                )
            };
            runner.run(process_spec, &mut on_spawned).await
        };
        let output = match execution {
            Ok(output) => output,
            Err(error) => {
                let error_text = error.to_string();
                let state = attempt
                    .state_transitions
                    .last()
                    .map(|transition| transition.to);
                if state == Some(ProviderInvocationState::DispatchStarting) {
                    let _ = reservation_owner.release_pre_dispatch(
                        reservation_id,
                        "supervised process failed before provider dispatch",
                    );
                    journal.transition(
                        attempt,
                        ProviderInvocationState::PreDispatchAborted,
                        vec![error.to_string()],
                    )?;
                } else {
                    let _ = reservation_owner.mark_unknown_outcome(reservation_id, &error_text);
                    if let Err(journal_error) = journal.record_post_dispatch_failure(
                        attempt,
                        vec![format!("supervisor_error:{error_text}")],
                    ) {
                        return Err(EngineError::WriteRejected(format!(
                            "Antigravity process failed after dispatch and reconciliation journaling failed; provider redispatch is forbidden; supervisor_error={error_text}; journal_error={journal_error}"
                        )));
                    }
                }
                return Err(error);
            }
        };
        if let Err(error) = journal.record_process_terminal(attempt, &output) {
            let _ = reservation_owner.mark_unknown_outcome(
                reservation_id,
                "process reaped but terminal journal persistence requires reconciliation",
            );
            return Err(error);
        }

        let stdout_capture = ProviderOutputSpool.capture(
            data_root,
            &attempt.invocation_attempt_id,
            "stdout",
            std::io::Cursor::new(output.stdout.clone()),
            DEFAULT_MAX_OUTPUT_BYTES as u64,
        );
        let stdout_capture = match stdout_capture {
            Ok(capture) => capture,
            Err(error) => {
                let _ = journal.transition(
                    attempt,
                    ProviderInvocationState::LocalCaptureFailed,
                    vec![format!("stdout_capture_failed:{error}")],
                );
                let _ = reservation_owner.fail_after_dispatch(
                    reservation_id,
                    "Antigravity stdout capture failed after terminal process facts",
                );
                return Err(error);
            }
        };
        let stderr_capture = ProviderOutputSpool.capture(
            data_root,
            &attempt.invocation_attempt_id,
            "stderr",
            std::io::Cursor::new(output.stderr.clone()),
            DEFAULT_MAX_OUTPUT_BYTES as u64,
        );
        let stderr_capture = match stderr_capture {
            Ok(capture) => capture,
            Err(error) => {
                let _ = journal.transition(
                    attempt,
                    ProviderInvocationState::LocalCaptureFailed,
                    vec![format!("stderr_capture_failed:{error}")],
                );
                let _ = reservation_owner.fail_after_dispatch(
                    reservation_id,
                    "Antigravity stderr capture failed after terminal process facts",
                );
                return Err(error);
            }
        };
        if let Err(error) = journal.record_captured_output(
            attempt,
            stdout_capture.blob_ref.clone(),
            stderr_capture.blob_ref.clone(),
        ) {
            let _ = reservation_owner.mark_unknown_outcome(
                reservation_id,
                "captured Antigravity output refs could not be journaled",
            );
            return Err(error);
        }
        if stdout_capture.output_observed || stderr_capture.output_observed {
            journal.transition(
                attempt,
                ProviderInvocationState::OutputObserved,
                vec!["supervised capture observed provider output".to_owned()],
            )?;
        }
        let stdout_text = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr_text = String::from_utf8_lossy(&output.stderr).into_owned();
        let combined = output_text(stdout_text.as_bytes(), stderr_text.as_bytes());
        let normalized = AntigravityTextOutputNormalizer.normalize_text(request, &combined);
        let structured_bytes = match serde_json::to_vec(&normalized) {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = journal.transition(
                    attempt,
                    ProviderInvocationState::LocalCaptureFailed,
                    vec![format!("structured_serialization_failed:{error}")],
                );
                let _ = reservation_owner.fail_after_dispatch(
                    reservation_id,
                    "Antigravity structured serialization failed after terminal process facts",
                );
                return Err(error.into());
            }
        };
        let structured_capture = ProviderOutputSpool.capture(
            data_root,
            &attempt.invocation_attempt_id,
            "structured",
            std::io::Cursor::new(structured_bytes),
            DEFAULT_MAX_OUTPUT_BYTES as u64,
        );
        let structured_capture = match structured_capture {
            Ok(capture) => capture,
            Err(error) => {
                let _ = journal.transition(
                    attempt,
                    ProviderInvocationState::LocalCaptureFailed,
                    vec![format!("structured_capture_failed:{error}")],
                );
                let _ = reservation_owner.fail_after_dispatch(
                    reservation_id,
                    "Antigravity structured capture failed after terminal process facts",
                );
                return Err(error);
            }
        };
        attempt.structured_output_blob_or_hash = Some(structured_capture.blob_ref.clone());
        if let Err(error) = journal.persist(attempt) {
            let _ = reservation_owner.mark_unknown_outcome(
                reservation_id,
                "captured Antigravity structured output ref could not be journaled",
            );
            return Err(error);
        }
        let exit_success = output.exit_code == Some(0);
        let capture_complete = output.reap_receipt.proves_complete_reap()
            && output.worker_error.is_none()
            && !output.stdout_truncated
            && !output.stderr_truncated
            && !stdout_capture.truncation_detected
            && !stderr_capture.truncation_detected
            && !structured_capture.truncation_detected
            && stdout_capture.stream_closed_cleanly
            && stderr_capture.stream_closed_cleanly
            && structured_capture.stream_closed_cleanly;
        let state = if output.timed_out {
            AntigravityRunState::TimedOut
        } else if exit_success && capture_complete {
            AntigravityRunState::Succeeded
        } else {
            AntigravityRunState::Failed
        };
        let completed_at = output.cleanup_completed_at;
        let terminal_state =
            if output.worker_error.is_some() || !output.reap_receipt.proves_complete_reap() {
                ProviderInvocationState::CleanupFailedAfterComplete
            } else if !capture_complete {
                ProviderInvocationState::LocalCaptureFailed
            } else if output.timed_out || stderr_text.contains("timeout waiting for response") {
                ProviderInvocationState::TimeoutPendingReconciliation
            } else if exit_success {
                ProviderInvocationState::CompletedCaptured
            } else {
                ProviderInvocationState::ProcessExitedNonzero
            };
        journal.transition(
            attempt,
            terminal_state,
            vec![format!(
                "exit_success={exit_success};timed_out={};timeout_class={:?};reap_complete={};worker_error={:?};stdout_truncated={};stderr_truncated={}",
                output.timed_out,
                output.timeout_class,
                output.reap_receipt.proves_complete_reap(),
                output.worker_error,
                output.stdout_truncated,
                output.stderr_truncated
            )],
        )?;
        let redaction_receipt = AntigravityOutputRedactionReceipt {
            redacted: false,
            redacted_markers: Vec::new(),
            original_bytes: output.stdout.len().saturating_add(output.stderr.len()),
            retained_bytes: output.stdout.len().saturating_add(output.stderr.len()),
        };
        let (receipt_argv, prompt_hash_blake3) = safety_argv_receipt(&argv, &request.question);
        Ok(AntigravityRun {
            run_id: new_id("antigravity-run"),
            request_id: request.request_id.clone(),
            state,
            provider_state: if exit_success && capture_complete {
                AntigravityProviderState::ReadyEnabled
            } else {
                AntigravityProviderState::DetectedDisabled
            },
            dry_run: false,
            fixture_runner: false,
            binary_path: contract.binary_path.clone(),
            effective_cwd: path_for_record(&effective_cwd),
            stdout_blob_ref: Some(stdout_capture.blob_ref),
            stderr_blob_ref: Some(stderr_capture.blob_ref),
            log_blob_ref: Some(blob_ref("antigravity/log.txt", combined.len())),
            stdout_excerpt: truncate_text(&stdout_text, 2_000),
            stderr_excerpt: truncate_text(&stderr_text, 2_000),
            safety_receipt: AntigravitySafetyReceipt {
                typed_argv: receipt_argv,
                prompt_hash_blake3,
                shell_false: true,
                stdin_devnull: true,
                process_group_kill_on_timeout: true,
                timeout_ms: DEFAULT_TIMEOUT_MS,
                max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
                effective_cwd: path_for_record(&effective_cwd),
                env_fixed_vars: process_env,
                env_dropped_names: dropped_names,
            },
            redaction_receipt,
            normalized_result: Some(normalized),
            message: if output.timed_out {
                "real Antigravity run hit the supervised absolute deadline".to_owned()
            } else if exit_success {
                "real Antigravity run completed with supervised durable capture".to_owned()
            } else {
                "real Antigravity run exited nonzero; output is pending reconciliation".to_owned()
            },
            created_at: started,
            completed_at: Some(completed_at),
        })
    }

    pub fn run_fixture(
        &self,
        request: &AntigravityReviewRequest,
        contract: &AntigravityCommandContract,
        effective_cwd: &Path,
    ) -> Result<AntigravityRun, EngineError> {
        let stdout = format!(
            "Antigravity fixture review for task {}. Candidate finding: inspect governed MCP tools and cognitive gate before any change.\n{}",
            request.task,
            AntigravityLiveSmokeService::CANDIDATE_FINAL_LINE
        );
        let redacted_stdout = redact_output(&stdout);
        let normalized =
            AntigravityTextOutputNormalizer.normalize_text(request, &redacted_stdout.text);
        let argv =
            AntigravityCommandContractService.typed_review_argv(contract, &request.question)?;
        let (receipt_argv, prompt_hash_blake3) = safety_argv_receipt(&argv, &request.question);
        let safety_receipt = AntigravitySafetyReceipt {
            typed_argv: receipt_argv,
            prompt_hash_blake3,
            shell_false: true,
            stdin_devnull: true,
            process_group_kill_on_timeout: true,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            effective_cwd: path_for_record(effective_cwd),
            env_fixed_vars: default_env_policy().fixed_vars,
            env_dropped_names: default_env_policy().dropped_names,
        };
        Ok(AntigravityRun {
            run_id: new_id("antigravity-run"),
            request_id: request.request_id.clone(),
            state: AntigravityRunState::DryRun,
            provider_state: AntigravityProviderState::DetectedDisabled,
            dry_run: true,
            fixture_runner: true,
            binary_path: contract.binary_path.clone(),
            effective_cwd: path_for_record(effective_cwd),
            stdout_blob_ref: Some(blob_ref(
                "antigravity/stdout.txt",
                redacted_stdout.text.len(),
            )),
            stderr_blob_ref: Some(blob_ref("antigravity/stderr.txt", 0)),
            log_blob_ref: Some(blob_ref("antigravity/log.txt", 0)),
            stdout_excerpt: truncate_text(&redacted_stdout.text, 2_000),
            stderr_excerpt: String::new(),
            safety_receipt,
            redaction_receipt: redacted_stdout.receipt,
            normalized_result: Some(normalized),
            message: "fixture dry-run completed without provider execution".to_owned(),
            created_at: OffsetDateTime::now_utc(),
            completed_at: Some(OffsetDateTime::now_utc()),
        })
    }

    pub fn blocked_run(
        &self,
        request: &AntigravityReviewRequest,
        contract: &AntigravityCommandContract,
        gate_decision: &AntigravityExecutionGateDecision,
        effective_cwd: &Path,
    ) -> AntigravityRun {
        AntigravityRun {
            run_id: new_id("antigravity-run"),
            request_id: request.request_id.clone(),
            state: AntigravityRunState::Blocked,
            provider_state: AntigravityProviderState::DetectedDisabled,
            dry_run: false,
            fixture_runner: false,
            binary_path: contract.binary_path.clone(),
            effective_cwd: path_for_record(effective_cwd),
            stdout_blob_ref: None,
            stderr_blob_ref: None,
            log_blob_ref: None,
            stdout_excerpt: String::new(),
            stderr_excerpt: String::new(),
            safety_receipt: AntigravitySafetyReceipt {
                typed_argv: Vec::new(),
                prompt_hash_blake3: blake3::hash(request.question.as_bytes())
                    .to_hex()
                    .to_string(),
                shell_false: true,
                stdin_devnull: true,
                process_group_kill_on_timeout: true,
                timeout_ms: DEFAULT_TIMEOUT_MS,
                max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
                effective_cwd: path_for_record(effective_cwd),
                env_fixed_vars: default_env_policy().fixed_vars,
                env_dropped_names: default_env_policy().dropped_names,
            },
            redaction_receipt: AntigravityOutputRedactionReceipt {
                redacted: false,
                redacted_markers: Vec::new(),
                original_bytes: 0,
                retained_bytes: 0,
            },
            normalized_result: None,
            message: format!("blocked by gate: {}", gate_decision.reasons.join("; ")),
            created_at: OffsetDateTime::now_utc(),
            completed_at: Some(OffsetDateTime::now_utc()),
        }
    }
}

impl AntigravityTextOutputNormalizer {
    pub fn normalize_text(
        &self,
        request: &AntigravityReviewRequest,
        text: &str,
    ) -> AntigravityNormalizedResult {
        let run_id = new_id("antigravity-normalization-run");
        let lower = text.to_ascii_lowercase();
        if lower.contains("done_verified")
            || lower.contains("verified:")
            || lower.contains("i have applied")
        {
            return AntigravityNormalizedResult {
                result_id: new_id("antigravity-result"),
                request_id: request.request_id.clone(),
                run_id,
                candidate_only: true,
                taint: TaintClass::ExternalAgent,
                external_review_result: None,
                rejected: true,
                rejection_reasons: vec![
                    "Antigravity output attempted a verified or action authority claim".to_owned(),
                ],
                write_receipt: None,
                created_at: OffsetDateTime::now_utc(),
            };
        }
        let external_request = external_request_from_antigravity(request);
        let job = ExternalReviewJob {
            job_id: new_id("external-review-job"),
            request_id: external_request.request_id.clone(),
            provider_id: external_request.provider_id.clone(),
            status: ExternalReviewJobStatus::Succeeded,
            adapter_request_id: None,
            adapter_result_id: None,
            result_id: None,
            raw_output_blob_ref: Some(blob_ref("antigravity/raw-output.txt", text.len())),
            message: "Antigravity text output captured as candidate-only evidence".to_owned(),
            created_at: OffsetDateTime::now_utc(),
            completed_at: Some(OffsetDateTime::now_utc()),
        };
        let raw = json!({
            "candidate_only": true,
            "findings": [{
                "finding_id": new_id("antigravity-finding"),
                "title": "Antigravity candidate output",
                "detail": truncate_text(text, 1_000),
                "severity": "info",
                "claim_status": "candidate",
                "citations": [{
                    "citation_id": new_id("antigravity-citation"),
                    "evidence_ref": request
                        .evidence_refs
                        .first()
                        .cloned()
                        .unwrap_or_else(|| "antigravity:stdout".to_owned()),
                    "file": request.allowed_paths.first().cloned(),
                    "line": 1,
                    "status": "cited"
                }]
            }],
            "proposed_changes": [],
            "verifier_suggestions": [],
            "uncertainties": []
        });
        let outcome = ExternalReviewNormalizer.normalize(&external_request, &job, &raw);
        let rejected = outcome.result.is_none();
        AntigravityNormalizedResult {
            result_id: new_id("antigravity-result"),
            request_id: request.request_id.clone(),
            run_id,
            candidate_only: true,
            taint: TaintClass::ExternalAgent,
            external_review_result: outcome.result,
            rejected,
            rejection_reasons: if rejected {
                vec![format!(
                    "external-review normalizer rejected Antigravity text as {:?}",
                    outcome.receipt.status
                )]
            } else {
                Vec::new()
            },
            write_receipt: None,
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub const fn included_in_normal_l3(&self, _result: &AntigravityNormalizedResult) -> bool {
        false
    }
}

impl AgyMcpCompatibilityAuditService {
    pub fn raw_tools_exposed(&self) -> bool {
        false
    }

    pub fn notes(&self) -> Vec<String> {
        vec![
            "agy-mcp is not used on the hot path".to_owned(),
            "raw agy or agy-mcp tools are not exposed through Eliot MCP".to_owned(),
        ]
    }
}

impl AntigravityTelemetryService {
    pub fn report(
        &self,
        probe: &AntigravityCapabilityProbe,
        runs: &[AntigravityRun],
    ) -> AntigravityTelemetryReport {
        AntigravityTelemetryReport {
            component: "antigravity_telemetry".to_owned(),
            detection_state: probe.provider_state,
            run_count: runs.len(),
            dry_run_count: runs.iter().filter(|run| run.dry_run).count(),
            real_run_count: runs.iter().filter(|run| !run.dry_run).count(),
            stdout_bytes: runs.iter().map(|run| run.stdout_excerpt.len()).sum(),
            stderr_bytes: runs.iter().map(|run| run.stderr_excerpt.len()).sum(),
            redaction_count: runs
                .iter()
                .filter(|run| run.redaction_receipt.redacted)
                .count(),
            timeouts: runs
                .iter()
                .filter(|run| run.state == AntigravityRunState::TimedOut)
                .count(),
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityDoctorIntegration {
    pub fn status(
        &self,
        resolution: &AntigravityBinaryResolution,
        probe: &AntigravityCapabilityProbe,
        contract: &AntigravityCommandContract,
        official_plugin_ready: bool,
        mcp_registered: bool,
        governed_mcp_tools_only: bool,
    ) -> AntigravityDoctorStatus {
        let ready = resolution.status == AntigravityBinaryResolutionStatus::Resolved
            && contract.noninteractive_supported
            && official_plugin_ready
            && mcp_registered
            && governed_mcp_tools_only;
        AntigravityDoctorStatus {
            component: "antigravity_doctor".to_owned(),
            provider_state: probe.provider_state,
            binary_resolution_status: resolution.status,
            contract_available: contract.noninteractive_supported
                || contract.source == AntigravityContractSource::Fixture,
            official_plugin_ready,
            mcp_registered,
            raw_agy_mcp_exposed: false,
            governed_mcp_tools_only,
            ready,
            message: match probe.provider_state {
                AntigravityProviderState::NotInstalled => {
                    "Antigravity is unavailable; real provider integration is not ready".to_owned()
                }
                _ if !official_plugin_ready => {
                    "Antigravity is installed, but the official ELIOT plugin is not ready"
                        .to_owned()
                }
                _ if !mcp_registered => {
                    "Antigravity is installed, but its ELIOT MCP registration is not executable"
                        .to_owned()
                }
                AntigravityProviderState::ReadyEnabled => {
                    "Antigravity provider is enabled through a current governed receipt".to_owned()
                }
                _ => {
                    "Antigravity detected but real execution remains disabled by default".to_owned()
                }
            },
            generated_at: OffsetDateTime::now_utc(),
        }
    }
}

impl AntigravityMcpBoundaryService {
    pub fn exposes_only_governed(&self, tools: &[&str], catalog_tools: &[&str]) -> bool {
        tools.iter().all(|tool| catalog_tools.contains(tool)) && self.no_raw_agy_tools(tools)
    }

    pub fn no_raw_agy_tools(&self, tools: &[&str]) -> bool {
        let denied = [
            "raw_agy", "agy_mcp", "login", "install", "shell", "secret", "patch", "truth",
            "mutation", "execute", "enable", "request",
        ];
        tools
            .iter()
            .all(|tool| denied.iter().all(|needle| !tool.contains(needle)))
    }

    pub fn invocation_receipt(
        &self,
        profile: &str,
        tool_name: &str,
        succeeded: bool,
        profile_allows_tool: bool,
    ) -> Result<AntigravityMcpInvocationReceipt, EngineError> {
        self.invocation_receipt_with_audit(profile, tool_name, succeeded, None, profile_allows_tool)
    }

    pub fn invocation_receipt_with_audit(
        &self,
        profile: &str,
        tool_name: &str,
        succeeded: bool,
        audit_event_ref: Option<&str>,
        profile_allows_tool: bool,
    ) -> Result<AntigravityMcpInvocationReceipt, EngineError> {
        if profile != "external_auditor" || !profile_allows_tool {
            return Err(rejected(
                "Antigravity MCP recursion or non-status tool invocation denied",
            ));
        }
        let audit_event_ref = audit_event_ref
            .map(str::trim)
            .filter(|reference| !reference.is_empty())
            .map(ToOwned::to_owned);
        if succeeded && audit_event_ref.is_none() {
            return Err(rejected(
                "successful Antigravity MCP invocation requires a matching ELIOT audit event",
            ));
        }
        Ok(AntigravityMcpInvocationReceipt {
            component: "antigravity_mcp_invocation_receipt".to_owned(),
            profile: profile.to_owned(),
            tool_name: tool_name.to_owned(),
            succeeded,
            matching_audit_event: audit_event_ref.is_some(),
            audit_event_ref,
            candidate_only: true,
            authority: "bounded status/report only; no provider, mutation, patch, completion, or truth authority"
                .to_owned(),
            invoked_at: OffsetDateTime::now_utc(),
        })
    }
}

pub fn antigravity_review_request(
    project: &str,
    task: &str,
    mode: AntigravityReviewMode,
    question: &str,
) -> AntigravityReviewRequest {
    AntigravityReviewRequest {
        request_id: new_id("antigravity-request"),
        project: project.to_owned(),
        project_id: ProjectId::new_v7(),
        task: task.to_owned(),
        task_id: TaskId::new_v7(),
        mode,
        question: question.to_owned(),
        work_lease_id: None,
        worktree_lease_id: None,
        allowed_paths: vec!["crates/eliot-app/src/mcp_stdio.rs".to_owned()],
        evidence_refs: vec!["codecortex:latest".to_owned()],
        provider_enabled: false,
        last_accepted_packet_id: None,
        created_at: OffsetDateTime::now_utc(),
    }
}

pub fn antigravity_report(
    resolution: AntigravityBinaryResolution,
    probe: AntigravityCapabilityProbe,
    contract: AntigravityCommandContract,
    latest_request: Option<AntigravityReviewRequest>,
    latest_run: Option<AntigravityRun>,
    doctor: AntigravityDoctorStatus,
    telemetry: AntigravityTelemetryReport,
) -> AntigravityReport {
    AntigravityReport {
        component: "antigravity_report".to_owned(),
        resolution,
        probe,
        contract,
        latest_request,
        latest_run,
        doctor,
        telemetry,
        generated_at: OffsetDateTime::now_utc(),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn antigravity_real_report(
    resolution: AntigravityBinaryResolution,
    probe: AntigravityCapabilityProbe,
    contract: AntigravityCommandContract,
    auth_check: AntigravityAuthCheck,
    enablement: Option<AntigravityEnablementReceipt>,
    latest_live_smoke: Option<AntigravityLiveSmokeResult>,
    disable_receipt: Option<AntigravityDisableReceipt>,
    doctor: AntigravityRealDoctorStatus,
    telemetry: AntigravityTelemetryReport,
) -> AntigravityRealReport {
    AntigravityRealReport {
        component: "antigravity_real_report".to_owned(),
        resolution,
        probe,
        contract,
        auth_check,
        enablement,
        latest_live_smoke,
        disable_receipt,
        doctor,
        telemetry,
        visibility: None,
        generated_at: OffsetDateTime::now_utc(),
    }
}

fn where_command_hits(name: &str) -> Vec<PathBuf> {
    let Ok(output) = ProcessCommand::new("where.exe")
        .arg(name)
        .stdin(Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect()
}

async fn run_supervised_provider_probe(
    path: &Path,
    arg: &str,
    operation_class: &str,
    timeout_ms: u64,
    runner: &dyn ProviderProcessRunner,
) -> Result<(String, bool, bool), EngineError> {
    let source_env = std::env::vars().collect::<Vec<_>>();
    let process_env = AntigravityEnvPolicyService.minimal_windows_env(&source_env);
    let route_policy = ProviderRoutePolicy::for_route(
        eliot_types::AgentHostId::Antigravity,
        operation_class,
        eliot_types::ProviderDeclaredBudget::new(timeout_ms, 2_000)
            .with_idle_output_deadline_ms(Some(timeout_ms)),
    );
    let mut on_spawned = |_| Ok(());
    let output = runner
        .run(
            ProviderProcessSpec {
                operation_id: new_id(operation_class),
                invocation_id: None,
                executable: path.to_owned(),
                args: vec![OsString::from(arg)],
                cwd: std::env::current_dir()?,
                environment: process_env
                    .into_iter()
                    .map(|(name, value)| (OsString::from(name), OsString::from(value)))
                    .collect(),
                stdin_payload: None,
                route_policy,
                cancellation: crate::runtime_supervision::CancellationToken::new(),
                deadline: tokio::time::Instant::now()
                    + std::time::Duration::from_millis(timeout_ms),
                runtime_contract_sha256: None,
                role_lease_id: None,
                role_lease_epoch: None,
            },
            &mut on_spawned,
        )
        .await?;
    if !output.reap_receipt.proves_complete_reap() {
        return Err(rejected(
            "provider probe returned an incomplete reap receipt",
        ));
    }
    if let Some(error) = output.worker_error {
        return Err(rejected(&format!("provider probe cleanup failed: {error}")));
    }
    Ok((
        output_text(&output.stdout, &output.stderr),
        output.timed_out,
        output.exit_code == Some(0),
    ))
}

fn run_help_probe(path: &Path, timeout_ms: u64) -> Result<(String, bool), EngineError> {
    let (output, timed_out, _succeeded) = run_bounded_command(path, &["--help"], timeout_ms)?;
    Ok((output, timed_out))
}

fn run_bounded_command(
    path: &Path,
    args: &[&str],
    timeout_ms: u64,
) -> Result<(String, bool, bool), EngineError> {
    let source_env = std::env::vars().collect::<Vec<_>>();
    let process_env = AntigravityEnvPolicyService.minimal_windows_env(&source_env);
    let mut command = ProcessCommand::new(path);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_clear();
    for (name, value) in process_env {
        command.env(name, value);
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now() + StdDuration::from_millis(timeout_ms);
    loop {
        if let Some(status) = child.try_wait()? {
            let output = child.wait_with_output()?;
            return Ok((
                output_text(&output.stdout, &output.stderr),
                false,
                status.success(),
            ));
        }
        if Instant::now() >= deadline {
            terminate_process_tree(&mut child);
            let output = child.wait_with_output()?;
            return Ok((output_text(&output.stdout, &output.stderr), true, false));
        }
        std::thread::sleep(StdDuration::from_millis(25));
    }
}

fn terminate_process_tree(child: &mut std::process::Child) {
    #[cfg(windows)]
    {
        let _ = ProcessCommand::new("taskkill.exe")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
}

fn safe_invocation_component(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect()
}

fn authenticode_signature(path: &Path) -> (AntigravityBinarySignatureStatus, Option<String>) {
    #[cfg(windows)]
    {
        let path_text = path_for_record(path);
        let escaped_path = path_text.replace('\'', "''");
        let script = format!(
            "$s=Get-AuthenticodeSignature -LiteralPath '{escaped_path}'; [pscustomobject]@{{status=[string]$s.Status;subject=if($s.SignerCertificate){{$s.SignerCertificate.Subject}}else{{$null}}}} | ConvertTo-Json -Compress"
        );
        let args = [
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &script,
        ];
        let Ok((output, timed_out, succeeded)) =
            run_bounded_command(Path::new("powershell.exe"), &args, HELP_PROBE_TIMEOUT_MS)
        else {
            return (AntigravityBinarySignatureStatus::Unavailable, None);
        };
        if timed_out || !succeeded {
            return (AntigravityBinarySignatureStatus::Unavailable, None);
        }
        let Ok(value) = serde_json::from_str::<Value>(output.trim()) else {
            return (AntigravityBinarySignatureStatus::Unavailable, None);
        };
        let status = match value
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str()
        {
            "valid" => AntigravityBinarySignatureStatus::Valid,
            "notsigned" => AntigravityBinarySignatureStatus::NotSigned,
            "unknownerror" | "hashmismatch" | "nottrusted" => {
                AntigravityBinarySignatureStatus::Invalid
            }
            _ => AntigravityBinarySignatureStatus::Unavailable,
        };
        let subject = value
            .get("subject")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        (status, subject)
    }
    #[cfg(not(windows))]
    {
        let _ = path;
        (AntigravityBinarySignatureStatus::Unavailable, None)
    }
}

fn parse_semantic_version(output: &str) -> Option<(u64, u64, u64, String)> {
    let bytes = output.as_bytes();
    for start in 0..bytes.len() {
        if !bytes[start].is_ascii_digit() {
            continue;
        }
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
            end += 1;
        }
        let candidate = &output[start..end];
        let parts = candidate.split('.').collect::<Vec<_>>();
        if parts.len() < 3 || parts[..3].iter().any(|part| part.is_empty()) {
            continue;
        }
        let (Ok(major), Ok(minor), Ok(patch)) = (
            parts[0].parse::<u64>(),
            parts[1].parse::<u64>(),
            parts[2].parse::<u64>(),
        ) else {
            continue;
        };
        let text = format!("{major}.{minor}.{patch}");
        return Some((major, minor, patch, text));
    }
    None
}

fn validate_active_work_lease_in_state(
    state: &WorkState,
    expected: &WorkLease,
) -> Result<(), EngineError> {
    let lease = state
        .leases
        .iter()
        .find(|lease| lease.work_lease_id == expected.work_lease_id)
        .ok_or_else(|| rejected("active WorkLease is not present in WorkState"))?;
    if !work_lease_is_active(lease)
        || lease.project_id != expected.project_id
        || lease.task_id != expected.task_id
        || lease.work_item_id != expected.work_item_id
        || lease.agent_session_id != expected.agent_session_id
        || lease.agent_id != expected.agent_id
    {
        return Err(rejected("WorkState WorkLease does not match active lease"));
    }
    Ok(())
}

fn validate_real_worktree(
    request: &AntigravityReviewRequest,
    lease: &WorktreeLease,
    effective_cwd: &Path,
) -> Result<PathBuf, EngineError> {
    if lease.state != WorktreeLeaseState::Active || lease.expires_at < OffsetDateTime::now_utc() {
        return Err(rejected(
            "real Antigravity run requires an active disposable WorktreeLease",
        ));
    }
    if request.work_lease_id != Some(lease.work_lease_id)
        || request.worktree_lease_id != Some(lease.worktree_lease_id)
        || request.project_id != lease.project_id
        || request.task_id != lease.task_id
    {
        return Err(rejected(
            "real Antigravity run does not match disposable WorktreeLease identity",
        ));
    }
    let cwd = effective_cwd.canonicalize()?;
    let leased_path = Path::new(&lease.worktree_path).canonicalize()?;
    if cwd != leased_path {
        return Err(rejected(
            "real Antigravity effective cwd must equal WorktreeLease.worktree_path",
        ));
    }
    Ok(cwd)
}

fn git_bytes_sync(cwd: &Path, args: &[&str]) -> Result<Vec<u8>, EngineError> {
    let output = ProcessCommand::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if !output.status.success() {
        return Err(rejected(&format!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

fn git_text_raw_sync(cwd: &Path, args: &[&str]) -> Result<String, EngineError> {
    Ok(String::from_utf8_lossy(&git_bytes_sync(cwd, args)?).into_owned())
}

fn git_text_sync(cwd: &Path, args: &[&str]) -> Result<String, EngineError> {
    Ok(git_text_raw_sync(cwd, args)?.trim().to_owned())
}

async fn git_status_async(cwd: &Path, args: &[&str]) -> Result<(), EngineError> {
    let mut command = tokio::process::Command::new("git");
    command
        .args(args)
        .current_dir(cwd)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = tokio::time::timeout(StdDuration::from_secs(30), command.output())
        .await
        .map_err(|_| rejected("git worktree command timed out"))??;
    if !output.status.success() {
        return Err(rejected(&format!(
            "git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn validate_eliot_mcp_executable(eliot_exe: &Path) -> Result<String, EngineError> {
    if !eliot_exe.is_absolute() {
        return Err(rejected("ELIOT MCP executable path must be absolute"));
    }
    let file_name = eliot_exe
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !file_name.starts_with("eliot") || command_is_antigravity(&path_for_record(eliot_exe)) {
        return Err(rejected(
            "ELIOT MCP executable must be an ELIOT binary and cannot recurse into Antigravity",
        ));
    }
    Ok(path_for_record(eliot_exe))
}

fn validate_project_root(project_root: &Path) -> Result<String, EngineError> {
    if !project_root.is_absolute() || !project_root.is_dir() {
        return Err(rejected(
            "ELIOT_PROJECT_ROOT must be an existing absolute directory",
        ));
    }
    Ok(path_for_record(&project_root.canonicalize()?))
}

fn command_is_antigravity(command: &str) -> bool {
    let file_name = Path::new(command)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(command)
        .to_ascii_lowercase();
    file_name == "agy" || file_name == "agy.exe" || file_name.starts_with("antigravity")
}

fn mcp_entry_has_secret_fields(entry: &Value) -> bool {
    let Some(object) = entry.as_object() else {
        return false;
    };
    object.iter().any(|(name, value)| {
        let lower = name.to_ascii_lowercase();
        matches!(lower.as_str(), "headers" | "oauth")
            || lower.contains("token")
            || lower.contains("secret")
            || lower.contains("password")
            || lower.contains("credential")
            || (lower == "env" && env_has_secret_like_values(value))
    })
}

fn env_has_secret_like_values(value: &Value) -> bool {
    let Some(env) = value.as_object() else {
        return true;
    };
    env.keys().any(|name| {
        let lower = name.to_ascii_lowercase();
        lower.contains("token")
            || lower.contains("secret")
            || lower.contains("password")
            || lower.contains("credential")
            || lower.contains("cookie")
            || lower.contains("key")
    })
}

fn unknown_root_fields_preserved(existing: &Value, merged: &Value) -> bool {
    let Some(existing) = existing.as_object() else {
        return false;
    };
    let Some(merged) = merged.as_object() else {
        return false;
    };
    existing
        .iter()
        .filter(|(name, _)| name.as_str() != "mcpServers")
        .all(|(name, value)| merged.get(name) == Some(value))
}

fn unknown_servers_preserved(existing: &Value, merged: &Value) -> bool {
    let existing = existing
        .get("mcpServers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let merged = merged
        .get("mcpServers")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    existing
        .iter()
        .filter(|(name, _)| name.as_str() != ELIOT_MCP_SERVER_NAME)
        .all(|(name, value)| merged.get(name) == Some(value))
}

fn atomic_backup_and_replace_json(
    path: &Path,
    value: &Value,
) -> Result<Option<PathBuf>, EngineError> {
    let parent = path
        .parent()
        .ok_or_else(|| rejected("Antigravity MCP config has no parent directory"))?;
    fs::create_dir_all(parent)?;
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| rejected("Antigravity MCP config filename is not UTF-8"))?;
    let temp_path = parent.join(format!(".{file_name}.eliot-{}.tmp", WriteId::new_v7()));
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut temp = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temp_path)?;
    temp.write_all(&bytes)?;
    temp.write_all(b"\n")?;
    temp.sync_all()?;
    drop(temp);
    let _: Value = serde_json::from_slice(&fs::read(&temp_path)?)?;

    let backup_path = if path.exists() {
        let backup = parent.join(format!(
            "{file_name}.eliot-backup-{}-{}",
            OffsetDateTime::now_utc().unix_timestamp(),
            WriteId::new_v7()
        ));
        fs::rename(path, &backup)?;
        Some(backup)
    } else {
        None
    };
    if let Err(error) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        if let Some(backup) = &backup_path {
            let _ = fs::rename(backup, path);
        }
        return Err(error.into());
    }
    Ok(backup_path)
}

fn valid_plugin_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
}

fn read_json_if_present(path: &Path) -> Option<Value> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

fn valid_plugin_at(root: &Path, require_schema: bool) -> bool {
    let Some(manifest) = read_json_if_present(&root.join("plugin.json")) else {
        return false;
    };
    let name_valid = manifest
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(valid_plugin_name);
    let schema_valid =
        manifest.get("$schema").and_then(Value::as_str) == Some(OFFICIAL_PLUGIN_SCHEMA);
    name_valid && (!require_schema || schema_valid)
}

fn directory_has_files(root: &Path) -> bool {
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| entry.path().is_file())
}

fn directory_contains_file_named(root: &Path, expected: &str) -> bool {
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| {
            let path = entry.path();
            if path.is_file() {
                path.file_name().is_some_and(|name| name == expected)
            } else if path.is_dir() {
                directory_has_named_file_one_level(&path, expected)
            } else {
                false
            }
        })
}

fn directory_has_named_file_one_level(root: &Path, expected: &str) -> bool {
    fs::read_dir(root)
        .ok()
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .any(|entry| {
            let path = entry.path();
            path.is_file() && path.file_name().is_some_and(|name| name == expected)
        })
}

fn parse_capabilities(help_text: &str) -> AntigravityCapabilities {
    let lower = help_text.to_ascii_lowercase();
    AntigravityCapabilities {
        print_mode: lower.contains("--print") || lower.contains(" -p"),
        prompt_arg: lower.contains("--prompt") || lower.contains(" -p"),
        print_timeout: lower.contains("--print-timeout"),
        log_file: lower.contains("--log-file"),
        sandbox: lower.contains("--sandbox"),
        add_dir: lower.contains("--add-dir"),
        continue_session: lower.contains("--continue"),
        conversation: lower.contains("--conversation"),
        json_output: lower.contains("--json") || lower.contains("json"),
        model_cli_arg: lower.contains("--model"),
        dangerously_skip_permissions_seen: lower.contains("--dangerously-skip-permissions"),
        text_output_supported: true,
    }
}

fn default_argv_policy() -> AntigravityArgvPolicy {
    AntigravityArgvPolicy {
        shell: false,
        fuse_flag_values: true,
        reject_user_value_starting_with_dash: true,
        forbidden_flags: vec![
            "--dangerously-skip-permissions".to_owned(),
            "AGY_BRIDGE_CMD".to_owned(),
        ],
    }
}

fn default_prompt_policy() -> AntigravityPromptPolicy {
    AntigravityPromptPolicy {
        deny_sensitive_paths: true,
        deny_destructive_commands: true,
        deny_remote_pipe_install: true,
        max_prompt_bytes: 16 * 1024,
    }
}

fn default_env_policy() -> AntigravityEnvPolicy {
    AntigravityEnvPolicy {
        clear_env_first: true,
        drop_secret_like_vars: true,
        dropped_names: vec![
            "AGY_BRIDGE_CMD".to_owned(),
            "ANTIGRAVITY_CONVERSATION_ID".to_owned(),
            "NODE_OPTIONS".to_owned(),
            "PYTHONPATH".to_owned(),
            "LD_PRELOAD".to_owned(),
            "DYLD_INSERT_LIBRARIES".to_owned(),
            "GIT_CONFIG_GLOBAL".to_owned(),
            "BASH_ENV".to_owned(),
            "ENV".to_owned(),
        ],
        fixed_vars: vec![
            ("AGY_CLI_DISABLE_AUTO_UPDATE".to_owned(), "1".to_owned()),
            ("AGY_CLI_HIDE_ACCOUNT_INFO".to_owned(), "1".to_owned()),
        ],
    }
}

fn default_sensitive_path_policy() -> AntigravitySensitivePathPolicy {
    AntigravitySensitivePathPolicy {
        denied_fragments: vec![
            ".ssh".to_owned(),
            "id_rsa".to_owned(),
            "AppData".to_owned(),
            ".eliot-governor/data".to_owned(),
        ],
        deny_home_secrets: true,
        deny_data_root: true,
    }
}

fn external_request_from_antigravity(request: &AntigravityReviewRequest) -> ExternalReviewRequest {
    ExternalReviewRequest {
        request_id: format!("external-review:{}", request.request_id),
        project: request.project.clone(),
        project_id: request.project_id,
        task: request.task.clone(),
        task_id: request.task_id,
        provider_id: "antigravity-cli".to_owned(),
        role: ExternalReviewRole::Auditor,
        question: request.question.clone(),
        output_schema: ExternalOutputSchemaKind::AuditFindings,
        budget: ExternalReviewBudget::default(),
        work_lease_id: request.work_lease_id,
        worktree_lease_id: request.worktree_lease_id,
        allowed_paths: request.allowed_paths.clone(),
        evidence_refs: request.evidence_refs.clone(),
        forbidden_actions: Vec::new(),
        created_at: request.created_at,
    }
}

fn output_text(stdout: &[u8], stderr: &[u8]) -> String {
    let mut text = String::from_utf8_lossy(stdout).into_owned();
    if !stderr.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&String::from_utf8_lossy(stderr));
    }
    truncate_text(&text, DEFAULT_MAX_OUTPUT_BYTES)
}

fn looks_executable(path: &Path) -> bool {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) => matches!(
            extension.to_ascii_lowercase().as_str(),
            "exe" | "cmd" | "bat" | "ps1"
        ),
        None => cfg!(not(windows)),
    }
}

fn looks_untrusted_download_or_temp(path: &Path) -> bool {
    let lower = path_for_record(path)
        .replace('\\', "/")
        .to_ascii_lowercase();
    lower.contains("/temp/")
        || lower.contains("/tmp/")
        || lower.contains("/downloads/")
        || lower.ends_with("/temp")
        || lower.ends_with("/tmp")
        || lower.ends_with("/downloads")
}

fn should_drop_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    upper.contains("TOKEN")
        || upper.contains("SECRET")
        || upper.contains("PASSWORD")
        || upper.contains("CREDENTIAL")
        || upper == "AGY_BRIDGE_CMD"
        || upper == "ANTIGRAVITY_CONVERSATION_ID"
        || upper.starts_with("NODE")
        || upper.starts_with("PYTHON")
        || upper.starts_with("LD_")
        || upper.starts_with("DYLD_")
        || upper.starts_with("GIT_CONFIG")
        || upper == "BASH_ENV"
        || upper == "ENV"
}

fn is_safe_runtime_env_name(name: &str) -> bool {
    matches!(
        name.to_ascii_uppercase().as_str(),
        "USERPROFILE"
            | "HOME"
            | "HOMEDRIVE"
            | "HOMEPATH"
            | "USERNAME"
            | "LOCALAPPDATA"
            | "APPDATA"
            | "PROGRAMDATA"
            | "SYSTEMROOT"
            | "WINDIR"
            | "COMSPEC"
            | "TEMP"
            | "TMP"
            | "PATH"
            | "PATHEXT"
    )
}

fn fused_arg(flag: &str, value: &str) -> Result<String, EngineError> {
    if value.trim_start().starts_with('-') {
        return Err(rejected(
            "user-provided Antigravity argv value starts with '-'",
        ));
    }
    Ok(format!("{flag}={value}"))
}

fn contains_shell_interpolation(value: &str) -> bool {
    ["$(", "`", "&&", "||", " ; ", "\nrm ", "\nRemove-Item"]
        .iter()
        .any(|needle| value.contains(needle))
}

const REDACTED_PROVIDER_LINE: &str = "[REDACTED:SENSITIVE_PROVIDER_OUTPUT]";
const SENSITIVE_OUTPUT_MARKERS: &[(&str, &str)] = &[
    ("token", "token"),
    ("secret", "secret"),
    ("password", "password"),
    ("authorization", "authorization"),
    ("api_key", "api_key"),
    ("api-key", "api_key"),
    ("access_key", "access_key"),
    ("access-key", "access_key"),
    ("bearer ", "bearer"),
    ("github_pat_", "provider_credential"),
    ("ghp_", "provider_credential"),
    ("gho_", "provider_credential"),
    ("ghu_", "provider_credential"),
    ("ghs_", "provider_credential"),
    ("ghr_", "provider_credential"),
    ("sk-", "provider_credential"),
    ("sk-proj-", "provider_credential"),
    ("xoxb-", "provider_credential"),
    ("xoxp-", "provider_credential"),
    ("akia", "provider_credential"),
];

struct RedactedOutput {
    text: String,
    receipt: AntigravityOutputRedactionReceipt,
}

fn sensitive_output_markers(text: &str) -> BTreeSet<String> {
    let lower = text.to_ascii_lowercase();
    let mut markers = SENSITIVE_OUTPUT_MARKERS
        .iter()
        .filter(|(needle, _)| lower.contains(needle))
        .map(|(_, label)| (*label).to_owned())
        .collect::<BTreeSet<_>>();
    if contains_compact_jwt(text) {
        markers.insert("jwt".to_owned());
    }
    markers
}

fn contains_compact_jwt(text: &str) -> bool {
    text.split(|character: char| {
        character.is_whitespace()
            || matches!(
                character,
                '"' | '\'' | ',' | ':' | ';' | '=' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    })
    .any(|candidate| {
        let mut segments = candidate.split('.');
        let Some(header) = segments.next() else {
            return false;
        };
        let Some(payload) = segments.next() else {
            return false;
        };
        let Some(signature) = segments.next() else {
            return false;
        };
        segments.next().is_none()
            && header.starts_with("eyJ")
            && payload.len() >= 8
            && signature.len() >= 8
            && [header, payload, signature].iter().all(|segment| {
                segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
            })
    })
}

fn sensitive_header_requires_continuation_redaction(line: &str) -> bool {
    let lower = line
        .trim_end_matches(['\r', '\n'])
        .trim_end()
        .to_ascii_lowercase();
    lower.ends_with("authorization:")
        || lower.ends_with("proxy-authorization:")
        || lower.ends_with("api_key:")
        || lower.ends_with("api-token:")
        || lower.ends_with("api_token:")
        || lower.ends_with("password:")
        || lower.ends_with("secret:")
}

fn redact_output(text: &str) -> RedactedOutput {
    let mut sanitized = String::with_capacity(text.len());
    let mut markers = BTreeSet::new();
    let mut redact_continuation = false;
    for line in text.split_inclusive('\n') {
        let mut line_markers = sensitive_output_markers(line);
        let is_continuation = line.starts_with(' ') || line.starts_with('\t');
        if redact_continuation && is_continuation {
            line_markers.insert("credential_continuation".to_owned());
        }
        redact_continuation = if is_continuation {
            redact_continuation
        } else {
            sensitive_header_requires_continuation_redaction(line)
        };
        if line_markers.is_empty() {
            sanitized.push_str(line);
            continue;
        }
        markers.extend(line_markers);
        sanitized.push_str(REDACTED_PROVIDER_LINE);
        if line.ends_with('\n') {
            sanitized.push('\n');
        }
    }
    RedactedOutput {
        receipt: AntigravityOutputRedactionReceipt {
            redacted: !markers.is_empty(),
            redacted_markers: markers.into_iter().collect(),
            original_bytes: text.len(),
            retained_bytes: sanitized.len().min(DEFAULT_MAX_OUTPUT_BYTES),
        },
        text: sanitized,
    }
}

fn merge_redaction_receipts(
    left: &AntigravityOutputRedactionReceipt,
    right: &AntigravityOutputRedactionReceipt,
) -> AntigravityOutputRedactionReceipt {
    let markers = left
        .redacted_markers
        .iter()
        .chain(&right.redacted_markers)
        .cloned()
        .collect::<BTreeSet<_>>();
    AntigravityOutputRedactionReceipt {
        redacted: left.redacted || right.redacted,
        redacted_markers: markers.into_iter().collect(),
        original_bytes: left.original_bytes.saturating_add(right.original_bytes),
        retained_bytes: left.retained_bytes.saturating_add(right.retained_bytes),
    }
}

fn safety_argv_receipt(argv: &[String], prompt: &str) -> (Vec<String>, String) {
    let mut skip_prompt_value = false;
    let argv_without_prompt = argv
        .iter()
        .filter_map(|arg| {
            if skip_prompt_value {
                skip_prompt_value = false;
                return None;
            }
            if arg == "--prompt" {
                skip_prompt_value = true;
                return None;
            }
            (!arg.starts_with("--prompt=")).then(|| arg.clone())
        })
        .collect();
    (
        argv_without_prompt,
        blake3::hash(prompt.as_bytes()).to_hex().to_string(),
    )
}

#[cfg(test)]
struct SensitiveOutputReader<R> {
    reader: BufReader<R>,
    pending: Vec<u8>,
    pending_offset: usize,
    markers: BTreeSet<String>,
    original_bytes: usize,
    retained_bytes: usize,
    discard_oversized_line_tail: bool,
    redact_continuation: bool,
}

#[cfg(test)]
impl<R: Read> SensitiveOutputReader<R> {
    fn new(reader: R) -> Self {
        Self {
            reader: BufReader::new(reader),
            pending: Vec::new(),
            pending_offset: 0,
            markers: BTreeSet::new(),
            original_bytes: 0,
            retained_bytes: 0,
            discard_oversized_line_tail: false,
            redact_continuation: false,
        }
    }

    fn fill_pending(&mut self) -> std::io::Result<bool> {
        if self.discard_oversized_line_tail {
            loop {
                let available = self.reader.fill_buf()?;
                if available.is_empty() {
                    self.discard_oversized_line_tail = false;
                    self.redact_continuation = false;
                    return Ok(false);
                }
                let newline = available.iter().position(|byte| *byte == b'\n');
                let consumed = newline.map_or(available.len(), |position| position + 1);
                self.original_bytes = self.original_bytes.saturating_add(consumed);
                self.reader.consume(consumed);
                if newline.is_some() {
                    self.discard_oversized_line_tail = false;
                    self.redact_continuation = false;
                    self.pending = vec![b'\n'];
                    self.pending_offset = 0;
                    self.retained_bytes = self.retained_bytes.saturating_add(1);
                    return Ok(true);
                }
            }
        }
        let mut raw = Vec::new();
        while raw.len() <= DEFAULT_MAX_OUTPUT_BYTES {
            let available = self.reader.fill_buf()?;
            if available.is_empty() {
                break;
            }
            let remaining = DEFAULT_MAX_OUTPUT_BYTES + 1 - raw.len();
            let through_newline = available
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(available.len(), |position| position + 1);
            let consumed = through_newline.min(remaining);
            raw.extend_from_slice(&available[..consumed]);
            self.reader.consume(consumed);
            if consumed == through_newline && raw.ends_with(b"\n") {
                break;
            }
        }
        if raw.is_empty() {
            return Ok(false);
        }
        self.original_bytes = self.original_bytes.saturating_add(raw.len());
        let raw_text = String::from_utf8_lossy(&raw);
        let mut markers = sensitive_output_markers(&raw_text);
        let is_continuation = matches!(raw.first(), Some(b' ' | b'\t'));
        if self.redact_continuation && is_continuation {
            markers.insert("credential_continuation".to_owned());
        }
        self.redact_continuation = if is_continuation {
            self.redact_continuation
        } else {
            sensitive_header_requires_continuation_redaction(&raw_text)
        };
        if raw.len() > DEFAULT_MAX_OUTPUT_BYTES {
            markers.insert("oversized_line".to_owned());
            self.discard_oversized_line_tail = !raw.ends_with(b"\n");
        }
        self.pending = if markers.is_empty() {
            raw_text.into_owned().into_bytes()
        } else {
            self.markers.extend(markers);
            let mut replacement = REDACTED_PROVIDER_LINE.as_bytes().to_vec();
            if raw.ends_with(b"\n") {
                replacement.push(b'\n');
            }
            replacement
        };
        self.pending_offset = 0;
        self.retained_bytes = self.retained_bytes.saturating_add(self.pending.len());
        Ok(true)
    }

    fn receipt(&self) -> AntigravityOutputRedactionReceipt {
        AntigravityOutputRedactionReceipt {
            redacted: !self.markers.is_empty(),
            redacted_markers: self.markers.iter().cloned().collect(),
            original_bytes: self.original_bytes,
            retained_bytes: self.retained_bytes.min(DEFAULT_MAX_OUTPUT_BYTES),
        }
    }
}

#[cfg(test)]
impl<R: Read> Read for SensitiveOutputReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.pending_offset == self.pending.len() && !self.fill_pending()? {
            return Ok(0);
        }
        let available = &self.pending[self.pending_offset..];
        let copied = available.len().min(buffer.len());
        buffer[..copied].copy_from_slice(&available[..copied]);
        self.pending_offset += copied;
        Ok(copied)
    }
}

fn real_doctor_message(
    resolution: &AntigravityBinaryResolution,
    auth: &AntigravityAuthCheck,
    live_smoke: Option<&AntigravityLiveSmokeResult>,
) -> String {
    if resolution.status != AntigravityBinaryResolutionStatus::Resolved {
        return "Antigravity CLI is not installed or not on the governed PATH probes".to_owned();
    }
    if auth.status == AntigravityAuthStatus::NotAuthenticated {
        return "Antigravity CLI appears unauthenticated; manual Google Sign-In is required outside Governor automation"
            .to_owned();
    }
    if let Some(smoke) = live_smoke {
        return match smoke.status {
            AntigravityLiveSmokeStatus::Passed => {
                "real disposable-worktree Antigravity smoke passed and provider was disabled afterward"
                    .to_owned()
            }
            AntigravityLiveSmokeStatus::ProviderUnavailable => {
                "real smoke was not attempted because provider was unavailable".to_owned()
            }
            AntigravityLiveSmokeStatus::NotAuthenticated => {
                "real smoke reported unauthenticated provider output".to_owned()
            }
            AntigravityLiveSmokeStatus::Timeout => {
                "real smoke timed out and was terminated".to_owned()
            }
            AntigravityLiveSmokeStatus::MalformedOutput => {
                "real smoke output missed the required marker".to_owned()
            }
            AntigravityLiveSmokeStatus::PolicyBlocked => {
                "real smoke was blocked by provider policy gate".to_owned()
            }
            AntigravityLiveSmokeStatus::Failed => "real smoke failed".to_owned(),
        };
    }
    "Antigravity real execution remains disabled pending explicit admin enablement".to_owned()
}

fn gate(
    decision: AntigravityExecutionGateDecisionKind,
    reasons: Vec<String>,
) -> AntigravityExecutionGateDecision {
    AntigravityExecutionGateDecision {
        decision,
        reasons,
        candidate_only: true,
        patch_permission_granted: false,
    }
}

fn path_for_record(path: &Path) -> String {
    strip_windows_verbatim_prefix(path.display().to_string())
}

fn strip_windows_verbatim_prefix(value: String) -> String {
    #[cfg(windows)]
    {
        if let Some(rest) = value.strip_prefix(r"\\?\UNC\") {
            return format!(r"\\{rest}");
        }
        if let Some(rest) = value.strip_prefix(r"\\?\") {
            return rest.to_owned();
        }
        if let Some(rest) = value.strip_prefix("//?/UNC/") {
            return format!("//{rest}");
        }
        if let Some(rest) = value.strip_prefix("//?/") {
            return rest.to_owned();
        }
    }
    value
}

fn truncate_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text[..end].to_owned()
}

fn blob_ref(relative_path: &str, size_bytes: usize) -> BlobRef {
    BlobRef {
        algorithm: "fixture".to_owned(),
        digest_hex: format!("{size_bytes:064x}"),
        size_bytes: size_bytes as u64,
        relative_path: relative_path.to_owned(),
    }
}

fn new_id(prefix: &str) -> String {
    format!("{prefix}-{}", WriteId::new_v7())
}

fn rejected(message: &str) -> EngineError {
    EngineError::WriteRejected(message.to_owned())
}

#[cfg(test)]
mod security_tests {
    use super::*;

    #[test]
    fn external_auditor_can_read_bound_cognitive_delivery_but_not_mutate_truth() {
        for tool in [
            "eliot_host_session_status",
            "eliot_project_identity",
            "eliot_task_state",
            "eliot_current_state",
            "eliot_recall_l0",
            "eliot_fetch_l2",
            "eliot_compile_packet_l3",
            "eliot_task_meaning",
            "eliot_experience_recall",
            "eliot_skill_list",
            "eliot_skill_inspect",
            "eliot_agent_result",
        ] {
            assert!(
                AntigravityMcpBoundaryService
                    .invocation_receipt_with_audit(
                        "external_auditor",
                        tool,
                        true,
                        Some("audit:l16"),
                        true,
                    )
                    .is_ok(),
                "external auditor is missing required delivery tool {tool}"
            );
        }
        for tool in [
            "eliot_task_contract_create",
            "eliot_task_action_request",
            "eliot_agent_result_disposition",
        ] {
            assert!(
                AntigravityMcpBoundaryService
                    .invocation_receipt_with_audit(
                        "external_auditor",
                        tool,
                        true,
                        Some("audit:l16"),
                        false,
                    )
                    .is_err(),
                "external auditor unexpectedly received mutating tool {tool}"
            );
        }
    }

    #[test]
    fn provider_output_redaction_removes_sensitive_values_from_text_and_streams()
    -> Result<(), Box<dyn std::error::Error>> {
        let sentinel = "sentinel-provider-credential-value";
        let source = format!("safe line\nAPI_TOKEN={sentinel}\nlast safe line");
        let redacted = redact_output(&source);
        assert!(redacted.receipt.redacted);
        assert!(!redacted.text.contains(sentinel));
        assert!(redacted.text.contains(REDACTED_PROVIDER_LINE));

        let mut reader = SensitiveOutputReader::new(std::io::Cursor::new(source));
        let mut persisted = String::new();
        reader.read_to_string(&mut persisted)?;
        assert!(reader.receipt().redacted);
        assert!(!persisted.contains(sentinel));
        assert!(persisted.contains(REDACTED_PROVIDER_LINE));
        Ok(())
    }

    #[test]
    fn provider_output_redaction_discards_oversized_line_tail_and_folded_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let tail_secret = "must-not-survive-oversized-tail";
        let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJlbGlvdCJ9.signaturebytes";
        let source = format!(
            "password={}{}\nAuthorization:\n Basic folded-secret\n second-folded-secret\nraw={jwt}\nsafe\n",
            "x".repeat(DEFAULT_MAX_OUTPUT_BYTES + 32),
            tail_secret
        );
        let mut reader = SensitiveOutputReader::new(std::io::Cursor::new(source));
        let mut persisted = String::new();
        reader.read_to_string(&mut persisted)?;
        let receipt = reader.receipt();
        assert!(receipt.redacted);
        assert!(!persisted.contains(tail_secret));
        assert!(!persisted.contains("folded-secret"));
        assert!(!persisted.contains("second-folded-secret"));
        assert!(!persisted.contains(jwt));
        assert!(persisted.contains("safe"));
        assert!(
            receipt
                .redacted_markers
                .contains(&"oversized_line".to_owned())
        );
        assert!(receipt.redacted_markers.contains(&"jwt".to_owned()));
        Ok(())
    }

    #[test]
    fn safety_receipt_omits_prompt_and_retains_only_its_hash()
    -> Result<(), Box<dyn std::error::Error>> {
        let prompt = "private governed prompt sentinel";
        let argv = vec![
            "agy.exe".to_owned(),
            "review".to_owned(),
            format!("--prompt={prompt}"),
        ];
        let (safe_argv, prompt_hash) = safety_argv_receipt(&argv, prompt);
        assert_eq!(
            prompt_hash,
            blake3::hash(prompt.as_bytes()).to_hex().to_string()
        );
        let serialized = serde_json::to_string(&(safe_argv, prompt_hash))?;
        assert!(!serialized.contains(prompt));
        Ok(())
    }
}
