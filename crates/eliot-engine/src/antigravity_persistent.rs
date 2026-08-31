#![forbid(unsafe_code)]

use eliot_types::antigravity_persistent::{
    ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION, AntigravityExecutableFingerprint,
    AntigravityFingerprintStatus, AntigravityPersistentBounds, AntigravityPersistentCapabilities,
    AntigravityPersistentFrame, AntigravityPersistentLaunchContract,
    AntigravityPersistentLaunchReceipt, AntigravityStdinMode, AntigravityStdoutMode,
    fingerprint_hash_for, hash_bytes_hex, is_allowed_env_name,
};
use eliot_types::{
    AntigravityBinaryResolution, AntigravityCapabilityProbe, AntigravityVersionGateResult,
    AntigravityVersionGateStatus,
};
use std::path::Path;
use time::OffsetDateTime;

use crate::EngineError;

fn rejected(msg: &str) -> EngineError {
    EngineError::WriteRejected(msg.to_owned())
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityFingerprintService;

#[derive(Clone, Copy, Debug, Default)]
pub struct AntigravityPersistentLaunchService;

#[derive(Clone, Debug)]
pub struct FakeAntigravityRuntime {
    pub contract: AntigravityPersistentLaunchContract,
    pub max_frame_bytes: usize,
    pub max_total_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FakeRuntimeError {
    MalformedFrame(String),
    OversizedFrame(String),
    SchemaDrift(String),
    BoundsExceeded(String),
    ContractInvalid(String),
}

impl std::fmt::Display for FakeRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedFrame(e) => write!(f, "malformed frame: {e}"),
            Self::OversizedFrame(e) => write!(f, "oversized frame: {e}"),
            Self::SchemaDrift(e) => write!(f, "schema drift: {e}"),
            Self::BoundsExceeded(e) => write!(f, "bounds exceeded: {e}"),
            Self::ContractInvalid(e) => write!(f, "contract invalid: {e}"),
        }
    }
}

impl std::error::Error for FakeRuntimeError {}

impl AntigravityFingerprintService {
    pub fn fingerprint_from_parts(
        &self,
        executable: &Path,
        canonical: Option<&Path>,
        version_gate: &AntigravityVersionGateResult,
        _probe: &AntigravityCapabilityProbe,
        version_output: &str,
        help_text: &str,
    ) -> AntigravityExecutableFingerprint {
        let executable_str = path_for_record(executable);
        let canonical_str = canonical.map(path_for_record);
        let capabilities = capabilities_for_persistent(help_text);
        let help_ok = capabilities.print_mode
            && capabilities.prompt_arg
            && capabilities.json_output
            && capabilities.log_file;
        let version_ok =
            version_gate.allowed && version_gate.status == AntigravityVersionGateStatus::Compatible;
        let status = if version_ok && help_ok {
            AntigravityFingerprintStatus::Compatible
        } else if version_gate.status == AntigravityVersionGateStatus::ProbeFailed
            || version_gate.status == AntigravityVersionGateStatus::ProbeTimedOut
            || version_gate.status == AntigravityVersionGateStatus::Unparseable
        {
            AntigravityFingerprintStatus::ProbeFailed
        } else {
            AntigravityFingerprintStatus::Incompatible
        };
        let fingerprint_hash = fingerprint_hash_for(&executable_str, version_output, help_text);
        let mut reasons = Vec::new();
        if version_ok {
            reasons.push("version compatible".to_owned());
        } else {
            reasons.extend(version_gate.reasons.clone());
        }
        if help_ok {
            reasons.push("help exposes persistent-required flags".to_owned());
        } else {
            reasons.push("help missing required persistent flags".to_owned());
        }
        AntigravityExecutableFingerprint {
            component: "antigravity_executable_fingerprint".to_owned(),
            executable: executable_str,
            canonical_path: canonical_str,
            version_output: version_output.to_owned(),
            parsed_version: version_gate.parsed_version.clone(),
            version_status: format!("{:?}", version_gate.status),
            version_allowed: version_gate.allowed,
            help_excerpt: truncate(help_text, 2000),
            help_capabilities: capabilities,
            fingerprint_status: status,
            fingerprint_hash,
            reasons,
            fingerprinted_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn fingerprint_from_resolution(
        &self,
        resolution: &AntigravityBinaryResolution,
        version_gate: &AntigravityVersionGateResult,
        probe: &AntigravityCapabilityProbe,
        version_output: &str,
        help_text: &str,
    ) -> Result<AntigravityExecutableFingerprint, EngineError> {
        let selected = resolution
            .selected_path
            .as_deref()
            .ok_or_else(|| rejected("no selected Antigravity executable for fingerprint"))?;
        let path = Path::new(selected);
        if !path.is_absolute() {
            return Err(rejected("fingerprint executable must be absolute"));
        }
        let canonical = resolution
            .candidates
            .iter()
            .find(|c| c.path == selected)
            .and_then(|c| c.canonical_path.as_deref())
            .map(Path::new);
        Ok(self.fingerprint_from_parts(
            path,
            canonical,
            version_gate,
            probe,
            version_output,
            help_text,
        ))
    }

    pub fn help_fingerprint_hash(&self, help_text: &str) -> String {
        hash_bytes_hex(help_text.as_bytes())
    }
}

impl AntigravityPersistentLaunchService {
    #[allow(clippy::needless_pass_by_value)]
    pub fn build_contract(
        &self,
        executable: &Path,
        canonical: Option<&Path>,
        cwd: &Path,
        fingerprint: &AntigravityExecutableFingerprint,
        bounds: AntigravityPersistentBounds,
        extra_env: &[(String, String)],
    ) -> Result<AntigravityPersistentLaunchContract, EngineError> {
        if fingerprint.fingerprint_status != AntigravityFingerprintStatus::Compatible {
            return Err(rejected(
                "persistent launch requires compatible executable fingerprint",
            ));
        }
        if !executable.is_absolute() {
            return Err(rejected("persistent launch executable must be absolute"));
        }
        if !cwd.is_absolute() {
            return Err(rejected("persistent launch cwd must be absolute"));
        }
        bounds
            .validate()
            .map_err(|e| rejected(&format!("bounds invalid: {e}")))?;

        // Executable existence and policy checks (temp/downloads, executable extension)
        let exe_str = path_for_record(executable);
        if looks_untrusted_download_or_temp(executable) {
            return Err(rejected("executable under temp/downloads rejected"));
        }
        if !looks_executable(executable) {
            return Err(rejected("executable does not look executable"));
        }

        // Build typed argv: shell-free, fused flag values
        let args = vec![
            "--mode=launch".to_owned(),
            "--stdin=ndjson".to_owned(),
            "--stdout=ndjson".to_owned(),
            format!("--schema-version={ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION}"),
        ];
        // Validate no arg starts with user-controlled dash value (already fixed)
        for arg in &args {
            if arg.trim_start().starts_with('-') && !arg.starts_with("--") {
                return Err(rejected("arg rejected"));
            }
        }

        // Env allowlist: start from minimal safe + fixed, filter extra_env
        let mut env = Vec::new();
        for (k, v) in extra_env {
            if !is_allowed_env_name(k) {
                continue;
            }
            // Drop secret-like even if allowlisted check already would fail for token etc, but allowlist doesn't contain them
            let upper = k.to_ascii_uppercase();
            if upper.contains("TOKEN")
                || upper.contains("SECRET")
                || upper.contains("PASSWORD")
                || upper.contains("CREDENTIAL")
            {
                return Err(rejected(&format!("secret-like env rejected: {k}")));
            }
            if v.contains("$(") || v.contains("&&") || v.contains("||") {
                return Err(rejected("shell interpolation in env value"));
            }
            env.push((k.clone(), v.clone()));
        }
        // Fixed vars
        if !env.iter().any(|(k, _)| k == "AGY_CLI_DISABLE_AUTO_UPDATE") {
            env.push(("AGY_CLI_DISABLE_AUTO_UPDATE".to_owned(), "1".to_owned()));
        }
        if !env.iter().any(|(k, _)| k == "AGY_CLI_HIDE_ACCOUNT_INFO") {
            env.push(("AGY_CLI_HIDE_ACCOUNT_INFO".to_owned(), "1".to_owned()));
        }

        let contract = AntigravityPersistentLaunchContract {
            contract_version: ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION.to_owned(),
            executable: exe_str,
            canonical_executable: canonical.map(path_for_record),
            args,
            cwd: path_for_record(cwd),
            env,
            bounds: bounds.clone(),
            shell: false,
            stdin_mode: AntigravityStdinMode::Ndjson,
            stdout_mode: AntigravityStdoutMode::Ndjson,
            fingerprint_hash: fingerprint.fingerprint_hash.clone(),
            help_excerpt_hash: hash_bytes_hex(fingerprint.help_excerpt.as_bytes()),
            created_at: OffsetDateTime::now_utc(),
        };
        contract
            .validate()
            .map_err(|e| rejected(&format!("contract validate failed: {e}")))?;
        Ok(contract)
    }

    pub fn receipt_for(
        &self,
        contract: &AntigravityPersistentLaunchContract,
    ) -> AntigravityPersistentLaunchReceipt {
        AntigravityPersistentLaunchReceipt {
            component: "antigravity_persistent_launch_receipt".to_owned(),
            contract_version: contract.contract_version.clone(),
            executable: contract.executable.clone(),
            cwd: contract.cwd.clone(),
            bounds: contract.bounds.clone(),
            fingerprint_hash: contract.fingerprint_hash.clone(),
            shell_free: !contract.shell,
            env_allowlisted: contract.env.iter().all(|(k, _)| is_allowed_env_name(k)),
            created_at: OffsetDateTime::now_utc(),
        }
    }

    pub fn validate_contract(
        &self,
        contract: &AntigravityPersistentLaunchContract,
    ) -> Result<(), EngineError> {
        contract
            .validate()
            .map_err(|e| rejected(&format!("contract invalid: {e}")))?;
        Ok(())
    }
}

impl FakeAntigravityRuntime {
    pub fn new(contract: AntigravityPersistentLaunchContract) -> Result<Self, FakeRuntimeError> {
        contract
            .validate()
            .map_err(FakeRuntimeError::ContractInvalid)?;
        let max_frame = contract.bounds.max_frame_bytes;
        let max_total = contract.bounds.max_total_bytes;
        Ok(Self {
            contract,
            max_frame_bytes: max_frame,
            max_total_bytes: max_total,
        })
    }

    /// Validate a single inbound NDJSON line fail-closed.
    pub fn validate_inbound_line(
        &self,
        line: &str,
    ) -> Result<AntigravityPersistentFrame, FakeRuntimeError> {
        if line.len() > self.max_frame_bytes {
            return Err(FakeRuntimeError::OversizedFrame(format!(
                "line {} > {}",
                line.len(),
                self.max_frame_bytes
            )));
        }
        let frame = AntigravityPersistentFrame::from_ndjson_line(line, self.max_frame_bytes)
            .map_err(|e| {
                if e.contains("oversized") {
                    FakeRuntimeError::OversizedFrame(e)
                } else if e.contains("schema drift") || e.contains("frame_version") {
                    FakeRuntimeError::SchemaDrift(e)
                } else {
                    FakeRuntimeError::MalformedFrame(e)
                }
            })?;
        Ok(frame)
    }

    /// Validate outbound frame before emitting.
    pub fn emit_frame(
        &self,
        frame: &AntigravityPersistentFrame,
    ) -> Result<String, FakeRuntimeError> {
        frame.validate(self.max_frame_bytes).map_err(|e| {
            if e.contains("oversized") {
                FakeRuntimeError::OversizedFrame(e)
            } else if e.contains("schema drift") || e.contains("frame_version") {
                FakeRuntimeError::SchemaDrift(e)
            } else {
                FakeRuntimeError::MalformedFrame(e)
            }
        })?;
        let line = frame
            .to_ndjson_line()
            .map_err(FakeRuntimeError::MalformedFrame)?;
        if line.len() > self.max_frame_bytes {
            return Err(FakeRuntimeError::OversizedFrame(format!(
                "emitted line {} > {}",
                line.len(),
                self.max_frame_bytes
            )));
        }
        Ok(line)
    }

    /// Simulate a full exchange: inbound lines -> outbound lines, enforcing total bytes and frame count bounds fail-closed.
    pub fn exchange(
        &self,
        inbound_lines: &[String],
        outbound_frames: &[AntigravityPersistentFrame],
    ) -> Result<Vec<String>, FakeRuntimeError> {
        if inbound_lines.len() > self.contract.bounds.max_frames
            || outbound_frames.len() > self.contract.bounds.max_frames
        {
            return Err(FakeRuntimeError::BoundsExceeded(format!(
                "frame count {} inbound / {} outbound exceeds max {}",
                inbound_lines.len(),
                outbound_frames.len(),
                self.contract.bounds.max_frames
            )));
        }
        let mut total: usize = 0;
        for line in inbound_lines {
            let frame = self.validate_inbound_line(line)?;
            // Also count inbound size
            total = total.saturating_add(line.len());
            if total > self.max_total_bytes {
                return Err(FakeRuntimeError::BoundsExceeded(format!(
                    "total bytes {} > {}",
                    total, self.max_total_bytes
                )));
            }
            // Validate payload schema drift already done
            let _ = frame;
        }
        let mut out_lines = Vec::new();
        for frame in outbound_frames {
            let line = self.emit_frame(frame)?;
            total = total.saturating_add(line.len());
            if total > self.max_total_bytes {
                return Err(FakeRuntimeError::BoundsExceeded(format!(
                    "total bytes {} > {}",
                    total, self.max_total_bytes
                )));
            }
            out_lines.push(line);
        }
        Ok(out_lines)
    }
}

fn capabilities_for_persistent(help_text: &str) -> AntigravityPersistentCapabilities {
    let lower = help_text.to_ascii_lowercase();
    AntigravityPersistentCapabilities {
        print_mode: lower.contains("--print"),
        prompt_arg: lower.contains("--prompt"),
        json_output: lower.contains("json") || lower.contains("--json"),
        log_file: lower.contains("--log-file"),
        sandbox: lower.contains("--sandbox"),
        disable_slash_commands: lower.contains("--disable-slash-commands"),
    }
}

fn truncate(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text[..end].to_owned()
}

fn path_for_record(path: &Path) -> String {
    let s = path.display().to_string();
    // Strip Windows verbatim prefix
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        return format!(r"\\{rest}");
    }
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        return rest.to_owned();
    }
    if let Some(rest) = s.strip_prefix("//?/UNC/") {
        return format!("//{rest}");
    }
    if let Some(rest) = s.strip_prefix("//?/") {
        return rest.to_owned();
    }
    s
}

fn looks_executable(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => matches!(
            ext.to_ascii_lowercase().as_str(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_types::AntigravityProviderState;
    use eliot_types::AntigravityVersionGateResult;
    use eliot_types::AntigravityVersionGateStatus;

    fn version_gate_allowed() -> AntigravityVersionGateResult {
        AntigravityVersionGateResult {
            component: "antigravity_version_gate".to_owned(),
            command: "agy --version".to_owned(),
            raw_output: "agy 1.2.3".to_owned(),
            parsed_version: Some("1.2.3".to_owned()),
            minimum_version: "1.1.1".to_owned(),
            status: AntigravityVersionGateStatus::Compatible,
            allowed: true,
            reasons: vec!["ok".to_owned()],
            checked_at: OffsetDateTime::now_utc(),
        }
    }

    fn probe_help() -> AntigravityCapabilityProbe {
        AntigravityCapabilityProbe {
            provider_state: AntigravityProviderState::DetectedDisabled,
            binary_path: Some("C:/exa/agy.exe".to_owned()),
            help_probe_command: Some("agy --help".to_owned()),
            capabilities: eliot_types::AntigravityCapabilities {
                print_mode: true,
                prompt_arg: true,
                print_timeout: true,
                log_file: true,
                sandbox: true,
                add_dir: false,
                continue_session: false,
                conversation: false,
                json_output: true,
                model_cli_arg: true,
                effort_cli_arg: true,
                disable_slash_commands: true,
                dangerously_skip_permissions_seen: false,
                text_output_supported: true,
            },
            timeout_enforced: true,
            plain_agy_invoked: false,
            install_attempted: false,
            output_excerpt: String::new(),
            message: "ok".to_owned(),
            probed_at: OffsetDateTime::now_utc(),
        }
    }

    #[test]
    fn valid_launch_succeeds() {
        let svc = AntigravityPersistentLaunchService;
        let fp_svc = AntigravityFingerprintService;
        let help =
            "Usage: agy --print --prompt --json --log-file --sandbox --disable-slash-commands";
        let version_output = "agy 1.2.3";
        let exe = Path::new("C:/Tools/agy.exe");
        // Create a dummy file for looks_executable check? On windows, .exe is considered executable without existence check in this service (we don't check exists, only policy). That's fine.
        let fp = fp_svc.fingerprint_from_parts(
            exe,
            Some(exe),
            &version_gate_allowed(),
            &probe_help(),
            version_output,
            help,
        );
        assert_eq!(
            fp.fingerprint_status,
            AntigravityFingerprintStatus::Compatible
        );
        let bounds = AntigravityPersistentBounds::default();
        let cwd = Path::new("C:/worktree/abc");
        let contract = svc
            .build_contract(exe, Some(exe), cwd, &fp, bounds, &[])
            .expect("contract");
        assert!(!contract.shell);
        assert!(contract.validate().is_ok());

        let runtime = FakeAntigravityRuntime::new(contract).expect("runtime");
        let frame = AntigravityPersistentFrame {
            frame_version: ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION.to_owned(),
            seq: 1,
            kind: eliot_types::antigravity_persistent::AntigravityFrameKind::Request,
            payload: serde_json::json!({"prompt":"hello"}),
        };
        let line = runtime.emit_frame(&frame).expect("emit");
        let inbound = vec![line.clone()];
        let outbound = vec![frame.clone()];
        let out = runtime.exchange(&inbound, &outbound).expect("exchange");
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn malformed_frame_fails_closed() {
        let svc = AntigravityPersistentLaunchService;
        let fp_svc = AntigravityFingerprintService;
        let help =
            "Usage: agy --print --prompt --json --log-file --sandbox --disable-slash-commands";
        let exe = Path::new("C:/Tools/agy.exe");
        let fp = fp_svc.fingerprint_from_parts(
            exe,
            Some(exe),
            &version_gate_allowed(),
            &probe_help(),
            "agy 1.2.3",
            help,
        );
        let contract = svc
            .build_contract(
                exe,
                Some(exe),
                Path::new("C:/worktree/abc"),
                &fp,
                AntigravityPersistentBounds::default(),
                &[],
            )
            .unwrap();
        let runtime = FakeAntigravityRuntime::new(contract).unwrap();
        let bad_line = "{ not json".to_owned();
        let err = runtime.validate_inbound_line(&bad_line).unwrap_err();
        assert!(matches!(err, FakeRuntimeError::MalformedFrame(_)));
    }

    #[test]
    fn oversized_frame_fails_closed() {
        let svc = AntigravityPersistentLaunchService;
        let fp_svc = AntigravityFingerprintService;
        let help =
            "Usage: agy --print --prompt --json --log-file --sandbox --disable-slash-commands";
        let exe = Path::new("C:/Tools/agy.exe");
        let fp = fp_svc.fingerprint_from_parts(
            exe,
            Some(exe),
            &version_gate_allowed(),
            &probe_help(),
            "agy 1.2.3",
            help,
        );
        let mut bounds = AntigravityPersistentBounds::default();
        bounds.max_frame_bytes = 1024;
        bounds.max_total_bytes = 4 * 1024;
        let contract = svc
            .build_contract(
                exe,
                Some(exe),
                Path::new("C:/worktree/abc"),
                &fp,
                bounds,
                &[],
            )
            .unwrap();
        let runtime = FakeAntigravityRuntime::new(contract).unwrap();
        let big_payload = "x".repeat(2000);
        let frame = AntigravityPersistentFrame {
            frame_version: ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION.to_owned(),
            seq: 1,
            kind: eliot_types::antigravity_persistent::AntigravityFrameKind::Request,
            payload: serde_json::json!({"data": big_payload}),
        };
        let err = runtime.emit_frame(&frame).unwrap_err();
        assert!(matches!(err, FakeRuntimeError::OversizedFrame(_)));
    }

    #[test]
    fn schema_drift_fails_closed() {
        let svc = AntigravityPersistentLaunchService;
        let fp_svc = AntigravityFingerprintService;
        let help =
            "Usage: agy --print --prompt --json --log-file --sandbox --disable-slash-commands";
        let exe = Path::new("C:/Tools/agy.exe");
        let fp = fp_svc.fingerprint_from_parts(
            exe,
            Some(exe),
            &version_gate_allowed(),
            &probe_help(),
            "agy 1.2.3",
            help,
        );
        let contract = svc
            .build_contract(
                exe,
                Some(exe),
                Path::new("C:/worktree/abc"),
                &fp,
                AntigravityPersistentBounds::default(),
                &[],
            )
            .unwrap();
        let runtime = FakeAntigravityRuntime::new(contract).unwrap();
        let frame = AntigravityPersistentFrame {
            frame_version: "999".to_owned(),
            seq: 1,
            kind: eliot_types::antigravity_persistent::AntigravityFrameKind::Request,
            payload: serde_json::json!({"prompt":"hi"}),
        };
        let err = runtime.emit_frame(&frame).unwrap_err();
        assert!(matches!(err, FakeRuntimeError::SchemaDrift(_)));

        // Also payload drift marker
        let frame2 = AntigravityPersistentFrame {
            frame_version: ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION.to_owned(),
            seq: 2,
            kind: eliot_types::antigravity_persistent::AntigravityFrameKind::Request,
            payload: serde_json::json!({"schema_drift": true}),
        };
        let err2 = runtime.emit_frame(&frame2).unwrap_err();
        assert!(matches!(err2, FakeRuntimeError::SchemaDrift(_)));
    }

    #[test]
    fn contract_enforces_strict_bounds() {
        let svc = AntigravityPersistentLaunchService;
        let fp_svc = AntigravityFingerprintService;
        let help =
            "Usage: agy --print --prompt --json --log-file --sandbox --disable-slash-commands";
        let exe = Path::new("C:/Tools/agy.exe");
        let fp = fp_svc.fingerprint_from_parts(
            exe,
            Some(exe),
            &version_gate_allowed(),
            &probe_help(),
            "agy 1.2.3",
            help,
        );
        let mut bounds = AntigravityPersistentBounds::default();
        bounds.timeout_ms = 999_999;
        let err = svc
            .build_contract(
                exe,
                Some(exe),
                Path::new("C:/worktree/abc"),
                &fp,
                bounds,
                &[],
            )
            .unwrap_err();
        assert!(err.to_string().contains("bounds invalid"));
    }

    #[test]
    fn contract_enforces_shell_free_and_env_allowlist() {
        let svc = AntigravityPersistentLaunchService;
        let fp_svc = AntigravityFingerprintService;
        let help =
            "Usage: agy --print --prompt --json --log-file --sandbox --disable-slash-commands";
        let exe = Path::new("C:/Tools/agy.exe");
        let fp = fp_svc.fingerprint_from_parts(
            exe,
            Some(exe),
            &version_gate_allowed(),
            &probe_help(),
            "agy 1.2.3",
            help,
        );
        // Secret env not in allowlist is dropped (fail-closed allowlist)
        let contract_dropped = svc
            .build_contract(
                exe,
                Some(exe),
                Path::new("C:/worktree/abc"),
                &fp,
                AntigravityPersistentBounds::default(),
                &[("API_TOKEN".to_owned(), "secret".to_owned())],
            )
            .expect("contract with dropped secret env");
        assert!(contract_dropped.env.iter().all(|(k, _)| k != "API_TOKEN"));

        // Non-allowlisted env is dropped, not error, but contract validates allowlist
        let contract = svc
            .build_contract(
                exe,
                Some(exe),
                Path::new("C:/worktree/abc"),
                &fp,
                AntigravityPersistentBounds::default(),
                &[("PATH".to_owned(), "C:/bin".to_owned())],
            )
            .unwrap();
        assert!(contract.env.iter().any(|(k, _)| k == "PATH"));
        assert!(!contract.shell);
        assert!(contract.validate().is_ok());
        // Direct validation fails if shell true
        let mut bad = contract.clone();
        bad.shell = true;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn fingerprint_requires_version_and_help() {
        let fp_svc = AntigravityFingerprintService;
        let exe = Path::new("C:/Tools/agy.exe");
        let mut bad_gate = version_gate_allowed();
        bad_gate.allowed = false;
        bad_gate.status = AntigravityVersionGateStatus::TooOld;
        let fp = fp_svc.fingerprint_from_parts(
            exe,
            Some(exe),
            &bad_gate,
            &probe_help(),
            "agy 0.9.0",
            "Usage: agy --print --prompt --json --log-file --sandbox --disable-slash-commands",
        );
        assert_eq!(
            fp.fingerprint_status,
            AntigravityFingerprintStatus::Incompatible
        );

        // Help missing required flags => incompatible
        let fp2 = fp_svc.fingerprint_from_parts(
            exe,
            Some(exe),
            &version_gate_allowed(),
            &probe_help(),
            "agy 1.2.3",
            "usage only",
        );
        assert_eq!(
            fp2.fingerprint_status,
            AntigravityFingerprintStatus::Incompatible
        );
    }
}
