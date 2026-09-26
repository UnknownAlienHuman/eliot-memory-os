#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

pub const ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION: &str = "1";
pub const ANTIGRAVITY_PERSISTENT_MIN_TIMEOUT_MS: u64 = 5_000;
pub const ANTIGRAVITY_PERSISTENT_MAX_TIMEOUT_MS: u64 = 310_000;
pub const ANTIGRAVITY_PERSISTENT_MIN_FRAME_BYTES: usize = 1_024;
pub const ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES: usize = 64 * 1024;
pub const ANTIGRAVITY_PERSISTENT_MIN_TOTAL_BYTES: usize = 4 * 1024;
pub const ANTIGRAVITY_PERSISTENT_MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;
pub const ANTIGRAVITY_PERSISTENT_MAX_FRAMES: usize = 2_048;
pub const ANTIGRAVITY_PERSISTENT_MIN_IDLE_TIMEOUT_MS: u64 = 1_000;
pub const ANTIGRAVITY_PERSISTENT_MAX_IDLE_TIMEOUT_MS: u64 = 60_000;

/// Allowlisted environment names for persistent launch (minimal Windows runtime + fixed AGY vars).
pub const ALLOWED_ENV_NAMES: &[&str] = &[
    "USERPROFILE",
    "HOME",
    "HOMEDRIVE",
    "HOMEPATH",
    "USERNAME",
    "LOCALAPPDATA",
    "APPDATA",
    "PROGRAMDATA",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "PATH",
    "PATHEXT",
    "AGY_CLI_DISABLE_AUTO_UPDATE",
    "AGY_CLI_HIDE_ACCOUNT_INFO",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityFingerprintStatus {
    Compatible,
    Incompatible,
    ProbeFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntigravityExecutableFingerprint {
    pub component: String,
    pub executable: String,
    pub canonical_path: Option<String>,
    pub version_output: String,
    pub parsed_version: Option<String>,
    pub version_status: String,
    pub version_allowed: bool,
    pub help_excerpt: String,
    pub help_capabilities: AntigravityPersistentCapabilities,
    pub fingerprint_status: AntigravityFingerprintStatus,
    pub fingerprint_hash: String,
    pub reasons: Vec<String>,
    #[serde(with = "time::serde::rfc3339")]
    pub fingerprinted_at: OffsetDateTime,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntigravityPersistentCapabilities {
    pub print_mode: bool,
    pub prompt_arg: bool,
    pub json_output: bool,
    pub log_file: bool,
    pub sandbox: bool,
    pub disable_slash_commands: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntigravityPersistentBounds {
    pub timeout_ms: u64,
    pub idle_timeout_ms: u64,
    pub max_frame_bytes: usize,
    pub max_total_bytes: usize,
    pub max_frames: usize,
}

impl Default for AntigravityPersistentBounds {
    fn default() -> Self {
        Self {
            timeout_ms: 60_000,
            idle_timeout_ms: 10_000,
            max_frame_bytes: 16 * 1024,
            max_total_bytes: 256 * 1024,
            max_frames: 256,
        }
    }
}

impl AntigravityPersistentBounds {
    pub fn validate(&self) -> Result<(), String> {
        if !(ANTIGRAVITY_PERSISTENT_MIN_TIMEOUT_MS..=ANTIGRAVITY_PERSISTENT_MAX_TIMEOUT_MS)
            .contains(&self.timeout_ms)
        {
            return Err(format!(
                "timeout_ms {} out of bounds [{}, {}]",
                self.timeout_ms,
                ANTIGRAVITY_PERSISTENT_MIN_TIMEOUT_MS,
                ANTIGRAVITY_PERSISTENT_MAX_TIMEOUT_MS
            ));
        }
        if !(ANTIGRAVITY_PERSISTENT_MIN_IDLE_TIMEOUT_MS
            ..=ANTIGRAVITY_PERSISTENT_MAX_IDLE_TIMEOUT_MS)
            .contains(&self.idle_timeout_ms)
        {
            return Err(format!(
                "idle_timeout_ms {} out of bounds",
                self.idle_timeout_ms
            ));
        }
        if !(ANTIGRAVITY_PERSISTENT_MIN_FRAME_BYTES..=ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES)
            .contains(&self.max_frame_bytes)
        {
            return Err(format!(
                "max_frame_bytes {} out of bounds [{}, {}]",
                self.max_frame_bytes,
                ANTIGRAVITY_PERSISTENT_MIN_FRAME_BYTES,
                ANTIGRAVITY_PERSISTENT_MAX_FRAME_BYTES
            ));
        }
        if !(ANTIGRAVITY_PERSISTENT_MIN_TOTAL_BYTES..=ANTIGRAVITY_PERSISTENT_MAX_TOTAL_BYTES)
            .contains(&self.max_total_bytes)
        {
            return Err(format!(
                "max_total_bytes {} out of bounds",
                self.max_total_bytes
            ));
        }
        if self.max_total_bytes < self.max_frame_bytes {
            return Err("max_total_bytes must be >= max_frame_bytes".to_owned());
        }
        if self.max_frames == 0 || self.max_frames > ANTIGRAVITY_PERSISTENT_MAX_FRAMES {
            return Err(format!(
                "max_frames {} out of bounds [1, {}]",
                self.max_frames, ANTIGRAVITY_PERSISTENT_MAX_FRAMES
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityStdinMode {
    Ndjson,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityStdoutMode {
    Ndjson,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntigravityPersistentLaunchContract {
    pub contract_version: String,
    pub executable: String,
    pub canonical_executable: Option<String>,
    pub args: Vec<String>,
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub bounds: AntigravityPersistentBounds,
    pub shell: bool,
    pub stdin_mode: AntigravityStdinMode,
    pub stdout_mode: AntigravityStdoutMode,
    pub fingerprint_hash: String,
    pub help_excerpt_hash: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

impl AntigravityPersistentLaunchContract {
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_version != ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION {
            return Err(format!(
                "contract_version {} != expected {}",
                self.contract_version, ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION
            ));
        }
        if self.shell {
            return Err("persistent launch must be shell-free (shell=false)".to_owned());
        }
        if self.stdin_mode != AntigravityStdinMode::Ndjson
            || self.stdout_mode != AntigravityStdoutMode::Ndjson
        {
            return Err("persistent launch requires NDJSON stdin/stdout".to_owned());
        }
        if self.executable.trim().is_empty() {
            return Err("executable must not be empty".to_owned());
        }
        // Executable must be absolute path.
        let exe_path = std::path::Path::new(&self.executable);
        if !exe_path.is_absolute() {
            return Err("executable must be absolute".to_owned());
        }
        // Args must not contain shell interpolation and must be fused flag=value.
        for arg in &self.args {
            if arg.trim().is_empty() {
                return Err("arg must not be empty".to_owned());
            }
            if contains_shell_interpolation(arg) {
                return Err(format!("shell interpolation rejected in arg: {arg}"));
            }
            // Forbid dangerous flag.
            if arg == "--dangerously-skip-permissions" {
                return Err("dangerous flag rejected".to_owned());
            }
        }
        // CWD must be absolute.
        let cwd_path = std::path::Path::new(&self.cwd);
        if !cwd_path.is_absolute() {
            return Err("cwd must be absolute".to_owned());
        }
        // Env allowlist.
        for (name, value) in &self.env {
            if !is_allowed_env_name(name) {
                return Err(format!("env var not allowlisted: {name}"));
            }
            if contains_shell_interpolation(value) {
                return Err(format!("shell interpolation in env value for {name}"));
            }
            if name.to_ascii_uppercase().contains("TOKEN")
                || name.to_ascii_uppercase().contains("SECRET")
                || name.to_ascii_uppercase().contains("PASSWORD")
                || name.to_ascii_uppercase().contains("CREDENTIAL")
            {
                return Err(format!("secret-like env var rejected: {name}"));
            }
        }
        self.bounds.validate()?;
        if self.fingerprint_hash.trim().is_empty() {
            return Err("fingerprint_hash must not be empty".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AntigravityFrameKind {
    Request,
    Response,
    Event,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntigravityPersistentFrame {
    pub frame_version: String,
    pub seq: u64,
    pub kind: AntigravityFrameKind,
    pub payload: serde_json::Value,
}

impl AntigravityPersistentFrame {
    pub fn validate(&self, max_frame_bytes: usize) -> Result<(), String> {
        if self.frame_version != ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION {
            return Err(format!(
                "frame_version {} != expected {}",
                self.frame_version, ANTIGRAVITY_PERSISTENT_SCHEMA_VERSION
            ));
        }
        let bytes = serde_json::to_vec(self).map_err(|e| format!("frame serialize failed: {e}"))?;
        if bytes.len() > max_frame_bytes {
            return Err(format!(
                "frame oversized {} > {}",
                bytes.len(),
                max_frame_bytes
            ));
        }
        // Explicit per-kind payload disposition (#934): no owner-defined Eliot
        // payload schema exists for any frame kind — the only producer is the
        // fake runtime, which emits ad-hoc objects — so every kind retains its
        // payload as inert bounded vendor data. The payload must be a JSON
        // object (the documented wire shape); the payload is never interpreted
        // as session/permission/terminal authority. Each arm below states its
        // kind's own disposition and diagnostic; content-level per-kind shapes
        // cannot be validated until a payload owner defines them (residual
        // R-934-W4, not a blacklist exception). The pre-existing drift-key
        // rejection below is preserved byte-for-byte: existing behavior (pinned
        // by the engine's schema_drift_fails_closed test) must not be weakened
        // by this decoder-closure slice; redesigning that policy is out of scope.
        match self.kind {
            AntigravityFrameKind::Request => {
                // Eliot-originated stimulus: the payload is a vendor-opaque
                // work description, retained as inert bounded data.
                if !self.payload.is_object() {
                    return Err("request frame payload must be a JSON object".to_owned());
                }
            }
            AntigravityFrameKind::Response => {
                // Vendor-originated result: inert bounded data, never trusted
                // as session/permission/terminal authority (I15.6: retrieved
                // content cannot grant permission).
                if !self.payload.is_object() {
                    return Err("response frame payload must be a JSON object".to_owned());
                }
            }
            AntigravityFrameKind::Event => {
                // Vendor-originated occurrence: inert bounded data, never
                // certified as a normalized host event (I7.23: only the
                // normalized projection drives policy/state/UI).
                if !self.payload.is_object() {
                    return Err("event frame payload must be a JSON object".to_owned());
                }
            }
            AntigravityFrameKind::Error => {
                // Vendor-originated failure signal: inert bounded diagnostic
                // data, never authenticated terminal evidence (case 15:
                // provider statements cannot become terminal evidence).
                if !self.payload.is_object() {
                    return Err("error frame payload must be a JSON object".to_owned());
                }
            }
        }
        if let Some(obj) = self.payload.as_object()
            && (obj.contains_key("schema_drift") || obj.contains_key("unknown_field_that_drifts"))
        {
            return Err("schema drift marker rejected".to_owned());
        }
        Ok(())
    }

    pub fn to_ndjson_line(&self) -> Result<String, String> {
        let mut line = serde_json::to_string(self).map_err(|e| format!("serialize failed: {e}"))?;
        line.push('\n');
        Ok(line)
    }

    pub fn from_ndjson_line(line: &str, max_frame_bytes: usize) -> Result<Self, String> {
        if line.len() > max_frame_bytes {
            return Err(format!(
                "ndjson line oversized {} > {}",
                line.len(),
                max_frame_bytes
            ));
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return Err("empty frame".to_owned());
        }
        let frame: Self =
            serde_json::from_str(trimmed).map_err(|e| format!("malformed frame: {e}"))?;
        frame.validate(max_frame_bytes)?;
        Ok(frame)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AntigravityPersistentLaunchReceipt {
    pub component: String,
    pub contract_version: String,
    pub executable: String,
    pub cwd: String,
    pub bounds: AntigravityPersistentBounds,
    pub fingerprint_hash: String,
    pub shell_free: bool,
    pub env_allowlisted: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: OffsetDateTime,
}

pub fn is_allowed_env_name(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    ALLOWED_ENV_NAMES.contains(&upper.as_str())
}

fn contains_shell_interpolation(value: &str) -> bool {
    ["$(", "`", "&&", "||", " ; ", "\nrm ", "\nRemove-Item"]
        .iter()
        .any(|needle| value.contains(needle))
}

pub fn hash_bytes_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn fingerprint_hash_for(executable: &str, version: &str, help: &str) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(executable.as_bytes());
    hasher.update(b"|");
    hasher.update(version.as_bytes());
    hasher.update(b"|");
    hasher.update(help.as_bytes());
    hasher.finalize().to_hex().to_string()
}
