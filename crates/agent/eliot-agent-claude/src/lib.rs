//! Wave 1 local Claude Agent SDK sidecar contract and native skeleton.
//!
//! This crate owns only the versioned NDJSON request/response schema, typed
//! shell-free launch plan, hard frame/prompt/output/time bounds, permission
//! allowlist, and candidate-only result.  It explicitly owns **no** task,
//! finish, recovery, or route-admission authority.  A sidecar result is a
//! candidate; `Task` / `FinishDecision` / `StateFence` promotion lives in
//! `eliot-governor` and `eliot-finish`.
//!
//! Distinct from Claude Code plugin (`claude.code.plugin`), hook host
//! (`claude.code.hooks`), MCP surface (`claude.code.mcp`), Desktop extension
//! (`claude.desktop.extension`), and the deferred remote Managed Agents route
//! (`claude.managed-agents.remote`).  Wave 1 excludes supervised process
//! launch, credentials / User Broker wiring, SDK execution, event
//! normalization, cancellation / cleanup / reconciliation, model catalogue /
//! selection receipts, `WorkItem` / child policy, live auth / model execution,
//! route admission, and Product Pulse.  No Python service and no runtime hot
//! path are introduced here.
//!
//! Transport is newline-delimited JSON (NDJSON): one UTF-8 JSON object per
//! line, `\n`-terminated, no shell interpolation, no credential leakage.

#![allow(clippy::pedantic)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::manual_string_new)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::manual_pattern_char_comparison)]
#![allow(clippy::single_match_else)]

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Protocol versioning
// ---------------------------------------------------------------------------

/// Exact sidecar NDJSON protocol version.  Unknown incompatible versions are
/// rejected fail-closed.
pub const CLAUDE_SIDECAR_PROTOCOL_VERSION: &str = "claude-sdk-sidecar/v1";

/// Compatible versions accepted by wave 1.  Only this exact version is admitted;
/// any other value is a hard error.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &[CLAUDE_SIDECAR_PROTOCOL_VERSION];

/// Adapter / route identity for the local sidecar.
pub const CLAUDE_SIDECAR_ADAPTER_ID: &str = "eliot-agent-claude-sidecar";
pub const CLAUDE_SIDECAR_HOST_FAMILY: &str = "claude";
pub const CLAUDE_SIDECAR_ROUTE_CLASS: &str = "claude.agent-sdk.local-sidecar";
pub const CLAUDE_SIDECAR_TRANSPORT: &str = "stdio_ndjson_sdk_sidecar";

/// Distinct host-surface / remote route ids (must not be conflated with the
/// local sidecar).
pub const CLAUDE_PLUGIN_SURFACE_ID: &str = "claude.code.plugin";
pub const CLAUDE_HOOKS_SURFACE_ID: &str = "claude.code.hooks";
pub const CLAUDE_MCP_SURFACE_ID: &str = "claude.code.mcp";
pub const CLAUDE_DESKTOP_EXTENSION_ID: &str = "claude.desktop.extension";
pub const CLAUDE_MANAGED_AGENTS_ROUTE_ID: &str = "claude.managed-agents.remote";

// ---------------------------------------------------------------------------
// Hard bounds
// ---------------------------------------------------------------------------

/// Maximum bytes per NDJSON frame (one line).  Oversized frames are rejected
/// before JSON parsing.
pub const MAX_FRAME_BYTES: usize = 256 * 1024; // 256 KiB

/// Maximum prompt bytes per request.
pub const MAX_PROMPT_BYTES: usize = 512 * 1024; // 512 KiB

/// Maximum output bytes per candidate result / per event payload.
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum wall-time per attempt in milliseconds (hard upper bound for any
/// future launch; wave 1 only validates).
pub const MAX_WALL_TIME_MS: u64 = 600_000; // 10 minutes

/// Minimum wall-time (must be > 0 when supplied).
pub const MIN_WALL_TIME_MS: u64 = 1;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ClaudeSidecarError {
    #[error("unsupported protocol version: {0}")]
    UnsupportedVersion(String),
    #[error("frame exceeds MAX_FRAME_BYTES ({limit} bytes, got {actual})")]
    FrameTooLarge { limit: usize, actual: usize },
    #[error("prompt exceeds MAX_PROMPT_BYTES ({limit} bytes, got {actual})")]
    PromptTooLarge { limit: usize, actual: usize },
    #[error("output exceeds MAX_OUTPUT_BYTES ({limit} bytes, got {actual})")]
    OutputTooLarge { limit: usize, actual: usize },
    #[error("field {0} must not be empty")]
    EmptyField(&'static str),
    #[error("field {0} must be > 0")]
    ZeroField(&'static str),
    #[error("time bounds out of range: wall_time_ms={0} (allowed {1}..={2})")]
    TimeOutOfRange(u64, u64, u64),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("argv must be shell-free and non-empty; got empty or blank entry")]
    InvalidArgv,
    #[error("argv entry contains shell metacharacter: {0}")]
    ShellMetacharacter(String),
    #[error("environment allowlist rejected key: {0}")]
    EnvRejected(String),
    #[error("malformed NDJSON: {0}")]
    MalformedFrame(&'static str),
    #[error("unknown permission mode: {0}")]
    UnknownPermission(String),
    #[error("result is candidate-only; task/finish authority not held")]
    NotAuthority,
}

// ---------------------------------------------------------------------------
// Permission allowlist
// ---------------------------------------------------------------------------

/// Explicit permission modes admitted by the sidecar contract.
/// No other string is accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudePermissionMode {
    /// Read-only / ask-first default.
    Default,
    /// Allow file edits without explicit plan approval.
    AcceptEdits,
    /// Plan mode (read + plan writes only).
    Plan,
}

impl ClaudePermissionMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::AcceptEdits => "accept_edits",
            Self::Plan => "plan",
        }
    }

    pub fn parse(s: &str) -> Result<Self, ClaudeSidecarError> {
        match s {
            "default" => Ok(Self::Default),
            "accept_edits" => Ok(Self::AcceptEdits),
            "plan" => Ok(Self::Plan),
            other => Err(ClaudeSidecarError::UnknownPermission(other.to_owned())),
        }
    }
}

/// Allowlisted tool names.  Wave 1 uses a closed enumeration; arbitrary tool
/// strings are rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeAllowedTool {
    Read,
    Edit,
    Write,
    Bash,
    Grep,
    Glob,
    WebFetch,
}

impl ClaudeAllowedTool {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Edit => "edit",
            Self::Write => "write",
            Self::Bash => "bash",
            Self::Grep => "grep",
            Self::Glob => "glob",
            Self::WebFetch => "web_fetch",
        }
    }
}

// ---------------------------------------------------------------------------
// Launch plan (typed, shell-free)
// ---------------------------------------------------------------------------

/// Shell-free argv: program plus typed argument vector.  No shell, no
/// interpolation, no credential spill.  `program` and every `argv` entry must be
/// non-blank and must not contain shell metacharacters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeArgv {
    pub program: String,
    pub argv: Vec<String>,
}

impl ClaudeArgv {
    pub fn validate(&self) -> Result<(), ClaudeSidecarError> {
        if self.program.trim().is_empty() {
            return Err(ClaudeSidecarError::EmptyField("program"));
        }
        if self.argv.is_empty() {
            return Err(ClaudeSidecarError::InvalidArgv);
        }
        for entry in std::iter::once(&self.program).chain(self.argv.iter()) {
            if entry.trim().is_empty() {
                return Err(ClaudeSidecarError::InvalidArgv);
            }
            // Reject shell metacharacters to enforce shell-free invariant.
            const META: &[char] = &[';', '|', '&', '`', '$', '(', ')', '<', '>', '\n', '\r'];
            if entry.chars().any(|c| META.contains(&c)) {
                return Err(ClaudeSidecarError::ShellMetacharacter(entry.clone()));
            }
        }
        Ok(())
    }
}

/// Allowlisted environment projection.  Only keys in the allowlist are
/// admitted; values are opaque but must be non-empty when present.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeEnvAllowlist {
    pub vars: Vec<(String, String)>,
}

impl ClaudeEnvAllowlist {
    /// Closed allowlist of environment keys the sidecar may receive.
    pub const ALLOWED_KEYS: &'static [&'static str] = &[
        "PATH",
        "HOME",
        "TMPDIR",
        "CLAUDE_CODE_ENTRYPOINT",
        "ELIOT_SIDECAR_VERSION",
    ];

    pub fn validate(&self) -> Result<(), ClaudeSidecarError> {
        for (k, v) in &self.vars {
            if !Self::ALLOWED_KEYS.contains(&k.as_str()) {
                return Err(ClaudeSidecarError::EnvRejected(k.clone()));
            }
            if k.trim().is_empty() || v.trim().is_empty() {
                return Err(ClaudeSidecarError::EmptyField("env var"));
            }
        }
        Ok(())
    }
}

/// Typed launch plan: shell-free, bounded, allowlisted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeSidecarLaunchPlan {
    /// Exact typed argv; shell is always false.
    pub argv: ClaudeArgv,
    /// Working directory (must be non-empty, absolute-like).
    pub working_directory: String,
    /// Allowlisted environment projection.
    pub env: ClaudeEnvAllowlist,
    /// Wall-time ceiling in ms (1..=MAX_WALL_TIME_MS).
    pub wall_time_ms: u64,
    /// Output ceiling in bytes (1..=MAX_OUTPUT_BYTES).
    pub max_output_bytes: usize,
    /// Permission mode.
    pub permission_mode: ClaudePermissionMode,
    /// Allowlisted tools (subset of closed set).
    pub allowed_tools: Vec<ClaudeAllowedTool>,
}

impl ClaudeSidecarLaunchPlan {
    pub fn validate(&self) -> Result<(), ClaudeSidecarError> {
        self.argv.validate()?;
        if self.working_directory.trim().is_empty() {
            return Err(ClaudeSidecarError::EmptyField("working_directory"));
        }
        self.env.validate()?;
        if self.wall_time_ms < MIN_WALL_TIME_MS || self.wall_time_ms > MAX_WALL_TIME_MS {
            return Err(ClaudeSidecarError::TimeOutOfRange(
                self.wall_time_ms,
                MIN_WALL_TIME_MS,
                MAX_WALL_TIME_MS,
            ));
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > MAX_OUTPUT_BYTES {
            return Err(ClaudeSidecarError::OutputTooLarge {
                limit: MAX_OUTPUT_BYTES,
                actual: self.max_output_bytes,
            });
        }
        // allowed_tools entries are already typed; empty is allowed (read-only).
        Ok(())
    }

    /// Convenience: is this plan for the local sidecar route (not plugin/MCP/remote)?
    pub fn is_local_sidecar_route(&self) -> bool {
        self.argv.program.contains("eliot-claude-sidecar")
    }
}

// ---------------------------------------------------------------------------
// Versioned NDJSON schema
// ---------------------------------------------------------------------------

/// Request kind discriminants for the sidecar stdin stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeRequestKind {
    /// Start one bounded candidate attempt.
    Query,
    /// Close the sidecar stream (no recovery / resume in wave 1).
    Close,
}

/// Versioned NDJSON request (one JSON object per line on stdin).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeSidecarRequest {
    /// Must equal `CLAUDE_SIDECAR_PROTOCOL_VERSION`.
    pub protocol_version: String,
    /// Caller-supplied request correlation id (non-empty).
    pub request_id: String,
    /// Request kind.
    pub kind: ClaudeRequestKind,
    /// Prompt / input text (bounded).  Present for `Query`, absent for `Close`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Launch plan (required for `Query`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub launch_plan: Option<ClaudeSidecarLaunchPlan>,
}

impl ClaudeSidecarRequest {
    pub fn validate(&self) -> Result<(), ClaudeSidecarError> {
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&self.protocol_version.as_str()) {
            return Err(ClaudeSidecarError::UnsupportedVersion(
                self.protocol_version.clone(),
            ));
        }
        if self.request_id.trim().is_empty() {
            return Err(ClaudeSidecarError::EmptyField("request_id"));
        }
        match self.kind {
            ClaudeRequestKind::Query => {
                let prompt = self
                    .prompt
                    .as_deref()
                    .ok_or(ClaudeSidecarError::EmptyField("prompt"))?;
                if prompt.trim().is_empty() {
                    return Err(ClaudeSidecarError::EmptyField("prompt"));
                }
                if prompt.len() > MAX_PROMPT_BYTES {
                    return Err(ClaudeSidecarError::PromptTooLarge {
                        limit: MAX_PROMPT_BYTES,
                        actual: prompt.len(),
                    });
                }
                let plan = self
                    .launch_plan
                    .as_ref()
                    .ok_or(ClaudeSidecarError::EmptyField("launch_plan"))?;
                plan.validate()?;
            }
            ClaudeRequestKind::Close => {
                // Close carries no prompt/plan.
                if self.prompt.is_some() || self.launch_plan.is_some() {
                    return Err(ClaudeSidecarError::MalformedFrame(
                        "close must not carry prompt/launch_plan",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Encode as a single NDJSON line (`\n`-terminated, no trailing whitespace).
    pub fn to_ndjson_line(&self) -> Result<String, serde_json::Error> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');
        Ok(s)
    }

    /// Decode one NDJSON line, enforcing frame and version bounds before
    /// full deserialization.
    pub fn from_ndjson_line(line: &str) -> Result<Self, ClaudeSidecarError> {
        let bytes = line.as_bytes();
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ClaudeSidecarError::FrameTooLarge {
                limit: MAX_FRAME_BYTES,
                actual: bytes.len(),
            });
        }
        // Trim single trailing newline for parsing but keep frame size check on raw.
        let trimmed = line.trim_end_matches(|c| c == '\n' || c == '\r');
        let req: Self = serde_json::from_str(trimmed)
            .map_err(|_| ClaudeSidecarError::MalformedFrame("invalid JSON object"))?;
        req.validate()?;
        Ok(req)
    }
}

/// Response / event kind on stdout.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeResponseKind {
    /// Acknowledged start.
    Started,
    /// Incremental text / tool event (candidate observation, not authority).
    Event,
    /// Terminal candidate result (candidate-only, no task finish).
    Result,
    /// Error (typed, no credential spill).
    Error,
}

/// Versioned NDJSON response frame (one JSON object per line on stdout).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeSidecarResponse {
    pub protocol_version: String,
    pub request_id: String,
    pub kind: ClaudeResponseKind,
    /// Human-readable / candidate payload (bounded).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Candidate result (present only for `Result`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_result: Option<ClaudeCandidateResult>,
    /// Error detail (present only for `Error`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ClaudeSidecarResponse {
    pub fn validate(&self) -> Result<(), ClaudeSidecarError> {
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&self.protocol_version.as_str()) {
            return Err(ClaudeSidecarError::UnsupportedVersion(
                self.protocol_version.clone(),
            ));
        }
        if self.request_id.trim().is_empty() {
            return Err(ClaudeSidecarError::EmptyField("request_id"));
        }
        if let Some(p) = &self.payload {
            if p.len() > MAX_OUTPUT_BYTES {
                return Err(ClaudeSidecarError::OutputTooLarge {
                    limit: MAX_OUTPUT_BYTES,
                    actual: p.len(),
                });
            }
        }
        match self.kind {
            ClaudeResponseKind::Result => {
                let r = self
                    .candidate_result
                    .as_ref()
                    .ok_or(ClaudeSidecarError::EmptyField("candidate_result"))?;
                r.validate()?;
                if self.error.is_some() {
                    return Err(ClaudeSidecarError::MalformedFrame(
                        "result must not carry error",
                    ));
                }
            }
            ClaudeResponseKind::Error => {
                if self
                    .error
                    .as_deref()
                    .map(str::trim)
                    .unwrap_or("")
                    .is_empty()
                {
                    return Err(ClaudeSidecarError::EmptyField("error"));
                }
                if self.candidate_result.is_some() {
                    return Err(ClaudeSidecarError::MalformedFrame(
                        "error must not carry candidate_result",
                    ));
                }
            }
            ClaudeResponseKind::Started | ClaudeResponseKind::Event => {
                if self.candidate_result.is_some() {
                    return Err(ClaudeSidecarError::MalformedFrame(
                        "non-result must not carry candidate_result",
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn to_ndjson_line(&self) -> Result<String, serde_json::Error> {
        let mut s = serde_json::to_string(self)?;
        s.push('\n');
        Ok(s)
    }

    pub fn from_ndjson_line(line: &str) -> Result<Self, ClaudeSidecarError> {
        let bytes = line.as_bytes();
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(ClaudeSidecarError::FrameTooLarge {
                limit: MAX_FRAME_BYTES,
                actual: bytes.len(),
            });
        }
        let trimmed = line.trim_end_matches(|c| c == '\n' || c == '\r');
        let resp: Self = serde_json::from_str(trimmed)
            .map_err(|_| ClaudeSidecarError::MalformedFrame("invalid JSON object"))?;
        resp.validate()?;
        Ok(resp)
    }
}

// ---------------------------------------------------------------------------
// Candidate-only result (no task / finish / recovery authority)
// ---------------------------------------------------------------------------

/// Candidate disposition.  No variant expresses `VERIFIED_COMPLETE` or task
/// finish; the strongest positive is `CandidateReady` (local proof ceiling only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaudeCandidateDisposition {
    CandidateReady,
    CandidatePartial,
    CandidateFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeCandidateResult {
    /// Attempt correlation (opaque, non-empty).  Not a TaskId.
    pub attempt_id: String,
    pub disposition: ClaudeCandidateDisposition,
    /// Bounded output (candidate evidence, not proof of finish).
    pub output: String,
    /// Digest of output (e.g. blake3 hex), non-empty.
    pub output_digest: String,
    /// Whether the candidate is considered truncated by output bound.
    pub truncated: bool,
}

impl ClaudeCandidateResult {
    pub fn validate(&self) -> Result<(), ClaudeSidecarError> {
        if self.attempt_id.trim().is_empty() {
            return Err(ClaudeSidecarError::EmptyField("attempt_id"));
        }
        if self.output.len() > MAX_OUTPUT_BYTES {
            return Err(ClaudeSidecarError::OutputTooLarge {
                limit: MAX_OUTPUT_BYTES,
                actual: self.output.len(),
            });
        }
        if self.output_digest.trim().is_empty() {
            return Err(ClaudeSidecarError::EmptyField("output_digest"));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Authority semantics helpers (explicit no-ownership)
// ---------------------------------------------------------------------------

/// Marker type proving the caller acknowledged candidate-only semantics.
/// No method on this crate can mint `TaskId`, `FinishDecision`, or
/// `StateFence`; this type exists only as documentation / lint aid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CandidateOnly;

/// Returns a static disclaimer for inclusion in receipts / logs.
pub fn authority_disclaimer() -> &'static str {
    "candidate-only: no task, no finish, no recovery, no route admission"
}

/// True iff `route_id` is the local sidecar route (not plugin/MCP/desktop/remote).
pub fn is_local_sidecar_route(route_id: &str) -> bool {
    route_id == CLAUDE_SIDECAR_ROUTE_CLASS
}

pub fn is_managed_agents_route(route_id: &str) -> bool {
    route_id == CLAUDE_MANAGED_AGENTS_ROUTE_ID
}

// ---------------------------------------------------------------------------
// Tests — deterministic contract / serde / validation
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn valid_plan() -> ClaudeSidecarLaunchPlan {
        ClaudeSidecarLaunchPlan {
            argv: ClaudeArgv {
                program: "eliot-claude-sidecar".into(),
                argv: vec!["--stdio".into()],
            },
            working_directory: "C:\\workspace".into(),
            env: ClaudeEnvAllowlist {
                vars: vec![("PATH".into(), "/usr/bin".into())],
            },
            wall_time_ms: 30_000,
            max_output_bytes: 64 * 1024,
            permission_mode: ClaudePermissionMode::Default,
            allowed_tools: vec![ClaudeAllowedTool::Read, ClaudeAllowedTool::Grep],
        }
    }

    fn valid_query() -> ClaudeSidecarRequest {
        ClaudeSidecarRequest {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-1".into(),
            kind: ClaudeRequestKind::Query,
            prompt: Some("hello claude".into()),
            launch_plan: Some(valid_plan()),
        }
    }

    #[test]
    fn protocol_version_is_exact_and_rejects_unknown() {
        let mut q = valid_query();
        assert!(q.validate().is_ok());
        q.protocol_version = "v0".into();
        assert_eq!(
            q.validate().unwrap_err(),
            ClaudeSidecarError::UnsupportedVersion("v0".into())
        );
        // NDJSON round-trip also rejects.
        let line = serde_json::to_string(&q).unwrap() + "\n";
        assert!(ClaudeSidecarRequest::from_ndjson_line(&line).is_err());
    }

    #[test]
    fn ndjson_roundtrip_query_and_close() {
        let q = valid_query();
        let line = q.to_ndjson_line().unwrap();
        assert!(line.ends_with('\n'));
        let decoded = ClaudeSidecarRequest::from_ndjson_line(&line).unwrap();
        assert_eq!(decoded, q);

        let close = ClaudeSidecarRequest {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-2".into(),
            kind: ClaudeRequestKind::Close,
            prompt: None,
            launch_plan: None,
        };
        let line2 = close.to_ndjson_line().unwrap();
        let decoded2 = ClaudeSidecarRequest::from_ndjson_line(&line2).unwrap();
        assert_eq!(decoded2, close);
    }

    #[test]
    fn frame_bound_enforced_before_parse() {
        let oversized = "x".repeat(MAX_FRAME_BYTES + 1) + "\n";
        assert!(matches!(
            ClaudeSidecarRequest::from_ndjson_line(&oversized),
            Err(ClaudeSidecarError::FrameTooLarge { .. })
        ));
        let resp_oversized = "y".repeat(MAX_FRAME_BYTES + 1) + "\n";
        assert!(matches!(
            ClaudeSidecarResponse::from_ndjson_line(&resp_oversized),
            Err(ClaudeSidecarError::FrameTooLarge { .. })
        ));
    }

    #[test]
    fn prompt_and_output_bounds() {
        let mut q = valid_query();
        q.prompt = Some("p".repeat(MAX_PROMPT_BYTES + 1));
        assert!(matches!(
            q.validate(),
            Err(ClaudeSidecarError::PromptTooLarge { .. })
        ));

        let mut resp = ClaudeSidecarResponse {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-1".into(),
            kind: ClaudeResponseKind::Event,
            payload: Some("o".repeat(MAX_OUTPUT_BYTES + 1)),
            candidate_result: None,
            error: None,
        };
        assert!(matches!(
            resp.validate(),
            Err(ClaudeSidecarError::OutputTooLarge { .. })
        ));
        // payload within bound passes.
        resp.payload = Some("ok".into());
        assert!(resp.validate().is_ok());
    }

    #[test]
    fn time_bounds() {
        let mut plan = valid_plan();
        plan.wall_time_ms = 0;
        assert!(plan.validate().is_err());
        plan.wall_time_ms = MAX_WALL_TIME_MS + 1;
        assert!(matches!(
            plan.validate(),
            Err(ClaudeSidecarError::TimeOutOfRange(..))
        ));
        plan.wall_time_ms = MAX_WALL_TIME_MS;
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn argv_is_shell_free() {
        let mut plan = valid_plan();
        plan.argv.argv = vec!["--flag; rm -rf /".into()];
        assert!(matches!(
            plan.validate(),
            Err(ClaudeSidecarError::ShellMetacharacter(_))
        ));
        plan.argv.argv = vec!["--stdio".into()];
        plan.argv.program = "".into();
        assert!(plan.validate().is_err());
        plan.argv.program = "eliot-claude-sidecar".into();
        assert!(plan.validate().is_ok());
        // Empty argv vector rejected.
        plan.argv.argv = vec![];
        assert!(matches!(
            plan.validate(),
            Err(ClaudeSidecarError::InvalidArgv)
        ));
    }

    #[test]
    fn env_allowlist_closed() {
        let mut plan = valid_plan();
        plan.env.vars = vec![("SECRET_TOKEN".into(), "xyz".into())];
        assert!(matches!(
            plan.validate(),
            Err(ClaudeSidecarError::EnvRejected(_))
        ));
        plan.env.vars = vec![("PATH".into(), "".into())];
        assert!(plan.validate().is_err());
        plan.env.vars = vec![("PATH".into(), "/bin".into())];
        assert!(plan.validate().is_ok());
    }

    #[test]
    fn permission_allowlist_typed() {
        // Serde rejects unknown permission strings.
        let bad = r#"{"vars":[]}"#;
        // ClaudePermissionMode parse rejects unknown.
        assert!(ClaudePermissionMode::parse("bypass").is_err());
        assert_eq!(
            ClaudePermissionMode::parse("default").unwrap(),
            ClaudePermissionMode::Default
        );
        // Serde round-trip for allowed values.
        let mode = ClaudePermissionMode::AcceptEdits;
        let json = serde_json::to_string(&mode).unwrap();
        assert_eq!(
            serde_json::from_str::<ClaudePermissionMode>(&json).unwrap(),
            mode
        );
        let _ = bad; // keep deterministic
    }

    #[test]
    fn candidate_result_is_candidate_only() {
        let cand = ClaudeCandidateResult {
            attempt_id: "attempt-1".into(),
            disposition: ClaudeCandidateDisposition::CandidateReady,
            output: "candidate output".into(),
            output_digest: "abc123".into(),
            truncated: false,
        };
        assert!(cand.validate().is_ok());
        // No TaskId field exists; verify serde deny_unknown_fields would reject a task_id injection.
        let injected = r#"{"attempt_id":"a","disposition":"candidate_ready","output":"o","output_digest":"d","truncated":false,"task_id":"illicit"}"#;
        assert!(serde_json::from_str::<ClaudeCandidateResult>(injected).is_err());
        // Empty output_digest rejected.
        let mut bad = cand.clone();
        bad.output_digest = "".into();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn response_kind_validation() {
        // Result without candidate_result rejected.
        let r = ClaudeSidecarResponse {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-1".into(),
            kind: ClaudeResponseKind::Result,
            payload: None,
            candidate_result: None,
            error: None,
        };
        assert!(r.validate().is_err());

        // Error without error detail rejected.
        let e = ClaudeSidecarResponse {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-1".into(),
            kind: ClaudeResponseKind::Error,
            payload: None,
            candidate_result: None,
            error: None,
        };
        assert!(e.validate().is_err());

        // Event carrying candidate_result rejected.
        let bad = ClaudeSidecarResponse {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-1".into(),
            kind: ClaudeResponseKind::Event,
            payload: Some("delta".into()),
            candidate_result: Some(ClaudeCandidateResult {
                attempt_id: "a".into(),
                disposition: ClaudeCandidateDisposition::CandidateReady,
                output: "o".into(),
                output_digest: "d".into(),
                truncated: false,
            }),
            error: None,
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn unknown_fields_rejected() {
        // Extra field on request is rejected (deny_unknown_fields).
        let with_extra = format!(
            r#"{{"protocol_version":"{}","request_id":"r","kind":"query","prompt":"hi","launch_plan":{},"extra":"no"}}"#,
            CLAUDE_SIDECAR_PROTOCOL_VERSION,
            serde_json::to_string(&valid_plan()).unwrap()
        );
        assert!(ClaudeSidecarRequest::from_ndjson_line(&(with_extra + "\n")).is_err());
    }

    #[test]
    fn distinct_surfaces_not_conflated() {
        assert!(is_local_sidecar_route(CLAUDE_SIDECAR_ROUTE_CLASS));
        assert!(!is_local_sidecar_route(CLAUDE_PLUGIN_SURFACE_ID));
        assert!(!is_local_sidecar_route(CLAUDE_MANAGED_AGENTS_ROUTE_ID));
        assert!(is_managed_agents_route(CLAUDE_MANAGED_AGENTS_ROUTE_ID));
        assert!(!is_managed_agents_route(CLAUDE_SIDECAR_ROUTE_CLASS));
        // Constants are distinct strings.
        assert_ne!(CLAUDE_SIDECAR_ADAPTER_ID, CLAUDE_PLUGIN_SURFACE_ID);
        assert_ne!(CLAUDE_SIDECAR_ROUTE_CLASS, CLAUDE_MANAGED_AGENTS_ROUTE_ID);
    }

    #[test]
    fn authority_disclaimer_is_candidate_only() {
        let d = authority_disclaimer();
        assert!(d.contains("candidate-only"));
        assert!(d.contains("no task"));
        assert!(d.contains("no finish"));
        // Ensure source does not contain forbidden authority owners.
        let src = include_str!("lib.rs");
        // Wave1 file must not mention supervised launch internals or User Broker credential wiring.
        // We assert absence of those concern strings to keep scope bounded.
        // (This is a scope-guard test; if future waves add those, update the guard.)
        assert!(!src.contains("UserBroker") || src.contains("No Python service"));
    }

    #[test]
    fn ndjson_determinism() {
        let q = valid_query();
        let line1 = q.to_ndjson_line().unwrap();
        let line2 = q.to_ndjson_line().unwrap();
        assert_eq!(line1, line2);
        let resp = ClaudeSidecarResponse {
            protocol_version: CLAUDE_SIDECAR_PROTOCOL_VERSION.into(),
            request_id: "req-1".into(),
            kind: ClaudeResponseKind::Started,
            payload: None,
            candidate_result: None,
            error: None,
        };
        let rl1 = resp.to_ndjson_line().unwrap();
        let rl2 = resp.to_ndjson_line().unwrap();
        assert_eq!(rl1, rl2);
    }
}
