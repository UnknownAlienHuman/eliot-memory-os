//! Lifecycle hook intake for host plugin bridges (issue #18 W11).
//!
//! Hosts invoke `eliot-agent-bridge.exe hook <event>` with the host hook JSON
//! on stdin. The intake decodes the event name from argv (never sniffed from
//! payload bytes), reads stdin under the retired facade contract (empty input
//! means `{}`), attaches `ELIOT_TASK_ID`, evaluates through the existing owner
//! [`EliotHookService`], and writes `decision.stdout` — the host decision
//! schema — to stdout. Per-event identity is preserved: every hooks.json row
//! keeps its own `<event>` argv. The intake takes no
//! `--profile`/`--transport`/`--client-declaration` flags and never enters the
//! MCP JSON-RPC front door or the private `op` loop.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use eliot_engine::EliotHookService;
use eliot_types::HookEventKind;
use thiserror::Error;

/// Leading argv token selecting the lifecycle hook intake (issue #18).
///
/// It mirrors the `mcp` token discipline: the mode is named by argv, stripped
/// before dispatch, and never inferred from payload bytes.
pub const HOOK_MODE_TOKEN: &str = "hook";

/// Typed lifecycle hook intake failure. Each variant carries its stable
/// emission code and process exit status.
#[derive(Debug, Error)]
pub enum HookIntakeError {
    /// `hook` without exactly one event name.
    #[error("hook intake requires exactly one event name, got {0}")]
    MissingEvent(usize),
    /// `hook <event>` names no hook the retired facade contract served.
    #[error("unknown hook event: {0}")]
    UnknownEvent(String),
    /// Host hook JSON stdin could not be read.
    #[error("hook stdin unreadable: {0}")]
    StdinUnreadable(#[source] std::io::Error),
    /// Host hook JSON stdin is not JSON.
    #[error("hook stdin is not JSON: {0}")]
    StdinNotJson(#[from] serde_json::Error),
    /// No runtime home resolves for hook spool state.
    #[error("hook runtime home unresolved: {0}")]
    RuntimeHomeUnresolved(String),
    /// The hook owner refused the event.
    #[error("hook evaluation refused: {0}")]
    EvaluationRefused(#[from] eliot_engine::EngineError),
    /// The host decision schema could not be written to stdout.
    #[error("hook decision unwritable: {0}")]
    DecisionUnwritable(#[source] std::io::Error),
}

impl HookIntakeError {
    /// Stable emission code for the stderr envelope.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingEvent(_) => "HOOK_MISSING_EVENT",
            Self::UnknownEvent(_) => "HOOK_UNKNOWN_EVENT",
            Self::StdinUnreadable(_) => "HOOK_STDIN_UNREADABLE",
            Self::StdinNotJson(_) => "HOOK_STDIN_NOT_JSON",
            Self::RuntimeHomeUnresolved(_) => "HOOK_RUNTIME_HOME_UNRESOLVED",
            Self::EvaluationRefused(_) => "HOOK_EVALUATION_REFUSED",
            Self::DecisionUnwritable(_) => "HOOK_DECISION_UNWRITABLE",
        }
    }

    /// Human detail for the stderr envelope.
    #[must_use]
    pub fn detail(&self) -> String {
        self.to_string()
    }

    /// Process exit status: malformed intake input mirrors the CLI argument
    /// exit, runtime/service failures mirror the composition exit.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::MissingEvent(_)
            | Self::UnknownEvent(_)
            | Self::StdinUnreadable(_)
            | Self::StdinNotJson(_) => crate::INVALID_ARGUMENT_EXIT,
            Self::RuntimeHomeUnresolved(_)
            | Self::EvaluationRefused(_)
            | Self::DecisionUnwritable(_) => crate::PROVIDER_PORT_EXIT,
        }
    }
}

/// The kebab-case argv spelling of one retired facade hook event.
///
/// This mirrors clap's default subcommand renaming for the facade
/// `HookCommand` (`SessionStart` → `session-start`): the exact argv the
/// hooks.json rows name today.
fn parse_hook_event(name: &str) -> Option<HookEventKind> {
    match name {
        "session-start" => Some(HookEventKind::SessionStart),
        "user-prompt-submit" => Some(HookEventKind::UserPromptSubmit),
        "subagent-start" => Some(HookEventKind::SubagentStart),
        "pre-tool-use" => Some(HookEventKind::PreToolUse),
        "permission-request" => Some(HookEventKind::PermissionRequest),
        "post-tool-use" => Some(HookEventKind::PostToolUse),
        "pre-compact" => Some(HookEventKind::PreCompact),
        "post-compact" => Some(HookEventKind::PostCompact),
        "subagent-stop" => Some(HookEventKind::SubagentStop),
        "stop" => Some(HookEventKind::Stop),
        _ => None,
    }
}

/// Runtime root the hook owner spools under.
///
/// This mirrors the retired facade resolution: `ELIOT_GOVERNOR_CONFIG` names
/// the config file whose grandparent directory is the root, otherwise the
/// standalone `LOCALAPPDATA\Eliot` home applies.
fn hook_runtime_root() -> Result<PathBuf, HookIntakeError> {
    if let Some(config) = std::env::var_os("ELIOT_GOVERNOR_CONFIG") {
        let path = PathBuf::from(config);
        let resolved = if path.is_absolute() {
            path
        } else {
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(path)
        };
        return Ok(resolved
            .parent()
            .and_then(Path::parent)
            .unwrap_or_else(|| Path::new(".eliot-governor"))
            .to_path_buf());
    }
    let local_app_data = std::env::var_os("LOCALAPPDATA").map(PathBuf::from).ok_or_else(|| {
        HookIntakeError::RuntimeHomeUnresolved(
            "LOCALAPPDATA is required for a standalone Eliot instance".to_owned(),
        )
    })?;
    Ok(local_app_data.join("Eliot"))
}

/// Serves one `hook <event>` invocation: stdin in, host decision on stdout.
///
/// The stdin/attach/decision contract is the retired `run_hook` contract:
/// empty input parses as `{}`, a set non-empty `ELIOT_TASK_ID` attaches the
/// session to a task, and only `result.decision.stdout` is written.
pub fn run_hook_intake(argv: &[String]) -> Result<(), HookIntakeError> {
    if argv.len() != 1 {
        return Err(HookIntakeError::MissingEvent(argv.len()));
    }
    let kind = parse_hook_event(&argv[0])
        .ok_or_else(|| HookIntakeError::UnknownEvent(argv[0].clone()))?;
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .map_err(HookIntakeError::StdinUnreadable)?;
    let payload = if input.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(&input)?
    };
    let task_attached = std::env::var("ELIOT_TASK_ID")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());
    let result = EliotHookService::for_session(hook_runtime_root()?, task_attached)
        .process(kind, &payload)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, &result.decision.stdout)
        .map_err(HookIntakeError::DecisionUnwritable)?;
    writeln!(lock).map_err(HookIntakeError::DecisionUnwritable)?;
    Ok(())
}
