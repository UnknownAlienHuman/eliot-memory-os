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
//!
//! Issue #4601 bounds this branch's stdin acquisition. Host hook stdin is read
//! through the accepted versioned finite raw-input owner
//! [`crate::request_input::HOOK_INPUT_PROFILE`] and its
//! [`crate::request_input::read_bounded_record`], so the byte ceiling is
//! enforced incrementally with checked arithmetic before any `String` or
//! `serde_json::Value` is constructed. An over-limit or invalid-UTF-8 payload is
//! rejected fail-closed without reaching [`EliotHookService`], without writing a
//! spool record, and without unbounded draining: the owner bounds its
//! resynchronization to `max_oversize_discard_bytes`. Over-limit input is never
//! truncated into a valid accepted prefix and no salvaged suffix is dispatched.
//! Host decision/output compatibility is unchanged: an accepted payload still
//! writes only `result.decision.stdout`, pretty-printed plus a newline.
//!
//! This boundary bounds acquisition only. It does not establish a wall-clock
//! deadline on a blocking slow stdin producer, so no timeout or interruption is
//! claimed here. Hook mode keeps its existing legacy task/environment/spool
//! semantics: bounded input is not authenticated event admission, and this
//! intake mints no task or session authority.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::request_input::{
    HOOK_INPUT_LIMIT_TABLE, HOOK_INPUT_PROFILE, HOOK_INPUT_PROFILE_ID, ReadOutcome,
    read_bounded_record,
};
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
    /// Host hook JSON stdin exceeded the accepted bounded input ceiling.
    ///
    /// Rejected during bounded acquisition, before any payload string or JSON
    /// value exists, before dispatch, and without any spool write. The detail
    /// carries only the published ceiling, the bounded resynchronization byte
    /// count, and whether a terminator was observed — never payload content.
    #[error(
        "hook stdin exceeds {limit_bytes} bytes ({HOOK_INPUT_PROFILE_ID}); \
         discarded {discarded_bytes}, found terminator: {found_terminator}"
    )]
    StdinOversize {
        /// Published ceiling for this host payload, in bytes.
        limit_bytes: usize,
        /// Bytes consumed while resynchronizing, bounded by the profile's
        /// `max_oversize_discard_bytes`. Never the dropped prefix and never
        /// request content.
        discarded_bytes: usize,
        /// Whether resynchronization proved framing by observing a terminator.
        found_terminator: bool,
    },
    /// Host hook JSON stdin is not valid UTF-8.
    ///
    /// Reported for a complete within-bound framed record that failed UTF-8
    /// decoding. Rejected without dispatch and without any spool write; the
    /// detail never echoes the offending bytes.
    #[error("hook stdin is not valid UTF-8 ({HOOK_INPUT_PROFILE_ID})")]
    StdinInvalidUtf8,
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
            Self::StdinOversize { .. } => "HOOK_STDIN_OVERSIZE",
            Self::StdinInvalidUtf8 => "HOOK_STDIN_INVALID_UTF8",
            Self::StdinNotJson(_) => "HOOK_STDIN_NOT_JSON",
            Self::RuntimeHomeUnresolved(_) => "HOOK_RUNTIME_HOME_UNRESOLVED",
            Self::EvaluationRefused(_) => "HOOK_EVALUATION_REFUSED",
            Self::DecisionUnwritable(_) => "HOOK_DECISION_UNWRITABLE",
        }
    }

    /// Human detail for the stderr envelope.
    ///
    /// The over-limit disposition additionally names the published limit table
    /// so the emitted envelope is self-describing about which source owner the
    /// ceiling came from. Only the table identity, the ceiling, the bounded
    /// resynchronization byte count, and the framing result cross into the
    /// detail; payload bytes and payload content never do.
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::StdinOversize { .. } => {
                format!("{self} [{HOOK_INPUT_LIMIT_TABLE}]")
            }
            _ => self.to_string(),
        }
    }

    /// Process exit status: malformed intake input mirrors the CLI argument
    /// exit, runtime/service failures mirror the composition exit.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::MissingEvent(_)
            | Self::UnknownEvent(_)
            | Self::StdinUnreadable(_)
            | Self::StdinOversize { .. }
            | Self::StdinInvalidUtf8
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
    let local_app_data = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .ok_or_else(|| {
            HookIntakeError::RuntimeHomeUnresolved(
                "LOCALAPPDATA is required for a standalone Eliot instance".to_owned(),
            )
        })?;
    Ok(local_app_data.join("Eliot"))
}

/// Reads the host hook payload under the published finite byte ceiling.
///
/// The returned bytes are accepted bytes only: they are empty for the accepted
/// EMPTY input case, and they are always within the published ceiling and valid
/// UTF-8. Every other disposition is a typed [`HookIntakeError`] raised before
/// dispatch.
///
/// The ceiling is enforced incrementally by the owner's
/// [`crate::request_input::read_bounded_record`] with checked arithmetic while
/// collecting, so acquisition never allocates past
/// [`HOOK_INPUT_PROFILE`]::`max_record_bytes` and no `String` or
/// `serde_json::Value` is constructed before the bound has been observed
/// against THIS input. Dispositions:
///
/// - accepted EMPTY input (no bytes at all, or a blank framed record) yields
///   empty bytes, preserving the retired facade contract where empty input
///   parses as `{}`;
/// - a within-bound record that is not valid UTF-8 is
///   [`HookIntakeError::StdinInvalidUtf8`];
/// - a record exceeding the ceiling is [`HookIntakeError::StdinOversize`] and
///   is rejected without truncation into a valid accepted prefix, without
///   dispatch, and with the owner's bounded resynchronization rather than an
///   unbounded drain.
///
/// Accepted bytes are therefore never merely "shaped right": the ceiling is
/// compared against this record's exact length by the owner's acquisition
/// arithmetic before this function returns.
fn acquire_hook_payload<R: std::io::BufRead>(reader: &mut R) -> Result<Vec<u8>, HookIntakeError> {
    let outcome = read_bounded_record(reader, HOOK_INPUT_PROFILE)
        .map_err(HookIntakeError::StdinUnreadable)?;
    let record = match outcome {
        // End of input with no pending bytes is the accepted EMPTY input case;
        // it parses as `{}` exactly as the retired facade contract did.
        ReadOutcome::Eof => Vec::new(),
        ReadOutcome::InvalidUtf8 => return Err(HookIntakeError::StdinInvalidUtf8),
        ReadOutcome::Oversize {
            discarded_bytes,
            found_terminator,
        } => {
            return Err(HookIntakeError::StdinOversize {
                limit_bytes: HOOK_INPUT_PROFILE.max_record_bytes,
                discarded_bytes,
                found_terminator,
            });
        }
        ReadOutcome::Record(bytes) => bytes,
    };
    Ok(record)
}

/// Serves one `hook <event>` invocation: stdin in, host decision on stdout.
///
/// The stdin/attach/decision contract is the retired `run_hook` contract:
/// empty input parses as `{}`, a set non-empty `ELIOT_TASK_ID` attaches the
/// session to a task, and only `result.decision.stdout` is written. Host stdin
/// is first acquired under the published finite ceiling by
/// [`acquire_hook_payload`]; only an accepted payload is decoded and
/// dispatched to [`EliotHookService`].
pub fn run_hook_intake(argv: &[String]) -> Result<(), HookIntakeError> {
    if argv.len() != 1 {
        return Err(HookIntakeError::MissingEvent(argv.len()));
    }
    let kind =
        parse_hook_event(&argv[0]).ok_or_else(|| HookIntakeError::UnknownEvent(argv[0].clone()))?;
    let mut stdin = std::io::stdin().lock();
    let record = acquire_hook_payload(&mut stdin)?;
    // The accepted record is valid UTF-8 by construction; this conversion is a
    // borrow, not a second unbounded copy, and it precedes every `serde_json`
    // allocation. Empty (or whitespace-only) input parses as `{}`, preserving
    // the retired facade contract.
    let Ok(text) = std::str::from_utf8(&record) else {
        return Err(HookIntakeError::StdinInvalidUtf8);
    };
    let payload = if text.trim().is_empty() {
        serde_json::json!({})
    } else {
        serde_json::from_str(text)?
    };
    let task_attached = std::env::var("ELIOT_TASK_ID")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());
    let result = EliotHookService::for_session(hook_runtime_root()?, task_attached)
        .process(kind, &payload)?;
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, &result.decision.stdout)
        .map_err(|e| HookIntakeError::DecisionUnwritable(std::io::Error::other(e)))?;
    writeln!(lock).map_err(HookIntakeError::DecisionUnwritable)?;
    Ok(())
}
