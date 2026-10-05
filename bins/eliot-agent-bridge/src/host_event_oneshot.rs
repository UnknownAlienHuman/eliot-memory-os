//! One-shot host-event intake for host plugin bridges (issue #18 W11).
//!
//! Hosts invoke `eliot-agent-bridge.exe host-event --host <host> --event <kind>`
//! with the host event JSON on stdin. This is the retired facade
//! `HostCommand::Event` contract
//! (`crates/eliot-app/src/host_runtime/event_and_authority.rs::record_event`):
//! stdin is bounded to 64 KiB + 1 byte, the payload is normalized through the
//! shared `eliot_engine::HostEventService`, task and work identifiers attach
//! from the process environment, and the blocking rule below decides between
//! `passive` (nothing persisted), `recorded` (envelope spooled under the
//! runtime root), and `deny`. The decision JSON is written to stdout.
//!
//! The leading `host-event` token is the one-shot intake. It is not the
//! `host-events` serving loop: that mode binds a User-Broker-minted
//! introduction and serves `/v1/host-events` until stopped, while this mode
//! records exactly one event and exits. The token is named by argv, stripped
//! before dispatch, and never inferred from payload bytes. The intake takes
//! no `--profile`/`--transport`/`--client-declaration` flags and never enters
//! the MCP JSON-RPC front door or the private `op` loop.
//!
//! Norm: docs/architecture/A02-02-roles.md:3 (every state change or effect
//! requires applicable authority - a recorded event carries task and lease
//! evidence or stays passive); docs/architecture/I02-11 (the agent bridge
//! bundle is an independent release unit, so its host-event intake lives in
//! the bridge-owning process).

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use eliot_engine::{EngineError, HostEventService};
use eliot_types::{AgentHostId, TaskId, WorkItemId, WorkLeaseId};
use serde_json::{Value, json};
use thiserror::Error;
use uuid::Uuid;

/// Leading argv token selecting the one-shot host-event intake (issue #18).
///
/// It mirrors the `hook` token discipline: the mode is named by argv, stripped
/// before dispatch, and never inferred from payload bytes. It is singular on
/// purpose: `host-events` (plural) is the supervised serving loop.
pub const HOST_EVENT_ONESHOT_MODE_TOKEN: &str = "host-event";

/// Stdin byte ceiling: the retired facade read 64 KiB + 1 so an over-limit
/// payload is observed before the normalizer refuses it.
const STDIN_MAX_BYTES: u64 = 64 * 1024 + 1;

/// Typed one-shot host-event intake failure. Each variant carries its stable
/// emission code and process exit status.
#[derive(Debug, Error)]
pub enum HostEventOneshotError {
    /// `host-event` without `--host <host> --event <kind>`.
    #[error("host-event intake requires --host <host> --event <kind>, got {0} args")]
    MissingArgs(usize),
    /// `--host` names no L7 managed integration target.
    #[error("unknown agent host: {0}")]
    UnknownHost(String),
    /// Host event stdin could not be read.
    #[error("host-event stdin unreadable: {0}")]
    StdinUnreadable(#[source] std::io::Error),
    /// Host event stdin exceeds the 64 KiB ceiling.
    #[error("host-event stdin exceeds 64 KiB")]
    StdinOversize,
    /// A task, work-item, or lease environment value does not parse.
    #[error("host-event environment identity unparsable: {0}")]
    IdentityUnparsable(String),
    /// Payload normalization refused the event.
    #[error("host-event normalization refused: {0}")]
    NormalizeRefused(#[source] EngineError),
    /// Runtime home (spool root) cannot be resolved.
    #[error("host-event runtime home unresolved: {0}")]
    RuntimeHomeUnresolved(String),
    /// Event envelope spool record cannot be written.
    #[error("host-event spool unwritable: {0}")]
    SpoolUnwritable(#[source] std::io::Error),
    /// Decision JSON cannot be written to stdout.
    #[error("host-event decision unwritable: {0}")]
    DecisionUnwritable(#[source] std::io::Error),
}
impl HostEventOneshotError {
    /// Stable emission code for the stderr envelope.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingArgs(_) => "HOST_EVENT_MISSING_ARGS",
            Self::UnknownHost(_) => "HOST_EVENT_UNKNOWN_HOST",
            Self::StdinUnreadable(_) => "HOST_EVENT_STDIN_UNREADABLE",
            Self::StdinOversize => "HOST_EVENT_STDIN_OVERSIZE",
            Self::IdentityUnparsable(_) => "HOST_EVENT_IDENTITY_UNPARSABLE",
            Self::NormalizeRefused(_) => "HOST_EVENT_NORMALIZE_REFUSED",
            Self::RuntimeHomeUnresolved(_) => "HOST_EVENT_RUNTIME_HOME_UNRESOLVED",
            Self::SpoolUnwritable(_) => "HOST_EVENT_SPOOL_UNWRITABLE",
            Self::DecisionUnwritable(_) => "HOST_EVENT_DECISION_UNWRITABLE",
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
            Self::MissingArgs(_)
            | Self::UnknownHost(_)
            | Self::StdinUnreadable(_)
            | Self::StdinOversize
            | Self::IdentityUnparsable(_)
            | Self::NormalizeRefused(_) => crate::INVALID_ARGUMENT_EXIT,
            Self::RuntimeHomeUnresolved(_)
            | Self::SpoolUnwritable(_)
            | Self::DecisionUnwritable(_) => crate::PROVIDER_PORT_EXIT,
        }
    }
}

/// Blocking rule for one recorded host event.
///
/// - `deny` stops the call: a mutating gate point (`PreToolUse`,
///   `tool.execute.before`) with an attached task but no work lease.
/// - `recorded` allows the call and is worth persisting: a task is attached,
///   so the event is evidence about that task.
/// - `passive` allows the call and is worth nothing: no task is attached, so
///   the session is not the bridge business. The plugin is installed at user
///   scope and sees every project on the machine, so this is the common case.
///
/// Ported verbatim from the retired facade so the gate keeps the exact
/// blocking behavior the bridge replaces. Pulled out of the event handler so
/// the blocking rule is exercised directly: a gate that is never tested is
/// indistinguishable from one that only records.
pub const fn oneshot_hook_decision(
    declared_event: &str,
    task_attached: bool,
    holds_work_lease: bool,
) -> &'static str {
    let mutation_gate_point = matches!(
        declared_event.as_bytes(),
        b"PreToolUse" | b"tool.execute.before"
    );
    if !task_attached {
        return "passive";
    }
    if mutation_gate_point && !holds_work_lease {
        return "deny";
    }
    "recorded"
}

fn parse_host(value: &str) -> Result<AgentHostId, HostEventOneshotError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "opencode" => Ok(AgentHostId::OpenCode),
        "claude" | "claude-code" => Ok(AgentHostId::Claude),
        "codex" => Ok(AgentHostId::Codex),
        "antigravity" | "agy" => Ok(AgentHostId::Antigravity),
        _ => Err(HostEventOneshotError::UnknownHost(value.to_owned())),
    }
}

fn ensure_l7_host(host: AgentHostId) -> Result<(), HostEventOneshotError> {
    if matches!(host, AgentHostId::OpenCode | AgentHostId::Claude) {
        Ok(())
    } else {
        Err(HostEventOneshotError::UnknownHost(format!(
            "{} is not an L7 managed integration target",
            host.as_str()
        )))
    }
}

fn env_identity<T>(name: &str) -> Result<Option<T>, HostEventOneshotError>
where
    T: FromStr,
    T::Err: std::fmt::Display,
{
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            value.parse().map_err(|error| {
                HostEventOneshotError::IdentityUnparsable(format!("parse {name}: {error}"))
            })
        })
        .transpose()
}

/// Runtime root the one-shot intake spools under.
///
/// This mirrors the retired facade resolution: `ELIOT_GOVERNOR_CONFIG` names
/// the config file whose grandparent directory is the root, otherwise the
/// standalone `LOCALAPPDATA\Eliot` home applies.
fn oneshot_runtime_root() -> Result<PathBuf, HostEventOneshotError> {
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
            HostEventOneshotError::RuntimeHomeUnresolved(
                "LOCALAPPDATA is required for a standalone Eliot instance".to_owned(),
            )
        })?;
    Ok(local_app_data.join("Eliot"))
}

fn atomic_write_json(path: &Path, value: &Value) -> Result<(), HostEventOneshotError> {
    let bytes = serde_json::to_vec_pretty(value).map_err(HostEventOneshotError::wrap_serde)?;
    atomic_write_bytes(path, &bytes).map_err(HostEventOneshotError::SpoolUnwritable)
}

fn atomic_write_bytes(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "atomic write path has no parent",
        )
    })?;
    std::fs::create_dir_all(parent)?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("eliot"),
        Uuid::new_v4()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    std::io::Write::write_all(&mut file, bytes)?;
    file.flush()?;
    file.sync_all()?;
    drop(file);
    #[cfg(windows)]
    eliot_windows_ipc::atomic_replace_file(&temp, path)?;
    #[cfg(not(windows))]
    std::fs::rename(&temp, path)?;
    Ok(())
}
/// Serves one `host-event --host <host> --event <kind>` invocation: stdin in,
/// host decision on stdout.
///
/// The argv/stdin/attach/decision contract is the retired
/// `HostCommand::Event` contract: flags arrive in any order, stdin carries the
/// host event JSON, `ELIOT_TASK_ID` attaches the session to a task,
/// `ELIOT_WORK_ITEM_ID` and `ELIOT_WORK_LEASE_ID` attach work evidence, and
/// only the decision JSON below is written to stdout.
pub fn run_host_event_oneshot(argv: &[String]) -> Result<(), HostEventOneshotError> {
    let (host_name, event_name) = parse_oneshot_argv(argv)?;
    let host = parse_host(&host_name)?;
    ensure_l7_host(host)?;
    let mut raw = Vec::new();
    std::io::stdin()
        .take(STDIN_MAX_BYTES)
        .read_to_end(&mut raw)
        .map_err(HostEventOneshotError::StdinUnreadable)?;
    if raw.len() as u64 > STDIN_MAX_BYTES {
        return Err(HostEventOneshotError::StdinOversize);
    }
    let mut envelope = HostEventService
        .normalize(host, &event_name, &raw)
        .map_err(HostEventOneshotError::NormalizeRefused)?;
    envelope.task_id = env_identity::<TaskId>("ELIOT_TASK_ID")?;
    envelope.work_item_id = env_identity::<WorkItemId>("ELIOT_WORK_ITEM_ID")?;
    let lease: Option<WorkLeaseId> = env_identity("ELIOT_WORK_LEASE_ID")?;
    let decision = oneshot_hook_decision(&event_name, envelope.task_id.is_some(), lease.is_some());
    // The plugin is installed at user scope, so these hooks fire in every
    // host session on this machine, including projects that have nothing to
    // do with ELIOT. An unbound event describes no task and changes no ELIOT
    // state, so persisting it writes two files per tool call to record that
    // something unrelated happened. Answer and get out of the way.
    let path = if decision == "passive" {
        None
    } else {
        let root = oneshot_runtime_root()?;
        let event_root = root.join("reports").join("host-events").join(host.as_str());
        let path = event_root.join(format!("{}.json", Uuid::new_v4()));
        atomic_write_json(
            &path,
            &serde_json::to_value(&envelope).map_err(HostEventOneshotError::wrap_serde)?,
        )?;
        atomic_write_json(
            &event_root.join("latest.json"),
            &serde_json::to_value(&envelope).map_err(HostEventOneshotError::wrap_serde)?,
        )?;
        Some(path)
    };
    if host == AgentHostId::Claude {
        if decision == "deny" {
            return write_decision(&json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": "attached mutating task has no current work lease reference"
                }
            }));
        }
        if event_name == "SessionStart" {
            return write_decision(&json!({
                "continue": true,
                "suppressOutput": true,
                "hookSpecificOutput": {
                    "hookEventName": "SessionStart",
                    "additionalContext": "For a material project task, load the matching eliot:* skill and use ELIOT project identity/current state before broad search or mutation. Skills guide; current task leases and gates authorize."
                }
            }));
        }
        return write_decision(&json!({
            "continue": true,
            "suppressOutput": true
        }));
    }
    write_decision(&json!({
        "decision": decision,
        "reason": (decision == "deny").then_some("attached mutating task has no current work lease reference"),
        "event_ref": path,
        "raw_payload_stored": false,
        "host_identity_granted_role": false
    }))
}

fn parse_oneshot_argv(argv: &[String]) -> Result<(String, String), HostEventOneshotError> {
    let mut host: Option<String> = None;
    let mut event: Option<String> = None;
    let mut rest = argv.iter();
    while let Some(flag) = rest.next() {
        match flag.as_str() {
            "--host" => host = rest.next().cloned(),
            "--event" => event = rest.next().cloned(),
            _ => {}
        }
    }
    match (host, event) {
        (Some(host), Some(event)) => Ok((host, event)),
        _ => Err(HostEventOneshotError::MissingArgs(argv.len())),
    }
}

fn write_decision(decision: &Value) -> Result<(), HostEventOneshotError> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, decision).map_err(HostEventOneshotError::wrap_serde)?;
    std::io::Write::write_all(&mut lock, b"\n")
        .map_err(HostEventOneshotError::DecisionUnwritable)?;
    Ok(())
}

impl HostEventOneshotError {
    fn wrap_serde(error: serde_json::Error) -> Self {
        Self::DecisionUnwritable(std::io::Error::other(error))
    }
}
#[cfg(test)]
mod tests {
    use super::oneshot_hook_decision;

    #[test]
    fn hook_decision_is_passive_without_task() {
        assert_eq!(oneshot_hook_decision("PreToolUse", false, false), "passive");
        assert_eq!(
            oneshot_hook_decision("SessionStart", false, true),
            "passive"
        );
        assert_eq!(
            oneshot_hook_decision("anything-else", false, false),
            "passive"
        );
    }

    #[test]
    fn hook_decision_denies_unleased_mutation_gate() {
        assert_eq!(oneshot_hook_decision("PreToolUse", true, false), "deny");
        assert_eq!(
            oneshot_hook_decision("tool.execute.before", true, false),
            "deny"
        );
    }

    #[test]
    fn hook_decision_records_attached_task() {
        assert_eq!(oneshot_hook_decision("PreToolUse", true, true), "recorded");
        assert_eq!(
            oneshot_hook_decision("tool.execute.before", true, true),
            "recorded"
        );
        assert_eq!(
            oneshot_hook_decision("SessionStart", true, false),
            "recorded"
        );
        assert_eq!(
            oneshot_hook_decision("anything-else", true, false),
            "recorded"
        );
    }

    #[test]
    fn parse_host_names_l7_targets() {
        assert!(super::parse_host("opencode").is_ok());
        assert!(super::parse_host("OpenCode").is_ok());
        assert!(super::parse_host("claude-code").is_ok());
        assert!(super::parse_host("codex").is_ok());
        assert!(super::parse_host("agy").is_ok());
        assert!(super::parse_host("no-such-host").is_err());
    }

    #[test]
    fn l7_gate_admits_only_opencode_and_claude() {
        use eliot_types::AgentHostId;
        assert!(super::ensure_l7_host(AgentHostId::OpenCode).is_ok());
        assert!(super::ensure_l7_host(AgentHostId::Claude).is_ok());
        assert!(super::ensure_l7_host(AgentHostId::Codex).is_err());
        assert!(super::ensure_l7_host(AgentHostId::Antigravity).is_err());
    }

    #[test]
    fn error_codes_and_exits_are_stable() {
        let cases = [
            (
                super::HostEventOneshotError::MissingArgs(0),
                "HOST_EVENT_MISSING_ARGS",
            ),
            (
                super::HostEventOneshotError::UnknownHost("x".to_owned()),
                "HOST_EVENT_UNKNOWN_HOST",
            ),
            (
                super::HostEventOneshotError::StdinOversize,
                "HOST_EVENT_STDIN_OVERSIZE",
            ),
        ];
        for (error, code) in cases {
            assert_eq!(error.code(), code);
            assert!(!error.detail().is_empty());
        }
        assert_eq!(
            super::HostEventOneshotError::StdinOversize.exit_code(),
            crate::INVALID_ARGUMENT_EXIT
        );
        assert_eq!(
            super::HostEventOneshotError::DecisionUnwritable(std::io::Error::other("x"))
                .exit_code(),
            crate::PROVIDER_PORT_EXIT
        );
    }
}
