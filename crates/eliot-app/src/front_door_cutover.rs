#![forbid(unsafe_code)]
//! Legacy-entrypoint front-door cutover gate (issue #1858; `I19.5`, `I19.10`, `I20.11`).
//!
//! `eliot-governor` is a retained legacy migration/regression facade (see
//! `disposition.rs`): host integrations still launch
//! `eliot-governor.exe mcp stdio --host <host> --instance default`, the staged
//! `eliot-governor.exe daemon run` path owns the shared runtime, generated
//! plugin hooks invoke `hook <event>` (`integrations/claude/eliot/hooks/hooks.json`),
//! and the Windows service registration dispatches `service run`.
//!
//! FRONT DOOR step 1' (issue #1858 Work/Acceptance): once
//! ``ELIOT_CLAUDE_FRONT_DOOR=agent-bridge`` selects the new stack, every one of
//! those legacy entries refuses with the stable machine-readable code
//! [`LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`] plus a redirect receipt naming
//! [`LEGACY_ENTRYPOINT_CANONICAL_ROUTE`]. The refusal is fail-closed and,
//! for every arm except `mcp stdio` (which carries its own delegation branch),
//! happens in the single entry gate at the top of `dispatch_command` — before
//! any arm handler runs, before `ensure_daemon_ready` could auto-launch the
//! daemon, before any `DbClientSet`/`CanonicalStore` start, and before any
//! `ControlWal` or `WriterActor` is constructed, so a cut-over invocation
//! never initializes an independent Governor, direct store mutation route,
//! local control channel, or alternate launch journal. Durable effects stay on
//! the manifest-bound installation path; typed Governor policy resolves only
//! through `eliotd::canonical_config_precedence`.
//!
//! Absent, `legacy`, or any unknown flag value preserves today's behavior;
//! the flag is the single cutover selector for every legacy entry alike.
//!
//! Explicit per-entrypoint disposition (issue Work parent-bullet census,
//! tracked as a checklist item against the entry gate in `dispatch_command`,
//! which names every arm through the single production caller):
//! - Launcher `eliot-governor[.exe]` (active binary plus staged installed
//!   artifact): facade entry only; every subcommand below funnels through
//!   `dispatch_command`, the single production caller of the gate.
//! - Every one of the 57 top-level `Command` arms — including `writer
//!   smoke`/`drain`, `maintenance run`, `import` execute, `daemon`/`service`
//!   status and control arms, `hook` arms, and read-only surfaces such as
//!   `mcp catalog` — is refused at the `dispatch_command` entry gate once the
//!   flag selects the new stack, with [`LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`]
//!   plus the canonical-route receipt. The arm label is preserved as
//!   identity/route evidence in the detail. Refusing read-only surfaces too
//!   keeps the behavior one explicit rule with no silent legacy invocation.
//! - `mcp stdio --host <any>` is the single arm that falls through the entry
//!   gate to its own branch: once the flag selects the new stack it first
//!   emits the same stable code plus canonical-route receipt as an observable
//!   redirect receipt, then delegates the stdio session to the approved
//!   Bridge (`delegate_claude_mcp_to_agent_bridge`). Delegation failures keep
//!   the refusal receipt and return fail-closed with no legacy fallback.
//! - `hook <event>` arms, including generated plugin hooks invoking
//!   `bin/eliot-governor.exe` (`integrations/claude/eliot/hooks/hooks.json`):
//!   refused at the entry gate before `dispatch_hook_command`; once the flag
//!   selects the new stack every hook event is refused with the same stable
//!   code and receipt instead of reaching hook processing.
//! - `daemon run` (and every other `daemon`/`service` arm): refused at the
//!   entry gate before `commands::run_daemon` or the Windows service
//!   dispatcher; once the flag selects the new stack it is refused before
//!   `DbClientSet::start`, `CanonicalStore::from_client_set`, and any
//!   `ControlWal`/`WriterActor` construction.
//! - Release/host scripts staging `eliot-governor.exe` and host/skill manifests
//!   (`scripts/*`, `integrations/*`): owned by #1719/#2562; referenced here
//!   for census only, never mutated by this lane.
//! - Compatibility alias `seal-provider-plan` (visible alias of the `seal`
//!   subcommand): same-dispatch alias, not a separate entrypoint or authority;
//!   no independent gate surface. No new aliases are added here.
//!
//! Wire receipt compatibility: the rejection object shape (`status`, `code`,
//! `detail`, `canonical_route`, `completed`) and the canonical-route text
//! match `bins/eliot/src/main.rs::write_legacy_governor_cutover_rejection`
//! and `bins/eliot/src/legacy_governor_config.rs::LEGACY_GOVERNOR_CANONICAL_ROUTE`
//! so cross-binary evidence joins on identical codes and routes.

use serde_json::json;

/// Operator launch flag that selects the new stack. Owned by #1719; this
/// module only observes it, never sets or documents new values.
pub const FRONT_DOOR_CUTOVER_FLAG: &str = "ELIOT_CLAUDE_FRONT_DOOR";

/// Flag value that selects the new stack and retires the legacy entrypoints.
/// Any other value (including absent) preserves today's legacy behavior.
pub const FRONT_DOOR_CUTOVER_VALUE: &str = "agent-bridge";

/// Stable machine-readable cutover code: the legacy entrypoint was refused
/// because the front-door flag selected the canonical stack.
pub const LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER: &str = "LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER";

/// Canonical Kernel-governed route named by every cutover redirect receipt.
/// Same wire text as the `eliot` binary's canonical route so evidence joins.
pub const LEGACY_ENTRYPOINT_CANONICAL_ROUTE: &str = "eliot setup through the Kernel canonical configuration surface (Host-managed StoreLaunchConfig bound to the installation manifest; Governor operates only as outbound-only eliotd polling Kernel; typed policy resolves only through eliotd::canonical_config_precedence)";

/// Returns true only when the operator explicitly selected the new stack.
/// Absent, `legacy`, or any unknown value keeps the legacy path.
#[must_use]
pub fn front_door_cutover_selected() -> bool {
    std::env::var(FRONT_DOOR_CUTOVER_FLAG).is_ok_and(|value| value == FRONT_DOOR_CUTOVER_VALUE)
}

/// Fail-closed gate for a legacy entrypoint invocation. Returns `Ok(())`
/// when the invocation may proceed on the legacy path, or `Err` with the
/// structured cutover detail once the flag selects the new stack — for every
/// legacy entrypoint and host alike. Callers must emit
/// [`write_cutover_rejection`] and abort; no daemon launch, store start,
/// `ControlWal` open, or `WriterActor` channel may follow. The optional host
/// is preserved as identity/route evidence in the detail.
pub fn gate_legacy_entrypoint(entrypoint: &str, host: Option<&str>) -> Result<(), String> {
    if front_door_cutover_selected() {
        let host_evidence = match host {
            Some(host) if !host.trim().is_empty() => format!(" for host {host}"),
            _ => String::new(),
        };
        return Err(format!(
            "legacy {entrypoint}{host_evidence} is retired: {FRONT_DOOR_CUTOVER_FLAG}={FRONT_DOOR_CUTOVER_VALUE} selects the canonical front door; retry through {LEGACY_ENTRYPOINT_CANONICAL_ROUTE}"
        ));
    }
    Ok(())
}

/// Structured legacy-entrypoint cutover rejection. Emits the stable
/// machine-readable cutover code with a redirect receipt naming the canonical
/// Kernel-governed route. Observational only: callers still return `Err`, so
/// the refusal stays fail-closed with no alternate writer.
#[allow(clippy::print_stdout)]
pub fn write_cutover_rejection(code: &str, detail: &str) {
    println!(
        "{}",
        json!({
            "status": "ERROR",
            "code": code,
            "detail": detail,
            "canonical_route": LEGACY_ENTRYPOINT_CANONICAL_ROUTE,
            "completed": false,
        })
    );
}

/// Observable redirect receipt for the delegated `mcp stdio` path. Emits the
/// same stable machine-readable cutover code and canonical-route receipt as
/// [`write_cutover_rejection`], but on stderr: a successful delegation hands
/// the inherited stdout to the approved Bridge as the live MCP session, so a
/// stdout receipt would corrupt the JSON-RPC stream the client is reading.
/// The stderr receipt keeps the redirect observable in host logs without
/// touching the delegated session. Observational only: the caller still
/// delegates (or returns `Err` on resolution/launch failure), so no legacy
/// semantic initialization follows.
#[allow(clippy::print_stderr)]
pub fn write_cutover_redirect_receipt(code: &str, detail: &str) {
    eprintln!(
        "{}",
        json!({
            "status": "REDIRECT",
            "code": code,
            "detail": detail,
            "canonical_route": LEGACY_ENTRYPOINT_CANONICAL_ROUTE,
            "completed": false,
        })
    );
}
