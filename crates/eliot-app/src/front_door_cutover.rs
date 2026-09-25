#![forbid(unsafe_code)]
//! Legacy-entrypoint front-door cutover gate (issue #1858; `I19.5`, `I19.10`, `I20.11`).
//!
//! `eliot-governor` is a retained legacy migration/regression facade (see
//! `disposition.rs`): every host integration still launches
//! `eliot-governor.exe mcp stdio --host <host> --instance default`, and the
//! staged `eliot-governor.exe daemon run` path owns the shared runtime that
//! serves the hosts which have not cut over. Owner decision 2026-09-25
//! (FRONT DOOR step 1'): exactly one host moves off the legacy entry behind
//! an explicit operator flag; every other host stays on legacy.
//!
//! Once ``ELIOT_CLAUDE_FRONT_DOOR=agent-bridge`` selects the new stack, the
//! retired `claude` host edge refuses with the stable machine-readable code
//! [`LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`] plus a redirect receipt naming
//! [`LEGACY_ENTRYPOINT_CANONICAL_ROUTE`]. The refusal is fail-closed and
//! happens before `ensure_daemon_ready` could auto-launch the daemon, before
//! any `DbClientSet`/`CanonicalStore` start, and before any `ControlWal` or
//! `WriterActor` is constructed, so a cut-over invocation never initializes
//! an independent Governor, direct store mutation route, local control
//! channel, or alternate launch journal. Durable effects stay on the
//! manifest-bound installation path; typed Governor policy resolves only
//! through `eliotd::canonical_config_precedence`.
//!
//! The remaining hosts (`codex`, `opencode`, `claude-desktop`) are untouched:
//! absent/legacy flag values preserve today's behavior, and the shared
//! `daemon run` path is retained while those hosts still terminate here
//! (disposition recorded in the release manifest by
//! `scripts/build-eliot-windows-x64-release.ps1`).
//!
//! Explicit per-entrypoint disposition (FRONT DOOR step 1', owner scope):
//! - `mcp stdio --host claude` with the flag set: refused here with
//!   [`LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`] plus the canonical-route receipt.
//! - `mcp stdio --host codex|opencode|claude-desktop` (any flag value):
//!   retained legacy path, owned by #1719 until each host's cutover.
//! - `hook <event>` arms: retained plugin-lifecycle path, gate intentionally
//!   not applied; hook cutover is owned by #1719/#13, not this module.
//! - `daemon run`: retained shared runtime serving the not-yet-cut-over
//!   hosts; refusing it here would break those retained paths, so the gate
//!   intentionally does not cover it (see #1719).
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

/// Flag value that retires the legacy `claude` host entrypoint. Any other
/// value (including absent) preserves today's legacy behavior.
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

/// Returns true for the single host retired by the flag. Every other host
/// (`codex`, `opencode`, `claude-desktop`, or none) stays on legacy.
#[must_use]
pub fn cutover_host_retired(host: Option<&str>) -> bool {
    host.is_some_and(|host| host.eq_ignore_ascii_case("claude"))
}

/// Fail-closed gate for a legacy entrypoint invocation. Returns `Ok(())`
/// when the invocation may proceed on the legacy path, or `Err` with the
/// structured cutover detail when the flag retired this host edge. Callers
/// must emit [`write_cutover_rejection`] and abort; no daemon launch, store
/// start, `ControlWal` open, or `WriterActor` channel may follow.
pub fn gate_legacy_entrypoint(entrypoint: &str, host: Option<&str>) -> Result<(), String> {
    if front_door_cutover_selected() && cutover_host_retired(host) {
        let host_name = host.unwrap_or("unknown");
        return Err(format!(
            "legacy {entrypoint} for host {host_name} is retired: {FRONT_DOOR_CUTOVER_FLAG}={FRONT_DOOR_CUTOVER_VALUE} selects the canonical front door; retry through {LEGACY_ENTRYPOINT_CANONICAL_ROUTE}"
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
