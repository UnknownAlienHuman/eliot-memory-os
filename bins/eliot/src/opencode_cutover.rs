//! OpenCode route cutover front door (issue #18, W11 slice).
//!
//! This module owns the exact operator-CLI argv the OpenCode production
//! route invokes, on the current-owner binary (`eliot`):
//!
//! - `eliot mcp stdio --host opencode --instance default` (from
//!   `integrations/opencode/opencode.json`);
//! - `eliot host event --host opencode --event <kind>` with the compact
//!   event JSON on stdin (compatibility fallback of
//!   `integrations/opencode/plugins/eliot.js`);
//! - `eliot host install --host opencode` / `host uninstall --host opencode`
//!   (documented in `integrations/opencode/README.md`).
//!
//! Serving semantics live with their declared owners, not here:
//!
//! - MCP serving is owned by `bins/eliot-agent-bridge` (`mcp --profile
//!   SPINE_FUNCTIONAL --transport stdio --client-declaration <abs>`), which
//!   admits no `--host opencode` selection and no OpenCode profile, so this
//!   front door cannot delegate without substituting semantics it does not
//!   own (I7.6 forbids host-specific semantic forks);
//! - one-shot host-event intake is owned by the authenticated loopback
//!   bridge (`POST /v1/host-events`); there is no admitted one-shot argv
//!   owner, and direct native-process launch from a runtime root is
//!   forbidden without recorded debt;
//! - the OpenCode JSONC-merge install/uninstall flow (global manifest,
//!   hash-verified governor artifacts, store-backed receipts) is facade
//!   semantics owned by the host-lifecycle lane (#14), not reproducible
//!   here.
//!
//! The cutover therefore resolves the production manifests to this
//! current-owner route and fails closed with a stable machine-readable
//! receipt instead of launching the legacy `eliot-governor` binary:
//!
//! - `mcp stdio` and `host install`/`uninstall` print the ERROR cutover
//!   receipt on stdout and exit `69` (closed front door);
//! - `host event` prints exactly one plugin-parseable
//!   `{"decision":"degraded",...}` object on stdout (mutating tools still
//!   fail closed inside the plugin, which never authorizes a mutation from
//!   the legacy transport) plus the redirect receipt on stderr, and exits
//!   `0` so passive observations degrade without blocking OpenCode.
//!
//! No daemon is started, no store is opened, no task/memory/policy/finish
//! semantics are added, and no new dependency is required: only
//! `anyhow`/`clap`/`serde_json` plus `std`.

use anyhow::Result;
use clap::Subcommand;
use serde_json::json;
use std::io::Read;

/// Stable machine-readable code: the OpenCode route reached the current
/// owner CLI, but the requested serving/install semantics have no admitted
/// owner path yet (bridge OpenCode profile under #13/#77, OpenCode
/// installer under #14).
pub const OPENCODE_ROUTE_CUTOVER: &str = "OPENCODE_ROUTE_CUTOVER";

/// Canonical route named by every OpenCode cutover receipt.
pub const OPENCODE_CANONICAL_ROUTE: &str = "authenticated loopback host-events bridge served by eliot-agent-bridge (POST /v1/host-events) for host events; bridge MCP front door once an OpenCode profile is admitted under #13/#77; OpenCode install/uninstall once admitted under #14";

/// Single host value this cutover front door serves.
pub const OPENCODE_HOST: &str = "opencode";

/// Maximum stdin bytes accepted by `host event`. The plugin's compact
/// payloads are small (bounded 64 KiB effect descriptors); anything larger
/// is not the documented caller and is refused without being read further.
const MAX_HOST_EVENT_STDIN_BYTES: usize = 1_048_576;

/// MCP front door: accepts the exact consumer argv, serves nothing.
#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Serve MCP over stdio. Only `--host opencode` parses here, and it is
    /// always refused with the cutover receipt: MCP serving is owned by
    /// `bins/eliot-agent-bridge`, which admits no OpenCode host/profile.
    Stdio {
        /// Requested access profile (recorded as evidence, never served).
        #[arg(long, default_value = "default")]
        profile: String,
        /// Agent host. Only `opencode` is recognized by this cutover.
        #[arg(long)]
        host: Option<String>,
        /// Runtime instance hint (recorded as evidence, never served).
        #[arg(long)]
        instance: Option<String>,
    },
}

/// Host front door: the minimal OpenCode caller protocol.
#[derive(Debug, Subcommand)]
pub enum HostCommand {
    /// One-shot host-event intake (plugin compatibility fallback). Always
    /// answers the plugin-parseable degraded decision; never authorizes.
    Event {
        /// Agent host. Only `opencode` is recognized by this cutover.
        #[arg(long)]
        host: String,
        /// Host event kind (recorded as evidence, never dispatched).
        #[arg(long)]
        event: String,
    },
    /// Install the OpenCode route. Refused: the install flow has no
    /// admitted owner path yet (host-lifecycle lane, #14).
    Install {
        /// Agent host. Only `opencode` is recognized by this cutover.
        #[arg(long)]
        host: String,
    },
    /// Uninstall the OpenCode route. Refused: the uninstall flow has no
    /// admitted owner path yet (host-lifecycle lane, #14).
    Uninstall {
        /// Agent host. Only `opencode` is recognized by this cutover.
        #[arg(long)]
        host: String,
    },
}

/// Structured cutover rejection on stdout. Same wire shape as the facade
/// `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` refusal so cross-binary evidence
/// joins on identical fields.
#[allow(clippy::print_stdout)]
fn write_cutover_rejection(detail: &str) {
    println!(
        "{}",
        json!({
            "status": "ERROR",
            "code": OPENCODE_ROUTE_CUTOVER,
            "detail": detail,
            "canonical_route": OPENCODE_CANONICAL_ROUTE,
            "completed": false,
        })
    );
}

/// Observable redirect receipt on stderr. Kept off stdout because the
/// `host event` stdout object belongs to the plugin's bridge parser.
#[allow(clippy::print_stderr)]
fn write_cutover_redirect_receipt(detail: &str) {
    eprintln!(
        "{}",
        json!({
            "status": "REDIRECT",
            "code": OPENCODE_ROUTE_CUTOVER,
            "detail": detail,
            "canonical_route": OPENCODE_CANONICAL_ROUTE,
            "completed": false,
        })
    );
}

/// Run the `mcp` front door. Never serves: every arm ends in the cutover
/// receipt before any daemon, store, or bridge initialization.
pub fn run_mcp(command: McpCommand) -> Result<i32> {
    match command {
        McpCommand::Stdio {
            profile,
            host,
            instance,
        } => {
            let host_evidence = host.as_deref().unwrap_or("<absent>");
            let instance_evidence = instance.as_deref().unwrap_or("<absent>");
            if host.as_deref() != Some(OPENCODE_HOST) {
                write_cutover_rejection(&format!(
                    "eliot mcp stdio for host {host_evidence} is not served: this front door carries only the OpenCode cutover (profile={profile} instance={instance_evidence}); retry through {OPENCODE_CANONICAL_ROUTE}"
                ));
                return Ok(crate::FRONT_DOOR_CLOSED_EXIT);
            }
            write_cutover_rejection(&format!(
                "eliot mcp stdio --host opencode is retired as legacy serving (profile={profile} instance={instance_evidence}): no admitted OpenCode MCP profile exists on the bridge owner; retry through {OPENCODE_CANONICAL_ROUTE}"
            ));
            Ok(crate::FRONT_DOOR_CLOSED_EXIT)
        }
    }
}

/// Run the `host` front door.
pub fn run_host(command: HostCommand) -> Result<i32> {
    match command {
        HostCommand::Event { host, event } => run_host_event(&host, &event),
        HostCommand::Install { host } => {
            if host != OPENCODE_HOST {
                write_cutover_rejection(&format!(
                    "eliot host install for host {host} is not served: this front door carries only the OpenCode cutover"
                ));
                return Ok(crate::INVALID_REQUEST_EXIT);
            }
            write_cutover_rejection(&format!(
                "eliot host install --host opencode has no admitted installer yet: the JSONC-merge install flow (global manifest, hash-verified artifacts, receipt-backed rollback) is facade semantics awaiting the host-lifecycle owner (#14); retry through {OPENCODE_CANONICAL_ROUTE}"
            ));
            Ok(crate::FRONT_DOOR_CLOSED_EXIT)
        }
        HostCommand::Uninstall { host } => {
            if host != OPENCODE_HOST {
                write_cutover_rejection(&format!(
                    "eliot host uninstall for host {host} is not served: this front door carries only the OpenCode cutover"
                ));
                return Ok(crate::INVALID_REQUEST_EXIT);
            }
            write_cutover_rejection(&format!(
                "eliot host uninstall --host opencode has no admitted uninstaller yet: the manifest-backed removal flow is facade semantics awaiting the host-lifecycle owner (#14); retry through {OPENCODE_CANONICAL_ROUTE}"
            ));
            Ok(crate::FRONT_DOOR_CLOSED_EXIT)
        }
    }
}

/// One-shot host-event intake. Reads (and drops) the bounded stdin payload
/// so the caller never blocks on a full pipe, validates only that it is
/// bounded JSON, then answers the plugin-parseable degraded decision. The
/// stdin bytes are never echoed: receipts carry identities and digests
/// only, never caller payloads.
#[allow(clippy::print_stdout)]
fn run_host_event(host: &str, event: &str) -> Result<i32> {
    if host != OPENCODE_HOST {
        write_cutover_rejection(&format!(
            "eliot host event for host {host} is not served: this front door carries only the OpenCode cutover"
        ));
        return Ok(crate::INVALID_REQUEST_EXIT);
    }
    if event.trim().is_empty() {
        write_cutover_rejection(
            "eliot host event requires a non-empty --event kind as route evidence",
        );
        return Ok(crate::INVALID_REQUEST_EXIT);
    }
    let mut stdin = std::io::stdin().lock();
    let mut body = Vec::new();
    if stdin.read_to_end(&mut body).is_err() || body.len() > MAX_HOST_EVENT_STDIN_BYTES {
        return emit_event_degraded(
            event,
            "host-event intake is oversized or unreadable; no owner path consumes it",
        );
    }
    if serde_json::from_slice::<serde_json::Value>(&body).is_err() {
        return emit_event_degraded(
            event,
            "host-event intake is not bounded JSON; no owner path consumes it",
        );
    }
    emit_event_degraded(
        event,
        &format!(
            "one-shot host-event intake for event {event} has no admitted argv owner; preferred transport is {OPENCODE_CANONICAL_ROUTE}"
        ),
    )
}

/// Emit the single plugin-parseable degraded decision on stdout plus the
/// redirect receipt on stderr. `decision` is never a permit: the plugin
/// authorizes mutating tools only from a verified host-events response,
/// which this transport cannot produce.
#[allow(clippy::print_stdout)]
fn emit_event_degraded(event: &str, reason: &str) -> Result<i32> {
    let detail = format!("{OPENCODE_ROUTE_CUTOVER}: {reason}");
    println!(
        "{}",
        json!({
            "decision": "degraded",
            "reason": detail,
        })
    );
    write_cutover_redirect_receipt(&format!(
        "eliot host event --host opencode --event {event} degraded without dispatch: {reason}"
    ));
    Ok(0)
}
