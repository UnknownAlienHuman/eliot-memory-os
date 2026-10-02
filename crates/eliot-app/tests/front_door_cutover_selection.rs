//! Front-door cutover selection: the operator flag is evidence, never a
//! routing decision (issue #18, rows W10/A5/N1).
//!
//! Drives the real production `eliot-governor` binary
//! (`main.rs::dispatch_command`, the single production caller of
//! `front_door_cutover::gate_legacy_entrypoint`) and asserts on the stable
//! machine-readable cutover receipt, never on a hand-typed message.
//!
//! The property under proof is the OWNER decision: no value of the operator flag
//! may restore a legacy route, so a legacy invocation is refused by the
//! canonical front door in every flag state.

use anyhow::{Context as _, Result};
use serde_json::Value;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

/// Stable machine-readable cutover code. Same wire value as
/// `front_door_cutover.rs::LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`.
const CUTOVER_CODE: &str = "LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER";

/// Operator launch flag, observed only as refusal evidence
/// (`front_door_cutover.rs::FRONT_DOOR_CUTOVER_FLAG`).
const CUTOVER_FLAG: &str = "ELIOT_CLAUDE_FRONT_DOOR";

/// Operator flag value naming the canonical front door as the selection
/// evidence (`front_door_cutover.rs::FRONT_DOOR_CUTOVER_VALUE`).
const CUTOVER_VALUE: &str = "agent-bridge";

/// Identity label the receipt must preserve for the probed arm
/// (`main.rs::legacy_entrypoint_label`).
const ARM_LABEL: &str = "eliot-governor daemon";

/// Invokes the real production binary with `args` under the given operator
/// flag state (`None` removes the flag entirely).
///
/// `--config` is always passed so the binary never resolves `LOCALAPPDATA`
/// (`runtime_instance.rs::default_config_path`); the path itself is never read,
/// because the refusal happens before any config load.
fn governor(config: &PathBuf, args: &[&str], flag: Option<&str>) -> Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_eliot-governor"));
    command
        .arg("--config")
        .arg(config)
        .args(args)
        .stdin(Stdio::null());
    match flag {
        Some(value) => command.env(CUTOVER_FLAG, value),
        None => command.env_remove(CUTOVER_FLAG),
    }
    .output()
    .with_context(|| format!("invoke eliot-governor with {args:?}"))
}

/// Decodes the single structured receipt a refused legacy invocation emits.
fn receipt(stdout: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(stdout).context("cutover receipt is not UTF-8")?;
    serde_json::from_str(text.trim()).with_context(|| {
        format!("cutover receipt is not one JSON object: {text}")
    })
}

/// Asserts the refusal contract shared by every refused legacy arm: the stable
/// cutover code, a canonical-route redirect receipt, no completion, and the
/// arm label preserved as identity evidence.
fn assert_refused(receipt: &Value) -> Result<String> {
    assert_eq!(
        receipt["code"].as_str(),
        Some(CUTOVER_CODE),
        "a refused legacy arm must carry the stable cutover code"
    );
    assert_eq!(receipt["status"].as_str(), Some("ERROR"));
    assert_eq!(receipt["completed"].as_bool(), Some(false));
    let canonical_route = receipt["canonical_route"].as_str().unwrap_or_default();
    assert!(
        canonical_route.contains("eliotd::canonical_config_precedence"),
        "a refusal must name the canonical Kernel-governed route, got {canonical_route:?}"
    );
    let detail = receipt["detail"].as_str().context("refusal carries no detail")?;
    assert!(
        detail.starts_with(&format!("legacy {ARM_LABEL} is retired")),
        "a refusal must preserve its identity label as route evidence, got {detail:?}"
    );
    Ok(detail.to_owned())
}

/// The operator flag never selects a legacy route. All three flag states — the
/// canonical value, an absent flag, and a stale `legacy` value — end in the same
/// refusal, and only the canonical value is reported as the selection evidence.
///
/// `daemon run` is the probe: `main.rs::dispatch_command` refuses it at the
/// entry gate before `commands::run_daemon`, so a refusal also proves no daemon,
/// store, `ControlWal`, or `WriterActor` was constructed.
#[test]
fn front_door_cutover_flag_is_evidence_and_never_restores_a_legacy_route() -> Result<()> {
    let args = ["daemon", "run"];
    let config = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("governor.toml");

    // The canonical selection: recorded as identity evidence, still refused.
    let selected = governor(&config, &args, Some(CUTOVER_VALUE))?;
    assert!(
        !selected.status.success(),
        "the selected front door must not exit successfully on a legacy arm"
    );
    let selected_receipt = receipt(&selected.stdout)?;
    let selected_detail = assert_refused(&selected_receipt)?;
    assert!(
        selected_detail.contains(&format!("{CUTOVER_FLAG}={CUTOVER_VALUE}")),
        "the canonical selection must be recorded as evidence, got {selected_detail:?}"
    );

    // Absent flag and a stale `legacy` value: both refuse with no legacy route,
    // and neither may claim the flag selects the canonical front door.
    for stale in [None, Some("legacy"), Some("Agent-Bridge")] {
        let refused = governor(&config, &args, stale)?;
        assert!(
            !refused.status.success(),
            "a legacy arm must not exit successfully under flag state {stale:?}"
        );
        let refused_receipt = receipt(&refused.stdout)?;
        let refused_detail = assert_refused(&refused_receipt)?;
        assert!(
            !refused_detail.contains(&format!("{CUTOVER_FLAG}={CUTOVER_VALUE}")),
            "flag state {stale:?} must not be reported as the selection, got {refused_detail:?}"
        );
    }
    Ok(())
}
