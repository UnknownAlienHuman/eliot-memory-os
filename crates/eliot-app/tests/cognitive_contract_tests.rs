use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .context("resolve workspace root")
}

#[test]
fn original_cognitive_suite_remains_a_separate_eighteen_call_contract() -> Result<()> {
    let path = workspace_root()?.join("tests/cognitive/cognitive-contract/cases.json");
    let cases: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    assert_eq!(
        cases["confirmation_token"],
        "CONFIRM-18-BOUNDED-PROVIDER-CALLS"
    );
    assert_eq!(cases["hard_provider_call_cap"], 18);
    assert_eq!(
        cases["cases"]
            .as_array()
            .context("cognitive cases array")?
            .len(),
        12
    );

    let ul_path = workspace_root()?.join("tests/cognitive/ul-cross-agent/suite.json");
    let ul: Value = serde_json::from_slice(&std::fs::read(ul_path)?)?;
    assert_eq!(
        ul["confirmation_token"],
        "CONFIRM-8-CLAUDE-ANTIGRAVITY-BLIND-RELAY"
    );
    assert_eq!(ul["hard_provider_call_cap"], 8);
    assert_ne!(cases["confirmation_token"], ul["confirmation_token"]);
    Ok(())
}

#[test]
fn sealed_cognitive_host_commands_remain_available() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_eliot-governor"))
        .args(["host", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for command in ["cognitive-seal", "cognitive-run", "cognitive-status"] {
        assert!(
            help.contains(command),
            "missing sealed host command {command}"
        );
    }
    Ok(())
}

#[test]
fn cognitive_runner_keeps_one_managed_provider_boundary() -> Result<()> {
    let source = std::fs::read_to_string(
        workspace_root()?.join("crates/eliot-app/src/cognitive_runner.rs"),
    )?;
    assert!(source.contains("run_managed_process("));
    assert!(source.contains("PinnedExecutionAuthority"));
    assert!(source.contains("seal_unknown_outcome_without_redispatch"));
    assert!(source.contains("ELIOT_COGNITIVE_CAPABILITY_FILE"));
    Ok(())
}
