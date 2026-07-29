use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

#[test]
fn cognitive_field_cli_validates_the_exact_suite_and_publishes_schemas() -> Result<()> {
    let root = workspace_root()?;
    let suite = root.join("tests/cognitive/field-v2/suite.json");
    let output = Command::new(env!("CARGO_BIN_EXE_eliot-governor"))
        .args(["cognitive-field", "validate", "--suite"])
        .arg(&suite)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["valid"], true);
    assert_eq!(report["case_count"], 48);
    assert_eq!(report["model_backed_case_count"], 18);

    for (kind, title) in [
        ("worker", "CognitiveWorkerResult"),
        ("reader", "CognitiveUnderstandingAnswer"),
        ("judge", "CognitiveJudgeResult"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_eliot-governor"))
            .args(["cognitive-field", "schema", "--kind", kind])
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let schema: Value = serde_json::from_slice(&output.stdout)?;
        assert_eq!(schema["title"], title);
    }
    Ok(())
}

#[test]
fn cognitive_field_help_exposes_validation_preparation_recording_and_grade() -> Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_eliot-governor"))
        .args(["cognitive-field", "--help"])
        .output()?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout)?;
    for command in [
        "validate",
        "schema",
        "prepare",
        "record-deterministic",
        "seal-provider-plan",
        "record-provider",
        "grade",
    ] {
        assert!(help.contains(command), "missing cognitive-field {command}");
    }
    Ok(())
}

fn workspace_root() -> Result<PathBuf> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .context("resolve workspace root")
}
