// Integration fixtures fail immediately when static paths or emitted JSON are invalid.
#![allow(clippy::expect_used)]

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use serde_json::Value;

fn repository_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_owned()
}

#[test]
fn snapshot_binds_explicit_root_when_process_starts_in_non_git_directory() {
    let root = repository_root();
    let temp_root =
        std::env::temp_dir().join(format!("eliot-system-snapshot-{}", std::process::id()));
    let output = temp_root.join("snapshot.json");
    fs::create_dir_all(&temp_root).expect("create non-git cwd");

    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "system",
            "snapshot",
            "--repo-root",
            root.to_str().expect("root is utf8"),
            "--output",
            output.to_str().expect("output is utf8"),
        ])
        .output()
        .expect("run snapshot command");

    assert!(
        result.status.success(),
        "snapshot failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    let stdout: Value = serde_json::from_slice(&result.stdout).expect("snapshot JSON on stdout");
    let file: Value = serde_json::from_slice(&fs::read(&output).expect("snapshot artifact"))
        .expect("snapshot JSON on disk");
    assert_eq!(stdout, file);
    assert_eq!(
        file.pointer("/receipt/snapshot_sha256")
            .and_then(Value::as_str),
        file.pointer("/snapshot/snapshot_sha256")
            .and_then(Value::as_str)
    );
    assert_eq!(
        file.pointer("/snapshot/selected_repository_root")
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase),
        Some(
            fs::canonicalize(&root)
                .expect("canonical root")
                .to_string_lossy()
                .to_ascii_lowercase()
        )
    );
    assert_eq!(
        file.pointer("/snapshot/records")
            .and_then(Value::as_array)
            .and_then(|records| {
                records.iter().find(|record| {
                    record.get("key").and_then(Value::as_str) == Some("runtime.status")
                })
            })
            .and_then(|record| record.get("value"))
            .and_then(Value::as_str),
        Some("NOT_RUNNING")
    );

    let second = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "system",
            "snapshot",
            "--repo-root",
            root.to_str().expect("root is utf8"),
            "--output",
            output.to_str().expect("output is utf8"),
        ])
        .output()
        .expect("rerun snapshot command");
    assert!(
        !second.status.success(),
        "existing artifact was overwritten"
    );

    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_status_requires_existing_explicit_registry() {
    let temp_root =
        std::env::temp_dir().join(format!("eliot-installation-status-{}", std::process::id()));
    fs::create_dir_all(&temp_root).expect("create status fixture");
    let registry = temp_root.join("missing.redb");
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .current_dir(&temp_root)
        .args([
            "installation",
            "status",
            "--registry",
            registry.to_str().expect("registry is utf8"),
        ])
        .output()
        .expect("run status command");

    assert!(!result.status.success());
    assert!(!registry.exists(), "status created a missing registry");
    let output: Value = serde_json::from_slice(&result.stdout).expect("status JSON error");
    assert_eq!(output["code"], "INSTALLATION_STATUS_UNAVAILABLE");
    let _ = fs::remove_dir_all(temp_root);
}

#[test]
fn installation_plan_rejects_relative_input() {
    let result = Command::new(env!("CARGO_BIN_EXE_eliot"))
        .args(["installation", "plan", "--input", "plan.json"])
        .output()
        .expect("run plan command");

    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("path must be absolute"));
}
