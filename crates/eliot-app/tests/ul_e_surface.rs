use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const EXACT_SKILLS: [&str; 4] = [
    "eliot-work",
    "eliot-remember",
    "eliot-recover",
    "eliot-finish",
];

#[test]
fn part_e_static_doctor_passes_for_all_native_hosts() -> TestResult {
    for host in ["codex", "claude", "antigravity"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_eliot-governor"));
        command
            .args(["ul", "doctor", "--host", host])
            .current_dir(repo_root());
        if host == "codex" {
            command.env(
                "ELIOT_DOCTOR_CODEX_CONFIG",
                repo_root().join("crates/eliot-app/tests/fixtures/codex_worker_config.toml"),
            );
        }
        let output = command.output()?;
        assert!(
            output.status.success(),
            "{host}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8(output.stdout)?;
        assert!(!stdout.contains("FIX "), "{host}: {stdout}");
        assert!(stdout.contains(&format!("PASS {host} part-e-tool-list")));
        assert!(stdout.contains(&format!("PASS {host} description-budget")));
        assert!(stdout.contains(&format!("PASS {host} canonical-skills")));
        if host == "codex" {
            assert!(stdout.contains("PASS codex installed-registration"));
        }
    }
    Ok(())
}

#[test]
fn active_skill_set_and_manifest_are_exact() -> TestResult {
    let root = repo_root();
    let manifest: Value = serde_json::from_slice(&std::fs::read(
        root.join("integrations/agent-skills/skill-pack.manifest.json"),
    )?)?;
    let names = manifest
        .get("skills")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|skill| skill.get("name").and_then(Value::as_str))
        .collect::<Vec<_>>();
    assert_eq!(names, EXACT_SKILLS);
    assert_eq!(
        manifest
            .get("derived_packages")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(4)
    );
    Ok(())
}

#[test]
fn codex_manifest_has_one_mcp_and_discoverable_hooks() -> TestResult {
    let package = repo_root().join("plugin/eliot-governor");
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(package.join(".codex-plugin/plugin.json"))?)?;
    assert_eq!(
        manifest.get("mcpServers").and_then(Value::as_str),
        Some("./.mcp.json")
    );
    assert!(manifest.get("hooks").is_none());
    let mcp: Value = serde_json::from_slice(&std::fs::read(package.join(".mcp.json"))?)?;
    assert_eq!(
        mcp.get("mcpServers")
            .and_then(Value::as_object)
            .map(serde_json::Map::len),
        Some(1)
    );
    assert_eq!(
        mcp.pointer("/mcpServers/eliot/args"),
        Some(&serde_json::json!([
            "mcp",
            "stdio",
            "--host",
            "codex",
            "--profile",
            "codex_worker",
            "--instance",
            "default"
        ]))
    );
    let hooks: Value = serde_json::from_slice(&std::fs::read(package.join("hooks/hooks.json"))?)?;
    for event in [
        "SessionStart",
        "PreToolUse",
        "PostToolUse",
        "PreCompact",
        "PostCompact",
    ] {
        assert!(hooks.pointer(&format!("/hooks/{event}")).is_some());
    }
    Ok(())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
