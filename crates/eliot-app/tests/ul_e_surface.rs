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
        let output = Command::new(env!("CARGO_BIN_EXE_eliot-governor"))
            .args(["ul", "doctor", "--host", host])
            .current_dir(repo_root())
            .output()?;
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
    assert!(package.join("hooks/hooks.json").is_file());
    Ok(())
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
