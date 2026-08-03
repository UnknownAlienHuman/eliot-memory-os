use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const EXACT_SKILLS: [&str; 4] = [
    "eliot-work",
    "eliot-remember",
    "eliot-recover",
    "eliot-finish",
];

#[test]
fn part_e_static_doctor_passes_for_all_native_hosts() -> TestResult {
    let installed = CodexInstalledPlugin::new()?;
    for host in ["codex", "claude", "antigravity", "opencode"] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_eliot-governor"));
        command
            .args(["ul", "doctor", "--host", host])
            .current_dir(repo_root());
        if host == "codex" {
            command
                .env(
                    "ELIOT_DOCTOR_CODEX_MARKETPLACE",
                    fixture("codex_personal_marketplace.json"),
                )
                .env("ELIOT_DOCTOR_CODEX_PLUGIN", installed.root())
                .env(
                    "ELIOT_DOCTOR_CODEX_CONFIG",
                    fixture("codex_system_config.toml"),
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
            assert!(stdout.contains("PASS codex personal-marketplace"));
            assert!(stdout.contains("PASS codex installed-plugin"));
            assert!(stdout.contains("PASS codex no-direct-registration"));
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
fn codex_system_artifact_has_controller_mcp_and_default_policy() -> TestResult {
    let package = repo_root().join("plugin/eliot-governor");
    let marketplace: Value = serde_json::from_slice(&std::fs::read(
        repo_root().join("integrations/codex/marketplace.json"),
    )?)?;
    assert_eq!(
        marketplace.get("name").and_then(Value::as_str),
        Some("eliot-system")
    );
    assert_eq!(
        marketplace
            .pointer("/plugins/0/name")
            .and_then(Value::as_str),
        Some("eliot-governor")
    );
    assert_eq!(
        marketplace
            .pointer("/plugins/0/source/path")
            .and_then(Value::as_str),
        Some("./plugins/eliot-governor")
    );
    assert_eq!(
        marketplace
            .pointer("/plugins/0/policy/installation")
            .and_then(Value::as_str),
        Some("INSTALLED_BY_DEFAULT")
    );
    assert_eq!(
        marketplace
            .pointer("/plugins/0/policy/authentication")
            .and_then(Value::as_str),
        Some("ON_INSTALL")
    );
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
            "--profile",
            "codex_controller",
            "--instance",
            "default"
        ]))
    );
    assert_eq!(
        mcp.pointer("/mcpServers/eliot/command")
            .and_then(Value::as_str),
        Some("bin/eliot-governor.exe")
    );
    assert_eq!(
        mcp.pointer("/mcpServers/eliot/cwd").and_then(Value::as_str),
        Some(".")
    );
    assert_eq!(
        mcp.pointer("/mcpServers/eliot/enabled")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        mcp.pointer("/mcpServers/eliot/required")
            .and_then(Value::as_bool),
        Some(false)
    );
    let hooks: Value = serde_json::from_slice(&std::fs::read(package.join("hooks/hooks.json"))?)?;
    for event in [
        "SessionStart",
        "PreToolUse",
        "PostToolUse",
        "PreCompact",
        "PostCompact",
        "Stop",
    ] {
        let handler = hooks
            .pointer(&format!("/hooks/{event}/0/hooks/0"))
            .ok_or_else(|| format!("missing canonical {event} command hook"))?;
        assert!(
            handler
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|command| command
                    .starts_with("\"${PLUGIN_ROOT}\\bin\\eliot-governor.exe\" hook "))
        );
        assert!(handler.get("args").is_none());
        assert!(handler.get("async").is_none());
    }
    Ok(())
}

#[test]
fn codex_doctor_rejects_legacy_direct_eliot_but_accepts_other_mcp() -> TestResult {
    let installed = CodexInstalledPlugin::new()?;
    let output = Command::new(env!("CARGO_BIN_EXE_eliot-governor"))
        .args(["ul", "doctor", "--host", "codex"])
        .current_dir(repo_root())
        .env(
            "ELIOT_DOCTOR_CODEX_MARKETPLACE",
            fixture("codex_personal_marketplace.json"),
        )
        .env("ELIOT_DOCTOR_CODEX_PLUGIN", installed.root())
        .env(
            "ELIOT_DOCTOR_CODEX_CONFIG",
            fixture("codex_legacy_direct_config.toml"),
        )
        .output()?;
    assert!(!output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("PASS codex personal-marketplace"));
    assert!(stdout.contains("PASS codex installed-plugin"));
    assert!(stdout.contains("FIX codex no-direct-registration"));
    Ok(())
}

struct CodexInstalledPlugin {
    root: PathBuf,
}

impl CodexInstalledPlugin {
    fn new() -> TestResult<Self> {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let root = std::env::temp_dir().join(format!(
            "eliot-codex-installed-plugin-{}-{nonce}",
            std::process::id()
        ));
        let source = repo_root().join("plugin/eliot-governor");
        fs::create_dir_all(root.join(".codex-plugin"))?;
        fs::create_dir_all(root.join("hooks"))?;
        fs::create_dir_all(root.join("bin"))?;
        fs::copy(
            source.join(".codex-plugin/plugin.json"),
            root.join(".codex-plugin/plugin.json"),
        )?;
        fs::copy(
            source.join("hooks/hooks.json"),
            root.join("hooks/hooks.json"),
        )?;
        for skill in EXACT_SKILLS {
            let destination = root.join("skills").join(skill);
            fs::create_dir_all(&destination)?;
            fs::copy(
                source.join("skills").join(skill).join("SKILL.md"),
                destination.join("SKILL.md"),
            )?;
        }
        let executable = root.join("bin/eliot-governor.exe");
        fs::write(&executable, b"installed-governor-fixture")?;
        fs::write(
            root.join(".mcp.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "mcpServers": {
                    "eliot": {
                        "type": "stdio",
                        "command": "bin/eliot-governor.exe",
                        "cwd": ".",
                        "args": [
                            "mcp",
                            "stdio",
                            "--profile",
                            "codex_controller",
                            "--instance",
                            "default"
                        ],
                        "enabled": true,
                        "required": false
                    }
                }
            }))?,
        )?;
        Ok(Self { root })
    }

    fn root(&self) -> &Path {
        &self.root
    }
}

impl Drop for CodexInstalledPlugin {
    fn drop(&mut self) {
        if self.root.starts_with(std::env::temp_dir())
            && self
                .root
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("eliot-codex-installed-plugin-"))
        {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}

fn fixture(name: &str) -> PathBuf {
    repo_root()
        .join("crates/eliot-app/tests/fixtures")
        .join(name)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}
