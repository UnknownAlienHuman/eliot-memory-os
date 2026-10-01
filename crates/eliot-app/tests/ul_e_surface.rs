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
fn part_e_static_ul_doctor_is_retired_for_all_native_hosts() -> TestResult {
    // The static Part-E UL doctor is gone with no successor, and this test
    // asserts the retirement rather than a pass that cannot happen.
    //
    // The retirement is documented as complete and unconditional, not partial.
    // `crates/eliot-app/src/front_door_cutover.rs` (module doc, "Explicit
    // per-entrypoint disposition") states that "Every one of the 57 top-level
    // `Command` arms -- including ... read-only surfaces such as `mcp
    // catalog` -- is refused unconditionally at the `dispatch_command` entry
    // gate, with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the canonical-route
    // receipt. The arm label is preserved as identity/route evidence in the
    // detail. Refusing read-only surfaces too keeps the behavior one explicit
    // rule with no silent legacy invocation." `ul doctor` is such a read-only
    // surface, and the same module records that the operator flag
    // `ELIOT_CLAUDE_FRONT_DOOR` "is observed only as identity evidence in the
    // refusal detail; it never gates behavior" -- so no flag value restores
    // the arm. `docs/release/WINDOWS_X64_RELEASE.md` ("Claude Code front
    // door") states the same rule from the release side: "every non-stdio
    // entrypoint (`daemon run`, `service run`, `hook`, and the rest),
    // unconditionally refuse with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the
    // canonical-route receipt."
    //
    // There is no migrated owner for this surface, so nothing is being
    // repointed here.
    // `crates/eliot-app/src/disposition.rs::MIGRATED_CONSUMER_EDGES` has seven
    // rows -- Codex plugin MCP server, Claude Desktop MCPB server entry point,
    // Claude Code plugin MCP server, Codex plugin lifecycle hooks, Claude Code
    // plugin lifecycle hooks, OpenCode MCP server registration, and Codex
    // plugin install route -- and every one of them is a hook, MCP, or install
    // route edge. None of them owns a UL surface doctor, so the retired arm has
    // no current owner to assert against. The canonical binary's nearest
    // documented surface, `eliot doctor`
    // (`bins/eliot/src/main.rs::DoctorCommand`), has exactly two subcommands --
    // `Integration`, which compares an installed integration's expectation and
    // observation records, and `ReleaseSurface`, which compares an accepted
    // `ReleaseSurfaceManifest` (I19.8) -- and neither is a per-host Part-E
    // static source-tree check. Naming an owner here would be a product
    // decision, not a contract update, so the contract asserted is the
    // documented refusal.
    let installed = CodexInstalledPlugin::new()?;
    for host in ["codex", "claude", "antigravity", "opencode"] {
        // Every host is driven against a fully prepared environment
        // (marketplace, installed plugin, and system config fixtures), so the
        // refusal below cannot be explained by a missing fixture: the entry
        // gate refuses before any arm handler runs.
        //
        // All three flag states are asserted because the documented rule is
        // that no flag value restores the arm: unset, the selecting
        // `agent-bridge`, and the non-selecting `legacy`.
        for front_door in [None, Some("agent-bridge"), Some("legacy")] {
            ul_doctor_stdout(host, "codex_system_config.toml", &installed, front_door)?;
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
    // The Codex plugin MCP edge no longer launches the legacy
    // `bin/eliot-governor.exe mcp stdio --profile codex_controller --instance
    // default` route. `docs/release/WINDOWS_X64_RELEASE.md` states: "Its sole
    // MCP server is `eliot`, resolves `bin/eliot-agent-bridge.exe` relative to
    // the plugin root, and starts the `codex_controller` profile for every
    // project through `bins/eliot-agent-bridge` with the installation-owned
    // client declaration", and in the front-door paragraph that every
    // non-stdio entrypoint other than the delegated MCP edges "unconditionally
    // refuse[s] with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER` plus the
    // canonical-route receipt". The migrated edge is registered in
    // `crates/eliot-app/src/disposition.rs::MIGRATED_CONSUMER_EDGES` ("Codex
    // plugin MCP server"), whose `legacy_reference` `"command":
    // "bin/eliot-governor.exe"` must be absent from this artifact and whose
    // `current_owner_reference` is `"command": "bin/eliot-agent-bridge.exe"`.
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
            "--profile",
            "codex_controller",
            "--transport",
            "stdio",
            "--client-declaration",
            "${PLUGIN_ROOT}/bin/agent-bridge/client-declaration-v2.json"
        ]))
    );
    assert_eq!(
        mcp.pointer("/mcpServers/eliot/command")
            .and_then(Value::as_str),
        Some("bin/eliot-agent-bridge.exe")
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
        // Same retirement as the MCP route above, one edge over:
        // `crates/eliot-app/src/disposition.rs::MIGRATED_CONSUMER_EDGES` ("Codex
        // plugin lifecycle hooks") records the legacy hook argv
        // `"${PLUGIN_ROOT}\\bin\\eliot-governor.exe"` as `legacy_reference` (it
        // must be absent here) and the current-owner argv
        // `"${PLUGIN_ROOT}\\bin\\eliot-agent-bridge.exe\" hook` as
        // `current_owner_reference`, served by
        // `bins/eliot-agent-bridge/src/hook_intake.rs::run_hook_intake`.
        assert!(
            handler
                .get("command")
                .and_then(Value::as_str)
                .is_some_and(|command| command
                    .starts_with("\"${PLUGIN_ROOT}\\bin\\eliot-agent-bridge.exe\" hook "))
        );
        assert!(handler.get("args").is_none());
        assert!(handler.get("async").is_none());
    }
    Ok(())
}

#[test]
fn codex_doctor_evaluates_neither_legacy_direct_eliot_nor_other_mcp() -> TestResult {
    // The `--host codex` arm of the retired static UL doctor evaluated one
    // config fixture and rendered a verdict line per check. It no longer
    // evaluates anything, so the honest contract is that neither verdict is
    // served: not the `FIX codex no-direct-registration` a legacy direct
    // `eliot_surrealdb` registration used to produce, and not the
    // `PASS codex personal-marketplace` / `PASS codex installed-plugin` a
    // clean config used to produce.
    //
    // The retirement is documented as complete and unconditional. See the
    // citation block on
    // `part_e_static_ul_doctor_is_retired_for_all_native_hosts`: the entry
    // gate refuses every one of the 57 top-level `Command` arms,
    // read-only surfaces included, with `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`
    // plus the canonical-route receipt, and
    // `crates/eliot-app/src/front_door_cutover.rs` records that
    // `ELIOT_CLAUDE_FRONT_DOOR` "never gates behavior". No migrated consumer
    // edge in `crates/eliot-app/src/disposition.rs::MIGRATED_CONSUMER_EDGES`
    // owns this surface, so there is no successor to render either verdict.
    let installed = CodexInstalledPlugin::new()?;
    let config = "codex_legacy_direct_config.toml";
    // The fixture under test must actually carry the legacy direct
    // registration. Without this, "no direct-registration verdict is
    // rendered" would be true of any config and would assert nothing.
    let legacy = fs::read_to_string(fixture(config))?;
    assert!(
        legacy.contains("[mcp_servers.eliot_surrealdb]"),
        "{config} must carry the legacy direct ELIOT registration this test names"
    );
    for front_door in [None, Some("agent-bridge")] {
        let stdout = ul_doctor_stdout("codex", config, &installed, front_door)?;
        // No verdict line is served for any check, in either flag state.
        for absent in [
            "PASS codex personal-marketplace",
            "PASS codex installed-plugin",
            "PASS codex no-direct-registration",
            "FIX codex no-direct-registration",
        ] {
            assert!(!stdout.contains(absent), "{absent} is not served: {stdout}");
        }
    }
    Ok(())
}

/// Invokes the retired `eliot-governor ul doctor --host <host>` arm and
/// returns the refusal receipt it must emit on stdout.
///
/// `crates/eliot-app/src/front_door_cutover.rs::write_cutover_rejection` emits
/// the receipt as JSON on stdout with `status: "ERROR"`, the stable code
/// `LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER`, the `canonical_route` named by
/// `LEGACY_ENTRYPOINT_CANONICAL_ROUTE`, and `completed: false`, and the caller
/// aborts with a non-zero exit. The receipt is the whole documented contract
/// for this surface, so both the fields and the absence of any verdict line are
/// asserted.
fn ul_doctor_stdout(
    host: &str,
    config: &str,
    installed: &CodexInstalledPlugin,
    front_door: Option<&str>,
) -> TestResult<String> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_eliot-governor"));
    command
        .args(["ul", "doctor", "--host", host])
        .current_dir(repo_root())
        .env(
            "ELIOT_DOCTOR_CODEX_MARKETPLACE",
            fixture("codex_personal_marketplace.json"),
        )
        .env("ELIOT_DOCTOR_CODEX_PLUGIN", installed.root())
        .env("ELIOT_DOCTOR_CODEX_CONFIG", fixture(config));
    match front_door {
        Some(value) => command.env("ELIOT_CLAUDE_FRONT_DOOR", value),
        // Explicitly cleared, not merely absent, so an ambient value in the
        // caller's environment cannot decide the assertion.
        None => command.env_remove("ELIOT_CLAUDE_FRONT_DOOR"),
    };
    let output = command.output()?;
    assert!(
        !output.status.success(),
        "{host}: the retired ul doctor must refuse, but exited successfully: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stdout = String::from_utf8(output.stdout)?;
    let receipt: Value = serde_json::from_str(stdout.trim()).map_err(|error| {
        format!("{host}: refusal is not the cutover receipt: {stdout} ({error})")
    })?;
    assert_eq!(receipt.get("status").and_then(Value::as_str), Some("ERROR"));
    assert_eq!(
        receipt.get("code").and_then(Value::as_str),
        Some("LEGACY_GOVERNOR_FRONT_DOOR_CUTOVER")
    );
    // The refusal names the canonical route to retry through, so the receipt is
    // actionable rather than a bare rejection.
    let canonical_route = receipt
        .get("canonical_route")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{host}: receipt names no canonical_route: {stdout}"))?;
    assert!(
        canonical_route
            .starts_with("eliot setup through the Kernel canonical configuration surface"),
        "{host}: unexpected canonical_route: {canonical_route}"
    );
    assert_eq!(
        receipt.get("completed").and_then(Value::as_bool),
        Some(false)
    );
    // `front_door_cutover::gate_legacy_entrypoint` keeps the arm label as
    // identity/route evidence in the detail.
    let detail = receipt
        .get("detail")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{host}: receipt names no detail: {stdout}"))?;
    assert!(
        detail.contains("legacy eliot-governor ul is retired"),
        "{host}: detail does not name the retired arm: {detail}"
    );
    // A refusal that also rendered a verdict would mean the arm partially
    // served.
    assert!(
        !stdout.contains("PASS ") && !stdout.contains("FIX "),
        "{host}: the retired arm served a verdict: {stdout}"
    );
    Ok(stdout)
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
