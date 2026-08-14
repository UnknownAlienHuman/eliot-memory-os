//! Installing and removing ELIOT's host integrations.
//!
//! Both hosts get the same guarantee and need different mechanics to keep it:
//! ELIOT owns only the paths it wrote, records their hashes, and backs up
//! whatever it replaced, so uninstall can prove it is removing its own files
//! and not the user's. `OpenCode` needs a lossless JSONC merge because its config
//! is hand-edited and the comments have to survive; Claude gets a plain owned
//! directory. Install and uninstall share a file because the manifest they
//! agree on is the whole safety property.

use super::*;

const CODEX_PLUGIN_GOVERNOR: &str = "bin/eliot-governor.exe";

struct CodexOperationGuard {
    _file: File,
}

fn acquire_codex_operation_lock() -> Result<CodexOperationGuard> {
    let path = codex_operation_lock_path()?;
    std::fs::create_dir_all(
        path.parent()
            .context("Codex operation lock has no parent")?,
    )?;
    if path.exists() {
        ensure!(
            !std::fs::symlink_metadata(&path)?.file_type().is_symlink(),
            "Codex operation lock may not be a symlink: {}",
            path.display()
        );
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;

        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).share_mode(0);
        let file = options.open(&path).with_context(|| {
            format!(
                "acquire exclusive Codex install/uninstall lock {}; another operation may be active",
                path.display()
            )
        })?;
        ensure!(
            file.metadata()?.is_file(),
            "Codex operation lock is not a regular file: {}",
            path.display()
        );
        Ok(CodexOperationGuard { _file: file })
    }
    #[cfg(not(windows))]
    {
        bail!("Codex global integration locking is supported only on Windows")
    }
}

fn cleanup_codex_uninstall_tombstone(dry_run: bool) -> Result<bool> {
    let base = install_base()?;
    let tombstone = codex_uninstall_tombstone_path()?;
    ensure_child(&base, &tombstone)?;
    if !tombstone.exists() {
        return Ok(false);
    }
    ensure!(
        !dry_run,
        "an interrupted Codex uninstall requires tombstone cleanup; rerun without --dry-run"
    );
    let metadata = std::fs::symlink_metadata(&tombstone)?;
    ensure!(
        !metadata.file_type().is_symlink() && metadata.is_dir(),
        "Codex uninstall tombstone must be an owned regular directory: {}",
        tombstone.display()
    );
    std::fs::remove_dir_all(&tombstone)?;
    Ok(true)
}

#[allow(clippy::too_many_lines)]
pub(super) fn install(
    config_path: &Path,
    host: AgentHostId,
    dry_run: bool,
) -> Result<HostIntegrationReceipt> {
    ensure_installable_host(host)?;
    let repo = repo_root(config_path);
    let source = bundle_root(&repo, host);
    let base = install_base()?;
    let target = base.join(host.as_str());
    let _codex_lock = (host == AgentHostId::Codex)
        .then(acquire_codex_operation_lock)
        .transpose()?;
    let recovered_codex_owned_lifecycle = if host == AgentHostId::Codex {
        cleanup_codex_uninstall_tombstone(dry_run)?;
        recover_codex_install_transaction(&target, dry_run)?
    } else {
        false
    };
    let staging = base.join(format!(".{}-{}-staging", host.as_str(), Uuid::new_v4()));
    let source_hash = bundle_hash(&source, host)?;
    let governor = std::env::current_exe().context("resolve Eliot integration executable")?;
    let governor_hash = bundle_hash_single(&governor)?;
    let installed_governor = target.join("bin").join("eliot-governor.exe");
    let before_hash = target
        .is_dir()
        .then(|| bundle_hash(&target, host))
        .transpose()?;
    let before_governor_hash = installed_governor
        .is_file()
        .then(|| bundle_hash_single(&installed_governor))
        .transpose()?;
    let previous_global = (host == AgentHostId::OpenCode)
        .then(|| read_opencode_global_manifest(&target))
        .transpose()?
        .flatten();
    let previous_claude_global = (host == AgentHostId::Claude)
        .then(|| read_claude_global_manifest(&target))
        .transpose()?
        .flatten();
    let previous_codex_global = (host == AgentHostId::Codex)
        .then(|| read_codex_global_manifest(&target))
        .transpose()?
        .flatten();
    let mut backup_refs = Vec::new();
    let mut modified_files = Vec::new();
    let needs_bundle_update = before_hash.as_deref() != Some(source_hash.as_str())
        || before_governor_hash.as_deref() != Some(governor_hash.as_str());
    if host != AgentHostId::Codex && !dry_run && needs_bundle_update {
        std::fs::create_dir_all(&base)?;
        copy_tree(&source, &staging, host)?;
        std::fs::create_dir_all(staging.join("bin"))?;
        std::fs::copy(&governor, staging.join("bin").join("eliot-governor.exe"))?;
        if target.exists() {
            let backup = base.join(format!(
                ".{}-{}-backup",
                host.as_str(),
                OffsetDateTime::now_utc().unix_timestamp()
            ));
            std::fs::rename(&target, &backup)?;
            backup_refs.push(backup.to_string_lossy().into_owned());
        }
        std::fs::rename(&staging, &target)?;
        modified_files.push(target.to_string_lossy().into_owned());
    }
    let mut installed_paths = vec![target.to_string_lossy().into_owned()];
    if host == AgentHostId::OpenCode {
        let global = install_opencode_global(
            &source,
            &target,
            &governor,
            previous_global.as_ref(),
            dry_run,
        )?;
        installed_paths.extend(global.installed_paths);
        modified_files.extend(global.modified_files);
        backup_refs.extend(global.backup_refs);
    } else if host == AgentHostId::Claude {
        let global = install_claude_global(
            &repo,
            &source,
            &target,
            &governor,
            previous_claude_global.as_ref(),
            dry_run,
        )?;
        installed_paths.extend(global.installed_paths);
        modified_files.extend(global.modified_files);
        backup_refs.extend(global.backup_refs);
    } else if host == AgentHostId::Codex {
        let global = install_codex_global(
            config_path,
            &source,
            &target,
            &governor,
            previous_codex_global.as_ref(),
            recovered_codex_owned_lifecycle,
            dry_run,
        )?;
        installed_paths.extend(global.installed_paths);
        modified_files.extend(global.modified_files);
        backup_refs.extend(global.backup_refs);
    }
    let host_version = if host == AgentHostId::Codex {
        HostProfileService.probe(host).map_or_else(
            |_| "codex-personal-marketplace".to_owned(),
            |profile| profile.version,
        )
    } else {
        HostProfileService.probe(host)?.version
    };
    let skills = SkillPackService.lint(&repo)?;
    let (mcp, lifecycle) = integration_refs(&source, host);
    let mut after_hashes = vec![source_hash.clone(), governor_hash];
    if host == AgentHostId::Claude {
        after_hashes.push(format!("sha256:{}", sha256_file(&governor)?));
    }
    let receipt = HostIntegrationReceipt {
        receipt_id: format!("host-install:{}", Uuid::new_v4()),
        host_id: host,
        host_version,
        scope: match host {
            AgentHostId::OpenCode => "user-local Eliot bundle plus additive OpenCode global discovery; provider/auth and unrelated config preserved".to_owned(),
            AgentHostId::Claude => "user-local Eliot bundle packaged into a local marketplace and installed through the official Claude Code plugin lifecycle; provider/auth and unrelated settings preserved".to_owned(),
            AgentHostId::Codex => "user-global Codex personal-marketplace plugin with the controller MCP enabled by default; project config, provider/auth, and unrelated marketplace entries preserved".to_owned(),
            AgentHostId::Antigravity => {
                "user-local Eliot integration bundle; host auth/config untouched".to_owned()
            }
        },
        installed_paths,
        modified_files,
        before_hashes: before_hash
            .into_iter()
            .chain(before_governor_hash)
            .collect(),
        after_hashes,
        backup_refs,
        integration_bundle_hash: source_hash,
        skill_pack_hash: skills.pack_hash,
        mcp_config_hash: bundle_hash_single(&mcp)?,
        lifecycle_bridge_hash: bundle_hash_single(&lifecycle)?,
        rollback_command: format!(
            "\"{}\" host uninstall --host {}",
            std::env::current_exe()?.display(),
            host.as_str()
        ),
        verified_at: OffsetDateTime::now_utc(),
    };
    if !dry_run {
        atomic_write_json(&install_receipt_path(config_path, host), &receipt)?;
    }
    Ok(receipt)
}

pub(super) fn read_opencode_global_manifest(
    target: &Path,
) -> Result<Option<OpenCodeGlobalInstallManifest>> {
    let path = target.join(OPENCODE_GLOBAL_MANIFEST);
    if !path.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?))
}

pub(super) fn read_claude_global_manifest(
    target: &Path,
) -> Result<Option<ClaudeGlobalInstallManifest>> {
    let current = target.join(CLAUDE_GLOBAL_MANIFEST);
    let path = if current.is_file() {
        current
    } else {
        target.join(CLAUDE_LEGACY_GLOBAL_MANIFEST)
    };
    if path.is_file() {
        return Ok(Some(serde_json::from_reader(std::fs::File::open(path)?)?));
    }
    // A host install swaps the versioned bundle before invoking the provider's
    // lifecycle. If that lifecycle fails, the previous ownership manifest is
    // still in the exact backup made by the swap and is required for a safe
    // retry (especially to retire the old skills-dir plugin). Recover only the
    // newest ELIOT-created Claude backup beside this target.
    let Some(parent) = target.parent() else {
        return Ok(None);
    };
    let mut backups = std::fs::read_dir(parent)?
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".claude-") && name.ends_with("-backup"))
        })
        .filter_map(|entry| {
            let manifest = entry.path().join(CLAUDE_GLOBAL_MANIFEST);
            manifest.is_file().then(|| {
                let modified = entry
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .ok();
                (modified, manifest)
            })
        })
        .collect::<Vec<_>>();
    backups.sort_by_key(|entry| entry.0);
    let Some((_, recovered)) = backups.pop() else {
        return Ok(None);
    };
    Ok(Some(serde_json::from_reader(std::fs::File::open(
        recovered,
    )?)?))
}

pub(super) fn read_codex_global_manifest(
    target: &Path,
) -> Result<Option<CodexGlobalInstallManifest>> {
    let current = target.join(CODEX_GLOBAL_MANIFEST);
    if !current.is_file() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_reader(std::fs::File::open(
        current,
    )?)?))
}

pub(super) struct CodexMarketplaceMerge {
    pub(super) value: Value,
    pub(super) bytes: Vec<u8>,
    pub(super) plugins_field_existed_before: bool,
    pub(super) entry_before: Option<Value>,
    pub(super) entry_before_index: Option<usize>,
    pub(super) continuing_owned: bool,
}

pub(super) fn codex_marketplace_entry() -> Value {
    json!({
        "name": CODEX_PLUGIN_NAME,
        "source": {
            "source": "local",
            "path": "./plugins/eliot-governor"
        },
        "policy": {
            "installation": "INSTALLED_BY_DEFAULT",
            "authentication": "ON_INSTALL"
        },
        "category": "Developer Tools"
    })
}

fn default_codex_marketplace() -> Value {
    json!({
        "name": CODEX_MARKETPLACE_NAME,
        "interface": { "displayName": "Personal" },
        "plugins": []
    })
}

fn codex_plugin_indices(plugins: &[Value]) -> Vec<usize> {
    plugins
        .iter()
        .enumerate()
        .filter_map(|(index, entry)| {
            (entry.get("name").and_then(Value::as_str) == Some(CODEX_PLUGIN_NAME)).then_some(index)
        })
        .collect()
}

pub(super) fn merge_codex_marketplace(
    existing: Option<&[u8]>,
    previous: Option<&CodexGlobalInstallManifest>,
) -> Result<CodexMarketplaceMerge> {
    let mut value = existing.map_or_else(
        || Ok(default_codex_marketplace()),
        |bytes| serde_json::from_slice(bytes).context("parse Codex personal marketplace"),
    )?;
    let root = value
        .as_object_mut()
        .context("Codex personal marketplace root must be an object")?;
    let plugins_field_existed_before = root.contains_key("plugins");
    if !plugins_field_existed_before {
        root.insert("plugins".to_owned(), Value::Array(Vec::new()));
    }
    let plugins = root
        .get_mut("plugins")
        .and_then(Value::as_array_mut)
        .context("Codex personal marketplace plugins must be an array")?;
    let indices = codex_plugin_indices(plugins);
    ensure!(
        indices.len() <= 1,
        "Codex personal marketplace contains duplicate {CODEX_PLUGIN_NAME} entries"
    );
    let current_index = indices.first().copied();
    let current_entry = current_index.map(|index| plugins[index].clone());
    let continuing_owned = previous
        .is_some_and(|manifest| current_entry.as_ref() == Some(&manifest.marketplace_entry_after));
    let (entry_before, entry_before_index, original_plugins_field) = if continuing_owned {
        let manifest = previous.context("continuing Codex ownership requires a manifest")?;
        (
            manifest.marketplace_entry_before.clone(),
            manifest.marketplace_entry_before_index,
            manifest.marketplace_plugins_field_existed_before,
        )
    } else {
        (current_entry, current_index, plugins_field_existed_before)
    };
    let entry_after = codex_marketplace_entry();
    if let Some(index) = current_index {
        plugins[index] = entry_after;
    } else {
        plugins.push(entry_after);
    }
    let bytes = serde_json::to_vec_pretty(&value)?;
    Ok(CodexMarketplaceMerge {
        value,
        bytes,
        plugins_field_existed_before: original_plugins_field,
        entry_before,
        entry_before_index,
        continuing_owned,
    })
}

pub(super) fn remove_codex_marketplace_entry(
    mut value: Value,
    expected_entry: &Value,
    entry_before: Option<&Value>,
    entry_before_index: Option<usize>,
    plugins_field_existed_before: bool,
) -> Result<Value> {
    let root = value
        .as_object_mut()
        .context("Codex personal marketplace root must be an object")?;
    let plugins = root
        .get_mut("plugins")
        .and_then(Value::as_array_mut)
        .context("Codex personal marketplace plugins must be an array")?;
    let indices = codex_plugin_indices(plugins);
    ensure!(
        indices.len() == 1,
        "Codex personal marketplace must contain exactly one owned {CODEX_PLUGIN_NAME} entry"
    );
    let current_index = indices[0];
    ensure!(
        &plugins[current_index] == expected_entry,
        "Codex personal marketplace {CODEX_PLUGIN_NAME} entry changed after install; refusing to overwrite it"
    );
    plugins.remove(current_index);
    if let Some(entry) = entry_before {
        let index = entry_before_index
            .unwrap_or(plugins.len())
            .min(plugins.len());
        plugins.insert(index, entry.clone());
    }
    if !plugins_field_existed_before && plugins.is_empty() {
        root.remove("plugins");
    }
    Ok(value)
}

pub(super) fn materialize_codex_mcp_config(config: &mut Value, _governor: &Path) -> Result<()> {
    let server = config
        .get_mut("mcpServers")
        .and_then(Value::as_object_mut)
        .and_then(|servers| servers.get_mut("eliot"))
        .and_then(Value::as_object_mut)
        .context("Codex plugin .mcp.json must define mcpServers.eliot")?;
    server.insert("type".to_owned(), Value::String("stdio".to_owned()));
    server.insert(
        "command".to_owned(),
        Value::String(CODEX_PLUGIN_GOVERNOR.to_owned()),
    );
    server.insert(
        "args".to_owned(),
        json!([
            "mcp",
            "stdio",
            "--profile",
            "codex_controller",
            "--instance",
            "default"
        ]),
    );
    server.insert("cwd".to_owned(), Value::String(".".to_owned()));
    server.insert("enabled".to_owned(), Value::Bool(true));
    server.insert("required".to_owned(), Value::Bool(false));
    Ok(())
}

pub(super) fn validate_codex_hook_commands(hooks: &Value) -> Result<usize> {
    fn visit(value: &Value) -> Result<usize> {
        match value {
            Value::Object(object) => {
                let mut validated = 0;
                if object.get("type").and_then(Value::as_str) == Some("command") {
                    let command = object
                        .get("command")
                        .and_then(Value::as_str)
                        .context("Codex command hook has no command string")?;
                    ensure!(
                        command.starts_with("\"${PLUGIN_ROOT}\\bin\\eliot-governor.exe\" hook ")
                            && !command.ends_with(" hook "),
                        "Codex hook must invoke the bundled Governor through PLUGIN_ROOT"
                    );
                    ensure!(
                        !object.contains_key("args") && !object.contains_key("async"),
                        "Codex command hooks use one command string and may not use unsupported args/async fields"
                    );
                    validated = 1;
                }
                object
                    .values()
                    .try_fold(validated, |count, child| Ok(count + visit(child)?))
            }
            Value::Array(values) => values
                .iter()
                .try_fold(0, |count, child| Ok(count + visit(child)?)),
            _ => Ok(0),
        }
    }

    let validated = visit(hooks)?;
    ensure!(
        validated > 0,
        "Codex plugin hooks.json contains no command hooks"
    );
    Ok(validated)
}

fn codex_cli_json(codex: &Path, args: &[&str]) -> Result<Value> {
    let output = StdCommand::new(codex)
        .args(args)
        .output()
        .with_context(|| format!("run {} {}", codex.display(), args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Codex CLI command failed ({}): {}",
            args.join(" "),
            stderr.trim()
        );
    }
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("parse Codex CLI JSON for {}", args.join(" ")))
}

fn codex_mcp_get(codex: &Path, name: &str) -> Result<Option<Value>> {
    let output = StdCommand::new(codex)
        .args(["mcp", "get", name, "--json"])
        .output()
        .with_context(|| format!("inspect Codex MCP registration {name}"))?;
    if output.status.success() {
        let value: Value = serde_json::from_slice(&output.stdout)
            .with_context(|| format!("parse Codex MCP registration {name}"))?;
        ensure!(
            value.get("name").and_then(Value::as_str) == Some(name),
            "Codex CLI returned the wrong MCP identity while inspecting {name}"
        );
        return Ok(Some(value));
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains(&format!("No MCP server named '{name}' found")) {
        return Ok(None);
    }
    bail!(
        "Codex CLI could not inspect MCP registration {name}: {}",
        stderr.trim()
    )
}

pub(super) struct CodexLegacyMcpApproval {
    pub(super) governor_paths: Vec<PathBuf>,
    pub(super) governor_packages_root: PathBuf,
    pub(super) surreal_executable: PathBuf,
    pub(super) surreal_namespace: String,
    pub(super) surreal_database: String,
    pub(super) surreal_storage: String,
}

fn codex_stdio_transport_is_plain(transport: &Value) -> bool {
    transport.get("type").and_then(Value::as_str) == Some("stdio")
        && transport.get("env").is_none_or(|value| {
            value.is_null() || value.as_object().is_some_and(serde_json::Map::is_empty)
        })
        && transport
            .get("env_vars")
            .is_none_or(|value| value.as_array().is_some_and(Vec::is_empty))
        && transport.get("cwd").is_none_or(Value::is_null)
}

fn path_is_within(path: &Path, root: &Path) -> bool {
    let path = path_identity(path);
    let root = path_identity(root);
    path == root || path.starts_with(&format!("{root}\\"))
}

pub(super) fn codex_legacy_mcp_is_owned(
    name: &str,
    value: &Value,
    approval: &CodexLegacyMcpApproval,
) -> bool {
    let Some(transport) = value.get("transport") else {
        return false;
    };
    if value.get("name").and_then(Value::as_str) != Some(name)
        || !codex_stdio_transport_is_plain(transport)
    {
        return false;
    }
    let Some(command) = transport.get("command").and_then(Value::as_str) else {
        return false;
    };
    let command = Path::new(command);
    let Some(args) = transport
        .get("args")
        .and_then(Value::as_array)
        .and_then(|args| args.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
    else {
        return false;
    };
    match name {
        "eliot-governor" => {
            let exact_args =
                args == [
                    "mcp",
                    "stdio",
                    "--profile",
                    "codex_controller",
                    "--instance",
                    "default",
                ] || args
                    == [
                        "mcp",
                        "stdio",
                        "--host",
                        "codex",
                        "--profile",
                        "codex_worker",
                        "--instance",
                        "default",
                    ];
            let approved_path = approval
                .governor_paths
                .iter()
                .any(|approved| path_identity(command) == path_identity(approved))
                || path_is_within(command, &approval.governor_packages_root);
            exact_args
                && approved_path
                && command
                    .file_name()
                    .and_then(|file| file.to_str())
                    .is_some_and(|file| file.eq_ignore_ascii_case("eliot-governor.exe"))
        }
        "eliot_surrealdb" => {
            args == [
                "mcp",
                "--ns",
                approval.surreal_namespace.as_str(),
                "--db",
                approval.surreal_database.as_str(),
                approval.surreal_storage.as_str(),
            ] && path_identity(command) == path_identity(&approval.surreal_executable)
        }
        _ => false,
    }
}

fn inspect_codex_legacy_direct_mcp(
    codex: &Path,
    approval: &CodexLegacyMcpApproval,
) -> Result<Vec<CodexLegacyMcpRegistration>> {
    let mut found = Vec::new();
    for name in ["eliot-governor", "eliot_surrealdb"] {
        let Some(value) = codex_mcp_get(codex, name)? else {
            continue;
        };
        let command = value
            .pointer("/transport/command")
            .and_then(Value::as_str)
            .map(Path::new)
            .context("Codex MCP registration has no command path")?;
        ensure!(
            command.is_absolute()
                && command.is_file()
                && !std::fs::symlink_metadata(command)?.file_type().is_symlink(),
            "Codex MCP registration {name} does not resolve to an approved regular executable"
        );
        ensure!(
            codex_legacy_mcp_is_owned(name, &value, approval),
            "Codex MCP registration {name} conflicts with ELIOT's reserved identity but does not match a known ELIOT command; refusing migration"
        );
        let exact_config_hash = bytes_hash(&serde_json::to_vec(&value)?);
        found.push(CodexLegacyMcpRegistration {
            name: name.to_owned(),
            exact_config: value,
            exact_config_hash,
        });
    }
    Ok(found)
}

fn remove_codex_legacy_direct_mcp(
    codex: &Path,
    registration: &CodexLegacyMcpRegistration,
) -> Result<()> {
    let name = &registration.name;
    if let Some(current) = codex_mcp_get(codex, name)? {
        ensure!(
            bytes_hash(&serde_json::to_vec(&current)?) == registration.exact_config_hash
                && current == registration.exact_config,
            "Codex MCP registration {name} changed after inspection; refusing removal"
        );
        let output = StdCommand::new(codex)
            .args(["mcp", "remove", name])
            .output()
            .with_context(|| format!("remove legacy Codex MCP registration {name}"))?;
        ensure!(
            output.status.success(),
            "Codex CLI could not remove legacy MCP registration {name}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        ensure!(
            codex_mcp_get(codex, name)?.is_none(),
            "Codex CLI reported success but legacy MCP registration {name} is still present"
        );
    }
    Ok(())
}

pub(super) fn codex_plugin_installed_enabled(list: &Value, selector: &str) -> Option<(bool, bool)> {
    list.get("installed")
        .and_then(Value::as_array)
        .and_then(|plugins| {
            plugins.iter().find_map(|plugin| {
                (plugin.get("pluginId").and_then(Value::as_str) == Some(selector)).then(|| {
                    (
                        plugin
                            .get("installed")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                        plugin
                            .get("enabled")
                            .and_then(Value::as_bool)
                            .unwrap_or(false),
                    )
                })
            })
        })
}

pub(super) fn codex_effective_plugin_installed_before(
    historical_preinstalled: Option<bool>,
    current_state: Option<(bool, bool)>,
) -> bool {
    match historical_preinstalled {
        Some(true) | None => current_state.is_some_and(|(installed, _)| installed),
        Some(false) => false,
    }
}

fn codex_plugin_list(codex: &Path) -> Result<Value> {
    codex_cli_json(codex, &["plugin", "list", "--json"])
}

struct CodexPluginExpectation<'a> {
    selector: &'a str,
    version: &'a str,
    source_path: &'a Path,
    cache_contract_hash: &'a str,
    installed_governor: &'a Path,
    installed_governor_sha256: &'a str,
}

fn codex_plugin_entry<'a>(list: &'a Value, selector: &str) -> Option<&'a Value> {
    list.get("installed")
        .and_then(Value::as_array)
        .and_then(|plugins| {
            plugins
                .iter()
                .find(|plugin| plugin.get("pluginId").and_then(Value::as_str) == Some(selector))
        })
}

fn codex_plugin_entry_has_owned_identity(
    entry: &Value,
    selector: &str,
    source_path: &Path,
) -> bool {
    entry.get("pluginId").and_then(Value::as_str) == Some(selector)
        && entry.get("name").and_then(Value::as_str) == Some(CODEX_PLUGIN_NAME)
        && entry.get("marketplaceName").and_then(Value::as_str) == Some(CODEX_MARKETPLACE_NAME)
        && entry.get("installed").and_then(Value::as_bool) == Some(true)
        && entry.pointer("/source/source").and_then(Value::as_str) == Some("local")
        && entry
            .pointer("/source/path")
            .and_then(Value::as_str)
            .is_some_and(|path| path_identity(Path::new(path)) == path_identity(source_path))
}

pub(super) fn codex_plugin_metadata_matches(
    entry: &Value,
    selector: &str,
    version: &str,
    source_path: &Path,
) -> bool {
    codex_plugin_entry_has_owned_identity(entry, selector, source_path)
        && entry.get("version").and_then(Value::as_str) == Some(version)
}

pub(super) fn codex_runtime_cache_path(registration: &Value, home: &Path) -> Option<PathBuf> {
    if registration.get("name").and_then(Value::as_str) != Some("eliot")
        || registration.get("enabled").and_then(Value::as_bool) != Some(true)
    {
        return None;
    }
    let transport = registration.get("transport")?;
    let command = PathBuf::from(transport.get("command").and_then(Value::as_str)?);
    let cwd = PathBuf::from(transport.get("cwd").and_then(Value::as_str)?);
    let resolved_command = if command.is_absolute() {
        command
    } else {
        cwd.join(command)
    };
    let cached_governor = cwd.join(CODEX_PLUGIN_GOVERNOR);
    let approved_cache_root = home
        .join(".codex")
        .join("plugins")
        .join("cache")
        .join(CODEX_MARKETPLACE_NAME)
        .join(CODEX_PLUGIN_NAME);
    (transport.get("type").and_then(Value::as_str) == Some("stdio")
        && path_identity(&resolved_command) == path_identity(&cached_governor)
        && transport.get("args")
            == Some(&json!([
                "mcp",
                "stdio",
                "--profile",
                "codex_controller",
                "--instance",
                "default"
            ]))
        && transport.get("env") == Some(&Value::Null)
        && transport.get("env_vars") == Some(&json!([]))
        && cwd.is_absolute()
        && path_is_within(&cwd, &approved_cache_root)
        && path_identity(&cwd) != path_identity(&approved_cache_root))
    .then_some(cwd)
}

fn codex_cached_plugin_payload_is_fresh(
    cache_path: &Path,
    expected: &CodexPluginExpectation<'_>,
) -> Result<bool> {
    if !cache_path.is_dir()
        || std::fs::symlink_metadata(cache_path)?
            .file_type()
            .is_symlink()
    {
        return Ok(false);
    }
    if codex_cache_contract_hash(cache_path)? != expected.cache_contract_hash {
        return Ok(false);
    }
    let manifest: Value = serde_json::from_reader(std::fs::File::open(
        cache_path.join(".codex-plugin").join("plugin.json"),
    )?)?;
    if manifest.get("name").and_then(Value::as_str) != Some(CODEX_PLUGIN_NAME)
        || manifest.get("version").and_then(Value::as_str) != Some(expected.version)
    {
        return Ok(false);
    }
    let mcp: Value = serde_json::from_reader(std::fs::File::open(cache_path.join(".mcp.json"))?)?;
    let command_matches = mcp
        .pointer("/mcpServers/eliot/command")
        .and_then(Value::as_str)
        .is_some_and(|command| {
            command
                .replace('\\', "/")
                .eq_ignore_ascii_case(CODEX_PLUGIN_GOVERNOR)
        });
    let args_match = mcp.pointer("/mcpServers/eliot/args")
        == Some(&json!([
            "mcp",
            "stdio",
            "--profile",
            "codex_controller",
            "--instance",
            "default"
        ]));
    let cached_cwd_matches =
        mcp.pointer("/mcpServers/eliot/cwd").and_then(Value::as_str) == Some(".");
    let cached_transport_matches = mcp
        .pointer("/mcpServers/eliot/type")
        .and_then(Value::as_str)
        == Some("stdio")
        && mcp
            .pointer("/mcpServers/eliot/enabled")
            .and_then(Value::as_bool)
            == Some(true)
        && mcp
            .pointer("/mcpServers/eliot/required")
            .and_then(Value::as_bool)
            == Some(false);
    let cached_governor = cache_path.join(CODEX_PLUGIN_GOVERNOR);
    Ok(command_matches
        && args_match
        && cached_cwd_matches
        && cached_transport_matches
        && expected.installed_governor.is_file()
        && sha256_file(expected.installed_governor)? == expected.installed_governor_sha256
        && cached_governor.is_file()
        && sha256_file(&cached_governor)? == expected.installed_governor_sha256)
}

fn codex_plugin_lifecycle_is_fresh(
    codex: &Path,
    list: &Value,
    expected: &CodexPluginExpectation<'_>,
) -> Result<bool> {
    let Some(entry) = codex_plugin_entry(list, expected.selector) else {
        return Ok(false);
    };
    if entry.get("enabled").and_then(Value::as_bool) != Some(true)
        || !codex_plugin_metadata_matches(
            entry,
            expected.selector,
            expected.version,
            expected.source_path,
        )
    {
        return Ok(false);
    }
    let Some(runtime) = codex_mcp_get(codex, "eliot")? else {
        return Ok(false);
    };
    let Some(cache_path) = codex_runtime_cache_path(&runtime, &user_home()?) else {
        return Ok(false);
    };
    codex_cached_plugin_payload_is_fresh(&cache_path, expected)
}

fn codex_cache_path_for_version(version: &str) -> Result<PathBuf> {
    ensure!(
        !version.is_empty()
            && version != "."
            && version != ".."
            && !version.contains('/')
            && !version.contains('\\')
            && !version.contains(':'),
        "Codex plugin version is not a safe cache path component: {version}"
    );
    Ok(user_home()?
        .join(".codex")
        .join("plugins")
        .join("cache")
        .join(CODEX_MARKETPLACE_NAME)
        .join(CODEX_PLUGIN_NAME)
        .join(version))
}

fn reconcile_codex_cache_in_place(expected: &CodexPluginExpectation<'_>) -> Result<()> {
    let cache_path = codex_cache_path_for_version(expected.version)?;
    let cache_root = user_home()?
        .join(".codex")
        .join("plugins")
        .join("cache")
        .join(CODEX_MARKETPLACE_NAME)
        .join(CODEX_PLUGIN_NAME);
    ensure_child(&cache_root, &cache_path)?;
    ensure!(
        expected.source_path.is_dir(),
        "Codex plugin source is missing during cache reconciliation: {}",
        expected.source_path.display()
    );
    if cache_path.exists() {
        let metadata = std::fs::symlink_metadata(&cache_path)?;
        ensure!(
            metadata.is_dir() && !metadata.file_type().is_symlink(),
            "Codex plugin cache must be an owned regular directory: {}",
            cache_path.display()
        );
    } else {
        std::fs::create_dir_all(&cache_path)?;
    }

    reconcile_codex_cache_tree(
        expected.source_path,
        &cache_path,
        expected.cache_contract_hash,
    )
}

pub(super) fn reconcile_codex_cache_tree(
    source_path: &Path,
    cache_path: &Path,
    expected_cache_contract_hash: &str,
) -> Result<()> {
    let mut source_files = Vec::new();
    collect_owned_files(source_path, source_path, &mut source_files)?;
    let mut cached_files = Vec::new();
    collect_owned_files(cache_path, cache_path, &mut cached_files)?;
    for (relative, source_file) in &source_files {
        let destination = cache_path.join(Path::new(&relative));
        ensure_child(cache_path, &destination)?;
        std::fs::create_dir_all(
            destination
                .parent()
                .context("Codex cache file has no parent")?,
        )?;
        if relative.eq_ignore_ascii_case(CODEX_PLUGIN_GOVERNOR) && destination.is_file() {
            ensure!(
                sha256_file(source_file)? == sha256_file(&destination)?,
                "Codex cached Governor differs from its content-addressed source artifact"
            );
            continue;
        }
        std::fs::copy(source_file, &destination).with_context(|| {
            format!(
                "reconcile Codex cache file {} -> {}",
                source_file.display(),
                destination.display()
            )
        })?;
    }
    for (relative, cached) in cached_files {
        if !source_files
            .iter()
            .any(|(source_relative, _)| source_relative.eq_ignore_ascii_case(&relative))
        {
            std::fs::remove_file(&cached)
                .with_context(|| format!("remove stale Codex cache file {}", cached.display()))?;
        }
    }
    ensure!(
        codex_cache_contract_hash(cache_path)? == expected_cache_contract_hash,
        "Codex plugin cache reconciliation did not produce the expected content contract"
    );
    Ok(())
}

fn install_codex_plugin_lifecycle(
    codex: &Path,
    expected: &CodexPluginExpectation<'_>,
    may_refresh_owned: bool,
    force_refresh_owned: bool,
) -> Result<()> {
    let list = codex_plugin_list(codex)?;
    if !force_refresh_owned && codex_plugin_lifecycle_is_fresh(codex, &list, expected)? {
        return Ok(());
    }
    if let Some(entry) = codex_plugin_entry(&list, expected.selector) {
        ensure!(
            may_refresh_owned
                && codex_plugin_entry_has_owned_identity(
                    entry,
                    expected.selector,
                    expected.source_path,
                ),
            "Codex plugin {} already exists but its version/source/cache is not the desired ELIOT artifact",
            expected.selector
        );
        if entry.get("version").and_then(Value::as_str) == Some(expected.version)
            && entry.get("enabled").and_then(Value::as_bool) == Some(true)
        {
            reconcile_codex_cache_in_place(expected)?;
        } else {
            let _ = codex_cli_json(codex, &["plugin", "add", expected.selector, "--json"])?;
        }
    } else {
        let _ = codex_cli_json(codex, &["plugin", "add", expected.selector, "--json"])?;
    }
    ensure!(
        codex_plugin_lifecycle_is_fresh(codex, &codex_plugin_list(codex)?, expected)?,
        "Codex plugin lifecycle did not install the expected fresh artifact for {}",
        expected.selector
    );
    Ok(())
}

fn remove_codex_plugin_lifecycle(codex: &Path, selector: &str) -> Result<()> {
    if codex_plugin_installed_enabled(&codex_plugin_list(codex)?, selector).is_some() {
        let _ = codex_cli_json(codex, &["plugin", "remove", selector, "--json"])?;
    }
    ensure!(
        codex_plugin_installed_enabled(&codex_plugin_list(codex)?, selector).is_none(),
        "Codex plugin lifecycle still reports {selector} installed after removal"
    );
    Ok(())
}

fn create_codex_install_journal(journal: &CodexInstallJournal) -> Result<()> {
    let path = codex_install_journal_path()?;
    ensure!(
        !path.exists(),
        "another Codex install transaction is active at {}",
        path.display()
    );
    std::fs::create_dir_all(path.parent().context("Codex journal has no parent")?)?;
    let bytes = serde_json::to_vec_pretty(journal)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("create exclusive Codex install journal {}", path.display()))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

fn persist_codex_owned_lifecycle_recovery(journal: &CodexInstallJournal) -> Result<()> {
    let mut owned_versions = Vec::new();
    if let Some(version) = &journal.plugin_lifecycle_version_before {
        owned_versions.push(version.clone());
    }
    if !owned_versions.contains(&journal.plugin_version) {
        owned_versions.push(journal.plugin_version.clone());
    }
    ensure!(
        !owned_versions.is_empty(),
        "Codex owned lifecycle recovery requires at least one version"
    );
    atomic_write_json(
        &codex_owned_lifecycle_recovery_path()?,
        &CodexOwnedLifecycleRecovery {
            schema_version: CODEX_OWNED_LIFECYCLE_RECOVERY_SCHEMA_V1.to_owned(),
            transaction_id: journal.transaction_id.clone(),
            plugin_selector: journal.plugin_selector.clone(),
            plugin_path: journal.plugin_path.clone(),
            codex_cli_path: journal.codex_cli_path.clone(),
            owned_versions,
            created_at: OffsetDateTime::now_utc().to_string(),
        },
    )
}

fn codex_owned_lifecycle_recovery_is_valid() -> Result<bool> {
    let path = codex_owned_lifecycle_recovery_path()?;
    if !path.exists() {
        return Ok(false);
    }
    let metadata = std::fs::symlink_metadata(&path)?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "Codex owned lifecycle recovery marker must be a regular file"
    );
    let marker: CodexOwnedLifecycleRecovery = serde_json::from_reader(std::fs::File::open(&path)?)?;
    ensure!(
        marker.schema_version == CODEX_OWNED_LIFECYCLE_RECOVERY_SCHEMA_V1
            && !marker.transaction_id.is_empty()
            && marker.plugin_selector == format!("{CODEX_PLUGIN_NAME}@{CODEX_MARKETPLACE_NAME}")
            && marker.plugin_path == codex_plugin_root()?
            && path_identity(&marker.codex_cli_path)
                == path_identity(
                    &crate::dogfood::find_codex_cli()
                        .context("locate installed Codex CLI for lifecycle recovery")?,
                )
            && !marker.owned_versions.is_empty(),
        "Codex owned lifecycle recovery marker has an unexpected identity"
    );
    for version in &marker.owned_versions {
        let _ = codex_cache_path_for_version(version)?;
    }
    let plugin_list = codex_plugin_list(&marker.codex_cli_path)?;
    if let Some(entry) = codex_plugin_entry(&plugin_list, &marker.plugin_selector) {
        ensure!(
            codex_plugin_entry_has_owned_identity(
                entry,
                &marker.plugin_selector,
                &marker.plugin_path,
            ) && entry
                .get("version")
                .and_then(Value::as_str)
                .is_some_and(|version| marker.owned_versions.iter().any(|owned| owned == version)),
            "Codex owned lifecycle recovery marker does not match the live plugin entry"
        );
    }
    Ok(true)
}

fn clear_codex_owned_lifecycle_recovery() -> Result<()> {
    let path = codex_owned_lifecycle_recovery_path()?;
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

fn rollback_codex_owned_path(
    path: &Path,
    before_hash: Option<&str>,
    after_hash: &str,
    backup: Option<&PathBuf>,
) -> Result<()> {
    if path.exists() {
        let current = hash_owned_path(path)?;
        if Some(current.as_str()) == before_hash {
            return Ok(());
        }
        ensure!(
            current == after_hash,
            "Codex transaction path changed concurrently: {}",
            path.display()
        );
        remove_owned_path(path)?;
    }
    if let Some(before_hash) = before_hash {
        let backup = backup.context("Codex transaction lost its required backup reference")?;
        ensure!(
            backup.exists(),
            "Codex transaction backup is missing: {}",
            backup.display()
        );
        std::fs::rename(backup, path)?;
        ensure!(
            hash_owned_path(path)? == before_hash,
            "Codex transaction restored the wrong content at {}",
            path.display()
        );
    }
    Ok(())
}

fn remove_codex_transaction_backup(
    transaction_backup: Option<&PathBuf>,
    persistent_backup: Option<&PathBuf>,
) -> Result<()> {
    let Some(transaction_backup) = transaction_backup else {
        return Ok(());
    };
    if persistent_backup
        .is_some_and(|persistent| path_identity(persistent) == path_identity(transaction_backup))
    {
        return Ok(());
    }
    if transaction_backup.exists() {
        ensure!(
            !std::fs::symlink_metadata(transaction_backup)?
                .file_type()
                .is_symlink(),
            "Codex transaction backup may not be a symlink: {}",
            transaction_backup.display()
        );
        remove_owned_path(transaction_backup)?;
    }
    Ok(())
}

pub(super) fn select_codex_original_plugin_hash(
    previous_schema_version: Option<&str>,
    recorded_before_hash: Option<&str>,
    legacy_backup_hash: Option<&str>,
    current_pre_mutation_hash: Option<&str>,
) -> Result<Option<String>> {
    match previous_schema_version {
        None => Ok(current_pre_mutation_hash.map(str::to_owned)),
        Some(CODEX_GLOBAL_MANIFEST_SCHEMA_V2) => Ok(recorded_before_hash.map(str::to_owned)),
        Some(CODEX_GLOBAL_MANIFEST_SCHEMA_V1) => Ok(legacy_backup_hash.map(str::to_owned)),
        Some(schema) => bail!("unsupported Codex global install manifest schema: {schema}"),
    }
}

fn validated_legacy_codex_plugin_backup_hash(
    manifest: &CodexGlobalInstallManifest,
) -> Result<Option<String>> {
    if manifest.schema_version != CODEX_GLOBAL_MANIFEST_SCHEMA_V1 {
        return Ok(None);
    }
    let Some(backup) = manifest.installed_plugin.backup_ref.as_ref() else {
        return Ok(None);
    };
    let backup_root = install_base()?.join("global-backups");
    ensure_child(&backup_root, backup)?;
    let metadata = std::fs::symlink_metadata(backup)
        .with_context(|| format!("inspect legacy Codex plugin backup {}", backup.display()))?;
    ensure!(
        !metadata.file_type().is_symlink() && (metadata.is_dir() || metadata.is_file()),
        "legacy Codex plugin backup must be a regular owned path: {}",
        backup.display()
    );
    Ok(Some(hash_owned_path(backup)?))
}

fn codex_original_plugin_hash(
    previous: Option<&CodexGlobalInstallManifest>,
    current_pre_mutation_hash: Option<&str>,
) -> Result<Option<String>> {
    let legacy_backup_hash = previous
        .map(validated_legacy_codex_plugin_backup_hash)
        .transpose()?
        .flatten();
    select_codex_original_plugin_hash(
        previous.map(|manifest| manifest.schema_version.as_str()),
        previous.and_then(|manifest| manifest.plugin_before_hash.as_deref()),
        legacy_backup_hash.as_deref(),
        current_pre_mutation_hash,
    )
}

pub(super) fn codex_manifest_plugin_source_hash(manifest: &CodexGlobalInstallManifest) -> &str {
    if manifest.plugin_source_hash.is_empty() {
        &manifest.installed_plugin.installed_hash
    } else {
        &manifest.plugin_source_hash
    }
}

fn codex_manifest_cache_contract_hash(
    manifest: &CodexGlobalInstallManifest,
    plugin_path: &Path,
) -> Result<String> {
    if manifest.cache_contract_hash.is_empty() {
        codex_cache_contract_hash(plugin_path)
    } else {
        Ok(manifest.cache_contract_hash.clone())
    }
}

pub(super) fn codex_materialized_plugin_version(
    source_version: &str,
    payload_hash: &str,
) -> Result<String> {
    let base_version = source_version
        .split_once('+')
        .map_or(source_version, |(base, _)| base)
        .trim();
    ensure!(
        !base_version.is_empty(),
        "Codex plugin base version may not be empty"
    );
    let digest = payload_hash
        .strip_prefix("blake3:")
        .context("Codex plugin payload hash must use the blake3 prefix")?;
    ensure!(
        digest.len() >= 32 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Codex plugin payload hash must contain at least 32 hexadecimal digits"
    );
    Ok(format!(
        "{base_version}+codex.artifact-{}",
        &digest[..32].to_ascii_lowercase()
    ))
}

pub(super) fn materialize_codex_plugin_version(root: &Path, version: &str) -> Result<()> {
    let manifest_path = root.join(".codex-plugin").join("plugin.json");
    let mut manifest: Value = serde_json::from_reader(
        std::fs::File::open(&manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?,
    )?;
    let object = manifest
        .as_object_mut()
        .context("Codex plugin manifest root must be an object")?;
    object.insert("version".to_owned(), Value::String(version.to_owned()));
    atomic_write_json(&manifest_path, &manifest)
}

pub(super) fn codex_owned_lifecycle_requires_refresh(
    has_previous_manifest: bool,
    plugin_installed_before: bool,
    previous_cache_contract_hash: Option<&str>,
    desired_cache_contract_hash: &str,
) -> bool {
    has_previous_manifest
        && !plugin_installed_before
        && previous_cache_contract_hash != Some(desired_cache_contract_hash)
}

pub(super) fn codex_plugin_path_is_restored(
    current_hash: Option<&str>,
    original_hash: Option<&str>,
) -> bool {
    current_hash == original_hash
}

pub(super) fn validate_codex_install_journal_schema(value: &Value) -> Result<()> {
    let schema = value
        .get("schema_version")
        .and_then(Value::as_str)
        .context("Codex install journal schema_version is missing")?;
    ensure!(
        schema == CODEX_INSTALL_JOURNAL_SCHEMA_V2,
        "unsupported Codex install journal schema: {schema}"
    );
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn recover_codex_install_transaction(target: &Path, dry_run: bool) -> Result<bool> {
    let journal_path = codex_install_journal_path()?;
    if !journal_path.exists() {
        return codex_owned_lifecycle_recovery_is_valid();
    }
    ensure!(
        !std::fs::symlink_metadata(&journal_path)?
            .file_type()
            .is_symlink(),
        "Codex install journal may not be a symlink"
    );
    ensure!(
        !dry_run,
        "an interrupted Codex install requires recovery; rerun without --dry-run"
    );
    let journal_value: Value = serde_json::from_reader(std::fs::File::open(&journal_path)?)?;
    validate_codex_install_journal_schema(&journal_value)?;
    let journal: CodexInstallJournal = serde_json::from_value(journal_value)?;
    ensure!(
        journal.target_path == target
            && journal.plugin_path == codex_plugin_root()?
            && journal.marketplace_path == codex_marketplace_path()?,
        "Codex install journal contains unexpected ownership paths"
    );
    let base = install_base()?;
    ensure_child(&base, &journal.target_path)?;
    ensure_child(&base, &journal.target_staging)?;
    let plugins_root = user_home()?.join("plugins");
    ensure_child(&plugins_root, &journal.plugin_path)?;
    ensure_child(&plugins_root, &journal.plugin_staging)?;
    if let Some(backup) = &journal.target_backup_ref {
        ensure_child(&base, backup)?;
    }
    if let Some(backup) = &journal.plugin_backup_ref {
        ensure_child(&base.join("global-backups"), backup)?;
    }
    if let Some(backup) = &journal.marketplace_backup_ref {
        ensure_child(&base.join("global-backups"), backup)?;
    }
    let manifest_path = target.join(CODEX_GLOBAL_MANIFEST);
    let committed_manifest = if manifest_path.is_file() {
        Some(serde_json::from_reader::<_, CodexGlobalInstallManifest>(
            std::fs::File::open(&manifest_path)?,
        )?)
    } else {
        None
    };
    if let Some(manifest) = committed_manifest
        .as_ref()
        .filter(|manifest| manifest.transaction_id == journal.transaction_id)
    {
        for staging in [&journal.target_staging, &journal.plugin_staging] {
            if staging.exists() {
                remove_owned_path(staging)?;
            }
        }
        remove_codex_transaction_backup(
            journal.plugin_backup_ref.as_ref(),
            manifest.installed_plugin.backup_ref.as_ref(),
        )?;
        remove_codex_transaction_backup(
            journal.marketplace_backup_ref.as_ref(),
            manifest.marketplace_backup_ref.as_ref(),
        )?;
        remove_codex_transaction_backup(journal.target_backup_ref.as_ref(), None)?;
        std::fs::remove_file(journal_path)?;
        clear_codex_owned_lifecycle_recovery()?;
        return Ok(false);
    }

    if journal.marketplace_path.exists() {
        let current_bytes = std::fs::read(&journal.marketplace_path)?;
        let current_hash = bytes_hash(&current_bytes);
        if Some(current_hash.as_str()) != journal.marketplace_before_hash.as_deref() {
            ensure!(
                current_hash == journal.marketplace_after_hash,
                "Codex marketplace changed concurrently during install recovery"
            );
            if journal.marketplace_existed_before {
                let backup = journal
                    .marketplace_backup_ref
                    .as_ref()
                    .context("Codex marketplace recovery requires a backup")?;
                ensure!(backup.is_file(), "Codex marketplace backup is missing");
                atomic_write_bytes(&journal.marketplace_path, &std::fs::read(backup)?)?;
            } else {
                std::fs::remove_file(&journal.marketplace_path)?;
            }
        }
    } else if journal.marketplace_existed_before {
        let backup = journal
            .marketplace_backup_ref
            .as_ref()
            .context("Codex marketplace recovery requires a backup")?;
        atomic_write_bytes(&journal.marketplace_path, &std::fs::read(backup)?)?;
    }
    rollback_codex_owned_path(
        &journal.plugin_path,
        journal.plugin_before_hash.as_deref(),
        &journal.plugin_after_hash,
        journal.plugin_backup_ref.as_ref(),
    )?;
    rollback_codex_owned_path(
        &journal.target_path,
        journal.target_before_hash.as_deref(),
        &journal.target_after_hash,
        journal.target_backup_ref.as_ref(),
    )?;
    let mut recovered_owned_lifecycle = false;
    if journal.plugin_lifecycle_owned_before || !journal.plugin_installed_before {
        let plugin_list = codex_plugin_list(&journal.codex_cli_path)?;
        if let Some(entry) = codex_plugin_entry(&plugin_list, &journal.plugin_selector) {
            let current_version = entry.get("version").and_then(Value::as_str);
            let version_is_owned = current_version == Some(journal.plugin_version.as_str())
                || journal.plugin_lifecycle_version_before.as_deref() == current_version;
            ensure!(
                codex_plugin_entry_has_owned_identity(
                    entry,
                    &journal.plugin_selector,
                    &journal.plugin_path,
                ) && version_is_owned,
                "interrupted Codex transaction found a foreign plugin lifecycle entry"
            );
            recovered_owned_lifecycle = true;
            // Never remove or downgrade an active Codex plugin during recovery. The
            // immediately following install materializes a content-addressed
            // cachebuster and either performs an add-only upgrade or repairs that
            // exact owned cache in place.
        }
    }
    for staging in [&journal.target_staging, &journal.plugin_staging] {
        if staging.exists() {
            remove_owned_path(staging)?;
        }
    }
    if recovered_owned_lifecycle {
        persist_codex_owned_lifecycle_recovery(&journal)?;
    }
    std::fs::remove_file(journal_path)?;
    Ok(recovered_owned_lifecycle)
}

#[allow(clippy::too_many_lines)]
pub(super) fn install_codex_global(
    config_path: &Path,
    source: &Path,
    target: &Path,
    governor: &Path,
    previous: Option<&CodexGlobalInstallManifest>,
    recovered_owned_lifecycle: bool,
    dry_run: bool,
) -> Result<GlobalInstallOutcome> {
    let home = user_home()?;
    let base = install_base()?;
    let plugins_root = home.join("plugins");
    let plugin_path = codex_plugin_root()?;
    let marketplace_path = codex_marketplace_path()?;
    let codex = crate::dogfood::find_codex_cli()
        .context("locate installed Codex CLI for the official personal-marketplace lifecycle")?;
    let plugin_selector = format!("{CODEX_PLUGIN_NAME}@{CODEX_MARKETPLACE_NAME}");
    let plugin_list_before = codex_plugin_list(&codex)?;
    let plugin_state_before = codex_plugin_installed_enabled(&plugin_list_before, &plugin_selector);
    let plugin_installed_before = !recovered_owned_lifecycle
        && codex_effective_plugin_installed_before(
            previous.map(|manifest| manifest.plugin_installed_before),
            plugin_state_before,
        );
    ensure_child(&plugins_root, &plugin_path)?;
    ensure!(
        source.is_dir(),
        "Codex plugin source is missing: {}",
        source.display()
    );

    let plugin_manifest_path = source.join(".codex-plugin").join("plugin.json");
    let plugin_manifest: Value = serde_json::from_reader(
        std::fs::File::open(&plugin_manifest_path)
            .with_context(|| format!("read {}", plugin_manifest_path.display()))?,
    )?;
    ensure!(
        plugin_manifest.get("name").and_then(Value::as_str) == Some(CODEX_PLUGIN_NAME),
        "Codex plugin manifest must identify {CODEX_PLUGIN_NAME}"
    );
    let plugin_source_version = plugin_manifest
        .get("version")
        .and_then(Value::as_str)
        .context("Codex plugin manifest version is missing")?
        .to_owned();
    let plugin_base_version = plugin_source_version
        .split_once('+')
        .map_or(plugin_source_version.as_str(), |(base, _)| base)
        .trim()
        .to_owned();
    ensure!(
        !plugin_base_version.is_empty(),
        "Codex plugin base version may not be empty"
    );
    let installed_governor = plugin_path.join("bin").join("eliot-governor.exe");
    let installed_governor_sha256 = sha256_file(governor)?;
    let mut mcp_config: Value =
        serde_json::from_reader(std::fs::File::open(source.join(".mcp.json"))?)?;
    materialize_codex_mcp_config(&mut mcp_config, &installed_governor)?;
    let hooks: Value = serde_json::from_reader(std::fs::File::open(
        source.join("hooks").join("hooks.json"),
    )?)?;
    validate_codex_hook_commands(&hooks)?;

    let config = load_config(config_path)?;
    let local_app_data =
        PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not set")?);
    let mut approved_governors = vec![governor.to_path_buf()];
    if let Some(previous) = previous {
        approved_governors.push(previous.installed_governor_path.clone());
    }
    let approval = CodexLegacyMcpApproval {
        governor_paths: approved_governors,
        governor_packages_root: local_app_data.join("Eliot").join("packages"),
        surreal_executable: PathBuf::from(&config.db.surreal.exe),
        surreal_namespace: config.db.surreal.ns.clone(),
        surreal_database: config.db.surreal.db.clone(),
        surreal_storage: config.db.surreal.storage.clone(),
    };
    let legacy_direct_mcp = inspect_codex_legacy_direct_mcp(&codex, &approval)?;

    if marketplace_path.exists() {
        let metadata = std::fs::symlink_metadata(&marketplace_path)?;
        ensure!(
            !metadata.file_type().is_symlink() && metadata.is_file(),
            "Codex personal marketplace must be a regular file: {}",
            marketplace_path.display()
        );
    }
    if plugin_path.exists() {
        ensure!(
            !std::fs::symlink_metadata(&plugin_path)?
                .file_type()
                .is_symlink(),
            "Codex plugin destination may not be a symlink: {}",
            plugin_path.display()
        );
    }
    let marketplace_existed_now = marketplace_path.is_file();
    let marketplace_before_bytes = marketplace_existed_now
        .then(|| std::fs::read(&marketplace_path))
        .transpose()?;
    let marketplace_before_hash_now = marketplace_before_bytes.as_deref().map(bytes_hash);
    let merged = merge_codex_marketplace(marketplace_before_bytes.as_deref(), previous)?;
    let (marketplace_existed_before, marketplace_before_hash, marketplace_backup_ref) = if merged
        .continuing_owned
    {
        let manifest = previous.context("continuing Codex ownership requires a manifest")?;
        (
            manifest.marketplace_existed_before,
            manifest.marketplace_before_hash.clone(),
            manifest.marketplace_backup_ref.clone(),
        )
    } else {
        (
            marketplace_existed_now,
            marketplace_before_hash_now.clone(),
            marketplace_existed_now
                .then(|| {
                    global_backup_path("codex-personal-marketplace", marketplace_path.extension())
                })
                .transpose()?,
        )
    };

    let mut outcome = GlobalInstallOutcome::default();
    outcome
        .installed_paths
        .push(plugin_path.to_string_lossy().into_owned());
    outcome
        .installed_paths
        .push(marketplace_path.to_string_lossy().into_owned());
    outcome
        .installed_paths
        .push(format!("official-plugin:{plugin_selector}"));
    if marketplace_before_bytes.as_deref() != Some(merged.bytes.as_slice()) {
        outcome
            .modified_files
            .push(marketplace_path.to_string_lossy().into_owned());
    }
    if let Some(backup) = &marketplace_backup_ref {
        outcome
            .backup_refs
            .push(backup.to_string_lossy().into_owned());
    }
    if dry_run {
        outcome
            .modified_files
            .push(plugin_path.to_string_lossy().into_owned());
        if plugin_state_before != Some((true, true)) {
            outcome
                .modified_files
                .push(format!("official-plugin:{plugin_selector}"));
        }
        outcome.modified_files.extend(
            legacy_direct_mcp
                .iter()
                .map(|registration| format!("legacy-direct-mcp:{}", registration.name)),
        );
        return Ok(outcome);
    }

    std::fs::create_dir_all(&base)?;
    std::fs::create_dir_all(&plugins_root)?;
    let transaction_id = Uuid::new_v4().to_string();
    let target_staging = base.join(format!(".codex-{transaction_id}-staging"));
    let plugin_staging =
        plugins_root.join(format!(".{CODEX_PLUGIN_NAME}-{transaction_id}-staging"));
    ensure_child(&base, &target_staging)?;
    ensure_child(&plugins_root, &plugin_staging)?;
    copy_tree(source, &target_staging, AgentHostId::Codex)?;
    std::fs::create_dir_all(target_staging.join("bin"))?;
    std::fs::copy(
        governor,
        target_staging.join("bin").join("eliot-governor.exe"),
    )?;
    copy_tree(source, &plugin_staging, AgentHostId::Codex)?;
    std::fs::create_dir_all(plugin_staging.join("bin"))?;
    std::fs::copy(
        governor,
        plugin_staging.join("bin").join("eliot-governor.exe"),
    )?;
    atomic_write_json(&plugin_staging.join(".mcp.json"), &mcp_config)?;
    atomic_write_json(&plugin_staging.join("hooks").join("hooks.json"), &hooks)?;
    materialize_codex_plugin_version(&plugin_staging, &plugin_base_version)?;
    let pre_version_payload_hash = codex_cache_contract_hash(&plugin_staging)?;
    let plugin_version =
        codex_materialized_plugin_version(&plugin_base_version, &pre_version_payload_hash)?;
    materialize_codex_plugin_version(&plugin_staging, &plugin_version)?;
    let desired_target_hash = hash_owned_path(&target_staging)?;
    let desired_plugin_hash = hash_owned_path(&plugin_staging)?;
    let desired_cache_contract_hash = codex_cache_contract_hash(&plugin_staging)?;
    let target_before_hash = target
        .exists()
        .then(|| hash_owned_path(target))
        .transpose()?;
    let current_plugin_hash = plugin_path
        .exists()
        .then(|| hash_owned_path(&plugin_path))
        .transpose()?;
    let continuing_owned_plugin = previous.is_some_and(|manifest| {
        manifest.installed_plugin.path == plugin_path
            && current_plugin_hash.as_deref()
                == Some(manifest.installed_plugin.installed_hash.as_str())
    });
    if plugin_state_before == Some((true, false)) {
        let manifest = previous.context(
            "disabled Codex Eliot plugin has no ELIOT ownership manifest; refusing update",
        )?;
        let entry = codex_plugin_entry(&plugin_list_before, &plugin_selector)
            .context("disabled Codex Eliot plugin disappeared during ownership validation")?;
        ensure!(
            continuing_owned_plugin
                && codex_plugin_entry_has_owned_identity(entry, &plugin_selector, &plugin_path)
                && entry.get("version").and_then(Value::as_str)
                    == Some(manifest.plugin_version.as_str()),
            "disabled Codex Eliot plugin is not the exact artifact owned by ELIOT"
        );
    }
    let previous_cache_contract_hash = previous
        .filter(|_| continuing_owned_plugin)
        .map(|manifest| codex_manifest_cache_contract_hash(manifest, &plugin_path))
        .transpose()?;
    let original_plugin_before_hash =
        codex_original_plugin_hash(previous, current_plugin_hash.as_deref())?;
    let plugin_lifecycle_owned_before = previous.is_some()
        && !plugin_installed_before
        && plugin_state_before.is_some_and(|(installed, _)| installed);
    let previous_owned_lifecycle = if plugin_lifecycle_owned_before {
        Some(previous.context("owned Codex lifecycle requires its prior manifest")?)
    } else {
        None
    };
    if let Some(manifest) = previous_owned_lifecycle {
        let previous_expected = CodexPluginExpectation {
            selector: &plugin_selector,
            version: &manifest.plugin_version,
            source_path: &plugin_path,
            cache_contract_hash: previous_cache_contract_hash
                .as_deref()
                .context("owned Codex lifecycle lacks its prior cache contract")?,
            installed_governor: &manifest.installed_governor_path,
            installed_governor_sha256: &manifest.installed_governor_sha256,
        };
        let previous_lifecycle_is_fresh =
            codex_plugin_lifecycle_is_fresh(&codex, &plugin_list_before, &previous_expected)?;
        if !previous_lifecycle_is_fresh {
            let entry = codex_plugin_entry(&plugin_list_before, &plugin_selector)
                .context("owned Codex lifecycle disappeared during install preflight")?;
            let entry_version = entry.get("version").and_then(Value::as_str);
            let version_is_proven = entry_version == Some(manifest.plugin_version.as_str())
                || (recovered_owned_lifecycle && entry_version == Some(plugin_version.as_str()));
            ensure!(
                continuing_owned_plugin
                    && codex_plugin_entry_has_owned_identity(entry, &plugin_selector, &plugin_path,)
                    && version_is_proven
                    && sha256_file(&manifest.installed_governor_path)?
                        == manifest.installed_governor_sha256
                    && (manifest.plugin_version != plugin_version
                        || plugin_state_before == Some((true, false))),
                "existing stale Codex lifecycle is not proven to be the before/after artifact owned by ELIOT"
            );
        }
    }
    let force_refresh_owned = codex_owned_lifecycle_requires_refresh(
        previous.is_some(),
        plugin_installed_before,
        previous_cache_contract_hash.as_deref(),
        &desired_cache_contract_hash,
    );
    let persistent_plugin_backup_ref = if continuing_owned_plugin {
        previous.and_then(|manifest| manifest.installed_plugin.backup_ref.clone())
    } else if plugin_path.exists() {
        Some(global_backup_path(CODEX_PLUGIN_NAME, None)?)
    } else {
        None
    };
    let transaction_plugin_backup = if plugin_path.exists() {
        if continuing_owned_plugin {
            Some(global_backup_path("codex-transaction-plugin", None)?)
        } else {
            persistent_plugin_backup_ref.clone()
        }
    } else {
        None
    };
    let target_backup = target
        .exists()
        .then(|| base.join(format!(".codex-{transaction_id}-backup")));
    let transaction_marketplace_backup = if marketplace_existed_now {
        if merged.continuing_owned {
            Some(global_backup_path(
                "codex-transaction-marketplace",
                marketplace_path.extension(),
            )?)
        } else {
            marketplace_backup_ref.clone()
        }
    } else {
        None
    };
    let journal = CodexInstallJournal {
        schema_version: CODEX_INSTALL_JOURNAL_SCHEMA_V2.to_owned(),
        transaction_id: transaction_id.clone(),
        target_path: target.to_path_buf(),
        target_existed_before: target.exists(),
        target_before_hash: target_before_hash.clone(),
        target_after_hash: desired_target_hash.clone(),
        target_backup_ref: target_backup.clone(),
        target_staging: target_staging.clone(),
        plugin_path: plugin_path.clone(),
        plugin_existed_before: plugin_path.exists(),
        plugin_before_hash: current_plugin_hash.clone(),
        plugin_after_hash: desired_plugin_hash.clone(),
        plugin_backup_ref: transaction_plugin_backup.clone(),
        plugin_staging: plugin_staging.clone(),
        marketplace_path: marketplace_path.clone(),
        marketplace_existed_before: marketplace_existed_now,
        marketplace_before_hash: marketplace_before_hash_now.clone(),
        marketplace_after_hash: bytes_hash(&merged.bytes),
        marketplace_backup_ref: transaction_marketplace_backup.clone(),
        marketplace_plugins_field_existed_before: merged.plugins_field_existed_before,
        marketplace_entry_before: merged.entry_before.clone(),
        marketplace_entry_before_index: merged.entry_before_index,
        marketplace_entry_after: codex_marketplace_entry(),
        codex_cli_path: codex.clone(),
        plugin_selector: plugin_selector.clone(),
        plugin_installed_before,
        plugin_lifecycle_owned_before,
        plugin_lifecycle_version_before: previous_owned_lifecycle
            .map(|manifest| manifest.plugin_version.clone()),
        plugin_lifecycle_source_hash_before: previous_owned_lifecycle
            .map(|manifest| codex_manifest_plugin_source_hash(manifest).to_owned()),
        plugin_cache_contract_hash_before: previous_cache_contract_hash
            .clone()
            .filter(|_| plugin_lifecycle_owned_before),
        plugin_cache_contract_hash_after: desired_cache_contract_hash.clone(),
        installed_governor_sha256_before: previous_owned_lifecycle
            .map(|manifest| manifest.installed_governor_sha256.clone()),
        plugin_version: plugin_version.clone(),
        installed_governor_path: installed_governor.clone(),
        installed_governor_sha256: installed_governor_sha256.clone(),
        created_at: OffsetDateTime::now_utc().to_string(),
    };
    create_codex_install_journal(&journal)?;
    let mutation = (|| -> Result<()> {
        if let Some(backup) = &transaction_marketplace_backup {
            std::fs::create_dir_all(
                backup
                    .parent()
                    .context("marketplace backup has no parent")?,
            )?;
            std::fs::copy(&marketplace_path, backup)?;
        }
        if let Some(backup) = &target_backup {
            std::fs::rename(target, backup)?;
        }
        std::fs::rename(&target_staging, target)?;
        if let Some(backup) = &transaction_plugin_backup {
            std::fs::create_dir_all(backup.parent().context("plugin backup has no parent")?)?;
            std::fs::rename(&plugin_path, backup)?;
        }
        std::fs::rename(&plugin_staging, &plugin_path)?;
        if marketplace_before_bytes.as_deref() != Some(merged.bytes.as_slice()) {
            atomic_write_json(&marketplace_path, &merged.value)?;
        }
        let expected = CodexPluginExpectation {
            selector: &plugin_selector,
            version: &plugin_version,
            source_path: &plugin_path,
            cache_contract_hash: &desired_cache_contract_hash,
            installed_governor: &installed_governor,
            installed_governor_sha256: &installed_governor_sha256,
        };
        install_codex_plugin_lifecycle(
            &codex,
            &expected,
            (previous.is_some() || recovered_owned_lifecycle) && !plugin_installed_before,
            force_refresh_owned,
        )?;
        Ok(())
    })();
    if let Err(error) = mutation {
        return match recover_codex_install_transaction(target, false) {
            Ok(true) if !recovered_owned_lifecycle => install_codex_global(
                config_path,
                source,
                target,
                governor,
                previous,
                true,
                false,
            )
            .with_context(|| {
                format!(
                    "Codex install retry after owned lifecycle recovery; initial failure: {error:#}"
                )
            }),
            Ok(_) => Err(error.context("Codex install transaction rolled back")),
            Err(recovery) => {
                Err(error.context(format!("Codex rollback also failed: {recovery:#}")))
            }
        };
    }
    outcome
        .modified_files
        .push(target.to_string_lossy().into_owned());
    outcome
        .modified_files
        .push(plugin_path.to_string_lossy().into_owned());
    if let Some(backup) = &persistent_plugin_backup_ref {
        outcome
            .backup_refs
            .push(backup.to_string_lossy().into_owned());
    }
    ensure!(
        hash_owned_path(&plugin_path)? == desired_plugin_hash,
        "installed Codex plugin hash does not match the staged plugin"
    );
    ensure!(
        sha256_file(&installed_governor)? == installed_governor_sha256,
        "installed Codex Eliot executable hash does not match current release"
    );
    let mut legacy_prior = previous
        .map(|manifest| manifest.legacy_direct_mcp_prior.clone())
        .unwrap_or_default();
    for registration in &legacy_direct_mcp {
        if !legacy_prior
            .iter()
            .any(|prior| prior.name == registration.name)
        {
            legacy_prior.push(registration.clone());
        }
    }
    let mut legacy_removed = previous
        .map(|manifest| manifest.legacy_direct_mcp_removed.clone())
        .unwrap_or_default();
    for prior in &legacy_prior {
        ensure!(
            matches!(prior.name.as_str(), "eliot-governor" | "eliot_surrealdb"),
            "Codex manifest contains an unknown legacy MCP identity: {}",
            prior.name
        );
        if !legacy_removed.contains(&prior.name)
            && !legacy_direct_mcp
                .iter()
                .any(|registration| registration.name == prior.name)
        {
            legacy_removed.push(prior.name.clone());
        }
    }
    let mut manifest = CodexGlobalInstallManifest {
        schema_version: CODEX_GLOBAL_MANIFEST_SCHEMA_V2.to_owned(),
        transaction_id,
        source_plugin_path: source.to_path_buf(),
        source_bundle_hash: bundle_hash(source, AgentHostId::Codex)?,
        installed_plugin: OpenCodeOwnedPath {
            path: plugin_path.clone(),
            installed_hash: desired_plugin_hash.clone(),
            backup_ref: persistent_plugin_backup_ref,
        },
        plugin_before_hash: original_plugin_before_hash,
        installed_governor_path: installed_governor.clone(),
        installed_governor_sha256: installed_governor_sha256.clone(),
        marketplace_path: marketplace_path.clone(),
        marketplace_existed_before,
        marketplace_before_hash,
        marketplace_after_hash: bytes_hash(&merged.bytes),
        marketplace_backup_ref,
        marketplace_plugins_field_existed_before: merged.plugins_field_existed_before,
        marketplace_entry_before: merged.entry_before,
        marketplace_entry_before_index: merged.entry_before_index,
        marketplace_entry_after: codex_marketplace_entry(),
        marketplace_name: CODEX_MARKETPLACE_NAME.to_owned(),
        plugin_version,
        plugin_source_hash: desired_plugin_hash,
        cache_contract_hash: desired_cache_contract_hash,
        codex_cli_path: codex.clone(),
        plugin_selector: plugin_selector.clone(),
        plugin_installed_before,
        plugin_installed_enabled_after: true,
        legacy_direct_mcp_prior: legacy_prior,
        legacy_direct_mcp_removed: legacy_removed,
        generated_at: OffsetDateTime::now_utc().to_string(),
    };
    atomic_write_json(&target.join(CODEX_GLOBAL_MANIFEST), &manifest)?;
    remove_codex_transaction_backup(
        transaction_plugin_backup.as_ref(),
        manifest.installed_plugin.backup_ref.as_ref(),
    )?;
    remove_codex_transaction_backup(
        transaction_marketplace_backup.as_ref(),
        manifest.marketplace_backup_ref.as_ref(),
    )?;
    remove_codex_transaction_backup(target_backup.as_ref(), None)?;
    std::fs::remove_file(codex_install_journal_path()?)?;
    clear_codex_owned_lifecycle_recovery()?;
    for registration in &legacy_direct_mcp {
        remove_codex_legacy_direct_mcp(&codex, registration)?;
        if !manifest
            .legacy_direct_mcp_removed
            .contains(&registration.name)
        {
            manifest
                .legacy_direct_mcp_removed
                .push(registration.name.clone());
            atomic_write_json(&target.join(CODEX_GLOBAL_MANIFEST), &manifest)?;
        }
        outcome
            .modified_files
            .push(format!("legacy-direct-mcp:{}", registration.name));
    }
    Ok(outcome)
}

#[allow(clippy::too_many_lines)]
pub(super) fn install_opencode_global(
    source: &Path,
    target: &Path,
    governor: &Path,
    previous: Option<&OpenCodeGlobalInstallManifest>,
    dry_run: bool,
) -> Result<GlobalInstallOutcome> {
    let root = opencode_global_root()?;
    let config_path = opencode_global_config_path(&root);
    let config_existed_now = config_path.is_file();
    let config_before_bytes = config_existed_now
        .then(|| std::fs::read(&config_path))
        .transpose()?;
    let config_before_hash_now = config_before_bytes.as_deref().map(bytes_hash);
    let config_input = config_before_bytes
        .clone()
        .unwrap_or_else(default_opencode_config_bytes);
    let installed_governor = target
        .join("bin")
        .join("eliot-governor.exe")
        .to_string_lossy()
        .replace('\\', "/");
    let instruction_destination = root.join("instructions").join("eliot-governor.md");
    let instruction_entry_after = instruction_destination.to_string_lossy().replace('\\', "/");
    let mcp_entry_after = json!({
        "type": "local",
        "command": [
            installed_governor,
            "mcp",
            "stdio",
            "--host",
            "opencode",
            "--instance",
            "default"
        ],
        "enabled": true,
        "timeout": 30000
    });
    let merged =
        merge_opencode_mcp_config(&config_input, &mcp_entry_after, &instruction_entry_after)
            .with_context(|| format!("merge Eliot into {}", config_path.display()))?;
    let current_eliot_entry = merged.mcp_entry_before.clone();
    let continuing_owned_config = previous.is_some_and(|manifest| {
        manifest.config_path == config_path
            && current_eliot_entry.as_ref() == Some(&manifest.mcp_entry_after)
            && (manifest.instruction_entry_after.is_empty()
                || (manifest.instruction_entry_after == instruction_entry_after
                    && merged.instruction_entry_existed_before))
    });
    let (
        config_existed,
        config_before_hash,
        config_backup_ref,
        mcp_field_existed_before,
        mcp_entry_before,
        instructions_field_existed_before,
        instruction_entry_existed_before,
    ) = if continuing_owned_config {
        let manifest = previous
            .context("continuing OpenCode ownership requires the previous install manifest")?;
        let instruction_origin = if manifest.instruction_entry_after.is_empty() {
            (
                merged.instructions_field_existed_before,
                merged.instruction_entry_existed_before,
            )
        } else {
            (
                manifest.instructions_field_existed_before,
                manifest.instruction_entry_existed_before,
            )
        };
        (
            manifest.config_existed,
            manifest.config_before_hash.clone(),
            manifest.config_backup_ref.clone(),
            manifest.mcp_field_existed_before,
            manifest.mcp_entry_before.clone(),
            instruction_origin.0,
            instruction_origin.1,
        )
    } else {
        let backup = config_existed_now
            .then(|| global_backup_path("opencode-config", config_path.extension()))
            .transpose()?;
        if !dry_run && let Some(backup) = &backup {
            std::fs::create_dir_all(backup.parent().context("config backup has no parent")?)?;
            std::fs::copy(&config_path, backup)?;
        }
        (
            config_existed_now,
            config_before_hash_now.clone(),
            backup,
            merged.mcp_field_existed_before,
            current_eliot_entry,
            merged.instructions_field_existed_before,
            merged.instruction_entry_existed_before,
        )
    };
    let config_after_bytes = merged.bytes;
    let config_after_hash = bytes_hash(&config_after_bytes);

    let mut outcome = GlobalInstallOutcome::default();
    outcome
        .installed_paths
        .push(config_path.to_string_lossy().into_owned());
    if config_before_bytes.as_deref() != Some(config_after_bytes.as_slice()) {
        outcome
            .modified_files
            .push(config_path.to_string_lossy().into_owned());
        if !dry_run {
            atomic_write_bytes(&config_path, &config_after_bytes)?;
        }
    }
    if let Some(backup) = &config_backup_ref {
        outcome
            .backup_refs
            .push(backup.to_string_lossy().into_owned());
    }

    let install_source = if dry_run { source } else { target };
    let mut owned_paths = Vec::new();
    for entry in std::fs::read_dir(install_source.join("skills"))? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let destination = root.join("skills").join(entry.file_name());
        let (owned, changed) = install_owned_path(&entry.path(), &destination, previous, dry_run)?;
        record_owned_outcome(&mut outcome, &owned, &destination, changed);
        owned_paths.push(owned);
    }
    let plugin_source = install_source.join("plugins").join("eliot.js");
    let plugin_destination = root.join("plugins").join("eliot-governor.js");
    let (plugin_owned, plugin_changed) =
        install_owned_path(&plugin_source, &plugin_destination, previous, dry_run)?;
    record_owned_outcome(
        &mut outcome,
        &plugin_owned,
        &plugin_destination,
        plugin_changed,
    );
    owned_paths.push(plugin_owned);
    let instruction_source = install_source.join("instructions").join("eliot.md");
    let (instruction_owned, instruction_changed) = install_owned_path(
        &instruction_source,
        &instruction_destination,
        previous,
        dry_run,
    )?;
    record_owned_outcome(
        &mut outcome,
        &instruction_owned,
        &instruction_destination,
        instruction_changed,
    );
    owned_paths.push(instruction_owned);

    let governor_hash = bundle_hash_single(governor)?;
    let installed_binary = target.join("bin").join("eliot-governor.exe");
    let binary_hash = if dry_run {
        governor_hash
    } else {
        bundle_hash_single(&installed_binary)?
    };
    if binary_hash != bundle_hash_single(governor)? {
        bail!("installed OpenCode Eliot executable hash does not match current release");
    }

    let manifest = OpenCodeGlobalInstallManifest {
        schema_version: "eliot-opencode-global-install-v2".to_owned(),
        config_path,
        config_existed,
        config_before_hash,
        config_after_hash,
        config_backup_ref,
        mcp_field_existed_before,
        mcp_entry_before,
        mcp_entry_after,
        instructions_field_existed_before,
        instruction_entry_existed_before,
        instruction_entry_after,
        owned_paths,
    };
    if !dry_run {
        atomic_write_json(&target.join(OPENCODE_GLOBAL_MANIFEST), &manifest)?;
    }
    Ok(outcome)
}

pub(super) struct OpenCodeConfigMerge {
    pub(super) bytes: Vec<u8>,
    pub(super) mcp_field_existed_before: bool,
    pub(super) mcp_entry_before: Option<Value>,
    pub(super) instructions_field_existed_before: bool,
    pub(super) instruction_entry_existed_before: bool,
}

pub(super) fn default_opencode_config_bytes() -> Vec<u8> {
    b"{\n  \"$schema\": \"https://opencode.ai/config.json\"\n}\n".to_vec()
}

pub(super) fn parse_opencode_jsonc(bytes: &[u8]) -> Result<CstRootNode> {
    let text = std::str::from_utf8(bytes).context("OpenCode config must be UTF-8")?;
    CstRootNode::parse(text, &ParseOptions::default()).context("parse OpenCode JSONC config")
}

pub(super) fn merge_opencode_mcp_config(
    bytes: &[u8],
    entry: &Value,
    instruction_entry: &str,
) -> Result<OpenCodeConfigMerge> {
    let root = parse_opencode_jsonc(bytes)?;
    let root_object = root
        .object_value()
        .context("OpenCode global config root must be an object")?;
    let mcp_field_existed_before = root_object.get("mcp").is_some();
    let mcp = root_object
        .object_value_or_create("mcp")
        .context("OpenCode global config mcp field must be an object")?;
    let mcp_entry_before = mcp
        .get("eliot")
        .and_then(|property| property.to_serde_value());
    match mcp.get("eliot") {
        Some(property) => property.set_value(json_to_cst_input(entry)),
        None => {
            mcp.append("eliot", json_to_cst_input(entry));
        }
    }
    let instructions_field_existed_before = root_object.get("instructions").is_some();
    let instruction_entry_existed_before = root_object
        .get("instructions")
        .and_then(|property| property.to_serde_value())
        .and_then(|value| value.as_array().cloned())
        .is_some_and(|values| {
            values
                .iter()
                .any(|value| value.as_str() == Some(instruction_entry))
        });
    match root_object.get("instructions") {
        Some(property) => {
            let mut instructions = property
                .to_serde_value()
                .and_then(|value| value.as_array().cloned())
                .context("OpenCode global config instructions field must be an array")?;
            if !instruction_entry_existed_before {
                instructions.push(Value::String(instruction_entry.to_owned()));
                property.set_value(json_to_cst_input(&Value::Array(instructions)));
            }
        }
        None => {
            root_object.append(
                "instructions",
                json_to_cst_input(&json!([instruction_entry])),
            );
        }
    }
    Ok(OpenCodeConfigMerge {
        bytes: root.to_string().into_bytes(),
        mcp_field_existed_before,
        mcp_entry_before,
        instructions_field_existed_before,
        instruction_entry_existed_before,
    })
}

pub(super) fn remove_opencode_mcp_config(
    bytes: &[u8],
    mcp_entry_before: Option<&Value>,
    mcp_field_existed_before: bool,
    instruction_entry: &str,
    instructions_field_existed_before: bool,
    instruction_entry_existed_before: bool,
) -> Result<Vec<u8>> {
    let root = parse_opencode_jsonc(bytes)?;
    let root_object = root
        .object_value()
        .context("OpenCode global config root must be an object")?;
    let mcp_property = root_object
        .get("mcp")
        .context("OpenCode global config mcp field is missing")?;
    let mcp = mcp_property
        .object_value()
        .context("OpenCode global config mcp field is no longer an object")?;
    let eliot = mcp
        .get("eliot")
        .context("OpenCode global config mcp.eliot is missing")?;
    if let Some(before) = mcp_entry_before {
        eliot.set_value(json_to_cst_input(before));
    } else {
        eliot.remove();
        if !mcp_field_existed_before && mcp.properties().is_empty() {
            mcp_property.remove();
        }
    }
    if !instruction_entry.is_empty() && !instruction_entry_existed_before {
        let instructions_property = root_object
            .get("instructions")
            .context("OpenCode global config instructions field is missing")?;
        let mut instructions = instructions_property
            .to_serde_value()
            .and_then(|value| value.as_array().cloned())
            .context("OpenCode global config instructions field is no longer an array")?;
        let before_len = instructions.len();
        instructions.retain(|value| value.as_str() != Some(instruction_entry));
        if instructions.len() == before_len {
            bail!("OpenCode Eliot instruction entry is missing");
        }
        if !instructions_field_existed_before && instructions.is_empty() {
            instructions_property.remove();
        } else {
            instructions_property.set_value(json_to_cst_input(&Value::Array(instructions)));
        }
    }
    Ok(root.to_string().into_bytes())
}

pub(super) fn json_to_cst_input(value: &Value) -> CstInputValue {
    match value {
        Value::Null => CstInputValue::Null,
        Value::Bool(value) => CstInputValue::Bool(*value),
        Value::Number(value) => CstInputValue::Number(value.to_string()),
        Value::String(value) => CstInputValue::String(value.clone()),
        Value::Array(values) => {
            CstInputValue::Array(values.iter().map(json_to_cst_input).collect())
        }
        Value::Object(values) => CstInputValue::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), json_to_cst_input(value)))
                .collect(),
        ),
    }
}

pub(super) fn install_owned_path(
    source: &Path,
    destination: &Path,
    previous: Option<&OpenCodeGlobalInstallManifest>,
    dry_run: bool,
) -> Result<(OpenCodeOwnedPath, bool)> {
    let installed_hash = hash_owned_path(source)?;
    let current_hash = destination
        .exists()
        .then(|| hash_owned_path(destination))
        .transpose()?;
    let previous_owned = previous.and_then(|manifest| {
        manifest
            .owned_paths
            .iter()
            .find(|owned| owned.path == destination)
    });
    let continuing_owned = previous_owned
        .is_some_and(|owned| current_hash.as_deref() == Some(owned.installed_hash.as_str()));
    let backup_ref = if continuing_owned {
        previous_owned.and_then(|owned| owned.backup_ref.clone())
    } else if destination.exists() {
        Some(global_backup_path(
            destination
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("opencode-owned-path"),
            destination.extension(),
        )?)
    } else {
        None
    };
    let changed = current_hash.as_deref() != Some(installed_hash.as_str());
    if !dry_run && changed {
        if let Some(backup) = &backup_ref
            && !continuing_owned
        {
            std::fs::create_dir_all(backup.parent().context("backup has no parent")?)?;
            std::fs::rename(destination, backup)?;
        } else if destination.exists() {
            remove_owned_path(destination)?;
        }
        copy_owned_path(source, destination)?;
    }
    Ok((
        OpenCodeOwnedPath {
            path: destination.to_path_buf(),
            installed_hash,
            backup_ref,
        },
        changed,
    ))
}

pub(super) fn record_owned_outcome(
    outcome: &mut GlobalInstallOutcome,
    owned: &OpenCodeOwnedPath,
    destination: &Path,
    changed: bool,
) {
    outcome
        .installed_paths
        .push(destination.to_string_lossy().into_owned());
    if changed {
        outcome
            .modified_files
            .push(destination.to_string_lossy().into_owned());
    }
    if let Some(backup) = &owned.backup_ref {
        outcome
            .backup_refs
            .push(backup.to_string_lossy().into_owned());
    }
}

pub(super) fn install_claude_global(
    repo: &Path,
    source: &Path,
    target: &Path,
    governor: &Path,
    previous: Option<&ClaudeGlobalInstallManifest>,
    dry_run: bool,
) -> Result<GlobalInstallOutcome> {
    const MARKETPLACE_NAME: &str = "eliot-local";
    const PLUGIN_ID: &str = "eliot@eliot-local";

    let profile = HostProfileService.probe(AgentHostId::Claude)?;
    let claude = PathBuf::from(&profile.executable_path);
    let package_root = claude_package_cache_root();
    let marketplace_root = package_root.join("claude-code-marketplace");
    let legacy_destination = claude_global_plugin_path()?;
    let mut outcome = GlobalInstallOutcome::default();
    outcome
        .installed_paths
        .push(marketplace_root.to_string_lossy().into_owned());

    if dry_run {
        outcome
            .installed_paths
            .push(format!("official-plugin:{PLUGIN_ID}"));
        return Ok(outcome);
    }

    let artifact =
        build_claude_marketplace(repo, source, governor, &marketplace_root, MARKETPLACE_NAME)?;
    let installed = install_official_claude_plugin(
        &claude,
        &marketplace_root,
        MARKETPLACE_NAME,
        PLUGIN_ID,
        &artifact.version,
        governor,
    )?;
    let legacy_direct_backup =
        retire_legacy_claude_plugin(&claude, &legacy_destination, previous, &mut outcome)?;

    let manifest = ClaudeGlobalInstallManifest {
        schema_version: "eliot-claude-global-install-v3".to_owned(),
        source_plugin_path: source.to_path_buf(),
        source_bundle_hash: bundle_hash(source, AgentHostId::Claude)?,
        target_plugin_path: installed.path.clone(),
        governor_source_path: governor.to_path_buf(),
        governor_sha256: installed.governor_sha256.clone(),
        installed_governor_path: installed.governor,
        installed_governor_sha256: installed.governor_sha256,
        generated_at: OffsetDateTime::now_utc().to_string(),
        legacy_owned_plugin: None,
        legacy_direct_backup,
        marketplace_name: MARKETPLACE_NAME.to_owned(),
        marketplace_root: marketplace_root.clone(),
        plugin_id: PLUGIN_ID.to_owned(),
        plugin_version: artifact.version,
        artifact_hash: artifact.hash,
        source_commit: artifact.source_commit,
        claude_executable: claude,
        claude_version: profile.version,
    };
    atomic_write_json(&target.join(CLAUDE_GLOBAL_MANIFEST), &manifest)?;
    outcome
        .installed_paths
        .push(installed.path.to_string_lossy().into_owned());
    outcome
        .modified_files
        .push(marketplace_root.to_string_lossy().into_owned());
    outcome
        .modified_files
        .push(format!("official-plugin:{PLUGIN_ID}"));
    Ok(outcome)
}

struct InstalledClaudePlugin {
    path: PathBuf,
    governor: PathBuf,
    governor_sha256: String,
}

fn install_official_claude_plugin(
    claude: &Path,
    marketplace_root: &Path,
    marketplace_name: &str,
    plugin_id: &str,
    expected_version: &str,
    governor: &Path,
) -> Result<InstalledClaudePlugin> {
    claude_cli_checked(
        claude,
        &[
            "plugin",
            "validate",
            "--strict",
            &path_arg(marketplace_root),
        ],
    )?;
    let marketplaces = claude_cli_json(claude, &["plugin", "marketplace", "list", "--json"])?;
    let registered = marketplaces.as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry.get("name").and_then(Value::as_str) == Some(marketplace_name))
    });
    if registered {
        claude_cli_checked(
            claude,
            &["plugin", "marketplace", "update", marketplace_name],
        )?;
    } else {
        claude_cli_checked(
            claude,
            &["plugin", "marketplace", "add", &path_arg(marketplace_root)],
        )?;
    }
    if claude_installed_plugin(claude, plugin_id)?.is_some() {
        claude_cli_checked(claude, &["plugin", "update", plugin_id])?;
    } else {
        claude_cli_checked(claude, &["plugin", "install", plugin_id, "--scope", "user"])?;
    }
    let mut installed = claude_installed_plugin(claude, plugin_id)?
        .context("Claude reported success but the official Eliot plugin is not installed")?;
    if installed.get("enabled").and_then(Value::as_bool) != Some(true) {
        claude_cli_checked(claude, &["plugin", "enable", plugin_id, "--scope", "user"])?;
        installed = claude_installed_plugin(claude, plugin_id)?
            .context("Claude enabled Eliot but no longer reports the plugin")?;
    }
    let installed_version = installed
        .get("version")
        .and_then(Value::as_str)
        .context("installed Claude Eliot plugin has no version")?;
    if installed_version != expected_version {
        bail!(
            "installed Claude Eliot plugin version {installed_version} differs from generated {expected_version}"
        );
    }
    if installed.get("enabled").and_then(Value::as_bool) != Some(true) {
        bail!("the official Claude Eliot plugin is installed but not enabled");
    }
    let path = PathBuf::from(
        installed
            .get("installPath")
            .and_then(Value::as_str)
            .context("installed Claude Eliot plugin has no installPath")?,
    );
    let installed_governor = path.join("bin").join("eliot-governor.exe");
    let governor_sha256 = sha256_file(governor)?;
    let installed_governor_sha256 = sha256_file(&installed_governor)
        .context("official Claude Eliot plugin is missing its Governor binary")?;
    if installed_governor_sha256 != governor_sha256 {
        bail!("official Claude Eliot plugin Governor differs from the current binary");
    }
    Ok(InstalledClaudePlugin {
        path,
        governor: installed_governor,
        governor_sha256,
    })
}

fn retire_legacy_claude_plugin(
    claude: &Path,
    destination: &Path,
    previous: Option<&ClaudeGlobalInstallManifest>,
    outcome: &mut GlobalInstallOutcome,
) -> Result<Option<PathBuf>> {
    if !destination.exists() {
        return Ok(previous.and_then(|manifest| manifest.legacy_direct_backup.clone()));
    }
    let owned = previous
        .and_then(|manifest| manifest.legacy_owned_plugin.as_ref())
        .context("refuse to remove an unowned Claude skills-dir plugin")?;
    let governor = destination.join("bin").join("eliot-governor.exe");
    let current_hash = claude_plugin_hash(destination, &governor)?;
    if owned.path != destination || owned.installed_hash != current_hash {
        bail!("refuse to remove the changed Claude skills-dir plugin");
    }
    claude_cli_checked(
        claude,
        &["plugin", "disable", "eliot@skills-dir", "--scope", "user"],
    )?;
    let backup = global_backup_path("claude-legacy-skills-dir", None)?;
    std::fs::create_dir_all(backup.parent().context("backup has no parent")?)?;
    std::fs::rename(destination, &backup)?;
    outcome
        .backup_refs
        .push(backup.to_string_lossy().into_owned());
    Ok(Some(backup))
}

struct ClaudeMarketplaceArtifact {
    version: String,
    hash: String,
    source_commit: String,
}

fn build_claude_marketplace(
    repo: &Path,
    source: &Path,
    governor: &Path,
    destination: &Path,
    marketplace_name: &str,
) -> Result<ClaudeMarketplaceArtifact> {
    let package_root = claude_package_cache_root();
    ensure_child(&package_root, destination)?;
    std::fs::create_dir_all(&package_root)?;
    let staging = package_root.join(format!(
        ".claude-code-marketplace-{}-staging",
        Uuid::new_v4()
    ));
    ensure_child(&package_root, &staging)?;
    let plugin = staging.join("plugins").join("eliot");
    copy_tree(source, &plugin, AgentHostId::Claude)?;
    std::fs::create_dir_all(plugin.join("bin"))?;
    std::fs::copy(governor, plugin.join("bin").join("eliot-governor.exe"))?;

    let plugin_manifest_path = plugin.join(".claude-plugin").join("plugin.json");
    let mut plugin_manifest: Value =
        serde_json::from_slice(&std::fs::read(&plugin_manifest_path)?)?;
    let base_version = plugin_manifest
        .get("version")
        .and_then(Value::as_str)
        .context("Claude plugin source version is missing")?;
    let source_hash = bundle_hash(source, AgentHostId::Claude)?;
    let governor_hash = sha256_file(governor)?;
    let version = format!(
        "{base_version}+{}.{}",
        short_hash(&source_hash),
        short_hash(&governor_hash)
    );
    plugin_manifest["version"] = Value::String(version.clone());
    atomic_write_json(&plugin_manifest_path, &plugin_manifest)?;

    let source_commit = git_head(repo)?;
    let marketplace = json!({
        "name": marketplace_name,
        "owner": { "name": "ELIOT Project" },
        "description": "Local deterministic marketplace for the private pre-alpha ELIOT Claude Code plugin.",
        "version": version,
        "plugins": [{
            "name": "eliot",
            "source": "./plugins/eliot",
            "description": plugin_manifest["description"],
            "version": plugin_manifest["version"],
            "author": plugin_manifest["author"],
            "homepage": plugin_manifest["homepage"],
            "repository": plugin_manifest["repository"],
            "license": plugin_manifest["license"],
            "strict": true
        }]
    });
    atomic_write_json(
        &staging.join(".claude-plugin").join("marketplace.json"),
        &marketplace,
    )?;
    let hash = claude_plugin_hash(&plugin, &plugin.join("bin").join("eliot-governor.exe"))?;
    atomic_write_json(
        &staging.join("build-receipt.json"),
        &json!({
            "schema_version": "eliot-claude-code-marketplace-build-v1",
            "plugin_version": version,
            "source_commit": source_commit,
            "source_bundle_hash": source_hash,
            "governor_sha256": governor_hash,
            "artifact_hash": hash,
            "generated_at": OffsetDateTime::now_utc()
        }),
    )?;

    let replaced = package_root.join(format!(
        ".claude-code-marketplace-{}-replaced",
        Uuid::new_v4()
    ));
    if destination.exists() {
        std::fs::rename(destination, &replaced)?;
    }
    std::fs::rename(&staging, destination)?;
    if replaced.exists() {
        remove_owned_path(&replaced)?;
    }
    Ok(ClaudeMarketplaceArtifact {
        version,
        hash,
        source_commit,
    })
}

fn short_hash(value: &str) -> &str {
    value.get(..12).unwrap_or(value)
}

fn git_head(repo: &Path) -> Result<String> {
    let output = StdCommand::new("git")
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "HEAD"])
        .output()
        .context("read canonical source commit for Claude plugin package")?;
    if !output.status.success() {
        bail!("git rev-parse failed while packaging the Claude plugin");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn claude_cli_checked(claude: &Path, args: &[&str]) -> Result<String> {
    let output = StdCommand::new(claude)
        .args(args)
        .output()
        .with_context(|| format!("run Claude Code plugin command: {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "Claude Code plugin command failed: {}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn claude_cli_json(claude: &Path, args: &[&str]) -> Result<Value> {
    let stdout = claude_cli_checked(claude, args)?;
    serde_json::from_str(&stdout)
        .with_context(|| format!("parse Claude Code JSON output for {}", args.join(" ")))
}

fn claude_installed_plugin(claude: &Path, plugin_id: &str) -> Result<Option<Value>> {
    let plugins = claude_cli_json(claude, &["plugin", "list", "--json"])?;
    Ok(plugins.as_array().and_then(|entries| {
        entries
            .iter()
            .find(|entry| entry.get("id").and_then(Value::as_str) == Some(plugin_id))
            .cloned()
    }))
}

pub(super) fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("open {} for SHA-256", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub(super) fn opencode_global_root() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("USERPROFILE").context("USERPROFILE is not set")?)
            .join(".config")
            .join("opencode"),
    )
}

pub(super) fn opencode_global_config_path(root: &Path) -> PathBuf {
    let jsonc = root.join("opencode.jsonc");
    if jsonc.is_file() {
        jsonc
    } else {
        root.join("opencode.json")
    }
}

pub(super) fn global_backup_path(
    label: &str,
    extension: Option<&std::ffi::OsStr>,
) -> Result<PathBuf> {
    let mut name = format!(".{label}-{}-backup", Uuid::new_v4());
    if let Some(extension) = extension.and_then(|value| value.to_str()) {
        name.push('.');
        name.push_str(extension);
    }
    Ok(install_base()?.join("global-backups").join(name))
}

pub(super) fn copy_owned_path(source: &Path, destination: &Path) -> Result<()> {
    if source.is_dir() {
        copy_tree(source, destination, AgentHostId::OpenCode)
    } else {
        std::fs::create_dir_all(destination.parent().context("destination has no parent")?)?;
        std::fs::copy(source, destination)?;
        Ok(())
    }
}

pub(super) fn remove_owned_path(path: &Path) -> Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)?;
    } else if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

pub(super) fn hash_owned_path(path: &Path) -> Result<String> {
    if path.is_file() {
        return bundle_hash_single(path);
    }
    let mut files = Vec::new();
    collect_owned_files(path, path, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = blake3::Hasher::new();
    for (relative, file) in files {
        hasher.update(relative.as_bytes());
        hasher.update(&[0]);
        hasher.update(&std::fs::read(file)?);
        hasher.update(&[0]);
    }
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

pub(super) fn codex_cache_contract_hash(path: &Path) -> Result<String> {
    ensure!(
        path.is_dir(),
        "Codex cache contract root must be a directory: {}",
        path.display()
    );
    let mut files = Vec::new();
    collect_owned_files(path, path, &mut files)?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    let mut hasher = blake3::Hasher::new();
    for (relative, file) in files {
        hasher.update(relative.as_bytes());
        hasher.update(&[0]);
        hasher.update(&std::fs::read(file)?);
        hasher.update(&[0]);
    }
    Ok(format!("blake3:{}", hasher.finalize().to_hex()))
}

pub(super) fn collect_owned_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<(String, PathBuf)>,
) -> Result<()> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            bail!("OpenCode global integration path may not contain symlinks");
        }
        if kind.is_dir() {
            collect_owned_files(root, &entry.path(), files)?;
        } else if kind.is_file() {
            files.push((
                entry
                    .path()
                    .strip_prefix(root)?
                    .to_string_lossy()
                    .replace('\\', "/"),
                entry.path(),
            ));
        }
    }
    Ok(())
}

pub(super) fn bytes_hash(bytes: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(bytes).to_hex())
}

#[allow(clippy::too_many_lines)]
pub(super) fn uninstall_codex_global(
    manifest: &CodexGlobalInstallManifest,
    dry_run: bool,
) -> Result<Value> {
    let plugin_path = codex_plugin_root()?;
    let marketplace_path = codex_marketplace_path()?;
    ensure!(
        manifest.installed_plugin.path == plugin_path,
        "Codex install manifest does not own {}",
        plugin_path.display()
    );
    ensure!(
        manifest.installed_governor_path == plugin_path.join("bin").join("eliot-governor.exe"),
        "Codex install manifest contains an unexpected Governor path"
    );
    ensure!(
        manifest.marketplace_path == marketplace_path,
        "Codex install manifest contains an unexpected marketplace path"
    );
    let original_plugin_before_hash = codex_original_plugin_hash(Some(manifest), None)?;
    let plugin_current_hash = plugin_path
        .exists()
        .then(|| hash_owned_path(&plugin_path))
        .transpose()?;
    let plugin_is_installed =
        plugin_current_hash.as_deref() == Some(manifest.installed_plugin.installed_hash.as_str());
    let plugin_is_restored = codex_plugin_path_is_restored(
        plugin_current_hash.as_deref(),
        original_plugin_before_hash.as_deref(),
    );
    let validated_plugin_backup = if original_plugin_before_hash.is_some()
        && (plugin_is_installed || plugin_current_hash.is_none())
    {
        let backup = manifest
            .installed_plugin
            .backup_ref
            .as_ref()
            .context("Codex plugin restore requires its ownership backup")?;
        let backup_root = install_base()?.join("global-backups");
        ensure_child(&backup_root, backup)?;
        let metadata = std::fs::symlink_metadata(backup)
            .with_context(|| format!("inspect Codex plugin backup {}", backup.display()))?;
        ensure!(
            !metadata.file_type().is_symlink() && (metadata.is_dir() || metadata.is_file()),
            "Codex plugin backup must be a regular owned path: {}",
            backup.display()
        );
        ensure!(
            Some(hash_owned_path(backup)?.as_str()) == original_plugin_before_hash.as_deref(),
            "Codex plugin backup does not match the pre-install hash"
        );
        Some(backup)
    } else {
        None
    };
    ensure!(
        plugin_is_installed || plugin_is_restored || validated_plugin_backup.is_some(),
        "Codex plugin path contains unknown content; refusing uninstall"
    );
    if plugin_is_installed {
        ensure!(
            sha256_file(&manifest.installed_governor_path)? == manifest.installed_governor_sha256,
            "installed Codex Governor changed after install; refusing to remove it"
        );
    }

    let mut marketplace_owned = false;
    let mut marketplace_already_restored =
        !marketplace_path.exists() && !manifest.marketplace_existed_before;
    let mut restored_marketplace = None;
    let mut exact_marketplace_state = false;
    if marketplace_path.exists() {
        let metadata = std::fs::symlink_metadata(&marketplace_path)?;
        ensure!(
            !metadata.file_type().is_symlink() && metadata.is_file(),
            "Codex personal marketplace must be a regular file"
        );
        let bytes = std::fs::read(&marketplace_path)?;
        exact_marketplace_state = bytes_hash(&bytes) == manifest.marketplace_after_hash;
        let marketplace: Value =
            serde_json::from_slice(&bytes).context("parse Codex personal marketplace")?;
        let current_entry = marketplace
            .get("plugins")
            .and_then(Value::as_array)
            .and_then(|plugins| {
                let indices = codex_plugin_indices(plugins);
                (indices.len() == 1).then(|| plugins[indices[0]].clone())
            });
        marketplace_owned = current_entry.as_ref() == Some(&manifest.marketplace_entry_after);
        marketplace_already_restored = current_entry.as_ref()
            == manifest.marketplace_entry_before.as_ref()
            || (current_entry.is_none() && manifest.marketplace_entry_before.is_none());
        ensure!(
            marketplace_owned || marketplace_already_restored,
            "Codex marketplace entry contains unknown content; refusing uninstall"
        );
        if marketplace_owned {
            restored_marketplace = Some(remove_codex_marketplace_entry(
                marketplace,
                &manifest.marketplace_entry_after,
                manifest.marketplace_entry_before.as_ref(),
                manifest.marketplace_entry_before_index,
                manifest.marketplace_plugins_field_existed_before,
            )?);
        }
    }
    ensure!(
        marketplace_path.exists() || !manifest.marketplace_existed_before,
        "Codex marketplace that existed before install is missing; refusing uninstall"
    );
    let codex = if manifest.codex_cli_path.is_file() {
        manifest.codex_cli_path.clone()
    } else {
        crate::dogfood::find_codex_cli()
            .context("locate installed Codex CLI for official plugin uninstall")?
    };
    ensure!(
        codex
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.eq_ignore_ascii_case("codex.exe")),
        "Codex plugin lifecycle executable must be codex.exe"
    );
    let plugin_lifecycle_state =
        codex_plugin_installed_enabled(&codex_plugin_list(&codex)?, &manifest.plugin_selector);
    if !manifest.plugin_installed_before && plugin_lifecycle_state.is_some() {
        let cache_contract_hash =
            codex_manifest_cache_contract_hash(manifest, &manifest.installed_plugin.path)?;
        let expected = CodexPluginExpectation {
            selector: &manifest.plugin_selector,
            version: &manifest.plugin_version,
            source_path: &manifest.installed_plugin.path,
            cache_contract_hash: &cache_contract_hash,
            installed_governor: &manifest.installed_governor_path,
            installed_governor_sha256: &manifest.installed_governor_sha256,
        };
        ensure!(
            codex_plugin_lifecycle_is_fresh(&codex, &codex_plugin_list(&codex)?, &expected)?,
            "Codex lifecycle entry changed after install; refusing removal"
        );
    }
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-codex-global-uninstall-v1",
            "dry_run": true,
            "plugin_path": plugin_path,
            "marketplace_path": marketplace_path,
            "exact_marketplace_state": exact_marketplace_state,
            "plugin_selector": manifest.plugin_selector,
            "plugin_will_be_removed": !manifest.plugin_installed_before && plugin_lifecycle_state.is_some(),
            "plugin_files_already_restored": plugin_is_restored,
            "marketplace_already_restored": marketplace_already_restored,
            "legacy_direct_mcp_will_be_restored": false,
            "provider_auth_modified": false,
            "project_config_modified": false,
            "unrelated_config_preserved": true
        }));
    }

    if !manifest.plugin_installed_before {
        remove_codex_plugin_lifecycle(&codex, &manifest.plugin_selector)?;
    }
    if marketplace_owned {
        if !manifest.marketplace_existed_before && exact_marketplace_state {
            std::fs::remove_file(&marketplace_path)?;
        } else if let Some(restored) = restored_marketplace {
            atomic_write_json(&marketplace_path, &restored)?;
        }
    }
    if plugin_is_installed {
        remove_owned_path(&plugin_path)?;
    }
    if original_plugin_before_hash.is_some() && !plugin_path.exists() {
        let backup = validated_plugin_backup
            .context("Codex plugin restore requires its validated ownership backup")?;
        std::fs::rename(backup, &plugin_path)?;
        let restored_hash = hash_owned_path(&plugin_path)?;
        ensure!(
            Some(restored_hash.as_str()) == original_plugin_before_hash.as_deref(),
            "restored Codex plugin does not match its pre-install hash"
        );
    }
    Ok(json!({
        "schema_version": "eliot-codex-global-uninstall-v1",
        "dry_run": false,
        "plugin_path": plugin_path,
        "marketplace_path": marketplace_path,
        "exact_marketplace_restore": !manifest.marketplace_existed_before && exact_marketplace_state,
        "preexisting_plugin_restored": manifest.installed_plugin.backup_ref.is_some(),
        "plugin_selector": manifest.plugin_selector,
        "plugin_lifecycle_removed": !manifest.plugin_installed_before,
        "legacy_direct_mcp_restored": false,
        "provider_auth_modified": false,
        "project_config_modified": false,
        "unrelated_config_preserved": true
    }))
}

pub(super) fn uninstall_claude_global(
    manifest: &ClaudeGlobalInstallManifest,
    dry_run: bool,
) -> Result<Value> {
    if !manifest.marketplace_name.is_empty() && !manifest.plugin_id.is_empty() {
        return uninstall_claude_marketplace(manifest, dry_run);
    }

    uninstall_legacy_claude_global(manifest, dry_run)
}

fn uninstall_claude_marketplace(
    manifest: &ClaudeGlobalInstallManifest,
    dry_run: bool,
) -> Result<Value> {
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-claude-global-uninstall-v2",
            "dry_run": true,
            "plugin_id": manifest.plugin_id,
            "marketplace_name": manifest.marketplace_name,
            "marketplace_root": manifest.marketplace_root,
            "mechanism": "official Claude Code plugin CLI",
            "provider_auth_modified": false,
            "settings_modified_outside_official_plugin_state": false,
            "unrelated_config_preserved": true
        }));
    }
    claude_cli_checked(
        &manifest.claude_executable,
        &[
            "plugin",
            "uninstall",
            &manifest.plugin_id,
            "--scope",
            "user",
        ],
    )?;
    claude_cli_checked(
        &manifest.claude_executable,
        &[
            "plugin",
            "marketplace",
            "remove",
            &manifest.marketplace_name,
        ],
    )?;
    let package_root = claude_package_cache_root();
    ensure_child(&package_root, &manifest.marketplace_root)?;
    if manifest.marketplace_root.is_dir() {
        let marketplace: Value = serde_json::from_slice(&std::fs::read(
            manifest
                .marketplace_root
                .join(".claude-plugin")
                .join("marketplace.json"),
        )?)?;
        if marketplace.get("name").and_then(Value::as_str)
            != Some(manifest.marketplace_name.as_str())
        {
            bail!("refuse to remove a marketplace directory with a different identity");
        }
        remove_owned_path(&manifest.marketplace_root)?;
    }
    Ok(json!({
        "schema_version": "eliot-claude-global-uninstall-v2",
        "dry_run": false,
        "plugin_id": manifest.plugin_id,
        "marketplace_name": manifest.marketplace_name,
        "marketplace_root": manifest.marketplace_root,
        "removed_through_official_cli": true,
        "legacy_direct_backup_preserved": manifest.legacy_direct_backup,
        "provider_auth_modified": false,
        "settings_modified_outside_official_plugin_state": false,
        "unrelated_config_preserved": true
    }))
}

fn uninstall_legacy_claude_global(
    manifest: &ClaudeGlobalInstallManifest,
    dry_run: bool,
) -> Result<Value> {
    let owned = manifest.legacy_owned_plugin.as_ref().context(
        "Claude install manifest has neither official marketplace state nor a legacy owned plugin",
    )?;
    let governor = owned.path.join("bin").join("eliot-governor.exe");
    if !owned.path.is_dir() || !governor.is_file() {
        bail!(
            "refuse Claude rollback because the owned plugin is missing: {}",
            owned.path.display()
        );
    }
    let current_hash = claude_plugin_hash(&owned.path, &governor)?;
    if current_hash != owned.installed_hash {
        bail!(
            "refuse Claude rollback because the owned plugin changed after install: {}",
            owned.path.display()
        );
    }
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-claude-global-uninstall-v1",
            "dry_run": true,
            "plugin_path": owned.path,
            "provider_auth_modified": false,
            "settings_modified": false,
            "unrelated_config_preserved": true
        }));
    }

    remove_owned_path(&owned.path)?;
    if let Some(backup) = &owned.backup_ref {
        std::fs::create_dir_all(
            owned
                .path
                .parent()
                .context("Claude plugin restore path has no parent")?,
        )?;
        std::fs::rename(backup, &owned.path)?;
    }
    Ok(json!({
        "schema_version": "eliot-claude-global-uninstall-v1",
        "dry_run": false,
        "plugin_path": owned.path,
        "plugin_restored": owned.backup_ref.is_some(),
        "provider_auth_modified": false,
        "settings_modified": false,
        "unrelated_config_preserved": true
    }))
}

#[allow(clippy::too_many_lines)]
pub(super) fn uninstall_opencode_global(
    manifest: &OpenCodeGlobalInstallManifest,
    dry_run: bool,
) -> Result<Value> {
    for owned in &manifest.owned_paths {
        let current_hash = owned
            .path
            .exists()
            .then(|| hash_owned_path(&owned.path))
            .transpose()?
            .with_context(|| {
                format!(
                    "refuse OpenCode rollback because owned path is missing: {}",
                    owned.path.display()
                )
            })?;
        if current_hash != owned.installed_hash {
            bail!(
                "refuse OpenCode rollback because owned path changed after install: {}",
                owned.path.display()
            );
        }
    }
    let current_bytes = std::fs::read(&manifest.config_path).with_context(|| {
        format!(
            "refuse OpenCode rollback because config is missing: {}",
            manifest.config_path.display()
        )
    })?;
    let current_root = parse_opencode_jsonc(&current_bytes).with_context(|| {
        format!(
            "refuse OpenCode rollback because config is no longer valid JSONC: {}",
            manifest.config_path.display()
        )
    })?;
    let current_eliot = current_root
        .object_value()
        .and_then(|root| root.object_value("mcp"))
        .and_then(|mcp| mcp.get("eliot"))
        .and_then(|property| property.to_serde_value());
    if current_eliot.as_ref() != Some(&manifest.mcp_entry_after) {
        bail!("refuse OpenCode rollback because mcp.eliot changed after install");
    }
    if !manifest.instruction_entry_after.is_empty() {
        let current_instructions = current_root
            .object_value()
            .and_then(|root| root.get("instructions"))
            .and_then(|property| property.to_serde_value())
            .and_then(|value| value.as_array().cloned())
            .context("refuse OpenCode rollback because instructions is missing or invalid")?;
        if !current_instructions
            .iter()
            .any(|value| value.as_str() == Some(manifest.instruction_entry_after.as_str()))
        {
            bail!("refuse OpenCode rollback because the Eliot instruction entry changed");
        }
    }
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-opencode-global-uninstall-v1",
            "dry_run": true,
            "config_path": manifest.config_path,
            "owned_paths": manifest.owned_paths,
            "provider_auth_modified": false,
            "unrelated_config_preserved": true
        }));
    }

    for owned in &manifest.owned_paths {
        remove_owned_path(&owned.path)?;
        if let Some(backup) = &owned.backup_ref {
            std::fs::create_dir_all(
                owned
                    .path
                    .parent()
                    .context("owned restore path has no parent")?,
            )?;
            std::fs::rename(backup, &owned.path)?;
        }
    }

    let current_hash = bytes_hash(&current_bytes);
    let exact_restore = current_hash == manifest.config_after_hash;
    if exact_restore {
        std::fs::remove_file(&manifest.config_path)?;
        if manifest.config_existed {
            let backup = manifest
                .config_backup_ref
                .as_ref()
                .context("OpenCode config backup is missing from install manifest")?;
            std::fs::create_dir_all(
                manifest
                    .config_path
                    .parent()
                    .context("config restore path has no parent")?,
            )?;
            std::fs::rename(backup, &manifest.config_path)?;
        }
    } else {
        let restored = remove_opencode_mcp_config(
            &current_bytes,
            manifest.mcp_entry_before.as_ref(),
            manifest.mcp_field_existed_before,
            &manifest.instruction_entry_after,
            manifest.instructions_field_existed_before,
            manifest.instruction_entry_existed_before,
        )?;
        atomic_write_bytes(&manifest.config_path, &restored)?;
    }
    Ok(json!({
        "schema_version": "eliot-opencode-global-uninstall-v1",
        "dry_run": false,
        "config_path": manifest.config_path,
        "exact_config_restore": exact_restore,
        "owned_paths_restored": manifest.owned_paths.len(),
        "provider_auth_modified": false,
        "unrelated_config_preserved": true
    }))
}

pub(super) fn uninstall(config_path: &Path, host: AgentHostId, dry_run: bool) -> Result<Value> {
    ensure_installable_host(host)?;
    let base = install_base()?;
    let target = base.join(host.as_str());
    ensure_child(&base, &target)?;
    let _codex_lock = (host == AgentHostId::Codex)
        .then(acquire_codex_operation_lock)
        .transpose()?;
    let codex_tombstone_recovered = if host == AgentHostId::Codex {
        let recovered = cleanup_codex_uninstall_tombstone(dry_run)?;
        let _ = recover_codex_install_transaction(&target, dry_run)?;
        recovered
    } else {
        false
    };
    let receipt_path = install_receipt_path(config_path, host);
    let recorded: HostIntegrationReceipt = serde_json::from_reader(
        std::fs::File::open(&receipt_path)
            .with_context(|| format!("read install receipt {}", receipt_path.display()))?,
    )?;
    if !recorded
        .installed_paths
        .iter()
        .any(|path| Path::new(path) == target)
    {
        bail!(
            "install receipt does not authorize removal of {}",
            target.display()
        );
    }
    let global_uninstall = match host {
        AgentHostId::OpenCode => {
            let manifest = read_opencode_global_manifest(&target)?.context(
                "OpenCode install receipt predates global discovery ownership; reinstall before uninstall",
            )?;
            Some(uninstall_opencode_global(&manifest, dry_run)?)
        }
        AgentHostId::Claude => {
            let manifest = read_claude_global_manifest(&target)?.context(
                "Claude install receipt predates global discovery ownership; reinstall before uninstall",
            )?;
            Some(uninstall_claude_global(&manifest, dry_run)?)
        }
        AgentHostId::Codex => {
            if target.exists() {
                let manifest = read_codex_global_manifest(&target)?.context(
                    "Codex install receipt predates personal-marketplace ownership; reinstall before uninstall",
                )?;
                Some(uninstall_codex_global(&manifest, dry_run)?)
            } else {
                Some(json!({
                    "schema_version": "eliot-codex-global-uninstall-v1",
                    "dry_run": dry_run,
                    "already_removed": true,
                    "legacy_direct_mcp_restored": false
                }))
            }
        }
        AgentHostId::Antigravity => None,
    };
    let existed = target.is_dir();
    if existed && !dry_run {
        if host == AgentHostId::Codex {
            let tombstone = codex_uninstall_tombstone_path()?;
            ensure_child(&base, &tombstone)?;
            ensure!(
                !tombstone.exists(),
                "Codex uninstall tombstone unexpectedly exists: {}",
                tombstone.display()
            );
            std::fs::rename(&target, &tombstone)?;
            std::fs::remove_dir_all(&tombstone)?;
        } else {
            std::fs::remove_dir_all(&target)?;
        }
    }
    Ok(json!({
        "schema_version": "eliot-host-uninstall-v1",
        "host": host,
        "target": target,
        "existed": existed,
        "removed": existed && !dry_run,
        "dry_run": dry_run,
        "codex_tombstone_recovered": codex_tombstone_recovered,
        "global_uninstall": global_uninstall,
        "provider_auth_modified": false,
        "unrelated_config_preserved": true
    }))
}
