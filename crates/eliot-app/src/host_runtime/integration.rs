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

#[allow(clippy::too_many_lines)]
pub(super) fn install(
    config_path: &Path,
    host: AgentHostId,
    dry_run: bool,
) -> Result<HostIntegrationReceipt> {
    ensure_l7_host(host)?;
    let repo = repo_root(config_path);
    let source = bundle_root(&repo, host);
    let base = install_base()?;
    let target = base.join(host.as_str());
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
    let mut backup_refs = Vec::new();
    let mut modified_files = Vec::new();
    let needs_bundle_update = before_hash.as_deref() != Some(source_hash.as_str())
        || before_governor_hash.as_deref() != Some(governor_hash.as_str());
    if !dry_run && needs_bundle_update {
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
    }
    let profile = HostProfileService.probe(host)?;
    let skills = SkillPackService.lint(&repo)?;
    let (mcp, lifecycle) = integration_refs(&source, host);
    let mut after_hashes = vec![source_hash.clone(), governor_hash];
    if host == AgentHostId::Claude {
        after_hashes.push(format!("sha256:{}", sha256_file(&governor)?));
    }
    let receipt = HostIntegrationReceipt {
        receipt_id: format!("host-install:{}", Uuid::new_v4()),
        host_id: host,
        host_version: profile.version,
        scope: match host {
            AgentHostId::OpenCode => "user-local Eliot bundle plus additive OpenCode global discovery; provider/auth and unrelated config preserved".to_owned(),
            AgentHostId::Claude => "user-local Eliot bundle packaged into a local marketplace and installed through the official Claude Code plugin lifecycle; provider/auth and unrelated settings preserved".to_owned(),
            _ => "user-local Eliot integration bundle; host auth/config untouched".to_owned(),
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
    ensure_l7_host(host)?;
    let base = install_base()?;
    let target = base.join(host.as_str());
    ensure_child(&base, &target)?;
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
        _ => None,
    };
    let existed = target.is_dir();
    if existed && !dry_run {
        std::fs::remove_dir_all(&target)?;
    }
    Ok(json!({
        "schema_version": "eliot-host-uninstall-v1",
        "host": host,
        "target": target,
        "existed": existed,
        "removed": existed && !dry_run,
        "dry_run": dry_run,
        "global_uninstall": global_uninstall,
        "provider_auth_modified": false,
        "unrelated_config_preserved": true
    }))
}
