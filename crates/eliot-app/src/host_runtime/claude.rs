//! The Claude host family: two packaged surfaces behind one Governor authority.
//!
//! Claude Code loads ELIOT as a plugin with skills and lifecycle hooks; Claude
//! Desktop loads it as an MCPB package with tools and prompts and no hooks.
//! Both are the same vendor and the same authority, so which one is active is a
//! property of the family rather than of either surface -- which is why the
//! doctor here reports both together and treats two active at once as a fault.

use super::*;

/// Resolves which Claude surface a `--host` selector names.
///
/// `claude-desktop` was historically a host string of its own, sitting beside
/// `claude` as though Anthropic shipped two unrelated products. It is one host
/// family with two packaged surfaces, so the selector now resolves to a
/// [`ClaudeSurface`] and the family stays [`AgentHostId::Claude`]. The old
/// spellings keep resolving; they are never emitted as the current name.
pub(super) fn claude_surface_selector(value: &str) -> Option<ClaudeSurface> {
    let normalized = value.trim().to_ascii_lowercase().replace('-', "_");
    match normalized.as_str() {
        // Bare `claude` names the family, not a surface: the caller decides.
        "claude" => None,
        other => ClaudeSurface::parse(other),
    }
}

pub(super) fn is_claude_desktop_host(value: &str) -> bool {
    claude_surface_selector(value) == Some(ClaudeSurface::ClaudeDesktopMcpb)
}

pub(super) fn claude_desktop_manifest_info(repo: &Path) -> Result<(PathBuf, String, String)> {
    let path = repo.join(CLAUDE_DESKTOP_MANIFEST);
    let manifest: Value = serde_json::from_reader(
        std::fs::File::open(&path)
            .with_context(|| format!("read Claude Desktop manifest {}", path.display()))?,
    )?;
    let name = manifest
        .get("name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("Claude Desktop manifest name is missing")?
        .to_owned();
    let version = manifest
        .get("version")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("Claude Desktop manifest version is missing")?
        .to_owned();
    Ok((path, name, version))
}

pub(super) fn claude_desktop_registry_path() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("APPDATA").context("APPDATA is not set")?)
            .join("Claude")
            .join("extensions-installations.json"),
    )
}

pub(super) fn claude_desktop_extensions_root() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("APPDATA").context("APPDATA is not set")?)
            .join("Claude")
            .join("Claude Extensions"),
    )
}

pub(super) fn claude_desktop_install_receipt_path(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-integrations")
        .join("claude-desktop-install.json")
}

/// Where `scripts/build-claude-desktop-extension.ps1` leaves the package.
///
/// The build script moved its output to an external cache so that rebuildable
/// artifacts stay out of OneDrive, but this resolver kept pointing at the
/// repository's `dist/`, so installation reported a missing package
/// immediately after a successful build. The two must read the same
/// `ELIOT_PACKAGE_ROOT`.
pub(super) fn claude_desktop_package_path(_repo: &Path, version: &str) -> PathBuf {
    claude_package_cache_root()
        .join("claude")
        .join(format!("eliot-{version}-windows-x64.mcpb"))
}

fn claude_package_cache_root() -> PathBuf {
    if let Some(root) = std::env::var_os("ELIOT_PACKAGE_ROOT") {
        return PathBuf::from(root);
    }
    std::env::var_os("LOCALAPPDATA").map_or_else(
        || PathBuf::from("Eliot").join("packages"),
        |local| PathBuf::from(local).join("Eliot").join("packages"),
    )
}

pub(super) fn claude_desktop_uninstall_receipt_path(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-integrations")
        .join("claude-desktop-uninstall.json")
}

pub(super) fn registry_entry_by_manifest(
    registry: &Value,
    manifest_name: &str,
) -> Option<(String, Value)> {
    registry
        .get("extensions")?
        .as_object()?
        .iter()
        .find(|(_, entry)| {
            entry
                .get("manifest")
                .and_then(|manifest| manifest.get("name"))
                .and_then(Value::as_str)
                == Some(manifest_name)
        })
        .map(|(id, entry)| (id.clone(), entry.clone()))
}

pub(super) fn claude_desktop_extension_state(
    manifest_name: &str,
) -> Result<Option<ClaudeDesktopExtensionState>> {
    let registry_path = claude_desktop_registry_path()?;
    if !registry_path.is_file() {
        return Ok(None);
    }
    let registry_bytes = std::fs::read(&registry_path)?;
    let registry: Value = serde_json::from_slice(&registry_bytes).with_context(|| {
        format!(
            "parse Claude extension registry {}",
            registry_path.display()
        )
    })?;
    let Some((extension_id, entry)) = registry_entry_by_manifest(&registry, manifest_name) else {
        return Ok(None);
    };
    let root = claude_desktop_extensions_root()?;
    let extension_path = root.join(&extension_id);
    ensure_child(&root, &extension_path)?;
    let installed_manifest = extension_path.join("manifest.json");
    let installed_binary = extension_path.join("server").join("eliot-governor.exe");
    Ok(Some(ClaudeDesktopExtensionState {
        extension_id,
        version: entry
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        source: entry
            .get("source")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_owned(),
        registry_hash: entry
            .get("hash")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        extension_path,
        installed_manifest_hash: installed_manifest
            .is_file()
            .then(|| bundle_hash_single(&installed_manifest))
            .transpose()?,
        installed_binary_hash: installed_binary
            .is_file()
            .then(|| bundle_hash_single(&installed_binary))
            .transpose()?,
    }))
}

pub(super) fn claude_desktop_state_is_current(
    state: &ClaudeDesktopExtensionState,
    manifest_version: &str,
    running_governor_hash: &str,
) -> bool {
    state.version == manifest_version
        && state.installed_manifest_hash.is_some()
        && state.installed_binary_hash.as_deref() == Some(running_governor_hash)
}

pub(super) fn claude_desktop_executable() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(override_path) = std::env::var_os("ELIOT_CLAUDE_DESKTOP_EXE") {
            let override_path = PathBuf::from(override_path);
            if override_path.is_file() {
                return Ok(override_path);
            }
            bail!(
                "ELIOT_CLAUDE_DESKTOP_EXE is not a file: {}",
                override_path.display()
            );
        }
        let output = StdCommand::new("powershell.exe")
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $package = Get-AppxPackage -Name Claude | Sort-Object Version -Descending | Select-Object -First 1; if ($null -eq $package) { exit 2 }; $package.InstallLocation",
            ])
            .output()
            .context("query the installed Claude Desktop AppX package")?;
        if !output.status.success() {
            bail!("the installed Claude Desktop AppX package was not found");
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let install_location = stdout
            .lines()
            .map(str::trim)
            .find(|value| !value.is_empty())
            .context("the installed Claude Desktop AppX location is empty")?
            .to_owned();
        let executable = PathBuf::from(install_location)
            .join("app")
            .join("Claude.exe");
        if !executable.is_file() {
            bail!(
                "the registered Claude Desktop executable is not a file: {}",
                executable.display()
            );
        }
        Ok(executable)
    }
    #[cfg(not(windows))]
    {
        bail!("Claude Desktop is supported only on Windows")
    }
}

pub(super) fn claude_desktop_doctor(config_path: &Path) -> Result<Value> {
    let repo = repo_root(config_path);
    let (manifest_path, manifest_name, manifest_version) = claude_desktop_manifest_info(&repo)?;
    let package_path = claude_desktop_package_path(&repo, &manifest_version);
    let state = claude_desktop_extension_state(&manifest_name)?;
    let running_governor = std::env::current_exe().context("resolve running Governor")?;
    let running_governor_hash = bundle_hash_single(&running_governor)?;
    let ready = state.as_ref().is_some_and(|installed| {
        claude_desktop_state_is_current(installed, &manifest_version, &running_governor_hash)
    });
    Ok(json!({
        "schema_version": "eliot-claude-desktop-doctor-v1",
        "surface": CLAUDE_DESKTOP_HOST,
        "ready": ready,
        "manifest_path": manifest_path,
        "manifest_name": manifest_name,
        "manifest_version": manifest_version,
        "package_path": package_path,
        "package_exists": package_path.is_file(),
        "extension": state,
        "running_governor_hash": running_governor_hash,
        "install_receipt_path": claude_desktop_install_receipt_path(config_path),
        "install_receipt_exists": claude_desktop_install_receipt_path(config_path).is_file(),
        "provider_auth_read_or_modified": false,
        "manual_claude_config_edit": false
    }))
}

#[allow(clippy::too_many_lines)]
pub(super) fn install_claude_desktop(
    config_path: &Path,
    dry_run: bool,
    wait_seconds: u64,
) -> Result<Value> {
    let repo = repo_root(config_path);
    let (manifest_path, manifest_name, manifest_version) = claude_desktop_manifest_info(&repo)?;
    let package_path = claude_desktop_package_path(&repo, &manifest_version);
    if !package_path.is_file() {
        bail!(
            "Claude Desktop package is missing: {}; build it before installation",
            package_path.display()
        );
    }
    let registry_path = claude_desktop_registry_path()?;
    let registry_before_hash = registry_path
        .is_file()
        .then(|| bundle_hash_single(&registry_path))
        .transpose()?;
    let package_hash = bundle_hash_single(&package_path)?;
    let manifest_hash = bundle_hash_single(&manifest_path)?;
    let running_governor = std::env::current_exe().context("resolve running Governor")?;
    let running_governor_hash = bundle_hash_single(&running_governor)?;
    let existing = claude_desktop_extension_state(&manifest_name)?;
    let already_current = existing.as_ref().is_some_and(|state| {
        claude_desktop_state_is_current(state, &manifest_version, &running_governor_hash)
    });
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-claude-desktop-install-plan-v1",
            "surface": CLAUDE_DESKTOP_HOST,
            "dry_run": true,
            "package_path": package_path,
            "package_hash": package_hash,
            "manifest_name": manifest_name,
            "manifest_version": manifest_version,
            "existing": existing,
            "already_current": already_current,
            "install_mechanism": "Governor invokes the installed Claude Desktop AppX executable with the MCPB path; Claude Desktop owns review, permissions, extraction, and registry mutation",
            "manual_claude_config_edit": false,
            "provider_auth_read_or_modified": false,
            "wait_seconds": wait_seconds
        }));
    }
    let installed = if already_current {
        existing.context("current Claude Desktop extension state disappeared")?
    } else {
        open_claude_desktop_package(&package_path)?;
        wait_for_claude_desktop_install(
            &manifest_name,
            &manifest_version,
            &running_governor_hash,
            wait_seconds,
        )?
    };
    let registry_after_hash = bundle_hash_single(&registry_path)?;
    let installed_manifest_hash = installed
        .installed_manifest_hash
        .clone()
        .context("installed Claude Desktop manifest is missing")?;
    let installed_binary_hash = installed
        .installed_binary_hash
        .clone()
        .context("installed Claude Desktop Governor binary is missing")?;
    let receipt = ClaudeDesktopInstallReceipt {
        schema_version: "eliot-claude-desktop-install-v1".to_owned(),
        receipt_id: format!("host-install:{}", Uuid::new_v4()),
        surface: CLAUDE_DESKTOP_HOST.to_owned(),
        package_path,
        package_hash,
        manifest_name,
        manifest_version,
        manifest_hash,
        registry_path,
        registry_before_hash,
        registry_after_hash,
        extension_id: installed.extension_id,
        extension_path: installed.extension_path,
        installed_manifest_hash,
        installed_binary_hash,
        install_mechanism:
            "Governor invoked Claude Desktop with MCPB path; Claude Desktop verified and installed"
                .to_owned(),
        status: "installed_and_verified".to_owned(),
        rollback_command: format!(
            "\"{}\" host uninstall --host {CLAUDE_DESKTOP_HOST} --wait-seconds {wait_seconds}",
            std::env::current_exe()?.display()
        ),
        provider_auth_modified: false,
        unrelated_config_preserved: true,
        verified_at: OffsetDateTime::now_utc(),
    };
    atomic_write_json(&claude_desktop_install_receipt_path(config_path), &receipt)?;
    Ok(serde_json::to_value(receipt)?)
}

pub(super) fn uninstall_claude_desktop(
    config_path: &Path,
    dry_run: bool,
    wait_seconds: u64,
) -> Result<Value> {
    let receipt_path = claude_desktop_install_receipt_path(config_path);
    let receipt: ClaudeDesktopInstallReceipt =
        serde_json::from_reader(std::fs::File::open(&receipt_path).with_context(|| {
            format!(
                "read Claude Desktop install receipt {}",
                receipt_path.display()
            )
        })?)?;
    if receipt.surface != CLAUDE_DESKTOP_HOST {
        bail!("install receipt does not authorize Claude Desktop removal");
    }
    let current = claude_desktop_extension_state(&receipt.manifest_name)?;
    if let Some(state) = &current
        && (state.extension_id != receipt.extension_id
            || state.extension_path != receipt.extension_path)
    {
        bail!("refuse Claude Desktop rollback because the installed extension identity changed");
    }
    if dry_run {
        return Ok(json!({
            "schema_version": "eliot-claude-desktop-uninstall-plan-v1",
            "surface": CLAUDE_DESKTOP_HOST,
            "dry_run": true,
            "authorized_by_receipt": receipt.receipt_id,
            "extension": current,
            "uninstall_mechanism": "Governor opens Claude Desktop; Claude owns the extension removal and Governor waits for verified registry removal",
            "provider_auth_read_or_modified": false,
            "unrelated_config_preserved": true,
            "wait_seconds": wait_seconds
        }));
    }
    let existed = current.is_some();
    if existed {
        open_claude_desktop()?;
        wait_for_claude_desktop_uninstall(&receipt.manifest_name, wait_seconds)?;
    }
    let uninstall_receipt = json!({
        "schema_version": "eliot-claude-desktop-uninstall-v1",
        "receipt_id": format!("host-uninstall:{}", Uuid::new_v4()),
        "surface": CLAUDE_DESKTOP_HOST,
        "authorized_by_receipt": receipt.receipt_id,
        "extension_id": receipt.extension_id,
        "extension_path": receipt.extension_path,
        "existed": existed,
        "removed": existed,
        "provider_auth_modified": false,
        "unrelated_config_preserved": true,
        "verified_at": OffsetDateTime::now_utc()
    });
    atomic_write_json(
        &claude_desktop_uninstall_receipt_path(config_path),
        &uninstall_receipt,
    )?;
    Ok(uninstall_receipt)
}

pub(super) fn claude_global_plugin_path() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("USERPROFILE").context("USERPROFILE is not set")?)
            .join(".claude")
            .join("skills")
            .join("eliot"),
    )
}

pub(super) fn claude_user_root() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("USERPROFILE").context("USERPROFILE is not set")?)
            .join(".claude"),
    )
}

/// Every root from which Claude Code could load ELIOT.
///
/// Claude Code discovers plugins from more than one place, and ELIOT has been
/// installed both into a skills directory and registered under the plugin data
/// root. Two roots holding ELIOT is not a cosmetic duplication: each one binds
/// its own MCP server, so a single session gets the tool set twice under
/// competing namespaces. Every root is reported, never just the first found.
pub(super) fn claude_code_plugin_roots() -> Result<Vec<PathBuf>> {
    let mut roots = Vec::new();
    let skills_install = claude_global_plugin_path()?;
    if skills_install.join(".mcp.json").is_file() || skills_install.join(".claude-plugin").is_dir()
    {
        roots.push(skills_install);
    }
    let plugin_data = claude_user_root()?.join("plugins").join("data");
    if let Ok(entries) = std::fs::read_dir(&plugin_data) {
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let names_eliot = path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.to_ascii_lowercase().contains("eliot"));
            // An empty registration directory is a leftover, not a live root.
            let has_content = std::fs::read_dir(&path).is_ok_and(|mut d| d.next().is_some());
            if names_eliot && has_content {
                roots.push(path);
            }
        }
    }
    Ok(roots)
}

/// Where the selected Claude surface is recorded.
///
/// Runtime state, not source: it describes this machine, so it lives with the
/// other host-integration receipts outside the repository and never in Git.
pub(super) fn claude_surface_selection_path(config_path: &Path) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-integrations")
        .join("claude-surface-selection.json")
}

pub(super) fn selected_claude_surface(config_path: &Path) -> Option<ClaudeSurface> {
    let raw = std::fs::read(claude_surface_selection_path(config_path)).ok()?;
    let value: Value = serde_json::from_slice(&raw).ok()?;
    value
        .get("selected_surface")
        .and_then(Value::as_str)
        .and_then(ClaudeSurface::parse)
}

/// Selects the one Claude surface this machine should expose.
///
/// Idempotent by construction: the plan is derived from observed state, so
/// re-running once the machine already matches asks for no actions at all.
/// Only ELIOT-owned integration state is ever named -- unrelated Claude
/// configuration and other vendors' extensions are not this command's business.
pub(super) fn activate_claude_surface(
    config_path: &Path,
    surface: ClaudeSurface,
    dry_run: bool,
) -> Result<Value> {
    let before = claude_family_doctor(config_path)?;
    let code_active = before
        .pointer("/surfaces/claude_code_plugin/active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let desktop_active = before
        .pointer("/surfaces/claude_desktop_mcpb/active")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let (keep_active, stand_down_active) = match surface {
        ClaudeSurface::ClaudeCodePlugin => (code_active, desktop_active),
        ClaudeSurface::ClaudeDesktopMcpb => (desktop_active, code_active),
    };
    let stand_down = match surface {
        ClaudeSurface::ClaudeCodePlugin => ClaudeSurface::ClaudeDesktopMcpb,
        ClaudeSurface::ClaudeDesktopMcpb => ClaudeSurface::ClaudeCodePlugin,
    };

    let mut actions = Vec::new();
    if !keep_active {
        actions.push(json!({
            "action": "install_surface",
            "surface": surface.as_str(),
            "command": format!("host install --host {}", match surface {
                ClaudeSurface::ClaudeCodePlugin => "claude",
                ClaudeSurface::ClaudeDesktopMcpb => "claude-desktop",
            })
        }));
    }
    if stand_down_active {
        // Not automated, and deliberately so. Claude Desktop owns its own
        // extension registry: uninstall opens Desktop and waits for Claude to
        // remove the entry, rather than ELIOT editing another application's
        // state behind its back. The Code plugin is likewise Claude Code's to
        // enable and disable. Selection is recorded here; the surface change
        // is executed through the owner.
        actions.push(json!({
            "action": "stand_down_surface",
            "surface": stand_down.as_str(),
            "command": format!("host uninstall --host {}", match stand_down {
                ClaudeSurface::ClaudeCodePlugin => "claude",
                ClaudeSurface::ClaudeDesktopMcpb => "claude-desktop",
            }),
            "automated": false,
            "reason": match stand_down {
                ClaudeSurface::ClaudeCodePlugin =>
                    "Claude Code owns plugin activation; run the command or `claude plugin disable eliot@skills-dir`",
                ClaudeSurface::ClaudeDesktopMcpb =>
                    "Claude Desktop owns its extension registry; uninstall opens Desktop and waits for it to remove the entry",
            }
        }));
    }

    let selection_path = claude_surface_selection_path(config_path);
    if !dry_run {
        if let Some(parent) = selection_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        atomic_write_json(
            &selection_path,
            &json!({
                "schema_version": "eliot-claude-surface-selection-v1",
                "host": AgentHostId::Claude.as_str(),
                "selected_surface": surface.as_str(),
                "selected_at": OffsetDateTime::now_utc(),
            }),
        )?;
    }

    Ok(json!({
        "schema_version": "eliot-claude-surface-activation-v1",
        "host": AgentHostId::Claude.as_str(),
        "selected_surface": surface.as_str(),
        "stood_down_surface": stand_down.as_str(),
        "dry_run": dry_run,
        "already_satisfied": actions.is_empty(),
        "pending_actions": actions,
        "selection_receipt": selection_path,
        // A live Claude process keeps the surfaces it started with.
        "claude_restart_required": !actions.is_empty(),
        "supports_lifecycle_hooks": surface.supports_lifecycle_hooks()
    }))
}

/// ELIOT-owned entries in Claude Desktop's extension registry.
///
/// Deliberately independent of the source tree. The detailed Desktop report
/// resolves its registry entry through the manifest name, which it reads from
/// the repository -- so on an installed runtime, with no source tree, it cannot
/// answer at all. Presence is the fact the family doctor actually needs in
/// order to say whether two surfaces are live, and the registry alone is enough
/// to establish it.
pub(super) fn claude_desktop_registered_extensions() -> Result<Vec<String>> {
    let registry_path = claude_desktop_registry_path()?;
    if !registry_path.is_file() {
        return Ok(Vec::new());
    }
    let registry: Value =
        serde_json::from_slice(&std::fs::read(&registry_path)?).with_context(|| {
            format!(
                "parse Claude extension registry {}",
                registry_path.display()
            )
        })?;
    Ok(registry
        .get("extensions")
        .and_then(Value::as_object)
        .map(|entries| {
            entries
                .keys()
                .filter(|id| id.to_ascii_lowercase().contains("eliot"))
                .cloned()
                .collect()
        })
        .unwrap_or_default())
}

/// What an installed Claude Code plugin root says about itself.
///
/// The install manifest records where the plugin was built from. That source
/// can be moved or deleted long after installation, leaving a plugin that still
/// loads and works but can never be updated again -- a failure that is
/// invisible until someone tries to reinstall and finds nothing there.
pub(super) fn claude_code_plugin_report(root: &Path) -> Value {
    let manifest = std::fs::read(root.join(".claude-plugin").join("plugin.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let install = std::fs::read(root.join(CLAUDE_GLOBAL_MANIFEST))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
    let source_path = install
        .as_ref()
        .and_then(|value| value.get("source_plugin_path"))
        .and_then(Value::as_str);
    let source_present = source_path.map(|path| Path::new(path).is_dir());

    json!({
        "root": root,
        "manifest_valid": manifest.is_some(),
        "plugin_version": manifest
            .as_ref()
            .and_then(|value| value.get("version"))
            .and_then(Value::as_str),
        "license": manifest
            .as_ref()
            .and_then(|value| value.get("license"))
            .and_then(Value::as_str),
        "install_source_path": source_path,
        "install_source_present": source_present,
        "installed_governor_sha256": install
            .as_ref()
            .and_then(|value| value.get("installed_governor_sha256"))
            .and_then(Value::as_str),
    })
}

/// One doctor for the whole Claude host family.
///
/// `claude` is a single vendor with a single Governor authority behind two
/// packaged surfaces. Reporting them separately is what let both be active at
/// once without anything calling it a fault, so the family view is the one that
/// decides readiness: two active surfaces is a configuration error, not health.
pub(super) fn claude_family_doctor(config_path: &Path) -> Result<Value> {
    let code_roots = claude_code_plugin_roots()?;
    // The Desktop report needs the source tree for its manifest, which an
    // installed runtime does not have. A diagnostic must not fail because one
    // of its inputs is out of reach: report that surface as unreadable and
    // carry on, so the rest of the picture still reaches the operator.
    let desktop = claude_desktop_doctor(config_path).unwrap_or_else(|error| {
        json!({
            "readable": false,
            "detail": format!("{error:#}"),
        })
    });
    let desktop_readable = desktop.get("readable") != Some(&Value::Bool(false));
    // Presence comes from the registry, which is always reachable; the detailed
    // report only enriches it. Otherwise an installed runtime would report the
    // Desktop surface as inactive purely because it could not look, and a
    // dual-active machine would read as healthy.
    let registered = claude_desktop_registered_extensions().unwrap_or_default();
    let desktop_active = !registered.is_empty()
        || desktop
            .get("extension")
            .is_some_and(|state| !state.is_null());
    let code_active = !code_roots.is_empty();

    let mut conflicts = Vec::new();
    if code_roots.len() > 1 {
        conflicts.push(json!({
            "kind": "duplicate_code_plugin_roots",
            "detail": "Claude Code can load ELIOT from more than one root, exposing the tool set twice",
            "roots": &code_roots,
            "remediation": "keep exactly one ELIOT plugin root and remove the others"
        }));
    }
    let code_reports = code_roots
        .iter()
        .map(|root| claude_code_plugin_report(root))
        .collect::<Vec<_>>();
    for report in &code_reports {
        if report.get("install_source_present") == Some(&Value::Bool(false)) {
            conflicts.push(json!({
                "kind": "install_source_missing",
                "detail": "the plugin still loads but the tree it was installed from is gone, so it can never be updated in place",
                "root": report.get("root"),
                "install_source_path": report.get("install_source_path"),
                "remediation": "reinstall from the canonical repository with `host install --host claude`"
            }));
        }
    }

    let selected = selected_claude_surface(config_path);
    if code_active && desktop_active {
        conflicts.push(json!({
            "kind": "dual_active_surface",
            "detail": "the Claude Code plugin and the Claude Desktop MCPB are both active; a Claude Code session hosted in Desktop binds ELIOT twice",
            "remediation": match selected {
                Some(surface) => format!("host activate --host claude --surface {}", match surface {
                    ClaudeSurface::ClaudeCodePlugin => "code",
                    ClaudeSurface::ClaudeDesktopMcpb => "desktop",
                }),
                None => "host activate --host claude --surface code|desktop".to_owned(),
            }
        }));
    }
    // A selection that the machine does not match is drift, not health: the
    // intended surface is recorded but something else is answering.
    if let Some(surface) = selected {
        let selected_is_active = match surface {
            ClaudeSurface::ClaudeCodePlugin => code_active,
            ClaudeSurface::ClaudeDesktopMcpb => desktop_active,
        };
        if !selected_is_active {
            conflicts.push(json!({
                "kind": "selected_surface_inactive",
                "detail": "the selected Claude surface is not active on this machine",
                "selected_surface": surface.as_str(),
                "remediation": "install the selected surface or select the one that is active"
            }));
        }
    }

    Ok(json!({
        "schema_version": "eliot-claude-family-doctor-v1",
        "host": AgentHostId::Claude.as_str(),
        "surfaces": {
            ClaudeSurface::ClaudeCodePlugin.as_str(): {
                "active": code_active,
                "roots": &code_roots,
                "root_count": code_roots.len(),
                "installations": &code_reports,
                "supports_lifecycle_hooks": ClaudeSurface::ClaudeCodePlugin.supports_lifecycle_hooks()
            },
            ClaudeSurface::ClaudeDesktopMcpb.as_str(): {
                "active": desktop_active,
                "readable": desktop_readable,
                "registered_extensions": &registered,
                "supports_lifecycle_hooks": ClaudeSurface::ClaudeDesktopMcpb.supports_lifecycle_hooks(),
                "detail": desktop
            }
        },
        "active_surface_count": usize::from(code_active) + usize::from(desktop_active),
        "selected_surface": selected.map(ClaudeSurface::as_str),
        "selection_receipt": claude_surface_selection_path(config_path),
        "conflicts": conflicts,
        "status": if conflicts.is_empty() {
            if code_active || desktop_active { "ready" } else { "not_installed" }
        } else {
            "conflict"
        }
    }))
}

pub(super) fn claude_plugin_hash(bundle: &Path, governor: &Path) -> Result<String> {
    Ok(format!(
        "bundle={};governor={}",
        bundle_hash(bundle, AgentHostId::Claude)?,
        bundle_hash_single(governor)?
    ))
}
