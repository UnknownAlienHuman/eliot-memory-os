/// The source tree, or the best honest guess at it.
///
/// This used to fall back to the runtime root's parent, which was the checkout
/// only while the runtime lived inside it. Once the runtime moved to
/// `%LOCALAPPDATA%/Eliot`, that fallback produced
/// `%LOCALAPPDATA%/integrations/...` -- a path that exists nowhere, so callers
/// reported "cannot find the path" about a directory nobody had ever named.
/// Failing back to the working directory keeps a wrong answer recognisable as
/// one.
fn repo_root(config_path: &Path) -> PathBuf {
    let _ = config_path;
    if let Some(root) = std::env::var_os("ELIOT_GOVERNOR_REPO_ROOT") {
        return PathBuf::from(root);
    }
    let is_source_tree = |candidate: &Path| {
        candidate.join("Cargo.toml").is_file()
            && candidate.join("integrations/agent-skills").is_dir()
    };
    let is_packaged_root = |candidate: &Path| {
        candidate.join("integrations").is_dir()
            && (candidate.join("eliot-governor.exe").is_file()
                || candidate.join("bin").join("eliot-governor.exe").is_file())
    };
    let is_runtime_root =
        |candidate: &Path| is_source_tree(candidate) || is_packaged_root(candidate);
    if let Ok(current) = std::env::current_dir()
        && let Some(root) = current
            .ancestors()
            .find(|candidate| is_runtime_root(candidate))
    {
        return root.to_path_buf();
    }
    // An installed Governor runs from outside the checkout, but a Governor
    // built for development runs from `<repo>/target/...` or an external build
    // cache; the first case is worth finding, the second correctly finds
    // nothing.
    if let Ok(exe) = std::env::current_exe()
        && let Some(root) = exe.ancestors().find(|candidate| is_runtime_root(candidate))
    {
        return root.to_path_buf();
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Resolve the repository root for installation from the explicit governed
/// environment contract. Installation must never infer source authority from
/// the process working directory or executable/cache location.
fn governed_repo_root(_config_path: &Path) -> Result<PathBuf> {
    governed_repo_root_from(std::env::var_os("ELIOT_GOVERNOR_REPO_ROOT").as_deref())
}

fn governed_repo_root_from(configured_root: Option<&std::ffi::OsStr>) -> Result<PathBuf> {
    let configured_root = configured_root
        .map(PathBuf::from)
        .context("ELIOT_GOVERNOR_REPO_ROOT is required for host installation")?;
    ensure!(
        configured_root.is_absolute(),
        "ELIOT_GOVERNOR_REPO_ROOT must be absolute"
    );
    let canonical = std::fs::canonicalize(&configured_root).with_context(|| {
        format!(
            "ELIOT_GOVERNOR_REPO_ROOT does not resolve: {}",
            configured_root.display()
        )
    })?;
    ensure!(
        canonical.is_dir() && canonical.join("Cargo.toml").is_file(),
        "ELIOT_GOVERNOR_REPO_ROOT must be a Cargo checkout: {}",
        canonical.display()
    );
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&canonical)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .context("validate ELIOT_GOVERNOR_REPO_ROOT with git")?;
    ensure!(
        output.status.success(),
        "ELIOT_GOVERNOR_REPO_ROOT is not a Git checkout: {}",
        canonical.display()
    );
    let git_root = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let canonical_git_root = std::fs::canonicalize(&git_root)
        .with_context(|| format!("canonicalize Git root returned for {}", canonical.display()))?;
    ensure!(
        canonical_git_root == canonical,
        "ELIOT_GOVERNOR_REPO_ROOT must name the exact Git root: {}",
        canonical.display()
    );
    Ok(canonical)
}

fn runtime_root(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(".eliot-governor"))
        .to_path_buf()
}

fn integration_refs(bundle: &Path, host: AgentHostId) -> (PathBuf, PathBuf) {
    match host {
        AgentHostId::OpenCode => (
            bundle.join("opencode.json"),
            bundle.join("plugins").join("eliot.js"),
        ),
        AgentHostId::Claude | AgentHostId::Codex => (
            bundle.join(".mcp.json"),
            bundle.join("hooks").join("hooks.json"),
        ),
        AgentHostId::Antigravity => (bundle.join("integration.json"), bundle.join("README.md")),
    }
}

fn prepare_launch_bundle(
    config_path: &Path,
    host: AgentHostId,
    source: &Path,
    governor: &Path,
) -> Result<PathBuf> {
    let sandbox_root = runtime_root(config_path).join("host-sandboxes");
    let (target_name, staging_prefix) = match host {
        AgentHostId::OpenCode => ("opencode-config-active", ".opencode-config"),
        AgentHostId::Claude => ("claude-plugin-active", ".claude-plugin"),
        _ => return Ok(source.to_path_buf()),
    };
    let target = sandbox_root.join(target_name);
    let staging = sandbox_root.join(format!("{staging_prefix}-{}-staging", Uuid::new_v4()));
    std::fs::create_dir_all(&sandbox_root)?;
    ensure_child(&sandbox_root, &target)?;
    ensure_child(&sandbox_root, &staging)?;
    copy_tree(source, &staging, host)?;
    if host == AgentHostId::Claude {
        let bin = staging.join("bin");
        std::fs::create_dir_all(&bin)?;
        std::fs::copy(governor, bin.join("eliot-governor.exe"))?;
    }
    atomic_write_json(
        &staging.join("eliot-launch-bundle.json"),
        &json!({
            "schema_version": "eliot-host-launch-bundle-v1",
            "host": host,
            "source_bundle_hash": bundle_hash(source, host)?,
            "governor_hash": bundle_hash_single(governor)?,
            "host_auth_or_config_copied": false
        }),
    )?;
    if target.exists() {
        std::fs::remove_dir_all(&target)?;
    }
    std::fs::rename(&staging, &target)?;
    Ok(target)
}

fn matching_installed_claude_bundle(source: &Path, governor: &Path) -> Result<Option<PathBuf>> {
    let installed = claude_global_plugin_path()?;
    let installed_governor = installed.join("bin").join("eliot-governor.exe");
    if !installed.is_dir() || !installed_governor.is_file() {
        return Ok(None);
    }
    let expected = claude_plugin_hash(source, governor)?;
    let actual = claude_plugin_hash(&installed, &installed_governor)?;
    Ok((actual == expected).then_some(installed))
}

fn install_base() -> Result<PathBuf> {
    Ok(
        PathBuf::from(std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is not set")?)
            .join("Eliot")
            .join("host-integrations"),
    )
}

fn user_home() -> Result<PathBuf> {
    let home = std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .context("USERPROFILE and HOME are not set")?;
    let home = PathBuf::from(home);
    ensure!(home.is_absolute(), "user home must be an absolute path");
    Ok(home)
}

fn codex_plugin_root_from_home(home: &Path) -> PathBuf {
    home.join("plugins").join(CODEX_PLUGIN_NAME)
}

fn codex_marketplace_path_from_home(home: &Path) -> PathBuf {
    home.join(".agents")
        .join("plugins")
        .join("marketplace.json")
}

fn codex_plugin_root() -> Result<PathBuf> {
    Ok(codex_plugin_root_from_home(&user_home()?))
}

fn codex_marketplace_path() -> Result<PathBuf> {
    Ok(codex_marketplace_path_from_home(&user_home()?))
}

fn codex_install_journal_path() -> Result<PathBuf> {
    Ok(install_base()?.join(CODEX_INSTALL_JOURNAL))
}

fn codex_owned_lifecycle_recovery_path() -> Result<PathBuf> {
    Ok(install_base()?.join(CODEX_OWNED_LIFECYCLE_RECOVERY))
}

fn codex_operation_lock_path() -> Result<PathBuf> {
    Ok(install_base()?.join(CODEX_OPERATION_LOCK))
}

fn codex_uninstall_tombstone_path() -> Result<PathBuf> {
    Ok(install_base()?.join(CODEX_UNINSTALL_TOMBSTONE))
}

fn install_receipt_path(config_path: &Path, host: AgentHostId) -> PathBuf {
    runtime_root(config_path)
        .join("reports")
        .join("host-integrations")
        .join(format!("{}-install.json", host.as_str()))
}

fn copy_tree(source: &Path, destination: &Path, host: AgentHostId) -> Result<()> {
    std::fs::create_dir_all(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if host_generated_bundle_entry(host, &entry.path()) {
            continue;
        }
        let target = destination.join(entry.file_name());
        if kind.is_symlink() {
            bail!(
                "integration bundle symlink is not allowed: {}",
                entry.path().display()
            );
        } else if kind.is_dir() {
            copy_tree(&entry.path(), &target, host)?;
        } else if kind.is_file() {
            std::fs::copy(entry.path(), target)?;
        }
    }
    Ok(())
}

fn ensure_child(base: &Path, target: &Path) -> Result<()> {
    let base = std::path::absolute(base)?;
    let target = std::path::absolute(target)?;
    if target == base || !target.starts_with(&base) {
        bail!("refuse unsafe integration path {}", target.display());
    }
    Ok(())
}

fn bundle_hash_single(path: &Path) -> Result<String> {
    let bytes = std::fs::read(path)?;
    Ok(format!("blake3:{}", blake3::hash(&bytes).to_hex()))
}

fn write_json<T: serde::Serialize>(value: &T) -> Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    writeln!(output)?;
    Ok(())
}
