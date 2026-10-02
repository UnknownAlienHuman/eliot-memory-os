//! Original selected-toolchain executable and environment owner.
//!
//! This is the shared implementation used by the profile resolver and the
//! daemon's live instrument admission path. It resolves a bare tool name only
//! inside the selected rustup toolchain, records the exact canonical file, and
//! projects the real published toolchain `PATH` without inheriting other
//! ambient variables.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eliot_process::{EnvironmentInheritance, EnvironmentProjection};
use thiserror::Error;

use crate::TOOLCHAIN_PATH_ENV;

/// Fail-closed refusal while selecting one current installed toolchain member.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
#[error("{detail}")]
pub struct ToolchainResolutionError {
    detail: String,
}

impl ToolchainResolutionError {
    fn refused(detail: impl Into<String>) -> Self {
        Self {
            detail: detail.into(),
        }
    }
}

/// Resolves an admitted bare tool name through the selected workspace
/// toolchain. There is deliberately no ambient `PATH` fallback.
pub fn resolve_tool(name: &str, source_root: &str) -> Result<PathBuf, ToolchainResolutionError> {
    let candidate = Path::new(name);
    if candidate.is_absolute() || candidate.components().count() > 1 {
        return Err(ToolchainResolutionError::refused(format!(
            "admitted executable '{name}' must be a bare tool name resolved through the selected toolchain"
        )));
    }
    let root = selected_toolchain_root(source_root)?;
    for suffix in executable_suffixes() {
        let candidate = root.join(format!("{name}{suffix}"));
        if candidate.is_file() {
            return std::fs::canonicalize(&candidate).map_err(|error| {
                ToolchainResolutionError::refused(format!(
                    "admitted executable {} is unavailable: {error}",
                    candidate.display()
                ))
            });
        }
    }
    Err(ToolchainResolutionError::refused(format!(
        "admitted executable '{name}' is not a member of the selected toolchain {}; an unpinned tool cannot be receipted",
        root.display()
    )))
}

/// Resolves one installed toolchain `bin` directory from the workspace pin or
/// the owner-published rustup default. Ambiguous installation matches refuse.
pub fn selected_toolchain_root(
    source_root: &str,
) -> Result<PathBuf, ToolchainResolutionError> {
    let rustup_home = rustup_home()?;
    let source_root = current_source_root(source_root)?;
    let settings_path = Path::new(&rustup_home).join("settings.toml");
    let settings = read_bounded_metadata(&settings_path, "rustup settings")?;
    let host = toml_string_value(&settings, "default_host_triple");
    let requested = read_toolchain_override(Path::new(&source_root))?
        .or_else(|| toml_string_value(&settings, "default_toolchain"))
        .ok_or_else(|| {
            ToolchainResolutionError::refused(format!(
                "no toolchain is selected: {source_root} pins none and {rustup_home} names no default"
            ))
        })?;
    let toolchains = Path::new(&rustup_home).join("toolchains");
    let mut candidates = std::fs::read_dir(&toolchains)
        .map_err(|error| {
            ToolchainResolutionError::refused(format!(
                "toolchain root {} is unavailable: {error}",
                toolchains.display()
            ))
        })?
        .filter_map(Result::ok)
        .filter_map(|entry| {
            entry
                .file_type()
                .ok()
                .filter(std::fs::FileType::is_dir)
                .map(|_| entry.file_name().to_string_lossy().into_owned())
        })
        .filter(|name| name == &requested || name.starts_with(&format!("{requested}-")))
        .collect::<Vec<_>>();
    candidates.sort();
    if let Some(host) = host.as_deref() {
        let host_candidates = candidates
            .iter()
            .filter(|name| name.ends_with(host))
            .cloned()
            .collect::<Vec<_>>();
        if !host_candidates.is_empty() {
            candidates = host_candidates;
        }
    }
    let [selected] = candidates.as_slice() else {
        return Err(ToolchainResolutionError::refused(format!(
            "toolchain '{requested}' is not installed under {}; an unpinned toolchain cannot be receipted",
            toolchains.display()
        )));
    };
    Ok(toolchains.join(selected).join("bin"))
}

/// Projects the actual process `PATH` as the one allowlisted toolchain
/// variable. An absent value is a refusal; no search path is synthesized.
pub fn isolated_projection() -> Result<EnvironmentProjection, ToolchainResolutionError> {
    let path = std::env::var(TOOLCHAIN_PATH_ENV).map_err(|error| {
        ToolchainResolutionError::refused(format!(
            "explicitly permitted toolchain environment is unavailable: {TOOLCHAIN_PATH_ENV} is unset ({error})"
        ))
    })?;
    EnvironmentProjection::new(
        BTreeMap::from([(TOOLCHAIN_PATH_ENV.to_owned(), path)]),
        Vec::new(),
        EnvironmentInheritance::None,
    )
    .map_err(|error| ToolchainResolutionError::refused(error.to_string()))
}

fn rustup_home() -> Result<String, ToolchainResolutionError> {
    let candidate = std::env::var_os("RUSTUP_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("USERPROFILE")
                .or_else(|| std::env::var_os("HOME"))
                .map(|home| PathBuf::from(home).join(".rustup"))
        })
        .ok_or_else(|| {
            ToolchainResolutionError::refused("toolchain root is unknown: RUSTUP_HOME is unset")
        })?;
    if !candidate.is_absolute() || !candidate.is_dir() {
        return Err(ToolchainResolutionError::refused(format!(
            "toolchain root {} is not an existing absolute directory",
            candidate.display()
        )));
    }
    Ok(std::fs::canonicalize(&candidate)
        .map_err(|error| {
            ToolchainResolutionError::refused(format!(
                "toolchain root {} cannot be canonicalized: {error}",
                candidate.display()
            ))
        })?
        .to_string_lossy()
        .into_owned())
}

fn current_source_root(source_root: &str) -> Result<String, ToolchainResolutionError> {
    let root = PathBuf::from(source_root);
    if !root.is_absolute() || !root.is_dir() {
        return Err(ToolchainResolutionError::refused(format!(
            "admitted source root {} is not an existing absolute directory",
            root.display()
        )));
    }
    Ok(std::fs::canonicalize(&root)
        .map_err(|error| {
            ToolchainResolutionError::refused(format!(
                "admitted source root {} cannot be canonicalized: {error}",
                root.display()
            ))
        })?
        .to_string_lossy()
        .into_owned())
}

fn read_toolchain_override(
    source_root: &Path,
) -> Result<Option<String>, ToolchainResolutionError> {
    for name in ["rust-toolchain.toml", "rust-toolchain"] {
        let path = source_root.join(name);
        if !path.is_file() {
            continue;
        }
        let text = read_bounded_metadata(&path, "rust-toolchain override")?;
        let value = if name.eq_ignore_ascii_case("rust-toolchain.toml") {
            toml_string_value(&text, "channel").or_else(|| toml_string_value(&text, "toolchain"))
        } else {
            text.lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with('#'))
                .map(ToOwned::to_owned)
        };
        return Ok(value
            .filter(|value| !value.trim().is_empty() && !value.chars().any(char::is_control)));
    }
    Ok(None)
}

fn read_bounded_metadata(
    path: &Path,
    what: &str,
) -> Result<String, ToolchainResolutionError> {
    const MAX_METADATA_BYTES: usize = 64 * 1024;
    let bytes = std::fs::read(path).map_err(|error| {
        ToolchainResolutionError::refused(format!(
            "{what} {} is unreadable: {error}",
            path.display()
        ))
    })?;
    if bytes.len() > MAX_METADATA_BYTES {
        return Err(ToolchainResolutionError::refused(format!(
            "{what} {} exceeds the bounded read size",
            path.display()
        )));
    }
    String::from_utf8(bytes).map_err(|_| {
        ToolchainResolutionError::refused(format!("{what} {} is not UTF-8", path.display()))
    })
}

fn toml_string_value(text: &str, key: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        let value = value.trim().trim_matches('"');
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn executable_suffixes() -> Vec<String> {
    let suffixes = std::env::var("PATHEXT")
        .map(|pathext| {
            pathext
                .split(';')
                .filter(|suffix| !suffix.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if suffixes.is_empty() {
        return vec![String::new()];
    }
    suffixes
}
