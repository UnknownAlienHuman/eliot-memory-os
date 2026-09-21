//! Typed update channels and versioned update installation (I3.8).
//!
//! Update packages are installed into new versioned directories; the installer
//! never overwrites a running binary. The only declared channels are `stable`,
//! `preview`, and `local-dev`. Kernel/Host updates are release-level
//! operations requiring the release approval path, while optional module
//! updates are normal hot-generation operations carrying explicit
//! generation/rollback metadata.

#![forbid(unsafe_code)]

use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Declared update channel (I3.8). Exactly these three channels exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateChannel {
    Stable,
    Preview,
    LocalDev,
}

impl UpdateChannel {
    /// Canonical channel name: `stable`, `preview`, or `local-dev`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Preview => "preview",
            Self::LocalDev => "local-dev",
        }
    }

    /// Parse a declared channel name; anything else is rejected.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateInstallerError::UnknownChannel`] for undeclared names.
    pub fn parse(value: &str) -> Result<Self, UpdateInstallerError> {
        match value {
            "stable" => Ok(Self::Stable),
            "preview" => Ok(Self::Preview),
            "local-dev" => Ok(Self::LocalDev),
            _ => Err(UpdateInstallerError::UnknownChannel {
                channel: value.to_owned(),
            }),
        }
    }
}

impl fmt::Display for UpdateChannel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for UpdateChannel {
    type Err = UpdateInstallerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Release-level versus hot-generation update classification (I3.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpdateKind {
    /// Kernel/Host update: a release-level operation on the authority boundary.
    KernelHostRelease,
    /// Optional module update: a normal hot-generation operation.
    ModuleGeneration,
}

impl UpdateKind {
    /// Classify a package by name. `eliot-kernel` and `eliot-host` are
    /// release-level; every other (optional module) package is a generation.
    #[must_use]
    pub fn classify(package_name: &str) -> Self {
        match package_name {
            "eliot-kernel" | "eliot-host" => Self::KernelHostRelease,
            _ => Self::ModuleGeneration,
        }
    }

    /// Release-level updates require the applicable release approval path.
    #[must_use]
    pub fn requires_release_approval(self) -> bool {
        matches!(self, Self::KernelHostRelease)
    }

    /// Canonical kind name for the update record.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KernelHostRelease => "kernel-host-release",
            Self::ModuleGeneration => "module-generation",
        }
    }
}

impl fmt::Display for UpdateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Update package metadata: identity, version, and declared channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageMetadata {
    /// Package (binary) name, e.g. `eliot-kernel` or an optional module name.
    pub name: String,
    /// Version label; becomes the versioned directory name.
    pub version: String,
    /// Declared update channel.
    pub channel: UpdateChannel,
    /// Lowercase hex SHA-256 of the update artifact payload.
    pub artifact_sha256: String,
}

impl PackageMetadata {
    /// Validate name/version/digest shape before any filesystem effect.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateInstallerError::InvalidPackage`] for empty names,
    /// versions, digests, path separators, parent navigation, or a malformed
    /// SHA-256 digest.
    pub fn validate(&self) -> Result<(), UpdateInstallerError> {
        if self.name.is_empty()
            || self.name.contains(['/', '\\'])
            || self.name == "."
            || self.name == ".."
        {
            return Err(UpdateInstallerError::InvalidPackage {
                reason: "package name must be a non-empty single path segment".to_owned(),
            });
        }
        if self.version.is_empty()
            || self.version.contains(['/', '\\'])
            || self.version == "."
            || self.version == ".."
        {
            return Err(UpdateInstallerError::InvalidPackage {
                reason: "package version must be a non-empty single path segment".to_owned(),
            });
        }
        let digest_ok =
            self.artifact_sha256.len() == 64 && self.artifact_sha256.bytes().all(is_lower_hex);
        if !digest_ok {
            return Err(UpdateInstallerError::InvalidPackage {
                reason: "artifact_sha256 must be 64 lowercase hex characters".to_owned(),
            });
        }
        Ok(())
    }
}

fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()
}

/// A staged update installation request.
#[derive(Debug)]
pub struct InstallUpdateRequest<'a> {
    /// Installation root; the versioned directory is created below it.
    pub install_root: &'a Path,
    /// Currently running executable, if any. Never overwritten.
    pub running_executable: Option<&'a Path>,
    /// Package metadata for the update.
    pub package: &'a PackageMetadata,
    /// Raw executable payload bytes staged into the new versioned directory.
    pub payload: &'a [u8],
    /// Previous versioned directory for module-generation rollback metadata.
    pub previous_version_dir: Option<&'a Path>,
    /// Release approval token presence for Kernel/Host release updates.
    pub release_approved: bool,
}

/// Durable record of a staged update installation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRecord {
    /// Package (binary) name.
    pub package_name: String,
    /// Installed version label.
    pub version: String,
    /// One of the three declared channels.
    pub channel: UpdateChannel,
    /// Release-level versus hot-generation classification.
    pub kind: UpdateKind,
    /// New versioned directory the package was staged into.
    pub installed_dir: PathBuf,
    /// Staged executable path inside the new versioned directory.
    pub executable_path: PathBuf,
    /// Generation identity (`<name>@<version>`) for rollback lineage.
    pub generation: String,
    /// Previous versioned directory; set only for module-generation updates.
    pub rollback_from: Option<PathBuf>,
}

/// Update installer failures. All variants fail closed before overwriting.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UpdateInstallerError {
    #[error("unknown update channel '{channel}': declared channels are stable, preview, local-dev")]
    UnknownChannel { channel: String },
    #[error("invalid update package: {reason}")]
    InvalidPackage { reason: String },
    #[error("refusing to overwrite the running binary at '{path}'")]
    RunningBinaryWouldBeOverwritten { path: String },
    #[error(
        "versioned directory already exists at '{path}': updates always create a new versioned directory"
    )]
    VersionedDirExists { path: String },
    #[error("kernel/host release update requires the release approval path")]
    ReleaseApprovalRequired,
    #[error("update staging failed: {reason}")]
    StagingFailed { reason: String },
}

/// Compute the versioned install directory `<root>/<name>/<version>`.
#[must_use]
pub fn versioned_dir(install_root: &Path, package_name: &str, version: &str) -> PathBuf {
    install_root.join(package_name).join(version)
}

/// Executable file name staged inside a versioned directory.
#[must_use]
pub fn staged_executable_name(package_name: &str) -> String {
    if cfg!(windows) {
        format!("{package_name}.exe")
    } else {
        package_name.to_owned()
    }
}

fn paths_equal(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    #[cfg(windows)]
    {
        left.as_os_str()
            .to_string_lossy()
            .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy())
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Report whether staging into `new_executable` would overwrite `running`.
#[must_use]
pub fn running_binary_would_be_overwritten(running: &Path, new_executable: &Path) -> bool {
    if paths_equal(running, new_executable) {
        return true;
    }
    match (running.parent(), new_executable.parent()) {
        (Some(running_dir), Some(new_dir)) => paths_equal(running_dir, new_dir),
        (None, None) => true,
        (None, Some(_)) | (Some(_), None) => false,
    }
}

/// Install an update package into a new versioned directory.
///
/// The running executable is never overwritten: when
/// `request.running_executable` resolves to the staged executable path or its
/// parent versioned directory, installation fails closed with
/// [`UpdateInstallerError::RunningBinaryWouldBeOverwritten`]. Kernel/Host
/// packages fail closed without `release_approved`.
///
/// # Errors
///
/// Returns an error for invalid metadata, a missing release approval, a
/// running-binary collision, an already-existing versioned directory, or any
/// staging I/O failure.
pub fn install_update(
    request: &InstallUpdateRequest<'_>,
) -> Result<UpdateRecord, UpdateInstallerError> {
    request.package.validate()?;
    if !request.install_root.is_absolute() {
        return Err(UpdateInstallerError::InvalidPackage {
            reason: "install_root must be absolute".to_owned(),
        });
    }
    let kind = UpdateKind::classify(&request.package.name);
    if kind.requires_release_approval() && !request.release_approved {
        return Err(UpdateInstallerError::ReleaseApprovalRequired);
    }
    let installed_dir = versioned_dir(
        request.install_root,
        &request.package.name,
        &request.package.version,
    );
    let executable_path = installed_dir.join(staged_executable_name(&request.package.name));
    if let Some(running) = request.running_executable
        && running_binary_would_be_overwritten(running, &executable_path)
    {
        return Err(UpdateInstallerError::RunningBinaryWouldBeOverwritten {
            path: running.display().to_string(),
        });
    }
    if installed_dir.exists() {
        return Err(UpdateInstallerError::VersionedDirExists {
            path: installed_dir.display().to_string(),
        });
    }
    std::fs::create_dir_all(&installed_dir).map_err(|error| {
        UpdateInstallerError::StagingFailed {
            reason: format!("create versioned directory: {error}"),
        }
    })?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&executable_path)
        .map_err(|error| UpdateInstallerError::StagingFailed {
            reason: format!("stage update executable: {error}"),
        })?;
    file.write_all(request.payload)
        .map_err(|error| UpdateInstallerError::StagingFailed {
            reason: format!("write update executable: {error}"),
        })?;
    file.sync_all()
        .map_err(|error| UpdateInstallerError::StagingFailed {
            reason: format!("flush update executable: {error}"),
        })?;
    drop(file);
    Ok(UpdateRecord {
        package_name: request.package.name.clone(),
        version: request.package.version.clone(),
        channel: request.package.channel,
        kind,
        installed_dir,
        executable_path,
        generation: format!("{}@{}", request.package.name, request.package.version),
        rollback_from: match kind {
            UpdateKind::ModuleGeneration => request.previous_version_dir.map(Path::to_path_buf),
            UpdateKind::KernelHostRelease => None,
        },
    })
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn test_package(name: &str, version: &str, channel: UpdateChannel) -> PackageMetadata {
        PackageMetadata {
            name: name.to_owned(),
            version: version.to_owned(),
            channel,
            artifact_sha256: "ab".repeat(32),
        }
    }

    fn unique_root(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let pid = std::process::id();
        std::env::temp_dir().join(format!("eliot-update-installer-{label}-{pid}-{nanos}"))
    }

    #[test]
    fn running_update_creates_new_versioned_dir_and_leaves_running_exe_unchanged() {
        let root = unique_root("running");
        let running_dir = versioned_dir(&root, "example-module", "1.0.0");
        std::fs::create_dir_all(&running_dir).expect("create running version dir");
        let running_exe = running_dir.join(staged_executable_name("example-module"));
        std::fs::write(&running_exe, b"running-v1").expect("write running exe");
        let before = std::fs::read(&running_exe).expect("read running exe");

        let package = test_package("example-module", "1.0.1", UpdateChannel::Stable);
        let request = InstallUpdateRequest {
            install_root: &root,
            running_executable: Some(&running_exe),
            package: &package,
            payload: b"updated-v2",
            previous_version_dir: Some(&running_dir),
            release_approved: false,
        };
        let record = install_update(&request).expect("install update");

        assert_eq!(record.channel, UpdateChannel::Stable);
        assert_eq!(record.kind, UpdateKind::ModuleGeneration);
        assert_eq!(
            record.installed_dir,
            versioned_dir(&root, "example-module", "1.0.1")
        );
        assert!(record.installed_dir.exists());
        assert_ne!(record.installed_dir, running_dir);
        let staged = std::fs::read(&record.executable_path).expect("read staged exe");
        assert_eq!(staged, b"updated-v2".as_slice());
        let after = std::fs::read(&running_exe).expect("reread running exe");
        assert_eq!(before, after);
        assert_eq!(record.rollback_from, Some(running_dir.clone()));
        assert_eq!(record.generation, "example-module@1.0.1");
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn channels_parse_and_kernel_host_vs_module_kinds_classify() {
        assert_eq!(UpdateChannel::parse("stable"), Ok(UpdateChannel::Stable));
        assert_eq!(UpdateChannel::parse("preview"), Ok(UpdateChannel::Preview));
        assert_eq!(
            UpdateChannel::parse("local-dev"),
            Ok(UpdateChannel::LocalDev)
        );
        assert!(UpdateChannel::parse("nightly").is_err());

        assert_eq!(
            UpdateKind::classify("eliot-kernel"),
            UpdateKind::KernelHostRelease
        );
        assert_eq!(
            UpdateKind::classify("eliot-host"),
            UpdateKind::KernelHostRelease
        );
        assert!(UpdateKind::KernelHostRelease.requires_release_approval());
        assert_eq!(
            UpdateKind::classify("example-module"),
            UpdateKind::ModuleGeneration
        );
        assert!(!UpdateKind::ModuleGeneration.requires_release_approval());

        let root = unique_root("channels");
        for channel in [
            UpdateChannel::Stable,
            UpdateChannel::Preview,
            UpdateChannel::LocalDev,
        ] {
            let package = test_package("example-module", channel.as_str(), channel);
            let request = InstallUpdateRequest {
                install_root: &root,
                running_executable: None,
                package: &package,
                payload: b"payload",
                previous_version_dir: None,
                release_approved: false,
            };
            let record = install_update(&request).expect("install module update");
            assert_eq!(record.channel, channel);
            assert_eq!(record.kind, UpdateKind::ModuleGeneration);
        }

        let kernel = test_package("eliot-kernel", "9.9.9", UpdateChannel::Stable);
        let denied = InstallUpdateRequest {
            install_root: &root,
            running_executable: None,
            package: &kernel,
            payload: b"payload",
            previous_version_dir: None,
            release_approved: false,
        };
        assert_eq!(
            install_update(&denied),
            Err(UpdateInstallerError::ReleaseApprovalRequired)
        );
        let allowed = InstallUpdateRequest {
            release_approved: true,
            ..denied
        };
        let record = install_update(&allowed).expect("install release update");
        assert_eq!(record.channel, UpdateChannel::Stable);
        assert_eq!(record.kind, UpdateKind::KernelHostRelease);
        assert_eq!(record.rollback_from, None);
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn reinstall_over_running_binary_fails_closed() {
        let root = unique_root("guard");
        let running_dir = versioned_dir(&root, "example-module", "2.0.0");
        std::fs::create_dir_all(&running_dir).expect("create running version dir");
        let running_exe = running_dir.join(staged_executable_name("example-module"));
        std::fs::write(&running_exe, b"running").expect("write running exe");

        let package = test_package("example-module", "2.0.0", UpdateChannel::Preview);
        let request = InstallUpdateRequest {
            install_root: &root,
            running_executable: Some(&running_exe),
            package: &package,
            payload: b"overwrite-attempt",
            previous_version_dir: None,
            release_approved: false,
        };
        let error = install_update(&request).expect_err("must refuse overwrite");
        assert!(matches!(
            error,
            UpdateInstallerError::RunningBinaryWouldBeOverwritten { .. }
                | UpdateInstallerError::VersionedDirExists { .. }
        ));
        assert_eq!(
            std::fs::read(&running_exe).expect("read"),
            b"running".as_slice()
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }
}
