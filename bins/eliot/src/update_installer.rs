//! Typed update channels and versioned update installation (I3.8).
//!
//! Update packages are installed into new versioned directories; the installer
//! never overwrites a running binary. Whether the update target is running is
//! observed from a live process snapshot before any filesystem effect, not
//! asserted by the operator, and an observed running target refuses the whole
//! install. The observation is **path-exact**: it compares the whole update
//! target path against the image path Windows reports for each live process
//! (`I1.6`, `docs/architecture/I01-06-windows-isolation.md:15`, "versioned
//! binaries are never replaced in place while running"), so a same-named copy
//! running from another directory is a different file and never stands in for
//! this one. An install additionally admits the new version as a **distinct
//! binary generation** through
//! [`super::binary_generation_staging`]: it creates a new versioned generation
//! directory, writes the new executable `create_new`, and names the superseded
//! generation directory as its rollback source, so a running generation's bytes
//! are never replaced in place (`I1.6`) and the new version is admitted as its
//! own generation identity (`I14.14`). The only declared channels are
//! `stable`, `preview`, and `local-dev`. Kernel/Host updates are release-level
//! operations requiring the release approval path, while optional module
//! updates are normal hot-generation operations carrying explicit
//! generation/rollback metadata.
//!
//! # Platform precondition
//!
//! The running-state observation is sourced from a live **Windows** process
//! snapshot. The observation owner returns `Unavailable` from a compile-time
//! `#[cfg(not(windows))]` branch, so on a non-Windows build every
//! [`install_update`] refuses with
//! [`UpdateInstallerError::RunningObservationFailed`] rather than assuming the
//! target is idle (I3.15 forbids adopting an unknown process). Update staging is
//! therefore a Windows-only operation as written; this is recorded rather than
//! worked around, because a non-Windows observation owner does not exist in this
//! tree.

#![forbid(unsafe_code)]

use std::fmt;
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

/// Observed liveness of an update target executable.
///
/// This is a fact taken from a live process snapshot before any filesystem
/// effect, never an operator assertion. `NotRunning` is only ever reported
/// from a completed snapshot in which every live name-matching candidate's
/// image path was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunningTargetObservation {
    /// A live process is executing **this exact file**: the image path Windows
    /// reports for that process equals the requested executable path.
    Running {
        /// The **requested** executable basename the path-exact comparison
        /// resolved to, not a basename matched somewhere on the machine: the
        /// owner compares whole image paths, so this is a label on the observed
        /// file rather than the predicate that was tested.
        process_basename: String,
    },
    /// The completed snapshot observed no live process whose image path is
    /// this exact file. A same-named copy executing from a different directory
    /// is a different file and is correctly outside this answer.
    NotRunning,
}

/// A staged update installation request.
#[derive(Debug)]
pub struct InstallUpdateRequest<'a> {
    /// Installation root; the versioned directory is created below it.
    pub install_root: &'a Path,
    /// Optional exact path of an executable the operator declares as running.
    ///
    /// The exact path-identity refusal in
    /// [`running_binary_would_be_overwritten`] reads this path, and the
    /// path-exact live snapshot observation behind
    /// [`UpdateRecord::running_target`] additionally observes this exact file
    /// when it differs from the staged executable path, so a live copy that is
    /// still the one actually executing is observed rather than assumed. The
    /// two mechanisms stay independent, and neither depends on this field:
    /// `install_update` gates on the observed `running_target` itself, so
    /// omitting this declaration never removes the running-binary refusal.
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
    /// Running state of the update target, observed before staging.
    pub running_target: RunningTargetObservation,
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
    #[error("cannot observe whether '{path}' is running: {reason}")]
    RunningObservationFailed { path: String, reason: String },
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

/// Observe, from a live process snapshot, whether the executable named by
/// `executable` is currently running (I3.8: the installer never overwrites a
/// running binary; `I1.6`: "versioned binaries are never replaced in place
/// while running").
///
/// The observation is **path-exact**: the whole `executable` path is compared
/// against the image path Windows reports for each live process
/// ([`eliot_platform_windows::any_running_process_executing`]), so
/// [`RunningTargetObservation::Running`] means a live process is executing
/// *this file*. It is not a basename search: a same-named copy installed
/// elsewhere on the machine — the failure mode the previous basename check
/// could not distinguish — is reported as `NotRunning` for this file, which is
/// the correct answer to the question actually being asked, and the installer
/// installs into a new versioned directory anyway, so no other file is touched.
///
/// This is an independent observation: it neither reads nor is read by the
/// exact path-identity check in [`running_binary_would_be_overwritten`], and it
/// never opens the target file, so the shared-locked image of a running
/// process is not a source of false refusals.
///
/// # Errors
///
/// Returns [`UpdateInstallerError::InvalidPackage`] when `executable` is not
/// an absolute drive-rooted or UNC path (a bare file name cannot be observed
/// path-exactly, and a relative spelling would silently degrade to a name
/// search), and [`UpdateInstallerError::RunningObservationFailed`] when the live
/// process snapshot is unavailable, when the enumeration fails, or when a live
/// name-matching candidate's image path cannot be read — including
/// unconditionally on a non-Windows build, where the owner reports
/// `Unavailable`. An unreadable candidate is a typed refusal rather than
/// `NotRunning`: the copy that matters may be the one that cannot be read, and
/// "I could not observe" must never be read as "it is idle". There is no path
/// that reports [`RunningTargetObservation::NotRunning`] without a completed
/// snapshot in which every live name-matching candidate's image was read.
pub fn observe_running_executable(
    executable: &Path,
) -> Result<RunningTargetObservation, UpdateInstallerError> {
    let Some(basename) = executable.file_name().and_then(|name| name.to_str()) else {
        return Err(UpdateInstallerError::InvalidPackage {
            reason: "update target executable must name a single path segment".to_owned(),
        });
    };
    match eliot_platform_windows::any_running_process_executing(executable) {
        Ok(true) => Ok(RunningTargetObservation::Running {
            process_basename: basename.to_owned(),
        }),
        Ok(false) => Ok(RunningTargetObservation::NotRunning),
        Err(error) => Err(UpdateInstallerError::RunningObservationFailed {
            path: executable.display().to_string(),
            reason: error.to_string(),
        }),
    }
}

/// Install an update package as a new admitted binary generation.
///
/// The running executable is never overwritten. Before any filesystem effect
/// the running state of the update target is **observed** from a live process
/// snapshot ([`observe_running_executable`]) and carried into the returned
/// [`UpdateRecord`]. The observation is path-exact: the staged executable path
/// `<installed_dir>/<package>.exe` — a file that does not exist yet — is
/// compared against the image path Windows reports for every live process, so
/// a same-named copy running from another directory is a different file and
/// does not refuse this one. When `request.running_executable` names a
/// different file, that exact file is observed too, so the operator-declared
/// live copy is observed rather than assumed; an observation failure for
/// either path refuses with
/// [`UpdateInstallerError::RunningObservationFailed`]. `NotRunning` proves only
/// that no live process is executing that exact file, and
/// `request.previous_version_dir` (where the running copy usually lives) is
/// not consulted.
///
/// The observation **gates** the install: an observed
/// [`RunningTargetObservation::Running`] refuses the whole install with
/// [`UpdateInstallerError::RunningBinaryWouldBeOverwritten`] naming the staged
/// executable path, whether or not `request.running_executable` is set.
/// Declaring a running path is never required for the refusal, and no
/// declaration can override it: the snapshot is fail-closed, so `NotRunning` is
/// never synthesized without a completed process snapshot whose every
/// name-matching candidate image was read. That refusal precedes every
/// filesystem effect, including the generation admission below.
///
/// The install then admits a **new admitted binary generation** through
/// [`super::binary_generation_staging::admit_binary_generation`] and writes its
/// bytes through
/// [`super::binary_generation_staging::stage_generation_executable`]. That pair
/// is what makes a deployment a new versioned generation rather than an
/// in-place replacement: an existing version directory or executable is refused
/// by admission, and the write itself opens the destination `create_new`, so no
/// deployment through this crate can overwrite the bytes of a file that already
/// exists — running or not. `I1.6` requires "versioned binaries are never
/// replaced in place while running"; this is the path that refuses it.
///
/// Separately and independently, when `request.running_executable` resolves to
/// the staged executable path or its parent versioned directory, installation
/// also fails closed with
/// [`UpdateInstallerError::RunningBinaryWouldBeOverwritten`] naming the
/// declared path. Kernel/Host packages fail closed without `release_approved`.
///
/// # Errors
///
/// Returns an error for invalid metadata, a missing release approval, a
/// running-state observation failure, a running-binary collision, an
/// already-existing versioned directory, or any staging I/O failure.
///
/// **Platform precondition:** the running-state observation is a live Windows
/// process snapshot. On a non-Windows build the owner reports `Unavailable` from
/// a compile-time `#[cfg(not(windows))]` branch, so this function **always**
/// returns [`UpdateInstallerError::RunningObservationFailed`] and stages
/// nothing there. That refusal is deliberate: I3.15 forbids adopting an unknown
/// process, and `docs/architecture/I01-07-linux-portability-boundary.md` keeps
/// authority/fencing semantics off the Windows-coupled path, so
/// [`RunningTargetObservation::NotRunning`] is never synthesized off-Windows.
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
    // Detect before staging and before any filesystem effect: the running
    // state is read from a live process snapshot, not supplied by the caller.
    // The staged executable path is always observed; a declared live path
    // naming a *different file* is observed too, so a live copy of an earlier
    // generation is still seen. Under the path-exact predicate the divergence
    // test is the whole path, not the file name: two paths that share a file
    // name in different directories are two different files, and a second
    // observation of the first one would observe nothing new.
    let mut running_target = observe_running_executable(&executable_path)?;
    if let Some(running) = request.running_executable
        && !paths_equal(running, &executable_path)
    {
        let declared = observe_running_executable(running)?;
        if matches!(declared, RunningTargetObservation::Running { .. }) {
            running_target = declared;
        }
    }
    // Enforce the observation, not just the declaration: a live process
    // executing the staged executable's exact file — or a declared different
    // file that a completed snapshot also found executing — refuses the whole
    // install. The snapshot is fail-closed, so an `Ok` observation always rests
    // on a completed process snapshot whose every name-matching candidate image
    // was read; there is no caller-supplied override, and the refusal lands
    // before `versioned_dir` staging and before the versioned-directory fence
    // below, so it is distinguishable from the structural refusal.
    if matches!(running_target, RunningTargetObservation::Running { .. }) {
        return Err(UpdateInstallerError::RunningBinaryWouldBeOverwritten {
            path: executable_path.display().to_string(),
        });
    }
    if let Some(running) = request.running_executable
        && running_binary_would_be_overwritten(running, &executable_path)
    {
        return Err(UpdateInstallerError::RunningBinaryWouldBeOverwritten {
            path: running.display().to_string(),
        });
    }
    // Admit the new version as a distinct binary generation before any
    // filesystem effect. `I14.14` keeps "Running artifacts are immutable" and
    // makes the active generation registry state, so a deployment admits a new
    // `<name>/<version>` generation and names the superseded one as its
    // rollback source. A version whose directory or executable already exists
    // is refused here rather than reused: that is the structural half of the
    // `I1.6` "never replaced in place" rule, and it is reached before any byte
    // of the new generation is written.
    let admitted = super::binary_generation_staging::admit_binary_generation(
        request.install_root,
        &request.package.name,
        &request.package.version,
        match kind {
            UpdateKind::ModuleGeneration => request.previous_version_dir,
            UpdateKind::KernelHostRelease => None,
        },
    )
    .map_err(|error| match error {
        super::binary_generation_staging::BinaryGenerationStagingError::VersionedDirectoryExists {
            path,
        }
        | super::binary_generation_staging::BinaryGenerationStagingError::GenerationPathNotADirectory {
            path,
        } => UpdateInstallerError::VersionedDirExists { path },
        // `admit_binary_generation` never produces this arm: admission refuses an
        // existing generation directory, and the executable path it hands back
        // lives inside that refused directory. The arm is kept only to keep this
        // match total; the reachable typed refusal is produced by the write
        // below, which is where an existing destination file is actually met.
        super::binary_generation_staging::BinaryGenerationStagingError::GenerationAlreadyExists {
            path,
        } => UpdateInstallerError::VersionedDirExists { path },
        super::binary_generation_staging::BinaryGenerationStagingError::StagingFailed { reason } => {
            UpdateInstallerError::StagingFailed { reason }
        }
    })?;
    // Write the new generation's bytes through the staging owner. It opens the
    // destination with `create_new`, so this is the point at which an attempt to
    // replace an existing file's bytes is refused as itself, rather than being
    // reported as a generic staging failure. The refusal stays typed across the
    // layer boundary: it surfaces as
    // `UpdateInstallerError::RunningBinaryWouldBeOverwritten`, the same refusal
    // the live running-target gate uses.
    super::binary_generation_staging::stage_generation_executable(&admitted, request.payload)
        .map_err(|error| match error {
            super::binary_generation_staging::BinaryGenerationStagingError::GenerationAlreadyExists {
                path,
            } => UpdateInstallerError::RunningBinaryWouldBeOverwritten { path },
            super::binary_generation_staging::BinaryGenerationStagingError::VersionedDirectoryExists {
                path,
            }
            | super::binary_generation_staging::BinaryGenerationStagingError::GenerationPathNotADirectory {
                path,
            } => UpdateInstallerError::VersionedDirExists { path },
            super::binary_generation_staging::BinaryGenerationStagingError::StagingFailed {
                reason,
            } => UpdateInstallerError::StagingFailed { reason },
        })?;
    Ok(UpdateRecord {
        package_name: request.package.name.clone(),
        version: request.package.version.clone(),
        channel: request.package.channel,
        kind,
        installed_dir: admitted.generation_dir,
        executable_path: admitted.executable_path,
        // The identity and the rollback source come from the admitted
        // generation itself, so the durable record cannot describe a different
        // generation than the one whose bytes were just written. The admitted
        // value is moved only here, after the write consumed a borrow of it.
        generation: admitted.generation,
        rollback_from: match kind {
            UpdateKind::ModuleGeneration => admitted.supersedes_dir,
            UpdateKind::KernelHostRelease => None,
        },
        running_target,
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
        // The staged versioned directory is deliberately absent, so the
        // structural `VersionedDirExists` fence cannot be what refuses here:
        // the only refusal this scenario can reach is the running-binary one.
        // The live process that stands in for the running copy is THIS test
        // binary, observed at its own exact image path. That is the path-exact
        // observation `I1.6` requires; the previous basename check could only
        // have proved that some process somewhere carried the file name.
        let own_image = std::env::current_exe().expect("resolve this test's own image");
        assert!(
            matches!(
                observe_running_executable(&own_image),
                Ok(RunningTargetObservation::Running { .. })
            ),
            "the proof process must be observed as running at its exact image \
             path for this scenario to cover anything"
        );
        // A same-named file in a different directory is a DIFFERENT file and
        // must not be reported as running: this is the false-refusal the
        // path-exact check exists to remove, and it is asserted here so the
        // caller's gate cannot silently weaken back to a name search.
        let same_name_elsewhere = own_image
            .parent()
            .expect("own image parent")
            .join("example-module.exe");
        assert_eq!(
            observe_running_executable(&same_name_elsewhere),
            Ok(RunningTargetObservation::NotRunning),
            "a same-named file in another directory must not stand in for the \
             exact file being replaced"
        );

        let root = unique_root("guard");
        let running_dir = versioned_dir(&root, "example-module", "2.0.0");
        let running_exe = running_dir.join(staged_executable_name("example-module"));
        let package = test_package("example-module", "2.0.0", UpdateChannel::Preview);

        // Declaring the live exact file must refuse the whole install with the
        // existing typed refusal, and must do so before any filesystem effect.
        let declared_live = InstallUpdateRequest {
            install_root: &root,
            running_executable: Some(&own_image),
            package: &package,
            payload: b"overwrite-attempt",
            previous_version_dir: None,
            release_approved: false,
        };
        let observed = install_update(&declared_live).expect_err("must refuse overwrite");
        assert!(
            matches!(
                observed,
                UpdateInstallerError::RunningBinaryWouldBeOverwritten { .. }
            ),
            "an observed running target must refuse with \
             RunningBinaryWouldBeOverwritten, got: {observed:?}"
        );
        assert_eq!(
            observed,
            UpdateInstallerError::RunningBinaryWouldBeOverwritten {
                path: versioned_dir(&root, "example-module", "2.0.0")
                    .join(staged_executable_name("example-module"))
                    .display()
                    .to_string(),
            }
        );
        assert!(
            !root.exists(),
            "the refusal must precede every filesystem effect"
        );

        // Nothing is executing at the staged path, so with no declaration the
        // install proceeds into a NEW versioned directory and leaves every
        // existing file alone: the path-exact gate is no longer a blanket
        // machine-wide name refusal, it is the sentence's actual predicate.
        // This one uses a DIFFERENT version so it does not collide with the
        // structural case below, which owns `<root>/example-module/2.0.0`.
        let idle_package = test_package("example-module", "3.0.0", UpdateChannel::Preview);
        let undeclared = InstallUpdateRequest {
            install_root: &root,
            running_executable: None,
            package: &idle_package,
            payload: b"overwrite-attempt",
            previous_version_dir: None,
            release_approved: false,
        };
        let record = install_update(&undeclared).expect("idle staged path must install");
        assert_eq!(record.running_target, RunningTargetObservation::NotRunning);
        assert_eq!(record.version, "3.0.0");
        assert!(record.installed_dir.exists());
        assert_eq!(
            std::fs::read(&record.executable_path).expect("read staged exe"),
            b"overwrite-attempt".as_slice()
        );
        assert_eq!(
            versioned_dir(&root, "example-module", "3.0.0"),
            record.installed_dir,
            "an idle target must still stage a new versioned generation"
        );

        // A declaration naming the same parent versioned directory takes the
        // path-identity refusal instead; it stays the structural case, and it
        // is reached with the SAME install root so the declared path really is
        // the file that would be replaced.
        std::fs::create_dir_all(&running_dir).expect("create running version dir");
        std::fs::write(&running_exe, b"running").expect("write running exe");
        let declared = InstallUpdateRequest {
            install_root: &root,
            running_executable: Some(&running_exe),
            ..undeclared
        };
        let error = install_update(&declared).expect_err("must refuse overwrite");
        assert_eq!(
            error,
            UpdateInstallerError::RunningBinaryWouldBeOverwritten {
                path: running_exe.display().to_string(),
            }
        );
        assert_eq!(
            std::fs::read(&running_exe).expect("read"),
            b"running".as_slice(),
            "the structural refusal must leave the declared file's bytes untouched"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn reinstallation_over_an_admitted_generation_is_refused_and_keeps_the_staged_bytes() {
        // A deployment must stage a NEW versioned binary generation and refuse
        // in-place replacement. This is the structural half on the reachable
        // production path: the package basename is deliberately not observed as
        // running (nothing named `w6-absent-module.exe` runs), so the
        // live-snapshot gate passes and the refusal that is reached is the
        // generation-admission refusal — the existing generation is never
        // rewritten with the new payload.
        let root = unique_root("in-place");
        let package = test_package("w6-absent-module", "3.1.0", UpdateChannel::Stable);

        let first = install_update(&InstallUpdateRequest {
            install_root: &root,
            running_executable: None,
            package: &package,
            payload: b"generation-three-one-zero",
            previous_version_dir: None,
            release_approved: false,
        })
        .expect("admit first generation");
        assert_eq!(first.generation, "w6-absent-module@3.1.0");
        let before = std::fs::read(&first.executable_path).expect("read first generation");

        // The same version again is an in-place replacement attempt.
        let error = install_update(&InstallUpdateRequest {
            install_root: &root,
            running_executable: None,
            package: &package,
            payload: b"in-place-overwrite",
            previous_version_dir: None,
            release_approved: false,
        })
        .expect_err("an admitted generation must not be replaced in place");
        assert_eq!(
            error,
            UpdateInstallerError::VersionedDirExists {
                path: first.installed_dir.display().to_string(),
            }
        );
        assert_eq!(
            std::fs::read(&first.executable_path).expect("reread first generation"),
            before,
            "the refused in-place replacement must leave the admitted bytes untouched"
        );

        // A different version is admitted as its own distinct generation and
        // records the superseded generation as the rollback source.
        let next_version = test_package("w6-absent-module", "3.2.0", UpdateChannel::Stable);
        let second = install_update(&InstallUpdateRequest {
            install_root: &root,
            running_executable: None,
            package: &next_version,
            payload: b"generation-three-two-zero",
            previous_version_dir: Some(&first.installed_dir),
            release_approved: false,
        })
        .expect("admit next generation");
        assert_eq!(second.generation, "w6-absent-module@3.2.0");
        assert_ne!(second.generation, first.generation);
        assert_ne!(second.installed_dir, first.installed_dir);
        assert_eq!(second.rollback_from, Some(first.installed_dir.clone()));
        assert_eq!(
            std::fs::read(&first.executable_path).expect("reread first generation"),
            before,
            "admitting a new generation must not alter the superseded generation's bytes"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }
}
