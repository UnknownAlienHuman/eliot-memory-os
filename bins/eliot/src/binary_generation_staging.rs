//! Versioned binary generation staging for update deployment (I1.6, I3.8, I14.14).
//!
//! `I1.6` (`docs/architecture/I01-06-windows-isolation.md:15`) requires that
//! "versioned binaries are never replaced in place while running". `I3.8`
//! (`docs/architecture/I03-08-updates.md:3`) requires that "Update packages are
//! placed in versioned directories" and that the "Installer never overwrites a
//! running binary". `I14.14`
//! (`docs/architecture/I14-14-module-hot-replacement.md:15`) requires that
//! "Running artifacts are immutable. Active generation is registry state."
//!
//! This module owns the two halves that together make a deployment observable
//! as a new admitted binary generation rather than an in-place rewrite:
//!
//! 1. [`admit_binary_generation`] computes the versioned generation directory
//!    and the staged executable path inside it, and refuses any generation whose
//!    directory or executable already exists. Because every write goes through
//!    [`stage_generation_executable`], which opens the destination with
//!    `create_new`, no deployment path in this crate can ever write over the
//!    bytes of a file that already exists — running or not. That refusal is
//!    structural, not heuristic: it is reached by the overwrite itself, not by
//!    some other precondition happening to fail first.
//!
//! 2. The generation identity admitted here (`<package>@<version>`) is carried
//!    by the caller into the durable update record, so the new version is
//!    recorded as a distinct generation identity and the superseded generation
//!    is recorded as the rollback source rather than being overwritten.
//!
//! # Detection boundary (recorded, not worked around)
//!
//! `I1.6` states the refusal target ("replaced in place") but does not name a
//! detection mechanism, and this crate owns no process-enumeration seam for it.
//! The live liveness observation remains owned by
//! `eliot_platform_windows::any_running_process_named`, which
//! [`super::update_installer::observe_running_executable`] already calls. That
//! owner searches by executable **basename** and returns only a boolean; the
//! platform crate exposes no public path-exact "is this exact file executing"
//! observation (`inspect_process_identity` is crate-private and
//! `WindowsPlatform::process_identity` needs a PID this installer does not
//! own, and `JobObject::job_processes` needs a Host-owned Job handle). This
//! module therefore does not restate or second-guess that observation: the
//! in-place refusal it enforces is the structural one above, which holds for
//! every path regardless of liveness.

#![forbid(unsafe_code)]

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::update_installer::staged_executable_name;

/// One admitted binary generation: a package identity staged into its own
/// versioned directory.
///
/// This is the deployment-staging projection of a generation identity. It is
/// not a second generation lifecycle: activation, cutover and retirement stay
/// with the installation owner (`ApprovedGenerationRegistry`), and this value
/// only records which distinct generation identity the new bytes were staged
/// under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryGeneration {
    /// Canonical generation identity `<package>@<version>`.
    pub generation: String,
    /// Package (binary) name.
    pub package_name: String,
    /// Installed version label; the versioned directory name.
    pub version: String,
    /// New versioned directory created for this generation.
    pub generation_dir: PathBuf,
    /// Executable staged inside the new generation directory.
    pub executable_path: PathBuf,
    /// Superseded generation directory retained as the rollback source, when
    /// the caller declared one.
    pub supersedes_dir: Option<PathBuf>,
}

/// Failures of binary-generation admission and staging. Every variant refuses
/// before the first byte of the new generation is written.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum BinaryGenerationStagingError {
    #[error(
        "refusing in-place replacement: '{path}' already exists as a versioned binary generation"
    )]
    GenerationAlreadyExists { path: String },
    #[error(
        "refusing in-place replacement: '{path}' already exists and is not a versioned directory"
    )]
    GenerationPathNotADirectory { path: String },
    #[error("refusing in-place replacement: versioned directory '{path}' already exists")]
    VersionedDirectoryExists { path: String },
    #[error("stage binary generation executable: {reason}")]
    StagingFailed { reason: String },
}

/// Compute the versioned generation directory `<root>/<package>/<version>`.
///
/// This is the existing `I3.8` versioned-directory layout. The new version
/// never reuses the previous version's directory, so a running generation's
/// bytes cannot be reached by a later deployment.
///
/// # Errors
///
/// Returns [`BinaryGenerationStagingError::VersionedDirectoryExists`] when that
/// exact versioned directory is already present, and
/// [`BinaryGenerationStagingError::GenerationPathNotADirectory`] when the path
/// exists as something other than a directory.
pub fn admit_binary_generation(
    install_root: &Path,
    package_name: &str,
    version: &str,
    supersedes_dir: Option<&Path>,
) -> Result<BinaryGeneration, BinaryGenerationStagingError> {
    let generation_dir = install_root.join(package_name).join(version);
    if generation_dir.exists() {
        // Refuse rather than reuse. This is the structural half of "never
        // replaced in place": a generation whose directory already exists is a
        // generation whose bytes already exist, whether or not anything is
        // currently running from it.
        if !generation_dir.is_dir() {
            return Err(BinaryGenerationStagingError::GenerationPathNotADirectory {
                path: generation_dir.display().to_string(),
            });
        }
        return Err(BinaryGenerationStagingError::VersionedDirectoryExists {
            path: generation_dir.display().to_string(),
        });
    }
    let executable_path = generation_dir.join(staged_executable_name(package_name));
    Ok(BinaryGeneration {
        generation: format!("{package_name}@{version}"),
        package_name: package_name.to_owned(),
        version: version.to_owned(),
        generation_dir,
        executable_path,
        supersedes_dir: supersedes_dir.map(Path::to_path_buf),
    })
}

/// Write the new generation's executable bytes into its own versioned
/// directory, creating the directory and the file new.
///
/// The file is opened with `create_new`, so this fails rather than writing over
/// any existing file. That is what makes the in-place refusal of `I1.6`
/// reachable on the write path itself instead of depending on a liveness
/// heuristic: a running binary's file already exists, so this call refuses, and
/// the running generation keeps every byte it had.
///
/// The superseded generation directory named by the admitted generation is
/// recorded as the rollback source by the caller. Nothing here reads, truncates
/// or replaces it: a running generation is immutable per `I14.14`.
///
/// # Errors
///
/// Returns [`BinaryGenerationStagingError::GenerationAlreadyExists`] when the
/// destination executable already exists, and
/// [`BinaryGenerationStagingError::StagingFailed`] for any directory, write or
/// flush failure.
pub fn stage_generation_executable(
    generation: &BinaryGeneration,
    payload: &[u8],
) -> Result<(), BinaryGenerationStagingError> {
    std::fs::create_dir_all(&generation.generation_dir).map_err(|error| {
        BinaryGenerationStagingError::StagingFailed {
            reason: format!("create versioned generation directory: {error}"),
        }
    })?;
    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&generation.executable_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            // The destination file object already exists, so this write would
            // replace its bytes. That is the in-place replacement `I1.6`
            // forbids, and it is refused here as itself rather than as a
            // generic staging failure.
            return Err(BinaryGenerationStagingError::GenerationAlreadyExists {
                path: generation.executable_path.display().to_string(),
            });
        }
        Err(error) => {
            return Err(BinaryGenerationStagingError::StagingFailed {
                reason: format!("create generation executable: {error}"),
            });
        }
    };
    file.write_all(payload)
        .map_err(|error| BinaryGenerationStagingError::StagingFailed {
            reason: format!("write generation executable: {error}"),
        })?;
    file.sync_all()
        .map_err(|error| BinaryGenerationStagingError::StagingFailed {
            reason: format!("flush generation executable: {error}"),
        })?;
    drop(file);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn unique_root(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        std::env::temp_dir().join(format!(
            "eliot-binary-generation-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn new_version_is_admitted_as_a_distinct_generation_and_never_touches_the_running_one() {
        // Positive path: the running generation's directory and bytes exist;
        // the new version still gets its own directory and its own bytes, and
        // the running copy is byte-identical afterwards.
        let root = unique_root("distinct");
        let running = admit_binary_generation(&root, "example-module", "1.0.0", None)
            .expect("admit running generation");
        stage_generation_executable(&running, b"running-v1").expect("stage running generation");

        let candidate = admit_binary_generation(
            &root,
            "example-module",
            "1.0.1",
            Some(&running.generation_dir),
        )
        .expect("admit candidate generation");

        assert_eq!(candidate.generation, "example-module@1.0.1");
        assert_ne!(candidate.generation, running.generation);
        assert_ne!(candidate.generation_dir, running.generation_dir);
        assert_eq!(
            candidate.supersedes_dir,
            Some(running.generation_dir.clone())
        );

        stage_generation_executable(&candidate, b"running-v2").expect("stage candidate generation");

        assert_eq!(
            std::fs::read(&candidate.executable_path).expect("read candidate"),
            b"running-v2".as_slice()
        );
        assert_eq!(
            std::fs::read(&running.executable_path).expect("read running"),
            b"running-v1".as_slice(),
            "a staged new generation must not alter the running generation's bytes"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }

    #[test]
    fn in_place_replacement_of_an_existing_generation_is_refused() {
        // Refusal path: the running generation's bytes exist, so re-admitting
        // the same version and writing to the same file must fail closed rather
        // than rewrite the file that a running process is executing.
        let root = unique_root("refuse");
        let running = admit_binary_generation(&root, "example-module", "2.0.0", None)
            .expect("admit running generation");
        stage_generation_executable(&running, b"running").expect("stage running generation");

        // Re-admitting the same version refuses with the typed
        // `VersionedDirectoryExists`: the versioned directory that holds the
        // running bytes already exists, so a new generation identity cannot be
        // admitted at that version.
        assert_eq!(
            admit_binary_generation(&root, "example-module", "2.0.0", None),
            Err(BinaryGenerationStagingError::VersionedDirectoryExists {
                path: running.generation_dir.display().to_string(),
            })
        );

        // Writing the already-admitted generation is refused as the typed
        // `GenerationAlreadyExists` rather than as a generic staging failure:
        // the destination file object exists, so opening it `create_new` would
        // replace the bytes a running process is executing. This is the refusal
        // `install_update` maps onto
        // `UpdateInstallerError::RunningBinaryWouldBeOverwritten`.
        assert_eq!(
            stage_generation_executable(&running, b"overwrite-attempt"),
            Err(BinaryGenerationStagingError::GenerationAlreadyExists {
                path: running.executable_path.display().to_string(),
            })
        );
        assert_eq!(
            std::fs::read(&running.executable_path).expect("read running"),
            b"running".as_slice(),
            "the refusal must leave the running bytes untouched"
        );
        std::fs::remove_dir_all(&root).expect("cleanup");
    }
}
