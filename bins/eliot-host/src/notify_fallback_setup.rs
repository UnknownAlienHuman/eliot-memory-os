//! Host Phase-B per-user Notify fallback setup (issue #1780, I11.6).
//!
//! Consumes
//! [`render_notify_fallback_declaration`](eliot_notify::render_notify_fallback_declaration):
//! publishes the canonical declaration to protected `ProgramData` through
//! the existing Phase-B file publisher, verifies readback under lease, then
//! registers the signed Task Scheduler fallback through the existing notify
//! route. This is the per-user setup consumer the installer invokes in the
//! interactive session; normal launch stays User-Broker owned (I11.6) and
//! this module spawns no process, assembles no daemon role, and mints no
//! authority — every value arrives explicitly in
//! [`NotifyFallbackSetupInputs`].
//!
//! Registration enforces the live caller identity inside the notify route:
//! setup must run in the interactive session matching the declaration, and
//! re-running with identical inputs replays by exact readback instead of
//! republishing. A changed declaration (new epoch/key/digest) against an
//! existing file fails closed rather than silently overwriting installer
//! material.

use std::path::{Path, PathBuf};

use eliot_installation::InstallationProfile;
use eliot_notify::{
    NotifyDeclarationInputs, RenderedNotifyDeclaration, render_notify_fallback_declaration,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{ProtectedPathLease, UserOwnedRootLease, protected_program_data_path};
use sha2::{Digest, Sha256};

use crate::HostError;

/// Explicit per-user setup inputs. Every value is caller-supplied except
/// the image digest and the interactive identity, which are always
/// observed, never configured: the digest is hashed from the installed
/// image bytes named below, and the SID/session come from the live process
/// token. Key material arrives as the public half from the installer key
/// ceremony — the private signing key never enters this module. Nothing is
/// probed from the loader path, environment, current directory, or build
/// output.
pub struct NotifyFallbackSetupInputs {
    /// Stable installation identity.
    pub installation_identity: PlatformHandle,
    /// Declared fallback audience.
    pub audience: PlatformHandle,
    /// Non-zero authority epoch.
    pub authority_epoch: u64,
    /// Watchdog signing key identifier.
    pub key_id: PlatformHandle,
    /// Lowercase hex Watchdog verifying key (public half only).
    pub public_key: String,
    /// Absolute installed `eliot-notify.exe` path. The image digest is
    /// hashed from these exact bytes; no caller-supplied digest is
    /// accepted.
    pub notify_executable: PathBuf,
    /// Explicit installation supervision/path profile.
    pub profile: InstallationProfile,
    /// Retained portable-dev root lease. Required for `PortableDev`;
    /// `None` for service/user profiles.
    pub portable_root: Option<UserOwnedRootLease>,
}

/// Observed installed image: verified path plus the digest hashed from its
/// exact bytes at setup time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedNotifySource {
    /// Verified absolute installed path.
    pub executable_path: PathBuf,
    /// SHA-256 of the exact bytes read (lowercase hex).
    pub artifact_digest: String,
}

/// Bound for one installed image read during setup (mirrors the pinned
/// artifact check; launch-time re-verification stays with the launcher).
const NOTIFY_SOURCE_BYTES_LIMIT: u64 = 256 * 1024 * 1024;

/// Verifies the installer-named image and hashes its exact bytes.
///
/// Fails closed on relative paths, wrong filenames, non-files, empty or
/// oversized images, and unreadable bytes. The returned digest always
/// describes the bytes read here — a caller cannot substitute a digest for
/// different bytes.
///
/// # Errors
///
/// Returns [`HostError::Platform`] when the path or bytes are invalid.
pub fn observe_installed_notify_source(
    executable: &Path,
) -> Result<ObservedNotifySource, HostError> {
    if !executable.is_absolute() {
        return Err(HostError::Platform(
            "notify executable path must be absolute".to_owned(),
        ));
    }
    if executable.file_name().and_then(|name| name.to_str())
        != Some(eliot_notify::NOTIFY_IMAGE_FILE_NAME)
    {
        return Err(HostError::Platform(
            "notify executable must name the canonical installed notify image".to_owned(),
        ));
    }
    let metadata = std::fs::metadata(executable)
        .map_err(|error| HostError::Platform(format!("open notify executable: {error}")))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > NOTIFY_SOURCE_BYTES_LIMIT {
        return Err(HostError::Platform(
            "notify executable is not a bounded regular file".to_owned(),
        ));
    }
    let bytes = std::fs::read(executable)
        .map_err(|error| HostError::Platform(format!("read notify executable: {error}")))?;
    if bytes.is_empty() {
        return Err(HostError::Platform("notify executable is empty".to_owned()));
    }
    Ok(ObservedNotifySource {
        executable_path: executable.to_path_buf(),
        artifact_digest: format!("{:x}", Sha256::digest(&bytes)),
    })
}

/// Published declaration binding: destination plus pinned digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedNotifyDeclaration {
    /// Absolute protected declaration path.
    pub declaration_path: PathBuf,
    /// SHA-256 of the published canonical bytes.
    pub declaration_digest: PlatformHandle,
}

/// Signed fallback registration observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyFallbackRegistration {
    /// Scheduler task name.
    pub task_name: String,
    /// Interactive user SID the task is bound to.
    pub sid: String,
    /// Interactive session id the task is bound to.
    pub session_id: u32,
    /// Registered notify artifact digest.
    pub notify_artifact_sha256: String,
    /// Verifier digest pinned at registration.
    pub verifier_sha256: String,
    /// Scheduler XML digest observed at registration.
    pub task_xml_sha256: String,
}

/// Complete per-user setup outcome: published declaration plus registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyFallbackSetup {
    /// Published declaration binding.
    pub declaration: PublishedNotifyDeclaration,
    /// Scheduler registration observation.
    pub registration: NotifyFallbackRegistration,
}

/// Publishes one canonical fallback declaration to protected storage.
///
/// Observes the installed image (path verified, digest hashed from the
/// exact bytes — never caller-supplied), binds the live interactive
/// identity from the current process token, renders, then publishes
/// through the existing Phase-B file publisher (create-new/atomic,
/// idempotent replay on exact bytes, fail-closed on unexpected existing
/// bytes) and verifies readback under lease with digest equality.
///
/// # Errors
///
/// Returns [`HostError`] when inputs are invalid, the image cannot be
/// observed, the protected path cannot be resolved, publication or
/// readback fails, or the platform is not Windows.
pub fn publish_notify_fallback_declaration(
    inputs: &NotifyFallbackSetupInputs,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<PublishedNotifyDeclaration, HostError> {
    let source = observe_installed_notify_source(&inputs.notify_executable)?;
    let identity = eliot_platform_windows::current_process_named_pipe_expectation()
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let declaration = NotifyDeclarationInputs {
        installation_identity: inputs.installation_identity.clone(),
        audience: inputs.audience.clone(),
        authority_epoch: inputs.authority_epoch,
        key_id: inputs.key_id.clone(),
        public_key: inputs.public_key.clone(),
        notify_executable: source.executable_path.to_string_lossy().into_owned(),
        notify_artifact_sha256: source.artifact_digest,
        interactive_user_sid: identity.expected_sid().to_owned(),
        interactive_session_id: identity.expected_session_id(),
    };
    let rendered = render_notify_fallback_declaration(&declaration)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    publish_rendered_declaration(&rendered, inputs.profile, portable_root)
}

/// Registers the signed Task Scheduler fallback against the published
/// declaration. Must run in the interactive session matching the
/// declaration; the notify route enforces the live caller identity and
/// re-verifies the pinned artifact before touching the scheduler.
///
/// # Errors
///
/// Returns [`HostError`] when the declaration is absent/invalid, the caller
/// identity mismatches, or scheduler registration/readback fails.
pub fn register_notify_fallback() -> Result<NotifyFallbackRegistration, HostError> {
    let receipt = eliot_notify::register_watchdog_fallback_task()
        .map_err(|error| HostError::Platform(error.to_string()))?;
    Ok(NotifyFallbackRegistration {
        task_name: receipt.task_name().to_owned(),
        sid: receipt.sid().to_owned(),
        session_id: receipt.session_id(),
        notify_artifact_sha256: receipt.notify_artifact_sha256().to_owned(),
        verifier_sha256: receipt.verifier_sha256().to_owned(),
        task_xml_sha256: receipt.task_xml_sha256().to_owned(),
    })
}

/// Composed per-user setup: publish the declaration, then register the
/// signed fallback task. Normal User-Broker launch is unaffected.
///
/// # Errors
///
/// Returns [`HostError`] from either stage; a publication already replayed
/// by exact readback proceeds to registration.
pub fn setup_notify_fallback_per_user(
    inputs: &NotifyFallbackSetupInputs,
) -> Result<NotifyFallbackSetup, HostError> {
    let declaration = publish_notify_fallback_declaration(inputs, inputs.portable_root.as_ref())?;
    let registration = register_notify_fallback()?;
    Ok(NotifyFallbackSetup {
        declaration,
        registration,
    })
}

#[cfg(windows)]
fn publish_rendered_declaration(
    rendered: &RenderedNotifyDeclaration,
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<PublishedNotifyDeclaration, HostError> {
    use crate::phase_b_materialize_file;

    let declaration_path = protected_program_data_path(rendered.relative_path)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let expected = PlatformHandle::new(rendered.declaration_digest.clone())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let (digest, _identity) = phase_b_materialize_file(
        profile,
        portable_root,
        Path::new(&declaration_path),
        &rendered.canonical_bytes,
        &[&expected],
        "Notify fallback declaration",
    )?;
    verify_declaration_readback(Path::new(&declaration_path), digest.as_str())?;
    Ok(PublishedNotifyDeclaration {
        declaration_path,
        declaration_digest: digest,
    })
}

#[cfg(not(windows))]
fn publish_rendered_declaration(
    _rendered: &RenderedNotifyDeclaration,
    _profile: InstallationProfile,
    _portable_root: Option<&UserOwnedRootLease>,
) -> Result<PublishedNotifyDeclaration, HostError> {
    Err(HostError::Platform(
        "notify fallback setup requires Windows".to_owned(),
    ))
}

#[cfg(windows)]
fn verify_declaration_readback(path: &Path, expected_digest: &str) -> Result<(), HostError> {
    let lease = ProtectedPathLease::open_existing_absolute(path)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    lease
        .verify_stable_identity()
        .and_then(|()| lease.verify_path_identity())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let bytes = lease
        .read_bounded(64 * 1024)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected_digest {
        return Err(HostError::RecoveryRequired(
            "notify fallback declaration readback digest differs from publication".to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn valid_setup_inputs(notify_executable: PathBuf) -> NotifyFallbackSetupInputs {
        NotifyFallbackSetupInputs {
            installation_identity: PlatformHandle::new("installation:test").expect("identity"),
            audience: PlatformHandle::new("audience:test").expect("audience"),
            authority_epoch: 7,
            key_id: PlatformHandle::new("key:test").expect("key id"),
            public_key: "ab".repeat(32),
            notify_executable,
            profile: InstallationProfile::PortableDev,
            portable_root: None,
        }
    }

    fn write_temp_image(name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, bytes).expect("fixture writable");
        path
    }

    #[test]
    fn observed_source_binds_path_to_hashed_bytes() {
        let bytes = b"installed-notify-setup-image-bytes".to_vec();
        let path = write_temp_image("eliot-1780-notify-setup-ok.bin", &bytes);
        // The fixture filename is not the canonical image name: observation
        // must reject it before hashing.
        assert!(observe_installed_notify_source(&path).is_err());
        let canonical_dir = std::env::temp_dir().join("eliot-1780-setup-canonical");
        let _ = std::fs::create_dir_all(&canonical_dir);
        let canonical = canonical_dir.join(eliot_notify::NOTIFY_IMAGE_FILE_NAME);
        std::fs::write(&canonical, &bytes).expect("fixture writable");
        let observed =
            observe_installed_notify_source(&canonical).expect("canonical image observes");
        assert_eq!(observed.executable_path, canonical);
        assert_eq!(
            observed.artifact_digest,
            format!("{:x}", Sha256::digest(&bytes))
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&canonical);
    }

    #[test]
    fn invalid_setup_inputs_fail_before_publication() {
        let bytes = b"installed-notify-setup-image-bytes".to_vec();
        let dir = std::env::temp_dir().join("eliot-1780-setup-invalid");
        let _ = std::fs::create_dir_all(&dir);
        let exe = dir.join(eliot_notify::NOTIFY_IMAGE_FILE_NAME);
        std::fs::write(&exe, &bytes).expect("fixture writable");
        // Bad authority epoch fails at render, after source observation but
        // before any protected publication.
        let mut setup = valid_setup_inputs(exe.clone());
        setup.authority_epoch = 0;
        let error = setup_notify_fallback_per_user(&setup).expect_err("bad epoch fails");
        assert!(
            matches!(error, HostError::Platform(_)),
            "render rejection surfaces without publication"
        );
        // Missing image fails at observation, before render.
        let mut missing = valid_setup_inputs(dir.join("eliot-notify.exe"));
        missing.authority_epoch = 7;
        assert!(setup_notify_fallback_per_user(&missing).is_err());
        let _ = std::fs::remove_file(&exe);
    }

    #[test]
    fn registration_without_declaration_fails_closed() {
        // Precondition: this test must never create scheduler state. If an
        // installer already published a declaration here, fail loudly instead
        // of registering against it.
        if let Ok(path) = protected_program_data_path("Eliot/notify/watchdog-verification.json") {
            assert!(
                !std::path::Path::new(&path).exists(),
                "test requires no published declaration"
            );
        }
        // No declaration is published by this test: the registration route
        // must reject before touching Task Scheduler.
        let outcome = register_notify_fallback();
        assert!(
            outcome.is_err(),
            "fallback registration without a declaration must fail"
        );
    }
}
