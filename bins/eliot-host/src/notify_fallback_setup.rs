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

/// Explicit per-user setup inputs. Every value is caller-supplied; nothing
/// is probed from the loader path, environment, current directory, or build
/// output. Key material arrives as the public half from the installer key
/// ceremony — the private signing key never enters this module.
pub struct NotifyFallbackSetupInputs {
    /// Installer-owned declaration fields (identity, audience, epoch, key
    /// reference, notify path/digest, interactive SID/session).
    pub declaration: NotifyDeclarationInputs,
    /// Explicit installation supervision/path profile.
    pub profile: InstallationProfile,
    /// Retained portable-dev root lease. Required for `PortableDev`;
    /// `None` for service/user profiles.
    pub portable_root: Option<UserOwnedRootLease>,
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
/// Renders first (pure — malformed inputs fail before any filesystem
/// effect), then publishes through the existing Phase-B file publisher
/// (create-new/atomic, idempotent replay on exact bytes, fail-closed on
/// unexpected existing bytes), then verifies readback under lease with
/// digest equality.
///
/// # Errors
///
/// Returns [`HostError`] when inputs are invalid, the protected path cannot
/// be resolved, publication or readback fails, or the platform is not
/// Windows.
pub fn publish_notify_fallback_declaration(
    declaration: &NotifyDeclarationInputs,
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<PublishedNotifyDeclaration, HostError> {
    let rendered = render_notify_fallback_declaration(declaration)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    publish_rendered_declaration(&rendered, profile, portable_root)
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
    let declaration = publish_notify_fallback_declaration(
        &inputs.declaration,
        inputs.profile,
        inputs.portable_root.as_ref(),
    )?;
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

    fn valid_declaration() -> NotifyDeclarationInputs {
        NotifyDeclarationInputs {
            installation_identity: PlatformHandle::new("installation:test").expect("identity"),
            audience: PlatformHandle::new("audience:test").expect("audience"),
            authority_epoch: 7,
            key_id: PlatformHandle::new("key:test").expect("key id"),
            public_key: valid_test_public_key(),
            notify_executable: "C:\\Eliot\\eliot-notify.exe".to_owned(),
            notify_artifact_sha256: "cd".repeat(32),
            interactive_user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
            interactive_session_id: 1,
        }
    }

    fn valid_test_public_key() -> String {
        // Lowercase hex that passes the shape gate; the negative tests below
        // fail on earlier fields, so curve validity is never reached here.
        // Valid-key rendering is proven in eliot-notify's own suite.
        "ab".repeat(32)
    }

    #[test]
    fn invalid_declaration_inputs_fail_before_filesystem_effect() {
        let mut inputs = valid_declaration();
        inputs.notify_artifact_sha256 = "NOT-HEX".to_owned();
        let setup = NotifyFallbackSetupInputs {
            declaration: inputs,
            profile: InstallationProfile::PortableDev,
            portable_root: None,
        };
        let error = setup_notify_fallback_per_user(&setup).expect_err("bad digest fails");
        assert!(
            matches!(error, HostError::Platform(_)),
            "render rejection surfaces without filesystem effect"
        );
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
