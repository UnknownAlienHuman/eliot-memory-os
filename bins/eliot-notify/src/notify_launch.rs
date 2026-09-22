//! Protected-input Notify launch artifact resolution (issue #1780, I11.6).
//!
//! Normal delivery launches the installed `eliot-notify.exe` through the
//! authorized User Broker on a Kernel-authorized grant. The grant minter
//! (Kernel automation lane) must bind the exact installed image — path plus
//! SHA-256 — sourced from protected installer inputs, never from a
//! configured path, loader location, build output, or environment. This
//! module resolves those launch inputs from protected declaration bytes:
//! parse, reader-gate validation, canonical-bytes equality, then the
//! admission-bound installed-binary verification from
//! [`installed_binary`](crate::installed_binary).
//!
//! The function takes declaration BYTES, not a path: the caller performs
//! the single protected lease read at its edge (mirroring
//! `load_fallback_material`) and injects the bytes here. Tests inject
//! fixture bytes, so this proof never touches the machine.
//!
//! The installer-owned declaration record is shared with the fallback
//! route (one installed image, one record — a second notify record would
//! be a parallel registry), but the launch paths stay distinct: this
//! resolver stages grant inputs, it never registers scheduler tasks.

use std::path::PathBuf;

use eliot_receipts::canonical_json_bytes;

use super::fallback_verification::{
    FallbackVerificationDeclaration, validate_fallback_declaration,
};
use crate::installed_binary::{
    NotifyBinaryError, NotifyDigest, notify_binding_from_declaration, resolve_notify_binary,
};

/// Verified Notify launch inputs for one grant staging: the exact installed
/// executable path plus the digest of the bytes observed at resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedNotifyLaunch {
    /// Verified installation-approved executable path.
    pub executable_path: PathBuf,
    /// Digest of the exact bytes observed at resolution.
    pub artifact_digest: NotifyDigest,
    /// Installation identity from the validated declaration record.
    pub installation_identity: String,
}

impl VerifiedNotifyLaunch {
    /// Returns the verified executable path for the staged grant.
    #[must_use]
    pub fn executable_path(&self) -> &std::path::Path {
        &self.executable_path
    }

    /// Returns the digest of the bytes observed at resolution.
    #[must_use]
    pub const fn artifact_digest(&self) -> &NotifyDigest {
        &self.artifact_digest
    }

    /// Returns the installation identity from the validated record.
    #[must_use]
    pub fn installation_identity(&self) -> &str {
        &self.installation_identity
    }
}

/// Fail-closed launch-input resolution errors. Codes only — no paths,
/// payloads, or key material are echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotifyLaunchError {
    /// The declaration bytes are undecodable, fail validation, or are not
    /// canonical JSON.
    InvalidDeclaration,
    /// The bound installed binary failed resolution.
    Binding(NotifyBinaryError),
}

impl NotifyLaunchError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidDeclaration => "NOTIFY_LAUNCH_INVALID_DECLARATION",
            Self::Binding(error) => error.code(),
        }
    }
}

impl std::fmt::Display for NotifyLaunchError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDeclaration => formatter.write_str(self.code()),
            Self::Binding(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for NotifyLaunchError {}

/// Resolves verified Notify launch inputs from protected declaration bytes.
///
/// The caller reads the exact bytes under its protected lease and injects
/// them here. Resolution parses with unknown-field rejection, enforces the
/// reader's validation gates and canonical-bytes equality, then verifies
/// the bound installed binary (is-file, non-empty, single-read digest
/// match). The returned digest is the observed digest — the same bytes the
/// grant names — so a file swapped between resolution and launch fails the
/// launch-time re-hash instead of executing unverified.
///
/// # Errors
///
/// Returns [`NotifyLaunchError::InvalidDeclaration`] when the bytes do not
/// decode, validate, or match canonical form, or
/// [`NotifyLaunchError::Binding`] when the installed binary fails
/// verification.
pub fn resolve_notify_launch_inputs(
    declaration_bytes: &[u8],
) -> Result<VerifiedNotifyLaunch, NotifyLaunchError> {
    let declaration: FallbackVerificationDeclaration = serde_json::from_slice(declaration_bytes)
        .map_err(|_| NotifyLaunchError::InvalidDeclaration)?;
    validate_fallback_declaration(&declaration)
        .map_err(|_| NotifyLaunchError::InvalidDeclaration)?;
    if canonical_json_bytes(&declaration).map_err(|_| NotifyLaunchError::InvalidDeclaration)?
        != declaration_bytes
    {
        return Err(NotifyLaunchError::InvalidDeclaration);
    }
    let binding = notify_binding_from_declaration(
        &declaration.notify_executable,
        &declaration.notify_artifact_sha256,
    )
    .map_err(NotifyLaunchError::Binding)?;
    let installed = resolve_notify_binary(&binding).map_err(NotifyLaunchError::Binding)?;
    Ok(VerifiedNotifyLaunch {
        executable_path: installed.path().to_path_buf(),
        artifact_digest: installed.digest().clone(),
        installation_identity: declaration.installation_identity.as_str().to_owned(),
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::notify_declaration::{NotifyDeclarationInputs, render_notify_fallback_declaration};
    use eliot_platform::PlatformHandle;

    fn test_public_key() -> String {
        use ed25519_dalek::SigningKey;
        SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    }

    fn fixture_image(name: &str) -> (PathBuf, Vec<u8>) {
        let bytes = b"installed-notify-launch-image-bytes".to_vec();
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, &bytes).expect("fixture writable");
        (path, bytes)
    }

    fn declaration_bytes_for(executable: &PathBuf, digest_hex: &str) -> Vec<u8> {
        let inputs = NotifyDeclarationInputs {
            installation_identity: PlatformHandle::new("installation:test").expect("identity"),
            audience: PlatformHandle::new("audience:test").expect("audience"),
            authority_epoch: 7,
            key_id: PlatformHandle::new("key:test").expect("key id"),
            public_key: test_public_key(),
            notify_executable: executable.to_string_lossy().into_owned(),
            notify_artifact_sha256: digest_hex.to_owned(),
            interactive_user_sid: "S-1-5-21-1-2-3-1001".to_owned(),
            interactive_session_id: 1,
        };
        render_notify_fallback_declaration(&inputs)
            .expect("fixture declaration renders")
            .canonical_bytes
    }

    #[test]
    fn valid_declaration_bytes_resolve_verified_launch_inputs() {
        let (path, bytes) = fixture_image("eliot-1780-notify-launch-ok.bin");
        let digest = NotifyDigest::of_bytes(&bytes);
        let declaration = declaration_bytes_for(&path, digest.as_str());
        let resolved = resolve_notify_launch_inputs(&declaration).expect("valid inputs resolve");
        assert_eq!(resolved.executable_path(), path.as_path());
        assert_eq!(resolved.artifact_digest(), &digest);
        assert_eq!(resolved.installation_identity(), "installation:test");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_undeclared_and_unverifiable_inputs_fail_closed() {
        let (path, bytes) = fixture_image("eliot-1780-notify-launch-bad.bin");
        let digest = NotifyDigest::of_bytes(&bytes);
        let mut declaration = declaration_bytes_for(&path, digest.as_str());
        assert_eq!(
            resolve_notify_launch_inputs(b"not json").map(|_| ()),
            Err(NotifyLaunchError::InvalidDeclaration)
        );
        let flip = declaration.len() / 2;
        declaration[flip] ^= 0xFF;
        assert_eq!(
            resolve_notify_launch_inputs(&declaration).map(|_| ()),
            Err(NotifyLaunchError::InvalidDeclaration)
        );
        let pretty: serde_json::Value =
            serde_json::from_slice(&declaration_bytes_for(&path, digest.as_str()))
                .expect("fixture parses");
        let non_canonical = format!("{pretty:#}");
        assert_eq!(
            resolve_notify_launch_inputs(non_canonical.as_bytes()).map(|_| ()),
            Err(NotifyLaunchError::InvalidDeclaration)
        );
        let wrong_digest = declaration_bytes_for(&path, &"ef".repeat(32));
        assert_eq!(
            resolve_notify_launch_inputs(&wrong_digest).map(|_| ()),
            Err(NotifyLaunchError::Binding(
                NotifyBinaryError::DigestMismatch
            ))
        );
        let missing = declaration_bytes_for(
            &PathBuf::from("C:\\eliot-no-such-dir\\no-such-notify.exe"),
            digest.as_str(),
        );
        assert!(matches!(
            resolve_notify_launch_inputs(&missing),
            Err(NotifyLaunchError::Binding(NotifyBinaryError::Unreadable(_)))
        ));
        assert_eq!(
            NotifyLaunchError::InvalidDeclaration.code(),
            "NOTIFY_LAUNCH_INVALID_DECLARATION"
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn production_section_uses_no_ambient_authority_source() {
        // Resolution above the test module takes only injected declaration
        // bytes and the bound filesystem path they name: it never probes
        // the loader path, build output, environment, or registry. Tokens
        // are assembled so this scan cannot match itself.
        let source = include_str!("notify_launch.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production section precedes the test module");
        for token in [
            ["current", "_exe"].concat(),
            ["CARGO_BIN", "_EXE"].concat(),
            ["std::", "env"].concat(),
            ["option_", "env"].concat(),
            ["env", "!"].concat(),
            ["CARGO_TARGET", "_DIR"].concat(),
            ["CARGO_MANIFEST", "_DIR"].concat(),
        ] {
            assert!(
                !production.contains(&token),
                "ambient authority source in production section: {token}"
            );
        }
    }
}
