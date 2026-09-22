//! Installed/registered Notify binary binding (issue #1780, I11.5/I11.7).
//!
//! The `eliot-notify.exe` one-shot adapter is launched through the authorized
//! User Broker on the normal route (I11.6) and through the separately
//! registered Task Scheduler fallback without Kernel/User Broker. Either
//! launcher must name an installed binary, never a build-output path or an
//! ambient caller input: this module resolves that installed binary — the
//! exact `eliot-notify.exe` the admitted launch intent names — from a
//! registration-bound binding and verifies it before the caller stages any
//! launch.
//!
//! Trust model: the [`NotifyBinaryBinding`] is assembled only from the
//! installer-owned registration record — the
//! `FallbackVerificationDeclaration` fields `notify_executable` /
//! `notify_artifact_sha256` (protected `ProgramData`, installer-pinned) that
//! feed [`WatchdogTaskRegistration`](eliot_platform_windows::WatchdogTaskRegistration)
//! on the fallback route, or the equivalent installer-pinned User Broker
//! launch record on the normal route. It is never assembled from the OS
//! loader path, build-output directories, environment variables, the WASM
//! component registry, or any other ambient caller input. The approved
//! installation registry carries no notify fields by design — the adapter
//! is a per-user one-shot surface, not an installed daemon role — so no
//! binding is sourced from it and none is invented here. Resolution binds the digest to the bytes actually read
//! (TOCTOU closure, the same single-read discipline as `artifact_preflight`);
//! Windows launch-time re-verification under a deny-write lease with reparse
//! refusal stays with `validate_pinned_artifact`, which re-hashes the file
//! before any scheduler touch.
//!
//! Failure discipline follows `artifact_preflight`: stable codes only, no
//! paths or payloads echoed.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Lowercase SHA-256 identity bound to one installed Notify image.
///
/// Shape discipline matches the installer declaration (`valid_sha256`):
/// exactly 64 lowercase hexadecimal characters. Malformed digests fail at
/// construction, never at resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyDigest(String);

impl NotifyDigest {
    /// Parses an exact lowercase SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns [`NotifyBinaryError::InvalidDigest`] when the value is not
    /// exactly 64 lowercase hexadecimal characters.
    pub fn new(value: impl Into<String>) -> Result<Self, NotifyBinaryError> {
        let value = value.into();
        if value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(NotifyBinaryError::InvalidDigest);
        }
        Ok(Self(value))
    }

    /// Computes the digest of observed bytes.
    #[must_use]
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Returns lowercase hexadecimal bytes.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Registration-bound installed-binary identity for one Notify launch.
///
/// Mirrors the installer-owned `notify_executable` / `notify_artifact_sha256`
/// registration fields. Constructed only from that record, never from ambient
/// input. The digest shape is enforced by [`NotifyDigest`]; the path must be
/// non-empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyBinaryBinding {
    /// Installation-approved absolute path of the `eliot-notify` image.
    executable_path: PathBuf,
    /// Expected SHA-256 of the installed image bytes.
    artifact_digest: NotifyDigest,
}

impl NotifyBinaryBinding {
    /// Binds one installation-approved path to its registered digest.
    ///
    /// # Errors
    ///
    /// Returns [`NotifyBinaryError::EmptyPath`] when the path is empty.
    pub fn new(
        executable_path: PathBuf,
        artifact_digest: NotifyDigest,
    ) -> Result<Self, NotifyBinaryError> {
        if executable_path.as_os_str().is_empty() {
            return Err(NotifyBinaryError::EmptyPath);
        }
        Ok(Self {
            executable_path,
            artifact_digest,
        })
    }

    /// Returns the bound installation-approved executable path.
    #[must_use]
    pub fn executable_path(&self) -> &Path {
        &self.executable_path
    }

    /// Returns the registered digest the installed bytes must match.
    #[must_use]
    pub const fn artifact_digest(&self) -> &NotifyDigest {
        &self.artifact_digest
    }
}

/// A verified installed Notify binary: the bound path whose observed bytes
/// match the registered digest.
///
/// The caller stages the launch with `path()` as the executable and
/// `digest()` as the intent digest. Launch-time re-verification under a
/// deny-write lease stays with the launcher; this resolution proves the
/// registration binding, it does not replace that launch check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledNotifyBinary {
    /// Verified installation-approved executable path.
    path: PathBuf,
    /// Digest of the exact bytes observed at resolution.
    digest: NotifyDigest,
}

impl InstalledNotifyBinary {
    /// Returns the verified executable path for the staged launch intent.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the digest of the bytes observed at resolution.
    #[must_use]
    pub const fn digest(&self) -> &NotifyDigest {
        &self.digest
    }
}

/// Fail-closed Notify binary resolution errors. Codes only — no paths or
/// payloads are echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NotifyBinaryError {
    /// The bound executable path is empty.
    EmptyPath,
    /// The registered digest is not exact lowercase SHA-256.
    InvalidDigest,
    /// The installed image file is empty.
    Empty,
    /// The bound path is not a regular file.
    NotAFile,
    /// The file could not be read (kind string only, no path/secret).
    Unreadable(String),
    /// The observed bytes do not match the registered digest.
    DigestMismatch,
}

impl NotifyBinaryError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyPath => "NOTIFY_BINARY_EMPTY_PATH",
            Self::InvalidDigest => "NOTIFY_BINARY_INVALID_DIGEST",
            Self::Empty => "NOTIFY_BINARY_EMPTY",
            Self::NotAFile => "NOTIFY_BINARY_NOT_A_FILE",
            Self::Unreadable(_) => "NOTIFY_BINARY_UNREADABLE",
            Self::DigestMismatch => "NOTIFY_BINARY_DIGEST_MISMATCH",
        }
    }
}

impl std::fmt::Display for NotifyBinaryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(kind) => {
                write!(formatter, "NOTIFY_BINARY_UNREADABLE:{kind}")
            }
            other => formatter.write_str(other.code()),
        }
    }
}

impl std::error::Error for NotifyBinaryError {}

/// Resolves one registration-bound installed Notify binary against the
/// filesystem.
///
/// Verifies the bound path names a regular file, reads its exact bytes once,
/// and requires the SHA-256 of those bytes to equal the registered digest.
/// The returned [`InstalledNotifyBinary`] carries the observed digest — the
/// same bytes the caller names in the staged launch intent — so a file
/// swapped between resolution and launch fails the launch-time re-hash
/// instead of executing unverified.
///
/// # Errors
///
/// Returns [`NotifyBinaryError`] when the path is unreadable, is not a file,
/// is empty, or its bytes mismatch the registered digest.
pub fn resolve_notify_binary(
    binding: &NotifyBinaryBinding,
) -> Result<InstalledNotifyBinary, NotifyBinaryError> {
    let metadata = std::fs::metadata(binding.executable_path())
        .map_err(|error| NotifyBinaryError::Unreadable(error.kind().to_string()))?;
    if !metadata.is_file() {
        return Err(NotifyBinaryError::NotAFile);
    }
    if metadata.len() == 0 {
        return Err(NotifyBinaryError::Empty);
    }
    let bytes = std::fs::read(binding.executable_path())
        .map_err(|error| NotifyBinaryError::Unreadable(error.kind().to_string()))?;
    if bytes.is_empty() {
        return Err(NotifyBinaryError::Empty);
    }
    let observed = NotifyDigest::of_bytes(&bytes);
    if observed.as_str() != binding.artifact_digest().as_str() {
        return Err(NotifyBinaryError::DigestMismatch);
    }
    Ok(InstalledNotifyBinary {
        path: binding.executable_path().to_path_buf(),
        digest: observed,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture_bytes() -> Vec<u8> {
        b"installed-notify-image-bytes".to_vec()
    }

    fn fixture_digest(bytes: &[u8]) -> NotifyDigest {
        NotifyDigest::of_bytes(bytes)
    }

    fn write_fixture(name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, bytes).expect("fixture writable");
        path
    }

    fn binding_for(path: PathBuf, bytes: &[u8]) -> NotifyBinaryBinding {
        NotifyBinaryBinding::new(path, fixture_digest(bytes)).expect("binding")
    }

    #[test]
    fn valid_notify_binary_resolves_with_observed_digest() {
        let bytes = fixture_bytes();
        let path = write_fixture("eliot-1780-notify-binary-ok.bin", &bytes);
        let binding = binding_for(path.clone(), &bytes);
        let resolved = resolve_notify_binary(&binding).expect("valid binary resolves");
        assert_eq!(resolved.path(), path.as_path());
        assert_eq!(
            resolved.digest().as_str(),
            binding.artifact_digest().as_str()
        );
        assert_eq!(resolved.digest(), &NotifyDigest::of_bytes(&bytes));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_bytes_and_bad_bindings_fail_closed() {
        let bytes = fixture_bytes();
        let path = write_fixture("eliot-1780-notify-binary-tampered.bin", &bytes);
        let tampered = binding_for(path.clone(), b"other-bytes");
        assert_eq!(
            resolve_notify_binary(&tampered).map(|_| ()),
            Err(NotifyBinaryError::DigestMismatch)
        );
        assert_eq!(
            NotifyBinaryError::DigestMismatch.code(),
            "NOTIFY_BINARY_DIGEST_MISMATCH"
        );
        assert_eq!(
            NotifyBinaryBinding::new(PathBuf::new(), fixture_digest(&bytes)).map(|_| ()),
            Err(NotifyBinaryError::EmptyPath)
        );
        assert_eq!(
            NotifyDigest::new("NOT-HEX").map(|_| ()),
            Err(NotifyBinaryError::InvalidDigest)
        );
        assert_eq!(
            NotifyDigest::new("A".repeat(64)).map(|_| ()),
            Err(NotifyBinaryError::InvalidDigest)
        );
        assert_eq!(
            resolve_notify_binary(&binding_for(
                PathBuf::from("C:\\eliot-no-such-dir\\no-such-binary.exe"),
                &bytes
            ))
            .map(|_| ())
            .map_err(|error| error.code()),
            Err("NOTIFY_BINARY_UNREADABLE")
        );
        assert_eq!(
            resolve_notify_binary(&binding_for(std::env::temp_dir(), &bytes)).map(|_| ()),
            Err(NotifyBinaryError::NotAFile)
        );
        let empty_path = write_fixture("eliot-1780-notify-binary-empty.bin", &[]);
        assert_eq!(
            resolve_notify_binary(&binding_for(empty_path.clone(), &[])).map(|_| ()),
            Err(NotifyBinaryError::Empty)
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&empty_path);
    }

    #[test]
    fn production_section_uses_no_ambient_authority_source() {
        // The resolution above the test module must never locate the binary
        // through the loader path, build output, environment, the WASM
        // component registry, or the installation registry: the binding is
        // the only authority input. Tokens are assembled so this scan cannot
        // match itself.
        let source = include_str!("installed_binary.rs");
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
            ["wasm", "_host"].concat(),
            ["Wasm", "Host"].concat(),
            ["Candidate", "Manifest"].concat(),
            ["RuntimeLaunch", "Descriptor"].concat(),
        ] {
            assert!(
                !production.contains(&token),
                "ambient authority source in production section: {token}"
            );
        }
    }
}
