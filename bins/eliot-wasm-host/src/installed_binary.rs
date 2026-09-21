//! Installed WASM-host child binary resolution (issue #1955, I1.6/I14.19).
//!
//! The P03 parent spawns the reaped child as an installed binary, never a
//! build-output path: I1.6 requires versioned binaries to live under the
//! installation and never be replaced in place while running. This module
//! resolves that installed binary — the exact `eliot-wasm-host.exe` the
//! Kernel-admitted [`ProcessRequest`](eliot_process::ProcessRequest) names —
//! from an admission-bound binding and verifies it before the caller stages
//! any launch.
//!
//! Trust model: the [`WasmHostBinaryBinding`] arrives only through B1's
//! authenticated Kernel grant channel (the same channel that delivers the
//! admitted `RuntimePorts`); it is never assembled from the OS loader path,
//! build-output directories, environment variables, or any other ambient
//! caller input. The binding mirrors the pending installation-registry
//! fields `wasm_host_executable_path` / `wasm_host_artifact_digest` on the
//! Host-owned `RuntimeLaunchDescriptor` (Ohm/Host lane — absent as of this
//! write, so no production caller constructs a binding yet). Resolution
//! binds the digest to the bytes actually read (TOCTOU closure, the same
//! single-read discipline as `artifact_preflight`); launch-time
//! re-verification under the executor's deny-write launch lease stays with
//! the P03 executor, which re-hashes the file before any start.
//!
//! Failure discipline follows `artifact_preflight`: stable codes only, no
//! paths or payloads echoed.

use std::path::{Path, PathBuf};

use eliot_wasm_runtime::Sha256Digest;

/// Admission-bound installed-binary identity for one WASM-host generation.
///
/// Mirrors the pending `wasm_host_executable_path` /
/// `wasm_host_artifact_digest` registry fields. Constructed only from the
/// Kernel-issued admission grant (B1 lane), never from ambient input. The
/// digest shape is enforced by [`Sha256Digest`]; the path must be non-empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WasmHostBinaryBinding {
    /// Installation-approved absolute path of the `eliot-wasm-host` image.
    executable_path: PathBuf,
    /// Expected SHA-256 of the installed image bytes.
    artifact_digest: Sha256Digest,
}

impl WasmHostBinaryBinding {
    /// Binds one installation-approved path to its admitted digest.
    ///
    /// # Errors
    ///
    /// Returns [`InstalledBinaryError::EmptyPath`] when the path is empty.
    pub fn new(
        executable_path: PathBuf,
        artifact_digest: Sha256Digest,
    ) -> Result<Self, InstalledBinaryError> {
        if executable_path.as_os_str().is_empty() {
            return Err(InstalledBinaryError::EmptyPath);
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

    /// Returns the admitted digest the installed bytes must match.
    #[must_use]
    pub const fn artifact_digest(&self) -> &Sha256Digest {
        &self.artifact_digest
    }
}

/// A verified installed binary: the bound path whose observed bytes match
/// the admitted digest.
///
/// The caller stages the launch with `path()` as the executable and
/// `digest()` as the intent digest. The P03 executor re-hashes the file
/// under its deny-write lease before any start; this resolution proves the
/// registry binding, it does not replace that launch check.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstalledBinary {
    /// Verified installation-approved executable path.
    path: PathBuf,
    /// Digest of the exact bytes observed at resolution.
    digest: Sha256Digest,
}

impl InstalledBinary {
    /// Returns the verified executable path for the staged launch intent.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the digest of the bytes observed at resolution.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }
}

/// Fail-closed installed-binary resolution errors. Codes only — no paths
/// or payloads are echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum InstalledBinaryError {
    /// The bound executable path is empty.
    EmptyPath,
    /// The installed image file is empty.
    Empty,
    /// The bound path is not a regular file.
    NotAFile,
    /// The file could not be read (kind string only, no path/secret).
    Unreadable(String),
    /// The observed bytes do not match the admitted digest.
    DigestMismatch,
}

impl InstalledBinaryError {
    /// Stable code for this rejection.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::EmptyPath => "INSTALLED_BINARY_EMPTY_PATH",
            Self::Empty => "INSTALLED_BINARY_EMPTY",
            Self::NotAFile => "INSTALLED_BINARY_NOT_A_FILE",
            Self::Unreadable(_) => "INSTALLED_BINARY_UNREADABLE",
            Self::DigestMismatch => "INSTALLED_BINARY_DIGEST_MISMATCH",
        }
    }
}

impl std::fmt::Display for InstalledBinaryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(kind) => {
                write!(formatter, "INSTALLED_BINARY_UNREADABLE:{kind}")
            }
            other => formatter.write_str(other.code()),
        }
    }
}

impl std::error::Error for InstalledBinaryError {}

/// Resolves one admission-bound installed binary against the filesystem.
///
/// Verifies the bound path names a regular file, reads its exact bytes
/// once, and requires the SHA-256 of those bytes to equal the admitted
/// digest. The returned [`InstalledBinary`] carries the observed digest —
/// the same bytes the caller names in the staged launch intent — so a file
/// swapped between resolution and launch fails the executor's launch-time
/// re-hash instead of executing unverified.
///
/// # Errors
///
/// Returns [`InstalledBinaryError`] when the path is unreadable, is not a
/// file, is empty, or its bytes mismatch the admitted digest.
pub fn resolve_installed_binary(
    binding: &WasmHostBinaryBinding,
) -> Result<InstalledBinary, InstalledBinaryError> {
    let metadata = std::fs::metadata(binding.executable_path())
        .map_err(|error| InstalledBinaryError::Unreadable(error.kind().to_string()))?;
    if !metadata.is_file() {
        return Err(InstalledBinaryError::NotAFile);
    }
    if metadata.len() == 0 {
        return Err(InstalledBinaryError::Empty);
    }
    let bytes = std::fs::read(binding.executable_path())
        .map_err(|error| InstalledBinaryError::Unreadable(error.kind().to_string()))?;
    if bytes.is_empty() {
        return Err(InstalledBinaryError::Empty);
    }
    let observed = Sha256Digest::of_bytes(&bytes);
    if observed.as_str() != binding.artifact_digest().as_str() {
        return Err(InstalledBinaryError::DigestMismatch);
    }
    Ok(InstalledBinary {
        path: binding.executable_path().to_path_buf(),
        digest: observed,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fixture_bytes() -> Vec<u8> {
        b"installed-wasm-host-image-bytes".to_vec()
    }

    fn write_fixture(name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, bytes).expect("fixture writable");
        path
    }

    fn binding_for(path: PathBuf, bytes: &[u8]) -> WasmHostBinaryBinding {
        WasmHostBinaryBinding::new(path, Sha256Digest::of_bytes(bytes)).expect("binding")
    }

    #[test]
    fn valid_installed_binary_resolves_with_observed_digest() {
        let bytes = fixture_bytes();
        let path = write_fixture("eliot-1955-installed-binary-ok.bin", &bytes);
        let binding = binding_for(path.clone(), &bytes);
        let resolved = resolve_installed_binary(&binding).expect("valid binary resolves");
        assert_eq!(resolved.path(), path.as_path());
        assert_eq!(
            resolved.digest().as_str(),
            binding.artifact_digest().as_str()
        );
        assert_eq!(resolved.digest(), &Sha256Digest::of_bytes(&bytes));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_bytes_and_bad_bindings_fail_closed() {
        let bytes = fixture_bytes();
        let path = write_fixture("eliot-1955-installed-binary-tampered.bin", &bytes);
        let tampered = binding_for(path.clone(), b"other-bytes");
        assert_eq!(
            resolve_installed_binary(&tampered).map(|_| ()),
            Err(InstalledBinaryError::DigestMismatch)
        );
        assert_eq!(
            InstalledBinaryError::DigestMismatch.code(),
            "INSTALLED_BINARY_DIGEST_MISMATCH"
        );
        assert_eq!(
            WasmHostBinaryBinding::new(PathBuf::new(), Sha256Digest::of_bytes(&bytes)).map(|_| ()),
            Err(InstalledBinaryError::EmptyPath)
        );
        assert_eq!(
            resolve_installed_binary(&binding_for(
                PathBuf::from("C:\\eliot-no-such-dir\\no-such-binary.exe"),
                &bytes
            ))
            .map(|_| ())
            .map_err(|error| error.code()),
            Err("INSTALLED_BINARY_UNREADABLE")
        );
        assert_eq!(
            resolve_installed_binary(&binding_for(std::env::temp_dir(), &bytes)).map(|_| ()),
            Err(InstalledBinaryError::NotAFile)
        );
        let empty_path = write_fixture("eliot-1955-installed-binary-empty.bin", &[]);
        assert_eq!(
            resolve_installed_binary(&binding_for(empty_path.clone(), &[])).map(|_| ()),
            Err(InstalledBinaryError::Empty)
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&empty_path);
    }

    #[test]
    fn production_section_uses_no_ambient_authority_source() {
        // The resolution above the test module must never locate the binary
        // through the loader path, build output, or environment: the binding
        // is the only authority input. Tokens are assembled so this scan
        // cannot match itself.
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
        ] {
            assert!(
                !production.contains(&token),
                "ambient authority source in production section: {token}"
            );
        }
    }
}
