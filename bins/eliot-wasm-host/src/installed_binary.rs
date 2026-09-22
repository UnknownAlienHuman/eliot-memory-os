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
//! caller input. The binding mirrors the installation-registry fields
//! `wasm_host_executable_path` / `wasm_host_artifact_digest` on the
//! Host-owned `RuntimeLaunchDescriptor` (Ohm/Host lane): the single
//! production constructor is [`binding_from_launch_descriptor`], which
//! consumes the descriptor read-only through
//! `RuntimeLaunchDescriptor::wasm_host_artifact_binding` (B2/installer lane
//! — the descriptor self-validates before the pair is released). Resolution
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

/// Builds the admission-bound binding from installation-approved records.
///
/// Pure shape check over the exact `(path, digest)` pair the live
/// [`RuntimeLaunchDescriptor`](eliot_installation::RuntimeLaunchDescriptor)
/// releases through `wasm_host_artifact_binding()` (B2/installer lane,
/// read-only): the descriptor self-validates before the pair is released,
/// and this constructor re-checks the digest shape, so a non-conforming
/// record can never become a launch binding.
///
/// # Errors
///
/// Returns [`InstalledBinaryError::EmptyPath`] when the path text is empty,
/// [`InstalledBinaryError::DescriptorInvalid`] when the digest text is not
/// an exact lowercase SHA-256.
pub fn binding_from_installation_records(
    executable_path_text: &str,
    artifact_digest_hex: &str,
) -> Result<WasmHostBinaryBinding, InstalledBinaryError> {
    if executable_path_text.is_empty() {
        return Err(InstalledBinaryError::EmptyPath);
    }
    let artifact_digest = Sha256Digest::new(artifact_digest_hex)
        .map_err(|_| InstalledBinaryError::DescriptorInvalid)?;
    WasmHostBinaryBinding::new(PathBuf::from(executable_path_text), artifact_digest)
}

/// Builds the admission-bound binding from the live installation descriptor.
///
/// Read-only consumption of the B2/installer lane: `wasm_host_artifact_binding`
/// validates the descriptor self-digest and all path/digest invariants before
/// releasing the pair, and this function only reshapes that validated pair
/// into the resolver binding. Any descriptor rejection or non-conforming
/// record fails closed as [`InstalledBinaryError::DescriptorInvalid`].
///
/// # Errors
///
/// Returns [`InstalledBinaryError::DescriptorInvalid`] when the descriptor
/// fails its own validation or its released records do not conform.
pub fn binding_from_launch_descriptor(
    descriptor: &eliot_installation::RuntimeLaunchDescriptor,
) -> Result<WasmHostBinaryBinding, InstalledBinaryError> {
    let (path, digest) = descriptor
        .wasm_host_artifact_binding()
        .map_err(|_| InstalledBinaryError::DescriptorInvalid)?;
    binding_from_installation_records(path.as_str(), digest.as_str())
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
    /// The installation descriptor (or its records) failed validation, so no
    /// binding was constructed. Carries no descriptor content.
    DescriptorInvalid,
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
            Self::DescriptorInvalid => "INSTALLED_BINARY_DESCRIPTOR_INVALID",
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
    fn installation_records_shape_checked_before_binding() {
        let bytes = fixture_bytes();
        let digest_hex = Sha256Digest::of_bytes(&bytes).as_str().to_owned();
        let path = std::env::temp_dir().join("eliot-1955-installed-binary-ok.bin");
        let path_text = path.to_str().expect("fixture path is unicode").to_owned();
        let binding =
            binding_from_installation_records(&path_text, &digest_hex).expect("valid records bind");
        assert_eq!(
            binding.executable_path().as_os_str().to_str(),
            Some(path_text.as_str())
        );
        assert_eq!(binding.artifact_digest().as_str(), digest_hex.as_str());
        assert_eq!(
            binding_from_installation_records("", &digest_hex).map(|_| ()),
            Err(InstalledBinaryError::EmptyPath)
        );
        assert_eq!(
            binding_from_installation_records(&path_text, "not-a-digest").map(|_| ()),
            Err(InstalledBinaryError::DescriptorInvalid)
        );
        assert_eq!(
            binding_from_installation_records(&path_text, &"A".repeat(64)).map(|_| ()),
            Err(InstalledBinaryError::DescriptorInvalid)
        );
        assert_eq!(
            InstalledBinaryError::DescriptorInvalid.code(),
            "INSTALLED_BINARY_DESCRIPTOR_INVALID"
        );
    }

    fn placeholder_handle(value: &str) -> eliot_installation::PlatformHandle {
        eliot_installation::PlatformHandle::new(value).expect("placeholder handle")
    }

    fn garbage_launch_descriptor() -> eliot_installation::RuntimeLaunchDescriptor {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
        use std::num::NonZeroU64;
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        let epoch = EpochId::new(lineage, NonZeroU64::new(1).expect("sequence")).expect("epoch");
        let handle = || placeholder_handle("placeholder");
        eliot_installation::RuntimeLaunchDescriptor {
            profile: eliot_installation::InstallationProfile::PortableDev,
            portable_root: None,
            installation_epoch: eliot_installation::InstallationEpoch {
                installation: handle(),
                lineage_id: handle(),
                sequence: 1,
            },
            generation: handle(),
            authority_generation: ResourceGeneration::genesis(),
            authority_state_fence: StateFence::new(epoch, ResourceGeneration::genesis()),
            authority_descriptor_path: handle(),
            authority_descriptor_digest: handle(),
            supervision_authority: eliot_installation::SupervisionAuthorityBinding::Pending {
                supervision_lease_scope_id: handle(),
            },
            runtime_state_roots: eliot_installation::RuntimeStateRoots {
                profile: eliot_installation::InstallationProfile::PortableDev,
                profile_anchor_root: handle(),
                installation_root: handle(),
                host_state_root: handle(),
                kernel_ors_root: handle(),
                kernel_work_root: handle(),
                store_data_root: handle(),
                store_work_root: handle(),
                store_temp_root: handle(),
                watchdog_state_root: handle(),
                roots_digest: handle(),
            },
            kernel_work_root: handle(),
            kernel_artifact_digest: handle(),
            eliotd_executable_path: handle(),
            eliotd_artifact_digest: handle(),
            eliotd_config_path: handle(),
            eliotd_config_digest: handle(),
            protected_snapshot_digest: handle(),
            eliotd_descriptor_path: handle(),
            eliotd_descriptor_digest: handle(),
            eliotd_launch_nonce: handle(),
            store_config_path: handle(),
            store_credential_target: handle(),
            store_bridge_executable_path: handle(),
            store_bridge_artifact_digest: handle(),
            store_bootstrap_descriptor_path: handle(),
            store_bootstrap_descriptor_digest: handle(),
            canonical_store_executable_path: handle(),
            canonical_store_artifact_digest: handle(),
            kernel_arguments: Vec::new(),
            store_bridge_arguments: Vec::new(),
            canonical_store_arguments: Vec::new(),
            host_executable_path: handle(),
            host_artifact_digest: handle(),
            watchdog_executable_path: handle(),
            watchdog_artifact_digest: handle(),
            doctor_artifact_digest: handle(),
            testd_artifact_digest: handle(),
            native_worker_artifact_digest: handle(),
            wasm_host_artifact_digest: handle(),
            doctor_executable_path: handle(),
            testd_executable_path: handle(),
            native_worker_executable_path: handle(),
            wasm_host_executable_path: handle(),
            descriptor_digest: handle(),
        }
    }

    #[test]
    fn unvalidated_descriptor_yields_no_binding() {
        // Placeholder records cannot satisfy the descriptor's own
        // self-digest/invariant validation: no binding is constructed, and no
        // descriptor content is echoed.
        assert_eq!(
            binding_from_launch_descriptor(&garbage_launch_descriptor()).map(|_| ()),
            Err(InstalledBinaryError::DescriptorInvalid)
        );
    }

    #[test]
    fn descriptor_records_resolve_against_observed_bytes() {
        // End-to-end resolver consumption: validated records bind, and the
        // bound file resolves only when its observed bytes match.
        let bytes = fixture_bytes();
        let digest_hex = Sha256Digest::of_bytes(&bytes).as_str().to_owned();
        let path = write_fixture("eliot-1955-installed-binary-descriptor.bin", &bytes);
        let path_text = path.to_str().expect("fixture path is unicode").to_owned();
        let binding =
            binding_from_installation_records(&path_text, &digest_hex).expect("records bind");
        let resolved = resolve_installed_binary(&binding).expect("bytes match the binding");
        assert_eq!(resolved.path(), path.as_path());
        assert_eq!(resolved.digest().as_str(), digest_hex.as_str());
        let _ = std::fs::remove_file(&path);
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
