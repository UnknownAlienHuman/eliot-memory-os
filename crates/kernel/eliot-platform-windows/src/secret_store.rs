//! Windows secret-storage closure.
//!
//! Extracted from `crates/kernel/eliot-platform-windows/src/lib.rs` to isolate
//! provider-neutral secret handling behind an explicit module boundary.
//! Ownership: physical Windows secret persistence/DPAPI only (Credential Manager / DPAPI via `secret_store`). Explicitly forbids semantic authority, provider ownership, default/cache/retry, path ownership, or capability minting.
//!
//! Architecture (normative, source-backed only):
//! - `ARCH-AUTH-01` — Authority explicit, scoped and fenced
//!   (`docs/architecture/A02-01-complementary-fallibility.md`)
//! - `ARCH-SEC-02` — One canonical transition path
//!   (`docs/architecture/A12-03-one-governed-write-path.md`)
//! - `ARCH-RES-01` — Fail locally, recover globally
//!   (`docs/architecture/A13-01-let-it-fail-locally.md`)
//!
//!   These are cited only where the source text directly supports secret
//!   isolation, least authority, and protected-storage semantics; no invented
//!   Architecture sections are claimed.
//!
//! Implementation (normative):
//! - `I15.4` Secrets — Windows Credential Manager/DPAPI-protected `SecretRef`
//!   values behind the secret-provider facade
//!   (`docs/architecture/I15-04-secrets.md`)
//! - `I2.1` Crate-rich extraction of a capability behind an owned contract
//!   (`docs/architecture/I02-01-primary-decision-crate-rich-process-sparse-owner-sparse.md`)
//!   and `I2.23` Capability-family topology
//!   (`docs/architecture/I02-23-capability-family-topology-and-crate-extraction-decisions.md`)
//!   — single-responsibility micro-module extraction within the owning crate.
//!
//! Normative sources: `docs/ARCHITECTURE_CONTRACT.md`,
//! `docs/architecture/ELIOT_ARCHITECTURE.md`,
//! `docs/architecture/ELIOT_IMPLEMENTATION.md` (compatibility entry points;
//! the governing shards are named per anchor above).
//!
//! Non-normative source-symbol references (traceability only, not authority).
//! Every symbol below is owned by this module; it was extracted here from the
//! crate root, so no line coordinates are recorded:
//! - `ProtectedSecret`, `WindowsPlatform::protect_secret`, `unprotect_secret`,
//!   `write_credential`, `read_credential`, `delete_credential`,
//!   `dpapi_protect`, `dpapi_unprotect`, `credential_write`, `credential_read`,
//!   `credential_read_optional`, `credential_delete`,
//!   `require_exact_credential_readback`
//! - Secret generation seams remain with their providers:
//!   `WindowsInstallerSecretProvider::generate_secret`,
//!   `WindowsLocalServiceCredentialProvider::generate_secret`,
//!   `HostCredentialMutationCapability::generate_secret`
//!
//! Secret bytes are opaque OS primitives and never become semantic authority. Only
//! durable installation markers, HMAC proofs, and explicit reloads are authority.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use eliot_platform::PlatformHandle;
use sha2::{Digest, Sha256};

const HOST_CREDENTIAL_MUTEX_PREFIX: &str = "Global\\Eliot-Host-Credential-";

#[cfg(windows)]
pub(crate) const HOST_CREDENTIAL_INTERLOCK_TIMEOUT_MS: u32 = 30_000;

pub(crate) const INSTALLER_CREDENTIAL_TARGET_PREFIX: &str = "eliot/installer-root/v1/";
pub(crate) const STORE_CREDENTIAL_TARGET_PREFIX: &str = "eliot/store/v1/";

/// User-scoped DPAPI ciphertext.  The bytes carry no authority and are not
/// serializable by this crate.
pub struct ProtectedSecret(pub(crate) Vec<u8>);

impl ProtectedSecret {
    /// Adopts opaque DPAPI ciphertext returned by durable storage.
    ///
    /// # Errors
    /// Returns [`crate::WindowsAdapterError::InvalidInput`] for empty ciphertext.
    pub fn from_ciphertext(ciphertext: Vec<u8>) -> Result<Self, crate::WindowsAdapterError> {
        if ciphertext.is_empty() {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        Ok(Self(ciphertext))
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Secret bytes read from Credential Manager.  Debug/serde are deliberately
/// absent and memory is cleared when the value is dropped.
pub struct CredentialSecret(pub(crate) Vec<u8>);

impl CredentialSecret {
    /// Moves already-secret bytes into a zeroizing owner.
    ///
    /// # Errors
    /// Empty or oversized `WinCred` blobs are rejected.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, crate::WindowsAdapterError> {
        if bytes.is_empty() || bytes.len() > 2560 {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        Ok(Self(bytes))
    }

    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for CredentialSecret {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Readback of one installer-owned Credential Manager target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerSecretObservation {
    /// The exact target does not exist.
    Absent,
    /// The exact target contains a bounded 256-bit ownership key.
    Present,
}

/// Result of creating an installer ownership key at an already-durable target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallerSecretCreateDisposition {
    /// This call created the exact Credential Manager entry.
    Created,
    /// The exact target already contained a valid ownership key.
    AlreadyExists,
}

/// Narrow current-user Credential Manager provider for installer ownership keys.
///
/// The provider never returns generated key bytes from a persistence operation.
/// Callers durably persist only the unpredictable target returned by
/// [`Self::fresh_reference`] and must commit that reference and its proof before
/// calling [`Self::write_exact_if_absent`].
///
/// This is an OS/Credential Manager primitive, not transaction authority. The
/// current-user SID and `CredMan` vault are the trust boundary; the installation
/// adapter alone combines this primitive with durable intent and an HMAC-bound
/// receipt. `WinCred` has no atomic create-only operation: this target interlock
/// serializes cooperating callers, while a non-cooperating same-user writer can
/// still race and replace the value, including before the write reaches the
/// provider. Exact readback verifies the bytes present immediately after the
/// write, so it detects post-write drift but is not atomic authority. Root
/// execution still requires the durable HMAC proof, Created CAS, and mandatory
/// reload. User/portable profiles therefore have the explicitly weaker
/// same-user boundary provided by Windows Credential Manager.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsInstallerSecretProvider;

impl WindowsInstallerSecretProvider {
    const KEY_BYTES: usize = 32;
    const REFERENCE_RANDOM_BYTES: usize = 16;

    /// Creates a provider without opening or changing Credential Manager.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the exact Windows SID owning this current-user provider scope.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error when the process token cannot be observed.
    pub fn principal_sid(&self) -> Result<PlatformHandle, crate::WindowsAdapterError> {
        let sid =
            crate::current_process_sid().map_err(|_| crate::WindowsAdapterError::Unavailable)?;
        PlatformHandle::new(sid).map_err(|_| crate::WindowsAdapterError::InvalidInput)
    }

    /// Issues a non-secret unpredictable Credential Manager target.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error when Windows CSPRNG is unavailable.
    pub fn fresh_reference(&self) -> Result<PlatformHandle, crate::WindowsAdapterError> {
        let mut random = [0_u8; Self::REFERENCE_RANDOM_BYTES];
        crate::fill_system_random(&mut random)?;
        let reference = format!("eliot/installer-root/v1/{}", hex_lower(&random));
        random.fill(0);
        PlatformHandle::new(reference).map_err(|_| crate::WindowsAdapterError::InvalidInput)
    }

    /// Authoritatively observes the exact target without creating it.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error for invalid targets, provider failure, or
    /// a present credential whose secret is not exactly 256 bits.
    pub fn inspect(
        &self,
        reference: &PlatformHandle,
    ) -> Result<InstallerSecretObservation, crate::WindowsAdapterError> {
        if !valid_installer_credential_target(reference.as_str()) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        match credential_read_optional(reference.as_str())? {
            Some(secret) if secret.expose().len() == Self::KEY_BYTES => {
                Ok(InstallerSecretObservation::Present)
            }
            Some(_) => Err(crate::WindowsAdapterError::InvalidInput),
            None => Ok(InstallerSecretObservation::Absent),
        }
    }

    /// Generates one 256-bit key without persisting it.
    ///
    /// The caller must retain the returned opaque value until the matching
    /// durable intent has been committed. The value intentionally has no
    /// `Debug`, `Clone`, or serialization implementation.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error when the Windows CSPRNG is unavailable.
    pub fn generate_secret(&self) -> Result<CredentialSecret, crate::WindowsAdapterError> {
        let mut secret = vec![0_u8; Self::KEY_BYTES];
        crate::fill_system_random(&mut secret)?;
        Ok(CredentialSecret(secret))
    }

    /// Reads an exact installer target without mutating Credential Manager.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error for invalid targets, provider failure, or
    /// malformed credential data.
    pub fn read_optional(
        &self,
        reference: &PlatformHandle,
    ) -> Result<Option<CredentialSecret>, crate::WindowsAdapterError> {
        if !valid_installer_credential_target(reference.as_str()) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        match credential_read_optional(reference.as_str())? {
            Some(secret) if secret.expose().len() == Self::KEY_BYTES => Ok(Some(secret)),
            Some(_) => Err(crate::WindowsAdapterError::InvalidInput),
            None => Ok(None),
        }
    }

    /// Writes exact bytes after an absence observation, under the bounded
    /// same-user target interlock, and verifies the authoritative readback.
    /// `WinCred` has no atomic create-only write; a non-cooperating same-user
    /// writer can race this operation, including before the write reaches the
    /// provider. The immediate constant-time readback verifies the bytes
    /// present after the write and detects post-write drift; it is not an
    /// authority decision.
    ///
    /// # Errors
    ///
    /// Returns a typed provider error for invalid targets, provider failure,
    /// interlock failure, or failed authoritative readback.
    pub fn write_exact_if_absent(
        &self,
        reference: &PlatformHandle,
        secret: CredentialSecret,
    ) -> Result<InstallerSecretCreateDisposition, crate::WindowsAdapterError> {
        if !valid_installer_credential_target(reference.as_str()) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        if secret.expose().len() != Self::KEY_BYTES {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        let _interlock =
            HostCredentialInterlock::acquire("eliot-installer-ownership-secret-v1", reference)?;
        if self.read_optional(reference)?.is_some() {
            return Ok(InstallerSecretCreateDisposition::AlreadyExists);
        }
        credential_write(reference.as_str(), secret.expose())?;
        let readback = self.read_optional(reference)?;
        let result = require_exact_credential_readback(
            secret.expose(),
            readback.as_ref().map(CredentialSecret::expose),
        );
        drop(readback);
        match result {
            Ok(()) => {
                drop(secret);
                Ok(InstallerSecretCreateDisposition::Created)
            }
            Err(error) => {
                drop(secret);
                Err(error)
            }
        }
    }

    /// Reads the exact 256-bit key into a zeroizing value.
    ///
    /// # Errors
    ///
    /// Missing, inaccessible, or malformed entries fail closed.
    pub fn read(
        &self,
        reference: &PlatformHandle,
    ) -> Result<CredentialSecret, crate::WindowsAdapterError> {
        if !valid_installer_credential_target(reference.as_str()) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        let secret = credential_read(reference.as_str())?;
        if secret.expose().len() != Self::KEY_BYTES {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        Ok(secret)
    }

    /// Deletes an exact terminal ownership credential.
    ///
    /// # Errors
    ///
    /// Missing and inaccessible entries remain explicit failures.
    pub fn delete(&self, reference: &PlatformHandle) -> Result<(), crate::WindowsAdapterError> {
        if !valid_installer_credential_target(reference.as_str()) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        credential_delete(reference.as_str())
    }
}

/// Raw current-token Credential Manager primitive used by the `LocalService`
/// Host.  It is deliberately private: callers must obtain the opaque
/// Host-owned capability from a live [`crate::HostOwnerLease`].
#[derive(Clone, Copy, Debug, Default)]
struct WindowsLocalServiceCredentialProvider;

#[allow(
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    reason = "the provider methods are kept as an opaque instance boundary"
)]
impl WindowsLocalServiceCredentialProvider {
    /// Creates the primitive without reading or mutating Credential Manager.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Returns the current process-token SID.
    ///
    /// # Errors
    /// Returns an error when the process token cannot be observed.
    pub fn principal_sid(&self) -> Result<PlatformHandle, crate::WindowsAdapterError> {
        let sid =
            crate::current_process_sid().map_err(|_| crate::WindowsAdapterError::Unavailable)?;
        PlatformHandle::new(sid).map_err(|_| crate::WindowsAdapterError::InvalidInput)
    }

    /// Generates 256 secret bits in a zeroizing value without persisting them.
    ///
    /// # Errors
    /// Returns an error when the Windows CSPRNG is unavailable.
    pub fn generate_secret(&self) -> Result<CredentialSecret, crate::WindowsAdapterError> {
        let mut secret = vec![0_u8; 32];
        crate::fill_system_random(&mut secret)?;
        Ok(CredentialSecret(secret))
    }

    /// Reads an exact target under the current token.
    ///
    /// # Errors
    /// Returns an error for invalid targets or provider failure.
    pub fn read_optional(
        &self,
        target: &PlatformHandle,
    ) -> Result<Option<CredentialSecret>, crate::WindowsAdapterError> {
        if !valid_credential_key(target.as_str()) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        credential_read_optional(target.as_str())
    }

    /// Writes exact bytes. This raw `WinCred` call can replace an entry; durable
    /// marker ownership and an immediately preceding absence check are required.
    ///
    /// # Errors
    /// Returns an error for invalid targets or provider failure.
    pub fn write(
        &self,
        target: &PlatformHandle,
        secret: &CredentialSecret,
    ) -> Result<(), crate::WindowsAdapterError> {
        if !valid_credential_key(target.as_str()) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        credential_write(target.as_str(), secret.expose())
    }

    /// Deletes the exact target.
    ///
    /// # Errors
    /// Missing and inaccessible targets fail closed.
    pub fn delete(&self, target: &PlatformHandle) -> Result<(), crate::WindowsAdapterError> {
        if !valid_credential_key(target.as_str()) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        credential_delete(target.as_str())
    }
}

/// Opaque capability for the authenticated Host credential boundary.
///
/// The capability owns no secret and exposes only operations needed by the
/// Host composition. The write-if-absent operation holds a protected,
/// per-installation/per-target mutex across the final read, `CredWriteW`, and
/// authoritative readback. `WinCred` has no atomic create-only write: the
/// mutex serializes cooperating callers, but a non-cooperating same-user
/// writer can still race and replace the value, including before the write
/// reaches the provider. Exact readback verifies the bytes present immediately
/// after the write and detects post-write drift; it is collision/recovery
/// evidence, not an atomic ownership proof.
#[derive(Debug)]
pub struct HostCredentialMutationCapability {
    installation_digest: String,
    authority: Arc<crate::HostLeaseAuthority>,
}

#[allow(
    clippy::missing_errors_doc,
    clippy::needless_pass_by_value,
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    reason = "this opaque capability deliberately preserves the provider API boundary"
)]
impl HostCredentialMutationCapability {
    pub fn principal_sid(&self) -> Result<PlatformHandle, crate::WindowsAdapterError> {
        self.with_authority(|| WindowsLocalServiceCredentialProvider::new().principal_sid())
    }

    pub fn read_optional(
        &self,
        target: &PlatformHandle,
    ) -> Result<Option<CredentialSecret>, crate::WindowsAdapterError> {
        self.with_authority(|| WindowsLocalServiceCredentialProvider::new().read_optional(target))
    }

    pub fn generate_secret(&self) -> Result<CredentialSecret, crate::WindowsAdapterError> {
        self.with_authority(|| WindowsLocalServiceCredentialProvider::new().generate_secret())
    }

    pub fn write_if_absent(
        &self,
        target: &PlatformHandle,
        secret: CredentialSecret,
    ) -> Result<CredentialSecret, crate::WindowsAdapterError> {
        self.with_authority(|| {
            let primitive = WindowsLocalServiceCredentialProvider::new();
            primitive.with_target_interlock(&self.installation_digest, target, || {
                if primitive.read_optional(target)?.is_some() {
                    return Err(crate::WindowsAdapterError::AlreadyExists);
                }
                primitive.write(target, &secret)?;
                let readback = primitive.read_optional(target)?;
                require_exact_credential_readback(
                    secret.expose(),
                    readback.as_ref().map(CredentialSecret::expose),
                )?;
                let readback = readback.ok_or(crate::WindowsAdapterError::Unavailable)?;
                Ok(readback)
            })
        })
    }

    pub fn delete(&self, target: &PlatformHandle) -> Result<(), crate::WindowsAdapterError> {
        self.with_authority(|| {
            let primitive = WindowsLocalServiceCredentialProvider::new();
            primitive.with_target_interlock(&self.installation_digest, target, || {
                primitive.delete(target)
            })
        })
    }

    pub fn delete_if_matching(
        &self,
        target: &PlatformHandle,
        expected_digest: &PlatformHandle,
        mut verify: impl FnMut(&CredentialSecret) -> bool,
    ) -> Result<(), crate::WindowsAdapterError> {
        self.with_authority(|| {
            let primitive = WindowsLocalServiceCredentialProvider::new();
            primitive.with_target_interlock(&self.installation_digest, target, || {
                if let Some(value) = primitive.read_optional(target)? {
                    if format!("{:x}", Sha256::digest(value.expose())) != expected_digest.as_str()
                        || !verify(&value)
                    {
                        return Err(crate::WindowsAdapterError::IdentityMismatch);
                    }
                    primitive.delete(target)?;
                }
                if primitive.read_optional(target)?.is_some() {
                    return Err(crate::WindowsAdapterError::Unavailable);
                }
                Ok(())
            })
        })
    }

    pub(crate) fn with_authority<T>(
        &self,
        operation: impl FnOnce() -> Result<T, crate::WindowsAdapterError>,
    ) -> Result<T, crate::WindowsAdapterError> {
        let _gate = self
            .authority
            .gate
            .lock()
            .map_err(|_| crate::WindowsAdapterError::IdentityMismatch)?;
        if self.authority.revoked.load(Ordering::Acquire) {
            return Err(crate::WindowsAdapterError::IdentityMismatch);
        }
        operation()
    }
}

fn host_owner_identity_digest(name: &str) -> String {
    format!("{:x}", Sha256::digest(name.as_bytes()))
}

#[allow(
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    reason = "the provider methods are kept as an opaque instance boundary"
)]
impl WindowsLocalServiceCredentialProvider {
    fn with_target_interlock<T>(
        &self,
        installation_digest: &str,
        target: &PlatformHandle,
        operation: impl FnOnce() -> Result<T, crate::WindowsAdapterError>,
    ) -> Result<T, crate::WindowsAdapterError> {
        let _interlock = HostCredentialInterlock::acquire(installation_digest, target)?;
        operation()
    }
}

struct HostCredentialInterlock {
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
pub(crate) fn classify_host_credential_interlock_wait(
    wait: u32,
) -> Result<(), crate::WindowsAdapterError> {
    use windows_sys::Win32::Foundation::{
        WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };

    if wait == WAIT_ABANDONED {
        return Err(crate::WindowsAdapterError::IdentityMismatch);
    }
    match wait {
        WAIT_OBJECT_0 => Ok(()),
        WAIT_TIMEOUT => Err(crate::WindowsAdapterError::Timeout),
        WAIT_FAILED => Err(crate::last_windows_adapter_error()),
        _ => Err(crate::WindowsAdapterError::IdentityMismatch),
    }
}

impl HostCredentialInterlock {
    fn acquire(
        installation_digest: &str,
        target: &PlatformHandle,
    ) -> Result<Self, crate::WindowsAdapterError> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
            use windows_sys::Win32::System::Threading::{CreateMutexW, WaitForSingleObject};
            let digest =
                Sha256::digest(format!("{installation_digest}\0{}", target.as_str()).as_bytes());
            let mut suffix = String::with_capacity(digest.len() * 2);
            for byte in digest {
                use std::fmt::Write as _;
                let _ = write!(suffix, "{byte:02x}");
            }
            let name = format!("{HOST_CREDENTIAL_MUTEX_PREFIX}{suffix}");
            let wide_name = crate::nul_terminated_wide(std::ffi::OsStr::new(&name))
                .map_err(|_| crate::WindowsAdapterError::InvalidInput)?;
            let descriptor = crate::OwnedSecurityDescriptor::for_host_owner()?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
                    .map_err(|_| crate::WindowsAdapterError::InvalidInput)?,
                lpSecurityDescriptor: descriptor.raw,
                bInheritHandle: 0,
            };
            let handle = unsafe { CreateMutexW(&raw const attributes, 0, wide_name.as_ptr()) };
            if handle.is_null() {
                return Err(crate::last_windows_adapter_error());
            }
            let wait = unsafe { WaitForSingleObject(handle, HOST_CREDENTIAL_INTERLOCK_TIMEOUT_MS) };
            match classify_host_credential_interlock_wait(wait) {
                Ok(()) => Ok(Self { handle }),
                Err(error) => {
                    let _ = unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) };
                    Err(error)
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = (installation_digest, target);
            Err(crate::WindowsAdapterError::Unavailable)
        }
    }
}

#[cfg(windows)]
impl Drop for HostCredentialInterlock {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::ReleaseMutex;
        let _ = unsafe { ReleaseMutex(self.handle) };
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

impl crate::HostOwnerLease {
    /// Issues the opaque Host-only credential mutation capability.
    ///
    /// The capability can only be derived from a freshly-created owner lease;
    /// callers cannot construct the raw `LocalService` Credential Manager
    /// primitive directly. The lease itself must remain live for the Host
    /// composition lifetime.
    ///
    /// # Errors
    ///
    /// Returns `IdentityMismatch` when this lease no longer owns its mutex.
    pub fn credential_mutation_capability(
        &self,
    ) -> Result<HostCredentialMutationCapability, crate::WindowsAdapterError> {
        let _gate = self
            .authority
            .gate
            .lock()
            .map_err(|_| crate::WindowsAdapterError::IdentityMismatch)?;
        if !self.owns || self.authority.revoked.load(Ordering::Acquire) {
            return Err(crate::WindowsAdapterError::IdentityMismatch);
        }
        Ok(HostCredentialMutationCapability {
            installation_digest: host_owner_identity_digest(&self.name),
            authority: Arc::clone(&self.authority),
        })
    }
}

impl crate::WindowsPlatform {
    /// Protects secret bytes for the current Windows user through DPAPI.
    ///
    /// # Errors
    /// Returns a typed adapter error for empty input or DPAPI failure.
    pub fn protect_secret(
        &self,
        secret: &[u8],
    ) -> Result<ProtectedSecret, crate::WindowsAdapterError> {
        if secret.is_empty() {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        dpapi_protect(secret)
    }

    /// Decrypts bytes previously protected for this Windows user.
    ///
    /// # Errors
    /// Returns a typed adapter error when ciphertext is invalid or unavailable.
    pub fn unprotect_secret(
        &self,
        protected: &ProtectedSecret,
    ) -> Result<CredentialSecret, crate::WindowsAdapterError> {
        dpapi_unprotect(protected.as_bytes())
    }

    /// Writes an opaque generic credential through Windows Credential Manager.
    ///
    /// # Errors
    /// Returns a typed adapter error for invalid keys, size or provider failure.
    pub fn write_credential(
        &self,
        key: &str,
        secret: &[u8],
    ) -> Result<(), crate::WindowsAdapterError> {
        if installer_credential_target(key) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        credential_write(key, secret)
    }

    /// Reads the exact opaque bytes stored in Windows Credential Manager.
    ///
    /// # Errors
    /// Returns a typed adapter error when the key is invalid, absent or inaccessible.
    pub fn read_credential(
        &self,
        key: &str,
    ) -> Result<CredentialSecret, crate::WindowsAdapterError> {
        if installer_credential_target(key) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        credential_read(key)
    }

    /// Deletes a generic credential. Missing credentials remain explicitly
    /// unavailable rather than being reported as a successful deletion.
    ///
    /// # Errors
    /// Returns a typed adapter error when the key is invalid, absent or inaccessible.
    pub fn delete_credential(&self, key: &str) -> Result<(), crate::WindowsAdapterError> {
        if installer_credential_target(key) {
            return Err(crate::WindowsAdapterError::InvalidInput);
        }
        credential_delete(key)
    }
}

fn constant_time_equal_bytes(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

pub(crate) fn require_exact_credential_readback(
    expected: &[u8],
    actual: Option<&[u8]>,
) -> Result<(), crate::WindowsAdapterError> {
    match actual {
        Some(actual) if constant_time_equal_bytes(expected, actual) => Ok(()),
        Some(_) => Err(crate::WindowsAdapterError::IdentityMismatch),
        None => Err(crate::WindowsAdapterError::Unavailable),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut value = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(windows)]
fn dpapi_protect(secret: &[u8]) -> Result<ProtectedSecret, crate::WindowsAdapterError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
    };
    let input_len =
        u32::try_from(secret.len()).map_err(|_| crate::WindowsAdapterError::InvalidInput)?;
    let input = CRYPT_INTEGER_BLOB {
        cbData: input_len,
        pbData: secret.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    if unsafe {
        CryptProtectData(
            &raw const input,
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(crate::last_windows_adapter_error());
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output.pbData, usize::try_from(output.cbData).unwrap_or(0))
    }
    .to_vec();
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(ProtectedSecret(bytes))
}

#[cfg(not(windows))]
fn dpapi_protect(_secret: &[u8]) -> Result<ProtectedSecret, crate::WindowsAdapterError> {
    Err(crate::WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
fn dpapi_unprotect(protected: &[u8]) -> Result<CredentialSecret, crate::WindowsAdapterError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };
    if protected.is_empty() {
        return Err(crate::WindowsAdapterError::InvalidInput);
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: u32::try_from(protected.len())
            .map_err(|_| crate::WindowsAdapterError::InvalidInput)?,
        pbData: protected.as_ptr().cast_mut(),
    };
    let mut output = CRYPT_INTEGER_BLOB::default();
    if unsafe {
        CryptUnprotectData(
            &raw const input,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &raw mut output,
        )
    } == 0
    {
        return Err(crate::last_windows_adapter_error());
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output.pbData, usize::try_from(output.cbData).unwrap_or(0))
    }
    .to_vec();
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(CredentialSecret(bytes))
}

#[cfg(not(windows))]
fn dpapi_unprotect(_protected: &[u8]) -> Result<CredentialSecret, crate::WindowsAdapterError> {
    Err(crate::WindowsAdapterError::Unavailable)
}

pub(crate) fn valid_credential_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 240
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | '/')
        })
}

pub(crate) fn installer_credential_target(value: &str) -> bool {
    value.starts_with(INSTALLER_CREDENTIAL_TARGET_PREFIX)
}

pub(crate) fn valid_installer_credential_target(value: &str) -> bool {
    value
        .strip_prefix(INSTALLER_CREDENTIAL_TARGET_PREFIX)
        .is_some_and(|token| {
            token.len() == 32
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

#[cfg(windows)]
pub(crate) fn credential_write(key: &str, secret: &[u8]) -> Result<(), crate::WindowsAdapterError> {
    if !valid_credential_key(key) || secret.is_empty() || secret.len() > 2560 {
        return Err(crate::WindowsAdapterError::InvalidInput);
    }
    eliot_windows_ipc::credential_write_current_user(key, secret)
        .map_err(|error| crate::windows_adapter_from_io(&error))
}

#[cfg(not(windows))]
fn credential_write(_key: &str, _secret: &[u8]) -> Result<(), crate::WindowsAdapterError> {
    Err(crate::WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
pub(crate) fn credential_read(key: &str) -> Result<CredentialSecret, crate::WindowsAdapterError> {
    if !valid_credential_key(key) {
        return Err(crate::WindowsAdapterError::InvalidInput);
    }
    match eliot_windows_ipc::credential_read_current_user(key)
        .map_err(|error| crate::windows_adapter_from_io(&error))?
    {
        Some(value) => Ok(CredentialSecret(value)),
        None => Err(crate::WindowsAdapterError::Unavailable),
    }
}

#[cfg(windows)]
pub(crate) fn credential_read_optional(
    key: &str,
) -> Result<Option<CredentialSecret>, crate::WindowsAdapterError> {
    if !valid_credential_key(key) {
        return Err(crate::WindowsAdapterError::InvalidInput);
    }
    eliot_windows_ipc::credential_read_current_user(key)
        .map(|secret| secret.map(CredentialSecret))
        .map_err(|error| crate::windows_adapter_from_io(&error))
}

#[cfg(not(windows))]
pub(crate) fn credential_read_optional(
    _key: &str,
) -> Result<Option<CredentialSecret>, crate::WindowsAdapterError> {
    Err(crate::WindowsAdapterError::Unavailable)
}

#[cfg(not(windows))]
pub(crate) fn credential_read(_key: &str) -> Result<CredentialSecret, crate::WindowsAdapterError> {
    Err(crate::WindowsAdapterError::Unavailable)
}

#[cfg(windows)]
pub(crate) fn credential_delete(key: &str) -> Result<(), crate::WindowsAdapterError> {
    if !valid_credential_key(key) {
        return Err(crate::WindowsAdapterError::InvalidInput);
    }
    if eliot_windows_ipc::credential_delete_current_user(key)
        .map_err(|error| crate::windows_adapter_from_io(&error))?
    {
        Ok(())
    } else {
        Err(crate::WindowsAdapterError::Unavailable)
    }
}

#[cfg(not(windows))]
pub(crate) fn credential_delete(_key: &str) -> Result<(), crate::WindowsAdapterError> {
    Err(crate::WindowsAdapterError::Unavailable)
}
