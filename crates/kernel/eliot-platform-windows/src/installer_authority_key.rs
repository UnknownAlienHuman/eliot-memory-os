//! Protected Windows signing-key storage for installer activation approvals.
//!
//! The key slot is deliberately a small, boring file primitive.  The parent
//! installation contour and the dedicated key root must already exist; this
//! module never creates, repairs, adopts, replaces or deletes an ambiguous
//! object.  A slot is created with `CREATE_NEW`, an explicit SY/BA-only
//! security descriptor, and no delete sharing.  Existing slots are opened only
//! when the caller supplies the exact key id, public-key fingerprint and file
//! identity previously recorded by the installer.

use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use eliot_runtime_contracts::{
    Ed25519InstallationActivationApprovalSigner, InstallationActivationApprovalSigner,
    InstallationActivationApprovalTrustAnchor, InstallationActivationError,
};

use super::{
    FileIdentity, ProtectedPathError, ProtectedRootLease, WindowsAdapterError,
    file_identity_from_handle, final_windows_path_from_handle, protected_program_data_path,
    verify_exact_file_security, windows_paths_equal,
};

#[cfg(windows)]
use super::{OwnedKernelHandle, OwnedSecurityDescriptor, fill_system_random, is_reparse_point};
#[cfg(windows)]
use std::sync::Arc;

/// Stable signer identity used by the Windows installer authority primitive.
pub const INSTALLATION_AUTHORITY_SIGNER_ID: &str = "installer-authority";
/// Stable key-file magic.  The remainder of the format is private to this
/// crate and is bounded by [`INSTALLATION_AUTHORITY_KEY_FILE_BYTES`].
pub const INSTALLATION_AUTHORITY_KEY_MAGIC: [u8; 8] = *b"ELIOTAK1";
/// Current key-file format version.
pub const INSTALLATION_AUTHORITY_KEY_FILE_VERSION: u32 = 1;
/// Exact file size: magic + version + reserved bytes + 256-bit seed.
pub const INSTALLATION_AUTHORITY_KEY_FILE_BYTES: usize = 8 + 4 + 4 + 32;
/// Maximum accepted key-id length in the key-slot path.
pub const INSTALLATION_AUTHORITY_KEY_ID_MAX_BYTES: usize = 64;
/// Fixed key-root path below the approved `SystemService` installation contour.
pub const INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE: &str = "host/authority-keys";

const EXPECTED_OWNER_SID: &str = "S-1-5-18";
const KEY_FILE_EXTENSION: &str = ".key";

/// Typed failure from the protected installer-authority key primitive.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationAuthorityKeyError {
    /// The caller supplied a relative, malformed or out-of-contour path.
    InvalidPath,
    /// The caller supplied a key id that cannot safely name one slot.
    InvalidKeyId,
    /// The dedicated key root or one of its required ancestors is absent.
    MissingRoot,
    /// A path component or target is a reparse point.
    ReparsePoint,
    /// The root or key file does not carry the exact SY/BA-only ACL.
    AclMismatch,
    /// The target already exists and therefore cannot be safely adopted.
    AlreadyExists,
    /// The existing key was absent, partial, malformed or otherwise ambiguous.
    MissingOrMalformed,
    /// The supplied identity/fingerprint/path does not match the retained file.
    IdentityMismatch,
    /// The OS CSPRNG or cryptographic signer could not be initialized.
    CryptographicFailure,
    /// The Windows call was denied by the active token.
    PermissionDenied,
    /// A bounded file operation failed without a safe committed classification.
    Io,
    /// This primitive is intentionally unavailable off Windows.
    UnsupportedPlatform,
}

impl fmt::Display for InstallationAuthorityKeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "installation authority key path is invalid",
            Self::InvalidKeyId => "installation authority key id is invalid",
            Self::MissingRoot => "installation authority key root is missing",
            Self::ReparsePoint => "installation authority key path contains a reparse point",
            Self::AclMismatch => "installation authority key owner or DACL is not exact",
            Self::AlreadyExists => "installation authority key slot already exists",
            Self::MissingOrMalformed => {
                "installation authority key slot is missing, partial or malformed"
            }
            Self::IdentityMismatch => "installation authority key identity does not match",
            Self::CryptographicFailure => "installation authority signing key failed to initialize",
            Self::PermissionDenied => "installation authority key access was denied",
            Self::Io => "installation authority key I/O failed",
            Self::UnsupportedPlatform => "installation authority key requires Windows",
        })
    }
}

impl std::error::Error for InstallationAuthorityKeyError {}

impl From<WindowsAdapterError> for InstallationAuthorityKeyError {
    fn from(error: WindowsAdapterError) -> Self {
        match error {
            WindowsAdapterError::PermissionDenied => Self::PermissionDenied,
            WindowsAdapterError::AlreadyExists => Self::AlreadyExists,
            WindowsAdapterError::IdentityMismatch | WindowsAdapterError::AclMismatch => {
                Self::IdentityMismatch
            }
            WindowsAdapterError::Unavailable | WindowsAdapterError::NotFound => Self::MissingRoot,
            WindowsAdapterError::InvalidInput => Self::InvalidPath,
            WindowsAdapterError::Failed | WindowsAdapterError::Timeout => Self::Io,
        }
    }
}

/// Public-only identity and trust-anchor material for one immutable key slot.
///
/// This type never contains the seed.  It is safe to persist as part of the
/// installation's public trust-anchor record, subject to the caller's normal
/// installation-registry binding.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationAuthorityKeyMetadata {
    /// External key reference selected by the installer authority.
    pub key_id: String,
    /// Ed25519 public verification key (exactly 32 bytes).
    pub public_key: Vec<u8>,
    /// Lowercase SHA-256 fingerprint of [`Self::public_key`].
    pub public_key_fingerprint: String,
    /// Exact key-slot path retained by the signer.
    pub slot_path: PathBuf,
    /// File identity captured from the retained no-follow handle.
    pub file_identity: FileIdentity,
}

/// Expected public identity required to reopen an existing key slot.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationAuthorityKeyExpectation {
    /// Exact key id and therefore exact slot path.
    pub key_id: String,
    /// Exact public-key fingerprint recorded at creation.
    pub public_key_fingerprint: String,
    /// Exact file identity recorded at creation.
    pub file_identity: FileIdentity,
}

impl InstallationAuthorityKeyMetadata {
    /// Returns the exact public identity required for a later reopen.
    ///
    /// # Errors
    ///
    /// Returns a typed identity error if the metadata was assembled outside
    /// the store and no longer has the canonical bounded shape.
    pub fn expectation(
        &self,
    ) -> Result<InstallationAuthorityKeyExpectation, InstallationAuthorityKeyError> {
        InstallationAuthorityKeyExpectation::new(
            self.key_id.clone(),
            self.public_key_fingerprint.clone(),
            self.file_identity,
        )
    }
}

impl InstallationAuthorityKeyExpectation {
    /// Constructs an expected identity after validating its bounded shape.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationAuthorityKeyError::InvalidKeyId`] for an unsafe
    /// slot id or [`InstallationAuthorityKeyError::IdentityMismatch`] for a
    /// malformed public-key fingerprint.
    pub fn new(
        key_id: impl Into<String>,
        public_key_fingerprint: impl Into<String>,
        file_identity: FileIdentity,
    ) -> Result<Self, InstallationAuthorityKeyError> {
        let expectation = Self {
            key_id: key_id.into(),
            public_key_fingerprint: public_key_fingerprint.into(),
            file_identity,
        };
        validate_key_id(&expectation.key_id)?;
        if !is_sha256(&expectation.public_key_fingerprint) {
            return Err(InstallationAuthorityKeyError::IdentityMismatch);
        }
        Ok(expectation)
    }
}

/// Opaque signer backed by one retained protected Windows key slot.
///
/// The private seed is held only inside the Ed25519 signer and is never
/// exposed, serialized, formatted, returned from an accessor, or placed in a
/// command line/environment value.  The retained file handle prevents an
/// unrelated process from deleting the slot while this signer is live.
pub struct InstallationAuthorityKeySigner {
    metadata: InstallationAuthorityKeyMetadata,
    signer: Ed25519InstallationActivationApprovalSigner,
    #[cfg(windows)]
    slot_handle: std::fs::File,
    #[cfg(windows)]
    contour: Arc<ProtectedRootLease>,
    #[cfg(windows)]
    root_identity: FileIdentity,
}

impl fmt::Debug for InstallationAuthorityKeySigner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstallationAuthorityKeySigner")
            .field("metadata", &self.metadata)
            .field("signing_seed", &"<redacted>")
            .field("signer", &"<redacted>")
            .field("slot_handle", &"<retained>")
            .field("contour", &"<retained>")
            .field("root_identity", &self.root_identity)
            .finish_non_exhaustive()
    }
}

impl InstallationAuthorityKeySigner {
    /// Returns public-only key metadata.
    #[must_use]
    pub fn metadata(&self) -> &InstallationAuthorityKeyMetadata {
        &self.metadata
    }

    /// Returns a public trust anchor for the caller's installation identity.
    ///
    /// The installation and signer ids are explicit composition inputs; this
    /// primitive never invents an installation identity or silently changes a
    /// caller's authority namespace.
    ///
    /// # Errors
    ///
    /// Returns [`InstallationAuthorityKeyError::CryptographicFailure`] if the
    /// public-only trust-anchor contract rejects the supplied identities.
    pub fn trust_anchor(
        &self,
        installation_id: impl Into<String>,
        signer_id: impl Into<String>,
    ) -> Result<InstallationActivationApprovalTrustAnchor, InstallationAuthorityKeyError> {
        let signer_id = signer_id.into();
        if signer_id != INSTALLATION_AUTHORITY_SIGNER_ID {
            return Err(InstallationAuthorityKeyError::IdentityMismatch);
        }
        InstallationActivationApprovalTrustAnchor::new(
            installation_id,
            signer_id,
            self.metadata.key_id.clone(),
            self.metadata.public_key.clone(),
        )
        .map_err(|_| InstallationAuthorityKeyError::CryptographicFailure)
    }

    /// Returns the external key id without exposing key material.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.metadata.key_id
    }

    /// Returns the lowercase public-key fingerprint without exposing key
    /// material.
    #[must_use]
    pub fn public_key_fingerprint(&self) -> &str {
        &self.metadata.public_key_fingerprint
    }
}

impl InstallationActivationApprovalSigner for InstallationAuthorityKeySigner {
    fn signer_id(&self) -> &str {
        INSTALLATION_AUTHORITY_SIGNER_ID
    }

    fn key_id(&self) -> &str {
        self.metadata.key_id.as_str()
    }

    fn public_key_fingerprint(&self) -> &str {
        self.metadata.public_key_fingerprint.as_str()
    }

    fn sign(&self, canonical_payload: &[u8]) -> Result<Vec<u8>, InstallationActivationError> {
        #[cfg(windows)]
        {
            validate_signer_contour(&self.contour, &self.metadata.slot_path, self.root_identity)
                .map_err(signing_error)?;
            validate_signer_slot(self).map_err(signing_error)?;
        }
        let signature = self.signer.sign(canonical_payload)?;
        #[cfg(windows)]
        {
            validate_signer_contour(&self.contour, &self.metadata.slot_path, self.root_identity)
                .map_err(signing_error)?;
            validate_signer_slot(self).map_err(signing_error)?;
        }
        Ok(signature)
    }
}

/// Existing-root Windows protected key-slot store.
#[derive(Debug)]
pub struct WindowsInstallationAuthorityKeyStore {
    key_root: PathBuf,
    #[cfg(windows)]
    root_identity: FileIdentity,
    #[cfg(windows)]
    contour: Arc<ProtectedRootLease>,
}

impl WindowsInstallationAuthorityKeyStore {
    /// Constructs a store at an already-existing dedicated key root.
    ///
    /// The root must be beneath `ProgramData\\Eliot`, must not contain a
    /// reparse component, and must already carry the exact SY/BA-only ACL.
    /// This constructor does not create or repair the root.
    ///
    /// # Errors
    ///
    /// Returns a typed path, reparse, root, identity or ACL error when the
    /// existing root cannot be proven to be the approved protected contour.
    pub fn new(key_root: impl Into<PathBuf>) -> Result<Self, InstallationAuthorityKeyError> {
        let key_root = key_root.into();
        #[cfg(windows)]
        {
            let contour = Arc::new(
                ProtectedRootLease::open_existing(&key_root).map_err(map_protected_path_error)?,
            );
            let root_identity = validate_existing_key_root(&key_root)?;
            if contour.identity() != root_identity {
                return Err(InstallationAuthorityKeyError::IdentityMismatch);
            }
            Ok(Self {
                key_root,
                root_identity,
                contour,
            })
        }
        #[cfg(not(windows))]
        {
            Err(InstallationAuthorityKeyError::UnsupportedPlatform)
        }
    }

    /// Returns the caller-supplied root path.  It contains no secret.
    #[must_use]
    pub fn key_root(&self) -> &Path {
        &self.key_root
    }

    /// Creates a fresh unpredictable key id and immutable slot.
    ///
    /// # Errors
    ///
    /// Returns a typed RNG, collision, ACL, identity or I/O error. Existing
    /// slots are never adopted or overwritten.
    pub fn create_new(
        &self,
    ) -> Result<InstallationAuthorityKeySigner, InstallationAuthorityKeyError> {
        let mut random = SecretRandom([0_u8; 16]);
        fill_random(&mut random.0)?;
        let key_id = format!("key-{}", hex_lower(&random.0));
        self.create_new_with_key_id(&key_id)
    }

    /// Creates a new immutable slot for an explicitly selected key id.
    ///
    /// A collision is terminal: this method never opens, overwrites or
    /// regenerates an existing slot.
    ///
    /// # Errors
    ///
    /// Returns a typed key-id, collision, ACL, identity or I/O error.
    pub fn create_new_with_key_id(
        &self,
        key_id: &str,
    ) -> Result<InstallationAuthorityKeySigner, InstallationAuthorityKeyError> {
        validate_key_id(key_id)?;
        self.validate_root()?;
        #[cfg(windows)]
        {
            let path = self.slot_path(key_id);
            let seed = SecretSeed({
                let mut bytes = [0_u8; 32];
                fill_system_random(&mut bytes).map_err(map_windows_error)?;
                bytes
            });
            let created = create_new_slot(&path)?;
            (|| {
                write_new_slot(&created, &seed.0)?;
                flush_parent_directory(&self.key_root);
                let reopened = reopen_slot(&path)?;
                let signer = build_signer(
                    &path,
                    reopened,
                    key_id,
                    None,
                    Arc::clone(&self.contour),
                    self.root_identity,
                )?;
                self.validate_root()?;
                validate_signer_slot(&signer)?;
                Ok(signer)
            })()
        }
        #[cfg(not(windows))]
        {
            let _ = key_id;
            Err(InstallationAuthorityKeyError::UnsupportedPlatform)
        }
    }

    /// Reopens one existing immutable slot only with its recorded public
    /// identity and exact file identity.
    ///
    /// # Errors
    ///
    /// Returns a typed mismatch, malformed-file, ACL, reparse, access or I/O
    /// error. No repair or regeneration is attempted.
    pub fn open_existing(
        &self,
        expected: &InstallationAuthorityKeyExpectation,
    ) -> Result<InstallationAuthorityKeySigner, InstallationAuthorityKeyError> {
        validate_key_id(&expected.key_id)?;
        if !is_sha256(&expected.public_key_fingerprint) {
            return Err(InstallationAuthorityKeyError::IdentityMismatch);
        }
        self.validate_root()?;
        #[cfg(windows)]
        {
            let path = self.slot_path(&expected.key_id);
            let reopened = reopen_slot(&path)?;
            let signer = build_signer(
                &path,
                reopened,
                &expected.key_id,
                Some(expected),
                Arc::clone(&self.contour),
                self.root_identity,
            )?;
            self.validate_root()?;
            validate_signer_slot(&signer)?;
            Ok(signer)
        }
        #[cfg(not(windows))]
        {
            Err(InstallationAuthorityKeyError::UnsupportedPlatform)
        }
    }

    fn slot_path(&self, key_id: &str) -> PathBuf {
        self.key_root.join(format!("{key_id}{KEY_FILE_EXTENSION}"))
    }

    fn validate_root(&self) -> Result<(), InstallationAuthorityKeyError> {
        #[cfg(windows)]
        {
            validate_signer_contour(&self.contour, &self.key_root, self.root_identity)?;
        }
        Ok(())
    }
}

/// Alias retained for composition code that calls this primitive a provider.
pub type WindowsInstallationAuthorityKeyProvider = WindowsInstallationAuthorityKeyStore;

struct SecretSeed([u8; 32]);

impl Drop for SecretSeed {
    fn drop(&mut self) {
        clear_secret(&mut self.0);
    }
}

struct SecretFileBytes([u8; INSTALLATION_AUTHORITY_KEY_FILE_BYTES]);

impl Drop for SecretFileBytes {
    fn drop(&mut self) {
        clear_secret(&mut self.0);
    }
}

struct SecretRandom([u8; 16]);

impl Drop for SecretRandom {
    fn drop(&mut self) {
        clear_secret(&mut self.0);
    }
}

fn clear_secret(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: every pointer is derived from a live mutable slice element;
        // volatile stores prevent the optimizer from eliding the wipe.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn validate_key_id(key_id: &str) -> Result<(), InstallationAuthorityKeyError> {
    if key_id.is_empty()
        || key_id.len() > INSTALLATION_AUTHORITY_KEY_ID_MAX_BYTES
        || !key_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || key_id.starts_with('-')
        || key_id.ends_with('-')
    {
        return Err(InstallationAuthorityKeyError::InvalidKeyId);
    }
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn map_windows_error(error: WindowsAdapterError) -> InstallationAuthorityKeyError {
    match error {
        WindowsAdapterError::PermissionDenied => InstallationAuthorityKeyError::PermissionDenied,
        WindowsAdapterError::AlreadyExists => InstallationAuthorityKeyError::AlreadyExists,
        WindowsAdapterError::IdentityMismatch => InstallationAuthorityKeyError::IdentityMismatch,
        WindowsAdapterError::AclMismatch => InstallationAuthorityKeyError::AclMismatch,
        WindowsAdapterError::NotFound | WindowsAdapterError::Unavailable => {
            InstallationAuthorityKeyError::MissingOrMalformed
        }
        WindowsAdapterError::InvalidInput => InstallationAuthorityKeyError::InvalidPath,
        WindowsAdapterError::Timeout | WindowsAdapterError::Failed => {
            InstallationAuthorityKeyError::Io
        }
    }
}

#[cfg(windows)]
fn fill_random(bytes: &mut [u8]) -> Result<(), InstallationAuthorityKeyError> {
    fill_system_random(bytes).map_err(|_| InstallationAuthorityKeyError::CryptographicFailure)
}

#[cfg(not(windows))]
fn fill_random(_bytes: &mut [u8]) -> Result<(), InstallationAuthorityKeyError> {
    Err(InstallationAuthorityKeyError::UnsupportedPlatform)
}

#[cfg(windows)]
fn validate_existing_key_root(path: &Path) -> Result<FileIdentity, InstallationAuthorityKeyError> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(InstallationAuthorityKeyError::InvalidPath);
    }
    let contour = protected_program_data_path("Eliot")
        .map_err(|_| InstallationAuthorityKeyError::InvalidPath)?;
    let expected = contour.join(Path::new(INSTALLATION_AUTHORITY_KEY_ROOT_RELATIVE));
    if !equivalent_windows_paths(path, &expected) || !path_within(path, &contour) {
        return Err(InstallationAuthorityKeyError::InvalidPath);
    }
    reject_reparse_chain(path)?;
    let directory = open_directory_no_follow(path)?;
    let canonical = final_windows_path_from_handle(&directory)
        .map_err(|_| InstallationAuthorityKeyError::IdentityMismatch)?;
    if !equivalent_windows_paths(&canonical, path) {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    let expected = OwnedSecurityDescriptor::for_installer_authority_key()
        .map_err(|_| InstallationAuthorityKeyError::AclMismatch)?;
    verify_exact_file_security(&directory, &expected, EXPECTED_OWNER_SID)
        .map_err(map_windows_error)?;
    file_identity_from_handle(&directory)
        .map_err(|_| InstallationAuthorityKeyError::IdentityMismatch)
}

#[cfg(not(windows))]
fn validate_existing_key_root(_path: &Path) -> Result<FileIdentity, InstallationAuthorityKeyError> {
    Err(InstallationAuthorityKeyError::UnsupportedPlatform)
}

#[cfg(windows)]
fn map_protected_path_error(error: ProtectedPathError) -> InstallationAuthorityKeyError {
    match error {
        ProtectedPathError::InvalidRoot => InstallationAuthorityKeyError::MissingRoot,
        ProtectedPathError::InvalidPath => InstallationAuthorityKeyError::InvalidPath,
        ProtectedPathError::ReparsePoint => InstallationAuthorityKeyError::ReparsePoint,
        ProtectedPathError::AclMismatch => InstallationAuthorityKeyError::AclMismatch,
        ProtectedPathError::Io | ProtectedPathError::SizeExceeded => {
            InstallationAuthorityKeyError::Io
        }
        ProtectedPathError::UnsupportedPlatform => {
            InstallationAuthorityKeyError::UnsupportedPlatform
        }
    }
}

#[cfg(windows)]
fn validate_signer_contour(
    contour: &ProtectedRootLease,
    key_root: &Path,
    root_identity: FileIdentity,
) -> Result<(), InstallationAuthorityKeyError> {
    let current_identity = validate_existing_key_root(key_root)?;
    if current_identity != root_identity {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    contour
        .verify_stable_identity()
        .map_err(map_protected_path_error)?;
    if contour.identity() != root_identity {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    let canonical = contour.canonical_path().map_err(map_protected_path_error)?;
    if !equivalent_windows_paths(&canonical, key_root) {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(windows)]
fn path_within(path: &Path, contour: &Path) -> bool {
    let path_components: Vec<_> = path.components().collect();
    let contour_components: Vec<_> = contour.components().collect();
    path_components.len() >= contour_components.len()
        && path_components
            .iter()
            .zip(contour_components.iter())
            .all(|(left, right)| {
                windows_paths_equal(Path::new(left.as_os_str()), Path::new(right.as_os_str()))
            })
}

#[cfg(windows)]
fn equivalent_windows_paths(left: &Path, right: &Path) -> bool {
    windows_paths_equal(left, right) || (path_within(left, right) && path_within(right, left))
}

#[cfg(windows)]
fn reject_reparse_chain(path: &Path) -> Result<(), InstallationAuthorityKeyError> {
    for ancestor in path.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                InstallationAuthorityKeyError::MissingRoot
            } else {
                InstallationAuthorityKeyError::Io
            }
        })?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) {
            return Err(InstallationAuthorityKeyError::ReparsePoint);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn open_directory_no_follow(path: &Path) -> Result<std::fs::File, InstallationAuthorityKeyError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let file = std::fs::OpenOptions::new()
        .read(true)
        // No FILE_SHARE_DELETE: the retained root identity must block rename,
        // replacement and deletion for the entire store lifetime.
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                InstallationAuthorityKeyError::MissingRoot
            } else if error.kind() == std::io::ErrorKind::PermissionDenied {
                InstallationAuthorityKeyError::PermissionDenied
            } else {
                InstallationAuthorityKeyError::Io
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|_| InstallationAuthorityKeyError::Io)?;
    if !metadata.is_dir() {
        return Err(InstallationAuthorityKeyError::InvalidPath);
    }
    if is_reparse_point(&metadata) {
        return Err(InstallationAuthorityKeyError::ReparsePoint);
    }
    Ok(file)
}

#[cfg(windows)]
fn ensure_single_link(file: &std::fs::File) -> Result<(), InstallationAuthorityKeyError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    let ok = unsafe {
        // SAFETY: file owns a live handle and the output points to initialized
        // storage of the exact documented structure.
        GetFileInformationByHandle(file.as_raw_handle().cast(), &raw mut information)
    };
    if ok == 0 {
        return Err(InstallationAuthorityKeyError::Io);
    }
    if information.nNumberOfLinks != 1 {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(windows)]
fn validate_live_slot(
    path: &Path,
    file: &std::fs::File,
    key_id: &str,
    expected_identity: Option<FileIdentity>,
) -> Result<FileIdentity, InstallationAuthorityKeyError> {
    let metadata = file
        .metadata()
        .map_err(|_| InstallationAuthorityKeyError::Io)?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(InstallationAuthorityKeyError::ReparsePoint);
    }
    if usize::try_from(metadata.len()).map_err(|_| InstallationAuthorityKeyError::Io)?
        != INSTALLATION_AUTHORITY_KEY_FILE_BYTES
    {
        return Err(InstallationAuthorityKeyError::MissingOrMalformed);
    }
    let expected_name = format!("{key_id}{KEY_FILE_EXTENSION}");
    if path
        .file_name()
        .is_none_or(|name| name != std::ffi::OsStr::new(&expected_name))
    {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    let canonical = final_windows_path_from_handle(file)
        .map_err(|_| InstallationAuthorityKeyError::IdentityMismatch)?;
    if !equivalent_windows_paths(&canonical, path) {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    let identity = file_identity_from_handle(file)
        .map_err(|_| InstallationAuthorityKeyError::IdentityMismatch)?;
    if expected_identity.is_some_and(|expected| expected != identity) {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    ensure_single_link(file)?;
    let descriptor = OwnedSecurityDescriptor::for_installer_authority_key()
        .map_err(|_| InstallationAuthorityKeyError::AclMismatch)?;
    verify_exact_file_security(file, &descriptor, EXPECTED_OWNER_SID).map_err(map_windows_error)?;
    Ok(identity)
}

#[cfg(windows)]
fn validate_signer_slot(
    signer: &InstallationAuthorityKeySigner,
) -> Result<(), InstallationAuthorityKeyError> {
    let identity = validate_live_slot(
        &signer.metadata.slot_path,
        &signer.slot_handle,
        &signer.metadata.key_id,
        Some(signer.metadata.file_identity),
    )?;
    if identity != signer.metadata.file_identity {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(windows)]
fn signing_error(error: InstallationAuthorityKeyError) -> InstallationActivationError {
    InstallationActivationError::InvalidField {
        field: "installation_authority_key.contour".to_owned(),
        reason: error.to_string(),
    }
}

#[cfg(windows)]
fn flush_parent_directory(path: &Path) {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    if let Ok(directory) = options.open(path)
        && directory.metadata().is_ok_and(|metadata| {
            metadata.is_dir() && {
                use std::os::windows::fs::MetadataExt;
                metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
            }
        })
    {
        // Directory flush is not supported by every Windows filesystem.  The
        // file flush remains mandatory; this best-effort metadata flush is used
        // whenever the filesystem accepts it and never invents a destructive
        // recovery path after CREATE_NEW has committed.
        let _ = directory.sync_all();
    }
}

#[cfg(windows)]
fn create_new_slot(path: &Path) -> Result<std::fs::File, InstallationAuthorityKeyError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_HIDDEN, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
    };

    let descriptor = OwnedSecurityDescriptor::for_installer_authority_key()
        .map_err(|_| InstallationAuthorityKeyError::AclMismatch)?;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| InstallationAuthorityKeyError::Io)?,
        lpSecurityDescriptor: descriptor.raw.cast(),
        bInheritHandle: 0,
    };
    let handle = unsafe {
        // SAFETY: path is a NUL-terminated UTF-16 buffer, the descriptor and
        // attributes live through the synchronous CreateFileW call, and the
        // access/share flags intentionally omit FILE_SHARE_WRITE and
        // FILE_SHARE_DELETE while the immutable slot is being published.
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        return Err(if code == ERROR_ALREADY_EXISTS {
            InstallationAuthorityKeyError::AlreadyExists
        } else if code == ERROR_ACCESS_DENIED {
            InstallationAuthorityKeyError::PermissionDenied
        } else {
            map_windows_error(WindowsAdapterError::Failed)
        });
    }
    let file = OwnedKernelHandle::new(handle)
        .map_err(map_windows_error)
        .map(OwnedKernelHandle::into_file)?;
    ensure_single_link(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn reopen_slot(path: &Path) -> Result<std::fs::File, InstallationAuthorityKeyError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, GetLastError,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ,
        OPEN_EXISTING,
    };
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let handle = unsafe {
        // SAFETY: path is a live NUL-terminated UTF-16 buffer and all flags
        // explicitly request a no-follow regular-file handle with no write or
        // delete sharing.
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        return Err(
            if code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND {
                InstallationAuthorityKeyError::MissingOrMalformed
            } else if code == windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED {
                InstallationAuthorityKeyError::PermissionDenied
            } else {
                InstallationAuthorityKeyError::Io
            },
        );
    }
    let file = OwnedKernelHandle::new(handle)
        .map_err(map_windows_error)
        .map(OwnedKernelHandle::into_file)?;
    ensure_single_link(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn write_new_slot(
    file: &std::fs::File,
    seed: &[u8; 32],
) -> Result<(), InstallationAuthorityKeyError> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
    let mut bytes = SecretFileBytes([0_u8; INSTALLATION_AUTHORITY_KEY_FILE_BYTES]);
    bytes.0[..INSTALLATION_AUTHORITY_KEY_MAGIC.len()]
        .copy_from_slice(&INSTALLATION_AUTHORITY_KEY_MAGIC);
    bytes.0[8..12].copy_from_slice(&INSTALLATION_AUTHORITY_KEY_FILE_VERSION.to_le_bytes());
    // bytes[12..16] are reserved and must stay zero.
    bytes.0[16..].copy_from_slice(seed);
    let mut writer = file;
    writer
        .seek(SeekFrom::Start(0))
        .map_err(|_| InstallationAuthorityKeyError::Io)?;
    writer
        .write_all(&bytes.0)
        .map_err(|_| InstallationAuthorityKeyError::Io)?;
    if unsafe {
        // SAFETY: the handle is live and uniquely owned by `file`.
        FlushFileBuffers(writer.as_raw_handle().cast())
    } == 0
    {
        return Err(InstallationAuthorityKeyError::Io);
    }
    Ok(())
}

#[cfg(windows)]
fn build_signer(
    path: &Path,
    mut file: std::fs::File,
    key_id: &str,
    expected: Option<&InstallationAuthorityKeyExpectation>,
    contour: Arc<ProtectedRootLease>,
    root_identity: FileIdentity,
) -> Result<InstallationAuthorityKeySigner, InstallationAuthorityKeyError> {
    let identity = validate_live_slot(
        path,
        &file,
        key_id,
        expected.map(|expected| expected.file_identity),
    )?;
    if let Some(expected) = expected
        && expected.file_identity != identity
    {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }

    file.seek(SeekFrom::Start(0))
        .map_err(|_| InstallationAuthorityKeyError::Io)?;
    let mut encoded = SecretFileBytes([0_u8; INSTALLATION_AUTHORITY_KEY_FILE_BYTES]);
    file.read_exact(&mut encoded.0)
        .map_err(|_| InstallationAuthorityKeyError::MissingOrMalformed)?;
    let mut extra = [0_u8; 1];
    if file
        .read(&mut extra)
        .map_err(|_| InstallationAuthorityKeyError::Io)?
        != 0
    {
        return Err(InstallationAuthorityKeyError::MissingOrMalformed);
    }
    if encoded.0[..INSTALLATION_AUTHORITY_KEY_MAGIC.len()] != INSTALLATION_AUTHORITY_KEY_MAGIC
        || u32::from_le_bytes(encoded.0[8..12].try_into().unwrap_or_default())
            != INSTALLATION_AUTHORITY_KEY_FILE_VERSION
        || encoded.0[12..16] != [0_u8; 4]
    {
        return Err(InstallationAuthorityKeyError::MissingOrMalformed);
    }
    let mut seed = SecretSeed([0_u8; 32]);
    seed.0.copy_from_slice(&encoded.0[16..]);
    if seed.0.iter().all(|byte| *byte == 0) {
        return Err(InstallationAuthorityKeyError::MissingOrMalformed);
    }
    let signer = Ed25519InstallationActivationApprovalSigner::from_secret_key(
        INSTALLATION_AUTHORITY_SIGNER_ID,
        key_id,
        seed.0,
    )
    .map_err(|_| InstallationAuthorityKeyError::CryptographicFailure)?;
    let public_key = signer.public_key().to_vec();
    let public_key_fingerprint = sha256_hex(&public_key);
    if let Some(expected) = expected
        && expected.public_key_fingerprint != public_key_fingerprint
    {
        return Err(InstallationAuthorityKeyError::IdentityMismatch);
    }
    Ok(InstallationAuthorityKeySigner {
        metadata: InstallationAuthorityKeyMetadata {
            key_id: key_id.to_owned(),
            public_key,
            public_key_fingerprint,
            slot_path: path.to_owned(),
            file_identity: identity,
        },
        signer,
        slot_handle: file,
        contour,
        root_identity,
    })
}

#[cfg(windows)]
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(not(windows))]
fn sha256_hex(_bytes: &[u8]) -> String {
    String::new()
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        use fmt::Write as _;
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_id_validation_is_path_safe_and_bounded() {
        assert!(validate_key_id("key-0123456789abcdef").is_ok());
        assert!(validate_key_id("").is_err());
        assert!(validate_key_id("../seed").is_err());
        assert!(validate_key_id("Key-ABC").is_err());
        assert!(validate_key_id(&"a".repeat(INSTALLATION_AUTHORITY_KEY_ID_MAX_BYTES + 1)).is_err());
    }

    #[test]
    fn key_file_format_is_fixed_and_versioned() {
        assert_eq!(INSTALLATION_AUTHORITY_KEY_FILE_BYTES, 48);
        assert_eq!(INSTALLATION_AUTHORITY_KEY_MAGIC, *b"ELIOTAK1");
        assert_eq!(INSTALLATION_AUTHORITY_KEY_FILE_VERSION, 1);
    }

    #[test]
    fn temporary_secret_buffers_are_explicitly_wiped() {
        let mut random = SecretRandom([0xa5_u8; 16]);
        let mut seed = SecretSeed([0xa5_u8; 32]);
        let mut encoded = SecretFileBytes([0xa5_u8; INSTALLATION_AUTHORITY_KEY_FILE_BYTES]);
        clear_secret(&mut random.0);
        clear_secret(&mut seed.0);
        clear_secret(&mut encoded.0);
        assert!(random.0.iter().all(|byte| *byte == 0));
        assert!(seed.0.iter().all(|byte| *byte == 0));
        assert!(encoded.0.iter().all(|byte| *byte == 0));
    }

    #[cfg(windows)]
    #[test]
    fn every_authority_contour_ancestor_reparse_is_rejected() {
        use std::os::windows::fs::MetadataExt;
        use std::process::Command;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

        for component in ["Eliot", "host", "authority-keys"] {
            let suffix = super::super::unique_suffix();
            let root =
                std::env::temp_dir().join(format!("eliot-authority-reparse-{component}-{suffix}"));
            let outside =
                std::env::temp_dir().join(format!("eliot-authority-reparse-outside-{suffix}"));
            std::fs::create_dir_all(&root).unwrap_or_else(|_| unreachable!());
            std::fs::create_dir_all(outside.join("authority-keys"))
                .unwrap_or_else(|_| unreachable!());
            std::fs::create_dir_all(outside.join("host/authority-keys"))
                .unwrap_or_else(|_| unreachable!());
            let victim = match component {
                "Eliot" => root.join("Eliot"),
                "host" => root.join("Eliot").join("host"),
                "authority-keys" => root.join("Eliot").join("host").join("authority-keys"),
                _ => unreachable!(),
            };
            if let Some(parent) = victim.parent() {
                std::fs::create_dir_all(parent).unwrap_or_else(|_| unreachable!());
            }
            let output = Command::new("cmd.exe")
                .args(["/D", "/C", "mklink", "/J"])
                .arg(&victim)
                .arg(&outside)
                .output()
                .unwrap_or_else(|_| unreachable!());
            assert!(
                output.status.success(),
                "mklink /J was not exercised for {component} (victim={victim:?}, target={outside:?}): stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let metadata = std::fs::symlink_metadata(&victim).unwrap_or_else(|_| unreachable!());
            assert_ne!(
                metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
                0,
                "junction fixture did not produce a reparse point"
            );
            let path = root.join("Eliot").join("host").join("authority-keys");
            assert_eq!(
                reject_reparse_chain(&path),
                Err(InstallationAuthorityKeyError::ReparsePoint),
                "ancestor {component} was not rejected for {path:?}"
            );
            std::fs::remove_dir(&victim).unwrap_or_else(|_| unreachable!());
            let _ = std::fs::remove_dir_all(&root);
            let _ = std::fs::remove_dir_all(&outside);
        }
    }

    #[cfg(windows)]
    #[test]
    fn hardlink_alias_is_rejected_by_single_link_guard() {
        let root = std::env::temp_dir().join(format!(
            "eliot-authority-hardlink-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir_all(&root).unwrap_or_else(|_| unreachable!());
        let path = root.join("key-hardlink.key");
        let alias = root.join("key-hardlink-alias.key");
        std::fs::write(&path, [0_u8; INSTALLATION_AUTHORITY_KEY_FILE_BYTES])
            .unwrap_or_else(|_| unreachable!());
        std::fs::hard_link(&path, &alias).unwrap_or_else(|_| unreachable!());
        let file = std::fs::File::open(&path).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            ensure_single_link(&file),
            Err(InstallationAuthorityKeyError::IdentityMismatch)
        );
        drop(file);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn malformed_partial_slot_is_terminal_and_not_adopted() {
        let root = std::env::temp_dir().join(format!(
            "eliot-authority-partial-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir_all(&root).unwrap_or_else(|_| unreachable!());
        let path = root.join("key-crash.key");
        std::fs::File::create(&path).unwrap_or_else(|_| unreachable!());
        let file = reopen_slot(&path).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            validate_live_slot(&path, &file, "key-crash", None),
            Err(InstallationAuthorityKeyError::MissingOrMalformed)
        );
        drop(file);
        assert!(
            path.exists(),
            "partial state must remain classified, not deleted"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn wrong_identity_and_default_acl_are_fail_closed() {
        let root = std::env::temp_dir().join(format!(
            "eliot-authority-identity-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir_all(&root).unwrap_or_else(|_| unreachable!());
        let path = root.join("key-identity.key");
        let other = root.join("other.key");
        std::fs::write(&path, [0_u8; INSTALLATION_AUTHORITY_KEY_FILE_BYTES])
            .unwrap_or_else(|_| unreachable!());
        std::fs::write(&other, [0_u8; INSTALLATION_AUTHORITY_KEY_FILE_BYTES])
            .unwrap_or_else(|_| unreachable!());
        let file = reopen_slot(&path).unwrap_or_else(|_| unreachable!());
        let other_file = reopen_slot(&other).unwrap_or_else(|_| unreachable!());
        let other_identity =
            file_identity_from_handle(&other_file).unwrap_or_else(|_| unreachable!());
        assert_eq!(
            validate_live_slot(&path, &file, "key-identity", Some(other_identity)),
            Err(InstallationAuthorityKeyError::IdentityMismatch)
        );
        assert!(matches!(
            validate_live_slot(&path, &file, "key-identity", None),
            Err(InstallationAuthorityKeyError::AclMismatch
                | InstallationAuthorityKeyError::IdentityMismatch)
        ));
        drop(other_file);
        drop(file);
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn signer_debug_does_not_contain_seed() {
        let secret = [0xa5_u8; 32];
        let inner = Ed25519InstallationActivationApprovalSigner::from_secret_key(
            INSTALLATION_AUTHORITY_SIGNER_ID,
            "key-debug",
            secret,
        )
        .unwrap_or_else(|_| unreachable!());
        let public_key = inner.public_key().to_vec();
        let metadata = InstallationAuthorityKeyMetadata {
            key_id: "key-debug".to_owned(),
            public_key: public_key.clone(),
            public_key_fingerprint: sha256_hex(&public_key),
            slot_path: PathBuf::from(r"C:\ProgramData\Eliot\authority.key"),
            file_identity: FileIdentity {
                volume_serial_number: 1,
                file_index: 2,
            },
        };
        let suffix = super::super::unique_suffix();
        let path = std::env::temp_dir().join(format!("eliot-authority-debug-{suffix}"));
        let slot = std::fs::File::create(&path).unwrap_or_else(|_| unreachable!());
        let contour_root =
            std::env::temp_dir().join(format!("eliot-authority-debug-contour-{suffix}"));
        std::fs::create_dir_all(&contour_root).unwrap_or_else(|_| unreachable!());
        let directories =
            vec![super::super::pin_directory(&contour_root).unwrap_or_else(|_| unreachable!())];
        let root_identity = super::super::file_identity_from_handle(
            directories.last().unwrap_or_else(|| unreachable!()),
        )
        .unwrap_or_else(|_| unreachable!());
        let signer = InstallationAuthorityKeySigner {
            metadata,
            signer: inner,
            slot_handle: slot,
            contour: Arc::new(ProtectedRootLease {
                path: contour_root.clone(),
                identity: root_identity,
                directories,
            }),
            root_identity,
        };
        let debug = format!("{signer:?}");
        let secret_hex = hex_lower(&secret);
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains(&secret_hex));
        let metadata_json = serde_json::to_string(signer.metadata()).unwrap_or_default();
        assert!(!metadata_json.contains(&secret_hex));
        drop(signer);
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_dir_all(contour_root);
    }
}
