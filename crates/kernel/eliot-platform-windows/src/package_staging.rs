//! Immutable side-by-side package staging primitives for Windows.
//!
//! This module is deliberately a measurement/mutation seam.  It retains the
//! source and destination contours, creates a generation and its files with
//! create-only semantics, and returns a receipt bound to handle identities and
//! byte/security observations.  It does not own installation transactions,
//! authority, activation, rollback policy, or durable state.

use std::cmp::Ordering;
#[cfg(windows)]
use std::collections::HashSet;
use std::fmt;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{FileIdentity, ProtectedPathError};

/// Maximum number of manifest files accepted by one bounded staging call.
pub const MAX_PACKAGE_FILES: usize = 4096;
/// Maximum relative path depth accepted by one package.
pub const MAX_PACKAGE_PATH_DEPTH: usize = 32;
/// Maximum source/destination file size accepted by the default stager.
pub const MAX_PACKAGE_FILE_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum aggregate bytes copied by one default stager call.
pub const MAX_PACKAGE_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// Maximum PE header prefix inspected by the pure parser.
pub const MAX_PE_HEADER_BYTES: usize = 1024 * 1024;
const COPY_BUFFER_BYTES: usize = 64 * 1024;
/// Maximum number of files plus directories walked from one source root.
pub const MAX_ENUMERATED_ENTRIES: usize = MAX_PACKAGE_FILES * 2 + MAX_PACKAGE_PATH_DEPTH;

/// A validated relative package path using `/` as its canonical separator.
///
/// The constructor rejects absolute, UNC, device, NT and verbatim forms;
/// colon/ADS syntax; empty, dot and parent components; and Windows-invalid
/// trailing dots or spaces.  Comparison of components uses Windows ordinal
/// case-insensitive semantics on Windows.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRelativePath {
    canonical: String,
    components: Vec<String>,
}

impl PackageRelativePath {
    /// Returns the canonical slash-separated path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Returns the validated path components.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    fn join_to(&self, root: &Path) -> PathBuf {
        self.components
            .iter()
            .fold(root.to_path_buf(), |mut path, component| {
                path.push(component);
                path
            })
    }
}

/// Validate one package-relative path and return its canonical representation.
///
/// # Errors
///
/// Returns [`PackageStagingError::InvalidRelativePath`] for any absolute,
/// device, ADS, dot, parent, empty or trailing-dot/space form.
pub fn validate_package_relative_path(
    path: &Path,
) -> Result<PackageRelativePath, PackageStagingError> {
    let raw = path
        .to_str()
        .ok_or(PackageStagingError::InvalidRelativePath)?;
    validate_relative_text(raw)
}

fn validate_relative_text(raw: &str) -> Result<PackageRelativePath, PackageStagingError> {
    if raw.is_empty()
        || raw.contains('\0')
        || raw.starts_with('/')
        || raw.starts_with('\\')
        || raw.starts_with("//")
        || raw.starts_with("\\\\")
    {
        return Err(PackageStagingError::InvalidRelativePath);
    }
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("\\?\\")
        || lower.starts_with("//?/")
        || lower.starts_with("\\.\\")
        || lower.starts_with("//./")
        || lower.starts_with("\\??\\")
        || lower.starts_with("/??/")
        || lower.starts_with("nt\\")
        || lower.starts_with("nt/")
    {
        return Err(PackageStagingError::InvalidRelativePath);
    }

    let mut components = Vec::new();
    for component in raw.split(['/', '\\']) {
        if component.is_empty()
            || component == "."
            || component == ".."
            || component.contains(':')
            || component.chars().any(char::is_control)
            || component.ends_with('.')
            || component.ends_with(' ')
            || is_windows_device_name(component)
        {
            return Err(PackageStagingError::InvalidRelativePath);
        }
        components.push(component.to_owned());
        if components.len() > MAX_PACKAGE_PATH_DEPTH {
            return Err(PackageStagingError::BoundExceeded);
        }
    }
    if components.is_empty() {
        return Err(PackageStagingError::InvalidRelativePath);
    }

    Ok(PackageRelativePath {
        canonical: components.join("/"),
        components,
    })
}

/// Return whether a path component names a DOS device rather than a regular
/// filesystem entry.  Windows applies these names even when an extension is
/// present (for example, `NUL.txt`), so the comparison uses the text before
/// the first dot.
fn is_windows_device_name(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    let upper = stem.to_ascii_uppercase();
    matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CLOCK$"
            | "COM¹"
            | "COM²"
            | "COM³"
            | "LPT¹"
            | "LPT²"
            | "LPT³"
    ) || (upper.len() == 4
        && (upper.starts_with("COM") || upper.starts_with("LPT"))
        && upper.as_bytes()[3].is_ascii_digit()
        && upper.as_bytes()[3] != b'0')
}

pub fn ordinal_component_cmp(left: &str, right: &str) -> Ordering {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Globalization::{CSTR_EQUAL, CSTR_LESS_THAN, CompareStringOrdinal};

        let left: Vec<u16> = std::ffi::OsStr::new(left).encode_wide().collect();
        let right: Vec<u16> = std::ffi::OsStr::new(right).encode_wide().collect();
        let Ok(left_len) = i32::try_from(left.len()) else {
            return Ordering::Greater;
        };
        let Ok(right_len) = i32::try_from(right.len()) else {
            return Ordering::Less;
        };
        let result =
            unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) };
        match result {
            CSTR_LESS_THAN => Ordering::Less,
            CSTR_EQUAL => Ordering::Equal,
            _ => Ordering::Greater,
        }
    }
    #[cfg(not(windows))]
    {
        left.to_lowercase().cmp(&right.to_lowercase())
    }
}

pub fn ordinal_path_cmp(left: &PackageRelativePath, right: &PackageRelativePath) -> Ordering {
    left.components
        .iter()
        .zip(&right.components)
        .map(|(left, right)| ordinal_component_cmp(left, right))
        .find(|ordering| *ordering != Ordering::Equal)
        .unwrap_or_else(|| left.components.len().cmp(&right.components.len()))
}

pub fn ordinal_path_eq(left: &PackageRelativePath, right: &PackageRelativePath) -> bool {
    left.components.len() == right.components.len()
        && left
            .components
            .iter()
            .zip(&right.components)
            .all(|(left, right)| ordinal_component_cmp(left, right) == Ordering::Equal)
}

pub fn ordinal_cmp_str(a: &str, b: &str) -> Ordering {
    let left = validate_relative_text(a);
    let right = validate_relative_text(b);
    match (left, right) {
        (Ok(l), Ok(r)) => ordinal_path_cmp(&l, &r),
        _ => a.to_lowercase().cmp(&b.to_lowercase()),
    }
}

pub fn ordinal_eq_str(a: &str, b: &str) -> bool {
    ordinal_cmp_str(a, b) == Ordering::Equal
}

/// One manifest file admitted to a package stage.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFileSpec {
    /// Canonical slash-separated relative path.
    pub relative_path: String,
    /// Whether the file must parse as an AMD64 PE/COFF executable and pass
    /// the Authenticode gate.
    pub executable: bool,
    /// Explicit per-file byte bound.
    pub max_size: u64,
}

impl PackageFileSpec {
    /// Build one file specification after validating its path and size bound.
    ///
    /// # Errors
    ///
    /// Returns an error when the path or byte bound is invalid.
    pub fn new(
        relative_path: impl AsRef<Path>,
        executable: bool,
        max_size: u64,
    ) -> Result<Self, PackageStagingError> {
        let relative_path = validate_package_relative_path(relative_path.as_ref())?;
        if max_size == 0 || max_size > MAX_PACKAGE_FILE_BYTES {
            return Err(PackageStagingError::BoundExceeded);
        }
        Ok(Self {
            relative_path: relative_path.canonical,
            executable,
            max_size,
        })
    }
}

/// Canonical package manifest supplied by the installation coordinator.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageManifest {
    /// Relative generation root below the retained installation root.
    pub generation: String,
    /// Exact files expected under the generation root.
    pub files: Vec<PackageFileSpec>,
}

impl PackageManifest {
    /// Build and validate a manifest.  File order is not authority: canonical
    /// bytes sort paths with Windows ordinal component semantics.
    ///
    /// # Errors
    ///
    /// Returns an error when generation or file paths are invalid, duplicate,
    /// or exceed the bounded manifest limits.
    pub fn new(
        generation: impl AsRef<Path>,
        files: Vec<PackageFileSpec>,
    ) -> Result<Self, PackageStagingError> {
        let generation = validate_package_relative_path(generation.as_ref())?;
        let manifest = Self {
            generation: generation.canonical,
            files,
        };
        manifest.validate()
    }

    fn validate(&self) -> Result<Self, PackageStagingError> {
        if self.files.len() > MAX_PACKAGE_FILES {
            return Err(PackageStagingError::BoundExceeded);
        }
        let generation = validate_relative_text(&self.generation)?;
        let mut files = Vec::with_capacity(self.files.len());
        for file in &self.files {
            let path = validate_relative_text(&file.relative_path)?;
            if file.max_size == 0 || file.max_size > MAX_PACKAGE_FILE_BYTES {
                return Err(PackageStagingError::BoundExceeded);
            }
            files.push((path, file));
        }
        files.sort_by(|left, right| ordinal_path_cmp(&left.0, &right.0));
        for pair in files.windows(2) {
            if ordinal_path_eq(&pair[0].0, &pair[1].0) {
                return Err(PackageStagingError::ManifestCollision);
            }
        }
        let files = files
            .into_iter()
            .map(|(path, file)| PackageFileSpec {
                relative_path: path.canonical,
                executable: file.executable,
                max_size: file.max_size,
            })
            .collect();
        Ok(Self {
            generation: generation.canonical,
            files,
        })
    }

    /// Return stable canonical bytes for receipt binding.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let validated = self.validate().unwrap_or_else(|_| self.clone());
        let mut bytes = b"ELIOT-PACKAGE-MANIFEST\0v1\0".to_vec();
        append_text(&mut bytes, &validated.generation);
        append_u64(&mut bytes, validated.files.len() as u64);
        for file in validated.files {
            append_text(&mut bytes, &file.relative_path);
            bytes.push(u8::from(file.executable));
            append_u64(&mut bytes, file.max_size);
        }
        bytes
    }

    /// Return the lowercase SHA-256 digest of [`Self::canonical_bytes`].
    #[must_use]
    pub fn canonical_digest(&self) -> String {
        hex_digest(&self.canonical_bytes())
    }
}

fn append_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn append_text(bytes: &mut Vec<u8>, value: &str) {
    append_u64(bytes, value.len() as u64);
    bytes.extend_from_slice(value.as_bytes());
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Pure bounded PE/COFF evidence.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeCoffEvidence {
    /// COFF machine value.
    pub machine: u16,
    /// Optional-header magic (`0x20b` for PE32+).
    pub optional_header_magic: u16,
    /// COFF characteristics.
    pub characteristics: u16,
    /// Number of section headers.
    pub sections: u16,
    /// Whether the optional header is PE32+.
    pub pe32_plus: bool,
}

/// Pure parser failures.  No Windows loader or shell is involved.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PeCoffError {
    /// Input exceeded the parser's explicit bound.
    SizeExceeded,
    /// Required DOS/PE/COFF bytes were absent.
    Truncated,
    /// DOS or PE signature was invalid.
    InvalidSignature,
    /// The image is not a PE32+ AMD64 image.
    WrongArchitecture,
    /// Header values would overflow or exceed the bounded input.
    InvalidHeader,
}

impl fmt::Display for PeCoffError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SizeExceeded => "PE/COFF parser input exceeds bound",
            Self::Truncated => "PE/COFF header is truncated",
            Self::InvalidSignature => "PE/COFF signature is invalid",
            Self::WrongArchitecture => "PE/COFF image is not AMD64 PE32+",
            Self::InvalidHeader => "PE/COFF header is invalid",
        })
    }
}

impl std::error::Error for PeCoffError {}

/// Parse a bounded PE/COFF header and require AMD64 PE32+ architecture.
///
/// The parser does not map, load or execute the image.  It only reads bounded
/// integer fields and validates the section-table contour.
///
/// # Errors
///
/// Returns [`PeCoffError`] when the input is over the parser bound, truncated,
/// malformed or not an AMD64 PE32+ executable.
pub fn parse_pe_coff(bytes: &[u8]) -> Result<PeCoffEvidence, PeCoffError> {
    if bytes.len() > MAX_PE_HEADER_BYTES {
        return Err(PeCoffError::SizeExceeded);
    }
    if bytes.len() < 0x40 {
        return Err(PeCoffError::Truncated);
    }
    if &bytes[..2] != b"MZ" {
        return Err(PeCoffError::InvalidSignature);
    }
    let pe_offset = read_u32(bytes, 0x3c).ok_or(PeCoffError::Truncated)? as usize;
    let signature_end = pe_offset.checked_add(4).ok_or(PeCoffError::InvalidHeader)?;
    if signature_end > bytes.len() {
        return Err(PeCoffError::Truncated);
    }
    if &bytes[pe_offset..signature_end] != b"PE\0\0" {
        return Err(PeCoffError::InvalidSignature);
    }
    let coff = signature_end;
    let machine = read_u16(bytes, coff).ok_or(PeCoffError::Truncated)?;
    let sections = read_u16(bytes, coff + 2).ok_or(PeCoffError::Truncated)?;
    let optional_size = read_u16(bytes, coff + 16).ok_or(PeCoffError::Truncated)? as usize;
    if sections == 0 || sections > 96 {
        return Err(PeCoffError::InvalidHeader);
    }
    let optional = coff.checked_add(20).ok_or(PeCoffError::InvalidHeader)?;
    let optional_end = optional
        .checked_add(optional_size)
        .ok_or(PeCoffError::InvalidHeader)?;
    if optional_end > bytes.len() || optional_size < 0x70 {
        return Err(PeCoffError::Truncated);
    }
    let optional_header_magic = read_u16(bytes, optional).ok_or(PeCoffError::Truncated)?;
    if machine != 0x8664 || optional_header_magic != 0x20b {
        return Err(PeCoffError::WrongArchitecture);
    }
    let section_table_bytes = usize::from(sections)
        .checked_mul(40)
        .ok_or(PeCoffError::InvalidHeader)?;
    let section_end = optional_end
        .checked_add(section_table_bytes)
        .ok_or(PeCoffError::InvalidHeader)?;
    if section_end > bytes.len() {
        return Err(PeCoffError::Truncated);
    }
    let characteristics = read_u16(bytes, coff + 18).ok_or(PeCoffError::Truncated)?;
    if characteristics & 0x0002 == 0 {
        return Err(PeCoffError::InvalidHeader);
    }
    Ok(PeCoffEvidence {
        machine,
        optional_header_magic,
        characteristics,
        sections,
        pe32_plus: true,
    })
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset.checked_add(2)?)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset.checked_add(4)?)
        .map(|bytes| u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// Authenticode provider verdict for one executable entry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthenticodeVerdict {
    /// `WinTrust` accepted the whole-chain policy and a primary signer was
    /// observed.
    Valid,
    /// The provider explicitly reported that no signature exists.
    Unsigned,
    /// The provider could not establish revocation status (for example an
    /// offline-only revocation check).  This is deliberately not equivalent
    /// to a valid chain and is rejected by the `SystemService` stage.
    RevocationUnknown,
    /// The provider could not classify the signature or chain.
    Unknown,
    /// The signature or evidence was malformed or rejected.
    Invalid,
}

/// Typed evidence returned by the official `WinTrust` seam.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthenticodeEvidence {
    /// Provider verdict.
    pub verdict: AuthenticodeVerdict,
    /// Leaf signer certificate SHA-256, when the provider exposed it.
    pub signer_certificate_sha256: Option<String>,
    /// Leaf signer simple display subject, when exposed.
    pub signer_subject: Option<String>,
    /// Leaf certificate validity start, when exposed, as Unix seconds.
    pub signer_not_before_unix_seconds: Option<i64>,
    /// Leaf certificate validity end, when exposed, as Unix seconds.
    pub signer_not_after_unix_seconds: Option<i64>,
    /// `WinTrust`'s verified-as-of time, when exposed, as Unix seconds.
    pub verification_time_unix_seconds: Option<i64>,
    /// Primary countersigner certificate SHA-256, when exposed.
    pub countersigner_certificate_sha256: Option<String>,
    /// Raw `WinTrust` status (`0` only means accepted).
    pub trust_status: u32,
}

/// Fail-closed Authenticode errors.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthenticodeError {
    /// The target path or expected digest/identity was invalid.
    InvalidInput,
    /// The target could not be opened safely.
    NotFound,
    /// The target was not a regular non-reparse file.
    InvalidFile,
    /// The handle-bound file bytes differ from the expected digest.
    DigestMismatch,
    /// The handle-bound identity changed during verification.
    IdentityMismatch,
    /// `WinTrust` could not expose a primary signer.
    SignerUnavailable,
    /// State cleanup after `WinTrust` was indeterminate.
    ProviderCleanupFailure,
    /// Authenticode is intentionally unavailable off Windows.
    UnsupportedPlatform,
}

impl fmt::Display for AuthenticodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "invalid Authenticode input",
            Self::NotFound => "Authenticode target could not be opened",
            Self::InvalidFile => "Authenticode target is not a regular file",
            Self::DigestMismatch => "Authenticode target digest changed",
            Self::IdentityMismatch => "Authenticode target identity changed",
            Self::SignerUnavailable => "WinTrust returned no primary signer",
            Self::ProviderCleanupFailure => "WinTrust state cleanup failed",
            Self::UnsupportedPlatform => "Authenticode requires Windows",
        })
    }
}

impl std::error::Error for AuthenticodeError {}

mod authenticode_sealed {
    pub trait Sealed {}
}

/// Narrow Authenticode injection seam.
///
/// The trait is sealed so production callers cannot replace the official
/// verifier with a shell, ad-hoc certificate parser or permissive test double.
/// Unit tests inside this crate may use a private implementation to exercise
/// staging failure/replay paths.
pub trait AuthenticodeVerifier: authenticode_sealed::Sealed + Send + Sync {
    /// Verify one handle-bound executable path and return typed evidence.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the handle, identity, digest, provider state
    /// or platform cannot be verified safely.
    fn verify(
        &self,
        path: &Path,
        identity: FileIdentity,
        sha256: &str,
    ) -> Result<AuthenticodeEvidence, AuthenticodeError>;
}

/// Official Windows WinTrust-backed verifier.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsAuthenticodeVerifier;

impl authenticode_sealed::Sealed for WindowsAuthenticodeVerifier {}

impl AuthenticodeVerifier for WindowsAuthenticodeVerifier {
    fn verify(
        &self,
        path: &Path,
        identity: FileIdentity,
        sha256: &str,
    ) -> Result<AuthenticodeEvidence, AuthenticodeError> {
        verify_authenticode_platform(path, identity, sha256)
    }
}

#[cfg(not(windows))]
fn verify_authenticode_platform(
    _path: &Path,
    _identity: FileIdentity,
    _sha256: &str,
) -> Result<AuthenticodeEvidence, AuthenticodeError> {
    Err(AuthenticodeError::UnsupportedPlatform)
}

#[cfg(windows)]
fn verify_authenticode_platform(
    path: &Path,
    expected_identity: FileIdentity,
    expected_sha256: &str,
) -> Result<AuthenticodeEvidence, AuthenticodeError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    if !path.is_absolute() || !super::valid_sha256_hex(expected_sha256) {
        return Err(AuthenticodeError::InvalidInput);
    }
    let mut file = std::fs::OpenOptions::new();
    file.read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = file.open(path).map_err(|_| AuthenticodeError::NotFound)?;
    let metadata = file
        .metadata()
        .map_err(|_| AuthenticodeError::InvalidFile)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(AuthenticodeError::InvalidFile);
    }
    let identity =
        super::file_identity_from_handle(&file).map_err(|_| AuthenticodeError::InvalidFile)?;
    if identity != expected_identity {
        return Err(AuthenticodeError::IdentityMismatch);
    }
    let observed_sha256 = hash_file(&mut file)?;
    if observed_sha256 != expected_sha256 {
        return Err(AuthenticodeError::DigestMismatch);
    }
    let canonical_path =
        super::final_windows_path_from_handle(&file).map_err(|_| AuthenticodeError::InvalidFile)?;
    if !super::windows_paths_equal(&canonical_path, path) {
        return Err(AuthenticodeError::IdentityMismatch);
    }
    verify_signature(&canonical_path, &file)
}

#[cfg(windows)]
fn hash_file(file: &mut std::fs::File) -> Result<String, AuthenticodeError> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AuthenticodeError::InvalidFile)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| AuthenticodeError::InvalidFile)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex_digest(&digest.finalize()))
}

#[cfg(windows)]
fn verify_signature(
    path: &Path,
    file: &std::fs::File,
) -> Result<AuthenticodeEvidence, AuthenticodeError> {
    use std::os::windows::ffi::OsStrExt as _;
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::HWND;
    use windows_sys::Win32::Security::WinTrust::{
        WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_FILE_INFO,
        WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN,
        WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
        WinVerifyTrustEx,
    };

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: u32::try_from(std::mem::size_of::<WINTRUST_FILE_INFO>())
            .map_err(|_| AuthenticodeError::InvalidInput)?,
        pcwszFilePath: wide_path.as_ptr(),
        hFile: file.as_raw_handle().cast(),
        ..WINTRUST_FILE_INFO::default()
    };
    let mut trust_data = WINTRUST_DATA {
        cbStruct: u32::try_from(std::mem::size_of::<WINTRUST_DATA>())
            .map_err(|_| AuthenticodeError::InvalidInput)?,
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
        dwUnionChoice: WTD_CHOICE_FILE,
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: WTD_REVOCATION_CHECK_CHAIN | WTD_CACHE_ONLY_URL_RETRIEVAL,
        ..WINTRUST_DATA::default()
    };
    trust_data.Anonymous.pFile = &raw mut file_info;
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    let status = unsafe {
        // SAFETY: all structures and the NUL-terminated path remain live for
        // the synchronous WinTrust call; the union arm matches WTD_CHOICE_FILE.
        WinVerifyTrustEx(HWND::default(), &raw mut action, &raw mut trust_data)
    };
    let status_u32 = status.cast_unsigned();
    let evidence = if status == 0 {
        provider_evidence(trust_data.hWVTStateData).ok_or(AuthenticodeError::SignerUnavailable)
    } else {
        let verdict = classify_wintrust_status(status_u32);
        Ok(AuthenticodeEvidence {
            verdict,
            signer_certificate_sha256: None,
            signer_subject: None,
            signer_not_before_unix_seconds: None,
            signer_not_after_unix_seconds: None,
            verification_time_unix_seconds: None,
            countersigner_certificate_sha256: None,
            trust_status: status_u32,
        })
    };
    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    let close_status = unsafe {
        // SAFETY: this closes the provider state returned by VERIFY.
        WinVerifyTrustEx(HWND::default(), &raw mut action, &raw mut trust_data)
    };
    if close_status != 0 {
        return Err(AuthenticodeError::ProviderCleanupFailure);
    }
    match evidence {
        Ok(mut evidence) => {
            evidence.trust_status = status_u32;
            Ok(evidence)
        }
        Err(error) => Err(error),
    }
}

/// Map the documented WinTrust/chain status values into fail-closed typed
/// evidence.  The raw status remains in [`AuthenticodeEvidence`] so callers
/// can retain the exact provider reason without treating an unknown value as
/// success.
fn classify_wintrust_status(status: u32) -> AuthenticodeVerdict {
    match status {
        // TRUST_E_NOSIGNATURE.
        0x800b_0100 => AuthenticodeVerdict::Unsigned,
        // CERT_E_REVOCATION_FAILURE, CRYPT_E_NO_REVOCATION_CHECK,
        // CRYPT_E_REVOCATION_OFFLINE and the offline KDC form.
        0x800b_010e | 0x8009_2012 | 0x8009_2013 | 0x8009_0353 => {
            AuthenticodeVerdict::RevocationUnknown
        }
        // Deterministic signature/chain rejection remains distinct from a
        // provider status not covered by this bounded mapping.
        0x800b_0004 | 0x800b_0101 | 0x800b_0109 | 0x800b_010c | 0x8009_6010 => {
            AuthenticodeVerdict::Invalid
        }
        _ => AuthenticodeVerdict::Unknown,
    }
}

#[cfg(windows)]
fn provider_evidence(
    state: windows_sys::Win32::Foundation::HANDLE,
) -> Option<AuthenticodeEvidence> {
    use windows_sys::Win32::Security::Cryptography::CERT_CONTEXT;
    use windows_sys::Win32::Security::WinTrust::{
        WTHelperGetProvCertFromChain, WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData,
    };

    if state.is_null() {
        return None;
    }
    let provider = unsafe {
        // SAFETY: state is owned by the active WinTrust provider until CLOSE.
        WTHelperProvDataFromStateData(state)
    };
    if provider.is_null() {
        return None;
    }
    let signer = unsafe {
        // SAFETY: provider is live and signer index zero is bounded by the
        // provider's own chain state.
        WTHelperGetProvSignerFromChain(provider, 0, 0, 0)
    };
    if signer.is_null() {
        return None;
    }
    let cert = unsafe {
        // SAFETY: signer is live; WinTrust bounds certificate index zero.
        WTHelperGetProvCertFromChain(signer, 0)
    };
    if cert.is_null() {
        return None;
    }
    let context: *const CERT_CONTEXT = unsafe {
        // SAFETY: cert is live until provider CLOSE.
        (*cert).pCert
    };
    let context = (!context.is_null()).then(|| unsafe {
        // SAFETY: context is provider-owned and live until CLOSE.
        &*context
    })?;
    if context.pbCertEncoded.is_null() || context.cbCertEncoded == 0 {
        return None;
    }
    let der = unsafe {
        // SAFETY: provider supplied the exact bounded DER length.
        std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize)
    };
    let (signer_subject, not_before, not_after) = certificate_evidence(context);
    let countersigner = unsafe {
        // SAFETY: provider is live; the optional countersigner is provider-owned.
        WTHelperGetProvSignerFromChain(provider, 0, 1, 0)
    };
    let countersigner_certificate_sha256 = (!countersigner.is_null())
        .then(|| {
            let cert = unsafe {
                // SAFETY: countersigner is provider-owned and live.
                WTHelperGetProvCertFromChain(countersigner, 0)
            };
            if cert.is_null() {
                return None;
            }
            let context = unsafe {
                // SAFETY: cert remains live until provider CLOSE.
                (*cert).pCert
            };
            let context = (!context.is_null()).then(|| unsafe { &*context })?;
            if context.pbCertEncoded.is_null() || context.cbCertEncoded == 0 {
                return None;
            }
            let der = unsafe {
                // SAFETY: provider supplied the exact bounded DER length.
                std::slice::from_raw_parts(context.pbCertEncoded, context.cbCertEncoded as usize)
            };
            Some(hex_digest(der))
        })
        .flatten();

    Some(AuthenticodeEvidence {
        verdict: AuthenticodeVerdict::Valid,
        signer_certificate_sha256: Some(hex_digest(der)),
        signer_subject,
        signer_not_before_unix_seconds: not_before,
        signer_not_after_unix_seconds: not_after,
        verification_time_unix_seconds: unsafe {
            // SAFETY: signer is provider-owned and live.
            filetime_to_unix_seconds((*signer).sftVerifyAsOf)
        },
        countersigner_certificate_sha256,
        trust_status: 0,
    })
}

#[cfg(windows)]
fn certificate_evidence(
    context: &windows_sys::Win32::Security::Cryptography::CERT_CONTEXT,
) -> (Option<String>, Option<i64>, Option<i64>) {
    use windows_sys::Win32::Security::Cryptography::{
        CERT_NAME_SIMPLE_DISPLAY_TYPE, CertGetNameStringW,
    };
    let (not_before, not_after) = if context.pCertInfo.is_null() {
        (None, None)
    } else {
        let info = unsafe {
            // SAFETY: provider-owned certificate info remains live until CLOSE.
            &*context.pCertInfo
        };
        (
            filetime_to_unix_seconds(info.NotBefore),
            filetime_to_unix_seconds(info.NotAfter),
        )
    };
    let required = unsafe {
        // SAFETY: context is live; null output requests required UTF-16 units.
        CertGetNameStringW(
            context,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
        )
    };
    let subject = if required == 0 || required > 4096 {
        None
    } else {
        let mut buffer = vec![0_u16; required as usize];
        let written = unsafe {
            // SAFETY: the buffer has exactly the provider-reported capacity.
            CertGetNameStringW(
                context,
                CERT_NAME_SIMPLE_DISPLAY_TYPE,
                0,
                std::ptr::null(),
                buffer.as_mut_ptr(),
                required,
            )
        };
        if written > 1 {
            String::from_utf16(&buffer[..written as usize - 1]).ok()
        } else {
            None
        }
    };
    (subject, not_before, not_after)
}

#[cfg(windows)]
fn filetime_to_unix_seconds(filetime: windows_sys::Win32::Foundation::FILETIME) -> Option<i64> {
    let ticks = (u64::from(filetime.dwHighDateTime) << 32) | u64::from(filetime.dwLowDateTime);
    let unix_ticks = ticks.checked_sub(116_444_736_000_000_000)?;
    i64::try_from(unix_ticks / 10_000_000).ok()
}

/// Fail-closed package staging errors.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackageStagingError {
    /// A relative path violates the exact package path grammar.
    InvalidRelativePath,
    /// A manifest contains the same Windows-ordinal path more than once.
    ManifestCollision,
    /// A bounded input exceeded its explicit limit.
    BoundExceeded,
    /// The source or destination root was absent or not a directory.
    RootUnavailable,
    /// A symlink, junction or other reparse substitution was observed.
    ReparsePoint,
    /// An object did not have the expected regular-file/directory kind.
    WrongEntryKind,
    /// An object identity changed while a handle-bound operation was in flight.
    IdentityMismatch,
    /// Source and destination bytes differ from their receipt observations.
    HashMismatch,
    /// Source and destination sizes differ from their receipt observations.
    SizeMismatch,
    /// A file or directory security descriptor did not match `SystemService`.
    SecurityMismatch,
    /// A generation already exists and therefore cannot be adopted or replaced.
    GenerationExists,
    /// The exact source/destination tree differs from the manifest.
    TreeMismatch,
    /// A crash or partial tree has no complete receipt.
    PartialTree,
    /// The PE/COFF evidence was invalid.
    PeParse(PeCoffError),
    /// Authenticode was absent, unknown or rejected.
    Authenticode(AuthenticodeError),
    /// A verifier returned a non-valid verdict.
    AuthenticodeRejected(AuthenticodeVerdict),
    /// Exact-owned reverse deletion could not be proven safe.
    RollbackRefused,
    /// The operation is intentionally unavailable off Windows.
    UnsupportedPlatform,
    /// A bounded Windows operation failed before classification.
    Io,
}

impl fmt::Display for PackageStagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeParse(error) => write!(formatter, "PE/COFF staging error: {error}"),
            Self::Authenticode(error) => write!(formatter, "Authenticode staging error: {error}"),
            Self::AuthenticodeRejected(verdict) => {
                write!(formatter, "Authenticode verdict rejected: {verdict:?}")
            }
            other => formatter.write_str(match other {
                Self::InvalidRelativePath => "invalid package-relative path",
                Self::ManifestCollision => "manifest path collision",
                Self::BoundExceeded => "package staging bound exceeded",
                Self::RootUnavailable => "package root unavailable",
                Self::ReparsePoint => "package tree contains a reparse point",
                Self::WrongEntryKind => "package tree entry kind mismatch",
                Self::IdentityMismatch => "package object identity changed",
                Self::HashMismatch => "package object hash mismatch",
                Self::SizeMismatch => "package object size mismatch",
                Self::SecurityMismatch => "package object security mismatch",
                Self::GenerationExists => "package generation already exists",
                Self::TreeMismatch => "package tree does not match exactly",
                Self::PartialTree => "package tree is partial or crashed",
                Self::RollbackRefused => "exact-owned package rollback was refused",
                Self::UnsupportedPlatform => "package staging requires Windows",
                Self::Io => "package staging I/O failed",
                Self::PeParse(_) | Self::Authenticode(_) | Self::AuthenticodeRejected(_) => {
                    unreachable!()
                }
            }),
        }
    }
}

impl std::error::Error for PackageStagingError {}

/// One retained trusted source bundle contour.
///
/// The directory and all existing ancestors are held open without delete
/// sharing for the lifetime of this value.  The source is never inferred from
/// CWD, environment variables or a mutable current path.
pub struct TrustedSourceBundle {
    path: PathBuf,
    identity: FileIdentity,
    #[cfg(windows)]
    contour: Vec<std::fs::File>,
}

impl fmt::Debug for TrustedSourceBundle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedSourceBundle")
            .field("path", &self.path)
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl TrustedSourceBundle {
    /// Retain an existing absolute, regular, non-reparse source directory.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the source contour cannot be retained or is
    /// substituted by a reparse point.
    pub fn open(path: &Path) -> Result<Self, PackageStagingError> {
        validate_source_root_input(path)?;
        retain_source_directory(path)
    }

    /// Returns the canonical path captured from the retained root handle.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the retained root directory identity.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    fn verify_stable(&self) -> Result<(), PackageStagingError> {
        #[cfg(windows)]
        {
            let root = self.contour.last().ok_or(PackageStagingError::Io)?;
            let identity =
                super::file_identity_from_handle(root).map_err(|_| PackageStagingError::Io)?;
            if identity != self.identity {
                return Err(PackageStagingError::IdentityMismatch);
            }
            let mut expected = self.path.ancestors().collect::<Vec<_>>();
            expected.reverse();
            if expected.len() != self.contour.len() {
                return Err(PackageStagingError::IdentityMismatch);
            }
            for (handle, expected_path) in self.contour.iter().zip(expected) {
                let observed = final_path_from_handle(handle)?;
                if !super::windows_paths_equal(&observed, expected_path) {
                    return Err(PackageStagingError::IdentityMismatch);
                }
            }
            Ok(())
        }
        #[cfg(not(windows))]
        {
            Err(PackageStagingError::UnsupportedPlatform)
        }
    }

    /// Observe every regular file below the retained source root.
    ///
    /// The walk is read-only and independent of any manifest, signature or
    /// approval claim.  Every returned item is measured from a no-follow file
    /// handle and contains only its canonical relative path, SHA-256, stable
    /// object identity and byte size.  The retained root contour is checked
    /// before and after the walk; directories and files are checked against
    /// their final handle paths while the handles are live.
    ///
    /// Empty child directories are rejected because they have no file fact to
    /// carry into the file-defined package plan.  An entirely empty source
    /// root is represented by an empty observation.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the source tree is substituted, contains a
    /// link/reparse/device/path collision, exceeds a bound, or changes while
    /// being read.
    pub fn observe(&self) -> Result<PackageSourceObservation, PackageStagingError> {
        #[cfg(not(windows))]
        {
            let _ = self;
            return Err(PackageStagingError::UnsupportedPlatform);
        }
        #[cfg(windows)]
        {
            self.verify_stable()?;
            let mut identities = HashSet::new();
            let mut total_bytes = 0_u64;
            let mut files = Vec::new();
            let _tree = walk_trusted_source_tree(self.path(), |relative, path, file, identity| {
                if !identities.insert(identity) {
                    return Err(PackageStagingError::IdentityMismatch);
                }
                if files.len() >= MAX_PACKAGE_FILES {
                    return Err(PackageStagingError::BoundExceeded);
                }
                let observed = observe_source_handle(file, path, MAX_PACKAGE_FILE_BYTES)?;
                total_bytes = total_bytes
                    .checked_add(observed.size)
                    .ok_or(PackageStagingError::BoundExceeded)?;
                if total_bytes > MAX_PACKAGE_TOTAL_BYTES {
                    return Err(PackageStagingError::BoundExceeded);
                }
                files.push(PackageSourceFileObservation {
                    relative_path: relative.canonical.clone(),
                    sha256: observed.sha256,
                    identity,
                    size: observed.size,
                });
                Ok(())
            })?;
            self.verify_stable()?;
            files.sort_by(|left, right| {
                let left = validate_relative_text(&left.relative_path).ok();
                let right = validate_relative_text(&right.relative_path).ok();
                match (left, right) {
                    (Some(left), Some(right)) => ordinal_path_cmp(&left, &right),
                    _ => Ordering::Equal,
                }
            });
            Ok(PackageSourceObservation { files, total_bytes })
        }
    }
}

fn validate_source_root_input(path: &Path) -> Result<(), PackageStagingError> {
    if !path.is_absolute() {
        return Err(PackageStagingError::RootUnavailable);
    }
    let raw = path.to_str().ok_or(PackageStagingError::RootUnavailable)?;
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("\\\\?\\")
        || lower.starts_with("\\\\.\\")
        || lower.starts_with("\\??\\")
        || path.components().any(|component| {
            matches!(component, std::path::Component::ParentDir)
                || match component {
                    std::path::Component::Normal(value) => value.to_str().is_none_or(|value| {
                        value.contains(':')
                            || value.ends_with('.')
                            || value.ends_with(' ')
                            || is_windows_device_name(value)
                    }),
                    _ => false,
                }
        })
    {
        return Err(PackageStagingError::RootUnavailable);
    }
    Ok(())
}

#[cfg(windows)]
fn retain_source_directory(path: &Path) -> Result<TrustedSourceBundle, PackageStagingError> {
    reject_reparse_ancestors(path)?;
    let canonical = super::canonical_windows_path(path).map_err(map_protected_path_error)?;
    let contour = retain_directory_contour(&canonical)?;
    let root = contour.last().ok_or(PackageStagingError::RootUnavailable)?;
    let identity = super::file_identity_from_handle(root).map_err(|_| PackageStagingError::Io)?;
    let observed = super::final_windows_path_from_handle(root).map_err(map_protected_path_error)?;
    if !super::windows_paths_equal(&observed, &canonical) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(TrustedSourceBundle {
        path: observed,
        identity,
        contour,
    })
}

#[cfg(not(windows))]
fn retain_source_directory(_path: &Path) -> Result<TrustedSourceBundle, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

fn map_protected_path_error(error: ProtectedPathError) -> PackageStagingError {
    match error {
        ProtectedPathError::ReparsePoint => PackageStagingError::ReparsePoint,
        ProtectedPathError::InvalidRoot | ProtectedPathError::InvalidPath => {
            PackageStagingError::RootUnavailable
        }
        ProtectedPathError::UnsupportedPlatform => PackageStagingError::UnsupportedPlatform,
        ProtectedPathError::AclMismatch => PackageStagingError::SecurityMismatch,
        ProtectedPathError::Io | ProtectedPathError::SizeExceeded => PackageStagingError::Io,
    }
}

/// One independently measured regular source file.
///
/// This is intentionally narrower than [`StagedFileReceipt`]: it contains no
/// destination, security, PE, Authenticode, manifest or approval fields.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSourceFileObservation {
    /// Canonical slash-separated path below the retained source root.
    pub relative_path: String,
    /// Lowercase SHA-256 of the bytes read from the retained file handle.
    pub sha256: String,
    /// Windows volume/file-object identity observed from the same handle.
    pub identity: FileIdentity,
    /// Number of bytes read from the same handle.
    pub size: u64,
}

/// Complete bounded read-only observation of a trusted source bundle.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageSourceObservation {
    /// File facts sorted by Windows ordinal whole-component path order.
    pub files: Vec<PackageSourceFileObservation>,
    /// Aggregate bytes read from all observed files.
    pub total_bytes: u64,
}

/// Receipt for one copied package file.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedFileReceipt {
    /// Canonical package-relative path.
    pub relative_path: String,
    /// Source file identity observed before copying.
    pub source_identity: FileIdentity,
    /// Destination file identity observed after copying.
    pub destination_identity: FileIdentity,
    /// Source/destination byte size.
    pub size: u64,
    /// Source/destination SHA-256 digest.
    pub sha256: String,
    /// SHA-256 digest of the final protected security descriptor.
    pub security_descriptor_sha256: String,
    /// PE/COFF evidence for executable entries.
    pub pe: Option<PeCoffEvidence>,
    /// Authenticode evidence for executable entries.
    pub authenticode: Option<AuthenticodeEvidence>,
}

/// Receipt for one create-only directory below the generation root.
///
/// Directory identities are retained so rollback can prove ownership before
/// deleting nested directories; the root directory has its own identity field
/// on [`StagingReceipt`].
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagedDirectoryReceipt {
    /// Canonical package-relative directory path.
    pub relative_path: String,
    /// Directory identity observed after creation.
    pub identity: FileIdentity,
    /// SHA-256 digest of the final protected security descriptor.
    pub security_descriptor_sha256: String,
}

/// Complete immutable package staging receipt.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagingReceipt {
    /// Manifest generation identity.
    pub generation: String,
    /// Canonical absolute generation-root path.
    pub root_path: PathBuf,
    /// Root directory identity captured after creation.
    pub root_identity: FileIdentity,
    /// Exact nested directories created below the generation root.
    pub directories: Vec<StagedDirectoryReceipt>,
    /// Exact file receipts sorted by ordinal path.
    pub files: Vec<StagedFileReceipt>,
    /// Canonical manifest SHA-256 digest.
    pub manifest_sha256: String,
}

impl StagingReceipt {
    /// Return a stable digest of the receipt itself for an outer coordinator.
    #[must_use]
    pub fn digest(&self) -> String {
        serde_json::to_vec(self).map_or_else(
            |_| hex_digest(b"staging-receipt-serialization-failed"),
            |bytes| hex_digest(&bytes),
        )
    }
}

/// Explicit result of inspecting a generation tree.
///
/// There is intentionally no `Staged` variant.  A complete receipt is either
/// returned as `Matching` or the tree is classified as absent, mismatched or
/// unknown; a crash/partial tree can never be promoted by this primitive.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PackageStagingObservation {
    /// Generation root is absent while its retained parent contour is stable.
    Absent,
    /// Existing tree exactly matches the supplied receipt.
    Matching(StagingReceipt),
    /// Existing tree is present but differs from the receipt/manifest.
    Mismatch(PackageStagingError),
    /// The OS could not classify the tree safely.
    Unknown(PackageStagingError),
}

#[derive(Debug)]
struct RetainedDestinationParent {
    path: PathBuf,
    #[cfg(windows)]
    _contour: Vec<std::fs::File>,
}

/// Measurement/mutation primitive for one retained source and installation
/// root.  It owns no transaction, activation or durable authority state.
pub struct PackageStager {
    source: TrustedSourceBundle,
    installation_root: PathBuf,
    #[cfg(windows)]
    _installation_lease: super::ProtectedRootLease,
}

impl fmt::Debug for PackageStager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackageStager")
            .field("source", &self.source)
            .field("installation_root", &self.installation_root)
            .finish_non_exhaustive()
    }
}

impl PackageStager {
    /// Retain a trusted source bundle and an existing protected installation
    /// root.  The installation root must already be below the OS-protected
    /// `ProgramData` contour; this constructor never creates/adopts it.
    ///
    /// # Errors
    ///
    /// Returns a typed error when either contour cannot be retained.
    pub fn open(
        source: TrustedSourceBundle,
        installation_root: &Path,
    ) -> Result<Self, PackageStagingError> {
        if !installation_root.is_absolute() {
            return Err(PackageStagingError::RootUnavailable);
        }
        #[cfg(windows)]
        {
            let lease = super::ProtectedRootLease::open_existing(installation_root)
                .map_err(map_protected_path_error)?;
            let canonical = lease.canonical_path().map_err(map_protected_path_error)?;
            verify_system_directory_at(&canonical)?;
            Ok(Self {
                source,
                installation_root: canonical,
                _installation_lease: lease,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = (source, installation_root);
            Err(PackageStagingError::UnsupportedPlatform)
        }
    }

    /// Returns the retained source bundle.
    #[must_use]
    pub fn source(&self) -> &TrustedSourceBundle {
        &self.source
    }

    /// Returns the canonical retained installation root.
    #[must_use]
    pub fn installation_root(&self) -> &Path {
        &self.installation_root
    }

    /// Create one immutable generation with the official `WinTrust` verifier.
    ///
    /// Existing generation roots are never adopted, replaced or overwritten.
    /// Any failure after root creation attempts exact-owned reverse deletion;
    /// if that proof fails, the result is `RollbackRefused`/`Unknown`.
    ///
    /// # Errors
    ///
    /// Returns a typed error for invalid manifests, tree mismatches, identity
    /// or security races, failed trust, or refused exact-owned rollback.
    pub fn stage(&self, manifest: &PackageManifest) -> Result<StagingReceipt, PackageStagingError> {
        self.stage_with_verifier(manifest, &WindowsAuthenticodeVerifier)
    }

    /// Same operation with the sealed Authenticode injection seam.
    ///
    /// # Errors
    ///
    /// Returns a typed error when any bounded source, destination, parser or
    /// verifier observation cannot be classified as a complete stage.
    pub fn stage_with_verifier<V: AuthenticodeVerifier>(
        &self,
        manifest: &PackageManifest,
        verifier: &V,
    ) -> Result<StagingReceipt, PackageStagingError> {
        let manifest = manifest.validate()?;
        let generation = validate_relative_text(&manifest.generation)?;
        let parent = self.retain_generation_parent(&generation)?;
        self.source.verify_stable()?;
        let source_tree = enumerate_trusted_source_tree(self.source.path(), &manifest)?;
        ensure_tree_matches_manifest(&source_tree, &manifest)?;
        let generation_root = generation.join_to(&parent.path);
        if path_exists(&generation_root)? {
            return Err(PackageStagingError::GenerationExists);
        }
        let root_file = create_generation_root(&generation_root)?;
        let root_identity = file_identity_from_open_handle(&root_file)?;
        verify_system_security(&root_file, true)?;
        let mut created = CreatedTree {
            root_path: generation_root.clone(),
            root_identity,
            root_file,
            directories: Vec::new(),
            files: Vec::with_capacity(manifest.files.len()),
        };
        let result = self.copy_and_measure(&manifest, &generation_root, verifier, &mut created);
        match result {
            Ok(files) => {
                let finalized = (|| {
                    let destination_tree = enumerate_tree(&generation_root, &manifest)?;
                    ensure_tree_matches_manifest(&destination_tree, &manifest)?;
                    let generation_name = manifest.generation.clone();
                    let manifest_sha256 = manifest.canonical_digest();
                    let root_path = final_path_from_handle(&created.root_file)?;
                    let receipt = StagingReceipt {
                        generation: generation_name,
                        root_path,
                        root_identity: created.root_identity,
                        directories: created
                            .directories
                            .iter()
                            .map(|directory| StagedDirectoryReceipt {
                                relative_path: directory.relative_path.clone(),
                                identity: directory.identity,
                                security_descriptor_sha256: directory
                                    .security_descriptor_sha256
                                    .clone(),
                            })
                            .collect(),
                        files,
                        manifest_sha256,
                    };
                    if !super::windows_paths_equal(&receipt.root_path, &generation_root) {
                        return Err(PackageStagingError::IdentityMismatch);
                    }
                    Ok(receipt)
                })();
                match finalized {
                    Ok(receipt) => Ok(receipt),
                    Err(error) => match rollback_created_tree(created) {
                        Ok(()) => Err(error),
                        Err(_) => Err(PackageStagingError::RollbackRefused),
                    },
                }
            }
            Err(error) => match rollback_created_tree(created) {
                Ok(()) | Err(PackageStagingError::UnsupportedPlatform) => Err(error),
                Err(_) => Err(PackageStagingError::RollbackRefused),
            },
        }
    }

    /// Inspect one generation against a complete prior receipt.
    ///
    /// An absent root is distinct from a partial tree; no tree is ever
    /// classified as staged by this method.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained contours or receipt grammar cannot
    /// be observed safely.
    pub fn reconcile(
        &self,
        receipt: &StagingReceipt,
    ) -> Result<PackageStagingObservation, PackageStagingError> {
        if receipt.generation.is_empty()
            || receipt.files.len() > MAX_PACKAGE_FILES
            || receipt.directories.len() > MAX_ENUMERATED_ENTRIES
        {
            return Err(PackageStagingError::InvalidRelativePath);
        }
        let files = receipt
            .files
            .iter()
            .map(|file| PackageFileSpec {
                relative_path: file.relative_path.clone(),
                executable: file.pe.is_some(),
                max_size: file.size.max(1),
            })
            .collect::<Vec<_>>();
        let manifest = PackageManifest::new(&receipt.generation, files)?;
        if receipt.manifest_sha256 != manifest.canonical_digest() {
            return Ok(PackageStagingObservation::Mismatch(
                PackageStagingError::HashMismatch,
            ));
        }
        validate_receipt_directories(receipt, &manifest)?;
        let generation = validate_relative_text(&manifest.generation)?;
        let parent = self.retain_generation_parent(&generation)?;
        let root_path = generation.join_to(&parent.path);
        if !receipt.root_path.is_absolute() {
            return Err(PackageStagingError::RootUnavailable);
        }
        if !super::windows_paths_equal(&receipt.root_path, &root_path) {
            return Ok(PackageStagingObservation::Mismatch(
                PackageStagingError::IdentityMismatch,
            ));
        }
        if !path_exists(&root_path)? {
            return Ok(PackageStagingObservation::Absent);
        }
        let root = match open_existing_directory(&root_path) {
            Ok(root) => root,
            Err(PackageStagingError::ReparsePoint | PackageStagingError::WrongEntryKind) => {
                return Ok(PackageStagingObservation::Mismatch(
                    PackageStagingError::TreeMismatch,
                ));
            }
            Err(error) => return Ok(PackageStagingObservation::Unknown(error)),
        };
        let root_identity = file_identity_from_open_handle(&root)?;
        if root_identity != receipt.root_identity {
            return Ok(PackageStagingObservation::Mismatch(
                PackageStagingError::IdentityMismatch,
            ));
        }
        if let Err(error) = verify_system_security(&root, true) {
            return Ok(PackageStagingObservation::Mismatch(error));
        }
        let actual_tree = match enumerate_tree(&root_path, &manifest) {
            Ok(tree) => tree,
            Err(error) => return Ok(PackageStagingObservation::Unknown(error)),
        };
        if ensure_tree_matches_manifest(&actual_tree, &manifest).is_err() {
            return Ok(PackageStagingObservation::Mismatch(
                PackageStagingError::TreeMismatch,
            ));
        }
        let actual_directories = match Self::read_current_directories(&root_path, &manifest) {
            Ok(directories) => directories,
            Err(error) => return Ok(PackageStagingObservation::Unknown(error)),
        };
        if actual_directories != receipt.directories {
            let error = if actual_directories
                .iter()
                .zip(&receipt.directories)
                .any(|(actual, expected)| actual.relative_path != expected.relative_path)
            {
                PackageStagingError::TreeMismatch
            } else if actual_directories
                .iter()
                .zip(&receipt.directories)
                .any(|(actual, expected)| actual.identity != expected.identity)
            {
                PackageStagingError::IdentityMismatch
            } else {
                PackageStagingError::SecurityMismatch
            };
            return Ok(PackageStagingObservation::Mismatch(error));
        }
        let actual = match self.read_current_files(&root_path, &manifest) {
            Ok(files) => files,
            Err(error) => return Ok(PackageStagingObservation::Unknown(error)),
        };
        if actual != receipt.files {
            return Ok(PackageStagingObservation::Mismatch(
                PackageStagingError::HashMismatch,
            ));
        }
        Ok(PackageStagingObservation::Matching(receipt.clone()))
    }

    /// Inspect a manifest without adopting an existing generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the manifest or retained destination contour is
    /// invalid or unavailable.
    pub fn inspect(
        &self,
        manifest: &PackageManifest,
    ) -> Result<PackageStagingObservation, PackageStagingError> {
        let manifest = manifest.validate()?;
        let generation = validate_relative_text(&manifest.generation)?;
        let parent = self.retain_generation_parent(&generation)?;
        let root_path = generation.join_to(&parent.path);
        if !path_exists(&root_path)? {
            return Ok(PackageStagingObservation::Absent);
        }
        if !is_directory_path(&root_path)? {
            return Ok(PackageStagingObservation::Mismatch(
                PackageStagingError::WrongEntryKind,
            ));
        }
        let tree = match enumerate_tree(&root_path, &manifest) {
            Ok(tree) => tree,
            Err(error) => return Ok(PackageStagingObservation::Unknown(error)),
        };
        if ensure_tree_matches_manifest(&tree, &manifest).is_err() {
            return Ok(PackageStagingObservation::Mismatch(
                PackageStagingError::TreeMismatch,
            ));
        }
        Ok(PackageStagingObservation::Mismatch(
            PackageStagingError::PartialTree,
        ))
    }

    /// Delete a complete tree only when the supplied receipt owns every file
    /// and the root identity still matches.  Deletion is reverse sorted and
    /// handle-bound; recursive path deletion is never used.
    ///
    /// # Errors
    ///
    /// Returns an error when any file/root identity, tree, security descriptor
    /// or exact delete operation is not proven to match the receipt.
    pub fn rollback(&self, receipt: &StagingReceipt) -> Result<(), PackageStagingError> {
        let manifest = PackageManifest::new(
            &receipt.generation,
            receipt
                .files
                .iter()
                .map(|file| PackageFileSpec {
                    relative_path: file.relative_path.clone(),
                    executable: file.pe.is_some(),
                    max_size: file.size.max(1),
                })
                .collect(),
        )?;
        if receipt.manifest_sha256 != manifest.canonical_digest() {
            return Err(PackageStagingError::HashMismatch);
        }
        validate_receipt_directories(receipt, &manifest)?;
        let generation = validate_relative_text(&manifest.generation)?;
        let parent = self.retain_generation_parent(&generation)?;
        let root_path = generation.join_to(&parent.path);
        if !receipt.root_path.is_absolute()
            || !super::windows_paths_equal(&receipt.root_path, &root_path)
        {
            return Err(PackageStagingError::IdentityMismatch);
        }
        let root = open_existing_directory(&root_path)?;
        let root_identity = file_identity_from_open_handle(&root)?;
        if root_identity != receipt.root_identity {
            return Err(PackageStagingError::IdentityMismatch);
        }
        verify_system_security(&root, true)?;
        let tree = enumerate_tree(&root_path, &manifest)?;
        ensure_tree_matches_manifest(&tree, &manifest)?;
        for file in receipt.files.iter().rev() {
            let path = validate_relative_text(&file.relative_path)?.join_to(&root_path);
            let handle = open_existing_file_for_delete(&path)?;
            let actual = file_identity_from_open_handle(&handle)?;
            if actual != file.destination_identity {
                return Err(PackageStagingError::IdentityMismatch);
            }
            let security = verify_system_security(&handle, false)?;
            if security != file.security_descriptor_sha256 {
                return Err(PackageStagingError::SecurityMismatch);
            }
            delete_open_handle(handle, actual)?;
        }
        for directory in receipt.directories.iter().rev() {
            let path = validate_relative_text(&directory.relative_path)?.join_to(&root_path);
            let handle = open_existing_directory_for_delete(&path)?;
            let actual = file_identity_from_open_handle(&handle)?;
            if actual != directory.identity {
                return Err(PackageStagingError::IdentityMismatch);
            }
            let security = verify_system_security(&handle, true)?;
            if security != directory.security_descriptor_sha256 {
                return Err(PackageStagingError::SecurityMismatch);
            }
            delete_open_handle(handle, actual)?;
        }
        drop(root);
        let root = open_existing_directory_for_delete(&root_path)?;
        delete_open_handle(root, root_identity)
    }

    fn retain_generation_parent(
        &self,
        generation: &PackageRelativePath,
    ) -> Result<RetainedDestinationParent, PackageStagingError> {
        let parent_components = generation
            .components
            .get(..generation.components.len().saturating_sub(1))
            .unwrap_or(&[]);
        let mut path = self.installation_root.clone();
        for component in parent_components {
            path.push(component);
        }
        retain_destination_parent(&path)
    }

    fn read_current_directories(
        root: &Path,
        manifest: &PackageManifest,
    ) -> Result<Vec<StagedDirectoryReceipt>, PackageStagingError> {
        let mut directories = Vec::new();
        for relative in expected_directories(manifest)? {
            let path = relative.join_to(root);
            let directory = open_existing_directory(&path)?;
            let identity = file_identity_from_open_handle(&directory)?;
            let canonical = final_path_from_handle(&directory)?;
            if !super::windows_paths_equal(&canonical, &path) {
                return Err(PackageStagingError::IdentityMismatch);
            }
            let security_descriptor_sha256 = verify_system_security(&directory, true)?;
            directories.push(StagedDirectoryReceipt {
                relative_path: relative.canonical,
                identity,
                security_descriptor_sha256,
            });
        }
        Ok(directories)
    }

    fn read_current_files(
        &self,
        root: &Path,
        manifest: &PackageManifest,
    ) -> Result<Vec<StagedFileReceipt>, PackageStagingError> {
        let verifier = WindowsAuthenticodeVerifier;
        let mut files = Vec::with_capacity(manifest.files.len());
        for spec in &manifest.files {
            let relative = validate_relative_text(&spec.relative_path)?;
            let source = relative.join_to(self.source.path());
            let destination = relative.join_to(root);
            let source_snapshot = snapshot_source_file(&source, spec.max_size)?;
            let destination_file = open_existing_file(&destination)?;
            let destination_identity = file_identity_from_open_handle(&destination_file)?;
            let destination_snapshot =
                read_destination_snapshot(&destination, spec.max_size, destination_identity)?;
            let pe = if spec.executable {
                let header = read_file_prefix(&destination, MAX_PE_HEADER_BYTES)?;
                Some(parse_pe_coff(&header).map_err(PackageStagingError::PeParse)?)
            } else {
                None
            };
            let authenticode = if spec.executable {
                let evidence = verifier
                    .verify(
                        &destination,
                        destination_identity,
                        &destination_snapshot.sha256,
                    )
                    .map_err(PackageStagingError::Authenticode)?;
                if evidence.verdict != AuthenticodeVerdict::Valid {
                    return Err(PackageStagingError::AuthenticodeRejected(evidence.verdict));
                }
                Some(evidence)
            } else {
                None
            };
            files.push(StagedFileReceipt {
                relative_path: spec.relative_path.clone(),
                source_identity: source_snapshot.identity,
                destination_identity,
                size: destination_snapshot.size,
                sha256: destination_snapshot.sha256,
                security_descriptor_sha256: destination_snapshot.security_descriptor_sha256,
                pe,
                authenticode,
            });
        }
        files.sort_by(|left, right| {
            let left = validate_relative_text(&left.relative_path).ok();
            let right = validate_relative_text(&right.relative_path).ok();
            match (left, right) {
                (Some(left), Some(right)) => ordinal_path_cmp(&left, &right),
                _ => Ordering::Equal,
            }
        });
        Ok(files)
    }

    fn copy_and_measure<V: AuthenticodeVerifier>(
        &self,
        manifest: &PackageManifest,
        destination_root: &Path,
        verifier: &V,
        created: &mut CreatedTree,
    ) -> Result<Vec<StagedFileReceipt>, PackageStagingError> {
        for entry in expected_tree(manifest)? {
            if entry.kind != TreeEntryKind::Directory {
                continue;
            }
            let path = entry.relative.join_to(destination_root);
            let (directory, identity, security_descriptor_sha256) =
                create_destination_directory(&path)?;
            created.directories.push(CreatedDirectory {
                relative_path: entry.relative.canonical,
                identity,
                security_descriptor_sha256,
                file: directory,
            });
        }
        let mut total = 0_u64;
        let mut files = Vec::with_capacity(manifest.files.len());
        for spec in &manifest.files {
            files.push(self.copy_one_file(
                spec,
                destination_root,
                verifier,
                &mut total,
                created,
            )?);
        }
        Ok(files)
    }

    fn copy_one_file<V: AuthenticodeVerifier>(
        &self,
        spec: &PackageFileSpec,
        destination_root: &Path,
        verifier: &V,
        total: &mut u64,
        created: &mut CreatedTree,
    ) -> Result<StagedFileReceipt, PackageStagingError> {
        let relative = validate_relative_text(&spec.relative_path)?;
        let source = relative.join_to(self.source.path());
        let destination = relative.join_to(destination_root);
        let source_snapshot = snapshot_source_file(&source, spec.max_size)?;
        *total = total
            .checked_add(source_snapshot.size)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if *total > MAX_PACKAGE_TOTAL_BYTES {
            return Err(PackageStagingError::BoundExceeded);
        }
        let pe = if spec.executable {
            Some(parse_pe_coff(&source_snapshot.pe_header).map_err(PackageStagingError::PeParse)?)
        } else {
            None
        };
        let (destination_file, destination_identity, destination_readback) =
            copy_destination_bytes(&source_snapshot, &destination, spec.max_size)?;
        let authenticode = if spec.executable {
            let evidence = match verifier.verify(
                &destination,
                destination_identity,
                &destination_readback.sha256,
            ) {
                Ok(evidence) => evidence,
                Err(error) => {
                    return Err(cleanup_created_handle(
                        destination_file,
                        destination_identity,
                        PackageStagingError::Authenticode(error),
                    ));
                }
            };
            if evidence.verdict != AuthenticodeVerdict::Valid {
                return Err(cleanup_created_handle(
                    destination_file,
                    destination_identity,
                    PackageStagingError::AuthenticodeRejected(evidence.verdict),
                ));
            }
            Some(evidence)
        } else {
            None
        };
        created.files.push(CreatedFile {
            identity: destination_identity,
            file: destination_file,
        });
        Ok(StagedFileReceipt {
            relative_path: spec.relative_path.clone(),
            source_identity: source_snapshot.identity,
            destination_identity,
            size: source_snapshot.size,
            sha256: source_snapshot.sha256,
            security_descriptor_sha256: destination_readback.security_descriptor_sha256,
            pe,
            authenticode,
        })
    }
}

#[cfg(windows)]
fn copy_destination_bytes(
    source_snapshot: &SourceSnapshot,
    destination: &Path,
    max_size: u64,
) -> Result<(std::fs::File, FileIdentity, DestinationSnapshot), PackageStagingError> {
    let (mut destination_file, destination_identity) = create_destination_file(destination)?;
    let copy_hash =
        match copy_source_to_destination(source_snapshot, &mut destination_file, max_size) {
            Ok(hash) => hash,
            Err(error) => {
                return Err(cleanup_created_handle(
                    destination_file,
                    destination_identity,
                    error,
                ));
            }
        };
    if copy_hash != source_snapshot.sha256 {
        return Err(cleanup_created_handle(
            destination_file,
            destination_identity,
            PackageStagingError::HashMismatch,
        ));
    }
    let destination_readback = match read_destination_snapshot_handle(
        &destination_file,
        destination,
        max_size,
        destination_identity,
    ) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Err(cleanup_created_handle(
                destination_file,
                destination_identity,
                error,
            ));
        }
    };
    if destination_readback.sha256 != source_snapshot.sha256
        || destination_readback.size != source_snapshot.size
    {
        return Err(cleanup_created_handle(
            destination_file,
            destination_identity,
            PackageStagingError::HashMismatch,
        ));
    }
    Ok((destination_file, destination_identity, destination_readback))
}

#[cfg(not(windows))]
fn copy_destination_bytes(
    _source_snapshot: &SourceSnapshot,
    _destination: &Path,
    _max_size: u64,
) -> Result<(std::fs::File, FileIdentity, DestinationSnapshot), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[derive(Debug)]
struct CreatedFile {
    identity: FileIdentity,
    file: std::fs::File,
}

#[derive(Debug)]
struct CreatedDirectory {
    relative_path: String,
    identity: FileIdentity,
    security_descriptor_sha256: String,
    file: std::fs::File,
}

#[derive(Debug)]
struct CreatedTree {
    root_path: PathBuf,
    root_identity: FileIdentity,
    root_file: std::fs::File,
    directories: Vec<CreatedDirectory>,
    files: Vec<CreatedFile>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TreeEntryKind {
    Directory,
    File,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct TreeEntry {
    relative: PackageRelativePath,
    kind: TreeEntryKind,
}

#[derive(Debug)]
struct SourceSnapshot {
    identity: FileIdentity,
    size: u64,
    sha256: String,
    pe_header: Vec<u8>,
    file: std::fs::File,
}

#[derive(Debug)]
struct DestinationSnapshot {
    size: u64,
    sha256: String,
    security_descriptor_sha256: String,
}

fn expected_tree(manifest: &PackageManifest) -> Result<Vec<TreeEntry>, PackageStagingError> {
    let mut entries = Vec::new();
    let mut seen_dirs = Vec::<PackageRelativePath>::new();
    for spec in &manifest.files {
        let relative = validate_relative_text(&spec.relative_path)?;
        for depth in 1..relative.components.len() {
            let directory = PackageRelativePath {
                canonical: relative.components[..depth].join("/"),
                components: relative.components[..depth].to_vec(),
            };
            if !seen_dirs
                .iter()
                .any(|existing| ordinal_path_eq(existing, &directory))
            {
                seen_dirs.push(directory.clone());
                entries.push(TreeEntry {
                    relative: directory,
                    kind: TreeEntryKind::Directory,
                });
            }
        }
        entries.push(TreeEntry {
            relative,
            kind: TreeEntryKind::File,
        });
    }
    entries.sort_by(|left, right| ordinal_path_cmp(&left.relative, &right.relative));
    Ok(entries)
}

fn expected_directories(
    manifest: &PackageManifest,
) -> Result<Vec<PackageRelativePath>, PackageStagingError> {
    Ok(expected_tree(manifest)?
        .into_iter()
        .filter_map(|entry| match entry.kind {
            TreeEntryKind::Directory => Some(entry.relative),
            TreeEntryKind::File => None,
        })
        .collect())
}

fn validate_receipt_directories(
    receipt: &StagingReceipt,
    manifest: &PackageManifest,
) -> Result<(), PackageStagingError> {
    let expected = expected_directories(manifest)?;
    if receipt.directories.len() != expected.len() {
        return Err(PackageStagingError::TreeMismatch);
    }
    for (actual, expected) in receipt.directories.iter().zip(expected) {
        let actual_path = validate_relative_text(&actual.relative_path)?;
        if !ordinal_path_eq(&actual_path, &expected) {
            return Err(PackageStagingError::TreeMismatch);
        }
        if !super::valid_sha256_hex(&actual.security_descriptor_sha256) {
            return Err(PackageStagingError::SecurityMismatch);
        }
    }
    Ok(())
}

fn ensure_tree_matches_manifest(
    actual: &[TreeEntry],
    manifest: &PackageManifest,
) -> Result<(), PackageStagingError> {
    let mut actual = actual.to_vec();
    actual.sort_by(|left, right| ordinal_path_cmp(&left.relative, &right.relative));
    let expected = expected_tree(manifest)?;
    if actual.len() != expected.len()
        || actual.iter().zip(&expected).any(|(actual, expected)| {
            !ordinal_path_eq(&actual.relative, &expected.relative) || actual.kind != expected.kind
        })
    {
        return Err(PackageStagingError::TreeMismatch);
    }
    Ok(())
}

#[cfg(windows)]
fn enumerate_tree(
    root: &Path,
    manifest: &PackageManifest,
) -> Result<Vec<TreeEntry>, PackageStagingError> {
    let entries = walk_tree(root, |_relative, _path, _file, _identity| Ok(()))?;
    let _ = manifest;
    Ok(entries)
}

/// Walk one retained regular tree once, holding every opened directory until
/// its descendants have been processed.  The callback runs while each file
/// handle is open, which lets source observation read the same no-follow
/// object that was enumerated rather than reopening a mutable path later.
#[cfg(windows)]
fn walk_tree<F>(root: &Path, mut on_file: F) -> Result<Vec<TreeEntry>, PackageStagingError>
where
    F: FnMut(
        &PackageRelativePath,
        &Path,
        &std::fs::File,
        FileIdentity,
    ) -> Result<(), PackageStagingError>,
{
    let root_handle = open_existing_directory(root)?;
    let root_final = final_path_from_handle(&root_handle)?;
    if !super::windows_paths_equal(&root_final, root) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let mut entries = Vec::new();
    let mut stack = vec![(
        root.to_path_buf(),
        Vec::<String>::new(),
        0_usize,
        root_handle,
    )];
    while let Some((directory, prefix, depth, directory_handle)) = stack.pop() {
        if depth > MAX_PACKAGE_PATH_DEPTH {
            return Err(PackageStagingError::BoundExceeded);
        }
        let mut pending = Vec::new();
        let read_dir = std::fs::read_dir(&directory).map_err(|_| PackageStagingError::Io)?;
        for entry in read_dir {
            let entry = entry.map_err(|_| PackageStagingError::Io)?;
            let name = entry
                .file_name()
                .to_str()
                .ok_or(PackageStagingError::InvalidRelativePath)?
                .to_owned();
            let relative_text = if prefix.is_empty() {
                name
            } else {
                format!("{}/{}", prefix.join("/"), name)
            };
            let relative = validate_relative_text(&relative_text)?;
            pending.push((relative, entry.path()));
        }
        pending.sort_by(|left, right| ordinal_path_cmp(&left.0, &right.0));
        for pair in pending.windows(2) {
            if ordinal_path_eq(&pair[0].0, &pair[1].0) {
                return Err(PackageStagingError::ManifestCollision);
            }
        }
        if pending.is_empty() && !prefix.is_empty() {
            return Err(PackageStagingError::TreeMismatch);
        }
        let mut child_directories = Vec::new();
        for (relative, path) in pending {
            if entries.len() >= MAX_ENUMERATED_ENTRIES {
                return Err(PackageStagingError::BoundExceeded);
            }
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| PackageStagingError::Io)?;
            if is_reparse_metadata(&metadata) {
                return Err(PackageStagingError::ReparsePoint);
            }
            if metadata.is_dir() {
                let child = open_existing_directory(&path)?;
                let final_path = final_path_from_handle(&child)?;
                if !super::windows_paths_equal(&final_path, &path) {
                    return Err(PackageStagingError::IdentityMismatch);
                }
                entries.push(TreeEntry {
                    relative: relative.clone(),
                    kind: TreeEntryKind::Directory,
                });
                child_directories.push((
                    path,
                    relative.components.clone(),
                    depth.saturating_add(1),
                    child,
                ));
            } else if metadata.is_file() {
                let file = open_existing_file(&path)?;
                let identity = file_identity_from_open_handle(&file)?;
                let final_path = final_path_from_handle(&file)?;
                if !super::windows_paths_equal(&final_path, &path) {
                    return Err(PackageStagingError::IdentityMismatch);
                }
                on_file(&relative, &path, &file, identity)?;
                entries.push(TreeEntry {
                    relative,
                    kind: TreeEntryKind::File,
                });
            } else {
                return Err(PackageStagingError::WrongEntryKind);
            }
        }
        drop(directory_handle);
        stack.extend(child_directories.into_iter().rev());
    }
    Ok(entries)
}

#[cfg(windows)]
fn walk_trusted_source_tree<F>(
    root: &Path,
    mut on_file: F,
) -> Result<Vec<TreeEntry>, PackageStagingError>
where
    F: FnMut(
        &PackageRelativePath,
        &Path,
        &std::fs::File,
        FileIdentity,
    ) -> Result<(), PackageStagingError>,
{
    let root_handle = open_existing_directory(root)?;
    let root_final = final_path_from_handle(&root_handle)?;
    if !super::windows_paths_equal(&root_final, root) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let mut entries = Vec::new();
    let mut stack = vec![(
        root.to_path_buf(),
        Vec::<String>::new(),
        0_usize,
        root_handle,
    )];
    while let Some((directory, prefix, depth, directory_handle)) = stack.pop() {
        if depth > MAX_PACKAGE_PATH_DEPTH {
            return Err(PackageStagingError::BoundExceeded);
        }
        let mut pending = Vec::new();
        let read_dir = std::fs::read_dir(&directory).map_err(|_| PackageStagingError::Io)?;
        for entry in read_dir {
            let entry = entry.map_err(|_| PackageStagingError::Io)?;
            let name = entry
                .file_name()
                .to_str()
                .ok_or(PackageStagingError::InvalidRelativePath)?
                .to_owned();
            let relative_text = if prefix.is_empty() {
                name
            } else {
                format!("{}/{}", prefix.join("/"), name)
            };
            let relative = validate_relative_text(&relative_text)?;
            pending.push((relative, entry.path()));
        }
        pending.sort_by(|left, right| ordinal_path_cmp(&left.0, &right.0));
        for pair in pending.windows(2) {
            if ordinal_path_eq(&pair[0].0, &pair[1].0) {
                return Err(PackageStagingError::ManifestCollision);
            }
        }
        if pending.is_empty() && !prefix.is_empty() {
            return Err(PackageStagingError::TreeMismatch);
        }
        let mut child_directories = Vec::new();
        for (relative, path) in pending {
            if entries.len() >= MAX_ENUMERATED_ENTRIES {
                return Err(PackageStagingError::BoundExceeded);
            }
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| PackageStagingError::Io)?;
            if is_reparse_metadata(&metadata) {
                return Err(PackageStagingError::ReparsePoint);
            }
            if metadata.is_dir() {
                let child = open_existing_directory(&path)?;
                let final_path = final_path_from_handle(&child)?;
                if !super::windows_paths_equal(&final_path, &path) {
                    return Err(PackageStagingError::IdentityMismatch);
                }
                entries.push(TreeEntry {
                    relative: relative.clone(),
                    kind: TreeEntryKind::Directory,
                });
                child_directories.push((
                    path,
                    relative.components.clone(),
                    depth.saturating_add(1),
                    child,
                ));
            } else if metadata.is_file() {
                let file = open_trusted_source_file(&path)?;
                let identity = file_identity_from_open_handle(&file)?;
                let final_path = final_path_from_handle(&file)?;
                if !super::windows_paths_equal(&final_path, &path) {
                    return Err(PackageStagingError::IdentityMismatch);
                }
                on_file(&relative, &path, &file, identity)?;
                entries.push(TreeEntry {
                    relative,
                    kind: TreeEntryKind::File,
                });
            } else {
                return Err(PackageStagingError::WrongEntryKind);
            }
        }
        drop(directory_handle);
        stack.extend(child_directories.into_iter().rev());
    }
    Ok(entries)
}

#[cfg(windows)]
fn enumerate_trusted_source_tree(
    root: &Path,
    manifest: &PackageManifest,
) -> Result<Vec<TreeEntry>, PackageStagingError> {
    let entries = walk_trusted_source_tree(root, |_relative, _path, _file, _identity| Ok(()))?;
    let _ = manifest;
    Ok(entries)
}

#[cfg(not(windows))]
fn enumerate_tree(
    _root: &Path,
    _manifest: &PackageManifest,
) -> Result<Vec<TreeEntry>, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn reject_reparse_ancestors(path: &Path) -> Result<(), PackageStagingError> {
    let mut ancestors = path.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    for ancestor in ancestors {
        match std::fs::symlink_metadata(ancestor) {
            Ok(metadata) if is_reparse_metadata(&metadata) => {
                return Err(PackageStagingError::ReparsePoint);
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(PackageStagingError::RootUnavailable);
            }
            Err(_) => return Err(PackageStagingError::Io),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn retain_directory_contour(path: &Path) -> Result<Vec<std::fs::File>, PackageStagingError> {
    let mut ancestors = path.ancestors().collect::<Vec<_>>();
    ancestors.reverse();
    let mut contour = Vec::with_capacity(ancestors.len());
    for ancestor in ancestors {
        contour.push(open_existing_directory(ancestor)?);
    }
    Ok(contour)
}

#[cfg(windows)]
fn retain_destination_parent(
    path: &Path,
) -> Result<RetainedDestinationParent, PackageStagingError> {
    let contour = retain_directory_contour(path)?;
    let canonical =
        final_path_from_handle(contour.last().ok_or(PackageStagingError::RootUnavailable)?)?;
    verify_system_directory_handles(&contour)?;
    Ok(RetainedDestinationParent {
        path: canonical,
        _contour: contour,
    })
}

#[cfg(not(windows))]
fn retain_destination_parent(
    _path: &Path,
) -> Result<RetainedDestinationParent, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn open_existing_directory(path: &Path) -> Result<std::fs::File, PackageStagingError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PackageStagingError::RootUnavailable
        } else {
            PackageStagingError::Io
        }
    })?;
    let metadata = file.metadata().map_err(|_| PackageStagingError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PackageStagingError::ReparsePoint);
    }
    if !metadata.is_dir() {
        return Err(PackageStagingError::WrongEntryKind);
    }
    Ok(file)
}

#[cfg(windows)]
fn open_existing_directory_for_delete(path: &Path) -> Result<std::fs::File, PackageStagingError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PackageStagingError::RootUnavailable
        } else {
            PackageStagingError::Io
        }
    })?;
    let metadata = file.metadata().map_err(|_| PackageStagingError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PackageStagingError::ReparsePoint);
    }
    if !metadata.is_dir() {
        return Err(PackageStagingError::WrongEntryKind);
    }
    Ok(file)
}

#[cfg(not(windows))]
fn open_existing_directory_for_delete(_path: &Path) -> Result<std::fs::File, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(not(windows))]
fn open_existing_directory(_path: &Path) -> Result<std::fs::File, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn open_existing_file(path: &Path) -> Result<std::fs::File, PackageStagingError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PackageStagingError::RootUnavailable
        } else {
            PackageStagingError::Io
        }
    })?;
    let metadata = file.metadata().map_err(|_| PackageStagingError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PackageStagingError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(PackageStagingError::WrongEntryKind);
    }
    ensure_single_link(&file)?;
    Ok(file)
}

#[cfg(windows)]
fn open_trusted_source_file(path: &Path) -> Result<std::fs::File, PackageStagingError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            PackageStagingError::RootUnavailable
        } else {
            PackageStagingError::Io
        }
    })?;
    let metadata = file.metadata().map_err(|_| PackageStagingError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PackageStagingError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(PackageStagingError::WrongEntryKind);
    }
    ensure_single_link(&file)?;
    Ok(file)
}

#[cfg(not(windows))]
fn open_existing_file(_path: &Path) -> Result<std::fs::File, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn open_existing_file_for_delete(path: &Path) -> Result<std::fs::File, PackageStagingError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ | DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(|_| PackageStagingError::Io)?;
    let metadata = file.metadata().map_err(|_| PackageStagingError::Io)?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(PackageStagingError::ReparsePoint);
    }
    if !metadata.is_file() {
        return Err(PackageStagingError::WrongEntryKind);
    }
    ensure_single_link(&file)?;
    Ok(file)
}

#[cfg(not(windows))]
fn open_existing_file_for_delete(_path: &Path) -> Result<std::fs::File, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn file_identity_from_open_handle(
    file: &std::fs::File,
) -> Result<FileIdentity, PackageStagingError> {
    super::file_identity_from_handle(file).map_err(|_| PackageStagingError::Io)
}

#[cfg(windows)]
fn ensure_single_link(file: &std::fs::File) -> Result<(), PackageStagingError> {
    use std::os::windows::io::AsRawHandle as _;
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
        return Err(PackageStagingError::Io);
    }
    if information.nNumberOfLinks != 1 {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(not(windows))]
fn ensure_single_link(_file: &std::fs::File) -> Result<(), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(not(windows))]
fn file_identity_from_open_handle(
    _file: &std::fs::File,
) -> Result<FileIdentity, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn final_path_from_handle(file: &std::fs::File) -> Result<PathBuf, PackageStagingError> {
    super::final_windows_path_from_handle(file).map_err(map_protected_path_error)
}

#[cfg(not(windows))]
fn final_path_from_handle(_file: &std::fs::File) -> Result<PathBuf, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn path_exists(path: &Path) -> Result<bool, PackageStagingError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if is_reparse_metadata(&metadata) => Err(PackageStagingError::ReparsePoint),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(PackageStagingError::Io),
    }
}

#[cfg(not(windows))]
fn path_exists(_path: &Path) -> Result<bool, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn is_directory_path(path: &Path) -> Result<bool, PackageStagingError> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| PackageStagingError::Io)?;
    if is_reparse_metadata(&metadata) {
        return Err(PackageStagingError::ReparsePoint);
    }
    Ok(metadata.is_dir())
}

#[cfg(not(windows))]
fn is_directory_path(_path: &Path) -> Result<bool, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn is_reparse_metadata(metadata: &std::fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(windows)]
fn verify_system_security(
    file: &std::fs::File,
    directory: bool,
) -> Result<String, PackageStagingError> {
    let expected = super::OwnedSecurityDescriptor::for_installer_system_object(directory)
        .map_err(|_| PackageStagingError::SecurityMismatch)?;
    super::verify_exact_file_security(file, &expected, "S-1-5-18")
        .map_err(|_| PackageStagingError::SecurityMismatch)?;
    security_descriptor_digest(file)
}

#[cfg(not(windows))]
fn verify_system_security(
    _file: &std::fs::File,
    _directory: bool,
) -> Result<String, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn verify_system_directory_at(path: &Path) -> Result<(), PackageStagingError> {
    let file = open_existing_directory(path)?;
    let _ = verify_system_security(&file, true)?;
    Ok(())
}

#[cfg(windows)]
fn verify_system_directory_handles(contour: &[std::fs::File]) -> Result<(), PackageStagingError> {
    for directory in contour {
        let _ = verify_system_security(directory, true)?;
    }
    Ok(())
}

#[cfg(windows)]
fn security_descriptor_digest(file: &std::fs::File) -> Result<String, PackageStagingError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, LocalFree};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, GetSecurityDescriptorLength, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR,
    };
    let mut descriptor: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    let status = unsafe {
        // SAFETY: the handle is live and the descriptor output points to a
        // valid local; Windows owns the descriptor until LocalFree.
        GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(PackageStagingError::Io);
    }
    let length = unsafe {
        // SAFETY: descriptor is live and self-relative.
        GetSecurityDescriptorLength(descriptor)
    } as usize;
    let digest = if length == 0 {
        None
    } else {
        Some(unsafe {
            // SAFETY: Windows reported the exact descriptor byte length.
            let bytes = std::slice::from_raw_parts(descriptor.cast::<u8>(), length);
            hex_digest(bytes)
        })
    };
    unsafe { LocalFree(descriptor.cast()) };
    digest.ok_or(PackageStagingError::Io)
}

#[cfg(windows)]
fn create_generation_root(path: &Path) -> Result<std::fs::File, PackageStagingError> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let parent = path.parent().ok_or(PackageStagingError::RootUnavailable)?;
    let parent_file = open_existing_directory(parent)?;
    let descriptor = super::OwnedSecurityDescriptor::for_installer_system_object(true)
        .map_err(|_| PackageStagingError::SecurityMismatch)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| PackageStagingError::Io)?,
        lpSecurityDescriptor: descriptor.raw,
        bInheritHandle: 0,
    };
    let wide = super::wide(path);
    let created = unsafe {
        // SAFETY: path and descriptor remain live for this synchronous call;
        // CreateDirectoryW is atomic and does not adopt an existing object.
        CreateDirectoryW(wide.as_ptr(), &raw const attributes)
    };
    if created == 0 {
        let error = unsafe { GetLastError() };
        drop(parent_file);
        return if error == ERROR_ALREADY_EXISTS {
            Err(PackageStagingError::GenerationExists)
        } else {
            Err(PackageStagingError::Io)
        };
    }
    drop(parent_file);
    let Ok(root) = open_existing_directory_for_delete(path) else {
        return Err(PackageStagingError::RollbackRefused);
    };
    let Ok(identity) = file_identity_from_open_handle(&root) else {
        drop(root);
        return Err(PackageStagingError::RollbackRefused);
    };
    let result = (|| {
        let canonical = final_path_from_handle(&root)?;
        if !super::windows_paths_equal(&canonical, path) {
            return Err(PackageStagingError::IdentityMismatch);
        }
        verify_system_security(&root, true)?;
        flush_file_buffers(&root)?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok(root),
        Err(error) => Err(cleanup_created_handle(root, identity, error)),
    }
}

#[cfg(not(windows))]
fn create_generation_root(_path: &Path) -> Result<std::fs::File, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn create_destination_file(
    path: &Path,
) -> Result<(std::fs::File, FileIdentity), PackageStagingError> {
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::{
        ERROR_ALREADY_EXISTS, GetLastError, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    let parent = path.parent().ok_or(PackageStagingError::RootUnavailable)?;
    let parent_file = open_existing_directory(parent)?;
    let descriptor = super::OwnedSecurityDescriptor::for_installer_system_object(false)
        .map_err(|_| PackageStagingError::SecurityMismatch)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| PackageStagingError::Io)?,
        lpSecurityDescriptor: descriptor.raw,
        bInheritHandle: 0,
    };
    let wide = super::wide(path);
    let handle = unsafe {
        // SAFETY: path/descriptor remain live; CREATE_NEW makes the file
        // create-only and the share mode deliberately omits delete sharing.
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            std::ptr::null_mut(),
        )
    };
    drop(parent_file);
    if handle == INVALID_HANDLE_VALUE {
        return if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            Err(PackageStagingError::GenerationExists)
        } else {
            Err(PackageStagingError::Io)
        };
    }
    let file = unsafe {
        // SAFETY: handle is a uniquely owned newly-created file handle.
        std::fs::File::from_raw_handle(handle.cast())
    };
    let Ok(identity) = file_identity_from_open_handle(&file) else {
        drop(file);
        return Err(PackageStagingError::RollbackRefused);
    };
    let result = (|| {
        ensure_single_link(&file)?;
        let canonical = final_path_from_handle(&file)?;
        if !super::windows_paths_equal(&canonical, path) {
            return Err(PackageStagingError::IdentityMismatch);
        }
        verify_system_security(&file, false)?;
        Ok(())
    })();
    match result {
        Ok(()) => Ok((file, identity)),
        Err(error) => Err(cleanup_created_handle(file, identity, error)),
    }
}

#[cfg(not(windows))]
fn create_destination_file(
    _path: &Path,
) -> Result<(std::fs::File, FileIdentity), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn create_destination_directory(
    path: &Path,
) -> Result<(std::fs::File, FileIdentity, String), PackageStagingError> {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let parent = path.parent().ok_or(PackageStagingError::RootUnavailable)?;
    let parent_file = open_existing_directory(parent)?;
    let descriptor = super::OwnedSecurityDescriptor::for_installer_system_object(true)
        .map_err(|_| PackageStagingError::SecurityMismatch)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| PackageStagingError::Io)?,
        lpSecurityDescriptor: descriptor.raw,
        bInheritHandle: 0,
    };
    let wide = super::wide(path);
    let created = unsafe {
        // SAFETY: path and descriptor remain live for this synchronous call;
        // CreateDirectoryW is create-only and never adopts an existing entry.
        CreateDirectoryW(wide.as_ptr(), &raw const attributes)
    };
    drop(parent_file);
    if created == 0 {
        return if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            Err(PackageStagingError::GenerationExists)
        } else {
            Err(PackageStagingError::Io)
        };
    }
    let Ok(directory) = open_existing_directory_for_delete(path) else {
        return Err(PackageStagingError::RollbackRefused);
    };
    let Ok(identity) = file_identity_from_open_handle(&directory) else {
        drop(directory);
        return Err(PackageStagingError::RollbackRefused);
    };
    let result = (|| {
        let canonical = final_path_from_handle(&directory)?;
        if !super::windows_paths_equal(&canonical, path) {
            return Err(PackageStagingError::IdentityMismatch);
        }
        let security_descriptor_sha256 = verify_system_security(&directory, true)?;
        flush_file_buffers(&directory)?;
        Ok(security_descriptor_sha256)
    })();
    match result {
        Ok(security_descriptor_sha256) => Ok((directory, identity, security_descriptor_sha256)),
        Err(error) => Err(cleanup_created_handle(directory, identity, error)),
    }
}

#[cfg(not(windows))]
fn create_destination_directory(
    _path: &Path,
) -> Result<(std::fs::File, FileIdentity, String), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn cleanup_created_handle(
    file: std::fs::File,
    identity: FileIdentity,
    original: PackageStagingError,
) -> PackageStagingError {
    match delete_open_handle(file, identity) {
        Ok(()) => original,
        Err(_) => PackageStagingError::RollbackRefused,
    }
}

#[cfg(windows)]
fn snapshot_source_file(path: &Path, max_size: u64) -> Result<SourceSnapshot, PackageStagingError> {
    let mut file = open_trusted_source_file(path)?;
    let canonical = final_path_from_handle(&file)?;
    if !super::windows_paths_equal(&canonical, path) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let identity = file_identity_from_open_handle(&file)?;
    ensure_single_link(&file)?;
    let metadata = file.metadata().map_err(|_| PackageStagingError::Io)?;
    if metadata.len() > max_size || metadata.len() > MAX_PACKAGE_FILE_BYTES {
        return Err(PackageStagingError::BoundExceeded);
    }
    let size = metadata.len();
    file.seek(SeekFrom::Start(0))
        .map_err(|_| PackageStagingError::Io)?;
    let mut digest = Sha256::new();
    let mut header = Vec::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut read_total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| PackageStagingError::Io)?;
        if read == 0 {
            break;
        }
        read_total = read_total
            .checked_add(read as u64)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if read_total > max_size {
            return Err(PackageStagingError::BoundExceeded);
        }
        digest.update(&buffer[..read]);
        if header.len() < MAX_PE_HEADER_BYTES {
            let take = (MAX_PE_HEADER_BYTES - header.len()).min(read);
            header.extend_from_slice(&buffer[..take]);
        }
    }
    if read_total != size {
        return Err(PackageStagingError::SizeMismatch);
    }
    ensure_single_link(&file)?;
    let after_identity = file_identity_from_open_handle(&file)?;
    let after_path = final_path_from_handle(&file)?;
    let after_size = file.metadata().map_err(|_| PackageStagingError::Io)?.len();
    if after_identity != identity
        || !super::windows_paths_equal(&after_path, path)
        || after_size != size
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(SourceSnapshot {
        identity,
        size,
        sha256: hex_digest(&digest.finalize()),
        pe_header: header,
        file,
    })
}

#[cfg(windows)]
fn observe_source_handle(
    file: &std::fs::File,
    expected_path: &Path,
    max_size: u64,
) -> Result<ObservedSourceRead, PackageStagingError> {
    observe_source_handle_with_post_read_hook(file, expected_path, max_size, || {})
}

#[cfg(windows)]
fn observe_source_handle_with_post_read_hook<H: FnOnce()>(
    file: &std::fs::File,
    expected_path: &Path,
    max_size: u64,
    post_read_hook: H,
) -> Result<ObservedSourceRead, PackageStagingError> {
    let identity = file_identity_from_open_handle(file)?;
    let before_path = final_path_from_handle(file)?;
    if !super::windows_paths_equal(&before_path, expected_path) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let before_size = file.metadata().map_err(|_| PackageStagingError::Io)?.len();
    if before_size > max_size || before_size > MAX_PACKAGE_FILE_BYTES {
        return Err(PackageStagingError::BoundExceeded);
    }
    let mut reader = file.try_clone().map_err(|_| PackageStagingError::Io)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| PackageStagingError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut size = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| PackageStagingError::Io)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if size > max_size || size > MAX_PACKAGE_FILE_BYTES {
            return Err(PackageStagingError::BoundExceeded);
        }
        digest.update(&buffer[..read]);
    }
    if size != before_size {
        return Err(PackageStagingError::SizeMismatch);
    }
    post_read_hook();
    ensure_single_link(file)?;
    let after_identity = file_identity_from_open_handle(file)?;
    let after_path = final_path_from_handle(file)?;
    let after_size = file.metadata().map_err(|_| PackageStagingError::Io)?.len();
    if after_identity != identity {
        return Err(PackageStagingError::IdentityMismatch);
    }
    if !super::windows_paths_equal(&after_path, expected_path) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    if after_size != before_size {
        return Err(PackageStagingError::SizeMismatch);
    }
    Ok(ObservedSourceRead {
        size,
        sha256: format!("{:x}", digest.finalize()),
    })
}

#[cfg(windows)]
#[derive(Debug)]
struct ObservedSourceRead {
    size: u64,
    sha256: String,
}

#[cfg(not(windows))]
fn snapshot_source_file(
    _path: &Path,
    _max_size: u64,
) -> Result<SourceSnapshot, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn copy_source_to_destination(
    source_snapshot: &SourceSnapshot,
    destination: &mut std::fs::File,
    max_size: u64,
) -> Result<String, PackageStagingError> {
    let mut source = source_snapshot
        .file
        .try_clone()
        .map_err(|_| PackageStagingError::Io)?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| PackageStagingError::Io)?;
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|_| PackageStagingError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|_| PackageStagingError::Io)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if total > max_size {
            return Err(PackageStagingError::BoundExceeded);
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|_| PackageStagingError::Io)?;
        digest.update(&buffer[..read]);
    }
    if total != source_snapshot.size {
        return Err(PackageStagingError::SizeMismatch);
    }
    flush_file_buffers(destination)?;
    Ok(hex_digest(&digest.finalize()))
}

#[cfg(not(windows))]
fn copy_source_to_destination(
    _source: &SourceSnapshot,
    _destination: &mut std::fs::File,
    _max_size: u64,
) -> Result<String, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn flush_file_buffers(file: &std::fs::File) -> Result<(), PackageStagingError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
    let ok = unsafe {
        // SAFETY: file owns a live writable handle.
        FlushFileBuffers(file.as_raw_handle().cast())
    };
    if ok == 0 {
        return Err(PackageStagingError::Io);
    }
    Ok(())
}

#[cfg(not(windows))]
fn flush_file_buffers(_file: &std::fs::File) -> Result<(), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn read_destination_snapshot(
    path: &Path,
    max_size: u64,
    expected_identity: FileIdentity,
) -> Result<DestinationSnapshot, PackageStagingError> {
    let file = open_existing_file(path)?;
    let actual_identity = file_identity_from_open_handle(&file)?;
    if actual_identity != expected_identity {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let metadata = file.metadata().map_err(|_| PackageStagingError::Io)?;
    if metadata.len() > max_size {
        return Err(PackageStagingError::BoundExceeded);
    }
    let mut reader = file.try_clone().map_err(|_| PackageStagingError::Io)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| PackageStagingError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut size = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| PackageStagingError::Io)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if size > max_size {
            return Err(PackageStagingError::BoundExceeded);
        }
        digest.update(&buffer[..read]);
    }
    if size != metadata.len() {
        return Err(PackageStagingError::SizeMismatch);
    }
    let security_descriptor_sha256 = verify_system_security(&file, false)?;
    Ok(DestinationSnapshot {
        size,
        sha256: hex_digest(&digest.finalize()),
        security_descriptor_sha256,
    })
}

#[cfg(windows)]
fn read_destination_snapshot_handle(
    file: &std::fs::File,
    expected_path: &Path,
    max_size: u64,
    expected_identity: FileIdentity,
) -> Result<DestinationSnapshot, PackageStagingError> {
    let actual_identity = file_identity_from_open_handle(file)?;
    if actual_identity != expected_identity {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let canonical = final_path_from_handle(file)?;
    if !super::windows_paths_equal(&canonical, expected_path) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let metadata = file.metadata().map_err(|_| PackageStagingError::Io)?;
    if metadata.len() > max_size {
        return Err(PackageStagingError::BoundExceeded);
    }
    let mut reader = file.try_clone().map_err(|_| PackageStagingError::Io)?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|_| PackageStagingError::Io)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut size = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| PackageStagingError::Io)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if size > max_size {
            return Err(PackageStagingError::BoundExceeded);
        }
        digest.update(&buffer[..read]);
    }
    if size != metadata.len() {
        return Err(PackageStagingError::SizeMismatch);
    }
    let security_descriptor_sha256 = verify_system_security(file, false)?;
    Ok(DestinationSnapshot {
        size,
        sha256: hex_digest(&digest.finalize()),
        security_descriptor_sha256,
    })
}

#[cfg(not(windows))]
fn read_destination_snapshot_handle(
    _file: &std::fs::File,
    _expected_path: &Path,
    _max_size: u64,
    _expected_identity: FileIdentity,
) -> Result<DestinationSnapshot, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(not(windows))]
fn read_destination_snapshot(
    _path: &Path,
    _max_size: u64,
    _expected_identity: FileIdentity,
) -> Result<DestinationSnapshot, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn read_file_prefix(path: &Path, limit: usize) -> Result<Vec<u8>, PackageStagingError> {
    let file = open_existing_file(path)?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).map_err(|_| PackageStagingError::BoundExceeded)?)
        .read_to_end(&mut bytes)
        .map_err(|_| PackageStagingError::Io)?;
    Ok(bytes)
}

#[cfg(not(windows))]
fn read_file_prefix(_path: &Path, _limit: usize) -> Result<Vec<u8>, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn rollback_created_tree(mut created: CreatedTree) -> Result<(), PackageStagingError> {
    for file in created.files.drain(..).rev() {
        delete_open_handle(file.file, file.identity)?;
    }
    for directory in created.directories.drain(..).rev() {
        delete_open_handle(directory.file, directory.identity)?;
    }
    drop(created.root_file);
    let root = open_existing_directory_for_delete(&created.root_path)?;
    let actual = file_identity_from_open_handle(&root)?;
    if actual != created.root_identity {
        return Err(PackageStagingError::IdentityMismatch);
    }
    delete_open_handle(root, actual)
}

#[cfg(not(windows))]
fn rollback_created_tree(_created: CreatedTree) -> Result<(), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn delete_open_handle(
    file: std::fs::File,
    expected_identity: FileIdentity,
) -> Result<(), PackageStagingError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_DISPOSITION_INFO, FileDispositionInfo, SetFileInformationByHandle,
    };
    let actual = file_identity_from_open_handle(&file)?;
    if actual != expected_identity {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    let ok = unsafe {
        // SAFETY: the handle was opened with DELETE and no delete sharing; the
        // disposition buffer has the exact documented layout.
        SetFileInformationByHandle(
            file.as_raw_handle().cast(),
            FileDispositionInfo,
            (&raw const disposition).cast(),
            u32::try_from(std::mem::size_of::<FILE_DISPOSITION_INFO>())
                .map_err(|_| PackageStagingError::Io)?,
        )
    };
    if ok == 0 {
        return Err(PackageStagingError::RollbackRefused);
    }
    drop(file);
    Ok(())
}

#[cfg(not(windows))]
fn delete_open_handle(
    _file: std::fs::File,
    _expected_identity: FileIdentity,
) -> Result<(), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, executable: bool) -> PackageFileSpec {
        PackageFileSpec {
            relative_path: path.to_owned(),
            executable,
            max_size: 1024,
        }
    }

    #[test]
    fn relative_path_rejects_escape_ads_device_and_trailing_forms() {
        for path in [
            "",
            "/absolute",
            "\\absolute",
            "..\\escape",
            ".\\dot",
            "a\\..\\b",
            "a:stream",
            "C:\\drive",
            "\\\\server\\share",
            "\\\\?\\C:\\verbatim",
            "\\\\.\\pipe\\x",
            "\\??\\C:\\nt",
            "CON",
            "NUL.txt",
            "COM1",
            "LPT9.log",
            "a.",
            "a ",
            "a//b",
            "a\\\\b",
        ] {
            assert!(
                validate_relative_text(path).is_err(),
                "path unexpectedly accepted: {path:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_root_rejects_verbatim_device_and_traversal_inputs() {
        for path in [
            r"\\?\C:\Windows",
            r"\\.\pipe\eliot",
            r"\\??\C:\Windows",
            r"C:\Windows\..\Temp",
        ] {
            assert!(
                matches!(
                    TrustedSourceBundle::open(Path::new(path)),
                    Err(PackageStagingError::RootUnavailable)
                ),
                "source root unexpectedly accepted: {path}"
            );
        }
    }

    #[test]
    fn relative_path_and_manifest_digest_are_stable_under_reordering() {
        let first = PackageManifest::new(
            "g1",
            vec![file("Bin/Z.dll", false), file("Bin/A.exe", true)],
        )
        .expect("manifest");
        let second = PackageManifest::new(
            "g1",
            vec![file("Bin/A.exe", true), file("Bin/Z.dll", false)],
        )
        .expect("manifest");
        assert_eq!(first.canonical_digest(), second.canonical_digest());
        assert_eq!(
            validate_relative_text("bin/A.exe").expect("path").as_str(),
            "bin/A.exe"
        );
    }

    #[cfg(windows)]
    #[test]
    fn unicode_ordinal_component_order_and_collision_are_explicit() {
        let manifest = PackageManifest::new(
            "g1",
            vec![
                file("épsilon.txt", false),
                file("zeta.txt", false),
                file("alpha.txt", false),
            ],
        )
        .expect("unicode manifest");
        let mut expected = manifest
            .files
            .iter()
            .map(|file| validate_relative_text(&file.relative_path).expect("path"))
            .collect::<Vec<_>>();
        expected.sort_by(ordinal_path_cmp);
        assert_eq!(
            manifest
                .files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>(),
            expected
                .iter()
                .map(PackageRelativePath::as_str)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            PackageManifest::new(
                "g1",
                vec![file("unicode/É.txt", false), file("unicode/é.txt", false)],
            ),
            Err(PackageStagingError::ManifestCollision)
        );
    }

    #[test]
    fn bounded_manifest_inputs_are_rejected_before_filesystem_work() {
        assert_eq!(
            PackageFileSpec::new("oversized.bin", false, MAX_PACKAGE_FILE_BYTES + 1),
            Err(PackageStagingError::BoundExceeded)
        );

        let too_many = (0..=MAX_PACKAGE_FILES)
            .map(|index| file(&format!("f-{index}.bin"), false))
            .collect();
        assert_eq!(
            PackageManifest::new("generation", too_many),
            Err(PackageStagingError::BoundExceeded)
        );

        let too_deep = std::iter::repeat_n("x", MAX_PACKAGE_PATH_DEPTH + 1)
            .collect::<Vec<_>>()
            .join("/");
        assert_eq!(
            validate_relative_text(&too_deep),
            Err(PackageStagingError::BoundExceeded)
        );
        assert_eq!(
            PackageManifest::new(
                "generation",
                vec![file("Bin/app.bin", false), file("bin/APP.BIN", false)],
            ),
            Err(PackageStagingError::ManifestCollision)
        );
    }

    #[test]
    fn wintrust_statuses_are_typed_and_fail_closed() {
        assert_eq!(
            classify_wintrust_status(0x800b_0100),
            AuthenticodeVerdict::Unsigned
        );
        assert_eq!(
            classify_wintrust_status(0x8009_2013),
            AuthenticodeVerdict::RevocationUnknown
        );
        assert_eq!(
            classify_wintrust_status(0x800b_0109),
            AuthenticodeVerdict::Invalid
        );
        assert_eq!(
            classify_wintrust_status(0xdead_beef),
            AuthenticodeVerdict::Unknown
        );
        for status in [0x800b_0100, 0x8009_2013, 0xdead_beef] {
            assert_ne!(classify_wintrust_status(status), AuthenticodeVerdict::Valid);
        }
    }

    #[test]
    fn exact_tree_matching_rejects_extra_missing_and_kind_mismatch() {
        let manifest = PackageManifest::new(
            "generation",
            vec![file("bin/app.exe", true), file("readme.txt", false)],
        )
        .expect("manifest");
        let expected = expected_tree(&manifest).expect("expected tree");
        ensure_tree_matches_manifest(&expected, &manifest).expect("exact tree");

        let mut extra = expected.clone();
        extra.push(TreeEntry {
            relative: validate_relative_text("foreign.txt").expect("path"),
            kind: TreeEntryKind::File,
        });
        assert_eq!(
            ensure_tree_matches_manifest(&extra, &manifest),
            Err(PackageStagingError::TreeMismatch)
        );

        let mut missing = expected.clone();
        missing.pop();
        assert_eq!(
            ensure_tree_matches_manifest(&missing, &manifest),
            Err(PackageStagingError::TreeMismatch)
        );

        let mut wrong_kind = expected;
        let entry = wrong_kind
            .iter_mut()
            .find(|entry| entry.kind == TreeEntryKind::File)
            .expect("file entry");
        entry.kind = TreeEntryKind::Directory;
        assert_eq!(
            ensure_tree_matches_manifest(&wrong_kind, &manifest),
            Err(PackageStagingError::TreeMismatch)
        );
    }

    #[test]
    fn directory_receipt_is_bound_to_the_manifest_and_security_digest() {
        let manifest =
            PackageManifest::new("generation", vec![file("bin/app.bin", false)]).expect("manifest");
        let receipt = StagingReceipt {
            generation: manifest.generation.clone(),
            root_path: PathBuf::from(r"C:\ProgramData\Eliot\generation"),
            root_identity: FileIdentity {
                volume_serial_number: 1,
                file_index: 2,
            },
            directories: vec![StagedDirectoryReceipt {
                relative_path: "bin".to_owned(),
                identity: FileIdentity {
                    volume_serial_number: 1,
                    file_index: 3,
                },
                security_descriptor_sha256: "a".repeat(64),
            }],
            files: Vec::new(),
            manifest_sha256: manifest.canonical_digest(),
        };
        validate_receipt_directories(&receipt, &manifest).expect("directory receipt");

        let mut foreign = receipt.clone();
        foreign.directories[0].relative_path = "foreign".to_owned();
        assert_eq!(
            validate_receipt_directories(&foreign, &manifest),
            Err(PackageStagingError::TreeMismatch)
        );
        let mut wrong_security = receipt;
        wrong_security.directories[0].security_descriptor_sha256 = "b".repeat(64);
        assert!(validate_receipt_directories(&wrong_security, &manifest).is_ok());
        wrong_security.directories[0].security_descriptor_sha256 = "not-a-digest".to_owned();
        assert_eq!(
            validate_receipt_directories(&wrong_security, &manifest),
            Err(PackageStagingError::SecurityMismatch)
        );
    }

    #[test]
    fn parser_rejects_truncated_and_x86_and_accepts_minimal_amd64() {
        assert_eq!(parse_pe_coff(b"MZ"), Err(PeCoffError::Truncated));
        let mut x86 = minimal_pe(0x14c, 0x10b);
        assert_eq!(parse_pe_coff(&x86), Err(PeCoffError::WrongArchitecture));
        x86[0x3c] = 0xff;
        assert_eq!(parse_pe_coff(&x86), Err(PeCoffError::InvalidSignature));
        let amd64 = minimal_pe(0x8664, 0x20b);
        assert_eq!(parse_pe_coff(&amd64).expect("amd64").machine, 0x8664);
    }

    fn minimal_pe(machine: u16, magic: u16) -> Vec<u8> {
        let pe_offset = 0x80_usize;
        let optional_size = 0xf0_usize;
        let section_end = pe_offset + 4 + 20 + optional_size + 40;
        let mut bytes = vec![0_u8; section_end];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[0x3c..0x40].copy_from_slice(&u32::try_from(pe_offset).expect("offset").to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        bytes[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        bytes[coff + 16..coff + 18].copy_from_slice(
            &u16::try_from(optional_size)
                .expect("optional size")
                .to_le_bytes(),
        );
        bytes[coff + 18..coff + 20].copy_from_slice(&2_u16.to_le_bytes());
        bytes[coff + 20..coff + 22].copy_from_slice(&magic.to_le_bytes());
        bytes
    }

    #[cfg(windows)]
    #[test]
    fn unsigned_authenticode_never_returns_valid_evidence() {
        let path = std::env::temp_dir().join(format!(
            "eliot-package-unsigned-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::write(&path, b"MZ unsigned fixture").expect("write");
        let file = open_existing_file(&path).expect("open");
        let identity = file_identity_from_open_handle(&file).expect("identity");
        let mut reader = file.try_clone().expect("clone");
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).expect("read");
        let sha256 = hex_digest(&bytes);
        let result = WindowsAuthenticodeVerifier.verify(&path, identity, &sha256);
        let _ = std::fs::remove_file(path);
        if let Ok(evidence) = result {
            assert_ne!(evidence.verdict, AuthenticodeVerdict::Valid);
        }
    }

    #[cfg(windows)]
    #[test]
    fn junction_is_rejected_by_no_follow_directory_open_and_enumeration() {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-reparse-{}",
            super::super::unique_suffix()
        ));
        let outside = std::env::temp_dir().join(format!(
            "eliot-package-reparse-outside-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        std::fs::create_dir(&outside).expect("outside");
        let junction = root.join("junction");
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()
            .expect("mklink");
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            let privilege_specific = output.status.code() == Some(5)
                || stderr.contains("privilege")
                || stderr.contains("access is denied");
            if privilege_specific {
                eprintln!(
                    "SKIP junction source observation: privilege-specific mklink failure: {}",
                    stderr.trim()
                );
                std::fs::remove_dir(&root).expect("root cleanup");
                std::fs::remove_dir(&outside).expect("outside cleanup");
                return;
            }
            panic!(
                "mklink /J failed for a non-privilege reason: {}",
                stderr.trim()
            );
        }
        assert!(matches!(
            open_existing_directory(&junction),
            Err(PackageStagingError::ReparsePoint)
        ));
        let manifest = PackageManifest::new("generation", Vec::new()).expect("manifest");
        assert_eq!(
            enumerate_tree(&root, &manifest),
            Err(PackageStagingError::ReparsePoint)
        );
        let source = TrustedSourceBundle::open(&root).expect("retained source");
        assert_eq!(source.observe(), Err(PackageStagingError::ReparsePoint));
        drop(source);
        std::fs::remove_dir(&junction).expect("junction cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
        std::fs::remove_dir(&outside).expect("outside cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn hardlink_is_rejected_by_single_link_identity_guard() {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-hardlink-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        let original = root.join("original.bin");
        let link = root.join("link.bin");
        std::fs::write(&original, b"hardlink fixture").expect("write");
        std::fs::hard_link(&original, &link).expect("hard link");
        assert!(matches!(
            open_existing_file(&original),
            Err(PackageStagingError::IdentityMismatch)
        ));
        assert!(matches!(
            open_existing_file(&link),
            Err(PackageStagingError::IdentityMismatch)
        ));
        let source = TrustedSourceBundle::open(&root).expect("source root");
        assert_eq!(source.observe(), Err(PackageStagingError::IdentityMismatch));
        drop(source);
        std::fs::remove_file(&link).expect("link cleanup");
        std::fs::remove_file(&original).expect("original cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observation_is_bounded_sorted_and_read_only() {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-source-observe-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        std::fs::create_dir(root.join("bin")).expect("bin");
        std::fs::write(root.join("bin/z.txt"), b"z").expect("z");
        std::fs::write(root.join("a.txt"), b"a").expect("a");
        let source = TrustedSourceBundle::open(&root).expect("retained source");
        let moved = root.with_file_name(format!(
            "eliot-package-source-observe-moved-{}",
            super::super::unique_suffix()
        ));
        assert!(
            std::fs::rename(&root, &moved).is_err(),
            "retained ancestor contour must block substitution"
        );
        let observed = source.observe().expect("source observation");
        assert_eq!(observed.total_bytes, 2);
        assert_eq!(
            observed
                .files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>(),
            vec!["a.txt", "bin/z.txt"]
        );
        assert_eq!(observed.files[0].size, 1);
        assert_eq!(observed.files[0].sha256, hex_digest(b"a"));
        assert!(root.join("a.txt").is_file());
        drop(source);
        std::fs::remove_file(root.join("bin/z.txt")).expect("z cleanup");
        std::fs::remove_dir(root.join("bin")).expect("bin cleanup");
        std::fs::remove_file(root.join("a.txt")).expect("a cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observation_rejects_empty_child_directories() {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-source-empty-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        std::fs::create_dir(root.join("empty")).expect("empty");
        let source = TrustedSourceBundle::open(&root).expect("retained source");
        assert_eq!(source.observe(), Err(PackageStagingError::TreeMismatch));
        drop(source);
        std::fs::remove_dir(root.join("empty")).expect("empty cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observation_rejects_file_and_depth_bounds() {
        let file_root = std::env::temp_dir().join(format!(
            "eliot-package-source-file-bound-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&file_root).expect("file root");
        for index in 0..=MAX_PACKAGE_FILES {
            std::fs::write(file_root.join(format!("file-{index}.bin")), []).expect("file");
        }
        let source = TrustedSourceBundle::open(&file_root).expect("retained source");
        assert_eq!(source.observe(), Err(PackageStagingError::BoundExceeded));
        drop(source);
        for index in 0..=MAX_PACKAGE_FILES {
            std::fs::remove_file(file_root.join(format!("file-{index}.bin")))
                .expect("file cleanup");
        }
        std::fs::remove_dir(&file_root).expect("file root cleanup");

        let depth_root = std::env::temp_dir().join(format!(
            "eliot-package-source-depth-bound-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&depth_root).expect("depth root");
        let mut deep = depth_root.clone();
        for index in 0..=MAX_PACKAGE_PATH_DEPTH {
            deep.push(format!("d{index}"));
        }
        std::fs::create_dir_all(&deep).expect("deep dirs");
        std::fs::write(deep.join("file.bin"), b"deep").expect("deep file");
        let source = TrustedSourceBundle::open(&depth_root).expect("retained depth source");
        assert_eq!(source.observe(), Err(PackageStagingError::BoundExceeded));
        drop(source);
        std::fs::remove_dir_all(&depth_root).expect("depth cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observation_post_read_identity_seam_rejects_replacement() {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-source-toctou-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        let path = root.join("mutable.bin");
        std::fs::write(&path, b"before").expect("before");
        let file = open_trusted_source_file(&path).expect("open");
        let mut hook_write_succeeded = false;
        let result = observe_source_handle_with_post_read_hook(&file, &path, 64, || {
            if std::fs::write(&path, b"replacement-with-a-different-size").is_ok() {
                hook_write_succeeded = true;
            }
        });
        if hook_write_succeeded {
            assert!(matches!(result, Err(PackageStagingError::SizeMismatch)));
        } else {
            assert!(
                result.is_ok(),
                "exclusive handle should block same-size/different-size writer"
            );
            assert!(matches!(
                std::fs::write(&path, b"replacement-with-a-different-size"),
                Err(_)
            ));
        }
        drop(file);
        std::fs::remove_file(&path).expect("file cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_same_size_overwrite_is_blocked_or_detected() {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-source-same-size-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        let path = root.join("same.bin");
        std::fs::write(&path, b"AAAAAA").expect("before");
        let before_hash = hex_digest(b"AAAAAA");
        let file = open_trusted_source_file(&path).expect("open");
        let mut hook_write_succeeded = false;
        let result = observe_source_handle_with_post_read_hook(&file, &path, 64, || {
            if std::fs::write(&path, b"BBBBBB").is_ok() {
                hook_write_succeeded = true;
            }
        });
        if hook_write_succeeded {
            assert!(result.is_err(), "same-size mutation must be detected");
        } else {
            let observed = result.expect("blocked same-size write should still observe original");
            assert_eq!(observed.sha256, before_hash);
            assert_eq!(observed.size, 6);
        }
        drop(file);
        assert_eq!(std::fs::read(&path).expect("read"), b"AAAAAA");
        std::fs::remove_file(&path).expect("file cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observer_fails_closed_when_writer_holds_file() {
        use std::os::windows::fs::OpenOptionsExt as _;
        let root = std::env::temp_dir().join(format!(
            "eliot-package-writer-hold-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        let path = root.join("held.bin");
        std::fs::write(&path, b"held").expect("before");
        let writer = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&path)
            .or_else(|_| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&path)
            })
            .expect("writer hold");
        let trusted_open = open_trusted_source_file(&path);
        assert!(
            trusted_open.is_err(),
            "observer must fail closed when writer holds file"
        );
        assert!(matches!(
            trusted_open,
            Err(PackageStagingError::Io) | Err(PackageStagingError::RootUnavailable)
        ));
        let source = TrustedSourceBundle::open(&root).expect("source");
        let observed = source.observe();
        assert!(
            observed.is_err(),
            "observe must fail closed when file is write-locked"
        );
        drop(writer);
        drop(source);
        std::fs::remove_file(&path).expect("file cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn staging_copies_from_retained_handle_not_reopened_path() {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-retained-copy-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        let source_path = root.join("source.bin");
        let dest_path = root.join("dest.bin");
        std::fs::write(&source_path, b"retained").expect("source");
        let snapshot = snapshot_source_file(&source_path, 64).expect("snapshot");
        let original_hash = snapshot.sha256.clone();
        let original_size = snapshot.size;
        let original_identity = snapshot.identity;
        let writer_attempt = std::fs::OpenOptions::new().write(true).open(&source_path);
        assert!(
            writer_attempt.is_err(),
            "exclusive snapshot handle must block writer"
        );
        let mut dest = std::fs::File::create(&dest_path).expect("dest");
        let copied_hash = copy_source_to_destination(&snapshot, &mut dest, 64).expect("copy");
        assert_eq!(copied_hash, original_hash);
        drop(dest);
        assert_eq!(std::fs::read(&dest_path).expect("read dest"), b"retained");
        drop(snapshot);
        std::fs::write(&source_path, b"mutated")
            .expect("mutate after handle closed should succeed");
        assert_eq!(
            std::fs::read(&source_path).expect("read mutated"),
            b"mutated"
        );
        assert_ne!(original_hash, hex_digest(b"mutated"));
        assert_eq!(original_size, 8);
        let _ = original_identity;
        std::fs::remove_file(&source_path).expect("source cleanup");
        std::fs::remove_file(&dest_path).expect("dest cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn source_snapshot_copy_reports_hash_and_size_changes() {
        use std::io::Write as _;

        let root = std::env::temp_dir().join(format!(
            "eliot-package-copy-fault-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        let source_path = root.join("source.bin");
        let destination_path = root.join("destination.bin");
        std::fs::write(&source_path, b"before").expect("source");
        let snapshot = snapshot_source_file(&source_path, 64).expect("snapshot");
        let writer_blocked = std::fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .is_err();
        if writer_blocked {
            let mut destination = std::fs::File::create(&destination_path).expect("destination");
            let copied = copy_source_to_destination(&snapshot, &mut destination, 64)
                .expect("copy blocked writer should retain original bytes");
            assert_eq!(copied, snapshot.sha256);
            drop(destination);
        } else {
            let mut changed = std::fs::OpenOptions::new()
                .write(true)
                .open(&source_path)
                .expect("open source");
            changed.write_all(b"after!").expect("mutate source");
            drop(changed);
            let mut destination = std::fs::File::create(&destination_path).expect("destination");
            let copied = copy_source_to_destination(&snapshot, &mut destination, 64)
                .expect("copy changed bytes");
            assert_ne!(
                copied, snapshot.sha256,
                "changed source must fail hash proof"
            );
            drop(destination);
        }
        drop(snapshot);

        std::fs::write(&source_path, b"before").expect("reset source");
        let snapshot = snapshot_source_file(&source_path, 64).expect("snapshot");
        let writer_blocked = std::fs::OpenOptions::new()
            .append(true)
            .open(&source_path)
            .is_err();
        if writer_blocked {
            let mut destination = std::fs::File::create(&destination_path).expect("destination");
            let copied = copy_source_to_destination(&snapshot, &mut destination, 64)
                .expect("copy should succeed with original bytes when writer blocked");
            assert_eq!(copied, snapshot.sha256);
            drop(destination);
        } else {
            let mut appended = std::fs::OpenOptions::new()
                .append(true)
                .open(&source_path)
                .expect("append source");
            appended.write_all(b"-size").expect("grow source");
            drop(appended);
            let mut destination = std::fs::File::create(&destination_path).expect("destination");
            assert_eq!(
                copy_source_to_destination(&snapshot, &mut destination, 64),
                Err(PackageStagingError::SizeMismatch)
            );
            drop(destination);
        }
        drop(snapshot);
        std::fs::remove_file(&source_path).expect("source cleanup");
        std::fs::remove_file(&destination_path).expect("destination cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn destination_readback_rejects_identity_and_security_mismatch() {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-readback-fault-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        let path = root.join("destination.bin");
        std::fs::write(&path, b"readback").expect("write");
        let file = open_existing_file(&path).expect("open");
        let identity = file_identity_from_open_handle(&file).expect("identity");
        let wrong_identity = FileIdentity {
            file_index: identity.file_index.saturating_add(1),
            ..identity
        };
        assert!(matches!(
            read_destination_snapshot(&path, 64, wrong_identity),
            Err(PackageStagingError::IdentityMismatch)
        ));
        assert_eq!(
            verify_system_security(&file, false),
            Err(PackageStagingError::SecurityMismatch)
        );
        drop(file);
        std::fs::remove_file(&path).expect("file cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn create_new_file_collision_never_overwrites_existing_bytes() {
        use std::io::Write as _;

        let root = std::env::temp_dir().join(format!(
            "eliot-package-create-new-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        let path = root.join("immutable.bin");
        let (mut first, _) = match create_destination_file(&path) {
            Ok(file) => file,
            Err(PackageStagingError::Io | PackageStagingError::SecurityMismatch) => {
                // The fixture needs a token able to apply the production
                // SystemService ACL; the test remains useful on developer
                // machines where that policy is unavailable.
                std::fs::remove_dir(&root).expect("root cleanup");
                return;
            }
            Err(error) => panic!("create-new fixture failed: {error}"),
        };
        first.write_all(b"sentinel").expect("write");
        flush_file_buffers(&first).expect("flush");
        drop(first);
        assert!(matches!(
            create_destination_file(&path),
            Err(PackageStagingError::GenerationExists)
        ));
        assert_eq!(std::fs::read(&path).expect("readback"), b"sentinel");
        std::fs::remove_file(&path).expect("file cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn create_new_generation_root_collision_is_never_adopted() {
        let parent = std::env::temp_dir().join(format!(
            "eliot-package-generation-parent-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&parent).expect("parent");
        let generation = parent.join("generation");
        let first = match create_generation_root(&generation) {
            Ok(root) => root,
            Err(PackageStagingError::Io | PackageStagingError::SecurityMismatch) => {
                // The fixture needs a token able to apply the production
                // SystemService ACL; the test remains useful on developer
                // machines where that policy is unavailable.
                std::fs::remove_dir(&parent).expect("parent cleanup");
                return;
            }
            Err(error) => panic!("generation create fixture failed: {error}"),
        };
        drop(first);
        assert!(matches!(
            create_generation_root(&generation),
            Err(PackageStagingError::GenerationExists)
        ));
        std::fs::remove_dir(&generation).expect("generation cleanup");
        std::fs::remove_dir(&parent).expect("parent cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn exact_root_delete_uses_a_delete_capable_no_follow_handle() {
        let parent = std::env::temp_dir().join(format!(
            "eliot-package-generation-delete-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&parent).expect("parent");
        let generation = parent.join("generation");
        let root = match create_generation_root(&generation) {
            Ok(root) => root,
            Err(PackageStagingError::Io | PackageStagingError::SecurityMismatch) => {
                std::fs::remove_dir(&parent).expect("parent cleanup");
                return;
            }
            Err(error) => panic!("generation delete fixture failed: {error}"),
        };
        let identity = file_identity_from_open_handle(&root).expect("identity");
        drop(root);
        let root = open_existing_directory_for_delete(&generation).expect("delete handle");
        delete_open_handle(root, identity).expect("delete root");
        assert!(!generation.exists());
        std::fs::remove_dir(&parent).expect("parent cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn nested_directory_creation_is_create_only_and_reverse_owned_delete() {
        let parent = std::env::temp_dir().join(format!(
            "eliot-package-nested-directory-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&parent).expect("parent");
        let first_path = parent.join("bin");
        let second_path = first_path.join("x64");
        let (first, first_identity, _) = match create_destination_directory(&first_path) {
            Ok(directory) => directory,
            Err(PackageStagingError::Io | PackageStagingError::SecurityMismatch) => {
                std::fs::remove_dir(&parent).expect("parent cleanup");
                return;
            }
            Err(error) => panic!("nested directory fixture failed: {error}"),
        };
        let (second, second_identity, _) =
            create_destination_directory(&second_path).expect("second directory");
        assert!(second_path.is_dir());
        delete_open_handle(second, second_identity).expect("second delete");
        delete_open_handle(first, first_identity).expect("first delete");
        assert!(!first_path.exists());
        std::fs::remove_dir(&parent).expect("parent cleanup");
    }

    #[test]
    fn partial_tree_observation_cannot_be_promoted_to_matching() {
        let observation = PackageStagingObservation::Mismatch(PackageStagingError::PartialTree);
        assert!(matches!(
            observation,
            PackageStagingObservation::Mismatch(PackageStagingError::PartialTree)
        ));
        assert!(!matches!(
            PackageStagingObservation::Mismatch(PackageStagingError::PartialTree),
            PackageStagingObservation::Matching(_)
        ));
    }

    #[cfg(windows)]
    #[test]
    fn rollback_delete_refuses_foreign_identity_and_keeps_file() {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-rollback-fault-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root).expect("root");
        let path = root.join("owned.bin");
        std::fs::write(&path, b"owned").expect("write");
        let handle = open_existing_file_for_delete(&path).expect("open for delete");
        let identity = file_identity_from_open_handle(&handle).expect("identity");
        let foreign = FileIdentity {
            file_index: identity.file_index.saturating_add(1),
            ..identity
        };
        assert_eq!(
            delete_open_handle(handle, foreign),
            Err(PackageStagingError::IdentityMismatch)
        );
        assert!(path.exists(), "foreign receipt must not delete the file");
        std::fs::remove_file(&path).expect("file cleanup");
        std::fs::remove_dir(&root).expect("root cleanup");
    }

    #[cfg(windows)]
    #[test]
    fn exact_rollback_refuses_foreign_content_before_root_delete() {
        use std::io::Write as _;

        let parent = std::env::temp_dir().join(format!(
            "eliot-package-rollback-foreign-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&parent).expect("parent");
        let generation = parent.join("generation");
        let root_file = match create_generation_root(&generation) {
            Ok(root) => root,
            Err(PackageStagingError::Io | PackageStagingError::SecurityMismatch) => {
                std::fs::remove_dir(&parent).expect("parent cleanup");
                return;
            }
            Err(error) => panic!("rollback fixture failed: {error}"),
        };
        let owned_path = generation.join("owned.bin");
        let (mut owned_file, owned_identity) =
            create_destination_file(&owned_path).expect("owned file");
        owned_file.write_all(b"owned").expect("owned bytes");
        flush_file_buffers(&owned_file).expect("owned flush");
        let foreign_path = generation.join("foreign.bin");
        std::fs::write(&foreign_path, b"foreign").expect("foreign bytes");
        let root_identity = file_identity_from_open_handle(&root_file).expect("root identity");
        let created = CreatedTree {
            root_path: generation.clone(),
            root_identity,
            root_file,
            directories: Vec::new(),
            files: vec![CreatedFile {
                identity: owned_identity,
                file: owned_file,
            }],
        };
        assert_eq!(
            rollback_created_tree(created),
            Err(PackageStagingError::RollbackRefused)
        );
        assert!(!owned_path.exists(), "owned file should be removed first");
        assert!(foreign_path.exists(), "foreign content must remain");
        let foreign = open_existing_file_for_delete(&foreign_path).expect("foreign delete");
        let foreign_identity = file_identity_from_open_handle(&foreign).expect("identity");
        delete_open_handle(foreign, foreign_identity).expect("foreign cleanup");
        std::fs::remove_dir(&generation).expect("generation cleanup");
        std::fs::remove_dir(&parent).expect("parent cleanup");
    }
}
