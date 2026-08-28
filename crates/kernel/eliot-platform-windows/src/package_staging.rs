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
use std::io::{Read, Write};
#[cfg(windows)]
use std::io::{Seek, SeekFrom};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::{AtomicU8, Ordering as AtomicOrdering};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{FileIdentity, ProtectedPathError, ProtectedPathStage};

mod package_manifest;
mod package_relative_path;

pub use package_manifest::{PackageFileSpec, PackageManifest};
pub use package_relative_path::{
    PackageRelativePath, ordinal_cmp_str, ordinal_component_cmp, ordinal_eq_str, ordinal_path_cmp,
    ordinal_path_eq, validate_package_relative_path,
};
use package_relative_path::{is_windows_device_name, validate_relative_text};

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
const MAX_AUTHENTICODE_CERT_DER_BYTES: usize = 16 * 1024 * 1024;
const MAX_AUTHENTICODE_PROVIDER_CHAIN_ELEMENTS: u32 = 1024;
#[cfg(test)]
const AGENT_BRIDGE_FAIL_FINAL_PATH: u8 = 1;
#[cfg(test)]
const AGENT_BRIDGE_FAIL_DESTINATION_EXISTS: u8 = 2;
#[cfg(test)]
static AGENT_BRIDGE_POST_CREATE_FAILURE: AtomicU8 = AtomicU8::new(0);
/// Maximum number of files plus directories walked from one source root.
pub const MAX_ENUMERATED_ENTRIES: usize = MAX_PACKAGE_FILES * 2 + MAX_PACKAGE_PATH_DEPTH;

/// One source-file fact retained in a durable `StagePackage` preparation
/// capability.  The fact is intentionally independent of any source path;
/// recovery uses it to validate only the authorised destination.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagePackageExpectedFile {
    /// Canonical package-relative path.
    pub relative_path: String,
    /// Source object identity observed before the stage intent was committed.
    pub source_identity: FileIdentity,
    /// Exact source byte length.
    pub size: u64,
    /// Lowercase source SHA-256.
    pub sha256: String,
}

/// Explicit source and destination facts for one auxiliary Agent Bridge file.
///
/// The caller must have observed the source before handing this request to the
/// provider.  The staging operation reopens that exact source path without
/// following reparse points and proves all three supplied source facts again.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeStagingRequest {
    /// Absolute source path observed by the caller.
    pub source_path: PathBuf,
    /// Source file-object identity observed by the caller.
    pub source_identity: FileIdentity,
    /// Lowercase SHA-256 observed by the caller.
    pub source_sha256: String,
    /// Source byte length observed by the caller.
    pub source_size: u64,
    /// Exact absent destination path below the retained installation root.
    pub destination_path: PathBuf,
}

/// Raw create disposition for one auxiliary Agent Bridge file stage.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentBridgeStagingCreateDisposition {
    /// The destination was created by this staging call with `CREATE_NEW`.
    Created,
}

/// Complete immutable receipt for one auxiliary Agent Bridge file stage.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeStagingReceipt {
    /// Versioned receipt discriminator.
    pub wire: String,
    /// Version of the receipt wire.
    pub wire_version: u32,
    /// Durable transaction binding.
    pub transaction_id: String,
    /// Durable effect binding.
    pub effect_id: String,
    /// Durable request binding.
    pub request_digest: String,
    /// Canonical source path observed through the retained source handle.
    pub source_path: PathBuf,
    /// Source file-object identity observed before copying.
    pub source_identity: FileIdentity,
    /// Canonical destination path observed through the retained destination
    /// handle.
    pub destination_path: PathBuf,
    /// Destination file-object identity observed after create and readback.
    pub destination_identity: FileIdentity,
    /// Canonical final-parent path retained during publication.
    pub parent_path: PathBuf,
    /// Final-parent identity retained during publication.
    pub parent_identity: FileIdentity,
    /// Operation-scoped temporary path used before publication.
    pub temporary_path: PathBuf,
    /// Identity of the temporary object, preserved by rename.
    pub temporary_identity: FileIdentity,
    /// Lowercase SHA-256 of the exact copied bytes.
    pub sha256: String,
    /// Number of copied bytes.
    pub size: u64,
    /// OS create disposition retained by the provider.
    pub create_disposition: AgentBridgeStagingCreateDisposition,
}

impl AgentBridgeStagingReceipt {
    /// Return a stable digest of this receipt for a durable plan or outer
    /// transaction receipt.
    #[must_use]
    pub fn digest(&self) -> String {
        serde_json::to_vec(self).map_or_else(
            |_| hex_digest(b"agent-bridge-staging-receipt-serialization-failed"),
            |bytes| hex_digest(&bytes),
        )
    }
}

/// Current wire identity for the crash-safe auxiliary bridge stage.
pub const AGENT_BRIDGE_STAGE_WIRE: &str = "eliot.agent-bridge.stage.v1";
/// Current prepared/receipt wire version.
pub const AGENT_BRIDGE_STAGE_WIRE_VERSION: u32 = 1;

/// Durable, serializable pre-rename capability for one auxiliary bridge file.
///
/// This record contains only observed source facts and exact same-parent
/// temporary/final identities. It is intentionally not a transaction record;
/// callers retain it durably after their own intent commit.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeStagePrepared {
    /// Explicit prepared-stage wire discriminator.
    pub wire: String,
    /// Prepared-stage wire version.
    pub wire_version: u32,
    /// Durable transaction binding.
    pub transaction_id: String,
    /// Durable effect binding.
    pub effect_id: String,
    /// Durable request binding.
    pub request_digest: String,
    /// Exact source path observed before preparation.
    pub source_path: PathBuf,
    /// Exact source object identity.
    pub source_identity: FileIdentity,
    /// Exact source SHA-256.
    pub source_sha256: String,
    /// Exact source byte length.
    pub source_size: u64,
    /// Canonical parent path shared by temporary and final leaves.
    pub parent_path: PathBuf,
    /// Canonical parent identity.
    pub parent_identity: FileIdentity,
    /// Operation-scoped temporary path.
    pub temporary_path: PathBuf,
    /// Temporary object identity captured after `CREATE_NEW`.
    pub temporary_identity: FileIdentity,
    /// Exact final destination path.
    pub destination_path: PathBuf,
    /// Final identity expected after the atomic rename (the rename preserves
    /// the temporary object identity).
    pub destination_identity: FileIdentity,
}

impl AgentBridgeStagePrepared {
    /// Return a stable digest of this prepared capability.
    #[must_use]
    pub fn digest(&self) -> String {
        serde_json::to_vec(self).map_or_else(
            |_| hex_digest(b"agent-bridge-stage-prepared-serialization-failed"),
            |bytes| hex_digest(&bytes),
        )
    }
}

/// Native operation that failed while the `StagePackage` provider was observing
/// or mutating a protected object.
#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PackageStagingStage {
    KnownFolderPath,
    CanonicalizePath,
    SymlinkMetadata,
    SetSecurityInfo,
    GetSecurityInfo,
    CreateFileW,
    FileMetadata,
    FlushFileBuffers,
    GetFileInformationByHandle,
    GetFinalPathNameByHandleW,
    DuplicateHandle,
    SetFilePointerEx,
    ReadFile,
    WriteFile,
}

/// Durable, HMAC-bound capability for one `StagePackage` mutation/recovery.
///
/// The installation coordinator persists the source snapshot and ownership
/// secret reference before the provider receives an apply request.  The
/// provider then persists an HMAC-protected marker containing this capability
/// before creating the generation tree.  A recovery that has no receipt can
/// therefore inspect only the exact marker-authorised destination; it never
/// adopts a destination by path or reopens the source bundle.
#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StagePackageAuthorization {
    /// Stable transaction identity.
    pub transaction_id: String,
    /// Stable `StagePackage` effect identity.
    pub effect_id: String,
    /// Immutable installer-plan digest.
    pub plan_digest: String,
    /// Exact source bundle identity captured in the precondition.
    pub source_bundle_identity: FileIdentity,
    /// Digest of the complete durable source observation.
    pub source_snapshot_digest: String,
    /// Exact protected destination contour.
    pub staging_root: PathBuf,
    /// Destination contour identity, when known by the mutating call.  The
    /// recovery path obtains the value from the authenticated marker and then
    /// compares it with a fresh protected-root readback.
    pub installation_root_identity: Option<FileIdentity>,
    /// Candidate generation identity.
    pub generation: String,
    /// Canonical manifest digest.
    pub manifest_sha256: String,
    /// Unpredictable marker nonce derived from the provider-owned reference.
    pub marker_nonce: String,
    /// Exact source file inventory bound into the capability.
    pub expected_files: Vec<StagePackageExpectedFile>,
}

impl StagePackageAuthorization {
    fn validate(&self) -> Result<(), PackageStagingError> {
        if self.transaction_id.trim().is_empty()
            || self.effect_id.trim().is_empty()
            || self.plan_digest.len() != 64
            || !self
                .plan_digest
                .chars()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.source_bundle_identity.volume_serial_number == 0
            || self.source_bundle_identity.file_index == 0
            || self.source_snapshot_digest.len() != 64
            || !super::valid_sha256_hex(&self.source_snapshot_digest)
            || !self.staging_root.is_absolute()
            || self.generation.is_empty()
            || self.manifest_sha256.len() != 64
            || !super::valid_sha256_hex(&self.manifest_sha256)
            || self.marker_nonce.len() != 64
            || !super::valid_sha256_hex(&self.marker_nonce)
            || self.expected_files.is_empty()
        {
            return Err(PackageStagingError::IdentityMismatch);
        }
        if self
            .installation_root_identity
            .is_some_and(|identity| identity.volume_serial_number == 0 || identity.file_index == 0)
        {
            return Err(PackageStagingError::IdentityMismatch);
        }
        let mut paths = std::collections::BTreeSet::new();
        for file in &self.expected_files {
            validate_relative_text(&file.relative_path)?;
            if file.source_identity.volume_serial_number == 0
                || file.source_identity.file_index == 0
                || file.size == 0
                || !super::valid_sha256_hex(&file.sha256)
                || !paths.insert(file.relative_path.to_ascii_lowercase())
            {
                return Err(PackageStagingError::IdentityMismatch);
            }
        }
        Ok(())
    }

    fn marker_path(&self) -> PathBuf {
        let name = format!(
            ".eliot-stage-{}-{}.prepared",
            sha256_marker_name(self),
            self.marker_nonce
        );
        self.staging_root.join(name)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct StagePackagePreparedMarker {
    version: u32,
    authorization: StagePackageAuthorization,
    mac: String,
}

const STAGE_PACKAGE_MARKER_VERSION: u32 = 1;

fn sha256_marker_name(authorization: &StagePackageAuthorization) -> String {
    let bytes = serde_json::to_vec(&(
        "eliot-stage-package-marker-name-v1",
        &authorization.transaction_id,
        &authorization.effect_id,
        &authorization.plan_digest,
        &authorization.staging_root,
        &authorization.generation,
        &authorization.marker_nonce,
    ))
    .unwrap_or_default();
    hex_digest(&bytes)
}

fn stage_package_marker_mac(
    authorization: &StagePackageAuthorization,
    key: &[u8],
) -> Result<String, PackageStagingError> {
    let bytes = serde_json::to_vec(&(STAGE_PACKAGE_MARKER_VERSION, authorization))
        .map_err(|_| PackageStagingError::Io)?;
    Ok(hmac_sha256_hex(key, &bytes))
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK_BYTES: usize = 64;
    let mut normalized = [0_u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK_BYTES];
    let mut outer_pad = [0x5c_u8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    normalized.fill(0);
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner_digest = inner.finalize();
    inner_pad.fill(0);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner_digest);
    outer_pad.fill(0);
    format!("{:x}", outer.finalize())
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
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

fn provider_chain_is_bounded<T>(count: u32, chain: *const T) -> bool {
    count != 0 && count <= MAX_AUTHENTICODE_PROVIDER_CHAIN_ELEMENTS && !chain.is_null()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderCounterSignerState {
    Absent,
    Present,
    Malformed,
}

fn provider_countersigner_state<T>(count: u32, chain: *const T) -> ProviderCounterSignerState {
    if count == 0 {
        ProviderCounterSignerState::Absent
    } else if count > MAX_AUTHENTICODE_PROVIDER_CHAIN_ELEMENTS || chain.is_null() {
        ProviderCounterSignerState::Malformed
    } else {
        ProviderCounterSignerState::Present
    }
}

fn provider_der_length(pointer: *const u8, length: u32) -> Option<usize> {
    let length = usize::try_from(length).ok()?;
    (length != 0 && length <= MAX_AUTHENTICODE_CERT_DER_BYTES && !pointer.is_null())
        .then_some(length)
}

fn hex_digest(bytes: &[u8]) -> String {
    encode_digest_hex(Sha256::digest(bytes).as_slice())
}

/// Encode an already-computed digest without hashing the digest bytes again.
///
/// Callers that stream file contents into a [`Sha256`] must use this helper on
/// the finalized output.  [`hex_digest`] is intentionally reserved for raw
/// content bytes so a content digest cannot accidentally become a SHA-256 of
/// the digest itself.
fn encode_digest_hex(digest: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(digest.len() * 2);
    for &byte in digest {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
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
    use std::os::windows::fs::OpenOptionsExt as _;
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ};

    if !path.is_absolute() || !super::valid_sha256_hex(expected_sha256) {
        return Err(AuthenticodeError::InvalidInput);
    }
    let mut file = std::fs::OpenOptions::new();
    file.read(true)
        // WinTrust needs to read the object, but this handle deliberately does
        // not share future writes or deletes during the provider call.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let mut file = file.open(path).map_err(|_| AuthenticodeError::NotFound)?;
    verify_authenticode_handle(path, &mut file, expected_identity, expected_sha256)
}

#[cfg(windows)]
#[derive(Clone, Debug, Eq, PartialEq)]
struct AuthenticodeFileObservation {
    path: PathBuf,
    identity: FileIdentity,
    size: u64,
    sha256: String,
}

#[cfg(windows)]
fn observe_authenticode_handle(
    file: &mut std::fs::File,
) -> Result<AuthenticodeFileObservation, AuthenticodeError> {
    use std::os::windows::fs::MetadataExt as _;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = file
        .metadata()
        .map_err(|_| AuthenticodeError::InvalidFile)?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(AuthenticodeError::InvalidFile);
    }
    let path =
        super::final_windows_path_from_handle(file).map_err(|_| AuthenticodeError::InvalidFile)?;
    let identity =
        super::file_identity_from_handle(file).map_err(|_| AuthenticodeError::InvalidFile)?;
    let size = metadata.len();
    let sha256 = hash_file(file)?;
    Ok(AuthenticodeFileObservation {
        path,
        identity,
        size,
        sha256,
    })
}

#[cfg(windows)]
fn compare_authenticode_observations(
    expected_path: &Path,
    before: &AuthenticodeFileObservation,
    after: &AuthenticodeFileObservation,
) -> Result<(), AuthenticodeError> {
    if !super::windows_paths_equal(&before.path, expected_path)
        || !super::windows_paths_equal(&after.path, expected_path)
        || before.identity != after.identity
    {
        return Err(AuthenticodeError::IdentityMismatch);
    }
    if before.size != after.size || before.sha256 != after.sha256 {
        return Err(AuthenticodeError::DigestMismatch);
    }
    Ok(())
}

#[cfg(windows)]
fn verify_authenticode_handle(
    path: &Path,
    file: &mut std::fs::File,
    expected_identity: FileIdentity,
    expected_sha256: &str,
) -> Result<AuthenticodeEvidence, AuthenticodeError> {
    if !path.is_absolute() || !super::valid_sha256_hex(expected_sha256) {
        return Err(AuthenticodeError::InvalidInput);
    }
    let before = observe_authenticode_handle(file)?;
    if before.identity != expected_identity {
        return Err(AuthenticodeError::IdentityMismatch);
    }
    if before.sha256 != expected_sha256 {
        return Err(AuthenticodeError::DigestMismatch);
    }
    let evidence = verify_signature(&before.path, file)?;
    let after = observe_authenticode_handle(file)?;
    compare_authenticode_observations(path, &before, &after)?;
    Ok(evidence)
}

#[cfg(not(windows))]
fn verify_authenticode_handle(
    _path: &Path,
    _file: &mut std::fs::File,
    _expected_identity: FileIdentity,
    _expected_sha256: &str,
) -> Result<AuthenticodeEvidence, AuthenticodeError> {
    Err(AuthenticodeError::UnsupportedPlatform)
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
    Ok(encode_digest_hex(&digest.finalize()))
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
    let (cert_count, cert_chain) = unsafe {
        // SAFETY: signer is live until provider CLOSE; these are the provider's
        // own chain count and first-element pointer.
        ((*signer).csCertChain, (*signer).pasCertChain)
    };
    if !provider_chain_is_bounded(cert_count, cert_chain.cast_const()) {
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
    let der_length = provider_der_length(context.pbCertEncoded, context.cbCertEncoded)?;
    let der = unsafe {
        // SAFETY: the provider pointer is non-null and the byte length is
        // explicitly bounded before constructing the DER slice.
        std::slice::from_raw_parts(context.pbCertEncoded, der_length)
    };
    let (signer_subject, not_before, not_after) = certificate_evidence(context);
    let (counter_count, counter_chain) = unsafe {
        // SAFETY: signer is provider-owned and live until CLOSE; these fields
        // describe the provider's optional countersigner chain.
        ((*signer).csCounterSigners, (*signer).pasCounterSigners)
    };
    let countersigner_certificate_sha256 =
        match provider_countersigner_state(counter_count, counter_chain.cast_const()) {
            ProviderCounterSignerState::Absent => None,
            // A non-zero countersigner count is a mandatory evidence claim.  Any
            // malformed provider state must therefore fail closed instead of
            // silently degrading to the optional-absent representation.
            ProviderCounterSignerState::Malformed => return None,
            ProviderCounterSignerState::Present => {
                let countersigner = unsafe {
                    // SAFETY: provider is live; the provider chain was bounded and
                    // non-null before asking WinTrust for its first countersigner.
                    WTHelperGetProvSignerFromChain(provider, 0, 1, 0)
                };
                if countersigner.is_null() {
                    return None;
                }
                let (cert_count, cert_chain) = unsafe {
                    // SAFETY: countersigner is provider-owned and live until CLOSE;
                    // these are its chain count and first-element pointer.
                    ((*countersigner).csCertChain, (*countersigner).pasCertChain)
                };
                if !provider_chain_is_bounded(cert_count, cert_chain.cast_const()) {
                    return None;
                }
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
                let der_length = provider_der_length(context.pbCertEncoded, context.cbCertEncoded)?;
                let der = unsafe {
                    // SAFETY: the provider pointer is non-null and the byte length
                    // is explicitly bounded before constructing the DER slice.
                    std::slice::from_raw_parts(context.pbCertEncoded, der_length)
                };
                Some(hex_digest(der))
            }
        };

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
    /// A native `StagePackage` operation failed; the semantic operation and raw
    /// Win32 status are retained for durable recovery observability.
    Win32 {
        stage: PackageStagingStage,
        code: u32,
    },
}

impl fmt::Display for PackageStagingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeParse(error) => write!(formatter, "PE/COFF staging error: {error}"),
            Self::Authenticode(error) => write!(formatter, "Authenticode staging error: {error}"),
            Self::AuthenticodeRejected(verdict) => {
                write!(formatter, "Authenticode verdict rejected: {verdict:?}")
            }
            Self::Win32 { stage, code } => {
                write!(formatter, "{stage:?} failed with Win32 status {code:#010x}")
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
                Self::PeParse(_)
                | Self::Authenticode(_)
                | Self::AuthenticodeRejected(_)
                | Self::Win32 { .. } => {
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

/// One retained regular file below a [`TrustedSourceBundle`]. The file handle
/// is opened no-follow with read-only, no-share-write/no-share-delete
/// semantics so an installer can carry `generation.json` through later
/// effects without reopening a mutable pathname.
pub struct TrustedSourceFileLease {
    path: PathBuf,
    relative_path: String,
    identity: FileIdentity,
    size: u64,
    sha256: String,
    #[cfg(windows)]
    file: std::fs::File,
}

impl fmt::Debug for TrustedSourceFileLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrustedSourceFileLease")
            .field("path", &self.path)
            .field("relative_path", &self.relative_path)
            .field("identity", &self.identity)
            .field("size", &self.size)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}

impl TrustedSourceFileLease {
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Reads through the retained handle and verifies the original identity,
    /// path, size and SHA-256 before returning bytes.
    ///
    /// # Errors
    ///
    /// Returns a staging error when the retained handle, identity, path, size,
    /// or hash cannot be verified.
    pub fn read_bounded(&self, limit: u64) -> Result<Vec<u8>, PackageStagingError> {
        #[cfg(windows)]
        {
            let observed = observe_source_handle(&self.file, &self.path, limit)?;
            if observed.size != self.size || observed.sha256 != self.sha256 {
                return Err(PackageStagingError::HashMismatch);
            }
            let identity = file_identity_from_open_handle(&self.file)?;
            if identity != self.identity {
                return Err(PackageStagingError::IdentityMismatch);
            }
            let mut file = self.file.try_clone().map_err(|error| {
                map_package_io_error(error, PackageStagingStage::DuplicateHandle)
            })?;
            file.seek(SeekFrom::Start(0)).map_err(|error| {
                map_package_io_error(error, PackageStagingStage::SetFilePointerEx)
            })?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)
                .map_err(|error| map_package_io_error(error, PackageStagingStage::ReadFile))?;
            Ok(bytes)
        }
        #[cfg(not(windows))]
        {
            let _ = limit;
            Err(PackageStagingError::UnsupportedPlatform)
        }
    }

    /// Alias for callers that already supplied a bounded source-file policy.
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Self::read_bounded`].
    pub fn read(&self, limit: u64) -> Result<Vec<u8>, PackageStagingError> {
        self.read_bounded(limit)
    }
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

    /// Retains one validated relative regular file below this source bundle.
    /// The complete file fact is measured before the handle is returned.
    ///
    /// # Errors
    ///
    /// Returns a staging error when the relative path, source contour, file
    /// identity, or bounded hash observation is not proven.
    pub fn retain_file(
        &self,
        relative_path: &str,
    ) -> Result<TrustedSourceFileLease, PackageStagingError> {
        #[cfg(windows)]
        {
            self.verify_stable()?;
            let relative = validate_relative_text(relative_path)?;
            let path = self.path.join(relative.as_str().replace('/', "\\"));
            let file = open_trusted_source_file(&path)?;
            let observed = observe_source_handle(&file, &path, MAX_PACKAGE_FILE_BYTES)?;
            let identity = file_identity_from_open_handle(&file)?;
            let observed_path = final_path_from_handle(&file)?;
            if !super::windows_paths_equal(&observed_path, &path) {
                return Err(PackageStagingError::IdentityMismatch);
            }
            self.verify_stable()?;
            Ok(TrustedSourceFileLease {
                path: observed_path,
                relative_path: relative.canonical,
                identity,
                size: observed.size,
                sha256: observed.sha256,
                file,
            })
        }
        #[cfg(not(windows))]
        {
            let _ = relative_path;
            Err(PackageStagingError::UnsupportedPlatform)
        }
    }

    /// Alias for [`Self::retain_file`].
    ///
    /// # Errors
    ///
    /// Propagates errors from [`Self::retain_file`].
    pub fn open_relative_file(
        &self,
        relative_path: &str,
    ) -> Result<TrustedSourceFileLease, PackageStagingError> {
        self.retain_file(relative_path)
    }

    fn verify_stable(&self) -> Result<(), PackageStagingError> {
        #[cfg(windows)]
        {
            let root = self.contour.last().ok_or(PackageStagingError::Io)?;
            let identity = super::file_identity_from_handle(root).map_err(|error| {
                map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
            })?;
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
            let root = self.contour.last().ok_or(PackageStagingError::Io)?;
            let _tree = walk_trusted_source_tree_with_root(
                self.path(),
                Some(root),
                |relative, path, file, identity| {
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
                        pe: observed.pe,
                    });
                    Ok(())
                },
            )?;
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
    let identity = super::file_identity_from_handle(root).map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })?;
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

/// Reuse an already-retained source root handle without reopening its path.
/// This is the publication bridge: the native-owned directory handle carries
/// DELETE access so it can later be renamed, and a path reopen would therefore
/// require `FILE_SHARE_DELETE` and weaken the substitution fence.  Ancestors
/// are still retained no-follow; the root itself is cloned from the exact
/// caller-owned handle.
#[cfg(windows)]
pub(crate) fn retain_source_directory_with_retained_root(
    path: &Path,
    root: &std::fs::File,
) -> Result<TrustedSourceBundle, PackageStagingError> {
    validate_source_root_input(path)?;
    reject_reparse_ancestors(path)?;
    let canonical = super::canonical_windows_path(path).map_err(map_protected_path_error)?;
    let mut ancestors = canonical
        .ancestors()
        .map(Path::to_path_buf)
        .collect::<Vec<_>>();
    ancestors.reverse();
    let expected_root = ancestors
        .pop()
        .ok_or(PackageStagingError::RootUnavailable)?;
    if !super::windows_paths_equal(&expected_root, &canonical) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let mut contour = Vec::with_capacity(ancestors.len().saturating_add(1));
    for ancestor in ancestors {
        contour.push(open_existing_directory(&ancestor)?);
    }
    let root = root
        .try_clone()
        .map_err(|error| map_package_io_error(error, PackageStagingStage::DuplicateHandle))?;
    let identity = super::file_identity_from_handle(&root).map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })?;
    let observed =
        super::final_windows_path_from_handle(&root).map_err(map_protected_path_error)?;
    if !super::windows_paths_equal(&observed, &canonical) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    contour.push(root);
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
        ProtectedPathError::Io => PackageStagingError::Io,
        ProtectedPathError::IdentityMismatch => PackageStagingError::IdentityMismatch,
        ProtectedPathError::Win32 { stage, code } => PackageStagingError::Win32 {
            stage: match stage {
                ProtectedPathStage::KnownFolderPath => PackageStagingStage::KnownFolderPath,
                ProtectedPathStage::CanonicalizePath => PackageStagingStage::CanonicalizePath,
                ProtectedPathStage::SymlinkMetadata => PackageStagingStage::SymlinkMetadata,
                ProtectedPathStage::CreateFileW => PackageStagingStage::CreateFileW,
                ProtectedPathStage::FileMetadata => PackageStagingStage::FileMetadata,
                ProtectedPathStage::GetFileInformationByHandle => {
                    PackageStagingStage::GetFileInformationByHandle
                }
                ProtectedPathStage::GetFinalPathNameByHandleW => {
                    PackageStagingStage::GetFinalPathNameByHandleW
                }
            },
            code,
        },
        ProtectedPathError::SizeExceeded => PackageStagingError::BoundExceeded,
    }
}

impl From<ProtectedPathError> for PackageStagingError {
    fn from(error: ProtectedPathError) -> Self {
        map_protected_path_error(error)
    }
}

fn map_package_open_error(error: std::io::Error) -> PackageStagingError {
    map_package_io_error(error, PackageStagingStage::CreateFileW)
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "std::io::Error is consumed by each map_err boundary"
)]
fn map_package_io_error(error: std::io::Error, stage: PackageStagingStage) -> PackageStagingError {
    if error.kind() == std::io::ErrorKind::NotFound {
        return PackageStagingError::RootUnavailable;
    }
    error
        .raw_os_error()
        .and_then(|code| u32::try_from(code).ok())
        .map_or(PackageStagingError::Io, |code| PackageStagingError::Win32 {
            stage,
            code,
        })
}

fn map_restore_privilege_error(error: super::InstallerRootError) -> PackageStagingError {
    match error {
        super::InstallerRootError::UnsupportedPlatform => PackageStagingError::UnsupportedPlatform,
        super::InstallerRootError::NotElevated
        | super::InstallerRootError::Win32 {
            stage:
                super::InstallerRootStage::OpenThreadToken
                | super::InstallerRootStage::OpenProcessToken
                | super::InstallerRootStage::DuplicateToken
                | super::InstallerRootStage::QueryPrivilege
                | super::InstallerRootStage::EnablePrivilege
                | super::InstallerRootStage::BindThreadToken,
            ..
        } => PackageStagingError::SecurityMismatch,
        _ => PackageStagingError::Io,
    }
}

fn map_directory_publication_error(error: super::DirectoryPublicationError) -> PackageStagingError {
    match error {
        super::DirectoryPublicationError::AlreadyExists => PackageStagingError::GenerationExists,
        super::DirectoryPublicationError::ReparsePoint => PackageStagingError::ReparsePoint,
        super::DirectoryPublicationError::IdentityMismatch => PackageStagingError::IdentityMismatch,
        super::DirectoryPublicationError::InvalidPath => PackageStagingError::InvalidRelativePath,
        super::DirectoryPublicationError::Win32 { code } => PackageStagingError::Win32 {
            stage: PackageStagingStage::SetSecurityInfo,
            code,
        },
        super::DirectoryPublicationError::Io => PackageStagingError::Io,
        super::DirectoryPublicationError::UnsupportedPlatform => {
            PackageStagingError::UnsupportedPlatform
        }
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
    /// PE/COFF evidence parsed from the same handle-bound prefix when the
    /// object is an AMD64 PE32+ executable.
    pub pe: Option<PeCoffEvidence>,
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
    identity: FileIdentity,
    #[cfg(windows)]
    contour: Vec<std::fs::File>,
}

fn agent_bridge_path_is_at_or_below(root: &Path, candidate: &Path) -> bool {
    let mut root_components = root.components();
    let mut candidate_components = candidate.components();
    loop {
        match (root_components.next(), candidate_components.next()) {
            (Some(root_component), Some(candidate_component))
                if root_component
                    .as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&candidate_component.as_os_str().to_string_lossy()) => {}
            (None, Some(_)) => return true,
            _ => return false,
        }
    }
}

fn validate_agent_bridge_request(
    installation_root: &Path,
    request: &AgentBridgeStagingRequest,
) -> Result<(), PackageStagingError> {
    if !request.source_path.is_absolute()
        || !request.destination_path.is_absolute()
        || request.source_identity.volume_serial_number == 0
        || request.source_identity.file_index == 0
        || !super::valid_sha256_hex(&request.source_sha256)
        || request.source_size > MAX_PACKAGE_FILE_BYTES
        || request.destination_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    if !agent_bridge_path_is_at_or_below(installation_root, &request.destination_path)
        || super::windows_paths_equal(installation_root, &request.destination_path)
        || request.destination_path.file_name().is_none()
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(())
}

fn final_path_after_agent_bridge_create(
    file: &std::fs::File,
) -> Result<PathBuf, PackageStagingError> {
    #[cfg(test)]
    if AGENT_BRIDGE_POST_CREATE_FAILURE
        .compare_exchange(
            AGENT_BRIDGE_FAIL_FINAL_PATH,
            0,
            AtomicOrdering::SeqCst,
            AtomicOrdering::SeqCst,
        )
        .is_ok()
    {
        return Err(PackageStagingError::Win32 {
            stage: PackageStagingStage::GetFinalPathNameByHandleW,
            code: 5,
        });
    }
    final_path_from_handle(file)
}

fn destination_exists_after_agent_bridge_create(path: &Path) -> Result<bool, PackageStagingError> {
    #[cfg(test)]
    if AGENT_BRIDGE_POST_CREATE_FAILURE
        .compare_exchange(
            AGENT_BRIDGE_FAIL_DESTINATION_EXISTS,
            0,
            AtomicOrdering::SeqCst,
            AtomicOrdering::SeqCst,
        )
        .is_ok()
    {
        return Err(PackageStagingError::Win32 {
            stage: PackageStagingStage::GetFileInformationByHandle,
            code: 5,
        });
    }
    path_exists(path)
}

fn agent_bridge_operation_temporary_prefix(
    parent: &Path,
    destination: &Path,
    transaction_id: &str,
    effect_id: &str,
    request_digest: &str,
) -> String {
    let name_digest = hex_digest(
        serde_json::to_vec(&(
            "eliot-agent-bridge-stage-temp-v1",
            parent,
            transaction_id,
            effect_id,
            request_digest,
            destination,
        ))
        .unwrap_or_default()
        .as_slice(),
    );
    format!(".eliot-agent-bridge.{name_digest}.")
}

fn agent_bridge_operation_temporary_path(
    parent: &Path,
    destination: &Path,
    transaction_id: &str,
    effect_id: &str,
    request_digest: &str,
) -> PathBuf {
    parent.join(format!(
        "{}{nonce}.tmp",
        agent_bridge_operation_temporary_prefix(
            parent,
            destination,
            transaction_id,
            effect_id,
            request_digest,
        ),
        nonce = super::unique_suffix()
    ))
}

fn validate_agent_bridge_temporary_name(
    parent: &Path,
    destination: &Path,
    temporary: &Path,
    transaction_id: &str,
    effect_id: &str,
    request_digest: &str,
) -> Result<(), PackageStagingError> {
    let temporary_parent = temporary
        .parent()
        .ok_or(PackageStagingError::InvalidRelativePath)?;
    if !super::windows_paths_equal(parent, temporary_parent) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    if super::windows_paths_equal(destination, temporary) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let name = temporary
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PackageStagingError::InvalidRelativePath)?;
    let prefix = agent_bridge_operation_temporary_prefix(
        parent,
        destination,
        transaction_id,
        effect_id,
        request_digest,
    );
    let Some(nonce) = name
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return Err(PackageStagingError::IdentityMismatch);
    };
    let nonce_parts = nonce.split('-').collect::<Vec<_>>();
    if nonce_parts.len() != 3
        || nonce_parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
        || nonce.is_empty()
        || nonce.len() > 128
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(())
}

fn validate_stage_binding(
    transaction_id: &str,
    effect_id: &str,
    request_digest: &str,
) -> Result<(), PackageStagingError> {
    if transaction_id.trim().is_empty()
        || effect_id.trim().is_empty()
        || !super::valid_sha256_hex(request_digest)
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(())
}

fn validate_agent_bridge_prepared(
    installation_root: &Path,
    prepared: &AgentBridgeStagePrepared,
) -> Result<(), PackageStagingError> {
    if prepared.wire != AGENT_BRIDGE_STAGE_WIRE
        || prepared.wire_version != AGENT_BRIDGE_STAGE_WIRE_VERSION
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    if prepared.destination_identity != prepared.temporary_identity {
        return Err(PackageStagingError::IdentityMismatch);
    }
    validate_stage_binding(
        &prepared.transaction_id,
        &prepared.effect_id,
        &prepared.request_digest,
    )?;
    if !prepared.source_path.is_absolute()
        || !prepared.parent_path.is_absolute()
        || !prepared.temporary_path.is_absolute()
        || !prepared.destination_path.is_absolute()
        || prepared.source_identity.volume_serial_number == 0
        || prepared.source_identity.file_index == 0
        || prepared.parent_identity.volume_serial_number == 0
        || prepared.parent_identity.file_index == 0
        || prepared.temporary_identity.volume_serial_number == 0
        || prepared.temporary_identity.file_index == 0
        || prepared.source_size == 0
        || prepared.source_size > MAX_PACKAGE_FILE_BYTES
        || !super::valid_sha256_hex(&prepared.source_sha256)
        || prepared.destination_identity.volume_serial_number == 0
        || prepared.destination_identity.file_index == 0
        || prepared
            .source_path
            .components()
            .chain(prepared.parent_path.components())
            .chain(prepared.temporary_path.components())
            .chain(prepared.destination_path.components())
            .any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir | std::path::Component::CurDir
                )
            })
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    if !agent_bridge_path_is_at_or_below(installation_root, &prepared.parent_path)
        || super::windows_paths_equal(installation_root, &prepared.parent_path)
        || !agent_bridge_path_is_at_or_below(&prepared.parent_path, &prepared.destination_path)
        || !agent_bridge_path_is_at_or_below(&prepared.parent_path, &prepared.temporary_path)
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let destination_name = prepared
        .destination_path
        .file_name()
        .ok_or(PackageStagingError::InvalidRelativePath)?;
    let expected_destination = prepared.parent_path.join(destination_name);
    if !super::windows_paths_equal(&expected_destination, &prepared.destination_path)
        || validate_agent_bridge_temporary_name(
            &prepared.parent_path,
            &prepared.destination_path,
            &prepared.temporary_path,
            &prepared.transaction_id,
            &prepared.effect_id,
            &prepared.request_digest,
        )
        .is_err()
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(())
}

fn agent_bridge_receipt_from_prepared(
    prepared: &AgentBridgeStagePrepared,
    destination_identity: FileIdentity,
) -> AgentBridgeStagingReceipt {
    AgentBridgeStagingReceipt {
        wire: prepared.wire.clone(),
        wire_version: prepared.wire_version,
        transaction_id: prepared.transaction_id.clone(),
        effect_id: prepared.effect_id.clone(),
        request_digest: prepared.request_digest.clone(),
        source_path: prepared.source_path.clone(),
        source_identity: prepared.source_identity,
        destination_path: prepared.destination_path.clone(),
        destination_identity,
        parent_path: prepared.parent_path.clone(),
        parent_identity: prepared.parent_identity,
        temporary_path: prepared.temporary_path.clone(),
        temporary_identity: prepared.temporary_identity,
        sha256: prepared.source_sha256.clone(),
        size: prepared.source_size,
        create_disposition: AgentBridgeStagingCreateDisposition::Created,
    }
}

#[cfg(windows)]
fn verify_retained_agent_bridge_parent(
    parent: &RetainedDestinationParent,
) -> Result<(), PackageStagingError> {
    let handle = parent
        .contour
        .last()
        .ok_or(PackageStagingError::RootUnavailable)?;
    let identity = file_identity_from_open_handle(handle)?;
    let canonical = final_path_from_handle(handle)?;
    if identity != parent.identity
        || !super::windows_paths_equal(&canonical, &parent.path)
        || verify_system_security(handle, true).is_err()
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(())
}

#[cfg(not(windows))]
fn verify_retained_agent_bridge_parent(
    _parent: &RetainedDestinationParent,
) -> Result<(), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

/// Prepare one operation-scoped bridge file without publishing its final
/// pathname. The returned value is the only durable capability needed for
/// later publish/reconcile; no transaction state is persisted here.
#[allow(
    clippy::too_many_lines,
    reason = "the prepared capability keeps the complete create-and-verify proof in one boundary"
)]
pub fn prepare_agent_bridge_stage(
    installation_root: &super::ProtectedRootLease,
    request: &AgentBridgeStagingRequest,
    transaction_id: &str,
    effect_id: &str,
    request_digest: &str,
) -> Result<AgentBridgeStagePrepared, PackageStagingError> {
    let root_path = installation_root
        .canonical_path()
        .map_err(map_protected_path_error)?;
    installation_root
        .verify_stable_identity()
        .map_err(map_protected_path_error)?;
    validate_stage_binding(transaction_id, effect_id, request_digest)?;
    if request.source_size == 0 {
        return Err(PackageStagingError::IdentityMismatch);
    }
    validate_agent_bridge_request(&root_path, request)?;
    verify_system_directory_at(&root_path)?;
    let parent = retain_destination_parent(
        request
            .destination_path
            .parent()
            .ok_or(PackageStagingError::RootUnavailable)?,
    )?;
    let destination_name = request
        .destination_path
        .file_name()
        .ok_or(PackageStagingError::InvalidRelativePath)?;
    let destination_path = parent.path.join(destination_name);
    if !super::windows_paths_equal(&destination_path, &request.destination_path) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    if path_exists(&destination_path)? {
        return Err(PackageStagingError::GenerationExists);
    }
    let source = snapshot_source_file(&request.source_path, request.source_size)?;
    if source.identity != request.source_identity
        || !super::windows_paths_equal(&final_path_from_handle(&source.file)?, &request.source_path)
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    if source.sha256 != request.source_sha256 {
        return Err(PackageStagingError::HashMismatch);
    }
    let mut staged = None;
    for _ in 0..64 {
        let temporary_path = agent_bridge_operation_temporary_path(
            &parent.path,
            &destination_path,
            transaction_id,
            effect_id,
            request_digest,
        );
        if path_exists(&temporary_path)? {
            continue;
        }
        match copy_destination_bytes(&source, &temporary_path, request.source_size) {
            Ok(copied) => {
                staged = Some((temporary_path, copied));
                break;
            }
            Err(PackageStagingError::GenerationExists) => {}
            Err(error) => return Err(error),
        }
    }
    let (temporary_path, (temporary, temporary_identity, readback)) =
        staged.ok_or(PackageStagingError::GenerationExists)?;
    let temporary_path_observed = match final_path_after_agent_bridge_create(&temporary) {
        Ok(path) => path,
        Err(error) => {
            return Err(cleanup_created_handle(temporary, temporary_identity, error));
        }
    };
    let destination_exists = match destination_exists_after_agent_bridge_create(&destination_path) {
        Ok(exists) => exists,
        Err(error) => {
            return Err(cleanup_created_handle(temporary, temporary_identity, error));
        }
    };
    if !super::windows_paths_equal(&temporary_path_observed, &temporary_path)
        || verify_retained_agent_bridge_parent(&parent).is_err()
        || readback.sha256 != request.source_sha256
        || readback.size != request.source_size
        || destination_exists
    {
        return Err(cleanup_created_handle(
            temporary,
            temporary_identity,
            PackageStagingError::IdentityMismatch,
        ));
    }
    drop(temporary);
    Ok(AgentBridgeStagePrepared {
        wire: AGENT_BRIDGE_STAGE_WIRE.to_owned(),
        wire_version: AGENT_BRIDGE_STAGE_WIRE_VERSION,
        transaction_id: transaction_id.to_owned(),
        effect_id: effect_id.to_owned(),
        request_digest: request_digest.to_owned(),
        source_path: request.source_path.clone(),
        source_identity: source.identity,
        source_sha256: source.sha256,
        source_size: source.size,
        parent_path: parent.path,
        parent_identity: parent.identity,
        temporary_path,
        temporary_identity,
        destination_path,
        destination_identity: temporary_identity,
    })
}

#[cfg(windows)]
fn rename_agent_bridge_file_from_handle(
    temporary: &std::fs::File,
    parent: &RetainedDestinationParent,
    destination_name: &str,
) -> Result<(), PackageStagingError> {
    let parent_handle = parent
        .contour
        .last()
        .ok_or(PackageStagingError::RootUnavailable)?;
    super::rename_directory_from_handle(temporary, parent_handle, destination_name)
        .map_err(map_directory_publication_error)
}

#[cfg(not(windows))]
fn rename_agent_bridge_file_from_handle(
    _temporary: &std::fs::File,
    _parent: &RetainedDestinationParent,
    _destination_name: &str,
) -> Result<(), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

fn read_prepared_final(
    prepared: &AgentBridgeStagePrepared,
) -> Result<AgentBridgeStagingReceipt, PackageStagingError> {
    let final_file = open_existing_file(&prepared.destination_path)?;
    let actual = read_destination_snapshot_handle(
        &final_file,
        &prepared.destination_path,
        prepared.source_size,
        prepared.destination_identity,
    )?;
    if actual.sha256 != prepared.source_sha256 || actual.size != prepared.source_size {
        return Err(PackageStagingError::HashMismatch);
    }
    Ok(agent_bridge_receipt_from_prepared(
        prepared,
        prepared.destination_identity,
    ))
}

#[cfg(windows)]
fn flush_agent_bridge_parent(
    parent: &RetainedDestinationParent,
) -> Result<(), PackageStagingError> {
    flush_file_buffers(
        parent
            .contour
            .last()
            .ok_or(PackageStagingError::RootUnavailable)?,
    )
}

#[cfg(not(windows))]
fn flush_agent_bridge_parent(
    _parent: &RetainedDestinationParent,
) -> Result<(), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

/// Publish a completely prepared bridge file with an atomic, no-replace
/// same-parent rename. The prepared capability remains valid for recovery if
/// post-rename readback is interrupted.
pub fn publish_agent_bridge_stage(
    installation_root: &super::ProtectedRootLease,
    prepared: &AgentBridgeStagePrepared,
) -> Result<AgentBridgeStagingReceipt, PackageStagingError> {
    let root_path = installation_root
        .canonical_path()
        .map_err(map_protected_path_error)?;
    installation_root
        .verify_stable_identity()
        .map_err(map_protected_path_error)?;
    validate_agent_bridge_prepared(&root_path, prepared)?;
    verify_system_directory_at(&root_path)?;
    let parent = retain_destination_parent(&prepared.parent_path)?;
    if parent.identity != prepared.parent_identity
        || !super::windows_paths_equal(&parent.path, &prepared.parent_path)
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    verify_retained_agent_bridge_parent(&parent)?;
    if path_exists(&prepared.destination_path)? {
        if path_exists(&prepared.temporary_path)? {
            return Err(PackageStagingError::IdentityMismatch);
        }
        return read_prepared_final(prepared);
    }
    if !path_exists(&prepared.temporary_path)? {
        return Err(PackageStagingError::PartialTree);
    }
    let temporary = open_existing_file_for_delete(&prepared.temporary_path)?;
    let actual = read_destination_snapshot_handle(
        &temporary,
        &prepared.temporary_path,
        prepared.source_size,
        prepared.temporary_identity,
    )?;
    if actual.sha256 != prepared.source_sha256 || actual.size != prepared.source_size {
        return Err(PackageStagingError::HashMismatch);
    }
    let destination_name = prepared
        .destination_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(PackageStagingError::InvalidRelativePath)?;
    rename_agent_bridge_file_from_handle(&temporary, &parent, destination_name)?;
    flush_agent_bridge_parent(&parent)?;
    let destination_path = final_path_from_handle(&temporary)?;
    if !super::windows_paths_equal(&destination_path, &prepared.destination_path) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let receipt = read_prepared_final(prepared)?;
    installation_root
        .verify_stable_identity()
        .map_err(map_protected_path_error)?;
    Ok(receipt)
}

/// Reconcile a prepared bridge operation after a crash or response loss.
///
/// Only the exact prepared temporary identity or the same identity after the
/// no-replace rename can become a matching receipt. Foreign or partial state
/// is never adopted.
pub fn reconcile_agent_bridge_stage(
    installation_root: &super::ProtectedRootLease,
    prepared: &AgentBridgeStagePrepared,
) -> Result<AgentBridgeStagingReceipt, PackageStagingError> {
    let root_path = installation_root
        .canonical_path()
        .map_err(map_protected_path_error)?;
    installation_root
        .verify_stable_identity()
        .map_err(map_protected_path_error)?;
    validate_agent_bridge_prepared(&root_path, prepared)?;
    verify_system_directory_at(&root_path)?;
    let parent = retain_destination_parent(&prepared.parent_path)?;
    if parent.identity != prepared.parent_identity {
        return Err(PackageStagingError::IdentityMismatch);
    }
    verify_retained_agent_bridge_parent(&parent)?;
    let final_exists = path_exists(&prepared.destination_path)?;
    let temporary_exists = path_exists(&prepared.temporary_path)?;
    match (final_exists, temporary_exists) {
        (true, false) => read_prepared_final(prepared),
        (false, true) => publish_agent_bridge_stage(installation_root, prepared),
        (false, false) => Err(PackageStagingError::PartialTree),
        (true, true) => Err(PackageStagingError::IdentityMismatch),
    }
}

/// Measurement/mutation primitive for one retained source and installation
/// root.  It owns no transaction, activation or durable authority state.
pub struct PackageStager {
    source: TrustedSourceBundle,
    installation_root: PathBuf,
    #[cfg(windows)]
    installation_lease: super::ProtectedRootLease,
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

#[allow(
    clippy::too_many_lines,
    reason = "destination-only reconciliation keeps the complete receipt proof in one boundary"
)]
fn reconcile_receipt_at_installation_root(
    installation_root: &Path,
    receipt: &StagingReceipt,
) -> Result<PackageStagingObservation, PackageStagingError> {
    if !installation_root.is_absolute() {
        return Err(PackageStagingError::RootUnavailable);
    }
    #[cfg(windows)]
    verify_system_directory_at(installation_root)?;

    if receipt.generation.is_empty()
        || receipt.files.len() > MAX_PACKAGE_FILES
        || receipt.directories.len() > MAX_ENUMERATED_ENTRIES
    {
        return Err(PackageStagingError::InvalidRelativePath);
    }
    validate_receipt_file_grammar(&receipt.files)?;
    let files = receipt
        .files
        .iter()
        .map(|file| PackageFileSpec {
            relative_path: file.relative_path.clone(),
            executable: file.pe.is_some(),
            expected_size: file.size,
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
    let parent_components = generation
        .components
        .get(..generation.components.len().saturating_sub(1))
        .unwrap_or(&[]);
    let mut parent_path = installation_root.to_path_buf();
    for component in parent_components {
        parent_path.push(component);
    }
    let parent = retain_destination_parent(&parent_path)?;
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
    let actual_directories = match PackageStager::read_current_directories(&root_path, &manifest) {
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
    let actual = match PackageStager::read_current_files(&root_path, &manifest, &receipt.files) {
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

fn inspect_published_destination_at_installation_root(
    installation_root: &Path,
    manifest: &PackageManifest,
    expectations: &[StagedFileReceipt],
) -> Result<PackageStagingObservation, PackageStagingError> {
    if !installation_root.is_absolute() {
        return Err(PackageStagingError::RootUnavailable);
    }
    #[cfg(windows)]
    verify_system_directory_at(installation_root)?;

    let manifest = manifest.validate()?;
    if expectations.len() != manifest.files.len() {
        return Ok(PackageStagingObservation::Mismatch(
            PackageStagingError::TreeMismatch,
        ));
    }
    for expected in expectations {
        if expected.source_identity.volume_serial_number == 0
            || expected.source_identity.file_index == 0
            || expected.size == 0
            || !super::valid_sha256_hex(&expected.sha256)
        {
            return Err(PackageStagingError::IdentityMismatch);
        }
    }
    let generation = validate_relative_text(&manifest.generation)?;
    let parent_components = generation
        .components
        .get(..generation.components.len().saturating_sub(1))
        .unwrap_or(&[]);
    let mut parent_path = installation_root.to_path_buf();
    for component in parent_components {
        parent_path.push(component);
    }
    let parent = retain_destination_parent(&parent_path)?;
    let root_path = generation.join_to(&parent.path);
    if !path_exists(&root_path)? {
        return Ok(PackageStagingObservation::Absent);
    }
    let root = open_existing_directory(&root_path)?;
    let root_identity = file_identity_from_open_handle(&root)?;
    verify_system_security(&root, true)?;
    let tree = enumerate_tree(&root_path, &manifest)?;
    ensure_tree_matches_manifest(&tree, &manifest)?;
    let directories = PackageStager::read_current_directories(&root_path, &manifest)?;
    let files = PackageStager::read_current_files(&root_path, &manifest, expectations)?;
    if files.iter().any(|actual| {
        let Some(expected) = expectations
            .iter()
            .find(|expected| ordinal_eq_str(&expected.relative_path, &actual.relative_path))
        else {
            return true;
        };
        actual.source_identity != expected.source_identity
            || actual.sha256 != expected.sha256
            || actual.size != expected.size
    }) {
        return Ok(PackageStagingObservation::Mismatch(
            PackageStagingError::HashMismatch,
        ));
    }
    let published_root_path = {
        #[cfg(windows)]
        {
            final_path_from_handle(&root)?
        }
        #[cfg(not(windows))]
        {
            root_path.clone()
        }
    };
    let receipt = StagingReceipt {
        generation: manifest.generation.clone(),
        root_path: published_root_path,
        root_identity,
        directories,
        files,
        manifest_sha256: manifest.canonical_digest(),
    };
    if !super::windows_paths_equal(&receipt.root_path, &root_path) {
        return Ok(PackageStagingObservation::Mismatch(
            PackageStagingError::IdentityMismatch,
        ));
    }
    Ok(PackageStagingObservation::Matching(receipt))
}

fn write_or_validate_prepared_marker(
    authorization: &StagePackageAuthorization,
    ownership_key: &[u8],
) -> Result<(), PackageStagingError> {
    let marker_path = authorization.marker_path();
    if path_exists(&marker_path)? {
        let marker = read_prepared_marker(&marker_path, ownership_key)?;
        let mut expected = authorization.clone();
        let mut observed = marker.authorization;
        if expected.installation_root_identity != observed.installation_root_identity {
            return Err(PackageStagingError::IdentityMismatch);
        }
        expected.installation_root_identity = None;
        observed.installation_root_identity = None;
        if expected != observed {
            return Err(PackageStagingError::IdentityMismatch);
        }
        return Ok(());
    }
    let mac = stage_package_marker_mac(authorization, ownership_key)?;
    let marker = StagePackagePreparedMarker {
        version: STAGE_PACKAGE_MARKER_VERSION,
        authorization: authorization.clone(),
        mac,
    };
    let bytes = serde_json::to_vec(&marker).map_err(|_| PackageStagingError::Io)?;
    let (mut file, _) = match create_destination_file(&marker_path) {
        Ok(file) => file,
        Err(PackageStagingError::GenerationExists) => {
            let marker = read_prepared_marker(&marker_path, ownership_key)?;
            let mut expected = authorization.clone();
            let mut observed = marker.authorization;
            if expected.installation_root_identity != observed.installation_root_identity {
                return Err(PackageStagingError::IdentityMismatch);
            }
            expected.installation_root_identity = None;
            observed.installation_root_identity = None;
            if expected != observed {
                return Err(PackageStagingError::IdentityMismatch);
            }
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    file.write_all(&bytes)
        .map_err(|error| map_package_io_error(error, PackageStagingStage::WriteFile))?;
    flush_file_buffers(&file)?;
    Ok(())
}

fn read_prepared_marker(
    path: &Path,
    ownership_key: &[u8],
) -> Result<StagePackagePreparedMarker, PackageStagingError> {
    if ownership_key.is_empty() {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let file = open_existing_file(path)?;
    #[cfg(windows)]
    {
        let canonical = final_path_from_handle(&file)?;
        if !super::windows_paths_equal(&canonical, path) {
            return Err(PackageStagingError::IdentityMismatch);
        }
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024)
        .read_to_end(&mut bytes)
        .map_err(|error| map_package_io_error(error, PackageStagingStage::ReadFile))?;
    let marker: StagePackagePreparedMarker =
        serde_json::from_slice(&bytes).map_err(|_| PackageStagingError::IdentityMismatch)?;
    if marker.version != STAGE_PACKAGE_MARKER_VERSION {
        return Err(PackageStagingError::IdentityMismatch);
    }
    marker.authorization.validate()?;
    let expected = stage_package_marker_mac(&marker.authorization, ownership_key)?;
    if !constant_time_equal(expected.as_bytes(), marker.mac.as_bytes())
        || marker.authorization.marker_path() != path
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(marker)
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
                installation_lease: lease,
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

    /// Returns the identity of the retained protected installation root.
    #[must_use]
    pub const fn installation_root_identity(&self) -> FileIdentity {
        #[cfg(windows)]
        {
            self.installation_lease.identity()
        }
        #[cfg(not(windows))]
        {
            FileIdentity {
                volume_serial_number: 0,
                file_index: 0,
            }
        }
    }

    /// Persist the exact HMAC-bound `StagePackage` preparation marker and then
    /// perform the normal create-only stage.  The marker is deliberately
    /// retained after success so a process that loses the response can
    /// reconstruct the exact receipt from the destination alone.
    ///
    /// # Errors
    ///
    /// Returns a staging error when the authorization, ownership key, source
    /// snapshot or protected destination cannot be proven exact.
    pub fn stage_authorized(
        &self,
        manifest: &PackageManifest,
        authorization: &StagePackageAuthorization,
        ownership_key: &[u8],
    ) -> Result<StagingReceipt, PackageStagingError> {
        authorization.validate()?;
        if ownership_key.is_empty()
            || !super::windows_paths_equal(&authorization.staging_root, &self.installation_root)
            || authorization.source_bundle_identity != self.source.identity()
            || authorization.generation != manifest.generation
            || authorization.manifest_sha256 != manifest.canonical_digest()
            || authorization.installation_root_identity != Some(self.installation_root_identity())
        {
            return Err(PackageStagingError::IdentityMismatch);
        }
        let observed = self.source.observe()?;
        if observed.files.len() != authorization.expected_files.len()
            || observed.files.iter().any(|actual| {
                authorization
                    .expected_files
                    .iter()
                    .find(|expected| ordinal_eq_str(&expected.relative_path, &actual.relative_path))
                    .is_none_or(|expected| {
                        expected.source_identity != actual.identity
                            || expected.size != actual.size
                            || expected.sha256 != actual.sha256
                    })
            })
        {
            return Err(PackageStagingError::HashMismatch);
        }
        super::installer_root::with_system_restore_privilege_mapped(
            super::InstallerRootProfile::SystemService,
            || {
                write_or_validate_prepared_marker(authorization, ownership_key)?;
                self.stage_with_expected_inventory(manifest, &authorization.expected_files)
            },
            map_restore_privilege_error,
        )
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
        super::installer_root::with_system_restore_privilege_mapped(
            super::InstallerRootProfile::SystemService,
            || self.stage_with_expected_inventory(manifest, &[]),
            map_restore_privilege_error,
        )
    }

    fn stage_with_expected_inventory(
        &self,
        manifest: &PackageManifest,
        expected_sources: &[StagePackageExpectedFile],
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
        let result =
            self.copy_and_measure(&manifest, &generation_root, &mut created, expected_sources);
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
        reconcile_receipt_at_installation_root(&self.installation_root, receipt)
    }

    /// Reconcile a durable receipt using only the retained destination root.
    ///
    /// This path deliberately never opens or infers the source bundle. It is
    /// the recovery seam for a crash after destination publication (including
    /// a source bundle that has already been removed).
    ///
    /// # Errors
    ///
    /// Returns a typed observation error when the destination root, receipt,
    /// identities, security descriptors or exact file evidence cannot be
    /// validated.
    pub fn reconcile_destination_only(
        installation_root: &Path,
        receipt: &StagingReceipt,
    ) -> Result<PackageStagingObservation, PackageStagingError> {
        reconcile_receipt_at_installation_root(installation_root, receipt)
    }

    /// Reconcile an intent whose receipt was lost after the provider had
    /// persisted its preparation marker.  This method opens no source path;
    /// the marker's HMAC and exact source observations are the only admission
    /// authority for reconstructing a receipt.
    ///
    /// # Errors
    ///
    /// Returns a staging error when the marker, ownership key, destination
    /// identity or manifest-bound tree cannot be proven exact.
    pub fn reconcile_prepared_destination_only(
        installation_root: &Path,
        manifest: &PackageManifest,
        authorization: &StagePackageAuthorization,
        ownership_key: &[u8],
    ) -> Result<PackageStagingObservation, PackageStagingError> {
        authorization.validate()?;
        if ownership_key.is_empty()
            || !super::windows_paths_equal(&authorization.staging_root, installation_root)
            || authorization.generation != manifest.generation
            || authorization.manifest_sha256 != manifest.canonical_digest()
        {
            return Err(PackageStagingError::IdentityMismatch);
        }
        let marker_path = authorization.marker_path();
        let marker = match read_prepared_marker(&marker_path, ownership_key) {
            Ok(marker) => marker,
            Err(PackageStagingError::RootUnavailable) => {
                return Ok(PackageStagingObservation::Unknown(
                    PackageStagingError::PartialTree,
                ));
            }
            Err(error) => return Err(error),
        };
        let mut expected_authorization = authorization.clone();
        if expected_authorization.installation_root_identity.is_some()
            && expected_authorization.installation_root_identity
                != marker.authorization.installation_root_identity
        {
            return Err(PackageStagingError::IdentityMismatch);
        }
        expected_authorization.installation_root_identity = None;
        let mut marker_authorization = marker.authorization.clone();
        let marker_root_identity = marker_authorization
            .installation_root_identity
            .ok_or(PackageStagingError::IdentityMismatch)?;
        marker_authorization.installation_root_identity = None;
        if expected_authorization != marker_authorization {
            return Err(PackageStagingError::IdentityMismatch);
        }
        #[cfg(windows)]
        {
            let root = open_existing_directory(installation_root)?;
            if file_identity_from_open_handle(&root)? != marker_root_identity {
                return Err(PackageStagingError::IdentityMismatch);
            }
            verify_system_security(&root, true)?;
            let expectations = marker
                .authorization
                .expected_files
                .iter()
                .map(|file| StagedFileReceipt {
                    relative_path: file.relative_path.clone(),
                    source_identity: file.source_identity,
                    destination_identity: FileIdentity {
                        volume_serial_number: 0,
                        file_index: 0,
                    },
                    size: file.size,
                    sha256: file.sha256.clone(),
                    security_descriptor_sha256: String::new(),
                    pe: None,
                    authenticode: None,
                })
                .collect::<Vec<_>>();
            inspect_published_destination_at_installation_root(
                installation_root,
                manifest,
                &expectations,
            )
        }
        #[cfg(not(windows))]
        {
            let _ = (installation_root, manifest, marker_root_identity, marker);
            Err(PackageStagingError::UnsupportedPlatform)
        }
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
        Self::rollback_destination_only(&self.installation_root, receipt)
    }

    /// Roll back an exact receipt without opening or validating the source
    /// bundle.  This is the only rollback path permitted after a receipt has
    /// been durably persisted.
    ///
    /// # Errors
    ///
    /// Returns a staging error when the receipt, destination identity, tree,
    /// security descriptors or exact deletion cannot be proven.
    pub fn rollback_destination_only(
        installation_root: &Path,
        receipt: &StagingReceipt,
    ) -> Result<(), PackageStagingError> {
        validate_receipt_file_grammar(&receipt.files)?;
        let manifest = PackageManifest::new(
            &receipt.generation,
            receipt
                .files
                .iter()
                .map(|file| PackageFileSpec {
                    relative_path: file.relative_path.clone(),
                    executable: file.pe.is_some(),
                    expected_size: file.size,
                })
                .collect(),
        )?;
        if receipt.manifest_sha256 != manifest.canonical_digest() {
            return Err(PackageStagingError::HashMismatch);
        }
        validate_receipt_directories(receipt, &manifest)?;
        let generation = validate_relative_text(&manifest.generation)?;
        let parent_components = generation
            .components
            .get(..generation.components.len().saturating_sub(1))
            .unwrap_or(&[]);
        let mut parent_path = installation_root.to_path_buf();
        for component in parent_components {
            parent_path.push(component);
        }
        let parent = retain_destination_parent(&parent_path)?;
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
        root: &Path,
        manifest: &PackageManifest,
        expected_files: &[StagedFileReceipt],
    ) -> Result<Vec<StagedFileReceipt>, PackageStagingError> {
        let mut files = Vec::with_capacity(manifest.files.len());
        for spec in &manifest.files {
            let relative = validate_relative_text(&spec.relative_path)?;
            let destination = relative.join_to(root);
            let source_identity = expected_files
                .iter()
                .find(|file| ordinal_eq_str(&file.relative_path, &spec.relative_path))
                .ok_or(PackageStagingError::TreeMismatch)?
                .source_identity;
            let mut destination_file = open_existing_file(&destination)?;
            let destination_identity = file_identity_from_open_handle(&destination_file)?;
            let destination_snapshot = read_destination_snapshot_handle(
                &destination_file,
                &destination,
                spec.expected_size,
                destination_identity,
            )?;
            let pe = if spec.executable {
                let header = read_file_prefix_handle(&destination_file, MAX_PE_HEADER_BYTES)?;
                Some(parse_pe_coff(&header).map_err(PackageStagingError::PeParse)?)
            } else {
                None
            };
            let authenticode = if spec.executable {
                let evidence = verify_authenticode_handle(
                    &destination,
                    &mut destination_file,
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
                source_identity,
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

    fn copy_and_measure(
        &self,
        manifest: &PackageManifest,
        destination_root: &Path,
        created: &mut CreatedTree,
        expected_sources: &[StagePackageExpectedFile],
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
                &mut total,
                created,
                expected_sources,
            )?);
        }
        Ok(files)
    }

    fn copy_one_file(
        &self,
        spec: &PackageFileSpec,
        destination_root: &Path,
        total: &mut u64,
        created: &mut CreatedTree,
        expected_sources: &[StagePackageExpectedFile],
    ) -> Result<StagedFileReceipt, PackageStagingError> {
        let relative = validate_relative_text(&spec.relative_path)?;
        let source = relative.join_to(self.source.path());
        let destination = relative.join_to(destination_root);
        let source_snapshot = snapshot_source_file(&source, spec.expected_size)?;
        if !expected_sources.is_empty() {
            let expected = expected_sources
                .iter()
                .find(|expected| ordinal_eq_str(&expected.relative_path, &spec.relative_path))
                .ok_or(PackageStagingError::IdentityMismatch)?;
            if expected.source_identity != source_snapshot.identity
                || expected.size != source_snapshot.size
                || expected.sha256 != source_snapshot.sha256
            {
                return Err(PackageStagingError::HashMismatch);
            }
        }
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
        let (mut destination_file, destination_identity, destination_readback) =
            copy_destination_bytes(&source_snapshot, &destination, spec.expected_size)?;
        let authenticode = if spec.executable {
            let evidence = match verify_authenticode_handle(
                &destination,
                &mut destination_file,
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
    expected_size: u64,
) -> Result<(std::fs::File, FileIdentity, DestinationSnapshot), PackageStagingError> {
    let (mut destination_file, destination_identity) = create_destination_file(destination)?;
    let copy_hash =
        match copy_source_to_destination(source_snapshot, &mut destination_file, expected_size) {
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
        expected_size,
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
    _expected_size: u64,
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

fn validate_receipt_file_grammar(files: &[StagedFileReceipt]) -> Result<(), PackageStagingError> {
    for file in files {
        if file.source_identity.volume_serial_number == 0
            || file.source_identity.file_index == 0
            || file.destination_identity.volume_serial_number == 0
            || file.destination_identity.file_index == 0
            || file.size == 0
            || !super::valid_sha256_hex(&file.sha256)
            || !super::valid_sha256_hex(&file.security_descriptor_sha256)
            || (file.pe.is_some() != file.authenticode.is_some())
            || file
                .authenticode
                .as_ref()
                .is_some_and(|evidence| evidence.verdict != AuthenticodeVerdict::Valid)
        {
            return Err(PackageStagingError::IdentityMismatch);
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
        let read_dir = std::fs::read_dir(&directory).map_err(map_package_open_error)?;
        for entry in read_dir {
            let entry = entry.map_err(map_package_open_error)?;
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
            let metadata = std::fs::symlink_metadata(&path).map_err(map_package_open_error)?;
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
    on_file: F,
) -> Result<Vec<TreeEntry>, PackageStagingError>
where
    F: FnMut(
        &PackageRelativePath,
        &Path,
        &std::fs::File,
        FileIdentity,
    ) -> Result<(), PackageStagingError>,
{
    walk_trusted_source_tree_with_root(root, None, on_file)
}

#[cfg(windows)]
fn walk_trusted_source_tree_with_root<F>(
    root: &Path,
    retained_root: Option<&std::fs::File>,
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
    let root_handle = match retained_root {
        Some(root) => root
            .try_clone()
            .map_err(|error| map_package_io_error(error, PackageStagingStage::DuplicateHandle))?,
        None => open_existing_directory(root)?,
    };
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
        let read_dir = std::fs::read_dir(&directory).map_err(map_package_open_error)?;
        for entry in read_dir {
            let entry = entry.map_err(map_package_open_error)?;
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
            let metadata = std::fs::symlink_metadata(&path).map_err(map_package_open_error)?;
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
fn enumerate_trusted_source_tree(
    _root: &Path,
    _manifest: &PackageManifest,
) -> Result<Vec<TreeEntry>, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
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
            Err(error) => return Err(map_package_open_error(error)),
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
        identity: file_identity_from_open_handle(
            contour.last().ok_or(PackageStagingError::RootUnavailable)?,
        )?,
        contour,
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
    use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
    open_existing_directory_with_access(path, FILE_GENERIC_READ)
}

#[cfg(windows)]
fn open_existing_directory_for_create(path: &Path) -> Result<std::fs::File, PackageStagingError> {
    use windows_sys::Win32::Storage::FileSystem::{FILE_ADD_SUBDIRECTORY, FILE_GENERIC_READ};
    open_existing_directory_with_access(path, FILE_GENERIC_READ | FILE_ADD_SUBDIRECTORY)
}

#[cfg(windows)]
fn open_existing_directory_with_access(
    path: &Path,
    access: u32,
) -> Result<std::fs::File, PackageStagingError> {
    use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        // Delete sharing remains omitted so an ancestor cannot be renamed
        // while its exact handle is being observed or used for creation.
        .access_mode(access)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(map_package_open_error)?;
    let metadata = file.metadata().map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })?;
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
    let file = options.open(path).map_err(map_package_open_error)?;
    let metadata = file.metadata().map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })?;
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
        FILE_SHARE_READ,
    };
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        // Retain a read-only observation fence: future writers and deletes
        // cannot open this object while the handle is live.
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    let file = options.open(path).map_err(map_package_open_error)?;
    let metadata = file.metadata().map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })?;
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
    let file = options.open(path).map_err(map_package_open_error)?;
    let metadata = file.metadata().map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })?;
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
    let file = options.open(path).map_err(map_package_open_error)?;
    let metadata = file.metadata().map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })?;
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
    super::file_identity_from_handle(file).map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })
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
        return Err(PackageStagingError::Win32 {
            stage: PackageStagingStage::GetFileInformationByHandle,
            code: unsafe { windows_sys::Win32::Foundation::GetLastError() },
        });
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
        Err(error) => Err(map_package_open_error(error)),
    }
}

#[cfg(not(windows))]
fn path_exists(_path: &Path) -> Result<bool, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn is_directory_path(path: &Path) -> Result<bool, PackageStagingError> {
    let metadata = std::fs::symlink_metadata(path).map_err(map_package_open_error)?;
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
    if super::verify_exact_file_security(file, &expected, "S-1-5-18").is_err() {
        // The shared verifier intentionally exposes only its semantic adapter
        // error. Probe the same handle once more to retain a raw GetSecurityInfo
        // status when the OS could not even produce a descriptor; any other
        // result remains a fail-closed ACL/security mismatch.
        return match security_descriptor_digest(file) {
            Err(
                error @ PackageStagingError::Win32 {
                    stage: PackageStagingStage::GetSecurityInfo,
                    ..
                },
            ) => Err(error),
            _ => Err(PackageStagingError::SecurityMismatch),
        };
    }
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

#[cfg(not(windows))]
fn verify_system_directory_at(_path: &Path) -> Result<(), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
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
        return Err(PackageStagingError::Win32 {
            stage: PackageStagingStage::GetSecurityInfo,
            code: status,
        });
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
    let parent = path.parent().ok_or(PackageStagingError::RootUnavailable)?;
    let parent_file = open_existing_directory_for_create(parent)?;
    let descriptor = super::OwnedSecurityDescriptor::for_installer_system_object(true)
        .map_err(|_| PackageStagingError::SecurityMismatch)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PackageStagingError::InvalidRelativePath)?;
    let root = super::create_owned_directory_relative(&parent_file, name, descriptor.raw)
        .map_err(map_directory_publication_error)?;
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
fn is_create_new_collision(code: u32) -> bool {
    use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};

    code == ERROR_FILE_EXISTS || code == ERROR_ALREADY_EXISTS
}

#[cfg(windows)]
fn create_destination_file(
    path: &Path,
) -> Result<(std::fs::File, FileIdentity), PackageStagingError> {
    use std::os::windows::io::FromRawHandle as _;
    use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_WRITE_THROUGH, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ,
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
        // create-only and the retained handle omits write/delete sharing.
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
            FILE_SHARE_READ,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
            std::ptr::null_mut(),
        )
    };
    drop(parent_file);
    if handle == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError() };
        return if is_create_new_collision(code) {
            Err(PackageStagingError::GenerationExists)
        } else {
            Err(PackageStagingError::Win32 {
                stage: PackageStagingStage::CreateFileW,
                code,
            })
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
    let parent = path.parent().ok_or(PackageStagingError::RootUnavailable)?;
    let parent_file = open_existing_directory_for_create(parent)?;
    let descriptor = super::OwnedSecurityDescriptor::for_installer_system_object(true)
        .map_err(|_| PackageStagingError::SecurityMismatch)?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(PackageStagingError::InvalidRelativePath)?;
    let directory = super::create_owned_directory_relative(&parent_file, name, descriptor.raw)
        .map_err(map_directory_publication_error)?;
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

#[cfg(not(windows))]
fn cleanup_created_handle(
    file: std::fs::File,
    identity: FileIdentity,
    original: PackageStagingError,
) -> PackageStagingError {
    let _ = (file, identity, original);
    PackageStagingError::UnsupportedPlatform
}

#[cfg(windows)]
fn snapshot_source_file(
    path: &Path,
    expected_size: u64,
) -> Result<SourceSnapshot, PackageStagingError> {
    let mut file = open_trusted_source_file(path)?;
    let canonical = final_path_from_handle(&file)?;
    if !super::windows_paths_equal(&canonical, path) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let identity = file_identity_from_open_handle(&file)?;
    ensure_single_link(&file)?;
    let metadata = file.metadata().map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })?;
    if metadata.len() != expected_size {
        return Err(PackageStagingError::SizeMismatch);
    }
    if metadata.len() > MAX_PACKAGE_FILE_BYTES {
        return Err(PackageStagingError::BoundExceeded);
    }
    let size = metadata.len();
    file.seek(SeekFrom::Start(0))
        .map_err(|error| map_package_io_error(error, PackageStagingStage::SetFilePointerEx))?;
    let mut digest = Sha256::new();
    let mut header = Vec::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut read_total = 0_u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| map_package_io_error(error, PackageStagingStage::ReadFile))?;
        if read == 0 {
            break;
        }
        read_total = read_total
            .checked_add(read as u64)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if read_total > expected_size {
            return Err(PackageStagingError::SizeMismatch);
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
    let after_size = file
        .metadata()
        .map_err(|error| {
            map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
        })?
        .len();
    if after_identity != identity
        || !super::windows_paths_equal(&after_path, path)
        || after_size != size
    {
        return Err(PackageStagingError::IdentityMismatch);
    }
    Ok(SourceSnapshot {
        identity,
        size,
        sha256: encode_digest_hex(&digest.finalize()),
        pe_header: header,
        file,
    })
}

#[cfg(windows)]
fn observe_source_handle(
    file: &std::fs::File,
    expected_path: &Path,
    max_observation_size: u64,
) -> Result<ObservedSourceRead, PackageStagingError> {
    observe_source_handle_with_post_read_hook(file, expected_path, max_observation_size, || {})
}

#[cfg(windows)]
fn observe_source_handle_with_post_read_hook<H: FnOnce()>(
    file: &std::fs::File,
    expected_path: &Path,
    max_observation_size: u64,
    post_read_hook: H,
) -> Result<ObservedSourceRead, PackageStagingError> {
    let identity = file_identity_from_open_handle(file)?;
    let before_path = final_path_from_handle(file)?;
    if !super::windows_paths_equal(&before_path, expected_path) {
        return Err(PackageStagingError::IdentityMismatch);
    }
    let before_size = file
        .metadata()
        .map_err(|error| {
            map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
        })?
        .len();
    if before_size > max_observation_size || before_size > MAX_PACKAGE_FILE_BYTES {
        return Err(PackageStagingError::BoundExceeded);
    }
    let mut reader = file
        .try_clone()
        .map_err(|error| map_package_io_error(error, PackageStagingStage::DuplicateHandle))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| map_package_io_error(error, PackageStagingStage::SetFilePointerEx))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut header = Vec::new();
    let mut size = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| map_package_io_error(error, PackageStagingStage::ReadFile))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if size > max_observation_size || size > MAX_PACKAGE_FILE_BYTES {
            return Err(PackageStagingError::BoundExceeded);
        }
        digest.update(&buffer[..read]);
        if header.len() < MAX_PE_HEADER_BYTES {
            let take = (MAX_PE_HEADER_BYTES - header.len()).min(read);
            header.extend_from_slice(&buffer[..take]);
        }
    }
    if size != before_size {
        return Err(PackageStagingError::SizeMismatch);
    }
    post_read_hook();
    ensure_single_link(file)?;
    let after_identity = file_identity_from_open_handle(file)?;
    let after_path = final_path_from_handle(file)?;
    let after_size = file
        .metadata()
        .map_err(|error| {
            map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
        })?
        .len();
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
        sha256: encode_digest_hex(&digest.finalize()),
        pe: parse_pe_coff(&header).ok(),
    })
}

#[cfg(windows)]
#[derive(Debug)]
struct ObservedSourceRead {
    size: u64,
    sha256: String,
    pe: Option<PeCoffEvidence>,
}

#[cfg(not(windows))]
fn snapshot_source_file(
    _path: &Path,
    _expected_size: u64,
) -> Result<SourceSnapshot, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn copy_source_to_destination(
    source_snapshot: &SourceSnapshot,
    destination: &mut std::fs::File,
    expected_size: u64,
) -> Result<String, PackageStagingError> {
    let mut source = source_snapshot
        .file
        .try_clone()
        .map_err(|error| map_package_io_error(error, PackageStagingStage::DuplicateHandle))?;
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| map_package_io_error(error, PackageStagingStage::SetFilePointerEx))?;
    destination
        .seek(SeekFrom::Start(0))
        .map_err(|error| map_package_io_error(error, PackageStagingStage::SetFilePointerEx))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut total = 0_u64;
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|error| map_package_io_error(error, PackageStagingStage::ReadFile))?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if total > expected_size {
            return Err(PackageStagingError::SizeMismatch);
        }
        destination
            .write_all(&buffer[..read])
            .map_err(|error| map_package_io_error(error, PackageStagingStage::WriteFile))?;
        digest.update(&buffer[..read]);
    }
    if total != source_snapshot.size {
        return Err(PackageStagingError::SizeMismatch);
    }
    flush_file_buffers(destination)?;
    Ok(encode_digest_hex(&digest.finalize()))
}

#[cfg(not(windows))]
fn copy_source_to_destination(
    _source: &SourceSnapshot,
    _destination: &mut std::fs::File,
    _expected_size: u64,
) -> Result<String, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn flush_file_buffers(file: &std::fs::File) -> Result<(), PackageStagingError> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::FlushFileBuffers;
    let ok = unsafe {
        // SAFETY: file owns a live writable handle.
        FlushFileBuffers(file.as_raw_handle().cast())
    };
    if ok == 0 {
        return Err(PackageStagingError::Win32 {
            stage: PackageStagingStage::FlushFileBuffers,
            code: unsafe { GetLastError() },
        });
    }
    Ok(())
}

#[cfg(not(windows))]
fn flush_file_buffers(_file: &std::fs::File) -> Result<(), PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
#[cfg(test)]
fn read_destination_snapshot(
    path: &Path,
    expected_size: u64,
    expected_identity: FileIdentity,
) -> Result<DestinationSnapshot, PackageStagingError> {
    let file = open_existing_file(path)?;
    read_destination_snapshot_handle(&file, path, expected_size, expected_identity)
}

#[cfg(windows)]
fn read_destination_snapshot_handle(
    file: &std::fs::File,
    expected_path: &Path,
    expected_size: u64,
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
    let metadata = file.metadata().map_err(|error| {
        map_package_io_error(error, PackageStagingStage::GetFileInformationByHandle)
    })?;
    if metadata.len() != expected_size {
        return Err(PackageStagingError::SizeMismatch);
    }
    if metadata.len() > MAX_PACKAGE_FILE_BYTES {
        return Err(PackageStagingError::BoundExceeded);
    }
    let mut reader = file
        .try_clone()
        .map_err(|error| map_package_io_error(error, PackageStagingStage::DuplicateHandle))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| map_package_io_error(error, PackageStagingStage::SetFilePointerEx))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_BYTES];
    let mut size = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| map_package_io_error(error, PackageStagingStage::ReadFile))?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(PackageStagingError::BoundExceeded)?;
        if size > expected_size {
            return Err(PackageStagingError::SizeMismatch);
        }
        digest.update(&buffer[..read]);
    }
    if size != metadata.len() {
        return Err(PackageStagingError::SizeMismatch);
    }
    let security_descriptor_sha256 = verify_system_security(file, false)?;
    Ok(DestinationSnapshot {
        size,
        sha256: encode_digest_hex(&digest.finalize()),
        security_descriptor_sha256,
    })
}

#[cfg(not(windows))]
fn read_destination_snapshot_handle(
    _file: &std::fs::File,
    _expected_path: &Path,
    _expected_size: u64,
    _expected_identity: FileIdentity,
) -> Result<DestinationSnapshot, PackageStagingError> {
    Err(PackageStagingError::UnsupportedPlatform)
}

#[cfg(windows)]
fn read_file_prefix_handle(
    file: &std::fs::File,
    limit: usize,
) -> Result<Vec<u8>, PackageStagingError> {
    let file = file
        .try_clone()
        .map_err(|error| map_package_io_error(error, PackageStagingStage::DuplicateHandle))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).map_err(|_| PackageStagingError::BoundExceeded)?)
        .read_to_end(&mut bytes)
        .map_err(|error| map_package_io_error(error, PackageStagingStage::ReadFile))?;
    Ok(bytes)
}

#[cfg(not(windows))]
fn read_file_prefix_handle(
    _file: &std::fs::File,
    _limit: usize,
) -> Result<Vec<u8>, PackageStagingError> {
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

    type TestResult = Result<(), Box<dyn std::error::Error>>;
    #[cfg(windows)]
    type FixtureResult<T> = Result<T, Box<dyn std::error::Error>>;

    fn file(path: &str, executable: bool) -> PackageFileSpec {
        PackageFileSpec {
            relative_path: path.to_owned(),
            executable,
            expected_size: 1024,
        }
    }

    #[cfg(windows)]
    fn security_fixture_unavailable(error: &PackageStagingError) -> bool {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_INVALID_OWNER, ERROR_PRIVILEGE_NOT_HELD,
        };

        match error {
            PackageStagingError::Io | PackageStagingError::SecurityMismatch => true,
            PackageStagingError::Win32 { code, .. } => matches!(
                *code,
                ERROR_ACCESS_DENIED | ERROR_INVALID_OWNER | ERROR_PRIVILEGE_NOT_HELD
            ),
            _ => false,
        }
    }

    #[cfg(windows)]
    struct AgentBridgeFixture {
        root_path: PathBuf,
        source_path: PathBuf,
        destination_path: PathBuf,
        root: crate::ProtectedRootLease,
    }

    #[cfg(windows)]
    fn agent_bridge_fixture() -> FixtureResult<Option<AgentBridgeFixture>> {
        let root_path = crate::protected_program_data_root()?.join(format!(
            "eliot-agent-bridge-stage-{}",
            super::super::unique_suffix()
        ));
        let source_path = std::env::temp_dir().join(format!(
            "eliot-agent-bridge-source-{}",
            super::super::unique_suffix()
        ));
        let destination_path = root_path
            .join("external-modules")
            .join("eliot-agent-bridge")
            .join("generation")
            .join("eliot-agent-bridge.exe");
        let mut created = Vec::new();
        for directory in [
            root_path.clone(),
            root_path.join("external-modules"),
            root_path
                .join("external-modules")
                .join("eliot-agent-bridge"),
            root_path
                .join("external-modules")
                .join("eliot-agent-bridge")
                .join("generation"),
        ] {
            match create_destination_directory(&directory) {
                Ok((file, identity, _)) => {
                    created.push((file, identity));
                }
                Err(error) if security_fixture_unavailable(&error) => {
                    drop(created);
                    let _ = std::fs::remove_dir_all(&root_path);
                    return Ok(None);
                }
                Err(error) => {
                    drop(created);
                    let _ = std::fs::remove_dir_all(&root_path);
                    return Err(error.into());
                }
            }
        }
        drop(created);
        if let Err(error) = std::fs::write(&source_path, b"agent-bridge-fixture") {
            let _ = std::fs::remove_file(&source_path);
            let _ = std::fs::remove_dir_all(&root_path);
            return Err(error.into());
        }
        let root = match crate::ProtectedRootLease::open_existing(&root_path) {
            Ok(root) => root,
            Err(error) => {
                let _ = std::fs::remove_file(&source_path);
                let _ = std::fs::remove_dir_all(&root_path);
                return Err(std::io::Error::other(error.to_string()).into());
            }
        };
        Ok(Some(AgentBridgeFixture {
            root_path,
            source_path,
            destination_path,
            root,
        }))
    }

    #[cfg(windows)]
    fn agent_bridge_request(
        fixture: &AgentBridgeFixture,
    ) -> Result<AgentBridgeStagingRequest, PackageStagingError> {
        let observed = snapshot_source_file(&fixture.source_path, 20)?;
        Ok(AgentBridgeStagingRequest {
            source_path: fixture.source_path.clone(),
            source_identity: observed.identity,
            source_sha256: observed.sha256,
            source_size: observed.size,
            destination_path: fixture.destination_path.clone(),
        })
    }

    #[cfg(windows)]
    fn cleanup_agent_bridge_fixture(fixture: AgentBridgeFixture) {
        drop(fixture.root);
        let _ = std::fs::remove_file(&fixture.source_path);
        let _ = std::fs::remove_dir_all(&fixture.root_path);
    }

    #[cfg(windows)]
    fn arm_agent_bridge_post_create_failure(kind: u8) {
        AGENT_BRIDGE_POST_CREATE_FAILURE.store(kind, AtomicOrdering::SeqCst);
    }

    #[cfg(windows)]
    fn clear_agent_bridge_post_create_failure() {
        AGENT_BRIDGE_POST_CREATE_FAILURE.store(0, AtomicOrdering::SeqCst);
    }

    #[cfg(windows)]
    fn assert_no_agent_bridge_temporary(
        fixture: &AgentBridgeFixture,
        transaction_id: &str,
        effect_id: &str,
        request_digest: &str,
    ) -> TestResult {
        let parent = fixture
            .destination_path
            .parent()
            .ok_or_else(|| std::io::Error::other("fixture destination has no parent"))?;
        let prefix = agent_bridge_operation_temporary_prefix(
            parent,
            &fixture.destination_path,
            transaction_id,
            effect_id,
            request_digest,
        );
        let found = std::fs::read_dir(parent)?.any(|entry| {
            entry
                .ok()
                .and_then(|entry| entry.file_name().into_string().ok())
                .is_some_and(|name| name.starts_with(&prefix))
        });
        assert!(!found, "unexpected retained Agent Bridge temporary");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_post_create_failures_clean_exact_temporary() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let transaction_id = "transaction:post-create-final-path";
        let effect_id = "effect:post-create-final-path";
        let request_digest = "4".repeat(64);
        arm_agent_bridge_post_create_failure(AGENT_BRIDGE_FAIL_FINAL_PATH);
        let result = prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            transaction_id,
            effect_id,
            &request_digest,
        );
        clear_agent_bridge_post_create_failure();
        match result {
            Err(PackageStagingError::Win32 {
                stage: PackageStagingStage::GetFinalPathNameByHandleW,
                code: 5,
            }) => {}
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            other => panic!("unexpected post-create final-path result: {other:?}"),
        }
        assert_no_agent_bridge_temporary(&fixture, transaction_id, effect_id, &request_digest)?;
        cleanup_agent_bridge_fixture(fixture);

        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let transaction_id = "transaction:post-create-path-exists";
        let effect_id = "effect:post-create-path-exists";
        let request_digest = "5".repeat(64);
        arm_agent_bridge_post_create_failure(AGENT_BRIDGE_FAIL_DESTINATION_EXISTS);
        let result = prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            transaction_id,
            effect_id,
            &request_digest,
        );
        clear_agent_bridge_post_create_failure();
        match result {
            Err(PackageStagingError::Win32 {
                stage: PackageStagingStage::GetFileInformationByHandle,
                code: 5,
            }) => {}
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            other => panic!("unexpected post-create path-exists result: {other:?}"),
        }
        assert_no_agent_bridge_temporary(&fixture, transaction_id, effect_id, &request_digest)?;
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_staging_success_receipts_are_serializable_and_read_back() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let prepared = match prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            "transaction:success",
            "effect:success",
            &"0".repeat(64),
        ) {
            Ok(prepared) => prepared,
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let receipt = reconcile_agent_bridge_stage(&fixture.root, &prepared)?;
        assert_eq!(receipt.source_identity, request.source_identity);
        assert_eq!(receipt.destination_path, request.destination_path);
        assert_eq!(receipt.sha256, request.source_sha256);
        assert_eq!(receipt.size, request.source_size);
        assert_eq!(
            receipt.create_disposition,
            AgentBridgeStagingCreateDisposition::Created
        );
        assert_eq!(
            serde_json::from_str::<AgentBridgeStagingReceipt>(&serde_json::to_string(&receipt)?)?,
            receipt
        );
        assert_eq!(receipt.destination_identity, prepared.destination_identity);
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_staging_rejects_source_substitution() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let replacement = fixture.source_path.with_extension("replacement");
        std::fs::rename(&fixture.source_path, &replacement)?;
        std::fs::write(&fixture.source_path, b"substituted-source-file")?;
        assert_eq!(
            prepare_agent_bridge_stage(
                &fixture.root,
                &request,
                "transaction:source-substitution",
                "effect:source-substitution",
                &"1".repeat(64),
            ),
            Err(PackageStagingError::IdentityMismatch)
        );
        let _ = std::fs::remove_file(replacement);
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_staging_rejects_destination_preexistence_without_overwrite() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        std::fs::write(&fixture.destination_path, b"foreign")?;
        let request = agent_bridge_request(&fixture)?;
        assert_eq!(
            prepare_agent_bridge_stage(
                &fixture.root,
                &request,
                "transaction:destination-preexisting",
                "effect:destination-preexisting",
                &"2".repeat(64),
            ),
            Err(PackageStagingError::GenerationExists)
        );
        assert_eq!(std::fs::read(&fixture.destination_path)?, b"foreign");
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_staging_retry_rejects_foreign_bytes_and_absence() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let prepared = match prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            "transaction:retry",
            "effect:retry",
            &"3".repeat(64),
        ) {
            Ok(prepared) => prepared,
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        reconcile_agent_bridge_stage(&fixture.root, &prepared)?;
        drop(fixture.root);
        std::fs::write(&fixture.destination_path, b"foreign")?;
        let root = crate::ProtectedRootLease::open_existing(&fixture.root_path)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        assert!(matches!(
            reconcile_agent_bridge_stage(&root, &prepared),
            Err(PackageStagingError::HashMismatch | PackageStagingError::IdentityMismatch)
        ));
        drop(root);
        std::fs::remove_file(&fixture.destination_path)?;
        let root = crate::ProtectedRootLease::open_existing(&fixture.root_path)
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        assert_eq!(
            reconcile_agent_bridge_stage(&root, &prepared),
            Err(PackageStagingError::PartialTree)
        );
        drop(root);
        let _ = std::fs::remove_file(&fixture.source_path);
        let _ = std::fs::remove_dir_all(&fixture.root_path);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_prepared_roundtrip_and_binding_substitution_are_rejected() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let prepared = match prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            "transaction:prepared",
            "effect:prepared",
            &"a".repeat(64),
        ) {
            Ok(prepared) => prepared,
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let encoded = serde_json::to_string(&prepared)?;
        assert_eq!(
            serde_json::from_str::<AgentBridgeStagePrepared>(&encoded)?,
            prepared
        );
        assert!(prepared.temporary_path.exists());
        let mut substituted = prepared.clone();
        substituted.request_digest = "b".repeat(64);
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &substituted),
            Err(PackageStagingError::IdentityMismatch)
        );
        let mut nested = prepared.clone();
        nested.source_size += 1;
        assert_eq!(
            publish_agent_bridge_stage(&fixture.root, &nested),
            Err(PackageStagingError::IdentityMismatch)
        );
        let mut transaction = prepared.clone();
        transaction.transaction_id.push_str(":substituted");
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &transaction),
            Err(PackageStagingError::IdentityMismatch)
        );
        let mut effect = prepared.clone();
        effect.effect_id.push_str(":substituted");
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &effect),
            Err(PackageStagingError::IdentityMismatch)
        );
        let mut parent = prepared.clone();
        parent.parent_identity.file_index += 1;
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &parent),
            Err(PackageStagingError::IdentityMismatch)
        );
        let mut temporary = prepared.clone();
        temporary.temporary_identity.file_index += 1;
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &temporary),
            Err(PackageStagingError::IdentityMismatch)
        );
        let mut destination = prepared.clone();
        destination.destination_identity.file_index += 1;
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &destination),
            Err(PackageStagingError::IdentityMismatch)
        );
        let mut wire = prepared.clone();
        wire.wire.push_str(":substituted");
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &wire),
            Err(PackageStagingError::IdentityMismatch)
        );
        let mut version = prepared.clone();
        version.wire_version += 1;
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &version),
            Err(PackageStagingError::IdentityMismatch)
        );
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_prepared_reconcile_publishes_before_rename_recovery() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let prepared = match prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            "transaction:before-rename",
            "effect:before-rename",
            &"c".repeat(64),
        ) {
            Ok(prepared) => prepared,
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let receipt = reconcile_agent_bridge_stage(&fixture.root, &prepared)?;
        assert_eq!(
            std::fs::read(&fixture.destination_path)?,
            b"agent-bridge-fixture"
        );
        assert!(!prepared.temporary_path.exists());
        assert_eq!(receipt.destination_identity, prepared.temporary_identity);
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_prepared_response_loss_after_rename_reconciles_exactly() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let prepared = match prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            "transaction:response-loss",
            "effect:response-loss",
            &"d".repeat(64),
        ) {
            Ok(prepared) => prepared,
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let first = publish_agent_bridge_stage(&fixture.root, &prepared)?;
        let second = reconcile_agent_bridge_stage(&fixture.root, &prepared)?;
        assert_eq!(first, second);
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_prepare_retry_uses_fresh_temp_without_adopting_orphan() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let first = match prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            "transaction:orphan-retry",
            "effect:orphan-retry",
            &"a".repeat(64),
        ) {
            Ok(prepared) => prepared,
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        assert!(first.temporary_path.exists());

        let second = prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            "transaction:orphan-retry",
            "effect:orphan-retry",
            &"a".repeat(64),
        )?;
        assert_ne!(first.temporary_path, second.temporary_path);
        assert_ne!(first.temporary_identity, second.temporary_identity);
        assert!(first.temporary_path.exists());
        publish_agent_bridge_stage(&fixture.root, &second)?;
        assert_eq!(
            std::fs::read(&fixture.destination_path)?,
            b"agent-bridge-fixture"
        );
        assert!(first.temporary_path.exists());
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_prepared_foreign_temp_and_final_never_adopted() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let prepared = match prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            "transaction:foreign",
            "effect:foreign",
            &"e".repeat(64),
        ) {
            Ok(prepared) => prepared,
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        std::fs::remove_file(&prepared.temporary_path)?;
        std::fs::write(&prepared.temporary_path, b"foreign-temp")?;
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &prepared),
            Err(PackageStagingError::IdentityMismatch)
        );
        std::fs::remove_file(&prepared.temporary_path)?;
        std::fs::write(&fixture.destination_path, b"foreign-final")?;
        assert!(matches!(
            reconcile_agent_bridge_stage(&fixture.root, &prepared),
            Err(PackageStagingError::IdentityMismatch | PackageStagingError::HashMismatch)
        ));
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn agent_bridge_prepared_rejects_foreign_temp_shape() -> TestResult {
        let Some(fixture) = agent_bridge_fixture()? else {
            return Ok(());
        };
        let request = agent_bridge_request(&fixture)?;
        let prepared = match prepare_agent_bridge_stage(
            &fixture.root,
            &request,
            "transaction:cleanup",
            "effect:cleanup",
            &"f".repeat(64),
        ) {
            Ok(prepared) => prepared,
            Err(error) if security_fixture_unavailable(&error) => {
                cleanup_agent_bridge_fixture(fixture);
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        let parent = prepared
            .temporary_path
            .parent()
            .ok_or_else(|| std::io::Error::other("prepared temp parent"))?;
        let mut foreign = prepared.clone();
        foreign.temporary_path = parent.join(".eliot-agent-bridge.foreign.tmp");
        assert_eq!(
            reconcile_agent_bridge_stage(&fixture.root, &foreign),
            Err(PackageStagingError::IdentityMismatch)
        );
        cleanup_agent_bridge_fixture(fixture);
        Ok(())
    }

    #[test]
    fn digest_helpers_encode_one_sha256_for_known_vector() {
        let digest = Sha256::digest(b"abc");
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(encode_digest_hex(digest.as_slice()), expected);
        assert_eq!(hex_digest(b"abc"), expected);
    }

    #[cfg(windows)]
    #[test]
    fn hash_file_returns_single_sha256_for_file_contents() -> TestResult {
        let path = std::env::temp_dir().join(format!(
            "eliot-package-hash-file-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::write(&path, b"abc")?;
        let mut file = std::fs::OpenOptions::new().read(true).open(&path)?;
        assert_eq!(
            hash_file(&mut file)?,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        drop(file);
        std::fs::remove_file(path)?;
        Ok(())
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
    fn relative_path_and_manifest_digest_are_stable_under_reordering() -> TestResult {
        let first = PackageManifest::new(
            "g1",
            vec![file("Bin/Z.dll", false), file("Bin/A.exe", true)],
        )?;
        let second = PackageManifest::new(
            "g1",
            vec![file("Bin/A.exe", true), file("Bin/Z.dll", false)],
        )?;
        assert_eq!(first.canonical_digest(), second.canonical_digest());
        assert_eq!(validate_relative_text("bin/A.exe")?.as_str(), "bin/A.exe");
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn unicode_ordinal_component_order_and_collision_are_explicit() -> TestResult {
        let manifest = PackageManifest::new(
            "g1",
            vec![
                file("épsilon.txt", false),
                file("zeta.txt", false),
                file("alpha.txt", false),
            ],
        )?;
        let mut expected = manifest
            .files
            .iter()
            .map(|file| validate_relative_text(&file.relative_path))
            .collect::<Result<Vec<_>, _>>()?;
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
        Ok(())
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
    fn package_staging_authenticode_dispatch_is_official_only() {
        let source = include_str!("package_staging.rs");
        let generic_stage_method = ["stage_", "with_verifier"].concat();
        let generic_dispatch_type = ["Staging", "Authenticode", "Verifier"].concat();
        let generic_variant = ["Generic", "("].concat();
        assert!(!source.contains(&generic_stage_method));
        assert!(!source.contains(&generic_dispatch_type));
        assert!(!source.contains(&generic_variant));
    }

    #[test]
    fn system_owned_package_mutations_are_restore_scoped() {
        let source = include_str!("package_staging.rs");
        assert!(source.contains("with_system_restore_privilege_mapped"));
        assert!(source.contains("InstallerRootProfile::SystemService"));
        assert!(source.contains("write_or_validate_prepared_marker(authorization, ownership_key)"));
        assert!(source.contains("self.stage_with_expected_inventory(manifest, &[]),"));
    }

    #[test]
    fn package_stage_win32_error_retains_operation_and_raw_status() -> TestResult {
        let error = PackageStagingError::Win32 {
            stage: PackageStagingStage::FlushFileBuffers,
            code: 5,
        };
        assert_eq!(
            error.to_string(),
            "FlushFileBuffers failed with Win32 status 0x00000005"
        );
        let json = serde_json::to_string(&error)?;
        assert!(json.contains("FLUSH_FILE_BUFFERS"));
        assert!(json.contains("\"code\":5"));
        Ok(())
    }

    #[test]
    fn protected_path_errors_retain_bounded_semantics_at_package_boundary() {
        assert_eq!(
            map_protected_path_error(ProtectedPathError::Io),
            PackageStagingError::Io
        );
        assert_eq!(
            map_protected_path_error(ProtectedPathError::SizeExceeded),
            PackageStagingError::BoundExceeded
        );
        assert_eq!(
            map_protected_path_error(ProtectedPathError::IdentityMismatch),
            PackageStagingError::IdentityMismatch
        );
        for (protected, package) in [
            (
                ProtectedPathStage::KnownFolderPath,
                PackageStagingStage::KnownFolderPath,
            ),
            (
                ProtectedPathStage::CanonicalizePath,
                PackageStagingStage::CanonicalizePath,
            ),
            (
                ProtectedPathStage::SymlinkMetadata,
                PackageStagingStage::SymlinkMetadata,
            ),
            (
                ProtectedPathStage::CreateFileW,
                PackageStagingStage::CreateFileW,
            ),
            (
                ProtectedPathStage::FileMetadata,
                PackageStagingStage::FileMetadata,
            ),
            (
                ProtectedPathStage::GetFileInformationByHandle,
                PackageStagingStage::GetFileInformationByHandle,
            ),
            (
                ProtectedPathStage::GetFinalPathNameByHandleW,
                PackageStagingStage::GetFinalPathNameByHandleW,
            ),
        ] {
            assert_eq!(
                map_protected_path_error(ProtectedPathError::Win32 {
                    stage: protected,
                    code: 8,
                }),
                PackageStagingError::Win32 {
                    stage: package,
                    code: 8,
                }
            );
        }
    }

    #[test]
    fn malformed_authenticode_provider_buffers_fail_closed_before_der_slice() -> TestResult {
        let dangling = std::ptr::NonNull::<u8>::dangling().as_ptr();
        assert!(!provider_chain_is_bounded(0, dangling));
        assert!(!provider_chain_is_bounded(1, std::ptr::null::<u8>()));
        assert!(provider_chain_is_bounded(1, dangling));
        assert_eq!(
            provider_countersigner_state(0, std::ptr::null::<u8>()),
            ProviderCounterSignerState::Absent
        );
        assert_eq!(
            provider_countersigner_state(0, dangling),
            ProviderCounterSignerState::Absent
        );
        assert_eq!(
            provider_countersigner_state(1, std::ptr::null::<u8>()),
            ProviderCounterSignerState::Malformed
        );
        assert_eq!(
            provider_countersigner_state(MAX_AUTHENTICODE_PROVIDER_CHAIN_ELEMENTS + 1, dangling,),
            ProviderCounterSignerState::Malformed
        );
        assert_eq!(
            provider_countersigner_state(1, dangling),
            ProviderCounterSignerState::Present
        );
        assert_eq!(provider_der_length(std::ptr::null(), 1), None);
        assert_eq!(provider_der_length(dangling, 0), None);
        assert_eq!(
            provider_der_length(
                dangling,
                u32::try_from(MAX_AUTHENTICODE_CERT_DER_BYTES + 1)?,
            ),
            None
        );
        assert_eq!(provider_der_length(dangling, 1), Some(1));
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn authenticode_observation_rejects_mutation_and_substitution() {
        let path = PathBuf::from(r"C:\Eliot\generation\app.exe");
        let baseline = AuthenticodeFileObservation {
            path: path.clone(),
            identity: FileIdentity {
                volume_serial_number: 1,
                file_index: 2,
            },
            size: 6,
            sha256: hex_digest(b"before"),
        };
        let mut mutation = baseline.clone();
        mutation.sha256 = hex_digest(b"after!");
        assert_eq!(
            compare_authenticode_observations(&path, &baseline, &mutation),
            Err(AuthenticodeError::DigestMismatch)
        );
        let mut substitution = baseline.clone();
        substitution.identity.file_index = 3;
        assert_eq!(
            compare_authenticode_observations(&path, &baseline, &substitution),
            Err(AuthenticodeError::IdentityMismatch)
        );
    }

    #[cfg(windows)]
    #[test]
    fn authenticode_retained_handle_blocks_write_and_substitution() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-authenticode-contour-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let path = root.join("app.exe");
        let replacement = root.join("replacement.exe");
        std::fs::write(&path, b"before")?;
        let mut file = open_trusted_source_file(&path)?;
        let before = observe_authenticode_handle(&mut file)?;
        assert_eq!(before.sha256, hex_digest(b"before"));
        assert!(
            std::fs::write(&path, b"after!").is_err(),
            "retained Authenticode handle must block future writes"
        );
        assert!(
            std::fs::rename(&path, &replacement).is_err(),
            "retained Authenticode handle must block path substitution"
        );
        let after = observe_authenticode_handle(&mut file)?;
        assert_eq!(after.sha256, before.sha256);
        compare_authenticode_observations(&path, &before, &after)?;
        drop(file);
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[test]
    fn exact_tree_matching_rejects_extra_missing_and_kind_mismatch() -> TestResult {
        let manifest = PackageManifest::new(
            "generation",
            vec![file("bin/app.exe", true), file("readme.txt", false)],
        )?;
        let expected = expected_tree(&manifest)?;
        ensure_tree_matches_manifest(&expected, &manifest)?;

        let mut extra = expected.clone();
        extra.push(TreeEntry {
            relative: validate_relative_text("foreign.txt")?,
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
            .ok_or(std::io::Error::other("expected file entry"))?;
        entry.kind = TreeEntryKind::Directory;
        assert_eq!(
            ensure_tree_matches_manifest(&wrong_kind, &manifest),
            Err(PackageStagingError::TreeMismatch)
        );
        Ok(())
    }

    #[test]
    fn directory_receipt_is_bound_to_the_manifest_and_security_digest() -> TestResult {
        let manifest = PackageManifest::new("generation", vec![file("bin/app.bin", false)])?;
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
        validate_receipt_directories(&receipt, &manifest)?;

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
        Ok(())
    }

    #[test]
    fn parser_rejects_truncated_and_x86_and_accepts_minimal_amd64() -> TestResult {
        assert_eq!(parse_pe_coff(b"MZ"), Err(PeCoffError::Truncated));
        let mut x86 = minimal_pe(0x14c, 0x10b);
        assert_eq!(parse_pe_coff(&x86), Err(PeCoffError::WrongArchitecture));
        x86[0x3c] = 0xff;
        assert_eq!(parse_pe_coff(&x86), Err(PeCoffError::InvalidSignature));
        let amd64 = minimal_pe(0x8664, 0x20b);
        assert_eq!(parse_pe_coff(&amd64)?.machine, 0x8664);
        Ok(())
    }

    fn minimal_pe(machine: u16, magic: u16) -> Vec<u8> {
        let pe_offset = 0x80_usize;
        let optional_size = 0xf0_usize;
        let section_end = pe_offset + 4 + 20 + optional_size + 40;
        let mut bytes = vec![0_u8; section_end];
        bytes[..2].copy_from_slice(b"MZ");
        let Ok(pe_offset_u32) = u32::try_from(pe_offset) else {
            unreachable!("minimal PE offset must fit in u32");
        };
        bytes[0x3c..0x40].copy_from_slice(&pe_offset_u32.to_le_bytes());
        bytes[pe_offset..pe_offset + 4].copy_from_slice(b"PE\0\0");
        let coff = pe_offset + 4;
        bytes[coff..coff + 2].copy_from_slice(&machine.to_le_bytes());
        bytes[coff + 2..coff + 4].copy_from_slice(&1_u16.to_le_bytes());
        let Ok(optional_size_u16) = u16::try_from(optional_size) else {
            unreachable!("minimal PE optional header size must fit in u16");
        };
        bytes[coff + 16..coff + 18].copy_from_slice(&optional_size_u16.to_le_bytes());
        bytes[coff + 18..coff + 20].copy_from_slice(&2_u16.to_le_bytes());
        bytes[coff + 20..coff + 22].copy_from_slice(&magic.to_le_bytes());
        bytes
    }

    #[cfg(windows)]
    #[test]
    fn unsigned_authenticode_never_returns_valid_evidence() -> TestResult {
        let path = std::env::temp_dir().join(format!(
            "eliot-package-unsigned-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::write(&path, b"MZ unsigned fixture")?;
        let file = open_existing_file(&path)?;
        let identity = file_identity_from_open_handle(&file)?;
        let mut reader = file.try_clone()?;
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        let sha256 = hex_digest(&bytes);
        let result = WindowsAuthenticodeVerifier.verify(&path, identity, &sha256);
        let _ = std::fs::remove_file(path);
        if let Ok(evidence) = result {
            assert_ne!(evidence.verdict, AuthenticodeVerdict::Valid);
        }
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn junction_is_rejected_by_no_follow_directory_open_and_enumeration() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-reparse-{}",
            super::super::unique_suffix()
        ));
        let outside = std::env::temp_dir().join(format!(
            "eliot-package-reparse-outside-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        std::fs::create_dir(&outside)?;
        let junction = root.join("junction");
        let output = std::process::Command::new("cmd.exe")
            .args(["/D", "/C", "mklink", "/J"])
            .arg(&junction)
            .arg(&outside)
            .output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
            let privilege_specific = output.status.code() == Some(5)
                || stderr.contains("privilege")
                || stderr.contains("access is denied");
            if privilege_specific {
                assert!(
                    privilege_specific,
                    "junction source observation skipped: privilege-specific mklink failure: {}",
                    stderr.trim()
                );
                std::fs::remove_dir(&root)?;
                std::fs::remove_dir(&outside)?;
                return Ok(());
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
        let manifest = PackageManifest::new("generation", Vec::new())?;
        assert_eq!(
            enumerate_tree(&root, &manifest),
            Err(PackageStagingError::ReparsePoint)
        );
        let source = TrustedSourceBundle::open(&root)?;
        assert_eq!(source.observe(), Err(PackageStagingError::ReparsePoint));
        drop(source);
        std::fs::remove_dir(&junction)?;
        std::fs::remove_dir(&root)?;
        std::fs::remove_dir(&outside)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn hardlink_is_rejected_by_single_link_identity_guard() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-hardlink-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let original = root.join("original.bin");
        let link = root.join("link.bin");
        std::fs::write(&original, b"hardlink fixture")?;
        std::fs::hard_link(&original, &link)?;
        assert!(matches!(
            open_existing_file(&original),
            Err(PackageStagingError::IdentityMismatch)
        ));
        assert!(matches!(
            open_existing_file(&link),
            Err(PackageStagingError::IdentityMismatch)
        ));
        let source = TrustedSourceBundle::open(&root)?;
        assert_eq!(source.observe(), Err(PackageStagingError::IdentityMismatch));
        drop(source);
        std::fs::remove_file(&link)?;
        std::fs::remove_file(&original)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observation_is_bounded_sorted_and_read_only() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-source-observe-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        std::fs::create_dir(root.join("bin"))?;
        std::fs::write(root.join("bin/z.txt"), b"z")?;
        std::fs::write(root.join("a.txt"), b"a")?;
        let source = TrustedSourceBundle::open(&root)?;
        let moved = root.with_file_name(format!(
            "eliot-package-source-observe-moved-{}",
            super::super::unique_suffix()
        ));
        assert!(
            std::fs::rename(&root, &moved).is_err(),
            "retained ancestor contour must block substitution"
        );
        let observed = source.observe()?;
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
        std::fs::remove_file(root.join("bin/z.txt"))?;
        std::fs::remove_dir(root.join("bin"))?;
        std::fs::remove_file(root.join("a.txt"))?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_file_lease_retains_hash_and_blocks_mutation() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-source-file-lease-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let path = root.join("generation.json");
        let bytes = br#"{"generation":1}"#;
        std::fs::write(&path, bytes)?;

        let source = TrustedSourceBundle::open(&root)?;
        let lease = source.retain_file("generation.json")?;
        assert_eq!(lease.relative_path(), "generation.json");
        assert_eq!(lease.size(), bytes.len() as u64);
        assert_eq!(lease.sha256(), hex_digest(bytes));
        assert_eq!(lease.read_bounded(4096)?, bytes);
        assert!(
            std::fs::write(&path, b"tampered").is_err(),
            "retained source file must deny a competing writer"
        );
        let moved = root.with_file_name(format!(
            "eliot-package-source-file-lease-moved-{}",
            super::super::unique_suffix()
        ));
        assert!(
            std::fs::rename(&root, &moved).is_err(),
            "retained source contour must deny rename"
        );
        assert_eq!(lease.read(4096)?, bytes);
        drop(lease);
        drop(source);
        std::fs::remove_file(path)?;
        std::fs::remove_dir(root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observation_rejects_empty_child_directories() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-source-empty-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        std::fs::create_dir(root.join("empty"))?;
        let source = TrustedSourceBundle::open(&root)?;
        assert_eq!(source.observe(), Err(PackageStagingError::TreeMismatch));
        drop(source);
        std::fs::remove_dir(root.join("empty"))?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observation_rejects_file_and_depth_bounds() -> TestResult {
        let file_root = std::env::temp_dir().join(format!(
            "eliot-package-source-file-bound-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&file_root)?;
        for index in 0..=MAX_PACKAGE_FILES {
            std::fs::write(file_root.join(format!("file-{index}.bin")), [])?;
        }
        let source = TrustedSourceBundle::open(&file_root)?;
        assert_eq!(source.observe(), Err(PackageStagingError::BoundExceeded));
        drop(source);
        for index in 0..=MAX_PACKAGE_FILES {
            std::fs::remove_file(file_root.join(format!("file-{index}.bin")))?;
        }
        std::fs::remove_dir(&file_root)?;

        let depth_root = std::env::temp_dir().join(format!(
            "eliot-package-source-depth-bound-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&depth_root)?;
        let mut deep = depth_root.clone();
        for index in 0..=MAX_PACKAGE_PATH_DEPTH {
            deep.push(format!("d{index}"));
        }
        std::fs::create_dir_all(&deep)?;
        std::fs::write(deep.join("file.bin"), b"deep")?;
        let source = TrustedSourceBundle::open(&depth_root)?;
        assert_eq!(source.observe(), Err(PackageStagingError::BoundExceeded));
        drop(source);
        std::fs::remove_dir_all(&depth_root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observation_post_read_identity_seam_rejects_replacement() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-source-toctou-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let path = root.join("mutable.bin");
        std::fs::write(&path, b"before")?;
        let file = open_trusted_source_file(&path)?;
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
            assert!(std::fs::write(&path, b"replacement-with-a-different-size").is_err());
        }
        drop(file);
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_same_size_overwrite_is_blocked_or_detected() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-source-same-size-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let path = root.join("same.bin");
        std::fs::write(&path, b"AAAAAA")?;
        let before_hash = hex_digest(b"AAAAAA");
        let file = open_trusted_source_file(&path)?;
        let mut hook_write_succeeded = false;
        let result = observe_source_handle_with_post_read_hook(&file, &path, 64, || {
            if std::fs::write(&path, b"BBBBBB").is_ok() {
                hook_write_succeeded = true;
            }
        });
        if hook_write_succeeded {
            assert!(result.is_err(), "same-size mutation must be detected");
        } else {
            let observed = result?;
            assert_eq!(observed.sha256, before_hash);
            assert_eq!(observed.size, 6);
        }
        drop(file);
        assert_eq!(std::fs::read(&path)?, b"AAAAAA");
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn trusted_source_observer_fails_closed_when_writer_holds_file() -> TestResult {
        use std::os::windows::fs::OpenOptionsExt as _;
        let root = std::env::temp_dir().join(format!(
            "eliot-package-writer-hold-{}-{}",
            std::process::id(),
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let path = root.join("held.bin");
        std::fs::write(&path, b"held")?;
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
            })?;
        let trusted_open = open_trusted_source_file(&path);
        assert!(
            trusted_open.is_err(),
            "observer must fail closed when writer holds file"
        );
        assert!(matches!(
            trusted_open,
            Err(PackageStagingError::Io
                | PackageStagingError::RootUnavailable
                | PackageStagingError::Win32 { .. })
        ));
        let source = TrustedSourceBundle::open(&root)?;
        let observed = source.observe();
        assert!(
            observed.is_err(),
            "observe must fail closed when file is write-locked"
        );
        drop(writer);
        drop(source);
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn staging_copies_from_retained_handle_not_reopened_path() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-retained-copy-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let source_path = root.join("source.bin");
        let dest_path = root.join("dest.bin");
        std::fs::write(&source_path, b"retained")?;
        let snapshot = snapshot_source_file(&source_path, 8)?;
        let original_hash = snapshot.sha256.clone();
        let original_size = snapshot.size;
        let original_identity = snapshot.identity;
        let writer_attempt = std::fs::OpenOptions::new().write(true).open(&source_path);
        assert!(
            writer_attempt.is_err(),
            "exclusive snapshot handle must block writer"
        );
        let mut dest = std::fs::File::create(&dest_path)?;
        let copied_hash = copy_source_to_destination(&snapshot, &mut dest, 8)?;
        assert_eq!(copied_hash, original_hash);
        drop(dest);
        assert_eq!(std::fs::read(&dest_path)?, b"retained");
        drop(snapshot);
        std::fs::write(&source_path, b"mutated")?;
        assert_eq!(std::fs::read(&source_path)?, b"mutated");
        assert_ne!(original_hash, hex_digest(b"mutated"));
        assert_eq!(original_size, 8);
        let _ = original_identity;
        std::fs::remove_file(&source_path)?;
        std::fs::remove_file(&dest_path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn source_snapshot_copy_reports_hash_and_size_changes() -> TestResult {
        use std::io::Write as _;

        let root = std::env::temp_dir().join(format!(
            "eliot-package-copy-fault-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let source_path = root.join("source.bin");
        let destination_path = root.join("destination.bin");
        std::fs::write(&source_path, b"before")?;
        let snapshot = snapshot_source_file(&source_path, 6)?;
        let writer_blocked = std::fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .is_err();
        if writer_blocked {
            let mut destination = std::fs::File::create(&destination_path)?;
            let copied = copy_source_to_destination(&snapshot, &mut destination, 6)?;
            assert_eq!(copied, snapshot.sha256);
            drop(destination);
        } else {
            let mut changed = std::fs::OpenOptions::new().write(true).open(&source_path)?;
            changed.write_all(b"after!")?;
            drop(changed);
            let mut destination = std::fs::File::create(&destination_path)?;
            let copied = copy_source_to_destination(&snapshot, &mut destination, 6)?;
            assert_ne!(
                copied, snapshot.sha256,
                "changed source must fail hash proof"
            );
            drop(destination);
        }
        drop(snapshot);

        std::fs::write(&source_path, b"before")?;
        let snapshot = snapshot_source_file(&source_path, 6)?;
        let writer_blocked = std::fs::OpenOptions::new()
            .append(true)
            .open(&source_path)
            .is_err();
        if writer_blocked {
            let mut destination = std::fs::File::create(&destination_path)?;
            let copied = copy_source_to_destination(&snapshot, &mut destination, 6)?;
            assert_eq!(copied, snapshot.sha256);
            drop(destination);
        } else {
            let mut appended = std::fs::OpenOptions::new()
                .append(true)
                .open(&source_path)?;
            appended.write_all(b"-size")?;
            drop(appended);
            let mut destination = std::fs::File::create(&destination_path)?;
            assert_eq!(
                copy_source_to_destination(&snapshot, &mut destination, 6),
                Err(PackageStagingError::SizeMismatch)
            );
            drop(destination);
        }
        drop(snapshot);
        std::fs::remove_file(&source_path)?;
        std::fs::remove_file(&destination_path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn destination_readback_rejects_identity_and_security_mismatch() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-readback-fault-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let path = root.join("destination.bin");
        std::fs::write(&path, b"readback")?;
        let file = open_existing_file(&path)?;
        let identity = file_identity_from_open_handle(&file)?;
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
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn create_new_collision_codes_are_typed_as_generation_exists() {
        use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS};

        assert!(is_create_new_collision(ERROR_FILE_EXISTS));
        assert!(is_create_new_collision(ERROR_ALREADY_EXISTS));
        assert!(!is_create_new_collision(0));
    }

    #[cfg(windows)]
    #[test]
    fn create_new_file_collision_never_overwrites_existing_bytes() -> TestResult {
        use std::io::Write as _;

        let root = std::env::temp_dir().join(format!(
            "eliot-package-create-new-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let path = root.join("immutable.bin");
        let (mut first, _) = match create_destination_file(&path) {
            Ok(file) => file,
            Err(error) if security_fixture_unavailable(&error) => {
                // The fixture needs a token able to apply the production
                // SystemService ACL; the test remains useful on developer
                // machines where that policy is unavailable.
                std::fs::remove_dir(&root)?;
                return Ok(());
            }
            Err(error) => panic!("create-new fixture failed: {error}"),
        };
        first.write_all(b"sentinel")?;
        flush_file_buffers(&first)?;
        drop(first);
        assert!(matches!(
            create_destination_file(&path),
            Err(PackageStagingError::GenerationExists)
        ));
        assert_eq!(std::fs::read(&path)?, b"sentinel");
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn create_new_generation_root_collision_is_never_adopted() -> TestResult {
        let parent = std::env::temp_dir().join(format!(
            "eliot-package-generation-parent-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&parent)?;
        let generation = parent.join("generation");
        let first = match create_generation_root(&generation) {
            Ok(root) => root,
            Err(error) if security_fixture_unavailable(&error) => {
                // The fixture needs a token able to apply the production
                // SystemService ACL; the test remains useful on developer
                // machines where that policy is unavailable.
                std::fs::remove_dir(&parent)?;
                return Ok(());
            }
            Err(error) => panic!("generation create fixture failed: {error}"),
        };
        drop(first);
        assert!(matches!(
            create_generation_root(&generation),
            Err(PackageStagingError::GenerationExists)
        ));
        std::fs::remove_dir(&generation)?;
        std::fs::remove_dir(&parent)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn exact_root_delete_uses_a_delete_capable_no_follow_handle() -> TestResult {
        let parent = std::env::temp_dir().join(format!(
            "eliot-package-generation-delete-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&parent)?;
        let generation = parent.join("generation");
        let root = match create_generation_root(&generation) {
            Ok(root) => root,
            Err(error) if security_fixture_unavailable(&error) => {
                std::fs::remove_dir(&parent)?;
                return Ok(());
            }
            Err(error) => panic!("generation delete fixture failed: {error}"),
        };
        let identity = file_identity_from_open_handle(&root)?;
        drop(root);
        let root = open_existing_directory_for_delete(&generation)?;
        delete_open_handle(root, identity)?;
        assert!(!generation.exists());
        std::fs::remove_dir(&parent)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn nested_directory_creation_is_create_only_and_reverse_owned_delete() -> TestResult {
        let parent = std::env::temp_dir().join(format!(
            "eliot-package-nested-directory-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&parent)?;
        let first_path = parent.join("bin");
        let second_path = first_path.join("x64");
        let (first, first_identity, _) = match create_destination_directory(&first_path) {
            Ok(directory) => directory,
            Err(error) if security_fixture_unavailable(&error) => {
                std::fs::remove_dir(&parent)?;
                return Ok(());
            }
            Err(error) => panic!("nested directory fixture failed: {error}"),
        };
        let (second, second_identity, _) = match create_destination_directory(&second_path) {
            Ok(directory) => directory,
            Err(error) if security_fixture_unavailable(&error) => {
                delete_open_handle(first, first_identity)?;
                std::fs::remove_dir(&parent)?;
                return Ok(());
            }
            Err(error) => panic!("nested child directory fixture failed: {error}"),
        };
        assert!(second_path.is_dir());
        let substituted = parent.join("bin-substituted");
        assert!(
            std::fs::rename(&first_path, &substituted).is_err(),
            "retained native child handle must block StagePackage child substitution"
        );
        delete_open_handle(second, second_identity)?;
        delete_open_handle(first, first_identity)?;
        assert!(!first_path.exists());
        std::fs::remove_dir(&parent)?;
        Ok(())
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

    #[test]
    fn package_open_errors_preserve_raw_win32_status_and_not_found_classification() {
        assert_eq!(
            map_package_open_error(std::io::Error::from_raw_os_error(5)),
            PackageStagingError::Win32 {
                stage: PackageStagingStage::CreateFileW,
                code: 5,
            }
        );
        assert_eq!(
            map_package_open_error(std::io::Error::from(std::io::ErrorKind::NotFound)),
            PackageStagingError::RootUnavailable
        );
    }

    #[test]
    fn package_handle_io_errors_preserve_operation_and_not_found_classification() {
        for (stage, expected) in [
            (
                PackageStagingStage::GetFileInformationByHandle,
                PackageStagingStage::GetFileInformationByHandle,
            ),
            (
                PackageStagingStage::DuplicateHandle,
                PackageStagingStage::DuplicateHandle,
            ),
            (
                PackageStagingStage::SetFilePointerEx,
                PackageStagingStage::SetFilePointerEx,
            ),
            (PackageStagingStage::ReadFile, PackageStagingStage::ReadFile),
            (
                PackageStagingStage::WriteFile,
                PackageStagingStage::WriteFile,
            ),
        ] {
            assert_eq!(
                map_package_io_error(std::io::Error::from_raw_os_error(5), stage),
                PackageStagingError::Win32 {
                    stage: expected,
                    code: 5
                }
            );
            assert_eq!(
                map_package_io_error(std::io::Error::from(std::io::ErrorKind::NotFound), stage),
                PackageStagingError::RootUnavailable
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn rollback_delete_refuses_foreign_identity_and_keeps_file() -> TestResult {
        let root = std::env::temp_dir().join(format!(
            "eliot-package-rollback-fault-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&root)?;
        let path = root.join("owned.bin");
        std::fs::write(&path, b"owned")?;
        let handle = open_existing_file_for_delete(&path)?;
        let identity = file_identity_from_open_handle(&handle)?;
        let foreign = FileIdentity {
            file_index: identity.file_index.saturating_add(1),
            ..identity
        };
        assert_eq!(
            delete_open_handle(handle, foreign),
            Err(PackageStagingError::IdentityMismatch)
        );
        assert!(path.exists(), "foreign receipt must not delete the file");
        std::fs::remove_file(&path)?;
        std::fs::remove_dir(&root)?;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn exact_rollback_refuses_foreign_content_before_root_delete() -> TestResult {
        use std::io::Write as _;

        let parent = std::env::temp_dir().join(format!(
            "eliot-package-rollback-foreign-{}",
            super::super::unique_suffix()
        ));
        std::fs::create_dir(&parent)?;
        let generation = parent.join("generation");
        let root_file = match create_generation_root(&generation) {
            Ok(root) => root,
            Err(error) if security_fixture_unavailable(&error) => {
                std::fs::remove_dir(&parent)?;
                return Ok(());
            }
            Err(error) => panic!("rollback fixture failed: {error}"),
        };
        let root_identity = file_identity_from_open_handle(&root_file)?;
        let owned_path = generation.join("owned.bin");
        let (mut owned_file, owned_identity) = match create_destination_file(&owned_path) {
            Ok(file) => file,
            Err(error) if security_fixture_unavailable(&error) => {
                delete_open_handle(root_file, root_identity)?;
                std::fs::remove_dir(&parent)?;
                return Ok(());
            }
            Err(error) => panic!("rollback child file fixture failed: {error}"),
        };
        owned_file.write_all(b"owned")?;
        flush_file_buffers(&owned_file)?;
        let foreign_path = generation.join("foreign.bin");
        std::fs::write(&foreign_path, b"foreign")?;
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
        let foreign = open_existing_file_for_delete(&foreign_path)?;
        let foreign_identity = file_identity_from_open_handle(&foreign)?;
        delete_open_handle(foreign, foreign_identity)?;
        std::fs::remove_dir(&generation)?;
        std::fs::remove_dir(&parent)?;
        Ok(())
    }
}
