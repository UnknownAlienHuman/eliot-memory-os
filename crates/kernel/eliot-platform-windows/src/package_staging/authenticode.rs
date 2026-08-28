//! Authenticode and PE/COFF bound measurement.
//!
//! Architecture (source-backed): A12.3, A12.4, A13.8, ARCH-AUTH-01,
//! ARCH-SEC-02, ARCH-RES-03.
//! Implementation (source-backed): I15.5, I15.9, I15.19, I2.2, I2.23.
//! Ownership: this child owns only bounded PE/COFF measurement and physical
//! signature evidence exposed by the Authenticode/WinTrust provider. It does
//! not own semantic acceptance, canonical authority, installation policy, path
//! ownership, publication, receipts, durable state, activation, or rollback.

use std::fmt;
#[cfg(windows)]
use std::io::{Read, Seek};
use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
#[cfg(windows)]
use sha2::{Digest, Sha256};

#[cfg(windows)]
use super::COPY_BUFFER_BYTES;
#[cfg(windows)]
use super::{encode_digest_hex, hex_digest};
use crate::FileIdentity;
#[cfg(windows)]
use crate::{
    file_identity_from_handle, final_windows_path_from_handle, valid_sha256_hex,
    windows_paths_equal,
};

/// Maximum PE header prefix inspected by the pure parser.
pub const MAX_PE_HEADER_BYTES: usize = 1024 * 1024;
pub(super) const MAX_AUTHENTICODE_CERT_DER_BYTES: usize = 16 * 1024 * 1024;
pub(super) const MAX_AUTHENTICODE_PROVIDER_CHAIN_ELEMENTS: u32 = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProviderCounterSignerState {
    Absent,
    Present,
    Malformed,
}

pub(super) fn provider_chain_is_bounded<T>(count: u32, chain: *const T) -> bool {
    count != 0 && count <= MAX_AUTHENTICODE_PROVIDER_CHAIN_ELEMENTS && !chain.is_null()
}

pub(super) fn provider_countersigner_state<T>(
    count: u32,
    chain: *const T,
) -> ProviderCounterSignerState {
    if count == 0 {
        ProviderCounterSignerState::Absent
    } else if count > MAX_AUTHENTICODE_PROVIDER_CHAIN_ELEMENTS || chain.is_null() {
        ProviderCounterSignerState::Malformed
    } else {
        ProviderCounterSignerState::Present
    }
}

pub(super) fn provider_der_length(pointer: *const u8, length: u32) -> Option<usize> {
    let length = usize::try_from(length).ok()?;
    (length != 0 && length <= MAX_AUTHENTICODE_CERT_DER_BYTES && !pointer.is_null())
        .then_some(length)
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

/// Pure parser failures. No Windows loader or shell is involved.
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
/// The parser does not map, load or execute the image. It only reads bounded
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
    /// offline-only revocation check). This is deliberately not equivalent
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

    if !path.is_absolute() || !valid_sha256_hex(expected_sha256) {
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
pub(super) struct AuthenticodeFileObservation {
    pub(super) path: PathBuf,
    pub(super) identity: FileIdentity,
    pub(super) size: u64,
    pub(super) sha256: String,
}

#[cfg(windows)]
pub(super) fn observe_authenticode_handle(
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
    let path = final_windows_path_from_handle(file).map_err(|_| AuthenticodeError::InvalidFile)?;
    let identity = file_identity_from_handle(file).map_err(|_| AuthenticodeError::InvalidFile)?;
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
pub(super) fn compare_authenticode_observations(
    expected_path: &Path,
    before: &AuthenticodeFileObservation,
    after: &AuthenticodeFileObservation,
) -> Result<(), AuthenticodeError> {
    if !windows_paths_equal(&before.path, expected_path)
        || !windows_paths_equal(&after.path, expected_path)
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
pub(super) fn verify_authenticode_handle(
    path: &Path,
    file: &mut std::fs::File,
    expected_identity: FileIdentity,
    expected_sha256: &str,
) -> Result<AuthenticodeEvidence, AuthenticodeError> {
    if !path.is_absolute() || !valid_sha256_hex(expected_sha256) {
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
pub(super) fn verify_authenticode_handle(
    _path: &Path,
    _file: &mut std::fs::File,
    _expected_identity: FileIdentity,
    _expected_sha256: &str,
) -> Result<AuthenticodeEvidence, AuthenticodeError> {
    Err(AuthenticodeError::UnsupportedPlatform)
}

#[cfg(windows)]
pub(super) fn hash_file(file: &mut std::fs::File) -> Result<String, AuthenticodeError> {
    file.seek(std::io::SeekFrom::Start(0))
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
/// evidence. The raw status remains in [`AuthenticodeEvidence`] so callers
/// can retain the exact provider reason without treating an unknown value as
/// success.
pub(super) fn classify_wintrust_status(status: u32) -> AuthenticodeVerdict {
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
            // A non-zero countersigner count is a mandatory evidence claim. Any
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
