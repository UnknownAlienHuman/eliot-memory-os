//! Windows DPAPI-NG provider for Kernel supervision signing keys.

use std::path::{Component, Path, PathBuf};

use eliot_contracts::{ResourceGeneration, sha256_hex};
use eliot_runtime_contracts::{
    Ed25519SupervisionLeaseSigner, ProvisionedSupervisionAuthority,
    SUPERVISION_AUTHORITY_HOST_SERVICE, SupervisionLeaseError, SupervisionSealedKeyFileIdentity,
    SupervisionSealedKeyReference, SupervisionTrustAnchor,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    CredentialSecret, InstallerRootError, InstallerRootObjectSnapshot, InstallerRootPrimitiveSpec,
    WindowsAdapterError, WindowsInstallerRootPrimitive, fill_system_random, resolve_service_sid,
    valid_service_sid_text,
};

const SEALED_KEY_ENVELOPE_WIRE: &str = "eliot.supervision-authority-key.v1";
const SEALED_KEY_FILE_LIMIT: u64 = 16 * 1024;

/// Exact provider failure without secret-bearing diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisionAuthorityKeyError {
    InvalidBinding,
    RandomUnavailable,
    ProviderUnavailable,
    AccessDenied,
    KeyInvalid,
}

impl std::fmt::Display for SupervisionAuthorityKeyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "supervision authority key provider failed: {self:?}"
        )
    }
}

impl std::error::Error for SupervisionAuthorityKeyError {}

/// Ciphertext and independently derived public anchor returned to the
/// installer. The plaintext seed is zeroized before this value is returned.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedSupervisionAuthorityKey {
    pub sealed_blob: Vec<u8>,
    pub trust_anchor: SupervisionTrustAnchor,
}

/// Stateless DPAPI-NG service-SID key provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsSupervisionAuthorityKeyProvider;

impl WindowsSupervisionAuthorityKeyProvider {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Generates one Ed25519 seed and seals it to the exact SID string.
    ///
    /// No account alias is accepted. The descriptor passed to DPAPI-NG is
    /// exactly `SID=S-1-5-80-...`.
    pub fn generate_and_seal(
        &self,
        service_sid: &str,
        installation_id: &str,
        signer_id: &str,
        key_id: &str,
    ) -> Result<SealedSupervisionAuthorityKey, SupervisionAuthorityKeyError> {
        if !valid_service_sid_text(service_sid)
            || [installation_id, signer_id, key_id]
                .iter()
                .any(|value| value.is_empty() || *value != value.trim())
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let mut seed = [0_u8; 32];
        fill_system_random(&mut seed)
            .map_err(|_| SupervisionAuthorityKeyError::RandomUnavailable)?;
        if seed.iter().all(|byte| *byte == 0) {
            return Err(SupervisionAuthorityKeyError::RandomUnavailable);
        }
        let signer = Ed25519SupervisionLeaseSigner::from_secret_key(signer_id, key_id, seed)
            .map_err(map_contract_error)?;
        let anchor = SupervisionTrustAnchor::new(
            installation_id,
            signer_id,
            key_id,
            signer.public_key().to_vec(),
        )
        .map_err(map_contract_error)?;
        let sealed = protect_for_service_sid(service_sid, &seed);
        seed.fill(0);
        let sealed_blob = sealed?;
        Ok(SealedSupervisionAuthorityKey {
            sealed_blob,
            trust_anchor: anchor,
        })
    }

    /// Unseals one seed only when the embedded descriptor is the exact
    /// installer-pinned service SID. DPAPI token admission alone is not used
    /// as the serialized provider-identity check.
    pub fn unseal(
        &self,
        expected_service_sid: &str,
        sealed_blob: &[u8],
    ) -> Result<CredentialSecret, SupervisionAuthorityKeyError> {
        if !valid_service_sid_text(expected_service_sid) || sealed_blob.is_empty() {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        unprotect_for_service_sid(expected_service_sid, sealed_blob)
    }
}

/// Immutable request used by the installer effect and its recovery path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SupervisionAuthorityKeyStoreRequest {
    pub transaction_id: String,
    pub effect_id: String,
    pub installation_plan_digest: String,
    pub installation_id: String,
    pub candidate_generation: String,
    pub authority_generation: ResourceGeneration,
    pub supervision_lease_scope_id: String,
    pub signer_id: String,
    pub key_id: String,
    pub kernel_root: PathBuf,
    pub relative_path: String,
    pub expected_host_service_sid: String,
}

impl SupervisionAuthorityKeyStoreRequest {
    fn validate(&self) -> Result<(), SupervisionAuthorityKeyError> {
        if [
            self.transaction_id.as_str(),
            self.effect_id.as_str(),
            self.installation_id.as_str(),
            self.candidate_generation.as_str(),
            self.supervision_lease_scope_id.as_str(),
            self.signer_id.as_str(),
            self.key_id.as_str(),
        ]
        .iter()
        .any(|value| value.is_empty() || *value != value.trim())
            || !valid_digest(&self.installation_plan_digest)
            || !self.kernel_root.is_absolute()
            || !valid_service_sid_text(&self.expected_host_service_sid)
            || !single_relative_component(&self.relative_path)
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(())
    }

    fn path(&self) -> PathBuf {
        self.kernel_root.join(&self.relative_path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedKeyEnvelope {
    wire: String,
    transaction_id: String,
    effect_id: String,
    installation_plan_digest: String,
    authority: ProvisionedSupervisionAuthority,
    sealed_blob: Vec<u8>,
    ownership_mac: String,
}

impl SealedKeyEnvelope {
    fn mac_payload(&self) -> Result<Vec<u8>, SupervisionAuthorityKeyError> {
        serde_json::to_vec(&(
            self.wire.as_str(),
            self.transaction_id.as_str(),
            self.effect_id.as_str(),
            self.installation_plan_digest.as_str(),
            &self.authority,
            &self.sealed_blob,
        ))
        .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)
    }

    fn validate(
        &self,
        request: &SupervisionAuthorityKeyStoreRequest,
        object: &InstallerRootObjectSnapshot,
        ownership_key: &[u8],
    ) -> Result<(), SupervisionAuthorityKeyError> {
        request.validate()?;
        self.authority.validate().map_err(map_contract_error)?;
        if self.wire != SEALED_KEY_ENVELOPE_WIRE
            || self.transaction_id != request.transaction_id
            || self.effect_id != request.effect_id
            || self.installation_plan_digest != request.installation_plan_digest
            || self.authority.supervision_lease_scope_id != request.supervision_lease_scope_id
            || self.authority.candidate_generation != request.candidate_generation
            || self.authority.authority_generation != request.authority_generation
            || self.authority.trust_anchor.installation_id != request.installation_id
            || self.authority.trust_anchor.signer_id != request.signer_id
            || self.authority.trust_anchor.key_id != request.key_id
            || self.authority.key_reference.relative_path != request.relative_path
            || self.authority.key_reference.host_service_sid != request.expected_host_service_sid
            || self.authority.key_reference.file_identity != file_identity(object)
            || self.authority.key_reference.sealed_blob_sha256 != sha256_hex(&self.sealed_blob)
            || !constant_time_eq(
                self.ownership_mac.as_bytes(),
                hmac_sha256_hex(ownership_key, &self.mac_payload()?).as_bytes(),
            )
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(())
    }
}

/// Atomic ciphertext store used only by the sealed installer effect.
#[derive(Debug, Default)]
pub struct WindowsSupervisionAuthorityKeyStore {
    primitive: WindowsInstallerRootPrimitive,
    provider: WindowsSupervisionAuthorityKeyProvider,
}

impl WindowsSupervisionAuthorityKeyStore {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            primitive: WindowsInstallerRootPrimitive::new(),
            provider: WindowsSupervisionAuthorityKeyProvider::new(),
        }
    }

    /// Creates a new ciphertext file or reconciles only an HMAC-proven prior
    /// create from the same durable transaction intent.
    pub fn create_or_reconcile(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        request: &SupervisionAuthorityKeyStoreRequest,
        ownership_key: &[u8],
    ) -> Result<ProvisionedSupervisionAuthority, SupervisionAuthorityKeyError> {
        request.validate()?;
        if ownership_key.len() < 32 || ownership_key.iter().all(|byte| *byte == 0) {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let live_host_sid = resolve_service_sid(SUPERVISION_AUTHORITY_HOST_SERVICE)?;
        if live_host_sid != request.expected_host_service_sid {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let path = request.path();
        match std::fs::symlink_metadata(&path) {
            Ok(_) => return self.inspect(spec, request, ownership_key),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(SupervisionAuthorityKeyError::ProviderUnavailable),
        }
        let sealed = self.provider.generate_and_seal(
            &live_host_sid,
            &request.installation_id,
            &request.signer_id,
            &request.key_id,
        )?;
        let sealed_blob_digest = sha256_hex(&sealed.sealed_blob);
        let mut result = None;
        let create = self.primitive.create_protected_file(spec, &path, |object| {
            let reference = SupervisionSealedKeyReference::new(
                request.relative_path.clone(),
                live_host_sid.clone(),
                file_identity(object),
                sealed_blob_digest.clone(),
            )
            .map_err(|_| InstallerRootError::ReceiptMismatch)?;
            let authority = ProvisionedSupervisionAuthority::new(
                request.supervision_lease_scope_id.clone(),
                request.candidate_generation.clone(),
                request.authority_generation,
                reference,
                sealed.trust_anchor.clone(),
            )
            .map_err(|_| InstallerRootError::ReceiptMismatch)?;
            let mut envelope = SealedKeyEnvelope {
                wire: SEALED_KEY_ENVELOPE_WIRE.to_owned(),
                transaction_id: request.transaction_id.clone(),
                effect_id: request.effect_id.clone(),
                installation_plan_digest: request.installation_plan_digest.clone(),
                authority: authority.clone(),
                sealed_blob: sealed.sealed_blob.clone(),
                ownership_mac: String::new(),
            };
            envelope.ownership_mac = hmac_sha256_hex(
                ownership_key,
                &envelope
                    .mac_payload()
                    .map_err(|_| InstallerRootError::ReceiptMismatch)?,
            );
            let bytes =
                serde_json::to_vec(&envelope).map_err(|_| InstallerRootError::ReceiptMismatch)?;
            result = Some(authority);
            Ok(bytes)
        });
        match create {
            Ok(_) => result.ok_or(SupervisionAuthorityKeyError::ProviderUnavailable),
            Err(InstallerRootError::ReceiptMismatch) => self.inspect(spec, request, ownership_key),
            Err(error) => Err(map_store_error(error)),
        }
    }

    /// Reads and validates the exact provider/file/transaction identity.
    pub fn inspect(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        request: &SupervisionAuthorityKeyStoreRequest,
        ownership_key: &[u8],
    ) -> Result<ProvisionedSupervisionAuthority, SupervisionAuthorityKeyError> {
        request.validate()?;
        let readback = self
            .primitive
            .read_protected_file(spec, &request.path(), SEALED_KEY_FILE_LIMIT)
            .map_err(map_store_error)?;
        let envelope: SealedKeyEnvelope = serde_json::from_slice(&readback.bytes)
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        envelope.validate(request, &readback.object, ownership_key)?;
        Ok(envelope.authority)
    }

    /// Reads the exact HMAC receipt and deletes only that retained file.
    pub fn delete(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        request: &SupervisionAuthorityKeyStoreRequest,
        ownership_key: &[u8],
    ) -> Result<(), SupervisionAuthorityKeyError> {
        let readback = self
            .primitive
            .read_protected_file(spec, &request.path(), SEALED_KEY_FILE_LIMIT)
            .map_err(map_store_error)?;
        let envelope: SealedKeyEnvelope = serde_json::from_slice(&readback.bytes)
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        envelope.validate(request, &readback.object, ownership_key)?;
        self.primitive
            .delete_file(&request.path(), &readback.object)
            .map_err(map_store_error)
    }

    /// Kernel-only ciphertext read and DPAPI-NG unseal after exact file and
    /// provider identity revalidation.
    pub fn unseal_for_kernel(
        &self,
        spec: &InstallerRootPrimitiveSpec,
        kernel_root: &Path,
        authority: &ProvisionedSupervisionAuthority,
    ) -> Result<CredentialSecret, SupervisionAuthorityKeyError> {
        authority.validate().map_err(map_contract_error)?;
        if !kernel_root.is_absolute()
            || !single_relative_component(&authority.key_reference.relative_path)
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let path = kernel_root.join(&authority.key_reference.relative_path);
        let readback = self
            .primitive
            .read_protected_file(spec, &path, SEALED_KEY_FILE_LIMIT)
            .map_err(map_store_error)?;
        let envelope: SealedKeyEnvelope = serde_json::from_slice(&readback.bytes)
            .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?;
        if envelope.authority != *authority
            || authority.key_reference.file_identity != file_identity(&readback.object)
            || authority.key_reference.sealed_blob_sha256 != sha256_hex(&envelope.sealed_blob)
            || resolve_service_sid(SUPERVISION_AUTHORITY_HOST_SERVICE)?
                != authority.key_reference.host_service_sid
        {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        let secret = self.provider.unseal(
            &authority.key_reference.host_service_sid,
            &envelope.sealed_blob,
        )?;
        let signer = Ed25519SupervisionLeaseSigner::from_secret_key(
            authority.trust_anchor.signer_id.clone(),
            authority.trust_anchor.key_id.clone(),
            secret
                .expose()
                .try_into()
                .map_err(|_| SupervisionAuthorityKeyError::KeyInvalid)?,
        )
        .map_err(map_contract_error)?;
        if sha256_hex(&signer.public_key()) != authority.trust_anchor.public_key_fingerprint {
            return Err(SupervisionAuthorityKeyError::InvalidBinding);
        }
        Ok(secret)
    }
}

fn file_identity(object: &InstallerRootObjectSnapshot) -> SupervisionSealedKeyFileIdentity {
    SupervisionSealedKeyFileIdentity {
        canonical_path_digest: object.canonical_path_digest.clone(),
        volume_serial_number: object.volume_serial_number,
        file_index: object.file_index,
        security_descriptor_digest: object.security_descriptor_digest.clone(),
    }
}

fn single_relative_component(value: &str) -> bool {
    let mut components = Path::new(value).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hmac_sha256_hex(key: &[u8], message: &[u8]) -> String {
    const BLOCK: usize = 64;
    let mut normalized = [0_u8; BLOCK];
    if key.len() > BLOCK {
        normalized[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        normalized[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36_u8; BLOCK];
    let mut outer_pad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        inner_pad[index] ^= normalized[index];
        outer_pad[index] ^= normalized[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner.finalize());
    format!("{:x}", outer.finalize())
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0
}

fn map_store_error(error: InstallerRootError) -> SupervisionAuthorityKeyError {
    match error {
        InstallerRootError::SecurityMismatch | InstallerRootError::IdentityMismatch => {
            SupervisionAuthorityKeyError::InvalidBinding
        }
        InstallerRootError::NotElevated => SupervisionAuthorityKeyError::AccessDenied,
        _ => SupervisionAuthorityKeyError::ProviderUnavailable,
    }
}

fn map_contract_error(_error: SupervisionLeaseError) -> SupervisionAuthorityKeyError {
    SupervisionAuthorityKeyError::KeyInvalid
}

fn provider_error() -> SupervisionAuthorityKeyError {
    match std::io::Error::last_os_error().raw_os_error() {
        Some(5) => SupervisionAuthorityKeyError::AccessDenied,
        _ => SupervisionAuthorityKeyError::ProviderUnavailable,
    }
}

fn protection_descriptor(service_sid: &str) -> Result<String, SupervisionAuthorityKeyError> {
    if !valid_service_sid_text(service_sid) {
        return Err(SupervisionAuthorityKeyError::InvalidBinding);
    }
    Ok(format!("SID={service_sid}"))
}

#[cfg(windows)]
fn protect_for_service_sid(
    service_sid: &str,
    secret: &[u8],
) -> Result<Vec<u8>, SupervisionAuthorityKeyError> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_SILENT_FLAG, NCryptCloseProtectionDescriptor, NCryptCreateProtectionDescriptor,
        NCryptProtectSecret,
    };
    let descriptor = protection_descriptor(service_sid)?
        .encode_utf16()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut handle = std::ptr::null_mut();
    let created =
        unsafe { NCryptCreateProtectionDescriptor(descriptor.as_ptr(), 0, &raw mut handle) };
    if created < 0 || handle.is_null() {
        return Err(provider_error());
    }
    let mut output = std::ptr::null_mut();
    let mut output_len = 0_u32;
    let status = unsafe {
        NCryptProtectSecret(
            handle,
            NCRYPT_SILENT_FLAG,
            secret.as_ptr(),
            u32::try_from(secret.len())
                .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?,
            std::ptr::null(),
            std::ptr::null_mut(),
            &raw mut output,
            &raw mut output_len,
        )
    };
    unsafe {
        NCryptCloseProtectionDescriptor(handle);
    }
    if status < 0 || output.is_null() || output_len == 0 {
        if !output.is_null() {
            unsafe { LocalFree(output.cast()) };
        }
        return Err(provider_error());
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output, usize::try_from(output_len).unwrap_or(0)).to_vec()
    };
    unsafe { LocalFree(output.cast()) };
    if bytes.is_empty() {
        Err(SupervisionAuthorityKeyError::ProviderUnavailable)
    } else {
        Ok(bytes)
    }
}

#[cfg(not(windows))]
fn protect_for_service_sid(
    _service_sid: &str,
    _secret: &[u8],
) -> Result<Vec<u8>, SupervisionAuthorityKeyError> {
    Err(SupervisionAuthorityKeyError::ProviderUnavailable)
}

#[cfg(windows)]
fn unprotect_for_service_sid(
    expected_service_sid: &str,
    sealed_blob: &[u8],
) -> Result<CredentialSecret, SupervisionAuthorityKeyError> {
    use std::os::windows::ffi::OsStringExt as _;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING, NCRYPT_SILENT_FLAG,
        NCryptCloseProtectionDescriptor, NCryptGetProtectionDescriptorInfo, NCryptUnprotectSecret,
    };
    let expected_descriptor = protection_descriptor(expected_service_sid)?;
    let mut handle = std::ptr::null_mut();
    let mut output = std::ptr::null_mut();
    let mut output_len = 0_u32;
    let status = unsafe {
        NCryptUnprotectSecret(
            &raw mut handle,
            NCRYPT_SILENT_FLAG,
            sealed_blob.as_ptr(),
            u32::try_from(sealed_blob.len())
                .map_err(|_| SupervisionAuthorityKeyError::InvalidBinding)?,
            std::ptr::null(),
            std::ptr::null_mut(),
            &raw mut output,
            &raw mut output_len,
        )
    };
    if status < 0 || handle.is_null() || output.is_null() || output_len == 0 {
        if !handle.is_null() {
            unsafe { NCryptCloseProtectionDescriptor(handle) };
        }
        if !output.is_null() {
            unsafe { LocalFree(output.cast()) };
        }
        return Err(provider_error());
    }
    let mut descriptor_ptr = std::ptr::null_mut();
    let descriptor_status = unsafe {
        NCryptGetProtectionDescriptorInfo(
            handle,
            std::ptr::null(),
            NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING,
            &raw mut descriptor_ptr,
        )
    };
    let descriptor = if descriptor_status < 0 || descriptor_ptr.is_null() {
        None
    } else {
        let wide = descriptor_ptr.cast::<u16>();
        let mut length = 0_usize;
        while unsafe { *wide.add(length) } != 0 {
            length += 1;
        }
        Some(
            unsafe { std::ffi::OsString::from_wide(std::slice::from_raw_parts(wide, length)) }
                .to_string_lossy()
                .into_owned(),
        )
    };
    if !descriptor_ptr.is_null() {
        unsafe { LocalFree(descriptor_ptr) };
    }
    unsafe { NCryptCloseProtectionDescriptor(handle) };
    if descriptor.as_deref() != Some(expected_descriptor.as_str()) {
        unsafe { LocalFree(output.cast()) };
        return Err(SupervisionAuthorityKeyError::InvalidBinding);
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(output, usize::try_from(output_len).unwrap_or(0)).to_vec()
    };
    unsafe { LocalFree(output.cast()) };
    if bytes.len() != 32 || bytes.iter().all(|byte| *byte == 0) {
        return Err(SupervisionAuthorityKeyError::KeyInvalid);
    }
    Ok(CredentialSecret(bytes))
}

#[cfg(not(windows))]
fn unprotect_for_service_sid(
    _expected_service_sid: &str,
    _sealed_blob: &[u8],
) -> Result<CredentialSecret, SupervisionAuthorityKeyError> {
    Err(SupervisionAuthorityKeyError::ProviderUnavailable)
}

impl From<WindowsAdapterError> for SupervisionAuthorityKeyError {
    fn from(error: WindowsAdapterError) -> Self {
        match error {
            WindowsAdapterError::PermissionDenied => Self::AccessDenied,
            WindowsAdapterError::InvalidInput | WindowsAdapterError::IdentityMismatch => {
                Self::InvalidBinding
            }
            _ => Self::ProviderUnavailable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_descriptor_requires_exact_service_sid_text() {
        assert_eq!(
            protection_descriptor("S-1-5-80-1-2-3-4-5")
                .unwrap_or_else(|error| panic!("descriptor: {error}")),
            "SID=S-1-5-80-1-2-3-4-5"
        );
        assert!(protection_descriptor("NT SERVICE\\EliotHost").is_err());
        assert!(protection_descriptor("S-1-5-19").is_err());
    }
}
