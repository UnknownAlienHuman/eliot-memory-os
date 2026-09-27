//! Signed Watchdog fallback verification material.
//!
//! Architecture: A11.5 Notifications — the fallback path is a restricted
//! installer-pinned, signed-envelope verification route that never opens the
//! Kernel front door or `UserBroker`; it verifies a pre-published
//! `SignedWatchdogFallbackEnvelope` against an installer-owned declaration.
//! See `ARCH-AUTH-01` (authority is the installer declaration plus the
//! Watchdog signing key), `ARCH-SEC-02` (protected `ProgramData` contour and
//! pinned-artifact checks), `ARCH-RES-01` (no repair or canonical-state
//! ownership).
//!
//! Implementation: I1.3 notification adapter (this crate is the `P-01`/`A-10`
//! adapter binding), I11.7 (Watchdog fallback registration), I14.21 unknown
//! outcome where applicable — unknown publication/delivery is never collapsed
//! into success or failure.
//!
//! State: fallback is signed Watchdog-envelope verification only and owns no
//! canonical state or repair authority. The one-shot ledger durability and
//! compare-and-swap lives in `lib.rs`; this module owns protected declaration
//! loading and digest helpers. Parsing and validation use eliot-notify-core.

pub(crate) use eliot_notify_core::{
    FallbackVerificationDeclaration, decode_fallback_key_hex as decode_hex,
    validate_fallback_declaration,
};
use eliot_platform::{PortError, ProviderError, ProviderErrorCode};
use eliot_platform_windows::{ProtectedPathLease, protected_program_data_path};
use sha2::{Digest, Sha256};

use crate::NotifyBuildError;
use crate::{FALLBACK_BYTES_LIMIT, FALLBACK_VERIFIER_RELATIVE};

pub(crate) struct FallbackMaterial {
    pub(crate) declaration: FallbackVerificationDeclaration,
    pub(crate) declaration_digest: String,
    pub(crate) lease: Option<ProtectedPathLease>,
}

impl FallbackMaterial {
    pub(crate) fn validate_live(&self) -> Result<FallbackVerificationDeclaration, PortError> {
        if let Some(lease) = &self.lease {
            lease
                .verify_stable_identity()
                .and_then(|()| lease.verify_path_identity())
                .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))?;
            let bytes = lease
                .read_bounded(FALLBACK_BYTES_LIMIT)
                .map_err(|_| fallback_provider_error(ProviderErrorCode::Unavailable))?;
            if sha256_hex(&bytes) != self.declaration_digest {
                return Err(fallback_provider_error(ProviderErrorCode::InvalidRequest));
            }
            let declaration: FallbackVerificationDeclaration = serde_json::from_slice(&bytes)
                .map_err(|_| fallback_provider_error(ProviderErrorCode::InvalidRequest))?;
            if declaration != self.declaration
                || eliot_receipts::canonical_json_bytes(&declaration)
                    .map_err(|_| fallback_provider_error(ProviderErrorCode::InvalidRequest))?
                    != bytes
            {
                return Err(fallback_provider_error(ProviderErrorCode::InvalidRequest));
            }
        }
        Ok(self.declaration.clone())
    }
}

pub(crate) fn fallback_provider_error(code: ProviderErrorCode) -> PortError {
    PortError::Provider(ProviderError {
        code,
        retryable: matches!(
            code,
            ProviderErrorCode::Unavailable | ProviderErrorCode::Timeout
        ),
    })
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn load_fallback_material() -> Result<FallbackMaterial, NotifyBuildError> {
    let path = protected_program_data_path(FALLBACK_VERIFIER_RELATIVE)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let lease = ProtectedPathLease::open_existing_absolute(&path)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let bytes = lease
        .read_bounded(FALLBACK_BYTES_LIMIT)
        .map_err(|error| NotifyBuildError::Fallback(error.to_string()))?;
    let declaration: FallbackVerificationDeclaration =
        serde_json::from_slice(&bytes).map_err(|error| {
            NotifyBuildError::Fallback(format!("decode verifier material: {error}"))
        })?;
    validate_fallback_declaration(&declaration).map_err(NotifyBuildError::Fallback)?;
    if eliot_receipts::canonical_json_bytes(&declaration).map_err(|error| {
        NotifyBuildError::Fallback(format!("canonicalize verifier material: {error}"))
    })? != bytes
    {
        return Err(NotifyBuildError::Fallback(
            "watchdog verification material is not canonical JSON".to_owned(),
        ));
    }
    Ok(FallbackMaterial {
        declaration,
        declaration_digest: sha256_hex(&bytes),
        lease: Some(lease),
    })
}
