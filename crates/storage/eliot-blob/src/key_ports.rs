//! Production key-lineage and AEAD providers over the closed `dpapi-user-v1`
//! set (issue #1873).
//!
//! [`DpapiUserKeyPort`] serves one owned key lineage; [`DpapiUserAeadPort`]
//! seals and opens envelopes through the installation DPAPI secret owner.
//! The request nonce context and associated data are length-framed inside
//! the protected payload, so tampering with either refuses on open. Test
//! doubles (`TestKeys`/`TestAead`) remain for unit compositions; production
//! staging through `BlobStoreService` uses these providers. There is no
//! homebrew cipher here: confidentiality and OS-identity binding come from
//! the platform primitive, while framing only binds the caller-supplied
//! context. Cross-machine envelopes refuse at the platform call — never
//! invented success.
//!
//! Denied-by-default mapping (existing [`BlobError`] variants only):
//! unknown algorithm or foreign lineage → [`BlobError::ProviderUnavailable`]
//! (the stage caller maps this to typed `KeyUnavailable` per the established
//! convention); framing/authentication failure → [`BlobError::IntegrityMismatch`];
//! platform failure → [`BlobError::Provider`]; malformed descriptor or empty
//! input → [`BlobError::InvalidField`].

use eliot_blob_api::{BlobError, BlobId, CryptoDescriptor};
use eliot_platform_windows::{ProtectedSecret, WindowsPlatform};

use super::{AeadOpenRequest, AeadSealRequest, BlobAeadPort, BlobKeyPort, BlobKeySelection};

/// The only key/aead algorithm these providers serve.
pub const KEY_PORT_ALGORITHM: &str = "dpapi-user-v1";
/// Envelope format version pinned into served selections.
pub const KEY_PORT_VERSION: u32 = 1;

const PROVIDER_SCOPE: &str = "dpapi-user-v1 key lineage only";

/// Production key-lineage provider for one owned lineage.
///
/// Serves `current` (this lineage at this generation) and `resolve` (this
/// lineage at any requested generation above zero, so previously sealed
/// envelopes stay openable after rotation). Anything else refuses: the
/// provider never echoes a foreign lineage or algorithm, so equal bytes
/// under different obligation domains cannot coalesce through it.
pub struct DpapiUserKeyPort {
    lineage: BlobId,
    generation: u64,
}

impl DpapiUserKeyPort {
    /// Binds the provider to one owned lineage at one current generation.
    ///
    /// # Errors
    ///
    /// Returns [`BlobError::InvalidField`] for a zero generation.
    pub fn new(lineage: BlobId, generation: u64) -> Result<Self, BlobError> {
        if generation == 0 {
            return Err(BlobError::InvalidField {
                field: "crypto_generation",
                reason: "must be greater than zero",
            });
        }
        Ok(Self {
            lineage,
            generation,
        })
    }

    fn selection(&self, generation: u64) -> Result<BlobKeySelection, BlobError> {
        Ok(BlobKeySelection {
            key_ref: BlobId::new(format!("dpapi-user-{}-{generation}", self.lineage.as_str()))?,
            crypto: CryptoDescriptor {
                algorithm: BlobId::new(KEY_PORT_ALGORITHM)?,
                version: KEY_PORT_VERSION,
                key_lineage: self.lineage.clone(),
                key_generation: generation,
            },
        })
    }
}

impl BlobKeyPort for DpapiUserKeyPort {
    fn current(&mut self) -> Result<BlobKeySelection, BlobError> {
        self.selection(self.generation)
    }

    fn resolve(&self, descriptor: &CryptoDescriptor) -> Result<BlobKeySelection, BlobError> {
        descriptor.validate()?;
        if descriptor.algorithm.as_str() != KEY_PORT_ALGORITHM {
            return Err(BlobError::ProviderUnavailable(PROVIDER_SCOPE));
        }
        if descriptor.key_lineage != self.lineage {
            return Err(BlobError::ProviderUnavailable(PROVIDER_SCOPE));
        }
        self.selection(descriptor.key_generation)
    }
}

/// Production AEAD provider through the installation secret owner.
///
/// Seal protects a length-framed
/// `nonce_len || nonce_context || ad_len || associated_data || plaintext`
/// payload; open reverses it and requires exact nonce and associated-data
/// equality. DPAPI randomizes protection internally, so equal plaintexts
/// never share an envelope.
pub struct DpapiUserAeadPort {
    platform: WindowsPlatform,
}

impl std::fmt::Debug for DpapiUserKeyPort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DpapiUserKeyPort")
            .field("lineage", &self.lineage)
            .field("generation", &self.generation)
            .finish()
    }
}

impl std::fmt::Debug for DpapiUserAeadPort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("DpapiUserAeadPort").finish()
    }
}

impl DpapiUserAeadPort {
    /// Binds the provider to an already-constructed platform handle.
    #[must_use]
    pub fn new(platform: WindowsPlatform) -> Self {
        Self { platform }
    }
}

fn require_selection(selection: &BlobKeySelection) -> Result<(), BlobError> {
    if selection.crypto.algorithm.as_str() != KEY_PORT_ALGORITHM {
        return Err(BlobError::ProviderUnavailable(PROVIDER_SCOPE));
    }
    selection.crypto.validate()?;
    Ok(())
}

fn frame(
    nonce_context: &[u8],
    associated_data: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, BlobError> {
    let invalid = |reason: &'static str| BlobError::InvalidField {
        field: "aead.framing",
        reason,
    };
    if nonce_context.len() > u32::MAX as usize
        || associated_data.len() > u32::MAX as usize
        || plaintext.len() > u32::MAX as usize
    {
        return Err(invalid("context lengths exceed the envelope ceiling"));
    }
    let total = 4usize
        .checked_add(nonce_context.len())
        .and_then(|total| total.checked_add(4))
        .and_then(|total| total.checked_add(associated_data.len()))
        .and_then(|total| total.checked_add(plaintext.len()))
        .ok_or_else(|| invalid("framed envelope length overflows"))?;
    let mut framed = Vec::with_capacity(total);
    framed.extend_from_slice(
        &u32::try_from(nonce_context.len())
            .map_err(|_| invalid("context lengths exceed the envelope ceiling"))?
            .to_le_bytes(),
    );
    framed.extend_from_slice(nonce_context);
    framed.extend_from_slice(
        &u32::try_from(associated_data.len())
            .map_err(|_| invalid("context lengths exceed the envelope ceiling"))?
            .to_le_bytes(),
    );
    framed.extend_from_slice(associated_data);
    framed.extend_from_slice(plaintext);
    Ok(framed)
}

fn split_framed(bytes: &[u8], mid: usize) -> Result<(&[u8], &[u8]), BlobError> {
    if mid > bytes.len() {
        return Err(BlobError::IntegrityMismatch);
    }
    Ok(bytes.split_at(mid))
}

fn read_framed_u32(bytes: &[u8]) -> Result<(u32, &[u8]), BlobError> {
    let (head, rest) = split_framed(bytes, 4)?;
    let mut length = [0_u8; 4];
    length.copy_from_slice(head);
    Ok((u32::from_le_bytes(length), rest))
}

fn parse_framed(
    framed: &[u8],
    nonce_context: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, BlobError> {
    let (nonce_len, rest) = read_framed_u32(framed)?;
    let (nonce, rest) = split_framed(rest, nonce_len as usize)?;
    let (ad_len, rest) = read_framed_u32(rest)?;
    let (associated, plaintext) = split_framed(rest, ad_len as usize)?;
    if nonce != nonce_context || associated != associated_data {
        return Err(BlobError::IntegrityMismatch);
    }
    Ok(plaintext.to_vec())
}

impl BlobAeadPort for DpapiUserAeadPort {
    fn seal(&mut self, request: AeadSealRequest<'_>) -> Result<Vec<u8>, BlobError> {
        require_selection(request.key)?;
        if request.plaintext.is_empty() {
            return Err(BlobError::InvalidField {
                field: "aead.plaintext",
                reason: "cannot seal empty plaintext",
            });
        }
        let framed = frame(
            request.nonce_context,
            request.associated_data,
            request.plaintext,
        )?;
        let protected = self
            .platform
            .protect_secret(&framed)
            .map_err(|error| BlobError::Provider(format!("envelope seal failed: {error:?}")))?;
        Ok(protected.as_bytes().to_vec())
    }

    fn open(&self, request: AeadOpenRequest<'_>) -> Result<Vec<u8>, BlobError> {
        require_selection(request.key)?;
        let protected =
            ProtectedSecret::from_ciphertext(request.ciphertext.to_vec()).map_err(|_| {
                BlobError::InvalidField {
                    field: "aead.ciphertext",
                    reason: "sealed envelope cannot be empty",
                }
            })?;
        let opened = self
            .platform
            .unprotect_secret(&protected)
            .map_err(|error| BlobError::Provider(format!("envelope open failed: {error:?}")))?;
        parse_framed(
            opened.expose(),
            request.nonce_context,
            request.associated_data,
        )
    }
}

#[cfg(test)]
mod key_port_tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    const TEST_LINEAGE: &str = "dpapi-user-1873k";
    const OTHER_LINEAGE: &str = "dpapi-user-other";

    fn key_port() -> DpapiUserKeyPort {
        DpapiUserKeyPort::new(BlobId::new(TEST_LINEAGE).expect("lineage"), 3).expect("key port")
    }

    fn platform_on_temp(label: &str) -> (WindowsPlatform, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("eliot-1873k-{label}"));
        std::fs::create_dir_all(&root).expect("isolated root");
        let platform = WindowsPlatform::new(root.clone()).expect("platform bind");
        (platform, root)
    }

    fn descriptor_for(algorithm: &str, lineage: &str, generation: u64) -> CryptoDescriptor {
        CryptoDescriptor {
            algorithm: BlobId::new(algorithm).expect("algorithm"),
            version: 1,
            key_lineage: BlobId::new(lineage).expect("lineage"),
            key_generation: generation,
        }
    }

    #[test]
    fn current_serves_owned_lineage_and_generation() {
        let mut port = key_port();
        let selection = port.current().expect("current");
        assert_eq!(selection.crypto.algorithm.as_str(), KEY_PORT_ALGORITHM);
        assert_eq!(selection.crypto.version, KEY_PORT_VERSION);
        assert_eq!(selection.crypto.key_lineage.as_str(), TEST_LINEAGE);
        assert_eq!(selection.crypto.key_generation, 3);
        assert!(selection.key_ref.as_str().contains(TEST_LINEAGE));
    }

    #[test]
    fn resolve_accepts_owned_lineage_any_live_generation() {
        let port = key_port();
        let selection = port
            .resolve(&descriptor_for(KEY_PORT_ALGORITHM, TEST_LINEAGE, 7))
            .expect("resolve");
        assert_eq!(selection.crypto.key_generation, 7);
        assert_eq!(selection.crypto.key_lineage.as_str(), TEST_LINEAGE);
    }

    #[test]
    fn resolve_refuses_unknown_algorithm() {
        let port = key_port();
        let error = port
            .resolve(&descriptor_for("aead-test", TEST_LINEAGE, 1))
            .expect_err("unknown algorithm must refuse");
        assert!(
            matches!(error, BlobError::ProviderUnavailable(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn resolve_refuses_foreign_lineage() {
        let port = key_port();
        let error = port
            .resolve(&descriptor_for(KEY_PORT_ALGORITHM, OTHER_LINEAGE, 1))
            .expect_err("foreign lineage must refuse");
        assert!(
            matches!(error, BlobError::ProviderUnavailable(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn key_port_rejects_zero_generation() {
        let error = DpapiUserKeyPort::new(BlobId::new(TEST_LINEAGE).expect("lineage"), 0)
            .expect_err("zero generation must refuse");
        assert!(
            matches!(error, BlobError::InvalidField { .. }),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn seal_refuses_empty_plaintext_without_crypto() {
        let (platform, root) = platform_on_temp("seal-empty");
        let mut port = DpapiUserAeadPort::new(platform);
        let key = key_port().current().expect("selection");
        let error = port
            .seal(AeadSealRequest {
                key: &key,
                nonce_context: b"nonce",
                associated_data: b"ad",
                plaintext: b"",
            })
            .expect_err("empty plaintext must refuse");
        assert!(
            matches!(error, BlobError::InvalidField { .. }),
            "unexpected error: {error}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn seal_refuses_foreign_selection_without_crypto() {
        let (platform, root) = platform_on_temp("seal-foreign");
        let mut port = DpapiUserAeadPort::new(platform);
        let foreign = BlobKeySelection {
            key_ref: BlobId::new("test-key-1").expect("key ref"),
            crypto: descriptor_for("test-only-authenticated-envelope", TEST_LINEAGE, 1),
        };
        let error = port
            .seal(AeadSealRequest {
                key: &foreign,
                nonce_context: b"nonce",
                associated_data: b"ad",
                plaintext: b"payload",
            })
            .expect_err("foreign selection must refuse");
        assert!(
            matches!(error, BlobError::ProviderUnavailable(_)),
            "unexpected error: {error}"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[cfg(windows)]
    #[test]
    fn seal_open_roundtrip_binds_nonce_and_associated_data() {
        let (platform, root) = platform_on_temp("roundtrip");
        let mut port = DpapiUserAeadPort::new(platform);
        let key = key_port().current().expect("selection");
        let sealed = port
            .seal(AeadSealRequest {
                key: &key,
                nonce_context: b"scope-nonce-1873k",
                associated_data: b"aad-1873k",
                plaintext: b"payload-1873k",
            })
            .expect("seal");
        assert!(!sealed.is_empty());
        let opened = port
            .open(AeadOpenRequest {
                key: &key,
                nonce_context: b"scope-nonce-1873k",
                associated_data: b"aad-1873k",
                ciphertext: &sealed,
            })
            .expect("open");
        assert_eq!(opened, b"payload-1873k");

        // Fresh protection randomizes: equal plaintext never shares an envelope.
        let resealed = port
            .seal(AeadSealRequest {
                key: &key,
                nonce_context: b"scope-nonce-1873k",
                associated_data: b"aad-1873k",
                plaintext: b"payload-1873k",
            })
            .expect("reseal");
        assert_ne!(sealed, resealed);

        let wrong_ad = port.open(AeadOpenRequest {
            key: &key,
            nonce_context: b"scope-nonce-1873k",
            associated_data: b"aad-tampered",
            ciphertext: &sealed,
        });
        assert_eq!(wrong_ad, Err(BlobError::IntegrityMismatch));

        let wrong_nonce = port.open(AeadOpenRequest {
            key: &key,
            nonce_context: b"nonce-tampered",
            associated_data: b"aad-1873k",
            ciphertext: &sealed,
        });
        assert_eq!(wrong_nonce, Err(BlobError::IntegrityMismatch));

        let foreign = port.open(AeadOpenRequest {
            key: &key,
            nonce_context: b"scope-nonce-1873k",
            associated_data: b"aad-1873k",
            ciphertext: b"foreign-ciphertext-bytes",
        });
        assert!(
            matches!(foreign, Err(BlobError::Provider(_))),
            "unexpected result: {foreign:?}"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
