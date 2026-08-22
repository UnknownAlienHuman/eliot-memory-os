use eliot_contracts::sha256_hex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{SupervisionLeaseError, SupervisionTrustAnchor};

/// Canonical schema for the immutable, public Watchdog admission template.
pub const WATCHDOG_ADMISSION_SCHEMA: &str = "eliot.watchdog-admission.v2";
/// Canonical schema for the marker-last Host publication bundle.
pub const WATCHDOG_PUBLICATION_SCHEMA: &str = "eliot.watchdog-publication.v1";

/// Validation failure for public Watchdog admission/publication contracts.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WatchdogPublicationError {
    /// A required textual field is blank or contains a control character.
    #[error("{field} is not valid text")]
    InvalidText { field: &'static str },
    /// A strict schema marker did not match the supported contract.
    #[error("{field} has an unsupported schema")]
    UnsupportedSchema { field: &'static str },
    /// A digest is not canonical lowercase SHA-256.
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    /// The externally provisioned public trust anchor is invalid.
    #[error("watchdog admission trust anchor: {0}")]
    TrustAnchor(#[from] SupervisionLeaseError),
    /// The contract could not be serialized canonically.
    #[error("watchdog publication canonical encoding failed")]
    Encoding,
    /// The marker does not bind the exact admission/lease bytes.
    #[error("watchdog publication marker does not bind the exact file bytes")]
    ContentMismatch,
}

fn validate_text(value: &str, field: &'static str) -> Result<(), WatchdogPublicationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(WatchdogPublicationError::InvalidText { field });
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), WatchdogPublicationError> {
    if !is_sha256_hex(value) {
        return Err(WatchdogPublicationError::InvalidDigest { field });
    }
    Ok(())
}

/// Immutable public admission selected by an approved installation manifest.
///
/// Dynamic lease state is deliberately absent. The manifest binds the digest
/// of these canonical bytes; Host publishes the current signed ORS artifact in
/// a separate marker-last bundle. No private key locator crosses this type.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogAdmissionTemplate {
    /// Strict public admission schema.
    pub schema: String,
    /// Installation identity which owns the public trust anchor.
    pub installation_id: String,
    /// Exact approved manifest generation.
    pub approved_generation: String,
    /// Exact installation-approved supervision lease identity.
    pub supervision_lease_id: String,
    /// Public verifier provisioned by the installer authority lane.
    pub trust_anchor: SupervisionTrustAnchor,
}

impl WatchdogAdmissionTemplate {
    /// Builds the strict current public template.
    pub fn new(
        installation_id: impl Into<String>,
        approved_generation: impl Into<String>,
        supervision_lease_id: impl Into<String>,
        trust_anchor: SupervisionTrustAnchor,
    ) -> Result<Self, WatchdogPublicationError> {
        let template = Self {
            schema: WATCHDOG_ADMISSION_SCHEMA.to_owned(),
            installation_id: installation_id.into(),
            approved_generation: approved_generation.into(),
            supervision_lease_id: supervision_lease_id.into(),
            trust_anchor,
        };
        template.validate()?;
        Ok(template)
    }

    /// Validates strict schema, identities and the externally provisioned key.
    pub fn validate(&self) -> Result<(), WatchdogPublicationError> {
        if self.schema != WATCHDOG_ADMISSION_SCHEMA {
            return Err(WatchdogPublicationError::UnsupportedSchema {
                field: "watchdog_admission.schema",
            });
        }
        validate_text(&self.installation_id, "watchdog_admission.installation_id")?;
        validate_text(
            &self.approved_generation,
            "watchdog_admission.approved_generation",
        )?;
        validate_text(
            &self.supervision_lease_id,
            "watchdog_admission.supervision_lease_id",
        )?;
        self.trust_anchor.validate()?;
        if self.trust_anchor.installation_id != self.installation_id {
            return Err(WatchdogPublicationError::InvalidText {
                field: "watchdog_admission.trust_anchor.installation_id",
            });
        }
        Ok(())
    }

    /// Returns the exact canonical JSON bytes covered by the manifest digest.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WatchdogPublicationError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| WatchdogPublicationError::Encoding)
    }

    /// Computes the manifest-facing lowercase SHA-256 template digest.
    pub fn digest(&self) -> Result<String, WatchdogPublicationError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

/// Marker published last after Host writes the immutable admission and exact
/// current signed lease. Readers must retain/read this marker before and after
/// both children and reject any byte, identity, or ORS-head mismatch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogPublicationBundle {
    /// Strict marker schema.
    pub schema: String,
    /// Manifest-bound installation identity.
    pub installation_id: String,
    /// Manifest-bound approved generation.
    pub approved_generation: String,
    /// Manifest-bound supervision lease identity.
    pub supervision_lease_id: String,
    /// Exact committed ORS lease revision.
    pub lease_revision: u64,
    /// Exact current ORS record identity.
    pub ors_record_id: String,
    /// Exact current ORS receipt digest.
    pub ors_receipt_sha256: String,
    /// Digest of the exact canonical admission file bytes.
    pub admission_sha256: String,
    /// Digest of the exact canonical signed-lease file bytes.
    pub lease_sha256: String,
}

impl WatchdogPublicationBundle {
    /// Validates marker shape without trusting the referenced files.
    pub fn validate(&self) -> Result<(), WatchdogPublicationError> {
        if self.schema != WATCHDOG_PUBLICATION_SCHEMA {
            return Err(WatchdogPublicationError::UnsupportedSchema {
                field: "watchdog_publication.schema",
            });
        }
        validate_text(
            &self.installation_id,
            "watchdog_publication.installation_id",
        )?;
        validate_text(
            &self.approved_generation,
            "watchdog_publication.approved_generation",
        )?;
        validate_text(
            &self.supervision_lease_id,
            "watchdog_publication.supervision_lease_id",
        )?;
        validate_text(&self.ors_record_id, "watchdog_publication.ors_record_id")?;
        if self.lease_revision == 0 {
            return Err(WatchdogPublicationError::InvalidText {
                field: "watchdog_publication.lease_revision",
            });
        }
        validate_digest(
            &self.ors_receipt_sha256,
            "watchdog_publication.ors_receipt_sha256",
        )?;
        validate_digest(
            &self.admission_sha256,
            "watchdog_publication.admission_sha256",
        )?;
        validate_digest(&self.lease_sha256, "watchdog_publication.lease_sha256")
    }

    /// Confirms the marker covers the exact two public child byte strings.
    pub fn verify_bytes(
        &self,
        admission_bytes: &[u8],
        lease_bytes: &[u8],
    ) -> Result<(), WatchdogPublicationError> {
        self.validate()?;
        if sha256_hex(admission_bytes) != self.admission_sha256
            || sha256_hex(lease_bytes) != self.lease_sha256
        {
            return Err(WatchdogPublicationError::ContentMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> SupervisionTrustAnchor {
        let signer =
            crate::Ed25519SupervisionLeaseSigner::from_secret_key("kernel", "key", [7; 32])
                .expect("signer");
        SupervisionTrustAnchor::new(
            "installation-1",
            "kernel",
            "key",
            signer.public_key().to_vec(),
        )
        .expect("anchor")
    }

    #[test]
    fn admission_digest_binds_public_anchor_and_lease_identity() {
        let template =
            WatchdogAdmissionTemplate::new("installation-1", "generation-7", "lease-7", anchor())
                .expect("template");
        let digest = template.digest().expect("digest");
        assert!(is_sha256_hex(&digest));

        let mut substituted = template;
        substituted.supervision_lease_id = "lease-8".to_owned();
        assert_ne!(substituted.digest().expect("substituted digest"), digest);
    }

    #[test]
    fn marker_rejects_mixed_admission_and_lease_bytes() {
        let admission = b"admission";
        let lease = b"lease-v1";
        let marker = WatchdogPublicationBundle {
            schema: WATCHDOG_PUBLICATION_SCHEMA.to_owned(),
            installation_id: "installation-1".to_owned(),
            approved_generation: "generation-7".to_owned(),
            supervision_lease_id: "lease-7".to_owned(),
            lease_revision: 3,
            ors_record_id: "record-3".to_owned(),
            ors_receipt_sha256: "a".repeat(64),
            admission_sha256: sha256_hex(admission),
            lease_sha256: sha256_hex(lease),
        };
        marker.verify_bytes(admission, lease).expect("exact bundle");
        assert_eq!(
            marker.verify_bytes(admission, b"lease-v2"),
            Err(WatchdogPublicationError::ContentMismatch)
        );
    }
}
