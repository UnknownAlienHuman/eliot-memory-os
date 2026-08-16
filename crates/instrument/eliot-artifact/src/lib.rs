//! Immutable, content-addressed artifact identity and evidence substrate.
//!
//! This crate is the C0 contract/domain core owned by work item `I-01`. It
//! defines the durable vocabulary for artifacts and raw evidence without
//! owning a store, a process, a scheduler or any semantic verdict:
//!
//! ```text
//! artifact identity   content-addressed, immutable, schema/source bound;
//! raw evidence handle location-independent reference to a captured payload;
//! omission reference  reversible handle to material that was shortened;
//! lineage manifest    provenance linking an artifact to its inputs;
//! canonical manifest  self-verifying bundle of identity, handles, omissions
//!                     and lineage under a state fence;
//! import/export       verified transfer boundaries that recompute digests;
//! atomic publication  staged -> published transition with a receipt;
//! verified read         owner-issued, non-deserializable proof of a bound read.
//! ```
//!
//! The crate deliberately contains no Tokio, filesystem, provider, graph or
//! database implementation. It imports `eliot-contracts` (C0-01) and the
//! `eliot-blob-api` (S-04) contract only: S-04 owns durable blob storage and
//! `BlobReadyReceipt`, while I-01 owns the immutable artifact/reference layer.
//! No blob owner, storage path, GC operation or second receipt issuer is
//! implemented here.

#![forbid(unsafe_code)]

mod binding;
mod blob;
mod evidence;
mod identity;
mod lineage;
mod manifest;
mod publication;
#[allow(dead_code)]
mod receipt;
mod transfer;

pub use binding::{SchemaBinding, SourceBinding};
pub use blob::{
    ArtifactBlobReadRequest, ArtifactBlobReader, ArtifactFuture, ArtifactOwner,
    ArtifactReadReceipt, ArtifactReference, BlobReadFuture, VerifiedArtifact,
};
pub use evidence::{ByteRange, Completeness, OmissionReason, OmissionReference, RawEvidenceHandle};
pub use identity::ArtifactIdentity;
pub use lineage::{LineageLink, LineageManifest, LinkClass};
pub use manifest::ArtifactManifest;
pub use publication::{PublicationPhase, PublicationReceipt, PublishedArtifact, StagedArtifact};
pub use transfer::{
    ArtifactExport, ExportFormat, ImportedArtifact, TransferReceipt, verify_import,
};

use eliot_contracts::ContractVersion;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable identity of this contract surface.
pub const CONTRACT_NAME: &str = "eliot.instrument.artifact";
/// Current wire revision of this contract surface.
pub const CONTRACT_VERSION: ContractVersion = ContractVersion::new(1, 0, 0);

/// Validation and lifecycle failures for the artifact substrate.
///
/// Two failure families are kept explicit so a caller can distinguish a
/// recoverable, typed *unavailable* outcome from an integrity failure that must
/// not be laundered as absence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArtifactError {
    /// A required text value is blank or contains a control character.
    #[error("{field} must be non-blank and free of control characters")]
    InvalidText { field: &'static str },
    /// A value is not a lowercase SHA-256 hex digest.
    #[error("{field} must be a lowercase SHA-256 hex digest")]
    InvalidDigest { field: &'static str },
    /// The stored content digest does not match the recomputed digest.
    #[error("{field} digest mismatch: expected {expected}, computed {actual}")]
    DigestMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    /// The stored length does not match the observed length.
    #[error("{field} length mismatch: expected {expected}, observed {actual}")]
    LengthMismatch {
        field: &'static str,
        expected: u64,
        actual: u64,
    },
    /// A collection required to satisfy the contract is empty.
    #[error("{field} must not be empty")]
    EmptyCollection { field: &'static str },
    /// A lifecycle interval is inverted.
    #[error("{field} has an invalid interval")]
    InvalidInterval { field: &'static str },
    /// A payload was shortened without a reversible omission reference.
    #[error("{field} is truncated without a reversible omission reference")]
    TruncatedWithoutOmission { field: &'static str },
    /// A value names a capability or algorithm outside the admitted surface.
    #[error("{field} unsupported: {reason}")]
    Unsupported {
        field: &'static str,
        reason: &'static str,
    },
    /// Structural corruption was observed.
    #[error("structural corruption: {reason}")]
    Corrupted { reason: String },
    /// The artifact could not be resolved.
    #[error("artifact unavailable: {reason}")]
    Unavailable { reason: String },
    /// A value could not be canonicalized for a content digest.
    #[error("canonicalization failed: {0}")]
    Canonicalization(String),
    /// An underlying shared-contract primitive failed validation.
    #[error(transparent)]
    Contract(#[from] eliot_contracts::ContractError),
}

/// The content-addressing algorithm admitted for artifact identities.
///
/// Only SHA-256 is admitted in the first release; the enum is `non_exhaustive`
/// so a future additive algorithm revision does not silently reinterpret an
/// existing identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum HashAlgorithm {
    /// SHA-256, represented as a lowercase hex digest.
    Sha256,
}

/// The broad class of an immutable artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ArtifactKind {
    /// An immutable byte payload captured before parsing or normalization.
    RawEvidence,
    /// A normalized projection derived from raw evidence.
    NormalizedEvidence,
    /// A canonical manifest binding an artifact to its handles and lineage.
    Manifest,
    /// A verified transfer bundle travelling across an import/export boundary.
    ExportBundle,
    /// A build or tool output payload.
    BuildOutput,
    /// A governed document payload.
    Document,
    /// An evidence-bound report projection.
    Report,
    /// A non-production fixture used only for testing.
    Fixture,
    /// The class could not be established.
    Unknown,
}

/// A location-independent, content-addressed reference to immutable bytes.
///
/// This is the handle substrate, not a durable storage receipt: it proves
/// nothing about where the bytes live, only what they must hash to and how
/// large they are.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContentAddress {
    /// Hashing algorithm.
    pub algorithm: HashAlgorithm,
    /// Lowercase hex digest of the addressed bytes.
    pub digest_hex: String,
    /// Exact addressed byte length.
    pub size_bytes: u64,
}

impl ContentAddress {
    /// Constructs a SHA-256 content address from a precomputed digest.
    pub fn sha256(digest_hex: impl Into<String>, size_bytes: u64) -> Result<Self, ArtifactError> {
        let digest_hex = digest_hex.into();
        validate_digest(&digest_hex, "digest_hex")?;
        Ok(Self {
            algorithm: HashAlgorithm::Sha256,
            digest_hex,
            size_bytes,
        })
    }

    /// Computes a content address over the given bytes.
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
            digest_hex: eliot_contracts::sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
        }
    }

    /// Verifies that the supplied bytes match this address.
    pub fn verify(&self, bytes: &[u8]) -> Result<(), ArtifactError> {
        let observed = bytes.len() as u64;
        if observed != self.size_bytes {
            return Err(ArtifactError::LengthMismatch {
                field: "content",
                expected: self.size_bytes,
                actual: observed,
            });
        }
        let actual = eliot_contracts::sha256_hex(bytes);
        if actual != self.digest_hex {
            return Err(ArtifactError::DigestMismatch {
                field: "content",
                expected: self.digest_hex.clone(),
                actual,
            });
        }
        Ok(())
    }
}

/// A reason an artifact failed structural integrity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum CorruptionReason {
    /// The content digest does not match the recomputed digest.
    DigestMismatch,
    /// The content length does not match the observed length.
    LengthMismatch,
    /// The schema binding does not match the admitted schema.
    SchemaMismatch,
    /// The source binding does not match the declared source.
    SourceMismatch,
    /// A payload was truncated without a reversible omission reference.
    TruncatedWithoutOmission,
    /// The manifest or bundle bytes could not be parsed.
    Malformed,
}

/// A reason an artifact could not be resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum UnavailableReason {
    /// The artifact has not reached a published state.
    NotPublished,
    /// The artifact was superseded by a newer immutable identity.
    Superseded,
    /// The addressed bytes are missing.
    Missing,
    /// The backing store cannot be reached.
    StoreUnreachable,
    /// The retention or lease window has expired.
    Expired,
    /// Availability cannot be established.
    Unknown,
}

/// The typed result of resolving a published artifact identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactResolution {
    /// The identity recomputed cleanly against the observed bytes.
    Available { identity: ArtifactIdentity },
    /// The artifact failed structural integrity.
    Corrupted {
        identity: ArtifactIdentity,
        reason: CorruptionReason,
    },
    /// The artifact could not be reached.
    Unavailable {
        identity: ArtifactIdentity,
        reason: UnavailableReason,
    },
}

/// Canonical JSON bytes with object keys sorted recursively.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ArtifactError> {
    eliot_contracts::canonical_json_bytes(value)
        .map_err(|error| ArtifactError::Canonicalization(error.to_string()))
}

/// Lowercase SHA-256 hex digest of the supplied bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    eliot_contracts::sha256_hex(bytes)
}

pub(crate) fn validate_text(value: &str, field: &'static str) -> Result<(), ArtifactError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(ArtifactError::InvalidText { field });
    }
    Ok(())
}

pub(crate) fn validate_digest(value: &str, field: &'static str) -> Result<(), ArtifactError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(ArtifactError::InvalidDigest { field });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{
        AuthorityEpoch, ClockReading, ContractId, ResourceGeneration, SourceId, Status,
    };

    fn clock() -> ClockReading {
        ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(2),
            transaction_sequence: None,
            monotonic_ns: None,
        }
    }

    fn fence() -> eliot_contracts::StateFence {
        eliot_contracts::StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn source() -> SourceBinding {
        SourceBinding {
            source_id: SourceId::new("source-1").expect("valid source id"),
            revision: "r1".to_owned(),
            integrity: None,
        }
    }

    fn schema() -> SchemaBinding {
        SchemaBinding {
            schema_id: ContractId::new("eliot.schema.raw").expect("valid schema id"),
            version: ContractVersion::new(1, 0, 0),
            shape_sha256: sha256_hex(b"{}"),
        }
    }

    fn raw_identity() -> ArtifactIdentity {
        ArtifactIdentity::bind(
            eliot_contracts::ArtifactId::new("raw-1").expect("valid artifact id"),
            ArtifactKind::RawEvidence,
            b"raw bytes",
            None,
            Some(source()),
            clock(),
        )
        .expect("valid raw identity")
    }

    fn handle() -> RawEvidenceHandle {
        RawEvidenceHandle {
            identity: raw_identity(),
            content_type: "text/plain".to_owned(),
            truncated: false,
            truncation: None,
            captured_at: clock(),
        }
    }

    fn manifest() -> ArtifactManifest {
        ArtifactManifest::new(
            eliot_contracts::ArtifactId::new("manifest-1").expect("valid manifest id"),
            raw_identity(),
            schema(),
            source(),
            vec![handle()],
            Vec::new(),
            LineageManifest {
                parents: Vec::new(),
                producer: Some(source()),
                transform: None,
                operation: None,
                created_at: clock(),
            },
            fence(),
            clock(),
        )
        .expect("valid manifest")
    }

    #[test]
    fn content_address_verifies_and_rejects_tampering() {
        let address = ContentAddress::of_bytes(b"payload");
        assert!(address.verify(b"payload").is_ok());
        assert!(matches!(
            address.verify(b"tamperd"),
            Err(ArtifactError::DigestMismatch { .. })
        ));
        assert!(matches!(
            address.verify(b"payload-extra"),
            Err(ArtifactError::LengthMismatch { .. })
        ));
    }

    #[test]
    fn identity_binds_and_verifies_content() {
        let identity = raw_identity();
        assert_eq!(identity.kind, ArtifactKind::RawEvidence);
        assert!(identity.verify_content(b"raw bytes").is_ok());
        assert!(identity.verify_content(b"other").is_err());
        assert!(!identity.identity_digest().expect("digest").is_empty());
    }

    #[test]
    fn manifest_is_self_verifying_and_forged_digest_is_rejected() {
        let manifest = manifest();
        assert!(manifest.validate().is_ok());

        let mut value: serde_json::Value =
            serde_json::to_value(&manifest).expect("serialize manifest");
        value["handles"][0]["identity"]["content"]["size_bytes"] = serde_json::json!(u64::MAX);
        let tampered: ArtifactManifest =
            serde_json::from_value(value).expect("deserialize tampered manifest");
        assert!(matches!(
            tampered.validate(),
            Err(ArtifactError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn truncated_handle_requires_a_reversible_omission() {
        let mut handle = handle();
        handle.truncated = true;
        assert!(matches!(
            handle.validate(),
            Err(ArtifactError::TruncatedWithoutOmission { .. })
        ));

        handle.truncation = Some(OmissionReference {
            omission_id: eliot_contracts::ArtifactId::new("omission-1").expect("valid omission id"),
            source: Some(ContentAddress::of_bytes(b"source")),
            source_checksum: sha256_hex(b"source"),
            original_bytes: 100,
            rendered_bytes: 10,
            omitted_ranges: vec![ByteRange {
                start: 10,
                end_exclusive: 100,
            }],
            reason: OmissionReason::Budget,
            completeness: Completeness::Complete,
            renderer: None,
            created_at: clock(),
        });
        assert!(handle.validate().is_ok());
    }

    #[test]
    fn complete_omission_requires_a_source_handle() {
        let mut omission = OmissionReference {
            omission_id: eliot_contracts::ArtifactId::new("omission-2").expect("valid omission id"),
            source: None,
            source_checksum: sha256_hex(b"source"),
            original_bytes: 100,
            rendered_bytes: 10,
            omitted_ranges: Vec::new(),
            reason: OmissionReason::Preview,
            completeness: Completeness::Complete,
            renderer: None,
            created_at: clock(),
        };
        assert!(matches!(
            omission.validate(),
            Err(ArtifactError::TruncatedWithoutOmission { .. })
        ));
        omission.completeness = Completeness::SourceUnavailable;
        assert!(omission.validate().is_ok());
    }

    #[test]
    fn verified_receipt_recomputes_digest() {
        let identity = raw_identity();
        assert!(identity.verify_content(b"raw bytes").is_ok());
        assert!(identity.verify_content(b"wrong bytes").is_err());
        assert!(crate::receipt::verify_content(&identity, b"raw bytes", clock()).is_ok());
        assert!(crate::receipt::verify_content(&identity, b"wrong bytes", clock()).is_err());
        let receipt =
            crate::receipt::verify_manifest(&manifest(), clock()).expect("verified manifest");
        assert_eq!(receipt.identity().artifact_id.as_str(), "manifest-1");
        assert_eq!(receipt.identity().kind, ArtifactKind::Manifest);
    }

    #[test]
    fn export_import_roundtrip_detects_tampering() {
        let export = ArtifactExport::build(
            eliot_contracts::ArtifactId::new("transfer-1").expect("valid transfer id"),
            manifest(),
            clock(),
        )
        .expect("build export");

        let imported = verify_import(export.clone(), clock()).expect("verify import");
        assert_eq!(
            imported.receipt().manifest_identity(),
            &export.manifest.identity
        );

        let mut tampered = export.clone();
        tampered.integrity = "0".repeat(64);
        assert!(matches!(
            verify_import(tampered, clock()),
            Err(ArtifactError::DigestMismatch { .. })
        ));

        let mut tampered_manifest = export.manifest.clone();
        tampered_manifest.published_at = ClockReading {
            known_time_ms: Some(999),
            ..clock()
        };
        let bad_export = ArtifactExport {
            transfer_id: export.transfer_id.clone(),
            format: export.format,
            integrity: export.integrity.clone(),
            manifest: tampered_manifest,
            exported_at: export.exported_at,
        };
        assert!(verify_import(bad_export, clock()).is_err());
    }

    #[test]
    fn publication_is_atomic() {
        let staged = StagedArtifact::stage(manifest()).expect("stage");
        assert_eq!(staged.phase(), PublicationPhase::Staged);
        let published = staged.publish(None, clock()).expect("publish");
        assert_eq!(published.phase(), PublicationPhase::Published);
        assert!(matches!(
            published.resolve(),
            ArtifactResolution::Available { .. }
        ));
        assert!(published.receipt().validate().is_ok());
    }

    #[test]
    fn unknown_fields_fail_closed() {
        let value = serde_json::json!({
            "artifact_id": "raw-1",
            "kind": "RAW_EVIDENCE",
            "content": {"algorithm": "SHA256", "digest_hex": "0".repeat(64), "size_bytes": 1},
            "schema": null,
            "source": null,
            "created_at": {},
            "unexpected": true
        });
        assert!(serde_json::from_value::<ArtifactIdentity>(value).is_err());
        let schema_bytes = schemars::schema_for!(ArtifactManifest);
        assert!(serde_json::to_vec(&schema_bytes).is_ok_and(|bytes| !bytes.is_empty()));
    }

    #[test]
    fn error_and_status_are_distinct() {
        assert!(Status::Succeeded.is_terminal());
        assert!(matches!(
            CorruptionReason::DigestMismatch,
            CorruptionReason::DigestMismatch
        ));
        assert_ne!(
            ArtifactError::Corrupted {
                reason: "x".to_owned()
            },
            ArtifactError::Unavailable {
                reason: "x".to_owned()
            }
        );
    }
}
