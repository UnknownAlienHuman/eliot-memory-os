//! Immutable, content-addressed artifact identity.

use crate::{
    ArtifactError, ArtifactKind, ContentAddress, HashAlgorithm, SchemaBinding, SourceBinding,
    validate_digest,
};
use eliot_contracts::{ArtifactId, ClockReading, OperationId, SourceId};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The durable, content-addressed identity of an immutable artifact.
///
/// The identity is derived, not caller-asserted: [`ArtifactIdentity::bind`]
/// computes the content address from bytes, and [`ArtifactIdentity::validate`]
/// re-checks every binding so a hand-crafted digest cannot pass through a
/// deserialization boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    /// Stable artifact handle.
    pub artifact_id: ArtifactId,
    /// Artifact class.
    pub kind: ArtifactKind,
    /// Content-addressed reference to the immutable bytes.
    pub content: ContentAddress,
    /// Schema binding, when the artifact has an admitted shape.
    pub schema: Option<SchemaBinding>,
    /// Source binding, when the producing origin is known.
    pub source: Option<SourceBinding>,
    /// Capture/creation clock.
    pub created_at: ClockReading,
}

impl ArtifactIdentity {
    /// Binds the complete source archive captured for one admitted Instrument
    /// invocation. The operation identity namespaces the artifact handle; the
    /// existing ArtifactIdentity content address is computed from every exact
    /// archive byte. Callers must first establish that `operation` is the
    /// retained, admitted invocation for the selected source candidate.
    pub fn bind_source_snapshot(
        operation: &OperationId,
        source_id: SourceId,
        source_revision: impl Into<String>,
        bytes: &[u8],
        schema: Option<SchemaBinding>,
        created_at: ClockReading,
    ) -> Result<Self, ArtifactError> {
        let artifact_id = ArtifactId::new(format!("source-snapshot:{}", operation.as_str()))?;
        let content = ContentAddress::of_bytes(bytes);
        let source = SourceBinding {
            source_id,
            revision: source_revision.into(),
            integrity: Some(content.digest_hex),
        };
        Self::bind(
            artifact_id,
            ArtifactKind::RawEvidence,
            bytes,
            schema,
            Some(source),
            created_at,
        )
    }

    /// Derives an identity from exact content bytes and bindings.
    pub fn bind(
        artifact_id: ArtifactId,
        kind: ArtifactKind,
        content: &[u8],
        schema: Option<SchemaBinding>,
        source: Option<SourceBinding>,
        created_at: ClockReading,
    ) -> Result<Self, ArtifactError> {
        let identity = Self {
            artifact_id,
            kind,
            content: ContentAddress::of_bytes(content),
            schema,
            source,
            created_at,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Validates content addressing, bindings and clock invariants.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        if self.content.algorithm != HashAlgorithm::Sha256 {
            return Err(ArtifactError::Unsupported {
                field: "content.algorithm",
                reason: "only SHA-256 is admitted",
            });
        }
        validate_digest(&self.content.digest_hex, "content.digest_hex")?;
        if let Some(schema) = &self.schema {
            schema.validate()?;
        }
        if let Some(source) = &self.source {
            source.validate()?;
        }
        self.created_at
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "created_at",
            })
    }

    /// Verifies that exact bytes satisfy this identity.
    pub fn verify_content(&self, bytes: &[u8]) -> Result<(), ArtifactError> {
        self.content.verify(bytes)
    }

    /// Computes the canonical identity digest for stable references.
    pub fn identity_digest(&self) -> Result<String, ArtifactError> {
        crate::canonical_json_bytes(self).map(|bytes| crate::sha256_hex(&bytes))
    }
}
