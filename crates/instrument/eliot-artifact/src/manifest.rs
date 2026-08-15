//! Canonical, self-verifying artifact manifest.

use crate::{
    ArtifactError, ArtifactIdentity, ArtifactKind, ContentAddress, LineageManifest,
    OmissionReference, RawEvidenceHandle, SchemaBinding, SourceBinding,
};
use eliot_contracts::{ArtifactId, ClockReading, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A canonical manifest binding one immutable artifact to its schema, source,
/// raw evidence handles, omissions and lineage under a state fence.
///
/// The manifest is itself an immutable, content-addressed artifact: its
/// `identity` digest is computed over the manifest body by [`ArtifactManifest::new`]
/// and re-checked by [`ArtifactManifest::validate`], so a hand-crafted manifest
/// with a forged digest cannot pass a deserialization/import boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    /// Content-addressed identity of the manifest itself (`ArtifactKind::Manifest`).
    pub identity: ArtifactIdentity,
    /// The immutable artifact this manifest describes.
    pub artifact: ArtifactIdentity,
    /// Admitted schema binding for the artifact.
    pub schema: SchemaBinding,
    /// Producing source binding for the artifact.
    pub source: SourceBinding,
    /// Raw evidence handles retained for forensic readback.
    pub handles: Vec<RawEvidenceHandle>,
    /// Reversible omission references for shortened material.
    pub omissions: Vec<OmissionReference>,
    /// Provenance lineage of the described artifact.
    pub lineage: LineageManifest,
    /// State fence under which the manifest was published.
    pub state_fence: StateFence,
    /// Publication clock.
    pub published_at: ClockReading,
}

/// The serializable body whose digest is the manifest identity.
#[derive(Serialize)]
struct ManifestBody<'a> {
    artifact: &'a ArtifactIdentity,
    schema: &'a SchemaBinding,
    source: &'a SourceBinding,
    handles: &'a [RawEvidenceHandle],
    omissions: &'a [OmissionReference],
    lineage: &'a LineageManifest,
    state_fence: &'a StateFence,
    published_at: &'a ClockReading,
}

impl ArtifactManifest {
    /// Builds a canonical manifest, computing its content-addressed identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        manifest_id: ArtifactId,
        artifact: ArtifactIdentity,
        schema: SchemaBinding,
        source: SourceBinding,
        handles: Vec<RawEvidenceHandle>,
        omissions: Vec<OmissionReference>,
        lineage: LineageManifest,
        state_fence: StateFence,
        published_at: ClockReading,
    ) -> Result<Self, ArtifactError> {
        let body = ManifestBody {
            artifact: &artifact,
            schema: &schema,
            source: &source,
            handles: &handles,
            omissions: &omissions,
            lineage: &lineage,
            state_fence: &state_fence,
            published_at: &published_at,
        };
        let bytes = crate::canonical_json_bytes(&body)?;
        let identity = ArtifactIdentity::bind(
            manifest_id,
            ArtifactKind::Manifest,
            &bytes,
            Some(schema.clone()),
            Some(source.clone()),
            published_at,
        )?;
        let manifest = Self {
            identity,
            artifact,
            schema,
            source,
            handles,
            omissions,
            lineage,
            state_fence,
            published_at,
        };
        manifest.validate()?;
        Ok(manifest)
    }

    /// Recomputes the manifest identity and validates every binding.
    pub fn validate(&self) -> Result<(), ArtifactError> {
        self.identity.validate()?;
        if self.identity.kind != ArtifactKind::Manifest {
            return Err(ArtifactError::Unsupported {
                field: "identity.kind",
                reason: "canonical manifest requires manifest identity",
            });
        }
        self.artifact.validate()?;
        self.schema.validate()?;
        self.source.validate()?;
        for handle in &self.handles {
            handle.validate()?;
        }
        for omission in &self.omissions {
            omission.validate()?;
        }
        self.lineage.validate()?;
        self.state_fence
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "state_fence",
            })?;
        self.published_at
            .validate()
            .map_err(|_| ArtifactError::InvalidInterval {
                field: "published_at",
            })?;

        // The manifest identity must equal the digest of the manifest body.
        let body = ManifestBody {
            artifact: &self.artifact,
            schema: &self.schema,
            source: &self.source,
            handles: &self.handles,
            omissions: &self.omissions,
            lineage: &self.lineage,
            state_fence: &self.state_fence,
            published_at: &self.published_at,
        };
        let bytes = crate::canonical_json_bytes(&body)?;
        let computed = ContentAddress::of_bytes(&bytes);
        if computed.digest_hex != self.identity.content.digest_hex {
            return Err(ArtifactError::DigestMismatch {
                field: "identity.content",
                expected: self.identity.content.digest_hex.clone(),
                actual: computed.digest_hex,
            });
        }
        if computed.size_bytes != self.identity.content.size_bytes {
            return Err(ArtifactError::LengthMismatch {
                field: "identity.content",
                expected: self.identity.content.size_bytes,
                actual: computed.size_bytes,
            });
        }
        Ok(())
    }
}
