//! Standalone accepted-source projection: handle-bound refs without bytes.
//!
//! [`AcceptedSourceProjection`] cites accepted Architecture/Implementation
//! sources by handle for self-queries built on the existing [`SelfQueryInput`]
//! owner contract. Each [`AcceptedSourceRef`] carries source identity
//! (handle plus owner), a revision cursor with its content digest, the
//! accepted status, and the acceptance receipt lineage — everything a
//! citation check needs, without embedding source bytes and without a
//! second request type.
//!
//! Placement: the wave briefs name no separate accepted-source owner; the
//! source vocabulary owner is this crate's `self_query::source` module
//! ("Accepted normative-source, anchor and coverage-denominator
//! contracts"), so the projection lives beside `ArchitectureSourceSnapshot`
//! and reuses its identity, digest, lineage, and pair-binding rules.
//!
//! Revalidation binding: the projection freezes the normative pair edition
//! ([`NormativePairBinding`]) and the [`StateFence`] it was read under.
//! Both are carried, not gated: consumers gate fence compatibility at
//! their edge, and a cited triple (handle, revision, digest) revalidates
//! by exact match against the projected refs. A revision or digest drift
//! means the citation is stale; there is no similarity fallback. The
//! projection covers exactly its listed refs and never claims owner
//! completeness. This module performs no acquisition, acceptance,
//! compilation, or briefing.

#![forbid(unsafe_code)]

use eliot_contracts::{ArtifactId, ReceiptId, SourceId, StateFence};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::result::SelfQueryContractError;
use super::source::{
    ArchitectureSourceStatus, NormativePairBinding, SCHEMA_VERSION, check_digest, check_id,
    check_schema, check_text,
};

/// Maximum accepted-source refs carried by one projection.
pub(crate) const MAX_SOURCES: usize = 1024;

/// One handle-bound accepted-source ref: identity, revision cursor, and
/// acceptance lineage without bytes.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedSourceRef {
    /// Exact source handle cited.
    pub source_handle: ArtifactId,
    /// External owner that accepted the source.
    pub owner: SourceId,
    /// Revision cursor observed for this handle.
    pub revision: String,
    /// Content digest at the revision cursor.
    pub digest: String,
    /// Acceptance lifecycle state; only accepted refs project.
    pub status: ArchitectureSourceStatus,
    /// Acceptance receipt lineage; joins without source bytes.
    pub acceptance_receipt: ReceiptId,
}

impl AcceptedSourceRef {
    /// Validate identity, cursor, digest, lineage, and accepted status.
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_id(self.source_handle.as_str(), "source_ref.source_handle")?;
        check_id(self.owner.as_str(), "source_ref.owner")?;
        check_text(&self.revision, "source_ref.revision", 256)?;
        check_digest(&self.digest, "source_ref.digest")?;
        check_id(
            self.acceptance_receipt.as_str(),
            "source_ref.acceptance_receipt",
        )?;
        if self.status != ArchitectureSourceStatus::Accepted {
            return Err(SelfQueryContractError::Conflict {
                field: "source_ref.status",
            });
        }
        Ok(())
    }
}

/// Standalone projection over accepted sources for handle-bound citation.
///
/// `pair` pins the normative edition every ref was accepted under;
/// `fence` pins the fence the projection was read under. Consumers cite
/// triples that must match a projected ref exactly.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedSourceProjection {
    /// Exact schema version; must be 1.
    pub schema_version: u32,
    /// Stable projection identity.
    pub projection_id: ArtifactId,
    /// Normative edition identity shared by every projected ref.
    pub pair: NormativePairBinding,
    /// Fence the projection was read under, carried for edge gating.
    pub fence: StateFence,
    /// Projected refs in deterministic supply order.
    pub sources: Vec<AcceptedSourceRef>,
    /// Frozen digest over the projection shape, excluding this field.
    pub digest: String,
}

impl AcceptedSourceProjection {
    /// Project validated refs under one pair edition and fence.
    pub fn project(
        projection_id: ArtifactId,
        pair: NormativePairBinding,
        fence: StateFence,
        sources: Vec<AcceptedSourceRef>,
    ) -> Result<Self, SelfQueryContractError> {
        let mut projection = Self {
            schema_version: SCHEMA_VERSION,
            projection_id,
            pair,
            fence,
            sources,
            digest: String::new(),
        };
        projection.digest = projection.compute_digest()?;
        projection.validate()?;
        Ok(projection)
    }

    /// Compute the frozen digest over the projection shape.
    pub fn compute_digest(&self) -> Result<String, SelfQueryContractError> {
        check_id(self.projection_id.as_str(), "projection.projection_id")?;
        if self.sources.len() > MAX_SOURCES {
            return Err(SelfQueryContractError::Bound {
                field: "projection.sources",
                maximum: MAX_SOURCES,
                actual: self.sources.len(),
            });
        }
        super::source::canonical_digest(
            &(
                self.schema_version,
                &self.projection_id,
                &self.pair,
                &self.fence,
                &self.sources,
            ),
            "projection.digest",
        )
    }

    /// Validate schema, identity, pair, fence, refs, handle uniqueness,
    /// and the frozen digest.
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        check_schema(self.schema_version, "projection.schema_version")?;
        check_id(self.projection_id.as_str(), "projection.projection_id")?;
        self.pair.validate()?;
        if self.fence.validate().is_err() {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "projection.fence",
            });
        }
        if self.sources.len() > MAX_SOURCES {
            return Err(SelfQueryContractError::Bound {
                field: "projection.sources",
                maximum: MAX_SOURCES,
                actual: self.sources.len(),
            });
        }
        let mut handles = std::collections::BTreeSet::new();
        for source in &self.sources {
            source.validate()?;
            // Pair/ref lineage equality mirrors the snapshot rule: a ref
            // joins this projection only under the pair's acceptor and
            // acceptance receipt.
            if source.owner != self.pair.accepted_by {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "projection.acceptance_owner",
                });
            }
            if source.acceptance_receipt != self.pair.acceptance_receipt {
                return Err(SelfQueryContractError::BindingMismatch {
                    field: "projection.acceptance_receipt",
                });
            }
            if !handles.insert(source.source_handle.clone()) {
                return Err(SelfQueryContractError::Duplicate {
                    field: "projection.sources",
                });
            }
        }
        if self.digest != self.compute_digest()? {
            return Err(SelfQueryContractError::DigestMismatch {
                field: "projection.digest",
            });
        }
        Ok(())
    }

    /// Find the projected ref for one source handle.
    #[must_use]
    pub fn find_source(&self, handle: &ArtifactId) -> Option<&AcceptedSourceRef> {
        self.sources
            .iter()
            .find(|source| source.source_handle == *handle)
    }

    /// Revalidate one cited triple against the projected refs: the handle
    /// must project, and its revision and digest must still match. Any
    /// mismatch means the citation is stale.
    pub fn check_cited(
        &self,
        handle: &ArtifactId,
        revision: &str,
        digest: &str,
    ) -> Result<(), SelfQueryContractError> {
        let projected =
            self.find_source(handle)
                .ok_or(SelfQueryContractError::BindingMismatch {
                    field: "cited.source_handle",
                })?;
        if projected.revision != revision || projected.digest != digest {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "cited.source_lineage",
            });
        }
        Ok(())
    }
}
