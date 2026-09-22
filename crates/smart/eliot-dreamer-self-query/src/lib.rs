//! Bounded Dreamer self-query pose over existing owner contracts
//! (#223, review repair, unit #3).
//!
//! [`pose_self_query`] accepts the existing
//! `eliot_dreamer_contracts::self_query::SelfQueryInput` (A-03 owner,
//! merged PR #1060), runs the owner's `validate()`, and freezes the owner's
//! `input_digest()` into a [`SelfQueryPoseReceipt`]. [`pose_with_sources`]
//! additionally cites an owner [`AcceptedSourceProjection`]: every source
//! triple the input cites (embedded snapshot plus anchors) must resolve to
//! a current projected ref, otherwise the pose fails closed as stale. That
//! validate-then-digest prefix mirrors the shared entry of both A-08 brief
//! projectors (`project_architecture_brief`, `project_implementation_brief`);
//! this adapter performs no selection, authoring, or model work of its own.
//!
//! There are no parallel subject/request/candidate types here: the request
//! surface, job/admission/attempt bindings, denominator, policy,
//! preservation, source snapshot, anchors, and accepted-source projection
//! stay with the A-03 owner, and brief projection stays with the A-08
//! owners. Source material travels inside owner types; the opaque
//! `source_bundle_handle` is not a typed citation and is never verified
//! here. This package is not a W9 unblock.

#![forbid(unsafe_code)]

use eliot_contracts::ArtifactId;
use eliot_dreamer_contracts::self_query::{
    AcceptedSourceProjection, SelfQueryContractError, SelfQueryInput,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Freeze identity this package builds against.
///
/// See `crates/smart/cognitive-rev12-contract-schema-freeze.toml`.
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22";
/// Owner contract this adapter poses over.
pub const OWNER_CONTRACT: &str = "eliot.smart.dreamer.contracts";

/// A posed self-query: the owner's input digest plus its schema pin.
///
/// The digest identifies the exact validated input closure the brief
/// projectors consume; it proves no admission or source authority beyond
/// what the owner's own `validate()` established.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfQueryPoseReceipt {
    /// Owner's canonical digest over the complete input closure.
    pub input_digest: String,
    /// Input schema version the digest was frozen against.
    pub schema_version: u32,
}

impl SelfQueryPoseReceipt {
    /// Validate the receipt: digest shape only. The digest's authority is
    /// the owner's validation at pose time, rechecked by each consumer.
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        if self.input_digest.len() != 64
            || !self
                .input_digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(SelfQueryContractError::InvalidDigest {
                field: "receipt.input_digest",
            });
        }
        Ok(())
    }
}

/// One cited source triple: handle plus the revision cursor and digest the
/// input claims for it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CitedSource {
    /// Cited source handle.
    pub handle: ArtifactId,
    /// Cited revision cursor.
    pub revision: String,
    /// Cited content digest at the cursor.
    pub digest: String,
}

impl CitedSource {
    /// Validate the cited triple shape.
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        if self.revision.trim().is_empty() {
            return Err(SelfQueryContractError::Missing {
                field: "cited.revision",
            });
        }
        if self.revision.len() > 256 {
            return Err(SelfQueryContractError::Bound {
                field: "cited.revision",
                maximum: 256,
                actual: self.revision.len(),
            });
        }
        if self.digest.len() != 64
            || !self
                .digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(SelfQueryContractError::InvalidDigest {
                field: "cited.digest",
            });
        }
        Ok(())
    }
}

/// Extract the source triples an owner input cites: its embedded snapshot,
/// when present, plus every anchor's source lineage.
#[must_use]
pub fn cited_sources(input: &SelfQueryInput) -> Vec<CitedSource> {
    let mut cited = Vec::new();
    if let Some(source) = &input.source {
        cited.push(CitedSource {
            handle: source.source_handle.clone(),
            revision: source.revision.clone(),
            digest: source.digest.clone(),
        });
    }
    for anchor in &input.anchors {
        cited.push(CitedSource {
            handle: anchor.source_handle.clone(),
            revision: anchor.revision.clone(),
            digest: anchor.source_digest.clone(),
        });
    }
    cited
}

/// Check cited triples against an accepted-source projection.
///
/// The projection itself is validated first; every triple must then match
/// a projected ref exactly (handle, revision, digest), otherwise the
/// citation is stale or uncited and the check fails closed.
pub fn check_citations(
    cited: &[CitedSource],
    sources: &AcceptedSourceProjection,
) -> Result<(), SelfQueryContractError> {
    sources.validate()?;
    for citation in cited {
        citation.validate()?;
        sources.check_cited(&citation.handle, &citation.revision, &citation.digest)?;
    }
    Ok(())
}

/// Pose a self-query over the existing owner input.
///
/// Runs the owner's `validate()` (job class, bundle/job/receipt/grounded
/// bindings, policy, denominator, preservation, question) and freezes the
/// owner's `input_digest()`. Any owner rejection fails the pose with the
/// owner's own error.
pub fn pose_self_query(
    input: &SelfQueryInput,
) -> Result<SelfQueryPoseReceipt, SelfQueryContractError> {
    input.validate()?;
    Ok(SelfQueryPoseReceipt {
        input_digest: input.input_digest()?,
        schema_version: input.schema_version,
    })
}

/// Pose a self-query with source citation.
///
/// Every source triple the input cites must resolve to a current projected
/// ref first; only then does the owner pose run. Stale or uncited sources
/// fail closed before any digest freezes.
pub fn pose_with_sources(
    input: &SelfQueryInput,
    sources: &AcceptedSourceProjection,
) -> Result<SelfQueryPoseReceipt, SelfQueryContractError> {
    check_citations(&cited_sources(input), sources)?;
    pose_self_query(input)
}
