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
pub const FREEZE_ID: &str = "cognitive-rev12-contract-schema-freeze-2026-09-22-r6";
/// Owner contract this adapter poses over.
pub const OWNER_CONTRACT: &str = "eliot.smart.dreamer.contracts";

/// A posed self-query: the owner's input digest, its schema pin, and the
/// source citations verified at pose time.
///
/// The digest identifies the exact validated input closure the brief
/// projectors consume; it proves no admission or source authority beyond
/// what the owner's own `validate()` established. The retained citations
/// preserve which sources were checked; they authorize nothing by
/// themselves. A receipt is not durable proof until revalidated with
/// [`revalidate`] against the live input and projection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SelfQueryPoseReceipt {
    /// Owner's canonical digest over the complete input closure.
    pub input_digest: String,
    /// Input schema version the digest was frozen against; always 1.
    pub schema_version: u32,
    /// Source citations verified at pose time, in input order.
    pub cited: Vec<CitedSource>,
}

impl SelfQueryPoseReceipt {
    /// Validate the receipt: exact schema version, digest shape, and every
    /// retained citation shape. Citation currency itself is rechecked only
    /// by [`revalidate`], never inferred from this shape.
    pub fn validate(&self) -> Result<(), SelfQueryContractError> {
        // Closed schema pin: the pose constructor echoes only the validated
        // input's schema version, and the owner self-query schema is 1.
        if self.schema_version != 1 {
            return Err(SelfQueryContractError::UnsupportedVersion {
                field: "receipt.schema_version",
                expected: 1,
                actual: self.schema_version,
            });
        }
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
        // Sanity ceiling above any constructible input (owner bounds
        // anchors plus one embedded snapshot); wire values beyond it are
        // rejected before per-citation checks.
        if self.cited.len() > 8192 {
            return Err(SelfQueryContractError::Bound {
                field: "receipt.cited",
                maximum: 8192,
                actual: self.cited.len(),
            });
        }
        for citation in &self.cited {
            citation.validate()?;
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
        cited: Vec::new(),
    })
}

/// Pose a self-query with source citation.
///
/// Every source triple the input cites must resolve to a current projected
/// ref first; the input snapshot lineage, when present, must join the
/// projection pair edition; and the projection fence must be compatible
/// with the input's governing job fence. Only then does the owner pose
/// run, and the verified citations are retained in the receipt. Stale or
/// uncited sources, lineage drift, or a drifted projection fence fail
/// closed before any digest freezes.
pub fn pose_with_sources(
    input: &SelfQueryInput,
    sources: &AcceptedSourceProjection,
) -> Result<SelfQueryPoseReceipt, SelfQueryContractError> {
    let cited = cited_sources(input);
    check_citations(&cited, sources)?;
    if let Some(snapshot) = &input.source {
        // Input-source lineage join: the cited snapshot must live under the
        // same pair edition, acceptor, and acceptance receipt as the
        // projection. Anchors carry no pair info, so snapshot-less inputs
        // bind only through their cited triples.
        if snapshot.pair != sources.pair {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "cited.source_pair",
            });
        }
        if snapshot.owner != sources.pair.accepted_by {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "cited.source_owner",
            });
        }
        if snapshot.acceptance_receipt.as_ref() != Some(&sources.pair.acceptance_receipt) {
            return Err(SelfQueryContractError::BindingMismatch {
                field: "cited.acceptance_receipt",
            });
        }
    }
    if !sources
        .fence
        .is_compatible_with(&input.validated_candidate.job.state_fence)
    {
        return Err(SelfQueryContractError::BindingMismatch {
            field: "cited.projection_fence",
        });
    }
    let mut receipt = pose_self_query(input)?;
    receipt.cited = cited;
    receipt.validate()?;
    Ok(receipt)
}

/// Revalidate a retained receipt against live input and projection.
///
/// Re-runs receipt shape, citation currency, lineage join, fence binding,
/// and the owner pose, then requires the fresh digest and citations to
/// equal the retained ones. Consumers run this before treating any receipt
/// as durable proof; an unvalidated receipt is advisory only.
pub fn revalidate(
    receipt: &SelfQueryPoseReceipt,
    input: &SelfQueryInput,
    sources: &AcceptedSourceProjection,
) -> Result<(), SelfQueryContractError> {
    receipt.validate()?;
    let fresh = pose_with_sources(input, sources)?;
    if fresh != *receipt {
        return Err(SelfQueryContractError::BindingMismatch {
            field: "receipt.revalidation",
        });
    }
    Ok(())
}
