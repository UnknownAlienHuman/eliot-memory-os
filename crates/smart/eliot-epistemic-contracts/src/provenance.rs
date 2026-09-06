//! Provenance closure: every handle behind a position, nothing invented.
//!
//! A [`ProvenanceClosure`] carries record handles, typed sources, raw handles, revisions, per-source
//! [`SourceLineage`] entries (with cycle rejection), assertability, scope, and fence. The untyped sets must
//! equal exactly the union over the lineage entries.
use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, SourceId, StateFence};
use eliot_evidence::Assertability;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, check_frozen, shape_digest, validate_bounded_text,
    validate_digest,
};
use crate::identity::SourceRevisionId;

/// One source's lineage inside a closure: owner, revision, content digest,
/// raw handle, and predecessor digests within the same bundle.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct SourceLineage {
    /// Source that produced this slice of the closure.
    pub owner: SourceId,
    /// Source revision this slice was read under.
    pub revision: String,
    /// Digest of the frozen content this slice covers.
    pub content_digest: String,
    /// Raw handle the slice was derived from, when retained.
    pub raw_handle: Option<String>,
    /// Content digests of predecessors within the same bundle.
    pub predecessors: BTreeSet<String>,
    /// Raw-to-derived mapping note, when this slice transforms raw input.
    pub derived_from_raw: Option<String>,
}
impl SourceLineage {
    pub fn new(
        owner: SourceId,
        revision: SourceRevisionId,
        content_digest: impl Into<String>,
        raw_handle: Option<String>,
        predecessors: BTreeSet<String>,
        derived_from_raw: Option<String>,
    ) -> Result<Self, ContractError> {
        let entry = Self {
            owner,
            revision: revision.into_string(),
            content_digest: content_digest.into(),
            raw_handle,
            predecessors,
            derived_from_raw,
        };
        entry.validate()?;
        Ok(entry)
    }
    /// Validates revision, digests, handles, and predecessor form (acyclicity lives in the closure).
    pub fn validate(&self) -> Result<(), ContractError> {
        validate_bounded_text(&self.revision, "provenance.revision", MAX_SHORT_TEXT)?;
        validate_digest(&self.content_digest, "provenance.content_digest")?;
        if let Some(raw) = &self.raw_handle {
            validate_bounded_text(raw.as_str(), "provenance.raw_handle", MAX_SHORT_TEXT)?;
        }
        if self.predecessors.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "provenance.predecessors",
            });
        }
        for predecessor in &self.predecessors {
            validate_digest(predecessor.as_str(), "provenance.predecessors")?;
        }
        if self.predecessors.contains(&self.content_digest) {
            return Err(ContractError::SelfReference {
                field: "provenance.predecessors",
            });
        }
        if let Some(note) = &self.derived_from_raw {
            validate_bounded_text(note.as_str(), "provenance.derived_from_raw", MAX_SHORT_TEXT)?;
            if self.raw_handle.is_none() {
                return Err(ContractError::MissingReference {
                    field: "provenance.raw_handle",
                });
            }
        }
        Ok(())
    }
}

/// Checks that predecessor edges over content digests are acyclic.
fn check_acyclic(entries: &[SourceLineage]) -> Result<(), ContractError> {
    let mut edges: BTreeMap<&str, &BTreeSet<String>> = BTreeMap::new();
    for entry in entries {
        edges.insert(entry.content_digest.as_str(), &entry.predecessors);
    }
    for entry in entries {
        let mut stack: Vec<&str> = entry.predecessors.iter().map(String::as_str).collect();
        let mut seen = BTreeSet::new();
        while let Some(next) = stack.pop() {
            if next == entry.content_digest.as_str() {
                return Err(ContractError::ImpossibleCombination {
                    field: "provenance.predecessors",
                });
            }
            if seen.insert(next) {
                // Unknown predecessors are foreign handles, not cycles: the
                // association check below rejects them; traversal skips them.
                if let Some(further) = edges.get(next) {
                    stack.extend(further.iter().map(String::as_str));
                }
            }
        }
    }
    Ok(())
}
// Donor disposition (`crates/smart/eliot-epistemic/src/lib.rs`): the donor `ProvenanceView` is subsumed here.
// Vectors become sets (`records`, typed `sources`, `raw_handles`, `revisions`); `mixed_sources` is derived and
// checked; `scope`, `fence`, and `digest` close the shape; `lowest_assertability` is resolver policy, not carried.

/// Marker proving a document is a provenance closure and never a view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ProvenanceClosureKind {
    /// The single admitted spelling of a provenance closure.
    #[serde(rename = "PROVENANCE_CLOSURE")]
    #[schemars(rename = "PROVENANCE_CLOSURE")]
    ProvenanceClosure,
}

/// The exact, frozen provenance closure of one position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceClosure {
    /// Marker binding this document to the closure decoding.
    pub closure_kind: ProvenanceClosureKind,
    /// Every record consulted; order carries no meaning. Each maps to its lineage entry below.
    pub records: BTreeSet<ArtifactId>,
    /// Every source consulted, typed; order carries no meaning. Must equal
    /// exactly the owners named by `lineage`.
    pub sources: BTreeSet<SourceId>,
    /// Every raw handle consulted; order carries no meaning. Must equal
    /// exactly the raw handles named by `lineage`.
    pub raw_handles: BTreeSet<String>,
    /// Every revision consulted; order carries no meaning. Must equal exactly
    /// the revisions named by `lineage`.
    pub revisions: BTreeSet<String>,
    /// Per-source lineage binding every owner to its revision, content
    /// digest, raw handle, and predecessors, in declaration order.
    pub lineage: Vec<SourceLineage>,
    /// Relational closure: every record handle maps to the content digest of its concrete lineage entry.
    /// Set unions matching is insufficient; a foreign handle fails here even when the unions match.
    pub record_origin: BTreeMap<ArtifactId, String>,
    /// Digest of the applicable temporal record, when the closure carries one.
    pub temporal_digest: Option<String>,
    /// Whether more than one source was consulted; derived, never asserted.
    pub mixed_sources: bool,
    /// Weakest assertability across the closure, supplied by the resolver.
    pub assertability: Assertability,
    /// Scope the closure was frozen under.
    pub scope: String,
    /// Fence the closure was frozen under.
    pub fence: StateFence,
    /// Canonical digest of the closure shape, excluding this field.
    pub digest: String,
}
/// Named constructor arguments for [`ProvenanceClosure::new`].
/// Named fields block transposition; text uses concrete [`String`].
#[derive(Clone, Debug)]
pub struct ProvenanceClosureParams {
    pub records: BTreeSet<ArtifactId>,
    pub sources: BTreeSet<SourceId>,
    pub raw_handles: BTreeSet<String>,
    pub revisions: BTreeSet<String>,
    pub lineage: Vec<SourceLineage>,
    pub record_origin: BTreeMap<ArtifactId, String>,
    pub temporal_digest: Option<String>,
    pub mixed_sources: bool,
    pub assertability: Assertability,
    pub scope: String,
    pub fence: StateFence,
}
impl ProvenanceClosure {
    pub fn new(params: ProvenanceClosureParams) -> Result<Self, ContractError> {
        let mut closure = Self {
            closure_kind: ProvenanceClosureKind::ProvenanceClosure,
            records: params.records,
            sources: params.sources,
            raw_handles: params.raw_handles,
            revisions: params.revisions,
            lineage: params.lineage,
            record_origin: params.record_origin,
            temporal_digest: params.temporal_digest,
            mixed_sources: params.mixed_sources,
            assertability: params.assertability,
            scope: params.scope,
            fence: params.fence,
            digest: String::new(),
        };
        closure.validate_shape()?;
        closure.digest = closure.compute_digest()?;
        Ok(closure)
    }
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.closure_kind,
            &self.records,
            &self.sources,
            &self.raw_handles,
            &self.revisions,
            &self.lineage,
            &self.record_origin,
            &self.temporal_digest,
            &self.mixed_sources,
            &self.assertability,
            &self.scope,
            &self.fence,
        ))
    }
    fn validate_shape(&self) -> Result<(), ContractError> {
        self.check_handle_bounds()?;
        self.check_lineage()?;
        self.check_derived()?;
        Ok(())
    }
    fn check_handle_bounds(&self) -> Result<(), ContractError> {
        if self.closure_kind != ProvenanceClosureKind::ProvenanceClosure {
            return Err(ContractError::ImpossibleCombination {
                field: "provenance.closure_kind",
            });
        }
        if self.records.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "provenance.records",
            });
        }
        if self.records.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "provenance.records",
            });
        }
        if self.sources.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "provenance.sources",
            });
        }
        if self.sources.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "provenance.sources",
            });
        }
        if self.raw_handles.len() > MAX_HANDLES || self.revisions.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "provenance.handles",
            });
        }
        for handle in self.raw_handles.iter().chain(self.revisions.iter()) {
            validate_bounded_text(handle.as_str(), "provenance.handles", MAX_SHORT_TEXT)?;
        }
        if self.lineage.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "provenance.lineage",
            });
        }
        if self.lineage.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "provenance.lineage",
            });
        }
        Ok(())
    }
    fn check_lineage(&self) -> Result<(), ContractError> {
        let mut seen_content = BTreeSet::new();
        let mut lineage_sources = BTreeSet::new();
        let mut lineage_raw = BTreeSet::new();
        let mut lineage_revisions = BTreeSet::new();
        let mut lineage_digests = BTreeSet::new();
        for entry in &self.lineage {
            entry.validate()?;
            if !seen_content.insert(entry.content_digest.clone()) {
                return Err(ContractError::Duplicate {
                    field: "provenance.lineage",
                });
            }
            lineage_sources.insert(entry.owner.clone());
            if let Some(raw) = &entry.raw_handle {
                lineage_raw.insert(raw.clone());
            }
            lineage_revisions.insert(entry.revision.clone());
            lineage_digests.insert(entry.content_digest.clone());
        }
        for entry in &self.lineage {
            for predecessor in &entry.predecessors {
                if !lineage_digests.contains(predecessor) {
                    return Err(ContractError::MissingReference {
                        field: "provenance.predecessors",
                    });
                }
            }
        }
        check_acyclic(&self.lineage)?;
        // Exact association: the untyped sets are exactly the union over the lineage entries.
        if lineage_sources != self.sources {
            return Err(ContractError::OutsideManifest {
                field: "provenance.sources",
            });
        }
        if lineage_raw != self.raw_handles {
            return Err(ContractError::OutsideManifest {
                field: "provenance.raw_handles",
            });
        }
        if lineage_revisions != self.revisions {
            return Err(ContractError::OutsideManifest {
                field: "provenance.revisions",
            });
        }
        // Relational closure: every record maps to a concrete lineage entry, and nothing else does.
        let field = "provenance.record_origin";
        for (handle, digest) in &self.record_origin {
            if !self.records.contains(handle) {
                return Err(ContractError::OutsideManifest { field });
            }
            if !lineage_digests.contains(digest) {
                return Err(ContractError::MissingReference { field });
            }
        }
        for handle in &self.records {
            if !self.record_origin.contains_key(handle) {
                return Err(ContractError::MissingReference { field });
            }
        }
        Ok(())
    }
    fn check_derived(&self) -> Result<(), ContractError> {
        if let Some(temporal) = &self.temporal_digest {
            validate_digest(temporal.as_str(), "provenance.temporal_digest")?;
        }
        if self.mixed_sources != (self.sources.len() > 1) {
            return Err(ContractError::ImpossibleCombination {
                field: "provenance.mixed_sources",
            });
        }
        validate_bounded_text(&self.scope, "provenance.scope", MAX_SHORT_TEXT)?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "provenance.fence",
            })?;
        Ok(())
    }
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        check_frozen(&self.digest, &self.compute_digest()?, "provenance.digest")
    }
}
