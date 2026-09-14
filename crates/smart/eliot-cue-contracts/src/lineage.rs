//! Retrieval lineage: which owner references produced a retrieval, and nothing more.
//!
//! A lineage names the snapshot, the source denominator, the direct and derived
//! targets, the selected binding candidates and the external admission digests
//! behind one retrieval. It never claims delivery, visibility, use, adherence
//! or outcome: those belong to other owners and are not representable here, so
//! no such field exists on this shape.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{
    BindingCandidateId, CueContractError, Digest, SnapshotId, SourceHandle, TargetHandle, bounds,
};

#[derive(Serialize)]
struct LineagePreimage<'a> {
    schema_revision: &'a str,
    snapshot_id: &'a SnapshotId,
    source_denominator: Vec<&'a SourceHandle>,
    direct_targets: Vec<&'a TargetHandle>,
    derived_targets: Vec<&'a DerivedTarget>,
    selected_candidates: Vec<&'a BindingCandidateId>,
    admission_digests: Vec<&'a Digest>,
}

/// One relation-derived target behind a retrieval.
///
/// A distinct wrapper so a derived target can never be passed where a direct
/// target is expected: the two are different results and stay different here.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(transparent)]
#[schemars(transparent)]
pub struct DerivedTarget(TargetHandle);

impl DerivedTarget {
    /// Constructs a derived target reference.
    ///
    /// # Errors
    /// Rejects blank text, control characters and text over the bound.
    pub fn new(value: TargetHandle) -> Result<Self, CueContractError> {
        bounds::text(value.as_str(), "lineage.derived_targets")?;
        Ok(Self(value))
    }

    /// Returns the referenced target handle.
    #[must_use]
    pub fn as_handle(&self) -> &TargetHandle {
        &self.0
    }
}

/// Which owner references produced one retrieval.
///
/// Every field is a reference to a record owned elsewhere: the snapshot, its
/// sources, the matched targets, the selected candidates and the digests of the
/// external admission assertions. A lineage carries no payload bytes, no
/// delivery claim and no outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RetrievalLineage {
    /// Schema revision this record was written against.
    pub schema_revision: String,
    /// The snapshot the retrieval was evaluated against.
    pub snapshot_id: SnapshotId,
    /// The exact sources the retrieval covered.
    pub source_denominator: Vec<SourceHandle>,
    /// Direct comparison hits behind the retrieval.
    pub direct_targets: Vec<TargetHandle>,
    /// Relation-derived hits behind the retrieval.
    pub derived_targets: Vec<DerivedTarget>,
    /// Binding candidates selected for the retrieval.
    pub selected_candidates: Vec<BindingCandidateId>,
    /// Digests of the external admission assertions consulted.
    pub admission_digests: Vec<Digest>,
    /// Digest over every identity-bearing field above.
    pub digest: Digest,
}

impl RetrievalLineage {
    /// Seals a lineage: validates every reference, then binds the digest.
    ///
    /// # Errors
    /// Rejects any collection past its bound, any malformed reference, any
    /// duplicate reference, and anything the lower-level owners reject.
    pub fn seal(
        snapshot_id: SnapshotId,
        source_denominator: Vec<SourceHandle>,
        direct_targets: Vec<TargetHandle>,
        derived_targets: Vec<DerivedTarget>,
        selected_candidates: Vec<BindingCandidateId>,
        admission_digests: Vec<Digest>,
    ) -> Result<Self, CueContractError> {
        let mut value = Self {
            schema_revision: crate::CONTRACT_REVISION.to_owned(),
            snapshot_id,
            source_denominator,
            direct_targets,
            derived_targets,
            selected_candidates,
            admission_digests,
            digest: Digest::new("0".repeat(64))?,
        };
        value.validate_shape()?;
        value.digest = value.canonical_digest()?;
        Ok(value)
    }

    /// Returns the versioned canonical JSON preimage, excluding `digest`.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, CueContractError> {
        self.validate_shape()?;
        let mut sources: Vec<_> = self.source_denominator.iter().collect();
        sources.sort_by(|left, right| {
            left.target
                .cmp(&right.target)
                .then(left.digest.cmp(&right.digest))
        });
        let mut direct: Vec<_> = self.direct_targets.iter().collect();
        direct.sort();
        let mut derived: Vec<_> = self.derived_targets.iter().collect();
        derived.sort();
        let mut candidates: Vec<_> = self.selected_candidates.iter().collect();
        candidates.sort();
        let mut admissions: Vec<_> = self.admission_digests.iter().collect();
        admissions.sort();
        let preimage = LineagePreimage {
            schema_revision: &self.schema_revision,
            snapshot_id: &self.snapshot_id,
            source_denominator: sources,
            direct_targets: direct,
            derived_targets: derived,
            selected_candidates: candidates,
            admission_digests: admissions,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&preimage).map_err(|_| {
            CueContractError::Foundation {
                field: "lineage.canonical_payload",
            }
        })?;
        let mut total = 0;
        bounds::bytes(&mut total, bytes.len(), "lineage.canonical_payload")?;
        Ok(bytes)
    }

    /// Computes this lineage's canonical digest.
    pub fn canonical_digest(&self) -> Result<Digest, CueContractError> {
        let bytes = self.canonical_payload_bytes()?;
        Digest::new(eliot_contracts::sha256_hex(&bytes))
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects an unsupported revision, any collection past its bound, any
    /// duplicate reference, and a digest that does not match the recorded
    /// references.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.validate_shape()?;
        if self.digest != self.canonical_digest()? {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), CueContractError> {
        if !crate::is_supported_schema_revision(&self.schema_revision) {
            return Err(CueContractError::InvalidText {
                field: "schema_revision",
            });
        }
        bounds::collection(
            &self.source_denominator,
            crate::MAX_SNAPSHOT_MEMBERS,
            "lineage.source_denominator",
        )?;
        bounds::collection(
            &self.direct_targets,
            crate::MAX_DIRECT,
            "lineage.direct_targets",
        )?;
        bounds::collection(
            &self.derived_targets,
            crate::MAX_DERIVED,
            "lineage.derived_targets",
        )?;
        bounds::collection(
            &self.selected_candidates,
            crate::MAX_LINEAGE_SELECTIONS,
            "lineage.selected_candidates",
        )?;
        bounds::collection(
            &self.admission_digests,
            crate::MAX_LINEAGE_SELECTIONS,
            "lineage.admission_digests",
        )?;
        let mut seen_sources = BTreeSet::new();
        for source in &self.source_denominator {
            source.validate()?;
            if !seen_sources.insert((source.target.clone(), source.digest.clone())) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "lineage.source_denominator",
                });
            }
        }
        let mut seen_direct = BTreeSet::new();
        for target in &self.direct_targets {
            bounds::text(target.as_str(), "lineage.direct_targets")?;
            if !seen_direct.insert(target.clone()) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "lineage.direct_targets",
                });
            }
        }
        let mut seen_derived = BTreeSet::new();
        for target in &self.derived_targets {
            bounds::text(target.as_handle().as_str(), "lineage.derived_targets")?;
            if !seen_derived.insert(target.clone()) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "lineage.derived_targets",
                });
            }
        }
        let mut seen_candidates = BTreeSet::new();
        for candidate in &self.selected_candidates {
            bounds::text(candidate.as_str(), "lineage.selected_candidates")?;
            if !seen_candidates.insert(candidate.clone()) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "lineage.selected_candidates",
                });
            }
        }
        let mut seen_admissions = BTreeSet::new();
        for digest in &self.admission_digests {
            if digest.as_str().len() != 64 {
                return Err(CueContractError::InvalidText {
                    field: "lineage.admission_digests",
                });
            }
            if !seen_admissions.insert(digest.clone()) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "lineage.admission_digests",
                });
            }
        }
        Ok(())
    }
}
