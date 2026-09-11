//! Immutable, rebuildable snapshot membership.
//!
//! `I12.7` requires a snapshot to be rebuildable. That is only checkable if the
//! snapshot carries the inputs it was built from, so `RebuildIdentity` is part
//! of the record rather than something a caller is trusted to remember.

use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::{
    CanonicalCueIdentity, CueContractError, Digest, MAX_SNAPSHOT_MEMBERS, NormalizationProfile,
    SnapshotId, SourceHandle, TargetHandle, bounds,
};

#[derive(Serialize)]
struct SnapshotPreimage<'a> {
    schema_revision: &'a str,
    snapshot_id: &'a SnapshotId,
    state_fence: &'a StateFence,
    normalization_profile: &'a NormalizationProfile,
    source_denominator: Vec<&'a SourceHandle>,
    members: Vec<&'a SnapshotMember>,
}

/// One admitted cue-to-target pair inside a snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SnapshotMember {
    /// The canonical cue.
    pub canonical: CanonicalCueIdentity,
    /// The bound target.
    pub target: TargetHandle,
}

impl SnapshotMember {
    /// Constructs one snapshot membership.
    #[must_use]
    pub const fn new(canonical: CanonicalCueIdentity, target: TargetHandle) -> Self {
        Self { canonical, target }
    }

    /// Validates the nested canonical identity and target handle.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.canonical.validate()?;
        bounds::text(self.target.as_str(), "member.target")
    }
}

/// Everything needed to rebuild a snapshot and check that it matches.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RebuildIdentity {
    /// The normalization profile every member was folded under.
    pub normalization_profile: NormalizationProfile,
    /// The exact sources the snapshot was built from. This is the denominator:
    /// a coverage claim about the snapshot is measured against it.
    pub source_denominator: Vec<SourceHandle>,
    /// Digest over the profile, the denominator and the member set.
    pub digest: Digest,
}

impl RebuildIdentity {
    /// Constructs a rebuild identity.
    #[must_use]
    pub const fn new(
        normalization_profile: NormalizationProfile,
        source_denominator: Vec<SourceHandle>,
        digest: Digest,
    ) -> Self {
        Self {
            normalization_profile,
            source_denominator,
            digest,
        }
    }
}

/// An immutable set of admitted cue-to-target memberships.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CueSnapshot {
    /// Schema revision this record was written against.
    pub schema_revision: String,
    /// Identity of this snapshot.
    pub snapshot_id: SnapshotId,
    /// The admitted memberships.
    pub members: Vec<SnapshotMember>,
    /// The inputs that make the snapshot reconstructible.
    pub rebuild: RebuildIdentity,
    /// The causal snapshot this was built against.
    pub state_fence: StateFence,
}

impl CueSnapshot {
    /// Constructs a snapshot. Call [`Self::validate`] before use.
    #[must_use]
    pub const fn new(
        schema_revision: String,
        snapshot_id: SnapshotId,
        members: Vec<SnapshotMember>,
        rebuild: RebuildIdentity,
        state_fence: StateFence,
    ) -> Self {
        Self {
            schema_revision,
            snapshot_id,
            members,
            rebuild,
            state_fence,
        }
    }

    /// Returns the versioned canonical JSON preimage, excluding `digest`.
    pub fn canonical_payload_bytes(&self) -> Result<Vec<u8>, CueContractError> {
        self.validate_shape()?;
        let mut sources: Vec<_> = self.rebuild.source_denominator.iter().collect();
        sources.sort_by(|left, right| {
            left.target
                .cmp(&right.target)
                .then(left.digest.cmp(&right.digest))
        });
        let mut members: Vec<_> = self.members.iter().collect();
        members.sort_by(|left, right| {
            left.canonical
                .canonical_cue_id
                .cmp(&right.canonical.canonical_cue_id)
                .then(left.target.cmp(&right.target))
        });
        let preimage = SnapshotPreimage {
            schema_revision: &self.schema_revision,
            snapshot_id: &self.snapshot_id,
            state_fence: &self.state_fence,
            normalization_profile: &self.rebuild.normalization_profile,
            source_denominator: sources,
            members,
        };
        let bytes = eliot_contracts::canonical_json_bytes(&preimage).map_err(|_| {
            CueContractError::Foundation {
                field: "snapshot.canonical_payload",
            }
        })?;
        let mut total = 0;
        bounds::bytes(&mut total, bytes.len(), "snapshot.canonical_payload")?;
        Ok(bytes)
    }

    /// Computes this snapshot's canonical rebuild digest.
    pub fn canonical_digest(&self) -> Result<Digest, CueContractError> {
        let bytes = self.canonical_payload_bytes()?;
        Digest::new(eliot_contracts::sha256_hex(&bytes))
    }

    /// Compatibility name for callers that need the canonical digest input.
    pub fn recompute_digest_input(&self) -> Result<Vec<u8>, CueContractError> {
        self.canonical_payload_bytes()
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects a member set past its bound, a duplicate membership, and a
    /// rebuild record whose digest does not match its own inputs.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.validate_shape()?;
        if self.rebuild.digest != self.canonical_digest()? {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), CueContractError> {
        bounds::collection(
            &self.rebuild.source_denominator,
            MAX_SNAPSHOT_MEMBERS,
            "source_denominator",
        )?;
        bounds::collection(&self.members, MAX_SNAPSHOT_MEMBERS, "members")?;
        self.validate_payload_budget()?;
        if self.schema_revision != crate::CONTRACT_REVISION {
            return Err(CueContractError::InvalidText {
                field: "schema_revision",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| CueContractError::Foundation {
                field: "snapshot.state_fence",
            })?;
        self.rebuild.normalization_profile.validate()?;
        for source in &self.rebuild.source_denominator {
            source.validate()?;
        }
        let mut seen = BTreeSet::new();
        let mut source_seen = BTreeSet::new();
        for source in &self.rebuild.source_denominator {
            if !source_seen.insert((source.target.clone(), source.digest.clone())) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "source_denominator",
                });
            }
        }
        for member in &self.members {
            member.validate()?;
            let key = (
                member.canonical.canonical_cue_id.clone(),
                member.target.clone(),
            );
            if !seen.insert(key) {
                return Err(CueContractError::DuplicateIdentity { field: "members" });
            }
        }
        Ok(())
    }

    fn validate_payload_budget(&self) -> Result<(), CueContractError> {
        let mut measured_bytes = 0;
        bounds::bytes(
            &mut measured_bytes,
            self.schema_revision.len(),
            "snapshot.schema_revision",
        )?;
        bounds::bytes(
            &mut measured_bytes,
            self.snapshot_id.as_str().len(),
            "snapshot.snapshot_id",
        )?;
        bounds::bytes(
            &mut measured_bytes,
            self.rebuild.normalization_profile.profile_id.len(),
            "snapshot.profile_id",
        )?;
        bounds::bytes(
            &mut measured_bytes,
            self.rebuild.normalization_profile.digest.as_str().len(),
            "snapshot.profile_digest",
        )?;
        bounds::bytes(
            &mut measured_bytes,
            self.rebuild.digest.as_str().len(),
            "snapshot.rebuild_digest",
        )?;
        bounds::bytes(
            &mut measured_bytes,
            self.rebuild.source_denominator.len(),
            "snapshot.source_denominator",
        )?;
        bounds::bytes(&mut measured_bytes, self.members.len(), "snapshot.members")?;
        for source in &self.rebuild.source_denominator {
            bounds::bytes(
                &mut measured_bytes,
                source.target.as_str().len(),
                "snapshot.source.target",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                source.digest.as_str().len(),
                "snapshot.source.digest",
            )?;
            bounds::bytes(&mut measured_bytes, 64, "snapshot.source.structure")?;
            bounds::bytes(
                &mut measured_bytes,
                source.provenance.source_id.as_str().len(),
                "snapshot.source.source_id",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                source.provenance.capture_route.len(),
                "snapshot.source.route",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                source.provenance.scope.len(),
                "snapshot.source.scope",
            )?;
            if let Some(raw_handle) = source.provenance.raw_handle.as_deref() {
                bounds::bytes(
                    &mut measured_bytes,
                    raw_handle.len(),
                    "snapshot.source.raw_handle",
                )?;
            }
            if let Some(revision) = source.provenance.revision.as_deref() {
                bounds::bytes(
                    &mut measured_bytes,
                    revision.len(),
                    "snapshot.source.revision",
                )?;
            }
        }
        for member in &self.members {
            bounds::bytes(
                &mut measured_bytes,
                member.canonical.canonical_cue_id.as_str().len(),
                "snapshot.member.canonical_id",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                member.canonical.canonical_value.len(),
                "snapshot.member.canonical_value",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                member.target.as_str().len(),
                "snapshot.member.target",
            )?;
            bounds::bytes(
                &mut measured_bytes,
                member.canonical.digest.as_str().len(),
                "snapshot.member.canonical_digest",
            )?;
            bounds::bytes(&mut measured_bytes, 64, "snapshot.member.structure")?;
        }
        Ok(())
    }
}
