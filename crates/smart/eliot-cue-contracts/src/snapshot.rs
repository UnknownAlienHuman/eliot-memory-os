//! Immutable, rebuildable snapshot membership.
//!
//! `I12.7` requires a snapshot to be rebuildable. That is only checkable if the
//! snapshot carries the inputs it was built from, so `RebuildIdentity` is part
//! of the record rather than something a caller is trusted to remember.

use eliot_contracts::StateFence;
use serde::{Deserialize, Serialize};

use crate::{
    CanonicalCueIdentity, CueContractError, Digest, MAX_SNAPSHOT_MEMBERS, NormalizationProfile,
    SnapshotId, SourceHandle, TargetHandle, bound,
};

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

    /// Recomputes the rebuild digest from the recorded inputs and members.
    ///
    /// The computation is deliberately simple and dependency-free: this cell
    /// owns the *shape* of rebuildability, not a hashing policy. A-13 supplies
    /// the real digest; this reproduces the same inputs in the same order so a
    /// mismatch is detectable here.
    #[must_use]
    pub fn recompute_digest_input(&self) -> String {
        let mut parts = String::new();
        parts.push_str(&self.rebuild.normalization_profile.profile_id);
        parts.push('\u{1f}');
        parts.push_str(
            &self
                .rebuild
                .normalization_profile
                .profile_revision
                .to_string(),
        );
        for source in &self.rebuild.source_denominator {
            parts.push('\u{1e}');
            parts.push_str(source.digest.as_str());
        }
        for member in &self.members {
            parts.push('\u{1d}');
            parts.push_str(member.canonical.digest.as_str());
            parts.push('\u{1f}');
            parts.push_str(member.target.as_str());
        }
        parts
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects a member set past its bound, a duplicate membership, and a
    /// rebuild record whose digest does not match its own inputs.
    pub fn validate(
        &self,
        expected_digest_of: &dyn Fn(&str) -> String,
    ) -> Result<(), CueContractError> {
        bound(&self.members, MAX_SNAPSHOT_MEMBERS, "members")?;

        let mut seen: Vec<(&str, &str)> = Vec::with_capacity(self.members.len());
        for member in &self.members {
            let key = (
                member.canonical.canonical_cue_id.as_str(),
                member.target.as_str(),
            );
            if seen.contains(&key) {
                return Err(CueContractError::DuplicateIdentity { field: "members" });
            }
            seen.push(key);
        }

        let recomputed = expected_digest_of(&self.recompute_digest_input());
        if recomputed != self.rebuild.digest.as_str() {
            return Err(CueContractError::SnapshotNotRebuildable);
        }
        Ok(())
    }
}
