//! Canonical identity, comparison keys, and the record of how they were derived.
//!
//! The central rule of this module is that a canonical identity and a comparison
//! key are different things. Canonical identity preserves the spelling that
//! carries meaning; a comparison key is a policy-folded form used for lookup. A
//! schema that lets one lowercase string serve both roles loses the distinction
//! the first time a symbol differs from its own path only by case.
//!
//! The transformation algorithm belongs to A-11. This module records its result.

use serde::{Deserialize, Serialize};

use crate::{
    CanonicalCueId, ComparisonKeyId, CueContractError, Digest, MAX_COMPARISON_KEYS,
    MAX_TRANSFORMATION_STEPS, ObservedCue, bound,
};

/// What a cue points at.
///
/// This cell is the Level-0 owner of the cue vocabulary — its `module.toml`
/// records `depends_on = []` — so the kind is defined here rather than imported.
/// `crates/eliot-types/src/ul/cue.rs` carries a parallel definition for the
/// shipped path; reconciling the two is unit F-CUE, and it is a contract change,
/// not something this cell may take unilaterally.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum CueKind {
    /// A path to a file.
    FilePath,
    /// A path to a directory.
    DirPath,
    /// A named symbol in source.
    Symbol,
    /// A diagnostic or error signature.
    ErrorSignature,
    /// A command invocation pattern.
    CommandPattern,
    /// A dependency identity.
    Dependency,
    /// A public API surface.
    ApiSurface,
    /// A class of task.
    TaskClass,
    /// A named subsystem.
    Subsystem,
    /// A concept name.
    Concept,
}

/// How a comparison key is matched.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum MatchMode {
    /// Byte-for-byte equality.
    Exact,
    /// ASCII case-insensitive equality.
    CaseInsensitive,
    /// Path separators and case folded per the path policy.
    PathNormalized,
    /// Symbol compared with its qualifying scope.
    SymbolQualified,
}

/// The versioned policy a normalization was performed under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NormalizationProfile {
    /// Stable profile name.
    pub profile_id: String,
    /// Profile revision. A change here invalidates snapshots built under it.
    pub profile_revision: u32,
    /// Digest of the profile definition.
    pub digest: Digest,
}

impl NormalizationProfile {
    /// Constructs a normalization profile reference.
    #[must_use]
    pub const fn new(profile_id: String, profile_revision: u32, digest: Digest) -> Self {
        Self {
            profile_id,
            profile_revision,
            digest,
        }
    }
}

/// One step a normalizer applied, in order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct TransformationStep {
    /// What the step did, as a stable label.
    pub step: String,
    /// The value after the step.
    pub result: String,
}

impl TransformationStep {
    /// Constructs one recorded transformation step.
    #[must_use]
    pub const fn new(step: String, result: String) -> Self {
        Self { step, result }
    }
}

/// The canonical identity of a cue.
///
/// Preserves the spelling that carries meaning. This is never a comparison key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CanonicalCueIdentity {
    /// Identity of this canonical cue.
    pub canonical_cue_id: CanonicalCueId,
    /// What kind of cue it is.
    pub kind: CueKind,
    /// Canonical value with meaningful case and separators preserved.
    pub canonical_value: String,
    /// Digest over kind, canonical value and profile.
    pub digest: Digest,
}

impl CanonicalCueIdentity {
    /// Constructs a canonical cue identity.
    #[must_use]
    pub const fn new(
        canonical_cue_id: CanonicalCueId,
        kind: CueKind,
        canonical_value: String,
        digest: Digest,
    ) -> Self {
        Self {
            canonical_cue_id,
            kind,
            canonical_value,
            digest,
        }
    }
}

/// One bounded comparison key derived from a canonical identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ComparisonKey {
    /// Identity of this key.
    pub comparison_key_id: ComparisonKeyId,
    /// The profile that produced it.
    pub profile: NormalizationProfile,
    /// The folded value used for lookup.
    pub key_value: String,
    /// How this key is matched.
    pub match_mode: MatchMode,
}

impl ComparisonKey {
    /// Constructs a comparison key.
    #[must_use]
    pub const fn new(
        comparison_key_id: ComparisonKeyId,
        profile: NormalizationProfile,
        key_value: String,
        match_mode: MatchMode,
    ) -> Self {
        Self {
            comparison_key_id,
            profile,
            key_value,
            match_mode,
        }
    }
}

/// Whether normalization preserved meaning, and if not, why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum NormalizationOutcome {
    /// Nothing meaningful was discarded.
    Lossless,
    /// Something was discarded under a named policy that permits it.
    AuthorizedLoss {
        /// The policy that authorized the loss.
        policy_ref: String,
    },
    /// The input maps to more than one canonical identity.
    Ambiguous {
        /// The competing identities, preserved rather than resolved here.
        rivals: Vec<CanonicalCueIdentity>,
    },
    /// The input is outside what this profile can normalize.
    Unsupported {
        /// Why it is unsupported.
        reason: String,
    },
}

/// An observed cue together with its canonical identity and comparison keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct NormalizedCue {
    /// Schema revision this record was written against.
    pub schema_revision: String,
    /// The observation this was derived from, kept intact.
    pub observed: ObservedCue,
    /// The canonical identity.
    pub canonical: CanonicalCueIdentity,
    /// Bounded comparison keys. May be empty when the outcome is unsupported.
    pub comparison_keys: Vec<ComparisonKey>,
    /// Whether meaning was preserved.
    pub outcome: NormalizationOutcome,
    /// The ordered steps that produced the canonical value.
    pub transformation_evidence: Vec<TransformationStep>,
}

impl NormalizedCue {
    /// Constructs a normalized cue. Call [`Self::validate`] before use.
    #[must_use]
    pub const fn new(
        schema_revision: String,
        observed: ObservedCue,
        canonical: CanonicalCueIdentity,
        comparison_keys: Vec<ComparisonKey>,
        outcome: NormalizationOutcome,
        transformation_evidence: Vec<TransformationStep>,
    ) -> Self {
        Self {
            schema_revision,
            observed,
            canonical,
            comparison_keys,
            outcome,
            transformation_evidence,
        }
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects a canonical value reused verbatim as its own comparison key, a
    /// duplicate key identity, and any collection past its bound.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.observed.validate()?;
        bound(
            &self.comparison_keys,
            MAX_COMPARISON_KEYS,
            "comparison_keys",
        )?;
        bound(
            &self.transformation_evidence,
            MAX_TRANSFORMATION_STEPS,
            "transformation_evidence",
        )?;

        let mut seen = Vec::with_capacity(self.comparison_keys.len());
        for key in &self.comparison_keys {
            if seen.contains(&&key.comparison_key_id) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "comparison_keys",
                });
            }
            seen.push(&key.comparison_key_id);

            // An `Exact` key that is byte-identical to the canonical value has
            // collapsed the two roles: lookup would then depend on the spelling
            // the canonical form exists to preserve.
            if key.match_mode == MatchMode::Exact
                && key.key_value == self.canonical.canonical_value
                && self.comparison_keys.len() == 1
            {
                return Err(CueContractError::IdentityCollapsedIntoKey);
            }
        }
        Ok(())
    }
}
