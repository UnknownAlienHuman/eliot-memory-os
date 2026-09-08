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
    MAX_TRANSFORMATION_STEPS, ObservedCue,
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
    /// Prefix matching for path or explicitly prefixable values.
    Prefix,
    /// Structured error-signature matching.
    Signature,
}

/// Normalization form used to produce a comparison key.
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
pub enum ComparisonForm {
    /// Preserve the original spelling.
    Exact,
    /// Fold case according to the profile.
    CaseInsensitive,
    /// Apply the profile's path separator and case policy.
    PathNormalized,
    /// Apply the profile's symbol qualification policy.
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

    /// Validates profile identity and its bounded text.
    pub fn validate(&self) -> Result<(), CueContractError> {
        validate_text(&self.profile_id, "profile.profile_id")?;
        if self.profile_revision == 0 {
            return Err(CueContractError::InvalidText {
                field: "profile.profile_revision",
            });
        }
        validate_digest(&self.digest, "profile.digest")
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
    /// Opaque owner-supplied digest for the canonical identity.
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

    /// Validates the canonical identity without interpreting its value.
    pub fn validate(&self) -> Result<(), CueContractError> {
        validate_text(&self.canonical_value, "canonical.canonical_value")?;
        validate_digest(&self.digest, "canonical.digest")
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
    /// The normalization form that produced this value.
    pub form: ComparisonForm,
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
        form: ComparisonForm,
    ) -> Self {
        Self {
            comparison_key_id,
            profile,
            key_value,
            form,
            match_mode,
        }
    }

    /// Validates the key and the normalization form that produced it.
    pub fn validate(&self) -> Result<(), CueContractError> {
        self.profile.validate()?;
        validate_text(&self.key_value, "comparison_key.key_value")
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
    /// The profile selected for this normalization, retained even when no
    /// canonical identity could be produced.
    pub profile: NormalizationProfile,
    /// The canonical identity.
    pub canonical: Option<CanonicalCueIdentity>,
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
        profile: NormalizationProfile,
        canonical: Option<CanonicalCueIdentity>,
        comparison_keys: Vec<ComparisonKey>,
        outcome: NormalizationOutcome,
        transformation_evidence: Vec<TransformationStep>,
    ) -> Self {
        Self {
            schema_revision,
            observed,
            profile,
            canonical,
            comparison_keys,
            outcome,
            transformation_evidence,
        }
    }

    /// Checks the intrinsic rules this record owns.
    ///
    /// # Errors
    /// Rejects malformed nested identities, duplicate keys, and unbounded
    /// collections while retaining exact canonical values independently from
    /// their comparison keys.
    pub fn validate(&self) -> Result<(), CueContractError> {
        if self.schema_revision != crate::CONTRACT_REVISION {
            return Err(CueContractError::InvalidText {
                field: "schema_revision",
            });
        }
        self.observed.validate()?;
        self.profile.validate()?;
        crate::bounds::collection(
            &self.comparison_keys,
            MAX_COMPARISON_KEYS,
            "comparison_keys",
        )?;
        crate::bounds::collection(
            &self.transformation_evidence,
            MAX_TRANSFORMATION_STEPS,
            "transformation_evidence",
        )?;
        self.validate_canonical_shape()?;
        self.validate_keys()?;
        self.validate_outcome()?;
        self.validate_transformations()
    }

    fn validate_canonical_shape(&self) -> Result<(), CueContractError> {
        match (&self.canonical, &self.outcome) {
            (
                Some(canonical),
                NormalizationOutcome::Lossless | NormalizationOutcome::AuthorizedLoss { .. },
            ) => {
                canonical.validate()?;
                if canonical.kind != self.observed.kind {
                    return Err(CueContractError::Foundation {
                        field: "canonical.kind",
                    });
                }
            }
            (
                None,
                NormalizationOutcome::Ambiguous { .. } | NormalizationOutcome::Unsupported { .. },
            ) => {}
            _ => {
                return Err(CueContractError::Foundation { field: "canonical" });
            }
        }
        Ok(())
    }

    fn validate_keys(&self) -> Result<(), CueContractError> {
        let mut seen = std::collections::BTreeSet::new();
        let expected_profile = &self.profile;
        for key in &self.comparison_keys {
            key.validate()?;
            if expected_profile != &key.profile {
                return Err(CueContractError::Foundation {
                    field: "comparison_key.profile",
                });
            }
            if !seen.insert(key.comparison_key_id.clone()) {
                return Err(CueContractError::DuplicateIdentity {
                    field: "comparison_keys",
                });
            }
            if !matches!(
                (
                    self.canonical.as_ref().map(|value| value.kind),
                    key.match_mode
                ),
                (_, MatchMode::Exact)
                    | (
                        Some(CueKind::FilePath | CueKind::DirPath),
                        MatchMode::Prefix
                    )
                    | (Some(CueKind::ErrorSignature), MatchMode::Signature)
            ) {
                return Err(CueContractError::Foundation {
                    field: "comparison_key.match_mode",
                });
            }
            if matches!(key.form, ComparisonForm::PathNormalized)
                && !matches!(
                    self.canonical.as_ref().map(|value| value.kind),
                    Some(CueKind::FilePath | CueKind::DirPath)
                )
            {
                return Err(CueContractError::Foundation {
                    field: "comparison_key.form",
                });
            }
            if matches!(key.form, ComparisonForm::SymbolQualified)
                && self.canonical.as_ref().map(|value| value.kind) != Some(CueKind::Symbol)
            {
                return Err(CueContractError::Foundation {
                    field: "comparison_key.form",
                });
            }
        }
        Ok(())
    }

    fn validate_outcome(&self) -> Result<(), CueContractError> {
        match &self.outcome {
            NormalizationOutcome::Lossless => {}
            NormalizationOutcome::AuthorizedLoss { policy_ref } => {
                validate_text(policy_ref, "outcome.policy_ref")?;
            }
            NormalizationOutcome::Ambiguous { rivals } => {
                crate::bounds::collection(rivals, MAX_COMPARISON_KEYS, "outcome.rivals")?;
                if rivals.len() < 2 {
                    return Err(CueContractError::InvalidText {
                        field: "outcome.rivals",
                    });
                }
                let mut rival_ids = std::collections::BTreeSet::new();
                for rival in rivals {
                    rival.validate()?;
                    if rival.kind != self.observed.kind
                        || !rival_ids.insert(rival.canonical_cue_id.clone())
                    {
                        return Err(CueContractError::DuplicateIdentity {
                            field: "outcome.rivals",
                        });
                    }
                }
                if !self.comparison_keys.is_empty() {
                    return Err(CueContractError::Foundation {
                        field: "comparison_keys",
                    });
                }
            }
            NormalizationOutcome::Unsupported { reason } => {
                validate_text(reason, "outcome.reason")?;
                if !self.comparison_keys.is_empty() {
                    return Err(CueContractError::Foundation {
                        field: "comparison_keys",
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_transformations(&self) -> Result<(), CueContractError> {
        for step in &self.transformation_evidence {
            validate_text(&step.step, "transformation.step")?;
            validate_text(&step.result, "transformation.result")?;
        }
        Ok(())
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), CueContractError> {
    crate::bounds::text(value, field)
}

fn validate_digest(value: &Digest, field: &'static str) -> Result<(), CueContractError> {
    if value.as_str().len() != 64
        || !value
            .as_str()
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(CueContractError::InvalidText { field });
    }
    Ok(())
}
