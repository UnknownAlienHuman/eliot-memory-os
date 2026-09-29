//! Immutable qualification evidence for enabling relation spreading.
//!
//! `I12.15` step 7 keeps default enablement separate from the algorithm. The
//! numerical profile is unbenchmarked policy; nothing about a passing
//! evaluation, a nonempty benchmark reference or a source comment qualifies it.
//! Qualification is a separate, immutable artifact that binds *what was
//! compared* — the exact weights, relation registry, normalization revision and
//! runtime identity — to a scope, an expiry and a kill condition.
//!
//! This module owns that binding. It is deliberately inert: it records and
//! validates evidence, it never runs a benchmark, never compares two runs and
//! never enables anything by itself. A caller decides whether to supply a
//! qualification; the absence of one is the default, and absence is expressed
//! as a decision, not as an accident.
//!
//! The substitutions this artifact exists to prevent are explicit:
//!
//! - a digest is validated against the *recorded* value, never recomputed over
//!   whatever the holder happens to carry;
//! - expiry is compared with the operation's own observed time, never with an
//!   ambient clock read here;
//! - a qualification is honored only for the exact profile, registry,
//!   normalization revision and runtime identity it names.

use eliot_contracts::ClockReading;
use eliot_cue_contracts::{Digest, NormalizationProfile, WorkScopeId};
use serde::{Deserialize, Serialize};

use crate::error::ActivationError;
use crate::profile::ActivationProfile;

/// Bounded text ceiling for one qualification text field.
const MAX_TEXT_BYTES: usize = 512;

/// Why a supplied qualification does not admit spreading right now.
///
/// Every variant is a comparison against the exact identity the qualification
/// recorded. None of them is a judgement about the algorithm, and none of them
/// can be satisfied by a later recomputation over different inputs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum QualificationRefusal {
    /// The qualification names a different numerical profile.
    ProfileChanged,
    /// The qualification names a different relation-registry revision.
    RegistryChanged,
    /// The qualification names a different normalization revision.
    NormalizationChanged,
    /// The qualification names a different runtime identity.
    RuntimeChanged,
    /// The qualification names a different work scope.
    ScopeChanged,
    /// The recorded expiry has passed at the operation's own observed time.
    Expired,
    /// The recorded kill condition has fired.
    Killed,
}

/// Immutable evidence that relation spreading was qualified for one exact
/// configuration.
///
/// This record is evidence, not authority: it cannot enable spreading on its
/// own, and a caller that supplies one still resolves its own enablement
/// decision. What it does is bind the qualification to the precise inputs it
/// was measured against, so a change of weights, registry, normalization or
/// runtime identity invalidates it rather than silently inheriting it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct SpreadQualification {
    /// Bounded identity of this qualification record.
    pub qualification_id: String,
    /// Digest of the exact numerical profile that was qualified.
    pub profile_digest: Digest,
    /// Relation-registry revision the qualified comparison ran under.
    pub registry_revision: String,
    /// Normalization revision the qualified comparison ran under.
    pub normalization_profile: NormalizationProfile,
    /// Runtime identity the qualified comparison ran under.
    pub runtime_identity: String,
    /// Scope the qualification is bound to.
    pub scope_id: WorkScopeId,
    /// Bounded reference to the immutable comparison evidence.
    pub evidence_reference: String,
    /// Expiry of this qualification, in the operation's own time domain.
    pub expires_at_ms: i64,
    /// Bounded kill or rollback condition that retires this qualification.
    pub kill_condition: String,
    /// Whether the recorded kill condition has fired.
    pub killed: bool,
}

/// The default enablement decision when no qualification is supplied.
///
/// Spreading is off. This is the decision a caller gets for free, and it is
/// deliberately a value rather than an absence: an unbenchmarked profile has no
/// path to being enabled by not being asked about.
///
/// This type is not `Copy`: the enabled variant owns the identity of the
/// qualification that admitted the operation, and that identity is the evidence
/// a consumer reads back. It is moved, not cloned at each call site.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum SpreadEnablement {
    /// Relation spreading is not enabled.
    Disabled,
    /// Relation spreading is enabled under the exact named qualification.
    Enabled {
        /// Identity of the qualification that admits this operation.
        qualification_id: String,
    },
}

/// The immutable facts a qualification binds, before admission.
///
/// Grouping these is not cosmetic: `SpreadQualification` is a record of WHAT
/// was compared, and taking it as one value keeps every admitted fact named
/// once at the call site instead of spread across a nine-argument list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QualificationRecord {
    /// Identity of the qualification itself.
    pub qualification_id: String,
    /// Digest of the profile the comparison was measured against.
    pub profile_digest: Digest,
    /// Relation-registry revision in force at measurement time.
    pub registry_revision: String,
    /// Normalization profile in force at measurement time.
    pub normalization_profile: NormalizationProfile,
    /// Runtime identity the measurement belongs to.
    pub runtime_identity: String,
    /// Work scope the qualification is bound to.
    pub scope_id: WorkScopeId,
    /// Where the comparison evidence lives.
    pub evidence_reference: String,
    /// Absolute expiry, in milliseconds since the Unix epoch.
    pub expires_at_ms: i64,
    /// The condition that revokes this qualification.
    pub kill_condition: String,
}

impl SpreadQualification {
    /// Binds a qualification to the exact configuration it was measured
    /// against.
    ///
    /// # Errors
    /// Rejects an empty, control-bearing or over-long text field and a
    /// non-positive expiry interval measured from the recorded issue time.
    pub fn new(record: QualificationRecord) -> Result<Self, ActivationError> {
        check_text(&record.qualification_id, "qualification.qualification_id")?;
        check_text(&record.registry_revision, "qualification.registry_revision")?;
        check_text(&record.runtime_identity, "qualification.runtime_identity")?;
        check_text(
            &record.evidence_reference,
            "qualification.evidence_reference",
        )?;
        check_text(&record.kill_condition, "qualification.kill_condition")?;
        if record.expires_at_ms <= 0 {
            return Err(ActivationError::Contract(
                eliot_cue_contracts::CueContractError::InvalidText {
                    field: "qualification.expires_at_ms",
                },
            ));
        }
        Ok(Self {
            qualification_id: record.qualification_id,
            profile_digest: record.profile_digest,
            registry_revision: record.registry_revision,
            normalization_profile: record.normalization_profile,
            runtime_identity: record.runtime_identity,
            scope_id: record.scope_id,
            evidence_reference: record.evidence_reference,
            expires_at_ms: record.expires_at_ms,
            kill_condition: record.kill_condition,
            killed: false,
        })
    }

    /// Whether this qualification admits spreading for the exact inputs.
    ///
    /// The comparison is against the values this record names, not against
    /// values recomputed from what the caller holds. A profile whose digest has
    /// changed since qualification is refused even if the caller recomputed an
    /// equal digest over its own current definition.
    ///
    /// # Errors
    /// Refuses when any named identity differs, when the recorded kill
    /// condition has fired, or when the operation's own observed time is at or
    /// past the recorded expiry.
    pub fn admits(
        &self,
        profile: &ActivationProfile,
        normalization_profile: &NormalizationProfile,
        scope_id: &WorkScopeId,
        runtime_identity: &str,
        observed: &ClockReading,
    ) -> Result<(), QualificationRefusal> {
        if self.killed {
            return Err(QualificationRefusal::Killed);
        }
        if self.profile_digest != profile.digest {
            return Err(QualificationRefusal::ProfileChanged);
        }
        if self.registry_revision.as_str() != profile.registry_revision.as_deref().unwrap_or("") {
            return Err(QualificationRefusal::RegistryChanged);
        }
        if &self.normalization_profile != normalization_profile {
            return Err(QualificationRefusal::NormalizationChanged);
        }
        if self.runtime_identity != runtime_identity {
            return Err(QualificationRefusal::RuntimeChanged);
        }
        if &self.scope_id != scope_id {
            return Err(QualificationRefusal::ScopeChanged);
        }
        let now = observed
            .valid_time_ms
            .ok_or(QualificationRefusal::Expired)?;
        if now >= self.expires_at_ms {
            return Err(QualificationRefusal::Expired);
        }
        Ok(())
    }
}

/// The enablement decision for one operation.
///
/// A caller that supplies no qualification gets [`SpreadEnablement::Disabled`].
/// A caller that supplies one gets it admitted only when every named identity
/// still matches, so new weights or a changed runtime invalidate a prior
/// qualification rather than inheriting it.
#[must_use]
pub fn resolve_enablement(
    qualification: Option<&SpreadQualification>,
    profile: &ActivationProfile,
    normalization_profile: &NormalizationProfile,
    scope_id: &WorkScopeId,
    runtime_identity: &str,
    observed: &ClockReading,
) -> SpreadEnablement {
    let Some(record) = qualification else {
        return SpreadEnablement::Disabled;
    };
    match record.admits(
        profile,
        normalization_profile,
        scope_id,
        runtime_identity,
        observed,
    ) {
        Ok(()) => SpreadEnablement::Enabled {
            qualification_id: record.qualification_id.clone(),
        },
        Err(_) => SpreadEnablement::Disabled,
    }
}

/// Rejects an empty, control-bearing or over-long qualification text field.
fn check_text(value: &str, field: &'static str) -> Result<(), ActivationError> {
    if value.trim().is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(char::is_control)
    {
        return Err(ActivationError::Contract(
            eliot_cue_contracts::CueContractError::InvalidText { field },
        ));
    }
    Ok(())
}
