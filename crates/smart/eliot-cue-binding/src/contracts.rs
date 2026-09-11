//! A-12 caller supplied binding parameters and bounded result shapes.

use eliot_change_monitor::{ChangeKind, ObservedChangeRecord};
use eliot_contracts::StateFence;
use eliot_cue_contracts::{
    CueBindingCandidate, CueKind, Digest, NormalizationProfile, TargetHandle,
};
use eliot_cue_normalizer::NormalizationEnvelope;
use eliot_observation::ObservationAdmissionReceipt;
use serde::{Deserialize, Serialize};

/// Maximum candidates retained inline; omitted identities remain recoverable.
pub const MAX_INLINE_CANDIDATES: usize = 12;
/// Maximum binding rules in one caller-supplied profile.
pub const MAX_BINDING_RULES: usize = 32;

/// Which exact snapshot discriminator a rule uses.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResourceField {
    Path,
    Symbol,
}

/// One explicit A-12 rule. It describes a candidate shape; it does not admit it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingRule {
    pub cue_kind: CueKind,
    pub change_kind: ChangeKind,
    pub role: eliot_cue_contracts::BindingRole,
    pub resource_field: ResourceField,
    pub rule_ref: String,
}

/// Versioned caller-supplied rule/profile binding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindingProfile {
    pub profile_id: String,
    pub profile_revision: u32,
    pub profile_digest: Digest,
    pub scope_id: eliot_cue_contracts::WorkScopeId,
    pub state_fence: StateFence,
    pub rules: Vec<BindingRule>,
    /// Exact A-11 profile expected by every supplied normalization envelope.
    pub expected_normalization_profile: NormalizationProfile,
}

impl BindingProfile {
    /// Seals an explicit rule profile over its receipt-excluded definition.
    pub fn sealed(
        profile_id: String,
        profile_revision: u32,
        scope_id: eliot_cue_contracts::WorkScopeId,
        state_fence: StateFence,
        rules: Vec<BindingRule>,
        expected_normalization_profile: NormalizationProfile,
    ) -> Result<Self, eliot_cue_contracts::CueContractError> {
        let placeholder = Digest::new("0".repeat(64))?;
        let candidate = Self {
            profile_id,
            profile_revision,
            profile_digest: placeholder,
            scope_id,
            state_fence,
            rules,
            expected_normalization_profile,
        };
        crate::bounds::profile(&candidate)
            .map_err(|_| eliot_cue_contracts::CueContractError::InvalidText { field: "profile" })?;
        let profile_digest = profile_digest(&candidate)?;
        Ok(Self {
            profile_digest,
            ..candidate
        })
    }
}

#[derive(Serialize)]
struct ProfilePreimage<'a> {
    domain: &'static str,
    profile_id: &'a str,
    profile_revision: u32,
    scope_id: &'a str,
    state_fence: &'a StateFence,
    rules: &'a [BindingRule],
    expected_normalization_profile: &'a NormalizationProfile,
}

pub(crate) fn profile_digest(
    profile: &BindingProfile,
) -> Result<Digest, eliot_cue_contracts::CueContractError> {
    let bytes = eliot_contracts::canonical_json_bytes(&ProfilePreimage {
        domain: "eliot.a12.cue-binding.profile.v1",
        profile_id: &profile.profile_id,
        profile_revision: profile.profile_revision,
        scope_id: profile.scope_id.as_str(),
        state_fence: &profile.state_fence,
        rules: &profile.rules,
        expected_normalization_profile: &profile.expected_normalization_profile,
    })
    .map_err(|_| eliot_cue_contracts::CueContractError::InvalidText { field: "profile" })?;
    Digest::new(eliot_contracts::sha256_hex(&bytes))
}

/// A touched denominator row composed from existing A-10/A-11/C1 contracts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TouchedResourceProjection {
    pub target: TargetHandle,
    pub normalization: NormalizationEnvelope,
    pub change: ObservedChangeRecord,
}

/// Optional expected-reuse evidence. It cannot add a target or a relation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedReuseHint {
    pub target: TargetHandle,
    pub evidence_ref: String,
}

/// Why an input row did not produce a positive withheld candidate.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ColdReason {
    MissingEvidence,
    UnknownOrigin,
    UnsupportedKind,
    IdentityConflict,
    HintUnproved,
}

/// Observable disposition of the supplied denominator.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum BindingOutcome {
    CandidatesForSuppliedInputs,
    Cold,
    PartialOverflow,
}

/// A retained cold identity, preserving the supplied target and reason.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ColdBinding {
    pub target: TargetHandle,
    pub revision: Option<String>,
    pub observed_cue_id: String,
    pub change_id: String,
    pub reason: ColdReason,
}

/// Identity retained after the inline page bound is reached.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OmittedBindingIdentity {
    pub target: TargetHandle,
    pub revision: Option<String>,
    pub candidate_digest: Option<Digest>,
}

/// A-12 result retaining all supplied evidence and an inert candidate page.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CueBindingResult {
    pub schema_revision: String,
    pub admission: ObservationAdmissionReceipt,
    pub profile: BindingProfile,
    pub touched: Vec<TouchedResourceProjection>,
    pub candidates: Vec<CueBindingCandidate>,
    pub cold: Vec<ColdBinding>,
    pub omitted: Vec<OmittedBindingIdentity>,
    pub continuation_digest: Option<Digest>,
    pub hint: Option<ExpectedReuseHint>,
    pub state_fence: StateFence,
    pub outcome: BindingOutcome,
    pub result_digest: Digest,
}

impl CueBindingResult {
    /// Returns the normalization profile from the first supplied row, when present.
    #[must_use]
    pub fn normalization_profile(&self) -> Option<&NormalizationProfile> {
        self.touched
            .first()
            .map(|row| &row.normalization.policy.profile)
    }
}
