//! Frozen portfolio input: expected members, observations, linkages, policy.
//!
//! The frozen evidence set is closed input. Freezing rejects duplicate member
//! identity, changed content under one immutable identity, a missing
//! denominator, a mixed evaluation boundary, and unknown schema variants.
//! Freezing performs no acquisition, no store access, and no model call: every
//! observation is supplied by the caller and only checked for envelope closure.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::RoleSeparationError;
use crate::{
    ASSURANCE_POLICY_VERSION, ASSURANCE_SCHEMA_VERSION, MAX_CITATIONS_PER_MEMBER, MAX_MEMBERS,
};
use crate::{digest_json, require_digest, require_text};

/// Authoritative lineage attribution for one portfolio member.
///
/// A missing root is unknown lineage, never a default root. Unknown lineage
/// means unknown independence: mirrored material never becomes independent
/// through multiple references alone.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LineageAttribution {
    /// Authoritative lineage root, or `None` for unknown lineage.
    pub root: Option<String>,
    /// Acquisition route that produced this observation.
    pub acquisition_route: String,
    /// Publisher or owner of the material.
    pub publisher: String,
    /// Common-mode generation identity, when the material shares a generator.
    pub generator: Option<String>,
}

/// One expected portfolio member with its immutable content identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExpectedMember {
    /// Opaque stable identity for the portfolio member.
    pub member_id: String,
    /// Digest of the exact bytes pinned to this identity.
    pub content_digest: String,
    /// Authoritative lineage attribution.
    pub lineage: LineageAttribution,
    /// Source class used for policy exclusions and blind-boundary reporting.
    pub source_class: String,
    /// Reference strings (URLs, citations). Never independence evidence.
    pub citation_refs: Vec<String>,
}

/// Exactly one disposition per expected portfolio member.
///
/// No unavailable, withheld, stale, conflicted, retracted, malformed,
/// unsupported-format, or unknown member disappears: each is an explicit
/// variant that flows into coverage, completeness, and blind boundaries.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "disposition", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemberDisposition {
    /// Content observed with the pinned digest and a lineage-completeness flag.
    Acquired {
        /// Digest observed for the member bytes; must equal the pinned digest.
        observed_digest: String,
        /// Whether provenance for this observation is complete.
        lineage_complete: bool,
    },
    /// The source could not be reached or produced nothing usable.
    Unavailable {
        /// Why the member is unavailable.
        reason: String,
    },
    /// The source is excluded by a declared policy or credential gap.
    Withheld {
        /// Declared exclusion reference from the assurance policy.
        policy_ref: String,
        /// Why the member is withheld.
        reason: String,
    },
    /// Content observed with the pinned digest but past its freshness fence.
    Stale {
        /// Digest observed for the member bytes; must equal the pinned digest.
        observed_digest: String,
        /// Observation time in epoch seconds.
        observed_at_secs: u64,
        /// Frontier generation the observation belongs to.
        frontier_generation: u64,
    },
    /// Content observed but asserting a conflicting claim.
    Conflicted {
        /// Digest observed for the member bytes; must equal the pinned digest.
        observed_digest: String,
        /// Claim this member contradicts.
        conflicting_claim_id: String,
    },
    /// The source was withdrawn upstream.
    Retracted {
        /// Retraction notice reference.
        retraction_ref: String,
    },
    /// The observation bytes cannot be parsed.
    Malformed {
        /// Why the observation is malformed.
        reason: String,
    },
    /// The observation format is not supported by any consumer.
    UnsupportedFormat {
        /// The unsupported format name.
        format: String,
    },
    /// The member state cannot be established.
    Unknown {
        /// Why the member state is unknown.
        reason: String,
    },
}

impl MemberDisposition {
    /// Stable key for deterministic ordering and coverage accounting.
    pub fn key(&self) -> &'static str {
        match self {
            Self::Acquired { .. } => "acquired",
            Self::Unavailable { .. } => "unavailable",
            Self::Withheld { .. } => "withheld",
            Self::Stale { .. } => "stale",
            Self::Conflicted { .. } => "conflicted",
            Self::Retracted { .. } => "retracted",
            Self::Malformed { .. } => "malformed",
            Self::UnsupportedFormat { .. } => "unsupported_format",
            Self::Unknown { .. } => "unknown",
        }
    }
}

/// One observation bound to the frozen evaluation boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberObservation {
    /// Expected member this observation describes.
    pub member_id: String,
    /// Boundary this observation was evaluated under.
    pub evaluation_boundary: String,
    /// The single explicit disposition.
    pub disposition: MemberDisposition,
}

/// Claim stance of one member. Support and contradiction stay separate: one
/// member asserts at most one stance toward one claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportStance {
    /// The member supports the linked claim.
    Supports,
    /// The member contradicts the linked claim.
    Contradicts,
    /// The member is context for the linked claim without taking a side.
    ContextOnly,
    /// The member is not linked to any claim.
    Unlinked,
}

/// Claim linkage for one member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ClaimLinkage {
    /// Expected member this linkage describes.
    pub member_id: String,
    /// Linked claim; required exactly when the stance is not `Unlinked`.
    pub claim_id: Option<String>,
    /// The member stance toward the linked claim.
    pub stance: SupportStance,
}

/// Permitted influence for consumers of an assurance result.
///
/// The ceiling is candidacy only. No authority issuance, influence change, or
/// completion decision can be expressed: no such variant exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InfluenceCeiling {
    /// No downstream influence is permitted.
    NoInfluence,
    /// The material may be treated as candidate evidence only.
    CandidateEvidence,
}

/// Owner-supplied assurance policy for one frozen evidence set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AssurancePolicy {
    /// Policy version this crate implements.
    pub policy_version: String,
    /// Boundary this policy governs; must equal the set boundary.
    pub evaluation_boundary: String,
    /// Source classes excluded from usable coverage.
    pub excluded_source_classes: Vec<String>,
    /// Declared credential-gap references a `Withheld` member may cite.
    pub credential_gap_refs: Vec<String>,
    /// Permitted downstream influence; never broader than candidacy.
    pub allowed_influence: InfluenceCeiling,
}

/// Closed input for one assurance evaluation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrozenEvidenceSet {
    /// Schema version this crate implements.
    pub schema_version: String,
    /// Stable set identity.
    pub set_id: String,
    /// Set revision; any material change mints a new revision.
    pub revision: String,
    /// The single evaluation boundary for every member and the policy.
    pub evaluation_boundary: String,
    /// Evaluation time in epoch seconds.
    pub evaluated_at_secs: u64,
    /// Expiry time in epoch seconds; must be after evaluation time.
    pub expires_at_secs: u64,
    /// Exact expected members, canonicalized by `member_id`.
    pub members: Vec<ExpectedMember>,
    /// Exactly one observation per expected member, canonicalized.
    pub observations: Vec<MemberObservation>,
    /// Exactly one claim linkage per expected member, canonicalized.
    pub linkages: Vec<ClaimLinkage>,
    /// The governing assurance policy.
    pub policy: AssurancePolicy,
    /// Digest over the canonical policy material.
    pub policy_digest: String,
    /// Digest over the complete canonical frozen material.
    pub set_digest: String,
}

/// Caller-supplied material for [`FrozenEvidenceSet::freeze`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreezeInput {
    /// Stable set identity.
    pub set_id: String,
    /// Set revision.
    pub revision: String,
    /// The single evaluation boundary.
    pub evaluation_boundary: String,
    /// Evaluation time in epoch seconds.
    pub evaluated_at_secs: u64,
    /// Expiry time in epoch seconds.
    pub expires_at_secs: u64,
    /// Exact expected members.
    pub members: Vec<ExpectedMember>,
    /// Exactly one observation per expected member.
    pub observations: Vec<MemberObservation>,
    /// Exactly one claim linkage per expected member.
    pub linkages: Vec<ClaimLinkage>,
    /// The governing assurance policy.
    pub policy: AssurancePolicy,
}

impl FrozenEvidenceSet {
    /// Freeze closed input after checking envelope closure.
    ///
    /// Rejects unknown schema or policy versions, an empty denominator, mixed
    /// evaluation boundaries, duplicate identities, observations or linkages
    /// that do not match the expected members one-to-one, changed content
    /// under one immutable identity, and withheld members citing undeclared
    /// exclusions. Members, observations, and linkages are canonicalized by
    /// `member_id` so every downstream calculation is deterministic.
    pub fn freeze(input: FreezeInput) -> Result<Self, RoleSeparationError> {
        require_text("set_id", &input.set_id)?;
        require_text("revision", &input.revision)?;
        require_text("evaluation_boundary", &input.evaluation_boundary)?;
        if input.expires_at_secs <= input.evaluated_at_secs {
            return Err(RoleSeparationError::InvalidEvaluationWindow);
        }
        if input.members.is_empty() {
            return Err(RoleSeparationError::MissingDenominator);
        }
        if input.members.len() > MAX_MEMBERS {
            return Err(RoleSeparationError::TooManyMembers(input.members.len()));
        }
        let mut members = input.members;
        for member in &members {
            validate_member(member)?;
        }
        members.sort_by(|left, right| left.member_id.cmp(&right.member_id));
        let mut member_ids = BTreeSet::new();
        for member in &members {
            if !member_ids.insert(member.member_id.as_str()) {
                return Err(RoleSeparationError::DuplicateMemberId(
                    member.member_id.clone(),
                ));
            }
        }
        validate_policy(&input.policy, &input.evaluation_boundary)?;

        let by_id: BTreeMap<&str, &ExpectedMember> = members
            .iter()
            .map(|member| (member.member_id.as_str(), member))
            .collect();
        let observations = freeze_observations(
            input.observations,
            &members,
            &by_id,
            &input.evaluation_boundary,
            &input.policy,
        )?;
        let linkages = freeze_linkages(input.linkages, &members, &by_id)?;

        let policy_digest = digest_json(&input.policy)?;
        let material = SetDigestMaterial {
            schema_version: ASSURANCE_SCHEMA_VERSION,
            set_id: &input.set_id,
            revision: &input.revision,
            evaluation_boundary: &input.evaluation_boundary,
            evaluated_at_secs: input.evaluated_at_secs,
            expires_at_secs: input.expires_at_secs,
            members: &members,
            observations: &observations,
            linkages: &linkages,
            policy_digest: &policy_digest,
        };
        let set_digest = digest_json(&material)?;
        Ok(Self {
            schema_version: ASSURANCE_SCHEMA_VERSION.to_owned(),
            set_id: input.set_id,
            revision: input.revision,
            evaluation_boundary: input.evaluation_boundary,
            evaluated_at_secs: input.evaluated_at_secs,
            expires_at_secs: input.expires_at_secs,
            members,
            observations,
            linkages,
            policy: input.policy,
            policy_digest,
            set_digest,
        })
    }

    /// Recompute the canonical digest and compare it with the frozen one.
    ///
    /// Any post-freeze mutation of members, observations, linkages, policy, or
    /// envelope fields is detected here instead of flowing silently into a
    /// consumer.
    pub fn verify_digest(&self) -> Result<(), RoleSeparationError> {
        if self.schema_version != ASSURANCE_SCHEMA_VERSION {
            return Err(RoleSeparationError::UnsupportedSchema(
                self.schema_version.clone(),
            ));
        }
        let policy_digest = digest_json(&self.policy)?;
        if policy_digest != self.policy_digest {
            return Err(RoleSeparationError::EnvelopeBindingMismatch);
        }
        let material = SetDigestMaterial {
            schema_version: &self.schema_version,
            set_id: &self.set_id,
            revision: &self.revision,
            evaluation_boundary: &self.evaluation_boundary,
            evaluated_at_secs: self.evaluated_at_secs,
            expires_at_secs: self.expires_at_secs,
            members: &self.members,
            observations: &self.observations,
            linkages: &self.linkages,
            policy_digest: &self.policy_digest,
        };
        if digest_json(&material)? != self.set_digest {
            return Err(RoleSeparationError::EnvelopeBindingMismatch);
        }
        Ok(())
    }

    /// Look up the expected member for an id.
    pub fn member(&self, member_id: &str) -> Option<&ExpectedMember> {
        self.members
            .iter()
            .find(|member| member.member_id == member_id)
    }

    /// Look up the observation for an id.
    pub fn observation(&self, member_id: &str) -> Option<&MemberObservation> {
        self.observations
            .iter()
            .find(|observation| observation.member_id == member_id)
    }

    /// Look up the claim linkage for an id.
    pub fn linkage(&self, member_id: &str) -> Option<&ClaimLinkage> {
        self.linkages
            .iter()
            .find(|linkage| linkage.member_id == member_id)
    }
}

/// Canonicalize observations and check them one-to-one against members.
fn freeze_observations(
    observations: Vec<MemberObservation>,
    members: &[ExpectedMember],
    by_id: &BTreeMap<&str, &ExpectedMember>,
    evaluation_boundary: &str,
    policy: &AssurancePolicy,
) -> Result<Vec<MemberObservation>, RoleSeparationError> {
    let mut observations = observations;
    observations.sort_by(|left, right| left.member_id.cmp(&right.member_id));
    let mut observed_ids = BTreeSet::new();
    for observation in &observations {
        if !observed_ids.insert(observation.member_id.as_str()) {
            return Err(RoleSeparationError::DuplicateMemberId(
                observation.member_id.clone(),
            ));
        }
        let Some(member) = by_id.get(observation.member_id.as_str()) else {
            return Err(RoleSeparationError::UnknownObservation(
                observation.member_id.clone(),
            ));
        };
        validate_observation(observation, member, evaluation_boundary, policy)?;
    }
    if observations.len() != members.len() {
        let missing = members
            .iter()
            .find(|member| !observed_ids.contains(member.member_id.as_str()))
            .map_or_else(String::new, |member| member.member_id.clone());
        return Err(RoleSeparationError::MissingObservation(missing));
    }
    Ok(observations)
}

/// Canonicalize linkages and check them one-to-one against members.
fn freeze_linkages(
    linkages: Vec<ClaimLinkage>,
    members: &[ExpectedMember],
    by_id: &BTreeMap<&str, &ExpectedMember>,
) -> Result<Vec<ClaimLinkage>, RoleSeparationError> {
    let mut linkages = linkages;
    linkages.sort_by(|left, right| left.member_id.cmp(&right.member_id));
    let mut linked_ids = BTreeSet::new();
    for linkage in &linkages {
        if !linked_ids.insert(linkage.member_id.as_str()) {
            return Err(RoleSeparationError::DuplicateLinkage(
                linkage.member_id.clone(),
            ));
        }
        if !by_id.contains_key(linkage.member_id.as_str()) {
            return Err(RoleSeparationError::UnknownMemberLinkage(
                linkage.member_id.clone(),
            ));
        }
        validate_linkage(linkage)?;
    }
    if linkages.len() != members.len() {
        let missing = members
            .iter()
            .find(|member| !linked_ids.contains(member.member_id.as_str()))
            .map_or_else(String::new, |member| member.member_id.clone());
        return Err(RoleSeparationError::MissingLinkage(missing));
    }
    Ok(linkages)
}

#[derive(Serialize)]
struct SetDigestMaterial<'a> {
    schema_version: &'a str,
    set_id: &'a str,
    revision: &'a str,
    evaluation_boundary: &'a str,
    evaluated_at_secs: u64,
    expires_at_secs: u64,
    members: &'a [ExpectedMember],
    observations: &'a [MemberObservation],
    linkages: &'a [ClaimLinkage],
    policy_digest: &'a str,
}

fn validate_member(member: &ExpectedMember) -> Result<(), RoleSeparationError> {
    require_text("member_id", &member.member_id)?;
    require_digest("content_digest", &member.content_digest)?;
    if let Some(root) = &member.lineage.root {
        require_text("lineage.root", root)?;
    }
    require_text(
        "lineage.acquisition_route",
        &member.lineage.acquisition_route,
    )?;
    require_text("lineage.publisher", &member.lineage.publisher)?;
    if let Some(generator) = &member.lineage.generator {
        require_text("lineage.generator", generator)?;
    }
    require_text("source_class", &member.source_class)?;
    if member.citation_refs.len() > MAX_CITATIONS_PER_MEMBER {
        return Err(RoleSeparationError::TextTooLong("citation_refs"));
    }
    for citation in &member.citation_refs {
        require_text("citation_ref", citation)?;
    }
    Ok(())
}

fn validate_policy(
    policy: &AssurancePolicy,
    evaluation_boundary: &str,
) -> Result<(), RoleSeparationError> {
    if policy.policy_version != ASSURANCE_POLICY_VERSION {
        return Err(RoleSeparationError::UnsupportedPolicy(
            policy.policy_version.clone(),
        ));
    }
    if policy.evaluation_boundary != evaluation_boundary {
        return Err(RoleSeparationError::MixedEvaluationBoundary {
            expected: evaluation_boundary.to_owned(),
            observed: policy.evaluation_boundary.clone(),
        });
    }
    for class in &policy.excluded_source_classes {
        require_text("excluded_source_class", class)?;
    }
    for gap in &policy.credential_gap_refs {
        require_text("credential_gap_ref", gap)?;
    }
    Ok(())
}

fn validate_observation(
    observation: &MemberObservation,
    member: &ExpectedMember,
    evaluation_boundary: &str,
    policy: &AssurancePolicy,
) -> Result<(), RoleSeparationError> {
    if observation.evaluation_boundary != evaluation_boundary {
        return Err(RoleSeparationError::MixedEvaluationBoundary {
            expected: evaluation_boundary.to_owned(),
            observed: observation.evaluation_boundary.clone(),
        });
    }
    match &observation.disposition {
        MemberDisposition::Acquired {
            observed_digest,
            lineage_complete: _,
        }
        | MemberDisposition::Stale {
            observed_digest,
            observed_at_secs: _,
            frontier_generation: _,
        }
        | MemberDisposition::Conflicted {
            observed_digest,
            conflicting_claim_id: _,
        } => {
            require_digest("observed_digest", observed_digest)?;
            if observed_digest != &member.content_digest {
                return Err(RoleSeparationError::ChangedContentUnderImmutableIdentity(
                    member.member_id.clone(),
                ));
            }
            if let MemberDisposition::Conflicted {
                conflicting_claim_id,
                ..
            } = &observation.disposition
            {
                require_text("conflicting_claim_id", conflicting_claim_id)?;
            }
        }
        MemberDisposition::Unavailable { reason }
        | MemberDisposition::Malformed { reason }
        | MemberDisposition::Unknown { reason } => {
            require_text("disposition.reason", reason)?;
        }
        MemberDisposition::Withheld { policy_ref, reason } => {
            require_text("withheld.reason", reason)?;
            require_text("withheld.policy_ref", policy_ref)?;
            let class_exclusion = format!("class:{}", member.source_class);
            if !policy
                .credential_gap_refs
                .iter()
                .any(|gap| gap == policy_ref)
                && *policy_ref != class_exclusion
            {
                return Err(RoleSeparationError::UndeclaredExclusion(
                    member.member_id.clone(),
                ));
            }
        }
        MemberDisposition::Retracted { retraction_ref } => {
            require_text("retraction_ref", retraction_ref)?;
        }
        MemberDisposition::UnsupportedFormat { format } => {
            require_text("unsupported_format", format)?;
        }
    }
    Ok(())
}

fn validate_linkage(linkage: &ClaimLinkage) -> Result<(), RoleSeparationError> {
    match (&linkage.claim_id, linkage.stance) {
        (
            Some(claim_id),
            SupportStance::Supports | SupportStance::Contradicts | SupportStance::ContextOnly,
        ) => {
            require_text("claim_id", claim_id)?;
        }
        (None, SupportStance::Unlinked) => {}
        _ => {
            return Err(RoleSeparationError::InconsistentClaimBinding(
                linkage.member_id.clone(),
            ));
        }
    }
    Ok(())
}
