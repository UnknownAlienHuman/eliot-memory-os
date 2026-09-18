//! Deterministic assessment over a frozen evidence set.
//!
//! Assessment separates every role: provenance, content integrity,
//! availability, accessibility, independence, relevance, claim support,
//! contradiction, confidence, and permitted influence are computed as
//! independent fields and never collapsed into one score. Counts of unique
//! authoritative lineage roots bound independence; reference multiplicity
//! cannot manufacture it. A successful acquisition or an intact digest never
//! establishes support, truth, currentness, or influence by itself.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::RoleSeparationError;
use crate::portfolio::{FrozenEvidenceSet, InfluenceCeiling, MemberDisposition, SupportStance};
use crate::{ASSURANCE_SCHEMA_VERSION, digest_json};

/// Provenance state of one member observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProvenanceState {
    /// Lineage root and route are known and the observation is complete.
    Complete,
    /// Lineage is known but the observation is marked incomplete.
    IncompleteLineage,
    /// The lineage root is unknown; independence is unknown as well.
    UnknownLineage,
}

/// Content-integrity state of one member observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityState {
    /// Observed bytes match the pinned immutable digest.
    DigestMatched,
    /// No bytes were observed for this member.
    NotAcquired,
}

/// Availability state of one member observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AvailabilityState {
    /// Content is in hand, whether fresh or stale.
    Observed,
    /// The source produced nothing usable.
    Unavailable,
    /// Policy or credentials bar the source.
    WithheldByPolicy,
    /// The source was withdrawn upstream.
    RetractedUpstream,
    /// The observation cannot be interpreted.
    Uninterpretable,
}

/// Accessibility state of one member observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccessibilityState {
    /// The bytes are accessible to consumers.
    Accessible,
    /// A credential gap bars access.
    CredentialGap,
    /// Policy excludes the member class.
    PolicyExcluded,
    /// The format is not supported.
    UnsupportedFormat,
    /// Accessibility cannot be established.
    Unknown,
}

/// Independence state of one member observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndependenceState {
    /// The member is the only observed member of its lineage root.
    UniqueRoot,
    /// The member shares its lineage root with another observed member.
    SharedRoot,
    /// Lineage is unknown, so independence is unknown.
    UnknownLineage,
    /// No content is in hand, so independence does not apply.
    NotApplicable,
}

/// Relevance state of one member observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RelevanceState {
    /// The member takes a stance on a claim.
    DirectlyLinked,
    /// The member is context without taking a side.
    Contextual,
    /// The member is linked to no claim.
    Unlinked,
}

/// Contradiction state of one member observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemberContradiction {
    /// No contradiction involves this member.
    None,
    /// This member asserts against its linked claim.
    AssertsAgainstClaim,
    /// Peers assert the opposite stance on the same claim.
    ContestedByPeers,
}

/// Separated axis readout for one portfolio member.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MemberAxisRecord {
    /// Portfolio member this record describes.
    pub member_id: String,
    /// Provenance axis, independent of integrity and support.
    pub provenance: ProvenanceState,
    /// Content-integrity axis: digest match only, never truth.
    pub integrity: IntegrityState,
    /// Availability axis: whether content is in hand.
    pub availability: AvailabilityState,
    /// Accessibility axis: whether consumers may reach the content.
    pub accessibility: AccessibilityState,
    /// Independence axis: lineage-root sharing, never reference counts.
    pub independence: IndependenceState,
    /// Relevance axis: claim linkage class.
    pub relevance: RelevanceState,
    /// Support stance asserted by the member linkage.
    pub stance: SupportStance,
    /// Contradiction axis for this member.
    pub contradiction: MemberContradiction,
}

/// One counted disposition in the coverage receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DispositionCount {
    /// Stable disposition key.
    pub disposition: String,
    /// Members carrying this disposition.
    pub count: usize,
}

/// Deterministic coverage receipt over the exact frozen denominator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CoverageReceipt {
    /// Expected members: the exact frozen denominator.
    pub expected_members: usize,
    /// Members usable as evidence: acquired, lineage-complete, policy-included.
    pub usable_members: usize,
    /// Explicit count for every disposition, including zeroes.
    pub per_disposition: Vec<DispositionCount>,
    /// Acquired members barred by a policy class exclusion.
    pub excluded_class_members: Vec<String>,
    /// Digest over the sorted member identities and the policy digest.
    pub denominator_digest: String,
}

/// Common-mode generation risk kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CommonModeKind {
    /// Two or more supporting members share one acquisition route.
    SharedAcquisitionRoute,
    /// Two or more supporting members share one generator.
    SharedGenerator,
    /// All support traces to a single lineage root.
    SingleRootForAllSupport,
}

/// One visible common-mode risk.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CommonModeFlag {
    /// The kind of common-mode risk.
    pub kind: CommonModeKind,
    /// Route, generator, or root the flag describes.
    pub detail: String,
}

/// Members sharing one authoritative lineage root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MirrorGroup {
    /// The shared authoritative lineage root.
    pub lineage_root: String,
    /// Members observed under that root.
    pub member_ids: Vec<String>,
}

/// Lineage-root independence assessment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct IndependenceAssessment {
    /// Sorted unique authoritative lineage roots observed.
    pub unique_lineage_roots: Vec<String>,
    /// Members with unknown lineage.
    pub unknown_lineage_members: Vec<String>,
    /// Roots observed through more than one member.
    pub mirror_groups: Vec<MirrorGroup>,
    /// Unique roots among usable supporting members. Never exceeds the
    /// unique-root count; mirrors and reference multiplicity add nothing.
    pub independent_support_count: usize,
    /// Visible common-mode risks over the supporting members.
    pub common_mode_flags: Vec<CommonModeFlag>,
}

/// Maximum epistemic use supported for one claim.
///
/// The strongest level is candidacy. There is no truth, verification, or
/// completion level: support ceilings never promote material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EpistemicUse {
    /// The input supports no epistemic use of this claim.
    NoUse,
    /// The input supports treating the claim as candidate evidence.
    EvidenceCandidate,
    /// The claim is contested; hypothesis-level use at most.
    HypothesisCandidate,
}

/// Confidence observation for one claim. A typed observation, never a scalar.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConfidenceObservation {
    /// Independent roots support the claim and none contradict it.
    SupportedByIndependentRoots,
    /// Independent roots disagree about the claim.
    ContestedByIndependentRoots,
    /// No usable basis for the claim exists in the input.
    InsufficientBasis,
    /// Support traces only to unknown lineage.
    UnknownBasis,
}

/// Maximum claim and evidence use supported by the frozen input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SupportCeiling {
    /// Claim this ceiling describes.
    pub claim_id: String,
    /// Sorted unique lineage roots of usable supporting members.
    pub supporting_roots: Vec<String>,
    /// Sorted unique lineage roots of acquired contradicting members.
    /// Dissent is preserved even when it comes from few members; contradiction
    /// from unknown lineage is kept under the explicit `unknown-lineage`
    /// marker so it is never silently dropped.
    pub contradicting_roots: Vec<String>,
    /// Whether any support traces only to unknown lineage.
    pub support_from_unknown_lineage: bool,
    /// Typed confidence observation for the claim.
    pub confidence: ConfidenceObservation,
    /// Maximum epistemic use of the claim.
    pub max_use: EpistemicUse,
    /// Permitted downstream influence, copied from policy and never broader.
    pub influence_ceiling: InfluenceCeiling,
}

/// Why a complete assurance result cannot be issued.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IncompletenessReason {
    /// At least one member has unknown lineage.
    UnknownLineage,
    /// Fewer members are usable than the denominator expects.
    PartialCoverage,
    /// At least one stale member is present.
    StalePresent,
    /// At least one retracted member is present.
    RetractedPresent,
    /// At least one withheld member is present.
    WithheldPresent,
    /// At least one conflicted member is present.
    ConflictedPresent,
    /// At least one unavailable member is present.
    UnavailablePresent,
    /// At least one malformed, unsupported-format, or unknown member exists.
    MalformedOrUnknownPresent,
    /// At least one claim has both support and contradiction.
    ContradictionUnresolved,
}

/// Completeness of the assurance result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "completeness", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Completeness {
    /// Every member is usable, lineage is known, and no claim is contested.
    Complete,
    /// A complete result is prevented; every reason is listed.
    Incomplete {
        /// All applicable reasons, in stable order.
        reasons: Vec<IncompletenessReason>,
    },
}

/// One explicit blind boundary of the assurance result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "boundary", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlindBoundary {
    /// A source class is excluded by policy.
    PolicyExcludedClass {
        /// The excluded class.
        class: String,
    },
    /// A credential gap bars a member.
    CredentialGap {
        /// The barred member.
        member_id: String,
    },
    /// A member is unavailable.
    UnavailableMember {
        /// The unavailable member.
        member_id: String,
    },
    /// A member was retracted upstream.
    RetractedMember {
        /// The retracted member.
        member_id: String,
    },
    /// A member asserts a conflicting claim.
    ConflictedMember {
        /// The conflicted member.
        member_id: String,
    },
    /// A member has unknown lineage.
    UnknownLineageMember {
        /// The member with unknown lineage.
        member_id: String,
    },
    /// A common-mode risk limits independence.
    CommonModeRisk {
        /// Description of the risk.
        detail: String,
    },
    /// Coverage is partial; the missing members are named.
    PartialCoverageGap {
        /// Non-usable members.
        missing_member_ids: Vec<String>,
    },
}

impl BlindBoundary {
    /// Stable key for deterministic ordering.
    pub fn key(&self) -> String {
        match self {
            Self::PolicyExcludedClass { class } => format!("class:{class}"),
            Self::CredentialGap { member_id } => format!("credential:{member_id}"),
            Self::UnavailableMember { member_id } => format!("unavailable:{member_id}"),
            Self::RetractedMember { member_id } => format!("retracted:{member_id}"),
            Self::ConflictedMember { member_id } => format!("conflicted:{member_id}"),
            Self::UnknownLineageMember { member_id } => format!("lineage:{member_id}"),
            Self::CommonModeRisk { detail } => format!("common-mode:{detail}"),
            Self::PartialCoverageGap { .. } => "partial-coverage".to_owned(),
        }
    }
}

/// Complete role-separated assurance result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct AssuranceResult {
    /// Schema version of this result.
    pub schema_version: String,
    /// Frozen set identity.
    pub set_id: String,
    /// Frozen set revision.
    pub revision: String,
    /// Digest of the frozen input this result was computed from.
    pub set_digest: String,
    /// Evaluation boundary the input was frozen under.
    pub evaluation_boundary: String,
    /// Evaluation time in epoch seconds, carried from the frozen set.
    pub evaluated_at_secs: u64,
    /// Expiry time in epoch seconds, carried from the frozen set.
    pub expires_at_secs: u64,
    /// Deterministic coverage over the exact denominator.
    pub coverage: CoverageReceipt,
    /// Lineage-root independence assessment.
    pub independence: IndependenceAssessment,
    /// Separated per-member axis readout.
    pub member_axes: Vec<MemberAxisRecord>,
    /// Per-claim support ceilings, ordered by claim.
    pub ceilings: Vec<SupportCeiling>,
    /// Whether a complete result could be issued.
    pub completeness: Completeness,
    /// Explicit blind boundaries; nothing is silently omitted.
    pub blind_boundaries: Vec<BlindBoundary>,
    /// Digest over the complete canonical result material.
    pub result_digest: String,
}

/// Why an exact replay did not reproduce the stored result.
#[derive(
    Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayConflict {
    /// The evidence set digest no longer matches the stored result.
    SetDigestChanged,
    /// The recomputed result digest differs: the stored result was altered.
    ResultDigestMismatch,
    /// The evaluation window expired before replay.
    EvaluationExpired,
    /// The claim set changed between freezing and replay.
    ClaimSetChanged,
    /// Usable or expected coverage changed between freezing and replay.
    CoverageChanged,
}

/// Outcome of replaying a stored result against an evidence set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "replay", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReplayOutcome {
    /// Exact replay reproduces the stored digest bit-for-bit.
    Identical {
        /// The reproduced result digest.
        result_digest: String,
    },
    /// The input or the stored result changed; every detected drift is listed.
    Conflict {
        /// All detected drift kinds, in stable order.
        reasons: Vec<ReplayConflict>,
    },
}

/// Assess a frozen evidence set.
///
/// Pure and deterministic: the same frozen input always yields the same
/// result digest. Assessment validates the frozen digest first, so a mutated
/// set never evaluates silently.
pub fn assess(set: &FrozenEvidenceSet) -> Result<AssuranceResult, RoleSeparationError> {
    set.verify_digest()?;
    let usable = usable_members(set);
    let coverage = coverage_receipt(set, &usable)?;
    let independence = independence_assessment(set, &usable);
    let member_axes = member_axes(set);
    let ceilings = support_ceilings(set, &usable);
    let completeness = completeness(set, &usable, &ceilings);
    let blind_boundaries = blind_boundaries(set, &usable, &independence);
    let mut result = AssuranceResult {
        schema_version: ASSURANCE_SCHEMA_VERSION.to_owned(),
        set_id: set.set_id.clone(),
        revision: set.revision.clone(),
        set_digest: set.set_digest.clone(),
        evaluation_boundary: set.evaluation_boundary.clone(),
        evaluated_at_secs: set.evaluated_at_secs,
        expires_at_secs: set.expires_at_secs,
        coverage,
        independence,
        member_axes,
        ceilings,
        completeness,
        blind_boundaries,
        result_digest: String::new(),
    };
    result.result_digest = digest_json(&ResultDigestMaterial::from_result(&result))?;
    Ok(result)
}

/// Replay a stored result against an evidence set.
///
/// Exact replay is idempotent: replaying the stored result against the exact
/// frozen input reproduces the digest. Changed content, lineage, denominator,
/// policy, retraction, or claim state yields a typed conflict; an altered
/// stored result yields `ResultDigestMismatch`.
pub fn replay(
    result: &AssuranceResult,
    set: &FrozenEvidenceSet,
) -> Result<ReplayOutcome, RoleSeparationError> {
    replay_inner(result, set, None)
}

/// Replay with an expiry check at `now_secs`.
///
/// In addition to [`replay`], an evaluation window that expired before `now`
/// yields `EvaluationExpired`.
pub fn replay_at(
    result: &AssuranceResult,
    set: &FrozenEvidenceSet,
    now_secs: u64,
) -> Result<ReplayOutcome, RoleSeparationError> {
    replay_inner(result, set, Some(now_secs))
}

fn replay_inner(
    result: &AssuranceResult,
    set: &FrozenEvidenceSet,
    now_secs: Option<u64>,
) -> Result<ReplayOutcome, RoleSeparationError> {
    set.verify_digest()?;
    let mut reasons = BTreeSet::new();
    if let Some(now) = now_secs
        && now > set.expires_at_secs
    {
        reasons.insert(ReplayConflict::EvaluationExpired);
    }
    if set.set_digest != result.set_digest {
        reasons.insert(ReplayConflict::SetDigestChanged);
    }
    let recomputed = assess(set)?;
    if recomputed.set_digest != result.set_digest {
        reasons.insert(ReplayConflict::SetDigestChanged);
    }
    if recomputed.coverage.expected_members != result.coverage.expected_members
        || recomputed.coverage.usable_members != result.coverage.usable_members
    {
        reasons.insert(ReplayConflict::CoverageChanged);
    }
    let before: BTreeSet<&str> = result
        .ceilings
        .iter()
        .map(|ceiling| ceiling.claim_id.as_str())
        .collect();
    let after: BTreeSet<&str> = recomputed
        .ceilings
        .iter()
        .map(|ceiling| ceiling.claim_id.as_str())
        .collect();
    if before != after {
        reasons.insert(ReplayConflict::ClaimSetChanged);
    }
    // Full-struct comparison, not digest comparison alone: a stored result
    // mutated in place keeps its old digest field, so only recomputing and
    // comparing the whole result detects stripped dissent or ceilings.
    if recomputed.ne(result) {
        reasons.insert(ReplayConflict::ResultDigestMismatch);
    }
    if reasons.is_empty() {
        Ok(ReplayOutcome::Identical {
            result_digest: result.result_digest.clone(),
        })
    } else {
        Ok(ReplayOutcome::Conflict {
            reasons: reasons.into_iter().collect(),
        })
    }
}

#[derive(Serialize)]
struct ResultDigestMaterial<'a> {
    schema_version: &'a str,
    set_digest: &'a str,
    coverage: &'a CoverageReceipt,
    independence: &'a IndependenceAssessment,
    member_axes: &'a [MemberAxisRecord],
    ceilings: &'a [SupportCeiling],
    completeness: &'a Completeness,
    blind_boundaries: &'a [BlindBoundary],
}

impl<'a> ResultDigestMaterial<'a> {
    fn from_result(result: &'a AssuranceResult) -> Self {
        Self {
            schema_version: &result.schema_version,
            set_digest: &result.set_digest,
            coverage: &result.coverage,
            independence: &result.independence,
            member_axes: &result.member_axes,
            ceilings: &result.ceilings,
            completeness: &result.completeness,
            blind_boundaries: &result.blind_boundaries,
        }
    }
}

/// Members usable as evidence: acquired with complete lineage and a
/// policy-included class. Integrity alone never suffices: lineage-incomplete
/// and policy-excluded members stay out of usable coverage and support.
fn usable_members(set: &FrozenEvidenceSet) -> BTreeSet<String> {
    set.observations
        .iter()
        .filter(|observation| {
            matches!(
                observation.disposition,
                MemberDisposition::Acquired {
                    lineage_complete: true,
                    ..
                }
            ) && set.member(&observation.member_id).is_some_and(|member| {
                !set.policy
                    .excluded_source_classes
                    .iter()
                    .any(|class| class == &member.source_class)
            })
        })
        .map(|observation| observation.member_id.clone())
        .collect()
}

fn coverage_receipt(
    set: &FrozenEvidenceSet,
    usable: &BTreeSet<String>,
) -> Result<CoverageReceipt, RoleSeparationError> {
    const DISPOSITIONS: [&str; 9] = [
        "acquired",
        "unavailable",
        "withheld",
        "stale",
        "conflicted",
        "retracted",
        "malformed",
        "unsupported_format",
        "unknown",
    ];
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for observation in &set.observations {
        *counts.entry(observation.disposition.key()).or_default() += 1;
    }
    let per_disposition = DISPOSITIONS
        .iter()
        .map(|key| DispositionCount {
            disposition: (*key).to_owned(),
            count: counts.get(key).copied().unwrap_or_default(),
        })
        .collect();
    let mut excluded_class_members: Vec<String> = set
        .observations
        .iter()
        .filter(|observation| {
            matches!(observation.disposition, MemberDisposition::Acquired { .. })
                && set.member(&observation.member_id).is_some_and(|member| {
                    set.policy
                        .excluded_source_classes
                        .iter()
                        .any(|class| class == &member.source_class)
                })
        })
        .map(|observation| observation.member_id.clone())
        .collect();
    excluded_class_members.sort();
    let mut member_ids: Vec<&str> = set
        .members
        .iter()
        .map(|member| member.member_id.as_str())
        .collect();
    member_ids.sort_unstable();
    let denominator_digest = digest_json(&DenominatorMaterial {
        member_ids: &member_ids,
        policy_digest: &set.policy_digest,
    })?;
    Ok(CoverageReceipt {
        expected_members: set.members.len(),
        usable_members: usable.len(),
        per_disposition,
        excluded_class_members,
        denominator_digest,
    })
}

#[derive(Serialize)]
struct DenominatorMaterial<'a> {
    member_ids: &'a [&'a str],
    policy_digest: &'a str,
}

fn independence_assessment(
    set: &FrozenEvidenceSet,
    usable: &BTreeSet<String>,
) -> IndependenceAssessment {
    let mut roots: BTreeSet<&str> = BTreeSet::new();
    let mut unknown_lineage_members: Vec<String> = Vec::new();
    let mut by_root: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for member in &set.members {
        match member.lineage.root.as_deref() {
            Some(root) => {
                roots.insert(root);
                by_root
                    .entry(root)
                    .or_default()
                    .push(member.member_id.clone());
            }
            None => unknown_lineage_members.push(member.member_id.clone()),
        }
    }
    unknown_lineage_members.sort();
    let mut mirror_groups: Vec<MirrorGroup> = by_root
        .iter()
        .filter(|(_, members)| members.len() > 1)
        .map(|(root, members)| {
            let mut member_ids = members.clone();
            member_ids.sort();
            MirrorGroup {
                lineage_root: (*root).to_owned(),
                member_ids,
            }
        })
        .collect();
    mirror_groups.sort_by(|left, right| left.lineage_root.cmp(&right.lineage_root));

    let mut supporting_roots: BTreeSet<&str> = BTreeSet::new();
    let mut routes: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    let mut generators: BTreeMap<&str, Vec<String>> = BTreeMap::new();
    for linkage in &set.linkages {
        if linkage.stance != SupportStance::Supports || !usable.contains(&linkage.member_id) {
            continue;
        }
        if let Some(member) = set.member(&linkage.member_id)
            && let Some(root) = member.lineage.root.as_deref()
        {
            supporting_roots.insert(root);
            routes
                .entry(member.lineage.acquisition_route.as_str())
                .or_default()
                .push(member.member_id.clone());
            if let Some(generator) = member.lineage.generator.as_deref() {
                generators
                    .entry(generator)
                    .or_default()
                    .push(member.member_id.clone());
            }
        }
    }
    let mut common_mode_flags: Vec<CommonModeFlag> = Vec::new();
    for (route, members) in &routes {
        if members.len() > 1 {
            common_mode_flags.push(CommonModeFlag {
                kind: CommonModeKind::SharedAcquisitionRoute,
                detail: (*route).to_owned(),
            });
        }
    }
    for (generator, members) in &generators {
        if members.len() > 1 {
            common_mode_flags.push(CommonModeFlag {
                kind: CommonModeKind::SharedGenerator,
                detail: (*generator).to_owned(),
            });
        }
    }
    let supporting_count: usize = routes.values().map(Vec::len).sum();
    if supporting_roots.len() == 1
        && supporting_count > 1
        && let Some(root) = supporting_roots.iter().next()
    {
        common_mode_flags.push(CommonModeFlag {
            kind: CommonModeKind::SingleRootForAllSupport,
            detail: (*root).to_owned(),
        });
    }
    common_mode_flags.sort_by(|left, right| {
        (kind_rank(left.kind), &left.detail).cmp(&(kind_rank(right.kind), &right.detail))
    });
    IndependenceAssessment {
        unique_lineage_roots: roots.iter().map(ToString::to_string).collect(),
        unknown_lineage_members,
        mirror_groups,
        independent_support_count: supporting_roots.len(),
        common_mode_flags,
    }
}

fn kind_rank(kind: CommonModeKind) -> u8 {
    match kind {
        CommonModeKind::SharedAcquisitionRoute => 0,
        CommonModeKind::SharedGenerator => 1,
        CommonModeKind::SingleRootForAllSupport => 2,
    }
}

fn member_axes(set: &FrozenEvidenceSet) -> Vec<MemberAxisRecord> {
    let mut root_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for member in &set.members {
        if let Some(root) = member.lineage.root.as_deref() {
            *root_counts.entry(root).or_default() += 1;
        }
    }
    let mut records: Vec<MemberAxisRecord> = set
        .observations
        .iter()
        .map(|observation| {
            let member = set.member(&observation.member_id);
            let linkage = set.linkage(&observation.member_id);
            axis_record(
                set,
                observation.member_id.as_str(),
                member,
                linkage,
                &root_counts,
            )
        })
        .collect();
    records.sort_by(|left, right| left.member_id.cmp(&right.member_id));
    records
}

fn axis_record(
    set: &FrozenEvidenceSet,
    member_id: &str,
    member: Option<&crate::portfolio::ExpectedMember>,
    linkage: Option<&crate::portfolio::ClaimLinkage>,
    root_counts: &BTreeMap<&str, usize>,
) -> MemberAxisRecord {
    let disposition = set
        .observation(member_id)
        .map(|observation| &observation.disposition);
    let provenance = match (member.and_then(|m| m.lineage.root.as_deref()), disposition) {
        (None, _) => ProvenanceState::UnknownLineage,
        (
            Some(_),
            Some(MemberDisposition::Acquired {
                lineage_complete: true,
                ..
            }),
        ) => ProvenanceState::Complete,
        _ => ProvenanceState::IncompleteLineage,
    };
    let integrity = match disposition {
        Some(
            MemberDisposition::Acquired { .. }
            | MemberDisposition::Stale { .. }
            | MemberDisposition::Conflicted { .. },
        ) => IntegrityState::DigestMatched,
        _ => IntegrityState::NotAcquired,
    };
    let availability = match disposition {
        Some(MemberDisposition::Acquired { .. } | MemberDisposition::Stale { .. }) => {
            AvailabilityState::Observed
        }
        Some(MemberDisposition::Withheld { .. }) => AvailabilityState::WithheldByPolicy,
        Some(MemberDisposition::Retracted { .. }) => AvailabilityState::RetractedUpstream,
        Some(MemberDisposition::Unavailable { .. }) => AvailabilityState::Unavailable,
        _ => AvailabilityState::Uninterpretable,
    };
    let accessibility = match disposition {
        Some(MemberDisposition::Withheld { policy_ref, .. }) => {
            if set
                .policy
                .credential_gap_refs
                .iter()
                .any(|gap| gap == policy_ref)
            {
                AccessibilityState::CredentialGap
            } else {
                AccessibilityState::PolicyExcluded
            }
        }
        Some(MemberDisposition::UnsupportedFormat { .. }) => AccessibilityState::UnsupportedFormat,
        Some(
            MemberDisposition::Acquired { .. }
            | MemberDisposition::Stale { .. }
            | MemberDisposition::Conflicted { .. }
            | MemberDisposition::Retracted { .. },
        ) => AccessibilityState::Accessible,
        _ => AccessibilityState::Unknown,
    };
    let independence = match member.and_then(|m| m.lineage.root.as_deref()) {
        None => IndependenceState::UnknownLineage,
        Some(root) => match disposition {
            Some(
                MemberDisposition::Acquired { .. }
                | MemberDisposition::Stale { .. }
                | MemberDisposition::Conflicted { .. },
            ) => {
                if root_counts.get(root).copied().unwrap_or_default() > 1 {
                    IndependenceState::SharedRoot
                } else {
                    IndependenceState::UniqueRoot
                }
            }
            _ => IndependenceState::NotApplicable,
        },
    };
    let (relevance, stance) = match linkage.map(|link| (link.stance, link.claim_id.as_deref())) {
        Some((SupportStance::Supports | SupportStance::Contradicts, _)) => (
            RelevanceState::DirectlyLinked,
            linkage.map_or(SupportStance::Unlinked, |l| l.stance),
        ),
        Some((SupportStance::ContextOnly, _)) => {
            (RelevanceState::Contextual, SupportStance::ContextOnly)
        }
        _ => (RelevanceState::Unlinked, SupportStance::Unlinked),
    };
    let contradiction = contradiction_state(set, member_id, linkage);
    MemberAxisRecord {
        member_id: member_id.to_owned(),
        provenance,
        integrity,
        availability,
        accessibility,
        independence,
        relevance,
        stance,
        contradiction,
    }
}

fn contradiction_state(
    set: &FrozenEvidenceSet,
    member_id: &str,
    linkage: Option<&crate::portfolio::ClaimLinkage>,
) -> MemberContradiction {
    let Some(link) = linkage else {
        return MemberContradiction::None;
    };
    let Some(claim_id) = link.claim_id.as_deref() else {
        return MemberContradiction::None;
    };
    if link.stance == SupportStance::Contradicts {
        return MemberContradiction::AssertsAgainstClaim;
    }
    if link.stance != SupportStance::Supports && link.stance != SupportStance::ContextOnly {
        return MemberContradiction::None;
    }
    let contested = set.linkages.iter().any(|peer| {
        peer.member_id != member_id
            && peer.claim_id.as_deref() == Some(claim_id)
            && peer.stance == SupportStance::Contradicts
            && set.observation(&peer.member_id).is_some_and(|observation| {
                matches!(
                    observation.disposition,
                    MemberDisposition::Acquired { .. }
                        | MemberDisposition::Stale { .. }
                        | MemberDisposition::Conflicted { .. }
                )
            })
    });
    if contested {
        MemberContradiction::ContestedByPeers
    } else {
        MemberContradiction::None
    }
}

fn support_ceilings(set: &FrozenEvidenceSet, usable: &BTreeSet<String>) -> Vec<SupportCeiling> {
    let mut claims: BTreeSet<&str> = BTreeSet::new();
    for linkage in &set.linkages {
        if let Some(claim_id) = linkage.claim_id.as_deref() {
            claims.insert(claim_id);
        }
    }
    claims
        .iter()
        .map(|claim_id| claim_ceiling(set, usable, claim_id))
        .collect()
}

fn claim_ceiling(
    set: &FrozenEvidenceSet,
    usable: &BTreeSet<String>,
    claim_id: &str,
) -> SupportCeiling {
    let mut supporting_roots: BTreeSet<String> = BTreeSet::new();
    let mut contradicting_roots: BTreeSet<String> = BTreeSet::new();
    let mut support_from_unknown_lineage = false;
    for linkage in &set.linkages {
        if linkage.claim_id.as_deref() != Some(claim_id) {
            continue;
        }
        let Some(member) = set.member(&linkage.member_id) else {
            continue;
        };
        let observation = set.observation(&linkage.member_id);
        let acquired = observation.is_some_and(|obs| {
            matches!(
                obs.disposition,
                MemberDisposition::Acquired { .. }
                    | MemberDisposition::Stale { .. }
                    | MemberDisposition::Conflicted { .. }
            )
        });
        match linkage.stance {
            SupportStance::Supports => {
                if !usable.contains(&linkage.member_id) {
                    continue;
                }
                match member.lineage.root.as_deref() {
                    Some(root) => {
                        supporting_roots.insert(root.to_owned());
                    }
                    None => support_from_unknown_lineage = true,
                }
            }
            SupportStance::Contradicts => {
                if !acquired {
                    continue;
                }
                match member.lineage.root.as_deref() {
                    Some(root) => {
                        contradicting_roots.insert(root.to_owned());
                    }
                    None => {
                        contradicting_roots.insert("unknown-lineage".to_owned());
                    }
                }
            }
            SupportStance::ContextOnly | SupportStance::Unlinked => {}
        }
    }
    let confidence = if supporting_roots.is_empty() && contradicting_roots.is_empty() {
        if support_from_unknown_lineage {
            ConfidenceObservation::UnknownBasis
        } else {
            ConfidenceObservation::InsufficientBasis
        }
    } else if contradicting_roots.is_empty() {
        ConfidenceObservation::SupportedByIndependentRoots
    } else {
        ConfidenceObservation::ContestedByIndependentRoots
    };
    let max_use = if supporting_roots.is_empty() && !support_from_unknown_lineage {
        EpistemicUse::NoUse
    } else if contradicting_roots.is_empty() {
        EpistemicUse::EvidenceCandidate
    } else {
        EpistemicUse::HypothesisCandidate
    };
    SupportCeiling {
        claim_id: claim_id.to_owned(),
        supporting_roots: supporting_roots.into_iter().collect(),
        contradicting_roots: contradicting_roots.into_iter().collect(),
        support_from_unknown_lineage,
        confidence,
        max_use,
        influence_ceiling: set.policy.allowed_influence,
    }
}

fn completeness(
    set: &FrozenEvidenceSet,
    usable: &BTreeSet<String>,
    ceilings: &[SupportCeiling],
) -> Completeness {
    let mut reasons: BTreeSet<IncompletenessReason> = BTreeSet::new();
    if usable.len() < set.members.len() {
        reasons.insert(IncompletenessReason::PartialCoverage);
    }
    for observation in &set.observations {
        match &observation.disposition {
            MemberDisposition::Acquired { .. } => {}
            MemberDisposition::Unavailable { .. } => {
                reasons.insert(IncompletenessReason::UnavailablePresent);
            }
            MemberDisposition::Withheld { .. } => {
                reasons.insert(IncompletenessReason::WithheldPresent);
            }
            MemberDisposition::Stale { .. } => {
                reasons.insert(IncompletenessReason::StalePresent);
            }
            MemberDisposition::Conflicted { .. } => {
                reasons.insert(IncompletenessReason::ConflictedPresent);
            }
            MemberDisposition::Retracted { .. } => {
                reasons.insert(IncompletenessReason::RetractedPresent);
            }
            MemberDisposition::Malformed { .. }
            | MemberDisposition::UnsupportedFormat { .. }
            | MemberDisposition::Unknown { .. } => {
                reasons.insert(IncompletenessReason::MalformedOrUnknownPresent);
            }
        }
        if set
            .member(&observation.member_id)
            .is_some_and(|member| member.lineage.root.is_none())
        {
            reasons.insert(IncompletenessReason::UnknownLineage);
        }
    }
    if ceilings.iter().any(|ceiling| {
        !ceiling.supporting_roots.is_empty() && !ceiling.contradicting_roots.is_empty()
    }) {
        reasons.insert(IncompletenessReason::ContradictionUnresolved);
    }
    if reasons.is_empty() {
        Completeness::Complete
    } else {
        Completeness::Incomplete {
            reasons: rank_reasons(reasons),
        }
    }
}

fn rank_reasons(reasons: BTreeSet<IncompletenessReason>) -> Vec<IncompletenessReason> {
    let mut ordered: Vec<IncompletenessReason> = reasons.into_iter().collect();
    ordered.sort_by_key(|reason| reason_rank(*reason));
    ordered
}

fn reason_rank(reason: IncompletenessReason) -> u8 {
    match reason {
        IncompletenessReason::UnknownLineage => 0,
        IncompletenessReason::PartialCoverage => 1,
        IncompletenessReason::StalePresent => 2,
        IncompletenessReason::RetractedPresent => 3,
        IncompletenessReason::WithheldPresent => 4,
        IncompletenessReason::ConflictedPresent => 5,
        IncompletenessReason::UnavailablePresent => 6,
        IncompletenessReason::MalformedOrUnknownPresent => 7,
        IncompletenessReason::ContradictionUnresolved => 8,
    }
}

fn blind_boundaries(
    set: &FrozenEvidenceSet,
    usable: &BTreeSet<String>,
    independence: &IndependenceAssessment,
) -> Vec<BlindBoundary> {
    let mut boundaries: Vec<BlindBoundary> = Vec::new();
    for class in &set.policy.excluded_source_classes {
        boundaries.push(BlindBoundary::PolicyExcludedClass {
            class: class.clone(),
        });
    }
    for observation in &set.observations {
        match &observation.disposition {
            MemberDisposition::Acquired { .. }
            | MemberDisposition::Stale { .. }
            | MemberDisposition::Malformed { .. }
            | MemberDisposition::UnsupportedFormat { .. }
            | MemberDisposition::Unknown { .. } => {}
            MemberDisposition::Unavailable { .. } => {
                boundaries.push(BlindBoundary::UnavailableMember {
                    member_id: observation.member_id.clone(),
                });
            }
            MemberDisposition::Withheld { policy_ref, .. } => {
                if set
                    .policy
                    .credential_gap_refs
                    .iter()
                    .any(|gap| gap == policy_ref)
                {
                    boundaries.push(BlindBoundary::CredentialGap {
                        member_id: observation.member_id.clone(),
                    });
                } else {
                    boundaries.push(BlindBoundary::PolicyExcludedClass {
                        class: policy_ref.clone(),
                    });
                }
            }
            MemberDisposition::Conflicted { .. } => {
                boundaries.push(BlindBoundary::ConflictedMember {
                    member_id: observation.member_id.clone(),
                });
            }
            MemberDisposition::Retracted { .. } => {
                boundaries.push(BlindBoundary::RetractedMember {
                    member_id: observation.member_id.clone(),
                });
            }
        }
    }
    for member_id in &independence.unknown_lineage_members {
        boundaries.push(BlindBoundary::UnknownLineageMember {
            member_id: member_id.clone(),
        });
    }
    for flag in &independence.common_mode_flags {
        boundaries.push(BlindBoundary::CommonModeRisk {
            detail: format!("{:?}:{}", flag.kind, flag.detail),
        });
    }
    let missing: Vec<String> = set
        .members
        .iter()
        .filter(|member| !usable.contains(&member.member_id))
        .map(|member| member.member_id.clone())
        .collect();
    if !missing.is_empty() {
        boundaries.push(BlindBoundary::PartialCoverageGap {
            missing_member_ids: missing,
        });
    }
    boundaries.sort_by_key(BlindBoundary::key);
    boundaries.dedup_by(|left, right| left.key() == right.key());
    boundaries
}
