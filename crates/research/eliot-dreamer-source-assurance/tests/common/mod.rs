//! Shared finite fixtures for the role-separation edge proofs.
//!
//! All digests are computed at runtime from fixed seeds: no canned hashes,
//! no network, no store, no model. The portfolio below exercises mirrors,
//! common lineage, an unavailable member, a retraction, a conflict, stale
//! evidence, a credentialed gap, and a partial denominator in one frozen set.

use eliot_dreamer_source_assurance::{
    ASSURANCE_POLICY_VERSION, AssurancePolicy, ClaimLinkage, ExpectedMember, FreezeInput,
    FrozenEvidenceSet, InfluenceCeiling, LineageAttribution, MemberDisposition, MemberObservation,
    RoleSeparationError, SupportStance,
};

/// Evaluation boundary shared by every fixture member and policy.
pub const BOUNDARY: &str = "research-evidence/v1";
/// Claim supported by roots A and B and contradicted by root C.
pub const CLAIM_ONE: &str = "claim-1";
/// Claim with no usable basis: its only supporter is unavailable.
pub const CLAIM_TWO: &str = "claim-2";

/// Compute a deterministic digest for a fixture seed.
pub fn digest(seed: &str) -> String {
    blake3::hash(seed.as_bytes()).to_hex().to_string()
}

fn attribution(root: Option<&str>, route: &str, generator: Option<&str>) -> LineageAttribution {
    LineageAttribution {
        root: root.map(str::to_owned),
        acquisition_route: route.to_owned(),
        publisher: "research-publisher".to_owned(),
        generator: generator.map(str::to_owned),
    }
}

fn member(
    id: &str,
    seed: &str,
    root: Option<&str>,
    route: &str,
    generator: Option<&str>,
    class: &str,
    citations: &[&str],
) -> ExpectedMember {
    ExpectedMember {
        member_id: id.to_owned(),
        content_digest: digest(seed),
        lineage: attribution(root, route, generator),
        source_class: class.to_owned(),
        citation_refs: citations.iter().map(ToString::to_string).collect(),
    }
}

fn observe(id: &str, seed: &str) -> MemberObservation {
    MemberObservation {
        member_id: id.to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        disposition: MemberDisposition::Acquired {
            observed_digest: digest(seed),
            lineage_complete: true,
        },
    }
}

fn link(id: &str, claim: Option<&str>, stance: SupportStance) -> ClaimLinkage {
    ClaimLinkage {
        member_id: id.to_owned(),
        claim_id: claim.map(str::to_owned),
        stance,
    }
}

/// Policy shared by every fixture: one credential gap, no class exclusions.
pub fn fixture_policy() -> AssurancePolicy {
    AssurancePolicy {
        policy_version: ASSURANCE_POLICY_VERSION.to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        excluded_source_classes: Vec::new(),
        credential_gap_refs: vec!["gap-cred-1".to_owned()],
        allowed_influence: InfluenceCeiling::CandidateEvidence,
    }
}

/// Freeze the rich edge-proof portfolio.
///
/// Members: `m1` (root A, supports claim-1), `m2` (exact mirror of `m1`:
/// same bytes, same root A, other citations, supports claim-1), `m3`
/// (root B, supports claim-1), `m4` (root C, contradicts claim-1),
/// `m5` (root D, stale), `m6` (root E, retracted), `m7` (withheld under
/// the credential gap), `m8` (root F, unavailable, supports claim-2).
pub fn freeze_rich_portfolio() -> Result<FrozenEvidenceSet, RoleSeparationError> {
    let input = FreezeInput {
        set_id: "research-set-1".to_owned(),
        revision: "rev-1".to_owned(),
        evaluation_boundary: BOUNDARY.to_owned(),
        evaluated_at_secs: 1_000,
        expires_at_secs: 2_000,
        members: rich_members(),
        observations: rich_observations(),
        linkages: rich_linkages(),
        policy: fixture_policy(),
    };
    FrozenEvidenceSet::freeze(input)
}

/// Expected members of the rich edge-proof portfolio.
fn rich_members() -> Vec<ExpectedMember> {
    let mirror_bytes = "bytes:m1";
    vec![
        member(
            "m1",
            mirror_bytes,
            Some("root-a"),
            "route-1",
            None,
            "paper",
            &["https://origin.invalid/paper-1"],
        ),
        member(
            "m2",
            mirror_bytes,
            Some("root-a"),
            "route-2",
            None,
            "paper",
            &[
                "https://mirror-a.invalid/paper-1",
                "https://mirror-b.invalid/paper-1",
            ],
        ),
        member(
            "m3",
            "bytes:m3",
            Some("root-b"),
            "route-1",
            Some("shared-run"),
            "paper",
            &["https://origin.invalid/paper-3"],
        ),
        member(
            "m4",
            "bytes:m4",
            Some("root-c"),
            "route-3",
            Some("shared-run"),
            "paper",
            &["https://origin.invalid/paper-4"],
        ),
        member(
            "m5",
            "bytes:m5",
            Some("root-d"),
            "route-4",
            None,
            "paper",
            &["https://origin.invalid/paper-5"],
        ),
        member(
            "m6",
            "bytes:m6",
            Some("root-e"),
            "route-5",
            None,
            "paper",
            &["https://origin.invalid/paper-6"],
        ),
        member(
            "m7",
            "bytes:m7",
            Some("root-g"),
            "route-6",
            None,
            "restricted",
            &["https://origin.invalid/paper-7"],
        ),
        member(
            "m8",
            "bytes:m8",
            Some("root-f"),
            "route-7",
            None,
            "paper",
            &["https://origin.invalid/paper-8"],
        ),
    ]
}

/// Observations of the rich edge-proof portfolio.
fn rich_observations() -> Vec<MemberObservation> {
    let mirror_bytes = "bytes:m1";
    vec![
        observe("m1", mirror_bytes),
        observe("m2", mirror_bytes),
        observe("m3", "bytes:m3"),
        MemberObservation {
            member_id: "m4".to_owned(),
            evaluation_boundary: BOUNDARY.to_owned(),
            disposition: MemberDisposition::Conflicted {
                observed_digest: digest("bytes:m4"),
                conflicting_claim_id: CLAIM_ONE.to_owned(),
            },
        },
        MemberObservation {
            member_id: "m5".to_owned(),
            evaluation_boundary: BOUNDARY.to_owned(),
            disposition: MemberDisposition::Stale {
                observed_digest: digest("bytes:m5"),
                observed_at_secs: 100,
                frontier_generation: 1,
            },
        },
        MemberObservation {
            member_id: "m6".to_owned(),
            evaluation_boundary: BOUNDARY.to_owned(),
            disposition: MemberDisposition::Retracted {
                retraction_ref: "retraction-6".to_owned(),
            },
        },
        MemberObservation {
            member_id: "m7".to_owned(),
            evaluation_boundary: BOUNDARY.to_owned(),
            disposition: MemberDisposition::Withheld {
                policy_ref: "gap-cred-1".to_owned(),
                reason: "credentialed source".to_owned(),
            },
        },
        MemberObservation {
            member_id: "m8".to_owned(),
            evaluation_boundary: BOUNDARY.to_owned(),
            disposition: MemberDisposition::Unavailable {
                reason: "host unreachable".to_owned(),
            },
        },
    ]
}

/// Claim linkages of the rich edge-proof portfolio.
fn rich_linkages() -> Vec<ClaimLinkage> {
    vec![
        link("m1", Some(CLAIM_ONE), SupportStance::Supports),
        link("m2", Some(CLAIM_ONE), SupportStance::Supports),
        link("m3", Some(CLAIM_ONE), SupportStance::Supports),
        link("m4", Some(CLAIM_ONE), SupportStance::Contradicts),
        link("m5", None, SupportStance::Unlinked),
        link("m6", None, SupportStance::Unlinked),
        link("m7", Some(CLAIM_ONE), SupportStance::Supports),
        link("m8", Some(CLAIM_TWO), SupportStance::Supports),
    ]
}
