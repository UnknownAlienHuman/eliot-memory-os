//! Owner-level descendant-closure enumeration (`#2100`).
//!
//! `GrantGraph::delegated_closure` is the Governor-side lineage primitive
//! behind durable closure revocation: the graph owner declares the complete
//! affected set at one revision so the Kernel never fences from caller
//! material or process memory alone.

use std::error::Error;

use eliot_authority::{
    AuthorityError, AuthoritySet, CapabilityGrant, GrantClosureDelegation, GrantGraph, GrantId,
    GrantStatus, LogicalTime, PrincipalRef,
};
use eliot_contracts::{ContractId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_receipts::{AuthorityBinding, EffectClass, ProofCeiling};

type TestResult = Result<(), Box<dyn Error>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn test_binding() -> Result<AuthorityBinding, Box<dyn Error>> {
    let epoch = EpochId::new(
        EpochLineageId::new(TEST_LINEAGE)?,
        std::num::NonZeroU64::new(7).expect("nonzero test sequence"),
    )?;
    let fence = StateFence::new(epoch.clone(), ResourceGeneration::new(1)?);
    Ok(AuthorityBinding {
        authority_id: ContractId::new("authority:test")?,
        authority_owner: "G-01".to_owned(),
        authority_epoch: epoch,
        state_fence: fence,
        allowed_effect: EffectClass::ExternalEffect,
        proof_ceiling: ProofCeiling::ObservedExternalEffect,
    })
}

/// Builds one chain entry that satisfies the narrowing edge rules of
/// `GrantGraph::from_grants`: a delegated child is issued by its parent
/// holder and never widens the parent authority, expiry, or use budget
/// (I6.15 "each child is an intersection of parent authority, requested
/// scope and current policy"). The `Delegation` tag is what makes the chain
/// strictly narrower at every hop — equal operations, resources, expiry and
/// budget would be rejected as `GrantNotNarrower` before any closure could be
/// enumerated.
fn grant(
    id: &str,
    parent: Option<&str>,
    root: &str,
    delegation: Delegation,
    binding: AuthorityBinding,
) -> Result<CapabilityGrant, Box<dyn Error>> {
    Ok(CapabilityGrant {
        grant_id: GrantId::new(id)?,
        parent_grant_id: parent.map(GrantId::new).transpose()?,
        authority_root_ref: root.to_owned(),
        // A child is issued by the holder of the parent it narrows.
        issuer: PrincipalRef::new(match parent {
            Some(parent) => parent_holder(parent),
            None => "governor".to_owned(),
        })?,
        holder: PrincipalRef::new(parent_holder(id))?,
        authority: AuthoritySet::new(
            ["op.read".to_owned(), "op.write".to_owned()],
            ["res:1".to_owned()],
            delegation.effect(),
        )?,
        inherited_source_ceiling: None,
        binding,
        issued_at: LogicalTime::new(1),
        expires_at: LogicalTime::new(delegation.expires_at),
        max_uses: delegation.max_uses,
        status: GrantStatus::Active,
    })
}

/// The principal that holds the named chain entry, matching the holder this
/// fixture derives from the grant id.
fn parent_holder(id: &str) -> String {
    format!("holder-{id}")
}

/// One strictly narrowing step of the fixture chain.
#[derive(Clone, Copy)]
struct Delegation {
    effect: EffectClass,
    expires_at: u64,
    max_uses: u32,
}

impl Delegation {
    fn root() -> Self {
        Self {
            effect: EffectClass::ExternalEffect,
            expires_at: 10_000,
            max_uses: 4,
        }
    }

    fn narrow(expires_at: u64, max_uses: u32) -> Self {
        Self {
            effect: EffectClass::Read,
            expires_at,
            max_uses,
        }
    }
}

fn chain_graph() -> Result<GrantGraph, Box<dyn Error>> {
    let binding = test_binding()?;
    GrantGraph::from_grants(
        [
            grant(
                "grant-origin",
                None,
                "root-test",
                Delegation::root(),
                binding.clone(),
            )?,
            grant(
                "grant-mid",
                Some("grant-origin"),
                "root-test",
                Delegation::narrow(9_000, 3),
                binding.clone(),
            )?,
            grant(
                "grant-leaf",
                Some("grant-mid"),
                "root-test",
                Delegation::narrow(8_000, 2),
                binding.clone(),
            )?,
            grant(
                "grant-tip",
                Some("grant-leaf"),
                "root-test",
                Delegation::narrow(7_000, 1),
                binding.clone(),
            )?,
            grant(
                "grant-other",
                None,
                "root-other",
                Delegation::root(),
                binding,
            )?,
        ],
        7,
    )
    .map_err(Into::into)
}

#[test]
fn delegated_closure_covers_exact_descendants_in_parent_order() -> TestResult {
    let graph = chain_graph()?;
    let closure: GrantClosureDelegation =
        graph.delegated_closure(&GrantId::new("grant-origin")?)?;
    assert_eq!(closure.authority_root_ref, "root-test");
    assert_eq!(closure.revision, 7);
    let ids: Vec<&str> = closure
        .members
        .iter()
        .map(|member| member.grant_id.as_str())
        .collect();
    assert_eq!(
        ids,
        ["grant-origin", "grant-mid", "grant-leaf", "grant-tip"]
    );
    // Every non-target member names an earlier parent.
    let mut seen = std::collections::BTreeSet::new();
    seen.insert("grant-origin");
    for member in closure.members.iter().skip(1) {
        let parent = member
            .parent_grant_id
            .as_ref()
            .expect("child names a parent");
        assert!(seen.contains(parent.as_str()));
        seen.insert(member.grant_id.as_str());
    }
    Ok(())
}

#[test]
fn delegated_closure_roots_mid_chain_subtree() -> TestResult {
    let graph = chain_graph()?;
    let closure = graph.delegated_closure(&GrantId::new("grant-mid")?)?;
    let ids: Vec<&str> = closure
        .members
        .iter()
        .map(|member| member.grant_id.as_str())
        .collect();
    assert_eq!(ids, ["grant-mid", "grant-leaf", "grant-tip"]);
    assert_eq!(
        closure.members[0]
            .parent_grant_id
            .as_ref()
            .expect("mid keeps its parent")
            .as_str(),
        "grant-origin"
    );
    Ok(())
}

#[test]
fn delegated_closure_rejects_unknown_target() -> TestResult {
    let graph = chain_graph()?;
    assert!(matches!(
        graph.delegated_closure(&GrantId::new("grant-ghost")?),
        Err(AuthorityError::MissingParent(_))
    ));
    Ok(())
}
