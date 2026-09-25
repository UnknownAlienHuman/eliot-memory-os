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

fn grant(
    id: &str,
    parent: Option<&str>,
    root: &str,
    binding: AuthorityBinding,
) -> Result<CapabilityGrant, Box<dyn Error>> {
    Ok(CapabilityGrant {
        grant_id: GrantId::new(id)?,
        parent_grant_id: parent.map(GrantId::new).transpose()?,
        authority_root_ref: root.to_owned(),
        issuer: PrincipalRef::new("governor")?,
        holder: PrincipalRef::new("holder-1")?,
        authority: AuthoritySet::new(
            ["op.read".to_owned()],
            ["res:1".to_owned()],
            EffectClass::Read,
        )?,
        inherited_source_ceiling: None,
        binding,
        issued_at: LogicalTime::new(1),
        expires_at: LogicalTime::new(10_000),
        max_uses: 1,
        status: GrantStatus::Active,
    })
}

fn chain_graph() -> Result<GrantGraph, Box<dyn Error>> {
    let binding = test_binding()?;
    GrantGraph::from_grants(
        [
            grant("grant-origin", None, "root-test", binding.clone())?,
            grant(
                "grant-mid",
                Some("grant-origin"),
                "root-test",
                binding.clone(),
            )?,
            grant(
                "grant-leaf",
                Some("grant-mid"),
                "root-test",
                binding.clone(),
            )?,
            grant(
                "grant-tip",
                Some("grant-leaf"),
                "root-test",
                binding.clone(),
            )?,
            grant("grant-other", None, "root-other", binding)?,
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
