//! Transitive influence-revocation recovery acceptance (issue #686).
//!
//! Proves the shipped authority decision edge: revoking an origin through
//! CURRENT revocation-history evidence suppresses the origin and its
//! dependent grants across snapshot recovery (never revived), unrelated
//! valid grants stay restorable, and missing, stale, or unknown evidence
//! refuses restoration with a typed error instead of an empty closure.
//!
//! The denominator identities come from the frozen
//! `tests/data/transitive-revocation/denominator.json` fixture; fences and
//! bindings are built with the same test constructors as the in-crate
//! recovery tests. `eliot-influence` itself is consumed read-only through
//! its closure shape: closures are built directly as the evidence the
//! revocation-history named read would serve.

#![allow(clippy::expect_used)] // test-only panic-acceptable, mirroring the in-crate recovery tests.

use std::collections::BTreeSet;

use eliot_authority::{
    AuthoritySet, CapabilityGrant, EffectAuthorizer, GrantGraph, GrantId, GrantStatus, LogicalTime,
    PrincipalRef, RevocationHistoryError, RevocationHistoryEvidence, SuppressionCause,
};
use eliot_contracts::{ContractId, EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_receipts::{
    AuthorityBinding, EffectClass, ProofCeiling, SessionBinding, WorkScopeBinding,
};
use eliot_security_contracts::{InfluenceDependencyClosure, InfluenceState, RevocationReason};
use std::num::NonZeroU64;

const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

#[derive(Debug, serde::Deserialize)]
struct Denominator {
    authority_root: String,
    origin_grant: String,
    mid_grant: String,
    leaf_grant: String,
    tip_grant: String,
    unrelated_grant: String,
    unrelated_root: String,
    origin_closure_id: String,
    mid_closure_id: String,
    source_revision: u64,
    invalidation_reason: String,
    origin_affected: Vec<String>,
    mid_affected: Vec<String>,
}

fn denominator() -> Denominator {
    let bytes = include_bytes!("data/transitive-revocation/denominator.json");
    serde_json::from_slice(bytes).expect("frozen denominator fixture parses")
}

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
        NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"))
}

fn binding(fence: &StateFence) -> AuthorityBinding {
    AuthorityBinding {
        authority_id: ContractId::new("authority:test").expect("contract"),
        authority_owner: "G-01".to_owned(),
        authority_epoch: fence.authority_epoch.clone(),
        state_fence: fence.clone(),
        allowed_effect: EffectClass::ExternalEffect,
        proof_ceiling: ProofCeiling::ObservedExternalEffect,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the fixture grant binds every delegation identity explicitly; grouping them would hide a binding"
)]
fn grant(
    id: &str,
    parent: Option<&str>,
    root: &str,
    issuer: &str,
    holder: &str,
    operations: &[&str],
    resources: &[&str],
    effect: EffectClass,
    fence: &StateFence,
) -> CapabilityGrant {
    CapabilityGrant {
        grant_id: GrantId::new(id).expect("grant id"),
        parent_grant_id: parent.map(GrantId::new).transpose().expect("parent"),
        authority_root_ref: root.to_owned(),
        issuer: PrincipalRef::new(issuer).expect("issuer"),
        holder: PrincipalRef::new(holder).expect("holder"),
        authority: AuthoritySet::new(
            operations.iter().map(|operation| (*operation).to_owned()),
            resources.iter().map(|resource| (*resource).to_owned()),
            effect,
        )
        .expect("authority"),
        inherited_source_ceiling: None,
        binding: binding(fence),
        issued_at: LogicalTime::new(1),
        expires_at: LogicalTime::new(10),
        max_uses: 2,
        status: GrantStatus::Active,
    }
}

/// Four-grant chain (origin > mid > leaf > tip) narrowing strictly at every
/// edge (by effect, then operations/resources, then effect), plus one
/// unrelated standalone grant under its own root.
fn chain(fence: &StateFence, denominator: &Denominator) -> GrantGraph {
    let full_ops = ["read", "write"];
    let full_res = ["resource:a", "resource:b"];
    let origin = grant(
        &denominator.origin_grant,
        None,
        &denominator.authority_root,
        "principal:root",
        "principal:mid",
        &full_ops,
        &full_res,
        EffectClass::ExternalEffect,
        fence,
    );
    let mid = grant(
        &denominator.mid_grant,
        Some(&denominator.origin_grant),
        &denominator.authority_root,
        "principal:mid",
        "principal:leaf",
        &full_ops,
        &full_res,
        EffectClass::ReversibleMutation,
        fence,
    );
    let leaf = grant(
        &denominator.leaf_grant,
        Some(&denominator.mid_grant),
        &denominator.authority_root,
        "principal:leaf",
        "principal:tip",
        &["read"],
        &["resource:a"],
        EffectClass::Candidate,
        fence,
    );
    let tip = grant(
        &denominator.tip_grant,
        Some(&denominator.leaf_grant),
        &denominator.authority_root,
        "principal:tip",
        "principal:end",
        &["read"],
        &["resource:a"],
        EffectClass::Read,
        fence,
    );
    let unrelated = grant(
        &denominator.unrelated_grant,
        None,
        &denominator.unrelated_root,
        "principal:other",
        "principal:unrelated",
        &["read"],
        &["resource:z"],
        EffectClass::Read,
        fence,
    );
    GrantGraph::from_grants([origin, mid, leaf, tip, unrelated], 7).expect("chain validates")
}

fn closure(
    closure_id: &str,
    root_ref: &str,
    dependents: &[String],
    revision: u64,
    fence: &StateFence,
) -> InfluenceDependencyClosure {
    InfluenceDependencyClosure {
        closure_id: closure_id.to_owned(),
        root_ref: root_ref.to_owned(),
        dependent_refs: dependents.to_owned(),
        invalidation_reason: Some(RevocationReason::SourceRevoked),
        current_influence: InfluenceState::Revoked,
        state_fence: fence.clone(),
        revision,
    }
}

fn origin_evidence(fence: &StateFence, denominator: &Denominator) -> RevocationHistoryEvidence {
    let mut dependents: Vec<String> = denominator
        .origin_affected
        .iter()
        .filter(|reference| *reference != &denominator.authority_root)
        .cloned()
        .collect();
    dependents.sort();
    RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: denominator.source_revision,
        closures: vec![closure(
            &denominator.origin_closure_id,
            &denominator.authority_root,
            &dependents,
            denominator.source_revision,
            fence,
        )],
    }
}

fn context(
    fence: &StateFence,
) -> (
    eliot_authority::SnapshotId,
    WorkScopeBinding,
    SessionBinding,
) {
    use eliot_contracts::{ProductId, SessionId};
    use eliot_receipts::WorkScopeId;
    let work_scope = WorkScopeBinding {
        scope_id: WorkScopeId::new("scope:test").expect("scope"),
        product_id: ProductId::new("product:test").expect("product"),
        resource_generation: fence.resource_generation,
        state_fence: fence.clone(),
    };
    let session = SessionBinding {
        session_id: SessionId::new("session:test").expect("session"),
        authority_epoch: fence.authority_epoch.clone(),
        state_fence: fence.clone(),
    };
    let snapshot_id = eliot_authority::SnapshotId::new("snapshot:686").expect("snapshot id");
    (snapshot_id, work_scope, session)
}

#[test]
fn revoke_origin_recovery_suppresses_origin_and_dependents() {
    let denominator = denominator();
    assert_eq!(denominator.invalidation_reason, "SOURCE_REVOKED");
    let fence = fence();
    let graph = chain(&fence, &denominator);
    let snapshot = graph.recovery_snapshot().expect("snapshot");
    let evidence = origin_evidence(&fence, &denominator);
    let outcome =
        GrantGraph::from_recovery_snapshot_with_revocation_history(snapshot, Some(&evidence))
            .expect("current evidence restores");
    let suppressed: BTreeSet<&str> = outcome
        .suppressed
        .iter()
        .map(|entry| entry.grant_id.as_str())
        .collect();
    assert_eq!(
        suppressed,
        BTreeSet::from([
            denominator.origin_grant.as_str(),
            denominator.mid_grant.as_str(),
            denominator.leaf_grant.as_str(),
            denominator.tip_grant.as_str(),
        ]),
        "origin revocation suppresses the whole delegation tree"
    );
    for entry in &outcome.suppressed {
        assert_eq!(entry.closure_id, denominator.origin_closure_id);
    }
    let causes: BTreeSet<String> = outcome
        .suppressed
        .iter()
        .map(|entry| {
            if entry.grant_id == denominator.origin_grant {
                assert_eq!(entry.cause, SuppressionCause::Origin);
            }
            format!("{:?}", entry.cause)
        })
        .collect();
    assert!(
        causes.contains("Origin"),
        "the origin grant is suppressed by origin revocation: {causes:?}"
    );
    // History is retained, never deleted: suppressed grants round-trip with
    // the revoked set carrying every suppression.
    let restored = outcome.graph.recovery_snapshot().expect("re-emit");
    for suppressed_id in &suppressed {
        assert!(
            restored.revoked.contains(&(*suppressed_id).to_owned()),
            "suppressed grant stays revoked: {suppressed_id}"
        );
    }
    assert_eq!(restored.grants.len(), 5, "no historical grant is deleted");
    // The unrelated grant restores effective for its holder.
    let (snapshot_id, work_scope, session) = context(&fence);
    let view = outcome
        .graph
        .snapshot(
            snapshot_id,
            &PrincipalRef::new("principal:unrelated").expect("holder"),
            &work_scope,
            &session,
            LogicalTime::new(2),
        )
        .expect("unrelated grant stays effective");
    assert!(view.allows("read", "resource:z", EffectClass::Read));
    // A suppressed holder has no effective path left.
    let (snapshot_id, work_scope, session) = context(&fence);
    let revoked = outcome.graph.snapshot(
        snapshot_id,
        &PrincipalRef::new("principal:end").expect("holder"),
        &work_scope,
        &session,
        LogicalTime::new(2),
    );
    assert!(revoked.is_err(), "revoked origin dependents do not revive");
}

#[test]
fn revoke_mid_tree_recovery_reports_transitive_suppression() {
    let denominator = denominator();
    let fence = fence();
    let graph = chain(&fence, &denominator);
    let snapshot = graph.recovery_snapshot().expect("snapshot");
    let evidence = RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: denominator.source_revision,
        closures: vec![closure(
            &denominator.mid_closure_id,
            &denominator.mid_grant,
            &denominator
                .mid_affected
                .iter()
                .filter(|reference| *reference != &denominator.mid_grant)
                .cloned()
                .collect::<Vec<_>>(),
            denominator.source_revision,
            &fence,
        )],
    };
    let outcome =
        GrantGraph::from_recovery_snapshot_with_revocation_history(snapshot, Some(&evidence))
            .expect("current evidence restores");
    let by_id: std::collections::BTreeMap<&str, &eliot_authority::SuppressedGrant> = outcome
        .suppressed
        .iter()
        .map(|entry| (entry.grant_id.as_str(), entry))
        .collect();
    assert_eq!(
        by_id.len(),
        3,
        "mid, leaf, and tip suppress; origin survives"
    );
    assert_eq!(
        by_id[denominator.mid_grant.as_str()].cause,
        SuppressionCause::Direct
    );
    assert_eq!(
        by_id[denominator.leaf_grant.as_str()].cause,
        SuppressionCause::Direct
    );
    assert_eq!(
        by_id[denominator.tip_grant.as_str()].cause,
        SuppressionCause::Transitive(denominator.leaf_grant.clone()),
        "the tip falls transitively through its suppressed parent"
    );
    assert!(!by_id.contains_key(denominator.origin_grant.as_str()));
    assert!(!by_id.contains_key(denominator.unrelated_grant.as_str()));
}

#[test]
fn missing_evidence_refuses_restoration() {
    let denominator = denominator();
    let fence = fence();
    let snapshot = chain(&fence, &denominator)
        .recovery_snapshot()
        .expect("snapshot");
    let error = GrantGraph::from_recovery_snapshot_with_revocation_history(snapshot, None)
        .expect_err("missing history must refuse");
    assert_eq!(error, RevocationHistoryError::MissingHistory);
}

#[test]
fn stale_evidence_refuses_restoration() {
    let denominator = denominator();
    let fence = fence();
    let snapshot = chain(&fence, &denominator)
        .recovery_snapshot()
        .expect("snapshot");
    // Zero source revision is stale.
    let zero = RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: 0,
        closures: Vec::new(),
    };
    assert_eq!(
        GrantGraph::from_recovery_snapshot_with_revocation_history(snapshot.clone(), Some(&zero))
            .expect_err("zero revision must refuse"),
        RevocationHistoryError::StaleHistory
    );
    // Closure revision drift against the source revision is stale.
    let drifted = RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: denominator.source_revision,
        closures: vec![closure(
            &denominator.origin_closure_id,
            &denominator.authority_root,
            &denominator.origin_affected,
            denominator.source_revision + 1,
            &fence,
        )],
    };
    assert_eq!(
        GrantGraph::from_recovery_snapshot_with_revocation_history(
            snapshot.clone(),
            Some(&drifted)
        )
        .expect_err("revision drift must refuse"),
        RevocationHistoryError::StaleHistory
    );
    // A fence from another epoch is stale.
    let other_epoch = EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
        NonZeroU64::new(2).expect("sequence"),
    )
    .expect("epoch");
    let other_fence = StateFence::new(other_epoch, ResourceGeneration::new(1).expect("generation"));
    let foreign = RevocationHistoryEvidence {
        state_fence: other_fence,
        source_revision: denominator.source_revision,
        closures: Vec::new(),
    };
    assert_eq!(
        GrantGraph::from_recovery_snapshot_with_revocation_history(snapshot, Some(&foreign))
            .expect_err("foreign fence must refuse"),
        RevocationHistoryError::StaleHistory
    );
}

#[test]
fn unknown_evidence_refuses_restoration() {
    let denominator = denominator();
    let fence = fence();
    let snapshot = chain(&fence, &denominator)
        .recovery_snapshot()
        .expect("snapshot");
    // A non-revoked closure is not revocation evidence.
    let mut active = closure(
        &denominator.origin_closure_id,
        &denominator.authority_root,
        &denominator.origin_affected,
        denominator.source_revision,
        &fence,
    );
    active.current_influence = InfluenceState::Active;
    active.invalidation_reason = None;
    let active_evidence = RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: denominator.source_revision,
        closures: vec![active],
    };
    assert_eq!(
        GrantGraph::from_recovery_snapshot_with_revocation_history(
            snapshot.clone(),
            Some(&active_evidence)
        )
        .expect_err("non-revoked closure must refuse"),
        RevocationHistoryError::UnknownHistory
    );
    // Unordered closures are unknown.
    let later = closure(
        &denominator.origin_closure_id,
        &denominator.authority_root,
        &denominator.origin_affected,
        denominator.source_revision,
        &fence,
    );
    let earlier = closure(
        "revocation-686-origin-00",
        &denominator.authority_root,
        &denominator.origin_affected,
        denominator.source_revision,
        &fence,
    );
    let unordered = RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: denominator.source_revision,
        closures: vec![later, earlier],
    };
    assert_eq!(
        GrantGraph::from_recovery_snapshot_with_revocation_history(snapshot, Some(&unordered))
            .expect_err("unordered closures must refuse"),
        RevocationHistoryError::UnknownHistory
    );
}

#[test]
fn current_empty_history_restores_unrelated_grants() {
    let denominator = denominator();
    let fence = fence();
    let graph = chain(&fence, &denominator);
    let snapshot = graph.recovery_snapshot().expect("snapshot");
    // An explicitly observed zero-revocation history is a complete
    // denominator: everything restores, nothing is suppressed.
    let empty = RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: denominator.source_revision,
        closures: Vec::new(),
    };
    let outcome =
        GrantGraph::from_recovery_snapshot_with_revocation_history(snapshot.clone(), Some(&empty))
            .expect("current empty history restores");
    assert!(outcome.suppressed.is_empty());
    assert_eq!(
        outcome.graph.recovery_snapshot().expect("re-emit"),
        snapshot
    );
    // Effect authorization is untouched by revocation history.
    let authorizer = EffectAuthorizer::default();
    authorizer.snapshot().expect("effect snapshot");
}
