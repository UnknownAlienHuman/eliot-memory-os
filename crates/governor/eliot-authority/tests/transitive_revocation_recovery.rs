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

use std::collections::{BTreeMap, BTreeSet};

use eliot_authority::{
    AuthorityError, AuthorityRevocationClosureEvidence, AuthoritySet, CapabilityGrant,
    EffectAuthorizer, GrantActivationRequest, GrantGraph, GrantGraphRecoverySnapshot, GrantId,
    GrantRestoreOutcome, GrantRevocationRequest, GrantStatus, IntroductionActivationRequest,
    IntroductionId, IntroductionRevocationRequest, LogicalTime, P07AuthorityPort, P07PortError,
    PrincipalRef, REVOCATION_HISTORY_EVIDENCE_VERSION, RevocationEvidenceDisposition,
    RevocationHistoryError, RevocationHistoryEvidence, RevocationOperationIdentity,
    SuppressionCause, UnavailableP07AuthorityPort,
};
use eliot_contracts::{
    ClockReading, ContractId, EpochId, EpochLineageId, ReceiptId, ResourceGeneration, StateFence,
    TaskId, TransactionSequence,
};
use eliot_receipts::{
    AuthorityBinding, EffectClass, ProofCeiling, SessionBinding, WorkScopeBinding,
};
use eliot_security_contracts::{
    InfluenceState, REVOCATION_DISPOSITION_COMPLETE, RevocationClosureDigestBounds,
    RevocationClosureDigestInput, RevocationReason,
};
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

#[derive(Debug, serde::Deserialize)]
struct RetentionExpectations {
    issue: u64,
    origin_closure_id: String,
    origin_suppressed: Vec<String>,
    mid_closure_id: String,
    mid_suppressed: Vec<String>,
    total_grants: usize,
}

fn retention_expectations() -> RetentionExpectations {
    let bytes = include_bytes!("data/transitive-revocation/retention-expectations.json");
    serde_json::from_slice(bytes).expect("retention fixture parses")
}

fn restore_with_origin_evidence(
    fence: &StateFence,
    denominator: &Denominator,
) -> GrantRestoreOutcome {
    let snapshot = chain(fence, denominator)
        .recovery_snapshot()
        .expect("snapshot");
    let evidence = origin_evidence(fence, denominator);
    GrantGraph::from_recovery_snapshot_with_revocation_history(
        &snapshot,
        Some(&evidence),
        &operation(),
    )
    .expect("current evidence restores")
}

fn restore_with_mid_evidence(fence: &StateFence, denominator: &Denominator) -> GrantRestoreOutcome {
    let snapshot = chain(fence, denominator)
        .recovery_snapshot()
        .expect("snapshot");
    let evidence = RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: denominator.source_revision,
        closures: vec![closure(
            &denominator.mid_closure_id,
            &denominator.authority_root,
            &denominator.mid_grant,
            &denominator
                .mid_affected
                .iter()
                .filter(|reference| *reference != &denominator.mid_grant)
                .cloned()
                .collect::<Vec<_>>(),
            denominator.source_revision,
            fence,
        )],
    };
    GrantGraph::from_recovery_snapshot_with_revocation_history(
        &snapshot,
        Some(&evidence),
        &operation(),
    )
    .expect("current evidence restores")
}

fn assert_full_lineage_retained(restored: &GrantGraphRecoverySnapshot, denominator: &Denominator) {
    let ids: BTreeSet<&str> = restored
        .grants
        .iter()
        .map(|record| record.grant_id.as_str())
        .collect();
    for record in &restored.grants {
        match &record.parent_grant_id {
            None => assert!(
                record.grant_id == denominator.origin_grant
                    || record.grant_id == denominator.unrelated_grant,
                "only origin and unrelated are roots: {}",
                record.grant_id
            ),
            Some(parent) => assert!(
                ids.contains(parent.as_str()),
                "parent linkage retained: {} -> {parent}",
                record.grant_id
            ),
        }
    }
    // Walk the chain through parent ids: tip -> leaf -> mid -> origin.
    let by_id: std::collections::BTreeMap<&str, Option<&str>> = restored
        .grants
        .iter()
        .map(|record| (record.grant_id.as_str(), record.parent_grant_id.as_deref()))
        .collect();
    assert_eq!(by_id[denominator.origin_grant.as_str()], None);
    assert_eq!(
        by_id[denominator.mid_grant.as_str()],
        Some(denominator.origin_grant.as_str())
    );
    assert_eq!(
        by_id[denominator.leaf_grant.as_str()],
        Some(denominator.mid_grant.as_str())
    );
    assert_eq!(
        by_id[denominator.tip_grant.as_str()],
        Some(denominator.leaf_grant.as_str())
    );
}

fn assert_validity_intervals_retained(
    source: &GrantGraphRecoverySnapshot,
    restored: &GrantGraphRecoverySnapshot,
) {
    let source_intervals: BTreeMap<&str, (u64, u64)> = source
        .grants
        .iter()
        .map(|record| {
            (
                record.grant_id.as_str(),
                (record.issued_at, record.expires_at),
            )
        })
        .collect();
    let restored_intervals: BTreeMap<&str, (u64, u64)> = restored
        .grants
        .iter()
        .map(|record| {
            (
                record.grant_id.as_str(),
                (record.issued_at, record.expires_at),
            )
        })
        .collect();
    assert_eq!(restored_intervals, source_intervals);
}

fn fence() -> StateFence {
    let epoch = EpochId::new(
        EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
        NonZeroU64::new(1).expect("sequence"),
    )
    .expect("epoch");
    StateFence::new(epoch, ResourceGeneration::new(1).expect("generation"))
}

/// The admitted revocation operation identity every restore below is handed
/// alongside its evidence. The graph is a pure evaluator with no plan, scope
/// binding or Store readback of its own, so it derives none of these five
/// coordinates; a fixture must hand it one that survives
/// [`RevocationOperationIdentity::admit`] — every text coordinate non-blank and
/// a causal `transaction_sequence` present. The principal, task, scope and
/// receipt are the fixture's own namespaced values, and no test asserts
/// anything about this value.
fn operation() -> RevocationOperationIdentity {
    RevocationOperationIdentity::admit(
        "principal:root",
        TaskId::new("task:686-alpha-recovery").expect("task id"),
        "scope:test",
        ReceiptId::new("receipt:686-alpha-recovery").expect("receipt id"),
        ClockReading {
            valid_time_ms: Some(1_000),
            known_time_ms: Some(1_000),
            transaction_sequence: Some(TransactionSequence::genesis()),
            monotonic_ns: None,
        },
    )
    .expect("fixture revocation operation identity is admitted")
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

/// One declared authority-specific versioned closure (issue #2966 step 2).
///
/// The fixture declares the coordinates the durable history owner declares:
/// the owner namespace the history was served under, the traversal bounds the
/// affected membership was committed under, the completeness disposition, the
/// omission set, and the two content addresses of the exact presented bytes.
fn closure(
    closure_id: &str,
    owner_namespace: &str,
    root_ref: &str,
    dependents: &[String],
    revision: u64,
    fence: &StateFence,
) -> AuthorityRevocationClosureEvidence {
    let dependent_refs = dependents.to_owned();
    let affected = AuthorityRevocationClosureEvidence::members_of(root_ref, &dependent_refs);
    let invalidation_reason = Some(RevocationReason::SourceRevoked);
    let affected_member_digest =
        AuthorityRevocationClosureEvidence::affected_members_digest(&affected)
            .expect("affected membership is addressable");
    let evidence_version = REVOCATION_HISTORY_EVIDENCE_VERSION;
    let bounds = eliot_influence::RevocationBounds::default_bounds();
    let disposition = RevocationEvidenceDisposition::Complete;
    let omissions: Vec<String> = Vec::new();
    let mut grant_validity = affected
        .iter()
        .filter(|reference| reference.as_str() != owner_namespace)
        .map(|reference| {
            (
                reference.clone(),
                eliot_contracts::LogicalValidityInterval {
                    issued_at: 1,
                    expires_at: 10,
                },
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    // A typed authority-root origin represents its root grant even when the
    // historical affected list uses the root marker instead of that grant ID.
    let fixture = denominator();
    if root_ref == fixture.authority_root {
        grant_validity.insert(
            fixture.origin_grant,
            eliot_contracts::LogicalValidityInterval {
                issued_at: 1,
                expires_at: 10,
            },
        );
    }
    let affected_member_count = affected.len() as u64;
    // The declared digest is computed over the SAME presentation the record
    // carries, coordinate for coordinate. Recovery recomputes it from the
    // presented bytes and refuses a disagreement, so a digest taken over any
    // other set of coordinates would make every fixture refuse for a reason
    // that has nothing to do with the case under test.
    let canonical_request_digest =
        AuthorityRevocationClosureEvidence::declared_canonical_request_digest(
            &RevocationClosureDigestInput {
                evidence_version,
                grant_validity: &grant_validity,
                closure_id,
                owner_namespace,
                root_ref,
                dependent_refs: &dependent_refs,
                invalidation_reason,
                current_influence: InfluenceState::Revoked,
                state_fence: fence,
                commit_state_fence: fence,
                revision,
                bounds: RevocationClosureDigestBounds {
                    max_nodes: bounds.max_nodes,
                    max_edges: bounds.max_edges,
                    max_depth: bounds.max_depth,
                    max_result: bounds.max_result,
                    max_work: bounds.max_work,
                    max_frontier: bounds.max_frontier,
                    max_time: bounds.max_time,
                },
                // This fixture is always `Complete`, so the canonical
                // disposition spelling is the crate's exported constant for
                // it rather than a locally spelled string.
                disposition: REVOCATION_DISPOSITION_COMPLETE,
                omissions: &omissions,
                affected_member_count,
                affected_member_digest: &affected_member_digest,
            },
        )
        .expect("closure presentation is addressable");
    AuthorityRevocationClosureEvidence {
        grant_validity,
        evidence_version,
        closure_id: closure_id.to_owned(),
        owner_namespace: owner_namespace.to_owned(),
        root_ref: root_ref.to_owned(),
        dependent_refs,
        invalidation_reason,
        current_influence: InfluenceState::Revoked,
        state_fence: fence.clone(),
        commit_state_fence: fence.clone(),
        revision,
        bounds,
        disposition,
        omissions,
        affected_member_count,
        affected_member_digest,
        canonical_request_digest,
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

fn bounded_closure(
    graph: &GrantGraph,
    denominator: &Denominator,
    fence: &StateFence,
) -> Result<eliot_influence::BoundedRevocationOutcome, Box<dyn std::error::Error>> {
    let origin = GrantId::new(denominator.origin_grant.clone())?;
    Ok(graph.transitive_revocation_closure(
        &origin,
        fence,
        &eliot_influence::RevocationBounds::default_bounds(),
        &operation(),
    )?)
}

fn assert_expiry_updates_are_digest_bound(
    baseline: &GrantGraphRecoverySnapshot,
    denominator: &Denominator,
    fence: &StateFence,
    updates: &[(&str, u64)],
) -> Result<(), Box<dyn std::error::Error>> {
    let baseline_graph = GrantGraph::from_recovery_snapshot(baseline)?;
    let before = bounded_closure(&baseline_graph, denominator, fence)?;
    assert_eq!(baseline_graph.recovery_snapshot()?, baseline.clone());
    let mut changed = baseline.clone();
    for &(grant_id, expires_at) in updates {
        let record = changed
            .grants
            .iter_mut()
            .find(|record| record.grant_id.as_str() == grant_id)
            .ok_or_else(|| format!("owner snapshot omitted {grant_id}"))?;
        assert!(expires_at > record.issued_at, "valid grant interval");
        record.expires_at = expires_at;
    }

    assert_eq!(changed.revision, baseline.revision);
    assert_eq!(changed.grants.len(), baseline.grants.len());
    for original in &baseline.grants {
        let current = changed
            .grants
            .iter()
            .find(|record| record.grant_id.as_str() == original.grant_id.as_str())
            .ok_or_else(|| format!("changed snapshot omitted {}", original.grant_id))?;
        assert_eq!(current.parent_grant_id, original.parent_grant_id);
        assert_eq!(current.issued_at, original.issued_at);
        assert_eq!(current.status, original.status);
    }
    for record in &changed.grants {
        assert!(record.expires_at > record.issued_at, "valid grant interval");
        if let Some(parent_id) = &record.parent_grant_id {
            let parent = changed
                .grants
                .iter()
                .find(|candidate| candidate.grant_id.as_str() == parent_id.as_str())
                .ok_or_else(|| format!("missing parent {parent_id}"))?;
            assert!(
                record.expires_at <= parent.expires_at,
                "child validity stays within parent validity: {} -> {}",
                record.grant_id,
                parent.grant_id
            );
        }
    }

    let changed_graph = GrantGraph::from_recovery_snapshot(&changed)?;
    let after = bounded_closure(&changed_graph, denominator, fence)?;
    assert_eq!(after.affected_refs, before.affected_refs);
    assert_ne!(after.grant_validity, before.grant_validity);
    assert_ne!(after.request_digest, before.request_digest);
    let after_closure_snapshot = changed_graph.recovery_snapshot()?;
    assert_eq!(
        after_closure_snapshot, changed,
        "closure does not mutate or activate grants"
    );
    assert_validity_intervals_retained(&changed, &after_closure_snapshot);

    let encoded = serde_json::to_vec(&after_closure_snapshot)?;
    let wire_roundtrip: GrantGraphRecoverySnapshot = serde_json::from_slice(&encoded)?;
    assert_eq!(wire_roundtrip, changed);
    let roundtrip_graph = GrantGraph::from_recovery_snapshot(&wire_roundtrip)?;
    let roundtrip = bounded_closure(&roundtrip_graph, denominator, fence)?;
    assert_eq!(roundtrip.affected_refs, after.affected_refs);
    assert_eq!(roundtrip.grant_validity, after.grant_validity);
    assert_eq!(roundtrip.request_digest, after.request_digest);
    assert_eq!(roundtrip_graph.recovery_snapshot()?, changed);
    Ok(())
}

// WORK_UNIT_CASE: 686/15
#[test]
fn revoke_origin_recovery_suppresses_origin_and_dependents()
-> Result<(), Box<dyn std::error::Error>> {
    let denominator = denominator();
    assert_eq!(denominator.invalidation_reason, "SOURCE_REVOKED");
    let fence = fence();
    let graph = chain(&fence, &denominator);
    let snapshot = graph.recovery_snapshot()?;
    let evidence = origin_evidence(&fence, &denominator);
    let outcome = GrantGraph::from_recovery_snapshot_with_revocation_history(
        &snapshot,
        Some(&evidence),
        &operation(),
    )?;
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
    let restored = outcome.graph.recovery_snapshot()?;
    assert_validity_intervals_retained(&snapshot, &restored);
    for suppressed_id in &suppressed {
        assert!(
            restored.revoked.contains(&(*suppressed_id).to_owned()),
            "suppressed grant stays revoked: {suppressed_id}"
        );
    }
    assert_eq!(restored.grants.len(), 5, "no historical grant is deleted");
    // The unrelated grant restores effective for its holder.
    let (snapshot_id, work_scope, session) = context(&fence);
    let unrelated_holder = PrincipalRef::new("principal:unrelated")?;
    let view = outcome.graph.snapshot(
        snapshot_id,
        &unrelated_holder,
        &work_scope,
        &session,
        LogicalTime::new(2),
    )?;
    assert!(view.allows("read", "resource:z", EffectClass::Read));
    // A suppressed holder has no effective path left.
    let (snapshot_id, work_scope, session) = context(&fence);
    let revoked_holder = PrincipalRef::new("principal:end")?;
    let revoked = outcome.graph.snapshot(
        snapshot_id,
        &revoked_holder,
        &work_scope,
        &session,
        LogicalTime::new(2),
    );
    assert!(revoked.is_err(), "revoked origin dependents do not revive");
    Ok(())
}

#[test]
fn revoke_mid_tree_recovery_reports_transitive_suppression()
-> Result<(), Box<dyn std::error::Error>> {
    let denominator = denominator();
    let fence = fence();
    let graph = chain(&fence, &denominator);
    let snapshot = graph.recovery_snapshot()?;
    let evidence = RevocationHistoryEvidence {
        state_fence: fence.clone(),
        source_revision: denominator.source_revision,
        closures: vec![closure(
            &denominator.mid_closure_id,
            &denominator.authority_root,
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
    let outcome = GrantGraph::from_recovery_snapshot_with_revocation_history(
        &snapshot,
        Some(&evidence),
        &operation(),
    )?;
    let restored = outcome.graph.recovery_snapshot()?;
    assert_validity_intervals_retained(&snapshot, &restored);
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
        SuppressionCause::Direct,
        "complete versioned history declares the tip explicitly"
    );
    assert!(!by_id.contains_key(denominator.origin_grant.as_str()));
    assert!(!by_id.contains_key(denominator.unrelated_grant.as_str()));
    Ok(())
}

// WORK_UNIT_CASE: 686/16
#[test]
fn missing_evidence_refuses_restoration() {
    let denominator = denominator();
    let fence = fence();
    let snapshot = chain(&fence, &denominator)
        .recovery_snapshot()
        .expect("snapshot");
    let error =
        GrantGraph::from_recovery_snapshot_with_revocation_history(&snapshot, None, &operation())
            .expect_err("missing history must refuse");
    assert_eq!(error, RevocationHistoryError::MissingHistory);
}

// WORK_UNIT_CASE: 686/12
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
        GrantGraph::from_recovery_snapshot_with_revocation_history(
            &snapshot,
            Some(&zero),
            &operation()
        )
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
            &denominator.authority_root,
            &denominator.origin_affected,
            denominator.source_revision + 1,
            &fence,
        )],
    };
    assert_eq!(
        GrantGraph::from_recovery_snapshot_with_revocation_history(
            &snapshot,
            Some(&drifted),
            &operation()
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
        GrantGraph::from_recovery_snapshot_with_revocation_history(
            &snapshot,
            Some(&foreign),
            &operation()
        )
        .expect_err("foreign fence must refuse"),
        RevocationHistoryError::StaleHistory
    );
}

// WORK_UNIT_CASE: 686/11
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
            &snapshot,
            Some(&active_evidence),
            &operation()
        )
        .expect_err("non-revoked closure must refuse"),
        RevocationHistoryError::UnknownHistory
    );
    // Unordered closures are unknown.
    let later = closure(
        &denominator.origin_closure_id,
        &denominator.authority_root,
        &denominator.authority_root,
        &denominator.origin_affected,
        denominator.source_revision,
        &fence,
    );
    let earlier = closure(
        "revocation-686-origin-00",
        &denominator.authority_root,
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
        GrantGraph::from_recovery_snapshot_with_revocation_history(
            &snapshot,
            Some(&unordered),
            &operation()
        )
        .expect_err("unordered closures must refuse"),
        RevocationHistoryError::UnknownHistory
    );
}

// WORK_UNIT_CASE: 686/17
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
    let outcome = GrantGraph::from_recovery_snapshot_with_revocation_history(
        &snapshot,
        Some(&empty),
        &operation(),
    )
    .expect("current empty history restores");
    assert!(outcome.suppressed.is_empty());
    assert_eq!(
        outcome.graph.recovery_snapshot().expect("re-emit"),
        snapshot
    );
    // Effective-path proof: the unrelated grant authorizes its holder after
    // the empty-history restore.
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
    // Effect authorization is untouched by revocation history.
    let authorizer = EffectAuthorizer::default();
    authorizer.snapshot().expect("effect snapshot");
}

// WORK_UNIT_CASE: 686/14
#[test]
fn p07_unknown_outcome_retains_request_without_commit_claim() {
    let fence = fence();
    let presented = binding(&fence);
    let snapshot_id =
        eliot_authority::SnapshotId::new("snapshot:686-unknown").expect("snapshot id");
    let revoke_request = GrantRevocationRequest {
        grant_id: GrantId::new("grant:origin-alpha").expect("grant id"),
        snapshot_id: snapshot_id.clone(),
        binding: presented.clone(),
    };
    let activate_request = GrantActivationRequest {
        grant_id: GrantId::new("grant:origin-alpha").expect("grant id"),
        snapshot_id: snapshot_id.clone(),
        binding: presented.clone(),
    };
    let intro_activate = IntroductionActivationRequest {
        introduction_id: IntroductionId::new("introduction:686-test").expect("introduction id"),
        snapshot_id: snapshot_id.clone(),
        binding: presented.clone(),
    };
    let intro_revoke = IntroductionRevocationRequest {
        introduction_id: IntroductionId::new("introduction:686-test").expect("introduction id"),
        snapshot_id: snapshot_id.clone(),
        binding: presented.clone(),
    };
    let port = UnavailableP07AuthorityPort;
    // A single call each: the unavailable port commits nothing and claims
    // nothing beyond unavailability — no retry, no receipt.
    assert_eq!(
        port.revoke_grant(&revoke_request),
        Err(P07PortError::Unavailable)
    );
    assert_eq!(
        port.activate_grant(&activate_request),
        Err(P07PortError::Unavailable)
    );
    assert_eq!(
        port.activate_introduction(&intro_activate),
        Err(P07PortError::Unavailable)
    );
    assert_eq!(
        port.revoke_introduction(&intro_revoke),
        Err(P07PortError::Unavailable)
    );
    // An unknown outcome retains the exact request identity for
    // reconciliation and never collapses to unavailability.
    let unknown = P07PortError::UnknownOutcome {
        snapshot_id: snapshot_id.clone(),
    };
    assert_ne!(unknown, P07PortError::Unavailable);
    assert!(
        format!("{unknown}").contains("snapshot:686-unknown"),
        "reconciliation retains the exact request identity: {unknown}"
    );
    assert!(matches!(unknown, P07PortError::UnknownOutcome { .. }));
}

// WORK_UNIT_CASE: 686/19
#[test]
fn history_suppression_retains_all_grants_and_lineage() {
    let fixture = retention_expectations();
    assert_eq!(fixture.issue, 686);
    let denominator = denominator();
    assert_eq!(fixture.origin_closure_id, denominator.origin_closure_id);
    assert_eq!(fixture.mid_closure_id, denominator.mid_closure_id);
    let fence = fence();

    // Origin revocation: suppressed set matches the fixture, history retained.
    let outcome = restore_with_origin_evidence(&fence, &denominator);
    let suppressed: BTreeSet<String> = outcome
        .suppressed
        .iter()
        .map(|entry| entry.grant_id.as_str().to_owned())
        .collect();
    let expected_origin: BTreeSet<String> = fixture.origin_suppressed.iter().cloned().collect();
    assert_eq!(
        suppressed, expected_origin,
        "origin suppression matches the retention fixture"
    );
    assert!(
        !suppressed.contains(&denominator.unrelated_grant),
        "the unrelated grant is never suppressed"
    );
    let restored = outcome.graph.recovery_snapshot().expect("re-emit");
    assert_eq!(
        restored.grants.len(),
        fixture.total_grants,
        "no historical grant is deleted"
    );
    for suppressed_id in &expected_origin {
        assert!(
            restored.revoked.contains(suppressed_id),
            "suppressed grant stays revoked: {suppressed_id}"
        );
    }
    assert_full_lineage_retained(&restored, &denominator);

    // Mid revocation: suppressed set matches the fixture; origin survives.
    let mid_outcome = restore_with_mid_evidence(&fence, &denominator);
    let mid_suppressed: BTreeSet<String> = mid_outcome
        .suppressed
        .iter()
        .map(|entry| entry.grant_id.as_str().to_owned())
        .collect();
    let expected_mid: BTreeSet<String> = fixture.mid_suppressed.iter().cloned().collect();
    assert_eq!(
        mid_suppressed, expected_mid,
        "mid suppression matches the retention fixture"
    );
    assert!(
        !mid_suppressed.contains(&denominator.origin_grant),
        "mid revocation leaves the origin restorable"
    );
    assert!(
        !mid_suppressed.contains(&denominator.unrelated_grant),
        "mid revocation leaves the unrelated grant restorable"
    );
}

#[test]
fn origin_expiry_changes_closure_identity_and_survives_snapshot_roundtrip()
-> Result<(), Box<dyn std::error::Error>> {
    let denominator = denominator();
    let fence = fence();
    let graph = chain(&fence, &denominator);
    let snapshot = graph.recovery_snapshot()?;

    // Extending only the origin leaves every child interval attenuated.
    assert_expiry_updates_are_digest_bound(
        &snapshot,
        &denominator,
        &fence,
        &[(denominator.origin_grant.as_str(), 11)],
    )?;
    Ok(())
}

#[test]
fn descendant_expiry_changes_closure_identity_and_survives_snapshot_roundtrip()
-> Result<(), Box<dyn std::error::Error>> {
    let denominator = denominator();
    let fence = fence();
    let graph = chain(&fence, &denominator);
    let snapshot = graph.recovery_snapshot()?;

    // Shortening the terminal descendant stays within its parent's interval.
    assert_expiry_updates_are_digest_bound(
        &snapshot,
        &denominator,
        &fence,
        &[(denominator.tip_grant.as_str(), 9)],
    )?;
    Ok(())
}

#[test]
fn historical_closure_does_not_reactivate_owner_expired_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let denominator = denominator();
    let fence = fence();
    let graph = chain(&fence, &denominator);
    let before = graph.recovery_snapshot()?;

    let outcome = bounded_closure(&graph, &denominator, &fence)?;
    assert!(!outcome.affected_refs.is_empty());
    assert_eq!(
        graph.recovery_snapshot()?,
        before,
        "closure is observational"
    );

    let (snapshot_id, work_scope, session) = context(&fence);
    let holder = PrincipalRef::new("principal:end")?;
    // These are owner logical-time reads, independent of operation/HLC time.
    let still_valid = graph.snapshot(
        snapshot_id.clone(),
        &holder,
        &work_scope,
        &session,
        LogicalTime::new(9),
    )?;
    assert!(still_valid.allows("read", "resource:a", EffectClass::Read));
    assert!(matches!(
        graph.snapshot(
            snapshot_id,
            &holder,
            &work_scope,
            &session,
            LogicalTime::new(10)
        ),
        Err(AuthorityError::NoEffectivePath)
    ));
    assert_eq!(graph.recovery_snapshot()?, before);
    Ok(())
}

#[test]
fn original_revocation_intervals_refuse_restore_after_grant_expiry_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let denominator = denominator();
    let fence = fence();
    let graph = chain(&fence, &denominator);
    let snapshot = graph.recovery_snapshot()?;
    let evidence = origin_evidence(&fence, &denominator);
    for (id, expiry) in [(&denominator.origin_grant, 11), (&denominator.tip_grant, 9)] {
        let mut changed = snapshot.clone();
        changed
            .grants
            .iter_mut()
            .find(|grant| &grant.grant_id == id)
            .ok_or("missing grant")?
            .expires_at = expiry;
        // This remains a structurally valid canonical grant graph. Only the
        // ORIGINAL recorded validity differs; recovery must not replace it.
        GrantGraph::from_recovery_snapshot(&changed)?;
        assert!(
            matches!(GrantGraph::from_recovery_snapshot_with_revocation_history(
            &changed, Some(&evidence), &operation()),
            Err(RevocationHistoryError::IdentityConflict(conflict))
                if conflict.field == "recovery.closure_grant_validity")
        );
    }
    Ok(())
}
