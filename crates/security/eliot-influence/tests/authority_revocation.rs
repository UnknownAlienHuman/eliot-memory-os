// Transitive influence revocation suite (issue #686, work unit B-SEC1).
//
// These tests pin the shipped authority-graph contract: `revoke` must close
// over every transitively influenced dependent (BFS with a visited set, so
// cycles and self edges terminate), every closure in the receipt must carry
// the revoking reason with `Revoked` influence, and `decide` must surface
// that closure as `DependencyRevoked` (which dominates every other reason).
//
// Denominator: every file-based graph in this suite is parsed from the one
// fixture directory `tests/data/transitive-revocation/` via `include_str!`.
// Each fixture line is `SRC DST`; `#` comments and blank lines are ignored.

#![allow(clippy::expect_used)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
use eliot_influence::{
    decide, revoke, InfluenceDisposition, InfluenceEdge, InfluenceLevel, InfluencePolicy,
    InfluenceReason, InfluenceRequest, ProvenanceRecord, RevocationRequest,
};
use eliot_security_contracts::{
    CompetenceLevel, EffectCeiling, EpistemicUse, FreshnessStatus, IndependenceLevel,
    InfluenceDependencyClosure, InfluenceState, InstructionTaint, IntegrityStatus, PrivacyClass,
    QuarantineState, RevocationReason, SourceAssurance,
};

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

fn fence_for_sequence(sequence: u64) -> StateFence {
    let lineage = EpochLineageId::new(TEST_LINEAGE).expect("valid test lineage");
    let ordinal = NonZeroU64::new(sequence).expect("nonzero test epoch ordinal");
    let epoch = EpochId::new(lineage, ordinal).expect("valid test epoch");
    let generation = ResourceGeneration::new(3).expect("valid test generation");
    StateFence::new(epoch, generation)
}

fn test_fence() -> StateFence {
    fence_for_sequence(7)
}

fn test_fence_seq2() -> StateFence {
    fence_for_sequence(2)
}

fn clean_assurance(fence: &StateFence) -> SourceAssurance {
    SourceAssurance {
        source_ref: "source:test-686".to_string(),
        provenance_ref: "provenance:test-686".to_string(),
        integrity: IntegrityStatus::Verified,
        freshness: FreshnessStatus::Current,
        competence: CompetenceLevel::DomainVerified,
        independence: IndependenceLevel::Independent,
        privacy_class: PrivacyClass::Public,
        instruction_taint: InstructionTaint::Cleared,
        allowed_epistemic_use: vec![EpistemicUse::Observation],
        allowed_effects: vec![EffectCeiling::ReadOnly],
        required_verifier: None,
        quarantine: QuarantineState::None,
        state_fence: fence.clone(),
    }
}

fn policy_for(fence: &StateFence, require_freshness: bool) -> InfluencePolicy {
    InfluencePolicy {
        policy_id: "policy:test-686".to_string(),
        revision: 1,
        state_fence: fence.clone(),
        require_verified_integrity: false,
        require_current_freshness: require_freshness,
        allow_unknown_independence: true,
        allow_instruction_taint: true,
        minimum_level: InfluenceLevel::VerifiedUse,
    }
}

fn provenance_for(
    subject: &str,
    origin: &str,
    fence: &StateFence,
    assurance: SourceAssurance,
) -> ProvenanceRecord {
    ProvenanceRecord {
        subject_ref: subject.to_string(),
        origin_ref: origin.to_string(),
        source_assurance: assurance,
        parent_refs: vec!["parent:test-686".to_string()],
        transformation_ref: None,
        state_fence: fence.clone(),
    }
}

fn closure_for(
    root: &str,
    dependents: Vec<String>,
    state: InfluenceState,
    reason: Option<RevocationReason>,
    fence: &StateFence,
    revision: u64,
) -> InfluenceDependencyClosure {
    InfluenceDependencyClosure {
        closure_id: format!("closure:686:{root}"),
        root_ref: root.to_string(),
        dependent_refs: dependents,
        invalidation_reason: reason,
        current_influence: state,
        state_fence: fence.clone(),
        revision,
    }
}

fn request_for(
    subject: &str,
    origin: &str,
    policy: InfluencePolicy,
    provenance: ProvenanceRecord,
    closure: InfluenceDependencyClosure,
) -> InfluenceRequest {
    assert_eq!(
        provenance.origin_ref, origin,
        "request origin must match provenance origin"
    );
    InfluenceRequest {
        request_id: format!("request:686:{subject}"),
        subject_ref: subject.to_string(),
        requested_level: InfluenceLevel::VerifiedUse,
        policy,
        provenance,
        dependency_closure: closure,
    }
}

fn revocation_request(
    id: &str,
    root: &str,
    reason: RevocationReason,
    fence: &StateFence,
    edges: Vec<InfluenceEdge>,
) -> RevocationRequest {
    RevocationRequest {
        request_id: id.to_string(),
        root_ref: root.to_string(),
        reason,
        state_fence: fence.clone(),
        graph: edges,
    }
}

/// Build a decide-ready request around a revoke-produced closure.
///
/// The subject is arbitrary but consistent (`subject:<suffix>`), the
/// provenance origin tracks the closure root, and every fence tracks the
/// closure fence, so `validate` passes and `decide` evaluates the closure.
fn decide_request_for_closure(
    suffix: &str,
    closure: &InfluenceDependencyClosure,
) -> InfluenceRequest {
    let fence = closure.state_fence.clone();
    let subject = format!("subject:{suffix}");
    let provenance = provenance_for(&subject, &closure.root_ref, &fence, clean_assurance(&fence));
    request_for(
        &subject,
        &closure.root_ref,
        policy_for(&fence, false),
        provenance,
        closure.clone(),
    )
}

fn parse_edges(text: &str) -> Vec<InfluenceEdge> {
    let mut edges = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert!(
            parts.len() == 2,
            "malformed fixture line {}: expected `SRC DST`, got {line:?}",
            index + 1
        );
        edges.push(InfluenceEdge {
            source_ref: parts[0].to_string(),
            dependent_ref: parts[1].to_string(),
        });
    }
    edges
}

fn assert_sorted_unique(refs: &[String], context: &str) {
    let mut sorted = refs.to_vec();
    sorted.sort();
    assert_eq!(
        refs,
        sorted.as_slice(),
        "{context}: affected_refs must be sorted"
    );
    let mut deduped = sorted.clone();
    deduped.dedup();
    assert_eq!(
        refs.len(),
        deduped.len(),
        "{context}: affected_refs must be unique"
    );
}

fn expect_fence_mismatch(error: &impl std::fmt::Debug, context: &str) {
    let text = format!("{error:?}");
    assert!(
        text.contains("FenceOrLineageMismatch"),
        "{context}: expected FenceOrLineageMismatch, got {text}"
    );
}

// WORK_UNIT_CASE: 686/1
#[test]
fn direct_one_edge_revocation_blocks_dependent() {
    let fence = test_fence();
    let edges = vec![InfluenceEdge {
        source_ref: "origin:one".to_string(),
        dependent_ref: "dep:one".to_string(),
    }];
    let request = revocation_request(
        "revoke:686:1",
        "origin:one",
        RevocationReason::SourceRevoked,
        &fence,
        edges,
    );
    let receipt = revoke(&request).expect("direct revocation succeeds");
    assert_eq!(
        receipt.affected_refs,
        vec!["dep:one".to_string(), "origin:one".to_string()]
    );
    assert_eq!(receipt.closures.len(), 2);
    for closure in &receipt.closures {
        assert_eq!(closure.current_influence, InfluenceState::Revoked);
        assert_eq!(
            closure.invalidation_reason,
            Some(RevocationReason::SourceRevoked)
        );
    }
    let dependent = receipt
        .closures
        .iter()
        .find(|closure| closure.closure_id.ends_with("dep:one"))
        .expect("dependent closure is present");
    let decision = decide(&decide_request_for_closure("one", dependent))
        .expect("revoked dependent decide succeeds");
    assert_eq!(decision.disposition, InfluenceDisposition::Revoked);
    assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
    assert!(
        decision
            .reasons
            .contains(&InfluenceReason::DependencyRevoked),
        "revoked closure must report DependencyRevoked: {:?}",
        decision.reasons
    );
}

// WORK_UNIT_CASE: 686/2
#[test]
fn multilevel_chain_closure_is_exact_and_ordered() {
    let fence = test_fence();
    let edges = parse_edges(include_str!("data/transitive-revocation/chain.txt"));
    let request = revocation_request(
        "revoke:686:2",
        "origin:alpha",
        RevocationReason::SourceRevoked,
        &fence,
        edges,
    );
    let receipt = revoke(&request).expect("chain revocation succeeds");
    assert_eq!(
        receipt.affected_refs,
        vec![
            "leaf:gamma".to_string(),
            "mid:beta".to_string(),
            "origin:alpha".to_string(),
        ]
    );
    assert_eq!(receipt.closures.len(), 3);
    assert_sorted_unique(&receipt.affected_refs, "chain");
}

// WORK_UNIT_CASE: 686/3
#[test]
fn branching_converging_graph_lists_convergence_once() {
    let fence = test_fence();
    let edges = parse_edges(include_str!("data/transitive-revocation/diamond.txt"));
    let request = revocation_request(
        "revoke:686:3",
        "origin:alpha",
        RevocationReason::SourceRevoked,
        &fence,
        edges,
    );
    let receipt = revoke(&request).expect("diamond revocation succeeds");
    assert_eq!(
        receipt.affected_refs,
        vec![
            "branch:b".to_string(),
            "branch:c".to_string(),
            "leaf:delta".to_string(),
            "origin:alpha".to_string(),
        ]
    );
    let convergences = receipt
        .affected_refs
        .iter()
        .filter(|reference| reference.as_str() == "leaf:delta")
        .count();
    assert_eq!(convergences, 1, "converging leaf must appear exactly once");
}

// WORK_UNIT_CASE: 686/4
#[test]
fn cycle_and_self_edge_terminate_with_exact_set() {
    let fence = test_fence();
    let edges = parse_edges(include_str!("data/transitive-revocation/cycle.txt"));
    let cyclic = revocation_request(
        "revoke:686:4a",
        "node:a",
        RevocationReason::Poisoned,
        &fence,
        edges.clone(),
    );
    let cyclic_receipt = revoke(&cyclic).expect("cyclic revocation terminates");
    assert_eq!(
        cyclic_receipt.affected_refs,
        vec![
            "node:a".to_string(),
            "node:b".to_string(),
            "node:c".to_string(),
        ]
    );
    let self_edge = revocation_request(
        "revoke:686:4b",
        "node:d",
        RevocationReason::Poisoned,
        &fence,
        edges,
    );
    let self_receipt = revoke(&self_edge).expect("self-edge revocation terminates");
    assert_eq!(self_receipt.affected_refs, vec!["node:d".to_string()]);
}

// WORK_UNIT_CASE: 686/5
#[test]
fn duplicate_and_changed_edge_stay_unique_and_visible() {
    let fence = test_fence();
    let edges = parse_edges(include_str!("data/transitive-revocation/duplicates.txt"));
    assert_eq!(edges.len(), 4, "fixture keeps the duplicate edge");
    let request = revocation_request(
        "revoke:686:5",
        "origin:x",
        RevocationReason::SourceRevoked,
        &fence,
        edges,
    );
    let receipt = revoke(&request).expect("duplicate-edge revocation succeeds");
    assert_eq!(
        receipt.affected_refs,
        vec![
            "dep:changed".to_string(),
            "dep:y".to_string(),
            "leaf:z".to_string(),
            "origin:x".to_string(),
        ]
    );
    assert_eq!(receipt.closures.len(), 4);
    assert_sorted_unique(&receipt.affected_refs, "duplicates");
}

// WORK_UNIT_CASE: 686/6
#[test]
fn edge_order_permutation_keeps_deterministic_closure() {
    let fence = test_fence();
    let edges = parse_edges(include_str!("data/transitive-revocation/diamond.txt"));
    let mut reversed = edges.clone();
    reversed.reverse();
    // Different request ids: the receipts cannot share a digest, but the
    // closed member set must be identical.
    let forward = revocation_request(
        "revoke:686:6a",
        "origin:alpha",
        RevocationReason::SourceRevoked,
        &fence,
        edges,
    );
    let backward = revocation_request(
        "revoke:686:6b",
        "origin:alpha",
        RevocationReason::SourceRevoked,
        &fence,
        reversed,
    );
    let forward_receipt = revoke(&forward).expect("forward revocation succeeds");
    let backward_receipt = revoke(&backward).expect("reversed revocation succeeds");
    assert_ne!(
        forward_receipt.request_digest, backward_receipt.request_digest,
        "distinct request ids must digest distinctly"
    );
    assert_eq!(
        forward_receipt.affected_refs,
        backward_receipt.affected_refs
    );
    let forward_members: Vec<&[String]> = forward_receipt
        .closures
        .iter()
        .map(|closure| closure.dependent_refs.as_slice())
        .collect();
    let backward_members: Vec<&[String]> = backward_receipt
        .closures
        .iter()
        .map(|closure| closure.dependent_refs.as_slice())
        .collect();
    assert_eq!(forward_members, backward_members);
}

// WORK_UNIT_CASE: 686/7
#[test]
fn quarantined_and_unknown_never_allow_use() {
    let fence = test_fence();
    let quarantined = closure_for(
        "origin:q7",
        vec!["origin:q7".to_string(), "dep:q7".to_string()],
        InfluenceState::Quarantined,
        Some(RevocationReason::Erasure),
        &fence,
        1,
    );
    let quarantined_request = request_for(
        "subject:q7",
        "origin:q7",
        policy_for(&fence, false),
        provenance_for("subject:q7", "origin:q7", &fence, clean_assurance(&fence)),
        quarantined,
    );
    let quarantined_decision = decide(&quarantined_request).expect("quarantined decide succeeds");
    assert_eq!(
        quarantined_decision.disposition,
        InfluenceDisposition::Quarantined
    );
    assert_eq!(quarantined_decision.allowed_level, InfluenceLevel::Stored);
    assert!(
        quarantined_decision
            .reasons
            .contains(&InfluenceReason::DependencyQuarantined),
        "quarantined closure must report DependencyQuarantined: {:?}",
        quarantined_decision.reasons
    );

    let unknown = closure_for(
        "origin:u7",
        vec!["origin:u7".to_string(), "dep:u7".to_string()],
        InfluenceState::Unknown,
        Some(RevocationReason::Erasure),
        &fence,
        1,
    );
    let unknown_request = request_for(
        "subject:u7",
        "origin:u7",
        policy_for(&fence, false),
        provenance_for("subject:u7", "origin:u7", &fence, clean_assurance(&fence)),
        unknown,
    );
    let unknown_decision = decide(&unknown_request).expect("unknown decide succeeds");
    assert_eq!(
        unknown_decision.disposition,
        InfluenceDisposition::Quarantined
    );
    assert_eq!(unknown_decision.allowed_level, InfluenceLevel::Stored);
    assert!(
        unknown_decision
            .reasons
            .contains(&InfluenceReason::DependencyQuarantined),
        "unknown closure must fail closed to DependencyQuarantined: {:?}",
        unknown_decision.reasons
    );

    for decision in [&quarantined_decision, &unknown_decision] {
        assert_ne!(
            decision.disposition,
            InfluenceDisposition::Allowed,
            "blocked closure must never allow use"
        );
        assert_ne!(
            decision.disposition,
            InfluenceDisposition::Revoked,
            "non-revoked closure must not report Revoked"
        );
    }
}

// WORK_UNIT_CASE: 686/8
#[test]
fn stale_source_keeps_revocation_visible() {
    let fence = test_fence();
    let mut assurance = clean_assurance(&fence);
    assurance.freshness = FreshnessStatus::Stale;
    let closure = closure_for(
        "origin:stale",
        vec!["origin:stale".to_string(), "dep:stale".to_string()],
        InfluenceState::Revoked,
        Some(RevocationReason::SourceRevoked),
        &fence,
        0,
    );
    let request = request_for(
        "subject:stale",
        "origin:stale",
        policy_for(&fence, true),
        provenance_for("subject:stale", "origin:stale", &fence, assurance),
        closure,
    );
    let decision = decide(&request).expect("stale revoked decide succeeds");
    assert_eq!(decision.disposition, InfluenceDisposition::Revoked);
    assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
    assert!(
        decision
            .reasons
            .contains(&InfluenceReason::DependencyRevoked),
        "revocation must stay visible under staleness: {:?}",
        decision.reasons
    );
    assert!(
        decision.reasons.contains(&InfluenceReason::SourceStale),
        "staleness must still be reported: {:?}",
        decision.reasons
    );
}

// WORK_UNIT_CASE: 686/9
#[test]
fn fence_mismatch_refuses_and_wrong_scope_stays_revoked() {
    let fenced = test_fence();
    let drifted = test_fence_seq2();
    // (a) The provenance (and its assurance) moved to epoch sequence 2 while
    // the policy and closure stay on sequence 1.
    let closure = closure_for(
        "origin:fence",
        vec!["origin:fence".to_string(), "dep:fence".to_string()],
        InfluenceState::Active,
        None,
        &fenced,
        1,
    );
    let drifted_request = request_for(
        "subject:fence",
        "origin:fence",
        policy_for(&fenced, false),
        provenance_for(
            "subject:fence",
            "origin:fence",
            &drifted,
            clean_assurance(&drifted),
        ),
        closure,
    );
    match drifted_request.validate() {
        Ok(()) => panic!("fence drift must fail validation"),
        Err(error) => expect_fence_mismatch(&error, "validate"),
    }
    match drifted_request.digest() {
        Ok(_) => panic!("fence drift must fail digest"),
        Err(error) => expect_fence_mismatch(&error, "digest"),
    }
    match decide(&drifted_request) {
        Ok(_) => panic!("fence drift must fail decide"),
        Err(error) => expect_fence_mismatch(&error, "decide"),
    }

    // (b) A WrongScope revocation still blocks use through decide.
    let scopes = vec![InfluenceEdge {
        source_ref: "origin:scope".to_string(),
        dependent_ref: "dep:scope".to_string(),
    }];
    let scope_request = revocation_request(
        "revoke:686:9",
        "origin:scope",
        RevocationReason::WrongScope,
        &fenced,
        scopes,
    );
    let scope_receipt = revoke(&scope_request).expect("wrong-scope revocation succeeds");
    for scope_closure in &scope_receipt.closures {
        assert_eq!(
            scope_closure.invalidation_reason,
            Some(RevocationReason::WrongScope)
        );
    }
    let target = scope_receipt
        .closures
        .iter()
        .find(|scope_closure| scope_closure.closure_id.ends_with("dep:scope"))
        .expect("scoped dependent closure is present");
    let decision =
        decide(&decide_request_for_closure("scope", target)).expect("wrong-scope decide succeeds");
    assert_eq!(decision.disposition, InfluenceDisposition::Revoked);
    assert!(
        decision
            .reasons
            .contains(&InfluenceReason::DependencyRevoked),
        "wrong-scope closure must report DependencyRevoked: {:?}",
        decision.reasons
    );
}

// WORK_UNIT_CASE: 686/10
#[test]
fn bounded_exhaustion_retains_exact_frontier() {
    let fence = test_fence();
    let edge = |source: &str, dependent: &str| InfluenceEdge {
        source_ref: source.to_string(),
        dependent_ref: dependent.to_string(),
    };
    let edges = vec![
        edge("node:r", "node:a"),
        edge("node:r", "node:b"),
        edge("node:a", "node:c"),
        edge("node:b", "node:c"),
        edge("node:c", "node:d"),
        edge("node:d", "node:b"),
        edge("node:d", "node:e"),
        edge("node:e", "node:f"),
        edge("node:f", "node:g"),
        edge("node:g", "node:e"),
        edge("node:g", "node:g"),
        edge("far:away", "far:other"),
    ];
    let request = revocation_request(
        "revoke:686:10",
        "node:r",
        RevocationReason::SourceRevoked,
        &fence,
        edges,
    );
    let receipt = revoke(&request).expect("bounded revocation succeeds");
    assert_eq!(
        receipt.affected_refs,
        vec![
            "node:a".to_string(),
            "node:b".to_string(),
            "node:c".to_string(),
            "node:d".to_string(),
            "node:e".to_string(),
            "node:f".to_string(),
            "node:g".to_string(),
            "node:r".to_string(),
        ]
    );
    assert_eq!(receipt.closures.len(), 8);
    assert_sorted_unique(&receipt.affected_refs, "bounded");
    assert!(
        !receipt.affected_refs.contains(&"far:away".to_string()),
        "disconnected nodes must stay outside the frontier"
    );
    assert!(
        !receipt.affected_refs.contains(&"far:other".to_string()),
        "disconnected nodes must stay outside the frontier"
    );
    for closure in &receipt.closures {
        assert_eq!(closure.current_influence, InfluenceState::Revoked);
    }
}

// WORK_UNIT_CASE: 686/13
#[test]
fn replay_is_stable_and_changed_payload_conflicts() {
    let fence = test_fence();
    let closure = closure_for(
        "origin:replay",
        vec!["origin:replay".to_string(), "dep:replay".to_string()],
        InfluenceState::Active,
        None,
        &fence,
        1,
    );
    let request = request_for(
        "subject:replay",
        "origin:replay",
        policy_for(&fence, false),
        provenance_for(
            "subject:replay",
            "origin:replay",
            &fence,
            clean_assurance(&fence),
        ),
        closure,
    );
    let first = request.digest().expect("base digest succeeds");
    let replayed = request.digest().expect("replay digest succeeds");
    assert_eq!(first, replayed, "replay must be stable");

    let mut changed = request.clone();
    changed.requested_level = InfluenceLevel::Used;
    let second = changed.digest().expect("changed digest succeeds");
    assert_ne!(first, second, "changed payload must conflict");

    let base_decision = decide(&request).expect("base decide succeeds");
    let changed_decision = decide(&changed).expect("changed decide succeeds");
    assert_eq!(base_decision.request_digest, first);
    assert_eq!(changed_decision.request_digest, second);
    assert_eq!(base_decision.disposition, InfluenceDisposition::Allowed);
    assert_eq!(changed_decision.disposition, InfluenceDisposition::Allowed);

    // The policy minimum is a ceiling (`allowed = requested.min(minimum)`),
    // so lowering the requested level alone cannot trigger
    // `RequestedLevelCapped`. Capping fires when the request exceeds the
    // minimum, and the disposition stays `Allowed`.
    let mut capped_policy = policy_for(&fence, false);
    capped_policy.minimum_level = InfluenceLevel::Available;
    let mut capped = request.clone();
    capped.policy = capped_policy;
    let capped_decision = decide(&capped).expect("capped decide succeeds");
    assert_eq!(capped_decision.disposition, InfluenceDisposition::Allowed);
    assert!(
        capped_decision
            .reasons
            .contains(&InfluenceReason::RequestedLevelCapped),
        "exceeding the minimum must cap: {:?}",
        capped_decision.reasons
    );
}

// WORK_UNIT_CASE: 686/18
#[test]
fn closure_evaluation_is_pure_with_no_authority_path() {
    let fence = test_fence();
    let edges = parse_edges(include_str!("data/transitive-revocation/chain.txt"));
    let request = revocation_request(
        "revoke:686:18",
        "origin:alpha",
        RevocationReason::SourceRevoked,
        &fence,
        edges,
    );
    let frozen = request.clone();
    let first_receipt = revoke(&request).expect("first revocation succeeds");
    assert_eq!(request, frozen, "revoke must not mutate its input");
    let second_receipt = revoke(&request).expect("second revocation succeeds");
    assert_eq!(
        first_receipt, second_receipt,
        "revoke must be deterministic"
    );
    assert_eq!(
        first_receipt.request_digest, second_receipt.request_digest,
        "receipt digest must be stable"
    );

    let target = first_receipt
        .closures
        .iter()
        .find(|closure| closure.closure_id.ends_with("leaf:gamma"))
        .expect("leaf closure is present");
    let decide_request = decide_request_for_closure("pure", target);
    let first_decision = decide(&decide_request).expect("first decide succeeds");
    let second_decision = decide(&decide_request).expect("second decide succeeds");
    assert_eq!(
        first_decision, second_decision,
        "decide must be deterministic"
    );
}

// WORK_UNIT_CASE: 686/20
#[test]
fn mutation_sequences_preserve_unique_members_and_integrate() {
    let fence = test_fence();
    let base_edges = parse_edges(include_str!("data/transitive-revocation/diamond.txt"));

    // Step 1: base diamond closes over exactly four members.
    let base = revocation_request(
        "revoke:686:20a",
        "origin:alpha",
        RevocationReason::SourceRevoked,
        &fence,
        base_edges,
    );
    let base_receipt = revoke(&base).expect("base revocation succeeds");
    assert_eq!(base_receipt.affected_refs.len(), 4);
    assert_sorted_unique(&base_receipt.affected_refs, "base");
    assert_eq!(
        base_receipt.closures.len(),
        base_receipt.affected_refs.len()
    );

    // Step 2: growing the frontier adds the tip and keeps every base member.
    let mut grown_edges = parse_edges(include_str!("data/transitive-revocation/diamond.txt"));
    grown_edges.push(InfluenceEdge {
        source_ref: "leaf:delta".to_string(),
        dependent_ref: "tip:extra".to_string(),
    });
    let grown = revocation_request(
        "revoke:686:20b",
        "origin:alpha",
        RevocationReason::SourceRevoked,
        &fence,
        grown_edges,
    );
    let grown_receipt = revoke(&grown).expect("grown revocation succeeds");
    assert_eq!(grown_receipt.affected_refs.len(), 5);
    assert_sorted_unique(&grown_receipt.affected_refs, "grown");
    assert_eq!(
        grown_receipt.closures.len(),
        grown_receipt.affected_refs.len()
    );
    let base_set: BTreeSet<&str> = base_receipt
        .affected_refs
        .iter()
        .map(String::as_str)
        .collect();
    for member in &base_set {
        assert!(
            grown_receipt.affected_refs.iter().any(|hit| hit == member),
            "grown closure must be a superset of the base closure"
        );
    }

    // Step 3: dropping one convergence edge keeps the leaf via the other
    // branch, so the member set is unchanged.
    let mut pruned_edges = parse_edges(include_str!("data/transitive-revocation/diamond.txt"));
    pruned_edges
        .retain(|edge| !(edge.source_ref == "branch:c" && edge.dependent_ref == "leaf:delta"));
    pruned_edges.push(InfluenceEdge {
        source_ref: "leaf:delta".to_string(),
        dependent_ref: "tip:extra".to_string(),
    });
    let pruned = revocation_request(
        "revoke:686:20c",
        "origin:alpha",
        RevocationReason::SourceRevoked,
        &fence,
        pruned_edges,
    );
    let pruned_receipt = revoke(&pruned).expect("pruned revocation succeeds");
    assert_eq!(pruned_receipt.affected_refs, grown_receipt.affected_refs);
    assert_eq!(
        pruned_receipt.closures.len(),
        pruned_receipt.affected_refs.len()
    );

    // Production integration: a revoke closure feeds decide and blocks use.
    let tip = pruned_receipt
        .closures
        .iter()
        .find(|closure| closure.closure_id.ends_with("tip:extra"))
        .expect("tip closure is present");
    let decision = decide(&decide_request_for_closure("tip", tip)).expect("tip decide succeeds");
    assert_eq!(decision.disposition, InfluenceDisposition::Revoked);
    assert_eq!(decision.allowed_level, InfluenceLevel::Stored);
    assert!(
        decision
            .reasons
            .contains(&InfluenceReason::DependencyRevoked),
        "tip closure must report DependencyRevoked: {:?}",
        decision.reasons
    );
}
