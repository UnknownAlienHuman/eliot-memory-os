#![allow(clippy::expect_used)]

use eliot_agent_contracts::TargetId;
use eliot_contracts::{
    ArtifactId, EpochId, EpochLineageId, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::EvidenceFreshness;
use eliot_learning_contracts::{
    AttemptLearningDeltaCandidate, CampaignId, CampaignLearningStateView, ChangeOperation,
    ChangeSurface, Completeness, ContractBinding, InverseChange, LearningStateViewRecipe, MemberId,
    MemberProjection, OmissionPolicy, OwnerId, ProofCeiling, SlotDisposition, SlotId,
    SlotProjection, SlotRequirement, SlotSpec, SourceDenominator, ValueState,
};
use eliot_learning_overlay::{
    AdmittedDeltaPair, OverlayComposeInput, OverlayError, compose_campaign_harness_overlay,
};
use std::collections::BTreeMap;

fn aid(value: &str) -> ArtifactId {
    ArtifactId::new(value).expect("fixture identity")
}

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn binding() -> ContractBinding {
    let mut fence = StateFence::new(
        EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid test lineage"),
            std::num::NonZeroU64::new(1).expect("nonzero test sequence"),
        )
        .expect("valid test epoch"),
        ResourceGeneration::genesis(),
    );
    fence.task_revision = Some(TaskRevision::genesis());
    fence.policy_revision = Some(PolicyRevision::genesis());
    ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new("request-overlay").expect("request"),
        operation_id: OperationId::new("operation-overlay").expect("operation"),
        product_id: ProductId::new("eliot").expect("product"),
        task_id: TaskId::new("task-overlay").expect("task"),
        scope: eliot_learning_contracts::WorkScopeId::new("scope-overlay").expect("scope"),
        state_fence: fence,
        source: eliot_learning_contracts::identity::SourceLineage {
            owner: SourceId::new("source-overlay").expect("source"),
            snapshot: aid("snapshot-overlay"),
            revision: TaskRevision::genesis(),
            digest: digest("source"),
        },
        proof_ceiling: ProofCeiling::CandidateArtifact,
    }
}

struct Fixture {
    recipe: LearningStateViewRecipe,
    view: CampaignLearningStateView,
    targets: [TargetId; 3],
    discriminator: ArtifactId,
}

#[allow(clippy::too_many_lines)]
fn fixture() -> Fixture {
    let binding = binding();
    let targets = [
        TargetId::new("target-add").expect("target"),
        TargetId::new("target-replace").expect("target"),
        TargetId::new("target-remove").expect("target"),
    ];
    let members = [
        MemberId::from_artifact(aid("member-replace")),
        MemberId::from_artifact(aid("member-remove")),
    ];
    let specs = vec![
        SlotSpec {
            slot_id: SlotId::from_artifact(aid("slot-add")),
            owner: OwnerId::from_artifact(aid("owner-add")),
            target: targets[0].clone(),
            requirement: SlotRequirement::Optional,
            declared_members: vec![],
            accepted_type: "verification/v1".to_owned(),
            schema_digest: digest("schema-add"),
        },
        SlotSpec {
            slot_id: SlotId::from_artifact(aid("slot-replace")),
            owner: OwnerId::from_artifact(aid("owner-replace")),
            target: targets[1].clone(),
            requirement: SlotRequirement::Optional,
            declared_members: vec![members[0].clone()],
            accepted_type: "verification/v1".to_owned(),
            schema_digest: digest("schema-replace"),
        },
        SlotSpec {
            slot_id: SlotId::from_artifact(aid("slot-remove")),
            owner: OwnerId::from_artifact(aid("owner-remove")),
            target: targets[2].clone(),
            requirement: SlotRequirement::Optional,
            declared_members: vec![members[1].clone()],
            accepted_type: "verification/v1".to_owned(),
            schema_digest: digest("schema-remove"),
        },
    ];
    let mut recipe = LearningStateViewRecipe {
        recipe_id: aid("recipe-overlay"),
        campaign_id: CampaignId::from_artifact(aid("campaign-overlay")),
        target: TargetId::new("task-target").expect("target"),
        binding: binding.clone(),
        slots: specs.clone(),
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy: OmissionPolicy::RequiredSlots,
        canonical_digest: String::new(),
    };
    recipe.seal().expect("recipe seal");
    let source = binding.source.clone();
    let members_for = |member: &MemberId, owner: &OwnerId, value: &str| MemberProjection {
        member_id: member.clone(),
        owner: owner.clone(),
        source: source.clone(),
        projection_revision: TaskRevision::genesis(),
        disposition: SlotDisposition::Current,
        value_digest: Some(digest(value)),
        evidence: vec![aid("member-evidence")],
    };
    let slots = vec![
        SlotProjection {
            slot_id: specs[0].slot_id.clone(),
            disposition: SlotDisposition::KnownEmpty,
            members: vec![],
            evidence: vec![aid("empty-owner-evidence")],
        },
        SlotProjection {
            slot_id: specs[1].slot_id.clone(),
            disposition: SlotDisposition::Current,
            members: vec![members_for(&members[0], &specs[1].owner, "replace-before")],
            evidence: vec![aid("replace-slot-evidence")],
        },
        SlotProjection {
            slot_id: specs[2].slot_id.clone(),
            disposition: SlotDisposition::Current,
            members: vec![members_for(&members[1], &specs[2].owner, "remove-before")],
            evidence: vec![aid("remove-slot-evidence")],
        },
    ];
    let mut view = CampaignLearningStateView {
        view_id: aid("view-overlay"),
        recipe_id: recipe.recipe_id.clone(),
        campaign_id: recipe.campaign_id.clone(),
        target: recipe.target.clone(),
        binding,
        recipe_digest: recipe.canonical_digest.clone(),
        slots,
        denominator: SourceDenominator {
            declared: 3,
            observed: 3,
        },
        completeness: Completeness::CompleteForDeclaredRecipe,
        omissions: vec![],
        frontier: vec![],
        owner_disagreements: vec![],
        required_references: vec![aid("objective-reference")],
        invalidated: false,
        invalidation_reason: None,
        canonical_digest: String::new(),
    };
    view.seal().expect("view seal");
    Fixture {
        recipe,
        view,
        targets,
        discriminator: aid("next-discriminator"),
    }
}

fn operation_add(target: &TargetId, value: &str) -> (ChangeOperation, InverseChange) {
    let after = ValueState {
        present: true,
        digest: Some(digest(value)),
    };
    (
        ChangeOperation::Add {
            target: target.clone(),
            surface: ChangeSurface::VerificationOrder,
            after: after.clone(),
        },
        InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Remove {
                target: target.clone(),
                surface: ChangeSurface::VerificationOrder,
                before: after,
            },
        },
    )
}

fn operation_replace(target: &TargetId) -> (ChangeOperation, InverseChange) {
    let before = ValueState {
        present: true,
        digest: Some(digest("replace-before")),
    };
    let after = ValueState {
        present: true,
        digest: Some(digest("replace-after")),
    };
    (
        ChangeOperation::Replace {
            target: target.clone(),
            surface: ChangeSurface::SearchProbeStopping,
            before: before.clone(),
            after: after.clone(),
        },
        InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Replace {
                target: target.clone(),
                surface: ChangeSurface::SearchProbeStopping,
                before: after,
                after: before,
            },
        },
    )
}

fn operation_remove(target: &TargetId) -> (ChangeOperation, InverseChange) {
    let before = ValueState {
        present: true,
        digest: Some(digest("remove-before")),
    };
    (
        ChangeOperation::Remove {
            target: target.clone(),
            surface: ChangeSurface::VerificationOrder,
            before: before.clone(),
        },
        InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Add {
                target: target.clone(),
                surface: ChangeSurface::VerificationOrder,
                after: before,
            },
        },
    )
}

fn delta(
    view: &CampaignLearningStateView,
    id: &str,
    operation: ChangeOperation,
    inverse: InverseChange,
) -> AttemptLearningDeltaCandidate {
    let mut delta = AttemptLearningDeltaCandidate {
        binding: view.binding.clone(),
        attempt_id: eliot_learning_contracts::AgentAttemptId::new(format!("attempt-{id}"))
            .expect("attempt"),
        delta_id: aid(&format!("delta-{id}")),
        target: view.target.clone(),
        base_view_digest: view.canonical_digest.clone(),
        pre_observation_discriminator: aid(&format!("prior-discriminator-{id}")),
        intended_strategy: aid(&format!("intended-{id}")),
        attempted_strategy: aid(&format!("attempted-{id}")),
        changes: vec![operation],
        inverses: vec![inverse],
        evidence: vec![aid(&format!("evidence-{id}"))],
        evaluator_receipts: vec![aid(&format!("evaluator-{id}"))],
        baseline: vec![],
        control: vec![],
        confounders: vec![],
        dependencies: vec![],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    delta.seal().expect("delta seal");
    delta
}

fn input<'a>(
    fixture: &'a Fixture,
    deltas: &'a [AttemptLearningDeltaCandidate],
    admitted: &'a [AdmittedDeltaPair],
) -> OverlayComposeInput<'a> {
    OverlayComposeInput {
        recipe: &fixture.recipe,
        view: &fixture.view,
        deltas,
        admitted,
        overlay_id: eliot_learning_contracts::OverlayId::from_artifact(aid("overlay-result")),
        parent_revision: TaskRevision::genesis(),
        protected_surface_base_digest: "0000000000000000000000000000000000000000000000000000000000000000",
        protected_surface_proposed_digest: "0000000000000000000000000000000000000000000000000000000000000000",
        fixed_before_observation_discriminator: &fixture.discriminator,
        expires_at_ms: 2_000,
        observed_at_ms: 1_000,
    }
}

fn admitted(deltas: &[AttemptLearningDeltaCandidate]) -> Vec<AdmittedDeltaPair> {
    deltas
        .iter()
        .map(|delta| AdmittedDeltaPair {
            delta_id: delta.delta_id.clone(),
            canonical_digest: delta.canonical_digest.clone(),
        })
        .collect()
}

fn apply_operation(states: &mut BTreeMap<String, ValueState>, operation: &ChangeOperation) {
    match operation {
        ChangeOperation::Replace { target, after, .. }
        | ChangeOperation::Add { target, after, .. } => {
            states.insert(target.as_str().to_owned(), after.clone());
        }
        ChangeOperation::Remove { target, .. } => {
            states.insert(
                target.as_str().to_owned(),
                ValueState {
                    present: false,
                    digest: None,
                },
            );
        }
    }
}

#[test]
fn composes_disjoint_add_replace_remove_with_exact_inverses() {
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "add-value");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let (remove, remove_inverse) = operation_remove(&fixture.targets[2]);
    let deltas = vec![
        delta(&fixture.view, "add", add, add_inverse),
        delta(&fixture.view, "replace", replace, replace_inverse),
        delta(&fixture.view, "remove", remove, remove_inverse),
    ];
    let pairs = admitted(&deltas);
    let original_view = fixture.view.clone();
    let candidate =
        compose_campaign_harness_overlay(&input(&fixture, &deltas, &pairs)).expect("candidate");
    assert_eq!(candidate.changes.len(), 3);
    assert!(candidate.is_reversible());
    assert_eq!(candidate.application_order[0], fixture.targets[0]);
    let mut base_states = BTreeMap::new();
    base_states.insert(
        fixture.targets[0].as_str().to_owned(),
        ValueState {
            present: false,
            digest: None,
        },
    );
    base_states.insert(
        fixture.targets[1].as_str().to_owned(),
        ValueState {
            present: true,
            digest: Some(digest("replace-before")),
        },
    );
    base_states.insert(
        fixture.targets[2].as_str().to_owned(),
        ValueState {
            present: true,
            digest: Some(digest("remove-before")),
        },
    );
    let mut applied_states = BTreeMap::new();
    for change in &candidate.changes {
        applied_states.insert(change.target.as_str().to_owned(), change.base.clone());
        apply_operation(
            &mut applied_states,
            &ChangeOperation::Replace {
                target: change.target.clone(),
                surface: change.surface,
                before: change.base.clone(),
                after: change.proposed.clone(),
            },
        );
    }
    for target in candidate.application_order.iter().rev() {
        let change = candidate
            .changes
            .iter()
            .find(|change| change.target == *target)
            .expect("ordered change");
        apply_operation(&mut applied_states, &change.inverse.inverse);
    }
    assert_eq!(applied_states, base_states);
    assert_eq!(fixture.view, original_view);
}

#[test]
fn rejects_binding_and_admission_mismatch() {
    let fixture = fixture();
    let (add, inverse) = operation_add(&fixture.targets[0], "add-value");
    let mut binding_delta = delta(&fixture.view, "binding", add, inverse);
    binding_delta.binding.request_id = RequestId::new("different-request").expect("request");
    let deltas = vec![binding_delta];
    let pairs = admitted(&deltas);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &deltas, &pairs)),
        Err(OverlayError::Contract(_))
    ));
    let valid = delta(
        &fixture.view,
        "admission",
        operation_add(&fixture.targets[0], "x").0,
        operation_add(&fixture.targets[0], "x").1,
    );
    let mut wrong_pairs = admitted(std::slice::from_ref(&valid));
    wrong_pairs[0].canonical_digest = digest("different");
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[valid], &wrong_pairs)),
        Err(OverlayError::Conflict {
            field: "admitted.digest"
        })
    ));
}

#[test]
fn rejects_unsupported_surfaces_and_opaque_dependencies() {
    let fixture = fixture();
    let mut operation = operation_add(&fixture.targets[0], "unsupported");
    operation.0 = ChangeOperation::Add {
        target: fixture.targets[0].clone(),
        surface: ChangeSurface::Memory,
        after: ValueState {
            present: true,
            digest: Some(digest("unsupported")),
        },
    };
    operation.1.inverse = ChangeOperation::Remove {
        target: fixture.targets[0].clone(),
        surface: ChangeSurface::Memory,
        before: ValueState {
            present: true,
            digest: Some(digest("unsupported")),
        },
    };
    let rejected = delta(&fixture.view, "surface", operation.0, operation.1);
    let pairs = admitted(std::slice::from_ref(&rejected));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[rejected], &pairs)),
        Err(OverlayError::Unsupported {
            field: "change.surface"
        })
    ));
    let (add, inverse) = operation_add(&fixture.targets[0], "dependency");
    let mut dependent = delta(&fixture.view, "dependency", add, inverse);
    dependent.dependencies.push(aid("opaque-dependency"));
    let pairs = admitted(std::slice::from_ref(&dependent));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[dependent], &pairs)),
        Err(OverlayError::Unsupported {
            field: "delta.dependencies"
        })
    ));
}

#[test]
fn rejects_noncurrent_member_and_inexact_before_value() {
    let mut stale_fixture = fixture();
    stale_fixture.view.slots[1].members[0].disposition = SlotDisposition::Historical;
    stale_fixture.view.seal().expect("view reseal");
    let (replace, inverse) = operation_replace(&stale_fixture.targets[1]);
    let stale_delta = delta(&stale_fixture.view, "stale", replace, inverse);
    let pairs = admitted(std::slice::from_ref(&stale_delta));
    let stale_result =
        compose_campaign_harness_overlay(&input(&stale_fixture, &[stale_delta], &pairs));
    assert!(matches!(
        stale_result,
        Err(OverlayError::Unsupported { .. } | OverlayError::Contract(_))
    ));
    let fixture = fixture();
    let before = ValueState {
        present: true,
        digest: Some(digest("wrong-before")),
    };
    let after = ValueState {
        present: true,
        digest: Some(digest("after")),
    };
    let operation = ChangeOperation::Replace {
        target: fixture.targets[1].clone(),
        surface: ChangeSurface::VerificationOrder,
        before: before.clone(),
        after,
    };
    let inverse = InverseChange {
        forward_target: fixture.targets[1].clone(),
        inverse: ChangeOperation::Replace {
            target: fixture.targets[1].clone(),
            surface: ChangeSurface::VerificationOrder,
            before: ValueState {
                present: true,
                digest: Some(digest("after")),
            },
            after: before,
        },
    };
    let wrong_delta = delta(&fixture.view, "wrong-before", operation, inverse);
    let pairs = admitted(std::slice::from_ref(&wrong_delta));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[wrong_delta], &pairs)),
        Err(OverlayError::Contract(_))
    ));
}

#[test]
fn rejects_expired_or_protected_surface_change() {
    let fixture = fixture();
    let (add, inverse) = operation_add(&fixture.targets[0], "expiry");
    let delta = delta(&fixture.view, "expiry", add, inverse);
    let pairs = admitted(std::slice::from_ref(&delta));
    let mut expired = input(&fixture, std::slice::from_ref(&delta), &pairs);
    expired.observed_at_ms = 2_000;
    assert!(matches!(
        compose_campaign_harness_overlay(&expired),
        Err(OverlayError::Expired)
    ));
    let mut protected = input(&fixture, std::slice::from_ref(&delta), &pairs);
    protected.protected_surface_proposed_digest = "1";
    assert!(matches!(
        compose_campaign_harness_overlay(&protected),
        Err(OverlayError::ProtectedSurfaceChanged)
    ));
}

#[test]
fn bounds_and_delta_order_are_deterministic() {
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "order-add");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let first = vec![
        delta(&fixture.view, "order-a", add, add_inverse),
        delta(&fixture.view, "order-b", replace, replace_inverse),
    ];
    let first_pairs = admitted(&first);
    let first_candidate = compose_campaign_harness_overlay(&input(&fixture, &first, &first_pairs))
        .expect("first candidate");
    let second = vec![first[1].clone(), first[0].clone()];
    let second_pairs = admitted(&second);
    let second_candidate =
        compose_campaign_harness_overlay(&input(&fixture, &second, &second_pairs))
            .expect("second candidate");
    assert_eq!(first_candidate.changes, second_candidate.changes);
    assert_eq!(
        first_candidate.admitted_delta_ids,
        second_candidate.admitted_delta_ids
    );
    assert_eq!(
        first_candidate.canonical_digest,
        second_candidate.canonical_digest
    );
    let mut huge_pairs = admitted(&first);
    huge_pairs[0].canonical_digest = "x".repeat(8193);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &first, &huge_pairs)),
        Err(OverlayError::Bound {
            field: "admitted.canonical_digest"
        })
    ));
}

// ------- WORK_UNIT_CASE 618 helpers (append-only; the 6 precursor tests above are unchanged) -------

fn next_revision() -> TaskRevision {
    TaskRevision::genesis().next().expect("next revision")
}

fn resealed_view(
    view: &CampaignLearningStateView,
    mutate: impl FnOnce(&mut CampaignLearningStateView),
) -> CampaignLearningStateView {
    let mut next = view.clone();
    mutate(&mut next);
    next.seal().expect("view reseal");
    next
}

fn mutated_delta(
    view: &CampaignLearningStateView,
    id: &str,
    operation: ChangeOperation,
    inverse: InverseChange,
    mutate: impl FnOnce(&mut AttemptLearningDeltaCandidate),
) -> AttemptLearningDeltaCandidate {
    let mut next = delta(view, id, operation, inverse);
    mutate(&mut next);
    next.seal().expect("delta reseal");
    next
}

fn add_with_surface(
    target: &TargetId,
    surface: ChangeSurface,
    value: &str,
) -> (ChangeOperation, InverseChange) {
    let after = ValueState {
        present: true,
        digest: Some(digest(value)),
    };
    (
        ChangeOperation::Add {
            target: target.clone(),
            surface,
            after: after.clone(),
        },
        InverseChange {
            forward_target: target.clone(),
            inverse: ChangeOperation::Remove {
                target: target.clone(),
                surface,
                before: after,
            },
        },
    )
}

fn add_delta_for(fixture: &Fixture, id: &str, value: &str) -> AttemptLearningDeltaCandidate {
    let (operation, inverse) = operation_add(&fixture.targets[0], value);
    delta(&fixture.view, id, operation, inverse)
}

fn compose_single_add(
    fixture: &Fixture,
    id: &str,
    value: &str,
) -> eliot_learning_contracts::CampaignHarnessOverlayCandidate {
    let deltas = vec![add_delta_for(fixture, id, value)];
    let pairs = admitted(&deltas);
    compose_campaign_harness_overlay(&input(fixture, &deltas, &pairs))
        .expect("single-add candidate")
}

fn expected_base_map(fixture: &Fixture) -> BTreeMap<String, ValueState> {
    BTreeMap::from([
        (
            fixture.targets[0].as_str().to_owned(),
            ValueState {
                present: false,
                digest: None,
            },
        ),
        (
            fixture.targets[1].as_str().to_owned(),
            ValueState {
                present: true,
                digest: Some(digest("replace-before")),
            },
        ),
        (
            fixture.targets[2].as_str().to_owned(),
            ValueState {
                present: true,
                digest: Some(digest("remove-before")),
            },
        ),
    ])
}

fn full_candidate(
    fixture: &Fixture,
) -> (
    Vec<AttemptLearningDeltaCandidate>,
    eliot_learning_contracts::CampaignHarnessOverlayCandidate,
) {
    let (add, add_inverse) = operation_add(&fixture.targets[0], "add-value");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let (remove, remove_inverse) = operation_remove(&fixture.targets[2]);
    let deltas = vec![
        delta(&fixture.view, "add", add, add_inverse),
        delta(&fixture.view, "replace", replace, replace_inverse),
        delta(&fixture.view, "remove", remove, remove_inverse),
    ];
    let pairs = admitted(&deltas);
    let candidate =
        compose_campaign_harness_overlay(&input(fixture, &deltas, &pairs)).expect("candidate");
    (deltas, candidate)
}

fn forward_of(change: &eliot_learning_contracts::OverlayChange) -> Option<ChangeOperation> {
    match (change.base.present, change.proposed.present) {
        (false, true) => Some(ChangeOperation::Add {
            target: change.target.clone(),
            surface: change.surface,
            after: change.proposed.clone(),
        }),
        (true, false) => Some(ChangeOperation::Remove {
            target: change.target.clone(),
            surface: change.surface,
            before: change.base.clone(),
        }),
        (true, true) => Some(ChangeOperation::Replace {
            target: change.target.clone(),
            surface: change.surface,
            before: change.base.clone(),
            after: change.proposed.clone(),
        }),
        (false, false) => None,
    }
}

// WORK_UNIT_CASE: 618/1
#[test]
fn case_01_valid_single_delta_task_local_overlay() {
    let fixture = fixture();
    let candidate = compose_single_add(&fixture, "solo", "solo-value");
    candidate.validate().expect("contract-valid candidate");
    assert_eq!(candidate.changes.len(), 1);
    assert_eq!(candidate.application_order.len(), 1);
    let change = &candidate.changes[0];
    assert_eq!(change.target, fixture.targets[0]);
    assert_eq!(change.surface, ChangeSurface::VerificationOrder);
    assert_eq!(
        change.origin,
        eliot_learning_contracts::OverlayOrigin::Overlay
    );
    assert!(!change.base.present);
    assert_eq!(change.base.digest, None);
    assert_eq!(change.proposed.digest, Some(digest("solo-value")));
    assert_eq!(candidate.application_order[0], fixture.targets[0]);
    assert_eq!(candidate.base_view_digest, fixture.view.canonical_digest);
    assert_eq!(candidate.binding, fixture.view.binding);
    assert_eq!(candidate.admitted_delta_ids.len(), 1);
    assert!(!candidate.canonical_digest.is_empty());
    assert!(candidate.is_reversible());
}

// WORK_UNIT_CASE: 618/2
#[test]
fn case_02_valid_multiple_disjoint_commuting_changes() {
    let fixture = fixture();
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let (remove, remove_inverse) = operation_remove(&fixture.targets[2]);
    let deltas = vec![
        delta(&fixture.view, "replace", replace, replace_inverse),
        delta(&fixture.view, "remove", remove, remove_inverse),
    ];
    let pairs = admitted(&deltas);
    let candidate =
        compose_campaign_harness_overlay(&input(&fixture, &deltas, &pairs)).expect("candidate");
    candidate.validate().expect("contract-valid candidate");
    assert_eq!(candidate.changes.len(), 2);
    assert_eq!(candidate.changes[0].target, fixture.targets[2]);
    assert_eq!(candidate.changes[1].target, fixture.targets[1]);
    assert_eq!(
        candidate.application_order,
        vec![fixture.targets[2].clone(), fixture.targets[1].clone()]
    );
    assert!(candidate.is_reversible());
}

// WORK_UNIT_CASE: 618/3
#[test]
fn case_03_exact_overlay_surface_conflict_rollback_vocabulary() {
    let fixture = fixture();
    let (_, candidate) = full_candidate(&fixture);
    assert!(
        candidate
            .changes
            .iter()
            .any(|change| change.surface == ChangeSurface::VerificationOrder)
    );
    assert!(
        candidate
            .changes
            .iter()
            .any(|change| change.surface == ChangeSurface::SearchProbeStopping)
    );
    for change in &candidate.changes {
        assert_eq!(
            change.origin,
            eliot_learning_contracts::OverlayOrigin::Overlay
        );
        assert_eq!(change.inverse.forward_target, change.target);
        let forward = forward_of(change).expect("forward operation");
        assert!(change.inverse.is_exact_inverse_of(&forward));
    }
    assert!(candidate.is_reversible());
    let variants = [
        format!("{}", OverlayError::Expired),
        format!("{}", OverlayError::ProtectedSurfaceChanged),
        format!("{}", OverlayError::Bound { field: "deltas" }),
        format!(
            "{}",
            OverlayError::Unsupported {
                field: "change.surface"
            }
        ),
        format!(
            "{}",
            OverlayError::Conflict {
                field: "change.target"
            }
        ),
    ];
    for (index, left) in variants.iter().enumerate() {
        assert!(!left.is_empty());
        for right in variants.iter().skip(index + 1) {
            assert_ne!(left, right);
        }
    }
}

// WORK_UNIT_CASE: 618/4
#[test]
fn case_04_task_target_scope_fence_base_parent_mismatch() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "mismatch");
    let wrong_target = mutated_delta(
        &fixture.view,
        "target",
        add.clone(),
        add_inverse.clone(),
        |next| {
            next.target = TargetId::new("task-other-target").expect("target");
        },
    );
    let pairs = admitted(std::slice::from_ref(&wrong_target));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[wrong_target], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.binding"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "mismatch");
    let wrong_scope = mutated_delta(&fixture.view, "scope", add, add_inverse, |next| {
        next.binding.scope =
            eliot_learning_contracts::WorkScopeId::new("scope-other").expect("scope");
    });
    let pairs = admitted(std::slice::from_ref(&wrong_scope));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[wrong_scope], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.binding"
        }))
    ));
    let stale_view = resealed_view(&fixture.view, |view| {
        view.required_references.push(aid("extra-reference"));
    });
    assert_ne!(stale_view.canonical_digest, fixture.view.canonical_digest);
    let (add, add_inverse) = operation_add(&fixture.targets[0], "mismatch");
    let stale_delta = delta(&fixture.view, "stale", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&stale_delta));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(
            &Fixture {
                recipe: fixture.recipe.clone(),
                view: stale_view,
                targets: fixture.targets.clone(),
                discriminator: fixture.discriminator.clone(),
            },
            &[stale_delta],
            &pairs,
        )),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.view_lineage"
        }))
    ));
    let mut recipe = fixture.recipe.clone();
    recipe.binding.state_fence.policy_revision = None;
    recipe.seal().expect("recipe reseal");
    let mut fenced = fixture.view.clone();
    fenced.binding.state_fence.policy_revision = None;
    fenced.recipe_digest = recipe.canonical_digest.clone();
    fenced.seal().expect("view reseal");
    let (add, add_inverse) = operation_add(&fixture.targets[0], "mismatch");
    let fenced_delta = delta(&fenced, "fence", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&fenced_delta));
    let fenced_fixture = Fixture {
        recipe,
        view: fenced,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fenced_fixture, &[fenced_delta], &pairs,)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "binding.policy_revision"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "mismatch");
    let deltas = vec![delta(&fixture.view, "parent", add, add_inverse)];
    let pairs = admitted(&deltas);
    let owned = input(&fixture, &deltas, &pairs);
    let wrong_parent = OverlayComposeInput {
        parent_revision: next_revision(),
        ..owned
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&wrong_parent),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "parent_revision"
        }))
    ));
}

// WORK_UNIT_CASE: 618/5
#[test]
fn case_05_missing_stale_wrong_parent_revision() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let mut recipe = fixture.recipe.clone();
    recipe.binding.state_fence.task_revision = None;
    recipe.seal().expect("recipe reseal");
    let mut parentless = fixture.view.clone();
    parentless.binding.state_fence.task_revision = None;
    parentless.recipe_digest = recipe.canonical_digest.clone();
    parentless.seal().expect("view reseal");
    let (add, add_inverse) = operation_add(&fixture.targets[0], "parentless");
    let parentless_delta = delta(&parentless, "parentless", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&parentless_delta));
    let parentless_fixture = Fixture {
        recipe,
        view: parentless,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&parentless_fixture, &[parentless_delta], &pairs,)),
        Err(OverlayError::Contract(Contract::Missing {
            field: "parent_revision"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "stale-parent");
    let stale_delta = delta(&fixture.view, "stale-parent", add, add_inverse);
    let resealed = resealed_view(&fixture.view, |view| {
        view.required_references.push(aid("parent-proof-reference"));
    });
    assert_eq!(resealed.view_id, fixture.view.view_id);
    assert_ne!(resealed.canonical_digest, fixture.view.canonical_digest);
    let pairs = admitted(std::slice::from_ref(&stale_delta));
    let before_view = resealed.clone();
    let stale_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: resealed,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    let stale_result =
        compose_campaign_harness_overlay(&input(&stale_fixture, &[stale_delta], &pairs));
    assert!(matches!(
        stale_result,
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.view_lineage"
        }))
    ));
    assert_eq!(stale_fixture.view, before_view);
    let (add, add_inverse) = operation_add(&fixture.targets[0], "wrong-parent");
    let deltas = vec![delta(&fixture.view, "wrong-parent", add, add_inverse)];
    let pairs = admitted(&deltas);
    let owned = input(&fixture, &deltas, &pairs);
    let wrong = OverlayComposeInput {
        parent_revision: next_revision(),
        ..owned
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&wrong),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "parent_revision"
        }))
    ));
}

// WORK_UNIT_CASE: 618/6
#[test]
fn case_06_same_base_id_with_changed_digest() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let evolved = resealed_view(&fixture.view, |view| {
        view.required_references.push(aid("evolved-reference"));
    });
    assert_eq!(evolved.view_id, fixture.view.view_id);
    assert_ne!(evolved.canonical_digest, fixture.view.canonical_digest);
    let (add, add_inverse) = operation_add(&fixture.targets[0], "evolved");
    let pinned_old = delta(&fixture.view, "evolved", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&pinned_old));
    let evolved_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: evolved.clone(),
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&evolved_fixture, &[pinned_old], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.view_lineage"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "evolved-fresh");
    let fresh = delta(&evolved, "evolved-fresh", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&fresh));
    let candidate = compose_campaign_harness_overlay(&input(&evolved_fixture, &[fresh], &pairs))
        .expect("fresh candidate");
    assert_eq!(candidate.base_view_digest, evolved.canonical_digest);
    assert_ne!(candidate.base_view_digest, fixture.view.canonical_digest);
}

// WORK_UNIT_CASE: 618/7
#[test]
fn case_07_valid_external_admission_for_evaluation_receipt() {
    let fixture = fixture();
    let (_, candidate) = full_candidate(&fixture);
    let sorted_ids: Vec<String> = candidate
        .admitted_delta_ids
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect();
    let mut ordered = sorted_ids.clone();
    ordered.sort();
    assert_eq!(sorted_ids, ordered);
    assert_eq!(
        candidate.admitted_delta_ids.len(),
        candidate.admitted_delta_digests.len()
    );
    assert_eq!(candidate.admitted_delta_ids.len(), 3);
    for digest in &candidate.admitted_delta_digests {
        assert_eq!(digest.len(), 64);
    }
    let (add, add_inverse) = operation_add(&fixture.targets[0], "receipt");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let deltas = vec![
        delta(&fixture.view, "receipt-a", add, add_inverse),
        delta(&fixture.view, "receipt-b", replace, replace_inverse),
    ];
    let mut reversed_pairs = admitted(&deltas);
    reversed_pairs.reverse();
    let first = compose_campaign_harness_overlay(&input(&fixture, &deltas, &reversed_pairs))
        .expect("reversed receipt order");
    let ordered_pairs = admitted(&deltas);
    let second = compose_campaign_harness_overlay(&input(&fixture, &deltas, &ordered_pairs))
        .expect("ordered receipt order");
    assert_eq!(first.canonical_digest, second.canonical_digest);
    assert_eq!(first.admitted_delta_ids, second.admitted_delta_ids);
}

// WORK_UNIT_CASE: 618/8
#[test]
fn case_08_unadmitted_expired_wrong_policy_delta() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "unadmitted");
    let deltas = vec![delta(&fixture.view, "unadmitted", add, add_inverse)];
    let missing: Vec<AdmittedDeltaPair> = vec![];
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &deltas, &missing)),
        Err(OverlayError::Conflict { field: "admitted" })
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "extra-pair");
    let single = vec![delta(&fixture.view, "extra-pair", add, add_inverse)];
    let mut extra = admitted(&single);
    extra.push(AdmittedDeltaPair {
        delta_id: aid("delta-phantom"),
        canonical_digest: digest("phantom"),
    });
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &single, &extra)),
        Err(OverlayError::Conflict { field: "admitted" })
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "late");
    let late = vec![delta(&fixture.view, "late", add, add_inverse)];
    let pairs = admitted(&late);
    let owned = input(&fixture, &late, &pairs);
    let observed_late = OverlayComposeInput {
        observed_at_ms: 3_000,
        ..owned
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&observed_late),
        Err(OverlayError::Expired)
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "escalated");
    let escalated = mutated_delta(&fixture.view, "escalated", add, add_inverse, |next| {
        next.proof_ceiling = ProofCeiling::ScopedVerification;
    });
    let pairs = admitted(std::slice::from_ref(&escalated));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[escalated], &pairs)),
        Err(OverlayError::Contract(Contract::CandidateCeiling))
    ));
}

// WORK_UNIT_CASE: 618/9
#[test]
fn case_09_exact_before_value_mismatch_and_no_auto_rebase() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let before = ValueState {
        present: true,
        digest: Some(digest("replace-before-tampered")),
    };
    let after = ValueState {
        present: true,
        digest: Some(digest("replace-after")),
    };
    let operation = ChangeOperation::Replace {
        target: fixture.targets[1].clone(),
        surface: ChangeSurface::VerificationOrder,
        before: before.clone(),
        after: after.clone(),
    };
    let inverse = InverseChange {
        forward_target: fixture.targets[1].clone(),
        inverse: ChangeOperation::Replace {
            target: fixture.targets[1].clone(),
            surface: ChangeSurface::VerificationOrder,
            before: after,
            after: before,
        },
    };
    let wrong = delta(&fixture.view, "wrong-before", operation, inverse);
    let pairs = admitted(std::slice::from_ref(&wrong));
    let view_before = fixture.view.clone();
    let delta_before = wrong.clone();
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[wrong], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "change.before"
        }))
    ));
    assert_eq!(fixture.view, view_before);
    assert_eq!(delta_before.canonical_digest, pairs[0].canonical_digest);
    let (add, add_inverse) = operation_add(&fixture.targets[0], "still-valid");
    let valid = vec![delta(&fixture.view, "still-valid", add, add_inverse)];
    let pairs = admitted(&valid);
    compose_campaign_harness_overlay(&input(&fixture, &valid, &pairs))
        .expect("valid after mismatch");
}

// WORK_UNIT_CASE: 618/10
#[test]
fn case_10_every_delta_and_changed_surface_disposition() {
    let fixture = fixture();
    let (deltas, candidate) = full_candidate(&fixture);
    let total_operations: usize = deltas.iter().map(|delta| delta.changes.len()).sum();
    assert_eq!(candidate.changes.len(), total_operations);
    for delta in &deltas {
        for operation in &delta.changes {
            let coverage = candidate
                .changes
                .iter()
                .filter(|change| forward_of(change).as_ref() == Some(operation))
                .count();
            assert_eq!(coverage, 1);
        }
    }
    for change in &candidate.changes {
        let order_hits = candidate
            .application_order
            .iter()
            .filter(|target| **target == change.target)
            .count();
        assert_eq!(order_hits, 1);
        assert_eq!(
            change.origin,
            eliot_learning_contracts::OverlayOrigin::Overlay
        );
    }
    assert_eq!(candidate.application_order.len(), candidate.changes.len());
    let mut identifiers: Vec<&str> = candidate
        .admitted_delta_ids
        .iter()
        .map(ArtifactId::as_str)
        .collect();
    identifiers.sort_unstable();
    identifiers.dedup();
    assert_eq!(identifiers.len(), deltas.len());
}

// WORK_UNIT_CASE: 618/11
#[test]
fn case_11_exact_duplicate_equivalent_replay_with_lineage() {
    let fixture = fixture();
    let first = compose_single_add(&fixture, "replay", "replay-value");
    let second = compose_single_add(&fixture, "replay", "replay-value");
    assert_eq!(first, second);
    assert_eq!(first.canonical_digest, second.canonical_digest);
    assert_eq!(first.admitted_delta_ids, second.admitted_delta_ids);
    assert_eq!(first.admitted_delta_digests, second.admitted_delta_digests);
    let (first_operation, first_inverse) = operation_add(&fixture.targets[0], "same-value");
    let (second_operation, second_inverse) = operation_add(&fixture.targets[0], "same-value");
    let duplicates = vec![
        delta(&fixture.view, "duplicate-a", first_operation, first_inverse),
        delta(
            &fixture.view,
            "duplicate-b",
            second_operation,
            second_inverse,
        ),
    ];
    let pairs = admitted(&duplicates);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &duplicates, &pairs)),
        Err(OverlayError::Conflict {
            field: "change.target"
        })
    ));
    for (index, duplicate) in duplicates.iter().enumerate() {
        let solo = vec![duplicate.clone()];
        let pairs = admitted(&solo);
        let candidate =
            compose_campaign_harness_overlay(&input(&fixture, &solo, &pairs)).expect("solo replay");
        assert_eq!(candidate.changes.len(), 1);
        assert_eq!(candidate.admitted_delta_ids.len(), 1);
        let _ = index;
    }
}

// WORK_UNIT_CASE: 618/12
#[test]
fn case_12_same_surface_different_value_conflict() {
    let fixture = fixture();
    let (first, first_inverse) = operation_replace(&fixture.targets[1]);
    let other_after = ValueState {
        present: true,
        digest: Some(digest("replace-divergent")),
    };
    let divergent = ChangeOperation::Replace {
        target: fixture.targets[1].clone(),
        surface: ChangeSurface::SearchProbeStopping,
        before: ValueState {
            present: true,
            digest: Some(digest("replace-before")),
        },
        after: other_after.clone(),
    };
    let divergent_inverse = InverseChange {
        forward_target: fixture.targets[1].clone(),
        inverse: ChangeOperation::Replace {
            target: fixture.targets[1].clone(),
            surface: ChangeSurface::SearchProbeStopping,
            before: other_after,
            after: ValueState {
                present: true,
                digest: Some(digest("replace-before")),
            },
        },
    };
    let deltas = vec![
        delta(&fixture.view, "conflict-a", first, first_inverse),
        delta(&fixture.view, "conflict-b", divergent, divergent_inverse),
    ];
    let pairs = admitted(&deltas);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &deltas, &pairs)),
        Err(OverlayError::Conflict {
            field: "change.target"
        })
    ));
}

// WORK_UNIT_CASE: 618/13
#[test]
fn case_13_canonical_set_like_commutative_merge_boundary() {
    let fixture = fixture();
    let (first_operation, first_inverse) = operation_add(&fixture.targets[0], "merged-value");
    let (second_operation, second_inverse) = operation_add(&fixture.targets[0], "merged-value");
    let equivalents = vec![
        delta(&fixture.view, "merge-a", first_operation, first_inverse),
        delta(&fixture.view, "merge-b", second_operation, second_inverse),
    ];
    let pairs = admitted(&equivalents);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &equivalents, &pairs)),
        Err(OverlayError::Conflict {
            field: "change.target"
        })
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "set-value");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let forward = vec![
        delta(&fixture.view, "set-a", add, add_inverse),
        delta(&fixture.view, "set-b", replace, replace_inverse),
    ];
    let forward_pairs = admitted(&forward);
    let forward_candidate =
        compose_campaign_harness_overlay(&input(&fixture, &forward, &forward_pairs))
            .expect("forward candidate");
    let (add, add_inverse) = operation_add(&fixture.targets[0], "set-value");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let backward = vec![
        delta(&fixture.view, "set-b", replace, replace_inverse),
        delta(&fixture.view, "set-a", add, add_inverse),
    ];
    let backward_pairs = admitted(&backward);
    let backward_candidate =
        compose_campaign_harness_overlay(&input(&fixture, &backward, &backward_pairs))
            .expect("backward candidate");
    assert_eq!(forward_candidate.changes, backward_candidate.changes);
    assert_eq!(
        forward_candidate.application_order,
        backward_candidate.application_order
    );
    assert_eq!(
        forward_candidate.canonical_digest,
        backward_candidate.canonical_digest
    );
}

// WORK_UNIT_CASE: 618/14
#[test]
fn case_14_no_input_order_confidence_or_source_count_winner() {
    let fixture = fixture();
    let rich_add = mutated_delta(
        &fixture.view,
        "rich",
        operation_add(&fixture.targets[0], "rich-value").0,
        operation_add(&fixture.targets[0], "rich-value").1,
        |next| {
            next.evidence.push(aid("rich-extra-a"));
            next.evidence.push(aid("rich-extra-b"));
            next.evidence.push(aid("rich-extra-c"));
        },
    );
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let plain_replace = delta(&fixture.view, "plain", replace, replace_inverse);
    let (remove, remove_inverse) = operation_remove(&fixture.targets[2]);
    let plain_remove = delta(&fixture.view, "other", remove, remove_inverse);
    let baseline = vec![
        rich_add.clone(),
        plain_replace.clone(),
        plain_remove.clone(),
    ];
    let baseline_pairs = admitted(&baseline);
    let baseline_candidate =
        compose_campaign_harness_overlay(&input(&fixture, &baseline, &baseline_pairs))
            .expect("baseline candidate");
    assert_eq!(baseline_candidate.changes.len(), 3);
    let permutations = [
        [0, 1, 2],
        [0, 2, 1],
        [1, 0, 2],
        [1, 2, 0],
        [2, 0, 1],
        [2, 1, 0],
    ];
    for permutation in permutations {
        let reordered = vec![
            baseline[permutation[0]].clone(),
            baseline[permutation[1]].clone(),
            baseline[permutation[2]].clone(),
        ];
        let pairs = admitted(&reordered);
        let candidate = compose_campaign_harness_overlay(&input(&fixture, &reordered, &pairs))
            .expect("permuted candidate");
        assert_eq!(candidate.changes, baseline_candidate.changes);
        assert_eq!(
            candidate.application_order,
            baseline_candidate.application_order
        );
        assert_eq!(
            candidate.canonical_digest,
            baseline_candidate.canonical_digest
        );
    }
}

// WORK_UNIT_CASE: 618/15
#[test]
fn case_15_exact_precedence_and_preserved_shadowed_alternatives() {
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "precedence");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let (remove, remove_inverse) = operation_remove(&fixture.targets[2]);
    let reversed = vec![
        delta(&fixture.view, "precedence-c", remove, remove_inverse),
        delta(&fixture.view, "precedence-b", replace, replace_inverse),
        delta(&fixture.view, "precedence-a", add, add_inverse),
    ];
    let pairs = admitted(&reversed);
    let candidate =
        compose_campaign_harness_overlay(&input(&fixture, &reversed, &pairs)).expect("candidate");
    let mut sorted = candidate.application_order.clone();
    sorted.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(candidate.application_order, sorted);
    let (first, first_inverse) = operation_replace(&fixture.targets[1]);
    let alternative_after = ValueState {
        present: true,
        digest: Some(digest("shadowed-alternative")),
    };
    let alternative = ChangeOperation::Replace {
        target: fixture.targets[1].clone(),
        surface: ChangeSurface::SearchProbeStopping,
        before: ValueState {
            present: true,
            digest: Some(digest("replace-before")),
        },
        after: alternative_after.clone(),
    };
    let alternative_inverse = InverseChange {
        forward_target: fixture.targets[1].clone(),
        inverse: ChangeOperation::Replace {
            target: fixture.targets[1].clone(),
            surface: ChangeSurface::SearchProbeStopping,
            before: alternative_after,
            after: ValueState {
                present: true,
                digest: Some(digest("replace-before")),
            },
        },
    };
    let rivals = vec![
        delta(&fixture.view, "rival-a", first, first_inverse),
        delta(&fixture.view, "rival-b", alternative, alternative_inverse),
    ];
    let pairs = admitted(&rivals);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &rivals, &pairs)),
        Err(OverlayError::Conflict {
            field: "change.target"
        })
    ));
    for rival in &rivals {
        let solo = vec![rival.clone()];
        let pairs = admitted(&solo);
        let candidate = compose_campaign_harness_overlay(&input(&fixture, &solo, &pairs))
            .expect("shadowed alternative stays composable");
        assert_eq!(candidate.changes.len(), 1);
    }
}

// WORK_UNIT_CASE: 618/16
#[test]
fn case_16_objective_acceptance_change_rejected() {
    let fixture = fixture();
    let protected_surfaces = [
        ChangeSurface::TaskLocalContext,
        ChangeSurface::Memory,
        ChangeSurface::Skill,
        ChangeSurface::Tool,
        ChangeSurface::Route,
        ChangeSurface::Hypothesis,
        ChangeSurface::Strategy,
        ChangeSurface::Abstraction,
        ChangeSurface::CandidateParent,
    ];
    for surface in protected_surfaces {
        let (operation, inverse) = add_with_surface(&fixture.targets[0], surface, "widening");
        let widening = delta(&fixture.view, "widening", operation, inverse);
        let pairs = admitted(std::slice::from_ref(&widening));
        assert!(
            matches!(
                compose_campaign_harness_overlay(&input(&fixture, &[widening], &pairs)),
                Err(OverlayError::Unsupported {
                    field: "change.surface"
                })
            ),
            "surface {surface:?} must stay outside the overlay composer"
        );
    }
}

// WORK_UNIT_CASE: 618/17
#[test]
fn case_17_evaluator_holdout_verifier_change_rejected() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "no-receipt");
    let unreceipted = mutated_delta(&fixture.view, "no-receipt", add, add_inverse, |next| {
        next.evaluator_receipts.clear();
    });
    let pairs = admitted(std::slice::from_ref(&unreceipted));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[unreceipted], &pairs)),
        Err(OverlayError::Contract(Contract::MissingOwnerEvidence {
            field: "delta.evaluator_receipts"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "no-evidence");
    let unevidenced = mutated_delta(&fixture.view, "no-evidence", add, add_inverse, |next| {
        next.evidence.clear();
    });
    let pairs = admitted(std::slice::from_ref(&unevidenced));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[unevidenced], &pairs)),
        Err(OverlayError::Contract(Contract::Missing {
            field: "delta.evidence"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "escalated");
    let escalated = mutated_delta(&fixture.view, "escalated", add, add_inverse, |next| {
        next.proof_ceiling = ProofCeiling::ObservedExternalEffect;
    });
    let pairs = admitted(std::slice::from_ref(&escalated));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[escalated], &pairs)),
        Err(OverlayError::Contract(Contract::CandidateCeiling))
    ));
}

// WORK_UNIT_CASE: 618/18
#[test]
fn case_18_authority_privacy_secret_widening_rejected() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "task-widen");
    let widened_task = mutated_delta(&fixture.view, "task-widen", add, add_inverse, |next| {
        next.binding.task_id = TaskId::new("task-other").expect("task");
    });
    let pairs = admitted(std::slice::from_ref(&widened_task));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[widened_task], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.binding"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "product-widen");
    let widened_product = mutated_delta(&fixture.view, "product-widen", add, add_inverse, |next| {
        next.binding.product_id = ProductId::new("product-other").expect("product");
    });
    let pairs = admitted(std::slice::from_ref(&widened_product));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[widened_product], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.binding"
        }))
    ));
    let mut recipe = fixture.recipe.clone();
    recipe.privacy_class = String::new();
    recipe.seal().expect("recipe reseal");
    let mut view = fixture.view.clone();
    view.recipe_digest = recipe.canonical_digest.clone();
    view.seal().expect("view reseal");
    let (add, add_inverse) = operation_add(&fixture.targets[0], "privacy");
    let private = delta(&view, "privacy", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&private));
    let exposed = Fixture {
        recipe,
        view,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&exposed, &[private], &pairs)),
        Err(OverlayError::Contract(Contract::Missing {
            field: "recipe.privacy_class"
        }))
    ));
}

// WORK_UNIT_CASE: 618/19
#[test]
fn case_19_cost_spend_scope_generation_widening_rejected() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "scope-widen");
    let widened_scope = mutated_delta(&fixture.view, "scope-widen", add, add_inverse, |next| {
        next.binding.scope =
            eliot_learning_contracts::WorkScopeId::new("scope-wider").expect("scope");
    });
    let pairs = admitted(std::slice::from_ref(&widened_scope));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[widened_scope], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.binding"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "operation-widen");
    let widened_operation =
        mutated_delta(&fixture.view, "operation-widen", add, add_inverse, |next| {
            next.binding.operation_id = OperationId::new("operation-other").expect("operation");
        });
    let pairs = admitted(std::slice::from_ref(&widened_operation));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[widened_operation], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.binding"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "generation-widen");
    let widened_generation = mutated_delta(
        &fixture.view,
        "generation-widen",
        add,
        add_inverse,
        |next| {
            next.binding.state_fence.resource_generation =
                ResourceGeneration::new(2).expect("generation");
        },
    );
    let pairs = admitted(std::slice::from_ref(&widened_generation));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[widened_generation], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.binding"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "epoch-widen");
    let widened_epoch = mutated_delta(&fixture.view, "epoch-widen", add, add_inverse, |next| {
        next.binding.state_fence.authority_epoch = EpochId::new(
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("valid test lineage"),
            std::num::NonZeroU64::new(2).expect("nonzero test sequence"),
        )
        .expect("valid test epoch");
    });
    let pairs = admitted(std::slice::from_ref(&widened_epoch));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[widened_epoch], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.binding"
        }))
    ));
}

// WORK_UNIT_CASE: 618/20
#[test]
fn case_20_direct_and_indirect_protected_field_change() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "direct");
    let direct = vec![delta(&fixture.view, "direct", add, add_inverse)];
    let pairs = admitted(&direct);
    let owned = input(&fixture, &direct, &pairs);
    let direct_change = OverlayComposeInput {
        protected_surface_proposed_digest: "1111111111111111111111111111111111111111111111111111111111111111",
        ..owned
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&direct_change),
        Err(OverlayError::ProtectedSurfaceChanged)
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "indirect-scope");
    let indirect_scope = mutated_delta(&fixture.view, "indirect-scope", add, add_inverse, |next| {
        next.binding.scope =
            eliot_learning_contracts::WorkScopeId::new("scope-escape").expect("scope");
    });
    let pairs = admitted(std::slice::from_ref(&indirect_scope));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[indirect_scope], &pairs)),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "delta.binding"
        }))
    ));
    let (operation, inverse) =
        add_with_surface(&fixture.targets[0], ChangeSurface::Tool, "indirect-tool");
    let indirect_tool = delta(&fixture.view, "indirect-tool", operation, inverse);
    let pairs = admitted(std::slice::from_ref(&indirect_tool));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[indirect_tool], &pairs)),
        Err(OverlayError::Unsupported {
            field: "change.surface"
        })
    ));
}

// WORK_UNIT_CASE: 618/21
#[test]
fn case_21_valid_dependency_dag_and_deterministic_topological_order() {
    let fixture = fixture();
    let (_, candidate) = full_candidate(&fixture);
    candidate.validate().expect("contract-valid candidate");
    assert!(candidate.dependencies.is_empty());
    let mut sorted = candidate.application_order.clone();
    sorted.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(candidate.application_order, sorted);
    let change_targets: Vec<&TargetId> = candidate
        .changes
        .iter()
        .map(|change| &change.target)
        .collect();
    assert_eq!(candidate.application_order.len(), change_targets.len());
    for target in &candidate.application_order {
        assert!(change_targets.contains(&target));
    }
    let again = full_candidate(&fixture).1;
    assert_eq!(candidate.application_order, again.application_order);
    assert_eq!(candidate.canonical_digest, again.canonical_digest);
}

// WORK_UNIT_CASE: 618/22
#[test]
fn case_22_missing_wrong_revision_cycle_partial_dependency_closure() {
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "missing-node");
    let missing = mutated_delta(&fixture.view, "missing-node", add, add_inverse, |next| {
        next.dependencies.push(aid("missing-dependency"));
    });
    let pairs = admitted(std::slice::from_ref(&missing));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[missing], &pairs)),
        Err(OverlayError::Unsupported {
            field: "delta.dependencies"
        })
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "self-cycle");
    let cyclic = mutated_delta(&fixture.view, "self-cycle", add, add_inverse, |next| {
        next.dependencies.push(aid("delta-self-cycle"));
    });
    let pairs = admitted(std::slice::from_ref(&cyclic));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[cyclic], &pairs)),
        Err(OverlayError::Unsupported {
            field: "delta.dependencies"
        })
    ));
    let (first_add, first_inverse) = operation_add(&fixture.targets[0], "edge-a");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let mut edge_pair = vec![
        delta(&fixture.view, "edge-a", first_add, first_inverse),
        delta(&fixture.view, "edge-b", replace, replace_inverse),
    ];
    edge_pair[1].dependencies.push(aid("delta-edge-a"));
    edge_pair[1].seal().expect("delta reseal");
    let pairs = admitted(&edge_pair);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &edge_pair, &pairs)),
        Err(OverlayError::Unsupported {
            field: "delta.dependencies"
        })
    ));
    let partial = resealed_view(&fixture.view, |view| {
        view.completeness = Completeness::Partial;
    });
    let (add, add_inverse) = operation_add(&fixture.targets[0], "partial");
    let partial_delta = delta(&partial, "partial", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&partial_delta));
    let partial_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: partial,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&partial_fixture, &[partial_delta], &pairs)),
        Err(OverlayError::Unsupported {
            field: "view.completeness"
        })
    ));
}

// WORK_UNIT_CASE: 618/23
#[test]
fn case_23_disjoint_changes_commute_under_semantic_digest() {
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "commute");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let forward = vec![
        delta(&fixture.view, "commute-a", add, add_inverse),
        delta(&fixture.view, "commute-b", replace, replace_inverse),
    ];
    let forward_pairs = admitted(&forward);
    let forward_candidate =
        compose_campaign_harness_overlay(&input(&fixture, &forward, &forward_pairs))
            .expect("forward candidate");
    let (add, add_inverse) = operation_add(&fixture.targets[0], "commute");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let backward = vec![
        delta(&fixture.view, "commute-b", replace, replace_inverse),
        delta(&fixture.view, "commute-a", add, add_inverse),
    ];
    let backward_pairs = admitted(&backward);
    let backward_candidate =
        compose_campaign_harness_overlay(&input(&fixture, &backward, &backward_pairs))
            .expect("backward candidate");
    assert_eq!(forward_candidate.changes, backward_candidate.changes);
    assert_eq!(
        forward_candidate.application_order,
        backward_candidate.application_order
    );
    assert_eq!(
        forward_candidate.canonical_digest,
        backward_candidate.canonical_digest
    );
}

// WORK_UNIT_CASE: 618/24
#[test]
fn case_24_exact_base_overlay_origin_for_every_effective_value() {
    let fixture = fixture();
    let (_, candidate) = full_candidate(&fixture);
    for change in &candidate.changes {
        assert_eq!(
            change.origin,
            eliot_learning_contracts::OverlayOrigin::Overlay
        );
        assert_ne!(change.base, change.proposed);
    }
    let restored =
        eliot_learning_overlay::remove_overlay(&candidate, &fixture.view, &fixture.recipe)
            .expect("removable candidate");
    assert_eq!(restored, expected_base_map(&fixture));
    let proposed = eliot_learning_overlay::overlay_proposed_states(&candidate);
    let base = eliot_learning_overlay::overlay_base_states(&candidate);
    assert_eq!(proposed.len(), 3);
    assert_eq!(base, expected_base_map(&fixture));
    assert_ne!(proposed, base);
}

// WORK_UNIT_CASE: 618/25
#[test]
fn case_25_base_input_remains_byte_and_semantically_immutable() {
    let fixture = fixture();
    let (deltas, _) = full_candidate(&fixture);
    let view_before = fixture.view.clone();
    let recipe_before = fixture.recipe.clone();
    let deltas_before = deltas.clone();
    let pairs = admitted(&deltas);
    let candidate =
        compose_campaign_harness_overlay(&input(&fixture, &deltas, &pairs)).expect("candidate");
    assert_eq!(fixture.view, view_before);
    assert_eq!(fixture.recipe, recipe_before);
    assert_eq!(deltas, deltas_before);
    assert_eq!(candidate.base_view_digest, view_before.canonical_digest);
    let (first, first_inverse) = operation_replace(&fixture.targets[1]);
    let (second, second_inverse) = operation_replace(&fixture.targets[1]);
    let rivals = vec![
        delta(&fixture.view, "immutable-a", first, first_inverse),
        delta(&fixture.view, "immutable-b", second, second_inverse),
    ];
    let pairs = admitted(&rivals);
    let _ = compose_campaign_harness_overlay(&input(&fixture, &rivals, &pairs));
    assert_eq!(fixture.view, view_before);
    assert_eq!(fixture.recipe, recipe_before);
}

// WORK_UNIT_CASE: 618/26
#[test]
fn case_26_no_active_current_canonical_state_in_output() {
    let fixture = fixture();
    let (_, candidate) = full_candidate(&fixture);
    assert!(!candidate.invalidated);
    assert_eq!(
        candidate.binding.proof_ceiling,
        ProofCeiling::CandidateArtifact
    );
    assert_eq!(candidate.expires_at_ms, 2_000);
    assert_eq!(
        candidate.fixed_before_observation_discriminator,
        fixture.discriminator
    );
    for change in &candidate.changes {
        let forward = forward_of(change).expect("forward operation");
        assert!(change.inverse.is_exact_inverse_of(&forward));
    }
    assert!(candidate.is_reversible());
}

// WORK_UNIT_CASE: 618/27
#[test]
fn case_27_exact_discriminator_fixed_before_observation() {
    let fixture = fixture();
    let deltas = vec![add_delta_for(
        &fixture,
        "discriminated",
        "discriminated-value",
    )];
    let pairs = admitted(&deltas);
    let candidate =
        compose_campaign_harness_overlay(&input(&fixture, &deltas, &pairs)).expect("candidate");
    assert_eq!(
        candidate.fixed_before_observation_discriminator,
        fixture.discriminator
    );
    for delta in &deltas {
        assert_ne!(
            candidate.fixed_before_observation_discriminator,
            delta.pre_observation_discriminator
        );
    }
    let owned = input(&fixture, &deltas, &pairs);
    let later_observation = OverlayComposeInput {
        observed_at_ms: 1_500,
        ..owned
    };
    let later = compose_campaign_harness_overlay(&later_observation).expect("later observation");
    assert_eq!(later.canonical_digest, candidate.canonical_digest);
    assert_eq!(
        later.fixed_before_observation_discriminator,
        fixture.discriminator
    );
}

// WORK_UNIT_CASE: 618/28
#[test]
fn case_28_post_hoc_proxy_self_reported_discriminator_rejected() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "post-hoc");
    let deltas = vec![delta(&fixture.view, "post-hoc", add, add_inverse)];
    let pairs = admitted(&deltas);
    let owned = input(&fixture, &deltas, &pairs);
    let post_hoc = OverlayComposeInput {
        observed_at_ms: 2_000,
        ..owned
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&post_hoc),
        Err(OverlayError::Expired)
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "proxy");
    let proxy = mutated_delta(&fixture.view, "proxy", add, add_inverse, |next| {
        next.evidence.clear();
    });
    let pairs = admitted(std::slice::from_ref(&proxy));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[proxy], &pairs)),
        Err(OverlayError::Contract(Contract::Missing {
            field: "delta.evidence"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "self-reported");
    let self_reported = mutated_delta(&fixture.view, "self-reported", add, add_inverse, |next| {
        next.evaluator_receipts.clear();
    });
    let pairs = admitted(std::slice::from_ref(&self_reported));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[self_reported], &pairs)),
        Err(OverlayError::Contract(Contract::MissingOwnerEvidence {
            field: "delta.evaluator_receipts"
        }))
    ));
}

// WORK_UNIT_CASE: 618/29
#[test]
fn case_29_mandatory_task_local_scope_expiry_and_cancellation() {
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "expiring");
    let deltas = vec![delta(&fixture.view, "expiring", add, add_inverse)];
    let pairs = admitted(&deltas);
    let owned = input(&fixture, &deltas, &pairs);
    let zero_expiry = OverlayComposeInput {
        expires_at_ms: 0,
        observed_at_ms: 0,
        ..owned
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&zero_expiry),
        Err(OverlayError::Expired)
    ));
    let owned = input(&fixture, &deltas, &pairs);
    let boundary = OverlayComposeInput {
        observed_at_ms: 2_000,
        ..owned
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&boundary),
        Err(OverlayError::Expired)
    ));
    let cancelled = resealed_view(&fixture.view, |view| {
        view.invalidated = true;
        view.invalidation_reason = Some("cancelled-by-owner".to_owned());
    });
    let (add, add_inverse) = operation_add(&fixture.targets[0], "cancelled");
    let cancelled_delta = delta(&cancelled, "cancelled", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&cancelled_delta));
    let cancelled_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: cancelled,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    let cancelled_result =
        compose_campaign_harness_overlay(&input(&cancelled_fixture, &[cancelled_delta], &pairs));
    assert!(cancelled_result.is_err());
    let live = compose_single_add(&fixture, "live", "live-value");
    assert!(!live.invalidated);
    assert_eq!(live.expires_at_ms, 2_000);
}

// WORK_UNIT_CASE: 618/30
#[test]
fn case_30_inverse_for_every_operation_kind() {
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "kind-add");
    let add_only = vec![delta(&fixture.view, "kind-add", add, add_inverse)];
    let pairs = admitted(&add_only);
    let added = compose_campaign_harness_overlay(&input(&fixture, &add_only, &pairs)).expect("add");
    assert!(added.is_reversible());
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let replace_only = vec![delta(
        &fixture.view,
        "kind-replace",
        replace,
        replace_inverse,
    )];
    let pairs = admitted(&replace_only);
    let replaced =
        compose_campaign_harness_overlay(&input(&fixture, &replace_only, &pairs)).expect("replace");
    assert!(replaced.is_reversible());
    let (remove, remove_inverse) = operation_remove(&fixture.targets[2]);
    let remove_only = vec![delta(&fixture.view, "kind-remove", remove, remove_inverse)];
    let pairs = admitted(&remove_only);
    let removed =
        compose_campaign_harness_overlay(&input(&fixture, &remove_only, &pairs)).expect("remove");
    assert!(removed.is_reversible());
    for candidate in [&added, &replaced, &removed] {
        for change in &candidate.changes {
            let forward = forward_of(change).expect("forward operation");
            assert!(change.inverse.is_exact_inverse_of(&forward));
        }
        let inverses = eliot_learning_overlay::overlay_inverse_operations(candidate)
            .expect("inverse operations");
        assert_eq!(inverses.len(), candidate.changes.len());
    }
}

// WORK_UNIT_CASE: 618/31
#[test]
fn case_31_exact_round_trip_remove_compose_equals_base() {
    let fixture = fixture();
    let (_, candidate) = full_candidate(&fixture);
    let restored =
        eliot_learning_overlay::remove_overlay(&candidate, &fixture.view, &fixture.recipe)
            .expect("exact round trip");
    assert_eq!(restored, expected_base_map(&fixture));
    let inverses =
        eliot_learning_overlay::overlay_inverse_operations(&candidate).expect("inverse operations");
    assert_eq!(inverses.len(), candidate.changes.len());
    let reversed: Vec<&TargetId> = candidate.application_order.iter().rev().collect();
    assert_eq!(reversed.len(), inverses.len());
    for (inverse, target) in inverses.iter().zip(reversed) {
        assert_eq!(inverse.target(), target);
    }
}

// WORK_UNIT_CASE: 618/32
#[test]
fn case_32_wrong_base_rollback_and_irreversible_change_rejected() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (_, candidate) = full_candidate(&fixture);
    let evolved = resealed_view(&fixture.view, |view| {
        view.required_references.push(aid("rollback-reference"));
    });
    assert!(matches!(
        eliot_learning_overlay::remove_overlay(&candidate, &evolved, &fixture.recipe),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "overlay.view_lineage"
        }))
    ));
    let mut broken_inverse = candidate.clone();
    broken_inverse.changes[0].inverse.inverse = operation_remove(&fixture.targets[1]).0;
    broken_inverse.seal().expect("candidate reseal");
    assert!(matches!(
        eliot_learning_overlay::remove_overlay(&broken_inverse, &fixture.view, &fixture.recipe),
        Err(OverlayError::Contract(_))
    ));
    let mut lost_history = candidate.clone();
    let tampered = lost_history
        .changes
        .iter_mut()
        .find(|change| change.target == fixture.targets[1])
        .expect("replace change");
    tampered.base.digest = Some(digest("tampered-before"));
    assert!(matches!(
        tampered.inverse.inverse,
        ChangeOperation::Replace { .. }
    ));
    if let ChangeOperation::Replace { after, .. } = &mut tampered.inverse.inverse {
        *after = tampered.base.clone();
    }
    lost_history.seal().expect("candidate reseal");
    assert!(matches!(
        eliot_learning_overlay::remove_overlay(&lost_history, &fixture.view, &fixture.recipe),
        Err(OverlayError::Contract(Contract::ScopeMismatch {
            field: "change.before"
        }))
    ));
}

// WORK_UNIT_CASE: 618/33
#[test]
fn case_33_conflict_or_rejected_delta_needs_no_destructive_rollback() {
    let fixture = fixture();
    let (first, first_inverse) = operation_replace(&fixture.targets[1]);
    let rival_after = ValueState {
        present: true,
        digest: Some(digest("rival-after")),
    };
    let rival = ChangeOperation::Replace {
        target: fixture.targets[1].clone(),
        surface: ChangeSurface::SearchProbeStopping,
        before: ValueState {
            present: true,
            digest: Some(digest("replace-before")),
        },
        after: rival_after.clone(),
    };
    let rival_inverse = InverseChange {
        forward_target: fixture.targets[1].clone(),
        inverse: ChangeOperation::Replace {
            target: fixture.targets[1].clone(),
            surface: ChangeSurface::SearchProbeStopping,
            before: rival_after,
            after: ValueState {
                present: true,
                digest: Some(digest("replace-before")),
            },
        },
    };
    let rivals = vec![
        delta(&fixture.view, "rival-a", first, first_inverse),
        delta(&fixture.view, "rival-b", rival, rival_inverse),
    ];
    let pairs = admitted(&rivals);
    let view_before = fixture.view.clone();
    let rivals_before = rivals.clone();
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &rivals, &pairs)),
        Err(OverlayError::Conflict {
            field: "change.target"
        })
    ));
    assert_eq!(fixture.view, view_before);
    assert_eq!(rivals, rivals_before);
    for rival in &rivals {
        let solo = vec![rival.clone()];
        let pairs = admitted(&solo);
        let candidate = compose_campaign_harness_overlay(&input(&fixture, &solo, &pairs))
            .expect("rejected delta leaves no destructive residue");
        assert_eq!(candidate.changes.len(), 1);
    }
}

// WORK_UNIT_CASE: 618/34
#[test]
fn case_34_complete_and_partial_delta_surface_dependency_denominators() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (_, complete) = full_candidate(&fixture);
    assert_eq!(complete.changes.len(), 3);
    let partial = resealed_view(&fixture.view, |view| {
        view.completeness = Completeness::Partial;
    });
    let (add, add_inverse) = operation_add(&fixture.targets[0], "partial-denominator");
    let partial_delta = delta(&partial, "partial-denominator", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&partial_delta));
    let partial_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: partial,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&partial_fixture, &[partial_delta], &pairs)),
        Err(OverlayError::Unsupported {
            field: "view.completeness"
        })
    ));
    let miscounted = resealed_view(&fixture.view, |view| {
        view.denominator.observed = 1;
    });
    let (add, add_inverse) = operation_add(&fixture.targets[0], "miscounted");
    let miscounted_delta = delta(&miscounted, "miscounted", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&miscounted_delta));
    let miscounted_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: miscounted,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&miscounted_fixture, &[miscounted_delta], &pairs,)),
        Err(OverlayError::Contract(Contract::IncompleteCoverage))
    ));
    let omitted = resealed_view(&fixture.view, |view| {
        let removed = view.slots.remove(0);
        view.omissions.push(removed.slot_id);
        view.denominator.observed = 2;
    });
    let (add, add_inverse) = operation_add(&fixture.targets[0], "omitted");
    let omitted_delta = delta(&omitted, "omitted", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&omitted_delta));
    let omitted_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: omitted,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&omitted_fixture, &[omitted_delta], &pairs)),
        Err(OverlayError::Unsupported {
            field: "view.completeness"
        })
    ));
}

// WORK_UNIT_CASE: 618/35
#[test]
fn case_35_every_independent_item_output_work_bound_and_frontier() {
    let fixture = fixture();
    let empty: Vec<AttemptLearningDeltaCandidate> = vec![];
    let pairs = admitted(&empty);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &empty, &pairs)),
        Err(OverlayError::Bound { field: "deltas" })
    ));
    let mut crowded = Vec::new();
    for index in 0..129 {
        let (operation, inverse) = operation_add(&fixture.targets[0], "crowded");
        crowded.push(delta(
            &fixture.view,
            &format!("many-{index}"),
            operation,
            inverse,
        ));
    }
    let pairs = admitted(&crowded);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &crowded, &pairs)),
        Err(OverlayError::Bound { field: "deltas" })
    ));
    let (operation, _) = operation_add(&fixture.targets[0], "oversized");
    let mut oversized = AttemptLearningDeltaCandidate {
        binding: fixture.view.binding.clone(),
        attempt_id: eliot_learning_contracts::AgentAttemptId::new("attempt-oversized")
            .expect("attempt"),
        delta_id: aid("delta-oversized"),
        target: fixture.view.target.clone(),
        base_view_digest: fixture.view.canonical_digest.clone(),
        pre_observation_discriminator: aid("prior-discriminator-oversized"),
        intended_strategy: aid("intended-oversized"),
        attempted_strategy: aid("attempted-oversized"),
        changes: vec![operation; 129],
        inverses: vec![operation_add(&fixture.targets[0], "oversized").1; 129],
        evidence: vec![aid("evidence-oversized")],
        evaluator_receipts: vec![aid("evaluator-oversized")],
        baseline: vec![],
        control: vec![],
        confounders: vec![],
        dependencies: vec![],
        equivalent_retry: None,
        proof_ceiling: ProofCeiling::CandidateArtifact,
        canonical_digest: String::new(),
    };
    oversized.inverses = oversized
        .changes
        .iter()
        .map(|change| {
            let (expected, expected_inverse) = operation_add(&fixture.targets[0], "oversized");
            assert_eq!(change, &expected);
            expected_inverse
        })
        .collect();
    oversized.seal().expect("delta seal");
    let pairs = admitted(std::slice::from_ref(&oversized));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[oversized], &pairs)),
        Err(OverlayError::Bound {
            field: "deltas.changes"
        })
    ));
    let verbose = resealed_view(&fixture.view, |view| {
        view.invalidation_reason = Some("x".repeat(8193));
    });
    let (add, add_inverse) = operation_add(&fixture.targets[0], "verbose");
    let verbose_delta = delta(&verbose, "verbose", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&verbose_delta));
    let verbose_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: verbose,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&verbose_fixture, &[verbose_delta], &pairs)),
        Err(OverlayError::Bound {
            field: "view.invalidation_reason"
        })
    ));
    let unexplored = resealed_view(&fixture.view, |view| {
        let removed = view.slots.remove(0);
        view.frontier.push(removed.slot_id);
        view.denominator.observed = 2;
    });
    let (add, add_inverse) = operation_add(&fixture.targets[0], "unexplored");
    let unexplored_delta = delta(&unexplored, "unexplored", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&unexplored_delta));
    let unexplored_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: unexplored,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&unexplored_fixture, &[unexplored_delta], &pairs,)),
        Err(OverlayError::Unsupported {
            field: "view.completeness"
        })
    ));
}

// WORK_UNIT_CASE: 618/36
#[test]
fn case_36_exact_replay_and_changed_same_id_request_policy_conflict() {
    let fixture = fixture();
    let first = compose_single_add(&fixture, "replayable", "replayable-value");
    let second = compose_single_add(&fixture, "replayable", "replayable-value");
    assert_eq!(first, second);
    assert_eq!(first.canonical_digest, second.canonical_digest);
    let variant_a = compose_single_add(&fixture, "same-id", "value-a");
    let variant_b = compose_single_add(&fixture, "same-id", "value-b");
    assert_eq!(variant_a.overlay_id, variant_b.overlay_id);
    assert_ne!(variant_a.canonical_digest, variant_b.canonical_digest);
    assert_ne!(variant_a.changes, variant_b.changes);
    let deltas = vec![add_delta_for(&fixture, "same-id", "value-a")];
    let mut tampered = admitted(&deltas);
    tampered[0].canonical_digest = digest("different-digest");
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &deltas, &tampered)),
        Err(OverlayError::Conflict {
            field: "admitted.digest"
        })
    ));
}

// WORK_UNIT_CASE: 618/37
#[test]
fn case_37_randomized_set_like_delta_order_yields_identical_overlay() {
    fn shuffled<T: Clone>(items: &[T], seed: u64) -> Vec<T> {
        let mut order = items.to_vec();
        let mut state = seed | 1;
        for index in (1..order.len()).rev() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let modulus = u64::try_from(index + 1).expect("shuffle modulus");
            let other = usize::try_from(state % modulus).expect("shuffle index");
            order.swap(index, other);
        }
        order
    }
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "shuffled");
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let (remove, remove_inverse) = operation_remove(&fixture.targets[2]);
    let baseline = vec![
        delta(&fixture.view, "shuffled-a", add, add_inverse),
        delta(&fixture.view, "shuffled-b", replace, replace_inverse),
        delta(&fixture.view, "shuffled-c", remove, remove_inverse),
    ];
    let baseline_pairs = admitted(&baseline);
    let baseline_candidate =
        compose_campaign_harness_overlay(&input(&fixture, &baseline, &baseline_pairs))
            .expect("baseline candidate");
    for seed in [7_u64, 42, 1_000_003] {
        let reordered = shuffled(&baseline, seed);
        let mut reordered_ids: Vec<&str> = reordered
            .iter()
            .map(|delta| delta.delta_id.as_str())
            .collect();
        let mut baseline_ids: Vec<&str> = baseline
            .iter()
            .map(|delta| delta.delta_id.as_str())
            .collect();
        reordered_ids.sort_unstable();
        baseline_ids.sort_unstable();
        assert_eq!(reordered_ids, baseline_ids);
        let pairs = admitted(&reordered);
        let candidate = compose_campaign_harness_overlay(&input(&fixture, &reordered, &pairs))
            .expect("shuffled candidate");
        assert_eq!(candidate.changes, baseline_candidate.changes);
        assert_eq!(
            candidate.application_order,
            baseline_candidate.application_order
        );
        assert_eq!(
            candidate.canonical_digest,
            baseline_candidate.canonical_digest
        );
    }
}

// WORK_UNIT_CASE: 618/38
#[test]
fn case_38_bounded_malformed_property_input_never_panics() {
    use eliot_learning_contracts::LearningContractError as Contract;
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "malformed");
    let single = vec![delta(&fixture.view, "malformed", add, add_inverse)];
    let mut duplicated = admitted(&single);
    duplicated.push(duplicated[0].clone());
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &single, &duplicated)),
        Err(OverlayError::Conflict { field: "admitted" })
    ));
    let (first_operation, first_inverse) = operation_add(&fixture.targets[0], "dup-value");
    let (second_operation, second_inverse) = operation_add(&fixture.targets[1], "dup-other");
    let cloned_id = vec![
        delta(&fixture.view, "dup", first_operation, first_inverse),
        mutated_delta(
            &fixture.view,
            "dup",
            second_operation,
            second_inverse,
            |_| {},
        ),
    ];
    let pairs = admitted(&cloned_id);
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &cloned_id, &pairs)),
        Err(OverlayError::Conflict {
            field: "admitted.delta_id"
        })
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "opaque");
    let opaque = vec![delta(&fixture.view, "opaque", add, add_inverse)];
    let mut opaque_pairs = admitted(&opaque);
    opaque_pairs[0].canonical_digest = "not-a-digest".to_owned();
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &opaque, &opaque_pairs)),
        Err(OverlayError::Contract(Contract::InvalidDigest {
            field: "admitted.digest"
        }))
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "empty");
    let hollow = mutated_delta(&fixture.view, "empty", add, add_inverse, |next| {
        next.changes.clear();
        next.inverses.clear();
    });
    let pairs = admitted(std::slice::from_ref(&hollow));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[hollow], &pairs)),
        Err(OverlayError::Bound {
            field: "delta.changes"
        })
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "broken-inverse");
    let broken = mutated_delta(&fixture.view, "broken-inverse", add, add_inverse, |next| {
        next.inverses[0].inverse = operation_add(&fixture.targets[1], "elsewhere").0;
    });
    let pairs = admitted(std::slice::from_ref(&broken));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[broken], &pairs)),
        Err(OverlayError::Contract(_))
    ));
    let (operation, inverse) = add_with_surface(
        &TargetId::new("target-unknown").expect("target"),
        ChangeSurface::VerificationOrder,
        "unknown",
    );
    let unknown = delta(&fixture.view, "unknown", operation, inverse);
    let pairs = admitted(std::slice::from_ref(&unknown));
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &[unknown], &pairs)),
        Err(OverlayError::Unsupported {
            field: "change.target"
        })
    ));
    let (add, add_inverse) = operation_add(&fixture.targets[0], "digest-tamper");
    let tampered = vec![delta(&fixture.view, "digest-tamper", add, add_inverse)];
    let mut tampered_pairs = admitted(&tampered);
    tampered_pairs[0].canonical_digest = digest("tampered-digest");
    assert!(matches!(
        compose_campaign_harness_overlay(&input(&fixture, &tampered, &tampered_pairs)),
        Err(OverlayError::Conflict {
            field: "admitted.digest"
        })
    ));
    let (_, candidate) = full_candidate(&fixture);
    let mut forged = candidate.clone();
    forged.canonical_digest = digest("forged-candidate");
    assert!(matches!(
        eliot_learning_overlay::remove_overlay(&forged, &fixture.view, &fixture.recipe),
        Err(OverlayError::Contract(_))
    ));
}

// WORK_UNIT_CASE: 618/39
#[test]
fn case_39_exact_base_identity_and_complete_contributing_delta_lineage() {
    // Reconciliation with case 13: the composer permits no multi-delta merge
    // into one effective value (same-target divergence is always `Conflict`
    // because A-32 coverage validation is bijective), so every effective value
    // keeps exactly one contributing delta here. The complete admitted
    // contributor set is retained on the candidate-level admitted ids/digests;
    // no false single-contributor identity is asserted for a merge because no
    // merge is representable in-scope.
    let fixture = fixture();
    let (deltas, candidate) = full_candidate(&fixture);
    for change in &candidate.changes {
        let contributors = deltas
            .iter()
            .filter(|delta| {
                delta
                    .changes
                    .iter()
                    .any(|operation| forward_of(change).as_ref() == Some(operation))
            })
            .count();
        assert_eq!(contributors, 1);
    }
    let replace = candidate
        .changes
        .iter()
        .find(|change| change.target == fixture.targets[1])
        .expect("replace change");
    assert_eq!(replace.base.digest, Some(digest("replace-before")));
    assert_eq!(
        replace.base.digest,
        fixture.view.slots[1].members[0].value_digest
    );
    assert_eq!(candidate.admitted_delta_ids.len(), deltas.len());
    for (id, expected_digest) in candidate
        .admitted_delta_ids
        .iter()
        .zip(candidate.admitted_delta_digests.iter())
    {
        let contributor = deltas
            .iter()
            .find(|delta| delta.delta_id == *id)
            .expect("admitted contributor");
        assert_eq!(&contributor.canonical_digest, expected_digest);
    }
}

// WORK_UNIT_CASE: 618/40
#[test]
fn case_40_protected_fields_unchanged_in_every_valid_output() {
    let fixture = fixture();
    let (add, add_inverse) = operation_add(&fixture.targets[0], "guarded-add");
    let add_only = vec![delta(&fixture.view, "guarded-add", add, add_inverse)];
    let (replace, replace_inverse) = operation_replace(&fixture.targets[1]);
    let replace_only = vec![delta(
        &fixture.view,
        "guarded-replace",
        replace,
        replace_inverse,
    )];
    let (remove, remove_inverse) = operation_remove(&fixture.targets[2]);
    let remove_only = vec![delta(
        &fixture.view,
        "guarded-remove",
        remove,
        remove_inverse,
    )];
    for deltas in [&add_only, &replace_only, &remove_only] {
        let pairs = admitted(deltas);
        let candidate =
            compose_campaign_harness_overlay(&input(&fixture, deltas, &pairs)).expect("candidate");
        assert_eq!(
            candidate.protected_surface_base_digest,
            candidate.protected_surface_proposed_digest
        );
        assert_eq!(candidate.binding, fixture.view.binding);
        assert_eq!(
            candidate.binding.proof_ceiling,
            ProofCeiling::CandidateArtifact
        );
        assert!(!candidate.invalidated);
    }
}

// WORK_UNIT_CASE: 618/41
#[test]
fn case_41_successful_composition_exactly_reversible_to_base_digest() {
    let fixture = fixture();
    let (_, candidate) = full_candidate(&fixture);
    candidate.validate().expect("contract-valid candidate");
    assert_eq!(candidate.base_view_digest, fixture.view.canonical_digest);
    assert!(candidate.is_reversible());
    let restored =
        eliot_learning_overlay::remove_overlay(&candidate, &fixture.view, &fixture.recipe)
            .expect("reversible to base");
    assert_eq!(restored, expected_base_map(&fixture));
    assert_eq!(restored.len(), candidate.changes.len());
}

// WORK_UNIT_CASE: 618/42
#[test]
fn case_42_conflicting_noncommutative_deltas_yield_no_complete_value() {
    let fixture = fixture();
    let (first, first_inverse) = operation_replace(&fixture.targets[1]);
    let rival_after = ValueState {
        present: true,
        digest: Some(digest("noncommutative-after")),
    };
    let rival = ChangeOperation::Replace {
        target: fixture.targets[1].clone(),
        surface: ChangeSurface::SearchProbeStopping,
        before: ValueState {
            present: true,
            digest: Some(digest("replace-before")),
        },
        after: rival_after.clone(),
    };
    let rival_inverse = InverseChange {
        forward_target: fixture.targets[1].clone(),
        inverse: ChangeOperation::Replace {
            target: fixture.targets[1].clone(),
            surface: ChangeSurface::SearchProbeStopping,
            before: rival_after,
            after: ValueState {
                present: true,
                digest: Some(digest("replace-before")),
            },
        },
    };
    let rivals = vec![
        delta(&fixture.view, "noncommutative-a", first, first_inverse),
        delta(&fixture.view, "noncommutative-b", rival, rival_inverse),
    ];
    let pairs = admitted(&rivals);
    let result = compose_campaign_harness_overlay(&input(&fixture, &rivals, &pairs));
    assert!(matches!(
        result,
        Err(OverlayError::Conflict {
            field: "change.target"
        })
    ));
    assert!(result.is_err());
}

// WORK_UNIT_CASE: 618/43
#[test]
fn case_43_changed_base_fence_admission_discriminator_invalidates_digest() {
    let fixture = fixture();
    let baseline = compose_single_add(&fixture, "pinned", "pinned-value");
    let evolved = resealed_view(&fixture.view, |view| {
        view.required_references.push(aid("rotated-reference"));
    });
    let (add, add_inverse) = operation_add(&fixture.targets[0], "pinned-value");
    let evolved_delta = delta(&evolved, "pinned", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&evolved_delta));
    let evolved_fixture = Fixture {
        recipe: fixture.recipe.clone(),
        view: evolved,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    let evolved_candidate =
        compose_campaign_harness_overlay(&input(&evolved_fixture, &[evolved_delta], &pairs))
            .expect("evolved candidate");
    assert_ne!(
        evolved_candidate.canonical_digest,
        baseline.canonical_digest
    );
    let mut recipe = fixture.recipe.clone();
    recipe.binding.scope =
        eliot_learning_contracts::WorkScopeId::new("scope-rotated").expect("scope");
    recipe.seal().expect("recipe reseal");
    let mut view = fixture.view.clone();
    view.binding.scope =
        eliot_learning_contracts::WorkScopeId::new("scope-rotated").expect("scope");
    view.recipe_digest = recipe.canonical_digest.clone();
    view.seal().expect("view reseal");
    let (add, add_inverse) = operation_add(&fixture.targets[0], "pinned-value");
    let rotated_delta = delta(&view, "pinned", add, add_inverse);
    let pairs = admitted(std::slice::from_ref(&rotated_delta));
    let rotated = Fixture {
        recipe,
        view,
        targets: fixture.targets.clone(),
        discriminator: fixture.discriminator.clone(),
    };
    let rotated_candidate =
        compose_campaign_harness_overlay(&input(&rotated, &[rotated_delta], &pairs))
            .expect("rotated candidate");
    assert_ne!(
        rotated_candidate.canonical_digest,
        baseline.canonical_digest
    );
    let renamed = compose_single_add(&fixture, "pinned-b", "pinned-value");
    assert_ne!(renamed.canonical_digest, baseline.canonical_digest);
    let other_discriminator = aid("next-discriminator-b");
    let deltas = vec![add_delta_for(&fixture, "pinned", "pinned-value")];
    let pairs = admitted(&deltas);
    let owned = input(&fixture, &deltas, &pairs);
    let varied = OverlayComposeInput {
        fixed_before_observation_discriminator: &other_discriminator,
        ..owned
    };
    let varied_candidate = compose_campaign_harness_overlay(&varied).expect("varied discriminator");
    assert_ne!(varied_candidate.canonical_digest, baseline.canonical_digest);
}

// WORK_UNIT_CASE: 618/44
#[test]
fn case_44_no_a33_a34_a36_implementation_dependency() {
    const MANIFEST: &str = include_str!("../Cargo.toml");
    const SOURCES: [&str; 6] = [
        include_str!("../src/lib.rs"),
        include_str!("../src/compose.rs"),
        include_str!("../src/base.rs"),
        include_str!("../src/bounds.rs"),
        include_str!("../src/changes.rs"),
        include_str!("../src/remove.rs"),
    ];
    for forbidden in [
        "eliot-learning-delta",
        "eliot-learning-state-view",
        "eliot-reactive-context-plan",
    ] {
        assert!(
            !MANIFEST.contains(forbidden),
            "forbidden implementation dependency {forbidden}"
        );
    }
    assert!(
        MANIFEST.contains("eliot-learning-contracts"),
        "additive A-32 contract reuse only"
    );
    for forbidden in [
        "eliot_learning_delta",
        "eliot_learning_state_view",
        "eliot_reactive_context_plan",
    ] {
        for source in SOURCES {
            assert!(
                !source.contains(forbidden),
                "forbidden implementation import {forbidden}"
            );
        }
    }
    let fixture = fixture();
    compose_single_add(&fixture, "contracts-only", "contracts-only-value");
}

// WORK_UNIT_CASE: 618/45
#[test]
fn case_45_no_store_runtime_model_provider_activation_delivery_promotion_finish_path() {
    const SOURCES: [&str; 6] = [
        include_str!("../src/lib.rs"),
        include_str!("../src/compose.rs"),
        include_str!("../src/base.rs"),
        include_str!("../src/bounds.rs"),
        include_str!("../src/changes.rs"),
        include_str!("../src/remove.rs"),
    ];
    fn dependency_names() -> Vec<&'static str> {
        const MANIFEST: &str = include_str!("../Cargo.toml");
        let mut in_section = false;
        let mut names = Vec::new();
        for line in MANIFEST.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('[') {
                in_section = trimmed == "[dependencies]" || trimmed == "[dev-dependencies]";
                continue;
            }
            if in_section && !trimmed.is_empty() && !trimmed.starts_with('#') {
                names.push(trimmed.split(['=', ' ']).next().unwrap_or("").trim());
            }
        }
        names
    }
    let mut names = dependency_names();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "eliot-agent-contracts",
            "eliot-contracts",
            "eliot-evidence",
            "eliot-learning-contracts",
            "thiserror",
        ]
    );
    for name in &names {
        for forbidden in [
            "store", "runtime", "provider", "model", "deliver", "promot", "activat", "finish",
        ] {
            assert!(
                !name.contains(forbidden),
                "forbidden dependency path in {name}"
            );
        }
    }
    for forbidden in [
        "use eliot_store",
        "eliot_store::",
        "use eliot_runtime",
        "eliot_runtime::",
        "provider_sdk",
        "ModelClient",
        "struct Store",
        "struct Runtime",
    ] {
        for source in SOURCES {
            assert!(
                !source.contains(forbidden),
                "forbidden runtime path {forbidden}"
            );
        }
    }
    let fixture = fixture();
    let (_, candidate) = full_candidate(&fixture);
    assert_eq!(
        candidate.binding.proof_ceiling,
        ProofCeiling::CandidateArtifact
    );
    assert!(!candidate.invalidated);
    assert!(candidate.dependencies.is_empty());
    for change in &candidate.changes {
        let forward = forward_of(change).expect("forward operation");
        assert!(change.inverse.is_exact_inverse_of(&forward));
    }
}
