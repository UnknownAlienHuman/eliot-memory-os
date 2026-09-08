#![allow(clippy::expect_used)]

use eliot_agent_contracts::TargetId;
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, OperationId, PolicyRevision, ProductId, RequestId,
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
    let mut fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
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
