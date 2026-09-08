#![allow(clippy::expect_used)]

use std::error::Error;

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, OperationId, PolicyRevision, ProductId, RequestId,
    ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, sha256_hex,
};
use eliot_evidence::EvidenceFreshness;
use eliot_learning_contracts::{
    CampaignLearningStateView, Completeness, ContractBinding, LearningStateViewRecipe,
    MemberProjection, OmissionPolicy, OwnerDisagreement, OwnerId, SlotDisposition, SlotId,
    SlotProjection, SlotRequirement, SlotSpec, TargetId,
};
use eliot_learning_contracts::{ProofCeiling, WorkScopeId};
use eliot_learning_state_view::compile_campaign_learning_state_view;

type TestResult = Result<(), Box<dyn Error>>;

fn digest(value: &str) -> String {
    sha256_hex(value.as_bytes())
}

fn artifact(value: &str) -> Result<ArtifactId, Box<dyn Error>> {
    Ok(ArtifactId::new(value)?)
}

fn source(
    tag: &str,
    revision: u64,
) -> Result<eliot_learning_contracts::identity::SourceLineage, Box<dyn Error>> {
    Ok(eliot_learning_contracts::identity::SourceLineage {
        owner: SourceId::new(format!("source-{tag}"))?,
        snapshot: artifact(&format!("snapshot-{tag}"))?,
        revision: TaskRevision::new(revision)?,
        digest: digest(&format!("source-{tag}-{revision}")),
    })
}

fn binding() -> Result<ContractBinding, Box<dyn Error>> {
    Ok(ContractBinding {
        schema_version: 1,
        policy_revision: PolicyRevision::genesis(),
        request_id: RequestId::new("request-614")?,
        operation_id: OperationId::new("operation-614")?,
        product_id: ProductId::new("product-614")?,
        task_id: TaskId::new("task-614")?,
        scope: WorkScopeId::new("scope-614")?,
        state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
        source: source("binding", 1)?,
        proof_ceiling: ProofCeiling::CandidateArtifact,
    })
}

fn recipe(
    requirements: Vec<SlotRequirement>,
    member_counts: Vec<usize>,
    omission_policy: OmissionPolicy,
) -> Result<LearningStateViewRecipe, Box<dyn Error>> {
    let target = TargetId::new("target-614")?;
    let binding = binding()?;
    let mut slots = Vec::new();
    for (index, (requirement, member_count)) in
        requirements.into_iter().zip(member_counts).enumerate()
    {
        let slot_id = SlotId::from_artifact(artifact(&format!("slot-{index}"))?);
        let owner = OwnerId::from_artifact(artifact(&format!("owner-{index}"))?);
        let members = (0..member_count)
            .map(|member| {
                artifact(&format!("member-{index}-{member}"))
                    .map(eliot_learning_contracts::MemberId::from_artifact)
            })
            .collect::<Result<Vec<_>, _>>()?;
        slots.push(SlotSpec {
            slot_id,
            owner,
            target: target.clone(),
            requirement,
            declared_members: members,
            accepted_type: "projection/v1".to_owned(),
            schema_digest: digest("projection-schema"),
        });
    }
    let mut value = LearningStateViewRecipe {
        recipe_id: artifact("recipe-614")?,
        campaign_id: eliot_learning_contracts::CampaignId::from_artifact(artifact("campaign-614")?),
        target,
        binding,
        slots,
        freshness: EvidenceFreshness::ExactCandidate,
        privacy_class: "task-local".to_owned(),
        omission_policy,
        canonical_digest: String::new(),
    };
    value.seal()?;
    Ok(value)
}

fn projection(
    recipe: &LearningStateViewRecipe,
    slot_index: usize,
    disposition: SlotDisposition,
) -> Result<SlotProjection, Box<dyn Error>> {
    let spec = &recipe.slots[slot_index];
    let lineage = source(&format!("slot-{slot_index}"), 1)?;
    let members = spec
        .declared_members
        .iter()
        .enumerate()
        .map(|(index, member_id)| {
            Ok(MemberProjection {
                member_id: member_id.clone(),
                owner: spec.owner.clone(),
                source: lineage.clone(),
                projection_revision: TaskRevision::new(1)?,
                disposition: if disposition == SlotDisposition::Current {
                    SlotDisposition::Current
                } else {
                    disposition
                },
                value_digest: Some(digest(&format!("value-{slot_index}-{index}"))),
                evidence: vec![artifact(&format!("evidence-{slot_index}-{index}"))?],
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok(SlotProjection {
        slot_id: spec.slot_id.clone(),
        disposition,
        members,
        evidence: vec![artifact(&format!("slot-evidence-{slot_index}"))?],
    })
}

fn compile(
    recipe: &LearningStateViewRecipe,
    projections: &[SlotProjection],
    refs: &[ArtifactId],
) -> Result<CampaignLearningStateView, eliot_learning_contracts::LearningContractError> {
    compile_campaign_learning_state_view(
        recipe,
        projections,
        &recipe.binding.state_fence,
        refs,
        &artifact("view-614").expect("view"),
        &[],
    )
}

#[test]
fn complete_reconstruction_preserves_recipe_member_order_and_canonical_digest() -> TestResult {
    let recipe = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    let first = projection(&recipe, 0, SlotDisposition::Current)?;
    let view = compile(
        &recipe,
        std::slice::from_ref(&first),
        &[artifact("ref-z")?, artifact("ref-a")?],
    )?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_eq!(
        view.slots[0].members[0].member_id,
        recipe.slots[0].declared_members[0]
    );
    assert_eq!(view.required_references[0], artifact("ref-a")?);
    assert!(!view.canonical_digest.is_empty());
    view.validate_against(&recipe)?;
    assert_eq!(view.slots[0], first);
    Ok(())
}

#[test]
fn shared_lineage_and_input_order_are_retained_without_resealing_recipe() -> TestResult {
    let recipe = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Required],
        vec![2, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let second = projection(&recipe, 1, SlotDisposition::Current)?;
    let first = projection(&recipe, 0, SlotDisposition::Current)?;
    let before = recipe.canonical_digest.clone();
    let view = compile(&recipe, &[second, first], &[artifact("ref-a")?])?;
    assert_eq!(recipe.canonical_digest, before);
    assert_eq!(view.slots[0].slot_id, recipe.slots[0].slot_id);
    assert_eq!(view.slots[1].slot_id, recipe.slots[1].slot_id);
    Ok(())
}

#[test]
fn duplicate_slot_and_changed_shared_lineage_fail_closed() -> TestResult {
    let recipe = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    let first = projection(&recipe, 0, SlotDisposition::Current)?;
    let duplicate = first.clone();
    assert!(matches!(
        compile(&recipe, &[first, duplicate], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    let first = projection(&recipe, 0, SlotDisposition::Current)?;
    assert!(matches!(
        compile(
            &recipe,
            std::slice::from_ref(&first),
            &[artifact("ref")?, artifact("ref")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    let mut changed = projection(&recipe, 0, SlotDisposition::Current)?;
    changed.members[1].source.revision = TaskRevision::new(2)?;
    assert!(matches!(
        compile(&recipe, &[changed], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    let mut inconsistent = projection(&recipe, 0, SlotDisposition::Current)?;
    inconsistent.members[0].disposition = SlotDisposition::Stale;
    assert!(matches!(
        compile(&recipe, &[inconsistent], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    Ok(())
}

#[test]
fn omission_policy_and_conditional_unknown_remain_explicit() -> TestResult {
    let required = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Optional],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    assert!(matches!(
        compile(&required, &[], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::IncompleteCoverage)
    ));
    let frontier = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Optional,
            SlotRequirement::Conditional {
                depends_on: SlotId::from_artifact(artifact("slot-1")?),
            },
        ],
        vec![1, 1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let view = compile(&frontier, &[], &[artifact("ref")?])?;
    assert_eq!(view.frontier.len(), 3);
    assert_eq!(view.completeness, Completeness::Partial);
    Ok(())
}

#[test]
fn optional_stale_and_explicit_disagreement_are_preserved() -> TestResult {
    let recipe = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Optional],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let required = projection(&recipe, 0, SlotDisposition::Current)?;
    let optional = projection(&recipe, 1, SlotDisposition::Stale)?;
    let disagreement = OwnerDisagreement {
        slot_id: recipe.slots[1].slot_id.clone(),
        owners: vec![
            OwnerId::from_artifact(artifact("owner-b")?),
            OwnerId::from_artifact(artifact("owner-a")?),
        ],
        evidence: vec![artifact("disagreement-z")?, artifact("disagreement-a")?],
    };
    let view = compile_campaign_learning_state_view(
        &recipe,
        &[optional.clone(), required],
        &recipe.binding.state_fence,
        &[artifact("ref")?],
        &artifact("view-614")?,
        std::slice::from_ref(&disagreement),
    )?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_eq!(view.slots[1], optional);
    assert_eq!(view.owner_disagreements, vec![disagreement]);
    Ok(())
}

#[test]
fn required_status_precedence_survives_missing_frontier() -> TestResult {
    let recipe = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Required],
        vec![1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let blocked = projection(&recipe, 0, SlotDisposition::Blocked)?;
    let view = compile(&recipe, &[blocked], &[artifact("ref")?])?;
    assert_eq!(view.completeness, Completeness::Blocked);
    assert_eq!(view.frontier, vec![recipe.slots[1].slot_id.clone()]);
    assert_eq!(view.slots[0].disposition, SlotDisposition::Blocked);
    Ok(())
}
