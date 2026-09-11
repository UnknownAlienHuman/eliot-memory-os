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
use eliot_learning_state_view::{
    MAX_EVIDENCE, MAX_LABEL_BYTES, MAX_RECORD_EVIDENCE, compile_campaign_learning_state_view,
};

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
    let lineage = source(&format!("slot-{slot_index}"), 1)?;
    projection_with_lineage(recipe, slot_index, disposition, &lineage)
}

fn projection_with_lineage(
    recipe: &LearningStateViewRecipe,
    slot_index: usize,
    disposition: SlotDisposition,
    lineage: &eliot_learning_contracts::identity::SourceLineage,
) -> Result<SlotProjection, Box<dyn Error>> {
    let spec = &recipe.slots[slot_index];
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
                evidence: vec![
                    artifact(&format!("evidence-{slot_index}-{index}-a"))?,
                    artifact(&format!("evidence-{slot_index}-{index}-b"))?,
                ],
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok(SlotProjection {
        slot_id: spec.slot_id.clone(),
        disposition,
        members,
        evidence: vec![
            artifact(&format!("slot-evidence-{slot_index}-a"))?,
            artifact(&format!("slot-evidence-{slot_index}-b"))?,
        ],
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
    let refs = vec![artifact("ref-z")?, artifact("ref-a")?];
    let view_id = artifact("view-explicit")?;
    let view = compile_campaign_learning_state_view(
        &recipe,
        std::slice::from_ref(&first),
        &recipe.binding.state_fence,
        &refs,
        &view_id,
        &[],
    )?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_eq!(view.view_id, view_id);
    assert_eq!(view.binding.state_fence, recipe.binding.state_fence);
    assert_eq!(
        view.required_references,
        vec![artifact("ref-a")?, artifact("ref-z")?]
    );
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
    let shared = source("shared", 1)?;
    let second = projection_with_lineage(&recipe, 1, SlotDisposition::Current, &shared)?;
    let first = projection_with_lineage(&recipe, 0, SlotDisposition::Current, &shared)?;
    let before = recipe.canonical_digest.clone();
    let view = compile(
        &recipe,
        &[first.clone(), second.clone()],
        &[artifact("ref-a")?],
    )?;
    let mut expected_first = first.clone();
    let mut expected_second = second.clone();
    for expected in [&mut expected_first, &mut expected_second] {
        expected
            .evidence
            .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        for member in &mut expected.members {
            member
                .evidence
                .sort_by(|left, right| left.as_str().cmp(right.as_str()));
        }
    }
    assert_eq!(view.slots[0], expected_first);
    assert_eq!(view.slots[1], expected_second);
    let mut reverse_first = first;
    reverse_first.members.reverse();
    reverse_first.evidence.reverse();
    for member in &mut reverse_first.members {
        member.evidence.reverse();
    }
    let mut reverse_second = second;
    reverse_second.members.reverse();
    reverse_second.evidence.reverse();
    for member in &mut reverse_second.members {
        member.evidence.reverse();
    }
    let reversed = compile(
        &recipe,
        &[reverse_second, reverse_first],
        &[artifact("ref-a")?],
    )?;
    assert_eq!(recipe.canonical_digest, before);
    assert_eq!(view, reversed);
    assert_eq!(view.slots[0].slot_id, recipe.slots[0].slot_id);
    assert_eq!(view.slots[1].slot_id, recipe.slots[1].slot_id);
    Ok(())
}

#[test]
fn duplicate_slot_and_changed_shared_lineage_fail_closed() -> TestResult {
    let base_recipe = recipe(
        vec![SlotRequirement::Required],
        vec![2],
        OmissionPolicy::RequiredSlots,
    )?;
    let first = projection(&base_recipe, 0, SlotDisposition::Current)?;
    let duplicate = first.clone();
    assert!(matches!(
        compile(&base_recipe, &[first, duplicate], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    let first = projection(&base_recipe, 0, SlotDisposition::Current)?;
    assert!(matches!(
        compile(
            &base_recipe,
            std::slice::from_ref(&first),
            &[artifact("ref")?, artifact("ref")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));
    let mut changed = projection(&base_recipe, 0, SlotDisposition::Current)?;
    changed.members[1].source.revision = TaskRevision::new(2)?;
    assert!(matches!(
        compile(&base_recipe, &[changed], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::ScopeMismatch { .. })
    ));
    let mut duplicate_member = projection(&base_recipe, 0, SlotDisposition::Current)?;
    let repeated_member = duplicate_member.members[0].clone();
    duplicate_member.members.push(repeated_member);
    assert!(matches!(
        compile(&base_recipe, &[duplicate_member], &[artifact("ref")?]),
        Err(eliot_learning_contracts::LearningContractError::Duplicate { .. })
    ));

    let mut oversized_dependency = recipe(
        vec![SlotRequirement::Required],
        vec![1],
        OmissionPolicy::RequiredSlots,
    )?;
    oversized_dependency.slots[0].requirement = SlotRequirement::Conditional {
        depends_on: SlotId::from_artifact(artifact(&"d".repeat(MAX_LABEL_BYTES + 1))?),
    };
    let oversized_projection = projection(&oversized_dependency, 0, SlotDisposition::Current)?;
    assert!(matches!(
        compile(
            &oversized_dependency,
            &[oversized_projection],
            &[artifact("ref")?]
        ),
        Err(eliot_learning_contracts::LearningContractError::Bound {
            field: "slot.depends_on"
        })
    ));

    let mut oversized_disagreements = Vec::new();
    for record in 0..=(MAX_EVIDENCE / MAX_RECORD_EVIDENCE) {
        let mut evidence = Vec::new();
        for item in 0..MAX_RECORD_EVIDENCE {
            evidence.push(artifact(&format!("disagreement-{record}-{item}"))?);
        }
        oversized_disagreements.push(OwnerDisagreement {
            slot_id: base_recipe.slots[0].slot_id.clone(),
            owners: vec![base_recipe.slots[0].owner.clone()],
            evidence,
        });
    }
    assert!(matches!(
        compile_campaign_learning_state_view(
            &base_recipe,
            &[],
            &base_recipe.binding.state_fence,
            &[artifact("ref")?],
            &artifact("view-614")?,
            &oversized_disagreements,
        ),
        Err(eliot_learning_contracts::LearningContractError::Bound {
            field: "owner_disagreement.evidence"
        })
    ));
    let mut inconsistent = projection(&base_recipe, 0, SlotDisposition::Current)?;
    inconsistent.members[0].disposition = SlotDisposition::Stale;
    assert!(matches!(
        compile(&base_recipe, &[inconsistent], &[artifact("ref")?]),
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
    assert_eq!(
        view.frontier,
        frontier
            .slots
            .iter()
            .map(|slot| slot.slot_id.clone())
            .collect::<Vec<_>>()
    );
    assert_eq!(view.completeness, Completeness::Partial);
    view.validate_against(&frontier)?;
    Ok(())
}

#[test]
fn optional_stale_and_explicit_disagreement_are_preserved() -> TestResult {
    let base_recipe = recipe(
        vec![SlotRequirement::Required, SlotRequirement::Optional],
        vec![1, 1],
        OmissionPolicy::RequiredSlots,
    )?;
    let required = projection(&base_recipe, 0, SlotDisposition::Current)?;
    let optional = projection(&base_recipe, 1, SlotDisposition::Stale)?;
    let disagreement = OwnerDisagreement {
        slot_id: base_recipe.slots[1].slot_id.clone(),
        owners: vec![
            OwnerId::from_artifact(artifact("owner-b")?),
            OwnerId::from_artifact(artifact("owner-a")?),
        ],
        evidence: vec![artifact("disagreement-z")?, artifact("disagreement-a")?],
    };
    let view = compile_campaign_learning_state_view(
        &base_recipe,
        &[optional.clone(), required],
        &base_recipe.binding.state_fence,
        &[artifact("ref")?],
        &artifact("view-614")?,
        std::slice::from_ref(&disagreement),
    )?;
    assert_eq!(view.completeness, Completeness::CompleteForDeclaredRecipe);
    assert_eq!(view.slots[1], optional);
    let mut expected_disagreement = disagreement;
    expected_disagreement
        .owners
        .sort_by(|left, right| left.as_str().cmp(right.as_str()));
    expected_disagreement
        .evidence
        .sort_by(|left, right| left.as_str().cmp(right.as_str()));
    assert_eq!(view.owner_disagreements, vec![expected_disagreement]);

    let conditional = recipe(
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
    let required = projection(&conditional, 0, SlotDisposition::Current)?;
    let blocked_optional = projection(&conditional, 1, SlotDisposition::Blocked)?;
    let dependent = compile(
        &conditional,
        &[required, blocked_optional.clone()],
        &[artifact("ref")?],
    )?;
    assert_eq!(dependent.completeness, Completeness::Blocked);
    assert_eq!(dependent.slots[1], blocked_optional);
    assert_eq!(
        dependent.frontier,
        vec![conditional.slots[2].slot_id.clone()]
    );
    dependent.validate_against(&conditional)?;
    Ok(())
}

#[test]
fn required_status_precedence_survives_missing_frontier() -> TestResult {
    let recipe = recipe(
        vec![
            SlotRequirement::Required,
            SlotRequirement::Required,
            SlotRequirement::Required,
        ],
        vec![1, 1, 1],
        OmissionPolicy::ExplicitFrontier,
    )?;
    let blocked = projection(&recipe, 0, SlotDisposition::Blocked)?;
    let stale = projection(&recipe, 1, SlotDisposition::Stale)?;
    let view = compile(&recipe, &[blocked, stale], &[artifact("ref")?])?;
    assert_eq!(view.completeness, Completeness::Blocked);
    assert_eq!(view.frontier, vec![recipe.slots[2].slot_id.clone()]);
    assert_eq!(view.slots[0].disposition, SlotDisposition::Blocked);
    assert_eq!(view.slots[1].disposition, SlotDisposition::Stale);
    Ok(())
}
