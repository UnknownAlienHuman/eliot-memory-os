use std::error::Error;

use eliot_context::{
    AdmissionDisposition, ContextAtom, ContextError, ContextInput, ContextRecipe, ContextRole,
    RoleBudget,
};
use eliot_contracts::{ArtifactId, AuthorityEpoch, ResourceGeneration, StateFence, TaskRevision};
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceFreshness};
use eliot_understanding::{UnderstandingError, UnderstandingRequest, UnderstandingSynthesizer};

type TestResult = Result<(), Box<dyn Error>>;

fn revision(value: u64) -> Result<TaskRevision, Box<dyn Error>> {
    Ok(TaskRevision::new(value)?)
}

fn fence(task_revision: TaskRevision) -> StateFence {
    let mut fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    fence.task_revision = Some(task_revision);
    fence
}

fn request(
    task_revision: TaskRevision,
    recipe_revision: TaskRevision,
    maximum_cost: u32,
) -> Result<UnderstandingRequest, Box<dyn Error>> {
    let atom_id = ArtifactId::new("atom:goal")?;
    Ok(UnderstandingRequest {
        input: ContextInput {
            scope: "scope:test".to_owned(),
            task_id: None,
            task_revision,
            state_fence: fence(task_revision),
            atoms: vec![ContextAtom {
                atom_id: atom_id.clone(),
                role: ContextRole::Goal,
                payload: "goal payload".to_owned(),
                source_handles: vec![ArtifactId::new("source:goal")?],
                status: EpistemicStatus::Observed,
                assertability: Assertability::NonAssertableUnverified,
                freshness: EvidenceFreshness::ExactCommit,
                state_fence: fence(task_revision),
                required: true,
                protected: true,
                cost: 1,
                expected_decision_delta: 10,
                risk: 1,
                cues: vec!["cue:goal".to_owned()],
            }],
            unknowns: Vec::new(),
        },
        recipe: ContextRecipe {
            recipe_revision,
            total_cost: 10,
            role_budgets: vec![RoleBudget {
                role: ContextRole::Goal,
                maximum_cost,
            }],
            required_roles: vec![ContextRole::Goal],
        },
        packet_label: "understanding:test".to_owned(),
    })
}

#[test]
fn matching_revision_keeps_synthesis_sections_and_manifest() -> TestResult {
    let task_revision = revision(1)?;
    let request = request(task_revision, task_revision, 10)?;
    let view = UnderstandingSynthesizer::synthesize(&request)?;

    assert_eq!(view.compiled.revision, task_revision);
    assert_eq!(view.sections.len(), 1);
    assert_eq!(view.sections[0].role, ContextRole::Goal);
    assert_eq!(view.manifest.included_atoms.len(), 1);
    assert!(view.manifest.handle_only_atoms.is_empty());
    Ok(())
}

#[test]
fn recipe_revision_mismatch_remains_a_context_error_for_consumers() -> TestResult {
    let task_revision = revision(2)?;
    let recipe_revision = revision(1)?;
    let request = request(task_revision, recipe_revision, 10)?;

    assert_eq!(
        UnderstandingSynthesizer::synthesize(&request),
        Err(UnderstandingError::Context(
            ContextError::RecipeRevisionMismatch {
                recipe_revision,
                task_revision,
            }
        ))
    );
    Ok(())
}

#[test]
fn required_zero_budget_remains_handle_only_through_synthesis() -> TestResult {
    let task_revision = revision(1)?;
    let request = request(task_revision, task_revision, 0)?;
    let view = UnderstandingSynthesizer::synthesize(&request)?;

    assert!(view.compiled.units.is_empty());
    assert_eq!(view.compiled.handle_only.len(), 1);
    assert_eq!(
        view.compiled.admissions[0].disposition,
        AdmissionDisposition::HandleOnly
    );
    assert!(view.sections.is_empty());
    assert_eq!(view.manifest.handle_only_atoms.len(), 1);
    assert!(view.manifest.included_atoms.is_empty());
    Ok(())
}
