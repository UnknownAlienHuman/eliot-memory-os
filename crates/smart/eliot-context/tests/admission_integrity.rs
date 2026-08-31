use std::error::Error;

use eliot_context::{
    AdmissionDisposition, ContextAtom, ContextCompiler, ContextError, ContextInput, ContextRecipe,
    ContextRole, RoleBudget,
};
use eliot_contracts::{ArtifactId, AuthorityEpoch, ResourceGeneration, StateFence, TaskRevision};
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceFreshness};

type TestResult = Result<(), Box<dyn Error>>;

fn revision(value: u64) -> Result<TaskRevision, Box<dyn Error>> {
    Ok(TaskRevision::new(value)?)
}

fn fence(task_revision: TaskRevision) -> StateFence {
    let mut fence = StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis());
    fence.task_revision = Some(task_revision);
    fence
}

fn atom(
    atom_id: &str,
    role: ContextRole,
    task_revision: TaskRevision,
) -> Result<ContextAtom, Box<dyn Error>> {
    Ok(ContextAtom {
        atom_id: ArtifactId::new(atom_id)?,
        role,
        payload: format!("payload for {atom_id}"),
        source_handles: vec![ArtifactId::new(format!("source:{atom_id}"))?],
        status: EpistemicStatus::Observed,
        assertability: Assertability::NonAssertableUnverified,
        freshness: EvidenceFreshness::ExactCommit,
        state_fence: fence(task_revision),
        required: true,
        protected: true,
        cost: 1,
        expected_decision_delta: 10,
        risk: 1,
        cues: vec![format!("cue:{atom_id}")],
    })
}

fn input(task_revision: TaskRevision) -> Result<ContextInput, Box<dyn Error>> {
    Ok(ContextInput {
        scope: "scope:test".to_owned(),
        task_id: None,
        task_revision,
        state_fence: fence(task_revision),
        atoms: vec![atom("atom:goal", ContextRole::Goal, task_revision)?],
        unknowns: Vec::new(),
    })
}

fn recipe(task_revision: TaskRevision, maximum_cost: u32) -> ContextRecipe {
    ContextRecipe {
        recipe_revision: task_revision,
        total_cost: 10,
        role_budgets: vec![RoleBudget {
            role: ContextRole::Goal,
            maximum_cost,
        }],
        required_roles: vec![ContextRole::Goal],
    }
}

#[test]
fn recipe_must_match_the_exact_task_revision() -> TestResult {
    let task_revision = revision(2)?;
    let recipe_revision = revision(1)?;
    let input = input(task_revision)?;
    let recipe = recipe(recipe_revision, 10);

    assert_eq!(
        ContextCompiler::compile(&input, &recipe),
        Err(ContextError::RecipeRevisionMismatch {
            recipe_revision,
            task_revision,
        })
    );
    Ok(())
}

#[test]
fn duplicate_atom_identity_is_rejected_before_admission() -> TestResult {
    let task_revision = revision(1)?;
    let mut input = input(task_revision)?;
    input.atoms.push(input.atoms[0].clone());

    assert_eq!(
        input.validate(),
        Err(ContextError::DuplicateIdentity {
            field: "input.atoms.atom_id",
        })
    );
    Ok(())
}

#[test]
fn duplicate_role_budget_is_rejected() -> TestResult {
    let task_revision = revision(1)?;
    let mut recipe = recipe(task_revision, 10);
    recipe.role_budgets.push(RoleBudget {
        role: ContextRole::Goal,
        maximum_cost: 1,
    });

    assert_eq!(
        recipe.validate(),
        Err(ContextError::DuplicateIdentity {
            field: "recipe.role_budgets.role",
        })
    );
    Ok(())
}

#[test]
fn duplicate_required_role_is_rejected() -> TestResult {
    let task_revision = revision(1)?;
    let mut recipe = recipe(task_revision, 10);
    recipe.required_roles.push(ContextRole::Goal);

    assert_eq!(
        recipe.validate(),
        Err(ContextError::DuplicateIdentity {
            field: "recipe.required_roles",
        })
    );
    Ok(())
}

#[test]
fn missing_required_role_budget_is_rejected() -> TestResult {
    let task_revision = revision(1)?;
    let mut recipe = recipe(task_revision, 10);
    recipe.role_budgets.clear();

    assert_eq!(
        recipe.validate(),
        Err(ContextError::MissingRequiredRole(ContextRole::Goal))
    );
    Ok(())
}

#[test]
fn zero_role_budget_preserves_required_atom_as_handle_only() -> TestResult {
    let task_revision = revision(1)?;
    let input = input(task_revision)?;
    let expected_handle = input.atoms[0].atom_id.clone();
    let compiled = ContextCompiler::compile(&input, &recipe(task_revision, 0))?;

    assert!(compiled.units.is_empty());
    assert_eq!(compiled.handle_only, vec![expected_handle]);
    assert_eq!(compiled.admissions.len(), 1);
    assert_eq!(
        compiled.admissions[0].disposition,
        AdmissionDisposition::HandleOnly
    );
    Ok(())
}

#[test]
fn matching_revision_preserves_deterministic_compile_path() -> TestResult {
    let task_revision = revision(1)?;
    let input = input(task_revision)?;
    let compiled = ContextCompiler::compile(&input, &recipe(task_revision, 10))?;

    assert_eq!(compiled.revision, task_revision);
    assert_eq!(compiled.units.len(), 1);
    assert!(compiled.handle_only.is_empty());
    assert_eq!(
        compiled.admissions[0].disposition,
        AdmissionDisposition::Included
    );
    Ok(())
}
