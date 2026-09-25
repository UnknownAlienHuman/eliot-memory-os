//! Production composition of the closed campaign owner-publication matrix.
//!
//! Each input below is produced by its owning crate. This module only joins
//! those owner outputs and their authenticated CAS heads; it does not read a
//! transcript, synthesize an owner record, or persist anything. The resulting
//! vector is handed to the Governor Task Controller transition, which commits
//! it through the existing Kernel/canonical path.

use std::collections::{BTreeMap, BTreeSet};

use eliot_context::campaign_publication::ContextCampaignRecipeBody;
use eliot_context_contracts::SessionDeliverySnapshot;
use eliot_governor::{
    CampaignOwnerSourceInput, CampaignSourcePublicationBundle, TaskControllerCampaignSources,
    assemble_task_owner_matrix,
};
use eliot_product_evaluation::ProductEvaluationCampaignPublications;
use eliot_store_api::{CampaignSourceHead, CampaignSourceRole};

use super::campaign_context_owner::build_context_owner_publications;
use super::campaign_evaluation_owner::build_product_evaluation_publications;

/// Join the real Task Controller, Context Compiler, Product Evaluation, and
/// remaining owner outputs into one validated 26-role matrix.
///
/// `heads` contains only heads read from the authenticated owner routes. A
/// missing entry means the owner read proved absence; it is never replaced by
/// a locally guessed default. The caller must commit the returned bundle via
/// `propose_task_with_complete_campaign_owner_materials` or its apply
/// counterpart.
pub fn assemble_campaign_owner_publications(
    task_sources: &TaskControllerCampaignSources,
    context_recipe: &ContextCampaignRecipeBody,
    prior_delivery: &SessionDeliverySnapshot,
    evaluation: &ProductEvaluationCampaignPublications,
    state_fence: &eliot_contracts::StateFence,
    heads: &BTreeMap<CampaignSourceRole, CampaignSourceHead>,
    remaining_owner_inputs: Vec<CampaignOwnerSourceInput>,
) -> Result<CampaignSourcePublicationBundle, String> {
    for (role, head) in heads {
        head.validate().map_err(|error| error.to_string())?;
        if head.role != *role {
            return Err("owner head map key differs from its typed role".to_owned());
        }
        let requirement = task_sources
            .recipe
            .source_requirements
            .iter()
            .find(|requirement| requirement.role == *role)
            .ok_or_else(|| format!("owner head names an undeclared campaign role {role:?}"))?;
        if requirement.source_binding == eliot_store_api::CampaignSourceBinding::ExplicitlyAbsent {
            return Err(format!(
                "explicitly absent campaign role {role:?} must not carry a source head"
            ));
        }
    }

    let mut context_rows = build_context_owner_publications(
        context_recipe,
        prior_delivery,
        heads.get(&CampaignSourceRole::ContextRecipe).cloned(),
        heads.get(&CampaignSourceRole::ContextToolPolicy).cloned(),
        heads.get(&CampaignSourceRole::ContextDelivery).cloned(),
        state_fence,
    )
    .map_err(|error| error.to_string())?;
    for row in &mut context_rows {
        let expected_head = heads.get(&row.record.role).cloned();
        *row = row
            .clone()
            .with_expected_head_and_read_fence(expected_head, state_fence)
            .map_err(|error| error.to_string())?;
    }

    let mut evaluation_rows = build_product_evaluation_publications(evaluation, state_fence)
        .map_err(|error| error.to_string())?;
    for row in &mut evaluation_rows {
        let expected_head = heads.get(&row.record.role).cloned();
        *row = row
            .clone()
            .with_expected_head_and_read_fence(expected_head, state_fence)
            .map_err(|error| error.to_string())?;
    }

    let mut owner_rows = Vec::with_capacity(
        context_rows.len() + evaluation_rows.len() + remaining_owner_inputs.len(),
    );
    owner_rows.extend(context_rows);
    owner_rows.extend(evaluation_rows);
    let mut input_roles = BTreeSet::new();
    for mut input in remaining_owner_inputs {
        if matches!(
            input.role,
            CampaignSourceRole::TaskObjective
                | CampaignSourceRole::TaskAcceptance
                | CampaignSourceRole::TaskPlan
                | CampaignSourceRole::TaskOpenItems
        ) {
            return Err(
                "owner-material inputs cannot replace Task Controller source rows".to_owned(),
            );
        }
        if matches!(
            input.role,
            CampaignSourceRole::ContextRecipe
                | CampaignSourceRole::ContextToolPolicy
                | CampaignSourceRole::ContextDelivery
                | CampaignSourceRole::EvaluatorContract
                | CampaignSourceRole::EvaluatorHoldout
                | CampaignSourceRole::EvaluationResults
        ) {
            return Err(
                "owner-material inputs duplicate a Context or evaluation owner row".to_owned(),
            );
        }
        if !input_roles.insert(input.role) {
            return Err("owner-material inputs contain a duplicate role".to_owned());
        }
        if input.read_state_fence != *state_fence {
            return Err(
                "remaining owner input is not bound to the authenticated read fence".to_owned(),
            );
        }
        // The material's head set is the authenticated observation. A missing
        // role proves absence; never retain a caller-supplied expected head.
        input.expected_head = heads.get(&input.role).cloned();
        owner_rows.push(
            input
                .into_publication()
                .map_err(|error| error.to_string())?,
        );
    }
    let represented_roles = owner_rows
        .iter()
        .map(|publication| publication.record.role)
        .chain([
            task_sources.objective.record.role,
            task_sources.plan.record.role,
            task_sources.acceptance.record.role,
            task_sources.open_items.record.role,
        ])
        .collect::<BTreeSet<_>>();
    if let Some(role) = heads.keys().find(|role| !represented_roles.contains(role)) {
        return Err(format!(
            "owner head {role:?} has no matching owner publication"
        ));
    }
    let publications =
        assemble_task_owner_matrix(task_sources, owner_rows).map_err(|error| error.to_string())?;
    let bundle = CampaignSourcePublicationBundle { publications };
    bundle
        .validate_complete_denominator(&task_sources.recipe)
        .map_err(|error| error.to_string())?;
    Ok(bundle)
}
