//! Authenticated Context-owner publication and consumption boundary for the
//! campaign packet path.
//!
//! The Context compiler owns the recipe and the session-delivery snapshot.
//! This adapter is deliberately thin: it invokes the owner validators, then
//! projects their exact typed bodies into the closed store publication shape.
//! It never creates a Context recipe, delivery snapshot, or campaign source
//! from a transcript/current-file substitute.

use std::collections::BTreeSet;

use eliot_context::CampaignCompiledContext;
use eliot_context::campaign_publication::{
    ContextCampaignRecipeBody, ContextPublicationError, ContextSourcePublication,
    context_delivery_publication, context_recipe_publication,
};
use eliot_context_contracts::SessionDeliverySnapshot;
use eliot_contracts::{ArtifactId, StateFence};
use eliot_learning_contracts::{CampaignSourceRole, OwnerId};
use eliot_store_api::{
    CampaignOwnerProjectionBody, CampaignSourceDocument as StoreCampaignSourceDocument,
    CampaignSourceDocumentSchema, CampaignSourceHead, CampaignSourcePublication,
    CampaignSourcePublisher, CampaignSourceRecord,
};

fn build_context_tool_policy_publication(
    recipe_body: &ContextCampaignRecipeBody,
    recipe_owner: &ContextSourcePublication,
    required_references: Vec<ArtifactId>,
    expected_head: Option<CampaignSourceHead>,
    read_state_fence: &StateFence,
) -> Result<CampaignSourcePublication, ContextPublicationError> {
    let owner_id =
        OwnerId::from_artifact(ArtifactId::new(recipe_owner.owner_id().to_owned()).map_err(
            |_| ContextPublicationError::BindingMismatch {
                field: "context_tool_policy.owner_id",
            },
        )?);
    let projection = serde_json::to_value(&recipe_body.recipe)
        .map_err(|error| ContextPublicationError::Serialization(error.to_string()))?;
    let projection_digest = eliot_contracts::sha256_hex(
        &eliot_contracts::canonical_json_bytes(&projection)
            .map_err(|error| ContextPublicationError::Serialization(error.to_string()))?,
    );
    let record_id = recipe_owner.record_id_text();
    let revision = recipe_owner.revision_text();
    let body = CampaignOwnerProjectionBody {
        owner_id: recipe_owner.owner_id().to_owned(),
        record_id,
        revision,
        state_fence: recipe_owner.recorded_state_fence().clone(),
        projection_digest,
        required_references: required_references.clone(),
        projection,
    };
    let record = CampaignSourceRecord::new(
        CampaignSourceRole::ContextToolPolicy,
        owner_id,
        recipe_owner.record_id().clone(),
        recipe_owner.revision().clone(),
        recipe_owner.recorded_state_fence().clone(),
        Vec::new(),
        Vec::new(),
        required_references,
        Vec::new(),
        Vec::new(),
        StoreCampaignSourceDocument {
            schema: CampaignSourceDocumentSchema::ContextToolPolicy,
            schema_version: StoreCampaignSourceDocument::SCHEMA_VERSION,
            body: serde_json::to_value(&body)
                .map_err(|error| ContextPublicationError::Serialization(error.to_string()))?,
        },
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_tool_policy.publication",
    })?;
    let publication = CampaignSourcePublication::from_observed_head(
        CampaignSourcePublisher::ContextToolPolicy,
        record,
        expected_head,
        read_state_fence,
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_tool_policy.publication",
    })?;
    Ok(publication)
}

/// Exact Context owner rows ready for the authenticated Kernel publication
/// transition. The owner validators run before any row is constructed.
pub fn build_context_owner_publications(
    recipe_body: &ContextCampaignRecipeBody,
    prior_delivery: &SessionDeliverySnapshot,
    expected_recipe_head: Option<CampaignSourceHead>,
    expected_tool_policy_head: Option<CampaignSourceHead>,
    expected_delivery_head: Option<CampaignSourceHead>,
    read_state_fence: &StateFence,
) -> Result<Vec<CampaignSourcePublication>, ContextPublicationError> {
    let recipe_owner =
        context_recipe_publication(&recipe_body.recipe, &recipe_body.compiler_input)?;
    let delivery_owner = context_delivery_publication(&recipe_body.recipe, prior_delivery)?;
    let recipe_value = recipe_owner.body_value()?;
    let delivery_value = delivery_owner.body_value()?;
    let recipe_owner_id =
        OwnerId::from_artifact(ArtifactId::new(recipe_owner.owner_id().to_owned()).map_err(
            |_| ContextPublicationError::BindingMismatch {
                field: "context_recipe.owner_id",
            },
        )?);
    let delivery_owner_id = OwnerId::from_artifact(
        ArtifactId::new(delivery_owner.owner_id().to_owned()).map_err(|_| {
            ContextPublicationError::BindingMismatch {
                field: "context_delivery.owner_id",
            }
        })?,
    );
    let required_references = recipe_body
        .compiler_input
        .atoms
        .iter()
        .flat_map(|atom| atom.source_handles.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let recipe_record = CampaignSourceRecord::new(
        CampaignSourceRole::ContextRecipe,
        recipe_owner_id,
        recipe_owner.record_id().clone(),
        recipe_owner.revision().clone(),
        recipe_owner.recorded_state_fence().clone(),
        Vec::new(),
        Vec::new(),
        required_references.clone(),
        Vec::new(),
        Vec::new(),
        StoreCampaignSourceDocument {
            schema: CampaignSourceDocumentSchema::ContextRecipe,
            schema_version: StoreCampaignSourceDocument::SCHEMA_VERSION,
            body: recipe_value,
        },
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_recipe.publication",
    })?;
    let tool_policy_publication = build_context_tool_policy_publication(
        recipe_body,
        &recipe_owner,
        required_references,
        expected_tool_policy_head,
        read_state_fence,
    )?;
    let delivery_record = CampaignSourceRecord::new(
        CampaignSourceRole::ContextDelivery,
        delivery_owner_id,
        delivery_owner.record_id().clone(),
        delivery_owner.revision().clone(),
        delivery_owner.recorded_state_fence().clone(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        StoreCampaignSourceDocument {
            schema: CampaignSourceDocumentSchema::ContextDelivery,
            schema_version: StoreCampaignSourceDocument::SCHEMA_VERSION,
            body: delivery_value,
        },
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_delivery.publication",
    })?;
    let recipe_publication = CampaignSourcePublication::from_observed_head(
        CampaignSourcePublisher::ContextRecipe,
        recipe_record,
        expected_recipe_head,
        read_state_fence,
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_recipe.publication",
    })?;
    let delivery_publication = CampaignSourcePublication::from_observed_head(
        CampaignSourcePublisher::ContextDelivery,
        delivery_record,
        expected_delivery_head,
        read_state_fence,
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_delivery.publication",
    })?;
    Ok(vec![
        recipe_publication,
        tool_policy_publication,
        delivery_publication,
    ])
}

/// Consume the exact Context compiler result at the packet boundary.
///
/// This is a downstream consumer, not another compiler: it checks that the
/// compiled context still names the exact learning-state view and recipe
/// digests, then projects a bounded delivery receipt for the caller. The
/// receipt contains no transcript copy and performs no store write.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CampaignContextDeliveryReceipt {
    pub(crate) learning_state_view_id: ArtifactId,
    pub(crate) learning_state_view_digest: String,
    pub(crate) context_recipe_digest: String,
    pub(crate) delivered_unit_count: usize,
    pub(crate) retained_handle_count: usize,
}

/// Consume one compiled Context result after the owner publications have been
/// independently validated by the packet compiler.
pub(crate) fn consume_compiled_context(
    compiled: &CampaignCompiledContext,
    expected_view_id: &ArtifactId,
    expected_view_digest: &str,
) -> Result<CampaignContextDeliveryReceipt, String> {
    if &compiled.learning_state_view_id != expected_view_id
        || compiled.learning_state_view_digest != expected_view_digest
        || compiled.context_recipe_digest.trim().is_empty()
    {
        return Err("compiled Context result is not bound to the current learning view".to_owned());
    }
    Ok(CampaignContextDeliveryReceipt {
        learning_state_view_id: compiled.learning_state_view_id.clone(),
        learning_state_view_digest: compiled.learning_state_view_digest.clone(),
        context_recipe_digest: compiled.context_recipe_digest.clone(),
        delivered_unit_count: compiled.context.units.len(),
        retained_handle_count: compiled.context.handle_only.len(),
    })
}

/// Validate the exact Context owner bodies against a campaign source fence
/// before a packet compiler consumes them.
pub(crate) fn validate_context_owner_bodies(
    recipe_body: &ContextCampaignRecipeBody,
    prior_delivery: Option<&SessionDeliverySnapshot>,
    state_fence: &StateFence,
) -> Result<Vec<CampaignSourcePublication>, String> {
    if recipe_body.recipe.binding.state_fence != *state_fence {
        return Err("Context recipe does not share the packet State Fence".to_owned());
    }
    let Some(prior_delivery) = prior_delivery else {
        let recipe_owner =
            context_recipe_publication(&recipe_body.recipe, &recipe_body.compiler_input)
                .map_err(|error| error.to_string())?;
        let owner_id = OwnerId::from_artifact(
            ArtifactId::new(recipe_owner.owner_id().to_owned())
                .map_err(|_| "Context recipe owner identity is invalid".to_owned())?,
        );
        let required_references = recipe_body
            .compiler_input
            .atoms
            .iter()
            .flat_map(|atom| atom.source_handles.iter().cloned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let record = CampaignSourceRecord::new(
            CampaignSourceRole::ContextRecipe,
            owner_id,
            recipe_owner.record_id().clone(),
            recipe_owner.revision().clone(),
            recipe_owner.recorded_state_fence().clone(),
            Vec::new(),
            Vec::new(),
            required_references.clone(),
            Vec::new(),
            Vec::new(),
            StoreCampaignSourceDocument {
                schema: CampaignSourceDocumentSchema::ContextRecipe,
                schema_version: StoreCampaignSourceDocument::SCHEMA_VERSION,
                body: recipe_owner
                    .body_value()
                    .map_err(|error| error.to_string())?,
            },
        )
        .map_err(|error| error.to_string())?;
        let publication = CampaignSourcePublication::from_observed_head(
            CampaignSourcePublisher::ContextRecipe,
            record,
            None,
            state_fence,
        )
        .map_err(|error| error.to_string())?;
        let tool_policy = build_context_tool_policy_publication(
            recipe_body,
            &recipe_owner,
            required_references,
            None,
            state_fence,
        )
        .map_err(|error| error.to_string())?;
        return Ok(vec![publication, tool_policy]);
    };
    if prior_delivery.state_fence != *state_fence {
        return Err("Context delivery does not share the packet State Fence".to_owned());
    }
    build_context_owner_publications(recipe_body, prior_delivery, None, None, None, state_fence)
        .map_err(|error| error.to_string())
}
