//! Authenticated Context-owner publication boundary for the campaign packet
//! path.
//!
//! The Context owner publishes the recipe and the session-delivery snapshot.
//! This adapter is deliberately thin: it invokes the owner validators, then
//! projects their exact typed bodies into the closed store publication shape,
//! and at consumption time re-runs those same owner validators so the decoded
//! bodies still bind to the packet State Fence. It never creates a Context
//! recipe, delivery snapshot, or campaign source from a transcript/current-file
//! substitute, and it is not a second compiler: the frozen
//! `eliot_context::ContextCompiler` takes no product caller on this route.

use std::collections::BTreeSet;

use eliot_context::campaign_publication::{
    ContextCampaignRecipeBody, ContextCompilerSupplierProfileV1, ContextPublicationError,
    ContextSourcePublication, ContextToolPolicyProjectionV1, context_delivery_publication,
    context_recipe_publication_with_compiler_suppliers,
};
use eliot_context_contracts::SessionDeliverySnapshot;
use eliot_contracts::{ArtifactId, StateFence};
use eliot_learning_contracts::{CampaignSourceRole, OwnerId};
use eliot_store_api::{
    CampaignOwnerProjectionBody, CampaignOwnerReadReceipt,
    CampaignSourceDocument as StoreCampaignSourceDocument, CampaignSourceDocumentSchema,
    CampaignSourceHead, CampaignSourcePublication, CampaignSourcePublisher, CampaignSourceRecord,
};

/// One current owner row and the exact head returned by its authenticated read.
/// Callers construct this only from a validated Kernel named read or its
/// current-reference publication; the owner validator rechecks the receipt
/// and complete row/head binding before accepting it.
#[derive(Clone, Copy)]
pub(crate) struct ContextOwnerSourceRead<'a> {
    pub(crate) record: &'a CampaignSourceRecord,
    pub(crate) current_head: &'a CampaignSourceHead,
    pub(crate) read_receipt: &'a CampaignOwnerReadReceipt,
}

/// Authenticated current Context rows selected by the task recipe.
#[derive(Clone, Copy)]
pub(crate) struct ContextOwnerSourceReads<'a> {
    pub(crate) recipe: ContextOwnerSourceRead<'a>,
    pub(crate) tool_policy: Option<ContextOwnerSourceRead<'a>>,
    pub(crate) delivery: Option<ContextOwnerSourceRead<'a>>,
}

fn context_required_references(recipe_body: &ContextCampaignRecipeBody) -> Vec<ArtifactId> {
    recipe_body
        .compiler_input
        .atoms
        .iter()
        .flat_map(|atom| atom.source_handles.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn build_context_recipe_record(
    recipe_owner: &ContextSourcePublication,
    required_references: Vec<ArtifactId>,
) -> Result<CampaignSourceRecord, ContextPublicationError> {
    let owner_id =
        OwnerId::from_artifact(ArtifactId::new(recipe_owner.owner_id().to_owned()).map_err(
            |_| ContextPublicationError::BindingMismatch {
                field: "context_recipe.owner_id",
            },
        )?);
    CampaignSourceRecord::new(
        CampaignSourceRole::ContextRecipe,
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
            schema: CampaignSourceDocumentSchema::ContextRecipe,
            schema_version: StoreCampaignSourceDocument::SCHEMA_VERSION,
            body: recipe_owner.body_value()?,
        },
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_recipe.publication",
    })
}

fn build_context_delivery_record(
    delivery_owner: &ContextSourcePublication,
) -> Result<CampaignSourceRecord, ContextPublicationError> {
    let owner_id = OwnerId::from_artifact(
        ArtifactId::new(delivery_owner.owner_id().to_owned()).map_err(|_| {
            ContextPublicationError::BindingMismatch {
                field: "context_delivery.owner_id",
            }
        })?,
    );
    CampaignSourceRecord::new(
        CampaignSourceRole::ContextDelivery,
        owner_id,
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
            body: delivery_owner.body_value()?,
        },
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_delivery.publication",
    })
}

fn build_context_tool_policy_record(
    recipe_body: &ContextCampaignRecipeBody,
    recipe_owner: &ContextSourcePublication,
    required_references: Vec<ArtifactId>,
) -> Result<CampaignSourceRecord, ContextPublicationError> {
    let owner_id =
        OwnerId::from_artifact(ArtifactId::new(recipe_owner.owner_id().to_owned()).map_err(
            |_| ContextPublicationError::BindingMismatch {
                field: "context_tool_policy.owner_id",
            },
        )?);
    let projection = match &recipe_body.compiler_suppliers {
        Some(compiler_suppliers) => serde_json::to_value(ContextToolPolicyProjectionV1 {
            schema_version: 1,
            recipe: recipe_body.recipe.clone(),
            compiler_suppliers: compiler_suppliers.clone(),
        }),
        None => serde_json::to_value(&recipe_body.recipe),
    }
    .map_err(|error| ContextPublicationError::Serialization(error.to_string()))?;
    let projection_digest = eliot_contracts::sha256_hex(
        &eliot_contracts::canonical_json_bytes(&projection)
            .map_err(|error| ContextPublicationError::Serialization(error.to_string()))?,
    );
    let body = CampaignOwnerProjectionBody {
        owner_id: recipe_owner.owner_id().to_owned(),
        record_id: recipe_owner.record_id_text(),
        revision: recipe_owner.revision_text(),
        state_fence: recipe_owner.recorded_state_fence().clone(),
        projection_digest,
        required_references: required_references.clone(),
        projection,
    };
    CampaignSourceRecord::new(
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
    })
}

/// The immutable owner-record content digest the Context owner re-derives for
/// this exact recipe body, through its own publication, from the recipe,
/// catalogue and compiler input it validated.
///
/// #1862: this is the domain the immutable campaign view records for its
/// `ContextRecipe` source row — a `CampaignSourceRecord` content digest — and
/// therefore the only value the candidate, admission and assembly cells can
/// compare that row against. `context_recipe_body_digest` digests the recipe
/// body alone, which is what `validate_context_owner_bodies` and the stored
/// document body are compared against; handing that to the cells would compare
/// two different objects and make their load-bearing-revision refusal
/// unsatisfiable for every view, including a current one.
pub(crate) fn derive_context_recipe_record_digest(
    recipe_body: &ContextCampaignRecipeBody,
) -> Result<String, String> {
    Ok(derive_context_recipe_record(recipe_body)?.content_digest)
}

/// Derive the exact recipe owner row for candidate validation before its
/// authenticated current row is read.
pub(crate) fn derive_context_recipe_record(
    recipe_body: &ContextCampaignRecipeBody,
) -> Result<CampaignSourceRecord, String> {
    let recipe_owner = context_recipe_publication_with_compiler_suppliers(
        &recipe_body.recipe,
        &recipe_body.catalogue,
        &recipe_body.compiler_input,
        recipe_body.compiler_suppliers.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    build_context_recipe_record(&recipe_owner, context_required_references(recipe_body))
        .map_err(|error| error.to_string())
}

fn build_context_tool_policy_publication(
    recipe_body: &ContextCampaignRecipeBody,
    recipe_owner: &ContextSourcePublication,
    required_references: Vec<ArtifactId>,
    expected_head: Option<CampaignSourceHead>,
    read_state_fence: &StateFence,
) -> Result<CampaignSourcePublication, ContextPublicationError> {
    let record = build_context_tool_policy_record(recipe_body, recipe_owner, required_references)?;
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
pub fn build_context_recipe_and_tool_policy_publications(
    recipe_body: &ContextCampaignRecipeBody,
    expected_recipe_head: Option<CampaignSourceHead>,
    expected_tool_policy_head: Option<CampaignSourceHead>,
    read_state_fence: &StateFence,
) -> Result<Vec<CampaignSourcePublication>, ContextPublicationError> {
    let recipe_owner = context_recipe_publication_with_compiler_suppliers(
        &recipe_body.recipe,
        &recipe_body.catalogue,
        &recipe_body.compiler_input,
        recipe_body.compiler_suppliers.as_ref(),
    )?;
    let required_references = context_required_references(recipe_body);
    let recipe_record = build_context_recipe_record(&recipe_owner, required_references.clone())?;
    let tool_policy_publication = build_context_tool_policy_publication(
        recipe_body,
        &recipe_owner,
        required_references,
        expected_tool_policy_head,
        read_state_fence,
    )?;
    let recipe_publication = CampaignSourcePublication::from_observed_head(
        CampaignSourcePublisher::ContextRecipe,
        recipe_record,
        expected_recipe_head,
        read_state_fence,
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_recipe.publication",
    })?;
    Ok(vec![recipe_publication, tool_policy_publication])
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
    let mut publications = build_context_recipe_and_tool_policy_publications(
        recipe_body,
        expected_recipe_head,
        expected_tool_policy_head,
        read_state_fence,
    )?;
    let delivery_owner = context_delivery_publication(&recipe_body.recipe, prior_delivery)?;
    let delivery_record = build_context_delivery_record(&delivery_owner)?;
    let delivery_publication = CampaignSourcePublication::from_observed_head(
        CampaignSourcePublisher::ContextDelivery,
        delivery_record,
        expected_delivery_head,
        read_state_fence,
    )
    .map_err(|_| ContextPublicationError::BindingMismatch {
        field: "context_delivery.publication",
    })?;
    publications.push(delivery_publication);
    Ok(publications)
}

/// Validate the exact Context owner bodies against a campaign source fence
/// before a packet attempt consumes them.
///
/// Every re-derived row must equal the row returned by its authenticated named
/// read, and the read's current head must identify that same complete row. A
/// successor publication is not current evidence and is rejected here.
pub(crate) fn validate_context_owner_bodies(
    recipe_body: &ContextCampaignRecipeBody,
    prior_delivery: Option<&SessionDeliverySnapshot>,
    source_reads: &ContextOwnerSourceReads<'_>,
    state_fence: &StateFence,
) -> Result<Vec<CampaignSourcePublication>, String> {
    if recipe_body.recipe.binding.state_fence != *state_fence {
        return Err("Context recipe does not share the packet State Fence".to_owned());
    }
    let recipe_owner = context_recipe_publication_with_compiler_suppliers(
        &recipe_body.recipe,
        &recipe_body.catalogue,
        &recipe_body.compiler_input,
        recipe_body.compiler_suppliers.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    let required_references = context_required_references(recipe_body);
    let recipe_record = build_context_recipe_record(&recipe_owner, required_references.clone())
        .map_err(|error| error.to_string())?;
    let recipe_publication = bind_current_owner_record(
        CampaignSourcePublisher::ContextRecipe,
        recipe_record,
        source_reads.recipe,
        state_fence,
    )?;
    let mut publications = vec![recipe_publication];

    if let Some(tool_policy_read) = source_reads.tool_policy {
        let tool_policy_record =
            build_context_tool_policy_record(recipe_body, &recipe_owner, required_references)
                .map_err(|error| error.to_string())?;
        publications.push(bind_current_owner_record(
            CampaignSourcePublisher::ContextToolPolicy,
            tool_policy_record,
            tool_policy_read,
            state_fence,
        )?);
    }

    match (prior_delivery, source_reads.delivery) {
        (Some(prior_delivery), Some(delivery_read)) => {
            let delivery_owner = context_delivery_publication(&recipe_body.recipe, prior_delivery)
                .map_err(|error| error.to_string())?;
            let delivery_record = build_context_delivery_record(&delivery_owner)
                .map_err(|error| error.to_string())?;
            publications.push(bind_current_owner_record(
                CampaignSourcePublisher::ContextDelivery,
                delivery_record,
                delivery_read,
                state_fence,
            )?);
        }
        (None, None) => {}
        _ => {
            return Err(
                "Context delivery body and authenticated read must be present together".to_owned(),
            );
        }
    }
    Ok(publications)
}

/// Validate the original ContextToolPolicy row against the same typed recipe
/// and supplier profile used to derive its owner publication.
pub(crate) fn validate_context_tool_policy_source_record(
    recipe_body: &ContextCampaignRecipeBody,
    source: &CampaignSourceRecord,
) -> Result<Option<ContextCompilerSupplierProfileV1>, String> {
    let recipe_owner = context_recipe_publication_with_compiler_suppliers(
        &recipe_body.recipe,
        &recipe_body.catalogue,
        &recipe_body.compiler_input,
        recipe_body.compiler_suppliers.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    let expected = build_context_tool_policy_record(
        recipe_body,
        &recipe_owner,
        context_required_references(recipe_body),
    )
    .map_err(|error| error.to_string())?;
    if *source != expected {
        return Err(
            "ContextToolPolicy row does not match its original typed recipe source".to_owned(),
        );
    }
    Ok(recipe_body.compiler_suppliers.clone())
}

fn source_record_matches_head(record: &CampaignSourceRecord, head: &CampaignSourceHead) -> bool {
    record.role == head.role
        && record.owner_id == head.owner_id
        && record.record_id == head.record_id
        && record.revision == head.revision
        && record.content_digest == head.content_digest
        && record.recorded_state_fence == head.recorded_state_fence
        && record.slot_projection_digests == head.slot_projection_digests
}

fn bind_current_owner_record(
    publisher: CampaignSourcePublisher,
    record: CampaignSourceRecord,
    read: ContextOwnerSourceRead<'_>,
    state_fence: &StateFence,
) -> Result<CampaignSourcePublication, String> {
    if read.read_receipt.validate().is_err()
        || read.read_receipt.read_state_fence != *state_fence
        || !read.read_receipt.binds_record(read.record)
        || read.current_head.validate().is_err()
        || !source_record_matches_head(read.record, read.current_head)
        || record != *read.record
    {
        return Err(
            "Context owner derivation does not match its authenticated current row".to_owned(),
        );
    }
    let publication = CampaignSourcePublication::from_observed_head(
        publisher,
        record,
        Some(read.current_head.clone()),
        state_fence,
    )
    .map_err(|error| error.to_string())?;
    if !publication.state.is_current_reference()
        || publication.state.current_head() != Some(read.current_head)
        || publication.record != *read.record
    {
        return Err("Context owner head is not the exact current row".to_owned());
    }
    Ok(publication)
}
