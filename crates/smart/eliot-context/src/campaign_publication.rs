//! Owner-derived immutable publications used by the campaign source boundary.
//!
//! These values are deliberately store-neutral. They carry closed typed owner
//! bodies and metadata derived from those bodies; the authenticated Kernel
//! publication path remains responsible for admitting and persisting them.

use eliot_context_contracts::{
    ContextError as ContractContextError, ContextRecipe, ReactiveInputError,
    SessionDeliverySnapshot,
};
use eliot_contracts::{StateFence, canonical_json_bytes, sha256_hex};
use eliot_learning_contracts::{CampaignOwnerRecordId, CampaignOwnerRevision, CampaignSourceRole};
use eliot_protocol::ReactiveContextStage;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ContextError, ContextInput};

/// Canonical owner identity for the immutable Context Compiler recipe.
pub const CONTEXT_RECIPE_CAMPAIGN_OWNER_ID: &str = "owner:eliot-context/context-compiler";

/// Closed source document selected by the campaign source schema.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContextSourceDocument {
    /// Current rich policy recipe together with the exact input admitted for it.
    Recipe(Box<ContextCampaignRecipeBody>),
    /// Actual prior owner-issued delivery snapshot, retaining its original
    /// attempt, revision, and fence.
    Delivery(Box<SessionDeliverySnapshot>),
}

/// Current Context Compiler `ContextRecipe` and exact compiler input admitted for it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCampaignRecipeBody {
    /// Exact rich immutable `ContextRecipe` policy.
    pub recipe: ContextRecipe,
    /// Current admitted Context input used by the compiler for this recipe.
    pub compiler_input: ContextInput,
}

/// Store-neutral immutable source publication derived from Context owner data.
/// Fields remain private so callers cannot supply an arbitrary owner, revision,
/// fence, or digest independently of the typed source body.
#[derive(Clone, Debug, PartialEq)]
pub struct ContextSourcePublication {
    role: CampaignSourceRole,
    owner_id: String,
    record_id: CampaignOwnerRecordId,
    revision: CampaignOwnerRevision,
    recorded_state_fence: StateFence,
    document: ContextSourceDocument,
    body_digest: String,
}

/// Invalid owner data or a cross-source binding mismatch.
#[derive(Debug, Error)]
pub enum ContextPublicationError {
    /// The rich `ContextRecipe` did not satisfy its closed contract.
    #[error("ContextRecipe is invalid: {0}")]
    Recipe(#[from] ContractContextError),
    /// The compiler input did not satisfy the pure Context contract.
    #[error("ContextInput is invalid: {0}")]
    Input(#[from] ContextError),
    /// The prior delivery snapshot did not satisfy its owner contract.
    #[error("SessionDeliverySnapshot is invalid: {0}")]
    Delivery(#[from] ReactiveInputError),
    /// A typed owner body could not be canonically serialized.
    #[error("Context source body serialization failed: {0}")]
    Serialization(String),
    /// The real source data does not bind to the admitted recipe.
    #[error("Context source does not bind field {field}")]
    BindingMismatch { field: &'static str },
    /// The retained prior snapshot has no current delivered record.
    #[error("prior Context snapshot has no current delivered record")]
    MissingCurrentDelivery,
}

impl ContextSourcePublication {
    /// Source role represented by this owner-derived document.
    #[must_use]
    pub const fn role(&self) -> CampaignSourceRole {
        self.role
    }

    /// Fixed closed schema tag corresponding to the selected body type.
    #[must_use]
    pub const fn schema_tag(&self) -> &'static str {
        match self.document {
            ContextSourceDocument::Recipe(_) => "CONTEXT_RECIPE",
            ContextSourceDocument::Delivery(_) => "CONTEXT_DELIVERY",
        }
    }

    /// Authenticated owner identity carried by this source.
    #[must_use]
    pub fn owner_id(&self) -> &str {
        &self.owner_id
    }

    /// Native owner record identity derived from the recipe or delivery source.
    #[must_use]
    pub const fn record_id(&self) -> &CampaignOwnerRecordId {
        &self.record_id
    }

    /// Native owner revision derived from the exact source record.
    #[must_use]
    pub const fn revision(&self) -> &CampaignOwnerRevision {
        &self.revision
    }

    /// Original fence carried by the exact source record.
    #[must_use]
    pub const fn recorded_state_fence(&self) -> &StateFence {
        &self.recorded_state_fence
    }

    /// Render the native owner record identity for a closed store envelope.
    #[must_use]
    pub fn record_id_text(&self) -> String {
        match &self.record_id {
            CampaignOwnerRecordId::Decision(value) => value.as_str().to_owned(),
            CampaignOwnerRecordId::Resource(value) => value.clone(),
            CampaignOwnerRecordId::Task(value) => value.as_str().to_owned(),
            CampaignOwnerRecordId::Contract(value) => value.as_str().to_owned(),
            CampaignOwnerRecordId::Artifact(value) => value.as_str().to_owned(),
        }
    }

    /// Render the native owner revision for a closed store envelope.
    #[must_use]
    pub fn revision_text(&self) -> String {
        match &self.revision {
            CampaignOwnerRevision::Task(value) => value.value().to_string(),
            CampaignOwnerRevision::Counter(value) => value.to_string(),
            CampaignOwnerRevision::AuthorityEpoch(value) => value.value().to_string(),
            CampaignOwnerRevision::Policy(value) => value.value().to_string(),
            CampaignOwnerRevision::ResourceGeneration(value) => value.value().to_string(),
            CampaignOwnerRevision::ResourceSnapshot(value) => value.clone(),
        }
    }

    /// Closed typed source document for the role.
    #[must_use]
    pub const fn document(&self) -> &ContextSourceDocument {
        &self.document
    }

    /// Serialize only the concrete source body, without transport metadata.
    pub fn body_value(&self) -> Result<serde_json::Value, ContextPublicationError> {
        let result = match &self.document {
            ContextSourceDocument::Recipe(body) => serde_json::to_value(body),
            ContextSourceDocument::Delivery(snapshot) => serde_json::to_value(snapshot),
        };
        result.map_err(|error| ContextPublicationError::Serialization(error.to_string()))
    }

    /// Canonical digest of the concrete typed document body.
    #[must_use]
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }
}

/// Build the exact campaign source for an admitted current `ContextRecipe` and
/// its compiler input. This publication is available before Context view
/// compilation and therefore does not depend on a later delivery.
pub fn context_recipe_publication(
    recipe: &ContextRecipe,
    compiler_input: &ContextInput,
) -> Result<ContextSourcePublication, ContextPublicationError> {
    recipe.validate()?;
    compiler_input.validate()?;
    validate_recipe_input_binding(recipe, compiler_input)?;

    let document = ContextSourceDocument::Recipe(Box::new(ContextCampaignRecipeBody {
        recipe: recipe.clone(),
        compiler_input: compiler_input.clone(),
    }));
    let body_digest = document_digest(&document)?;
    Ok(ContextSourcePublication {
        role: CampaignSourceRole::ContextRecipe,
        owner_id: CONTEXT_RECIPE_CAMPAIGN_OWNER_ID.to_owned(),
        record_id: CampaignOwnerRecordId::Decision(recipe.decision.decision_id.clone()),
        revision: CampaignOwnerRevision::Task(recipe.decision.recipe_revision),
        recorded_state_fence: recipe.binding.state_fence.clone(),
        document,
        body_digest,
    })
}

/// Retain the exact prior delivered snapshot for the current task and scope.
///
/// The prior delivery's own current record must be current against the
/// snapshot's original attempt and fence. The new recipe may belong to a later
/// attempt and fence; this function preserves those original delivery values.
pub fn context_delivery_publication(
    recipe: &ContextRecipe,
    prior_delivery: &SessionDeliverySnapshot,
) -> Result<ContextSourcePublication, ContextPublicationError> {
    recipe.validate()?;
    prior_delivery.validate()?;
    validate_recipe_prior_delivery_link(recipe, prior_delivery)?;

    let document = ContextSourceDocument::Delivery(Box::new(prior_delivery.clone()));
    let body_digest = document_digest(&document)?;
    Ok(ContextSourcePublication {
        role: CampaignSourceRole::ContextDelivery,
        // Kernel publication still verifies this identity against the
        // authenticated delivery owner.
        owner_id: prior_delivery.owner_id.clone(),
        record_id: CampaignOwnerRecordId::Resource(prior_delivery.source_id.as_str().to_owned()),
        revision: CampaignOwnerRevision::ResourceSnapshot(prior_delivery.snapshot_revision.clone()),
        recorded_state_fence: prior_delivery.state_fence.clone(),
        document,
        body_digest,
    })
}

/// Compute the canonical digest of the exact current recipe-plus-input body.
pub fn context_recipe_body_digest(
    body: &ContextCampaignRecipeBody,
) -> Result<String, ContextPublicationError> {
    body.recipe.validate()?;
    body.compiler_input.validate()?;
    validate_recipe_input_binding(&body.recipe, &body.compiler_input)?;
    let bytes = canonical_json_bytes(body)
        .map_err(|error| ContextPublicationError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// Compute the canonical digest of an exact prior owner delivery snapshot.
pub fn context_delivery_body_digest(
    snapshot: &SessionDeliverySnapshot,
) -> Result<String, ContextPublicationError> {
    snapshot.validate()?;
    let bytes = canonical_json_bytes(snapshot)
        .map_err(|error| ContextPublicationError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

fn validate_recipe_input_binding(
    recipe: &ContextRecipe,
    compiler_input: &ContextInput,
) -> Result<(), ContextPublicationError> {
    if compiler_input.task_id.as_ref() != Some(&recipe.binding.decision_id) {
        return Err(ContextPublicationError::BindingMismatch {
            field: "compiler_input.task_id",
        });
    }
    if compiler_input.scope != recipe.binding.scope_id.as_str() {
        return Err(ContextPublicationError::BindingMismatch {
            field: "compiler_input.scope",
        });
    }
    if compiler_input.task_revision != recipe.decision.recipe_revision {
        return Err(ContextPublicationError::BindingMismatch {
            field: "compiler_input.task_revision",
        });
    }
    if compiler_input.state_fence != recipe.binding.state_fence {
        return Err(ContextPublicationError::BindingMismatch {
            field: "compiler_input.state_fence",
        });
    }
    Ok(())
}

fn validate_recipe_prior_delivery_link(
    recipe: &ContextRecipe,
    prior_delivery: &SessionDeliverySnapshot,
) -> Result<(), ContextPublicationError> {
    if prior_delivery.task_id != recipe.binding.task_id {
        return Err(ContextPublicationError::BindingMismatch {
            field: "prior_delivery.task_id",
        });
    }
    if prior_delivery.scope_id != recipe.binding.scope_id {
        return Err(ContextPublicationError::BindingMismatch {
            field: "prior_delivery.scope_id",
        });
    }

    let has_current_delivery = prior_delivery.records.iter().any(|record| {
        record.stage == ReactiveContextStage::DeliveredToExactEndpoint
            && matches!(
                record.validity,
                eliot_protocol::ReactiveContextValidity::Current
            )
            && record.closure.as_ref().is_some_and(|closure| {
                closure.context_view.view.binding.task_id == prior_delivery.task_id
                    && closure.context_view.view.binding.attempt_id.as_str()
                        == prior_delivery.attempt_id.as_str()
                    && closure.context_view.view.binding.scope_id == prior_delivery.scope_id
                    && closure.context_view.view.binding.state_fence == prior_delivery.state_fence
            })
    });
    if !has_current_delivery {
        return Err(ContextPublicationError::MissingCurrentDelivery);
    }
    Ok(())
}

fn document_digest(document: &ContextSourceDocument) -> Result<String, ContextPublicationError> {
    let bytes = match document {
        ContextSourceDocument::Recipe(body) => canonical_json_bytes(body),
        ContextSourceDocument::Delivery(snapshot) => canonical_json_bytes(snapshot),
    }
    .map_err(|error| ContextPublicationError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}
