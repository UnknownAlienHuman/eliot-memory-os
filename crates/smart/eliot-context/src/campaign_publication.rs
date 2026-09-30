//! Owner-derived immutable publications used by the campaign source boundary.
//!
//! These values are deliberately store-neutral. They carry closed typed owner
//! bodies and metadata derived from those bodies; the authenticated Kernel
//! publication path remains responsible for admitting and persisting them.

use eliot_context_candidates::{CandidatePolicy, CandidateRequest};
use eliot_context_contracts::{
    ApprovedRecipeCatalogue, RecipeResolutionRefusal, AssemblyPolicy, ContextError as ContractContextError, ContextRecipe, PacketAdmissionParts,
    QualityScorecard, ReactiveInputError, SessionDeliverySnapshot,
};
use eliot_contracts::{ArtifactId, StateFence, canonical_json_bytes, sha256_hex};
use eliot_context_measurement::{MeasurementParams, measure_exact_utf8};
use eliot_learning_contracts::{CampaignOwnerRecordId, CampaignOwnerRevision, CampaignSourceRole};
use eliot_protocol::ReactiveContextStage;
use schemars::JsonSchema;
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

/// Current Context Compiler owner recipe configuration, the recipe identity it
/// resolves, and the exact compiler input admitted for it.
///
/// The three members are the three revisions I12.13 and #1724 keep apart:
/// `catalogue` is the owner-published configuration from which exactly one
/// applicable approved policy revision is resolved, `recipe` is the
/// compilation-bound instance that carries the task/attempt/scope/fence binding
/// and the task revision, and `compiler_input` is the admitted input for that
/// one compilation. The catalogue is a required member, not a defaulted one: a
/// body published without it is refused rather than read as an instance that
/// was compiled under no approved recipe configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextCampaignRecipeBody {
    /// Owner recipe configuration this instance is resolved from.
    pub catalogue: ApprovedRecipeCatalogue,
    /// Exact rich immutable `ContextRecipe` policy instance.
    pub recipe: ContextRecipe,
    /// Current admitted Context input used by the compiler for this recipe.
    pub compiler_input: ContextInput,
    /// Original typed suppliers for the native packet compiler. Legacy source
    /// rows omit this field and therefore remain explicitly unavailable for a
    /// live compilation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compiler_suppliers: Option<ContextCompilerSupplierProfileV1>,
}

/// Versioned native owner inputs for one campaign Context compilation.
///
/// The exact profile is retained in the original ContextRecipe source and
/// mirrored by the ContextToolPolicy projection. Their existing named-read
/// receipts provide source provenance; this value does not create another
/// receipt or digest scheme.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextCompilerSupplierProfileV1 {
    /// Closed profile version, currently exactly `1`.
    pub schema_version: u32,
    /// Exact existing immutable learning-state view selected for this
    /// compilation. The authenticated named read validates its current
    /// task/scope/fence binding before the compiler consumes it.
    pub campaign_learning_state_view_id: ArtifactId,
    /// Original candidate request and identity.
    pub candidate_request: CandidateRequest,
    /// Native candidate bounds and serializer policy.
    pub candidate_policy: CandidatePolicy,
    /// Original floor, admission policy/rule and supplied closure records.
    pub admission_parts: PacketAdmissionParts,
    /// Original quality owner scorecard.
    pub quality_scorecard: QualityScorecard,
    /// Original assembly boundary and measurement policy.
    pub assembly_policy: AssemblyPolicy,
    /// Original exact-measurement owner parameters.
    pub measurement_params: MeasurementParams,
}

impl PartialEq for ContextCompilerSupplierProfileV1 {
    fn eq(&self, other: &Self) -> bool {
        self.schema_version == other.schema_version
            && self.campaign_learning_state_view_id == other.campaign_learning_state_view_id
            && self.candidate_request == other.candidate_request
            && self.candidate_policy == other.candidate_policy
            && self.admission_parts.floor == other.admission_parts.floor
            && self.admission_parts.priority == other.admission_parts.priority
            && self.admission_parts.rule == other.admission_parts.rule
            && self.admission_parts.measurement_profile
                == other.admission_parts.measurement_profile
            && self.admission_parts.supplied_omissions
                == other.admission_parts.supplied_omissions
            && self.admission_parts.measurements == other.admission_parts.measurements
            && self.quality_scorecard == other.quality_scorecard
            && self.assembly_policy == other.assembly_policy
            && self.measurement_params == other.measurement_params
    }
}

impl Eq for ContextCompilerSupplierProfileV1 {}

impl ContextCompilerSupplierProfileV1 {
    /// Validate intrinsic supplier contracts and their exact recipe binding.
    pub fn validate_for_recipe(
        &self,
        recipe: &ContextRecipe,
    ) -> Result<(), ContextPublicationError> {
        if self.schema_version != 1 {
            return Err(ContextPublicationError::CompilerSupplierInvalid);
        }
        if ArtifactId::new(self.campaign_learning_state_view_id.as_str().to_owned()).is_err() {
            return Err(ContextPublicationError::CompilerSupplierInvalid);
        }
        self.candidate_request
            .validate()
            .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
        self.candidate_policy
            .validate()
            .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
        self.quality_scorecard
            .validate()
            .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
        self.assembly_policy
            .validate()
            .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
        self.measurement_params
            .validate()
            .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;

        let parts = &self.admission_parts;
        parts
            .floor
            .validate()
            .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
        parts
            .priority
            .validate()
            .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
        parts
            .rule
            .validate()
            .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
        parts
            .measurement_profile
            .validate()
            .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
        for omission in &parts.supplied_omissions {
            omission
                .validate(&recipe.binding)
                .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
        }
        for measurement in &parts.measurements {
            measurement
                .validate()
                .map_err(|_| ContextPublicationError::CompilerSupplierInvalid)?;
            if measurement.binding.context != recipe.binding {
                return Err(ContextPublicationError::CompilerSupplierInvalid);
            }
        }

        if self.candidate_request.binding != recipe.binding
            || self.quality_scorecard.binding != recipe.binding
            || self.measurement_params.context != recipe.binding
            || parts.floor.decision.decision_id != recipe.binding.decision_id
            || parts.priority.decision.decision_id != recipe.binding.decision_id
            || parts.rule.decision.decision_id != recipe.binding.decision_id
            || self.assembly_policy.serializer_id != self.measurement_params.serializer_id
            || self.assembly_policy.serializer_version != self.measurement_params.serializer_version
            || self.assembly_policy.serializer_options_digest
                != self.measurement_params.serializer_options_digest
            || self.assembly_policy.route_id != self.measurement_params.route_id
            || self.assembly_policy.model_id != self.measurement_params.model_id
            || self.assembly_policy.max_serialized_bytes
                != self.measurement_params.max_serialized_bytes
            || self.assembly_policy.serializer_id != parts.measurement_profile.serializer_id
            || self.assembly_policy.serializer_version != parts.measurement_profile.serializer_version
            || self.assembly_policy.serializer_options_digest
                != parts.measurement_profile.serializer_options_digest
            || self.assembly_policy.route_id != parts.measurement_profile.route_id
            || self.assembly_policy.model_id != parts.measurement_profile.model_id
        {
            return Err(ContextPublicationError::CompilerSupplierInvalid);
        }
        Ok(())
    }

    /// Measure final serialized bytes using the supplied exact measurement
    /// parameters; no estimate or observation is manufactured here.
    pub fn measure(
        &self,
        payload: &[u8],
    ) -> Result<eliot_context_contracts::SerializedContextMeasurement, ContractContextError> {
        measure_exact_utf8(payload, &self.measurement_params)
    }
}

/// Typed versioned projection published by the ContextToolPolicy owner when
/// compilation suppliers are present.
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextToolPolicyProjectionV1 {
    /// Projection schema version, currently exactly `1`.
    pub schema_version: u32,
    /// Exact recipe mirrored from the ContextRecipe owner read.
    pub recipe: ContextRecipe,
    /// Exact original compiler supplier profile.
    pub compiler_suppliers: ContextCompilerSupplierProfileV1,
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
    /// Exactly one applicable approved recipe could not be resolved from the
    /// owner catalogue. The typed refusal is preserved rather than collapsed
    /// into a generic invalid-recipe answer.
    #[error("Context recipe resolution refused: {0}")]
    Resolution(#[from] RecipeResolutionRefusal),
    /// The real source data does not bind to the admitted recipe.
    #[error("Context source does not bind field {field}")]
    BindingMismatch { field: &'static str },
    /// A compiler supplier profile failed its native boundary validation.
    #[error("Context compiler supplier profile is invalid or does not bind to its recipe")]
    CompilerSupplierInvalid,
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

/// Build the exact campaign source for an admitted current `ContextRecipe`, the
/// owner recipe configuration it is resolved from, and its compiler input. This
/// publication is available before Context view compilation and therefore does
/// not depend on a later delivery.
///
/// #1724 W2: exactly one applicable approved recipe is resolved from the owner
/// catalogue before anything is published. An ambiguous, unrevoked-but-
/// inapplicable or stale candidate set returns the typed
/// [`RecipeResolutionRefusal`]; there is no first-match and no fallback.
/// W3: the resolved revision is then validated against the catalogue's
/// independent governing requirements, and against the instance through
/// `binds_recipe`, which compares the policy's own recorded digest with the
/// digest the instance recorded in its `DecisionRevision`.
pub fn context_recipe_publication(
    recipe: &ContextRecipe,
    catalogue: &ApprovedRecipeCatalogue,
    compiler_input: &ContextInput,
) -> Result<ContextSourcePublication, ContextPublicationError> {
    context_recipe_publication_with_compiler_suppliers(recipe, catalogue, compiler_input, None)
}

/// Build the exact campaign source for an admitted recipe, compiler input, and
/// optional original typed supplier profile.
pub fn context_recipe_publication_with_compiler_suppliers(
    recipe: &ContextRecipe,
    catalogue: &ApprovedRecipeCatalogue,
    compiler_input: &ContextInput,
    compiler_suppliers: Option<&ContextCompilerSupplierProfileV1>,
) -> Result<ContextSourcePublication, ContextPublicationError> {
    let resolved = catalogue.resolve()?;
    catalogue.governing.authorize(&resolved, recipe)?;
    recipe.validate()?;
    compiler_input.validate()?;
    validate_recipe_input_binding(recipe, compiler_input)?;
    if let Some(suppliers) = compiler_suppliers {
        suppliers.validate_for_recipe(recipe)?;
    }

    let document = ContextSourceDocument::Recipe(Box::new(ContextCampaignRecipeBody {
        catalogue: catalogue.clone(),
        recipe: recipe.clone(),
        compiler_input: compiler_input.clone(),
        compiler_suppliers: compiler_suppliers.cloned(),
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

/// Compute the canonical digest of the exact current catalogue, recipe and input.
///
/// The resolution is re-derived from the catalogue on every consumption rather
/// than read from the stored body, so an altered, revoked, stale or ambiguous
/// owner configuration refuses here exactly as it does at publication.
pub fn context_recipe_body_digest(
    body: &ContextCampaignRecipeBody,
) -> Result<String, ContextPublicationError> {
    let resolved = body.catalogue.resolve()?;
    body.catalogue
        .governing
        .authorize(&resolved, &body.recipe)?;
    body.compiler_input.validate()?;
    validate_recipe_input_binding(&body.recipe, &body.compiler_input)?;
    if let Some(suppliers) = &body.compiler_suppliers {
        suppliers.validate_for_recipe(&body.recipe)?;
    }
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
