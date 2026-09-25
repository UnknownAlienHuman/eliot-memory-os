//! Product-evaluation owner publication adapter for campaign sources.
//!
//! The report builder remains the authority. This module only serializes the
//! exact plan/policy/report values returned by that builder into the closed
//! campaign-source carrier; it never invents an evaluator row or a report.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence};
use eliot_learning_contracts::{
    CampaignOwnerRecordId, CampaignOwnerRevision, CampaignSourceRole, OwnerId,
};
use eliot_product_evaluation::{
    ProductEvaluationCampaignDocument, ProductEvaluationCampaignPublication,
    ProductEvaluationCampaignPublications, ProductEvaluationError,
};
use eliot_store_api::{
    CampaignSourceDocument, CampaignSourceDocumentSchema, CampaignSourcePublication,
    CampaignSourcePublisher, CampaignSourceRecord,
};

fn owner_id() -> Result<OwnerId, ProductEvaluationError> {
    Ok(OwnerId::from_artifact(
        ArtifactId::new("owner:eliot-instrument/product-evaluation".to_owned()).map_err(|_| {
            ProductEvaluationError::InvalidText {
                field: "campaign.evaluation.owner",
            }
        })?,
    ))
}

fn publication_for(
    role: CampaignSourceRole,
    publisher: CampaignSourcePublisher,
    source: &ProductEvaluationCampaignPublication,
    required_references: Vec<ArtifactId>,
) -> Result<CampaignSourcePublication, ProductEvaluationError> {
    let schema = match source.document() {
        ProductEvaluationCampaignDocument::EvaluatorContract(_) => {
            CampaignSourceDocumentSchema::EvaluatorContract
        }
        ProductEvaluationCampaignDocument::EvaluatorHoldout(_) => {
            CampaignSourceDocumentSchema::EvaluatorHoldout
        }
        ProductEvaluationCampaignDocument::EvaluationResults(_) => {
            CampaignSourceDocumentSchema::EvaluationResults
        }
    };
    let record = CampaignSourceRecord::new(
        role,
        owner_id()?,
        CampaignOwnerRecordId::Contract(source.record_id().clone()),
        CampaignOwnerRevision::ResourceSnapshot(source.revision().to_owned()),
        source.recorded_state_fence().clone(),
        Vec::new(),
        Vec::new(),
        required_references,
        Vec::new(),
        Vec::new(),
        CampaignSourceDocument {
            schema,
            schema_version: CampaignSourceDocument::SCHEMA_VERSION,
            body: source.body_value()?,
        },
    )
    .map_err(|error| ProductEvaluationError::Serialization(error.to_string()))?;
    let publication = CampaignSourcePublication::from_observed_head(
        publisher,
        record,
        None,
        source.recorded_state_fence(),
    )
    .map_err(|error| ProductEvaluationError::Serialization(error.to_string()))?;
    Ok(publication)
}

/// Convert the three exact rows emitted by the real product-evaluation report
/// builder into owner-bound campaign publications.
pub fn build_product_evaluation_publications(
    publications: &ProductEvaluationCampaignPublications,
    state_fence: &StateFence,
) -> Result<Vec<CampaignSourcePublication>, ProductEvaluationError> {
    publications.validate_for_state_fence(state_fence)?;
    let report = publications.report();
    let required_references = report
        .evidence_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    Ok(vec![
        publication_for(
            CampaignSourceRole::EvaluatorContract,
            CampaignSourcePublisher::ProductEvaluatorContract,
            publications.evaluator_contract(),
            Vec::new(),
        )?,
        publication_for(
            CampaignSourceRole::EvaluatorHoldout,
            CampaignSourcePublisher::ProductEvaluatorHoldout,
            publications.evaluator_holdout(),
            Vec::new(),
        )?,
        publication_for(
            CampaignSourceRole::EvaluationResults,
            CampaignSourcePublisher::ProductEvaluationResults,
            publications.evaluation_results(),
            required_references,
        )?,
    ])
}
