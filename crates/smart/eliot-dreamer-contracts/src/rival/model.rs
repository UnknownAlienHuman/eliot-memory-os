//! Shared identity and availability bindings for retained rival declarations.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::{
    AssumptionRecord, CausalClaim, ConflictSet, CoverageDenominator, CoverageReceipt,
    CurrentEpistemicPosition, LineageRootId, PositionId, PositionRevision, PropositionId,
    ProvenanceClosure, SupportRecord, TemporalRecord, ValidityBounds,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::ContractViolation;
use crate::grounding::{AuthorizedReference, MaterialClaim, PrecisionPayload};

use super::prediction::RivalPrediction;
use super::validation;

/// Exact identity binding for one retained rival-model declaration.
///
/// The model revision is the declaration's own positive revision number. It
/// is deliberately separate from source revisions, contract revisions, and
/// epistemic-position revisions.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RivalModelRef {
    /// Stable artifact identity of the model declaration.
    pub model_id: ArtifactId,
    /// Positive revision owned by the model declaration.
    pub model_revision: u64,
    /// Digest of the exact retained declaration bytes/preimage supplied by its owner.
    pub declaration_digest: String,
}

impl RivalModelRef {
    /// Validates the reference without resolving the retained declaration.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::artifact(&self.model_id, "rival.model_ref.model_id")?;
        if self.model_revision == 0 {
            return Err(ContractViolation::OutOfBounds {
                field: "rival.model_ref.model_revision",
                min: 1,
                max: i64::MAX,
                got: 0,
            });
        }
        validation::digest(
            &self.declaration_digest,
            "rival.model_ref.declaration_digest",
        )
    }
}

/// Exact identity binding for one retained [`super::prediction::RivalPrediction`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RivalPredictionRef {
    /// Stable artifact identity of the prediction declaration.
    pub prediction_id: ArtifactId,
    /// Digest frozen by the prediction declaration owner.
    pub prediction_digest: String,
}

impl RivalPredictionRef {
    /// Builds a reference from a prediction that has already passed its owner validation.
    pub fn from_prediction(
        prediction: &super::prediction::RivalPrediction,
    ) -> Result<Self, ContractViolation> {
        validation::preflight(prediction)?;
        prediction.validate()?;
        let reference = Self {
            prediction_id: prediction.prediction_id.clone(),
            prediction_digest: prediction.digest.clone(),
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validates the reference without resolving the retained prediction.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::artifact(&self.prediction_id, "rival.prediction_ref.prediction_id")?;
        validation::digest(
            &self.prediction_digest,
            "rival.prediction_ref.prediction_digest",
        )
    }
}

/// Exact reference to one retained [`MaterialClaim`] payload.
///
/// The digest is the canonical owner-provided claim preimage digest. The
/// existing [`MaterialClaim::computed_digest`] binds its typed precision
/// payload, proposed support and counterevidence, component digests, screen
/// binding, claim identity, and proposition. It is a consistency binding only;
/// it does not authenticate the claim owner or admit the claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterialClaimRef {
    /// Stable identity from the retained material claim.
    pub claim_id: String,
    /// Proposition identity from the retained material claim.
    pub proposition: PropositionId,
    /// Existing owner digest of the complete claim preimage.
    pub claim_preimage_digest: String,
}

impl MaterialClaimRef {
    /// Builds an exact reference after validating the owner-provided full-claim digest.
    pub fn from_claim(claim: &MaterialClaim) -> Result<Self, ContractViolation> {
        claim.preflight_bytes()?;
        claim.validate()?;
        let reference = Self {
            claim_id: claim.claim_id.clone(),
            proposition: claim.proposition.clone(),
            claim_preimage_digest: claim.source_preimage_digest.clone(),
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validates the reference shape without resolving its external payload.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::text(&self.claim_id, "rival.claim_ref.claim_id")?;
        validation::text(self.proposition.as_str(), "rival.claim_ref.proposition")?;
        validation::digest(
            &self.claim_preimage_digest,
            "rival.claim_ref.claim_preimage_digest",
        )
    }

    /// Checks this reference against the exact retained claim payload.
    pub fn validate_against(&self, claim: &MaterialClaim) -> Result<(), ContractViolation> {
        self.validate()?;
        claim.preflight_bytes()?;
        claim.validate()?;
        if self.claim_id != claim.claim_id || self.proposition != claim.proposition {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.claim_ref.identity",
                reason: "claim identity differs from the retained MaterialClaim".to_owned(),
            });
        }
        if self.claim_preimage_digest.as_str() != claim.source_preimage_digest.as_str() {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.claim_ref.claim_preimage_digest",
                reason: "reference does not bind the complete retained MaterialClaim".to_owned(),
            });
        }
        Ok(())
    }
}

/// Supplied material claim declarations, or an explicit absence of such data.
///
/// `Supplied { claims: [] }` is an explicit empty list. It does not claim
/// completeness, independence, or that no further claims exist.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ClaimDeclarations {
    /// Retained claim references in meaningful declaration order.
    Supplied { claims: Vec<MaterialClaimRef> },
    /// Claim declarations were relevant but unavailable.
    Unknown { reason: String },
    /// Claim declarations do not apply to this carrier.
    NotApplicable { reason: String },
}

impl ClaimDeclarations {
    /// Validates bounded shape and same-identity consistency without resolving claims.
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Supplied { claims } => validate_claim_refs(claims, field),
            Self::Unknown { reason } | Self::NotApplicable { reason } => {
                validation::text(reason, field)
            }
        }
    }
}

fn validate_claim_refs(
    claims: &[MaterialClaimRef],
    field: &'static str,
) -> Result<(), ContractViolation> {
    validation::sequence(claims.len(), field)?;
    for (index, claim) in claims.iter().enumerate() {
        claim.validate()?;
        for prior in &claims[..index] {
            if prior.claim_id == claim.claim_id
                && (prior.proposition != claim.proposition
                    || prior.claim_preimage_digest != claim.claim_preimage_digest)
            {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: "one claim identity has conflicting proposition or digest".to_owned(),
                });
            }
        }
    }
    Ok(())
}

/// Supplied consistency binding to an admitted epistemic-position view.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CurrentPositionBinding {
    /// Exact position identity read from the owner view.
    pub position_id: PositionId,
    /// Exact position revision read from the owner view.
    pub position_revision: PositionRevision,
    /// Digest of the exact owner view.
    pub view_digest: String,
}

impl CurrentPositionBinding {
    /// Builds a binding from a validated owner view; it performs no admission or issuance.
    pub fn from_view(view: &CurrentEpistemicPosition) -> Result<Self, ContractViolation> {
        validation::preflight(view)?;
        view.validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "rival.current_position",
                reason: error.to_string(),
            })?;
        let (position_id, position_revision) = view.position_identity();
        let binding = Self {
            position_id: position_id.clone(),
            position_revision,
            view_digest: view.digest.clone(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates the supplied binding against the exact owner view.
    pub fn validate_against(
        &self,
        view: &CurrentEpistemicPosition,
    ) -> Result<(), ContractViolation> {
        self.validate()?;
        validation::preflight(view)?;
        view.validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "rival.current_position",
                reason: error.to_string(),
            })?;
        let (position_id, position_revision) = view.position_identity();
        if &self.position_id != position_id || self.position_revision != position_revision {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.current_position.identity",
                reason: "position identity or revision differs from the owner view".to_owned(),
            });
        }
        if self.view_digest.as_str() != view.digest.as_str() {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.current_position.view_digest",
                reason: "view digest differs from the owner view".to_owned(),
            });
        }
        Ok(())
    }

    /// Validates the binding without resolving its owner view.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::text(
            self.position_id.as_str(),
            "rival.current_position.position_id",
        )?;
        if self.position_revision.value() == 0 {
            return Err(ContractViolation::OutOfBounds {
                field: "rival.current_position.position_revision",
                min: 1,
                max: i64::MAX,
                got: 0,
            });
        }
        validation::digest(&self.view_digest, "rival.current_position.view_digest")
    }
}

/// Supplied, unavailable, or inapplicable current-position evidence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CurrentPositionAvailability {
    /// Supplied consistency binding; it does not prove currentness or authenticity.
    Referenced { binding: CurrentPositionBinding },
    /// A position was relevant but unavailable.
    Unknown {
        position_id: Option<PositionId>,
        position_revision: Option<PositionRevision>,
        view_digest: Option<String>,
        reason: String,
    },
    /// No current-position view applies to this declaration.
    NotApplicable { reason: String },
}

impl CurrentPositionAvailability {
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Referenced { binding } => binding.validate(),
            Self::Unknown {
                position_id,
                position_revision,
                view_digest,
                reason,
            } => {
                if let Some(position_id) = position_id {
                    validation::text(position_id.as_str(), field)?;
                }
                if let Some(position_revision) = position_revision
                    && position_revision.value() == 0
                {
                    return Err(ContractViolation::OutOfBounds {
                        field,
                        min: 1,
                        max: i64::MAX,
                        got: 0,
                    });
                }
                if let Some(view_digest) = view_digest {
                    validation::digest(view_digest, field)?;
                }
                validation::text(reason, field)
            }
            Self::NotApplicable { reason } => validation::text(reason, field),
        }
    }
}

/// Supplied source/provenance closure, or explicit unavailability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum SuppliedLineage {
    /// Retained provenance closure; source and record domains remain owner-defined.
    Retained { closure: Box<ProvenanceClosure> },
    /// The lineage was relevant but unavailable.
    Unknown {
        closure_digest: Option<String>,
        reason: String,
    },
}

impl SuppliedLineage {
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Retained { closure } => {
                closure
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field,
                        reason: error.to_string(),
                    })
            }
            Self::Unknown {
                closure_digest,
                reason,
            } => {
                if let Some(digest) = closure_digest {
                    validation::digest(digest, field)?;
                }
                validation::text(reason, field)
            }
        }
    }
}

/// Supplied common-lineage disclosure, without an independence verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum CommonModeDisclosure {
    /// Lineage roots disclosed as a possible common mode, with supporting claims.
    Supplied {
        lineage_roots: BTreeSet<LineageRootId>,
        basis: ClaimDeclarations,
    },
    /// Common mode could not be established.
    Unknown { reason: String },
}

impl CommonModeDisclosure {
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Supplied {
                lineage_roots,
                basis,
            } => {
                validation::sequence(lineage_roots.len(), field)?;
                if lineage_roots.is_empty() {
                    return Err(ContractViolation::MissingField(field));
                }
                for root in lineage_roots {
                    validation::text(root.as_str(), field)?;
                }
                basis.validate("rival.common_mode.basis")
            }
            Self::Unknown { reason } => validation::text(reason, field),
        }
    }
}

/// Five-role temporal evidence carrier for a model declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum TemporalAvailability {
    /// Supplied temporal record; event/effective/observation/ingestion/commit remain distinct.
    Supplied { temporal: TemporalRecord },
    /// Temporal evidence was relevant but unavailable.
    Unknown { reason: String },
}

impl TemporalAvailability {
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Supplied { temporal } => {
                temporal
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field,
                        reason: error.to_string(),
                    })
            }
            Self::Unknown { reason } => validation::text(reason, field),
        }
    }
}

/// One provider-neutral retained dependency of a model declaration.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RivalDependency {
    /// A previous model declaration, bound by its exact identity tuple.
    Model { reference: RivalModelRef },
    /// An immutable retained record owned outside the rival-model contract.
    Record {
        /// Stable identity of the retained record.
        record_id: ArtifactId,
        /// Digest of the exact retained record content.
        content_digest: String,
        /// Revision supplied by the record owner.
        source_revision: String,
    },
}

impl RivalDependency {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Model { reference } => reference.validate(),
            Self::Record {
                record_id,
                content_digest,
                source_revision,
            } => {
                validation::artifact(record_id, "rival.dependency.record_id")?;
                validation::digest(content_digest, "rival.dependency.content_digest")?;
                validation::text(source_revision, "rival.dependency.source_revision")
            }
        }
    }
}

/// Availability of an ordered declaration collection owned by a later resolver.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DeclarationAvailability<T> {
    /// Supplied entries in meaningful declaration order.
    Supplied { entries: Vec<T> },
    /// Entries were relevant but unavailable.
    Unknown { reason: String },
    /// Entries do not apply to this declaration.
    NotApplicable { reason: String },
}

impl<T: Serialize> DeclarationAvailability<T> {
    fn validate_with<F>(
        &self,
        field: &'static str,
        mut validate_entry: F,
    ) -> Result<(), ContractViolation>
    where
        F: FnMut(&T) -> Result<(), ContractViolation>,
    {
        validation::preflight(self)?;
        match self {
            Self::Supplied { entries } => {
                validation::sequence(entries.len(), field)?;
                for entry in entries {
                    validate_entry(entry)?;
                }
                Ok(())
            }
            Self::Unknown { reason } | Self::NotApplicable { reason } => {
                validation::text(reason, field)
            }
        }
    }
}

/// One immutable, provider-neutral rival model declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RivalModelDeclaration {
    /// Exact wire revision of this declaration.
    pub schema_version: u32,
    /// Stable identity of this frozen model declaration artifact.
    pub model_id: ArtifactId,
    /// Positive revision owned by the model declaration.
    pub model_revision: u64,
    /// Exact prior model declaration identities retained as history.
    pub predecessors: BTreeSet<RivalModelRef>,
    /// Task under which the declaration was supplied.
    pub task_id: TaskId,
    /// State fence under which the declaration was supplied.
    pub state_fence: StateFence,
    /// Scope, time, version, and precision under which the model applies.
    pub applicability: ValidityBounds,
    /// Bounded question the model addresses.
    pub question: String,
    /// Non-empty retained material explanations.
    pub explanations: Vec<MaterialClaimRef>,
    /// Assumption references retained by the declaration.
    pub assumptions: DeclarationAvailability<super::prediction::ConditionAssumptionRef>,
    /// Ordered prediction references; matching is a later owner concern.
    pub prediction_refs: DeclarationAvailability<RivalPredictionRef>,
    /// Ordered dependency declarations.
    pub dependency_refs: DeclarationAvailability<RivalDependency>,
    /// Supplied support observations, retaining the canonical owner records.
    pub support_observations: DeclarationAvailability<SupportRecord>,
    /// Supplied causal readings, retaining the canonical owner records.
    pub causal_readings: DeclarationAvailability<CausalClaim>,
    /// Supplied conflict records; analysis remains a separate owner.
    pub conflicts: DeclarationAvailability<ConflictSet>,
    /// Claims supporting transfer, invalidation, and downstream declarations.
    pub supporting_claims: ClaimDeclarations,
    pub counterevidence_claims: ClaimDeclarations,
    pub revision_conditions: ClaimDeclarations,
    pub invalidation_conditions: ClaimDeclarations,
    pub successful_transfers: ClaimDeclarations,
    pub failed_transfers: ClaimDeclarations,
    pub downstream_effects: ClaimDeclarations,
    /// Supplied epistemic-position consistency binding or explicit absence.
    pub current_position: CurrentPositionAvailability,
    /// Five-role temporal carrier or explicit absence.
    pub temporal: TemporalAvailability,
    /// Supplied source/provenance closure or explicit absence.
    pub lineage: SuppliedLineage,
    /// Supplied possible common mode or explicit absence.
    pub common_mode: CommonModeDisclosure,
    /// Unresolved bounded residue; absence is never interpreted as certainty.
    pub unresolved: BTreeSet<String>,
    /// Canonical digest of this declaration, excluding this field.
    pub digest: String,
}

/// Named constructor arguments for [`RivalModelDeclaration::new`].
#[derive(Clone, Debug)]
pub struct RivalModelDeclarationParams {
    pub model_id: ArtifactId,
    pub model_revision: u64,
    pub predecessors: BTreeSet<RivalModelRef>,
    pub task_id: TaskId,
    pub state_fence: StateFence,
    pub applicability: ValidityBounds,
    pub question: String,
    pub explanations: Vec<MaterialClaimRef>,
    pub assumptions: DeclarationAvailability<super::prediction::ConditionAssumptionRef>,
    pub prediction_refs: DeclarationAvailability<RivalPredictionRef>,
    pub dependency_refs: DeclarationAvailability<RivalDependency>,
    pub support_observations: DeclarationAvailability<SupportRecord>,
    pub causal_readings: DeclarationAvailability<CausalClaim>,
    pub conflicts: DeclarationAvailability<ConflictSet>,
    pub supporting_claims: ClaimDeclarations,
    pub counterevidence_claims: ClaimDeclarations,
    pub revision_conditions: ClaimDeclarations,
    pub invalidation_conditions: ClaimDeclarations,
    pub successful_transfers: ClaimDeclarations,
    pub failed_transfers: ClaimDeclarations,
    pub downstream_effects: ClaimDeclarations,
    pub current_position: CurrentPositionAvailability,
    pub temporal: TemporalAvailability,
    pub lineage: SuppliedLineage,
    pub common_mode: CommonModeDisclosure,
    pub unresolved: BTreeSet<String>,
}

pub const RIVAL_MODEL_SCHEMA_VERSION: u32 = 1;

impl RivalModelDeclaration {
    /// Constructs and freezes an intrinsically validated declaration.
    pub fn new(params: RivalModelDeclarationParams) -> Result<Self, ContractViolation> {
        let mut declaration = Self {
            schema_version: RIVAL_MODEL_SCHEMA_VERSION,
            model_id: params.model_id,
            model_revision: params.model_revision,
            predecessors: params.predecessors,
            task_id: params.task_id,
            state_fence: params.state_fence,
            applicability: params.applicability,
            question: params.question,
            explanations: params.explanations,
            assumptions: params.assumptions,
            prediction_refs: params.prediction_refs,
            dependency_refs: params.dependency_refs,
            support_observations: params.support_observations,
            causal_readings: params.causal_readings,
            conflicts: params.conflicts,
            supporting_claims: params.supporting_claims,
            counterevidence_claims: params.counterevidence_claims,
            revision_conditions: params.revision_conditions,
            invalidation_conditions: params.invalidation_conditions,
            successful_transfers: params.successful_transfers,
            failed_transfers: params.failed_transfers,
            downstream_effects: params.downstream_effects,
            current_position: params.current_position,
            temporal: params.temporal,
            lineage: params.lineage,
            common_mode: params.common_mode,
            unresolved: params.unresolved,
            digest: String::new(),
        };
        validation::preflight(&declaration)?;
        declaration.validate_content()?;
        declaration.digest = declaration.compute_digest()?;
        validation::preflight(&declaration)?;
        Ok(declaration)
    }

    /// Validates the complete declaration and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_content()?;
        validation::digest(&self.digest, "rival.model.digest")?;
        let expected = self.compute_digest()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.model.digest",
                reason: "model digest does not match its declaration".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the declaration digest after bounded intrinsic validation.
    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            model_id: &'a ArtifactId,
            model_revision: u64,
            predecessors: &'a BTreeSet<RivalModelRef>,
            task_id: &'a TaskId,
            state_fence: &'a StateFence,
            applicability: &'a ValidityBounds,
            question: &'a str,
            explanations: &'a [MaterialClaimRef],
            assumptions: &'a DeclarationAvailability<super::prediction::ConditionAssumptionRef>,
            prediction_refs: &'a DeclarationAvailability<RivalPredictionRef>,
            dependency_refs: &'a DeclarationAvailability<RivalDependency>,
            support_observations: &'a DeclarationAvailability<SupportRecord>,
            causal_readings: &'a DeclarationAvailability<CausalClaim>,
            conflicts: &'a DeclarationAvailability<ConflictSet>,
            supporting_claims: &'a ClaimDeclarations,
            counterevidence_claims: &'a ClaimDeclarations,
            revision_conditions: &'a ClaimDeclarations,
            invalidation_conditions: &'a ClaimDeclarations,
            successful_transfers: &'a ClaimDeclarations,
            failed_transfers: &'a ClaimDeclarations,
            downstream_effects: &'a ClaimDeclarations,
            current_position: &'a CurrentPositionAvailability,
            temporal: &'a TemporalAvailability,
            lineage: &'a SuppliedLineage,
            common_mode: &'a CommonModeDisclosure,
            unresolved: &'a BTreeSet<String>,
        }
        validation::preflight(self)?;
        self.validate_content()?;
        validation::canonical_digest(&Preimage {
            schema_version: self.schema_version,
            model_id: &self.model_id,
            model_revision: self.model_revision,
            predecessors: &self.predecessors,
            task_id: &self.task_id,
            state_fence: &self.state_fence,
            applicability: &self.applicability,
            question: &self.question,
            explanations: &self.explanations,
            assumptions: &self.assumptions,
            prediction_refs: &self.prediction_refs,
            dependency_refs: &self.dependency_refs,
            support_observations: &self.support_observations,
            causal_readings: &self.causal_readings,
            conflicts: &self.conflicts,
            supporting_claims: &self.supporting_claims,
            counterevidence_claims: &self.counterevidence_claims,
            revision_conditions: &self.revision_conditions,
            invalidation_conditions: &self.invalidation_conditions,
            successful_transfers: &self.successful_transfers,
            failed_transfers: &self.failed_transfers,
            downstream_effects: &self.downstream_effects,
            current_position: &self.current_position,
            temporal: &self.temporal,
            lineage: &self.lineage,
            common_mode: &self.common_mode,
            unresolved: &self.unresolved,
        })
    }

    fn validate_content(&self) -> Result<(), ContractViolation> {
        if self.schema_version != RIVAL_MODEL_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.model.schema_version",
                reason: "unsupported rival model schema revision".to_owned(),
            });
        }
        self.validate_shallow()
    }

    fn validate_shallow(&self) -> Result<(), ContractViolation> {
        validation::artifact(&self.model_id, "rival.model.model_id")?;
        if self.model_revision == 0 {
            return Err(ContractViolation::OutOfBounds {
                field: "rival.model.model_revision",
                min: 1,
                max: i64::MAX,
                got: 0,
            });
        }
        validation::text(self.task_id.as_str(), "rival.model.task_id")?;
        self.state_fence
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "rival.model.state_fence",
                reason: error.to_string(),
            })?;
        self.applicability
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "rival.model.applicability",
                reason: error.to_string(),
            })?;
        validation::text(&self.question, "rival.model.question")?;
        validation::sequence(self.explanations.len(), "rival.model.explanations")?;
        if self.explanations.is_empty() {
            return Err(ContractViolation::MissingField("rival.model.explanations"));
        }
        validation::sequence(self.predecessors.len(), "rival.model.predecessors")?;
        self.validate_work_budget()?;
        for predecessor in &self.predecessors {
            predecessor.validate()?;
        }
        validate_claim_refs(&self.explanations, "rival.model.explanations")?;
        self.validate_declarations()?;
        self.validate_owner_records()
    }

    fn validate_declarations(&self) -> Result<(), ContractViolation> {
        self.assumptions.validate_with(
            "rival.model.assumptions",
            super::prediction::ConditionAssumptionRef::validate,
        )?;
        self.prediction_refs
            .validate_with("rival.model.prediction_refs", RivalPredictionRef::validate)?;
        self.dependency_refs
            .validate_with("rival.model.dependency_refs", RivalDependency::validate)?;
        self.support_observations
            .validate_with("rival.model.support_observations", |_| Ok(()))?;
        self.causal_readings
            .validate_with("rival.model.causal_readings", |_| Ok(()))?;
        self.conflicts
            .validate_with("rival.model.conflicts", |_| Ok(()))?;
        self.supporting_claims
            .validate("rival.model.supporting_claims")?;
        self.counterevidence_claims
            .validate("rival.model.counterevidence_claims")?;
        self.revision_conditions
            .validate("rival.model.revision_conditions")?;
        self.invalidation_conditions
            .validate("rival.model.invalidation_conditions")?;
        self.successful_transfers
            .validate("rival.model.successful_transfers")?;
        self.failed_transfers
            .validate("rival.model.failed_transfers")?;
        self.downstream_effects
            .validate("rival.model.downstream_effects")?;
        self.current_position
            .validate("rival.model.current_position")?;
        self.temporal.validate("rival.model.temporal")?;
        self.lineage.validate("rival.model.lineage")?;
        self.common_mode.validate("rival.model.common_mode")?;
        validation::sequence(self.unresolved.len(), "rival.model.unresolved")?;
        for unresolved in &self.unresolved {
            validation::text(unresolved, "rival.model.unresolved")?;
        }
        self.validate_reference_consistency()
    }

    fn validate_owner_records(&self) -> Result<(), ContractViolation> {
        if let DeclarationAvailability::Supplied { entries } = &self.support_observations {
            for support in entries {
                support
                    .validate_for(
                        &self.task_id,
                        self.applicability.scope.as_str(),
                        &self.state_fence,
                    )
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "rival.model.support_observations",
                        reason: error.to_string(),
                    })?;
            }
        }
        if let DeclarationAvailability::Supplied { entries } = &self.causal_readings {
            for causal in entries {
                causal
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "rival.model.causal_readings",
                        reason: error.to_string(),
                    })?;
                if causal.scope != self.applicability.scope {
                    return Err(ContractViolation::BindingMismatch {
                        field: "rival.model.causal_readings.scope",
                        reason: "causal reading scope differs from model applicability".to_owned(),
                    });
                }
                if !causal.fence.is_compatible_with(&self.state_fence) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "rival.model.causal_readings.fence",
                        reason: "causal reading fence is incompatible with model fence".to_owned(),
                    });
                }
            }
        }
        if let DeclarationAvailability::Supplied { entries } = &self.conflicts {
            for conflict in entries {
                conflict
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "rival.model.conflicts",
                        reason: error.to_string(),
                    })?;
                if conflict.scope != self.applicability.scope {
                    return Err(ContractViolation::BindingMismatch {
                        field: "rival.model.conflicts.scope",
                        reason: "conflict scope differs from model applicability".to_owned(),
                    });
                }
                if let Some(task_id) = &conflict.task_id
                    && task_id != &self.task_id
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "rival.model.conflicts.task_id",
                        reason: "conflict task differs from model task".to_owned(),
                    });
                }
            }
        }
        if let SuppliedLineage::Retained { closure } = &self.lineage {
            if closure.scope != self.applicability.scope {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.model.lineage.scope",
                    reason: "lineage scope differs from model applicability".to_owned(),
                });
            }
            if !closure.fence.is_compatible_with(&self.state_fence) {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.model.lineage.fence",
                    reason: "lineage fence is incompatible with model fence".to_owned(),
                });
            }
        }
        Ok(())
    }

    fn validate_reference_consistency(&self) -> Result<(), ContractViolation> {
        validate_predecessor_references(&self.predecessors)?;
        if let DeclarationAvailability::Supplied { entries } = &self.assumptions {
            for (index, assumption) in entries.iter().enumerate() {
                for prior in entries.iter().take(index) {
                    if prior.assumption_id == assumption.assumption_id
                        && prior.assumption_digest != assumption.assumption_digest
                    {
                        return Err(ContractViolation::BindingMismatch {
                            field: "rival.model.assumptions",
                            reason: "one assumption identity has conflicting digests".to_owned(),
                        });
                    }
                }
            }
        }
        if let DeclarationAvailability::Supplied { entries } = &self.prediction_refs {
            for (index, prediction) in entries.iter().enumerate() {
                for prior in entries.iter().take(index) {
                    if prior.prediction_id == prediction.prediction_id
                        && prior.prediction_digest != prediction.prediction_digest
                    {
                        return Err(ContractViolation::BindingMismatch {
                            field: "rival.model.prediction_refs",
                            reason: "one prediction identity has conflicting digests".to_owned(),
                        });
                    }
                }
            }
        }
        if let DeclarationAvailability::Supplied { entries } = &self.dependency_refs {
            for (index, dependency) in entries.iter().enumerate() {
                let (model, record) = match dependency {
                    RivalDependency::Model { reference } => (Some(reference), None),
                    RivalDependency::Record {
                        record_id,
                        content_digest,
                        source_revision,
                    } => (None, Some((record_id, content_digest, source_revision))),
                };
                for prior in entries.iter().take(index) {
                    match (model, record, prior) {
                        (Some(reference), _, RivalDependency::Model { reference: prior })
                            if prior.model_id == reference.model_id
                                && prior.model_revision == reference.model_revision
                                && prior.declaration_digest != reference.declaration_digest =>
                        {
                            return Err(ContractViolation::BindingMismatch {
                                field: "rival.model.dependency_refs",
                                reason: "one model dependency identity has conflicting digests"
                                    .to_owned(),
                            });
                        }
                        (
                            _,
                            Some((record_id, content_digest, source_revision)),
                            RivalDependency::Record {
                                record_id: prior_id,
                                content_digest: prior_digest,
                                source_revision: prior_revision,
                            },
                        ) if prior_id == record_id
                            && (prior_digest != content_digest
                                || prior_revision != source_revision) =>
                        {
                            return Err(ContractViolation::BindingMismatch {
                                field: "rival.model.dependency_refs",
                                reason: "one record dependency identity has conflicting content"
                                    .to_owned(),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
        if let DeclarationAvailability::Supplied { entries } = &self.conflicts {
            for (index, conflict) in entries.iter().enumerate() {
                for prior in entries.iter().take(index) {
                    if prior.conflict_id == conflict.conflict_id && prior.digest != conflict.digest
                    {
                        return Err(ContractViolation::BindingMismatch {
                            field: "rival.model.conflicts",
                            reason: "one conflict identity has conflicting digests".to_owned(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_work_budget(&self) -> Result<usize, ContractViolation> {
        let mut total = 0usize;
        add_work(&mut total, self.predecessors.len(), "rival.model.work")?;
        add_work(&mut total, self.explanations.len(), "rival.model.work")?;
        add_work(&mut total, self.unresolved.len(), "rival.model.work")?;
        count_availability(&self.assumptions, &mut total, "rival.model.work")?;
        count_availability(&self.prediction_refs, &mut total, "rival.model.work")?;
        count_availability(&self.dependency_refs, &mut total, "rival.model.work")?;
        count_support_availability(&self.support_observations, &mut total)?;
        count_causal_availability(&self.causal_readings, &mut total)?;
        count_conflict_availability(&self.conflicts, &mut total)?;
        for claims in [
            &self.supporting_claims,
            &self.counterevidence_claims,
            &self.revision_conditions,
            &self.invalidation_conditions,
            &self.successful_transfers,
            &self.failed_transfers,
            &self.downstream_effects,
        ] {
            count_claims(claims, &mut total, "rival.model.work")?;
        }
        if let SuppliedLineage::Retained { closure } = &self.lineage {
            count_collection(
                closure.records.len(),
                "rival.model.lineage.records",
                &mut total,
            )?;
            count_collection(
                closure.sources.len(),
                "rival.model.lineage.sources",
                &mut total,
            )?;
            count_collection(
                closure.raw_handles.len(),
                "rival.model.lineage.raw_handles",
                &mut total,
            )?;
            count_collection(
                closure.revisions.len(),
                "rival.model.lineage.revisions",
                &mut total,
            )?;
            count_collection(
                closure.lineage.len(),
                "rival.model.lineage.entries",
                &mut total,
            )?;
            count_collection(
                closure.record_origin.len(),
                "rival.model.lineage.record_origin",
                &mut total,
            )?;
            for entry in &closure.lineage {
                count_collection(
                    entry.predecessors.len(),
                    "rival.model.lineage.predecessors",
                    &mut total,
                )?;
            }
        }
        if let CommonModeDisclosure::Supplied {
            lineage_roots,
            basis,
        } = &self.common_mode
        {
            add_work(&mut total, lineage_roots.len(), "rival.model.work")?;
            count_claims(basis, &mut total, "rival.model.work")?;
        }
        Ok(total)
    }
}

impl RivalModelRef {
    /// Builds a reference from a model declaration that passed its owner validation.
    pub fn from_model(model: &RivalModelDeclaration) -> Result<Self, ContractViolation> {
        validation::preflight(model)?;
        model.validate()?;
        let reference = Self {
            model_id: model.model_id.clone(),
            model_revision: model.model_revision,
            declaration_digest: model.digest.clone(),
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validates this reference against the exact retained model declaration.
    pub fn validate_against(&self, model: &RivalModelDeclaration) -> Result<(), ContractViolation> {
        self.validate()?;
        validation::preflight(model)?;
        model.validate()?;
        if self.model_id != model.model_id || self.model_revision != model.model_revision {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.model_ref.identity",
                reason: "model identity or revision differs from the retained declaration"
                    .to_owned(),
            });
        }
        if self.declaration_digest.as_str() != model.digest.as_str() {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.model_ref.declaration_digest",
                reason: "reference does not bind the retained model declaration".to_owned(),
            });
        }
        Ok(())
    }
}

fn add_work(
    total: &mut usize,
    amount: usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    *total = total
        .checked_add(amount)
        .ok_or(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: crate::error::len_i64(super::validation::MAX_RIVAL_ITEMS),
            got: i64::MAX,
        })?;
    if *total > super::validation::MAX_RIVAL_ITEMS {
        return Err(ContractViolation::OutOfBounds {
            field,
            min: 0,
            max: crate::error::len_i64(super::validation::MAX_RIVAL_ITEMS),
            got: crate::error::len_i64(*total),
        });
    }
    Ok(())
}

fn count_availability<T: Serialize>(
    availability: &DeclarationAvailability<T>,
    total: &mut usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    if let DeclarationAvailability::Supplied { entries } = availability {
        validation::sequence(entries.len(), field)?;
        add_work(total, entries.len(), field)?;
    }
    Ok(())
}

fn count_collection(
    len: usize,
    field: &'static str,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    validation::sequence(len, field)?;
    add_work(total, len, "rival.model.work")
}

fn count_support_availability(
    availability: &DeclarationAvailability<SupportRecord>,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    if let DeclarationAvailability::Supplied { entries } = availability {
        count_collection(entries.len(), "rival.model.support_observations", total)?;
        for support in entries {
            count_collection(support.handles.len(), "rival.model.support.handles", total)?;
        }
    }
    Ok(())
}

fn count_causal_availability(
    availability: &DeclarationAvailability<CausalClaim>,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    if let DeclarationAvailability::Supplied { entries } = availability {
        count_collection(entries.len(), "rival.model.causal_readings", total)?;
        for causal in entries {
            count_collection(causal.rivals.len(), "rival.model.causal.rivals", total)?;
            count_collection(
                causal.confounders.len(),
                "rival.model.causal.confounders",
                total,
            )?;
            count_collection(
                causal.evidence_refs.len(),
                "rival.model.causal.evidence_refs",
                total,
            )?;
            count_collection(
                causal.source_lineage.predecessors.len(),
                "rival.model.causal.source_lineage.predecessors",
                total,
            )?;
        }
    }
    Ok(())
}

fn count_conflict_availability(
    availability: &DeclarationAvailability<ConflictSet>,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    if let DeclarationAvailability::Supplied { entries } = availability {
        count_collection(entries.len(), "rival.model.conflicts", total)?;
        for conflict in entries {
            count_collection(
                conflict.positions.len(),
                "rival.model.conflict.positions",
                total,
            )?;
            count_collection(
                conflict.evidence_refs.len(),
                "rival.model.conflict.evidence_refs",
                total,
            )?;
            count_collection(conflict.owners.len(), "rival.model.conflict.owners", total)?;
            count_collection(
                conflict.common_lineage.len(),
                "rival.model.conflict.common_lineage",
                total,
            )?;
            count_collection(
                conflict.resolved_parts.len(),
                "rival.model.conflict.resolved_parts",
                total,
            )?;
            count_collection(
                conflict.unresolved.len(),
                "rival.model.conflict.unresolved",
                total,
            )?;
            count_collection(
                conflict.unresolved_owners.len(),
                "rival.model.conflict.unresolved_owners",
                total,
            )?;
            count_collection(
                conflict.defeated_refs.len(),
                "rival.model.conflict.defeated_refs",
                total,
            )?;
            count_collection(
                conflict.affected_actions.len(),
                "rival.model.conflict.affected_actions",
                total,
            )?;
            for position in &conflict.positions {
                count_collection(
                    position.assumptions.len(),
                    "rival.model.conflict.assumptions",
                    total,
                )?;
                count_collection(
                    position.counters.len(),
                    "rival.model.conflict.counters",
                    total,
                )?;
            }
        }
    }
    Ok(())
}

fn validate_predecessor_references(
    predecessors: &BTreeSet<RivalModelRef>,
) -> Result<(), ContractViolation> {
    for (index, predecessor) in predecessors.iter().enumerate() {
        for prior in predecessors.iter().take(index) {
            if prior.model_id == predecessor.model_id
                && prior.model_revision == predecessor.model_revision
                && prior.declaration_digest != predecessor.declaration_digest
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.model.predecessors",
                    reason: "one predecessor identity has conflicting digests".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn count_claims(
    declarations: &ClaimDeclarations,
    total: &mut usize,
    field: &'static str,
) -> Result<(), ContractViolation> {
    if let ClaimDeclarations::Supplied { claims } = declarations {
        validation::sequence(claims.len(), field)?;
        add_work(total, claims.len(), "rival.model.work")?;
    }
    Ok(())
}

/// Wire revision for the retained rival declaration set carrier.
pub const RIVAL_DECLARATION_SET_SCHEMA_VERSION: u32 = 1;

/// One complete rival-model declaration, or an explicit unavailable slot.
///
/// This is a retained supplied-data table entry. It does not claim that the
/// declaration was admitted, executed, current, or authoritative.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RivalModelSlot {
    /// Full model declaration retained in this carrier.
    Retained {
        declaration: Box<RivalModelDeclaration>,
    },
    /// Model identity is known while its declaration payload is unavailable.
    Unavailable {
        model_id: ArtifactId,
        model_revision: Option<u64>,
        declaration_digest: Option<String>,
        reason: String,
    },
}

impl RivalModelSlot {
    /// Returns the supplied stable model artifact identity.
    pub fn stable_id(&self) -> &ArtifactId {
        match self {
            Self::Retained { declaration } => &declaration.model_id,
            Self::Unavailable { model_id, .. } => model_id,
        }
    }

    /// Validates slot shape and, when retained, the complete model owner value.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Retained { declaration } => declaration.validate(),
            Self::Unavailable {
                model_id,
                model_revision,
                declaration_digest,
                reason,
            } => {
                validation::artifact(model_id, "rival.model_slot.model_id")?;
                if let Some(revision) = model_revision
                    && *revision == 0
                {
                    return Err(ContractViolation::OutOfBounds {
                        field: "rival.model_slot.model_revision",
                        min: 1,
                        max: i64::MAX,
                        got: 0,
                    });
                }
                if let Some(digest) = declaration_digest {
                    validation::digest(digest, "rival.model_slot.declaration_digest")?;
                }
                validation::text(reason, "rival.model_slot.reason")
            }
        }
    }
}

/// One complete material claim, or an explicit unavailable claim slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RivalClaimSlot {
    /// Full typed material claim retained in this carrier.
    Retained { claim: Box<MaterialClaim> },
    /// Claim identity is known while its payload is unavailable.
    Unavailable {
        claim_id: String,
        proposition: Option<PropositionId>,
        claim_preimage_digest: Option<String>,
        reason: String,
    },
}

impl RivalClaimSlot {
    /// Returns the supplied stable claim identity.
    pub fn stable_id(&self) -> &str {
        match self {
            Self::Retained { claim } => claim.claim_id.as_str(),
            Self::Unavailable { claim_id, .. } => claim_id.as_str(),
        }
    }

    /// Validates slot shape and, when retained, the complete claim owner value.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Retained { claim } => {
                claim.preflight_bytes()?;
                claim.validate()
            }
            Self::Unavailable {
                claim_id,
                proposition,
                claim_preimage_digest,
                reason,
            } => {
                validation::text(claim_id, "rival.claim_slot.claim_id")?;
                if let Some(proposition) = proposition {
                    validation::text(proposition.as_str(), "rival.claim_slot.proposition")?;
                }
                if let Some(digest) = claim_preimage_digest {
                    validation::digest(digest, "rival.claim_slot.claim_preimage_digest")?;
                }
                validation::text(reason, "rival.claim_slot.reason")
            }
        }
    }

    pub fn validate_for_context(
        &self,
        task_id: &TaskId,
        scope: &str,
        fence: &StateFence,
    ) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Retained { claim } => {
                claim
                    .validate_for_context(task_id, scope, fence)
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "rival.claim_slot.claim",
                        reason: error.to_string(),
                    })
            }
            Self::Unavailable { .. } => self.validate(),
        }
    }
}

/// One complete assumption record, or an explicit unavailable assumption slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RivalAssumptionSlot {
    /// Full typed assumption record retained in this carrier.
    Retained { assumption: Box<AssumptionRecord> },
    /// Assumption identity is known while its payload is unavailable.
    Unavailable {
        assumption_id: String,
        assumption_digest: Option<String>,
        reason: String,
    },
}

impl RivalAssumptionSlot {
    /// Returns the supplied stable assumption identity.
    pub fn stable_id(&self) -> &str {
        match self {
            Self::Retained { assumption } => assumption.assumption_id.as_str(),
            Self::Unavailable { assumption_id, .. } => assumption_id.as_str(),
        }
    }

    /// Validates slot shape and, when retained, the complete assumption owner value.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Retained { assumption } => {
                validation::preflight(assumption)?;
                assumption
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "rival.assumption_slot.assumption",
                        reason: error.to_string(),
                    })
            }
            Self::Unavailable {
                assumption_id,
                assumption_digest,
                reason,
            } => {
                validation::text(assumption_id, "rival.assumption_slot.assumption_id")?;
                if let Some(digest) = assumption_digest {
                    validation::digest(digest, "rival.assumption_slot.assumption_digest")?;
                }
                validation::text(reason, "rival.assumption_slot.reason")
            }
        }
    }

    pub fn validate_for_context(
        &self,
        task_id: &TaskId,
        scope: &str,
        fence: &StateFence,
    ) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Retained { assumption } => assumption
                .validate_for(task_id, scope, fence)
                .map_err(|error| ContractViolation::BindingMismatch {
                    field: "rival.assumption_slot.assumption",
                    reason: error.to_string(),
                }),
            Self::Unavailable { .. } => self.validate(),
        }
    }
}

/// One complete rival prediction, or an explicit unavailable prediction slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RivalPredictionSlot {
    /// Full typed prediction retained in this carrier.
    Retained { prediction: Box<RivalPrediction> },
    /// Prediction identity is known while its payload is unavailable.
    Unavailable {
        prediction_id: ArtifactId,
        prediction_digest: Option<String>,
        reason: String,
    },
}

impl RivalPredictionSlot {
    /// Returns the supplied stable prediction artifact identity.
    pub fn stable_id(&self) -> &ArtifactId {
        match self {
            Self::Retained { prediction } => &prediction.prediction_id,
            Self::Unavailable { prediction_id, .. } => prediction_id,
        }
    }

    /// Validates slot shape and, when retained, the complete prediction owner value.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Retained { prediction } => prediction.validate(),
            Self::Unavailable {
                prediction_id,
                prediction_digest,
                reason,
            } => {
                validation::artifact(prediction_id, "rival.prediction_slot.prediction_id")?;
                if let Some(digest) = prediction_digest {
                    validation::digest(digest, "rival.prediction_slot.prediction_digest")?;
                }
                validation::text(reason, "rival.prediction_slot.reason")
            }
        }
    }
}

/// One complete authorized source reference, or an explicit unavailable slot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RivalSourceSlot {
    /// Full source reference retained as supplied data.
    Retained { reference: Box<AuthorizedReference> },
    /// Source handle is known while its reference payload is unavailable.
    Unavailable {
        handle: ArtifactId,
        content_digest: Option<String>,
        source_revision: Option<String>,
        reason: String,
    },
}

impl RivalSourceSlot {
    /// Returns the supplied stable source artifact handle.
    pub fn stable_id(&self) -> &ArtifactId {
        match self {
            Self::Retained { reference } => &reference.handle,
            Self::Unavailable { handle, .. } => handle,
        }
    }

    /// Validates slot shape and, when retained, the complete reference owner value.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Retained { reference } => {
                reference.preflight_bytes()?;
                reference
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "rival.source_slot.reference",
                        reason: error.to_string(),
                    })
            }
            Self::Unavailable {
                handle,
                content_digest,
                source_revision,
                reason,
            } => {
                validation::artifact(handle, "rival.source_slot.handle")?;
                if let Some(digest) = content_digest {
                    validation::digest(digest, "rival.source_slot.content_digest")?;
                }
                if let Some(revision) = source_revision {
                    validation::text(revision, "rival.source_slot.source_revision")?;
                }
                validation::text(reason, "rival.source_slot.reason")
            }
        }
    }
}

/// Exact historical or external model identity whose declaration body is unavailable here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelatedRivalModelReference {
    /// Exact model identity and declaration digest retained from the supplied reference.
    pub reference: RivalModelRef,
    /// Why the referenced model body is not embedded in this set.
    pub payload_unavailable_reason: String,
}

impl RelatedRivalModelReference {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.reference.validate()?;
        validation::text(
            &self.payload_unavailable_reason,
            "rival.related_model.payload_unavailable_reason",
        )
    }
}

/// A coverage receipt is either supplied or explicitly unavailable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RivalCoverageReceipt {
    /// Full owner receipt retained for later set-level reconciliation.
    Supplied { receipt: Box<CoverageReceipt> },
    /// Receipt payload was unavailable, with no implied completeness.
    Unavailable {
        receipt_digest: Option<String>,
        reason: String,
    },
}

impl RivalCoverageReceipt {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Supplied { receipt } => {
                receipt
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "rival.coverage.receipt",
                        reason: error.to_string(),
                    })
            }
            Self::Unavailable {
                receipt_digest,
                reason,
            } => {
                if let Some(digest) = receipt_digest {
                    validation::digest(digest, "rival.coverage.receipt_digest")?;
                }
                validation::text(reason, "rival.coverage.receipt.reason")
            }
        }
    }
}

/// Coverage denominator and optional receipt supplied for one set table.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum RivalCoverageDeclaration {
    /// Denominator is supplied; receipt may remain explicitly unavailable.
    Supplied {
        denominator: Box<CoverageDenominator>,
        receipt: RivalCoverageReceipt,
    },
    /// No denominator is supplied, so no completeness claim is made.
    Unknown {
        denominator_digest: Option<String>,
        receipt: RivalCoverageReceipt,
        reason: String,
    },
}

impl RivalCoverageDeclaration {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Supplied {
                denominator,
                receipt,
            } => {
                denominator
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "rival.coverage.denominator",
                        reason: error.to_string(),
                    })?;
                if let RivalCoverageReceipt::Supplied { receipt } = receipt
                    && receipt.denominator != denominator.digest
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "rival.coverage.receipt.denominator",
                        reason: "receipt denominator differs from supplied denominator".to_owned(),
                    });
                }
                receipt.validate()
            }
            Self::Unknown {
                denominator_digest,
                receipt,
                reason,
            } => {
                if let Some(digest) = denominator_digest {
                    validation::digest(digest, "rival.coverage.denominator_digest")?;
                }
                if let (Some(denominator_digest), RivalCoverageReceipt::Supplied { receipt }) =
                    (denominator_digest, receipt)
                    && receipt.denominator != *denominator_digest
                {
                    return Err(ContractViolation::BindingMismatch {
                        field: "rival.coverage.denominator_digest",
                        reason: "receipt denominator differs from supplied digest claim".to_owned(),
                    });
                }
                receipt.validate()?;
                validation::text(reason, "rival.coverage.reason")
            }
        }
    }
}

/// Immutable supplied carrier for rival declarations.
///
/// Outer semantic tables are kept in canonical stable-identity order while
/// meaningful inner owner sequences remain unchanged. Intrinsic slot,
/// reference, coverage, and context validation perform no inference or
/// promotion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalDeclarationSet {
    pub schema_version: u32,
    pub set_id: ArtifactId,
    pub task_id: TaskId,
    pub scope: String,
    pub state_fence: StateFence,
    pub models: Vec<RivalModelSlot>,
    pub related_models: Vec<RelatedRivalModelReference>,
    pub claims: Vec<RivalClaimSlot>,
    pub assumptions: Vec<RivalAssumptionSlot>,
    pub predictions: Vec<RivalPredictionSlot>,
    /// Every explicitly referenced evidence or record handle, including
    /// records named by retained transitive provenance closures.
    pub sources: Vec<RivalSourceSlot>,
    pub model_coverage: RivalCoverageDeclaration,
    pub source_coverage: RivalCoverageDeclaration,
    pub unresolved: BTreeSet<String>,
    pub digest: String,
}

/// Constructor data for [`RivalDeclarationSet`].
#[derive(Clone, Debug)]
pub struct RivalDeclarationSetParams {
    pub set_id: ArtifactId,
    pub task_id: TaskId,
    pub scope: String,
    pub state_fence: StateFence,
    pub models: Vec<RivalModelSlot>,
    pub related_models: Vec<RelatedRivalModelReference>,
    pub claims: Vec<RivalClaimSlot>,
    pub assumptions: Vec<RivalAssumptionSlot>,
    pub predictions: Vec<RivalPredictionSlot>,
    pub sources: Vec<RivalSourceSlot>,
    pub model_coverage: RivalCoverageDeclaration,
    pub source_coverage: RivalCoverageDeclaration,
    pub unresolved: BTreeSet<String>,
}

impl RivalDeclarationSet {
    /// Constructs a canonical table carrier, sorting only its outer semantic tables.
    pub fn new(params: RivalDeclarationSetParams) -> Result<Self, ContractViolation> {
        let mut set = Self {
            schema_version: RIVAL_DECLARATION_SET_SCHEMA_VERSION,
            set_id: params.set_id,
            task_id: params.task_id,
            scope: params.scope,
            state_fence: params.state_fence,
            models: params.models,
            related_models: params.related_models,
            claims: params.claims,
            assumptions: params.assumptions,
            predictions: params.predictions,
            sources: params.sources,
            model_coverage: params.model_coverage,
            source_coverage: params.source_coverage,
            unresolved: params.unresolved,
            digest: String::new(),
        };
        validation::preflight(&set)?;
        set.validate_shape(false)?;
        set.sort_outer_tables();
        validation::preflight(&set)?;
        set.validate_content()?;
        set.digest = set.compute_digest_unchecked()?;
        validation::preflight(&set)?;
        Ok(set)
    }

    /// Validates the canonical outer table order, owner payloads, and frozen digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_content()?;
        validation::digest(&self.digest, "rival.declaration_set.digest")?;
        let expected = self.compute_digest_unchecked()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.digest",
                reason: "declaration set digest does not match its canonical content".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the canonical digest after validating the supplied set content.
    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::preflight(self)?;
        self.validate_content()?;
        self.compute_digest_unchecked()
    }

    fn compute_digest_unchecked(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            set_id: &'a ArtifactId,
            task_id: &'a TaskId,
            scope: &'a str,
            state_fence: &'a StateFence,
            models: &'a [RivalModelSlot],
            related_models: &'a [RelatedRivalModelReference],
            claims: &'a [RivalClaimSlot],
            assumptions: &'a [RivalAssumptionSlot],
            predictions: &'a [RivalPredictionSlot],
            sources: &'a [RivalSourceSlot],
            model_coverage: &'a RivalCoverageDeclaration,
            source_coverage: &'a RivalCoverageDeclaration,
            unresolved: &'a BTreeSet<String>,
        }
        validation::canonical_digest(&Preimage {
            schema_version: self.schema_version,
            set_id: &self.set_id,
            task_id: &self.task_id,
            scope: &self.scope,
            state_fence: &self.state_fence,
            models: &self.models,
            related_models: &self.related_models,
            claims: &self.claims,
            assumptions: &self.assumptions,
            predictions: &self.predictions,
            sources: &self.sources,
            model_coverage: &self.model_coverage,
            source_coverage: &self.source_coverage,
            unresolved: &self.unresolved,
        })
    }

    fn validate_content(&self) -> Result<(), ContractViolation> {
        self.validate_shape(true)?;
        for model in &self.models {
            model.validate()?;
            if let RivalModelSlot::Retained { declaration } = model
                && (declaration.task_id != self.task_id
                    || declaration.state_fence != self.state_fence
                    || declaration.applicability.scope != self.scope)
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.declaration_set.models",
                    reason: "retained model task, fence, or scope differs from set".to_owned(),
                });
            }
        }
        for claim in &self.claims {
            claim.validate_for_context(&self.task_id, &self.scope, &self.state_fence)?;
        }
        for assumption in &self.assumptions {
            assumption.validate_for_context(&self.task_id, &self.scope, &self.state_fence)?;
        }
        for prediction in &self.predictions {
            prediction.validate()?;
            if let RivalPredictionSlot::Retained { prediction } = prediction
                && prediction.applicability.scope != self.scope
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.declaration_set.predictions",
                    reason: "retained prediction scope differs from set".to_owned(),
                });
            }
        }
        for source in &self.sources {
            source.validate()?;
        }
        for related in &self.related_models {
            related.validate()?;
        }
        self.model_coverage.validate()?;
        self.source_coverage.validate()?;
        validation::validate_reference_closure(self)?;
        validation::validate_coverage_reconciliation(self)
    }

    fn validate_shape(&self, require_canonical_order: bool) -> Result<(), ContractViolation> {
        if self.schema_version != RIVAL_DECLARATION_SET_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.schema_version",
                reason: "unsupported rival declaration set schema revision".to_owned(),
            });
        }
        validation::artifact(&self.set_id, "rival.declaration_set.set_id")?;
        validation::text(self.task_id.as_str(), "rival.declaration_set.task_id")?;
        validation::text(&self.scope, "rival.declaration_set.scope")?;
        self.state_fence
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "rival.declaration_set.state_fence",
                reason: error.to_string(),
            })?;
        validation::sequence(self.unresolved.len(), "rival.declaration_set.unresolved")?;
        for value in &self.unresolved {
            validation::text(value, "rival.declaration_set.unresolved")?;
        }
        validation::sequence(self.models.len(), "rival.declaration_set.models")?;
        validation::sequence(
            self.related_models.len(),
            "rival.declaration_set.related_models",
        )?;
        validation::sequence(self.claims.len(), "rival.declaration_set.claims")?;
        validation::sequence(self.assumptions.len(), "rival.declaration_set.assumptions")?;
        validation::sequence(self.predictions.len(), "rival.declaration_set.predictions")?;
        validation::sequence(self.sources.len(), "rival.declaration_set.sources")?;
        if require_canonical_order {
            ensure_sorted_slots(
                &self.models,
                "rival.declaration_set.models",
                |left, right| left.stable_id().cmp(right.stable_id()),
            )?;
            ensure_sorted_slots(
                &self.claims,
                "rival.declaration_set.claims",
                |left, right| left.stable_id().cmp(right.stable_id()),
            )?;
            ensure_sorted_slots(
                &self.assumptions,
                "rival.declaration_set.assumptions",
                |left, right| left.stable_id().cmp(right.stable_id()),
            )?;
            ensure_sorted_slots(
                &self.predictions,
                "rival.declaration_set.predictions",
                |left, right| left.stable_id().cmp(right.stable_id()),
            )?;
            ensure_sorted_slots(
                &self.sources,
                "rival.declaration_set.sources",
                |left, right| left.stable_id().cmp(right.stable_id()),
            )?;
            ensure_sorted_related(&self.related_models)?;
        }
        self.validate_set_work_budget().map(|_| ())
    }

    fn sort_outer_tables(&mut self) {
        self.models
            .sort_by(|left, right| left.stable_id().cmp(right.stable_id()));
        self.claims
            .sort_by(|left, right| left.stable_id().cmp(right.stable_id()));
        self.assumptions
            .sort_by(|left, right| left.stable_id().cmp(right.stable_id()));
        self.predictions
            .sort_by(|left, right| left.stable_id().cmp(right.stable_id()));
        self.sources
            .sort_by(|left, right| left.stable_id().cmp(right.stable_id()));
        self.related_models.sort_by(compare_related);
    }

    fn validate_set_work_budget(&self) -> Result<usize, ContractViolation> {
        let mut total = 0usize;
        validation::set_sequence(
            self.models.len(),
            &mut total,
            "rival.declaration_set.models",
        )?;
        validation::set_sequence(
            self.related_models.len(),
            &mut total,
            "rival.declaration_set.related_models",
        )?;
        validation::set_sequence(
            self.claims.len(),
            &mut total,
            "rival.declaration_set.claims",
        )?;
        validation::set_sequence(
            self.assumptions.len(),
            &mut total,
            "rival.declaration_set.assumptions",
        )?;
        validation::set_sequence(
            self.predictions.len(),
            &mut total,
            "rival.declaration_set.predictions",
        )?;
        validation::set_sequence(
            self.sources.len(),
            &mut total,
            "rival.declaration_set.sources",
        )?;
        validation::set_sequence(
            self.unresolved.len(),
            &mut total,
            "rival.declaration_set.unresolved",
        )?;
        for model in &self.models {
            if let RivalModelSlot::Retained { declaration } = model {
                validation::set_work(
                    &mut total,
                    declaration.validate_work_budget()?,
                    "rival.declaration_set.work",
                )?;
            }
        }
        for claim in &self.claims {
            if let RivalClaimSlot::Retained { claim } = claim {
                count_material_claim(claim, &mut total)?;
            }
        }
        for assumption in &self.assumptions {
            if let RivalAssumptionSlot::Retained { assumption } = assumption {
                validation::set_sequence(
                    assumption.dependents.len(),
                    &mut total,
                    "rival.declaration_set.assumption.dependents",
                )?;
            }
        }
        for prediction in &self.predictions {
            if let RivalPredictionSlot::Retained { prediction } = prediction {
                count_prediction(prediction, &mut total)?;
            }
        }
        for source in &self.sources {
            if let RivalSourceSlot::Retained { reference } = source {
                count_authorized_reference(reference, &mut total)?;
            }
        }
        count_coverage_declaration(&self.model_coverage, &mut total)?;
        count_coverage_declaration(&self.source_coverage, &mut total)?;
        Ok(total)
    }
}

fn ensure_sorted_slots<T, F>(
    entries: &[T],
    field: &'static str,
    compare: F,
) -> Result<(), ContractViolation>
where
    F: Fn(&T, &T) -> Ordering,
{
    for pair in entries.windows(2) {
        match compare(&pair[0], &pair[1]) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: "duplicate stable identity in canonical table".to_owned(),
                });
            }
            Ordering::Greater => {
                return Err(ContractViolation::BindingMismatch {
                    field,
                    reason: "table is not in canonical stable-identity order".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn compare_related(
    left: &RelatedRivalModelReference,
    right: &RelatedRivalModelReference,
) -> Ordering {
    left.reference
        .model_id
        .cmp(&right.reference.model_id)
        .then(
            left.reference
                .model_revision
                .cmp(&right.reference.model_revision),
        )
        .then(
            left.reference
                .declaration_digest
                .cmp(&right.reference.declaration_digest),
        )
}

fn ensure_sorted_related(entries: &[RelatedRivalModelReference]) -> Result<(), ContractViolation> {
    for pair in entries.windows(2) {
        let identity_equal = pair[0].reference.model_id == pair[1].reference.model_id
            && pair[0].reference.model_revision == pair[1].reference.model_revision;
        match compare_related(&pair[0], &pair[1]) {
            Ordering::Greater => {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.declaration_set.related_models",
                    reason: "table is not in canonical model identity order".to_owned(),
                });
            }
            Ordering::Equal if identity_equal => {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.declaration_set.related_models",
                    reason: "duplicate related model identity".to_owned(),
                });
            }
            Ordering::Less | Ordering::Equal => {}
        }
        if identity_equal
            && pair[0].reference.declaration_digest != pair[1].reference.declaration_digest
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.declaration_set.related_models",
                reason: "related model identity has conflicting declaration digests".to_owned(),
            });
        }
    }
    Ok(())
}

fn count_material_claim(claim: &MaterialClaim, total: &mut usize) -> Result<(), ContractViolation> {
    validation::set_sequence(
        claim.subclaim_ids.len(),
        total,
        "rival.declaration_set.claim.subclaim_ids",
    )?;
    validation::set_sequence(
        claim.proposed_support.len(),
        total,
        "rival.declaration_set.claim.proposed_support",
    )?;
    validation::set_sequence(
        claim.proposed_counterevidence.len(),
        total,
        "rival.declaration_set.claim.proposed_counterevidence",
    )?;
    validation::set_sequence(
        claim.component_digests.len(),
        total,
        "rival.declaration_set.claim.component_digests",
    )?;
    if let Some(screen_target) = &claim.screen_target {
        validation::set_sequence(
            screen_target.screen.screened_targets.len(),
            total,
            "rival.declaration_set.claim.screened_targets",
        )?;
        validation::set_sequence(
            screen_target.target_denominator.members.len(),
            total,
            "rival.declaration_set.claim.target_denominator.members",
        )?;
    }
    count_precision_payload(&claim.payload, total)
}

fn count_precision_payload(
    payload: &PrecisionPayload,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    match payload {
        PrecisionPayload::Causal { causal } => count_causal(causal, total),
        PrecisionPayload::AbsenceExhaustiveNegative {
            denominator,
            receipt,
            absence_proof,
            ..
        } => {
            count_coverage_denominator(denominator, total)?;
            if let Some(receipt) = receipt {
                count_raw_coverage_receipt(receipt, total)?;
            }
            if let Some(absence_proof) = absence_proof {
                validation::set_work(total, 1, "rival.declaration_set.claim.absence_proof")?;
                count_raw_coverage_receipt(&absence_proof.receipt, total)?;
            }
            Ok(())
        }
        PrecisionPayload::RecommendationNormativeInference {
            fact_components,
            assumptions,
            ..
        } => {
            validation::set_sequence(
                fact_components.len(),
                total,
                "rival.declaration_set.claim.fact_components",
            )?;
            validation::set_sequence(
                assumptions.len(),
                total,
                "rival.declaration_set.claim.assumptions",
            )
        }
        _ => Ok(()),
    }
}

fn count_causal(causal: &CausalClaim, total: &mut usize) -> Result<(), ContractViolation> {
    validation::set_sequence(
        causal.rivals.len(),
        total,
        "rival.declaration_set.causal.rivals",
    )?;
    validation::set_sequence(
        causal.confounders.len(),
        total,
        "rival.declaration_set.causal.confounders",
    )?;
    validation::set_sequence(
        causal.evidence_refs.len(),
        total,
        "rival.declaration_set.causal.evidence_refs",
    )?;
    validation::set_sequence(
        causal.source_lineage.predecessors.len(),
        total,
        "rival.declaration_set.causal.source_lineage.predecessors",
    )
}

fn count_prediction(
    prediction: &RivalPrediction,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    validation::set_work(total, 1, "rival.declaration_set.prediction.target")?;
    validation::set_sequence(
        prediction.condition_assumptions.len(),
        total,
        "rival.declaration_set.prediction.condition_assumptions",
    )?;
    for availability in [
        &prediction.forecast.verifier_verdict,
        &prediction.forecast.diagnostic_change,
        &prediction.forecast.effect_blast_radius,
        &prediction.forecast.expected_value_or_range,
    ] {
        if matches!(
            availability,
            super::prediction::ForecastAvailability::Claim { .. }
        ) {
            validation::set_work(total, 1, "rival.declaration_set.prediction.forecast")?;
        }
    }
    Ok(())
}

fn count_authorized_reference(
    reference: &AuthorizedReference,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    if let Some(source_lineage) = &reference.source_lineage {
        validation::set_sequence(
            source_lineage.predecessors.len(),
            total,
            "rival.declaration_set.source.source_lineage.predecessors",
        )?;
    }
    if let Some(support) = &reference.support {
        validation::set_sequence(
            support.handles.len(),
            total,
            "rival.declaration_set.source.support.handles",
        )?;
    }
    if let Some(provenance) = &reference.provenance {
        count_provenance(provenance, total)?;
    }
    validation::set_sequence(
        reference.assertions.len(),
        total,
        "rival.declaration_set.source.assertions",
    )?;
    for assertion in &reference.assertions {
        if let Some(support) = &assertion.support {
            validation::set_sequence(
                support.handles.len(),
                total,
                "rival.declaration_set.source.assertion.support.handles",
            )?;
        }
        count_precision_payload(&assertion.precision, total)?;
    }
    Ok(())
}

fn count_provenance(
    provenance: &ProvenanceClosure,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    for (length, field) in [
        (
            provenance.records.len(),
            "rival.declaration_set.provenance.records",
        ),
        (
            provenance.sources.len(),
            "rival.declaration_set.provenance.sources",
        ),
        (
            provenance.raw_handles.len(),
            "rival.declaration_set.provenance.raw_handles",
        ),
        (
            provenance.revisions.len(),
            "rival.declaration_set.provenance.revisions",
        ),
        (
            provenance.lineage.len(),
            "rival.declaration_set.provenance.lineage",
        ),
        (
            provenance.record_origin.len(),
            "rival.declaration_set.provenance.record_origin",
        ),
    ] {
        validation::set_sequence(length, total, field)?;
    }
    for lineage in &provenance.lineage {
        validation::set_sequence(
            lineage.predecessors.len(),
            total,
            "rival.declaration_set.provenance.predecessors",
        )?;
    }
    Ok(())
}

fn count_coverage_declaration(
    declaration: &RivalCoverageDeclaration,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    validation::set_work(total, 1, "rival.declaration_set.coverage")?;
    match declaration {
        RivalCoverageDeclaration::Supplied {
            denominator,
            receipt,
        } => {
            count_coverage_denominator(denominator, total)?;
            count_coverage_receipt(receipt, total)
        }
        RivalCoverageDeclaration::Unknown { receipt, .. } => count_coverage_receipt(receipt, total),
    }
}

fn count_coverage_receipt(
    receipt: &RivalCoverageReceipt,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    if let RivalCoverageReceipt::Supplied { receipt } = receipt {
        count_raw_coverage_receipt(receipt, total)?;
    }
    Ok(())
}

fn count_raw_coverage_receipt(
    receipt: &CoverageReceipt,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    for (length, field) in [
        (receipt.groups.len(), "rival.declaration_set.receipt.groups"),
        (
            receipt.members.len(),
            "rival.declaration_set.receipt.members",
        ),
        (
            receipt.omissions.len(),
            "rival.declaration_set.receipt.omissions",
        ),
    ] {
        validation::set_sequence(length, total, field)?;
    }
    Ok(())
}

fn count_coverage_denominator(
    denominator: &CoverageDenominator,
    total: &mut usize,
) -> Result<(), ContractViolation> {
    for (length, field) in [
        (
            denominator.members.len(),
            "rival.declaration_set.denominator.members",
        ),
        (
            denominator.roles.len(),
            "rival.declaration_set.denominator.roles",
        ),
        (
            denominator.exclusions.len(),
            "rival.declaration_set.denominator.exclusions",
        ),
    ] {
        validation::set_sequence(length, total, field)?;
    }
    Ok(())
}
