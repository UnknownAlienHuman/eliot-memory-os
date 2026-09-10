//! Inert, typed rival prediction and falsifier declarations.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::ArtifactId;
use eliot_epistemic_contracts::ValidityBounds;
use eliot_evaluation_contracts::{ExpectedObservableSpec, PlannedVerifierRef};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::model::MaterialClaimRef;
use super::validation;
use crate::error::ContractViolation;

/// Wire revision for one rival prediction declaration.
pub const RIVAL_PREDICTION_SCHEMA_VERSION: u32 = 1;

/// Exact reference to a condition/assumption retained by the declaration set.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConditionAssumptionRef {
    /// Stable assumption identity.
    pub assumption_id: String,
    /// Digest of the exact retained assumption record.
    pub assumption_digest: String,
}

impl ConditionAssumptionRef {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::text(&self.assumption_id, "rival.prediction.assumption_id")?;
        validation::digest(
            &self.assumption_digest,
            "rival.prediction.assumption_digest",
        )
    }
}

/// Expected or falsifying observable content, with absence kept explicit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PredictionAvailability {
    /// A supplied expected observable declaration; no matcher is executed here.
    Declared { observable: ExpectedObservableSpec },
    /// The observable is required or relevant but unavailable for this declaration.
    Unknown { reason: String },
}

impl PredictionAvailability {
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        match self {
            Self::Declared { observable } => validate_observable(observable, field),
            Self::Unknown { reason } => validation::text(reason, field),
        }
    }
}

/// One material forecast dimension, retained as a declaration rather than an
/// observed result or causal verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ForecastAvailability {
    /// A typed expected observable declaration.
    Observable { spec: ExpectedObservableSpec },
    /// An exact retained typed material claim reference.
    Claim { reference: MaterialClaimRef },
    /// The forecast is load-bearing but unavailable.
    Unknown { reason: String },
    /// The dimension does not apply, with an explicit bounded reason.
    NotApplicable { reason: String },
}

impl ForecastAvailability {
    pub fn validate(&self, field: &'static str) -> Result<(), ContractViolation> {
        match self {
            Self::Observable { spec } => validate_observable(spec, field),
            Self::Claim { reference } => reference.validate(),
            Self::Unknown { reason } | Self::NotApplicable { reason } => {
                validation::text(reason, field)
            }
        }
    }
}

/// Applicability-aware material forecasts from I12.18.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RivalForecast {
    /// Predicted verifier verdict, if applicable.
    pub verifier_verdict: ForecastAvailability,
    /// Predicted diagnostic change, if applicable.
    pub diagnostic_change: ForecastAvailability,
    /// Predicted effect or blast-radius change, if applicable.
    pub effect_blast_radius: ForecastAvailability,
    /// Expected observable value or range, if applicable.
    pub expected_value_or_range: ForecastAvailability,
}

impl RivalForecast {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.verifier_verdict
            .validate("rival.forecast.verifier_verdict")?;
        self.diagnostic_change
            .validate("rival.forecast.diagnostic_change")?;
        self.effect_blast_radius
            .validate("rival.forecast.effect_blast_radius")?;
        self.expected_value_or_range
            .validate("rival.forecast.expected_value_or_range")
    }
}

/// Optional verifier claim accompanying an expected observable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum VerifierAvailability {
    /// A supplied, inert planned verifier reference.
    Supplied { verifier: PlannedVerifierRef },
    /// A verifier was expected but is unavailable.
    Unavailable { reason: String },
    /// No verifier applies to this purely epistemic prediction.
    NotApplicable,
}

impl VerifierAvailability {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Supplied { verifier } => validate_planned_verifier(verifier),
            Self::Unavailable { reason } => {
                validation::text(reason, "rival.prediction.verifier.reason")
            }
            Self::NotApplicable => Ok(()),
        }
    }
}

/// A bounded expected observation and its explicit falsifier.
///
/// This is supplied declaration data. It performs no matching, parsing,
/// verification, experiment execution, or observed-support promotion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RivalPrediction {
    /// Exact schema revision for this prediction wire.
    pub schema_version: u32,
    /// Stable identity of the prediction declaration artifact.
    pub prediction_id: ArtifactId,
    /// Material claim whose prediction is being declared.
    pub target: MaterialClaimRef,
    /// Scope/time/version conditions under which this prediction applies.
    pub applicability: ValidityBounds,
    /// Exact scope/time/version conditions under which the prediction applies.
    pub condition_assumptions: BTreeSet<ConditionAssumptionRef>,
    /// Expected observable, or an explicit unknown declaration.
    pub expected: PredictionAvailability,
    /// Falsifying observable, or an explicit unknown declaration.
    pub falsifier: PredictionAvailability,
    /// Material causal/action forecast dimensions, each applicability-aware.
    pub forecast: RivalForecast,
    /// Optional supplied verifier claim for the expected observable.
    pub verifier: VerifierAvailability,
    /// Canonical digest of the declaration, excluding this field.
    pub digest: String,
}

impl RivalPrediction {
    /// Constructs and freezes a prediction declaration after intrinsic checks.
    pub fn new(params: RivalPredictionParams) -> Result<Self, ContractViolation> {
        let mut prediction = Self {
            schema_version: RIVAL_PREDICTION_SCHEMA_VERSION,
            prediction_id: params.prediction_id,
            target: params.target,
            applicability: params.applicability,
            condition_assumptions: params.condition_assumptions,
            expected: params.expected,
            falsifier: params.falsifier,
            forecast: params.forecast,
            verifier: params.verifier,
            digest: String::new(),
        };
        validation::preflight(&prediction)?;
        prediction.validate_content()?;
        prediction.digest = prediction.compute_digest()?;
        validation::preflight(&prediction)?;
        Ok(prediction)
    }

    /// Validates the complete declaration, including its frozen digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_content()?;
        validation::digest(&self.digest, "rival.prediction.digest")?;
        let expected = self.compute_digest()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.prediction.digest",
                reason: "prediction digest does not match its declaration".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the frozen digest after bounded content validation.
    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            prediction_id: &'a ArtifactId,
            target: &'a MaterialClaimRef,
            applicability: &'a ValidityBounds,
            condition_assumptions: &'a BTreeSet<ConditionAssumptionRef>,
            expected: &'a PredictionAvailability,
            falsifier: &'a PredictionAvailability,
            forecast: &'a RivalForecast,
            verifier: &'a VerifierAvailability,
        }
        validation::preflight(self)?;
        self.validate_content()?;
        validation::canonical_digest(&Preimage {
            schema_version: self.schema_version,
            prediction_id: &self.prediction_id,
            target: &self.target,
            applicability: &self.applicability,
            condition_assumptions: &self.condition_assumptions,
            expected: &self.expected,
            falsifier: &self.falsifier,
            forecast: &self.forecast,
            verifier: &self.verifier,
        })
    }

    fn validate_content(&self) -> Result<(), ContractViolation> {
        if self.schema_version != RIVAL_PREDICTION_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.prediction.schema_version",
                reason: "unsupported rival prediction schema revision".to_owned(),
            });
        }
        validation::artifact(&self.prediction_id, "rival.prediction.prediction_id")?;
        self.target.validate()?;
        self.applicability
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "rival.prediction.applicability",
                reason: error.to_string(),
            })?;
        validation::sequence(
            self.condition_assumptions.len(),
            "rival.prediction.condition_assumptions",
        )?;
        let mut assumption_digests = BTreeMap::new();
        for assumption in &self.condition_assumptions {
            if let Some(previous) = assumption_digests.insert(
                assumption.assumption_id.as_str(),
                assumption.assumption_digest.as_str(),
            ) && previous != assumption.assumption_digest.as_str()
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.prediction.condition_assumptions",
                    reason: "one assumption identity has conflicting digests".to_owned(),
                });
            }
            assumption.validate()?;
        }
        self.expected.validate("rival.prediction.expected")?;
        self.falsifier.validate("rival.prediction.falsifier")?;
        self.forecast.validate()?;
        self.verifier.validate()?;
        if let (
            PredictionAvailability::Declared {
                observable: expected,
            },
            VerifierAvailability::Supplied { verifier },
        ) = (&self.expected, &self.verifier)
            && verifier.expected_observable != *expected
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.prediction.verifier.expected_observable",
                reason: "planned verifier does not bind the known expected observable".to_owned(),
            });
        }
        Ok(())
    }
}

/// Named constructor arguments for [`RivalPrediction::new`].
#[derive(Clone, Debug)]
pub struct RivalPredictionParams {
    /// Stable identity of the prediction declaration artifact.
    pub prediction_id: ArtifactId,
    /// Material claim whose prediction is being declared.
    pub target: MaterialClaimRef,
    /// Scope/time/version conditions under which this prediction applies.
    pub applicability: ValidityBounds,
    /// Exact condition and assumption references.
    pub condition_assumptions: BTreeSet<ConditionAssumptionRef>,
    /// Expected observable, or an explicit unknown declaration.
    pub expected: PredictionAvailability,
    /// Falsifying observable, or an explicit unknown declaration.
    pub falsifier: PredictionAvailability,
    /// Material causal/action forecast dimensions.
    pub forecast: RivalForecast,
    /// Optional supplied verifier claim.
    pub verifier: VerifierAvailability,
}

fn validate_observable(
    observable: &ExpectedObservableSpec,
    field: &'static str,
) -> Result<(), ContractViolation> {
    validation::text(&observable.property, field)?;
    validation::text(&observable.matcher, field)?;
    validation::text(&observable.artifact_selector, field)?;
    observable
        .validate()
        .map_err(|error| ContractViolation::BindingMismatch {
            field,
            reason: error.to_string(),
        })
}

fn validate_planned_verifier(verifier: &PlannedVerifierRef) -> Result<(), ContractViolation> {
    validation::text(
        verifier.verifier_id.as_str(),
        "rival.prediction.verifier_id",
    )?;
    validation::text(verifier.scope.as_str(), "rival.prediction.verifier.scope")?;
    validation::text(
        verifier.verifier_config_hash.as_str(),
        "rival.prediction.verifier.config_hash",
    )?;
    validate_observable(
        &verifier.expected_observable,
        "rival.prediction.verifier.expected_observable",
    )?;
    validation::text(
        verifier.environment_binding.as_str(),
        "rival.prediction.verifier.environment_binding",
    )?;
    validation::text(
        verifier.verifier_authority_ref.as_str(),
        "rival.prediction.verifier.authority_ref",
    )?;
    verifier
        .validate()
        .map_err(|error| ContractViolation::BindingMismatch {
            field: "rival.prediction.verifier",
            reason: error.to_string(),
        })
}
