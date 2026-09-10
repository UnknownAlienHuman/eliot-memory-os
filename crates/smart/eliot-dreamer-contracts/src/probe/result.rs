//! Finite possible-result schemas and supplied update declarations.

use std::collections::BTreeSet;

use eliot_contracts::ArtifactId;
use eliot_epistemic_contracts::CoverageDenominator;
use eliot_evaluation_contracts::{ExpectedObservableSpec, PlannedVerifierRef};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContractViolation,
    rival::{RivalModelRef, RivalPredictionRef},
};

use super::{
    bounds::{
        MAX_PROBE_UPDATES_PER_BRANCH, PROBE_RESULT_SCHEMA_VERSION, check_branches, check_sequence,
    },
    validation,
};

/// One declared target in the result-update denominator.
/// The identity includes owner-supplied digests, so a changed declaration with
/// the same local ID cannot silently bind.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ResultTarget {
    Rival {
        model: RivalModelRef,
        prediction: Option<RivalPredictionRef>,
    },
    Gap {
        objective: super::objective::ProbeObjectiveRef,
    },
}

impl ResultTarget {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Rival { model, prediction } => {
                model.validate()?;
                if let Some(prediction) = prediction {
                    prediction.validate()?;
                }
            }
            Self::Gap { objective } => objective.validate()?,
        }
        Ok(())
    }
}

/// A possible result declaration. It is never an acquired observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PossibleResultValue {
    Observable {
        observable: ExpectedObservableSpec,
    },
    Coverage {
        denominator: Box<CoverageDenominator>,
    },
    Verifier {
        verifier: Box<PlannedVerifierRef>,
    },
    Unknown {
        reason: String,
    },
    Unavailable {
        reason: String,
    },
    InstrumentationFailure {
        reason: String,
    },
}

impl PossibleResultValue {
    /// Validates the declaration shape and its retained owner atom.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Observable { observable } => {
                observable
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "probe.result.observable",
                        reason: error.to_string(),
                    })
            }
            Self::Coverage { denominator } => {
                denominator
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "probe.result.denominator",
                        reason: error.to_string(),
                    })
            }
            Self::Verifier { verifier } => {
                verifier
                    .validate()
                    .map_err(|error| ContractViolation::BindingMismatch {
                        field: "probe.result.verifier",
                        reason: error.to_string(),
                    })
            }
            Self::Unknown { reason }
            | Self::Unavailable { reason }
            | Self::InstrumentationFailure { reason } => {
                validation::text(reason, "probe.result.reason")
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RivalUpdateMeaning {
    Strengthened,
    Weakened,
    Unchanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum GapUpdateMeaning {
    Addressed,
    PartiallyAddressed,
    RemainsOpen,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ResultUpdate {
    Rival {
        model: RivalModelRef,
        prediction: Option<RivalPredictionRef>,
        meaning: RivalUpdateMeaning,
    },
    Gap {
        objective: super::objective::ProbeObjectiveRef,
        meaning: GapUpdateMeaning,
    },
    Unknown {
        target: ResultTarget,
        reason: String,
    },
}

impl ResultUpdate {
    fn target(&self) -> ResultTarget {
        match self {
            Self::Rival {
                model, prediction, ..
            } => ResultTarget::Rival {
                model: model.clone(),
                prediction: prediction.clone(),
            },
            Self::Gap { objective, .. } => ResultTarget::Gap {
                objective: objective.clone(),
            },
            Self::Unknown { target, .. } => target.clone(),
        }
    }

    fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.target().validate()?;
        if let Self::Unknown { reason, .. } = self {
            validation::text(reason, "probe.result.update.reason")?;
        }
        Ok(())
    }
}

/// One ordered result branch. Every branch must cover every target in the
/// enclosing schema denominator exactly once.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultBranch {
    pub result_id: ArtifactId,
    pub value: PossibleResultValue,
    pub updates: Vec<ResultUpdate>,
}

impl ResultBranch {
    fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::text(self.result_id.as_str(), "probe.result.result_id")?;
        self.value.validate()?;
        check_sequence(self.updates.len(), "probe.result.updates")?;
        if self.updates.len() > MAX_PROBE_UPDATES_PER_BRANCH {
            return Err(ContractViolation::OutOfBounds {
                field: "probe.result.updates",
                min: 0,
                max: MAX_PROBE_UPDATES_PER_BRANCH as i64,
                got: self.updates.len() as i64,
            });
        }
        for update in &self.updates {
            update.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PossibleResultSchema {
    pub schema_version: u32,
    pub result_schema_id: ArtifactId,
    /// Exact target denominator shared by every ordered branch.
    pub targets: Vec<ResultTarget>,
    pub branches: Vec<ResultBranch>,
    pub digest: String,
}

impl PossibleResultSchema {
    pub fn new(
        result_schema_id: ArtifactId,
        targets: Vec<ResultTarget>,
        branches: Vec<ResultBranch>,
    ) -> Result<Self, ContractViolation> {
        let mut schema = Self {
            schema_version: PROBE_RESULT_SCHEMA_VERSION,
            result_schema_id,
            targets,
            branches,
            digest: String::new(),
        };
        validation::preflight(&schema)?;
        schema.validate_shape()?;
        schema.digest = schema.compute_digest()?;
        Ok(schema)
    }

    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "probe.result_schema.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.result_schema.digest",
                reason: "result schema digest does not match declaration".to_owned(),
            });
        }
        Ok(())
    }

    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        self.validate_shape()?;
        validation::canonical_digest(&(
            self.schema_version,
            &self.result_schema_id,
            &self.targets,
            &self.branches,
        ))
    }

    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != PROBE_RESULT_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.result_schema.schema_version",
                reason: "unsupported result schema".to_owned(),
            });
        }
        validation::text(
            self.result_schema_id.as_str(),
            "probe.result_schema.result_schema_id",
        )?;
        check_sequence(self.targets.len(), "probe.result_schema.targets")?;
        check_branches(self.branches.len(), "probe.result_schema.branches")?;
        if self.targets.is_empty() {
            return Err(ContractViolation::MissingField(
                "probe.result_schema.targets",
            ));
        }
        if self.branches.is_empty() {
            return Err(ContractViolation::MissingField(
                "probe.result_schema.branches",
            ));
        }
        let mut targets = BTreeSet::new();
        for target in &self.targets {
            target.validate()?;
            if !targets.insert(target.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.result_schema.targets",
                    reason: "duplicate result target".to_owned(),
                });
            }
        }
        let mut branch_ids = BTreeSet::new();
        for branch in &self.branches {
            branch.validate()?;
            if !branch_ids.insert(branch.result_id.clone()) {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.result_schema.branches",
                    reason: "duplicate result identity".to_owned(),
                });
            }
            let mut updates = BTreeSet::new();
            for update in &branch.updates {
                let target = update.target();
                if !targets.contains(&target) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "probe.result_schema.branches",
                        reason: "branch update targets undeclared target".to_owned(),
                    });
                }
                if !updates.insert(target) {
                    return Err(ContractViolation::BindingMismatch {
                        field: "probe.result_schema.branches",
                        reason: "branch contains duplicate target update".to_owned(),
                    });
                }
            }
            if updates != targets {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.result_schema.branches",
                    reason: "branch must cover every declared result target exactly once"
                        .to_owned(),
                });
            }
        }
        Ok(())
    }
}
