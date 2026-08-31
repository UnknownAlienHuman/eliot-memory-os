//! Typed diversity wave for the Swarm `ControlBoard`.
//!
//! This module adds explicit `DiversityRequirement` and `DegradedDiversity`
//! outcomes, each bound to the exact `AttemptId` that requested the decision.
//! It performs no provider call, process launch, or dispatch. All decisions
//! remain candidate-only and preserve the existing authority ceiling.
//!
//! Negative cases are fail-closed:
//! - secret-bearing inputs are rejected (`api_key`, `secret`, …);
//! - a fixed universal model identity is rejected as drift;
//! - at most one primary per host is permitted;
//! - challenger/verifier host-route-model-family gaps are explicit degraded
//!   outcomes rather than silent reuse.

use std::collections::{BTreeMap, BTreeSet};

use eliot_agent_api::AttemptId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model_control::{ModelCatalogueEntry, ModelControlError, ModelRole};

const FORBIDDEN_FRAGMENTS: &[&str] = &[
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "password",
    "private_key",
    "secret",
    "token",
];

const FORBIDDEN_FIXED_MODELS: &[&str] = &["universal-model", "fixed-model", "fixed-universal"];

/// Distinct diversity dimensions — challenger/verifier must differ on all three
/// when required.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DiversityDimension {
    Host,
    Route,
    ModelFamily,
}

/// Typed requirement: `attempt_id` must differ from `source_attempt_id` on every
/// listed dimension. The decision is bound to the exact `AttemptId`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiversityRequirement {
    pub attempt_id: AttemptId,
    pub source_attempt_id: AttemptId,
    pub dimensions: BTreeSet<DiversityDimension>,
}

impl DiversityRequirement {
    /// Creates a validated requirement. `dimensions` must be non-empty and unique;
    /// `attempt_id` and `source_attempt_id` must differ.
    pub fn new(
        attempt_id: AttemptId,
        source_attempt_id: AttemptId,
        dimensions: BTreeSet<DiversityDimension>,
    ) -> Result<Self, DiversityError> {
        if dimensions.is_empty() {
            return Err(DiversityError::InvalidField("diversity.dimensions"));
        }
        if attempt_id == source_attempt_id {
            return Err(DiversityError::InvalidField("diversity.attempt_id"));
        }
        let requirement = Self {
            attempt_id,
            source_attempt_id,
            dimensions,
        };
        requirement.validate()?;
        Ok(requirement)
    }

    fn validate(&self) -> Result<(), DiversityError> {
        if self.attempt_id.as_str().trim().is_empty()
            || self.source_attempt_id.as_str().trim().is_empty()
        {
            return Err(DiversityError::InvalidField("diversity.attempt_id"));
        }
        Ok(())
    }
}

/// Explicit degraded outcome — diversity was required but not satisfied.
/// The gaps list the dimensions where the two selections collided.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DegradedDiversity {
    pub attempt_id: AttemptId,
    pub requirement: DiversityRequirement,
    pub gaps: Vec<DiversityDimension>,
}

impl DegradedDiversity {
    fn validate(&self) -> Result<(), DiversityError> {
        if self.gaps.is_empty() {
            return Err(DiversityError::InvalidField("degraded.gaps"));
        }
        // Ensure gaps are sorted unique and subset of requirement dimensions.
        let mut seen = BTreeSet::new();
        for gap in &self.gaps {
            if !self.requirement.dimensions.contains(gap) {
                return Err(DiversityError::InvalidField("degraded.gaps"));
            }
            if !seen.insert(*gap) {
                return Err(DiversityError::DuplicateIdentity("degraded.gaps"));
            }
        }
        Ok(())
    }
}

/// Outcome of a diversity decision bound to one exact `AttemptId`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum DiversityOutcome {
    Satisfied { attempt_id: AttemptId },
    Degraded(DegradedDiversity),
}

/// One AttemptId-bound diversity decision — the only place where
/// challenger/verifier independence is evaluated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiversityDecision {
    pub attempt_id: AttemptId,
    pub requirement: Option<DiversityRequirement>,
    pub outcome: DiversityOutcome,
    /// Candidate-only proof ceiling — diversity never grants dispatch.
    pub candidate_only: bool,
    pub dispatch_authority: bool,
    pub execution_zero: bool,
}

impl DiversityDecision {
    fn validate(&self) -> Result<(), DiversityError> {
        match &self.outcome {
            DiversityOutcome::Satisfied { attempt_id } => {
                if attempt_id != &self.attempt_id {
                    return Err(DiversityError::InvalidField("decision.attempt_id"));
                }
                if let Some(requirement) = &self.requirement
                    && &requirement.attempt_id != attempt_id
                {
                    return Err(DiversityError::InvalidField("decision.requirement"));
                }
            }
            DiversityOutcome::Degraded(degraded) => {
                if degraded.attempt_id != self.attempt_id {
                    return Err(DiversityError::InvalidField("decision.attempt_id"));
                }
                degraded.validate()?;
                if let Some(requirement) = &self.requirement {
                    if requirement != &degraded.requirement {
                        return Err(DiversityError::InvalidField("decision.requirement"));
                    }
                } else {
                    return Err(DiversityError::InvalidField("decision.requirement"));
                }
            }
        }
        if !self.candidate_only || self.dispatch_authority || !self.execution_zero {
            return Err(DiversityError::InvalidField("decision.authority"));
        }
        Ok(())
    }
}

/// Fail-closed diversity errors. Provider absence is not an error here — an
/// empty map means no diversity constraint was supplied.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DiversityError {
    #[error("invalid diversity field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate diversity identity: {0}")]
    DuplicateIdentity(&'static str),
    #[error("secret-bearing input is forbidden: {0}")]
    SecretInput(&'static str),
    #[error("fixed universal model identity is forbidden: {0}")]
    FixedModelDrift(&'static str),
    #[error("one-primary-per-host violation: host {0}")]
    OnePrimaryPerHost(String),
    #[error(transparent)]
    ModelControl(#[from] ModelControlError),
}

fn contains_forbidden_fragment(value: &str) -> bool {
    let lowered = value.to_lowercase().replace('-', "_");
    FORBIDDEN_FRAGMENTS
        .iter()
        .any(|fragment| lowered.contains(fragment))
}

fn reject_secret_value(value: &str, field: &'static str) -> Result<(), DiversityError> {
    if contains_forbidden_fragment(value) {
        return Err(DiversityError::SecretInput(field));
    }
    Ok(())
}

fn reject_fixed_model_value(value: &str, field: &'static str) -> Result<(), DiversityError> {
    let lowered = value.to_lowercase();
    for forbidden in FORBIDDEN_FIXED_MODELS {
        if lowered == *forbidden || lowered.contains(forbidden) {
            return Err(DiversityError::FixedModelDrift(field));
        }
    }
    Ok(())
}

/// Rejects any catalogue entry that carries secret-bearing or fixed-model
/// material. This is the Rust analogue of the Python `reject_secret_bearing_shape`
/// and fixed-model drift check.
pub fn validate_no_secret_or_fixed_input(
    entries: &[ModelCatalogueEntry],
) -> Result<(), DiversityError> {
    for entry in entries {
        // Check textual fields that an untrusted caller could influence.
        for (value, field) in [
            (entry.entry_id.as_str(), "entry.entry_id"),
            (entry.host_family.as_str(), "entry.host_family"),
            (entry.provider_id.as_str(), "entry.provider_id"),
            (entry.model_id.as_str(), "entry.model_id"),
            (entry.model_family.as_str(), "entry.model_family"),
            (entry.account_scope.as_str(), "entry.account_scope"),
        ] {
            reject_secret_value(value, field)?;
            reject_fixed_model_value(value, "entry.model_id")?;
        }
        for evidence in &entry.evidence_refs {
            reject_secret_value(evidence, "entry.evidence_refs")?;
        }
        for capability in entry.capabilities.keys() {
            reject_secret_value(capability, "entry.capability")?;
        }
        // Route fields are also checked — they carry host/provider/model.
        reject_secret_value(&entry.route.host_family, "entry.route.host_family")?;
        reject_secret_value(&entry.route.provider, "entry.route.provider")?;
        reject_secret_value(&entry.route.model, "entry.route.model")?;
        reject_fixed_model_value(&entry.route.model, "entry.route.model")?;
    }
    Ok(())
}

fn diversity_gaps(
    current: &ModelCatalogueEntry,
    prior: &ModelCatalogueEntry,
    dimensions: &BTreeSet<DiversityDimension>,
) -> Vec<DiversityDimension> {
    let mut gaps = Vec::new();
    for dimension in dimensions {
        let equal = match dimension {
            DiversityDimension::Host => current.host_family == prior.host_family,
            DiversityDimension::Route => current.route == prior.route,
            DiversityDimension::ModelFamily => current.model_family == prior.model_family,
        };
        if equal {
            gaps.push(*dimension);
        }
    }
    gaps.sort();
    gaps.dedup();
    gaps
}

/// Evaluates one `AttemptId`-bound diversity requirement against the exact prior
/// selection it must differ from. Returns a candidate-only `DiversityDecision`
/// whose outcome is either `Satisfied` or an explicit `DegradedDiversity`.
#[allow(clippy::needless_pass_by_value)]
pub fn decide_diversity(
    attempt_id: AttemptId,
    current: &ModelCatalogueEntry,
    prior: Option<(&AttemptId, &ModelCatalogueEntry)>,
    requirement: Option<DiversityRequirement>,
) -> Result<DiversityDecision, DiversityError> {
    // Fail-closed on secret / fixed-model before any ranking.
    validate_no_secret_or_fixed_input(std::slice::from_ref(current))?;
    if let Some((_, prior_entry)) = prior {
        validate_no_secret_or_fixed_input(std::slice::from_ref(prior_entry))?;
    }
    if let Some(ref req) = requirement {
        if req.attempt_id != attempt_id {
            return Err(DiversityError::InvalidField("decision.attempt_id"));
        }
        if let Some((prior_id, _)) = prior {
            if prior_id != &req.source_attempt_id {
                return Err(DiversityError::InvalidField("diversity.source_attempt_id"));
            }
        } else {
            return Err(DiversityError::InvalidField("diversity.source_missing"));
        }
    }

    let requirement_clone = requirement.clone();
    let outcome = match (requirement, prior) {
        (None, _) => DiversityOutcome::Satisfied {
            attempt_id: attempt_id.clone(),
        },
        (Some(req), Some((_, prior_entry))) => {
            let gaps = diversity_gaps(current, prior_entry, &req.dimensions);
            if gaps.is_empty() {
                DiversityOutcome::Satisfied {
                    attempt_id: attempt_id.clone(),
                }
            } else {
                let degraded = DegradedDiversity {
                    attempt_id: attempt_id.clone(),
                    requirement: req.clone(),
                    gaps,
                };
                degraded.validate()?;
                DiversityOutcome::Degraded(degraded)
            }
        }
        (Some(_), None) => {
            return Err(DiversityError::InvalidField("diversity.source_missing"));
        }
    };

    let decision = DiversityDecision {
        attempt_id: attempt_id.clone(),
        requirement: requirement_clone,
        outcome,
        candidate_only: true,
        dispatch_authority: false,
        execution_zero: true,
    };
    decision.validate()?;
    Ok(decision)
}

/// Validates that at most one primary (`MainAgent`) exists per host family.
/// `selections` is a map from `AttemptId` to `(ModelRole, ModelCatalogueEntry)`.
/// Returns the first violating host on duplicate.
pub fn validate_one_primary_per_host(
    selections: &BTreeMap<AttemptId, (ModelRole, ModelCatalogueEntry)>,
) -> Result<(), DiversityError> {
    let mut primary_hosts: BTreeMap<String, AttemptId> = BTreeMap::new();
    for (attempt_id, (role, entry)) in selections {
        validate_no_secret_or_fixed_input(std::slice::from_ref(entry))?;
        if *role == ModelRole::MainAgent {
            if let Some(existing) = primary_hosts.get(&entry.host_family) {
                let _ = existing;
                return Err(DiversityError::OnePrimaryPerHost(entry.host_family.clone()));
            }
            primary_hosts.insert(entry.host_family.clone(), attempt_id.clone());
        }
    }
    Ok(())
}

/// Convenience helper used by `ControlBoard`: validates a batch of
/// `AttemptId`-bound selections with optional per-attempt diversity
/// requirements and returns one `DiversityDecision` per attempt.
///
/// The caller supplies the exact `AttemptId` → `(role, entry)` map and a map
/// from `AttemptId` → `DiversityRequirement`. Missing requirements produce a
/// `Satisfied` decision with no gaps; supplied requirements produce either
/// `Satisfied` or an explicit `Degraded` outcome. Secret and fixed-model inputs
/// fail closed before any decision is emitted.
pub fn decide_swarm_diversity(
    selections: &BTreeMap<AttemptId, (ModelRole, ModelCatalogueEntry)>,
    requirements: &BTreeMap<AttemptId, DiversityRequirement>,
) -> Result<BTreeMap<AttemptId, DiversityDecision>, DiversityError> {
    // Validate global invariants first.
    validate_one_primary_per_host(selections)?;
    // Collect entries for secret/fixed check.
    let entries: Vec<ModelCatalogueEntry> = selections
        .values()
        .map(|(_, entry)| entry.clone())
        .collect();
    validate_no_secret_or_fixed_input(&entries)?;

    let mut decisions = BTreeMap::new();
    for (attempt_id, (_, entry)) in selections {
        let requirement = requirements.get(attempt_id).cloned();
        let prior = if let Some(req) = &requirement {
            let source_entry = selections
                .get(&req.source_attempt_id)
                .map(|(_, e)| (&req.source_attempt_id, e))
                .ok_or(DiversityError::InvalidField("diversity.source_missing"))?;
            Some(source_entry)
        } else {
            None
        };
        // Re-validate the requirement binding.
        if let Some(ref req) = requirement
            && &req.attempt_id != attempt_id
        {
            return Err(DiversityError::InvalidField("diversity.attempt_id"));
        }
        let gaps = if let (Some(req), Some((_, prior_entry))) = (requirement.as_ref(), prior) {
            diversity_gaps(entry, prior_entry, &req.dimensions)
        } else {
            Vec::new()
        };
        let outcome = if let Some(req) = requirement {
            if gaps.is_empty() {
                DiversityOutcome::Satisfied {
                    attempt_id: attempt_id.clone(),
                }
            } else {
                let degraded = DegradedDiversity {
                    attempt_id: attempt_id.clone(),
                    requirement: req,
                    gaps,
                };
                degraded.validate()?;
                DiversityOutcome::Degraded(degraded)
            }
        } else {
            DiversityOutcome::Satisfied {
                attempt_id: attempt_id.clone(),
            }
        };
        // Preserve requirement in decision for audit when it was supplied.
        let decision_requirement = match &outcome {
            DiversityOutcome::Satisfied { .. } => requirements.get(attempt_id).cloned(),
            DiversityOutcome::Degraded(d) => Some(d.requirement.clone()),
        };
        let decision = DiversityDecision {
            attempt_id: attempt_id.clone(),
            requirement: decision_requirement,
            outcome,
            candidate_only: true,
            dispatch_authority: false,
            execution_zero: true,
        };
        decision.validate()?;
        decisions.insert(attempt_id.clone(), decision);
    }
    Ok(decisions)
}

#[cfg(test)]
#[path = "diversity_tests.rs"]
mod tests;
