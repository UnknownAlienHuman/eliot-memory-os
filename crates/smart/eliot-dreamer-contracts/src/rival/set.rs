//! Owner-neutral rival projection consumed by discriminative-probe planning.
//!
//! The rich rival-structuring implementation may retain additional packing and
//! diagnostic state. This projection carries only the immutable identities,
//! discriminative objectives, and explicit omissions required by consumers.
//!
//! Divergence from [`super::projection::RivalModelSet`]: that canonical
//! projection (re-exported at the `rival::` level since #1502) seals a
//! discriminator preimage (retained discriminators, unresolved requirements,
//! coverage summaries, omission frontier). This module seals a different,
//! probe-input preimage (retained [`ProbeObjective`] rows, explicit
//! [`RivalObjectiveOmission`] accounting, declared counts, coverage digests,
//! [`RivalModelSetDisposition`]). The two shapes serve different consumers
//! and hash different preimages, so they cannot share one digest input:
//! merging them would alter a frozen canonical digest. Each module therefore
//! owns its wire revision under its own path, and only the projection
//! revision is re-exported at the `rival::` level, keeping a single canonical
//! crate-level definition. Long-term consolidation is an auditor decision;
//! this module intentionally stays separate and keeps its own preimage.

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use serde::{Deserialize, Serialize};

use crate::{ContractViolation, probe::ProbeObjective};

use super::validation;

/// Wire revision for the owner-neutral rival projection.
pub const RIVAL_MODEL_SET_SCHEMA_VERSION: u32 = 1;

/// Projection completeness. No variant is a truth or winner verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RivalModelSetDisposition {
    Complete,
    Partial,
    InsufficientRivals,
    Unprobeable,
}

/// Why one source-addressable discriminator did not become an objective.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RivalObjectiveOmissionReason {
    Unknown,
    Unavailable,
    InternallyIdentical,
    NotApplicable,
    OutsideFrontier,
    InvalidResultSchema,
}

/// Exact accounting record for one omitted discriminator input.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalObjectiveOmission {
    pub model_id: Option<ArtifactId>,
    pub prediction_id: Option<ArtifactId>,
    pub peer_model_id: Option<ArtifactId>,
    pub peer_prediction_id: Option<ArtifactId>,
    pub reason: RivalObjectiveOmissionReason,
    pub detail: String,
}

impl RivalObjectiveOmission {
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        for (value, field) in [
            (&self.model_id, "rival.projection.omission.model_id"),
            (&self.prediction_id, "rival.projection.omission.prediction_id"),
            (&self.peer_model_id, "rival.projection.omission.peer_model_id"),
            (
                &self.peer_prediction_id,
                "rival.projection.omission.peer_prediction_id",
            ),
        ] {
            if let Some(value) = value {
                validation::artifact(value, field)?;
            }
        }
        validation::text(&self.detail, "rival.projection.omission.detail")
    }
}

/// Named constructor input for [`RivalModelSet`].
#[derive(Clone, Debug)]
pub struct RivalModelSetParams {
    pub set_id: ArtifactId,
    pub task_id: TaskId,
    pub scope: String,
    pub state_fence: StateFence,
    pub bundle_digest: String,
    pub validated_input_digest: String,
    pub source_set_id: ArtifactId,
    pub source_set_digest: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub declared_model_count: u32,
    pub declared_source_count: u32,
    pub model_coverage_digest: String,
    pub source_coverage_digest: String,
    pub objectives: Vec<ProbeObjective>,
    pub omissions: Vec<RivalObjectiveOmission>,
    pub disposition: RivalModelSetDisposition,
}

/// Immutable, bounded rival projection used by later contract-only consumers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RivalModelSet {
    pub schema_version: u32,
    pub set_id: ArtifactId,
    pub task_id: TaskId,
    pub scope: String,
    pub state_fence: StateFence,
    pub bundle_digest: String,
    pub validated_input_digest: String,
    pub source_set_id: ArtifactId,
    pub source_set_digest: String,
    pub policy_id: String,
    pub policy_digest: String,
    pub declared_model_count: u32,
    pub declared_source_count: u32,
    pub model_coverage_digest: String,
    pub source_coverage_digest: String,
    /// Complete number of source discriminator rows considered.
    pub objective_denominator: u32,
    /// Canonically ordered retained probe objectives.
    pub objectives: Vec<ProbeObjective>,
    /// Canonically ordered explicit omission accounting.
    pub omissions: Vec<RivalObjectiveOmission>,
    pub disposition: RivalModelSetDisposition,
    pub digest: String,
}

/// Canonical digest preimage for [`RivalModelSet`], excluding the digest field.
///
/// A named struct is required because serde implements `Serialize` for tuples
/// only up to 16 elements, while this preimage carries 19 fields. Field names
/// and declaration order mirror the [`RivalModelSet`] content fields in their
/// original tuple order; canonical bytes sort object keys, so the digest is
/// stable regardless of declaration order. This preimage never compiled as a
/// tuple, so no prior digest value exists: this struct establishes the first
/// canonical encoding, and any field addition, removal, reorder, or rename
/// alters the digest.
#[derive(Serialize)]
struct RivalModelSetDigestPreimage<'a> {
    schema_version: u32,
    set_id: &'a ArtifactId,
    task_id: &'a TaskId,
    scope: &'a String,
    state_fence: &'a StateFence,
    bundle_digest: &'a String,
    validated_input_digest: &'a String,
    source_set_id: &'a ArtifactId,
    source_set_digest: &'a String,
    policy_id: &'a String,
    policy_digest: &'a String,
    declared_model_count: u32,
    declared_source_count: u32,
    model_coverage_digest: &'a String,
    source_coverage_digest: &'a String,
    objective_denominator: u32,
    objectives: &'a Vec<ProbeObjective>,
    omissions: &'a Vec<RivalObjectiveOmission>,
    disposition: RivalModelSetDisposition,
}

impl RivalModelSet {
    /// Constructs and seals one canonical owner-neutral projection.
    pub fn new(mut params: RivalModelSetParams) -> Result<Self, ContractViolation> {
        params
            .objectives
            .sort_by(|left, right| left.objective_id.cmp(&right.objective_id));
        params.omissions.sort();
        let denominator = params
            .objectives
            .len()
            .checked_add(params.omissions.len())
            .ok_or(ContractViolation::OutOfBounds {
                field: "rival.projection.objective_denominator",
                min: 0,
                max: i64::from(u32::MAX),
                got: i64::MAX,
            })?;
        let objective_denominator =
            u32::try_from(denominator).map_err(|_| ContractViolation::OutOfBounds {
                field: "rival.projection.objective_denominator",
                min: 0,
                max: i64::from(u32::MAX),
                got: crate::error::len_i64(denominator),
            })?;
        let mut value = Self {
            schema_version: RIVAL_MODEL_SET_SCHEMA_VERSION,
            set_id: params.set_id,
            task_id: params.task_id,
            scope: params.scope,
            state_fence: params.state_fence,
            bundle_digest: params.bundle_digest,
            validated_input_digest: params.validated_input_digest,
            source_set_id: params.source_set_id,
            source_set_digest: params.source_set_digest,
            policy_id: params.policy_id,
            policy_digest: params.policy_digest,
            declared_model_count: params.declared_model_count,
            declared_source_count: params.declared_source_count,
            model_coverage_digest: params.model_coverage_digest,
            source_coverage_digest: params.source_coverage_digest,
            objective_denominator,
            objectives: params.objectives,
            omissions: params.omissions,
            disposition: params.disposition,
            digest: String::new(),
        };
        value.validate_shape()?;
        value.digest = value.compute_digest()?;
        Ok(value)
    }

    /// Validates intrinsic shape and canonical digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "rival.projection.digest")?;
        if self.digest != self.compute_digest()? {
            return binding(
                "rival.projection.digest",
                "digest does not match the rival projection",
            );
        }
        Ok(())
    }

    /// Computes the canonical digest excluding the digest field.
    ///
    /// The preimage is [`RivalModelSetDigestPreimage`]: the same 19 content
    /// fields, in the same order, under their struct field names.
    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::canonical_digest(&RivalModelSetDigestPreimage {
            schema_version: self.schema_version,
            set_id: &self.set_id,
            task_id: &self.task_id,
            scope: &self.scope,
            state_fence: &self.state_fence,
            bundle_digest: &self.bundle_digest,
            validated_input_digest: &self.validated_input_digest,
            source_set_id: &self.source_set_id,
            source_set_digest: &self.source_set_digest,
            policy_id: &self.policy_id,
            policy_digest: &self.policy_digest,
            declared_model_count: self.declared_model_count,
            declared_source_count: self.declared_source_count,
            model_coverage_digest: &self.model_coverage_digest,
            source_coverage_digest: &self.source_coverage_digest,
            objective_denominator: self.objective_denominator,
            objectives: &self.objectives,
            omissions: &self.omissions,
            disposition: self.disposition,
        })
    }

    #[allow(clippy::too_many_lines)] // Sequential per-field shape checks stay contiguous.
    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != RIVAL_MODEL_SET_SCHEMA_VERSION {
            return binding(
                "rival.projection.schema_version",
                "unsupported projection schema version",
            );
        }
        validation::artifact(&self.set_id, "rival.projection.set_id")?;
        validation::text(self.task_id.as_str(), "rival.projection.task_id")?;
        validation::text(&self.scope, "rival.projection.scope")?;
        self.state_fence
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "rival.projection.state_fence",
                reason: error.to_string(),
            })?;
        for (digest, field) in [
            (&self.bundle_digest, "rival.projection.bundle_digest"),
            (
                &self.validated_input_digest,
                "rival.projection.validated_input_digest",
            ),
            (&self.source_set_digest, "rival.projection.source_set_digest"),
            (&self.policy_digest, "rival.projection.policy_digest"),
            (
                &self.model_coverage_digest,
                "rival.projection.model_coverage_digest",
            ),
            (
                &self.source_coverage_digest,
                "rival.projection.source_coverage_digest",
            ),
        ] {
            validation::digest(digest, field)?;
        }
        validation::artifact(&self.source_set_id, "rival.projection.source_set_id")?;
        validation::text(&self.policy_id, "rival.projection.policy_id")?;
        for (count, field) in [
            (self.declared_model_count, "rival.projection.declared_model_count"),
            (
                self.declared_source_count,
                "rival.projection.declared_source_count",
            ),
        ] {
            if usize::try_from(count).map_or(true, |count| count > validation::MAX_RIVAL_ITEMS) {
                return Err(ContractViolation::OutOfBounds {
                    field,
                    min: 0,
                    max: crate::error::len_i64(validation::MAX_RIVAL_ITEMS),
                    got: i64::from(count),
                });
            }
        }
        validation::sequence(self.objectives.len(), "rival.projection.objectives")?;
        validation::sequence(self.omissions.len(), "rival.projection.omissions")?;
        let actual_denominator = self
            .objectives
            .len()
            .checked_add(self.omissions.len())
            .ok_or(ContractViolation::OutOfBounds {
                field: "rival.projection.objective_denominator",
                min: 0,
                max: i64::from(u32::MAX),
                got: i64::MAX,
            })?;
        if usize::try_from(self.objective_denominator).ok() != Some(actual_denominator) {
            return binding(
                "rival.projection.objective_denominator",
                "denominator differs from retained plus omitted rows",
            );
        }
        let mut previous_objective: Option<&ArtifactId> = None;
        for objective in &self.objectives {
            objective.validate()?;
            if previous_objective.is_some_and(|prior| prior >= &objective.objective_id) {
                return binding(
                    "rival.projection.objectives",
                    "objective identities must be unique and canonically ordered",
                );
            }
            previous_objective = Some(&objective.objective_id);
        }
        let mut previous_omission: Option<&RivalObjectiveOmission> = None;
        for omission in &self.omissions {
            omission.validate()?;
            if previous_omission.is_some_and(|prior| prior >= omission) {
                return binding(
                    "rival.projection.omissions",
                    "omissions must be unique and canonically ordered",
                );
            }
            previous_omission = Some(omission);
        }
        match self.disposition {
            RivalModelSetDisposition::Complete
                if self.objectives.is_empty() || !self.omissions.is_empty() =>
            {
                return binding(
                    "rival.projection.disposition",
                    "complete projection requires objectives and no omissions",
                );
            }
            RivalModelSetDisposition::InsufficientRivals if self.declared_model_count >= 2 => {
                return binding(
                    "rival.projection.disposition",
                    "insufficient-rivals requires fewer than two declared models",
                );
            }
            _ => {}
        }
        Ok(())
    }
}

fn binding<T>(field: &'static str, reason: &str) -> Result<T, ContractViolation> {
    Err(ContractViolation::BindingMismatch {
        field,
        reason: reason.to_owned(),
    })
}
