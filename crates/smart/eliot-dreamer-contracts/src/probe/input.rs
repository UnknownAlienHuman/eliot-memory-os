//! Closed versioned immutable probe input declarations for the bounded probe planner.
//!
//! Cell `smart.dreamer.contracts`. This module owns the contract half of issue
//! #1073: an immutable [`ProbeInput`] joining exact job/operation/requester/
//! task/attempt/scope/fence identity, manifest/source digests, a digest-pinned
//! A05 grounding reference, rival declaration/prediction references, a
//! digest-pinned objective, one finite [`PossibleResultSchema`], a
//! digest-pinned affordance reference, expected observable/verifier/coverage
//! owners, applicability, typed owners, capability availability, typed bounded
//! parameters, source/snapshot identity, external admission/execution/evidence/
//! verifier owners, and lifecycle cancellation/cleanup/reconciliation/repeat
//! references, with a frozen canonical digest.
//!
//! Inputs are descriptive only. They never invent a validation receipt, never
//! claim A05 accepted newly attached data, never authorize, permit, execute,
//! reserve, resolve rivals, promote truth, grant authority, or issue Finish.
//! References to requirements never confer consent, permission, or capacity.
//! Unknown stays explicit and never reads as zero, unlimited, safe, cheap,
//! feasible, permitted, or granted. There is no ordering across independent
//! dimensions and no cross-dimension score.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::{CoverageDenominator, SnapshotRef, ValidityBounds};
use eliot_evaluation_contracts::{ExpectedObservableSpec, PlannedVerifierRef};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    error::ContractViolation,
    job::{JobClass, Requester},
    rival::{RivalDeclarationSetRef, RivalModelRef, RivalPredictionRef},
};

use super::{
    bounds::check_sequence,
    objective::{ProbeObjectiveRef, ProbeOwnerRef},
    result::PossibleResultSchema,
    validation,
};

/// Wire revision for one closed probe input declaration.
pub const PROBE_INPUT_SCHEMA_VERSION: u32 = 1;

/// Descriptive capability-availability state for one probe input.
///
/// `Unknown`/`Unavailable`/`NotApplicable` are explicit and incomparable:
/// they never read as available.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum ProbeCapabilityAvailability {
    Available { detail: String },
    Unavailable { reason: String },
    Unknown { reason: String },
    NotApplicable { reason: String },
}

impl ProbeCapabilityAvailability {
    /// Validates the bounded declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match self {
            Self::Available { detail } => {
                validation::text(detail, "probe.input.capability.detail")
            }
            Self::Unavailable { reason }
            | Self::Unknown { reason }
            | Self::NotApplicable { reason } => {
                validation::text(reason, "probe.input.capability.reason")
            }
        }
    }

    /// Whether the dimension carries an explicit known determination.
    pub fn is_known(&self) -> bool {
        !matches!(self, Self::Unknown { .. })
    }

    /// Whether the input declares available capability. Unknown, unavailable,
    /// and not-applicable never read as available.
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }
}

/// One typed bounded probe parameter in canonical `(name, value)` order.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ProbeParam {
    /// Stable parameter name, non-blank and bounded.
    pub name: String,
    /// Bounded parameter value, non-blank.
    pub value: String,
}

impl ProbeParam {
    /// Validates the bounded parameter shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::text(&self.name, "probe.input.param.name")?;
        validation::text(&self.value, "probe.input.param.value")
    }
}

/// Exact source identity bound by one probe input.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct ProbeSourceRef {
    /// Stable source handle.
    pub handle: ArtifactId,
    /// Digest of the exact retained source content.
    pub content_digest: String,
    /// Revision supplied by the source owner.
    pub source_revision: String,
}

impl ProbeSourceRef {
    /// Validates the source identity without resolving its payload.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::text(self.handle.as_str(), "probe.input.source.handle")?;
        validation::digest(
            &self.content_digest,
            "probe.input.source.content_digest",
        )?;
        validation::text(
            &self.source_revision,
            "probe.input.source.source_revision",
        )
    }
}

/// Digest-pinned reference to one A05-bound grounding candidate.
///
/// Pins the candidate by its receipt-excluded output digest. It carries no
/// receipt, invents no acceptance, and claims nothing about newly attached
/// data: A05 remains the semantic acceptance owner.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeGroundingRef {
    /// Receipt-excluded output digest of the bound candidate.
    pub candidate_digest: String,
}

impl ProbeGroundingRef {
    /// Binds an already-validated candidate by its output digest.
    pub fn from_candidate(
        candidate: &crate::validation::ValidatedGroundingCandidate,
    ) -> Result<Self, ContractViolation> {
        let digest = candidate
            .output_digest()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.input.grounding.candidate_digest",
                reason: error.to_string(),
            })?;
        let reference = Self {
            candidate_digest: digest,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Validates the pinned digest without resolving the candidate.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::digest(
            &self.candidate_digest,
            "probe.input.grounding.candidate_digest",
        )
    }
}

/// Digest-pinned reference to one supplied inquiry-affordance descriptor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeAffordanceRef {
    /// Stable identity of the bound descriptor.
    pub affordance_id: ArtifactId,
    /// Frozen canonical digest of the bound descriptor.
    pub affordance_digest: String,
}

impl ProbeAffordanceRef {
    /// Validates the bound descriptor identity without resolving it.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::text(
            self.affordance_id.as_str(),
            "probe.input.affordance.affordance_id",
        )?;
        validation::digest(
            &self.affordance_digest,
            "probe.input.affordance.affordance_digest",
        )
    }
}

/// Exact external owners for admission, execution, evidence, and verifier planes.
///
/// Each owner is a typed [`ProbeOwnerRef`]: a reference, never an authority
/// claim. References never confer consent, permission, or capacity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeExternalOwners {
    /// Owner that admits the inquiry for planning.
    pub admission: ProbeOwnerRef,
    /// Owner that would execute the inquiry, if ever planned.
    pub execution: ProbeOwnerRef,
    /// Owner that retains inquiry evidence.
    pub evidence: ProbeOwnerRef,
    /// Owner that verifies the inquiry outcome.
    pub verifier: ProbeOwnerRef,
}

impl ProbeExternalOwners {
    /// Validates the four typed owner references.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validate_owner_ref(&self.admission, "probe.input.external.admission")?;
        validate_owner_ref(&self.execution, "probe.input.external.execution")?;
        validate_owner_ref(&self.evidence, "probe.input.external.evidence")?;
        validate_owner_ref(&self.verifier, "probe.input.external.verifier")
    }
}

/// Failed-repeat and change-of-conditions reference for one probe input.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeRepeatRef {
    /// Stable identity of the prior requirement or attempt referenced.
    pub requirement_id: String,
    /// Bounded reason the repeat or condition change is recorded.
    pub reason: String,
}

impl ProbeRepeatRef {
    /// Validates the repeat reference shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::text(
            &self.requirement_id,
            "probe.input.lifecycle.repeat.requirement_id",
        )?;
        validation::text(&self.reason, "probe.input.lifecycle.repeat.reason")
    }
}

/// Lifecycle requirements preserved by one probe input.
///
/// Cancellation, cleanup/rollback, unknown-effect reconciliation, and
/// failed-repeat/change-of-conditions references are declarations only:
/// they describe required handling without executing anything.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeLifecycle {
    /// Bounded cancellation requirement.
    pub cancellation: String,
    /// Bounded cleanup/rollback requirement.
    pub cleanup_rollback: String,
    /// Bounded unknown-effect reconciliation requirement.
    pub reconciliation: String,
    /// Failed-repeat and change-of-conditions reference.
    pub repeat: ProbeRepeatRef,
}

impl ProbeLifecycle {
    /// Validates the lifecycle declaration shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::text(
            &self.cancellation,
            "probe.input.lifecycle.cancellation",
        )?;
        validation::text(
            &self.cleanup_rollback,
            "probe.input.lifecycle.cleanup_rollback",
        )?;
        validation::text(
            &self.reconciliation,
            "probe.input.lifecycle.reconciliation",
        )?;
        self.repeat.validate()
    }
}

/// Digest-pinned identity used when a planner binds one probe input.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeInputRef {
    /// Stable identity of the bound input.
    pub input_id: ArtifactId,
    /// Frozen canonical digest of the bound input.
    pub input_digest: String,
}

impl ProbeInputRef {
    /// Validates the bound input identity without resolving it.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::text(self.input_id.as_str(), "probe.input_ref.input_id")?;
        validation::digest(&self.input_digest, "probe.input_ref.input_digest")
    }
}

fn validate_owner_ref(owner: &ProbeOwnerRef, field: &'static str) -> Result<(), ContractViolation> {
    match owner {
        ProbeOwnerRef::Source { owner } => validation::text(owner.as_str(), field),
        ProbeOwnerRef::Verifier { verifier_id } => {
            validation::text(verifier_id.as_str(), field)
        }
        ProbeOwnerRef::Unavailable { reason } => validation::text(reason, field),
    }
}

/// One closed immutable probe input declaration.
///
/// Joins exact job/operation/requester/task/attempt/scope/fence identity,
/// manifest/source digests, a digest-pinned grounding reference, rival
/// references, a digest-pinned objective, one finite result schema, a
/// digest-pinned affordance reference, expected observable/verifier/coverage
/// owners, applicability, typed owners, capability availability, typed bounded
/// parameters, source/snapshot identity, external owners, and lifecycle
/// references, with a frozen canonical digest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProbeInput {
    /// Wire revision; always [`PROBE_INPUT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Stable identity of this input.
    pub input_id: ArtifactId,
    /// Task identity copied exactly from the bound job.
    pub task_id: TaskId,
    /// Scope copied exactly from the bound job.
    pub scope: String,
    /// State fence copied exactly from the bound job.
    pub state_fence: StateFence,
    /// Closed job class selecting the owning brief surface.
    pub job_class: JobClass,
    /// Authenticated requester binding.
    pub requester: Requester,
    /// Non-blank operation identity.
    pub operation_id: String,
    /// Non-blank attempt identity.
    pub attempt_id: String,
    /// Lowercase SHA-256 digest of the frozen source manifest.
    pub manifest_digest: String,
    /// Exact source identities in canonical handle order.
    pub sources: BTreeSet<ProbeSourceRef>,
    /// Digest-pinned A05 grounding reference; carries no receipt.
    pub grounding: ProbeGroundingRef,
    /// Exact identity of the bound rival declaration set.
    pub rival_set: RivalDeclarationSetRef,
    /// Bound rival model references in canonical identity order.
    pub rival_models: BTreeSet<RivalModelRef>,
    /// Bound rival prediction references in canonical identity order.
    pub rival_predictions: BTreeSet<RivalPredictionRef>,
    /// Digest-pinned probe objective.
    pub objective: ProbeObjectiveRef,
    /// Finite possible-result schema with exact branch cover.
    pub result_schema: PossibleResultSchema,
    /// Digest-pinned supplied affordance descriptor.
    pub affordance: ProbeAffordanceRef,
    /// Expected observable the probe is declared to establish.
    pub expected_observable: ExpectedObservableSpec,
    /// Planned verifier for the probe outcome.
    pub verifier: PlannedVerifierRef,
    /// Exact coverage denominator the probe applies under.
    pub coverage: CoverageDenominator,
    /// Scope, time, version, and precision bounds of the probe.
    pub applicability: ValidityBounds,
    /// Typed owner reference; never an authority claim.
    pub owner: ProbeOwnerRef,
    /// Exact external admission/execution/evidence/verifier owners.
    pub external_owners: ProbeExternalOwners,
    /// Descriptive capability-availability state.
    pub capability: ProbeCapabilityAvailability,
    /// Typed bounded parameters in canonical name order.
    pub params: BTreeSet<ProbeParam>,
    /// Owned snapshot the probe inputs were frozen from.
    pub snapshot: SnapshotRef,
    /// Preserved lifecycle requirements.
    pub lifecycle: ProbeLifecycle,
    /// Frozen canonical digest of the preimage above, excluding itself.
    pub digest: String,
}

/// Constructor data for [`ProbeInput`]; `schema_version` and `digest` are
/// assigned by [`ProbeInput::new`].
#[derive(Clone, Debug)]
pub struct ProbeInputParams {
    /// Stable identity of this input.
    pub input_id: ArtifactId,
    /// Task identity copied exactly from the bound job.
    pub task_id: TaskId,
    /// Scope copied exactly from the bound job.
    pub scope: String,
    /// State fence copied exactly from the bound job.
    pub state_fence: StateFence,
    /// Closed job class selecting the owning brief surface.
    pub job_class: JobClass,
    /// Authenticated requester binding.
    pub requester: Requester,
    /// Non-blank operation identity.
    pub operation_id: String,
    /// Non-blank attempt identity.
    pub attempt_id: String,
    /// Lowercase SHA-256 digest of the frozen source manifest.
    pub manifest_digest: String,
    /// Exact source identities; canonicalized by construction.
    pub sources: BTreeSet<ProbeSourceRef>,
    /// Digest-pinned A05 grounding reference; carries no receipt.
    pub grounding: ProbeGroundingRef,
    /// Exact identity of the bound rival declaration set.
    pub rival_set: RivalDeclarationSetRef,
    /// Bound rival model references; canonicalized by construction.
    pub rival_models: BTreeSet<RivalModelRef>,
    /// Bound rival prediction references; canonicalized by construction.
    pub rival_predictions: BTreeSet<RivalPredictionRef>,
    /// Digest-pinned probe objective.
    pub objective: ProbeObjectiveRef,
    /// Finite possible-result schema with exact branch cover.
    pub result_schema: PossibleResultSchema,
    /// Digest-pinned supplied affordance descriptor.
    pub affordance: ProbeAffordanceRef,
    /// Expected observable the probe is declared to establish.
    pub expected_observable: ExpectedObservableSpec,
    /// Planned verifier for the probe outcome.
    pub verifier: PlannedVerifierRef,
    /// Exact coverage denominator the probe applies under.
    pub coverage: CoverageDenominator,
    /// Scope, time, version, and precision bounds of the probe.
    pub applicability: ValidityBounds,
    /// Typed owner reference; never an authority claim.
    pub owner: ProbeOwnerRef,
    /// Exact external admission/execution/evidence/verifier owners.
    pub external_owners: ProbeExternalOwners,
    /// Descriptive capability-availability state.
    pub capability: ProbeCapabilityAvailability,
    /// Typed bounded parameters; canonicalized by construction.
    pub params: BTreeSet<ProbeParam>,
    /// Owned snapshot the probe inputs were frozen from.
    pub snapshot: SnapshotRef,
    /// Preserved lifecycle requirements.
    pub lifecycle: ProbeLifecycle,
}

impl ProbeInput {
    /// Constructs a canonical input with a frozen digest.
    pub fn new(params: ProbeInputParams) -> Result<Self, ContractViolation> {
        let mut input = Self {
            schema_version: PROBE_INPUT_SCHEMA_VERSION,
            input_id: params.input_id,
            task_id: params.task_id,
            scope: params.scope,
            state_fence: params.state_fence,
            job_class: params.job_class,
            requester: params.requester,
            operation_id: params.operation_id,
            attempt_id: params.attempt_id,
            manifest_digest: params.manifest_digest,
            sources: params.sources,
            grounding: params.grounding,
            rival_set: params.rival_set,
            rival_models: params.rival_models,
            rival_predictions: params.rival_predictions,
            objective: params.objective,
            result_schema: params.result_schema,
            affordance: params.affordance,
            expected_observable: params.expected_observable,
            verifier: params.verifier,
            coverage: params.coverage,
            applicability: params.applicability,
            owner: params.owner,
            external_owners: params.external_owners,
            capability: params.capability,
            params: params.params,
            snapshot: params.snapshot,
            lifecycle: params.lifecycle,
            digest: String::new(),
        };
        validation::preflight(&input)?;
        input.validate_shape()?;
        input.digest = input.compute_digest_unchecked()?;
        validation::preflight(&input)?;
        Ok(input)
    }

    /// Validates the input shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        validation::digest(&self.digest, "probe.input.digest")?;
        let expected = self.compute_digest_unchecked()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.input.digest",
                reason: "probe input digest does not match declaration".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the canonical digest after validating the input shape.
    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::preflight(self)?;
        self.validate_shape()?;
        self.compute_digest_unchecked()
    }

    fn compute_digest_unchecked(&self) -> Result<String, ContractViolation> {
        #[derive(Serialize)]
        struct Preimage<'a> {
            schema_version: u32,
            input_id: &'a ArtifactId,
            task_id: &'a TaskId,
            scope: &'a str,
            state_fence: &'a StateFence,
            job_class: JobClass,
            requester: &'a Requester,
            operation_id: &'a str,
            attempt_id: &'a str,
            manifest_digest: &'a str,
            sources: &'a BTreeSet<ProbeSourceRef>,
            grounding: &'a ProbeGroundingRef,
            rival_set: &'a RivalDeclarationSetRef,
            rival_models: &'a BTreeSet<RivalModelRef>,
            rival_predictions: &'a BTreeSet<RivalPredictionRef>,
            objective: &'a ProbeObjectiveRef,
            result_schema: &'a PossibleResultSchema,
            affordance: &'a ProbeAffordanceRef,
            expected_observable: &'a ExpectedObservableSpec,
            verifier: &'a PlannedVerifierRef,
            coverage: &'a CoverageDenominator,
            applicability: &'a ValidityBounds,
            owner: &'a ProbeOwnerRef,
            external_owners: &'a ProbeExternalOwners,
            capability: &'a ProbeCapabilityAvailability,
            params: &'a BTreeSet<ProbeParam>,
            snapshot: &'a SnapshotRef,
            lifecycle: &'a ProbeLifecycle,
        }
        validation::canonical_digest(&Preimage {
            schema_version: self.schema_version,
            input_id: &self.input_id,
            task_id: &self.task_id,
            scope: &self.scope,
            state_fence: &self.state_fence,
            job_class: self.job_class,
            requester: &self.requester,
            operation_id: &self.operation_id,
            attempt_id: &self.attempt_id,
            manifest_digest: &self.manifest_digest,
            sources: &self.sources,
            grounding: &self.grounding,
            rival_set: &self.rival_set,
            rival_models: &self.rival_models,
            rival_predictions: &self.rival_predictions,
            objective: &self.objective,
            result_schema: &self.result_schema,
            affordance: &self.affordance,
            expected_observable: &self.expected_observable,
            verifier: &self.verifier,
            coverage: &self.coverage,
            applicability: &self.applicability,
            owner: &self.owner,
            external_owners: &self.external_owners,
            capability: &self.capability,
            params: &self.params,
            snapshot: &self.snapshot,
            lifecycle: &self.lifecycle,
        })
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one bounded pass validates the complete input join"
    )]
    fn validate_shape(&self) -> Result<(), ContractViolation> {
        if self.schema_version != PROBE_INPUT_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.input.schema_version",
                reason: "unsupported probe input schema".to_owned(),
            });
        }
        validation::text(self.input_id.as_str(), "probe.input.input_id")?;
        validation::text(self.task_id.as_str(), "probe.input.task_id")?;
        validation::text(&self.scope, "probe.input.scope")?;
        self.state_fence
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.input.state_fence",
                reason: error.to_string(),
            })?;
        self.requester.validate()?;
        validation::text(&self.operation_id, "probe.input.operation_id")?;
        validation::text(&self.attempt_id, "probe.input.attempt_id")?;
        validation::digest(&self.manifest_digest, "probe.input.manifest_digest")?;
        check_sequence(self.sources.len(), "probe.input.sources")?;
        for source in &self.sources {
            source.validate()?;
        }
        check_source_table(&self.sources)?;
        self.grounding.validate()?;
        self.rival_set.validate()?;
        check_sequence(self.rival_models.len(), "probe.input.rival_models")?;
        for model in &self.rival_models {
            model.validate()?;
        }
        check_rival_model_table(&self.rival_models)?;
        check_sequence(
            self.rival_predictions.len(),
            "probe.input.rival_predictions",
        )?;
        for prediction in &self.rival_predictions {
            prediction.validate()?;
        }
        check_rival_prediction_table(&self.rival_predictions)?;
        self.objective.validate()?;
        self.result_schema.validate()?;
        self.affordance.validate()?;
        self.expected_observable
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.input.expected_observable",
                reason: error.to_string(),
            })?;
        self.verifier
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.input.verifier",
                reason: error.to_string(),
            })?;
        self.coverage
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.input.coverage",
                reason: error.to_string(),
            })?;
        self.applicability
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.input.applicability",
                reason: error.to_string(),
            })?;
        if self.applicability.scope != self.scope {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.input.applicability",
                reason: "applicability scope differs from input scope".to_owned(),
            });
        }
        if self.coverage.scope != self.scope {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.input.coverage",
                reason: "coverage scope differs from input scope".to_owned(),
            });
        }
        if self.coverage.fence != self.state_fence {
            return Err(ContractViolation::BindingMismatch {
                field: "probe.input.coverage",
                reason: "coverage fence differs from input fence".to_owned(),
            });
        }
        validate_owner_ref(&self.owner, "probe.input.owner")?;
        self.external_owners.validate()?;
        self.capability.validate()?;
        check_sequence(self.params.len(), "probe.input.params")?;
        for param in &self.params {
            param.validate()?;
        }
        check_param_table(&self.params)?;
        self.snapshot
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "probe.input.snapshot",
                reason: error.to_string(),
            })?;
        self.lifecycle.validate()?;
        Ok(())
    }
}

fn check_source_table(entries: &BTreeSet<ProbeSourceRef>) -> Result<(), ContractViolation> {
    let mut digests: BTreeMap<&ArtifactId, (&str, &str)> = BTreeMap::new();
    for entry in entries {
        if let Some((digest, revision)) = digests.get(&entry.handle) {
            if *digest != entry.content_digest.as_str()
                || *revision != entry.source_revision.as_str()
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.input.sources",
                    reason: "one source identity maps to changed content".to_owned(),
                });
            }
            return Err(ContractViolation::BindingMismatch {
                field: "probe.input.sources",
                reason: "duplicate source identity".to_owned(),
            });
        }
        digests.insert(
            &entry.handle,
            (
                entry.content_digest.as_str(),
                entry.source_revision.as_str(),
            ),
        );
    }
    Ok(())
}

fn check_rival_model_table(entries: &BTreeSet<RivalModelRef>) -> Result<(), ContractViolation> {
    let mut seen: BTreeMap<&ArtifactId, &RivalModelRef> = BTreeMap::new();
    for entry in entries {
        if let Some(previous) = seen.get(&entry.model_id) {
            if *previous != entry {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.input.rival_models",
                    reason: "one model identity maps to changed declaration".to_owned(),
                });
            }
            return Err(ContractViolation::BindingMismatch {
                field: "probe.input.rival_models",
                reason: "duplicate rival model identity".to_owned(),
            });
        }
        seen.insert(&entry.model_id, entry);
    }
    Ok(())
}

fn check_rival_prediction_table(
    entries: &BTreeSet<RivalPredictionRef>,
) -> Result<(), ContractViolation> {
    let mut seen: BTreeMap<&ArtifactId, &RivalPredictionRef> = BTreeMap::new();
    for entry in entries {
        if let Some(previous) = seen.get(&entry.prediction_id) {
            if *previous != entry {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.input.rival_predictions",
                    reason: "one prediction identity maps to changed declaration".to_owned(),
                });
            }
            return Err(ContractViolation::BindingMismatch {
                field: "probe.input.rival_predictions",
                reason: "duplicate rival prediction identity".to_owned(),
            });
        }
        seen.insert(&entry.prediction_id, entry);
    }
    Ok(())
}

fn check_param_table(entries: &BTreeSet<ProbeParam>) -> Result<(), ContractViolation> {
    let mut values: BTreeMap<&str, &str> = BTreeMap::new();
    for entry in entries {
        if let Some(previous) = values.get(entry.name.as_str()) {
            if *previous != entry.value.as_str() {
                return Err(ContractViolation::BindingMismatch {
                    field: "probe.input.params",
                    reason: "one parameter name maps to changed value".to_owned(),
                });
            }
            return Err(ContractViolation::BindingMismatch {
                field: "probe.input.params",
                reason: "duplicate probe parameter".to_owned(),
            });
        }
        values.insert(entry.name.as_str(), entry.value.as_str());
    }
    Ok(())
}
