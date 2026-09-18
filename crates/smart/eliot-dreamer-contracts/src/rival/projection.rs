//! Owner-neutral bounded immutable projection of one rival-model outcome.
//!
//! Cell `smart.dreamer.contracts`. This module owns the contract half of issue
//! #1236: a bounded immutable [`RivalModelSet`] projection carrying exact
//! task/scope/fence/input/policy identity, declaration-set identity, retained
//! discriminators, unresolved discriminator requirements, coverage summaries,
//! an explicit omission frontier, and a canonical digest.
//!
//! The projection is not the analysis implementation object. The rich
//! packing/analysis internals stay owned by the A-16b implementation cell, and
//! the deterministic conversion from that rich result to this projection lives
//! in the A-16b-owned conversion constructor (its `result.rs` owner), which is
//! out of scope here. This module never depends on that cell: the dependency
//! direction stays A-16b depends on A-03, never the reverse.
//!
//! True sets are canonicalized: [`RivalModelSet::new`] sorts discriminators,
//! unresolved requirements, and the omission frontier into canonical address
//! order, so set-only permutations preserve the digest. There are no embedded
//! semantic sequences in this projection; any content change alters the digest.

use std::cmp::Ordering;
use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, StateFence, TaskId};
use eliot_epistemic_contracts::ValidityBounds;
use eliot_evaluation_contracts::ExpectedObservableSpec;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::model::{MaterialClaimRef, RivalModelRef, RivalPredictionRef};
use super::prediction::ConditionAssumptionRef;
use super::validation;
use crate::error::ContractViolation;

/// Wire revision for the owner-neutral rival-model projection.
pub const RIVAL_MODEL_SET_SCHEMA_VERSION: u32 = 1;

/// The declaration facet that left a discriminator comparison incomplete.
///
/// Ordering between facets is canonical address order only (see
/// [`requirement_order_key`); it never ranks one facet above another
/// semantically.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequirementFacet {
    PredictionReferences,
    Expected,
    Falsifier,
    ModelFrontier,
}

/// Why an exact discriminator requirement could not be emitted as a match.
///
/// `Unknown` and `Unavailable` stay explicit: they are never read as retained,
/// safe, or resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequirementReason {
    Unknown,
    Unavailable,
    InternallyIdentical,
    NotApplicable,
    OutsideAnalysisFrontier,
}

/// Compact address of a peer prediction, without copying its declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DiscriminatorPeerAddress {
    /// Row address of the peer model in the bound declaration-set model table.
    pub model_row: u32,
    /// Entry address of the peer prediction reference, when the facet applies
    /// to a prediction rather than the model frontier.
    pub prediction_ref_entry: Option<u32>,
}

/// One explicit unresolved discriminator requirement with source identity.
///
/// Every omitted or unresolvable comparison is represented here with its exact
/// source address, facet, optional peer, and closed reason, so the projection
/// accounts for the complete denominator without copying declaration tables.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UnresolvedDiscriminatorRequirement {
    /// Row address of the model in the bound declaration-set model table.
    pub model_row: u32,
    /// Entry address of the prediction reference, when the facet applies to a
    /// prediction rather than the model frontier.
    pub prediction_ref_entry: Option<u32>,
    /// The declaration facet that made the comparison incomplete.
    pub facet: RequirementFacet,
    /// Address of the peer comparison endpoint, when one was identified.
    pub peer: Option<DiscriminatorPeerAddress>,
    /// Why no exact match could be emitted.
    pub reason: RequirementReason,
}

impl UnresolvedDiscriminatorRequirement {
    /// Validates facet/reason accounting and peer address shape.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        if self.reason == RequirementReason::OutsideAnalysisFrontier
            && self.facet != RequirementFacet::ModelFrontier
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.projection.unresolved.facet",
                reason: "outside-frontier reason requires the model-frontier facet".to_owned(),
            });
        }
        if matches!(
            self.facet,
            RequirementFacet::Expected | RequirementFacet::Falsifier
        ) && self.prediction_ref_entry.is_none()
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.projection.unresolved.prediction_ref_entry",
                reason: "expected/falsifier facets require a prediction entry address".to_owned(),
            });
        }
        if self.facet == RequirementFacet::ModelFrontier && self.prediction_ref_entry.is_some() {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.projection.unresolved.prediction_ref_entry",
                reason: "model-frontier facet must not carry a prediction entry address".to_owned(),
            });
        }
        if let Some(peer) = &self.peer {
            validation::preflight(peer)?;
            if peer.model_row == self.model_row
                && peer.prediction_ref_entry == self.prediction_ref_entry
            {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.projection.unresolved.peer",
                    reason: "requirement peer must differ from its own address".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// One owner-neutral inert cross-match between an expected and a falsifying
/// observable declaration.
///
/// This is the contract form of the A-16b inert discriminator: exact
/// digest-pinned model and prediction references on both endpoints, the shared
/// material target, shared applicability, shared assumption references, and
/// the opaque expected observable. No matcher is executed here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RetainedDiscriminator {
    /// Model whose prediction declares the observable as expected.
    pub expected_model: RivalModelRef,
    /// Prediction declaring the expected observable.
    pub expected_prediction: RivalPredictionRef,
    /// Model whose prediction declares the same observable as a falsifier.
    pub falsifying_model: RivalModelRef,
    /// Prediction declaring the falsifying observable.
    pub falsifying_prediction: RivalPredictionRef,
    /// Exact material target shared by both declarations.
    pub target: MaterialClaimRef,
    /// Exact applicability shared by both declarations.
    pub applicability: ValidityBounds,
    /// Exact assumption references shared by both declarations.
    pub condition_assumptions: BTreeSet<ConditionAssumptionRef>,
    /// Exact opaque owner observable; no matcher is executed here.
    pub observable: ExpectedObservableSpec,
}

impl RetainedDiscriminator {
    /// Validates endpoint identity, shared target/applicability, and the
    /// opaque observable declaration without executing anything.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.expected_model.validate()?;
        self.expected_prediction.validate()?;
        self.falsifying_model.validate()?;
        self.falsifying_prediction.validate()?;
        self.target.validate()?;
        self.applicability
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "rival.projection.discriminator.applicability",
                reason: error.to_string(),
            })?;
        validation::sequence(
            self.condition_assumptions.len(),
            "rival.projection.discriminator.condition_assumptions",
        )?;
        for assumption in &self.condition_assumptions {
            assumption.validate()?;
        }
        self.observable
            .validate()
            .map_err(|error| ContractViolation::BindingMismatch {
                field: "rival.projection.discriminator.observable",
                reason: error.to_string(),
            })?;
        if self.expected_model == self.falsifying_model
            && self.expected_prediction == self.falsifying_prediction
        {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.projection.discriminator.endpoints",
                reason: "expected and falsifying endpoints must differ".to_owned(),
            });
        }
        Ok(())
    }
}

/// Closed coverage status for one declaration table of the projection.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RivalCoverageStatus {
    Complete,
    Partial,
    Unknown,
}

/// Bounded coverage summary for one declaration table.
///
/// A `Complete` claim must bind the exact denominator digest. `Unknown` binds
/// no denominator: an unknown table never reads as covered.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RivalCoverageSummary {
    /// Closed coverage status of the table.
    pub status: RivalCoverageStatus,
    /// Digest of the exact denominator the status applies to, when known.
    pub denominator_digest: Option<String>,
}

impl RivalCoverageSummary {
    /// Validates the status/denominator accounting without resolving tables.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        match (&self.status, &self.denominator_digest) {
            (RivalCoverageStatus::Complete | RivalCoverageStatus::Partial, Some(digest)) => {
                validation::digest(digest, "rival.projection.coverage.denominator_digest")?;
            }
            (RivalCoverageStatus::Complete, None) => {
                return Err(ContractViolation::MissingField(
                    "rival.projection.coverage.denominator_digest",
                ));
            }
            (RivalCoverageStatus::Unknown, Some(_)) => {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.projection.coverage.denominator_digest",
                    reason: "unknown coverage must not bind a denominator digest".to_owned(),
                });
            }
            (RivalCoverageStatus::Partial | RivalCoverageStatus::Unknown, None) => {}
        }
        Ok(())
    }
}

/// Exact identity of the bound declaration set, without copying its tables.
///
/// Lineage is preserved by identity: the projection binds the declaration
/// set's stable ID and frozen digest exactly.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RivalDeclarationSetRef {
    /// Stable identity of the bound declaration set.
    pub set_id: ArtifactId,
    /// Frozen canonical digest of the bound declaration set.
    pub digest: String,
}

impl RivalDeclarationSetRef {
    /// Validates the bound declaration-set identity.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        validation::artifact(&self.set_id, "rival.projection.declaration_set.set_id")?;
        validation::digest(&self.digest, "rival.projection.declaration_set.digest")
    }
}

/// Bounded immutable owner-neutral projection of one rival-model outcome.
///
/// Carries exact task/scope/fence/input/policy identity, declaration-set
/// identity, retained discriminators, unresolved requirements, per-table
/// coverage summaries, an explicit omission frontier, and a frozen canonical
/// digest. Discriminators, requirements, and frontier entries are true sets:
/// construction canonicalizes their order, so set-only permutations preserve
/// the digest while any content change alters it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RivalModelSet {
    /// Wire revision; always [`RIVAL_MODEL_SET_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Stable identity of this projection, distinct from the declaration-set ID.
    pub set_id: ArtifactId,
    /// Task identity copied exactly from the bound input.
    pub task_id: TaskId,
    /// Scope copied exactly from the bound input.
    pub scope: String,
    /// State fence copied exactly from the bound input.
    pub state_fence: StateFence,
    /// Lineage digest of the input bundle the analysis packed.
    pub bundle_digest: String,
    /// Lineage digest of the validated input the analysis consumed.
    pub validated_input_digest: String,
    /// Exact identity of the bound declaration set.
    pub declaration_set: RivalDeclarationSetRef,
    /// Bounding-policy identity supplied by the caller.
    pub policy_id: String,
    /// Digest of the exact bounding-policy bytes.
    pub policy_digest: String,
    /// Retained inert cross-matches in canonical address order.
    pub discriminators: Vec<RetainedDiscriminator>,
    /// Every omitted/unresolved comparison in canonical address order.
    pub unresolved: Vec<UnresolvedDiscriminatorRequirement>,
    /// Coverage summary for the bound model table.
    pub model_coverage: RivalCoverageSummary,
    /// Coverage summary for the bound source table.
    pub source_coverage: RivalCoverageSummary,
    /// Explicit bounded frontier addresses with no retained comparison.
    pub omission_frontier: Vec<ArtifactId>,
    /// Frozen canonical digest of the preimage above, excluding itself.
    pub digest: String,
}

/// Constructor data for [`RivalModelSet`]; `schema_version` and `digest` are
/// assigned by [`RivalModelSet::new`].
#[derive(Clone, Debug)]
pub struct RivalModelSetParams {
    /// Stable identity of this projection, distinct from the declaration-set ID.
    pub set_id: ArtifactId,
    /// Task identity copied exactly from the bound input.
    pub task_id: TaskId,
    /// Scope copied exactly from the bound input.
    pub scope: String,
    /// State fence copied exactly from the bound input.
    pub state_fence: StateFence,
    /// Lineage digest of the input bundle the analysis packed.
    pub bundle_digest: String,
    /// Lineage digest of the validated input the analysis consumed.
    pub validated_input_digest: String,
    /// Exact identity of the bound declaration set.
    pub declaration_set: RivalDeclarationSetRef,
    /// Bounding-policy identity supplied by the caller.
    pub policy_id: String,
    /// Digest of the exact bounding-policy bytes.
    pub policy_digest: String,
    /// Retained inert cross-matches; canonicalized by construction.
    pub discriminators: Vec<RetainedDiscriminator>,
    /// Every omitted/unresolved comparison; canonicalized by construction.
    pub unresolved: Vec<UnresolvedDiscriminatorRequirement>,
    /// Coverage summary for the bound model table.
    pub model_coverage: RivalCoverageSummary,
    /// Coverage summary for the bound source table.
    pub source_coverage: RivalCoverageSummary,
    /// Explicit bounded frontier addresses with no retained comparison.
    pub omission_frontier: Vec<ArtifactId>,
}

impl RivalModelSet {
    /// Constructs a canonical projection, sorting only its true-set tables.
    pub fn new(params: RivalModelSetParams) -> Result<Self, ContractViolation> {
        let mut set = Self {
            schema_version: RIVAL_MODEL_SET_SCHEMA_VERSION,
            set_id: params.set_id,
            task_id: params.task_id,
            scope: params.scope,
            state_fence: params.state_fence,
            bundle_digest: params.bundle_digest,
            validated_input_digest: params.validated_input_digest,
            declaration_set: params.declaration_set,
            policy_id: params.policy_id,
            policy_digest: params.policy_digest,
            discriminators: params.discriminators,
            unresolved: params.unresolved,
            model_coverage: params.model_coverage,
            source_coverage: params.source_coverage,
            omission_frontier: params.omission_frontier,
            digest: String::new(),
        };
        validation::preflight(&set)?;
        set.validate_shape(false)?;
        set.sort_tables();
        validation::preflight(&set)?;
        set.validate_content()?;
        set.digest = set.compute_digest_unchecked()?;
        validation::preflight(&set)?;
        Ok(set)
    }

    /// Validates identity, tables, canonical order, and the frozen digest.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validation::preflight(self)?;
        self.validate_content()?;
        validation::digest(&self.digest, "rival.projection.digest")?;
        let expected = self.compute_digest_unchecked()?;
        if self.digest != expected {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.projection.digest",
                reason: "projection digest does not match its canonical content".to_owned(),
            });
        }
        Ok(())
    }

    /// Computes the canonical digest after validating the projection content.
    pub fn compute_digest(&self) -> Result<String, ContractViolation> {
        validation::preflight(self)?;
        self.validate_content()?;
        self.compute_digest_unchecked()
    }

    fn compute_digest_unchecked(&self) -> Result<String, ContractViolation> {
        validation::canonical_digest(&(
            self.schema_version,
            &self.set_id,
            &self.task_id,
            &self.scope,
            &self.state_fence,
            &self.bundle_digest,
            &self.validated_input_digest,
            &self.declaration_set,
            &self.policy_id,
            &self.policy_digest,
            &self.discriminators,
            &self.unresolved,
            &self.model_coverage,
            &self.source_coverage,
            &self.omission_frontier,
        ))
    }

    fn validate_content(&self) -> Result<(), ContractViolation> {
        self.validate_shape(true)
    }

    fn validate_shape(&self, require_canonical_order: bool) -> Result<(), ContractViolation> {
        if self.schema_version != RIVAL_MODEL_SET_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "rival.projection.schema_version",
                reason: "unsupported rival projection schema revision".to_owned(),
            });
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
        validation::digest(&self.bundle_digest, "rival.projection.bundle_digest")?;
        validation::digest(
            &self.validated_input_digest,
            "rival.projection.validated_input_digest",
        )?;
        self.declaration_set.validate()?;
        validation::text(&self.policy_id, "rival.projection.policy_id")?;
        validation::digest(&self.policy_digest, "rival.projection.policy_digest")?;
        for discriminator in &self.discriminators {
            discriminator.validate()?;
        }
        for requirement in &self.unresolved {
            requirement.validate()?;
        }
        self.model_coverage.validate()?;
        self.source_coverage.validate()?;
        for handle in &self.omission_frontier {
            validation::artifact(handle, "rival.projection.omission_frontier")?;
        }
        let mut total = 0usize;
        validation::set_sequence(
            self.discriminators.len(),
            &mut total,
            "rival.projection.discriminators",
        )?;
        validation::set_sequence(
            self.unresolved.len(),
            &mut total,
            "rival.projection.unresolved",
        )?;
        validation::set_sequence(
            self.omission_frontier.len(),
            &mut total,
            "rival.projection.omission_frontier",
        )?;
        if require_canonical_order {
            check_discriminator_table(&self.discriminators)?;
            check_requirement_table(&self.unresolved)?;
            check_frontier_order(&self.omission_frontier)?;
        }
        Ok(())
    }

    fn sort_tables(&mut self) {
        self.discriminators.sort_by(|left, right| {
            discriminator_sort_key(left).cmp(&discriminator_sort_key(right))
        });
        self.unresolved.sort_by_key(requirement_order_key);
        self.omission_frontier.sort();
    }
}

fn discriminator_sort_key(
    discriminator: &RetainedDiscriminator,
) -> (&str, u64, &str, &str, u64, &str, &str) {
    (
        discriminator.expected_model.model_id.as_str(),
        discriminator.expected_model.model_revision,
        discriminator.expected_prediction.prediction_id.as_str(),
        discriminator.falsifying_model.model_id.as_str(),
        discriminator.falsifying_model.model_revision,
        discriminator.falsifying_prediction.prediction_id.as_str(),
        discriminator.target.claim_id.as_str(),
    )
}

fn facet_rank(facet: RequirementFacet) -> u8 {
    match facet {
        RequirementFacet::PredictionReferences => 0,
        RequirementFacet::Expected => 1,
        RequirementFacet::Falsifier => 2,
        RequirementFacet::ModelFrontier => 3,
    }
}

fn reason_rank(reason: RequirementReason) -> u8 {
    match reason {
        RequirementReason::Unknown => 0,
        RequirementReason::Unavailable => 1,
        RequirementReason::InternallyIdentical => 2,
        RequirementReason::NotApplicable => 3,
        RequirementReason::OutsideAnalysisFrontier => 4,
    }
}

fn peer_order_key(peer: &DiscriminatorPeerAddress) -> (u32, Option<u32>) {
    (peer.model_row, peer.prediction_ref_entry)
}

/// Canonical identity of one unresolved requirement: source address, facet
/// rank, and peer address. The reason is meaning, not identity.
type RequirementIdentity = (u32, Option<u32>, u8, Option<(u32, Option<u32>)>);
/// Total canonical order key: identity plus reason rank.
type RequirementOrderKey = (u32, Option<u32>, u8, Option<(u32, Option<u32>)>, u8);

fn requirement_identity(requirement: &UnresolvedDiscriminatorRequirement) -> RequirementIdentity {
    (
        requirement.model_row,
        requirement.prediction_ref_entry,
        facet_rank(requirement.facet),
        requirement.peer.as_ref().map(peer_order_key),
    )
}

fn requirement_order_key(requirement: &UnresolvedDiscriminatorRequirement) -> RequirementOrderKey {
    let (row, entry, facet, peer) = requirement_identity(requirement);
    (row, entry, facet, peer, reason_rank(requirement.reason))
}

fn check_discriminator_table(entries: &[RetainedDiscriminator]) -> Result<(), ContractViolation> {
    for pair in entries.windows(2) {
        match discriminator_sort_key(&pair[0]).cmp(&discriminator_sort_key(&pair[1])) {
            Ordering::Less => {}
            Ordering::Equal => {
                if pair[0] == pair[1] {
                    return Err(ContractViolation::BindingMismatch {
                        field: "rival.projection.discriminators",
                        reason: "duplicate discriminator entry".to_owned(),
                    });
                }
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.projection.discriminators",
                    reason: "one discriminator identity maps to changed meaning".to_owned(),
                });
            }
            Ordering::Greater => {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.projection.discriminators",
                    reason: "table is not in canonical address order".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn check_requirement_table(
    entries: &[UnresolvedDiscriminatorRequirement],
) -> Result<(), ContractViolation> {
    for pair in entries.windows(2) {
        let identity_conflict = requirement_identity(&pair[0]) == requirement_identity(&pair[1]);
        match requirement_order_key(&pair[0]).cmp(&requirement_order_key(&pair[1])) {
            Ordering::Less => {
                if identity_conflict {
                    return Err(ContractViolation::BindingMismatch {
                        field: "rival.projection.unresolved",
                        reason: "one requirement address maps to changed reason".to_owned(),
                    });
                }
            }
            Ordering::Equal => {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.projection.unresolved",
                    reason: "duplicate unresolved requirement".to_owned(),
                });
            }
            Ordering::Greater => {
                if identity_conflict {
                    return Err(ContractViolation::BindingMismatch {
                        field: "rival.projection.unresolved",
                        reason: "one requirement address maps to changed reason".to_owned(),
                    });
                }
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.projection.unresolved",
                    reason: "table is not in canonical address order".to_owned(),
                });
            }
        }
    }
    Ok(())
}

fn check_frontier_order(entries: &[ArtifactId]) -> Result<(), ContractViolation> {
    for pair in entries.windows(2) {
        match pair[0].cmp(&pair[1]) {
            Ordering::Less => {}
            Ordering::Equal => {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.projection.omission_frontier",
                    reason: "duplicate frontier address".to_owned(),
                });
            }
            Ordering::Greater => {
                return Err(ContractViolation::BindingMismatch {
                    field: "rival.projection.omission_frontier",
                    reason: "table is not in canonical address order".to_owned(),
                });
            }
        }
    }
    Ok(())
}
