//! Contract and documentation burden views over canonical state (I16.22).
//!
//! I16.22 asks for the system's own specification cost to be made visible.
//! [`ContractSurfaceProfile`] measures the contract surface one work unit
//! actually carries, and [`DocumentationBurdenReceipt`] records the
//! documentation change that moved it. Both are read-only projections:
//! canonical state is taken by shared reference, every observed row is bound to
//! the immutable [`ReportInputRevision`] it was read from, and nothing here
//! writes canonical state or decides completion, acceptance, or `Finish`.
//!
//! Each view is a projection body in the sense I16.8 already uses: the input
//! revisions it renders are canonical references a reader expands back to, and
//! the envelope that versions them is the existing
//! [`ProjectedReport`](crate::projection::ProjectedReport). No second revision
//! mechanism is declared here.
//!
//! The burden default is a code path, not a comment. [`resolve_burden`] returns
//! a [`BurdenResponse`] — `SIMPLIFY`, `MERGE`, `GENERATE`, or `REMOVE` — with
//! the measured task or recovery deltas it was decided from, and refuses a
//! burden case whose delta was never measured. Adding a rule layer is not a
//! representable response, and no token total, row count, or duration is ever
//! compared against a constant: a number in this module is what canonical state
//! showed, never a value to reach. I16.8's report families and the `Product
//! Progress` rules are untouched by this module.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::projection::ReportInputRevision;
use crate::{ReportError, escape_markdown, valid_text};

/// The work family and route profile one surface was measured on.
///
/// This is the canon `work_family_and_route_profile`: the work family selects
/// the route, and the route profile is the route as canonical state describes
/// it. Neither value is inferred from the other here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkFamilyRouteProfile {
    /// Work family the measurement was taken on.
    pub work_family: String,
    /// Route profile that family resolves to in canonical state.
    pub route_profile: String,
    /// Canonical source that described the work family and route.
    pub observed_by: ReportInputRevision,
}

impl WorkFamilyRouteProfile {
    /// Binds one work family to its route profile and the source that read them.
    pub fn new(
        work_family: impl Into<String>,
        route_profile: impl Into<String>,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let profile = Self {
            work_family: work_family.into(),
            route_profile: route_profile.into(),
            observed_by,
        };
        profile.validate()?;
        Ok(profile)
    }

    /// Validates the two identities and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.work_family, "burden.route.work_family").map_err(BurdenError::Report)?;
        valid_text(&self.route_profile, "burden.route.route_profile")
            .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// One contract that actually applies to the measured work unit, and its owner.
///
/// This is the canon `applicable_contract_owner_count`: the count is this
/// collection's length, and the identities behind it are carried so the count
/// can be checked against the contracts the route really pulled in.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplicableContractOwner {
    /// Stable identity of the contract that applies.
    pub contract_id: String,
    /// Owner accountable for that contract.
    pub owner: String,
    /// Canonical source that found the contract applicable.
    pub observed_by: ReportInputRevision,
}

impl ApplicableContractOwner {
    /// Binds one applicable contract to its accountable owner.
    pub fn new(
        contract_id: impl Into<String>,
        owner: impl Into<String>,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let applicable = Self {
            contract_id: contract_id.into(),
            owner: owner.into(),
            observed_by,
        };
        applicable.validate()?;
        Ok(applicable)
    }

    /// Validates the identities and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.contract_id, "burden.applicable_contract.contract_id")
            .map_err(BurdenError::Report)?;
        valid_text(&self.owner, "burden.applicable_contract.owner").map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// The instruction, contract, and tool tokens one work unit actually rendered.
///
/// This is the canon `rendered_instruction_contract_and_tool_tokens`. The three
/// counts stay separate on purpose: they measure what the route rendered, and
/// they are never summed into one cost figure to bring down.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenderedContractTokenCost {
    /// Tokens rendered from instructions for this work unit.
    pub instruction_tokens: u64,
    /// Tokens rendered from contracts applicable to this work unit.
    pub contract_tokens: u64,
    /// Tokens rendered from tool definitions for this work unit.
    pub tool_tokens: u64,
    /// Canonical source the rendered token counts were read from.
    pub observed_by: ReportInputRevision,
}

impl RenderedContractTokenCost {
    /// Records the three rendered token counts separately.
    pub fn new(
        instruction_tokens: u64,
        contract_tokens: u64,
        tool_tokens: u64,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let cost = Self {
            instruction_tokens,
            contract_tokens,
            tool_tokens,
            observed_by,
        };
        cost.validate()?;
        Ok(cost)
    }

    /// Validates the bound input revision.
    ///
    /// The three counts are deliberately not range-checked: a count is what
    /// canonical state rendered, and no value of it is a target.
    pub fn validate(&self) -> Result<(), BurdenError> {
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// One expansion handle the route offered, and how often it was used.
///
/// This is the canon `expansion_handle_count_and_usage`: the handle count is
/// this collection's length, and the usage is recorded per handle.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpansionHandleUsage {
    /// Stable identity of the expansion handle.
    pub handle_id: String,
    /// How often the handle was expanded, as observed.
    pub expansion_count: u64,
    /// Canonical source that observed the handle and its usage.
    pub observed_by: ReportInputRevision,
}

impl ExpansionHandleUsage {
    /// Records one expansion handle with the usage observed for it.
    pub fn new(
        handle_id: impl Into<String>,
        expansion_count: u64,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let usage = Self {
            handle_id: handle_id.into(),
            expansion_count,
            observed_by,
        };
        usage.validate()?;
        Ok(usage)
    }

    /// Validates the handle identity and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.handle_id, "burden.expansion_handle.handle_id")
            .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// Whether a projection read from canonical state is stale or in conflict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProjectionStaleness {
    /// The projection no longer matches the canonical state behind it.
    Stale,
    /// The projection contradicts another projection of the same state.
    Conflicting,
}

/// One projection that is stale or in conflict with canonical state.
///
/// This is the canon `stale_or_conflicting_projection_count`: the count is this
/// collection's length, and each row names the projection and which of the two
/// conditions was observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaleOrConflictingProjection {
    /// Stable identity of the stale or conflicting projection.
    pub projection_id: String,
    /// Which condition canonical state showed for the projection.
    pub state: ProjectionStaleness,
    /// Canonical source that observed the condition.
    pub observed_by: ReportInputRevision,
}

impl StaleOrConflictingProjection {
    /// Records one stale or conflicting projection.
    pub fn new(
        projection_id: impl Into<String>,
        state: ProjectionStaleness,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let projection = Self {
            projection_id: projection_id.into(),
            state,
            observed_by,
        };
        projection.validate()?;
        Ok(projection)
    }

    /// Validates the projection identity and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.projection_id, "burden.stale_projection.projection_id")
            .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// What one contract change reaches when the contract changes.
///
/// This is the canon `contract_change_fanout`. The fan-out is carried as the
/// identities a change to that contract reaches, so the cost of touching the
/// contract is readable without counting anything against a limit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractChangeFanout {
    /// Stable identity of the contract that changed.
    pub contract_id: String,
    /// Surfaces a change to that contract reaches, in canonical order.
    pub affected_surfaces: Vec<String>,
    /// Canonical source the fan-out was read from.
    pub observed_by: ReportInputRevision,
}

impl ContractChangeFanout {
    /// Records the fan-out of one contract, in canonical order.
    pub fn new(
        contract_id: impl Into<String>,
        mut affected_surfaces: Vec<String>,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        affected_surfaces.sort();
        let fanout = Self {
            contract_id: contract_id.into(),
            affected_surfaces,
            observed_by,
        };
        fanout.validate()?;
        Ok(fanout)
    }

    /// Validates the contract identity, its fan-out, and the input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.contract_id, "burden.change_fanout.contract_id")
            .map_err(BurdenError::Report)?;
        if self.affected_surfaces.is_empty() {
            return Err(BurdenError::EmptyField {
                field: "burden.change_fanout.affected_surfaces",
            });
        }
        valid_order(
            self.affected_surfaces.iter().map(String::as_str),
            "burden.change_fanout.affected_surfaces",
        )?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// The generated definition surface and the manual prose duplicating it.
///
/// This is the canon `generated_vs_manual_definition_ratio`. The ratio is kept
/// as the two counted populations it is made of, in canonical order, and is
/// never pre-divided into a single number to compare: the populations are what
/// a reader needs to decide whether the manual half should be generated instead.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedAndManualDefinitionSurface {
    /// Definitions generated from executable schema or code, in canonical order.
    pub generated_definition_ids: Vec<String>,
    /// Manual definitions duplicating the generated surface, in canonical order.
    pub duplicating_manual_definition_ids: Vec<String>,
    /// Canonical source both populations were read from.
    pub observed_by: ReportInputRevision,
}

impl GeneratedAndManualDefinitionSurface {
    /// Records the generated population and the manual definitions duplicating it.
    pub fn new(
        mut generated_definition_ids: Vec<String>,
        mut duplicating_manual_definition_ids: Vec<String>,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        generated_definition_ids.sort();
        duplicating_manual_definition_ids.sort();
        let surface = Self {
            generated_definition_ids,
            duplicating_manual_definition_ids,
            observed_by,
        };
        surface.validate()?;
        Ok(surface)
    }

    /// Whether manual prose duplicates generated surface, as observed.
    #[must_use]
    pub fn has_duplicating_manual_definitions(&self) -> bool {
        !self.duplicating_manual_definition_ids.is_empty()
    }

    /// Validates both populations and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_order(
            self.generated_definition_ids.iter().map(String::as_str),
            "burden.generated_and_manual.generated_definition_ids",
        )?;
        valid_order(
            self.duplicating_manual_definition_ids
                .iter()
                .map(String::as_str),
            "burden.generated_and_manual.duplicating_manual_definition_ids",
        )?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// Time one agent profile spent orienting, as observed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentOrientationTime {
    /// Stable identity of the agent profile that oriented.
    pub agent_profile_id: String,
    /// Orientation time observed for that profile, in milliseconds.
    pub orientation_time_ms: u64,
    /// Canonical source the observation was read from.
    pub observed_by: ReportInputRevision,
}

impl AgentOrientationTime {
    /// Records one agent profile's observed orientation time.
    pub fn new(
        agent_profile_id: impl Into<String>,
        orientation_time_ms: u64,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let observation = Self {
            agent_profile_id: agent_profile_id.into(),
            orientation_time_ms,
            observed_by,
        };
        observation.validate()?;
        Ok(observation)
    }

    /// Validates the profile identity and the bound input revision.
    ///
    /// The duration is not range-checked: it is an observation, and no
    /// duration is a value this crate asks a profile to reach.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(
            &self.agent_profile_id,
            "burden.orientation_time.agent_profile_id",
        )
        .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// One Contract Challenge raised against a contract surface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractChallenge {
    /// Stable identity of the challenge.
    pub challenge_id: String,
    /// Surface the challenge was raised against.
    pub challenged_surface_id: String,
    /// Factual reason the challenge was raised, in one clause.
    pub reason: String,
    /// Canonical source that recorded the challenge.
    pub observed_by: ReportInputRevision,
}

impl ContractChallenge {
    /// Records one Contract Challenge with its factual reason.
    pub fn new(
        challenge_id: impl Into<String>,
        challenged_surface_id: impl Into<String>,
        reason: impl Into<String>,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let challenge = Self {
            challenge_id: challenge_id.into(),
            challenged_surface_id: challenged_surface_id.into(),
            reason: reason.into(),
            observed_by,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    /// Validates the challenge fields and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.challenge_id, "burden.contract_challenge.challenge_id")
            .map_err(BurdenError::Report)?;
        valid_text(
            &self.challenged_surface_id,
            "burden.contract_challenge.challenged_surface_id",
        )
        .map_err(BurdenError::Report)?;
        valid_text(&self.reason, "burden.contract_challenge.reason")
            .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// One event where work was attributed to an owner that does not own it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrongOwnerEvent {
    /// Stable identity of the event.
    pub event_id: String,
    /// Owner the surface names as accountable.
    pub expected_owner: String,
    /// Owner the event was actually attributed to.
    pub observed_owner: String,
    /// Canonical source that recorded the event.
    pub observed_by: ReportInputRevision,
}

impl WrongOwnerEvent {
    /// Records one wrong-owner event with the owner it was attributed to.
    pub fn new(
        event_id: impl Into<String>,
        expected_owner: impl Into<String>,
        observed_owner: impl Into<String>,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let event = Self {
            event_id: event_id.into(),
            expected_owner: expected_owner.into(),
            observed_owner: observed_owner.into(),
            observed_by,
        };
        event.validate()?;
        Ok(event)
    }

    /// Validates the event fields and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.event_id, "burden.wrong_owner.event_id").map_err(BurdenError::Report)?;
        valid_text(&self.expected_owner, "burden.wrong_owner.expected_owner")
            .map_err(BurdenError::Report)?;
        valid_text(&self.observed_owner, "burden.wrong_owner.observed_owner")
            .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// Orientation time, Contract Challenges, and wrong-owner events, as read.
///
/// This is the canon
/// `orientation_time_contract_challenges_and_wrong_owner_events`; the three
/// observations I0.7 asks to be kept apart stay in three collections here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrientationBurden {
    /// Observed orientation time per agent profile, in canonical order.
    pub orientation_times: Vec<AgentOrientationTime>,
    /// Observed Contract Challenges, in canonical order.
    pub contract_challenges: Vec<ContractChallenge>,
    /// Observed wrong-owner events, in canonical order.
    pub wrong_owner_events: Vec<WrongOwnerEvent>,
}

impl OrientationBurden {
    /// Records the three orientation observations in canonical order.
    pub fn new(
        mut orientation_times: Vec<AgentOrientationTime>,
        mut contract_challenges: Vec<ContractChallenge>,
        mut wrong_owner_events: Vec<WrongOwnerEvent>,
    ) -> Result<Self, BurdenError> {
        orientation_times.sort_by(|left, right| left.agent_profile_id.cmp(&right.agent_profile_id));
        contract_challenges.sort_by(|left, right| left.challenge_id.cmp(&right.challenge_id));
        wrong_owner_events.sort_by(|left, right| left.event_id.cmp(&right.event_id));
        let burden = Self {
            orientation_times,
            contract_challenges,
            wrong_owner_events,
        };
        burden.validate()?;
        Ok(burden)
    }

    /// Validates all three collections and the rows inside them.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_order(
            self.orientation_times
                .iter()
                .map(|row| row.agent_profile_id.as_str()),
            "burden.orientation_burden.orientation_times",
        )?;
        for row in &self.orientation_times {
            row.validate()?;
        }
        valid_order(
            self.contract_challenges
                .iter()
                .map(|row| row.challenge_id.as_str()),
            "burden.orientation_burden.contract_challenges",
        )?;
        for row in &self.contract_challenges {
            row.validate()?;
        }
        valid_order(
            self.wrong_owner_events
                .iter()
                .map(|row| row.event_id.as_str()),
            "burden.orientation_burden.wrong_owner_events",
        )?;
        for row in &self.wrong_owner_events {
            row.validate()?;
        }
        Ok(())
    }
}

/// Which existing mechanism a surface depends on for its proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BurdenDependencyKind {
    /// The surface depends on a product-proof record to be believed.
    ProductProof,
    /// The surface depends on a product pulse to be believed.
    ProductPulse,
}

/// One proof or product-pulse dependency of a measured surface.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurdenDependency {
    /// Stable identity of the dependency.
    pub dependency_id: String,
    /// Which mechanism the surface depends on.
    pub kind: BurdenDependencyKind,
    /// Surface that carries the dependency.
    pub surface_id: String,
    /// Canonical source the dependency was read from.
    pub observed_by: ReportInputRevision,
}

impl BurdenDependency {
    /// Records one proof or product-pulse dependency.
    pub fn new(
        dependency_id: impl Into<String>,
        kind: BurdenDependencyKind,
        surface_id: impl Into<String>,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let dependency = Self {
            dependency_id: dependency_id.into(),
            kind,
            surface_id: surface_id.into(),
            observed_by,
        };
        dependency.validate()?;
        Ok(dependency)
    }

    /// Validates the dependency fields and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.dependency_id, "burden.dependency.dependency_id")
            .map_err(BurdenError::Report)?;
        valid_text(&self.surface_id, "burden.dependency.surface_id")
            .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// The contract surface one work unit actually carries (I16.22).
///
/// Every field here is one line of the canon `ContractSurfaceProfile`, read from
/// canonical state and bound to the input revision it came from. The canon
/// counts are carried as the rows they count — the applicable owners are the
/// contracts that pulled in an owner, the expansion handles are the handles the
/// route offered, the stale projections are the projections that no longer match
/// — so each count stays checkable against the canonical input instead of being
/// asserted on its own.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractSurfaceProfile {
    /// Canon `work_family_and_route_profile`.
    pub route: WorkFamilyRouteProfile,
    /// Canon `applicable_contract_owner_count`.
    pub applicable_contract_owners: Vec<ApplicableContractOwner>,
    /// Canon `rendered_instruction_contract_and_tool_tokens`.
    pub rendered_tokens: RenderedContractTokenCost,
    /// Canon `expansion_handle_count_and_usage`.
    pub expansion_handles: Vec<ExpansionHandleUsage>,
    /// Canon `stale_or_conflicting_projection_count`.
    pub stale_or_conflicting_projections: Vec<StaleOrConflictingProjection>,
    /// Canon `contract_change_fanout`.
    pub contract_change_fanout: Vec<ContractChangeFanout>,
    /// Canon `generated_vs_manual_definition_ratio`.
    pub generated_and_manual_definitions: GeneratedAndManualDefinitionSurface,
    /// Canon `orientation_time_contract_challenges_and_wrong_owner_events`.
    pub orientation_burden: OrientationBurden,
    /// Canon `proof_and_product_pulse_dependencies`.
    pub proof_and_product_pulse_dependencies: Vec<BurdenDependency>,
}

impl ContractSurfaceProfile {
    /// Validates the profile and every row bound into it.
    ///
    /// A profile must bind at least one canonical input revision: a contract
    /// surface with no canonical input behind it is not a measurement, and the
    /// versioned artifact that carries this body enforces the same rule for
    /// itself.
    pub fn validate(&self) -> Result<(), BurdenError> {
        if self.input_revisions().is_empty() {
            return Err(BurdenError::NoInputRevisions);
        }
        self.route.validate()?;
        valid_order(
            self.applicable_contract_owners
                .iter()
                .map(|row| row.contract_id.as_str()),
            "contract_surface_profile.applicable_contract_owners",
        )?;
        for row in &self.applicable_contract_owners {
            row.validate()?;
        }
        self.rendered_tokens.validate()?;
        valid_order(
            self.expansion_handles
                .iter()
                .map(|row| row.handle_id.as_str()),
            "contract_surface_profile.expansion_handles",
        )?;
        for row in &self.expansion_handles {
            row.validate()?;
        }
        valid_order(
            self.stale_or_conflicting_projections
                .iter()
                .map(|row| row.projection_id.as_str()),
            "contract_surface_profile.stale_or_conflicting_projections",
        )?;
        for row in &self.stale_or_conflicting_projections {
            row.validate()?;
        }
        valid_order(
            self.contract_change_fanout
                .iter()
                .map(|row| row.contract_id.as_str()),
            "contract_surface_profile.contract_change_fanout",
        )?;
        for row in &self.contract_change_fanout {
            row.validate()?;
        }
        self.generated_and_manual_definitions.validate()?;
        self.orientation_burden.validate()?;
        valid_order(
            self.proof_and_product_pulse_dependencies
                .iter()
                .map(|row| row.dependency_id.as_str()),
            "contract_surface_profile.proof_and_product_pulse_dependencies",
        )?;
        for row in &self.proof_and_product_pulse_dependencies {
            row.validate()?;
        }
        Ok(())
    }

    /// Returns the immutable input revisions this profile was read from.
    ///
    /// The set is canonicalized once, so two profiles over the same canonical
    /// state expose the same references in the same order.
    pub fn input_revisions(&self) -> Vec<ReportInputRevision> {
        let mut inputs = vec![self.route.observed_by.clone()];
        inputs.extend(
            self.applicable_contract_owners
                .iter()
                .map(|row| row.observed_by.clone()),
        );
        inputs.push(self.rendered_tokens.observed_by.clone());
        inputs.extend(
            self.expansion_handles
                .iter()
                .map(|row| row.observed_by.clone()),
        );
        inputs.extend(
            self.stale_or_conflicting_projections
                .iter()
                .map(|row| row.observed_by.clone()),
        );
        inputs.extend(
            self.contract_change_fanout
                .iter()
                .map(|row| row.observed_by.clone()),
        );
        inputs.push(self.generated_and_manual_definitions.observed_by.clone());
        inputs.extend(
            self.orientation_burden
                .orientation_times
                .iter()
                .map(|row| row.observed_by.clone()),
        );
        inputs.extend(
            self.orientation_burden
                .contract_challenges
                .iter()
                .map(|row| row.observed_by.clone()),
        );
        inputs.extend(
            self.orientation_burden
                .wrong_owner_events
                .iter()
                .map(|row| row.observed_by.clone()),
        );
        inputs.extend(
            self.proof_and_product_pulse_dependencies
                .iter()
                .map(|row| row.observed_by.clone()),
        );
        canonical_input_revisions(inputs)
    }

    /// Renders the profile as a stable Markdown view.
    ///
    /// The text repeats the structured fields and the input revisions they were
    /// read from. It is never an authority input, and it sets no target: every
    /// number below is the observation canonical state carried.
    pub fn markdown(&self) -> Result<String, BurdenError> {
        self.validate()?;
        let mut output = String::new();
        output.push_str("# ELIOT Contract Surface Profile\n\n");
        writeln!(
            output,
            "- Work family: `{}`",
            escape_markdown(&self.route.work_family)
        )?;
        writeln!(
            output,
            "- Route profile: `{}`",
            escape_markdown(&self.route.route_profile)
        )?;
        output.push_str("\n## Applicable contract owners\n\n");
        if self.applicable_contract_owners.is_empty() {
            output.push_str("No contract was read as applicable to this work unit.\n");
        } else {
            output.push_str("| Contract | Owner | Observed by |\n|---|---|---|\n");
            for row in &self.applicable_contract_owners {
                writeln!(
                    output,
                    "| `{}` | {} | `{}`@`{}` |",
                    escape_markdown(&row.contract_id),
                    escape_markdown(&row.owner),
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        writeln!(
            output,
            "\n## Rendered instruction, contract, and tool tokens\n\n| Instruction | Contract | Tool | Observed by |\n|---|---|---|---|\n| `{}` | `{}` | `{}` | `{}`@`{}` |",
            self.rendered_tokens.instruction_tokens,
            self.rendered_tokens.contract_tokens,
            self.rendered_tokens.tool_tokens,
            escape_markdown(&self.rendered_tokens.observed_by.input_id),
            self.rendered_tokens.observed_by.revision
        )?;
        output.push_str("\n## Expansion handles and usage\n\n");
        if self.expansion_handles.is_empty() {
            output.push_str("No expansion handle was offered by this route.\n");
        } else {
            output.push_str("| Handle | Expansions observed | Observed by |\n|---|---|---|\n");
            for row in &self.expansion_handles {
                writeln!(
                    output,
                    "| `{}` | `{}` | `{}`@`{}` |",
                    escape_markdown(&row.handle_id),
                    row.expansion_count,
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        output.push_str("\n## Stale or conflicting projections\n\n");
        if self.stale_or_conflicting_projections.is_empty() {
            output.push_str("No stale or conflicting projection was read.\n");
        } else {
            output.push_str("| Projection | State | Observed by |\n|---|---|---|\n");
            for row in &self.stale_or_conflicting_projections {
                writeln!(
                    output,
                    "| `{}` | `{}` | `{}`@`{}` |",
                    escape_markdown(&row.projection_id),
                    staleness_text(row.state),
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        output.push_str("\n## Contract change fanout\n\n");
        if self.contract_change_fanout.is_empty() {
            output.push_str("No contract change fan-out was read.\n");
        } else {
            output.push_str("| Contract | Affected surfaces | Observed by |\n|---|---|---|\n");
            for row in &self.contract_change_fanout {
                writeln!(
                    output,
                    "| `{}` | {} | `{}`@`{}` |",
                    escape_markdown(&row.contract_id),
                    markdown_list(&row.affected_surfaces),
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        let definitions = &self.generated_and_manual_definitions;
        writeln!(
            output,
            "\n## Generated and manual definitions\n\n| Generated definitions | Manual definitions duplicating them | Observed by |\n|---|---|---|\n| {} | {} | `{}`@`{}` |",
            markdown_list(&definitions.generated_definition_ids),
            markdown_list(&definitions.duplicating_manual_definition_ids),
            escape_markdown(&definitions.observed_by.input_id),
            definitions.observed_by.revision
        )?;
        self.orientation_markdown(&mut output)?;
        output.push_str("\n## Proof and product pulse dependencies\n\n");
        if self.proof_and_product_pulse_dependencies.is_empty() {
            output.push_str("No proof or product-pulse dependency was read.\n");
        } else {
            output.push_str("| Dependency | Kind | Surface | Observed by |\n|---|---|---|---|\n");
            for row in &self.proof_and_product_pulse_dependencies {
                writeln!(
                    output,
                    "| `{}` | `{}` | `{}` | `{}`@`{}` |",
                    escape_markdown(&row.dependency_id),
                    dependency_text(row.kind),
                    escape_markdown(&row.surface_id),
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        write_input_revisions(&mut output, &self.input_revisions())?;
        Ok(output)
    }

    /// Renders the three orientation observations, keeping them apart.
    fn orientation_markdown(&self, output: &mut String) -> Result<(), BurdenError> {
        let burden = &self.orientation_burden;
        output.push_str("\n## Orientation burden\n\n### Orientation time observed\n\n");
        if burden.orientation_times.is_empty() {
            output.push_str("No orientation time was read from canonical state.\n");
        } else {
            output.push_str(
                "| Agent profile | Orientation time observed (ms) | Observed by |\n|---|---|---|\n",
            );
            for row in &burden.orientation_times {
                writeln!(
                    output,
                    "| `{}` | `{}` | `{}`@`{}` |",
                    escape_markdown(&row.agent_profile_id),
                    row.orientation_time_ms,
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        output.push_str("\n### Contract challenges\n\n");
        if burden.contract_challenges.is_empty() {
            output.push_str("No Contract Challenge was read from canonical state.\n");
        } else {
            output.push_str("| Challenge | Surface | Reason | Observed by |\n|---|---|---|---|\n");
            for row in &burden.contract_challenges {
                writeln!(
                    output,
                    "| `{}` | `{}` | {} | `{}`@`{}` |",
                    escape_markdown(&row.challenge_id),
                    escape_markdown(&row.challenged_surface_id),
                    escape_markdown(&row.reason),
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        output.push_str("\n### Wrong-owner events\n\n");
        if burden.wrong_owner_events.is_empty() {
            output.push_str("No wrong-owner event was read from canonical state.\n");
        } else {
            output.push_str(
                "| Event | Expected owner | Observed owner | Observed by |\n|---|---|---|---|\n",
            );
            for row in &burden.wrong_owner_events {
                writeln!(
                    output,
                    "| `{}` | `{}` | `{}` | `{}`@`{}` |",
                    escape_markdown(&row.event_id),
                    escape_markdown(&row.expected_owner),
                    escape_markdown(&row.observed_owner),
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        Ok(())
    }
}

/// Whether a changed artifact is a document or a contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ChangedArtifactKind {
    /// Prose that changed.
    Document,
    /// Executable contract that changed.
    Contract,
}

/// One document or contract that changed, bound to its canonical bytes.
///
/// This is the canon `changed_document_and_contract_digests`. The digest of the
/// exact canonical bytes the change was read from is the one carried on the
/// bound [`ReportInputRevision`], so this row cannot name a document digest it
/// was not read from; no second digest is computed here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangedDocumentOrContract {
    /// Stable identity of the changed document or contract.
    pub artifact_id: String,
    /// Whether the change touched prose or an executable contract.
    pub kind: ChangedArtifactKind,
    /// Canonical input revision whose digest is the changed artifact's digest.
    pub observed_by: ReportInputRevision,
}

impl ChangedDocumentOrContract {
    /// Records one changed document or contract against its canonical input.
    pub fn new(
        artifact_id: impl Into<String>,
        kind: ChangedArtifactKind,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let changed = Self {
            artifact_id: artifact_id.into(),
            kind,
            observed_by,
        };
        changed.validate()?;
        Ok(changed)
    }

    /// Validates the artifact identity and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.artifact_id, "burden.changed_artifact.artifact_id")
            .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// How a documentation change moved the surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SurfaceChangeKind {
    /// Prose or surface the change added.
    Added,
    /// Prose or surface the change removed.
    Removed,
    /// Surface the change brought under generation.
    Generated,
}

/// One surface the change added, removed, or brought under generation.
///
/// This is the canon `added_removed_or_generated_surface`, kept as the named
/// surfaces rather than as three counts, so a later reader can see which surface
/// moved and not only how many did.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurdenSurfaceChange {
    /// Stable identity of the surface that changed.
    pub surface_id: String,
    /// How the change moved that surface.
    pub change: SurfaceChangeKind,
    /// Canonical source the change was read from.
    pub observed_by: ReportInputRevision,
}

impl BurdenSurfaceChange {
    /// Records one added, removed, or generated surface.
    pub fn new(
        surface_id: impl Into<String>,
        change: SurfaceChangeKind,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let row = Self {
            surface_id: surface_id.into(),
            change,
            observed_by,
        };
        row.validate()?;
        Ok(row)
    }

    /// Validates the surface identity and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.surface_id, "burden.surface_change.surface_id")
            .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// Whether an affected identity is an agent profile or another consumer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BurdenConsumerKind {
    /// An agent profile that reads the changed surface.
    AgentProfile,
    /// Any other consumer of the changed surface.
    Consumer,
}

/// One agent profile or other consumer the change reached.
///
/// This is the canon `affected_agent_profiles_and_consumers`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffectedProfileOrConsumer {
    /// Stable identity of the agent profile or consumer.
    pub profile_or_consumer_id: String,
    /// Which kind of reader the change reached.
    pub kind: BurdenConsumerKind,
    /// Canonical source the affected reader was read from.
    pub observed_by: ReportInputRevision,
}

impl AffectedProfileOrConsumer {
    /// Records one affected agent profile or other consumer.
    pub fn new(
        profile_or_consumer_id: impl Into<String>,
        kind: BurdenConsumerKind,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let affected = Self {
            profile_or_consumer_id: profile_or_consumer_id.into(),
            kind,
            observed_by,
        };
        affected.validate()?;
        Ok(affected)
    }

    /// Validates the reader identity and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(
            &self.profile_or_consumer_id,
            "burden.affected_reader.profile_or_consumer_id",
        )
        .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// Which measured dimension a delta belongs to.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BurdenDeltaDimension {
    /// Task effort: time or steps a work unit cost.
    Task,
    /// Recovery effort: time or steps a recovery cost.
    Recovery,
}

/// One measured task or recovery delta, with the measurement that produced it.
///
/// This is the canon `measured_task_or_recovery_delta`. The delta is signed and
/// is recorded as observed — negative when the measured cost went down, positive
/// when it went up — and is carried into [`BurdenResolution`] as the evidence
/// behind a response. It is never compared against a constant: no duration here
/// is a value a change must reach.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasuredBurdenDelta {
    /// Stable identity of the measurement.
    pub delta_id: String,
    /// Which measured dimension the delta belongs to.
    pub dimension: BurdenDeltaDimension,
    /// Measured change in milliseconds; negative means the cost went down.
    pub measured_delta_ms: i64,
    /// Canonical source the measurement was read from.
    pub observed_by: ReportInputRevision,
}

impl MeasuredBurdenDelta {
    /// Records one measured task or recovery delta.
    pub fn new(
        delta_id: impl Into<String>,
        dimension: BurdenDeltaDimension,
        measured_delta_ms: i64,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        let measured = Self {
            delta_id: delta_id.into(),
            dimension,
            measured_delta_ms,
            observed_by,
        };
        measured.validate()?;
        Ok(measured)
    }

    /// Validates the measurement identity and the bound input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.delta_id, "burden.measured_delta.delta_id")
            .map_err(BurdenError::Report)?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// What kind of reduction one burden candidate calls for.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BurdenCandidateKind {
    /// The surface can be stated with less precision.
    Simplification,
    /// The surface overlaps another and can be merged into it.
    Merge,
    /// The surface is stale and can be retired.
    Retirement,
}

/// One simplification, merge, or retirement candidate the change produced.
///
/// This is the canon `simplification_merge_or_retirement_candidates`. Each
/// candidate names at least one surface, so a recorded reduction always points
/// at something a reader can open.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurdenCandidate {
    /// Stable identity of the candidate.
    pub candidate_id: String,
    /// Which reduction the candidate calls for.
    pub kind: BurdenCandidateKind,
    /// Surfaces the reduction applies to, in canonical order.
    pub surface_ids: Vec<String>,
    /// Canonical source the candidate was read from.
    pub observed_by: ReportInputRevision,
}

impl BurdenCandidate {
    /// Records one simplification, merge, or retirement candidate.
    pub fn new(
        candidate_id: impl Into<String>,
        kind: BurdenCandidateKind,
        mut surface_ids: Vec<String>,
        observed_by: ReportInputRevision,
    ) -> Result<Self, BurdenError> {
        surface_ids.sort();
        let candidate = Self {
            candidate_id: candidate_id.into(),
            kind,
            surface_ids,
            observed_by,
        };
        candidate.validate()?;
        Ok(candidate)
    }

    /// The response I16.22 names as the default for this candidate.
    ///
    /// A simplification candidate simplifies, a merge candidate merges, and a
    /// retirement candidate removes. Generating is not a candidate kind here: it
    /// arises from a measured duplication signal, not from a recorded candidate.
    #[must_use]
    pub fn response(&self) -> BurdenResponse {
        match self.kind {
            BurdenCandidateKind::Simplification => BurdenResponse::Simplify,
            BurdenCandidateKind::Merge => BurdenResponse::Merge,
            BurdenCandidateKind::Retirement => BurdenResponse::Remove,
        }
    }

    /// Validates the candidate identity, its surfaces, and the input revision.
    pub fn validate(&self) -> Result<(), BurdenError> {
        valid_text(&self.candidate_id, "burden.candidate.candidate_id")
            .map_err(BurdenError::Report)?;
        if self.surface_ids.is_empty() {
            return Err(BurdenError::EmptyField {
                field: "burden.candidate.surface_ids",
            });
        }
        valid_order(
            self.surface_ids.iter().map(String::as_str),
            "burden.candidate.surface_ids",
        )?;
        self.observed_by.validate().map_err(BurdenError::Report)
    }
}

/// The documentation change that moved a contract surface (I16.22).
///
/// Every field here is one line of the canon `DocumentationBurdenReceipt`, read
/// from canonical state and bound to the input revision it came from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentationBurdenReceipt {
    /// Canon `changed_document_and_contract_digests`.
    pub changed_document_and_contract_digests: Vec<ChangedDocumentOrContract>,
    /// Canon `added_removed_or_generated_surface`.
    pub added_removed_or_generated_surface: Vec<BurdenSurfaceChange>,
    /// Canon `affected_agent_profiles_and_consumers`.
    pub affected_agent_profiles_and_consumers: Vec<AffectedProfileOrConsumer>,
    /// Canon `measured_task_or_recovery_delta`.
    pub measured_task_or_recovery_delta: Vec<MeasuredBurdenDelta>,
    /// Canon `simplification_merge_or_retirement_candidates`.
    pub simplification_merge_or_retirement_candidates: Vec<BurdenCandidate>,
}

impl DocumentationBurdenReceipt {
    /// Validates the receipt and every row bound into it.
    ///
    /// A receipt must bind at least one canonical input revision: a
    /// documentation change with no canonical input behind it cannot carry a
    /// burden measurement.
    pub fn validate(&self) -> Result<(), BurdenError> {
        if self.input_revisions().is_empty() {
            return Err(BurdenError::NoInputRevisions);
        }
        valid_order(
            self.changed_document_and_contract_digests
                .iter()
                .map(|row| row.artifact_id.as_str()),
            "documentation_burden_receipt.changed_document_and_contract_digests",
        )?;
        for row in &self.changed_document_and_contract_digests {
            row.validate()?;
        }
        valid_order(
            self.added_removed_or_generated_surface
                .iter()
                .map(|row| row.surface_id.as_str()),
            "documentation_burden_receipt.added_removed_or_generated_surface",
        )?;
        for row in &self.added_removed_or_generated_surface {
            row.validate()?;
        }
        valid_order(
            self.affected_agent_profiles_and_consumers
                .iter()
                .map(|row| row.profile_or_consumer_id.as_str()),
            "documentation_burden_receipt.affected_agent_profiles_and_consumers",
        )?;
        for row in &self.affected_agent_profiles_and_consumers {
            row.validate()?;
        }
        valid_order(
            self.measured_task_or_recovery_delta
                .iter()
                .map(|row| row.delta_id.as_str()),
            "documentation_burden_receipt.measured_task_or_recovery_delta",
        )?;
        for row in &self.measured_task_or_recovery_delta {
            row.validate()?;
        }
        valid_order(
            self.simplification_merge_or_retirement_candidates
                .iter()
                .map(|row| row.candidate_id.as_str()),
            "documentation_burden_receipt.simplification_merge_or_retirement_candidates",
        )?;
        for row in &self.simplification_merge_or_retirement_candidates {
            row.validate()?;
        }
        Ok(())
    }

    /// Returns the immutable input revisions this receipt was read from.
    ///
    /// The set is canonicalized once, so two receipts over the same canonical
    /// state expose the same references in the same order.
    pub fn input_revisions(&self) -> Vec<ReportInputRevision> {
        let inputs: Vec<ReportInputRevision> = self
            .changed_document_and_contract_digests
            .iter()
            .map(|row| row.observed_by.clone())
            .chain(
                self.added_removed_or_generated_surface
                    .iter()
                    .map(|row| row.observed_by.clone()),
            )
            .chain(
                self.affected_agent_profiles_and_consumers
                    .iter()
                    .map(|row| row.observed_by.clone()),
            )
            .chain(
                self.measured_task_or_recovery_delta
                    .iter()
                    .map(|row| row.observed_by.clone()),
            )
            .chain(
                self.simplification_merge_or_retirement_candidates
                    .iter()
                    .map(|row| row.observed_by.clone()),
            )
            .collect();
        canonical_input_revisions(inputs)
    }

    /// Renders the receipt as a stable Markdown view.
    ///
    /// The text repeats the structured fields and the input revisions they were
    /// read from. It is never an authority input, and it recommends no prose:
    /// the response a burden case resolves to is [`resolve_burden`], not a line
    /// of this rendering.
    pub fn markdown(&self) -> Result<String, BurdenError> {
        self.validate()?;
        let mut output = String::new();
        output.push_str("# ELIOT Documentation Burden Receipt\n\n");
        output.push_str("## Changed documents and contracts\n\n");
        if self.changed_document_and_contract_digests.is_empty() {
            output.push_str("No changed document or contract was read.\n");
        } else {
            output.push_str(
                "| Artifact | Kind | Revision | Digest | Observed by |\n|---|---|---|---|---|\n",
            );
            for row in &self.changed_document_and_contract_digests {
                writeln!(
                    output,
                    "| `{}` | `{}` | `{}` | `{}` | `{}` |",
                    escape_markdown(&row.artifact_id),
                    changed_kind_text(row.kind),
                    row.observed_by.revision,
                    row.observed_by.input_digest,
                    escape_markdown(&row.observed_by.input_id)
                )?;
            }
        }
        output.push_str("\n## Added, removed, or generated surface\n\n");
        if self.added_removed_or_generated_surface.is_empty() {
            output.push_str("No surface was read as added, removed, or generated.\n");
        } else {
            output.push_str("| Surface | Change | Observed by |\n|---|---|---|\n");
            for row in &self.added_removed_or_generated_surface {
                writeln!(
                    output,
                    "| `{}` | `{}` | `{}`@`{}` |",
                    escape_markdown(&row.surface_id),
                    surface_change_text(row.change),
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        output.push_str("\n## Affected agent profiles and consumers\n\n");
        if self.affected_agent_profiles_and_consumers.is_empty() {
            output.push_str("No agent profile or other consumer was read as affected.\n");
        } else {
            output.push_str("| Profile or consumer | Kind | Observed by |\n|---|---|---|\n");
            for row in &self.affected_agent_profiles_and_consumers {
                writeln!(
                    output,
                    "| `{}` | `{}` | `{}`@`{}` |",
                    escape_markdown(&row.profile_or_consumer_id),
                    consumer_text(row.kind),
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        output.push_str("\n## Measured task or recovery delta\n\n");
        if self.measured_task_or_recovery_delta.is_empty() {
            output.push_str("No task or recovery delta was measured.\n");
        } else {
            output.push_str(
                "| Delta | Dimension | Measured delta (ms) | Observed by |\n|---|---|---|---|\n",
            );
            for row in &self.measured_task_or_recovery_delta {
                writeln!(
                    output,
                    "| `{}` | `{}` | `{}` | `{}`@`{}` |",
                    escape_markdown(&row.delta_id),
                    dimension_text(row.dimension),
                    row.measured_delta_ms,
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        output.push_str("\n## Simplification, merge, and retirement candidates\n\n");
        if self
            .simplification_merge_or_retirement_candidates
            .is_empty()
        {
            output.push_str("No simplification, merge, or retirement candidate was read.\n");
        } else {
            output.push_str("| Candidate | Kind | Surfaces | Observed by |\n|---|---|---|---|\n");
            for row in &self.simplification_merge_or_retirement_candidates {
                writeln!(
                    output,
                    "| `{}` | `{}` | {} | `{}`@`{}` |",
                    escape_markdown(&row.candidate_id),
                    candidate_text(row.kind),
                    markdown_list(&row.surface_ids),
                    escape_markdown(&row.observed_by.input_id),
                    row.observed_by.revision
                )?;
            }
        }
        write_input_revisions(&mut output, &self.input_revisions())?;
        Ok(output)
    }
}

/// The response I16.22 names as the default for a burden case.
///
/// These four outcomes are the whole vocabulary. Adding a rule layer is not a
/// variant, so a burden case that bought no correctness, recovery, or product
/// outcome cannot resolve into more prose.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BurdenResponse {
    /// State the surface with less precision.
    Simplify,
    /// Merge the overlapping surfaces into one.
    Merge,
    /// Generate the surface from the schema or code that already defines it.
    Generate,
    /// Remove the stale surface.
    Remove,
}

/// A burden case resolved against I16.22's burden default.
///
/// The response is the decision and the measured deltas are its evidence: a
/// resolution without a measurement is not produced at all.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BurdenResolution {
    /// Which default response the case resolved to.
    pub response: BurdenResponse,
    /// Surfaces the response applies to, in canonical order and deduplicated.
    pub surfaces: Vec<String>,
    /// The measured task or recovery deltas the response was decided from.
    pub measured_deltas: Vec<MeasuredBurdenDelta>,
}

/// Resolves a burden case to the response I16.22 names as the default.
///
/// The refusal is the rule, not a comment:
///
/// * both views must validate, so no resolution is decided from a profile or
///   receipt that is not bound to canonical state;
/// * a receipt with no measured task or recovery delta carries no burden case
///   yet, so this returns [`BurdenError::UnmeasuredDelta`] instead of a
///   decision — the case resolves *with the delta measured* or not at all;
/// * the response is read from the observed shape of the surface — stale or
///   conflicting projections, then manual definitions duplicating generated
///   surface, then the recorded retirement and merge candidates — and
///   simplification is the default. No count, token total, or duration is
///   compared with a constant anywhere in this function, so no burden number can
///   become a target, and no outcome adds a rule layer.
pub fn resolve_burden(
    profile: &ContractSurfaceProfile,
    receipt: &DocumentationBurdenReceipt,
) -> Result<BurdenResolution, BurdenError> {
    profile.validate()?;
    receipt.validate()?;
    if receipt.measured_task_or_recovery_delta.is_empty() {
        return Err(BurdenError::UnmeasuredDelta);
    }
    let response = response_of(profile, receipt);
    let mut surfaces = surfaces_of(profile, receipt, response);
    surfaces.sort();
    surfaces.dedup();
    Ok(BurdenResolution {
        response,
        surfaces,
        measured_deltas: receipt.measured_task_or_recovery_delta.clone(),
    })
}

/// Reads the response from the observed shape of the surface.
///
/// The order is the order of burden in the canon sentence: stale prose is
/// removed first, then duplication is generated out of the code that already
/// defines it, then whatever canonical state recorded as retirable or mergeable.
/// A precision that bought nothing in particular simplifies.
fn response_of(
    profile: &ContractSurfaceProfile,
    receipt: &DocumentationBurdenReceipt,
) -> BurdenResponse {
    if !profile.stale_or_conflicting_projections.is_empty() {
        return BurdenResponse::Remove;
    }
    if profile
        .generated_and_manual_definitions
        .has_duplicating_manual_definitions()
    {
        return BurdenResponse::Generate;
    }
    let candidates = &receipt.simplification_merge_or_retirement_candidates;
    if candidates
        .iter()
        .any(|candidate| candidate.response() == BurdenResponse::Remove)
    {
        return BurdenResponse::Remove;
    }
    if candidates
        .iter()
        .any(|candidate| candidate.response() == BurdenResponse::Merge)
    {
        return BurdenResponse::Merge;
    }
    BurdenResponse::Simplify
}

/// Collects the surfaces the chosen response applies to.
fn surfaces_of(
    profile: &ContractSurfaceProfile,
    receipt: &DocumentationBurdenReceipt,
    response: BurdenResponse,
) -> Vec<String> {
    let mut surfaces: Vec<String> = Vec::new();
    if response == BurdenResponse::Remove {
        surfaces.extend(
            profile
                .stale_or_conflicting_projections
                .iter()
                .map(|row| row.projection_id.clone()),
        );
    }
    if response == BurdenResponse::Generate {
        surfaces.extend(
            profile
                .generated_and_manual_definitions
                .duplicating_manual_definition_ids
                .clone(),
        );
    }
    if let Some(kind) = candidate_kind_of(response) {
        surfaces.extend(
            receipt
                .simplification_merge_or_retirement_candidates
                .iter()
                .filter(|candidate| candidate.kind == kind)
                .flat_map(|candidate| candidate.surface_ids.iter().cloned()),
        );
    }
    surfaces
}

/// The candidate kind a response was decided from, when it was decided from one.
fn candidate_kind_of(response: BurdenResponse) -> Option<BurdenCandidateKind> {
    match response {
        BurdenResponse::Simplify => Some(BurdenCandidateKind::Simplification),
        BurdenResponse::Merge => Some(BurdenCandidateKind::Merge),
        BurdenResponse::Remove => Some(BurdenCandidateKind::Retirement),
        BurdenResponse::Generate => None,
    }
}

/// Typed failures of the burden views.
#[derive(Debug, Error)]
pub enum BurdenError {
    /// A required field was blank, malformed, or held control characters.
    #[error("invalid field: {0}")]
    Report(#[from] ReportError),
    /// A required collection was empty.
    #[error("{field} must not be empty")]
    EmptyField {
        /// Field that must not be empty.
        field: &'static str,
    },
    /// A collection contains a duplicate identity.
    #[error("duplicate identity in {field}")]
    DuplicateField {
        /// Field that contains a duplicate.
        field: &'static str,
    },
    /// A collection is not in canonical order.
    #[error("{field} is not in canonical order")]
    UnorderedField {
        /// Field that is not in canonical order.
        field: &'static str,
    },
    /// A burden view must bind at least one canonical input revision.
    #[error("a burden view must bind at least one input revision")]
    NoInputRevisions,
    /// A burden case was offered without a measured task or recovery delta.
    #[error("a burden case cannot be resolved before its task or recovery delta is measured")]
    UnmeasuredDelta,
    /// Canonical JSON could not be produced.
    #[error("canonical burden serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Markdown formatting could not be completed.
    #[error("burden view formatting failed: {0}")]
    Formatting(#[from] std::fmt::Error),
}

/// Validates one canonically ordered collection of identities.
///
/// Every burden collection is ordered by its stable identity and free of
/// duplicates, so a reader can compare two revisions of the same surface
/// position by position.
fn valid_order<'a>(
    identities: impl Iterator<Item = &'a str>,
    field: &'static str,
) -> Result<(), BurdenError> {
    let mut seen = BTreeSet::new();
    let mut previous: Option<&str> = None;
    for identity in identities {
        valid_text(identity, field).map_err(BurdenError::Report)?;
        if previous.is_some_and(|earlier| earlier >= identity) {
            return Err(BurdenError::UnorderedField { field });
        }
        if !seen.insert(identity) {
            return Err(BurdenError::DuplicateField { field });
        }
        previous = Some(identity);
    }
    Ok(())
}

/// Sorts and deduplicates a collected input-revision set.
///
/// The key is the source, identity, and revision of each reference, which is the
/// canonical order the projection surface already uses.
fn canonical_input_revisions(mut inputs: Vec<ReportInputRevision>) -> Vec<ReportInputRevision> {
    inputs.sort_by_key(|input| (input.source, input.input_id.as_str(), input.revision));
    inputs.dedup();
    inputs
}

/// Renders the input-revision table both burden views end with.
fn write_input_revisions(
    output: &mut String,
    inputs: &[ReportInputRevision],
) -> Result<(), BurdenError> {
    output.push_str("\n## Input revisions\n\n");
    output.push_str("| Source | Input | Revision | Digest |\n|---|---|---|---|\n");
    for input in inputs {
        writeln!(
            output,
            "| `{}` | `{}` | `{}` | `{}` |",
            serde_json::to_string(&input.source)?.trim_matches('"'),
            escape_markdown(&input.input_id),
            input.revision,
            input.input_digest
        )?;
    }
    Ok(())
}

/// Renders one identity collection as an inline Markdown list.
fn markdown_list(identities: &[String]) -> String {
    if identities.is_empty() {
        return "none".to_owned();
    }
    identities
        .iter()
        .map(|identity| format!("`{}`", escape_markdown(identity)))
        .collect::<Vec<String>>()
        .join(", ")
}

fn staleness_text(value: ProjectionStaleness) -> &'static str {
    match value {
        ProjectionStaleness::Stale => "STALE",
        ProjectionStaleness::Conflicting => "CONFLICTING",
    }
}

fn dependency_text(value: BurdenDependencyKind) -> &'static str {
    match value {
        BurdenDependencyKind::ProductProof => "PRODUCT_PROOF",
        BurdenDependencyKind::ProductPulse => "PRODUCT_PULSE",
    }
}

fn changed_kind_text(value: ChangedArtifactKind) -> &'static str {
    match value {
        ChangedArtifactKind::Document => "DOCUMENT",
        ChangedArtifactKind::Contract => "CONTRACT",
    }
}

fn surface_change_text(value: SurfaceChangeKind) -> &'static str {
    match value {
        SurfaceChangeKind::Added => "ADDED",
        SurfaceChangeKind::Removed => "REMOVED",
        SurfaceChangeKind::Generated => "GENERATED",
    }
}

fn consumer_text(value: BurdenConsumerKind) -> &'static str {
    match value {
        BurdenConsumerKind::AgentProfile => "AGENT_PROFILE",
        BurdenConsumerKind::Consumer => "CONSUMER",
    }
}

fn dimension_text(value: BurdenDeltaDimension) -> &'static str {
    match value {
        BurdenDeltaDimension::Task => "TASK",
        BurdenDeltaDimension::Recovery => "RECOVERY",
    }
}

fn candidate_text(value: BurdenCandidateKind) -> &'static str {
    match value {
        BurdenCandidateKind::Simplification => "SIMPLIFICATION",
        BurdenCandidateKind::Merge => "MERGE",
        BurdenCandidateKind::Retirement => "RETIREMENT",
    }
}
