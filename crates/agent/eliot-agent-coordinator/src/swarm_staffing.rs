//! Bounded Swarm staffing compiled from exact current A-02 selections.
//!
//! [`compile_swarm_staffing`] binds one [`ModelSelectionReceipt`] per demanded
//! [`ModelRole`] into a deterministic role slot. A staffed slot carries the
//! exact selection identity that authorized it: selection ID/digest, account
//! scope, catalogue snapshot ID/digest, Human policy ID/revision/digest, and
//! the full selected [`ModelCatalogueEntry`] including its field-complete
//! route. There is no second ranking or selection path: eligibility, ranking,
//! and receipt minting stay owned by `compile_model_selection`; this module
//! only admits exact current receipts and projects them into bounded slots.
//!
//! Fail-closed admission, in deterministic precedence:
//!
//! 1. structural receipt validation (`ModelSelectionReceipt::validate`);
//! 2. single-generation agreement across the admitted set (account scope,
//!    catalogue snapshot ID/digest, Human policy ID/revision/digest);
//! 3. identity and demand admission (duplicate selection IDs, reused catalogue
//!    entries across roles, receipts for undemanded roles, duplicate roles);
//! 4. exact-current admission against the supplied catalogue/policy generation
//!    (`validate_against`: stale or mismatched selections are rejected);
//! 5. secret-bearing or fixed-model input rejection.
//!
//! Demanded roles without a receipt remain typed [`StaffingGap::MissingRole`]
//! gaps. Challenger/Verifier slots are classified against the staffed primary
//! (`MainAgent`) over host, full-route, and model-family dimensions with the
//! shared [`entry_diversity_gaps`] helper; a collision is an explicit
//! [`StaffingGap::DegradedIndependence`] gap, never silent reuse. Display
//! strings (entry/model labels) are never compared, so a different display
//! name alone cannot satisfy independence.
//!
//! The output is structurally candidate-only: `candidate_only` is true,
//! `dispatch_authority` is false, execution counters are zero, and the value
//! carries no `WorkLeaseId`, `AttemptId`, mailbox mutation, Concilium
//! decision, or Finish authority. It performs no provider/model call, no
//! catalogue refresh, no process launch, no route admission, and no
//! fallback/redispatch.
//!
//! Proof ceiling: `SWARM_STAFFING_CANDIDATE_PACKAGE_PROOF_ONLY`. Provider
//! admission, `WorkLease`/`StateFence` issuance, supervised `AgentAttempt`
//! execution, and Product Pulse remain separate.

use std::collections::{BTreeMap, BTreeSet};

use serde::de::Error as SerdeError;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::model_control::{
    HumanModelPreferencePolicy, ModelCatalogueEntry, ModelCatalogueSnapshot, ModelControlError,
    ModelRole, ModelSelectionReceipt, ZeroModelExecutionCounters, canonical_digest,
    catalogue_digest, preference_policy_digest, validate_canonical_digest,
};
use crate::swarm_controlboard::diversity::{
    DiversityDimension, DiversityError, entry_diversity_gaps, validate_no_secret_or_fixed_input,
};

/// Schema identity for the candidate-only staffing value.
pub const SWARM_STAFFING_CANDIDATE_VERSION: &str = "eliot.agent-swarm-staffing-candidate/v1";

/// Maximum staffed slots. One slot exists per distinct [`ModelRole`], and
/// `ModelRole` has eight variants, so more than eight selections necessarily
/// repeat a role and fail closed.
pub const MAX_STAFFING_SLOTS: usize = 8;

/// Dimensions every Challenger/Verifier slot must differ on versus the staffed
/// primary. Full-route equality subsumes provider/model/auth/billing route
/// identity because catalogue validation binds `route.provider` to
/// `provider_id` (and host/model likewise).
fn independence_dimensions() -> BTreeSet<DiversityDimension> {
    BTreeSet::from([
        DiversityDimension::Host,
        DiversityDimension::Route,
        DiversityDimension::ModelFamily,
    ])
}

fn validate_text(value: &str, field: &'static str) -> Result<(), SwarmStaffingError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SwarmStaffingError::InvalidField(field));
    }
    Ok(())
}

/// Fail-closed staffing errors. Provider absence is not representable here:
/// the caller supplies the exact catalogue/policy generation, and a stale or
/// mismatched selection is rejected rather than projected.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SwarmStaffingError {
    #[error(transparent)]
    ModelControl(#[from] ModelControlError),
    #[error(transparent)]
    Diversity(#[from] DiversityError),
    #[error("invalid swarm staffing field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate swarm staffing identity: {0}")]
    DuplicateIdentity(&'static str),
}

/// Exact staffing input: immutable role demand plus the candidate receipts to
/// admit, bound to one catalogue/policy generation observed at `now_unix_ms`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmStaffingRequest {
    pub staffing_id: String,
    pub demand: Vec<ModelRole>,
    pub selections: Vec<ModelSelectionReceipt>,
    pub catalogue: ModelCatalogueSnapshot,
    pub policy: HumanModelPreferencePolicy,
    pub now_unix_ms: u64,
}

/// One demanded role bound to the exact selection that authorized it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffedSlot {
    pub slot_id: String,
    pub role: ModelRole,
    pub selection_id: String,
    pub selection_digest: String,
    pub account_scope: String,
    pub catalogue_snapshot_id: String,
    pub catalogue_digest: String,
    pub preference_policy_id: String,
    pub preference_revision: String,
    pub preference_policy_digest: String,
    pub selected: ModelCatalogueEntry,
    /// Canonical digest over the staffing identity plus every bound field,
    /// including the full selected entry (and therefore the full route).
    /// Validators recompute; a tampered copy is rejected.
    pub slot_digest: String,
}

impl StaffedSlot {
    fn digest(&self, staffing_id: &str) -> Result<String, ModelControlError> {
        canonical_digest(&(
            SWARM_STAFFING_CANDIDATE_VERSION,
            staffing_id,
            self.role,
            self.selection_id.as_str(),
            self.selection_digest.as_str(),
            self.account_scope.as_str(),
            self.catalogue_snapshot_id.as_str(),
            self.catalogue_digest.as_str(),
            self.preference_policy_id.as_str(),
            self.preference_revision.as_str(),
            self.preference_policy_digest.as_str(),
            &self.selected,
        ))
    }

    fn validate(&self, staffing_id: &str) -> Result<(), SwarmStaffingError> {
        if self.slot_id != slot_id(staffing_id, self.role) {
            return Err(SwarmStaffingError::InvalidField("staffing.slot_id"));
        }
        for (value, field) in [
            (self.selection_id.as_str(), "staffing.selection_id"),
            (self.account_scope.as_str(), "staffing.account_scope"),
            (
                self.catalogue_snapshot_id.as_str(),
                "staffing.catalogue_snapshot_id",
            ),
            (
                self.preference_policy_id.as_str(),
                "staffing.preference_policy_id",
            ),
            (
                self.preference_revision.as_str(),
                "staffing.preference_revision",
            ),
        ] {
            validate_text(value, field)?;
        }
        validate_canonical_digest(&self.selection_digest, "staffing.selection_digest")?;
        validate_canonical_digest(&self.catalogue_digest, "staffing.catalogue_digest")?;
        validate_canonical_digest(
            &self.preference_policy_digest,
            "staffing.preference_policy_digest",
        )?;
        self.selected.validate(&self.account_scope)?;
        if self.slot_digest != self.digest(staffing_id)? {
            return Err(SwarmStaffingError::InvalidField("staffing.slot_digest"));
        }
        Ok(())
    }
}

/// Explicit reason a demanded staffing is not a complete runnable Swarm.
/// Gaps are sortable and deterministic; they never carry launch authority.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum StaffingGap {
    MissingRole {
        role: ModelRole,
    },
    DegradedIndependence {
        role: ModelRole,
        dimensions: Vec<DiversityDimension>,
    },
}

/// Challenger/Verifier independence outcome versus the staffed primary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", tag = "kind")]
pub enum StaffingIndependenceOutcome {
    Satisfied,
    Degraded { dimensions: Vec<DiversityDimension> },
}

/// Primary-versus-Challenger/Verifier independence classification over exact
/// host, full-route, and model-family equality. A degraded outcome is explicit
/// candidate metadata; it cannot satisfy an independent-verifier requirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaffingIndependenceDecision {
    pub role: ModelRole,
    pub primary_role: ModelRole,
    pub dimensions: BTreeSet<DiversityDimension>,
    pub outcome: StaffingIndependenceOutcome,
}

/// Deterministic, bounded, candidate-only staffing result. Replaying the exact
/// input reproduces the exact value; reusing the staffing identity with
/// changed bytes is a conflict detected by [`SwarmStaffingCandidate::validate`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmStaffingCandidate {
    pub schema_version: String,
    pub staffing_id: String,
    pub staffing_digest: String,
    pub account_scope: String,
    pub catalogue_snapshot_id: String,
    pub catalogue_digest: String,
    pub preference_policy_id: String,
    pub preference_revision: String,
    pub preference_policy_digest: String,
    /// Canonical (sorted, deduped) role demand this candidate was compiled for.
    pub demand: Vec<ModelRole>,
    /// One slot per staffed role in canonical [`ModelRole`] order.
    pub slots: Vec<StaffedSlot>,
    /// Typed gaps in canonical order. Empty means the staffing is complete.
    pub gaps: Vec<StaffingGap>,
    /// Challenger/Verifier independence decisions in canonical role order.
    pub independence: Vec<StaffingIndependenceDecision>,
    pub execution: ZeroModelExecutionCounters,
    pub candidate_only: bool,
    pub dispatch_authority: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwarmStaffingCandidateFields {
    schema_version: String,
    staffing_id: String,
    staffing_digest: String,
    account_scope: String,
    catalogue_snapshot_id: String,
    catalogue_digest: String,
    preference_policy_id: String,
    preference_revision: String,
    preference_policy_digest: String,
    demand: Vec<ModelRole>,
    slots: Vec<StaffedSlot>,
    gaps: Vec<StaffingGap>,
    independence: Vec<StaffingIndependenceDecision>,
    execution: ZeroModelExecutionCounters,
    candidate_only: bool,
    dispatch_authority: bool,
}

impl<'de> Deserialize<'de> for SwarmStaffingCandidate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = SwarmStaffingCandidateFields::deserialize(deserializer)?;
        let candidate = Self {
            schema_version: fields.schema_version,
            staffing_id: fields.staffing_id,
            staffing_digest: fields.staffing_digest,
            account_scope: fields.account_scope,
            catalogue_snapshot_id: fields.catalogue_snapshot_id,
            catalogue_digest: fields.catalogue_digest,
            preference_policy_id: fields.preference_policy_id,
            preference_revision: fields.preference_revision,
            preference_policy_digest: fields.preference_policy_digest,
            demand: fields.demand,
            slots: fields.slots,
            gaps: fields.gaps,
            independence: fields.independence,
            execution: fields.execution,
            candidate_only: fields.candidate_only,
            dispatch_authority: fields.dispatch_authority,
        };
        candidate.validate().map_err(D::Error::custom)?;
        Ok(candidate)
    }
}

impl SwarmStaffingCandidate {
    /// A staffing with no gaps is complete; any gap means it cannot be
    /// represented as a runnable Swarm.
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    fn digest(&self) -> Result<String, ModelControlError> {
        let slot_digests: Vec<&str> = self
            .slots
            .iter()
            .map(|slot| slot.slot_digest.as_str())
            .collect();
        canonical_digest(&(
            SWARM_STAFFING_CANDIDATE_VERSION,
            self.staffing_id.as_str(),
            self.account_scope.as_str(),
            self.catalogue_snapshot_id.as_str(),
            self.catalogue_digest.as_str(),
            self.preference_policy_id.as_str(),
            self.preference_revision.as_str(),
            self.preference_policy_digest.as_str(),
            &self.demand,
            slot_digests,
            &self.gaps,
            &self.independence,
        ))
    }

    /// Validates identity, ordering, slot binding, gap/independence
    /// consistency, digest closure, and the candidate-only ceiling. Called on
    /// deserialization and after compilation.
    pub fn validate(&self) -> Result<(), SwarmStaffingError> {
        if self.schema_version != SWARM_STAFFING_CANDIDATE_VERSION {
            return Err(SwarmStaffingError::ModelControl(
                ModelControlError::UnsupportedSchema("swarm_staffing_candidate"),
            ));
        }
        validate_text(&self.staffing_id, "staffing.staffing_id")?;
        for (value, field) in [
            (self.account_scope.as_str(), "staffing.account_scope"),
            (
                self.catalogue_snapshot_id.as_str(),
                "staffing.catalogue_snapshot_id",
            ),
            (
                self.preference_policy_id.as_str(),
                "staffing.preference_policy_id",
            ),
            (
                self.preference_revision.as_str(),
                "staffing.preference_revision",
            ),
        ] {
            validate_text(value, field)?;
        }
        validate_canonical_digest(&self.staffing_digest, "staffing.staffing_digest")?;
        validate_canonical_digest(&self.catalogue_digest, "staffing.catalogue_digest")?;
        validate_canonical_digest(
            &self.preference_policy_digest,
            "staffing.preference_policy_digest",
        )?;
        if self.demand.is_empty() || self.demand.len() > MAX_STAFFING_SLOTS {
            return Err(SwarmStaffingError::InvalidField("staffing.demand"));
        }
        if !self.demand.is_sorted() || has_duplicates(&self.demand) {
            return Err(SwarmStaffingError::InvalidField("staffing.demand"));
        }
        self.validate_slots()?;
        self.validate_gaps()?;
        self.validate_independence()?;
        if !self.candidate_only || self.dispatch_authority {
            return Err(SwarmStaffingError::InvalidField("staffing.authority"));
        }
        if self.execution != ZeroModelExecutionCounters::zero() {
            return Err(SwarmStaffingError::InvalidField("staffing.execution"));
        }
        if self.staffing_digest != self.digest()? {
            return Err(SwarmStaffingError::InvalidField("staffing.staffing_digest"));
        }
        Ok(())
    }

    fn validate_slots(&self) -> Result<(), SwarmStaffingError> {
        if !self.slots.is_sorted_by_key(|slot| slot.role)
            || has_duplicates_by(&self.slots, |slot| slot.role)
        {
            return Err(SwarmStaffingError::InvalidField("staffing.slots"));
        }
        for slot in &self.slots {
            slot.validate(&self.staffing_id)?;
            if !self.demand.contains(&slot.role) {
                return Err(SwarmStaffingError::InvalidField("staffing.slots"));
            }
            if slot.account_scope != self.account_scope
                || slot.catalogue_snapshot_id != self.catalogue_snapshot_id
                || slot.catalogue_digest != self.catalogue_digest
                || slot.preference_policy_id != self.preference_policy_id
                || slot.preference_revision != self.preference_revision
                || slot.preference_policy_digest != self.preference_policy_digest
            {
                return Err(SwarmStaffingError::InvalidField("staffing.generation"));
            }
        }
        Ok(())
    }

    fn validate_gaps(&self) -> Result<(), SwarmStaffingError> {
        if !self.gaps.is_sorted() || has_duplicates(&self.gaps) {
            return Err(SwarmStaffingError::InvalidField("staffing.gaps"));
        }
        for gap in &self.gaps {
            match gap {
                StaffingGap::MissingRole { role } => {
                    if !self.demand.contains(role)
                        || self.slots.iter().any(|slot| &slot.role == role)
                    {
                        return Err(SwarmStaffingError::InvalidField("staffing.gaps"));
                    }
                }
                StaffingGap::DegradedIndependence { role, dimensions } => {
                    if dimensions.is_empty()
                        || !dimensions.is_sorted()
                        || has_duplicates(dimensions)
                        || !dimensions
                            .iter()
                            .all(|dimension| independence_dimensions().contains(dimension))
                    {
                        return Err(SwarmStaffingError::InvalidField("staffing.gaps"));
                    }
                    if !self.slots.iter().any(|slot| &slot.role == role) {
                        return Err(SwarmStaffingError::InvalidField("staffing.gaps"));
                    }
                }
            }
        }
        // Every demanded role resolves to exactly one slot or one missing gap.
        for role in &self.demand {
            let slotted = self.slots.iter().any(|slot| &slot.role == role);
            let gapped = self.gaps.iter().any(
                |gap| matches!(gap, StaffingGap::MissingRole { role: gap_role } if gap_role == role),
            );
            if slotted == gapped {
                return Err(SwarmStaffingError::InvalidField("staffing.gaps"));
            }
        }
        Ok(())
    }

    fn validate_independence(&self) -> Result<(), SwarmStaffingError> {
        if !self.independence.is_sorted_by_key(|decision| decision.role)
            || has_duplicates_by(&self.independence, |decision| decision.role)
        {
            return Err(SwarmStaffingError::InvalidField("staffing.independence"));
        }
        let primary_staffed = self
            .slots
            .iter()
            .any(|slot| slot.role == ModelRole::MainAgent);
        if self.independence.is_empty() {
            return Ok(());
        }
        if !primary_staffed {
            return Err(SwarmStaffingError::InvalidField("staffing.independence"));
        }
        for decision in &self.independence {
            if decision.role != ModelRole::Challenger && decision.role != ModelRole::Verifier {
                return Err(SwarmStaffingError::InvalidField("staffing.independence"));
            }
            if decision.primary_role != ModelRole::MainAgent {
                return Err(SwarmStaffingError::InvalidField("staffing.independence"));
            }
            if !self.slots.iter().any(|slot| slot.role == decision.role) {
                return Err(SwarmStaffingError::InvalidField("staffing.independence"));
            }
            if decision.dimensions != independence_dimensions() {
                return Err(SwarmStaffingError::InvalidField("staffing.independence"));
            }
            let expected_gap = self.gaps.iter().find(|gap| {
                matches!(
                    gap,
                    StaffingGap::DegradedIndependence { role, .. } if *role == decision.role
                )
            });
            match &decision.outcome {
                StaffingIndependenceOutcome::Satisfied => {
                    if expected_gap.is_some() {
                        return Err(SwarmStaffingError::InvalidField("staffing.independence"));
                    }
                }
                StaffingIndependenceOutcome::Degraded { dimensions } => {
                    let Some(StaffingGap::DegradedIndependence {
                        role: _,
                        dimensions: gap_dimensions,
                    }) = expected_gap
                    else {
                        return Err(SwarmStaffingError::InvalidField("staffing.independence"));
                    };
                    if dimensions != gap_dimensions {
                        return Err(SwarmStaffingError::InvalidField("staffing.independence"));
                    }
                }
            }
        }
        Ok(())
    }
}

/// Pairwise duplicate scan. Staffing collections stay within
/// `MAX_STAFFING_SLOTS`, so no ordering assumption is required.
fn has_duplicates<T: Eq>(values: &[T]) -> bool {
    values
        .iter()
        .enumerate()
        .any(|(index, left)| values.iter().skip(index + 1).any(|right| left == right))
}

fn has_duplicates_by<T, K: Eq>(values: &[T], mut key: impl FnMut(&T) -> K) -> bool {
    values.iter().enumerate().any(|(index, left)| {
        values
            .iter()
            .skip(index + 1)
            .any(|right| key(left) == key(right))
    })
}

/// Deterministic slot identity: staffing identity plus the canonical role key.
fn slot_id(staffing_id: &str, role: ModelRole) -> String {
    format!("{staffing_id}/{}", role_slot_key(role))
}

const fn role_slot_key(role: ModelRole) -> &'static str {
    match role {
        ModelRole::MainAgent => "MAIN_AGENT",
        ModelRole::Worker => "WORKER",
        ModelRole::Challenger => "CHALLENGER",
        ModelRole::Verifier => "VERIFIER",
        ModelRole::Researcher => "RESEARCHER",
        ModelRole::Synthesis => "SYNTHESIS",
        ModelRole::Watchdog => "WATCHDOG",
        ModelRole::Dreamer => "DREAMER",
    }
}

fn canonical_demand(request: &SwarmStaffingRequest) -> Result<Vec<ModelRole>, SwarmStaffingError> {
    if request.demand.is_empty() || request.demand.len() > MAX_STAFFING_SLOTS {
        return Err(SwarmStaffingError::InvalidField("staffing.demand"));
    }
    let mut demand = request.demand.clone();
    demand.sort();
    demand.dedup();
    if demand.len() != request.demand.len() {
        return Err(SwarmStaffingError::DuplicateIdentity("staffing.demand"));
    }
    Ok(demand)
}

fn admit_by_role<'request>(
    request: &'request SwarmStaffingRequest,
    demand: &[ModelRole],
) -> Result<BTreeMap<ModelRole, &'request ModelSelectionReceipt>, SwarmStaffingError> {
    if request.selections.len() > MAX_STAFFING_SLOTS {
        return Err(SwarmStaffingError::DuplicateIdentity("staffing.role"));
    }
    for receipt in &request.selections {
        receipt.validate()?;
    }
    for pair in request.selections.windows(2) {
        let (left, right) = (&pair[0], &pair[1]);
        if left.account_scope != right.account_scope
            || left.catalogue_snapshot_id != right.catalogue_snapshot_id
            || left.catalogue_digest != right.catalogue_digest
            || left.preference_policy_id != right.preference_policy_id
            || left.preference_revision != right.preference_revision
            || left.preference_policy_digest != right.preference_policy_digest
        {
            return Err(SwarmStaffingError::InvalidField("staffing.generation"));
        }
    }
    let mut selection_ids = BTreeSet::new();
    let mut entry_ids = BTreeSet::new();
    let mut by_role: BTreeMap<ModelRole, &ModelSelectionReceipt> = BTreeMap::new();
    for receipt in &request.selections {
        if !selection_ids.insert(receipt.selection_id.as_str()) {
            return Err(SwarmStaffingError::DuplicateIdentity(
                "staffing.selection_id",
            ));
        }
        if !entry_ids.insert(receipt.selected.entry_id.as_str()) {
            return Err(SwarmStaffingError::DuplicateIdentity(
                "staffing.selected_entry",
            ));
        }
        if !demand.contains(&receipt.role) {
            return Err(SwarmStaffingError::InvalidField("staffing.role"));
        }
        if by_role.insert(receipt.role, receipt).is_some() {
            return Err(SwarmStaffingError::DuplicateIdentity("staffing.role"));
        }
    }
    Ok(by_role)
}

/// Compiles the bounded staffing candidate for one immutable role demand from
/// exact current A-02 selection receipts. Pure and deterministic: permuting
/// the input demand or selection order yields the identical output.
///
/// The supplied catalogue/policy generation is the currentness anchor: every
/// receipt must reproduce exactly against it via `validate_against`, so a
/// missing or stale selection fails closed instead of staffing a slot.
pub fn compile_swarm_staffing(
    request: &SwarmStaffingRequest,
) -> Result<SwarmStaffingCandidate, SwarmStaffingError> {
    validate_text(&request.staffing_id, "staffing.staffing_id")?;
    if request.now_unix_ms == 0 {
        return Err(SwarmStaffingError::InvalidField("staffing.now_unix_ms"));
    }
    let demand = canonical_demand(request)?;
    request.catalogue.validate()?;
    request.policy.validate()?;
    if request.catalogue.account_scope != request.policy.account_scope {
        return Err(SwarmStaffingError::InvalidField("staffing.account_scope"));
    }
    let by_role = admit_by_role(request, &demand)?;
    for receipt in by_role.values() {
        receipt.validate_against(&request.catalogue, &request.policy, request.now_unix_ms)?;
    }
    let entries: Vec<ModelCatalogueEntry> = by_role
        .values()
        .map(|receipt| receipt.selected.clone())
        .collect();
    validate_no_secret_or_fixed_input(&entries)?;

    let mut slots = Vec::with_capacity(by_role.len());
    let mut gaps = Vec::new();
    for role in &demand {
        let Some(receipt) = by_role.get(role) else {
            gaps.push(StaffingGap::MissingRole { role: *role });
            continue;
        };
        let mut slot = StaffedSlot {
            slot_id: slot_id(&request.staffing_id, *role),
            role: *role,
            selection_id: receipt.selection_id.clone(),
            selection_digest: receipt.selection_digest.clone(),
            account_scope: receipt.account_scope.clone(),
            catalogue_snapshot_id: receipt.catalogue_snapshot_id.clone(),
            catalogue_digest: receipt.catalogue_digest.clone(),
            preference_policy_id: receipt.preference_policy_id.clone(),
            preference_revision: receipt.preference_revision.clone(),
            preference_policy_digest: receipt.preference_policy_digest.clone(),
            selected: receipt.selected.clone(),
            slot_digest: String::new(),
        };
        slot.slot_digest = slot.digest(&request.staffing_id)?;
        slots.push(slot);
    }

    let mut independence = Vec::new();
    if let Some(primary) = slots.iter().find(|slot| slot.role == ModelRole::MainAgent) {
        for slot in &slots {
            if slot.role != ModelRole::Challenger && slot.role != ModelRole::Verifier {
                continue;
            }
            let dimensions = independence_dimensions();
            let collision = entry_diversity_gaps(&slot.selected, &primary.selected, &dimensions);
            let outcome = if collision.is_empty() {
                StaffingIndependenceOutcome::Satisfied
            } else {
                gaps.push(StaffingGap::DegradedIndependence {
                    role: slot.role,
                    dimensions: collision.clone(),
                });
                StaffingIndependenceOutcome::Degraded {
                    dimensions: collision,
                }
            };
            independence.push(StaffingIndependenceDecision {
                role: slot.role,
                primary_role: ModelRole::MainAgent,
                dimensions,
                outcome,
            });
        }
        gaps.sort();
    }

    let mut candidate = SwarmStaffingCandidate {
        schema_version: SWARM_STAFFING_CANDIDATE_VERSION.to_owned(),
        staffing_id: request.staffing_id.clone(),
        staffing_digest: String::new(),
        account_scope: request.catalogue.account_scope.clone(),
        catalogue_snapshot_id: request.catalogue.snapshot_id.clone(),
        catalogue_digest: catalogue_digest(&request.catalogue)?,
        preference_policy_id: request.policy.policy_id.clone(),
        preference_revision: request.policy.revision.clone(),
        preference_policy_digest: preference_policy_digest(&request.policy)?,
        demand,
        slots,
        gaps,
        independence,
        execution: ZeroModelExecutionCounters::zero(),
        candidate_only: true,
        dispatch_authority: false,
    };
    candidate.staffing_digest = candidate.digest()?;
    candidate.validate()?;
    Ok(candidate)
}
