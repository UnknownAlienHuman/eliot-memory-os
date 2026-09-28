//! Bind staffed model slots to exact external attempt, lease and fence admissions.
//!
//! [`compile_swarm_admission_plan`] consumes one complete
//! [`SwarmStaffingCandidate`] (compiled by the exact owner entrypoint
//! [`compile_swarm_staffing`](crate::swarm_staffing::compile_swarm_staffing)),
//! one externally issued [`ProviderAdmissionReceipt`], and one immutable
//! [`SwarmSlotAdmission`] per staffed role slot. It records the handoff as a
//! deterministic [`SwarmAdmissionPlanCandidate`] with a canonical digest.
//! There is no second staffing, selection, or admission path: slot identity,
//! selection digests, catalogue/policy pins, attempt/lease/fence identities,
//! and admitted routes stay owned by their exact owners; this module only
//! admits exact values present in the supplied envelope and records the
//! resulting binding.
//!
//! Time currency is an owner-issued bound, enforced here. The external
//! [`ProviderAdmissionReceipt`] carries `expires_at_unix_ms` — the admission's
//! own expiry, issued by the admission owner (I6.10:79-91, "issued/expires/
//! heartbeat" on the admission that authorizes work; I14.6:45-61,
//! `expires_at_and_release_reason` on the matching canonical admission). This
//! compiler compares that recorded value against the request's observation
//! instant in exactly the shape the sibling adapters already use for every
//! other owner-issued bound
//! ([`crates/agent/eliot-agent-opencode/src/catalogue.rs`](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/main/crates/agent/eliot-agent-opencode/src/catalogue.rs) `window`),
//! so an expired receipt fails closed with
//! [`SwarmAdmissionBindError::ExpiredAdmission`] and a stale epoch, a rotated
//! generation, and an aged receipt stay three distinct refusals. A zero
//! expiry is refused as an unissued bound, never read as "never expires".
//!
//! One residual is not expressible as a value and is stated once here instead:
//! **no production issuer of `expires_at_unix_ms` exists in this tree yet.**
//! Every construction site of the receipt is a test fixture, so a bound that
//! passes today has been validated as a supplied value, not yet as a value
//! some live owner issued against a real admission. See
//! [`ADMISSION_EXPIRY_PRODUCER_STATUS`]. This is deliberately not a field on
//! [`SwarmAdmissionPlanCandidate`]: a durable, replayable plan carrying a
//! "no producer yet" flag would become false the moment a real issuer lands and
//! would retroactively invalidate every stored plan.
//!
//! No production caller publishes a [`SwarmAdmissionPlanCandidate`] yet: a
//! repo-wide grep finds the type only in this module and in the serde-boundary
//! data file, with no `From`/`Into` to any launch or Task-completion type. The
//! only constructor is [`compile_swarm_admission_plan`] plus validating
//! deserialization.
//!
//! Fail-closed binding, in deterministic precedence:
//!
//! 1. structural input validation (a blank plan identity, a blank slot or
//!    selection pin, or a zero observation instant is rejected before any
//!    other check);
//! 2. staffing self-validation: the candidate must validate through its exact
//!    owner and contain no gaps ([`SwarmStaffingCandidate::is_complete`]);
//!    a gapped staffing cannot advance toward execution;
//! 3. admission-envelope structural validation (blank receipt refs, an invalid
//!    [`StateFence`], an unvalidated provider identity, or an empty lane
//!    denominator is rejected);
//! 4. exact one-to-one denominator: binding and admitted-lane counts must
//!    equal the staffed slot count, every staffed slot resolves to exactly
//!    one binding/lane, and duplicate or extra identities fail closed;
//! 5. per-slot identity survival: the caller-presented slot, selection,
//!    catalogue, and policy pins must equal the staffed slot byte-for-byte,
//!    so selection/catalogue/policy identity survives unchanged into the
//!    handoff;
//! 6. independent external validation: every bound
//!    [`AdmittedRouteReceipt`] is revalidated through its exact owner
//!    ([`AdmittedRouteReceipt::validate`]), which recomputes the receipt self
//!    digest and enforces the candidate-only proof ceiling;
//! 7. exact route binding: the admitted selected route and the requested route
//!    must both equal the staffed [`RouteFingerprint`]; an admission for
//!    another route, or an admission authorizing no route, fails closed rather
//!    than substituting the staffed route;
//! 8. exact fence pinning: the bound [`StateFence`] must equal the fence
//!    inside the external receipt, so a caller cannot swap the fence between
//!    external issuance and binding;
//! 9. authority-epoch currency: the bound fence epoch must be the exact same
//!    authority tuple as the envelope controller epoch
//!    ([`EpochId::is_same_authority`]); a stale epoch fails closed;
//! 10. lane currency: the bound work-unit/attempt/lease triple must appear in
//!     the current envelope lanes, and the matched lane must carry the same
//!     external route receipt. Lease and attempt identity must match the
//!     route receipt and supplied envelope exactly, and the lane's recorded
//!     routing digest must equal the receipt's admitted candidate digest, so
//!     a receipt crossed into a foreign lane fails;
//! 11. owner-issued expiry: the recorded observation instant must fall inside
//!     the external receipt's own `expires_at_unix_ms`. A zero observation
//!     instant, a zero (unissued) expiry, or an expiry already passed fails
//!     closed; on `validate()` the check re-runs against the plan's own stored
//!     `observed_at_unix_ms` and the stored receipt's stored expiry, so a
//!     tampered expiry or a restated observation is rejected rather than
//!     silently treated as current.
//!
//! The output is structurally candidate-only: `candidate_only` is true,
//! `dispatch_authority` is false, execution counters are zero, and the value
//! carries no executable argv, credential, process handle, provider session,
//! mailbox mutation, Concilium decision, canonical Task write, or Finish
//! authority. It performs no provider/model call, no process launch or cancel,
//! no lease/fence/attempt/route issuance, no Task write, and no automatic
//! failover. There is no `From`/`Into` conversion from the plan to a launch
//! or Task-completion type: the only constructor is
//! [`compile_swarm_admission_plan`] (plus validating deserialization), and the
//! accessors below re-assert the ceiling on every read.
//!
//! Proof ceiling: `SWARM_EXTERNAL_ADMISSION_HANDOFF_PACKAGE_PROOF_ONLY`. Real
//! Governor/User Broker admission, provider process execution, liveness/effect
//! reconciliation and Product Pulse remain separate.

use std::collections::BTreeSet;

use eliot_agent_api::{
    AdmittedRouteReceipt, AttemptId, ContractError, EpochId, ResourceGeneration, RouteFingerprint,
    StateFence, TaskId, WorkLeaseId, WorkUnitId,
};
use eliot_agent_contracts::RevisionId;
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

use crate::model::{AdmissionId, CoordinatorError, ProviderAdmissionReceipt, validate_text};
use crate::model_control::{
    ModelControlError, ModelRole, ZeroModelExecutionCounters, canonical_digest,
    validate_canonical_digest,
};
use crate::swarm_staffing::{
    MAX_STAFFING_SLOTS, StaffedSlot, SwarmStaffingCandidate, SwarmStaffingError,
};

/// Schema identity for the candidate-only admission-plan value.
pub const SWARM_ADMISSION_PLAN_VERSION: &str = "eliot.agent-swarm-admission-plan/v1";

/// Fail-closed admission-binding errors. Every production path returns these
/// instead of panicking; a malformed, unauthorized, stale, mismatched, or
/// conflicting binding is rejected, never repaired.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SwarmAdmissionBindError {
    #[error(transparent)]
    ModelControl(#[from] ModelControlError),
    #[error(transparent)]
    Staffing(#[from] SwarmStaffingError),
    #[error(transparent)]
    Contract(#[from] ContractError),
    #[error(transparent)]
    Coordinator(#[from] CoordinatorError),
    #[error("invalid swarm admission-binding field: {0}")]
    InvalidField(&'static str),
    #[error("duplicate swarm admission-binding identity: {0}")]
    DuplicateIdentity(&'static str),
    #[error("swarm staffing candidate is not complete")]
    IncompleteStaffing,
    #[error("swarm admission binding pins a stale authority epoch")]
    StaleEpoch,
    #[error("swarm admission binding pins a stale admission generation")]
    StaleGeneration,
    #[error("swarm admission binding pins an expired external admission receipt")]
    ExpiredAdmission,
    #[error("swarm admission binding identity conflict: same id with changed bytes")]
    IdentityConflict,
}

/// Field label for the owner-issued admission expiry window.
pub const ADMISSION_EXPIRY_WINDOW_FIELD: &str = "admission.expires_at_unix_ms";

/// The one fact about the expiry bound that a type cannot express: no
/// PRODUCTION issuer of [`ProviderAdmissionReceipt`] populates
/// `expires_at_unix_ms` yet. Every construction site of that receipt in this
/// tree is a test fixture
/// (`crates/agent/eliot-agent-coordinator/tests/coordinator.rs`,
/// `crates/agent/eliot-agent-coordinator/src/tests.rs`,
/// `crates/agent/eliot-agent-coordinator/src/core/admission_normalization_tests.rs`),
/// so a bound that passes this module's window check today has been validated
/// as a supplied value, not yet as a value some owner actually issued against a
/// live admission.
///
/// This is deliberately a documentation constant and not a field on
/// [`SwarmAdmissionPlanCandidate`]. A plan is a durable, replayable record: a
/// per-plan "no production issuer yet" flag would become false the moment a
/// real issuer lands and would retroactively invalidate every stored plan,
/// which is a worse failure than saying it once, here.
pub const ADMISSION_EXPIRY_PRODUCER_STATUS: &str =
    "no production issuer of ProviderAdmissionReceipt::expires_at_unix_ms in this tree yet";

/// Enforces the owner-issued admission expiry window, in the shape the sibling
/// adapters already use for every owner-issued bound
/// (`crates/agent/eliot-agent-opencode/src/catalogue.rs::window`,
/// `crates/agent/eliot-agent-codex/src/catalogue.rs::window`).
///
/// Both values are the ORIGINAL recorded ones: `expires_at_unix_ms` is read
/// from the supplied external receipt and `observed_at_unix_ms` is the
/// instant the binding was recorded at. Nothing is recomputed and the receipt
/// is never re-derived.
///
/// A zero observation instant and a zero expiry both fail closed with
/// [`SwarmAdmissionBindError::InvalidField`]: an unissued bound is not a
/// current bound, and zero is never read as "never expires". An expiry that
/// has already passed fails closed with
/// [`SwarmAdmissionBindError::ExpiredAdmission`], so a stale epoch, a rotated
/// generation, and an aged receipt are three distinct refusals rather than one.
fn check_admission_window(
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
) -> Result<(), SwarmAdmissionBindError> {
    if observed_at_unix_ms == 0 || expires_at_unix_ms == 0 {
        return Err(SwarmAdmissionBindError::InvalidField(
            ADMISSION_EXPIRY_WINDOW_FIELD,
        ));
    }
    if expires_at_unix_ms < observed_at_unix_ms {
        return Err(SwarmAdmissionBindError::ExpiredAdmission);
    }
    Ok(())
}

/// One immutable admission-binding input per staffed role slot.
///
/// The slot, selection, catalogue, and policy pins echo the staffed slot and
/// must reproduce it exactly; the work-unit, attempt, lease, fence, and
/// admitted route are externally issued admission evidence. The compiler
/// admits them only on exact match and never mints replacements.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmSlotAdmission {
    pub slot_id: String,
    pub selection_id: String,
    pub selection_digest: String,
    pub catalogue_snapshot_id: String,
    pub catalogue_digest: String,
    pub preference_policy_id: String,
    pub preference_revision: String,
    pub preference_policy_digest: String,
    pub work_unit_id: WorkUnitId,
    pub attempt_id: AttemptId,
    pub lease_id: WorkLeaseId,
    pub fence: StateFence,
    pub admitted_route: AdmittedRouteReceipt,
}

/// Exact binding input: the complete staffing candidate, the current external
/// admission envelope, one [`SwarmSlotAdmission`] per staffed slot, and the
/// non-zero observation instant the binding is recorded against. That instant
/// is compared against the owner-issued `expires_at_unix_ms` carried on the
/// supplied receipt, so it establishes the receipt's time currency rather than
/// asserting a local deadline.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmAdmissionBindRequest {
    pub plan_id: String,
    pub staffing: SwarmStaffingCandidate,
    pub admission: ProviderAdmissionReceipt,
    pub bindings: Vec<SwarmSlotAdmission>,
    /// Must be non-zero. The instant the binding is observed at; it is compared
    /// against the receipt's own owner-issued `expires_at_unix_ms`, and a
    /// zero value is refused rather than read as "before any expiry".
    pub now_unix_ms: u64,
}

/// One staffed slot bound to its exact external admission evidence.
///
/// The bound route is the staffed [`RouteFingerprint`] itself (never a digest
/// reference or vendor/model tuple); the stored external receipt pins the
/// exact externally issued bytes the binding was compiled from, and the
/// catalogue/policy pins reproduce the staffed generation verbatim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmBoundSlot {
    pub slot_id: String,
    pub role: ModelRole,
    pub selection_id: String,
    pub selection_digest: String,
    pub catalogue_snapshot_id: String,
    pub catalogue_digest: String,
    pub preference_policy_id: String,
    pub preference_revision: String,
    pub preference_policy_digest: String,
    pub work_unit_id: WorkUnitId,
    pub attempt_id: AttemptId,
    pub lease_id: WorkLeaseId,
    pub fence: StateFence,
    pub route: RouteFingerprint,
    pub admitted_route: AdmittedRouteReceipt,
    pub runtime_generation: ResourceGeneration,
    /// Canonical digest over the plan identity plus every bound field,
    /// including the external receipt self digest. Validators recompute; a
    /// tampered copy is rejected.
    pub slot_binding_digest: String,
}

impl SwarmBoundSlot {
    fn digest(&self, plan_id: &str) -> Result<String, ModelControlError> {
        canonical_digest(&(
            SWARM_ADMISSION_PLAN_VERSION,
            plan_id,
            self.slot_id.as_str(),
            self.role,
            self.selection_id.as_str(),
            self.selection_digest.as_str(),
            (
                self.catalogue_snapshot_id.as_str(),
                self.catalogue_digest.as_str(),
                self.preference_policy_id.as_str(),
                self.preference_revision.as_str(),
                self.preference_policy_digest.as_str(),
            ),
            (
                &self.work_unit_id,
                &self.attempt_id,
                &self.lease_id,
                &self.fence,
                &self.route,
            ),
            (
                &self.admitted_route.self_digest,
                self.runtime_generation,
                &self.admitted_route.policy_revision,
            ),
        ))
    }

    /// Re-checks the stored pins against the staffed slot they were compiled
    /// from. On the compile path the pins were just echoed, so this passes
    /// for honest inputs; on the validation path (deserialized bytes) it
    /// rejects any drift in selection/catalogue/policy identity.
    fn check_staffing_pins(&self, staffed: &StaffedSlot) -> Result<(), SwarmAdmissionBindError> {
        if self.slot_id != staffed.slot_id || self.role != staffed.role {
            return Err(SwarmAdmissionBindError::InvalidField("admission.slot"));
        }
        if self.selection_id != staffed.selection_id
            || self.selection_digest != staffed.selection_digest
            || self.catalogue_snapshot_id != staffed.catalogue_snapshot_id
            || self.catalogue_digest != staffed.catalogue_digest
            || self.preference_policy_id != staffed.preference_policy_id
            || self.preference_revision != staffed.preference_revision
            || self.preference_policy_digest != staffed.preference_policy_digest
        {
            return Err(SwarmAdmissionBindError::InvalidField("admission.selection"));
        }
        if self.route != staffed.selected.route {
            return Err(SwarmAdmissionBindError::InvalidField("admission.route"));
        }
        Ok(())
    }
}

/// Deterministic, bounded, candidate-only admission plan. Replaying the exact
/// input reproduces the exact value; reusing the plan identity with changed
/// bytes is a conflict detected by
/// [`SwarmAdmissionPlanCandidate::replay_disposition`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmAdmissionPlanCandidate {
    pub schema_version: String,
    pub plan_id: String,
    pub plan_digest: String,
    pub staffing_id: String,
    pub staffing_digest: String,
    pub admission_id: AdmissionId,
    pub task_id: TaskId,
    pub task_revision: String,
    pub plan_revision: RevisionId,
    pub controller_epoch: EpochId,
    pub coordinator_lease: WorkLeaseId,
    /// One bound slot per staffed role in canonical [`ModelRole`] order.
    pub slots: Vec<SwarmBoundSlot>,
    /// The complete staffing this plan was compiled from, stored verbatim so
    /// validation is self-contained.
    pub staffing: SwarmStaffingCandidate,
    /// The current external admission envelope this plan was compiled
    /// against, stored verbatim so validation is self-contained. Its
    /// owner-issued `expires_at_unix_ms` is the recorded time bound.
    pub admission: ProviderAdmissionReceipt,
    /// The instant this plan was compiled and observed at. Stored so
    /// [`SwarmAdmissionPlanCandidate::validate`] can re-check the recorded
    /// expiry against a recorded observation instead of a caller-supplied
    /// clock, and sealed into `plan_digest` so a replay cannot restate the
    /// same binding at a different observation.
    pub observed_at_unix_ms: u64,
    pub execution: ZeroModelExecutionCounters,
    pub candidate_only: bool,
    pub dispatch_authority: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SwarmAdmissionPlanCandidateFields {
    schema_version: String,
    plan_id: String,
    plan_digest: String,
    staffing_id: String,
    staffing_digest: String,
    admission_id: AdmissionId,
    task_id: TaskId,
    task_revision: String,
    plan_revision: RevisionId,
    controller_epoch: EpochId,
    coordinator_lease: WorkLeaseId,
    slots: Vec<SwarmBoundSlot>,
    staffing: SwarmStaffingCandidate,
    admission: ProviderAdmissionReceipt,
    observed_at_unix_ms: u64,
    execution: ZeroModelExecutionCounters,
    candidate_only: bool,
    dispatch_authority: bool,
}

impl<'de> Deserialize<'de> for SwarmAdmissionPlanCandidate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = SwarmAdmissionPlanCandidateFields::deserialize(deserializer)?;
        let candidate = Self {
            schema_version: fields.schema_version,
            plan_id: fields.plan_id,
            plan_digest: fields.plan_digest,
            staffing_id: fields.staffing_id,
            staffing_digest: fields.staffing_digest,
            admission_id: fields.admission_id,
            task_id: fields.task_id,
            task_revision: fields.task_revision,
            plan_revision: fields.plan_revision,
            controller_epoch: fields.controller_epoch,
            coordinator_lease: fields.coordinator_lease,
            slots: fields.slots,
            staffing: fields.staffing,
            admission: fields.admission,
            observed_at_unix_ms: fields.observed_at_unix_ms,
            execution: fields.execution,
            candidate_only: fields.candidate_only,
            dispatch_authority: fields.dispatch_authority,
        };
        candidate.validate().map_err(serde::de::Error::custom)?;
        Ok(candidate)
    }
}

impl SwarmAdmissionPlanCandidate {
    fn digest(&self) -> Result<String, ModelControlError> {
        let slot_digests: Vec<&str> = self
            .slots
            .iter()
            .map(|slot| slot.slot_binding_digest.as_str())
            .collect();
        let envelope_digest = canonical_digest(&self.admission)?;
        canonical_digest(&(
            SWARM_ADMISSION_PLAN_VERSION,
            self.plan_id.as_str(),
            self.staffing_digest.as_str(),
            envelope_digest.as_str(),
            self.observed_at_unix_ms,
            self.admission_id.as_str(),
            self.task_id.as_str(),
            self.task_revision.as_str(),
            &self.plan_revision,
            &self.controller_epoch,
            &self.coordinator_lease,
            slot_digests,
        ))
    }

    /// Validates identity, staffing completeness, envelope structure,
    /// slot/route/fence/epoch/lane binding, the owner-issued admission expiry
    /// window, digest closure, and the candidate-only ceiling. Called on
    /// deserialization and after compilation. Full compilation against fresh
    /// caller inputs requires [`compile_swarm_admission_plan`]; this check
    /// covers internal consistency of the stored value only.
    pub fn validate(&self) -> Result<(), SwarmAdmissionBindError> {
        if self.schema_version != SWARM_ADMISSION_PLAN_VERSION {
            return Err(SwarmAdmissionBindError::ModelControl(
                ModelControlError::UnsupportedSchema("swarm_admission_plan"),
            ));
        }
        validate_text(&self.plan_id, "admission.plan_id")?;
        validate_text(&self.task_revision, "admission.task_revision")?;
        validate_canonical_digest(&self.plan_digest, "admission.plan_digest")?;
        self.staffing.validate()?;
        if !self.staffing.is_complete() {
            return Err(SwarmAdmissionBindError::IncompleteStaffing);
        }
        validate_envelope(&self.admission)?;
        self.validate_pins()?;
        self.validate_admission_window()?;
        self.validate_slots()?;
        if !self.candidate_only || self.dispatch_authority {
            return Err(SwarmAdmissionBindError::InvalidField("admission.authority"));
        }
        if self.execution != ZeroModelExecutionCounters::zero() {
            return Err(SwarmAdmissionBindError::InvalidField("admission.execution"));
        }
        if self.plan_digest != self.digest()? {
            return Err(SwarmAdmissionBindError::InvalidField(
                "admission.plan_digest",
            ));
        }
        Ok(())
    }

    fn validate_pins(&self) -> Result<(), SwarmAdmissionBindError> {
        if self.staffing_id != self.staffing.staffing_id
            || self.staffing_digest != self.staffing.staffing_digest
        {
            return Err(SwarmAdmissionBindError::InvalidField("admission.staffing"));
        }
        if self.admission_id != self.admission.admission_id
            || self.task_id != self.admission.task_id
            || self.task_revision != self.admission.task_revision
            || self.plan_revision != self.admission.plan_revision
            || self.controller_epoch != self.admission.controller_epoch
            || self.coordinator_lease != self.admission.coordinator_lease
        {
            return Err(SwarmAdmissionBindError::InvalidField("admission.envelope"));
        }
        Ok(())
    }

    /// Re-checks the owner-issued expiry against this plan's own recorded
    /// observation instant.
    ///
    /// Both operands are ORIGINAL recorded values: the expiry is the
    /// `expires_at_unix_ms` on the stored external receipt and the observation
    /// is this plan's `observed_at_unix_ms`, which is sealed into
    /// `plan_digest`. Nothing is recomputed and the receipt is never
    /// re-derived, so a tampered expiry or a restated observation fails here
    /// rather than being silently accepted as current.
    fn validate_admission_window(&self) -> Result<(), SwarmAdmissionBindError> {
        check_admission_window(self.observed_at_unix_ms, self.admission.expires_at_unix_ms)
    }

    fn validate_slots(&self) -> Result<(), SwarmAdmissionBindError> {
        if self.slots.len() != self.staffing.slots.len()
            || !self.slots.is_sorted_by_key(|slot| slot.role)
            || has_duplicate_slot_ids(&self.slots)
        {
            return Err(SwarmAdmissionBindError::InvalidField(
                "admission.denominator",
            ));
        }
        validate_lane_denominator(&self.admission, self.staffing.slots.len())?;
        let mut work_unit_ids = BTreeSet::new();
        let mut attempt_ids = BTreeSet::new();
        let mut lease_ids = BTreeSet::new();
        let mut route_receipt_digests = BTreeSet::new();
        for bound in &self.slots {
            if !work_unit_ids.insert(&bound.work_unit_id)
                || !attempt_ids.insert(&bound.attempt_id)
                || !lease_ids.insert(&bound.lease_id)
                || !route_receipt_digests.insert(bound.admitted_route.self_digest.as_str())
            {
                return Err(SwarmAdmissionBindError::InvalidField(
                    "admission.denominator",
                ));
            }
            let Some(staffed) = self
                .staffing
                .slots
                .iter()
                .find(|slot| slot.slot_id == bound.slot_id)
            else {
                return Err(SwarmAdmissionBindError::InvalidField("admission.slot"));
            };
            check_bound_slot(bound, staffed, &self.plan_id, &self.admission)?;
        }
        Ok(())
    }

    /// Plans never execute: the counter receipt is always zero.
    #[must_use]
    pub const fn execution(&self) -> ZeroModelExecutionCounters {
        ZeroModelExecutionCounters::zero()
    }

    /// Plans never grant dispatch authority.
    #[must_use]
    pub const fn dispatch_authority(&self) -> bool {
        false
    }

    /// Plans are candidate preparation only.
    #[must_use]
    pub const fn candidate_only(&self) -> bool {
        true
    }

    /// The owner-issued expiry of the external admission receipt this plan was
    /// compiled against, in Unix milliseconds.
    ///
    /// This is the recorded value, not a recomputed one. It was already
    /// checked against [`SwarmAdmissionPlanCandidate::observed_at_unix_ms`] by
    /// [`SwarmAdmissionPlanCandidate::validate`]; reading it re-exposes the
    /// bound without re-deciding currency.
    #[must_use]
    pub const fn admission_expires_at_unix_ms(&self) -> u64 {
        self.admission.expires_at_unix_ms
    }

    /// The instant this plan was compiled and observed at, in Unix
    /// milliseconds. Sealed into the plan digest, so replaying the same plan
    /// identity at a different instant is a conflict, not a silent refresh.
    #[must_use]
    pub const fn observed_at_unix_ms(&self) -> u64 {
        self.observed_at_unix_ms
    }

    /// Exact-replay/conflict rule: identical canonical bytes replay, a reused
    /// plan id with changed bytes conflicts, and a different plan id is a new
    /// plan rather than a replay.
    pub fn replay_disposition(
        &self,
        previous: &Self,
    ) -> Result<SwarmAdmissionReplayDisposition, SwarmAdmissionBindError> {
        self.validate()?;
        previous.validate()?;
        if self.plan_id != previous.plan_id {
            return Ok(SwarmAdmissionReplayDisposition::NewBinding);
        }
        if self.plan_digest == previous.plan_digest {
            Ok(SwarmAdmissionReplayDisposition::ExactReplay)
        } else {
            Err(SwarmAdmissionBindError::IdentityConflict)
        }
    }
}

/// Outcome of [`SwarmAdmissionPlanCandidate::replay_disposition`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SwarmAdmissionReplayDisposition {
    ExactReplay,
    NewBinding,
}

fn has_duplicate_slot_ids(slots: &[SwarmBoundSlot]) -> bool {
    slots.iter().enumerate().any(|(index, left)| {
        slots
            .iter()
            .skip(index + 1)
            .any(|right| left.slot_id == right.slot_id)
    })
}

/// Structural validation of the external admission envelope: receipt refs are
/// non-blank, the envelope fence validates, the provider identity validates
/// through its exact owner, and the lane denominator is non-empty and
/// bounded. The envelope's owner-issued `expires_at_unix_ms` is the time bound
/// this compiler validates; the currentness of that bound is
/// [`check_admission_window`], not a field-shape question. The compiler pins
/// these exact bytes into the plan digest and never mints a newer admission.
fn validate_envelope(admission: &ProviderAdmissionReceipt) -> Result<(), SwarmAdmissionBindError> {
    validate_text(&admission.task_revision, "admission.task_revision")?;
    validate_text(
        &admission.g11_admission_receipt_ref,
        "admission.g11_admission_receipt_ref",
    )?;
    validate_text(&admission.durable_job_ref, "admission.durable_job_ref")?;
    if admission.state_fence.validate().is_err() {
        return Err(SwarmAdmissionBindError::InvalidField("admission.envelope"));
    }
    admission.provider_identity.validate()?;
    if admission.admitted_lanes.is_empty() || admission.admitted_lanes.len() > MAX_STAFFING_SLOTS {
        return Err(SwarmAdmissionBindError::InvalidField("admission.lanes"));
    }
    Ok(())
}

/// The external envelope must contain exactly one distinct admitted lane for
/// every staffed slot. A shared lane cannot satisfy multiple slots, and an
/// unrelated extra lane cannot be smuggled into this candidate's denominator.
fn validate_lane_denominator(
    admission: &ProviderAdmissionReceipt,
    expected_slots: usize,
) -> Result<(), SwarmAdmissionBindError> {
    if admission.admitted_lanes.len() != expected_slots {
        return Err(SwarmAdmissionBindError::InvalidField(
            "admission.lanes.denominator",
        ));
    }
    let mut work_unit_ids = BTreeSet::new();
    let mut attempt_ids = BTreeSet::new();
    let mut lease_ids = BTreeSet::new();
    for lane in &admission.admitted_lanes {
        if !work_unit_ids.insert(&lane.work_unit_id)
            || !attempt_ids.insert(&lane.attempt_id)
            || !lease_ids.insert(&lane.lease_id)
        {
            return Err(SwarmAdmissionBindError::DuplicateIdentity(
                "admission.lanes",
            ));
        }
    }
    Ok(())
}

/// Checks one compiled bound slot against its staffed slot and the current
/// envelope: slot/selection/catalogue/policy identity survival, independent
/// external receipt validation, exact route and fence binding,
/// authority-epoch currency, lane currency, and digest closure.
fn check_bound_slot(
    bound: &SwarmBoundSlot,
    staffed: &StaffedSlot,
    plan_id: &str,
    admission: &ProviderAdmissionReceipt,
) -> Result<(), SwarmAdmissionBindError> {
    bound.check_staffing_pins(staffed)?;
    bound.admitted_route.validate()?;
    if bound.admitted_route.selected_route.as_ref() != Some(&bound.route)
        || bound.admitted_route.requested_route != bound.route
    {
        return Err(SwarmAdmissionBindError::InvalidField("admission.route"));
    }
    if bound.admitted_route.attempt_id != bound.attempt_id
        || bound.admitted_route.lease_id != bound.lease_id
        || bound.admitted_route.runtime_generation != bound.fence.resource_generation
    {
        return Err(SwarmAdmissionBindError::InvalidField(
            "admission.route_identity",
        ));
    }
    if bound.fence != bound.admitted_route.state_fence {
        return Err(SwarmAdmissionBindError::InvalidField("admission.fence"));
    }
    if bound.fence != admission.state_fence {
        return Err(SwarmAdmissionBindError::InvalidField(
            "admission.envelope_fence",
        ));
    }
    if bound.fence.validate().is_err() {
        return Err(SwarmAdmissionBindError::InvalidField("admission.fence"));
    }
    if !bound
        .fence
        .authority_epoch
        .is_same_authority(&admission.controller_epoch)
    {
        return Err(SwarmAdmissionBindError::StaleEpoch);
    }
    check_lane_currency(bound, admission)?;
    if bound.slot_binding_digest != bound.digest(plan_id)? {
        return Err(SwarmAdmissionBindError::InvalidField(
            "admission.slot_binding_digest",
        ));
    }
    Ok(())
}

/// The bound work-unit/attempt/lease triple must appear in the supplied
/// envelope lanes, the matched lane must carry the exact external route
/// receipt, the lane's recorded routing digest must equal the receipt's
/// admitted candidate digest (the S5 admit invariant), and the lane route
/// must equal the bound route. A triple the supplied envelope does not
/// admit — rotated or foreign — fails closed, as does a receipt crossed
/// into a lane admitted for another candidate; this compiler does not mint
/// replacements. Envelope age is a separate axis, refused through
/// [`check_admission_window`] against the receipt's own
/// `expires_at_unix_ms`.
fn check_lane_currency(
    bound: &SwarmBoundSlot,
    admission: &ProviderAdmissionReceipt,
) -> Result<(), SwarmAdmissionBindError> {
    let Some(lane) = admission.admitted_lanes.iter().find(|lane| {
        lane.work_unit_id == bound.work_unit_id
            && lane.attempt_id == bound.attempt_id
            && lane.lease_id == bound.lease_id
    }) else {
        return Err(SwarmAdmissionBindError::StaleGeneration);
    };
    let Some(lane_route) = lane.admitted_route.as_ref() else {
        return Err(SwarmAdmissionBindError::StaleGeneration);
    };
    if lane_route != &bound.admitted_route {
        return Err(SwarmAdmissionBindError::StaleGeneration);
    }
    if lane.routing_receipt_digest != lane_route.candidate_digest {
        return Err(SwarmAdmissionBindError::InvalidField(
            "admission.route_identity",
        ));
    }
    if lane.route != bound.route {
        return Err(SwarmAdmissionBindError::InvalidField("admission.route"));
    }
    Ok(())
}

/// Binds one complete staffing candidate to exact external admission evidence.
///
/// Pure and deterministic: no provider/model call, no process launch or
/// cancel, no lease/fence/attempt/route issuance, no Task write, no mailbox
/// mutation, no fallback. Any missing, extra, duplicate, stale, mismatched,
/// expired, or tampered binding fails closed. Receipt age is refused through
/// the owner-issued `expires_at_unix_ms` on the supplied external receipt,
/// compared against the request's observation instant.
pub fn compile_swarm_admission_plan(
    request: &SwarmAdmissionBindRequest,
) -> Result<SwarmAdmissionPlanCandidate, SwarmAdmissionBindError> {
    validate_text(&request.plan_id, "admission.plan_id")?;
    if request.now_unix_ms == 0 {
        return Err(SwarmAdmissionBindError::InvalidField(
            "admission.now_unix_ms",
        ));
    }
    request.staffing.validate()?;
    if !request.staffing.is_complete() {
        return Err(SwarmAdmissionBindError::IncompleteStaffing);
    }
    validate_envelope(&request.admission)?;
    check_admission_window(request.now_unix_ms, request.admission.expires_at_unix_ms)?;
    let slots = admit_all_slots(request)?;
    let mut plan = SwarmAdmissionPlanCandidate {
        schema_version: SWARM_ADMISSION_PLAN_VERSION.to_owned(),
        plan_id: request.plan_id.clone(),
        plan_digest: String::new(),
        staffing_id: request.staffing.staffing_id.clone(),
        staffing_digest: request.staffing.staffing_digest.clone(),
        admission_id: request.admission.admission_id.clone(),
        task_id: request.admission.task_id.clone(),
        task_revision: request.admission.task_revision.clone(),
        plan_revision: request.admission.plan_revision.clone(),
        controller_epoch: request.admission.controller_epoch.clone(),
        coordinator_lease: request.admission.coordinator_lease.clone(),
        slots,
        staffing: request.staffing.clone(),
        admission: request.admission.clone(),
        observed_at_unix_ms: request.now_unix_ms,
        execution: ZeroModelExecutionCounters::zero(),
        candidate_only: true,
        dispatch_authority: false,
    };
    plan.plan_digest = plan.digest()?;
    plan.validate()?;
    Ok(plan)
}

/// Admits the exact one-to-one denominator: the binding count must equal the
/// staffed slot count, every binding names a distinct staffed slot, and every
/// staffed slot resolves to exactly one binding.
fn admit_all_slots(
    request: &SwarmAdmissionBindRequest,
) -> Result<Vec<SwarmBoundSlot>, SwarmAdmissionBindError> {
    if request.bindings.len() != request.staffing.slots.len()
        || request.bindings.len() > MAX_STAFFING_SLOTS
    {
        return Err(SwarmAdmissionBindError::InvalidField(
            "admission.denominator",
        ));
    }
    let mut seen_slot_ids = BTreeSet::new();
    for binding in &request.bindings {
        validate_text(&binding.slot_id, "admission.slot")?;
        validate_text(&binding.selection_id, "admission.selection")?;
        validate_canonical_digest(&binding.selection_digest, "admission.selection")?;
        validate_canonical_digest(&binding.catalogue_digest, "admission.selection")?;
        validate_canonical_digest(&binding.preference_policy_digest, "admission.selection")?;
        if !seen_slot_ids.insert(binding.slot_id.as_str()) {
            return Err(SwarmAdmissionBindError::DuplicateIdentity("admission.slot"));
        }
    }
    let mut slots = Vec::with_capacity(request.bindings.len());
    for staffed in &request.staffing.slots {
        let Some(binding) = request
            .bindings
            .iter()
            .find(|binding| binding.slot_id == staffed.slot_id)
        else {
            return Err(SwarmAdmissionBindError::InvalidField(
                "admission.denominator",
            ));
        };
        slots.push(admit_one_slot(
            binding,
            staffed,
            &request.plan_id,
            &request.admission,
        )?);
    }
    slots.sort_by_key(|slot: &SwarmBoundSlot| slot.role);
    Ok(slots)
}

/// Admits one slot binding and records the compiled bound slot. The bound
/// pins echo the caller-presented binding verbatim. The digest seals the
/// record first, exactly as the staffing owner seals `slot_digest`
/// immediately after construction, and only then does [`check_bound_slot`]
/// run: its final branch compares the stored `slot_binding_digest` against a
/// canonical digest that is never empty, so it can only be a tamper guard
/// once the record is sealed. Validating first would compare the still-empty
/// field against a canonical digest and refuse every honest handoff.
/// [`check_bound_slot`] still runs every other check first and still fails
/// closed, digest closure included.
fn admit_one_slot(
    binding: &SwarmSlotAdmission,
    staffed: &StaffedSlot,
    plan_id: &str,
    admission: &ProviderAdmissionReceipt,
) -> Result<SwarmBoundSlot, SwarmAdmissionBindError> {
    let mut bound = SwarmBoundSlot {
        slot_id: binding.slot_id.clone(),
        role: staffed.role,
        selection_id: binding.selection_id.clone(),
        selection_digest: binding.selection_digest.clone(),
        catalogue_snapshot_id: binding.catalogue_snapshot_id.clone(),
        catalogue_digest: binding.catalogue_digest.clone(),
        preference_policy_id: binding.preference_policy_id.clone(),
        preference_revision: binding.preference_revision.clone(),
        preference_policy_digest: binding.preference_policy_digest.clone(),
        work_unit_id: binding.work_unit_id.clone(),
        attempt_id: binding.attempt_id.clone(),
        lease_id: binding.lease_id.clone(),
        fence: binding.fence.clone(),
        route: staffed.selected.route.clone(),
        admitted_route: binding.admitted_route.clone(),
        runtime_generation: binding.admitted_route.runtime_generation,
        slot_binding_digest: String::new(),
    };
    bound.slot_binding_digest = bound.digest(plan_id)?;
    check_bound_slot(&bound, staffed, plan_id, admission)?;
    Ok(bound)
}
