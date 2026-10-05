//! Solo-agent vertical slice driver (issue #2567).
//!
//! Architecture: I10.15 (existing fabric and admission saga, semantic objects,
//! `SoloVerified` as the first supported recipe) with the I7.6
//! `eliot.coordinate/delegate` operation as the single semantic surface and the
//! I1.8 canonical admission plus external-effect separation underneath. This
//! module is wiring, not a second scheduler, task store, attempt journal,
//! write authority, provider runner, or recovery path: it connects one
//! admitted solo delegate intake to exactly one injected [`AgentFabric`]
//! through the existing owner seams and leaves every owner policy where it
//! lives (Task Controller definitions, capability-based staffing policy,
//! Governor capability evidence, Kernel fence/epoch, coordinator verification).
//!
//! # Selected route (implementation order 1)
//!
//! The frozen slice is `eliot.coordinate { operation: delegate }` under the
//! `SoloVerified` recipe (`solo-verified-v1`): one capable agent, then a
//! deterministic verifier, with optional narrow review. The public MCP schema
//! is `crates/surfaces/eliot-mcp/src/contract.rs::DelegateRequest`
//! (`goal`, `owned_resources`, `expected_result`); the daemon-side intake
//! below mirrors those three fields byte-for-byte instead of depending on the
//! surface crate, so the bridge direction never inverts. The frozen
//! [`StaffingPlanRequest`] is Task Controller-authored and is never invented
//! here: a single lane, `max_fanout == 1`, and the solo recipe identity are
//! enforced before anything is recorded.
//!
//! # Adapter map (implementation order 3-4)
//!
//! | Port | Solo binding | Owner backing |
//! |---|---|---|
//! | `ModelRegistry` | [`SoloModelRegistryPort`] echoes the policy-staffed route | staffing receipt lanes plus the fabric evidence gate; never invents a route |
//! | `AdmissionAuthority` | [`SoloAdmissionAuthorityPort`] honestly reports the missing owner binding | frozen definition digest, staffing receipt, live fence/epoch; coordinates, never owns |
//! | `ActivationAuthority` | [`SoloActivationAuthorityPort`] honestly reports the missing owner binding | committed admission, attempt membership, live fence/epoch |
//! | `DispatchEgress` | [`SoloDispatchEgressPort`] honestly reports the missing owner binding | activated intent, persisted dispatch record, worker-claim single-flight identity |
//! | `PeerChannel` | production missing port, never called on this path | B-PEER #696 has no accepted revision; solo needs none |
//! | `SwarmControl` | production missing port, never called on this path | B-SWARM #698 has no accepted revision; solo needs none |
//!
//! The driver never calls `deliver_peer` or `enter_swarm`, so the solo path
//! cannot depend on fake peer success by construction. Load-bearing order is
//! the fabric's own chain (`define_and_plan` -> `stage_reservation` ->
//! `commit_admission` -> `activate` -> `dispatch` -> persist -> `emit`);
//! every step revalidates the live fence and epoch plus exact digest
//! bindings, so missing, stale, or substituted material refuses before
//! launch. [`DispatchAck`] retention is surfaced as retention only: no
//! completion flag exists anywhere in this module, and worker output stays
//! candidate evidence that can never satisfy task Finish.
//!
//! # Ownership notes
//!
//! Solo coordination records carry deterministic `solo-` identities derived
//! from verified digests. They are daemon coordination records that bind
//! owner-verified material field for field; they do not claim to be
//! Kernel-minted reservation identities or Governor-minted admission
//! identities, and the per-call checks below refuse anything that drifts
//! from the verified material. The Kernel ORS solo-stage arm and the
//! Governor solo-admission seal remain future owner legs: until each lands,
//! the matching solo port reports [`PortBindingState::Missing`] and every
//! staging/commit/activation/emission attempt raises the typed
//! [`FabricOperation`]-keyed missing-prerequisite residual before any
//! dependent effect, exactly like the closed production ports in
//! `bins/eliotd/src/lib.rs`. No local constant, trait presence,
//! self-digest, or serialized `Verified` value establishes `Bound`, and no
//! adapter mints owner evidence locally — a missing leg fails closed
//! instead of fabricating a row or receipt to make the gate tautological.
//!
//! # Pollability and durability
//!
//! The runtime queue poll snapshots its head plus the expected
//! task/route/admission/fence revisions under a short composition lock and
//! releases that guard before any await. The verified drive then borrows the
//! composition across the seam await: `agent_fabric_new_verified_async`
//! resolves the session halves and verifies through the Kernel
//! provider-admission verifier on `&DaemonComposition`, so the borrow cannot
//! drop before the fabric exists without forking the closed admission path
//! (a prepare/adopt split of the seam itself is a lib.rs residual). The
//! poll flight stays single-flighted, so ticks never overlap a drive and
//! other composition users queue on the mutex only for the bounded seam
//! await. Both the drive adopt and the queue adopt revalidate the consumed
//! revisions before adopting; a stale or moved revision refuses typed with
//! the head left queued. Until the owner ports bind (B-MOD #694 for the
//! route, the native-worker executable-binding digest for execution), the
//! drive fails closed with the typed owner residual before admission,
//! activation, or dispatch. The test-only historical dispatch projection is
//! persisted under the daemon state root before `emit`; uncertain ownership
//! is never released without an observed terminal disposition.

use std::collections::VecDeque;
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use eliot_agent_api::{AttemptId, RouteFingerprint};
use eliot_agent_bridge_core::ToolResultReceipt;
#[cfg(not(test))]
use eliot_agent_coordinator::CoordinatorError;
use eliot_agent_coordinator::{
    CandidateId, RUNTIME_PROFILE_FILE_NAME, SchedulingProfile, StaffingPlanRequest,
    load_runtime_scheduling_profile,
};
use eliot_contracts::{fences_match_exact, sha256_hex};
use serde::{Deserialize, Serialize};

use crate::agent_fabric::{
    ActivationAuthorityPort, ActivationEvidence, AdmissionAuthorityPort, AgentFabric, DispatchAck,
    DispatchEgressPort, DispatchIntent, FabricAdmission, FabricError, FabricOperation,
    FabricPortId, FabricSnapshot, PortBindingState, Reservation, RouteRequirements,
    SwarmDefinition, VerifiedProviderMaterial, daemon_coordinator_config,
};
#[cfg(test)]
use crate::agent_fabric::{FabricPorts, ModelRegistryPort};
use crate::daemon_kernel_client::DaemonKernelClient;
use crate::staffing_policy::{
    StaffedLane, StaffingPlanReceipt, plan_coordinator_staffing, verify_receipt_digest,
};
use crate::{DaemonComposition, DaemonError};
use eliot_governor::{CompositionError, CompositionReadiness, RouteScopeFingerprint};

/// Solo recipe identity pinned by this slice (I10.15 first supported recipe).
pub const SOLO_RECIPE_ID: &str = "solo-verified-v1";
/// Accepted-interface revision reported by the solo model registry adapter.
#[cfg(test)]
pub const SOLO_MODEL_REGISTRY_REVISION: &str = "solo-model-registry/v1";
/// Subdirectory of the daemon state root holding solo dispatch projections.
pub const SOLO_PROJECTION_DIR: &str = "solo-agent";
/// Upper bound on one persisted solo projection file, in bytes.
pub const SOLO_PROJECTION_MAX_BYTES: u64 = 1_048_576;
/// Upper bound on queued solo intakes waiting for a free live slot.
pub const SOLO_QUEUE_MAX_LEN: usize = 16;
/// Wire version of the persisted solo projection envelope.
pub const SOLO_PROJECTION_WIRE_VERSION: u32 = 1;

fn require_text(value: &str, field: &'static str) -> Result<(), FabricError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(FabricError::Contract(format!(
            "blank or control-bearing solo {field}"
        )));
    }
    Ok(())
}

fn contract(error: impl std::fmt::Display) -> FabricError {
    FabricError::Contract(error.to_string())
}

/// Exact delegate field mirror of the public MCP contract
/// (`crates/surfaces/eliot-mcp/src/contract.rs::DelegateRequest`).
///
/// `goal`, `owned_resources`, and `expected_result` carry the same validation
/// as the canonical contract (non-blank goal/result, at least one unique
/// non-blank owned resource). `source_bytes` preserves the ORIGINAL canonical
/// delegate JSON; `source_digest` binds it (content compare on readback).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoloDelegateBody {
    /// Bounded goal, mirrored from the canonical contract.
    pub goal: String,
    /// Owned artifact/resource scope, mirrored from the canonical contract.
    pub owned_resources: Vec<String>,
    /// Expected result contract; becomes the worker result schema name.
    pub expected_result: String,
    /// ORIGINAL canonical delegate bytes; digests validate against these.
    pub source_bytes: Vec<u8>,
    /// Lowercase SHA-256 over `source_bytes`.
    pub source_digest: String,
}

impl SoloDelegateBody {
    fn validate(&self) -> Result<(), FabricError> {
        require_text(&self.goal, "delegate goal")?;
        require_text(&self.expected_result, "delegate expected result")?;
        if self.owned_resources.is_empty() {
            return Err(FabricError::Contract(
                "solo delegate owned resources must not be empty".to_owned(),
            ));
        }
        for resource in &self.owned_resources {
            require_text(resource, "delegate owned resource")?;
        }
        let recomputed = sha256_hex(&self.source_bytes);
        if recomputed != self.source_digest {
            return Err(FabricError::IdentityConflict(
                "solo delegate digest does not match the original bytes".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Claimed provider halves of one solo delegate intake.
///
/// Everything here is operation-presented. In particular, `expectation` is
/// deserialized caller input: its route and capacity revisions are not a live
/// Governor read. The async Kernel probe may validate the remaining claim
/// tuple, but its echo of those revisions is not admission evidence and this
/// path fails closed before capability construction.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoloClaimedHalves {
    /// Provider identity the binding must match exactly.
    pub identity: eliot_agent_coordinator::ProviderIdentity,
    /// Durable claim identity as claimed by the operation at hand.
    pub claim_id: String,
    /// Attempt identity as claimed by the operation at hand.
    pub attempt_id: String,
    /// Exact external-effect operation identity as claimed.
    pub operation_id: String,
    /// Presented claim binding digest (lowercase SHA-256).
    pub binding_digest: String,
    /// Presented executable binding digest (lowercase SHA-256).
    pub executable_digest: String,
    /// Presented route revision from the operation at hand.
    pub route_revision: String,
    /// Presented capacity revision from the operation at hand.
    pub capacity_revision: String,
    /// Claimed worker generation from the operation presentation (nonzero).
    pub worker_generation: u64,
    /// Operation fence from the operation at hand.
    pub presented_fence: eliot_contracts::StateFence,
    /// Caller-presented revisions labeled as Governor currentness. This is
    /// untrusted input and is never treated as a live Governor observation.
    pub expectation: eliot_kernel_service::ProviderCapabilityExpectation,
    /// Minimum replayed event sequence for restore (zero means no floor).
    pub minimum_event_sequence: u64,
}

impl SoloClaimedHalves {
    fn validate(&self) -> Result<(), FabricError> {
        require_text(&self.claim_id, "claim identity")?;
        require_text(&self.attempt_id, "attempt identity")?;
        require_text(&self.operation_id, "operation identity")?;
        require_text(&self.binding_digest, "binding digest")?;
        require_text(&self.executable_digest, "executable digest")?;
        require_text(&self.route_revision, "route revision")?;
        require_text(&self.capacity_revision, "capacity revision")?;
        if self.worker_generation == 0 {
            return Err(FabricError::Contract(
                "solo claimed worker generation must be nonzero".to_owned(),
            ));
        }
        self.expectation
            .validate()
            .map_err(|error| contract(format!("solo expectation shape: {error}")))?;
        Ok(())
    }

    fn material(&self) -> VerifiedProviderMaterial {
        VerifiedProviderMaterial {
            identity: self.identity.clone(),
            claim_id: self.claim_id.clone(),
            attempt_id: self.attempt_id.clone(),
            operation_id: self.operation_id.clone(),
            binding_digest: self.binding_digest.clone(),
            executable_digest: self.executable_digest.clone(),
            route_revision: self.route_revision.clone(),
            capacity_revision: self.capacity_revision.clone(),
            worker_generation: self.worker_generation,
            presented_fence: self.presented_fence.clone(),
            expectation: self.expectation.clone(),
            // Overwritten unconditionally by the session-bound resolution
            // inside `agent_fabric_verified_capability` before any verifier
            // observes it; never read beforehand.
            live_fence: self.presented_fence.clone(),
            health: None,
            minimum_event_sequence: self.minimum_event_sequence,
        }
    }
}

/// One admitted solo delegate intake: the full drive input.
///
/// The frozen [`StaffingPlanRequest`] is Task Controller-authored; the
/// delegate body is requester-authored; the claimed halves are
/// operation-presented. Nothing here is invented by the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoloDelegateIntake {
    /// Exact delegate body with its original bytes bound.
    pub delegate: SoloDelegateBody,
    /// Frozen Task Controller-authored staffing plan request.
    pub plan: StaffingPlanRequest,
    /// Operation-presented provider halves.
    pub claimed: SoloClaimedHalves,
    /// Route requirements for the admitted-route gate.
    pub requirements: RouteRequirements,
    /// Caller-observed route scope threaded into the evidence gate.
    pub observed_scope: RouteScopeFingerprint,
    /// Claim deadline in Unix milliseconds; must be in the future at drive.
    pub deadline_unix_ms: u64,
}

impl SoloDelegateIntake {
    fn validate(&self, now_unix_ms: u64) -> Result<(), FabricError> {
        self.delegate.validate()?;
        self.claimed.validate()?;
        require_text(&self.requirements.role, "route role")?;
        if self.requirements.competence.is_empty() {
            return Err(FabricError::Contract(
                "solo route competence must not be empty".to_owned(),
            ));
        }
        for item in &self.requirements.competence {
            require_text(item, "route competence")?;
        }
        if self.deadline_unix_ms == 0 || self.deadline_unix_ms <= now_unix_ms {
            return Err(FabricError::Contract(
                "solo delegate deadline is not in the future".to_owned(),
            ));
        }
        Ok(())
    }
}

/// Verified solo context threaded into every adapter.
///
/// Every field traces to an owner: the frozen definition digest and work
/// class from the Task Controller-authored plan, the route from the staffing
/// receipt, the fence/epoch from the live Kernel snapshot, the
/// claim/attempt/operation identities and digests from the verified provider
/// material. Adapters revalidate these against each call and refuse drift.
#[derive(Clone, Debug)]
struct SoloVerifiedContext {
    definition_id: CandidateId,
    definition_digest: String,
    work_class: eliot_agent_coordinator::WorkClass,
    fence: eliot_contracts::StateFence,
    epoch: eliot_contracts::EpochId,
    attempt_id: AttemptId,
}

/// Owner-verified route preloaded into the solo registry adapter.
#[derive(Clone, Debug)]
#[cfg(test)]
struct PreloadedRoute {
    role: String,
    competence: Vec<String>,
    route: RouteFingerprint,
}

/// Solo B-MOD model registry adapter.
///
/// Echoes the policy-staffed route preloaded by the driver on an exact
/// role/competence match and `None` otherwise. It ranks nothing, admits
/// nothing, and invents no route: the fabric evidence gate plus the staffing
/// receipt decide, and anything unstaged there refuses downstream.
#[derive(Clone, Debug)]
#[cfg(test)]
pub struct SoloModelRegistryPort {
    preloaded: Arc<Mutex<Option<PreloadedRoute>>>,
}

#[cfg(test)]
impl SoloModelRegistryPort {
    fn new() -> Self {
        Self {
            preloaded: Arc::new(Mutex::new(None)),
        }
    }

    fn preload(&self, route: PreloadedRoute) -> Result<(), FabricError> {
        let mut guard = self
            .preloaded
            .lock()
            .map_err(|_| FabricError::Contract("solo registry preload lock poisoned".to_owned()))?;
        *guard = Some(route);
        Ok(())
    }
}

#[cfg(test)]
impl ModelRegistryPort for SoloModelRegistryPort {
    fn resolve_route(
        &self,
        requirements: &RouteRequirements,
    ) -> Result<Option<RouteFingerprint>, FabricError> {
        let guard = self
            .preloaded
            .lock()
            .map_err(|_| FabricError::Contract("solo registry preload lock poisoned".to_owned()))?;
        let Some(preloaded) = guard.as_ref() else {
            return Ok(None);
        };
        if preloaded.role == requirements.role && preloaded.competence == requirements.competence {
            return Ok(Some(preloaded.route.clone()));
        }
        Ok(None)
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::bound(SOLO_MODEL_REGISTRY_REVISION.to_owned())
            .unwrap_or(PortBindingState::Uncertain)
    }
}

/// Solo Governor admission authority adapter.
///
/// Honest closed port: the Kernel ORS solo-stage arm and the Governor
/// solo-admission seal do not exist yet, so no accepted interface revision
/// is reported and no reservation or admission is minted here. Every call
/// first revalidates the live fence/epoch against the verified context
/// (a real Kernel owner read with typed stale failures), then raises the
/// typed missing-prerequisite residual before staging any dependent effect.
/// Reservation and admission stay with their owners (I10.15 one-owner
/// rule); owner delegation lands with the Governor swarm-admission owner.
#[derive(Clone)]
pub struct SoloAdmissionAuthorityPort {
    context: Arc<SoloVerifiedContext>,
    kernel: Arc<DaemonKernelClient>,
}

impl SoloAdmissionAuthorityPort {
    fn live_fence(&self) -> eliot_contracts::StateFence {
        self.kernel.kernel_fence()
    }

    fn check_live(&self) -> Result<(), FabricError> {
        let live = self.live_fence();
        if !fences_match_exact(&live, &self.context.fence) {
            return Err(FabricError::StaleFence(
                "solo live fence moved under the verified context".to_owned(),
            ));
        }
        if !live.authority_epoch.is_same_authority(&self.context.epoch) {
            return Err(FabricError::StaleEpoch(
                "solo live epoch moved under the verified context".to_owned(),
            ));
        }
        Ok(())
    }
}

impl AdmissionAuthorityPort for SoloAdmissionAuthorityPort {
    fn stage_reservation(&self, definition: &SwarmDefinition) -> Result<Reservation, FabricError> {
        self.check_live()?;
        if definition.definition_id != self.context.definition_id
            || definition.definition_digest != self.context.definition_digest
            || definition.work_class != self.context.work_class
        {
            return Err(FabricError::ReceiptBinding(
                "solo reservation refuses a substituted definition".to_owned(),
            ));
        }
        if !fences_match_exact(&definition.fence, &self.context.fence) {
            return Err(FabricError::StaleFence(
                "solo reservation refuses a fence-moved definition".to_owned(),
            ));
        }
        // #1700 AUD1/AUD2: the Kernel ORS solo-stage arm does not exist, so
        // no reservation is staged or stored here. The validated definition
        // is retained by the caller for reevaluation after owner acceptance.
        Err(crate::blocked_port(
            FabricPortId::AdmissionAuthority,
            FabricOperation::StageReservation,
            definition.definition_id.as_str().to_owned(),
            Some(definition.fence.clone()),
            None,
        ))
    }

    fn commit_admission(&self, reservation: &Reservation) -> Result<FabricAdmission, FabricError> {
        self.check_live()?;
        // #1700 AUD1/AUD2: the Governor solo-admission seal does not exist,
        // so no admission is committed here. The retained reservation is
        // named in the residual for reevaluation after owner acceptance.
        Err(crate::blocked_port(
            FabricPortId::AdmissionAuthority,
            FabricOperation::CommitAdmission,
            reservation.reservation_id.clone(),
            Some(reservation.fence.clone()),
            None,
        ))
    }

    fn interface_binding(&self) -> PortBindingState {
        // #1700 AUD1: no owner receipt, registration revision, generation,
        // fence, revocation cursor, or acceptance evidence exists for the
        // missing solo legs, so no accepted revision is reported. A local
        // constant or trait presence must never establish `Bound`.
        PortBindingState::Missing
    }
}

/// Solo Kernel activation authority adapter.
///
/// Honest closed port: the Kernel solo activation receipt does not exist
/// yet, so no accepted interface revision is reported and no activation
/// evidence is minted here. The presented admission and attempt are still
/// validated against the verified context and the live fence/epoch (real
/// owner reads with typed failures), then the call raises the typed
/// missing-prerequisite residual. Activation stays with the Kernel owner
/// (I10.15 one-owner rule); owner delegation lands with
/// B-ACTIVATION-PROJECTION #839.
#[derive(Clone)]
pub struct SoloActivationAuthorityPort {
    context: Arc<SoloVerifiedContext>,
    kernel: Arc<DaemonKernelClient>,
}

impl ActivationAuthorityPort for SoloActivationAuthorityPort {
    fn activate(
        &self,
        admission: &FabricAdmission,
        attempt_id: &AttemptId,
    ) -> Result<ActivationEvidence, FabricError> {
        let live = self.kernel.kernel_fence();
        if !fences_match_exact(&live, &self.context.fence)
            || !fences_match_exact(&admission.fence, &self.context.fence)
        {
            return Err(FabricError::StaleFence(
                "solo activation refuses a fence-moved admission".to_owned(),
            ));
        }
        if !live.authority_epoch.is_same_authority(&self.context.epoch)
            || !admission.epoch.is_same_authority(&self.context.epoch)
        {
            return Err(FabricError::StaleEpoch(
                "solo activation refuses an epoch-moved admission".to_owned(),
            ));
        }
        if admission.definition_id != self.context.definition_id
            || admission.definition_digest != self.context.definition_digest
            || admission.work_class != self.context.work_class
        {
            return Err(FabricError::ReceiptBinding(
                "solo activation refuses a substituted admission".to_owned(),
            ));
        }
        if *attempt_id != self.context.attempt_id || !admission.attempt_ids.contains(attempt_id) {
            return Err(FabricError::IdentityConflict(
                "solo activation refuses a foreign attempt".to_owned(),
            ));
        }
        // #1700 AUD1/AUD2: no Kernel activation receipt exists to mint
        // evidence from; deterministic local computation is not owner
        // authority. The validated admission/attempt is retained by the
        // caller for reevaluation after owner acceptance.
        Err(crate::blocked_port(
            FabricPortId::ActivationAuthority,
            FabricOperation::Activate,
            attempt_id.as_str().to_owned(),
            Some(admission.fence.clone()),
            Some(admission.epoch.clone()),
        ))
    }

    fn interface_binding(&self) -> PortBindingState {
        // #1700 AUD1: the solo activation owner leg is absent; no accepted
        // revision is reported and no local value establishes `Bound`.
        PortBindingState::Missing
    }
}

/// Claim-compatible dispatch binding retained at the worker handoff.
///
/// Every daemon-known field traces to verified owner material: identities
/// and digests from the verified provider halves, route class from the
/// staffing receipt lane, budget and cancellation policy from the Task
/// Controller-authored launch request, schema name from the delegate body.
/// Fields the daemon cannot know (worker registration, the M1 executable
/// join, Task Controller decision/parent-job and scope handles) are named in
/// [`SoloDispatchRecord::worker_completed_fields`] and are completed by the
/// admitted worker claim path (#874); they are never defaulted here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoloDispatchRecord {
    /// Stable dispatch identity (`solo-dispatch-<attempt>-<admission>`).
    pub dispatch_id: String,
    /// Durable claim identity bound to this dispatch.
    pub claim_id: String,
    /// Registered attempt identity.
    pub attempt_id: String,
    /// Exact external-effect operation identity.
    pub operation_id: String,
    /// Governed task identity.
    pub task_id: String,
    /// Admitted route fingerprint.
    pub route: RouteFingerprint,
    /// Admitted route class from the staffing receipt lane.
    pub route_class: String,
    /// Claimed worker generation (nonzero, verified against the live fence).
    pub worker_generation: u64,
    /// Presented claim binding digest from the verified halves.
    pub binding_digest: String,
    /// Presented executable binding digest from the verified halves.
    pub executable_digest: String,
    /// Expected result schema name from the delegate body.
    pub expected_result_schema: String,
    /// Claim deadline in Unix milliseconds.
    pub deadline_unix_ms: u64,
    /// Deterministic cancellation identity (`<operation>-cancel`).
    pub cancellation_id: String,
    /// Fence bound at dispatch time.
    pub fence: eliot_contracts::StateFence,
    /// Epoch bound at dispatch time.
    pub epoch: eliot_contracts::EpochId,
    /// Claim fields completed downstream by the admitted worker path.
    pub worker_completed_fields: Vec<String>,
}

/// Solo dispatch egress adapter.
///
/// Honest closed port: the real dispatch-egress retention receipt does not
/// exist yet, so no accepted interface revision is reported and no
/// acknowledgement is retained here. The presented intent is still validated
/// against the verified context, the live fence/epoch, and the deterministic
/// dispatch identity (real checks with typed failures), then the call raises
/// the typed missing-prerequisite residual. Retention stays with the egress
/// owner; owner delegation lands with the executor-daemon bind (#874).
#[derive(Clone)]
pub struct SoloDispatchEgressPort {
    context: Arc<SoloVerifiedContext>,
    kernel: Arc<DaemonKernelClient>,
}

impl DispatchEgressPort for SoloDispatchEgressPort {
    fn emit(&self, intent: &DispatchIntent) -> Result<DispatchAck, FabricError> {
        let live = self.kernel.kernel_fence();
        if !fences_match_exact(&live, &self.context.fence)
            || !fences_match_exact(&intent.fence, &self.context.fence)
        {
            return Err(FabricError::StaleFence(
                "solo egress refuses a fence-moved intent".to_owned(),
            ));
        }
        if !live.authority_epoch.is_same_authority(&self.context.epoch)
            || !intent.epoch.is_same_authority(&self.context.epoch)
        {
            return Err(FabricError::StaleEpoch(
                "solo egress refuses an epoch-moved intent".to_owned(),
            ));
        }
        if intent.attempt_id != self.context.attempt_id
            || intent.admission_id.as_str().is_empty()
            || intent.work_class != self.context.work_class
        {
            return Err(FabricError::ReceiptBinding(
                "solo egress refuses a substituted intent".to_owned(),
            ));
        }
        let expected_dispatch = solo_dispatch_identity(
            self.context.attempt_id.as_str(),
            intent.admission_id.as_str(),
        );
        if intent.dispatch_id != expected_dispatch {
            return Err(FabricError::IdentityConflict(
                "solo egress refuses a foreign dispatch identity".to_owned(),
            ));
        }
        // #1700 AUD1/AUD2: no egress retention receipt exists to store or
        // return here; an in-memory ack is not retention. The validated
        // intent is retained by the caller for reevaluation after owner
        // acceptance.
        Err(crate::blocked_port(
            FabricPortId::DispatchEgress,
            FabricOperation::Emit,
            intent.dispatch_id.clone(),
            Some(intent.fence.clone()),
            Some(intent.epoch.clone()),
        ))
    }

    fn interface_binding(&self) -> PortBindingState {
        // #1700 AUD1: the solo egress owner leg is absent; no accepted
        // revision is reported and no local value establishes `Bound`.
        PortBindingState::Missing
    }
}

/// Derives the deterministic solo dispatch identity.
fn solo_dispatch_identity(attempt_id: &str, admission_id: &str) -> String {
    format!("solo-dispatch-{attempt_id}-{admission_id}")
}

/// Derives the deterministic solo cancellation identity.
///
/// Non-test: the verified async drive binds the same `<operation>-cancel`
/// identity as the test-only sync drive, so both paths address one
/// cancellation per operation.
fn solo_cancellation_identity(operation_id: &str) -> String {
    format!("{operation_id}-cancel")
}

/// Durable solo attempt projection: the exact restart readback.
///
/// The live fabric is never the durable truth: this projection (carrier
/// summary, fabric snapshot, dispatch record, observed outcome) is persisted
/// before `emit` and reloaded on restart, after which
/// `agent_fabric_restore_verified` re-resolves live evidence and unknown
/// outcomes reconcile instead of relaunching.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SoloPersistedAttempt {
    /// Operation identity keying every readback to the same attempt.
    pub operation_id: String,
    /// Attempt identity bound to the operation.
    pub attempt_id: String,
    /// Digest of the original delegate bytes.
    pub delegate_digest: String,
    /// Digest of the frozen plan bytes at drive time.
    pub plan_digest: String,
    /// Route requirements the admitted route was gated on.
    pub requirements: RouteRequirements,
    /// Caller-observed route scope threaded into the evidence gate.
    pub observed_scope: RouteScopeFingerprint,
    /// Claimed provider halves for restore-time material rebuild.
    pub claimed: SoloClaimedHalves,
    /// Staffing receipt lanes bound at drive time (route source of truth).
    pub receipt: StaffingPlanReceipt,
    /// Fabric snapshot persisted before emit.
    pub snapshot: FabricSnapshot,
    /// Dispatch record persisted before emit, if the drive reached dispatch.
    pub dispatch: Option<SoloDispatchRecord>,
    /// Whether the egress acknowledgement was observed.
    pub emitted: bool,
    /// Candidate result digest ingested through the fabric, if any.
    pub result_digest: Option<String>,
    /// Terminal cancellation evidence ref, if reconciled.
    pub cancellation_evidence: Option<String>,
}

/// Envelope binding the persisted projection to its own digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SoloProjectionFile {
    wire_version: u32,
    payload: SoloPersistedAttempt,
    sha256: String,
}

/// Outcome of one completed solo drive: retention evidence, never completion.
///
/// Carries the correlated dispatch/attempt identities plus the retained
/// acknowledgement. No field here claims task success, provider completion,
/// or Finish: worker output stays candidate evidence.
#[derive(Clone, Debug)]
pub struct SoloDriveOutcome {
    /// Exact external-effect operation identity driven.
    pub operation_id: String,
    /// Registered attempt identity.
    pub attempt_id: String,
    /// Stable dispatch identity retained at the handoff.
    pub dispatch_id: String,
    /// Solo coordination admission identity.
    pub admission_id: String,
    /// Admitted route fingerprint.
    pub route: RouteFingerprint,
    /// Egress retention acknowledgement (retention only).
    pub retained: bool,
    /// Claim-compatible dispatch binding for the worker handoff.
    pub dispatch: SoloDispatchRecord,
}

/// Attempt status read back under the same durable identity.
#[derive(Clone, Debug)]
pub struct SoloAttemptStatus {
    /// Exact external-effect operation identity.
    pub operation_id: String,
    /// Registered attempt identity.
    pub attempt_id: String,
    /// Fabric attempt lifecycle (retention/observation states only).
    pub lifecycle: crate::agent_fabric::AttemptLifecycle,
    /// Cancellation lifecycle, if a cancellation was requested.
    pub cancellation: Option<crate::agent_fabric::CancellationLifecycle>,
    /// Candidate result digest ingested through the fabric, if any.
    pub result_digest: Option<String>,
    /// Whether the egress acknowledgement was observed.
    pub emitted: bool,
}

/// Tick outcome for the runtime solo poll hook.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SoloPollOutcome {
    /// No queued intake was ready to drive.
    Idle,
    /// The live slot holds a non-settled attempt; the queue waits.
    SlotBusy,
    /// One queued intake drove to a retained dispatch.
    Drove {
        /// Operation identity driven.
        operation_id: String,
        /// Dispatch identity retained.
        dispatch_id: String,
    },
}

/// Retained solo driver state held by the daemon composition.
///
/// The live slot holds at most one unsettled attempt projection: a second
/// drive while the slot is live refuses instead of overlapping it, and a
/// restart restores from the persisted projection, never from memory alone.
#[derive(Debug, Default)]
pub struct SoloDriverState {
    queue: VecDeque<SoloDelegateIntake>,
    live_operation: Option<String>,
}

impl SoloDriverState {
    /// Creates empty solo driver state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

/// Builds the six solo fabric ports: four bound solo adapters plus the
/// honestly missing peer/swarm production ports.
///
/// `PeerChannel` and `SwarmControl` reuse the closed production ports (no
/// accepted B-PEER/B-SWARM revision on this base); the solo driver never
/// calls them, so solo work neither depends on nor fabricates peer success.
/// The solo admission, activation, and egress adapters are likewise closed:
/// with no Kernel ORS solo-stage arm, no Governor solo-admission seal, and
/// no egress retention receipt, they report `Missing` and refuse with the
/// typed residual instead of minting local authority.
#[cfg(test)]
fn solo_fabric_ports(
    context: SoloVerifiedContext,
    kernel: &Arc<DaemonKernelClient>,
    registry: SoloModelRegistryPort,
) -> FabricPorts {
    let context = Arc::new(context);
    FabricPorts {
        model_registry: Arc::new(registry),
        peer_channel: Arc::new(crate::ProductionPeerChannelPort),
        swarm_control: Arc::new(crate::ProductionSwarmControlPort),
        admission_authority: Arc::new(SoloAdmissionAuthorityPort {
            context: Arc::clone(&context),
            kernel: Arc::clone(kernel),
        }),
        activation_authority: Arc::new(SoloActivationAuthorityPort {
            context: Arc::clone(&context),
            kernel: Arc::clone(kernel),
        }),
        dispatch_egress: Arc::new(SoloDispatchEgressPort {
            context: Arc::clone(&context),
            kernel: Arc::clone(kernel),
        }),
    }
}

fn solo_projection_path(state_root: &std::path::Path, operation_id: &str) -> std::path::PathBuf {
    state_root
        .join(SOLO_PROJECTION_DIR)
        .join(format!("attempt-{operation_id}.json"))
}

fn persist_projection(
    state_root: &std::path::Path,
    projection: &SoloPersistedAttempt,
) -> Result<(), DaemonError> {
    let payload_bytes = serde_json::to_vec(projection).map_err(|error| {
        DaemonError::Composition(CompositionError::Recovery(format!(
            "solo projection encode: {error}"
        )))
    })?;
    let file = SoloProjectionFile {
        wire_version: SOLO_PROJECTION_WIRE_VERSION,
        payload: projection.clone(),
        sha256: sha256_hex(&payload_bytes),
    };
    let bytes = serde_json::to_vec(&file).map_err(|error| {
        DaemonError::Composition(CompositionError::Recovery(format!(
            "solo projection envelope encode: {error}"
        )))
    })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > SOLO_PROJECTION_MAX_BYTES {
        return Err(DaemonError::Composition(CompositionError::Recovery(
            "solo projection exceeds the bounded file size".to_owned(),
        )));
    }
    let dir = state_root.join(SOLO_PROJECTION_DIR);
    std::fs::create_dir_all(&dir).map_err(|error| {
        DaemonError::Composition(CompositionError::Recovery(format!(
            "solo projection directory: {error}"
        )))
    })?;
    let path = solo_projection_path(state_root, &projection.operation_id);
    let _lease = eliot_platform_windows::ProtectedRuntimePathLease::open_or_create_absolute(&path)
        .map_err(DaemonError::Protected)?;
    std::fs::write(&path, &bytes).map_err(|error| {
        DaemonError::Composition(CompositionError::Recovery(format!(
            "solo projection write: {error}"
        )))
    })?;
    // Content compare on readback: the write is verified before the drive
    // proceeds, so a torn write fails closed here instead of persisting.
    let back = std::fs::read(&path).map_err(|error| {
        DaemonError::Composition(CompositionError::Recovery(format!(
            "solo projection readback: {error}"
        )))
    })?;
    if back != bytes {
        return Err(DaemonError::Composition(CompositionError::Recovery(
            "solo projection readback mismatch after write".to_owned(),
        )));
    }
    Ok(())
}

/// Reads the durable projection file bytes for one operation.
///
/// This is the durable byte source. The bytes come from the FILE through its
/// [`ProtectedRuntimePathLease`](eliot_platform_windows::ProtectedRuntimePathLease)
/// under the recorded path identity and the `SOLO_PROJECTION_MAX_BYTES` bound.
/// No already-typed in-memory projection can stand in for it.
fn read_projection_bytes(
    state_root: &std::path::Path,
    operation_id: &str,
) -> Result<Vec<u8>, DaemonError> {
    require_text(operation_id, "operation identity").map_err(DaemonError::ProviderAdmission)?;
    let path = solo_projection_path(state_root, operation_id);
    let lease = eliot_platform_windows::ProtectedRuntimePathLease::open_or_create_absolute(&path)
        .map_err(DaemonError::Protected)?;
    if lease.path() != path {
        return Err(DaemonError::Composition(CompositionError::Recovery(
            "solo projection path identity changed".to_owned(),
        )));
    }
    lease
        .read_bounded(SOLO_PROJECTION_MAX_BYTES)
        .map_err(DaemonError::Protected)
}

/// Verifies one durable projection envelope over its own bytes (issue #370
/// W24/W25/W26/A2/A28).
///
/// The recorded envelope is validated, not recomputed: the wire version must
/// be current, `sha256_hex(&payload_bytes)` must equal the RECORDED
/// `file.sha256`, and the payload must address this exact operation. This runs
/// to completion BEFORE any caller selects the coordinator document out of
/// these bytes, so a document is never read out of an unverified envelope.
fn verify_projection(bytes: &[u8], operation_id: &str) -> Result<SoloProjectionFile, DaemonError> {
    let file: SoloProjectionFile = serde_json::from_slice(bytes).map_err(|error| {
        DaemonError::Composition(CompositionError::Recovery(format!(
            "solo projection decode: {error}"
        )))
    })?;
    if file.wire_version != SOLO_PROJECTION_WIRE_VERSION {
        return Err(DaemonError::Composition(CompositionError::Recovery(
            "solo projection wire version mismatch".to_owned(),
        )));
    }
    let payload_bytes = serde_json::to_vec(&file.payload).map_err(|error| {
        DaemonError::Composition(CompositionError::Recovery(format!(
            "solo projection payload encode: {error}"
        )))
    })?;
    if sha256_hex(&payload_bytes) != file.sha256 {
        return Err(DaemonError::Composition(CompositionError::Recovery(
            "solo projection digest does not match its payload".to_owned(),
        )));
    }
    if file.payload.operation_id != operation_id {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "solo projection addresses a foreign operation".to_owned(),
            ),
        ));
    }
    Ok(file)
}

fn load_projection(
    state_root: &std::path::Path,
    operation_id: &str,
) -> Result<SoloPersistedAttempt, DaemonError> {
    let bytes = read_projection_bytes(state_root, operation_id)?;
    Ok(verify_projection(&bytes, operation_id)?.payload)
}

/// Verified durable readback: the typed state carrier plus the coordinator
/// document selected out of the SAME verified file bytes.
///
/// `payload` is a state carrier only — it is compared against the live
/// coordinator config and carries the fabric, semantic and admission state.
/// The coordinator itself is restored from `coordinator_document`, which is the
/// JSON selected by pointer out of the durable bytes. The typed value is never
/// the byte source, and the selected document must be the same coordinator
/// state the accepted envelope carries, so the carrier can never contradict
/// the bytes it was decoded from.
#[cfg(not(test))]
struct VerifiedSoloProjection {
    /// Typed carrier for config comparison and fabric/semantic state.
    payload: SoloPersistedAttempt,
    /// Coordinator snapshot JSON selected out of the durable file bytes.
    coordinator_document: String,
}

/// Durable ingress readback for the production restore seam (issue #370
/// W24/W25/W26/A2/A28).
///
/// Order is the security property: the file bytes are read under the lease
/// and bound, the envelope is verified over those bytes, and only then is the
/// coordinator document selected out of them by JSON pointer.
#[cfg(not(test))]
fn load_verified_projection(
    state_root: &std::path::Path,
    operation_id: &str,
) -> Result<VerifiedSoloProjection, DaemonError> {
    let bytes = read_projection_bytes(state_root, operation_id)?;
    let file = verify_projection(&bytes, operation_id)?;
    let document: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        DaemonError::Composition(CompositionError::Recovery(format!(
            "solo coordinator document decode: {error}"
        )))
    })?;
    let coordinator_document = document
        .pointer("/payload/snapshot/coordinator_snapshot")
        .ok_or_else(|| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo projection carries no coordinator document".to_owned(),
            ))
        })?;
    let carrier =
        serde_json::to_value(&file.payload.snapshot.coordinator_snapshot).map_err(|error| {
            DaemonError::Composition(CompositionError::Recovery(format!(
                "solo coordinator carrier encode: {error}"
            )))
        })?;
    if *coordinator_document != carrier {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "durable coordinator document does not match the verified projection carrier"
                    .to_owned(),
            ),
        ));
    }
    Ok(VerifiedSoloProjection {
        payload: file.payload,
        coordinator_document: coordinator_document.to_string(),
    })
}

/// Guards the solo slice shape: one lane, no fanout, the solo recipe.
///
/// Anything requiring peer or swarm behavior refuses here, before any port
/// is touched; the driver additionally never calls those ports.
fn guard_solo_plan(plan: &StaffingPlanRequest) -> Result<(), FabricError> {
    plan.launch
        .validate()
        .map_err(|error| contract(format!("solo frozen launch: {error}")))?;
    if plan.recipe.recipe_id.as_str() != SOLO_RECIPE_ID {
        return Err(FabricError::Contract(format!(
            "solo slice refuses recipe {}; only {SOLO_RECIPE_ID} is supported",
            plan.recipe.recipe_id.as_str()
        )));
    }
    if plan.lanes.len() != 1 {
        return Err(FabricError::Contract(format!(
            "solo slice admits one lane; plan carries {}",
            plan.lanes.len()
        )));
    }
    if plan.launch.max_fanout != 1 {
        return Err(FabricError::Contract(
            "solo slice refuses fanout above one; wider work needs the swarm path".to_owned(),
        ));
    }
    Ok(())
}

/// Drives one admitted solo delegate intake to a retained dispatch.
///
/// Test-only record of the previous synchronous fabric flow. Production is
/// blocked from this path until the authenticated Kernel and executable-owner
/// receipt legs are available.
#[cfg(test)]
#[allow(clippy::too_many_lines)]
#[allow(clippy::needless_pass_by_value)]
pub fn drive_solo_delegate(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    intake: SoloDelegateIntake,
    now_unix_ms: u64,
) -> Result<SoloDriveOutcome, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    intake
        .validate(now_unix_ms)
        .map_err(DaemonError::ProviderAdmission)?;
    guard_solo_plan(&intake.plan).map_err(DaemonError::ProviderAdmission)?;
    let material = intake.claimed.material();
    let operation_id = material.operation_id.clone();
    let attempt_id = AttemptId::new(material.attempt_id.clone())
        .map_err(|error| DaemonError::ProviderAdmission(contract(error)))?;
    // Single live slot: a second drive while the slot holds an unsettled
    // attempt refuses instead of overlapping ownership. A settled slot
    // clears so the next admitted operation may proceed.
    {
        let mut state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        if let Some(live) = state.live_operation.clone()
            && live != operation_id
        {
            let settled = load_projection(composition.state_root(), &live)
                .is_ok_and(|projection| projection_settled(&projection));
            if !settled {
                return Err(DaemonError::ProviderAdmission(FabricError::Contract(
                    format!("solo slice holds live attempt {live}; settle or cancel it first"),
                )));
            }
            state.live_operation = None;
        }
    }
    let capability = composition.agent_fabric_verified_capability(kernel, material)?;
    let config = daemon_coordinator_config()?;
    let receipt = plan_coordinator_staffing(&config, &intake.plan).map_err(|error| {
        DaemonError::ProviderAdmission(FabricError::Contract(error.to_string()))
    })?;
    verify_receipt_digest(&receipt).map_err(|error| {
        DaemonError::ProviderAdmission(FabricError::Contract(error.to_string()))
    })?;
    let staffed = receipt.lanes.first().ok_or_else(|| {
        DaemonError::ProviderAdmission(FabricError::NoRoute(
            "solo staffing receipt staffed no lane".to_owned(),
        ))
    })?;
    let registry = SoloModelRegistryPort::new();
    registry
        .preload(PreloadedRoute {
            role: intake.requirements.role.clone(),
            competence: intake.requirements.competence.clone(),
            route: staffed.route.clone(),
        })
        .map_err(DaemonError::ProviderAdmission)?;
    let live_fence = kernel.kernel_fence();
    // The frozen definition digest is computed over the exact request bytes
    // through the same canonical digest the fabric records, so the adapters
    // bind the frozen bytes from the first call instead of an empty digest.
    let definition_digest = crate::agent_fabric::frozen_definition_digest(&intake.plan)
        .map_err(DaemonError::ProviderAdmission)?;
    let context = SoloVerifiedContext {
        definition_id: intake.plan.candidate_id.clone(),
        definition_digest,
        work_class: intake.plan.work_class,
        fence: live_fence.clone(),
        epoch: live_fence.authority_epoch.clone(),
        attempt_id: attempt_id.clone(),
    };
    let ports = solo_fabric_ports(context, kernel, registry);
    let mut fabric = AgentFabric::new_with_admitted_provider(config, ports, capability)
        .map_err(DaemonError::ProviderAdmission)?;
    // Issue #1702 W2: the drive runs against the daemon state root, so every
    // owner-separated revision published on this fabric is committed and
    // verified durably before anything reports it current. Attaching the store
    // before the first semantic write is what makes the ordering property
    // reachable from the production path instead of a separate test seam.
    fabric.attach_semantic_revision_store(composition.state_root());
    let evidence = composition.capability_admission()?;
    let route = fabric.require_model_route(
        &intake.requirements,
        evidence,
        &intake.observed_scope,
        now_unix_ms,
    )?;
    let (definition, _) = fabric.define_and_plan(intake.plan.clone())?;
    let reservation = fabric.stage_reservation(&definition.definition_id)?;
    let admission = fabric.commit_admission(&reservation.reservation_id)?;
    let _evidence = fabric.activate(&admission.admission_id, &attempt_id)?;
    let dispatch_id = solo_dispatch_identity(attempt_id.as_str(), admission.admission_id.as_str());
    let intent = fabric.dispatch(&admission.admission_id, &attempt_id, &dispatch_id)?;
    let dispatch = SoloDispatchRecord {
        dispatch_id: dispatch_id.clone(),
        claim_id: intake.claimed.claim_id.clone(),
        attempt_id: attempt_id.as_str().to_owned(),
        operation_id: operation_id.clone(),
        task_id: intake.plan.launch.task_id.as_str().to_owned(),
        route: route.clone(),
        route_class: staffed.route_class.clone(),
        worker_generation: intake.claimed.worker_generation,
        binding_digest: intake.claimed.binding_digest.clone(),
        executable_digest: intake.claimed.executable_digest.clone(),
        expected_result_schema: intake.delegate.expected_result.clone(),
        deadline_unix_ms: intake.deadline_unix_ms,
        cancellation_id: solo_cancellation_identity(&operation_id),
        fence: intent.fence.clone(),
        epoch: intent.epoch.clone(),
        worker_completed_fields: vec![
            "registration_id".to_owned(),
            "executable_binding".to_owned(),
            "decision_id".to_owned(),
            "parent_job_id".to_owned(),
            "work_scope_id".to_owned(),
            "expected_result_schema_version".to_owned(),
        ],
    };
    let snapshot = fabric.snapshot()?;
    let projection = SoloPersistedAttempt {
        operation_id: operation_id.clone(),
        attempt_id: attempt_id.as_str().to_owned(),
        delegate_digest: intake.delegate.source_digest.clone(),
        plan_digest: definition.definition_digest.clone(),
        requirements: intake.requirements.clone(),
        observed_scope: intake.observed_scope.clone(),
        claimed: intake.claimed.clone(),
        receipt: receipt.clone(),
        snapshot,
        dispatch: Some(dispatch.clone()),
        emitted: false,
        result_digest: None,
        cancellation_evidence: None,
    };
    persist_projection(composition.state_root(), &projection)?;
    let ack = fabric.emit(&dispatch_id)?;
    if !ack.retained || ack.dispatch_id != dispatch_id {
        return Err(DaemonError::ProviderAdmission(FabricError::Contract(
            "solo egress acknowledgement does not retain the intent".to_owned(),
        )));
    }
    let mut projection = projection;
    projection.emitted = true;
    projection.snapshot = fabric.snapshot()?;
    persist_projection(composition.state_root(), &projection)?;
    {
        let mut state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        state.live_operation = Some(operation_id.clone());
    }
    Ok(SoloDriveOutcome {
        operation_id,
        attempt_id: attempt_id.as_str().to_owned(),
        dispatch_id,
        admission_id: admission.admission_id.as_str().to_owned(),
        route,
        retained: ack.retained,
        dispatch,
    })
}

/// Performs the authenticated Kernel provider-binding check for one solo
/// intake without crossing into local admission, activation, or dispatch
/// substitutes.
///
/// This is the direct-entry probe behind
/// [`DaemonComposition::solo_drive_once_async`]: it validates the
/// plan-only staffing receipt and verifies the remaining exact owner tuple
/// through the Kernel verifier, then returns the typed fail-closed residual
/// before any capability or fabric effect is created. The runtime queue
/// poll does not use this probe: [`solo_poll_queue_async`] drives through
/// [`drive_solo_delegate_verified_async`] into
/// [`DaemonComposition::agent_fabric_new_verified_async`] instead, so the
/// verified-construct seam has its production caller on the poll path while
/// the direct entry stays a probe until its `lib.rs` wrapper threads the
/// composition through (one-line follow-up outside this module).
///
/// Kernel currently has no independently owner-backed executable-binding
/// digest on its durable provider claim row. Its accepted verifier therefore
/// cannot yet authorize construction of an `AdmittedProviderCapability` for
/// this operation. The call below verifies the remaining exact owner tuple,
/// then returns a typed fail-closed residual before any capability or fabric
/// effect is created. The native-worker owner must persist and verify the
/// executable join itself before this path can proceed.
pub async fn drive_solo_delegate_async(
    kernel: &Arc<DaemonKernelClient>,
    intake: SoloDelegateIntake,
    now_unix_ms: u64,
) -> Result<SoloDriveOutcome, DaemonError> {
    intake
        .validate(now_unix_ms)
        .map_err(DaemonError::ProviderAdmission)?;
    guard_solo_plan(&intake.plan).map_err(DaemonError::ProviderAdmission)?;

    // Preserve the useful plan-only staffing validation while the authenticated
    // owner check runs; it does not construct a coordinator capability or
    // reserve, activate, or dispatch work.
    let config = daemon_coordinator_config()?;
    let receipt = plan_coordinator_staffing(&config, &intake.plan).map_err(|error| {
        DaemonError::ProviderAdmission(FabricError::Contract(error.to_string()))
    })?;
    verify_receipt_digest(&receipt).map_err(|error| {
        DaemonError::ProviderAdmission(FabricError::Contract(error.to_string()))
    })?;

    let material = intake.claimed.material();
    kernel
        .verify_provider_binding_async(&material)
        .await
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;

    // #1700 AUD4: the missing executable-binding owner is a missing owner
    // prerequisite, not a generic contract string. The residual below names
    // the exact interface (kernel activation authority), the blocked
    // operation/work (launch activation of this operation), the live
    // fence/epoch observed at the probe, the disposition, and the next
    // permitted action, and it travels the real daemon response path as
    // `DaemonError::ProviderAdmission`, consumable by status/recovery/UI
    // code without string interpretation. The native-worker owner must
    // persist and verify the executable join itself before this path can
    // proceed (residual owner leg: the Kernel native-worker executable
    // binding; no durable row exists on any owner today).
    let live_fence = kernel.kernel_fence();
    Err(DaemonError::ProviderAdmission(crate::blocked_port(
        FabricPortId::ActivationAuthority,
        FabricOperation::Activate,
        material.operation_id.clone(),
        Some(live_fence.clone()),
        Some(live_fence.authority_epoch.clone()),
    )))
}

/// Refuses when the consumed binding does not bind this exact intake.
///
/// A caller-claimed digest is never evidence: the binding the drive consumes
/// must carry the same presented halves the intake claims, or the drive
/// refuses with a typed identity conflict before any capability,
/// reservation, or dispatch exists. The binding is currently derived from
/// the queued intake itself, so this pins the invariant the poll path
/// relies on; an owner-supplied binding takes the same parameter.
fn check_verified_binds_intake(
    intake: &SoloDelegateIntake,
    material: &VerifiedProviderMaterial,
) -> Result<(), DaemonError> {
    let claimed = &intake.claimed;
    if material.identity != claimed.identity
        || material.claim_id != claimed.claim_id
        || material.attempt_id != claimed.attempt_id
        || material.operation_id != claimed.operation_id
        || material.binding_digest != claimed.binding_digest
        || material.executable_digest != claimed.executable_digest
        || material.route_revision != claimed.route_revision
        || material.capacity_revision != claimed.capacity_revision
        || material.worker_generation != claimed.worker_generation
        || !fences_match_exact(&material.presented_fence, &claimed.presented_fence)
    {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "owner-verified binding does not bind this solo intake".to_owned(),
            ),
        ));
    }
    Ok(())
}

/// Revalidates the launch gate immediately before dispatch.
///
/// Missing, substituted, moved-route, or stale-activation material refuses
/// here, before the first possible external effect: the activation must
/// address this exact admission and attempt (and belong to it), the live
/// queue head must still carry the consumed route revision, and the live
/// fence/epoch must still match the activation fence/epoch.
fn revalidate_launch_gate(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    admission: &FabricAdmission,
    attempt_id: &AttemptId,
    evidence: &ActivationEvidence,
    consumed: &VerifiedProviderMaterial,
) -> Result<(), DaemonError> {
    if evidence.admission_id != admission.admission_id
        || evidence.attempt_id != *attempt_id
        || !admission.attempt_ids.contains(attempt_id)
    {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleAdmission(
            "solo launch gate refuses activation for another admission or attempt".to_owned(),
        )));
    }
    {
        let state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        let Some(head) = state.queue.front() else {
            return Err(DaemonError::ProviderAdmission(
                FabricError::IdentityConflict(
                    "solo launch gate refuses: queue head left before dispatch".to_owned(),
                ),
            ));
        };
        if head.claimed.operation_id != consumed.operation_id
            || head.claimed.route_revision != consumed.route_revision
        {
            return Err(DaemonError::ProviderAdmission(
                FabricError::IdentityConflict(
                    "solo launch gate refuses a route-moved activation".to_owned(),
                ),
            ));
        }
    }
    let live = kernel.kernel_fence();
    if !fences_match_exact(&live, &evidence.fence) {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleFence(
            "solo launch gate refuses a fence-moved activation".to_owned(),
        )));
    }
    if !live.authority_epoch.is_same_authority(&evidence.epoch) {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleEpoch(
            "solo launch gate refuses an epoch-moved activation".to_owned(),
        )));
    }
    Ok(())
}

/// Cross-checks the dispatch record against the consumed binding and the
/// live clock immediately before it is persisted.
///
/// The persisted record must carry the consumed operation/attempt/claim
/// identities and digests (never caller-claimed substitutes), and the claim
/// deadline must still be in the future at dispatch time: a deadline that
/// elapsed during owner IO refuses instead of launching stale.
fn check_dispatch_record(
    record: &SoloDispatchRecord,
    material: &VerifiedProviderMaterial,
) -> Result<(), DaemonError> {
    if record.operation_id != material.operation_id
        || record.attempt_id != material.attempt_id
        || record.claim_id != material.claim_id
        || record.binding_digest != material.binding_digest
        || record.executable_digest != material.executable_digest
        || record.worker_generation != material.worker_generation
    {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "solo dispatch record does not bind the consumed material".to_owned(),
            ),
        ));
    }
    if record.deadline_unix_ms == 0 || record.deadline_unix_ms <= crate::unix_ms() {
        return Err(DaemonError::ProviderAdmission(FabricError::Contract(
            "solo claim deadline elapsed before dispatch".to_owned(),
        )));
    }
    Ok(())
}

/// Re-resolves the exact dispatch material immediately before dispatch
/// (issue #2567 AUD12/I4).
///
/// The fabric chain above resolved each piece through its owner, but nothing
/// yet proves the resolved pieces still cohere at dispatch time: the
/// admission must bind the planned definition and the staged reservation,
/// the definition must still echo the consumed frozen plan (task, launch,
/// revisions, class), the frozen delegate packet must still bind its bytes
/// with artifact scope present, the resolved route must be the receipt-staffed
/// lane route with the receipt (budget, routes, evidence) still digest-bound,
/// and the solo launch contract, the consumed binding halves, and a
/// still-live claim deadline must hold. Anything missing, substituted, or
/// moved refuses here, before the first possible external effect, with the
/// same typed vocabulary as the launch gate.
#[allow(clippy::too_many_arguments)]
fn revalidate_dispatch_material(
    intake: &SoloDelegateIntake,
    prepared: &VerifiedProviderMaterial,
    receipt: &StaffingPlanReceipt,
    staffed: &StaffedLane,
    route: &RouteFingerprint,
    definition: &SwarmDefinition,
    reservation: &Reservation,
    admission: &FabricAdmission,
) -> Result<(), DaemonError> {
    if definition.definition_id != intake.plan.candidate_id
        || definition.task_id != intake.plan.launch.task_id.as_str()
        || definition.task_revision != intake.plan.task_revision
        || definition.plan_revision != intake.plan.plan_revision.as_str()
        || definition.work_class != intake.plan.work_class
    {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "solo dispatch refuses a definition that no longer echoes the frozen plan"
                    .to_owned(),
            ),
        ));
    }
    if reservation.definition_id != definition.definition_id
        || reservation.definition_digest != definition.definition_digest
    {
        return Err(DaemonError::ProviderAdmission(FabricError::ReceiptBinding(
            "solo dispatch refuses a reservation that no longer stages the planned definition"
                .to_owned(),
        )));
    }
    if admission.definition_id != definition.definition_id
        || admission.definition_digest != definition.definition_digest
        || admission.reservation_id != reservation.reservation_id
    {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleAdmission(
            "solo dispatch refuses an admission that no longer commits the staged definition"
                .to_owned(),
        )));
    }
    if sha256_hex(&intake.delegate.source_bytes) != intake.delegate.source_digest {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "solo dispatch refuses a delegate packet whose bytes no longer bind its digest"
                    .to_owned(),
            ),
        ));
    }
    if intake.delegate.owned_resources.is_empty() {
        return Err(DaemonError::ProviderAdmission(FabricError::Contract(
            "solo dispatch refuses a delegate packet with no artifact scope".to_owned(),
        )));
    }
    if *route != staffed.route {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "solo dispatch refuses a route that is not the receipt-staffed lane route"
                    .to_owned(),
            ),
        ));
    }
    verify_receipt_digest(receipt).map_err(|error| {
        DaemonError::ProviderAdmission(FabricError::Contract(format!(
            "solo dispatch refuses a staffing receipt that no longer binds its body: {error}"
        )))
    })?;
    guard_solo_plan(&intake.plan).map_err(DaemonError::ProviderAdmission)?;
    if intake.deadline_unix_ms == 0 || intake.deadline_unix_ms <= crate::unix_ms() {
        return Err(DaemonError::ProviderAdmission(FabricError::Contract(
            "solo claim deadline elapsed before dispatch".to_owned(),
        )));
    }
    if prepared.operation_id != intake.claimed.operation_id
        || prepared.binding_digest != intake.claimed.binding_digest
        || prepared.executable_digest != intake.claimed.executable_digest
        || prepared.route_revision != intake.claimed.route_revision
    {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "solo dispatch refuses consumed material that no longer binds the intake"
                    .to_owned(),
            ),
        ));
    }
    Ok(())
}

/// Binds the recorded dispatch authority to the retained intent (issue #2567
/// I4).
///
/// The intent the fabric retained must address this exact dispatch identity,
/// admission, attempt, and activation digest, and carry the activation
/// fence/epoch and the admission work class verbatim. A mismatch refuses with
/// typed stale/substitution instead of persisting foreign authority under
/// this operation.
fn check_dispatch_intent(
    intent: &DispatchIntent,
    dispatch_id: &str,
    admission: &FabricAdmission,
    attempt_id: &AttemptId,
    activation: &ActivationEvidence,
) -> Result<(), DaemonError> {
    if intent.dispatch_id != dispatch_id
        || intent.admission_id != admission.admission_id
        || intent.attempt_id != *attempt_id
        || intent.activation_digest != activation.activation_digest
        || intent.work_class != admission.work_class
    {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "solo dispatch refuses an intent that does not bind this admission and activation"
                    .to_owned(),
            ),
        ));
    }
    if !fences_match_exact(&intent.fence, &activation.fence) {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleFence(
            "solo dispatch refuses an intent with a moved fence".to_owned(),
        )));
    }
    if !intent.epoch.is_same_authority(&activation.epoch) {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleEpoch(
            "solo dispatch refuses an intent with a moved epoch".to_owned(),
        )));
    }
    Ok(())
}

/// Returns true when the live queue head still carries the consumed revisions.
///
/// The compared tuple is the prepare/adopt contract: operation/claim/attempt
/// identity, provider identity, task and candidate binding, route and
/// capacity revisions, the Governor currentness expectation, the restore
/// floor, the route-gate requirements and observed scope, the claim deadline,
/// worker generation, binding digests, and the presented fence. Anything else
/// about the head may evolve; a move in this tuple means the consumed plan no
/// longer addresses the queued head.
fn intake_revisions_match(live: &SoloDelegateIntake, consumed: &SoloDelegateIntake) -> bool {
    live.claimed.operation_id == consumed.claimed.operation_id
        && live.claimed.claim_id == consumed.claimed.claim_id
        && live.claimed.attempt_id == consumed.claimed.attempt_id
        && live.claimed.identity == consumed.claimed.identity
        && live.claimed.route_revision == consumed.claimed.route_revision
        && live.claimed.capacity_revision == consumed.claimed.capacity_revision
        && live.claimed.expectation == consumed.claimed.expectation
        && live.claimed.minimum_event_sequence == consumed.claimed.minimum_event_sequence
        && live.claimed.worker_generation == consumed.claimed.worker_generation
        && live.claimed.binding_digest == consumed.claimed.binding_digest
        && live.claimed.executable_digest == consumed.claimed.executable_digest
        && fences_match_exact(
            &live.claimed.presented_fence,
            &consumed.claimed.presented_fence,
        )
        && live.requirements == consumed.requirements
        && live.observed_scope == consumed.observed_scope
        && live.deadline_unix_ms == consumed.deadline_unix_ms
        && live.plan.launch.task_id.as_str() == consumed.plan.launch.task_id.as_str()
        && live.plan.candidate_id == consumed.plan.candidate_id
        && live.delegate.source_digest == consumed.delegate.source_digest
}

/// Adopt step for the drive path: revalidates the consumed revisions after
/// owner IO, before the adopt step touches the fabric (issue #2567 AUD9).
///
/// The fence check the drive already had is the first of five: a fence that
/// moved under the seam await refuses with a typed stale fence; a live
/// authority epoch that no longer matches the consumed expectation refuses
/// with a typed stale epoch; a queue head that no longer carries the
/// consumed task/route/admission revisions refuses with a typed identity
/// conflict; the consumed owner-verified binding must still bind the live
/// head itself (never a caller-claimed substitute that arrived under IO);
/// and a live slot that another unsettled operation now holds refuses with
/// a typed identity conflict (a settled slot clears under the same rule as
/// the prepare step). Every refusal leaves the queue head queued for a
/// fresh evaluation instead of adopting verified material under another
/// generation, task, route, or admission.
fn adopt_solo_drive(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    intake: &SoloDelegateIntake,
    prepared: &VerifiedProviderMaterial,
) -> Result<(), DaemonError> {
    let live = kernel.kernel_fence();
    if !fences_match_exact(&live, &prepared.presented_fence) {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleFence(
            "solo adopt refuses a fence moved during owner IO".to_owned(),
        )));
    }
    if !live
        .authority_epoch
        .is_same_authority(&prepared.expectation.live_authority_epoch)
    {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleEpoch(
            "solo adopt refuses an epoch moved during owner IO".to_owned(),
        )));
    }
    {
        let mut state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        let Some(head) = state.queue.front() else {
            return Err(DaemonError::ProviderAdmission(
                FabricError::IdentityConflict(
                    "solo adopt refuses: queue head left during owner IO".to_owned(),
                ),
            ));
        };
        if !intake_revisions_match(head, intake) {
            return Err(DaemonError::ProviderAdmission(
                FabricError::IdentityConflict(
                    "solo adopt refuses a task, route, or admission moved during owner IO"
                        .to_owned(),
                ),
            ));
        }
        // The prepare-time cross-check ran before the seam await, so adopt
        // re-proves the consumed owner-verified binding against the live
        // head: a caller-claimed substitute that arrived under IO refuses
        // here with a typed identity conflict and the head stays queued.
        check_verified_binds_intake(head, prepared)?;
        if let Some(live_operation) = state.live_operation.clone()
            && live_operation != prepared.operation_id
        {
            let settled = load_projection(composition.state_root(), &live_operation)
                .is_ok_and(|projection| projection_settled(&projection));
            if !settled {
                return Err(DaemonError::ProviderAdmission(
                    FabricError::IdentityConflict(
                        "solo adopt refuses: live slot moved during owner IO".to_owned(),
                    ),
                ));
            }
            state.live_operation = None;
        }
    }
    Ok(())
}

/// Drives one admitted solo delegate intake through the verified async
/// seam to a retained dispatch (issue #1108 W4/A2).
///
/// This is the runtime poll's construct path into
/// [`DaemonComposition::agent_fabric_new_verified_async`]: the driver's own
/// claimed halves (`intake.claimed`, operation-presented) travel as the
/// per-operation `claimed` argument while the same halves' material travels
/// as the resolution input, and the fabric is built over
/// [`DaemonComposition::production_fabric_ports`] — never over the
/// test-only solo ports. Session halves are overwritten with the live
/// authenticated session values and the binding is verified through the
/// Kernel provider-admission verifier inside the seam before any admitted
/// capability exists, so this path mints no authority of its own.
///
/// Fail-closed order mirrors the test-only sync drive: readiness, intake
/// shape, solo recipe, single live slot, plan-only staffing receipt, then
/// the seam, then the admitted-route gate and the fabric chain
/// (`define_and_plan` -> `stage_reservation` -> `commit_admission` ->
/// `activate` -> `dispatch` -> persist -> `emit`). Until the owner ports
/// bind, the drive refuses at the gate with the typed missing-prerequisite
/// residual: B-MOD #694 for the route, the Governor swarm-admission owner
/// for staging, B-ACTIVATION-PROJECTION #839 for activation, the
/// executor-daemon bind (#874) for emission. The projection is persisted
/// before `emit` exactly as in the sync drive, so a restart reads back the
/// same digest-bound attempt.
///
/// The caller holds the composition guard across the seam await (see
/// [`solo_poll_queue_async`]); this function takes `&DaemonComposition`
/// like the sync drive and performs no locking of its own.
async fn drive_solo_delegate_verified_async(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    intake: SoloDelegateIntake,
    now_unix_ms: u64,
) -> Result<SoloDriveOutcome, DaemonError> {
    let material = intake.claimed.material();
    // The admitted-material future below is heap-pinned so the queue-poll
    // future that awaits this wrapper stays small: the intake would
    // otherwise be counted in both frames across the seam await.
    Box::pin(drive_admitted_material_async(
        composition,
        kernel,
        intake,
        material,
        now_unix_ms,
    ))
    .await
}

/// Drives one intake on its consumed binding through the verified async seam
/// to a retained dispatch (issue #1108 W4/A2).
///
/// Prepare/IO/adopt: readiness, intake shape, solo recipe, binding
/// cross-check, and single live slot are prepared under short borrows; the
/// snapshot below is cloned before the seam await so the adopt step
/// (`adopt_solo_drive`) can revalidate the exact consumed
/// fence/epoch, task/route/admission, and live-slot revisions after owner
/// IO; the fabric chain (`define_and_plan` -> `stage_reservation` ->
/// `commit_admission` -> `activate` -> launch-gate revalidation ->
/// dispatch-material revalidation -> `dispatch` -> intent-authority check ->
/// persist -> frame) adopts the typed result only when every revision still
/// binds.
#[allow(clippy::too_many_lines)]
#[allow(clippy::needless_pass_by_value)]
async fn drive_admitted_material_async(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    intake: SoloDelegateIntake,
    material: VerifiedProviderMaterial,
    now_unix_ms: u64,
) -> Result<SoloDriveOutcome, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    intake
        .validate(now_unix_ms)
        .map_err(DaemonError::ProviderAdmission)?;
    guard_solo_plan(&intake.plan).map_err(DaemonError::ProviderAdmission)?;
    check_verified_binds_intake(&intake, &material)?;
    let prepared = Box::new(material.clone());
    let operation_id = material.operation_id.clone();
    let attempt_id = AttemptId::new(material.attempt_id.clone())
        .map_err(|error| DaemonError::ProviderAdmission(contract(error)))?;
    // Single live slot: a second drive while the slot holds an unsettled
    // attempt refuses instead of overlapping ownership. A settled slot
    // clears so the next admitted operation may proceed.
    {
        let mut state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        if let Some(live) = state.live_operation.clone()
            && live != operation_id
        {
            let settled = load_projection(composition.state_root(), &live)
                .is_ok_and(|projection| projection_settled(&projection));
            if !settled {
                return Err(DaemonError::ProviderAdmission(FabricError::Contract(
                    format!("solo slice holds live attempt {live}; settle or cancel it first"),
                )));
            }
            state.live_operation = None;
        }
    }
    let config = daemon_coordinator_config()?;
    let receipt = plan_coordinator_staffing(&config, &intake.plan).map_err(|error| {
        DaemonError::ProviderAdmission(FabricError::Contract(error.to_string()))
    })?;
    verify_receipt_digest(&receipt).map_err(|error| {
        DaemonError::ProviderAdmission(FabricError::Contract(error.to_string()))
    })?;
    let staffed = receipt.lanes.first().ok_or_else(|| {
        DaemonError::ProviderAdmission(FabricError::NoRoute(
            "solo staffing receipt staffed no lane".to_owned(),
        ))
    })?;
    // Issue #1108 W1/W4/A2: the verified-construct site. Production ports plus
    // the driver's claimed halves enter the async seam; the seam resolves
    // the session halves over the live authenticated session, verifies the
    // binding through the Kernel provider-admission verifier, and builds
    // the sealed capability through the closed admission port before the
    // coordinator is constructed.
    let ports = composition.production_fabric_ports()?;
    let mut fabric = composition
        .agent_fabric_new_verified_async(kernel, ports, material, &intake.claimed)
        .await?;
    // AUD9: adopt revalidates the consumed revisions after owner IO, before
    // touching the fabric (see `adopt_solo_drive`): fence, epoch,
    // task/route, and live-slot admission. Any move refuses with a typed
    // stale/conflict instead of adopting verified material under another
    // generation; the queue head stays queued for a fresh evaluation.
    adopt_solo_drive(composition, kernel, &intake, &prepared)?;
    // Issue #1702 W2: the drive runs against the daemon state root, so every
    // owner-separated revision published on this fabric is committed and
    // verified durably before anything reports it current. Attaching the store
    // before the first semantic write is what makes the ordering property
    // reachable from the production path instead of a separate test seam.
    fabric.attach_semantic_revision_store(composition.state_root());
    let evidence = composition.capability_admission()?;
    let route = fabric.require_model_route(
        &intake.requirements,
        evidence,
        &intake.observed_scope,
        now_unix_ms,
    )?;
    let (definition, _) = fabric.define_and_plan(intake.plan.clone())?;
    let reservation = fabric.stage_reservation(&definition.definition_id)?;
    let admission = fabric.commit_admission(&reservation.reservation_id)?;
    let activation = fabric.activate(&admission.admission_id, &attempt_id)?;
    // AUD13: the launch gate is revalidated immediately before dispatch,
    // after the last owner write and before the first possible external
    // effect. Missing, substituted, moved-route, or stale-activation
    // material refuses here instead of launching.
    revalidate_launch_gate(
        composition,
        kernel,
        &admission,
        &attempt_id,
        &activation,
        &prepared,
    )?;
    // AUD12/I4: the resolved material is re-resolved immediately before
    // dispatch: frozen definition, staged reservation, committed admission,
    // frozen packet bytes, staffed route, digest-bound receipt (budget,
    // routes, evidence), solo launch contract, consumed binding halves, and
    // a still-live deadline. Anything moved refuses before any external
    // effect.
    revalidate_dispatch_material(
        &intake,
        &prepared,
        &receipt,
        staffed,
        &route,
        &definition,
        &reservation,
        &admission,
    )?;
    let dispatch_id = solo_dispatch_identity(attempt_id.as_str(), admission.admission_id.as_str());
    let intent = fabric.dispatch(&admission.admission_id, &attempt_id, &dispatch_id)?;
    // I4: the retained intent must carry this exact dispatch identity,
    // admission, attempt, activation digest, fence, epoch, and work class
    // before anything persists it.
    check_dispatch_intent(&intent, &dispatch_id, &admission, &attempt_id, &activation)?;
    let dispatch = SoloDispatchRecord {
        dispatch_id: dispatch_id.clone(),
        claim_id: intake.claimed.claim_id.clone(),
        attempt_id: attempt_id.as_str().to_owned(),
        operation_id: operation_id.clone(),
        task_id: intake.plan.launch.task_id.as_str().to_owned(),
        route: route.clone(),
        route_class: staffed.route_class.clone(),
        worker_generation: intake.claimed.worker_generation,
        binding_digest: intake.claimed.binding_digest.clone(),
        executable_digest: intake.claimed.executable_digest.clone(),
        expected_result_schema: intake.delegate.expected_result.clone(),
        deadline_unix_ms: intake.deadline_unix_ms,
        cancellation_id: solo_cancellation_identity(&operation_id),
        fence: intent.fence.clone(),
        epoch: intent.epoch.clone(),
        worker_completed_fields: vec![
            "registration_id".to_owned(),
            "executable_binding".to_owned(),
            "decision_id".to_owned(),
            "parent_job_id".to_owned(),
            "work_scope_id".to_owned(),
            "expected_result_schema_version".to_owned(),
        ],
    };
    // AUD12/AUD13: the dispatch record is cross-checked against the consumed
    // binding and the live clock immediately before it is persisted. The
    // persisted identity below carries verified digests (never substitutes)
    // and a still-live deadline; a mismatch refuses before any external
    // effect instead of recording a stale launch.
    check_dispatch_record(&dispatch, &prepared)?;
    let snapshot = fabric.snapshot()?;
    let projection = SoloPersistedAttempt {
        operation_id: operation_id.clone(),
        attempt_id: attempt_id.as_str().to_owned(),
        delegate_digest: intake.delegate.source_digest.clone(),
        plan_digest: definition.definition_digest.clone(),
        requirements: intake.requirements.clone(),
        observed_scope: intake.observed_scope.clone(),
        claimed: intake.claimed.clone(),
        receipt: receipt.clone(),
        snapshot,
        dispatch: Some(dispatch.clone()),
        emitted: false,
        result_digest: None,
        cancellation_evidence: None,
    };
    persist_projection(composition.state_root(), &projection)?;
    // Issue #1108 W3 (acceptance A3/A7/A10/A11): the verified-path
    // production caller of the provider-capability frame. The frame binds
    // the recorded intent's operation/attempt identity, the admitted
    // provider identity from the verified coordinator binding, and the
    // canonical payload digest, then emits through the existing
    // DispatchEgressPort under the FabricOperation::Emit gate — the same
    // egress with identity bound, never a second dispatch scheme. Until
    // the executor-daemon bind (#874) lands, the gate refuses typed and
    // the head stays queued.
    let frame = fabric.dispatch_provider_capability_frame(&dispatch_id)?;
    if frame.dispatch_id != dispatch_id {
        return Err(DaemonError::ProviderAdmission(FabricError::Contract(
            "solo provider capability frame does not address the dispatched intent".to_owned(),
        )));
    }
    let mut projection = projection;
    projection.emitted = true;
    projection.snapshot = fabric.snapshot()?;
    if projection.snapshot.provider_frames.get(&dispatch_id) != Some(&frame) {
        return Err(DaemonError::ProviderAdmission(FabricError::Contract(
            "solo provider capability frame was not recorded for the dispatched intent".to_owned(),
        )));
    }
    persist_projection(composition.state_root(), &projection)?;
    {
        let mut state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        state.live_operation = Some(operation_id.clone());
    }
    Ok(SoloDriveOutcome {
        operation_id,
        attempt_id: attempt_id.as_str().to_owned(),
        dispatch_id,
        admission_id: admission.admission_id.as_str().to_owned(),
        route,
        // Retention is established above: the frame call emitted through
        // the DispatchEgressPort under the Emit gate with the ack identity
        // verified inside, and the recorded frame read back exactly.
        retained: true,
        dispatch,
    })
}

/// The synchronous solo path is retained only for unit tests. Production
/// drives through the async verified seam: the runtime poll uses
/// [`drive_solo_delegate_verified_async`], while direct production calls
/// stay on the [`drive_solo_delegate_async`] probe; both refuse this
/// synchronous path because authenticated Kernel verification requires an
/// async call.
#[cfg(not(test))]
pub fn drive_solo_delegate(
    _composition: &DaemonComposition,
    _kernel: &Arc<DaemonKernelClient>,
    _intake: SoloDelegateIntake,
    _now_unix_ms: u64,
) -> Result<SoloDriveOutcome, DaemonError> {
    Err(DaemonError::Kernel(
        "synchronous solo driving is disabled; use the async Kernel-verified entry point"
            .to_owned(),
    ))
}

/// Returns true when the persisted projection needs no further drive.
///
/// Non-test: the verified async drive clears a settled live slot under the
/// same rule as the test-only sync drive, so one settled attempt never
/// pins the slot against the next admitted operation.
fn projection_settled(projection: &SoloPersistedAttempt) -> bool {
    if projection.result_digest.is_some() || projection.cancellation_evidence.is_some() {
        return true;
    }
    let terminal_cancel = projection
        .snapshot
        .cancellations
        .values()
        .any(|state| *state == crate::agent_fabric::CancellationLifecycle::Terminal);
    if terminal_cancel {
        return true;
    }
    projection.snapshot.attempt_states.values().any(|state| {
        matches!(
            state,
            crate::agent_fabric::AttemptLifecycle::ResultSubmitted
                | crate::agent_fabric::AttemptLifecycle::UnknownOutcome
        )
    })
}

/// Rebuilds the solo ports plus a restored fabric from a persisted projection.
///
/// Ports are reconstructed from the persisted verified material (definition
/// digest, fence, epoch, attempt, receipt lanes) with a fresh live fence
/// check at restore: the snapshot's stored binding must equal the live
/// binding or the restore refuses instead of resuming effect authority.
#[cfg(test)]
fn restore_solo_fabric(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    projection: &SoloPersistedAttempt,
) -> Result<AgentFabric, DaemonError> {
    let definition = projection
        .snapshot
        .definitions
        .values()
        .find(|definition| definition.definition_digest == projection.plan_digest)
        .ok_or_else(|| {
            DaemonError::ProviderAdmission(FabricError::BrokenOwnershipLink(
                "solo restore finds no definition binding the frozen plan digest".to_owned(),
            ))
        })?
        .clone();
    let live_fence = kernel.kernel_fence();
    if !fences_match_exact(&live_fence, &definition.fence) {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleFence(
            "solo restore refuses a fence-moved definition".to_owned(),
        )));
    }
    let attempt_id = AttemptId::new(projection.attempt_id.clone())
        .map_err(|error| DaemonError::ProviderAdmission(contract(error)))?;
    let context = SoloVerifiedContext {
        definition_id: definition.definition_id.clone(),
        definition_digest: definition.definition_digest.clone(),
        work_class: definition.work_class,
        fence: live_fence,
        epoch: definition.fence.authority_epoch.clone(),
        attempt_id,
    };
    let staffed = projection.receipt.lanes.first().ok_or_else(|| {
        DaemonError::ProviderAdmission(FabricError::NoRoute(
            "solo restore finds no staffed lane".to_owned(),
        ))
    })?;
    let registry = SoloModelRegistryPort::new();
    registry
        .preload(PreloadedRoute {
            role: projection.requirements.role.clone(),
            competence: projection.requirements.competence.clone(),
            route: staffed.route.clone(),
        })
        .map_err(DaemonError::ProviderAdmission)?;
    let ports = solo_fabric_ports(context, kernel, registry);
    let mut fabric = composition.agent_fabric_restore_verified(
        kernel,
        projection.snapshot.clone(),
        ports,
        projection.claimed.material(),
    )?;
    // #1702 W2: every production solo operation restores through this one
    // seam -- the fair-pull recovery poll, cancellation request, terminal
    // reconciliation and worker-result ingest all call `restore_solo_fabric`
    // and drive the fabric it returns. Binding the daemon state root to the
    // fabric HERE is what makes the ordering property hold on the production
    // path rather than only under `cfg(test)`: `agent_fabric_restore_verified`
    // is itself a test-only helper, so it carries no store of its own on this
    // seam, and without this attach the restored fabric would refuse every
    // owner-separated revision with `DurabilityUnproven`. Attaching before
    // the first semantic write means each publish is committed and verified
    // durably before it is readable as current, across restart, for the
    // retained history of all three owners.
    fabric.attach_semantic_revision_store(composition.state_root());
    // Reconcile the unknown: an emitted dispatch with no ingested result
    // cannot relaunch and cannot release; its outcome stays unknown until
    // the worker observation arrives through the ingest leg.
    if projection.emitted && projection.result_digest.is_none() {
        let attempt = AttemptId::new(projection.attempt_id.clone())
            .map_err(|error| DaemonError::ProviderAdmission(contract(error)))?;
        if fabric.attempt_of(&attempt) == Some(crate::agent_fabric::AttemptLifecycle::Dispatched) {
            fabric.mark_unknown_outcome(&attempt)?;
        }
    }
    Ok(fabric)
}

/// Rebuilds the solo ports plus a restored fabric from a persisted projection.
///
/// Synchronous production restore stays fail-closed (issue #1108 A4/A5, A8).
///
/// Every restore caller in this module except `solo_fair_pull_recovery` is
/// synchronous (`solo_request_cancel`, `solo_reconcile_cancel`,
/// `solo_ingest_result`, `solo_ingest_tool_result`, `solo_restore`), while
/// the durable owner row that witnesses a capability resolves only through
/// the async claim-row read
/// (`DaemonKernelClient::load_provider_claim_row_async`). Awaiting it here
/// would convert sync to async with no composition mutex held across the
/// await and no sync-to-async conversion, so this path refuses typed with
/// `StaleProviderBinding` instead of constructing a rowless capability for
/// `AgentFabric::restore_with_admitted_provider`: without the retained row
/// the witnessed-binding gate cannot tell a live binding from
/// caller-supplied halves. The witnessed restore path is
/// `restore_solo_fabric_async`, reached from the async fair-pull recovery
/// poll; no production build resumes effecting operations from a snapshot
/// over this path.
///
/// The projection liveness guards below still run first, so a missing
/// definition binding, a fence-moved definition, or a missing validated
/// session keeps its exact typed refusal.
///
/// # Errors
///
/// Returns the readiness, definition-binding, fence, or session rejection
/// unchanged; otherwise the typed `StaleProviderBinding` refusal.
#[cfg(not(test))]
fn restore_solo_fabric(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    projection: &SoloPersistedAttempt,
) -> Result<AgentFabric, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    let definition = projection
        .snapshot
        .definitions
        .values()
        .find(|definition| definition.definition_digest == projection.plan_digest)
        .ok_or_else(|| {
            DaemonError::ProviderAdmission(FabricError::BrokenOwnershipLink(
                "solo restore finds no definition binding the frozen plan digest".to_owned(),
            ))
        })?;
    let live_fence = kernel.kernel_fence();
    if !fences_match_exact(&live_fence, &definition.fence) {
        return Err(DaemonError::ProviderAdmission(FabricError::StaleFence(
            "solo restore refuses a fence-moved definition".to_owned(),
        )));
    }
    if composition.owner_session_binding().is_none() {
        return Err(DaemonError::Kernel(
            "daemon has no validated Kernel session binding; verified provider admission stays plan-only"
                .to_owned(),
        ));
    }
    Err(DaemonError::ProviderAdmission(FabricError::Coordinator(
        CoordinatorError::StaleProviderBinding,
    )))
}

/// Restores the solo fabric through the verified async seam (issue #1108
/// A6/A8/A9, production restore caller for the async path).
///
/// Production counterpart of the test-only synchronous `restore_solo_fabric`:
/// builds the closed production ports through
/// [`DaemonComposition::production_fabric_ports`], then restores through
/// [`DaemonComposition::agent_fabric_restore_verified_async`] with the
/// projection's own claimed halves as both the resolution input and the
/// per-operation `claimed` argument. Session halves are re-resolved over the
/// live authenticated session and the binding is verified through the Kernel
/// provider-admission verifier inside the seam, so a stored snapshot or a
/// stored `Verified` label alone restores nothing: missing, stale, or revoked
/// evidence refuses typed before any state mutation, and production never
/// silently resumes effecting operations (ARCH-RES-01). The seam restores
/// over the daemon state-root store itself, so no manual revision-store
/// attach is needed here.
///
/// Unknown-outcome reconcile mirrors the synchronous seam: an
/// emitted-but-unresulted dispatch that the restored fabric still reports as
/// dispatched reconciles to unknown instead of relaunching, blocking blind
/// retry and route substitution until exact reconciliation.
///
/// The caller holds the composition guard across the seam await (see
/// [`solo_fair_pull_recovery`]); this function takes `&DaemonComposition`
/// like the construct path and performs no locking of its own.
///
/// `coordinator_document` is the coordinator snapshot JSON selected out of the
/// persisted projection FILE bytes by [`load_verified_projection`] after that
/// file's envelope was verified. It, not `projection.snapshot.coordinator_snapshot`,
/// is what the coordinator is restored from: the typed projection stays a
/// state carrier for the config comparison and the fabric state, and the
/// in-memory snapshot is never reserialized to stand in for the durable bytes.
#[cfg(not(test))]
async fn restore_solo_fabric_async(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    projection: &SoloPersistedAttempt,
    coordinator_document: &str,
) -> Result<AgentFabric, DaemonError> {
    let material = projection.claimed.material();
    let ports = composition.production_fabric_ports()?;
    let mut fabric = composition
        .agent_fabric_restore_verified_async(
            kernel,
            projection.snapshot.clone(),
            ports,
            material,
            &projection.claimed,
            coordinator_document,
        )
        .await?;
    // Reconcile the unknown: an emitted dispatch with no ingested result
    // cannot relaunch and cannot release; its outcome stays unknown until
    // the worker observation arrives through the ingest leg.
    if projection.emitted && projection.result_digest.is_none() {
        let attempt = AttemptId::new(projection.attempt_id.clone())
            .map_err(|error| DaemonError::ProviderAdmission(contract(error)))?;
        if fabric.attempt_of(&attempt) == Some(crate::agent_fabric::AttemptLifecycle::Dispatched) {
            fabric.mark_unknown_outcome(&attempt)?;
        }
    }
    Ok(fabric)
}

/// Re-persists the projection after a control operation.
///
/// Reloads the fresh snapshot from the fabric and carries the durable
/// outcome fields forward, so every control step leaves the same
/// digest-bound projection a restart reads back.
fn repersist_after_control(
    composition: &DaemonComposition,
    fabric: &AgentFabric,
    projection: &mut SoloPersistedAttempt,
) -> Result<(), DaemonError> {
    projection.snapshot = fabric.snapshot()?;
    persist_projection(composition.state_root(), projection)
}

/// Resolves the Kernel-owned nine-class scheduling profile beside the
/// Host-approved launch config.
///
/// The `runtime.toml` is resolved beside the Host-approved launch config — the
/// same protected runtime root `daemon_config` derives `state_root` from — and
/// not from an environment variable, a working directory or a legacy Governor
/// file. An absent, unreadable, malformed, wrongly-versioned or incomplete
/// document is the loader's own typed refusal and is returned unchanged: it is
/// never defaulted, because I14.1 requires a bounded byte profile for all nine
/// classes and I14.2 states an item ceiling for only five of them, so "no file"
/// cannot compile a nine-class policy without inventing numbers no fragment
/// states.
///
/// Both arms of the I14.8 progress loop resolve the profile through this one
/// function, so the release event and the bounded recovery poll can never
/// compile different policies from different places.
fn load_scheduling_profile(
    composition: &DaemonComposition,
) -> Result<SchedulingProfile, DaemonError> {
    let runtime_root = composition.config_path().parent().ok_or_else(|| {
        DaemonError::Composition(CompositionError::Recovery(
            "approved launch config has no runtime parent for the Kernel queue profile".to_owned(),
        ))
    })?;
    load_runtime_scheduling_profile(&runtime_root.join(RUNTIME_PROFILE_FILE_NAME))
        .map_err(|error| DaemonError::ProviderAdmission(FabricError::from(error)))
}

/// Drives the coordinator's fair pull over the capacity a settled attempt just
/// released (issue #1683 W1, I14.8 "Scheduler is pull-based").
///
/// This is the **event arm** of the I14.8 progress loop: the daemon's
/// production call of `AgentFabric::drive_fair_pull`, on the I14.8 release
/// path. `submit_attempt_result` has just settled an attempt, so the
/// coordinator is asked for the next currently admissible item instead of
/// waiting for another agent command. It runs after
/// [`repersist_after_control`], so the candidate result and settlement state are
/// already durable and a refused queue profile cannot lose an observation.
///
/// A release that arrives while nobody is listening to a wake still cannot
/// strand work, because the same drive is also reached by the always-armed
/// bounded recovery poll in [`solo_fair_pull_recovery`]. This arm is the
/// low-latency path; it is not the correctness mechanism.
///
/// Reachable in a non-test build: [`solo_ingest_result`] and
/// [`DaemonComposition::solo_ingest_result`](crate::DaemonComposition::solo_ingest_result)
/// are not `cfg(test)`-gated, so this join is compiled and callable in
/// production. The restore leg is production now (issue #1108 A12): the
/// fabric above is already a restored verified fabric, so this pull runs
/// over live admitted capacity. The remaining documented residual is not
/// this issue's: `drive_solo_delegate_async` still refuses before any fabric
/// effect until the Kernel native-worker owner retains an independently
/// owner-verified executable-binding digest (issue #1678), so no production
/// build yet drives a fresh admitted projection to pull over. The join is
/// placed on the release path because that is where I14.8 says the wake
/// happens, not on a site that would be reachable only by pulling over an
/// empty plan-only coordinator.
fn drive_fair_pull_after_release(
    composition: &DaemonComposition,
    fabric: &mut AgentFabric,
    projection: &mut SoloPersistedAttempt,
) -> Result<(), DaemonError> {
    let profile = load_scheduling_profile(composition)?;
    let outcome = fabric.drive_fair_pull(&profile, false)?;
    // The drive advances the coordinator's fairness credit and may have started
    // attempts, so the digest-bound snapshot is re-persisted after it rather
    // than before.
    repersist_after_control(composition, fabric, projection)?;
    tracing::info!(
        algorithm = outcome.algorithm,
        profile_revision = outcome.profile_revision.as_str(),
        started = outcome.started.len(),
        pulls = outcome.pulls_performed,
        "bounded fair pull over released coordinator capacity"
    );
    Ok(())
}

/// Exact disposition of one bounded fair-pull recovery poll (issue #1683 W5).
///
/// It is deliberately a *poll* outcome, not a success flag: a poll that started
/// nothing is a fully successful poll that observed an empty or fully closed
/// projection, and reporting that as an error would train a reader to ignore the
/// arm that has to stay armed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FairPullRecovery {
    /// No live admitted operation is retained, so there is no projection to
    /// poll. This is the idle observation, not a failure: nothing is eligible
    /// because nothing is admitted, and the next tick observes again.
    NoLiveProjection,
    /// The bounded drive ran and started nothing this pass.
    PolledNothing,
    /// The bounded drive ran and started these many attempts. Names the
    /// operation whose projection was polled so a reader can find it.
    PolledStarted {
        operation_id: String,
        started: usize,
    },
}

/// The always-armed bounded recovery poll of the I14.8 progress loop (issue
/// #1683 W5).
///
/// **This is the arm that makes the loop correct under a lost notification, and
/// the event arm in [`drive_fair_pull_after_release`] is only the optimisation.**
/// An event-only loop deadlocks: if a wake is dropped, coalesced away, or
/// delivered before anything is waiting, the loop waits forever for work that
/// is already eligible. So this poll is *armed unconditionally* — the caller
/// invokes it on every bounded cadence tick without consulting any wake state,
/// any prior failure, or any "did anything change" flag, and the drive it
/// performs runs its bounded selector loop whether or not a wake was pending.
/// That is why a lost wake costs one cadence of latency rather than stranding
/// work.
///
/// It is the same drive over the same projection as the release path, with the
/// same `SchedulingProfile` resolved from the same Kernel-owned `runtime.toml`
/// ([`load_scheduling_profile`]) and the same digest-bound re-persist
/// ([`repersist_after_control`]), so the two arms can never compile different
/// policies or persist a different snapshot shape. The only difference is that
/// this one does not wait to be told there is work.
///
/// Bound: one drive per call, and the drive's own bound is derived from the
/// projection (at most one attempt per currently non-terminal admitted attempt).
/// This function adds no interval, no retry, no cap and no timeout of its own —
/// the cadence is the caller's existing bounded tick.
///
/// Reachable in a non-test build: this is not `cfg(test)`-gated, and its
/// production caller is `daemon_runtime::maybe_start_fair_pull_recovery`, which
/// runs it on the daemon's existing `ACTIVATION_POLL_INTERVAL` cadence. The
/// restore leg is production now (issue #1108 A12): the poll restores the
/// verified fabric from the digest-bound projection and drives it, reporting
/// the typed owner refusal unchanged when the session, fence, or capability
/// is not current. The remaining documented residual is the fresh-drive leg:
/// `drive_solo_delegate_async` still refuses before any fabric effect until
/// the Kernel native-worker owner and the G-11 admission owner (#1678) land.
///
/// The Kernel handle is used only for the restore's live owner-evidence
/// re-resolution that the restore seam already performs (the async verified
/// seam on a production build, [`restore_solo_fabric`] under test); this poll
/// performs no authenticated Kernel request of its own and adds none.
///
/// # Errors
///
/// Returns the owner rejection unchanged. A refusal is a refusal, not a
/// degraded poll: the caller records it and the next tick polls again.
pub async fn solo_fair_pull_recovery(
    composition: &Arc<tokio::sync::Mutex<DaemonComposition>>,
    kernel: &Arc<DaemonKernelClient>,
) -> Result<FairPullRecovery, DaemonError> {
    // Snapshot the live slot under a short synchronous lock, exactly as the
    // intake poll does, then release the composition guard before the restore.
    let operation_id = {
        let Ok(composition) = composition.try_lock() else {
            return Ok(FairPullRecovery::NoLiveProjection);
        };
        if composition.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        // Absent live slot: nothing is admitted, so there is no projection that
        // a missed wake could have stranded. That is the honest idle answer and
        // it costs no owner IO.
        let Some(live) = state.live_operation.clone() else {
            return Ok(FairPullRecovery::NoLiveProjection);
        };
        live
    };
    let composition = composition.lock().await;
    // Production restores the coordinator from the durable document selected
    // out of the verified projection bytes; the test-only synchronous seam
    // keeps the typed readback it has always used.
    #[cfg(not(test))]
    let (mut projection, coordinator_document) = {
        let verified = load_verified_projection(composition.state_root(), &operation_id)?;
        (verified.payload, verified.coordinator_document)
    };
    #[cfg(test)]
    let mut projection = load_projection(composition.state_root(), &operation_id)?;
    #[cfg(test)]
    let mut fabric = restore_solo_fabric(&composition, kernel, &projection)?;
    #[cfg(not(test))]
    let mut fabric =
        restore_solo_fabric_async(&composition, kernel, &projection, &coordinator_document).await?;
    let profile = load_scheduling_profile(&composition)?;
    let outcome = fabric.drive_fair_pull(&profile, true)?;
    repersist_after_control(&composition, &fabric, &mut projection)?;
    let started = outcome.started.len();
    tracing::debug!(
        algorithm = outcome.algorithm,
        profile_revision = outcome.profile_revision.as_str(),
        started,
        pulls = outcome.pulls_performed,
        consumed_wake = outcome.consumed_wake.is_some(),
        cursor_event_sequence = outcome.cursor_event_sequence,
        "bounded fair pull recovery poll"
    );
    if started == 0 {
        Ok(FairPullRecovery::PolledNothing)
    } else {
        Ok(FairPullRecovery::PolledStarted {
            operation_id,
            started,
        })
    }
}

///
/// Serves the persisted projection when no live slot exists, so inspect
/// and post-restart readback address the same attempt without requiring a
/// restore first. Control operations still restore before acting.
pub fn solo_status(
    composition: &DaemonComposition,
    operation_id: &str,
) -> Result<SoloAttemptStatus, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    let projection = load_projection(composition.state_root(), operation_id)?;
    let attempt_key = projection.attempt_id.clone();
    let lifecycle = projection
        .snapshot
        .attempt_states
        .get(&attempt_key)
        .copied()
        .ok_or_else(|| {
            DaemonError::ProviderAdmission(FabricError::Quarantined(format!(
                "solo status finds no registered attempt for {operation_id}"
            )))
        })?;
    Ok(SoloAttemptStatus {
        operation_id: projection.operation_id.clone(),
        attempt_id: attempt_key.clone(),
        lifecycle,
        cancellation: projection.snapshot.cancellations.get(&attempt_key).copied(),
        result_digest: projection.result_digest.clone(),
        emitted: projection.emitted,
    })
}

/// Requests cancellation of the exact admitted attempt.
///
/// Records the request only; possible effects remain reconciling until a
/// terminal disposition is observed through the reconcile leg.
pub fn solo_request_cancel(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    operation_id: &str,
) -> Result<SoloAttemptStatus, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    let mut projection = load_projection(composition.state_root(), operation_id)?;
    let mut fabric = restore_solo_fabric(composition, kernel, &projection)?;
    let attempt = AttemptId::new(projection.attempt_id.clone())
        .map_err(|error| DaemonError::ProviderAdmission(contract(error)))?;
    fabric.request_cancellation(&attempt, &projection.operation_id)?;
    repersist_after_control(composition, &fabric, &mut projection)?;
    solo_status(composition, operation_id)
}

/// Reconciles an observed terminal cancellation for a requested attempt.
///
/// The caller presents the terminal evidence reference (worker terminal
/// receipt observed through the owner result path); the daemon records it
/// verbatim and never synthesizes a terminal it did not observe.
pub fn solo_reconcile_cancel(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    operation_id: &str,
    terminal_evidence: &str,
) -> Result<SoloAttemptStatus, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    require_text(terminal_evidence, "terminal evidence").map_err(DaemonError::ProviderAdmission)?;
    let mut projection = load_projection(composition.state_root(), operation_id)?;
    let mut fabric = restore_solo_fabric(composition, kernel, &projection)?;
    let attempt = AttemptId::new(projection.attempt_id.clone())
        .map_err(|error| DaemonError::ProviderAdmission(contract(error)))?;
    fabric.reconcile_terminal_cancellation(&attempt)?;
    projection.cancellation_evidence = Some(terminal_evidence.to_owned());
    repersist_after_control(composition, &fabric, &mut projection)?;
    solo_status(composition, operation_id)
}

/// Ingests one worker observation as the correlated candidate result.
///
/// Records the worker acknowledgement (never success) and submits the
/// candidate result digest (never Finish) under the same attempt identity.
/// The digest is the owner-observed candidate evidence; `observed_via`
/// names the observation leg verbatim without granting it authority.
pub fn solo_ingest_result(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    operation_id: &str,
    worker_id: &str,
    result_digest: &str,
    observed_via: &str,
) -> Result<SoloAttemptStatus, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    require_text(worker_id, "worker identity").map_err(DaemonError::ProviderAdmission)?;
    require_text(result_digest, "result digest").map_err(DaemonError::ProviderAdmission)?;
    require_text(observed_via, "observation leg").map_err(DaemonError::ProviderAdmission)?;
    let mut projection = load_projection(composition.state_root(), operation_id)?;
    let mut fabric = restore_solo_fabric(composition, kernel, &projection)?;
    let attempt = AttemptId::new(projection.attempt_id.clone())
        .map_err(|error| DaemonError::ProviderAdmission(contract(error)))?;
    let worker = crate::agent_fabric::WorkerAck {
        attempt_id: attempt.clone(),
        worker_id: worker_id.to_owned(),
    };
    fabric.observe_worker_ack(&worker)?;
    let record = crate::agent_fabric::AttemptResultRecord {
        attempt_id: attempt,
        result_digest: result_digest.to_owned(),
    };
    fabric.submit_attempt_result(&record)?;
    projection.result_digest = Some(result_digest.to_owned());
    repersist_after_control(composition, &fabric, &mut projection)?;
    // Issue #1683 W1 / I14.8: the settled attempt released its slot, so the
    // coordinator's bounded fair pull runs now instead of on the next agent
    // command. The candidate result is already durable above.
    drive_fair_pull_after_release(composition, &mut fabric, &mut projection)?;
    solo_status(composition, operation_id)
}

/// Ingests one bridge-projected tool result as attempt evidence for the
/// recorded dispatch operation (issue #1108, A12).
///
/// Production entry for the bridge-receipt leg: `receipt` is the bridge
/// owner's projected ORIGINAL. It is validated with the existing
/// [`ToolResultReceipt::check_complete_evidence`] gate inside
/// [`AgentFabric::observe_tool_result`] — never recomputed here — and bound
/// to the exact dispatch identity recorded in the durable projection, whose
/// recorded intent in the restored fabric is the independent expected set.
/// The recorded dispatch binding (operation/attempt identity) is
/// content-compared before anything is observed, so a receipt for a foreign
/// operation refuses instead of attaching; same identity and payload replay
/// exactly with no second effect, while a changed payload under one identity
/// is the typed `FabricError` residual, never a substitution. The candidate
/// digest submitted is the owner-observed [`ToolResultReceipt::result_digest`],
/// never a caller string, and it stays candidate evidence that can never
/// satisfy task Finish.
///
/// No `DaemonComposition` method drives this yet (STITCH): the transport leg
/// that delivers the bridge-projected receipt is outside this slice's paths.
/// The string-digest leg ([`solo_ingest_result`]) is unchanged.
pub fn solo_ingest_tool_result(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    operation_id: &str,
    worker_id: &str,
    receipt: &ToolResultReceipt,
    observed_via: &str,
) -> Result<SoloAttemptStatus, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    require_text(worker_id, "worker identity").map_err(DaemonError::ProviderAdmission)?;
    require_text(observed_via, "observation leg").map_err(DaemonError::ProviderAdmission)?;
    let mut projection = load_projection(composition.state_root(), operation_id)?;
    let dispatch = projection.dispatch.clone().ok_or_else(|| {
        DaemonError::ProviderAdmission(FabricError::Quarantined(format!(
            "solo tool result finds no recorded dispatch for {operation_id}; \
             a receipt without a recorded intent is never attached"
        )))
    })?;
    if dispatch.operation_id != projection.operation_id
        || dispatch.attempt_id != projection.attempt_id
    {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "solo tool result refuses a dispatch binding that drifted from the recorded \
                 projection; no substitution"
                    .to_owned(),
            ),
        ));
    }
    let mut fabric = restore_solo_fabric(composition, kernel, &projection)?;
    fabric
        .observe_tool_result(&dispatch.dispatch_id, receipt)
        .map_err(DaemonError::ProviderAdmission)?;
    if let Some(recorded) = projection.result_digest.clone()
        && recorded.as_str() != receipt.result_digest()
    {
        return Err(DaemonError::ProviderAdmission(
            FabricError::IdentityConflict(
                "solo tool result reuses the dispatch identity with different bytes; no \
                 substitution, retry, or route change"
                    .to_owned(),
            ),
        ));
    }
    if projection.result_digest.is_some() {
        return solo_status(composition, operation_id);
    }
    let attempt = AttemptId::new(projection.attempt_id.clone())
        .map_err(|error| DaemonError::ProviderAdmission(contract(error)))?;
    let worker = crate::agent_fabric::WorkerAck {
        attempt_id: attempt.clone(),
        worker_id: worker_id.to_owned(),
    };
    fabric.observe_worker_ack(&worker)?;
    let record = crate::agent_fabric::AttemptResultRecord {
        attempt_id: attempt,
        result_digest: receipt.result_digest().to_owned(),
    };
    fabric.submit_attempt_result(&record)?;
    projection.result_digest = Some(receipt.result_digest().to_owned());
    repersist_after_control(composition, &fabric, &mut projection)?;
    // Issue #1683 W1 / I14.8: the settled attempt released its slot, so the
    // coordinator's bounded fair pull runs now instead of on the next agent
    // command. The candidate result is already durable above.
    drive_fair_pull_after_release(composition, &mut fabric, &mut projection)?;
    solo_status(composition, operation_id)
}

/// Ingests one bridge-projected tool result as attempt evidence (issue #1108,
/// A12).
///
/// Production composition caller over [`solo_ingest_tool_result`]: the
/// bridge owner's projected receipt travels the same validated
/// dispatch-bound path as the free function, and its typed outcome is
/// returned unchanged — never discarded into `Ok`. This mirrors the
/// existing [`DaemonComposition::solo_ingest_result`] wrapper for the
/// string-digest leg; it lives in the driver module because the
/// composition root surface is outside this slice's paths.
///
/// Reachable in a non-test build: neither this method nor the free
/// function is `cfg`-gated, so the call compiles and runs in production.
/// The restore leg is production now: the free function restores the
/// verified fabric from the digest-bound projection over the live
/// authenticated session and carries the bridge receipt to
/// [`crate::provider_capability::observe_tool_result`] through the recorded
/// dispatch intent, failing closed with the typed owner refusal when the
/// session, fence, or capability is not current.
/// The remaining stitch (STITCH) is the transport leg that delivers a
/// bridge-projected [`ToolResultReceipt`] to this caller: no in-tree
/// producer hands one here yet.
///
/// # Errors
///
/// Returns the readiness or ingestion rejection unchanged.
impl DaemonComposition {
    pub fn solo_ingest_tool_result(
        &self,
        kernel: &Arc<DaemonKernelClient>,
        operation_id: &str,
        worker_id: &str,
        receipt: &ToolResultReceipt,
        observed_via: &str,
    ) -> Result<SoloAttemptStatus, DaemonError> {
        solo_ingest_tool_result(self, kernel, operation_id, worker_id, receipt, observed_via)
    }
}

/// Restores the durable projection after a restart without relaunching.
///
/// Reloads the persisted attempt, re-resolves live evidence through the
/// verified restore seam, and reconciles unknown outcomes. Same-source
/// replay replays under the original identities; changed material, fence,
/// or route refuses instead of resuming effect authority.
pub fn solo_restore(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    operation_id: &str,
) -> Result<SoloAttemptStatus, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    let mut projection = load_projection(composition.state_root(), operation_id)?;
    let fabric = restore_solo_fabric(composition, kernel, &projection)?;
    repersist_after_control(composition, &fabric, &mut projection)?;
    {
        let mut state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        state.live_operation = Some(projection.operation_id.clone());
    }
    solo_status(composition, operation_id)
}

/// Enqueues one validated solo intake for the runtime poll hook.
///
/// Bounded and memory-only: queued-but-undriven intakes are admission
/// offers, not obligations, so a shutdown drops them without reconciliation
/// and the producer re-offers after restart.
pub fn solo_enqueue(
    composition: &DaemonComposition,
    intake: SoloDelegateIntake,
    now_unix_ms: u64,
) -> Result<(), DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    let mut state = composition.solo_state.lock().map_err(|_| {
        DaemonError::Composition(CompositionError::Recovery(
            "solo driver state lock poisoned".to_owned(),
        ))
    })?;
    push_validated_intake(&mut state, intake, now_unix_ms)
}

/// Validates one intake and pushes it onto the driver queue (issue #2567 W2).
///
/// Pure queue half of [`solo_enqueue`]: intake shape, solo plan guard, and the
/// `SOLO_QUEUE_MAX_LEN` bound, with no readiness or composition touch, so the
/// queue-fill proof runs without a daemon composition. The readiness gate
/// stays in `solo_enqueue`.
pub(crate) fn push_validated_intake(
    state: &mut SoloDriverState,
    intake: SoloDelegateIntake,
    now_unix_ms: u64,
) -> Result<(), DaemonError> {
    intake
        .validate(now_unix_ms)
        .map_err(DaemonError::ProviderAdmission)?;
    guard_solo_plan(&intake.plan).map_err(DaemonError::ProviderAdmission)?;
    if state.queue.len() >= SOLO_QUEUE_MAX_LEN {
        return Err(DaemonError::ProviderAdmission(FabricError::Contract(
            "solo intake queue is full; backpressure instead of unbounded growth".to_owned(),
        )));
    }
    state.queue.push_back(intake);
    Ok(())
}

/// Test-only synchronous poll behavior. Production uses the async fail-closed
/// poll path below.
///
/// Bounded work per tick keeps control and shutdown pollable: an empty
/// queue idles without owner IO, a busy live slot waits without overlap,
/// and each drive is atomic with its projection persisted before emit.
#[cfg(test)]
pub fn solo_poll_queue(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
) -> Result<SoloPollOutcome, DaemonError> {
    if composition.readiness() != CompositionReadiness::Ready {
        return Err(DaemonError::Composition(CompositionError::NotReady));
    }
    let intake = {
        let mut state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        let Some(head) = state.queue.front().cloned() else {
            return Ok(SoloPollOutcome::Idle);
        };
        if let Some(live) = state.live_operation.as_ref()
            && live != &head.claimed.operation_id
        {
            return Ok(SoloPollOutcome::SlotBusy);
        }
        let Some(intake) = state.queue.pop_front() else {
            return Ok(SoloPollOutcome::Idle);
        };
        intake
    };
    let now_unix_ms = crate::unix_ms();
    let outcome = drive_solo_delegate(composition, kernel, intake, now_unix_ms)?;
    Ok(SoloPollOutcome::Drove {
        operation_id: outcome.operation_id,
        dispatch_id: outcome.dispatch_id,
    })
}

/// Async runtime poll hook. It leaves the head item queued when the verified
/// drive refuses or when the post-drive adopt recheck finds moved revisions,
/// preserving the exact operation for a later fresh evaluation.
///
/// Prepare/IO/adopt (issue #2567 AUD9/AUD10): the head intake is snapshotted
/// under a short `try_lock` and that guard is released before any await. The
/// verified drive then borrows the composition across the seam await because
/// the sole-path seam
/// ([`DaemonComposition::agent_fabric_new_verified_async`]) resolves the
/// session halves and verifies through the Kernel provider-admission
/// verifier on `&DaemonComposition`; invoking it without that borrow would
/// fork the closed admission path, so a prepare/adopt split of the seam
/// itself stays a lib.rs residual (see below). The poll flight stays
/// single-flighted (see `daemon_runtime`), so ticks never overlap a drive,
/// and the drive adopt plus the queue adopt below both revalidate the
/// consumed task/route/admission/fence revisions before adopting. Other
/// composition users queue on the mutex during the bounded seam await. Until
/// the owner ports bind, the drive refuses with the typed
/// missing-prerequisite residual and the head stays queued; a refusal is a
/// refusal, never a degraded drive.
pub async fn solo_poll_queue_async(
    composition: &tokio::sync::Mutex<DaemonComposition>,
    kernel: &Arc<DaemonKernelClient>,
) -> Result<SoloPollOutcome, DaemonError> {
    let intake = {
        let Ok(composition) = composition.try_lock() else {
            return Ok(SoloPollOutcome::SlotBusy);
        };
        if composition.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        let Some(head) = state.queue.front().cloned() else {
            return Ok(SoloPollOutcome::Idle);
        };
        if let Some(live) = state.live_operation.as_ref()
            && live != &head.claimed.operation_id
        {
            return Ok(SoloPollOutcome::SlotBusy);
        }
        head
    };
    // The expected revisions travel as an owned clone: the intake moves into
    // the drive below, and the queue adopt revalidates the live head against
    // this snapshot after the await.
    let expected = intake.clone();
    // Issue #1108 W4/A2: the runtime drive chain
    // (`run_loop` -> `solo_poll_queue_async` -> verified drive) enters the
    // async seam here with the driver's claimed halves. The composition
    // guard is held across this await: the seam needs `&DaemonComposition`
    // for the production ports, the session-half resolution, and the closed
    // capability construction, and the single live slot the drive adopts
    // must not move underneath it. Releasing this borrow across the owner
    // IO needs a prepare/adopt split of the seam itself
    // (`agent_fabric_new_verified_async` takes `&self` across its internal
    // verifier awaits), which lives in `lib.rs` and is out of this slice's
    // scope; the single-flighted poll flight bounds the hold to one drive.
    let outcome = {
        let composition = composition.lock().await;
        drive_solo_delegate_verified_async(&composition, kernel, intake, crate::unix_ms()).await?
    };
    // Queue adopt (issue #2567 AUD9): recheck the consumed revisions under a
    // short lock before dequeuing. The drive adopt already revalidated
    // post-seam; this closes the remaining window over the sync fabric
    // chain and persist, and binds the drive outcome to the consumed
    // material before the head leaves the queue. A head that left or moved
    // (task/route/admission), an outcome that addresses another
    // operation/attempt/binding, or a live fence/epoch that no longer binds
    // the consumed fence, refuses with a typed stale/conflict and the head
    // stays queued instead of dequeuing another operation's intake.
    {
        let composition = composition.lock().await;
        let live = kernel.kernel_fence();
        let mut state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        let Some(head) = state.queue.front() else {
            return Err(DaemonError::ProviderAdmission(
                FabricError::IdentityConflict(
                    "solo queue adopt refuses: head left during the verified drive".to_owned(),
                ),
            ));
        };
        if !intake_revisions_match(head, &expected) {
            return Err(DaemonError::ProviderAdmission(
                FabricError::IdentityConflict(
                    "solo queue adopt refuses a task, route, or admission moved during the verified drive"
                        .to_owned(),
                ),
            ));
        }
        if !fences_match_exact(&live, &expected.claimed.presented_fence) {
            return Err(DaemonError::ProviderAdmission(FabricError::StaleFence(
                "solo queue adopt refuses a fence moved during the verified drive".to_owned(),
            )));
        }
        let expected_epoch = &expected.claimed.expectation.live_authority_epoch;
        if !live.authority_epoch.is_same_authority(expected_epoch) {
            return Err(DaemonError::ProviderAdmission(FabricError::StaleEpoch(
                "solo queue adopt refuses an epoch moved during the verified drive".to_owned(),
            )));
        }
        // Queue adopt also binds the drive outcome to the consumed material:
        // an outcome that addresses another operation, attempt, or binding
        // refuses with a typed identity conflict instead of dequeuing (and
        // granting) this head's slot.
        if outcome.operation_id != expected.claimed.operation_id
            || outcome.attempt_id != expected.claimed.attempt_id
            || outcome.dispatch.binding_digest != expected.claimed.binding_digest
            || outcome.dispatch.executable_digest != expected.claimed.executable_digest
        {
            return Err(DaemonError::ProviderAdmission(
                FabricError::IdentityConflict(
                    "solo queue adopt refuses an outcome that does not bind the consumed material"
                        .to_owned(),
                ),
            ));
        }
        if head.claimed.operation_id == outcome.operation_id {
            state.queue.pop_front();
        }
    }
    Ok(SoloPollOutcome::Drove {
        operation_id: outcome.operation_id,
        dispatch_id: outcome.dispatch_id,
    })
}

/// Synchronous queue polling cannot perform authenticated owner IO. It
/// refuses without dequeuing the retained intake.
#[cfg(not(test))]
pub fn solo_poll_queue(
    _composition: &DaemonComposition,
    _kernel: &Arc<DaemonKernelClient>,
) -> Result<SoloPollOutcome, DaemonError> {
    Err(DaemonError::Kernel(
        "synchronous solo polling is disabled; use the async Kernel-verified poll entry point"
            .to_owned(),
    ))
}
