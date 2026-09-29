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
//! | `AdmissionAuthority` | [`SoloAdmissionAuthorityPort`] coordinates reservation/admission records | frozen definition digest, staffing receipt, live fence/epoch; coordinates, never owns |
//! | `ActivationAuthority` | [`SoloActivationAuthorityPort`] binds activation evidence | committed admission, attempt membership, live fence/epoch |
//! | `DispatchEgress` | [`SoloDispatchEgressPort`] retains the intent plus the claim-compatible binding | activated intent, persisted dispatch record, worker-claim single-flight identity |
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
//! Governor solo-admission seal remain future owner legs; their absence is
//! carried as documented follow-up, not as a silent substitution.
//!
//! # Pollability and durability
//!
//! The production queue poll snapshots its head under a short composition
//! lock, reads the full Governor binding and same-row ORS projection through
//! the authenticated Kernel path without holding that lock across the await,
//! then revalidates the row with Governor. Route/capacity currentness is not
//! available from the M1 owner record, so the poll returns a typed pending or
//! refusal before capability construction, activation, or dispatch. The
//! test-only historical dispatch projection is persisted under the daemon
//! state root before `emit`; uncertain ownership is never released without an
//! observed terminal disposition.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use eliot_agent_api::{AttemptId, RouteFingerprint};
use eliot_agent_coordinator::{AdmissionId, CandidateId, StaffingPlanRequest};
use eliot_contracts::{fences_match_exact, sha256_hex};
use serde::{Deserialize, Serialize};

use crate::agent_fabric::{
    ActivationAuthorityPort, ActivationEvidence, AdmissionAuthorityPort, AgentFabric, DispatchAck,
    DispatchEgressPort, DispatchIntent, FabricAdmission, FabricError, FabricSnapshot,
    PortBindingState, Reservation, RouteRequirements, SwarmDefinition, VerifiedProviderMaterial,
    daemon_coordinator_config,
};
#[cfg(test)]
use crate::agent_fabric::{FabricPorts, ModelRegistryPort};
use crate::daemon_kernel_client::DaemonKernelClient;
use crate::staffing_policy::{
    StaffingPlanReceipt, plan_coordinator_staffing, verify_receipt_digest,
};
use crate::{DaemonComposition, DaemonError};
use eliot_governor::{CompositionError, CompositionReadiness, RouteScopeFingerprint};

/// Solo recipe identity pinned by this slice (I10.15 first supported recipe).
pub const SOLO_RECIPE_ID: &str = "solo-verified-v1";
/// Accepted-interface revision reported by the solo model registry adapter.
#[cfg(test)]
pub const SOLO_MODEL_REGISTRY_REVISION: &str = "solo-model-registry/v1";
/// Accepted-interface revision reported by the solo admission adapter.
pub const SOLO_ADMISSION_AUTHORITY_REVISION: &str = "solo-admission-authority/v1";
/// Accepted-interface revision reported by the solo activation adapter.
pub const SOLO_ACTIVATION_AUTHORITY_REVISION: &str = "solo-activation-authority/v1";
/// Accepted-interface revision reported by the solo dispatch egress adapter.
pub const SOLO_DISPATCH_EGRESS_REVISION: &str = "solo-dispatch-egress/v1";
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
            // observes them; never read beforehand.
            live_fence: self.presented_fence.clone(),
            session_binding: String::new(),
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
    fn validate_shape(&self) -> Result<(), FabricError> {
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
        Ok(())
    }

    fn validate(&self, now_unix_ms: u64) -> Result<(), FabricError> {
        self.validate_shape()?;
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
/// Coordinates the staged reservation and committed admission records from
/// the verified solo context: definition digest and work class from the
/// frozen plan, capacity from the staffing receipt lane, fence/epoch
/// re-queried live per call. Record identities are deterministic
/// `solo-` derivations of the verified definition digest so exact replay
/// rebuilds the same record instead of minting a second operation.
#[derive(Clone)]
pub struct SoloAdmissionAuthorityPort {
    context: Arc<SoloVerifiedContext>,
    kernel: Arc<DaemonKernelClient>,
    staged: Arc<Mutex<BTreeMap<String, Reservation>>>,
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

    fn reservation_identity(definition_digest: &str) -> String {
        format!("solo-reservation-{definition_digest}")
    }

    fn admission_identity(definition_digest: &str) -> String {
        format!("solo-admission-{definition_digest}")
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
        let reservation = Reservation {
            reservation_id: Self::reservation_identity(&definition.definition_digest),
            definition_id: definition.definition_id.clone(),
            definition_digest: definition.definition_digest.clone(),
            work_class: definition.work_class,
            fence: definition.fence.clone(),
        };
        let mut guard = self
            .staged
            .lock()
            .map_err(|_| FabricError::Contract("solo staged lock poisoned".to_owned()))?;
        guard.insert(reservation.reservation_id.clone(), reservation.clone());
        Ok(reservation)
    }

    fn commit_admission(&self, reservation: &Reservation) -> Result<FabricAdmission, FabricError> {
        self.check_live()?;
        let guard = self
            .staged
            .lock()
            .map_err(|_| FabricError::Contract("solo staged lock poisoned".to_owned()))?;
        let stored = guard.get(&reservation.reservation_id).ok_or_else(|| {
            FabricError::StaleReservation(
                "solo admission refuses an unstaged reservation".to_owned(),
            )
        })?;
        if stored != reservation {
            return Err(FabricError::ReceiptBinding(
                "solo admission refuses a substituted reservation".to_owned(),
            ));
        }
        let admission_id =
            AdmissionId::new(Self::admission_identity(&reservation.definition_digest))?;
        Ok(FabricAdmission {
            admission_id,
            definition_id: reservation.definition_id.clone(),
            definition_digest: reservation.definition_digest.clone(),
            work_class: reservation.work_class,
            reservation_id: reservation.reservation_id.clone(),
            fence: reservation.fence.clone(),
            epoch: self.context.epoch.clone(),
            attempt_ids: vec![self.context.attempt_id.clone()],
        })
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::bound(SOLO_ADMISSION_AUTHORITY_REVISION.to_owned())
            .unwrap_or(PortBindingState::Uncertain)
    }
}

/// Solo Kernel activation authority adapter.
///
/// Binds activation evidence to the committed admission, the registered
/// attempt, and the live fence/epoch. The activation digest deterministically
/// binds admission, attempt, definition digest, fence, and epoch, so exact
/// replay reproduces the same evidence instead of minting fresh authority.
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
        let digest_input = serde_json::json!({
            "admission_id": admission.admission_id.as_str(),
            "attempt_id": attempt_id.as_str(),
            "definition_digest": self.context.definition_digest,
            "fence": self.context.fence,
            "epoch": self.context.epoch,
        });
        let bytes = eliot_contracts::canonical_json_bytes(&digest_input)
            .map_err(|error| contract(format!("solo activation digest bytes: {error}")))?;
        Ok(ActivationEvidence {
            admission_id: admission.admission_id.clone(),
            attempt_id: attempt_id.clone(),
            activation_digest: sha256_hex(&bytes),
            fence: self.context.fence.clone(),
            epoch: self.context.epoch.clone(),
        })
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::bound(SOLO_ACTIVATION_AUTHORITY_REVISION.to_owned())
            .unwrap_or(PortBindingState::Uncertain)
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
/// Retains the activated intent after the driver persisted the dispatch
/// projection: re-emission of the same dispatch identity returns the same
/// acknowledgement without a second effect, and an unknown identity refuses
/// instead of launching blindly.
#[derive(Clone)]
pub struct SoloDispatchEgressPort {
    context: Arc<SoloVerifiedContext>,
    kernel: Arc<DaemonKernelClient>,
    emitted: Arc<Mutex<BTreeMap<String, DispatchAck>>>,
}

impl DispatchEgressPort for SoloDispatchEgressPort {
    fn emit(&self, intent: &DispatchIntent) -> Result<DispatchAck, FabricError> {
        let mut guard = self
            .emitted
            .lock()
            .map_err(|_| FabricError::Contract("solo emitted lock poisoned".to_owned()))?;
        if let Some(ack) = guard.get(&intent.dispatch_id) {
            return Ok(ack.clone());
        }
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
        let ack = DispatchAck {
            dispatch_id: intent.dispatch_id.clone(),
            retained: true,
        };
        guard.insert(intent.dispatch_id.clone(), ack.clone());
        Ok(ack)
    }

    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::bound(SOLO_DISPATCH_EGRESS_REVISION.to_owned())
            .unwrap_or(PortBindingState::Uncertain)
    }
}

/// Derives the deterministic solo dispatch identity.
fn solo_dispatch_identity(attempt_id: &str, admission_id: &str) -> String {
    format!("solo-dispatch-{attempt_id}-{admission_id}")
}

/// Derives the deterministic solo cancellation identity.
#[cfg(test)]
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
    /// The requested Kernel claim exists but its Governor binding has not
    /// yet been published. The exact queue head remains available for retry.
    OwnerBindingPending {
        /// Claim identity selected by the retained queue head.
        claim_id: String,
        /// Attempt identity selected by the retained queue head.
        attempt_id: String,
        /// Operation identity selected by the retained queue head.
        operation_id: String,
        /// Task identity selected by the retained queue head.
        task_id: String,
        /// Kernel owner time at which the missing binding was observed.
        observed_at_unix_ms: u64,
    },
    /// Governor confirmed the retained binding, but current provider route
    /// and capacity revisions are not available from an independent owner.
    /// The exact queue head remains blocked before capability construction.
    ProviderRevisionsUnavailable {
        /// Claim identity selected by the retained queue head.
        claim_id: String,
        /// Attempt identity selected by the retained queue head.
        attempt_id: String,
        /// Operation identity selected by the retained queue head.
        operation_id: String,
        /// Task identity selected by the retained queue head.
        task_id: String,
        /// Kernel owner time at which the current binding was observed.
        observed_at_unix_ms: u64,
    },
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
            staged: Arc::new(Mutex::new(BTreeMap::new())),
        }),
        activation_authority: Arc::new(SoloActivationAuthorityPort {
            context: Arc::clone(&context),
            kernel: Arc::clone(kernel),
        }),
        dispatch_egress: Arc::new(SoloDispatchEgressPort {
            context: Arc::clone(&context),
            kernel: Arc::clone(kernel),
            emitted: Arc::new(Mutex::new(BTreeMap::new())),
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

fn load_projection(
    state_root: &std::path::Path,
    operation_id: &str,
) -> Result<SoloPersistedAttempt, DaemonError> {
    require_text(operation_id, "operation identity").map_err(DaemonError::ProviderAdmission)?;
    let path = solo_projection_path(state_root, operation_id);
    let lease = eliot_platform_windows::ProtectedRuntimePathLease::open_or_create_absolute(&path)
        .map_err(DaemonError::Protected)?;
    if lease.path() != path {
        return Err(DaemonError::Composition(CompositionError::Recovery(
            "solo projection path identity changed".to_owned(),
        )));
    }
    let bytes = lease
        .read_bounded(SOLO_PROJECTION_MAX_BYTES)
        .map_err(DaemonError::Protected)?;
    let file: SoloProjectionFile = serde_json::from_slice(&bytes).map_err(|error| {
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
    Ok(file.payload)
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

/// Performs plan-only validation for a direct solo intake. This entry does not
/// own a Governor composition borrow, so it cannot perform the exact owner
/// readback/currentness adoption used by the queue path. The legacy client
/// call is fail-closed and never sends caller-presented digests or revisions
/// as owner expectations.
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

    kernel
        .verify_provider_binding_async(&intake.claimed.material())
        .await
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;

    Err(DaemonError::ProviderAdmission(FabricError::Contract(
        "Kernel verified the claim binding, but the native-worker owner has no durable executable-binding digest for this claim; admitted provider capability and execution remain blocked"
            .to_owned(),
    )))
}

/// The synchronous solo path is retained only for unit tests. Production must
/// use [`drive_solo_delegate_async`] so Kernel verification never blocks the
/// current-thread daemon runtime.
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
#[cfg(test)]
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

#[cfg(not(test))]
fn restore_solo_fabric(
    _composition: &DaemonComposition,
    _kernel: &Arc<DaemonKernelClient>,
    _projection: &SoloPersistedAttempt,
) -> Result<AgentFabric, DaemonError> {
    Err(DaemonError::Kernel(
        "solo restore is blocked until Kernel retains an independently owner-verified executable-binding digest"
            .to_owned(),
    ))
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

/// Reads the attempt status under the same durable identity.
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
    solo_status(composition, operation_id)
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
    intake
        .validate(now_unix_ms)
        .map_err(DaemonError::ProviderAdmission)?;
    guard_solo_plan(&intake.plan).map_err(DaemonError::ProviderAdmission)?;
    let mut state = composition.solo_state.lock().map_err(|_| {
        DaemonError::Composition(CompositionError::Recovery(
            "solo driver state lock poisoned".to_owned(),
        ))
    })?;
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

/// Async runtime poll hook. It reads the authenticated Kernel owner record
/// without a composition guard, revalidates it with Governor under a short
/// synchronous borrow, then leaves the exact head queued whenever provider
/// route/capacity currentness is unavailable or an outcome needs reconciliation.
pub async fn solo_poll_queue_async(
    composition: &tokio::sync::Mutex<DaemonComposition>,
    kernel: &Arc<DaemonKernelClient>,
) -> Result<SoloPollOutcome, DaemonError> {
    let (intake, expected_kernel_fence) = {
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
        (head, kernel.kernel_fence())
    };
    intake
        .validate_shape()
        .map_err(DaemonError::ProviderAdmission)?;
    guard_solo_plan(&intake.plan).map_err(DaemonError::ProviderAdmission)?;

    // Kernel readback performs authenticated IPC with only owned tuple
    // selectors; the composition guard is intentionally absent across this
    // await. The returned payload is the full Governor binding and its same-row
    // ORS projection, never a reconstruction from `SoloClaimedHalves`.
    let task_id = intake.plan.launch.task_id.as_str();
    let readback = kernel
        .read_native_worker_executable_binding_async(
            &intake.claimed.claim_id,
            &intake.claimed.attempt_id,
            &intake.claimed.operation_id,
            task_id,
        )
        .await
        .map_err(|error| DaemonError::Kernel(error.to_string()))?;

    let observation = {
        let composition = composition.lock().await;
        if composition.readiness() != CompositionReadiness::Ready {
            return Err(DaemonError::Composition(CompositionError::NotReady));
        }
        let live_kernel_fence = kernel.kernel_fence();
        if !fences_match_exact(&expected_kernel_fence, &live_kernel_fence) {
            return Err(DaemonError::ProviderAdmission(FabricError::StaleFence(
                "Kernel fence changed while the solo binding readback was in flight".to_owned(),
            )));
        }
        let state = composition.solo_state.lock().map_err(|_| {
            DaemonError::Composition(CompositionError::Recovery(
                "solo driver state lock poisoned".to_owned(),
            ))
        })?;
        let Some(head) = state.queue.front() else {
            return Ok(SoloPollOutcome::SlotBusy);
        };
        if head.claimed.claim_id != intake.claimed.claim_id
            || head.claimed.attempt_id != intake.claimed.attempt_id
            || head.claimed.operation_id != intake.claimed.operation_id
            || head.plan.launch.task_id != intake.plan.launch.task_id
        {
            return Ok(SoloPollOutcome::SlotBusy);
        }
        drop(state);
        composition.validate_solo_native_worker_binding_readback(
            kernel,
            &intake.claimed.claim_id,
            &intake.claimed.attempt_id,
            &intake.claimed.operation_id,
            task_id,
            readback,
        )?
    };

    // The owner validator confirms Governor currentness using Kernel's
    // observed timestamp. M1 binding has no independently current route or
    // capacity revision, so both outcomes remain before capability
    // construction and the queue head is preserved for later reconciliation.
    match observation {
        eliot_governor::NativeWorkerBindingObservation::Pending {
            claim_id,
            attempt_id,
            operation_id,
            task_id,
            observed_at_unix_ms,
        } => Ok(SoloPollOutcome::OwnerBindingPending {
            claim_id,
            attempt_id,
            operation_id,
            task_id,
            observed_at_unix_ms,
        }),
        eliot_governor::NativeWorkerBindingObservation::GovernorCurrentButProviderRevisionsUnavailable {
            claim_id,
            attempt_id,
            operation_id,
            task_id,
            observed_at_unix_ms,
            ..
        } => Ok(SoloPollOutcome::ProviderRevisionsUnavailable {
            claim_id,
            attempt_id,
            operation_id,
            task_id,
            observed_at_unix_ms,
        }),
        eliot_governor::NativeWorkerBindingObservation::Revoked { .. } => {
            Err(DaemonError::ProviderAdmission(FabricError::Contract(
                "Governor reports the native-worker binding is revoked; the retained solo item remains blocked"
                    .to_owned(),
            )))
        }
        eliot_governor::NativeWorkerBindingObservation::UnknownOutcome { .. } => {
            Err(DaemonError::ProviderAdmission(FabricError::Contract(
                "Kernel reports an unknown native-worker binding outcome; exact reconciliation is required before retry"
                    .to_owned(),
            )))
        }
    }
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
