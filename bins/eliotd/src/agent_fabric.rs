//! Thin durable swarm-control composition for `eliotd` (issue #872).
//!
//! Architecture: I10.15 places deterministic planning plus Ready Queue admission
//! inside the daemon-owned [`AgentCoordinator`](eliot_agent_coordinator::AgentCoordinator);
//! this module is wiring, not a second scheduler, store, attempt journal,
//! authority source, or provider executor. It connects one admitted ingress
//! (`DaemonComposition::start` / `run_loop`) to exactly one injected
//! coordinator (definition validation, admission tracking, activation gating,
//! provider-neutral dispatch) and leaves every owner policy where it lives:
//! Task-Controller definitions, Governor admission, Kernel reservation and
//! activation, B-MOD route registry (#694), B-PEER coordination channel (#696),
//! and B-SWARM durable control (#698 / #839).
//!
//! The six injected ports are seams only. This module never reimplements route
//! ranking, peer delivery, swarm entry, reservation, admission, or activation;
//! each seam records its call in the daemon-owned call ledger so the 28-case
//! wiring proof can assert exact call order without inventing authority. Where
//! a prerequisite owner port has no accepted revision on this base (prereqs
//! #694 / #696 / #698 / #839 / #837 remain OPEN), the fabric stays generic
//! over the injected port and the inventory case freezes the missing-port
//! expectation as a `ContractChallenge` residual instead of a local substitute.
//!
//! Issue #1700 carries that inventory further without replacing it: each
//! injected port reports its own accepted-interface binding state through
//! [`PortBindingState`] (default [`PortBindingState::Uncertain` — no absence
//! conclusion follows from an open owning issue or a generic seam), and every
//! dependent entrypoint checks the port it actually needs before the owner
//! call. A port that reports [`PortBindingState::Missing`],
//! [`PortBindingState::Unavailable`], [`PortBindingState::Incompatible`] or
//! [`PortBindingState::StaleRevoked`] blocks only its dependent operations
//! with a typed [`MissingPortResidual`] (exact port, owner, state, blocked
//! operation/work, fence/epoch, disposition, next action) instead of a local
//! substitute. Plan-only planning, read-only observation, recovery/status and
//! independently admissible solo work never consult the broken port.
//!
//! Issue #1963 makes the capability-based staffing policy load-bearing on this
//! path instead of merely available. Every plan is bridged onto
//! [`crate::staffing_policy::plan_coordinator_staffing`], and the resulting
//! `StaffingPlanReceipt` is the only authority on which routes a plan may use:
//! the compiled candidate is held against it at
//! [`AgentFabric::define_and_plan`], the enforced receipt is retained and
//! persisted with the definition, and it is enforced again at the dispatch
//! boundary. An unavailable independent-audit class therefore carries an
//! explicit receipted escalate/defer disposition and can never be satisfied by
//! a silent same-family or paid substitute, and a mid-attempt provider switch
//! is refused unless an explicit receipted policy-authorized degradation was
//! recorded first. Route-class eligibility is bound to the request's own
//! declared route classes, so a class the request never bound a route to is
//! unstaffed and carries an explicit disposition rather than a candidate
//! borrowed from a neighbouring class. The selected Human preset, its cost
//! ceiling, and route-owner class/privacy evidence are bound into the canonical
//! receipt persisted with the definition.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Arc;

use eliot_agent_api::{AttemptId, RouteFingerprint};
use eliot_agent_bridge_core::ToolResultReceipt;
use eliot_agent_contracts::{
    ExecutionUpdateProposal, OldWaveDisposition, RevisionId, SupersessionLink, SwarmAdmissionId,
    SwarmCoordinatorLease, SwarmExecutionId, SwarmExecutionRevision, SwarmPlanAdmission,
    SwarmPlanAdmissionDisposition, SwarmPlanDefinition, SwarmPlanDefinitionLifecycle,
    SwarmPlanView, check_definition_author, check_execution_update, check_owner_join,
    check_stored_links, check_supersession, join_view, reassign_coordinator,
};
use eliot_agent_coordinator::{
    AdmissionId, AdmittedProviderCapability, AgentCoordinator, CandidateId, CoordinatorConfig,
    CoordinatorError, CoordinatorSnapshot, FairPullOutcome, PlanGap, ProviderBindingSnapshot,
    ProviderIdentity, ProviderSelectionHealth, SchedulingProfile, StaffingPlanCandidate,
    StaffingPlanRequest, SwarmDefinitionAdmissionPrep, WorkClass,
};
#[cfg(test)]
use eliot_agent_coordinator::{OwnerCurrentness, PresentedClaimMaterial};
use eliot_contracts::{EpochId, StateFence, fences_match_exact};
use eliot_kernel_service::ProviderCapabilityExpectation;
use eliot_store_api::{StoreError, SwarmOwnerRevision, WriteReceipt, WriteReceiptStatus};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::semantic_revision_store::{RecoveredSemanticRevisions, SemanticRevisionStore};
use crate::staffing_policy::{
    PolicyAuthorizedDegradation, StaffingPlanReceipt, check_attempt_route_continuity,
    enforce_plan_receipt, plan_coordinator_staffing, verify_receipt_digest,
};

/// Crate that owns the coordinated execution projection.
pub const COORDINATOR_CRATE: &str = "eliot-agent-coordinator";
/// Daemon composition root that owns this wiring.
pub const DAEMON_CRATE: &str = "eliotd";
/// Explicit plan-gap reason: the coordinator has no admitted G-11 provider
/// admission owner, and the human/brain-owned Task-Controller operation that
/// would drive this fabric from definition through admission, activation and
/// dispatch is not present, so candidate planning is the only reachable step.
pub const FABRIC_PLAN_GAP_REASON: &str = "eliotd agent fabric holds definition, admission, activation and dispatch capability but is entered with the G-11 plan gap: no admitted Task-Controller production operation drives this path and no sealed G-11 provider admission owner is present";
/// Capacity identity threaded by the daemon fabric composition.
pub const FABRIC_CAPACITY_IDENTITY: &str = "eliotd-fabric-capacity";
/// Capacity revision threaded by the daemon fabric composition.
pub const FABRIC_CAPACITY_REVISION: &str = "fabric-capacity-rev-1";
/// Prerequisite owner ports consumed read-only at accepted seams. All remain
/// OPEN on the base revision; the fabric injects them and never reimplements
/// them. See case 1 inventory.
pub const PREREQ_PORTS: [&str; 5] = [
    "B-MOD #694 model registry",
    "B-PEER #696 coordination channel",
    "B-SWARM #698 durable swarm control",
    "B-ACTIVATION-PROJECTION #839 activation projection",
    "D-WU-FINAL #837 assignment gate",
];

/// Returns the prerequisite owner ports consumed read-only at accepted seams.
#[must_use]
pub fn prereq_ports() -> Vec<String> {
    PREREQ_PORTS.iter().map(|port| (*port).to_owned()).collect()
}

/// Closed identity of one injected fabric port (issue #1700).
///
/// This is the runtime dependency map the fabric actually enforces: each
/// public entrypoint that needs a live owner guarantee names exactly one
/// port through [`FabricOperation::required_port`]. It is distinct from the
/// frozen [`PREREQ_PORTS`] string inventory above, which the 872/1 case pins
/// verbatim (including the D-WU-FINAL #837 development assignment gate).
/// #837 stays outside this map: it gates development assignment, never
/// runtime execution authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FabricPortId {
    /// B-MOD model registry (#694): route resolution only.
    ModelRegistry,
    /// B-PEER coordination channel (#696): peer delivery only.
    PeerChannel,
    /// B-SWARM durable swarm control (#698): swarm entry only.
    SwarmControl,
    /// Governor admission authority: reservation staging plus admission
    /// commit. The fabric composes both results and implements neither.
    AdmissionAuthority,
    /// Kernel activation authority (#839): launch activation only.
    ActivationAuthority,
    /// Dispatch egress: activated dispatch emission only.
    DispatchEgress,
}

impl FabricPortId {
    /// Returns the stable port code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ModelRegistry => "MODEL_REGISTRY",
            Self::PeerChannel => "PEER_CHANNEL",
            Self::SwarmControl => "SWARM_CONTROL",
            Self::AdmissionAuthority => "ADMISSION_AUTHORITY",
            Self::ActivationAuthority => "ACTIVATION_AUTHORITY",
            Self::DispatchEgress => "DISPATCH_EGRESS",
        }
    }

    /// Returns the stable load-bearing interface identity served by this port.
    #[must_use]
    pub const fn interface(self) -> &'static str {
        match self {
            Self::ModelRegistry => "b-mod-route-registry",
            Self::PeerChannel => "b-peer-coordination-channel",
            Self::SwarmControl => "b-swarm-durable-control",
            Self::AdmissionAuthority => "governor-admission-authority",
            Self::ActivationAuthority => "kernel-activation-authority",
            Self::DispatchEgress => "dispatch-egress",
        }
    }

    /// Returns the owning-contract reference for this port, which doubles as
    /// the development `ContractChallenge` surface key where applicable
    /// (I2.17). A static reference never confers execution authority; only
    /// a [`PortBindingState::Bound`] report from the injected port admits
    /// dependent use, and only the per-call owner verifier admits effects.
    #[must_use]
    pub const fn owner_ref(self) -> &'static str {
        match self {
            Self::ModelRegistry => "B-MOD #694",
            Self::PeerChannel => "B-PEER #696",
            Self::SwarmControl => "B-SWARM #698",
            Self::AdmissionAuthority => "governor-admission",
            Self::ActivationAuthority => "B-ACTIVATION-PROJECTION #839",
            Self::DispatchEgress => "dispatch-egress",
        }
    }
}

/// Runtime ports the fabric may block on (issue #1700): exactly the six
/// injected seams. D-WU-FINAL #837 is deliberately absent — it is a
/// development assignment gate, not a runtime service dependency, unless an
/// actual separately documented runtime contract requires it.
pub const RUNTIME_PORTS: [FabricPortId; 6] = [
    FabricPortId::ModelRegistry,
    FabricPortId::PeerChannel,
    FabricPortId::SwarmControl,
    FabricPortId::AdmissionAuthority,
    FabricPortId::ActivationAuthority,
    FabricPortId::DispatchEgress,
];

/// Returns the runtime port identities the fabric enforces.
#[must_use]
pub fn runtime_ports() -> Vec<FabricPortId> {
    RUNTIME_PORTS.to_vec()
}

/// How one injected port reports its own accepted-interface binding state
/// (issue #1700). Missing, unavailable, incompatible, stale/revoked and
/// uncertain stay distinct: only a positively reported non-bound state
/// blocks dependent use. An accepted interface (owner-validated revision
/// identity) stays distinct from a currently available/authorized provider —
/// availability is decided per call by the owner verifier, never here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum PortBindingState {
    /// The owner affirms an accepted interface binding at the named
    /// revision. Dependent use proceeds to the per-call owner verifier,
    /// which still decides. A nonempty revision, trait implementation,
    /// self-hash or serialized `Verified` snapshot cannot establish
    /// acceptance on its own: only the owner's affirmative report does,
    /// and only through this variant.
    Bound {
        /// Accepted interface revision affirmed by the owner.
        interface_revision: String,
    },
    /// The owner has no accepted revision for this interface.
    Missing,
    /// The owner is temporarily unreachable; carries no claim about
    /// acceptance either way.
    Unavailable,
    /// The owner observes an interface revision the fabric cannot consume.
    Incompatible {
        /// Interface revision the fabric requires.
        required_revision: String,
        /// Interface revision the owner observes.
        observed_revision: String,
    },
    /// The binding was accepted but is now stale or revoked by its owner.
    StaleRevoked,
    /// The port does not report binding state. The fabric draws no absence
    /// conclusion from this state and proceeds to the per-call owner
    /// verifier, which remains the authority. This is the default for every
    /// injected seam, so generic injection stays a seam, not a defect.
    Uncertain,
}

impl PortBindingState {
    /// Reports an owner-affirmed accepted binding. Blank or control-bearing
    /// revisions are rejected here: forged or empty acceptance evidence
    /// cannot pass as [`PortBindingState::Bound`].
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when the revision is blank or
    /// control-bearing.
    pub fn bound(interface_revision: String) -> Result<Self, FabricError> {
        validate_text(&interface_revision, "interface_revision")?;
        Ok(Self::Bound { interface_revision })
    }

    /// Reports an incompatible observed revision. Both revisions must be
    /// well-formed text; blank evidence cannot pass.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when either revision is blank or
    /// control-bearing.
    pub fn incompatible(
        required_revision: String,
        observed_revision: String,
    ) -> Result<Self, FabricError> {
        validate_text(&required_revision, "required_revision")?;
        validate_text(&observed_revision, "observed_revision")?;
        Ok(Self::Incompatible {
            required_revision,
            observed_revision,
        })
    }

    /// Returns true only when dependent use may proceed past the pre-check:
    /// [`PortBindingState::Bound`] proceeds to the per-call owner verifier,
    /// and [`PortBindingState::Uncertain`] defers to it entirely. Every
    /// other state blocks with a typed residual at the point of use.
    #[must_use]
    pub const fn admits_dependent_use(&self) -> bool {
        matches!(self, Self::Bound { .. } | Self::Uncertain)
    }
}

/// Stable I7.20 disposition carried by a missing-prerequisite residual.
/// The disposition is derived from the reported binding state; it never
/// widens into a generic internal error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResidualDisposition {
    /// The owner reports no accepted binding: further evidence is required.
    NeedsEvidence,
    /// The owner is unreachable: capacity/availability, not refusal.
    UnavailableOrCapacity,
    /// The observed revision cannot be consumed.
    Denied,
    /// The binding is stale or revoked.
    StaleOrConflict,
}

impl ResidualDisposition {
    /// Derives the disposition from the reported binding state. `Bound` and
    /// `Uncertain` never reach a residual; they map here only for
    /// completeness and keep the pre-check/refusal vocabulary closed.
    #[must_use]
    pub const fn of_state(state: &PortBindingState) -> Self {
        match state {
            PortBindingState::Missing => Self::NeedsEvidence,
            PortBindingState::Unavailable => Self::UnavailableOrCapacity,
            PortBindingState::Incompatible { .. } => Self::Denied,
            PortBindingState::StaleRevoked => Self::StaleOrConflict,
            PortBindingState::Bound { .. } | PortBindingState::Uncertain => {
                Self::UnavailableOrCapacity
            }
        }
    }

    /// Returns the stable disposition code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NeedsEvidence => "NEEDS_EVIDENCE",
            Self::UnavailableOrCapacity => "UNAVAILABLE_OR_CAPACITY",
            Self::Denied => "DENIED",
            Self::StaleOrConflict => "STALE_OR_CONFLICT",
        }
    }
}

/// Next permitted action carried by a missing-prerequisite residual. A
/// newly accepted owner binding permits reevaluation of the retained
/// operation under the current policy/fence; it never auto-activates old
/// candidates, resumes unknown attempts, or rewrites refusal evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NextPermittedAction {
    /// Restore the owner binding, then reevaluate the same retained
    /// operation under the current fence. Never mint a replacement
    /// identity and never implicitly retry: resolving the prerequisite
    /// requires a fresh normal evaluation, not a replay with new IDs.
    ReevaluateAfterOwnerAcceptance,
    /// The blocked delivery is optional: skip it. Independently valid
    /// solo/read-only work proceeds without the missing peer path.
    ProceedWithoutBlockedDelivery,
}

impl NextPermittedAction {
    /// Returns the stable action code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReevaluateAfterOwnerAcceptance => "REEVALUATE_AFTER_OWNER_ACCEPTANCE",
            Self::ProceedWithoutBlockedDelivery => "PROCEED_WITHOUT_BLOCKED_DELIVERY",
        }
    }
}

/// Fabric operation that may block on a missing prerequisite port
/// (issue #1700). Plan-only planning, read-only observation,
/// recovery/status/control reads and snapshot/restore carry no entry here:
/// they keep their own explicit dependency set and must not require the
/// broken execution port merely to explain or contain its failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FabricOperation {
    /// Candidate-only route resolution through the model registry.
    ResolveModelRoute,
    /// One peer delivery through the owning channel.
    DeliverPeer,
    /// Entry of one planned candidate through swarm control.
    EnterSwarm,
    /// Staging of one inactive Kernel reservation.
    StageReservation,
    /// Commit of one canonical Governor admission.
    CommitAdmission,
    /// Activation of launch authority for one admitted attempt.
    Activate,
    /// Emission of one built dispatch intent through the egress port.
    Emit,
}

impl FabricOperation {
    /// Returns the stable operation code.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ResolveModelRoute => "RESOLVE_MODEL_ROUTE",
            Self::DeliverPeer => "DELIVER_PEER",
            Self::EnterSwarm => "ENTER_SWARM",
            Self::StageReservation => "STAGE_RESERVATION",
            Self::CommitAdmission => "COMMIT_ADMISSION",
            Self::Activate => "ACTIVATE",
            Self::Emit => "EMIT",
        }
    }

    /// Returns the single injected port this operation depends on. A peer
    /// gap blocks only [`FabricOperation::DeliverPeer`]; every other
    /// operation names its own port, so an optional missing peer path never
    /// blocks an independently valid solo/read-only path.
    #[must_use]
    pub const fn required_port(self) -> FabricPortId {
        match self {
            Self::ResolveModelRoute => FabricPortId::ModelRegistry,
            Self::DeliverPeer => FabricPortId::PeerChannel,
            Self::EnterSwarm => FabricPortId::SwarmControl,
            Self::StageReservation | Self::CommitAdmission => FabricPortId::AdmissionAuthority,
            Self::Activate => FabricPortId::ActivationAuthority,
            Self::Emit => FabricPortId::DispatchEgress,
        }
    }

    /// Returns the next permitted action when this operation blocks. Only a
    /// blocked peer delivery is skippable; every other block retains the
    /// exact operation for reevaluation after owner acceptance.
    #[must_use]
    pub const fn next_permitted_action(self) -> NextPermittedAction {
        match self {
            Self::DeliverPeer => NextPermittedAction::ProceedWithoutBlockedDelivery,
            Self::ResolveModelRoute
            | Self::EnterSwarm
            | Self::StageReservation
            | Self::CommitAdmission
            | Self::Activate
            | Self::Emit => NextPermittedAction::ReevaluateAfterOwnerAcceptance,
        }
    }
}

/// Typed admission-blocking residual for an unresolved fabric port contract
/// (issue #1700).
///
/// Source-derived facts (the port's own report, the owner reference, the
/// fence/epoch observed at the failure) stay separate from unverified
/// expectations: the residual never claims the port is absent beyond what
/// the port itself reported, and it never confers execution authority.
/// Propagated through the daemon response/status path via
/// [`FabricError::MissingPrerequisite`] without string matching.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingPortResidual {
    /// Injected port that reported no accepted binding.
    pub port: FabricPortId,
    /// Stable load-bearing interface identity that is missing.
    pub interface: String,
    /// Owning-contract reference (I2.17 `ContractChallenge` surface key).
    pub owner_ref: String,
    /// Non-bound binding state the port reported. Never `Bound` or
    /// `Uncertain`: those admit dependent use and never build a residual.
    pub state: PortBindingState,
    /// Blocked fabric operation.
    pub blocked_operation: FabricOperation,
    /// Affected operation/work identity (definition, reservation,
    /// admission/attempt, dispatch, role, or message identity).
    pub work_identity: String,
    /// Fence observed at the failure, when the operation carries one.
    pub fence: Option<StateFence>,
    /// Authority epoch observed at the failure, when the operation carries one.
    pub epoch: Option<EpochId>,
    /// Stable I7.20 disposition derived from the binding state.
    pub disposition: ResidualDisposition,
    /// Next permitted action for the blocked work.
    pub next_action: NextPermittedAction,
}

impl MissingPortResidual {
    /// Builds the residual from the port's own binding report. The port must
    /// serve the blocked operation, the state must be a blocking one, and
    /// the work identity must be well-formed text.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when the state admits dependent
    /// use, the port does not serve the blocked operation, or the work
    /// identity is blank or control-bearing.
    pub fn new(
        port: FabricPortId,
        state: PortBindingState,
        blocked_operation: FabricOperation,
        work_identity: String,
        fence: Option<StateFence>,
        epoch: Option<EpochId>,
    ) -> Result<Self, FabricError> {
        if state.admits_dependent_use() {
            return Err(FabricError::Contract(
                "missing-prerequisite residual requires a blocking binding state".to_owned(),
            ));
        }
        if blocked_operation.required_port() != port {
            return Err(FabricError::Contract(
                "residual port does not serve the blocked operation".to_owned(),
            ));
        }
        validate_text(&work_identity, "blocked_work_identity")?;
        Ok(Self {
            port,
            interface: port.interface().to_owned(),
            owner_ref: port.owner_ref().to_owned(),
            disposition: ResidualDisposition::of_state(&state),
            next_action: blocked_operation.next_permitted_action(),
            state,
            blocked_operation,
            work_identity,
            fence,
            epoch,
        })
    }
}

impl fmt::Display for MissingPortResidual {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "port=[{}] interface=[{}] owner=[{}] state=[{}] op=[{}] work=[{}] disposition=[{}] next=[{}]",
            self.port.as_str(),
            self.interface,
            self.owner_ref,
            self.state,
            self.blocked_operation.as_str(),
            self.work_identity,
            self.disposition.as_str(),
            self.next_action.as_str(),
        )?;
        if let Some(fence) = &self.fence {
            write!(f, " fence=[{fence:?}]")?;
        }
        if let Some(epoch) = &self.epoch {
            write!(f, " epoch=[{epoch:?}]")?;
        }
        Ok(())
    }
}

impl fmt::Display for PortBindingState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bound { interface_revision } => {
                write!(f, "BOUND revision=[{interface_revision}]")
            }
            Self::Missing => write!(f, "MISSING"),
            Self::Unavailable => write!(f, "UNAVAILABLE"),
            Self::Incompatible {
                required_revision,
                observed_revision,
            } => write!(
                f,
                "INCOMPATIBLE required=[{required_revision}] observed=[{observed_revision}]"
            ),
            Self::StaleRevoked => write!(f, "STALE_REVOKED"),
            Self::Uncertain => write!(f, "UNCERTAIN"),
        }
    }
}

fn validate_text(value: &str, _field: &'static str) -> Result<(), FabricError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(FabricError::Contract(
            "blank or control-bearing text".to_owned(),
        ));
    }
    Ok(())
}

fn digest_json<T: Serialize>(value: &T) -> Result<String, FabricError> {
    let bytes = eliot_contracts::canonical_json_bytes(value)
        .map_err(|error| FabricError::Contract(format!("canonical bytes: {error}")))?;
    Ok(eliot_contracts::sha256_hex(&bytes))
}

/// Computes the frozen definition digest for one Task Controller-authored
/// staffing plan request (issue #2567).
///
/// Crate-internal: the solo driver binds its adapters to the exact frozen
/// bytes before fabric construction through this helper, so the fabric's own
/// `define_and_plan` records the identical digest for the identical request.
/// No second digest algorithm exists; this is the same canonical-JSON
/// SHA-256 the fabric uses.
///
/// # Errors
///
/// Returns [`FabricError::Contract`] when the request cannot be canonically
/// encoded.
#[cfg(test)]
pub(crate) fn frozen_definition_digest(
    request: &StaffingPlanRequest,
) -> Result<String, FabricError> {
    digest_json(request)
}

/// Deterministic daemon coordinator configuration for this composition.
///
/// # Errors
///
/// Returns [`FabricError::Contract`] when the static capacity revision is
/// rejected by its owner.
pub fn daemon_coordinator_config() -> Result<CoordinatorConfig, FabricError> {
    let capacity_revision = RevisionId::new(FABRIC_CAPACITY_REVISION)
        .map_err(|error| FabricError::Contract(format!("fabric capacity revision: {error}")))?;
    Ok(CoordinatorConfig {
        max_ready_items: 32,
        max_admitted_attempts: 8,
        max_active_per_route: 4,
        capacity_identity: FABRIC_CAPACITY_IDENTITY.to_owned(),
        capacity_revision,
    })
}

/// Authenticated Kernel claim material for one verified provider binding
/// (issue #1108, W4/A1/A2).
///
/// Two halves, resolved by the daemon composition per construction, per
/// restore, and per daemon operation resolution — never cached across live
/// fence changes:
///
/// - presented: the claim material as claimed by the operation at hand
///   (admission receipt refs, lane claim presentation), including the
///   operation fence and the claimed worker generation;
/// - owner: the currentness the daemon observed over its authenticated
///   Kernel session — the Governor currentness it holds
///   ([`ProviderCapabilityExpectation`]), the live fence it freshly
///   re-queried ([`DaemonKernelClient::kernel_fence`](crate::DaemonKernelClient::kernel_fence)),
///   and the Kernel-issued session binding it presented under
///   ([`OwnerSessionFacts::session_binding`](crate::OwnerSessionFacts::session_binding),
///   blank before the validated handshake, which fails closed).
///
/// M2 (#22): the supplier is Kernel over the authenticated front-door
/// session plus ORS operation records bound to the exact attempt; no new
/// signing or token service. Digest equality between the presented binding
/// digests and the durable ORS row is enforced Kernel-side per effecting
/// operation through the authenticated capability wire operation; the
/// capability construction below enforces presented-versus-owner coherence
/// (revisions, epoch, generation), and the sealed receipt from that wire
/// operation is the per-operation owner proof the executor applies before
/// touching the coordinator.
///
/// Evidence only, never authority: only [`AdmittedProviderCapability::new`]
/// plus [`AgentCoordinator::new_with_admitted_provider`] admit effects, and
/// every proof re-runs the T9-04 pure Kernel verifier. Carries no secret
/// material (identities, digests, revisions, fences, epoch, sequence only).
/// Catalogue, quota, and liveness observations (issue #265) ride only in
/// `health`: selection/health input, never admission.
#[derive(Clone, Debug)]
pub struct VerifiedProviderMaterial {
    /// Provider identity the binding must match exactly.
    pub identity: ProviderIdentity,
    /// Durable claim identity as claimed by the operation at hand.
    pub claim_id: String,
    /// Attempt identity as claimed by the operation at hand.
    pub attempt_id: String,
    /// Exact external-effect operation identity as claimed by the operation
    /// at hand.
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
    pub presented_fence: StateFence,
    /// Current Governor/Kernel expectation observed by the daemon.
    pub expectation: ProviderCapabilityExpectation,
    /// Live fence freshly re-queried by the daemon over its session.
    pub live_fence: StateFence,
    /// Kernel-issued session binding the daemon presented under.
    pub session_binding: String,
    /// Issue #265 selection/health observation, if any. Input only: never
    /// read by the verifier, never mints admission.
    pub health: Option<ProviderSelectionHealth>,
    /// Minimum replayed event sequence for restore.
    pub minimum_event_sequence: u64,
}

/// Builds the sealed admission capability from authenticated Kernel claim
/// material (issue #1108).
///
/// Crate-internal: the only cross-crate construction path is
/// [`DaemonComposition::agent_fabric_verified_capability`](crate::DaemonComposition::agent_fabric_verified_capability),
/// which unconditionally overwrites the caller-supplied session halves
/// (live fence, session binding) with the live authenticated session
/// values before calling this builder. External callers therefore cannot
/// bypass the session-half overwrite with coherent caller-built halves.
///
/// Wiring plus coherence: forwards the daemon-resolved
/// [`VerifiedProviderMaterial`] halves into the presented/owner capability
/// boundary, which fails closed on any presented-versus-owner disagreement
/// (route/capacity revision, authority epoch, resource generation) or owner
/// rejection (revoked, malformed, stale). The caller must supply a freshly
/// re-queried live fence and the validated session binding per call: a
/// blank binding (no live session) or a stale fence fails here, never at
/// first effect. Currency is re-checked on every coordinator `verify` call,
/// never cached.
///
/// # Errors
///
/// Returns the coordinator owner rejection unchanged (shape, coherence, or
/// stale/revoked binding).
#[cfg(test)]
pub(crate) fn build_admitted_provider_capability(
    material: VerifiedProviderMaterial,
) -> Result<AdmittedProviderCapability, FabricError> {
    let presented = PresentedClaimMaterial::new(
        material.claim_id,
        material.attempt_id,
        material.operation_id,
        material.binding_digest,
        material.executable_digest,
        material.route_revision,
        material.capacity_revision,
        material.worker_generation,
        material.presented_fence,
    )?;
    let currentness = OwnerCurrentness::new(
        material.expectation,
        material.live_fence,
        material.session_binding,
    )?;
    Ok(AdmittedProviderCapability::new(
        material.identity,
        presented,
        currentness,
        material.health,
        material.minimum_event_sequence,
    )?)
}

/// Plans one candidate through the real coordinator owner.
///
/// Load-bearing order is preserved here: the caller supplies an already-frozen
/// Task-Controller request and this function only compiles the deterministic
/// candidate via [`AgentCoordinator::plan`]. No admission, reservation,
/// attempt, or dispatch occurs here.
///
/// Issue #1963: the capability-based staffing policy is applied, not merely
/// available. The frozen request is bridged onto
/// [`plan_coordinator_staffing`] first, and the compiled candidate is then
/// held against the resulting [`StaffingPlanReceipt`] by
/// [`enforce_plan_receipt`]. A candidate that selected a route the receipt did
/// not staff for this task class — a same-family or paid stand-in for an
/// unavailable independent audit included — is refused here, before any
/// reservation, admission, activation or dispatch can observe it.
///
/// Route-class eligibility is bound to the route owner's classes intersected
/// with recipe, role, and launch declarations. The selected Human intent and
/// route-local privacy evidence are also bound into the canonical staffing
/// receipt enforced against the compiled candidate.
///
/// # Errors
///
/// Returns [`FabricError::Contract`] carrying the staffing-policy rejection
/// verbatim, or the coordinator owner rejection from [`AgentCoordinator::plan`].
pub fn plan_candidate(
    config: &CoordinatorConfig,
    request: StaffingPlanRequest,
) -> Result<StaffingPlanCandidate, FabricError> {
    // #740: candidate-planning span over the existing #872 control path.
    // Planning compiles a candidate only; admission happens exclusively
    // through the staged reservation + committed admission below.
    let _span = tracing::info_span!(
        "eliotd.fabric_plan_candidate",
        candidate = %crate::diagnostics::sanitize_identity(request.candidate_id.as_str())
    )
    .entered();
    let receipt =
        plan_coordinator_staffing(config, &request).map_err(|error| staffing_rejection(&error))?;
    let mut coordinator = AgentCoordinator::new(
        config.clone(),
        PlanGap::G11Unavailable {
            reason: FABRIC_PLAN_GAP_REASON.to_owned(),
        },
    )?;
    let candidate = coordinator.plan(request)?;
    enforce_plan_receipt(&receipt, &candidate).map_err(|error| staffing_rejection(&error))?;
    Ok(candidate)
}

/// Prepares one Task Controller-authored swarm definition for Governor
/// admission through the real coordinator owner (issue #1699).
///
/// Load-bearing order mirrors [`plan_candidate`]: the caller supplies an
/// already-authored `eliot_swarm::SwarmPlanProposal` plus the sealed P1
/// `eliot_swarm::SealedIndependentMaps`, and this function only compiles the
/// candidate-only admission preparation via
/// [`AgentCoordinator::prepare_swarm_definition_admission`]. No Governor
/// receipt is minted, no durable write occurs, and nothing is launched: the
/// prep carries the exact `swarm.plan.admit` provider request the Governor
/// admission port must seal, and launch stays with the existing injected
/// admission/activation/dispatch ports.
pub fn prepare_swarm_definition_admission_candidate(
    config: &CoordinatorConfig,
    proposal: &eliot_swarm::SwarmPlanProposal,
    maps: &eliot_swarm::SealedIndependentMaps,
) -> Result<SwarmDefinitionAdmissionPrep, FabricError> {
    let _span = tracing::info_span!("eliotd.fabric_prepare_swarm_definition_admission").entered();
    let coordinator = AgentCoordinator::new(
        config.clone(),
        PlanGap::G11Unavailable {
            reason: FABRIC_PLAN_GAP_REASON.to_owned(),
        },
    )?;
    Ok(coordinator.prepare_swarm_definition_admission(proposal, maps)?)
}

/// Frozen Task-Controller definition as accepted at the admitted boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmDefinition {
    /// Candidate identity minted by the Task Controller owner.
    pub definition_id: CandidateId,
    /// Digest of the exact frozen request bytes.
    pub definition_digest: String,
    /// I14.1 work class carried as the closed boundary type from the
    /// admitted request (issue #1698). The single `WorkClass` enum is owned
    /// by the coordinator crate and reused here; there is no second enum.
    /// Bound into every reservation, admission and dispatch built from this
    /// definition; never defaulted. The wire spelling stays the nine
    /// lowercase I14.1 strings via `WorkClass` serde.
    pub work_class: WorkClass,
    /// Task identity preserved verbatim.
    pub task_id: String,
    /// Task revision preserved verbatim.
    pub task_revision: String,
    /// Plan revision preserved verbatim.
    pub plan_revision: String,
    /// Admitted fence preserved verbatim.
    pub fence: StateFence,
}

/// Kernel-staged inactive reservation for the exact definition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reservation {
    /// Reservation identity minted by the Kernel owner.
    pub reservation_id: String,
    /// Definition this reservation stages.
    pub definition_id: CandidateId,
    /// Digest of the staged definition; must equal the frozen digest.
    pub definition_digest: String,
    /// I14.1 work class echoed from the staged definition (issue #1698) as
    /// the closed boundary type; the fabric rejects a reservation that does
    /// not bind the exact class.
    pub work_class: WorkClass,
    /// Fence at staging time.
    pub fence: StateFence,
}

/// Governor canonical admission referencing the staged reservation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricAdmission {
    /// Admission identity minted by the Governor owner.
    pub admission_id: AdmissionId,
    /// Admitted definition identity.
    pub definition_id: CandidateId,
    /// Exact frozen definition digest bound by this admission.
    pub definition_digest: String,
    /// I14.1 work class bound by this admission (issue #1698) as the closed
    /// boundary type; echoes the staged reservation and frozen definition
    /// exactly.
    pub work_class: WorkClass,
    /// Reservation identity this admission commits.
    pub reservation_id: String,
    /// Fence at admission time.
    pub fence: StateFence,
    /// Authority epoch at admission time.
    pub epoch: EpochId,
    /// Registered attempt identities for this admission.
    pub attempt_ids: Vec<AttemptId>,
}

/// Kernel activation evidence for one admitted attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActivationEvidence {
    /// Activated admission identity.
    pub admission_id: AdmissionId,
    /// Activated attempt identity.
    pub attempt_id: AttemptId,
    /// Digest binding the admission plus the Kernel activation receipt.
    pub activation_digest: String,
    /// Fence at activation time; must match admission exactly.
    pub fence: StateFence,
    /// Epoch at activation time; must match admission exactly.
    pub epoch: EpochId,
}

/// Provider-neutral externally dispatchable intent.
///
/// Carries the exact attempt plus activated launch evidence. It names no
/// provider SDK, process, credential, or effect commit; concrete execution
/// remains #874.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchIntent {
    /// Dispatch operation identity minted by this composition.
    pub dispatch_id: String,
    /// Admitted admission identity.
    pub admission_id: AdmissionId,
    /// Registered attempt identity.
    pub attempt_id: AttemptId,
    /// I14.1 work class carried as the closed boundary type from the
    /// admission (issue #1698), so the dispatch record identifies the same
    /// class.
    pub work_class: WorkClass,
    /// Activated launch evidence digest.
    pub activation_digest: String,
    /// Fence carried verbatim from activation.
    pub fence: StateFence,
    /// Epoch carried verbatim from activation.
    pub epoch: EpochId,
}

/// Closed acknowledgement of an emitted dispatch intent. It advances no
/// attempt and decides no task Finish.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DispatchAck {
    /// Dispatch operation acknowledged.
    pub dispatch_id: String,
    /// Whether the egress retained the exact intent bytes.
    pub retained: bool,
}

/// Provider-capability dispatch frame for one recorded dispatch intent
/// (issue #1108, W3).
///
/// Carries the exact operation (`dispatch_id`), attempt, and admitted
/// provider identity with the canonical payload digest of the recorded
/// intent. The provider identity is read from the coordinator's verified
/// binding, never caller-supplied; the payload digest is the canonical-JSON
/// SHA-256 of the recorded [`DispatchIntent`] through the existing
/// [`digest_json`] helper, never recomputed from caller bytes. The frame is
/// provider-dispatch evidence only and decides no task Finish.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderCapabilityDispatchFrame {
    /// Dispatch operation identity; keys the recorded intent.
    pub dispatch_id: String,
    /// Attempt the recorded intent dispatches.
    pub attempt_id: AttemptId,
    /// Exact admitted provider identity from the verified binding.
    pub provider_identity: ProviderIdentity,
    /// Canonical payload digest of the recorded intent.
    pub payload_digest: String,
    /// Fence carried verbatim from the recorded intent.
    pub fence: StateFence,
    /// Epoch carried verbatim from the recorded intent.
    pub epoch: EpochId,
}

/// Worker acknowledgement. Never attempt success.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerAck {
    /// Attempt acknowledged.
    pub attempt_id: AttemptId,
    /// Worker identity presenting the acknowledgement.
    pub worker_id: String,
}

/// Candidate attempt result. Never task Finish.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttemptResultRecord {
    /// Attempt this candidate result belongs to.
    pub attempt_id: AttemptId,
    /// Candidate output digest.
    pub result_digest: String,
}

/// Route requirements resolved through the injected B-MOD registry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRequirements {
    /// Role requesting a route.
    pub role: String,
    /// Required competence items.
    pub competence: Vec<String>,
}

impl RouteRequirements {
    fn validate(&self) -> Result<(), FabricError> {
        validate_text(&self.role, "route_role")?;
        if self.competence.is_empty() {
            return Err(FabricError::Contract(
                "route competence must not be empty".to_owned(),
            ));
        }
        for item in &self.competence {
            validate_text(item, "route_competence")?;
        }
        Ok(())
    }
}

/// Live peer message delivered through the injected B-PEER channel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerMessage {
    /// Message identity.
    pub message_id: String,
    /// Sending attempt.
    pub sender_attempt: AttemptId,
    /// Recipient attempt.
    pub recipient_attempt: AttemptId,
}

/// Peer delivery receipt from the owning channel.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerReceipt {
    /// Delivered message identity.
    pub message_id: String,
    /// Channel sequence assigned by the owner.
    pub channel_sequence: u64,
}

/// Swarm entry receipt from the owning B-SWARM control.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmEntryReceipt {
    /// Candidate identity entered.
    pub candidate_id: CandidateId,
    /// Digest of the entered candidate bytes; must equal the planned digest.
    pub entered_digest: String,
}

/// One ordered call-ledger entry for this composition.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEntry {
    /// Monotone sequence within this fabric instance.
    pub seq: u64,
    /// Stable event name (e.g. `coordinator_constructed`).
    pub event: String,
    /// Operation identity carried by the event.
    pub operation: String,
}

/// Typed dispositions. Every variant is load-bearing and distinct: collapsing
/// any two (e.g. narrowed vs needs-*, ack vs result, requested vs terminal
/// cancellation) is a composition error.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum FabricError {
    /// Daemon is not ready for swarm control.
    #[error("fabric not ready: {0}")]
    NotReady(String),
    /// Owner contract violation carrying the owner message.
    #[error("fabric contract: {0}")]
    Contract(String),
    /// Coordinator owner rejection, surfaced unchanged.
    #[error(transparent)]
    Coordinator(#[from] CoordinatorError),
    /// Same identity presented with different bytes.
    #[error("fabric definition conflict: {0}")]
    DefinitionConflict(String),
    /// Identity or revision interchange between definition, admission, and
    /// execution owners.
    #[error("fabric identity conflict: {0}")]
    IdentityConflict(String),
    /// Governor denied admission.
    #[error("fabric admission denied: {0}")]
    AdmissionDenied(String),
    /// Admission arrived incomplete and cannot run.
    #[error("fabric admission incomplete: {0}")]
    AdmissionIncomplete(String),
    /// Governor narrowed the proposal; the old definition cannot be rewritten
    /// or started.
    #[error("fabric narrowed: {0}")]
    Narrowed(String),
    /// Admission needs a revised task proposal from its owner.
    #[error("fabric needs task: {0}")]
    NeedsTask(String),
    /// Admission needs a revised scope proposal from its owner.
    #[error("fabric needs scope: {0}")]
    NeedsScope(String),
    /// Admission needs a revised source proposal from its owner.
    #[error("fabric needs source: {0}")]
    NeedsSource(String),
    /// Admission needs a revised capability proposal from its owner.
    #[error("fabric needs capability: {0}")]
    NeedsCapability(String),
    /// Admission needs a revised supervision proposal from its owner.
    #[error("fabric needs supervision: {0}")]
    NeedsSupervision(String),
    /// Presented fence is stale or mismatched.
    #[error("fabric stale fence: {0}")]
    StaleFence(String),
    /// Presented epoch is stale or mismatched.
    #[error("fabric stale epoch: {0}")]
    StaleEpoch(String),
    /// Reservation is stale, unknown, or already consumed.
    #[error("fabric stale reservation: {0}")]
    StaleReservation(String),
    /// Admission is stale, cancelled, or superseded.
    #[error("fabric stale admission: {0}")]
    StaleAdmission(String),
    /// Admission was cancelled before activation.
    #[error("fabric cancelled: {0}")]
    Cancelled(String),
    /// Admission was superseded by a newer revision.
    #[error("fabric superseded: {0}")]
    Superseded(String),
    /// No eligible route; typed outcome, never a local fallback.
    #[error("fabric no route: {0}")]
    NoRoute(String),
    /// Coordinator is unavailable for this operation.
    #[error("fabric coordinator unavailable: {0}")]
    CoordinatorUnavailable(String),
    /// Dispatch egress is unavailable; the registered operation is retained
    /// without duplicate launch or false success.
    #[error("fabric dispatch unavailable: {0}")]
    DispatchUnavailable(String),
    /// Dispatch was lost without retention; the original operation is
    /// preserved as unknown, never recomputed.
    #[error("fabric dispatch lost: {0}")]
    DispatchLost(String),
    /// Unknown child outcome; remains unknown and cannot satisfy Finish.
    #[error("fabric unknown child outcome: {0}")]
    UnknownChild(String),
    /// Orphan, foreign, or stale worker observation quarantined through
    /// existing supervision; it publishes no proof or effect.
    #[error("fabric quarantined: {0}")]
    Quarantined(String),
    /// A worker acknowledgement was presented where an attempt result was
    /// required; ack is never success.
    #[error("fabric ack is not result: {0}")]
    AckNotResult(String),
    /// An attempt result was presented where a task Finish decision was
    /// required; result is never Finish.
    #[error("fabric result is not finish: {0}")]
    ResultNotFinish(String),
    /// No activation evidence exists for this admission/attempt.
    #[error("fabric not activated: {0}")]
    NotActivated(String),
    /// A second initialization was attempted; exactly one coordinator exists.
    #[error("fabric already initialized: {0}")]
    AlreadyInitialized(String),
    /// Admission receipt does not bind the exact definition digest and
    /// reservation identity.
    #[error("fabric receipt binding: {0}")]
    ReceiptBinding(String),
    /// A second launch was attempted for an already-registered operation.
    #[error("fabric duplicate launch: {0}")]
    DuplicateLaunch(String),
    /// An execution update attempted to change frozen plan semantics
    /// (work graph, objective, acceptance, ceilings, stop conditions, wave
    /// or root). Semantic change needs a new definition revision, never an
    /// execution update.
    #[error("fabric semantic drift: {0}")]
    SemanticDrift(String),
    /// The presenter is not the current owner lease holder or epoch.
    #[error("fabric stale owner lease: {0}")]
    StaleOwnerLease(String),
    /// The caller attempted another owner's fields.
    #[error("fabric foreign owner field: {0}")]
    ForeignOwnerField(String),
    /// The definition/admission/execution ownership join is broken.
    #[error("fabric broken ownership link: {0}")]
    BrokenOwnershipLink(String),
    /// A revision was presented for reporting as current without the canonical
    /// Store transaction that durably persists it. The typed Store refusal
    /// rides unchanged; the revision is never published from an uncommitted or
    /// unknown write (issue #1702 W2, I1.8 canonical write path).
    #[error("fabric revision not durable: {0}")]
    RevisionNotDurable(StoreError),
    /// Cancellation was requested but its terminal reconciliation has not been
    /// observed; the two remain distinct.
    #[error("fabric cancellation requested: {0}")]
    CancellationRequested(String),
    /// Terminal cancellation was observed for a previously requested
    /// operation.
    #[error("fabric terminal cancellation: {0}")]
    TerminalCancellation(String),
    /// The snapshot carries a verified provider binding but no fresh owner
    /// material was supplied. Restore stays blocked: re-resolve live
    /// evidence through [`AgentFabric::restore_verified`]. A serialized
    /// `Verified` label alone never restores effecting readiness, and
    /// missing/stale/revoked evidence never downgrades silently to a
    /// plan-only restore masquerading as recovery.
    #[error(
        "fabric restore blocked: snapshot holds a verified provider binding; supply fresh owner material through restore_verified"
    )]
    ProviderEvidenceRequired,
    /// An owner-separated revision could not be proven durable, so it is
    /// never reported as current (issue #1702 W2).
    ///
    /// The ordering guarantee is: a definition, admission or execution
    /// revision becomes readable as current only after its durable write
    /// commits and verifies. When that write is unproven — the protected
    /// lease cannot be held, the envelope exceeds its bound, the write
    /// fails, or the readback does not match — the revision is not published
    /// in memory either, and the caller sees this typed failure instead of a
    /// revision a crash could erase. Failure may temporarily withhold a
    /// revision; it never grants an unrecorded one.
    #[error("fabric durability unproven: {0}")]
    DurabilityUnproven(String),
    /// Restart recovery could not rehydrate the owner-separated history, so
    /// recovery stays explicitly BLOCKED (issue #1702 W6).
    ///
    /// This is not an empty new plan. A committed owner revision that is
    /// missing its immutable content, a torn persistence boundary, a
    /// contradictory pair of stored records, or a snapshot whose links
    /// disagree with the records they point at all land here: the operator
    /// sees a blocked recovery with the exact cause instead of a fabric that
    /// silently starts over on empty maps. Nothing in this state is
    /// reportable as current authority, and no new revision may be published
    /// until the retained history is repaired or the affected owner
    /// dispositioned by its owner.
    #[error("fabric semantic recovery blocked: {0}")]
    SemanticRecoveryBlocked(String),
    /// A load-bearing injected port reports no accepted interface binding
    /// for the blocked operation (issue #1700). The boxed residual names
    /// the exact port, owner, binding state, blocked operation/work,
    /// fence/epoch, disposition and next permitted action. Boxed: the
    /// residual rides every fallible fabric boundary, so the error itself
    /// stays small.
    #[error("missing prerequisite: {0}")]
    MissingPrerequisite(Box<MissingPortResidual>),
}

/// Maps a semantic contract rejection onto the fabric vocabulary.
///
/// Owner-identity failures keep their typed meaning (`SemanticDrift`,
/// `StaleOwnerLease`, `ForeignOwnerField`, `BrokenOwnershipLink`); all other
/// contract failures surface as [`FabricError::Contract`]. The mapping is
/// total: no contract rejection escapes unclassified.
fn contract_rejection(error: eliot_agent_contracts::ContractError) -> FabricError {
    use eliot_agent_contracts::ContractError as ContractRejection;
    match error {
        ContractRejection::SemanticDrift(field) => FabricError::SemanticDrift(field.to_owned()),
        ContractRejection::StaleLease(owner) => FabricError::StaleOwnerLease(owner.to_owned()),
        ContractRejection::ForeignOwner(field) => FabricError::ForeignOwnerField(field.to_owned()),
        ContractRejection::BrokenOwnershipLink(link) => {
            FabricError::BrokenOwnershipLink(link.to_owned())
        }
        other => FabricError::Contract(format!("semantic contract: {other}")),
    }
}

/// Requires the canonical Store transaction that durably persists one
/// owner-separated revision, before that revision may be published as current
/// (issue #1702 W2, I1.8 canonical write path).
///
/// The in-memory owner maps this module reports through
/// [`AgentFabric::semantic_join_view`] and [`AgentFabric::snapshot`] are a
/// projection, not an authority: publishing into them is the "report as
/// current" step, so the durable write has to be complete first. This gate is
/// what makes the ordering non-invertible — the caller cannot obtain the
/// [`WriteReceipt`] without the Store having committed the record, its
/// compare-and-set head and the outbox row in one transaction, and a revision
/// with no such receipt is refused rather than published. A crash between the
/// commit and the publish leaves the durable record present and the projection
/// merely absent, which recovery reconstructs; the reverse order would leave a
/// reader believing in a revision that does not exist.
///
/// The binding is the receipt's own ordering head, not a caller label: the
/// receipt must be `Committed` under
/// [`eliot_store_api::TransitionClass::TaskControl`] and must carry the head
/// for exactly this owner stream at exactly this revision, so a receipt for
/// another owner or an earlier revision of this one cannot authorize a
/// different record. The record's own bytes, digest and expected-predecessor
/// progression are re-checked through [`SwarmOwnerRevision::validate`], the
/// existing Store contract — never re-derived here.
///
/// `record` is the semantic record the caller wants published, as its JSON
/// value. [`SwarmOwnerRevision::validate`] has already established that
/// `record_json` is the canonical encoding and that `content_digest` binds
/// those exact bytes, so comparing the decoded value here is an exact
/// comparison of the committed content: the published revision is the revision
/// the Store holds, not one that merely shares its identity and revision
/// number.
///
/// # Errors
///
/// Returns [`FabricError::RevisionNotDurable`] carrying the typed
/// [`StoreError`] when the owner revision is malformed, when it does not carry
/// `record` verbatim, or when the receipt is absent, non-committed, of another
/// transition class, or bound to another owner stream or revision.
fn require_durable_owner_revision(
    owner_revision: &SwarmOwnerRevision,
    receipt: &WriteReceipt,
    record: &serde_json::Value,
) -> Result<(), FabricError> {
    owner_revision
        .validate()
        .map_err(FabricError::RevisionNotDurable)?;
    if serde_json::from_str::<serde_json::Value>(&owner_revision.record_json)
        .ok()
        .as_ref()
        != Some(record)
    {
        return Err(FabricError::RevisionNotDurable(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: "committed owner record does not bind the presented revision bytes",
        }));
    }
    receipt
        .validate()
        .map_err(FabricError::RevisionNotDurable)?;
    if receipt.status != WriteReceiptStatus::Committed {
        return Err(FabricError::RevisionNotDurable(StoreError::InvalidReceipt));
    }
    if receipt.transition_class != eliot_store_api::TransitionClass::TaskControl {
        return Err(FabricError::RevisionNotDurable(StoreError::InvalidField {
            field: "swarm.receipt.transition_class",
            reason: "owner revisions commit under the task-control class",
        }));
    }
    let scope = owner_revision
        .ordering_scope()
        .map_err(FabricError::RevisionNotDurable)?;
    let head = receipt
        .ordering_sequences
        .iter()
        .find(|head| head.scope == scope)
        .ok_or(FabricError::RevisionNotDurable(StoreError::InvalidField {
            field: "swarm.receipt.ordering_sequences",
            reason: "receipt does not carry the presented owner stream",
        }))?;
    if head.sequence != owner_revision.revision {
        return Err(FabricError::RevisionNotDurable(StoreError::InvalidField {
            field: "swarm.receipt.ordering_sequences",
            reason: "receipt commits another revision of the presented owner stream",
        }));
    }
    Ok(())
}

/// Maps a staffing-policy rejection onto the fabric vocabulary (issue #1963).
///
/// A plan the capability-based staffing policy cannot staff is a contract
/// violation of this composition: the plan receipt is the only authority on
/// which routes a task class may use, and an unstaffable plan never becomes a
/// candidate. The owner message is carried verbatim so the receipted
/// defer/degrade/escalate reason stays readable at the refusal.
///
/// A dedicated `FabricError` variant would also need an arm in
/// `crate::diagnostics::rejection_of`, which is not this change's writer, so
/// the existing `Contract` variant carries the rejection.
fn staffing_rejection(error: &crate::staffing_policy::StaffingPolicyError) -> FabricError {
    FabricError::Contract(format!("staffing plan receipt: {error}"))
}

/// Verifies semantic ownership maps carried by a durable snapshot.
///
/// Every stored definition revalidates (shape plus bound digest); every map
/// key must equal its record identity; every stored execution must satisfy
/// the structural ownership links against its stored definition and
/// admission; every supersession link must join its stored prior and
/// replacement, and every replacement chain must stay acyclic so one current
/// authority always resolves. Every stored staffing plan receipt must still
/// bind its own body. Legacy snapshots carry no semantic records and no
/// staffing receipts and pass trivially. A contradictory image fails closed so
/// torn persistence never restores authority.
///
/// This function verifies the STORED SEMANTIC MAPS only. It does not rehydrate
/// live coherence: nothing re-derives leases or active dispositions from this
/// snapshot after restore, so a saved `Verified` or `Active` label is evidence
/// about the stored record and never about a live lease. A caller that needs
/// live authority must re-resolve it from its own owner.
fn verify_snapshot_semantics(snapshot: &FabricSnapshot) -> Result<(), FabricError> {
    // Issue #1963: a restored staffing plan receipt is only usable while it
    // still binds its own body, so a tampered or torn persisted receipt refuses
    // the restore instead of becoming the authority on dispatchable routes.
    for receipt in snapshot.staffing_receipts.values() {
        verify_receipt_digest(receipt).map_err(|error| staffing_rejection(&error))?;
    }
    verify_semantic_record_set(
        &snapshot.semantic_definitions,
        &snapshot.semantic_admissions,
        &snapshot.semantic_executions,
        &snapshot.semantic_supersessions,
    )
}

/// Verifies one owner-separated record set as strictly as fresh admission
/// (issue #1702 W6).
///
/// This is the single strictness gate both the snapshot restore and the reopen
/// of real storage run, so a recovered record set is never held to a weaker
/// standard than a freshly admitted one. It verifies, over the four owner maps
/// alone:
///
/// 1. every definition revalidates (shape plus its bound content digest) and
///    its map key equals its own record identity — map key versus record
///    identity is checked, never assumed;
/// 2. every admission revalidates, binds exactly one stored frozen definition
///    with narrowed (never widened) ceilings, and no definition has two
///    conflicting stored admissions (duplicate reverse-index mapping);
/// 3. every execution revalidates, its map key equals its identity, and it
///    satisfies the structural ownership links against its stored definition
///    and admission;
/// 4. every supersession link joins its stored prior and replacement, matches
///    the replacement's own carried link, and the whole chain stays acyclic so
///    one current authority always resolves.
///
/// Recovered cross-record INDEXES are rebuilt from these records as
/// projections rather than accepted from any supplied reverse link; the only
/// reverse mapping consulted is each record's own embedded link, which must
/// agree with the record it points at. A missing record or any contradiction
/// fails closed, so torn persistence or a contradictory snapshot restores
/// nothing.
///
/// This function verifies the STORED RECORD SET only. It does not rehydrate
/// live coherence: nothing here re-derives a lease, an active disposition or
/// an open process, so a saved `Verified`/`Active` label is evidence about the
/// stored record and never about a live lease. A caller that needs live
/// authority must re-resolve it from its own owner.
fn verify_semantic_record_set(
    definitions: &BTreeMap<String, SwarmPlanDefinition>,
    admissions: &BTreeMap<String, SwarmPlanAdmission>,
    executions: &BTreeMap<String, SwarmExecutionRevision>,
    supersessions: &BTreeMap<String, SupersessionLink>,
) -> Result<(), FabricError> {
    for (key, definition) in definitions {
        definition.validate().map_err(contract_rejection)?;
        if key != definition.definition_id.as_str() {
            return Err(FabricError::BrokenOwnershipLink(
                "semantic definition map key does not match record identity".to_owned(),
            ));
        }
    }
    verify_record_set_admissions(definitions, admissions)?;
    for (key, execution) in executions {
        execution.validate().map_err(contract_rejection)?;
        if key != execution.execution_id.as_str() {
            return Err(FabricError::BrokenOwnershipLink(
                "semantic execution map key does not match record identity".to_owned(),
            ));
        }
        let definition = definitions
            .get(execution.definition_id.as_str())
            .ok_or_else(|| {
                FabricError::BrokenOwnershipLink(
                    "semantic execution without stored definition".to_owned(),
                )
            })?;
        let admission = admissions
            .get(execution.admission_id.as_str())
            .ok_or_else(|| {
                FabricError::BrokenOwnershipLink(
                    "semantic execution without stored admission".to_owned(),
                )
            })?;
        check_stored_links(definition, admission, execution).map_err(contract_rejection)?;
    }
    for (key, link) in supersessions {
        let next = definitions.get(key).ok_or_else(|| {
            FabricError::BrokenOwnershipLink(
                "supersession without stored replacement definition".to_owned(),
            )
        })?;
        let prior = definitions
            .get(link.prior_definition_id.as_str())
            .ok_or_else(|| {
                FabricError::BrokenOwnershipLink(
                    "supersession without stored prior definition".to_owned(),
                )
            })?;
        if next.supersedes.as_ref() != Some(link) {
            return Err(FabricError::BrokenOwnershipLink(
                "supersession link does not match stored replacement".to_owned(),
            ));
        }
        check_supersession(prior, next).map_err(contract_rejection)?;
    }
    check_record_set_supersession_chains(supersessions)
}

/// Rejects cyclic replacement chains in an owner-separated record set.
///
/// Each link is valid on its own, but a cycle (A supersedes B while B
/// transitively supersedes A) orders no current authority: revision order
/// must stay a DAG. The walk follows prior links from every replacement; a
/// revisited replacement is contradictory history and restores nothing.
fn check_record_set_supersession_chains(
    supersessions: &BTreeMap<String, SupersessionLink>,
) -> Result<(), FabricError> {
    for start in supersessions.keys() {
        let mut visited = BTreeSet::new();
        let mut current = start.as_str();
        while let Some(link) = supersessions.get(current) {
            if !visited.insert(current) {
                return Err(FabricError::BrokenOwnershipLink(
                    "semantic supersession chain is cyclic".to_owned(),
                ));
            }
            current = link.prior_definition_id.as_str();
        }
    }
    Ok(())
}

/// Revalidates every persisted semantic admission against its immutable
/// definition while retaining valid terminal dispositions as history.
fn verify_record_set_admissions(
    definitions: &BTreeMap<String, SwarmPlanDefinition>,
    admissions: &BTreeMap<String, SwarmPlanAdmission>,
) -> Result<(), FabricError> {
    let mut admission_by_definition = BTreeMap::new();
    for (key, admission) in admissions {
        admission.validate().map_err(contract_rejection)?;
        if key != admission.admission_id.as_str() {
            return Err(FabricError::BrokenOwnershipLink(
                "semantic admission map key does not match record identity".to_owned(),
            ));
        }
        if admission_by_definition
            .insert(admission.definition_id.as_str(), key.as_str())
            .is_some()
        {
            return Err(FabricError::DefinitionConflict(format!(
                "semantic definition {} has conflicting stored admissions",
                admission.definition_id.as_str()
            )));
        }
        let definition = definitions
            .get(admission.definition_id.as_str())
            .ok_or_else(|| {
                FabricError::BrokenOwnershipLink(
                    "semantic admission without stored definition".to_owned(),
                )
            })?;
        if definition.lifecycle == SwarmPlanDefinitionLifecycle::Draft
            || !admission.binds(definition)
        {
            return Err(FabricError::BrokenOwnershipLink(
                "semantic admission does not bind its frozen definition".to_owned(),
            ));
        }
        if !admission
            .admitted_ceilings
            .narrowed_from(&definition.ceilings)
        {
            return Err(FabricError::SemanticDrift(
                "stored semantic admission widens definition ceilings".to_owned(),
            ));
        }
        match (definition.lifecycle, admission.disposition) {
            (
                SwarmPlanDefinitionLifecycle::Superseded,
                SwarmPlanAdmissionDisposition::Superseded
                | SwarmPlanAdmissionDisposition::Cancelled,
            )
            | (SwarmPlanDefinitionLifecycle::Cancelled, SwarmPlanAdmissionDisposition::Cancelled)
            | (SwarmPlanDefinitionLifecycle::Frozen, _) => {}
            _ => {
                return Err(FabricError::BrokenOwnershipLink(
                    "semantic admission disposition contradicts definition lifecycle".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// Verifies recorded provider-frame and tool-result evidence still binds
/// its recorded dispatch operation (issue #1108, W3/A12 restore gate).
///
/// Every frame must key the recorded intent it was built from with the same
/// attempt, fence, and epoch carried verbatim; the payload digest is the
/// recorded value and is never recomputed here. Every tool result must key a
/// recorded intent, and the recorded receipt re-runs the bridge owner's
/// complete-evidence gate on its original value. Orphan or rebound evidence
/// fails closed instead of restoring detached history.
fn verify_snapshot_tool_evidence(snapshot: &FabricSnapshot) -> Result<(), FabricError> {
    for (dispatch_id, frame) in &snapshot.provider_frames {
        let intent = snapshot.intents.get(dispatch_id).ok_or_else(|| {
            FabricError::ReceiptBinding(format!(
                "provider capability frame {dispatch_id} binds no recorded dispatch"
            ))
        })?;
        if frame.dispatch_id != *dispatch_id
            || frame.attempt_id != intent.attempt_id
            || !fences_match_exact(&frame.fence, &intent.fence)
            || frame.epoch != intent.epoch
        {
            return Err(FabricError::ReceiptBinding(format!(
                "provider capability frame {dispatch_id} no longer binds its recorded dispatch"
            )));
        }
    }
    for (dispatch_id, receipt) in &snapshot.tool_results {
        if !snapshot.intents.contains_key(dispatch_id) {
            return Err(FabricError::ReceiptBinding(format!(
                "tool result {dispatch_id} binds no recorded dispatch"
            )));
        }
        receipt
            .check_complete_evidence()
            .map_err(|error| FabricError::Contract(format!("tool result evidence: {error}")))?;
    }
    Ok(())
}

/// Reconstructs the definition-to-admission cache from committed owner
/// records, rejecting torn or contradictory joins instead of allowing map
/// insertion to choose one admission silently.
fn rebuild_admission_by_definition(
    snapshot: &FabricSnapshot,
) -> Result<BTreeMap<String, String>, FabricError> {
    let mut admission_by_definition = BTreeMap::new();

    for (key, definition) in &snapshot.definitions {
        if key != definition.definition_id.as_str() {
            return Err(FabricError::BrokenOwnershipLink(
                "definition map key does not match record identity".to_owned(),
            ));
        }
    }

    for (key, reservation) in &snapshot.reservations {
        if key != &reservation.reservation_id {
            return Err(FabricError::BrokenOwnershipLink(
                "reservation map key does not match record identity".to_owned(),
            ));
        }
        let definition = snapshot
            .definitions
            .get(reservation.definition_id.as_str())
            .ok_or_else(|| {
                FabricError::BrokenOwnershipLink("reservation without stored definition".to_owned())
            })?;
        if reservation.definition_id != definition.definition_id
            || reservation.definition_digest != definition.definition_digest
            || reservation.work_class != definition.work_class
        {
            return Err(FabricError::ReceiptBinding(
                "stored reservation does not bind its exact definition".to_owned(),
            ));
        }
    }

    for (key, admission) in &snapshot.admissions {
        if key != admission.admission_id.as_str() {
            return Err(FabricError::BrokenOwnershipLink(
                "admission map key does not match record identity".to_owned(),
            ));
        }
        let definition_key = admission.definition_id.as_str();
        let definition = snapshot.definitions.get(definition_key).ok_or_else(|| {
            FabricError::BrokenOwnershipLink("admission without stored definition".to_owned())
        })?;
        if admission.definition_id != definition.definition_id
            || admission.definition_digest != definition.definition_digest
            || admission.work_class != definition.work_class
        {
            return Err(FabricError::ReceiptBinding(
                "stored admission does not bind its exact definition".to_owned(),
            ));
        }
        let reservation = snapshot
            .reservations
            .get(&admission.reservation_id)
            .ok_or_else(|| {
                FabricError::BrokenOwnershipLink("admission without stored reservation".to_owned())
            })?;
        if admission.reservation_id != reservation.reservation_id
            || admission.definition_id != reservation.definition_id
            || admission.definition_digest != reservation.definition_digest
            || admission.work_class != reservation.work_class
            || admission.fence != reservation.fence
        {
            return Err(FabricError::ReceiptBinding(
                "stored admission does not bind its exact reservation".to_owned(),
            ));
        }
        if admission_by_definition
            .insert(definition_key.to_owned(), key.clone())
            .is_some()
        {
            return Err(FabricError::DefinitionConflict(format!(
                "definition {definition_key} has conflicting stored admissions"
            )));
        }
    }

    Ok(admission_by_definition)
}

/// Rehydrates the owner-separated semantic record set from real durable storage
/// on reopen (issue #1702 W6, A5).
///
/// This is the missing recovery leg: the write path commits the owner-separated
/// revisions through [`SemanticRevisionStore::commit`], and this reads the same
/// committed bytes back so a restarted daemon restores the retained history of
/// all three owners instead of starting over on empty maps.
///
/// The recovered set is validated as strictly as fresh admission through
/// [`verify_semantic_record_set`]: map key versus record identity, full
/// definition digest, admission-to-definition binding with narrowed ceilings,
/// execution-to-admission structural links, and acyclic supersession — all over
/// the recovered records themselves. Cross-record indexes are reconstructed
/// here as projections of those verified records; no supplied reverse link is
/// taken as truth.
///
/// A committed record whose immutable content or cross-record link does not
/// hold, or any contradiction between the store's committed image and the
/// supplied snapshot, leaves recovery explicitly BLOCKED with
/// [`FabricError::SemanticRecoveryBlocked`] — never an empty new plan and never
/// a partially trusted set. Current authority (a live lease or active
/// disposition) is not re-derived from these bytes: a saved label or an open
/// process never restores a lease, and the caller re-resolves live authority
/// from its own owner after this returns the retained history.
///
/// # Errors
///
/// Returns [`FabricError::SemanticRecoveryBlocked`] when the store cannot be
/// read, the recovered set fails strict verification, or the supplied snapshot
/// contradicts the committed durable image.
pub fn recover_semantic_revisions(
    store: &SemanticRevisionStore,
    supplied_snapshot: &FabricSnapshot,
) -> Result<RecoveredSemanticRevisions, FabricError> {
    let recovered = store.load().map_err(|error| {
        FabricError::SemanticRecoveryBlocked(format!(
            "owner-separated history cannot be rehydrated from real storage: {error}"
        ))
    })?;
    verify_semantic_record_set(
        &recovered.definitions,
        &recovered.admissions,
        &recovered.executions,
        &recovered.supersessions,
    )
    .map_err(|error| {
        FabricError::SemanticRecoveryBlocked(format!(
            "recovered owner-separated history fails strict recovery verification: {error}"
        ))
    })?;
    // The durable store is the commit point for the owner-separated image. A
    // supplied snapshot that disagrees with it is contradictory persistence, not
    // a newer truth: refuse rather than choose one side. (An empty supplied
    // snapshot is the normal case where the caller carries no in-image copy.)
    if !supplied_snapshot.semantic_definitions.is_empty()
        || !supplied_snapshot.semantic_admissions.is_empty()
        || !supplied_snapshot.semantic_executions.is_empty()
        || !supplied_snapshot.semantic_supersessions.is_empty()
    {
        let supplied_consistent = supplied_snapshot.semantic_definitions == recovered.definitions
            && supplied_snapshot.semantic_admissions == recovered.admissions
            && supplied_snapshot.semantic_executions == recovered.executions
            && supplied_snapshot.semantic_supersessions == recovered.supersessions;
        if !supplied_consistent {
            return Err(FabricError::SemanticRecoveryBlocked(
                "supplied snapshot contradicts the committed durable owner-separated image"
                    .to_owned(),
            ));
        }
    }
    Ok(recovered)
}

/// B-MOD model registry seam (#694). The fabric resolves routes only through
/// this injected port; ranking stays with the owner.
pub trait ModelRegistryPort: Send + Sync {
    /// Resolves one route for the given requirements, or `None` when no route
    /// is eligible. Never falls back locally.
    fn resolve_route(
        &self,
        requirements: &RouteRequirements,
    ) -> Result<Option<RouteFingerprint>, FabricError>;

    /// Reports this port's accepted-interface binding state (issue #1700).
    ///
    /// The default is [`PortBindingState::Uncertain`]: the port does not
    /// report binding state, so the fabric proceeds to the per-call owner
    /// verifier, which remains the authority. Override with an
    /// owner-affirmed [`PortBindingState::Bound`] (or a positively known
    /// non-bound state) once the owner tracks acceptance revisions.
    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Uncertain
    }
}

/// B-PEER coordination channel seam (#696). The fabric delivers only through
/// this injected port; delivery stays with the owner.
pub trait PeerChannelPort: Send + Sync {
    /// Delivers one peer message through the owning channel.
    fn deliver(&self, message: &PeerMessage) -> Result<PeerReceipt, FabricError>;

    /// Reports this port's accepted-interface binding state (issue #1700).
    /// See [`ModelRegistryPort::interface_binding`].
    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Uncertain
    }
}

/// B-SWARM durable swarm control seam (#698). The fabric enters the admitted
/// plan only through this injected port; the plan crosses unchanged.
pub trait SwarmControlPort: Send + Sync {
    /// Enters one planned candidate without semantic rewrite.
    fn enter_plan(
        &self,
        candidate: &StaffingPlanCandidate,
    ) -> Result<SwarmEntryReceipt, FabricError>;

    /// Reports this port's accepted-interface binding state (issue #1700).
    /// See [`ModelRegistryPort::interface_binding`].
    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Uncertain
    }
}

/// Governor admission authority seam. Kernel stages the inactive reservation;
/// Governor commits the canonical admission. The fabric composes both results
/// and implements neither store.
pub trait AdmissionAuthorityPort: Send + Sync {
    /// Stages one inactive reservation for the exact definition.
    fn stage_reservation(&self, definition: &SwarmDefinition) -> Result<Reservation, FabricError>;
    /// Commits one canonical admission referencing the staged reservation.
    fn commit_admission(&self, reservation: &Reservation) -> Result<FabricAdmission, FabricError>;

    /// Reports this port's accepted-interface binding state (issue #1700).
    /// See [`ModelRegistryPort::interface_binding`].
    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Uncertain
    }
}

/// Kernel activation authority seam (#839). Activation is granted only after
/// the matching canonical receipt under an unchanged fence and epoch.
pub trait ActivationAuthorityPort: Send + Sync {
    /// Activates launch authority for one admitted attempt.
    fn activate(
        &self,
        admission: &FabricAdmission,
        attempt_id: &AttemptId,
    ) -> Result<ActivationEvidence, FabricError>;

    /// Reports this port's accepted-interface binding state (issue #1700).
    /// See [`ModelRegistryPort::interface_binding`].
    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Uncertain
    }
}

/// Dispatch egress seam. The provider-neutral intent leaves the control
/// boundary only post-activation through this port.
pub trait DispatchEgressPort: Send + Sync {
    /// Emits one activated dispatch intent.
    fn emit(&self, intent: &DispatchIntent) -> Result<DispatchAck, FabricError>;

    /// Reports this port's accepted-interface binding state (issue #1700).
    /// See [`ModelRegistryPort::interface_binding`].
    fn interface_binding(&self) -> PortBindingState {
        PortBindingState::Uncertain
    }
}

/// Injected owner ports for one fabric instance.
#[derive(Clone)]
pub struct FabricPorts {
    /// B-MOD model registry (#694).
    pub model_registry: Arc<dyn ModelRegistryPort>,
    /// B-PEER coordination channel (#696).
    pub peer_channel: Arc<dyn PeerChannelPort>,
    /// B-SWARM durable swarm control (#698).
    pub swarm_control: Arc<dyn SwarmControlPort>,
    /// Governor admission authority.
    pub admission_authority: Arc<dyn AdmissionAuthorityPort>,
    /// Kernel activation authority (#839).
    pub activation_authority: Arc<dyn ActivationAuthorityPort>,
    /// Dispatch egress.
    pub dispatch_egress: Arc<dyn DispatchEgressPort>,
}

/// Durable snapshot of one fabric instance. Restart reconstructs exactly one
/// execution owner from this value plus live owner projections; unresolved
/// reservations stay unresolved and no second coordinator is created.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FabricSnapshot {
    /// Coordinator owner snapshot.
    pub coordinator_snapshot: CoordinatorSnapshot,
    /// Frozen definitions by definition identity.
    pub definitions: BTreeMap<String, SwarmDefinition>,
    /// Staged reservations by reservation identity.
    pub reservations: BTreeMap<String, Reservation>,
    /// Committed admissions by admission identity.
    pub admissions: BTreeMap<String, FabricAdmission>,
    /// Activation evidence by `admission_id/attempt_id`.
    pub activations: BTreeMap<String, ActivationEvidence>,
    /// Emitted dispatch intents by dispatch identity.
    pub intents: BTreeMap<String, DispatchIntent>,
    /// Ordered call ledger.
    pub ledger: Vec<LedgerEntry>,
    /// Attempt states by attempt identity.
    pub attempt_states: BTreeMap<String, AttemptLifecycle>,
    /// Cancellation states by attempt identity.
    pub cancellations: BTreeMap<String, CancellationLifecycle>,
    /// Validated Task-Controller semantic definitions by definition identity
    /// (issue #1702). Absent on legacy snapshots; legacy restores proceed
    /// without semantic bindings exactly as before.
    #[serde(default)]
    pub semantic_definitions: BTreeMap<String, SwarmPlanDefinition>,
    /// Governor semantic admissions by admission identity (issue #1702).
    #[serde(default)]
    pub semantic_admissions: BTreeMap<String, SwarmPlanAdmission>,
    /// Coordinator execution revisions by execution identity (issue #1702).
    #[serde(default)]
    pub semantic_executions: BTreeMap<String, SwarmExecutionRevision>,
    /// Supersession links by replacement definition identity (issue #1702).
    #[serde(default)]
    pub semantic_supersessions: BTreeMap<String, SupersessionLink>,
    /// Capability-based staffing plan receipts by definition identity (issue
    /// #1963). Persisted so the receipted defer/degrade/escalate dispositions
    /// and the authorized route classes survive restart; a definition without a
    /// stored receipt cannot dispatch. Absent on pre-#1963 snapshots, which
    /// therefore stay un-dispatchable rather than silently unstaffed.
    #[serde(default)]
    pub staffing_receipts: BTreeMap<String, StaffingPlanReceipt>,
    /// Route each already-dispatched attempt runs on, by attempt identity
    /// (issue #1963). The first dispatch records the route its staffing plan
    /// receipt authorized; a later route change for the same attempt is refused
    /// unless an explicit policy-authorized degradation was recorded first.
    #[serde(default)]
    pub attempt_routes: BTreeMap<String, RouteFingerprint>,
    /// Provider-capability dispatch frames by dispatch identity (issue #1108,
    /// W3). Persisted so the exact operation/attempt/provider/payload binding
    /// survives restart; absent on older snapshots, which restore without
    /// frames exactly as before.
    #[serde(default)]
    pub provider_frames: BTreeMap<String, ProviderCapabilityDispatchFrame>,
    /// Bridge-projected tool-result evidence by dispatch identity (issue
    /// #1108, A12). Attempt evidence only, never task Finish authority;
    /// absent on older snapshots, which restore without tool evidence exactly
    /// as before.
    #[serde(default)]
    pub tool_results: BTreeMap<String, ToolResultReceipt>,
}

/// Attempt lifecycle tracked by this composition. Terminal states never
/// advance silently; unknown remains unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AttemptLifecycle {
    /// Admitted and registered, not yet activated.
    Admitted,
    /// Activated by the Kernel owner.
    Activated,
    /// Dispatched post-activation.
    Dispatched,
    /// Candidate result submitted; not task Finish.
    ResultSubmitted,
    /// Outcome unknown; requires authenticated reconciliation.
    UnknownOutcome,
}

/// Cancellation lifecycle. Request and terminal observation remain distinct.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CancellationLifecycle {
    /// Cancellation requested, terminal not yet observed.
    Requested,
    /// Terminal cancellation observed.
    Terminal,
}

/// Thin durable swarm-control composition.
///
/// Owns exactly one [`AgentCoordinator`] plus the saga maps above it. All
/// owner policy stays with the owners; this type only threads admitted values,
/// verifies exact bindings at each boundary, and records the call ledger.
pub struct AgentFabric {
    config: CoordinatorConfig,
    coordinator: AgentCoordinator,
    ports: FabricPorts,
    ledger: Vec<LedgerEntry>,
    definitions: BTreeMap<String, SwarmDefinition>,
    definition_bytes: BTreeMap<String, String>,
    reservations: BTreeMap<String, Reservation>,
    admissions: BTreeMap<String, FabricAdmission>,
    admission_by_definition: BTreeMap<String, String>,
    activations: BTreeMap<String, ActivationEvidence>,
    intents: BTreeMap<String, DispatchIntent>,
    intent_by_operation: BTreeMap<String, String>,
    attempt_states: BTreeMap<String, AttemptLifecycle>,
    cancellations: BTreeMap<String, CancellationLifecycle>,
    /// Validated Task-Controller semantic definitions by definition identity.
    semantic_definitions: BTreeMap<String, SwarmPlanDefinition>,
    /// Governor semantic admissions by admission identity.
    semantic_admissions: BTreeMap<String, SwarmPlanAdmission>,
    /// Coordinator execution revisions by execution identity.
    semantic_executions: BTreeMap<String, SwarmExecutionRevision>,
    /// Supersession links by replacement definition identity.
    semantic_supersessions: BTreeMap<String, SupersessionLink>,
    /// Capability-based staffing plan receipts by definition identity.
    staffing_receipts: BTreeMap<String, StaffingPlanReceipt>,
    /// Route each already-dispatched attempt runs on.
    attempt_routes: BTreeMap<String, RouteFingerprint>,
    /// Provider-capability dispatch frames by dispatch identity (issue #1108,
    /// W3). Recorded on dispatch, persisted with the snapshot, and re-bound
    /// to the recorded intent by the restore gate.
    provider_frames: BTreeMap<String, ProviderCapabilityDispatchFrame>,
    /// Bridge-projected tool-result evidence by dispatch identity (issue
    /// #1108, A12). Attempt evidence only; recording one never advances an
    /// attempt lifecycle or task Finish.
    tool_results: BTreeMap<String, ToolResultReceipt>,
    /// Explicit policy-authorized degradations recorded before an attempt
    /// continues on a different route. In-memory only: a restart drops them,
    /// so a restored fabric re-refuses the switch instead of resuming it.
    attempt_degradations: BTreeMap<String, PolicyAuthorizedDegradation>,
    /// Durable owner-separated revision store (issue #1702 W2). Every
    /// owner-separated revision publish goes through this path first, so a
    /// revision is only readable as current after its durable write commits
    /// and verifies. `None` on a fabric that was never given a state root:
    /// such a fabric carries no owner-separated revisions and publishing one
    /// is refused typed rather than reported as current without durability.
    semantic_revisions: Option<SemanticRevisionStore>,
    initialized: bool,
}

impl AgentFabric {
    /// Constructs the one coordinator for this composition.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when the config is invalid.
    pub fn new(config: CoordinatorConfig, ports: FabricPorts) -> Result<Self, FabricError> {
        config
            .validate()
            .map_err(|error| FabricError::Contract(format!("coordinator config: {error}")))?;
        let coordinator = AgentCoordinator::new(
            config.clone(),
            PlanGap::G11Unavailable {
                reason: FABRIC_PLAN_GAP_REASON.to_owned(),
            },
        )?;
        let mut fabric = Self {
            config,
            coordinator,
            ports,
            ledger: Vec::new(),
            definitions: BTreeMap::new(),
            definition_bytes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            admissions: BTreeMap::new(),
            admission_by_definition: BTreeMap::new(),
            activations: BTreeMap::new(),
            intents: BTreeMap::new(),
            intent_by_operation: BTreeMap::new(),
            attempt_states: BTreeMap::new(),
            cancellations: BTreeMap::new(),
            semantic_definitions: BTreeMap::new(),
            semantic_admissions: BTreeMap::new(),
            semantic_executions: BTreeMap::new(),
            semantic_supersessions: BTreeMap::new(),
            staffing_receipts: BTreeMap::new(),
            attempt_routes: BTreeMap::new(),
            provider_frames: BTreeMap::new(),
            tool_results: BTreeMap::new(),
            attempt_degradations: BTreeMap::new(),
            semantic_revisions: None,
            initialized: true,
        };
        fabric.record("coordinator_constructed", "coordinator");
        Ok(fabric)
    }

    /// Constructs the one coordinator on a sealed admitted provider
    /// capability (issue #1108, production composition caller for A1/A2).
    ///
    /// The `capability` must be built via
    /// [`build_admitted_provider_capability`] from claim material the daemon
    /// resolved over its authenticated Kernel session plus ORS operation
    /// records bound to the exact attempt (M2). The coordinator performs no
    /// I/O and launches nothing; stale, revoked, foreign, or conflicting
    /// evidence fails closed through the T9-04 pure verifier.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when the config is invalid, or the
    /// coordinator owner rejection (e.g. stale capacity binding) unchanged.
    pub fn new_with_admitted_provider(
        config: CoordinatorConfig,
        ports: FabricPorts,
        capability: AdmittedProviderCapability,
    ) -> Result<Self, FabricError> {
        config
            .validate()
            .map_err(|error| FabricError::Contract(format!("coordinator config: {error}")))?;
        let coordinator = AgentCoordinator::new_with_admitted_provider(config.clone(), capability)?;
        let mut fabric = Self {
            config,
            coordinator,
            ports,
            ledger: Vec::new(),
            definitions: BTreeMap::new(),
            definition_bytes: BTreeMap::new(),
            reservations: BTreeMap::new(),
            admissions: BTreeMap::new(),
            admission_by_definition: BTreeMap::new(),
            activations: BTreeMap::new(),
            intents: BTreeMap::new(),
            intent_by_operation: BTreeMap::new(),
            attempt_states: BTreeMap::new(),
            cancellations: BTreeMap::new(),
            semantic_definitions: BTreeMap::new(),
            semantic_admissions: BTreeMap::new(),
            semantic_executions: BTreeMap::new(),
            semantic_supersessions: BTreeMap::new(),
            staffing_receipts: BTreeMap::new(),
            attempt_routes: BTreeMap::new(),
            provider_frames: BTreeMap::new(),
            tool_results: BTreeMap::new(),
            attempt_degradations: BTreeMap::new(),
            semantic_revisions: None,
            initialized: true,
        };
        fabric.record("coordinator_constructed_verified", "coordinator");
        Ok(fabric)
    }

    /// Attaches the durable owner-separated revision store over one daemon
    /// state root (issue #1702 W2).
    ///
    /// Attaching is what makes the ordering guarantee reachable: before it,
    /// this fabric has no durable carrier for owner-separated revisions and
    /// every semantic write site refuses with
    /// [`FabricError::DurabilityUnproven`] rather than reporting an
    /// undurable revision as current. After it, each publish is committed
    /// and verified before it is readable.
    ///
    /// The state root is the daemon's own protected subtree; the store
    /// resolves its own owned file under it and never adopts a foreign object
    /// at that path. Attaching twice to the same root is idempotent.
    pub fn attach_semantic_revision_store(&mut self, state_root: &std::path::Path) {
        self.semantic_revisions = Some(SemanticRevisionStore::new(state_root));
    }

    /// Rejects a second initialization on the same instance.
    ///
    /// # Errors
    ///
    /// Always returns [`FabricError::AlreadyInitialized`].
    pub fn try_initialize_again(&self) -> Result<(), FabricError> {
        if self.initialized {
            return Err(FabricError::AlreadyInitialized(
                "exactly one coordinator per fabric instance".to_owned(),
            ));
        }
        Ok(())
    }

    /// Returns the number of coordinators owned by this instance. Always one.
    #[must_use]
    pub const fn coordinator_count(&self) -> usize {
        1
    }

    /// Borrows the coordinator configuration threaded by this composition.
    #[must_use]
    pub const fn config(&self) -> &CoordinatorConfig {
        &self.config
    }

    /// Returns the ordered call ledger.
    #[must_use]
    pub fn ledger(&self) -> &[LedgerEntry] {
        &self.ledger
    }

    /// Returns the event names in ledger order.
    #[must_use]
    pub fn ledger_events(&self) -> Vec<String> {
        self.ledger
            .iter()
            .map(|entry| entry.event.clone())
            .collect()
    }

    fn record(&mut self, event: &str, operation: &str) {
        let seq = u64::try_from(self.ledger.len()).unwrap_or(u64::MAX);
        self.ledger.push(LedgerEntry {
            seq,
            event: event.to_owned(),
            operation: operation.to_owned(),
        });
    }

    /// Durably commits a proposed owner-separated revision set BEFORE it is
    /// published as current (issue #1702 W2).
    ///
    /// This is the ordering gate every semantic write site calls. The caller
    /// stages its proposed revisions into the real maps, this method commits
    /// the resulting image, and on failure the caller rolls the maps back to
    /// the exact pre-stage state — so a reader can never observe a revision
    /// that is not durable. Two independent writes where the second can fail
    /// after the first succeeds is not the mechanism: the durable write is the
    /// first step, and the in-memory publish is the only step after it, so a
    /// failure leaves the previously-current revisions current and nothing
    /// else.
    ///
    /// A fabric constructed without a durable store holds no owner-separated
    /// revisions; publishing one there is refused with
    /// [`FabricError::DurabilityUnproven`] instead of being reported as
    /// current with no durability behind it.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::DurabilityUnproven`] when no durable store is
    /// attached or the commit cannot be proven.
    fn publish_semantic_revision(&mut self) -> Result<(), FabricError> {
        let Some(store) = self.semantic_revisions.clone() else {
            return Err(FabricError::DurabilityUnproven(
                "owner-separated revision requires an attached durable store; attach the daemon state root before publishing a revision as current"
                    .to_owned(),
            ));
        };
        let snapshot = self.snapshot()?;
        store.commit(&snapshot)
    }

    /// Checks the accepted-interface binding of the single port the given
    /// operation depends on, before the owner call (issue #1700).
    ///
    /// [`PortBindingState::Bound`] proceeds to the per-call owner verifier
    /// and [`PortBindingState::Uncertain`] defers to it entirely: this check
    /// supplements, never replaces, the existing per-call
    /// authority/fence/receipt verification. A positively reported
    /// non-bound state stops before staging dependent capacity and returns
    /// the typed [`MissingPortResidual`] at the point of use. Operations
    /// without a map entry (plan-only planning, read-only observation,
    /// recovery/status/control, snapshot/restore) never call this helper.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::MissingPrerequisite`] when the required port
    /// reports a non-bound binding state, or [`FabricError::Contract`] when
    /// the residual itself is malformed.
    fn check_port_binding(
        &mut self,
        operation: FabricOperation,
        work_identity: &str,
        fence: Option<StateFence>,
        epoch: Option<EpochId>,
    ) -> Result<(), FabricError> {
        let port = operation.required_port();
        let state = match port {
            FabricPortId::ModelRegistry => self.ports.model_registry.interface_binding(),
            FabricPortId::PeerChannel => self.ports.peer_channel.interface_binding(),
            FabricPortId::SwarmControl => self.ports.swarm_control.interface_binding(),
            FabricPortId::AdmissionAuthority => self.ports.admission_authority.interface_binding(),
            FabricPortId::ActivationAuthority => {
                self.ports.activation_authority.interface_binding()
            }
            FabricPortId::DispatchEgress => self.ports.dispatch_egress.interface_binding(),
        };
        if state.admits_dependent_use() {
            return Ok(());
        }
        let residual = MissingPortResidual::new(
            port,
            state,
            operation,
            work_identity.to_owned(),
            fence,
            epoch,
        )?;
        self.record("prerequisite_blocked", work_identity);
        Err(FabricError::MissingPrerequisite(Box::new(residual)))
    }

    /// Validates and freezes one Task-Controller definition, then compiles its
    /// deterministic candidate through the real coordinator owner.
    ///
    /// The definition bytes are frozen before planning; planning never rewrites
    /// them. Identity reuse with different bytes is a conflict.
    ///
    /// Issue #1963: the capability-based staffing plan receipt is produced and
    /// enforced here, before any reservation, admission, activation or
    /// dispatch, and the enforced receipt is retained under the definition
    /// identity so it is the only authority on which routes that definition may
    /// dispatch. The `staffing_plan_receipted` ledger event precedes
    /// `definition_validated`.
    ///
    /// Definition is the first step of the chain an admitted Task-Controller
    /// production operation must drive ([`Self::define_and_plan`] →
    /// [`Self::stage_reservation`] → [`Self::commit_admission`] →
    /// [`Self::activate`] → [`Self::dispatch`]). That operation is not wired
    /// into `eliotd`: no `DaemonComposition` method or daemon poll step calls
    /// this method, so on the current base no production operation reaches
    /// definition, admission, activation and dispatch through this fabric.
    ///
    /// BLOCKED-BY scope `bins/eliotd/src/lib.rs::DaemonComposition` (and
    /// `bins/eliotd/src/campaign_task_controller.rs` /
    /// `bins/eliotd/src/daemon_runtime.rs` for the request producer): an
    /// admitted Task-Controller operation must be defined that carries the
    /// frozen `StaffingPlanRequest` plus the owner reservation, admission and
    /// activation authorities through these five steps. The step methods exist
    /// and are exercised; only the admitted production caller is absent.
    ///
    /// # Errors
    ///
    /// Returns the coordinator owner rejection, the staffing-policy rejection
    /// when the recipe exceeds the selected policy's lane or writer bound or
    /// the task class cannot be staffed under current evidence, or
    /// [`FabricError::DefinitionConflict`].
    pub fn define_and_plan(
        &mut self,
        request: StaffingPlanRequest,
    ) -> Result<(SwarmDefinition, StaffingPlanCandidate), FabricError> {
        // The receipt is computed from the frozen request and the live
        // coordinator config before anything is recorded, so a plan the policy
        // cannot staff never enters this composition's state.
        let receipt = plan_coordinator_staffing(&self.config, &request)
            .map_err(|error| staffing_rejection(&error))?;
        self.record("staffing_plan_receipted", request.candidate_id.as_str());
        self.record("definition_validated", request.candidate_id.as_str());
        // Freeze bytes before planning: identity reuse with different bytes is
        // a definition conflict, surfaced in fabric vocabulary before the
        // coordinator owner sees the replay.
        let digest = digest_json(&request)?;
        let key = request.candidate_id.as_str().to_owned();
        if let Some(stored_bytes) = self.definition_bytes.get(&key) {
            if *stored_bytes != digest {
                return Err(FabricError::DefinitionConflict(format!(
                    "definition {key} reused with different bytes"
                )));
            }
            let candidate = self.coordinator.plan(request)?;
            enforce_plan_receipt(&receipt, &candidate)
                .map_err(|error| staffing_rejection(&error))?;
            let stored = self.definitions.get(&key).cloned().ok_or_else(|| {
                FabricError::Contract(format!("definition {key} bytes without record"))
            })?;
            self.staffing_receipts.insert(key.clone(), receipt);
            self.record("plan_replayed", &key);
            return Ok((stored, candidate));
        }
        let candidate = self.coordinator.plan(request.clone())?;
        enforce_plan_receipt(&receipt, &candidate).map_err(|error| staffing_rejection(&error))?;
        let definition = SwarmDefinition {
            definition_id: request.candidate_id.clone(),
            definition_digest: digest.clone(),
            work_class: request.work_class,
            task_id: request.launch.task_id.as_str().to_owned(),
            task_revision: request.task_revision.clone(),
            plan_revision: request.plan_revision.as_str().to_owned(),
            fence: request.state_fence.clone(),
        };
        self.definitions.insert(key.clone(), definition.clone());
        self.definition_bytes.insert(key.clone(), digest);
        self.staffing_receipts.insert(key.clone(), receipt);
        self.record("plan_compiled", &key);
        Ok((definition, candidate))
    }

    /// Resolves one model route through the injected B-MOD registry.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::NoRoute`] when no route is eligible. Never falls
    /// back locally.
    pub fn resolve_model_route(
        &mut self,
        requirements: &RouteRequirements,
    ) -> Result<Option<RouteFingerprint>, FabricError> {
        requirements.validate()?;
        // #1700: a missing route binding prevents claiming an
        // evidence-backed selected route. The registry is not consulted and
        // no resolution is recorded when the port itself reports no accepted
        // binding; an uncertain port defers to the owner call below.
        self.check_port_binding(
            FabricOperation::ResolveModelRoute,
            &requirements.role,
            None,
            None,
        )?;
        let route = self.ports.model_registry.resolve_route(requirements)?;
        self.record("model_route_resolved", &requirements.role);
        Ok(route)
    }

    /// Requires one resolved route through the injected B-MOD registry,
    /// gated on Governor capability evidence (#1957).
    ///
    /// Resolution stays candidate-only through the injected port; the route
    /// is required only when every competence item holds fresh
    /// exact-fingerprint production admission in the daemon-held
    /// [`GovernorCapabilityAdmission`](super::capability_evidence_wiring::GovernorCapabilityAdmission)
    /// on the caller-supplied observed scope at `now`. The scope fingerprint
    /// is an observation the caller threads in (requested and observed
    /// routes stay separate objects); it is never derived here from the
    /// resolved route.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::NoRoute`] when the registry resolves no route
    /// or any competence item lacks fresh evidence. Never falls back
    /// locally.
    pub fn require_model_route(
        &mut self,
        requirements: &RouteRequirements,
        evidence: &super::capability_evidence_wiring::GovernorCapabilityAdmission,
        scope: &eliot_governor::RouteScopeFingerprint,
        now: u64,
    ) -> Result<RouteFingerprint, FabricError> {
        match self.resolve_model_route(requirements)? {
            Some(route) => {
                for competence in &requirements.competence {
                    if !evidence.admit_production_route(competence, scope, now) {
                        let role = requirements.role.clone();
                        return Err(FabricError::NoRoute(format!(
                            "no admitted capability evidence for role {role} competence {competence}"
                        )));
                    }
                }
                Ok(route)
            }
            None => Err(FabricError::NoRoute(format!(
                "no eligible route for role {}",
                requirements.role
            ))),
        }
    }

    /// Delivers one peer message through the injected B-PEER channel.
    ///
    /// # Errors
    ///
    /// Returns the channel owner rejection.
    pub fn deliver_peer(&mut self, message: &PeerMessage) -> Result<PeerReceipt, FabricError> {
        validate_text(&message.message_id, "peer_message_id")?;
        // #1700: a peer gap blocks only this delivery. Solo/read-only paths
        // never consult the peer port, so an optional missing peer path does
        // not block independently valid work.
        self.check_port_binding(
            FabricOperation::DeliverPeer,
            &message.message_id,
            None,
            None,
        )?;
        let receipt = self.ports.peer_channel.deliver(message)?;
        self.record("peer_delivered", &message.message_id);
        Ok(receipt)
    }

    /// Enters one planned candidate through the injected B-SWARM control
    /// without semantic rewrite.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::IdentityConflict`] when the entered digest does
    /// not match the planned digest.
    pub fn enter_swarm(
        &mut self,
        candidate: &StaffingPlanCandidate,
    ) -> Result<SwarmEntryReceipt, FabricError> {
        // #1700: stop before entering when the swarm port reports no accepted
        // binding; the planned candidate is retained for reevaluation.
        self.check_port_binding(
            FabricOperation::EnterSwarm,
            candidate.candidate_id.as_str(),
            Some(candidate.state_fence.clone()),
            None,
        )?;
        let planned_digest = digest_json(candidate)?;
        let receipt = self.ports.swarm_control.enter_plan(candidate)?;
        if receipt.entered_digest != planned_digest
            || receipt.candidate_id != candidate.candidate_id
        {
            return Err(FabricError::IdentityConflict(
                "swarm entry changed the admitted plan".to_owned(),
            ));
        }
        self.record("swarm_entered", candidate.candidate_id.as_str());
        Ok(receipt)
    }

    /// Stages one Kernel reservation for the exact frozen definition.
    ///
    /// # Errors
    ///
    /// Returns the reservation owner rejection.
    pub fn stage_reservation(
        &mut self,
        definition_id: &CandidateId,
    ) -> Result<Reservation, FabricError> {
        // #740: staged-reservation span over the existing control path.
        let _span = tracing::info_span!(
            "eliotd.fabric_stage",
            definition = %crate::diagnostics::sanitize_identity(definition_id.as_str())
        )
        .entered();
        let key = definition_id.as_str().to_owned();
        let definition = self
            .definitions
            .get(&key)
            .cloned()
            .ok_or_else(|| FabricError::Contract(format!("unknown definition {key}")))?;
        // #1700: a missing admission prerequisite is already known here, so
        // stop before staging dependent capacity unnecessarily. The frozen
        // definition is retained for reevaluation after owner acceptance.
        self.check_port_binding(
            FabricOperation::StageReservation,
            &key,
            Some(definition.fence.clone()),
            None,
        )?;
        let reservation = self
            .ports
            .admission_authority
            .stage_reservation(&definition)?;
        if reservation.definition_id != *definition_id
            || reservation.definition_digest != definition.definition_digest
        {
            return Err(FabricError::ReceiptBinding(
                "reservation does not bind the exact definition".to_owned(),
            ));
        }
        // I14.1 work class (issue #1698): the staged reservation must echo
        // the frozen definition class exactly; a class mismatch is a binding
        // failure, never a silent downgrade.
        if reservation.work_class != definition.work_class {
            return Err(FabricError::ReceiptBinding(
                "reservation does not bind the exact definition work class".to_owned(),
            ));
        }
        validate_text(&reservation.reservation_id, "reservation_id")?;
        self.reservations
            .insert(reservation.reservation_id.clone(), reservation.clone());
        self.record("reservation_staged", &reservation.reservation_id);
        Ok(reservation)
    }

    /// Commits one Governor admission for a staged reservation. Fresh requests
    /// admit once; exact replay returns the same receipt without a second
    /// owner call.
    ///
    /// # Errors
    ///
    /// Returns the admission owner rejection, or [`FabricError::ReceiptBinding`]
    /// when the receipt does not bind the exact definition digest and
    /// reservation identity.
    pub fn commit_admission(
        &mut self,
        reservation_id: &str,
    ) -> Result<FabricAdmission, FabricError> {
        // #740: admission span over the existing control path. The committed
        // receipt binds the exact definition digest and reservation; every
        // rejection records its typed reason plus the exact owner.
        let _span = tracing::info_span!(
            "eliotd.fabric_commit",
            reservation = %crate::diagnostics::sanitize_identity(reservation_id)
        )
        .entered();
        let outcome = self.commit_admission_checked(reservation_id);
        match &outcome {
            Ok(admission) => {
                let _ = crate::diagnostics::AdmissionRecord::of(
                    crate::diagnostics::disposition_of_admission(admission),
                    &admission.reservation_id,
                    admission.definition_digest.as_str(),
                )
                .emit();
            }
            Err(error) => {
                let _ = crate::diagnostics::RejectionRecord::of_fabric_error(error).emit();
            }
        }
        outcome
    }

    fn commit_admission_checked(
        &mut self,
        reservation_id: &str,
    ) -> Result<FabricAdmission, FabricError> {
        let reservation = self
            .reservations
            .get(reservation_id)
            .cloned()
            .ok_or_else(|| {
                FabricError::StaleReservation(format!("unknown reservation {reservation_id}"))
            })?;
        let definition_key = reservation.definition_id.as_str().to_owned();
        if let Some(existing) = self
            .admission_by_definition
            .get(&definition_key)
            .and_then(|existing_id| self.admissions.get(existing_id))
            .cloned()
        {
            if existing.reservation_id == reservation_id {
                self.record("admission_replayed", existing.admission_id.as_str());
                return Ok(existing);
            }
            return Err(FabricError::DefinitionConflict(format!(
                "definition {definition_key} already admitted under a different reservation"
            )));
        }
        // #1700: unresolved admission binding prevents launch with a typed
        // residual naming the exact prerequisite and the blocked operation.
        // Exact replay above stays untouched: an already-committed admission
        // is returned without consulting the port again.
        self.check_port_binding(
            FabricOperation::CommitAdmission,
            reservation_id,
            Some(reservation.fence.clone()),
            None,
        )?;
        let receipt = self
            .ports
            .admission_authority
            .commit_admission(&reservation)?;
        if receipt.definition_digest
            != self
                .definitions
                .get(&definition_key)
                .map(|definition| definition.definition_digest.clone())
                .unwrap_or_default()
            || receipt.reservation_id != reservation_id
            || receipt.definition_id != reservation.definition_id
            || receipt.work_class != reservation.work_class
        {
            return Err(FabricError::ReceiptBinding(
                "admission receipt does not bind the exact definition digest and reservation"
                    .to_owned(),
            ));
        }
        if receipt.fence != reservation.fence {
            return Err(FabricError::StaleFence(
                "admission fence does not match the staged reservation".to_owned(),
            ));
        }
        let admission_key = receipt.admission_id.as_str().to_owned();
        for attempt in &receipt.attempt_ids {
            let attempt_key = attempt.as_str().to_owned();
            if self.attempt_states.contains_key(&attempt_key) {
                return Err(FabricError::DuplicateLaunch(format!(
                    "attempt {attempt_key} already registered"
                )));
            }
        }
        for attempt in &receipt.attempt_ids {
            self.attempt_states
                .insert(attempt.as_str().to_owned(), AttemptLifecycle::Admitted);
        }
        self.admissions
            .insert(admission_key.clone(), receipt.clone());
        self.admission_by_definition
            .insert(definition_key, admission_key);
        self.record("admission_committed", receipt.admission_id.as_str());
        Ok(receipt)
    }

    /// Registers one Task-Controller semantic definition revision (issue
    /// #1702).
    ///
    /// Only the holder of the definition's current Task Controller lease may
    /// register; a valid payload digest never substitutes for author
    /// authority. `DRAFT` and `FROZEN` revisions register; superseded or
    /// cancelled history stays in the records and never re-registers as
    /// current. Same-identity replay is exact; changed content conflicts.
    /// Freezing (`DRAFT → FROZEN` with otherwise identical content) replaces
    /// the stored draft; any other same-identity change is a conflict.
    ///
    /// The revision is published as current only after the canonical Store
    /// transaction that durably persists it committed: `owner_revision` and
    /// `receipt` are that transaction's owner record and its receipt, checked
    /// by [`require_durable_owner_revision`] before anything enters the
    /// in-memory owner map. Publishing first and persisting afterwards would
    /// let a reader observe a revision no Store holds.
    ///
    /// # Errors
    ///
    /// Returns the semantic contract rejection,
    /// [`FabricError::StaleOwnerLease`] for a foreign or stale controller,
    /// [`FabricError::RevisionNotDurable`] when the durable commit is absent or
    /// does not bind this exact owner stream and revision, or
    /// [`FabricError::DefinitionConflict`] for changed content under a live
    /// identity, or [`FabricError::DurabilityUnproven`] when the revision
    /// could not be persisted before being reported as current.
    pub fn register_semantic_definition(
        &mut self,
        definition: SwarmPlanDefinition,
        controller_holder: &str,
        controller_epoch: u64,
        owner_revision: &SwarmOwnerRevision,
        receipt: &WriteReceipt,
    ) -> Result<(), FabricError> {
        definition.validate().map_err(contract_rejection)?;
        check_definition_author(&definition, controller_holder, controller_epoch)
            .map_err(contract_rejection)?;
        let record = serde_json::to_value(&definition).map_err(|error| {
            FabricError::Contract(format!("semantic definition encode: {error}"))
        })?;
        require_durable_owner_revision(owner_revision, receipt, &record)?;
        if !matches!(
            definition.lifecycle,
            SwarmPlanDefinitionLifecycle::Draft | SwarmPlanDefinitionLifecycle::Frozen
        ) {
            return Err(FabricError::BrokenOwnershipLink(
                "only draft or frozen definitions register as current".to_owned(),
            ));
        }
        let key = definition.definition_id.as_str().to_owned();
        if let Some(stored) = self.semantic_definitions.get(&key).cloned() {
            if stored == definition {
                self.record("semantic_definition_replayed", &key);
                return Ok(());
            }
            if stored.lifecycle == SwarmPlanDefinitionLifecycle::Draft {
                let mut frozen = stored.clone();
                frozen.lifecycle = SwarmPlanDefinitionLifecycle::Frozen;
                if frozen == definition {
                    // #1702 W2: the frozen revision is durable before it
                    // becomes the current one. On an unproven write the
                    // stored draft stays current, so no reader ever sees a
                    // revision a crash could erase.
                    self.semantic_definitions
                        .insert(key.clone(), definition.clone());
                    if let Err(error) = self.publish_semantic_revision() {
                        self.semantic_definitions.insert(key.clone(), stored);
                        return Err(error);
                    }
                    self.record("semantic_definition_frozen", &key);
                    return Ok(());
                }
            }
            return Err(FabricError::DefinitionConflict(format!(
                "semantic definition {key} reused with different bytes"
            )));
        }
        self.semantic_definitions.insert(key.clone(), definition);
        if let Err(error) = self.publish_semantic_revision() {
            self.semantic_definitions.remove(&key);
            return Err(error);
        }
        self.record("semantic_definition_registered", &key);
        Ok(())
    }

    /// Binds one Governor semantic admission to its registered frozen
    /// definition (issue #1702).
    ///
    /// Only `FROZEN` definitions may be admitted and only `ADMITTED`
    /// dispositions bind; admitted ceilings must narrow, never widen, the
    /// definition. Same-identity replay is exact; a second admission identity
    /// for one definition conflicts, so a new definition revision always
    /// yields a distinct admission.
    ///
    /// The admission is published as current only after the canonical Store
    /// transaction that durably persists it committed; see
    /// [`AgentFabric::register_semantic_definition`] for the ordering this
    /// preserves.
    ///
    /// # Errors
    ///
    /// Returns the semantic contract rejection,
    /// [`FabricError::BrokenOwnershipLink`] when the definition is unknown,
    /// not frozen, or not bound exactly, [`FabricError::SemanticDrift`] when
    /// admitted ceilings widen the definition,
    /// [`FabricError::RevisionNotDurable`] when the durable commit is absent or
    /// does not bind this exact owner stream and revision, or
    /// [`FabricError::DefinitionConflict`] for a second admission identity on
    /// one definition.
    pub fn bind_semantic_admission(
        &mut self,
        admission: SwarmPlanAdmission,
        owner_revision: &SwarmOwnerRevision,
        receipt: &WriteReceipt,
    ) -> Result<(), FabricError> {
        admission.validate().map_err(contract_rejection)?;
        let record = serde_json::to_value(&admission).map_err(|error| {
            FabricError::Contract(format!("semantic admission encode: {error}"))
        })?;
        require_durable_owner_revision(owner_revision, receipt, &record)?;
        let definition_key = admission.definition_id.as_str().to_owned();
        let definition = self
            .semantic_definitions
            .get(&definition_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic definition {definition_key}"))
            })?;
        if definition.lifecycle != SwarmPlanDefinitionLifecycle::Frozen {
            return Err(FabricError::BrokenOwnershipLink(
                "only frozen definitions may be admitted".to_owned(),
            ));
        }
        if !admission.binds(&definition) {
            return Err(FabricError::BrokenOwnershipLink(
                "admission does not bind the exact frozen definition".to_owned(),
            ));
        }
        if admission.disposition != SwarmPlanAdmissionDisposition::Admitted {
            return Err(FabricError::BrokenOwnershipLink(
                "only admitted dispositions bind".to_owned(),
            ));
        }
        if !admission
            .admitted_ceilings
            .narrowed_from(&definition.ceilings)
        {
            return Err(FabricError::SemanticDrift(
                "admitted ceilings widen the frozen definition".to_owned(),
            ));
        }
        for existing in self.semantic_admissions.values() {
            if existing.definition_id == admission.definition_id
                && existing.admission_id != admission.admission_id
            {
                return Err(FabricError::DefinitionConflict(format!(
                    "semantic definition {definition_key} already admitted under a different admission"
                )));
            }
        }
        let key = admission.admission_id.as_str().to_owned();
        if let Some(stored) = self.semantic_admissions.get(&key).cloned() {
            if stored == admission {
                self.record("semantic_admission_replayed", &key);
                return Ok(());
            }
            return Err(FabricError::DefinitionConflict(format!(
                "semantic admission {key} reused with different bytes"
            )));
        }
        self.semantic_admissions.insert(key.clone(), admission);
        // #1702 W2: the admission is durable before it is reported current.
        if let Err(error) = self.publish_semantic_revision() {
            self.semantic_admissions.remove(&key);
            return Err(error);
        }
        self.record("semantic_admission_bound", &key);
        Ok(())
    }

    /// Mirrors the Governor disposition of a bound semantic admission (issue
    /// #1702).
    ///
    /// The fabric never originates dispositions: the Governor owner decides
    /// and this composition only records the transition after validating it
    /// against the I14.20 admission lifecycle. Mirroring `SUPERSEDED` or
    /// `CANCELLED` freezes new execution updates under the old admission;
    /// retained records stay readable history. Re-noting the stored
    /// disposition replays exactly (a retried Governor acknowledgement after a
    /// crash commits nothing twice); a different disposition must still pass
    /// the lifecycle.
    ///
    /// The new disposition is published as current only after the canonical
    /// Store transaction that durably persists it committed; see
    /// [`AgentFabric::register_semantic_definition`] for the ordering this
    /// preserves.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] for an unknown admission,
    /// [`FabricError::RevisionNotDurable`] when the durable commit is absent or
    /// does not bind this exact owner stream and revision, or the semantic
    /// contract rejection for an illegal disposition transition.
    pub fn note_semantic_admission_disposition(
        &mut self,
        admission_id: &SwarmAdmissionId,
        disposition: SwarmPlanAdmissionDisposition,
        owner_revision: &SwarmOwnerRevision,
        receipt: &WriteReceipt,
    ) -> Result<(), FabricError> {
        let key = admission_id.as_str().to_owned();
        let stored =
            self.semantic_admissions.get(&key).cloned().ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic admission {key}"))
            })?;
        if stored.disposition == disposition {
            self.record("semantic_admission_disposition_replayed", &key);
            return Ok(());
        }
        let mut admission = stored.clone();
        admission.disposition = admission
            .disposition
            .decide(disposition)
            .map_err(contract_rejection)?;
        admission.validate().map_err(contract_rejection)?;
        let record = serde_json::to_value(&admission).map_err(|error| {
            FabricError::Contract(format!("semantic admission encode: {error}"))
        })?;
        require_durable_owner_revision(owner_revision, receipt, &record)?;
        self.semantic_admissions.insert(key.clone(), admission);
        // #1702 W2: the disposition is durable before it becomes the current
        // one; a failed write leaves the previous disposition authoritative.
        if let Err(error) = self.publish_semantic_revision() {
            self.semantic_admissions.insert(key.clone(), stored);
            return Err(error);
        }
        self.record("semantic_admission_disposition_noted", &key);
        Ok(())
    }

    /// Records one coordinator execution revision against its bound admission
    /// (issue #1702).
    ///
    /// Validates the full ownership join at record time: the definition must
    /// be registered, the admission bound, and the execution linked to both.
    /// The presenter must hold the execution's current coordinator lease: a
    /// stale or foreign coordinator cannot write execution fields, nor can
    /// another owner's holder under its own labels. Only a
    /// live wave takes new execution identities: once a replacement
    /// definition is recorded, or once the admission leaves `ADMITTED`, the
    /// old wave freezes and new identities record through the replacement
    /// admission. Same-identity replay is exact; changed content conflicts.
    /// Terminal states are retained verbatim: history is never rewritten and
    /// `UNKNOWN_OUTCOME` never becomes a clean failure here.
    ///
    /// The execution revision is published as current only after the canonical
    /// Store transaction that durably persists it committed; see
    /// [`AgentFabric::register_semantic_definition`] for the ordering this
    /// preserves.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when the definition or admission is
    /// unknown, [`FabricError::StaleOwnerLease`] for a stale or foreign
    /// coordinator, [`FabricError::Superseded`] for a new identity under a
    /// superseded definition, [`FabricError::RevisionNotDurable`] when the
    /// durable commit is absent or does not bind this exact owner stream and
    /// revision, the semantic contract rejection for a broken join, or
    /// [`FabricError::DefinitionConflict`] for changed content under a live
    /// execution identity.
    pub fn record_semantic_execution(
        &mut self,
        execution: SwarmExecutionRevision,
        coordinator_holder: &str,
        coordinator_epoch: u64,
        owner_revision: &SwarmOwnerRevision,
        receipt: &WriteReceipt,
    ) -> Result<(), FabricError> {
        execution.validate().map_err(contract_rejection)?;
        let record = serde_json::to_value(&execution).map_err(|error| {
            FabricError::Contract(format!("semantic execution encode: {error}"))
        })?;
        require_durable_owner_revision(owner_revision, receipt, &record)?;
        if !execution
            .coordinator
            .authorizes(coordinator_holder, coordinator_epoch)
        {
            return Err(FabricError::StaleOwnerLease("swarm coordinator".to_owned()));
        }
        let definition_key = execution.definition_id.as_str().to_owned();
        let definition = self
            .semantic_definitions
            .get(&definition_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic definition {definition_key}"))
            })?;
        let admission_key = execution.admission_id.as_str().to_owned();
        let admission = self
            .semantic_admissions
            .get(&admission_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic admission {admission_key}"))
            })?;
        let key = execution.execution_id.as_str().to_owned();
        if let Some(stored) = self.semantic_executions.get(&key).cloned() {
            if stored == execution {
                self.record("semantic_execution_replayed", &key);
                return Ok(());
            }
            return Err(FabricError::DefinitionConflict(format!(
                "semantic execution {key} reused with different bytes"
            )));
        }
        if self
            .semantic_supersessions
            .values()
            .any(|link| link.prior_definition_id.as_str() == definition_key)
        {
            return Err(FabricError::Superseded(format!(
                "semantic definition {definition_key} superseded; record through the replacement admission"
            )));
        }
        if admission.disposition != SwarmPlanAdmissionDisposition::Admitted {
            return Err(FabricError::BrokenOwnershipLink(
                "new semantic execution requires an admitted admission".to_owned(),
            ));
        }
        check_owner_join(&definition, &admission, &execution).map_err(contract_rejection)?;
        self.semantic_executions.insert(key.clone(), execution);
        // #1702 W2: the execution revision is durable before it is reported
        // current; an unproven write publishes nothing.
        if let Err(error) = self.publish_semantic_revision() {
            self.semantic_executions.remove(&key);
            return Err(error);
        }
        self.record("semantic_execution_recorded", &key);
        Ok(())
    }

    /// Rebinds one retained execution to a new coordinator epoch after owner
    /// loss (issue #1702).
    ///
    /// Only the affected owner's lease moves: the presenter must be the
    /// incoming holder at the incoming epoch, the epoch must advance past the
    /// retained one, and the definition, admission, wave, root, state and
    /// coverage bindings are preserved verbatim through
    /// [`reassign_coordinator`]. Spend is never reset and `UNKNOWN_OUTCOME`
    /// never becomes a clean failure here. Re-presenting the stored lease
    /// replays exactly; presenting a stale epoch or a foreign holder fails
    /// with [`FabricError::StaleOwnerLease`].
    ///
    /// The rebound execution revision is published as current only after the
    /// canonical Store transaction that durably persists it committed; see
    /// [`AgentFabric::register_semantic_definition`] for the ordering this
    /// preserves. Retained effects and coverage are never rewritten by the
    /// rebind, so the durable record and the published revision stay the same
    /// bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] for an unknown execution,
    /// [`FabricError::StaleOwnerLease`] for a presenter outside the incoming
    /// lease or a non-advancing epoch, [`FabricError::RevisionNotDurable`]
    /// when the durable commit is absent or does not bind this exact owner
    /// stream and revision, or the mapped semantic rejection otherwise.
    pub fn reassign_semantic_coordinator(
        &mut self,
        execution_id: &SwarmExecutionId,
        new_coordinator: &SwarmCoordinatorLease,
        presenter_holder: &str,
        presenter_epoch: u64,
        owner_revision: &SwarmOwnerRevision,
        receipt: &WriteReceipt,
    ) -> Result<(), FabricError> {
        if !new_coordinator.authorizes(presenter_holder, presenter_epoch) {
            return Err(FabricError::StaleOwnerLease("swarm coordinator".to_owned()));
        }
        let key = execution_id.as_str().to_owned();
        let stored =
            self.semantic_executions.get(&key).cloned().ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic execution {key}"))
            })?;
        if stored.coordinator == *new_coordinator {
            self.record("semantic_coordinator_reassigned_replayed", &key);
            return Ok(());
        }
        let next = reassign_coordinator(&stored, new_coordinator).map_err(contract_rejection)?;
        let record = serde_json::to_value(&next).map_err(|error| {
            FabricError::Contract(format!("semantic execution encode: {error}"))
        })?;
        require_durable_owner_revision(owner_revision, receipt, &record)?;
        self.semantic_executions.insert(key.clone(), next);
        // #1702 W2: the rebind is durable before it becomes the current
        // execution owner; a failed write leaves the previous epoch in force.
        if let Err(error) = self.publish_semantic_revision() {
            self.semantic_executions.insert(key.clone(), stored);
            return Err(error);
        }
        self.record("semantic_coordinator_reassigned", &key);
        Ok(())
    }

    /// Guards one coordinator execution update against frozen plan semantics
    /// (issue #1702).
    ///
    /// Mechanical updates under the current coordinator lease and the exact
    /// active admission pass; any attempt to change the work graph,
    /// objective, acceptance, ceilings, stop conditions, wave or root fails
    /// with [`FabricError::SemanticDrift`]. Updates against a cancelled or
    /// superseded old wave fail with [`FabricError::Superseded`]: replacement
    /// work needs the new definition and its distinct admission. `Drain` is
    /// NOT a narrowed permission: it is the arm that declines to refuse, so a
    /// draining old wave is checked by exactly the same guard as any other
    /// frozen-and-admitted wave, and is refused for semantic change on the same
    /// terms. A stale or foreign coordinator fails with
    /// [`FabricError::StaleOwnerLease`].
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when the admission or execution is
    /// unknown, or the mapped semantic rejection otherwise.
    pub fn check_semantic_execution_update(
        &self,
        admission_id: &SwarmAdmissionId,
        execution_id: &SwarmExecutionId,
        update: &ExecutionUpdateProposal,
        caller_holder: &str,
        caller_epoch: u64,
    ) -> Result<(), FabricError> {
        let admission_key = admission_id.as_str().to_owned();
        let admission = self
            .semantic_admissions
            .get(&admission_key)
            .ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic admission {admission_key}"))
            })?;
        let execution_key = execution_id.as_str().to_owned();
        let execution = self
            .semantic_executions
            .get(&execution_key)
            .ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic execution {execution_key}"))
            })?;
        let definition_key = admission.definition_id.as_str().to_owned();
        let definition = self
            .semantic_definitions
            .get(&definition_key)
            .ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic definition {definition_key}"))
            })?;
        if let Some(link) = self
            .semantic_supersessions
            .values()
            .find(|link| link.prior_definition_id.as_str() == definition_key)
        {
            match link.disposition {
                OldWaveDisposition::Drain => {}
                OldWaveDisposition::Cancel | OldWaveDisposition::Supersede => {
                    return Err(FabricError::Superseded(format!(
                        "semantic definition {definition_key} superseded; update through the replacement admission"
                    )));
                }
            }
        }
        check_execution_update(
            definition,
            admission,
            execution,
            update,
            caller_holder,
            caller_epoch,
        )
        .map_err(contract_rejection)
    }

    /// Proposes the replacement of active work with a new definition revision
    /// (issue #1702).
    ///
    /// The proposer must hold the prior definition's current Task Controller
    /// lease or the replacement's named lease (owner-loss reassignment under
    /// a newer epoch); anyone else fails with
    /// [`FabricError::StaleOwnerLease`]. The replacement links the exact
    /// prior revision with an explicit drain/cancel/supersede disposition and
    /// carries a distinct identity. Stored history is never mutated: the
    /// prior frozen record stays verbatim and the link records the
    /// disposition. The new revision still needs its distinct Governor
    /// admission ([`AgentFabric::bind_semantic_admission`]) before any
    /// execution runs under it, and the old admission disposition is mirrored
    /// through [`AgentFabric::note_semantic_admission_disposition`].
    /// Re-proposing the stored replacement replays exactly (a retried Task
    /// Controller acknowledgement after a crash records no duplicate
    /// revision); any other reuse of the replacement identity conflicts.
    ///
    /// The replacement revision and its supersession link are published as
    /// current only after the canonical Store transaction that durably persists
    /// them committed; see [`AgentFabric::register_semantic_definition`] for
    /// the ordering this preserves. The prior frozen record stays verbatim, so
    /// the durable history and the published history are the same bytes.
    ///
    /// # Errors
    ///
    /// Returns the semantic contract rejection,
    /// [`FabricError::RevisionNotDurable`] when the durable commit is absent or
    /// does not bind this exact owner stream and revision, or
    /// [`FabricError::DefinitionConflict`] when the replacement identity is
    /// already registered with different bytes.
    pub fn supersede_semantic_definition(
        &mut self,
        next: SwarmPlanDefinition,
        controller_holder: &str,
        controller_epoch: u64,
        owner_revision: &SwarmOwnerRevision,
        receipt: &WriteReceipt,
    ) -> Result<(), FabricError> {
        next.validate().map_err(contract_rejection)?;
        let record = serde_json::to_value(&next).map_err(|error| {
            FabricError::Contract(format!("semantic definition encode: {error}"))
        })?;
        require_durable_owner_revision(owner_revision, receipt, &record)?;
        let link = next.supersedes.clone().ok_or_else(|| {
            FabricError::BrokenOwnershipLink("replacement without supersedes link".to_owned())
        })?;
        let prior_key = link.prior_definition_id.as_str().to_owned();
        let prior = self
            .semantic_definitions
            .get(&prior_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic definition {prior_key}"))
            })?;
        if !prior
            .controller
            .authorizes(controller_holder, controller_epoch)
            && !next
                .controller
                .authorizes(controller_holder, controller_epoch)
        {
            return Err(FabricError::StaleOwnerLease("task controller".to_owned()));
        }
        check_supersession(&prior, &next).map_err(contract_rejection)?;
        let next_key = next.definition_id.as_str().to_owned();
        if let Some(stored) = self.semantic_definitions.get(&next_key).cloned() {
            if stored == next && self.semantic_supersessions.get(&next_key) == Some(&link) {
                self.record("semantic_definition_supersession_replayed", &next_key);
                return Ok(());
            }
            return Err(FabricError::DefinitionConflict(format!(
                "replacement semantic definition {next_key} already registered"
            )));
        }
        self.semantic_definitions.insert(next_key.clone(), next);
        self.semantic_supersessions.insert(next_key.clone(), link);
        // #1702 W2: the replacement and its old-wave disposition are two
        // records, so they are staged together and committed in ONE durable
        // write before either becomes current. A partial write here would let
        // a reader see a replacement without its disposition (or the reverse),
        // which is exactly the ordering hazard this lane closes. A failed
        // commit rolls both back to the prior state.
        if let Err(error) = self.publish_semantic_revision() {
            self.semantic_supersessions.remove(&next_key);
            self.semantic_definitions.remove(&next_key);
            return Err(error);
        }
        self.record("semantic_definition_superseded", &next_key);
        Ok(())
    }

    /// Reads the joined owner state as an explicit non-authoritative view
    /// (issue #1702).
    ///
    /// Built only from validated stored records; joined reads never serve as
    /// write authorization. Surfaces the pending replacement link, when one
    /// is proposed, and preserved unknown effects.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when the admission or execution is
    /// unknown, or the mapped semantic rejection for a broken join.
    pub fn semantic_join_view(
        &self,
        admission_id: &SwarmAdmissionId,
        execution_id: &SwarmExecutionId,
        unknown_effects: Vec<String>,
    ) -> Result<SwarmPlanView, FabricError> {
        let admission_key = admission_id.as_str().to_owned();
        let admission = self
            .semantic_admissions
            .get(&admission_key)
            .ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic admission {admission_key}"))
            })?;
        let execution_key = execution_id.as_str().to_owned();
        let execution = self
            .semantic_executions
            .get(&execution_key)
            .ok_or_else(|| {
                FabricError::Contract(format!("unknown semantic execution {execution_key}"))
            })?;
        let definition = self
            .semantic_definitions
            .get(execution.definition_id.as_str())
            .ok_or_else(|| {
                FabricError::Contract(format!(
                    "unknown semantic definition {}",
                    execution.definition_id.as_str()
                ))
            })?;
        let pending = self
            .semantic_supersessions
            .values()
            .find(|link| link.prior_definition_id == definition.definition_id)
            .cloned();
        join_view(definition, admission, execution, pending, unknown_effects)
            .map_err(contract_rejection)
    }

    /// Activates launch authority for one admitted attempt after the matching
    /// canonical receipt under an unchanged fence and epoch.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::StaleFence`], [`FabricError::StaleEpoch`], or the
    /// activation owner rejection.
    pub fn activate(
        &mut self,
        admission_id: &AdmissionId,
        attempt_id: &AttemptId,
    ) -> Result<ActivationEvidence, FabricError> {
        let admission_key = admission_id.as_str().to_owned();
        let admission = self
            .admissions
            .get(&admission_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::StaleAdmission(format!("unknown admission {admission_key}"))
            })?;
        if !admission.attempt_ids.contains(attempt_id) {
            return Err(FabricError::IdentityConflict(
                "attempt does not belong to this admission".to_owned(),
            ));
        }
        let key = format!("{admission_key}/{}", attempt_id.as_str());
        if let Some(existing) = self.activations.get(&key).cloned() {
            self.record("activation_replayed", &key);
            return Ok(existing);
        }
        // #1700: unresolved activation binding prevents launch with a typed
        // residual. Replay of already-committed evidence stays untouched.
        self.check_port_binding(
            FabricOperation::Activate,
            &key,
            Some(admission.fence.clone()),
            Some(admission.epoch.clone()),
        )?;
        let evidence = self
            .ports
            .activation_authority
            .activate(&admission, attempt_id)?;
        if evidence.admission_id != *admission_id || evidence.attempt_id != *attempt_id {
            return Err(FabricError::IdentityConflict(
                "activation evidence identity does not match the admission".to_owned(),
            ));
        }
        if !fences_match_exact(&evidence.fence, &admission.fence) {
            return Err(FabricError::StaleFence(
                "activation fence does not match the admission".to_owned(),
            ));
        }
        if !evidence.epoch.is_same_authority(&admission.epoch) {
            return Err(FabricError::StaleEpoch(
                "activation epoch does not match the admission".to_owned(),
            ));
        }
        validate_text(&evidence.activation_digest, "activation_digest")?;
        self.activations.insert(key.clone(), evidence.clone());
        self.attempt_states
            .insert(attempt_id.as_str().to_owned(), AttemptLifecycle::Activated);
        self.record("activation_committed", &key);
        Ok(evidence)
    }

    /// Builds the provider-neutral dispatch intent for one activated attempt.
    /// The intent leaves the control boundary only through the egress port.
    ///
    /// Issue #1963: the dispatch boundary is where the capability-based
    /// staffing plan receipt is enforced a second time, at the point the lane
    /// would actually run. The definition's retained receipt must exist, its
    /// digest must still bind its body, and the attempt's route must be one the
    /// receipt staffed. An attempt already bound to a route continues on that
    /// route only; a different route is refused unless an explicit receipted
    /// policy-authorized degradation for exactly this transition was recorded
    /// first through [`AgentFabric::authorize_attempt_route_degradation`].
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::NotActivated`] when no activation evidence
    /// exists, [`FabricError::Contract`] when the staffing plan receipt does not
    /// authorize this attempt's route or a mid-attempt provider switch carries
    /// no authorized degradation, or [`FabricError::DuplicateLaunch`] for a
    /// replayed operation with different bytes.
    pub fn dispatch(
        &mut self,
        admission_id: &AdmissionId,
        attempt_id: &AttemptId,
        dispatch_id: &str,
    ) -> Result<DispatchIntent, FabricError> {
        validate_text(dispatch_id, "dispatch_id")?;
        let admission_key = admission_id.as_str().to_owned();
        let admission = self
            .admissions
            .get(&admission_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::StaleAdmission(format!("unknown admission {admission_key}"))
            })?;
        let activation_key = format!("{admission_key}/{}", attempt_id.as_str());
        let evidence = self
            .activations
            .get(&activation_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::NotActivated(format!("no activation for {activation_key}"))
            })?;
        // Enforced before the replay/duplicate guards so a route change for an
        // already-routed attempt is judged as a provider switch, not as a
        // duplicate dispatch id.
        let attempt_route = self.authorized_attempt_route(&admission, attempt_id)?;
        if let Some(existing) = self.intents.get(dispatch_id).cloned() {
            if existing.admission_id == *admission_id
                && existing.attempt_id == *attempt_id
                && existing.activation_digest == evidence.activation_digest
                && existing.work_class == admission.work_class
            {
                self.record("dispatch_replayed", dispatch_id);
                return Ok(existing);
            }
            return Err(FabricError::DuplicateLaunch(format!(
                "dispatch {dispatch_id} reused with different bytes"
            )));
        }
        if self
            .intent_by_operation
            .values()
            .any(|operation| operation == &activation_key)
        {
            return Err(FabricError::DuplicateLaunch(format!(
                "operation {activation_key} already dispatched"
            )));
        }
        let intent = DispatchIntent {
            dispatch_id: dispatch_id.to_owned(),
            admission_id: admission_id.clone(),
            attempt_id: attempt_id.clone(),
            work_class: admission.work_class,
            activation_digest: evidence.activation_digest.clone(),
            fence: evidence.fence.clone(),
            epoch: evidence.epoch.clone(),
        };
        self.intents.insert(dispatch_id.to_owned(), intent.clone());
        self.intent_by_operation
            .insert(dispatch_id.to_owned(), activation_key.clone());
        self.attempt_states
            .insert(attempt_id.as_str().to_owned(), AttemptLifecycle::Dispatched);
        self.attempt_routes
            .insert(attempt_id.as_str().to_owned(), attempt_route);
        self.record("dispatch_built", dispatch_id);
        Ok(intent)
    }

    /// Resolves the route this attempt's staffing plan receipt authorized, and
    /// enforces mid-attempt route continuity (issue #1963).
    ///
    /// The definition's retained receipt must exist and must still bind its own
    /// body, so a receipt that did not survive its persistence boundary fails
    /// closed. Attempt `n` of the admission runs on the `n`th route the receipt
    /// staffed; an attempt beyond the staffed routes is refused instead of
    /// running on an unstaffed route.
    ///
    /// The first dispatch of an attempt records that route. A later dispatch of
    /// the same attempt whose receipted route differs is a mid-attempt provider
    /// switch and continues only when
    /// [`AgentFabric::authorize_attempt_route_degradation`] recorded an
    /// explicit receipted policy-authorized degradation for exactly this
    /// attempt and this route transition; otherwise
    /// [`check_attempt_route_continuity`] refuses it.
    fn authorized_attempt_route(
        &mut self,
        admission: &FabricAdmission,
        attempt_id: &AttemptId,
    ) -> Result<RouteFingerprint, FabricError> {
        let definition_key = admission.definition_id.as_str().to_owned();
        let receipt = self
            .staffing_receipts
            .get(&definition_key)
            .ok_or_else(|| {
                FabricError::Contract(format!(
                    "definition {definition_key} has no staffing plan receipt; nothing is authorized to dispatch"
                ))
            })?
            .clone();
        verify_receipt_digest(&receipt).map_err(|error| staffing_rejection(&error))?;
        let position = admission
            .attempt_ids
            .iter()
            .position(|candidate| candidate == attempt_id)
            .ok_or_else(|| {
                FabricError::IdentityConflict(
                    "attempt does not belong to this admission".to_owned(),
                )
            })?;
        let route = receipt
            .lanes
            .get(position)
            .map(|lane| lane.route.clone())
            .ok_or_else(|| {
                FabricError::Contract(format!(
                    "staffing plan receipt staffed {} routes for {definition_key}; attempt at position {position} is unstaffed",
                    receipt.lanes.len()
                ))
            })?;
        let attempt_key = attempt_id.as_str().to_owned();
        if let Some(previous) = self.attempt_routes.get(&attempt_key).cloned() {
            let degradation = self.attempt_degradations.get(&attempt_key);
            check_attempt_route_continuity(&previous, &route, degradation, &attempt_key)
                .map_err(|error| staffing_rejection(&error))?;
        }
        Ok(route)
    }

    /// Records the explicit receipted policy-authorized degradation that lets
    /// one attempt continue on a different route (issue #1963).
    ///
    /// The decision is taken before continuation: the degradation must bind this
    /// exact attempt and this exact route transition, and it is checked here by
    /// [`check_attempt_route_continuity`] against the route the attempt is
    /// already bound to. The recorded authorization is what
    /// [`AgentFabric::dispatch`] consults; without it a route change is
    /// refused. It is deliberately not persisted, so a restart drops the
    /// authorization and re-refuses the switch rather than resuming it.
    ///
    /// # Errors
    ///
    /// Returns the staffing-policy rejection when the attempt is not yet bound
    /// to a route or the degradation does not bind the exact transition.
    pub fn authorize_attempt_route_degradation(
        &mut self,
        attempt_id: &AttemptId,
        next_route: &RouteFingerprint,
        degradation: &PolicyAuthorizedDegradation,
    ) -> Result<(), FabricError> {
        let attempt_key = attempt_id.as_str().to_owned();
        let previous = self
            .attempt_routes
            .get(&attempt_key)
            .cloned()
            .ok_or_else(|| {
                FabricError::Contract(format!(
                    "attempt {attempt_key} has no recorded route to degrade from"
                ))
            })?;
        check_attempt_route_continuity(&previous, next_route, Some(degradation), &attempt_key)
            .map_err(|error| staffing_rejection(&error))?;
        self.attempt_degradations
            .insert(attempt_key.clone(), degradation.clone());
        self.record("attempt_route_degradation_authorized", &attempt_key);
        Ok(())
    }

    /// Emits one built dispatch intent through the egress port.
    ///
    /// # Errors
    ///
    /// Returns the egress owner outcome, including typed unavailability and
    /// loss. Loss retains the original operation without false success.
    pub fn emit(&mut self, dispatch_id: &str) -> Result<DispatchAck, FabricError> {
        let intent = self
            .intents
            .get(dispatch_id)
            .cloned()
            .ok_or_else(|| FabricError::Contract(format!("unknown dispatch {dispatch_id}")))?;
        // #1700: stop before emitting when the egress port reports no
        // accepted binding. The built intent is retained (never recomputed
        // under a new ID) for reevaluation after owner acceptance.
        self.check_port_binding(
            FabricOperation::Emit,
            dispatch_id,
            Some(intent.fence.clone()),
            Some(intent.epoch.clone()),
        )?;
        let ack = self.ports.dispatch_egress.emit(&intent)?;
        if ack.dispatch_id != dispatch_id {
            return Err(FabricError::IdentityConflict(
                "dispatch ack identity does not match the intent".to_owned(),
            ));
        }
        self.record("dispatch_emitted", dispatch_id);
        Ok(ack)
    }

    /// Dispatches the provider-capability frame for one recorded intent
    /// (issue #1108, W3; acceptance A3/A7/A10/A11).
    ///
    /// The frame carries the exact operation (`dispatch_id`) and attempt from
    /// the recorded [`DispatchIntent`], the admitted provider identity read
    /// from the coordinator's verified binding, and the canonical payload
    /// digest of the recorded intent. The recorded intent is then emitted
    /// through the existing [`DispatchEgressPort`], so this is the same
    /// egress with provider identity bound, never a second dispatch scheme.
    /// Same identity and payload replay exactly; a changed payload under one
    /// identity conflicts.
    ///
    /// No `DaemonComposition` method drives this yet: the admitted
    /// Task-Controller production operation that would carry the frozen
    /// request plus the owner authorities through definition, admission,
    /// activation, and this dispatch is absent on the current base
    /// (BLOCKED-BY scope `bins/eliotd/src/lib.rs::DaemonComposition`).
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::CoordinatorUnavailable`] on a plan-only fabric
    /// with no admitted provider binding, [`FabricError::DuplicateLaunch`]
    /// when the identity is reused with different bytes, or the egress owner
    /// outcome unchanged.
    pub fn dispatch_provider_capability_frame(
        &mut self,
        dispatch_id: &str,
    ) -> Result<ProviderCapabilityDispatchFrame, FabricError> {
        let _span = tracing::info_span!(
            "eliotd.fabric_provider_frame",
            dispatch = %crate::diagnostics::sanitize_identity(dispatch_id)
        )
        .entered();
        let outcome = self.dispatch_provider_capability_frame_checked(dispatch_id);
        if let Err(error) = &outcome {
            let _ = crate::diagnostics::RejectionRecord::of_fabric_error(error).emit();
        }
        outcome
    }

    fn dispatch_provider_capability_frame_checked(
        &mut self,
        dispatch_id: &str,
    ) -> Result<ProviderCapabilityDispatchFrame, FabricError> {
        validate_text(dispatch_id, "dispatch_id")?;
        let intent = self
            .intents
            .get(dispatch_id)
            .cloned()
            .ok_or_else(|| FabricError::Contract(format!("unknown dispatch {dispatch_id}")))?;
        let identity = match self.coordinator.snapshot()?.provider_binding {
            ProviderBindingSnapshot::Verified { identity } => identity,
            ProviderBindingSnapshot::Gap { .. } => {
                return Err(FabricError::CoordinatorUnavailable(
                    "provider capability frame requires an admitted provider binding; a plan-only fabric cannot dispatch"
                        .to_owned(),
                ));
            }
        };
        let frame = ProviderCapabilityDispatchFrame {
            dispatch_id: dispatch_id.to_owned(),
            attempt_id: intent.attempt_id.clone(),
            provider_identity: identity,
            payload_digest: digest_json(&intent)?,
            fence: intent.fence.clone(),
            epoch: intent.epoch.clone(),
        };
        if let Some(recorded) = self.provider_frames.get(dispatch_id).cloned() {
            if recorded == frame {
                self.record("provider_capability_frame_replayed", dispatch_id);
                return Ok(recorded);
            }
            return Err(FabricError::DuplicateLaunch(format!(
                "provider capability frame {dispatch_id} reused with different bytes"
            )));
        }
        // Same gate and egress as `emit`: a missing egress binding blocks
        // before any launch, and the ack must match the recorded intent.
        self.check_port_binding(
            FabricOperation::Emit,
            dispatch_id,
            Some(intent.fence.clone()),
            Some(intent.epoch.clone()),
        )?;
        let ack = self.ports.dispatch_egress.emit(&intent)?;
        if ack.dispatch_id != dispatch_id {
            return Err(FabricError::IdentityConflict(
                "dispatch ack identity does not match the intent".to_owned(),
            ));
        }
        self.provider_frames
            .insert(dispatch_id.to_owned(), frame.clone());
        self.record("provider_capability_frame_dispatched", dispatch_id);
        Ok(frame)
    }

    /// Records a worker acknowledgement. An ack never becomes attempt success.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::AckNotResult`] when the caller treats the ack as
    /// a result, and [`FabricError::Quarantined`] for unknown attempts.
    pub fn observe_worker_ack(&mut self, ack: &WorkerAck) -> Result<(), FabricError> {
        // #740: ack span. A worker acknowledgement is never completed work;
        // the record keeps `completed='false'` even on success.
        let _span = tracing::info_span!(
            "eliotd.fabric_ack",
            attempt = %crate::diagnostics::sanitize_identity(ack.attempt_id.as_str())
        )
        .entered();
        let outcome = self.observe_worker_ack_checked(ack);
        if outcome.is_ok() {
            let _ = crate::diagnostics::emit_worker_ack(
                ack.attempt_id.as_str(),
                ack.worker_id.as_str(),
            );
        }
        outcome
    }

    fn observe_worker_ack_checked(&mut self, ack: &WorkerAck) -> Result<(), FabricError> {
        validate_text(&ack.worker_id, "worker_id")?;
        let key = ack.attempt_id.as_str().to_owned();
        if !self.attempt_states.contains_key(&key) {
            return Err(FabricError::Quarantined(format!(
                "orphan ack for unknown attempt {key}"
            )));
        }
        self.record("worker_ack_observed", &key);
        Ok(())
    }

    /// Submits one candidate attempt result. A result never becomes task
    /// Finish; unknown outcomes remain unknown.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::ResultNotFinish`] when the caller treats the
    /// candidate as Finish, or [`FabricError::Quarantined`] for unknown or
    /// undispatched attempts.
    pub fn submit_attempt_result(
        &mut self,
        result: &AttemptResultRecord,
    ) -> Result<(), FabricError> {
        // #740: result span. An attempt result is never task Finish; only the
        // authoritative Finish result can complete work.
        let _span = tracing::info_span!(
            "eliotd.fabric_result",
            attempt = %crate::diagnostics::sanitize_identity(result.attempt_id.as_str())
        )
        .entered();
        let outcome = self.submit_attempt_result_checked(result);
        if let Err(error) = &outcome {
            let _ = crate::diagnostics::RejectionRecord::of_fabric_error(error).emit();
        }
        outcome
    }

    fn submit_attempt_result_checked(
        &mut self,
        result: &AttemptResultRecord,
    ) -> Result<(), FabricError> {
        validate_text(&result.result_digest, "result_digest")?;
        let key = result.attempt_id.as_str().to_owned();
        match self.attempt_states.get(&key) {
            Some(AttemptLifecycle::Dispatched) => {
                self.attempt_states
                    .insert(key.clone(), AttemptLifecycle::ResultSubmitted);
                self.record("attempt_result_submitted", &key);
                Ok(())
            }
            Some(_) => Err(FabricError::ResultNotFinish(format!(
                "attempt {key} result is a candidate artifact, not task Finish"
            ))),
            None => Err(FabricError::Quarantined(format!(
                "orphan result for unknown attempt {key}"
            ))),
        }
    }

    /// Observes one worker result line. Orphan, foreign, or stale observations
    /// are quarantined and publish no proof or effect.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Quarantined`] for unknown attempts.
    pub fn observe_worker_result(
        &mut self,
        attempt_id: &AttemptId,
        worker_id: &str,
    ) -> Result<(), FabricError> {
        validate_text(worker_id, "worker_id")?;
        let key = attempt_id.as_str().to_owned();
        if !self.attempt_states.contains_key(&key) {
            self.record("observation_quarantined", &key);
            return Err(FabricError::Quarantined(format!(
                "orphan observation for unknown attempt {key}"
            )));
        }
        self.record("observation_accepted", &key);
        Ok(())
    }

    /// Observes one bridge-projected tool result as attempt evidence for the
    /// recorded dispatch operation (issue #1108, A12).
    ///
    /// The receipt is the bridge owner's projected value: it is validated
    /// with the existing [`ToolResultReceipt::check_complete_evidence`] gate
    /// on its original recorded value, never recomputed here, and it is bound
    /// to the dispatch identity whose recorded intent is the independent
    /// expected set. Same identity and payload replay exactly; a changed
    /// payload under one identity conflicts.
    ///
    /// The receipt is stored as evidence only: the attempt lifecycle is left
    /// untouched and [`AgentFabric::require_finish`] still refuses every
    /// state, so a tool result can never become task Finish.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Contract`] when the receipt fails the
    /// complete-evidence gate, [`FabricError::Quarantined`] for a dispatch
    /// with no recorded intent, or [`FabricError::DuplicateLaunch`] when the
    /// identity is reused with different bytes.
    pub fn observe_tool_result(
        &mut self,
        dispatch_id: &str,
        receipt: &ToolResultReceipt,
    ) -> Result<(), FabricError> {
        let _span = tracing::info_span!(
            "eliotd.fabric_tool_result",
            dispatch = %crate::diagnostics::sanitize_identity(dispatch_id)
        )
        .entered();
        let outcome = self.observe_tool_result_checked(dispatch_id, receipt);
        if let Err(error) = &outcome {
            let _ = crate::diagnostics::RejectionRecord::of_fabric_error(error).emit();
        }
        outcome
    }

    fn observe_tool_result_checked(
        &mut self,
        dispatch_id: &str,
        receipt: &ToolResultReceipt,
    ) -> Result<(), FabricError> {
        validate_text(dispatch_id, "dispatch_id")?;
        receipt
            .check_complete_evidence()
            .map_err(|error| FabricError::Contract(format!("tool result evidence: {error}")))?;
        if !self.intents.contains_key(dispatch_id) {
            return Err(FabricError::Quarantined(format!(
                "orphan tool result for unknown dispatch {dispatch_id}"
            )));
        }
        if let Some(recorded) = self.tool_results.get(dispatch_id).cloned() {
            if recorded == *receipt {
                self.record("tool_result_replayed", dispatch_id);
                return Ok(());
            }
            return Err(FabricError::DuplicateLaunch(format!(
                "tool result {dispatch_id} reused with different bytes"
            )));
        }
        self.tool_results
            .insert(dispatch_id.to_owned(), receipt.clone());
        self.record("tool_result_observed", dispatch_id);
        Ok(())
    }

    /// Marks one attempt outcome unknown. Unknown remains unknown and cannot
    /// satisfy Finish.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Quarantined`] for unknown attempts.
    pub fn mark_unknown_outcome(&mut self, attempt_id: &AttemptId) -> Result<(), FabricError> {
        // #740: unknown-outcome span. The original identity is preserved
        // verbatim; diagnostics never trigger a resend or recompute.
        let _span = tracing::info_span!(
            "eliotd.fabric_unknown",
            attempt = %crate::diagnostics::sanitize_identity(attempt_id.as_str())
        )
        .entered();
        let key = attempt_id.as_str().to_owned();
        if !self.attempt_states.contains_key(&key) {
            return Err(FabricError::Quarantined(format!(
                "unknown outcome for unregistered attempt {key}"
            )));
        }
        self.attempt_states
            .insert(key.clone(), AttemptLifecycle::UnknownOutcome);
        self.record("outcome_unknown", &key);
        Ok(())
    }

    /// Drives the coordinator's bounded fair pull over its admitted projection
    /// (issue #1683 W1, I14.8 "Scheduler is pull-based").
    ///
    /// This is the daemon composition root's join to the coordinator's
    /// pull-based scheduler, and it is a real effect rather than a probe: every
    /// entry in the returned `started` is an attempt the coordinator actually
    /// transitioned to `Running` through its own admission, so capacity freed
    /// by a terminal attempt advances work without another agent command.
    /// Nothing here admits, launches a process, binds a provider execution or
    /// grants Finish authority; the coordinator drive's own proof ceiling
    /// bounds it.
    ///
    /// `profile` is the Kernel-owned nine-class scheduling policy compiled by
    /// `eliot_agent_coordinator::load_runtime_scheduling_profile`. The fabric
    /// resolves no file, environment variable or working directory of its own,
    /// so the configuration location stays the composition root's decision, and
    /// an absent document is the loader's own typed refusal rather than a
    /// defaulted profile.
    ///
    /// `recovery_poll` names which arm of the I14.8 progress loop this is
    /// (issue #1683 W5), and is passed through to the coordinator verbatim: it
    /// is evidence in the returned outcome, never a gate. `true` is the
    /// always-armed bounded recovery poll that survives a lost notification;
    /// `false` is the response to an observed release/reconciliation event. Both
    /// drive the identical selector over the identical projection, so the fabric
    /// re-decides nothing here and records the caller's own classification.
    ///
    /// Production residual, unchanged here and not worked around: no issuer of
    /// the provider-verified `ProviderAdmissionReceipt` that
    /// `AgentCoordinator::admit` requires exists in the tree today (issue
    /// #1678), so in production the coordinator's `attempts` map is empty and
    /// the drive reports that no work is currently admissible. This method is
    /// the caller that makes the drive live the moment that owner lands.
    ///
    /// # Errors
    ///
    /// Returns the coordinator owner rejection unchanged, including the
    /// profile's own validation failure when it is not a valid versioned
    /// nine-class set.
    pub fn drive_fair_pull(
        &mut self,
        profile: &SchedulingProfile,
        recovery_poll: bool,
    ) -> Result<FairPullOutcome, FabricError> {
        // #1683: bounded fair-pull span over the release path. The recorded
        // decision is the coordinator's; the fabric never re-decides it.
        let _span = tracing::info_span!("eliotd.fabric_fair_pull").entered();
        Ok(self.coordinator.drive_fair_pull(profile, recovery_poll)?)
    }

    /// Asserts that an unknown outcome cannot satisfy Finish.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::UnknownChild`] when the attempt is unknown, and
    /// [`FabricError::ResultNotFinish`] otherwise: no fabric state is task
    /// Finish.
    pub fn require_finish(&self, attempt_id: &AttemptId) -> Result<(), FabricError> {
        // #740: strict-Finish span. Refusal records refusal without
        // fabricated completion; success is impossible here by owner design
        // (attempt results are never Finish) and stays unlogged as finished.
        let _span = tracing::info_span!(
            "eliotd.fabric_finish",
            attempt = %crate::diagnostics::sanitize_identity(attempt_id.as_str())
        )
        .entered();
        let outcome = self.require_finish_checked(attempt_id);
        if let Err(error) = &outcome {
            let (reason, owner) = crate::diagnostics::fabric_rejection_of(error);
            let _ = crate::diagnostics::emit_finish_evaluation(
                attempt_id.as_str(),
                crate::diagnostics::strict_finish_completed(false),
            );
            let _ = crate::diagnostics::emit_finish_refusal(attempt_id.as_str(), reason, owner);
        }
        outcome
    }

    fn require_finish_checked(&self, attempt_id: &AttemptId) -> Result<(), FabricError> {
        let key = attempt_id.as_str().to_owned();
        match self.attempt_states.get(&key) {
            Some(AttemptLifecycle::UnknownOutcome) => Err(FabricError::UnknownChild(format!(
                "attempt {key} outcome is unknown and cannot satisfy Finish"
            ))),
            Some(_) => Err(FabricError::ResultNotFinish(format!(
                "attempt {key} candidate state is not task Finish"
            ))),
            None => Err(FabricError::Quarantined(format!(
                "finish requested for unknown attempt {key}"
            ))),
        }
    }

    /// Requests cancellation for one attempt. Request and terminal observation
    /// remain distinct.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Quarantined`] for unknown attempts.
    pub fn request_cancellation(
        &mut self,
        attempt_id: &AttemptId,
        operation: &str,
    ) -> Result<(), FabricError> {
        validate_text(operation, "cancellation_operation")?;
        let key = attempt_id.as_str().to_owned();
        if !self.attempt_states.contains_key(&key) {
            return Err(FabricError::Quarantined(format!(
                "cancellation for unknown attempt {key}"
            )));
        }
        self.cancellations
            .insert(key.clone(), CancellationLifecycle::Requested);
        self.record("cancellation_requested", &key);
        Ok(())
    }

    /// Reconciles the observed terminal cancellation for a previously
    /// requested operation.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::Cancelled`] when no request exists, keeping
    /// request and terminal distinct.
    pub fn reconcile_terminal_cancellation(
        &mut self,
        attempt_id: &AttemptId,
    ) -> Result<(), FabricError> {
        let key = attempt_id.as_str().to_owned();
        match self.cancellations.get(&key) {
            Some(CancellationLifecycle::Requested) => {
                self.cancellations
                    .insert(key.clone(), CancellationLifecycle::Terminal);
                self.record("cancellation_terminal", &key);
                Ok(())
            }
            _ => Err(FabricError::Cancelled(format!(
                "no requested cancellation reconciles attempt {key}"
            ))),
        }
    }

    /// Returns the cancellation lifecycle for one attempt, if any.
    #[must_use]
    pub fn cancellation_of(&self, attempt_id: &AttemptId) -> Option<CancellationLifecycle> {
        self.cancellations.get(attempt_id.as_str()).copied()
    }

    /// Returns the attempt lifecycle for one attempt, if any.
    #[must_use]
    pub fn attempt_of(&self, attempt_id: &AttemptId) -> Option<AttemptLifecycle> {
        self.attempt_states.get(attempt_id.as_str()).copied()
    }

    /// Snapshots this instance for durable restart.
    ///
    /// # Errors
    ///
    /// Returns the coordinator owner snapshot rejection.
    pub fn snapshot(&self) -> Result<FabricSnapshot, FabricError> {
        Ok(FabricSnapshot {
            coordinator_snapshot: self.coordinator.snapshot()?,
            definitions: self.definitions.clone(),
            reservations: self.reservations.clone(),
            admissions: self.admissions.clone(),
            activations: self.activations.clone(),
            intents: self.intents.clone(),
            ledger: self.ledger.clone(),
            attempt_states: self.attempt_states.clone(),
            cancellations: self.cancellations.clone(),
            semantic_definitions: self.semantic_definitions.clone(),
            semantic_admissions: self.semantic_admissions.clone(),
            semantic_executions: self.semantic_executions.clone(),
            semantic_supersessions: self.semantic_supersessions.clone(),
            staffing_receipts: self.staffing_receipts.clone(),
            attempt_routes: self.attempt_routes.clone(),
            provider_frames: self.provider_frames.clone(),
            tool_results: self.tool_results.clone(),
        })
    }

    /// Restores exactly one execution owner from a durable snapshot.
    ///
    /// Definition, admission, lease, and epoch revisions are preserved;
    /// unresolved reservations stay unresolved and no second coordinator is
    /// created. Semantic ownership maps (issue #1702) verify strictly before
    /// any state is adopted: contradictory definition/admission/execution
    /// links fail closed with [`FabricError::BrokenOwnershipLink`] instead of
    /// restoring authority.
    ///
    /// A snapshot carrying a verified provider binding is rejected here
    /// with [`FabricError::ProviderEvidenceRequired`]: without freshly
    /// resolved owner material the restore stays blocked instead of
    /// silently resuming as plan-only. Re-resolve live evidence through
    /// [`AgentFabric::restore_verified`], or construct an explicitly fresh
    /// plan-only fabric through [`AgentFabric::new`].
    ///
    /// Issue #1963: a stored staffing plan receipt must still bind its own body
    /// or the restore fails closed, and a definition with no stored receipt
    /// cannot dispatch. Recorded policy-authorized degradations are not
    /// persisted, so a restored fabric re-refuses a mid-attempt provider switch
    /// until one is recorded again.
    ///
    /// # Errors
    ///
    /// Returns [`FabricError::ProviderEvidenceRequired`] when the snapshot
    /// holds a verified provider binding, the coordinator owner restore
    /// rejection, a stale-config conflict, a broken semantic ownership link, or
    /// a staffing plan receipt that no longer binds its body.
    ///
    /// Issue #1702 W2: pass the daemon state root's
    /// [`SemanticRevisionStore`] so the restored fabric keeps publishing
    /// owner-separated revisions through a durable write before they are
    /// reported current. `None` restores the historical plan-only behaviour:
    /// retained semantic records stay readable history, but publishing a new
    /// one is refused typed until a store is attached.
    pub fn restore(
        snapshot: FabricSnapshot,
        config: CoordinatorConfig,
        ports: FabricPorts,
        semantic_revisions: Option<&SemanticRevisionStore>,
    ) -> Result<Self, FabricError> {
        if snapshot.coordinator_snapshot.config != config {
            return Err(FabricError::IdentityConflict(
                "restore config does not match the snapshotted coordinator config".to_owned(),
            ));
        }
        if matches!(
            snapshot.coordinator_snapshot.provider_binding,
            ProviderBindingSnapshot::Verified { .. }
        ) {
            return Err(FabricError::ProviderEvidenceRequired);
        }
        // Issue #1702: contradictory semantic ownership never restores
        // authority. Legacy snapshots carry no semantic records and pass
        // trivially.
        verify_snapshot_semantics(&snapshot)?;
        verify_snapshot_tool_evidence(&snapshot)?;
        let admission_by_definition = rebuild_admission_by_definition(&snapshot)?;
        let coordinator = AgentCoordinator::restore(
            snapshot.coordinator_snapshot.clone(),
            config.clone(),
            PlanGap::G11Unavailable {
                reason: FABRIC_PLAN_GAP_REASON.to_owned(),
            },
        )?;
        let mut definition_bytes = BTreeMap::new();
        for (key, definition) in &snapshot.definitions {
            definition_bytes.insert(key.clone(), definition.definition_digest.clone());
        }
        let mut intent_by_operation = BTreeMap::new();
        for (dispatch_id, intent) in &snapshot.intents {
            intent_by_operation.insert(
                dispatch_id.clone(),
                format!(
                    "{}/{}",
                    intent.admission_id.as_str(),
                    intent.attempt_id.as_str()
                ),
            );
        }
        let mut fabric = Self {
            config,
            coordinator,
            ports,
            ledger: snapshot.ledger.clone(),
            definitions: snapshot.definitions,
            definition_bytes,
            reservations: snapshot.reservations,
            admissions: snapshot.admissions,
            admission_by_definition,
            activations: snapshot.activations,
            intents: snapshot.intents,
            intent_by_operation,
            attempt_states: snapshot.attempt_states,
            cancellations: snapshot.cancellations,
            semantic_definitions: snapshot.semantic_definitions,
            semantic_admissions: snapshot.semantic_admissions,
            semantic_executions: snapshot.semantic_executions,
            semantic_supersessions: snapshot.semantic_supersessions,
            staffing_receipts: snapshot.staffing_receipts,
            attempt_routes: snapshot.attempt_routes,
            provider_frames: snapshot.provider_frames,
            tool_results: snapshot.tool_results,
            attempt_degradations: BTreeMap::new(),
            // #1702 W2: a restored fabric re-attaches the same durable
            // carrier, so a revision published after restore is committed
            // before it is reported current exactly as it was before.
            semantic_revisions: semantic_revisions.cloned(),
            initialized: true,
        };
        fabric.record("fabric_restored", "fabric");
        Ok(fabric)
    }

    /// Restores the fabric on a freshly supplied admitted provider
    /// capability (issue #1108, verified restore for A8).
    ///
    /// The daemon re-queries Kernel and passes a fresh `capability`; the
    /// snapshot's stored binding must equal the live binding and every
    /// replayed event re-verifies through the T9-04 pure verifier, so a
    /// serialized `Verified` label alone never restores authority and
    /// missing/stale/revoked evidence stays plan-only/blocked instead of
    /// silently resuming effecting operations.
    ///
    /// # Errors
    ///
    /// Returns the coordinator owner restore rejection, a stale-config
    /// conflict, or a stale/revoked binding rejection unchanged.
    pub fn restore_with_admitted_provider(
        snapshot: FabricSnapshot,
        config: CoordinatorConfig,
        ports: FabricPorts,
        semantic_revisions: Option<&SemanticRevisionStore>,
        capability: AdmittedProviderCapability,
    ) -> Result<Self, FabricError> {
        if snapshot.coordinator_snapshot.config != config {
            return Err(FabricError::IdentityConflict(
                "restore config does not match the snapshotted coordinator config".to_owned(),
            ));
        }
        // Issue #1702: contradictory semantic ownership never restores
        // authority. Legacy snapshots carry no semantic records and pass
        // trivially.
        verify_snapshot_semantics(&snapshot)?;
        verify_snapshot_tool_evidence(&snapshot)?;
        let admission_by_definition = rebuild_admission_by_definition(&snapshot)?;
        let coordinator = AgentCoordinator::restore_with_admitted_provider(
            snapshot.coordinator_snapshot.clone(),
            config.clone(),
            capability,
        )?;
        let mut definition_bytes = BTreeMap::new();
        for (key, definition) in &snapshot.definitions {
            definition_bytes.insert(key.clone(), definition.definition_digest.clone());
        }
        let mut intent_by_operation = BTreeMap::new();
        for (dispatch_id, intent) in &snapshot.intents {
            intent_by_operation.insert(
                dispatch_id.clone(),
                format!(
                    "{}/{}",
                    intent.admission_id.as_str(),
                    intent.attempt_id.as_str()
                ),
            );
        }
        let mut fabric = Self {
            config,
            coordinator,
            ports,
            ledger: snapshot.ledger.clone(),
            definitions: snapshot.definitions,
            definition_bytes,
            reservations: snapshot.reservations,
            admissions: snapshot.admissions,
            admission_by_definition,
            activations: snapshot.activations,
            intents: snapshot.intents,
            intent_by_operation,
            attempt_states: snapshot.attempt_states,
            cancellations: snapshot.cancellations,
            semantic_definitions: snapshot.semantic_definitions,
            semantic_admissions: snapshot.semantic_admissions,
            semantic_executions: snapshot.semantic_executions,
            semantic_supersessions: snapshot.semantic_supersessions,
            staffing_receipts: snapshot.staffing_receipts,
            attempt_routes: snapshot.attempt_routes,
            provider_frames: snapshot.provider_frames,
            tool_results: snapshot.tool_results,
            attempt_degradations: BTreeMap::new(),
            // #1702 W2: same durable carrier as the plan-only restore, so a
            // revision published after a verified restore is committed before
            // it is reported current.
            semantic_revisions: semantic_revisions.cloned(),
            initialized: true,
        };
        fabric.record("fabric_restored_verified", "fabric");
        Ok(fabric)
    }

    /// Restores the fabric on freshly resolved owner material in one call
    /// (issue #1108, verified restore for A8).
    ///
    /// Crate-internal: the only cross-crate restore path is
    /// [`DaemonComposition::agent_fabric_restore_verified`](crate::DaemonComposition::agent_fabric_restore_verified),
    /// which re-resolves the session halves over the live authenticated
    /// session before calling this restore. External callers therefore
    /// cannot restore effecting readiness with caller-held halves alone.
    ///
    /// Builds a fresh capability from `material` — the daemon's per-restore
    /// resolution over its authenticated session (fresh live fence, current
    /// Governor expectation, validated session binding) — then restores
    /// through [`AgentFabric::restore_with_admitted_provider`]. Callers pass
    /// freshly resolved material on every restore: a stored capability is
    /// never reused across restarts, so missing/stale/revoked evidence stays
    /// plan-only/blocked instead of silently resuming effecting operations.
    ///
    /// # Errors
    ///
    /// Returns the capability construction rejection, the coordinator owner
    /// restore rejection, or a stale-config conflict unchanged.
    #[cfg(test)]
    pub(crate) fn restore_verified(
        snapshot: FabricSnapshot,
        config: CoordinatorConfig,
        ports: FabricPorts,
        semantic_revisions: Option<SemanticRevisionStore>,
        material: VerifiedProviderMaterial,
    ) -> Result<Self, FabricError> {
        let capability = build_admitted_provider_capability(material)?;
        Self::restore_with_admitted_provider(
            snapshot,
            config,
            ports,
            semantic_revisions,
            capability,
        )
    }
}

/// Readiness-gated descriptor proving the production daemon caller reaches
/// this composition. Built by `DaemonComposition` from its admitted snapshot;
/// it carries evidence only, never authority.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFabricDescriptor {
    /// Daemon service identity.
    pub service: String,
    /// Admitted resource generation.
    pub generation: u64,
    /// Admitted authority epoch sequence.
    pub authority_epoch: u64,
    /// Coordinator capacity identity threaded for this composition.
    pub capacity_identity: String,
}
