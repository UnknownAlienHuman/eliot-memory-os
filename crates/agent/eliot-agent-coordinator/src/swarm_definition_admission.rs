//! Coordinator-managed admission preparation for one durable-swarm definition (issue #1699).
//!
//! `compile_swarm_definition_admission` accepts a Task Controller-authored
//! `eliot_swarm::SwarmPlanProposal` plus the sealed P1
//! `eliot_swarm::SealedIndependentMaps` and compiles the exact Governor
//! admission artifact through the existing owner entrypoint
//! `eliot_swarm::plan_admission_request`. It applies coordinator-side
//! admission-preparation gates only — a validated coordinator configuration, a
//! non-empty work graph, nonzero WIP ceilings, a work-item count within
//! `CoordinatorConfig::max_ready_items`, and exact plan/root lineage agreement
//! with the sealed-map coordination binding — and returns a candidate-only
//! `SwarmDefinitionAdmissionPrep`.
//!
//! Preparation is strictly pre-admission. No Governor receipt is minted,
//! required, or faked here: actual admission stays with the Governor owner via
//! `eliot_swarm::admit_plan`, which validates the exact admission receipt
//! through the injected receipt verifier. A definition whose prerequisite
//! Governor admission is unavailable is therefore never presented as admitted;
//! the prep carries the exact `eliot_swarm::ProviderRequest` the Governor
//! admission port must seal (`swarm.plan.admit`) together with the sealed-map
//! digest it binds.
//!
//! Launch stays exclusively with the existing injected ports: P3 wave execution
//! through the injected `eliot_swarm::AgentRouteProvider` (A-02) and
//! `eliot_swarm::ReceiptVerificationPort`; staged durable work through the
//! injected `eliot_swarm::durable_work::DurableWorkStore` owner port and
//! `eliot_swarm::durable_work::WorkExecutor` launch port; daemon orchestration
//! through the existing coordinator admission/activation/dispatch seams. This
//! module performs no durable write, owns no task store, attempt journal,
//! scheduler, write authority, or recovery path, and inserts nothing into the
//! Ready Queue: replaying exact inputs reproduces the exact prep value.
//!
//! Proof ceiling: `SWARM_DEFINITION_ADMISSION_PREP_PROOF_ONLY`. Governor
//! admission, Kernel reservation/activation, provider dispatch, mailbox
//! delivery, strict Finish, and Product Pulse remain separate.

use eliot_agent_contracts::RevisionId;
use eliot_receipts::ReceiptEnvelope;
use eliot_swarm::{
    AdmittedSwarmPlan, AgentRouteProvider, ExecutionState, ProviderRequest,
    ReceiptVerificationPort, RootContextRevision, SealedIndependentMaps, SwarmError,
    SwarmPlanProposal, admit_plan, begin_execution, plan_admission_request,
};
use eliot_swarm::adapter_launch::{SealedChildInputs, SealedChildLaunch, launch_sealed_child};
use eliot_swarm::durable_dispatch::DurableJobAttachment;
use eliot_swarm::durable_work::{DurableWorkStore, WorkExecutor};
use serde::Serialize;

use crate::model::{CoordinatorConfig, CoordinatorError};

/// Schema identity for the candidate-only swarm-definition admission-preparation value.
pub const SWARM_DEFINITION_ADMISSION_PREP_VERSION: &str =
    "eliot.swarm-definition-admission-prep/v1";

/// Candidate-only admission preparation for one valid swarm definition.
///
/// The value proves that the Task Controller-authored definition reached
/// coordinator-managed admission preparation over the reachable
/// `eliotd` → `eliot-agent-coordinator` → `eliot-swarm` owner path: the exact
/// Governor admission request is bound, coordinator capacity gates passed, and
/// no admission was claimed. It carries no `WorkLeaseId`, no attempt identity,
/// no route admission receipt, no process control, and no dispatch authority.
/// Launch requires the Governor admission receipt first, then the existing
/// injected admission/activation/dispatch ports; this value alone launches
/// nothing.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SwarmDefinitionAdmissionPrep {
    plan_revision: RevisionId,
    root_context_revision: RootContextRevision,
    maps_digest: String,
    work_item_count: usize,
    global_wip: u32,
    per_route_wip: u32,
    admission_request: ProviderRequest,
}

impl SwarmDefinitionAdmissionPrep {
    /// Frozen Task Controller definition revision this prep was compiled from.
    #[must_use]
    pub fn plan_revision(&self) -> &RevisionId {
        &self.plan_revision
    }

    /// Frozen shared-root revision pinned by the sealed P1 maps.
    #[must_use]
    pub fn root_context_revision(&self) -> &RootContextRevision {
        &self.root_context_revision
    }

    /// Digest of the sealed P1 independent maps bound by the admission request.
    #[must_use]
    pub fn maps_digest(&self) -> &str {
        &self.maps_digest
    }

    /// Number of work items in the definition work graph.
    #[must_use]
    pub const fn work_item_count(&self) -> usize {
        self.work_item_count
    }

    /// Global WIP ceiling echoed from the definition.
    #[must_use]
    pub const fn global_wip(&self) -> u32 {
        self.global_wip
    }

    /// Per-route WIP ceiling echoed from the definition.
    #[must_use]
    pub const fn per_route_wip(&self) -> u32 {
        self.per_route_wip
    }

    /// Exact Governor admission artifact the admission port must seal.
    ///
    /// Its `operation_kind` is `swarm.plan.admit` and its `artifact_digest`
    /// binds the definition plus the sealed-map digest; the Governor admission
    /// receipt is still outstanding when this prep is returned.
    #[must_use]
    pub const fn admission_request(&self) -> &ProviderRequest {
        &self.admission_request
    }
}

/// Compiles coordinator-managed admission preparation for one swarm definition.
///
/// Fail-closed gate order, mirroring `AgentCoordinator::plan` backpressure
/// without consuming capacity or mutating coordinator state:
///
/// 1. coordinator configuration ceiling is usable (`max_ready_items` nonzero);
/// 2. the definition work graph is non-empty;
/// 3. definition WIP ceilings are nonzero;
/// 4. the work-item count fits the coordinator ready-item ceiling, otherwise
///    `CoordinatorError::Backpressure`;
/// 5. proposal plan and root-context revisions equal the sealed-map binding,
///    otherwise `CoordinatorError::IdentityConflict`;
/// 6. the exact Governor admission artifact is compiled through the existing
///    `eliot_swarm::plan_admission_request` owner entrypoint.
///
/// A Governor admission receipt is never required nor produced: unavailable
/// Governor admission leaves the definition in preparation, never admitted.
///
/// # Errors
///
/// Returns `CoordinatorError::InvalidField` for a degenerate configuration or
/// definition, `CoordinatorError::Backpressure` when the work graph alone
/// exceeds the ready-item ceiling, `CoordinatorError::IdentityConflict` when
/// proposal lineage differs from the sealed-map binding, or
/// `CoordinatorError::Serialization` when the admission artifact cannot be
/// canonically digested.
pub fn compile_swarm_definition_admission(
    config: &CoordinatorConfig,
    proposal: &SwarmPlanProposal,
    maps: &SealedIndependentMaps,
) -> Result<SwarmDefinitionAdmissionPrep, CoordinatorError> {
    if config.max_ready_items == 0 {
        return Err(CoordinatorError::InvalidField("max_ready_items"));
    }
    if proposal.work_items.is_empty() {
        return Err(CoordinatorError::InvalidField("swarm_work_items"));
    }
    if proposal.global_wip == 0 || proposal.per_route_wip == 0 || proposal.reduction_fan_in == 0 {
        return Err(CoordinatorError::InvalidField("swarm_wip_ceiling"));
    }
    if proposal.work_items.len() > config.max_ready_items {
        return Err(CoordinatorError::Backpressure {
            active: 0,
            requested: proposal.work_items.len(),
            limit: config.max_ready_items,
        });
    }
    let (bound_plan_revision, bound_root_context_revision) = maps.admission_plan_lineage();
    if proposal.plan_revision != *bound_plan_revision
        || proposal.root_context_revision != *bound_root_context_revision
    {
        return Err(CoordinatorError::IdentityConflict("swarm_lineage"));
    }
    let admission_request = plan_admission_request(proposal, maps)
        .map_err(|_| CoordinatorError::Serialization("swarm plan admission request".to_owned()))?;
    Ok(SwarmDefinitionAdmissionPrep {
        plan_revision: proposal.plan_revision.clone(),
        root_context_revision: proposal.root_context_revision.clone(),
        maps_digest: maps.digest().to_owned(),
        work_item_count: proposal.work_items.len(),
        global_wip: proposal.global_wip,
        per_route_wip: proposal.per_route_wip,
        admission_request,
    })
}

/// Maps one swarm-owner failure onto the coordinator boundary without
/// flattening it: lineage, partition, binding, receipt, replay and route
/// failures keep their exact coordinator variant, and anything outside the
/// coordinator vocabulary keeps its message inside `ProviderContract` rather
/// than becoming a pretended admission or a generic serialization string.
fn swarm_error(error: SwarmError) -> CoordinatorError {
    match error {
        SwarmError::Blank(field)
        | SwarmError::ControlCharacter(field)
        | SwarmError::Empty(field) => CoordinatorError::InvalidField(field),
        SwarmError::Duplicate(field) => CoordinatorError::DuplicateIdentity(field),
        SwarmError::StaleLineage => CoordinatorError::IdentityConflict("swarm_lineage"),
        SwarmError::WrongPartition | SwarmError::OmittedLane => {
            CoordinatorError::IdentityConflict("swarm_partition")
        }
        SwarmError::BindingMismatch
        | SwarmError::AssignmentMismatch
        | SwarmError::LineageMismatch => {
            CoordinatorError::IdentityConflict("swarm_admission_binding")
        }
        SwarmError::InvalidReceipt => {
            CoordinatorError::ProviderVerification("swarm admission receipt".to_owned())
        }
        SwarmError::OwnershipConflict => CoordinatorError::IdentityConflict("swarm_attachment"),
        SwarmError::PayloadConflict => CoordinatorError::IdempotencyConflict,
        SwarmError::RouteBlocked => CoordinatorError::RouteEvidence,
        SwarmError::BudgetExceeded => CoordinatorError::BudgetExceeded,
        SwarmError::Serialization => {
            CoordinatorError::Serialization("swarm plan admission".to_owned())
        }
        other => CoordinatorError::ProviderContract(other.to_string()),
    }
}

/// Admits one prepared swarm definition through the Governor admission owner
/// (issue #1699 R2).
///
/// Fail-closed gate order:
///
/// 1. the prep binds this exact definition: proposal plan and root-context
///    revisions plus the sealed-map digest equal the prep, otherwise
///    `CoordinatorError::IdentityConflict`;
/// 2. the exact Governor admission artifact is admitted through the existing
///    `eliot_swarm::admit_plan` owner entrypoint with the Governor receipt
///    and the injected receipt verifier.
///
/// A missing verifier, a forged or mismatched receipt, or any unavailable
/// prerequisite port fails typed through [`swarm_error`]: the definition is
/// never presented as admitted, so an unavailable prerequisite stays a typed
/// residual instead of a pretended admission. This performs no durable write,
/// owns no task store, attempt journal, scheduler, write authority, or
/// recovery path.
///
/// # Errors
///
/// Returns `CoordinatorError::IdentityConflict` when the prep does not bind
/// the presented definition, or the typed [`swarm_error`] mapping of the
/// owner admission failure otherwise.
pub fn admit_swarm_definition(
    prep: &SwarmDefinitionAdmissionPrep,
    proposal: &SwarmPlanProposal,
    maps: &SealedIndependentMaps,
    admission_receipt: ReceiptEnvelope,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<AdmittedSwarmPlan, CoordinatorError> {
    if proposal.plan_revision != *prep.plan_revision()
        || proposal.root_context_revision != *prep.root_context_revision()
        || maps.digest() != prep.maps_digest()
    {
        return Err(CoordinatorError::IdentityConflict("swarm_lineage"));
    }
    admit_plan(proposal.clone(), maps, admission_receipt, verifier).map_err(swarm_error)
}

/// Begins provider-owned P3 execution for one admitted swarm plan through the
/// injected A-02 activation port (issue #1699 R2).
///
/// This delegates to the existing `eliot_swarm::begin_execution` owner
/// entrypoint: the provider seals the first execution state over the injected
/// `AgentRouteProvider`, bound by the injected receipt verifier to the plan
/// admission. A missing route provider or verifier fails typed through
/// [`swarm_error`]; this performs no durable write and starts no process.
///
/// # Errors
///
/// Returns the typed [`swarm_error`] mapping of the owner activation failure.
pub fn begin_swarm_execution(
    plan: &AdmittedSwarmPlan,
    a02: Option<&dyn AgentRouteProvider>,
    verifier: Option<&dyn ReceiptVerificationPort>,
) -> Result<ExecutionState, CoordinatorError> {
    begin_execution(plan, a02, verifier).map_err(swarm_error)
}

/// Dispatches one sealed swarm child through the existing injected
/// dispatch ports (issue #1699 R2).
///
/// This delegates to the existing `eliot_swarm::adapter_launch` owner path
/// (`launch_sealed_child`): sealed-denominator membership and the
/// plan/attachment owner binding are proved before the dispatch is built and
/// the full envelope is re-verified after. The returned intent is
/// candidate-only: the daemon composition persists it through the owner-side
/// append path (`DurableWorkStore` append) BEFORE calling the executor, so no
/// launched child is omitted from restart accounting. `store` and `executor`
/// pin that feeding seam only; this helper performs no store append and no
/// executor call, owns no scheduler, and inserts nothing into the Ready
/// Queue.
///
/// # Errors
///
/// Returns the typed [`swarm_error`] mapping of the owner dispatch failure:
/// a revoked or stale route is `RouteEvidence` with no fallback, a
/// same-identity changed payload is `IdempotencyConflict`, and an
/// attach-once refusal names the binding conflict.
pub fn launch_swarm_child(
    plan: &AdmittedSwarmPlan,
    attachment: &DurableJobAttachment,
    inputs: SealedChildInputs<'_>,
    store: &dyn DurableWorkStore,
    executor: &dyn WorkExecutor,
) -> Result<SealedChildLaunch, CoordinatorError> {
    launch_sealed_child(store, executor, plan, attachment, inputs).map_err(swarm_error)
}
