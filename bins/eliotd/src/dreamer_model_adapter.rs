//! Governed Dreamer model-call join (T12-07, integration #702, semantic #18).
//!
//! Architecture: A2.3 (contract → ports → adapters layering); A10.4 delegation (one bounded
//! causal join); A0.3 hard boundaries stay fail-closed. Implementation: T12-07 model call
//! through the existing provider execution/verification stack.
//!
//! [`GovernedDreamerModelAdapter::invoke`] joins one staffing request to the existing
//! agent-coordinator execution contour in load-bearing order: Governor readiness plus exact
//! fence binding first, then the current account catalogue plus explicit Human route policy,
//! then deterministic candidate planning through [`AgentCoordinator::plan`], then the
//! attempt/route linkage pre-check, then exactly one provider execution through the
//! [`DreamerModelExecution`] port, then the sealed-intake result binding through
//! [`AgentResult::validate_for_binding`]. Every failure fails closed before provider budget
//! is spent, and a wrong or stale attempt/route receipt is rejected before the port is
//! touched.
//!
//! Delegation boundary (delegate, never copy):
//!
//! - candidate planning is [`AgentCoordinator::plan`]; planning runs on a plan-only
//!   coordinator carrying the explicit typed [`PlanGap::G11Unavailable`], which the
//!   coordinator owner keeps available for planning while providers are gapped;
//! - Governor admission is the readiness plus exact-fence gate plus the externally issued
//!   [`AdmittedRouteReceipt`] shape check — this helper never mints admission, and the
//!   sealed per-proof verification (`Binding`/`Result` through the coordinator
//!   `admit`/`bind_provider_execution`/`submit_result` path over the sealed
//!   `KernelProviderVerifier`) stays owned by the coordinator and is neither bypassed nor
//!   reimplemented here;
//! - provider execution is the [`DreamerModelExecution`] port: production binds the single
//!   owner-approved admitted route only. `OpenCodeClient::run_read_only` yields
//!   `NoAuthorityRunResult` and is explicitly non-admitted, so it can never satisfy this
//!   port: the port returns [`AgentResult`], a different type whose linkage closes through
//!   [`AgentResult::validate_for_binding`];
//! - sealed-intake verification recomputes every digest through the shared owner
//!   validators ([`AdmittedRouteReceipt::validate`],
//!   [`ProviderExecutionBinding::validate_internal`],
//!   [`PhysicalRouteObservationReceipt::validate_against`] inside
//!   [`AgentResult::validate_for_binding`]). There is no `always_verified` verifier in this
//!   crate: every check recomputes, and a stale, foreign, or conflicting presentation fails
//!   closed.
//!
//! Preservation: requested, logical (admitted), and observed route identities cross
//! unchanged and are linkage-checked, never rewritten; usage, cancellation, and unknown
//! outcomes ride inside the returned [`AgentResult`] verbatim — an `UnknownOutcome`
//! disposition keeps its reason and is never converted to success. There is no vendor
//! hardcoding (routes compare as whole [`RouteFingerprint`] values; no provider, model, or
//! host string is ever matched) and no silent fallback: a lane without a selected route, a
//! route outside the current account catalogue, or a failed linkage errors instead of
//! substituting another route.
//!
//! Catalogue and Human policy use: the caller threads the current account
//! [`ModelCatalogueSnapshot`] and the explicit [`HumanModelPreferencePolicy`] per call (no
//! default policy is ever invented here). Both are shape-validated, their account scopes
//! must agree, the snapshot must be current at `now_unix_ms`, the policy must govern the
//! [`ModelRole::Dreamer`] role, and every planned selected route must be a member of the
//! current catalogue by full-fingerprint equality. Per-role preferred/denied compilation
//! (`compile_model_selection`) stays owned by the coordinator model-control cell and is
//! consumed at request-construction time by the caller through lane preference-rank
//! evidence; the binary adds no second policy evaluator.
//!
//! Like the T12-06 intake shape, this module imports no `eliot-dreamer-orientation` leaf
//! (GAP-1 orientation root-excluded is inherited, not reopened): the join is typed over
//! staffing/admission/binding/result contracts only.
//!
//! [`AgentCoordinator::plan`]: eliot_agent_coordinator::AgentCoordinator::plan
//! [`PlanGap::G11Unavailable`]: eliot_agent_coordinator::PlanGap::G11Unavailable
//! [`PhysicalRouteObservationReceipt::validate_against`]:
//!     eliot_agent_api::PhysicalRouteObservationReceipt::validate_against

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentResult, AttemptId, ExecutionOutcome, LowercaseSha256,
    ProviderExecutionBinding, ResultDisposition, RouteFingerprint, RouteObservationState,
};
use eliot_agent_coordinator::{
    AgentCoordinator, CoordinatorConfig, HumanModelPreferencePolicy, ModelCatalogueSnapshot,
    ModelRole, PlanGap, ProviderIdentity, RoleProfileId, StaffingPlanCandidate,
    StaffingPlanRequest,
};
use eliot_agent_api::WorkUnitId;
use eliot_agent_opencode::{OpenCodeClient, OpenCodeRouteAdmission};
use eliot_read::LocalReadPort;
use eliot_contracts::{
    ClockReading, ContractIdentity, ContractVersion, ProductId, RequestId, RequestMetadata,
    SourceId, StateFence, canonical_json_bytes, contract_identity,
};
use eliot_governor::{CompositionError, CompositionReadiness, RouteScopeFingerprint};
use eliot_protocol::{ContinuityKind, dreamer_job::ProviderStaffingRuntimeSourcePublication};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::capability_admission::{
    CapabilityEvidenceRecord, CapabilityEvidenceStatus, DynamicCapabilityPulse,
    ProductionAdmissionRequest, ProductionEvidenceBundle, StaticCapabilityAttestation,
    admit_production_route, canonical_required_set,
};
use super::capability_evidence_wiring::GovernorCapabilityAdmission;
use super::capability_outcome::{
    AttemptReceipt, CapabilityOutcome, CapabilityRegistryView, DegradationProjection,
    FallbackOutcomeRequest, GenerationChallengeOutcomeRequest, MAX_REFS, OutcomeDisposition,
    fallback_outcome, generation_challenge_outcome, project_degradation, removed_promise,
    surviving_operation,
};
use super::route_execution_identity::{
    DeclaredRoute, LaunchAuthority, RouteIdentityError, admit_declared_launch, declared_continuity,
    declared_route_key,
};
use super::route_receipts::{RuntimeObservedFacts, effective_route_key};
use super::{DaemonComposition, DaemonKernelClient, SERVICE_NAME, kernel_port_error};

/// Contract name for the explicit daemon/provider staffing source used by
/// one native Orientation execution.
pub const DREAMER_PROVIDER_STAFFING_RUNTIME_SOURCE_CONTRACT_NAME: &str =
    "eliot.dreamer.provider-staffing-runtime-source";
/// Contract version for the provider staffing source.
pub const DREAMER_PROVIDER_STAFFING_RUNTIME_SOURCE_CONTRACT_VERSION: ContractVersion =
    ContractVersion::new(1, 0, 0);
const DREAMER_PROVIDER_STAFFING_RUNTIME_SOURCE_SCHEMA_VERSION: u32 = 1;

/// Native provider-runtime configuration carried unchanged by the original
/// source publication. Staffing, recipe, role, launch, privacy, capacity and
/// provider identity all remain values issued by their existing owners; this
/// profile does not synthesize them from the model selection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DreamerProviderStaffingRuntimeProfile {
    /// Exact profile schema version.
    pub schema_version: u32,
    /// Canonical DreamJobAdmission identity this profile was issued for.
    pub admitted_job_id: String,
    /// Provider identity supplied by the configured provider owner.
    pub provider_identity: ProviderIdentity,
    /// Original explicit staffing request, including recipe and launch data.
    pub staffing_request: StaffingPlanRequest,
    /// Exact lane this Orientation call is authorized to use.
    pub orientation_work_unit_id: WorkUnitId,
    /// Exact role profile for the Orientation lane.
    pub orientation_role_id: RoleProfileId,
}

/// Rejection while resolving one original provider-staffing source.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum DreamerProviderStaffingRuntimeProfileError {
    /// The outer source reference or bytes are invalid.
    #[error("provider staffing source publication is invalid: {0}")]
    Publication(String),
    /// The content reference names another source contract.
    #[error("provider staffing source contract identity does not match the runtime schema")]
    ContractIdentity,
    /// The source carries another profile revision.
    #[error("provider staffing source has an unsupported schema version")]
    SchemaVersion,
    /// The selected route, job, bundle, or provider capacity differs from
    /// the exact original staffing owner input.
    #[error("provider staffing source does not bind the admitted Orientation operation")]
    OperationBinding,
}

impl DreamerProviderStaffingRuntimeProfile {
    /// Returns the content-addressed profile contract identity.
    pub fn contract_identity(
    ) -> Result<ContractIdentity, DreamerProviderStaffingRuntimeProfileError> {
        let shape = serde_json::json!({
            "schema_version": DREAMER_PROVIDER_STAFFING_RUNTIME_SOURCE_SCHEMA_VERSION,
            "admitted_job_id": "DreamJobAdmission::canonical_id()",
            "provider_identity": "eliot_agent_coordinator::ProviderIdentity",
            "staffing_request": "eliot_agent_coordinator::StaffingPlanRequest",
            "orientation_work_unit_id": "eliot_agent_coordinator::WorkUnitId",
            "orientation_role_id": "eliot_agent_coordinator::RoleProfileId",
        });
        contract_identity(
            DREAMER_PROVIDER_STAFFING_RUNTIME_SOURCE_CONTRACT_NAME,
            DREAMER_PROVIDER_STAFFING_RUNTIME_SOURCE_CONTRACT_VERSION,
            &shape,
        )
        .map_err(|_| DreamerProviderStaffingRuntimeProfileError::ContractIdentity)
    }

    /// Decodes only the exact, original canonical source publication.
    pub fn from_publication(
        publication: &ProviderStaffingRuntimeSourcePublication,
    ) -> Result<Self, DreamerProviderStaffingRuntimeProfileError> {
        publication
            .validate()
            .map_err(|error| DreamerProviderStaffingRuntimeProfileError::Publication(error.to_string()))?;
        if publication.reference.contract != Self::contract_identity()? {
            return Err(DreamerProviderStaffingRuntimeProfileError::ContractIdentity);
        }
        let profile: Self = serde_json::from_slice(&publication.canonical_bytes)
            .map_err(|error| DreamerProviderStaffingRuntimeProfileError::Publication(error.to_string()))?;
        if profile.schema_version != DREAMER_PROVIDER_STAFFING_RUNTIME_SOURCE_SCHEMA_VERSION {
            return Err(DreamerProviderStaffingRuntimeProfileError::SchemaVersion);
        }
        if canonical_json_bytes(&profile)
            .map_err(|error| DreamerProviderStaffingRuntimeProfileError::Publication(error.to_string()))?
            != publication.canonical_bytes
        {
            return Err(DreamerProviderStaffingRuntimeProfileError::Publication(
                "typed provider staffing profile differs from its original canonical bytes".to_owned(),
            ));
        }
        Ok(profile)
    }

    /// Joins the explicit profile lane to the original job/bundle and exact
    /// model route selected by the current catalogue and Human policy.
    pub fn validate_for_orientation(
        &self,
        job: &eliot_dreamer_contracts::DreamJobInput,
        admission: &eliot_dreamer_contracts::DreamJobAdmission,
        bundle: &eliot_dreamer_contracts::DreamInputBundle,
        selected_route: &eliot_agent_api::RouteFingerprint,
    ) -> Result<(), DreamerProviderStaffingRuntimeProfileError> {
        let request = &self.staffing_request;
        if self.schema_version != DREAMER_PROVIDER_STAFFING_RUNTIME_SOURCE_SCHEMA_VERSION
            || self.admitted_job_id != admission.canonical_id()
            || self.admitted_job_id != bundle.job_id
            || admission.job_class != job.job_class
            || admission.requester.principal != job.requester
            || admission.scope_id != job.scope_id
            || admission.scope_id != bundle.scope_id
            || admission.task_id != bundle.task_id
            || admission.privacy_profile != job.privacy_profile
            || admission.state_fence != job.state_fence
            || request.launch.task_id.as_str() != bundle.task_id
            || request.state_fence != bundle.state_fence
            || request.state_fence != job.state_fence
        {
            return Err(DreamerProviderStaffingRuntimeProfileError::OperationBinding);
        }
        let lane = request.lanes.iter().find(|lane| {
            lane.work_unit_id == self.orientation_work_unit_id
                && lane.role_id == self.orientation_role_id
        });
        let Some(lane) = lane else {
            return Err(DreamerProviderStaffingRuntimeProfileError::OperationBinding);
        };
        let route = lane
            .route_candidates
            .iter()
            .find(|candidate| candidate.route == *selected_route);
        let Some(route) = route else {
            return Err(DreamerProviderStaffingRuntimeProfileError::OperationBinding);
        };
        if route.capacity_identity != self.provider_identity.capacity_identity
            || route.capacity_revision != self.provider_identity.capacity_revision
            || selected_route.provider.trim().is_empty()
            || selected_route.model.trim().is_empty()
        {
            return Err(DreamerProviderStaffingRuntimeProfileError::OperationBinding);
        }
        Ok(())
    }
}

/// Closed model-execution port behind the governed invoke.
///
/// Production binds the single owner-approved admitted provider execution: exactly one
/// [`AgentResult`] per planned candidate under the presented admission and binding. Tests
/// bind a recording responder owned by the test: the port never admits, so a test double
/// can only answer an already-admitted attempt, never admit one itself.
///
/// The port implementation must echo the presented admission and binding verbatim into the
/// result's physical observation linkage (`admitted_route_digest` equals the admission
/// `self_digest`, `binding` equals the presented binding); the post-execution
/// [`AgentResult::validate_for_binding`] gate rejects anything else.
///
/// The method desugars to a lifetime-bound `impl Future` (rather than `async fn`) so no
/// `async_fn_in_trait` lint is introduced.
pub trait DreamerModelExecution {
    /// Executes one planned candidate under exact admission and binding.
    fn execute(
        &self,
        candidate: &StaffingPlanCandidate,
        admission: &AdmittedRouteReceipt,
        binding: &ProviderExecutionBinding,
    ) -> impl Future<Output = Result<AgentResult, CompositionError>>;
}

/// Concrete adapter from the configured OpenCode runtime owner to the
/// production CC-002 Orientation worker. It borrows the live OpenCode client
/// and its retained route-admission record; it neither constructs attempt
/// authority nor substitutes an unadmitted `run_read_only` call.
pub struct ConfiguredDreamerOrientationModelOwner<'a> {
    client: &'a OpenCodeClient,
    route_admission: &'a OpenCodeRouteAdmission,
}

impl<'a> ConfiguredDreamerOrientationModelOwner<'a> {
    /// Borrows the current configured provider runtime and its exact route
    /// admission evidence.
    #[must_use]
    pub const fn new(
        client: &'a OpenCodeClient,
        route_admission: &'a OpenCodeRouteAdmission,
    ) -> Self {
        Self {
            client,
            route_admission,
        }
    }

    /// Executes one admitted Orientation model call through the real
    /// OpenCode route owner. The worker returns the exact owner outcome or
    /// typed refusal with any already-observed raw bytes, usage, and route
    /// receipts still attached.
    pub async fn execute_admitted_orientation<R: LocalReadPort>(
        &self,
        input: super::dreamer_orientation_model_worker::DreamerOrientationModelWorkerInput<'_, R>,
    ) -> Result<
        super::dreamer_orientation_model::DreamerOrientationModelAttempt,
        super::dreamer_orientation_model_worker::DreamerOrientationModelWorkerError,
    > {
        super::dreamer_orientation_model_worker::execute_admitted_orientation_model(
            self.client,
            self.route_admission,
            input,
        )
        .await
    }
}

/// One governed model invocation: staffing request plus the current catalogue, explicit
/// Human policy, observation time, and the externally issued admission and binding the
/// execution must run under.
///
/// `catalogue` and `policy` are the live account inputs threaded per call; `now_unix_ms`
/// is the Unix-millisecond clock reading the catalogue currentness is checked against.
/// `admission` rides from the external admission owner (never minted here) and `binding`
/// is the exact provider-execution binding the port must execute under. The effect
/// ceiling is taken from `request.launch.effect_ceiling`, never supplied twice.
#[derive(Clone, Debug)]
pub struct ModelInvokeInput {
    /// Deterministic staffing request compiled by [`AgentCoordinator::plan`].
    pub request: StaffingPlanRequest,
    /// Current account model catalogue; must be current at `now_unix_ms`.
    pub catalogue: ModelCatalogueSnapshot,
    /// Explicit Human route policy; must govern the Dreamer role.
    pub policy: HumanModelPreferencePolicy,
    /// Unix-millisecond observation time for catalogue currentness.
    pub now_unix_ms: u64,
    /// Externally issued admitted route decision for the attempt.
    pub admission: AdmittedRouteReceipt,
    /// Exact provider-execution binding the attempt runs under.
    pub binding: ProviderExecutionBinding,
    /// Caller-threaded attempt identity for the Governor route-attempt
    /// receipt (issue #228 A1). Must equal the binding attempt (already
    /// linkage-verified against the admission attempt before the gate);
    /// a mismatch fails the gate closed.
    pub attempt_id: AttemptId,
    /// Caller-observed runtime route facts for the Governor route-attempt
    /// receipt (issue #228 A1): handshake, transport metadata, or
    /// equivalent evidence-bearing observations. `None` fails the gate
    /// closed; facts are never derived here from the bound route.
    pub observed_facts: Option<RuntimeObservedFacts>,
    /// Caller-observed capability evidence records for the funnel side of
    /// the capability gate (issue #1959). Threaded per call from the
    /// retained Governor registry snapshots plus probe/handshake observers;
    /// windows are owner-set, never minted here.
    pub evidence_records: Vec<CapabilityEvidenceRecord>,
    /// Static attestation for critical capabilities, if the capability is
    /// critical. `None` for non-critical capabilities.
    pub static_attestation: Option<StaticCapabilityAttestation>,
    /// Fresh pulse for critical capabilities, if the capability is critical.
    /// `None` for non-critical capabilities.
    pub pulse: Option<DynamicCapabilityPulse>,
    /// Caller-observed route scope for the adopted registry side of the
    /// capability gate (issue #1957). Threaded per call from handshake or
    /// transport observations; never derived here from the bound route.
    /// `None` leaves the registry side unevaluable and fails the gate
    /// closed.
    pub evidence_scope: Option<RouteScopeFingerprint>,
    /// Caller-observed live Kernel fence at invoke time (the current
    /// snapshot boundary). The admitted fence is the startup boundary;
    /// `eliotd` and Kernel may not evaluate different semantic snapshots
    /// (I1.8), so the admitted fence must stay compatible with the live
    /// fence or the invoke fails closed on rotation instead of admitting
    /// on stale evidence.
    pub current_fence: StateFence,
    /// Kernel-issued active-generation projection for this invoke (R4),
    /// threaded per call once the authenticated generation query lands.
    /// `None` while the query is unserved: cold and honest — outcomes carry
    /// an empty (unknown) fingerprint, never an inferred or defaulted one.
    pub kernel_generation: Option<KernelGenerationProjection>,
    /// Declared execution identity and route policy of the bound route
    /// (issue #1816, I10.3–I10.7): the canonical route fingerprint plus the
    /// declared `service | interactive_user | remote` identity and the
    /// retention/network and workspace/scope policy that identity runs under.
    /// `None` fails the gate closed — a route with no declared execution
    /// identity is not launchable, and the identity is never inferred from
    /// the route, the host, or the process account.
    pub declared_route: Option<DeclaredRoute>,
    /// The surface through which this launch reached the daemon. An
    /// `INTERACTIVE_USER` route is admitted only under
    /// [`LaunchAuthority::UserBrokerDelegated`]; a launch that claims a
    /// user-desktop identity without resolving to the authorized User Broker
    /// is refused.
    pub launch_authority: LaunchAuthority,
    /// The declared route recorded for the session this invoke would
    /// continue, or `None` for a fresh attempt. A changed declaration yields
    /// an explicit rehydrated new attempt instead of silent continuation,
    /// and a carried session across such a change is refused.
    pub resumed_from: Option<DeclaredRoute>,
}

/// Kernel-issued active-generation projection observation (R4).
///
/// The fingerprint is the canonical SHA-256 scheme computed by the Kernel
/// Generation Registry from live owned state (route scope, active
/// generation, lineage-aware epoch, exact State Fence); the fence is the
/// projection's exact admitted fence. Both arrive caller-observed per call
/// and are validated here: the fingerprint must parse as lowercase SHA-256
/// and the fence must equal the admitted fence exactly, or the invoke fails
/// closed. Nothing here mints, aliases, or substitutes a Config digest.
#[derive(Clone, Debug)]
pub struct KernelGenerationProjection {
    /// Canonical fingerprint in lowercase hexadecimal (64 chars).
    pub fingerprint: String,
    /// Exact State Fence the projection was issued under.
    pub fence: StateFence,
}

/// Thin governed Dreamer model-call adapter over the retained daemon owners.
///
/// Holds only a borrow of the composition, retains no client and no thread, and changes
/// no lifecycle: callers take a fresh adapter per operation through
/// [`DaemonComposition::dreamer_model`], so a Governor refresh surfaces as an exact fence
/// mismatch instead of silent divergence. Unlike the T12-06 intake adapter this slice
/// performs no Kernel reads — catalogue, policy, admission, binding, and the
/// caller-opened attempt receipt arrive threaded per call, the Governor
/// capability admission view is borrowed from the retained composition, and
/// the outcome registry view is locked from that same composition so a broad
/// degradation outcome outlives the attempt that recorded it, and
/// execution leaves through the [`DreamerModelExecution`] port — so no
/// Kernel client is retained here.
pub struct GovernedDreamerModelAdapter<'a> {
    composition: &'a DaemonComposition,
}

impl<'a> GovernedDreamerModelAdapter<'a> {
    /// Borrows the retained composition. No new session, no thread.
    #[must_use]
    pub const fn new(composition: &'a DaemonComposition) -> Self {
        Self { composition }
    }

    /// Builds the fence-bound route context for the admitted snapshot.
    ///
    /// Pure registration check with no I/O: validates the admitted fence and the derived
    /// request metadata. Used once at attach time by the daemon runtime and on every
    /// invoke.
    pub fn model_route_context(&self) -> Result<RequestMetadata, CompositionError> {
        let admitted = self.composition.kernel_snapshot().state_fence();
        admitted
            .validate()
            .map_err(|error| owner_error(format!("dreamer model admitted fence: {error}")))?;
        model_read_context(&admitted)
    }

    /// Invokes one governed model call and returns its verified candidate result.
    ///
    /// Order is load-bearing: Governor readiness, catalogue plus Human-policy admission,
    /// fence join, candidate planning, attempt/route linkage, the C1 capability
    /// join over the daemon-held Governor admission view (registry plus funnel
    /// over the canonical required set at the admitted generation), exactly
    /// one port execution, then the sealed-intake result binding plus the
    /// call-scoped result-intake join on the caller-threaded receipt. Any
    /// earlier failure returns before the port is touched, so no provider
    /// budget is spent on a wrong or stale receipt; usage, cancellation, and
    /// unknown outcomes in the returned result cross unchanged.
    pub async fn invoke(
        &self,
        coordinator_config: &CoordinatorConfig,
        input: &ModelInvokeInput,
        intake: &mut AttemptReceipt,
        execution: &impl DreamerModelExecution,
    ) -> Result<AgentResult, CompositionError> {
        let admitted = self.composition.kernel_snapshot().state_fence();
        let readiness = self.composition.readiness();
        let ctx = self.model_route_context()?;
        if ctx.state_fence != admitted {
            return Err(owner_error(
                "dreamer model route context does not match the admitted snapshot",
            ));
        }
        let registry = self
            .composition
            .capability_admission()
            .map_err(|_| CompositionError::NotReady)?;
        // The outcome registry is daemon-held (#1961), not per call: a
        // generation-scope block recorded here must still be refusing the
        // next attempt. The handle is borrowed, not locked, so the gate locks
        // it only for its own synchronous decision and no guard is ever held
        // across the provider execution await below.
        let outcomes = self
            .composition
            .capability_outcomes()
            .map_err(|_| CompositionError::NotReady)?;
        invoke_admitted_model(
            readiness,
            &admitted,
            coordinator_config,
            registry,
            outcomes,
            input,
            intake,
            execution,
        )
        .await
    }
}

/// Builds the fence-bound read metadata for the governed model route.
pub(crate) fn model_read_context(
    admitted_fence: &StateFence,
) -> Result<RequestMetadata, CompositionError> {
    let context = RequestMetadata {
        request_id: RequestId::new("eliotd:dreamer:model:route")
            .map_err(|error| owner_error(format!("dreamer model route context: {error}")))?,
        session_id: None,
        task_id: None,
        product_id: ProductId::new(SERVICE_NAME)
            .map_err(|error| owner_error(format!("dreamer model route context: {error}")))?,
        source_id: SourceId::new(SERVICE_NAME)
            .map_err(|error| owner_error(format!("dreamer model route context: {error}")))?,
        state_fence: admitted_fence.clone(),
        clock: ClockReading {
            valid_time_ms: None,
            known_time_ms: None,
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    context
        .validate()
        .map_err(|error| owner_error(format!("dreamer model route context: {error}")))?;
    Ok(context)
}

/// Admits the current account catalogue plus explicit Human route policy for one invoke.
///
/// Shape-validates both through their owners, requires agreeing account scopes, requires
/// a current snapshot at `now_unix_ms`, and requires the policy to govern the Dreamer
/// role: a model call outside explicit Human Dreamer policy fails closed here, before any
/// planning or execution.
pub(crate) fn admit_model_route_policy(
    catalogue: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
    now_unix_ms: u64,
) -> Result<(), CompositionError> {
    catalogue
        .validate()
        .map_err(|error| owner_error(format!("dreamer model catalogue: {error}")))?;
    policy
        .validate()
        .map_err(|error| owner_error(format!("dreamer model Human policy: {error}")))?;
    if catalogue.account_scope != policy.account_scope {
        return Err(owner_error(
            "dreamer model catalogue does not match the Human policy account scope",
        ));
    }
    if !catalogue.is_current(now_unix_ms) {
        return Err(owner_error(
            "dreamer model catalogue is stale at the observation time",
        ));
    }
    if !policy
        .roles
        .iter()
        .any(|preference| preference.role == ModelRole::Dreamer)
    {
        return Err(owner_error(
            "dreamer model Human policy does not govern the Dreamer role",
        ));
    }
    Ok(())
}

/// Verifies the attempt/route linkage before any provider execution.
///
/// Validates admission and binding shapes through their owners, then enforces exact
/// attempt, lease, fence, generation, and route agreement between them, requires the
/// admission to select exactly the bound route (a no-route admission authorizes no
/// execution), requires the bound route to be one the planned candidate actually
/// selected (no silent substitution), and requires full-fingerprint membership in the
/// current account catalogue (never a vendor/model string match). A wrong or stale
/// receipt fails closed here; the execution port is never reached.
pub(crate) fn verify_model_attempt_linkage(
    admitted_fence: &StateFence,
    candidate: &StaffingPlanCandidate,
    catalogue: &ModelCatalogueSnapshot,
    admission: &AdmittedRouteReceipt,
    binding: &ProviderExecutionBinding,
) -> Result<(), CompositionError> {
    admission
        .validate()
        .map_err(|error| owner_error(format!("dreamer model admission: {error}")))?;
    binding
        .validate_internal()
        .map_err(|error| owner_error(format!("dreamer model binding: {error}")))?;
    if admission.state_fence != *admitted_fence || binding.state_fence != *admitted_fence {
        return Err(owner_error(
            "dreamer model admission/binding fence is stale",
        ));
    }
    if binding.attempt_id != admission.attempt_id {
        return Err(owner_error(
            "dreamer model attempt receipt does not match the admitted attempt",
        ));
    }
    if binding.lease_id != admission.lease_id {
        return Err(owner_error(
            "dreamer model lease does not match the admitted lease",
        ));
    }
    if binding.runtime_generation != admission.runtime_generation {
        return Err(owner_error(
            "dreamer model runtime generation does not match the admitted generation",
        ));
    }
    if binding.route != admission.requested_route {
        return Err(owner_error(
            "dreamer model route does not match the admitted requested route",
        ));
    }
    match &admission.selected_route {
        Some(selected) if *selected == binding.route => {}
        _ => {
            return Err(owner_error(
                "dreamer model admission does not select the bound route",
            ));
        }
    }
    let planned = candidate
        .lanes
        .iter()
        .any(|lane| lane.routing.selected.as_ref() == Some(&binding.route));
    if !planned {
        return Err(owner_error(
            "dreamer model route was not selected by the planned candidate",
        ));
    }
    let catalogued = catalogue
        .entries
        .iter()
        .any(|entry| entry.route == binding.route);
    if !catalogued {
        return Err(owner_error(
            "dreamer model route is not in the current account catalogue",
        ));
    }
    Ok(())
}

/// Proof ceiling recorded on call-scoped result-intake outcomes.
///
/// Always the weakest candidate ceiling: a degraded or diverged execution
/// proves at most one bounded candidate artifact for its exact execution
/// unit, never task completion. The spelling matches the owner
/// [`ProofCeiling::CandidateArtifact`](eliot_agent_api::ProofCeiling)
/// vocabulary; a unit test below asserts the sync so the intake marker
/// cannot drift from the contract enum.
const INTAKE_PROOF_CEILING: &str = "CANDIDATE_ARTIFACT";

/// Recovery marker recorded on call-scoped result-intake outcomes.
///
/// Names the only defined recovery path: requalification of the exact
/// fingerprint on fresh evidence (the `Defer` disposition contract). A
/// static marker, never a schedule: no freshness window is minted here.
const INTAKE_RECOVERY: &str = "requalify-exact-fingerprint-on-fresh-evidence";

/// Effective mode recorded on an outcome for a call that never executed.
///
/// The execution port is not touched on a capability refusal, so there is no
/// fallback mode to report. `none` is the honest effective mode; naming any
/// other mode would claim a substitution this module forbids.
const REFUSED_EFFECTIVE_MODE: &str = "none";

/// Proof ceiling recorded on a refused call or a blocked generation.
///
/// The weakest [`ProofCeiling`](eliot_receipts::ProofCeiling) value: the
/// degraded execution proves at most that the refusal was observed. It
/// subtracts the candidate-artifact, scoped-verification, and
/// observed-external-effect promises instead of reporting the incomplete
/// state as complete.
const REFUSED_PROOF_CEILING: &str = "OBSERVATION";

/// Recovery marker recorded on a call-scoped capability refusal.
///
/// A refused call carries no sticky block: the next attempt is admitted on
/// its own evidence through the same gate. This is the acceptance-visible
/// half of "later attempts remain eligible for their own evidence-based
/// admission".
const CALL_RECOVERY: &str = "re-admit-next-attempt-on-its-own-fresh-evidence";

/// Refusal context naming the adopted Governor registry side of the gate.
const REGISTRY_REFUSAL_CONTEXT: &str = "governor capability registry";

/// Refusal context naming the production admission funnel side of the gate.
const FUNNEL_REFUSAL_CONTEXT: &str = "production admission";

/// Refusal context naming the declared execution-identity and route-fingerprint
/// side of the gate (issue #1816, I10.3).
const EXECUTION_IDENTITY_REFUSAL_CONTEXT: &str = "declared route execution identity";

/// The capability this gate tests when it refuses: the route's declared
/// execution identity and the route fingerprint that declares it.
const EXECUTION_IDENTITY_CAPABILITY: &str = "route.execution_identity";

/// Recovery marker recorded on a generation-scoped challenge failure.
///
/// Names the TWO recovery paths this crate can actually perform, and only
/// those: reaching the owner-set expiry carried on the outcome, or the
/// gate's explicit requalification — [`CapabilityRegistryView`]'s
/// `requalify_generation`, wired in [`refuse_blocked_generation`] to fire
/// when the caller-threaded evidence carries fresh positive
/// (`probe_passed`/`observed`) standing on the exact route and generation
/// with no contradictory fresh negative standing. A requalification the
/// daemon cannot perform is never named here.
const GENERATION_RECOVERY: &str =
    "reach-outcome-expiry-or-requalify-exact-fingerprint-on-fresh-positive-evidence";

/// What survives every degradation this gate records (A13.11).
///
/// The capability is subtracted, not the installation: deterministic memory,
/// state, and tools keep working, and the attempt receipt that carries the
/// outcome is itself retained evidence.
const SURVIVES_DETERMINISTIC_CORE: &str = "deterministic-memory-state-tools-and-partial-work";
/// The attempt receipt outlives the refusal that produced it.
const SURVIVES_ATTEMPT_RECEIPT: &str = "attempt-receipt-carrying-this-outcome";
/// A blocked generation leaves every other generation fingerprint alone.
const SURVIVES_OTHER_GENERATIONS: &str = "attempts-on-other-generation-fingerprints";
/// Candidate artifact for the affected attempt is removed.
const REMOVES_CANDIDATE_ARTIFACT: &str = "candidate-artifact-on-this-attempt";
/// Verified finish for the affected attempt is removed.
const REMOVES_VERIFIED_FINISH: &str = "verified-finish-on-this-attempt";

/// Truthful subtraction projection for one refused or blocked call.
///
/// Reports both sides A13.11 requires: what keeps working and which promises
/// the degradation removes, on the affected attempt.
fn call_degradation_projection() -> Vec<String> {
    vec![
        surviving_operation(SURVIVES_DETERMINISTIC_CORE),
        surviving_operation(SURVIVES_ATTEMPT_RECEIPT),
        removed_promise(REMOVES_CANDIDATE_ARTIFACT),
        removed_promise(REMOVES_VERIFIED_FINISH),
    ]
}

/// Truthful subtraction projection for one blocked generation fingerprint.
///
/// Adds the surviving sibling generations: the block is keyed to the exact
/// generation/route fingerprint and never widens to the installation.
fn generation_degradation_projection() -> Vec<String> {
    vec![
        surviving_operation(SURVIVES_DETERMINISTIC_CORE),
        surviving_operation(SURVIVES_OTHER_GENERATIONS),
        surviving_operation(SURVIVES_ATTEMPT_RECEIPT),
        removed_promise(REMOVES_CANDIDATE_ARTIFACT),
        removed_promise(REMOVES_VERIFIED_FINISH),
    ]
}

/// Renders one adopted outcome's subtraction projection into bounded text.
///
/// Keeps the refusal reason and the surviving/removed split in the same
/// string, so a caller that only surfaces the error still shows the reduced
/// promises instead of a bare failure.
fn render_projection(projection: &DegradationProjection) -> String {
    let surviving = if projection.surviving_operations.is_empty() {
        "none recorded".to_owned()
    } else {
        projection.surviving_operations.join(", ")
    };
    let removed = if projection.removed_promises.is_empty() {
        "none recorded".to_owned()
    } else {
        projection.removed_promises.join(", ")
    };
    let evidence = if projection.evidence_refs.is_empty() {
        "absent".to_owned()
    } else {
        projection.evidence_refs.join(", ")
    };
    format!(
        "scope={:?} owner={} generation={} proof-ceiling={} survives=[{}] removed=[{}] evidence=[{}]",
        projection.degradation_scope,
        projection.scope_owner,
        if projection.generation_fingerprint.is_empty() {
            "unknown".to_owned()
        } else {
            projection.generation_fingerprint.clone()
        },
        projection.proof_ceiling,
        surviving,
        removed,
        evidence
    )
}

/// Core model-call flow over explicit authority values.
///
/// `readiness`, `admitted_fence`, and `coordinator_config` must come from the live
/// composition and the daemon-threaded capacity view (see
/// [`GovernedDreamerModelAdapter::invoke`]); `registry` is the daemon-held
/// Governor capability admission view; `intake` is the caller-opened attempt
/// receipt for the bound attempt, carrying the call-scoped outcomes of this
/// invoke. Tests supply exact values directly. The execution port is touched
/// only after every read-only gate passes, and the returned result is the
/// port's candidate bound by [`AgentResult::validate_for_binding`] —
/// requested, logical, and observed identities plus usage, cancellation, and unknown
/// outcomes cross unchanged and are never rewritten here.
#[allow(
    clippy::too_many_arguments,
    reason = "the gate threads the identities the owner requires per invoke plus the held outcome registry handle; a struct would duplicate the owner's own request shape"
)]
pub(crate) async fn invoke_admitted_model(
    readiness: CompositionReadiness,
    admitted_fence: &StateFence,
    coordinator_config: &CoordinatorConfig,
    registry: &GovernorCapabilityAdmission,
    outcomes: &std::sync::Mutex<CapabilityRegistryView>,
    input: &ModelInvokeInput,
    intake: &mut AttemptReceipt,
    execution: &impl DreamerModelExecution,
) -> Result<AgentResult, CompositionError> {
    if readiness != CompositionReadiness::Ready {
        return Err(CompositionError::NotReady);
    }
    // Issue #1834 (I10.11): every model provider adapter runs under one
    // governed transport policy. The default deadlines, bounded retries, and
    // byte limits validate before any planning or execution, so the
    // execution-port await below runs inside the declared budget. No lock is
    // taken here, and no guard is held across that await.
    super::provider_transport_policy::TransportPolicy::governed_default()
        .validate()
        .map_err(|error| owner_error(format!("dreamer model transport policy: {error}")))?;
    admit_model_route_policy(&input.catalogue, &input.policy, input.now_unix_ms)?;
    if input.request.state_fence != *admitted_fence {
        return Err(owner_error("dreamer model request fence is stale"));
    }
    // Candidate planning delegates to the coordinator owner. The plan-only coordinator
    // carries the explicit typed G-11 gap: planning stays available under the gap while
    // live provider admission remains unavailable, and nothing here mints authority.
    let mut coordinator = AgentCoordinator::new(
        coordinator_config.clone(),
        PlanGap::G11Unavailable {
            reason: "governed dreamer model plans candidates only; live provider execution is bound per call through DreamerModelExecution".to_owned(),
        },
    )
    .map_err(|error| owner_error(format!("dreamer model coordinator: {error}")))?;
    let candidate = coordinator
        .plan(input.request.clone())
        .map_err(|error| owner_error(format!("dreamer model plan: {error}")))?;
    verify_model_attempt_linkage(
        admitted_fence,
        &candidate,
        &input.catalogue,
        &input.admission,
        &input.binding,
    )?;
    // R4 generation binding: the Kernel-issued projection (when served) is
    // validated against the admitted fence before execution. It is resolved
    // before the capability gate because the gate needs the exact generation
    // fingerprint to scope a reproduced failure and to admit only the routes
    // that fingerprint admits. Both joins are pure and run before the
    // execution port is touched, so the ordering guarantee is unchanged.
    let generation_fingerprint =
        bind_kernel_generation_projection(admitted_fence, input.kernel_generation.as_ref())?;
    // C1 capability join (issues #1957/#1959): every required capability must
    // hold fresh admission on BOTH the adopted Governor registry side and the
    // funnel side before the execution port is touched. A refusal is recorded
    // as a scoped outcome on this attempt's receipt (#1961), never as global
    // capability state.
    let required = gate_model_capability(
        admitted_fence,
        registry,
        outcomes,
        input,
        &generation_fingerprint,
        intake,
    )?;
    let result = execution
        .execute(&candidate, &input.admission, &input.binding)
        .await?;
    result
        .validate_for_binding(
            &input.binding,
            &input.admission,
            &input.request.launch.effect_ceiling,
        )
        .map_err(|error| owner_error(format!("dreamer model result: {error}")))?;
    record_model_result_intake(
        &result,
        &input.binding,
        &required,
        &generation_fingerprint,
        intake,
    )?;
    Ok(result)
}

/// Returns true when the caller threads critical evidence for one capability.
///
/// Criticality has no separate owner: the caller asserts it by threading a
/// static attestation or a dynamic pulse bound to the exact capability,
/// route, and admitted generation. Either assertion alone evaluates the
/// critical join, so partial critical evidence fails closed instead of
/// admitting through the base join.
fn is_critical_capability(
    capability: &str,
    route: &RouteFingerprint,
    generation: u64,
    input: &ModelInvokeInput,
) -> bool {
    input
        .static_attestation
        .as_ref()
        .is_some_and(|attestation| {
            attestation.capability == capability && attestation.route == *route
        })
        || input.pulse.as_ref().is_some_and(|pulse| {
            pulse.capability == capability
                && pulse.route == *route
                && pulse.generation == generation
        })
}

/// Returns the exact `reproduced_failure` evidence reference for one record,
/// or `None` when the record is not a reproduced failure.
///
/// The I3.4 `reproduced_failure` source is exactly the fresh `broken` or
/// `unsupported` standing: "reproduced failure on the exact fingerprint;
/// overrides declared proof". The reference is derived from the already
/// observed record values — capability, generation, standing, and the
/// owner-set observation window — so it names the exact evidence that carried
/// the failure. No digest, receipt, or identity is minted here.
fn reproduced_failure_evidence_reference(record: &CapabilityEvidenceRecord) -> Option<String> {
    let standing = match record.status {
        CapabilityEvidenceStatus::Broken => "broken",
        CapabilityEvidenceStatus::Unsupported => "unsupported",
        _ => return None,
    };
    Some(format!(
        "capability-evidence:{}@generation{}:{standing}@observed{}@expires{}",
        record.capability, record.generation, record.observed_at_unix_ms, record.expires_at_unix_ms
    ))
}

/// Derives the generation-scoped outcome for one required capability, or
/// `None` when no exact-generation failure is evidenced.
///
/// Returns `Some` only when all three hold, so a broad scope is never
/// asserted from absence:
/// - the Kernel-issued generation projection is served, so the exact
///   fingerprint is known (an unserved projection leaves the generation
///   unknown and the failure stays call-scoped, never widened);
/// - the threaded evidence carries at least two fresh reproduced failures on
///   this exact capability, route fingerprint, and generation, observed at
///   distinct times — one failure is a call error, two independent
///   observations of the same exact failure are the reproduction I3.4
///   requires;
/// - those records share one owner-set expiry, which becomes the outcome's
///   expiry instead of a minted window.
///
/// Returns `None` rather than failing the call when the fresh reproduced
/// evidence set exceeds the owner's bounded evidence shape or the records
/// disagree about their expiry: declining to broaden is the safe direction,
/// and the refusal then stays `CALL`-scoped with the owner's own reason.
#[allow(
    clippy::too_many_arguments,
    reason = "the derivation reads one exact evidence slice plus the identities already threaded per call; a struct would duplicate the request"
)]
fn exact_generation_outcome(
    capability: &str,
    evidence: &[CapabilityEvidenceRecord],
    route: &RouteFingerprint,
    generation: u64,
    now_unix_ms: u64,
    generation_fingerprint: &str,
    generation_owner: &str,
    requested_mode: &str,
) -> Result<Option<CapabilityOutcome>, CompositionError> {
    if generation_fingerprint.is_empty() {
        return Ok(None);
    }
    let mut references: Vec<String> = Vec::new();
    let mut observed_times: Vec<u64> = Vec::new();
    let mut expiry: Option<u64> = None;
    for record in evidence {
        if record.capability != capability
            || record.generation != generation
            || record.route != *route
            || record.observed_at_unix_ms > now_unix_ms
            || now_unix_ms >= record.expires_at_unix_ms
        {
            continue;
        }
        let Some(reference) = reproduced_failure_evidence_reference(record) else {
            continue;
        };
        if observed_times.contains(&record.observed_at_unix_ms) {
            // The same observation threaded twice is one observation, not a
            // reproduction, and never a second evidence reference.
            continue;
        }
        match expiry {
            None => expiry = Some(record.expires_at_unix_ms),
            Some(bound) if bound == record.expires_at_unix_ms => {}
            Some(_) => {
                // Conflicting owner-set windows on the same exact failure
                // are not a settled generation finding; keep the scope
                // narrow instead of picking a window.
                return Ok(None);
            }
        }
        observed_times.push(record.observed_at_unix_ms);
        references.push(reference);
    }
    if observed_times.len() < 2 {
        return Ok(None);
    }
    if references.len() > MAX_REFS {
        return Ok(None);
    }
    let outcome = generation_challenge_outcome(GenerationChallengeOutcomeRequest {
        capability: capability.to_owned(),
        requested_mode: requested_mode.to_owned(),
        effective_mode: REFUSED_EFFECTIVE_MODE.to_owned(),
        reason: format!(
            "reproduced failure on the exact route fingerprint at the admitted generation across {} independent observations",
            observed_times.len()
        ),
        evidence_refs: references,
        affected_outputs_or_operations: generation_degradation_projection(),
        proof_ceiling: REFUSED_PROOF_CEILING.to_owned(),
        recovery_requalification_or_expiry: GENERATION_RECOVERY.to_owned(),
        generation_owner: generation_owner.to_owned(),
        generation_fingerprint: generation_fingerprint.to_owned(),
        valid_until_unix_ms: expiry,
    })
    .map_err(|error| owner_error(format!("dreamer model generation outcome: {error}")))?;
    Ok(Some(outcome))
}

/// Records one refused capability on this attempt's receipt and returns the
/// refusal error carrying the truthful subtraction projection.
///
/// `context` names the join that refused, so the caller still sees which side
/// of the capability gate stopped the call. The outcome is `CALL`-scoped: it
/// becomes visible on the attempt that refused and nothing else. It is never
/// handed to a registry view, so a single refused call cannot become an
/// installation-global flag and the next attempt is admitted by the same gate
/// on its own fresh evidence.
fn refuse_capability_call(
    context: &str,
    capability: &str,
    reason: &str,
    requested_key: &str,
    generation_fingerprint: &str,
    attempt_id: &str,
    intake: &mut AttemptReceipt,
) -> CompositionError {
    let mut outcome = match fallback_outcome(FallbackOutcomeRequest {
        capability: capability.to_owned(),
        requested_mode: requested_key.to_owned(),
        effective_mode: REFUSED_EFFECTIVE_MODE.to_owned(),
        reason: reason.to_owned(),
        affected_outputs_or_operations: call_degradation_projection(),
        proof_ceiling: REFUSED_PROOF_CEILING.to_owned(),
        recovery_requalification_or_expiry: CALL_RECOVERY.to_owned(),
        attempt_id: attempt_id.to_owned(),
    }) {
        Ok(outcome) => outcome,
        Err(error) => {
            return owner_error(format!(
                "{context} does not admit capability {capability} for the bound route and its call-scoped outcome is malformed: {error}"
            ));
        }
    };
    // R4: the Kernel-issued fingerprint bound pre-execution; empty while the
    // projection query is unserved (unknown, never inferred).
    generation_fingerprint.clone_into(&mut outcome.generation_fingerprint);
    match intake.attach(outcome) {
        Ok(()) => {
            let recorded = intake.capability_outcomes.last();
            let detail = recorded.map_or_else(String::new, |outcome| {
                render_projection(&project_degradation(outcome))
            });
            owner_error(format!(
                "{context} does not admit capability {capability} for the bound route: {reason} ({detail})"
            ))
        }
        Err(error) => owner_error(format!(
            "{context} does not admit capability {capability} for the bound route and its call-scoped outcome could not be recorded on the attempt receipt: {error} ({reason})"
        )),
    }
}

/// Enforces the declared execution identity and route fingerprint of the bound
/// route (issue #1816, I10.3–I10.7) before any capability evidence join runs.
///
/// The declaration is caller-threaded per call and is never inferred from the
/// route, the host family, or the process account. Every refusal fails closed,
/// is recorded on this attempt's receipt through the one existing
/// call-scoped outcome owner ([`refuse_capability_call`]) so the declared
/// identity and the exact limitation are visible where the invoke stopped, and
/// is surfaced in the returned error text, which is what the invocation and
/// recovery surfaces report:
///
/// - no declaration, or a malformed one: [`RouteIdentityError::RouteNotDeclared`]
///   / [`RouteIdentityError::InvalidDeclaration`];
/// - a declaration naming a different route than the bound fingerprint:
///   [`RouteIdentityError::DeclarationRouteMismatch`];
/// - an `INTERACTIVE_USER` route launched directly by the daemon or the Kernel
///   instead of through the authorized User Broker:
///   [`RouteIdentityError::InteractiveUserRequiresUserBroker`];
/// - a session carried across a changed declared route — a different execution
///   identity, a local-versus-managed adapter, or a distinct account/credential
///   mode: [`RouteIdentityError::SessionCarryRequiresRehydration`], because the
///   only legal transition there is an explicit rehydrated new attempt.
///
/// The same declared route with no session is admitted here; that is a fresh or
/// natively-resumed attempt, not a continuation across an identity boundary.
fn enforce_declared_route(
    input: &ModelInvokeInput,
    generation_fingerprint: &str,
    intake: &mut AttemptReceipt,
) -> Result<(), CompositionError> {
    // The key the refusal is recorded under is the complete declared route:
    // canonical fingerprint plus execution identity plus policy, so a service
    // route and an interactive-user route over the same provider/model are
    // distinct keys and never share one receipt entry.
    let requested_key = input
        .declared_route
        .as_ref()
        .and_then(|declared| declared_route_key(declared).ok())
        .map_or_else(
            || {
                effective_route_key(&input.binding.route)
                    .map(|key| key.as_str().to_owned())
                    .unwrap_or_default()
            },
            |key| key.as_str().to_owned(),
        );
    let mut refuse = |error: RouteIdentityError| {
        let identity = input.declared_route.as_ref().map_or_else(
            || "none".to_owned(),
            |declared| declared.execution_identity.as_str().to_owned(),
        );
        refuse_capability_call(
            EXECUTION_IDENTITY_REFUSAL_CONTEXT,
            EXECUTION_IDENTITY_CAPABILITY,
            &format!("declared execution identity {identity}: {error}"),
            &requested_key,
            generation_fingerprint,
            input.attempt_id.as_str(),
            intake,
        )
    };
    let Some(declared) = input.declared_route.clone() else {
        return Err(refuse(RouteIdentityError::RouteNotDeclared));
    };
    if declared.route != input.binding.route {
        return Err(refuse(RouteIdentityError::DeclarationRouteMismatch));
    }
    if let Err(error) = declared.validate() {
        return Err(refuse(error));
    }
    if let Err(error) = admit_declared_launch(&declared, input.launch_authority) {
        return Err(refuse(error));
    }
    // A session may only continue on the exact same declared route. A changed
    // execution identity, a local-versus-managed adapter, or a distinct
    // account/credential mode yields an explicit rehydrated new attempt, so a
    // carried session across that boundary is refused rather than continued.
    if let Some(resumed_from) = input.resumed_from.as_ref()
        && input.binding.session_id.is_some()
        && !matches!(
            declared_continuity(resumed_from, &declared),
            Ok(ContinuityKind::NativeResume)
        )
    {
        return Err(refuse(RouteIdentityError::SessionCarryRequiresRehydration));
    }
    Ok(())
}

/// Lifts the retained exact-fingerprint generation block when the
/// caller-threaded evidence requalifies the generation, returning true.
///
/// Requalification is fresh positive standing, not absence: at least one
/// required capability must carry a fresh `probe_passed` or `observed`
/// record on the exact route and admitted generation — the standing I3.4
/// requires for production admission — and no required capability may carry
/// a fresh `broken` or `unsupported` record on that same exact scope. Fresh
/// contradictory standing fails closed (returns false, the block stands),
/// because a reproduced-failure finding is not displaced while its negative
/// evidence is still fresh; unknown or stale standing is likewise not a
/// requalification, and expiry of the block's own window remains that case's
/// recovery through `clear_expired`.
///
/// Every filter mirrors [`exact_generation_outcome`]: same route equality,
/// same admitted generation, same owner-set freshness window, same
/// future-observation exclusion, same required-capability binding. The
/// fingerprint itself is never recomputed: the caller lifts exactly the
/// block the eligibility check refused on.
///
/// A lifted block is not an admission: the caller re-derives from the same
/// evidence next (re-recording when reproduced negatives persist) and the
/// funnel side still admits per capability, so only currently evidenced
/// routes proceed.
fn requalify_generation_on_fresh_positive(
    required: &[String],
    input: &ModelInvokeInput,
    generation: u64,
    generation_fingerprint: &str,
    outcomes: &mut CapabilityRegistryView,
) -> bool {
    if generation_fingerprint.is_empty() {
        return false;
    }
    let mut positive = false;
    for record in &input.evidence_records {
        if record.generation != generation
            || record.route != input.binding.route
            || record.observed_at_unix_ms > input.now_unix_ms
            || input.now_unix_ms >= record.expires_at_unix_ms
            || !required.contains(&record.capability)
        {
            continue;
        }
        match record.status {
            CapabilityEvidenceStatus::ProbePassed | CapabilityEvidenceStatus::Observed => {
                positive = true;
            }
            CapabilityEvidenceStatus::Broken | CapabilityEvidenceStatus::Unsupported => {
                return false;
            }
            CapabilityEvidenceStatus::Declared
            | CapabilityEvidenceStatus::Degraded
            | CapabilityEvidenceStatus::Unknown => {}
        }
    }
    if !positive {
        return false;
    }
    outcomes.requalify_generation(generation_fingerprint);
    true
}

/// Applies the #1961 exact-generation scope to one invoke.
///
/// A reproduced failure on the exact capability, route fingerprint, and
/// admitted generation is a generation finding, not a call error. The
/// daemon-held [`CapabilityRegistryView`] decides eligibility and refuses
/// every route presenting that exact fingerprint; the outcome is attached to
/// this attempt's receipt so the finding stays visible with its evidence and
/// current scope, and it is never installation-global state.
///
/// `outcomes` is the daemon's held view, not a per-call one, so the recorded
/// finding outlives the attempt that produced it. It is consulted before any
/// evidence is re-derived, so a later attempt on the same exact fingerprint
/// reads the retained block instead of re-deriving one, and the
/// generation-scope record survives as state instead of a per-call value.
///
/// The block is lifted by the owner's expiry, `clear_expired` against the
/// recorded record's own window, or by explicit requalification: fresh
/// positive (`probe_passed`/`observed`) standing on the exact route and
/// generation with no contradictory fresh negative standing lifts the
/// retained finding through the view's own `requalify_generation` (see
/// [`requalify_generation_on_fresh_positive`]), and a new admitted
/// generation carries a different fingerprint and is therefore unaffected.
/// A lone positive never displaces still-fresh negative evidence, and absent
/// or stale standing requalifies nothing.
///
/// Returns the refusal when the bound generation fingerprint is blocked, and
/// `Ok(None)` when no required capability carries reproduced
/// exact-fingerprint evidence at that generation — including when the
/// Kernel-issued projection is unserved, so the generation stays unknown
/// rather than inferred.
#[allow(
    clippy::too_many_arguments,
    reason = "the decision needs the exact operation identities the owner binds per invoke; a struct would duplicate the owner's own outcome request"
)]
fn refuse_blocked_generation(
    required: &[String],
    input: &ModelInvokeInput,
    generation: u64,
    generation_fingerprint: &str,
    generation_owner: &str,
    requested_key: &str,
    outcomes: &std::sync::Mutex<CapabilityRegistryView>,
    intake: &mut AttemptReceipt,
) -> Result<Option<CompositionError>, CompositionError> {
    // Locked here, inside the gate's own synchronous body, so no guard is held
    // across the provider execution await and every eligibility decision in
    // this call reads the same retained state.
    let mut outcomes = outcomes
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Expiry is the owner's recovery path and runs against the retained view,
    // so a block whose own window has passed stops refusing without any
    // external trigger, and the eligibility decision below reads the same
    // state it just pruned.
    outcomes.clear_expired(input.now_unix_ms);
    // The retained block is authoritative for this fingerprint. A live
    // installation block is reported at its own broader scope rather than
    // being restated as a generation finding; both refuse.
    if outcomes.live_installation_blocks(input.now_unix_ms) > 0 {
        return Ok(Some(owner_error(format!(
            "capability admission is blocked installation-wide after a recorded broad-scope failure, so route {requested_key} on generation {generation} is not invoked"
        ))));
    }
    if !outcomes.is_route_eligible(generation_fingerprint, None, input.now_unix_ms) {
        // Explicit requalification comes before the retained refusal: a
        // generation whose exact scope now carries fresh positive standing
        // with no contradictory fresh negative standing is requalified
        // instead of refused past its recovery. When nothing requalifies,
        // the retained finding refuses; when it does, the derivation below
        // re-reads the same evidence (re-blocking on still-reproduced
        // negatives) and the funnel side still admits per capability.
        if !requalify_generation_on_fresh_positive(
            required,
            input,
            generation,
            generation_fingerprint,
            &mut outcomes,
        ) {
            return Ok(Some(owner_error(format!(
                "capability is not admitted on generation {generation} of route {requested_key}: a retained exact-fingerprint failure already blocks that generation until its recovery or requalification"
            ))));
        }
    }
    for capability in required {
        let Some(outcome) = exact_generation_outcome(
            capability,
            &input.evidence_records,
            &input.binding.route,
            generation,
            input.now_unix_ms,
            generation_fingerprint,
            generation_owner,
            requested_key,
        )?
        else {
            continue;
        };
        let disposition = outcomes
            .record(&outcome)
            .map_err(|error| owner_error(format!("dreamer model generation record: {error}")))?;
        outcomes.clear_expired(input.now_unix_ms);
        // The block verdict stays bound to this operation through the
        // validated original record: the eligibility key is the digest the
        // record itself carries (checked by the owner's validate() during
        // record()), compared by content against the operation-bound
        // fingerprint. A record naming any other fingerprint fails closed
        // instead of blocking a foreign generation, and no fresh key is
        // recomputed for the check.
        if outcome.generation_fingerprint != generation_fingerprint {
            return Err(owner_error(format!(
                "evidenced generation outcome for {capability} does not name the bound generation fingerprint"
            )));
        }
        if disposition != OutcomeDisposition::GlobalApplied
            || outcomes.is_route_eligible(&outcome.generation_fingerprint, None, input.now_unix_ms)
        {
            return Err(owner_error(format!(
                "evidenced generation outcome for {capability} did not block its exact fingerprint"
            )));
        }
        intake
            .attach(outcome.clone())
            .map_err(|error| owner_error(format!("dreamer model generation attach: {error}")))?;
        return Ok(Some(owner_error(format!(
            "capability {capability} is not admitted on generation {generation} of route {requested_key} after a reproduced exact-fingerprint failure: {}",
            render_projection(&project_degradation(&outcome))
        ))));
    }
    Ok(None)
}

/// Verifies the boundary conditions the C1 capability gate depends on and
/// returns the canonical required set.
///
/// These are the same fail-closed preconditions the gate evaluated inline
/// before, kept in one place so the gate body stays the admission join:
/// - the caller-observed live fence validates and the admitted
///   (startup-boundary) fence stays compatible with it, so rotation fails
///   closed instead of admitting on stale evidence;
/// - the binding generation equals the admitted Kernel generation exactly;
/// - the caller-threaded attempt is the bound attempt, and the receipt the
///   gate may write into is that attempt's own receipt. A foreign receipt
///   fails closed instead of filing this call's degradation under another
///   attempt.
fn verify_gate_preconditions(
    admitted_fence: &StateFence,
    input: &ModelInvokeInput,
    intake: &AttemptReceipt,
) -> Result<Vec<String>, CompositionError> {
    input
        .current_fence
        .validate()
        .map_err(|error| owner_error(format!("dreamer model live fence: {error}")))?;
    if !admitted_fence.is_compatible_with(&input.current_fence) {
        return Err(owner_error(
            "dreamer model admitted fence is not compatible with the live kernel fence (rotation)",
        ));
    }
    let required = canonical_required_set(
        &input.request.launch.required_competence,
        &input.policy,
    )
    .ok_or_else(|| {
        owner_error(
            "dreamer model invoke has no valid required capabilities; refusing an empty required set",
        )
    })?;
    if input.binding.runtime_generation != admitted_fence.resource_generation {
        return Err(owner_error(
            "dreamer model binding generation does not match the admitted Kernel generation",
        ));
    }
    if input.attempt_id != input.binding.attempt_id {
        return Err(owner_error(
            "dreamer model invoke attempt does not match the bound attempt",
        ));
    }
    if intake.attempt_id != input.binding.attempt_id.as_str() {
        return Err(owner_error(
            "dreamer model capability gate receipt does not belong to the bound attempt",
        ));
    }
    Ok(required)
}

/// Runs the C1 capability join for one invoke: registry side plus funnel side.
///
/// Order is load-bearing and every failure returns before the execution port
/// is touched:
/// - snapshot boundaries (I1.8): the caller-observed live fence must validate
///   and the admitted (startup-boundary) fence must stay compatible with it,
///   using the same owner check as the startup evidence build. Rotation fails
///   closed instead of admitting on stale evidence; compatibility carries the
///   exact generation agreement, so the evaluated generation below is current.
/// - R2: the canonical required set (launch intent plus Human Dreamer-role
///   preference, via [`canonical_required_set`]) is resolved per call; empty
///   or malformed fails closed.
/// - R4: the generation under evaluation is the Kernel-owned admitted
///   fence's resource generation, and the execution binding must agree with
///   it exactly. No caller-supplied generation is trusted. The Kernel-issued
///   exact fingerprint for that generation arrives bound and is the only key
///   a generation-scoped outcome may use.
/// - R3: freshness is evaluated at the caller-threaded observation time
///   against owner-set windows (`observed_at`/`expires_at` on funnel
///   records, `observed_at`/`expires_at` plus derived scope invalidation on
///   registry records). No window is minted here and no TTL constant exists.
/// - the registry side requires fresh exact-scope positive evidence with no
///   fresh restriction; a missing observed scope fails closed.
/// - #1961 exact-generation scope: before the per-capability join, a
///   reproduced failure on the exact fingerprint is recorded at
///   `GENERATION` scope, attached to this attempt's receipt, and admitted
///   through [`CapabilityRegistryView::is_route_eligible`], which refuses
///   every route presenting that exact fingerprint and no other. That view is
///   the daemon-held one, so the block is also re-read on later attempts
///   before any evidence is re-derived; fresh positive standing on the exact
///   scope requalifies (lifts) the retained block first, while still-fresh
///   negative standing keeps it refusing. A refusal
///   with no such evidence stays `CALL`-scoped (see
///   [`refuse_capability_call`]).
/// - the funnel side runs through [`admit_production_route`]: the same
///   requested route is evaluated over the threaded records plus the
///   critical join exactly when the caller threaded critical evidence,
///   while `RouteAdmissionVisibility::observe` plus `GovernorRouteAttempt::new`
///   observe and link the caller-threaded attempt on handshake-observed
///   facts. The registry bool path stays: the receipt observes and links
///   the attempt, it never admits — only the funnel disposition admits.
///   Absent observed facts fail closed; facts are never fabricated from
///   the resolved route.
/// - issue #1816 (I10.3–I10.7): the declared execution identity and route
///   fingerprint are enforced first, through
///   [`enforce_declared_route`], before any capability evidence is
///   evaluated — a route with no declared identity, an identity that was not
///   launched through its authorized User Broker, or a session carried
///   across a changed identity / local-versus-managed adapter / account mode
///   is refused there and recorded on this attempt's receipt.
///
/// Returns the evaluated required set for the result-intake join below.
fn gate_model_capability(
    admitted_fence: &StateFence,
    registry: &GovernorCapabilityAdmission,
    outcomes: &std::sync::Mutex<CapabilityRegistryView>,
    input: &ModelInvokeInput,
    generation_fingerprint: &str,
    intake: &mut AttemptReceipt,
) -> Result<Vec<String>, CompositionError> {
    let required = verify_gate_preconditions(admitted_fence, input, intake)?;
    let generation = admitted_fence.resource_generation.value();
    // Issue #1816: the declared execution identity and route fingerprint are
    // enforced before any evidence join, so an undeclared, wrongly-launched,
    // or silently-continued route never reaches the capability funnel.
    enforce_declared_route(input, generation_fingerprint, intake)?;
    let scope = input.evidence_scope.as_ref().ok_or_else(|| {
        owner_error(
            "dreamer model invoke threads no observed route scope; capability evidence is unevaluable",
        )
    })?;
    let observed = input.observed_facts.as_ref().ok_or_else(|| {
        owner_error(
            "dreamer model invoke threads no handshake-observed route facts; capability evidence is unevaluable",
        )
    })?;
    let now = input.now_unix_ms;
    let requested_key = effective_route_key(&input.binding.route)
        .map_err(|error| owner_error(format!("dreamer model gate requested route key: {error}")))?
        .as_str()
        .to_owned();
    // #1961 exact-generation scope: a reproduced failure on the exact
    // fingerprint is a generation finding, not a call error. The daemon-held
    // registry view decides eligibility, so a block recorded here keeps
    // refusing later attempts until its own recovery or an explicit
    // requalification on fresh positive evidence; the outcome stays
    // visible on this attempt's receipt and never becomes
    // installation-global state.
    let generation_owner = format!("kernel-resource-generation:{generation}");
    if let Some(refusal) = refuse_blocked_generation(
        &required,
        input,
        generation,
        generation_fingerprint,
        &generation_owner,
        &requested_key,
        outcomes,
        intake,
    )? {
        return Err(refusal);
    }
    for capability in &required {
        if !registry.admit_production_route(capability, scope, now) {
            return Err(refuse_capability_call(
                REGISTRY_REFUSAL_CONTEXT,
                capability,
                "no fresh exact-scope capability evidence admits it on the observed scope",
                &requested_key,
                generation_fingerprint,
                input.binding.attempt_id.as_str(),
                intake,
            ));
        }
        let request = ProductionAdmissionRequest {
            capability: capability.clone(),
            route: input.binding.route.clone(),
            generation,
            now_unix_ms: now,
            critical: is_critical_capability(capability, &input.binding.route, generation, input),
        };
        let bundle = ProductionEvidenceBundle {
            records: &input.evidence_records,
            static_attestation: input.static_attestation.as_ref(),
            pulse: input.pulse.as_ref(),
        };
        // One owner for the funnel-plus-receipt join: the free admission
        // route evaluates the disposition and constructs the Governor
        // attempt receipt in production. Visibility never implies
        // admission: only the funnel disposition admits.
        let decision =
            admit_production_route(&request, &bundle, input.attempt_id.clone(), observed)
                .map_err(|error| owner_error(format!("dreamer model route receipt: {error}")))?;
        if !decision.outcome.admitted() {
            return Err(refuse_capability_call(
                FUNNEL_REFUSAL_CONTEXT,
                capability,
                decision.outcome.reason,
                &requested_key,
                generation_fingerprint,
                input.binding.attempt_id.as_str(),
                intake,
            ));
        }
    }
    Ok(required)
}

/// Binds one Kernel-issued generation projection to the admitted fence (R4).
///
/// `None` (query unserved or unobserved) binds to the empty marker: outcomes
/// carry an unknown fingerprint, never an inference. A served projection
/// must carry the exact admitted fence and a lowercase SHA-256 fingerprint
/// or the invoke fails closed — a foreign fence is rotation, a malformed
/// digest is not a projection. Runs before the execution port is touched.
fn bind_kernel_generation_projection(
    admitted_fence: &StateFence,
    projection: Option<&KernelGenerationProjection>,
) -> Result<String, CompositionError> {
    let Some(observed) = projection else {
        return Ok(String::new());
    };
    if observed.fence != *admitted_fence {
        return Err(owner_error(
            "kernel generation projection fence does not match the admitted fence (rotation)",
        ));
    }
    let digest: LowercaseSha256 = serde_json::from_value(serde_json::Value::String(
        observed.fingerprint.clone(),
    ))
    .map_err(|error| {
        owner_error(format!(
            "kernel generation fingerprint is not a canonical digest: {error}"
        ))
    })?;
    Ok(digest.as_str().to_owned())
}

/// Authenticated daemon operation selector for the Kernel-owned active
/// generation projection (R4 route contract). The Kernel serves
/// `daemon_generation_projection`; this lane never mints the selector.
pub const DAEMON_GENERATION_PROJECTION_OPERATION: &str = "daemon_generation_projection";

/// Kernel-issued generation projection response value (R4 route contract).
///
/// Closed shape inside the authenticated `status: known` envelope:
/// `{version: 1, fingerprint, state_fence}`. Generation and epoch travel
/// only inside the fence; no route scope or scalar is accepted.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationProjectionResponse {
    version: u64,
    fingerprint: String,
    state_fence: StateFence,
}

/// Decodes one authenticated generation-projection response value against
/// the admitted fence.
///
/// Pure transport-boundary validation: the shape must be closed, the version
/// must be 1, the fingerprint must parse as lowercase SHA-256, and the
/// returned fence must equal the admitted fence exactly (rotation between
/// request and response fails closed). Transport failures never reach here.
fn decode_generation_projection(
    value: serde_json::Value,
    admitted_fence: &StateFence,
) -> Result<KernelGenerationProjection, CompositionError> {
    let response: GenerationProjectionResponse = serde_json::from_value(value)
        .map_err(|error| owner_error(format!("generation projection shape: {error}")))?;
    if response.version != 1 {
        return Err(owner_error(
            "generation projection version must be 1".to_owned(),
        ));
    }
    let digest: LowercaseSha256 = serde_json::from_value(serde_json::Value::String(
        response.fingerprint,
    ))
    .map_err(|error| {
        owner_error(format!(
            "generation projection fingerprint is not a canonical digest: {error}"
        ))
    })?;
    if response.state_fence != *admitted_fence {
        return Err(owner_error(
            "generation projection fence does not match the admitted fence (rotation)".to_owned(),
        ));
    }
    Ok(KernelGenerationProjection {
        fingerprint: digest.as_str().to_owned(),
        fence: response.state_fence,
    })
}

/// Fetches the Kernel-owned active generation projection over the
/// authenticated daemon channel (R4).
///
/// Mirrors the `dreamer_admission` transport template: the admitted fence
/// validates before any transport is touched, the call travels under a
/// fresh operation-bound identity minted by the channel owner, and the
/// typed response decodes through [`decode_generation_projection`] with
/// exact admitted-fence binding. Transport, fenced, and contract failures
/// surface as [`CompositionError::Kernel`]; absence or rotation is never
/// converted into a default projection — callers propagate it as unknown.
pub async fn query_kernel_generation(
    kernel: &DaemonKernelClient,
    admitted_fence: &StateFence,
) -> Result<KernelGenerationProjection, CompositionError> {
    admitted_fence
        .validate()
        .map_err(|error| owner_error(format!("generation query fence: {error}")))?;
    let payload = serde_json::json!({
        "version": 1,
        "state_fence": admitted_fence,
    });
    let value = kernel
        .transact_async(DAEMON_GENERATION_PROJECTION_OPERATION, payload)
        .await
        .map_err(kernel_port_error)
        .map_err(CompositionError::Kernel)?;
    decode_generation_projection(value, admitted_fence)
}

/// Records the result-intake join for one verified invoke result (C1).
///
/// The receipt must be opened by the caller for the executed attempt; a
/// foreign receipt fails closed. Classification is derived only from the
/// verified result, never synthesized:
/// - diverged route observation or `DegradedNoProof` disposition: one
///   call-scoped outcome per required capability, attempt-visible only and
///   never global state. Route keys are the canonical digests of the
///   admitted requested route and (on divergence) the runtime-observed
///   route. Each outcome carries the bound Kernel generation fingerprint
///   (R4; empty while the projection query is unserved) and the
///   surviving/removed projection A13.11 requires, so the receipt reports
///   the reduced promises instead of a bare failure.
/// - unobserved route, `UnknownOutcome` disposition, or unknown execution
///   outcome: no positive claim is recorded; the receipt stays empty. Absent
///   evidence stays unknown and is never reported as healthy or broken.
/// - matched successful execution: nothing to record.
///
/// Broad degradation scopes are never emitted here: the generation scope
/// requires reproduced exact-fingerprint evidence, which this site does not
/// observe, so the wider invalidation stays with the capability gate's
/// [`exact_generation_outcome`].
fn record_model_result_intake(
    result: &AgentResult,
    binding: &ProviderExecutionBinding,
    required: &[String],
    generation_fingerprint: &str,
    intake: &mut AttemptReceipt,
) -> Result<(), CompositionError> {
    if intake.attempt_id != binding.attempt_id.as_str() {
        return Err(owner_error(
            "model result intake receipt does not belong to the executed attempt",
        ));
    }
    let diverged = result.actual_route.route_state == RouteObservationState::Diverged;
    let degraded = result.disposition == ResultDisposition::DegradedNoProof;
    let unknown = result.disposition == ResultDisposition::UnknownOutcome
        || result.actual_route.route_state == RouteObservationState::Unobserved
        || result.actual_route.execution_outcome == ExecutionOutcome::UnknownOutcome;
    if unknown || (!diverged && !degraded) {
        return Ok(());
    }
    let requested_key = effective_route_key(&binding.route).map_err(|error| {
        owner_error(format!("model result intake requested route key: {error}"))
    })?;
    let effective_key = match (&result.actual_route.observed_route, diverged) {
        (Some(observed), true) => effective_route_key(observed).map_err(|error| {
            owner_error(format!("model result intake observed route key: {error}"))
        })?,
        _ => requested_key.clone(),
    };
    let reason = if diverged {
        "executed route diverged from the admitted requested route"
    } else {
        "degraded execution without proof on the admitted route"
    };
    for capability in required {
        let mut outcome = fallback_outcome(FallbackOutcomeRequest {
            capability: capability.clone(),
            requested_mode: requested_key.as_str().to_owned(),
            effective_mode: effective_key.as_str().to_owned(),
            reason: reason.to_owned(),
            affected_outputs_or_operations: call_degradation_projection(),
            proof_ceiling: INTAKE_PROOF_CEILING.to_owned(),
            recovery_requalification_or_expiry: INTAKE_RECOVERY.to_owned(),
            attempt_id: binding.attempt_id.as_str().to_owned(),
        })
        .map_err(|error| owner_error(format!("model result intake outcome: {error}")))?;
        // R4: the Kernel-issued fingerprint bound pre-execution; empty while
        // the projection query is unserved (unknown, never inferred).
        generation_fingerprint.clone_into(&mut outcome.generation_fingerprint);
        intake
            .attach(outcome)
            .map_err(|error| owner_error(format!("model result intake attach: {error}")))?;
    }
    Ok(())
}

fn owner_error(reason: impl Into<String>) -> CompositionError {
    CompositionError::Owner(reason.into())
}

// The daemon runtime wires no live provider credentials or runtime in this slice, so a
// live model acceptance through this adapter is NOT_EXECUTED here by construction: the
// only execution path is the caller-supplied DreamerModelExecution port, and no
// production port binding lands in this slice. Recorded, not mocked: no test asserts a
// passing live execution.

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};
    use std::num::NonZeroU64;
    use std::sync::Mutex;

    use crate::capability_admission::CapabilityEvidenceStatus;
    use crate::capability_outcome::DegradationScope;
    use eliot_agent_api::{
        AgentLaunchRequest, AgentWorkUnitBrief, AttemptId, BudgetEnvelope, CONTRACT_VERSION,
        DecisionId, EffectCeiling, EffectKind, EventCursor, ExecutionOutcome, LaunchRequestId,
        LowercaseSha256, NativeSession, PhysicalRouteObservationReceipt, ProofCeiling,
        QuotaKnowledge, ResultDisposition, RouteFingerprint, RouteObservationState,
        RouteSelectionCandidate, TaskId, UsageReceipt, WorkUnitId, candidate_digest_for,
        route_divergence_fields,
    };
    use eliot_agent_contracts::RevisionId;
    use eliot_contracts::{EpochLineageId, ResourceGeneration, sha256_hex};
    use eliot_evaluation_contracts::BudgetEvidence;
    use eliot_governor::{
        CapabilityEvidenceRecord as GovernorEvidenceRecord, CapabilitySource, CapabilityStatus,
    };
    use eliot_security_contracts::PrivacyClass;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const TEST_SCOPE: &str = "account-t12-07";
    const TEST_NOW: u64 = 1_500;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

    fn rev(value: &str) -> TestResult<RevisionId> {
        Ok(RevisionId::new(value)?)
    }

    fn test_fence() -> TestResult<StateFence> {
        Ok(StateFence::new(
            eliot_agent_api::EpochId::new(
                EpochLineageId::new(TEST_LINEAGE)?,
                NonZeroU64::new(1).ok_or("nonzero test sequence")?,
            )?,
            eliot_agent_api::ResourceGeneration::genesis(),
        ))
    }

    fn test_digest(seed: &str) -> TestResult<LowercaseSha256> {
        serde_json::from_value(serde_json::json!(sha256_hex(seed.as_bytes()))).map_err(Into::into)
    }

    fn fixture_reference(
        label: &str,
    ) -> Result<eliot_agent_contracts::PublicReference, eliot_agent_contracts::ContractError> {
        Ok(eliot_agent_contracts::PublicReference {
            kind: "fixture".to_owned(),
            id: eliot_agent_contracts::TargetId::new(format!("fixture-{label}"))?,
            revision: RevisionId::new("fixture-v1")?,
            digest: None,
        })
    }

    fn fixture_schema_identity(
        label: &str,
    ) -> Result<eliot_contracts::ContractIdentity, eliot_contracts::ContractError> {
        eliot_contracts::contract_identity(
            format!("fixture-{label}"),
            eliot_contracts::ContractVersion::new(1, 0, 0),
            &serde_json::json!({ "fixture_schema": label }),
        )
    }

    fn test_route() -> TestResult<RouteFingerprint> {
        Ok(RouteFingerprint {
            host_family: "test-host".to_owned(),
            adapter: "adapter-model-a".to_owned(),
            protocol_transport: "fixture".to_owned(),
            runtime_hash: test_digest("t12-07-runtime")?,
            adapter_hash: test_digest("t12-07-adapter")?,
            provider: "provider-model-a".to_owned(),
            model: "model-a".to_owned(),
            auth_billing: "fixture-account".to_owned(),
            serializer_hash: test_digest("t12-07-serializer")?,
            tool_semantics_hash: test_digest("t12-07-tools")?,
            reasoning_mode: "bounded".to_owned(),
            continuation_behavior: "fresh".to_owned(),
            feature_flags_hash: test_digest("t12-07-features")?,
        })
    }

    fn test_budget() -> BudgetEnvelope {
        BudgetEnvelope {
            context_tokens: 8_000,
            wall_time_ms: 60_000,
            output_bytes: 256_000,
            cost_microunits: 1_000_000,
            max_depth: 3,
            max_descendants: 8,
        }
    }

    fn test_config() -> TestResult<CoordinatorConfig> {
        Ok(CoordinatorConfig {
            max_ready_items: 32,
            max_admitted_attempts: 4,
            max_active_per_route: 4,
            capacity_identity: "capacity-a".to_owned(),
            capacity_revision: rev("capacity-rev-1")?,
        })
    }

    fn test_request(
        fence: &StateFence,
        route: &RouteFingerprint,
    ) -> TestResult<StaffingPlanRequest> {
        use eliot_agent_coordinator::{
            CandidateId, LearningRole, RecipeId, RecipeManifest, RoleProfileId,
            RoleProfileManifest, RouteCandidateEvidence, StaffingLaneRequest,
        };
        let work_budget = test_budget();
        let work = AgentWorkUnitBrief {
            id: WorkUnitId::new("work-1")?,
            objective: "bounded responsibility work-1".to_owned(),
            causal_property: "causal property work-1".to_owned(),
            scope_ref: "scope-work-1".to_owned(),
            expected_outputs: vec!["candidate artifact".to_owned()],
            source_refs: vec!["architecture:10635".to_owned()],
            verifier_ref: "cargo-test".to_owned(),
            integration_owner: "independent-integrator".to_owned(),
            contract_revision: "work-v1".to_owned(),
            budget: work_budget,
            effect_ceiling: EffectCeiling {
                scope_ref: "scope-work-1".to_owned(),
                allowed: BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace]),
                max_external_effects: 0,
            },
            stop_condition: "candidate submitted".to_owned(),
        };
        let role_effects = work.effect_ceiling.clone();
        Ok(StaffingPlanRequest {
            candidate_id: CandidateId::new("candidate-t12-07")?,
            launch: AgentLaunchRequest {
                id: LaunchRequestId::new("launch-t12-07")?,
                task_id: TaskId::new("task-1")?,
                parent_attempt: None,
                work_units: vec![work],
                required_competence: vec!["rust".to_owned()],
                allowed_route_classes: vec!["provider-model-a".to_owned()],
                native_child_policy: "bounded".to_owned(),
                root_context_revision: "root-v1".to_owned(),
                context_budget: test_budget(),
                evidence_capability_refs: vec!["capability-fixture".to_owned()],
                privacy_profile: "PRIVATE".to_owned(),
                effect_ceiling: EffectCeiling {
                    scope_ref: "task-scope".to_owned(),
                    allowed: BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace]),
                    max_external_effects: 0,
                },
                max_depth: 3,
                max_fanout: 8,
                cumulative_descendant_budget: test_budget(),
                verifier_ref: "cargo-test".to_owned(),
                synthesis_owner: "synthesis-owner".to_owned(),
                integration_owner: "integration-owner".to_owned(),
                cancellation_policy: "cascade".to_owned(),
            },
            recipe: RecipeManifest {
                recipe_id: RecipeId::new("recipe-t12-07")?,
                manifest_revision: rev("recipe-rev-t12-07")?,
                schema_identity: fixture_schema_identity("recipe-t12-07")?,
                content_digest: test_digest("recipe-manifest-t12-07")?,
                route_policy_revision: rev("route-policy-1")?,
                max_lanes: 1,
                max_descendants: 8,
                stage_templates: vec![fixture_reference("stage-template")?],
                work_item_templates: vec![fixture_reference("work-item-template")?],
                dependency_templates: vec![fixture_reference("dependency-template")?],
                merge_templates: vec![fixture_reference("merge-template")?],
                eligible_route_classes: vec!["provider-model-a".to_owned()],
                expansion_conditions: vec![fixture_reference("expansion-condition")?],
                contraction_conditions: vec![fixture_reference("contraction-condition")?],
                verifier_requirements: vec![fixture_reference("verifier-requirement")?],
                audit_requirements: vec![fixture_reference("audit-requirement")?],
                budget: test_budget(),
                partial_result_behavior: fixture_reference("partial-result-behavior")?,
                failure_behavior: fixture_reference("failure-behavior")?,
                role_profiles: vec![RoleProfileManifest {
                    role_id: RoleProfileId::new("role-1")?,
                    manifest_revision: rev("role-rev-role-1")?,
                    schema_identity: fixture_schema_identity("role-1")?,
                    content_digest: test_digest("role-manifest-role-1")?,
                    required_competence: vec!["rust".to_owned()],
                    allowed_operations: vec![fixture_reference("role-operation")?],
                    allowed_effects: role_effects,
                    independence_requirement: fixture_reference("independence-requirement")?,
                    input_schemas: vec![fixture_reference("role-input-schema")?],
                    output_schemas: vec![fixture_reference("role-output-schema")?],
                    visibility_policy: fixture_reference("visibility-policy")?,
                    learning_role: LearningRole::NotApplicable,
                    stop_condition: fixture_reference("candidate-submitted")?,
                    escalation_policy: fixture_reference("integration-owner")?,
                    allowed_route_classes: vec!["provider-model-a".to_owned()],
                    mutation_capable: false,
                }],
            },
            task_revision: "task-rev-1".to_owned(),
            plan_revision: rev("plan-rev-t12-07")?,
            state_fence: fence.clone(),
            human_staffing_intent: eliot_agent_coordinator::HumanStaffingIntent {
                preset: eliot_agent_coordinator::StaffingPreset::Balanced,
                per_job_budget: test_budget(),
            },
            privacy_class: PrivacyClass::Private,
            work_class: "model_jobs".parse()?,
            lanes: vec![StaffingLaneRequest {
                work_unit_id: WorkUnitId::new("work-1")?,
                role_id: RoleProfileId::new("role-1")?,
                work_class: "model_jobs".parse()?,
                route_candidates: vec![RouteCandidateEvidence {
                    route: route.clone(),
                    preference_rank: 0,
                    capacity_identity: "capacity-a".to_owned(),
                    capacity_revision: rev("capacity-rev-1")?,
                    capacity_limit: 4,
                    budget_evidence: BudgetEvidence {
                        arm_id: "route-arm-0".to_owned(),
                        model_calls: 1,
                        wall_time_ms: 100,
                        ..BudgetEvidence::default()
                    },
                    route_classes: vec!["provider-model-a".to_owned()],
                    route_class_evidence_refs: vec!["route-class-evidence-0".to_owned()],
                    privacy_classes: vec![PrivacyClass::Private],
                    privacy_evidence_refs: vec!["privacy-evidence-0".to_owned()],
                    evidence_refs: vec!["route-evidence-0".to_owned()],
                }],
                budget: test_budget(),
                priority: 0,
                mutation_scope: None,
            }],
        })
    }

    fn test_catalogue(route: &RouteFingerprint) -> TestResult<ModelCatalogueSnapshot> {
        use eliot_agent_coordinator::{
            BillingClass, BillingEvidence, MODEL_CATALOGUE_SCHEMA_VERSION, ModelAvailability,
            ModelCatalogueEntry, QuotaDisposition, QuotaObservation, RouteAdmissionStatus,
            RouteHealthStatus,
        };
        let entry = ModelCatalogueEntry {
            entry_id: "entry-t12-07".to_owned(),
            account_scope: TEST_SCOPE.to_owned(),
            host_family: route.host_family.clone(),
            provider_id: route.provider.clone(),
            model_id: route.model.clone(),
            model_family: "family-t12-07".to_owned(),
            route: route.clone(),
            route_admission: RouteAdmissionStatus::Admitted,
            route_health: RouteHealthStatus::Healthy,
            availability: ModelAvailability::Available,
            billing: BillingEvidence {
                class: BillingClass::Free,
                source: "billing-source".to_owned(),
                receipt_ref: "billing-receipt".to_owned(),
                observed_at_unix_ms: 1_000,
                expires_at_unix_ms: 2_000,
            },
            quota: QuotaObservation {
                disposition: QuotaDisposition::Available,
                source: "quota-source".to_owned(),
                receipt_ref: "quota-receipt".to_owned(),
                observed_at_unix_ms: 1_000,
                expires_at_unix_ms: 2_000,
                reset_at_unix_ms: None,
                remaining_microunits: None,
            },
            context_window: 8_000,
            cost_class: 1,
            latency_class: 1,
            capabilities: BTreeMap::new(),
            role_eligibility: BTreeSet::from([ModelRole::Dreamer]),
            evidence_refs: vec!["catalogue-evidence-0".to_owned()],
        };
        let catalogue = ModelCatalogueSnapshot {
            schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
            snapshot_id: "catalogue-t12-07".to_owned(),
            account_scope: TEST_SCOPE.to_owned(),
            collector_identity: "collector-t12-07".to_owned(),
            observed_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
            entries: vec![entry],
        };
        catalogue
            .validate()
            .map_err(|error| format!("catalogue fixture must validate: {error}"))?;
        Ok(catalogue)
    }

    fn test_policy() -> TestResult<HumanModelPreferencePolicy> {
        use eliot_agent_coordinator::{
            BillingClass, MODEL_PREFERENCE_SCHEMA_VERSION, RoleModelPreference,
        };
        let policy = HumanModelPreferencePolicy {
            schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
            policy_id: "policy-t12-07".to_owned(),
            revision: "policy-rev-1".to_owned(),
            account_scope: TEST_SCOPE.to_owned(),
            roles: vec![RoleModelPreference {
                role: ModelRole::Dreamer,
                preferred: Vec::new(),
                denied: Vec::new(),
                allowed_billing: BTreeSet::from([BillingClass::Free]),
                allow_paid_fallback: false,
                allow_degraded_routes: false,
                minimum_context_window: 1,
                maximum_cost_class: 10,
                maximum_latency_class: 10,
                required_capabilities: BTreeSet::new(),
            }],
        };
        policy
            .validate()
            .map_err(|error| format!("policy fixture must validate: {error}"))?;
        Ok(policy)
    }

    fn test_lease_id(value: &str) -> TestResult<eliot_agent_api::WorkLeaseId> {
        serde_json::from_value(serde_json::json!({
            "namespace": eliot_contracts::WORK_LEASE_NAMESPACE,
            "revision": eliot_contracts::WORK_LEASE_WIRE_REVISION,
            "value": value,
        }))
        .map_err(Into::into)
    }

    fn test_admission(
        routing: &eliot_agent_api::RouteSelectionCandidate,
        attempt: &str,
        fence: &StateFence,
    ) -> TestResult<AdmittedRouteReceipt> {
        let route = routing
            .selected
            .clone()
            .ok_or("planned routing must select a route")?;
        let mut receipt = AdmittedRouteReceipt {
            schema_version: CONTRACT_VERSION.to_owned(),
            decision_id: DecisionId::new("decision-t12-07-0")?,
            candidate_digest: candidate_digest_for(routing)?,
            attempt_id: AttemptId::new(attempt)?,
            lease_id: test_lease_id("lease-t12-07")?,
            state_fence: fence.clone(),
            runtime_generation: eliot_agent_api::ResourceGeneration::genesis(),
            policy_revision: routing.policy_revision,
            requested_route: route.clone(),
            selected_route: Some(route),
            no_route: None,
            evidence_refs: routing.evidence_refs.clone(),
            proof_ceiling: eliot_agent_api::ProofCeiling::CandidateArtifact,
            self_digest: test_digest("t12-07-placeholder")?,
        };
        receipt.self_digest = receipt.compute_digest()?;
        receipt
            .validate()
            .map_err(|error| format!("admission fixture must validate: {error}"))?;
        Ok(receipt)
    }

    fn test_binding(
        attempt: &str,
        route: &RouteFingerprint,
        fence: &StateFence,
    ) -> TestResult<ProviderExecutionBinding> {
        use eliot_agent_api::ExecutionUnit;
        let binding = ProviderExecutionBinding {
            attempt_id: AttemptId::new(attempt)?,
            lease_id: test_lease_id("lease-t12-07")?,
            state_fence: fence.clone(),
            runtime_generation: eliot_agent_api::ResourceGeneration::genesis(),
            route: route.clone(),
            session_id: None,
            provider_scope_ref: "scope-t12-07".to_owned(),
            native_session: NativeSession::Sessionless,
            execution_unit: ExecutionUnit::new("unit-ns-t12-07", "unit-t12-07")?,
            start_request_id: eliot_agent_api::RequestId::new("start-t12-07")?,
            start_request_sha256: sha256_hex(b"start-t12-07"),
        };
        binding
            .validate_internal()
            .map_err(|error| format!("binding fixture must validate: {error}"))?;
        Ok(binding)
    }

    /// Test-only execution port recording every call. The responder never runs in the
    /// wrong-receipt case below: the adapter rejects before touching it.
    struct RecordingExecution {
        calls: Mutex<u32>,
    }

    impl DreamerModelExecution for RecordingExecution {
        async fn execute(
            &self,
            _candidate: &StaffingPlanCandidate,
            _admission: &AdmittedRouteReceipt,
            _binding: &ProviderExecutionBinding,
        ) -> Result<AgentResult, CompositionError> {
            if let Ok(mut calls) = self.calls.lock() {
                *calls += 1;
            }
            Err(CompositionError::Owner(
                "test execution must not run on a wrong receipt".to_owned(),
            ))
        }
    }

    /// Test-only execution port answering one prebuilt verified result. The
    /// result is built from the same admission/binding fixtures the invoke
    /// runs under, so the sealed-intake linkage holds exactly.
    struct SucceedingExecution {
        calls: Mutex<u32>,
        result: AgentResult,
    }

    impl DreamerModelExecution for SucceedingExecution {
        async fn execute(
            &self,
            _candidate: &StaffingPlanCandidate,
            _admission: &AdmittedRouteReceipt,
            _binding: &ProviderExecutionBinding,
        ) -> Result<AgentResult, CompositionError> {
            if let Ok(mut calls) = self.calls.lock() {
                *calls += 1;
            }
            Ok(self.result.clone())
        }
    }

    fn execution_calls(execution: &RecordingExecution) -> TestResult<u32> {
        execution
            .calls
            .lock()
            .map(|calls| *calls)
            .map_err(|_| "test execution lock".into())
    }

    #[tokio::test]
    async fn wrong_attempt_receipt_is_rejected_before_execution() -> TestResult {
        let fence = test_fence()?;
        let config = test_config()?;
        let route = test_route()?;
        let request = test_request(&fence, &route)?;
        // Pre-plan through the real coordinator owner so the admission fixture binds the
        // exact planned routing bytes (digests recomputed, never hardcoded).
        let mut planner = AgentCoordinator::new(
            config.clone(),
            PlanGap::G11Unavailable {
                reason: "t12-07 test plans under the explicit gap".to_owned(),
            },
        )?;
        let candidate = planner.plan(request.clone())?;
        let routing = candidate
            .lanes
            .first()
            .ok_or("planned candidate must carry one lane")?
            .routing
            .clone();
        let catalogue = test_catalogue(&route)?;
        let policy = test_policy()?;
        // The admission is valid for attempt A while the binding presents attempt B: both
        // shapes validate on their own, only their linkage is wrong.
        let admission = test_admission(&routing, "attempt-t12-07-a", &fence)?;
        let binding = test_binding("attempt-t12-07-b", &route, &fence)?;
        let input = ModelInvokeInput {
            request,
            catalogue,
            policy,
            now_unix_ms: TEST_NOW,
            admission,
            binding,
            attempt_id: AttemptId::new("attempt-t12-07-b")?,
            observed_facts: Some(test_observed_facts()),
            evidence_records: Vec::new(),
            static_attestation: None,
            pulse: None,
            evidence_scope: None,
            current_fence: fence.clone(),
            kernel_generation: None,
            declared_route: Some(test_declared_route(&route)),
            launch_authority: LaunchAuthority::DirectDaemonOrKernel,
            resumed_from: None,
        };
        let execution = RecordingExecution {
            calls: Mutex::new(0),
        };
        let mut intake =
            AttemptReceipt::new("attempt-t12-07-b").map_err(|error| format!("intake: {error}"))?;
        let outcome = invoke_admitted_model(
            CompositionReadiness::Ready,
            &fence,
            &config,
            &GovernorCapabilityAdmission::new(),
            &std::sync::Mutex::new(CapabilityRegistryView::default()),
            &input,
            &mut intake,
            &execution,
        )
        .await;
        match outcome {
            Err(error) => {
                let message = error.to_string();
                assert!(
                    message.contains("attempt"),
                    "rejection must name the attempt mismatch, got: {message}"
                );
            }
            Ok(_) => panic!("wrong attempt receipt must fail closed"),
        }
        assert_eq!(
            execution_calls(&execution)?,
            0,
            "wrong receipt must be rejected before execution"
        );
        Ok(())
    }

    fn succeeding_calls(execution: &SucceedingExecution) -> TestResult<u32> {
        execution
            .calls
            .lock()
            .map(|calls| *calls)
            .map_err(|_| "test execution lock".into())
    }

    /// Shared invoke fixtures: one planned candidate plus the admission and
    /// binding the invoke runs under, all on the genesis generation.
    struct InvokeFixtures {
        fence: StateFence,
        config: CoordinatorConfig,
        route: RouteFingerprint,
        request: StaffingPlanRequest,
        catalogue: ModelCatalogueSnapshot,
        policy: HumanModelPreferencePolicy,
        admission: AdmittedRouteReceipt,
        binding: ProviderExecutionBinding,
    }

    fn invoke_fixtures_with(fence: &StateFence) -> TestResult<InvokeFixtures> {
        let config = test_config()?;
        let route = test_route()?;
        let request = test_request(fence, &route)?;
        let mut planner = AgentCoordinator::new(
            config.clone(),
            PlanGap::G11Unavailable {
                reason: "t12-07 test plans under the explicit gap".to_owned(),
            },
        )?;
        let candidate = planner.plan(request.clone())?;
        let routing: RouteSelectionCandidate = candidate
            .lanes
            .first()
            .ok_or("planned candidate must carry one lane")?
            .routing
            .clone();
        let catalogue = test_catalogue(&route)?;
        let policy = test_policy()?;
        let admission = test_admission(&routing, "attempt-t12-07", fence)?;
        let binding = test_binding("attempt-t12-07", &route, fence)?;
        Ok(InvokeFixtures {
            fence: fence.clone(),
            config,
            route,
            request,
            catalogue,
            policy,
            admission,
            binding,
        })
    }

    fn invoke_fixtures() -> TestResult<InvokeFixtures> {
        invoke_fixtures_with(&test_fence()?)
    }

    fn drifted_fence() -> TestResult<StateFence> {
        Ok(StateFence::new(
            eliot_agent_api::EpochId::new(
                EpochLineageId::new(TEST_LINEAGE)?,
                NonZeroU64::new(1).ok_or("nonzero test sequence")?,
            )?,
            ResourceGeneration::new(2).map_err(|error| format!("generation: {error}"))?,
        ))
    }

    /// Caller-observed route scope for the adopted registry side, threaded
    /// per call from handshake observations (never derived from the bound
    /// route here).
    fn test_evidence_scope() -> RouteScopeFingerprint {
        RouteScopeFingerprint {
            host_family: Some("t12-07-host-1".to_owned()),
            adapter_id: Some("t12-07-adapter-id-1".to_owned()),
            protocol_transport: Some("app-server|stdio".to_owned()),
            runtime_hash: Some("t12-07-runtime-1".to_owned()),
            adapter_hash: Some("t12-07-adapter-1".to_owned()),
            os_architecture: Some("x86_64-windows".to_owned()),
            auth_profile_class: Some("user-broker".to_owned()),
            provider_model_route: Some("provider-model-a/model-a/fixture-account".to_owned()),
            tool_call_id_and_role_ordering: Some("t12-07-tool-ordering-1".to_owned()),
            reasoning_continuation_and_compaction: Some("t12-07-reasoning-compaction-1".to_owned()),
            feature_flags_and_serializer: Some("t12-07-serializer-1".to_owned()),
        }
    }

    /// Daemon-held registry view holding fresh probe evidence for the
    /// `rust` competence on the observed scope.
    fn test_registry_admitted(
        scope: &RouteScopeFingerprint,
    ) -> TestResult<GovernorCapabilityAdmission> {
        let mut registry = GovernorCapabilityAdmission::new();
        registry.insert(
            GovernorEvidenceRecord::verified(
                "rust",
                CapabilityStatus::ProbePassed,
                CapabilitySource::ActiveProbe,
                scope.clone(),
                1_000,
            )
            .map_err(|error| format!("probe evidence: {error}"))?
            .expires_at(2_000),
            eliot_governor::OwnerEvidenceRevision::issued(
                1,
                &eliot_store_api::sha256_hex(b"test.dreamer.probe-evidence"),
            )
            .map_err(|error| format!("owner revision: {error}"))?,
        );
        Ok(registry)
    }

    /// Caller-observed funnel record for the `rust` competence on the exact
    /// bound route and generation. Windows are owner-set inputs, never
    /// minted by the gate.
    fn test_funnel_record(route: &RouteFingerprint, generation: u64) -> CapabilityEvidenceRecord {
        CapabilityEvidenceRecord {
            capability: "rust".to_owned(),
            route: route.clone(),
            generation,
            status: CapabilityEvidenceStatus::Observed,
            observed_at_unix_ms: 1_000,
            expires_at_unix_ms: 2_000,
        }
    }

    /// Caller-threaded handshake observations for the Governor
    /// route-attempt receipt (issue #228 A1). Provider/model/billing stay
    /// unexposed (`unknown` in the observed route, never inferred from
    /// the bound route); the handshake evidence reference backs the
    /// observation.
    fn test_observed_facts() -> RuntimeObservedFacts {
        RuntimeObservedFacts {
            host_family: "test-host".to_owned(),
            adapter: "adapter-model-a".to_owned(),
            protocol_transport: "fixture".to_owned(),
            runtime_hash: test_digest("t12-07-runtime").expect("facts runtime digest"),
            adapter_hash: test_digest("t12-07-adapter").expect("facts adapter digest"),
            provider: None,
            model: None,
            auth_billing: None,
            serializer_hash: test_digest("t12-07-serializer").expect("facts serializer digest"),
            tool_semantics_hash: test_digest("t12-07-tools").expect("facts tools digest"),
            reasoning_mode: "bounded".to_owned(),
            continuation_behavior: "fresh".to_owned(),
            feature_flags_hash: test_digest("t12-07-features").expect("facts features digest"),
            evidence_refs: vec!["handshake:t12-07-session-1".to_owned()],
        }
    }

    fn test_declared_route(route: &RouteFingerprint) -> DeclaredRoute {
        DeclaredRoute {
            route: route.clone(),
            execution_identity: ExecutionIdentity::Service,
            retention_policy: "provider-retained-30d".to_owned(),
            network_policy: "egress-allowlist".to_owned(),
            workspace_scope_policy: "workroot-scoped".to_owned(),
        }
    }

    fn gate_input(
        fixtures: &InvokeFixtures,
        records: Vec<CapabilityEvidenceRecord>,
        scope: Option<RouteScopeFingerprint>,
    ) -> ModelInvokeInput {
        ModelInvokeInput {
            request: fixtures.request.clone(),
            catalogue: fixtures.catalogue.clone(),
            policy: fixtures.policy.clone(),
            now_unix_ms: TEST_NOW,
            admission: fixtures.admission.clone(),
            binding: fixtures.binding.clone(),
            attempt_id: fixtures.binding.attempt_id.clone(),
            observed_facts: Some(test_observed_facts()),
            evidence_records: records,
            static_attestation: None,
            pulse: None,
            evidence_scope: scope,
            current_fence: fixtures.fence.clone(),
            kernel_generation: None,
            declared_route: Some(test_declared_route(&fixtures.binding.route)),
            launch_authority: LaunchAuthority::DirectDaemonOrKernel,
            resumed_from: None,
        }
    }

    fn test_usage() -> UsageReceipt {
        UsageReceipt {
            input_tokens: None,
            output_tokens: None,
            cost_microunits: None,
            quota: QuotaKnowledge::Unknown,
        }
    }

    fn test_clock(valid_ms: i64, known_ms: i64) -> ClockReading {
        ClockReading {
            valid_time_ms: Some(valid_ms),
            known_time_ms: Some(known_ms),
            transaction_sequence: None,
            monotonic_ns: None,
        }
    }

    fn matched_observation(
        admission: &AdmittedRouteReceipt,
        binding: &ProviderExecutionBinding,
        route: &RouteFingerprint,
        fence: &StateFence,
    ) -> TestResult<PhysicalRouteObservationReceipt> {
        let mut observation = PhysicalRouteObservationReceipt {
            schema_version: CONTRACT_VERSION.to_owned(),
            attempt_id: binding.attempt_id.clone(),
            state_fence: fence.clone(),
            runtime_generation: ResourceGeneration::genesis(),
            admitted_route_digest: admission.self_digest.clone(),
            binding: binding.clone(),
            requested_route: route.clone(),
            observed_route: Some(route.clone()),
            route_state: RouteObservationState::Matched,
            diverged_fields: Vec::new(),
            execution_outcome: ExecutionOutcome::Observed,
            request_digest: test_digest("t12-07-request")?,
            translation_digest: None,
            raw_evidence_digest: None,
            raw_evidence_ref: None,
            usage: test_usage(),
            started: test_clock(1_000, 1_001),
            first_byte: ClockReading::default(),
            first_semantic: ClockReading::default(),
            terminal: test_clock(2_000, 2_001),
            event_cursor: EventCursor::new("cursor-t12-07")
                .map_err(|error| format!("cursor: {error}"))?,
            event_sequence: 1,
            cancellation: None,
            unobserved_reason: None,
            recovery_ref: None,
            safe_public_error: None,
            restricted_raw_error_ref: None,
            self_digest: test_digest("t12-07-placeholder")?,
        };
        observation.self_digest = observation
            .compute_digest()
            .map_err(|error| format!("observation digest: {error}"))?;
        observation
            .validate()
            .map_err(|error| format!("observation fixture must validate: {error}"))?;
        Ok(observation)
    }

    fn invoke_result(
        admission: &AdmittedRouteReceipt,
        binding: &ProviderExecutionBinding,
        route: &RouteFingerprint,
        fence: &StateFence,
        disposition: ResultDisposition,
        mutate: impl FnOnce(&mut PhysicalRouteObservationReceipt) -> TestResult,
    ) -> TestResult<AgentResult> {
        let mut actual_route = matched_observation(admission, binding, route, fence)?;
        mutate(&mut actual_route)?;
        actual_route.self_digest = actual_route
            .compute_digest()
            .map_err(|error| format!("observation digest: {error}"))?;
        actual_route
            .validate()
            .map_err(|error| format!("mutated observation must validate: {error}"))?;
        let unknown_reason = (disposition == ResultDisposition::UnknownOutcome)
            .then(|| "provider did not report an outcome".to_owned());
        Ok(AgentResult {
            attempt_id: binding.attempt_id.clone(),
            disposition,
            artifacts: Vec::new(),
            evidence_refs: Vec::new(),
            proposed_effects: Vec::new(),
            unresolved_questions: Vec::new(),
            usage: test_usage(),
            actual_route,
            unknown_reason,
        })
    }

    fn matched_success(
        admission: &AdmittedRouteReceipt,
        binding: &ProviderExecutionBinding,
        route: &RouteFingerprint,
        fence: &StateFence,
    ) -> TestResult<AgentResult> {
        invoke_result(
            admission,
            binding,
            route,
            fence,
            ResultDisposition::CandidateSucceeded,
            |_| Ok(()),
        )
    }

    async fn run_gate(
        fixtures: &InvokeFixtures,
        registry: &GovernorCapabilityAdmission,
        input: &ModelInvokeInput,
        intake: &mut AttemptReceipt,
        execution: &SucceedingExecution,
    ) -> Result<AgentResult, CompositionError> {
        // The production caller borrows the daemon-held handle; a test helper
        // owns an equivalent one so the gate's own state handling is
        // exercised without a composition.
        let outcomes = std::sync::Mutex::new(CapabilityRegistryView::default());
        invoke_admitted_model(
            CompositionReadiness::Ready,
            &fixtures.fence,
            &fixtures.config,
            registry,
            &outcomes,
            input,
            intake,
            execution,
        )
        .await
    }

    #[tokio::test]
    async fn capability_gate_admits_with_fresh_evidence_on_both_sides() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        let result = matched_success(
            &fixtures.admission,
            &fixtures.binding,
            &fixtures.route,
            &fixtures.fence,
        )?;
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await?;
        assert_eq!(outcome.attempt_id, fixtures.binding.attempt_id);
        assert_eq!(succeeding_calls(&execution)?, 1);
        assert!(
            intake.capability_outcomes.is_empty(),
            "matched success records no intake outcome"
        );
        Ok(())
    }

    #[tokio::test]
    async fn missing_capability_evidence_denies_before_execution() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let input = gate_input(&fixtures, Vec::new(), Some(test_evidence_scope()));
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result: matched_success(
                &fixtures.admission,
                &fixtures.binding,
                &fixtures.route,
                &fixtures.fence,
            )?,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(
            &fixtures,
            &GovernorCapabilityAdmission::new(),
            &input,
            &mut intake,
            &execution,
        )
        .await;
        match outcome {
            Err(error) => assert!(
                error.to_string().contains("capability"),
                "denial must name the capability gap, got: {error}"
            ),
            Ok(_) => panic!("unevidenced invoke must fail closed"),
        }
        assert_eq!(succeeding_calls(&execution)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn stale_funnel_evidence_denies_before_execution() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        // Registry side stays fresh so the funnel staleness decides: an
        // expired record defers instead of admitting.
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let mut stale = test_funnel_record(&fixtures.route, generation);
        stale.observed_at_unix_ms = 100;
        stale.expires_at_unix_ms = 200;
        let input = gate_input(&fixtures, vec![stale], Some(scope));
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result: matched_success(
                &fixtures.admission,
                &fixtures.binding,
                &fixtures.route,
                &fixtures.fence,
            )?,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await;
        match outcome {
            Err(error) => assert!(
                error.to_string().contains("production admission"),
                "staleness must deny at the funnel join, got: {error}"
            ),
            Ok(_) => panic!("stale evidence must fail closed"),
        }
        assert_eq!(succeeding_calls(&execution)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn policy_required_capability_without_evidence_denies() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let mut input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        // The Human Dreamer-role preference requires a second capability no
        // evidence covers: the R2 union admits nothing by default.
        input
            .policy
            .roles
            .iter_mut()
            .find(|preference| preference.role == ModelRole::Dreamer)
            .ok_or("dreamer role preference")?
            .required_capabilities
            .insert("telemetry".to_owned());
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result: matched_success(
                &fixtures.admission,
                &fixtures.binding,
                &fixtures.route,
                &fixtures.fence,
            )?,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await;
        match outcome {
            Err(error) => assert!(
                error.to_string().contains("telemetry"),
                "denial must name the uncovered required capability, got: {error}"
            ),
            Ok(_) => panic!("uncovered policy capability must fail closed"),
        }
        assert_eq!(succeeding_calls(&execution)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn binding_generation_drift_denies_before_execution() -> TestResult {
        // Admission and binding agree with each other at the genesis
        // generation, but the admitted Kernel fence has since advanced: the
        // R4 exact-generation match against the Kernel-owned fence decides.
        let fence = drifted_fence()?;
        let fixtures = invoke_fixtures_with(&fence)?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fence.resource_generation.value();
        let input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result: matched_success(
                &fixtures.admission,
                &fixtures.binding,
                &fixtures.route,
                &fixtures.fence,
            )?,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await;
        match outcome {
            Err(error) => assert!(
                error.to_string().contains("generation"),
                "drift must deny on the generation join, got: {error}"
            ),
            Ok(_) => panic!("generation drift must fail closed"),
        }
        assert_eq!(succeeding_calls(&execution)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn partial_critical_evidence_denies_before_execution() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let mut input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        // Threading a static attestation asserts criticality; without the
        // matching fresh pulse the critical join must fail closed.
        input.static_attestation = Some(StaticCapabilityAttestation {
            capability: "rust".to_owned(),
            route: fixtures.route.clone(),
            invalidated: false,
        });
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result: matched_success(
                &fixtures.admission,
                &fixtures.binding,
                &fixtures.route,
                &fixtures.fence,
            )?,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await;
        match outcome {
            Err(error) => assert!(
                error.to_string().contains("rust"),
                "partial critical evidence must deny for the capability, got: {error}"
            ),
            Ok(_) => panic!("partial critical evidence must fail closed"),
        }
        assert_eq!(succeeding_calls(&execution)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn rotated_live_fence_denies_before_execution() -> TestResult {
        // The admitted (startup-boundary) fence is genesis, but the live
        // kernel fence has since advanced: eliotd and Kernel may not
        // evaluate different semantic snapshots (I1.8), so the invoke fails
        // closed on rotation even with fresh evidence on both sides.
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let base = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        let input = ModelInvokeInput {
            current_fence: drifted_fence()?,
            ..base
        };
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result: matched_success(
                &fixtures.admission,
                &fixtures.binding,
                &fixtures.route,
                &fixtures.fence,
            )?,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await;
        match outcome {
            Err(error) => assert!(
                error.to_string().contains("rotation") || error.to_string().contains("compatible"),
                "rotation must deny on the snapshot boundary, got: {error}"
            ),
            Ok(_) => panic!("rotated live fence must fail closed"),
        }
        assert_eq!(succeeding_calls(&execution)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn served_generation_projection_binds_outcome_fingerprint() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let mut input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        // Kernel-issued projection observed for this invoke: canonical digest
        // under the exact admitted fence.
        let fingerprint = test_digest("t12-07-generation")?;
        input.kernel_generation = Some(KernelGenerationProjection {
            fingerprint: fingerprint.as_str().to_owned(),
            fence: fixtures.fence.clone(),
        });
        let mut observed = fixtures.route.clone();
        observed.model = "model-diverged".to_owned();
        let result = invoke_result(
            &fixtures.admission,
            &fixtures.binding,
            &fixtures.route,
            &fixtures.fence,
            ResultDisposition::CandidateSucceeded,
            |observation| {
                observation.observed_route = Some(observed.clone());
                observation.route_state = RouteObservationState::Diverged;
                observation.diverged_fields =
                    route_divergence_fields(&observation.requested_route, &observed);
                observation.recovery_ref = Some("recovery-diverged-1".to_owned());
                Ok(())
            },
        )?;
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        run_gate(&fixtures, &registry, &input, &mut intake, &execution).await?;
        assert_eq!(succeeding_calls(&execution)?, 1);
        assert_eq!(intake.capability_outcomes.len(), 1);
        assert_eq!(
            intake.capability_outcomes[0].generation_fingerprint,
            fingerprint.as_str(),
            "intake binds the Kernel-issued fingerprint, never a local mint"
        );
        Ok(())
    }

    #[tokio::test]
    async fn foreign_generation_projection_denies_before_execution() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let mut input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        // Well-formed digest but issued under a rotated fence: stale foreign
        // observation, never bound.
        input.kernel_generation = Some(KernelGenerationProjection {
            fingerprint: test_digest("t12-07-generation")?.as_str().to_owned(),
            fence: drifted_fence()?,
        });
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result: matched_success(
                &fixtures.admission,
                &fixtures.binding,
                &fixtures.route,
                &fixtures.fence,
            )?,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await;
        match outcome {
            Err(error) => assert!(
                error.to_string().contains("rotation"),
                "foreign projection must deny on rotation, got: {error}"
            ),
            Ok(_) => panic!("foreign projection must fail closed"),
        }
        assert_eq!(succeeding_calls(&execution)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn malformed_generation_fingerprint_denies_before_execution() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let mut input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        // Right fence, wrong shape: not a canonical digest, not a projection.
        input.kernel_generation = Some(KernelGenerationProjection {
            fingerprint: "NOT-A-DIGEST".to_owned(),
            fence: fixtures.fence.clone(),
        });
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result: matched_success(
                &fixtures.admission,
                &fixtures.binding,
                &fixtures.route,
                &fixtures.fence,
            )?,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await;
        match outcome {
            Err(error) => assert!(
                error.to_string().contains("canonical digest"),
                "malformed fingerprint must deny, got: {error}"
            ),
            Ok(_) => panic!("malformed fingerprint must fail closed"),
        }
        assert_eq!(succeeding_calls(&execution)?, 0);
        Ok(())
    }

    #[tokio::test]
    async fn diverged_execution_records_call_scoped_intake() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        let mut observed = fixtures.route.clone();
        observed.model = "model-diverged".to_owned();
        let result = invoke_result(
            &fixtures.admission,
            &fixtures.binding,
            &fixtures.route,
            &fixtures.fence,
            ResultDisposition::CandidateSucceeded,
            |observation| {
                observation.observed_route = Some(observed.clone());
                observation.route_state = RouteObservationState::Diverged;
                observation.diverged_fields =
                    route_divergence_fields(&observation.requested_route, &observed);
                observation.recovery_ref = Some("recovery-diverged-1".to_owned());
                Ok(())
            },
        )?;
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await?;
        assert_eq!(outcome.attempt_id, fixtures.binding.attempt_id);
        assert_eq!(succeeding_calls(&execution)?, 1);
        assert_eq!(
            intake.capability_outcomes.len(),
            1,
            "diverged execution records exactly one outcome per required capability"
        );
        let recorded = &intake.capability_outcomes[0];
        assert_eq!(recorded.capability, "rust");
        assert_eq!(recorded.degradation_scope, DegradationScope::Call);
        assert_eq!(
            recorded.scope_owner,
            fixtures.binding.attempt_id.as_str(),
            "call-scoped outcomes stay on the attempt receipt"
        );
        assert_ne!(
            recorded.requested_mode, recorded.effective_mode,
            "divergence must separate the admitted and observed route keys"
        );
        Ok(())
    }

    #[tokio::test]
    async fn degraded_execution_records_call_scoped_intake() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        let result = invoke_result(
            &fixtures.admission,
            &fixtures.binding,
            &fixtures.route,
            &fixtures.fence,
            ResultDisposition::DegradedNoProof,
            |_| Ok(()),
        )?;
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        run_gate(&fixtures, &registry, &input, &mut intake, &execution).await?;
        assert_eq!(intake.capability_outcomes.len(), 1);
        let recorded = &intake.capability_outcomes[0];
        assert_eq!(recorded.degradation_scope, DegradationScope::Call);
        assert_eq!(
            recorded.requested_mode, recorded.effective_mode,
            "degraded execution on the admitted route keys both modes alike"
        );
        Ok(())
    }

    #[tokio::test]
    async fn unobserved_unknown_result_records_no_positive_claim() -> TestResult {
        let fixtures = invoke_fixtures()?;
        let scope = test_evidence_scope();
        let registry = test_registry_admitted(&scope)?;
        let generation = fixtures.fence.resource_generation.value();
        let input = gate_input(
            &fixtures,
            vec![test_funnel_record(&fixtures.route, generation)],
            Some(scope),
        );
        let result = invoke_result(
            &fixtures.admission,
            &fixtures.binding,
            &fixtures.route,
            &fixtures.fence,
            ResultDisposition::UnknownOutcome,
            |observation| {
                observation.observed_route = None;
                observation.route_state = RouteObservationState::Unobserved;
                observation.diverged_fields = Vec::new();
                observation.unobserved_reason =
                    Some("provider did not expose route evidence".to_owned());
                observation.execution_outcome = ExecutionOutcome::UnknownOutcome;
                observation.terminal = ClockReading::default();
                observation.recovery_ref = Some("recovery-unknown-1".to_owned());
                Ok(())
            },
        )?;
        let execution = SucceedingExecution {
            calls: Mutex::new(0),
            result,
        };
        let mut intake = AttemptReceipt::new(fixtures.binding.attempt_id.as_str())
            .map_err(|error| format!("intake: {error}"))?;
        let outcome = run_gate(&fixtures, &registry, &input, &mut intake, &execution).await?;
        assert_eq!(outcome.disposition, ResultDisposition::UnknownOutcome);
        assert!(
            intake.capability_outcomes.is_empty(),
            "unobserved unknown execution records no positive claim"
        );
        Ok(())
    }

    #[test]
    fn intake_proof_ceiling_matches_owner_vocabulary() -> TestResult {
        let value = serde_json::to_value(ProofCeiling::CandidateArtifact)
            .map_err(|error| format!("ceiling wire: {error}"))?;
        assert_eq!(
            value.as_str(),
            Some(INTAKE_PROOF_CEILING),
            "the intake marker must spell the owner ceiling exactly"
        );
        Ok(())
    }

    fn projection_value(fingerprint: &str, fence: &StateFence) -> serde_json::Value {
        serde_json::json!({
            "version": 1,
            "fingerprint": fingerprint,
            "state_fence": fence,
        })
    }

    #[test]
    fn projection_response_binds_fingerprint_to_returned_fence() -> TestResult {
        let fence = test_fence()?;
        let hex = test_digest("t12-07-projection")?;
        let projection =
            decode_generation_projection(projection_value(hex.as_str(), &fence), &fence)?;
        assert_eq!(projection.fingerprint, hex.as_str());
        assert_eq!(projection.fence, fence);
        Ok(())
    }

    #[test]
    fn projection_response_rejects_wrong_version() -> TestResult {
        let fence = test_fence()?;
        let mut value = projection_value(test_digest("t12-07-projection")?.as_str(), &fence);
        value["version"] = serde_json::json!(2);
        match decode_generation_projection(value, &fence) {
            Err(error) => assert!(
                error.to_string().contains("version"),
                "unexpected refusal: {error}"
            ),
            Ok(_) => panic!("version 2 must fail closed"),
        }
        Ok(())
    }

    #[test]
    fn projection_response_rejects_malformed_digest() -> TestResult {
        let fence = test_fence()?;
        match decode_generation_projection(projection_value("NOT-A-DIGEST", &fence), &fence) {
            Err(error) => assert!(
                error.to_string().contains("canonical digest"),
                "unexpected refusal: {error}"
            ),
            Ok(_) => panic!("malformed digest must fail closed"),
        }
        Ok(())
    }

    #[test]
    fn projection_response_rejects_foreign_fence() -> TestResult {
        let fence = test_fence()?;
        let foreign = drifted_fence()?;
        match decode_generation_projection(
            projection_value(test_digest("t12-07-projection")?.as_str(), &foreign),
            &fence,
        ) {
            Err(error) => assert!(
                error.to_string().contains("rotation"),
                "unexpected refusal: {error}"
            ),
            Ok(_) => panic!("foreign fence must fail closed"),
        }
        Ok(())
    }

    #[test]
    fn projection_response_rejects_unknown_fields() -> TestResult {
        let fence = test_fence()?;
        let mut value = projection_value(test_digest("t12-07-projection")?.as_str(), &fence);
        value["route_scope"] = serde_json::json!("daemon");
        match decode_generation_projection(value, &fence) {
            Err(error) => assert!(
                error.to_string().contains("shape"),
                "unexpected refusal: {error}"
            ),
            Ok(_) => panic!("unknown fields must fail closed"),
        }
        Ok(())
    }

    #[test]
    fn projection_response_rejects_non_object() -> TestResult {
        let fence = test_fence()?;
        match decode_generation_projection(serde_json::json!("known"), &fence) {
            Err(error) => assert!(
                error.to_string().contains("shape"),
                "unexpected refusal: {error}"
            ),
            Ok(_) => panic!("non-object must fail closed"),
        }
        Ok(())
    }
}
