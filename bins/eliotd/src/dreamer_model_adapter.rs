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
    AdmittedRouteReceipt, AgentResult, ExecutionOutcome, LowercaseSha256, ProviderExecutionBinding,
    ResultDisposition, RouteFingerprint, RouteObservationState,
};
use eliot_agent_coordinator::{
    AgentCoordinator, CoordinatorConfig, HumanModelPreferencePolicy, ModelCatalogueSnapshot,
    ModelRole, PlanGap, StaffingPlanCandidate, StaffingPlanRequest,
};
use eliot_contracts::{ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence};
use eliot_governor::{CompositionError, CompositionReadiness, RouteScopeFingerprint};

use super::capability_admission::{
    CapabilityEvidenceRecord, DynamicCapabilityPulse, ProductionAdmissionRequest,
    ProductionEvidenceBundle, StaticCapabilityAttestation, canonical_required_set,
    evaluate_production_admission,
};
use super::capability_evidence_wiring::GovernorCapabilityAdmission;
use super::capability_outcome::{AttemptReceipt, FallbackOutcomeRequest, fallback_outcome};
use super::route_receipts::effective_route_key;
use super::{DaemonComposition, SERVICE_NAME};

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
        invoke_admitted_model(
            readiness,
            &admitted,
            coordinator_config,
            registry,
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
pub(crate) async fn invoke_admitted_model(
    readiness: CompositionReadiness,
    admitted_fence: &StateFence,
    coordinator_config: &CoordinatorConfig,
    registry: &GovernorCapabilityAdmission,
    input: &ModelInvokeInput,
    intake: &mut AttemptReceipt,
    execution: &impl DreamerModelExecution,
) -> Result<AgentResult, CompositionError> {
    if readiness != CompositionReadiness::Ready {
        return Err(CompositionError::NotReady);
    }
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
    // C1 capability join (issues #1957/#1959): every required capability must
    // hold fresh admission on BOTH the adopted Governor registry side and the
    // funnel side before the execution port is touched.
    let required = gate_model_capability(admitted_fence, registry, input)?;
    // R4 generation binding: the Kernel-issued projection (when served) is
    // validated against the admitted fence before execution; the bound
    // fingerprint rides the intake outcomes below.
    let generation_fingerprint =
        bind_kernel_generation_projection(admitted_fence, input.kernel_generation.as_ref())?;
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
///   it exactly. No caller-supplied generation is trusted.
/// - R3: freshness is evaluated at the caller-threaded observation time
///   against owner-set windows (`observed_at`/`expires_at` on funnel
///   records, `observed_at`/`expires_at` plus derived scope invalidation on
///   registry records). No window is minted here and no TTL constant exists.
/// - the registry side requires fresh exact-scope positive evidence with no
///   fresh restriction; a missing observed scope fails closed.
/// - the funnel side requires an `Admit` disposition over the threaded
///   records plus the critical join exactly when the caller threaded
///   critical evidence.
///
/// Returns the evaluated required set for the result-intake join below.
fn gate_model_capability(
    admitted_fence: &StateFence,
    registry: &GovernorCapabilityAdmission,
    input: &ModelInvokeInput,
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
    let generation = admitted_fence.resource_generation.value();
    if input.binding.runtime_generation != admitted_fence.resource_generation {
        return Err(owner_error(
            "dreamer model binding generation does not match the admitted Kernel generation",
        ));
    }
    let scope = input.evidence_scope.as_ref().ok_or_else(|| {
        owner_error(
            "dreamer model invoke threads no observed route scope; capability evidence is unevaluable",
        )
    })?;
    let now = input.now_unix_ms;
    for capability in &required {
        if !registry.admit_production_route(capability, scope, now) {
            return Err(owner_error(format!(
                "no fresh Governor capability evidence admits {capability} on the observed scope"
            )));
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
        let outcome = evaluate_production_admission(
            &request,
            bundle.records,
            bundle.static_attestation,
            bundle.pulse,
        );
        if !outcome.admitted() {
            return Err(owner_error(format!(
                "production admission does not admit {capability} for the bound route: {}",
                outcome.reason
            )));
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
///   (R4; empty while the projection query is unserved).
/// - unobserved route, `UnknownOutcome` disposition, or unknown execution
///   outcome: no positive claim is recorded; the receipt stays empty.
/// - matched successful execution: nothing to record.
///
/// Broad degradation scopes are never emitted here: broader invalidation
/// requires evidence tied to the broader owner plus its named recovery,
/// which the invoke site does not hold.
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
            affected_outputs_or_operations: Vec::new(),
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
            CandidateId, RecipeId, RecipeManifest, RoleProfileId, RoleProfileManifest,
            RouteCandidateEvidence, StaffingLaneRequest,
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
                route_policy_revision: rev("route-policy-1")?,
                max_lanes: 1,
                max_descendants: 8,
                role_profiles: vec![RoleProfileManifest {
                    role_id: RoleProfileId::new("role-1")?,
                    manifest_revision: rev("role-rev-role-1")?,
                    required_competence: vec!["rust".to_owned()],
                    allowed_route_classes: vec!["provider-model-a".to_owned()],
                    mutation_capable: false,
                }],
            },
            task_revision: "task-rev-1".to_owned(),
            plan_revision: rev("plan-rev-t12-07")?,
            state_fence: fence.clone(),
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
            evidence_records: Vec::new(),
            static_attestation: None,
            pulse: None,
            evidence_scope: None,
            current_fence: fence.clone(),
            kernel_generation: None,
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
            runtime_hash: Some("t12-07-runtime-1".to_owned()),
            adapter_hash: Some("t12-07-adapter-1".to_owned()),
            os_architecture: Some("x86_64-windows".to_owned()),
            auth_profile_class: Some("user-broker".to_owned()),
            provider_model_route: Some("provider-model-a/model-a/fixture-account".to_owned()),
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
            evidence_records: records,
            static_attestation: None,
            pulse: None,
            evidence_scope: scope,
            current_fence: fixtures.fence.clone(),
            kernel_generation: None,
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
        invoke_admitted_model(
            CompositionReadiness::Ready,
            &fixtures.fence,
            &fixtures.config,
            registry,
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
}
