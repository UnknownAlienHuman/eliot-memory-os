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

use eliot_agent_api::{AdmittedRouteReceipt, AgentResult, ProviderExecutionBinding};
use eliot_agent_coordinator::{
    AgentCoordinator, CoordinatorConfig, HumanModelPreferencePolicy, ModelCatalogueSnapshot,
    ModelRole, PlanGap, StaffingPlanCandidate, StaffingPlanRequest,
};
use eliot_contracts::{ClockReading, ProductId, RequestId, RequestMetadata, SourceId, StateFence};
use eliot_governor::{CompositionError, CompositionReadiness};

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
}

/// Thin governed Dreamer model-call adapter over the retained daemon owners.
///
/// Holds only a borrow of the composition, retains no client and no thread, and changes
/// no lifecycle: callers take a fresh adapter per operation through
/// [`DaemonComposition::dreamer_model`], so a Governor refresh surfaces as an exact fence
/// mismatch instead of silent divergence. Unlike the T12-06 intake adapter this slice
/// performs no Kernel reads — catalogue, policy, admission, and binding arrive threaded
/// by the caller and execution leaves through the [`DreamerModelExecution`] port — so no
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
    /// fence join, candidate planning, attempt/route linkage, exactly one port execution,
    /// then the sealed-intake result binding. Any earlier failure returns before the port
    /// is touched, so no provider budget is spent on a wrong or stale receipt; usage,
    /// cancellation, and unknown outcomes in the returned result cross unchanged.
    pub async fn invoke(
        &self,
        coordinator_config: &CoordinatorConfig,
        input: &ModelInvokeInput,
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
        invoke_admitted_model(readiness, &admitted, coordinator_config, input, execution).await
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

/// Core model-call flow over explicit authority values.
///
/// `readiness`, `admitted_fence`, and `coordinator_config` must come from the live
/// composition and the daemon-threaded capacity view (see
/// [`GovernedDreamerModelAdapter::invoke`]); tests supply exact values directly. The
/// execution port is touched only after every read-only gate passes, and the returned
/// result is the port's candidate bound by [`AgentResult::validate_for_binding`] —
/// requested, logical, and observed identities plus usage, cancellation, and unknown
/// outcomes cross unchanged and are never rewritten here.
pub(crate) async fn invoke_admitted_model(
    readiness: CompositionReadiness,
    admitted_fence: &StateFence,
    coordinator_config: &CoordinatorConfig,
    input: &ModelInvokeInput,
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
    Ok(result)
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

    use eliot_agent_api::{
        AgentLaunchRequest, AgentWorkUnitBrief, AttemptId, BudgetEnvelope, CONTRACT_VERSION,
        DecisionId, EffectCeiling, EffectKind, LaunchRequestId, LowercaseSha256, NativeSession,
        RouteFingerprint, TaskId, WorkUnitId, candidate_digest_for,
    };
    use eliot_agent_contracts::RevisionId;
    use eliot_contracts::{EpochLineageId, sha256_hex};
    use eliot_evaluation_contracts::BudgetEvidence;
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
            lanes: vec![StaffingLaneRequest {
                work_unit_id: WorkUnitId::new("work-1")?,
                role_id: RoleProfileId::new("role-1")?,
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
        };
        let execution = RecordingExecution {
            calls: Mutex::new(0),
        };
        let outcome = invoke_admitted_model(
            CompositionReadiness::Ready,
            &fence,
            &config,
            &input,
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
}
