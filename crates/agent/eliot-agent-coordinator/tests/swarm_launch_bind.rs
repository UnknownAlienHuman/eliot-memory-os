//! Focused swarm launch-binding tests for issue #501.
//!
//! Two groups only: happy-path binding with the candidate-only ceiling and
//! replay stability, plus the fail-closed negatives. Deferred cases are
//! listed in the issue work unit (`writer.md`).
//!
//! Proof ceiling: `SWARM_LAUNCH_BINDING_PACKAGE_PROOF_ONLY`. Provider process
//! execution, live `WorkLease`/`StateFence` issuance, route admission,
//! mailbox/Concilium, strict Finish, and Product Pulse remain separate.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use eliot_agent_api::{EpochId, LowercaseSha256, ResourceGeneration, RouteFingerprint, StateFence};
use eliot_agent_coordinator::{
    BillingClass, BillingEvidence, HumanModelPreferencePolicy, LaunchSwarmRequest,
    MODEL_CATALOGUE_SCHEMA_VERSION, MODEL_PREFERENCE_SCHEMA_VERSION, ModelAvailability,
    ModelCatalogueEntry, ModelCatalogueSnapshot, ModelRole, QuotaDisposition, QuotaObservation,
    RefreshCatalogueRequest, RoleModelPreference, RouteAdmissionStatus, RouteHealthStatus,
    StaffingGap, StaffingIndependenceOutcome, SwarmCommandCallerBinding, SwarmCommandCandidate,
    SwarmLaunchBindError, SwarmLaunchBindRequest, SwarmLaunchBinding, SwarmLaunchReplayDisposition,
    SwarmStaffingRequest, ZeroModelExecutionCounters, bind_swarm_launch,
    compile_launch_swarm_candidate, compile_model_selection, compile_refresh_catalogue_candidate,
    compile_swarm_staffing,
};
use eliot_contracts::{EpochLineageId, sha256_hex};

const NOW: u64 = 10_000;
const ACCOUNT: &str = "account-scope-1";
const CATALOGUE_ID: &str = "catalogue-launch-bind";
const POLICY_ID: &str = "human-policy";
const POLICY_REVISION: &str = "revision-1";
const VIEW_REVISION: &str = "view-revision-7";
const COMMAND_ID: &str = "command-launch-bind";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn digest(seed: &str) -> TestResult<LowercaseSha256> {
    Ok(serde_json::from_value(serde_json::json!(sha256_hex(
        format!("launch-bind-fixture-{seed}").as_bytes()
    )))?)
}

fn route(host: &str, provider: &str, model: &str, suffix: &str) -> TestResult<RouteFingerprint> {
    Ok(RouteFingerprint {
        host_family: host.to_owned(),
        adapter: "eliot-agent-opencode".to_owned(),
        protocol_transport: "http+sse".to_owned(),
        runtime_hash: digest(&format!("runtime-{suffix}"))?,
        adapter_hash: digest(&format!("adapter-{suffix}"))?,
        provider: provider.to_owned(),
        model: model.to_owned(),
        auth_billing: ACCOUNT.to_owned(),
        serializer_hash: digest(&format!("serializer-{suffix}"))?,
        tool_semantics_hash: digest(&format!("tools-{suffix}"))?,
        reasoning_mode: "default".to_owned(),
        continuation_behavior: "native-resume".to_owned(),
        feature_flags_hash: digest(&format!("features-{suffix}"))?,
    })
}

fn entry(
    entry_id: &str,
    host: &str,
    provider: &str,
    model: &str,
    family: &str,
    role: ModelRole,
) -> TestResult<ModelCatalogueEntry> {
    entry_with_admission(
        entry_id,
        host,
        provider,
        model,
        family,
        role,
        RouteAdmissionStatus::Admitted,
    )
}

fn entry_with_admission(
    entry_id: &str,
    host: &str,
    provider: &str,
    model: &str,
    family: &str,
    role: ModelRole,
    admission: RouteAdmissionStatus,
) -> TestResult<ModelCatalogueEntry> {
    Ok(ModelCatalogueEntry {
        entry_id: entry_id.to_owned(),
        account_scope: ACCOUNT.to_owned(),
        host_family: host.to_owned(),
        provider_id: provider.to_owned(),
        model_id: model.to_owned(),
        model_family: family.to_owned(),
        route: route(host, provider, model, entry_id)?,
        route_admission: admission,
        route_health: RouteHealthStatus::Healthy,
        availability: ModelAvailability::Available,
        billing: BillingEvidence {
            class: BillingClass::Free,
            source: "test-billing".to_owned(),
            receipt_ref: format!("billing-{entry_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
        },
        quota: QuotaObservation {
            disposition: QuotaDisposition::Available,
            source: "test-quota".to_owned(),
            receipt_ref: format!("quota-{entry_id}"),
            observed_at_unix_ms: NOW - 100,
            expires_at_unix_ms: NOW + 100,
            reset_at_unix_ms: Some(NOW + 1_000),
            remaining_microunits: Some(1),
        },
        context_window: 128_000,
        cost_class: 0,
        latency_class: 0,
        capabilities: BTreeMap::new(),
        role_eligibility: BTreeSet::from([role]),
        evidence_refs: vec![format!("evidence-{entry_id}")],
    })
}

fn snapshot() -> TestResult<ModelCatalogueSnapshot> {
    Ok(ModelCatalogueSnapshot {
        schema_version: MODEL_CATALOGUE_SCHEMA_VERSION.to_owned(),
        snapshot_id: CATALOGUE_ID.to_owned(),
        account_scope: ACCOUNT.to_owned(),
        collector_identity: "test-collector".to_owned(),
        observed_at_unix_ms: NOW - 100,
        expires_at_unix_ms: NOW + 100,
        entries: vec![
            entry(
                "entry-main",
                "host-a",
                "provider-a",
                "model-a",
                "family-a",
                ModelRole::MainAgent,
            )?,
            entry(
                "entry-worker",
                "host-b",
                "provider-b",
                "model-b",
                "family-b",
                ModelRole::Worker,
            )?,
        ],
    })
}

fn role_preference(role: ModelRole) -> RoleModelPreference {
    RoleModelPreference {
        role,
        preferred: Vec::new(),
        denied: Vec::new(),
        allowed_billing: BTreeSet::from([BillingClass::Free]),
        allow_paid_fallback: false,
        allow_degraded_routes: false,
        minimum_context_window: 1,
        maximum_cost_class: 10,
        maximum_latency_class: 10,
        required_capabilities: BTreeSet::new(),
    }
}

fn policy_for(roles: &[ModelRole]) -> HumanModelPreferencePolicy {
    HumanModelPreferencePolicy {
        schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
        policy_id: POLICY_ID.to_owned(),
        revision: POLICY_REVISION.to_owned(),
        account_scope: ACCOUNT.to_owned(),
        roles: roles.iter().copied().map(role_preference).collect(),
    }
}

fn policy() -> HumanModelPreferencePolicy {
    policy_for(&[ModelRole::MainAgent, ModelRole::Worker])
}

fn fence(sequence: u64) -> TestResult<StateFence> {
    let lineage = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")?;
    let epoch = EpochId::new(
        lineage,
        NonZeroU64::new(sequence).ok_or("sequence must be nonzero")?,
    )?;
    let generation = ResourceGeneration::new(1)?;
    Ok(StateFence::new(epoch, generation))
}

fn caller_binding(command_id: &str) -> TestResult<SwarmCommandCallerBinding> {
    let fence_value = fence(1)?;
    Ok(SwarmCommandCallerBinding {
        command_id: command_id.to_owned(),
        capability_present: true,
        capability_scope: ACCOUNT.to_owned(),
        view_revision: VIEW_REVISION.to_owned(),
        expected_view_revision: VIEW_REVISION.to_owned(),
        view_fence: fence_value.clone(),
        expected_view_fence: fence_value,
        now_unix_ms: NOW,
    })
}

fn launch_candidate(
    catalogue: &ModelCatalogueSnapshot,
    human_policy: &HumanModelPreferencePolicy,
    command_id: &str,
    demand: Vec<ModelRole>,
) -> TestResult<SwarmCommandCandidate> {
    let request = LaunchSwarmRequest {
        binding: caller_binding(command_id)?,
        account_scope: ACCOUNT.to_owned(),
        catalogue: catalogue.clone(),
        policy: human_policy.clone(),
        task_id: "task-1".to_owned(),
        plan_revision: "plan-revision-3".to_owned(),
        demand,
    };
    Ok(compile_launch_swarm_candidate(&request)?)
}

fn bind_request(
    candidate: &SwarmCommandCandidate,
    catalogue: &ModelCatalogueSnapshot,
    human_policy: &HumanModelPreferencePolicy,
) -> SwarmLaunchBindRequest {
    SwarmLaunchBindRequest {
        candidate: candidate.clone(),
        catalogue: catalogue.clone(),
        policy: human_policy.clone(),
        now_unix_ms: NOW,
    }
}

fn assert_candidate_ceiling(binding: &SwarmLaunchBinding) -> TestResult {
    assert!(binding.candidate_only);
    assert!(!binding.dispatch_authority);
    assert_eq!(
        binding.execution,
        ZeroModelExecutionCounters::zero(),
        "binding execution counters must stay zero"
    );
    assert!(binding.candidate_only());
    assert!(!binding.dispatch_authority());
    assert_eq!(binding.execution(), ZeroModelExecutionCounters::zero());
    assert!(binding.staffing.candidate_only);
    assert!(!binding.staffing.dispatch_authority);
    for selection in &binding.selections {
        assert!(selection.candidate_only);
        assert!(!selection.dispatch_authority);
        assert_eq!(selection.execution, ZeroModelExecutionCounters::zero());
    }
    binding.validate()?;
    let round_trip: SwarmLaunchBinding = serde_json::from_value(serde_json::to_value(binding)?)?;
    assert_eq!(round_trip, *binding);
    round_trip.validate()?;
    Ok(())
}

#[test]
fn launch_binding_compiles_candidate_only() -> TestResult {
    let (catalogue, human_policy, candidate, binding) = happy_binding()?;
    assert_candidate_ceiling(&binding)?;

    assert_eq!(binding.command_id, COMMAND_ID);
    assert_eq!(binding.command_digest, candidate.command_digest);
    assert_eq!(binding.account_scope, ACCOUNT);
    assert_eq!(binding.view_revision, VIEW_REVISION);
    assert_eq!(binding.view_fence, candidate.view_fence);
    assert_eq!(binding.task_id, "task-1");
    assert_eq!(binding.plan_revision, "plan-revision-3");
    assert_eq!(binding.catalogue_snapshot_id, CATALOGUE_ID);
    assert_eq!(binding.preference_policy_id, POLICY_ID);
    assert_eq!(binding.preference_revision, POLICY_REVISION);
    assert_eq!(binding.staffing_id, format!("{COMMAND_ID}/staffing"));
    assert_eq!(binding.selections.len(), 2);
    assert!(binding.staffing.is_complete());
    assert!(binding.staffing.gaps.is_empty());

    // No second selector: every bound selection is byte-identical to a direct
    // owner call with the sealed probe identity.
    for (role, key) in [
        (ModelRole::MainAgent, "MAIN_AGENT"),
        (ModelRole::Worker, "WORKER"),
    ] {
        let direct = compile_model_selection(
            &catalogue,
            &human_policy,
            role,
            &format!("{COMMAND_ID}/{key}"),
            NOW,
        )?;
        assert!(
            binding.selections.contains(&direct),
            "bound selection for {role:?} must equal the direct owner receipt"
        );
    }

    // No second staffing path: the bound staffing is byte-identical to a
    // direct owner call over the bound selections.
    let direct_staffing = compile_swarm_staffing(&SwarmStaffingRequest {
        staffing_id: format!("{COMMAND_ID}/staffing"),
        demand: vec![ModelRole::MainAgent, ModelRole::Worker],
        selections: binding.selections.clone(),
        catalogue: catalogue.clone(),
        policy: human_policy.clone(),
        now_unix_ms: NOW,
    })?;
    assert_eq!(binding.staffing, direct_staffing);
    Ok(())
}

fn happy_binding() -> TestResult<(
    ModelCatalogueSnapshot,
    HumanModelPreferencePolicy,
    SwarmCommandCandidate,
    SwarmLaunchBinding,
)> {
    let catalogue = snapshot()?;
    let human_policy = policy();
    let candidate = launch_candidate(
        &catalogue,
        &human_policy,
        COMMAND_ID,
        vec![ModelRole::Worker, ModelRole::MainAgent],
    )?;
    let binding = bind_swarm_launch(&bind_request(&candidate, &catalogue, &human_policy))?;
    Ok((catalogue, human_policy, candidate, binding))
}

#[test]
fn launch_binding_replay_and_tamper_rules() -> TestResult {
    let (catalogue, human_policy, candidate, binding) = happy_binding()?;
    // Exact replay reproduces the exact binding; a different command id is a
    // new binding rather than a replay.
    let replay = bind_swarm_launch(&bind_request(&candidate, &catalogue, &human_policy))?;
    assert_eq!(binding, replay);
    assert_eq!(
        binding.replay_disposition(&replay)?,
        SwarmLaunchReplayDisposition::ExactReplay
    );
    let other = launch_candidate(
        &catalogue,
        &human_policy,
        "command-other",
        vec![ModelRole::MainAgent],
    )?;
    let other_binding = bind_swarm_launch(&bind_request(&other, &catalogue, &human_policy))?;
    assert_eq!(
        binding.replay_disposition(&other_binding)?,
        SwarmLaunchReplayDisposition::NewBinding
    );

    // Reusing the command identity with changed bytes conflicts.
    let conflict_launch = LaunchSwarmRequest {
        binding: caller_binding(COMMAND_ID)?,
        account_scope: ACCOUNT.to_owned(),
        catalogue: catalogue.clone(),
        policy: human_policy.clone(),
        task_id: "task-1".to_owned(),
        plan_revision: "plan-revision-4".to_owned(),
        demand: vec![ModelRole::MainAgent, ModelRole::Worker],
    };
    let conflict_candidate = compile_launch_swarm_candidate(&conflict_launch)?;
    let conflict = bind_swarm_launch(&bind_request(
        &conflict_candidate,
        &catalogue,
        &human_policy,
    ))?;
    assert!(
        matches!(
            binding.replay_disposition(&conflict),
            Err(SwarmLaunchBindError::IdentityConflict)
        ),
        "reusing a command id with changed bytes must conflict"
    );

    // Caller-edited bytes are rejected: neither the sealed candidate nor the
    // binding survives a digest-breaking edit.
    let mut tampered_candidate = serde_json::to_value(&candidate)?;
    tampered_candidate["plan_revision"] = serde_json::json!("plan-revision-9");
    assert!(
        serde_json::from_value::<SwarmCommandCandidate>(tampered_candidate).is_err(),
        "edited candidate bytes must fail the sealed digest closure"
    );
    let mut tampered_binding = serde_json::to_value(&binding)?;
    tampered_binding["task_id"] = serde_json::json!("task-2");
    assert!(
        serde_json::from_value::<SwarmLaunchBinding>(tampered_binding).is_err(),
        "edited binding bytes must fail the binding digest closure"
    );
    let mut ceiling_tampered = serde_json::to_value(&binding)?;
    ceiling_tampered["candidate_only"] = serde_json::json!(false);
    assert!(
        serde_json::from_value::<SwarmLaunchBinding>(ceiling_tampered).is_err(),
        "a non-candidate ceiling must fail closed on deserialize"
    );
    Ok(())
}

#[test]
fn launch_binding_rejects_non_launch_kind_and_scope_mismatch() -> TestResult {
    let catalogue = snapshot()?;
    let human_policy = policy();

    let refresh = compile_refresh_catalogue_candidate(&RefreshCatalogueRequest {
        binding: caller_binding("command-refresh")?,
        account_scope: ACCOUNT.to_owned(),
        catalogue: catalogue.clone(),
        reason: "operator refresh".to_owned(),
    })?;
    assert_eq!(
        bind_swarm_launch(&bind_request(&refresh, &catalogue, &human_policy)),
        Err(SwarmLaunchBindError::InvalidField("launch.kind")),
        "a non-launch candidate is not a launch binding"
    );

    let candidate = launch_candidate(
        &catalogue,
        &human_policy,
        COMMAND_ID,
        vec![ModelRole::MainAgent, ModelRole::Worker],
    )?;
    let mut foreign_policy = human_policy.clone();
    foreign_policy.account_scope = "other-scope".to_owned();
    assert_eq!(
        bind_swarm_launch(&bind_request(&candidate, &catalogue, &foreign_policy)),
        Err(SwarmLaunchBindError::InvalidField("launch.account_scope")),
        "a policy scoped elsewhere must fail closed"
    );
    Ok(())
}

#[test]
fn launch_binding_fails_closed_on_stale_generations() -> TestResult {
    let catalogue = snapshot()?;
    let human_policy = policy();
    let candidate = launch_candidate(
        &catalogue,
        &human_policy,
        COMMAND_ID,
        vec![ModelRole::MainAgent, ModelRole::Worker],
    )?;

    // A catalogue generation the candidate never saw fails closed, even when
    // the snapshot identity is unchanged but bytes outside the demanded
    // roles moved: the full-generation digest pin still binds them.
    let mut renamed = catalogue.clone();
    renamed.snapshot_id = "catalogue-other".to_owned();
    assert_eq!(
        bind_swarm_launch(&bind_request(&candidate, &renamed, &human_policy)),
        Err(SwarmLaunchBindError::StaleCatalogue),
        "a catalogue snapshot the candidate never saw must fail closed"
    );
    let mut extended = catalogue.clone();
    extended.entries.push(entry(
        "entry-dreamer",
        "host-d",
        "provider-d",
        "model-d",
        "family-d",
        ModelRole::Dreamer,
    )?);
    assert_eq!(
        bind_swarm_launch(&bind_request(&candidate, &extended, &human_policy)),
        Err(SwarmLaunchBindError::StaleCatalogue),
        "catalogue bytes outside the demand are still covered by the digest pin"
    );

    // A superseded Human policy revision fails closed.
    let mut stale_policy = human_policy.clone();
    stale_policy.revision = "revision-0".to_owned();
    assert_eq!(
        bind_swarm_launch(&bind_request(&candidate, &catalogue, &stale_policy)),
        Err(SwarmLaunchBindError::StalePolicy),
        "a stale policy revision must fail closed"
    );

    // A changed route under the same snapshot identity fails closed as a
    // stale catalogue: route-bearing bytes are covered by the catalogue
    // digest pin, so the sealed per-role pin can no longer reproduce.
    let mut rerouted = catalogue.clone();
    let worker = rerouted
        .entries
        .iter_mut()
        .find(|entry| entry.entry_id == "entry-worker")
        .ok_or("worker entry must exist")?;
    worker.model_id = "model-b2".to_owned();
    worker.route.model = "model-b2".to_owned();
    worker.route.runtime_hash = digest("runtime-entry-worker-2")?;
    assert_eq!(
        bind_swarm_launch(&bind_request(&candidate, &rerouted, &human_policy)),
        Err(SwarmLaunchBindError::StaleCatalogue),
        "a route change under the same snapshot identity must fail closed"
    );

    // A superseded Human policy body fails closed even when the revision
    // text is unchanged: the digest pin covers the full policy content.
    let mut drifted_policy = human_policy.clone();
    drifted_policy.roles[0].maximum_cost_class = 0;
    assert_eq!(
        bind_swarm_launch(&bind_request(&candidate, &catalogue, &drifted_policy)),
        Err(SwarmLaunchBindError::StalePolicy),
        "a drifted policy body must fail closed"
    );

    // An expired evidence window fails closed with the typed owner error:
    // the sealed generation is no longer current at bind time.
    let mut late = bind_request(&candidate, &catalogue, &human_policy);
    late.now_unix_ms = NOW + 1_000;
    assert!(
        matches!(
            bind_swarm_launch(&late),
            Err(SwarmLaunchBindError::ModelControl(_))
        ),
        "expired evidence windows must fail closed with the owner error"
    );
    Ok(())
}

#[test]
fn launch_binding_fails_closed_on_role_problems() -> TestResult {
    let catalogue = snapshot()?;
    let human_policy = policy();
    let candidate = launch_candidate(
        &catalogue,
        &human_policy,
        COMMAND_ID,
        vec![ModelRole::MainAgent, ModelRole::Worker],
    )?;

    // A demanded role removed from the Human policy moves the generation,
    // so binding fails closed as stale: the missing role is never staffed
    // from another role's receipt.
    let main_only = policy_for(&[ModelRole::MainAgent]);
    assert_eq!(
        bind_swarm_launch(&bind_request(&candidate, &catalogue, &main_only)),
        Err(SwarmLaunchBindError::StalePolicy),
        "a role removed from Human policy must fail closed as stale"
    );

    // An unavailable provider route moves the catalogue generation, so the
    // bind fails closed as stale: no silent fallback ever substitutes
    // another entry, and no provider binding is synthesized.
    let mut rejected = catalogue.clone();
    let worker = rejected
        .entries
        .iter_mut()
        .find(|entry| entry.entry_id == "entry-worker")
        .ok_or("worker entry must exist")?;
    worker.route_admission = RouteAdmissionStatus::Rejected;
    assert_eq!(
        bind_swarm_launch(&bind_request(&candidate, &rejected, &human_policy)),
        Err(SwarmLaunchBindError::StaleCatalogue),
        "an unavailable provider route must fail closed, never silently substitute"
    );

    // Two roles resolving to one catalogue entry fail closed on the duplicate
    // selection identity instead of staffing the same entry twice.
    let shared = ModelCatalogueSnapshot {
        entries: vec![ModelCatalogueEntry {
            role_eligibility: BTreeSet::from([ModelRole::MainAgent, ModelRole::Worker]),
            ..entry(
                "entry-shared",
                "host-s",
                "provider-s",
                "model-s",
                "family-s",
                ModelRole::MainAgent,
            )?
        }],
        ..catalogue.clone()
    };
    let shared_candidate = launch_candidate(
        &shared,
        &human_policy,
        COMMAND_ID,
        vec![ModelRole::MainAgent, ModelRole::Worker],
    )?;
    assert!(
        matches!(
            bind_swarm_launch(&bind_request(&shared_candidate, &shared, &human_policy)),
            Err(SwarmLaunchBindError::Staffing(_))
        ),
        "duplicate selection identity across roles must fail closed"
    );
    Ok(())
}

#[test]
fn launch_binding_preserves_degraded_independence() -> TestResult {
    // Challenger and Verifier share the MainAgent host and model family on
    // distinct routes: they stay explicitly degraded, never independent.
    let catalogue = ModelCatalogueSnapshot {
        entries: vec![
            entry(
                "entry-main",
                "host-a",
                "provider-a",
                "model-a",
                "family-a",
                ModelRole::MainAgent,
            )?,
            entry(
                "entry-challenger",
                "host-a",
                "provider-c",
                "model-c",
                "family-a",
                ModelRole::Challenger,
            )?,
            entry(
                "entry-verifier",
                "host-a",
                "provider-v",
                "model-v",
                "family-a",
                ModelRole::Verifier,
            )?,
        ],
        ..snapshot()?
    };
    let human_policy = policy_for(&[
        ModelRole::MainAgent,
        ModelRole::Challenger,
        ModelRole::Verifier,
    ]);
    let candidate = launch_candidate(
        &catalogue,
        &human_policy,
        COMMAND_ID,
        vec![
            ModelRole::MainAgent,
            ModelRole::Challenger,
            ModelRole::Verifier,
        ],
    )?;
    let binding = bind_swarm_launch(&bind_request(&candidate, &catalogue, &human_policy))?;
    assert_candidate_ceiling(&binding)?;
    assert!(
        !binding.staffing.is_complete(),
        "same-family challenger/verifier must leave typed gaps"
    );
    for role in [ModelRole::Challenger, ModelRole::Verifier] {
        let gap = binding.staffing.gaps.iter().find(|gap| {
            matches!(
                gap,
                StaffingGap::DegradedIndependence { role: gap_role, .. } if *gap_role == role
            )
        });
        assert!(
            gap.is_some(),
            "same-family {role:?} must remain a degraded-independence gap"
        );
        let decision = binding
            .staffing
            .independence
            .iter()
            .find(|decision| decision.role == role)
            .ok_or("independence decision must exist")?;
        assert!(
            matches!(
                decision.outcome,
                StaffingIndependenceOutcome::Degraded { .. }
            ),
            "same-family {role:?} must never read as independent"
        );
    }
    Ok(())
}

#[test]
fn launch_binding_output_claims_no_authority() -> TestResult {
    let catalogue = snapshot()?;
    let human_policy = policy();
    let candidate = launch_candidate(
        &catalogue,
        &human_policy,
        COMMAND_ID,
        vec![ModelRole::MainAgent, ModelRole::Worker],
    )?;
    let binding = bind_swarm_launch(&bind_request(&candidate, &catalogue, &human_policy))?;
    let wire = serde_json::to_value(&binding)?.to_string().to_lowercase();
    for forbidden in [
        "lease_id",
        "attempt_id",
        "argv",
        "credential",
        "session_id",
        "finish",
        "admitted_route",
        "admission_receipt",
        "routing_receipt",
        "mailbox",
        "concilium",
        "work_unit",
        "role_profile",
        "process_control",
        "secret",
    ] {
        assert!(
            !wire.contains(forbidden),
            "binding output must not claim `{forbidden}`"
        );
    }
    Ok(())
}
