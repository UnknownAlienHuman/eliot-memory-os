//! Focused swarm command-candidate tests for issue #484.
//!
//! Two groups only: happy-path compilation with candidate-only ceiling and
//! replay stability, plus the fail-closed negatives. Deferred cases are
//! listed in the issue work unit (`writer.md`).
//!
//! Proof ceiling: `AUTHENTICATED_SWARM_COMMAND_CANDIDATE_PACKAGE_PROOF_ONLY`.
//! Real `AccessBinding` verification inside `ControlBoard` stays MGR01 lane.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU64;

use eliot_agent_api::{
    AttemptId, EpochId, LowercaseSha256, ResourceGeneration, RouteFingerprint, StateFence,
};
use eliot_agent_coordinator::{
    ATTEMPT_HEALTH_PROJECTION_VERSION, AttemptAutomationDisposition, AttemptHealthProjection,
    AttemptLivenessStatus, AttemptTerminalReconciliation, AttemptWorkEligibility, BillingClass,
    BillingEvidence, CancelAttemptRequest, HumanModelPreferencePolicy, LaunchSwarmRequest,
    MODEL_CATALOGUE_SCHEMA_VERSION, MODEL_PREFERENCE_SCHEMA_VERSION, ModelAvailability,
    ModelCatalogueEntry, ModelCatalogueSnapshot, ModelControlError, ModelRole, QuotaDisposition,
    QuotaObservation, RefreshCatalogueRequest, ReplacePreferencePolicyRequest, RoleModelPreference,
    RouteAdmissionStatus, RouteHealthStatus, SwarmAttemptProjection, SwarmAttemptSelectionBinding,
    SwarmCommandCallerBinding, SwarmCommandCandidate, SwarmCommandCandidateError, SwarmCommandKind,
    SwarmCommandReplayDisposition, ZeroModelExecutionCounters, compile_cancel_attempt_candidate,
    compile_launch_swarm_candidate, compile_model_selection, compile_refresh_catalogue_candidate,
    compile_replace_policy_candidate,
};
use eliot_contracts::{EpochLineageId, sha256_hex};

const NOW: u64 = 10_000;
const ACCOUNT: &str = "account-scope-1";
const CATALOGUE_ID: &str = "catalogue-commands";
const POLICY_ID: &str = "human-policy";
const POLICY_REVISION: &str = "revision-1";
const VIEW_REVISION: &str = "view-revision-7";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn digest(seed: &str) -> TestResult<LowercaseSha256> {
    Ok(serde_json::from_value(serde_json::json!(sha256_hex(
        format!("command-fixture-{seed}").as_bytes()
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
    Ok(ModelCatalogueEntry {
        entry_id: entry_id.to_owned(),
        account_scope: ACCOUNT.to_owned(),
        host_family: host.to_owned(),
        provider_id: provider.to_owned(),
        model_id: model.to_owned(),
        model_family: family.to_owned(),
        route: route(host, provider, model, entry_id)?,
        route_admission: RouteAdmissionStatus::Admitted,
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

/// Two single-role entries on disjoint host/provider/model-family routes.
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

fn policy() -> HumanModelPreferencePolicy {
    HumanModelPreferencePolicy {
        schema_version: MODEL_PREFERENCE_SCHEMA_VERSION.to_owned(),
        policy_id: POLICY_ID.to_owned(),
        revision: POLICY_REVISION.to_owned(),
        account_scope: ACCOUNT.to_owned(),
        roles: vec![
            role_preference(ModelRole::MainAgent),
            role_preference(ModelRole::Worker),
        ],
    }
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

fn binding(command_id: &str) -> TestResult<SwarmCommandCallerBinding> {
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

fn visible_attempt(
    snapshot: &ModelCatalogueSnapshot,
    policy: &HumanModelPreferencePolicy,
    role: ModelRole,
    selection_id: &str,
    attempt: &str,
) -> TestResult<SwarmAttemptProjection> {
    let receipt = compile_model_selection(snapshot, policy, role, selection_id, NOW)?;
    Ok(SwarmAttemptProjection {
        selection_id: receipt.selection_id.clone(),
        selection_digest: receipt.selection_digest.clone(),
        account_scope: receipt.account_scope.clone(),
        role: receipt.role,
        catalogue_snapshot_id: receipt.catalogue_snapshot_id.clone(),
        catalogue_digest: receipt.catalogue_digest.clone(),
        preference_policy_id: receipt.preference_policy_id.clone(),
        preference_revision: receipt.preference_revision.clone(),
        preference_policy_digest: receipt.preference_policy_digest.clone(),
        selected: receipt.selected.clone(),
        selection_binding: SwarmAttemptSelectionBinding::ExactCurrent,
        health: AttemptHealthProjection {
            schema_version: ATTEMPT_HEALTH_PROJECTION_VERSION.to_owned(),
            attempt_id: AttemptId::new(attempt)?,
            observed_at_unix_ms: NOW,
            status: AttemptLivenessStatus::Live,
            alerts: Vec::new(),
            work_eligibility: AttemptWorkEligibility::Eligible,
            terminal_reconciliation: AttemptTerminalReconciliation::Unreconciled,
            automation: AttemptAutomationDisposition::ManualOnly,
        },
    })
}

fn assert_wire_ceiling(candidate: &SwarmCommandCandidate) -> TestResult {
    assert!(candidate.candidate_only);
    assert!(!candidate.dispatch_authority);
    assert_eq!(
        candidate.execution,
        ZeroModelExecutionCounters::zero(),
        "command execution counters must stay zero"
    );
    assert!(candidate.candidate_only());
    assert!(!candidate.dispatch_authority());
    assert_eq!(candidate.execution(), ZeroModelExecutionCounters::zero());
    let round_trip: SwarmCommandCandidate =
        serde_json::from_value(serde_json::to_value(candidate)?)?;
    assert_eq!(round_trip, *candidate);
    round_trip.validate()?;

    let mut tampered = serde_json::to_value(candidate)?;
    tampered["view_revision"] = serde_json::json!("tampered-view");
    assert!(
        serde_json::from_value::<SwarmCommandCandidate>(tampered).is_err(),
        "changed command bytes must conflict on the command digest"
    );
    let mut ceiling_tampered = serde_json::to_value(candidate)?;
    ceiling_tampered["candidate_only"] = serde_json::json!(false);
    assert!(
        serde_json::from_value::<SwarmCommandCandidate>(ceiling_tampered).is_err(),
        "a non-candidate ceiling must fail closed on deserialize"
    );
    Ok(())
}

fn happy_refresh(catalogue: &ModelCatalogueSnapshot) -> TestResult<SwarmCommandCandidate> {
    let request = RefreshCatalogueRequest {
        binding: binding("command-refresh")?,
        account_scope: ACCOUNT.to_owned(),
        catalogue: catalogue.clone(),
        reason: "operator refresh".to_owned(),
    };
    let candidate = compile_refresh_catalogue_candidate(&request)?;
    assert!(matches!(
        candidate.kind,
        SwarmCommandKind::RefreshCatalogue { .. }
    ));
    assert_wire_ceiling(&candidate)?;
    let replay = compile_refresh_catalogue_candidate(&request)?;
    assert_eq!(
        candidate, replay,
        "exact replay must reproduce the exact candidate"
    );
    assert_eq!(
        candidate.replay_disposition(&replay)?,
        SwarmCommandReplayDisposition::ExactReplay
    );
    Ok(candidate)
}

fn happy_replace(
    catalogue: &ModelCatalogueSnapshot,
    human_policy: &HumanModelPreferencePolicy,
) -> TestResult<SwarmCommandCandidate> {
    let probe = compile_model_selection(
        catalogue,
        human_policy,
        ModelRole::MainAgent,
        "selection-probe",
        NOW,
    )?;
    let request = ReplacePreferencePolicyRequest {
        binding: binding("command-replace")?,
        account_scope: ACCOUNT.to_owned(),
        policy: human_policy.clone(),
        expected_policy_revision: POLICY_REVISION.to_owned(),
        expected_policy_digest: probe.preference_policy_digest.clone(),
    };
    let candidate = compile_replace_policy_candidate(&request)?;
    match &candidate.kind {
        SwarmCommandKind::ReplacePreferencePolicy { policy, .. } => {
            assert_eq!(
                policy, human_policy,
                "replacement must preserve the exact full policy"
            );
        }
        other => panic!("expected preference replacement, got {other:?}"),
    }
    assert_wire_ceiling(&candidate)?;
    Ok(candidate)
}

fn happy_launch(
    catalogue: &ModelCatalogueSnapshot,
    human_policy: &HumanModelPreferencePolicy,
) -> TestResult<(LaunchSwarmRequest, SwarmCommandCandidate)> {
    let request = LaunchSwarmRequest {
        binding: binding("command-launch")?,
        account_scope: ACCOUNT.to_owned(),
        catalogue: catalogue.clone(),
        policy: human_policy.clone(),
        task_id: "task-1".to_owned(),
        plan_revision: "plan-revision-3".to_owned(),
        demand: vec![ModelRole::Worker, ModelRole::MainAgent],
    };
    let candidate = compile_launch_swarm_candidate(&request)?;
    match &candidate.kind {
        SwarmCommandKind::RequestSwarmLaunch { demand, routes, .. } => {
            assert_eq!(*demand, vec![ModelRole::MainAgent, ModelRole::Worker]);
            assert_eq!(routes.len(), 2, "every requested role needs a bound route");
        }
        other => panic!("expected swarm launch, got {other:?}"),
    }
    assert_wire_ceiling(&candidate)?;
    Ok((request, candidate))
}

fn assert_launch_replay_rules(
    launch_request: &LaunchSwarmRequest,
    launch: &SwarmCommandCandidate,
    refresh: &SwarmCommandCandidate,
) -> TestResult {
    assert_eq!(
        launch.replay_disposition(refresh)?,
        SwarmCommandReplayDisposition::NewCommand,
        "a different command id is a new command, not a replay"
    );
    let conflict_request = LaunchSwarmRequest {
        plan_revision: "plan-revision-4".to_owned(),
        ..launch_request.clone()
    };
    let conflict = compile_launch_swarm_candidate(&conflict_request)?;
    assert!(
        matches!(
            launch.replay_disposition(&conflict),
            Err(SwarmCommandCandidateError::IdentityConflict)
        ),
        "reusing a command id with changed bytes must conflict"
    );
    Ok(())
}

fn happy_cancel(
    catalogue: &ModelCatalogueSnapshot,
    human_policy: &HumanModelPreferencePolicy,
) -> TestResult<SwarmCommandCandidate> {
    let visible = visible_attempt(
        catalogue,
        human_policy,
        ModelRole::Worker,
        "selection-visible",
        "attempt-1",
    )?;
    let request = CancelAttemptRequest {
        binding: binding("command-cancel")?,
        account_scope: ACCOUNT.to_owned(),
        visible_attempts: vec![visible],
        attempt_id: AttemptId::new("attempt-1")?,
        reason: "operator cancel".to_owned(),
    };
    let candidate = compile_cancel_attempt_candidate(&request)?;
    match &candidate.kind {
        SwarmCommandKind::CancelAttempt { role, reason, .. } => {
            assert_eq!(*role, ModelRole::Worker);
            assert_eq!(reason, "operator cancel");
        }
        other => panic!("expected attempt cancel, got {other:?}"),
    }
    assert_wire_ceiling(&candidate)?;
    Ok(candidate)
}

#[test]
fn command_candidates_compile_candidate_only_and_replay_stable() -> TestResult {
    let catalogue = snapshot()?;
    let human_policy = policy();
    let refresh = happy_refresh(&catalogue)?;
    let _replace = happy_replace(&catalogue, &human_policy)?;
    let (launch_request, launch) = happy_launch(&catalogue, &human_policy)?;
    assert_launch_replay_rules(&launch_request, &launch, &refresh)?;
    let _cancel = happy_cancel(&catalogue, &human_policy)?;
    Ok(())
}

fn refresh_request(catalogue: &ModelCatalogueSnapshot) -> TestResult<RefreshCatalogueRequest> {
    Ok(RefreshCatalogueRequest {
        binding: binding("command-refresh")?,
        account_scope: ACCOUNT.to_owned(),
        catalogue: catalogue.clone(),
        reason: "operator refresh".to_owned(),
    })
}

fn assert_capability_negatives(request: &RefreshCatalogueRequest) {
    let mut no_capability = request.clone();
    no_capability.binding.capability_present = false;
    assert_eq!(
        compile_refresh_catalogue_candidate(&no_capability),
        Err(SwarmCommandCandidateError::MissingCapability),
        "a missing capability flag must fail closed"
    );
    let mut wrong_scope = request.clone();
    "other-scope".clone_into(&mut wrong_scope.binding.capability_scope);
    assert_eq!(
        compile_refresh_catalogue_candidate(&wrong_scope),
        Err(SwarmCommandCandidateError::MissingCapability),
        "a capability scoped elsewhere must fail closed"
    );
}

fn assert_view_negatives(request: &RefreshCatalogueRequest) -> TestResult {
    let mut stale_revision = request.clone();
    "view-revision-8".clone_into(&mut stale_revision.binding.expected_view_revision);
    assert_eq!(
        compile_refresh_catalogue_candidate(&stale_revision),
        Err(SwarmCommandCandidateError::StaleView),
        "a stale view revision must fail closed"
    );
    let mut stale_fence = request.clone();
    stale_fence.binding.expected_view_fence = fence(2)?;
    assert_eq!(
        compile_refresh_catalogue_candidate(&stale_fence),
        Err(SwarmCommandCandidateError::StaleView),
        "a stale view fence must fail closed"
    );
    Ok(())
}

fn replace_request(
    human_policy: &HumanModelPreferencePolicy,
    expected_digest: &str,
) -> TestResult<ReplacePreferencePolicyRequest> {
    Ok(ReplacePreferencePolicyRequest {
        binding: binding("command-replace")?,
        account_scope: ACCOUNT.to_owned(),
        policy: human_policy.clone(),
        expected_policy_revision: POLICY_REVISION.to_owned(),
        expected_policy_digest: expected_digest.to_owned(),
    })
}

fn assert_policy_negatives(
    human_policy: &HumanModelPreferencePolicy,
    actual_digest: &str,
) -> TestResult {
    let mut stale_revision = replace_request(human_policy, actual_digest)?;
    "revision-0".clone_into(&mut stale_revision.expected_policy_revision);
    assert_eq!(
        compile_replace_policy_candidate(&stale_revision),
        Err(SwarmCommandCandidateError::StalePolicy),
        "a stale expected policy revision must fail closed"
    );
    let mut digest_text = actual_digest.to_owned();
    digest_text.pop();
    if actual_digest.ends_with('0') {
        digest_text.push('1');
    } else {
        digest_text.push('0');
    }
    let stale_digest = replace_request(human_policy, &digest_text)?;
    assert_eq!(
        compile_replace_policy_candidate(&stale_digest),
        Err(SwarmCommandCandidateError::StalePolicy),
        "a stale expected policy digest must fail closed"
    );
    Ok(())
}

fn assert_launch_and_cancel_negatives(
    catalogue: &ModelCatalogueSnapshot,
    human_policy: &HumanModelPreferencePolicy,
) -> TestResult {
    let unstaffable = LaunchSwarmRequest {
        binding: binding("command-launch")?,
        account_scope: ACCOUNT.to_owned(),
        catalogue: catalogue.clone(),
        policy: human_policy.clone(),
        task_id: "task-1".to_owned(),
        plan_revision: "plan-revision-3".to_owned(),
        demand: vec![ModelRole::MainAgent, ModelRole::Dreamer],
    };
    assert!(
        matches!(
            compile_launch_swarm_candidate(&unstaffable),
            Err(SwarmCommandCandidateError::ModelControl(
                ModelControlError::MissingRolePolicy(ModelRole::Dreamer)
            ))
        ),
        "a role without a dispatchable eligible route must fail the launch closed"
    );

    let visible = visible_attempt(
        catalogue,
        human_policy,
        ModelRole::Worker,
        "selection-visible",
        "attempt-1",
    )?;
    let absent = CancelAttemptRequest {
        binding: binding("command-cancel")?,
        account_scope: ACCOUNT.to_owned(),
        visible_attempts: vec![visible],
        attempt_id: AttemptId::new("attempt-absent")?,
        reason: "operator cancel".to_owned(),
    };
    assert_eq!(
        compile_cancel_attempt_candidate(&absent),
        Err(SwarmCommandCandidateError::UnknownAttempt),
        "an attempt outside the visible view must fail closed"
    );
    Ok(())
}

#[test]
fn command_candidates_fail_closed() -> TestResult {
    let catalogue = snapshot()?;
    let human_policy = policy();
    let refresh = refresh_request(&catalogue)?;
    assert_capability_negatives(&refresh);
    assert_view_negatives(&refresh)?;
    let probe = compile_model_selection(
        &catalogue,
        &human_policy,
        ModelRole::MainAgent,
        "selection-probe",
        NOW,
    )?;
    assert_policy_negatives(&human_policy, &probe.preference_policy_digest)?;
    assert_launch_and_cancel_negatives(&catalogue, &human_policy)
}
