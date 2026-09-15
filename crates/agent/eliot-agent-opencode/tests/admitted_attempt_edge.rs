//! Admitted read-only attempt edge (issue #487).
//!
//! One externally admitted `AgentAttempt` flows through the supervised
//! attach-only loopback route, read-only, and seals to a candidate-only
//! artifact. Exactly two tests: the admitted happy path against a
//! deterministic fake loopback server (replay-stable seal, candidate-only
//! ceiling), and the fail-closed matrix (missing/stale admission,
//! attempt/lease/fence/route/model mismatch, terminal attempt, and sealing
//! negatives) with no live provider call.

use eliot_agent_api::{
    AdmittedRouteReceipt, AgentAttempt, AgentWorkUnitBrief, AttemptId, AttemptState,
    AuthorityEnvelope, BudgetEnvelope, CONTRACT_VERSION, CancellationState,
    CandidateSelectionDisposition, ContinuityKind, EffectCeiling, EffectKind, ExecutionUnit,
    LaunchRequestId, NativeSession, NativeSessionLocator, NoRouteDisposition, PolicyRevision,
    ProofCeiling, ProviderExecutionBinding, RequestId, RouteFingerprint, RouteSelectionCandidate,
    WorkUnitId, candidate_digest_for,
};
use eliot_agent_opencode::{
    AdmittedAttemptCandidate, AdmittedAttemptError, AdmittedOpenCodeAttempt, AuthorityCeiling,
    BasicAuth, LoopbackEndpoint, ModelSelection, NoAuthorityRunResult, OpenCodeClient,
    OpenCodeRunPolicy, OpenCodeWireRouteReceipt, QuotaAvailability, ReadOnlyRunRequest, RunStatus,
    UsageAvailability,
};
use eliot_contracts::{
    DecisionId, EpochId, EpochLineageId, LowercaseSha256, ResourceGeneration, StateFence, TaskId,
    WorkLeaseId,
};
use secrecy::SecretString;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::num::NonZeroU64;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

const DIRECTORY: &str = r"C:\Scratch";
const SESSION_ID: &str = "ses_487";
const MESSAGE_ID: &str = "msg_487_edge_1";
const ASSISTANT_ID: &str = "msg_assistant_487";
const PROVIDER: &str = "opencode-go";
const MODEL: &str = "deepseek-v4-flash";
const LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440001";
const SCOPE: &str = "scope:487";

#[tokio::test]
async fn admitted_happy_path_seals_replay_stable_candidate()
-> Result<(), Box<dyn std::error::Error>> {
    let parts = valid_parts()?;
    let request = ReadOnlyRunRequest::new("Return JSON status.", parts.model.clone())?
        .with_message_id(MESSAGE_ID)?;
    let responses = happy_path_responses()?;
    let client = client_for(responses).await?;
    let outcome = client
        .run_admitted_read_only(&parts.edge, &request, &parts.fence, parts.generation)
        .await?;

    assert_eq!(outcome.run.status, RunStatus::Succeeded);
    assert!(outcome.run.candidate_only);
    assert_eq!(outcome.run.authority, AuthorityCeiling::CandidateOnly);
    assert_eq!(outcome.run.output, Some(json!({"status": "ready"})));
    assert!(outcome.run.diff.is_empty());
    assert!(!outcome.run.events.is_empty());
    for event in &outcome.run.events {
        let bound = event
            .properties
            .get("sessionID")
            .and_then(Value::as_str)
            .is_some_and(|observed| observed == SESSION_ID);
        assert!(bound || event.event_type == "server.connected");
    }

    let candidate = &outcome.candidate;
    assert_eq!(candidate.attempt_id, AttemptId::new("attempt-487")?);
    assert_eq!(
        candidate.admitted_route_digest,
        *parts.edge.admitted_route_digest()
    );
    assert_eq!(candidate.authority, AuthorityCeiling::CandidateOnly);
    assert_eq!(candidate.status, RunStatus::Succeeded);

    let first_digest = parts.edge.attempt_digest()?;
    assert_eq!(parts.edge.attempt_digest()?, first_digest);
    let resealed = AdmittedAttemptCandidate::seal(&parts.edge, &outcome.run)?;
    assert_eq!(resealed.compute_digest()?, candidate.compute_digest()?);
    assert_eq!(resealed, *candidate);

    let wire = serde_json::to_value(candidate)?;
    let keys: BTreeSet<String> = wire
        .as_object()
        .ok_or("sealed candidate must serialize as an object")?
        .keys()
        .cloned()
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "admitted_route_digest".to_owned(),
            "attempt_id".to_owned(),
            "authority".to_owned(),
            "result_digest".to_owned(),
            "status".to_owned(),
        ])
    );
    Ok(())
}

#[tokio::test]
async fn admission_mismatch_fails_closed_before_dispatch() -> Result<(), Box<dyn std::error::Error>>
{
    let parts = valid_parts()?;
    reject_identity_mismatches(&parts)?;
    reject_stale_context(&parts)?;
    reject_route_model_and_terminal(&parts)?;
    reject_unsealable_results(&parts);

    let drifted_request = ReadOnlyRunRequest::new(
        "Return JSON status.",
        ModelSelection::new("other-provider", "other-model")?,
    )?
    .with_message_id("msg_487_drifted")?;
    let endpoint = "http://127.0.0.1:9".parse::<LoopbackEndpoint>()?;
    let policy = OpenCodeRunPolicy::new(Path::new(DIRECTORY))?
        .with_timeouts(Duration::from_secs(2), Duration::from_millis(100));
    let client = OpenCodeClient::new(
        endpoint,
        BasicAuth::new("opencode", SecretString::from("secret".to_owned()))?,
        policy,
    )?;
    let error = client
        .run_admitted_read_only(
            &parts.edge,
            &drifted_request,
            &parts.fence,
            parts.generation,
        )
        .await;
    assert!(matches!(error, Err(AdmittedAttemptError::ModelMismatch)));
    Ok(())
}

fn reject_identity_mismatches(parts: &ValidParts) -> Result<(), Box<dyn std::error::Error>> {
    let missing = AdmittedOpenCodeAttempt::new(
        None,
        parts.binding.clone(),
        parts.attempt.clone(),
        parts.model.clone(),
        &parts.fence,
        parts.generation,
    );
    assert!(matches!(
        missing,
        Err(AdmittedAttemptError::MissingAdmission)
    ));

    let wrong_attempt = with_admission(parts, |overrides| {
        overrides.attempt_id = Some(AttemptId::new("attempt-other")?);
        Ok(())
    })?;
    assert!(matches!(
        wrong_attempt,
        Err(AdmittedAttemptError::AttemptMismatch)
    ));

    let wrong_lease = with_admission(parts, |overrides| {
        overrides.lease = Some(fixture_lease("lease-other")?);
        Ok(())
    })?;
    assert!(matches!(
        wrong_lease,
        Err(AdmittedAttemptError::LeaseMismatch)
    ));
    Ok(())
}

fn reject_stale_context(parts: &ValidParts) -> Result<(), Box<dyn std::error::Error>> {
    let stale_fence = StateFence::new(fixture_epoch(2)?, fixture_generation()?);
    let stale_admission = with_admission(parts, |overrides| {
        overrides.fence = Some(stale_fence.clone());
        Ok(())
    })?;
    assert!(matches!(
        stale_admission,
        Err(AdmittedAttemptError::FenceMismatch)
    ));
    assert!(matches!(
        parts.edge.verify(&stale_fence, parts.generation),
        Err(AdmittedAttemptError::FenceMismatch)
    ));

    let stale_admission = with_admission(parts, |overrides| {
        overrides.generation = Some(ResourceGeneration::new(2)?);
        Ok(())
    })?;
    assert!(matches!(
        stale_admission,
        Err(AdmittedAttemptError::GenerationMismatch)
    ));
    assert!(matches!(
        parts.edge.verify(&parts.fence, ResourceGeneration::new(2)?),
        Err(AdmittedAttemptError::GenerationMismatch)
    ));
    Ok(())
}

fn reject_route_model_and_terminal(parts: &ValidParts) -> Result<(), Box<dyn std::error::Error>> {
    let other_route = fixture_route_with(PROVIDER, "other-model")?;
    let wrong_route = with_admission(parts, |overrides| {
        overrides.route = Some(other_route.clone());
        Ok(())
    })?;
    assert!(matches!(
        wrong_route,
        Err(AdmittedAttemptError::RouteMismatch)
    ));

    let no_route = with_admission(parts, |overrides| {
        overrides.no_route = true;
        Ok(())
    })?;
    assert!(matches!(no_route, Err(AdmittedAttemptError::RouteMismatch)));

    let wrong_requested = with_admission(parts, |overrides| {
        overrides.requested = Some(other_route.clone());
        Ok(())
    })?;
    assert!(matches!(
        wrong_requested,
        Err(AdmittedAttemptError::RouteMismatch)
    ));

    let other_model = ModelSelection::new("other-provider", "other-model")?;
    let wrong_model = AdmittedOpenCodeAttempt::new(
        Some(parts.admission.clone()),
        parts.binding.clone(),
        parts.attempt.clone(),
        other_model,
        &parts.fence,
        parts.generation,
    );
    assert!(matches!(
        wrong_model,
        Err(AdmittedAttemptError::ModelMismatch)
    ));

    let terminal = fixture_attempt(&parts.binding, AttemptState::Cancelled)?;
    let terminal_edge = AdmittedOpenCodeAttempt::new(
        Some(parts.admission.clone()),
        parts.binding.clone(),
        terminal,
        parts.model.clone(),
        &parts.fence,
        parts.generation,
    );
    assert!(matches!(
        terminal_edge,
        Err(AdmittedAttemptError::AttemptTerminal)
    ));

    let matching_request =
        ReadOnlyRunRequest::new("Return JSON status.", ModelSelection::new(PROVIDER, MODEL)?)?;
    let drifted_request = ReadOnlyRunRequest::new(
        "Return JSON status.",
        ModelSelection::new("other-provider", "other-model")?,
    )?;
    assert!(parts.edge.verify_request(&matching_request).is_ok());
    assert!(matches!(
        parts.edge.verify_request(&drifted_request),
        Err(AdmittedAttemptError::ModelMismatch)
    ));
    Ok(())
}

fn reject_unsealable_results(parts: &ValidParts) {
    let outputless = NoAuthorityRunResult {
        status: RunStatus::Succeeded,
        candidate_only: true,
        authority: AuthorityCeiling::CandidateOnly,
        actual_route: OpenCodeWireRouteReceipt::unavailable(
            parts.model.clone(),
            "server did not attest route",
        ),
        usage: UsageAvailability::unavailable("usage endpoint unavailable"),
        quota: QuotaAvailability::unavailable("quota endpoint unavailable"),
        session_id: None,
        output: None,
        events: Vec::new(),
        diff: Vec::new(),
        extra: BTreeMap::new(),
    };
    assert!(matches!(
        AdmittedAttemptCandidate::seal(&parts.edge, &outputless),
        Err(AdmittedAttemptError::SealRejected { .. })
    ));

    let forged = json!({
        "attempt_id": "attempt-487",
        "admitted_route_digest": "0000000000000000000000000000000000000000000000000000000000000000",
        "result_digest": "0000000000000000000000000000000000000000000000000000000000000000",
        "authority": "unbounded",
        "status": "succeeded",
    });
    assert!(serde_json::from_value::<AdmittedAttemptCandidate>(forged).is_err());
}

struct ValidParts {
    edge: AdmittedOpenCodeAttempt,
    binding: ProviderExecutionBinding,
    admission: AdmittedRouteReceipt,
    attempt: AgentAttempt,
    model: ModelSelection,
    fence: StateFence,
    generation: ResourceGeneration,
}

fn valid_parts() -> Result<ValidParts, Box<dyn std::error::Error>> {
    let route = fixture_route()?;
    let fence = StateFence::new(fixture_epoch(1)?, fixture_generation()?);
    let generation = fixture_generation()?;
    let lease = fixture_lease("lease-487")?;
    let attempt_id = AttemptId::new("attempt-487")?;
    let binding = fixture_binding(&route, &attempt_id, &lease, &fence, generation)?;
    let admission = fixture_admission(&binding, AdmissionOverrides::default())?;
    let attempt = fixture_attempt(&binding, AttemptState::Admitted)?;
    let model = ModelSelection::new(PROVIDER, MODEL)?;
    let edge = AdmittedOpenCodeAttempt::new(
        Some(admission.clone()),
        binding.clone(),
        attempt.clone(),
        model.clone(),
        &fence,
        generation,
    )?;
    Ok(ValidParts {
        edge,
        binding,
        admission,
        attempt,
        model,
        fence,
        generation,
    })
}

fn with_admission(
    parts: &ValidParts,
    configure: impl FnOnce(&mut AdmissionOverrides) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<Result<AdmittedOpenCodeAttempt, AdmittedAttemptError>, Box<dyn std::error::Error>> {
    let mut overrides = AdmissionOverrides::default();
    configure(&mut overrides)?;
    let admission = fixture_admission(&parts.binding, overrides)?;
    Ok(AdmittedOpenCodeAttempt::new(
        Some(admission),
        parts.binding.clone(),
        parts.attempt.clone(),
        parts.model.clone(),
        &parts.fence,
        parts.generation,
    ))
}

#[derive(Default)]
struct AdmissionOverrides {
    attempt_id: Option<AttemptId>,
    lease: Option<WorkLeaseId>,
    fence: Option<StateFence>,
    generation: Option<ResourceGeneration>,
    route: Option<RouteFingerprint>,
    requested: Option<RouteFingerprint>,
    no_route: bool,
}

fn fixture_digest(seed: &str) -> Result<LowercaseSha256, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(json!(eliot_contracts::sha256_hex(
        format!("opencode-487-{seed}").as_bytes()
    )))?)
}

fn fixture_epoch(sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
    let lineage = EpochLineageId::new(LINEAGE)?;
    let sequence = NonZeroU64::new(sequence).ok_or("epoch sequence must be nonzero")?;
    Ok(EpochId::new(lineage, sequence)?)
}

fn fixture_generation() -> Result<ResourceGeneration, Box<dyn std::error::Error>> {
    Ok(ResourceGeneration::new(1)?)
}

fn fixture_lease(value: &str) -> Result<WorkLeaseId, Box<dyn std::error::Error>> {
    Ok(serde_json::from_value(json!({
        "namespace": "eliot.governor.work-lease",
        "revision": "v1",
        "value": value,
    }))?)
}

fn fixture_route() -> Result<RouteFingerprint, Box<dyn std::error::Error>> {
    fixture_route_with(PROVIDER, MODEL)
}

fn fixture_route_with(
    provider: &str,
    model: &str,
) -> Result<RouteFingerprint, Box<dyn std::error::Error>> {
    Ok(RouteFingerprint {
        host_family: "opencode".to_owned(),
        adapter: "eliot-agent-opencode".to_owned(),
        protocol_transport: "http+sse".to_owned(),
        runtime_hash: fixture_digest("runtime")?,
        adapter_hash: fixture_digest("adapter")?,
        provider: provider.to_owned(),
        model: model.to_owned(),
        auth_billing: "interactive-user".to_owned(),
        serializer_hash: fixture_digest("serializer")?,
        tool_semantics_hash: fixture_digest("tools")?,
        reasoning_mode: "catalogue-default".to_owned(),
        continuation_behavior: "native-resume".to_owned(),
        feature_flags_hash: fixture_digest("features")?,
    })
}

fn fixture_binding(
    route: &RouteFingerprint,
    attempt_id: &AttemptId,
    lease: &WorkLeaseId,
    fence: &StateFence,
    generation: ResourceGeneration,
) -> Result<ProviderExecutionBinding, Box<dyn std::error::Error>> {
    Ok(ProviderExecutionBinding {
        attempt_id: attempt_id.clone(),
        lease_id: lease.clone(),
        state_fence: fence.clone(),
        runtime_generation: generation,
        route: route.clone(),
        session_id: None,
        provider_scope_ref: SCOPE.to_owned(),
        native_session: NativeSession::Native(NativeSessionLocator::new(SESSION_ID)?),
        execution_unit: ExecutionUnit::new("opencode", "unit-487")?,
        start_request_id: RequestId::new("req-487")?,
        start_request_sha256: eliot_contracts::sha256_hex(b"req-487"),
    })
}

fn fixture_admission(
    binding: &ProviderExecutionBinding,
    overrides: AdmissionOverrides,
) -> Result<AdmittedRouteReceipt, Box<dyn std::error::Error>> {
    let route = overrides.route.unwrap_or_else(|| binding.route.clone());
    let candidate = RouteSelectionCandidate {
        capability: "opencode".to_owned(),
        query_intent: "read-only candidate synthesis".to_owned(),
        scope_ref: SCOPE.to_owned(),
        policy_revision: PolicyRevision::new(3)?,
        candidates: vec![route.clone()],
        selected: Some(route.clone()),
        rejected: Vec::new(),
        selection: CandidateSelectionDisposition::Selected,
        evidence_refs: vec!["evidence-487".to_owned()],
    };
    candidate.validate()?;
    let zero: LowercaseSha256 = serde_json::from_value(json!(
        "0000000000000000000000000000000000000000000000000000000000000000"
    ))?;
    let mut receipt = AdmittedRouteReceipt {
        schema_version: CONTRACT_VERSION.to_owned(),
        decision_id: DecisionId::new("decision-487")?,
        candidate_digest: candidate_digest_for(&candidate)?,
        attempt_id: overrides
            .attempt_id
            .unwrap_or_else(|| binding.attempt_id.clone()),
        lease_id: overrides.lease.unwrap_or_else(|| binding.lease_id.clone()),
        state_fence: overrides
            .fence
            .unwrap_or_else(|| binding.state_fence.clone()),
        runtime_generation: overrides.generation.unwrap_or(binding.runtime_generation),
        policy_revision: PolicyRevision::new(3)?,
        requested_route: overrides.requested.unwrap_or_else(|| binding.route.clone()),
        selected_route: if overrides.no_route {
            None
        } else {
            Some(route)
        },
        no_route: if overrides.no_route {
            Some(NoRouteDisposition::AdmissionDenied)
        } else {
            None
        },
        evidence_refs: vec!["evidence-487".to_owned()],
        proof_ceiling: ProofCeiling::CandidateArtifact,
        self_digest: zero,
    };
    receipt.self_digest = receipt.compute_digest()?;
    receipt.validate()?;
    Ok(receipt)
}

fn fixture_attempt(
    binding: &ProviderExecutionBinding,
    state: AttemptState,
) -> Result<AgentAttempt, Box<dyn std::error::Error>> {
    let budget = BudgetEnvelope {
        context_tokens: 4096,
        wall_time_ms: 60_000,
        output_bytes: 65_536,
        cost_microunits: 1000,
        max_depth: 2,
        max_descendants: 4,
    };
    let allowed: BTreeSet<EffectKind> =
        BTreeSet::from([EffectKind::Observe, EffectKind::ReadWorkspace]);
    let ceiling = EffectCeiling {
        scope_ref: SCOPE.to_owned(),
        allowed,
        max_external_effects: 0,
    };
    Ok(AgentAttempt {
        id: binding.attempt_id.clone(),
        launch_request_id: LaunchRequestId::new("launch-487")?,
        task_id: TaskId::new("task-487")?,
        parent_attempt: None,
        work_unit: AgentWorkUnitBrief {
            id: WorkUnitId::new("unit-487")?,
            objective: "return a read-only status candidate".to_owned(),
            causal_property: "read-only candidate synthesis".to_owned(),
            scope_ref: SCOPE.to_owned(),
            expected_outputs: vec!["status".to_owned()],
            source_refs: Vec::new(),
            verifier_ref: "verifier-487".to_owned(),
            integration_owner: "mgr02".to_owned(),
            contract_revision: "v1".to_owned(),
            budget: budget.clone(),
            effect_ceiling: ceiling.clone(),
            stop_condition: "terminal candidate sealed".to_owned(),
        },
        session: None,
        lease: binding.lease_id.clone(),
        state,
        continuity: ContinuityKind::Fresh,
        route: binding.route.clone(),
        budget,
        authority: AuthorityEnvelope {
            epoch: binding.state_fence.authority_epoch.clone(),
            scope_ref: SCOPE.to_owned(),
            effect_ceiling: ceiling,
            lease: binding.lease_id.clone(),
            state_fence: binding.state_fence.clone(),
            valid_until: "2099-01-01T00:00:00Z".to_owned(),
        },
        cancellation: CancellationState::NotRequested,
        event_cursor: None,
        continuation: None,
        provider_binding: Some(binding.clone()),
    })
}

fn happy_path_responses() -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let mut responses = vec![
        json_response(br#"{"healthy":true,"version":"1.4.3"}"#),
        json_response(br#"{"all":[{"id":"opencode-go","models":{"deepseek-v4-flash":{"id":"deepseek-v4-flash"}}}],"default":{},"connected":["opencode-go"]}"#),
        json_response(br#"[{"name":"plan","mode":"primary","permission":{},"options":{}}]"#),
    ];
    let session = serde_json::to_vec(&json!({
        "id": SESSION_ID,
        "slug": "edge-487",
        "projectID": "p",
        "directory": DIRECTORY,
        "title": "ELIOT",
        "version": "1.4.3",
        "time": {"created": 1, "updated": 1},
        "permission": [
            {"permission": "*", "pattern": "*", "action": "deny"},
            {"permission": "read", "pattern": "*", "action": "allow"},
            {"permission": "read", "pattern": "*.env", "action": "deny"},
            {"permission": "read", "pattern": "*.env.*", "action": "deny"},
            {"permission": "glob", "pattern": "*", "action": "allow"},
            {"permission": "grep", "pattern": "*", "action": "allow"},
            {"permission": "list", "pattern": "*", "action": "allow"}
        ]
    }))?;
    responses.push(json_response(&session));
    responses.push(json_response(br"[]"));
    let events = [
        json!({"type": "server.connected", "properties": {}}),
        json!({"type": "message.updated", "properties": {"sessionID": SESSION_ID, "info": {
            "id": ASSISTANT_ID, "sessionID": SESSION_ID, "parentID": MESSAGE_ID, "role": "assistant",
            "time": {"created": 2, "completed": 3},
            "providerID": PROVIDER, "modelID": MODEL, "finish": "stop"}}}),
        json!({"type": "message.part.updated", "properties": {"sessionID": SESSION_ID, "part": {
            "sessionID": SESSION_ID, "messageID": ASSISTANT_ID,
            "type": "step-finish", "reason": "stop"}}}),
        json!({"type": "session.status", "properties": {"sessionID": SESSION_ID, "status": {"type": "idle"}}}),
    ];
    let body: Vec<u8> = events
        .iter()
        .map(|event| format!("data: {event}\n\n").into_bytes())
        .collect::<Vec<_>>()
        .concat();
    responses.push(chunked_sse(&body));
    responses.push(no_content());
    responses.push(json_response(br#"{"ses_487":{"type":"idle"}}"#));
    let assistant = json!({"info": {"id": ASSISTANT_ID, "sessionID": SESSION_ID, "role": "assistant",
        "time": {"created": 2, "completed": 3}, "parentID": MESSAGE_ID,
        "modelID": MODEL, "providerID": PROVIDER,
        "mode": "plan", "agent": "plan",
        "path": {"cwd": DIRECTORY, "root": DIRECTORY},
        "cost": 0.01,
        "tokens": {"total": 12, "input": 7, "output": 5, "reasoning": 0, "cache": {"read": 0, "write": 0}},
        "finish": "stop"},
        "parts": [
            {"id": "part_text", "sessionID": SESSION_ID, "messageID": ASSISTANT_ID,
             "type": "text", "text": "{\"status\":\"ready\"}"},
            {"id": "part_1", "sessionID": SESSION_ID, "messageID": ASSISTANT_ID,
             "type": "step-finish", "reason": "stop"}]});
    let user = json!({"info": {"id": MESSAGE_ID, "sessionID": SESSION_ID, "role": "user",
        "time": {"created": 1}, "format": {"type": "text"}, "agent": "plan",
        "model": {"providerID": PROVIDER, "modelID": MODEL}}, "parts": []});
    responses.push(json_response(&serde_json::to_vec(&json!([
        user, assistant
    ]))?));
    responses.push(json_response(br"[]"));
    Ok(responses)
}

async fn client_for(responses: Vec<Vec<u8>>) -> Result<OpenCodeClient, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let captured = Arc::new(Mutex::new(Vec::new()));
    tokio::spawn(serve(listener, responses, Arc::clone(&captured)));
    let endpoint = format!("http://127.0.0.1:{port}").parse::<LoopbackEndpoint>()?;
    let policy = OpenCodeRunPolicy::new(Path::new(DIRECTORY))?
        .with_timeouts(Duration::from_secs(5), Duration::from_secs(2));
    Ok(OpenCodeClient::new(
        endpoint,
        BasicAuth::new("opencode", SecretString::from("secret".to_owned()))?,
        policy,
    )?)
}

async fn serve(listener: TcpListener, responses: Vec<Vec<u8>>, captured: Arc<Mutex<Vec<Vec<u8>>>>) {
    let responses = Arc::new(Mutex::new(VecDeque::from(responses)));
    loop {
        let Some(response) = responses.lock().await.pop_front() else {
            break;
        };
        let accepted = listener.accept().await;
        let Ok((mut stream, _)) = accepted else {
            break;
        };
        let mut raw = Vec::<u8>::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.unwrap_or(0);
            if read == 0 {
                break;
            }
            raw.extend_from_slice(&buffer[..read]);
            let Some(head_end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let content_length = String::from_utf8_lossy(&raw[..head_end])
                .lines()
                .find_map(|line| {
                    line.strip_prefix("Content-Length: ")
                        .and_then(|value| value.parse::<usize>().ok())
                })
                .unwrap_or(0);
            if raw.len() >= head_end + 4 + content_length {
                break;
            }
        }
        captured.lock().await.push(raw);
        let _ = stream.write_all(&response).await;
        let _ = stream.shutdown().await;
    }
}

fn json_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

fn chunked_sse(body: &[u8]) -> Vec<u8> {
    let mut response =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
            .to_vec();
    response.extend_from_slice(format!("{:X}\r\n", body.len()).as_bytes());
    response.extend_from_slice(body);
    response.extend_from_slice(b"\r\n0\r\n\r\n");
    response
}

fn no_content() -> Vec<u8> {
    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n".to_vec()
}
