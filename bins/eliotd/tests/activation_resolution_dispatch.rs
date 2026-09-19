//! Issue #839 dispatch matrix batch: cases 1, 2, 3, 20, and 22.
//!
//! These tests bind the existing daemon source seams to the accepted typed
//! protocol contracts. They do not add a transport simulator or widen a
//! production seam: live attach and production reachability remain outside
//! this slice.

use std::num::NonZeroU64;
use std::path::PathBuf;

use eliot_contracts::{EpochId, EpochLineageId, RequestId, ResourceGeneration, StateFence};
use eliot_protocol::{
    AgentActivationCandidateCoverage, AgentActivationResolutionDisposition,
    AgentActivationResolutionResult, AgentActivationResolutionTicket,
    AgentActivationResolvedBinding, AgentActivationResultAck, AgentActivationResultSubmit,
    AgentActivationRetryDirective, AgentActivationSelectionDirective,
};
use serde::Deserialize;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

#[derive(Debug, Deserialize)]
struct MatrixFixture {
    cases: Vec<MatrixCase>,
}

#[derive(Debug, Deserialize)]
struct MatrixCase {
    id: u8,
    name: String,
}

fn fixture() -> TestResult<MatrixFixture> {
    serde_json::from_str(include_str!("data/activation_resolution_dispatch.json"))
        .map_err(|error| format!("activation dispatch fixture: {error}").into())
}

fn assert_fixture_case(id: u8, expected_name: &str) -> TestResult {
    let fixture = fixture()?;
    let case = fixture
        .cases
        .iter()
        .find(|case| case.id == id)
        .ok_or_else(|| format!("fixture is missing case {id}"))?;
    assert_eq!(case.name, expected_name);
    Ok(())
}

fn source(relative: &str) -> TestResult<String> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path)
        .map_err(|error| format!("read {}: {error}", path.display()).into())
}

fn slice_between<'a>(source: &'a str, start: &str, end: &str) -> TestResult<&'a str> {
    let start_at = source
        .find(start)
        .ok_or_else(|| format!("source is missing anchor {start:?}"))?;
    let body = &source[start_at..];
    let end_at = body
        .find(end)
        .ok_or_else(|| format!("source is missing closing anchor {end:?}"))?;
    Ok(&body[..end_at])
}

fn assert_ordered(source: &str, markers: &[&str]) -> TestResult {
    let mut cursor = 0;
    for marker in markers {
        let relative = source[cursor..]
            .find(marker)
            .ok_or_else(|| format!("source is missing ordered marker {marker:?}"))?;
        cursor += relative + marker.len();
    }
    Ok(())
}

fn test_epoch(sequence: u64) -> TestResult<EpochId> {
    let lineage = EpochLineageId::new(TEST_LINEAGE)?;
    let sequence = NonZeroU64::new(sequence).ok_or("test epoch sequence must be non-zero")?;
    Ok(EpochId::new(lineage, sequence)?)
}

fn test_fence(generation: u64) -> TestResult<StateFence> {
    Ok(StateFence::new(
        test_epoch(1)?,
        ResourceGeneration::new(generation)?,
    ))
}

fn valid_ticket(id: &str) -> TestResult<AgentActivationResolutionTicket> {
    AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: id.to_owned(),
        activation_request_id: RequestId::new(format!("{id}:request"))?,
        activation_request_sha256: "a".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        connection_id: format!("{id}:connection"),
        state_fence: test_fence(1)?,
        kernel_deadline_unix_ms: 100,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(Into::into)
}

fn selection(
    handles: Vec<&str>,
    coverage: AgentActivationCandidateCoverage,
) -> AgentActivationSelectionDirective {
    AgentActivationSelectionDirective {
        candidate_handles: handles.into_iter().map(str::to_owned).collect(),
        candidate_coverage: coverage,
        recovery_handle: "activation:test-recovery".to_owned(),
    }
}

fn all_dispositions() -> TestResult<Vec<AgentActivationResolutionDisposition>> {
    Ok(vec![
        AgentActivationResolutionDisposition::Resolved {
            binding: Box::new(AgentActivationResolvedBinding {
                principal_id: "principal:test".to_owned(),
                session_id: "session:test".to_owned(),
                task_id: "task:test".to_owned(),
                work_unit_id: "work:test".to_owned(),
                work_scope_id: "scope:test".to_owned(),
                task_revision: "7".to_owned(),
                plan_id: "plan:test".to_owned(),
                plan_revision: "plan-revision:test".to_owned(),
            }),
        },
        AgentActivationResolutionDisposition::TaskSelectionRequired {
            selection: selection(
                vec!["task:candidate"],
                AgentActivationCandidateCoverage::Complete,
            ),
        },
        AgentActivationResolutionDisposition::ScopeSelectionRequired {
            selection: selection(
                vec!["scope:candidate"],
                AgentActivationCandidateCoverage::Complete,
            ),
        },
        AgentActivationResolutionDisposition::ScopeAmbiguous {
            selection: selection(
                vec!["scope:candidate-a", "scope:candidate-b"],
                AgentActivationCandidateCoverage::Complete,
            ),
        },
        AgentActivationResolutionDisposition::NotReady {
            recovery_handle: "activation:test-recovery".to_owned(),
            retry: AgentActivationRetryDirective {
                dependency_ref: "dependency:test".to_owned(),
                observed_dependency_revision: "revision:test".to_owned(),
                not_before_unix_ms: 60,
            },
        },
        AgentActivationResolutionDisposition::StaleFence {
            recovery_handle: "activation:test-recovery".to_owned(),
            observed_state_fence: Some(test_fence(2)?),
        },
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "activation:test-failure".to_owned(),
        },
    ])
}

// WORK_UNIT_CASE: 839/1
#[test]
fn current_ingress_maps_to_typed_submit_and_receiver_contract() -> TestResult {
    assert_fixture_case(
        1,
        "current ingress, typed resolution, submission, and receiver contract",
    )?;
    let runtime = source("src/daemon_runtime.rs")?;
    let claim_step = slice_between(
        &runtime,
        "fn start_valid_claim_step(",
        "/// Bounded shutdown drain for one in-flight activation",
    )?;
    assert_ordered(
        claim_step,
        &[
            "activation_deadline_expired",
            "resolve_agent_activation_v2",
            "dispatch_agent_activation_result",
        ],
    )?;

    let client = source("src/daemon_kernel_client.rs")?;
    let submit = slice_between(
        &client,
        "pub async fn submit_agent_activation_result(",
        "pub async fn reconcile_agent_activation_result(",
    )?;
    assert_ordered(
        submit,
        &[
            "AgentActivationResultSubmit::new(result.clone())",
            "\"agent_activation_submit\"",
            "value.get(\"ack\")",
            "AgentActivationResultAck",
            "ack.validate()",
        ],
    )?;

    let kernel = source("../../bins/eliot-kernel/src/daemon_request_dispatch.rs")?;
    let receiver = slice_between(
        &kernel,
        "\n            \"agent_activation_submit\" => {",
        "\n            \"agent_activation_reconcile\" => {",
    )?;
    assert_ordered(
        receiver,
        &[
            "AgentActivationResultSubmit",
            "submit_agent_activation_result",
            "activation_result_daemon_response",
        ],
    )?;
    Ok(())
}

// WORK_UNIT_CASE: 839/2
#[test]
fn valid_ticket_reaches_actual_daemon_v2_dispatch_path() -> TestResult {
    assert_fixture_case(2, "valid ticket reaches the daemon v2 dispatch path")?;
    let ticket = valid_ticket("ticket-839-2")?;
    let raw = serde_json::to_vec(&ticket)?;
    match eliotd::classify_claimed_ticket_value(&raw) {
        eliotd::ActivationClaim::Valid(decoded) => {
            assert_eq!(*decoded, ticket);
            decoded.validate()?;
        }
        other => return Err(format!("valid ticket must enter Valid claim arm: {other:?}").into()),
    }

    let runtime = source("src/daemon_runtime.rs")?;
    let claim_step = slice_between(
        &runtime,
        "fn start_valid_claim_step(",
        "/// Bounded shutdown drain for one in-flight activation",
    )?;
    assert_ordered(
        claim_step,
        &[
            "resolve_agent_activation_v2",
            "let retained = RetainedActivationIdentity",
            "dispatch_agent_activation_result(&kernel_clone, &ticket, result)",
        ],
    )?;
    assert!(!claim_step.contains("resolve_agent_activation("));
    Ok(())
}

// WORK_UNIT_CASE: 839/3
#[test]
fn accepted_exact_replay_reuses_one_resolution_identity() -> TestResult {
    assert_fixture_case(3, "one resolution is retained across exact replay")?;
    let ticket = valid_ticket("ticket-839-3")?;
    let result = AgentActivationResolutionResult::new(
        &ticket,
        50,
        AgentActivationResolutionDisposition::FailedInternal {
            failure_handle: "activation:test-failure".to_owned(),
        },
    )?;
    let replay = AgentActivationResultAck::replayed(&result)?;
    replay.validate()?;
    assert_eq!(replay.ticket_id, ticket.ticket_id);
    assert_eq!(replay.result_sha256, result.result_sha256);
    assert_eq!(replay.result.as_ref(), Some(&result));

    let runtime = source("src/daemon_runtime.rs")?;
    let claim_step = slice_between(
        &runtime,
        "fn start_valid_claim_step(",
        "/// Bounded shutdown drain for one in-flight activation",
    )?;
    assert_eq!(claim_step.matches("resolve_agent_activation_v2").count(), 1);
    let dispatch = slice_between(
        &runtime,
        "async fn dispatch_agent_activation_result(",
        "/// Builds the lost-acknowledgement reconcile query",
    )?;
    assert!(!dispatch.contains("resolve_agent_activation_v2"));
    assert!(dispatch.contains("classify_submit_ack"));
    Ok(())
}

// WORK_UNIT_CASE: 839/22
#[test]
fn every_disposition_uses_the_accepted_v2_submit_envelope() -> TestResult {
    assert_fixture_case(22, "all seven dispositions use the v2 submit envelope")?;
    let ticket = valid_ticket("ticket-839-22")?;
    let dispositions = all_dispositions()?;
    assert_eq!(dispositions.len(), 7);
    for disposition in dispositions {
        let result = AgentActivationResolutionResult::new(&ticket, 50, disposition)?;
        let submit = AgentActivationResultSubmit::new(result.clone())?;
        submit.validate()?;
        let encoded = serde_json::to_value(&submit)?;
        let decoded: AgentActivationResultSubmit = serde_json::from_value(encoded)?;
        decoded.validate()?;
        assert_eq!(decoded.result, result);
    }

    let client = source("src/daemon_kernel_client.rs")?;
    let submit = slice_between(
        &client,
        "pub async fn submit_agent_activation_result(",
        "pub async fn reconcile_agent_activation_result(",
    )?;
    assert!(submit.contains("AgentActivationResultSubmit::new(result.clone())"));
    assert!(submit.contains("serde_json::json!({ \"result\": submit })"));
    Ok(())
}

// WORK_UNIT_CASE: 839/20
#[test]
fn v1_compatibility_isolated_from_current_v2_resolution() -> TestResult {
    assert_fixture_case(
        20,
        "explicit v1 compatibility cannot consume current v2 accidentally",
    )?;

    let library = source("src/lib.rs")?;
    let v1 = slice_between(
        &library,
        "pub fn resolve_agent_activation(\n",
        "    /// Single production resolver spine:",
    )?;
    assert!(v1.contains("map_activation_snapshot"));
    assert!(v1.contains("GovernorActivationOutcome::Resolved"));
    assert!(v1.contains("outcome => Err"));
    assert!(!v1.contains("map_governor_outcome_to_protocol"));
    assert!(!v1.contains("AgentActivationResolutionResult"));

    let runtime = source("src/daemon_runtime.rs")?;
    let claim_step = slice_between(
        &runtime,
        "fn start_valid_claim_step(\n",
        "/// Bounded shutdown drain for one in-flight activation",
    )?;
    assert!(!claim_step.contains("resolve_agent_activation("));
    assert!(claim_step.contains("resolve_agent_activation_v2"));
    Ok(())
}
