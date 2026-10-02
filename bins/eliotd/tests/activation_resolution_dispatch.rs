//! Issue #839 dispatch matrix batch: cases 1, 2, 3, 6, 7, 20, and 22.
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
    AgentActivationRetryDirective, AgentActivationSelectionDirective, AgentBridgeActivationRequest,
    AgentBridgePeerAdmissionReceipt,
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

fn assert_source_excludes(source: &str, forbidden: &[&str]) -> TestResult {
    for marker in forbidden {
        if source.contains(marker) {
            return Err(format!("source unexpectedly contains forbidden marker {marker:?}").into());
        }
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
        demand_id: format!("{id}:demand"),
        activation_request_sha256: "a".repeat(64),
        peer_admission_receipt_sha256: "b".repeat(64),
        connection_id: format!("{id}:connection"),
        workspace_selector: None,
        cancellation_id: format!("{id}:cancellation"),
        state_fence: test_fence(1)?,
        kernel_deadline_unix_ms: 100,
        successor_of: None,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()
    .map_err(Into::into)
}

fn valid_admission() -> TestResult<(
    AgentBridgeActivationRequest,
    AgentBridgePeerAdmissionReceipt,
)> {
    let state_fence = test_fence(1)?;
    let receipt = AgentBridgePeerAdmissionReceipt {
        wire_id: eliot_protocol::AGENT_BRIDGE_PEER_ADMISSION_RECEIPT_WIRE_ID.to_owned(),
        wire_version: AgentBridgePeerAdmissionReceipt::CONTRACT_VERSION,
        module_id: "eliot-agent-bridge".to_owned(),
        connection_id: "ticket-binding:connection".to_owned(),
        profile_id: "SPINE_FUNCTIONAL".to_owned(),
        descriptor_sha256: "c".repeat(64),
        client_declaration_sha256: "d".repeat(64),
        bridge_generation: ResourceGeneration::new(1)?,
        state_fence: state_fence.clone(),
        activation_deadline_unix_ms: 100,
        challenge_nonce: "ticket-binding:challenge".to_owned(),
        challenge_sha256: "e".repeat(64),
        client_hello_sha256: "f".repeat(64),
        observed_sid: "S-1-5-21-1000".to_owned(),
        observed_session_id: 1,
        observed_process_id: 123,
        observed_process_start_time_100ns: 456,
        observed_image_path: "C:\\bridge.exe".to_owned(),
        observed_image_volume_serial: 1,
        observed_image_file_index: 2,
        receipt_sha256: String::new(),
    }
    .with_computed_digest()?;
    let request_id = RequestId::new("ticket-binding:request")?;
    let request = serde_json::from_value::<AgentBridgeActivationRequest>(serde_json::json!({
        "wire_id": eliot_protocol::AGENT_BRIDGE_ACTIVATION_REQUEST_WIRE_ID,
        "wire_version": AgentBridgeActivationRequest::CONTRACT_VERSION,
        "operation": eliot_protocol::AGENT_BRIDGE_ACTIVATION_OPERATION,
        "demand_id": "ticket-binding:demand",
        "connection_id": receipt.connection_id,
        "attach_kind": "MANAGED",
        "pre_attach_blind_interval": null,
        "request_identity": {
            "request": {
                "metadata": {
                    "request_id": request_id.as_str(),
                    "session_id": null,
                    "task_id": null,
                    "product_id": "eliot-agent-bridge",
                    "source_id": "ticket-binding-test",
                    "state_fence": state_fence,
                    "clock": {
                        "valid_time_ms": null,
                        "known_time_ms": null,
                        "transaction_sequence": null,
                        "monotonic_ns": null
                    }
                },
                "state_fence": state_fence
            },
            "idempotency_key": "ticket-binding:idempotency",
            "deadline_unix_ms": 100,
            "cancellation_id": "ticket-binding:cancellation"
        },
        "peer_admission_receipt_sha256": receipt.receipt_sha256,
        "request_sha256": ""
    }))?
    .with_computed_digest()?;
    request.validate_admission(&receipt)?;
    Ok((request, receipt))
}

fn ticket_bound_to_admission(
    request: &AgentBridgeActivationRequest,
    receipt: &AgentBridgePeerAdmissionReceipt,
) -> TestResult<AgentActivationResolutionTicket> {
    Ok(AgentActivationResolutionTicket {
        wire_id: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_ID.to_owned(),
        wire_version: eliot_protocol::AGENT_ACTIVATION_RESOLUTION_TICKET_WIRE_VERSION,
        ticket_id: "ticket-binding:ticket".to_owned(),
        activation_request_id: request.request_identity.request.metadata.request_id.clone(),
        demand_id: request.demand_id.clone(),
        activation_request_sha256: request.request_sha256.clone(),
        peer_admission_receipt_sha256: receipt.receipt_sha256.clone(),
        connection_id: receipt.connection_id.clone(),
        workspace_selector: request.workspace_selector.clone(),
        cancellation_id: request.request_identity.cancellation_id.clone(),
        state_fence: receipt.state_fence.clone(),
        kernel_deadline_unix_ms: receipt.activation_deadline_unix_ms,
        successor_of: None,
        ticket_sha256: String::new(),
    }
    .with_computed_digest()?)
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

fn assert_activation_runtime_path(runtime: &str) -> TestResult {
    let install_resolve = slice_between(
        runtime,
        "fn install_activation_resolve(",
        "/// Starts the resolve-wait step for one validated ticket",
    )?;
    assert!(install_resolve.contains("start_activation_resolve("));

    let settle_completion = slice_between(
        runtime,
        "fn settle_activation_completion(",
        "/// Settles one completed activation dispatch",
    )?;
    assert_ordered(
        settle_completion,
        &[
            "ActivationClaimStep::Valid(ticket)",
            "install_activation_resolve(kernel, composition, flight, *ticket)",
            "ActivationCompletion::Resolve(resolve_outcome)",
            "settle_activation_resolve_completion(kernel, flight, resolve_outcome)",
            "ActivationCompletion::Dispatch(dispatch_outcome)",
        ],
    )?;

    let resolve = slice_between(
        runtime,
        "fn start_activation_resolve(",
        "/// Settles one completed resolve-wait step",
    )?;
    assert!(resolve.contains("resolve_valid_ticket("));

    let settle_resolve = slice_between(
        runtime,
        "fn settle_activation_resolve_completion(",
        "/// Settles one invalid activation claim",
    )?;
    assert_ordered(
        settle_resolve,
        &["Ok(Some(resolved))", "start_activation_dispatch("],
    )?;

    let resolve_result = slice_between(
        runtime,
        "fn resolve_valid_ticket(",
        "/// Starts the dispatch step for one resolved ticket",
    )?;
    assert_ordered(
        resolve_result,
        &[
            "activation_deadline_expired",
            "AgentActivationResolver::resolve_agent_activation_v2(composition, &ticket, now)",
            "Ok(Some(Box::new(ActivationResolvedTicket",
        ],
    )?;

    let start_dispatch = slice_between(
        runtime,
        "fn start_activation_dispatch(",
        "/// Stage-aware shutdown drain for every already-started flight",
    )?;
    assert_ordered(
        start_dispatch,
        &[
            "ticket_id: resolved.ticket.ticket_id.clone()",
            "result_sha256: resolved.result.result_sha256.clone()",
            "dispatch_agent_activation_result(",
        ],
    )?;
    assert!(start_dispatch.contains("resolved.owner_readback"));
    Ok(())
}

fn assert_activation_dispatch_reconciliation(runtime: &str) -> TestResult {
    let dispatch = slice_between(
        runtime,
        "async fn dispatch_agent_activation_result(",
        "/// Builds the lost-acknowledgement reconcile query",
    )?;
    assert_ordered(
        dispatch,
        &[
            ".submit_agent_activation_result(&result, owner_readback)",
            "classify_submit_ack(ticket, &result, &ack)?",
            "Err(submit_error @ ActivationSubmitError::PossiblySubmitted { .. })",
            "retained_reconcile_query(ticket, &result)?",
            ".reconcile_agent_activation_result(&query)",
            "classify_reconcile_ack(ticket, &result, &ack, &submit_detail)?",
        ],
    )?;
    assert!(!dispatch.contains("resolve_agent_activation_v2"));
    assert_source_excludes(
        dispatch,
        &[
            "AgentActivationResolutionResult::new",
            "Session::new",
            "P07AuthorityPort",
        ],
    )?;

    let reconcile_query = slice_between(
        runtime,
        "fn retained_reconcile_query(",
        "/// Classifies a submit acknowledgement against the retained identity",
    )?;
    assert!(reconcile_query.contains(
        "AgentActivationResultReconcile::new(ticket.ticket_id.clone(), result.result_sha256.clone())"
    ));
    assert!(!reconcile_query.contains("resolve_agent_activation_v2"));
    assert!(!reconcile_query.contains("AgentActivationResolutionResult::new"));
    Ok(())
}

fn assert_activation_ack_classifiers(runtime: &str) -> TestResult {
    let classifier = slice_between(
        runtime,
        "fn classify_submit_ack(",
        "/// Classifies a reconcile acknowledgement after a submit failure",
    )?;
    assert_source_excludes(
        classifier,
        &["Session::new", "P07AuthorityPort", "transact_async"],
    )?;
    assert_ordered(
        classifier,
        &[
            "if ack.ticket_id != ticket.ticket_id",
            "ack.ticket_id != result.ticket_id",
            "ack.result_sha256 != result.result_sha256",
            "match ack.outcome",
            "AgentActivationResultAckOutcome::Accepted => {",
            "ack.validate_against_result(result)",
            "AgentActivationResultAckOutcome::Unknown => Err(ActivationDispatchError::Unknown",
            "ticket_id: ticket.ticket_id.clone()",
            "result_sha256: result.result_sha256.clone()",
            "detail: format!(",
        ],
    )?;
    let before_match = classifier
        .split("match ack.outcome")
        .next()
        .ok_or("submit classifier is missing its outcome match")?;
    assert!(!before_match.contains("ack.validate_against_result("));
    let accepted = slice_between(
        classifier,
        "AgentActivationResultAckOutcome::Accepted => {",
        "AgentActivationResultAckOutcome::Unknown =>",
    )?;
    assert!(accepted.contains("validate_against_result(result)"));
    let unknown = classifier
        .split("AgentActivationResultAckOutcome::Unknown =>")
        .nth(1)
        .ok_or("submit classifier is missing its Unknown arm")?;
    assert!(!unknown.contains("ack.validate_against_result("));

    let reconcile_classifier = slice_between(
        runtime,
        "fn classify_reconcile_ack(",
        "/// Preserves the exact retained result identity",
    )?;
    let reconcile_unknown = reconcile_classifier
        .split("AgentActivationResultAckOutcome::Unknown =>")
        .nth(1)
        .ok_or("reconcile classifier is missing its Unknown arm")?;
    assert_ordered(
        reconcile_unknown,
        &[
            "ActivationDispatchError::Unknown",
            "ticket_id: ticket.ticket_id.clone()",
            "result_sha256: result.result_sha256.clone()",
            "{submit_detail}",
        ],
    )?;
    Ok(())
}

fn assert_activation_transport_contract(client: &str, kernel: &str, protocol: &str) -> TestResult {
    let submit = slice_between(
        client,
        "pub async fn submit_agent_activation_result(",
        "pub async fn reconcile_agent_activation_result(",
    )?;
    assert_ordered(
        submit,
        &[
            "AgentActivationResultSubmit::new_with_owner_readback",
            "\"agent_activation_submit\"",
            "let response: ActivationSubmitResponse",
            "serde_json::from_value(value)",
            "let ack = response",
            ".ack",
            ".ok_or_else",
            "ack.validate()",
            "ack.replay_key() != (result.ticket_id.as_str(), result.result_sha256.as_str())",
            "Ok(ack)",
        ],
    )?;
    assert!(!submit.contains("ack.validate_against_result("));
    assert!(!submit.contains("Session::new"));

    let reconcile = slice_between(
        client,
        "pub async fn reconcile_agent_activation_result(",
        "    pub fn connect(",
    )?;
    assert_ordered(
        reconcile,
        &[
            "query.validate()",
            "\"agent_activation_reconcile\"",
            "serde_json::json!({ \"reconcile\": query })",
            "response.ack.validate()",
            "response.ack.replay_key() != (query.ticket_id.as_str(), query.result_sha256.as_str())",
            "Ok(response.ack)",
        ],
    )?;
    assert!(!reconcile.contains("validate_against_result"));

    let v2_submit = slice_between(
        kernel,
        "\n            \"agent_activation_submit\" => {",
        "\n            \"agent_activation_reconcile\" => {",
    )?;
    assert_ordered(
        v2_submit,
        &[
            "object.contains_key(\"decision\")",
            "decode_agent_activation_result_submit",
            "submit_agent_activation_result_authenticated",
            "activation_result_daemon_response",
        ],
    )?;
    assert!(!v2_submit.contains("decode_activation_resolution_v1_import"));

    let v2_decoder = slice_between(
        protocol,
        "pub fn decode_agent_activation_result_submit(",
        "\n/// The Kernel answers purely from its retained per-ticket result record",
    )?;
    assert!(v2_decoder.contains("Result<AgentActivationResultSubmit, ProtocolError>"));
    assert!(v2_decoder.contains("submit.validate()?"));
    Ok(())
}

// WORK_UNIT_CASE: 839/1
#[test]
fn current_ingress_maps_to_typed_submit_and_receiver_contract() -> TestResult {
    assert_fixture_case(
        1,
        "current ingress, typed resolution, submission, and receiver contract",
    )?;
    let runtime = source("src/daemon_runtime.rs")?;
    assert_activation_runtime_path(&runtime)?;
    assert_activation_dispatch_reconciliation(&runtime)?;
    assert_activation_ack_classifiers(&runtime)?;

    let client = source("src/daemon_kernel_client.rs")?;
    let kernel = source("../../bins/eliot-kernel/src/daemon_request_dispatch.rs")?;
    let protocol = source("../../crates/foundation/eliot-protocol/src/activation_resolution.rs")?;
    assert_activation_transport_contract(&client, &kernel, &protocol)?;
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
    let resolve = slice_between(
        &runtime,
        "fn resolve_valid_ticket(",
        "/// Starts the dispatch step for one resolved ticket",
    )?;
    assert_ordered(
        resolve,
        &[
            "activation_deadline_expired",
            "AgentActivationResolver::resolve_agent_activation_v2(composition, &ticket, now)",
            "let result = if result.resolved_binding().is_some()",
            "Ok(Some(Box::new(ActivationResolvedTicket",
        ],
    )?;
    assert!(!resolve.contains("map_activation_snapshot"));
    assert!(!resolve.contains("AgentActivationResolutionDecision"));
    assert!(!resolve.contains("submit_agent_activation_decision"));
    let start_dispatch = slice_between(
        &runtime,
        "fn start_activation_dispatch(",
        "/// Stage-aware shutdown drain for every already-started flight",
    )?;
    assert_ordered(
        start_dispatch,
        &[
            "ticket_id: resolved.ticket.ticket_id.clone()",
            "result_sha256: resolved.result.result_sha256.clone()",
            "dispatch_agent_activation_result(",
        ],
    )?;
    assert!(start_dispatch.contains("resolved.result"));
    assert!(start_dispatch.contains("resolved.owner_readback"));
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
    let replay = AgentActivationResultAck::accepted(&result)?;
    let initial = AgentActivationResultAck::accepted(&result)?;
    replay.validate()?;
    assert_eq!(replay, initial);
    assert_eq!(replay.ticket_id, ticket.ticket_id);
    assert_eq!(replay.result_sha256, result.result_sha256);
    assert_eq!(replay.result.as_ref(), Some(&result));

    let runtime = source("src/daemon_runtime.rs")?;
    let resolver = slice_between(
        &runtime,
        "fn resolve_valid_ticket(",
        "/// Starts the dispatch step for one resolved ticket",
    )?;
    assert_eq!(
        resolver
            .matches(
                "AgentActivationResolver::resolve_agent_activation_v2(composition, &ticket, now)"
            )
            .count(),
        1
    );
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
    assert!(submit.contains("AgentActivationResultSubmit::new_with_owner_readback"));
    assert!(submit.contains("serde_json::json!({ \"result\": submit })"));
    Ok(())
}

// WORK_UNIT_CASE: 839/6
#[test]
fn ticket_request_identity_and_digest_mismatch_fails_closed() -> TestResult {
    assert_fixture_case(6, "activation request identity and digest mismatch")?;
    let (request, receipt) = valid_admission()?;
    let ticket = ticket_bound_to_admission(&request, &receipt)?;
    ticket.validate_against(&request, &receipt)?;

    let mut wrong_identity = ticket.clone();
    wrong_identity.activation_request_id = RequestId::new("ticket-binding:other-request")?;
    wrong_identity.ticket_sha256 = wrong_identity.compute_digest()?;
    assert!(
        wrong_identity.validate_against(&request, &receipt).is_err(),
        "a ticket with a different request identity must fail closed"
    );

    let mut wrong_digest = ticket;
    wrong_digest.activation_request_sha256 = "0".repeat(64);
    wrong_digest.ticket_sha256 = wrong_digest.compute_digest()?;
    assert!(
        wrong_digest.validate_against(&request, &receipt).is_err(),
        "a ticket with a different request digest must fail closed"
    );
    Ok(())
}

// WORK_UNIT_CASE: 839/7
#[test]
fn ticket_peer_admission_and_connection_mismatch_fails_closed() -> TestResult {
    assert_fixture_case(7, "peer-admission and connection binding mismatch")?;
    let (request, receipt) = valid_admission()?;
    let ticket = ticket_bound_to_admission(&request, &receipt)?;
    ticket.validate_against(&request, &receipt)?;

    let mut wrong_receipt = ticket.clone();
    wrong_receipt.peer_admission_receipt_sha256 = "0".repeat(64);
    wrong_receipt.ticket_sha256 = wrong_receipt.compute_digest()?;
    assert!(
        wrong_receipt.validate_against(&request, &receipt).is_err(),
        "a ticket with a different admission receipt must fail closed"
    );

    let mut wrong_connection = ticket;
    wrong_connection.connection_id = "ticket-binding:other-connection".to_owned();
    wrong_connection.ticket_sha256 = wrong_connection.compute_digest()?;
    assert!(
        wrong_connection
            .validate_against(&request, &receipt)
            .is_err(),
        "a ticket with a different connection must fail closed"
    );
    Ok(())
}

// WORK_UNIT_CASE: 839/20
#[test]
fn v1_compatibility_retired_v2_resolution_is_the_spine() -> TestResult {
    assert_fixture_case(
        20,
        "explicit v1 compatibility cannot consume current v2 accidentally",
    )?;

    let library = source("src/lib.rs")?;
    assert!(!library.contains("fn resolve_agent_activation("));
    assert!(library.contains("resolve_agent_activation_v2"));
    assert!(!library.contains("map_activation_snapshot"));
    assert!(!library.contains("AgentActivationResolutionDecision"));
    assert!(library.contains("map_governor_outcome_to_protocol"));
    assert!(library.contains("AgentActivationResolutionResult"));

    let projection = source("src/activation_projection.rs")?;
    assert!(!projection.contains("map_activation_snapshot"));
    assert!(!projection.contains("AgentActivationResolutionDecision"));
    assert!(projection.contains("map_governor_outcome_to_protocol"));

    let runtime = source("src/daemon_runtime.rs")?;
    let resolve = slice_between(
        &runtime,
        "fn resolve_valid_ticket(\n",
        "/// Starts the dispatch step for one resolved ticket",
    )?;
    assert!(!resolve.contains("map_activation_snapshot"));
    assert!(!resolve.contains("AgentActivationResolutionDecision"));
    assert!(!resolve.contains("submit_agent_activation_decision"));
    assert!(resolve.contains("AgentActivationResolver::resolve_agent_activation_v2"));

    let kernel = source("../../bins/eliot-kernel/src/daemon_request_dispatch.rs")?;
    let v2_submit = slice_between(
        &kernel,
        "\n            \"agent_activation_submit\" => {",
        "\n            \"agent_activation_reconcile\" => {",
    )?;
    assert!(v2_submit.contains("decode_agent_activation_result_submit"));
    assert!(!v2_submit.contains("decode_activation_resolution_v1_import"));
    assert!(v2_submit.contains("object.contains_key(\"decision\")"));

    let v1_import = slice_between(
        &kernel,
        "\n            AGENT_ACTIVATION_V1_IMPORT_OPERATION => {",
        "\n            \"local_read_claim\" => {",
    )?;
    assert_ordered(
        v1_import,
        &[
            "object.contains_key(\"result\")",
            "AGENT_ACTIVATION_V1_IMPORT_OPERATION",
            "object.contains_key(\"decision\")",
            "activation_resolution_v1::decode_activation_resolution_v1_import",
        ],
    )?;
    assert!(!v1_import.contains("submit_agent_activation_result_authenticated"));

    let protocol_root = source("../../crates/foundation/eliot-protocol/src/root.rs")?;
    assert!(protocol_root.contains("pub mod activation_resolution_v1;"));
    Ok(())
}

// WORK_UNIT_CASE: 839/26
#[test]
fn protected_activation_canaries_are_redacted_before_diagnostics() -> TestResult {
    assert_fixture_case(
        26,
        "protected and credential canaries are absent from diagnostics",
    )?;
    for canary in [
        "password=839-canary",
        "secret=839-canary",
        "credential=839-canary",
        "Bearer 839-canary",
        "model-text=839-canary",
    ] {
        assert!(eliotd::diagnostics::carries_denied_content(canary));
        assert_eq!(
            eliotd::diagnostics::sanitize_identity(canary),
            eliotd::diagnostics::REDACTED
        );
        assert_eq!(
            eliotd::diagnostics::sanitize_detail(canary),
            eliotd::diagnostics::REDACTED
        );
    }

    let runtime = source("src/daemon_runtime.rs")?;
    let dispatch = slice_between(
        &runtime,
        "async fn dispatch_agent_activation_result(",
        "/// Builds the lost-acknowledgement reconcile query",
    )?;
    assert!(dispatch.contains("sanitize_identity(&ticket.ticket_id)"));
    assert!(!dispatch.contains("serde_json::to_string(&result)"));
    assert!(!dispatch.contains("format!(\"{result:?}\""));
    Ok(())
}

// WORK_UNIT_CASE: 839/27
#[test]
fn activation_modules_have_no_module_wide_dead_code_suppression() -> TestResult {
    assert_fixture_case(27, "module-wide dead_code suppression is absent")?;
    for path in [
        "src/activation_projection.rs",
        "src/lib.rs",
        "src/daemon_runtime.rs",
        "src/daemon_kernel_client.rs",
    ] {
        let source = source(path)?;
        let module_header: String = source.lines().take(80).collect::<Vec<_>>().join("\n");
        assert!(
            !module_header.contains("dead_code"),
            "activation module header must not suppress dead_code: {path}"
        );
    }
    Ok(())
}

// WORK_UNIT_CASE: 839/28
#[test]
fn required_activation_functions_are_production_reachable() -> TestResult {
    assert_fixture_case(28, "required activation functions have production callers")?;
    let projection = source("src/activation_projection.rs")?;
    let projection_production = projection
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .ok_or("activation projection test boundary is missing")?;
    for marker in [
        "map_coverage(selection.candidate_coverage)",
        "selection: map_selection(selection)",
        "retry: map_retry(retry)",
    ] {
        assert!(
            projection_production.contains(marker),
            "production projection must call {marker}"
        );
    }

    let library = source("src/lib.rs")?;
    let library_production = library
        .split("\n#[cfg(test)]\nmod tests;")
        .next()
        .ok_or("daemon library test boundary is missing")?;
    for marker in [
        "activation_projection::map_governor_outcome_to_protocol(",
        "activation_projection::stale_fence_for_resolved_mismatch(",
        "activation_projection::failed_internal_for_unready_governor(",
        "activation_projection::failed_internal_for_mapping_failure(",
        "DaemonComposition::resolve_agent_activation_v2(self, ticket, now)",
    ] {
        assert!(
            library_production.contains(marker),
            "production daemon path must call {marker}"
        );
    }

    let runtime = source("src/daemon_runtime.rs")?;
    let resolve = slice_between(
        &runtime,
        "fn resolve_valid_ticket(",
        "/// Starts the dispatch step for one resolved ticket",
    )?;
    assert!(resolve.contains(
        "AgentActivationResolver::resolve_agent_activation_v2(composition, &ticket, now)"
    ));
    let dispatch = slice_between(
        &runtime,
        "async fn dispatch_agent_activation_result(",
        "/// Builds the lost-acknowledgement reconcile query",
    )?;
    assert!(dispatch.contains("submit_agent_activation_result"));
    assert!(dispatch.contains("owner_readback"));
    assert!(dispatch.contains("reconcile_agent_activation_result(&query)"));
    Ok(())
}

// WORK_UNIT_CASE: 839/29
#[test]
fn unrelated_dead_functions_are_exposed_to_package_lint() -> TestResult {
    assert_fixture_case(
        29,
        "an unrelated new dead function fails the actual package lint",
    )?;
    let package = source("Cargo.toml")?;
    let workspace = source("../../Cargo.toml")?;
    assert!(package.contains("[lints]\nworkspace = true"));
    assert!(workspace.contains("[workspace.lints.clippy]"));
    assert!(workspace.contains("all = { level = \"warn\", priority = -1 }"));
    assert!(workspace.contains("pedantic = { level = \"warn\", priority = -1 }"));
    assert!(!package.contains("dead_code = \"allow\""));
    assert!(!workspace.contains("dead_code = \"allow\""));
    Ok(())
}

// WORK_UNIT_CASE: 839/30
#[test]
fn activation_source_excludes_unowned_effects_and_duplicate_paths() -> TestResult {
    assert_fixture_case(
        30,
        "activation source excludes Store writes, Session allocation, authority, effects, and duplicate paths",
    )?;
    let projection = source("src/activation_projection.rs")?;
    let projection_production = projection
        .split("\n#[cfg(test)]\nmod tests")
        .next()
        .ok_or("activation projection test boundary is missing")?;
    assert_source_excludes(
        projection_production,
        &[
            "NamedWrite",
            "Store::",
            "Session::new",
            "P07AuthorityPort",
            "transact_async",
            "tokio::spawn",
            "ProcessExecutor",
        ],
    )?;

    let library = source("src/lib.rs")?;
    let resolver = slice_between(
        &library,
        "pub fn resolve_agent_activation_v2(",
        "/// Records the already-validated Kernel-issued owner session facts",
    )?;
    assert_source_excludes(
        resolver,
        &[
            "Session::new",
            "P07AuthorityPort",
            "transact_async",
            "tokio::spawn",
            "ProcessExecutor",
            "store_named",
        ],
    )?;

    let client = source("src/daemon_kernel_client.rs")?;
    let submit = slice_between(
        &client,
        "pub async fn submit_agent_activation_result(",
        "pub async fn reconcile_agent_activation_result(",
    )?;
    assert_eq!(submit.matches("transact_async(").count(), 1);
    assert_source_excludes(
        submit,
        &[
            "resolve_agent_activation_v2",
            "Session::new",
            "Store::",
            "P07AuthorityPort",
            "tokio::spawn",
        ],
    )?;

    let runtime = source("src/daemon_runtime.rs")?;
    let resolve = slice_between(
        &runtime,
        "fn resolve_valid_ticket(",
        "/// Starts the dispatch step for one resolved ticket",
    )?;
    assert!(!resolve.contains("map_activation_snapshot"));
    assert!(!resolve.contains("AgentActivationResolutionDecision"));
    assert!(!resolve.contains("submit_agent_activation_decision"));
    let dispatch = slice_between(
        &runtime,
        "async fn dispatch_agent_activation_result(",
        "/// Builds the lost-acknowledgement reconcile query",
    )?;
    assert_eq!(
        dispatch.matches("submit_agent_activation_result").count(),
        1
    );
    assert_eq!(
        dispatch
            .matches("reconcile_agent_activation_result")
            .count(),
        1
    );
    assert!(!dispatch.contains("resolve_agent_activation_v2"));
    assert!(!dispatch.contains("transact_async"));
    Ok(())
}
