use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    error::Error,
    mem::size_of,
};

use eliot_mcp::{
    ActInput, ActiveSessionBinding, ApplicationRequest, BindingResolutionRequest, BridgeError,
    CANONICAL_TOOL_NAMES, CompatibilityCorrelation, CoordinateInput, DurableJobHandle,
    FinishAttemptDraft, InitializeRequest, JobPresentation, KernelGovernorPort, LoopbackProfile,
    McpCore, McpProtocolVersion, NoProviderPort, ObserveInput, PacketInput, PortFailure,
    PortProjection, ProjectionKind, QueryInput, ResponseKind, StateInput, ToolRequest,
    TransportProfile, TransportRequestContext, VerifyInput, canonical_schema,
    canonical_tool_schemas,
};
use eliot_protocol::HARD_STRUCTURED_RESPONSE_BYTES;
use eliot_receipts::{ProofCeiling, SessionBinding};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn fence(task_revision: u64) -> Value {
    json!({
        "authority_epoch": 1,
        "resource_generation": 1,
        "task_revision": task_revision,
        "policy_revision": 1,
        "integration_revision": 1
    })
}

fn request_value(request_id: &str, idempotency_key: &str, tasks: bool, tool: Value) -> Value {
    let mut request = json!({
        "protocol_version": "2026-07-28",
        "session": {
            "session_id": "session-1",
            "authority_epoch": 1,
            "state_fence": fence(7)
        },
        "identity": {
            "request": {
                "metadata": {
                    "request_id": request_id,
                    "session_id": "session-1",
                    "task_id": "task-1",
                    "product_id": "product-1",
                    "source_id": "source-1",
                    "state_fence": fence(7),
                    "clock": {
                        "valid_time_ms": 1000,
                        "known_time_ms": 1001,
                        "transaction_sequence": 1,
                        "monotonic_ns": 500
                    }
                },
                "state_fence": fence(7)
            },
            "idempotency_key": idempotency_key,
            "deadline_unix_ms": 5000,
            "cancellation_id": "cancel-1"
        },
        "security": {
            "privacy_class": "INTERNAL",
            "instruction_taint": "DATA_ONLY",
            "effect_ceiling": "CANDIDATE_ONLY"
        },
        "client_capabilities": { "tasks": tasks }
    });
    request["tool"] = tool;
    request
}

fn parse_request(value: Value) -> Result<ApplicationRequest, serde_json::Error> {
    serde_json::from_value(value)
}

fn state_tool() -> Value {
    json!({
        "name": "eliot.state",
        "arguments": { "include": ["task", "scope"] }
    })
}

fn stdio_transport(connection_id: &str, generation: u64) -> TransportRequestContext {
    TransportRequestContext {
        profile: TransportProfile::Stdio,
        connection_id: connection_id.to_owned(),
        scoped_credential_ref: "credential/stdio/1".to_owned(),
        transport_generation: generation,
    }
}

fn loopback_transport(
    host: &str,
    origin: Option<&str>,
    credential_ref: &str,
    generation: u64,
) -> TransportRequestContext {
    TransportRequestContext {
        profile: TransportProfile::LoopbackHttp(LoopbackProfile {
            bind_address: "127.0.0.1".to_owned(),
            host: host.to_owned(),
            browser_origin: origin.map(str::to_owned),
            credential_ref: credential_ref.to_owned(),
        }),
        connection_id: "connection-http-1".to_owned(),
        scoped_credential_ref: credential_ref.to_owned(),
        transport_generation: generation,
    }
}

fn resolved_binding(request: &BindingResolutionRequest) -> ActiveSessionBinding {
    ActiveSessionBinding {
        binding_id: format!(
            "binding-{}-{}",
            request.transport.connection_id, request.transport.transport_generation
        ),
        principal_ref: "principal/local-user".to_owned(),
        session: request.claimed_session.clone(),
        transport: request.transport.clone(),
        request_id: request.request_id.clone(),
        idempotency_key: request.idempotency_key.clone(),
        cancellation_id: request.cancellation_id.clone(),
        canonical_request_sha256: request.canonical_request_sha256.clone(),
        resolved_at_unix_ms: 1_100,
        valid_until_unix_ms: request.deadline_unix_ms + 1_000,
    }
}

macro_rules! test_resolver {
    () => {
        fn resolve_active_session(
            &self,
            request: &BindingResolutionRequest,
        ) -> Result<ActiveSessionBinding, PortFailure> {
            Ok(resolved_binding(request))
        }
    };
}

fn projection(content: Value) -> PortProjection {
    PortProjection {
        kind: ProjectionKind::Projection,
        content,
        artifacts: Vec::new(),
        proof_ceiling: ProofCeiling::Observation,
        resource: None,
        durable_job: None,
    }
}

#[derive(Default)]
struct ReplayPort {
    seen: RefCell<BTreeMap<String, (String, PortProjection)>>,
    resolutions: RefCell<Vec<TransportRequestContext>>,
}

impl KernelGovernorPort for ReplayPort {
    fn resolve_active_session(
        &self,
        request: &BindingResolutionRequest,
    ) -> Result<ActiveSessionBinding, PortFailure> {
        self.resolutions
            .borrow_mut()
            .push(request.transport.clone());
        Ok(resolved_binding(request))
    }

    fn dispatch(
        &self,
        request: &eliot_mcp::ForwardedRequest,
    ) -> Result<PortProjection, PortFailure> {
        let key = request.request.identity.idempotency_key.clone();
        if let Some((digest, response)) = self.seen.borrow().get(&key) {
            return if digest == &request.canonical_request_sha256 {
                Ok(response.clone())
            } else {
                Err(PortFailure::IdempotencyConflict)
            };
        }
        let response =
            projection(json!({ "owner_projection": request.request.tool.canonical_name() }));
        self.seen.borrow_mut().insert(
            key,
            (request.canonical_request_sha256.clone(), response.clone()),
        );
        Ok(response)
    }
}

struct BoundPort {
    expected_transport: TransportRequestContext,
    expected_session: SessionBinding,
    dispatches: Cell<usize>,
}

impl BoundPort {
    fn new(expected_transport: TransportRequestContext, expected_session: SessionBinding) -> Self {
        Self {
            expected_transport,
            expected_session,
            dispatches: Cell::new(0),
        }
    }
}

impl KernelGovernorPort for BoundPort {
    fn resolve_active_session(
        &self,
        request: &BindingResolutionRequest,
    ) -> Result<ActiveSessionBinding, PortFailure> {
        if request.transport != self.expected_transport
            || request.claimed_session != self.expected_session
        {
            return Err(PortFailure::TransportBindingRejected {
                reason: "credential, connection, profile, generation, Session, or fence mismatch"
                    .to_owned(),
            });
        }
        Ok(resolved_binding(request))
    }

    fn dispatch(
        &self,
        _request: &eliot_mcp::ForwardedRequest,
    ) -> Result<PortProjection, PortFailure> {
        self.dispatches.set(self.dispatches.get() + 1);
        Ok(projection(json!({"bound": true})))
    }
}

#[test]
fn request_response_correlation_and_replay_are_bounded() -> Result<(), Box<dyn Error>> {
    let port = ReplayPort::default();
    let request = parse_request(request_value("request-1", "idem-1", false, state_tool()))?;
    let first = McpCore.execute(&port, stdio_transport("connection-1", 1), request.clone())?;
    let replay = McpCore.execute(&port, stdio_transport("connection-1", 1), request)?;

    assert_eq!(first, replay);
    assert_eq!(first.request_id, "request-1");
    assert_eq!(first.idempotency_key, "idem-1");
    assert_eq!(first.canonical_request_sha256.len(), 64);
    assert!(serde_json::to_vec(&first)?.len() <= HARD_STRUCTURED_RESPONSE_BYTES);
    Ok(())
}

#[test]
fn same_idempotency_key_with_different_bytes_conflicts() -> Result<(), Box<dyn Error>> {
    let port = ReplayPort::default();
    let first = parse_request(request_value("request-1", "idem-1", false, state_tool()))?;
    let second = parse_request(request_value(
        "request-2",
        "idem-1",
        false,
        json!({"name":"eliot.state","arguments":{"include":["health"]}}),
    ))?;
    let _ = McpCore.execute(&port, stdio_transport("connection-1", 1), first)?;
    assert!(matches!(
        McpCore.execute(&port, stdio_transport("connection-1", 1), second),
        Err(BridgeError::Port(PortFailure::IdempotencyConflict))
    ));
    Ok(())
}

#[test]
fn reconnect_continuity_requires_the_same_explicit_binding() -> Result<(), Box<dyn Error>> {
    let port = ReplayPort::default();
    let request = parse_request(request_value("request-1", "idem-1", false, state_tool()))?;
    let before_restart =
        McpCore.execute(&port, stdio_transport("connection-1", 1), request.clone())?;
    let after_restart = McpCore.execute(&port, stdio_transport("connection-2", 2), request)?;

    assert_eq!(size_of::<McpCore>(), 0);
    assert_eq!(before_restart, after_restart);
    assert_eq!(port.resolutions.borrow().len(), 2);
    assert_ne!(port.resolutions.borrow()[0], port.resolutions.borrow()[1]);
    let initialized = McpCore::initialize(InitializeRequest::default());
    assert!(!initialized.application_binding_created);
    Ok(())
}

#[test]
fn trusted_resolver_rejects_forged_session_and_transport_facts() -> Result<(), Box<dyn Error>> {
    let canonical = parse_request(request_value("request-1", "idem-1", false, state_tool()))?;
    let expected_transport = stdio_transport("connection-1", 1);
    let port = BoundPort::new(expected_transport.clone(), canonical.session.clone());

    let accepted = McpCore.execute(&port, expected_transport.clone(), canonical.clone())?;
    assert_eq!(accepted.content["bound"], true);

    let mut wrong_credential = expected_transport.clone();
    wrong_credential.scoped_credential_ref = "credential/stdio/forged".to_owned();
    assert!(matches!(
        McpCore.execute(&port, wrong_credential, canonical.clone()),
        Err(BridgeError::Port(
            PortFailure::TransportBindingRejected { .. }
        ))
    ));

    let mut wrong_connection = expected_transport.clone();
    wrong_connection.connection_id = "connection-forged".to_owned();
    assert!(matches!(
        McpCore.execute(&port, wrong_connection, canonical.clone()),
        Err(BridgeError::Port(
            PortFailure::TransportBindingRejected { .. }
        ))
    ));

    let mut wrong_generation = expected_transport.clone();
    wrong_generation.transport_generation = 2;
    assert!(matches!(
        McpCore.execute(&port, wrong_generation, canonical.clone()),
        Err(BridgeError::Port(
            PortFailure::TransportBindingRejected { .. }
        ))
    ));

    let mut forged_session_value = request_value("request-2", "idem-2", false, state_tool());
    forged_session_value["session"]["session_id"] = json!("session-forged");
    forged_session_value["identity"]["request"]["metadata"]["session_id"] = json!("session-forged");
    let forged_session = parse_request(forged_session_value)?;
    assert!(matches!(
        McpCore.execute(&port, expected_transport.clone(), forged_session),
        Err(BridgeError::Port(
            PortFailure::TransportBindingRejected { .. }
        ))
    ));

    let mut forged_fence_value = request_value("request-3", "idem-3", false, state_tool());
    forged_fence_value["session"]["state_fence"]["resource_generation"] = json!(2);
    forged_fence_value["identity"]["request"]["state_fence"]["resource_generation"] = json!(2);
    forged_fence_value["identity"]["request"]["metadata"]["state_fence"]["resource_generation"] =
        json!(2);
    let forged_fence = parse_request(forged_fence_value)?;
    assert!(matches!(
        McpCore.execute(&port, expected_transport, forged_fence),
        Err(BridgeError::Port(
            PortFailure::TransportBindingRejected { .. }
        ))
    ));
    assert_eq!(port.dispatches.get(), 1);
    Ok(())
}

#[test]
fn trusted_resolver_rejects_wrong_loopback_binding() -> Result<(), Box<dyn Error>> {
    let canonical = parse_request(request_value("request-1", "idem-1", false, state_tool()))?;
    let expected_loopback = loopback_transport(
        "127.0.0.1:7777",
        Some("http://127.0.0.1:7777"),
        "credential/http/1",
        1,
    );
    let loopback_port = BoundPort::new(expected_loopback.clone(), canonical.session.clone());
    let _ = McpCore.execute(&loopback_port, expected_loopback, canonical.clone())?;

    let wrong_host = loopback_transport(
        "127.0.0.1:8888",
        Some("http://127.0.0.1:8888"),
        "credential/http/1",
        1,
    );
    assert!(matches!(
        McpCore.execute(&loopback_port, wrong_host, canonical.clone()),
        Err(BridgeError::Port(
            PortFailure::TransportBindingRejected { .. }
        ))
    ));

    let missing_origin = loopback_transport("127.0.0.1:7777", None, "credential/http/1", 1);
    assert!(matches!(
        McpCore.execute(&loopback_port, missing_origin, canonical.clone()),
        Err(BridgeError::Port(
            PortFailure::TransportBindingRejected { .. }
        ))
    ));

    let wrong_origin = TransportRequestContext {
        profile: TransportProfile::LoopbackHttp(LoopbackProfile {
            bind_address: "127.0.0.1".to_owned(),
            host: "127.0.0.1:7777".to_owned(),
            browser_origin: Some("http://127.0.0.1:8888".to_owned()),
            credential_ref: "credential/http/1".to_owned(),
        }),
        connection_id: "connection-http-1".to_owned(),
        scoped_credential_ref: "credential/http/1".to_owned(),
        transport_generation: 1,
    };
    assert!(matches!(
        McpCore.execute(&loopback_port, wrong_origin, canonical.clone()),
        Err(BridgeError::InvalidArgument { .. })
    ));

    let wrong_http_credential = loopback_transport(
        "127.0.0.1:7777",
        Some("http://127.0.0.1:7777"),
        "credential/http/forged",
        1,
    );
    assert!(matches!(
        McpCore.execute(&loopback_port, wrong_http_credential, canonical),
        Err(BridgeError::Port(
            PortFailure::TransportBindingRejected { .. }
        ))
    ));
    assert_eq!(loopback_port.dispatches.get(), 1);
    Ok(())
}

#[test]
fn wrong_session_fence_and_finish_revision_fail_closed() -> Result<(), Box<dyn Error>> {
    let port = ReplayPort::default();
    let mut wrong_session = request_value("request-1", "idem-1", false, state_tool());
    wrong_session["session"]["session_id"] = json!("session-2");
    assert!(matches!(
        McpCore.execute(
            &port,
            stdio_transport("connection-1", 1),
            parse_request(wrong_session)?
        ),
        Err(BridgeError::InvalidArgument { .. })
    ));

    let mut wrong_fence = request_value("request-2", "idem-2", false, state_tool());
    wrong_fence["session"]["state_fence"]["resource_generation"] = json!(2);
    assert!(matches!(
        McpCore.execute(
            &port,
            stdio_transport("connection-1", 1),
            parse_request(wrong_fence)?
        ),
        Err(BridgeError::InvalidArgument { .. })
    ));

    let finish = json!({
        "name": "eliot.finish",
        "arguments": {
            "task_id": "task-1",
            "expected_task_revision": 8,
            "requested_outcome": "COMPLETE_CANDIDATE",
            "artifact_refs": ["artifact-1"],
            "observation_refs": [],
            "verifier_run_refs": ["verify-1"],
            "remaining_unknowns_declared_by_caller": [],
            "rationale_candidate": "candidate only"
        }
    });
    assert!(matches!(
        McpCore.execute(
            &port,
            stdio_transport("connection-1", 1),
            parse_request(request_value("request-3", "idem-3", false, finish))?
        ),
        Err(BridgeError::InvalidArgument { .. })
    ));
    Ok(())
}

#[test]
fn broad_query_without_intent_and_unknown_inputs_fail_decode() {
    let broad = request_value(
        "request-1",
        "idem-1",
        false,
        json!({
            "name": "eliot.query",
            "arguments": { "query": "everything", "exact_resource_uri": null }
        }),
    );
    assert!(parse_request(broad).is_err());

    let unknown_command = request_value(
        "request-2",
        "idem-2",
        false,
        json!({"name":"eliot.admin","arguments":{}}),
    );
    assert!(parse_request(unknown_command).is_err());

    let extra_field = request_value(
        "request-3",
        "idem-3",
        false,
        json!({"name":"eliot.state","arguments":{"include":[],"vendor_flag":true}}),
    );
    assert!(parse_request(extra_field).is_err());

    let legacy_proof = request_value(
        "request-4",
        "idem-4",
        false,
        json!({
            "name": "eliot.finish",
            "arguments": {
                "task_id":"task-1",
                "expected_task_revision":7,
                "requested_outcome":"COMPLETE_CANDIDATE",
                "artifact_refs":[],
                "observation_refs":[],
                "verifier_run_refs":[],
                "remaining_unknowns_declared_by_caller":[],
                "rationale_candidate":"candidate",
                "completion_proof":{"verdict":"VERIFIED_COMPLETE"}
            }
        }),
    );
    assert!(parse_request(legacy_proof).is_err());
}

#[test]
fn observe_and_coordinate_discriminators_are_exact_and_closed() {
    let observe = [
        json!({"kind":"observation","content":"seen","affected_resources":[],"source_handles":[]}),
        json!({"kind":"decision","chosen_path":"a","alternatives":["b"],"revisit_condition":"new evidence"}),
        json!({"kind":"failure","failed_path":"a","signature":"E1","evidence_refs":[],"next_discriminator":"probe"}),
        json!({"kind":"outcome","outcome":"artifact produced","artifact_refs":["a"],"effect_refs":[],"verifier_run_refs":[]}),
        json!({"kind":"influence_ack","memory_handle":"m","influence_class":"seen_but_not_used","downstream_public_ref":null}),
    ];
    assert!(
        observe
            .into_iter()
            .all(|value| serde_json::from_value::<ObserveInput>(value).is_ok())
    );
    assert!(serde_json::from_value::<ObserveInput>(json!({"kind":"reuse_candidate"})).is_err());

    let coordinate = [
        json!({"operation":"delegate","goal":"bounded","owned_resources":["file"],"expected_result":"candidate"}),
        json!({"operation":"audit","sealed_packet_ref":"packet","evaluation_contract_ref":"contract@1"}),
        json!({"operation":"compare","candidate_refs":["a","b"],"criteria":["correctness"]}),
        json!({"operation":"wait","job_id":"job","expected_revision":1}),
        json!({"operation":"inspect","job_id":"job","expected_revision":1}),
        json!({"operation":"cancel","job_id":"job","expected_revision":1,"reason":"stop","include_descendants":true}),
        json!({"operation":"send","recipient_ref":"mailbox","message":{"answer":1},"predecessor_refs":[]}),
    ];
    assert!(
        coordinate
            .into_iter()
            .all(|value| serde_json::from_value::<CoordinateInput>(value).is_ok())
    );
    assert!(serde_json::from_value::<CoordinateInput>(json!({"operation":"launch"})).is_err());
}

#[derive(Default)]
struct CapturePort {
    tools: RefCell<Vec<ToolRequest>>,
}

impl KernelGovernorPort for CapturePort {
    test_resolver!();

    fn dispatch(
        &self,
        request: &eliot_mcp::ForwardedRequest,
    ) -> Result<PortProjection, PortFailure> {
        self.tools.borrow_mut().push(request.request.tool.clone());
        Ok(projection(json!({"captured": true})))
    }
}

#[test]
fn memory_use_alias_is_exactly_observe_influence_ack() -> Result<(), Box<dyn Error>> {
    let port = CapturePort::default();
    let arguments = json!({
        "memory_handle": "memory-1",
        "influence_class": "changed_verifier",
        "downstream_public_ref": "verification-1"
    });
    let canonical = parse_request(request_value(
        "request-1",
        "idem-1",
        false,
        json!({
            "name":"eliot.observe",
            "arguments":{
                "kind":"influence_ack",
                "memory_handle":"memory-1",
                "influence_class":"changed_verifier",
                "downstream_public_ref":"verification-1"
            }
        }),
    ))?;
    let alias = parse_request(request_value(
        "request-2",
        "idem-2",
        false,
        json!({"name":"eliot.memory_use","arguments":arguments}),
    ))?;
    let canonical_response =
        McpCore.execute(&port, stdio_transport("connection-1", 1), canonical)?;
    let alias_response = McpCore.execute(&port, stdio_transport("connection-1", 1), alias)?;

    assert_eq!(canonical_response.canonical_tool_name, "eliot.observe");
    assert_eq!(alias_response.canonical_tool_name, "eliot.observe");
    let tools = port.tools.borrow();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0], tools[1]);
    Ok(())
}

#[test]
fn semantic_duplicate_arrays_fail_before_dispatch() -> Result<(), Box<dyn Error>> {
    let port = CapturePort::default();
    let duplicate = parse_request(request_value(
        "request-1",
        "idem-1",
        false,
        json!({
            "name":"eliot.verify",
            "arguments":{
                "intent":"crate-fast",
                "artifact_refs":["artifact-1","artifact-1"],
                "verifier_profile_ref":"profile-1@1"
            }
        }),
    ))?;
    assert!(matches!(
        McpCore.execute(&port, stdio_transport("connection-1", 1), duplicate),
        Err(BridgeError::InvalidArgument { .. })
    ));
    assert!(port.tools.borrow().is_empty());
    Ok(())
}

#[test]
fn catalogue_has_exact_names_and_schema_parity() -> Result<(), Box<dyn Error>> {
    let catalogue = canonical_tool_schemas()?;
    let names = catalogue
        .iter()
        .map(|item| item.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, CANONICAL_TOOL_NAMES);
    assert!(!names.contains(&"eliot.memory_use"));

    assert_eq!(catalogue[0].input_schema, canonical_schema::<StateInput>()?);
    assert_eq!(
        catalogue[1].input_schema,
        canonical_schema::<PacketInput>()?
    );
    assert_eq!(
        catalogue[2].input_schema,
        canonical_schema::<ObserveInput>()?
    );
    assert_eq!(catalogue[3].input_schema, canonical_schema::<QueryInput>()?);
    assert_eq!(catalogue[4].input_schema, canonical_schema::<ActInput>()?);
    assert_eq!(
        catalogue[5].input_schema,
        canonical_schema::<VerifyInput>()?
    );
    assert_eq!(
        catalogue[6].input_schema,
        canonical_schema::<CoordinateInput>()?
    );
    assert_eq!(
        catalogue[7].input_schema,
        canonical_schema::<FinishAttemptDraft>()?
    );
    assert!(catalogue.windows(2).all(|pair| {
        pair[0].output_schema == pair[1].output_schema
            && pair[0].schema_sha256.len() == pair[1].schema_sha256.len()
    }));
    Ok(())
}

struct LargePort {
    with_resource: bool,
    mismatched_binding: bool,
}

impl KernelGovernorPort for LargePort {
    test_resolver!();

    fn dispatch(
        &self,
        request: &eliot_mcp::ForwardedRequest,
    ) -> Result<PortProjection, PortFailure> {
        let content = json!({"large": "x".repeat(300_000)});
        let content_bytes =
            serde_json::to_vec(&content).map_err(|error| PortFailure::Unsupported {
                capability: "test-fixture".to_owned(),
                reason: error.to_string(),
            })?;
        let content_size =
            u64::try_from(content_bytes.len()).map_err(|error| PortFailure::Unsupported {
                capability: "test-fixture".to_owned(),
                reason: error.to_string(),
            })?;
        let content_sha256 = if self.mismatched_binding {
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned()
        } else {
            format!("{:x}", Sha256::digest(&content_bytes))
        };
        let mut value = projection(content);
        if self.with_resource {
            let artifact = json!({
                "artifact_id":"artifact-large",
                "sha256":content_sha256,
                "role":"ARTIFACT",
                "source_revision":"7"
            });
            value.artifacts =
                serde_json::from_value(json!([artifact.clone()])).map_err(|error| {
                    PortFailure::Unsupported {
                        capability: "test-fixture".to_owned(),
                        reason: error.to_string(),
                    }
                })?;
            value.resource = Some(
                serde_json::from_value(json!({
                    "uri":"eliot://resource/artifact-large",
                    "artifact":artifact,
                    "media_type":"application/json",
                    "size_bytes":content_size,
                    "session":request.request.session
                }))
                .map_err(|error| PortFailure::Unsupported {
                    capability: "test-fixture".to_owned(),
                    reason: error.to_string(),
                })?,
            );
        }
        Ok(value)
    }
}

#[test]
fn oversize_requires_resource_and_resource_response_is_bounded() -> Result<(), Box<dyn Error>> {
    let request = parse_request(request_value("request-1", "idem-1", false, state_tool()))?;
    assert!(matches!(
        McpCore.execute(
            &LargePort {
                with_resource: false,
                mismatched_binding: false,
            },
            stdio_transport("connection-1", 1),
            request.clone()
        ),
        Err(BridgeError::ResourceRequired { .. })
    ));
    let response = McpCore.execute(
        &LargePort {
            with_resource: true,
            mismatched_binding: false,
        },
        stdio_transport("connection-1", 1),
        request,
    )?;
    assert!(response.resource.is_some());
    assert_eq!(
        response.content["resource_uri"],
        "eliot://resource/artifact-large"
    );
    assert!(serde_json::to_vec(&response)?.len() <= HARD_STRUCTURED_RESPONSE_BYTES);

    let mismatched = parse_request(request_value("request-2", "idem-2", false, state_tool()))?;
    assert!(matches!(
        McpCore.execute(
            &LargePort {
                with_resource: true,
                mismatched_binding: true,
            },
            stdio_transport("connection-1", 1),
            mismatched,
        ),
        Err(BridgeError::ResourceBindingMismatch)
    ));
    Ok(())
}

struct JobPort;

impl KernelGovernorPort for JobPort {
    test_resolver!();

    fn dispatch(
        &self,
        request: &eliot_mcp::ForwardedRequest,
    ) -> Result<PortProjection, PortFailure> {
        let handle: DurableJobHandle = serde_json::from_value(json!({
            "job_id":"job-1",
            "resource_uri":"eliot://job/job-1",
            "revision":1,
            "session":request.request.session
        }))
        .map_err(|error| PortFailure::Unsupported {
            capability: "test-fixture".to_owned(),
            reason: error.to_string(),
        })?;
        let mut value = projection(json!({"queued":true}));
        value.durable_job = Some(handle);
        Ok(value)
    }
}

struct EscalatingPort;

impl KernelGovernorPort for EscalatingPort {
    test_resolver!();

    fn dispatch(
        &self,
        _request: &eliot_mcp::ForwardedRequest,
    ) -> Result<PortProjection, PortFailure> {
        Ok(PortProjection {
            kind: ProjectionKind::Projection,
            content: json!({"claimed":"external effect"}),
            artifacts: Vec::new(),
            proof_ceiling: ProofCeiling::ObservedExternalEffect,
            resource: None,
            durable_job: None,
        })
    }
}

#[test]
fn projection_cannot_escalate_to_external_effect_or_finish_proof() -> Result<(), Box<dyn Error>> {
    let request = parse_request(request_value("request-1", "idem-1", false, state_tool()))?;
    assert!(matches!(
        McpCore.execute(&EscalatingPort, stdio_transport("connection-1", 1), request),
        Err(BridgeError::InvalidArgument { .. })
    ));
    Ok(())
}

#[test]
fn tasks_and_fallback_wrap_the_identical_durable_job_handle() -> Result<(), Box<dyn Error>> {
    let without_tasks = McpCore.execute(
        &JobPort,
        stdio_transport("connection-1", 1),
        parse_request(request_value("request-1", "idem-1", false, state_tool()))?,
    )?;
    let with_tasks = McpCore.execute(
        &JobPort,
        stdio_transport("connection-1", 1),
        parse_request(request_value("request-2", "idem-2", true, state_tool()))?,
    )?;
    assert!(matches!(
        without_tasks.job,
        Some(JobPresentation::DurableJob { .. })
    ));
    assert!(matches!(
        with_tasks.job,
        Some(JobPresentation::McpTask { .. })
    ));
    assert_eq!(
        without_tasks.job.as_ref().map(JobPresentation::handle),
        with_tasks.job.as_ref().map(JobPresentation::handle)
    );
    Ok(())
}

#[test]
fn absent_provider_is_typed_plan_gap_never_fake_success() -> Result<(), Box<dyn Error>> {
    let response = McpCore.execute(
        &NoProviderPort,
        stdio_transport("connection-1", 1),
        parse_request(request_value("request-1", "idem-1", false, state_tool()))?,
    )?;
    assert_eq!(response.kind, ResponseKind::PlanGap);
    assert_eq!(response.content["code"], "PLAN_GAP");
    assert_eq!(response.proof_ceiling, ProofCeiling::Observation);
    Ok(())
}

#[test]
fn compatibility_hint_is_isolated_and_cannot_supply_session() -> Result<(), Box<dyn Error>> {
    let port = CapturePort::default();
    let mut request = parse_request(request_value("request-1", "idem-1", false, state_tool()))?;
    request.protocol_version = McpProtocolVersion::Compat2025_11_25;
    assert!(matches!(
        McpCore.execute(&port, stdio_transport("connection-1", 1), request.clone()),
        Err(BridgeError::InvalidArgument { .. })
    ));
    let response = McpCore.execute_compat(
        &port,
        stdio_transport("connection-1", 1),
        request,
        CompatibilityCorrelation {
            transport_session_hint: Some("transport-only".to_owned()),
        },
    )?;
    assert_eq!(
        response.compatibility_correlation_hint.as_deref(),
        Some("transport-only")
    );

    let mut missing_session = request_value("request-2", "idem-2", false, state_tool());
    missing_session["protocol_version"] = json!("2025-11-25");
    missing_session["identity"]["request"]["metadata"]["session_id"] = Value::Null;
    let parsed = parse_request(missing_session)?;
    assert!(matches!(
        McpCore.execute_compat(
            &port,
            stdio_transport("connection-1", 1),
            parsed,
            CompatibilityCorrelation {
                transport_session_hint: Some("session-1".to_owned())
            }
        ),
        Err(BridgeError::InvalidArgument { .. })
    ));
    Ok(())
}

#[test]
fn transport_profiles_are_stdio_default_and_exact_loopback_only() -> Result<(), Box<dyn Error>> {
    assert_eq!(TransportProfile::default(), TransportProfile::Stdio);
    let valid: TransportProfile = serde_json::from_value(json!({
        "kind":"loopback_http",
        "bind_address":"127.0.0.1",
        "host":"127.0.0.1:7777",
        "browser_origin":"http://127.0.0.1:7777",
        "credential_ref":"credential/local/1"
    }))?;
    valid.validate()?;

    let invalid: TransportProfile = serde_json::from_value(json!({
        "kind":"loopback_http",
        "bind_address":"0.0.0.0",
        "host":"localhost:7777",
        "browser_origin":null,
        "credential_ref":"credential/local/1"
    }))?;
    assert!(invalid.validate().is_err());

    let ambiguous: TransportProfile = serde_json::from_value(json!({
        "kind":"loopback_http",
        "bind_address":"127.0.0.1",
        "host":"127.0.0.1:shadow:7777",
        "browser_origin":null,
        "credential_ref":"credential/local/1"
    }))?;
    assert!(ambiguous.validate().is_err());
    Ok(())
}
