#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    cell::{Cell, RefCell},
    error::Error,
};

use eliot_mcp::{
    ActiveSessionBinding, ApplicationRequest, AssuranceRecoveryCode, BindingResolutionRequest,
    KernelGovernorPort, McpCore, PortFailure, PortProjection, ProjectionKind, ReplayDisposition,
    TransportProfile, TransportRequestContext, TypedRejection, decode_protected_request_bytes,
    derive_transformed_lineage, envelope_authority, is_exact_replay, replay_disposition,
};
use eliot_receipts::ProofCeiling;
use eliot_source_assurance::{
    AdmissibleUse, AdmissionExpectation, AxisStatus, EffectCeiling, GoverningSourceIdentity,
    GoverningSourceSet, InstructionTaint, OwnerSourceEvidence, PrivacyClass, QuarantineStatus,
    ScopeBindingProof, SourceAssurance, SourceAssurancePolicy, SourceFrontierBinding,
    SourceProvenance, SourceSnapshotBinding, SourceTrustProfile, ThreatStatus, canonical_digest,
};
use serde_json::json;

fn digest(value: impl AsRef<[u8]>) -> String {
    canonical_digest(&value.as_ref()).expect("fixture digest must be serializable")
}

fn request() -> ApplicationRequest {
    serde_json::from_value(json!({
        "protocol_version": "2026-07-28",
        "session": {"session_id":"session-1","authority_epoch":1,"state_fence": {
            "authority_epoch":1,"resource_generation":1,"task_revision":7,"policy_revision":1,"integration_revision":1
        }},
        "identity": {"request": {"metadata": {
            "request_id":"request-1","session_id":"session-1","task_id":"task-1","product_id":"product-1","source_id":"source-1",
            "state_fence":{"authority_epoch":1,"resource_generation":1,"task_revision":7,"policy_revision":1,"integration_revision":1},
            "clock":{"valid_time_ms":1000,"known_time_ms":1001,"transaction_sequence":1,"monotonic_ns":500}
        },"state_fence":{"authority_epoch":1,"resource_generation":1,"task_revision":7,"policy_revision":1,"integration_revision":1}},
        "idempotency_key":"idempotency-1","deadline_unix_ms":5000,"cancellation_id":"cancel-1"},
        "security":{"privacy_class":"INTERNAL","instruction_taint":"DATA_ONLY","effect_ceiling":"CANDIDATE_ONLY"},
        "client_capabilities":{"tasks":false},
        "tool":{"name":"eliot.state","arguments":{"include":["task"]}}
    }))
    .expect("request fixture must decode")
}

fn transport() -> TransportRequestContext {
    TransportRequestContext {
        profile: TransportProfile::Stdio,
        connection_id: "connection-1".into(),
        scoped_credential_ref: "credential/stdio/1".into(),
        transport_generation: 1,
    }
}

fn source_evidence(request_id: &str, canonical_request_sha256: &str) -> OwnerSourceEvidence {
    let frontier = SourceFrontierBinding {
        frontier_id: "frontier-1".into(),
        workspace_identity: "workspace-1".into(),
        repository_revision: "revision-1".into(),
        dirty_state_digest: digest("dirty"),
        generation: 1,
    };
    let scope = ScopeBindingProof {
        expected_scope: "scope-1".into(),
        observed_scope: "scope-1".into(),
        expected_generation: 1,
        observed_generation: 1,
        evidence_digest: digest("scope"),
    };
    let assurance = SourceAssurance {
        schema_version: "eliot-source-assurance-v1".into(),
        governing_sources: GoverningSourceSet::new(
            "governing-set",
            "revision-1",
            vec![GoverningSourceIdentity {
                source_id: "architecture".into(),
                kind: "governing".into(),
                canonical_ref: "docs/ARCHITECTURE_CONTRACT.md".into(),
                content_digest: digest("architecture"),
                origin_ref: "owner-receipt:architecture".into(),
                revision: "revision-1".into(),
            }],
        )
        .expect("source fixture must be valid"),
        provenance: SourceProvenance {
            producer: "authenticated-owner".into(),
            acquisition_ref: "capture-1".into(),
            lineage_digest: digest("lineage"),
            authentication_ref: "owner-auth:1".into(),
        },
        trust: SourceTrustProfile {
            integrity: AxisStatus::Verified,
            freshness: AxisStatus::Verified,
            competence: AxisStatus::Verified,
            incentives: AxisStatus::Verified,
            independence: AxisStatus::Verified,
            privacy: PrivacyClass::Internal,
            instruction_taint: InstructionTaint::Data,
            threat: ThreatStatus::NoneObserved,
        },
        quarantine: QuarantineStatus::Clear,
        snapshot: SourceSnapshotBinding {
            snapshot_id: "snapshot-1".into(),
            source_set_id: "governing-set".into(),
            source_set_revision: "revision-1".into(),
            content_digest: digest("snapshot"),
            frontier_digest: canonical_digest(&frontier).expect("frontier fixture must digest"),
            state_fence: "fence-1".into(),
        },
        frontier: frontier.clone(),
        scope: scope.clone(),
        requested_use: AdmissibleUse::Evidence,
        effect_ceiling: EffectCeiling::ReadOnlyCandidate,
    };
    OwnerSourceEvidence {
        owner_principal_ref: "principal/local-user".into(),
        evidence_ref: "owner-evidence:1".into(),
        request_id: request_id.into(),
        original_request_sha256: canonical_request_sha256.into(),
        idempotency_key: "idempotency-1".into(),
        cancellation_id: "cancel-1".into(),
        session_id: "session-1".into(),
        state_fence_digest: canonical_digest(&"state-fence").expect("state fence digest"),
        canonical_request_sha256: canonical_request_sha256.into(),
        verifier_ref: Some("verifier/source-v1".into()),
        policy: SourceAssurancePolicy {
            policy_version: "source-policy-v1".into(),
            expected_source_state_fence: "fence-1".into(),
            expectation: AdmissionExpectation {
                source_set_id: "governing-set".into(),
                source_set_revision: "revision-1".into(),
                frontier,
                scope,
            },
            allowed_use: AdmissibleUse::Evidence,
            privacy_class: PrivacyClass::Internal,
            effect_ceiling: EffectCeiling::ReadOnlyCandidate,
            required_verifier: Some("verifier/source-v1".into()),
        },
        assurance,
    }
}

struct SpyPort {
    dispatches: Cell<u32>,
    saw_assurance: Cell<bool>,
    evidence: RefCell<OwnerSourceEvidence>,
    forwarded: RefCell<Option<eliot_mcp::ForwardedRequest>>,
}

impl Default for SpyPort {
    fn default() -> Self {
        Self {
            dispatches: Cell::new(0),
            saw_assurance: Cell::new(false),
            evidence: RefCell::new(source_evidence("request-1", &"0".repeat(64))),
            forwarded: RefCell::new(None),
        }
    }
}

impl KernelGovernorPort for SpyPort {
    fn resolve_active_session(
        &self,
        request: &BindingResolutionRequest,
    ) -> Result<ActiveSessionBinding, PortFailure> {
        Ok(ActiveSessionBinding {
            binding_id: "binding-1".into(),
            principal_ref: "principal/local-user".into(),
            session: request.claimed_session.clone(),
            transport: request.transport.clone(),
            request_id: request.request_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            cancellation_id: request.cancellation_id.clone(),
            canonical_request_sha256: request.canonical_request_sha256.clone(),
            resolved_at_unix_ms: 1100,
            valid_until_unix_ms: request.deadline_unix_ms + 1000,
        })
    }

    fn resolve_source_assurance(
        &self,
        request: &BindingResolutionRequest,
        _binding: &ActiveSessionBinding,
    ) -> Result<OwnerSourceEvidence, PortFailure> {
        let mut evidence = self.evidence.borrow().clone();
        evidence.request_id.clone_from(&request.request_id);
        evidence
            .original_request_sha256
            .clone_from(&request.original_request_sha256);
        evidence
            .idempotency_key
            .clone_from(&request.idempotency_key);
        evidence
            .cancellation_id
            .clone_from(&request.cancellation_id);
        evidence.session_id = request.claimed_session.session_id.to_string();
        evidence.state_fence_digest =
            canonical_digest(&request.claimed_session.state_fence).expect("state fence digest");
        evidence
            .canonical_request_sha256
            .clone_from(&request.canonical_request_sha256);
        Ok(evidence)
    }

    fn dispatch(
        &self,
        request: &eliot_mcp::ForwardedRequest,
    ) -> Result<PortProjection, PortFailure> {
        self.dispatches.set(self.dispatches.get() + 1);
        self.saw_assurance
            .set(!request.source_assurance.evidence_ref.is_empty());
        *self.forwarded.borrow_mut() = Some(request.clone());
        Ok(PortProjection {
            kind: ProjectionKind::Projection,
            content: json!({"ok":true}),
            artifacts: Vec::new(),
            proof_ceiling: ProofCeiling::Observation,
            resource: None,
            durable_job: None,
        })
    }
}

#[derive(Default)]
struct NoEvidencePort {
    dispatches: Cell<u32>,
}

impl KernelGovernorPort for NoEvidencePort {
    fn resolve_active_session(
        &self,
        request: &BindingResolutionRequest,
    ) -> Result<ActiveSessionBinding, PortFailure> {
        Ok(ActiveSessionBinding {
            binding_id: "binding-1".into(),
            principal_ref: "principal/local-user".into(),
            session: request.claimed_session.clone(),
            transport: request.transport.clone(),
            request_id: request.request_id.clone(),
            idempotency_key: request.idempotency_key.clone(),
            cancellation_id: request.cancellation_id.clone(),
            canonical_request_sha256: request.canonical_request_sha256.clone(),
            resolved_at_unix_ms: 1100,
            valid_until_unix_ms: request.deadline_unix_ms + 1000,
        })
    }

    fn dispatch(
        &self,
        _request: &eliot_mcp::ForwardedRequest,
    ) -> Result<PortProjection, PortFailure> {
        self.dispatches.set(self.dispatches.get() + 1);
        Ok(PortProjection {
            kind: ProjectionKind::Projection,
            content: json!({"unexpected":true}),
            artifacts: Vec::new(),
            proof_ceiling: ProofCeiling::Observation,
            resource: None,
            durable_job: None,
        })
    }
}

#[test]
fn assured_ingress_forwards_one_complete_envelope() -> Result<(), Box<dyn Error>> {
    let port = SpyPort::default();
    let original = request();
    let response = McpCore.execute(&port, transport(), original.clone())?;
    assert_eq!(response.kind, eliot_mcp::ResponseKind::Projection);
    assert_eq!(port.dispatches.get(), 1);
    assert!(port.saw_assurance.get());
    let forwarded = port.forwarded.borrow();
    let forwarded = forwarded
        .as_ref()
        .expect("semantic port receives a request");
    assert_eq!(
        forwarded.original_request_sha256,
        forwarded.canonical_request_sha256
    );
    assert_eq!(
        forwarded.original_payload_sha256,
        forwarded.canonical_payload_sha256
    );
    assert_eq!(forwarded.source_assurance.request_id, "request-1");
    assert_eq!(forwarded.source_assurance.session_id, "session-1");
    Ok(())
}

#[test]
fn stale_owner_evidence_stops_before_semantic_dispatch() {
    let port = SpyPort::default();
    let mut evidence = source_evidence("request-1", &"0".repeat(64));
    evidence.policy.expectation.frontier.generation = 2;
    *port.evidence.borrow_mut() = evidence;
    let result = McpCore.execute(&port, transport(), request());
    assert!(matches!(
        result,
        Err(eliot_mcp::BridgeError::SourceAssuranceRejected { .. })
    ));
    assert_eq!(port.dispatches.get(), 0);
}

#[test]
fn caller_cannot_spoof_owner_principal_or_upgrade_assurance() {
    let port = SpyPort::default();
    let mut evidence = source_evidence("request-1", &"0".repeat(64));
    evidence.owner_principal_ref = "principal/forged".into();
    *port.evidence.borrow_mut() = evidence;
    let result = McpCore.execute(&port, transport(), request());
    assert!(matches!(
        result,
        Err(eliot_mcp::BridgeError::SourceAssuranceRejected { .. })
    ));
    assert_eq!(port.dispatches.get(), 0);
}

#[test]
fn missing_owner_evidence_is_a_typed_gap_before_dispatch() {
    let port = NoEvidencePort::default();
    let result = McpCore
        .execute(&port, transport(), request())
        .expect("gap is a response");
    assert_eq!(result.kind, eliot_mcp::ResponseKind::PlanGap);
    assert_eq!(port.dispatches.get(), 0);
}

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!("data/source_assurance_ingress.json"))
        .expect("fixtures must be valid JSON")
}

fn fixture_request(name: &str) -> ApplicationRequest {
    serde_json::from_value(fixtures()[name].clone()).expect("fixture request must decode")
}

fn is_hex64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// WORK_UNIT_CASE 692/26
#[test]
fn raw_duplicate_protected_keys_rejected_before_dispatch() -> Result<(), Box<dyn Error>> {
    let data = fixtures();
    let raw = data["raw_duplicate_keys"]
        .as_str()
        .expect("raw duplicate fixture")
        .as_bytes();
    let escaped = data["raw_duplicate_keys_escaped"]
        .as_str()
        .expect("escaped duplicate fixture")
        .as_bytes();
    for bytes in [raw, escaped] {
        let decoded = decode_protected_request_bytes(bytes);
        assert!(
            matches!(decoded, Err(TypedRejection::DuplicateKey { .. })),
            "raw duplicates must be typed rejections"
        );
        if let Err(TypedRejection::DuplicateKey { key }) = decoded {
            assert_eq!(key, "tool");
        }
        let port = SpyPort::default();
        let result = McpCore.execute_raw(&port, transport(), bytes);
        assert!(matches!(
            result,
            Err(eliot_mcp::BridgeError::InvalidArgument { .. })
        ));
        if let Err(error) = result {
            let display = error.to_string();
            assert!(display.contains("duplicate protected key"));
            assert!(
                !display.contains("other"),
                "diagnostics must not echo bodies"
            );
        }
        assert_eq!(port.dispatches.get(), 0);
    }
    let unknown = serde_json::to_vec(&data["unknown_variant"])?;
    let decoded = decode_protected_request_bytes(&unknown);
    assert!(
        matches!(decoded, Err(TypedRejection::UnknownVariant { .. })),
        "unknown variants must be typed rejections"
    );
    let port = SpyPort::default();
    let result = McpCore.execute_raw(&port, transport(), &unknown);
    assert!(matches!(
        result,
        Err(eliot_mcp::BridgeError::InvalidArgument { .. })
    ));
    if let Err(error) = result {
        let display = error.to_string();
        assert!(display.contains("eliot.admin"));
        assert!(
            !display.contains("session-1"),
            "diagnostics must not echo protected bodies"
        );
    }
    assert_eq!(port.dispatches.get(), 0);
    Ok(())
}

// WORK_UNIT_CASE 692/15
#[test]
fn admitted_forwards_once_with_complete_envelope() -> Result<(), Box<dyn Error>> {
    let port = SpyPort::default();
    let original = fixture_request("valid_envelope");
    let raw = serde_json::to_vec(&fixtures()["valid_envelope"])?;
    let decoded = decode_protected_request_bytes(&raw)?;
    assert_eq!(decoded, original);
    let response = McpCore.execute_raw(&port, transport(), &raw)?;
    assert_eq!(response.kind, eliot_mcp::ResponseKind::Projection);
    assert_eq!(port.dispatches.get(), 1);
    assert!(port.saw_assurance.get());
    let forwarded = port.forwarded.borrow();
    let forwarded = forwarded
        .as_ref()
        .expect("semantic port receives a request");
    for digest in [
        &forwarded.original_request_sha256,
        &forwarded.original_payload_sha256,
        &forwarded.canonical_payload_sha256,
        &forwarded.canonical_request_sha256,
        &forwarded.source_assurance.assurance_digest,
        &forwarded.source_assurance.state_fence_digest,
        &forwarded.source_assurance.canonical_request_sha256,
        &forwarded.source_assurance.original_request_sha256,
    ] {
        assert!(is_hex64(digest), "digests must be lowercase hex");
    }
    assert_eq!(forwarded.source_assurance.request_id, "request-1");
    assert_eq!(forwarded.source_assurance.session_id, "session-1");
    assert_eq!(forwarded.source_assurance.idempotency_key, "idempotency-1");
    assert_eq!(
        forwarded.source_assurance.owner_principal_ref,
        "principal/local-user"
    );
    assert_eq!(
        forwarded.active_session_binding.principal_ref,
        "principal/local-user"
    );
    assert_eq!(
        forwarded
            .active_session_binding
            .session
            .session_id
            .to_string(),
        "session-1"
    );
    assert_eq!(
        forwarded.source_assurance.verifier_ref.as_deref(),
        Some("verifier/source-v1")
    );
    assert_eq!(
        forwarded.source_assurance.policy.policy_version,
        "source-policy-v1"
    );
    assert_eq!(
        forwarded
            .source_assurance
            .policy
            .required_verifier
            .as_deref(),
        Some("verifier/source-v1")
    );
    assert!(!forwarded.source_assurance.evidence_ref.is_empty());
    let authority = envelope_authority(
        &forwarded.request,
        &forwarded.active_session_binding,
        &forwarded.source_assurance,
    );
    assert_eq!(authority.selector, "eliot.state");
    assert_eq!(authority.request_id, "request-1");
    assert_eq!(authority.session_id, "session-1");
    assert_eq!(authority.principal_ref, "principal/local-user");
    assert!(is_exact_replay(forwarded, &forwarded.clone()));
    assert_eq!(
        replay_disposition(forwarded, &forwarded.clone()),
        ReplayDisposition::ExactReplay
    );
    let lineage = derive_transformed_lineage(
        &forwarded
            .source_assurance
            .assurance
            .provenance
            .lineage_digest,
        "transform/test-1",
    )?;
    assert_eq!(
        lineage.original_lineage_digest,
        forwarded
            .source_assurance
            .assurance
            .provenance
            .lineage_digest
    );
    assert!(is_hex64(&lineage.derived_digest));
    assert_ne!(lineage.derived_digest, lineage.original_lineage_digest);
    Ok(())
}

// WORK_UNIT_CASE 692/8
#[test]
fn nested_encoded_bidi_data_remains_data() -> Result<(), Box<dyn Error>> {
    let port = SpyPort::default();
    let request = fixture_request("nested_data_as_data");
    let response = McpCore.execute(&port, transport(), request.clone())?;
    assert_eq!(response.kind, eliot_mcp::ResponseKind::Projection);
    assert_eq!(port.dispatches.get(), 1);
    let forwarded = port.forwarded.borrow();
    let forwarded = forwarded
        .as_ref()
        .expect("semantic port receives a request");
    assert_eq!(forwarded.request.tool.canonical_name(), "eliot.query");
    let authority = envelope_authority(
        &forwarded.request,
        &forwarded.active_session_binding,
        &forwarded.source_assurance,
    );
    assert_eq!(authority.selector, "eliot.query");
    assert_eq!(authority.request_id, "request-1");
    assert_eq!(authority.session_id, "session-1");
    assert_eq!(authority.principal_ref, "principal/local-user");
    assert_eq!(authority.policy_version, "source-policy-v1");
    let query_text = match &forwarded.request.tool {
        eliot_mcp::ToolRequest::Query(input) => input.query.clone(),
        other => panic!("expected query, got {}", other.canonical_name()),
    };
    assert!(query_text.contains("forged"));
    assert!(query_text.contains("aGVsbG8td29ybGQ="));
    assert!(query_text.contains('\u{202a}'));
    assert!(query_text.contains('\u{200b}'));
    assert_ne!(forwarded.request.tool.canonical_name(), "eliot.finish");
    Ok(())
}

// WORK_UNIT_CASE 692/27
#[test]
fn stale_incomplete_typed_recovery_zero_calls_and_replay_conflicts() -> Result<(), Box<dyn Error>> {
    let stale_port = SpyPort::default();
    let mut stale_evidence = source_evidence("request-1", &"0".repeat(64));
    stale_evidence.policy.expectation.frontier.generation = 2;
    *stale_port.evidence.borrow_mut() = stale_evidence;
    let stale_request = fixture_request("stale_binding");
    let stale_result = McpCore.execute(&stale_port, transport(), stale_request);
    match stale_result {
        Err(eliot_mcp::BridgeError::SourceAssuranceRejected {
            code,
            findings,
            reason,
        }) => {
            assert_eq!(code, AssuranceRecoveryCode::Stale);
            assert!(!findings.is_empty(), "evaluator findings must be preserved");
            assert!(!reason.is_empty());
            assert!(
                !reason.contains("revision-1") || reason.contains("revalidation"),
                "reason must stay redacted"
            );
        }
        other => panic!("stale evidence must be a typed rejection, got {other:?}"),
    }
    assert_eq!(stale_port.dispatches.get(), 0);

    let incomplete_port = SpyPort::default();
    let mut incomplete = source_evidence("request-1", &"0".repeat(64));
    incomplete.evidence_ref = String::new();
    *incomplete_port.evidence.borrow_mut() = incomplete;
    let incomplete_result = McpCore.execute(&incomplete_port, transport(), request());
    match incomplete_result {
        Err(eliot_mcp::BridgeError::SourceAssuranceRejected { code, .. }) => {
            assert_eq!(code, AssuranceRecoveryCode::Incomplete);
        }
        other => panic!("incomplete evidence must be typed, got {other:?}"),
    }
    assert_eq!(incomplete_port.dispatches.get(), 0);

    let first_port = SpyPort::default();
    let second_port = SpyPort::default();
    let original = fixture_request("replay_original");
    let changed = fixture_request("replay_changed_payload");
    McpCore.execute(&first_port, transport(), original)?;
    McpCore.execute(&second_port, transport(), changed)?;
    let first = first_port.forwarded.borrow();
    let second = second_port.forwarded.borrow();
    let (first, second) = (
        first.as_ref().expect("first forwards"),
        second.as_ref().expect("second forwards"),
    );
    assert!(!is_exact_replay(first, second));
    assert!(matches!(
        replay_disposition(first, second),
        ReplayDisposition::Conflict(eliot_mcp::ReplayConflictKind::PayloadChanged)
    ));
    assert_eq!(first_port.dispatches.get(), 1);
    assert_eq!(second_port.dispatches.get(), 1);
    Ok(())
}
