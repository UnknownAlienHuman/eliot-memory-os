#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::{
    cell::{Cell, RefCell},
    error::Error,
};

use eliot_mcp::{
    ActiveSessionBinding, ApplicationRequest, BindingResolutionRequest, KernelGovernorPort,
    McpCore, PortFailure, PortProjection, ProjectionKind, TransportProfile,
    TransportRequestContext,
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
