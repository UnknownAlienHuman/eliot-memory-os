//! Issue #1838 W3/W4/A2: the four I16.12 evidence classes the trace manifest
//! binds as REQUIRED slots.
//!
//! I16.12 requires a replayable Material/Critical trace to contain the
//! "Active View/packet manifest", the "principal, Session, leases and policy
//! snapshots", and the "verifier/artifact results", with "missing parts
//! explicitly listed"; and it states that "Missing trace does not invent failure
//! or success; it limits replay and may force `DEGRADED_NO_PROOF`."
//!
//! Two proofs, one per direction:
//!
//! - POSITIVE: a seal whose durable record carries the producer principal and
//!   the applicable policy snapshot binds both, and a run that also observes
//!   the Active View/packet manifest and the verifier/artifact result seals
//!   `VERIFIED_COMPLETE` with an empty `missing_parts`.
//! - REFUSAL: withholding any one of the four classes names that class in
//!   `missing_parts` and seals `DEGRADED_NO_PROOF`, forged or substituted
//!   evidence for a class does not satisfy its slot, and a body claiming
//!   `VERIFIED_COMPLETE` while withholding one is refused on readback instead
//!   of being served as a complete trace.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test fixtures use expect for fail-fast setup"
)]

use eliot_contracts::{EpochId, EpochLineageId, PolicyRevision, ResourceGeneration, StateFence};
use eliot_kernel::kernel_audit::{
    AuditAssuranceClass, AuditCaptureMode, AuditEventKind, AuditLineage, AuditRecord,
};
use eliot_kernel::trace_manifest::{
    TRACE_MANIFEST_FORMAT_VERSION, TRACE_MANIFEST_REQUIRED_SLOTS, TraceEvidence, TraceFinish,
    TraceManifest,
};
use eliot_ors::{
    HostRequestEffectEvidence, HostRequestKind, HostRequestRecord, HostRequestRetainedLineage,
    HostRequestRetainedResultClass, HostRequestState, OpaqueLabel, OperationIdentity,
};
use eliot_protocol::{HOST_REQUEST_RESULT_BODY_WIRE_ID, HostRequestResultBody, LocalReadAttempt};
use eliot_security_contracts::{InfluenceState, PolicyFence};

/// The four required I16.12 classes this proof names.
const EVIDENCE_CLASSES: [&str; 4] = [
    "principal",
    "policy_snapshot",
    "active_view_packet_manifest",
    "verifier_result",
];

const PRINCIPAL: &str = "principal:windows:trace-manifest";
const POLICY_SNAPSHOT: &str = "policy-snapshot:trace-manifest";
const VIEW_MANIFEST: &str = "campaign-view:trace-manifest";
const VERIFIER_RESULT: &str = "verifier:trace-manifest:accepted";

const RESULT_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const REQUEST_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const INPUT_HANDLE: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const OPERATION_ID: &str =
    "hostreq:4444444444444444444444444444444444444444444444444444444444444444";

fn test_epoch() -> EpochId {
    EpochId::new(
        EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("lineage"),
        std::num::NonZeroU64::new(1).expect("seq"),
    )
    .expect("epoch")
}

/// Policy-bound fence: the I16.12 "policy snapshots" class has a revision here
/// to agree with.
fn policy_bound_fence() -> StateFence {
    StateFence {
        authority_epoch: test_epoch(),
        resource_generation: ResourceGeneration::new(7).expect("generation"),
        task_revision: None,
        policy_revision: Some(PolicyRevision::new(4).expect("policy revision")),
        integration_revision: None,
    }
}

fn test_session() -> eliot_ipc::Session {
    let fence = policy_bound_fence();
    eliot_ipc::Session {
        connection_id: "trace-manifest-conn".to_owned(),
        protocol_version: eliot_protocol::ProtocolVersion::CURRENT,
        peer: eliot_ipc::PeerIdentity::Unavailable {
            reason: eliot_ipc::PeerIdentityUnavailable::ProviderProofNotComposed,
        },
        authority_epoch: test_epoch(),
        module_generation: eliot_runtime_contracts::ModuleGeneration {
            module_id: eliot_contracts::ContractId::new("eliotd").expect("module id"),
            generation: fence.resource_generation,
            artifact_id: eliot_contracts::ArtifactId::new("a".repeat(64)).expect("artifact id"),
            state: eliot_runtime_contracts::ModuleGenerationState::Starting,
            health: eliot_runtime_contracts::HealthVector::healthy(),
            state_fence: fence,
        },
        launch_nonce: "trace-manifest-nonce".to_owned(),
        capabilities: Vec::new(),
        privacy_classes: Vec::new(),
        effects: Vec::new(),
        session_epoch: 1,
        state: eliot_ipc::SessionState::Open,
    }
}

/// The durable result lineage the production seal site persists: the read
/// owner's authenticated producer reference and its applicable policy snapshot.
fn retained_lineage() -> HostRequestRetainedLineage {
    HostRequestRetainedLineage {
        output_artifact_ref: None,
        output_digest: RESULT_DIGEST.to_owned(),
        producer_ref: Some(PRINCIPAL.to_owned()),
        source_revisions: None,
        source_state_fence: None,
        input_refs: None,
        transformation_lineage: None,
        closure_refs: None,
        policy_fence: Some(PolicyFence {
            policy_snapshot_id: POLICY_SNAPSHOT.to_owned(),
            state_fence: policy_bound_fence(),
        }),
        origin_evidence_refs: None,
        semantic_receipt_ref: None,
        result_class: HostRequestRetainedResultClass::ExistingEvidenceRead,
        proof_ceiling: None,
        influence_state: InfluenceState::Unknown,
        instruction_taint: None,
    }
}

fn durable_record() -> HostRequestRecord {
    HostRequestRecord {
        contract_version: 1,
        send_claim_protocol_version: 0,
        transport_channel_binding_sha256: None,
        operation_id: OperationIdentity::new(OPERATION_ID).expect("operation identity"),
        kind: HostRequestKind::Invocation,
        request_id: OpaqueLabel::new("trace-manifest-request").expect("request id"),
        correlation_projection: None,
        idempotency_key: OpaqueLabel::new("trace-manifest-request:invoke")
            .expect("idempotency key"),
        cancellation_id: OpaqueLabel::new("trace-manifest-request:cancel")
            .expect("cancellation id"),
        parent_operation_id: None,
        request_digest: REQUEST_DIGEST.to_owned(),
        payload_digest: INPUT_HANDLE.to_owned(),
        payload_schema_id: Some(OpaqueLabel::new("eliot.mcp.tool-request.v1").expect("schema id")),
        payload_body: None,
        connection_ref: OpaqueLabel::new("trace-manifest-conn").expect("connection ref"),
        session_ref: Some(OpaqueLabel::new("trace-manifest-session").expect("session ref")),
        task_ref: Some(OpaqueLabel::new("trace-manifest-task").expect("task ref")),
        scope_ref: Some(OpaqueLabel::new("trace-manifest-scope").expect("scope ref")),
        capability_ref: OpaqueLabel::new("eliot.query").expect("capability ref"),
        fence_digest: "e".repeat(64),
        authority_epoch: test_epoch(),
        generation: 7,
        deadline_unix_ms: u64::MAX,
        state: HostRequestState::ResultReceived,
        attempt: None,
        attempt_history: Vec::new(),
        cancellation_target: None,
        result_digest: Some(RESULT_DIGEST.to_owned()),
        result_response: Some(serde_json::json!({"query": "trace-manifest"})),
        result_evidence: Some(HostRequestEffectEvidence {
            operation_id: OperationIdentity::new(OPERATION_ID).expect("evidence operation id"),
            input_handle: Some(INPUT_HANDLE.to_owned()),
            output_handle: Some(RESULT_DIGEST.to_owned()),
            side_effects: Some("none".to_owned()),
            actual_route: Some("query".to_owned()),
            invoked_operation: Some("local_read".to_owned()),
            adapter_identity: Some("trace-manifest-adapter".to_owned()),
            executor_identity: None,
        }),
        result_lineage: Some(retained_lineage()),
        commit_order: 1,
    }
}

fn result_body() -> HostRequestResultBody {
    HostRequestResultBody {
        wire_id: HOST_REQUEST_RESULT_BODY_WIRE_ID.to_owned(),
        wire_version: HostRequestResultBody::CONTRACT_VERSION,
        operation_id: OPERATION_ID.to_owned(),
        request_sha256: REQUEST_DIGEST.to_owned(),
        result_digest: RESULT_DIGEST.to_owned(),
        response: serde_json::json!({"query": "trace-manifest"}),
        lineage: None,
        attempt: Some(LocalReadAttempt {
            wire_id: eliot_protocol::LOCAL_READ_ATTEMPT_WIRE_ID.to_owned(),
            wire_version: LocalReadAttempt::CONTRACT_VERSION,
            operation_id: OPERATION_ID.to_owned(),
            attempt_id: "trace-manifest-attempt".to_owned(),
            fencing_generation: 1,
            session_id: "trace-manifest-session".to_owned(),
            authority_epoch: test_epoch(),
            scope_id: "trace-manifest-scope".to_owned(),
            facet_method: "eliot.query".to_owned(),
            expires_at_unix_ms: u64::MAX,
            use_budget: 1,
        }),
        evidence: None,
    }
}

/// The production observation, exactly as the two seal sites perform it.
fn observed() -> TraceEvidence {
    TraceEvidence::observed(&durable_record(), Some(&policy_bound_fence()))
}

/// The evidence of a run that also observes the two classes this seal site has
/// no producer for.
fn complete_evidence() -> TraceEvidence {
    let mut evidence = observed();
    evidence.active_view_packet_manifest = Some(VIEW_MANIFEST.to_owned());
    evidence.verifier_result = Some(VERIFIER_RESULT.to_owned());
    evidence
}

fn seal(evidence: &TraceEvidence) -> TraceManifest {
    TraceManifest::seal(
        &test_session(),
        &result_body(),
        &durable_record(),
        None,
        "query",
        evidence,
    )
}

fn sealed_record(manifest: &TraceManifest) -> AuditRecord {
    AuditRecord {
        format_version: 1,
        chain_id: "trace-manifest-chain".to_owned(),
        seq: 1,
        prev_hash: "0".repeat(128),
        kind: AuditEventKind::TRACE_MANIFEST_SEALED.to_owned(),
        lineage: {
            let mut lineage = AuditLineage::empty();
            lineage.operation_id = Some(manifest.operation_id.clone());
            lineage
        },
        event_digest: "f".repeat(64),
        event_body: serde_json::to_value(manifest).expect("manifest serializes"),
        assurance: AuditAssuranceClass::Critical,
        capture_mode: AuditCaptureMode::Full,
        emitted_at_ms: 0,
        current_hash: "a".repeat(128),
    }
}

/// POSITIVE: every I16.12 evidence class this seal observes is bound, and a run
/// observing all of them seals a proof-bearing completion with an empty
/// missing-parts list.
#[test]
fn observed_evidence_classes_bind_and_a_complete_run_seals_verified_complete() {
    let record = durable_record();
    let fence = policy_bound_fence();

    // The production observation reads the durable row, not the submitted body.
    let projected = TraceEvidence::observed(&record, Some(&fence));
    assert_eq!(
        projected.principal.as_deref(),
        Some(PRINCIPAL),
        "the retained authenticated producer reference is the observed principal"
    );
    assert_eq!(
        projected.policy_snapshot.as_deref(),
        Some(POLICY_SNAPSHOT),
        "the retained applicable policy snapshot is the observed policy snapshot"
    );
    assert!(
        projected.active_view_packet_manifest.is_none() && projected.verifier_result.is_none(),
        "this seal site observes neither the Active View/packet manifest nor a verifier \
         result, so neither is invented"
    );

    let manifest = seal(&complete_evidence());

    assert!(
        manifest.missing_parts.is_empty(),
        "a run observing every required class lists no missing part, got {:?}",
        manifest.missing_parts
    );
    assert_eq!(
        manifest.finish,
        TraceFinish::VerifiedComplete,
        "only complete required evidence may claim a completed trace"
    );
    for class in EVIDENCE_CLASSES {
        assert!(
            !manifest.unavailable.contains(&class.to_owned()),
            "{class} is required, so it is never diverted into the unavailable list"
        );
    }
    assert!(
        TraceManifest::find_sealed(&[sealed_record(&manifest)], OPERATION_ID).is_some(),
        "a complete seal is served back on readback"
    );
}

/// REFUSAL: withholding any one of the four required classes names that class
/// as an explicit missing part and degrades the run, forged or substituted
/// evidence does not satisfy a slot, and a forged completion claim that
/// withholds a class is refused rather than served as a complete trace.
#[test]
fn withholding_or_forging_one_evidence_class_degrades_and_is_refused_on_readback() {
    for class in EVIDENCE_CLASSES {
        let mut withheld_evidence = complete_evidence();
        match class {
            "principal" => withheld_evidence.principal = None,
            "policy_snapshot" => withheld_evidence.policy_snapshot = None,
            "active_view_packet_manifest" => {
                withheld_evidence.active_view_packet_manifest = None;
            }
            _ => withheld_evidence.verifier_result = None,
        }
        let withheld = seal(&withheld_evidence);

        assert!(
            withheld.missing_parts.contains(&class.to_owned()),
            "withholding {class} names it as an explicit missing part, got {:?}",
            withheld.missing_parts
        );
        assert_eq!(
            withheld.finish,
            TraceFinish::DegradedNoProof,
            "withholding {class} degrades the run instead of claiming success"
        );
        assert!(
            TraceManifest::find_sealed(&[sealed_record(&withheld)], OPERATION_ID).is_some(),
            "a degraded seal is still served, as the degraded record it is"
        );

        // A forged completion claim that withholds the class is self-
        // contradicting and is refused rather than served as complete.
        let forged = TraceManifest {
            finish: TraceFinish::VerifiedComplete,
            missing_parts: Vec::new(),
            unavailable: Vec::new(),
            ..withheld.clone()
        };
        assert!(
            TraceManifest::find_sealed(&[sealed_record(&forged)], OPERATION_ID).is_none(),
            "a VERIFIED_COMPLETE body withholding {class} is refused on readback"
        );
    }

    // Forged evidence does not satisfy a required slot.
    let mut blank_principal = complete_evidence();
    blank_principal.principal = Some("   ".to_owned());
    assert!(
        seal(&blank_principal)
            .missing_parts
            .contains(&"principal".to_owned()),
        "a blank principal reference does not satisfy the principal slot"
    );

    // A policy-snapshot claim bound to a fence other than the one the
    // authority decision was taken under is a substituted snapshot, and the
    // projection refuses it rather than recording it.
    let substituted_record = HostRequestRecord {
        result_lineage: Some(HostRequestRetainedLineage {
            policy_fence: Some(PolicyFence {
                policy_snapshot_id: "policy-snapshot:someone-elses".to_owned(),
                state_fence: StateFence {
                    authority_epoch: test_epoch(),
                    resource_generation: ResourceGeneration::new(9).expect("generation"),
                    task_revision: None,
                    policy_revision: Some(PolicyRevision::new(2).expect("policy revision")),
                    integration_revision: None,
                },
            }),
            ..retained_lineage()
        }),
        ..durable_record()
    };
    let substituted = TraceEvidence::observed(&substituted_record, Some(&policy_bound_fence()));
    assert_ne!(
        substituted.policy_snapshot.as_deref(),
        Some("policy-snapshot:someone-elses"),
        "a snapshot bound to a different fence is refused as substituted"
    );
    assert_eq!(
        substituted.policy_snapshot.as_deref(),
        Some("4"),
        "the authority decision's own fence supplies the policy identity instead"
    );
    assert!(
        substituted.policy_snapshot_binding.is_none(),
        "a refused claim binds no fence, so it cannot corroborate itself"
    );
    assert!(
        !TraceManifest::seal(
            &test_session(),
            &result_body(),
            &durable_record(),
            None,
            "query",
            &substituted,
        )
        .missing_parts
        .contains(&"policy_snapshot".to_owned()),
        "the substituted claim is never the recorded policy snapshot"
    );

    // A recorded snapshot whose binding fence disagrees with the recorded fence
    // is a substituted reference and does not satisfy the required slot.
    let substituted_binding = TraceManifest::seal(
        &test_session(),
        &result_body(),
        &durable_record(),
        None,
        "query",
        &TraceEvidence {
            policy_snapshot: Some(POLICY_SNAPSHOT.to_owned()),
            policy_snapshot_binding: Some(StateFence {
                authority_epoch: test_epoch(),
                resource_generation: ResourceGeneration::new(9).expect("generation"),
                task_revision: None,
                policy_revision: Some(PolicyRevision::new(2).expect("policy revision")),
                integration_revision: None,
            }),
            ..complete_evidence()
        },
    );
    assert!(
        substituted_binding
            .missing_parts
            .contains(&"policy_snapshot".to_owned()),
        "a policy snapshot bound to a foreign fence does not satisfy the slot"
    );

    for class in EVIDENCE_CLASSES {
        assert!(
            TRACE_MANIFEST_REQUIRED_SLOTS.contains(&class),
            "the required set declares {class}"
        );
    }
    assert_eq!(
        seal(&complete_evidence()).format_version,
        TRACE_MANIFEST_FORMAT_VERSION,
        "the fixture seals the current format version"
    );
}
