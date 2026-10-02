//! Issue #262, D-1: the shared `recall_candidate.payload` column contract.
//!
//! `payload: Value` is PERMITTED INERT EVIDENCE CONTENT — that is issue #937's
//! distinction, and it is preserved here unchanged. What was undecided and is
//! now typed is the Eliot CONTROL-ENVELOPE vocabulary that rides inside that
//! escape: the seven store-projection keys plus the ranking signals, all read by
//! `canonical_store.rs` for every one of the six record-type arms through
//! `searchable_field` / `payload_bool` / `payload_i32`. A wrong-typed control
//! field used to be silently dropped, and the row then ranked as if the record
//! had stated no cue at all.
//!
//! One POSITIVE case and one REFUSAL case per migrated arm, all six arms in this
//! file. The refusal is the existing typed
//! [`eliot_types::WriteRejectReason`] surfaced as
//! [`eliot_engine::EngineError::WriteRejected`] — never a string verdict, never
//! a boolean. A partial migration is the defect this file exists to prevent.
//!
//! Nothing here relaxes an existing oracle. It only adds assertions.

use eliot_engine::{EngineError, WriteAdmissionService};
use eliot_types::{
    AgentId, ClaimCardInput, ClaimId, ClaimProposeCommand, CommandContext, EpistemicStatus,
    EvidenceAtomInput, EvidenceId, EvidenceIngestCommand, FailureRecordCommand, LifecycleStatus,
    ProjectId, RecallCandidatePayload, RecallPayloadViolation, SemanticCommand,
    SourceSnapshotInput, TaintClass, ToolObservationRecordCommand, VerificationId,
    VerificationRecordCommand, VerificationResult, VerificationRunInput, Visibility, WriteId,
    WriteRejectReason,
};
use serde_json::{Value, json};

fn context() -> CommandContext {
    CommandContext {
        write_id: WriteId::new_v7(),
        agent_id: AgentId::new_v7(),
        session_id: None,
        project_id: ProjectId::new_v7(),
        task_id: None,
        scope: "recall-column-contract".to_owned(),
        authority: "local-test".to_owned(),
        visibility: Visibility::Internal,
        taint: TaintClass::LocalVerified,
        lifecycle_status: LifecycleStatus::Active,
    }
}

/// A well-typed payload for every migrated arm: every declared control-envelope
/// member present at its contract type, plus inert evidence content beside it.
fn typed_payload() -> Value {
    json!({
        "path": "src/core/retrieval.rs",
        "symbol": "paged_projection",
        "error": "fixed-candidate-limit",
        "task_class": "retrieval-certification",
        "concept_id": "concept:progressive-disclosure",
        "concept_refs": ["concept:recall", "concept:scope"],
        "subsystem": "core",
        "subsystem_concept_refs": ["concept:core"],
        "changed_outcome": true,
        "beneficial_use_count": 3,
        "harmful": false,
        "repeated": false,
        "distraction": false,
        "cue_bindings": [],
        "nested": {"free": "form"},
    })
}

/// An inert-evidence-only payload: no control member stated at all. Measured
/// against `crates/eliot-store/tests/memory_retrieval.rs:669`, which writes
/// exactly this shape on the failure arm.
fn inert_payload() -> Value {
    json!({"cause": "граница кодировки", "cue_bindings": []})
}

/// Arm 1 — `failure_fingerprint`, the arm this issue is named for.
fn failure_arm(payload: Value) -> SemanticCommand {
    SemanticCommand::FailureRecord(FailureRecordCommand {
        context: context(),
        fingerprint: "fp-contract".to_owned(),
        summary: "typed failure fingerprint".to_owned(),
        payload,
    })
}

/// Arm 2 — `evidence_atom`.
fn evidence_arm(payload: Value) -> SemanticCommand {
    SemanticCommand::EvidenceIngest(EvidenceIngestCommand {
        context: context(),
        source: SourceSnapshotInput {
            source_id: "src-contract".to_owned(),
            uri: "file:src/core/retrieval.rs".to_owned(),
            authority: "local-test".to_owned(),
            content_hash: "0".repeat(64),
            excerpt: "typed evidence atom".to_owned(),
        },
        evidence: EvidenceAtomInput {
            evidence_id: EvidenceId::new_v7(),
            source_id: "src-contract".to_owned(),
            summary: "typed evidence atom".to_owned(),
            payload,
        },
    })
}

/// Arm 3 — `claim_card`.
fn claim_arm(payload: Value) -> SemanticCommand {
    SemanticCommand::ClaimPropose(ClaimProposeCommand {
        context: context(),
        claim: ClaimCardInput {
            claim_id: ClaimId::new_v7(),
            statement: "typed claim card".to_owned(),
            status: EpistemicStatus::Supported,
            payload,
        },
    })
}

/// Arm 4 — `verification_run`.
fn verification_arm(payload: Value) -> SemanticCommand {
    SemanticCommand::VerificationRecord(VerificationRecordCommand {
        context: context(),
        verification: VerificationRunInput {
            verification_id: VerificationId::new_v7(),
            claim_id: None,
            verifier: "local-test".to_owned(),
            result: VerificationResult::Passed,
            summary: "typed verification run".to_owned(),
            payload,
        },
    })
}

/// Arm 5 — `tool_observation`.
fn observation_arm(payload: Value) -> SemanticCommand {
    SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: context(),
        tool_name: "local-test".to_owned(),
        observation: "typed tool observation".to_owned(),
        payload,
    })
}

/// Arm 6 — the UL artifact arm. Its payload is the `receipt_body` the store's
/// artifact branch reads (`canonical_store.rs` `receipt_body` handling), built
/// here in the exact shape `WriteAdmissionService::admit_ul_artifact_batch_record`
/// writes it (`receipt_kind` + `receipt_body`).
fn artifact_arm(receipt_body: Value) -> SemanticCommand {
    observation_arm(json!({
        "receipt_kind": "module_card",
        "receipt_body": receipt_body,
        "writer_path": "ul_artifact_writer_actor",
    }))
}

fn typed_receipt_body() -> Value {
    json!({
        "card_id": "card-contract",
        "project_id": ProjectId::new_v7().to_string(),
        "path": "src/core/retrieval.rs",
        "body_md": "typed module card",
        "concept_id": "concept:progressive-disclosure",
        "concept_refs": ["concept:recall"],
        "subsystem_concept_refs": ["concept:core"],
        "source_refs": ["file:src/core/retrieval.rs"],
        "beneficial_use_count": 2,
    })
}

/// The six arms, in the order `canonical_store.rs::envelope_projection_rows`
/// projects them.
fn arms() -> Vec<(&'static str, fn(Value) -> SemanticCommand)> {
    vec![
        ("failure_fingerprint", failure_arm),
        ("evidence_atom", evidence_arm),
        ("claim_card", claim_arm),
        ("verification_run", verification_arm),
        ("tool_observation", observation_arm),
        ("ul_artifact_receipt_body", artifact_arm),
    ]
}

/// POSITIVE, all six arms: a payload whose declared control members are stated
/// at their contract types is admitted, and permitted inert evidence content is
/// admitted unchanged.
#[test]
fn every_migrated_arm_admits_typed_and_inert_payloads() {
    let service = WriteAdmissionService;
    for (record_type, arm) in arms() {
        assert!(
            service.admit(&arm(typed_payload())).is_ok(),
            "{record_type} must admit the typed shared column contract payload"
        );
        assert!(
            service.admit(&arm(inert_payload())).is_ok(),
            "{record_type} must admit permitted inert evidence content"
        );
    }
}

/// POSITIVE, all six arms: the UL artifact arm's `receipt_body`, which is where
/// the store's artifact branch actually reads the contract from.
#[test]
fn the_artifact_arm_admits_a_typed_receipt_body() {
    let service = WriteAdmissionService;
    assert!(
        service.admit(&artifact_arm(typed_receipt_body())).is_ok(),
        "the UL artifact arm must admit a typed receipt_body"
    );
}

/// REFUSAL, all six arms: a declared control-envelope member stated with the
/// wrong JSON type is `WriteRejectReason::InvalidEnvelope` surfaced as
/// `EngineError::WriteRejected`.
#[test]
fn every_migrated_arm_refuses_a_wrong_typed_control_field() {
    let service = WriteAdmissionService;
    for (field, wrong) in [
        ("path", json!(7)),
        ("symbol", json!({"nested": true})),
        ("error", json!(["a"])),
        ("task_class", json!(false)),
        ("concept_id", json!(7)),
        ("concept_refs", json!("concept:recall")),
        ("subsystem", json!(3)),
        ("subsystem_concept_refs", json!([1, 2])),
        ("changed_outcome", json!("true")),
        ("beneficial_use_count", json!("3")),
        ("harmful", json!(1)),
    ] {
        let mut payload = typed_payload();
        payload
            .as_object_mut()
            .expect("typed_payload is an object")
            .insert(field.to_owned(), wrong);
        for (record_type, arm) in arms() {
            match service.admit(&arm(payload.clone())) {
                Ok(_) => panic!("{record_type} must refuse a wrong-typed {field}"),
                Err(EngineError::WriteRejected(reason)) => assert!(
                    reason.starts_with(&format!("{:?}", WriteRejectReason::InvalidEnvelope)),
                    "{record_type}/{field} refused with {reason}, not InvalidEnvelope"
                ),
                Err(other) => {
                    panic!("{record_type}/{field} refused with {other}, not WriteRejected")
                }
            }
        }
    }
}

/// REFUSAL, all six arms: a payload that is neither an object nor `null` has no
/// member set to project — `MissingRequiredField`.
#[test]
fn every_migrated_arm_refuses_a_non_object_payload_as_missing_required_field() {
    let service = WriteAdmissionService;
    for (record_type, arm) in arms() {
        match service.admit(&arm(json!(["not", "an", "object"]))) {
            Ok(_) => panic!("{record_type} must refuse a non-object payload"),
            Err(EngineError::WriteRejected(reason)) => assert!(
                reason.starts_with(&format!("{:?}", WriteRejectReason::MissingRequiredField)),
                "{record_type} refused with {reason}, not MissingRequiredField"
            ),
            Err(other) => panic!("{record_type} refused with {other}, not WriteRejected"),
        }
    }
}

/// REFUSAL, the artifact arm: a `receipt_body` whose `path` is not a string is
/// refused rather than projected as a module card with no path.
#[test]
fn the_artifact_arm_refuses_a_wrong_typed_receipt_body_field() {
    let service = WriteAdmissionService;
    let mut receipt_body = typed_receipt_body();
    receipt_body
        .as_object_mut()
        .expect("typed_receipt_body is an object")
        .insert("path".to_owned(), json!(7));
    match service.admit(&artifact_arm(receipt_body)) {
        Ok(_) => panic!("the UL artifact arm must refuse a numeric receipt_body.path"),
        Err(EngineError::WriteRejected(reason)) => assert!(
            reason.starts_with(&format!("{:?}", WriteRejectReason::InvalidEnvelope)),
            "refused with {reason}, not InvalidEnvelope"
        ),
        Err(other) => panic!("refused with {other}, not WriteRejected"),
    }
}

/// JSON `null` is "no members stated", not a wrong type. The store's existing
/// byte-preservation oracle writes `payload: Value::Null`
/// (`crates/eliot-store/src/payload_byte_preservation.rs`), so this must hold.
#[test]
fn a_null_payload_is_the_empty_contract_not_a_refusal() {
    let service = WriteAdmissionService;
    for (record_type, arm) in arms() {
        assert!(
            service.admit(&arm(Value::Null)).is_ok(),
            "{record_type} must admit a null payload as the empty contract"
        );
    }
}

/// The contract is closed over the control-envelope vocabulary, and inert
/// evidence survives the round trip byte-for-byte.
#[test]
fn the_contract_is_closed_and_round_trips_inert_evidence() {
    let wire = typed_payload();
    let contract =
        RecallCandidatePayload::from_wire(&wire).expect("typed_payload satisfies the contract");

    assert_eq!(contract.cues.path.as_deref(), Some("src/core/retrieval.rs"));
    assert_eq!(contract.cues.symbol.as_deref(), Some("paged_projection"));
    assert_eq!(
        contract.cues.error.as_deref(),
        Some("fixed-candidate-limit")
    );
    assert_eq!(
        contract.cues.task_class.as_deref(),
        Some("retrieval-certification")
    );
    assert_eq!(
        contract.concepts.concept_id.as_deref(),
        Some("concept:progressive-disclosure")
    );
    assert_eq!(
        contract.concepts.concept_refs.as_deref(),
        Some(["concept:recall".to_owned(), "concept:scope".to_owned()].as_slice())
    );
    assert_eq!(contract.ranking.changed_outcome, Some(true));
    assert_eq!(contract.ranking.beneficial_use_count, Some(3));

    // Inert evidence is carried, never interpreted as a control member.
    assert_eq!(contract.evidence["cue_bindings"], json!([]));
    assert_eq!(contract.evidence["nested"]["free"], json!("form"));
    assert_eq!(contract.evidence.get("path"), None);

    // Round trip is byte-identical.
    assert_eq!(contract.to_wire(), wire);
}

/// A closed control-envelope struct refuses an undeclared member sitting next
/// to the declared ones. That is what makes this a contract and not a bag.
#[test]
fn a_closed_control_envelope_struct_refuses_an_undeclared_member() {
    assert!(
        serde_json::from_value::<eliot_types::RecallCueFields>(json!({
            "path": "src/core/retrieval.rs",
            "declared_but_not_contracted": true,
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<eliot_types::RecallRankingFields>(json!({
            "changed_outcome": true,
            "harmful": false,
            "repeated": false,
            "distraction": false,
            "beneficial_use_count": 3,
            "utility_score": 0.9,
        }))
        .is_err()
    );
}

/// The two refusals are distinguished by type, not by string.
#[test]
fn violations_are_typed_and_content_free() {
    assert_eq!(
        RecallCandidatePayload::from_wire(&json!("a string")),
        Err(RecallPayloadViolation::NotAnObject)
    );
    assert_eq!(
        RecallCandidatePayload::from_wire(&json!({"path": 7})),
        Err(RecallPayloadViolation::FieldWrongType {
            field: "path",
            expected: "string",
        })
    );
    assert_eq!(
        RecallCandidatePayload::from_wire(&json!({"beneficial_use_count": -1})),
        Err(RecallPayloadViolation::FieldWrongType {
            field: "beneficial_use_count",
            expected: "integer",
        })
    );
    assert_eq!(
        RecallCandidatePayload::from_wire(&json!({"concept_refs": [1]})),
        Err(RecallPayloadViolation::FieldWrongType {
            field: "concept_refs",
            expected: "array",
        })
    );
}

/// The declared owner of the seven keys: an ABSENT control field is `None`,
/// never an empty string, and the store's own absent-means-zero rule is kept.
#[test]
fn an_absent_control_field_is_absent_not_empty() {
    let contract =
        RecallCandidatePayload::from_wire(&json!({})).expect("an empty object is a valid payload");
    assert_eq!(contract.cues.path, None);
    assert_eq!(contract.concepts.concept_id, None);
    assert_eq!(contract.ranking.beneficial_use_count, None);
    assert_eq!(contract.cue_text(), String::new());
    assert_eq!(contract.concept_text(), String::new());
    assert_eq!(contract.claim_concept_text(), String::new());
    assert_eq!(contract.artifact_concept_text(), String::new());
    assert_eq!(contract.prior_beneficial_use(), 0);
    assert_eq!(contract.known_decision_delta(), 0);
    assert!(!contract.harm_signal());
    assert!(!contract.repetition_signal());
    assert!(!contract.distraction_signal());
}

/// The store's cue and concept projections are unchanged by the migration: the
/// same four keys joined by one space, and reference arrays rendered as the
/// store already rendered them.
#[test]
fn the_cue_and_concept_projections_are_unchanged() {
    let contract = RecallCandidatePayload::from_wire(&json!({
        "path": "src/core/retrieval.rs",
        "symbol": "paged_projection",
        "error": "",
        "task_class": "retrieval-certification",
        "concept_id": "concept:recall",
        "concept_refs": ["a", "b"],
        "subsystem": "core",
        "subsystem_concept_refs": ["c"],
    }))
    .expect("the payload satisfies the contract");
    // The empty `error` is dropped exactly as `joined_search_fields` dropped it.
    assert_eq!(
        contract.cue_text(),
        "src/core/retrieval.rs paged_projection retrieval-certification"
    );
    assert_eq!(contract.concept_text(), "concept:recall [\"a\",\"b\"]");
    assert_eq!(
        contract.claim_concept_text(),
        "concept:recall [\"a\",\"b\"] core"
    );
    assert_eq!(
        contract.artifact_concept_text(),
        "concept:recall [\"a\",\"b\"] [\"c\"]"
    );
}
