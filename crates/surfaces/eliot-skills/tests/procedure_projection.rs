#![allow(clippy::expect_used)]

use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ContractId, ResourceGeneration, StateFence, TaskId, TaskRevision,
    TransactionSequence,
};
use eliot_contracts::{ClockReading, ProductId, RequestId, SourceId};
use eliot_receipts::{
    AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling, ReceiptCore,
    ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding, SessionBinding, TaskBinding,
    VerifierBinding, WorkScopeBinding, WorkScopeId,
};
use eliot_skills::{
    CANDIDATE_LIFECYCLE_STATE, GENERATED_CANDIDATE_SOURCE,
    GOVERNED_PROCEDURE_PROJECTION_SCHEMA_VERSION, GovernedProcedureProjection, InertAsset,
    ProcedureDefinition, ProcedureEvidence, ProcedureState, ProcedureVerifier,
    SafetyPrivacyDisclosure, TargetDisposition, TargetProfile,
    project_governed_procedure_to_portable_skill_candidates,
};

fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}

fn receipt(procedure_revision: &str, state_fence: StateFence) -> eliot_skills::ReceiptClaim {
    let request_id = RequestId::new("request-1").expect("request id");
    let task_id = TaskId::new("task-1").expect("task id");
    let metadata = eliot_receipts::RequestMetadata {
        request_id: request_id.clone(),
        session_id: Some(eliot_contracts::SessionId::new("session-1").expect("session id")),
        task_id: Some(task_id),
        product_id: ProductId::new("product-1").expect("product id"),
        source_id: SourceId::new("source-1").expect("source id"),
        state_fence: state_fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(10),
            known_time_ms: Some(11),
            transaction_sequence: Some(TransactionSequence::genesis()),
            monotonic_ns: Some(12),
        },
    };
    let verifier_artifact_id = ArtifactId::new("verifier-artifact-1").expect("artifact id");
    let rollback_artifact_id = ArtifactId::new("rollback-artifact-1").expect("artifact id");
    let core = ReceiptCore {
        contract: eliot_receipts::contract_identity().expect("receipt contract"),
        kind: ReceiptKind::Verification,
        work_scope: WorkScopeBinding {
            scope_id: WorkScopeId::new("scope-1").expect("scope id"),
            product_id: metadata.product_id.clone(),
            resource_generation: ResourceGeneration::genesis(),
            state_fence: state_fence.clone(),
        },
        task: Some(TaskBinding {
            task_id: TaskId::new("task-1").expect("task id"),
            task_revision: TaskRevision::genesis(),
            state_fence: state_fence.clone(),
        }),
        session: Some(SessionBinding {
            session_id: eliot_contracts::SessionId::new("session-1").expect("session id"),
            authority_epoch: AuthorityEpoch::genesis(),
            state_fence: state_fence.clone(),
        }),
        causal: CausalBinding {
            state_fence: state_fence.clone(),
            transaction_sequence: TransactionSequence::genesis(),
            parent_receipt_id: None,
            predecessor_receipt_ids: Vec::new(),
        },
        request: RequestBinding {
            metadata,
            state_fence: state_fence.clone(),
        },
        operation: OperationBinding {
            operation_id: eliot_contracts::OperationId::new("operation-1").expect("operation id"),
            request_id,
            idempotency_key: "accept-procedure".to_owned(),
            operation_kind: "procedure.accept".to_owned(),
            effect: EffectClass::Read,
            state_fence: state_fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("authority-1").expect("authority id"),
            authority_owner: "governor.skill".to_owned(),
            authority_epoch: AuthorityEpoch::genesis(),
            state_fence: state_fence.clone(),
            allowed_effect: EffectClass::Read,
            proof_ceiling: ProofCeiling::ScopedVerification,
        },
        artifacts: vec![
            eliot_receipts::ArtifactBinding {
                artifact_id: verifier_artifact_id.clone(),
                sha256: eliot_receipts::sha256_hex(b"accepted-procedure"),
                role: ReceiptKind::Artifact,
                source_revision: Some(procedure_revision.to_owned()),
            },
            eliot_receipts::ArtifactBinding {
                artifact_id: rollback_artifact_id,
                sha256: eliot_receipts::sha256_hex(b"rollback-procedure"),
                role: ReceiptKind::Artifact,
                source_revision: Some(procedure_revision.to_owned()),
            },
        ],
        verifier: Some(VerifierBinding {
            verifier_id: ContractId::new("procedure-verifier").expect("verifier id"),
            verifier_revision: eliot_contracts::ContractVersion::new(1, 0, 0),
            artifact_ids: vec![verifier_artifact_id],
            proof_ceiling: ProofCeiling::ScopedVerification,
            state_fence,
        }),
        problem: None,
        coordination: None,
        disposition: ReceiptDisposition::Success {
            proof: ProofCeiling::ScopedVerification,
        },
    };
    let envelope = ReceiptEnvelope::issue(core).expect("accepted receipt");
    eliot_skills::ReceiptClaim {
        evidence_ref: "receipt-evidence-1".to_owned(),
        envelope,
    }
}

fn procedure() -> GovernedProcedureProjection {
    let state_fence = fence();
    let acceptance_receipt = receipt("revision-1", state_fence.clone());
    let mut projection = GovernedProcedureProjection {
        schema_version: GOVERNED_PROCEDURE_PROJECTION_SCHEMA_VERSION.to_owned(),
        procedure_id: "procedure-1".to_owned(),
        procedure_revision: "revision-1".to_owned(),
        procedure_digest: "0".repeat(64),
        state: ProcedureState::Accepted,
        state_fence: state_fence.clone(),
        work_scope: acceptance_receipt.envelope.core.work_scope.clone(),
        task: acceptance_receipt
            .envelope
            .core
            .task
            .clone()
            .expect("task binding"),
        acceptance_receipt,
        definition: ProcedureDefinition {
            name: "bounded procedure".to_owned(),
            purpose: "make one bounded change".to_owned(),
            trigger: "a bounded change is requested".to_owned(),
            action: "apply the reviewed change".to_owned(),
            applies_when: vec!["scope is exact".to_owned()],
            where_not_apply: vec!["scope is stale".to_owned()],
            required_inputs: vec!["reviewed input".to_owned()],
            ordered_steps: vec!["review".to_owned(), "apply".to_owned()],
            expected_outputs: vec!["candidate artifact".to_owned()],
            stop_conditions: vec!["stop on mismatch".to_owned()],
            required_writebacks: vec!["NONE".to_owned()],
            escalation: "return the owner challenge".to_owned(),
            challenge: "show the exact gap".to_owned(),
            rollback_or_recovery: "restore the prior artifact".to_owned(),
            required_tools: vec![eliot_skills::VersionedRequirement {
                name: "reviewer".to_owned(),
                version: "1".to_owned(),
            }],
            required_capabilities: vec![eliot_skills::VersionedRequirement {
                name: "review".to_owned(),
                version: "1".to_owned(),
            }],
        },
        evidence: ProcedureEvidence {
            source_refs: vec!["source-1".to_owned()],
            receipt_refs: vec!["receipt-evidence-1".to_owned()],
            applicability_refs: vec!["applicability-1".to_owned()],
            counterexample_refs: vec!["counterexample-1".to_owned()],
            negative_trigger_refs: vec!["negative-trigger-1".to_owned()],
            verifier_artifact_refs: vec!["verifier-artifact-1".to_owned()],
            rollback_artifact_ref: "rollback-artifact-1".to_owned(),
        },
        verifier: ProcedureVerifier {
            verifier_ref: "procedure-verifier".to_owned(),
            verifier_revision: "1.0.0".to_owned(),
            artifact_refs: vec!["verifier-artifact-1".to_owned()],
        },
        safety_privacy_disclosure: SafetyPrivacyDisclosure {
            safety_owner_ref: "safety-owner".to_owned(),
            safety_evidence_refs: vec!["safety-1".to_owned()],
            privacy_owner_ref: "privacy-owner".to_owned(),
            privacy_evidence_refs: vec!["privacy-1".to_owned()],
            disclosure_owner_ref: "disclosure-owner".to_owned(),
            disclosure_evidence_refs: vec!["disclosure-1".to_owned()],
        },
        assets: vec![InertAsset {
            asset_ref: "asset-1".to_owned(),
            sha256: eliot_receipts::sha256_hex(b"asset"),
            role: "reference".to_owned(),
            executable: false,
        }],
    };
    projection.procedure_digest = projection.expected_digest().expect("procedure digest");
    projection
}

fn target(target_id: &str, fingerprint: &str, available: bool) -> TargetProfile {
    TargetProfile {
        target_id: target_id.to_owned(),
        host: "rust-host".to_owned(),
        profile: "safe".to_owned(),
        fingerprint: fingerprint.to_owned(),
        available_tools: if available {
            vec![eliot_skills::VersionedRequirement {
                name: "reviewer".to_owned(),
                version: "1".to_owned(),
            }]
        } else {
            Vec::new()
        },
        available_capabilities: if available {
            vec![eliot_skills::VersionedRequirement {
                name: "review".to_owned(),
                version: "1".to_owned(),
            }]
        } else {
            Vec::new()
        },
    }
}

#[test]
fn accepted_projection_maps_each_target_deterministically() {
    let targets = [
        target("unsupported", &"2".repeat(64), false),
        target("supported", &"1".repeat(64), true),
    ];
    let result = project_governed_procedure_to_portable_skill_candidates(&procedure(), &targets)
        .expect("projection");
    let reversed = project_governed_procedure_to_portable_skill_candidates(
        &procedure(),
        &[targets[1].clone(), targets[0].clone()],
    )
    .expect("permuted projection");
    assert_eq!(result, reversed);
    assert_eq!(result.candidates.len(), 1);
    assert_eq!(result.candidates[0].source, GENERATED_CANDIDATE_SOURCE);
    assert_eq!(
        result.candidates[0].lifecycle_state,
        CANDIDATE_LIFECYCLE_STATE
    );
    assert!(result.candidates[0].candidate_only);
    assert!(!result.candidates[0].activation_applied);
    assert_eq!(result.target_dispositions[0].target_id, "supported");
    assert!(matches!(
        result.target_dispositions[0].disposition,
        TargetDisposition::Compatible
    ));
    assert_eq!(result.target_dispositions[1].target_id, "unsupported");
    assert!(matches!(
        result.target_dispositions[1].disposition,
        TargetDisposition::Unsupported { .. }
    ));
}

#[test]
fn raw_non_accepted_state_is_rejected_without_candidate_fallback() {
    let mut projection = procedure();
    projection.state = ProcedureState::Quarantined;
    assert!(matches!(
        project_governed_procedure_to_portable_skill_candidates(
            &projection,
            &[target("supported", &"1".repeat(64), true)]
        ),
        Err(eliot_skills::ProcedureProjectionError::NotAccepted(
            ProcedureState::Quarantined
        ))
    ));
}

#[test]
fn candidate_validator_rejects_recomputed_quarantined_procedure() {
    let mut candidate = project_governed_procedure_to_portable_skill_candidates(
        &procedure(),
        &[target("supported", &"1".repeat(64), true)],
    )
    .expect("projection")
    .candidates
    .pop()
    .expect("candidate");
    candidate.procedure.state = ProcedureState::Quarantined;
    candidate.procedure.procedure_digest = candidate
        .procedure
        .expected_digest()
        .expect("quarantined procedure digest");
    let candidate_digest = eliot_skills::canonical_digest(&(
        &candidate.procedure.procedure_digest,
        &candidate.target.target_id,
        &candidate.target.fingerprint,
    ))
    .expect("candidate digest");
    candidate.candidate_id = format!("skill-candidate:{candidate_digest}");
    assert_eq!(
        candidate.validate(),
        Err(eliot_skills::ProcedureProjectionError::NotAccepted(
            ProcedureState::Quarantined
        ))
    );
}

fn reissue_receipt(projection: &mut GovernedProcedureProjection) {
    let core = projection.acceptance_receipt.envelope.core.clone();
    projection.acceptance_receipt.envelope = ReceiptEnvelope::issue(core).expect("receipt");
    projection.procedure_digest = projection.expected_digest().expect("procedure digest");
}

#[test]
fn receipt_verifier_identity_and_artifacts_must_match_declared_verifier() {
    let mut projection = procedure();
    projection
        .acceptance_receipt
        .envelope
        .core
        .verifier
        .as_mut()
        .expect("receipt verifier")
        .verifier_id = ContractId::new("other-verifier").expect("verifier id");
    reissue_receipt(&mut projection);
    assert_eq!(
        projection.validate(),
        Err(
            eliot_skills::ProcedureProjectionError::ReceiptBindingMismatch {
                field: "acceptance_receipt.verifier.verifier_id",
            }
        )
    );

    let mut projection = procedure();
    projection
        .acceptance_receipt
        .envelope
        .core
        .verifier
        .as_mut()
        .expect("receipt verifier")
        .artifact_ids = vec![ArtifactId::new("rollback-artifact-1").expect("artifact id")];
    reissue_receipt(&mut projection);
    assert_eq!(
        projection.validate(),
        Err(
            eliot_skills::ProcedureProjectionError::ReceiptBindingMismatch {
                field: "acceptance_receipt.verifier.artifact_ids",
            }
        )
    );
}

#[test]
fn receipt_must_bind_the_declared_rollback_artifact() {
    let mut projection = procedure();
    projection
        .acceptance_receipt
        .envelope
        .core
        .artifacts
        .retain(|artifact| artifact.artifact_id.as_str() != "rollback-artifact-1");
    reissue_receipt(&mut projection);
    assert_eq!(
        projection.validate(),
        Err(
            eliot_skills::ProcedureProjectionError::ReceiptBindingMismatch {
                field: "acceptance_receipt.rollback_artifact",
            }
        )
    );
}

#[test]
fn receipt_fence_and_identity_tampering_fail_closed() {
    let mut projection = procedure();
    projection.state_fence = StateFence::new(
        AuthorityEpoch::new(2).expect("epoch"),
        ResourceGeneration::genesis(),
    );
    assert!(matches!(
        projection.validate(),
        Err(
            eliot_skills::ProcedureProjectionError::ReceiptBindingMismatch { .. }
                | eliot_skills::ProcedureProjectionError::IdentityMismatch,
        )
    ));

    let mut projection = procedure();
    projection.procedure_id = "changed".to_owned();
    assert_eq!(
        projection.validate(),
        Err(eliot_skills::ProcedureProjectionError::IdentityMismatch)
    );
}

#[test]
fn executable_asset_and_missing_safety_are_rejected() {
    let mut projection = procedure();
    projection.assets[0].executable = true;
    assert!(matches!(
        projection.validate(),
        Err(eliot_skills::ProcedureProjectionError::CandidateOnlyViolation { .. })
    ));

    let mut projection = procedure();
    projection
        .safety_privacy_disclosure
        .safety_owner_ref
        .clear();
    assert!(matches!(
        projection.validate(),
        Err(eliot_skills::ProcedureProjectionError::InvalidField {
            field: "safety.owner_ref",
            ..
        })
    ));
}

#[test]
fn candidate_wire_cannot_be_minted_as_a_valid_admitted_package() {
    let mut candidate = project_governed_procedure_to_portable_skill_candidates(
        &procedure(),
        &[target("supported", &"1".repeat(64), true)],
    )
    .expect("projection")
    .candidates
    .pop()
    .expect("candidate");
    candidate.lifecycle_state = "ACTIVE".to_owned();
    assert!(matches!(
        candidate.validate(),
        Err(eliot_skills::ProcedureProjectionError::CandidateOnlyViolation { .. })
    ));
}

#[test]
fn candidate_mapping_fields_cannot_be_rewritten_independently() {
    let mut candidate = project_governed_procedure_to_portable_skill_candidates(
        &procedure(),
        &[target("supported", &"1".repeat(64), true)],
    )
    .expect("projection")
    .candidates
    .pop()
    .expect("candidate");
    candidate.behavior.action = "unreviewed action".to_owned();
    assert_eq!(
        candidate.validate(),
        Err(eliot_skills::ProcedureProjectionError::IdentityMismatch)
    );
}
