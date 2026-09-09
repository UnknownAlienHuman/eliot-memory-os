//! Adapted from the A03 full `FailureInput` fixture with public dependencies only.
#![allow(
    clippy::too_many_lines,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::missing_panics_doc
)]
use eliot_contracts::{
    ArtifactId, AuthorityEpoch, ClockReading, ContractId, ContractVersion, OperationId, ProductId,
    RequestId, ResourceGeneration, SourceId, StateFence, TaskId, TaskRevision, TransactionSequence,
    sha256_hex,
};
use eliot_dreamer_contracts::curation::{FailurePayload, TargetEvidence};
use eliot_dreamer_contracts::*;
use eliot_dreamer_failure::FailurePolicy;
use eliot_evidence::{
    Assertability, EpistemicStatus, EvidenceAuthority, EvidenceCoverage, EvidenceEnvelope,
    EvidenceFreshness, Provenance,
};
use eliot_receipts::{
    AuthorityBinding, CausalBinding, EffectClass, OperationBinding, ProofCeiling, ReceiptCore,
    ReceiptDisposition, ReceiptEnvelope, ReceiptKind, RequestBinding, TaskBinding, VerifierBinding,
    WorkScopeBinding, WorkScopeId, contract_identity,
};

fn sample_job() -> DreamJobInput {
    DreamJobInput {
        schema_version: 1,
        job_class: JobClass::Curation,
        requester: Requester {
            origin: RequesterOrigin::Human,
            principal: "alice".into(),
            session: None,
        },
        operation_id: "op-1".into(),
        idempotency_key: "idem-1".into(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        privacy_profile: "local_only".into(),
        contract_ref: "contract-1".into(),
        policy_ref: "policy-1".into(),
        budget: BudgetLimits {
            input_bytes: Some(1_048_576),
            output_bytes: Some(1_048_576),
            source_width: Some(512),
            reference_width: Some(512),
            model_calls: Some(4),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(10_000),
            work_fan_out: Some(2),
            report_bytes: Some(1_048_576),
            max_stu: Some(10),
        },
        deadline_ms: None,
        frozen_manifest_digest: "0".repeat(64),
    }
}
fn valid_receipt(draft_digest: &str, state_fence: StateFence) -> ValidationReceipt {
    ValidationReceipt {
        schema_version: 1,
        validator_contract: "a05-validator".into(),
        validator_policy: "policy-7".into(),
        job_id: "job-1".into(),
        draft_digest: draft_digest.into(),
        bundle_digest: sha256_hex(b"bundle"),
        manifest_digest: sha256_hex(b"manifest"),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        input_digest: sha256_hex(b"validator-input"),
        output_digest: sha256_hex(b"validator-output"),
        terminal_disposition: "accepted".into(),
        proof_ceiling: "candidate-only".into(),
        state_fence,
        preservation_digest: sha256_hex(b"preservation"),
        budget_digest: sha256_hex(b"budget"),
    }
}
fn sample_payload(_kind: CurationKind) -> CurationPayload {
    CurationPayload::Failure(FailurePayload {
        fingerprint: "fp-1".into(),
        signature: "sig-1".into(),
        target_evidence: TargetEvidence {
            targets: vec!["a".into(), "b".into(), "ab".into()],
            evidence_refs: vec!["e-1".into()],
        },
    })
}
fn sample_binding() -> ScreenBinding {
    ScreenBinding {
        request_id: RequestId::new("req-1").unwrap(),
        receipt_id: eliot_contracts::ReceiptId::new("rcpt-1").unwrap(),
        screened_targets: vec!["a".into(), "b".into(), "ab".into()],
        source_snapshot: "snap-1".into(),
        source_revision: "rev-1".into(),
        profile: "default".into(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        state: ScreenState::Eligible,
        result_digest: "a".repeat(64),
        item_digest: "b".repeat(64),
    }
}
fn preservation() -> eliot_dreamer_contracts::relation::RelationPreservation {
    eliot_dreamer_contracts::relation::RelationPreservation {
        verdicts: RelationPreservationDimension::all()
            .iter()
            .copied()
            .map(|dimension| RelationPreservationVerdict {
                dimension,
                passed: true,
                known: true,
                note: "retained".into(),
            })
            .collect(),
    }
}

pub(crate) fn sealed_policy() -> FailurePolicy {
    let mut policy = FailurePolicy::new("test-policy");
    policy.seal().expect("policy fixture seals");
    policy
}
fn fence() -> StateFence {
    StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
}
fn distinct_fence(generation: u64) -> StateFence {
    StateFence::new(
        AuthorityEpoch::genesis(),
        ResourceGeneration::new(generation).unwrap(),
    )
}
fn digest(value: &[u8]) -> String {
    sha256_hex(value)
}
fn action_receipt(
    operation: &FailureOperation,
    disposition: ReceiptDisposition,
) -> ReceiptEnvelope {
    let state_fence = operation.state_fence.clone();
    let request_id = RequestId::new(operation.request_id.clone()).unwrap();
    let operation_id = OperationId::new(operation.operation_id.clone()).unwrap();
    let task_id = TaskId::new(operation.task_id.clone()).unwrap();
    let scope_id = WorkScopeId::new(operation.scope_id.clone()).unwrap();
    let product_id = ProductId::new("product-1").unwrap();
    let source_id = SourceId::new("source-1").unwrap();
    let metadata = eliot_contracts::RequestMetadata {
        request_id: request_id.clone(),
        session_id: None,
        task_id: Some(task_id.clone()),
        product_id: product_id.clone(),
        source_id,
        state_fence: state_fence.clone(),
        clock: ClockReading {
            valid_time_ms: Some(1),
            known_time_ms: Some(1),
            transaction_sequence: Some(TransactionSequence::genesis()),
            monotonic_ns: None,
        },
    };
    ReceiptEnvelope::issue(ReceiptCore {
        contract: contract_identity().unwrap(),
        kind: ReceiptKind::Operation,
        work_scope: WorkScopeBinding {
            scope_id,
            product_id,
            resource_generation: state_fence.resource_generation,
            state_fence: state_fence.clone(),
        },
        task: Some(TaskBinding {
            task_id,
            task_revision: TaskRevision::genesis(),
            state_fence: state_fence.clone(),
        }),
        session: None,
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
            operation_id,
            request_id,
            idempotency_key: operation.idempotency_key.clone(),
            operation_kind: "failed-action".into(),
            effect: EffectClass::Candidate,
            state_fence: state_fence.clone(),
        },
        authority: AuthorityBinding {
            authority_id: ContractId::new("authority-1").unwrap(),
            authority_owner: "owner".into(),
            authority_epoch: state_fence.authority_epoch,
            state_fence,
            allowed_effect: EffectClass::Candidate,
            proof_ceiling: ProofCeiling::CandidateArtifact,
        },
        artifacts: vec![eliot_receipts::ArtifactBinding {
            artifact_id: ArtifactId::new("action-artifact").unwrap(),
            sha256: digest(b"action"),
            role: ReceiptKind::Artifact,
            source_revision: None,
        }],
        verifier: Some(VerifierBinding {
            verifier_id: ContractId::new("verifier-1").unwrap(),
            verifier_revision: ContractVersion::new(1, 0, 0),
            artifact_ids: vec![ArtifactId::new("action-artifact").unwrap()],
            proof_ceiling: ProofCeiling::CandidateArtifact,
            state_fence: operation.state_fence.clone(),
        }),
        problem: None,
        coordination: None,
        disposition,
    })
    .unwrap()
}
fn evidence_envelope(state_fence: StateFence, raw_handle: &str) -> EvidenceEnvelope {
    EvidenceEnvelope {
        authority: EvidenceAuthority::SourceIdentity,
        freshness: EvidenceFreshness::ExactCandidate,
        coverage: EvidenceCoverage::CompleteForScope,
        status: EpistemicStatus::Supported,
        assertability: Assertability::Assertable,
        provenance: Provenance {
            source_id: SourceId::new("source-1").unwrap(),
            capture_route: "failure-fixture".into(),
            scope: "scope-1".into(),
            raw_handle: Some(raw_handle.into()),
            revision: Some("source-r1".into()),
        },
        verification: None,
        state_fence,
    }
}
pub fn full_input() -> FailureInput {
    let mut job = sample_job();
    job.job_class = JobClass::Curation;
    job.frozen_manifest_digest = digest(b"manifest");
    let grounded = GroundedDreamDraft {
        schema_version: 1,
        job_id: "job-1".into(),
        draft_digest: digest(b"draft"),
        residues: vec![ClaimResidue {
            claim: "failure".into(),
            state: SupportState::Partial,
            detail: "grounded".into(),
        }],
        coverage_note: "one claim".into(),
    };
    let receipt = valid_receipt(&grounded.draft_digest, fence());
    let mut payload = sample_payload(CurationKind::Failure);
    if let eliot_dreamer_contracts::curation::CurationPayload::Failure(payload) = &mut payload {
        payload.target_evidence.evidence_refs = vec!["action-envelope".into()];
    }
    let denominator = TargetDenominator {
        mode: AtomicityMode::AllOrNothing,
        members: vec!["a".into(), "b".into(), "ab".into()],
        expected_total: 3,
    };
    let source_digest = digest(b"a");
    let profile_definition = FailureProfileDefinition::from_parts(
        "profile-owner".into(),
        "exact".into(),
        1,
        "profile-r1".into(),
        FailureComparator::ExactEquality,
        vec![
            FailureDimensionDescriptor {
                source: FailureDimensionSource::Action,
                field: "target_id".into(),
                name: "target".into(),
            },
            FailureDimensionDescriptor {
                source: FailureDimensionSource::Environment,
                field: "environment_id".into(),
                name: "environment".into(),
            },
        ],
        "profile".into(),
    )
    .unwrap();
    let item = ValidatedCurationItem {
        receipt: receipt.clone(),
        kind_spelling: "failure".into(),
        family_spelling: "failure".into(),
        payload: payload.clone(),
        denominator: denominator.clone(),
        source_digest: source_digest.clone(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: fence(),
        job_digest: digest(&canonical_bytes(&job).unwrap()),
        requester: job.requester.clone(),
        budget_note: "bounded".into(),
    };
    let mut screen = sample_binding();
    screen.request_id = eliot_contracts::RequestId::new("req-1").unwrap();
    screen.receipt_id = eliot_contracts::ReceiptId::new("rcpt-1").unwrap();
    screen.task_id = "task-1".into();
    screen.scope_id = "scope-1".into();
    screen.state_fence = fence();
    screen.state = ScreenState::Eligible;
    let mut request = TypedCurationHandlerRequest {
        request_id: "req-1".into(),
        receipt_id: "rcpt-1".into(),
        source_snapshot: screen.source_snapshot.clone(),
        source_revision: screen.source_revision.clone(),
        profile: screen.profile.clone(),
        kind: CurationKind::Failure,
        family: CurationFamily::Failure,
        job_id: "job-1".into(),
        scope_id: "scope-1".into(),
        task_id: "task-1".into(),
        state_fence: fence(),
        payload: payload.clone(),
        denominator: denominator.clone(),
        screen_binding: Some(screen.clone()),
    };
    let materials = vec![
        BundleMaterial {
            handle: "a".into(),
            disposition: SourceDisposition::Required,
            bytes: 1,
            digest: source_digest.clone(),
        },
        BundleMaterial {
            handle: "b".into(),
            disposition: SourceDisposition::Required,
            bytes: 1,
            digest: digest(b"b"),
        },
        BundleMaterial {
            handle: "ab".into(),
            disposition: SourceDisposition::Required,
            bytes: 2,
            digest: digest(b"ab"),
        },
        BundleMaterial {
            handle: "profile".into(),
            disposition: SourceDisposition::Required,
            bytes: profile_definition.definition_bytes.len() as u64,
            digest: profile_definition.definition_digest.clone(),
        },
    ];
    let mut bundle = eliot_dreamer_contracts::bundle::DreamInputBundle {
        schema_version: 1,
        job_id: "job-1".into(),
        scope_id: "scope-1".into(),
        task_id: "task-1".into(),
        state_fence: fence(),
        manifest_digest: digest(b"manifest"),
        materials,
        omissions: vec![eliot_dreamer_contracts::bundle::OmissionHandle {
            handle: "e-1".into(),
            reason: "not carried".into(),
            reversible: true,
            scope_id: "scope-1".into(),
            task_id: "task-1".into(),
            digest: digest(b"e-1"),
            nonrecoverable_reason: None,
        }],
        completeness: eliot_dreamer_contracts::bundle::BundleCompleteness::CompleteForScope,
        authoritative_denominator: Some("denom".into()),
    };
    let item_digest = item.item_digest(&grounded).unwrap();
    screen.item_digest = item_digest;
    request.screen_binding = Some(screen.clone());
    let action_operation = FailureOperation {
        operation_id: "failed-op".into(),
        idempotency_key: "failed-idem".into(),
        request_id: "failed-req".into(),
        candidate_id: "failed-cand".into(),
        attempt_id: "attempt-1".into(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: distinct_fence(2),
        requester: job.requester.clone(),
    };
    let action = FailureAction {
        action_id: "action-1".into(),
        operation_id: "failed-op".into(),
        attempt_id: "attempt-1".into(),
        target_id: "a".into(),
        input_schema: "schema".into(),
        input_digest: digest(b"input"),
        effect_id: "effect".into(),
        effect_class: EffectClass::Candidate,
        owner: "owner".into(),
        contract_revision: "r1".into(),
        contract_digest: digest(b"contract"),
    };
    let failed_receipt = action_receipt(
        &action_operation,
        ReceiptDisposition::Failure {
            code: eliot_contracts::ErrorCode::InvalidRequest,
            proof: ProofCeiling::CandidateArtifact,
        },
    );
    let action_envelope = evidence_envelope(distinct_fence(2), "raw-failed");
    let action_envelope_digest = digest(&canonical_bytes(&action_envelope).unwrap());
    bundle.materials.push(BundleMaterial {
        handle: "action-envelope".into(),
        disposition: SourceDisposition::Required,
        bytes: canonical_bytes(&action_envelope).unwrap().len() as u64,
        digest: action_envelope_digest.clone(),
    });
    let evidence = FailureEvidence {
        evidence_id: "e-1".into(),
        kind: FailureEvidenceKind::SemanticVerifier,
        operation_id: "failed-op".into(),
        request_id: "failed-req".into(),
        idempotency_key: "failed-idem".into(),
        action_id: "action-1".into(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: distinct_fence(2),
        digest: digest(b"verify"),
        envelope_digest: action_envelope_digest.clone(),
        material_handle: "action-envelope".into(),
        material_digest: action_envelope_digest.clone(),
        material_bytes: canonical_bytes(&action_envelope).unwrap(),
        owner: "owner".into(),
        coverage: FailureCoverage::Complete,
    };
    let outcome = FailureOutcome {
        intended: FailureExpectation {
            expected: FailureExpectedState::Failure,
            verifier: "verify".into(),
        },
        attempted: None,
        observed: ReceiptDisposition::Failure {
            code: eliot_contracts::ErrorCode::InvalidRequest,
            proof: ProofCeiling::CandidateArtifact,
        },
        verified: ReceiptDisposition::Failure {
            code: eliot_contracts::ErrorCode::InvalidRequest,
            proof: ProofCeiling::CandidateArtifact,
        },
        failure_state: Some(FailureObservationState::ExecutedButSemanticallyFailed),
        observed_receipt_ref: Some(failed_receipt.identity.receipt_id.to_string()),
        verified_receipt_ref: Some(failed_receipt.identity.receipt_id.to_string()),
        output_digest: None,
        possible_effects: vec!["unknown".into()],
        receipt_refs: vec![failed_receipt.identity.receipt_id.to_string()],
        coverage: FailureCoverage::Complete,
    };
    let action_evidence = FailureActionEvidence {
        action_operation: action_operation.clone(),
        action: action.clone(),
        outcome: outcome.clone(),
        evidence: vec![evidence.clone()],
        receipts: vec![failed_receipt.clone()],
        receipt_materials: vec![FailureReceiptMaterial {
            receipt_id: failed_receipt.identity.receipt_id.to_string(),
            handle: "action-receipt".into(),
            digest: failed_receipt.canonical_sha256().into(),
            bytes: failed_receipt.canonical_bytes().unwrap(),
        }],
        evidence_envelopes: vec![action_envelope.clone()],
        omitted_envelope_refs: vec![],
        coverage: FailureCoverage::Complete,
    };
    let environment = FailureEnvironment {
        environment_id: "env".into(),
        environment_revision: "r1".into(),
        platform: "windows".into(),
        tool_revision: "tool".into(),
        model_revision: None,
        config_revision: "cfg".into(),
        capability_revision: "cap".into(),
        policy_revision: "pol".into(),
        state_fence: fence(),
        coverage: FailureCoverage::Complete,
    };
    let control_operation = FailureOperation {
        operation_id: "control-op".into(),
        idempotency_key: "control-idem".into(),
        request_id: "control-req".into(),
        candidate_id: "control-cand".into(),
        attempt_id: "control-attempt".into(),
        task_id: "task-1".into(),
        scope_id: "scope-1".into(),
        state_fence: distinct_fence(3),
        requester: job.requester.clone(),
    };
    let control_receipt = action_receipt(
        &control_operation,
        ReceiptDisposition::Success {
            proof: ProofCeiling::CandidateArtifact,
        },
    );
    let control_envelope = evidence_envelope(distinct_fence(3), "raw-control");
    let control_envelope_digest = digest(&canonical_bytes(&control_envelope).unwrap());
    let mut historical_failed_evidence = evidence.clone();
    historical_failed_evidence.evidence_id = "e-1".into();
    bundle.materials.push(BundleMaterial {
        handle: "control-envelope".into(),
        disposition: SourceDisposition::Required,
        bytes: canonical_bytes(&control_envelope).unwrap().len() as u64,
        digest: control_envelope_digest.clone(),
    });
    bundle.materials.push(BundleMaterial {
        handle: "action-receipt".into(),
        disposition: SourceDisposition::Required,
        bytes: failed_receipt.canonical_bytes().unwrap().len() as u64,
        digest: failed_receipt.canonical_sha256().into(),
    });
    bundle.materials.push(BundleMaterial {
        handle: "control-receipt".into(),
        disposition: SourceDisposition::Required,
        bytes: control_receipt.canonical_bytes().unwrap().len() as u64,
        digest: control_receipt.canonical_sha256().into(),
    });
    let history = FailureHistory {
        coverage: FailureCoverage::Complete,
        expected_total: 2,
        entries: vec![
            FailureHistoryEntry {
                history_id: "history-failed".into(),
                operation_id: action_operation.operation_id.clone(),
                request_id: action_operation.request_id.clone(),
                idempotency_key: action_operation.idempotency_key.clone(),
                fingerprint_id: "failed-fingerprint".into(),
                trigger_digest: digest(b"failed-trigger"),
                outcome: ReceiptDisposition::Failure {
                    code: eliot_contracts::ErrorCode::InvalidRequest,
                    proof: ProofCeiling::CandidateArtifact,
                },
                failure_state: Some(FailureObservationState::ExecutedButSemanticallyFailed),
                task_id: action_operation.task_id.clone(),
                scope_id: action_operation.scope_id.clone(),
                state_fence: action_operation.state_fence.clone(),
                independent: true,
                semantic_success: false,
                near_match: false,
                false_activation: false,
                observed: true,
                evidence_refs: vec!["e-1".into()],
                receipt_refs: vec![failed_receipt.identity.receipt_id.to_string()],
                coverage: FailureCoverage::Complete,
            },
            FailureHistoryEntry {
                history_id: "history-control".into(),
                operation_id: control_operation.operation_id.clone(),
                request_id: control_operation.request_id.clone(),
                idempotency_key: control_operation.idempotency_key.clone(),
                fingerprint_id: "control-fingerprint".into(),
                trigger_digest: digest(b"control-trigger"),
                outcome: ReceiptDisposition::Success {
                    proof: ProofCeiling::CandidateArtifact,
                },
                failure_state: None,
                task_id: control_operation.task_id.clone(),
                scope_id: control_operation.scope_id.clone(),
                state_fence: control_operation.state_fence.clone(),
                independent: true,
                semantic_success: true,
                near_match: false,
                false_activation: false,
                observed: true,
                evidence_refs: vec!["history-evidence".into()],
                receipt_refs: vec![control_receipt.identity.receipt_id.to_string()],
                coverage: FailureCoverage::Complete,
            },
        ],
        omitted_refs: vec![],
        success_count: 1,
        near_match_count: 0,
        false_activation_count: 0,
        unknown_count: 0,
        receipts: vec![failed_receipt.clone(), control_receipt.clone()],
        receipt_materials: vec![
            FailureReceiptMaterial {
                receipt_id: failed_receipt.identity.receipt_id.to_string(),
                handle: "action-receipt".into(),
                digest: failed_receipt.canonical_sha256().into(),
                bytes: failed_receipt.canonical_bytes().unwrap(),
            },
            FailureReceiptMaterial {
                receipt_id: control_receipt.identity.receipt_id.to_string(),
                handle: "control-receipt".into(),
                digest: control_receipt.canonical_sha256().into(),
                bytes: control_receipt.canonical_bytes().unwrap(),
            },
        ],
        historical_evidence: vec![
            historical_failed_evidence,
            FailureEvidence {
                evidence_id: "history-evidence".into(),
                kind: FailureEvidenceKind::Control,
                operation_id: control_operation.operation_id,
                request_id: "control-req".into(),
                idempotency_key: "control-idem".into(),
                action_id: "control-action".into(),
                task_id: "task-1".into(),
                scope_id: "scope-1".into(),
                state_fence: distinct_fence(3),
                digest: digest(b"control-evidence"),
                envelope_digest: control_envelope_digest.clone(),
                material_handle: "control-envelope".into(),
                material_digest: control_envelope_digest,
                material_bytes: canonical_bytes(&control_envelope).unwrap(),
                owner: "control-owner".into(),
                coverage: FailureCoverage::Complete,
            },
        ],
        historical_evidence_envelopes: vec![action_envelope.clone(), control_envelope.clone()],
        omitted_evidence_envelope_refs: vec![],
    };
    let comparison = FailureComparisonProfile {
        profile_id: "exact".into(),
        schema_version: 1,
        comparator: FailureComparator::ExactEquality,
        definition: profile_definition.clone(),
        dimensions: vec![
            FailureDimension {
                source: FailureDimensionSource::Action,
                field: "target_id".into(),
                name: "target".into(),
                value: FailureDimensionValue::Text("a".into()),
            },
            FailureDimension {
                source: FailureDimensionSource::Environment,
                field: "environment_id".into(),
                name: "environment".into(),
                value: FailureDimensionValue::Text("env".into()),
            },
        ],
        missing_dimensions: vec![],
    };
    let proposal = FailureProposal {
        schema_version: 1,
        candidate_id: "cand-1".into(),
        fingerprint: "fp-1".into(),
        signature: "sig-1".into(),
        operation: FailureOperation {
            operation_id: job.operation_id.clone(),
            idempotency_key: job.idempotency_key.clone(),
            request_id: "req-1".into(),
            candidate_id: "cand-1".into(),
            attempt_id: "attempt-1".into(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: fence(),
            requester: job.requester.clone(),
        },
        class: FailureClass::PartialOrUnknownEffect,
        target_evidence: TargetEvidence {
            targets: vec!["a".into(), "b".into(), "ab".into()],
            evidence_refs: vec!["action-envelope".into()],
        },
        comparison,
        trigger: vec![
            FailureDimension {
                source: FailureDimensionSource::Action,
                field: "target_id".into(),
                name: "target".into(),
                value: FailureDimensionValue::Text("a".into()),
            },
            FailureDimension {
                source: FailureDimensionSource::Environment,
                field: "environment_id".into(),
                name: "environment".into(),
                value: FailureDimensionValue::Text("env".into()),
            },
        ],
        action: action.clone(),
        outcome,
        environment: environment.clone(),
        applicability: FailureApplicability {
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            target_id: "a".into(),
            environment_id: "env".into(),
            platform: "windows".into(),
            tool_revision: "tool".into(),
            model_revision: None,
            config_revision: "cfg".into(),
            capability_revision: "cap".into(),
            effect_class: EffectClass::Candidate,
            coverage: FailureCoverage::Complete,
        },
        violated_invariant: "invariant".into(),
        evidence_refs: vec!["e-1".into()],
        counterevidence_refs: vec![],
        causal: FailureHypothesis {
            hypothesis_id: "h".into(),
            statement: "unknown".into(),
            evidence_refs: vec!["e-1".into()],
            limitation_refs: vec![],
            rival_refs: vec![],
            confounder_refs: vec![],
            status: FailureCausalStatus::Unknown,
        },
        controls: vec![],
        mitigation: FailureMitigation {
            do_not_repeat_until: "verify".into(),
            note: "safe".into(),
            owner: "owner".into(),
            safe_reattempt_verifier: "verifier-1".into(),
            verifier_revision: "1.0.0".into(),
            verifier_digest: digest(
                &canonical_bytes(action_evidence.receipts[0].core.verifier.as_ref().unwrap())
                    .unwrap(),
            ),
            verifier_receipt_ref: action_evidence.receipts[0].identity.receipt_id.to_string(),
        },
        lifecycle: FailureLifecycle {
            reopen_condition: "new evidence".into(),
            extinction_condition: "superseded".into(),
            expiry_ms: None,
            inverse_refs: vec![],
            predecessor_fingerprint: None,
            current_fingerprint_revision: "r1".into(),
            raw_history_refs: vec![],
        },
        history,
        preservation: preservation(),
        source_refs: vec!["a".into()],
        policy_digest: digest(b"policy"),
        proof_ceiling: ProofCeiling::CandidateArtifact,
    };
    let mut source_members = vec![
        FailureSourceMember {
            handle: "a".into(),
            digest: source_digest,
            bytes: b"a".to_vec(),
            source_snapshot: screen.source_snapshot.clone(),
            source_revision: screen.source_revision.clone(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: fence(),
        },
        FailureSourceMember {
            handle: "b".into(),
            digest: digest(b"b"),
            bytes: b"b".to_vec(),
            source_snapshot: screen.source_snapshot.clone(),
            source_revision: screen.source_revision.clone(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: fence(),
        },
        FailureSourceMember {
            handle: "ab".into(),
            digest: digest(b"ab"),
            bytes: b"ab".to_vec(),
            source_snapshot: screen.source_snapshot.clone(),
            source_revision: screen.source_revision.clone(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: fence(),
        },
        FailureSourceMember {
            handle: "profile".into(),
            digest: profile_definition.definition_digest.clone(),
            bytes: profile_definition.definition_bytes.clone(),
            source_snapshot: screen.source_snapshot.clone(),
            source_revision: screen.source_revision.clone(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: fence(),
        },
    ];
    for (handle, bytes, member_digest) in [
        (
            "action-envelope",
            canonical_bytes(&action_envelope).unwrap(),
            action_envelope_digest.clone(),
        ),
        (
            "control-envelope",
            canonical_bytes(&control_envelope).unwrap(),
            digest(&canonical_bytes(&control_envelope).unwrap()),
        ),
        (
            "action-receipt",
            failed_receipt.canonical_bytes().unwrap(),
            failed_receipt.canonical_sha256().to_owned(),
        ),
        (
            "control-receipt",
            control_receipt.canonical_bytes().unwrap(),
            control_receipt.canonical_sha256().to_owned(),
        ),
    ] {
        source_members.push(FailureSourceMember {
            handle: handle.into(),
            digest: member_digest,
            bytes,
            source_snapshot: screen.source_snapshot.clone(),
            source_revision: screen.source_revision.clone(),
            task_id: "task-1".into(),
            scope_id: "scope-1".into(),
            state_fence: fence(),
        });
    }
    FailureInput {
        schema_version: 1,
        operation: proposal.operation.clone(),
        job,
        bundle,
        grounded,
        usage: BudgetUsage {
            input_bytes: 1,
            output_bytes: 1,
            source_width: 1,
            reference_width: 1,
            model_calls: 0,
            attempts: 0,
            candidates: 0,
            wall_ms: 0,
            work_fan_out: 0,
            report_bytes: 0,
            stu_used: 0,
        },
        source_members,
        item,
        request,
        screen,
        action_evidence,
        environment,
        history: proposal.history.clone(),
        proposal,
        policy_digest: digest(b"policy"),
        preservation: preservation(),
    }
}
