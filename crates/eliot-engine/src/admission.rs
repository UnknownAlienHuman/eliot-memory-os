use crate::EngineError;
use eliot_types::{
    ClaimCardInput, EpistemicStatus, EvidenceAtomInput, FailureFingerprintInput,
    IdempotencyOptions, LifecycleWriteOptions, MemoryWriteEnvelope, OperationId, RelationInput,
    RelationType, SemanticCommand, SourceSnapshotInput, TaskContractInput, ToolObservationInput,
    VerificationResult, VerificationRunInput, WriteRejectReason,
};
use serde::Serialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

const MAX_COMMAND_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Default)]
pub struct WriteAdmissionService;

impl WriteAdmissionService {
    pub fn admit(&self, command: &SemanticCommand) -> Result<MemoryWriteEnvelope, EngineError> {
        let value = serde_json::to_value(command)?;
        let violations = eliot_types::ul::guard::inspect_text_encoding(&value);
        if !violations.is_empty() {
            return Err(EngineError::EncodingRejected { violations });
        }
        validate_command_shape(command)?;
        let input_hash = stable_input_hash(command)?;
        let context = command.context().clone();
        validate_context(&context.scope, &context.authority)?;
        let admitted = admit_command(command)?;

        Ok(MemoryWriteEnvelope {
            write_id: context.write_id,
            operation_id: OperationId::new_v7(),
            agent_id: context.agent_id,
            session_id: context.session_id,
            project_id: context.project_id,
            task_id: context.task_id,
            command_kind: command.kind(),
            input_hash,
            policy_snapshot_id: None,
            project_sequence_hint: None,
            created_at: OffsetDateTime::now_utc(),
            scope: context.scope,
            authority: context.authority,
            task_contracts: admitted.task_contracts,
            source_snapshots: admitted.source_snapshots,
            evidence_atoms: admitted.evidence_atoms,
            tool_observations: admitted.tool_observations,
            failures: admitted.failures,
            claims: admitted.claims,
            verification_runs: admitted.verification_runs,
            relations: admitted.relations,
            lifecycle: LifecycleWriteOptions {
                status: context.lifecycle_status,
                visibility: context.visibility,
                taint: context.taint,
            },
            idempotency: IdempotencyOptions { allow_replay: true },
        })
    }
}

#[derive(Default)]
struct AdmittedCommand {
    task_contracts: Vec<TaskContractInput>,
    source_snapshots: Vec<SourceSnapshotInput>,
    evidence_atoms: Vec<EvidenceAtomInput>,
    tool_observations: Vec<ToolObservationInput>,
    failures: Vec<FailureFingerprintInput>,
    claims: Vec<ClaimCardInput>,
    verification_runs: Vec<VerificationRunInput>,
    relations: Vec<RelationInput>,
}

fn admit_command(command: &SemanticCommand) -> Result<AdmittedCommand, EngineError> {
    let mut admitted = AdmittedCommand::default();
    match command {
        SemanticCommand::TaskContractWrite(body) => {
            if body.context.task_id != Some(body.contract.task_id) {
                return reject("TaskContract context.task_id must match contract.task_id");
            }
            if body.contract.title.trim().is_empty() {
                return reject("TaskContract title is required");
            }
            if body.contract.acceptance_items.is_empty() {
                return reject("TaskContract requires acceptance items");
            }
            admitted.task_contracts.push(body.contract.clone());
            if let Some(observation) = &body.observation {
                admitted.tool_observations.push(observation.clone());
            }
            if let Some(verification) = &body.verification {
                if verification.result == VerificationResult::Passed
                    && body.context.taint != eliot_types::TaintClass::LocalVerified
                {
                    return reject("passed verification requires LocalVerified authority");
                }
                admitted.verification_runs.push(verification.clone());
            }
        }
        SemanticCommand::EvidenceIngest(body) => {
            admitted.source_snapshots.push(body.source.clone());
            admitted.evidence_atoms.push(body.evidence.clone());
        }
        SemanticCommand::ToolObservationRecord(body) => {
            admitted.tool_observations.push(ToolObservationInput {
                observation_id: body.context.write_id.to_string(),
                tool_name: body.tool_name.clone(),
                observation: body.observation.clone(),
                payload: body.payload.clone(),
            });
        }
        SemanticCommand::ClaimPropose(body) => admit_claim_propose(&mut admitted, body)?,
        SemanticCommand::ClaimSupport(body) => admit_claim_support(&mut admitted, body),
        SemanticCommand::ClaimVerify(body) => admit_claim_verify(&mut admitted, body)?,
        SemanticCommand::FailureRecord(body) => admitted.failures.push(FailureFingerprintInput {
            fingerprint: body.fingerprint.clone(),
            summary: body.summary.clone(),
            payload: body.payload.clone(),
        }),
        SemanticCommand::VerificationRecord(body) => {
            admitted.verification_runs.push(body.verification.clone());
        }
        SemanticCommand::AgentResultRecord(body) => admit_agent_result(&mut admitted, body)?,
        SemanticCommand::DiagnosticBatchRecord(_)
        | SemanticCommand::ActiveDecisionTransition(_)
        | SemanticCommand::ProbeRecord(_)
        | SemanticCommand::CompletionProofSubmit(_) => {
            return Err(EngineError::WriteRejected(format!(
                "{:?}",
                WriteRejectReason::NotImplemented
            )));
        }
    }
    Ok(admitted)
}

fn admit_agent_result(
    admitted: &mut AdmittedCommand,
    body: &eliot_types::AgentResultRecordCommand,
) -> Result<(), EngineError> {
    let context = &body.context;
    let lineage = &body.lineage;
    if context.task_id != Some(lineage.task_id) {
        return reject("AgentResultRecord context.task_id must match lineage.task_id");
    }
    if context.session_id != Some(lineage.child_session_id) {
        return reject("AgentResultRecord session must match the child handoff session");
    }
    if context.authority != "daemon-finish-gate"
        || context.taint != eliot_types::TaintClass::LocalVerified
        || context.scope != format!("task:{}", lineage.task_id)
    {
        return reject("AgentResultRecord requires daemon-derived verified authority");
    }
    if lineage.controller_receipt_id.as_uuid() != context.write_id.as_uuid() {
        return reject("AgentResultRecord receipt must be bound to its write_id");
    }
    if lineage.base_commit.trim().is_empty()
        || lineage.resulting_controller_commit.trim().is_empty()
        || lineage.base_commit == lineage.resulting_controller_commit
        || lineage.branch.trim().is_empty()
        || lineage.candidate_artifact_or_diff_ref.trim().is_empty()
        || lineage.accepted_write_set.is_empty()
        || lineage.verification_ids.is_empty()
        || lineage.verification_ids.len() != lineage.verification_receipt_ids.len()
        || lineage.canonical_artifact_refs.is_empty()
        || lineage.canonical_artifact_refs.len() != lineage.accepted_write_set.len()
        || lineage.provenance_set_hash.trim().is_empty()
    {
        return reject("AgentResultRecord requires exact controller handoff lineage");
    }
    if lineage
        .canonical_artifact_refs
        .iter()
        .any(|artifact| !lineage.accepted_write_set.contains(&artifact.resource_ref))
        || lineage
            .verification_ids
            .iter()
            .zip(&lineage.verification_receipt_ids)
            .any(|(verification_id, receipt_id)| verification_id.as_uuid() != receipt_id.as_uuid())
        || lineage.candidate_artifact_or_diff_ref
            != format!(
                "git-diff:{}..{}",
                lineage.base_commit, lineage.resulting_controller_commit
            )
    {
        return reject("AgentResultRecord lineage does not match canonical artifact receipts");
    }

    admitted.tool_observations.push(ToolObservationInput {
        observation_id: context.write_id.to_string(),
        tool_name: "eliot_submit_completion_proof".to_owned(),
        observation: "daemon-derived controller commit handoff".to_owned(),
        payload: json!({
            "lineage": lineage,
            "memory": &body.memory,
        }),
    });

    if let eliot_types::CompletionMemoryAdmission::SaveDecision { decision } = &body.memory {
        if decision.claim.statement.trim().is_empty()
            || decision.claim.status != EpistemicStatus::Verified
            || decision.evidence.source_id != decision.source.source_id
            || decision.where_applicable.is_empty()
            || decision.where_not_applicable.is_empty()
            || decision.freshness_rule.trim().is_empty()
        {
            return reject("saved completion memory is not a bounded verified decision");
        }
        admitted.source_snapshots.push(decision.source.clone());
        admitted.evidence_atoms.push(decision.evidence.clone());
        admitted.claims.push(decision.claim.clone());
        admitted.relations.push(RelationInput {
            relation_type: RelationType::Supports,
            from: decision.claim.claim_id.to_string(),
            to: decision.evidence.evidence_id.to_string(),
        });
        for verification_id in &lineage.verification_ids {
            admitted.relations.push(RelationInput {
                relation_type: RelationType::VerifiedBy,
                from: decision.claim.claim_id.to_string(),
                to: verification_id.to_string(),
            });
        }
        admitted.relations.push(RelationInput {
            relation_type: RelationType::BelongsTo,
            from: decision.claim.claim_id.to_string(),
            to: lineage.task_id.to_string(),
        });
    }
    Ok(())
}

fn admit_claim_propose(
    admitted: &mut AdmittedCommand,
    body: &eliot_types::ClaimProposeCommand,
) -> Result<(), EngineError> {
    if body.claim.status != EpistemicStatus::Candidate {
        return reject("ClaimPropose must use candidate status");
    }
    admitted.claims.push(body.claim.clone());
    if let Some(task_id) = body.context.task_id {
        admitted.relations.push(RelationInput {
            relation_type: RelationType::BelongsTo,
            from: body.claim.claim_id.to_string(),
            to: task_id.to_string(),
        });
    }
    Ok(())
}

fn admit_claim_support(admitted: &mut AdmittedCommand, body: &eliot_types::ClaimSupportCommand) {
    admitted.relations.push(RelationInput {
        relation_type: RelationType::Supports,
        from: body.claim_id.to_string(),
        to: body.evidence_id.to_string(),
    });
    if let Some(statement) = &body.statement {
        admitted.claims.push(ClaimCardInput {
            claim_id: body.claim_id,
            statement: statement.clone(),
            status: EpistemicStatus::Supported,
            payload: body.payload.clone(),
        });
    }
}

fn admit_claim_verify(
    admitted: &mut AdmittedCommand,
    body: &eliot_types::ClaimVerifyCommand,
) -> Result<(), EngineError> {
    if body.verification.result != VerificationResult::Passed {
        return reject("ClaimVerify requires a passed verification run");
    }
    admitted.relations.push(RelationInput {
        relation_type: RelationType::VerifiedBy,
        from: body.claim_id.to_string(),
        to: body.verification.verification_id.to_string(),
    });
    admitted.verification_runs.push(body.verification.clone());
    if let Some(statement) = &body.statement {
        admitted.claims.push(ClaimCardInput {
            claim_id: body.claim_id,
            statement: statement.clone(),
            status: EpistemicStatus::Verified,
            payload: body.payload.clone(),
        });
    }
    Ok(())
}

fn validate_context(scope: &str, authority: &str) -> Result<(), EngineError> {
    if scope.trim().is_empty() || authority.trim().is_empty() {
        return reject("scope and authority are required");
    }
    Ok(())
}

fn validate_command_shape(command: &SemanticCommand) -> Result<(), EngineError> {
    let bytes = serde_json::to_vec(command)?;
    if bytes.len() > MAX_COMMAND_BYTES {
        return reject("semantic command payload is too large");
    }
    let value: Value = serde_json::from_slice(&bytes)?;
    if contains_forbidden_db_surface(&value) {
        return reject("semantic command contains forbidden DB surface");
    }
    Ok(())
}

fn contains_forbidden_db_surface(value: &Value) -> bool {
    match value {
        Value::Object(map) => map.iter().any(|(key, value)| {
            let key = key.to_ascii_lowercase();
            matches!(
                key.as_str(),
                "sql" | "surql" | "query" | "endpoint" | "credential" | "credentials" | "password"
            ) || contains_forbidden_db_surface(value)
        }),
        Value::Array(values) => values.iter().any(contains_forbidden_db_surface),
        _ => false,
    }
}

fn stable_input_hash<T>(value: &T) -> Result<String, EngineError>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec(value)?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

fn reject<T>(reason: &str) -> Result<T, EngineError> {
    Err(EngineError::WriteRejected(reason.to_owned()))
}
