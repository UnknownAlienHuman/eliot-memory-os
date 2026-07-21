use crate::EngineError;
use eliot_store::{CanonicalClaimCard, CanonicalRecord, CanonicalStore};
use eliot_types::{
    AgentResultDispositionKind, AgentRole, AgentSessionId, CanonicalCaseDisposition, ClaimId,
    CognitiveRawVerifierEvidence, CognitiveRunAttempt, CognitiveRunCallPlan,
    CognitiveRunCallStatus, CognitiveRunContract, CognitiveRunTerminal, ControllerLease,
    EpistemicStatus, MemoryRevision, SemanticCommandKind, SessionId, TaskRoleLease, VerificationId,
    VerificationResult, VerificationRun, WriteReceipt, WriteReceiptRef, WriteStatus,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use time::OffsetDateTime;

fn rejected(reason: impl Into<String>) -> EngineError {
    EngineError::WriteRejected(reason.into())
}

fn string_list(value: Option<&Value>, field: &str) -> Result<Vec<String>, EngineError> {
    let values = value
        .and_then(Value::as_array)
        .ok_or_else(|| rejected(format!("canonical disposition {field} is absent")))?;
    let mut result = Vec::with_capacity(values.len());
    for value in values {
        let item = value
            .as_str()
            .filter(|item| !item.trim().is_empty())
            .ok_or_else(|| rejected(format!("canonical disposition {field} is invalid")))?;
        if result.iter().any(|existing| existing == item) {
            return Err(rejected(format!(
                "canonical disposition {field} contains duplicates"
            )));
        }
        result.push(item.to_owned());
    }
    if result.is_empty() {
        return Err(rejected(format!("canonical disposition {field} is empty")));
    }
    Ok(result)
}

fn committed_receipt(receipt: &WriteReceipt, expected: &WriteReceiptRef) -> bool {
    receipt.receipt_id == expected.receipt_id
        && receipt.write_id == expected.write_id
        && matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
        && receipt.rejected_reason.is_none()
}

async fn current_authority<T: DeserializeOwned>(
    store: &CanonicalStore,
    project_id: eliot_types::ProjectId,
    task_id: eliot_types::TaskId,
    entity_kind: &str,
    entity_ref: &str,
    expected_receipt_kind: &str,
) -> Result<T, EngineError> {
    let observations = store
        .latest_authority_observations_by_entity(project_id, Some(task_id), entity_kind, entity_ref)
        .await?;
    let current = observations
        .first()
        .ok_or_else(|| rejected(format!("{entity_kind} canonical authority is absent")))?;
    if observations.get(1).is_some_and(|previous| {
        previous.memory_revision == current.memory_revision
            && previous.project_sequence == current.project_sequence
    }) {
        return Err(rejected(format!(
            "{entity_kind} canonical authority is ambiguous"
        )));
    }
    if current.payload.get("receipt_kind").and_then(Value::as_str) != Some(expected_receipt_kind) {
        return Err(rejected(format!(
            "{entity_kind} canonical authority has the wrong receipt kind"
        )));
    }
    let body = current
        .payload
        .get("receipt_body")
        .cloned()
        .ok_or_else(|| rejected(format!("{entity_kind} canonical body is absent")))?;
    let receipt = store
        .write_receipt_by_id(&current.write_id)
        .await?
        .ok_or_else(|| rejected(format!("{entity_kind} canonical receipt is absent")))?;
    if receipt.project_id != project_id
        || receipt.task_id != Some(task_id)
        || !matches!(
            receipt.status,
            WriteStatus::Committed | WriteStatus::IdempotentReplay
        )
        || receipt.rejected_reason.is_some()
        || !receipt
            .created_records
            .iter()
            .any(|record| record == &current.observation_id)
    {
        return Err(rejected(format!(
            "{entity_kind} canonical receipt is invalid"
        )));
    }
    Ok(serde_json::from_value(body)?)
}

async fn require_active_disposition_actor(
    store: &CanonicalStore,
    project_id: eliot_types::ProjectId,
    task_id: eliot_types::TaskId,
    actor_session_id: AgentSessionId,
    role_lease_id: &str,
    controller_lease_id: Option<&str>,
    now: OffsetDateTime,
) -> Result<(), EngineError> {
    let role: TaskRoleLease = current_authority(
        store,
        project_id,
        task_id,
        "task_role_lease",
        role_lease_id,
        "host_role_lease_authority",
    )
    .await?;
    if role.role_lease_id != role_lease_id
        || role.task_id != task_id
        || role.agent_session_id != actor_session_id
        || role.expires_at <= now
        || !matches!(role.role, AgentRole::Controller | AgentRole::Reviewer)
        || !role
            .capability_scope
            .iter()
            .any(|capability| matches!(capability.as_str(), "review" | "review_candidate"))
    {
        return Err(rejected(
            "canonical disposition actor has a stale or unauthorized role lease",
        ));
    }
    if role.role == AgentRole::Controller {
        let controller_lease_id = controller_lease_id.ok_or_else(|| {
            rejected("controller disposition is missing its ControllerLease binding")
        })?;
        let controller: ControllerLease = current_authority(
            store,
            project_id,
            task_id,
            "controller_lease",
            controller_lease_id,
            "controller_lease",
        )
        .await?;
        if controller.controller_lease_id != controller_lease_id
            || controller.task_id != task_id
            || controller.agent_session_id != actor_session_id
            || controller.expires_at <= now
        {
            return Err(rejected(
                "canonical disposition actor has a stale ControllerLease",
            ));
        }
    }
    Ok(())
}

async fn require_raw_verifiers(
    store: &CanonicalStore,
    contract: &CognitiveRunContract,
    terminal: &CanonicalRecord<CognitiveRunTerminal>,
) -> Result<Vec<String>, EngineError> {
    if terminal.receipt_body.raw_verifier_receipts.is_empty() {
        return Err(rejected(
            "canonical disposition has no raw verifier evidence",
        ));
    }
    let mut verifier_refs =
        Vec::with_capacity(terminal.receipt_body.raw_verifier_receipts.len() + 1);
    for verifier_receipt in &terminal.receipt_body.raw_verifier_receipts {
        let verifier = store
            .canonical_record_by_write_id::<CognitiveRawVerifierEvidence>(
                contract.project_id,
                Some(contract.task_id),
                &["cognitive_raw_verifier"],
                verifier_receipt.write_id,
            )
            .await?
            .ok_or_else(|| rejected("canonical raw verifier record is absent"))?;
        if verifier.canonical_receipt != *verifier_receipt
            || !verifier.receipt_body.passed
            || verifier.receipt_body.run_id != contract.run_id
            || verifier.receipt_body.call_id != terminal.receipt_body.call_id
            || verifier.receipt_body.call_number != terminal.receipt_body.call_number
        {
            return Err(rejected("canonical raw verifier binding is invalid"));
        }
        verifier_refs.push(format!("receipt:{}", verifier_receipt.receipt_id));
    }
    Ok(verifier_refs)
}

async fn canonical_source_candidate(
    store: &CanonicalStore,
    contract: &CognitiveRunContract,
    terminal: &CanonicalRecord<CognitiveRunTerminal>,
    call: &CognitiveRunCallPlan,
) -> Result<(WriteReceiptRef, ClaimId, CanonicalClaimCard), EngineError> {
    let candidate_receipt = terminal
        .receipt_body
        .candidate_receipt
        .clone()
        .ok_or_else(|| rejected("source terminal candidate receipt is absent"))?;
    let source_receipt = store
        .write_receipt_by_id(&candidate_receipt.write_id)
        .await?
        .ok_or_else(|| rejected("source candidate receipt is absent"))?;
    if !committed_receipt(&source_receipt, &candidate_receipt)
        || source_receipt.project_id != contract.project_id
        || source_receipt.task_id != Some(contract.task_id)
    {
        return Err(rejected("source candidate receipt binding is invalid"));
    }
    let attempt = store
        .canonical_record_by_write_id::<CognitiveRunAttempt>(
            contract.project_id,
            Some(contract.task_id),
            &["cognitive_run_attempt"],
            terminal.receipt_body.attempt_receipt.write_id,
        )
        .await?
        .ok_or_else(|| rejected("source attempt is absent"))?;
    if attempt.canonical_receipt != terminal.receipt_body.attempt_receipt
        || attempt.receipt_body.run_id != contract.run_id
        || attempt.receipt_body.call_id != call.call_id
        || attempt.receipt_body.call_number != call.call_number
    {
        return Err(rejected("source attempt binding is invalid"));
    }
    let claim_id = ClaimId::from_uuid(candidate_receipt.write_id.as_uuid());
    let claim = store
        .claim_card_by_id(contract.project_id, claim_id)
        .await?
        .ok_or_else(|| rejected("canonical candidate disposition is absent"))?;
    if claim.project_id != contract.project_id
        || claim.task_id != Some(contract.task_id)
        || claim.status != EpistemicStatus::Verified
        || claim.payload.get("candidate_only").and_then(Value::as_bool) != Some(false)
        || claim
            .payload
            .get("admitted_by_operator")
            .and_then(Value::as_bool)
            != Some(true)
        || claim.payload.get("cognitive_run_id") != Some(&Value::String(contract.run_id.clone()))
        || claim.payload.get("cognitive_call_id") != Some(&Value::String(call.call_id.clone()))
    {
        return Err(rejected(
            "canonical disposition points to another candidate, task, or run",
        ));
    }
    let disposition = claim
        .payload
        .get("operator_candidate_disposition")
        .ok_or_else(|| rejected("canonical operator disposition is absent"))?;
    if disposition.get("disposition").and_then(Value::as_str) != Some("promote")
        || disposition.get("task_id") != Some(&serde_json::json!(contract.task_id))
        || disposition.get("source_write_id")
            != Some(&serde_json::json!(candidate_receipt.write_id))
    {
        return Err(rejected(
            "canonical disposition is rejected or has the wrong subject",
        ));
    }
    Ok((candidate_receipt, claim_id, claim))
}

struct ValidatedDisposition {
    receipt: WriteReceipt,
    verification: VerificationRun,
    verification_id: VerificationId,
    revision_before: MemoryRevision,
    revision_after: MemoryRevision,
}

async fn canonical_disposition_chain(
    store: &CanonicalStore,
    contract: &CognitiveRunContract,
    candidate_receipt: &WriteReceiptRef,
    claim_id: ClaimId,
    claim: &CanonicalClaimCard,
) -> Result<ValidatedDisposition, EngineError> {
    let receipt = store
        .write_receipt_by_id(&claim.write_id)
        .await?
        .ok_or_else(|| rejected("canonical disposition receipt is absent"))?;
    let receipt_ref = WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: claim.write_id,
    };
    if !committed_receipt(&receipt, &receipt_ref)
        || receipt.project_id != contract.project_id
        || receipt.task_id != Some(contract.task_id)
        || receipt.command_kind != SemanticCommandKind::ClaimVerify
        || claim.write_id != receipt.write_id
    {
        return Err(rejected(
            "canonical disposition receipt/revision binding is invalid",
        ));
    }
    let revision_after = receipt
        .memory_revision
        .ok_or_else(|| rejected("canonical disposition receipt has no revision"))?;
    let revision_before = revision_after
        .value()
        .checked_sub(1)
        .map(MemoryRevision::new)
        .ok_or_else(|| rejected("canonical disposition revision pair is invalid"))?;
    let verification_id = VerificationId::from_uuid(receipt.write_id.as_uuid());
    let verification = store
        .verification_run_by_id(verification_id)
        .await?
        .ok_or_else(|| rejected("canonical disposition verification is absent"))?;
    if verification.result != VerificationResult::Passed
        || verification.claim_id != Some(claim_id)
        || verification
            .payload
            .get("authority")
            .and_then(Value::as_str)
            != Some("human_operator")
        || verification.payload.get("project_id") != Some(&serde_json::json!(contract.project_id))
        || verification.payload.get("task_id") != Some(&serde_json::json!(contract.task_id))
        || verification.payload.get("candidate_original_write_id")
            != Some(&serde_json::json!(candidate_receipt.write_id))
        || verification
            .payload
            .get("disposition")
            .and_then(Value::as_str)
            != Some("promote")
    {
        return Err(rejected(
            "canonical disposition verification binding is invalid",
        ));
    }
    Ok(ValidatedDisposition {
        receipt,
        verification,
        verification_id,
        revision_before,
        revision_after,
    })
}

struct DispositionAuthority {
    session_id: AgentSessionId,
    role_lease_id: String,
    evidence_refs: Vec<String>,
    verifier_refs: Vec<String>,
}

async fn canonical_disposition_authority(
    store: &CanonicalStore,
    contract: &CognitiveRunContract,
    terminal: &CanonicalRecord<CognitiveRunTerminal>,
    chain: &ValidatedDisposition,
    now: OffsetDateTime,
) -> Result<DispositionAuthority, EngineError> {
    let actor_session: SessionId = serde_json::from_value(
        chain
            .verification
            .payload
            .get("operator_session_id")
            .cloned()
            .ok_or_else(|| rejected("canonical disposition actor session is absent"))?,
    )?;
    let session_id = AgentSessionId::from_uuid(actor_session.as_uuid());
    let role_lease_id = chain
        .verification
        .payload
        .get("actor_role_lease_id")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| rejected("canonical disposition actor role lease is absent"))?
        .to_owned();
    let controller_lease_id = chain
        .verification
        .payload
        .get("actor_controller_lease_id")
        .and_then(Value::as_str);
    require_active_disposition_actor(
        store,
        contract.project_id,
        contract.task_id,
        session_id,
        &role_lease_id,
        controller_lease_id,
        now,
    )
    .await?;
    let evidence_refs = string_list(
        chain.verification.payload.get("evidence_refs"),
        "evidence_refs",
    )?;
    let source_refs = string_list(
        chain.verification.payload.get("source_provenance_refs"),
        "source_provenance_refs",
    )?;
    if source_refs
        .iter()
        .any(|source_ref| !evidence_refs.contains(source_ref))
    {
        return Err(rejected(
            "canonical disposition evidence does not cover source provenance",
        ));
    }
    let mut verifier_refs = require_raw_verifiers(store, contract, terminal).await?;
    verifier_refs.push(format!("verification:{}", chain.verification_id));
    Ok(DispositionAuthority {
        session_id,
        role_lease_id,
        evidence_refs,
        verifier_refs,
    })
}

/// Resolves the two reciprocal cognitive source dispositions entirely from canonical store state.
/// Editable harness artifacts are deliberately not accepted as inputs.
pub async fn resolve_canonical_case_dispositions(
    store: &CanonicalStore,
    contract_record: &CanonicalRecord<CognitiveRunContract>,
    now: OffsetDateTime,
) -> Result<Vec<CanonicalCaseDisposition>, EngineError> {
    let contract = &contract_record.receipt_body;
    let mut terminals = store
        .canonical_records_by_subject_ref::<CognitiveRunTerminal>(
            contract.project_id,
            Some(contract.task_id),
            &["cognitive_run_terminal"],
            &contract.run_id,
            64,
        )
        .await?;
    terminals.retain(|record| record.receipt_body.run_id == contract.run_id);
    let mut dispositions = Vec::with_capacity(2);
    for source_call in [5_u8, 7_u8] {
        let terminal = terminals
            .iter()
            .find(|record| record.receipt_body.call_number == source_call)
            .ok_or_else(|| rejected(format!("source terminal call {source_call} is absent")))?;
        if terminal.receipt_body.status != CognitiveRunCallStatus::Succeeded {
            return Err(rejected(format!(
                "source terminal call {source_call} did not succeed"
            )));
        }
        let call = contract
            .exact_plan
            .iter()
            .find(|call| call.call_number == source_call)
            .ok_or_else(|| rejected(format!("source plan call {source_call} is absent")))?;
        let (candidate_receipt, claim_id, claim) =
            canonical_source_candidate(store, contract, terminal, call).await?;
        let chain =
            canonical_disposition_chain(store, contract, &candidate_receipt, claim_id, &claim)
                .await?;
        let authority =
            canonical_disposition_authority(store, contract, terminal, &chain, now).await?;
        dispositions.push(CanonicalCaseDisposition {
            case_id: call.case_id.clone(),
            task_id: contract.task_id,
            candidate_result_id: candidate_receipt.write_id.to_string(),
            disposition_id: chain.receipt.write_id.to_string(),
            disposition_kind: AgentResultDispositionKind::Accepted,
            actor_session_id: authority.session_id,
            actor_role_lease_id: authority.role_lease_id,
            evidence_refs: authority.evidence_refs,
            verifier_refs: authority.verifier_refs,
            write_receipt_id: chain.receipt.receipt_id,
            task_revision_before: chain.revision_before,
            task_revision_after: chain.revision_after,
            source_commit: contract.source_commit.clone(),
            policy_snapshot_id: contract.policy_snapshot_id.clone(),
            resolved_from_store: true,
        });
    }
    Ok(dispositions)
}
