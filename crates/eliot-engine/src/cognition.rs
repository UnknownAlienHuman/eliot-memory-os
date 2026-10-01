//! Behavioral cognition validation, memory influence accounting, and comparison experiments.
//!
//! Causal candidates (issue #1910) travel the same seams: the runtime outcome
//! writer records explicitly assessed intervention outcomes through the
//! owner's own transition, and the uncertainty/inspector projections expose
//! unresolved causal uncertainty and the full A6.5 field set without ever
//! collapsing rivals into one explanation.

use crate::{EngineError, WriteAdmissionService, WriterHandle};
use eliot_types::cognition::{
    CAUSAL_DISCRIMINATIVE_CHECK_WORK_CLASS, CausalCandidate, CausalCheckAssignment,
    CausalEdgeStatus, CausalInterventionOutcomeRecord,
};
use eliot_types::{
    AgentId, AgentSessionId, CommandContext, ContextCargoReceipt, LifecycleStatus,
    MemoryAdmissionDecision, MemoryDecisionReceipt, MemoryInfluenceClass, MemoryInfluenceTrace,
    MemoryValueComparison, MemoryValueExperiment, OBSERVABILITY_SCHEMA_VERSION, ObservabilityKind,
    ObservabilityWriteEnvelope, ObservabilityWriteReceipt, PlanningDecisionRecord, ProjectId,
    SemanticCommand, SessionId, TaintClass, TaskId, ToolObservationRecordCommand,
    UnderstandingOutcomeRecord, Visibility, WorkItemId, WriteId, WriteReceiptRef,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;
use time::OffsetDateTime;

mod understanding_outcome;
pub use understanding_outcome::UnderstandingOutcomeService;

#[derive(Clone, Copy, Debug, Default)]
pub struct MemoryInfluenceTraceService;

#[allow(clippy::fn_params_excessive_bools, clippy::too_many_arguments)]
impl MemoryInfluenceTraceService {
    pub fn trace(
        task_id: TaskId,
        session_id: AgentSessionId,
        packet_id: String,
        decision: &MemoryDecisionReceipt,
        cited_in_understanding_proof: bool,
        action_or_probe_changed: bool,
        write_set_changed: bool,
        verifier_changed: bool,
        repeated_failure_prevented: bool,
        downstream_outcome_ref: Option<String>,
    ) -> MemoryInfluenceTrace {
        let suppressed_as_stale_or_wrong_scope = matches!(
            decision.admission,
            MemoryAdmissionDecision::SuppressStale | MemoryAdmissionDecision::SuppressWrongScope
        );
        let influence_class = if decision.admission == MemoryAdmissionDecision::SuppressWrongScope {
            MemoryInfluenceClass::SuppressedAsWrongScope
        } else if decision.admission == MemoryAdmissionDecision::SuppressStale {
            MemoryInfluenceClass::SuppressedAsStale
        } else if repeated_failure_prevented {
            MemoryInfluenceClass::PreventedRepeatedFailure
        } else if action_or_probe_changed || write_set_changed {
            MemoryInfluenceClass::UsedAndChangedAction
        } else if verifier_changed {
            MemoryInfluenceClass::UsedForVerification
        } else if cited_in_understanding_proof {
            MemoryInfluenceClass::SeenButNotUsed
        } else {
            MemoryInfluenceClass::LoadedWithoutDelta
        };
        MemoryInfluenceTrace {
            task_id,
            session_id,
            memory_handle: decision.memory_handle.clone(),
            packet_id,
            admission_decision: decision.admission,
            inclusion_or_suppression_reason: decision.freshness.clone(),
            epistemic_status_at_use: decision.status.clone(),
            cited_in_understanding_proof,
            action_or_probe_changed,
            write_set_changed,
            verifier_changed,
            repeated_failure_prevented,
            suppressed_as_stale_or_wrong_scope,
            downstream_outcome_ref,
            influence_class,
            canonical_receipt: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ContextCargoService;

impl ContextCargoService {
    pub fn receipt(
        task_id: TaskId,
        session_id: AgentSessionId,
        memory_handle: String,
        packet_load_count: u32,
        decision_delta_count: u32,
        verifier_delta_count: u32,
    ) -> ContextCargoReceipt {
        let loaded_without_delta = decision_delta_count == 0 && verifier_delta_count == 0;
        ContextCargoReceipt {
            receipt_id: format!("context-cargo-{}", WriteId::new_v7()),
            task_id,
            session_id,
            memory_handle,
            packet_load_count,
            decision_delta_count,
            verifier_delta_count,
            disposition: if loaded_without_delta {
                MemoryInfluenceClass::LoadedWithoutDelta
            } else {
                MemoryInfluenceClass::UsedAndChangedAction
            },
            demotion_candidate: loaded_without_delta && packet_load_count >= 3,
            reason: if loaded_without_delta {
                "loaded repeatedly without decision or verifier delta".to_owned()
            } else {
                "retained because an observable decision or verifier delta exists".to_owned()
            },
            generated_at: OffsetDateTime::now_utc(),
            canonical_receipt: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CognitiveExperimentService;

impl CognitiveExperimentService {
    pub fn compare_memory_value(
        experiment: &MemoryValueExperiment,
        control: PlanningDecisionRecord,
        treatment: PlanningDecisionRecord,
    ) -> Result<MemoryValueComparison, EngineError> {
        if experiment.task_b_hash.trim().is_empty()
            || experiment.host_model_harness.trim().is_empty()
            || experiment.contamination_controls.is_empty()
        {
            return Err(EngineError::WriteRejected(
                "memory-value experiment requires a frozen task hash, host/model/harness, and contamination controls"
                    .to_owned(),
            ));
        }
        let mut changed_dimensions = Vec::new();
        if control.first_action_or_probe != treatment.first_action_or_probe {
            changed_dimensions.push("first_action_or_probe".to_owned());
        }
        if control.selected_owner_or_module != treatment.selected_owner_or_module {
            changed_dimensions.push("selected_owner_or_module".to_owned());
        }
        if control.selected_write_set != treatment.selected_write_set {
            changed_dimensions.push("selected_write_set".to_owned());
        }
        if control.selected_verifier != treatment.selected_verifier {
            changed_dimensions.push("selected_verifier".to_owned());
        }
        if control.wrong_path_attempts != treatment.wrong_path_attempts {
            changed_dimensions.push("wrong_path_attempts".to_owned());
        }
        if control.tool_calls_before_correct_boundary
            != treatment.tool_calls_before_correct_boundary
        {
            changed_dimensions.push("tool_calls_before_correct_boundary".to_owned());
        }
        if control.material_unknowns != treatment.material_unknowns {
            changed_dimensions.push("material_unknowns".to_owned());
        }
        let observable_decision_delta = changed_dimensions.iter().any(|dimension| {
            matches!(
                dimension.as_str(),
                "first_action_or_probe"
                    | "selected_owner_or_module"
                    | "selected_write_set"
                    | "selected_verifier"
                    | "wrong_path_attempts"
                    | "tool_calls_before_correct_boundary"
            )
        });
        let treatment_safe = !treatment.selected_verifier.trim().is_empty()
            && !treatment.selected_write_set.is_empty()
            && treatment.wrong_path_attempts <= control.wrong_path_attempts;
        let treatment_more_efficient = treatment.tool_calls_before_correct_boundary
            < control.tool_calls_before_correct_boundary
            || treatment.wrong_path_attempts < control.wrong_path_attempts
            || treatment.estimated_tokens < control.estimated_tokens;
        let treatment_preferred =
            observable_decision_delta && treatment_safe && treatment_more_efficient;
        let reasons = if observable_decision_delta {
            vec![format!(
                "observable delta in {}",
                changed_dimensions.join(",")
            )]
        } else {
            vec!["memory was loaded but produced no observable planning delta".to_owned()]
        };
        Ok(MemoryValueComparison {
            task_b_hash: experiment.task_b_hash.clone(),
            control,
            treatment,
            changed_dimensions,
            observable_decision_delta,
            treatment_preferred,
            reasons,
        })
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CognitiveMemoryWriter;

impl CognitiveMemoryWriter {
    pub async fn write_understanding_outcome(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        project_id: ProjectId,
        record: &mut UnderstandingOutcomeRecord,
    ) -> Result<WriteReceiptRef, EngineError> {
        UnderstandingOutcomeService::validate(record)?;
        let receipt = write_cognitive_observation(
            handle,
            admission,
            project_id,
            record.task_id,
            record.session_id,
            "understanding_outcome_record",
            "cognitive-memory-l8",
            record,
        )
        .await?;
        record.canonical_receipt = Some(receipt.clone());
        Ok(receipt)
    }

    /// Records one explicitly assessed intervention outcome against its causal
    /// candidate and commits the updated candidate beside the appended history
    /// entry.
    ///
    /// Issue #1910 W5/A2: the reachable runtime outcome writer. The state
    /// change is this file's restatement of nothing: it is the owner's own
    /// [`CausalCandidate::record_intervention_outcome`], so the outcome must
    /// name this candidate, its before state must match the candidate's
    /// current edge status, rival set, calibration and transfer boundary, and
    /// its assessment must be complete — otherwise the typed owner refusal
    /// below carries the whole call and nothing is written. On success the
    /// caller's candidate carries the outcome's after state with the outcome
    /// appended to its append-only history, so the before/after linkage
    /// outlives the pass that observed it and the caller retains exactly what
    /// was committed.
    ///
    /// # Update, not overwrite, and what the record does NOT do
    ///
    /// The document is the updated candidate beside the history entry this
    /// call appended, read back out of the updated value rather than
    /// re-stated, so the durable bytes are one record rather than two that
    /// could drift apart. It carries no permit, no authority and no
    /// activation: a status of `observed-under-intervention` records that an
    /// intervention was observed, it does not promote the mechanism, and a
    /// successful outcome still supports an effect without confirming the
    /// claimed mechanism. The three edge statuses stay three distinct values
    /// chosen only by explicit assessment — recording an outcome never
    /// promotes a status by itself — and an outcome never erases a rival on
    /// its own: dropping a documented rival without `rival_update_evidence`
    /// is an owner refusal, not a silent edit.
    ///
    /// # Seam and caller
    ///
    /// The write travels the same production seam as every other cognitive
    /// write in this file (`write_cognitive_observation` in
    /// `crates/eliot-engine/src/cognition.rs`, scope `cognitive-memory-l8`),
    /// which is live in production through
    /// `crates/eliot-app/src/mcp_stdio/task_handlers.rs::dispatch_understanding_outcome_record`.
    /// The production caller of THIS writer is STITCH, stated not papered
    /// over: no production path hands it an explicitly assessed causal
    /// outcome yet, so it is reachable API with no caller rather than a
    /// caller that fabricates an assessment.
    pub async fn write_causal_intervention_outcome(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        project_id: ProjectId,
        task_id: TaskId,
        session_id: AgentSessionId,
        candidate: &mut CausalCandidate,
        outcome: CausalInterventionOutcomeRecord,
    ) -> Result<WriteReceiptRef, EngineError> {
        let candidate_id = outcome.candidate_id.clone();
        candidate
            .record_intervention_outcome(outcome)
            .map_err(|error| {
                EngineError::WriteRejected(format!(
                    "causal intervention outcome on candidate {candidate_id} refused: {error}"
                ))
            })?;
        let Some(appended) = candidate.intervention_outcomes.last().cloned() else {
            return Err(EngineError::WriteRejected(format!(
                "causal intervention outcome on candidate {candidate_id} applied but left no history entry"
            )));
        };
        let record = serde_json::json!({
            "causal_candidate": candidate,
            "intervention_outcome": appended,
        });
        write_cognitive_observation(
            handle,
            admission,
            project_id,
            task_id,
            session_id,
            "causal_intervention_outcome",
            "cognitive-memory-l8",
            &record,
        )
        .await
    }

    pub async fn write_memory_influence_trace(
        handle: &WriterHandle,
        project_id: ProjectId,
        write_id: WriteId,
        trace: &MemoryInfluenceTrace,
    ) -> Result<ObservabilityWriteReceipt, EngineError> {
        if matches!(
            trace.influence_class,
            MemoryInfluenceClass::UsedAndChangedAction
                | MemoryInfluenceClass::UsedForVerification
                | MemoryInfluenceClass::PreventedRepeatedFailure
        ) && trace.downstream_outcome_ref.is_none()
        {
            return Err(EngineError::WriteRejected(
                "claimed memory influence requires a downstream outcome reference".to_owned(),
            ));
        }
        let mut canonical_trace = trace.clone();
        canonical_trace.canonical_receipt = None;
        let payload = serde_json::to_value(&canonical_trace)?;
        let kind = ObservabilityKind::MemoryInfluenceTrace;
        let task_id = Some(trace.task_id);
        let session_id = Some(SessionId::from_uuid(trace.session_id.as_uuid()));
        let input_hash = blake3::hash(&serde_json::to_vec(&(
            OBSERVABILITY_SCHEMA_VERSION,
            project_id,
            task_id,
            session_id,
            kind,
            &payload,
        ))?)
        .to_hex()
        .to_string();
        handle
            .submit_observability(ObservabilityWriteEnvelope {
                schema_version: OBSERVABILITY_SCHEMA_VERSION.to_owned(),
                write_id,
                project_id,
                task_id,
                session_id,
                kind,
                record_id: format!("memory-influence:{write_id}"),
                payload,
                input_hash,
                created_at: time::OffsetDateTime::now_utc(),
            })
            .await
    }

    pub async fn write_context_cargo_receipt(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        project_id: ProjectId,
        receipt: &mut ContextCargoReceipt,
    ) -> Result<WriteReceiptRef, EngineError> {
        let write_receipt = write_cognitive_observation(
            handle,
            admission,
            project_id,
            receipt.task_id,
            receipt.session_id,
            "context_cargo_receipt",
            "cognitive-memory-l8",
            receipt,
        )
        .await?;
        receipt.canonical_receipt = Some(write_receipt.clone());
        Ok(write_receipt)
    }

    pub async fn write_semantic_record<T>(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        project_id: ProjectId,
        task_id: TaskId,
        session_id: AgentSessionId,
        kind: &str,
        record: &T,
    ) -> Result<WriteReceiptRef, EngineError>
    where
        T: Serialize,
    {
        const ALLOWED_KINDS: &[&str] = &[
            "cognitive_failure_localization_report",
            "memory_corpus_profile",
            "task_meaning_frame",
            "experience_case",
            "experience_pattern",
            "memory_applicability_decision",
            "context_reinstatement_bundle",
            "negative_transfer_record",
            "cognitive_transfer_lab_report",
            "candidate_reasoning_job_output",
        ];
        if !ALLOWED_KINDS.contains(&kind) {
            return Err(EngineError::WriteRejected(format!(
                "unsupported semantic experience record kind {kind}"
            )));
        }
        let value = serde_json::to_value(record)?;
        if matches!(kind, "experience_case" | "experience_pattern")
            && (value
                .pointer("/authority/current_truth")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
                || value
                    .pointer("/authority/candidate_only")
                    .and_then(serde_json::Value::as_bool)
                    != Some(true))
        {
            return Err(EngineError::WriteRejected(
                "experience records must be candidate-only and may never claim current truth"
                    .to_owned(),
            ));
        }
        write_cognitive_observation(
            handle,
            admission,
            project_id,
            task_id,
            session_id,
            kind,
            "cognitive-memory-l9",
            record,
        )
        .await
    }
}

/// One admitted causal candidate as the Active View exposes it: its identity,
/// its current edge status, and the rivals or no-rival rationale that keep
/// its mechanism uncertain.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CausalUncertaintyEntry {
    /// Candidate this entry projects; never a second construction.
    pub candidate_id: String,
    /// Current edge status: hypothetical, supported, or
    /// observed-under-intervention. The three values stay distinct here.
    pub edge_status: CausalEdgeStatus,
    /// Rival explanations still standing against the claimed mechanism.
    pub rival_explanations: Vec<String>,
    /// Explicit rationale when no plausible rival exists.
    pub no_plausible_rival_rationale: Option<String>,
    /// True while the mechanism is unresolved: the edge was never observed
    /// under intervention, or rivals still stand. An entry with false here
    /// records that an intervention was observed and no rival stands; it does
    /// not promote the mechanism — only explicit assessment does, and only
    /// the owner's transition changes status.
    pub unresolved_uncertainty: bool,
}

/// The Active View's causal section: every admitted candidate, none collapsed
/// into one explanation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CausalUncertaintyView {
    /// One entry per admitted candidate, in admission order. The view ranks
    /// nothing, selects no winner, and carries no single-explanation field.
    pub entries: Vec<CausalUncertaintyEntry>,
    /// Entries with `unresolved_uncertainty` set.
    pub unresolved_count: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CausalUncertaintyViewService;

impl CausalUncertaintyViewService {
    /// Admits owner-validated causal candidates and projects the Active View's
    /// causal section over them.
    ///
    /// Issue #1910 W6: unresolved causal uncertainty is exposed, never
    /// collapsed into one explanation. Admission is the owner's own
    /// [`CausalCandidate::validate_material`] — the full A6.5 field set plus
    /// rival-or-rationale plus a valid intervention history — and the whole
    /// projection is refused when any candidate is not material, so an
    /// unvalidated causal claim is never projected. The projection itself is
    /// total over the admitted set: one entry per candidate with its status
    /// and its rivals intact.
    ///
    /// Active View wiring is STITCH, stated not papered over:
    /// `crates/smart/eliot-context-assembly/src/assemble.rs::assemble_active_view`
    /// takes no causal candidates yet, so no production reader pages this
    /// projection. This service is the admitted-set surface that reader
    /// embeds when it arrives, not a second Active View scheme.
    pub fn project(candidates: &[CausalCandidate]) -> Result<CausalUncertaintyView, EngineError> {
        let mut entries = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            candidate.validate_material().map_err(|error| {
                EngineError::WriteRejected(format!(
                    "causal candidate {} is not material: {error}",
                    candidate.candidate_id
                ))
            })?;
            entries.push(CausalUncertaintyEntry {
                candidate_id: candidate.candidate_id.clone(),
                edge_status: candidate.edge_status,
                rival_explanations: candidate.rival_explanations.clone(),
                no_plausible_rival_rationale: candidate.no_plausible_rival_rationale.clone(),
                unresolved_uncertainty: candidate.edge_status
                    != CausalEdgeStatus::ObservedUnderIntervention
                    || !candidate.rival_explanations.is_empty(),
            });
        }
        let unresolved_count = entries
            .iter()
            .filter(|entry| entry.unresolved_uncertainty)
            .count();
        Ok(CausalUncertaintyView {
            entries,
            unresolved_count,
        })
    }
}

/// Everything a production inspector reads for one material causal
/// recommendation: the full A6.5 field set, the current edge status and
/// calibration, and the linked verification work unit.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CausalCandidateInspectorView {
    /// Candidate under inspection.
    pub candidate_id: String,
    /// Claimed causal mechanism.
    pub mechanism: String,
    /// Intervention the mechanism is claimed under.
    pub intervention: String,
    /// Preregistered predicted observable.
    pub predicted_observable: String,
    /// Counterfactual: what would be observed if the mechanism did not hold.
    pub counterfactual: String,
    /// Possible confounders of the claimed effect.
    pub possible_confounders: Vec<String>,
    /// Causes interacting with the claimed mechanism.
    pub interacting_causes: Vec<String>,
    /// Temporal lag between intervention and observable effect.
    pub temporal_lag: String,
    /// Abstraction level of the claim.
    pub abstraction_level: String,
    /// Rival explanations still standing.
    pub rival_explanations: Vec<String>,
    /// Explicit rationale when no plausible rival exists.
    pub no_plausible_rival_rationale: Option<String>,
    /// Boundary the claim does not transfer beyond without new evidence.
    pub transfer_boundary: String,
    /// Current edge status: hypothetical, supported, or
    /// observed-under-intervention.
    pub edge_status: CausalEdgeStatus,
    /// Current calibration of the claim.
    pub calibration: String,
    /// Assigned discriminative check, when one is assigned: the verifier
    /// work item or bounded inquiry a Critical action depends on.
    pub assigned_check: Option<CausalCheckAssignment>,
    /// Linked verification work unit, when the assigned check is one.
    pub verifier_work_item: Option<WorkItemId>,
    /// Bounded inquiry text, when the assigned check is one.
    pub bounded_inquiry: Option<String>,
    /// Recorded explicitly assessed intervention outcomes against this
    /// candidate.
    pub recorded_outcome_count: usize,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CausalCandidateInspectorService;

impl CausalCandidateInspectorService {
    /// The I14.1 work class every causal discriminative check is submitted
    /// through: whichever check form is assigned, the check that makes a
    /// causal claim load-bearing stays a verification-class work unit.
    pub fn discriminative_check_work_class() -> &'static str {
        CAUSAL_DISCRIMINATIVE_CHECK_WORK_CLASS
    }

    /// Projects the inspector view of one material causal candidate.
    ///
    /// Issue #1910 A1: for a material causal recommendation, an inspector
    /// sees the mechanism, the predicted observable, the counterfactual, the
    /// confounder and rival fields, the transfer boundary, and the linked
    /// verification work unit. Admission is the owner's own
    /// [`CausalCandidate::validate_material`], so an unvalidated candidate is
    /// refused rather than rendered. The view is a pure read: it assigns no
    /// check, admits no claim for a Critical action, and promotes nothing —
    /// the Critical-action gate stays the owner's
    /// [`CausalCandidate::validate_for_critical_action`].
    ///
    /// The production inspector path is STITCH, stated not papered over: no
    /// production inspector reads this view yet. The view is the typed
    /// inspector surface that path renders when it arrives.
    pub fn inspect(
        candidate: &CausalCandidate,
    ) -> Result<CausalCandidateInspectorView, EngineError> {
        candidate.validate_material().map_err(|error| {
            EngineError::WriteRejected(format!(
                "causal candidate {} is not material: {error}",
                candidate.candidate_id
            ))
        })?;
        let (verifier_work_item, bounded_inquiry) = match &candidate.assigned_check {
            Some(CausalCheckAssignment::VerifierWorkItem(work_item_id)) => {
                (Some(*work_item_id), None)
            }
            Some(CausalCheckAssignment::BoundedInquiry(description)) => {
                (None, Some(description.clone()))
            }
            None => (None, None),
        };
        Ok(CausalCandidateInspectorView {
            candidate_id: candidate.candidate_id.clone(),
            mechanism: candidate.mechanism.clone(),
            intervention: candidate.intervention.clone(),
            predicted_observable: candidate.predicted_observable.clone(),
            counterfactual: candidate.counterfactual.clone(),
            possible_confounders: candidate.possible_confounders.clone(),
            interacting_causes: candidate.interacting_causes.clone(),
            temporal_lag: candidate.temporal_lag.clone(),
            abstraction_level: candidate.abstraction_level.clone(),
            rival_explanations: candidate.rival_explanations.clone(),
            no_plausible_rival_rationale: candidate.no_plausible_rival_rationale.clone(),
            transfer_boundary: candidate.transfer_boundary.clone(),
            edge_status: candidate.edge_status,
            calibration: candidate.calibration.clone(),
            assigned_check: candidate.assigned_check.clone(),
            verifier_work_item,
            bounded_inquiry,
            recorded_outcome_count: candidate.intervention_outcomes.len(),
        })
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_cognitive_observation<T>(
    handle: &WriterHandle,
    admission: &WriteAdmissionService,
    project_id: ProjectId,
    task_id: TaskId,
    session_id: AgentSessionId,
    kind: &str,
    scope: &str,
    body: &T,
) -> Result<WriteReceiptRef, EngineError>
where
    T: Serialize,
{
    let body = serde_json::to_value(body)?;
    let (write_id, agent_id) = if scope == "cognitive-memory-l9" {
        deterministic_semantic_context_ids(project_id, kind, &body)?
    } else {
        (WriteId::new_v7(), AgentId::new_v7())
    };
    let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
        context: CommandContext {
            write_id,
            agent_id,
            session_id: Some(SessionId::from_uuid(session_id.as_uuid())),
            project_id,
            task_id: Some(task_id),
            scope: scope.to_owned(),
            authority: "local-cognitive-loop".to_owned(),
            visibility: Visibility::Internal,
            taint: TaintClass::LocalVerified,
            lifecycle_status: LifecycleStatus::Active,
        },
        tool_name: if scope == "cognitive-memory-l9" {
            "eliot_semantic_memory".to_owned()
        } else {
            "eliot_cognitive_memory".to_owned()
        },
        observation: format!("Cognitive {kind} written through WriterActor"),
        payload: json!({
            "receipt_kind": kind,
            "receipt_body": body,
            "writer_path": "semantic_command_writer_actor"
        }),
    });
    let envelope = admission.admit(&command)?;
    let receipt = handle.submit(envelope).await?;
    Ok(WriteReceiptRef {
        receipt_id: receipt.receipt_id,
        write_id: receipt.write_id,
    })
}

fn deterministic_semantic_context_ids(
    project_id: ProjectId,
    kind: &str,
    body: &serde_json::Value,
) -> Result<(WriteId, AgentId), EngineError> {
    let material = serde_json::to_vec(&(project_id, kind, body))?;
    let write_id = deterministic_uuid_text(b"eliot-l9-write", &material);
    let agent_id = deterministic_uuid_text(b"eliot-l9-agent", &material);
    Ok((
        WriteId::from_str(&write_id).map_err(|error| {
            EngineError::WriteRejected(format!("invalid deterministic semantic write id: {error}"))
        })?,
        AgentId::from_str(&agent_id).map_err(|error| {
            EngineError::WriteRejected(format!("invalid deterministic semantic agent id: {error}"))
        })?,
    ))
}

fn deterministic_uuid_text(domain: &[u8], material: &[u8]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    hasher.update(&[0]);
    hasher.update(material);
    let hex = hasher.finalize().to_hex().to_string();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_types::{
        CausalBridgeHop, MemoryAdmissionDecision, MemoryDecisionReceipt, UnderstandingOutcome,
        VerificationResult,
    };

    fn decision(task_id: TaskId, admission: MemoryAdmissionDecision) -> MemoryDecisionReceipt {
        MemoryDecisionReceipt {
            task_id,
            memory_handle: "claim:memory".to_owned(),
            source_and_anchor: "source:file:10".to_owned(),
            scope: vec!["project:test".to_owned()],
            status: "verified".to_owned(),
            freshness: "exact scope".to_owned(),
            authority: "canonical_evidence_chain".to_owned(),
            conflicts: Vec::new(),
            admission,
            action_effect: "not_yet_observed".to_owned(),
            verifier_effect: "not_yet_observed".to_owned(),
            future_activation: "revalidate on revision".to_owned(),
            canonical_receipt: None,
        }
    }

    #[test]
    fn packet_inclusion_without_delta_is_not_claimed_as_influence() {
        let task_id = TaskId::new_v7();
        let trace = MemoryInfluenceTraceService::trace(
            task_id,
            AgentSessionId::new_v7(),
            "eliot/packet/test".to_owned(),
            &decision(task_id, MemoryAdmissionDecision::IncludeVerified),
            false,
            false,
            false,
            false,
            false,
            None,
        );
        assert_eq!(
            trace.influence_class,
            MemoryInfluenceClass::LoadedWithoutDelta
        );
    }

    #[test]
    fn wrong_scope_suppression_is_an_observable_memory_decision() {
        let task_id = TaskId::new_v7();
        let trace = MemoryInfluenceTraceService::trace(
            task_id,
            AgentSessionId::new_v7(),
            "eliot/packet/test".to_owned(),
            &decision(task_id, MemoryAdmissionDecision::SuppressWrongScope),
            false,
            false,
            false,
            false,
            false,
            Some("outcome:current-truth-won".to_owned()),
        );
        assert_eq!(
            trace.influence_class,
            MemoryInfluenceClass::SuppressedAsWrongScope
        );
        assert!(trace.suppressed_as_stale_or_wrong_scope);
    }

    #[test]
    fn validated_understanding_requires_reality_linked_verifier() -> Result<(), EngineError> {
        let task_id = TaskId::new_v7();
        let record = UnderstandingOutcomeRecord {
            task_id,
            session_id: AgentSessionId::new_v7(),
            packet_id: "eliot/packet/test".to_owned(),
            expected_owner_or_module: "context".to_owned(),
            selected_owner_or_module: "context".to_owned(),
            proposed_causal_bridge: vec![CausalBridgeHop {
                from: "intent".to_owned(),
                relation: "owned_by".to_owned(),
                to: "context".to_owned(),
                evidence_ref: Some("file:context.rs".to_owned()),
            }],
            exact_handles_used: vec!["file:context.rs".to_owned()],
            predicted_observable: "test passes".to_owned(),
            selected_probe_or_action: "edit context".to_owned(),
            selected_write_set: vec!["crates/eliot-engine/src/context.rs".to_owned()],
            selected_verifier: "cargo test packet".to_owned(),
            actual_changed_artifacts: vec!["crates/eliot-engine/src/context.rs".to_owned()],
            actual_observation: "focused test passed".to_owned(),
            verifier_result: VerificationResult::Passed,
            causal_bridge_validated: true,
            wrong_path_attempts: 0,
            avoidable_tool_calls: 0,
            revision_required: false,
            outcome: UnderstandingOutcome::Validated,
            evidence_refs: vec!["verification:packet".to_owned()],
            canonical_receipt: None,
        };
        UnderstandingOutcomeService::validate(&record)?;
        Ok(())
    }

    #[test]
    fn context_cargo_proposes_but_does_not_apply_demotion() {
        let receipt = ContextCargoService::receipt(
            TaskId::new_v7(),
            AgentSessionId::new_v7(),
            "claim:unused".to_owned(),
            3,
            0,
            0,
        );
        assert!(receipt.demotion_candidate);
        assert_eq!(
            receipt.disposition,
            MemoryInfluenceClass::LoadedWithoutDelta
        );
        assert!(receipt.canonical_receipt.is_none());
    }

    fn planning(
        action: &str,
        owner: &str,
        verifier: &str,
        wrong_paths: u32,
    ) -> PlanningDecisionRecord {
        PlanningDecisionRecord {
            first_action_or_probe: action.to_owned(),
            selected_owner_or_module: owner.to_owned(),
            selected_write_set: vec![format!("crates/{owner}")],
            selected_verifier: verifier.to_owned(),
            wrong_path_attempts: wrong_paths,
            tool_calls_before_correct_boundary: wrong_paths + 1,
            material_unknowns: Vec::new(),
            confidence: 0.8,
            estimated_tokens: 500 + wrong_paths as usize * 100,
            latency_ms: 100,
        }
    }

    fn memory_experiment() -> MemoryValueExperiment {
        MemoryValueExperiment {
            task_b_hash: "task-b-hash".to_owned(),
            host_model_harness: "same-host-model-harness".to_owned(),
            current_truth_snapshot: eliot_types::CurrentTruthSnapshot {
                project_id: ProjectId::new_v7(),
                task_id: "task-b".to_owned(),
                branch: "main".to_owned(),
                commit: "abc".to_owned(),
                environment: vec!["windows".to_owned()],
                revision_fence: eliot_types::MemoryRevision::new(1),
                captured_at: OffsetDateTime::now_utc(),
            },
            reusable_memory_handles: vec!["claim:owner".to_owned()],
            stale_or_wrong_scope_control_handles: vec!["claim:stale".to_owned()],
            expected_decision_delta: vec!["selected_owner_or_module".to_owned()],
            primary_metrics: vec!["correct_first_boundary".to_owned()],
            counter_metrics: vec!["packet_bloat".to_owned()],
            contamination_controls: vec!["fresh isolated sessions".to_owned()],
        }
    }

    #[test]
    fn memory_value_comparison_requires_observable_delta() -> Result<(), EngineError> {
        let decision = planning("inspect", "eliot-engine", "cargo test", 0);
        let comparison = CognitiveExperimentService::compare_memory_value(
            &memory_experiment(),
            decision.clone(),
            decision,
        )?;
        assert!(!comparison.observable_decision_delta);
        assert!(!comparison.treatment_preferred);
        Ok(())
    }

    #[test]
    fn memory_value_comparison_prefers_safer_more_efficient_treatment() -> Result<(), EngineError> {
        let comparison = CognitiveExperimentService::compare_memory_value(
            &memory_experiment(),
            planning("search all crates", "wrong-owner", "cargo check", 2),
            planning("inspect context compiler", "eliot-engine", "cargo test", 0),
        )?;
        assert!(comparison.observable_decision_delta);
        assert!(comparison.treatment_preferred);
        assert!(
            comparison
                .changed_dimensions
                .contains(&"selected_verifier".to_owned())
        );
        Ok(())
    }
}
