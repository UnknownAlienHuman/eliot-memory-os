use crate::{EngineError, WorkState, WriteAdmissionService, WriterHandle};
use eliot_types::{
    AgentId, AgentSessionId, BlackboardItem, BlackboardItemId, BlackboardItemKind,
    BlackboardItemStatus, BlackboardScope, CanonicalReplayExecutionRecord,
    CanonicalReplayObservationEvidence, CanonicalTraceCompletenessContract, CanonicalTraceEvidence,
    CanonicalTraceEvidenceKind, CanonicalTraceEvidenceSource, CanonicalTraceReceiptBinding,
    CommandContext, ConfidenceLevel, DreamCandidate, DreamCandidateId, DreamCandidateKind,
    LifecycleStatus, MailboxMessage, MailboxMessageId, MailboxMessageKind, MailboxMessageStatus,
    MailboxRecipient, MemoryRevision, MemorySynthesisTaint, MemorySynthesisTaintReason,
    MissingTracePart, ProhibitedDreamEffect, ProjectId, ReplayAudit, ReplayCase, ReplayCaseId,
    ReplayCaseKind, ReplayCaseResult, ReplayCaseStatus, ReplayDecision, ReplayInputSnapshot,
    ReplayMeasurement, ReplayMeasurementResult, ReplayRun, ReplayRunId, ReplayRunProfile,
    ReplayRunStatus, ReplaySet, ReplaySetId, ReplaySetRole, ReplaySuccessCriterion, ReplayVerdict,
    SealedReplayCaseRecord, SealedReplayInputSnapshotRecord, SealedReplaySetRecord,
    SemanticCommand, SkillReplayRequirement, SleepCandidateArtifact, SleepCandidateArtifactKind,
    SleepConsolidationBundle, SleepConsolidationRun, SleepConsolidationStatus, SleepInputScope,
    SleepOutputKind, SleepOutputRef, SleepTrigger, TaintClass, TaskId,
    ToolObservationRecordCommand, TraceCompletenessContract, Visibility, WriteId, WriteReceiptRef,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct TraceCompletenessInput {
    pub project_id: ProjectId,
    pub task_id: Option<TaskId>,
    pub trace_ref: String,
    pub present_refs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct CanonicalTraceCompletenessInput {
    pub project_id: ProjectId,
    pub task_id: TaskId,
    pub source_task_revision: MemoryRevision,
    pub trace_ref: String,
    pub evidence: Vec<CanonicalTraceEvidence>,
}

#[derive(Clone, Debug)]
pub struct ReplaySealInput {
    pub set: ReplaySet,
    pub role: ReplaySetRole,
    pub version: u64,
    pub evaluator_version: String,
    pub context_version: String,
    pub cases: Vec<ReplayCase>,
    pub snapshots: Vec<ReplayInputSnapshot>,
}

#[derive(Clone, Debug)]
pub struct ReplaySealBundle {
    pub set: SealedReplaySetRecord,
    pub cases: Vec<SealedReplayCaseRecord>,
    pub snapshots: Vec<SealedReplayInputSnapshotRecord>,
}

#[derive(Clone, Debug)]
pub struct CanonicalReplayExecutionInput {
    pub sealed_set: SealedReplaySetRecord,
    pub cases: Vec<SealedReplayCaseRecord>,
    pub snapshots: Vec<SealedReplayInputSnapshotRecord>,
    pub trace_contracts: Vec<CanonicalTraceCompletenessContract>,
    pub observations: Vec<CanonicalReplayObservationEvidence>,
    pub baseline_ref: String,
    pub candidate_ref: String,
    pub candidate_version: String,
    pub mutation_attempt: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ReplayCaseInput {
    pub project_id: ProjectId,
    pub source_task_id: Option<TaskId>,
    pub case_kind: ReplayCaseKind,
    pub trace_contract_ref: String,
    pub input_snapshot_refs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ReplaySetInput {
    pub project_id: ProjectId,
    pub name: String,
    pub purpose: String,
    pub cases: Vec<ReplayCaseId>,
    pub fixed: bool,
    pub holdout: bool,
    pub created_from_refs: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct SleepRunInput {
    pub project_id: ProjectId,
    pub trigger: SleepTrigger,
    pub dry_run: bool,
    pub input_traces: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ReplayCaseObservation {
    pub replay_case_id: ReplayCaseId,
    pub produced_refs: Vec<String>,
    pub denied_actions: Vec<String>,
    pub taint_preserved: bool,
    pub duration_ms: u64,
}

#[derive(Clone, Debug)]
pub struct SealedReplayInput {
    pub project_id: ProjectId,
    pub set: ReplaySet,
    pub cases: Vec<ReplayCase>,
    pub trace_contracts: Vec<TraceCompletenessContract>,
    pub observations: Vec<ReplayCaseObservation>,
    pub baseline_ref: String,
    pub candidate_ref: String,
    pub candidate_version: String,
    pub sealed_context_version: String,
    pub mutation_attempt: Option<String>,
}

pub struct TraceCompletenessService;

impl TraceCompletenessService {
    #[allow(clippy::too_many_arguments)]
    pub fn receipt_evidence(
        kind: CanonicalTraceEvidenceKind,
        project_id: ProjectId,
        task_id: TaskId,
        memory_revision: MemoryRevision,
        reference: String,
        binding: CanonicalTraceReceiptBinding,
        taint: TaintClass,
    ) -> Result<CanonicalTraceEvidence, EngineError> {
        let canonical_kind = kind.as_str().to_owned();
        let content_hash = canonical_hash(&serde_json::json!({
            "kind": kind,
            "canonical_kind": canonical_kind,
            "project_id": project_id,
            "task_id": task_id,
            "memory_revision": memory_revision,
            "reference": reference,
            "binding": binding,
            "taint": taint,
        }))?;
        Ok(CanonicalTraceEvidence {
            kind,
            canonical_kind,
            project_id,
            task_id,
            memory_revision,
            reference,
            content_hash,
            taint,
            source: CanonicalTraceEvidenceSource::CanonicalReceipt { binding },
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn derivation_evidence(
        kind: CanonicalTraceEvidenceKind,
        project_id: ProjectId,
        task_id: TaskId,
        memory_revision: MemoryRevision,
        reference: String,
        algorithm_version: String,
        input_refs: Vec<String>,
        input_hashes: Vec<String>,
        taint: TaintClass,
    ) -> Result<CanonicalTraceEvidence, EngineError> {
        if algorithm_version.trim().is_empty()
            || input_refs.is_empty()
            || input_refs.len() != input_hashes.len()
            || input_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
            || input_hashes.iter().any(|hash| !is_blake3_hex(hash))
        {
            return Err(EngineError::WriteRejected(
                "canonical derivation requires a versioned algorithm and paired inputs".to_owned(),
            ));
        }
        let output_hash = canonical_hash(&serde_json::json!({
            "kind": kind,
            "project_id": project_id,
            "task_id": task_id,
            "memory_revision": memory_revision,
            "reference": reference,
            "algorithm_version": algorithm_version,
            "input_refs": input_refs,
            "input_hashes": input_hashes,
            "taint": taint,
        }))?;
        Ok(CanonicalTraceEvidence {
            kind,
            canonical_kind: kind.as_str().to_owned(),
            project_id,
            task_id,
            memory_revision,
            reference,
            content_hash: output_hash.clone(),
            taint,
            source: CanonicalTraceEvidenceSource::EngineDerivation {
                derivation: eliot_types::CanonicalTraceDerivation {
                    algorithm_version,
                    input_refs,
                    input_hashes,
                    output_hash,
                },
            },
        })
    }

    pub fn build_canonical(
        mut input: CanonicalTraceCompletenessInput,
    ) -> Result<CanonicalTraceCompletenessContract, EngineError> {
        if input.trace_ref.trim().is_empty() {
            return Err(EngineError::WriteRejected(
                "canonical trace requires a non-empty trace reference".to_owned(),
            ));
        }
        input.evidence.sort_by_key(|evidence| evidence.kind);
        validate_canonical_trace_evidence(
            input.project_id,
            input.task_id,
            input.source_task_revision,
            &input.evidence,
        )?;
        let evidence_manifest_hash = canonical_hash(&input.evidence)?;
        let contract_hash = canonical_hash(&serde_json::json!({
            "project_id": input.project_id,
            "task_id": input.task_id,
            "source_task_revision": input.source_task_revision,
            "trace_ref": input.trace_ref,
            "evidence_manifest_hash": evidence_manifest_hash,
        }))?;
        let created_at = deterministic_timestamp("trace-contract", &contract_hash)?;
        Ok(CanonicalTraceCompletenessContract {
            contract_id: format!("trace-contract:{contract_hash}"),
            project_id: input.project_id,
            task_id: input.task_id,
            source_task_revision: input.source_task_revision,
            trace_ref: input.trace_ref,
            evidence: input.evidence,
            evidence_manifest_hash,
            replay_allowed: true,
            rejected_reasons: Vec::new(),
            created_at,
        })
    }

    pub fn validate_canonical_contract(
        contract: &CanonicalTraceCompletenessContract,
    ) -> Result<(), EngineError> {
        validate_canonical_trace_evidence(
            contract.project_id,
            contract.task_id,
            contract.source_task_revision,
            &contract.evidence,
        )?;
        let manifest_hash = canonical_hash(&contract.evidence)?;
        let contract_hash = canonical_hash(&serde_json::json!({
            "project_id": contract.project_id,
            "task_id": contract.task_id,
            "source_task_revision": contract.source_task_revision,
            "trace_ref": contract.trace_ref,
            "evidence_manifest_hash": manifest_hash,
        }))?;
        if !contract.replay_allowed
            || !contract.rejected_reasons.is_empty()
            || contract.evidence_manifest_hash != manifest_hash
            || contract.contract_id != format!("trace-contract:{contract_hash}")
        {
            return Err(EngineError::WriteRejected(
                "canonical trace contract identity or authority marker is invalid".to_owned(),
            ));
        }
        Ok(())
    }

    /// Compatibility surface only. Prefix-shaped caller strings are never replay-authoritative.
    pub fn build(input: TraceCompletenessInput) -> eliot_types::TraceCompletenessContract {
        let required = required_trace_refs();
        let mut missing_trace_parts = Vec::new();
        for (reference, part) in required {
            if !input
                .present_refs
                .iter()
                .any(|present| trace_ref_matches(present, reference))
                && !missing_trace_parts.contains(&part)
            {
                missing_trace_parts.push(part);
            }
        }
        let replay_allowed = !input.trace_ref.trim().is_empty() && missing_trace_parts.is_empty();
        eliot_types::TraceCompletenessContract {
            contract_id: format!("legacy-unverified-trace-contract:{}", WriteId::new_v7()),
            project_id: input.project_id,
            task_id: input.task_id,
            trace_ref: input.trace_ref,
            required_inputs: vec!["task_contract".to_owned()],
            required_context_snapshot: vec![
                "context_packet".to_owned(),
                "current_truth_revision".to_owned(),
                "memory_exposure_set".to_owned(),
            ],
            required_tool_records: vec![
                "agent_tool_events".to_owned(),
                "expected_observation".to_owned(),
                "actual_observation".to_owned(),
            ],
            required_verifier_records: vec!["verifier_run".to_owned()],
            required_artifact_refs: vec!["artifact_ref".to_owned(), "finish_decision".to_owned()],
            required_policy_refs: vec![
                "policy_snapshot".to_owned(),
                "model_route".to_owned(),
                "outcome_and_cost".to_owned(),
            ],
            replay_allowed,
            missing_trace_parts,
            created_at: OffsetDateTime::now_utc(),
        }
    }
}

pub struct ReplayCaseService;

impl ReplayCaseService {
    pub fn create(input: ReplayCaseInput) -> Result<ReplayCase, EngineError> {
        if input.trace_contract_ref.trim().is_empty() {
            return Err(EngineError::WriteRejected(
                "replay case requires trace contract".to_owned(),
            ));
        }
        let identity_hash = canonical_hash(&serde_json::json!({
            "project_id": input.project_id,
            "source_task_id": input.source_task_id,
            "case_kind": input.case_kind,
            "trace_contract_ref": input.trace_contract_ref,
            "input_snapshot_refs": input.input_snapshot_refs,
        }))?;
        Ok(ReplayCase {
            replay_case_id: ReplayCaseId::from_uuid(deterministic_uuid(
                "replay-case",
                &identity_hash,
            )),
            project_id: input.project_id,
            source_task_id: input.source_task_id,
            case_kind: input.case_kind,
            input_snapshot_refs: input.input_snapshot_refs,
            expected_observation_refs: vec!["candidate_only".to_owned()],
            expected_verifier_refs: vec!["deterministic-no-mutation".to_owned()],
            forbidden_output_patterns: vec![
                "DONE_VERIFIED".to_owned(),
                "promote".to_owned(),
                "apply".to_owned(),
            ],
            success_criteria: vec![
                ReplaySuccessCriterion {
                    criterion_id: "preserve-taint".to_owned(),
                    description: "candidate taint is preserved".to_owned(),
                    required: true,
                    measurement: ReplayMeasurement::MustPreserveTaint,
                },
                ReplaySuccessCriterion {
                    criterion_id: "no-done".to_owned(),
                    description: "replay output must not finish task".to_owned(),
                    required: true,
                    measurement: ReplayMeasurement::MustNotReturnDoneVerified,
                },
            ],
            trace_contract_ref: input.trace_contract_ref,
            taint: TaintClass::Unknown,
            created_at: deterministic_timestamp("replay-case", &identity_hash)?,
        })
    }
}

pub struct ReplaySetService;

impl ReplaySetService {
    pub fn create(input: ReplaySetInput) -> ReplaySet {
        let identity_hash = canonical_hash(&serde_json::json!({
            "project_id": input.project_id,
            "name": input.name,
            "purpose": input.purpose,
            "cases": input.cases,
            "fixed": input.fixed,
            "holdout": input.holdout,
            "created_from_refs": input.created_from_refs,
        }))
        .unwrap_or_else(|_| blake3::hash(b"invalid-replay-set").to_hex().to_string());
        ReplaySet {
            replay_set_id: ReplaySetId::from_uuid(deterministic_uuid("replay-set", &identity_hash)),
            project_id: input.project_id,
            name: input.name,
            purpose: input.purpose,
            cases: input.cases,
            fixed: input.fixed,
            holdout: input.holdout,
            created_from_refs: input.created_from_refs,
            created_at: deterministic_timestamp("replay-set", &identity_hash)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        }
    }

    pub fn add_case(set: &mut ReplaySet, case_id: ReplayCaseId) -> Result<(), EngineError> {
        if set.fixed {
            return Err(EngineError::WriteRejected(
                "fixed replay set cannot be mutated".to_owned(),
            ));
        }
        if !set.cases.contains(&case_id) {
            set.cases.push(case_id);
        }
        Ok(())
    }
}

pub struct ReplaySafetyGate;

impl ReplaySafetyGate {
    pub fn profile_is_safe(profile: &ReplayRunProfile) -> bool {
        profile.deterministic
            && profile.no_external_network
            && profile.no_mutation
            && profile.allowed_services.iter().all(|service| {
                matches!(
                    service.as_str(),
                    "context_l3" | "candidate_taint" | "gate_decision" | "report"
                )
            })
    }

    pub fn mutation_attempt_blocked(action: &str) -> bool {
        [
            "promote",
            "apply",
            "truth",
            "policy",
            "permission",
            "patch",
            "finish",
        ]
        .iter()
        .any(|needle| action.contains(needle))
    }
}

pub struct ReplayRunnerService;

pub struct ReplaySealService;

impl ReplaySealService {
    pub fn seal(input: ReplaySealInput) -> Result<ReplaySealBundle, EngineError> {
        validate_replay_seal_membership(&input)?;
        let (set, cases, snapshots) =
            canonicalize_replay_membership(input.set, input.cases, input.snapshots)?;
        let input = ReplaySealInput {
            set,
            cases,
            snapshots,
            ..input
        };
        let profile = ReplayRunnerService::deterministic_no_mutation_profile();
        let evaluator_hash = canonical_hash(&serde_json::json!({
            "engine": "eliot-replay-evaluator",
            "version": input.evaluator_version,
        }))?;
        let profile_hash = canonical_hash(&profile)?;
        let context_hash = canonical_hash(&serde_json::json!({
            "context_version": input.context_version,
        }))?;

        let mut cases = input.cases;
        cases.sort_by_key(|case| case.replay_case_id.to_string());
        let case_records = cases
            .into_iter()
            .map(|case| {
                let case_digest = canonical_hash(&case)?;
                Ok(SealedReplayCaseRecord {
                    record_id: format!("replay-case:{case_digest}"),
                    replay_set_id: input.set.replay_set_id,
                    case,
                    content_hash: case_digest,
                })
            })
            .collect::<Result<Vec<_>, EngineError>>()?;

        let mut snapshots = input.snapshots;
        snapshots.sort_by_key(|snapshot| snapshot.replay_case_id.to_string());
        let snapshot_records = snapshots
            .into_iter()
            .map(|snapshot| {
                let snapshot_digest = canonical_hash(&snapshot)?;
                Ok(SealedReplayInputSnapshotRecord {
                    record_id: format!("replay-snapshot:{snapshot_digest}"),
                    replay_set_id: input.set.replay_set_id,
                    snapshot,
                    content_hash: snapshot_digest,
                })
            })
            .collect::<Result<Vec<_>, EngineError>>()?;

        let case_hashes = case_records
            .iter()
            .map(|record| record.content_hash.clone())
            .collect::<Vec<_>>();
        let snapshot_hashes = snapshot_records
            .iter()
            .map(|record| record.content_hash.clone())
            .collect::<Vec<_>>();
        let sealed_hash = canonical_hash(&serde_json::json!({
            "set": input.set,
            "role": input.role,
            "version": input.version,
            "evaluator_hash": evaluator_hash,
            "profile_hash": profile_hash,
            "context_hash": context_hash,
            "case_hashes": case_hashes,
            "snapshot_hashes": snapshot_hashes,
        }))?;
        let created_at = deterministic_timestamp("sealed-replay-set", &sealed_hash)?;
        let set = SealedReplaySetRecord {
            record_id: format!("replay-set:{sealed_hash}"),
            set: input.set,
            role: input.role,
            version: input.version,
            evaluator_version: input.evaluator_version,
            evaluator_hash,
            profile_hash,
            context_version: input.context_version,
            context_hash,
            case_hashes,
            snapshot_hashes,
            sealed_hash,
            created_at,
        };
        Ok(ReplaySealBundle {
            set,
            cases: case_records,
            snapshots: snapshot_records,
        })
    }
}

impl ReplayRunnerService {
    pub fn deterministic_no_mutation_profile() -> ReplayRunProfile {
        ReplayRunProfile {
            profile_id: "deterministic-no-mutation".to_owned(),
            deterministic: true,
            no_external_network: true,
            no_mutation: true,
            max_runtime_seconds: 30,
            allowed_services: vec![
                "context_l3".to_owned(),
                "candidate_taint".to_owned(),
                "gate_decision".to_owned(),
                "report".to_owned(),
            ],
        }
    }

    pub fn run(
        project_id: ProjectId,
        set: &ReplaySet,
        cases: &[ReplayCase],
        candidate_ref: Option<String>,
        mutation_attempt: Option<&str>,
    ) -> (ReplayRun, ReplayAudit) {
        let started_at = OffsetDateTime::now_utc();
        let profile = Self::deterministic_no_mutation_profile();
        let unsafe_profile = !ReplaySafetyGate::profile_is_safe(&profile);
        let mutation_attempts_blocked = mutation_attempt
            .filter(|attempt| ReplaySafetyGate::mutation_attempt_blocked(attempt))
            .map(|attempt| vec![attempt.to_owned()])
            .unwrap_or_default();
        let case_results = cases
            .iter()
            .map(|case| evaluate_case(case, !mutation_attempts_blocked.is_empty()))
            .collect::<Vec<_>>();
        let missing_trace_parts = cases
            .iter()
            .filter(|case| case.trace_contract_ref.contains("missing"))
            .map(|_| MissingTracePart::ContextPacket)
            .collect::<Vec<_>>();
        let status = if unsafe_profile {
            ReplayRunStatus::BlockedUnsafeProfile
        } else if !missing_trace_parts.is_empty() {
            ReplayRunStatus::BlockedMissingTrace
        } else {
            ReplayRunStatus::Completed
        };
        let replay_run_id = ReplayRunId::new_v7();
        let run = ReplayRun {
            replay_run_id,
            project_id,
            replay_set_id: set.replay_set_id,
            candidate_ref,
            baseline_ref: None,
            run_profile: profile,
            case_results,
            sealed_input_hash: String::new(),
            reproducibility_hash: String::new(),
            uncertainty: String::new(),
            started_at,
            finished_at: Some(OffsetDateTime::now_utc()),
            status,
        };
        let audit = ReplayAudit {
            audit_id: format!("replay-audit-{}", WriteId::new_v7()),
            replay_run_id,
            trace_contract_refs: cases
                .iter()
                .map(|case| case.trace_contract_ref.clone())
                .collect(),
            missing_trace_parts,
            mutation_attempts_blocked,
            taint_preserved: true,
            authority_mutation_blocked: true,
            created_at: OffsetDateTime::now_utc(),
        };
        (run, audit)
    }

    pub fn run_sealed(input: SealedReplayInput) -> Result<(ReplayRun, ReplayAudit), EngineError> {
        validate_sealed_replay_input(&input)?;

        let started_at = OffsetDateTime::now_utc();
        let profile = Self::deterministic_no_mutation_profile();
        let mutation_attempts_blocked = input
            .mutation_attempt
            .as_deref()
            .filter(|attempt| ReplaySafetyGate::mutation_attempt_blocked(attempt))
            .map(|attempt| vec![attempt.to_owned()])
            .unwrap_or_default();
        let observations = input
            .observations
            .iter()
            .map(|observation| (observation.replay_case_id, observation))
            .collect::<BTreeMap<_, _>>();

        let missing_trace_parts = sealed_replay_missing_parts(&input, &observations);

        let blocked_missing_trace = !missing_trace_parts.is_empty();
        let case_results = input
            .cases
            .iter()
            .map(|case| match observations.get(&case.replay_case_id) {
                Some(observation) if !blocked_missing_trace => {
                    evaluate_observed_case(case, observation)
                }
                _ => blocked_case_result(case),
            })
            .collect::<Vec<_>>();
        let sealed_input_hash = sealed_replay_input_hash(&input)?;
        let reproducibility_hash = replay_result_hash(
            &sealed_input_hash,
            &input.baseline_ref,
            &input.candidate_ref,
            &case_results,
        )?;
        let status = if blocked_missing_trace {
            ReplayRunStatus::BlockedMissingTrace
        } else {
            ReplayRunStatus::Completed
        };
        let replay_run_id = ReplayRunId::new_v7();
        let run = ReplayRun {
            replay_run_id,
            project_id: input.project_id,
            replay_set_id: input.set.replay_set_id,
            candidate_ref: Some(input.candidate_ref),
            baseline_ref: Some(input.baseline_ref),
            run_profile: profile,
            case_results,
            sealed_input_hash,
            reproducibility_hash,
            uncertainty: if blocked_missing_trace {
                "incomplete trace contracts excluded from replay".to_owned()
            } else {
                "deterministic replay is bounded to sealed declared observations".to_owned()
            },
            started_at,
            finished_at: Some(OffsetDateTime::now_utc()),
            status,
        };
        let audit = ReplayAudit {
            audit_id: format!("replay-audit-{}", WriteId::new_v7()),
            replay_run_id,
            trace_contract_refs: input
                .cases
                .iter()
                .map(|case| case.trace_contract_ref.clone())
                .collect(),
            missing_trace_parts,
            mutation_attempts_blocked,
            taint_preserved: input.observations.len() == input.cases.len()
                && input
                    .observations
                    .iter()
                    .all(|observation| observation.taint_preserved),
            authority_mutation_blocked: true,
            created_at: OffsetDateTime::now_utc(),
        };
        Ok((run, audit))
    }

    pub fn run_canonical(
        input: CanonicalReplayExecutionInput,
    ) -> Result<CanonicalReplayExecutionRecord, EngineError> {
        validate_canonical_replay_input(&input)?;
        let profile = Self::deterministic_no_mutation_profile();
        let mutation_attempts_blocked = input
            .mutation_attempt
            .as_deref()
            .filter(|attempt| ReplaySafetyGate::mutation_attempt_blocked(attempt))
            .map(|attempt| vec![attempt.to_owned()])
            .unwrap_or_default();
        let mut observation_projection = input.observations.clone();
        observation_projection.sort_by_key(|observation| observation.replay_case_id.to_string());
        for observation in &mut observation_projection {
            observation.evidence.sort_by_key(|evidence| evidence.kind);
        }
        let observation_evidence_hash = canonical_hash(&observation_projection)?;
        let sealed_input_hash = canonical_hash(&serde_json::json!({
            "sealed_set_hash": input.sealed_set.sealed_hash,
            "observation_evidence_hash": observation_evidence_hash,
            "baseline_ref": input.baseline_ref,
            "candidate_ref": input.candidate_ref,
            "candidate_version": input.candidate_version,
        }))?;
        let observations = input
            .observations
            .iter()
            .map(|observation| (observation.replay_case_id, observation))
            .collect::<BTreeMap<_, _>>();
        let case_results = input
            .cases
            .iter()
            .map(|record| {
                observations
                    .get(&record.case.replay_case_id)
                    .map(|observation| {
                        evaluate_canonical_case(&record.case, observation, &sealed_input_hash)
                    })
                    .transpose()?
                    .ok_or_else(|| {
                        EngineError::WriteRejected(
                            "canonical replay observation disappeared after validation".to_owned(),
                        )
                    })
            })
            .collect::<Result<Vec<_>, EngineError>>()?;
        let reproducibility_hash = replay_result_hash(
            &sealed_input_hash,
            &input.baseline_ref,
            &input.candidate_ref,
            &case_results,
        )?;
        let execution_id = format!("sealed-replay:{reproducibility_hash}");
        let replay_run_id =
            ReplayRunId::from_uuid(deterministic_uuid("canonical-replay-run", &execution_id));
        let executed_at = deterministic_timestamp("canonical-replay-execution", &execution_id)?;
        let run = ReplayRun {
            replay_run_id,
            project_id: input.sealed_set.set.project_id,
            replay_set_id: input.sealed_set.set.replay_set_id,
            candidate_ref: Some(input.candidate_ref),
            baseline_ref: Some(input.baseline_ref),
            run_profile: profile,
            case_results,
            sealed_input_hash,
            reproducibility_hash: reproducibility_hash.clone(),
            uncertainty: "bounded to sealed canonical receipts and engine derivations".to_owned(),
            started_at: executed_at,
            finished_at: Some(executed_at),
            status: ReplayRunStatus::Completed,
        };
        let audit = ReplayAudit {
            audit_id: format!("replay-audit:{reproducibility_hash}"),
            replay_run_id,
            trace_contract_refs: input
                .cases
                .iter()
                .map(|record| record.case.trace_contract_ref.clone())
                .collect(),
            missing_trace_parts: Vec::new(),
            mutation_attempts_blocked,
            taint_preserved: true,
            authority_mutation_blocked: true,
            created_at: executed_at,
        };
        Ok(CanonicalReplayExecutionRecord {
            execution_id,
            sealed_set_ref: input.sealed_set.record_id,
            sealed_set_hash: input.sealed_set.sealed_hash,
            evaluator_hash: input.sealed_set.evaluator_hash,
            profile_hash: input.sealed_set.profile_hash,
            context_hash: input.sealed_set.context_hash,
            observation_evidence_hash,
            run,
            audit,
            authoritative_replay: None,
        })
    }

    pub fn validate_canonical_execution_identity(
        execution: &CanonicalReplayExecutionRecord,
    ) -> Result<(), EngineError> {
        let expected_hash = replay_result_hash(
            &execution.run.sealed_input_hash,
            execution.run.baseline_ref.as_deref().unwrap_or_default(),
            execution.run.candidate_ref.as_deref().unwrap_or_default(),
            &execution.run.case_results,
        )?;
        let expected_execution_id = format!("sealed-replay:{expected_hash}");
        let expected_run_id = ReplayRunId::from_uuid(deterministic_uuid(
            "canonical-replay-run",
            &expected_execution_id,
        ));
        let expected_time =
            deterministic_timestamp("canonical-replay-execution", &expected_execution_id)?;
        if execution.run.reproducibility_hash != expected_hash
            || execution.execution_id != expected_execution_id
            || execution.run.replay_run_id != expected_run_id
            || execution.run.started_at != expected_time
            || execution.run.finished_at != Some(expected_time)
            || execution.audit.audit_id != format!("replay-audit:{expected_hash}")
            || execution.audit.replay_run_id != expected_run_id
            || execution.audit.created_at != expected_time
        {
            return Err(EngineError::WriteRejected(
                "canonical replay execution identity is not deterministic".to_owned(),
            ));
        }
        for result in &execution.run.case_results {
            let result_hash = canonical_hash(&serde_json::json!({
                "execution_seed": execution.run.sealed_input_hash,
                "replay_case_id": result.replay_case_id,
                "status": result.status,
                "measurements": result.measurements,
                "produced_refs": result.produced_refs,
                "errors": result.errors,
                "duration_ms": result.duration_ms,
            }))?;
            if result.result_id != format!("replay-result:{result_hash}") {
                return Err(EngineError::WriteRejected(
                    "canonical replay result identity is not deterministic".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

pub struct ReplayVerdictService;

impl ReplayVerdictService {
    pub fn verdict(run: &ReplayRun) -> ReplayVerdict {
        let all_passed = run
            .case_results
            .iter()
            .all(|result| result.status == ReplayCaseStatus::Passed);
        let decision = match run.status {
            ReplayRunStatus::Completed if all_passed => ReplayDecision::Pass,
            ReplayRunStatus::BlockedMissingTrace => ReplayDecision::RequiresMoreCases,
            ReplayRunStatus::BlockedUnsafeProfile => ReplayDecision::UnsafeToPromote,
            ReplayRunStatus::Completed => ReplayDecision::Fail,
            _ => ReplayDecision::Inconclusive,
        };
        let identity = if run.reproducibility_hash.is_empty() {
            run.replay_run_id.to_string()
        } else {
            run.reproducibility_hash.clone()
        };
        ReplayVerdict {
            verdict_id: format!("replay-verdict:{identity}"),
            replay_run_id: run.replay_run_id,
            candidate_ref: run.candidate_ref.clone(),
            decision,
            reasons: vec!["verdict is marker-only and grants no apply authority".to_owned()],
            required_followups: Vec::new(),
            created_at: deterministic_timestamp("replay-verdict", &identity)
                .unwrap_or(OffsetDateTime::UNIX_EPOCH),
        }
    }

    pub fn marker_only_requirement(
        requirement: &SkillReplayRequirement,
        verdict: &ReplayVerdict,
    ) -> SkillReplayRequirement {
        let mut next = requirement.clone();
        if verdict.decision == ReplayDecision::Pass {
            next.replay_marker = Some(verdict.verdict_id.clone());
        }
        next
    }
}

pub struct SleepConsolidationService;

impl SleepConsolidationService {
    pub fn run(
        input: SleepRunInput,
        incident_lockdown_active: bool,
    ) -> Result<SleepConsolidationRun, EngineError> {
        Self::run_internal(input, Vec::new(), incident_lockdown_active)
    }

    pub fn run_with_contracts(
        mut input: SleepRunInput,
        trace_contracts: &[TraceCompletenessContract],
        incident_lockdown_active: bool,
    ) -> Result<SleepConsolidationRun, EngineError> {
        let mut complete_traces = Vec::new();
        let mut excluded = Vec::new();
        for trace_ref in &input.input_traces {
            match trace_contracts
                .iter()
                .find(|contract| contract.trace_ref == *trace_ref)
            {
                Some(contract)
                    if contract.replay_allowed && contract.project_id == input.project_id =>
                {
                    if is_legacy_trace_contract(contract) {
                        excluded.push(contract.contract_id.clone());
                    } else {
                        complete_traces.push(trace_ref.clone());
                    }
                }
                Some(contract) => excluded.push(contract.contract_id.clone()),
                None => excluded.push(format!("missing-contract:{trace_ref}")),
            }
        }
        input.input_traces = complete_traces;
        Self::run_internal(input, excluded, incident_lockdown_active)
    }

    pub fn run_with_artifacts(
        mut input: SleepRunInput,
        trace_contracts: &[CanonicalTraceCompletenessContract],
        incident_lockdown_active: bool,
    ) -> Result<SleepConsolidationBundle, EngineError> {
        let mut complete_traces = Vec::new();
        let mut excluded = Vec::new();
        for trace_ref in &input.input_traces {
            match trace_contracts
                .iter()
                .find(|contract| contract.trace_ref == *trace_ref)
            {
                Some(contract)
                    if contract.replay_allowed
                        && contract.project_id == input.project_id
                        && canonical_hash(&contract.evidence)?
                            == contract.evidence_manifest_hash =>
                {
                    TraceCompletenessService::validate_canonical_contract(contract)?;
                    complete_traces.push(trace_ref.clone());
                }
                Some(contract) => excluded.push(contract.contract_id.clone()),
                None => excluded.push(format!("missing-contract:{trace_ref}")),
            }
        }
        input.input_traces = complete_traces;
        let run = Self::run_internal(input, excluded, incident_lockdown_active)?;
        let source_trace_ref = run.input_traces.first().cloned().ok_or_else(|| {
            EngineError::WriteRejected("sleep trace selection is empty".to_owned())
        })?;
        let source_trace_contract_ref = trace_contracts
            .iter()
            .find(|contract| contract.trace_ref == source_trace_ref)
            .map(|contract| contract.contract_id.clone())
            .ok_or_else(|| {
                EngineError::WriteRejected("sleep trace has no canonical contract".to_owned())
            })?;
        let required_replay = run.replay_requirement.clone();
        let artifacts = run
            .outputs
            .iter()
            .map(|output| {
                let artifact_kind = sleep_artifact_kind(&output.output_ref)?;
                Ok(SleepCandidateArtifact {
                    artifact_id: output.output_ref.clone(),
                    project_id: run.project_id,
                    artifact_kind,
                    source_trace_ref: source_trace_ref.clone(),
                    source_trace_contract_ref: source_trace_contract_ref.clone(),
                    body: serde_json::json!({
                        "schema_version": 1,
                        "sleep_run_ref": run.sleep_run_id,
                        "proposal_kind": artifact_kind.receipt_kind(),
                        "source_trace_count": run.input_traces.len(),
                    }),
                    candidate_only: true,
                    taint: TaintClass::Unknown,
                    prohibited_direct_effects: all_prohibited_dream_effects(),
                    required_replay: required_replay.clone(),
                    created_at: deterministic_timestamp(
                        "sleep-artifact",
                        &format!("{}:{}", run.sleep_run_id, output.output_ref),
                    )?,
                })
            })
            .collect::<Result<Vec<_>, EngineError>>()?;
        let bundle_hash = canonical_hash(&serde_json::json!({
            "run": run,
            "artifacts": artifacts,
        }))?;
        Ok(SleepConsolidationBundle {
            bundle_id: format!("sleep-bundle:{bundle_hash}"),
            bundle_hash,
            run,
            artifacts,
        })
    }

    fn run_internal(
        mut input: SleepRunInput,
        mut excluded_trace_contract_refs: Vec<String>,
        incident_lockdown_active: bool,
    ) -> Result<SleepConsolidationRun, EngineError> {
        if incident_lockdown_active {
            return Err(EngineError::WriteRejected(
                "incident lockdown blocks sleep candidate creation".to_owned(),
            ));
        }
        input.input_traces.retain(|trace| !trace.trim().is_empty());
        input.input_traces.sort();
        input.input_traces.dedup();
        input.input_traces.truncate(20);
        excluded_trace_contract_refs.sort();
        excluded_trace_contract_refs.dedup();
        if input.input_traces.is_empty() {
            return Err(EngineError::WriteRejected(
                "sleep consolidation requires at least one complete input trace".to_owned(),
            ));
        }

        let identity_hash = canonical_hash(&serde_json::json!({
            "project_id": input.project_id,
            "trigger": input.trigger,
            "dry_run": input.dry_run,
            "input_traces": input.input_traces,
            "excluded_trace_contract_refs": excluded_trace_contract_refs,
        }))?;
        let short_digest = &identity_hash[..16];
        let run_timestamp = deterministic_timestamp("sleep-consolidation", &identity_hash)?;
        let recent_failures = input
            .input_traces
            .iter()
            .filter(|trace| {
                let normalized = trace.to_ascii_lowercase();
                normalized.contains("failure") || normalized.contains("failed")
            })
            .cloned()
            .collect::<Vec<_>>();
        let repeated_patterns = vec![format!(
            "{} complete trace(s) selected for bounded candidate synthesis",
            input.input_traces.len()
        )];
        Ok(SleepConsolidationRun {
            sleep_run_id: format!("sleep-run:{identity_hash}"),
            project_id: input.project_id,
            trigger: input.trigger,
            input_scope: SleepInputScope {
                project_id: input.project_id,
                task_ids: Vec::new(),
                memory_refs: input.input_traces.clone(),
                skill_refs: Vec::new(),
                max_trace_count: 20,
                max_age_days: Some(30),
            },
            input_traces: input.input_traces,
            recent_failures,
            repeated_patterns,
            outputs: vec![
                SleepOutputRef {
                    output_ref: format!("procedure-candidate:{short_digest}"),
                    output_kind: SleepOutputKind::ProposedSkillPatch,
                    candidate_only: true,
                },
                SleepOutputRef {
                    output_ref: format!("forgetting-candidate:{short_digest}"),
                    output_kind: SleepOutputKind::ProposedForgettingAction,
                    candidate_only: true,
                },
                SleepOutputRef {
                    output_ref: format!("test-candidate:{short_digest}"),
                    output_kind: SleepOutputKind::ProposedTest,
                    candidate_only: true,
                },
                SleepOutputRef {
                    output_ref: format!("replay-case-candidate:{short_digest}"),
                    output_kind: SleepOutputKind::ReplayCase,
                    candidate_only: true,
                },
                SleepOutputRef {
                    output_ref: format!("dream-candidate:{short_digest}"),
                    output_kind: SleepOutputKind::DreamCandidate,
                    candidate_only: true,
                },
            ],
            excluded_trace_contract_refs,
            reasoning_route_ref: format!("deterministic:sleep-consolidation-v2:{short_digest}"),
            replay_requirement: SkillReplayRequirement {
                required: true,
                reason: "sleep output requires replay before activation".to_owned(),
                replay_marker: None,
                verifier_refs: vec!["deterministic-no-mutation".to_owned()],
            },
            taint: TaintClass::Unknown,
            status: if input.dry_run {
                SleepConsolidationStatus::CompletedCandidateOnly
            } else {
                SleepConsolidationStatus::ReplayRequired
            },
            started_at: run_timestamp,
            finished_at: Some(run_timestamp),
        })
    }
}

pub struct DreamCandidateService;

impl DreamCandidateService {
    pub fn create(
        project_id: ProjectId,
        kind: DreamCandidateKind,
        source_trace: String,
    ) -> (DreamCandidate, MemorySynthesisTaint) {
        let dream_candidate_id = DreamCandidateId::new_v7();
        let candidate_ref = format!("dream:{dream_candidate_id}");
        let candidate = DreamCandidate {
            dream_candidate_id,
            project_id,
            candidate_kind: kind,
            source_traces: vec![source_trace.clone()],
            source_trace_contract_refs: Vec::new(),
            reasoning_route_ref: "deterministic:dream-candidate-v1".to_owned(),
            rationale: "candidate-only deterministic synthesis from existing trace".to_owned(),
            proposed_refs: vec![format!("candidate-ref:{source_trace}")],
            support_refs: vec![source_trace],
            counterevidence_refs: Vec::new(),
            required_reconciliation: vec!["human-or-replay-review-required".to_owned()],
            required_replay: Some(SkillReplayRequirement {
                required: true,
                reason: "dream candidates require replay before activation".to_owned(),
                replay_marker: None,
                verifier_refs: vec!["deterministic-no-mutation".to_owned()],
            }),
            prohibited_direct_effects: vec![
                ProhibitedDreamEffect::CurrentTruth,
                ProhibitedDreamEffect::ActivePolicy,
                ProhibitedDreamEffect::Permission,
                ProhibitedDreamEffect::Completion,
                ProhibitedDreamEffect::SkillPromotion,
                ProhibitedDreamEffect::MemorySuppression,
                ProhibitedDreamEffect::PatchApplication,
            ],
            taint: TaintClass::Unknown,
            created_at: OffsetDateTime::now_utc(),
        };
        let taint = MemorySynthesisTaint {
            taint_id: format!("memory-synthesis-taint-{}", WriteId::new_v7()),
            candidate_ref,
            reason: MemorySynthesisTaintReason::OfflineConsolidation,
            promotion_block: true,
            created_at: OffsetDateTime::now_utc(),
        };
        (candidate, taint)
    }

    pub fn allowed_in_normal_l3(candidate: &DreamCandidate) -> bool {
        candidate.taint == TaintClass::LocalVerified && candidate.required_replay.is_none()
    }

    pub fn route_to_collective(
        state: &mut WorkState,
        project_id: ProjectId,
        task_id: TaskId,
        candidate: &DreamCandidate,
    ) -> (BlackboardItem, MailboxMessage) {
        let item = BlackboardItem {
            blackboard_item_id: BlackboardItemId::new_v7(),
            project_id,
            task_id,
            owner_session_id: AgentSessionId::new_v7(),
            work_item_id: None,
            lease_id: None,
            kind: BlackboardItemKind::HypothesisCandidate,
            scope: BlackboardScope::default(),
            payload_ref: format!("dream:{}", candidate.dream_candidate_id),
            evidence_refs: candidate.support_refs.clone(),
            status: BlackboardItemStatus::Open,
            confidence: Some(ConfidenceLevel::Low),
            created_at: OffsetDateTime::now_utc(),
            expires_at: None,
            acknowledged_by: Vec::new(),
            write_receipt: None,
        };
        let message = MailboxMessage {
            message_id: MailboxMessageId::new_v7(),
            project_id,
            task_id,
            sender_session_id: AgentSessionId::new_v7(),
            recipient: MailboxRecipient::Controller,
            sequence: state.mailbox_messages.len() as u64 + 1,
            kind: MailboxMessageKind::ReviewRequested,
            payload_ref: format!("dream-review:{}", candidate.dream_candidate_id),
            requires_ack: true,
            created_at: OffsetDateTime::now_utc(),
            expires_at: None,
            acknowledged_at: None,
            status: MailboxMessageStatus::Pending,
            write_receipt: None,
        };
        state.blackboard_items.push(item.clone());
        state.mailbox_messages.push(message.clone());
        (item, message)
    }
}

pub struct ReplayMemoryWriter;

impl ReplayMemoryWriter {
    pub async fn write_observation<T: Serialize>(
        handle: &WriterHandle,
        admission: &WriteAdmissionService,
        project_id: ProjectId,
        task_id: Option<TaskId>,
        tool_name: &str,
        observation: &str,
        payload: &T,
    ) -> Result<WriteReceiptRef, EngineError> {
        let command = SemanticCommand::ToolObservationRecord(ToolObservationRecordCommand {
            context: CommandContext {
                write_id: WriteId::new_v7(),
                agent_id: AgentId::new_v7(),
                session_id: None,
                project_id,
                task_id,
                scope: "replay-and-sleep".to_owned(),
                authority: "local-replay-sleep".to_owned(),
                visibility: Visibility::Internal,
                taint: TaintClass::Unknown,
                lifecycle_status: LifecycleStatus::Active,
            },
            tool_name: tool_name.to_owned(),
            observation: observation.to_owned(),
            payload: serde_json::to_value(payload)?,
        });
        let envelope = admission.admit(&command)?;
        let receipt = handle.submit(envelope).await?;
        Ok(WriteReceiptRef {
            receipt_id: receipt.receipt_id,
            write_id: receipt.write_id,
        })
    }
}

fn evaluate_case(case: &ReplayCase, blocked_mutation: bool) -> ReplayCaseResult {
    let measurements = case
        .success_criteria
        .iter()
        .map(|criterion| ReplayMeasurementResult {
            criterion_id: criterion.criterion_id.clone(),
            passed: match &criterion.measurement {
                ReplayMeasurement::MustIncludeRef(reference) => {
                    case.input_snapshot_refs.contains(reference)
                        || case.expected_observation_refs.contains(reference)
                }
                ReplayMeasurement::MustExcludeRef(reference) => {
                    !case.input_snapshot_refs.contains(reference)
                        && !case.expected_observation_refs.contains(reference)
                }
                ReplayMeasurement::MustDenyAction(action) => {
                    ReplaySafetyGate::mutation_attempt_blocked(action)
                }
                ReplayMeasurement::MustRequireVerifier(verifier) => {
                    case.expected_verifier_refs.contains(verifier)
                }
                ReplayMeasurement::MustProduceGateDecision(decision) => {
                    case.expected_observation_refs.contains(decision)
                }
                ReplayMeasurement::MustNotPromoteCandidate
                | ReplayMeasurement::MustNotReturnDoneVerified
                | ReplayMeasurement::MustPreserveTaint => true,
                ReplayMeasurement::MustGenerateReport(report) => !report.trim().is_empty(),
            },
            observed: "deterministic internal replay check".to_owned(),
            evidence_refs: case.input_snapshot_refs.clone(),
        })
        .collect::<Vec<_>>();
    let failed_required = case
        .success_criteria
        .iter()
        .zip(measurements.iter())
        .any(|(criterion, result)| criterion.required && !result.passed);
    ReplayCaseResult {
        result_id: format!("replay-result-{}", WriteId::new_v7()),
        replay_case_id: case.replay_case_id,
        status: if blocked_mutation || !failed_required {
            ReplayCaseStatus::Passed
        } else {
            ReplayCaseStatus::Failed
        },
        measurements,
        produced_refs: vec!["replay-audit".to_owned()],
        errors: Vec::new(),
        duration_ms: 0,
    }
}

fn sealed_replay_missing_parts(
    input: &SealedReplayInput,
    observations: &BTreeMap<ReplayCaseId, &ReplayCaseObservation>,
) -> Vec<MissingTracePart> {
    let mut missing_trace_parts = Vec::new();
    for case in &input.cases {
        match input
            .trace_contracts
            .iter()
            .find(|contract| contract.contract_id == case.trace_contract_ref)
        {
            Some(contract)
                if !is_legacy_trace_contract(contract)
                    && contract.replay_allowed
                    && contract.project_id == input.project_id
                    && contract.task_id == case.source_task_id => {}
            Some(contract) => {
                for part in &contract.missing_trace_parts {
                    push_missing_part(&mut missing_trace_parts, part.clone());
                }
                if contract.missing_trace_parts.is_empty() {
                    push_missing_part(&mut missing_trace_parts, MissingTracePart::TaskContract);
                }
            }
            None => push_missing_part(&mut missing_trace_parts, MissingTracePart::TaskContract),
        }
        if !observations.contains_key(&case.replay_case_id) {
            push_missing_part(&mut missing_trace_parts, MissingTracePart::AgentToolEvents);
        }
    }
    missing_trace_parts
}

fn push_missing_part(parts: &mut Vec<MissingTracePart>, part: MissingTracePart) {
    if !parts.contains(&part) {
        parts.push(part);
    }
}

fn validate_sealed_replay_input(input: &SealedReplayInput) -> Result<(), EngineError> {
    if input.project_id != input.set.project_id {
        return Err(EngineError::WriteRejected(
            "replay project must match replay set project".to_owned(),
        ));
    }
    if !input.set.fixed {
        return Err(EngineError::WriteRejected(
            "sealed replay requires an immutable fixed replay set".to_owned(),
        ));
    }
    if input.cases.is_empty() || input.set.cases.is_empty() {
        return Err(EngineError::WriteRejected(
            "sealed replay requires at least one replay case".to_owned(),
        ));
    }
    if input.baseline_ref.trim().is_empty()
        || input.candidate_ref.trim().is_empty()
        || input.candidate_version.trim().is_empty()
        || input.sealed_context_version.trim().is_empty()
    {
        return Err(EngineError::WriteRejected(
            "sealed replay requires baseline, candidate, candidate version, and context version"
                .to_owned(),
        ));
    }
    let case_ids = input
        .cases
        .iter()
        .map(|case| case.replay_case_id)
        .collect::<BTreeSet<_>>();
    let set_case_ids = input.set.cases.iter().copied().collect::<BTreeSet<_>>();
    if case_ids != set_case_ids
        || input
            .cases
            .iter()
            .any(|case| case.project_id != input.project_id)
    {
        return Err(EngineError::WriteRejected(
            "sealed replay cases must exactly match the fixed replay set".to_owned(),
        ));
    }
    let observation_ids = input
        .observations
        .iter()
        .map(|observation| observation.replay_case_id)
        .collect::<BTreeSet<_>>();
    if observation_ids.len() != input.observations.len() || !observation_ids.is_subset(&case_ids) {
        return Err(EngineError::WriteRejected(
            "sealed replay observations must be unique and belong to the fixed replay set"
                .to_owned(),
        ));
    }
    Ok(())
}

fn sealed_replay_input_hash(input: &SealedReplayInput) -> Result<String, EngineError> {
    let mut cases = input.cases.clone();
    cases.sort_by_key(|case| case.replay_case_id.to_string());
    let mut contracts = input.trace_contracts.clone();
    contracts.sort_by(|left, right| left.contract_id.cmp(&right.contract_id));
    let mut observations = input.observations.clone();
    observations.sort_by_key(|observation| observation.replay_case_id.to_string());
    let value = serde_json::json!({
        "project_id": input.project_id,
        "replay_set_id": input.set.replay_set_id,
        "fixed": input.set.fixed,
        "holdout": input.set.holdout,
        "cases": cases,
        "trace_contracts": contracts,
        "observations": observations,
        "baseline_ref": input.baseline_ref,
        "candidate_ref": input.candidate_ref,
        "candidate_version": input.candidate_version,
        "sealed_context_version": input.sealed_context_version,
    });
    Ok(blake3::hash(&serde_json::to_vec(&value)?)
        .to_hex()
        .to_string())
}

fn replay_result_hash(
    sealed_input_hash: &str,
    baseline_ref: &str,
    candidate_ref: &str,
    case_results: &[ReplayCaseResult],
) -> Result<String, EngineError> {
    let result_projection = case_results
        .iter()
        .map(|result| {
            serde_json::json!({
                "replay_case_id": result.replay_case_id,
                "status": result.status,
                "measurements": result.measurements,
                "produced_refs": result.produced_refs,
                "errors": result.errors,
                "duration_ms": result.duration_ms,
            })
        })
        .collect::<Vec<_>>();
    let value = serde_json::json!({
        "sealed_input_hash": sealed_input_hash,
        "baseline_ref": baseline_ref,
        "candidate_ref": candidate_ref,
        "case_results": result_projection,
    });
    Ok(blake3::hash(&serde_json::to_vec(&value)?)
        .to_hex()
        .to_string())
}

fn evaluate_observed_case(
    case: &ReplayCase,
    observation: &ReplayCaseObservation,
) -> ReplayCaseResult {
    let measurements = case
        .success_criteria
        .iter()
        .map(|criterion| {
            let passed = match &criterion.measurement {
                ReplayMeasurement::MustIncludeRef(reference) => {
                    observation.produced_refs.contains(reference)
                }
                ReplayMeasurement::MustExcludeRef(reference) => {
                    !observation.produced_refs.contains(reference)
                }
                ReplayMeasurement::MustDenyAction(action) => {
                    observation.denied_actions.contains(action)
                }
                ReplayMeasurement::MustRequireVerifier(verifier)
                | ReplayMeasurement::MustProduceGateDecision(verifier)
                | ReplayMeasurement::MustGenerateReport(verifier) => {
                    observation.produced_refs.contains(verifier)
                }
                ReplayMeasurement::MustNotPromoteCandidate => !observation
                    .produced_refs
                    .iter()
                    .any(|reference| reference.contains("PROMOTED")),
                ReplayMeasurement::MustNotReturnDoneVerified => !observation
                    .produced_refs
                    .iter()
                    .any(|reference| reference.contains("DONE_VERIFIED")),
                ReplayMeasurement::MustPreserveTaint => observation.taint_preserved,
            };
            ReplayMeasurementResult {
                criterion_id: criterion.criterion_id.clone(),
                passed,
                observed: "sealed replay observation".to_owned(),
                evidence_refs: observation.produced_refs.clone(),
            }
        })
        .collect::<Vec<_>>();
    let failed_required = case
        .success_criteria
        .iter()
        .zip(&measurements)
        .any(|(criterion, measurement)| criterion.required && !measurement.passed);
    ReplayCaseResult {
        result_id: format!("replay-result-{}", WriteId::new_v7()),
        replay_case_id: case.replay_case_id,
        status: if failed_required {
            ReplayCaseStatus::Failed
        } else {
            ReplayCaseStatus::Passed
        },
        measurements,
        produced_refs: observation.produced_refs.clone(),
        errors: Vec::new(),
        duration_ms: observation.duration_ms,
    }
}

fn blocked_case_result(case: &ReplayCase) -> ReplayCaseResult {
    ReplayCaseResult {
        result_id: format!("replay-result-{}", WriteId::new_v7()),
        replay_case_id: case.replay_case_id,
        status: ReplayCaseStatus::Blocked,
        measurements: Vec::new(),
        produced_refs: Vec::new(),
        errors: vec!["trace completeness prerequisite not satisfied".to_owned()],
        duration_ms: 0,
    }
}

fn canonical_hash<T: Serialize>(value: &T) -> Result<String, EngineError> {
    Ok(blake3::hash(&serde_json::to_vec(value)?)
        .to_hex()
        .to_string())
}

fn is_blake3_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_canonical_trace_evidence(
    project_id: ProjectId,
    task_id: TaskId,
    source_task_revision: MemoryRevision,
    evidence: &[CanonicalTraceEvidence],
) -> Result<(), EngineError> {
    let kinds = evidence
        .iter()
        .map(|entry| entry.kind)
        .collect::<BTreeSet<_>>();
    let expected = CanonicalTraceEvidenceKind::ALL
        .into_iter()
        .collect::<BTreeSet<_>>();
    if evidence.len() != eliot_types::CANONICAL_TRACE_EVIDENCE_PART_COUNT || kinds != expected {
        return Err(EngineError::WriteRejected(
            "canonical trace evidence must contain each of the thirteen evidence kinds once"
                .to_owned(),
        ));
    }
    let receipt_inputs = canonical_receipt_inputs(evidence)?;
    for entry in evidence {
        if entry.project_id != project_id
            || entry.task_id != task_id
            || entry.memory_revision != source_task_revision
            || entry.canonical_kind != entry.kind.as_str()
            || entry.reference.trim().is_empty()
            || !is_blake3_hex(&entry.content_hash)
        {
            return Err(EngineError::WriteRejected(
                "canonical trace evidence scope or identity mismatch".to_owned(),
            ));
        }
        let expected_hash = match &entry.source {
            CanonicalTraceEvidenceSource::CanonicalReceipt { binding } => {
                if !canonical_receipt_kind(entry.kind)
                    || !is_blake3_hex(&binding.input_hash)
                    || !is_blake3_hex(&binding.source_content_hash)
                {
                    return Err(EngineError::WriteRejected(
                        "canonical trace receipt binding is incomplete or attached to a derived kind"
                            .to_owned(),
                    ));
                }
                canonical_hash(&serde_json::json!({
                    "kind": entry.kind,
                    "canonical_kind": entry.canonical_kind,
                    "project_id": entry.project_id,
                    "task_id": entry.task_id,
                    "memory_revision": entry.memory_revision,
                    "reference": entry.reference,
                    "binding": binding,
                    "taint": entry.taint,
                }))?
            }
            CanonicalTraceEvidenceSource::EngineDerivation { derivation } => {
                if canonical_receipt_kind(entry.kind)
                    || derivation.algorithm_version.trim().is_empty()
                    || derivation.input_refs.is_empty()
                    || derivation.input_refs.len() != derivation.input_hashes.len()
                    || derivation.input_refs != receipt_inputs.0
                    || derivation.input_hashes != receipt_inputs.1
                    || derivation
                        .input_refs
                        .iter()
                        .any(|reference| reference.trim().is_empty())
                    || derivation
                        .input_hashes
                        .iter()
                        .any(|hash| !is_blake3_hex(hash))
                {
                    return Err(EngineError::WriteRejected(
                        "canonical trace derivation is incomplete".to_owned(),
                    ));
                }
                let hash = canonical_hash(&serde_json::json!({
                    "kind": entry.kind,
                    "project_id": entry.project_id,
                    "task_id": entry.task_id,
                    "memory_revision": entry.memory_revision,
                    "reference": entry.reference,
                    "algorithm_version": derivation.algorithm_version,
                    "input_refs": derivation.input_refs,
                    "input_hashes": derivation.input_hashes,
                    "taint": entry.taint,
                }))?;
                if derivation.output_hash != hash {
                    return Err(EngineError::WriteRejected(
                        "canonical trace derivation hash mismatch".to_owned(),
                    ));
                }
                hash
            }
        };
        if entry.content_hash != expected_hash {
            return Err(EngineError::WriteRejected(
                "canonical trace evidence content hash mismatch".to_owned(),
            ));
        }
    }
    Ok(())
}

fn deterministic_uuid(domain: &str, identity: &str) -> Uuid {
    let digest = blake3::hash(format!("{domain}:{identity}").as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest.as_bytes()[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

fn deterministic_timestamp(domain: &str, identity: &str) -> Result<OffsetDateTime, EngineError> {
    let digest = blake3::hash(format!("{domain}:{identity}").as_bytes());
    let offset = u32::from_be_bytes(digest.as_bytes()[..4].try_into().map_err(|_| {
        EngineError::WriteRejected("deterministic timestamp digest is incomplete".to_owned())
    })?);
    OffsetDateTime::from_unix_timestamp(1_700_000_000_i64 + i64::from(offset % 100_000_000))
        .map_err(|error| EngineError::WriteRejected(error.to_string()))
}

fn canonical_receipt_inputs(
    evidence: &[CanonicalTraceEvidence],
) -> Result<(Vec<String>, Vec<String>), EngineError> {
    let mut references = Vec::new();
    let mut hashes = Vec::new();
    for kind in [
        CanonicalTraceEvidenceKind::TaskContract,
        CanonicalTraceEvidenceKind::ActualObservation,
        CanonicalTraceEvidenceKind::VerifierRun,
    ] {
        let entry = evidence
            .iter()
            .find(|entry| entry.kind == kind)
            .ok_or_else(|| {
                EngineError::WriteRejected("canonical receipt evidence is missing".to_owned())
            })?;
        let CanonicalTraceEvidenceSource::CanonicalReceipt { binding } = &entry.source else {
            return Err(EngineError::WriteRejected(
                "canonical receipt evidence cannot be replaced by a derivation".to_owned(),
            ));
        };
        references.push(entry.reference.clone());
        hashes.push(binding.input_hash.clone());
    }
    Ok((references, hashes))
}

const fn canonical_receipt_kind(kind: CanonicalTraceEvidenceKind) -> bool {
    matches!(
        kind,
        CanonicalTraceEvidenceKind::TaskContract
            | CanonicalTraceEvidenceKind::ActualObservation
            | CanonicalTraceEvidenceKind::VerifierRun
    )
}

fn canonicalize_replay_membership(
    mut set: ReplaySet,
    mut cases: Vec<ReplayCase>,
    mut snapshots: Vec<ReplayInputSnapshot>,
) -> Result<(ReplaySet, Vec<ReplayCase>, Vec<ReplayInputSnapshot>), EngineError> {
    let mut case_ids = BTreeMap::new();
    for case in &mut cases {
        let old_id = case.replay_case_id;
        let identity_hash = canonical_hash(&serde_json::json!({
            "project_id": case.project_id,
            "source_task_id": case.source_task_id,
            "case_kind": case.case_kind,
            "input_snapshot_refs": case.input_snapshot_refs,
            "expected_observation_refs": case.expected_observation_refs,
            "expected_verifier_refs": case.expected_verifier_refs,
            "forbidden_output_patterns": case.forbidden_output_patterns,
            "success_criteria": case.success_criteria,
            "trace_contract_ref": case.trace_contract_ref,
            "taint": case.taint,
        }))?;
        case.replay_case_id =
            ReplayCaseId::from_uuid(deterministic_uuid("sealed-replay-case", &identity_hash));
        case.created_at = deterministic_timestamp("sealed-replay-case", &identity_hash)?;
        case_ids.insert(old_id, case.replay_case_id);
    }
    cases.sort_by_key(|case| case.replay_case_id.to_string());
    if cases
        .iter()
        .map(|case| case.replay_case_id)
        .collect::<BTreeSet<_>>()
        .len()
        != cases.len()
    {
        return Err(EngineError::WriteRejected(
            "sealed replay cases must remain distinct after canonicalization".to_owned(),
        ));
    }
    for snapshot in &mut snapshots {
        snapshot.replay_case_id =
            case_ids
                .get(&snapshot.replay_case_id)
                .copied()
                .ok_or_else(|| {
                    EngineError::WriteRejected(
                        "sealed snapshot lost its canonical replay case".to_owned(),
                    )
                })?;
        let identity_hash = canonical_hash(&serde_json::json!({
            "replay_case_id": snapshot.replay_case_id,
            "context_packet_ref": snapshot.context_packet_ref,
            "memory_refs": snapshot.memory_refs,
            "skill_refs": snapshot.skill_refs,
            "policy_refs": snapshot.policy_refs,
            "artifact_refs": snapshot.artifact_refs,
        }))?;
        snapshot.snapshot_id = format!("replay-input-snapshot:{identity_hash}");
        snapshot.created_at = deterministic_timestamp("replay-input-snapshot", &identity_hash)?;
    }
    snapshots.sort_by_key(|snapshot| snapshot.replay_case_id.to_string());
    set.cases = cases.iter().map(|case| case.replay_case_id).collect();
    set.created_from_refs.sort();
    set.created_from_refs.dedup();
    let set_hash = canonical_hash(&serde_json::json!({
        "project_id": set.project_id,
        "name": set.name,
        "purpose": set.purpose,
        "cases": set.cases,
        "fixed": set.fixed,
        "holdout": set.holdout,
        "created_from_refs": set.created_from_refs,
    }))?;
    set.replay_set_id = ReplaySetId::from_uuid(deterministic_uuid("sealed-replay-set", &set_hash));
    set.created_at = deterministic_timestamp("sealed-replay-set-input", &set_hash)?;
    Ok((set, cases, snapshots))
}

fn validate_replay_seal_membership(input: &ReplaySealInput) -> Result<(), EngineError> {
    let expected_holdout = matches!(input.role, ReplaySetRole::Holdout);
    if !input.set.fixed || input.set.holdout != expected_holdout || input.version == 0 {
        return Err(EngineError::WriteRejected(
            "sealed replay requires fixed set role, membership, and positive version".to_owned(),
        ));
    }
    if input.evaluator_version.trim().is_empty() || input.context_version.trim().is_empty() {
        return Err(EngineError::WriteRejected(
            "sealed replay requires evaluator and context versions".to_owned(),
        ));
    }
    let set_ids = input.set.cases.iter().copied().collect::<BTreeSet<_>>();
    let case_ids = input
        .cases
        .iter()
        .map(|case| case.replay_case_id)
        .collect::<BTreeSet<_>>();
    let snapshot_ids = input
        .snapshots
        .iter()
        .map(|snapshot| snapshot.replay_case_id)
        .collect::<BTreeSet<_>>();
    if set_ids.len() < 2
        || set_ids.len() != input.set.cases.len()
        || case_ids.len() != input.cases.len()
        || snapshot_ids.len() != input.snapshots.len()
        || set_ids != case_ids
        || case_ids != snapshot_ids
        || input
            .cases
            .iter()
            .any(|case| case.project_id != input.set.project_id)
    {
        return Err(EngineError::WriteRejected(
            "sealed replay cases and snapshots must exactly match unique set membership".to_owned(),
        ));
    }
    Ok(())
}

fn validate_canonical_replay_input(
    input: &CanonicalReplayExecutionInput,
) -> Result<(), EngineError> {
    if input.baseline_ref.trim().is_empty()
        || input.candidate_ref.trim().is_empty()
        || input.candidate_version.trim().is_empty()
    {
        return Err(EngineError::WriteRejected(
            "canonical replay requires baseline, candidate, and candidate version".to_owned(),
        ));
    }
    validate_canonical_replay_records(input)?;
    validate_canonical_replay_set(input)?;
    validate_canonical_replay_observations(input)
}

fn validate_canonical_replay_records(
    input: &CanonicalReplayExecutionInput,
) -> Result<(), EngineError> {
    let case_hashes = input
        .cases
        .iter()
        .map(|record| canonical_hash(&record.case))
        .collect::<Result<Vec<_>, _>>()?;
    let snapshot_hashes = input
        .snapshots
        .iter()
        .map(|record| canonical_hash(&record.snapshot))
        .collect::<Result<Vec<_>, _>>()?;
    if case_hashes != input.sealed_set.case_hashes
        || snapshot_hashes != input.sealed_set.snapshot_hashes
        || input.cases.iter().zip(&case_hashes).any(|(record, hash)| {
            record.replay_set_id != input.sealed_set.set.replay_set_id
                || record.content_hash != *hash
                || record.record_id != format!("replay-case:{hash}")
        })
        || input
            .snapshots
            .iter()
            .zip(&snapshot_hashes)
            .any(|(record, hash)| {
                record.replay_set_id != input.sealed_set.set.replay_set_id
                    || record.content_hash != *hash
                    || record.record_id != format!("replay-snapshot:{hash}")
            })
    {
        return Err(EngineError::WriteRejected(
            "sealed replay case or snapshot hash mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_canonical_replay_set(input: &CanonicalReplayExecutionInput) -> Result<(), EngineError> {
    let expected_profile_hash =
        canonical_hash(&ReplayRunnerService::deterministic_no_mutation_profile())?;
    let expected_evaluator_hash = canonical_hash(&serde_json::json!({
        "engine": "eliot-replay-evaluator",
        "version": input.sealed_set.evaluator_version,
    }))?;
    let expected_context_hash = canonical_hash(&serde_json::json!({
        "context_version": input.sealed_set.context_version,
    }))?;
    let expected_sealed_hash = canonical_hash(&serde_json::json!({
        "set": input.sealed_set.set,
        "role": input.sealed_set.role,
        "version": input.sealed_set.version,
        "evaluator_hash": input.sealed_set.evaluator_hash,
        "profile_hash": input.sealed_set.profile_hash,
        "context_hash": input.sealed_set.context_hash,
        "case_hashes": input.sealed_set.case_hashes,
        "snapshot_hashes": input.sealed_set.snapshot_hashes,
    }))?;
    if input.sealed_set.evaluator_hash != expected_evaluator_hash
        || input.sealed_set.profile_hash != expected_profile_hash
        || input.sealed_set.context_hash != expected_context_hash
        || input.sealed_set.case_hashes.len() < 2
        || input.sealed_set.case_hashes.len() != input.sealed_set.snapshot_hashes.len()
        || input.sealed_set.set.cases.len() != input.sealed_set.case_hashes.len()
        || !input.sealed_set.set.fixed
        || input.sealed_set.set.holdout != matches!(input.sealed_set.role, ReplaySetRole::Holdout)
        || input.sealed_set.sealed_hash != expected_sealed_hash
        || input.sealed_set.record_id != format!("replay-set:{expected_sealed_hash}")
    {
        return Err(EngineError::WriteRejected(
            "sealed replay set hash or version fence mismatch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_canonical_replay_observations(
    input: &CanonicalReplayExecutionInput,
) -> Result<(), EngineError> {
    let case_ids = input
        .cases
        .iter()
        .map(|record| record.case.replay_case_id)
        .collect::<BTreeSet<_>>();
    let observation_ids = input
        .observations
        .iter()
        .map(|observation| observation.replay_case_id)
        .collect::<BTreeSet<_>>();
    if case_ids.len() != input.cases.len()
        || observation_ids.len() != input.observations.len()
        || case_ids != observation_ids
    {
        return Err(EngineError::WriteRejected(
            "canonical observations must exactly match sealed replay membership".to_owned(),
        ));
    }
    for record in &input.cases {
        let snapshot = input
            .snapshots
            .iter()
            .find(|snapshot| snapshot.snapshot.replay_case_id == record.case.replay_case_id)
            .ok_or_else(|| EngineError::WriteRejected("missing sealed snapshot".to_owned()))?;
        let observation = input
            .observations
            .iter()
            .find(|observation| observation.replay_case_id == record.case.replay_case_id)
            .ok_or_else(|| {
                EngineError::WriteRejected("missing canonical observation".to_owned())
            })?;
        let contract = input
            .trace_contracts
            .iter()
            .find(|contract| contract.contract_id == record.case.trace_contract_ref)
            .ok_or_else(|| {
                EngineError::WriteRejected("missing canonical trace contract".to_owned())
            })?;
        if record.case.source_task_id != Some(contract.task_id)
            || contract.project_id != input.sealed_set.set.project_id
            || !contract.replay_allowed
            || observation.snapshot_hash != snapshot.content_hash
        {
            return Err(EngineError::WriteRejected(
                "canonical replay trace, task, or snapshot fence mismatch".to_owned(),
            ));
        }
        validate_canonical_trace_evidence(
            contract.project_id,
            contract.task_id,
            contract.source_task_revision,
            &observation.evidence,
        )?;
        if canonical_hash(&observation.evidence)? != contract.evidence_manifest_hash
            || observation.evidence != contract.evidence
        {
            return Err(EngineError::WriteRejected(
                "canonical replay observation does not match its sealed trace contract".to_owned(),
            ));
        }
    }
    Ok(())
}

fn evaluate_canonical_case(
    case: &ReplayCase,
    observation: &CanonicalReplayObservationEvidence,
    execution_seed: &str,
) -> Result<ReplayCaseResult, EngineError> {
    let evidence_refs = observation
        .evidence
        .iter()
        .map(|evidence| evidence.reference.clone())
        .collect::<Vec<_>>();
    let measurements = case
        .success_criteria
        .iter()
        .map(|criterion| {
            let passed = match &criterion.measurement {
                ReplayMeasurement::MustIncludeRef(reference) => evidence_refs.contains(reference),
                ReplayMeasurement::MustExcludeRef(reference) => !evidence_refs.contains(reference),
                ReplayMeasurement::MustDenyAction(action) => {
                    ReplaySafetyGate::mutation_attempt_blocked(action)
                }
                ReplayMeasurement::MustRequireVerifier(reference)
                | ReplayMeasurement::MustProduceGateDecision(reference)
                | ReplayMeasurement::MustGenerateReport(reference) => {
                    evidence_refs.contains(reference)
                }
                ReplayMeasurement::MustNotPromoteCandidate
                | ReplayMeasurement::MustNotReturnDoneVerified
                | ReplayMeasurement::MustPreserveTaint => true,
            };
            ReplayMeasurementResult {
                criterion_id: criterion.criterion_id.clone(),
                passed,
                observed: "engine-derived canonical replay measurement".to_owned(),
                evidence_refs: evidence_refs.clone(),
            }
        })
        .collect::<Vec<_>>();
    let failed_required = case
        .success_criteria
        .iter()
        .zip(&measurements)
        .any(|(criterion, measurement)| criterion.required && !measurement.passed);
    let status = if failed_required {
        ReplayCaseStatus::Failed
    } else {
        ReplayCaseStatus::Passed
    };
    let result_hash = canonical_hash(&serde_json::json!({
        "execution_seed": execution_seed,
        "replay_case_id": case.replay_case_id,
        "status": status,
        "measurements": measurements,
        "produced_refs": evidence_refs,
        "errors": Vec::<String>::new(),
        "duration_ms": 0,
    }))?;
    Ok(ReplayCaseResult {
        result_id: format!("replay-result:{result_hash}"),
        replay_case_id: case.replay_case_id,
        status,
        measurements,
        produced_refs: evidence_refs,
        errors: Vec::new(),
        duration_ms: 0,
    })
}

fn sleep_artifact_kind(reference: &str) -> Result<SleepCandidateArtifactKind, EngineError> {
    let kind = if reference.starts_with("procedure-candidate:") {
        SleepCandidateArtifactKind::Procedure
    } else if reference.starts_with("forgetting-candidate:") {
        SleepCandidateArtifactKind::ForgettingAction
    } else if reference.starts_with("test-candidate:") {
        SleepCandidateArtifactKind::Test
    } else if reference.starts_with("replay-case-candidate:") {
        SleepCandidateArtifactKind::ReplayCase
    } else if reference.starts_with("dream-candidate:") {
        SleepCandidateArtifactKind::Dream
    } else {
        return Err(EngineError::WriteRejected(
            "sleep output has no canonical typed artifact kind".to_owned(),
        ));
    };
    Ok(kind)
}

fn all_prohibited_dream_effects() -> Vec<ProhibitedDreamEffect> {
    vec![
        ProhibitedDreamEffect::CurrentTruth,
        ProhibitedDreamEffect::ActivePolicy,
        ProhibitedDreamEffect::Permission,
        ProhibitedDreamEffect::Completion,
        ProhibitedDreamEffect::SkillPromotion,
        ProhibitedDreamEffect::MemorySuppression,
        ProhibitedDreamEffect::PatchApplication,
    ]
}

fn is_legacy_trace_contract(contract: &TraceCompletenessContract) -> bool {
    contract
        .contract_id
        .starts_with("legacy-unverified-trace-contract:")
}

fn trace_ref_matches(value: &str, category: &str) -> bool {
    let value = value.trim();
    value == category
        || value
            .strip_prefix(category)
            .and_then(|suffix| {
                suffix
                    .strip_prefix(':')
                    .or_else(|| suffix.strip_prefix('='))
            })
            .is_some_and(|reference| !reference.trim().is_empty())
}

fn required_trace_refs() -> [(&'static str, MissingTracePart); 13] {
    [
        ("task_contract", MissingTracePart::TaskContract),
        ("context_packet", MissingTracePart::ContextPacket),
        (
            "current_truth_revision",
            MissingTracePart::CurrentTruthRevision,
        ),
        ("memory_exposure_set", MissingTracePart::MemoryExposureSet),
        ("agent_tool_events", MissingTracePart::AgentToolEvents),
        (
            "expected_observation",
            MissingTracePart::CognitiveGateDecision,
        ),
        ("actual_observation", MissingTracePart::AgentToolEvents),
        ("verifier_run", MissingTracePart::VerifierRun),
        ("artifact_ref", MissingTracePart::ArtifactRef),
        ("finish_decision", MissingTracePart::FinishDecision),
        ("policy_snapshot", MissingTracePart::PolicySnapshot),
        ("model_route", MissingTracePart::ModelRoute),
        ("outcome_and_cost", MissingTracePart::OutcomeAndCost),
    ]
}
