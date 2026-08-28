//! Typed replay and sleep input and observation data-model.
//!
//! This module owns only the contiguous typed input/observation value closure
//! mechanically extracted from [`crate::replay`] — the pure data shapes used
//! to describe trace completeness, sealed replay membership, canonical replay
//! execution, and sleep synthesis inputs plus sealed replay observations. It
//! records typed inputs and observations; it does not decide replay safety,
//! seal validity, execution, verdict, canonical hashing/validation, authority,
//! or sleep/Dreamer lifecycle.
//!
//! Normative basis: Implementation I18.41 Deterministic simulation and replay
//! and I12.26 Memory admission and retrieval trace (bounded trace contracts
//! and sealed replay inputs), and Architecture A5.5 Verifier & Evaluation
//! Contract (evaluation authority separate from input shape). This child has
//! no semantic truth, canonical write, Dreamer, provider, runtime, or
//! lifecycle authority; all replay authority, sealing, execution/write
//! orchestration, hashing/validation helpers, and services remain in
//! [`crate::replay`] (`TraceCompletenessService`, `ReplayCaseService`,
//! `ReplaySetService`, `ReplaySealService`, `ReplayRunnerService`,
//! `ReplayVerdictService`, `SleepConsolidationService`, and helpers).
//!
//! Inputs vs. authority: the structs here are caller-supplied typed values and
//! observed outputs. Replay authority — whether an input is complete, sealed,
//! or safe to run, and whether a result promotes or mutates truth — is decided
//! exclusively by the parent `replay` services and canonical validation. Moving
//! this closure preserves all public paths, derives, serialization shape, field
//! ordering, and visibility.

use eliot_types::{
    CanonicalReplayObservationEvidence, CanonicalTraceCompletenessContract, CanonicalTraceEvidence,
    MemoryRevision, ProjectId, ReplayCase, ReplayCaseId, ReplayCaseKind, ReplayInputSnapshot,
    ReplaySet, ReplaySetRole, SealedReplayCaseRecord, SealedReplayInputSnapshotRecord,
    SealedReplaySetRecord, SleepTrigger, TaskId, TraceCompletenessContract,
};
use serde::Serialize;

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
    pub max_input_bytes: u32,
    pub reasoning_retry_limit: u8,
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
